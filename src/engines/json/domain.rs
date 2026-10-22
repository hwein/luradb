//! Domain management for the JSON store.
//!
//! Self-hosting pattern like the KV `DomainRegistry`: metadata lives in the
//! JSON LSM instance under `__sys:json_domain:{name}`, separate from document
//! data. Deletion only marks the domain `Deleting`; the background purger
//! does the physical cleanup.

use super::error::JsonStoreError;
use crate::engines::lsm::domain::{fnv64, now_secs};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::StorageEngine;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

const SYS_JSON_DOMAIN_PREFIX: &[u8] = b"__sys:json_domain:";
pub(crate) const DEFAULT_DOMAIN: &str = "default";
pub(super) const MAX_DOMAIN_NAME_LEN: usize = 50;

fn sys_key(name: &str) -> Vec<u8> {
    let mut k = SYS_JSON_DOMAIN_PREFIX.to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

/// Lower bound of `json.lsm.max_key_length`: the longest
/// management key, `__sys:json_domain:{name}` at a maximal name, plus 1 byte.
pub(crate) const MIN_LSM_KEY_LENGTH: usize = SYS_JSON_DOMAIN_PREFIX.len() + MAX_DOMAIN_NAME_LEN + 1;

fn validate_domain_name(name: &str) -> Result<(), JsonStoreError> {
    if name.is_empty() {
        return Err(JsonStoreError::InvalidDomainName(
            "name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_DOMAIN_NAME_LEN {
        return Err(JsonStoreError::InvalidDomainName(format!(
            "name length {} exceeds maximum of {} characters",
            name.len(),
            MAX_DOMAIN_NAME_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(JsonStoreError::InvalidDomainName(format!(
            "name '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
            name
        )));
    }
    // Shadowed by the static /json/domains admin routes: data endpoints of
    // such a domain would answer 404/405 (matchit prefers static segments).
    if name == "domains" {
        return Err(JsonStoreError::InvalidDomainName(
            "name 'domains' is reserved".to_string(),
        ));
    }
    Ok(())
}

// ── JsonDomain ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum JsonDomainState {
    #[default]
    Active,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonDomain {
    pub name: String,
    /// 16 lowercase hex chars (FNV-64a of the name) — colon-free so the
    /// composite key `DOC:{prefix}:{key}` stays parseable.
    pub system_prefix: Vec<u8>,
    pub created_at: u64,
    #[serde(default)]
    pub state: JsonDomainState,
    /// Document writes over REST must carry `If-Match` or
    /// `If-None-Match: *`; fixed at creation.
    #[serde(default)]
    pub require_conditional_writes: bool,
}

impl JsonDomain {
    fn new(name: &str, require_conditional_writes: bool) -> Self {
        Self {
            name: name.to_string(),
            system_prefix: format!("{:016x}", fnv64(name.as_bytes())).into_bytes(),
            created_at: now_secs(),
            state: JsonDomainState::Active,
            require_conditional_writes,
        }
    }
}

// ── JsonDomainRegistry ────────────────────────────────────────────────────────

/// Holds the JSON domains: lookup, listing, recovery. Creates and deletes
/// run through the control plane, one at a time.
pub struct JsonDomainRegistry {
    domains: RwLock<HashMap<String, JsonDomain>>,
    engine: Arc<LsmStorageEngine>,
}

impl JsonDomainRegistry {
    /// Loads all persisted domains, then, with `owns_default`, creates the
    /// default domain if it is missing in any state.
    pub async fn recover(engine: Arc<LsmStorageEngine>, owns_default: bool) -> anyhow::Result<Self> {
        let keys = engine.scan_keys(SYS_JSON_DOMAIN_PREFIX).await?;
        let mut loaded = HashMap::new();
        for key in keys {
            if let Some(bytes) = engine.get(&key).await? {
                match serde_json::from_slice::<JsonDomain>(&bytes) {
                    Ok(domain) => {
                        loaded.insert(domain.name.clone(), domain);
                    }
                    Err(e) => tracing::warn!(
                        "[JsonDomainRegistry] cannot deserialize domain at key {:?}: {e}",
                        key
                    ),
                }
            }
        }
        let registry = Self { domains: RwLock::new(loaded), engine };
        // Any state counts: creating over a Deleting default would fail with
        // DomainAlreadyExists and abort every boot. The purger finalizes it;
        // the next recover() then recreates it.
        match registry.get_domain_any(DEFAULT_DOMAIN) {
            None if !owns_default => {}
            None => {
                registry.create_domain(DEFAULT_DOMAIN).await?;
            }
            Some(d) if d.state == JsonDomainState::Deleting => tracing::warn!(
                "[JsonDomainRegistry] default domain is Deleting at startup; \
                 it will be recreated on the first start after the purge finishes"
            ),
            Some(_) => {}
        }
        Ok(registry)
    }

    /// Creates a new domain. Fails if the name already exists (incl. deleting).
    pub(crate) async fn create_domain(&self, name: &str) -> Result<JsonDomain, JsonStoreError> {
        self.create_domain_with(name, false).await
    }

    /// [`Self::create_domain`] with the domain's
    /// [`JsonDomain::require_conditional_writes`] setting. The check and the
    /// insert span an await: callers must not run two lifecycle changes at once.
    pub(crate) async fn create_domain_with(
        &self,
        name: &str,
        require_conditional_writes: bool,
    ) -> Result<JsonDomain, JsonStoreError> {
        validate_domain_name(name)?;
        if self.domains.read().contains_key(name) {
            return Err(JsonStoreError::DomainAlreadyExists(name.to_string()));
        }
        let domain = JsonDomain::new(name, require_conditional_writes);
        let data = serde_json::to_vec(&domain)?;
        self.engine.put(&sys_key(name), &data).await?;
        self.domains.write().insert(name.to_string(), domain.clone());
        Ok(domain)
    }

    /// Looks up an **active** domain. Returns `None` for deleting/unknown ones.
    pub fn get_domain(&self, name: &str) -> Option<JsonDomain> {
        self.domains
            .read()
            .get(name)
            .filter(|d| d.state == JsonDomainState::Active)
            .cloned()
    }

    /// Looks up a domain regardless of its state (detail views, purger).
    pub fn get_domain_any(&self, name: &str) -> Option<JsonDomain> {
        self.domains.read().get(name).cloned()
    }

    /// Lists all domains including `Deleting` ones (state is part of the
    /// returned model).
    pub fn list_domains(&self) -> Vec<JsonDomain> {
        self.domains.read().values().cloned().collect()
    }

    /// Domains currently in `Deleting` state (used by the purger).
    pub(crate) fn list_deleting_domains(&self) -> Vec<JsonDomain> {
        self.domains
            .read()
            .values()
            .filter(|d| d.state == JsonDomainState::Deleting)
            .cloned()
            .collect()
    }

    /// Marks the domain `Deleting` and persists the change. Documents and
    /// indexes stay on disk until the purger cleans them up.
    pub(crate) async fn delete_domain(&self, name: &str) -> Result<(), JsonStoreError> {
        let mut domain = match self.get_domain_any(name) {
            None => return Err(JsonStoreError::DomainNotFound(name.to_string())),
            Some(d) if d.state == JsonDomainState::Deleting => {
                return Err(JsonStoreError::DomainDeleting(name.to_string()))
            }
            Some(d) => d,
        };
        domain.state = JsonDomainState::Deleting;
        let data = serde_json::to_vec(&domain)?;
        self.engine.put(&sys_key(name), &data).await?;
        self.domains.write().insert(name.to_string(), domain);
        Ok(())
    }

    /// Removes the domain metadata for good — once the purger removed all
    /// documents and index entries.
    pub(crate) async fn finalize_deletion(&self, name: &str) -> Result<(), JsonStoreError> {
        self.engine.delete(&sys_key(name)).await?;
        self.domains.write().remove(name);
        Ok(())
    }

    /// Resolves an active domain; `DomainDeleting` (→ 410) for deleting ones,
    /// `DomainNotFound` (→ 404) for unknown ones.
    pub(crate) fn require_active(&self, name: &str) -> Result<JsonDomain, JsonStoreError> {
        match self.get_domain_any(name) {
            None => Err(JsonStoreError::DomainNotFound(name.to_string())),
            Some(d) if d.state == JsonDomainState::Deleting => {
                Err(JsonStoreError::DomainDeleting(name.to_string()))
            }
            Some(d) => Ok(d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The domain key at a maximal name stays below the
    // startup lower bound of json.lsm.max_key_length.
    #[test]
    fn test_sys_key_at_max_name_fits_key_limit_lower_bound() {
        let key = sys_key(&"d".repeat(MAX_DOMAIN_NAME_LEN));
        assert!(key.len() < MIN_LSM_KEY_LENGTH, "{}", key.len());
    }
}
