//! Domain management for the relational store (spec rel/002).
//!
//! Self-hosting pattern like the KV/JSON registries: metadata lives in the
//! dedicated rel LSM instance under `__sys:rel_domain:{name}`, separate from
//! the catalog (`CAT:`) and row data (`ROW:`/`IDX:`/`SEQ:`) that land in
//! rel/003 on the same `system_prefix`. Deletion only marks the domain
//! `Deleting`; physical cleanup follows in spec rel/013.

use super::error::RelStoreError;
use crate::engines::lsm::domain::{fnv64, now_secs};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::StorageEngine;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const SYS_REL_DOMAIN_PREFIX: &[u8] = b"__sys:rel_domain:";
pub(crate) const DEFAULT_DOMAIN: &str = "default";
const MAX_DOMAIN_NAME_LEN: usize = 50;

fn sys_key(name: &str) -> Vec<u8> {
    let mut k = SYS_REL_DOMAIN_PREFIX.to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

fn validate_domain_name(name: &str) -> Result<(), RelStoreError> {
    if name.is_empty() {
        return Err(RelStoreError::InvalidDomainName(
            "name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_DOMAIN_NAME_LEN {
        return Err(RelStoreError::InvalidDomainName(format!(
            "name length {} exceeds maximum of {} characters",
            name.len(),
            MAX_DOMAIN_NAME_LEN
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(RelStoreError::InvalidDomainName(format!(
            "name '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
            name
        )));
    }
    // Shadowed by the static /store-api/rel/domains routes (rel/009): data
    // endpoints of such a domain would answer 404/405 (matchit prefers
    // static segments).
    if name == "domains" {
        return Err(RelStoreError::InvalidDomainName(
            "name 'domains' is reserved".to_string(),
        ));
    }
    Ok(())
}

// ── RelDomain ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum RelDomainState {
    #[default]
    Active,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelDomain {
    pub name: String,
    /// 16 lowercase hex chars (FNV-64a of the name) — colon-free so the
    /// later data keys `CAT:{prefix}:{name}`, `ROW:{prefix}:{table_id}:...`
    /// etc. (rel/003) split cleanly on `:`.
    pub system_prefix: Vec<u8>,
    pub created_at: u64,
    #[serde(default)]
    pub state: RelDomainState,
}

impl RelDomain {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            system_prefix: format!("{:016x}", fnv64(name.as_bytes())).into_bytes(),
            created_at: now_secs(),
            state: RelDomainState::Active,
        }
    }
}

// ── RelDomainRegistry ──────────────────────────────────────────────────────────

/// Manages rel domain lifecycle: creation, lookup, listing, deletion, recovery.
pub struct RelDomainRegistry {
    domains: RwLock<HashMap<String, RelDomain>>,
    engine: Arc<LsmStorageEngine>,
    /// Serializes `create_domain`/`delete_domain` end-to-end: each is a
    /// check-then-act that spans an await, so the lifecycle transitions must
    /// not interleave (spec general/003; rel/002 §4).
    lifecycle_lock: Mutex<()>,
}

impl RelDomainRegistry {
    /// Loads all persisted domains, then creates the default domain if it is
    /// missing in any state.
    pub async fn recover(engine: Arc<LsmStorageEngine>) -> anyhow::Result<Self> {
        let keys = engine.scan_keys(SYS_REL_DOMAIN_PREFIX).await?;
        let mut loaded = HashMap::new();
        for key in keys {
            if let Some(bytes) = engine.get(&key).await? {
                match serde_json::from_slice::<RelDomain>(&bytes) {
                    Ok(domain) => {
                        loaded.insert(domain.name.clone(), domain);
                    }
                    Err(e) => tracing::warn!(
                        "[RelDomainRegistry] cannot deserialize domain at key {:?}: {e}",
                        key
                    ),
                }
            }
        }
        let registry = Self {
            domains: RwLock::new(loaded),
            engine,
            lifecycle_lock: Mutex::new(()),
        };
        // Any state counts: creating over a Deleting default would fail with
        // DomainAlreadyExists and abort every boot. The purger (rel/013)
        // finalizes it; the next recover() then recreates it.
        match registry.get_domain_any(DEFAULT_DOMAIN) {
            None => {
                registry.create_domain(DEFAULT_DOMAIN).await?;
            }
            Some(d) if d.state == RelDomainState::Deleting => tracing::warn!(
                "[RelDomainRegistry] default domain is Deleting at startup; \
                 it will be recreated on the first start after the purge finishes"
            ),
            Some(_) => {}
        }
        Ok(registry)
    }

    /// Creates a new domain. Fails if the name already exists (incl. deleting).
    pub async fn create_domain(&self, name: &str) -> Result<RelDomain, RelStoreError> {
        validate_domain_name(name)?;
        let _guard = self.lifecycle_lock.lock().await;
        if self.domains.read().contains_key(name) {
            return Err(RelStoreError::DomainAlreadyExists(name.to_string()));
        }
        let domain = RelDomain::new(name);
        let data = serde_json::to_vec(&domain)?;
        self.engine.put(&sys_key(name), &data).await?;
        self.domains.write().insert(name.to_string(), domain.clone());
        Ok(domain)
    }

    /// Looks up an **active** domain. Returns `None` for deleting/unknown ones.
    pub fn get_domain(&self, name: &str) -> Option<RelDomain> {
        self.domains
            .read()
            .get(name)
            .filter(|d| d.state == RelDomainState::Active)
            .cloned()
    }

    /// Looks up a domain regardless of its state.
    pub fn get_domain_any(&self, name: &str) -> Option<RelDomain> {
        self.domains.read().get(name).cloned()
    }

    /// Lists **all** domains including `Deleting` ones, each carrying its
    /// `state` (rel/013, pattern: json/013): operators can watch purge
    /// progress. This deliberately supersedes the rel/002 default (concept
    /// 3.1 "hidden from get/list") — `get_domain`/`require_active` stay
    /// active-only, so CRUD resolution is unchanged and the 410 detail path
    /// remains rel/009's.
    pub fn list_domains(&self) -> Vec<RelDomain> {
        self.domains.read().values().cloned().collect()
    }

    /// Domains currently in `Deleting` state (rel/013 purger consumer).
    pub(crate) fn list_deleting_domains(&self) -> Vec<RelDomain> {
        self.domains
            .read()
            .values()
            .filter(|d| d.state == RelDomainState::Deleting)
            .cloned()
            .collect()
    }

    /// Marks the domain `Deleting` and persists the change. Catalog and row
    /// data (rel/003+) stay on disk under the domain's prefix until the
    /// purger (spec rel/013) cleans them up.
    pub async fn delete_domain(&self, name: &str) -> Result<(), RelStoreError> {
        let _guard = self.lifecycle_lock.lock().await;
        let mut domain = match self.get_domain_any(name) {
            None => return Err(RelStoreError::DomainNotFound(name.to_string())),
            Some(d) if d.state == RelDomainState::Deleting => {
                return Err(RelStoreError::DomainDeleting(name.to_string()))
            }
            Some(d) => d,
        };
        domain.state = RelDomainState::Deleting;
        let data = serde_json::to_vec(&domain)?;
        self.engine.put(&sys_key(name), &data).await?;
        self.domains.write().insert(name.to_string(), domain);
        Ok(())
    }

    /// Removes the domain metadata for good — `__sys:rel_domain:{name}` from
    /// persistence and the cache. The rel/013 purger calls this after all data
    /// and catalog keys of the domain are gone (metadata is the last anchor,
    /// so a crash before this leaves the domain `Deleting` and resumable).
    pub(crate) async fn finalize_deletion(&self, name: &str) -> Result<(), RelStoreError> {
        self.engine.delete(&sys_key(name)).await?;
        self.domains.write().remove(name);
        Ok(())
    }

    /// Resolves an active domain; `DomainDeleting` (→ 410) for deleting ones,
    /// `DomainNotFound` (→ 404) for unknown ones. This is the domain
    /// resolution every catalog/DML operation calls from rel/003 on.
    pub(crate) fn require_active(&self, name: &str) -> Result<RelDomain, RelStoreError> {
        match self.get_domain_any(name) {
            None => Err(RelStoreError::DomainNotFound(name.to_string())),
            Some(d) if d.state == RelDomainState::Deleting => {
                Err(RelStoreError::DomainDeleting(name.to_string()))
            }
            Some(d) => Ok(d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;

    async fn make_setup() -> (Arc<LsmStorageEngine>, Arc<RelDomainRegistry>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal,
                wal_path,
                vlog,
                vlog_path,
                fm,
                mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let registry =
            Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap());
        (engine, registry, dir)
    }

    async fn make_registry() -> (Arc<RelDomainRegistry>, tempfile::TempDir) {
        let (_, registry, dir) = make_setup().await;
        (registry, dir)
    }

    // 1. create_domain -> get_domain returns it; system_prefix is 16 bytes.
    #[tokio::test]
    async fn test_create_and_get_domain() {
        let (registry, _dir) = make_registry().await;
        let created = registry.create_domain("alpha").await.unwrap();
        assert_eq!(created.system_prefix.len(), 16);
        let fetched = registry.get_domain("alpha").unwrap();
        assert_eq!(fetched.name, "alpha");
        assert_eq!(fetched.system_prefix, created.system_prefix);
    }

    // 2. Duplicate (active) domain -> DomainAlreadyExists (409).
    #[tokio::test]
    async fn test_duplicate_domain_rejected() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("beta").await.unwrap();
        let err = registry.create_domain("beta").await.unwrap_err();
        assert!(matches!(err, RelStoreError::DomainAlreadyExists(_)), "got: {err}");
    }

    // 3. Create against a Deleting domain of the same name -> still
    //    DomainAlreadyExists (name stays reserved until rel/013 purges it).
    #[tokio::test]
    async fn test_create_against_deleting_domain_still_rejected() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("gamma").await.unwrap();
        registry.delete_domain("gamma").await.unwrap();
        let err = registry.create_domain("gamma").await.unwrap_err();
        assert!(matches!(err, RelStoreError::DomainAlreadyExists(_)), "got: {err}");
    }

    // 4. Invalid names -> InvalidDomainName. "domains" is reserved: the
    //    static /store-api/rel/domains routes (rel/009) would shadow it.
    #[tokio::test]
    async fn test_invalid_domain_name_rejected() {
        let (registry, _dir) = make_registry().await;
        for bad in ["", "bad name!", "bad/slash", "domains", &"x".repeat(51)] {
            let err = registry.create_domain(bad).await.unwrap_err();
            assert!(
                matches!(err, RelStoreError::InvalidDomainName(_)),
                "'{bad}' got: {err}"
            );
        }
    }

    // 5. system_prefix is deterministic, collision-free and colon-free.
    #[tokio::test]
    async fn test_system_prefix_deterministic_and_colon_free() {
        let (registry, _dir) = make_registry().await;
        let a = registry.create_domain("prefix-a").await.unwrap();
        let b = registry.create_domain("prefix-b").await.unwrap();

        let expected_a = format!("{:016x}", fnv64(b"prefix-a")).into_bytes();
        assert_eq!(a.system_prefix, expected_a, "prefix must be a deterministic FNV-64a hash");
        assert_ne!(a.system_prefix, b.system_prefix, "different names must yield different prefixes");

        for prefix in [&a.system_prefix, &b.system_prefix] {
            assert_eq!(prefix.len(), 16);
            assert!(!prefix.contains(&0x3a), "prefix must not contain a ':' byte");
        }
    }

    // 6. Default domain exists after recover; survives a simulated restart
    //    (second recover on the same engine instance).
    #[tokio::test]
    async fn test_default_domain_persists_across_recover() {
        let (engine, registry, _dir) = make_setup().await;
        assert!(registry.get_domain(DEFAULT_DOMAIN).is_some());

        let registry2 = RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap();
        assert!(registry2.get_domain(DEFAULT_DOMAIN).is_some());
    }

    // 7. delete_domain -> get_domain returns None; require_active ->
    //    DomainDeleting (410); the domain still exists internally (no purger).
    #[tokio::test]
    async fn test_delete_domain_hides_it_but_keeps_it_internally() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("to-delete").await.unwrap();
        registry.delete_domain("to-delete").await.unwrap();

        assert!(registry.get_domain("to-delete").is_none());
        let err = registry.require_active("to-delete").unwrap_err();
        assert!(matches!(err, RelStoreError::DomainDeleting(_)), "got: {err}");
        assert!(registry.get_domain_any("to-delete").is_some());
    }

    // 8. require_active on an unknown domain -> DomainNotFound (404); on an
    //    active one -> Ok.
    #[tokio::test]
    async fn test_require_active_unknown_and_active() {
        let (registry, _dir) = make_registry().await;
        let err = registry.require_active("nope").unwrap_err();
        assert!(matches!(err, RelStoreError::DomainNotFound(_)), "got: {err}");

        registry.create_domain("known").await.unwrap();
        let ok = registry.require_active("known").unwrap();
        assert_eq!(ok.name, "known");
    }

    // 9. list_domains now lists ALL domains incl. Deleting (with state,
    //    rel/013); get_domain/require_active stay active-only.
    #[tokio::test]
    async fn test_list_domains_includes_deleting_with_state() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("one").await.unwrap();
        registry.create_domain("two").await.unwrap();
        registry.delete_domain("two").await.unwrap();

        let listed = registry.list_domains();
        let names: Vec<&str> = listed.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"default"));
        assert!(names.contains(&"one"));
        let two = listed.iter().find(|d| d.name == "two").expect("deleting domain must be listed");
        assert_eq!(two.state, RelDomainState::Deleting);
        // Resolution stays active-only.
        assert!(registry.get_domain("two").is_none());
        assert!(matches!(registry.require_active("two").unwrap_err(), RelStoreError::DomainDeleting(_)));
        assert_eq!(registry.list_deleting_domains().len(), 1);
    }

    // 10. 8 parallel create_domain calls for the same name -> exactly one Ok
    //     (create-lock, spec general/003).
    #[tokio::test]
    async fn test_concurrent_create_domain_single_winner() {
        let (registry, _dir) = make_registry().await;
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let reg = Arc::clone(&registry);
                tokio::spawn(async move { reg.create_domain("contested").await })
            })
            .collect();
        let mut ok = 0;
        for t in tasks {
            if t.await.unwrap().is_ok() {
                ok += 1;
            }
        }
        assert_eq!(ok, 1, "exactly one concurrent create_domain must succeed");
    }

    // 11. recover survives a Deleting default domain without a 409 boot loop;
    //     it stays invisible/Deleting (until rel/013 purges it).
    #[tokio::test]
    async fn test_recover_survives_deleting_default_domain() {
        let (engine, registry, _dir) = make_setup().await;
        registry.delete_domain(DEFAULT_DOMAIN).await.unwrap();

        let registry2 = RelDomainRegistry::recover(Arc::clone(&engine))
            .await
            .expect("recover must survive a Deleting default domain");
        assert!(registry2.get_domain(DEFAULT_DOMAIN).is_none());
        assert!(matches!(
            registry2.require_active(DEFAULT_DOMAIN).unwrap_err(),
            RelStoreError::DomainDeleting(_)
        ));
    }

    // 12. 8 parallel delete_domain calls on the same active domain -> exactly
    //     one Ok, the rest DomainDeleting (410): the lifecycle lock serializes
    //     the check-then-act across its await (rel/002 §4). Without the lock all
    //     callers read `Active` and return Ok.
    #[tokio::test]
    async fn test_concurrent_delete_domain_single_winner() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("contested").await.unwrap();
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let reg = Arc::clone(&registry);
                tokio::spawn(async move { reg.delete_domain("contested").await })
            })
            .collect();
        let mut ok = 0;
        let mut deleting = 0;
        for t in tasks {
            match t.await.unwrap() {
                Ok(()) => ok += 1,
                Err(RelStoreError::DomainDeleting(_)) => deleting += 1,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(ok, 1, "exactly one concurrent delete_domain must succeed");
        assert_eq!(deleting, 7, "the losers must see DomainDeleting (410)");
    }
}
