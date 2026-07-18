//! Auth module — AuthCache, domain types, and key utilities.
//!
//! System keys layout:
//!   __sys:auth:user:<name>          → serialised UserRecord (JSON)
//!   __sys:auth:perm:<name>:<domain> → serialised DomainPermission (JSON)

pub mod handlers;
pub mod middleware;

use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::StorageEngine;
use anyhow::Result;
use hex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ── Key helpers ───────────────────────────────────────────────────────────────

const PREFIX_USER: &str = "__sys:auth:user:";
const PREFIX_PERM: &str = "__sys:auth:perm:";

fn user_key(name: &str) -> Vec<u8> {
    format!("{PREFIX_USER}{name}").into_bytes()
}

fn perm_key(name: &str, domain: &str) -> Vec<u8> {
    format!("{PREFIX_PERM}{name}:{domain}").into_bytes()
}

/// Generates a new `lura_<64 hex chars>` API key.
pub fn generate_api_key() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    format!("lura_{}", hex::encode(bytes))
}

/// SHA-256 hex digest of an API key.
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Domain types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    User,
}

/// Ordered Read < Write < Ddl (derive order = declaration order, spec
/// rel/011 §3) — a higher grant covers the lower ones (`granted >= required`).
/// Adding `Ddl` is wire-compatible: existing persisted `"Read"`/`"Write"`
/// values deserialize unchanged, no migration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessLevel {
    Read,
    Write,
    Ddl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub name: String,
    pub api_key_hash: String,
    pub role: UserRole,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPermission {
    pub username: String,
    pub domain: String,
    pub access: AccessLevel,
}

// ── AuthCache ─────────────────────────────────────────────────────────────────

pub struct AuthCache {
    /// api_key_hash → UserRecord
    users: RwLock<HashMap<String, UserRecord>>,
    /// (username, domain_name) → AccessLevel
    permissions: RwLock<HashMap<(String, String), AccessLevel>>,
    engine: Arc<LsmStorageEngine>,
}

impl AuthCache {
    pub fn new(engine: Arc<LsmStorageEngine>) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            permissions: RwLock::new(HashMap::new()),
            engine,
        }
    }

    /// Loads all auth data from the engine into the in-memory cache.
    pub async fn load_from_engine(&self) -> Result<()> {
        let user_keys = self
            .engine
            .scan_keys(PREFIX_USER.as_bytes())
            .await?;

        let mut users = self.users.write().await;
        for k in &user_keys {
            if let Some(bytes) = self.engine.get(k).await? {
                if let Ok(record) = serde_json::from_slice::<UserRecord>(&bytes) {
                    users.insert(record.api_key_hash.clone(), record);
                }
            }
        }
        drop(users);

        let perm_keys = self
            .engine
            .scan_keys(PREFIX_PERM.as_bytes())
            .await?;

        let mut perms = self.permissions.write().await;
        for k in &perm_keys {
            if let Some(bytes) = self.engine.get(k).await? {
                if let Ok(perm) = serde_json::from_slice::<DomainPermission>(&bytes) {
                    perms.insert((perm.username.clone(), perm.domain.clone()), perm.access);
                }
            }
        }

        Ok(())
    }

    /// Returns all stored UserRecords (for listing / reconciliation).
    pub async fn all_users(&self) -> Vec<UserRecord> {
        self.users.read().await.values().cloned().collect()
    }

    /// Look up a user by the SHA-256 hash of their API key.
    pub async fn get_user_by_key_hash(&self, hash: &str) -> Option<UserRecord> {
        self.users.read().await.get(hash).cloned()
    }

    /// Look up a user by name (scans all records).
    pub async fn get_user_by_name(&self, name: &str) -> Option<UserRecord> {
        self.users
            .read()
            .await
            .values()
            .find(|r| r.name == name)
            .cloned()
    }

    /// Returns all permissions for a given user.
    pub async fn permissions_for_user(&self, username: &str) -> Vec<DomainPermission> {
        self.permissions
            .read()
            .await
            .iter()
            .filter(|((u, _), _)| u == username)
            .map(|((u, d), a)| DomainPermission {
                username: u.clone(),
                domain: d.clone(),
                access: a.clone(),
            })
            .collect()
    }

    /// Returns the access level for (username, domain), or None.
    pub async fn get_permission(&self, username: &str, domain: &str) -> Option<AccessLevel> {
        self.permissions
            .read()
            .await
            .get(&(username.to_string(), domain.to_string()))
            .cloned()
    }

    /// Persists and caches a UserRecord.
    pub async fn upsert_user(&self, record: UserRecord) -> Result<()> {
        let key = user_key(&record.name);
        let value = serde_json::to_vec(&record)?;
        self.engine.put(&key, &value).await?;
        self.users
            .write()
            .await
            .insert(record.api_key_hash.clone(), record);
        Ok(())
    }

    /// Removes a user and all their permissions from the engine and cache.
    pub async fn remove_user(&self, name: &str) -> Result<()> {
        // Remove permissions first
        let perm_prefix = format!("{PREFIX_PERM}{name}:");
        let perm_keys = self.engine.scan_keys(perm_prefix.as_bytes()).await?;
        for k in &perm_keys {
            self.engine.delete(k).await?;
        }
        {
            let mut perms = self.permissions.write().await;
            perms.retain(|(u, _), _| u != name);
        }

        // Remove the user record
        let key = user_key(name);
        self.engine.delete(&key).await?;
        {
            let mut users = self.users.write().await;
            users.retain(|_, r| r.name != name);
        }

        Ok(())
    }

    /// Updates only the api_key_hash for an existing user (key rotation).
    pub async fn rotate_key(&self, name: &str, new_hash: &str) -> Result<()> {
        let old = {
            let users = self.users.read().await;
            users.values().find(|r| r.name == name).cloned()
        };
        let mut record = old.ok_or_else(|| anyhow::anyhow!("404 Not Found: user '{name}'"))?;
        let old_hash = record.api_key_hash.clone();
        record.api_key_hash = new_hash.to_string();

        let key = user_key(name);
        let value = serde_json::to_vec(&record)?;
        self.engine.put(&key, &value).await?;

        let mut users = self.users.write().await;
        users.remove(&old_hash);
        users.insert(new_hash.to_string(), record);

        Ok(())
    }

    /// Persists and caches a domain permission.
    pub async fn set_permission(&self, perm: DomainPermission) -> Result<()> {
        let key = perm_key(&perm.username, &perm.domain);
        let value = serde_json::to_vec(&perm)?;
        self.engine.put(&key, &value).await?;
        self.permissions
            .write()
            .await
            .insert((perm.username.clone(), perm.domain.clone()), perm.access);
        Ok(())
    }

    /// Removes a domain permission from the engine and cache.
    pub async fn remove_permission(&self, username: &str, domain: &str) -> Result<()> {
        let key = perm_key(username, domain);
        self.engine.delete(&key).await?;
        self.permissions
            .write()
            .await
            .remove(&(username.to_string(), domain.to_string()));
        Ok(())
    }
}

// ── Admin reconciliation ──────────────────────────────────────────────────────

/// Reconciles the admin list from config with what is stored in the engine.
///
/// 1. Upserts all admins from config (hash of key stored, plaintext discarded).
/// 2. Removes any admin entries in the engine that are no longer in the config.
/// 3. Logs a warning if no admins remain and auth is enabled.
pub async fn reconcile_admins(
    cache: &AuthCache,
    admins: &[crate::config::AdminEntry],
    auth_enabled: bool,
) -> Result<()> {
    let config_names: std::collections::HashSet<&str> =
        admins.iter().map(|a| a.name.as_str()).collect();

    // Remove stale admins
    let existing: Vec<UserRecord> = cache
        .all_users()
        .await
        .into_iter()
        .filter(|r| r.role == UserRole::Admin)
        .collect();

    for record in &existing {
        if !config_names.contains(record.name.as_str()) {
            cache.remove_user(&record.name).await?;
            tracing::info!("Auth: removed stale admin '{}'", record.name);
        }
    }

    // Upsert current admins
    for entry in admins {
        let hash = hash_api_key(&entry.api_key);
        let record = UserRecord {
            name: entry.name.clone(),
            api_key_hash: hash,
            role: UserRole::Admin,
            created_at: now_secs(),
        };
        cache.upsert_user(record).await?;
        tracing::info!("Auth: admin '{}' reconciled", entry.name);
    }

    if auth_enabled && admins.is_empty() {
        tracing::warn!("Auth is enabled but no admins are configured in luradb.toml");
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_round_trip() {
        let key = generate_api_key();
        assert!(key.starts_with("lura_"));
        assert_eq!(key.len(), 5 + 64); // "lura_" + 64 hex chars
        let hash = hash_api_key(&key);
        assert_eq!(hash.len(), 64);
        // same input → same hash
        assert_eq!(hash_api_key(&key), hash);
        // different key → different hash
        let key2 = generate_api_key();
        assert_ne!(hash_api_key(&key2), hash);
    }

    #[test]
    fn access_level_ordering() {
        assert!(AccessLevel::Read < AccessLevel::Write);
        assert!(AccessLevel::Write < AccessLevel::Ddl);
        assert!(AccessLevel::Read < AccessLevel::Ddl);
        assert!(AccessLevel::Ddl >= AccessLevel::Write);
        assert!(AccessLevel::Write >= AccessLevel::Read);
        assert!(AccessLevel::Ddl >= AccessLevel::Read);
    }

    #[test]
    fn access_level_serde_round_trip() {
        for (level, wire) in [
            (AccessLevel::Read, "\"Read\""),
            (AccessLevel::Write, "\"Write\""),
            (AccessLevel::Ddl, "\"Ddl\""),
        ] {
            assert_eq!(serde_json::to_string(&level).unwrap(), wire);
            assert_eq!(serde_json::from_str::<AccessLevel>(wire).unwrap(), level);
        }
        // Pre-rel/011 persisted entries only ever contain "Read"/"Write" —
        // must deserialize unchanged (no migration, spec §3).
        assert_eq!(serde_json::from_str::<AccessLevel>("\"Write\"").unwrap(), AccessLevel::Write);
    }
}
