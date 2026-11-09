//! Auth module — AuthCache, domain types, and key utilities.
//!
//! System keys layout:
//!   __sys:auth:user:<name>          → serialised UserRecord (JSON)
//!   __sys:auth:perm:<name>:<grant>  → serialised DomainPermission (JSON); <grant> is
//!                                     domain:<d> (whole domain), <d> (key-value),
//!                                     json:<d> or rel:<d>
//!   __sys:oauth:client:<id>         → serialised OAuthClient (JSON), with a TTL until its first code
//!   __sys:oauth:token:<hash>        → serialised TokenRecord (JSON), with a TTL

pub mod handlers;
pub mod middleware;
pub mod oauth;

use crate::control::Engine;
use crate::engines::lsm::engine::{BatchOp, LsmStorageEngine};
use crate::engines::StorageEngine;
use anyhow::Result;
use hex;
use middleware::{permission_domain, split_permission_domain};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub(crate) const PREFIX_USER: &str = "__sys:auth:user:";
pub(crate) const PREFIX_PERM: &str = "__sys:auth:perm:";
/// Longest user name.
pub(crate) const MAX_USER_NAME_LENGTH: usize = 50;

pub(crate) fn user_key(name: &str) -> Vec<u8> {
    format!("{PREFIX_USER}{name}").into_bytes()
}

pub(crate) fn perm_key(name: &str, domain: &str) -> Vec<u8> {
    format!("{PREFIX_PERM}{name}:{domain}").into_bytes()
}

/// The stored keys of every grant of every user on `domain`.
pub(crate) async fn domain_permission_keys(engine: &LsmStorageEngine, domain: &str) -> Result<Vec<Vec<u8>>> {
    let on_domain = |key: &[u8]| {
        let rest = std::str::from_utf8(&key[PREFIX_PERM.len()..]).ok();
        rest.and_then(|rest| rest.split_once(':')).is_some_and(|(_, grant)| split_permission_domain(grant).1 == domain)
    };
    Ok(engine.scan_keys(PREFIX_PERM.as_bytes()).await?.into_iter().filter(|key| on_domain(key)).collect())
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

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    User,
}

/// Ordered Read < Write < Ddl (derive order = declaration order) — a
/// higher grant covers the lower ones (`granted >= required`).
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

/// What one user holds on one domain, by grant: `None` the whole domain.
type Grants = BTreeMap<Option<Engine>, AccessLevel>;

/// The grants of a user on a domain, `held`, once the grant on `engine`
/// (`None` the whole domain) is set to `access` or, without, revoked. A user
/// holds either a grant on the whole domain or grants on engines: a change on
/// the whole domain replaces the engine grants, a change on an engine first
/// splits a whole-domain grant into one of its level per engine.
fn changed(mut held: Grants, engine: Option<Engine>, access: Option<AccessLevel>) -> Grants {
    match engine {
        None => held.clear(),
        Some(_) => {
            if let Some(level) = held.remove(&None) {
                held.extend(Engine::ALL.map(|engine| (Some(engine), level)));
            }
        }
    }
    match access {
        Some(access) => held.insert(engine, access),
        None => held.remove(&engine),
    };
    held
}

/// Every grant a user can hold on a domain.
const GRANTS: [Option<Engine>; 4] = [None, Some(Engine::Kv), Some(Engine::Json), Some(Engine::Rel)];

pub struct AuthCache {
    /// api_key_hash → UserRecord
    users: RwLock<HashMap<String, UserRecord>>,
    /// (username, stored grant, see the module doc) → AccessLevel
    permissions: RwLock<HashMap<(String, String), AccessLevel>>,
    /// OAuth clients and tokens of the MCP listener.
    oauth: RwLock<oauth::OAuthState>,
    /// The resource access tokens must be for, with the MCP listener and
    /// its OAuth on; without, the OAuth state is not even loaded.
    oauth_resource: Option<String>,
    engine: Arc<LsmStorageEngine>,
}

impl AuthCache {
    pub fn new(engine: Arc<LsmStorageEngine>, oauth_resource: Option<String>) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            permissions: RwLock::new(HashMap::new()),
            oauth: RwLock::new(oauth::OAuthState::default()),
            oauth_resource,
            engine,
        }
    }

    /// Loads all auth data from the engine into the in-memory cache.
    ///
    /// Rebuilds both maps rather than merging, so a hash the store no longer
    /// holds stops authenticating. Built off-lock, then swapped in — no
    /// empty-cache window.
    pub async fn load_from_engine(&self) -> Result<()> {
        let user_keys = self
            .engine
            .scan_keys(PREFIX_USER.as_bytes())
            .await?;

        let mut new_users = HashMap::new();
        for k in &user_keys {
            if let Some(bytes) = self.engine.get(k).await? {
                if let Ok(record) = serde_json::from_slice::<UserRecord>(&bytes) {
                    new_users.insert(record.api_key_hash.clone(), record);
                }
            }
        }

        let perm_keys = self
            .engine
            .scan_keys(PREFIX_PERM.as_bytes())
            .await?;

        let mut new_perms = HashMap::new();
        for k in &perm_keys {
            if let Some(bytes) = self.engine.get(k).await? {
                if let Ok(perm) = serde_json::from_slice::<DomainPermission>(&bytes) {
                    new_perms.insert((perm.username.clone(), perm.domain.clone()), perm.access);
                }
            }
        }

        let new_oauth = if self.oauth_resource.is_some() { oauth::load(&self.engine).await? } else { oauth::OAuthState::default() };

        *self.users.write().await = new_users;
        *self.permissions.write().await = new_perms;
        *self.oauth.write().await = new_oauth;

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
                access: *a,
            })
            .collect()
    }

    /// The level `username` holds on `engine` of `domain`: the grant on the
    /// whole domain, else the grant on the engine. Without an engine, on the
    /// domain as a whole: the grant on the whole domain, else the highest
    /// engine grant.
    pub async fn effective(&self, username: &str, domain: &str, engine: Option<Engine>) -> Option<AccessLevel> {
        let permissions = self.permissions.read().await;
        let level = |grant| permissions.get(&(username.to_string(), permission_domain(grant, domain))).copied();
        level(None).or_else(|| match engine {
            Some(engine) => level(Some(engine)),
            None => Engine::ALL.into_iter().filter_map(|engine| level(Some(engine))).max(),
        })
    }

    /// Persists and caches a UserRecord.
    ///
    /// Drops any existing entry for the same name before inserting under the
    /// new hash — a name maps to exactly one valid hash, matching the engine.
    pub async fn upsert_user(&self, record: UserRecord) -> Result<()> {
        let key = user_key(&record.name);
        let value = serde_json::to_vec(&record)?;
        self.engine.put(&key, &value).await?;

        let mut users = self.users.write().await;
        users.retain(|_, r| r.name != record.name);
        users.insert(record.api_key_hash.clone(), record);
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

    /// Sets the grant of `username` on `engine` of `domain` (`None` the whole
    /// domain) to `access`, or revokes it without, under the rule of
    /// [`changed`]; every key it touches changes in one write. Changes run
    /// one at a time (the control plane's worker).
    pub async fn change_permission(
        &self,
        username: &str,
        domain: &str,
        engine: Option<Engine>,
        access: Option<AccessLevel>,
    ) -> Result<()> {
        let entry = |grant| (username.to_string(), permission_domain(grant, domain));
        let held: Grants = {
            let permissions = self.permissions.read().await;
            GRANTS.into_iter().filter_map(|grant| permissions.get(&entry(grant)).map(|level| (grant, *level))).collect()
        };
        let wanted = changed(held.clone(), engine, access);
        let mut ops = Vec::new();
        for grant in GRANTS {
            let key = perm_key(username, &entry(grant).1);
            match wanted.get(&grant) {
                Some(&access) if held.get(&grant) != Some(&access) => {
                    let perm = DomainPermission { username: username.to_string(), domain: entry(grant).1, access };
                    ops.push(BatchOp::Put { key, value: serde_json::to_vec(&perm)? });
                }
                None if held.contains_key(&grant) => ops.push(BatchOp::Delete { key }),
                _ => {}
            }
        }
        self.engine.write_batch(ops).await?;
        let mut permissions = self.permissions.write().await;
        for grant in GRANTS {
            match wanted.get(&grant) {
                Some(&access) => permissions.insert(entry(grant), access),
                None => permissions.remove(&entry(grant)),
            };
        }
        Ok(())
    }

    /// Writes `with` and removes every grant of every user on `domain`, in one write.
    pub async fn remove_domain(&self, domain: &str, with: BatchOp) -> Result<()> {
        let held: Vec<(String, String)> = {
            let permissions = self.permissions.read().await;
            permissions.keys().filter(|(_, grant)| split_permission_domain(grant).1 == domain).cloned().collect()
        };
        let mut ops = vec![with];
        ops.extend(held.iter().map(|(user, grant)| BatchOp::Delete { key: perm_key(user, grant) }));
        self.engine.write_batch(ops).await?;
        let mut permissions = self.permissions.write().await;
        for entry in &held {
            permissions.remove(entry);
        }
        Ok(())
    }

    /// Writes one permission as it is, past the rule of [`changed`].
    #[cfg(test)]
    pub async fn set_permission(&self, perm: DomainPermission) -> Result<()> {
        let key = perm_key(&perm.username, &perm.domain);
        self.engine.put(&key, &serde_json::to_vec(&perm)?).await?;
        self.permissions.write().await.insert((perm.username.clone(), perm.domain.clone()), perm.access);
        Ok(())
    }
}

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
        // Entries persisted before `Ddl` existed only contain "Read"/"Write" —
        // must deserialize unchanged (no migration).
        assert_eq!(serde_json::from_str::<AccessLevel>("\"Write\"").unwrap(), AccessLevel::Write);
    }

    async fn test_cache() -> (AuthCache, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(dir.path()));
        let engine = Arc::new(
            crate::engines::lsm::engine::LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        (AuthCache::new(engine, None), dir)
    }

    /// A user record overwritten by name with a different api_key_hash —
    /// reloading must drop the superseded hash, not keep it alongside the
    /// new one.
    #[test]
    fn load_from_engine_drops_superseded_key_hash() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            let hash_a = hash_api_key("lura_first");
            let hash_b = hash_api_key("lura_second");

            let mut record = UserRecord {
                name: "alice".to_string(),
                api_key_hash: hash_a.clone(),
                role: UserRole::User,
                created_at: 0,
            };
            let key = user_key(&record.name);
            let value = serde_json::to_vec(&record).unwrap();
            cache.engine.put(&key, &value).await.unwrap();
            cache.load_from_engine().await.unwrap();
            assert!(cache.get_user_by_key_hash(&hash_a).await.is_some());

            // The same record, overwritten by name with a new key hash.
            record.api_key_hash = hash_b.clone();
            let value = serde_json::to_vec(&record).unwrap();
            cache.engine.put(&key, &value).await.unwrap();
            cache.load_from_engine().await.unwrap();

            assert!(cache.get_user_by_key_hash(&hash_a).await.is_none());
            assert!(cache.get_user_by_key_hash(&hash_b).await.is_some());
            assert_eq!(cache.all_users().await.len(), 1);
        })
    }

    /// upsert_user must drop the previous hash for the same name, not add
    /// the new one alongside it.
    #[test]
    fn upsert_user_replaces_previous_hash_for_same_name() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            let hash1 = hash_api_key("lura_first");
            let hash2 = hash_api_key("lura_second");

            cache
                .upsert_user(UserRecord {
                    name: "a".to_string(),
                    api_key_hash: hash1.clone(),
                    role: UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();
            cache
                .upsert_user(UserRecord {
                    name: "a".to_string(),
                    api_key_hash: hash2.clone(),
                    role: UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();

            assert!(cache.get_user_by_key_hash(&hash1).await.is_none());
            assert!(cache.get_user_by_key_hash(&hash2).await.is_some());
            assert_eq!(
                cache.get_user_by_name("a").await.unwrap().api_key_hash,
                hash2
            );
        })
    }

    /// Rotation scenario: reconcile_admins is the documented way to rotate an
    /// admin key on restart. A cache pre-populated the way load_from_engine
    /// leaves it (old hash from the persisted record), followed by
    /// reconcile_admins with a changed api_key for the same admin name, must
    /// invalidate the old hash — not leave both valid.
    #[test]
    fn reconcile_admins_rotation_invalidates_old_hash() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            let old_key = "lura_old_admin_key";
            let new_key = "lura_new_admin_key";
            let old_hash = hash_api_key(old_key);
            let new_hash = hash_api_key(new_key);

            let old_record = UserRecord {
                name: "admin".to_string(),
                api_key_hash: old_hash.clone(),
                role: UserRole::Admin,
                created_at: 0,
            };
            let key = user_key(&old_record.name);
            let value = serde_json::to_vec(&old_record).unwrap();
            cache.engine.put(&key, &value).await.unwrap();
            cache.load_from_engine().await.unwrap();
            assert!(cache.get_user_by_key_hash(&old_hash).await.is_some());

            let admins = vec![crate::config::AdminEntry {
                name: "admin".to_string(),
                api_key: new_key.to_string(),
            }];
            reconcile_admins(&cache, &admins, true).await.unwrap();

            assert!(cache.get_user_by_key_hash(&old_hash).await.is_none());
            assert!(cache.get_user_by_key_hash(&new_hash).await.is_some());
            assert_eq!(
                cache.get_user_by_name("admin").await.unwrap().api_key_hash,
                new_hash
            );
        })
    }

    use crate::control::Engine;

    /// Every level `user` holds on `domain`, by grant: `None` the whole domain.
    async fn held(cache: &AuthCache, user: &str, domain: &str) -> Vec<(Option<Engine>, AccessLevel)> {
        let mut held: Vec<_> = cache
            .permissions_for_user(user)
            .await
            .iter()
            .filter_map(|p| {
                let (engine, on) = split_permission_domain(&p.domain);
                (on == domain).then_some((engine, p.access))
            })
            .collect();
        held.sort();
        held
    }

    /// What a fresh cache over the same store holds: the store matches the cache.
    async fn reloaded(cache: &AuthCache, user: &str, domain: &str) -> Vec<(Option<Engine>, AccessLevel)> {
        let fresh = AuthCache::new(Arc::clone(&cache.engine), None);
        fresh.load_from_engine().await.unwrap();
        held(&fresh, user, domain).await
    }

    const ENGINES: [Option<Engine>; 3] = [Some(Engine::Kv), Some(Engine::Json), Some(Engine::Rel)];

    #[test]
    fn a_domain_grant_holds_in_every_engine_and_an_engine_grant_only_in_its_own() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", None, Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ben", "shop", Some(Engine::Json), Some(AccessLevel::Read)).await.unwrap();
            for engine in ENGINES {
                assert_eq!(cache.effective("ana", "shop", engine).await, Some(AccessLevel::Write), "{engine:?}");
            }
            assert_eq!(cache.effective("ana", "shop", None).await, Some(AccessLevel::Write));
            assert_eq!(cache.effective("ana", "other", None).await, None);
            assert_eq!(cache.effective("ben", "shop", Some(Engine::Json)).await, Some(AccessLevel::Read));
            assert_eq!(cache.effective("ben", "shop", Some(Engine::Kv)).await, None);
            assert_eq!(cache.effective("ben", "shop", Some(Engine::Rel)).await, None);
            assert_eq!(cache.effective("ben", "shop", None).await, Some(AccessLevel::Read));
        })
    }

    // Without an engine, the highest engine grant counts.
    #[test]
    fn the_domain_as_a_whole_reads_the_highest_engine_grant() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", Some(Engine::Kv), Some(AccessLevel::Read)).await.unwrap();
            cache.change_permission("ana", "shop", Some(Engine::Rel), Some(AccessLevel::Ddl)).await.unwrap();
            assert_eq!(cache.effective("ana", "shop", None).await, Some(AccessLevel::Ddl));
        })
    }

    #[test]
    fn a_domain_grant_replaces_the_engine_grants() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            for engine in ENGINES {
                cache.change_permission("ana", "shop", engine, Some(AccessLevel::Write)).await.unwrap();
            }
            cache.change_permission("ana", "other", Some(Engine::Kv), Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ana", "shop", None, Some(AccessLevel::Read)).await.unwrap();
            let expected = vec![(None, AccessLevel::Read)];
            assert_eq!(held(&cache, "ana", "shop").await, expected);
            assert_eq!(reloaded(&cache, "ana", "shop").await, expected);
            assert_eq!(held(&cache, "ana", "other").await, vec![(Some(Engine::Kv), AccessLevel::Write)]);
        })
    }

    // A downgrade through the domain grant holds: no engine grant beside it
    // keeps the higher level.
    #[test]
    fn a_domain_grant_downgrades_an_engine_grant() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", Some(Engine::Kv), Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ana", "shop", None, Some(AccessLevel::Read)).await.unwrap();
            assert_eq!(cache.effective("ana", "shop", Some(Engine::Kv)).await, Some(AccessLevel::Read));
        })
    }

    #[test]
    fn an_engine_grant_splits_the_domain_grant() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", None, Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ana", "shop", Some(Engine::Rel), Some(AccessLevel::Ddl)).await.unwrap();
            let expected = vec![
                (Some(Engine::Kv), AccessLevel::Write),
                (Some(Engine::Json), AccessLevel::Write),
                (Some(Engine::Rel), AccessLevel::Ddl),
            ];
            assert_eq!(held(&cache, "ana", "shop").await, expected);
            assert_eq!(reloaded(&cache, "ana", "shop").await, expected);
        })
    }

    #[test]
    fn revoking_one_engine_of_a_domain_grant_keeps_the_other_two() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", None, Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ana", "shop", Some(Engine::Kv), None).await.unwrap();
            let expected = vec![(Some(Engine::Json), AccessLevel::Write), (Some(Engine::Rel), AccessLevel::Write)];
            assert_eq!(held(&cache, "ana", "shop").await, expected);
            assert_eq!(reloaded(&cache, "ana", "shop").await, expected);
            assert_eq!(cache.effective("ana", "shop", Some(Engine::Kv)).await, None);
        })
    }

    #[test]
    fn revoking_the_domain_removes_every_grant_on_it() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", Some(Engine::Kv), Some(AccessLevel::Read)).await.unwrap();
            cache.change_permission("ana", "shop", Some(Engine::Json), Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ana", "other", None, Some(AccessLevel::Read)).await.unwrap();
            cache.change_permission("ana", "shop", None, None).await.unwrap();
            assert_eq!(held(&cache, "ana", "shop").await, vec![]);
            assert_eq!(reloaded(&cache, "ana", "shop").await, vec![]);
            assert_eq!(held(&cache, "ana", "other").await, vec![(None, AccessLevel::Read)]);
        })
    }

    // A grant stored without a prefix, as every key-value grant before
    // whole-domain grants, stays a key-value grant.
    #[test]
    fn a_stored_grant_without_a_prefix_stays_a_key_value_grant() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            let perm = DomainPermission { username: "ana".into(), domain: "shop".into(), access: AccessLevel::Write };
            cache.engine.put(&perm_key("ana", "shop"), &serde_json::to_vec(&perm).unwrap()).await.unwrap();
            cache.load_from_engine().await.unwrap();
            assert_eq!(cache.effective("ana", "shop", Some(Engine::Kv)).await, Some(AccessLevel::Write));
            assert_eq!(cache.effective("ana", "shop", Some(Engine::Json)).await, None);
            assert_eq!(cache.effective("ana", "shop", Some(Engine::Rel)).await, None);
        })
    }

    #[test]
    fn removing_a_domain_drops_the_grants_of_every_user_on_it() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            cache.change_permission("ana", "shop", None, Some(AccessLevel::Write)).await.unwrap();
            cache.change_permission("ben", "shop", Some(Engine::Json), Some(AccessLevel::Read)).await.unwrap();
            cache.change_permission("ben", "shop", Some(Engine::Kv), Some(AccessLevel::Read)).await.unwrap();
            cache.change_permission("ben", "keep", Some(Engine::Kv), Some(AccessLevel::Read)).await.unwrap();
            let marker = BatchOp::Put { key: b"__sys:test:marker".to_vec(), value: b"1".to_vec() };
            cache.remove_domain("shop", marker).await.unwrap();
            for user in ["ana", "ben"] {
                assert_eq!(held(&cache, user, "shop").await, vec![], "{user}");
                assert_eq!(reloaded(&cache, user, "shop").await, vec![], "{user}");
            }
            assert_eq!(held(&cache, "ben", "keep").await, vec![(Some(Engine::Kv), AccessLevel::Read)]);
            assert!(cache.engine.get(b"__sys:test:marker").await.unwrap().is_some(), "the write it came with");
        })
    }

    /// Upserting one user must not disturb another user's cached hash.
    #[test]
    fn upsert_user_leaves_other_users_untouched() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = test_cache().await;
            let hash_a1 = hash_api_key("lura_a1");
            let hash_a2 = hash_api_key("lura_a2");
            let hash_b = hash_api_key("lura_b");

            cache
                .upsert_user(UserRecord {
                    name: "a".to_string(),
                    api_key_hash: hash_a1.clone(),
                    role: UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();
            cache
                .upsert_user(UserRecord {
                    name: "b".to_string(),
                    api_key_hash: hash_b.clone(),
                    role: UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();
            cache
                .upsert_user(UserRecord {
                    name: "a".to_string(),
                    api_key_hash: hash_a2.clone(),
                    role: UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();

            assert!(cache.get_user_by_key_hash(&hash_a1).await.is_none());
            assert!(cache.get_user_by_key_hash(&hash_a2).await.is_some());
            assert!(cache.get_user_by_key_hash(&hash_b).await.is_some());
        })
    }
}
