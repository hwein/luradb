//! Domain management layer for logical isolation and multi-tenancy.
//!
//! Implements a domain-scoped facade over `LsmStorageEngine`. Each domain gets a
//! deterministic system prefix derived from its name via FNV-64a; all KV operations
//! are transparently prefixed so keys from different domains never collide.
//!
//! Spec 009 additions:
//! - `DomainState`: active vs. deleting (lazy background purge).
//! - `DomainRuntime`: non-serializable per-domain state (rate limiter).
//! - `DomainPurger`: background task that tombstones keys of deleting domains.
//!
//! Spec 013: `DomainCacheStats` replaced by `MetricsStore` integration.

use crate::core::events::Resume;
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::rate_limiter::{DomainQuota, RateLimiter};
use crate::engines::lsm::reader::{GetResult, Snapshot};
use crate::engines::lsm::watcher::{WalEvent, WatchMessage};
use crate::metrics::MetricsStore;
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{broadcast, Mutex};
use tokio::time::{sleep, Duration};

// ── Constants ────────────────────────────────────────────────────────────────

const SYS_DOMAIN_PREFIX: &[u8] = b"__sys:domain:";

// ── DomainConfig ──────────────────────────────────────────────────────────────

/// Configuration for the domain management layer.
pub struct DomainConfig {
    pub max_name_length: usize,
    pub max_user_key_length: usize,
    pub default_domain: String,
    pub default_read_iops: u32,
    pub default_write_iops: u32,
    pub default_max_storage_bytes: u64,
    pub purger_batch_size: usize,
    pub purger_interval_secs: u64,
}

impl Default for DomainConfig {
    fn default() -> Self {
        Self {
            max_name_length: 50,
            max_user_key_length: 256,
            default_domain: "default".to_string(),
            default_read_iops: 1000,
            default_write_iops: 500,
            default_max_storage_bytes: 0,
            purger_batch_size: 100,
            purger_interval_secs: 5,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Absolute expiry stamp for a TTL in seconds. The extra second compensates the
/// sub-second remainder `now_secs()` drops, which would expire the entry early.
pub(crate) fn expire_at_from_ttl(ttl_secs: u64) -> u64 {
    if ttl_secs == 0 { now_secs() } else { now_secs() + ttl_secs + 1 }
}

pub(crate) fn fnv64(data: &[u8]) -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut h = OFFSET;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

fn generate_prefix(name: &str) -> Vec<u8> {
    format!("d:{:016x}:", fnv64(name.as_bytes())).into_bytes()
}

fn validate_domain_name(name: &str, max_len: usize) -> Result<()> {
    anyhow::ensure!(!name.is_empty(), "Domain name must not be empty");
    anyhow::ensure!(
        name.len() <= max_len,
        "Domain name '{}' exceeds maximum of {} characters",
        name,
        max_len
    );
    anyhow::ensure!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "Domain name '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
        name
    );
    Ok(())
}

fn sys_key(name: &str) -> Vec<u8> {
    let mut k = SYS_DOMAIN_PREFIX.to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

// ── DomainState ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum DomainState {
    #[default]
    Active,
    Deleting,
}

// ── Domain ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    pub name: String,
    pub system_prefix: Vec<u8>,
    pub created_at: u64,
    /// Lifecycle state — `Active` or `Deleting` (lazy background purge).
    #[serde(default)]
    pub state: DomainState,
}

impl Domain {
    fn new(name: &str) -> Self {
        Domain {
            name: name.to_string(),
            system_prefix: generate_prefix(name),
            created_at: now_secs(),
            state: DomainState::Active,
        }
    }
}

// ── DomainRuntime ─────────────────────────────────────────────────────────────

/// Non-serializable, per-domain in-memory state.
struct DomainRuntime {
    rate_limiter: RateLimiter,
}

impl DomainRuntime {
    fn new(quota: DomainQuota) -> Arc<Self> {
        Arc::new(Self {
            rate_limiter: RateLimiter::new(quota),
        })
    }
}

// ── DomainRegistry ────────────────────────────────────────────────────────────

/// Manages domain lifecycle: creation, lookup, listing, deletion, and recovery.
pub struct DomainRegistry {
    /// Persistent domain metadata (name → Domain), cached in memory.
    domains: RwLock<HashMap<String, Domain>>,
    /// Non-serializable runtime state (rate limiter).
    runtimes: RwLock<HashMap<String, Arc<DomainRuntime>>>,
    /// Serializes `create_domain` end-to-end: the check-then-act spans an
    /// `.await`, so a `parking_lot` guard cannot cover it (spec general/003).
    create_lock: Mutex<()>,
    engine: Arc<LsmStorageEngine>,
    config: DomainConfig,
    metrics: Arc<MetricsStore>,
}

impl DomainRegistry {
    /// Recovers the registry from the engine, then creates the default domain
    /// if it is missing in any state.
    pub async fn recover(
        engine: Arc<LsmStorageEngine>,
        config: DomainConfig,
        metrics: Arc<MetricsStore>,
    ) -> Result<Self> {
        let default_domain = config.default_domain.clone();
        let registry = Self {
            domains: RwLock::new(HashMap::new()),
            runtimes: RwLock::new(HashMap::new()),
            create_lock: Mutex::new(()),
            engine,
            config,
            metrics,
        };
        registry.load_from_engine().await?;
        // Check in any state: creating over a Deleting default would 409 and
        // abort every boot. The purger finalizes it; the next recover() then
        // recreates it.
        let default_state = registry.domains.read().get(&default_domain).map(|d| d.state.clone());
        match default_state {
            None => {
                registry.create_domain(&default_domain).await?;
            }
            Some(DomainState::Deleting) => tracing::warn!(
                "[DomainRegistry] default domain is Deleting at startup; \
                 it will be recreated on the first start after the purge finishes"
            ),
            Some(DomainState::Active) => {}
        }
        Ok(registry)
    }

    /// Returns a reference to the underlying storage engine.
    pub fn engine(&self) -> &Arc<LsmStorageEngine> {
        &self.engine
    }

    fn make_runtime(&self) -> Arc<DomainRuntime> {
        DomainRuntime::new(DomainQuota {
            read_iops: self.config.default_read_iops,
            write_iops: self.config.default_write_iops,
            max_storage_bytes: self.config.default_max_storage_bytes,
        })
    }

    async fn load_from_engine(&self) -> Result<()> {
        let sys_keys = self.engine.scan_keys(SYS_DOMAIN_PREFIX).await?;
        let mut cache = self.domains.write();
        let mut runtimes = self.runtimes.write();
        for key in sys_keys {
            let snap = self.engine.snapshot();
            match self.engine.get_with_snapshot(&key, snap.snapshot()).await?.into_option() {
                Some(value) => match serde_json::from_slice::<Domain>(&value) {
                    Ok(domain) => {
                        runtimes.insert(domain.name.clone(), self.make_runtime());
                        cache.insert(domain.name.clone(), domain);
                    }
                    Err(e) => eprintln!(
                        "[DomainRegistry] Cannot deserialize domain at key {:?}: {e}",
                        key
                    ),
                },
                None => {}
            }
        }
        Ok(())
    }

    /// Creates a new domain. Returns `Err` (409-style) if the name already exists.
    pub async fn create_domain(&self, name: &str) -> Result<Domain> {
        validate_domain_name(name, self.config.max_name_length)?;
        let _guard = self.create_lock.lock().await;
        if self.domains.read().contains_key(name) {
            return Err(anyhow!("409 Conflict: Domain '{}' already exists", name));
        }
        let domain = Domain::new(name);
        let data = serde_json::to_vec(&domain)?;
        self.engine.put(&sys_key(name), &data).await?;
        self.runtimes.write().insert(name.to_string(), self.make_runtime());
        self.domains.write().insert(name.to_string(), domain.clone());
        Ok(domain)
    }

    /// Looks up an **active** domain by name. Returns `None` for deleting domains.
    pub async fn get_domain(&self, name: &str) -> Result<Option<Domain>> {
        {
            let cache = self.domains.read();
            if let Some(d) = cache.get(name) {
                if d.state == DomainState::Deleting {
                    return Ok(None);
                }
                return Ok(Some(d.clone()));
            }
        }
        // Engine fallback (e.g. after a cold start that didn't hit load_from_engine).
        let key = sys_key(name);
        let snap = self.engine.snapshot();
        if let Some(value) = self.engine.get_with_snapshot(&key, snap.snapshot()).await?.into_option() {
            let domain: Domain = serde_json::from_slice(&value)?;
            if domain.state == DomainState::Deleting {
                return Ok(None);
            }
            let rt = self.make_runtime();
            self.runtimes
                .write()
                .entry(name.to_string())
                .or_insert_with(|| rt);
            self.domains.write().insert(name.to_string(), domain.clone());
            return Ok(Some(domain));
        }
        Ok(None)
    }

    /// Lists all **active** domains.
    pub async fn list_domains(&self) -> Result<Vec<Domain>> {
        Ok(self
            .domains
            .read()
            .values()
            .filter(|d| d.state == DomainState::Active)
            .cloned()
            .collect())
    }

    /// Transitions the domain to `Deleting` state and persists the change.
    ///
    /// Returns `Err` if the domain doesn't exist. Physical key cleanup is
    /// handled asynchronously by `DomainPurger`.
    pub async fn delete_domain(&self, name: &str) -> Result<()> {
        let mut domain = {
            let cache = self.domains.read();
            cache
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("404 Not Found: Domain '{}' not found", name))?
        };
        domain.state = DomainState::Deleting;
        let data = serde_json::to_vec(&domain)?;
        self.engine.put(&sys_key(name), &data).await?;
        self.domains.write().insert(name.to_string(), domain);
        Ok(())
    }

    /// Lists domains currently in `Deleting` state (used by `DomainPurger`).
    pub fn list_deleting_domains(&self) -> Vec<Domain> {
        self.domains
            .read()
            .values()
            .filter(|d| d.state == DomainState::Deleting)
            .cloned()
            .collect()
    }

    /// Finalises a purged domain: removes metadata from engine and cache.
    pub async fn finalize_domain_deletion(&self, name: &str) -> Result<()> {
        self.engine.write_tombstone(&sys_key(name)).await?;
        // runtimes before domains: a create_domain that passed the domains
        // check can then never lose its freshly inserted runtime.
        self.runtimes.write().remove(name);
        self.domains.write().remove(name);
        self.metrics.remove_domain(name);
        Ok(())
    }

    /// Returns a `DomainStore` for the named **active** domain.
    ///
    /// Returns `Err` with "410 Gone" prefix if the domain is in `Deleting` state,
    /// or "404 Not Found" prefix if it doesn't exist.
    pub async fn store(&self, name: &str) -> Result<DomainStore> {
        let (domain, runtime) = {
            let cache = self.domains.read();
            match cache.get(name) {
                None => return Err(anyhow!("404 Not Found: Domain '{}' not found", name)),
                Some(d) if d.state == DomainState::Deleting => {
                    return Err(anyhow!("410 Gone: Domain '{}' is being deleted", name));
                }
                Some(d) => {
                    let rt = self
                        .runtimes
                        .read()
                        .get(name)
                        .cloned()
                        .ok_or_else(|| anyhow!("internal: no runtime for domain '{}'", name))?;
                    (d.clone(), rt)
                }
            }
        };
        Ok(DomainStore {
            domain,
            engine: Arc::clone(&self.engine),
            runtime,
            max_user_key_len: self.config.max_user_key_length,
            metrics: Arc::clone(&self.metrics),
        })
    }

    /// Returns a `DomainStore` for the built-in default domain.
    pub async fn default_store(&self) -> Result<DomainStore> {
        self.store(&self.config.default_domain).await
    }
}

// ── DomainStore ───────────────────────────────────────────────────────────────

/// Domain-scoped facade over `LsmStorageEngine`.
///
/// All operations transparently prepend `domain.system_prefix` to every key
/// and enforce per-domain rate limits before touching the engine.
pub struct DomainStore {
    domain: Domain,
    engine: Arc<LsmStorageEngine>,
    runtime: Arc<DomainRuntime>,
    max_user_key_len: usize,
    metrics: Arc<MetricsStore>,
}

/// Key metadata without the value bytes (spec kv/022): TTL expiry and the
/// write time of the newest visible version. Backs `GET …/{key}/meta`;
/// never dereferences a VLog pointer.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyMeta {
    /// Absolute Unix seconds; 0 = no TTL set.
    pub expire_at: u64,
    /// Unix milliseconds of the newest visible version's write.
    pub last_modified_ms: u64,
}

/// Result of starting (or resuming) a KV watch (spec kv/024 §4.3):
/// `resume` is already domain-filtered/stripped, `rx` is the live stream.
pub struct WatchStart {
    pub resume: Resume<WalEvent>,
    pub rx: broadcast::Receiver<WatchMessage>,
}

impl DomainStore {
    fn prefixed_key(&self, user_key: &[u8]) -> Vec<u8> {
        let mut k = self.domain.system_prefix.clone();
        k.extend_from_slice(user_key);
        k
    }

    fn validate_user_key(&self, key: &[u8]) -> Result<()> {
        anyhow::ensure!(!key.is_empty(), "400 Bad Request: Key must not be empty");
        anyhow::ensure!(
            key.len() <= self.max_user_key_len,
            "400 Bad Request: Key length {} exceeds maximum of {} bytes",
            key.len(),
            self.max_user_key_len
        );
        anyhow::ensure!(
            std::str::from_utf8(key).is_ok(),
            "400 Bad Request: key must be valid UTF-8"
        );
        Ok(())
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// Upserts a key-value pair in this domain.
    pub async fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.validate_user_key(key)?;
        if !self.runtime.rate_limiter.check_write() {
            self.metrics.record_rate_limit_rejection(&self.domain.name);
            return Err(anyhow!("429 Too Many Requests: write rate limit exceeded"));
        }
        let start = std::time::Instant::now();
        self.engine.write_kv_pair(&self.prefixed_key(key), value, None).await?;
        self.metrics.record_write(&self.domain.name, start.elapsed().as_micros() as u64);
        Ok(())
    }

    /// Upserts a key-value pair with a TTL (seconds from now).
    pub async fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_secs: u64) -> Result<()> {
        self.validate_user_key(key)?;
        if !self.runtime.rate_limiter.check_write() {
            self.metrics.record_rate_limit_rejection(&self.domain.name);
            return Err(anyhow!("429 Too Many Requests: write rate limit exceeded"));
        }
        let expire_at = expire_at_from_ttl(ttl_secs);
        let start = std::time::Instant::now();
        self.engine.write_kv_pair(&self.prefixed_key(key), value, Some(expire_at)).await?;
        self.metrics.record_write(&self.domain.name, start.elapsed().as_micros() as u64);
        Ok(())
    }

    /// Reads a value by user key — three-valued (spec kv/018): `Present`,
    /// `Null` (key exists in the NULL state), or `Absent`. Records latency
    /// and hit/miss in MetricsStore (a `Null` read counts as a hit).
    pub async fn get(&self, key: &[u8]) -> Result<GetResult> {
        Ok(self.get_with_expiry(key).await?.0)
    }

    /// Like [`Self::get`], but also returns `expire_at` (absolute Unix
    /// seconds, 0 = no TTL) — spec kv/022, backs the `X-Expires-At` response
    /// header. Same validation, rate-limiting and hit/miss accounting as
    /// `get`; unlike [`Self::get_with_snapshot`] this acquires its own
    /// snapshot and goes through the read rate limiter.
    pub async fn get_with_expiry(&self, key: &[u8]) -> Result<(GetResult, u64)> {
        self.validate_user_key(key)?;
        if !self.runtime.rate_limiter.check_read() {
            self.metrics.record_rate_limit_rejection(&self.domain.name);
            return Err(anyhow!("429 Too Many Requests: read rate limit exceeded"));
        }
        let start = std::time::Instant::now();
        let snap = self.engine.snapshot();
        let result = self
            .engine
            .get_with_expiry(&self.prefixed_key(key), snap.snapshot())
            .await?;
        let elapsed_us = start.elapsed().as_micros() as u64;
        self.metrics.record_read(&self.domain.name, elapsed_us, !matches!(result.0, GetResult::Absent));
        Ok(result)
    }

    /// Reads a key's TTL expiry and last-modified time without its value
    /// bytes (spec kv/022) — backs `GET …/{key}/meta`; never dereferences a
    /// VLog pointer. Same validation and rate-limiting as `get`, including
    /// the same hit/miss rule (a `Null` key is a hit, only an absent key is
    /// a miss) — the read still spends a rate-limit token on the domain path.
    pub async fn get_meta(&self, key: &[u8]) -> Result<Option<KeyMeta>> {
        self.validate_user_key(key)?;
        if !self.runtime.rate_limiter.check_read() {
            self.metrics.record_rate_limit_rejection(&self.domain.name);
            return Err(anyhow!("429 Too Many Requests: read rate limit exceeded"));
        }
        let start = std::time::Instant::now();
        let snap = self.engine.snapshot();
        let result = self
            .engine
            .get_with_metadata(&self.prefixed_key(key), snap.snapshot())
            .await?;
        let elapsed_us = start.elapsed().as_micros() as u64;
        self.metrics.record_read(&self.domain.name, elapsed_us, result.is_some());
        Ok(result.map(|m| KeyMeta { expire_at: m.expire_at, last_modified_ms: m.last_modified_ms }))
    }

    /// Tombstones a key (hard delete).
    pub async fn delete(&self, key: &[u8]) -> Result<()> {
        self.validate_user_key(key)?;
        if !self.runtime.rate_limiter.check_write() {
            self.metrics.record_rate_limit_rejection(&self.domain.name);
            return Err(anyhow!("429 Too Many Requests: write rate limit exceeded"));
        }
        let start = std::time::Instant::now();
        self.engine.write_tombstone(&self.prefixed_key(key)).await?;
        self.metrics.record_write(&self.domain.name, start.elapsed().as_micros() as u64);
        Ok(())
    }

    /// Sets a key to the technical NULL state (spec kv/018): an update, not a
    /// delete — the key stays visible with no value and appears in scans. A
    /// non-existent key is upserted into the NULL state.
    pub async fn set_null(&self, key: &[u8]) -> Result<()> {
        self.validate_user_key(key)?;
        if !self.runtime.rate_limiter.check_write() {
            self.metrics.record_rate_limit_rejection(&self.domain.name);
            return Err(anyhow!("429 Too Many Requests: write rate limit exceeded"));
        }
        let start = std::time::Instant::now();
        self.engine.write_null(&self.prefixed_key(key)).await?;
        self.metrics.record_write(&self.domain.name, start.elapsed().as_micros() as u64);
        Ok(())
    }

    /// Returns all live user-keys whose raw form starts with `prefix`.
    pub async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !self.runtime.rate_limiter.check_read() {
            return Err(anyhow!("429 Too Many Requests: read rate limit exceeded"));
        }
        let full_prefix = self.prefixed_key(prefix);
        let raw_keys = self.engine.scan_keys(&full_prefix).await?;
        let prefix_len = self.domain.system_prefix.len();
        Ok(raw_keys.into_iter().map(|k| k[prefix_len..].to_vec()).collect())
    }

    /// Counts live user-keys whose raw form starts with `prefix` — same scan
    /// as `scan_keys` (spec general/017), without materializing the stripped
    /// key strings.
    pub async fn count_keys(&self, prefix: &[u8]) -> Result<u64> {
        if !self.runtime.rate_limiter.check_read() {
            return Err(anyhow!("429 Too Many Requests: read rate limit exceeded"));
        }
        let full_prefix = self.prefixed_key(prefix);
        Ok(self.engine.scan_keys(&full_prefix).await?.len() as u64)
    }

    /// Test-only: drains and locks this domain's read bucket so the next
    /// read deterministically answers 429 — no refill race no matter how
    /// slow the test runs (flaky-test fix, spec general/008 pattern).
    #[cfg(test)]
    pub fn drain_read_budget_for_test(&self) {
        self.runtime.rate_limiter.read_bucket.drain_for_test();
    }

    /// Restore-path upsert (spec general/006): same key validation as
    /// [`Self::put`]/[`Self::put_with_ttl`] but takes the absolute
    /// `expire_at` directly (no now-relative round trip) and bypasses the
    /// rate limiter (admin maintenance operation, per spec general/006's
    /// authorization section — the restore throttle is `scan_batch_size`/
    /// `scan_pause_ms`).
    pub(crate) async fn put_unthrottled(&self, key: &[u8], value: &[u8], expire_at: Option<u64>) -> Result<()> {
        self.validate_user_key(key)?;
        let start = std::time::Instant::now();
        self.engine.write_kv_pair(&self.prefixed_key(key), value, expire_at).await?;
        self.metrics.record_write(&self.domain.name, start.elapsed().as_micros() as u64);
        Ok(())
    }

    /// Restore-path variant of [`Self::set_null`] — same rate-limiter bypass
    /// rationale as [`Self::put_unthrottled`].
    pub(crate) async fn set_null_unthrottled(&self, key: &[u8]) -> Result<()> {
        self.validate_user_key(key)?;
        let start = std::time::Instant::now();
        self.engine.write_null(&self.prefixed_key(key)).await?;
        self.metrics.record_write(&self.domain.name, start.elapsed().as_micros() as u64);
        Ok(())
    }

    /// Reads a value against an externally held snapshot, with `expire_at`
    /// (spec general/006 backup export) instead of acquiring a snapshot
    /// internally like [`Self::get`] — lets the backup writer pin every read
    /// of a domain export to the same point in time. Bypasses the rate
    /// limiter (admin maintenance operation, per spec general/006's
    /// authorization section).
    pub async fn get_with_snapshot(&self, key: &[u8], snapshot: &Snapshot) -> Result<(GetResult, u64)> {
        self.validate_user_key(key)?;
        self.engine.get_with_expiry(&self.prefixed_key(key), snapshot).await
    }

    /// Returns all user-keys (raw form) visible under `snapshot` and
    /// starting with `prefix` (spec general/006 backup export) — the
    /// snapshot-pinned counterpart of [`Self::scan_keys`]. Bypasses the rate
    /// limiter (admin maintenance operation).
    pub async fn scan_keys_with_snapshot(&self, prefix: &[u8], snapshot: &Snapshot) -> Result<Vec<Vec<u8>>> {
        let full_prefix = self.prefixed_key(prefix);
        let raw_keys = self.engine.scan_keys_with_snapshot(&full_prefix, snapshot).await?;
        let prefix_len = self.domain.system_prefix.len();
        Ok(raw_keys.into_iter().map(|k| k[prefix_len..].to_vec()).collect())
    }

    /// Subscribes to write events for this domain (domain prefix already
    /// stripped), optionally resuming from `last_event_id` (spec kv/024 §4).
    ///
    /// Step order is binding (spec kv/024 §4.3): subscribing to the raw
    /// engine broadcast happens *before* the ring snapshot, so nothing can
    /// be lost between the snapshot and the relay task picking up live
    /// traffic — only overlap, which the caller suppresses using the
    /// returned `Resume`'s `head` (a live event with `seq <= head` is a
    /// re-delivery of what was just replayed).
    pub fn watch_from(&self, last_event_id: Option<&str>) -> WatchStart {
        let mut raw_rx = self.engine.watch_subscribe(); // step 1: subscribe first
        let resume = self.strip_domain_prefix(self.engine.watch_decide_resume(last_event_id)); // step 2

        let prefix = self.domain.system_prefix.clone();
        let prefix_len = prefix.len();
        let (tx, rx) = broadcast::channel(self.engine.wal_event_channel_capacity());
        tokio::spawn(async move {
            // step 3: relay task
            loop {
                match raw_rx.recv().await {
                    Ok(event) => {
                        if event.key.starts_with(&prefix) {
                            let stripped = WalEvent {
                                seq: event.seq,
                                key: event.key[prefix_len..].to_vec(),
                                op: event.op,
                            };
                            if tx.send(WatchMessage::Event(stripped)).is_err() {
                                break;
                            }
                        }
                    }
                    // A silent `continue` would hide the gap forever — the
                    // domain-filtered stream isn't sequence-contiguous by
                    // construction, so the client can't infer it either
                    // (spec kv/024 §6).
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if tx.send(WatchMessage::Gap).is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        WatchStart { resume, rx } // step 4
    }

    /// Current head of the engine's watch-stream sequence (spec kv/024 §5)
    /// — stamps a `reset` triggered by a live lag, as opposed to one from
    /// the initial resume decision, which already carries its own `head`.
    pub fn watch_head(&self) -> u64 {
        self.engine.watch_head()
    }

    /// Filters a resume's replay list to this domain's keys and strips the
    /// domain prefix — the ring holds raw (prefixed) keys across every
    /// domain (spec kv/024 §2.1); `head` and non-`Replay` variants pass
    /// through unchanged.
    fn strip_domain_prefix(&self, resume: Resume<WalEvent>) -> Resume<WalEvent> {
        match resume {
            Resume::Replay { events, head } => {
                let prefix = &self.domain.system_prefix;
                let prefix_len = prefix.len();
                let events = events
                    .into_iter()
                    .filter(|e| e.key.starts_with(prefix))
                    .map(|e| WalEvent { seq: e.seq, key: e.key[prefix_len..].to_vec(), op: e.op })
                    .collect();
                Resume::Replay { events, head }
            }
            other => other,
        }
    }
}

// ── DomainPurger ──────────────────────────────────────────────────────────────

/// Background task that tombstones all keys belonging to `Deleting` domains.
///
/// Operates in batches to avoid starving normal I/O. After all keys of a
/// domain are purged, the domain metadata is removed permanently.
pub struct DomainPurger {
    engine: Arc<LsmStorageEngine>,
    registry: Arc<DomainRegistry>,
    pub batch_size: usize,
    pub interval: Duration,
    shutdown: Arc<AtomicBool>,
}

impl DomainPurger {
    pub fn new(
        engine: Arc<LsmStorageEngine>,
        registry: Arc<DomainRegistry>,
        shutdown: Arc<AtomicBool>,
        batch_size: usize,
        interval_secs: u64,
    ) -> Self {
        Self {
            engine,
            registry,
            batch_size,
            interval: Duration::from_secs(interval_secs),
            shutdown,
        }
    }

    /// Runs the purge loop until `shutdown` is set.
    pub async fn run(self: Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            if let Err(e) = self.purge_tick().await {
                eprintln!("[DomainPurger] Error: {e}");
            }
            sleep(self.interval).await;
        }
    }

    /// Performs one purge cycle: finds deleting domains and tombstones their keys.
    pub async fn purge_tick(&self) -> Result<()> {
        for domain in self.registry.list_deleting_domains() {
            let prefix = domain.system_prefix.clone();
            let all_keys = self.engine.scan_keys(&prefix).await?;
            if all_keys.is_empty() {
                self.registry.finalize_domain_deletion(&domain.name).await?;
                continue;
            }
            for key in all_keys.iter().take(self.batch_size) {
                self.engine.write_tombstone(key).await?;
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::events::{format_event_id, stream_epoch, ResetReason};
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::engine::LsmEngineConfig;
    use crate::engines::lsm::watcher::WATCH_TAG;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::vlog::VLog;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;

    async fn make_setup() -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        make_setup_with_engine_config(LsmEngineConfig::default()).await
    }

    // Spec kv/024 tests 3/5/11 need a non-default `watch_replay_buffer_size`
    // or `wal_event_channel_capacity` — every other test keeps using the
    // default-config `make_setup` above.
    async fn make_setup_with_engine_config(
        engine_config: LsmEngineConfig,
    ) -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions {
                    engine: engine_config,
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
        );
        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry = Arc::new(DomainRegistry::recover(Arc::clone(&engine), DomainConfig::default(), metrics).await.unwrap());
        (engine, registry, dir)
    }

    async fn make_registry() -> (Arc<DomainRegistry>, tempfile::TempDir) {
        let (_, registry, dir) = make_setup().await;
        (registry, dir)
    }

    // 1. Create domain → get_domain returns it.
    #[tokio::test]
    async fn test_create_and_get_domain() {
        let (registry, _dir) = make_registry().await;
        let domain = registry.create_domain("alpha").await.unwrap();
        assert_eq!(domain.name, "alpha");
        let fetched = registry.get_domain("alpha").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().name, "alpha");
    }

    // 2. Duplicate domain → 409-style error.
    #[tokio::test]
    async fn test_duplicate_domain_rejected() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("beta").await.unwrap();
        let err = registry.create_domain("beta").await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("409"));
    }

    // 3. put in domain A, get in domain B → None (isolation).
    #[tokio::test]
    async fn test_domain_isolation() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("tenant-a").await.unwrap();
        registry.create_domain("tenant-b").await.unwrap();
        let store_a = registry.store("tenant-a").await.unwrap();
        let store_b = registry.store("tenant-b").await.unwrap();
        store_a.put(b"secret", b"value-a").await.unwrap();
        let result = store_b.get(b"secret").await.unwrap();
        assert_eq!(result, GetResult::Absent, "Domain B must not see Domain A's keys");
    }

    // 4. scan_keys in domain A sees only its own keys.
    #[tokio::test]
    async fn test_scan_keys_isolation() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("scan-a").await.unwrap();
        registry.create_domain("scan-b").await.unwrap();
        let store_a = registry.store("scan-a").await.unwrap();
        let store_b = registry.store("scan-b").await.unwrap();
        store_a.put(b"key:1", b"v1").await.unwrap();
        store_a.put(b"key:2", b"v2").await.unwrap();
        store_b.put(b"key:1", b"vb").await.unwrap();
        let keys_a = store_a.scan_keys(b"key:").await.unwrap();
        assert_eq!(keys_a.len(), 2);
        assert!(keys_a.contains(&b"key:1".to_vec()));
        assert!(keys_a.contains(&b"key:2".to_vec()));
        let keys_b = store_b.scan_keys(b"key:").await.unwrap();
        assert_eq!(keys_b.len(), 1);
        assert!(keys_b.contains(&b"key:1".to_vec()));
    }

    // 5. Invalid domain names → error.
    #[tokio::test]
    async fn test_invalid_domain_name_rejected() {
        let (registry, _dir) = make_registry().await;
        assert!(registry.create_domain("").await.is_err());
        let long = "a".repeat(51);
        assert!(registry.create_domain(&long).await.is_err());
        assert!(registry.create_domain("bad name!").await.is_err());
        assert!(registry.create_domain("bad/slash").await.is_err());
    }

    // 6. Default domain exists after recovery.
    #[tokio::test]
    async fn test_default_domain_exists_after_recovery() {
        let (registry, _dir) = make_registry().await;
        let default_name = DomainConfig::default().default_domain;
        let default = registry.get_domain(&default_name).await.unwrap();
        assert!(default.is_some());
        assert_eq!(default.unwrap().name, default_name);
    }

    // 7. delete_domain → domain no longer visible via get_domain.
    #[tokio::test]
    async fn test_delete_domain() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("to-delete").await.unwrap();
        registry.delete_domain("to-delete").await.unwrap();
        let result = registry.get_domain("to-delete").await.unwrap();
        assert!(result.is_none());
    }

    // 8. Prefix is deterministic.
    #[tokio::test]
    async fn test_prefix_is_deterministic() {
        let p1 = generate_prefix("myapp");
        let p2 = generate_prefix("myapp");
        assert_eq!(p1, p2);
        assert_ne!(generate_prefix("myapp"), generate_prefix("myapp2"));
    }

    // 9. Concurrent create of the same name → exactly one succeeds (spec general/003).
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

    // Test: Domain in Deleting state → store() returns 410.
    #[tokio::test]
    async fn test_deleting_domain_returns_410() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("gone-soon").await.unwrap();
        registry.delete_domain("gone-soon").await.unwrap();
        let err = registry.store("gone-soon").await;
        assert!(err.is_err());
        let msg = format!("{}", err.err().unwrap());
        assert!(msg.contains("410"), "expected 410 in error: {msg}");
    }

    // Test: Domain-Purge removes all keys → scan_keys returns empty.
    #[tokio::test]
    async fn test_domain_purge_removes_keys() {
        let (engine, registry, _dir) = make_setup().await;
        registry.create_domain("purge-test").await.unwrap();
        let store = registry.store("purge-test").await.unwrap();
        store.put(b"key1", b"val1").await.unwrap();
        store.put(b"key2", b"val2").await.unwrap();
        let prefix = store.domain().system_prefix.clone();

        registry.delete_domain("purge-test").await.unwrap();

        let shutdown = Arc::new(AtomicBool::new(false));
        let cfg = DomainConfig::default();
        let purger = DomainPurger::new(
            Arc::clone(&engine),
            Arc::clone(&registry),
            Arc::clone(&shutdown),
            cfg.purger_batch_size,
            cfg.purger_interval_secs,
        );
        // Run two ticks: first removes keys, second finalises metadata.
        purger.purge_tick().await.unwrap();
        purger.purge_tick().await.unwrap();

        let remaining = engine.scan_keys(&prefix).await.unwrap();
        assert!(remaining.is_empty(), "All domain keys must be removed after purge");
        assert!(registry.get_domain("purge-test").await.unwrap().is_none());
    }

    // Regression: recover() must not 409 (boot loop) when the default domain
    // is still in Deleting state at startup (pendant of the JSON registry fix).
    #[tokio::test]
    async fn test_recover_survives_deleting_default_domain() {
        let (engine, registry, _dir) = make_setup().await;
        registry.delete_domain("default").await.unwrap();

        // Simulated restart before the purge finished: recover must succeed
        // and keep the default domain invisible (still Deleting).
        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry2 = Arc::new(
            DomainRegistry::recover(Arc::clone(&engine), DomainConfig::default(), metrics)
                .await
                .expect("recover must survive a Deleting default domain"),
        );
        assert!(registry2.get_domain("default").await.unwrap().is_none());

        // After the purger finalized it, the next recover recreates it as Active.
        let cfg = DomainConfig::default();
        let purger = DomainPurger::new(
            Arc::clone(&engine),
            Arc::clone(&registry2),
            Arc::new(AtomicBool::new(false)),
            cfg.purger_batch_size,
            cfg.purger_interval_secs,
        );
        purger.purge_tick().await.unwrap();
        purger.purge_tick().await.unwrap();

        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry3 = DomainRegistry::recover(engine, DomainConfig::default(), metrics)
            .await
            .unwrap();
        assert!(registry3.get_domain("default").await.unwrap().is_some());
    }

    // ── Spec general/007: UTF-8 key invariant ───────────────────────────────

    // Test 1a: all five DomainStore operations reject a non-UTF-8 key with a
    // "400 "-prefixed error.
    #[tokio::test]
    async fn test_invalid_utf8_key_rejected_on_all_five_ops() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("utf8-test").await.unwrap();
        let store = registry.store("utf8-test").await.unwrap();
        let bad_key: &[u8] = &[0xFF, 0xFE];

        let err = store.put(bad_key, b"v").await.unwrap_err();
        assert!(err.to_string().starts_with("400"), "put: {err}");

        let err = store.put_with_ttl(bad_key, b"v", 60).await.unwrap_err();
        assert!(err.to_string().starts_with("400"), "put_with_ttl: {err}");

        let err = store.get(bad_key).await.unwrap_err();
        assert!(err.to_string().starts_with("400"), "get: {err}");

        let err = store.delete(bad_key).await.unwrap_err();
        assert!(err.to_string().starts_with("400"), "delete: {err}");

        let err = store.set_null(bad_key).await.unwrap_err();
        assert!(err.to_string().starts_with("400"), "set_null: {err}");
    }

    // Test 1b: valid UTF-8 keys (umlaut, 4-byte emoji codepoint) are unaffected.
    #[tokio::test]
    async fn test_valid_utf8_keys_unaffected() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("utf8-ok").await.unwrap();
        let store = registry.store("utf8-ok").await.unwrap();

        store.put("clé".as_bytes(), b"v1").await.unwrap();
        assert_eq!(store.get("clé".as_bytes()).await.unwrap(), GetResult::Present(b"v1".to_vec()));

        store.put("🎉".as_bytes(), b"v2").await.unwrap();
        assert_eq!(store.get("🎉".as_bytes()).await.unwrap(), GetResult::Present(b"v2".to_vec()));

        store.set_null("clé".as_bytes()).await.unwrap();
        store.delete("🎉".as_bytes()).await.unwrap();
    }

    // Test 5: the length limit counts bytes, not chars — 100 four-byte emoji
    // codepoints (400 bytes) exceed the default 256-byte max_user_key_length.
    #[tokio::test]
    async fn test_key_length_limit_counts_bytes_not_chars() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("utf8-len").await.unwrap();
        let store = registry.store("utf8-len").await.unwrap();
        let long_key = "🎉".repeat(100);
        assert_eq!(long_key.len(), 400, "sanity: emoji key must be 400 bytes");
        let err = store.put(long_key.as_bytes(), b"v").await.unwrap_err();
        assert!(err.to_string().starts_with("400"), "expected 400 prefix, got: {err}");
    }

    // Test 2 (ScanKeys half): a partial-codepoint byte prefix (0xC3, the lead
    // byte of the whole Latin-1 "ä/ö/ü…" block) is a legitimate raw-byte scan
    // query and still finds every key in that block.
    #[tokio::test]
    async fn test_scan_keys_partial_codepoint_prefix() {
        let (registry, _dir) = make_registry().await;
        registry.create_domain("utf8-scan").await.unwrap();
        let store = registry.store("utf8-scan").await.unwrap();
        store.put("älg".as_bytes(), b"v1").await.unwrap();
        store.put("äpple".as_bytes(), b"v2").await.unwrap();
        store.put("zebra".as_bytes(), b"v3").await.unwrap();

        let found = store.scan_keys(&[0xC3]).await.unwrap();
        assert_eq!(found.len(), 2, "expected both ä-prefixed keys, got {found:?}");
    }

    // ── Spec general/006: snapshot-pinned reads/scans (backup export) ───────

    // get_with_snapshot/scan_keys_with_snapshot must strip the domain prefix
    // like their unpinned counterparts and stay isolated between domains.
    #[tokio::test]
    async fn test_get_and_scan_keys_with_snapshot_strip_domain_prefix() {
        let (engine, registry, _dir) = make_setup().await;
        registry.create_domain("backup-a").await.unwrap();
        registry.create_domain("backup-b").await.unwrap();
        let store_a = registry.store("backup-a").await.unwrap();
        let store_b = registry.store("backup-b").await.unwrap();

        store_a.put(b"key:1", b"va").await.unwrap();
        store_b.put(b"key:1", b"vb").await.unwrap();
        let snap = engine.snapshot();

        let (result_a, _) = store_a.get_with_snapshot(b"key:1", snap.snapshot()).await.unwrap();
        assert_eq!(result_a, GetResult::Present(b"va".to_vec()));
        let (result_b, _) = store_b.get_with_snapshot(b"key:1", snap.snapshot()).await.unwrap();
        assert_eq!(result_b, GetResult::Present(b"vb".to_vec()));

        let keys_a = store_a.scan_keys_with_snapshot(b"key:", snap.snapshot()).await.unwrap();
        assert_eq!(keys_a, vec![b"key:1".to_vec()], "must be domain-a's raw user key, not prefixed");
    }

    // Writes after the snapshot are invisible to the pinned domain read/scan,
    // while the domain's live view has moved on (spec general/006, consistency section).
    #[tokio::test]
    async fn test_domain_snapshot_consistency() {
        let (engine, registry, _dir) = make_setup().await;
        registry.create_domain("snap-dom").await.unwrap();
        let store = registry.store("snap-dom").await.unwrap();
        store.put(b"k1", b"old").await.unwrap();
        let snap = engine.snapshot();
        store.put(b"k1", b"new").await.unwrap();
        store.put(b"k2", b"created-after").await.unwrap();

        let (result, _) = store.get_with_snapshot(b"k1", snap.snapshot()).await.unwrap();
        assert_eq!(result, GetResult::Present(b"old".to_vec()));

        let keys = store.scan_keys_with_snapshot(b"k", snap.snapshot()).await.unwrap();
        assert_eq!(keys, vec![b"k1".to_vec()]);

        assert_eq!(store.get(b"k1").await.unwrap(), GetResult::Present(b"new".to_vec()));
    }

    // ── Spec kv/024: watch event ids, resume & gap signal ───────────────────

    // Test 1: 10 writes, disconnect after event 3, reconnect with its id ->
    // exactly events 4..=10, in order, as a gapless Replay (no reset).
    #[tokio::test]
    async fn test_watch_resume_gapless_after_reconnect() {
        let (_engine, registry, _dir) = make_setup().await;
        registry.create_domain("w1").await.unwrap();
        let store = registry.store("w1").await.unwrap();

        let started = store.watch_from(None);
        assert!(matches!(started.resume, Resume::Live));
        let mut rx = started.rx;

        for i in 0..10 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }

        let mut last_id = String::new();
        for _ in 0..3 {
            match rx.recv().await.unwrap() {
                WatchMessage::Event(e) => last_id = format_event_id(WATCH_TAG, stream_epoch(), e.seq),
                WatchMessage::Gap => panic!("unexpected gap"),
            }
        }

        let resumed = store.watch_from(Some(&last_id));
        match resumed.resume {
            Resume::Replay { events, .. } => {
                assert_eq!(events.len(), 7, "expected events 4..=10, got {events:?}");
                for (i, e) in events.iter().enumerate() {
                    assert_eq!(e.key, format!("k{}", i + 3).into_bytes());
                }
            }
            _ => panic!("expected a gapless replay"),
        }
    }

    // Test 3: watch_replay_buffer_size = 4, 10 writes, resume from event 1 ->
    // reset(window_exceeded); the stream still continues live afterward.
    #[tokio::test]
    async fn test_watch_window_exceeded_resets_then_live_continues() {
        let engine_config = LsmEngineConfig { watch_replay_buffer_size: 4, ..LsmEngineConfig::default() };
        let (_engine, registry, _dir) = make_setup_with_engine_config(engine_config).await;
        registry.create_domain("w3").await.unwrap();
        let store = registry.store("w3").await.unwrap();

        for i in 0..10 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }
        let id = format_event_id(WATCH_TAG, stream_epoch(), 1);
        let mut resumed = store.watch_from(Some(&id));
        match resumed.resume {
            Resume::Reset { reason: ResetReason::WindowExceeded, .. } => {}
            _ => panic!("expected window_exceeded"),
        }

        store.put(b"after", b"v").await.unwrap();
        match resumed.rx.recv().await.unwrap() {
            WatchMessage::Event(e) => assert_eq!(e.key, b"after"),
            WatchMessage::Gap => panic!("unexpected gap"),
        }
    }

    // Test 4: a resume id from a different epoch -> reset(restart). The
    // fabricated epoch stands in for "a different process" — see
    // core::events::tests for the fully parameterized version of this row.
    #[tokio::test]
    async fn test_watch_resume_wrong_epoch_is_restart() {
        let (_engine, registry, _dir) = make_setup().await;
        registry.create_domain("w4").await.unwrap();
        let store = registry.store("w4").await.unwrap();
        store.put(b"k", b"v").await.unwrap();

        let fake_epoch = stream_epoch().wrapping_add(1);
        let id = format_event_id(WATCH_TAG, fake_epoch, 1);
        let started = store.watch_from(Some(&id));
        match started.resume {
            Resume::Reset { reason: ResetReason::Restart, .. } => {}
            _ => panic!("expected restart on epoch mismatch"),
        }
    }

    // Test 5: a tiny wal_event_channel_capacity plus a non-draining
    // receiver must eventually lag (tokio::broadcast's own detection) --
    // proves watch_from actually wires the configured capacity through
    // rather than a hardcoded value. The Lagged-to-reset(lagged) mapping
    // itself is unit-tested at the kv.rs handler level (pure function, no
    // timing dependency).
    #[tokio::test]
    async fn test_watch_slow_client_channel_lags_when_capacity_exceeded() {
        let engine_config = LsmEngineConfig { wal_event_channel_capacity: 2, ..LsmEngineConfig::default() };
        let (_engine, registry, _dir) = make_setup_with_engine_config(engine_config).await;
        registry.create_domain("w5").await.unwrap();
        let store = registry.store("w5").await.unwrap();

        let started = store.watch_from(None);
        let mut rx = started.rx;

        for i in 0..10 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }

        let mut saw_lag = false;
        for _ in 0..10 {
            match rx.recv().await {
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    saw_lag = true;
                    break;
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        assert!(saw_lag, "a burst past channel capacity must eventually lag a non-draining receiver");
    }

    // Test 6: no Last-Event-ID -> Live (no replay, no reset), plus every
    // live event still carries a real seq (id: is additive).
    #[tokio::test]
    async fn test_watch_no_last_event_id_is_additive_live_only() {
        let (_engine, registry, _dir) = make_setup().await;
        registry.create_domain("w6").await.unwrap();
        let store = registry.store("w6").await.unwrap();

        let started = store.watch_from(None);
        assert!(matches!(started.resume, Resume::Live));
        let mut rx = started.rx;

        store.put(b"only", b"v").await.unwrap();
        match rx.recv().await.unwrap() {
            WatchMessage::Event(e) => {
                assert_eq!(e.key, b"only");
                assert!(e.seq > 0, "seq must be assigned even without a resume attempt");
            }
            WatchMessage::Gap => panic!("unexpected gap"),
        }
    }

    // Test 11: watch_replay_buffer_size = 0 -> id: still assigned, and even
    // an immediate reconnect with the just-received id resets (spec §4.2:
    // the cap == 0 row is checked before the window-arithmetic rows).
    #[tokio::test]
    async fn test_watch_cap_zero_ids_present_but_every_resume_is_window_exceeded() {
        let engine_config = LsmEngineConfig { watch_replay_buffer_size: 0, ..LsmEngineConfig::default() };
        let (_engine, registry, _dir) = make_setup_with_engine_config(engine_config).await;
        registry.create_domain("w11").await.unwrap();
        let store = registry.store("w11").await.unwrap();

        let started = store.watch_from(None);
        let mut rx = started.rx;
        store.put(b"k", b"v").await.unwrap();
        let last_id = match rx.recv().await.unwrap() {
            WatchMessage::Event(e) => {
                assert!(e.seq > 0, "id must be assigned even with the ring disabled");
                format_event_id(WATCH_TAG, stream_epoch(), e.seq)
            }
            WatchMessage::Gap => panic!("unexpected gap"),
        };

        let resumed = store.watch_from(Some(&last_id));
        match resumed.resume {
            Resume::Reset { reason: ResetReason::WindowExceeded, .. } => {}
            _ => panic!("cap == 0 must always reset, even for the just-received id"),
        }
    }

    // Test 12: an id tagged for a different stream (general/018's "g") must
    // reset as unknown_id, never silently succeed.
    #[tokio::test]
    async fn test_watch_foreign_tag_is_unknown_id() {
        let (_engine, registry, _dir) = make_setup().await;
        registry.create_domain("w12").await.unwrap();
        let store = registry.store("w12").await.unwrap();
        store.put(b"k", b"v").await.unwrap();

        let id = format_event_id("g", stream_epoch(), 1);
        let started = store.watch_from(Some(&id));
        match started.resume {
            Resume::Reset { reason: ResetReason::UnknownId, .. } => {}
            _ => panic!("a foreign tag must reset as unknown_id, not silently succeed"),
        }
    }

    // Replay is filtered to this domain's keys and prefix-stripped, exactly
    // like the live relay (spec kv/024 §2.1/§4.3) -- a foreign domain's
    // events in the same engine-wide ring must never surface here.
    #[tokio::test]
    async fn test_watch_replay_is_isolated_and_stripped_per_domain() {
        let (_engine, registry, _dir) = make_setup().await;
        registry.create_domain("wa").await.unwrap();
        registry.create_domain("wb").await.unwrap();
        let store_a = registry.store("wa").await.unwrap();
        let store_b = registry.store("wb").await.unwrap();

        let started = store_a.watch_from(None);
        let mut rx = started.rx;

        store_b.put(b"other-domain-key", b"v").await.unwrap();
        store_a.put(b"mine", b"v").await.unwrap();
        match rx.recv().await.unwrap() {
            WatchMessage::Event(e) => {
                assert_eq!(e.key, b"mine", "domain B's key must never reach domain A's live stream");
            }
            WatchMessage::Gap => panic!("unexpected gap"),
        }

        // Resuming from before either write: replay must contain only A's
        // key, raw-prefix-stripped, even though the ring holds both.
        let before_id = format_event_id(WATCH_TAG, stream_epoch(), 0);
        let resumed = store_a.watch_from(Some(&before_id));
        match resumed.resume {
            Resume::Replay { events, .. } => {
                assert_eq!(events.len(), 1, "expected exactly A's own write, got {events:?}");
                assert_eq!(events[0].key, b"mine");
            }
            _ => panic!("expected a gapless replay"),
        }
    }
}
