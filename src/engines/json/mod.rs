//! JSON document engine — runs on its own dedicated LSM instance so JSON
//! workloads (bulk imports, compaction) never impact KV performance.

pub mod bulk;
pub mod document;
pub mod domain;
pub mod error;
pub mod index;
pub mod purger;
pub mod query;
pub mod reindex;

pub use bulk::BulkLoadResult;
pub use document::{etag_value, Document, ExpectedVersion, Precondition};
pub use domain::{JsonDomain, JsonDomainState};
pub use error::JsonStoreError;
pub use index::{IndexDefinition, IndexFieldType};
pub use purger::JsonDomainPurger;
pub use query::{DocumentListResult, FilterCondition, ListOptions, SearchQuery, SearchResult};
pub use reindex::{ReindexResult, ReindexStatus};

use crate::config::{BlockCacheConfig, JsonStoreConfig};
use crate::control::{ControlPlane, Engine};
use crate::core::wal::WriteAheadLog;
use crate::engines::lsm::compaction::CompactionConfig;
use crate::engines::lsm::engine::{BatchOp, LsmEngineConfig, LsmEngineOptions, LsmStorageEngine};
use crate::engines::lsm::janitor::JanitorConfig;
use crate::engines::lsm::reader::Snapshot;
use crate::engines::StorageEngine;
use crate::metrics::{EngineKind, MetricsStore};
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use anyhow::Result;
use document::{
    doc_key, generate_uuid_v4, new_generation, reject_reserved_fields, validate_document_key,
    StoredDocument, DOC_KEY_OVERHEAD,
};
use domain::JsonDomainRegistry;
use index::IndexRegistry;
use parking_lot::{Mutex as SyncMutex, RwLock};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Number of document-write lock shards. Not configurable —
/// the number only caps the collision probability.
const DOC_WRITE_SHARDS: usize = 64;

/// Upper bound on document keys; `json.lsm.max_key_length` may cap it further.
const MAX_DOCUMENT_KEY_LENGTH: usize = 256;
/// Documents per atomic write batch during bulk load.
const BULK_BATCH_SIZE: usize = 100;
/// Documents per re-index batch and the throttle pause between batches.
const REINDEX_BATCH_SIZE: usize = 500;
const REINDEX_PAUSE_MS: u64 = 10;

/// Central entry point for all JSON-store operations.
pub struct JsonEngine {
    engine: Arc<LsmStorageEngine>,
    domains: Arc<JsonDomainRegistry>,
    indexes: Arc<IndexRegistry>,
    max_value_size: usize,
    max_document_key_length: usize,
    max_lsm_key_length: usize,
    bulk_batch_size: usize,
    bulk_body_limit_bytes: usize,
    reindex_batch_size: usize,
    reindex_pause_ms: u64,
    /// task_id → (domain, status) of started re-index tasks; the domain
    /// scopes status lookups (no cross-domain task reads).
    reindex_tasks: RwLock<HashMap<String, (String, ReindexStatus)>>,
    /// Domains with a currently running re-index (domain → task_id).
    reindex_running: SyncMutex<HashMap<String, String>>,
    /// Serializes read→write in document writes so version checks (OCC)
    /// cannot race, and fences writers against the purger's
    /// finalize: domain state is checked under the shard guard.
    /// Sharded per document reference — writes on keys of
    /// different shards no longer wait for each other.
    doc_write_locks: [tokio::sync::Mutex<()>; DOC_WRITE_SHARDS],
    /// Publishes the index events and finishes purges. Unset for a
    /// standalone engine, which then publishes nothing.
    control: OnceLock<Arc<ControlPlane>>,
    /// Engine-aggregate op/latency window. No `Option`,
    /// no setter — always supplied at bootstrap.
    metrics: Arc<MetricsStore>,
}

impl JsonEngine {
    /// Tests only: [`Self::bootstrap_with_wal`] on a local WAL committer
    /// instead of the storage hub.
    #[cfg(test)]
    pub async fn bootstrap(config: &JsonStoreConfig, metrics: Arc<MetricsStore>) -> Result<Arc<Self>> {
        let wal = WriteAheadLog::new(&config.wal_path).await?;
        Self::bootstrap_with_wal(config, wal, metrics).await
    }

    /// Creates the dedicated JSON LSM instance from `config`, with `wal` as
    /// the log at `config.wal_path`, and starts its background tasks (flush,
    /// compaction, janitor).
    pub async fn bootstrap_with_wal(
        config: &JsonStoreConfig,
        wal: WriteAheadLog,
        metrics: Arc<MetricsStore>,
    ) -> Result<Arc<Self>> {
        let wal_path = PathBuf::from(&config.wal_path);
        let vlog_path = PathBuf::from(&config.vlog_path);
        let wal = Arc::new(wal);
        let vlog = Arc::new(VLog::new(&vlog_path).await?);
        let file_manager = Arc::new(FileManager::new(&config.sstable_dir).await?);
        let manifest_manager = Arc::new(ManifestManager::new(&config.sstable_dir));
        let options = Self::lsm_options(config, BlockCacheConfig::default());
        let engine = Arc::new(
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, options).await?,
        );
        engine.start_background_tasks();
        Self::open(config, engine, metrics, true).await
    }

    /// Options of the JSON engine's LSM instances, with `block_cache`.
    pub fn lsm_options(config: &JsonStoreConfig, block_cache: BlockCacheConfig) -> LsmEngineOptions {
        LsmEngineOptions {
            engine: LsmEngineConfig {
                max_key_length: config.lsm.max_key_length,
                max_value_size: config.lsm.max_value_size,
                watch_replay_buffer_size: 0, // no watch endpoint on the JSON engine
                ..LsmEngineConfig::default()
            },
            compaction: CompactionConfig::default(),
            janitor: JanitorConfig::default(),
            block_cache,
            ..LsmEngineOptions::default()
        }
    }

    /// The JSON engine on `engine`, a recovered instance whose background
    /// tasks run; with `owns_default` it creates the default domain if that
    /// is missing.
    pub async fn open(
        config: &JsonStoreConfig,
        engine: Arc<LsmStorageEngine>,
        metrics: Arc<MetricsStore>,
        owns_default: bool,
    ) -> Result<Arc<Self>> {
        let domains = Arc::new(JsonDomainRegistry::recover(Arc::clone(&engine), owns_default).await?);
        let indexes = Arc::new(IndexRegistry::recover(Arc::clone(&engine)).await?);
        Ok(Arc::new(Self {
            engine,
            domains,
            indexes,
            max_value_size: config.lsm.max_value_size,
            // Effective limit: the composite doc key must fit the LSM key
            // limit, otherwise valid keys fail deep in the engine (500).
            max_document_key_length: MAX_DOCUMENT_KEY_LENGTH
                .min(config.lsm.max_key_length.saturating_sub(DOC_KEY_OVERHEAD)),
            max_lsm_key_length: config.lsm.max_key_length,
            bulk_batch_size: BULK_BATCH_SIZE,
            bulk_body_limit_bytes: config.bulk_body_limit_bytes,
            reindex_batch_size: REINDEX_BATCH_SIZE,
            reindex_pause_ms: REINDEX_PAUSE_MS,
            reindex_tasks: RwLock::new(HashMap::new()),
            reindex_running: SyncMutex::new(HashMap::new()),
            doc_write_locks: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
            control: OnceLock::new(),
            metrics,
        }))
    }

    /// The dedicated JSON LSM instance.
    pub fn engine(&self) -> &Arc<LsmStorageEngine> {
        &self.engine
    }

    /// Set once at startup, before the purger runs.
    pub(crate) fn attach_control_plane(&self, control: Arc<ControlPlane>) {
        let _ = self.control.set(control);
    }

    /// Max HTTP body size for bulk imports (applied at router build).
    pub fn bulk_body_limit_bytes(&self) -> usize {
        self.bulk_body_limit_bytes
    }

    /// Gracefully shuts down the underlying LSM instance.
    pub async fn shutdown(&self) {
        self.engine.shutdown().await;
    }

    // ── Domain management ─────────────────────────────────────

    /// Creates a new JSON domain, bypassing the control plane.
    #[cfg(test)]
    pub(crate) async fn create_domain(&self, name: &str) -> Result<JsonDomain, JsonStoreError> {
        self.domains.create_domain(name).await
    }

    /// Creates a new JSON domain with its `require_conditional_writes` setting.
    pub(crate) async fn create_domain_with(
        &self,
        name: &str,
        require_conditional_writes: bool,
    ) -> Result<JsonDomain, JsonStoreError> {
        self.domains.create_domain_with(name, require_conditional_writes).await
    }

    /// Looks up an active JSON domain.
    pub fn get_domain(&self, name: &str) -> Option<JsonDomain> {
        self.domains.get_domain(name)
    }

    /// Looks up a domain regardless of state (detail views expose `Deleting`).
    pub fn get_domain_any(&self, name: &str) -> Option<JsonDomain> {
        self.domains.get_domain_any(name)
    }

    /// Lists all JSON domains including deleting ones (state in the model).
    pub fn list_domains(&self) -> Vec<JsonDomain> {
        self.domains.list_domains()
    }

    /// Marks a JSON domain as deleting; the purger cleans up in background.
    /// A running re-index is not aborted here — it stops itself at the next
    /// chunk via its per-chunk domain-state check (run_reindex).
    pub(crate) async fn delete_domain(&self, name: &str) -> Result<(), JsonStoreError> {
        self.domains.delete_domain(name).await
    }

    /// Removes a purged domain's metadata for good.
    pub(crate) async fn finalize_deletion(&self, name: &str) -> Result<(), JsonStoreError> {
        self.domains.finalize_deletion(name).await
    }

    /// Removes a purged domain — through the control plane once attached.
    async fn finish_purge(&self, name: &str) -> Result<()> {
        match self.control.get() {
            Some(control) => control.finalize_deletion(Engine::Json, name).await,
            None => Ok(self.finalize_deletion(name).await?),
        }
    }

    /// Returns once every document write that holds its lock shard ended;
    /// later ones see the current domain state.
    pub(crate) async fn quiesce_writes(&self) {
        drop(self.lock_shards((0..DOC_WRITE_SHARDS).collect()).await);
    }

    /// The lock shard a write of `key` in `domain` holds.
    #[cfg(test)]
    pub(crate) async fn doc_write_lock_for_test(&self, domain: &str, key: &str) -> tokio::sync::MutexGuard<'_, ()> {
        self.doc_write_locks[Self::shard(domain, key)].lock().await
    }

    // ── Index management ──────────────────────────────────────

    /// Creates an index definition on `field` for an existing domain.
    ///
    /// Existing documents are NOT back-indexed here (that is re-indexing);
    /// new writes pick the index up immediately.
    pub async fn create_index(
        &self,
        domain: &str,
        field: &str,
        field_type: IndexFieldType,
    ) -> Result<IndexDefinition, JsonStoreError> {
        let def = self.indexes.create_index(&self.domains, domain, field, field_type).await?;
        if let Some(control) = self.control.get() {
            control.publish_global(Engine::Json, "index_created", domain, Some(field.to_string()));
        }
        Ok(def)
    }

    /// All index definitions of a domain.
    pub fn get_indexes(&self, domain: &str) -> Result<Vec<IndexDefinition>, JsonStoreError> {
        self.domains.require_active(domain)?;
        Ok(self.indexes.get_indexes(domain))
    }

    /// Like [`Self::get_indexes`], but read from the persisted definitions
    /// visible under `snapshot` instead of the live cache (backup
    /// export) — index DDL during an export must not leak into the
    /// archive that pins its documents to an earlier point in time.
    pub async fn get_indexes_with_snapshot(
        &self,
        domain: &str,
        snapshot: &Snapshot,
    ) -> Result<Vec<IndexDefinition>, JsonStoreError> {
        self.domains.require_active(domain)?;
        // Key layout of index.rs (its prefix constant is module-private).
        let prefix = format!("__sys:index:{domain}:");
        let keys = self.engine.scan_keys_with_snapshot(prefix.as_bytes(), snapshot).await?;
        let mut defs = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(bytes) = self.engine.get_with_snapshot(&key, snapshot).await?.into_option() {
                defs.push(serde_json::from_slice(&bytes)?);
            }
        }
        Ok(defs)
    }

    /// Removes an index definition and tombstones the field's `IDX:` entries.
    pub async fn delete_index(&self, domain: &str, field: &str) -> Result<(), JsonStoreError> {
        self.indexes.delete_index(&self.domains, domain, field).await?;
        if let Some(control) = self.control.get() {
            control.publish_global(Engine::Json, "index_dropped", domain, Some(field.to_string()));
        }
        Ok(())
    }

    // ── Document write locks ──────────────────────────────────

    /// Lock shard of a document reference. Domain and key both feed the hash,
    /// so equal keys of different domains need not share a shard.
    fn shard(domain: &str, key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        key.hash(&mut hasher);
        (hasher.finish() % DOC_WRITE_SHARDS as u64) as usize
    }

    /// Acquires several shards at once. Sole owner of the acquisition order
    /// (ascending shard index, deduplicated), which is what makes concurrent
    /// multi-key writers deadlock-free.
    async fn lock_shards(
        &self,
        mut shards: Vec<usize>,
    ) -> Vec<tokio::sync::MutexGuard<'_, ()>> {
        shards.sort_unstable();
        shards.dedup();
        let mut guards = Vec::with_capacity(shards.len());
        for shard in shards {
            guards.push(self.doc_write_locks[shard].lock().await);
        }
        guards
    }

    // ── Core CRUD (domain-aware) ────────────────

    /// Stores `content` under a system-generated UUIDv4 key.
    pub async fn create_document(
        &self,
        domain: &str,
        content: Value,
    ) -> Result<Document, JsonStoreError> {
        reject_reserved_fields(&content)?;
        let key = generate_uuid_v4();
        let _guard = self.doc_write_locks[Self::shard(domain, &key)].lock().await;
        let dom = self.domains.require_active(domain)?;
        if key.len() > self.max_document_key_length {
            return Err(JsonStoreError::InvalidKey(format!(
                "generated UUID key needs {} chars but the effective key limit is {} — raise json.lsm.max_key_length",
                key.len(),
                self.max_document_key_length
            )));
        }
        self.write_document(&dom, &key, content, new_generation(), 1, None).await
    }

    /// Upserts a document under a caller-supplied key, incrementing the
    /// version (last-write-wins, no version check).
    pub async fn put_document(
        &self,
        domain: &str,
        key: &str,
        content: Value,
    ) -> Result<Document, JsonStoreError> {
        self.put_document_with_version(domain, key, content, &[]).await
    }

    /// Upsert under write preconditions, checked in order under the key's
    /// write shard: `Precondition::IfMatch` is the optimistic concurrency
    /// check (fails with `VersionConflict` if the document is missing or
    /// generation or version differ — a stale ETag of a deleted incarnation
    /// never matches); `Precondition::MustNotExist` is the create-only write
    /// (fails with `DocumentAlreadyExists` if it is present). A domain that
    /// requires conditional writes rejects one without preconditions with
    /// `PreconditionRequired`, after key, content and domain checks.
    pub async fn put_document_with_version(
        &self,
        domain: &str,
        key: &str,
        content: Value,
        preconditions: &[Precondition],
    ) -> Result<Document, JsonStoreError> {
        validate_document_key(key, self.max_document_key_length)?;
        reject_reserved_fields(&content)?;
        let _guard = self.doc_write_locks[Self::shard(domain, key)].lock().await;
        let dom = self.domains.require_active(domain)?;
        require_preconditions(&dom, preconditions)?;
        let old = self.read_stored(&dom, key).await?;
        check_preconditions(&dom, key, old.as_ref(), preconditions)?;
        // No predecessor → new incarnation with a fresh random generation.
        let (generation, version) = match &old {
            Some(o) => (o.generation, o.version + 1),
            None => (new_generation(), 1),
        };
        self.write_document(&dom, key, content, generation, version, old.as_ref().map(|o| &o.content))
            .await
    }

    /// Reads a document. Returns `None` if the key does not exist.
    pub async fn get_document(
        &self,
        domain: &str,
        key: &str,
    ) -> Result<Option<Document>, JsonStoreError> {
        let start = std::time::Instant::now();
        validate_document_key(key, self.max_document_key_length)?;
        let dom = self.domains.require_active(domain)?;
        let result = self.read_stored(&dom, key).await?.map(|stored| Document {
            key: key.to_string(),
            domain: dom.name.clone(),
            content: stored.content,
            version: stored.version,
            generation: stored.generation,
        });
        self.metrics.record_engine_read(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(result)
    }

    /// Like [`Self::get_document`], but against an externally held snapshot
    /// instead of one acquired internally (backup export) —
    /// lets the backup writer pin every document read of a domain export to
    /// the same point in time. Keys come from the engine's own scan, so they
    /// are not re-validated: a lowered key limit must not make stored
    /// documents unexportable.
    pub async fn get_document_with_snapshot(
        &self,
        domain: &str,
        key: &str,
        snapshot: &Snapshot,
    ) -> Result<Option<Document>, JsonStoreError> {
        let start = std::time::Instant::now();
        let dom = self.domains.require_active(domain)?;
        let result = self.read_stored_with_snapshot(&dom, key, snapshot).await?.map(|stored| Document {
            key: key.to_string(),
            domain: dom.name.clone(),
            content: stored.content,
            version: stored.version,
            generation: stored.generation,
        });
        self.metrics.record_engine_read(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(result)
    }

    /// Deletes a document and all its index entries in one atomic batch.
    /// Returns `false` if it did not exist.
    pub async fn delete_document(&self, domain: &str, key: &str) -> Result<bool, JsonStoreError> {
        self.delete_document_with_version(domain, key, &[]).await
    }

    /// Delete under write preconditions, checked like in
    /// [`Self::put_document_with_version`].
    pub async fn delete_document_with_version(
        &self,
        domain: &str,
        key: &str,
        preconditions: &[Precondition],
    ) -> Result<bool, JsonStoreError> {
        let start = std::time::Instant::now();
        validate_document_key(key, self.max_document_key_length)?;
        let _guard = self.doc_write_locks[Self::shard(domain, key)].lock().await;
        let dom = self.domains.require_active(domain)?;
        require_preconditions(&dom, preconditions)?;
        let old = self.read_stored(&dom, key).await?;
        check_preconditions(&dom, key, old.as_ref(), preconditions)?;
        let Some(old) = old else {
            return Ok(false);
        };
        let mut ops: Vec<BatchOp> = self
            .index_entry_keys(&dom, key, &old.content)
            .into_iter()
            .map(|key| BatchOp::Delete { key })
            .collect();
        ops.push(BatchOp::Delete { key: doc_key(&dom.system_prefix, key) });
        self.engine.write_batch(ops).await?;
        self.metrics.record_engine_write(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(true)
    }

    async fn read_stored(
        &self,
        dom: &JsonDomain,
        key: &str,
    ) -> Result<Option<StoredDocument>, JsonStoreError> {
        let raw = self.engine.get(&doc_key(&dom.system_prefix, key)).await?;
        match raw {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Like [`Self::read_stored`], but against an externally held snapshot
    /// (backup export) instead of one acquired internally.
    async fn read_stored_with_snapshot(
        &self,
        dom: &JsonDomain,
        key: &str,
        snapshot: &Snapshot,
    ) -> Result<Option<StoredDocument>, JsonStoreError> {
        let raw = self
            .engine
            .get_with_snapshot(&doc_key(&dom.system_prefix, key), snapshot)
            .await?
            .into_option();
        match raw {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Persists the document plus index maintenance in ONE atomic batch:
    /// stale index entries are tombstoned, the document and the new index
    /// entries are written (synchronous indexing).
    async fn write_document(
        &self,
        dom: &JsonDomain,
        key: &str,
        content: Value,
        generation: u64,
        version: u64,
        old_content: Option<&Value>,
    ) -> Result<Document, JsonStoreError> {
        let start = std::time::Instant::now();
        let stored = StoredDocument { version, generation, content };
        let payload = serde_json::to_vec(&stored)?;
        if payload.len() > self.max_value_size {
            return Err(JsonStoreError::PayloadTooLarge {
                size: payload.len(),
                max: self.max_value_size,
            });
        }
        let new_keys = self.index_entry_keys(dom, key, &stored.content);
        let old_keys = old_content
            .map(|c| self.index_entry_keys(dom, key, c))
            .unwrap_or_default();
        let mut ops: Vec<BatchOp> = old_keys
            .difference(&new_keys)
            .cloned()
            .map(|key| BatchOp::Delete { key })
            .collect();
        ops.push(BatchOp::Put {
            key: doc_key(&dom.system_prefix, key),
            value: payload,
        });
        for idx_key in new_keys {
            ops.push(BatchOp::Put { key: idx_key, value: Vec::new() });
        }
        self.engine.write_batch(ops).await?;
        self.metrics.record_engine_write(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(Document {
            key: key.to_string(),
            domain: dom.name.clone(),
            content: stored.content,
            version,
            generation,
        })
    }

    /// All index-entry keys for `content` under the domain's active index
    /// definitions. Non-indexable values and oversized keys produce no entry.
    fn index_entry_keys(&self, dom: &JsonDomain, key: &str, content: &Value) -> HashSet<Vec<u8>> {
        let mut keys = HashSet::new();
        for def in self.indexes.get_indexes(&dom.name) {
            let Some(value) = index::extract_field(content, &def.field) else {
                continue;
            };
            let Some(encoded) = index::encode_index_value(&value, def.field_type) else {
                continue;
            };
            let idx_key = index::index_key(&dom.system_prefix, &def.field, &encoded, key);
            if idx_key.len() <= self.max_lsm_key_length {
                keys.insert(idx_key);
            }
        }
        keys
    }
}

fn require_preconditions(dom: &JsonDomain, preconditions: &[Precondition]) -> Result<(), JsonStoreError> {
    if dom.require_conditional_writes && preconditions.is_empty() {
        return Err(JsonStoreError::PreconditionRequired { domain: dom.name.clone() });
    }
    Ok(())
}

/// Checks `preconditions` in order against the stored document (`None` =
/// absent); the first that fails decides the error.
fn check_preconditions(
    dom: &JsonDomain,
    key: &str,
    old: Option<&StoredDocument>,
    preconditions: &[Precondition],
) -> Result<(), JsonStoreError> {
    let current = old.map(|o| etag_value(o.generation, o.version));
    for precondition in preconditions {
        match precondition {
            Precondition::IfMatch(expected) => {
                if !old.is_some_and(|o| o.generation == expected.generation && o.version == expected.version) {
                    return Err(JsonStoreError::VersionConflict {
                        expected: etag_value(expected.generation, expected.version),
                        actual: current,
                    });
                }
            }
            Precondition::MustNotExist => {
                if let Some(etag) = current {
                    return Err(JsonStoreError::DocumentAlreadyExists {
                        domain: dom.name.clone(),
                        key: key.to_string(),
                        etag,
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage_thread::{TestHub, WalTarget};
    use serde_json::json;

    fn config_in(dir: &std::path::Path) -> JsonStoreConfig {
        JsonStoreConfig {
            wal_path: dir.join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.join("json_sstables").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        }
    }

    /// Bootstraps on `config`; with `on_hub` a fresh storage hub writes the WAL.
    async fn bootstrap_on(config: &JsonStoreConfig, on_hub: bool) -> (Arc<JsonEngine>, Option<TestHub>) {
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        if !on_hub {
            return (JsonEngine::bootstrap(config, metrics).await.unwrap(), None);
        }
        let hub = TestHub::start(&[(WalTarget::Json, std::path::Path::new(&config.wal_path))]);
        let engine = JsonEngine::bootstrap_with_wal(config, hub.wal(WalTarget::Json), metrics).await.unwrap();
        (engine, Some(hub))
    }

    async fn make_engine() -> (Arc<JsonEngine>, tempfile::TempDir) {
        let (engine, _, dir) = make_engine_on(false).await;
        (engine, dir)
    }

    /// [`make_engine`]; with `on_hub` a running storage hub writes the WAL.
    async fn make_engine_on(on_hub: bool) -> (Arc<JsonEngine>, Option<TestHub>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let (engine, hub) = bootstrap_on(&config_in(dir.path()), on_hub).await;
        (engine, hub, dir)
    }

    // 1. Bootstrap creates a working second LSM instance (put/get roundtrip).
    #[test]
    fn test_bootstrap_put_get_roundtrip() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.engine().put(b"doc:1", b"{}").await.unwrap();
            let snap = json.engine().snapshot().await;
            let got = json
                .engine()
                .get_with_snapshot(b"doc:1", snap.snapshot())
                .await
                .unwrap()
                .into_option();
            assert_eq!(got, Some(b"{}".to_vec()));
            json.shutdown().await;
        })
    }

    // 2. Bootstrap creates the sstable directory if it does not exist.
    #[test]
    fn test_bootstrap_creates_sstable_dir() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sstable_dir = dir.path().join("nested").join("sstables");
            let config = JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: sstable_dir.to_string_lossy().into_owned(),
                ..JsonStoreConfig::default()
            };
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
            assert!(sstable_dir.is_dir());
            json.shutdown().await;
        })
    }

    // 3. create_document → get_document returns identical content, with the
    //    WAL local and on the storage hub.
    #[test]
    fn test_create_then_get_roundtrip() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let (json, _hub, _dir) = make_engine_on(on_hub).await;
                json.create_domain("people").await.unwrap();
                let content = json!({"name": "Ada", "tags": ["a", "b"], "age": 42});
                let doc = json.create_document("people", content.clone()).await.unwrap();
                assert_eq!(doc.version, 1);
                let fetched = json.get_document("people", &doc.key).await.unwrap().unwrap();
                assert_eq!(fetched.content, content);
                assert_eq!(fetched.version, 1);
                assert_eq!(fetched.domain, "people");
            }
        })
    }

    // 4. create_document generates a valid UUIDv4 key.
    #[test]
    fn test_create_generates_uuid_v4() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let doc = json.create_document("default", json!({})).await.unwrap();
            let k = &doc.key;
            assert_eq!(k.len(), 36);
            let bytes: Vec<char> = k.chars().collect();
            for &pos in &[8, 13, 18, 23] {
                assert_eq!(bytes[pos], '-', "dash expected at {pos} in {k}");
            }
            assert_eq!(bytes[14], '4', "version nibble must be 4 in {k}");
            assert!(matches!(bytes[19], '8' | '9' | 'a' | 'b'), "invalid variant in {k}");
            assert!(k
                .chars()
                .all(|c| c == '-' || c.is_ascii_hexdigit()));
        })
    }

    // 5. put_document → get_document returns identical content.
    #[test]
    fn test_put_then_get_roundtrip() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_domain("catalog").await.unwrap();
            let content = json!({"sku": "X-1", "price": 9.99});
            json.put_document("catalog", "item-1", content.clone()).await.unwrap();
            let fetched = json.get_document("catalog", "item-1").await.unwrap().unwrap();
            assert_eq!(fetched.content, content);
            assert_eq!(fetched.key, "item-1");
        })
    }

    // 6. put_document twice increments the version, with the WAL local and
    //    on the storage hub.
    #[test]
    fn test_put_twice_increments_version() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let (json, _hub, _dir) = make_engine_on(on_hub).await;
                let v1 = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
                assert_eq!(v1.version, 1);
                let v2 = json.put_document("default", "k", json!({"n": 2})).await.unwrap();
                assert_eq!(v2.version, 2);
                let fetched = json.get_document("default", "k").await.unwrap().unwrap();
                assert_eq!(fetched.version, 2);
                assert_eq!(fetched.content, json!({"n": 2}));
            }
        })
    }

    // 7. delete_document → get_document returns None, with the WAL local and
    //    on the storage hub.
    #[test]
    fn test_delete_then_get_none() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let (json, _hub, _dir) = make_engine_on(on_hub).await;
                json.put_document("default", "gone", json!({})).await.unwrap();
                assert!(json.delete_document("default", "gone").await.unwrap());
                assert!(json.get_document("default", "gone").await.unwrap().is_none());
            }
        })
    }

    // 8. delete_document on a missing key returns false.
    #[test]
    fn test_delete_missing_returns_false() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            assert!(!json.delete_document("default", "never-existed").await.unwrap());
        })
    }

    // 9. Empty key is rejected with InvalidKey.
    #[test]
    fn test_empty_key_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let err = json.put_document("default", "", json!({})).await.unwrap_err();
            assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
        })
    }

    // 10. Key containing a colon is rejected with InvalidKey.
    #[test]
    fn test_colon_key_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let err = json.put_document("default", "a:b", json!({})).await.unwrap_err();
            assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
        })
    }

    // 10b. A document with a reserved top-level field smuggled in before
    //      this check existed (direct write_batch, bypassing
    //      create_document/put_document_with_version) stays readable via
    //      get_document -- overshadowed, no new read error (no
    //      migration/scan step for existing data).
    #[test]
    fn test_legacy_document_with_reserved_field_stays_readable() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let dom = json.get_domain("default").unwrap();
            let stored = StoredDocument {
                version: 1,
                generation: new_generation(),
                content: json!({"_key": "smuggled", "x": 1}),
            };
            let payload = serde_json::to_vec(&stored).unwrap();
            json.engine()
                .write_batch(vec![BatchOp::Put { key: doc_key(&dom.system_prefix, "legacy"), value: payload }])
                .await
                .unwrap();

            let fetched = json.get_document("default", "legacy").await.unwrap().unwrap();
            assert_eq!(fetched.content, json!({"_key": "smuggled", "x": 1}));
        })
    }

    // 11. Domain create → get_domain returns it.
    #[test]
    fn test_create_and_get_domain() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let created = json.create_domain("alpha").await.unwrap();
            assert_eq!(created.system_prefix.len(), 16);
            let fetched = json.get_domain("alpha").unwrap();
            assert_eq!(fetched.name, "alpha");
            assert_eq!(fetched.system_prefix, created.system_prefix);
        })
    }

    // 12. Duplicate domain → DomainAlreadyExists.
    #[test]
    fn test_duplicate_domain_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_domain("beta").await.unwrap();
            let err = json.create_domain("beta").await.unwrap_err();
            assert!(matches!(err, JsonStoreError::DomainAlreadyExists(_)), "got: {err}");
        })
    }

    // 13. Invalid domain names → InvalidDomainName. "domains" is reserved:
    //     the static /json/domains admin routes shadow such a domain.
    #[test]
    fn test_invalid_domain_name_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            for bad in ["", "bad name!", "bad/slash", "domains", &"x".repeat(51)] {
                let err = json.create_domain(bad).await.unwrap_err();
                assert!(
                    matches!(err, JsonStoreError::InvalidDomainName(_)),
                    "'{bad}' got: {err}"
                );
            }
        })
    }

    // 14. Same key in two domains is isolated.
    #[test]
    fn test_domain_isolation() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_domain("tenant-a").await.unwrap();
            json.create_domain("tenant-b").await.unwrap();
            json.put_document("tenant-a", "secret", json!({"of": "a"})).await.unwrap();
            assert!(json.get_document("tenant-b", "secret").await.unwrap().is_none());
        })
    }

    // 15. put_document into an unknown domain → DomainNotFound.
    #[test]
    fn test_put_into_unknown_domain_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let err = json.put_document("nope", "k", json!({})).await.unwrap_err();
            assert!(matches!(err, JsonStoreError::DomainNotFound(_)), "got: {err}");
        })
    }

    // 16. Default domain exists after bootstrap/recovery.
    #[test]
    fn test_default_domain_exists() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            assert!(json.get_domain("default").is_some());
        })
    }

    // 17. list_domains contains all domains; deleting ones carry their state
    //     (they are listed, not hidden).
    #[test]
    fn test_list_domains() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_domain("one").await.unwrap();
            json.create_domain("two").await.unwrap();
            json.delete_domain("two").await.unwrap();
            let domains = json.list_domains();
            let state_of = |n: &str| domains.iter().find(|d| d.name == n).map(|d| d.state.clone());
            assert_eq!(state_of("default"), Some(JsonDomainState::Active));
            assert_eq!(state_of("one"), Some(JsonDomainState::Active));
            assert_eq!(state_of("two"), Some(JsonDomainState::Deleting));
            assert!(json.get_domain("two").is_none(), "deleting domain is not resolvable for CRUD");
        })
    }

    // 18. create_index → get_indexes returns it.
    #[test]
    fn test_create_and_get_index() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            let defs = json.get_indexes("default").unwrap();
            assert_eq!(defs.len(), 1);
            assert_eq!(defs[0].field, "city");
            assert_eq!(defs[0].field_type, IndexFieldType::String);
        })
    }

    // 19. Duplicate index on the same field → IndexAlreadyExists.
    #[test]
    fn test_duplicate_index_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            let err = json
                .create_index("default", "city", IndexFieldType::Number)
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::IndexAlreadyExists { .. }), "got: {err}");
        })
    }

    // 20. Index on an unknown domain → DomainNotFound.
    #[test]
    fn test_index_on_unknown_domain_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let err = json
                .create_index("nope", "city", IndexFieldType::String)
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::DomainNotFound(_)), "got: {err}");
        })
    }

    // 21. delete_index removes the definition.
    #[test]
    fn test_delete_index() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "age", IndexFieldType::Number).await.unwrap();
            json.delete_index("default", "age").await.unwrap();
            assert!(json.get_indexes("default").unwrap().is_empty());
            let err = json.delete_index("default", "age").await.unwrap_err();
            assert!(matches!(err, JsonStoreError::IndexNotFound { .. }), "got: {err}");
        })
    }

    // 22. Index definitions survive an engine restart (recovery), with the
    //     WAL local and on the storage hub.
    #[test]
    fn test_index_recovery_after_restart() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let dir = tempfile::TempDir::new().unwrap();
                let config = config_in(dir.path());
                {
                    let (json, _hub) = bootstrap_on(&config, on_hub).await;
                    json.create_domain("persistent").await.unwrap();
                    json.create_index("persistent", "city", IndexFieldType::String).await.unwrap();
                    json.shutdown().await;
                }
                let (json, _hub) = bootstrap_on(&config, on_hub).await;
                assert!(json.get_domain("persistent").is_some(), "domain must survive restart");
                let defs = json.get_indexes("persistent").unwrap();
                assert_eq!(defs.len(), 1);
                assert_eq!(defs[0].field, "city");
                json.shutdown().await;
            }
        })
    }

    // Writes of an engine that stopped without a shutdown -- no flush, no
    // truncate -- come back from the WAL the storage hub wrote.
    #[test]
    fn test_unflushed_writes_come_back_from_the_hub_written_wal() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let config = config_in(dir.path());
            let (json, hub) = bootstrap_on(&config, true).await;
            json.create_domain("crash").await.unwrap();
            json.put_document("crash", "doc", json!({"name": "clé ✓"})).await.unwrap();
            json.engine().stop_background_tasks().await;
            drop(json);
            drop(hub);
            assert!(std::fs::metadata(&config.wal_path).unwrap().len() > 0, "the writes are only in the WAL");

            let (json, _hub) = bootstrap_on(&config, true).await;
            assert!(json.get_domain("crash").is_some());
            let doc = json.get_document("crash", "doc").await.unwrap().unwrap();
            assert_eq!(doc.content, json!({"name": "clé ✓"}));
            json.shutdown().await;
        })
    }

    // 22a. require_conditional_writes is persisted with the domain and
    //      survives a restart; a domain created without it keeps it off.
    #[test]
    fn test_conditional_writes_setting_survives_restart() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let config = JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
                ..JsonStoreConfig::default()
            };
            {
                let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
                let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
                json.create_domain_with("strict", true).await.unwrap();
                json.create_domain("plain").await.unwrap();
                json.shutdown().await;
            }
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
            assert!(json.get_domain("strict").unwrap().require_conditional_writes);
            assert!(!json.get_domain("plain").unwrap().require_conditional_writes);
            json.shutdown().await;
        })
    }

    // 22b. get_indexes_with_snapshot serves the definitions pinned by the
    //      snapshot, so index DDL during a backup export cannot leak into an
    //      archive whose documents come from an earlier point in time.
    #[test]
    fn test_get_indexes_with_snapshot_ignores_later_ddl() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            let snap = json.engine().snapshot().await;
            json.create_index("default", "age", IndexFieldType::Number).await.unwrap();

            let defs = json.get_indexes_with_snapshot("default", snap.snapshot()).await.unwrap();
            assert_eq!(defs.len(), 1, "the index created after the snapshot must not appear");
            assert_eq!(defs[0].field, "city");
            assert_eq!(defs[0].field_type, IndexFieldType::String);
            assert_eq!(json.get_indexes("default").unwrap().len(), 2, "live view sees both");
        })
    }

    // ── Optimistic concurrency ───────────────────────────────

    // 30. Conditional update with the correct version succeeds; the
    //     generation stays stable across updates.
    #[test]
    fn test_occ_correct_version_succeeds() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
            let doc = json
                .put_document_with_version(
                    "default",
                    "k",
                    json!({"n": 2}),
                    &[Precondition::IfMatch(ExpectedVersion { generation: created.generation, version: 1 })],
                )
                .await
                .unwrap();
            assert_eq!(doc.version, 2);
            assert_eq!(doc.generation, created.generation);
        })
    }

    // 31. Wrong expected version → VersionConflict with actual ETag value.
    #[test]
    fn test_occ_wrong_version_conflicts() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
            json.put_document("default", "k", json!({"n": 2})).await.unwrap();
            let err = json
                .put_document_with_version(
                    "default",
                    "k",
                    json!({"n": 3}),
                    &[Precondition::IfMatch(ExpectedVersion { generation: created.generation, version: 1 })],
                )
                .await
                .unwrap_err();
            match err {
                JsonStoreError::VersionConflict { expected, actual } => {
                    assert_eq!(expected, etag_value(created.generation, 1));
                    assert_eq!(actual, Some(etag_value(created.generation, 2)));
                }
                other => panic!("got: {other}"),
            }
            let unchanged = json.get_document("default", "k").await.unwrap().unwrap();
            assert_eq!(unchanged.content, json!({"n": 2}));
        })
    }

    // 32. Conditional update on a missing document → VersionConflict without
    //     an actual version.
    #[test]
    fn test_occ_missing_document() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let err = json
                .put_document_with_version(
                    "default",
                    "nope",
                    json!({}),
                    &[Precondition::IfMatch(ExpectedVersion { generation: 0, version: 1 })],
                )
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::VersionConflict { actual: None, .. }), "got: {err}");
        })
    }

    // 33. Two parallel conditional updates → exactly one wins.
    #[test]
    fn test_occ_parallel_updates_single_winner() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let created = json.put_document("default", "k", json!({"n": 0})).await.unwrap();
            let expected = ExpectedVersion { generation: created.generation, version: 1 };
            let tasks: Vec<_> = (0..2)
                .map(|i| {
                    let engine = Arc::clone(&json);
                    compio::runtime::spawn(async move {
                        engine
                            .put_document_with_version(
                                "default",
                                "k",
                                json!({"winner": i}),
                                &[Precondition::IfMatch(expected)],
                            )
                            .await
                    })
                })
                .collect();
            let mut ok = 0;
            let mut conflicts = 0;
            for t in tasks {
                match t.await.unwrap() {
                    Ok(_) => ok += 1,
                    Err(JsonStoreError::VersionConflict { .. }) => conflicts += 1,
                    Err(e) => panic!("unexpected error: {e}"),
                }
            }
            assert_eq!(ok, 1);
            assert_eq!(conflicts, 1);
        })
    }

    // 34. Conditional delete: correct version succeeds, wrong version conflicts.
    #[test]
    fn test_occ_conditional_delete() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
            json.put_document("default", "k", json!({"n": 2})).await.unwrap();
            let generation = created.generation;
            let err = json
                .delete_document_with_version(
                    "default",
                    "k",
                    &[Precondition::IfMatch(ExpectedVersion { generation, version: 1 })],
                )
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::VersionConflict { .. }), "got: {err}");
            assert!(json
                .delete_document_with_version(
                    "default",
                    "k",
                    &[Precondition::IfMatch(ExpectedVersion { generation, version: 2 })],
                )
                .await
                .unwrap());
            assert!(json.get_document("default", "k").await.unwrap().is_none());
        })
    }

    // 38. ABA guard: a stale ExpectedVersion of a deleted incarnation must
    //     not match the recreated document, even though both are version 1.
    #[test]
    fn test_occ_stale_version_after_delete_recreate() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let old_doc = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
            let stale =
                ExpectedVersion { generation: old_doc.generation, version: old_doc.version };
            assert!(json.delete_document("default", "k").await.unwrap());

            let new_doc = json.put_document("default", "k", json!({"n": 2})).await.unwrap();
            assert_eq!(new_doc.version, 1);
            assert_ne!(
                new_doc.generation, old_doc.generation,
                "recreate must roll a fresh generation"
            );

            let err = json
                .put_document_with_version("default", "k", json!({"n": 3}), &[Precondition::IfMatch(stale)])
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::VersionConflict { .. }), "got: {err}");
            let err = json
                .delete_document_with_version("default", "k", &[Precondition::IfMatch(stale)])
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::VersionConflict { .. }), "got: {err}");
            let unchanged = json.get_document("default", "k").await.unwrap().unwrap();
            assert_eq!(unchanged.content, json!({"n": 2}), "lost update must not happen");
        })
    }

    // ── Create-only precondition ─────────────────────────────

    // 39. Two parallel create-only-PUTs on the same free key → exactly one
    //     creates, the other sees DocumentAlreadyExists; the key's write
    //     shard serializes the race (same pattern as test 33).
    #[test]
    fn test_create_only_parallel_puts_single_winner() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let tasks: Vec<_> = (0..2)
                .map(|i| {
                    let engine = Arc::clone(&json);
                    compio::runtime::spawn(async move {
                        engine
                            .put_document_with_version(
                                "default",
                                "k",
                                json!({"winner": i}),
                                &[Precondition::MustNotExist],
                            )
                            .await
                    })
                })
                .collect();
            let mut created = 0;
            let mut exists = 0;
            for t in tasks {
                match t.await.unwrap() {
                    Ok(doc) => {
                        assert_eq!(doc.version, 1);
                        created += 1;
                    }
                    Err(JsonStoreError::DocumentAlreadyExists { .. }) => exists += 1,
                    Err(e) => panic!("unexpected error: {e}"),
                }
            }
            assert_eq!(created, 1);
            assert_eq!(exists, 1);
        })
    }

    // ── Sharded document-write locks ─────────────────────────

    // 40. A held write shard blocks only keys of that shard: a put on a key
    //     of another shard runs through, one on the same shard waits.
    #[test]
    fn test_writes_serialize_per_shard_only() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let held = JsonEngine::shard("default", "anchor");
            let other_shard_key = (0..)
                .map(|i| format!("o{i}"))
                .find(|k| JsonEngine::shard("default", k) != held)
                .unwrap();
            let same_shard_key = (0..)
                .map(|i| format!("s{i}"))
                .find(|k| JsonEngine::shard("default", k) == held)
                .unwrap();

            let guard = json.doc_write_locks[held].lock().await;

            let free = compio::runtime::spawn({
                let json = Arc::clone(&json);
                async move { json.put_document("default", &other_shard_key, json!({"n": 1})).await }
            });
            compio::time::timeout(std::time::Duration::from_secs(5), free)
                .await
                .expect("a key of another shard must not wait")
                .unwrap()
                .unwrap();

            let parked = compio::runtime::spawn({
                let json = Arc::clone(&json);
                async move { json.put_document("default", &same_shard_key, json!({"n": 2})).await }
            });
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            assert!(!parked.is_finished(), "a key of the held shard must wait");
            drop(guard);
            parked.await.unwrap().unwrap();
        })
    }

    // 41. The same document reference always maps to the same shard, and the
    //     domain is part of the hash (no forced collision across domains).
    #[test]
    fn test_shard_is_stable_and_domain_aware() {
        crate::core::engine_runtime::block_on(async {
            assert_eq!(JsonEngine::shard("a", "k"), JsonEngine::shard("a", "k"));
            assert!((0..DOC_WRITE_SHARDS).contains(&JsonEngine::shard("a", "k")));
            let differs = (0..64).any(|i| {
                let key = format!("k{i}");
                JsonEngine::shard("a", &key) != JsonEngine::shard("b", &key)
            });
            assert!(differs, "domain must feed the hash");
        })
    }

    // ── Synchronous indexing ─────────────────────────────────

    async fn default_prefix(json: &JsonEngine) -> Vec<u8> {
        json.get_domain("default").unwrap().system_prefix
    }

    async fn scan_field(json: &JsonEngine, prefix: &[u8], field: &str) -> Vec<Vec<u8>> {
        json.engine()
            .scan_keys(&index::index_field_prefix(prefix, field))
            .await
            .unwrap()
    }

    // 23. put_document writes an IDX entry (verified via raw LSM lookup).
    #[test]
    fn test_put_creates_index_entry() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.put_document("default", "u1", json!({"city": "Essen"})).await.unwrap();
            let prefix = default_prefix(&json).await;
            let idx = index::index_key(&prefix, "city", b"Essen", "u1");
            assert!(json.engine().get(&idx).await.unwrap().is_some());
        })
    }

    // 24. Update replaces the stale index entry with the new one, in one
    //     batch, with the WAL local and on the storage hub.
    #[test]
    fn test_update_swaps_index_entry() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let (json, _hub, _dir) = make_engine_on(on_hub).await;
                json.create_index("default", "city", IndexFieldType::String).await.unwrap();
                json.put_document("default", "u1", json!({"city": "Essen"})).await.unwrap();
                json.put_document("default", "u1", json!({"city": "Berlin"})).await.unwrap();
                let prefix = default_prefix(&json).await;
                let old_idx = index::index_key(&prefix, "city", b"Essen", "u1");
                let new_idx = index::index_key(&prefix, "city", b"Berlin", "u1");
                assert!(json.engine().get(&old_idx).await.unwrap().is_none(), "stale entry must be gone");
                assert!(json.engine().get(&new_idx).await.unwrap().is_some());
            }
        })
    }

    // 25. delete_document removes the index entry.
    #[test]
    fn test_delete_removes_index_entry() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.put_document("default", "u1", json!({"city": "Essen"})).await.unwrap();
            json.delete_document("default", "u1").await.unwrap();
            let prefix = default_prefix(&json).await;
            assert!(scan_field(&json, &prefix, "city").await.is_empty());
            assert!(json.get_document("default", "u1").await.unwrap().is_none());
        })
    }

    // 26. Missing indexed field → no entry, no error.
    #[test]
    fn test_missing_field_not_indexed() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.put_document("default", "u1", json!({"name": "Ada"})).await.unwrap();
            let prefix = default_prefix(&json).await;
            assert!(scan_field(&json, &prefix, "city").await.is_empty());
        })
    }

    // 27. null in the indexed field → no entry.
    #[test]
    fn test_null_field_not_indexed() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.put_document("default", "u1", json!({"city": null})).await.unwrap();
            let prefix = default_prefix(&json).await;
            assert!(scan_field(&json, &prefix, "city").await.is_empty());
        })
    }

    // 28. Empty string is a valid indexed value.
    #[test]
    fn test_empty_string_indexed() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.put_document("default", "u1", json!({"city": ""})).await.unwrap();
            let prefix = default_prefix(&json).await;
            let idx = index::index_key(&prefix, "city", b"", "u1");
            assert!(json.engine().get(&idx).await.unwrap().is_some());
        })
    }

    // 29. Multiple indexes per domain are all maintained.
    #[test]
    fn test_multiple_indexes_maintained() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.create_index("default", "age", IndexFieldType::Number).await.unwrap();
            json.put_document("default", "u1", json!({"city": "Essen", "age": 30})).await.unwrap();
            let prefix = default_prefix(&json).await;
            let age30 = index::encode_index_value(&json!(30), IndexFieldType::Number).unwrap();
            assert!(json.engine().get(&index::index_key(&prefix, "city", b"Essen", "u1")).await.unwrap().is_some());
            assert!(json.engine().get(&index::index_key(&prefix, "age", &age30, "u1")).await.unwrap().is_some());

            json.put_document("default", "u1", json!({"city": "Essen", "age": 31})).await.unwrap();
            let age31 = index::encode_index_value(&json!(31), IndexFieldType::Number).unwrap();
            assert!(json.engine().get(&index::index_key(&prefix, "age", &age30, "u1")).await.unwrap().is_none());
            assert!(json.engine().get(&index::index_key(&prefix, "age", &age31, "u1")).await.unwrap().is_some());
            assert!(json.engine().get(&index::index_key(&prefix, "city", b"Essen", "u1")).await.unwrap().is_some(), "unchanged field entry must survive");

            json.delete_document("default", "u1").await.unwrap();
            assert!(scan_field(&json, &prefix, "city").await.is_empty());
            assert!(scan_field(&json, &prefix, "age").await.is_empty());
        })
    }

    // 35. delete_index tombstones the field's IDX entries; other fields keep theirs.
    #[test]
    fn test_delete_index_tombstones_entries() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.create_index("default", "age", IndexFieldType::Number).await.unwrap();
            json.put_document("default", "u1", json!({"city": "Essen", "age": 30})).await.unwrap();
            json.delete_index("default", "city").await.unwrap();
            let prefix = default_prefix(&json).await;
            assert!(scan_field(&json, &prefix, "city").await.is_empty(), "IDX entries must be gone");
            assert_eq!(scan_field(&json, &prefix, "age").await.len(), 1, "other index untouched");
        })
    }

    // 36. Keys valid per config but too long for the composite LSM key are
    //     rejected upfront with InvalidKey (400), not StorageError (500);
    //     keys at the effective limit still work.
    #[test]
    fn test_overlong_key_invalid_key_not_storage_error() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            let err = json
                .put_document("default", &"x".repeat(240), json!({}))
                .await
                .unwrap_err();
            assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
            // 235 + 21 bytes overhead = LSM limit 256 → still valid.
            json.put_document("default", &"x".repeat(235), json!({})).await.unwrap();
        })
    }

    // 36b. Documents stored under a key that a later config lowers below
    //      stay readable through the snapshot path: the backup export feeds
    //      back keys the engine itself produced, so re-validating them would
    //      abort every export of the domain. The live path keeps validating.
    #[test]
    fn test_snapshot_read_ignores_lowered_key_limit() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let config = JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
                ..JsonStoreConfig::default()
            };
            let long_key = "k".repeat(100);
            {
                let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
                let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
                json.put_document("default", &long_key, json!({"n": 1})).await.unwrap();
                json.shutdown().await;
            }
            let lowered = JsonStoreConfig {
                lsm: crate::config::JsonLsmConfig { max_key_length: 32 + DOC_KEY_OVERHEAD, ..config.lsm },
                ..config
            };
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let json = JsonEngine::bootstrap(&lowered, metrics).await.unwrap();
            let snap = json.engine().snapshot().await;
            let doc = json
                .get_document_with_snapshot("default", &long_key, snap.snapshot())
                .await
                .unwrap()
                .expect("the stored document must stay exportable");
            assert_eq!(doc.content, json!({"n": 1}));
            assert!(
                matches!(json.get_document("default", &long_key).await, Err(JsonStoreError::InvalidKey(_))),
                "caller input on the live path is still validated"
            );
            json.shutdown().await;
        })
    }

    // 37. create_document with an effective key limit below the UUID length
    //     fails with a clear InvalidKey error instead of writing documents
    //     unreachable via get/put/delete.
    #[test]
    fn test_create_document_rejects_too_small_key_limit() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let config = JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
                lsm: crate::config::JsonLsmConfig { max_key_length: 20 + DOC_KEY_OVERHEAD, ..Default::default() },
                ..JsonStoreConfig::default()
            };
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
            let err = json.create_document("default", json!({})).await.unwrap_err();
            assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
            json.shutdown().await;
        })
    }

    // With both LSM limits at their startup lower
    // bounds, a domain with a maximal name and a document with a 1-byte key work.
    #[test]
    fn test_lsm_limits_at_lower_bounds_still_work() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let config = JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
                lsm: crate::config::JsonLsmConfig {
                    max_key_length: domain::MIN_LSM_KEY_LENGTH,
                    max_value_size: crate::config::JSON_LSM_MIN_VALUE_SIZE,
                },
                ..JsonStoreConfig::default()
            };
            config.validate().unwrap();
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();

            let domain = "d".repeat(domain::MAX_DOMAIN_NAME_LEN);
            json.create_domain(&domain).await.unwrap();
            json.put_document(&domain, "a", json!({"n": 1})).await.unwrap();
            let doc = json.get_document(&domain, "a").await.unwrap().expect("document stored");
            assert_eq!(doc.content, json!({"n": 1}));
            json.shutdown().await;
        })
    }

    // ── Global lifecycle event bus ────────────────────────

    // Test 5: create_index/delete_index publish index_created/index_dropped
    // with engine "json" and the field name as `object`.
    #[test]
    fn test_index_events_published_with_field_as_object() {
        crate::core::engine_runtime::block_on(async {
            let (json, dir) = make_engine().await;
            let bus = Arc::new(crate::core::events::GlobalEventBus::new(16, 16));
            let kv = crate::control::testing::kv_registry(dir.path()).await;
            crate::control::testing::start(dir.path(), kv, Some(Arc::clone(&json)), None, Arc::clone(&bus)).await;
            let mut rx = bus.subscribe();

            json.create_index("default", "city", IndexFieldType::String).await.unwrap();
            json.delete_index("default", "city").await.unwrap();

            let created = rx.try_recv().unwrap();
            assert_eq!(created.engine, "json");
            assert_eq!(created.kind, "index_created");
            assert_eq!(created.domain, "default");
            assert_eq!(created.object.as_deref(), Some("city"));

            let dropped = rx.try_recv().unwrap();
            assert_eq!(dropped.kind, "index_dropped");
            assert_eq!(dropped.object.as_deref(), Some("city"));
        })
    }

    // Without a control plane, domain and index ops succeed unchanged, no panic.
    #[test]
    fn test_lifecycle_and_index_ops_without_control_plane_succeed() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;
            json.create_domain("no-bus").await.unwrap();
            json.create_index("no-bus", "city", IndexFieldType::String).await.unwrap();
            json.delete_index("no-bus", "city").await.unwrap();
            json.delete_domain("no-bus").await.unwrap();
        })
    }

    // ── Per-engine metrics — no double counting ───────────

    // Test 7: put_document (-> put_document_with_version -> write_document)
    // is exactly 1 write_op; a conditional put_document_with_version (which
    // reads the old version first) is still exactly 1 write_op and 0
    // read_ops -- the read-before-write does not count; delete_document is
    // exactly 1 write_op.
    #[test]
    fn test_engine_metrics_no_double_counting() {
        crate::core::engine_runtime::block_on(async {
            let (json, _dir) = make_engine().await;

            // aggregate_engine only sums fully ticked buckets.
            let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
            json.metrics.tick_all();
            let after_put = json.metrics.engine_metrics();
            assert_eq!(after_put[EngineKind::Json as usize].write_ops, 1);

            json.put_document_with_version(
                "default",
                "k",
                json!({"n": 2}),
                &[Precondition::IfMatch(ExpectedVersion { generation: created.generation, version: 1 })],
            )
            .await
            .unwrap();
            json.metrics.tick_all();
            let after_conditional_put = json.metrics.engine_metrics();
            assert_eq!(
                after_conditional_put[EngineKind::Json as usize].write_ops, 2,
                "exactly one more write_op, not two"
            );
            assert_eq!(
                after_conditional_put[EngineKind::Json as usize].read_ops, 0,
                "the read-before-write inside put_document_with_version must not count"
            );

            json.delete_document("default", "k").await.unwrap();
            json.metrics.tick_all();
            let after_delete = json.metrics.engine_metrics();
            assert_eq!(after_delete[EngineKind::Json as usize].write_ops, 3);
        })
    }
}
