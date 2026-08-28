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

use crate::config::JsonStoreConfig;
use crate::core::events::GlobalEventBus;
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

/// Number of document-write lock shards (spec json/018). Not configurable —
/// the number only caps the collision probability.
const DOC_WRITE_SHARDS: usize = 64;

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
    /// scopes status lookups (json/009: no cross-domain task reads).
    reindex_tasks: RwLock<HashMap<String, (String, ReindexStatus)>>,
    /// Domains with a currently running re-index (domain → task_id).
    reindex_running: SyncMutex<HashMap<String, String>>,
    /// Serializes read→write in document writes so version checks (OCC,
    /// json/011) cannot race, and fences writers against the purger's
    /// finalize: domain state is checked under the shard guard (json/013).
    /// Sharded per document reference (json/018) — writes on keys of
    /// different shards no longer wait for each other.
    doc_write_locks: [tokio::sync::Mutex<()>; DOC_WRITE_SHARDS],
    /// Global lifecycle/DDL event bus (spec general/018 §1) — backs
    /// `create_index`/`delete_index`'s `index_created`/`index_dropped`;
    /// domain lifecycle events are published by `domains` itself. Unset in
    /// unit tests and a standalone-built engine, which then publish nothing.
    event_bus: OnceLock<Arc<GlobalEventBus>>,
    /// Engine-aggregate op/latency window (spec general/019). No `Option`,
    /// no setter — always supplied at bootstrap.
    metrics: Arc<MetricsStore>,
}

impl JsonEngine {
    /// Creates the dedicated JSON LSM instance from `config` and starts its
    /// background tasks (flush, compaction, janitor).
    pub async fn bootstrap(config: &JsonStoreConfig, metrics: Arc<MetricsStore>) -> Result<Arc<Self>> {
        let wal_path = PathBuf::from(&config.wal_path);
        let vlog_path = PathBuf::from(&config.vlog_path);
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await?);
        let vlog = Arc::new(VLog::new(&vlog_path).await?);
        let file_manager = Arc::new(FileManager::new(&config.sstable_dir).await?);
        let manifest_manager = Arc::new(ManifestManager::new(&config.sstable_dir));

        let engine_config = LsmEngineConfig {
            vlog_inline_threshold: config.lsm.vlog_inline_threshold,
            memtable_size_threshold: config.lsm.memtable_size_threshold,
            max_key_length: config.lsm.max_key_length,
            max_value_size: config.lsm.max_value_size,
            flush_check_interval_ms: config.lsm.flush_check_interval_ms,
            compaction_check_interval_ms: config.lsm.compaction_check_interval_ms,
            wal_event_channel_capacity: config.lsm.wal_event_channel_capacity,
            use_mmap: config.lsm.use_mmap,
            watch_replay_buffer_size: 0, // no watch endpoint on the JSON engine (spec kv/024 §3)
        };
        let compaction_config = CompactionConfig {
            l0_compaction_threshold: config.compaction.l0_threshold,
            l1_max_size: config.compaction.l1_max_size,
            level_size_ratio: config.compaction.level_size_ratio,
            max_sstable_size: config.compaction.max_sstable_size,
            low_watermark: None,
        };
        let janitor_config = JanitorConfig {
            check_interval_secs: config.janitor.check_interval_secs,
            dead_bytes_threshold: config.janitor.dead_bytes_threshold,
            min_vlog_size_bytes: config.janitor.min_vlog_size_bytes,
        };
        let block_cache_config = crate::config::BlockCacheConfig {
            capacity_bytes: config.block_cache.capacity_bytes,
            small_ratio: config.block_cache.small_ratio,
            ghost_capacity: config.block_cache.ghost_capacity,
        };

        let engine = Arc::new(
            LsmStorageEngine::new(
                wal,
                wal_path,
                vlog,
                vlog_path,
                file_manager,
                manifest_manager,
                LsmEngineOptions {
                    engine: engine_config,
                    compaction: compaction_config,
                    janitor: janitor_config,
                    block_cache: block_cache_config,
                },
            )
            .await?,
        );
        engine.start_background_tasks();
        let domains = Arc::new(JsonDomainRegistry::recover(Arc::clone(&engine)).await?);
        let indexes = Arc::new(IndexRegistry::recover(Arc::clone(&engine)).await?);
        Ok(Arc::new(Self {
            engine,
            domains,
            indexes,
            max_value_size: config.lsm.max_value_size,
            // Effective limit: the composite doc key must fit the LSM key
            // limit, otherwise valid keys fail deep in the engine (500).
            max_document_key_length: config
                .max_document_key_length
                .min(config.lsm.max_key_length.saturating_sub(DOC_KEY_OVERHEAD)),
            max_lsm_key_length: config.lsm.max_key_length,
            bulk_batch_size: config.bulk_batch_size.max(1),
            bulk_body_limit_bytes: config.bulk_body_limit_bytes,
            reindex_batch_size: config.reindex_batch_size.max(1),
            reindex_pause_ms: config.reindex_pause_ms,
            reindex_tasks: RwLock::new(HashMap::new()),
            reindex_running: SyncMutex::new(HashMap::new()),
            doc_write_locks: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
            event_bus: OnceLock::new(),
            metrics,
        }))
    }

    /// The dedicated JSON LSM instance.
    pub fn engine(&self) -> &Arc<LsmStorageEngine> {
        &self.engine
    }

    /// Wires the global event bus (spec general/018 §1): its own `OnceLock`
    /// backs `create_index`/`delete_index`, and it forwards to `domains` for
    /// the domain lifecycle events.
    pub fn attach_event_bus(&self, bus: Arc<GlobalEventBus>) {
        self.domains.attach_event_bus(Arc::clone(&bus));
        let _ = self.event_bus.set(bus);
    }

    /// Max HTTP body size for bulk imports (applied at router build).
    pub fn bulk_body_limit_bytes(&self) -> usize {
        self.bulk_body_limit_bytes
    }

    /// Gracefully shuts down the underlying LSM instance.
    pub async fn shutdown(&self) {
        self.engine.shutdown().await;
    }

    // ── Domain management (spec json/003) ─────────────────────────────────────

    /// Creates a new JSON domain.
    pub async fn create_domain(&self, name: &str) -> Result<JsonDomain, JsonStoreError> {
        self.domains.create_domain(name).await
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
    pub async fn delete_domain(&self, name: &str) -> Result<(), JsonStoreError> {
        self.domains.delete_domain(name).await
    }

    // ── Index management (spec json/004) ──────────────────────────────────────

    /// Creates an index definition on `field` for an existing domain.
    ///
    /// Existing documents are NOT back-indexed here (that is re-indexing,
    /// spec json/008); new writes pick the index up from spec json/005 on.
    pub async fn create_index(
        &self,
        domain: &str,
        field: &str,
        field_type: IndexFieldType,
    ) -> Result<IndexDefinition, JsonStoreError> {
        let def = self.indexes.create_index(&self.domains, domain, field, field_type).await?;
        if let Some(bus) = self.event_bus.get() {
            bus.publish("json", "index_created", domain, Some(field.to_string()));
        }
        Ok(def)
    }

    /// All index definitions of a domain.
    pub fn get_indexes(&self, domain: &str) -> Result<Vec<IndexDefinition>, JsonStoreError> {
        self.domains.require_active(domain)?;
        Ok(self.indexes.get_indexes(domain))
    }

    /// Like [`Self::get_indexes`], but read from the persisted definitions
    /// visible under `snapshot` instead of the live cache (spec general/006
    /// backup export) — index DDL during an export must not leak into the
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
        if let Some(bus) = self.event_bus.get() {
            bus.publish("json", "index_dropped", domain, Some(field.to_string()));
        }
        Ok(())
    }

    // ── Document write locks (spec json/018) ──────────────────────────────────

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

    // ── Core CRUD (spec json/002, domain-aware since json/003) ────────────────

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
                "generated UUID key needs {} chars but the effective key limit is {} — raise json.max_document_key_length or json.lsm.max_key_length",
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
        self.put_document_with_version(domain, key, content, None).await
    }

    /// Upsert with an optional write precondition: `Precondition::IfMatch`
    /// is the optimistic concurrency check of spec json/011 (fails with
    /// `DocumentNotFound` if the document is missing or `VersionConflict` if
    /// generation or version differ — a stale ETag of a deleted incarnation
    /// never matches); `Precondition::MustNotExist` is the create-only write
    /// of spec json/014 (fails with `DocumentAlreadyExists` if it is present).
    pub async fn put_document_with_version(
        &self,
        domain: &str,
        key: &str,
        content: Value,
        precondition: Option<Precondition>,
    ) -> Result<Document, JsonStoreError> {
        validate_document_key(key, self.max_document_key_length)?;
        reject_reserved_fields(&content)?;
        let _guard = self.doc_write_locks[Self::shard(domain, key)].lock().await;
        let dom = self.domains.require_active(domain)?;
        let old = self.read_stored(&dom, key).await?;
        if let Some(precondition) = precondition {
            match precondition {
                Precondition::IfMatch(expected) => match &old {
                    None => {
                        return Err(JsonStoreError::DocumentNotFound {
                            domain: dom.name.clone(),
                            key: key.to_string(),
                        })
                    }
                    Some(o)
                        if o.generation != expected.generation
                            || o.version != expected.version =>
                    {
                        return Err(JsonStoreError::VersionConflict {
                            expected: etag_value(expected.generation, expected.version),
                            actual: etag_value(o.generation, o.version),
                        })
                    }
                    Some(_) => {}
                },
                Precondition::MustNotExist => {
                    if old.is_some() {
                        return Err(JsonStoreError::DocumentAlreadyExists {
                            domain: dom.name.clone(),
                            key: key.to_string(),
                        });
                    }
                }
            }
        }
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
    /// instead of one acquired internally (spec general/006 backup export) —
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
        self.delete_document_with_version(domain, key, None).await
    }

    /// Delete with optional optimistic concurrency check (spec json/011).
    pub async fn delete_document_with_version(
        &self,
        domain: &str,
        key: &str,
        expected_version: Option<ExpectedVersion>,
    ) -> Result<bool, JsonStoreError> {
        let start = std::time::Instant::now();
        validate_document_key(key, self.max_document_key_length)?;
        let _guard = self.doc_write_locks[Self::shard(domain, key)].lock().await;
        let dom = self.domains.require_active(domain)?;
        let old = match self.read_stored(&dom, key).await? {
            Some(old) => old,
            None => {
                return match expected_version {
                    Some(_) => Err(JsonStoreError::DocumentNotFound {
                        domain: dom.name.clone(),
                        key: key.to_string(),
                    }),
                    None => Ok(false),
                }
            }
        };
        if let Some(expected) = expected_version {
            if old.generation != expected.generation || old.version != expected.version {
                return Err(JsonStoreError::VersionConflict {
                    expected: etag_value(expected.generation, expected.version),
                    actual: etag_value(old.generation, old.version),
                });
            }
        }
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
    /// (spec general/006 backup export) instead of one acquired internally.
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
    /// entries are written (synchronous indexing, spec json/005).
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn make_engine() -> (Arc<JsonEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        };
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let engine = JsonEngine::bootstrap(&config, metrics).await.unwrap();
        (engine, dir)
    }

    // 1. Bootstrap creates a working second LSM instance (put/get roundtrip).
    #[tokio::test]
    async fn test_bootstrap_put_get_roundtrip() {
        let (json, _dir) = make_engine().await;
        json.engine().put(b"doc:1", b"{}").await.unwrap();
        let snap = json.engine().snapshot();
        let got = json
            .engine()
            .get_with_snapshot(b"doc:1", snap.snapshot())
            .await
            .unwrap()
            .into_option();
        assert_eq!(got, Some(b"{}".to_vec()));
        json.shutdown().await;
    }

    // 2. Bootstrap creates the sstable directory if it does not exist.
    #[tokio::test]
    async fn test_bootstrap_creates_sstable_dir() {
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
    }

    // 3. create_document → get_document returns identical content.
    #[tokio::test]
    async fn test_create_then_get_roundtrip() {
        let (json, _dir) = make_engine().await;
        json.create_domain("people").await.unwrap();
        let content = json!({"name": "Ada", "tags": ["a", "b"], "age": 42});
        let doc = json.create_document("people", content.clone()).await.unwrap();
        assert_eq!(doc.version, 1);
        let fetched = json.get_document("people", &doc.key).await.unwrap().unwrap();
        assert_eq!(fetched.content, content);
        assert_eq!(fetched.version, 1);
        assert_eq!(fetched.domain, "people");
    }

    // 4. create_document generates a valid UUIDv4 key.
    #[tokio::test]
    async fn test_create_generates_uuid_v4() {
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
    }

    // 5. put_document → get_document returns identical content.
    #[tokio::test]
    async fn test_put_then_get_roundtrip() {
        let (json, _dir) = make_engine().await;
        json.create_domain("catalog").await.unwrap();
        let content = json!({"sku": "X-1", "price": 9.99});
        json.put_document("catalog", "item-1", content.clone()).await.unwrap();
        let fetched = json.get_document("catalog", "item-1").await.unwrap().unwrap();
        assert_eq!(fetched.content, content);
        assert_eq!(fetched.key, "item-1");
    }

    // 6. put_document twice increments the version.
    #[tokio::test]
    async fn test_put_twice_increments_version() {
        let (json, _dir) = make_engine().await;
        let v1 = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
        assert_eq!(v1.version, 1);
        let v2 = json.put_document("default", "k", json!({"n": 2})).await.unwrap();
        assert_eq!(v2.version, 2);
        let fetched = json.get_document("default", "k").await.unwrap().unwrap();
        assert_eq!(fetched.version, 2);
        assert_eq!(fetched.content, json!({"n": 2}));
    }

    // 7. delete_document → get_document returns None.
    #[tokio::test]
    async fn test_delete_then_get_none() {
        let (json, _dir) = make_engine().await;
        json.put_document("default", "gone", json!({})).await.unwrap();
        assert!(json.delete_document("default", "gone").await.unwrap());
        assert!(json.get_document("default", "gone").await.unwrap().is_none());
    }

    // 8. delete_document on a missing key returns false.
    #[tokio::test]
    async fn test_delete_missing_returns_false() {
        let (json, _dir) = make_engine().await;
        assert!(!json.delete_document("default", "never-existed").await.unwrap());
    }

    // 9. Empty key is rejected with InvalidKey.
    #[tokio::test]
    async fn test_empty_key_rejected() {
        let (json, _dir) = make_engine().await;
        let err = json.put_document("default", "", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
    }

    // 10. Key containing a colon is rejected with InvalidKey.
    #[tokio::test]
    async fn test_colon_key_rejected() {
        let (json, _dir) = make_engine().await;
        let err = json.put_document("default", "a:b", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
    }

    // 10b. A document with a reserved top-level field smuggled in before
    //      this check existed (direct write_batch, bypassing
    //      create_document/put_document_with_version) stays readable via
    //      get_document -- overshadowed, no new read error (spec json/017
    //      §3 test 6; no migration/scan step for existing data).
    #[tokio::test]
    async fn test_legacy_document_with_reserved_field_stays_readable() {
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
    }

    // 11. Domain create → get_domain returns it.
    #[tokio::test]
    async fn test_create_and_get_domain() {
        let (json, _dir) = make_engine().await;
        let created = json.create_domain("alpha").await.unwrap();
        assert_eq!(created.system_prefix.len(), 16);
        let fetched = json.get_domain("alpha").unwrap();
        assert_eq!(fetched.name, "alpha");
        assert_eq!(fetched.system_prefix, created.system_prefix);
    }

    // 12. Duplicate domain → DomainAlreadyExists.
    #[tokio::test]
    async fn test_duplicate_domain_rejected() {
        let (json, _dir) = make_engine().await;
        json.create_domain("beta").await.unwrap();
        let err = json.create_domain("beta").await.unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainAlreadyExists(_)), "got: {err}");
    }

    // 13. Invalid domain names → InvalidDomainName. "domains" is reserved:
    //     the static /json/domains admin routes shadow such a domain.
    #[tokio::test]
    async fn test_invalid_domain_name_rejected() {
        let (json, _dir) = make_engine().await;
        for bad in ["", "bad name!", "bad/slash", "domains", &"x".repeat(51)] {
            let err = json.create_domain(bad).await.unwrap_err();
            assert!(
                matches!(err, JsonStoreError::InvalidDomainName(_)),
                "'{bad}' got: {err}"
            );
        }
    }

    // 14. Same key in two domains is isolated.
    #[tokio::test]
    async fn test_domain_isolation() {
        let (json, _dir) = make_engine().await;
        json.create_domain("tenant-a").await.unwrap();
        json.create_domain("tenant-b").await.unwrap();
        json.put_document("tenant-a", "secret", json!({"of": "a"})).await.unwrap();
        assert!(json.get_document("tenant-b", "secret").await.unwrap().is_none());
    }

    // 15. put_document into an unknown domain → DomainNotFound.
    #[tokio::test]
    async fn test_put_into_unknown_domain_rejected() {
        let (json, _dir) = make_engine().await;
        let err = json.put_document("nope", "k", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainNotFound(_)), "got: {err}");
    }

    // 16. Default domain exists after bootstrap/recovery.
    #[tokio::test]
    async fn test_default_domain_exists() {
        let (json, _dir) = make_engine().await;
        assert!(json.get_domain("default").is_some());
    }

    // 17. list_domains contains all domains; deleting ones carry their state
    //     (spec json/013 supersedes the json/003 hide-behaviour).
    #[tokio::test]
    async fn test_list_domains() {
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
    }

    // 18. create_index → get_indexes returns it.
    #[tokio::test]
    async fn test_create_and_get_index() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let defs = json.get_indexes("default").unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].field, "city");
        assert_eq!(defs[0].field_type, IndexFieldType::String);
    }

    // 19. Duplicate index on the same field → IndexAlreadyExists.
    #[tokio::test]
    async fn test_duplicate_index_rejected() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let err = json
            .create_index("default", "city", IndexFieldType::Number)
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::IndexAlreadyExists { .. }), "got: {err}");
    }

    // 20. Index on an unknown domain → DomainNotFound.
    #[tokio::test]
    async fn test_index_on_unknown_domain_rejected() {
        let (json, _dir) = make_engine().await;
        let err = json
            .create_index("nope", "city", IndexFieldType::String)
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainNotFound(_)), "got: {err}");
    }

    // 21. delete_index removes the definition.
    #[tokio::test]
    async fn test_delete_index() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "age", IndexFieldType::Number).await.unwrap();
        json.delete_index("default", "age").await.unwrap();
        assert!(json.get_indexes("default").unwrap().is_empty());
        let err = json.delete_index("default", "age").await.unwrap_err();
        assert!(matches!(err, JsonStoreError::IndexNotFound { .. }), "got: {err}");
    }

    // 22. Index definitions survive an engine restart (recovery).
    #[tokio::test]
    async fn test_index_recovery_after_restart() {
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
            json.create_domain("persistent").await.unwrap();
            json.create_index("persistent", "city", IndexFieldType::String).await.unwrap();
            json.shutdown().await;
        }
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
        assert!(json.get_domain("persistent").is_some(), "domain must survive restart");
        let defs = json.get_indexes("persistent").unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].field, "city");
        json.shutdown().await;
    }

    // 22b. get_indexes_with_snapshot serves the definitions pinned by the
    //      snapshot, so index DDL during a backup export cannot leak into an
    //      archive whose documents come from an earlier point in time.
    #[tokio::test]
    async fn test_get_indexes_with_snapshot_ignores_later_ddl() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let snap = json.engine().snapshot();
        json.create_index("default", "age", IndexFieldType::Number).await.unwrap();

        let defs = json.get_indexes_with_snapshot("default", snap.snapshot()).await.unwrap();
        assert_eq!(defs.len(), 1, "the index created after the snapshot must not appear");
        assert_eq!(defs[0].field, "city");
        assert_eq!(defs[0].field_type, IndexFieldType::String);
        assert_eq!(json.get_indexes("default").unwrap().len(), 2, "live view sees both");
    }

    // ── Optimistic concurrency (spec json/011) ───────────────────────────────

    // 30. Conditional update with the correct version succeeds; the
    //     generation stays stable across updates.
    #[tokio::test]
    async fn test_occ_correct_version_succeeds() {
        let (json, _dir) = make_engine().await;
        let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
        let doc = json
            .put_document_with_version(
                "default",
                "k",
                json!({"n": 2}),
                Some(Precondition::IfMatch(ExpectedVersion { generation: created.generation, version: 1 })),
            )
            .await
            .unwrap();
        assert_eq!(doc.version, 2);
        assert_eq!(doc.generation, created.generation);
    }

    // 31. Wrong expected version → VersionConflict with actual ETag value.
    #[tokio::test]
    async fn test_occ_wrong_version_conflicts() {
        let (json, _dir) = make_engine().await;
        let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
        json.put_document("default", "k", json!({"n": 2})).await.unwrap();
        let err = json
            .put_document_with_version(
                "default",
                "k",
                json!({"n": 3}),
                Some(Precondition::IfMatch(ExpectedVersion { generation: created.generation, version: 1 })),
            )
            .await
            .unwrap_err();
        match err {
            JsonStoreError::VersionConflict { expected, actual } => {
                assert_eq!(expected, etag_value(created.generation, 1));
                assert_eq!(actual, etag_value(created.generation, 2));
            }
            other => panic!("got: {other}"),
        }
        let unchanged = json.get_document("default", "k").await.unwrap().unwrap();
        assert_eq!(unchanged.content, json!({"n": 2}));
    }

    // 32. Conditional update on a missing document → DocumentNotFound.
    #[tokio::test]
    async fn test_occ_missing_document() {
        let (json, _dir) = make_engine().await;
        let err = json
            .put_document_with_version(
                "default",
                "nope",
                json!({}),
                Some(Precondition::IfMatch(ExpectedVersion { generation: 0, version: 1 })),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::DocumentNotFound { .. }), "got: {err}");
    }

    // 33. Two parallel conditional updates → exactly one wins.
    #[tokio::test]
    async fn test_occ_parallel_updates_single_winner() {
        let (json, _dir) = make_engine().await;
        let created = json.put_document("default", "k", json!({"n": 0})).await.unwrap();
        let expected = ExpectedVersion { generation: created.generation, version: 1 };
        let tasks: Vec<_> = (0..2)
            .map(|i| {
                let engine = Arc::clone(&json);
                tokio::spawn(async move {
                    engine
                        .put_document_with_version(
                            "default",
                            "k",
                            json!({"winner": i}),
                            Some(Precondition::IfMatch(expected)),
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
    }

    // 34. Conditional delete: correct version succeeds, wrong version conflicts.
    #[tokio::test]
    async fn test_occ_conditional_delete() {
        let (json, _dir) = make_engine().await;
        let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
        json.put_document("default", "k", json!({"n": 2})).await.unwrap();
        let generation = created.generation;
        let err = json
            .delete_document_with_version(
                "default",
                "k",
                Some(ExpectedVersion { generation, version: 1 }),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::VersionConflict { .. }), "got: {err}");
        assert!(json
            .delete_document_with_version(
                "default",
                "k",
                Some(ExpectedVersion { generation, version: 2 }),
            )
            .await
            .unwrap());
        assert!(json.get_document("default", "k").await.unwrap().is_none());
    }

    // 38. ABA guard: a stale ExpectedVersion of a deleted incarnation must
    //     not match the recreated document, even though both are version 1.
    #[tokio::test]
    async fn test_occ_stale_version_after_delete_recreate() {
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
            .put_document_with_version("default", "k", json!({"n": 3}), Some(Precondition::IfMatch(stale)))
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::VersionConflict { .. }), "got: {err}");
        let err = json
            .delete_document_with_version("default", "k", Some(stale))
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::VersionConflict { .. }), "got: {err}");
        let unchanged = json.get_document("default", "k").await.unwrap().unwrap();
        assert_eq!(unchanged.content, json!({"n": 2}), "lost update must not happen");
    }

    // ── Create-only precondition (spec json/014) ─────────────────────────────

    // 39. Two parallel create-only-PUTs on the same free key → exactly one
    //     creates, the other sees DocumentAlreadyExists; the key's write
    //     shard serializes the race (pattern: test 33 for json/011).
    #[tokio::test]
    async fn test_create_only_parallel_puts_single_winner() {
        let (json, _dir) = make_engine().await;
        let tasks: Vec<_> = (0..2)
            .map(|i| {
                let engine = Arc::clone(&json);
                tokio::spawn(async move {
                    engine
                        .put_document_with_version(
                            "default",
                            "k",
                            json!({"winner": i}),
                            Some(Precondition::MustNotExist),
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
    }

    // ── Sharded document-write locks (spec json/018) ─────────────────────────

    // 40. A held write shard blocks only keys of that shard: a put on a key
    //     of another shard runs through, one on the same shard waits.
    #[tokio::test]
    async fn test_writes_serialize_per_shard_only() {
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

        let free = tokio::spawn({
            let json = Arc::clone(&json);
            async move { json.put_document("default", &other_shard_key, json!({"n": 1})).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), free)
            .await
            .expect("a key of another shard must not wait")
            .unwrap()
            .unwrap();

        let parked = tokio::spawn({
            let json = Arc::clone(&json);
            async move { json.put_document("default", &same_shard_key, json!({"n": 2})).await }
        });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(!parked.is_finished(), "a key of the held shard must wait");
        drop(guard);
        parked.await.unwrap().unwrap();
    }

    // 41. The same document reference always maps to the same shard, and the
    //     domain is part of the hash (no forced collision across domains).
    #[tokio::test]
    async fn test_shard_is_stable_and_domain_aware() {
        assert_eq!(JsonEngine::shard("a", "k"), JsonEngine::shard("a", "k"));
        assert!((0..DOC_WRITE_SHARDS).contains(&JsonEngine::shard("a", "k")));
        let differs = (0..64).any(|i| {
            let key = format!("k{i}");
            JsonEngine::shard("a", &key) != JsonEngine::shard("b", &key)
        });
        assert!(differs, "domain must feed the hash");
    }

    // ── Synchronous indexing (spec json/005) ─────────────────────────────────

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
    #[tokio::test]
    async fn test_put_creates_index_entry() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "u1", json!({"city": "Essen"})).await.unwrap();
        let prefix = default_prefix(&json).await;
        let idx = index::index_key(&prefix, "city", b"Essen", "u1");
        assert!(json.engine().get(&idx).await.unwrap().is_some());
    }

    // 24. Update replaces the stale index entry with the new one.
    #[tokio::test]
    async fn test_update_swaps_index_entry() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "u1", json!({"city": "Essen"})).await.unwrap();
        json.put_document("default", "u1", json!({"city": "Berlin"})).await.unwrap();
        let prefix = default_prefix(&json).await;
        let old_idx = index::index_key(&prefix, "city", b"Essen", "u1");
        let new_idx = index::index_key(&prefix, "city", b"Berlin", "u1");
        assert!(json.engine().get(&old_idx).await.unwrap().is_none(), "stale entry must be gone");
        assert!(json.engine().get(&new_idx).await.unwrap().is_some());
    }

    // 25. delete_document removes the index entry.
    #[tokio::test]
    async fn test_delete_removes_index_entry() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "u1", json!({"city": "Essen"})).await.unwrap();
        json.delete_document("default", "u1").await.unwrap();
        let prefix = default_prefix(&json).await;
        assert!(scan_field(&json, &prefix, "city").await.is_empty());
        assert!(json.get_document("default", "u1").await.unwrap().is_none());
    }

    // 26. Missing indexed field → no entry, no error.
    #[tokio::test]
    async fn test_missing_field_not_indexed() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "u1", json!({"name": "Ada"})).await.unwrap();
        let prefix = default_prefix(&json).await;
        assert!(scan_field(&json, &prefix, "city").await.is_empty());
    }

    // 27. null in the indexed field → no entry.
    #[tokio::test]
    async fn test_null_field_not_indexed() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "u1", json!({"city": null})).await.unwrap();
        let prefix = default_prefix(&json).await;
        assert!(scan_field(&json, &prefix, "city").await.is_empty());
    }

    // 28. Empty string is a valid indexed value.
    #[tokio::test]
    async fn test_empty_string_indexed() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "u1", json!({"city": ""})).await.unwrap();
        let prefix = default_prefix(&json).await;
        let idx = index::index_key(&prefix, "city", b"", "u1");
        assert!(json.engine().get(&idx).await.unwrap().is_some());
    }

    // 29. Multiple indexes per domain are all maintained.
    #[tokio::test]
    async fn test_multiple_indexes_maintained() {
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
    }

    // 35. delete_index tombstones the field's IDX entries; other fields keep theirs.
    #[tokio::test]
    async fn test_delete_index_tombstones_entries() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.create_index("default", "age", IndexFieldType::Number).await.unwrap();
        json.put_document("default", "u1", json!({"city": "Essen", "age": 30})).await.unwrap();
        json.delete_index("default", "city").await.unwrap();
        let prefix = default_prefix(&json).await;
        assert!(scan_field(&json, &prefix, "city").await.is_empty(), "IDX entries must be gone");
        assert_eq!(scan_field(&json, &prefix, "age").await.len(), 1, "other index untouched");
    }

    // 36. Keys valid per config but too long for the composite LSM key are
    //     rejected upfront with InvalidKey (400), not StorageError (500);
    //     keys at the effective limit still work.
    #[tokio::test]
    async fn test_overlong_key_invalid_key_not_storage_error() {
        let (json, _dir) = make_engine().await;
        let err = json
            .put_document("default", &"x".repeat(240), json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
        // 235 + 21 bytes overhead = LSM limit 256 → still valid.
        json.put_document("default", &"x".repeat(235), json!({})).await.unwrap();
    }

    // 36b. Documents stored under a key that a later config lowers below
    //      stay readable through the snapshot path: the backup export feeds
    //      back keys the engine itself produced, so re-validating them would
    //      abort every export of the domain. The live path keeps validating.
    #[tokio::test]
    async fn test_snapshot_read_ignores_lowered_key_limit() {
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
        let lowered = JsonStoreConfig { max_document_key_length: 32, ..config };
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let json = JsonEngine::bootstrap(&lowered, metrics).await.unwrap();
        let snap = json.engine().snapshot();
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
    }

    // 37. create_document with an effective key limit below the UUID length
    //     fails with a clear InvalidKey error instead of writing documents
    //     unreachable via get/put/delete.
    #[tokio::test]
    async fn test_create_document_rejects_too_small_key_limit() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            max_document_key_length: 20,
            ..JsonStoreConfig::default()
        };
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let json = JsonEngine::bootstrap(&config, metrics).await.unwrap();
        let err = json.create_document("default", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
        json.shutdown().await;
    }

    // ── Spec general/018: global lifecycle event bus ────────────────────────

    // Test 1 (json slice): create_domain/delete_domain publish domain_created/
    // domain_deleted with engine "json" and the right domain.
    #[tokio::test]
    async fn test_domain_lifecycle_events_published_with_json_engine_tag() {
        let (json, _dir) = make_engine().await;
        let bus = Arc::new(GlobalEventBus::new(16, 16));
        json.attach_event_bus(Arc::clone(&bus));
        let mut rx = bus.subscribe();

        json.create_domain("evdom").await.unwrap();
        json.delete_domain("evdom").await.unwrap();

        let created = rx.try_recv().unwrap();
        assert_eq!(created.engine, "json");
        assert_eq!(created.kind, "domain_created");
        assert_eq!(created.domain, "evdom");
        assert_eq!(created.object, None);

        let deleted = rx.try_recv().unwrap();
        assert_eq!(deleted.kind, "domain_deleted");
        assert_eq!(deleted.domain, "evdom");
    }

    // Test 5: create_index/delete_index publish index_created/index_dropped
    // with engine "json" and the field name as `object`.
    #[tokio::test]
    async fn test_index_events_published_with_field_as_object() {
        let (json, _dir) = make_engine().await;
        let bus = Arc::new(GlobalEventBus::new(16, 16));
        json.attach_event_bus(Arc::clone(&bus));
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
    }

    // Test 2 (json slice): after a purge run, domain_purged appears, after
    // domain_deleted.
    #[tokio::test]
    async fn test_domain_purge_event_published_after_domain_deleted() {
        let (json, _dir) = make_engine().await;
        let bus = Arc::new(GlobalEventBus::new(16, 16));
        json.attach_event_bus(Arc::clone(&bus));
        let mut rx = bus.subscribe();

        json.create_domain("purge-ev").await.unwrap();
        rx.try_recv().unwrap(); // domain_created, not under test here
        json.delete_domain("purge-ev").await.unwrap();

        let purger = JsonDomainPurger::new(Arc::clone(&json), Arc::new(std::sync::atomic::AtomicBool::new(false)), 100, 5);
        purger.purge_tick().await.unwrap(); // empty domain: finalizes immediately

        let deleted = rx.try_recv().unwrap();
        assert_eq!(deleted.kind, "domain_deleted");
        let purged = rx.try_recv().unwrap();
        assert_eq!(purged.kind, "domain_purged");
        assert_eq!(purged.domain, "purge-ev");
    }

    // Test 12 (json slice): no bus attached -> domain and index lifecycle ops
    // succeed unchanged, no panic, and nothing is published anywhere.
    #[tokio::test]
    async fn test_lifecycle_and_index_ops_without_event_bus_attached_publish_nothing() {
        let (json, _dir) = make_engine().await;
        let bus = GlobalEventBus::new(16, 16); // never attached
        let mut rx = bus.subscribe();

        json.create_domain("no-bus").await.unwrap();
        json.create_index("no-bus", "city", IndexFieldType::String).await.unwrap();
        json.delete_index("no-bus", "city").await.unwrap();
        json.delete_domain("no-bus").await.unwrap();

        assert!(rx.try_recv().is_err(), "no bus attached must mean no event, anywhere");
    }

    // ── Spec general/019: per-engine metrics — no double counting ───────────

    // Test 7: put_document (-> put_document_with_version -> write_document)
    // is exactly 1 write_op; a conditional put_document_with_version (which
    // reads the old version first) is still exactly 1 write_op and 0
    // read_ops -- the read-before-write does not count; delete_document is
    // exactly 1 write_op.
    #[tokio::test]
    async fn test_engine_metrics_no_double_counting() {
        let (json, _dir) = make_engine().await;

        // aggregate_engine only sums fully ticked buckets (spec general/019).
        let created = json.put_document("default", "k", json!({"n": 1})).await.unwrap();
        json.metrics.tick_all();
        let after_put = json.metrics.engine_metrics();
        assert_eq!(after_put[EngineKind::Json as usize].write_ops, 1);

        json.put_document_with_version(
            "default",
            "k",
            json!({"n": 2}),
            Some(Precondition::IfMatch(ExpectedVersion { generation: created.generation, version: 1 })),
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
    }
}
