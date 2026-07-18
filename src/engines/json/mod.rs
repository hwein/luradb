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
pub use document::{etag_value, Document, ExpectedVersion};
pub use domain::{JsonDomain, JsonDomainState};
pub use error::JsonStoreError;
pub use index::{IndexDefinition, IndexFieldType};
pub use purger::JsonDomainPurger;
pub use query::{DocumentListResult, FilterCondition, ListOptions, SearchQuery, SearchResult};
pub use reindex::{ReindexResult, ReindexStatus};

use crate::config::JsonStoreConfig;
use crate::core::wal::WriteAheadLog;
use crate::engines::lsm::compaction::CompactionConfig;
use crate::engines::lsm::engine::{BatchOp, LsmEngineConfig, LsmEngineOptions, LsmStorageEngine};
use crate::engines::lsm::janitor::JanitorConfig;
use crate::engines::StorageEngine;
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use anyhow::Result;
use document::{
    doc_key, generate_uuid_v4, new_generation, validate_document_key, StoredDocument,
    DOC_KEY_OVERHEAD,
};
use domain::JsonDomainRegistry;
use index::IndexRegistry;
use parking_lot::{Mutex as SyncMutex, RwLock};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

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
    /// finalize: domain state is checked under this lock (json/013).
    doc_write_lock: tokio::sync::Mutex<()>,
}

impl JsonEngine {
    /// Creates the dedicated JSON LSM instance from `config` and starts its
    /// background tasks (flush, compaction, janitor).
    pub async fn bootstrap(config: &JsonStoreConfig) -> Result<Arc<Self>> {
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
            doc_write_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// The dedicated JSON LSM instance.
    pub fn engine(&self) -> &Arc<LsmStorageEngine> {
        &self.engine
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
        self.indexes
            .create_index(&self.domains, domain, field, field_type)
            .await
    }

    /// All index definitions of a domain.
    pub fn get_indexes(&self, domain: &str) -> Result<Vec<IndexDefinition>, JsonStoreError> {
        self.domains.require_active(domain)?;
        Ok(self.indexes.get_indexes(domain))
    }

    /// Removes an index definition and tombstones the field's `IDX:` entries.
    pub async fn delete_index(&self, domain: &str, field: &str) -> Result<(), JsonStoreError> {
        self.indexes.delete_index(&self.domains, domain, field).await
    }

    // ── Core CRUD (spec json/002, domain-aware since json/003) ────────────────

    /// Stores `content` under a system-generated UUIDv4 key.
    pub async fn create_document(
        &self,
        domain: &str,
        content: Value,
    ) -> Result<Document, JsonStoreError> {
        let _guard = self.doc_write_lock.lock().await;
        let dom = self.domains.require_active(domain)?;
        let key = generate_uuid_v4();
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

    /// Upsert with optional optimistic concurrency check (spec json/011):
    /// with `expected_version`, the write fails with `DocumentNotFound` if the
    /// document is missing or `VersionConflict` if generation or version
    /// differ (a stale ETag of a deleted incarnation never matches).
    pub async fn put_document_with_version(
        &self,
        domain: &str,
        key: &str,
        content: Value,
        expected_version: Option<ExpectedVersion>,
    ) -> Result<Document, JsonStoreError> {
        validate_document_key(key, self.max_document_key_length)?;
        let _guard = self.doc_write_lock.lock().await;
        let dom = self.domains.require_active(domain)?;
        let old = self.read_stored(&dom, key).await?;
        if let Some(expected) = expected_version {
            match &old {
                None => {
                    return Err(JsonStoreError::DocumentNotFound {
                        domain: dom.name.clone(),
                        key: key.to_string(),
                    })
                }
                Some(o)
                    if o.generation != expected.generation || o.version != expected.version =>
                {
                    return Err(JsonStoreError::VersionConflict {
                        expected: etag_value(expected.generation, expected.version),
                        actual: etag_value(o.generation, o.version),
                    })
                }
                Some(_) => {}
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
        validate_document_key(key, self.max_document_key_length)?;
        let dom = self.domains.require_active(domain)?;
        Ok(self.read_stored(&dom, key).await?.map(|stored| Document {
            key: key.to_string(),
            domain: dom.name.clone(),
            content: stored.content,
            version: stored.version,
            generation: stored.generation,
        }))
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
        validate_document_key(key, self.max_document_key_length)?;
        let _guard = self.doc_write_lock.lock().await;
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
        let engine = JsonEngine::bootstrap(&config).await.unwrap();
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
        let json = JsonEngine::bootstrap(&config).await.unwrap();
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
            let json = JsonEngine::bootstrap(&config).await.unwrap();
            json.create_domain("persistent").await.unwrap();
            json.create_index("persistent", "city", IndexFieldType::String).await.unwrap();
            json.shutdown().await;
        }
        let json = JsonEngine::bootstrap(&config).await.unwrap();
        assert!(json.get_domain("persistent").is_some(), "domain must survive restart");
        let defs = json.get_indexes("persistent").unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].field, "city");
        json.shutdown().await;
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
                Some(ExpectedVersion { generation: created.generation, version: 1 }),
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
                Some(ExpectedVersion { generation: created.generation, version: 1 }),
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
                Some(ExpectedVersion { generation: 0, version: 1 }),
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
                            Some(expected),
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
            .put_document_with_version("default", "k", json!({"n": 3}), Some(stale))
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
        let json = JsonEngine::bootstrap(&config).await.unwrap();
        let err = json.create_document("default", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidKey(_)), "got: {err}");
        json.shutdown().await;
    }
}
