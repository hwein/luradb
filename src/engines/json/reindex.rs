//! Re-indexing of existing documents (spec json/008).
//!
//! Runs as a background task: scans all documents of a domain and writes
//! missing index entries in throttled batches. Idempotent — existing entries
//! are left untouched. Each chunk runs under the engine's `doc_write_lock`
//! (concurrent updates cannot be clobbered with stale entries) and re-checks
//! the domain state (a domain deleted mid-run ends the task as `Failed`).

use super::document::{doc_scan_prefix, generate_uuid_v4, parse_doc_key};
use super::domain::JsonDomain;
use super::error::JsonStoreError;
use super::index::{encode_index_value, extract_field, index_key, IndexDefinition};
use super::JsonEngine;
use crate::engines::lsm::engine::BatchOp;
use crate::engines::StorageEngine;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ReindexStatus {
    Running { processed: u64, total_estimated: u64 },
    Completed { processed: u64, duration_secs: u64 },
    Failed { error: String, processed: u64 },
}

#[derive(Debug, Clone, Serialize)]
pub struct ReindexResult {
    pub task_id: String,
    pub status: ReindexStatus,
}

impl JsonEngine {
    /// Starts a background re-index over ALL active indexes of the domain.
    pub fn reindex_domain(self: &Arc<Self>, domain: &str) -> Result<ReindexResult, JsonStoreError> {
        let dom = self.domains.require_active(domain)?;
        let defs = self.indexes.get_indexes(&dom.name);
        self.spawn_reindex(dom, defs)
    }

    /// Starts a background re-index for one specific index definition.
    pub fn reindex_index(
        self: &Arc<Self>,
        domain: &str,
        field: &str,
    ) -> Result<ReindexResult, JsonStoreError> {
        let dom = self.domains.require_active(domain)?;
        let def = self
            .indexes
            .get_indexes(&dom.name)
            .into_iter()
            .find(|d| d.field == field)
            .ok_or_else(|| JsonStoreError::IndexNotFound {
                domain: dom.name.clone(),
                field: field.to_string(),
            })?;
        self.spawn_reindex(dom, vec![def])
    }

    /// Current status of a re-index task, if it belongs to `domain`.
    pub fn get_reindex_status(&self, domain: &str, task_id: &str) -> Option<ReindexStatus> {
        self.reindex_tasks
            .read()
            .get(task_id)
            .filter(|(d, _)| d == domain)
            .map(|(_, status)| status.clone())
    }

    fn spawn_reindex(
        self: &Arc<Self>,
        dom: JsonDomain,
        defs: Vec<IndexDefinition>,
    ) -> Result<ReindexResult, JsonStoreError> {
        let task_id = generate_uuid_v4();
        {
            let mut running = self.reindex_running.lock();
            if let Some(existing) = running.get(&dom.name) {
                return Err(JsonStoreError::ReindexInProgress {
                    domain: dom.name.clone(),
                    task_id: existing.clone(),
                });
            }
            running.insert(dom.name.clone(), task_id.clone());
        }
        let status = ReindexStatus::Running { processed: 0, total_estimated: 0 };
        self.reindex_tasks
            .write()
            .insert(task_id.clone(), (dom.name.clone(), status.clone()));

        let engine = Arc::clone(self);
        let tid = task_id.clone();
        let domain_name = dom.name.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let final_status = match engine.run_reindex(&tid, &dom, &defs).await {
                Ok(processed) => ReindexStatus::Completed {
                    processed,
                    duration_secs: started.elapsed().as_secs(),
                },
                Err((processed, e)) => {
                    tracing::warn!("[reindex] task {tid} failed after {processed} docs: {e}");
                    ReindexStatus::Failed { error: e.to_string(), processed }
                }
            };
            engine
                .reindex_tasks
                .write()
                .insert(tid, (domain_name.clone(), final_status));
            engine.reindex_running.lock().remove(&domain_name);
        });
        Ok(ReindexResult { task_id, status })
    }

    async fn run_reindex(
        &self,
        task_id: &str,
        dom: &JsonDomain,
        defs: &[IndexDefinition],
    ) -> Result<u64, (u64, JsonStoreError)> {
        let mut processed: u64 = 0;
        let keys = self
            .engine
            .scan_keys(&doc_scan_prefix(&dom.system_prefix))
            .await
            .map_err(|e| (0, JsonStoreError::from(e)))?;
        let total = keys.len() as u64;
        self.set_running_status(task_id, dom, 0, total);

        for chunk in keys.chunks(self.reindex_batch_size.max(1)) {
            self.reindex_chunk(dom, defs, chunk, &mut processed)
                .await
                .map_err(|e| (processed, e))?;
            self.set_running_status(task_id, dom, processed, total);
            if self.reindex_pause_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(self.reindex_pause_ms)).await;
            }
        }
        Ok(processed)
    }

    fn set_running_status(&self, task_id: &str, dom: &JsonDomain, processed: u64, total: u64) {
        self.reindex_tasks.write().insert(
            task_id.to_string(),
            (dom.name.clone(), ReindexStatus::Running { processed, total_estimated: total }),
        );
    }

    async fn reindex_chunk(
        &self,
        dom: &JsonDomain,
        defs: &[IndexDefinition],
        chunk: &[Vec<u8>],
        processed: &mut u64,
    ) -> Result<(), JsonStoreError> {
        // read → existence check → write of a chunk runs under the doc
        // write lock so concurrent updates/deletes cannot be overwritten
        // with stale index entries.
        let _guard = self.doc_write_lock.lock().await;
        // Domain deleted mid-run? Stop instead of racing the purger
        // (checked under the lock, which the purger holds to finalize).
        self.domains.require_active(&dom.name)?;
        let mut ops = Vec::new();
        for lsm_key in chunk {
            let Some((_, document_key)) = parse_doc_key(lsm_key) else {
                *processed += 1;
                continue;
            };
            match self.read_stored(dom, &document_key).await {
                Ok(Some(stored)) => {
                    self.index_ops_for_doc(dom, defs, &document_key, &stored.content, &mut ops)
                        .await?;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("[reindex] skipping corrupt document '{document_key}': {e}");
                }
            }
            *processed += 1;
        }
        if !ops.is_empty() {
            self.engine.write_batch(ops).await?;
        }
        Ok(())
    }

    async fn index_ops_for_doc(
        &self,
        dom: &JsonDomain,
        defs: &[IndexDefinition],
        document_key: &str,
        content: &Value,
        ops: &mut Vec<BatchOp>,
    ) -> Result<(), JsonStoreError> {
        for def in defs {
            let Some(value) = extract_field(content, &def.field) else {
                continue;
            };
            let Some(encoded) = encode_index_value(&value, def.field_type) else {
                continue;
            };
            let idx_key = index_key(&dom.system_prefix, &def.field, &encoded, document_key);
            if idx_key.len() > self.max_lsm_key_length {
                continue;
            }
            match self.engine.get(&idx_key).await {
                Ok(None) => ops.push(BatchOp::Put { key: idx_key, value: Vec::new() }),
                Ok(Some(_)) => {}
                Err(e) => return Err(JsonStoreError::from(e)),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FilterCondition, IndexFieldType, JsonEngine, SearchQuery};
    use super::*;
    use crate::config::JsonStoreConfig;
    use serde_json::json;
    use std::collections::HashMap;

    async fn make_engine_cfg(
        batch: usize,
        pause_ms: u64,
    ) -> (Arc<JsonEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            reindex_batch_size: batch,
            reindex_pause_ms: pause_ms,
            ..JsonStoreConfig::default()
        };
        let engine = JsonEngine::bootstrap(&config).await.unwrap();
        (engine, dir)
    }

    async fn wait_done(json: &Arc<JsonEngine>, domain: &str, task_id: &str) -> ReindexStatus {
        for _ in 0..500 {
            match json.get_reindex_status(domain, task_id) {
                Some(s @ ReindexStatus::Completed { .. }) | Some(s @ ReindexStatus::Failed { .. }) => {
                    return s;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        }
        panic!("reindex task {task_id} did not finish");
    }

    fn city_query(value: &str) -> SearchQuery {
        SearchQuery {
            filters: HashMap::from([(
                "city".to_string(),
                FilterCondition::Eq(json!(value)),
            )]),
            ..Default::default()
        }
    }

    // 1. Docs written BEFORE index creation become searchable after re-index.
    #[tokio::test]
    async fn test_reindex_makes_existing_docs_searchable() {
        let (json, _dir) = make_engine_cfg(500, 0).await;
        for i in 0..10 {
            json.put_document("default", &format!("d{i}"), json!({"city": "Essen"})).await.unwrap();
        }
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        assert_eq!(
            json.search_documents("default", city_query("Essen")).await.unwrap().total,
            0,
            "before re-index nothing is indexed"
        );
        let result = json.reindex_domain("default").unwrap();
        let status = wait_done(&json, "default", &result.task_id).await;
        assert!(matches!(status, ReindexStatus::Completed { processed: 10, .. }), "got: {status:?}");
        assert_eq!(json.search_documents("default", city_query("Essen")).await.unwrap().total, 10);
    }

    // 2. Re-index is idempotent.
    #[tokio::test]
    async fn test_reindex_idempotent() {
        let (json, _dir) = make_engine_cfg(500, 0).await;
        json.put_document("default", "a", json!({"city": "Essen"})).await.unwrap();
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let r1 = json.reindex_domain("default").unwrap();
        wait_done(&json, "default", &r1.task_id).await;
        let r2 = json.reindex_domain("default").unwrap();
        wait_done(&json, "default", &r2.task_id).await;
        assert_eq!(json.search_documents("default", city_query("Essen")).await.unwrap().total, 1);
    }

    // 3. Documents without the indexed field are skipped without error.
    #[tokio::test]
    async fn test_reindex_partial_documents() {
        let (json, _dir) = make_engine_cfg(500, 0).await;
        json.put_document("default", "a", json!({"city": "Essen"})).await.unwrap();
        json.put_document("default", "b", json!({"name": "no-city"})).await.unwrap();
        json.put_document("default", "c", json!({"city": "Essen"})).await.unwrap();
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let result = json.reindex_index("default", "city").unwrap();
        let status = wait_done(&json, "default", &result.task_id).await;
        assert!(matches!(status, ReindexStatus::Completed { processed: 3, .. }), "got: {status:?}");
        assert_eq!(json.search_documents("default", city_query("Essen")).await.unwrap().total, 2);
    }

    // 4. Status transitions from Running to Completed.
    #[tokio::test]
    async fn test_status_tracking() {
        let (json, _dir) = make_engine_cfg(1, 20).await;
        for i in 0..5 {
            json.put_document("default", &format!("d{i}"), json!({"city": "X"})).await.unwrap();
        }
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let result = json.reindex_domain("default").unwrap();
        assert!(matches!(result.status, ReindexStatus::Running { .. }));
        let status = wait_done(&json, "default", &result.task_id).await;
        assert!(matches!(status, ReindexStatus::Completed { processed: 5, .. }), "got: {status:?}");
    }

    // 5. A second re-index on the same domain is rejected while one runs.
    #[tokio::test]
    async fn test_double_reindex_rejected() {
        let (json, _dir) = make_engine_cfg(1, 50).await;
        for i in 0..5 {
            json.put_document("default", &format!("d{i}"), json!({"city": "X"})).await.unwrap();
        }
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let first = json.reindex_domain("default").unwrap();
        let err = json.reindex_domain("default").unwrap_err();
        assert!(matches!(err, JsonStoreError::ReindexInProgress { .. }), "got: {err}");
        wait_done(&json, "default", &first.task_id).await;
        // After completion a new run is allowed again.
        let second = json.reindex_domain("default").unwrap();
        wait_done(&json, "default", &second.task_id).await;
    }

    // 6. Re-index on an unknown domain fails immediately.
    #[tokio::test]
    async fn test_reindex_unknown_domain() {
        let (json, _dir) = make_engine_cfg(500, 0).await;
        let err = json.reindex_domain("nope").unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainNotFound(_)), "got: {err}");
    }

    // 7. Regression: delete_index tombstones the field's IDX entries — after
    //    recreate + re-index a search must not serve pre-delete values.
    #[tokio::test]
    async fn test_recreated_index_serves_no_stale_values() {
        let (json, _dir) = make_engine_cfg(500, 0).await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "a", json!({"city": "Essen"})).await.unwrap();
        json.delete_index("default", "city").await.unwrap();
        // Update while no index exists: nothing maintains the old entry.
        json.put_document("default", "a", json!({"city": "Berlin"})).await.unwrap();
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let result = json.reindex_domain("default").unwrap();
        wait_done(&json, "default", &result.task_id).await;
        assert_eq!(json.search_documents("default", city_query("Essen")).await.unwrap().total, 0);
        assert_eq!(json.search_documents("default", city_query("Berlin")).await.unwrap().total, 1);
    }

    // 8. Regression: a domain deleted mid-run ends the re-index as Failed at
    //    the next chunk instead of writing into the deleted domain.
    #[tokio::test]
    async fn test_reindex_fails_when_domain_deleted_mid_run() {
        let (json, _dir) = make_engine_cfg(1, 0).await;
        json.create_domain("doomed").await.unwrap();
        json.put_document("doomed", "a", json!({"city": "X"})).await.unwrap();
        json.put_document("doomed", "b", json!({"city": "Y"})).await.unwrap();
        json.create_index("doomed", "city", IndexFieldType::String).await.unwrap();
        // Block the first chunk on the doc write lock; delete the domain meanwhile.
        let guard = json.doc_write_lock.lock().await;
        let result = json.reindex_domain("doomed").unwrap();
        json.delete_domain("doomed").await.unwrap();
        drop(guard);
        let status = wait_done(&json, "doomed", &result.task_id).await;
        assert!(matches!(status, ReindexStatus::Failed { .. }), "got: {status:?}");
    }
}
