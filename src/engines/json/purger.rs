//! Background cleanup for deleted JSON domains (spec json/013).
//!
//! Purge order per tick: `DOC:` entries first, then `IDX:` entries, then the
//! index definitions and the domain metadata — so a crash mid-purge simply
//! resumes on the next start (the domain stays in `Deleting` state).

use super::document::doc_scan_prefix;
use super::index::index_domain_prefix;
use super::JsonEngine;
use crate::engines::lsm::engine::BatchOp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct JsonDomainPurger {
    engine: Arc<JsonEngine>,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
    interval: Duration,
}

impl JsonDomainPurger {
    pub fn new(
        engine: Arc<JsonEngine>,
        shutdown: Arc<AtomicBool>,
        batch_size: usize,
        interval_secs: u64,
    ) -> Self {
        Self {
            engine,
            shutdown,
            batch_size: batch_size.max(1),
            interval: Duration::from_secs(interval_secs),
        }
    }

    /// Runs the purge loop until the shutdown flag is set.
    pub async fn run(self: Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            if let Err(e) = self.purge_tick().await {
                tracing::warn!("[JsonDomainPurger] error: {e}");
            }
            sleep(self.interval).await;
        }
    }

    /// One purge cycle: tombstones up to `batch_size` keys per deleting
    /// domain; finalizes the domain once no data keys remain. Scans through
    /// tombstone/finalize run under the engine's doc write lock so no
    /// in-flight writer can land keys after the final empty scan (json/013).
    pub async fn purge_tick(&self) -> anyhow::Result<()> {
        for domain in self.engine.domains.list_deleting_domains() {
            let _guard = self.engine.doc_write_lock.lock().await;
            let doc_keys = self
                .engine
                .engine()
                .scan_keys_limited(&doc_scan_prefix(&domain.system_prefix), self.batch_size)
                .await?;
            let idx_keys = self
                .engine
                .engine()
                .scan_keys_limited(&index_domain_prefix(&domain.system_prefix), self.batch_size)
                .await?;
            if doc_keys.is_empty() && idx_keys.is_empty() {
                self.engine.indexes.purge_domain_definitions(&domain.name).await?;
                self.engine.domains.finalize_deletion(&domain.name).await?;
                tracing::info!("[JsonDomainPurger] domain '{}' fully purged", domain.name);
                continue;
            }
            let ops: Vec<BatchOp> = doc_keys
                .into_iter()
                .chain(idx_keys)
                .take(self.batch_size)
                .map(|key| BatchOp::Delete { key })
                .collect();
            self.engine.engine().write_batch(ops).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{IndexFieldType, JsonEngine, JsonStoreError};
    use super::*;
    use crate::config::JsonStoreConfig;
    use serde_json::json;

    fn config_for(dir: &tempfile::TempDir) -> JsonStoreConfig {
        JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sst").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        }
    }

    async fn seeded_engine(dir: &tempfile::TempDir) -> Arc<JsonEngine> {
        let json = JsonEngine::bootstrap(&config_for(dir)).await.unwrap();
        json.create_domain("doomed").await.unwrap();
        json.create_index("doomed", "city", IndexFieldType::String).await.unwrap();
        for i in 0..5 {
            json.put_document("doomed", &format!("d{i}"), json!({"city": "Essen"})).await.unwrap();
        }
        json
    }

    fn purger(json: &Arc<JsonEngine>, batch: usize) -> JsonDomainPurger {
        JsonDomainPurger::new(
            Arc::clone(json),
            Arc::new(AtomicBool::new(false)),
            batch,
            5,
        )
    }

    // 1./2. Deleting state blocks CRUD with DomainDeleting (→ 410).
    #[tokio::test]
    async fn test_deleting_domain_blocks_crud() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = seeded_engine(&dir).await;
        json.delete_domain("doomed").await.unwrap();

        let err = json.put_document("doomed", "x", json!({})).await.unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainDeleting(_)), "got: {err}");
        let err = json.get_document("doomed", "d0").await.unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainDeleting(_)), "got: {err}");
        let err = json
            .create_index("doomed", "x", IndexFieldType::String)
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::DomainDeleting(_)), "got: {err}");
    }

    // 3./4. Purge removes DOC and IDX entries, then the metadata.
    #[tokio::test]
    async fn test_purge_removes_all_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = seeded_engine(&dir).await;
        let prefix = json.get_domain("doomed").unwrap().system_prefix;
        json.delete_domain("doomed").await.unwrap();

        let purger = purger(&json, 100);
        // Tick 1 tombstones data, tick 2 finalizes metadata.
        purger.purge_tick().await.unwrap();
        purger.purge_tick().await.unwrap();

        assert!(json.engine().scan_keys(&doc_scan_prefix(&prefix)).await.unwrap().is_empty());
        assert!(json.engine().scan_keys(&index_domain_prefix(&prefix)).await.unwrap().is_empty());
        assert!(json.engine().scan_keys(b"__sys:index:doomed:").await.unwrap().is_empty());
        assert!(
            json.domains.get_domain_any("doomed").is_none(),
            "metadata must be gone after finalize"
        );
    }

    // Small batches need several ticks but converge.
    #[tokio::test]
    async fn test_purge_in_small_batches() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = seeded_engine(&dir).await;
        json.delete_domain("doomed").await.unwrap();
        let purger = purger(&json, 2);
        for _ in 0..12 {
            purger.purge_tick().await.unwrap();
            if json.domains.get_domain_any("doomed").is_none() {
                return;
            }
        }
        panic!("purge did not converge with small batches");
    }

    // Regression: purge must converge even when tombstones are flushed to
    // SSTables between ticks (scan_keys used to resurrect purged keys).
    #[tokio::test]
    async fn test_purge_converges_across_flushes() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = seeded_engine(&dir).await; // 5 DOC + 5 IDX keys > batch_size
        json.delete_domain("doomed").await.unwrap();
        let purger = purger(&json, 2);
        for _ in 0..12 {
            purger.purge_tick().await.unwrap();
            json.engine().freeze_active_memtable();
            json.engine().flush_memtable().await.unwrap();
            if json.domains.get_domain_any("doomed").is_none() {
                return;
            }
        }
        panic!("purge did not converge across flushes");
    }

    // 5. A deleting domain survives a restart and the purge resumes.
    #[tokio::test]
    async fn test_purge_resumes_after_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        {
            let json = seeded_engine(&dir).await;
            json.delete_domain("doomed").await.unwrap();
            json.shutdown().await;
        }
        let json = JsonEngine::bootstrap(&config_for(&dir)).await.unwrap();
        let deleting = json.domains.list_deleting_domains();
        assert_eq!(deleting.len(), 1, "deleting domain must survive restart");

        let purger = purger(&json, 100);
        purger.purge_tick().await.unwrap();
        purger.purge_tick().await.unwrap();
        assert!(json.domains.get_domain_any("doomed").is_none());
        json.shutdown().await;
    }

    // 6. list_domains includes deleting domains with their state.
    #[tokio::test]
    async fn test_list_includes_deleting_with_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = seeded_engine(&dir).await;
        json.delete_domain("doomed").await.unwrap();
        let domains = json.list_domains();
        let doomed = domains.iter().find(|d| d.name == "doomed").unwrap();
        assert_eq!(doomed.state, super::super::JsonDomainState::Deleting);
    }

    // Regression: a default domain still Deleting at restart must not break
    // bootstrap (recover() used to fail with DomainAlreadyExists → boot loop).
    #[tokio::test]
    async fn test_bootstrap_survives_deleting_default_domain() {
        let dir = tempfile::TempDir::new().unwrap();
        {
            let json = JsonEngine::bootstrap(&config_for(&dir)).await.unwrap();
            json.put_document("default", "d0", json!({"city": "Essen"})).await.unwrap();
            json.delete_domain("default").await.unwrap();
            json.shutdown().await;
        }
        // Restart before the purge finished: boot must succeed, default stays Deleting.
        let json = JsonEngine::bootstrap(&config_for(&dir)).await.unwrap();
        assert!(json.get_domain("default").is_none(), "deleting default must not be active");

        let purger = purger(&json, 100);
        purger.purge_tick().await.unwrap();
        purger.purge_tick().await.unwrap();
        assert!(json.domains.get_domain_any("default").is_none());
        json.shutdown().await;
    }

    // After the purger finalized a deleted default domain, the next bootstrap
    // recreates it as Active.
    #[tokio::test]
    async fn test_default_domain_recreated_after_purge() {
        let dir = tempfile::TempDir::new().unwrap();
        {
            let json = JsonEngine::bootstrap(&config_for(&dir)).await.unwrap();
            json.put_document("default", "d0", json!({"city": "Essen"})).await.unwrap();
            json.delete_domain("default").await.unwrap();
            let purger = purger(&json, 100);
            purger.purge_tick().await.unwrap();
            purger.purge_tick().await.unwrap();
            assert!(json.domains.get_domain_any("default").is_none());
            json.shutdown().await;
        }
        let json = JsonEngine::bootstrap(&config_for(&dir)).await.unwrap();
        let default = json.domains.get_domain_any("default").expect("default must be recreated");
        assert_eq!(default.state, super::super::JsonDomainState::Active);
        json.shutdown().await;
    }

    // Regression (json/013): a writer that passed require_active before the
    // domain was deleted must not land its write after the purger finalized —
    // orphan DOC keys would resurrect in a recreated same-name domain.
    #[tokio::test]
    async fn test_inflight_write_cannot_land_after_finalize() {
        let dir = tempfile::TempDir::new().unwrap();
        let json = JsonEngine::bootstrap(&config_for(&dir)).await.unwrap();
        json.create_domain("doomed").await.unwrap();
        let prefix = json.get_domain("doomed").unwrap().system_prefix;

        // In-flight writer: parked on the doc write lock held by the test.
        let guard = json.doc_write_lock.lock().await;
        let writer = tokio::spawn({
            let json = Arc::clone(&json);
            async move { json.put_document("doomed", "zombie", json!({"n": 1})).await }
        });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        json.delete_domain("doomed").await.unwrap();
        // The purger must block on the same lock instead of finalizing.
        let tick = tokio::spawn({
            let p = purger(&json, 100);
            async move { p.purge_tick().await }
        });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(
            json.domains.get_domain_any("doomed").is_some(),
            "purger must not finalize while a writer is in flight"
        );
        drop(guard);

        let err = writer.await.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                JsonStoreError::DomainDeleting(_) | JsonStoreError::DomainNotFound(_)
            ),
            "got: {err}"
        );
        tick.await.unwrap().unwrap();
        assert!(json.domains.get_domain_any("doomed").is_none());
        assert!(
            json.engine().scan_keys(&doc_scan_prefix(&prefix)).await.unwrap().is_empty(),
            "no orphan DOC keys may survive the purge"
        );
    }

    // Regression (json/013): bulk_load re-checks the domain state per batch
    // flush, so no import batch lands after the domain started deleting.
    #[tokio::test]
    async fn test_bulk_flush_aborts_when_domain_deleted_mid_import() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig { bulk_batch_size: 1, ..config_for(&dir) };
        let json = JsonEngine::bootstrap(&config).await.unwrap();
        json.create_domain("doomed").await.unwrap();
        let prefix = json.get_domain("doomed").unwrap().system_prefix;

        // Park the import's first batch flush on the doc write lock.
        let guard = json.doc_write_lock.lock().await;
        let loader = tokio::spawn({
            let json = Arc::clone(&json);
            async move {
                let docs = vec![
                    (Some("a".to_string()), json!({"n": 1})),
                    (Some("b".to_string()), json!({"n": 2})),
                ];
                json.bulk_load("doomed", docs).await
            }
        });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        json.delete_domain("doomed").await.unwrap();
        drop(guard);
        assert!(
            loader.await.unwrap().is_err(),
            "batch flush must fail once the domain is deleting"
        );

        let p = purger(&json, 100);
        p.purge_tick().await.unwrap();
        assert!(json.domains.get_domain_any("doomed").is_none());
        assert!(
            json.engine().scan_keys(&doc_scan_prefix(&prefix)).await.unwrap().is_empty(),
            "no orphan DOC keys may survive the purge"
        );
    }
}
