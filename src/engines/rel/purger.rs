//! Background cleanup for the relational engine (spec rel/013).
//!
//! Two jobs per tick: (a) fully purge `Deleting` domains — tombstone their
//! `ROW:`/`IDX:`/`SEQ:` data, then drop the `CAT:` definitions + catalog id
//! counter, then the domain metadata (that order makes a mid-purge crash
//! resumable — the domain stays `Deleting`); (b) reap orphaned
//! `ROW:`/`IDX:`/`SEQ:` ranges left in **active** domains by `DROP TABLE`/`DROP
//! INDEX` (ids allocated but no longer in the catalog). Both are batch-bounded
//! and crash-trivial; job (a)'s emptiness check + finalization run under the
//! engine write guard so no in-flight writer can land keys after finalization
//! (rel/013 §3, pattern: json/013).

use super::domain::{RelDomain, RelDomainState};
use super::keys;
use super::RelEngine;
use crate::engines::lsm::engine::BatchOp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct RelDomainPurger {
    engine: Arc<RelEngine>,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
    interval: Duration,
}

impl RelDomainPurger {
    pub fn new(
        engine: Arc<RelEngine>,
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

    /// Runs the purge loop until the shutdown flag is set (shared with the
    /// KV/JSON purgers via `main.rs`); stops after the current tick.
    pub async fn run(self: Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            if let Err(e) = self.purge_tick().await {
                tracing::warn!("[RelDomainPurger] error: {e}");
            }
            sleep(self.interval).await;
        }
    }

    /// One cycle: first fully purge `Deleting` domains (job a), then reap
    /// orphaned ranges of active domains (job b). Per-domain errors are logged;
    /// the tick continues.
    pub async fn purge_tick(&self) -> anyhow::Result<()> {
        self.purge_deleting_domains().await?;
        self.sweep_active_domains().await?;
        Ok(())
    }

    // ── Job (a): fully purge Deleting domains (§3) ──────────────────────────

    async fn purge_deleting_domains(&self) -> anyhow::Result<()> {
        for domain in self.engine.domains.list_deleting_domains() {
            if let Err(e) = self.purge_one_deleting(&domain).await {
                tracing::warn!("[RelDomainPurger] '{}': {e}", domain.name);
            }
        }
        Ok(())
    }

    /// Tombstones up to `batch_size` data keys of one deleting domain; once
    /// `ROW:`/`IDX:`/`SEQ:` are all empty, drops the catalog definitions and
    /// then the domain metadata. The whole per-domain body runs under the
    /// engine write guard, so the emptiness check that gates finalization sees
    /// every committed writer's keys (spec rel/013 §3, pattern: json/013).
    async fn purge_one_deleting(&self, domain: &RelDomain) -> anyhow::Result<()> {
        let _wg = self.engine.write_guard.lock().await;
        let engine = self.engine.engine();
        let prefix = &domain.system_prefix;
        let row_p = keys::row_domain_prefix(prefix);
        let idx_p = keys::index_domain_prefix(prefix);
        let seq_p = keys::seq_domain_prefix(prefix);

        let row_keys = engine.scan_keys_limited(&row_p, self.batch_size).await?;
        let idx_keys = engine.scan_keys_limited(&idx_p, self.batch_size).await?;
        let seq_keys = engine.scan_keys_limited(&seq_p, self.batch_size).await?;

        if row_keys.is_empty() && idx_keys.is_empty() && seq_keys.is_empty() {
            self.engine.catalog.purge_domain_definitions(domain).await?;
            self.engine.domains.finalize_deletion(&domain.name).await?;
            self.engine.drop_domain_rate_limiter(&domain.name);
            tracing::info!("[RelDomainPurger] domain '{}' fully purged", domain.name);
            return Ok(());
        }

        let ops: Vec<BatchOp> = row_keys
            .into_iter()
            .chain(idx_keys)
            .chain(seq_keys)
            .take(self.batch_size)
            .map(|key| BatchOp::Delete { key })
            .collect();
        let purged = ops.len() as u64;
        engine.write_batch(ops).await?;
        self.engine.metrics.record_rel_purged_keys(purged);
        Ok(())
    }

    // ── Job (b): reap orphaned ranges of active domains (§4) ────────────────

    async fn sweep_active_domains(&self) -> anyhow::Result<()> {
        for domain in self.engine.domains.list_domains() {
            // `list_domains` now surfaces `Deleting` domains too — those are
            // job (a)'s; only sweep active ones here.
            if domain.state != RelDomainState::Active {
                continue;
            }
            if let Err(e) = self.sweep_one_active(&domain).await {
                tracing::warn!("[RelDomainPurger] orphan sweep '{}': {e}", domain.name);
            }
        }
        Ok(())
    }

    /// Reaps orphaned `ROW:`/`SEQ:`/`IDX:` ranges of one active domain: the
    /// prefix ranges of `table_id`/`index_id`s that were allocated (`≤` the
    /// high-water mark) but are no longer catalog-live (dropped tables/indexes;
    /// ids are never reused, rel/003). Candidates are re-derived fresh each
    /// tick from `high-water mark \ live` and confirmed by a prefix probe, so
    /// the sweep is crash-trivial and idempotent. Bounded by the per-tick
    /// delete budget; drained candidates yield cheap empty probes that consume
    /// none of it, so progress is guaranteed and steady-state ticks are near
    /// no-ops (§4). No write guard: dropped ids never re-enter `live`, so a
    /// late writer on a dropped id is harmless and reaped on a later tick.
    async fn sweep_one_active(&self, domain: &RelDomain) -> anyhow::Result<()> {
        let prefix = &domain.system_prefix;
        let live = self.engine.catalog.live_object_ids(domain);
        let hwm = self.engine.catalog.allocated_id_high_watermark(domain);

        let mut deleted = 0u64;
        let mut ranges = 0u64;
        for id in 1..=hwm {
            if deleted >= self.batch_size as u64 {
                break; // rest follows in later ticks
            }
            if live.contains(id) {
                continue;
            }
            // A reserved index id (in-flight CREATE INDEX, rel/013 F1) is not an
            // orphan yet — its backfilled IDX bytes must survive this sweep.
            if self.engine.catalog.is_id_reserved(prefix, id) {
                continue;
            }
            let (d, r) = self.reap_dropped_id(prefix, id, self.batch_size as u64 - deleted).await?;
            deleted += d;
            ranges += r;
        }

        if deleted > 0 {
            self.engine.metrics.record_rel_purged_keys(deleted);
        }
        if ranges > 0 {
            self.engine.metrics.record_rel_orphan_ranges_purged(ranges);
        }
        Ok(())
    }

    async fn reap_dropped_id(&self, prefix: &[u8], id: u32, budget: u64) -> anyhow::Result<(u64, u64)> {
        let engine = self.engine.engine();
        let mut deleted = 0u64;
        let mut ranges = 0u64;
        // A dropped id is either a table (ROW:/SEQ:) or an index (IDX:);
        // the shared id space makes it unambiguous — probe all three.
        for probe in [
            keys::row_table_prefix(prefix, id),
            keys::seq_key(prefix, id),
            keys::index_value_prefix(prefix, id, &[]),
        ] {
            let remaining = budget - deleted;
            if remaining == 0 {
                break;
            }
            let found = engine.scan_keys_limited(&probe, remaining as usize).await?;
            if found.is_empty() {
                continue;
            }
            let n = found.len() as u64;
            let ops: Vec<BatchOp> = found.into_iter().map(|key| BatchOp::Delete { key }).collect();
            engine.write_batch(ops).await?;
            deleted += n;
            if n < remaining {
                ranges += 1; // range fully drained this tick
            }
        }
        Ok((deleted, ranges))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::rel::{CatalogEntry, CrossEngineResolver, RelStoreError, TableSchema};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use std::path::Path;

    fn config_in(dir: &Path) -> RelStoreConfig {
        RelStoreConfig {
            wal_path: dir.join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.join("ss").to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        }
    }

    async fn boot(config: &RelStoreConfig) -> Arc<RelEngine> {
        let metrics = MetricsStore::new(MetricsConfig::default());
        let cross_engine = CrossEngineResolver::disabled(Arc::clone(&metrics));
        RelEngine::bootstrap(config, metrics, cross_engine).await.unwrap()
    }

    async fn make() -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(&config_in(dir.path())).await;
        (rel, dir)
    }

    fn purger(rel: &Arc<RelEngine>, batch: usize) -> RelDomainPurger {
        RelDomainPurger::new(Arc::clone(rel), Arc::new(AtomicBool::new(false)), batch, 5)
    }

    async fn ok(rel: &RelEngine, domain: &str, sql: &str) {
        rel.execute(domain, sql, &[]).await.unwrap();
    }

    fn table_schema(rel: &RelEngine, domain: &str, name: &str) -> TableSchema {
        match rel.get_object(domain, name).unwrap() {
            CatalogEntry::Table(t) => t,
            _ => panic!("'{name}' is not a table"),
        }
    }

    /// Domain "doomed" with an autoincrement table, a secondary index and 5
    /// rows — so all three data families (ROW:/IDX:/SEQ:) are populated.
    async fn seed_doomed(rel: &RelEngine) {
        rel.create_domain("doomed").await.unwrap();
        ok(rel, "doomed", "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, city TEXT)").await;
        ok(rel, "doomed", "CREATE INDEX t_city ON t (city)").await;
        for _ in 0..5 {
            ok(rel, "doomed", "INSERT INTO t (city) VALUES ('Essen')").await;
        }
    }

    // 1. delete_domain hides the domain from CRUD but keeps it internally
    //    (410 via require_active) — the purge precondition.
    #[tokio::test]
    async fn test_delete_marks_deleting() {
        let (rel, _dir) = make().await;
        rel.create_domain("doomed").await.unwrap();
        rel.delete_domain("doomed").await.unwrap();
        assert!(rel.get_domain("doomed").is_none());
        assert!(rel.get_domain_any("doomed").is_some());
        let err = rel.execute("doomed", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::DomainDeleting(_)), "got: {err}");
        rel.shutdown().await;
    }

    // 2. Purge removes ROW/IDX/SEQ, then CAT + catalog seq + domain metadata.
    #[tokio::test]
    async fn test_purge_deleting_removes_everything() {
        let (rel, _dir) = make().await;
        seed_doomed(&rel).await;
        let prefix = rel.get_domain("doomed").unwrap().system_prefix;
        rel.delete_domain("doomed").await.unwrap();

        let p = purger(&rel, 100);
        p.purge_tick().await.unwrap(); // tombstone data
        p.purge_tick().await.unwrap(); // finalize

        let e = rel.engine();
        assert!(e.scan_keys(&keys::row_domain_prefix(&prefix)).await.unwrap().is_empty());
        assert!(e.scan_keys(&keys::index_domain_prefix(&prefix)).await.unwrap().is_empty());
        assert!(e.scan_keys(&keys::seq_domain_prefix(&prefix)).await.unwrap().is_empty());
        let mut cat = b"CAT:".to_vec();
        cat.extend_from_slice(&prefix);
        cat.push(b':');
        assert!(e.scan_keys(&cat).await.unwrap().is_empty(), "CAT entries gone");
        assert!(e.scan_keys(b"__sys:rel_catalog_seq:doomed").await.unwrap().is_empty(), "catalog seq gone");
        assert!(e.scan_keys(b"__sys:rel_domain:doomed").await.unwrap().is_empty(), "metadata gone");
        assert!(rel.get_domain_any("doomed").is_none());
        rel.shutdown().await;
    }

    // 3. Small batches need several ticks but converge.
    #[tokio::test]
    async fn test_purge_converges_in_small_batches() {
        let (rel, _dir) = make().await;
        seed_doomed(&rel).await;
        rel.delete_domain("doomed").await.unwrap();
        let p = purger(&rel, 2);
        for _ in 0..20 {
            p.purge_tick().await.unwrap();
            if rel.get_domain_any("doomed").is_none() {
                rel.shutdown().await;
                return;
            }
        }
        panic!("purge did not converge with small batches");
    }

    // 4. Purge converges even when tombstones are flushed to SSTables between
    //    ticks (scan_keys stays MVCC-correct across sources).
    #[tokio::test]
    async fn test_purge_converges_across_flushes() {
        let (rel, _dir) = make().await;
        seed_doomed(&rel).await;
        rel.delete_domain("doomed").await.unwrap();
        let p = purger(&rel, 2);
        for _ in 0..20 {
            p.purge_tick().await.unwrap();
            rel.engine().freeze_active_memtable();
            rel.engine().flush_memtable().await.unwrap();
            if rel.get_domain_any("doomed").is_none() {
                rel.shutdown().await;
                return;
            }
        }
        panic!("purge did not converge across flushes");
    }

    // 5. A deleting domain survives a restart and the purge resumes.
    #[tokio::test]
    async fn test_purge_resumes_after_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = config_in(dir.path());
        {
            let rel = boot(&cfg).await;
            seed_doomed(&rel).await;
            rel.delete_domain("doomed").await.unwrap();
            rel.shutdown().await;
        }
        let rel = boot(&cfg).await;
        assert_eq!(rel.domains.list_deleting_domains().len(), 1, "deleting domain survives restart");
        let p = purger(&rel, 100);
        p.purge_tick().await.unwrap();
        p.purge_tick().await.unwrap();
        assert!(rel.get_domain_any("doomed").is_none());
        rel.shutdown().await;
    }

    // 6. list_domains shows Deleting domains with state; get_domain stays
    //    active-only.
    #[tokio::test]
    async fn test_list_shows_deleting_but_resolution_active_only() {
        let (rel, _dir) = make().await;
        rel.create_domain("doomed").await.unwrap();
        rel.delete_domain("doomed").await.unwrap();
        let listed = rel.list_domains();
        let d = listed.iter().find(|d| d.name == "doomed").expect("deleting domain listed");
        assert_eq!(d.state, RelDomainState::Deleting);
        assert!(rel.get_domain("doomed").is_none(), "get_domain active-only");
        rel.shutdown().await;
    }

    // 7. A Deleting default domain survives boot (no 409 loop); after the purge
    //    finalizes it, the next boot recreates it as Active.
    #[tokio::test]
    async fn test_deleting_default_survives_boot_and_recreates() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = config_in(dir.path());
        {
            let rel = boot(&cfg).await;
            ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
            ok(&rel, "default", "INSERT INTO t VALUES (1)").await;
            rel.delete_domain("default").await.unwrap();
            rel.shutdown().await;
        }
        // Reboot before the purge finished: boot must succeed, default Deleting.
        let rel = boot(&cfg).await;
        assert!(rel.get_domain("default").is_none());
        let p = purger(&rel, 100);
        p.purge_tick().await.unwrap();
        p.purge_tick().await.unwrap();
        assert!(rel.get_domain_any("default").is_none(), "default finalized");
        rel.shutdown().await;
        // Next boot recreates default as Active.
        let rel = boot(&cfg).await;
        let d = rel.get_domain_any("default").expect("default recreated");
        assert_eq!(d.state, RelDomainState::Active);
        rel.shutdown().await;
    }

    // 8. Orphan sweep after DROP TABLE: ROW/IDX/SEQ of the dropped table's ids
    //    vanish; a co-resident live table is untouched.
    #[tokio::test]
    async fn test_orphan_sweep_drop_table() {
        let (rel, _dir) = make().await;
        ok(&rel, "default", "CREATE TABLE keep (id INTEGER PRIMARY KEY, s TEXT)").await;
        ok(&rel, "default", "INSERT INTO keep VALUES (1, 'live')").await;
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, city TEXT)").await;
        ok(&rel, "default", "CREATE INDEX t_city ON t (city)").await;
        for _ in 0..3 {
            ok(&rel, "default", "INSERT INTO t (city) VALUES ('E')").await;
        }
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let t = table_schema(&rel, "default", "t");
        let t_id = t.table_id;
        let ix_id = t.indexes.iter().find(|i| i.name == "t_city").unwrap().index_id;
        let keep_id = table_schema(&rel, "default", "keep").table_id;

        rel.drop_object("default", "t").await.unwrap(); // catalog-only

        let e = rel.engine();
        assert!(!e.scan_keys(&keys::row_table_prefix(&prefix, t_id)).await.unwrap().is_empty());
        assert!(!e.scan_keys(&keys::index_value_prefix(&prefix, ix_id, &[])).await.unwrap().is_empty());
        assert!(!e.scan_keys(&keys::seq_key(&prefix, t_id)).await.unwrap().is_empty());

        purger(&rel, 100).purge_tick().await.unwrap();

        assert!(e.scan_keys(&keys::row_table_prefix(&prefix, t_id)).await.unwrap().is_empty(), "orphan rows swept");
        assert!(e.scan_keys(&keys::index_value_prefix(&prefix, ix_id, &[])).await.unwrap().is_empty(), "orphan index swept");
        assert!(e.scan_keys(&keys::seq_key(&prefix, t_id)).await.unwrap().is_empty(), "orphan seq swept");
        assert!(!e.scan_keys(&keys::row_table_prefix(&prefix, keep_id)).await.unwrap().is_empty(), "live table intact");
        rel.shutdown().await;
    }

    // 9. Orphan sweep after DROP INDEX: only the dropped index_id's IDX entries
    //    go; the table's rows and other indexes stay.
    #[tokio::test]
    async fn test_orphan_sweep_drop_index() {
        let (rel, _dir) = make().await;
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, city TEXT)").await;
        ok(&rel, "default", "CREATE INDEX t_city ON t (city)").await;
        ok(&rel, "default", "INSERT INTO t VALUES (1, 'E'), (2, 'F')").await;
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let t = table_schema(&rel, "default", "t");
        let t_id = t.table_id;
        let ix_id = t.indexes.iter().find(|i| i.name == "t_city").unwrap().index_id;
        assert!(!rel.engine().scan_keys(&keys::index_value_prefix(&prefix, ix_id, &[])).await.unwrap().is_empty());

        rel.execute("default", "DROP INDEX t_city", &[]).await.unwrap(); // catalog-only

        purger(&rel, 100).purge_tick().await.unwrap();

        let e = rel.engine();
        assert!(e.scan_keys(&keys::index_value_prefix(&prefix, ix_id, &[])).await.unwrap().is_empty(), "orphan index entries swept");
        assert_eq!(e.scan_keys(&keys::row_table_prefix(&prefix, t_id)).await.unwrap().len(), 2, "rows intact");
        rel.shutdown().await;
    }

    // 10. Orphan sweep is idempotent/crash-trivial: a second run after a full
    //     sweep is a no-op (candidates re-derived, all probes empty).
    #[tokio::test]
    async fn test_orphan_sweep_idempotent() {
        let (rel, _dir) = make().await;
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, city TEXT)").await;
        ok(&rel, "default", "CREATE INDEX t_city ON t (city)").await;
        ok(&rel, "default", "INSERT INTO t VALUES (1, 'E')").await;
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let t_id = table_schema(&rel, "default", "t").table_id;
        rel.drop_object("default", "t").await.unwrap();

        let p = purger(&rel, 100);
        p.purge_tick().await.unwrap();
        let before = rel.metrics.system.rel_purged_keys_total.load(Ordering::Relaxed);
        p.purge_tick().await.unwrap();
        let after = rel.metrics.system.rel_purged_keys_total.load(Ordering::Relaxed);
        assert_eq!(before, after, "second sweep is a no-op");
        assert!(rel.engine().scan_keys(&keys::row_table_prefix(&prefix, t_id)).await.unwrap().is_empty());
        rel.shutdown().await;
    }

    // 11. Never-reuse: after DROP t + orphan purge, a same-named new table gets
    //     a fresh id (> old); no collision with old data.
    #[tokio::test]
    async fn test_never_reuse_after_orphan_purge() {
        let (rel, _dir) = make().await;
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        let old_id = table_schema(&rel, "default", "t").table_id;
        ok(&rel, "default", "INSERT INTO t VALUES (1)").await;
        rel.drop_object("default", "t").await.unwrap();
        purger(&rel, 100).purge_tick().await.unwrap();

        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        let new_id = table_schema(&rel, "default", "t").table_id;
        assert!(new_id > old_id, "new id {new_id} must exceed old {old_id}");
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        assert!(rel.engine().scan_keys(&keys::row_table_prefix(&prefix, new_id)).await.unwrap().is_empty());
        rel.shutdown().await;
    }

    // 12. Regression (§3): an in-flight writer parked on the write guard before
    //     delete_domain must abort (410/404) instead of landing keys after the
    //     purger finalized — no orphan ROW keys survive.
    #[tokio::test]
    async fn test_inflight_write_cannot_land_after_finalize() {
        let (rel, _dir) = make().await;
        rel.create_domain("doomed").await.unwrap();
        ok(&rel, "doomed", "CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)").await;
        let prefix = rel.get_domain("doomed").unwrap().system_prefix;

        // Park an in-flight writer on the write guard held by the test.
        let guard = rel.write_guard.lock().await;
        let writer = tokio::spawn({
            let rel = Arc::clone(&rel);
            async move { rel.execute("doomed", "INSERT INTO t VALUES (1, 1)", &[]).await }
        });
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        rel.delete_domain("doomed").await.unwrap();
        // The purger must block on the same guard instead of finalizing.
        let tick = tokio::spawn({
            let p = purger(&rel, 100);
            async move { p.purge_tick().await }
        });
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(rel.get_domain_any("doomed").is_some(), "purger must not finalize while a writer is in flight");
        drop(guard);

        let err = writer.await.unwrap().unwrap_err();
        assert!(
            matches!(err, RelStoreError::DomainDeleting(_) | RelStoreError::DomainNotFound(_)),
            "got: {err}"
        );
        tick.await.unwrap().unwrap();
        // Belt and suspenders: make sure it is fully finalized and clean.
        let p = purger(&rel, 100);
        p.purge_tick().await.unwrap();
        assert!(rel.get_domain_any("doomed").is_none());
        assert!(
            rel.engine().scan_keys(&keys::row_domain_prefix(&prefix)).await.unwrap().is_empty(),
            "no orphan ROW keys may survive the purge"
        );
        rel.shutdown().await;
    }

    // 13. Metrics: rel_purged_keys_total grows with tombstoned keys;
    //     rel_orphan_ranges_purged_total counts reaped orphan ranges.
    #[tokio::test]
    async fn test_metrics_counters() {
        let (rel, _dir) = make().await;
        seed_doomed(&rel).await;
        rel.delete_domain("doomed").await.unwrap();
        let keys_before = rel.metrics.system.rel_purged_keys_total.load(Ordering::Relaxed);
        let p = purger(&rel, 100);
        p.purge_tick().await.unwrap();
        let keys_after = rel.metrics.system.rel_purged_keys_total.load(Ordering::Relaxed);
        assert!(keys_after > keys_before, "purged-keys counter grew");

        // Orphan ranges via a DROP TABLE in an active domain (rows + index).
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, city TEXT)").await;
        ok(&rel, "default", "CREATE INDEX t_city ON t (city)").await;
        ok(&rel, "default", "INSERT INTO t VALUES (1, 'E')").await;
        rel.drop_object("default", "t").await.unwrap();
        let ranges_before = rel.metrics.system.rel_orphan_ranges_purged_total.load(Ordering::Relaxed);
        p.purge_tick().await.unwrap();
        let ranges_after = rel.metrics.system.rel_orphan_ranges_purged_total.load(Ordering::Relaxed);
        assert!(ranges_after > ranges_before, "orphan-ranges counter grew");
        rel.shutdown().await;
    }

    // 14. Orphan sweep budget: a small batch caps a single tick's deletions
    //     and forces several ticks to fully drain the orphan ranges.
    #[tokio::test]
    async fn test_orphan_sweep_converges_in_small_batches() {
        let (rel, _dir) = make().await;
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, city TEXT)").await;
        ok(&rel, "default", "CREATE INDEX t_city ON t (city)").await;
        for i in 1..=5 {
            ok(&rel, "default", &format!("INSERT INTO t VALUES ({i}, 'c{i}')")).await;
        }
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let t = table_schema(&rel, "default", "t");
        let t_id = t.table_id;
        let ix_id = t.indexes.iter().find(|i| i.name == "t_city").unwrap().index_id;

        rel.drop_object("default", "t").await.unwrap();

        let p = purger(&rel, 2);
        let mut ticks = 0;
        loop {
            let before = rel.metrics.system.rel_purged_keys_total.load(Ordering::Relaxed);
            p.purge_tick().await.unwrap();
            let delta = rel.metrics.system.rel_purged_keys_total.load(Ordering::Relaxed) - before;
            assert!(delta <= 2, "one tick must not delete more than batch_size keys, got {delta}");
            ticks += 1;
            let e = rel.engine();
            let done = e.scan_keys(&keys::row_table_prefix(&prefix, t_id)).await.unwrap().is_empty()
                && e.scan_keys(&keys::index_value_prefix(&prefix, ix_id, &[])).await.unwrap().is_empty();
            if done {
                break;
            }
            assert!(ticks < 20, "orphan sweep did not converge with small batches");
        }
        assert!(ticks > 1, "10 orphan keys must not fit in a single batch of 2");
        rel.shutdown().await;
    }

    // 15. Regression (rel/013 F1): the orphan sweep must spare an index id that
    //     is reserved by an in-flight CREATE INDEX (the
    //     create_index_reserve→commit window). The reserved id is past the
    //     high-water mark but not yet catalog-live, so without the reservation
    //     guard the sweep would reap its freshly backfilled IDX bytes.
    #[tokio::test]
    async fn test_orphan_sweep_spares_reserved_index_id() {
        let (rel, _dir) = make().await;
        ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, city TEXT)").await;
        let prefix = rel.get_domain("default").unwrap().system_prefix;

        // Reserve an index id without committing it: the id is now allocated
        // (hwm bumped) and reserved, but not catalog-live.
        let (_dom, _schema, meta) = rel
            .catalog()
            .create_index_reserve(&rel.domains, "default", "t", "t_city", "city", false)
            .await
            .unwrap();
        // Simulate the backfill that runs inside that window: an IDX entry for
        // the reserved id (empty value, exactly as the real backfill writes).
        let idx_key = keys::index_key(&prefix, meta.index_id, b"Essen", b"\x00\x00\x00\x01");
        rel.engine()
            .write_batch(vec![BatchOp::Put { key: idx_key, value: Vec::new() }])
            .await
            .unwrap();

        purger(&rel, 100).purge_tick().await.unwrap();

        assert!(
            !rel.engine()
                .scan_keys(&keys::index_value_prefix(&prefix, meta.index_id, &[]))
                .await
                .unwrap()
                .is_empty(),
            "a reserved index id's IDX bytes must survive the orphan sweep"
        );
        rel.shutdown().await;
    }

    // 16. Regression (rel/009 F2): finalizing a deleting domain drops its
    //     rate-limiter bucket, so a recreated same-name domain cannot inherit
    //     the old (possibly drained) bucket state.
    #[tokio::test]
    async fn test_finalize_drops_rate_limiter() {
        let (rel, _dir) = make().await;
        rel.create_domain("doomed").await.unwrap();
        // A request lazily creates the per-domain bucket.
        rel.check_domain_budget("doomed", true);
        assert!(rel.has_rate_limiter("doomed"), "bucket exists after a request");

        rel.delete_domain("doomed").await.unwrap();
        // Empty domain: one tick finds no data and finalizes immediately.
        purger(&rel, 100).purge_tick().await.unwrap();

        assert!(rel.get_domain_any("doomed").is_none(), "domain finalized");
        assert!(!rel.has_rate_limiter("doomed"), "rate-limiter bucket dropped on finalize");
        rel.shutdown().await;
    }
}
