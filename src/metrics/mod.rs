//! Metrics system — Spec 013.
//!
//! - `MetricsStore`: central store for system-wide lifetime counters and per-domain
//!   sliding-window metrics. Held as `Arc<MetricsStore>` in `AppState`.
//! - `MetricsTicker`: background task that calls `tick_all()` every second.
//! - `HeartbeatMetrics`: data returned by `GET /health`.
//! - `DomainWindowMetrics`: aggregated per-domain window returned by `/metrics`.
//! - `EngineWindowMetrics`: aggregated per-engine (kv/json/rel) window returned
//!   by `/metrics` (spec general/019).

pub mod window;

use crate::engines::lsm::engine::EngineHeartbeatData;
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use window::MetricsWindow;

// ── Version string ────────────────────────────────────────────────────────────

pub const LURADB_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Width of the rolling window in seconds.
    pub window_secs: u64,
    /// Tick interval of the background task in milliseconds.
    pub ticker_interval_ms: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            ticker_interval_ms: 1000,
        }
    }
}

// ── HeartbeatMetrics ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HeartbeatMetrics {
    pub status: &'static str,
    pub uptime_secs: u64,
    pub version: &'static str,
    pub domain_count: usize,
    pub estimated_memtable_keys: u64,
    pub vlog_size_bytes: u64,
    pub l0_sstable_count: usize,
}

// ── SystemMetrics ─────────────────────────────────────────────────────────────

pub struct SystemMetrics {
    pub total_reads: AtomicU64,
    pub total_writes: AtomicU64,
    /// Relational DDL counters (spec rel/003).
    pub rel_ddl_create_total: AtomicU64,
    pub rel_ddl_drop_total: AtomicU64,
    /// SQL frontend counters (spec rel/004 §10), one field per `{class}`/`{op}`
    /// label value — same flat-counter style as the rel/003 fields above.
    pub rel_frontend_statements_read_total: AtomicU64,
    pub rel_frontend_statements_write_total: AtomicU64,
    pub rel_frontend_statements_ddl_total: AtomicU64,
    pub rel_frontend_parse_errors_total: AtomicU64,
    pub rel_ddl_op_create_table_total: AtomicU64,
    pub rel_ddl_op_alter_table_total: AtomicU64,
    pub rel_ddl_op_drop_table_total: AtomicU64,
    pub rel_ddl_op_create_index_total: AtomicU64,
    pub rel_ddl_op_drop_index_total: AtomicU64,
    /// DML write-path counters (spec rel/005 §16), one field per `{op}` label.
    pub rel_dml_statements_insert_total: AtomicU64,
    pub rel_dml_statements_update_total: AtomicU64,
    pub rel_dml_statements_delete_total: AtomicU64,
    pub rel_dml_scanned_rows_total: AtomicU64,
    pub rel_index_backfill_entries_total: AtomicU64,
    /// SELECT executor counters (spec rel/006 §12).
    pub rel_select_statements_total: AtomicU64,
    pub rel_select_scanned_keys_total: AtomicU64,
    pub rel_sort_fallback_total: AtomicU64,
    /// LEFT JOIN counter (spec rel/007 §9): one per executed probe.
    pub rel_join_probes_total: AtomicU64,
    /// View counters (spec rel/008 §10): inlined view references (execution
    /// time, recursive substitutions included), and `CREATE`/`DROP VIEW` ops.
    pub rel_view_inlinings_total: AtomicU64,
    pub rel_ddl_view_ops_create_view_total: AtomicU64,
    pub rel_ddl_view_ops_drop_view_total: AtomicU64,
    /// Cross-engine link counters (spec rel/012 §8), one field per `{engine}`
    /// label value — same flat-counter style as the fields above.
    pub rel_cross_engine_expand_lookups_kv_total: AtomicU64,
    pub rel_cross_engine_expand_lookups_json_total: AtomicU64,
    pub rel_cross_engine_swept_cells_total: AtomicU64,
    pub rel_cross_engine_write_validations_kv_total: AtomicU64,
    pub rel_cross_engine_write_validations_json_total: AtomicU64,
    /// Domain-purger counters (spec rel/013 §9): tombstoned data keys (both
    /// purger tasks) and fully-reaped orphan id ranges (orphan sweep).
    pub rel_purged_keys_total: AtomicU64,
    pub rel_orphan_ranges_purged_total: AtomicU64,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            total_reads: AtomicU64::new(0),
            total_writes: AtomicU64::new(0),
            rel_ddl_create_total: AtomicU64::new(0),
            rel_ddl_drop_total: AtomicU64::new(0),
            rel_frontend_statements_read_total: AtomicU64::new(0),
            rel_frontend_statements_write_total: AtomicU64::new(0),
            rel_frontend_statements_ddl_total: AtomicU64::new(0),
            rel_frontend_parse_errors_total: AtomicU64::new(0),
            rel_ddl_op_create_table_total: AtomicU64::new(0),
            rel_ddl_op_alter_table_total: AtomicU64::new(0),
            rel_ddl_op_drop_table_total: AtomicU64::new(0),
            rel_ddl_op_create_index_total: AtomicU64::new(0),
            rel_ddl_op_drop_index_total: AtomicU64::new(0),
            rel_dml_statements_insert_total: AtomicU64::new(0),
            rel_dml_statements_update_total: AtomicU64::new(0),
            rel_dml_statements_delete_total: AtomicU64::new(0),
            rel_dml_scanned_rows_total: AtomicU64::new(0),
            rel_index_backfill_entries_total: AtomicU64::new(0),
            rel_select_statements_total: AtomicU64::new(0),
            rel_select_scanned_keys_total: AtomicU64::new(0),
            rel_sort_fallback_total: AtomicU64::new(0),
            rel_join_probes_total: AtomicU64::new(0),
            rel_view_inlinings_total: AtomicU64::new(0),
            rel_ddl_view_ops_create_view_total: AtomicU64::new(0),
            rel_ddl_view_ops_drop_view_total: AtomicU64::new(0),
            rel_cross_engine_expand_lookups_kv_total: AtomicU64::new(0),
            rel_cross_engine_expand_lookups_json_total: AtomicU64::new(0),
            rel_cross_engine_swept_cells_total: AtomicU64::new(0),
            rel_cross_engine_write_validations_kv_total: AtomicU64::new(0),
            rel_cross_engine_write_validations_json_total: AtomicU64::new(0),
            rel_purged_keys_total: AtomicU64::new(0),
            rel_orphan_ranges_purged_total: AtomicU64::new(0),
        }
    }
}

// ── DomainWindowMetrics ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DomainWindowMetrics {
    pub domain: String,
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_latency_us_p50: u64,
    pub read_latency_us_p99: u64,
    pub cache_hit_rate: f32,
    pub rate_limit_rejections: u64,
    pub window_secs: u64,
}

// ── EngineWindowMetrics (spec general/019) ────────────────────────────────────

/// Which storage engine an aggregate op/latency window belongs to; indexes
/// `MetricsStore::engines`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    Kv = 0,
    Json = 1,
    Rel = 2,
}

/// Per-engine counterpart of `DomainWindowMetrics`: aggregate ops/s and
/// latency percentiles across all domains of one engine (kv/json/rel), read
/// and write side by side. No `cache_hit_rate` — engine windows don't track
/// cache hit/miss.
#[derive(Serialize)]
pub struct EngineWindowMetrics {
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_latency_us_p50: u64,
    pub read_latency_us_p95: u64,
    pub read_latency_us_p99: u64,
    pub write_latency_us_p50: u64,
    pub write_latency_us_p95: u64,
    pub write_latency_us_p99: u64,
    pub window_secs: u64,
}

// ── MetricsStore ──────────────────────────────────────────────────────────────

pub struct MetricsStore {
    pub system: SystemMetrics,
    domains: RwLock<HashMap<String, MetricsWindow>>,
    /// Per-engine aggregate windows (spec general/019), indexed by
    /// `EngineKind`. Fixed at construction — no lazy insert, no removal on
    /// domain deletion — so engine windows outlive individual domains.
    engines: [MetricsWindow; 3],
    /// Per-rel-domain catalog-object count gauge (spec rel/003).
    rel_catalog_objects: RwLock<HashMap<String, u64>>,
    started_at: u64,
    config: MetricsConfig,
}

impl MetricsStore {
    pub fn new(config: MetricsConfig) -> Arc<Self> {
        let window_secs = config.window_secs as usize;
        Arc::new(Self {
            system: SystemMetrics::default(),
            domains: RwLock::new(HashMap::new()),
            engines: std::array::from_fn(|_| MetricsWindow::new(window_secs)),
            rel_catalog_objects: RwLock::new(HashMap::new()),
            started_at: now_secs(),
            config,
        })
    }

    // ── Relational catalog metrics (spec rel/003) ────────────────────────────

    pub fn record_rel_ddl_create(&self) {
        self.system.rel_ddl_create_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rel_ddl_drop(&self) {
        self.system.rel_ddl_drop_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Sets the current catalog-object count (tables + views) of a rel domain.
    pub fn set_rel_catalog_objects(&self, domain: &str, count: u64) {
        self.rel_catalog_objects
            .write()
            .insert(domain.to_string(), count);
    }

    /// Current catalog-object count of a rel domain, if known.
    pub fn rel_catalog_objects(&self, domain: &str) -> Option<u64> {
        self.rel_catalog_objects.read().get(domain).copied()
    }

    // ── SQL frontend & DDL metrics (spec rel/004 §10) ────────────────────────

    /// Counts a parsed+bound statement by class: `"read"`/`"write"`/`"ddl"`.
    pub fn record_rel_frontend_statement(&self, class: &str) {
        let counter = match class {
            "read" => &self.system.rel_frontend_statements_read_total,
            "write" => &self.system.rel_frontend_statements_write_total,
            "ddl" => &self.system.rel_frontend_statements_ddl_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a lex/parse failure (statement never reached the binder).
    pub fn record_rel_frontend_parse_error(&self) {
        self.system.rel_frontend_parse_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts an executed DDL operation by kind (`"create_table"`,
    /// `"alter_table"`, `"drop_table"`, `"create_index"`, `"drop_index"`).
    pub fn record_rel_ddl_op(&self, op: &str) {
        let counter = match op {
            "create_table" => &self.system.rel_ddl_op_create_table_total,
            "alter_table" => &self.system.rel_ddl_op_alter_table_total,
            "drop_table" => &self.system.rel_ddl_op_drop_table_total,
            "create_index" => &self.system.rel_ddl_op_create_index_total,
            "drop_index" => &self.system.rel_ddl_op_drop_index_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    // ── DML write-path metrics (spec rel/005 §16) ────────────────────────────

    /// Counts an executed DML statement by op (`"insert"`/`"update"`/`"delete"`).
    pub fn record_rel_dml_statement(&self, op: &str) {
        let counter = match op {
            "insert" => &self.system.rel_dml_statements_insert_total,
            "update" => &self.system.rel_dml_statements_update_total,
            "delete" => &self.system.rel_dml_statements_delete_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` rows scanned during full-scan candidate acquisition.
    pub fn record_rel_dml_scanned_rows(&self, n: u64) {
        self.system.rel_dml_scanned_rows_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` index entries written by a CREATE INDEX backfill.
    pub fn record_rel_index_backfill_entries(&self, n: u64) {
        self.system
            .rel_index_backfill_entries_total
            .fetch_add(n, Ordering::Relaxed);
    }

    // ── SELECT executor metrics (spec rel/006 §12) ───────────────────────────

    /// Counts one executed single-table SELECT/COUNT statement.
    pub fn record_rel_select_statement(&self) {
        self.system.rel_select_statements_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` ROW/IDX keys visited by the chosen access path (I/O budget
    /// visibility; §9).
    pub fn record_rel_select_scanned_keys(&self, n: u64) {
        self.system.rel_select_scanned_keys_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Counts a statement that fell back to the in-memory ORDER BY sort path.
    pub fn record_rel_sort_fallback(&self) {
        self.system.rel_sort_fallback_total.fetch_add(1, Ordering::Relaxed);
    }

    // ── LEFT JOIN metrics (spec rel/007 §9) ──────────────────────────────────

    /// Counts one executed join probe (non-NULL ON value; NULL never probes).
    pub fn record_rel_join_probes(&self, n: u64) {
        self.system.rel_join_probes_total.fetch_add(n, Ordering::Relaxed);
    }

    // ── View metrics (spec rel/008 §10) ──────────────────────────────────────

    /// Adds `n` view references substituted by the inliner (recursive ones
    /// included), at SELECT execution time.
    pub fn record_rel_view_inlinings(&self, n: u64) {
        self.system.rel_view_inlinings_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Counts an executed view DDL op (`"create_view"`/`"drop_view"`).
    pub fn record_rel_ddl_view_op(&self, op: &str) {
        let counter = match op {
            "create_view" => &self.system.rel_ddl_view_ops_create_view_total,
            "drop_view" => &self.system.rel_ddl_view_ops_drop_view_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    // ── Cross-engine link metrics (spec rel/012 §8) ──────────────────────────

    /// Counts one actual cross-engine expand point-lookup by `{engine}`
    /// (`"kv"`/`"json"`); NULL/masked entries never reach here.
    pub fn record_rel_cross_engine_expand_lookup(&self, engine: &str) {
        let counter = match engine {
            "kv" => &self.system.rel_cross_engine_expand_lookups_kv_total,
            "json" => &self.system.rel_cross_engine_expand_lookups_json_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` physically nulled link cells (sweep progress, §5).
    pub fn record_rel_cross_engine_swept_cells(&self, n: u64) {
        self.system.rel_cross_engine_swept_cells_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Counts one link existence check in the write path by `{engine}`.
    pub fn record_rel_cross_engine_write_validation(&self, engine: &str) {
        let counter = match engine {
            "kv" => &self.system.rel_cross_engine_write_validations_kv_total,
            "json" => &self.system.rel_cross_engine_write_validations_json_total,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` tombstoned data keys (both purger tasks, spec rel/013 §9).
    pub fn record_rel_purged_keys(&self, n: u64) {
        self.system.rel_purged_keys_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` fully-reaped orphan id ranges (orphan sweep, spec rel/013 §9).
    pub fn record_rel_orphan_ranges_purged(&self, n: u64) {
        self.system.rel_orphan_ranges_purged_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Lazily creates a `MetricsWindow` for `domain` if it doesn't exist yet.
    fn ensure_domain(&self, domain: &str) {
        if self.domains.read().contains_key(domain) {
            return;
        }
        self.domains
            .write()
            .entry(domain.to_string())
            .or_insert_with(|| MetricsWindow::new(self.config.window_secs as usize));
    }

    /// KV-only (every current call site is `DomainStore`'s read path) —
    /// also mirrors into the KV engine-aggregate window (spec general/019).
    /// JSON and rel use `record_engine_read` instead.
    pub fn record_read(&self, domain: &str, latency_us: u64, is_hit: bool) {
        self.system.total_reads.fetch_add(1, Ordering::Relaxed);
        self.ensure_domain(domain);
        let domains = self.domains.read();
        if let Some(w) = domains.get(domain) {
            w.record_read(latency_us, is_hit);
        }
        self.engines[EngineKind::Kv as usize].record_read(latency_us, is_hit);
    }

    /// KV-only — see [`Self::record_read`]. JSON and rel use
    /// `record_engine_write` instead.
    pub fn record_write(&self, domain: &str, latency_us: u64) {
        self.system.total_writes.fetch_add(1, Ordering::Relaxed);
        self.ensure_domain(domain);
        let domains = self.domains.read();
        if let Some(w) = domains.get(domain) {
            w.record_write(latency_us);
        }
        self.engines[EngineKind::Kv as usize].record_write(latency_us);
    }

    /// Records one read op on `kind`'s engine-aggregate window (spec
    /// general/019) — the JSON/rel counterpart of KV's `record_read`
    /// mirroring. Engine windows don't track cache hit/miss.
    pub fn record_engine_read(&self, kind: EngineKind, latency_us: u64) {
        self.engines[kind as usize].record_read(latency_us, false);
    }

    /// Records one write op on `kind`'s engine-aggregate window (spec
    /// general/019).
    pub fn record_engine_write(&self, kind: EngineKind, latency_us: u64) {
        self.engines[kind as usize].record_write(latency_us);
    }

    /// Aggregates the three engine windows, indexed by `EngineKind`
    /// (`[kv, json, rel]`).
    pub fn engine_metrics(&self) -> [EngineWindowMetrics; 3] {
        std::array::from_fn(|i| self.engines[i].aggregate_engine(self.config.window_secs))
    }

    pub fn record_rate_limit_rejection(&self, domain: &str) {
        self.ensure_domain(domain);
        let domains = self.domains.read();
        if let Some(w) = domains.get(domain) {
            w.record_rate_limit_rejection();
        }
    }

    /// Removes a domain's metrics window (called when domain is purged).
    pub fn remove_domain(&self, domain: &str) {
        self.domains.write().remove(domain);
        self.rel_catalog_objects.write().remove(domain);
    }

    pub fn get_domain_metrics(&self, domain: &str) -> Option<DomainWindowMetrics> {
        let domains = self.domains.read();
        domains.get(domain).map(|w| w.aggregate(domain, self.config.window_secs))
    }

    pub fn get_all_domain_metrics(&self) -> Vec<DomainWindowMetrics> {
        let domains = self.domains.read();
        domains.iter().map(|(name, w)| w.aggregate(name, self.config.window_secs)).collect()
    }

    /// Advances all per-domain rolling windows by one second.
    ///
    /// Called by `MetricsTicker` once per tick interval.
    pub fn tick_all(&self) {
        let domains = self.domains.read();
        for w in domains.values() {
            w.tick();
        }
        for w in &self.engines {
            w.tick();
        }
    }

    /// Builds a `HeartbeatMetrics` snapshot using live engine data.
    pub fn heartbeat(&self, engine_data: &EngineHeartbeatData, domain_count: usize) -> HeartbeatMetrics {
        HeartbeatMetrics {
            status: "ok",
            uptime_secs: now_secs().saturating_sub(self.started_at),
            version: LURADB_VERSION,
            domain_count,
            estimated_memtable_keys: engine_data.estimated_memtable_keys,
            vlog_size_bytes: engine_data.vlog_size_bytes,
            l0_sstable_count: engine_data.l0_sstable_count,
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── MetricsTicker ─────────────────────────────────────────────────────────────

/// Background task: ticks all domain windows once per `config.ticker_interval_ms`.
pub struct MetricsTicker {
    store: Arc<MetricsStore>,
    interval_ms: u64,
}

impl MetricsTicker {
    pub fn new(store: Arc<MetricsStore>) -> Self {
        let interval_ms = store.config.ticker_interval_ms;
        Self { store, interval_ms }
    }

    pub async fn run(self) {
        let interval = tokio::time::Duration::from_millis(self.interval_ms);
        loop {
            tokio::time::sleep(interval).await;
            self.store.tick_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rel_catalog_metrics() {
        let store = MetricsStore::new(MetricsConfig::default());
        store.record_rel_ddl_create();
        store.record_rel_ddl_create();
        store.record_rel_ddl_drop();
        assert_eq!(store.system.rel_ddl_create_total.load(Ordering::Relaxed), 2);
        assert_eq!(store.system.rel_ddl_drop_total.load(Ordering::Relaxed), 1);

        store.set_rel_catalog_objects("shop", 3);
        assert_eq!(store.rel_catalog_objects("shop"), Some(3));
        store.remove_domain("shop");
        assert_eq!(store.rel_catalog_objects("shop"), None);
    }

    // SQL frontend & DDL counters (spec rel/004 §10).
    #[test]
    fn test_rel_frontend_metrics() {
        let store = MetricsStore::new(MetricsConfig::default());
        store.record_rel_frontend_statement("ddl");
        store.record_rel_frontend_statement("read");
        store.record_rel_frontend_statement("read");
        store.record_rel_frontend_statement("write");
        store.record_rel_frontend_statement("bogus"); // unknown label: ignored, not panicking
        assert_eq!(store.system.rel_frontend_statements_ddl_total.load(Ordering::Relaxed), 1);
        assert_eq!(store.system.rel_frontend_statements_read_total.load(Ordering::Relaxed), 2);
        assert_eq!(store.system.rel_frontend_statements_write_total.load(Ordering::Relaxed), 1);

        store.record_rel_frontend_parse_error();
        assert_eq!(store.system.rel_frontend_parse_errors_total.load(Ordering::Relaxed), 1);

        store.record_rel_ddl_op("create_table");
        store.record_rel_ddl_op("drop_index");
        store.record_rel_ddl_op("drop_index");
        assert_eq!(store.system.rel_ddl_op_create_table_total.load(Ordering::Relaxed), 1);
        assert_eq!(store.system.rel_ddl_op_drop_index_total.load(Ordering::Relaxed), 2);
    }
}
