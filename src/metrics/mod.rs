//! Metrics system.
//!
//! - `MetricsStore`: one per data shard — lifetime counters and per-domain
//!   and per-engine sliding-window metrics of that shard's work. Held as
//!   `Arc<MetricsStore>` in the shard's `AppState`.
//! - `MetricsSample`: a store's counters and windows as of one moment; the
//!   samples of all shards merge into what `/metrics` reports.
//! - `MetricsTicker`: background task that calls `tick_all()` every second.
//! - `HeartbeatMetrics`: data returned by `GET /health`.
//! - `DomainWindowMetrics`: aggregated per-domain window returned by `/metrics`.
//! - `EngineWindowMetrics`: aggregated per-engine (kv/json/rel) window returned
//!   by `/metrics`.

pub mod window;

use crate::control::resources::ResourceReport;
use crate::storage::write_failures::IoReport;
use crate::engines::lsm::engine::EngineHeartbeatData;
use parking_lot::{RwLock, RwLockReadGuard};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use window::{MetricsWindow, WindowTotals};

pub const LURADB_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Width of the rolling window in seconds.
const WINDOW_SECS: u64 = 60;
/// Tick interval of the background task in milliseconds.
const TICKER_INTERVAL_MS: u64 = 1000;

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
            window_secs: WINDOW_SECS,
            ticker_interval_ms: TICKER_INTERVAL_MS,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct HeartbeatMetrics {
    /// `ok`, or `degraded` while a data shard does not answer, disk space
    /// or memory runs short (`resources`) or writes of a data file fail
    /// (`io`).
    pub status: &'static str,
    pub uptime_secs: u64,
    pub version: &'static str,
    pub domain_count: usize,
    pub estimated_memtable_keys: u64,
    pub vlog_size_bytes: u64,
    pub l0_sstable_count: usize,
    /// Every data shard, by id.
    pub shards: Vec<ShardHealth>,
    /// Free disk space of each data volume and the server's own memory.
    pub resources: ResourceReport,
    /// Only while writes of a data file fail: the file with the most
    /// failures in a row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<IoReport>,
}

/// A data shard as `GET /health` reports it: `ok` once it answered its
/// ping, `timeout` otherwise.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ShardHealth {
    pub id: u16,
    pub status: &'static str,
}

pub struct SystemMetrics {
    pub total_reads: AtomicU64,
    pub total_writes: AtomicU64,
    /// Relational DDL counters.
    pub rel_ddl_create_total: AtomicU64,
    pub rel_ddl_drop_total: AtomicU64,
    /// SQL frontend counters, one field per `{class}`/`{op}`
    /// label value — same flat-counter style as the DDL fields above.
    pub rel_frontend_statements_read_total: AtomicU64,
    pub rel_frontend_statements_write_total: AtomicU64,
    pub rel_frontend_statements_ddl_total: AtomicU64,
    pub rel_frontend_parse_errors_total: AtomicU64,
    pub rel_ddl_op_create_table_total: AtomicU64,
    pub rel_ddl_op_alter_table_total: AtomicU64,
    pub rel_ddl_op_drop_table_total: AtomicU64,
    pub rel_ddl_op_create_index_total: AtomicU64,
    pub rel_ddl_op_drop_index_total: AtomicU64,
    /// DML write-path counters, one field per `{op}` label.
    pub rel_dml_statements_insert_total: AtomicU64,
    pub rel_dml_statements_update_total: AtomicU64,
    pub rel_dml_statements_delete_total: AtomicU64,
    pub rel_dml_scanned_rows_total: AtomicU64,
    pub rel_index_backfill_entries_total: AtomicU64,
    /// SELECT executor counters.
    pub rel_select_statements_total: AtomicU64,
    pub rel_select_scanned_keys_total: AtomicU64,
    pub rel_sort_fallback_total: AtomicU64,
    /// LEFT JOIN counter: one per executed probe.
    pub rel_join_probes_total: AtomicU64,
    /// View counters: inlined view references (execution
    /// time, recursive substitutions included), and `CREATE`/`DROP VIEW` ops.
    pub rel_view_inlinings_total: AtomicU64,
    pub rel_ddl_view_ops_create_view_total: AtomicU64,
    pub rel_ddl_view_ops_drop_view_total: AtomicU64,
    /// Cross-engine link counters, one field per `{engine}`
    /// label value — same flat-counter style as the fields above.
    pub rel_cross_engine_expand_lookups_kv_total: AtomicU64,
    pub rel_cross_engine_expand_lookups_json_total: AtomicU64,
    pub rel_cross_engine_swept_cells_total: AtomicU64,
    pub rel_cross_engine_write_validations_kv_total: AtomicU64,
    pub rel_cross_engine_write_validations_json_total: AtomicU64,
    /// Domain-purger counters: tombstoned data keys (both
    /// purger tasks) and fully-reaped orphan id ranges (orphan sweep).
    pub rel_purged_keys_total: AtomicU64,
    pub rel_orphan_ranges_purged_total: AtomicU64,
    /// SHM snapshot publisher: publishes, publishes skipped because a client
    /// still pinned the target buffer, the current run of skips (0 again after
    /// the next publish), and clients disconnected for blocking a run too long.
    pub shm_snapshot_publishes_total: AtomicU64,
    pub shm_snapshot_publish_skips_total: AtomicU64,
    pub shm_snapshot_consecutive_skips: AtomicU64,
    pub shm_clients_kicked_total: AtomicU64,
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
            shm_snapshot_publishes_total: AtomicU64::new(0),
            shm_snapshot_publish_skips_total: AtomicU64::new(0),
            shm_snapshot_consecutive_skips: AtomicU64::new(0),
            shm_clients_kicked_total: AtomicU64::new(0),
        }
    }
}

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

/// One store's counters and windows as of one moment. Samples of several
/// stores, one per data shard, merge into the totals `/metrics` reports.
pub struct MetricsSample {
    pub total_reads: u64,
    pub total_writes: u64,
    pub shm_snapshot_publishes_total: u64,
    pub shm_snapshot_publish_skips_total: u64,
    pub shm_snapshot_consecutive_skips: u64,
    pub shm_clients_kicked_total: u64,
    domains: HashMap<String, WindowTotals>,
    engines: [WindowTotals; 3],
    window_secs: u64,
}

impl MetricsSample {
    /// Adds `other` field by field; windows of the same domain add up.
    pub fn merge(&mut self, other: MetricsSample) {
        self.total_reads += other.total_reads;
        self.total_writes += other.total_writes;
        self.shm_snapshot_publishes_total += other.shm_snapshot_publishes_total;
        self.shm_snapshot_publish_skips_total += other.shm_snapshot_publish_skips_total;
        self.shm_snapshot_consecutive_skips += other.shm_snapshot_consecutive_skips;
        self.shm_clients_kicked_total += other.shm_clients_kicked_total;
        for (domain, totals) in other.domains {
            self.domains.entry(domain).or_default().add(&totals);
        }
        for (engine, totals) in self.engines.iter_mut().zip(&other.engines) {
            engine.add(totals);
        }
    }

    pub fn domain_metrics(&self) -> Vec<DomainWindowMetrics> {
        self.domains.iter().map(|(name, totals)| totals.domain_metrics(name, self.window_secs)).collect()
    }

    /// The three engine windows, indexed by `EngineKind` (`[kv, json, rel]`).
    pub fn engine_metrics(&self) -> [EngineWindowMetrics; 3] {
        std::array::from_fn(|i| self.engines[i].engine_metrics(self.window_secs))
    }
}

pub struct MetricsStore {
    pub system: SystemMetrics,
    /// Per-domain windows, created on a domain's first recorded op. `Arc` so
    /// a domain's runtime can keep its own window and record reads without
    /// a lookup here.
    domains: RwLock<HashMap<String, Arc<MetricsWindow>>>,
    /// Test-only count of read locks taken on `domains`.
    #[cfg(test)]
    domain_map_reads: AtomicU64,
    /// Per-engine aggregate windows, indexed by
    /// `EngineKind`. Fixed at construction — no lazy insert, no removal on
    /// domain deletion — so engine windows outlive individual domains.
    engines: [MetricsWindow; 3],
    /// Per-rel-domain catalog-object count gauge.
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
            #[cfg(test)]
            domain_map_reads: AtomicU64::new(0),
            engines: std::array::from_fn(|_| MetricsWindow::new(window_secs)),
            rel_catalog_objects: RwLock::new(HashMap::new()),
            started_at: now_secs(),
            config,
        })
    }

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

    /// Counts one executed single-table SELECT/COUNT statement.
    pub fn record_rel_select_statement(&self) {
        self.system.rel_select_statements_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` ROW/IDX keys visited by the chosen access path (I/O budget
    /// visibility).
    pub fn record_rel_select_scanned_keys(&self, n: u64) {
        self.system.rel_select_scanned_keys_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Counts a statement that fell back to the in-memory ORDER BY sort path.
    pub fn record_rel_sort_fallback(&self) {
        self.system.rel_sort_fallback_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one executed join probe (non-NULL ON value; NULL never probes).
    pub fn record_rel_join_probes(&self, n: u64) {
        self.system.rel_join_probes_total.fetch_add(n, Ordering::Relaxed);
    }

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

    /// Adds `n` physically nulled link cells (sweep progress).
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

    /// Adds `n` tombstoned data keys (both purger tasks).
    pub fn record_rel_purged_keys(&self, n: u64) {
        self.system.rel_purged_keys_total.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` fully-reaped orphan id ranges (orphan sweep).
    pub fn record_rel_orphan_ranges_purged(&self, n: u64) {
        self.system.rel_orphan_ranges_purged_total.fetch_add(n, Ordering::Relaxed);
    }

    // The publisher task is the only writer, so the run gauge needs no CAS.

    /// Counts a published snapshot and ends the current skip run.
    pub fn record_shm_publish(&self) {
        self.system.shm_snapshot_publishes_total.fetch_add(1, Ordering::Relaxed);
        self.system.shm_snapshot_consecutive_skips.store(0, Ordering::Relaxed);
    }

    /// Counts a skipped publish and extends the current skip run.
    pub fn record_shm_publish_skip(&self) {
        self.system.shm_snapshot_publish_skips_total.fetch_add(1, Ordering::Relaxed);
        self.system.shm_snapshot_consecutive_skips.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one client disconnected for blocking the snapshot too long.
    pub fn record_shm_client_kicked(&self) {
        self.system.shm_clients_kicked_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Read access to the domain map, counted in test builds.
    fn domains(&self) -> RwLockReadGuard<'_, HashMap<String, Arc<MetricsWindow>>> {
        #[cfg(test)]
        self.domain_map_reads.fetch_add(1, Ordering::Relaxed);
        self.domains.read()
    }

    /// Test-only: read locks taken on the domain map so far.
    #[cfg(test)]
    pub(crate) fn domain_map_reads(&self) -> u64 {
        self.domain_map_reads.load(Ordering::Relaxed)
    }

    /// The window of `domain`, created on first use.
    pub fn domain_window(&self, domain: &str) -> Arc<MetricsWindow> {
        if let Some(window) = self.domains().get(domain) {
            return Arc::clone(window);
        }
        let mut domains = self.domains.write();
        let window = domains
            .entry(domain.to_string())
            .or_insert_with(|| Arc::new(MetricsWindow::new(self.config.window_secs as usize)));
        Arc::clone(window)
    }

    /// KV-only (every current call site is `DomainStore`'s read path) —
    /// also mirrors into the KV engine-aggregate window.
    /// `window` comes from [`Self::domain_window`]. JSON and rel use
    /// `record_engine_read` instead.
    pub fn record_read(&self, window: &MetricsWindow, latency_us: u64, is_hit: bool) {
        self.system.total_reads.fetch_add(1, Ordering::Relaxed);
        window.record_read(latency_us, is_hit);
        self.engines[EngineKind::Kv as usize].record_read(latency_us, is_hit);
    }

    /// KV-only — see [`Self::record_read`]. JSON and rel use
    /// `record_engine_write` instead.
    pub fn record_write(&self, domain: &str, latency_us: u64) {
        self.system.total_writes.fetch_add(1, Ordering::Relaxed);
        self.domain_window(domain).record_write(latency_us);
        self.engines[EngineKind::Kv as usize].record_write(latency_us);
    }

    /// Records one read op on `kind`'s engine-aggregate window — the
    /// JSON/rel counterpart of KV's `record_read` mirroring. Engine windows
    /// don't track cache hit/miss.
    pub fn record_engine_read(&self, kind: EngineKind, latency_us: u64) {
        self.engines[kind as usize].record_read(latency_us, false);
    }

    /// Records one write op on `kind`'s engine-aggregate window.
    pub fn record_engine_write(&self, kind: EngineKind, latency_us: u64) {
        self.engines[kind as usize].record_write(latency_us);
    }

    /// Aggregates the three engine windows, indexed by `EngineKind`
    /// (`[kv, json, rel]`).
    pub fn engine_metrics(&self) -> [EngineWindowMetrics; 3] {
        std::array::from_fn(|i| self.engines[i].aggregate_engine(self.config.window_secs))
    }

    pub fn record_rate_limit_rejection(&self, domain: &str) {
        self.domain_window(domain).record_rate_limit_rejection();
    }

    /// Removes a domain's metrics window (called when domain is purged).
    pub fn remove_domain(&self, domain: &str) {
        self.domains.write().remove(domain);
        self.rel_catalog_objects.write().remove(domain);
    }

    pub fn get_domain_metrics(&self, domain: &str) -> Option<DomainWindowMetrics> {
        let domains = self.domains();
        domains.get(domain).map(|w| w.aggregate(domain, self.config.window_secs))
    }

    /// The counters and windows as of now.
    pub fn sample(&self) -> MetricsSample {
        let sys = &self.system;
        MetricsSample {
            total_reads: sys.total_reads.load(Ordering::Relaxed),
            total_writes: sys.total_writes.load(Ordering::Relaxed),
            shm_snapshot_publishes_total: sys.shm_snapshot_publishes_total.load(Ordering::Relaxed),
            shm_snapshot_publish_skips_total: sys.shm_snapshot_publish_skips_total.load(Ordering::Relaxed),
            shm_snapshot_consecutive_skips: sys.shm_snapshot_consecutive_skips.load(Ordering::Relaxed),
            shm_clients_kicked_total: sys.shm_clients_kicked_total.load(Ordering::Relaxed),
            domains: self.domains().iter().map(|(name, w)| (name.clone(), w.totals())).collect(),
            engines: std::array::from_fn(|i| self.engines[i].totals()),
            window_secs: self.config.window_secs,
        }
    }

    /// Advances all per-domain rolling windows by one second.
    ///
    /// Called by `MetricsTicker` once per tick interval. Ticks a copy of the
    /// window list, so the map is not locked for the whole round.
    pub fn tick_all(&self) {
        let windows: Vec<Arc<MetricsWindow>> = self.domains().values().cloned().collect();
        for w in &windows {
            w.tick();
        }
        for w in &self.engines {
            w.tick();
        }
    }

    /// Builds a `HeartbeatMetrics` snapshot from the live data of every data
    /// shard's engine, summed, whether each shard answered, by index, the
    /// resource state and the failing writes.
    pub fn heartbeat(
        &self,
        engines: &[EngineHeartbeatData],
        domain_count: usize,
        answered: &[bool],
        resources: ResourceReport,
        io: Option<IoReport>,
    ) -> HeartbeatMetrics {
        let healthy = answered.iter().all(|&ok| ok) && resources.state == "ok" && io.is_none();
        HeartbeatMetrics {
            status: if healthy { "ok" } else { "degraded" },
            uptime_secs: now_secs().saturating_sub(self.started_at),
            version: LURADB_VERSION,
            domain_count,
            estimated_memtable_keys: engines.iter().map(|e| e.estimated_memtable_keys).sum(),
            vlog_size_bytes: engines.iter().map(|e| e.vlog_size_bytes).sum(),
            l0_sstable_count: engines.iter().map(|e| e.l0_sstable_count).sum(),
            shards: (0u16..)
                .zip(answered)
                .map(|(id, &ok)| ShardHealth { id, status: if ok { "ok" } else { "timeout" } })
                .collect(),
            resources,
            io,
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
        let interval = std::time::Duration::from_millis(self.interval_ms);
        loop {
            compio::time::sleep(interval).await;
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

    // SQL frontend & DDL counters.
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

    // A publish counts and ends the skip run; each skip counts and extends it.
    #[test]
    fn test_shm_publish_counters_follow_the_skip_run() {
        let store = MetricsStore::new(MetricsConfig::default());
        let sys = &store.system;
        let counters = || {
            (
                sys.shm_snapshot_publishes_total.load(Ordering::Relaxed),
                sys.shm_snapshot_publish_skips_total.load(Ordering::Relaxed),
                sys.shm_snapshot_consecutive_skips.load(Ordering::Relaxed),
            )
        };

        store.record_shm_publish();
        assert_eq!(counters(), (1, 0, 0));
        store.record_shm_publish_skip();
        store.record_shm_publish_skip();
        assert_eq!(counters(), (1, 2, 2));
        store.record_shm_publish();
        assert_eq!(counters(), (2, 2, 0), "a publish resets the run, not the total");
        store.record_shm_publish_skip();
        assert_eq!(counters(), (2, 3, 1));

        store.record_shm_client_kicked();
        assert_eq!(sys.shm_clients_kicked_total.load(Ordering::Relaxed), 1);
    }

    // The samples of two stores add up field by field, a domain's windows by
    // its name; a percentile of the merged sample is the one of all writes
    // together, not the mean of the stores' percentiles.
    #[test]
    fn samples_of_several_stores_merge_field_by_field() {
        let (fast, slow) = (MetricsStore::new(MetricsConfig::default()), MetricsStore::new(MetricsConfig::default()));
        for _ in 0..3 {
            fast.record_write("a", 5);
        }
        slow.record_write("a", 5);
        slow.record_write("b", 2_000_000);
        slow.record_shm_publish();
        fast.tick_all();
        slow.tick_all();

        let mut sample = fast.sample();
        sample.merge(slow.sample());
        assert_eq!((sample.total_writes, sample.total_reads, sample.shm_snapshot_publishes_total), (5, 0, 1));
        let [kv, json, _] = sample.engine_metrics();
        assert_eq!((kv.write_ops, kv.write_latency_us_p50, kv.write_latency_us_p99), (5, 5, 2_000_000));
        assert_eq!((json.write_ops, kv.window_secs), (0, 60));
        let mut domains: Vec<_> = sample.domain_metrics().into_iter().map(|d| (d.domain, d.write_ops)).collect();
        domains.sort();
        assert_eq!(domains, [("a".to_string(), 4), ("b".to_string(), 1)]);
    }
}
