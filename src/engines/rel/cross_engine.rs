//! Cross-engine links (spec rel/012): the `CrossEngineResolver` bridge from
//! the rel engine to the same-named KV/JSON domains, the per-query read
//! `LinkMask`, and the background `RelCrossEngineSweeper` that physically nulls
//! orphaned link cells. This is the **only** rel module that imports `kv`/`json`
//! types — the rest of the engine stays link-agnostic (rel never appears in
//! `kv`/`json`, so no cycles).

use super::catalog::{CatalogEntry, ColumnDef, IndexMeta, TableSchema};
use super::domain::{RelDomain, RelDomainState};
use super::error::RelStoreError;
use super::keys;
use super::row::{decode_row, decode_value, encode_row};
use super::types::{encode_sortable, ColumnType, ScalarValue};
use super::RelEngine;
use crate::engines::json::{JsonEngine, JsonStoreError};
use crate::engines::lsm::domain::DomainRegistry;
use crate::engines::lsm::engine::BatchOp;
use crate::engines::lsm::reader::{GetResult, Snapshot};
use crate::metrics::MetricsStore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ── Resolver result types (spec §1) ──────────────────────────────────────────

/// State of the same-named target domain in the target engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDomain {
    Active,
    GoneOrDeleting,
    EngineDisabled,
}

impl TargetDomain {
    fn is_active(self) -> bool {
        matches!(self, TargetDomain::Active)
    }
}

/// Outcome of a KVREF point lookup (raw KV value = bytes). `NullValue` is a
/// key that exists in the explicit NULL state (spec kv/018).
pub enum KvResolution {
    DomainUnavailable,
    Absent,
    NullValue,
    Present(Vec<u8>),
}

/// Outcome of a JSONREF point lookup.
pub enum JsonResolution {
    DomainUnavailable,
    Absent,
    Present(serde_json::Value),
}

/// Bridge from the rel engine to the same-named KV/JSON domains. Both handles
/// are optional: an engine can be disabled by config, and `disabled ⇒ target
/// gone` is then structurally the same path.
pub struct CrossEngineResolver {
    kv: Option<Arc<DomainRegistry>>,
    json: Option<Arc<JsonEngine>>,
    metrics: Arc<MetricsStore>,
}

impl CrossEngineResolver {
    pub fn new(
        kv: Option<Arc<DomainRegistry>>,
        json: Option<Arc<JsonEngine>>,
        metrics: Arc<MetricsStore>,
    ) -> Arc<Self> {
        Arc::new(Self { kv, json, metrics })
    }

    /// Both handles absent — every link is masked and every non-NULL write
    /// 409s. Used by the rel-module tests that boot without target engines.
    pub fn disabled(metrics: Arc<MetricsStore>) -> Arc<Self> {
        Self::new(None, None, metrics)
    }

    /// Whether at least one target engine is wired (main.rs only spawns the
    /// sweeper then).
    pub fn has_target(&self) -> bool {
        self.kv.is_some() || self.json.is_some()
    }

    pub(crate) fn kv_enabled(&self) -> bool {
        self.kv.is_some()
    }

    pub(crate) fn json_enabled(&self) -> bool {
        self.json.is_some()
    }

    // ── Domain status (§1/§3) ────────────────────────────────────────────────

    /// KV `get_domain` is async (cache-first, cold-cache engine fallback);
    /// `None` (disabled) → `EngineDisabled`, missing/`Deleting` → `GoneOrDeleting`.
    pub async fn kv_domain_status(&self, name: &str) -> anyhow::Result<TargetDomain> {
        let Some(kv) = &self.kv else { return Ok(TargetDomain::EngineDisabled) };
        Ok(match kv.get_domain(name).await? {
            Some(_) => TargetDomain::Active,
            None => TargetDomain::GoneOrDeleting,
        })
    }

    /// JSON `get_domain` is sync/cache-only.
    pub fn json_domain_status(&self, name: &str) -> TargetDomain {
        let Some(json) = &self.json else { return TargetDomain::EngineDisabled };
        match json.get_domain(name) {
            Some(_) => TargetDomain::Active,
            None => TargetDomain::GoneOrDeleting,
        }
    }

    // ── Point lookups (§1) ───────────────────────────────────────────────────

    /// KVREF point lookup **directly on the KV LSM instance** (not via
    /// `DomainStore`): governance is already charged once at the rel REST edge
    /// against the rel domain (§1), so a second KV rate-limit hit is wrong.
    /// Authorization is likewise handled upstream, not here (spec rel/016): a
    /// caller lacking KV read access never reaches this function — the read
    /// path masks the link cell to `NULL` before expand ever resolves it, and
    /// the write path rejects the link before `validate_cross_engine_link`
    /// calls this.
    pub async fn kv_lookup(&self, domain: &str, key: &str) -> anyhow::Result<KvResolution> {
        let Some(kv) = &self.kv else { return Ok(KvResolution::DomainUnavailable) };
        let Some(dom) = kv.get_domain(domain).await? else {
            return Ok(KvResolution::DomainUnavailable);
        };
        let mut prefixed = dom.system_prefix.clone();
        prefixed.extend_from_slice(key.as_bytes());
        let engine = kv.engine();
        let snap = engine.snapshot();
        Ok(match engine.get_with_snapshot(&prefixed, snap.snapshot()).await? {
            GetResult::Present(bytes) => KvResolution::Present(bytes),
            GetResult::Null => KvResolution::NullValue,
            GetResult::Absent => KvResolution::Absent,
        })
    }

    /// JSONREF point lookup via the rate-limit-free `get_document` primitive.
    /// A key that is not a valid document key cannot reference a document →
    /// `Absent` (a clean 409/`exists:false`, never a 500). Authorization is
    /// handled upstream, same as `kv_lookup` above (spec rel/016).
    pub async fn json_lookup(&self, domain: &str, key: &str) -> anyhow::Result<JsonResolution> {
        let Some(json) = &self.json else { return Ok(JsonResolution::DomainUnavailable) };
        match json.get_document(domain, key).await {
            Ok(Some(doc)) => Ok(JsonResolution::Present(doc.content)),
            Ok(None) => Ok(JsonResolution::Absent),
            Err(JsonStoreError::DomainNotFound(_)) | Err(JsonStoreError::DomainDeleting(_)) => {
                Ok(JsonResolution::DomainUnavailable)
            }
            Err(JsonStoreError::InvalidKey(_)) => Ok(JsonResolution::Absent),
            Err(e) => Err(e.into()),
        }
    }

    // ── Metrics (§8) ─────────────────────────────────────────────────────────

    pub(crate) fn record_expand_lookup(&self, engine: &str) {
        self.metrics.record_rel_cross_engine_expand_lookup(engine);
    }

    pub(crate) fn record_write_validation(&self, engine: &str) {
        self.metrics.record_rel_cross_engine_write_validation(engine);
    }

    pub(crate) fn record_swept_cells(&self, n: u64) {
        self.metrics.record_rel_cross_engine_swept_cells(n);
    }
}

// ── Authorization (spec rel/016) ──────────────────────────────────────────────

/// Per-request cross-engine read rights, resolved by the REST handlers from
/// the caller's KV/JSON permissions and threaded down to `compute_link_mask`
/// (read path) and `validate_cross_engine_link` (write path). Plain bools —
/// no `auth`-crate type reaches this engine module.
#[derive(Debug, Clone, Copy)]
pub struct LinkAuth {
    pub kv_read: bool,
    pub json_read: bool,
}

impl LinkAuth {
    /// Unrestricted: admins, trusted UDS peers, `auth.enabled = false`, and
    /// every caller going through `RelEngine::execute` (internal/test path).
    pub fn full() -> Self {
        Self { kv_read: true, json_read: true }
    }
}

// ── Read masking (spec §3) ────────────────────────────────────────────────────

/// Per-query masking flags: a set flag means every column of that link type is
/// materialized as `NULL` (the same-named target domain is gone/`Deleting` or
/// its engine is disabled). Computed once per query, not per row.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LinkMask {
    pub(crate) kvref: bool,
    pub(crate) jsonref: bool,
}

impl LinkMask {
    /// Whether a column of type `ct` is masked.
    pub(crate) fn masks(&self, ct: ColumnType) -> bool {
        (self.kvref && matches!(ct, ColumnType::KvRef))
            || (self.jsonref && matches!(ct, ColumnType::JsonRef))
    }

    fn any(&self) -> bool {
        self.kvref || self.jsonref
    }

    /// Overwrites masked link cells (in `schema.columns` order) with `NULL`
    /// in place — the single materialization seam every read path funnels
    /// through (§3).
    pub(crate) fn apply(&self, values: &mut [ScalarValue], schema: &TableSchema) {
        if !self.any() {
            return;
        }
        for (v, c) in values.iter_mut().zip(&schema.columns) {
            if self.masks(c.col_type) {
                *v = ScalarValue::Null;
            }
        }
    }
}

impl RelEngine {
    /// Computes the query-wide `LinkMask` for the given schemas (all in the
    /// same rel domain): one KV status read (async) and one JSON status read
    /// (sync), each only when a column of that type is actually present. A
    /// missing `auth` right masks the column outright without even checking
    /// the target domain's status (spec rel/016) — indistinguishable from
    /// "target domain gone", so no new read-side oracle is introduced.
    pub(crate) async fn compute_link_mask(
        &self,
        domain: &str,
        schemas: &[&TableSchema],
        auth: LinkAuth,
    ) -> Result<LinkMask, RelStoreError> {
        let has = |ct: ColumnType| {
            schemas
                .iter()
                .any(|s| s.columns.iter().any(|c| c.col_type == ct))
        };
        let kvref = has(ColumnType::KvRef)
            && (!auth.kv_read || !self.cross_engine.kv_domain_status(domain).await?.is_active());
        let jsonref = has(ColumnType::JsonRef)
            && (!auth.json_read || !self.cross_engine.json_domain_status(domain).is_active());
        Ok(LinkMask { kvref, jsonref })
    }

    /// All KVREF/JSONREF columns of a domain's tables (sweeper candidate set, §5).
    pub(crate) fn link_columns(
        &self,
        domain: &str,
    ) -> Result<Vec<(TableSchema, ColumnDef)>, RelStoreError> {
        let mut out = Vec::new();
        for entry in self.catalog.list(&self.domains, domain)? {
            if let CatalogEntry::Table(t) = entry {
                for c in &t.columns {
                    if matches!(c.col_type, ColumnType::KvRef | ColumnType::JsonRef) {
                        out.push((t.clone(), c.clone()));
                    }
                }
            }
        }
        Ok(out)
    }
}

// ── Base64 (spec §4; no crate — hand-written standard-alphabet encoder) ───────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

// ── Physical sweep (spec §5) ──────────────────────────────────────────────────

/// Background task that physically nulls link cells whose same-named target
/// domain vanished in a foreign engine — the durable half of "nulled stays
/// nulled". Distinct from the rel/013 purger (which tombstones a rel domain's
/// own orphaned prefix ranges); this one rewrites cells in *live* tables.
pub struct RelCrossEngineSweeper {
    engine: Arc<RelEngine>,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
    interval: Duration,
}

impl RelCrossEngineSweeper {
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
            interval: Duration::from_secs(interval_secs.max(1)),
        }
    }

    pub async fn run(self: Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            if let Err(e) = self.sweep_tick().await {
                tracing::warn!("[RelCrossEngineSweeper] tick error: {e}");
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    pub async fn sweep_tick(&self) -> anyhow::Result<()> {
        for dom in self.engine.domains.list_domains() {
            // rel/013 made `list_domains` surface `Deleting` domains too; the
            // rel/013 purger owns those (it tombstones every row), so the
            // cross-engine sweeper must skip them — rewriting a cell here could
            // resurrect a row the purger already reaped.
            if dom.state != RelDomainState::Active {
                continue;
            }
            self.sweep_domain(&dom).await?;
        }
        Ok(())
    }

    async fn sweep_domain(&self, dom: &RelDomain) -> anyhow::Result<()> {
        let kv_gone = !self.engine.cross_engine.kv_domain_status(&dom.name).await?.is_active();
        let json_gone = !self.engine.cross_engine.json_domain_status(&dom.name).is_active();
        if !kv_gone && !json_gone {
            return Ok(());
        }
        let columns = match self.engine.link_columns(&dom.name) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("[RelCrossEngineSweeper] {}: {e}", dom.name);
                return Ok(());
            }
        };
        for (table, col) in columns {
            if !link_target_gone(col.col_type, kv_gone, json_gone) {
                continue;
            }
            if let Err(e) = self.sweep_column(dom, &table, &col).await {
                tracing::warn!("[RelCrossEngineSweeper] {}.{}: {e}", table.name, col.name);
            }
        }
        Ok(())
    }

    /// Nulls up to `batch_size` unchanged non-NULL cells of one link column,
    /// under the table write lock (same serialization as the DML path).
    async fn sweep_column(
        &self,
        dom: &RelDomain,
        table: &TableSchema,
        col: &ColumnDef,
    ) -> anyhow::Result<()> {
        let prefix = &dom.system_prefix;
        let engine = &self.engine.engine;
        let snapshot = engine.snapshot();
        let snap = snapshot.snapshot();
        let ix = table.indexes.iter().find(|ix| ix.column == col.name);

        let pk_encs = self.candidate_pk_encs(prefix, table, col, ix, snap).await?;

        let lock = self.engine.table_locks.get(prefix, table.table_id);
        let _guard = lock.lock().await;
        let mut swept = 0u64;
        for pk_enc in pk_encs {
            if swept >= self.batch_size as u64 {
                break;
            }
            let row_key = keys::row_key(prefix, table.table_id, &pk_enc);
            let Some((now_bytes, v_now)) = self.unchanged_link_value(&row_key, col, snap).await? else {
                continue;
            };
            let ops = null_cell_ops(table, col, ix, prefix, &pk_enc, row_key, &now_bytes, &v_now);
            // rel/013 §3 guard: commit under the engine write guard and re-check
            // the rel domain is still active. If the rel/013 purger is
            // finalizing this domain, stop — otherwise this row rewrite could
            // land after the domain was emptied and orphan a `ROW:` key.
            {
                let _wg = self.engine.write_guard.lock().await;
                if self.engine.domains.require_active(&dom.name).is_err() {
                    break;
                }
                engine.write_batch(ops).await?;
            }
            swept += 1;
        }
        if swept > 0 {
            self.engine.cross_engine.record_swept_cells(swept);
        }
        Ok(())
    }

    /// Candidate pk_encs: index scan lists exactly the non-NULL cells (NULL
    /// is never indexed), else a table scan decodes and checks the cell.
    async fn candidate_pk_encs(
        &self,
        prefix: &[u8],
        table: &TableSchema,
        col: &ColumnDef,
        ix: Option<&IndexMeta>,
        snap: &Snapshot,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let engine = &self.engine.engine;
        let mut pk_encs: Vec<Vec<u8>> = Vec::new();
        if let Some(ix) = ix {
            let scan_prefix = keys::index_value_prefix(prefix, ix.index_id, &[]);
            for k in engine.scan_keys(&scan_prefix).await? {
                if let Some(pk_enc) = split_text_val_pk(&k[scan_prefix.len()..]) {
                    pk_encs.push(pk_enc.to_vec());
                }
            }
        } else {
            let row_prefix = keys::row_table_prefix(prefix, table.table_id);
            for rk in engine.scan_keys(&row_prefix).await? {
                if let Some(bytes) = engine.get_with_snapshot(&rk, snap).await?.into_option() {
                    if !matches!(decode_value(&bytes, col), ScalarValue::Null) {
                        pk_encs.push(rk[row_prefix.len()..].to_vec());
                    }
                }
            }
        }
        Ok(pk_encs)
    }

    async fn unchanged_link_value(
        &self,
        row_key: &[u8],
        col: &ColumnDef,
        snap: &Snapshot,
    ) -> anyhow::Result<Option<(Vec<u8>, ScalarValue)>> {
        let engine = &self.engine.engine;
        // v_snap: state at tick start.
        let Some(snap_bytes) = engine.get_with_snapshot(row_key, snap).await?.into_option() else {
            return Ok(None);
        };
        let v_snap = decode_value(&snap_bytes, col);
        if matches!(v_snap, ScalarValue::Null) {
            return Ok(None);
        }
        // v_now: latest committed. Only null it if untouched since the snapshot
        // (a fresh valid link against a recreated domain must survive, §5).
        let now_guard = engine.snapshot();
        let Some(now_bytes) = engine.get_with_snapshot(row_key, now_guard.snapshot()).await?.into_option() else {
            return Ok(None);
        };
        let v_now = decode_value(&now_bytes, col);
        if matches!(v_now, ScalarValue::Null) || v_now != v_snap {
            return Ok(None);
        }
        Ok(Some((now_bytes, v_now)))
    }
}

fn link_target_gone(col_type: ColumnType, kv_gone: bool, json_gone: bool) -> bool {
    match col_type {
        ColumnType::KvRef => kv_gone,
        ColumnType::JsonRef => json_gone,
        _ => false,
    }
}

fn null_cell_ops(
    table: &TableSchema,
    col: &ColumnDef,
    ix: Option<&IndexMeta>,
    prefix: &[u8],
    pk_enc: &[u8],
    row_key: Vec<u8>,
    now_bytes: &[u8],
    v_now: &ScalarValue,
) -> Vec<BatchOp> {
    let mut values: HashMap<u16, ScalarValue> = table
        .columns
        .iter()
        .zip(decode_row(now_bytes, table))
        .map(|(c, v)| (c.col_id, v))
        .collect();
    values.insert(col.col_id, ScalarValue::Null);
    let new_row = encode_row(table, &values);

    let mut ops = Vec::new();
    if let Some(ix) = ix {
        if let Some(old_enc) = encode_sortable(v_now) {
            ops.push(BatchOp::Delete {
                key: keys::index_key(prefix, ix.index_id, &old_enc, pk_enc),
            });
        }
    }
    ops.push(BatchOp::Put { key: row_key, value: new_row });
    ops
}

/// Splits `val_enc ++ pk_enc` (after an index's `IDX:…:{index_id}:` prefix) at
/// the text value's `0x00 0x00` terminator, honoring `0x00 0xFF` escapes
/// (rel/003 text encoding); returns `pk_enc`. KVREF/JSONREF are physically TEXT.
fn split_text_val_pk(rest: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < rest.len() {
        if rest[i] == 0x00 {
            match rest[i + 1] {
                0x00 => return Some(&rest[i + 2..]),
                0xFF => i += 2,
                _ => return None,
            }
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{JsonStoreConfig, RelStoreConfig};
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::DomainConfig;
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::engines::rel::{ExecOutcome, ExpandedBlock, SqlOutcome};
    use crate::metrics::MetricsConfig;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use serde_json::{json, Value};
    use std::path::Path;

    // ── Harness: three real, separate LSM instances (kv/json/rel) ────────────

    async fn make_lsm(dir: &Path, tag: &str) -> Arc<LsmStorageEngine> {
        let wal = Arc::new(WriteAheadLog::new(&dir.join(format!("{tag}.wal"))).await.unwrap());
        let vlog = Arc::new(VLog::new(&dir.join(format!("{tag}.vlog"))).await.unwrap());
        let ss = dir.join(format!("{tag}_ss"));
        let fm = Arc::new(FileManager::new(&ss).await.unwrap());
        let mm = Arc::new(ManifestManager::new(&ss));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal,
                dir.join(format!("{tag}.wal")),
                vlog,
                dir.join(format!("{tag}.vlog")),
                fm,
                mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        engine.start_background_tasks();
        engine
    }

    async fn make_kv(dir: &Path, metrics: Arc<MetricsStore>) -> Arc<DomainRegistry> {
        let engine = make_lsm(dir, "kv").await;
        Arc::new(DomainRegistry::recover(engine, DomainConfig::default(), metrics).await.unwrap())
    }

    async fn make_json(dir: &Path, metrics: Arc<MetricsStore>) -> Arc<JsonEngine> {
        let cfg = JsonStoreConfig {
            wal_path: dir.join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.join("json_ss").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        };
        JsonEngine::bootstrap(&cfg, metrics).await.unwrap()
    }

    async fn boot_rel(
        dir: &Path,
        over: RelStoreConfig,
        metrics: Arc<MetricsStore>,
        resolver: Arc<CrossEngineResolver>,
    ) -> Arc<RelEngine> {
        let cfg = RelStoreConfig {
            wal_path: dir.join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.join("rel_ss").to_string_lossy().into_owned(),
            ..over
        };
        RelEngine::bootstrap(&cfg, metrics, resolver).await.unwrap()
    }

    struct Env {
        rel: Arc<RelEngine>,
        kv: Arc<DomainRegistry>,
        json: Arc<JsonEngine>,
        metrics: Arc<MetricsStore>,
        _dir: tempfile::TempDir,
    }

    /// KV and JSON both wired.
    async fn env() -> Env {
        env_with(RelStoreConfig::default(), true, true).await
    }

    async fn env_with(over: RelStoreConfig, kv_on: bool, json_on: bool) -> Env {
        let dir = tempfile::TempDir::new().unwrap();
        let metrics = MetricsStore::new(MetricsConfig::default());
        let kv = make_kv(dir.path(), Arc::clone(&metrics)).await;
        let json = make_json(dir.path(), Arc::clone(&metrics)).await;
        let resolver = CrossEngineResolver::new(
            kv_on.then(|| Arc::clone(&kv)),
            json_on.then(|| Arc::clone(&json)),
            Arc::clone(&metrics),
        );
        let rel = boot_rel(dir.path(), over, Arc::clone(&metrics), resolver).await;
        Env { rel, kv, json, metrics, _dir: dir }
    }

    async fn kv_put(kv: &DomainRegistry, domain: &str, key: &[u8], val: &[u8]) {
        kv.store(domain).await.unwrap().put(key, val).await.unwrap();
    }

    async fn ok(rel: &RelEngine, domain: &str, sql: &str) {
        rel.execute(domain, sql, &[]).await.unwrap();
    }

    async fn exec_err(rel: &RelEngine, domain: &str, sql: &str) -> RelStoreError {
        rel.execute(domain, sql, &[]).await.unwrap_err()
    }

    async fn rows(rel: &RelEngine, domain: &str, sql: &str) -> Vec<Vec<ScalarValue>> {
        match rel.execute(domain, sql, &[]).await.unwrap() {
            ExecOutcome::Select(r) => r.rows,
            o => panic!("expected SELECT, got {o:?}"),
        }
    }

    async fn count(rel: &RelEngine, domain: &str, table: &str) -> i64 {
        match &rows(rel, domain, &format!("SELECT COUNT(*) FROM {table}")).await[0][0] {
            ScalarValue::Integer(n) => *n,
            v => panic!("not an int: {v:?}"),
        }
    }

    async fn expand_block(rel: &RelEngine, domain: &str, sql: &str, ex: &[&str]) -> ExpandedBlock {
        let ex: Vec<String> = ex.iter().map(|s| s.to_string()).collect();
        match rel.execute_sql(domain, sql, &[], &ex, LinkAuth::full()).await.unwrap() {
            SqlOutcome::Select { expanded, .. } => expanded.unwrap_or_default(),
            o => panic!("expected SELECT, got {o:?}"),
        }
    }

    fn mk_body(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn colv<'a>(exp: &'a ExpandedBlock, name: &str) -> &'a [Value] {
        exp.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
            .unwrap_or_else(|| panic!("expanded column '{name}' not found in {exp:?}"))
    }

    fn table_of(rel: &RelEngine, domain: &str, name: &str) -> (Vec<u8>, TableSchema) {
        let prefix = rel.get_domain(domain).unwrap().system_prefix;
        match rel.get_object(domain, name).unwrap() {
            CatalogEntry::Table(t) => (prefix, t),
            _ => panic!("not a table"),
        }
    }

    async fn raw_cell(rel: &RelEngine, domain: &str, table: &str, pk: i64, col: &str) -> ScalarValue {
        let (prefix, schema) = table_of(rel, domain, table);
        let pk_enc = encode_sortable(&ScalarValue::Integer(pk)).unwrap();
        let row_key = keys::row_key(&prefix, schema.table_id, &pk_enc);
        let snap = rel.engine().snapshot();
        let bytes = rel.engine().get_with_snapshot(&row_key, snap.snapshot()).await.unwrap().into_option().unwrap();
        let c = schema.columns.iter().find(|c| c.name == col).unwrap();
        decode_value(&bytes, c)
    }

    async fn index_entries(rel: &RelEngine, domain: &str, table: &str, index: &str) -> usize {
        let (prefix, schema) = table_of(rel, domain, table);
        let ix = schema.indexes.iter().find(|i| i.name == index).unwrap();
        let scan = keys::index_value_prefix(&prefix, ix.index_id, &[]);
        rel.engine().scan_keys(&scan).await.unwrap().len()
    }

    async fn sweep_once(rel: &Arc<RelEngine>, batch: usize) {
        RelCrossEngineSweeper::new(Arc::clone(rel), Arc::new(AtomicBool::new(false)), batch, 10)
            .sweep_tick()
            .await
            .unwrap();
    }

    // ── Base64 (§4) ──────────────────────────────────────────────────────────

    #[test]
    fn test_base64_encoder() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_encode(&[0xFF, 0xFE, 0xFD]), "//79");
    }

    // ── 1. Write validation KVREF ok ─────────────────────────────────────────

    #[tokio::test]
    async fn test_write_kvref_ok() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"hello").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        assert_eq!(
            rows(&e.rel, "default", "SELECT payload FROM t WHERE id = 1").await[0][0],
            ScalarValue::Text("k".into())
        );
    }

    // ── 2. Write validation KVREF missing + multi-row atomicity ──────────────

    #[tokio::test]
    async fn test_write_kvref_missing_and_atomic() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;

        let err = exec_err(&e.rel, "default", "INSERT INTO t VALUES (1, 'missing')").await;
        assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");

        // One violating row leaves none of the statement's rows.
        let err = exec_err(&e.rel, "default", "INSERT INTO t VALUES (1, 'k'), (2, 'missing')").await;
        assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");
        assert_eq!(count(&e.rel, "default", "t").await, 0, "atomic: no row survives");
    }

    // ── 3. Write validation JSONREF ok/missing ───────────────────────────────

    #[tokio::test]
    async fn test_write_jsonref_ok_and_missing() {
        let e = env().await;
        e.json.put_document("default", "d1", json!({"a": 1})).await.unwrap();
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, doc JSONREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'd1')").await;
        let err = exec_err(&e.rel, "default", "INSERT INTO t VALUES (2, 'ghost')").await;
        assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");
    }

    // ── 4. Target domain gone/deleting → 409 unavailable ─────────────────────

    #[tokio::test]
    async fn test_write_target_domain_gone() {
        let e = env().await;
        // rel domain "x" exists, but KV domain "x" never did.
        e.rel.create_domain("x").await.unwrap();
        ok(&e.rel, "x", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        let err = exec_err(&e.rel, "x", "INSERT INTO t VALUES (1, 'k')").await;
        assert!(matches!(err, RelStoreError::CrossEngineTargetUnavailable { .. }), "missing domain: {err}");

        // Deleting target domain: create then delete KV "y".
        e.rel.create_domain("y").await.unwrap();
        e.kv.create_domain("y").await.unwrap();
        e.kv.delete_domain("y").await.unwrap();
        ok(&e.rel, "y", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        let err = exec_err(&e.rel, "y", "INSERT INTO t VALUES (1, 'k')").await;
        assert!(matches!(err, RelStoreError::CrossEngineTargetUnavailable { .. }), "deleting domain: {err}");
    }

    // ── 5. Engine disabled: DDL 409, and value 409 when domain absent ────────

    #[tokio::test]
    async fn test_engine_disabled_ddl_and_value() {
        // JSON disabled: a JSONREF column can't even be declared.
        let e = env_with(RelStoreConfig::default(), true, false).await;
        let err = exec_err(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, doc JSONREF)").await;
        assert!(matches!(&err, RelStoreError::CrossEngineTargetUnavailable { engine, domain: None } if engine == "json"), "got: {err}");

        // JSON enabled but the same-named domain doesn't exist yet: DDL ok
        // (engine enabled suffices), only the first non-NULL value fails.
        let e = env().await;
        e.rel.create_domain("z").await.unwrap(); // no JSON domain "z"
        ok(&e.rel, "z", "CREATE TABLE t (id INTEGER PRIMARY KEY, doc JSONREF)").await;
        let err = exec_err(&e.rel, "z", "INSERT INTO t VALUES (1, 'd1')").await;
        assert!(matches!(err, RelStoreError::CrossEngineTargetUnavailable { .. }), "value: {err}");
    }

    // ── 6. NULL link unchecked (no cross-engine read) ───────────────────────

    #[tokio::test]
    async fn test_null_link_unchecked() {
        let e = env().await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        let before = e.metrics.system.rel_cross_engine_write_validations_kv_total.load(Ordering::Relaxed);
        // No KV key 'k' exists; a NULL link inserts fine and does no lookup.
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, NULL)").await;
        assert_eq!(count(&e.rel, "default", "t").await, 1);
        assert_eq!(
            e.metrics.system.rel_cross_engine_write_validations_kv_total.load(Ordering::Relaxed),
            before,
            "NULL link performs no cross-engine validation"
        );
    }

    // ── 7. UPDATE re-validates only changed link columns ─────────────────────

    #[tokio::test]
    async fn test_update_only_changed_links() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k1", b"v1").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 0, 'k1')").await;

        // Make the link hang (delete the KV key), then UPDATE a non-link column
        // — the unchanged (now hanging) link cell is not re-validated.
        e.kv.store("default").await.unwrap().delete(b"k1").await.unwrap();
        ok(&e.rel, "default", "UPDATE t SET tag = 9 WHERE id = 1").await;

        // SET the link itself to a missing key → 409.
        let err = exec_err(&e.rel, "default", "UPDATE t SET payload = 'missing' WHERE id = 1").await;
        assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");
    }

    // ── 8. Expand KVREF utf8 (incl. empty) ───────────────────────────────────

    #[tokio::test]
    async fn test_expand_kvref_utf8_and_empty() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k1", b"hello").await;
        kv_put(&e.kv, "default", b"k2", b"").await; // empty value *exists*
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k1'), (2, 'k2')").await;

        let exp = expand_block(&e.rel, "default", "SELECT * FROM t ORDER BY id", &["payload"]).await;
        let v = colv(&exp, "payload");
        assert_eq!(v[0], json!({ "exists": true, "value": "hello", "encoding": "utf8" }));
        assert_eq!(v[1], json!({ "exists": true, "value": "", "encoding": "utf8" }), "empty value exists");
    }

    // ── 9. Expand KVREF base64 (non-UTF-8 bytes) ─────────────────────────────

    #[tokio::test]
    async fn test_expand_kvref_base64() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", &[0xFF, 0xFE, 0xFD]).await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
        assert_eq!(colv(&exp, "payload")[0], json!({ "exists": true, "value": "//79", "encoding": "base64" }));
    }

    // ── 10. Expand KVREF hanging / domain gone → exists:false ────────────────

    #[tokio::test]
    async fn test_expand_kvref_hanging_and_domain_gone() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        // Delete the key after writing → hanging link.
        e.kv.store("default").await.unwrap().delete(b"k").await.unwrap();
        let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
        assert_eq!(colv(&exp, "payload")[0], json!({ "exists": false, "value": null }));

        // Domain gone: use a named domain so masking doesn't also fire on "default".
        let e = env().await;
        e.rel.create_domain("g").await.unwrap();
        e.kv.create_domain("g").await.unwrap();
        kv_put(&e.kv, "g", b"k", b"v").await;
        ok(&e.rel, "g", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "g", "INSERT INTO t VALUES (1, 'k')").await;
        e.kv.delete_domain("g").await.unwrap();
        // Masked cell → null entry (rel-NULL), distinct from a resolved exists:false.
        let exp = expand_block(&e.rel, "g", "SELECT * FROM t", &["payload"]).await;
        assert_eq!(colv(&exp, "payload")[0], Value::Null, "masked column expands to null");
    }

    // ── 10b. Expand KVREF of a nulled key (spec kv/018) ──────────────────────

    #[tokio::test]
    async fn test_expand_kvref_null_value() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        // Null the KV key after linking: the key still exists, valueless.
        e.kv.store("default").await.unwrap().set_null(b"k").await.unwrap();
        let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
        assert_eq!(colv(&exp, "payload")[0], json!({ "exists": true, "value": null }));
    }

    // ── 11. Expand JSONREF ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_expand_jsonref() {
        let e = env().await;
        e.json.put_document("default", "d1", json!({"name": "ada"})).await.unwrap();
        e.json.put_document("default", "d2", json!({"gone": true})).await.unwrap();
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, doc JSONREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'd1'), (2, 'd2')").await;
        e.json.delete_document("default", "d2").await.unwrap(); // hanging

        let exp = expand_block(&e.rel, "default", "SELECT * FROM t ORDER BY id", &["doc"]).await;
        let v = colv(&exp, "doc");
        assert_eq!(v[0], json!({ "exists": true, "document": {"name": "ada"} }));
        assert_eq!(v[1], json!({ "exists": false, "document": null }));
    }

    // ── 12. rel-NULL vs. target-gone (three-states) ──────────────────────────

    #[tokio::test]
    async fn test_expand_rel_null_vs_gone() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, NULL), (2, 'k')").await;
        e.kv.store("default").await.unwrap().delete(b"k").await.unwrap(); // row 2 now hangs
        let exp = expand_block(&e.rel, "default", "SELECT * FROM t ORDER BY id", &["payload"]).await;
        let v = colv(&exp, "payload");
        assert_eq!(v[0], Value::Null, "rel-NULL → null entry (no lookup)");
        assert_eq!(v[1], json!({ "exists": false, "value": null }), "gone target → exists:false");
    }

    // ── 13. Wildcard resolves REFERENCES *and* KVREF/JSONREF ─────────────────

    #[tokio::test]
    async fn test_expand_wildcard_references_and_links() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        e.json.put_document("default", "d1", json!({"ok": 1})).await.unwrap();
        ok(&e.rel, "default", "CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT)").await;
        ok(&e.rel, "default", "INSERT INTO parent VALUES (7, 'p')").await;
        ok(
            &e.rel,
            "default",
            "CREATE TABLE t (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent, payload KVREF, doc JSONREF)",
        )
        .await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 7, 'k', 'd1')").await;

        let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["*"]).await;
        assert_eq!(colv(&exp, "pid")[0], json!({"id": 7, "name": "p"}));
        assert_eq!(colv(&exp, "payload")[0], json!({ "exists": true, "value": "v", "encoding": "utf8" }));
        assert_eq!(colv(&exp, "doc")[0], json!({ "exists": true, "document": {"ok": 1} }));
    }

    // ── 14. Explicit link expand resolves (no more 400) ──────────────────────

    #[tokio::test]
    async fn test_expand_explicit_link_resolves() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        let out = e
            .rel
            .execute_sql("default", "SELECT * FROM t", &[], &["payload".to_string()], LinkAuth::full())
            .await
            .unwrap();
        match out {
            SqlOutcome::Select { expanded, .. } => {
                assert_eq!(colv(&expanded.unwrap(), "payload")[0], json!({ "exists": true, "value": "v", "encoding": "utf8" }));
            }
            o => panic!("got {o:?}"),
        }
    }

    // ── 15. max_join_depth counts link expand columns ────────────────────────

    #[tokio::test]
    async fn test_expand_max_join_depth() {
        let e = env_with(RelStoreConfig { max_join_depth: 0, ..RelStoreConfig::default() }, true, true).await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        let out = e
            .rel
            .execute_sql("default", "SELECT * FROM t", &[], &["payload".to_string()], LinkAuth::full())
            .await;
        assert!(matches!(out, Err(RelStoreError::JoinDepthExceeded { .. })), "got: {out:?}");
    }

    // ── 16. Large KV value flows into the expand block (413 backstop input) ──

    #[tokio::test]
    async fn test_expand_large_kv_value_in_block() {
        let e = env().await;
        let big = vec![b'a'; 4096];
        kv_put(&e.kv, "default", b"k", &big).await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
        let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
        // The full KV value is carried into the response the handler's 413 cap
        // measures (the cap itself is the unchanged rel/009 handler check).
        assert_eq!(colv(&exp, "payload")[0]["value"].as_str().unwrap().len(), 4096);
    }

    // ── 17. Read masking (KV gone) leaves JSONREF untouched ──────────────────

    #[tokio::test]
    async fn test_read_masking_kv_only() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        e.json.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k", b"v").await;
        e.json.put_document("d", "j1", json!({"x": 1})).await.unwrap();
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF, doc JSONREF)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k', 'j1')").await;

        e.kv.delete_domain("d").await.unwrap(); // only KV gone
        let r = rows(&e.rel, "d", "SELECT payload, doc FROM t WHERE id = 1").await;
        assert_eq!(r[0][0], ScalarValue::Null, "KVREF masked");
        assert_eq!(r[0][1], ScalarValue::Text("j1".into()), "JSONREF untouched");
    }

    // ── 18. Masking + WHERE + index-path guard ───────────────────────────────

    #[tokio::test]
    async fn test_masking_where_and_index_guard() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k1", b"v").await;
        kv_put(&e.kv, "d", b"k2", b"v").await;
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "d", "CREATE INDEX ix ON t (payload)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k1'), (2, 'k2')").await;

        e.kv.delete_domain("d").await.unwrap(); // mask

        // IS NULL matches all masked rows; an index-driven equality on the
        // masked column matches none (planner must not take the index path).
        assert_eq!(rows(&e.rel, "d", "SELECT id FROM t WHERE payload IS NULL").await.len(), 2);
        assert_eq!(rows(&e.rel, "d", "SELECT id FROM t WHERE payload = 'k1'").await.len(), 0);
        assert_eq!(rows(&e.rel, "d", "SELECT id FROM t WHERE payload IS NOT NULL").await.len(), 0);
    }

    // ── 19. Sweep physically nulls; recreate does not restore ────────────────

    #[tokio::test]
    async fn test_sweep_physically_nulls() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k", b"v").await;
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "d", "CREATE INDEX ix ON t (payload)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k')").await;
        assert_eq!(index_entries(&e.rel, "d", "t", "ix").await, 1);

        e.kv.delete_domain("d").await.unwrap();
        sweep_once(&e.rel, 100).await;

        assert_eq!(raw_cell(&e.rel, "d", "t", 1, "payload").await, ScalarValue::Null, "cell physically NULL");
        assert_eq!(index_entries(&e.rel, "d", "t", "ix").await, 0, "index entry removed");

        // Recreate the KV domain: the physically-nulled cell stays NULL.
        e.kv.finalize_domain_deletion("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        assert_eq!(raw_cell(&e.rel, "d", "t", 1, "payload").await, ScalarValue::Null, "nulled stays nulled");
    }

    // ── 20. Sweep is optimistic: recreate + fresh valid link survives ────────

    #[tokio::test]
    async fn test_sweep_optimistic_recreate() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k1", b"v").await;
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k1')").await;

        // Delete, finalize, recreate, seed a new key, and write a fresh link.
        e.kv.delete_domain("d").await.unwrap();
        e.kv.finalize_domain_deletion("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k2", b"v").await;
        ok(&e.rel, "d", "UPDATE t SET payload = 'k2' WHERE id = 1").await;

        // Domain is Active again → the sweep leaves the new cell untouched.
        sweep_once(&e.rel, 100).await;
        assert_eq!(raw_cell(&e.rel, "d", "t", 1, "payload").await, ScalarValue::Text("k2".into()));
    }

    // ── 21. Sweep via index vs. table scan; co-residents untouched ───────────

    #[tokio::test]
    async fn test_sweep_index_vs_table_scan() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k", b"v").await;
        // indexed KVREF + a co-resident non-link column, plus an all-TEXT table.
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF, note TEXT)").await;
        ok(&e.rel, "d", "CREATE INDEX ix ON t (payload)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k', 'keep')").await;
        ok(&e.rel, "d", "CREATE TABLE plain (id INTEGER PRIMARY KEY, s TEXT)").await;
        ok(&e.rel, "d", "INSERT INTO plain VALUES (1, 'untouched')").await;

        e.kv.delete_domain("d").await.unwrap();
        sweep_once(&e.rel, 100).await;

        assert_eq!(raw_cell(&e.rel, "d", "t", 1, "payload").await, ScalarValue::Null);
        assert_eq!(raw_cell(&e.rel, "d", "t", 1, "note").await, ScalarValue::Text("keep".into()), "co-resident column untouched");
        assert_eq!(index_entries(&e.rel, "d", "t", "ix").await, 0);
        assert_eq!(raw_cell(&e.rel, "d", "plain", 1, "s").await, ScalarValue::Text("untouched".into()), "other table untouched");
    }

    // ── 22. Sweep convergence, budget, and metric ────────────────────────────

    #[tokio::test]
    async fn test_sweep_convergence_and_budget() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        for i in 0..3 {
            kv_put(&e.kv, "d", format!("k{i}").as_bytes(), b"v").await;
        }
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k0'), (2, 'k1'), (3, 'k2')").await;

        e.kv.delete_domain("d").await.unwrap();

        // batch_size = 1 → one cell per tick; three ticks converge.
        let before = e.metrics.system.rel_cross_engine_swept_cells_total.load(Ordering::Relaxed);
        for _ in 0..3 {
            sweep_once(&e.rel, 1).await;
        }
        let swept = e.metrics.system.rel_cross_engine_swept_cells_total.load(Ordering::Relaxed) - before;
        assert_eq!(swept, 3, "three cells nulled across three ticks");
        assert_eq!(count_nonnull_payload(&e.rel, "d").await, 0, "all cells NULL");

        // Steady-state: a further tick is a no-op.
        let before = e.metrics.system.rel_cross_engine_swept_cells_total.load(Ordering::Relaxed);
        sweep_once(&e.rel, 100).await;
        assert_eq!(e.metrics.system.rel_cross_engine_swept_cells_total.load(Ordering::Relaxed), before, "no-op steady state");
    }

    async fn count_nonnull_payload(rel: &RelEngine, domain: &str) -> usize {
        let (prefix, schema) = table_of(rel, domain, "t");
        let col = schema.columns.iter().find(|c| c.name == "payload").unwrap();
        let mut n = 0;
        for rk in rel.engine().scan_keys(&keys::row_table_prefix(&prefix, schema.table_id)).await.unwrap() {
            let snap = rel.engine().snapshot();
            if let Some(bytes) = rel.engine().get_with_snapshot(&rk, snap.snapshot()).await.unwrap().into_option() {
                if !matches!(decode_value(&bytes, col), ScalarValue::Null) {
                    n += 1;
                }
            }
        }
        n
    }

    // ── 23. Expand-lookup metrics per engine (not on null/masked) ────────────

    #[tokio::test]
    async fn test_metrics_expand_lookups() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        e.json.put_document("default", "d1", json!({})).await.unwrap();
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF, doc JSONREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k', 'd1'), (2, NULL, NULL)").await;

        let kv0 = e.metrics.system.rel_cross_engine_expand_lookups_kv_total.load(Ordering::Relaxed);
        let js0 = e.metrics.system.rel_cross_engine_expand_lookups_json_total.load(Ordering::Relaxed);
        expand_block(&e.rel, "default", "SELECT * FROM t ORDER BY id", &["*"]).await;
        let kv = e.metrics.system.rel_cross_engine_expand_lookups_kv_total.load(Ordering::Relaxed) - kv0;
        let js = e.metrics.system.rel_cross_engine_expand_lookups_json_total.load(Ordering::Relaxed) - js0;
        assert_eq!(kv, 1, "one KV lookup (row 2 is NULL → no lookup)");
        assert_eq!(js, 1, "one JSON lookup");
    }

    // ── 24. Disabled-handle smoke: pre-existing links masked, writes 409 ─────
    //
    // A link *column* can only be created while its engine is enabled (§2), so
    // the disabled case is a restart: build the schema+rows with engines on,
    // then reboot the same rel data with a fully-disabled resolver.
    #[tokio::test]
    async fn test_disabled_smoke() {
        let dir = tempfile::TempDir::new().unwrap();
        let metrics = MetricsStore::new(MetricsConfig::default());
        let kv = make_kv(dir.path(), Arc::clone(&metrics)).await;
        let json = make_json(dir.path(), Arc::clone(&metrics)).await;

        {
            let resolver =
                CrossEngineResolver::new(Some(Arc::clone(&kv)), Some(Arc::clone(&json)), Arc::clone(&metrics));
            let rel = boot_rel(dir.path(), RelStoreConfig::default(), Arc::clone(&metrics), resolver).await;
            kv_put(&kv, "default", b"k", b"v").await;
            json.put_document("default", "d1", json!({})).await.unwrap();
            ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF, doc JSONREF)").await;
            ok(&rel, "default", "INSERT INTO t VALUES (1, 'k', 'd1'), (2, NULL, NULL)").await;
            rel.shutdown().await;
        }

        // Reboot the same rel data with no target handles at all.
        let resolver = CrossEngineResolver::disabled(Arc::clone(&metrics));
        let rel = boot_rel(dir.path(), RelStoreConfig::default(), metrics, resolver).await;

        // Pre-existing link columns read back masked — no panic, no 500.
        let r = rows(&rel, "default", "SELECT payload, doc FROM t WHERE id = 1").await;
        assert_eq!(r[0][0], ScalarValue::Null, "KVREF masked when KV disabled");
        assert_eq!(r[0][1], ScalarValue::Null, "JSONREF masked when JSON disabled");

        // A non-NULL link write 409s; a NULL-link write still succeeds.
        let err = exec_err(&rel, "default", "INSERT INTO t VALUES (3, 'k', NULL)").await;
        assert!(matches!(err, RelStoreError::CrossEngineTargetUnavailable { .. }), "disabled write: {err}");
        ok(&rel, "default", "INSERT INTO t VALUES (4, NULL, NULL)").await;
        let exp = expand_block(&rel, "default", "SELECT * FROM t WHERE id = 4", &["*"]).await;
        assert_eq!(colv(&exp, "payload")[0], Value::Null);
        assert_eq!(colv(&exp, "doc")[0], Value::Null);
    }

    // 25. sweep_tick skip: a rel-Deleting domain is left untouched even though
    // its KV target is gone — the rel/013 purger owns it, not the sweeper.
    #[tokio::test]
    async fn test_sweep_skips_deleting_rel_domain() {
        let e = env().await;
        e.rel.create_domain("d").await.unwrap();
        e.kv.create_domain("d").await.unwrap();
        kv_put(&e.kv, "d", b"k", b"v").await;
        ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k')").await;
        let (prefix, schema) = table_of(&e.rel, "d", "t");
        let col = schema.columns.iter().find(|c| c.name == "payload").unwrap().clone();

        e.kv.delete_domain("d").await.unwrap(); // target gone: would normally be swept
        e.rel.delete_domain("d").await.unwrap(); // but the rel domain itself is Deleting

        sweep_once(&e.rel, 100).await;

        let row_key = keys::row_key(&prefix, schema.table_id, &encode_sortable(&ScalarValue::Integer(1)).unwrap());
        let snap = e.rel.engine().snapshot();
        let bytes = e.rel.engine().get_with_snapshot(&row_key, snap.snapshot()).await.unwrap().into_option().unwrap();
        assert_eq!(
            decode_value(&bytes, &col),
            ScalarValue::Text("k".into()),
            "Deleting rel domain untouched by the cross-engine sweeper"
        );
    }

    // ── LinkAuth (spec rel/016) ────────────────────────────────────────────

    // 26. (a)+(b) missing read right masks only that engine's link columns —
    // identical to "target domain gone" — the other engine stays untouched;
    // both rights present resolves exactly as before.
    #[tokio::test]
    async fn test_link_auth_masks_select_and_expand_per_engine() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k", b"v").await;
        e.json.put_document("default", "j1", json!({"x": 1})).await.unwrap();
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF, doc JSONREF)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k', 'j1')").await;

        // kv_read=false: KVREF masked in SELECT and expand; JSONREF untouched.
        let no_kv = LinkAuth { kv_read: false, json_read: true };
        let out = e
            .rel
            .execute_sql("default", "SELECT * FROM t", &[], &["*".to_string()], no_kv)
            .await
            .unwrap();
        let SqlOutcome::Select { result, expanded } = out else { panic!("expected SELECT") };
        assert_eq!(result.rows[0][1], ScalarValue::Null, "KVREF masked in SELECT projection");
        assert_eq!(result.rows[0][2], ScalarValue::Text("j1".into()), "JSONREF untouched");
        let expanded = expanded.unwrap();
        assert_eq!(colv(&expanded, "payload")[0], Value::Null, "masked column expands to null");
        assert_eq!(colv(&expanded, "doc")[0], json!({ "exists": true, "document": {"x": 1} }));

        // json_read=false: the mirror case.
        let no_json = LinkAuth { kv_read: true, json_read: false };
        let out = e
            .rel
            .execute_sql("default", "SELECT * FROM t", &[], &["*".to_string()], no_json)
            .await
            .unwrap();
        let SqlOutcome::Select { result, expanded } = out else { panic!("expected SELECT") };
        assert_eq!(result.rows[0][1], ScalarValue::Text("k".into()), "KVREF untouched");
        assert_eq!(result.rows[0][2], ScalarValue::Null, "JSONREF masked in SELECT projection");
        let expanded = expanded.unwrap();
        assert_eq!(colv(&expanded, "payload")[0], json!({ "exists": true, "value": "v", "encoding": "utf8" }));
        assert_eq!(colv(&expanded, "doc")[0], Value::Null, "masked column expands to null");

        // Both rights present: unchanged from the rel/012 baseline.
        let out = e
            .rel
            .execute_sql("default", "SELECT * FROM t", &[], &["*".to_string()], LinkAuth::full())
            .await
            .unwrap();
        let SqlOutcome::Select { result, .. } = out else { panic!("expected SELECT") };
        assert_eq!(result.rows[0][1], ScalarValue::Text("k".into()));
        assert_eq!(result.rows[0][2], ScalarValue::Text("j1".into()));
    }

    // 27. (c) write path: missing read right rejects *before* any existence
    // lookup — an existing and a nonexistent key get the identical
    // CrossEngineForbidden, proving there is no oracle; no write-validation
    // metric tick either.
    #[tokio::test]
    async fn test_link_auth_forbids_write_before_existence_check() {
        let e = env().await;
        kv_put(&e.kv, "default", b"exists", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;

        let no_kv = LinkAuth { kv_read: false, json_read: true };
        let before = e.metrics.system.rel_cross_engine_write_validations_kv_total.load(Ordering::Relaxed);

        let body_existing = mk_body(json!({"id": 1, "payload": "exists"}));
        let err = e.rel.insert_row("default", "t", &body_existing, no_kv).await.unwrap_err();
        assert!(matches!(&err, RelStoreError::CrossEngineForbidden { engine } if engine == "kv"), "got: {err}");

        let body_missing = mk_body(json!({"id": 2, "payload": "does-not-exist"}));
        let err = e.rel.insert_row("default", "t", &body_missing, no_kv).await.unwrap_err();
        assert!(matches!(&err, RelStoreError::CrossEngineForbidden { engine } if engine == "kv"), "got: {err}");

        assert_eq!(count(&e.rel, "default", "t").await, 0, "both rejected inserts left no row");
        assert_eq!(
            e.metrics.system.rel_cross_engine_write_validations_kv_total.load(Ordering::Relaxed),
            before,
            "a forbidden link performs no cross-engine write-validation metric tick"
        );
    }

    // 28. (d) WHERE-oracle: a masked column matches nothing under an equality
    // predicate and everything under IS NULL — mirrors test 18's domain-gone
    // case, but caused by a missing LinkAuth right instead.
    #[tokio::test]
    async fn test_link_auth_where_oracle() {
        let e = env().await;
        kv_put(&e.kv, "default", b"k1", b"v").await;
        kv_put(&e.kv, "default", b"k2", b"v").await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
        ok(&e.rel, "default", "CREATE INDEX ix ON t (payload)").await;
        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k1'), (2, 'k2')").await;

        let no_kv = LinkAuth { kv_read: false, json_read: true };

        async fn count_rows(rel: &RelEngine, sql: &str, auth: LinkAuth) -> usize {
            match rel.execute_sql("default", sql, &[], &[], auth).await.unwrap() {
                SqlOutcome::Select { result, .. } => result.rows.len(),
                o => panic!("expected SELECT, got {o:?}"),
            }
        }

        assert_eq!(count_rows(&e.rel, "SELECT id FROM t WHERE payload IS NULL", no_kv).await, 2);
        assert_eq!(count_rows(&e.rel, "SELECT id FROM t WHERE payload = 'k1'", no_kv).await, 0);
        assert_eq!(count_rows(&e.rel, "SELECT id FROM t WHERE payload IS NOT NULL", no_kv).await, 0);
    }

    // ── Spec general/019: per-engine ops/s + latency percentiles ─────────────

    // Tests 3+4: one op per engine (KV put+get, JSON create+get, rel
    // INSERT+SELECT) increments exactly that engine's read_ops/write_ops and
    // fills its latency buckets, while the other two engines stay at 0.
    #[tokio::test]
    async fn test_engine_metrics_isolated_per_engine() {
        let e = env().await;
        ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)").await;

        e.kv.store("default").await.unwrap().put(b"k", b"v").await.unwrap();
        e.kv.store("default").await.unwrap().get(b"k").await.unwrap();

        let doc = e.json.create_document("default", json!({"n": 1})).await.unwrap();
        e.json.get_document("default", &doc.key).await.unwrap();

        ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'a')").await;
        rows(&e.rel, "default", "SELECT * FROM t").await;
        e.metrics.tick_all();

        let [kv, json_m, rel_m] = e.metrics.engine_metrics();
        assert_eq!((kv.read_ops, kv.write_ops), (1, 1), "kv: only its own ops");
        assert_eq!((json_m.read_ops, json_m.write_ops), (1, 1), "json: only its own ops");
        // CREATE TABLE must not count (test 8 below) -- exactly 1 read + 1 write.
        assert_eq!((rel_m.read_ops, rel_m.write_ops), (1, 1), "rel: only its own ops, DDL excluded");

        assert_ne!(kv.read_latency_us_p99, 0, "kv read latency bucket must be filled");
        assert_ne!(kv.write_latency_us_p99, 0, "kv write latency bucket must be filled");
        assert_ne!(json_m.read_latency_us_p99, 0, "json read latency bucket must be filled");
        assert_ne!(json_m.write_latency_us_p99, 0, "json write latency bucket must be filled");
        assert_ne!(rel_m.read_latency_us_p99, 0, "rel read latency bucket must be filled");
        assert_ne!(rel_m.write_latency_us_p99, 0, "rel write latency bucket must be filled");
    }

    // Test 8: rel DDL (CREATE TABLE) increments neither read_ops nor
    // write_ops -- it never reaches execute_dml (dml.rs:114).
    #[tokio::test]
    async fn test_engine_metrics_rel_ddl_not_counted() {
        let e = env().await;
        ok(&e.rel, "default", "CREATE TABLE ddl_only (id INTEGER PRIMARY KEY)").await;
        e.metrics.tick_all();

        let [_, _, rel_m] = e.metrics.engine_metrics();
        assert_eq!(rel_m.read_ops, 0);
        assert_eq!(rel_m.write_ops, 0);
    }
}
