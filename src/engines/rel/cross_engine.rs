//! Cross-engine links: the `CrossEngineResolver` bridge from
//! the rel engine to the same-named KV/JSON domains, and the per-query read
//! `LinkMask`. This is the **only** rel module that imports `kv`/`json`
//! types — the rest of the engine stays link-agnostic (rel never appears in
//! `kv`/`json`, so no cycles).

use super::catalog::TableSchema;
use super::error::RelStoreError;
use super::types::{ColumnType, ScalarValue};
use super::RelEngine;
use crate::engines::json::{JsonEngine, JsonStoreError};
use crate::engines::lsm::domain::DomainRegistry;
use crate::engines::lsm::reader::GetResult;
use crate::metrics::MetricsStore;
use std::sync::Arc;

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
/// key that exists in the explicit NULL state.
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
/// are optional: an engine can be disabled by config. Reads and writes treat a
/// disabled engine like a gone target.
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

    pub(crate) fn kv_enabled(&self) -> bool {
        self.kv.is_some()
    }

    pub(crate) fn json_enabled(&self) -> bool {
        self.json.is_some()
    }

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

    /// KVREF point lookup **directly on the KV LSM instance** (not via
    /// `DomainStore`): governance is already charged once at the rel REST edge
    /// against the rel domain, so a second KV rate-limit hit is wrong.
    /// Authorization is likewise handled upstream, not here: a
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
        let snap = engine.snapshot().await;
        Ok(match engine.get_with_snapshot(&prefixed, snap.snapshot()).await? {
            GetResult::Present(bytes) => KvResolution::Present(bytes),
            GetResult::Null => KvResolution::NullValue,
            GetResult::Absent => KvResolution::Absent,
        })
    }

    /// JSONREF point lookup via the rate-limit-free `get_document` primitive.
    /// A key that is not a valid document key cannot reference a document →
    /// `Absent` (a clean 409/`exists:false`, never a 500). Authorization is
    /// handled upstream, same as `kv_lookup` above.
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

    pub(crate) fn record_expand_lookup(&self, engine: &str) {
        self.metrics.record_rel_cross_engine_expand_lookup(engine);
    }

    pub(crate) fn record_write_validation(&self, engine: &str) {
        self.metrics.record_rel_cross_engine_write_validation(engine);
    }
}

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
    /// through.
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
    /// the target domain's status — indistinguishable from
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
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{JsonStoreConfig, RelStoreConfig};
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::{DomainConfig, DomainPurger};
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::engines::rel::catalog::CatalogEntry;
    use crate::engines::rel::keys;
    use crate::engines::rel::row::decode_value;
    use crate::engines::rel::types::encode_sortable;
    use crate::engines::rel::{ExecOutcome, ExpandedBlock, SqlOutcome};
    use crate::metrics::MetricsConfig;
    use crate::storage::file_manager::FileManager;
    use std::sync::atomic::Ordering;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use serde_json::{json, Value};
    use std::path::Path;

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
        Arc::new(DomainRegistry::recover_with_default(engine, DomainConfig::default(), metrics).await.unwrap())
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
        let snap = rel.engine().snapshot().await;
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

    #[test]
    fn test_base64_encoder() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"hi"), "aGk=");
        assert_eq!(base64_encode(&[0xFF, 0xFE, 0xFD]), "//79");
    }

    #[test]
    fn test_write_kvref_ok() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            kv_put(&e.kv, "default", b"k", b"hello").await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
            assert_eq!(
                rows(&e.rel, "default", "SELECT payload FROM t WHERE id = 1").await[0][0],
                ScalarValue::Text("k".into())
            );
        })
    }

    #[test]
    fn test_write_kvref_missing_and_atomic() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            kv_put(&e.kv, "default", b"k", b"v").await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;

            let err = exec_err(&e.rel, "default", "INSERT INTO t VALUES (1, 'missing')").await;
            assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");

            // One violating row leaves none of the statement's rows.
            let err = exec_err(&e.rel, "default", "INSERT INTO t VALUES (1, 'k'), (2, 'missing')").await;
            assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");
            assert_eq!(count(&e.rel, "default", "t").await, 0, "atomic: no row survives");
        })
    }

    #[test]
    fn test_write_jsonref_ok_and_missing() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            e.json.put_document("default", "d1", json!({"a": 1})).await.unwrap();
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, doc JSONREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'd1')").await;
            let err = exec_err(&e.rel, "default", "INSERT INTO t VALUES (2, 'ghost')").await;
            assert!(matches!(err, RelStoreError::CrossEngineLinkMissing { .. }), "got: {err}");
        })
    }

    #[test]
    fn test_write_target_domain_gone() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_engine_disabled_ddl_and_value() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_null_link_unchecked() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_update_only_changed_links() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_expand_kvref_utf8_and_empty() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            kv_put(&e.kv, "default", b"k1", b"hello").await;
            kv_put(&e.kv, "default", b"k2", b"").await; // empty value *exists*
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k1'), (2, 'k2')").await;

            let exp = expand_block(&e.rel, "default", "SELECT * FROM t ORDER BY id", &["payload"]).await;
            let v = colv(&exp, "payload");
            assert_eq!(v[0], json!({ "exists": true, "value": "hello", "encoding": "utf8" }));
            assert_eq!(v[1], json!({ "exists": true, "value": "", "encoding": "utf8" }), "empty value exists");
        })
    }

    #[test]
    fn test_expand_kvref_base64() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            kv_put(&e.kv, "default", b"k", &[0xFF, 0xFE, 0xFD]).await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
            let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
            assert_eq!(colv(&exp, "payload")[0], json!({ "exists": true, "value": "//79", "encoding": "base64" }));
        })
    }

    #[test]
    fn test_expand_kvref_hanging_and_domain_gone() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_expand_kvref_null_value() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            kv_put(&e.kv, "default", b"k", b"v").await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
            // Null the KV key after linking: the key still exists, valueless.
            e.kv.store("default").await.unwrap().set_null(b"k").await.unwrap();
            let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
            assert_eq!(colv(&exp, "payload")[0], json!({ "exists": true, "value": null }));
        })
    }

    #[test]
    fn test_expand_jsonref() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_expand_rel_null_vs_gone() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            kv_put(&e.kv, "default", b"k", b"v").await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, NULL), (2, 'k')").await;
            e.kv.store("default").await.unwrap().delete(b"k").await.unwrap(); // row 2 now hangs
            let exp = expand_block(&e.rel, "default", "SELECT * FROM t ORDER BY id", &["payload"]).await;
            let v = colv(&exp, "payload");
            assert_eq!(v[0], Value::Null, "rel-NULL → null entry (no lookup)");
            assert_eq!(v[1], json!({ "exists": false, "value": null }), "gone target → exists:false");
        })
    }

    #[test]
    fn test_expand_wildcard_references_and_links() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_expand_explicit_link_resolves() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_expand_max_join_depth() {
        crate::core::engine_runtime::block_on(async {
            let mut e = env_with(RelStoreConfig::default(), true, true).await;
            Arc::get_mut(&mut e.rel).unwrap().set_max_join_depth(0);
            kv_put(&e.kv, "default", b"k", b"v").await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
            let out = e
                .rel
                .execute_sql("default", "SELECT * FROM t", &[], &["payload".to_string()], LinkAuth::full())
                .await;
            assert!(matches!(out, Err(RelStoreError::JoinDepthExceeded { .. })), "got: {out:?}");
        })
    }

    #[test]
    fn test_expand_large_kv_value_in_block() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            let big = vec![b'a'; 4096];
            kv_put(&e.kv, "default", b"k", &big).await;
            ok(&e.rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
            let exp = expand_block(&e.rel, "default", "SELECT * FROM t", &["payload"]).await;
            // The full KV value is carried into the response the handler's 413 cap
            // measures (the cap itself is the unchanged handler check).
            assert_eq!(colv(&exp, "payload")[0]["value"].as_str().unwrap().len(), 4096);
        })
    }

    #[test]
    fn test_read_masking_kv_only() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_masking_where_and_index_guard() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    #[test]
    fn test_purging_target_part_is_masked_and_links_stay_stored() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            e.rel.create_domain("d").await.unwrap();
            e.kv.create_domain("d").await.unwrap();
            kv_put(&e.kv, "d", b"k", b"v").await;
            ok(&e.rel, "d", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
            ok(&e.rel, "d", "CREATE INDEX ix ON t (payload)").await;
            ok(&e.rel, "d", "INSERT INTO t VALUES (1, 'k')").await;

            e.kv.delete_domain("d").await.unwrap();
            let r = rows(&e.rel, "d", "SELECT payload FROM t WHERE id = 1").await;
            assert_eq!(r[0][0], ScalarValue::Null, "link to a purging part reads as NULL");
            assert_eq!(raw_cell(&e.rel, "d", "t", 1, "payload").await, ScalarValue::Text("k".into()), "stored cell unchanged");
            assert_eq!(index_entries(&e.rel, "d", "t", "ix").await, 1, "index entry kept");

            // The purge finishes and an empty part is laid again.
            let purger = DomainPurger::new(Arc::clone(e.kv.engine()), Arc::clone(&e.kv), 100);
            purger.purge_tick().await.unwrap();
            purger.purge_tick().await.unwrap();
            e.kv.create_domain("d").await.unwrap();
            assert_eq!(raw_cell(&e.rel, "d", "t", 1, "payload").await, ScalarValue::Text("k".into()), "stored cell still the old key");
            let exp = expand_block(&e.rel, "d", "SELECT * FROM t", &["payload"]).await;
            assert_eq!(colv(&exp, "payload")[0], json!({ "exists": false, "value": null }));
        })
    }

    #[test]
    fn test_metrics_expand_lookups() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    // A link *column* can only be created while its engine is enabled, so
    // the disabled case is a restart: build the schema+rows with engines on,
    // then reboot the same rel data with a fully-disabled resolver.
    // Disabled handle: existing links are masked, writes answer 409.
    #[test]
    fn test_disabled_smoke() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    // 26. (a)+(b) missing read right masks only that engine's link columns —
    // identical to "target domain gone" — the other engine stays untouched;
    // both rights present resolves exactly as before.
    #[test]
    fn test_link_auth_masks_select_and_expand_per_engine() {
        crate::core::engine_runtime::block_on(async {
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

            // Both rights present: unchanged from the unmasked baseline.
            let out = e
                .rel
                .execute_sql("default", "SELECT * FROM t", &[], &["*".to_string()], LinkAuth::full())
                .await
                .unwrap();
            let SqlOutcome::Select { result, .. } = out else { panic!("expected SELECT") };
            assert_eq!(result.rows[0][1], ScalarValue::Text("k".into()));
            assert_eq!(result.rows[0][2], ScalarValue::Text("j1".into()));
        })
    }

    // 27. (c) write path: missing read right rejects *before* any existence
    // lookup — an existing and a nonexistent key get the identical
    // CrossEngineForbidden, proving there is no oracle; no write-validation
    // metric tick either.
    #[test]
    fn test_link_auth_forbids_write_before_existence_check() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    // 28. (d) WHERE-oracle: a masked column matches nothing under an equality
    // predicate and everything under IS NULL — mirrors test 18's domain-gone
    // case, but caused by a missing LinkAuth right instead.
    #[test]
    fn test_link_auth_where_oracle() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    // Tests 3+4: one op per engine (KV put+get, JSON create+get, rel
    // INSERT+SELECT) increments exactly that engine's read_ops/write_ops and
    // fills its latency buckets, while the other two engines stay at 0.
    #[test]
    fn test_engine_metrics_isolated_per_engine() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    // Test 8: rel DDL (CREATE TABLE) increments neither read_ops nor
    // write_ops -- it never reaches execute_dml (dml.rs:114).
    #[test]
    fn test_engine_metrics_rel_ddl_not_counted() {
        crate::core::engine_runtime::block_on(async {
            let e = env().await;
            ok(&e.rel, "default", "CREATE TABLE ddl_only (id INTEGER PRIMARY KEY)").await;
            e.metrics.tick_all();

            let [_, _, rel_m] = e.metrics.engine_metrics();
            assert_eq!(rel_m.read_ops, 0);
            assert_eq!(rel_m.write_ops, 0);
        })
    }

    // JSONREF: masked while JSON is disabled, the stored cell is untouched,
    // and the reference is back once JSON is re-enabled. A non-NULL JSONREF
    // write still 409s while JSON stays disabled.
    #[test]
    fn test_jsonref_survives_disable_reenable() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let metrics = MetricsStore::new(MetricsConfig::default());
            let kv = make_kv(dir.path(), Arc::clone(&metrics)).await;
            let json = make_json(dir.path(), Arc::clone(&metrics)).await;

            // Phase 1: both engines enabled — schema + a non-NULL JSONREF row.
            {
                let resolver =
                    CrossEngineResolver::new(Some(Arc::clone(&kv)), Some(Arc::clone(&json)), Arc::clone(&metrics));
                let rel = boot_rel(dir.path(), RelStoreConfig::default(), Arc::clone(&metrics), resolver).await;
                json.put_document("default", "d1", json!({"a": 1})).await.unwrap();
                ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, doc JSONREF)").await;
                ok(&rel, "default", "INSERT INTO t VALUES (1, 'd1')").await;
                rel.shutdown().await;
            }

            // Phase 2: JSON disabled — masked read, the cell stays physically
            // untouched, and a non-NULL write 409s.
            {
                let resolver = CrossEngineResolver::new(Some(Arc::clone(&kv)), None, Arc::clone(&metrics));
                let rel = boot_rel(dir.path(), RelStoreConfig::default(), Arc::clone(&metrics), resolver).await;
                let r = rows(&rel, "default", "SELECT doc FROM t WHERE id = 1").await;
                assert_eq!(r[0][0], ScalarValue::Null, "masked while JSON disabled");

                assert_eq!(
                    raw_cell(&rel, "default", "t", 1, "doc").await,
                    ScalarValue::Text("d1".into()),
                    "a disabled target engine must not change the stored cell"
                );

                let err = exec_err(&rel, "default", "INSERT INTO t VALUES (2, 'd1')").await;
                assert!(
                    matches!(&err, RelStoreError::CrossEngineTargetUnavailable { engine, domain: Some(d) } if engine == "json" && d == "default"),
                    "got: {err}"
                );
                assert_eq!(count(&rel, "default", "t").await, 1, "the rejected insert left no row");
                rel.shutdown().await;
            }

            // Phase 3: JSON re-enabled — the reference reads back unchanged.
            {
                let resolver =
                    CrossEngineResolver::new(Some(Arc::clone(&kv)), Some(Arc::clone(&json)), Arc::clone(&metrics));
                let rel = boot_rel(dir.path(), RelStoreConfig::default(), metrics, resolver).await;
                let r = rows(&rel, "default", "SELECT doc FROM t WHERE id = 1").await;
                assert_eq!(r[0][0], ScalarValue::Text("d1".into()), "JSONREF survives disable+re-enable");
            }
        })
    }

    // KVREF counterpart: masked while KV is disabled, the stored cell is
    // untouched, and the reference is back once KV is re-enabled.
    #[test]
    fn test_kvref_survives_disable_reenable() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let metrics = MetricsStore::new(MetricsConfig::default());
            let kv = make_kv(dir.path(), Arc::clone(&metrics)).await;
            let json = make_json(dir.path(), Arc::clone(&metrics)).await;

            // Phase 1: both engines enabled — schema + a non-NULL KVREF row.
            {
                let resolver =
                    CrossEngineResolver::new(Some(Arc::clone(&kv)), Some(Arc::clone(&json)), Arc::clone(&metrics));
                let rel = boot_rel(dir.path(), RelStoreConfig::default(), Arc::clone(&metrics), resolver).await;
                kv_put(&kv, "default", b"k", b"v").await;
                ok(&rel, "default", "CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)").await;
                ok(&rel, "default", "INSERT INTO t VALUES (1, 'k')").await;
                rel.shutdown().await;
            }

            // Phase 2: KV disabled — masked read, the cell stays physically
            // untouched.
            {
                let resolver = CrossEngineResolver::new(None, Some(Arc::clone(&json)), Arc::clone(&metrics));
                let rel = boot_rel(dir.path(), RelStoreConfig::default(), Arc::clone(&metrics), resolver).await;
                let r = rows(&rel, "default", "SELECT payload FROM t WHERE id = 1").await;
                assert_eq!(r[0][0], ScalarValue::Null, "masked while KV disabled");

                assert_eq!(
                    raw_cell(&rel, "default", "t", 1, "payload").await,
                    ScalarValue::Text("k".into()),
                    "a disabled target engine must not change the stored cell"
                );
                rel.shutdown().await;
            }

            // Phase 3: KV re-enabled — the reference reads back unchanged.
            {
                let resolver = CrossEngineResolver::new(Some(kv), Some(json), Arc::clone(&metrics));
                let rel = boot_rel(dir.path(), RelStoreConfig::default(), metrics, resolver).await;
                let r = rows(&rel, "default", "SELECT payload FROM t WHERE id = 1").await;
                assert_eq!(r[0][0], ScalarValue::Text("k".into()), "KVREF survives disable+re-enable");
            }
        })
    }
}
