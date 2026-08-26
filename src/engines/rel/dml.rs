//! DML deep-binder, atomic write path, and PK-point SELECT (spec rel/005
//! §5-12). INSERT/UPDATE/DELETE run under a per-table write lock (held across
//! candidate acquisition and the single `WriteBatch`), an MVCC snapshot for
//! all check-reads. Value binding, the hand-written ISO-8601 parser and
//! `now_millis` live here; the WHERE predicate is bound to a `Pred` (eval.rs).

use super::ast::{Assignment, CompareOp, Delete, Expr, Insert, Literal, Operand, Select, Statement, Update};
use super::catalog::{CatalogEntry, ColumnDef, DefaultValue, TableSchema};
use super::cross_engine::{JsonResolution, KvResolution, LinkAuth};
use super::domain::RelDomain;
use super::error::RelStoreError;
use super::eval::{eval, Bool3, Pred, PredOperand};
use super::keys;
use super::row::{decode_row, encode_row};
use super::types::{encode_sortable, ColumnType, ScalarValue};
use super::{ExecOutcome, RelEngine};
use crate::engines::lsm::engine::BatchOp;
use crate::engines::lsm::reader::Snapshot;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ── Per-table write lock (spec §8.1) ────────────────────────────────────────

type LockMap = HashMap<(Vec<u8>, u32), Arc<tokio::sync::Mutex<()>>>;

/// Lazily-filled map of `(system_prefix, table_id)` → async mutex. A tokio
/// mutex (never a parking_lot guard held across `.await`) serializes
/// check-then-write races per table.
#[derive(Default)]
pub struct TableLocks {
    map: Mutex<LockMap>,
}

impl TableLocks {
    pub(super) fn get(&self, system_prefix: &[u8], table_id: u32) -> Arc<tokio::sync::Mutex<()>> {
        self.map
            .lock()
            .entry((system_prefix.to_vec(), table_id))
            .or_default()
            .clone()
    }
}

// ── Execution results (spec §14) ────────────────────────────────────────────

#[derive(Debug)]
pub struct DmlResult {
    pub affected: u64,
    pub last_pk: Option<ScalarValue>,
}

#[derive(Debug)]
pub struct SelectResult {
    pub columns: Vec<(String, ColumnType)>,
    pub rows: Vec<Vec<ScalarValue>>,
    /// `true` iff the effective LIMIT was reduced by `max_limit`, or more
    /// matching rows existed past OFFSET+LIMIT than were returned (rel/006
    /// §6/§10). Always `false` for COUNT(*).
    pub limit_applied: bool,
    /// REFERENCES target table name per output column (rel/009 §5 `expand`),
    /// parallel to `columns`; `None` where the column isn't a projected
    /// REFERENCES/KVREF/JSONREF link (always `None` for COUNT(*)'s single
    /// column). Engine-internal wiring for `expand`, not part of any public
    /// wire format — `pub(crate)` rather than exposed on `columns` itself.
    pub(crate) column_refs: Vec<Option<String>>,
    /// Number of `LEFT JOIN` stages the statement itself used (0 outside
    /// join.rs). `expand` columns are charged against `max_join_depth` on
    /// top of this count (rel/007 §8, rel/009 §5).
    pub(crate) joins_used: usize,
    /// The MVCC snapshot the rows were read at (rel/005/006 `snapshot()` +
    /// `get_with_snapshot`). `expand` resolution (rel/009 §5) reuses it so
    /// referenced rows are read at the same point in time as the driving
    /// SELECT, rather than a fresh (later) snapshot. `None` for COUNT(*),
    /// which is never expand-eligible (`column_refs` is all-`None` there).
    pub(crate) snapshot: Option<Snapshot>,
}

/// A row selected for UPDATE/DELETE: its ROW key plus decoded values (in
/// `schema.columns` order).
struct Candidate {
    key: Vec<u8>,
    values: Vec<ScalarValue>,
}

/// An INSERT row's resolved values plus whether the AUTOINCREMENT PK still
/// needs a sequence value (filled under the write lock).
struct RowPlan {
    values: HashMap<u16, ScalarValue>,
    needs_auto: bool,
}

impl RelEngine {
    /// Dispatches a bound DML/SELECT statement. Table/index DDL is handled
    /// before this point (`ddl.rs`); `CREATE`/`DROP VIEW` are intercepted even
    /// earlier, in `RelEngine::execute`, since they need the raw SQL text
    /// (rel/008 `view.rs`) — they can never reach here.
    pub(super) async fn execute_dml(
        &self,
        domain: &str,
        stmt: Statement,
        params: &[Value],
        auth: LinkAuth,
    ) -> Result<ExecOutcome, RelStoreError> {
        match stmt {
            Statement::Insert(i) => self.exec_insert(domain, i, params, auth).await.map(ExecOutcome::Dml),
            Statement::Update(u) => self.exec_update(domain, u, params, auth).await.map(ExecOutcome::Dml),
            Statement::Delete(d) => self.exec_delete(domain, d, params).await.map(ExecOutcome::Dml),
            Statement::Select(s) => self.exec_select(domain, s, params, auth).await,
            Statement::CreateView(_) | Statement::DropView(_) => {
                unreachable!("CREATE/DROP VIEW are dispatched in RelEngine::execute (rel/008 view.rs)")
            }
            _ => unreachable!("DDL is dispatched before execute_dml"),
        }
    }

    /// Resolves a DML target to a table: view → `NotWritable`, missing →
    /// `TableNotFound`, deleting/unknown domain → 410/404 (spec §1).
    /// `pub(super)`: reused by the Row-Browse/Row-Write REST entry points
    /// (rel/010 `rest_browse.rs`/`rest_write.rs`) to resolve the table schema
    /// before synthesizing a bound Select/DML statement.
    pub(super) fn require_table(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<(RelDomain, TableSchema), RelStoreError> {
        let dom = self.domains.require_active(domain)?;
        match self.catalog.get(&self.domains, domain, name) {
            Ok(CatalogEntry::Table(t)) => Ok((dom, t)),
            Ok(CatalogEntry::View(_)) => Err(RelStoreError::NotWritable { name: name.to_string() }),
            Err(RelStoreError::ObjectNotFound { domain, name }) => {
                Err(RelStoreError::TableNotFound { domain, name })
            }
            Err(e) => Err(e),
        }
    }

    // ── INSERT (spec §8-9) ──────────────────────────────────────────────────

    async fn exec_insert(
        &self,
        domain: &str,
        ins: Insert,
        params: &[Value],
        auth: LinkAuth,
    ) -> Result<DmlResult, RelStoreError> {
        let (dom, schema) = self.require_table(domain, &ins.table)?;
        let prefix = &dom.system_prefix;

        let target_cols = resolve_insert_columns(&schema, &ins)?;
        let pk_col = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
        let now = now_millis();
        let mut rows = build_row_plans(&schema, &target_cols, &ins.rows, params, now)?;

        let lock = self.table_locks.get(prefix, schema.table_id);
        let _guard = lock.lock().await;
        let snapshot = self.engine.snapshot();
        let snap = snapshot.snapshot();

        // AUTOINCREMENT high-water: assign omitted PKs, raise for explicit ones.
        let auto = pk_col.autoincrement;
        let hw0 = if auto { self.read_seq(prefix, schema.table_id, snap).await? } else { 0 };
        let hw = if auto { assign_autoincrement(pk_col, &mut rows, hw0, &schema.name)? } else { hw0 };

        let single = rows.len() == 1;
        let mut ops: Vec<BatchOp> = Vec::new();
        let mut seen_pk: HashSet<Vec<u8>> = HashSet::new();
        let mut seen_unique: HashSet<(u32, Vec<u8>)> = HashSet::new();
        let mut last_pk = None;

        for row in &rows {
            let pk_v = self
                .stage_insert_row(domain, &schema, prefix, row, snap, &mut seen_pk, &mut seen_unique, &mut ops, auth)
                .await?;
            if single {
                last_pk = Some(pk_v);
            }
        }

        if hw != hw0 {
            ops.push(BatchOp::Put {
                key: keys::seq_key(prefix, schema.table_id),
                value: hw.to_be_bytes().to_vec(),
            });
        }

        self.commit_guarded(domain, ops).await?;
        self.metrics.record_rel_dml_statement("insert");
        Ok(DmlResult { affected: rows.len() as u64, last_pk })
    }

    /// One INSERT row's checks and batch ops (spec §8-9): NOT NULL/text size
    /// → PK dup → row size → UNIQUE → REFERENCES → cross-engine links → index
    /// entries → row `Put`. Returns the row's PK, for `exec_insert`'s
    /// single-row `last_pk`.
    async fn stage_insert_row(
        &self,
        domain: &str,
        schema: &TableSchema,
        prefix: &[u8],
        row: &RowPlan,
        snap: &Snapshot,
        seen_pk: &mut HashSet<Vec<u8>>,
        seen_unique: &mut HashSet<(u32, Vec<u8>)>,
        ops: &mut Vec<BatchOp>,
        auth: LinkAuth,
    ) -> Result<ScalarValue, RelStoreError> {
        let pk_col = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
        self.validate_not_null_and_text(schema, &row.values)?;
        let pk_v = row.values.get(&pk_col.col_id).cloned().unwrap_or(ScalarValue::Null);
        let pk_enc = encode_sortable(&pk_v).ok_or_else(|| RelStoreError::NotNull {
            table: schema.name.clone(),
            column: pk_col.name.clone(),
        })?;
        let row_key = keys::row_key(prefix, schema.table_id, &pk_enc);
        self.guard_key_len(&row_key)?;

        if !seen_pk.insert(pk_enc.clone())
            || self.engine.get_with_snapshot(&row_key, snap).await?.into_option().is_some()
        {
            return Err(RelStoreError::DuplicateKey { table: schema.name.clone() });
        }

        let row_bytes = encode_row(schema, &row.values);
        if row_bytes.len() > self.max_row_size {
            return Err(RelStoreError::RowTooLarge {
                size: row_bytes.len(),
                max: self.max_row_size,
            });
        }

        self.check_row_unique(schema, &row.values, prefix, &pk_enc, seen_unique).await?;
        self.check_row_references(domain, schema, &row.values, prefix, snap).await?;
        self.check_row_cross_engine_links(domain, schema, &row.values, auth).await?;

        for k in row_index_keys(schema, &row.values, prefix, &pk_enc) {
            self.guard_key_len(&k)?;
            ops.push(BatchOp::Put { key: k, value: Vec::new() });
        }
        ops.push(BatchOp::Put { key: row_key, value: row_bytes });
        Ok(pk_v)
    }

    // ── UPDATE (spec §10) ───────────────────────────────────────────────────

    async fn exec_update(
        &self,
        domain: &str,
        upd: Update,
        params: &[Value],
        auth: LinkAuth,
    ) -> Result<DmlResult, RelStoreError> {
        let (dom, schema) = self.require_table(domain, &upd.table)?;
        let prefix = &dom.system_prefix;

        let sets = bind_update_assignments(&schema, &upd.assignments, params)?;
        let set_ids: HashSet<u16> = sets.iter().map(|(c, _)| c.col_id).collect();

        let quals = vec![schema.name.clone()];
        let lock = self.table_locks.get(prefix, schema.table_id);
        let _guard = lock.lock().await;
        let snapshot = self.engine.snapshot();
        let snap = snapshot.snapshot();
        let candidates = self
            .acquire_candidates(&dom, &schema, &upd.where_clause, &quals, params, snap)
            .await?;

        let mut ops: Vec<BatchOp> = Vec::new();
        let mut seen_unique: HashSet<(u32, Vec<u8>)> = HashSet::new();
        for cand in &candidates {
            let old = values_by_col_id(&schema, &cand.values);
            let mut new = old.clone();
            for (c, v) in &sets {
                new.insert(c.col_id, v.clone());
            }
            self.validate_not_null_and_text(&schema, &new)?;
            let pk_enc = pk_enc_of(&schema, &new)?;

            let row_bytes = encode_row(&schema, &new);
            if row_bytes.len() > self.max_row_size {
                return Err(RelStoreError::RowTooLarge {
                    size: row_bytes.len(),
                    max: self.max_row_size,
                });
            }
            let row_key = keys::row_key(prefix, schema.table_id, &pk_enc);
            self.guard_key_len(&row_key)?;

            self.check_updated_references(domain, prefix, &sets, snap, auth).await?;
            self.diff_update_indexes(&schema, prefix, &old, &new, &set_ids, &pk_enc, &mut seen_unique, &mut ops)
                .await?;
            ops.push(BatchOp::Put { key: row_key, value: row_bytes });
        }

        self.commit_guarded(domain, ops).await?;
        self.metrics.record_rel_dml_statement("update");
        Ok(DmlResult { affected: candidates.len() as u64, last_pk: None })
    }

    /// Re-validates every SET'd REFERENCES/KVREF/JSONREF cell against its
    /// target (spec rel/012 §2); unchanged link cells stay "valid enough".
    async fn check_updated_references(
        &self,
        domain: &str,
        prefix: &[u8],
        sets: &[(ColumnDef, ScalarValue)],
        snap: &Snapshot,
        auth: LinkAuth,
    ) -> Result<(), RelStoreError> {
        for (c, v) in sets {
            if c.references.is_some() && !matches!(c.col_type, ColumnType::KvRef | ColumnType::JsonRef) {
                self.check_reference(domain, prefix, c, v, snap).await?;
            }
            if matches!(c.col_type, ColumnType::KvRef | ColumnType::JsonRef) {
                if let ScalarValue::Text(key) = v {
                    self.validate_cross_engine_link(domain, c, key, auth).await?;
                }
            }
        }
        Ok(())
    }

    /// Diffs only indexes over changed columns (spec §8): UNIQUE re-check,
    /// then delete-old/put-new index entries.
    async fn diff_update_indexes(
        &self,
        schema: &TableSchema,
        prefix: &[u8],
        old: &HashMap<u16, ScalarValue>,
        new: &HashMap<u16, ScalarValue>,
        set_ids: &HashSet<u16>,
        pk_enc: &[u8],
        seen_unique: &mut HashSet<(u32, Vec<u8>)>,
        ops: &mut Vec<BatchOp>,
    ) -> Result<(), RelStoreError> {
        for ix in &schema.indexes {
            let Some(col) = schema.columns.iter().find(|c| c.name == ix.column) else {
                continue;
            };
            if !set_ids.contains(&col.col_id) {
                continue;
            }
            let new_v = new.get(&col.col_id).unwrap_or(&ScalarValue::Null);
            if ix.unique {
                if let Some(val_enc) = encode_sortable(new_v) {
                    self.check_unique(prefix, ix, &val_enc, pk_enc, seen_unique).await?;
                }
            }
            if let Some(oe) = old.get(&col.col_id).and_then(encode_sortable) {
                ops.push(BatchOp::Delete { key: keys::index_key(prefix, ix.index_id, &oe, pk_enc) });
            }
            if let Some(ne) = encode_sortable(new_v) {
                let k = keys::index_key(prefix, ix.index_id, &ne, pk_enc);
                self.guard_key_len(&k)?;
                ops.push(BatchOp::Put { key: k, value: Vec::new() });
            }
        }
        Ok(())
    }

    // ── DELETE (spec §11) ───────────────────────────────────────────────────

    async fn exec_delete(
        &self,
        domain: &str,
        del: Delete,
        params: &[Value],
    ) -> Result<DmlResult, RelStoreError> {
        let (dom, schema) = self.require_table(domain, &del.table)?;
        let prefix = &dom.system_prefix;
        let quals = vec![schema.name.clone()];

        let lock = self.table_locks.get(prefix, schema.table_id);
        let _guard = lock.lock().await;
        let snapshot = self.engine.snapshot();
        let snap = snapshot.snapshot();
        let candidates = self
            .acquire_candidates(&dom, &schema, &del.where_clause, &quals, params, snap)
            .await?;

        let mut ops: Vec<BatchOp> = Vec::new();
        for cand in &candidates {
            let values = values_by_col_id(&schema, &cand.values);
            let pk_enc = pk_enc_of(&schema, &values)?;
            for k in row_index_keys(&schema, &values, prefix, &pk_enc) {
                ops.push(BatchOp::Delete { key: k });
            }
            ops.push(BatchOp::Delete { key: cand.key.clone() });
        }

        self.commit_guarded(domain, ops).await?;
        self.metrics.record_rel_dml_statement("delete");
        Ok(DmlResult { affected: candidates.len() as u64, last_pk: None })
    }

    // ── Candidate acquisition (spec §7) ─────────────────────────────────────

    async fn acquire_candidates(
        &self,
        dom: &RelDomain,
        schema: &TableSchema,
        where_clause: &Option<Expr>,
        quals: &[String],
        params: &[Value],
        snap: &Snapshot,
    ) -> Result<Vec<Candidate>, RelStoreError> {
        let prefix = &dom.system_prefix;
        if let Some(expr) = where_clause {
            if let Some(pk_value) = try_pk_point(schema, expr, quals, params)? {
                let Some(pk_enc) = encode_sortable(&pk_value) else {
                    return Ok(Vec::new());
                };
                let key = keys::row_key(prefix, schema.table_id, &pk_enc);
                return Ok(match self.engine.get_with_snapshot(&key, snap).await?.into_option() {
                    Some(bytes) => vec![Candidate { values: decode_row(&bytes, schema), key }],
                    None => Vec::new(),
                });
            }
        }

        let pred = match where_clause {
            Some(e) => Some(bind_predicate(e, schema, quals, params)?),
            None => None,
        };
        let keys = self.engine.scan_keys(&keys::row_table_prefix(prefix, schema.table_id)).await?;
        let mut out = Vec::new();
        let mut scanned = 0u64;
        for key in keys {
            let Some(bytes) = self.engine.get_with_snapshot(&key, snap).await?.into_option() else {
                continue;
            };
            scanned += 1;
            let values = decode_row(&bytes, schema);
            let keep = match &pred {
                Some(p) => matches!(eval(p, &values), Bool3::True),
                None => true,
            };
            if keep {
                out.push(Candidate { key, values });
            }
        }
        self.metrics.record_rel_dml_scanned_rows(scanned);
        Ok(out)
    }

    // ── Validation helpers (spec §8.4) ──────────────────────────────────────

    fn validate_not_null_and_text(
        &self,
        schema: &TableSchema,
        values: &HashMap<u16, ScalarValue>,
    ) -> Result<(), RelStoreError> {
        for c in &schema.columns {
            let v = values.get(&c.col_id).unwrap_or(&ScalarValue::Null);
            if matches!(v, ScalarValue::Null) && !c.nullable {
                return Err(RelStoreError::NotNull {
                    table: schema.name.clone(),
                    column: c.name.clone(),
                });
            }
            if let ScalarValue::Text(s) = v {
                if s.len() > self.max_text_len {
                    return Err(RelStoreError::TextTooLong { len: s.len(), max: self.max_text_len });
                }
            }
        }
        Ok(())
    }

    async fn check_row_unique(
        &self,
        schema: &TableSchema,
        values: &HashMap<u16, ScalarValue>,
        prefix: &[u8],
        pk_enc: &[u8],
        seen: &mut HashSet<(u32, Vec<u8>)>,
    ) -> Result<(), RelStoreError> {
        for ix in schema.indexes.iter().filter(|ix| ix.unique) {
            let Some(col) = schema.columns.iter().find(|c| c.name == ix.column) else {
                continue;
            };
            if let Some(val_enc) = values.get(&col.col_id).and_then(encode_sortable) {
                self.check_unique(prefix, ix, &val_enc, pk_enc, seen).await?;
            }
        }
        Ok(())
    }

    /// A non-NULL value on a unique index must not exist under a different PK,
    /// nor be duplicated within this statement.
    async fn check_unique(
        &self,
        prefix: &[u8],
        ix: &super::catalog::IndexMeta,
        val_enc: &[u8],
        pk_enc: &[u8],
        seen: &mut HashSet<(u32, Vec<u8>)>,
    ) -> Result<(), RelStoreError> {
        let scan = keys::index_value_prefix(prefix, ix.index_id, val_enc);
        let our = keys::index_key(prefix, ix.index_id, val_enc, pk_enc);
        for k in self.engine.scan_keys(&scan).await? {
            if k != our {
                return Err(RelStoreError::UniqueViolation { index: ix.name.clone() });
            }
        }
        if !seen.insert((ix.index_id, val_enc.to_vec())) {
            return Err(RelStoreError::UniqueViolation { index: ix.name.clone() });
        }
        Ok(())
    }

    async fn check_row_references(
        &self,
        domain: &str,
        schema: &TableSchema,
        values: &HashMap<u16, ScalarValue>,
        prefix: &[u8],
        snap: &Snapshot,
    ) -> Result<(), RelStoreError> {
        for c in &schema.columns {
            if c.references.is_none() || matches!(c.col_type, ColumnType::KvRef | ColumnType::JsonRef)
            {
                continue;
            }
            if let Some(v) = values.get(&c.col_id) {
                if !matches!(v, ScalarValue::Null) {
                    self.check_reference(domain, prefix, c, v, snap).await?;
                }
            }
        }
        Ok(())
    }

    async fn check_reference(
        &self,
        domain: &str,
        prefix: &[u8],
        col: &ColumnDef,
        value: &ScalarValue,
        snap: &Snapshot,
    ) -> Result<(), RelStoreError> {
        let target = col.references.as_ref().expect("caller guards references.is_some");
        let missing = || RelStoreError::LinkTargetMissing {
            column: col.name.clone(),
            target: target.clone(),
        };
        let table_id = match self.catalog.get(&self.domains, domain, target) {
            Ok(CatalogEntry::Table(t)) => t.table_id,
            _ => return Err(missing()),
        };
        let Some(pk_enc) = encode_sortable(value) else {
            return Ok(());
        };
        let key = keys::row_key(prefix, table_id, &pk_enc);
        if self.engine.get_with_snapshot(&key, snap).await?.into_option().is_none() {
            return Err(missing());
        }
        Ok(())
    }

    /// Cross-engine link validation (spec rel/012 §2): every non-NULL
    /// KVREF/JSONREF cell must resolve to an existing key/document in the
    /// same-named target domain. Runs inside the rel/005 §8 chain, before the
    /// `WriteBatch`, under the held table write lock — but the cross-engine
    /// read is *not* part of the rel batch (no cross-engine atomicity, §6).
    async fn check_row_cross_engine_links(
        &self,
        domain: &str,
        schema: &TableSchema,
        values: &HashMap<u16, ScalarValue>,
        auth: LinkAuth,
    ) -> Result<(), RelStoreError> {
        for c in &schema.columns {
            if !matches!(c.col_type, ColumnType::KvRef | ColumnType::JsonRef) {
                continue;
            }
            if let Some(ScalarValue::Text(key)) = values.get(&c.col_id) {
                self.validate_cross_engine_link(domain, c, key, auth).await?;
            }
        }
        Ok(())
    }

    /// Validates one non-NULL link value against its same-named target domain
    /// (existence suffices — a null-value key *exists*). Missing read access
    /// (`auth`, spec rel/016) is rejected first, before any existence lookup
    /// and without charging the write-validation metric — otherwise an
    /// unauthorized caller could distinguish an existing from a missing key,
    /// exactly the oracle this spec closes. `DomainUnavailable`
    /// (disabled/gone/`Deleting`) and `Absent` (active but missing) map to the
    /// two 409 variants (spec §2/§7).
    async fn validate_cross_engine_link(
        &self,
        domain: &str,
        col: &ColumnDef,
        key: &str,
        auth: LinkAuth,
    ) -> Result<(), RelStoreError> {
        match col.col_type {
            ColumnType::KvRef => {
                if !auth.kv_read {
                    return Err(RelStoreError::CrossEngineForbidden { engine: "kv".to_string() });
                }
                self.cross_engine.record_write_validation("kv");
                match self.cross_engine.kv_lookup(domain, key).await? {
                    KvResolution::DomainUnavailable => Err(RelStoreError::CrossEngineTargetUnavailable {
                        engine: "kv".to_string(),
                        domain: Some(domain.to_string()),
                    }),
                    KvResolution::Absent => Err(RelStoreError::CrossEngineLinkMissing {
                        column: col.name.clone(),
                        engine: "kv".to_string(),
                        target: key.to_string(),
                    }),
                    KvResolution::Present(_) | KvResolution::NullValue => Ok(()),
                }
            }
            ColumnType::JsonRef => {
                if !auth.json_read {
                    return Err(RelStoreError::CrossEngineForbidden { engine: "json".to_string() });
                }
                self.cross_engine.record_write_validation("json");
                match self.cross_engine.json_lookup(domain, key).await? {
                    JsonResolution::DomainUnavailable => Err(RelStoreError::CrossEngineTargetUnavailable {
                        engine: "json".to_string(),
                        domain: Some(domain.to_string()),
                    }),
                    JsonResolution::Absent => Err(RelStoreError::CrossEngineLinkMissing {
                        column: col.name.clone(),
                        engine: "json".to_string(),
                        target: key.to_string(),
                    }),
                    JsonResolution::Present(_) => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }

    async fn read_seq(
        &self,
        prefix: &[u8],
        table_id: u32,
        snap: &Snapshot,
    ) -> Result<u64, RelStoreError> {
        let key = keys::seq_key(prefix, table_id);
        match self.engine.get_with_snapshot(&key, snap).await?.into_option() {
            Some(b) if b.len() == 8 => Ok(u64::from_be_bytes(b.try_into().unwrap())),
            _ => Ok(0),
        }
    }

    fn guard_key_len(&self, key: &[u8]) -> Result<(), RelStoreError> {
        if key.len() > self.max_key_length {
            return Err(RelStoreError::KeyTooLong { len: key.len(), max: self.max_key_length });
        }
        Ok(())
    }

    /// Commits a DML `WriteBatch` under the engine-global write guard, first
    /// re-checking the domain is still active (spec rel/013 §3). A writer that
    /// passed `require_active` before a concurrent `delete_domain` must abort
    /// with 410/404 here rather than land keys after the purger finalized the
    /// domain — otherwise an orphan `ROW:` key could resurrect under a recreated
    /// same-name domain. The guard is the same one the purger holds around its
    /// emptiness check + finalization.
    async fn commit_guarded(&self, domain: &str, ops: Vec<BatchOp>) -> Result<(), RelStoreError> {
        let _wg = self.write_guard.lock().await;
        self.domains.require_active(domain)?;
        self.engine.write_batch(ops).await?;
        Ok(())
    }
}

// ── Column/value binding (spec §5) ──────────────────────────────────────────

fn resolve_insert_columns(
    schema: &TableSchema,
    ins: &Insert,
) -> Result<Vec<ColumnDef>, RelStoreError> {
    match &ins.columns {
        None => Ok(schema.columns.clone()),
        Some(names) => {
            let mut seen = HashSet::new();
            let mut cols = Vec::with_capacity(names.len());
            for n in names {
                if !seen.insert(n.clone()) {
                    return Err(RelStoreError::InvalidSchema(format!(
                        "duplicate column '{n}' in INSERT column list"
                    )));
                }
                let c = schema.columns.iter().find(|c| &c.name == n).ok_or_else(|| {
                    RelStoreError::ColumnNotFound { table: schema.name.clone(), name: n.clone() }
                })?;
                cols.push(c.clone());
            }
            Ok(cols)
        }
    }
}

/// Resolves a DEFAULT for an omitted INSERT column. `None` = AUTOINCREMENT PK
/// (assigned from the sequence under the write lock); a non-nullable column
/// with no default yields `Null`, caught by the NOT NULL check.
fn resolve_default(col: &ColumnDef, now: i64) -> Option<ScalarValue> {
    match &col.default {
        DefaultValue::Literal(v) => Some(v.clone()),
        DefaultValue::CurrentTimestamp => Some(ScalarValue::Timestamp(now)),
        DefaultValue::Null => Some(ScalarValue::Null),
        DefaultValue::None if col.autoincrement => None,
        DefaultValue::None => Some(ScalarValue::Null),
    }
}

/// Binds every INSERT row's target-column operands, then fills any omitted
/// column with its DEFAULT (`needs_auto` marks an omitted AUTOINCREMENT PK,
/// filled later under the write lock).
fn build_row_plans(
    schema: &TableSchema,
    target_cols: &[ColumnDef],
    rows: &[Vec<Operand>],
    params: &[Value],
    now: i64,
) -> Result<Vec<RowPlan>, RelStoreError> {
    let mut out: Vec<RowPlan> = Vec::with_capacity(rows.len());
    for row_ops in rows {
        if row_ops.len() != target_cols.len() {
            return Err(RelStoreError::InvalidSchema(format!(
                "INSERT has {} values but {} target columns",
                row_ops.len(),
                target_cols.len()
            )));
        }
        let mut values = HashMap::new();
        for (c, op) in target_cols.iter().zip(row_ops) {
            values.insert(c.col_id, bind_value(c, op, params)?);
        }
        let mut needs_auto = false;
        for c in &schema.columns {
            if values.contains_key(&c.col_id) {
                continue;
            }
            match resolve_default(c, now) {
                Some(v) => {
                    values.insert(c.col_id, v);
                }
                None => needs_auto = true, // AUTOINCREMENT PK, filled under lock
            }
        }
        out.push(RowPlan { values, needs_auto });
    }
    Ok(out)
}

/// AUTOINCREMENT high-water (spec §9): assigns the next sequence value to
/// every row still needing one, raises the high-water for explicit larger
/// PKs. Returns the new high-water for the caller's seq-key write-back.
fn assign_autoincrement(
    pk_col: &ColumnDef,
    rows: &mut [RowPlan],
    hw0: u64,
    table_name: &str,
) -> Result<u64, RelStoreError> {
    let mut hw = hw0;
    for row in rows {
        if !row.needs_auto {
            if let Some(ScalarValue::Integer(v)) = row.values.get(&pk_col.col_id) {
                if *v > 0 {
                    hw = hw.max(*v as u64);
                }
            }
            continue;
        }
        if hw >= i64::MAX as u64 {
            return Err(RelStoreError::SequenceExhausted { table: table_name.to_string() });
        }
        hw += 1;
        row.values.insert(pk_col.col_id, ScalarValue::Integer(hw as i64));
    }
    Ok(hw)
}

/// Binds every UPDATE assignment's target column and value, rejecting a SET
/// on the PK column immediately (spec §10).
fn bind_update_assignments(
    schema: &TableSchema,
    assignments: &[Assignment],
    params: &[Value],
) -> Result<Vec<(ColumnDef, ScalarValue)>, RelStoreError> {
    let mut sets = Vec::with_capacity(assignments.len());
    for a in assignments {
        let c = schema
            .columns
            .iter()
            .find(|c| c.name == a.column)
            .ok_or_else(|| RelStoreError::ColumnNotFound {
                table: schema.name.clone(),
                name: a.column.clone(),
            })?;
        if c.primary_key {
            return Err(RelStoreError::PrimaryKeyImmutable {
                table: schema.name.clone(),
                column: c.name.clone(),
            });
        }
        sets.push((c.clone(), bind_value(c, &a.value, params)?));
    }
    Ok(sets)
}

/// `pub(super)`: reused by the SELECT planner (rel/006 `plan.rs`) to bind a
/// sargable conjunct's literal/param side against its resolved column.
pub(super) fn bind_value(col: &ColumnDef, op: &Operand, params: &[Value]) -> Result<ScalarValue, RelStoreError> {
    bind_operand_value(col.col_type, op, params, &col.name)
}

/// `pub(super)`: reused by the multi-binding join WHERE binder (rel/007 `join.rs`).
pub(super) fn bind_operand_value(
    t: ColumnType,
    op: &Operand,
    params: &[Value],
    ctx: &str,
) -> Result<ScalarValue, RelStoreError> {
    match op {
        Operand::Literal(l) => coerce_literal(t, l, ctx),
        Operand::Param(i) => {
            let v = params.get(*i).ok_or_else(|| {
                RelStoreError::InvalidSchema(format!("parameter ${i} out of range"))
            })?;
            coerce_json(t, v, ctx)
        }
        Operand::Column(_) => Err(type_mismatch(t, "column reference", ctx)),
    }
}

/// `pub(super)`: reused by the multi-binding join WHERE binder (rel/007 `join.rs`).
pub(super) fn coerce_literal(t: ColumnType, lit: &Literal, ctx: &str) -> Result<ScalarValue, RelStoreError> {
    match lit {
        Literal::Null => Ok(ScalarValue::Null),
        Literal::Integer(x) => match t.physical_type() {
            ColumnType::Integer => Ok(ScalarValue::Integer(*x)),
            ColumnType::Real => Ok(ScalarValue::Real(*x as f64)),
            ColumnType::Timestamp => Ok(ScalarValue::Timestamp(*x)),
            _ => Err(type_mismatch(t, "integer", ctx)),
        },
        Literal::Real(f) => match t.physical_type() {
            ColumnType::Real => Ok(ScalarValue::Real(*f)),
            _ => Err(type_mismatch(t, "real", ctx)),
        },
        Literal::Text(s) => match t.physical_type() {
            ColumnType::Text => Ok(ScalarValue::Text(s.clone())),
            ColumnType::Timestamp => parse_iso8601_millis(s)
                .map(ScalarValue::Timestamp)
                .ok_or_else(|| timestamp_mismatch(ctx)),
            _ => Err(type_mismatch(t, "text", ctx)),
        },
        Literal::Boolean(b) => match t.physical_type() {
            ColumnType::Boolean => Ok(ScalarValue::Boolean(*b)),
            _ => Err(type_mismatch(t, "boolean", ctx)),
        },
    }
}

pub(super) fn coerce_json(t: ColumnType, v: &Value, ctx: &str) -> Result<ScalarValue, RelStoreError> {
    match v {
        Value::Null => Ok(ScalarValue::Null),
        Value::Bool(b) => match t.physical_type() {
            ColumnType::Boolean => Ok(ScalarValue::Boolean(*b)),
            _ => Err(type_mismatch(t, "boolean", ctx)),
        },
        Value::Number(n) => match t.physical_type() {
            ColumnType::Integer => n.as_i64().map(ScalarValue::Integer).ok_or_else(|| type_mismatch(t, "integer", ctx)),
            // serde_json's `Number` cannot hold NaN/±Inf (rejected at parse and by
            // `Number::from_f64`), so `as_f64()` is always finite here; the only
            // reachable non-finite source, a REAL literal, is rejected in the lexer.
            ColumnType::Real => n.as_f64().map(ScalarValue::Real).ok_or_else(|| type_mismatch(t, "real", ctx)),
            ColumnType::Timestamp => n.as_i64().map(ScalarValue::Timestamp).ok_or_else(|| type_mismatch(t, "timestamp", ctx)),
            _ => Err(type_mismatch(t, "number", ctx)),
        },
        Value::String(s) => match t.physical_type() {
            ColumnType::Text => Ok(ScalarValue::Text(s.clone())),
            ColumnType::Timestamp => parse_iso8601_millis(s)
                .map(ScalarValue::Timestamp)
                .ok_or_else(|| timestamp_mismatch(ctx)),
            _ => Err(type_mismatch(t, "text", ctx)),
        },
        Value::Array(_) | Value::Object(_) => Err(type_mismatch(t, "array/object", ctx)),
    }
}

fn type_mismatch(expected: ColumnType, actual: &str, ctx: &str) -> RelStoreError {
    RelStoreError::TypeMismatch {
        context: format!("value for {ctx}"),
        expected: format!("{expected:?}"),
        actual: actual.to_string(),
    }
}

fn timestamp_mismatch(ctx: &str) -> RelStoreError {
    RelStoreError::TypeMismatch {
        context: format!("TIMESTAMP value for {ctx}"),
        expected: "UTC ISO-8601 or millis".to_string(),
        actual: "unparseable".to_string(),
    }
}

// ── WHERE binding (spec §5-6) ───────────────────────────────────────────────

/// Table name plus SELECT alias — the qualifiers a column ref may carry.
///
/// `pub(super)`: reused by the SELECT executor (rel/006 `select.rs`/`plan.rs`).
pub(super) fn accepted_quals(schema: &TableSchema, sel: &Select) -> Vec<String> {
    let mut q = vec![schema.name.clone()];
    if let Some(alias) = &sel.from.alias {
        q.push(alias.clone());
    }
    q
}

/// `pub(super)`: reused by the SELECT executor (rel/006 `select.rs`/`plan.rs`)
/// for projection/ORDER BY binding and sargable-conjunct column resolution.
pub(super) fn resolve_column<'a>(
    cref: &super::ast::ColumnRef,
    schema: &'a TableSchema,
    quals: &[String],
) -> Result<(usize, &'a ColumnDef), RelStoreError> {
    if let Some(q) = &cref.qualifier {
        if !quals.iter().any(|a| a == q) {
            return Err(RelStoreError::ColumnNotFound {
                table: schema.name.clone(),
                name: format!("{q}.{}", cref.name),
            });
        }
    }
    let pos = schema.columns.iter().position(|c| c.name == cref.name).ok_or_else(|| {
        RelStoreError::ColumnNotFound { table: schema.name.clone(), name: cref.name.clone() }
    })?;
    Ok((pos, &schema.columns[pos]))
}

/// `pub(super)`: the SELECT executor (rel/006 §4) reuses this WHERE binder
/// unchanged for its residual predicate — rel/005's evaluator/binder is not
/// duplicated.
pub(super) fn bind_predicate(
    expr: &Expr,
    schema: &TableSchema,
    quals: &[String],
    params: &[Value],
) -> Result<Pred, RelStoreError> {
    match expr {
        Expr::Paren(e) => bind_predicate(e, schema, quals, params),
        Expr::Not(e) => Ok(Pred::Not(Box::new(bind_predicate(e, schema, quals, params)?))),
        Expr::And(a, b) => Ok(Pred::And(
            Box::new(bind_predicate(a, schema, quals, params)?),
            Box::new(bind_predicate(b, schema, quals, params)?),
        )),
        Expr::Or(a, b) => Ok(Pred::Or(
            Box::new(bind_predicate(a, schema, quals, params)?),
            Box::new(bind_predicate(b, schema, quals, params)?),
        )),
        Expr::Compare { lhs, op, rhs } => bind_compare(lhs, *op, rhs, schema, quals, params),
        Expr::In { col, negated, list } => {
            let (pos, c) = resolve_column(col, schema, quals)?;
            let list = list
                .iter()
                .map(|l| {
                    let t = widen_predicate_hint(c.col_type, matches!(l, Literal::Real(_)));
                    coerce_literal(t, l, &c.name)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Pred::In { col: pos, negated: *negated, list })
        }
        Expr::Like { col, negated, pattern } => {
            let (pos, c) = resolve_column(col, schema, quals)?;
            if !matches!(c.col_type.physical_type(), ColumnType::Text) {
                return Err(RelStoreError::TypeMismatch {
                    context: format!("LIKE on column '{}'", c.name),
                    expected: "Text".to_string(),
                    actual: format!("{:?}", c.col_type),
                });
            }
            Ok(Pred::Like { col: pos, negated: *negated, pattern: pattern.clone() })
        }
        Expr::IsNull { col, negated } => {
            let (pos, _) = resolve_column(col, schema, quals)?;
            Ok(Pred::IsNull { col: pos, negated: *negated })
        }
    }
}

fn bind_compare(
    lhs: &Operand,
    op: CompareOp,
    rhs: &Operand,
    schema: &TableSchema,
    quals: &[String],
    params: &[Value],
) -> Result<Pred, RelStoreError> {
    let hint = operand_column_type(lhs, schema, quals).or_else(|| operand_column_type(rhs, schema, quals));
    let bl = bind_pred_operand(lhs, schema, quals, hint, params)?;
    let br = bind_pred_operand(rhs, schema, quals, hint, params)?;
    if !comparable(effective_type(&bl, schema), effective_type(&br, schema)) {
        return Err(RelStoreError::TypeMismatch {
            context: "WHERE comparison".to_string(),
            expected: "compatible operand types".to_string(),
            actual: "incompatible".to_string(),
        });
    }
    Ok(Pred::Compare { lhs: bl, op, rhs: br })
}

fn operand_column_type(op: &Operand, schema: &TableSchema, quals: &[String]) -> Option<ColumnType> {
    match op {
        Operand::Column(cref) => resolve_column(cref, schema, quals).ok().map(|(_, c)| c.col_type),
        _ => None,
    }
}

fn bind_pred_operand(
    op: &Operand,
    schema: &TableSchema,
    quals: &[String],
    hint: Option<ColumnType>,
    params: &[Value],
) -> Result<PredOperand, RelStoreError> {
    match op {
        Operand::Column(cref) => {
            let (pos, _) = resolve_column(cref, schema, quals)?;
            Ok(PredOperand::Column(pos))
        }
        _ => {
            let natural = natural_type(op, params);
            let t = match hint {
                Some(h) => widen_predicate_hint(h, natural == ColumnType::Real),
                None => natural,
            };
            Ok(PredOperand::Value(bind_operand_value(t, op, params, "WHERE comparison")?))
        }
    }
}

/// WHERE-only (spec §6): a REAL-natured literal/param compared against an
/// INTEGER-hinted column keeps its own REAL type instead of a lossy coercion
/// down to INTEGER — `comparable`/`eval::cmp_scalars` widen the INTEGER side
/// to `f64` at runtime instead (the one implicit widening). Every other hint
/// passes through unchanged, including INTEGER-literal-vs-REAL-column, which
/// `coerce_literal` already widens on its own. VALUES/SET binding
/// (`bind_value`/`bind_update_assignments`) never calls this — only WHERE
/// operand binding does, so a REAL value written into an INTEGER column is
/// still rejected as lossy.
///
/// `pub(super)`: reused by the multi-binding join WHERE binder (rel/007
/// `join.rs`), which mirrors this predicate binding for joined tables.
pub(super) fn widen_predicate_hint(hint: ColumnType, is_real_valued: bool) -> ColumnType {
    if hint == ColumnType::Integer && is_real_valued {
        ColumnType::Real
    } else {
        hint
    }
}

/// `pub(super)`: reused by the multi-binding join WHERE binder (rel/007 `join.rs`).
pub(super) fn natural_type(op: &Operand, params: &[Value]) -> ColumnType {
    match op {
        Operand::Literal(Literal::Real(_)) => ColumnType::Real,
        Operand::Literal(Literal::Text(_)) => ColumnType::Text,
        Operand::Literal(Literal::Boolean(_)) => ColumnType::Boolean,
        Operand::Param(i) => match params.get(*i) {
            Some(Value::Bool(_)) => ColumnType::Boolean,
            Some(Value::String(_)) => ColumnType::Text,
            Some(Value::Number(n)) if n.as_i64().is_none() => ColumnType::Real,
            _ => ColumnType::Integer,
        },
        _ => ColumnType::Integer,
    }
}

fn effective_type(op: &PredOperand, schema: &TableSchema) -> Option<ColumnType> {
    match op {
        PredOperand::Column(pos) => Some(schema.columns[*pos].col_type.physical_type()),
        PredOperand::Value(v) => scalar_physical_type(v),
    }
}

/// `pub(super)`: reused by the multi-binding join WHERE binder (rel/007 `join.rs`).
pub(super) fn scalar_physical_type(v: &ScalarValue) -> Option<ColumnType> {
    match v {
        ScalarValue::Integer(_) => Some(ColumnType::Integer),
        ScalarValue::Real(_) => Some(ColumnType::Real),
        ScalarValue::Text(_) => Some(ColumnType::Text),
        ScalarValue::Boolean(_) => Some(ColumnType::Boolean),
        ScalarValue::Timestamp(_) => Some(ColumnType::Timestamp),
        ScalarValue::Null => None,
    }
}

/// `pub(super)`: reused by the ON type-check and the multi-binding join
/// WHERE binder (rel/007 `join.rs`).
pub(super) fn comparable(a: Option<ColumnType>, b: Option<ColumnType>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => {
            x == y
                || matches!(
                    (x, y),
                    (ColumnType::Integer, ColumnType::Real) | (ColumnType::Real, ColumnType::Integer)
                )
        }
        _ => true, // a NULL operand → runtime Unknown, not a bind-time error
    }
}

/// Recognizes `pk = literal|param` (either operand order); returns the bound PK
/// value or `None` if the shape does not match (spec §7/§12).
fn try_pk_point(
    schema: &TableSchema,
    expr: &Expr,
    quals: &[String],
    params: &[Value],
) -> Result<Option<ScalarValue>, RelStoreError> {
    let mut e = expr;
    while let Expr::Paren(inner) = e {
        e = inner;
    }
    let Expr::Compare { lhs, op: CompareOp::Eq, rhs } = e else {
        return Ok(None);
    };
    let pk = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
    let value_op = if is_pk_column(lhs, pk, quals) && is_value(rhs) {
        rhs
    } else if is_pk_column(rhs, pk, quals) && is_value(lhs) {
        lhs
    } else {
        return Ok(None);
    };
    let v = bind_value(pk, value_op, params)?;
    if matches!(v, ScalarValue::Null) {
        return Ok(None);
    }
    Ok(Some(v))
}

fn is_pk_column(op: &Operand, pk: &ColumnDef, quals: &[String]) -> bool {
    match op {
        Operand::Column(cref) => {
            cref.name == pk.name
                && cref.qualifier.as_ref().is_none_or(|q| quals.iter().any(|a| a == q))
        }
        _ => false,
    }
}

/// `pub(super)`: reused by the SELECT planner (rel/006 `plan.rs`).
pub(super) fn is_value(op: &Operand) -> bool {
    matches!(op, Operand::Literal(_) | Operand::Param(_))
}

// ── Row helpers ──────────────────────────────────────────────────────────────

fn values_by_col_id(schema: &TableSchema, values: &[ScalarValue]) -> HashMap<u16, ScalarValue> {
    schema.columns.iter().zip(values).map(|(c, v)| (c.col_id, v.clone())).collect()
}

fn pk_enc_of(schema: &TableSchema, values: &HashMap<u16, ScalarValue>) -> Result<Vec<u8>, RelStoreError> {
    let pk = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
    let v = values.get(&pk.col_id).unwrap_or(&ScalarValue::Null);
    encode_sortable(v).ok_or_else(|| RelStoreError::NotNull {
        table: schema.name.clone(),
        column: pk.name.clone(),
    })
}

/// All index-entry keys for a row (skipping NULL-valued indexes).
fn row_index_keys(
    schema: &TableSchema,
    values: &HashMap<u16, ScalarValue>,
    prefix: &[u8],
    pk_enc: &[u8],
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for ix in &schema.indexes {
        if let Some(col) = schema.columns.iter().find(|c| c.name == ix.column) {
            if let Some(val_enc) = values.get(&col.col_id).and_then(encode_sortable) {
                out.push(keys::index_key(prefix, ix.index_id, &val_enc, pk_enc));
            }
        }
    }
    out
}

// ── Time helpers (spec §5, no new crate) ────────────────────────────────────

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parses the UTC subset `YYYY-MM-DDThh:mm:ss[.fff][Z]` (also space for `T`,
/// missing `Z` = UTC) to epoch millis. Non-UTC offsets / bad format → `None`.
fn parse_iso8601_millis(s: &str) -> Option<i64> {
    let s = s.trim();
    let sep = s.find(['T', ' '])?;
    let (date, rest) = (&s[..sep], &s[sep + 1..]);

    let mut dp = date.split('-');
    let y: i64 = parse_digits(dp.next()?)?;
    let mo: u32 = parse_digits(dp.next()?)?;
    let d: u32 = parse_digits(dp.next()?)?;
    // Year bounded to the plain 4-digit range (matches `format_iso8601_millis`'s
    // zero-padded output in types.rs) so `days_from_civil` below can never
    // overflow i64, however many digits `parse_digits` accepted.
    if dp.next().is_some() || !(0..=9999).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }

    let time = rest.strip_suffix('Z').unwrap_or(rest);
    if time.contains('+') || time.contains('-') || time.contains('Z') {
        return None; // any offset (or a stray Z) → not UTC / malformed
    }
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (time, None),
    };
    let mut tp = hms.split(':');
    let hh: u32 = parse_digits(tp.next()?)?;
    let mi: u32 = parse_digits(tp.next()?)?;
    let ss: u32 = parse_digits(tp.next()?)?;
    if tp.next().is_some() || hh > 23 || mi > 59 || ss > 59 {
        return None;
    }
    let frac_ms: i64 = match frac {
        None => 0,
        Some(f) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) => {
            let mut ms = 0i64;
            for (i, ch) in f.chars().take(3).enumerate() {
                ms += (ch as i64 - '0' as i64) * 10i64.pow(2 - i as u32);
            }
            ms
        }
        Some(_) => return None,
    };

    let days = days_from_civil(y, mo, d);
    let secs = days * 86_400 + hh as i64 * 3_600 + mi as i64 * 60 + ss as i64;
    Some(secs * 1_000 + frac_ms)
}

fn parse_digits<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp: i64 = if m > 2 { (m - 3) as i64 } else { (m + 9) as i64 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use serde_json::json;
    use std::path::Path;

    fn config_in(dir: &Path) -> RelStoreConfig {
        RelStoreConfig {
            wal_path: dir.join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.join("ss").to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        }
    }

    async fn boot(config: RelStoreConfig) -> Arc<RelEngine> {
        let metrics = MetricsStore::new(MetricsConfig::default());
        let cross_engine = crate::engines::rel::CrossEngineResolver::disabled(Arc::clone(&metrics));
        RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap()
    }

    async fn make() -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(config_in(dir.path())).await;
        (rel, dir)
    }

    async fn run(rel: &RelEngine, sql: &str, params: &[Value]) -> Result<ExecOutcome, RelStoreError> {
        rel.execute("default", sql, params).await
    }

    async fn ok(rel: &RelEngine, sql: &str) {
        run(rel, sql, &[]).await.unwrap();
    }

    async fn dml(rel: &RelEngine, sql: &str, params: &[Value]) -> DmlResult {
        match run(rel, sql, params).await.unwrap() {
            ExecOutcome::Dml(r) => r,
            o => panic!("expected DML, got {o:?}"),
        }
    }

    async fn sel(rel: &RelEngine, sql: &str, params: &[Value]) -> SelectResult {
        match run(rel, sql, params).await.unwrap() {
            ExecOutcome::Select(r) => r,
            o => panic!("expected SELECT, got {o:?}"),
        }
    }

    async fn err(rel: &RelEngine, sql: &str, params: &[Value]) -> RelStoreError {
        run(rel, sql, params).await.unwrap_err()
    }

    fn table_of(rel: &RelEngine, name: &str) -> (Vec<u8>, TableSchema) {
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        match rel.get_object("default", name).unwrap() {
            CatalogEntry::Table(t) => (prefix, t),
            _ => panic!("not a table"),
        }
    }

    /// Count of raw IDX entries for the given index name of `table`.
    async fn index_count(rel: &RelEngine, table: &str, index: &str, val: ScalarValue) -> usize {
        let (prefix, schema) = table_of(rel, table);
        let ix = schema.indexes.iter().find(|i| i.name == index).expect("index exists");
        let val_enc = encode_sortable(&val).unwrap();
        let scan = keys::index_value_prefix(&prefix, ix.index_id, &val_enc);
        rel.engine().scan_keys(&scan).await.unwrap().len()
    }

    /// All raw IDX entries across the domain (used to prove nothing leaked).
    async fn all_index_entries(rel: &RelEngine) -> usize {
        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let mut p = b"IDX:".to_vec();
        p.extend_from_slice(&prefix);
        p.push(b':');
        rel.engine().scan_keys(&p).await.unwrap().len()
    }

    async fn row_count(rel: &RelEngine, table: &str) -> usize {
        let (prefix, schema) = table_of(rel, table);
        let scan = keys::row_table_prefix(&prefix, schema.table_id);
        rel.engine().scan_keys(&scan).await.unwrap().len()
    }

    // 3. INSERT single row, then PK-point SELECT returns identical values.
    #[tokio::test]
    async fn test_insert_and_pk_select() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)").await;
        let r = dml(&rel, "INSERT INTO t (id, name, age) VALUES (1, 'alice', 30)", &[]).await;
        assert_eq!(r.affected, 1);
        assert_eq!(r.last_pk, Some(ScalarValue::Integer(1)));

        let s = sel(&rel, "SELECT * FROM t WHERE id = ?", &[json!(1)]).await;
        assert_eq!(s.rows.len(), 1);
        assert_eq!(
            s.rows[0],
            vec![
                ScalarValue::Integer(1),
                ScalarValue::Text("alice".into()),
                ScalarValue::Integer(30)
            ]
        );
    }

    // 4. Multi-row INSERT is atomic: one bad row (missing link) leaves none.
    #[tokio::test]
    async fn test_multi_row_insert_atomic() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE parent (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO parent VALUES (1)").await;
        ok(&rel, "CREATE TABLE child (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent)").await;

        let e = err(&rel, "INSERT INTO child VALUES (1, 1), (2, 999)", &[]).await;
        assert!(matches!(e, RelStoreError::LinkTargetMissing { .. }), "got: {e}");
        assert_eq!(row_count(&rel, "child").await, 0, "no row of the statement survives");
    }

    // 5. AUTOINCREMENT: sequential; explicit larger PK lifts the sequence;
    //    DELETE never lowers it; the high-water survives a restart.
    #[tokio::test]
    async fn test_autoincrement_and_recovery() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(config_in(dir.path())).await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v INTEGER)").await;
        assert_eq!(dml(&rel, "INSERT INTO t (v) VALUES (10)", &[]).await.last_pk, Some(ScalarValue::Integer(1)));
        assert_eq!(dml(&rel, "INSERT INTO t (v) VALUES (20)", &[]).await.last_pk, Some(ScalarValue::Integer(2)));
        ok(&rel, "INSERT INTO t (id, v) VALUES (100, 30)").await; // explicit lifts hw
        assert_eq!(dml(&rel, "INSERT INTO t (v) VALUES (40)", &[]).await.last_pk, Some(ScalarValue::Integer(101)));
        ok(&rel, "DELETE FROM t WHERE id = 101").await; // does not lower the sequence
        assert_eq!(dml(&rel, "INSERT INTO t (v) VALUES (50)", &[]).await.last_pk, Some(ScalarValue::Integer(102)));

        rel.shutdown().await;
        let rel = boot(config_in(dir.path())).await;
        assert_eq!(
            dml(&rel, "INSERT INTO t (v) VALUES (60)", &[]).await.last_pk,
            Some(ScalarValue::Integer(103)),
            "the high-water must survive the restart"
        );
    }

    // 6. DEFAULT: literal, CURRENT_TIMESTAMP (= insert time), DEFAULT NULL.
    #[tokio::test]
    async fn test_defaults() {
        let (rel, _d) = make().await;
        ok(
            &rel,
            "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER DEFAULT 7, \
             ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, n TEXT DEFAULT NULL)",
        )
        .await;
        let before = now_millis();
        ok(&rel, "INSERT INTO t (id) VALUES (1)").await;
        let after = now_millis();

        let s = sel(&rel, "SELECT * FROM t WHERE id = 1", &[]).await;
        let row = &s.rows[0];
        assert_eq!(row[1], ScalarValue::Integer(7));
        match row[2] {
            ScalarValue::Timestamp(ms) => assert!(before <= ms && ms <= after, "insert-time ts"),
            ref v => panic!("expected timestamp, got {v:?}"),
        }
        assert_eq!(row[3], ScalarValue::Null);
    }

    // 7. NOT NULL: omitted or explicit NULL into a NOT NULL column → NotNull.
    #[tokio::test]
    async fn test_not_null() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL, note TEXT)").await;
        ok(&rel, "INSERT INTO t (id, name) VALUES (1, 'x')").await; // note → NULL ok
        assert!(matches!(err(&rel, "INSERT INTO t (id, note) VALUES (2, 'y')", &[]).await, RelStoreError::NotNull { .. }));
        assert!(matches!(err(&rel, "INSERT INTO t (id, name) VALUES (3, NULL)", &[]).await, RelStoreError::NotNull { .. }));
    }

    // 8. Type check: REAL literal into INTEGER → TypeMismatch; INTEGER into
    //    REAL is widened.
    #[tokio::test]
    async fn test_type_check_and_widening() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, i INTEGER, r REAL)").await;
        assert!(matches!(err(&rel, "INSERT INTO t (id, i) VALUES (1, 2.5)", &[]).await, RelStoreError::TypeMismatch { .. }));
        ok(&rel, "INSERT INTO t (id, r) VALUES (2, 3)").await;
        let s = sel(&rel, "SELECT r FROM t WHERE id = 2", &[]).await;
        assert_eq!(s.rows[0][0], ScalarValue::Real(3.0));
    }

    // 9. TIMESTAMP: ISO-8601 UTC string and millis number agree; non-UTC
    //    offset / garbage → TypeMismatch.
    #[tokio::test]
    async fn test_timestamp_input() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, ts TIMESTAMP)").await;
        let ms = parse_iso8601_millis("2026-01-01T00:00:00Z").unwrap();
        ok(&rel, "INSERT INTO t VALUES (1, '2026-01-01T00:00:00Z')").await;
        ok(&rel, &format!("INSERT INTO t VALUES (2, {ms})")).await;
        let a = sel(&rel, "SELECT ts FROM t WHERE id = 1", &[]).await;
        let b = sel(&rel, "SELECT ts FROM t WHERE id = 2", &[]).await;
        assert_eq!(a.rows[0][0], b.rows[0][0]);
        assert_eq!(a.rows[0][0], ScalarValue::Timestamp(ms));

        assert!(matches!(err(&rel, "INSERT INTO t VALUES (3, '2026-01-01T00:00:00+02:00')", &[]).await, RelStoreError::TypeMismatch { .. }));
        assert!(matches!(err(&rel, "INSERT INTO t VALUES (4, 'nonsense')", &[]).await, RelStoreError::TypeMismatch { .. }));
    }

    // 10. PK collision: duplicate insert and within-statement duplicate → 409.
    #[tokio::test]
    async fn test_pk_collision() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1)").await;
        assert!(matches!(err(&rel, "INSERT INTO t VALUES (1)", &[]).await, RelStoreError::DuplicateKey { .. }));
        assert!(matches!(err(&rel, "INSERT INTO t VALUES (2), (2)", &[]).await, RelStoreError::DuplicateKey { .. }));
    }

    // 11. UNIQUE: collision → 409; multiple NULLs in a UNIQUE column allowed.
    #[tokio::test]
    async fn test_unique_and_nulls() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, u INTEGER UNIQUE, x INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5, 0)").await;
        assert!(matches!(err(&rel, "INSERT INTO t VALUES (2, 5, 0)", &[]).await, RelStoreError::UniqueViolation { .. }));
        ok(&rel, "INSERT INTO t VALUES (3, NULL, 0)").await;
        ok(&rel, "INSERT INTO t VALUES (4, NULL, 0)").await; // multiple NULLs ok
    }

    // 12. REFERENCES: present target ok; missing → 409; NULL link unchecked.
    //     (Cross-engine KVREF/JSONREF validation needs real target engines —
    //     covered by the rel/012 tests in cross_engine.rs, not here.)
    #[tokio::test]
    async fn test_references() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE parent (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO parent VALUES (1)").await;
        ok(&rel, "CREATE TABLE child (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent)").await;
        ok(&rel, "INSERT INTO child VALUES (1, 1)").await;
        assert!(matches!(err(&rel, "INSERT INTO child VALUES (2, 999)", &[]).await, RelStoreError::LinkTargetMissing { .. }));
        ok(&rel, "INSERT INTO child VALUES (3, NULL)").await; // NULL link unchecked
    }

    // 13. Size guards: TextTooLong, RowTooLarge, KeyTooLong (not an LSM-500).
    #[tokio::test]
    async fn test_size_guards() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { max_text_len: 10, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)").await;
        let long = "x".repeat(20);
        assert!(matches!(err(&rel, &format!("INSERT INTO t VALUES (1, '{long}')"), &[]).await, RelStoreError::TextTooLong { .. }));

        let dir2 = tempfile::TempDir::new().unwrap();
        let rel2 = boot(RelStoreConfig { max_row_size: 16, ..config_in(dir2.path()) }).await;
        ok(&rel2, "CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)").await;
        assert!(matches!(err(&rel2, "INSERT INTO t VALUES (1, 'hello')", &[]).await, RelStoreError::RowTooLarge { .. }));

        let (rel3, _d3) = make().await;
        ok(&rel3, "CREATE TABLE t (k TEXT PRIMARY KEY)").await;
        let huge = "y".repeat(300); // ROW key > max_key_length (256)
        assert!(matches!(err(&rel3, &format!("INSERT INTO t VALUES ('{huge}')"), &[]).await, RelStoreError::KeyTooLong { .. }));
    }

    // 14. UPDATE swaps the changed index entry; unchanged index survives.
    #[tokio::test]
    async fn test_update_index_swap() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_a ON t (a)").await;
        ok(&rel, "CREATE INDEX idx_b ON t (b)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 10, 100)").await;
        assert_eq!(index_count(&rel, "t", "idx_a", ScalarValue::Integer(10)).await, 1);

        let r = dml(&rel, "UPDATE t SET a = 20 WHERE id = 1", &[]).await;
        assert_eq!(r.affected, 1);
        assert_eq!(index_count(&rel, "t", "idx_a", ScalarValue::Integer(10)).await, 0, "old gone");
        assert_eq!(index_count(&rel, "t", "idx_a", ScalarValue::Integer(20)).await, 1, "new there");
        assert_eq!(index_count(&rel, "t", "idx_b", ScalarValue::Integer(100)).await, 1, "unchanged survives");
    }

    // 15. UPDATE on the PK column → PrimaryKeyImmutable.
    #[tokio::test]
    async fn test_pk_immutable() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 0)").await;
        assert!(matches!(err(&rel, "UPDATE t SET id = 5 WHERE id = 1", &[]).await, RelStoreError::PrimaryKeyImmutable { .. }));
    }

    // 16. Full-scan UPDATE/DELETE: only matching rows; affected correct; no
    //     match → 0.
    #[tokio::test]
    async fn test_full_scan_update_delete() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, grp INTEGER, v INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 1, 10), (2, 1, 20), (3, 2, 30)").await;

        assert_eq!(dml(&rel, "UPDATE t SET v = 0 WHERE grp = 1", &[]).await.affected, 2);
        assert_eq!(sel(&rel, "SELECT v FROM t WHERE id = 1", &[]).await.rows[0][0], ScalarValue::Integer(0));
        assert_eq!(sel(&rel, "SELECT v FROM t WHERE id = 3", &[]).await.rows[0][0], ScalarValue::Integer(30));

        assert_eq!(dml(&rel, "DELETE FROM t WHERE grp = 2", &[]).await.affected, 1);
        assert_eq!(dml(&rel, "DELETE FROM t WHERE grp = 9", &[]).await.affected, 0);
        assert_eq!(row_count(&rel, "t").await, 2);
    }

    // UPDATE -> UniqueViolation: a SET introduces a UNIQUE-column collision
    // with another row (quality/007 prep work).
    #[tokio::test]
    async fn test_update_unique_violation() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, u INTEGER UNIQUE)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5), (2, 6)").await;
        assert!(matches!(
            err(&rel, "UPDATE t SET u = 5 WHERE id = 2", &[]).await,
            RelStoreError::UniqueViolation { .. }
        ));
    }

    // UPDATE -> LinkTargetMissing: the FK re-check runs over changed
    // REFERENCES columns, not just at INSERT time (quality/007 prep work).
    #[tokio::test]
    async fn test_update_link_target_missing() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE parent (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO parent VALUES (1)").await;
        ok(&rel, "CREATE TABLE child (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent)").await;
        ok(&rel, "INSERT INTO child VALUES (1, 1)").await;
        assert!(matches!(
            err(&rel, "UPDATE child SET pid = 999 WHERE id = 1", &[]).await,
            RelStoreError::LinkTargetMissing { .. }
        ));
    }

    // UPDATE -> TextTooLong / RowTooLarge: the same size guards as INSERT
    // apply on the UPDATE path (quality/007 prep work).
    #[tokio::test]
    async fn test_update_size_guards() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { max_text_len: 10, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)").await;
        ok(&rel, "INSERT INTO t (id) VALUES (1)").await;
        let long = "x".repeat(20);
        assert!(matches!(
            err(&rel, &format!("UPDATE t SET s = '{long}' WHERE id = 1"), &[]).await,
            RelStoreError::TextTooLong { .. }
        ));

        // Row encoding is a fixed 32 bytes for this schema with `s` NULL, and
        // 37 once `s` holds "hello" (rel/005 row.rs: 4B version+count + 2×2B
        // col_dir + 1B bitmap padded to slots_start=16 + 2×8B slots, +5B var).
        let dir2 = tempfile::TempDir::new().unwrap();
        let rel2 = boot(RelStoreConfig { max_row_size: 34, ..config_in(dir2.path()) }).await;
        ok(&rel2, "CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT)").await;
        ok(&rel2, "INSERT INTO t (id) VALUES (1)").await;
        assert!(matches!(
            err(&rel2, "UPDATE t SET s = 'hello' WHERE id = 1", &[]).await,
            RelStoreError::RowTooLarge { .. }
        ));
    }

    // 17. DELETE removes the row and all its index entries.
    #[tokio::test]
    async fn test_delete_clears_indexes() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_a ON t (a)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 10)").await;
        ok(&rel, "DELETE FROM t WHERE id = 1").await;
        assert_eq!(row_count(&rel, "t").await, 0);
        assert_eq!(all_index_entries(&rel).await, 0, "index entries gone too");
    }

    // 21. PK-point SELECT with projection: only chosen columns, in projection
    //     order; a missing row yields zero rows.
    #[tokio::test]
    async fn test_pk_select_projection() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b TEXT)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 10, 'x')").await;

        let s = sel(&rel, "SELECT b, id FROM t WHERE id = 1", &[]).await;
        assert_eq!(s.columns.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), vec!["b", "id"]);
        assert_eq!(s.rows[0], vec![ScalarValue::Text("x".into()), ScalarValue::Integer(1)]);

        assert!(sel(&rel, "SELECT * FROM t WHERE id = 2", &[]).await.rows.is_empty());
    }

    // 23. CREATE INDEX backfills existing rows; a UNIQUE backfill over a
    //     duplicate → UniqueViolation and leaves no entry and no IndexMeta.
    #[tokio::test]
    async fn test_create_index_backfill() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 10), (2, 20), (3, 10)").await;
        ok(&rel, "CREATE INDEX idx_a ON t (a)").await;
        assert_eq!(index_count(&rel, "t", "idx_a", ScalarValue::Integer(10)).await, 2);
        assert_eq!(index_count(&rel, "t", "idx_a", ScalarValue::Integer(20)).await, 1);
        assert_eq!(all_index_entries(&rel).await, 3);

        let e = err(&rel, "CREATE UNIQUE INDEX uidx ON t (a)", &[]).await;
        assert!(matches!(e, RelStoreError::UniqueViolation { .. }), "got: {e}");
        assert_eq!(all_index_entries(&rel).await, 3, "no half index left behind");
        let (_p, schema) = table_of(&rel, "t");
        assert!(!schema.indexes.iter().any(|i| i.name == "uidx"), "IndexMeta not committed");
    }

    // 24. DML target guards: missing table → 404; view → NotWritable (400);
    //     deleting domain → 410.
    #[tokio::test]
    async fn test_dml_target_guards() {
        let (rel, _d) = make().await;
        assert!(matches!(err(&rel, "INSERT INTO ghost VALUES (1)", &[]).await, RelStoreError::TableNotFound { .. }));

        rel.create_view("default", "v", "SELECT 1").await.unwrap();
        assert!(matches!(err(&rel, "INSERT INTO v VALUES (1)", &[]).await, RelStoreError::NotWritable { .. }));

        rel.create_domain("d2").await.unwrap();
        rel.execute("d2", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        rel.delete_domain("d2").await.unwrap();
        let e = rel.execute("d2", "INSERT INTO t VALUES (1)", &[]).await.unwrap_err();
        assert!(matches!(e, RelStoreError::DomainDeleting(_)), "got: {e}");
    }

    // Three-valued WHERE end-to-end: a NULL column value drops the row.
    #[tokio::test]
    async fn test_where_unknown_drops_row() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, NULL), (2, 5)").await;
        // a = 5 is Unknown for row 1 (NULL), True for row 2.
        assert_eq!(dml(&rel, "DELETE FROM t WHERE a = 5", &[]).await.affected, 1);
        assert_eq!(row_count(&rel, "t").await, 1);
    }

    // 005-F1: a REAL literal/param/IN-element compared against an INTEGER
    // column keeps its own REAL type and widens at eval time instead of
    // being lossily forced to INTEGER and rejected (spec §6: INTEGER<->REAL
    // is the one implicit widening, and it applies to literals/params too,
    // not only column-vs-column comparisons).
    #[tokio::test]
    async fn test_where_real_literal_widens_against_integer_column() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, i INTEGER, hit INTEGER DEFAULT 0)").await;
        ok(&rel, "INSERT INTO t (id, i) VALUES (1, 3)").await;
        ok(&rel, "INSERT INTO t (id, i) VALUES (2, 4)").await;

        // Literal: only i=4 is > 3.5 (pre-fix: TypeMismatch/400 on the bind).
        assert_eq!(dml(&rel, "UPDATE t SET hit = 1 WHERE i > 3.5", &[]).await.affected, 1);
        assert_eq!(sel(&rel, "SELECT hit FROM t WHERE id = 1", &[]).await.rows[0][0], ScalarValue::Integer(0));
        assert_eq!(sel(&rel, "SELECT hit FROM t WHERE id = 2", &[]).await.rows[0][0], ScalarValue::Integer(1));

        // A param arriving as a REAL number widens the same way.
        ok(&rel, "UPDATE t SET hit = 0 WHERE id = 2").await;
        assert_eq!(dml(&rel, "UPDATE t SET hit = 1 WHERE i > ?", &[json!(3.5)]).await.affected, 1);
        assert_eq!(sel(&rel, "SELECT hit FROM t WHERE id = 2", &[]).await.rows[0][0], ScalarValue::Integer(1));

        // IN-list with a REAL element against an INTEGER column: must bind
        // (not 400), and the REAL element must widen-match an equal row.
        assert_eq!(dml(&rel, "UPDATE t SET hit = 2 WHERE i IN (1, 2.5)", &[]).await.affected, 0);
        assert_eq!(dml(&rel, "UPDATE t SET hit = 4 WHERE i IN (4.0, 99)", &[]).await.affected, 1);
        assert_eq!(sel(&rel, "SELECT hit FROM t WHERE id = 2", &[]).await.rows[0][0], ScalarValue::Integer(4));

        // `= 3.0` behaves sensibly: matches the Integer row i=3.
        assert_eq!(dml(&rel, "UPDATE t SET hit = 3 WHERE i = 3.0", &[]).await.affected, 1);
        assert_eq!(sel(&rel, "SELECT hit FROM t WHERE id = 1", &[]).await.rows[0][0], ScalarValue::Integer(3));

        // Genuine type errors on the same column stay 400.
        assert!(matches!(err(&rel, "UPDATE t SET hit = 9 WHERE i > 'x'", &[]).await, RelStoreError::TypeMismatch { .. }));
    }

    // ISO-8601 parser corner cases (spec §5).
    #[test]
    fn test_iso8601_parser() {
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:01Z"), Some(1000));
        assert_eq!(parse_iso8601_millis("1970-01-01 00:00:00"), Some(0)); // space, no Z = UTC
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:00.5Z"), Some(500));
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:00.250Z"), Some(250));
        assert_eq!(parse_iso8601_millis("1970-01-01T00:00:00+01:00"), None); // non-UTC
        assert_eq!(parse_iso8601_millis("2026-13-01T00:00:00Z"), None); // bad month
        assert_eq!(parse_iso8601_millis("nonsense"), None);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    // 005-F2: an absurdly large ISO year must not overflow i64 (debug:
    // arithmetic-overflow panic ~ 500; release: wraps to a garbage
    // timestamp) — it must cleanly fail to parse instead. A normal date is
    // unaffected.
    #[test]
    fn test_iso8601_year_overflow_guard() {
        assert_eq!(parse_iso8601_millis("25000000000000001-01-01T00:00:00Z"), None);
        assert!(parse_iso8601_millis("2026-07-15T00:00:00Z").is_some(), "a normal date still parses");
    }

    #[tokio::test]
    async fn test_insert_rejects_absurd_iso_year() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, ts TIMESTAMP)").await;
        assert!(matches!(
            err(&rel, "INSERT INTO t VALUES (1, '25000000000000001-01-01T00:00:00Z')", &[]).await,
            RelStoreError::TypeMismatch { .. }
        ));
    }
}
