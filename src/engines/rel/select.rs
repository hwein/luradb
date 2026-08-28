//! SELECT executor (spec rel/006): Volcano pull-model operators, LIMIT/OFFSET,
//! ORDER BY (index order or in-memory sort), COUNT(*). Access-path selection
//! lives in `plan.rs`; the WHERE residual is bound via the rel/005 evaluator
//! (`dml::bind_predicate`/`eval::eval`), reused unchanged (spec §0 contract).
//!
//! The rel/005 PK-point SELECT is now just one access path (`AccessPath::PkPoint`,
//! §3) among several — this module replaces `dml.rs`'s old `exec_select`
//! entirely; there is exactly one SELECT path (spec §1).

use super::ast::{Limit, OrderItem, Select, SelectItem};
use super::catalog::{CatalogEntry, TableSchema};
use super::cross_engine::{LinkAuth, LinkMask};
use super::dml::{accepted_quals, resolve_column};
use super::error::RelStoreError;
use super::eval::{eval, Bool3, Pred};
use super::keys;
use super::plan::{self, AccessPath, RangeBounds};
use super::row::decode_row;
use super::types::{encode_sortable, ColumnType, ScalarValue};
use super::{ExecOutcome, RelEngine};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::reader::Snapshot;
use serde_json::Value;
use std::cmp::Ordering;
use std::future::Future;
use std::sync::Arc;

// ── PlanRow / SourceBinding (spec §2) ────────────────────────────────────────
//
// v1 always fills exactly one `SourceBinding` (the one table). rel/007 appends
// a second binding per join stage; `Filter`/`Sort`/`OffsetLimit`/projection all
// go through `PlanRow` rather than a flat `Vec<ScalarValue>`, so they need no
// change when that lands.

/// One source table's contribution to a `PlanRow` (spec §2). `Clone` is
/// needed by the rel/007 join operator: fan-out (n right-hand hits for one
/// left row) clones the shared left bindings once per output row.
#[derive(Debug, Clone)]
pub struct SourceBinding {
    pub table_id: u32,
    pub alias: String,
    pub values: Vec<ScalarValue>,
}

/// A row flowing through the pipeline, carrying its values per source table.
#[derive(Debug)]
pub struct PlanRow {
    pub bindings: Vec<SourceBinding>,
}

impl PlanRow {
    fn single(table_id: u32, alias: String, values: Vec<ScalarValue>) -> Self {
        Self { bindings: vec![SourceBinding { table_id, alias, values }] }
    }
}

// ── Volcano operator interface (spec §2) ─────────────────────────────────────
//
// `async fn` in a trait is not `dyn`-compatible (spec's Rust note); this
// project's established pattern for async traits (`StorageEngine`,
// `src/engines/mod.rs`) is RPITIT (`fn(&mut self) -> impl Future<...> + Send`),
// used here too. v1 needs no dynamic dispatch (no join yet), so the finitely
// many pipeline shapes (Filter/Sort present or not) are composed statically
// via generics and wrapped in the small `RowPipeline` enum below — this also
// sidesteps the "recursive async fn" sizing problem a `Box<dyn RowSource>`
// chain would need `Pin<Box<dyn Future>>` boxing for. rel/007's join operator
// will need `Box<dyn RowSource>` for its left input (per spec); since RPITIT
// is not `dyn`-safe, that will need its own boxed-future trait (or an
// operator enum) at that point — the seam is conceptual, not literal (spec §2).
// `pub(super)`: the rel/007 join operator (`join.rs`) composes over this same
// trait — the sanctioned single mechanism (spec rel/006 §2 Rust note).
pub(super) trait RowSource {
    fn next(&mut self) -> impl Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send;
}

/// Unified `SeqScan`/`PkLookup`/`IndexScan` leaf (spec §2): the candidate ROW
/// keys are already resolved (by `resolve_candidate_keys`, planner-driven);
/// this operator only does the per-row `get_with_snapshot` + `decode_row`,
/// lazily, so `OffsetLimit` can stop it early (spec §6).
pub(super) struct RowScan {
    pub(super) engine: Arc<LsmStorageEngine>,
    pub(super) snapshot: Snapshot,
    pub(super) schema: Arc<TableSchema>,
    pub(super) table_id: u32,
    pub(super) alias: String,
    pub(super) keys: std::vec::IntoIter<Vec<u8>>,
    /// Read masking (spec rel/012 §3): masked link cells decode as `NULL`.
    pub(super) mask: LinkMask,
}

impl RowSource for RowScan {
    fn next(&mut self) -> impl Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send {
        async move {
            loop {
                let Some(key) = self.keys.next() else { return Ok(None) };
                // A key live during the key-list scan but gone at the
                // snapshot fetch is a ghost (spec §2 "Snapshot &
                // Ghosts") — skip it, not an error.
                if let Some(bytes) = self.engine.get_with_snapshot(&key, &self.snapshot).await?.into_option() {
                    let mut values = decode_row(&bytes, &self.schema);
                    self.mask.apply(&mut values, &self.schema);
                    return Ok(Some(PlanRow::single(self.table_id, self.alias.clone(), values)));
                }
            }
        }
    }
}

/// Wraps a source, keeping only rows where `eval(residual) == True` (rel/005
/// evaluator, spec §4). Evaluates over the *flattened* row (spec rel/007 §5:
/// all bindings concatenated in binding order) — for the v1 single-binding
/// case this is exactly `bindings[0].values`, so no behavior changes there.
pub(super) struct Filter<S> {
    pub(super) input: S,
    pub(super) pred: Pred,
}

impl<S: RowSource + Send> RowSource for Filter<S> {
    fn next(&mut self) -> impl Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send {
        async move {
            loop {
                match self.input.next().await? {
                    None => return Ok(None),
                    Some(row) => {
                        let keep = matches!(eval(&self.pred, &flatten(&row.bindings))?, Bool3::True);
                        if keep {
                            return Ok(Some(row));
                        }
                    }
                }
            }
        }
    }
}

/// Concatenates every binding's values in binding order — the flat position
/// space that WHERE/ORDER BY/projection resolve into once a join adds more
/// than one binding (spec rel/007 §5). For a single binding this is just a
/// clone of its values.
pub(super) fn flatten(bindings: &[SourceBinding]) -> Vec<ScalarValue> {
    bindings.iter().flat_map(|b| b.values.iter().cloned()).collect()
}

/// Materializing ORDER BY (spec §5): drains the source into a buffer (hard
/// capped at `max_rows` — `SortBufferExceeded`, no spill), sorts it, then
/// serves from the buffer.
pub(super) struct Sort<S> {
    input: S,
    items: Vec<(usize, bool)>,
    max_rows: usize,
    buffer: Option<std::vec::IntoIter<PlanRow>>,
}

impl<S> Sort<S> {
    pub(super) fn new(input: S, items: Vec<(usize, bool)>, max_rows: usize) -> Self {
        Self { input, items, max_rows, buffer: None }
    }
}

impl<S: RowSource + Send> RowSource for Sort<S> {
    fn next(&mut self) -> impl Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send {
        async move {
            if self.buffer.is_none() {
                let mut rows = Vec::new();
                while let Some(row) = self.input.next().await? {
                    rows.push(row);
                    if rows.len() > self.max_rows {
                        return Err(RelStoreError::SortBufferExceeded {
                            rows: rows.len(),
                            max: self.max_rows,
                        });
                    }
                }
                let items = &self.items;
                rows.sort_by(|a, b| row_cmp(&flatten(&a.bindings), &flatten(&b.bindings), items));
                self.buffer = Some(rows.into_iter());
            }
            Ok(self.buffer.as_mut().unwrap().next())
        }
    }
}

/// NULL sorts as the largest element (NULLS LAST on ASC, NULLS FIRST on
/// DESC — spec §5/§8, PostgreSQL convention).
fn scalar_cmp_nulls_last(a: &ScalarValue, b: &ScalarValue) -> Ordering {
    match (a, b) {
        (ScalarValue::Null, ScalarValue::Null) => Ordering::Equal,
        (ScalarValue::Null, _) => Ordering::Greater,
        (_, ScalarValue::Null) => Ordering::Less,
        _ => super::eval::cmp_scalars(a, b).unwrap_or(Ordering::Equal),
    }
}

/// Lexicographic multi-column comparison; each item carries its own ASC/DESC
/// (and, through `scalar_cmp_nulls_last`, its own NULL placement — spec §5).
fn row_cmp(a: &[ScalarValue], b: &[ScalarValue], items: &[(usize, bool)]) -> Ordering {
    for &(pos, desc) in items {
        let ord = scalar_cmp_nulls_last(&a[pos], &b[pos]);
        let ord = if desc { ord.reverse() } else { ord };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Skips `offset`, yields up to `limit` rows, then stops the source (spec
/// §6). Peeks exactly one extra row once `limit` is reached to learn whether
/// more matching rows existed (`limit_applied`, spec §10), without ever
/// re-peeking on subsequent calls.
pub(super) struct OffsetLimitOp<S> {
    input: S,
    offset: u64,
    limit: u64,
    skipped: u64,
    taken: u64,
    peeked: bool,
    more: bool,
}

impl<S> OffsetLimitOp<S> {
    pub(super) fn new(input: S, offset: u64, limit: u64) -> Self {
        Self { input, offset, limit, skipped: 0, taken: 0, peeked: false, more: false }
    }

    pub(super) fn limit_applied(&self) -> bool {
        self.more
    }
}

impl<S: RowSource + Send> RowSource for OffsetLimitOp<S> {
    fn next(&mut self) -> impl Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send {
        async move {
            while self.skipped < self.offset {
                match self.input.next().await? {
                    None => {
                        self.peeked = true;
                        return Ok(None);
                    }
                    Some(_) => self.skipped += 1,
                }
            }
            if self.taken < self.limit {
                match self.input.next().await? {
                    None => {
                        self.peeked = true;
                        Ok(None)
                    }
                    Some(row) => {
                        self.taken += 1;
                        Ok(Some(row))
                    }
                }
            } else {
                if !self.peeked {
                    self.peeked = true;
                    if self.input.next().await?.is_some() {
                        self.more = true;
                    }
                }
                Ok(None)
            }
        }
    }
}

/// The finitely many v1 pipeline shapes (Filter/Sort each present or absent),
/// composed statically over `RowScan` (spec §2 pipeline: `Scan → Filter? →
/// Sort? → OffsetLimit`). A closed enum instead of `Box<dyn RowSource>` avoids
/// both the dyn-incompatibility of RPITIT and the recursive-async-fn sizing
/// problem a self-referential operator tree would hit.
enum RowPipeline {
    Plain(OffsetLimitOp<RowScan>),
    Filtered(OffsetLimitOp<Filter<RowScan>>),
    Sorted(OffsetLimitOp<Sort<RowScan>>),
    FilteredSorted(OffsetLimitOp<Sort<Filter<RowScan>>>),
}

impl RowPipeline {
    async fn next(&mut self) -> Result<Option<PlanRow>, RelStoreError> {
        match self {
            RowPipeline::Plain(p) => p.next().await,
            RowPipeline::Filtered(p) => p.next().await,
            RowPipeline::Sorted(p) => p.next().await,
            RowPipeline::FilteredSorted(p) => p.next().await,
        }
    }

    fn limit_applied(&self) -> bool {
        match self {
            RowPipeline::Plain(p) => p.limit_applied(),
            RowPipeline::Filtered(p) => p.limit_applied(),
            RowPipeline::Sorted(p) => p.limit_applied(),
            RowPipeline::FilteredSorted(p) => p.limit_applied(),
        }
    }
}

// ── Access-path key resolution (spec §3) ─────────────────────────────────────

/// Resolves `access` to its candidate ROW keys, in the path's natural
/// ascending key order (byte order == value order, spec §3/§5), plus the
/// number of underlying LSM keys visited (I/O-budget metric, §9).
///
/// Every branch reads *at* `snapshot` (spec rel/018): a row deleted after
/// the snapshot was taken still yields its key here, just like a point read
/// via `get_with_snapshot` would still find it — candidate acquisition and
/// row fetch now agree on the same point in time on every access path.
///
/// `fast_limit`: only consulted for `AccessPath::FullScan` — the
/// `scan_keys_limited_with_snapshot` shortcut is sound *only* for "full
/// scan, no residual, no ORDER BY, LIMIT set" (spec §6); its caller enforces
/// that. The cap counts only snapshot-visible keys (spec rel/014), so a key
/// that only starts existing after the snapshot can never occupy one of the
/// capped slots. Every other case of FullScan (and every other path) sees
/// the full, correctly ordered, snapshot-visible key set via
/// `scan_keys_with_snapshot`.
pub(super) async fn resolve_candidate_keys(
    engine: &Arc<LsmStorageEngine>,
    schema: &TableSchema,
    prefix: &[u8],
    access: &AccessPath,
    snapshot: &Snapshot,
    fast_limit: Option<usize>,
) -> Result<(Vec<Vec<u8>>, u64), RelStoreError> {
    match access {
        AccessPath::PkPoint(value) => {
            let Some(pk_enc) = encode_sortable(value) else {
                return Ok((Vec::new(), 0));
            };
            let key = keys::row_key(prefix, schema.table_id, &pk_enc);
            Ok((vec![key], 1))
        }
        AccessPath::PkRange(bounds) => {
            let row_prefix = keys::row_table_prefix(prefix, schema.table_id);
            let all = engine.scan_keys_with_snapshot(&row_prefix, snapshot).await?;
            let n = all.len() as u64;
            let out = all
                .into_iter()
                .filter(|k| bounds_match(&k[row_prefix.len()..], bounds))
                .collect();
            Ok((out, n))
        }
        AccessPath::PkPrefix(literal) => {
            let mut scan_prefix = keys::row_table_prefix(prefix, schema.table_id);
            scan_prefix.extend_from_slice(&encode_text_prefix(literal));
            let hits = engine.scan_keys_with_snapshot(&scan_prefix, snapshot).await?;
            let n = hits.len() as u64;
            Ok((hits, n))
        }
        AccessPath::IndexPoint { index, value } => {
            let Some(val_enc) = encode_sortable(value) else {
                return Ok((Vec::new(), 0));
            };
            let scan_prefix = keys::index_value_prefix(prefix, index.index_id, &val_enc);
            let hits = engine.scan_keys_with_snapshot(&scan_prefix, snapshot).await?;
            let n = hits.len() as u64;
            let row_keys = hits
                .iter()
                .map(|k| keys::row_key(prefix, schema.table_id, &k[scan_prefix.len()..]))
                .collect();
            Ok((row_keys, n))
        }
        AccessPath::IndexRange { index, bounds } => {
            let phys = index_column_physical_type(schema, index);
            let scan_prefix = keys::index_value_prefix(prefix, index.index_id, &[]);
            let all = engine.scan_keys_with_snapshot(&scan_prefix, snapshot).await?;
            let n = all.len() as u64;
            let mut out = Vec::new();
            for k in &all {
                let rest = &k[scan_prefix.len()..];
                let Some((val_enc, pk_enc)) = split_val_enc(phys, rest) else { continue };
                if bounds_match(val_enc, bounds) {
                    out.push(keys::row_key(prefix, schema.table_id, pk_enc));
                }
            }
            Ok((out, n))
        }
        AccessPath::IndexPrefix { index, prefix: literal } => {
            let value_prefix = keys::index_value_prefix(prefix, index.index_id, &[]);
            let mut scan_prefix = value_prefix.clone();
            scan_prefix.extend_from_slice(&encode_text_prefix(literal));
            let hits = engine.scan_keys_with_snapshot(&scan_prefix, snapshot).await?;
            let n = hits.len() as u64;
            let row_keys = hits
                .iter()
                .map(|k| {
                    let rest = &k[value_prefix.len()..];
                    let pk_enc = split_val_enc(ColumnType::Text, rest).map(|(_, pk)| pk).unwrap_or(rest);
                    keys::row_key(prefix, schema.table_id, pk_enc)
                })
                .collect();
            Ok((row_keys, n))
        }
        AccessPath::FullScan => {
            let row_prefix = keys::row_table_prefix(prefix, schema.table_id);
            let all = match fast_limit {
                Some(cap) => engine.scan_keys_limited_with_snapshot(&row_prefix, cap, snapshot).await?,
                None => engine.scan_keys_with_snapshot(&row_prefix, snapshot).await?,
            };
            let n = all.len() as u64;
            Ok((all, n))
        }
    }
}

fn index_column_physical_type(schema: &TableSchema, index: &super::catalog::IndexMeta) -> ColumnType {
    schema
        .columns
        .iter()
        .find(|c| c.name == index.column)
        .map(|c| c.col_type.physical_type())
        .unwrap_or(ColumnType::Integer)
}

/// Byte-comparison range check (spec §3): the sortable encoding makes byte
/// order equal value order, so no value decoding is needed (json/query.rs
/// pattern).
fn bounds_match(val_enc: &[u8], bounds: &RangeBounds) -> bool {
    if let Some((v, inclusive)) = &bounds.lower {
        let Some(enc) = encode_sortable(v) else { return false };
        let ok = if *inclusive { val_enc >= enc.as_slice() } else { val_enc > enc.as_slice() };
        if !ok {
            return false;
        }
    }
    if let Some((v, inclusive)) = &bounds.upper {
        let Some(enc) = encode_sortable(v) else { return false };
        let ok = if *inclusive { val_enc <= enc.as_slice() } else { val_enc < enc.as_slice() };
        if !ok {
            return false;
        }
    }
    true
}

/// Splits the bytes after an index's `IDX:…:{index_id}:` prefix (`val_enc ++
/// pk_enc`) at the value/PK boundary — pure byte-boundary logic, no value
/// decoding (spec §3): fixed 8/1 bytes for Integer/Timestamp/Real/Boolean,
/// scan-for-terminator for Text (rel/003 `encode_text` escapes content
/// `0x00` as `0x00 0xFF`, so an unescaped `0x00 0x00` is unambiguously the
/// terminator).
fn split_val_enc(phys: ColumnType, rest: &[u8]) -> Option<(&[u8], &[u8])> {
    match phys {
        ColumnType::Integer | ColumnType::Timestamp | ColumnType::Real => {
            (rest.len() >= 8).then(|| rest.split_at(8))
        }
        ColumnType::Boolean => (!rest.is_empty()).then(|| rest.split_at(1)),
        ColumnType::Text => {
            let mut i = 0;
            while i + 1 < rest.len() {
                if rest[i] == 0x00 {
                    if rest[i + 1] == 0x00 {
                        return Some(rest.split_at(i + 2));
                    } else if rest[i + 1] == 0xFF {
                        i += 2;
                        continue;
                    } else {
                        return None; // malformed escape
                    }
                }
                i += 1;
            }
            None
        }
        ColumnType::KvRef | ColumnType::JsonRef => unreachable!("physical_type collapses to Text"),
    }
}

/// The escaped-but-unterminated bytes of a LIKE literal prefix:
/// `encode_sortable` minus its trailing `0x00 0x00` terminator, so the result
/// is a *prefix* scan key matching any text value starting with `literal`
/// (spec §3).
fn encode_text_prefix(literal: &str) -> Vec<u8> {
    let mut full = encode_sortable(&ScalarValue::Text(literal.to_string())).unwrap_or_default();
    full.truncate(full.len().saturating_sub(2));
    full
}

// ── SELECT-specific binding (spec §1) ────────────────────────────────────────

pub(super) struct ProjectedColumn {
    pub(super) name: String,
    pub(super) col_type: ColumnType,
    pub(super) pos: usize,
    /// The source column's `REFERENCES` target table name, if any (rel/009
    /// §5 `expand`); carried through so `SelectResult::column_refs` can be
    /// built without re-resolving the projection.
    pub(super) references: Option<String>,
}

/// Binds the SELECT list to output columns: `*` → all columns in catalog
/// order; a column list → each resolved column (alias or name), in
/// projection order. `CountStar` is handled by the caller before this runs.
/// `pub(super)`: reused by the view CREATE-time bind-and-discard (rel/008 `view.rs`).
pub(super) fn bind_projection(
    items: &[SelectItem],
    schema: &TableSchema,
    quals: &[String],
) -> Result<Vec<ProjectedColumn>, RelStoreError> {
    if items.len() == 1 && matches!(items[0], SelectItem::Star) {
        return Ok(schema
            .columns
            .iter()
            .enumerate()
            .map(|(pos, c)| ProjectedColumn {
                name: c.name.clone(),
                col_type: c.col_type,
                pos,
                references: c.references.clone(),
            })
            .collect());
    }
    let mut proj = Vec::with_capacity(items.len());
    for item in items {
        match item {
            SelectItem::Column { col, alias } => {
                let (pos, c) = resolve_column(col, schema, quals)?;
                proj.push(ProjectedColumn {
                    name: alias.clone().unwrap_or_else(|| c.name.clone()),
                    col_type: c.col_type,
                    pos,
                    references: c.references.clone(),
                });
            }
            SelectItem::Star | SelectItem::CountStar => {
                unreachable!("grammar: Star/CountStar are only ever alone (rel/004)")
            }
        }
    }
    Ok(proj)
}

/// Binds each ORDER BY item's column (`ColumnNotFound` 404 on absence);
/// ASC/DESC carried through unchanged. ORDER-BY columns need not be in the
/// projection (standard SQL — the row is decoded regardless).
fn bind_order_by(
    items: &[OrderItem],
    schema: &TableSchema,
    quals: &[String],
) -> Result<Vec<(usize, bool)>, RelStoreError> {
    items.iter().map(|o| resolve_column(&o.col, schema, quals).map(|(pos, _)| (pos, o.desc))).collect()
}

/// Binds LIMIT/OFFSET (spec §6): negative → `InvalidSchema`; effective limit
/// `L = min(explicit LIMIT or default_limit, max_limit)`. Returns `(offset,
/// L, capped_by_max_limit)`.
pub(super) fn bind_limit(
    limit: &Option<Limit>,
    default_limit: usize,
    max_limit: usize,
) -> Result<(u64, u64, bool), RelStoreError> {
    match limit {
        None => Ok((0, default_limit.min(max_limit) as u64, false)),
        Some(l) => {
            if l.limit < 0 {
                return Err(RelStoreError::InvalidSchema("LIMIT must not be negative".to_string()));
            }
            let offset = match l.offset {
                Some(o) if o < 0 => {
                    return Err(RelStoreError::InvalidSchema("OFFSET must not be negative".to_string()))
                }
                Some(o) => o as u64,
                None => 0,
            };
            let explicit = l.limit as u64;
            let capped_limit = explicit.min(max_limit as u64);
            Ok((offset, capped_limit, capped_limit < explicit))
        }
    }
}

// ── Executor entry point (spec §1) ───────────────────────────────────────────

impl RelEngine {
    /// Runs a single-table SELECT/COUNT(*) end to end: plan the access path
    /// (`plan::plan_access`), resolve its candidate keys, build the Volcano
    /// pipeline, drive it to completion (spec §2 pipeline: `Scan|PkLookup|
    /// IndexScan → Filter(residual) → Sort? → OffsetLimit → Project`).
    /// Replaces the rel/005 PK-point-only `exec_select` (§1: PK-point is now
    /// the `PkPoint` access path, not a separate code path).
    pub(super) async fn exec_select(
        &self,
        domain: &str,
        sel: Select,
        params: &[Value],
        auth: LinkAuth,
    ) -> Result<ExecOutcome, RelStoreError> {
        // View-inlining pre-stage (spec rel/008 §1/§4): replaces every FROM/JOIN
        // view reference with its definition, recursively, *before* the rest of
        // this function (or exec_select_joined) ever sees the statement. A
        // select touching no view pays nothing (returns `sel` unchanged).
        let sel = super::view::inline_views(self, domain, sel)?;
        if !sel.joins.is_empty() {
            return self.exec_select_joined(domain, sel, params, auth).await;
        }
        let dom = self.domains.require_active(domain)?;
        let schema = match self.catalog.get(&self.domains, domain, &sel.from.name) {
            Ok(CatalogEntry::Table(t)) => t,
            // The inline_views pre-pass resolved this name as a table; hitting
            // a view here means concurrent DDL swapped the object in between
            // (DROP TABLE + CREATE VIEW). Report the vanished table instead of
            // panicking on the race.
            Ok(CatalogEntry::View(_)) => {
                return Err(RelStoreError::TableNotFound {
                    domain: domain.to_string(),
                    name: sel.from.name.clone(),
                })
            }
            Err(RelStoreError::ObjectNotFound { domain, name }) => {
                return Err(RelStoreError::TableNotFound { domain, name })
            }
            Err(e) => return Err(e),
        };
        let quals = accepted_quals(&schema, &sel);
        let prefix = dom.system_prefix.clone();
        self.metrics.record_rel_select_statement();

        // One registry lookup per query (spec rel/012 §3), reused for the
        // planner guard and the RowScan materialization.
        let mask = self.compute_link_mask(domain, &[&schema], auth).await?;

        if sel.items.len() == 1 && matches!(sel.items[0], SelectItem::CountStar) {
            return self.exec_count(&schema, &prefix, &sel, &quals, params, mask).await;
        }

        let proj = bind_projection(&sel.items, &schema, &quals)?;
        let order_by = bind_order_by(&sel.order_by, &schema, &quals)?;
        let (offset, limit, capped) = bind_limit(&sel.limit, self.default_limit, self.max_limit)?;

        let plan = plan::plan_access(&schema, &sel.where_clause, &quals, params, &order_by, mask)?;

        let use_fast_limit = matches!(plan.access, AccessPath::FullScan)
            && plan.residual.is_none()
            && order_by.is_empty()
            && sel.limit.is_some();
        let fast_cap = use_fast_limit.then(|| (offset + limit + 1) as usize);

        // Register the snapshot *before* scanning for candidate keys (spec
        // rel/018 §4): every branch below reads *at* this snapshot
        // (`scan_keys_with_snapshot`), so what registering first buys is a
        // stable read horizon — the guard must stay alive across the whole
        // scan+fetch episode so compaction/GC cannot advance past a version
        // this snapshot still needs, matching `acquire_candidates` (dml.rs).
        let snapshot_guard = self.engine.snapshot();
        let snap = snapshot_guard.snapshot().clone();

        let (mut row_keys, scanned) =
            resolve_candidate_keys(&self.engine, &schema, &prefix, &plan.access, &snap, fast_cap).await?;
        if !order_by.is_empty() && plan.order_free && plan.order_desc {
            row_keys.reverse();
        }
        self.metrics.record_rel_select_scanned_keys(scanned);

        let alias = sel.from.alias.clone().unwrap_or_else(|| schema.name.clone());
        let schema = Arc::new(schema);
        let scan = RowScan {
            engine: Arc::clone(&self.engine),
            // Cloned (not moved): `snap` is carried into the `SelectResult`
            // below so `expand` (rel/009 §5) can resolve REFERENCES columns
            // in this exact same snapshot, not a fresh one.
            snapshot: snap.clone(),
            schema: Arc::clone(&schema),
            table_id: schema.table_id,
            alias,
            keys: row_keys.into_iter(),
            mask,
        };

        let needs_sort = !order_by.is_empty() && !plan.order_free;
        let mut pipeline = match (plan.residual, needs_sort) {
            (None, false) => RowPipeline::Plain(OffsetLimitOp::new(scan, offset, limit)),
            (Some(pred), false) => {
                RowPipeline::Filtered(OffsetLimitOp::new(Filter { input: scan, pred }, offset, limit))
            }
            (None, true) => RowPipeline::Sorted(OffsetLimitOp::new(
                Sort::new(scan, order_by.clone(), self.max_sort_rows),
                offset,
                limit,
            )),
            (Some(pred), true) => RowPipeline::FilteredSorted(OffsetLimitOp::new(
                Sort::new(Filter { input: scan, pred }, order_by.clone(), self.max_sort_rows),
                offset,
                limit,
            )),
        };

        let mut rows = Vec::new();
        while let Some(row) = pipeline.next().await? {
            let values = &row.bindings[0].values;
            rows.push(proj.iter().map(|p| values[p.pos].clone()).collect());
        }
        if needs_sort {
            self.metrics.record_rel_sort_fallback();
        }
        let limit_applied = capped || pipeline.limit_applied();
        let column_refs: Vec<Option<String>> = proj.iter().map(|p| p.references.clone()).collect();
        let columns = proj.into_iter().map(|p| (p.name, p.col_type)).collect();
        Ok(ExecOutcome::Select(super::dml::SelectResult {
            columns,
            rows,
            limit_applied,
            column_refs,
            joins_used: 0,
            snapshot: Some(snap),
        }))
    }

    /// COUNT(*) (spec §7): counts over the chosen access path without
    /// materializing rows. ORDER BY/LIMIT are ignored (meaningless for a count).
    /// No residual ⇒ pure key count (`resolve_candidate_keys` never decodes
    /// a row); a residual ⇒ fetch+decode+`eval` per candidate, as usual.
    async fn exec_count(
        &self,
        schema: &TableSchema,
        prefix: &[u8],
        sel: &Select,
        quals: &[String],
        params: &[Value],
        mask: LinkMask,
    ) -> Result<ExecOutcome, RelStoreError> {
        let plan = plan::plan_access(schema, &sel.where_clause, quals, params, &[], mask)?;
        // Registered before the key scan (spec rel/018 §2): every branch
        // below, including the no-residual key-count path, now reads at
        // this snapshot — see the identical note in `exec_select`.
        let snapshot_guard = self.engine.snapshot();
        let snap = snapshot_guard.snapshot().clone();
        let (row_keys, scanned) =
            resolve_candidate_keys(&self.engine, schema, prefix, &plan.access, &snap, None).await?;
        self.metrics.record_rel_select_scanned_keys(scanned);

        let n: i64 = match plan.residual {
            // PkPoint constructs its single key without scanning — its
            // existence must be verified (spec §7: "0/1 at a point"). Every
            // other path derives keys from a live scan, so len() is the count.
            None if matches!(plan.access, AccessPath::PkPoint(_)) => {
                match row_keys.first() {
                    Some(k) => {
                        i64::from(self.engine.get_with_snapshot(k, &snap).await?.into_option().is_some())
                    }
                    None => 0,
                }
            }
            None => row_keys.len() as i64,
            Some(pred) => {
                let alias = sel.from.alias.clone().unwrap_or_else(|| schema.name.clone());
                let mut scan = RowScan {
                    engine: Arc::clone(&self.engine),
                    snapshot: snap,
                    schema: Arc::new(schema.clone()),
                    table_id: schema.table_id,
                    alias,
                    keys: row_keys.into_iter(),
                    mask,
                };
                let mut count = 0i64;
                while let Some(row) = scan.next().await? {
                    if matches!(eval(&pred, &row.bindings[0].values)?, Bool3::True) {
                        count += 1;
                    }
                }
                count
            }
        };
        Ok(ExecOutcome::Select(super::dml::SelectResult {
            columns: vec![("count".to_string(), ColumnType::Integer)],
            rows: vec![vec![ScalarValue::Integer(n)]],
            limit_applied: false,
            // COUNT(*) has no REFERENCES column to expand and never will —
            // no need to carry the snapshot for it.
            column_refs: vec![None],
            joins_used: 0,
            snapshot: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::lsm::engine::BatchOp;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use std::sync::atomic::Ordering;

    fn config_in(dir: &std::path::Path) -> RelStoreConfig {
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

    async fn run(rel: &RelEngine, sql: &str) -> Result<ExecOutcome, RelStoreError> {
        rel.execute("default", sql, &[]).await
    }

    async fn ok(rel: &RelEngine, sql: &str) {
        run(rel, sql).await.unwrap();
    }

    async fn sel(rel: &RelEngine, sql: &str) -> super::super::dml::SelectResult {
        match run(rel, sql).await.unwrap() {
            ExecOutcome::Select(r) => r,
            o => panic!("expected SELECT, got {o:?}"),
        }
    }

    async fn err(rel: &RelEngine, sql: &str) -> RelStoreError {
        run(rel, sql).await.unwrap_err()
    }

    fn ints(rows: &[Vec<ScalarValue>], col: usize) -> Vec<i64> {
        rows.iter()
            .map(|r| match &r[col] {
                ScalarValue::Integer(i) => *i,
                v => panic!("not an integer: {v:?}"),
            })
            .collect()
    }

    fn scanned_keys(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_select_scanned_keys_total.load(Ordering::Relaxed)
    }

    fn statements_total(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_select_statements_total.load(Ordering::Relaxed)
    }

    fn sort_fallback_total(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_sort_fallback_total.load(Ordering::Relaxed)
    }

    // 1. PK-point (generalized): identical to the rel/005 behavior, now
    // running through the new access-path executor.
    #[tokio::test]
    async fn test_pk_point_regression() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 100)").await;

        let s = sel(&rel, "SELECT * FROM t WHERE id = 1").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(1), ScalarValue::Integer(100)]]);
        assert!(!s.limit_applied);

        assert!(sel(&rel, "SELECT * FROM t WHERE id = 2").await.rows.is_empty());
    }

    // 2. Full scan without WHERE: all rows; `*` and a column list with alias.
    #[tokio::test]
    async fn test_full_scan_projection_and_alias() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b TEXT)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 10, 'x'), (2, 20, 'y')").await;

        let s = sel(&rel, "SELECT * FROM t").await;
        assert_eq!(s.columns.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), vec!["id", "a", "b"]);
        assert_eq!(s.rows.len(), 2);

        let s = sel(&rel, "SELECT b AS label, id FROM t").await;
        assert_eq!(s.columns.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), vec!["label", "id"]);
        assert!(s.rows.iter().any(|r| r == &vec![ScalarValue::Text("x".into()), ScalarValue::Integer(1)]));
    }

    // 3. Full scan with a residual WHERE: AND/OR/NOT/parens, IN, LIKE, IS NULL
    // all filter correctly through the rel/005 evaluator.
    #[tokio::test]
    async fn test_full_scan_residual_operators() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, grp INTEGER, note TEXT)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 1, 'alpha'), (2, 2, 'beta'), (3, NULL, 'gamma')").await;

        let s = sel(&rel, "SELECT id FROM t WHERE NOT (grp = 1) OR note = 'gamma'").await;
        assert_eq!(ints(&s.rows, 0), vec![2, 3]);

        let s = sel(&rel, "SELECT id FROM t WHERE grp IN (1, 2)").await;
        assert_eq!(ints(&s.rows, 0), vec![1, 2]);

        let s = sel(&rel, "SELECT id FROM t WHERE note LIKE 'al%'").await;
        assert_eq!(ints(&s.rows, 0), vec![1]);

        let s = sel(&rel, "SELECT id FROM t WHERE grp IS NULL").await;
        assert_eq!(ints(&s.rows, 0), vec![3]);
    }

    // 4. Index point: same set as a full-scan reference; scans only the
    // matching IDX entries, not every ROW key.
    #[tokio::test]
    async fn test_index_point_scans_fewer_keys_than_full_scan() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_tag ON t (tag)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5), (2, 7), (3, 5), (4, 9)").await;

        let before = scanned_keys(&rel);
        let s = sel(&rel, "SELECT id FROM t WHERE tag = 5").await;
        let after = scanned_keys(&rel);
        assert_eq!(ints(&s.rows, 0), vec![1, 3]);
        assert_eq!(after - before, 2, "index point must visit only the 2 matching IDX entries");

        let before2 = after;
        let full = sel(&rel, "SELECT id FROM t").await;
        let after2 = scanned_keys(&rel);
        assert_eq!(full.rows.len(), 4);
        assert_eq!(after2 - before2, 4, "full scan visits all 4 ROW keys");
    }

    // 5. Unique-index point: 0/1 row.
    #[tokio::test]
    async fn test_unique_index_point() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, email TEXT UNIQUE)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 'a@x.com'), (2, 'b@x.com')").await;

        assert_eq!(ints(&sel(&rel, "SELECT id FROM t WHERE email = 'a@x.com'").await.rows, 0), vec![1]);
        assert!(sel(&rel, "SELECT id FROM t WHERE email = 'ghost@x.com'").await.rows.is_empty());
    }

    // 6. PK range: correct window including both boundaries; a second
    // same-column range conjunct becomes residual (only one predicate drives).
    #[tokio::test]
    async fn test_pk_range_inclusive_bounds() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1), (2), (3), (4), (5)").await;

        let s = sel(&rel, "SELECT id FROM t WHERE id >= 2 AND id <= 4").await;
        assert_eq!(ints(&s.rows, 0), vec![2, 3, 4]);
    }

    // 7. Index range on a NOT NULL column: correct byte-comparison window,
    // incl. i64 extremes and text ordering.
    #[tokio::test]
    async fn test_index_range_not_null_incl_i64_extremes_and_text_order() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL, s TEXT NOT NULL)").await;
        ok(&rel, "CREATE INDEX idx_v ON t (v)").await;
        ok(&rel, "CREATE INDEX idx_s ON t (s)").await;
        ok(
            &rel,
            &format!(
                "INSERT INTO t VALUES (1, {}, 'banana'), (2, -1, 'apple'), (3, 0, 'cherry'), \
                 (4, {}, 'date'), (5, 100, 'fig')",
                i64::MIN,
                i64::MAX
            ),
        )
        .await;

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE v > 0").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![4, 5]);

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE v <= -1").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![1, 2]);

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE s > 'cherry'").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![4, 5], "text order: date/fig > cherry");
    }

    // 8. LIKE: 'prefix%' drives an index range + residual re-check; a
    // leading-wildcard pattern forces a full scan with a correct result.
    #[tokio::test]
    async fn test_like_prefix_and_leading_wildcard() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL)").await;
        ok(&rel, "CREATE INDEX idx_name ON t (name)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 'alice'), (2, 'alba'), (3, 'bob'), (4, 'alicia')").await;

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE name LIKE 'ali%'").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![1, 4], "'alba' shares only 'al', not the 'ali' prefix");

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE name LIKE 'alic_'").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![1], "'_' matches exactly one char: 'alice' fits, 'alicia' doesn't");

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE name LIKE '%b%'").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![2, 3], "leading wildcard -> full scan, still correct");
    }

    // 9. Access-path determinism: the highest-priority sargable conjunct
    // drives (PK over index); a top-level OR forces a full scan.
    #[tokio::test]
    async fn test_access_path_determinism() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_tag ON t (tag)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5), (2, 5), (3, 9)").await;

        let before = scanned_keys(&rel);
        let s = sel(&rel, "SELECT id FROM t WHERE id = 1 AND tag = 5").await;
        let after = scanned_keys(&rel);
        assert_eq!(ints(&s.rows, 0), vec![1]);
        assert_eq!(after - before, 1, "PK point must drive (1 ROW key), not the tag index");

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE id = 1 OR tag = 9").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![1, 3]);
    }

    // 10. ORDER BY pk under a full scan: free ordering, no Sort fallback.
    #[tokio::test]
    async fn test_order_by_pk_full_scan_no_sort() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (3), (1), (2)").await;

        let before = sort_fallback_total(&rel);
        let s = sel(&rel, "SELECT id FROM t ORDER BY id").await;
        assert_eq!(ints(&s.rows, 0), vec![1, 2, 3]);
        assert_eq!(sort_fallback_total(&rel), before, "PK order is free under a full scan");

        let s = sel(&rel, "SELECT id FROM t ORDER BY id DESC").await;
        assert_eq!(ints(&s.rows, 0), vec![3, 2, 1]);
    }

    // 11. ORDER BY on the driven indexed NOT-NULL column: index order, no Sort.
    #[tokio::test]
    async fn test_order_by_driven_indexed_column_no_sort() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)").await;
        ok(&rel, "CREATE INDEX idx_v ON t (v)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 30), (2, 10), (3, 20)").await;

        let before = sort_fallback_total(&rel);
        let s = sel(&rel, "SELECT id FROM t WHERE v >= 10 ORDER BY v").await;
        assert_eq!(ints(&s.rows, 0), vec![2, 3, 1]);
        assert_eq!(sort_fallback_total(&rel), before, "index order on the driving column is free");
    }

    // 12. ORDER BY on a nullable column: Sort fallback; NULLS LAST (ASC) and
    // NULLS FIRST (DESC).
    #[tokio::test]
    async fn test_order_by_nullable_column_sort_path_nulls_placement() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 20), (2, NULL), (3, 10)").await;

        let before = sort_fallback_total(&rel);
        let s = sel(&rel, "SELECT id FROM t ORDER BY v ASC").await;
        assert_eq!(ints(&s.rows, 0), vec![3, 1, 2], "NULLS LAST on ASC");
        assert_eq!(sort_fallback_total(&rel), before + 1);

        let s = sel(&rel, "SELECT id FROM t ORDER BY v DESC").await;
        assert_eq!(ints(&s.rows, 0), vec![2, 1, 3], "NULLS FIRST on DESC");
    }

    // 13. Multi-column ORDER BY: Sort fallback; DESC reverses that column.
    #[tokio::test]
    async fn test_multi_column_order_by_sort_path() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, grp INTEGER, v INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 1, 20), (2, 1, 10), (3, 2, 5)").await;

        let s = sel(&rel, "SELECT id FROM t ORDER BY grp ASC, v DESC").await;
        assert_eq!(ints(&s.rows, 0), vec![1, 2, 3]);
    }

    // 14. ORDER-BY-driven path without WHERE: an indexed NOT-NULL column
    // drives the ordered range scan directly, no Sort.
    #[tokio::test]
    async fn test_order_by_driven_path_without_where() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)").await;
        ok(&rel, "CREATE INDEX idx_v ON t (v)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 30), (2, 10), (3, 20)").await;

        let before = sort_fallback_total(&rel);
        let s = sel(&rel, "SELECT id FROM t ORDER BY v").await;
        assert_eq!(ints(&s.rows, 0), vec![2, 3, 1]);
        assert_eq!(sort_fallback_total(&rel), before, "no WHERE: ORDER BY itself drives the index range");
    }

    // 15. max_sort_rows exceeded -> SortBufferExceeded, no partial/spilled result.
    #[tokio::test]
    async fn test_sort_buffer_exceeded() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { max_sort_rows: 3, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 4), (2, 3), (3, 2), (4, 1)").await;

        let e = err(&rel, "SELECT id FROM t ORDER BY v").await;
        assert!(matches!(e, RelStoreError::SortBufferExceeded { rows: 4, max: 3 }), "got: {e}");
    }

    // 16. LIMIT/OFFSET: default_limit without LIMIT; explicit LIMIT >
    // max_limit capped (limit_applied = true); OFFSET correct; more rows
    // withheld -> limit_applied = true, exact/short fit -> false; negative
    // LIMIT/OFFSET rejected.
    #[tokio::test]
    async fn test_limit_offset_semantics() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { default_limit: 3, max_limit: 5, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1),(2),(3),(4),(5),(6),(7)").await;

        let s = sel(&rel, "SELECT id FROM t ORDER BY id").await;
        assert_eq!(ints(&s.rows, 0), vec![1, 2, 3]);
        assert!(s.limit_applied, "more rows exist past default_limit");

        let s = sel(&rel, "SELECT id FROM t ORDER BY id LIMIT 100").await;
        assert_eq!(ints(&s.rows, 0), vec![1, 2, 3, 4, 5]);
        assert!(s.limit_applied, "explicit LIMIT capped by max_limit");

        let s = sel(&rel, "SELECT id FROM t ORDER BY id LIMIT 3 OFFSET 4").await;
        assert_eq!(ints(&s.rows, 0), vec![5, 6, 7]);
        assert!(!s.limit_applied, "exactly 3 rows remained after OFFSET 4 of 7");

        let s = sel(&rel, "SELECT id FROM t ORDER BY id LIMIT 3 OFFSET 6").await;
        assert_eq!(ints(&s.rows, 0), vec![7]);
        assert!(!s.limit_applied, "fewer than LIMIT remained");

        assert!(matches!(err(&rel, "SELECT id FROM t LIMIT -1").await, RelStoreError::InvalidSchema(_)));
        assert!(matches!(
            err(&rel, "SELECT id FROM t LIMIT 1 OFFSET -1").await,
            RelStoreError::InvalidSchema(_)
        ));
    }

    // 17. COUNT(*) without WHERE: pure key count, one row/one column.
    #[tokio::test]
    async fn test_count_star_no_where() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1),(2),(3)").await;

        let s = sel(&rel, "SELECT COUNT(*) FROM t").await;
        assert_eq!(s.columns, vec![("count".to_string(), ColumnType::Integer)]);
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(3)]]);
        assert!(!s.limit_applied);
    }

    // 18. COUNT(*) with WHERE: correct count via residual; an index path
    // without residual is a pure key count.
    #[tokio::test]
    async fn test_count_star_with_where_and_index_key_count() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER, note TEXT)").await;
        ok(&rel, "CREATE INDEX idx_tag ON t (tag)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5, 'x'), (2, 5, 'y'), (3, 9, 'x')").await;

        let s = sel(&rel, "SELECT COUNT(*) FROM t WHERE tag = 5").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(2)]]);

        let s = sel(&rel, "SELECT COUNT(*) FROM t WHERE tag = 5 AND note = 'x'").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(1)]]);
    }

    // 19. NULL/Index: IS NULL forces a full scan and finds the NULL rows; an
    // index point on a nullable column simply never matches NULL rows
    // (they're absent from the index).
    #[tokio::test]
    async fn test_null_is_null_full_scan_and_index_point_skips_nulls() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_tag ON t (tag)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5), (2, NULL), (3, NULL), (4, 5)").await;

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE tag IS NULL").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![2, 3]);

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE tag = 5").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![1, 4]);
    }

    // 21. MVCC/Ghost: a key live at scan time but absent at the (older)
    // snapshot is silently skipped, not surfaced and not an error.
    #[tokio::test]
    async fn test_mvcc_ghost_skipped_not_error() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1)").await;

        let snapshot_guard = rel.engine().snapshot();
        let snap = snapshot_guard.snapshot().clone();
        ok(&rel, "INSERT INTO t VALUES (2)").await; // live now, but not in `snap`

        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let schema = match rel.get_object("default", "t").unwrap() {
            CatalogEntry::Table(t) => t,
            _ => unreachable!(),
        };
        let table_id = schema.table_id;
        let key1 = keys::row_key(&prefix, table_id, &encode_sortable(&ScalarValue::Integer(1)).unwrap());
        let key2 = keys::row_key(&prefix, table_id, &encode_sortable(&ScalarValue::Integer(2)).unwrap());

        let mut scan = RowScan {
            engine: Arc::clone(rel.engine()),
            snapshot: snap,
            schema: Arc::new(schema),
            table_id,
            alias: "t".to_string(),
            keys: vec![key1, key2].into_iter(),
            mask: LinkMask::default(),
        };
        let row1 = scan.next().await.unwrap().expect("key1 exists at snap");
        assert_eq!(row1.bindings[0].values[0], ScalarValue::Integer(1));
        assert!(scan.next().await.unwrap().is_none(), "ghost key2 must be skipped silently");
    }

    // 22. Metrics: statement + scanned-key counters increment as expected.
    #[tokio::test]
    async fn test_select_metrics_increment() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1), (2), (3)").await;

        let stmts_before = statements_total(&rel);
        let keys_before = scanned_keys(&rel);
        sel(&rel, "SELECT * FROM t").await;
        assert_eq!(statements_total(&rel), stmts_before + 1);
        assert_eq!(scanned_keys(&rel) - keys_before, 3);

        sel(&rel, "SELECT COUNT(*) FROM t").await;
        assert_eq!(statements_total(&rel), stmts_before + 2);
    }

    // 23. COUNT(*) via PK-point verifies existence: a missing PK counts 0,
    //     not 1 (the constructed key must not be counted blindly).
    #[tokio::test]
    async fn test_count_pk_point_checks_existence() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1)").await;

        let hit = sel(&rel, "SELECT COUNT(*) FROM t WHERE id = 1").await;
        assert_eq!(hit.rows[0][0], ScalarValue::Integer(1));

        let miss = sel(&rel, "SELECT COUNT(*) FROM t WHERE id = 99").await;
        assert_eq!(miss.rows[0][0], ScalarValue::Integer(0), "missing PK must count 0");
    }

    // 24. flip_op: literal-on-the-left comparisons (`3 = id`, `3 < id`, `3 >=
    // id`) resolve the same as their column-first form (point + range).
    #[tokio::test]
    async fn test_flipped_literal_left_point_and_range() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1), (2), (3), (4), (5)").await;

        let before = scanned_keys(&rel);
        let s = sel(&rel, "SELECT id FROM t WHERE 3 = id").await;
        let after = scanned_keys(&rel);
        assert_eq!(ints(&s.rows, 0), vec![3]);
        assert_eq!(after - before, 1, "literal-left point must drive PK point (1 key), not a full scan");

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE 3 < id").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![4, 5], "flip_op(Lt)=Gt: '3 < id' means id > 3");

        let mut got = ints(&sel(&rel, "SELECT id FROM t WHERE 3 >= id").await.rows, 0);
        got.sort();
        assert_eq!(got, vec![1, 2, 3], "flip_op(GtEq)=LtEq: '3 >= id' means id <= 3");
    }

    // 25. Spec rel/014 §5 (wiring regression): a table with generous headroom
    // over LIMIT (comfortably >= limit + 1 committed rows) must keep
    // returning a full page under concurrent inserts of early-sorting rows.
    // The deterministic proof that ghosts never occupy a cap slot is engine
    // test 1 (engine.rs); this only proves the rel-level wiring doesn't
    // regress under real interleaving. Bounded, no tight timing window as
    // the test condition (general/008-line): any short page or `false` here
    // is a genuine bug, not a flake.
    #[tokio::test]
    async fn test_fast_limit_snapshot_consistent_under_concurrent_inserts() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)").await;
        // Baseline PKs (1000..1020) sort after every concurrently-inserted
        // row below, and comfortably exceed limit(10) + 1.
        for i in 1000..1020 {
            ok(&rel, &format!("INSERT INTO t VALUES ({i}, 0)")).await;
        }

        let writer = Arc::clone(&rel);
        let inserter = tokio::spawn(async move {
            // Early-sorting PKs: a ghost landing in the capped scan window
            // must never displace a real row.
            for i in 0..50 {
                writer.execute("default", &format!("INSERT INTO t VALUES ({i}, 1)"), &[]).await.unwrap();
            }
        });

        for _ in 0..50 {
            let s = sel(&rel, "SELECT * FROM t LIMIT 10").await;
            assert_eq!(s.rows.len(), 10, "a concurrent insert must never shrink a full LIMIT page");
            assert!(s.limit_applied, "more rows exist past LIMIT -- must stay true under concurrent inserts");
        }
        inserter.await.unwrap();
    }

    // 26. Spec rel/014 §6 (limit_applied discriminator): exactly `limit + 1`
    // committed rows -- the minimal count for which `limit_applied = true`
    // is correct -- racing concurrent early-sorting inserts. This is the
    // exact configuration that used to separate old from new: the old
    // unsnapshotted cap would either lose the "+1 probe" to a ghost slot
    // (limit_applied wrongly false) or lose a real row to one (a short
    // page); the snapshot-capped scan must get both fields right every time.
    #[tokio::test]
    async fn test_fast_limit_snapshot_correct_at_minimal_visible_plus_ghosts() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)").await;
        // Exactly limit(10) + 1 committed rows -- zero headroom in the cap.
        for i in 1000..1011 {
            ok(&rel, &format!("INSERT INTO t VALUES ({i}, 0)")).await;
        }

        let writer = Arc::clone(&rel);
        let inserter = tokio::spawn(async move {
            for i in 0..50 {
                writer.execute("default", &format!("INSERT INTO t VALUES ({i}, 1)"), &[]).await.unwrap();
            }
        });

        for _ in 0..50 {
            let s = sel(&rel, "SELECT * FROM t LIMIT 10").await;
            assert_eq!(s.rows.len(), 10, "the minimal +1 row must never be displaced by a ghost slot");
            assert!(s.limit_applied, "the +1 probe must never be lost to a ghost slot");
        }
        inserter.await.unwrap();
    }

    // 27. Spec rel/018 §Test 1 (delete side, Full Scan): a key deleted
    // *after* the snapshot was taken must still be a candidate -- the
    // engine-level delete mirrors a concurrent DELETE racing the SELECT's
    // snapshot registration. Direct unit test against the function, no HTTP
    // (the deterministic engine-level proof is rel/014 engine test 2; this
    // only proves the rel-level wiring passes the snapshot through).
    #[tokio::test]
    async fn test_resolve_candidate_keys_full_scan_sees_snapshot_deleted_row() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1), (2)").await;

        let snapshot_guard = rel.engine().snapshot();
        let snap = snapshot_guard.snapshot().clone();

        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let schema = match rel.get_object("default", "t").unwrap() {
            CatalogEntry::Table(t) => t,
            _ => unreachable!(),
        };
        let key1 = keys::row_key(&prefix, schema.table_id, &encode_sortable(&ScalarValue::Integer(1)).unwrap());
        // Engine-level delete (tombstone), bypassing the DML write path --
        // the same effect a concurrent `DELETE FROM t WHERE id = 1` has on
        // the live key set.
        rel.engine().write_batch(vec![BatchOp::Delete { key: key1.clone() }]).await.unwrap();

        let (row_keys, _scanned) =
            resolve_candidate_keys(rel.engine(), &schema, &prefix, &AccessPath::FullScan, &snap, None)
                .await
                .unwrap();
        assert!(row_keys.contains(&key1), "a key deleted after the snapshot must remain a candidate");
    }

    // 28. Spec rel/018 §Test 2 (delete side, index branches): a concurrent
    // UPDATE of an indexed column tombstones the *old* IDX entry, not the
    // ROW key -- a live index scan loses the row even though its snapshot
    // version (the old value) still satisfies the predicate.
    // IndexPoint/IndexRange/IndexPrefix must still return it when resolved
    // at the snapshot; a fresh (post-tombstone) snapshot must not (Gegenprobe:
    // proves the difference is the snapshot, not a scan bug).
    #[tokio::test]
    async fn test_resolve_candidate_keys_index_paths_see_snapshot_deleted_index_entry() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER, name TEXT)").await;
        ok(&rel, "CREATE INDEX idx_tag ON t (tag)").await;
        ok(&rel, "CREATE INDEX idx_name ON t (name)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5, 'alice')").await;

        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let schema = match rel.get_object("default", "t").unwrap() {
            CatalogEntry::Table(t) => t,
            _ => unreachable!(),
        };
        let idx_tag = schema.indexes.iter().find(|ix| ix.column == "tag").unwrap().clone();
        let idx_name = schema.indexes.iter().find(|ix| ix.column == "name").unwrap().clone();
        let row_key = keys::row_key(&prefix, schema.table_id, &encode_sortable(&ScalarValue::Integer(1)).unwrap());

        // Read back the real on-disk IDX-entry bytes (rather than
        // re-deriving them) so the tombstone below hits exactly what
        // INSERT wrote.
        let tag_scan_prefix = keys::index_value_prefix(&prefix, idx_tag.index_id, &[]);
        let tag_idx_key = rel.engine().scan_keys(&tag_scan_prefix).await.unwrap().into_iter().next().unwrap();
        let name_scan_prefix = keys::index_value_prefix(&prefix, idx_name.index_id, &[]);
        let name_idx_key = rel.engine().scan_keys(&name_scan_prefix).await.unwrap().into_iter().next().unwrap();

        let snapshot_guard = rel.engine().snapshot();
        let snap = snapshot_guard.snapshot().clone();

        // Simulates a concurrent UPDATE moving `tag`/`name` off their
        // indexed values: only the IDX entries vanish, the ROW key doesn't.
        rel.engine()
            .write_batch(vec![
                BatchOp::Delete { key: tag_idx_key },
                BatchOp::Delete { key: name_idx_key },
            ])
            .await
            .unwrap();

        let (point, _) = resolve_candidate_keys(
            rel.engine(),
            &schema,
            &prefix,
            &AccessPath::IndexPoint { index: idx_tag.clone(), value: ScalarValue::Integer(5) },
            &snap,
            None,
        )
        .await
        .unwrap();
        assert_eq!(point, vec![row_key.clone()], "IndexPoint must still see the snapshot-visible entry");

        let (range, _) = resolve_candidate_keys(
            rel.engine(),
            &schema,
            &prefix,
            &AccessPath::IndexRange {
                index: idx_tag.clone(),
                bounds: RangeBounds { lower: Some((ScalarValue::Integer(0), true)), upper: None },
            },
            &snap,
            None,
        )
        .await
        .unwrap();
        assert_eq!(range, vec![row_key.clone()], "IndexRange must still see the snapshot-visible entry");

        let (prefix_hits, _) = resolve_candidate_keys(
            rel.engine(),
            &schema,
            &prefix,
            &AccessPath::IndexPrefix { index: idx_name, prefix: "ali".to_string() },
            &snap,
            None,
        )
        .await
        .unwrap();
        assert_eq!(prefix_hits, vec![row_key], "IndexPrefix must still see the snapshot-visible entry");

        // Gegenprobe: a fresh snapshot taken after the tombstone must NOT
        // see the vanished index entry -- proves the assertions above
        // exercise the snapshot, not a scan that ignores deletes outright.
        let now_guard = rel.engine().snapshot();
        let now_snap = now_guard.snapshot().clone();
        let (point_now, _) = resolve_candidate_keys(
            rel.engine(),
            &schema,
            &prefix,
            &AccessPath::IndexPoint { index: idx_tag, value: ScalarValue::Integer(5) },
            &now_snap,
            None,
        )
        .await
        .unwrap();
        assert!(point_now.is_empty(), "a current snapshot must not see the tombstoned index entry");
    }
}
