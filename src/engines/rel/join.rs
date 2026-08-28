//! LEFT JOIN execution (spec rel/007): `IndexNestedLoopJoin` operator, ON
//! resolution + probe-strategy selection, multi-binding column resolution,
//! left-deep join-chain planning. Reuses `RowScan`/`Filter`/`Sort`/
//! `OffsetLimitOp`/`RowSource` (select.rs), the rel/005 evaluator (eval.rs)
//! and key builders (keys.rs) unchanged — this module only adds the join
//! layer between the base scan and the residual filter.

use super::ast::{ColumnRef, CompareOp, Expr, Join, Literal, Operand, OrderItem, Select, SelectItem};
use super::catalog::{CatalogEntry, TableSchema};
use super::cross_engine::{LinkAuth, LinkMask};
use super::error::RelStoreError;
use super::eval::{eval, Bool3, Pred, PredOperand};
use super::keys;
use super::plan;
use super::row::decode_row;
use super::select::{
    self, flatten, Filter, OffsetLimitOp, PlanRow, ProjectedColumn, RowScan, RowSource, Sort,
    SourceBinding,
};
use super::types::{encode_sortable, ColumnType, ScalarValue};
use super::{ExecOutcome, RelEngine};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::reader::Snapshot;
use crate::metrics::MetricsStore;
use serde_json::Value;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── Dynamic RowSource boxing (spec §2 Rust note) ──────────────────────────
//
// `RowSource::next` is RPITIT (rel/006 §2 pattern), which is not `dyn`-safe.
// A join chain has dynamic depth (`max_join_depth` stages), so the left input
// of an `IndexNestedLoopJoin` cannot be a single fixed generic type the way
// v1's finitely-many pipeline shapes are (`RowPipeline` enum). This trait is
// the one sanctioned boxing seam (rel/006 §2 comment): it boxes exactly the
// recursive edge (the left input's `next()` future), not the whole operator
// tree — Filter/Sort/OffsetLimit above the join still compose statically via
// generics over `IndexNestedLoopJoin`, unchanged from v1's mechanism.
trait DynRowSource: Send {
    fn next_boxed(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send + '_>>;
}

impl<T: RowSource + Send> DynRowSource for T {
    fn next_boxed(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send + '_>> {
        Box::pin(RowSource::next(self))
    }
}

// ── Probe strategy & JoinProbe (spec §3) ─────────────────────────────────────

#[derive(Clone, Copy)]
enum ProbeStrategy {
    PkPoint,
    Index { index_id: u32 },
    ScanFallback,
}

/// The right-hand sonde of one join stage: how to turn a left ON-value into
/// 0..n right `SourceBinding`s (spec §2/§3). `pub(super)`: named (though never
/// constructed or inspected) in `build_join_probe`'s `pub(super)` return type,
/// used by rel/008 `view.rs`'s CREATE-time bind-and-discard.
pub(super) struct JoinProbe {
    engine: Arc<LsmStorageEngine>,
    snapshot: Snapshot,
    metrics: Arc<MetricsStore>,
    right_prefix: Vec<u8>,
    right_table: Arc<TableSchema>,
    right_alias: String,
    /// Position of the right ON-column in `right_table.columns`.
    right_col_pos: usize,
    /// `(binding_idx, value_idx)` of the LEFT ON-column in the driving `PlanRow`.
    value_source: (usize, usize),
    strategy: ProbeStrategy,
    /// The left value's declared type is INTEGER while the right column is
    /// REAL — the one implicit widening (spec §3); the probe value must be
    /// converted before `encode_sortable`.
    widen_int_to_real: bool,
    /// Statement-wide cumulative `ScanFallback` row-visit counter, shared
    /// across every fallback-using join stage (spec §3).
    fallback_budget: Arc<AtomicU64>,
    max_fallback_scan: usize,
    /// Read masking (spec rel/012 §3): the right side shares the query's rel
    /// domain, so its link cells mask by the same flags as the left.
    mask: LinkMask,
}

impl JoinProbe {
    /// The LEFT-preserved binding: all-NULL, used for "no match" and "NULL ON
    /// value" alike (spec §4).
    fn null_binding(&self) -> SourceBinding {
        SourceBinding {
            table_id: self.right_table.table_id,
            alias: self.right_alias.clone(),
            values: vec![ScalarValue::Null; self.right_table.columns.len()],
        }
    }

    /// A matched right-hand row. Masking (spec rel/012 §3) is applied to the
    /// materialized output only — the physical join match (by key/eval)
    /// already happened, so a hanging link still joins but reads as `NULL`.
    fn row_binding(&self, mut values: Vec<ScalarValue>) -> SourceBinding {
        self.mask.apply(&mut values, &self.right_table);
        SourceBinding { table_id: self.right_table.table_id, alias: self.right_alias.clone(), values }
    }

    /// Executes one probe for a non-NULL left value `v` (spec §3/§9): returns
    /// the right-hand hits (0..n `SourceBinding`s); the caller turns an empty
    /// result into the LEFT-preserved all-NULL binding (spec §4).
    async fn probe(&self, v: &ScalarValue) -> Result<Vec<SourceBinding>, RelStoreError> {
        self.metrics.record_rel_join_probes(1);
        // spec rel/012: a masked right ON-column reads NULL for every row;
        // NULL never matches under 3-valued ON equality, so skip storage.
        if self.mask.masks(self.right_table.columns[self.right_col_pos].col_type) {
            return Ok(Vec::new());
        }
        let v = self.widened(v);
        // NULL is already excluded by the caller (spec §2); every other
        // ScalarValue encodes to `Some` (rel/003).
        let Some(val_enc) = encode_sortable(&v) else { return Ok(Vec::new()) };

        match self.strategy {
            ProbeStrategy::PkPoint => self.probe_pk_point(&val_enc).await,
            ProbeStrategy::Index { index_id } => self.probe_index(index_id, &val_enc).await,
            ProbeStrategy::ScanFallback => self.probe_scan_fallback(&v).await,
        }
    }

    /// The one implicit widening (spec §3): an INTEGER left value probing a
    /// REAL right column.
    fn widened(&self, v: &ScalarValue) -> ScalarValue {
        if self.widen_int_to_real {
            match v {
                ScalarValue::Integer(i) => ScalarValue::Real(*i as f64),
                other => other.clone(),
            }
        } else {
            v.clone()
        }
    }

    async fn probe_pk_point(&self, val_enc: &[u8]) -> Result<Vec<SourceBinding>, RelStoreError> {
        let key = keys::row_key(&self.right_prefix, self.right_table.table_id, val_enc);
        self.metrics.record_rel_select_scanned_keys(1);
        match self.engine.get_with_snapshot(&key, &self.snapshot).await?.into_option() {
            Some(bytes) => Ok(vec![self.row_binding(decode_row(&bytes, &self.right_table))]),
            None => Ok(Vec::new()), // ghost or never existed — not a hit (spec §2 Snapshot & Ghosts)
        }
    }

    async fn probe_index(&self, index_id: u32, val_enc: &[u8]) -> Result<Vec<SourceBinding>, RelStoreError> {
        let scan_prefix = keys::index_value_prefix(&self.right_prefix, index_id, val_enc);
        let hits = self.engine.scan_keys_with_snapshot(&scan_prefix, &self.snapshot).await?;
        self.metrics.record_rel_select_scanned_keys(hits.len() as u64);
        let mut out = Vec::with_capacity(hits.len());
        for h in &hits {
            let pk_enc = &h[scan_prefix.len()..];
            let row_key = keys::row_key(&self.right_prefix, self.right_table.table_id, pk_enc);
            self.metrics.record_rel_select_scanned_keys(1);
            if let Some(bytes) = self.engine.get_with_snapshot(&row_key, &self.snapshot).await?.into_option() {
                out.push(self.row_binding(decode_row(&bytes, &self.right_table)));
            } // ghost: skip, not a hit (spec §2)
        }
        Ok(out)
    }

    async fn probe_scan_fallback(&self, v: &ScalarValue) -> Result<Vec<SourceBinding>, RelStoreError> {
        let row_prefix = keys::row_table_prefix(&self.right_prefix, self.right_table.table_id);
        // Cap the scan itself (spec rel/007 F1): scan only the remaining
        // budget + 1, so a right table bigger than the cap is never fully
        // materialized before the cap check below ever runs.
        let consumed = self.fallback_budget.load(Ordering::Relaxed);
        let remaining = (self.max_fallback_scan as u64).saturating_sub(consumed);
        let scan_keys = self
            .engine
            .scan_keys_limited_with_snapshot(&row_prefix, remaining as usize + 1, &self.snapshot)
            .await?;
        let n = scan_keys.len() as u64;
        self.metrics.record_rel_select_scanned_keys(n);
        let total = self.fallback_budget.fetch_add(n, Ordering::Relaxed) + n;
        if total > self.max_fallback_scan as u64 {
            return Err(RelStoreError::UnindexedJoinScanExceeded {
                scanned: total as usize,
                max: self.max_fallback_scan,
            });
        }
        let pred = Pred::Compare {
            lhs: PredOperand::Column(self.right_col_pos),
            op: CompareOp::Eq,
            rhs: PredOperand::Value(v.clone()),
        };
        let mut out = Vec::new();
        for k in &scan_keys {
            if let Some(bytes) = self.engine.get_with_snapshot(k, &self.snapshot).await?.into_option() {
                let values = decode_row(&bytes, &self.right_table);
                if matches!(eval(&pred, &values), Bool3::True) {
                    out.push(self.row_binding(values));
                }
            } // ghost: skip
        }
        Ok(out)
    }
}

// ── IndexNestedLoopJoin (spec §2) ────────────────────────────────────────────

/// Sits above its left source (a base scan or a shallower join). Streaming:
/// buffers only the current left row's right-hand hits, never the whole
/// input (spec §2).
struct IndexNestedLoopJoin {
    left: Box<dyn DynRowSource>,
    probe: JoinProbe,
    buffer: std::vec::IntoIter<PlanRow>,
}

impl IndexNestedLoopJoin {
    fn new(left: Box<dyn DynRowSource>, probe: JoinProbe) -> Self {
        Self { left, probe, buffer: Vec::new().into_iter() }
    }
}

impl RowSource for IndexNestedLoopJoin {
    fn next(&mut self) -> impl Future<Output = Result<Option<PlanRow>, RelStoreError>> + Send {
        async move {
            if let Some(row) = self.buffer.next() {
                return Ok(Some(row));
            }
            let Some(lrow) = self.left.next_boxed().await? else {
                return Ok(None);
            };
            let (bi, vi) = self.probe.value_source;
            let v = lrow.bindings[bi].values[vi].clone();
            // Three-valued ON (spec §4/concept 3.7): NULL never probes.
            let right_bindings = if matches!(v, ScalarValue::Null) {
                vec![self.probe.null_binding()]
            } else {
                let hits = self.probe.probe(&v).await?;
                if hits.is_empty() {
                    vec![self.probe.null_binding()] // LEFT-preserve on no match
                } else {
                    hits // fan-out: one output row per hit
                }
            };
            let mut rows: Vec<PlanRow> = right_bindings
                .into_iter()
                .map(|rb| {
                    let mut bindings = lrow.bindings.clone();
                    bindings.push(rb);
                    PlanRow { bindings }
                })
                .collect();
            let first = rows.remove(0);
            self.buffer = rows.into_iter(); // remaining fan-out rows served next
            Ok(Some(first))
        }
    }
}

/// The finitely many SELECT pipeline shapes over a join chain (spec §6 step
/// 5), mirroring v1's `RowPipeline` (select.rs) but based on
/// `IndexNestedLoopJoin` instead of `RowScan` — same Filter/Sort/OffsetLimit,
/// no new mechanism.
enum JoinRowPipeline {
    Plain(OffsetLimitOp<IndexNestedLoopJoin>),
    Filtered(OffsetLimitOp<Filter<IndexNestedLoopJoin>>),
    Sorted(OffsetLimitOp<Sort<IndexNestedLoopJoin>>),
    FilteredSorted(OffsetLimitOp<Sort<Filter<IndexNestedLoopJoin>>>),
}

impl JoinRowPipeline {
    async fn next(&mut self) -> Result<Option<PlanRow>, RelStoreError> {
        match self {
            JoinRowPipeline::Plain(p) => p.next().await,
            JoinRowPipeline::Filtered(p) => p.next().await,
            JoinRowPipeline::Sorted(p) => p.next().await,
            JoinRowPipeline::FilteredSorted(p) => p.next().await,
        }
    }

    fn limit_applied(&self) -> bool {
        match self {
            JoinRowPipeline::Plain(p) => p.limit_applied(),
            JoinRowPipeline::Filtered(p) => p.limit_applied(),
            JoinRowPipeline::Sorted(p) => p.limit_applied(),
            JoinRowPipeline::FilteredSorted(p) => p.limit_applied(),
        }
    }
}

// ── Multi-binding column resolution (spec §5) ────────────────────────────────

/// One FROM-/JOIN-chain source: its binding key (`AS` alias, else table name)
/// and schema, in statement order (base first, spec §5).
/// `pub(super)`: reused by the view CREATE-time/dependency structural bind
/// (rel/008 `view.rs`), which builds these directly from base tables once
/// the inliner has fully flattened a (possibly view-touching) SELECT.
pub(super) struct BindingInfo {
    pub(super) alias: String,
    pub(super) schema: Arc<TableSchema>,
}

/// Flat position of each binding's first column — the position space WHERE
/// residual/ORDER BY/projection resolve into once bindings are concatenated
/// via `select::flatten` (spec §5/§7.1). `pub(super)`: reused by rel/008 `view.rs`.
pub(super) fn flat_offsets(bindings: &[BindingInfo]) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(bindings.len());
    let mut acc = 0usize;
    for b in bindings {
        offsets.push(acc);
        acc += b.schema.columns.len();
    }
    offsets
}

/// `pub(super)`: reused by rel/008 `view.rs` (structural bind over a fully
/// flattened statement).
pub(super) fn check_unique_aliases(bindings: &[BindingInfo]) -> Result<(), RelStoreError> {
    let mut seen = HashSet::new();
    for b in bindings {
        if !seen.insert(b.alias.as_str()) {
            return Err(RelStoreError::InvalidSchema(format!(
                "duplicate alias/table name '{}' in this query — self-joins need unique aliases",
                b.alias
            )));
        }
    }
    Ok(())
}

/// Tries to resolve `cref` within `bindings` only. `Ok(None)` = not found in
/// *this* set (not yet an error — used by ON resolution, which tries two
/// disjoint sets); `Err` = a hard error (ambiguous, or an explicit qualifier
/// naming a binding not in this set... only reachable via the qualified arm
/// when the caller passes the full binding list, see `resolve_multi`).
fn try_resolve_in_many(
    cref: &ColumnRef,
    bindings: &[BindingInfo],
) -> Result<Option<(usize, usize)>, RelStoreError> {
    if let Some(q) = &cref.qualifier {
        let Some(bi) = bindings.iter().position(|b| &b.alias == q) else { return Ok(None) };
        let pos = bindings[bi]
            .schema
            .columns
            .iter()
            .position(|c| c.name == cref.name)
            .ok_or_else(|| RelStoreError::ColumnNotFound {
                table: bindings[bi].schema.name.clone(),
                name: cref.name.clone(),
            })?;
        return Ok(Some((bi, pos)));
    }
    let mut hit = None;
    for (bi, b) in bindings.iter().enumerate() {
        if let Some(pos) = b.schema.columns.iter().position(|c| c.name == cref.name) {
            if hit.is_some() {
                return Err(RelStoreError::AmbiguousColumn { name: cref.name.clone() });
            }
            hit = Some((bi, pos));
        }
    }
    Ok(hit)
}

/// General column resolution (spec §5: WHERE residual/ORDER BY/projection)
/// against the *full* binding list — qualified/unqualified, ambiguous, or
/// not-found all become hard errors here. `pub(super)`: reused by rel/008 `view.rs`.
pub(super) fn resolve_multi(cref: &ColumnRef, bindings: &[BindingInfo]) -> Result<(usize, usize), RelStoreError> {
    match try_resolve_in_many(cref, bindings)? {
        Some(hit) => Ok(hit),
        None if cref.qualifier.is_some() => Err(RelStoreError::InvalidSchema(format!(
            "unknown alias/table name '{}'",
            cref.qualifier.as_ref().unwrap()
        ))),
        None => Err(RelStoreError::ColumnNotFound {
            table: "<join>".to_string(),
            name: cref.name.clone(),
        }),
    }
}

/// Which side of the binding split an ON operand resolved into (spec §3).
enum OnSide {
    Known(usize, usize),
    New(usize),
}

/// Resolves one ON operand against the two disjoint sets a join stage sees:
/// the already-established bindings and the newly-joined table. Exactly one
/// must hit (spec §3's "violations" list; ambiguity/no-match are hard errors).
fn resolve_on_side(
    cref: &ColumnRef,
    known: &[BindingInfo],
    new_binding: &BindingInfo,
) -> Result<OnSide, RelStoreError> {
    let in_known = try_resolve_in_many(cref, known)?;
    let in_new = try_resolve_in_many(cref, std::slice::from_ref(new_binding))?;
    match (in_known, in_new) {
        (Some((bi, pos)), None) => Ok(OnSide::Known(bi, pos)),
        (None, Some((_, pos))) => Ok(OnSide::New(pos)),
        (Some(_), Some(_)) => Err(RelStoreError::AmbiguousColumn { name: cref.name.clone() }),
        (None, None) => Err(RelStoreError::ColumnNotFound {
            table: new_binding.schema.name.clone(),
            name: cref.name.clone(),
        }),
    }
}

// ── WHERE split: base-driving vs. residual-over-the-chain (spec §6 step 2/4) ─

/// True iff every column referenced anywhere in `expr` resolves — unambiguously
/// — to the base binding (`bindings[0]`) alone. Such a conjunct is the only
/// kind that may drive the base access path; anything else (join-table
/// columns, or a name ambiguous with a join table) becomes residual.
fn expr_is_base_only(expr: &Expr, bindings: &[BindingInfo]) -> bool {
    match expr {
        Expr::Compare { lhs, rhs, .. } => {
            operand_is_base_only(lhs, bindings) && operand_is_base_only(rhs, bindings)
        }
        Expr::In { col, .. } | Expr::Like { col, .. } | Expr::IsNull { col, .. } => {
            column_ref_is_base_only(col, bindings)
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            expr_is_base_only(a, bindings) && expr_is_base_only(b, bindings)
        }
        Expr::Not(e) | Expr::Paren(e) => expr_is_base_only(e, bindings),
    }
}

fn operand_is_base_only(op: &Operand, bindings: &[BindingInfo]) -> bool {
    match op {
        Operand::Column(cref) => column_ref_is_base_only(cref, bindings),
        _ => true, // literal/param: nothing to check
    }
}

fn column_ref_is_base_only(cref: &ColumnRef, bindings: &[BindingInfo]) -> bool {
    match &cref.qualifier {
        Some(q) => {
            q == &bindings[0].alias && bindings[0].schema.columns.iter().any(|c| c.name == cref.name)
        }
        None => {
            let hits =
                bindings.iter().filter(|b| b.schema.columns.iter().any(|c| c.name == cref.name)).count();
            hits == 1 && bindings[0].schema.columns.iter().any(|c| c.name == cref.name)
        }
    }
}

/// ANDs owned clones of `conjuncts` back together (the inverse of
/// `plan::flatten_and`, but over an owned `Expr` since `plan::plan_access`
/// wants a self-contained WHERE clause for just the base-driving subset).
fn fold_and_exprs(conjuncts: Vec<&Expr>) -> Option<Expr> {
    let mut it = conjuncts.into_iter();
    let first = it.next()?.clone();
    Some(it.fold(first, |acc, e| Expr::And(Box::new(acc), Box::new(e.clone()))))
}

// ── Flat multi-binding WHERE binder (spec §5) ────────────────────────────────
//
// Mirrors `dml::bind_predicate`/`bind_compare`/`bind_pred_operand` exactly,
// but resolves columns via `resolve_multi` (multi-binding) instead of
// `dml::resolve_column` (single-table), and binds `PredOperand::Column` to a
// *flat* position (spec rel/007 orchestrator note: flattening the `PlanRow`
// into one values list and binding to flat positions is the option that
// leaves `eval.rs` and rel/006's single-table `Pred`/`PredOperand` completely
// untouched — the alternative, lifting `PredOperand::Column` to a
// `(binding_idx, value_idx)` pair, would instead have to change `eval.rs`'s
// public types and every existing call site).
/// `pub(super)`: reused by rel/008 `view.rs` (structural bind over a fully
/// flattened statement).
pub(super) fn bind_flat_predicate(
    expr: &Expr,
    bindings: &[BindingInfo],
    offsets: &[usize],
    params: &[Value],
) -> Result<Pred, RelStoreError> {
    match expr {
        Expr::Paren(e) => bind_flat_predicate(e, bindings, offsets, params),
        Expr::Not(e) => Ok(Pred::Not(Box::new(bind_flat_predicate(e, bindings, offsets, params)?))),
        Expr::And(a, b) => Ok(Pred::And(
            Box::new(bind_flat_predicate(a, bindings, offsets, params)?),
            Box::new(bind_flat_predicate(b, bindings, offsets, params)?),
        )),
        Expr::Or(a, b) => Ok(Pred::Or(
            Box::new(bind_flat_predicate(a, bindings, offsets, params)?),
            Box::new(bind_flat_predicate(b, bindings, offsets, params)?),
        )),
        Expr::Compare { lhs, op, rhs } => bind_flat_compare(lhs, *op, rhs, bindings, offsets, params),
        Expr::In { col, negated, list } => {
            let (bi, pos) = resolve_multi(col, bindings)?;
            let c = &bindings[bi].schema.columns[pos];
            let list = list
                .iter()
                .map(|l| {
                    let t = super::dml::widen_predicate_hint(c.col_type, matches!(l, Literal::Real(_)));
                    super::dml::coerce_literal(t, l, &c.name)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Pred::In { col: offsets[bi] + pos, negated: *negated, list })
        }
        Expr::Like { col, negated, pattern } => {
            let (bi, pos) = resolve_multi(col, bindings)?;
            let c = &bindings[bi].schema.columns[pos];
            if !matches!(c.col_type.physical_type(), ColumnType::Text) {
                return Err(RelStoreError::TypeMismatch {
                    context: format!("LIKE on column '{}'", c.name),
                    expected: "Text".to_string(),
                    actual: format!("{:?}", c.col_type),
                });
            }
            Ok(Pred::Like { col: offsets[bi] + pos, negated: *negated, pattern: pattern.clone() })
        }
        Expr::IsNull { col, negated } => {
            let (bi, pos) = resolve_multi(col, bindings)?;
            Ok(Pred::IsNull { col: offsets[bi] + pos, negated: *negated })
        }
    }
}

fn bind_flat_compare(
    lhs: &Operand,
    op: CompareOp,
    rhs: &Operand,
    bindings: &[BindingInfo],
    offsets: &[usize],
    params: &[Value],
) -> Result<Pred, RelStoreError> {
    let hint = flat_operand_type_hint(lhs, bindings).or_else(|| flat_operand_type_hint(rhs, bindings));
    let (bl, tl) = bind_flat_operand(lhs, bindings, offsets, hint, params)?;
    let (br, tr) = bind_flat_operand(rhs, bindings, offsets, hint, params)?;
    if !super::dml::comparable(tl, tr) {
        return Err(RelStoreError::TypeMismatch {
            context: "WHERE comparison".to_string(),
            expected: "compatible operand types".to_string(),
            actual: "incompatible".to_string(),
        });
    }
    Ok(Pred::Compare { lhs: bl, op, rhs: br })
}

fn flat_operand_type_hint(op: &Operand, bindings: &[BindingInfo]) -> Option<ColumnType> {
    match op {
        Operand::Column(cref) => {
            resolve_multi(cref, bindings).ok().map(|(bi, pos)| bindings[bi].schema.columns[pos].col_type)
        }
        _ => None,
    }
}

fn bind_flat_operand(
    op: &Operand,
    bindings: &[BindingInfo],
    offsets: &[usize],
    hint: Option<ColumnType>,
    params: &[Value],
) -> Result<(PredOperand, Option<ColumnType>), RelStoreError> {
    match op {
        Operand::Column(cref) => {
            let (bi, pos) = resolve_multi(cref, bindings)?;
            let c = &bindings[bi].schema.columns[pos];
            Ok((PredOperand::Column(offsets[bi] + pos), Some(c.col_type.physical_type())))
        }
        _ => {
            let natural = super::dml::natural_type(op, params);
            let t = match hint {
                Some(h) => super::dml::widen_predicate_hint(h, natural == ColumnType::Real),
                None => natural,
            };
            let v = super::dml::bind_operand_value(t, op, params, "WHERE comparison")?;
            let vt = super::dml::scalar_physical_type(&v);
            Ok((PredOperand::Value(v), vt))
        }
    }
}

// ── Projection & ORDER BY over multiple bindings (spec §5/§7) ───────────────

/// `*` → all columns of all bindings in binding order (spec §5/§7.1,
/// duplicate names allowed); an explicit list resolves each column via
/// `resolve_multi` to a flat position.
/// `pub(super)`: reused by rel/008 `view.rs` (structural bind over a fully
/// flattened statement, and the `*`-expansion inside the inliner itself).
pub(super) fn bind_join_projection(
    items: &[SelectItem],
    bindings: &[BindingInfo],
    offsets: &[usize],
) -> Result<Vec<ProjectedColumn>, RelStoreError> {
    if items.len() == 1 && matches!(items[0], SelectItem::Star) {
        let mut proj = Vec::new();
        for (bi, b) in bindings.iter().enumerate() {
            for (local, c) in b.schema.columns.iter().enumerate() {
                proj.push(ProjectedColumn {
                    name: c.name.clone(),
                    col_type: c.col_type,
                    pos: offsets[bi] + local,
                    references: c.references.clone(),
                });
            }
        }
        return Ok(proj);
    }
    let mut proj = Vec::with_capacity(items.len());
    for item in items {
        match item {
            SelectItem::Column { col, alias } => {
                let (bi, pos) = resolve_multi(col, bindings)?;
                let c = &bindings[bi].schema.columns[pos];
                proj.push(ProjectedColumn {
                    name: alias.clone().unwrap_or_else(|| c.name.clone()),
                    col_type: c.col_type,
                    pos: offsets[bi] + pos,
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

fn bind_join_order_by(
    items: &[OrderItem],
    bindings: &[BindingInfo],
    offsets: &[usize],
) -> Result<Vec<(usize, bool)>, RelStoreError> {
    items
        .iter()
        .map(|o| resolve_multi(&o.col, bindings).map(|(bi, pos)| (offsets[bi] + pos, o.desc)))
        .collect()
}

/// Depth guard (spec §8): `already_used` lets a future caller (rel/009 expand
/// columns, which count against the same limit) feed in an already-consumed
/// starting depth — this spec always passes 0 (signature prep only, no logic).
/// `pub(super)`: reused by rel/008 `view.rs`'s CREATE-time full bind.
pub(super) fn check_join_depth(joins_len: usize, already_used: usize, max_join_depth: usize) -> Result<(), RelStoreError> {
    let depth = joins_len + already_used;
    if depth > max_join_depth {
        return Err(RelStoreError::JoinDepthExceeded { depth, max: max_join_depth });
    }
    Ok(())
}

/// ON resolution + type check for one join stage (spec §3) — the *structural*
/// half of `RelEngine::build_join_probe`, deliberately engine-free (no
/// index-requirement/probe-strategy decision): exactly one ON operand must
/// bind into `new_binding`, the other into an earlier binding (`known`,
/// arbitrarily deep). Returns `(value_source, right_col_pos, widen_int_to_real)`.
/// `pub(super)`: reused by rel/008 `view.rs`'s dependency re-bind (spec §7,
/// which explicitly excludes the index requirement — a dropped index alone
/// must not block unrelated DDL) *and* by `build_join_probe` below (which
/// layers the probe-strategy selection on top for CREATE-time/execution binding).
pub(super) fn resolve_join_on(
    j: &Join,
    known: &[BindingInfo],
    new_binding: &BindingInfo,
) -> Result<((usize, usize), usize, bool), RelStoreError> {
    let left_side = resolve_on_side(&j.left, known, new_binding)?;
    let right_side = resolve_on_side(&j.right, known, new_binding)?;
    let (value_source, right_col_pos) = match (left_side, right_side) {
        (OnSide::Known(bi, pos), OnSide::New(npos)) => ((bi, pos), npos),
        (OnSide::New(npos), OnSide::Known(bi, pos)) => ((bi, pos), npos),
        (OnSide::Known(..), OnSide::Known(..)) => {
            return Err(RelStoreError::InvalidSchema(format!(
                "ON {} = {}: both sides reference already-known tables; exactly one must reference the new join table '{}'",
                j.left.name, j.right.name, new_binding.schema.name
            )))
        }
        (OnSide::New(_), OnSide::New(_)) => {
            return Err(RelStoreError::InvalidSchema(format!(
                "ON {} = {}: both sides reference the new join table '{}'; exactly one must reference an earlier table",
                j.left.name, j.right.name, new_binding.schema.name
            )))
        }
    };
    let (left_bi, left_pos) = value_source;
    let left_col = &known[left_bi].schema.columns[left_pos];
    let right_col = &new_binding.schema.columns[right_col_pos];
    let lt = left_col.col_type.physical_type();
    let rt = right_col.col_type.physical_type();
    if !super::dml::comparable(Some(lt), Some(rt)) {
        return Err(RelStoreError::TypeMismatch {
            context: format!(
                "ON {}.{} = {}.{}",
                known[left_bi].alias, left_col.name, new_binding.alias, right_col.name
            ),
            expected: format!("{lt:?}"),
            actual: format!("{rt:?}"),
        });
    }
    // The only implicit widening is INTEGER -> REAL (spec §3); the reverse
    // (a REAL probe value against an INTEGER column) is a forbidden narrowing.
    if lt == ColumnType::Real && rt == ColumnType::Integer {
        return Err(RelStoreError::TypeMismatch {
            context: format!(
                "ON {}.{} = {}.{}",
                known[left_bi].alias, left_col.name, new_binding.alias, right_col.name
            ),
            expected: "INTEGER (narrowing a REAL value into an INTEGER column is not allowed)".to_string(),
            actual: "REAL".to_string(),
        });
    }
    let widen_int_to_real = lt == ColumnType::Integer && rt == ColumnType::Real;
    Ok((value_source, right_col_pos, widen_int_to_real))
}

// ── Probe-build environment (spec §7 too_many_arguments finding) ────────────

/// The four statement-wide constants every join stage's `build_join_probe`
/// call needs, bundled to stay under Clippy's argument-count threshold. Pure
/// data bundling of what `JoinProbe` already carries as fields — no new
/// abstraction; built once per statement, passed by reference per stage.
pub(super) struct ProbeEnv<'a> {
    pub(super) prefix: &'a [u8],
    pub(super) snap: &'a Snapshot,
    pub(super) fallback_budget: &'a Arc<AtomicU64>,
    pub(super) mask: LinkMask,
}

// ── exec_select_joined helpers (spec §6) ─────────────────────────────────────

/// WHERE split (step 2/4): base-only top-level conjuncts (may drive the base
/// scan) vs. everything else (residual over the chain).
fn split_where<'a>(where_clause: &'a Option<Expr>, bindings: &[BindingInfo]) -> (Vec<&'a Expr>, Vec<&'a Expr>) {
    let mut base_conjuncts: Vec<&Expr> = Vec::new();
    let mut other_conjuncts: Vec<&Expr> = Vec::new();
    if let Some(e) = where_clause {
        let mut all = Vec::new();
        plan::flatten_and(e, &mut all);
        for c in all {
            if expr_is_base_only(c, bindings) {
                base_conjuncts.push(c);
            } else {
                other_conjuncts.push(c);
            }
        }
    }
    (base_conjuncts, other_conjuncts)
}

/// ANDs the base access path's own residual together with every join-touching
/// WHERE conjunct, bound at flat positions (step 4).
fn fold_residual(
    base_residual: Option<Pred>,
    other: Vec<&Expr>,
    bindings: &[BindingInfo],
    offsets: &[usize],
    params: &[Value],
) -> Result<Option<Pred>, RelStoreError> {
    let mut residual = base_residual;
    for c in other {
        let bound = bind_flat_predicate(c, bindings, offsets, params)?;
        residual = Some(match residual {
            Some(r) => Pred::And(Box::new(r), Box::new(bound)),
            None => bound,
        });
    }
    Ok(residual)
}

/// ORDER BY free-order special case (spec §7): only a single ORDER BY item on
/// a *base* column can possibly ride the base access path's key order for
/// free; anything else (including COUNT, which has no output order) forces
/// the Sort path regardless.
fn base_order_hint(sel: &Select, bindings: &[BindingInfo], is_count: bool) -> Vec<(usize, bool)> {
    if !is_count && sel.order_by.len() == 1 {
        match resolve_multi(&sel.order_by[0].col, bindings) {
            Ok((0, pos)) => vec![(pos, sel.order_by[0].desc)],
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    }
}

/// No key-count shortcut over a join (spec §7): fan-out and LEFT preservation
/// change the count vs. the raw key set, so this always iterates the
/// pipeline (residual-filtered, if any).
async fn count_join_rows(chain: IndexNestedLoopJoin, residual: Option<Pred>) -> Result<i64, RelStoreError> {
    let mut count: i64 = 0;
    match residual {
        None => {
            let mut c = chain;
            while c.next().await?.is_some() {
                count += 1;
            }
        }
        Some(pred) => {
            let mut f = Filter { input: chain, pred };
            while f.next().await?.is_some() {
                count += 1;
            }
        }
    }
    Ok(count)
}

// ── Planner & executor entry point (spec §1/§6) ──────────────────────────────

impl RelEngine {
    /// Resolves one FROM-/JOIN-chain table reference. `select::exec_select`'s
    /// `view::inline_views` pre-pass (rel/008 §1) runs before this ever does,
    /// so a view can no longer reach here; missing → `TableNotFound`.
    fn require_table_for_join(&self, domain: &str, name: &str) -> Result<TableSchema, RelStoreError> {
        match self.catalog.get(&self.domains, domain, name) {
            Ok(CatalogEntry::Table(t)) => Ok(t),
            // Resolved as a table during inlining; a view here means concurrent
            // DDL swapped the object in between — error, don't panic on the race.
            Ok(CatalogEntry::View(_)) => Err(RelStoreError::TableNotFound {
                domain: domain.to_string(),
                name: name.to_string(),
            }),
            Err(RelStoreError::ObjectNotFound { domain, name }) => Err(RelStoreError::TableNotFound { domain, name }),
            Err(e) => Err(e),
        }
    }

    /// ON resolution + probe-strategy selection for one join stage (spec §3):
    /// exactly one ON operand must bind into `new_binding`, the other into an
    /// earlier binding (`known`, arbitrarily deep — not just the previous stage).
    /// `pub(super)`: reused by rel/008 `view.rs`'s CREATE-time full bind (which
    /// needs the index requirement too, unlike the DDL dependency check —
    /// see `resolve_join_on`).
    pub(super) fn build_join_probe(
        &self,
        j: &Join,
        known: &[BindingInfo],
        new_binding: &BindingInfo,
        env: &ProbeEnv<'_>,
    ) -> Result<JoinProbe, RelStoreError> {
        let (value_source, right_col_pos, widen_int_to_real) = resolve_join_on(j, known, new_binding)?;
        let right_col = &new_binding.schema.columns[right_col_pos];

        let strategy = if right_col.primary_key {
            ProbeStrategy::PkPoint
        } else if let Some(ix) = new_binding
            .schema
            .indexes
            .iter()
            .filter(|ix| ix.column == right_col.name)
            .min_by_key(|ix| ix.index_id)
        {
            ProbeStrategy::Index { index_id: ix.index_id }
        } else if self.allow_unindexed_joins {
            ProbeStrategy::ScanFallback
        } else {
            return Err(RelStoreError::UnindexedJoin {
                table: new_binding.schema.name.clone(),
                column: right_col.name.clone(),
                hint: format!("CREATE INDEX <name> ON {} ({})", new_binding.schema.name, right_col.name),
            });
        };

        Ok(JoinProbe {
            engine: Arc::clone(&self.engine),
            snapshot: env.snap.clone(),
            metrics: Arc::clone(&self.metrics),
            right_prefix: env.prefix.to_vec(),
            right_table: Arc::clone(&new_binding.schema),
            right_alias: new_binding.alias.clone(),
            right_col_pos,
            value_source,
            strategy,
            widen_int_to_real,
            fallback_budget: Arc::clone(env.fallback_budget),
            max_fallback_scan: self.max_sort_rows,
            mask: env.mask,
        })
    }

    /// Runs a `LEFT JOIN` SELECT/COUNT end to end (spec §1/§6): depth guard →
    /// resolve every table ref (a view can no longer appear here — rel/008's
    /// `view::inline_views` pre-pass already replaced it) → split WHERE into
    /// base-driving vs. residual-over-the-chain → plan the base access path
    /// (rel/006 §3, unchanged) → build one `JoinProbe` per stage (§3) → stack
    /// `IndexNestedLoopJoin`s left-deep (§6) → `Filter`? → `Sort`? →
    /// `OffsetLimit` → project (or count).
    pub(super) async fn exec_select_joined(
        &self,
        domain: &str,
        sel: Select,
        params: &[Value],
        auth: LinkAuth,
    ) -> Result<ExecOutcome, RelStoreError> {
        check_join_depth(sel.joins.len(), 0, self.max_join_depth)?;

        let dom = self.domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let base_schema = Arc::new(self.require_table_for_join(domain, &sel.from.name)?);
        let base_alias = sel.from.alias.clone().unwrap_or_else(|| base_schema.name.clone());
        let mut bindings = vec![BindingInfo { alias: base_alias, schema: base_schema }];
        for j in &sel.joins {
            let schema = Arc::new(self.require_table_for_join(domain, &j.table.name)?);
            let alias = j.table.alias.clone().unwrap_or_else(|| schema.name.clone());
            bindings.push(BindingInfo { alias, schema });
        }
        check_unique_aliases(&bindings)?;
        let offsets = flat_offsets(&bindings);

        // One masking lookup for the whole query (spec rel/012 §3): every
        // binding shares this rel domain, so one KV/JSON status pair covers all.
        let schemas: Vec<&TableSchema> = bindings.iter().map(|b| b.schema.as_ref()).collect();
        let mask = self.compute_link_mask(domain, &schemas, auth).await?;

        self.metrics.record_rel_select_statement();

        // One snapshot for the whole statement — base *and* every join fetch
        // (spec §2 Snapshot & Ghosts). Kept alive for the whole function so
        // compaction cannot advance past it mid-pipeline.
        let snapshot_guard = self.engine.snapshot();
        let snap = snapshot_guard.snapshot().clone();

        let is_count = sel.items.len() == 1 && matches!(sel.items[0], SelectItem::CountStar);

        // WHERE split (spec §6 step 2/4): only base-only top-level conjuncts
        // may drive the base scan; everything else is residual over the chain.
        let (base_conjuncts, other_conjuncts) = split_where(&sel.where_clause, &bindings);
        let base_where = fold_and_exprs(base_conjuncts);

        // ORDER BY free-order special case (spec §7): only a single ORDER BY
        // item on a *base* column can possibly ride the base access path's key
        // order for free; anything else forces the Sort path regardless.
        let base_order_local = base_order_hint(&sel, &bindings, is_count);
        let base_quals = vec![bindings[0].alias.clone()];
        let base_plan =
            plan::plan_access(&bindings[0].schema, &base_where, &base_quals, params, &base_order_local, mask)?;

        let (mut row_keys, scanned) = select::resolve_candidate_keys(
            &self.engine,
            &bindings[0].schema,
            &prefix,
            &base_plan.access,
            &snap,
            None,
        )
        .await?;
        let order_free = !base_order_local.is_empty() && base_plan.order_free;
        if order_free && base_plan.order_desc {
            row_keys.reverse();
        }
        self.metrics.record_rel_select_scanned_keys(scanned);

        let base_scan = RowScan {
            engine: Arc::clone(&self.engine),
            snapshot: snap.clone(),
            schema: Arc::clone(&bindings[0].schema),
            table_id: bindings[0].schema.table_id,
            alias: bindings[0].alias.clone(),
            keys: row_keys.into_iter(),
            mask,
        };

        // One JoinProbe per stage, in statement order (left-deep, spec §6).
        let fallback_budget = Arc::new(AtomicU64::new(0));
        let env = ProbeEnv { prefix: &prefix, snap: &snap, fallback_budget: &fallback_budget, mask };
        let mut probes = Vec::with_capacity(sel.joins.len());
        for (k, j) in sel.joins.iter().enumerate() {
            let known = &bindings[0..=k];
            let new_binding = &bindings[k + 1];
            probes.push(self.build_join_probe(j, known, new_binding, &env)?);
        }

        // Residual = base_plan's own residual (already base-local, which is
        // flat-position-0-based) AND every other (join-touching) conjunct,
        // bound at flat positions.
        let residual = fold_residual(base_plan.residual, other_conjuncts, &bindings, &offsets, params)?;

        let mut iter = probes.into_iter();
        let first_probe = iter.next().expect("joins non-empty — guarded by the select.rs dispatch");
        let mut chain = IndexNestedLoopJoin::new(Box::new(base_scan), first_probe);
        for probe in iter {
            chain = IndexNestedLoopJoin::new(Box::new(chain), probe);
        }

        if is_count {
            let count = count_join_rows(chain, residual).await?;
            return Ok(ExecOutcome::Select(super::dml::SelectResult {
                columns: vec![("count".to_string(), ColumnType::Integer)],
                rows: vec![vec![ScalarValue::Integer(count)]],
                limit_applied: false,
                // COUNT(*) has no REFERENCES column to expand.
                column_refs: vec![None],
                joins_used: sel.joins.len(),
                snapshot: None,
            }));
        }

        let proj = bind_join_projection(&sel.items, &bindings, &offsets)?;
        let order_items_flat = bind_join_order_by(&sel.order_by, &bindings, &offsets)?;
        let (offset, limit, capped) = select::bind_limit(&sel.limit, self.default_limit, self.max_limit)?;
        let needs_sort = !sel.order_by.is_empty() && !order_free;

        let mut pipeline = match (residual, needs_sort) {
            (None, false) => JoinRowPipeline::Plain(OffsetLimitOp::new(chain, offset, limit)),
            (Some(pred), false) => {
                JoinRowPipeline::Filtered(OffsetLimitOp::new(Filter { input: chain, pred }, offset, limit))
            }
            (None, true) => JoinRowPipeline::Sorted(OffsetLimitOp::new(
                Sort::new(chain, order_items_flat.clone(), self.max_sort_rows),
                offset,
                limit,
            )),
            (Some(pred), true) => JoinRowPipeline::FilteredSorted(OffsetLimitOp::new(
                Sort::new(Filter { input: chain, pred }, order_items_flat.clone(), self.max_sort_rows),
                offset,
                limit,
            )),
        };

        let mut rows = Vec::new();
        while let Some(row) = pipeline.next().await? {
            let values = flatten(&row.bindings);
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
            joins_used: sel.joins.len(),
            // `snap` was only ever cloned/borrowed above (`base_scan`,
            // `build_join_probe`), so it's still ours to hand to `expand`
            // (rel/009 §5) — the same snapshot the join itself read at.
            snapshot: Some(snap),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use std::sync::atomic::Ordering as AtomicOrdering;

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

    fn join_probes(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_join_probes_total.load(AtomicOrdering::Relaxed)
    }
    fn scanned_keys(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_select_scanned_keys_total.load(AtomicOrdering::Relaxed)
    }
    fn sort_fallback_total(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_sort_fallback_total.load(AtomicOrdering::Relaxed)
    }

    async fn setup_a_b(rel: &RelEngine) {
        ok(rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, note TEXT)").await;
        ok(rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER)").await;
    }

    // 1. PK-probe (link resolution): matched rows widen; unmatched rows get
    // the all-NULL binding.
    #[tokio::test]
    async fn test_pk_probe_link_resolution() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x'), (2, 'y')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, 2), (12, NULL), (13, 99)").await;

        let s = sel(&rel, "SELECT a.id, b.id, b.note FROM a LEFT JOIN b ON a.b_id = b.id ORDER BY a.id").await;
        assert_eq!(s.rows.len(), 4);
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(10), ScalarValue::Integer(1), ScalarValue::Text("x".into())]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(11), ScalarValue::Integer(2), ScalarValue::Text("y".into())]);
        assert_eq!(s.rows[2], vec![ScalarValue::Integer(12), ScalarValue::Null, ScalarValue::Null]);
        assert_eq!(s.rows[3], vec![ScalarValue::Integer(13), ScalarValue::Null, ScalarValue::Null]);
    }

    // 2. INNER-emulation: WHERE b.id IS NOT NULL drops the unmatched rows,
    // through the unchanged rel/005 evaluator.
    #[tokio::test]
    async fn test_inner_emulation_via_is_not_null() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, NULL), (12, 99)").await;

        let s = sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.b_id = b.id WHERE b.id IS NOT NULL").await;
        assert_eq!(ints(&s.rows, 0), vec![10]);
    }

    // 3. Non-unique index probe -> one output row per right-hand hit (fan-out).
    #[tokio::test]
    async fn test_nonunique_index_probe_fan_out() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, grp INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_grp ON b (grp)").await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, g INTEGER)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 5), (2, 5), (3, 9)").await;
        ok(&rel, "INSERT INTO a VALUES (10, 5)").await;

        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.g = b.grp ORDER BY b.id").await;
        assert_eq!(s.rows.len(), 2);
        assert_eq!(ints(&s.rows, 1), vec![1, 2]);
    }

    // 4. Unique-index probe: 0 or 1 right-hand row.
    #[tokio::test]
    async fn test_unique_index_probe() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, code TEXT UNIQUE)").await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, code TEXT)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 'x'), (11, 'ghost')").await;

        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.code = b.code ORDER BY a.id").await;
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(10), ScalarValue::Integer(1)]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(11), ScalarValue::Null]);
    }

    // 5. NULL left ON value: no probe at all, all-NULL binding; the probes
    // metric must not move.
    #[tokio::test]
    async fn test_null_on_value_no_probe() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x')").await;
        ok(&rel, "INSERT INTO a VALUES (10, NULL)").await;

        let before = join_probes(&rel);
        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.b_id = b.id").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(10), ScalarValue::Null]]);
        assert_eq!(join_probes(&rel), before, "a NULL ON value must not count as a probe");
    }

    // 6. Dangling link: the referenced row is gone -> all-NULL binding
    // (tolerant, concept 3.4), not an error.
    #[tokio::test]
    async fn test_dangling_link_tolerant() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO a VALUES (10, 999)").await; // b(999) never existed
        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.b_id = b.id").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(10), ScalarValue::Null]]);
    }

    // 7. Join chain (3 tables), left-deep: bindings append in statement order;
    // the third stage probes with a value from the *first* table, not the
    // immediately preceding one.
    #[tokio::test]
    async fn test_join_chain_left_deep() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE c (id INTEGER PRIMARY KEY, a_id INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_c_a ON c (a_id)").await;
        ok(&rel, "INSERT INTO b VALUES (1)").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1)").await;
        ok(&rel, "INSERT INTO c VALUES (100, 10), (101, 10)").await;

        let s = sel(
            &rel,
            "SELECT a.id, b.id, c.id FROM a LEFT JOIN b ON a.b_id = b.id LEFT JOIN c ON a.id = c.a_id ORDER BY c.id",
        )
        .await;
        assert_eq!(s.rows.len(), 2);
        assert_eq!(ints(&s.rows, 2), vec![100, 101]);
        assert_eq!(ints(&s.rows, 0), vec![10, 10]);
        assert_eq!(ints(&s.rows, 1), vec![1, 1]);
    }

    // 8. Self-join with aliases disambiguates; the same query without aliases
    // (duplicate binding key) -> InvalidSchema.
    #[tokio::test]
    async fn test_self_join_aliases_and_duplicate_key() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE emp (id INTEGER PRIMARY KEY, mgr_id INTEGER)").await;
        ok(&rel, "INSERT INTO emp VALUES (1, NULL), (2, 1)").await;

        let s = sel(&rel, "SELECT e.id, m.id FROM emp e LEFT JOIN emp m ON e.mgr_id = m.id ORDER BY e.id").await;
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(1), ScalarValue::Null]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(2), ScalarValue::Integer(1)]);

        let e = err(&rel, "SELECT * FROM emp LEFT JOIN emp ON emp.mgr_id = emp.id").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "got: {e}");
    }

    // 9. Index requirement: an unindexed right ON-column with allow_unindexed_joins
    // = false -> UnindexedJoin with a CREATE INDEX hint.
    #[tokio::test]
    async fn test_unindexed_join_rejected_by_default() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 5)").await;
        ok(&rel, "INSERT INTO a VALUES (10, 5)").await;

        let e = err(&rel, "SELECT * FROM a LEFT JOIN b ON a.tag = b.tag").await;
        match &e {
            RelStoreError::UnindexedJoin { table, column, hint } => {
                assert_eq!(table, "b");
                assert_eq!(column, "tag");
                assert!(hint.contains("CREATE INDEX"), "hint: {hint}");
            }
            _ => panic!("got: {e}"),
        }
    }

    // 10. Fallback scan: allow_unindexed_joins = true produces a correct
    // result; cumulative scanned rows over max_sort_rows -> UnindexedJoinScanExceeded.
    #[tokio::test]
    async fn test_unindexed_join_fallback_and_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { allow_unindexed_joins: true, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 5), (2, 9)").await;
        ok(&rel, "INSERT INTO a VALUES (10, 5), (11, 9)").await;

        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.tag = b.tag ORDER BY a.id").await;
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(10), ScalarValue::Integer(1)]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(11), ScalarValue::Integer(2)]);

        let dir2 = tempfile::TempDir::new().unwrap();
        let rel2 =
            boot(RelStoreConfig { allow_unindexed_joins: true, max_sort_rows: 3, ..config_in(dir2.path()) }).await;
        ok(&rel2, "CREATE TABLE b (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel2, "CREATE TABLE a (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel2, "INSERT INTO b VALUES (1, 5), (2, 9), (3, 1), (4, 2)").await; // 4 rows scanned per probe
        ok(&rel2, "INSERT INTO a VALUES (10, 5), (11, 9)").await;

        let e = err(&rel2, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.tag = b.tag").await;
        assert!(matches!(e, RelStoreError::UnindexedJoinScanExceeded { .. }), "got: {e}");
    }

    // 11. max_join_depth: a chain longer than the limit -> JoinDepthExceeded,
    // before any execution.
    #[tokio::test]
    async fn test_max_join_depth_exceeded() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { max_join_depth: 1, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE c (id INTEGER PRIMARY KEY)").await;

        let e = err(&rel, "SELECT * FROM a LEFT JOIN b ON a.id = b.id LEFT JOIN c ON a.id = c.id").await;
        assert!(matches!(e, RelStoreError::JoinDepthExceeded { depth: 2, max: 1 }), "got: {e}");
    }

    // 12. Column resolution: a qualified reference resolves; the same name
    // unqualified across two bindings -> AmbiguousColumn; unqualified but
    // unique -> ok.
    #[tokio::test]
    async fn test_column_resolution_qualified_ambiguous_unique() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, name TEXT)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_b_a_id ON b (a_id)").await;
        ok(&rel, "INSERT INTO a VALUES (1, 'x')").await;
        ok(&rel, "INSERT INTO b VALUES (100, 1)").await;

        let s = sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.id = b.a_id WHERE a.id = 1").await;
        assert_eq!(ints(&s.rows, 0), vec![1]);

        let e = err(&rel, "SELECT * FROM a LEFT JOIN b ON a.id = b.a_id WHERE id = 1").await;
        assert!(matches!(e, RelStoreError::AmbiguousColumn { .. }), "got: {e}");

        let s = sel(&rel, "SELECT name FROM a LEFT JOIN b ON a.id = b.a_id").await;
        assert_eq!(s.rows[0][0], ScalarValue::Text("x".into()));
    }

    // 13. Projection *: all columns of all bindings in binding order;
    // colliding names (id/id) allowed since rows are arrays.
    #[tokio::test]
    async fn test_star_projection_binding_order_and_duplicates() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, v INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_b_a_id ON b (a_id)").await;
        ok(&rel, "INSERT INTO a VALUES (1, 100)").await;
        ok(&rel, "INSERT INTO b VALUES (5, 1)").await;

        let s = sel(&rel, "SELECT * FROM a LEFT JOIN b ON a.id = b.a_id").await;
        assert_eq!(s.columns.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), vec!["id", "v", "id", "a_id"]);
        assert_eq!(
            s.rows[0],
            vec![ScalarValue::Integer(1), ScalarValue::Integer(100), ScalarValue::Integer(5), ScalarValue::Integer(1)]
        );
    }

    // 14. Explicit projection `a.id, b.id`: two `id` columns; AS disambiguates
    // the wire names.
    #[tokio::test]
    async fn test_explicit_projection_as_disambiguates() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_b_a_id ON b (a_id)").await;
        ok(&rel, "INSERT INTO a VALUES (1)").await;
        ok(&rel, "INSERT INTO b VALUES (5, 1)").await;

        let s = sel(&rel, "SELECT a.id AS aid, b.id AS bid FROM a LEFT JOIN b ON a.id = b.a_id").await;
        assert_eq!(s.columns.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(), vec!["aid", "bid"]);
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(1), ScalarValue::Integer(5)]);
    }

    // 15. ON assignment is not positional: `ON b.id = a.b_id` behaves exactly
    // like `ON a.b_id = b.id`.
    #[tokio::test]
    async fn test_on_side_order_not_positional() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1)").await;

        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON b.id = a.b_id").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(10), ScalarValue::Integer(1)]]);
    }

    // 16. ON shape errors: both operands the same/no new table -> InvalidSchema;
    // INTEGER -> REAL widening works; REAL -> INTEGER narrowing is rejected.
    #[tokio::test]
    async fn test_on_form_errors_and_widening() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, x INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, y INTEGER)").await;
        ok(&rel, "INSERT INTO a VALUES (1, 5)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 5)").await;

        let e = err(&rel, "SELECT * FROM a LEFT JOIN b ON a.x = a.id").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "got: {e}");
        let e = err(&rel, "SELECT * FROM a LEFT JOIN b ON b.y = b.id").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "got: {e}");

        ok(&rel, "CREATE TABLE s (id INTEGER PRIMARY KEY, code REAL)").await;
        ok(&rel, "CREATE INDEX idx_code ON s (code)").await;
        ok(&rel, "INSERT INTO s VALUES (7, 5.0)").await;
        let s2 = sel(&rel, "SELECT a.id, s.id FROM a LEFT JOIN s ON a.x = s.code").await;
        assert_eq!(s2.rows, vec![vec![ScalarValue::Integer(1), ScalarValue::Integer(7)]]);

        ok(&rel, "CREATE TABLE r (id INTEGER PRIMARY KEY, v REAL)").await;
        ok(&rel, "INSERT INTO r VALUES (1, 5.0)").await;
        ok(&rel, "CREATE TABLE t2 (id INTEGER PRIMARY KEY, k INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_t2_k ON t2 (k)").await;
        let e = err(&rel, "SELECT * FROM r LEFT JOIN t2 ON r.v = t2.k").await;
        assert!(matches!(e, RelStoreError::TypeMismatch { .. }), "got: {e}");
    }

    // 17. ORDER BY on the base PK: free ordering (no Sort) even with fan-out,
    // since fan-out rows share their base row's key.
    #[tokio::test]
    async fn test_order_by_base_pk_free_despite_fanout() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, grp INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_grp ON b (grp)").await;
        ok(&rel, "INSERT INTO a VALUES (3), (1), (2)").await;
        ok(&rel, "INSERT INTO b VALUES (10, 1), (11, 1), (12, 2)").await;

        let before = sort_fallback_total(&rel);
        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.id = b.grp ORDER BY a.id").await;
        assert_eq!(ints(&s.rows, 0), vec![1, 1, 2, 3]);
        assert_eq!(sort_fallback_total(&rel), before, "base PK order must be free even with fan-out");
    }

    // 18. ORDER BY on a join-table column: Sort path.
    #[tokio::test]
    async fn test_order_by_join_column_uses_sort() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'z'), (2, 'a')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, 2)").await;

        let before = sort_fallback_total(&rel);
        let s = sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.b_id = b.id ORDER BY b.note").await;
        assert_eq!(ints(&s.rows, 0), vec![11, 10]);
        assert_eq!(sort_fallback_total(&rel), before + 1);
    }

    // 19. WHERE split: a base-only conjunct drives the base scan (PK-point,
    // not a full scan); a conjunct on the right table filters over the join.
    #[tokio::test]
    async fn test_where_split_base_drives_right_filters_over_join() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, note TEXT)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 'keep'), (2, 'drop')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, 2)").await;

        let before = scanned_keys(&rel);
        let s = sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.b_id = b.id WHERE a.id = 10 AND b.note = 'keep'").await;
        let after = scanned_keys(&rel);
        assert_eq!(ints(&s.rows, 0), vec![10]);
        // 1 base PK-point key + 1 right-hand PK-point probe key — not a full
        // scan of either table.
        assert_eq!(after - before, 2, "PK-point base access + PK-point probe, no full scan");
    }

    // 20. LIMIT/OFFSET over a join, including fan-out; limit_applied semantics.
    #[tokio::test]
    async fn test_limit_offset_over_join_with_fanout() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, grp INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_grp ON b (grp)").await;
        ok(&rel, "INSERT INTO a VALUES (1), (2)").await;
        ok(&rel, "INSERT INTO b VALUES (10, 1), (11, 1), (12, 2)").await;

        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.id = b.grp ORDER BY a.id, b.id LIMIT 2").await;
        assert_eq!(s.rows.len(), 2);
        assert_eq!(ints(&s.rows, 1), vec![10, 11]);
        assert!(s.limit_applied, "more output rows exist past LIMIT 2");

        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.id = b.grp ORDER BY a.id, b.id LIMIT 10").await;
        assert_eq!(s.rows.len(), 3);
        assert!(!s.limit_applied);
    }

    // 21. COUNT(*) over a join: counts output rows including LEFT-preserved
    // ones, post-residual; ORDER BY is ignored.
    #[tokio::test]
    async fn test_count_star_over_join() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, NULL), (12, 99)").await;

        let s = sel(&rel, "SELECT COUNT(*) FROM a LEFT JOIN b ON a.b_id = b.id ORDER BY a.id").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(3)]]);
        assert!(!s.limit_applied);
    }

    // 22 (superseded by rel/008): a view touching the join (base or join
    // side) is inlined to its base table before the join planner ever runs
    // — see view.rs for the dedicated view-in-join test coverage.
    #[tokio::test]
    async fn test_view_touching_join_now_inlines() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO a VALUES (1)").await;
        ok(&rel, "INSERT INTO b VALUES (1)").await;
        rel.create_view("default", "va", "SELECT * FROM a").await.unwrap();

        let s = sel(&rel, "SELECT * FROM va LEFT JOIN b ON va.id = b.id").await;
        assert_eq!(s.rows.len(), 1, "view in FROM position joins fine");

        let s = sel(&rel, "SELECT * FROM a LEFT JOIN va ON a.id = va.id").await;
        assert_eq!(s.rows.len(), 1, "view in JOIN position (no WHERE) joins fine");
    }

    // 23. MVCC/Ghost on the right side: a key live at scan time but gone at
    // the (older) snapshot is skipped, not surfaced as a hit. Driving this
    // through the SQL surface would need an externally-injected snapshot,
    // which `execute()` does not expose (same reasoning as rel/006's own
    // ghost test) — exercised white-box on `JoinProbe` directly instead.
    #[tokio::test]
    async fn test_right_side_ghost_skipped_white_box() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1)").await;

        let snapshot_guard = rel.engine().snapshot();
        let snap = snapshot_guard.snapshot().clone();
        ok(&rel, "INSERT INTO b VALUES (1)").await; // live now, but not in `snap`

        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let b_schema = match rel.get_object("default", "b").unwrap() {
            CatalogEntry::Table(t) => Arc::new(t),
            _ => unreachable!(),
        };
        let probe = JoinProbe {
            engine: Arc::clone(rel.engine()),
            snapshot: snap,
            metrics: Arc::clone(&rel.metrics),
            right_prefix: prefix,
            right_table: Arc::clone(&b_schema),
            right_alias: "b".to_string(),
            right_col_pos: 0,
            value_source: (0, 1),
            strategy: ProbeStrategy::PkPoint,
            widen_int_to_real: false,
            fallback_budget: Arc::new(AtomicU64::new(0)),
            max_fallback_scan: 100_000,
            mask: LinkMask::default(),
        };
        let hits = probe.probe(&ScalarValue::Integer(1)).await.unwrap();
        assert!(hits.is_empty(), "a ghost key must be skipped, not surfaced as a hit");
    }

    // 24. Metrics: rel_join_probes_total +1 per executed probe (NULL ON values
    // excluded); visited probe keys increase rel_select_scanned_keys_total.
    #[tokio::test]
    async fn test_join_metrics() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'x'), (2, 'y')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, 2), (12, NULL)").await;

        let probes_before = join_probes(&rel);
        let keys_before = scanned_keys(&rel);
        sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.b_id = b.id").await;
        assert_eq!(join_probes(&rel) - probes_before, 2, "only the 2 non-NULL ON values probe");
        assert!(scanned_keys(&rel) > keys_before, "probe key visits must be counted");
    }

    // 25. COUNT(*) over a join with a WHERE residual (a join-table conjunct,
    // so `other_conjuncts` is non-empty): the `Some(pred)` arm in the COUNT
    // branch (quality/007 prep work).
    #[tokio::test]
    async fn test_count_star_over_join_with_residual() {
        let (rel, _d) = make().await;
        setup_a_b(&rel).await;
        ok(&rel, "INSERT INTO b VALUES (1, 'keep'), (2, 'drop')").await;
        ok(&rel, "INSERT INTO a VALUES (10, 1), (11, 2), (12, NULL)").await;

        let s = sel(&rel, "SELECT COUNT(*) FROM a LEFT JOIN b ON a.b_id = b.id WHERE b.note = 'keep'").await;
        assert_eq!(s.rows, vec![vec![ScalarValue::Integer(1)]]);
    }

    // 26 (007-F1 regression): the scan-fallback cap must bound the storage
    // scan itself, not just the reported cumulative total. (a) a right table
    // within the cap still yields the same join result as before; (b) a
    // right table over the cap reports `scanned` bounded by `max + 1` — the
    // pre-fix code instead reports b's actual (much larger) row count, since
    // it always materialized the full table before ever checking the cap.
    #[tokio::test]
    async fn test_scan_fallback_caps_the_scan_before_materializing() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { allow_unindexed_joins: true, max_sort_rows: 50, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 5), (2, 9), (3, 1)").await;
        ok(&rel, "INSERT INTO a VALUES (10, 5), (11, 9)").await;
        let s = sel(&rel, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.tag = b.tag ORDER BY a.id").await;
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(10), ScalarValue::Integer(1)]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(11), ScalarValue::Integer(2)]);

        let dir2 = tempfile::TempDir::new().unwrap();
        let rel2 =
            boot(RelStoreConfig { allow_unindexed_joins: true, max_sort_rows: 3, ..config_in(dir2.path()) }).await;
        ok(&rel2, "CREATE TABLE b (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel2, "CREATE TABLE a (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        ok(&rel2, "INSERT INTO b VALUES (1,1),(2,2),(3,3),(4,4),(5,5),(6,6),(7,7),(8,8),(9,9),(10,10)").await;
        ok(&rel2, "INSERT INTO a VALUES (100, 1)").await;

        // `scanned` comes straight from the same `n` the scanned-keys metric
        // is recorded with (spec rel/007 F1) — asserting it is capped at
        // max+1 proves both the scan and the metric reflect the capped read,
        // not b's full (10-row) table.
        let e = err(&rel2, "SELECT a.id, b.id FROM a LEFT JOIN b ON a.tag = b.tag").await;
        match e {
            RelStoreError::UnindexedJoinScanExceeded { scanned, max } => {
                assert_eq!(max, 3);
                assert_eq!(scanned, 4, "scan must be capped at max+1 (4), not b's full row count (10)");
            }
            other => panic!("got: {other}"),
        }
    }

    // 27 (012-F1 regression): a masked right ON-column (its link target
    // domain gone) must probe empty — under 3-valued ON equality NULL never
    // matches, and a masked column reads NULL on every row — without ever
    // touching storage. DDL can't declare a real KVREF/JSONREF column here
    // (this test module's `boot`/`make` disables the cross-engine resolver
    // entirely, so CREATE TABLE with such a column is rejected up front —
    // see cross_engine.rs's engine-disabled DDL test); a plain TEXT
    // column/row is built instead and relabeled to KvRef in a schema clone
    // used only for this hand-built `JoinProbe` — KvRef/JsonRef physically
    // encode identically to Text (both collapse to `ColumnType::Text`, see
    // `physical_type`), so the relabeling changes only what the mask sees,
    // not what is actually stored.
    #[tokio::test]
    async fn test_masked_right_on_column_probes_empty() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, link TEXT)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 'k')").await; // a row a physical probe *would* find

        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let mut b_schema = match rel.get_object("default", "b").unwrap() {
            CatalogEntry::Table(t) => t,
            _ => unreachable!(),
        };
        b_schema.columns[1].col_type = ColumnType::KvRef; // relabel `link` for the mask check only

        let snapshot_guard = rel.engine().snapshot();
        let snap = snapshot_guard.snapshot().clone();
        let probe = JoinProbe {
            engine: Arc::clone(rel.engine()),
            snapshot: snap,
            metrics: Arc::clone(&rel.metrics),
            right_prefix: prefix,
            right_table: Arc::new(b_schema),
            right_alias: "b".to_string(),
            right_col_pos: 1, // `link`, the (now-masked) ON column
            value_source: (0, 1),
            strategy: ProbeStrategy::ScanFallback,
            widen_int_to_real: false,
            fallback_budget: Arc::new(AtomicU64::new(0)),
            max_fallback_scan: 100_000,
            mask: LinkMask { kvref: true, jsonref: false },
        };
        let hits = probe.probe(&ScalarValue::Text("k".into())).await.unwrap();
        assert!(hits.is_empty(), "a masked ON column must never match, even though the physical row exists");
    }

    // 27. WHERE over a join (finding 005-F1): a REAL literal / param / IN element
    // compared against an INTEGER column widens per spec §6 instead of 400. The
    // predicate sits on the right (joined) table, so it is bound by the flat
    // join binder (`bind_flat_operand`/`bind_flat_predicate`), not the base-scan
    // path — exercising the join-side mirror of the fix.
    #[tokio::test]
    async fn test_join_residual_real_literal_widens_against_integer_column() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, a_id INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_b_a_id ON b (a_id)").await;
        ok(&rel, "INSERT INTO a VALUES (1), (2)").await;
        ok(&rel, "INSERT INTO b VALUES (100, 1), (200, 2)").await;

        // b.a_id > 1.5 is a right-table residual → flat binder; widening keeps a.id = 2.
        let s = sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.id = b.a_id WHERE b.a_id > 1.5").await;
        assert_eq!(ints(&s.rows, 0), vec![2]);

        // IN list with a REAL element widens likewise.
        let s = sel(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.id = b.a_id WHERE b.a_id IN (2.0, 99)").await;
        assert_eq!(ints(&s.rows, 0), vec![2]);

        // A genuine type error is still rejected.
        let e = err(&rel, "SELECT a.id FROM a LEFT JOIN b ON a.id = b.a_id WHERE b.a_id > 'x'").await;
        assert!(matches!(e, RelStoreError::TypeMismatch { .. }), "got: {e}");
    }

    // 28. Spec rel/018 §Test 3 (join fallback cap, exact): a right table
    // with exactly `max_fallback_scan` snapshot-visible rows plus ghosts
    // inserted after the snapshot must not trip `UnindexedJoinScanExceeded`
    // -- pre-fix, the live (unsnapshotted) fallback scan counted the ghosts
    // too and threw one row too early (the Insert-side mirror of test 26's
    // cap-exactness check, now snapshot-scoped). White-box on `JoinProbe`
    // directly (pattern: tests 23/27) so the snapshot boundary is exact,
    // not timing-dependent.
    #[tokio::test]
    async fn test_scan_fallback_cap_excludes_ghosts_from_budget() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, tag INTEGER)").await;
        for i in 0..5 {
            ok(&rel, &format!("INSERT INTO b VALUES ({i}, 42)")).await;
        }

        let snapshot_guard = rel.engine().snapshot();
        let snap = snapshot_guard.snapshot().clone();
        // Ghosts: live at probe time, but after the snapshot -- must not
        // count toward the fallback budget nor appear in the result.
        for i in 5..8 {
            ok(&rel, &format!("INSERT INTO b VALUES ({i}, 42)")).await;
        }

        let prefix = rel.get_domain("default").unwrap().system_prefix;
        let b_schema = match rel.get_object("default", "b").unwrap() {
            CatalogEntry::Table(t) => Arc::new(t),
            _ => unreachable!(),
        };
        let probe = JoinProbe {
            engine: Arc::clone(rel.engine()),
            snapshot: snap,
            metrics: Arc::clone(&rel.metrics),
            right_prefix: prefix,
            right_table: Arc::clone(&b_schema),
            right_alias: "b".to_string(),
            right_col_pos: 1,
            value_source: (0, 1),
            strategy: ProbeStrategy::ScanFallback,
            widen_int_to_real: false,
            fallback_budget: Arc::new(AtomicU64::new(0)),
            max_fallback_scan: 5,
            mask: LinkMask::default(),
        };
        let hits = probe.probe(&ScalarValue::Integer(42)).await.unwrap();
        assert_eq!(hits.len(), 5, "all 5 snapshot-visible rows must match; ghosts excluded from the scan itself");
    }
}
