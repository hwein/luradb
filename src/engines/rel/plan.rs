//! Access-path planner (spec rel/006 §3/§5): rule-based, deterministic — no
//! cost-based optimizer, no statistics. Chooses exactly one access path from
//! the WHERE clause's top-level AND conjuncts (or, absent one, from ORDER BY)
//! and binds the remaining conjuncts as the residual `Pred` (rel/005
//! evaluator, reused unchanged — see `dml::bind_predicate`).

use super::ast::{ColumnRef, CompareOp, Expr, Operand};
use super::catalog::{ColumnDef, IndexMeta, TableSchema};
use super::cross_engine::LinkMask;
use super::dml::{bind_predicate, bind_value, is_value, resolve_column};
use super::error::RelStoreError;
use super::eval::Pred;
use super::types::{ColumnType, ScalarValue};
use serde_json::Value;

/// A lower/upper bound for a range access path. `None` on a side = unbounded
/// on that side (used for the ORDER-BY-driven "full range" path, §5).
#[derive(Debug, Clone, Default)]
pub struct RangeBounds {
    pub lower: Option<(ScalarValue, bool)>, // (bound, inclusive)
    pub upper: Option<(ScalarValue, bool)>,
}

impl RangeBounds {
    fn unbounded() -> Self {
        Self::default()
    }
}

/// The chosen access path (spec §3 table). Priority order (1 = highest) is
/// given by [`AccessPath::priority`]; `PkPoint`/`PkRange`/`PkPrefix` always
/// use `PkLookup`/`SeqScan`-over-`ROW:`; the `Index*` variants use `IndexScan`
/// over the index's `IDX:` range.
#[derive(Debug, Clone)]
pub enum AccessPath {
    PkPoint(ScalarValue),
    PkRange(RangeBounds),
    PkPrefix(String),
    IndexPoint { index: IndexMeta, value: ScalarValue },
    IndexRange { index: IndexMeta, bounds: RangeBounds },
    IndexPrefix { index: IndexMeta, prefix: String },
    FullScan,
}

impl AccessPath {
    /// Lower is better; ties broken by `col_id` then statement order (§3).
    fn priority(&self) -> u8 {
        match self {
            AccessPath::PkPoint(_) => 1,
            AccessPath::PkRange(_) | AccessPath::PkPrefix(_) => 2,
            AccessPath::IndexPoint { index, .. } if index.unique => 3,
            AccessPath::IndexPoint { .. } => 4,
            AccessPath::IndexRange { .. } | AccessPath::IndexPrefix { .. } => 5,
            AccessPath::FullScan => 6,
        }
    }
}

/// The planner's decision: the access path plus the bound residual predicate
/// (checked per row by the `Filter` operator via the rel/005 evaluator), and
/// whether the chosen path already satisfies ORDER BY for free (§5).
pub struct Plan {
    pub access: AccessPath,
    pub residual: Option<Pred>,
    /// `true` iff ORDER BY (if any) is already satisfied by `access`'s key
    /// order, so no `Sort` operator is needed.
    pub order_free: bool,
    /// Whether the (single, order-free) ORDER BY item is DESC — the caller
    /// reverses the resolved key list when this is set. Meaningless unless
    /// `order_free` and ORDER BY is non-empty.
    pub order_desc: bool,
}

/// One sargable top-level AND conjunct recognized during planning.
struct Candidate {
    path: AccessPath,
    col_id: u16,
    position: usize,
    /// LIKE-prefix candidates are not exact: the full pattern must still be
    /// re-checked in the residual (spec §3/§4).
    is_like: bool,
}

/// Chooses the access path and binds the residual (spec §3-§5).
///
/// `order_by` is `(row position, DESC)` per ORDER BY item, already resolved
/// against `schema` by the caller (`select::bind_order_by`).
pub(crate) fn plan_access(
    schema: &TableSchema,
    where_clause: &Option<Expr>,
    quals: &[String],
    params: &[Value],
    order_by: &[(usize, bool)],
    mask: LinkMask,
) -> Result<Plan, RelStoreError> {
    let mut conjuncts: Vec<&Expr> = Vec::new();
    if let Some(e) = where_clause {
        flatten_and(e, &mut conjuncts);
    }

    let mut candidates: Vec<Candidate> = Vec::new();
    for (position, conjunct) in conjuncts.iter().enumerate() {
        if let Some(c) = classify_conjunct(conjunct, position, schema, quals, params, mask)? {
            candidates.push(c);
        }
    }
    candidates.sort_by_key(|c| (c.path.priority(), c.col_id, c.position));

    if let Some(winner) = candidates.into_iter().next() {
        let mut residual_terms: Vec<Pred> = Vec::new();
        for (position, conjunct) in conjuncts.iter().enumerate() {
            if position == winner.position && !winner.is_like {
                continue; // consumed exactly by the access path (§4)
            }
            residual_terms.push(bind_predicate(conjunct, schema, quals, params)?);
        }
        let order_free = order_by_satisfied(&winner.path, schema, order_by);
        let order_desc = order_by.first().is_some_and(|&(_, desc)| desc);
        return Ok(Plan {
            access: winner.path,
            residual: fold_and(residual_terms),
            order_free,
            order_desc,
        });
    }

    // No sargable WHERE predicate: try the ORDER-BY-driven path (§5) before
    // falling back to a full scan.
    let access = order_by_driven_path(schema, order_by, mask).unwrap_or(AccessPath::FullScan);
    let residual = match where_clause {
        Some(e) => Some(bind_predicate(e, schema, quals, params)?),
        None => None,
    };
    let order_free = order_by_satisfied(&access, schema, order_by);
    let order_desc = order_by.first().is_some_and(|&(_, desc)| desc);
    Ok(Plan { access, residual, order_free, order_desc })
}

/// Flattens top-level `AND`/`Paren` nodes into their leaf conjuncts. A
/// non-AND node (incl. a top-level `OR`) becomes a single opaque conjunct —
/// never sargable, so it forces a full scan unless a sibling conjunct drives
/// (spec §3: "the candidate column sits under OR/NOT" → not representative).
/// `pub(super)`: reused by the join planner (rel/007 `join.rs`) to partition
/// WHERE conjuncts into base-driving vs. residual-over-the-chain (§6).
pub(super) fn flatten_and<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::And(a, b) => {
            flatten_and(a, out);
            flatten_and(b, out);
        }
        Expr::Paren(inner) => flatten_and(inner, out),
        other => out.push(other),
    }
}

fn fold_and(terms: Vec<Pred>) -> Option<Pred> {
    let mut it = terms.into_iter();
    let first = it.next()?;
    Some(it.fold(first, |acc, t| Pred::And(Box::new(acc), Box::new(t))))
}

/// Recognizes one top-level conjunct as sargable (spec §3 table): `col = v`,
/// `col </<=/>/>= v` (PK or indexed), or `col LIKE 'prefix%'` (PK or indexed,
/// text-like). `IN`, `IS NULL`, `!=`, and non-prefix `LIKE` never drive.
fn classify_conjunct(
    expr: &Expr,
    position: usize,
    schema: &TableSchema,
    quals: &[String],
    params: &[Value],
    mask: LinkMask,
) -> Result<Option<Candidate>, RelStoreError> {
    match expr {
        Expr::Paren(inner) => classify_conjunct(inner, position, schema, quals, params, mask),
        Expr::Compare { lhs, op, rhs } => Ok(classify_compare(lhs, *op, rhs, schema, quals, params, mask)?
            .map(|(path, col_id)| Candidate { path, col_id, position, is_like: false })),
        Expr::Like { col, negated: false, pattern } => Ok(classify_like(col, pattern, schema, quals, mask)?
            .map(|(path, col_id)| Candidate { path, col_id, position, is_like: true })),
        // In/IsNull/Like(negated)/And/Or/Not: never a driving predicate (v1, §3).
        _ => Ok(None),
    }
}

fn classify_compare(
    lhs: &Operand,
    op: CompareOp,
    rhs: &Operand,
    schema: &TableSchema,
    quals: &[String],
    params: &[Value],
    mask: LinkMask,
) -> Result<Option<(AccessPath, u16)>, RelStoreError> {
    let (col, eff_op, value_operand) = match (as_column(lhs, schema, quals), as_column(rhs, schema, quals)) {
        (Some(c), None) if is_value(rhs) => (c, op, rhs),
        (None, Some(c)) if is_value(lhs) => (c, flip_op(op), lhs),
        _ => return Ok(None), // column-vs-column, literal-vs-literal, or unresolvable
    };
    // A masked link column is all-NULL for this query — never let it
    // drive an index/PK path (that would probe pre-mask values, §3).
    if mask.masks(col.col_type) {
        return Ok(None);
    }
    if matches!(eff_op, CompareOp::NotEq) {
        return Ok(None); // != is never sargable (not in the §3 table)
    }
    let value = bind_value(col, value_operand, params)?;
    if matches!(value, ScalarValue::Null) {
        return Ok(None); // NULL-bind guard already prevents this in practice
    }
    let path = if matches!(eff_op, CompareOp::Eq) {
        sargable_point(schema, col, value)
    } else {
        sargable_range(schema, col, eff_op, value)
    };
    Ok(path.map(|path| (path, col.col_id)))
}

fn classify_like(
    col: &ColumnRef,
    pattern: &str,
    schema: &TableSchema,
    quals: &[String],
    mask: LinkMask,
) -> Result<Option<(AccessPath, u16)>, RelStoreError> {
    let (_, c) = resolve_column(col, schema, quals)?;
    if mask.masks(c.col_type) {
        return Ok(None); // masked link column drives no index path (§3)
    }
    if !matches!(c.col_type.physical_type(), ColumnType::Text) {
        return Ok(None);
    }
    let Some(prefix) = literal_prefix_of_like(pattern) else {
        return Ok(None);
    };
    let path = if c.primary_key {
        Some(AccessPath::PkPrefix(prefix))
    } else {
        schema
            .indexes
            .iter()
            .find(|ix| ix.column == c.name)
            .map(|ix| AccessPath::IndexPrefix { index: ix.clone(), prefix })
    };
    Ok(path.map(|path| (path, c.col_id)))
}

fn as_column<'a>(
    op: &super::ast::Operand,
    schema: &'a TableSchema,
    quals: &[String],
) -> Option<&'a ColumnDef> {
    match op {
        super::ast::Operand::Column(cref) => resolve_column(cref, schema, quals).ok().map(|(_, c)| c),
        _ => None,
    }
}

fn flip_op(op: CompareOp) -> CompareOp {
    match op {
        CompareOp::Lt => CompareOp::Gt,
        CompareOp::LtEq => CompareOp::GtEq,
        CompareOp::Gt => CompareOp::Lt,
        CompareOp::GtEq => CompareOp::LtEq,
        CompareOp::Eq => CompareOp::Eq,
        CompareOp::NotEq => CompareOp::NotEq,
    }
}

fn sargable_point(schema: &TableSchema, col: &ColumnDef, value: ScalarValue) -> Option<AccessPath> {
    if col.primary_key {
        return Some(AccessPath::PkPoint(value));
    }
    schema
        .indexes
        .iter()
        .find(|ix| ix.column == col.name)
        .map(|ix| AccessPath::IndexPoint { index: ix.clone(), value })
}

fn sargable_range(
    schema: &TableSchema,
    col: &ColumnDef,
    op: CompareOp,
    value: ScalarValue,
) -> Option<AccessPath> {
    let bounds = single_bound(op, value);
    if col.primary_key {
        return Some(AccessPath::PkRange(bounds));
    }
    schema
        .indexes
        .iter()
        .find(|ix| ix.column == col.name)
        .map(|ix| AccessPath::IndexRange { index: ix.clone(), bounds })
}

fn single_bound(op: CompareOp, value: ScalarValue) -> RangeBounds {
    match op {
        CompareOp::Gt => RangeBounds { lower: Some((value, false)), upper: None },
        CompareOp::GtEq => RangeBounds { lower: Some((value, true)), upper: None },
        CompareOp::Lt => RangeBounds { lower: None, upper: Some((value, false)) },
        CompareOp::LtEq => RangeBounds { lower: None, upper: Some((value, true)) },
        CompareOp::Eq | CompareOp::NotEq => unreachable!("caller only passes range operators"),
    }
}

/// `'prefix%'` with a non-empty literal prefix and no other wildcard — the
/// only LIKE shape the planner treats as sargable (spec §3).
fn literal_prefix_of_like(pattern: &str) -> Option<String> {
    let head = pattern.strip_suffix('%')?;
    if head.is_empty() || head.contains(['%', '_']) {
        return None;
    }
    Some(head.to_string())
}

/// §5 special rule: no sargable WHERE predicate exists (path would be a full
/// scan), but ORDER BY is single-column on PK or an indexed NOT-NULL column
/// — that column drives a full PK-/index-range scan instead, avoiding Sort.
fn order_by_driven_path(
    schema: &TableSchema,
    order_by: &[(usize, bool)],
    mask: LinkMask,
) -> Option<AccessPath> {
    let &[(pos, _)] = order_by else { return None };
    let col = &schema.columns[pos];
    if mask.masks(col.col_type) {
        return None; // masked link column drives no ordered index path (§3)
    }
    if col.primary_key {
        return Some(AccessPath::PkRange(RangeBounds::unbounded()));
    }
    if col.nullable {
        return None;
    }
    schema
        .indexes
        .iter()
        .find(|ix| ix.column == col.name)
        .map(|ix| AccessPath::IndexRange { index: ix.clone(), bounds: RangeBounds::unbounded() })
}

/// Whether `path`'s key order already satisfies `order_by` for free (§5):
/// single-column ORDER BY on the path's own driving column (PK for
/// `Pk*`/`FullScan`, the index's column for `Index*`), which must be
/// schema-NOT-NULL for the index case (nullable columns' NULL rows are
/// missing from the index; PK is always NOT NULL).
fn order_by_satisfied(path: &AccessPath, schema: &TableSchema, order_by: &[(usize, bool)]) -> bool {
    let &[(pos, _)] = order_by else { return order_by.is_empty() };
    let col = &schema.columns[pos];
    match path {
        AccessPath::PkPoint(_) | AccessPath::PkRange(_) | AccessPath::PkPrefix(_) | AccessPath::FullScan => {
            col.primary_key
        }
        AccessPath::IndexPoint { index, .. }
        | AccessPath::IndexRange { index, .. }
        | AccessPath::IndexPrefix { index, .. } => !col.nullable && index.column == col.name,
    }
}
