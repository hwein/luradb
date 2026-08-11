//! Views (spec rel/008): `CREATE`/`DROP VIEW` execution, the AST-inlining
//! pre-stage for `FROM`/`JOIN` view references, and the DDL dependency check.
//!
//! No new executor operator: a SELECT touching a view is rewritten into a
//! flat statement over base tables only (`inline`/`expand`), then handed
//! unchanged to the existing rel/006/007 planner/executor. `CREATE VIEW`
//! validates by building (and discarding) that same flat plan — reusing the
//! rel/006/007 binder (`select::bind_projection`, `dml::bind_predicate`,
//! `join::{check_unique_aliases, resolve_join_on, bind_flat_predicate,
//! bind_join_projection}`, `RelEngine::build_join_probe`) rather than
//! duplicating it. The DDL dependency check (§7) reuses the same binder
//! again, but against a hypothetical *prospective* catalog map instead of
//! the live catalog, and deliberately skips the join index requirement (an
//! execution-time concern per §7) and stops needing `RelEngine` entirely.

use super::ast::{
    ColumnRef, CreateView, DropView, Expr, Join, Operand, OrderItem, Select, SelectItem, Statement,
    TableRef,
};
use super::catalog::CatalogEntry;
use super::ddl::DdlOutcome;
use super::dml;
use super::error::RelStoreError;
use super::join::{self, BindingInfo};
use super::lexer;
use super::parser;
use super::select::{self, ProjectedColumn};
use super::RelEngine;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

/// View-over-view depth limit (spec §5): `depth(view) = 1 + max(depth of the
/// referenced views)`, a view referencing only tables has depth 1. A plain
/// constant, not a config knob (concept ch. 8 defines none for this) — and,
/// since an already-stored view's own depth is guaranteed valid by
/// construction (no cycles, no forward references — spec §5), it doubles as
/// the defensive recursion cap against manual catalog corruption.
const MAX_VIEW_DEPTH: usize = 3;

// ── CREATE/DROP VIEW execution (spec §3/§7) ─────────────────────────────────

/// Executes `CREATE VIEW` (spec §3): validates the subset (§2), then binds
/// and stores the *raw* SELECT text atomically under the catalog's
/// `ddl_lock` (via `create_view_checked`'s `validate` closure) — so no
/// concurrent DDL can invalidate the view between validation and storage.
pub(super) async fn execute_create_view(
    engine: &RelEngine,
    domain: &str,
    cv: CreateView,
    sql: &str,
) -> Result<DdlOutcome, RelStoreError> {
    engine.domains.require_active(domain)?;
    validate_view_subset(&cv.select)?;
    let raw_sql = extract_view_sql(sql, cv.select_offset);

    let view = engine
        .catalog
        .create_view_checked(&engine.domains, domain, &cv.name, &raw_sql, |current| {
            let lookup = map_lookup(current);
            let (flat, _substitutions) = inline(&lookup, &cv.select, 1)?;
            validate_flat_select_full(engine, domain, &flat)
        })
        .await?;
    engine.metrics.record_rel_ddl_view_op("create_view");
    Ok(DdlOutcome::ViewCreated(view))
}

/// Executes `DROP VIEW` (spec §7): the dependency check and the delete run
/// atomically under the same `ddl_lock` acquisition (`drop_object_checked`).
pub(super) async fn execute_drop_view(
    engine: &RelEngine,
    domain: &str,
    dv: DropView,
) -> Result<DdlOutcome, RelStoreError> {
    engine
        .catalog
        .drop_object_checked(&engine.domains, domain, &dv.name, |removed, m| match removed {
            CatalogEntry::View(_) => check_view_dependents(m, &dv.name, domain),
            // A concurrent re-CREATE turned the name into a table before the
            // lock: from DROP VIEW's point of view there is no view by that
            // name — checked atomically here so the race cannot drop the table.
            CatalogEntry::Table(_) => Err(RelStoreError::ObjectNotFound {
                domain: domain.to_string(),
                name: dv.name.clone(),
            }),
        })
        .await?;
    engine.metrics.record_rel_ddl_view_op("drop_view");
    Ok(DdlOutcome::ViewDropped { name: dv.name })
}

// ── §2: the allowed view-definition subset ──────────────────────────────────

/// Rejects the view-body shapes concept 6.4 disallows (spec §2): `?`
/// parameters, `ORDER BY`, `LIMIT`/`OFFSET`, a bare `COUNT(*)` projection, and
/// duplicate *explicit* output names. `*`-driven duplicates can only be
/// detected once the projection is actually resolved against the catalog —
/// that half of the check lives in `check_no_duplicate_names`, run as part
/// of the deep bind (§3).
fn validate_view_subset(sel: &Select) -> Result<(), RelStoreError> {
    if !sel.order_by.is_empty() {
        return Err(RelStoreError::InvalidSchema(
            "a view body must not contain ORDER BY — apply it to the outer query instead".to_string(),
        ));
    }
    if sel.limit.is_some() {
        return Err(RelStoreError::InvalidSchema(
            "a view body must not contain LIMIT/OFFSET — apply it to the outer query instead".to_string(),
        ));
    }
    if matches!(sel.items.as_slice(), [SelectItem::CountStar]) {
        return Err(RelStoreError::InvalidSchema(
            "a view body must not be COUNT(*) — a view yields rows, not a scalar".to_string(),
        ));
    }
    if sel.where_clause.as_ref().is_some_and(expr_has_param) {
        return Err(RelStoreError::InvalidSchema(
            "a view body must not contain '?' parameters — a view is parameterless".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for item in &sel.items {
        if let SelectItem::Column { col, alias } = item {
            let out = alias.clone().unwrap_or_else(|| col.name.clone());
            if !seen.insert(out.clone()) {
                return Err(RelStoreError::InvalidSchema(format!(
                    "duplicate output column name '{out}' in view definition"
                )));
            }
        }
    }
    Ok(())
}

fn expr_has_param(expr: &Expr) -> bool {
    match expr {
        Expr::Compare { lhs, rhs, .. } => operand_has_param(lhs) || operand_has_param(rhs),
        Expr::And(a, b) | Expr::Or(a, b) => expr_has_param(a) || expr_has_param(b),
        Expr::Not(e) | Expr::Paren(e) => expr_has_param(e),
        // Grammar: `IN`'s list is literals only, `LIKE`'s pattern is a bare
        // string, `IS [NOT] NULL` has no RHS at all — `?` cannot occur here.
        Expr::In { .. } | Expr::Like { .. } | Expr::IsNull { .. } => false,
    }
}

fn operand_has_param(op: &Operand) -> bool {
    matches!(op, Operand::Param(_))
}

/// Slices the raw, unparsed view SELECT text out of the original SQL string
/// (spec §3: the stored `sql` must be byte-identical to what the client
/// submitted, not a re-serialized AST): from `offset` (the first token past
/// `AS`, set by the parser) to end of statement, trimming trailing
/// whitespace and the one optional statement-terminating `;`.
fn extract_view_sql(sql: &str, offset: usize) -> String {
    let body = sql.get(offset..).unwrap_or("").trim_end();
    match body.strip_suffix(';') {
        Some(rest) => rest.trim_end().to_string(),
        None => body.to_string(),
    }
}

// ── Catalog lookup abstraction (live vs. a prospective in-memory map) ───────

type Lookup<'a> = dyn Fn(&str) -> Result<CatalogEntry, RelStoreError> + 'a;

/// Looks up against the live catalog (SELECT-time inlining, CREATE VIEW's
/// deep bind).
fn live_lookup<'a>(engine: &'a RelEngine, domain: &'a str) -> impl Fn(&str) -> Result<CatalogEntry, RelStoreError> + 'a {
    move |name| engine.catalog.get(&engine.domains, domain, name)
}

/// Looks up against a hypothetical prospective per-domain map (the DDL
/// dependency check, spec §7) — same error shape as `RelCatalog::get`, so
/// downstream `ObjectNotFound` → `TableNotFound` mapping works unchanged.
fn map_lookup(map: &HashMap<String, CatalogEntry>) -> impl Fn(&str) -> Result<CatalogEntry, RelStoreError> + '_ {
    move |name| {
        map.get(name).cloned().ok_or_else(|| RelStoreError::ObjectNotFound {
            domain: String::new(),
            name: name.to_string(),
        })
    }
}

/// `ObjectNotFound` → `TableNotFound`, matching the convention used
/// everywhere else a `FROM`/`JOIN` target is resolved (select.rs/join.rs/dml.rs).
fn require_entry(lookup: &Lookup, name: &str) -> Result<CatalogEntry, RelStoreError> {
    match lookup(name) {
        Err(RelStoreError::ObjectNotFound { domain, name }) => Err(RelStoreError::TableNotFound { domain, name }),
        other => other,
    }
}

/// Re-parses a stored view body (spec §4: re-parsed on every use, v1 — a
/// cache is an allowed but non-mandatory optimization). `usize::MAX`: the
/// text already passed `max_statement_len` once, at its own CREATE VIEW time.
fn parse_view_sql(sql: &str) -> Result<Select, RelStoreError> {
    let tokens = lexer::tokenize(sql, usize::MAX)?;
    match parser::parse(&tokens)? {
        Statement::Select(sel) => Ok(sel),
        _ => unreachable!("a stored view body is always a bare SELECT (validated at CREATE VIEW time)"),
    }
}

// ── The inliner (spec §4/§5) ─────────────────────────────────────────────────

/// Per-source output-name map: `output name -> the flat, fully-qualified
/// ColumnRef it resolves to` (spec §4.3). A plain table source gets the
/// identity map (every catalog column, qualified by the source's own kept
/// alias); a view source maps each of its *projected* output names onto the
/// underlying (already recursively flattened and freshly re-aliased) base column.
struct SourceMap(Vec<(String, ColumnRef)>);

impl SourceMap {
    fn resolve(&self, name: &str) -> Option<ColumnRef> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, c)| c.clone())
    }
}

fn identity_source_map(schema: &super::catalog::TableSchema, alias: &str) -> SourceMap {
    SourceMap(
        schema
            .columns
            .iter()
            .map(|c| (c.name.clone(), ColumnRef { qualifier: Some(alias.to_string()), name: c.name.clone() }))
            .collect(),
    )
}

/// A flattened select's own projection is always fully resolved to explicit
/// `Column` items by `rewrite_projection` (never `Star`/`CountStar`, spec
/// §4.5) — this turns that resolved list back into a `SourceMap` for the
/// *next* level up, once this select is itself substituted as a view.
fn view_projection_map(items: &[SelectItem]) -> SourceMap {
    SourceMap(
        items
            .iter()
            .map(|item| match item {
                SelectItem::Column { col, alias } => (alias.clone().unwrap_or_else(|| col.name.clone()), col.clone()),
                SelectItem::Star | SelectItem::CountStar => {
                    unreachable!("a flattened select's projection is always resolved to explicit columns")
                }
            })
            .collect(),
    )
}

/// Threaded through one whole top-level `inline` call (all recursion levels):
/// the fresh-alias namespace and the running view-substitution counter.
struct InlineCtx<'a> {
    lookup: &'a Lookup<'a>,
    used_aliases: HashSet<String>,
    next_fresh: u32,
    substitutions: u32,
}

impl InlineCtx<'_> {
    /// A collision-free alias, reserved immediately. Only a view's *own*
    /// internal aliases ever need one (spec §4.1) — a name kept from a plain
    /// table reference never collides because it is reserved up front (or,
    /// for a nested view's transient internal names, thrown away by the very
    /// next `realias` call before it could ever reach the final output).
    fn fresh_alias(&mut self) -> String {
        loop {
            let candidate = format!("__rel008_v{}", self.next_fresh);
            self.next_fresh += 1;
            if self.used_aliases.insert(candidate.clone()) {
                return candidate;
            }
        }
    }
}

/// SELECT-time entry point (rel/008 §1/§4), called from `select::exec_select`
/// before the rel/006/007 planner ever sees the statement. A select touching
/// no view returns `sel` unchanged at no cost (spec §1).
pub(super) fn inline_views(engine: &RelEngine, domain: &str, sel: Select) -> Result<Select, RelStoreError> {
    let lookup = live_lookup(engine, domain);
    let (flat, substitutions) = inline(&lookup, &sel, 0)?;
    if substitutions > 0 {
        engine.metrics.record_rel_view_inlinings(substitutions as u64);
    }
    Ok(flat)
}

/// Whether any `FROM`/`JOIN` target of `sel` resolves to a view. Lenient on
/// lookup errors (treats them as "not a view") — a genuinely missing table
/// is correctly reported later, by the normal (non-inlining) execution path,
/// without this pre-check having to replicate that error handling itself.
fn touches_any_view(lookup: &Lookup, sel: &Select) -> bool {
    let is_view = |name: &str| matches!(lookup(name), Ok(CatalogEntry::View(_)));
    is_view(&sel.from.name) || sel.joins.iter().any(|j| is_view(&j.table.name))
}

/// Recursively expands every view reference in `sel`'s `FROM`/`JOIN` chain
/// (spec §4/§5). `depth` is `sel`'s own assumed view-nesting depth, were it
/// registered as a view right now (1 for CREATE VIEW's own body, 0 for an
/// ad-hoc query) — `MAX_VIEW_DEPTH` is enforced against it before recursing
/// into any further view.
pub(super) fn inline(lookup: &Lookup, sel: &Select, depth: usize) -> Result<(Select, u32), RelStoreError> {
    if !touches_any_view(lookup, sel) {
        return Ok((sel.clone(), 0));
    }
    let mut used_aliases = HashSet::new();
    used_aliases.insert(sel.from.alias.clone().unwrap_or_else(|| sel.from.name.clone()));
    for j in &sel.joins {
        used_aliases.insert(j.table.alias.clone().unwrap_or_else(|| j.table.name.clone()));
    }
    let mut ctx = InlineCtx { lookup, used_aliases, next_fresh: 0, substitutions: 0 };
    let flat = expand(&mut ctx, sel, depth)?;
    Ok((flat, ctx.substitutions))
}

fn expand(ctx: &mut InlineCtx, sel: &Select, depth: usize) -> Result<Select, RelStoreError> {
    let from_outer_alias = sel.from.alias.clone().unwrap_or_else(|| sel.from.name.clone());
    let from_entry = require_entry(ctx.lookup, &sel.from.name)?;

    let (flat_from, mut flat_joins, from_where, from_map) = match from_entry {
        CatalogEntry::Table(t) => {
            let map = identity_source_map(&t, &from_outer_alias);
            let flat_from = TableRef { name: t.name.clone(), alias: Some(from_outer_alias.clone()) };
            (flat_from, Vec::new(), None, map)
        }
        CatalogEntry::View(v) => {
            let child_depth = depth + 1;
            if child_depth > MAX_VIEW_DEPTH {
                return Err(view_depth_exceeded());
            }
            let inner_sel = parse_view_sql(&v.sql)?;
            let inner_flat = expand(ctx, &inner_sel, child_depth)?;
            ctx.substitutions += 1;
            let (renamed_from, renamed_joins, rename) = realias(ctx, &inner_flat);
            let renamed_where = inner_flat.where_clause.as_ref().map(|w| rewrite_expr(w, &rename));
            let renamed_items = rewrite_items_via_rename(&inner_flat.items, &rename);
            (renamed_from, renamed_joins, renamed_where, view_projection_map(&renamed_items))
        }
    };

    let mut sources: Vec<(String, SourceMap)> = vec![(from_outer_alias, from_map)];

    for j in &sel.joins {
        let outer_alias = j.table.alias.clone().unwrap_or_else(|| j.table.name.clone());
        let entry = require_entry(ctx.lookup, &j.table.name)?;
        match entry {
            CatalogEntry::Table(t) => {
                let map = identity_source_map(&t, &outer_alias);
                let (left, right) = rewrite_on_against_new_source(&j.left, &j.right, &sources, &map, &outer_alias)?;
                flat_joins.push(Join {
                    table: TableRef { name: t.name.clone(), alias: Some(outer_alias.clone()) },
                    left,
                    right,
                });
                sources.push((outer_alias, map));
            }
            CatalogEntry::View(v) => {
                let child_depth = depth + 1;
                if child_depth > MAX_VIEW_DEPTH {
                    return Err(view_depth_exceeded());
                }
                let inner_sel = parse_view_sql(&v.sql)?;
                let inner_flat = expand(ctx, &inner_sel, child_depth)?;
                if inner_flat.where_clause.is_some() {
                    return Err(RelStoreError::InvalidSchema(format!(
                        "view '{}' has a WHERE clause and cannot be used in JOIN position; use it in FROM position instead",
                        j.table.name
                    )));
                }
                ctx.substitutions += 1;
                let (renamed_from, renamed_joins, rename) = realias(ctx, &inner_flat);
                let renamed_items = rewrite_items_via_rename(&inner_flat.items, &rename);
                let map = view_projection_map(&renamed_items);

                let (left, right) = rewrite_on_against_new_source(&j.left, &j.right, &sources, &map, &outer_alias)?;
                flat_joins.push(Join { table: renamed_from, left, right });
                flat_joins.extend(renamed_joins);
                sources.push((outer_alias, map));
            }
        }
    }

    let outer_where = sel.where_clause.as_ref().map(|w| rewrite_where(w, &sources)).transpose()?;
    let where_clause = and_opt(from_where, outer_where);
    let items = rewrite_projection(&sel.items, &sources)?;
    let order_by = rewrite_order_by(&sel.order_by, &sources)?;

    Ok(Select { items, from: flat_from, joins: flat_joins, where_clause, order_by, limit: sel.limit.clone() })
}

fn view_depth_exceeded() -> RelStoreError {
    RelStoreError::LimitExceeded { which: "view_depth".to_string(), max: MAX_VIEW_DEPTH }
}

/// Alias hygiene (spec §4.1): renames *all* of an already-fully-flattened
/// view body's own `FROM`/`JOIN` aliases to fresh, collision-free names —
/// unconditionally, regardless of whether they were already fresh (from a
/// deeper substitution) or literal table names (a view with no further
/// nested views) — so they can never collide with the enclosing statement's
/// own namespace. Returns the renamed `(from, joins)` plus the
/// old-alias → new-alias map used to rewrite this view's own WHERE/projection.
fn realias(ctx: &mut InlineCtx, inner: &Select) -> (TableRef, Vec<Join>, HashMap<String, String>) {
    let mut rename: HashMap<String, String> = HashMap::new();
    let from_old = inner.from.alias.clone().unwrap_or_else(|| inner.from.name.clone());
    let from_new = ctx.fresh_alias();
    rename.insert(from_old, from_new.clone());
    let new_from = TableRef { name: inner.from.name.clone(), alias: Some(from_new) };

    let mut new_joins = Vec::with_capacity(inner.joins.len());
    for j in &inner.joins {
        let old = j.table.alias.clone().unwrap_or_else(|| j.table.name.clone());
        let new = ctx.fresh_alias();
        // ON operands may reference the join's own (about-to-be-renamed)
        // table, so `old` must already be in `rename` before rewriting them.
        rename.insert(old, new.clone());
        new_joins.push(Join {
            table: TableRef { name: j.table.name.clone(), alias: Some(new) },
            left: rename_colref(&j.left, &rename),
            right: rename_colref(&j.right, &rename),
        });
    }
    (new_from, new_joins, rename)
}

fn rename_colref(cref: &ColumnRef, rename: &HashMap<String, String>) -> ColumnRef {
    match &cref.qualifier {
        // `expand`'s own output always fully qualifies ON/WHERE/projection
        // column refs (every ref is produced via a `SourceMap` lookup, which
        // always attaches a qualifier) — the `None` arm is an unreached
        // defensive fallback, not a real case.
        Some(q) => ColumnRef { qualifier: Some(rename.get(q).cloned().unwrap_or_else(|| q.clone())), name: cref.name.clone() },
        None => cref.clone(),
    }
}

/// Rewrites a fully-flattened inner select's own WHERE by remapping its
/// column refs' qualifiers through `rename` (spec §4.1) — every ref is
/// already fully qualified (an `expand()` output invariant), so only the
/// qualifier string changes, never the resolution itself.
fn rewrite_expr(expr: &Expr, rename: &HashMap<String, String>) -> Expr {
    match expr {
        Expr::Compare { lhs, op, rhs } => {
            Expr::Compare { lhs: rewrite_operand_via_rename(lhs, rename), op: *op, rhs: rewrite_operand_via_rename(rhs, rename) }
        }
        Expr::In { col, negated, list } => Expr::In { col: rename_colref(col, rename), negated: *negated, list: list.clone() },
        Expr::Like { col, negated, pattern } => {
            Expr::Like { col: rename_colref(col, rename), negated: *negated, pattern: pattern.clone() }
        }
        Expr::IsNull { col, negated } => Expr::IsNull { col: rename_colref(col, rename), negated: *negated },
        Expr::And(a, b) => Expr::And(Box::new(rewrite_expr(a, rename)), Box::new(rewrite_expr(b, rename))),
        Expr::Or(a, b) => Expr::Or(Box::new(rewrite_expr(a, rename)), Box::new(rewrite_expr(b, rename))),
        Expr::Not(e) => Expr::Not(Box::new(rewrite_expr(e, rename))),
        Expr::Paren(e) => Expr::Paren(Box::new(rewrite_expr(e, rename))),
    }
}

fn rewrite_operand_via_rename(op: &Operand, rename: &HashMap<String, String>) -> Operand {
    match op {
        Operand::Column(c) => Operand::Column(rename_colref(c, rename)),
        other => other.clone(),
    }
}

fn rewrite_items_via_rename(items: &[SelectItem], rename: &HashMap<String, String>) -> Vec<SelectItem> {
    items
        .iter()
        .map(|item| match item {
            SelectItem::Column { col, alias } => SelectItem::Column { col: rename_colref(col, rename), alias: alias.clone() },
            other => other.clone(),
        })
        .collect()
}

/// Resolves one ON operand of the join stage currently substituting `new_map`
/// (the source not yet appended to `known`): if it qualifies into (or, when
/// unqualified, uniquely matches) the new source, resolve through its own
/// map; otherwise it must resolve against an already-known source (spec §3,
/// mirrored at the pre-flattening level).
fn rewrite_on_against_new_source(
    left: &ColumnRef,
    right: &ColumnRef,
    known: &[(String, SourceMap)],
    new_map: &SourceMap,
    new_alias: &str,
) -> Result<(ColumnRef, ColumnRef), RelStoreError> {
    Ok((
        resolve_on_operand(left, known, new_map, new_alias)?,
        resolve_on_operand(right, known, new_map, new_alias)?,
    ))
}

fn resolve_on_operand(
    cref: &ColumnRef,
    known: &[(String, SourceMap)],
    new_map: &SourceMap,
    new_alias: &str,
) -> Result<ColumnRef, RelStoreError> {
    let matches_new = cref.qualifier.as_deref() == Some(new_alias)
        || (cref.qualifier.is_none() && new_map.resolve(&cref.name).is_some());
    if matches_new {
        new_map.resolve(&cref.name).ok_or_else(|| RelStoreError::ColumnNotFound {
            table: new_alias.to_string(),
            name: cref.name.clone(),
        })
    } else {
        resolve_via_sources(cref, known)
    }
}

/// Qualified/unqualified/ambiguous resolution against the declared outer
/// sources (spec §5, mirrored at the pre-flattening level): each source
/// contributes its *output* name list (a view's projection, or a table's
/// catalog columns) rather than a `TableSchema` directly.
fn resolve_via_sources(cref: &ColumnRef, sources: &[(String, SourceMap)]) -> Result<ColumnRef, RelStoreError> {
    if let Some(q) = &cref.qualifier {
        let Some((_, map)) = sources.iter().find(|(alias, _)| alias == q) else {
            return Err(RelStoreError::InvalidSchema(format!("unknown alias/table name '{q}'")));
        };
        return map
            .resolve(&cref.name)
            .ok_or_else(|| RelStoreError::ColumnNotFound { table: q.clone(), name: cref.name.clone() });
    }
    let mut hit = None;
    for (_, map) in sources {
        if let Some(target) = map.resolve(&cref.name) {
            if hit.is_some() {
                return Err(RelStoreError::AmbiguousColumn { name: cref.name.clone() });
            }
            hit = Some(target);
        }
    }
    hit.ok_or_else(|| RelStoreError::ColumnNotFound { table: "<view>".to_string(), name: cref.name.clone() })
}

fn rewrite_where(expr: &Expr, sources: &[(String, SourceMap)]) -> Result<Expr, RelStoreError> {
    Ok(match expr {
        Expr::Compare { lhs, op, rhs } => Expr::Compare {
            lhs: rewrite_operand(lhs, sources)?,
            op: *op,
            rhs: rewrite_operand(rhs, sources)?,
        },
        Expr::In { col, negated, list } => {
            Expr::In { col: resolve_via_sources(col, sources)?, negated: *negated, list: list.clone() }
        }
        Expr::Like { col, negated, pattern } => {
            Expr::Like { col: resolve_via_sources(col, sources)?, negated: *negated, pattern: pattern.clone() }
        }
        Expr::IsNull { col, negated } => Expr::IsNull { col: resolve_via_sources(col, sources)?, negated: *negated },
        Expr::And(a, b) => Expr::And(Box::new(rewrite_where(a, sources)?), Box::new(rewrite_where(b, sources)?)),
        Expr::Or(a, b) => Expr::Or(Box::new(rewrite_where(a, sources)?), Box::new(rewrite_where(b, sources)?)),
        Expr::Not(e) => Expr::Not(Box::new(rewrite_where(e, sources)?)),
        Expr::Paren(e) => Expr::Paren(Box::new(rewrite_where(e, sources)?)),
    })
}

fn rewrite_operand(op: &Operand, sources: &[(String, SourceMap)]) -> Result<Operand, RelStoreError> {
    Ok(match op {
        Operand::Column(c) => Operand::Column(resolve_via_sources(c, sources)?),
        other => other.clone(),
    })
}

/// Projection rewriting (spec §4.3/§4.5): `*` expands per source in
/// declaration order (a view source → its own projection, a table source →
/// its catalog columns, spec §4.5); an explicit item is resolved via
/// `resolve_via_sources` — the output name is *always* pinned to an explicit
/// alias (the original `AS`, or else the reference's own bare name) so
/// rewriting the underlying qualifier never silently changes the wire name a
/// view exposes.
fn rewrite_projection(items: &[SelectItem], sources: &[(String, SourceMap)]) -> Result<Vec<SelectItem>, RelStoreError> {
    if let [SelectItem::CountStar] = items {
        return Ok(vec![SelectItem::CountStar]);
    }
    if let [SelectItem::Star] = items {
        let mut out = Vec::new();
        for (_, map) in sources {
            for (name, target) in &map.0 {
                out.push(SelectItem::Column { col: target.clone(), alias: Some(name.clone()) });
            }
        }
        return Ok(out);
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let SelectItem::Column { col, alias } = item else {
            unreachable!("grammar: Star/CountStar are only ever alone")
        };
        let target = resolve_via_sources(col, sources)?;
        let out_alias = Some(alias.clone().unwrap_or_else(|| col.name.clone()));
        out.push(SelectItem::Column { col: target, alias: out_alias });
    }
    Ok(out)
}

fn rewrite_order_by(items: &[OrderItem], sources: &[(String, SourceMap)]) -> Result<Vec<OrderItem>, RelStoreError> {
    items
        .iter()
        .map(|o| Ok(OrderItem { col: resolve_via_sources(&o.col, sources)?, desc: o.desc }))
        .collect()
}

fn and_opt(a: Option<Expr>, b: Option<Expr>) -> Option<Expr> {
    match (a, b) {
        (Some(a), Some(b)) => Some(Expr::And(Box::new(a), Box::new(b))),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

// ── §3: CREATE-time full bind-and-discard (needs RelEngine: index requirement) ─

/// Builds (and discards) the flat plan for an already-inlined `flat` select,
/// reusing the exact rel/006/007 binder rel/006/007 execution would use
/// (spec §3: "building performs all checks") — including, for joins, the
/// rel/007 index requirement and `max_join_depth`. No engine I/O: no
/// snapshot read ever happens, `build_join_probe`'s `JoinProbe` is built and
/// immediately dropped.
fn validate_flat_select_full(engine: &RelEngine, domain: &str, flat: &Select) -> Result<(), RelStoreError> {
    join::check_join_depth(flat.joins.len(), 0, engine.max_join_depth)?;

    if flat.joins.is_empty() {
        let schema = require_table_schema(engine, domain, &flat.from.name)?;
        let quals = dml::accepted_quals(&schema, flat);
        let proj = select::bind_projection(&flat.items, &schema, &quals)?;
        check_no_duplicate_names(&proj)?;
        if let Some(w) = &flat.where_clause {
            dml::bind_predicate(w, &schema, &quals, &[])?;
        }
        return Ok(());
    }

    let bindings = flat_bindings(engine, domain, flat)?;
    join::check_unique_aliases(&bindings)?;
    let offsets = join::flat_offsets(&bindings);

    let prefix = engine.domains.require_active(domain)?.system_prefix;
    let snapshot_guard = engine.engine().snapshot();
    let snap = snapshot_guard.snapshot().clone();
    let fallback_budget = Arc::new(AtomicU64::new(0));
    // CREATE-time structural bind only (no execution) — masking is a
    // read-time concern, so the default (no-op) mask is correct here.
    let env = join::ProbeEnv {
        prefix: &prefix,
        snap: &snap,
        fallback_budget: &fallback_budget,
        mask: super::cross_engine::LinkMask::default(),
    };
    for (k, j) in flat.joins.iter().enumerate() {
        let known = &bindings[0..=k];
        let new_binding = &bindings[k + 1];
        engine.build_join_probe(j, known, new_binding, &env)?;
    }

    if let Some(w) = &flat.where_clause {
        join::bind_flat_predicate(w, &bindings, &offsets, &[])?;
    }
    let proj = join::bind_join_projection(&flat.items, &bindings, &offsets)?;
    check_no_duplicate_names(&proj)?;
    Ok(())
}

fn flat_bindings(engine: &RelEngine, domain: &str, flat: &Select) -> Result<Vec<BindingInfo>, RelStoreError> {
    let mut bindings = Vec::with_capacity(flat.joins.len() + 1);
    let base_schema = require_table_schema(engine, domain, &flat.from.name)?;
    let base_alias = flat.from.alias.clone().unwrap_or_else(|| base_schema.name.clone());
    bindings.push(BindingInfo { alias: base_alias, schema: Arc::new(base_schema) });
    for j in &flat.joins {
        let schema = require_table_schema(engine, domain, &j.table.name)?;
        let alias = j.table.alias.clone().unwrap_or_else(|| schema.name.clone());
        bindings.push(BindingInfo { alias, schema: Arc::new(schema) });
    }
    Ok(bindings)
}

fn require_table_schema(engine: &RelEngine, domain: &str, name: &str) -> Result<super::catalog::TableSchema, RelStoreError> {
    match engine.catalog.get(&engine.domains, domain, name) {
        Ok(CatalogEntry::Table(t)) => Ok(t),
        Ok(CatalogEntry::View(_)) => unreachable!("inline() must never leave a view in a flattened statement"),
        Err(RelStoreError::ObjectNotFound { domain, name }) => Err(RelStoreError::TableNotFound { domain, name }),
        Err(e) => Err(e),
    }
}

fn check_no_duplicate_names(proj: &[ProjectedColumn]) -> Result<(), RelStoreError> {
    let mut seen = HashSet::new();
    for p in proj {
        if !seen.insert(p.name.as_str()) {
            return Err(RelStoreError::InvalidSchema(format!(
                "duplicate output column name '{}' in view definition",
                p.name
            )));
        }
    }
    Ok(())
}

// ── §7: DDL dependency check (structural bind only, no RelEngine) ──────────

/// The `check` guard `ddl.rs`'s DROP TABLE / DROP COLUMN / RENAME COLUMN /
/// RENAME TABLE arms and this module's own `DROP VIEW` pass to the catalog's
/// `*_checked` primitives (spec §7): re-binds every view still present in
/// the prospective post-DDL map; any that fails to resolve is dependent on
/// `object`. Brute-force (KISS, v1: up to `max_tables_per_domain` small
/// re-binds — no reverse-dependency index, spec §7's own cost argument).
pub(super) fn check_view_dependents(
    prospective: &HashMap<String, CatalogEntry>,
    object: &str,
    domain: &str,
) -> Result<(), RelStoreError> {
    let mut dependents = Vec::new();
    for entry in prospective.values() {
        if let CatalogEntry::View(v) = entry {
            if rebind_structural(domain, prospective, &v.sql).is_err() {
                dependents.push(v.name.clone());
            }
        }
    }
    if dependents.is_empty() {
        return Ok(());
    }
    dependents.sort();
    Err(RelStoreError::ViewDependencyConflict { object: object.to_string(), views: dependents })
}

fn rebind_structural(domain: &str, prospective: &HashMap<String, CatalogEntry>, sql: &str) -> Result<(), RelStoreError> {
    let sel = parse_view_sql(sql)?;
    let lookup = map_lookup(prospective);
    let (flat, _substitutions) = inline(&lookup, &sel, 1)?;
    validate_flat_select_structural(domain, prospective, &flat)
}

/// Structural-only counterpart of `validate_flat_select_full`: name/type
/// resolution (columns, ON operands) with no engine access — deliberately
/// skips the join index requirement and `max_join_depth` (spec §7: those are
/// execution-time concerns; a dropped index alone must not block an
/// unrelated `DROP COLUMN`).
fn validate_flat_select_structural(
    domain: &str,
    prospective: &HashMap<String, CatalogEntry>,
    flat: &Select,
) -> Result<(), RelStoreError> {
    if flat.joins.is_empty() {
        let schema = require_table_schema_from_map(domain, prospective, &flat.from.name)?;
        let quals = dml::accepted_quals(&schema, flat);
        select::bind_projection(&flat.items, &schema, &quals)?;
        if let Some(w) = &flat.where_clause {
            dml::bind_predicate(w, &schema, &quals, &[])?;
        }
        return Ok(());
    }

    let mut bindings = Vec::with_capacity(flat.joins.len() + 1);
    let base_schema = require_table_schema_from_map(domain, prospective, &flat.from.name)?;
    let base_alias = flat.from.alias.clone().unwrap_or_else(|| base_schema.name.clone());
    bindings.push(BindingInfo { alias: base_alias, schema: Arc::new(base_schema) });
    for j in &flat.joins {
        let schema = require_table_schema_from_map(domain, prospective, &j.table.name)?;
        let alias = j.table.alias.clone().unwrap_or_else(|| schema.name.clone());
        bindings.push(BindingInfo { alias, schema: Arc::new(schema) });
    }
    join::check_unique_aliases(&bindings)?;
    let offsets = join::flat_offsets(&bindings);
    for (k, j) in flat.joins.iter().enumerate() {
        join::resolve_join_on(j, &bindings[0..=k], &bindings[k + 1])?;
    }
    if let Some(w) = &flat.where_clause {
        join::bind_flat_predicate(w, &bindings, &offsets, &[])?;
    }
    join::bind_join_projection(&flat.items, &bindings, &offsets)?;
    Ok(())
}

fn require_table_schema_from_map(
    domain: &str,
    map: &HashMap<String, CatalogEntry>,
    name: &str,
) -> Result<super::catalog::TableSchema, RelStoreError> {
    match map.get(name) {
        Some(CatalogEntry::Table(t)) => Ok(t.clone()),
        _ => Err(RelStoreError::TableNotFound { domain: domain.to_string(), name: name.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::rel::ScalarValue;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use serde_json::json;
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

    async fn run(rel: &RelEngine, sql: &str, params: &[serde_json::Value]) -> Result<super::super::ExecOutcome, RelStoreError> {
        rel.execute("default", sql, params).await
    }

    async fn ok(rel: &RelEngine, sql: &str) {
        run(rel, sql, &[]).await.unwrap();
    }

    async fn sel(rel: &RelEngine, sql: &str) -> super::super::dml::SelectResult {
        match run(rel, sql, &[]).await.unwrap() {
            super::super::ExecOutcome::Select(r) => r,
            o => panic!("expected SELECT, got {o:?}"),
        }
    }

    async fn err(rel: &RelEngine, sql: &str) -> RelStoreError {
        run(rel, sql, &[]).await.unwrap_err()
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

    fn inlinings(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_view_inlinings_total.load(Ordering::Relaxed)
    }

    fn create_view_ops(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_ddl_view_ops_create_view_total.load(Ordering::Relaxed)
    }

    fn drop_view_ops(rel: &RelEngine) -> u64 {
        rel.metrics.system.rel_ddl_view_ops_drop_view_total.load(Ordering::Relaxed)
    }

    // 1. CREATE VIEW binds/validates, stores the raw text; get()/list() see it.
    #[tokio::test]
    async fn test_create_view_binds_and_stores_raw_text() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b TEXT)").await;
        ok(&rel, "CREATE VIEW v AS SELECT a, b FROM t WHERE a > 1").await;

        match rel.get_object("default", "v").unwrap() {
            CatalogEntry::View(vw) => assert_eq!(vw.sql, "SELECT a, b FROM t WHERE a > 1"),
            other => panic!("expected view, got {other:?}"),
        }
        assert_eq!(rel.list_objects("default").unwrap().len(), 2);
    }

    // 1b. Views count against max_tables_per_domain (rel/003, invariant confirmed
    // through the SQL/execute() path rel/008 adds).
    #[tokio::test]
    async fn test_create_view_counts_against_max_tables_per_domain() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { max_tables_per_domain: 1, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        let e = err(&rel, "CREATE VIEW v AS SELECT * FROM t").await;
        assert!(matches!(e, RelStoreError::LimitExceeded { .. }), "got: {e}");
    }

    // 2. `?` in the view body -> InvalidSchema, even with a matching params list.
    #[tokio::test]
    async fn test_create_view_rejects_params_even_with_matching_bind_list() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;

        let e = run(&rel, "CREATE VIEW v AS SELECT * FROM t WHERE a = ?", &[json!(1)])
            .await
            .unwrap_err();
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "got: {e}");
    }

    // 3. ORDER BY / LIMIT / OFFSET / COUNT(*) / duplicate output name -> InvalidSchema.
    #[tokio::test]
    async fn test_create_view_subset_violations() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER)").await;

        let e = err(&rel, "CREATE VIEW v1 AS SELECT * FROM t ORDER BY a").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "ORDER BY: got {e}");

        let e = err(&rel, "CREATE VIEW v2 AS SELECT * FROM t LIMIT 10").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "LIMIT: got {e}");

        let e = err(&rel, "CREATE VIEW v3 AS SELECT * FROM t LIMIT 10 OFFSET 5").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "LIMIT OFFSET: got {e}");

        let e = err(&rel, "CREATE VIEW v4 AS SELECT COUNT(*) FROM t").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "COUNT(*): got {e}");

        let e = err(&rel, "CREATE VIEW v5 AS SELECT a, b AS a FROM t").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "duplicate output name: got {e}");
    }

    // 4. Missing table/column, WHERE type mismatch -> 404/404/400 (full bind at CREATE).
    #[tokio::test]
    async fn test_create_view_full_bind_errors() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;

        let e = err(&rel, "CREATE VIEW v1 AS SELECT * FROM ghost").await;
        assert!(matches!(e, RelStoreError::TableNotFound { .. }), "got: {e}");

        let e = err(&rel, "CREATE VIEW v2 AS SELECT ghost_col FROM t").await;
        assert!(matches!(e, RelStoreError::ColumnNotFound { .. }), "got: {e}");

        let e = err(&rel, "CREATE VIEW v3 AS SELECT * FROM t WHERE a = 'x'").await;
        assert!(matches!(e, RelStoreError::TypeMismatch { .. }), "got: {e}");
    }

    // 5. Name collision view-vs-table and view-vs-view -> 409 (via create_view).
    #[tokio::test]
    async fn test_create_view_name_collisions() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE VIEW v AS SELECT * FROM t").await;

        let e = err(&rel, "CREATE VIEW t AS SELECT * FROM t").await;
        assert!(matches!(e, RelStoreError::ObjectAlreadyExists { .. }), "view vs table: got {e}");

        let e = err(&rel, "CREATE VIEW v AS SELECT * FROM t").await;
        assert!(matches!(e, RelStoreError::ObjectAlreadyExists { .. }), "view vs view: got {e}");
    }

    // 6. SELECT * FROM v (simple 1-table view): identical rows to the direct
    // SELECT; output names = the view's own projection names; +1 inlining.
    #[tokio::test]
    async fn test_select_star_from_simple_view_matches_direct_select() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b TEXT)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 10, 'x'), (2, 20, 'y')").await;
        ok(&rel, "CREATE VIEW v AS SELECT id, a AS aa, b FROM t").await;

        let direct = sel(&rel, "SELECT id, a AS aa, b FROM t").await;
        let before = inlinings(&rel);
        let via_view = sel(&rel, "SELECT * FROM v").await;
        assert_eq!(inlinings(&rel) - before, 1, "one view reference substituted");

        assert_eq!(
            via_view.columns.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            vec!["id".to_string(), "aa".to_string(), "b".to_string()]
        );
        assert_eq!(via_view.rows, direct.rows);
    }

    // 7. Outer WHERE AND-ed with the view's own WHERE; `pk = ?` still reaches
    // the PK-point access path through a view (optimizability preserved).
    #[tokio::test]
    async fn test_select_from_view_merges_where_and_keeps_pk_point_path() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;
        ok(&rel, "INSERT INTO t VALUES (1, 5), (2, 15), (3, 25)").await;
        ok(&rel, "CREATE VIEW v AS SELECT id, a FROM t WHERE a > 10").await;

        let s = sel(&rel, "SELECT id FROM v WHERE a < 20").await;
        assert_eq!(ints(&s.rows, 0), vec![2]);

        let before = scanned_keys(&rel);
        let s = sel(&rel, "SELECT id FROM v WHERE id = 2").await;
        let after = scanned_keys(&rel);
        assert_eq!(ints(&s.rows, 0), vec![2]);
        assert_eq!(after - before, 1, "pk = ? through a view must still drive the PK-point access path");
    }

    // 8. View with an internal LEFT JOIN in FROM position: an outer filter on
    // the joined (right) column works; a dangling link yields NULL.
    #[tokio::test]
    async fn test_view_with_internal_join_in_from_position() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER)").await;
        ok(&rel, "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)").await;
        ok(&rel, "INSERT INTO customers VALUES (1, 'alice')").await;
        ok(&rel, "INSERT INTO orders VALUES (100, 1), (101, 999)").await;
        ok(
            &rel,
            "CREATE VIEW order_customer AS SELECT orders.id AS order_id, customers.name AS customer_name \
             FROM orders LEFT JOIN customers ON orders.customer_id = customers.id",
        )
        .await;

        let s = sel(&rel, "SELECT order_id FROM order_customer WHERE customer_name = 'alice'").await;
        assert_eq!(ints(&s.rows, 0), vec![100]);

        let s = sel(&rel, "SELECT order_id, customer_name FROM order_customer ORDER BY order_id").await;
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(100), ScalarValue::Text("alice".into())]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(101), ScalarValue::Null], "dangling link -> NULL");
    }

    // 9. View in JOIN position (no WHERE): works; the view's own output maps
    // onto the base table's PK, so it is probeable.
    #[tokio::test]
    async fn test_view_in_join_position_without_where() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)").await;
        ok(&rel, "CREATE TABLE names (id INTEGER PRIMARY KEY, name TEXT)").await;
        ok(&rel, "INSERT INTO names VALUES (1, 'alice'), (2, 'bob')").await;
        ok(&rel, "INSERT INTO t VALUES (10, 1), (11, 2), (12, 99)").await;
        ok(&rel, "CREATE VIEW customer_names AS SELECT id AS pk, name FROM names").await;

        let s = sel(
            &rel,
            "SELECT t.id, customer_names.name FROM t LEFT JOIN customer_names ON t.x = customer_names.pk ORDER BY t.id",
        )
        .await;
        assert_eq!(s.rows[0], vec![ScalarValue::Integer(10), ScalarValue::Text("alice".into())]);
        assert_eq!(s.rows[1], vec![ScalarValue::Integer(11), ScalarValue::Text("bob".into())]);
        assert_eq!(s.rows[2], vec![ScalarValue::Integer(12), ScalarValue::Null]);
    }

    // 10. A view with its own WHERE used in JOIN position -> InvalidSchema.
    #[tokio::test]
    async fn test_view_with_where_in_join_position_rejected() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)").await;
        ok(&rel, "CREATE TABLE names (id INTEGER PRIMARY KEY, name TEXT, active BOOLEAN)").await;
        ok(&rel, "CREATE VIEW active_names AS SELECT id, name FROM names WHERE active = TRUE").await;

        let e = err(&rel, "SELECT t.id FROM t LEFT JOIN active_names ON t.x = active_names.id").await;
        assert!(matches!(e, RelStoreError::InvalidSchema(_)), "got: {e}");
    }

    // 11. View-over-view depth 3 resolves correctly; depth 4 -> LimitExceeded
    // (view_depth) at CREATE time.
    #[tokio::test]
    async fn test_view_over_view_depth_limit() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1), (2)").await;
        ok(&rel, "CREATE VIEW v1 AS SELECT * FROM t").await;
        ok(&rel, "CREATE VIEW v2 AS SELECT * FROM v1").await;
        ok(&rel, "CREATE VIEW v3 AS SELECT * FROM v2").await;

        let s = sel(&rel, "SELECT * FROM v3").await;
        assert_eq!(s.rows.len(), 2);

        let e = err(&rel, "CREATE VIEW v4 AS SELECT * FROM v3").await;
        match &e {
            RelStoreError::LimitExceeded { which, max } => {
                assert_eq!(which, "view_depth");
                assert_eq!(*max, 3);
            }
            other => panic!("expected LimitExceeded(view_depth), got {other}"),
        }
    }

    // 12. Self-reference -> TableNotFound (documents the cycle-unconstructibility
    // argument: `v` isn't in the catalog yet while its own body is bound).
    #[tokio::test]
    async fn test_self_reference_view_fails_as_table_not_found() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;

        let e = err(&rel, "CREATE VIEW v AS SELECT * FROM v").await;
        assert!(matches!(e, RelStoreError::TableNotFound { .. }), "got: {e}");
    }

    // 13. `max_join_depth` over the *combined* chain: an outer join pushing a
    // view's own chain over the limit fails at execution time; a view whose
    // own expansion alone already exceeds it fails at CREATE time.
    #[tokio::test]
    async fn test_max_join_depth_over_combined_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel = boot(RelStoreConfig { max_join_depth: 1, ..config_in(dir.path()) }).await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, c_id INTEGER)").await;
        ok(&rel, "CREATE TABLE c (id INTEGER PRIMARY KEY)").await;

        let e = err(
            &rel,
            "CREATE VIEW v_wide AS SELECT a.id FROM a LEFT JOIN b ON a.b_id = b.id LEFT JOIN c ON b.c_id = c.id",
        )
        .await;
        assert!(matches!(e, RelStoreError::JoinDepthExceeded { .. }), "own expansion alone: got {e}");

        ok(&rel, "CREATE VIEW v1 AS SELECT a.id AS id, b.id AS bid FROM a LEFT JOIN b ON a.b_id = b.id").await;
        ok(&rel, "CREATE TABLE d (id INTEGER PRIMARY KEY)").await;

        let e = err(&rel, "SELECT v1.id FROM v1 LEFT JOIN d ON v1.bid = d.id").await;
        assert!(matches!(e, RelStoreError::JoinDepthExceeded { .. }), "combined chain at execution time: got {e}");
    }

    // 14. Dependency — DROP TABLE: a referenced table is blocked with the
    // view list; an unreferenced one drops fine.
    #[tokio::test]
    async fn test_dependency_drop_table() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE TABLE unrelated (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE VIEW v AS SELECT * FROM t").await;

        let e = err(&rel, "DROP TABLE t").await;
        match &e {
            RelStoreError::ViewDependencyConflict { object, views } => {
                assert_eq!(object, "t");
                assert_eq!(views, &vec!["v".to_string()]);
            }
            other => panic!("expected ViewDependencyConflict, got {other}"),
        }
        assert!(rel.get_object("default", "t").is_ok(), "the drop must have been blocked");

        ok(&rel, "DROP TABLE unrelated").await;
    }

    // 15. Dependency — DROP COLUMN: an explicitly named referenced column blocks
    // (transitively through a `SELECT *` view too); a column only covered by
    // `SELECT *` (never named) does not block it directly.
    #[tokio::test]
    async fn test_dependency_drop_column() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER)").await;
        ok(&rel, "CREATE VIEW v_named AS SELECT a FROM t").await;
        ok(&rel, "CREATE VIEW v_star AS SELECT * FROM t").await;
        ok(&rel, "CREATE VIEW v_over_star AS SELECT a FROM v_star").await;

        let e = err(&rel, "ALTER TABLE t DROP COLUMN a").await;
        match &e {
            RelStoreError::ViewDependencyConflict { views, .. } => {
                let mut v = views.clone();
                v.sort();
                assert_eq!(v, vec!["v_named".to_string(), "v_over_star".to_string()]);
            }
            other => panic!("expected ViewDependencyConflict, got {other}"),
        }

        ok(&rel, "ALTER TABLE t DROP COLUMN b").await;
    }

    // 16. Dependency — RENAME COLUMN / RENAME TO: referenced -> 409.
    #[tokio::test]
    async fn test_dependency_rename_column_and_table() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;
        ok(&rel, "CREATE VIEW v AS SELECT a FROM t").await;

        let e = err(&rel, "ALTER TABLE t RENAME COLUMN a TO a2").await;
        assert!(matches!(e, RelStoreError::ViewDependencyConflict { .. }), "rename column: got {e}");

        let e = err(&rel, "ALTER TABLE t RENAME TO t2").await;
        assert!(matches!(e, RelStoreError::ViewDependencyConflict { .. }), "rename table: got {e}");
    }

    // 17. Dependency — DROP VIEW: referenced by another view -> 409;
    // unreferenced -> ok (then neither get() nor list() see it).
    #[tokio::test]
    async fn test_dependency_drop_view() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE VIEW base AS SELECT * FROM t").await;
        ok(&rel, "CREATE VIEW derived AS SELECT * FROM base").await;

        let e = err(&rel, "DROP VIEW base").await;
        match &e {
            RelStoreError::ViewDependencyConflict { object, views } => {
                assert_eq!(object, "base");
                assert_eq!(views, &vec!["derived".to_string()]);
            }
            other => panic!("expected ViewDependencyConflict, got {other}"),
        }

        ok(&rel, "DROP VIEW derived").await;
        ok(&rel, "DROP VIEW base").await;
        assert!(rel.get_object("default", "base").is_err());
        assert!(rel.list_objects("default").unwrap().iter().all(|o| o.name() != "base"));
    }

    // 18. DROP INDEX is never blocked by a view; a subsequent SELECT through
    // that view then fails at *execution* time with the rel/007 index
    // requirement message, not at DROP time.
    #[tokio::test]
    async fn test_drop_index_not_blocked_but_join_fails_at_execution_time() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE a (id INTEGER PRIMARY KEY, k INTEGER)").await;
        ok(&rel, "CREATE TABLE b (id INTEGER PRIMARY KEY, k INTEGER)").await;
        ok(&rel, "CREATE INDEX idx_b_k ON b (k)").await;
        ok(&rel, "CREATE VIEW v AS SELECT a.id AS aid, b.id AS bid FROM a LEFT JOIN b ON a.k = b.k").await;
        ok(&rel, "INSERT INTO a VALUES (1, 5)").await;
        ok(&rel, "INSERT INTO b VALUES (1, 5)").await;

        ok(&rel, "SELECT * FROM v").await;
        ok(&rel, "DROP INDEX idx_b_k").await;

        let e = err(&rel, "SELECT * FROM v").await;
        assert!(matches!(e, RelStoreError::UnindexedJoin { .. }), "got: {e}");
    }

    // 19. DML on a view -> NotWritable (rel/005 guard; test only, per spec §8).
    #[tokio::test]
    async fn test_dml_on_view_not_writable() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "CREATE VIEW v AS SELECT * FROM t").await;

        let e = err(&rel, "INSERT INTO v VALUES (1)").await;
        assert!(matches!(e, RelStoreError::NotWritable { .. }), "insert: got {e}");
        let e = err(&rel, "UPDATE v SET id = 1").await;
        assert!(matches!(e, RelStoreError::NotWritable { .. }), "update: got {e}");
        let e = err(&rel, "DELETE FROM v").await;
        assert!(matches!(e, RelStoreError::NotWritable { .. }), "delete: got {e}");
    }

    // 20. Raw-text fidelity (incl. a trimmed trailing ';') & re-parse: stored
    // `sql` == the submitted text; repeated execution re-parses consistently.
    #[tokio::test]
    async fn test_raw_text_fidelity_and_reparse() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)").await;
        let submitted = "SELECT   id,  a   FROM t   WHERE  a > 1";
        ok(&rel, &format!("CREATE VIEW v AS {submitted}")).await;
        match rel.get_object("default", "v").unwrap() {
            CatalogEntry::View(vw) => assert_eq!(vw.sql, submitted),
            other => panic!("expected view, got {other:?}"),
        }

        ok(&rel, "CREATE VIEW v2 AS SELECT * FROM t;").await;
        match rel.get_object("default", "v2").unwrap() {
            CatalogEntry::View(vw) => assert_eq!(vw.sql, "SELECT * FROM t"),
            other => panic!("expected view, got {other:?}"),
        }

        ok(&rel, "INSERT INTO t VALUES (1, 5), (2, 0)").await;
        let s1 = sel(&rel, "SELECT id FROM v").await;
        let s2 = sel(&rel, "SELECT id FROM v").await;
        assert_eq!(s1.rows, s2.rows);
        assert_eq!(ints(&s1.rows, 0), vec![1]);
    }

    // 21. Metrics: `rel_view_inlinings_total` counts every substituted (incl.
    // recursive) view reference; `rel_ddl_view_ops_total{create_view|drop_view}`
    // increments as expected.
    #[tokio::test]
    async fn test_view_metrics() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;
        ok(&rel, "INSERT INTO t VALUES (1)").await;
        ok(&rel, "CREATE VIEW v1 AS SELECT * FROM t").await;
        ok(&rel, "CREATE VIEW v2 AS SELECT * FROM v1").await;

        let create_before = create_view_ops(&rel);
        ok(&rel, "CREATE VIEW v3 AS SELECT * FROM v2").await;
        assert_eq!(create_view_ops(&rel) - create_before, 1);

        let inlinings_before = inlinings(&rel);
        ok(&rel, "SELECT * FROM v3").await;
        assert_eq!(inlinings(&rel) - inlinings_before, 3, "v3 -> v2 -> v1 -> t: 3 substitutions");

        let drop_before = drop_view_ops(&rel);
        ok(&rel, "DROP VIEW v3").await;
        assert_eq!(drop_view_ops(&rel) - drop_before, 1);
    }

    // 22. (004 TOCTOU) DROP VIEW on a table name is rejected — the kind is now
    // checked atomically under the ddl_lock on the removed entry, not by a
    // pre-lock probe a concurrent re-CREATE could race — and the table survives.
    #[tokio::test]
    async fn test_drop_view_on_table_rejected_and_table_survives() {
        let (rel, _d) = make().await;
        ok(&rel, "CREATE TABLE t (id INTEGER PRIMARY KEY)").await;

        let e = err(&rel, "DROP VIEW t").await;
        assert!(matches!(e, RelStoreError::ObjectNotFound { .. }), "got: {e}");
        assert!(
            matches!(rel.get_object("default", "t").unwrap(), CatalogEntry::Table(_)),
            "the table must survive a rejected DROP VIEW"
        );
    }
}
