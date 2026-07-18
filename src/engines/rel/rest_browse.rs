//! Row-Browse engine entry points (spec rel/010 §3/§4/§6): `?col=` filters
//! and the path PK compile to the same bound `Statement::Select` (rel/006)
//! `/sql` would use for the equivalent `SELECT * FROM t WHERE … LIMIT …` —
//! no second query path. Expand reuses the rel/009 resolver unchanged.

use super::ast::{ColumnRef, CompareOp, Expr, Limit, Operand, Select, SelectItem, TableRef};
use super::catalog::{CatalogEntry, TableSchema};
use super::dml::SelectResult;
use super::error::RelStoreError;
use super::rest_exec::ExpandedBlock;
use super::types::ColumnType;
use super::{ExecOutcome, RelEngine};
use serde_json::Value;
use std::collections::HashMap;

impl RelEngine {
    /// Read-side table resolution for the browse endpoints: a view is simply
    /// "no such table" (404, matching `GET tables/{t}`, spec §2) — not the
    /// write path's `NotWritable` (400), which would be nonsense on a GET.
    /// Views have no `/rows` resource in v1.
    fn browse_table(&self, domain: &str, name: &str) -> Result<TableSchema, RelStoreError> {
        match self.catalog.get(&self.domains, domain, name) {
            Ok(CatalogEntry::Table(t)) => Ok(t),
            Ok(CatalogEntry::View(_)) => Err(RelStoreError::TableNotFound {
                domain: domain.to_string(),
                name: name.to_string(),
            }),
            Err(RelStoreError::ObjectNotFound { domain, name }) => {
                Err(RelStoreError::TableNotFound { domain, name })
            }
            Err(e) => Err(e),
        }
    }
    /// Compiles `filters` (already stripped of `expand`/`limit`/`offset`) and
    /// `limit`/`offset` into a bound `*`-SELECT and runs it through the
    /// rel/006 executor, then resolves `expand` (rel/009 §5) against the same
    /// result. Returns the applied `(limit, offset)` alongside the result —
    /// `SelectResult` itself only carries whether the limit was capped, not
    /// the numeric values the REST response echoes (spec §3).
    pub(crate) async fn browse_rows(
        &self,
        domain: &str,
        table: &str,
        filters: &HashMap<String, String>,
        expand: &[String],
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<(SelectResult, Option<ExpandedBlock>, u64, u64), RelStoreError> {
        let schema = self.browse_table(domain, table)?;

        let mut params: Vec<Value> = Vec::with_capacity(filters.len());
        let mut where_clause: Option<Expr> = None;
        // Sorted so the synthesized AND-chain (and any param-order-dependent
        // behavior) is deterministic across requests with the same filters.
        let mut names: Vec<&String> = filters.keys().collect();
        names.sort();
        for name in names {
            // Normalize to the lexer's column casing (rel/004 §1) so
            // `?Amount=` resolves like the equivalent `/sql` WHERE clause
            // (spec rel/010, fix 010-F1).
            let lower = name.to_ascii_lowercase();
            let col = schema.columns.iter().find(|c| c.name == lower).ok_or_else(|| {
                RelStoreError::InvalidSchema(format!("unknown filter column '{name}'"))
            })?;
            let value = parse_raw_value(col.col_type, &filters[name])?;
            let cmp = Expr::Compare {
                lhs: Operand::Column(ColumnRef { qualifier: None, name: col.name.clone() }),
                op: CompareOp::Eq,
                rhs: Operand::Param(params.len()),
            };
            params.push(value);
            where_clause = Some(match where_clause {
                None => cmp,
                Some(existing) => Expr::And(Box::new(existing), Box::new(cmp)),
            });
        }

        // Without an explicit `limit`, `default_limit` must apply even if
        // `offset` alone was given — `Limit` (grammar: LIMIT required, OFFSET
        // optional) has no "offset-only" shape, so that case still needs an
        // explicit limit value.
        let limit_clause = match (limit, offset) {
            (None, None) => None,
            (Some(l), o) => Some(Limit { limit: l, offset: o }),
            (None, Some(o)) => Some(Limit { limit: self.default_limit as i64, offset: Some(o) }),
        };

        let sel = Select {
            items: vec![SelectItem::Star],
            from: TableRef { name: table.to_string(), alias: None },
            joins: Vec::new(),
            where_clause,
            order_by: Vec::new(),
            limit: limit_clause,
        };

        let ExecOutcome::Select(result) = self.exec_select(domain, sel, &params).await? else {
            unreachable!("a Select statement always yields ExecOutcome::Select")
        };

        let expanded = if expand.is_empty() {
            None
        } else {
            let resolved = self.resolve_expand(domain, &result, expand).await?;
            (!resolved.is_empty()).then_some(resolved)
        };

        let applied_offset = offset.unwrap_or(0).max(0) as u64;
        let applied_limit = match limit {
            Some(l) => (l.max(0) as u64).min(self.max_limit as u64),
            None => (self.default_limit as u64).min(self.max_limit as u64),
        };
        Ok((result, expanded, applied_limit, applied_offset))
    }

    /// PK-point SELECT + expand (spec §4): `None` when no row matches
    /// (handler maps that to 404); the SELECT itself never errors on a
    /// missing key, it just returns zero rows.
    pub(crate) async fn get_row(
        &self,
        domain: &str,
        table: &str,
        pk_raw: &str,
        expand: &[String],
    ) -> Result<Option<(SelectResult, Option<ExpandedBlock>)>, RelStoreError> {
        let schema = self.browse_table(domain, table)?;
        let pk_col = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
        let pk_value = parse_raw_value(pk_col.col_type, pk_raw)?;

        let sel = Select {
            items: vec![SelectItem::Star],
            from: TableRef { name: table.to_string(), alias: None },
            joins: Vec::new(),
            where_clause: Some(Expr::Compare {
                lhs: Operand::Column(ColumnRef { qualifier: None, name: pk_col.name.clone() }),
                op: CompareOp::Eq,
                rhs: Operand::Param(0),
            }),
            order_by: Vec::new(),
            limit: None,
        };

        let ExecOutcome::Select(result) = self.exec_select(domain, sel, &[pk_value]).await? else {
            unreachable!("a Select statement always yields ExecOutcome::Select")
        };
        if result.rows.is_empty() {
            return Ok(None);
        }

        let expanded = if expand.is_empty() {
            None
        } else {
            let resolved = self.resolve_expand(domain, &result, expand).await?;
            (!resolved.is_empty()).then_some(resolved)
        };
        Ok(Some((result, expanded)))
    }
}

/// Parses a raw HTTP string (a `?col=` filter value, or a path PK) into the
/// JSON shape [`super::dml::coerce_json`] expects for `col_type` — query
/// strings and path segments are always textual, so INTEGER/REAL/BOOLEAN need
/// an upfront shape fix-up (a bare numeric/bool string isn't valid JSON
/// number/bool syntax by itself once quoted). TEXT/KVREF/JSONREF pass through
/// raw; TIMESTAMP tries millis first, then falls back to a string so
/// `coerce_json`'s ISO-8601 parser (rel/005) can take over — same rule set as
/// `/sql`'s `params` binding, just fed from a string instead of a JSON body.
pub(super) fn parse_raw_value(col_type: ColumnType, raw: &str) -> Result<Value, RelStoreError> {
    let mismatch = || RelStoreError::TypeMismatch {
        context: "REST path/query value".to_string(),
        expected: format!("{col_type:?}"),
        actual: raw.to_string(),
    };
    Ok(match col_type.physical_type() {
        ColumnType::Integer => Value::from(raw.parse::<i64>().map_err(|_| mismatch())?),
        ColumnType::Real => Value::from(raw.parse::<f64>().map_err(|_| mismatch())?),
        ColumnType::Boolean => match raw {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => return Err(mismatch()),
        },
        ColumnType::Text => Value::String(raw.to_string()),
        ColumnType::Timestamp => match raw.parse::<i64>() {
            Ok(millis) => Value::from(millis),
            Err(_) => Value::String(raw.to_string()),
        },
        ColumnType::KvRef | ColumnType::JsonRef => unreachable!("physical_type collapses to Text"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::rel::{ColumnInput, ScalarValue, TableInput};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use serde_json::json;
    use std::sync::Arc;

    async fn make_engine() -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("rel_sstables").to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        };
        let metrics = MetricsStore::new(MetricsConfig::default());
        let cross_engine = crate::engines::rel::CrossEngineResolver::disabled(Arc::clone(&metrics));
        let engine = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();
        (engine, dir)
    }

    fn mk_body(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    async fn make_orders_with_rows(rel: &RelEngine) {
        let mut id_col = ColumnInput::new("id", ColumnType::Integer);
        id_col.primary_key = true;
        let amount_col = ColumnInput::new("amount", ColumnType::Integer);
        rel.create_table("default", TableInput { name: "orders".to_string(), columns: vec![id_col, amount_col] })
            .await
            .unwrap();
        rel.insert_row("default", "orders", &mk_body(json!({"id": 1, "amount": 50}))).await.unwrap();
        rel.insert_row("default", "orders", &mk_body(json!({"id": 2, "amount": 99}))).await.unwrap();
    }

    // 010-F1(c): a mixed-case `?col=` filter name must resolve against the
    // (always-lowercase) catalog column, same as the equivalent /sql WHERE.
    // Pre-fix: "Amount" != "amount" -> InvalidSchema("unknown filter column").
    #[tokio::test]
    async fn test_browse_rows_filter_normalizes_mixed_case_column() {
        let (rel, _dir) = make_engine().await;
        make_orders_with_rows(&rel).await;

        let mut filters = HashMap::new();
        filters.insert("Amount".to_string(), "50".to_string());
        let (result, _, _, _) = rel.browse_rows("default", "orders", &filters, &[], None, None).await.unwrap();

        assert_eq!(result.rows.len(), 1, "exactly the row with amount=50 must match");
        let idx = result.columns.iter().position(|(n, _)| n.as_str() == "id").unwrap();
        assert_eq!(result.rows[0][idx], ScalarValue::Integer(1));
    }
}
