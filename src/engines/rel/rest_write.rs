//! Row-Write engine entry points (spec rel/010 §5): synthesize the bound
//! `Statement::{Insert,Update,Delete}` an equivalent `/sql` DML statement
//! would produce (`Operand::Param` + REST values as positional `params`) and
//! hand it to the shared post-parse dispatch (`execute_dml`, dml.rs) — the
//! exact same write path, constraints, and error codes as `/sql`.

use super::ast::{Assignment, ColumnRef, CompareOp, Delete, Expr, Insert, Operand, Statement, Update};
use super::dml::{coerce_json, DmlResult};
use super::error::RelStoreError;
use super::rest_browse::parse_raw_value;
use super::{ExecOutcome, RelEngine};
use serde_json::Value;
use std::collections::HashSet;

impl RelEngine {
    /// `POST …/rows` (spec §5): body keys become the INSERT column list, body
    /// values the positional params — an omitted AUTOINCREMENT PK is simply
    /// absent from that list, so `exec_insert` assigns it from the sequence.
    /// Keys are normalized to the lexer's column casing first (010-F1), so a
    /// key like `"Amount"` binds to catalog column `amount`, same as `/sql`.
    pub(crate) async fn insert_row(
        &self,
        domain: &str,
        table: &str,
        body: &serde_json::Map<String, Value>,
    ) -> Result<DmlResult, RelStoreError> {
        let (columns, params): (Vec<String>, Vec<Value>) = normalize_body_keys(body)?.into_iter().unzip();
        let row: Vec<Operand> = (0..params.len()).map(Operand::Param).collect();
        let stmt = Statement::Insert(Insert { table: table.to_string(), columns: Some(columns), rows: vec![row] });
        match self.execute_dml(domain, stmt, &params).await? {
            ExecOutcome::Dml(r) => Ok(r),
            _ => unreachable!("Insert always yields ExecOutcome::Dml"),
        }
    }

    /// `PUT …/rows/{pk}` (spec §5): partial update — only the body's columns
    /// are set. A body value for the PK column itself is never put into SET
    /// (rel/005 would reject that as `PrimaryKeyImmutable` anyway); instead
    /// it must equal the path PK, or the request is rejected outright. Body
    /// keys are normalized to the lexer's column casing first (010-F1), so a
    /// mixed-case PK key like `"Id"` is recognized as the PK, not treated as
    /// an unknown SET column.
    pub(crate) async fn update_row(
        &self,
        domain: &str,
        table: &str,
        pk_raw: &str,
        body: &serde_json::Map<String, Value>,
    ) -> Result<DmlResult, RelStoreError> {
        let (_, schema) = self.require_table(domain, table)?;
        let pk_col = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");

        let mut assignments: Vec<Assignment> = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        for (k, v) in normalize_body_keys(body)? {
            if k == pk_col.name {
                let body_pk = coerce_json(pk_col.col_type, &v, &pk_col.name)?;
                let path_pk = coerce_json(pk_col.col_type, &parse_raw_value(pk_col.col_type, pk_raw)?, &pk_col.name)?;
                if body_pk != path_pk {
                    return Err(RelStoreError::InvalidSchema(format!(
                        "body primary key '{}' does not match path primary key",
                        pk_col.name
                    )));
                }
                continue; // PK never enters SET, even when it matches (spec §5)
            }
            assignments.push(Assignment { column: k, value: Operand::Param(params.len()) });
            params.push(v);
        }

        let pk_param = params.len();
        params.push(parse_raw_value(pk_col.col_type, pk_raw)?);
        let stmt = Statement::Update(Update {
            table: table.to_string(),
            assignments,
            where_clause: Some(Expr::Compare {
                lhs: Operand::Column(ColumnRef { qualifier: None, name: pk_col.name.clone() }),
                op: CompareOp::Eq,
                rhs: Operand::Param(pk_param),
            }),
        });
        match self.execute_dml(domain, stmt, &params).await? {
            ExecOutcome::Dml(r) => Ok(r),
            _ => unreachable!("Update always yields ExecOutcome::Dml"),
        }
    }

    /// `DELETE …/rows/{pk}` (spec §5): `pk = ?` with the path PK as the sole
    /// param — `affected == 0` (handler-side 404) vs `1` is the caller's call.
    pub(crate) async fn delete_row(
        &self,
        domain: &str,
        table: &str,
        pk_raw: &str,
    ) -> Result<DmlResult, RelStoreError> {
        let (_, schema) = self.require_table(domain, table)?;
        let pk_col = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
        let pk_value = parse_raw_value(pk_col.col_type, pk_raw)?;

        let stmt = Statement::Delete(Delete {
            table: table.to_string(),
            where_clause: Some(Expr::Compare {
                lhs: Operand::Column(ColumnRef { qualifier: None, name: pk_col.name.clone() }),
                op: CompareOp::Eq,
                rhs: Operand::Param(0),
            }),
        });
        match self.execute_dml(domain, stmt, &[pk_value]).await? {
            ExecOutcome::Dml(r) => Ok(r),
            _ => unreachable!("Delete always yields ExecOutcome::Dml"),
        }
    }
}

/// Normalizes REST body keys to the lexer's column casing (`to_ascii_lowercase`,
/// `lexer.rs`) before they reach the binder — `/rows` must resolve columns
/// exactly like the equivalent `/sql` statement (spec rel/010, fix 010-F1).
/// Two keys colliding after normalization (e.g. `"Amount"` and `"amount"`)
/// would otherwise silently drop one value, so that case is rejected outright
/// rather than picked arbitrarily.
fn normalize_body_keys(body: &serde_json::Map<String, Value>) -> Result<Vec<(String, Value)>, RelStoreError> {
    let mut seen = HashSet::with_capacity(body.len());
    let mut out = Vec::with_capacity(body.len());
    for (k, v) in body {
        let lower = k.to_ascii_lowercase();
        if !seen.insert(lower.clone()) {
            return Err(RelStoreError::InvalidSchema(format!("duplicate column '{lower}' in request body")));
        }
        out.push((lower, v.clone()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::rel::{ColumnInput, ColumnType, ScalarValue, TableInput};
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

    async fn make_orders_table(rel: &RelEngine) {
        let mut id_col = ColumnInput::new("id", ColumnType::Integer);
        id_col.primary_key = true;
        let amount_col = ColumnInput::new("amount", ColumnType::Integer);
        rel.create_table("default", TableInput { name: "orders".to_string(), columns: vec![id_col, amount_col] })
            .await
            .unwrap();
    }

    fn mk_body(v: Value) -> serde_json::Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    // 010-F1(a): a mixed-case body key ("Amount") must bind to catalog column
    // `amount`, same as `INSERT INTO orders (Amount) ...` would via /sql.
    // Pre-fix: the raw key "Amount" reached the binder unchanged -> ColumnNotFound.
    #[tokio::test]
    async fn test_insert_row_normalizes_mixed_case_column() {
        let (rel, _dir) = make_engine().await;
        make_orders_table(&rel).await;

        let result = rel
            .insert_row("default", "orders", &mk_body(json!({"id": 1, "Amount": 42})))
            .await
            .unwrap();
        assert_eq!(result.affected, 1);

        let (row, _) = rel.get_row("default", "orders", "1", &[]).await.unwrap().unwrap();
        let idx = row.columns.iter().position(|(n, _)| n.as_str() == "amount").unwrap();
        assert_eq!(row.rows[0][idx], ScalarValue::Integer(42));
    }

    // 010-F1(d): body keys colliding after normalization ("Amount"/"amount")
    // must not silently drop a value on INSERT.
    #[tokio::test]
    async fn test_insert_row_rejects_colliding_keys() {
        let (rel, _dir) = make_engine().await;
        make_orders_table(&rel).await;

        let body = mk_body(json!({"id": 1, "Amount": 1, "amount": 2}));
        let err = rel.insert_row("default", "orders", &body).await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
    }

    // 010-F1(b): a mixed-case body PK key ("Id") equal to the path PK must be
    // recognized as the PK, not fall through to a SET assignment on a
    // nonexistent "Id" column.
    #[tokio::test]
    async fn test_update_row_recognizes_mixed_case_body_pk_match() {
        let (rel, _dir) = make_engine().await;
        make_orders_table(&rel).await;
        rel.insert_row("default", "orders", &mk_body(json!({"id": 1, "amount": 5}))).await.unwrap();

        let result = rel
            .update_row("default", "orders", "1", &mk_body(json!({"Id": 1, "amount": 9})))
            .await
            .unwrap();
        assert_eq!(result.affected, 1);

        let (row, _) = rel.get_row("default", "orders", "1", &[]).await.unwrap().unwrap();
        let idx = row.columns.iter().position(|(n, _)| n.as_str() == "amount").unwrap();
        assert_eq!(row.rows[0][idx], ScalarValue::Integer(9));
    }

    // 010-F1(b): a mixed-case body PK key that disagrees with the path PK
    // must hit the body/path PK mismatch check, not ColumnNotFound("Id").
    #[tokio::test]
    async fn test_update_row_rejects_mismatched_mixed_case_body_pk() {
        let (rel, _dir) = make_engine().await;
        make_orders_table(&rel).await;
        rel.insert_row("default", "orders", &mk_body(json!({"id": 1, "amount": 5}))).await.unwrap();

        let err = rel
            .update_row("default", "orders", "1", &mk_body(json!({"Id": 2})))
            .await
            .unwrap_err();
        match err {
            RelStoreError::InvalidSchema(msg) => {
                assert!(msg.contains("does not match path primary key"), "got: {msg}")
            }
            other => panic!("expected InvalidSchema body-PK mismatch, got: {other}"),
        }
    }

    // 010-F1(d): body keys colliding after normalization must not silently
    // drop a value on UPDATE either — the shared UPDATE binder
    // (bind_update_assignments, dml.rs) applies every assignment
    // independently and has no duplicate-column guard of its own.
    #[tokio::test]
    async fn test_update_row_rejects_colliding_keys() {
        let (rel, _dir) = make_engine().await;
        make_orders_table(&rel).await;
        rel.insert_row("default", "orders", &mk_body(json!({"id": 1, "amount": 5}))).await.unwrap();

        let body = mk_body(json!({"Amount": 1, "amount": 2}));
        let err = rel.update_row("default", "orders", "1", &body).await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
    }
}
