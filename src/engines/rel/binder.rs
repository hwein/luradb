//! Binder for LuraSQL (spec rel/004 §5-6, §8).
//!
//! Two statement-independent front-end checks run for every class:
//! parameter-count matching and the NULL-bind guard (§6). DDL (table/index)
//! then gets a full AST → catalog-input translation, ready for `ddl.rs` to
//! hand straight to `RelCatalog`'s self-validating primitives — those
//! primitives remain the single source of truth for schema/constraint/limit
//! checks, exactly like rel/003's `create_table` already works; duplicating
//! that validation here would drift out of sync with it. `AstColumnDef` is
//! translated into a `catalog::ColumnInput` here per its own doc comment.
//! Every other class passes the two front-end checks and is returned as
//! `Pending`, carrying its AST on to `mod.rs`, which dispatches DML, SELECT,
//! and view DDL to their executors.

use super::ast::{
    AlterAction, AlterTable, AstColumnDef, ColumnConstraint, CreateTable, DefaultVal, Expr,
    Literal, Operand, Select, Statement, StatementClass,
};
use super::catalog::{ColumnInput, DefaultValue, TableInput};
use super::error::RelStoreError;
use super::types::ScalarValue;
use serde_json::Value;

// ── Bound statement / DDL plan ──────────────────────────────────────────────────

/// Result of binding: either a fully translated table/index DDL operation
/// ready for `ddl.rs`, or a statement that passed the front-end guards and
/// carries its AST on to `mod.rs` for execution (DML, SELECT, and CREATE/DROP
/// VIEW alike).
#[derive(Debug)]
pub enum BoundStatement {
    Ddl(DdlPlan),
    Pending {
        /// Surfaced for rel/011's two-stage auth enforcement.
        #[allow(dead_code)]
        class: StatementClass,
        stmt: Statement,
    },
}

/// A translated, catalog-ready DDL operation. Semantic validation
/// (existence, types, limits) is deliberately not duplicated here — see the
/// module doc comment.
#[derive(Debug)]
pub enum DdlPlan {
    CreateTable(TableInput),
    AddColumn { table: String, column: ColumnInput },
    DropColumn { table: String, column: String },
    RenameColumn { table: String, from: String, to: String },
    RenameTable { table: String, to: String },
    DropTable { table: String },
    CreateIndex {
        table: String,
        name: String,
        column: String,
        unique: bool,
    },
    DropIndex { name: String },
}

// ── bind ─────────────────────────────────────────────────────────────────────

/// `param_count` is the number of `?` placeholders the lexer counted
/// (`lexer::count_params`); `params` is the caller-supplied bind list.
pub fn bind(
    stmt: Statement,
    param_count: usize,
    params: &[Value],
) -> Result<BoundStatement, RelStoreError> {
    if param_count != params.len() {
        return Err(RelStoreError::ParameterCountMismatch {
            expected: param_count,
            actual: params.len(),
        });
    }
    check_statement_null_guard(&stmt, params)?;

    Ok(match stmt {
        Statement::CreateTable(ct) => {
            BoundStatement::Ddl(DdlPlan::CreateTable(translate_create_table(ct)))
        }
        Statement::AlterTable(at) => BoundStatement::Ddl(translate_alter_table(at)),
        Statement::DropTable(dt) => BoundStatement::Ddl(DdlPlan::DropTable { table: dt.table }),
        Statement::CreateIndex(ci) => BoundStatement::Ddl(DdlPlan::CreateIndex {
            table: ci.table,
            name: ci.name,
            column: ci.column,
            unique: ci.unique,
        }),
        Statement::DropIndex(di) => BoundStatement::Ddl(DdlPlan::DropIndex { name: di.name }),
        // DML, SELECT, and CREATE/DROP VIEW carry their AST on as `Pending`;
        // `mod.rs` dispatches each to its executor.
        other => {
            let class = other.class();
            BoundStatement::Pending { class, stmt: other }
        }
    })
}

// ── NULL-bind guard (spec rel/004 §6) ───────────────────────────────────────────
//
// Walks WHERE expression trees only — the only place `Expr` occurs in the AST
// (a `JOIN ... ON` is always `column_ref = column_ref`, never a general
// `Expr`, so there is nothing to guard there). `INSERT VALUES`/`UPDATE SET`
// use the separate `value_expr`/`Operand` slot, never `Expr`, so a `NULL`
// there is naturally outside the guard's reach — no special-casing needed.

/// Same nesting cap the parser enforces — this guard recurses over the same
/// `Expr`, so it needs its own bound against a stack-overflow abort when `bind`
/// receives a deeply nested tree directly.
const MAX_EXPR_DEPTH: usize = 100;

fn check_statement_null_guard(stmt: &Statement, params: &[Value]) -> Result<(), RelStoreError> {
    match stmt {
        Statement::Select(s) => check_select_null_guard(s, params),
        Statement::Update(u) => match &u.where_clause {
            Some(e) => check_expr_null_guard(e, params, 0),
            None => Ok(()),
        },
        Statement::Delete(d) => match &d.where_clause {
            Some(e) => check_expr_null_guard(e, params, 0),
            None => Ok(()),
        },
        Statement::CreateView(cv) => check_select_null_guard(&cv.select, params),
        _ => Ok(()),
    }
}

fn check_select_null_guard(sel: &Select, params: &[Value]) -> Result<(), RelStoreError> {
    match &sel.where_clause {
        Some(e) => check_expr_null_guard(e, params, 0),
        None => Ok(()),
    }
}

fn check_expr_null_guard(expr: &Expr, params: &[Value], depth: usize) -> Result<(), RelStoreError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(RelStoreError::Syntax {
            pos: 0,
            msg: format!("expression nesting too deep (max {})", MAX_EXPR_DEPTH),
        });
    }
    match expr {
        Expr::Compare { lhs, rhs, .. } => {
            check_operand_not_null(lhs, params)?;
            check_operand_not_null(rhs, params)?;
        }
        // The grammar allows only literals inside `IN (...)` (no `?`), so a
        // null-valued *parameter* can never occur here — only a literal NULL.
        Expr::In { list, .. } => {
            if list.iter().any(|l| matches!(l, Literal::Null)) {
                return Err(null_comparison_err());
            }
        }
        // `LIKE`'s pattern is always a string literal; `IS [NOT] NULL` is the
        // sanctioned path — the guard does not fire on either.
        Expr::Like { .. } | Expr::IsNull { .. } => {}
        Expr::And(a, b) | Expr::Or(a, b) => {
            check_expr_null_guard(a, params, depth + 1)?;
            check_expr_null_guard(b, params, depth + 1)?;
        }
        Expr::Not(e) | Expr::Paren(e) => check_expr_null_guard(e, params, depth + 1)?,
    }
    Ok(())
}

fn check_operand_not_null(op: &Operand, params: &[Value]) -> Result<(), RelStoreError> {
    match op {
        Operand::Literal(Literal::Null) => Err(null_comparison_err()),
        Operand::Param(i) => {
            if params.get(*i).is_some_and(Value::is_null) {
                Err(null_comparison_err())
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

fn null_comparison_err() -> RelStoreError {
    RelStoreError::NullComparison {
        hint: "use `col IS NULL` / `col IS NOT NULL` instead of comparing to NULL".to_string(),
    }
}

// ── DDL translation: AST → catalog inputs ───────────────────────────────────────

fn translate_create_table(ct: CreateTable) -> TableInput {
    TableInput {
        name: ct.name,
        columns: ct.columns.into_iter().map(column_input_from_ast).collect(),
    }
}

fn translate_alter_table(at: AlterTable) -> DdlPlan {
    match at.action {
        AlterAction::AddColumn(col) => DdlPlan::AddColumn {
            table: at.table,
            column: column_input_from_ast(col),
        },
        AlterAction::DropColumn(name) => DdlPlan::DropColumn {
            table: at.table,
            column: name,
        },
        AlterAction::RenameColumn { from, to } => DdlPlan::RenameColumn {
            table: at.table,
            from,
            to,
        },
        AlterAction::RenameTable(to) => DdlPlan::RenameTable { table: at.table, to },
    }
}

fn column_input_from_ast(col: AstColumnDef) -> ColumnInput {
    let mut input = ColumnInput::new(&col.name, col.ty);
    for c in col.constraints {
        match c {
            ColumnConstraint::PrimaryKey { autoincrement } => {
                input.primary_key = true;
                input.autoincrement = autoincrement;
            }
            ColumnConstraint::NotNull => input.nullable = false,
            ColumnConstraint::Unique => input.unique = true,
            ColumnConstraint::Default(DefaultVal::CurrentTimestamp) => {
                input.default = DefaultValue::CurrentTimestamp;
            }
            ColumnConstraint::Default(DefaultVal::Literal(Literal::Null)) => {
                input.default = DefaultValue::Null;
            }
            ColumnConstraint::Default(DefaultVal::Literal(lit)) => {
                input.default = DefaultValue::Literal(scalar_from_literal(lit));
            }
            ColumnConstraint::References(target) => input.references = Some(target),
        }
    }
    input
}

fn scalar_from_literal(lit: Literal) -> ScalarValue {
    match lit {
        Literal::Integer(i) => ScalarValue::Integer(i),
        Literal::Real(f) => ScalarValue::Real(f),
        Literal::Text(s) => ScalarValue::Text(s),
        Literal::Boolean(b) => ScalarValue::Boolean(b),
        Literal::Null => ScalarValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::rel::ast::{ColumnRef, Delete};
    use crate::engines::rel::lexer::{count_params, tokenize};
    use crate::engines::rel::parser::parse;

    fn bind_sql(sql: &str, params: &[Value]) -> Result<BoundStatement, RelStoreError> {
        let tokens = tokenize(sql, 64 * 1024).unwrap();
        let param_count = count_params(&tokens);
        let stmt = parse(&tokens).unwrap();
        bind(stmt, param_count, params)
    }

    // 8. `col = NULL` rejected with an IS-NULL hint; `IS [NOT] NULL` allowed.
    #[test]
    fn test_null_literal_comparison_rejected() {
        let err = bind_sql("SELECT * FROM t WHERE x = NULL", &[]).unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");

        assert!(bind_sql("SELECT * FROM t WHERE x IS NULL", &[]).is_ok());
        assert!(bind_sql("SELECT * FROM t WHERE x IS NOT NULL", &[]).is_ok());
    }

    // 9. `col = ?` with a null-valued parameter rejected; INSERT/UPDATE with a
    //    literal NULL value is allowed (guard is comparisons-only).
    #[test]
    fn test_null_param_comparison_rejected_but_write_null_allowed() {
        let err = bind_sql("SELECT * FROM t WHERE x = ?", &[Value::Null]).unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");

        assert!(bind_sql("SELECT * FROM t WHERE x = ?", &[Value::from(1)]).is_ok());
        assert!(bind_sql("UPDATE t SET c = NULL", &[]).is_ok());
        assert!(bind_sql("INSERT INTO t VALUES (NULL)", &[]).is_ok());
    }

    #[test]
    fn test_null_guard_inside_in_list_and_nested_bool_expr() {
        let err = bind_sql("SELECT * FROM t WHERE x IN (1, NULL, 3)", &[]).unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");

        let err = bind_sql("SELECT * FROM t WHERE a = 1 AND (b = NULL OR c = 2)", &[]).unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");
    }

    #[test]
    fn test_null_guard_reaches_into_create_view_select() {
        let err = bind_sql("CREATE VIEW v AS SELECT * FROM t WHERE x = NULL", &[]).unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");
    }

    // 004-F1 (binder path): an over-deep WHERE tree fed straight to `bind`
    // (bypassing the parser's own cap) yields a clean Syntax error instead of a
    // stack-overflow abort in the null guard.
    #[test]
    fn test_null_guard_depth_limit_rejects_without_overflow() {
        let mut expr = Expr::IsNull {
            col: ColumnRef { qualifier: None, name: "x".to_string() },
            negated: false,
        };
        for _ in 0..250 {
            expr = Expr::Not(Box::new(expr));
        }
        let stmt = Statement::Delete(Delete { table: "t".to_string(), where_clause: Some(expr) });
        match bind(stmt, 0, &[]).unwrap_err() {
            RelStoreError::Syntax { msg, .. } => assert!(msg.contains("nesting too deep"), "got: {msg}"),
            other => panic!("expected Syntax, got: {other}"),
        }
    }

    // 10. Parameter count mismatch in both directions.
    #[test]
    fn test_parameter_count_mismatch() {
        let err = bind_sql("SELECT * FROM t WHERE x = ?", &[]).unwrap_err();
        assert!(
            matches!(err, RelStoreError::ParameterCountMismatch { expected: 1, actual: 0 }),
            "got: {err}"
        );
        let err = bind_sql("SELECT * FROM t", &[Value::from(1)]).unwrap_err();
        assert!(
            matches!(err, RelStoreError::ParameterCountMismatch { expected: 0, actual: 1 }),
            "got: {err}"
        );
    }

    #[test]
    fn test_ddl_translates_and_dml_select_view_are_pending() {
        let bound = bind_sql("CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Ddl(DdlPlan::CreateTable(_))));

        let bound = bind_sql("SELECT * FROM t", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Pending { class: StatementClass::Read, .. }));

        let bound = bind_sql("INSERT INTO t VALUES (1)", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Pending { class: StatementClass::Write, .. }));

        let bound = bind_sql("CREATE VIEW v AS SELECT * FROM t", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Pending { class: StatementClass::Ddl, .. }));
    }

    #[test]
    fn test_create_table_translation_maps_constraints() {
        let bound = bind_sql(
            "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE)",
            &[],
        )
        .unwrap();
        let BoundStatement::Ddl(DdlPlan::CreateTable(input)) = bound else {
            panic!("expected a CreateTable plan")
        };
        assert_eq!(input.name, "t");
        assert!(input.columns[0].primary_key);
        assert!(input.columns[0].autoincrement);
        assert!(!input.columns[1].nullable);
        assert!(input.columns[1].unique);
    }

    #[test]
    fn test_alter_table_translation() {
        let bound = bind_sql("ALTER TABLE t ADD COLUMN x INTEGER", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Ddl(DdlPlan::AddColumn { .. })));

        let bound = bind_sql("ALTER TABLE t DROP COLUMN x", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Ddl(DdlPlan::DropColumn { .. })));

        let bound = bind_sql("ALTER TABLE t RENAME COLUMN x TO y", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Ddl(DdlPlan::RenameColumn { .. })));

        let bound = bind_sql("ALTER TABLE t RENAME TO u", &[]).unwrap();
        assert!(matches!(bound, BoundStatement::Ddl(DdlPlan::RenameTable { .. })));
    }
}
