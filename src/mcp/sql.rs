//! Which statements each SQL tool passes on: the public LuraSQL parser
//! decides before the statement reaches the SQL route, so no tool drops a
//! table, an index, a view or a column, whatever the key's permission.

use crate::engines::rel::ast::{AlterAction, Statement};
use crate::engines::rel::{lexer, parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SqlTool {
    /// `SELECT`.
    Query,
    /// `INSERT`, `UPDATE`, `DELETE`.
    Execute,
    /// `CREATE TABLE`, `CREATE INDEX`, `CREATE VIEW`, and `ALTER TABLE` with
    /// `ADD COLUMN`, `RENAME COLUMN` or `RENAME TO`.
    Ddl,
}

/// Why a statement does not reach the SQL route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rejected {
    /// The statement does not lex or parse: the message the SQL route would
    /// answer with 400.
    Invalid(String),
    /// The statement belongs to another tool or to none.
    NotAllowed(String),
}

/// Lexes and parses `sql` with the SQL route's statement limit and checks
/// that `tool` may run it.
pub(crate) fn check(tool: SqlTool, sql: &str, max_statement_len: usize) -> Result<(), Rejected> {
    let tokens = lexer::tokenize(sql, max_statement_len).map_err(|e| Rejected::Invalid(e.to_string()))?;
    let statement = parser::parse(&tokens).map_err(|e| Rejected::Invalid(e.to_string()))?;
    let allowed = match (tool, &statement) {
        (SqlTool::Query, Statement::Select(_)) => true,
        (SqlTool::Execute, Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_)) => true,
        (SqlTool::Ddl, Statement::CreateTable(_) | Statement::CreateIndex(_) | Statement::CreateView(_)) => true,
        (SqlTool::Ddl, Statement::AlterTable(alter)) => matches!(
            alter.action,
            AlterAction::AddColumn(_) | AlterAction::RenameColumn { .. } | AlterAction::RenameTable(_)
        ),
        _ => false,
    };
    if allowed {
        return Ok(());
    }
    let reason = match &statement {
        Statement::DropTable(_) | Statement::DropIndex(_) | Statement::DropView(_) => {
            "dropping a table, an index or a view is not available over MCP".to_string()
        }
        Statement::AlterTable(alter) if matches!(alter.action, AlterAction::DropColumn(_)) => {
            "dropping a column is not available over MCP".to_string()
        }
        _ => format!("this statement does not belong to this tool; {}", tool_hint(&statement)),
    };
    Err(Rejected::NotAllowed(reason))
}

fn tool_hint(statement: &Statement) -> &'static str {
    match statement {
        Statement::Select(_) => "use sql_query",
        Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_) => "use sql_execute",
        _ => "use sql_ddl",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::rel::MAX_STATEMENT_LEN as LIMIT;

    /// One statement per `Statement` and `AlterAction` variant.
    const STATEMENTS: [(&str, Option<SqlTool>); 14] = [
        ("SELECT id FROM t", Some(SqlTool::Query)),
        ("INSERT INTO t VALUES (1, 'clé')", Some(SqlTool::Execute)),
        ("UPDATE t SET name = 'x' WHERE id = 1", Some(SqlTool::Execute)),
        ("DELETE FROM t WHERE id = 1", Some(SqlTool::Execute)),
        ("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", Some(SqlTool::Ddl)),
        ("CREATE INDEX idx1 ON t (name)", Some(SqlTool::Ddl)),
        ("CREATE VIEW v AS SELECT * FROM t", Some(SqlTool::Ddl)),
        ("ALTER TABLE t ADD COLUMN x INTEGER", Some(SqlTool::Ddl)),
        ("ALTER TABLE t RENAME COLUMN x TO y", Some(SqlTool::Ddl)),
        ("ALTER TABLE t RENAME TO u", Some(SqlTool::Ddl)),
        ("ALTER TABLE t DROP COLUMN x", None),
        ("DROP TABLE t", None),
        ("DROP INDEX idx1", None),
        ("DROP VIEW v", None),
    ];

    #[test]
    fn each_statement_passes_exactly_its_tool() {
        for (sql, owner) in STATEMENTS {
            for tool in [SqlTool::Query, SqlTool::Execute, SqlTool::Ddl] {
                let result = check(tool, sql, LIMIT);
                if Some(tool) == owner {
                    assert_eq!(result, Ok(()), "{tool:?}: {sql}");
                } else {
                    assert!(matches!(result, Err(Rejected::NotAllowed(_))), "{tool:?}: {sql}: {result:?}");
                }
            }
        }
    }

    #[test]
    fn drops_are_refused_with_a_reason() {
        for sql in ["DROP TABLE t", "DROP INDEX idx1", "DROP VIEW v", "ALTER TABLE t DROP COLUMN x"] {
            let Err(Rejected::NotAllowed(reason)) = check(SqlTool::Ddl, sql, LIMIT) else { panic!("{sql}") };
            assert!(reason.contains("not available over MCP"), "{sql}: {reason}");
        }
    }

    #[test]
    fn several_statements_are_refused_by_the_parser() {
        let result = check(SqlTool::Query, "SELECT id FROM t; DROP TABLE t", LIMIT);
        let expected = crate::engines::rel::RelStoreError::MultipleStatements.to_string();
        assert_eq!(result, Err(Rejected::Invalid(expected)));
    }

    #[test]
    fn parse_errors_and_the_statement_limit_come_back_unchanged() {
        let Err(Rejected::Invalid(message)) = check(SqlTool::Query, "SELEC id FROM t", LIMIT) else { panic!() };
        let expected = parser::parse(&lexer::tokenize("SELEC id FROM t", LIMIT).unwrap()).unwrap_err().to_string();
        assert_eq!(message, expected);

        let long = format!("SELECT id FROM t WHERE name = '{}'", "x".repeat(100));
        let Err(Rejected::Invalid(message)) = check(SqlTool::Query, &long, 40) else { panic!() };
        assert_eq!(message, lexer::tokenize(&long, 40).unwrap_err().to_string());
    }
}
