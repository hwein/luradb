//! Recursive-descent parser for the full LuraSQL grammar (spec rel/004 §4,
//! concept 004 ch. 4.1). It builds the AST for every statement class; the
//! binder and `mod.rs` then translate and execute each of them downstream.
//!
//! Error positions: every `expect_*`/`parse_*` helper reports a `Syntax`
//! error using the position of the token it *failed to consume* — so each
//! checks via `peek()` first and only advances on the success path.

use super::ast::{
    AlterAction, AlterTable, Assignment, AstColumnDef, ColumnConstraint, ColumnRef, CompareOp,
    CreateIndex, CreateTable, CreateView, DefaultVal, Delete, DropIndex, DropTable, DropView,
    Expr, Insert, Join, Limit, Literal, Operand, OrderItem, Select, SelectItem, Statement,
    TableRef, Update,
};
use super::error::RelStoreError;
use super::lexer::{Keyword, Token};
use super::types::ColumnType;

/// Hard cap on WHERE-expression nesting depth (`(…)` / `NOT …`). Recursive
/// descent uses one stack frame per level; without this bound a ~40 KB
/// statement overflows the stack and aborts the process. 100 is far above any
/// legitimate query and far below the overflow point.
const MAX_EXPR_DEPTH: usize = 100;

/// Parses one full statement (with an optional single trailing `;`) from
/// already-lexed `(Token, byte_pos)` pairs. Empty input → `EmptyStatement`;
/// leftover tokens after the statement (and its optional `;`) →
/// `MultipleStatements` (spec rel/004 §1).
pub fn parse(tokens: &[(Token, usize)]) -> Result<Statement, RelStoreError> {
    if tokens.is_empty() {
        return Err(RelStoreError::EmptyStatement);
    }
    let mut p = Parser { tokens, pos: 0, depth: 0 };
    let stmt = p.parse_statement()?;
    p.eat_punct(&Token::Semicolon);
    if !p.at_eof() {
        return Err(RelStoreError::MultipleStatements);
    }
    Ok(stmt)
}

struct Parser<'a> {
    tokens: &'a [(Token, usize)],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    // ── token stream primitives ─────────────────────────────────────────────

    fn at_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(t, _)| t)
    }

    fn peek2(&self) -> Option<&Token> {
        self.tokens.get(self.pos + 1).map(|(t, _)| t)
    }

    /// Byte position for error reporting: the current token's start, or just
    /// past the last token if we are at EOF (there is no raw `sql` here to
    /// report a true end-of-string offset — an approximation is enough for
    /// a diagnostic message).
    fn peek_pos(&self) -> usize {
        match self.tokens.get(self.pos) {
            Some((_, p)) => *p,
            None => self.tokens.last().map(|(_, p)| *p + 1).unwrap_or(0),
        }
    }

    fn describe_current(&self) -> String {
        match self.peek() {
            Some(t) => t.describe(),
            None => "end of input".to_string(),
        }
    }

    fn err(&self, msg: impl Into<String>) -> RelStoreError {
        RelStoreError::Syntax {
            pos: self.peek_pos(),
            msg: msg.into(),
        }
    }

    fn eat_kw(&mut self, kw: Keyword) -> bool {
        if matches!(self.peek(), Some(Token::Keyword(k)) if *k == kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_kw(&mut self, kw: Keyword) -> Result<(), RelStoreError> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            Err(self.err(format!("expected {}, found {}", kw.as_str(), self.describe_current())))
        }
    }

    fn eat_punct(&mut self, tok: &Token) -> bool {
        if self.peek() == Some(tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, tok: Token) -> Result<(), RelStoreError> {
        if self.eat_punct(&tok) {
            Ok(())
        } else {
            Err(self.err(format!("expected {}, found {}", tok.describe(), self.describe_current())))
        }
    }

    fn expect_ident(&mut self) -> Result<String, RelStoreError> {
        match self.peek() {
            Some(Token::Ident(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => Err(self.err(format!("expected an identifier, found {}", self.describe_current()))),
        }
    }

    fn expect_integer(&mut self) -> Result<i64, RelStoreError> {
        match self.peek() {
            Some(Token::Integer(i)) => {
                let i = *i;
                self.pos += 1;
                Ok(i)
            }
            _ => Err(self.err(format!("expected an integer, found {}", self.describe_current()))),
        }
    }

    // ── statement dispatch ───────────────────────────────────────────────────

    fn parse_statement(&mut self) -> Result<Statement, RelStoreError> {
        match self.peek() {
            Some(Token::Keyword(Keyword::Create)) => self.parse_create(),
            Some(Token::Keyword(Keyword::Alter)) => self.parse_alter_table(),
            Some(Token::Keyword(Keyword::Drop)) => self.parse_drop(),
            Some(Token::Keyword(Keyword::Insert)) => self.parse_insert(),
            Some(Token::Keyword(Keyword::Update)) => self.parse_update(),
            Some(Token::Keyword(Keyword::Delete)) => self.parse_delete(),
            Some(Token::Keyword(Keyword::Select)) => self.parse_select().map(Statement::Select),
            _ => Err(self.err(format!(
                "expected a statement (CREATE/ALTER/DROP/INSERT/UPDATE/DELETE/SELECT), found {}",
                self.describe_current()
            ))),
        }
    }

    fn parse_create(&mut self) -> Result<Statement, RelStoreError> {
        self.expect_kw(Keyword::Create)?;
        if self.eat_kw(Keyword::Table) {
            self.parse_create_table_body()
        } else if self.eat_kw(Keyword::Unique) {
            self.expect_kw(Keyword::Index)?;
            self.parse_create_index_body(true)
        } else if self.eat_kw(Keyword::Index) {
            self.parse_create_index_body(false)
        } else if self.eat_kw(Keyword::View) {
            self.parse_create_view_body()
        } else {
            Err(self.err(format!(
                "expected TABLE/INDEX/UNIQUE/VIEW after CREATE, found {}",
                self.describe_current()
            )))
        }
    }

    fn parse_drop(&mut self) -> Result<Statement, RelStoreError> {
        self.expect_kw(Keyword::Drop)?;
        if self.eat_kw(Keyword::Table) {
            Ok(Statement::DropTable(DropTable {
                table: self.expect_ident()?,
            }))
        } else if self.eat_kw(Keyword::Index) {
            Ok(Statement::DropIndex(DropIndex {
                name: self.expect_ident()?,
            }))
        } else if self.eat_kw(Keyword::View) {
            Ok(Statement::DropView(DropView {
                name: self.expect_ident()?,
            }))
        } else {
            Err(self.err(format!(
                "expected TABLE/INDEX/VIEW after DROP, found {}",
                self.describe_current()
            )))
        }
    }

    // ── CREATE TABLE ─────────────────────────────────────────────────────────

    fn parse_create_table_body(&mut self) -> Result<Statement, RelStoreError> {
        let name = self.expect_ident()?;
        self.expect_punct(Token::LParen)?;
        let mut columns = vec![self.parse_column_def()?];
        while self.eat_punct(&Token::Comma) {
            columns.push(self.parse_column_def()?);
        }
        self.expect_punct(Token::RParen)?;
        Ok(Statement::CreateTable(CreateTable { name, columns }))
    }

    fn parse_column_def(&mut self) -> Result<AstColumnDef, RelStoreError> {
        let name = self.expect_ident()?;
        let ty = self.parse_type_name()?;
        let mut constraints = Vec::new();
        while let Some(c) = self.try_parse_column_constraint()? {
            constraints.push(c);
        }
        Ok(AstColumnDef { name, ty, constraints })
    }

    /// `type_name` (grammar §4): canonical types, aliases, and `VARCHAR`/`CHAR`
    /// with an optional, ignored `(n)` length. Delegates alias resolution to
    /// `ColumnType::from_sql_name` (rel/003) so the alias table lives once.
    fn parse_type_name(&mut self) -> Result<ColumnType, RelStoreError> {
        let kw = match self.peek() {
            Some(Token::Keyword(k)) if k.is_type_name() => *k,
            _ => return Err(self.err(format!("expected a type name, found {}", self.describe_current()))),
        };
        self.pos += 1;
        if matches!(kw, Keyword::Varchar | Keyword::Char) && self.eat_punct(&Token::LParen) {
            self.expect_integer()?; // length ignored (documented, spec §4)
            self.expect_punct(Token::RParen)?;
        }
        Ok(ColumnType::from_sql_name(kw.as_str()).expect("every type keyword maps to a ColumnType"))
    }

    fn try_parse_column_constraint(&mut self) -> Result<Option<ColumnConstraint>, RelStoreError> {
        if self.eat_kw(Keyword::Primary) {
            self.expect_kw(Keyword::Key)?;
            let autoincrement = self.eat_kw(Keyword::Autoincrement);
            return Ok(Some(ColumnConstraint::PrimaryKey { autoincrement }));
        }
        if self.eat_kw(Keyword::Not) {
            self.expect_kw(Keyword::Null)?;
            return Ok(Some(ColumnConstraint::NotNull));
        }
        if self.eat_kw(Keyword::Unique) {
            return Ok(Some(ColumnConstraint::Unique));
        }
        if self.eat_kw(Keyword::Default) {
            return if self.eat_kw(Keyword::CurrentTimestamp) {
                Ok(Some(ColumnConstraint::Default(DefaultVal::CurrentTimestamp)))
            } else {
                Ok(Some(ColumnConstraint::Default(DefaultVal::Literal(self.parse_literal()?))))
            };
        }
        if self.eat_kw(Keyword::References) {
            return Ok(Some(ColumnConstraint::References(self.expect_ident()?)));
        }
        Ok(None)
    }

    fn parse_literal(&mut self) -> Result<Literal, RelStoreError> {
        match self.peek() {
            Some(Token::Integer(i)) => {
                let i = *i;
                self.pos += 1;
                Ok(Literal::Integer(i))
            }
            Some(Token::Real(f)) => {
                let f = *f;
                self.pos += 1;
                Ok(Literal::Real(f))
            }
            Some(Token::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(Literal::Text(s))
            }
            Some(Token::Keyword(Keyword::True)) => {
                self.pos += 1;
                Ok(Literal::Boolean(true))
            }
            Some(Token::Keyword(Keyword::False)) => {
                self.pos += 1;
                Ok(Literal::Boolean(false))
            }
            Some(Token::Keyword(Keyword::Null)) => {
                self.pos += 1;
                Ok(Literal::Null)
            }
            _ => Err(self.err(format!("expected a literal, found {}", self.describe_current()))),
        }
    }

    // ── ALTER TABLE ──────────────────────────────────────────────────────────

    fn parse_alter_table(&mut self) -> Result<Statement, RelStoreError> {
        self.expect_kw(Keyword::Alter)?;
        self.expect_kw(Keyword::Table)?;
        let table = self.expect_ident()?;
        let action = if self.eat_kw(Keyword::Add) {
            self.expect_kw(Keyword::Column)?;
            AlterAction::AddColumn(self.parse_column_def()?)
        } else if self.eat_kw(Keyword::Drop) {
            self.expect_kw(Keyword::Column)?;
            AlterAction::DropColumn(self.expect_ident()?)
        } else if self.eat_kw(Keyword::Rename) {
            if self.eat_kw(Keyword::Column) {
                let from = self.expect_ident()?;
                self.expect_kw(Keyword::To)?;
                let to = self.expect_ident()?;
                AlterAction::RenameColumn { from, to }
            } else {
                self.expect_kw(Keyword::To)?;
                AlterAction::RenameTable(self.expect_ident()?)
            }
        } else {
            return Err(self.err(format!(
                "expected ADD/DROP/RENAME after ALTER TABLE ident, found {}",
                self.describe_current()
            )));
        };
        Ok(Statement::AlterTable(AlterTable { table, action }))
    }

    // ── CREATE/DROP INDEX ────────────────────────────────────────────────────

    fn parse_create_index_body(&mut self, unique: bool) -> Result<Statement, RelStoreError> {
        let name = self.expect_ident()?;
        self.expect_kw(Keyword::On)?;
        let table = self.expect_ident()?;
        self.expect_punct(Token::LParen)?;
        let column = self.expect_ident()?;
        self.expect_punct(Token::RParen)?;
        Ok(Statement::CreateIndex(CreateIndex {
            name,
            table,
            column,
            unique,
        }))
    }

    // ── CREATE VIEW ──────────────────────────────────────────────────────────

    fn parse_create_view_body(&mut self) -> Result<Statement, RelStoreError> {
        let name = self.expect_ident()?;
        self.expect_kw(Keyword::As)?;
        // The next token's byte offset is where the raw view SELECT text
        // starts (rel/008 §3): the caller slices the original SQL string
        // from here instead of re-serializing the AST, preserving it verbatim.
        let select_offset = self.peek_pos();
        let select = self.parse_select()?;
        Ok(Statement::CreateView(CreateView {
            name,
            select: Box::new(select),
            select_offset,
        }))
    }

    // ── INSERT ───────────────────────────────────────────────────────────────

    fn parse_insert(&mut self) -> Result<Statement, RelStoreError> {
        self.expect_kw(Keyword::Insert)?;
        self.expect_kw(Keyword::Into)?;
        let table = self.expect_ident()?;
        let columns = if self.eat_punct(&Token::LParen) {
            let mut cols = vec![self.expect_ident()?];
            while self.eat_punct(&Token::Comma) {
                cols.push(self.expect_ident()?);
            }
            self.expect_punct(Token::RParen)?;
            Some(cols)
        } else {
            None
        };
        self.expect_kw(Keyword::Values)?;
        let mut rows = vec![self.parse_row()?];
        while self.eat_punct(&Token::Comma) {
            rows.push(self.parse_row()?);
        }
        Ok(Statement::Insert(Insert { table, columns, rows }))
    }

    fn parse_row(&mut self) -> Result<Vec<Operand>, RelStoreError> {
        self.expect_punct(Token::LParen)?;
        let mut vals = vec![self.parse_value_expr()?];
        while self.eat_punct(&Token::Comma) {
            vals.push(self.parse_value_expr()?);
        }
        self.expect_punct(Token::RParen)?;
        Ok(vals)
    }

    /// `value_expr := literal | "?"` — never a column reference.
    fn parse_value_expr(&mut self) -> Result<Operand, RelStoreError> {
        match self.peek() {
            Some(Token::Param(i)) => {
                let i = *i;
                self.pos += 1;
                Ok(Operand::Param(i))
            }
            _ => self.parse_literal().map(Operand::Literal),
        }
    }

    // ── UPDATE ───────────────────────────────────────────────────────────────

    fn parse_update(&mut self) -> Result<Statement, RelStoreError> {
        self.expect_kw(Keyword::Update)?;
        let table = self.expect_ident()?;
        self.expect_kw(Keyword::Set)?;
        let mut assignments = vec![self.parse_assignment()?];
        while self.eat_punct(&Token::Comma) {
            assignments.push(self.parse_assignment()?);
        }
        let where_clause = self.try_parse_where()?;
        Ok(Statement::Update(Update {
            table,
            assignments,
            where_clause,
        }))
    }

    fn parse_assignment(&mut self) -> Result<Assignment, RelStoreError> {
        let column = self.expect_ident()?;
        self.expect_punct(Token::Eq)?;
        let value = self.parse_value_expr()?;
        Ok(Assignment { column, value })
    }

    // ── DELETE ───────────────────────────────────────────────────────────────

    fn parse_delete(&mut self) -> Result<Statement, RelStoreError> {
        self.expect_kw(Keyword::Delete)?;
        self.expect_kw(Keyword::From)?;
        let table = self.expect_ident()?;
        let where_clause = self.try_parse_where()?;
        Ok(Statement::Delete(Delete { table, where_clause }))
    }

    fn try_parse_where(&mut self) -> Result<Option<Expr>, RelStoreError> {
        if self.eat_kw(Keyword::Where) {
            Ok(Some(self.parse_expr()?))
        } else {
            Ok(None)
        }
    }

    // ── SELECT ───────────────────────────────────────────────────────────────

    fn parse_select(&mut self) -> Result<Select, RelStoreError> {
        self.expect_kw(Keyword::Select)?;
        let items = self.parse_select_list()?;
        self.expect_kw(Keyword::From)?;
        let from = self.parse_table_ref()?;
        let mut joins = Vec::new();
        while self.eat_kw(Keyword::Left) {
            self.eat_kw(Keyword::Outer); // optional
            self.expect_kw(Keyword::Join)?;
            let table = self.parse_table_ref()?;
            self.expect_kw(Keyword::On)?;
            let left = self.parse_column_ref()?;
            self.expect_punct(Token::Eq)?;
            let right = self.parse_column_ref()?;
            joins.push(Join { table, left, right });
        }
        let where_clause = self.try_parse_where()?;
        let order_by = self.try_parse_order_by()?;
        let limit = self.try_parse_limit()?;
        Ok(Select {
            items,
            from,
            joins,
            where_clause,
            order_by,
            limit,
        })
    }

    /// `select_list := "*" | COUNT "(" "*" ")" | select_item { "," select_item }`
    /// — no computed expressions, scalar functions, or other aggregates.
    fn parse_select_list(&mut self) -> Result<Vec<SelectItem>, RelStoreError> {
        if self.eat_punct(&Token::Star) {
            return Ok(vec![SelectItem::Star]);
        }
        if self.eat_kw(Keyword::Count) {
            self.expect_punct(Token::LParen)?;
            self.expect_punct(Token::Star)?;
            self.expect_punct(Token::RParen)?;
            return Ok(vec![SelectItem::CountStar]);
        }
        let mut items = vec![self.parse_select_item()?];
        while self.eat_punct(&Token::Comma) {
            items.push(self.parse_select_item()?);
        }
        Ok(items)
    }

    fn parse_select_item(&mut self) -> Result<SelectItem, RelStoreError> {
        let col = self.parse_column_ref()?;
        let alias = self.try_parse_alias()?;
        Ok(SelectItem::Column { col, alias })
    }

    /// `[ [ AS ] ident ]` — an explicit `AS`, or a bare trailing identifier
    /// (never ambiguous: every reserved word is lexed as a `Keyword`, not
    /// an `Ident`).
    fn try_parse_alias(&mut self) -> Result<Option<String>, RelStoreError> {
        if self.eat_kw(Keyword::As) {
            Ok(Some(self.expect_ident()?))
        } else if matches!(self.peek(), Some(Token::Ident(_))) {
            Ok(Some(self.expect_ident()?))
        } else {
            Ok(None)
        }
    }

    fn parse_column_ref(&mut self) -> Result<ColumnRef, RelStoreError> {
        let first = self.expect_ident()?;
        if self.eat_punct(&Token::Dot) {
            let name = self.expect_ident()?;
            Ok(ColumnRef {
                qualifier: Some(first),
                name,
            })
        } else {
            Ok(ColumnRef {
                qualifier: None,
                name: first,
            })
        }
    }

    fn parse_table_ref(&mut self) -> Result<TableRef, RelStoreError> {
        let name = self.expect_ident()?;
        let alias = self.try_parse_alias()?;
        Ok(TableRef { name, alias })
    }

    fn try_parse_order_by(&mut self) -> Result<Vec<OrderItem>, RelStoreError> {
        if !self.eat_kw(Keyword::Order) {
            return Ok(Vec::new());
        }
        self.expect_kw(Keyword::By)?;
        let mut items = vec![self.parse_order_item()?];
        while self.eat_punct(&Token::Comma) {
            items.push(self.parse_order_item()?);
        }
        Ok(items)
    }

    fn parse_order_item(&mut self) -> Result<OrderItem, RelStoreError> {
        let col = self.parse_column_ref()?;
        let desc = if self.eat_kw(Keyword::Desc) {
            true
        } else {
            self.eat_kw(Keyword::Asc);
            false
        };
        Ok(OrderItem { col, desc })
    }

    fn try_parse_limit(&mut self) -> Result<Option<Limit>, RelStoreError> {
        if !self.eat_kw(Keyword::Limit) {
            return Ok(None);
        }
        let limit = self.expect_integer()?;
        let offset = if self.eat_kw(Keyword::Offset) {
            Some(self.expect_integer()?)
        } else {
            None
        };
        Ok(Some(Limit { limit, offset }))
    }

    // ── WHERE expressions: OR < AND < NOT < predicate/paren (grammar §4) ────

    fn parse_expr(&mut self) -> Result<Expr, RelStoreError> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Expr, RelStoreError> {
        let mut lhs = self.parse_and_expr()?;
        while self.eat_kw(Keyword::Or) {
            let rhs = self.parse_and_expr()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and_expr(&mut self) -> Result<Expr, RelStoreError> {
        let mut lhs = self.parse_not_expr()?;
        while self.eat_kw(Keyword::And) {
            let rhs = self.parse_not_expr()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    /// Every nested `(…)` re-enters here (via `parse_expr` → … → this node) and
    /// so does every `NOT`, so one depth check here bounds the whole expression
    /// recursion against a stack-overflow abort.
    fn parse_not_expr(&mut self) -> Result<Expr, RelStoreError> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            return Err(self.err(format!("expression nesting too deep (max {})", MAX_EXPR_DEPTH)));
        }
        let result = if self.eat_kw(Keyword::Not) {
            self.parse_not_expr().map(|e| Expr::Not(Box::new(e)))
        } else {
            self.parse_predicate()
        };
        self.depth -= 1;
        result
    }

    /// `"(" expr ")" | column_ref IS [NOT] NULL | column_ref [NOT] IN (...)
    /// | column_ref [NOT] LIKE string | operand comparison_op operand`.
    /// Disambiguated by parsing a leading `operand` and then looking ahead
    /// for `IS`/`IN`/`LIKE`/`NOT IN`/`NOT LIKE`; anything else falls back to
    /// a plain comparison (the only shape left in the grammar).
    fn parse_predicate(&mut self) -> Result<Expr, RelStoreError> {
        if self.eat_punct(&Token::LParen) {
            let inner = self.parse_expr()?;
            self.expect_punct(Token::RParen)?;
            return Ok(Expr::Paren(Box::new(inner)));
        }

        let lhs = self.parse_operand()?;

        if matches!(self.peek(), Some(Token::Keyword(Keyword::Is))) {
            let col = self.require_column(lhs, "IS")?;
            self.pos += 1; // IS
            let negated = self.eat_kw(Keyword::Not);
            self.expect_kw(Keyword::Null)?;
            return Ok(Expr::IsNull { col, negated });
        }
        let negated_in_or_like = matches!(self.peek(), Some(Token::Keyword(Keyword::Not)))
            && matches!(
                self.peek2(),
                Some(Token::Keyword(Keyword::In)) | Some(Token::Keyword(Keyword::Like))
            );
        if negated_in_or_like {
            self.pos += 1; // NOT
            return self.parse_in_or_like(lhs, true);
        }
        if matches!(
            self.peek(),
            Some(Token::Keyword(Keyword::In)) | Some(Token::Keyword(Keyword::Like))
        ) {
            return self.parse_in_or_like(lhs, false);
        }

        let op = self.parse_comparison_op()?;
        let rhs = self.parse_operand()?;
        Ok(Expr::Compare { lhs, op, rhs })
    }

    fn parse_in_or_like(&mut self, lhs: Operand, negated: bool) -> Result<Expr, RelStoreError> {
        match self.peek() {
            Some(Token::Keyword(Keyword::In)) => {
                let col = self.require_column(lhs, "IN")?;
                self.pos += 1;
                self.expect_punct(Token::LParen)?;
                let mut list = vec![self.parse_literal()?];
                while self.eat_punct(&Token::Comma) {
                    list.push(self.parse_literal()?);
                }
                self.expect_punct(Token::RParen)?;
                Ok(Expr::In { col, negated, list })
            }
            Some(Token::Keyword(Keyword::Like)) => {
                let col = self.require_column(lhs, "LIKE")?;
                self.pos += 1;
                let pattern = match self.parse_literal()? {
                    Literal::Text(s) => s,
                    _ => return Err(self.err("expected a string literal after LIKE")),
                };
                Ok(Expr::Like { col, negated, pattern })
            }
            _ => Err(self.err(format!("expected IN or LIKE, found {}", self.describe_current()))),
        }
    }

    /// `IS`/`IN`/`LIKE` all require their subject to be a bare column
    /// reference (grammar §4), not a literal or `?`.
    fn require_column(&self, operand: Operand, ctx: &str) -> Result<ColumnRef, RelStoreError> {
        match operand {
            Operand::Column(c) => Ok(c),
            _ => Err(self.err(format!("{ctx} requires a column reference on its left-hand side"))),
        }
    }

    fn parse_operand(&mut self) -> Result<Operand, RelStoreError> {
        match self.peek() {
            Some(Token::Param(i)) => {
                let i = *i;
                self.pos += 1;
                Ok(Operand::Param(i))
            }
            Some(Token::Integer(_))
            | Some(Token::Real(_))
            | Some(Token::Str(_))
            | Some(Token::Keyword(Keyword::True))
            | Some(Token::Keyword(Keyword::False))
            | Some(Token::Keyword(Keyword::Null)) => self.parse_literal().map(Operand::Literal),
            Some(Token::Ident(_)) => self.parse_column_ref().map(Operand::Column),
            _ => Err(self.err(format!(
                "expected a column, literal, or '?', found {}",
                self.describe_current()
            ))),
        }
    }

    fn parse_comparison_op(&mut self) -> Result<CompareOp, RelStoreError> {
        let op = match self.peek() {
            Some(Token::Eq) => CompareOp::Eq,
            Some(Token::NotEq) => CompareOp::NotEq,
            Some(Token::Lt) => CompareOp::Lt,
            Some(Token::LtEq) => CompareOp::LtEq,
            Some(Token::Gt) => CompareOp::Gt,
            Some(Token::GtEq) => CompareOp::GtEq,
            _ => {
                return Err(self.err(format!(
                    "expected a comparison operator, found {}",
                    self.describe_current()
                )))
            }
        };
        self.pos += 1;
        Ok(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::rel::ast::StatementClass;
    use crate::engines::rel::lexer::tokenize;

    fn parse_sql(sql: &str) -> Result<Statement, RelStoreError> {
        let tokens = tokenize(sql, 64 * 1024)?;
        parse(&tokens)
    }

    // 3. Statement boundaries: single trailing ';' ok; two statements ->
    //    MultipleStatements; empty/whitespace-only -> EmptyStatement.
    #[test]
    fn test_statement_boundaries() {
        assert!(parse_sql("SELECT * FROM t").is_ok());
        assert!(parse_sql("SELECT * FROM t;").is_ok());
        assert!(matches!(
            parse_sql("SELECT * FROM t; SELECT * FROM t"),
            Err(RelStoreError::MultipleStatements)
        ));
        assert!(matches!(parse_sql(""), Err(RelStoreError::EmptyStatement)));
        assert!(matches!(parse_sql("   \t\n"), Err(RelStoreError::EmptyStatement)));
    }

    // 4. CREATE TABLE with every constraint kind parses to the right AST.
    #[test]
    fn test_create_table_all_constraints() {
        let sql = "CREATE TABLE t (\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \
            name TEXT NOT NULL, \
            email TEXT UNIQUE, \
            score REAL DEFAULT 1.5, \
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
            parent_id INTEGER REFERENCES parent, \
            blob KVREF, \
            doc JSONREF\
        )";
        let stmt = parse_sql(sql).unwrap();
        let Statement::CreateTable(ct) = stmt else { panic!("expected CreateTable") };
        assert_eq!(ct.name, "t");
        assert_eq!(ct.columns.len(), 8);

        assert_eq!(ct.columns[0].name, "id");
        assert_eq!(ct.columns[0].ty, ColumnType::Integer);
        assert_eq!(
            ct.columns[0].constraints,
            vec![ColumnConstraint::PrimaryKey { autoincrement: true }]
        );

        assert_eq!(ct.columns[1].constraints, vec![ColumnConstraint::NotNull]);
        assert_eq!(ct.columns[2].constraints, vec![ColumnConstraint::Unique]);
        assert_eq!(
            ct.columns[3].constraints,
            vec![ColumnConstraint::Default(DefaultVal::Literal(Literal::Real(1.5)))]
        );
        assert_eq!(
            ct.columns[4].constraints,
            vec![ColumnConstraint::Default(DefaultVal::CurrentTimestamp)]
        );
        assert_eq!(
            ct.columns[5].constraints,
            vec![ColumnConstraint::References("parent".to_string())]
        );
        assert_eq!(ct.columns[6].ty, ColumnType::KvRef);
        assert_eq!(ct.columns[7].ty, ColumnType::JsonRef);
    }

    // 5. SELECT with LEFT JOIN, WHERE (AND/OR/NOT, parens, IN, LIKE, IS
    //    [NOT] NULL), ORDER BY, LIMIT/OFFSET all parse.
    #[test]
    fn test_select_full_shape() {
        let sql = "SELECT a.x, b.y AS yy FROM a LEFT OUTER JOIN b ON a.id = b.a_id \
                    WHERE (a.x = 1 AND a.y > 2) OR NOT a.z IS NULL \
                    ORDER BY a.x DESC, a.y LIMIT 10 OFFSET 5";
        let stmt = parse_sql(sql).unwrap();
        let Statement::Select(sel) = stmt else { panic!("expected Select") };
        assert_eq!(sel.items.len(), 2);
        assert_eq!(sel.from.name, "a");
        assert_eq!(sel.joins.len(), 1);
        assert_eq!(sel.joins[0].table.name, "b");
        assert!(sel.where_clause.is_some());
        assert_eq!(
            sel.order_by,
            vec![
                OrderItem { col: ColumnRef { qualifier: Some("a".into()), name: "x".into() }, desc: true },
                OrderItem { col: ColumnRef { qualifier: Some("a".into()), name: "y".into() }, desc: false },
            ]
        );
        assert_eq!(sel.limit, Some(Limit { limit: 10, offset: Some(5) }));
    }

    #[test]
    fn test_where_in_like_isnull_notnull() {
        let sql = "SELECT * FROM t WHERE x IN (1, 2, 3) AND y NOT IN (4) \
                    AND name LIKE 'a%' AND other NOT LIKE 'b%' \
                    AND a IS NULL AND b IS NOT NULL";
        assert!(parse_sql(sql).is_ok());
    }

    #[test]
    fn test_select_star_and_count_star() {
        let stmt = parse_sql("SELECT * FROM t").unwrap();
        let Statement::Select(sel) = stmt else { panic!("expected Select") };
        assert_eq!(sel.items, vec![SelectItem::Star]);

        let stmt = parse_sql("SELECT COUNT(*) FROM t").unwrap();
        let Statement::Select(sel) = stmt else { panic!("expected Select") };
        assert_eq!(sel.items, vec![SelectItem::CountStar]);

        assert!(matches!(
            parse_sql("SELECT COUNT(x) FROM t"),
            Err(RelStoreError::Syntax { .. })
        ));
    }

    // 6a. Type aliases resolve to canonical ColumnType; VARCHAR length ignored.
    #[test]
    fn test_type_aliases_and_varchar_length() {
        let sql = "CREATE TABLE t (\
            a INT PRIMARY KEY, b BIGINT, c SMALLINT, d FLOAT, e DOUBLE, \
            f VARCHAR(255), g CHAR(10), h BOOL, i DATETIME\
        )";
        let stmt = parse_sql(sql).unwrap();
        let Statement::CreateTable(ct) = stmt else { panic!("expected CreateTable") };
        let types: Vec<ColumnType> = ct.columns.iter().map(|c| c.ty).collect();
        assert_eq!(
            types,
            vec![
                ColumnType::Integer,
                ColumnType::Integer,
                ColumnType::Integer,
                ColumnType::Real,
                ColumnType::Real,
                ColumnType::Text,
                ColumnType::Text,
                ColumnType::Boolean,
                ColumnType::Timestamp,
            ]
        );
    }

    // 6b. Negative integer/real literals, incl. i64::MIN, parse correctly
    //     wherever a literal is accepted (here: DEFAULT).
    #[test]
    fn test_negative_literals_incl_i64_min() {
        let sql = format!("CREATE TABLE t (a INTEGER PRIMARY KEY, b INTEGER DEFAULT {})", i64::MIN);
        let stmt = parse_sql(&sql).unwrap();
        let Statement::CreateTable(ct) = stmt else { panic!("expected CreateTable") };
        assert_eq!(
            ct.columns[1].constraints,
            vec![ColumnConstraint::Default(DefaultVal::Literal(Literal::Integer(i64::MIN)))]
        );

        let stmt = parse_sql("CREATE TABLE t (a INTEGER PRIMARY KEY, b REAL DEFAULT -3.5)").unwrap();
        let Statement::CreateTable(ct) = stmt else { panic!("expected CreateTable") };
        assert_eq!(
            ct.columns[1].constraints,
            vec![ColumnConstraint::Default(DefaultVal::Literal(Literal::Real(-3.5)))]
        );
    }

    // 7. Syntax errors report position + expected/found.
    #[test]
    fn test_syntax_error_reports_position() {
        let err = parse_sql("CREATE TABLE (a INTEGER)").unwrap_err();
        assert!(matches!(err, RelStoreError::Syntax { .. }), "got: {err}");

        let err = parse_sql("SELECT * FROM").unwrap_err();
        assert!(matches!(err, RelStoreError::Syntax { .. }), "got: {err}");

        // Position should point at "FROM" itself (byte offset 7 in "CREATE ").
        let err = parse_sql("CREATE FROM t").unwrap_err();
        if let RelStoreError::Syntax { pos, .. } = err {
            assert_eq!(pos, 7);
        } else {
            panic!("expected Syntax, got {err}");
        }
    }

    // NULL is syntactically a valid literal everywhere `literal` is accepted,
    // including as a comparison operand (rejected later by the NULL-bind
    // guard in binder.rs, not here).
    #[test]
    fn test_null_parses_as_literal_in_comparison() {
        assert!(parse_sql("SELECT * FROM t WHERE x = NULL").is_ok());
        assert!(parse_sql("SELECT * FROM t WHERE x IS NULL").is_ok());
        assert!(parse_sql("SELECT * FROM t WHERE x IS NOT NULL").is_ok());
        assert!(parse_sql("UPDATE t SET c = NULL").is_ok());
        assert!(parse_sql("INSERT INTO t VALUES (NULL, 1)").is_ok());
    }

    #[test]
    fn test_alter_table_actions() {
        let Statement::AlterTable(at) = parse_sql("ALTER TABLE t ADD COLUMN x INTEGER").unwrap() else {
            panic!("expected AlterTable")
        };
        assert!(matches!(at.action, AlterAction::AddColumn(_)));

        let Statement::AlterTable(at) = parse_sql("ALTER TABLE t DROP COLUMN x").unwrap() else {
            panic!("expected AlterTable")
        };
        assert_eq!(at.action, AlterAction::DropColumn("x".to_string()));

        let Statement::AlterTable(at) = parse_sql("ALTER TABLE t RENAME COLUMN x TO y").unwrap() else {
            panic!("expected AlterTable")
        };
        assert_eq!(
            at.action,
            AlterAction::RenameColumn { from: "x".to_string(), to: "y".to_string() }
        );

        let Statement::AlterTable(at) = parse_sql("ALTER TABLE t RENAME TO u").unwrap() else {
            panic!("expected AlterTable")
        };
        assert_eq!(at.action, AlterAction::RenameTable("u".to_string()));
    }

    #[test]
    fn test_create_and_drop_index() {
        let Statement::CreateIndex(ci) = parse_sql("CREATE INDEX idx1 ON t (col)").unwrap() else {
            panic!("expected CreateIndex")
        };
        assert!(!ci.unique);
        assert_eq!((ci.name.as_str(), ci.table.as_str(), ci.column.as_str()), ("idx1", "t", "col"));

        let Statement::CreateIndex(ci) = parse_sql("CREATE UNIQUE INDEX idx2 ON t (col)").unwrap() else {
            panic!("expected CreateIndex")
        };
        assert!(ci.unique);

        let Statement::DropIndex(di) = parse_sql("DROP INDEX idx1").unwrap() else {
            panic!("expected DropIndex")
        };
        assert_eq!(di.name, "idx1");
    }

    #[test]
    fn test_insert_update_delete_create_view_drop_view_parse() {
        assert!(parse_sql("INSERT INTO t VALUES (1, 'a')").is_ok());
        assert!(parse_sql("INSERT INTO t (a, b) VALUES (1, 'a'), (2, 'b')").is_ok());
        assert!(parse_sql("INSERT INTO t VALUES (?, ?)").is_ok());
        assert!(parse_sql("UPDATE t SET a = 1, b = ? WHERE id = 1").is_ok());
        assert!(parse_sql("DELETE FROM t WHERE id = 1").is_ok());
        assert!(parse_sql("CREATE VIEW v AS SELECT * FROM t").is_ok());
        assert!(parse_sql("DROP VIEW v").is_ok());
    }

    #[test]
    fn test_param_positions_left_to_right_across_statement() {
        let Statement::Insert(ins) =
            parse_sql("INSERT INTO t (a, b, c) VALUES (?, 1, ?)").unwrap()
        else {
            panic!("expected Insert")
        };
        assert_eq!(ins.rows[0][0], Operand::Param(0));
        assert_eq!(ins.rows[0][2], Operand::Param(1));
    }

    #[test]
    fn test_statement_class() {
        assert_eq!(parse_sql("SELECT * FROM t").unwrap().class(), StatementClass::Read);
        assert_eq!(parse_sql("INSERT INTO t VALUES (1)").unwrap().class(), StatementClass::Write);
        assert_eq!(parse_sql("UPDATE t SET a = 1").unwrap().class(), StatementClass::Write);
        assert_eq!(parse_sql("DELETE FROM t").unwrap().class(), StatementClass::Write);
        assert_eq!(
            parse_sql("CREATE TABLE t (a INTEGER PRIMARY KEY)").unwrap().class(),
            StatementClass::Ddl
        );
        assert_eq!(parse_sql("DROP TABLE t").unwrap().class(), StatementClass::Ddl);
        assert_eq!(parse_sql("CREATE VIEW v AS SELECT * FROM t").unwrap().class(), StatementClass::Ddl);
    }

    // Depth guard (004-F1): pathological nesting yields a clean Syntax error
    // instead of recursing until the stack overflows and the process aborts.
    #[test]
    fn test_deeply_nested_parens_rejected_not_overflow() {
        let sql = format!("SELECT * FROM t WHERE {}x IS NULL{}", "(".repeat(200), ")".repeat(200));
        match parse_sql(&sql).unwrap_err() {
            RelStoreError::Syntax { msg, .. } => assert!(msg.contains("nesting too deep"), "got: {msg}"),
            other => panic!("expected Syntax, got: {other}"),
        }
    }

    #[test]
    fn test_deeply_nested_not_rejected_not_overflow() {
        let sql = format!("SELECT * FROM t WHERE {}x IS NULL", "NOT ".repeat(200));
        match parse_sql(&sql).unwrap_err() {
            RelStoreError::Syntax { msg, .. } => assert!(msg.contains("nesting too deep"), "got: {msg}"),
            other => panic!("expected Syntax, got: {other}"),
        }
    }

    // A legitimately deep statement, comfortably under the cap, still parses.
    #[test]
    fn test_deep_but_bounded_expression_parses() {
        let sql = format!("SELECT * FROM t WHERE {}x IS NULL{}", "(".repeat(50), ")".repeat(50));
        assert!(parse_sql(&sql).is_ok());
    }
}
