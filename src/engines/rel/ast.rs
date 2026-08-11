//! AST for LuraSQL (spec rel/004, concept 004 ch. 4).
//!
//! The parser (`parser.rs`) builds these types via recursive descent; the
//! binder (`binder.rs`) translates the DDL subset into catalog inputs
//! (`super::catalog::{TableInput, ColumnInput}`). `AstColumnDef` is deliberately
//! not named `ColumnDef` — that name belongs to the catalog's own struct.

use super::types::ColumnType;

// ── Statement classification (concept 4.2; rel/011 auth) ───────────────────────

/// Coarse statement class for the two-stage auth enforcement rel/011 adds.
/// `Ddl` covers table/index/view DDL alike; every DDL statement parses, binds,
/// and executes downstream (view DDL included, since rel/008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementClass {
    Read,
    Write,
    Ddl,
}

// ── Top-level statement ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    CreateTable(CreateTable),
    AlterTable(AlterTable),
    DropTable(DropTable),
    CreateIndex(CreateIndex),
    DropIndex(DropIndex),
    CreateView(CreateView),
    DropView(DropView),
    Insert(Insert),
    Update(Update),
    Delete(Delete),
    Select(Select),
}

impl Statement {
    pub fn class(&self) -> StatementClass {
        match self {
            Statement::CreateTable(_)
            | Statement::AlterTable(_)
            | Statement::DropTable(_)
            | Statement::CreateIndex(_)
            | Statement::DropIndex(_)
            | Statement::CreateView(_)
            | Statement::DropView(_) => StatementClass::Ddl,
            Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_) => {
                StatementClass::Write
            }
            Statement::Select(_) => StatementClass::Read,
        }
    }
}

// ── DDL: tables & indexes ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct CreateTable {
    pub name: String,
    pub columns: Vec<AstColumnDef>,
}

/// One column in a `CREATE TABLE`/`ADD COLUMN`. Not `ColumnDef` — that name is
/// the catalog's own struct (rel/003); the binder translates this into a
/// `catalog::ColumnInput`.
#[derive(Debug, Clone, PartialEq)]
pub struct AstColumnDef {
    pub name: String,
    pub ty: ColumnType,
    pub constraints: Vec<ColumnConstraint>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ColumnConstraint {
    PrimaryKey { autoincrement: bool },
    NotNull,
    Unique,
    Default(DefaultVal),
    References(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DefaultVal {
    Literal(Literal),
    CurrentTimestamp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlterTable {
    pub table: String,
    pub action: AlterAction,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlterAction {
    AddColumn(AstColumnDef),
    DropColumn(String),
    RenameColumn { from: String, to: String },
    RenameTable(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DropTable {
    pub table: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateIndex {
    pub name: String,
    pub table: String,
    pub column: String,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DropIndex {
    pub name: String,
}

// ── DDL: views (parse + bind only in this spec; execution → rel/008) ───────────

#[derive(Debug, Clone, PartialEq)]
pub struct CreateView {
    pub name: String,
    pub select: Box<Select>,
    /// Byte offset in the original SQL text where the `SELECT` body begins
    /// (right after `AS`) — rel/008 slices the raw, unparsed view text from
    /// here to end-of-statement instead of re-serializing the AST.
    pub select_offset: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DropView {
    pub name: String,
}

// ── DML (parse + front-end checks only in this spec; execution → rel/005) ──────

#[derive(Debug, Clone, PartialEq)]
pub struct Insert {
    pub table: String,
    pub columns: Option<Vec<String>>,
    /// One entry per `VALUES(...)` row. `Operand` here is only ever
    /// `Literal`/`Param` — `value_expr` never produces `Operand::Column`.
    pub rows: Vec<Vec<Operand>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub column: String,
    pub value: Operand,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Update {
    pub table: String,
    pub assignments: Vec<Assignment>,
    pub where_clause: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Delete {
    pub table: String,
    pub where_clause: Option<Expr>,
}

// ── SELECT (parse + front-end checks only in this spec; execution → rel/006-007) ─

#[derive(Debug, Clone, PartialEq)]
pub struct Select {
    pub items: Vec<SelectItem>,
    pub from: TableRef,
    pub joins: Vec<Join>,
    pub where_clause: Option<Expr>,
    pub order_by: Vec<OrderItem>,
    pub limit: Option<Limit>,
}

/// A `select_list` is exclusively `*`, `COUNT(*)`, or a non-empty list of
/// `Column` items (grammar §4) — enforced by the parser, not by this type.
#[derive(Debug, Clone, PartialEq)]
pub enum SelectItem {
    Star,
    CountStar,
    Column { col: ColumnRef, alias: Option<String> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnRef {
    pub qualifier: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TableRef {
    pub name: String,
    pub alias: Option<String>,
}

/// `LEFT [OUTER] JOIN table ON left = right` — the only join shape in v1; the
/// `ON` operands are always plain column refs, never literals or params.
#[derive(Debug, Clone, PartialEq)]
pub struct Join {
    pub table: TableRef,
    pub left: ColumnRef,
    pub right: ColumnRef,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OrderItem {
    pub col: ColumnRef,
    pub desc: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Limit {
    pub limit: i64,
    pub offset: Option<i64>,
}

// ── Expressions (WHERE) ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Integer(i64),
    Real(f64),
    Text(String),
    Boolean(bool),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

/// RHS/LHS of a comparison. `Column` never appears in `value_expr` positions
/// (INSERT/UPDATE) — those slots only ever construct `Literal`/`Param`.
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Column(ColumnRef),
    Literal(Literal),
    Param(usize),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Compare {
        lhs: Operand,
        op: CompareOp,
        rhs: Operand,
    },
    /// `list` is literals only — the grammar does not allow `?` inside `IN (...)`.
    In {
        col: ColumnRef,
        negated: bool,
        list: Vec<Literal>,
    },
    Like {
        col: ColumnRef,
        negated: bool,
        pattern: String,
    },
    IsNull {
        col: ColumnRef,
        negated: bool,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Paren(Box<Expr>),
}
