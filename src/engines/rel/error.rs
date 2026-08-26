//! Error types for the relational store.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelStoreError {
    #[error("domain '{0}' not found")]
    DomainNotFound(String),
    #[error("domain '{0}' is being deleted")]
    DomainDeleting(String),
    #[error("domain '{0}' already exists")]
    DomainAlreadyExists(String),
    #[error("invalid domain name: {0}")]
    InvalidDomainName(String),

    // ── Catalog (spec rel/003) ──────────────────────────────────────────────
    /// Table/view/column/index name violates the identifier rules (→ 400).
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    /// Name collision against an existing table or view (shared namespace, → 409),
    /// for statement classes that are not themselves table-specific (`CREATE
    /// VIEW`). `CREATE TABLE`/`RENAME TO` use the more specific `TableAlreadyExists`.
    #[error("object '{name}' already exists in domain '{domain}'")]
    ObjectAlreadyExists { domain: String, name: String },
    /// `get`/generic `drop` on a missing catalog object (→ 404).
    #[error("object '{name}' not found in domain '{domain}'")]
    ObjectNotFound { domain: String, name: String },
    /// Schema constraint violation: PK/AUTOINCREMENT/default/column rules (→ 400).
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    /// The per-domain u32 id counter is exhausted (practically unreachable).
    #[error("catalog id space exhausted for domain '{0}'")]
    IdSpaceExhausted(String),

    // ── SQL frontend & DDL (spec rel/004) ───────────────────────────────────
    /// `sql.len()` exceeds `max_statement_len` — checked before lexing (→ 400).
    #[error("statement length {len} exceeds maximum of {max} bytes")]
    StatementTooLong { len: usize, max: usize },
    /// Empty or whitespace-only input (→ 400).
    #[error("empty statement")]
    EmptyStatement,
    /// More than one statement in a single request (→ 400).
    #[error("multiple statements in a single request are not allowed")]
    MultipleStatements,
    /// Lexer/parser failure with a byte position (→ 400).
    #[error("syntax error at position {pos}: {msg}")]
    Syntax { pos: usize, msg: String },
    /// `NULL` used as a comparison operand instead of `IS [NOT] NULL` (→ 400).
    #[error("NULL used in a comparison: {hint}")]
    NullComparison { hint: String },
    /// Bound-parameter count does not match the number of `?` placeholders (→ 400).
    #[error("expected {expected} parameters, got {actual}")]
    ParameterCountMismatch { expected: usize, actual: usize },
    /// `REFERENCES`/`DEFAULT` type incompatibility (→ 400).
    #[error("type mismatch in {context}: expected {expected}, got {actual}")]
    TypeMismatch {
        context: String,
        expected: String,
        actual: String,
    },
    /// A configured catalog limit was exceeded (→ 400).
    #[error("limit exceeded: {which} (max {max})")]
    LimitExceeded { which: String, max: usize },
    /// `ALTER`/`DROP`/`REFERENCES`/`CREATE INDEX` target table missing (→ 404).
    #[error("table '{name}' not found in domain '{domain}'")]
    TableNotFound { domain: String, name: String },
    /// `DROP`/`RENAME COLUMN`/`CREATE INDEX` target column missing (→ 404).
    #[error("column '{name}' not found on table '{table}'")]
    ColumnNotFound { table: String, name: String },
    /// `DROP INDEX` on an unknown index name (→ 404).
    #[error("index '{name}' not found in domain '{domain}'")]
    IndexNotFound { domain: String, name: String },
    /// `CREATE TABLE`/`RENAME TO` on a name already used by a table or view (→ 409).
    #[error("table '{name}' already exists in domain '{domain}'")]
    TableAlreadyExists { domain: String, name: String },
    /// `ADD COLUMN`/`RENAME COLUMN` on a name already used on the table (→ 409).
    #[error("column '{name}' already exists on table '{table}'")]
    ColumnAlreadyExists { table: String, name: String },
    /// `CREATE INDEX` on a name already used in the domain (→ 409).
    #[error("index '{name}' already exists in domain '{domain}'")]
    IndexAlreadyExists { domain: String, name: String },
    /// `DROP COLUMN` on the primary key or an indexed column (→ 409).
    #[error("column '{column}' of table '{table}' is the primary key or is indexed")]
    ColumnIndexedOrPrimaryKey { table: String, column: String },
    // ── DML write path (spec rel/005) ───────────────────────────────────────
    /// DML/SELECT target is a view, not a table (→ 400).
    #[error("'{name}' is a view and is not writable")]
    NotWritable { name: String },
    /// NULL in a NOT-NULL column on INSERT/UPDATE (→ 400).
    #[error("column '{column}' of table '{table}' must not be NULL")]
    NotNull { table: String, column: String },
    /// `UPDATE` targeting the primary-key column (→ 400).
    #[error("primary key '{column}' of table '{table}' is immutable")]
    PrimaryKeyImmutable { table: String, column: String },
    /// TEXT/KVREF/JSONREF value exceeds `max_text_len` (→ 400).
    #[error("text length {len} exceeds maximum of {max} bytes")]
    TextTooLong { len: usize, max: usize },
    /// Encoded LuraRow exceeds `max_row_size` (→ 400).
    #[error("row size {size} exceeds maximum of {max} bytes")]
    RowTooLarge { size: usize, max: usize },
    /// A `ROW:`/`IDX:` key exceeds `max_key_length` (→ 400).
    #[error("key length {len} exceeds maximum of {max} bytes")]
    KeyTooLong { len: usize, max: usize },
    /// PK already exists, or a PK is duplicated within a multi-row INSERT (→ 409).
    #[error("duplicate primary key in table '{table}'")]
    DuplicateKey { table: String },
    /// Unique-index collision on INSERT/UPDATE/backfill (→ 409).
    #[error("unique constraint violated on index '{index}'")]
    UniqueViolation { index: String },
    /// A `REFERENCES` target PK does not exist (→ 409).
    #[error("REFERENCES target of column '{column}' is missing in table '{target}'")]
    LinkTargetMissing { column: String, target: String },
    /// AUTOINCREMENT sequence exhausted `i64::MAX` (→ 409, unreachable).
    #[error("AUTOINCREMENT sequence of table '{table}' is exhausted")]
    SequenceExhausted { table: String },

    // ── SELECT executor (spec rel/006) ──────────────────────────────────────
    /// In-memory ORDER BY sort buffer exceeded `max_sort_rows` (→ 400).
    #[error("sort buffer of {rows} rows exceeds maximum of {max}; narrow the result with WHERE/LIMIT or add a matching index")]
    SortBufferExceeded { rows: usize, max: usize },

    // ── LEFT JOIN (spec rel/007) ─────────────────────────────────────────────
    /// `select.joins.len()` (plus any already-consumed expand stages, rel/009
    /// interface prep) exceeds `max_join_depth` (→ 400).
    #[error("join depth {depth} exceeds the maximum of {max}")]
    JoinDepthExceeded { depth: usize, max: usize },
    /// The right ON-column is neither the PK nor indexed and
    /// `allow_unindexed_joins = false` (→ 400).
    #[error("join column '{table}.{column}' is neither the primary key nor indexed; {hint}")]
    UnindexedJoin { table: String, column: String, hint: String },
    /// Cumulative rows visited by `ScanFallback` probes (statement-wide) exceeded
    /// `max_sort_rows` (→ 400).
    #[error("unindexed join fallback scan visited {scanned} rows, exceeding the limit of {max}; add an index or narrow the result")]
    UnindexedJoinScanExceeded { scanned: usize, max: usize },
    /// An unqualified column reference resolves in more than one join binding (→ 400).
    #[error("column '{name}' is ambiguous across the tables in this query")]
    AmbiguousColumn { name: String },

    // ── Views (spec rel/008) ─────────────────────────────────────────────────
    /// DROP TABLE / DROP COLUMN / RENAME COLUMN / RENAME TO / DROP VIEW would
    /// invalidate a view that (transitively) references the changed object (→ 409).
    #[error("'{object}' is referenced by view(s) {views:?} and cannot be changed")]
    ViewDependencyConflict { object: String, views: Vec<String> },

    // ── REST I: domains & /sql (spec rel/009) ───────────────────────────────
    /// Per-domain request budget (§7) exhausted — checked before any
    /// execution I/O (→ 429, `Retry-After` set by `ApiError`).
    #[error("rate limit exceeded for domain '{domain}'")]
    RateLimited { domain: String },
    /// `expand` is malformed for this statement: non-empty on DML/DDL, names
    /// a column that isn't projected/unambiguous, or names a non-REFERENCES
    /// column (§5) (→ 400).
    #[error("invalid expand: {0}")]
    InvalidExpand(String),

    // ── Cross-engine links (spec rel/012) ───────────────────────────────────
    /// DML: the target KV/JSON engine is disabled, or the same-named target
    /// domain is missing/`Deleting`. DDL: a link column is declared but its
    /// target engine is disabled (`domain` = `None`). `engine ∈ {"kv","json"}` (→ 409).
    #[error("cross-engine {engine} target unavailable{}", domain.as_ref().map(|d| format!(" for domain '{d}'")).unwrap_or_default())]
    CrossEngineTargetUnavailable { engine: String, domain: Option<String> },
    /// DML: the target domain is active, but the linked key/document `target`
    /// does not exist in the `engine` (→ 409).
    #[error("cross-engine link target '{target}' of column '{column}' is missing in {engine}")]
    CrossEngineLinkMissing { column: String, engine: String, target: String },
    /// DML: the caller lacks read access to the same-named target domain —
    /// rejected before any existence lookup, so an unauthorized caller cannot
    /// distinguish an existing from a missing key (spec rel/016) (→ 403).
    #[error("cross-engine {engine} link forbidden: missing read access to the target domain")]
    CrossEngineForbidden { engine: String },

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    StorageError(#[from] anyhow::Error),
}
