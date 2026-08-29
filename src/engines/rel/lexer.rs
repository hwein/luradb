//! Hand-written tokenizer for LuraSQL (spec rel/004 §2).
//!
//! Operates on `sql`'s bytes: every structural token (keyword, identifier,
//! number, operator, punctuation, string delimiter) is ASCII, so byte-wise
//! scanning is safe even though string-literal *content* may be arbitrary
//! UTF-8 (the ASCII delimiter byte `'` never occurs inside a multi-byte
//! UTF-8 sequence — that's a UTF-8 encoding guarantee). Comments are not
//! part of v1 (KISS).

use super::error::RelStoreError;

// ── Keywords ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    Create,
    Table,
    Alter,
    Drop,
    Add,
    Column,
    Rename,
    To,
    Index,
    Unique,
    On,
    View,
    As,
    Insert,
    Into,
    Values,
    Update,
    Set,
    Delete,
    From,
    Select,
    Left,
    Outer,
    Join,
    Where,
    Order,
    By,
    Asc,
    Desc,
    Limit,
    Offset,
    And,
    Or,
    Not,
    In,
    Like,
    Is,
    Null,
    Primary,
    Key,
    Autoincrement,
    Default,
    References,
    Count,
    CurrentTimestamp,
    True,
    False,
    // Type names & aliases (concept 3.2) — resolved to `ColumnType` via
    // `ColumnType::from_sql_name(kw.as_str())` in the parser, not re-mapped here.
    Integer,
    Int,
    Bigint,
    Smallint,
    Real,
    Float,
    Double,
    Text,
    Varchar,
    Char,
    Boolean,
    Bool,
    Timestamp,
    Datetime,
    Kvref,
    Jsonref,
}

impl Keyword {
    /// Case-insensitive keyword lookup; `word` must already be lowercase.
    fn from_lowercase(word: &str) -> Option<Keyword> {
        use Keyword::*;
        Some(match word {
            "create" => Create,
            "table" => Table,
            "alter" => Alter,
            "drop" => Drop,
            "add" => Add,
            "column" => Column,
            "rename" => Rename,
            "to" => To,
            "index" => Index,
            "unique" => Unique,
            "on" => On,
            "view" => View,
            "as" => As,
            "insert" => Insert,
            "into" => Into,
            "values" => Values,
            "update" => Update,
            "set" => Set,
            "delete" => Delete,
            "from" => From,
            "select" => Select,
            "left" => Left,
            "outer" => Outer,
            "join" => Join,
            "where" => Where,
            "order" => Order,
            "by" => By,
            "asc" => Asc,
            "desc" => Desc,
            "limit" => Limit,
            "offset" => Offset,
            "and" => And,
            "or" => Or,
            "not" => Not,
            "in" => In,
            "like" => Like,
            "is" => Is,
            "null" => Null,
            "primary" => Primary,
            "key" => Key,
            "autoincrement" => Autoincrement,
            "default" => Default,
            "references" => References,
            "count" => Count,
            "current_timestamp" => CurrentTimestamp,
            "true" => True,
            "false" => False,
            "integer" => Integer,
            "int" => Int,
            "bigint" => Bigint,
            "smallint" => Smallint,
            "real" => Real,
            "float" => Float,
            "double" => Double,
            "text" => Text,
            "varchar" => Varchar,
            "char" => Char,
            "boolean" => Boolean,
            "bool" => Bool,
            "timestamp" => Timestamp,
            "datetime" => Datetime,
            "kvref" => Kvref,
            "jsonref" => Jsonref,
            _ => return None,
        })
    }

    /// Canonical uppercase spelling — used for syntax-error messages and to
    /// delegate type-name resolution to `ColumnType::from_sql_name` (rel/003)
    /// so the alias table lives in exactly one place.
    pub fn as_str(&self) -> &'static str {
        use Keyword::*;
        match self {
            Create => "CREATE",
            Table => "TABLE",
            Alter => "ALTER",
            Drop => "DROP",
            Add => "ADD",
            Column => "COLUMN",
            Rename => "RENAME",
            To => "TO",
            Index => "INDEX",
            Unique => "UNIQUE",
            On => "ON",
            View => "VIEW",
            As => "AS",
            Insert => "INSERT",
            Into => "INTO",
            Values => "VALUES",
            Update => "UPDATE",
            Set => "SET",
            Delete => "DELETE",
            From => "FROM",
            Select => "SELECT",
            Left => "LEFT",
            Outer => "OUTER",
            Join => "JOIN",
            Where => "WHERE",
            Order => "ORDER",
            By => "BY",
            Asc => "ASC",
            Desc => "DESC",
            Limit => "LIMIT",
            Offset => "OFFSET",
            And => "AND",
            Or => "OR",
            Not => "NOT",
            In => "IN",
            Like => "LIKE",
            Is => "IS",
            Null => "NULL",
            Primary => "PRIMARY",
            Key => "KEY",
            Autoincrement => "AUTOINCREMENT",
            Default => "DEFAULT",
            References => "REFERENCES",
            Count => "COUNT",
            CurrentTimestamp => "CURRENT_TIMESTAMP",
            True => "TRUE",
            False => "FALSE",
            Integer => "INTEGER",
            Int => "INT",
            Bigint => "BIGINT",
            Smallint => "SMALLINT",
            Real => "REAL",
            Float => "FLOAT",
            Double => "DOUBLE",
            Text => "TEXT",
            Varchar => "VARCHAR",
            Char => "CHAR",
            Boolean => "BOOLEAN",
            Bool => "BOOL",
            Timestamp => "TIMESTAMP",
            Datetime => "DATETIME",
            Kvref => "KVREF",
            Jsonref => "JSONREF",
        }
    }

    /// True for tokens that can start a `type_name` production (grammar §4).
    pub fn is_type_name(&self) -> bool {
        use Keyword::*;
        matches!(
            self,
            Integer
                | Int
                | Bigint
                | Smallint
                | Real
                | Float
                | Double
                | Text
                | Varchar
                | Char
                | Boolean
                | Bool
                | Timestamp
                | Datetime
                | Kvref
                | Jsonref
        )
    }
}

// ── Tokens ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Keyword(Keyword),
    Ident(String),
    Integer(i64),
    Real(f64),
    Str(String),
    /// 0-based, left-to-right position among all `?` placeholders (assigned
    /// here so numbering is correct regardless of how the parser later
    /// structures the AST — even inside a nested `CREATE VIEW ... AS SELECT`).
    Param(usize),
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    LParen,
    RParen,
    Comma,
    Dot,
    Semicolon,
    Star,
}

impl Token {
    /// Human-readable label for syntax-error messages.
    pub fn describe(&self) -> String {
        match self {
            Token::Keyword(k) => k.as_str().to_string(),
            Token::Ident(s) => format!("identifier '{s}'"),
            Token::Integer(i) => format!("integer {i}"),
            Token::Real(f) => format!("real {f}"),
            Token::Str(s) => format!("string '{s}'"),
            Token::Param(_) => "'?'".to_string(),
            Token::Eq => "'='".to_string(),
            Token::NotEq => "'!='".to_string(),
            Token::Lt => "'<'".to_string(),
            Token::LtEq => "'<='".to_string(),
            Token::Gt => "'>'".to_string(),
            Token::GtEq => "'>='".to_string(),
            Token::LParen => "'('".to_string(),
            Token::RParen => "')'".to_string(),
            Token::Comma => "','".to_string(),
            Token::Dot => "'.'".to_string(),
            Token::Semicolon => "';'".to_string(),
            Token::Star => "'*'".to_string(),
        }
    }
}

fn syntax_err(pos: usize, msg: impl Into<String>) -> RelStoreError {
    RelStoreError::Syntax {
        pos,
        msg: msg.into(),
    }
}

// ── Tokenizer ────────────────────────────────────────────────────────────────

/// Lexes `sql` into `(Token, byte_pos)` pairs. `max_statement_len` is checked
/// first — over the limit, no token is produced at all (spec rel/004 §1).
pub fn tokenize(
    sql: &str,
    max_statement_len: usize,
) -> Result<Vec<(Token, usize)>, RelStoreError> {
    if sql.len() > max_statement_len {
        return Err(RelStoreError::StatementTooLong {
            len: sql.len(),
            max: max_statement_len,
        });
    }

    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut pos = 0usize;
    let mut param_idx = 0usize;
    let mut tokens = Vec::new();

    while pos < len {
        let b = bytes[pos];
        if b.is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        let start = pos;
        let token = match b {
            b'(' => {
                pos += 1;
                Token::LParen
            }
            b')' => {
                pos += 1;
                Token::RParen
            }
            b',' => {
                pos += 1;
                Token::Comma
            }
            b';' => {
                pos += 1;
                Token::Semicolon
            }
            b'*' => {
                pos += 1;
                Token::Star
            }
            b'=' => {
                pos += 1;
                Token::Eq
            }
            b'!' | b'<' | b'>' => scan_comparison_op(bytes, &mut pos)?,
            b'?' => {
                pos += 1;
                let t = Token::Param(param_idx);
                param_idx += 1;
                t
            }
            b'\'' => scan_string(sql, &mut pos)?,
            b'"' | b'`' => {
                return Err(syntax_err(pos, "quoted identifiers are not supported"));
            }
            // A leading '-' is part of a numeric literal only when immediately
            // followed by a digit — there are no arithmetic expressions, so
            // this cannot be ambiguous with anything else (spec rel/004 §2).
            b'-' if bytes.get(pos + 1).copied().is_some_and(|c| c.is_ascii_digit()) => {
                scan_number(sql, &mut pos)?
            }
            // A bare '.' (not part of a number) is qualified-name punctuation
            // (`table.column`) — handled by the caller, one byte here.
            b'.' => {
                pos += 1;
                Token::Dot
            }
            _ if b.is_ascii_digit() => scan_number(sql, &mut pos)?,
            _ if b.is_ascii_alphabetic() || b == b'_' => scan_ident_or_keyword(sql, &mut pos),
            _ => {
                return Err(syntax_err(pos, format!("unexpected character '{}'", b as char)));
            }
        };
        tokens.push((token, start));
    }
    Ok(tokens)
}

/// Counts `?` placeholders in an already-lexed token stream — the expected
/// bind-parameter count for the binder's parameter-count guard (spec §5).
pub fn count_params(tokens: &[(Token, usize)]) -> usize {
    tokens.iter().filter(|(t, _)| matches!(t, Token::Param(_))).count()
}

/// Scans the multi-byte lookahead for `!`/`<`/`>` (`!=`, `<=`, `<>`, `>=`) —
/// `*pos` starts on the operator's first byte. Same pattern as `scan_string`/
/// `scan_number`/`scan_ident_or_keyword`.
fn scan_comparison_op(bytes: &[u8], pos: &mut usize) -> Result<Token, RelStoreError> {
    let token = match bytes[*pos] {
        b'!' => {
            if bytes.get(*pos + 1).copied() == Some(b'=') {
                *pos += 2;
                Token::NotEq
            } else {
                return Err(syntax_err(*pos, "expected '=' after '!'"));
            }
        }
        b'<' => match bytes.get(*pos + 1).copied() {
            Some(b'=') => {
                *pos += 2;
                Token::LtEq
            }
            Some(b'>') => {
                *pos += 2;
                Token::NotEq
            }
            _ => {
                *pos += 1;
                Token::Lt
            }
        },
        b'>' => match bytes.get(*pos + 1).copied() {
            Some(b'=') => {
                *pos += 2;
                Token::GtEq
            }
            _ => {
                *pos += 1;
                Token::Gt
            }
        },
        _ => unreachable!("scan_comparison_op is only called for '!'/'<'/'>'"),
    };
    Ok(token)
}

/// Scans `'...'` with `''` as an escaped literal apostrophe. `*pos` starts on
/// the opening quote and ends just past the closing one.
fn scan_string(sql: &str, pos: &mut usize) -> Result<Token, RelStoreError> {
    let start = *pos;
    let mut i = start + 1;
    let mut out = String::new();
    loop {
        match sql.as_bytes().get(i) {
            None => return Err(syntax_err(start, "unterminated string literal")),
            Some(b'\'') => {
                if sql.as_bytes().get(i + 1).copied() == Some(b'\'') {
                    out.push('\'');
                    i += 2;
                } else {
                    *pos = i + 1;
                    return Ok(Token::Str(out));
                }
            }
            Some(_) => {
                let ch = sql[i..].chars().next().expect("byte present implies a char");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
}

/// Index just past the last consecutive ASCII digit starting at `i` (`i`
/// itself if `bytes[i]` is not a digit) — replaces three identical
/// while-loops in `scan_number`.
fn scan_digits(bytes: &[u8], i: usize) -> usize {
    let mut i = i;
    while bytes.get(i).copied().is_some_and(|b| b.is_ascii_digit()) {
        i += 1;
    }
    i
}

/// Scans a `[eE][+-]?[0-9]+` exponent starting at `i`. `None` = no `e`/`E` at
/// `i`, or no digit after an optional sign — the caller then leaves the scan
/// position untouched (no exponent consumed, not even the `e`/sign).
fn scan_exponent(bytes: &[u8], i: usize) -> Option<usize> {
    if !matches!(bytes.get(i).copied(), Some(b'e') | Some(b'E')) {
        return None;
    }
    let mut j = i + 1;
    if matches!(bytes.get(j).copied(), Some(b'+') | Some(b'-')) {
        j += 1;
    }
    if !bytes.get(j).copied().is_some_and(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(scan_digits(bytes, j))
}

/// Scans an integer or real literal, including an optional leading `-` and
/// exponent. `i64::MIN` parses correctly because the sign stays attached to
/// the digit string through a single `str::parse` call (never negate-after-parse).
fn scan_number(sql: &str, pos: &mut usize) -> Result<Token, RelStoreError> {
    let bytes = sql.as_bytes();
    let start = *pos;
    let mut i = start;
    if bytes[i] == b'-' {
        i += 1;
    }
    i = scan_digits(bytes, i);

    let mut is_real = false;
    if bytes.get(i).copied() == Some(b'.')
        && bytes.get(i + 1).copied().is_some_and(|b| b.is_ascii_digit())
    {
        is_real = true;
        i = scan_digits(bytes, i + 1);
    }
    if let Some(j) = scan_exponent(bytes, i) {
        is_real = true;
        i = j;
    }
    let text = &sql[start..i];
    *pos = i;
    if is_real {
        // `f64::parse` saturates an over-range exponent to ±Infinity instead of
        // erroring; a non-finite real must never reach the catalog (it would
        // serialize to JSON `null` and silently drop the row on recovery).
        let f = text
            .parse::<f64>()
            .map_err(|e| syntax_err(start, format!("invalid real literal '{text}': {e}")))?;
        if !f.is_finite() {
            return Err(syntax_err(start, format!("real literal '{text}' is out of range (non-finite)")));
        }
        Ok(Token::Real(f))
    } else {
        text.parse::<i64>()
            .map(Token::Integer)
            .map_err(|e| syntax_err(start, format!("invalid integer literal '{text}': {e}")))
    }
}

/// Scans `[a-zA-Z_][a-zA-Z0-9_]*`, lowercases it, and resolves it against the
/// keyword table; anything else becomes an identifier (concept 3.5).
fn scan_ident_or_keyword(sql: &str, pos: &mut usize) -> Token {
    let bytes = sql.as_bytes();
    let start = *pos;
    let mut i = start;
    while bytes
        .get(i)
        .copied()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        i += 1;
    }
    let word = sql[start..i].to_ascii_lowercase();
    *pos = i;
    match Keyword::from_lowercase(&word) {
        Some(kw) => Token::Keyword(kw),
        None => Token::Ident(word),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(sql: &str) -> Vec<Token> {
        tokenize(sql, 64 * 1024)
            .unwrap()
            .into_iter()
            .map(|(t, _)| t)
            .collect()
    }

    // 1a. Keywords recognized case-insensitively.
    #[test]
    fn test_keywords_case_insensitive() {
        assert_eq!(toks("select"), vec![Token::Keyword(Keyword::Select)]);
        assert_eq!(toks("SELECT"), vec![Token::Keyword(Keyword::Select)]);
        assert_eq!(toks("SeLeCt"), vec![Token::Keyword(Keyword::Select)]);
        assert_eq!(
            toks("CREATE TABLE"),
            vec![Token::Keyword(Keyword::Create), Token::Keyword(Keyword::Table)]
        );
    }

    // 1b. Identifiers vs keywords; identifiers normalize to lowercase.
    #[test]
    fn test_identifier_vs_keyword() {
        assert_eq!(toks("Users"), vec![Token::Ident("users".to_string())]);
        assert_eq!(toks("_x1"), vec![Token::Ident("_x1".to_string())]);
    }

    // 1c. String literal with '' escape.
    #[test]
    fn test_string_escape() {
        assert_eq!(toks("'hello'"), vec![Token::Str("hello".to_string())]);
        assert_eq!(toks("'it''s'"), vec![Token::Str("it's".to_string())]);
        assert_eq!(toks("''"), vec![Token::Str(String::new())]);
    }

    #[test]
    fn test_unterminated_string_is_syntax_error() {
        let err = tokenize("'abc", 64 * 1024).unwrap_err();
        assert!(matches!(err, RelStoreError::Syntax { pos: 0, .. }), "got: {err}");
    }

    // 1d. Numbers: integer, real, exponent, negative incl. i64::MIN.
    #[test]
    fn test_numbers() {
        assert_eq!(toks("42"), vec![Token::Integer(42)]);
        assert_eq!(toks("3.25"), vec![Token::Real(3.25)]);
        assert_eq!(toks("1e3"), vec![Token::Real(1e3)]);
        assert_eq!(toks("1.5e-2"), vec![Token::Real(1.5e-2)]);
        assert_eq!(toks("-7"), vec![Token::Integer(-7)]);
        assert_eq!(toks("-7.5"), vec![Token::Real(-7.5)]);
        assert_eq!(toks("-9223372036854775808"), vec![Token::Integer(i64::MIN)]);
        assert_eq!(toks(&i64::MAX.to_string()), vec![Token::Integer(i64::MAX)]);
    }

    // 1e. `?` parameters get a 0-based, left-to-right position.
    #[test]
    fn test_param_positions() {
        assert_eq!(
            toks("? ?"),
            vec![Token::Param(0), Token::Param(1)]
        );
    }

    // 1f. Operators, including `<>` as a `!=` synonym.
    #[test]
    fn test_operators() {
        assert_eq!(
            toks("= != <> < <= > >="),
            vec![
                Token::Eq,
                Token::NotEq,
                Token::NotEq,
                Token::Lt,
                Token::LtEq,
                Token::Gt,
                Token::GtEq,
            ]
        );
    }

    #[test]
    fn test_punctuation_and_qualified_name() {
        assert_eq!(
            toks("t.col, (x)"),
            vec![
                Token::Ident("t".to_string()),
                Token::Dot,
                Token::Ident("col".to_string()),
                Token::Comma,
                Token::LParen,
                Token::Ident("x".to_string()),
                Token::RParen,
            ]
        );
    }

    #[test]
    fn test_quoted_identifier_rejected() {
        for sql in ["\"col\"", "`col`"] {
            let err = tokenize(sql, 64 * 1024).unwrap_err();
            assert!(matches!(err, RelStoreError::Syntax { .. }), "'{sql}' got: {err}");
        }
    }

    // 2. max_statement_len guard fires before any token is produced.
    #[test]
    fn test_statement_too_long_guard() {
        let sql = "x".repeat(100);
        let err = tokenize(&sql, 64).unwrap_err();
        assert!(
            matches!(err, RelStoreError::StatementTooLong { len: 100, max: 64 }),
            "got: {err}"
        );
    }

    #[test]
    fn test_statement_at_exact_limit_ok() {
        let sql = "x".repeat(64);
        assert!(tokenize(&sql, 64).is_ok());
    }

    // ── Prep work (spec quality/008): tokenize/scan_number error paths ─────────

    // A lone '!' (no following '=') is a syntax error, not silently consumed.
    #[test]
    fn test_bang_without_eq_is_syntax_error() {
        let err = tokenize("!", 64 * 1024).unwrap_err();
        match &err {
            RelStoreError::Syntax { pos, msg } => {
                assert_eq!(*pos, 0);
                assert!(msg.contains("expected '=' after '!'"), "got: {msg}");
            }
            other => panic!("expected Syntax, got: {other}"),
        }
    }

    // A byte matching none of the token arms (not whitespace/digit/alpha/
    // punctuation) hits the catch-all "unexpected character" error.
    #[test]
    fn test_unexpected_character_is_syntax_error() {
        let err = tokenize("@", 64 * 1024).unwrap_err();
        match &err {
            RelStoreError::Syntax { pos, msg } => {
                assert_eq!(*pos, 0);
                assert!(msg.contains("unexpected character"), "got: {msg}");
            }
            other => panic!("expected Syntax, got: {other}"),
        }
    }

    // scan_number: a digit string outside i64's range is a syntax error
    // (both above i64::MAX and below i64::MIN).
    #[test]
    fn test_scan_number_overflow_is_syntax_error() {
        let err = tokenize("9223372036854775808", 64 * 1024).unwrap_err(); // i64::MAX + 1
        match &err {
            RelStoreError::Syntax { pos, msg } => {
                assert_eq!(*pos, 0);
                assert!(msg.contains("invalid integer literal"), "got: {msg}");
            }
            other => panic!("expected Syntax, got: {other}"),
        }

        let err = tokenize("-9223372036854775809", 64 * 1024).unwrap_err(); // i64::MIN - 1
        assert!(matches!(err, RelStoreError::Syntax { pos: 0, .. }), "got: {err}");
    }

    // scan_number: a trailing 'e' with no exponent digits does not extend the
    // number — it stays a bare integer, and the 'e' re-lexes as its own token.
    #[test]
    fn test_scan_number_incomplete_exponent_stays_integer_plus_ident() {
        assert_eq!(toks("1e"), vec![Token::Integer(1), Token::Ident("e".to_string())]);
    }

    // scan_number: a trailing '.' with no fraction digit does not start a
    // decimal part — it stays a bare integer, and the '.' is its own token.
    #[test]
    fn test_scan_number_dot_without_fraction_stays_integer_plus_dot() {
        assert_eq!(toks("1."), vec![Token::Integer(1), Token::Dot]);
    }

    // scan_number (004-F2): a real literal whose exponent overflows f64 to a
    // non-finite value is a syntax error, not a silent `Token::Real(inf)` that
    // would later corrupt the catalog.
    #[test]
    fn test_scan_number_non_finite_real_is_syntax_error() {
        for sql in ["1e309", "-1e309", "1e400"] {
            match tokenize(sql, 64 * 1024).unwrap_err() {
                RelStoreError::Syntax { pos, msg } => {
                    assert_eq!(pos, 0, "'{sql}'");
                    assert!(msg.contains("non-finite"), "'{sql}' got: {msg}");
                }
                other => panic!("expected Syntax for '{sql}', got: {other}"),
            }
        }
        // A finite real still lexes fine.
        assert_eq!(toks("1e10"), vec![Token::Real(1e10)]);
        assert_eq!(toks("1.5"), vec![Token::Real(1.5)]);
    }
}
