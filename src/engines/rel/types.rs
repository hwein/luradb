//! Type system and order-preserving memcomparable encoding (spec rel/003).
//!
//! Five canonical value types plus the `KvRef`/`JsonRef` tags, the SQL alias
//! resolver, and `encode_sortable` — the encoder later specs build `ROW:`/
//! `IDX:` keys from (rel/005). Decoding is out of scope (not needed in v1).

use serde::{Deserialize, Serialize};

// ── ColumnType ─────────────────────────────────────────────────────────────────

/// The five canonical value types plus the two reference tags. `KvRef`/`JsonRef`
/// are physically TEXT; they are only registered as type tags here — validation
/// and resolution land in rel/012.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    Integer,
    Real,
    Text,
    Boolean,
    Timestamp,
    KvRef,
    JsonRef,
}

impl ColumnType {
    /// Physical storage type: `KvRef`/`JsonRef` collapse to `Text`, the rest map
    /// to themselves.
    pub fn physical_type(self) -> ColumnType {
        match self {
            ColumnType::KvRef | ColumnType::JsonRef => ColumnType::Text,
            other => other,
        }
    }

    /// Resolves a SQL type name (case-insensitive) incl. aliases to a canonical
    /// type. A trailing `(n)` length (e.g. `VARCHAR(255)`) is ignored.
    pub fn from_sql_name(name: &str) -> Option<ColumnType> {
        let base = name.split('(').next().unwrap_or(name).trim();
        match base.to_ascii_uppercase().as_str() {
            "INTEGER" | "INT" | "BIGINT" | "SMALLINT" => Some(ColumnType::Integer),
            "REAL" | "FLOAT" | "DOUBLE" => Some(ColumnType::Real),
            "TEXT" | "VARCHAR" | "CHAR" => Some(ColumnType::Text),
            "BOOLEAN" | "BOOL" => Some(ColumnType::Boolean),
            "TIMESTAMP" | "DATETIME" => Some(ColumnType::Timestamp),
            "KVREF" => Some(ColumnType::KvRef),
            "JSONREF" => Some(ColumnType::JsonRef),
            _ => None,
        }
    }
}

// ── ScalarValue ────────────────────────────────────────────────────────────────

/// A canonical scalar value — the shared basis for defaults and encoding.
/// `KvRef`/`JsonRef` values live as `Text`; the tag stays in `ColumnType`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScalarValue {
    Integer(i64),
    Real(f64),
    Text(String),
    Boolean(bool),
    Timestamp(i64),
    Null,
}

impl ScalarValue {
    /// True if this value is storable in a column of physical type `col_type`.
    /// `Null` matches any type (nullability is checked separately).
    pub fn matches_type(&self, col_type: ColumnType) -> bool {
        matches!(
            (col_type.physical_type(), self),
            (ColumnType::Integer, ScalarValue::Integer(_))
                | (ColumnType::Real, ScalarValue::Real(_))
                | (ColumnType::Text, ScalarValue::Text(_))
                | (ColumnType::Boolean, ScalarValue::Boolean(_))
                | (ColumnType::Timestamp, ScalarValue::Timestamp(_))
        ) || matches!(self, ScalarValue::Null)
    }
}

// ── Memcomparable encoding ─────────────────────────────────────────────────────

/// Order-preserving, self-terminating encoding of a scalar value. `Null` yields
/// `None` (not indexed). The byte order of the result matches the natural order
/// of the value's type, so LSM prefix/range scans return sorted results.
pub fn encode_sortable(value: &ScalarValue) -> Option<Vec<u8>> {
    match value {
        ScalarValue::Null => None,
        ScalarValue::Integer(i) | ScalarValue::Timestamp(i) => Some(encode_i64(*i).to_vec()),
        ScalarValue::Real(f) => Some(encode_f64(*f).to_vec()),
        ScalarValue::Text(s) => Some(encode_text(s.as_bytes())),
        ScalarValue::Boolean(b) => Some(vec![u8::from(*b)]),
    }
}

/// Exact `i64` encoding: flip the sign bit, big-endian. Correct over the whole
/// range incl. `MIN`/`MAX` — no `f64` detour (that loses precision past 2^53).
fn encode_i64(i: i64) -> [u8; 8] {
    ((i as u64) ^ 0x8000_0000_0000_0000).to_be_bytes()
}

/// IEEE-754 total-order transform, big-endian. `-0.0` canonicalizes to `+0.0`
/// and every `NaN` to one bit pattern (sorting as the largest element).
fn encode_f64(f: f64) -> [u8; 8] {
    let f = if f.is_nan() {
        f64::NAN
    } else if f == 0.0 {
        0.0
    } else {
        f
    };
    let bits = f.to_bits();
    let sortable = if bits & 0x8000_0000_0000_0000 != 0 {
        !bits
    } else {
        bits ^ 0x8000_0000_0000_0000
    };
    sortable.to_be_bytes()
}

/// UTF-8 bytes with content `0x00` escaped as `0x00 0xFF`, terminated by
/// `0x00 0x00`. Self-terminating and order-preserving incl. prefix relations.
fn encode_text(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    for &b in bytes {
        out.push(b);
        if b == 0x00 {
            out.push(0xFF);
        }
    }
    out.push(0x00);
    out.push(0x00);
    out
}

// ── Wire serialization (spec rel/009 §4) ────────────────────────────────────
//
// Placed here (not `src/api/rel.rs`, where the spec's own snippet puts it):
// `RelEngine::execute_sql`'s `ExpandedBlock` (rel/009 §5) already builds its
// `serde_json::Value` objects at the engine layer, before the REST handler
// ever sees the result — so the engine needs this conversion too. Making the
// engine depend on `src/api/` would invert the crate's layering; keeping the
// one function here and having `src/api/rel.rs` reuse it (for `rows`/`last_pk`)
// keeps a single conversion, just colocated with `ScalarValue` instead.

/// `ScalarValue` → JSON (spec §4): the single conversion used for `rows`,
/// `last_pk`, and expand objects alike. KVREF/JSONREF values are physically
/// `Text` and serialize as a plain string — no resolution here (rel/012).
pub fn scalar_to_json(v: &ScalarValue) -> serde_json::Value {
    match v {
        ScalarValue::Integer(i) => serde_json::Value::from(*i),
        ScalarValue::Real(f) => serde_json::Value::from(*f),
        ScalarValue::Text(s) => serde_json::Value::from(s.clone()),
        ScalarValue::Boolean(b) => serde_json::Value::from(*b),
        ScalarValue::Timestamp(millis) => serde_json::Value::from(format_iso8601_millis(*millis)),
        ScalarValue::Null => serde_json::Value::Null,
    }
}

/// `i64` millis-UTC → `YYYY-MM-DDThh:mm:ss[.fff]Z` (spec §4), the inverse of
/// `dml.rs`'s hand-written ISO-8601 parser (`days_from_civil`). Always UTC
/// (`Z` suffix); the `.fff` fraction is only emitted when non-zero, so a
/// value with no millis roundtrips through the parser unchanged. Correct
/// over the full `i64` range, including dates before 1970 (negative years).
fn format_iso8601_millis(millis: i64) -> String {
    const DAY_MS: i64 = 86_400_000;
    let days = millis.div_euclid(DAY_MS);
    let rem_ms = millis.rem_euclid(DAY_MS); // always in [0, DAY_MS), even for negative millis
    let (y, m, d) = civil_from_days(days);
    let hh = rem_ms / 3_600_000;
    let mi = (rem_ms / 60_000) % 60;
    let ss = (rem_ms / 1_000) % 60;
    let ms = rem_ms % 1_000;
    let date = if (0..=9999).contains(&y) {
        format!("{y:04}-{m:02}-{d:02}")
    } else {
        // Outside the plain 4-digit range (astronomically distant dates from
        // i64::MIN/MAX millis) — still well-formed, just not zero-padded.
        format!("{y}-{m:02}-{d:02}")
    };
    if ms == 0 {
        format!("{date}T{hh:02}:{mi:02}:{ss:02}Z")
    } else {
        format!("{date}T{hh:02}:{mi:02}:{ss:02}.{ms:03}Z")
    }
}

/// Days since 1970-01-01 → `(year, month, day)` — Howard Hinnant's
/// `civil_from_days`, the exact inverse of `dml.rs`'s `days_from_civil`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (y + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 6. Alias resolution (case-insensitive, canonical names stay valid, (n) ignored).
    #[test]
    fn test_sql_name_aliases() {
        assert_eq!(ColumnType::from_sql_name("INT"), Some(ColumnType::Integer));
        assert_eq!(ColumnType::from_sql_name("bigint"), Some(ColumnType::Integer));
        assert_eq!(ColumnType::from_sql_name("VARCHAR(255)"), Some(ColumnType::Text));
        assert_eq!(ColumnType::from_sql_name("char(10)"), Some(ColumnType::Text));
        assert_eq!(ColumnType::from_sql_name("DOUBLE"), Some(ColumnType::Real));
        assert_eq!(ColumnType::from_sql_name("BOOL"), Some(ColumnType::Boolean));
        assert_eq!(ColumnType::from_sql_name("DATETIME"), Some(ColumnType::Timestamp));
        assert_eq!(ColumnType::from_sql_name("Integer"), Some(ColumnType::Integer));
        assert_eq!(ColumnType::from_sql_name("kvref"), Some(ColumnType::KvRef));
        assert_eq!(ColumnType::from_sql_name("nope"), None);
    }

    #[test]
    fn test_physical_type() {
        assert_eq!(ColumnType::KvRef.physical_type(), ColumnType::Text);
        assert_eq!(ColumnType::JsonRef.physical_type(), ColumnType::Text);
        assert_eq!(ColumnType::Integer.physical_type(), ColumnType::Integer);
    }

    // 11. Integer encoding sorts over the whole i64 range.
    #[test]
    fn test_encode_integer_order() {
        let enc = |i: i64| encode_sortable(&ScalarValue::Integer(i)).unwrap();
        assert!(enc(i64::MIN) < enc(-1));
        assert!(enc(-1) < enc(0));
        assert!(enc(0) < enc(1));
        assert!(enc(1) < enc(i64::MAX));
        // Exact past 2^53 (an f64 detour would collapse these).
        assert_ne!(enc((1i64 << 53) + 1), enc(1i64 << 53));
    }

    // 12. Timestamp extremes sort correctly (same encoder as Integer).
    #[test]
    fn test_encode_timestamp_order() {
        let enc = |i: i64| encode_sortable(&ScalarValue::Timestamp(i)).unwrap();
        assert!(enc(i64::MIN) < enc(-999));
        assert!(enc(-999) < enc(0));
        assert!(enc(0) < enc(999));
        assert!(enc(999) < enc(i64::MAX));
    }

    // 13. Real ordering; -0.0 == 0.0; all NaN equal and >= every finite value.
    #[test]
    fn test_encode_real_order_and_specials() {
        let enc = |f: f64| encode_sortable(&ScalarValue::Real(f)).unwrap();
        assert!(enc(-1e300) < enc(-1.5));
        assert!(enc(-1.5) < enc(0.0));
        assert!(enc(0.0) < enc(1.5));
        assert!(enc(1.5) < enc(1e300));
        assert_eq!(enc(-0.0), enc(0.0));
        assert_eq!(enc(f64::NAN), enc(-f64::NAN));
        assert!(enc(f64::NAN) > enc(1e300));
        assert!(enc(f64::NAN) >= enc(f64::INFINITY));
    }

    // 14. Text with an embedded 0x00: self-terminating, order-preserving.
    #[test]
    fn test_encode_text_order_and_escaping() {
        let enc = |s: &str| encode_sortable(&ScalarValue::Text(s.to_string())).unwrap();
        assert!(enc("") < enc("a"));
        assert!(enc("a") < enc("a\0"));
        assert!(enc("a\0") < enc("a\0b"));
        assert!(enc("a\0b") < enc("ab"));
        // Escaping: content 0x00 becomes 0x00 0xFF, then the 0x00 0x00 terminator.
        assert_eq!(enc("a\0b"), vec![b'a', 0x00, 0xFF, b'b', 0x00, 0x00]);
        assert_ne!(enc("ab"), enc("ba"));
    }

    // 15. Boolean: false < true.
    #[test]
    fn test_encode_boolean_order() {
        let f = encode_sortable(&ScalarValue::Boolean(false)).unwrap();
        let t = encode_sortable(&ScalarValue::Boolean(true)).unwrap();
        assert_eq!(f, vec![0x00]);
        assert_eq!(t, vec![0x01]);
        assert!(f < t);
    }

    // 16. Null is not indexable.
    #[test]
    fn test_encode_null_is_none() {
        assert_eq!(encode_sortable(&ScalarValue::Null), None);
    }

    // ── scalar_to_json / ISO-8601 formatter (spec rel/009 §4) ───────────────

    #[test]
    fn test_scalar_to_json_all_variants() {
        assert_eq!(scalar_to_json(&ScalarValue::Integer(42)), serde_json::json!(42));
        assert_eq!(scalar_to_json(&ScalarValue::Real(1.5)), serde_json::json!(1.5));
        assert_eq!(scalar_to_json(&ScalarValue::Text("hi".to_string())), serde_json::json!("hi"));
        assert_eq!(scalar_to_json(&ScalarValue::Boolean(true)), serde_json::json!(true));
        assert_eq!(scalar_to_json(&ScalarValue::Null), serde_json::Value::Null);
    }

    // Millis with a non-zero fraction get ".fff"; an exact-second value doesn't.
    #[test]
    fn test_timestamp_to_json_fraction_only_when_nonzero() {
        assert_eq!(
            scalar_to_json(&ScalarValue::Timestamp(1_700_000_000_000)),
            serde_json::json!("2023-11-14T22:13:20Z")
        );
        assert_eq!(
            scalar_to_json(&ScalarValue::Timestamp(1_700_000_000_123)),
            serde_json::json!("2023-11-14T22:13:20.123Z")
        );
    }

    // Epoch and just-before-epoch: civil_from_days must handle the 1970-01-01
    // boundary and negative days (pre-1970) correctly.
    #[test]
    fn test_timestamp_to_json_epoch_and_pre_1970() {
        assert_eq!(scalar_to_json(&ScalarValue::Timestamp(0)), serde_json::json!("1970-01-01T00:00:00Z"));
        assert_eq!(scalar_to_json(&ScalarValue::Timestamp(-1)), serde_json::json!("1969-12-31T23:59:59.999Z"));
        assert_eq!(
            scalar_to_json(&ScalarValue::Timestamp(-86_400_000)),
            serde_json::json!("1969-12-31T00:00:00Z")
        );
    }

    // Full i64 range must format without panicking (overflow-safety), and
    // civil_from_days/days_from_civil (dml.rs) must agree on ordinary dates —
    // the formatter is the documented inverse of that parser.
    #[test]
    fn test_timestamp_to_json_i64_extremes_do_not_panic() {
        let _ = scalar_to_json(&ScalarValue::Timestamp(i64::MIN));
        let _ = scalar_to_json(&ScalarValue::Timestamp(i64::MAX));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(31), (1970, 2, 1)); // January has 31 days
        assert_eq!(civil_from_days(365), (1971, 1, 1)); // 1970 is not a leap year
    }
}
