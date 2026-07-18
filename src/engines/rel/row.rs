//! LuraRow binary row codec (spec rel/005 §3-4, concept 5.4).
//!
//! Compact per-column format with an 8-byte-aligned slot array (zero-copy
//! preparation, perf/002). Header/slot fields are little-endian; the var
//! region is raw bytes. Each slot carries its `col_id` in the `col_dir`, so a
//! row is bound to columns by *id*, not position — ADD/DROP/RENAME COLUMN are
//! readable without a row rewrite (§4).
//!
//! ```text
//! 0 : schema_version u16 LE
//! 2 : n = col_count  u16 LE
//! 4 : col_dir        n × u16 LE   (col_id per slot, ascending)
//!   : null_bitmap    ceil(n/8) B  (bit i set ⇒ slot i is NULL)
//!   : padding        0-bytes to the next multiple of 8
//!   : slots          n × 8 B      (scalar inline OR off:u32 LE,len:u32 LE)
//!   : var region     TEXT/KVREF/JSONREF payloads
//! ```

use super::catalog::{ColumnDef, DefaultValue, TableSchema};
use super::types::{ColumnType, ScalarValue};
use std::collections::HashMap;

/// Encodes a row from `values_by_col_id`, writing one slot per column of the
/// **current** schema in ascending `col_id` order.
pub fn encode_row(schema: &TableSchema, values_by_col_id: &HashMap<u16, ScalarValue>) -> Vec<u8> {
    let mut cols: Vec<&ColumnDef> = schema.columns.iter().collect();
    cols.sort_by_key(|c| c.col_id);
    let n = cols.len();

    let mut out = Vec::new();
    out.extend_from_slice(&schema.schema_version.to_le_bytes());
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for c in &cols {
        out.extend_from_slice(&c.col_id.to_le_bytes());
    }
    let bitmap_start = out.len();
    out.resize(bitmap_start + n.div_ceil(8), 0);
    let slots_start = (out.len() + 7) & !7;
    out.resize(slots_start, 0);

    let mut var: Vec<u8> = Vec::new();
    for (i, c) in cols.iter().enumerate() {
        match values_by_col_id.get(&c.col_id).unwrap_or(&ScalarValue::Null) {
            ScalarValue::Null => {
                out[bitmap_start + i / 8] |= 1 << (i % 8);
                out.extend_from_slice(&[0u8; 8]);
            }
            ScalarValue::Integer(x) | ScalarValue::Timestamp(x) => {
                out.extend_from_slice(&x.to_le_bytes());
            }
            ScalarValue::Real(f) => out.extend_from_slice(&f.to_le_bytes()),
            ScalarValue::Boolean(b) => {
                out.push(u8::from(*b));
                out.extend_from_slice(&[0u8; 7]);
            }
            ScalarValue::Text(s) => {
                out.extend_from_slice(&(var.len() as u32).to_le_bytes());
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                var.extend_from_slice(s.as_bytes());
            }
        }
    }
    out.extend_from_slice(&var);
    out
}

/// Decodes every column of `schema` from `row` (schema-evolution read path §4).
pub fn decode_row(row: &[u8], schema: &TableSchema) -> Vec<ScalarValue> {
    match RowView::new(row) {
        Some(v) => schema.columns.iter().map(|c| v.get(c)).collect(),
        None => schema.columns.iter().map(read_fill).collect(),
    }
}

/// Decodes a single column's value from `row` (schema-evolution read path §4).
pub fn decode_value(row: &[u8], col: &ColumnDef) -> ScalarValue {
    match RowView::new(row) {
        Some(v) => v.get(col),
        None => read_fill(col),
    }
}

/// A column absent from the row's `col_dir` (ADD COLUMN newer than the row):
/// a `Literal` default fills it, everything else reads as `NULL` (§4).
fn read_fill(col: &ColumnDef) -> ScalarValue {
    match &col.default {
        DefaultValue::Literal(v) => v.clone(),
        _ => ScalarValue::Null,
    }
}

/// A parsed view over a LuraRow's header, resolving slots by `col_id`.
struct RowView<'a> {
    bytes: &'a [u8],
    n: usize,
    bitmap_start: usize,
    slots_start: usize,
    var_start: usize,
}

impl<'a> RowView<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let n = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let bitmap_start = 4 + 2 * n;
        let slots_start = (bitmap_start + n.div_ceil(8) + 7) & !7;
        let var_start = slots_start + 8 * n;
        if bytes.len() < var_start {
            return None;
        }
        Some(Self { bytes, n, bitmap_start, slots_start, var_start })
    }

    fn slot_index(&self, col_id: u16) -> Option<usize> {
        (0..self.n).find(|&i| {
            let off = 4 + 2 * i;
            u16::from_le_bytes([self.bytes[off], self.bytes[off + 1]]) == col_id
        })
    }

    fn is_null(&self, i: usize) -> bool {
        self.bytes[self.bitmap_start + i / 8] & (1 << (i % 8)) != 0
    }

    fn get(&self, col: &ColumnDef) -> ScalarValue {
        let Some(i) = self.slot_index(col.col_id) else {
            return read_fill(col);
        };
        if self.is_null(i) {
            return ScalarValue::Null;
        }
        let slot = &self.bytes[self.slots_start + 8 * i..self.slots_start + 8 * i + 8];
        match col.col_type.physical_type() {
            ColumnType::Integer => ScalarValue::Integer(i64::from_le_bytes(slot.try_into().unwrap())),
            ColumnType::Timestamp => {
                ScalarValue::Timestamp(i64::from_le_bytes(slot.try_into().unwrap()))
            }
            ColumnType::Real => ScalarValue::Real(f64::from_le_bytes(slot.try_into().unwrap())),
            ColumnType::Boolean => ScalarValue::Boolean(slot[0] != 0),
            ColumnType::Text => {
                let off = u32::from_le_bytes(slot[0..4].try_into().unwrap()) as usize;
                let len = u32::from_le_bytes(slot[4..8].try_into().unwrap()) as usize;
                let start = self.var_start + off;
                let bytes = self.bytes.get(start..start + len).unwrap_or(&[]);
                ScalarValue::Text(String::from_utf8_lossy(bytes).into_owned())
            }
            ColumnType::KvRef | ColumnType::JsonRef => unreachable!("physical_type collapses to Text"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, col_id: u16, col_type: ColumnType) -> ColumnDef {
        ColumnDef {
            name: name.to_string(),
            col_id,
            col_type,
            nullable: true,
            primary_key: false,
            autoincrement: false,
            unique: false,
            default: DefaultValue::None,
            references: None,
        }
    }

    fn schema(columns: Vec<ColumnDef>) -> TableSchema {
        TableSchema {
            name: "t".to_string(),
            table_id: 1,
            schema_version: 1,
            columns,
            indexes: Vec::new(),
            created_at: 0,
            next_col_id: 100,
        }
    }

    // 1. Roundtrip: all five value types + KVREF/JSONREF + NULL (bitmap);
    //    the slot array is 8-byte aligned.
    #[test]
    fn test_roundtrip_all_types_and_null() {
        let s = schema(vec![
            col("i", 1, ColumnType::Integer),
            col("r", 2, ColumnType::Real),
            col("t", 3, ColumnType::Text),
            col("b", 4, ColumnType::Boolean),
            col("ts", 5, ColumnType::Timestamp),
            col("kv", 6, ColumnType::KvRef),
            col("js", 7, ColumnType::JsonRef),
            col("nul", 8, ColumnType::Text),
        ]);
        let mut vals = HashMap::new();
        vals.insert(1, ScalarValue::Integer(-42));
        vals.insert(2, ScalarValue::Real(3.5));
        vals.insert(3, ScalarValue::Text("hello".to_string()));
        vals.insert(4, ScalarValue::Boolean(true));
        vals.insert(5, ScalarValue::Timestamp(1_700_000_000_000));
        vals.insert(6, ScalarValue::Text("kvref".to_string()));
        vals.insert(7, ScalarValue::Text("{\"a\":1}".to_string()));
        vals.insert(8, ScalarValue::Null);

        let bytes = encode_row(&s, &vals);
        // Slot array 8-byte aligned.
        let view = RowView::new(&bytes).unwrap();
        assert_eq!(view.slots_start % 8, 0);

        let got = decode_row(&bytes, &s);
        assert_eq!(got[0], ScalarValue::Integer(-42));
        assert_eq!(got[1], ScalarValue::Real(3.5));
        assert_eq!(got[2], ScalarValue::Text("hello".to_string()));
        assert_eq!(got[3], ScalarValue::Boolean(true));
        assert_eq!(got[4], ScalarValue::Timestamp(1_700_000_000_000));
        assert_eq!(got[5], ScalarValue::Text("kvref".to_string()));
        assert_eq!(got[6], ScalarValue::Text("{\"a\":1}".to_string()));
        assert_eq!(got[7], ScalarValue::Null);
    }

    // 2. Schema evolution: ADD COLUMN read-fill, DROP orphan ignored, RENAME
    //    transparent (bound by col_id).
    #[test]
    fn test_schema_evolution_read_path() {
        // Row written with two columns (id=1, name=2).
        let write_schema = schema(vec![
            col("id", 1, ColumnType::Integer),
            col("name", 2, ColumnType::Text),
        ]);
        let mut vals = HashMap::new();
        vals.insert(1, ScalarValue::Integer(7));
        vals.insert(2, ScalarValue::Text("alice".to_string()));
        let bytes = encode_row(&write_schema, &vals);

        // Current schema: id renamed to pk (col_id 1 unchanged), name dropped,
        // a new col added with a literal default and one with no default.
        let mut added_lit = col("added", 3, ColumnType::Integer);
        added_lit.default = DefaultValue::Literal(ScalarValue::Integer(99));
        let added_null = col("added2", 4, ColumnType::Text);
        let read_schema = schema(vec![col("pk", 1, ColumnType::Integer), added_lit, added_null]);

        let got = decode_row(&bytes, &read_schema);
        assert_eq!(got[0], ScalarValue::Integer(7)); // rename transparent (col_id)
        assert_eq!(got[1], ScalarValue::Integer(99)); // ADD COLUMN literal read-fill
        assert_eq!(got[2], ScalarValue::Null); // ADD COLUMN no default → NULL
        // The dropped "name" slot is simply not read.
        assert_eq!(decode_value(&bytes, &read_schema.columns[0]), ScalarValue::Integer(7));
    }

    #[test]
    fn test_empty_text_and_var_offsets() {
        let s = schema(vec![
            col("a", 1, ColumnType::Text),
            col("b", 2, ColumnType::Text),
        ]);
        let mut vals = HashMap::new();
        vals.insert(1, ScalarValue::Text(String::new()));
        vals.insert(2, ScalarValue::Text("xy".to_string()));
        let bytes = encode_row(&s, &vals);
        let got = decode_row(&bytes, &s);
        assert_eq!(got[0], ScalarValue::Text(String::new()));
        assert_eq!(got[1], ScalarValue::Text("xy".to_string()));
    }
}
