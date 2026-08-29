//! CSV/TSV file import: CREATE TABLE + bulk INSERT with inferred column
//! types (spec rel/019) -- the rel counterpart of the JSON bulk load
//! (json/007). Two passes over the fully-buffered file (no sampling, no
//! streaming, per spec §5): Pass 1 infers one LuraDB type per column; Pass 2
//! creates the table through the existing catalog path (`RelEngine::create_table`)
//! and inserts rows in batches through the existing per-row DML staging
//! (`dml.rs`'s `stage_insert_row`) -- no SQL text is ever built from file data.

use super::catalog::{ColumnInput, TableInput, MAX_IDENTIFIER_LEN};
use super::cross_engine::LinkAuth;
use super::dml::{coerce_json, RowPlan};
use super::error::RelStoreError;
use super::types::{ColumnType, ScalarValue};
use super::RelEngine;
use crate::engines::lsm::engine::BatchOp;
use crate::metrics::EngineKind;
use csv::{ReaderBuilder, StringRecord};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Rows staged per `write_batch` group (spec §5), mirroring the DDL backfill
/// chunk size (`ddl.rs`'s `BACKFILL_CHUNK`) rather than a new config knob.
const IMPORT_BATCH_SIZE: usize = 500;

/// Server-side file formats (spec §2 decision 2 -- no Excel/ODS/Sheets here).
#[derive(Debug, Clone, Copy)]
pub enum FileFormat {
    Csv,
    Tsv,
}

impl FileFormat {
    fn delimiter(self) -> u8 {
        match self {
            FileFormat::Csv => b',',
            FileFormat::Tsv => b'\t',
        }
    }
}

/// One column of the created table (spec §5 response summary).
#[derive(Debug)]
pub struct ImportColumn {
    pub name: String,
    pub col_type: ColumnType,
    pub primary_key: bool,
    /// The original CSV header text (`header=true` only); `None` for the
    /// synthetic `_row` column and for `header=false`'s generated names.
    pub source_header: Option<String>,
}

/// One row-level import failure (spec §5).
#[derive(Debug)]
pub struct ImportRowError {
    pub row: u64,
    pub error: String,
}

/// Result of [`RelEngine::create_table_from_file`].
#[derive(Debug)]
pub struct CreateFromFileResult {
    pub table: String,
    pub columns: Vec<ImportColumn>,
    pub imported: u64,
    pub failed: u64,
    pub errors: Vec<ImportRowError>,
}

/// Where a planned column's Pass-2 value comes from.
enum ColumnSource {
    /// The synthetic `_row` primary key: the 1-based data-row number.
    RowNumber,
    /// A CSV field, by its index in the parsed record.
    Csv(usize),
}

struct PlannedColumn {
    source: ColumnSource,
    input: ColumnInput,
    header: Option<String>,
}

impl RelEngine {
    /// Creates a table from an uploaded CSV/TSV file and imports its rows
    /// (spec rel/019 §1-§5). `pk` is the caller's raw query value, if any;
    /// matched against the normalized column names case-insensitively.
    pub async fn create_table_from_file(
        &self,
        domain: &str,
        table: &str,
        format: FileFormat,
        header: bool,
        pk: Option<&str>,
        body: &[u8],
    ) -> Result<CreateFromFileResult, RelStoreError> {
        let (raw_headers, data_records) = read_records(format, header, body)?;
        let column_count = raw_headers.len();
        let names = normalize_headers(&raw_headers);
        let pk = pk.map(|s| s.to_ascii_lowercase());

        // `_row` reservation (spec §3): only allowed as a file column when it
        // is itself the chosen PK.
        if let Some(pos) = names.iter().position(|n| n == "_row") {
            if pk.as_deref() != Some("_row") {
                return Err(RelStoreError::InvalidSchema(format!(
                    "column '{}' normalizes to the reserved name '_row' \
                     (use ?pk=_row to make it the primary key)",
                    raw_headers[pos].as_deref().unwrap_or("_row")
                )));
            }
        }
        if let Some(pk_name) = &pk {
            if !names.iter().any(|n| n == pk_name) {
                return Err(RelStoreError::InvalidSchema(format!("pk column '{pk_name}' not found")));
            }
        }

        // Pass 1 (spec §5.1): narrowest type per column over every non-empty
        // value of the fully-buffered file.
        let col_types: Vec<ColumnType> = (0..column_count)
            .map(|i| {
                let values = data_records
                    .iter()
                    .filter_map(|r| r.as_ref().ok())
                    .filter_map(move |r| r.get(i))
                    .filter(|v| !v.is_empty());
                infer_column_type(values)
            })
            .collect();

        // Column plan, in the table's final column order (spec §4): a
        // synthetic `_row` PK when none was requested, else the CSV columns
        // in their natural order with the requested one marked as PK.
        let mut planned: Vec<PlannedColumn> = Vec::with_capacity(column_count + 1);
        if pk.is_none() {
            let mut row_col = ColumnInput::new("_row", ColumnType::Integer);
            row_col.primary_key = true;
            planned.push(PlannedColumn { source: ColumnSource::RowNumber, input: row_col, header: None });
        }
        for (i, name) in names.iter().enumerate() {
            let mut input = ColumnInput::new(name, col_types[i]);
            input.primary_key = pk.as_deref() == Some(name.as_str());
            planned.push(PlannedColumn { source: ColumnSource::Csv(i), input, header: raw_headers[i].clone() });
        }

        // Pass 2, part 1 (spec §5.2): CREATE TABLE through the existing
        // catalog path -- nothing is persisted if this fails (400/404/409/410).
        let table_input =
            TableInput { name: table.to_string(), columns: planned.iter().map(|p| p.input.clone()).collect() };
        let schema = self.create_table(domain, table_input).await?;

        let columns: Vec<ImportColumn> = planned
            .iter()
            .zip(&schema.columns)
            .map(|(p, c)| ImportColumn {
                name: c.name.clone(),
                col_type: c.col_type,
                primary_key: c.primary_key,
                source_header: p.header.clone(),
            })
            .collect();

        // Pass 2, part 2: insert rows in `IMPORT_BATCH_SIZE` groups through
        // the same per-row staging (NOT NULL/PK-dup/size/UNIQUE/REFERENCES
        // checks, index entries) the SQL/REST write paths use -- a row that
        // fails is logged and the import continues (spec §5).
        let dom = self.domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();
        let lock = self.table_locks.get(&prefix, schema.table_id);
        let _guard = lock.lock().await;

        let mut imported = 0u64;
        let mut errors: Vec<ImportRowError> = Vec::new();
        let mut seen_pk: HashSet<Vec<u8>> = HashSet::new();
        let mut seen_unique: HashSet<(u32, Vec<u8>)> = HashSet::new();

        let write_start = std::time::Instant::now();
        let mut start = 0usize;
        while start < data_records.len() {
            let end = (start + IMPORT_BATCH_SIZE).min(data_records.len());
            // A fresh snapshot per group: it must see the previous groups'
            // own commits for the PK-duplicate check inside `stage_insert_row`.
            let snapshot = self.engine.snapshot();
            let snap = snapshot.snapshot();
            let mut ops: Vec<BatchOp> = Vec::new();

            for (offset, record_result) in data_records[start..end].iter().enumerate() {
                let row_number = (start + offset + 1) as u64;
                let record = match record_result {
                    Ok(r) => r,
                    Err(e) => {
                        errors.push(ImportRowError { row: row_number, error: e.to_string() });
                        continue;
                    }
                };

                let mut values: HashMap<u16, ScalarValue> = HashMap::with_capacity(schema.columns.len());
                let mut cell_error: Option<String> = None;
                for (p, col) in planned.iter().zip(&schema.columns) {
                    let scalar = match p.source {
                        ColumnSource::RowNumber => ScalarValue::Integer(row_number as i64),
                        ColumnSource::Csv(i) => match record.get(i).filter(|v| !v.is_empty()) {
                            None => ScalarValue::Null,
                            Some(raw) => match coerce_cell(col.col_type, raw) {
                                Ok(v) => v,
                                Err(msg) => {
                                    cell_error = Some(msg);
                                    break;
                                }
                            },
                        },
                    };
                    values.insert(col.col_id, scalar);
                }
                if let Some(msg) = cell_error {
                    errors.push(ImportRowError { row: row_number, error: msg });
                    continue;
                }

                let plan = RowPlan::new(values);
                match self
                    .stage_insert_row(
                        domain,
                        &schema,
                        &prefix,
                        &plan,
                        snap,
                        &mut seen_pk,
                        &mut seen_unique,
                        &mut ops,
                        LinkAuth::full(), // no KVREF/JSONREF column is ever inferred
                    )
                    .await
                {
                    Ok(_) => {
                        imported += 1;
                        self.metrics.record_rel_dml_statement("insert");
                    }
                    Err(e) => errors.push(ImportRowError { row: row_number, error: e.to_string() }),
                }
            }

            if !ops.is_empty() {
                self.commit_guarded(domain, ops).await?;
            }
            start = end;
        }
        self.metrics.record_engine_write(EngineKind::Rel, write_start.elapsed().as_micros() as u64);

        let failed = errors.len() as u64;
        Ok(CreateFromFileResult { table: schema.name.clone(), columns, imported, failed, errors })
    }
}

/// Reads the file into `(raw_headers, data_records)` (spec §2/§3): with
/// `header=true` the first record supplies `Some(text)` per column; with
/// `header=false` every entry is `None` (the caller assigns `col_N`). Row
/// numbering (§4) is 1-based over `data_records`, uniform for both modes.
/// UTF-8 validation comes from the crate's `StringRecord` (spec §2) -- an
/// invalid header record surfaces here; an invalid *data* record is left as
/// its `Err` for the per-row loop to report and skip.
fn read_records(
    format: FileFormat,
    header: bool,
    body: &[u8],
) -> Result<(Vec<Option<String>>, Vec<Result<StringRecord, csv::Error>>), RelStoreError> {
    let reader =
        ReaderBuilder::new().delimiter(format.delimiter()).has_headers(false).flexible(false).from_reader(body);
    let mut records = reader.into_records();

    let first = records
        .next()
        .transpose()
        .map_err(|e| RelStoreError::InvalidSchema(format!("cannot read the file's column header: {e}")))?;
    let Some(first) = first else {
        return Err(RelStoreError::InvalidSchema("file is empty".to_string()));
    };
    if first.is_empty() {
        return Err(RelStoreError::InvalidSchema("file has no columns".to_string()));
    }

    if header {
        let raw_headers = (0..first.len()).map(|i| Some(first.get(i).unwrap_or("").to_string())).collect();
        Ok((raw_headers, records.collect()))
    } else {
        let raw_headers = vec![None; first.len()];
        let mut data_records = vec![Ok(first)];
        data_records.extend(records);
        Ok((raw_headers, data_records))
    }
}

/// Header normalization (spec §3): trim, lowercase, invalid chars -> `_`,
/// leading digit -> prefix `c`, empty -> `col_{i}`, over `MAX_IDENTIFIER_LEN`
/// -> truncated, collisions (including ones truncation creates) -> `_2`,
/// `_3`, … suffixed, still within the length cap.
fn normalize_headers(raw: &[Option<String>]) -> Vec<String> {
    let mut names: Vec<String> = raw
        .iter()
        .enumerate()
        .map(|(i, h)| match h {
            Some(text) => normalize_one_header(text, i + 1),
            None => format!("col_{}", i + 1),
        })
        .collect();
    dedupe_names(&mut names);
    names
}

fn normalize_one_header(raw: &str, position: usize) -> String {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() {
        return format!("col_{position}");
    }
    let sanitized: String = trimmed
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' { c } else { '_' })
        .collect();
    let prefixed = if sanitized.starts_with(|c: char| c.is_ascii_digit()) {
        format!("c{sanitized}")
    } else {
        sanitized
    };
    if prefixed.len() > MAX_IDENTIFIER_LEN {
        prefixed.chars().take(MAX_IDENTIFIER_LEN).collect()
    } else {
        prefixed
    }
}

/// Suffixes `_2`, `_3`, … onto later occurrences of a name already seen —
/// left to right, so the first column keeps the bare name.
fn dedupe_names(names: &mut [String]) {
    let mut seen: HashSet<String> = HashSet::with_capacity(names.len());
    for name in names.iter_mut() {
        if seen.insert(name.clone()) {
            continue;
        }
        let mut n = 2u32;
        loop {
            let suffix = format!("_{n}");
            let max_base = MAX_IDENTIFIER_LEN.saturating_sub(suffix.len());
            let base: String = name.chars().take(max_base).collect();
            let candidate = format!("{base}{suffix}");
            if seen.insert(candidate.clone()) {
                *name = candidate;
                break;
            }
            n += 1;
        }
    }
}

/// Pass-1 type inference (spec §5.1): the narrowest type that parses every
/// given (already non-empty) value, in the mandated order INTEGER -> REAL ->
/// BOOLEAN -> TIMESTAMP -> TEXT; TEXT always matches, so this never fails.
/// A column with no values at all (empty iterator: either truly all-empty,
/// or every value already excluded by the caller) is TEXT (spec §5.1).
fn infer_column_type<'a>(values: impl Iterator<Item = &'a str> + Clone) -> ColumnType {
    const CANDIDATES: [ColumnType; 4] =
        [ColumnType::Integer, ColumnType::Real, ColumnType::Boolean, ColumnType::Timestamp];
    for ct in CANDIDATES {
        let mut saw_value = false;
        let mut all_match = true;
        for v in values.clone() {
            saw_value = true;
            if coerce_cell(ct, v).is_err() {
                all_match = false;
                break;
            }
        }
        if saw_value && all_match {
            return ct;
        }
    }
    ColumnType::Text
}

/// Coerces one raw (non-empty) CSV field into `col_type`'s `ScalarValue`,
/// reusing the exact `coerce_json` rules DML value binding uses everywhere
/// else (rel/005) -- in particular its TIMESTAMP parser (millis or
/// ISO-8601) and its rejection of non-finite REAL values (`serde_json`'s
/// `Number` cannot hold NaN/±Inf). A value Pass 1 accepted as REAL but that
/// doesn't actually fit (e.g. "inf") surfaces here as a normal per-row
/// failure instead of silently becoming NULL.
fn coerce_cell(col_type: ColumnType, raw: &str) -> Result<ScalarValue, String> {
    let json_value = match col_type {
        ColumnType::Integer => raw.parse::<i64>().ok().map(Value::from),
        ColumnType::Real => raw.parse::<f64>().ok().filter(|f| f.is_finite()).map(Value::from),
        ColumnType::Boolean => match raw.to_ascii_lowercase().as_str() {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        ColumnType::Timestamp | ColumnType::Text => Some(Value::String(raw.to_string())),
        ColumnType::KvRef | ColumnType::JsonRef => None, // never inferred for a CSV column
    };
    let json_value = json_value.ok_or_else(|| format!("'{raw}' does not fit column type {col_type:?}"))?;
    coerce_json(col_type, &json_value, "csv cell").map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::rel::ExecOutcome;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use std::sync::Arc;

    async fn make_engine_with(overrides: RelStoreConfig) -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("rel_sstables").to_string_lossy().into_owned(),
            ..overrides
        };
        let metrics = MetricsStore::new(MetricsConfig::default());
        let cross_engine = crate::engines::rel::CrossEngineResolver::disabled(Arc::clone(&metrics));
        let engine = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();
        (engine, dir)
    }

    async fn make_engine() -> (Arc<RelEngine>, tempfile::TempDir) {
        make_engine_with(RelStoreConfig::default()).await
    }

    async fn select_all(rel: &RelEngine, sql: &str) -> (Vec<(String, ColumnType)>, Vec<Vec<ScalarValue>>) {
        match rel.execute("default", sql, &[]).await.unwrap() {
            ExecOutcome::Select(r) => (r.columns, r.rows),
            other => panic!("expected SELECT, got {other:?}"),
        }
    }

    // 1. CSV with header, mixed types -> success; schema as inferred; `_row`
    //    PK; every row readable via SELECT (spec §7 test 1).
    #[tokio::test]
    async fn test_csv_header_mixed_types_and_row_pk() {
        let (rel, _dir) = make_engine().await;
        let csv = "id,amount,active,Date,label\n\
                   1,42,true,2024-01-01T00:00:00Z,alpha\n\
                   2,7.5,false,2024-02-01T00:00:00Z,beta\n";
        let result = rel
            .create_table_from_file("default", "sales", FileFormat::Csv, true, None, csv.as_bytes())
            .await
            .unwrap();
        assert_eq!(result.table, "sales");
        assert_eq!(result.imported, 2);
        assert_eq!(result.failed, 0);
        assert!(result.errors.is_empty());

        let by_name = |n: &str| result.columns.iter().find(|c| c.name == n).unwrap();
        let row_col = by_name("_row");
        assert_eq!(row_col.col_type, ColumnType::Integer);
        assert!(row_col.primary_key);
        assert!(row_col.source_header.is_none());
        assert_eq!(by_name("amount").col_type, ColumnType::Real, "1 int + 1 real value -> REAL");
        assert_eq!(by_name("date").col_type, ColumnType::Timestamp);
        assert_eq!(by_name("date").source_header.as_deref(), Some("Date"));
        assert_eq!(by_name("label").col_type, ColumnType::Text);

        let (cols, rows) = select_all(&rel, "SELECT _row, id, amount, active, label FROM sales ORDER BY _row").await;
        assert_eq!(cols[0].1, ColumnType::Integer);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            vec![
                ScalarValue::Integer(1),
                ScalarValue::Integer(1),
                ScalarValue::Real(42.0),
                ScalarValue::Boolean(true),
                ScalarValue::Text("alpha".to_string()),
            ]
        );
    }

    // 2. TSV variant -> identical result, delimiter aside (spec §7 test 2).
    #[tokio::test]
    async fn test_tsv_variant_identical_result() {
        let (rel, _dir) = make_engine().await;
        let tsv = "id\tamount\n1\t10\n2\t20\n";
        let result =
            rel.create_table_from_file("default", "t", FileFormat::Tsv, true, None, tsv.as_bytes()).await.unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.columns.iter().find(|c| c.name == "amount").unwrap().col_type, ColumnType::Integer);
        let (_, rows) = select_all(&rel, "SELECT id, amount FROM t ORDER BY id").await;
        assert_eq!(rows[1], vec![ScalarValue::Integer(2), ScalarValue::Integer(20)]);
    }

    // 3. header=false -> generated names col_1..col_n, no source_header
    //    anywhere (spec §7 test 3).
    #[tokio::test]
    async fn test_header_false_generates_col_names() {
        let (rel, _dir) = make_engine().await;
        let csv = "1,alpha\n2,beta\n";
        let result =
            rel.create_table_from_file("default", "t", FileFormat::Csv, false, None, csv.as_bytes()).await.unwrap();
        let names: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["_row", "col_1", "col_2"]);
        assert!(result.columns.iter().all(|c| c.source_header.is_none()));
    }

    // 4. Header normalization: punctuation -> `_`, source_header preserved,
    //    a collision suffixed, an overlong header truncated to the
    //    identifier cap (spec §7 test 4).
    #[tokio::test]
    async fn test_header_normalization_and_collisions() {
        let (rel, _dir) = make_engine().await;
        let long = "a".repeat(60);
        let csv = format!("Revenue (EUR),revenue (eur),{long}\n1,2,3\n");
        let result =
            rel.create_table_from_file("default", "t", FileFormat::Csv, true, None, csv.as_bytes()).await.unwrap();
        // columns[0] is the synthetic _row; the three CSV columns follow in order.
        assert_eq!(result.columns[1].name, "revenue__eur_");
        assert_eq!(result.columns[1].source_header.as_deref(), Some("Revenue (EUR)"));
        assert_eq!(result.columns[2].name, "revenue__eur__2", "collision with column 1 after normalization");
        assert_eq!(result.columns[3].name.len(), MAX_IDENTIFIER_LEN, "truncated to the identifier cap");
    }

    // 5. Type inference cascade: "1,2,x" -> TEXT; "1,2.5" -> REAL; an empty
    //    field is nullable and reads back as NULL (spec §7 test 5).
    #[tokio::test]
    async fn test_type_inference_cascade_and_nullable() {
        let (rel, _dir) = make_engine().await;
        let csv = "mixed,real_col,gap\n1,1,x\n2,2.5,\nx,,\n";
        let result =
            rel.create_table_from_file("default", "t", FileFormat::Csv, true, None, csv.as_bytes()).await.unwrap();
        let ty = |name: &str| result.columns.iter().find(|c| c.name == name).unwrap().col_type;
        assert_eq!(ty("mixed"), ColumnType::Text, "a non-numeric value forces TEXT");
        assert_eq!(ty("real_col"), ColumnType::Real, "an int and a real value together -> REAL");
        assert_eq!(ty("gap"), ColumnType::Text, "its only non-empty value is text");

        let (_, rows) = select_all(&rel, "SELECT gap FROM t WHERE _row = 2").await;
        assert_eq!(rows[0][0], ScalarValue::Null, "an empty field reads back as NULL");
    }

    // 6. `?pk=id` with a unique column -> adopted as PK, no `_row`; a
    //    duplicate value fails just that row, the rest still import
    //    (spec §7 test 6).
    #[tokio::test]
    async fn test_pk_query_param_unique_and_duplicate() {
        let (rel, _dir) = make_engine().await;
        let csv = "id,name\n1,alpha\n2,beta\n2,gamma\n";
        let result = rel
            .create_table_from_file("default", "t", FileFormat::Csv, true, Some("id"), csv.as_bytes())
            .await
            .unwrap();
        assert!(!result.columns.iter().any(|c| c.name == "_row"), "no synthetic _row when ?pk= is set");
        assert!(result.columns.iter().find(|c| c.name == "id").unwrap().primary_key);
        assert_eq!(result.imported, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].row, 3, "the third data row (duplicate id=2) fails");

        let (_, rows) = select_all(&rel, "SELECT id FROM t ORDER BY id").await;
        assert_eq!(rows, vec![vec![ScalarValue::Integer(1)], vec![ScalarValue::Integer(2)]]);
    }

    // 7. Row errors: a mismatched column count and an overlong TEXT cell
    //    each fail just that row (numbered), the import continues past them
    //    (spec §7 test 7).
    #[tokio::test]
    async fn test_row_errors_continue_import() {
        let (rel, _dir) = make_engine_with(RelStoreConfig { max_text_len: 4, ..RelStoreConfig::default() }).await;
        let csv = "id,label\n1,ok\n2,a,extra\n3,toolong\n4,fine\n";
        let result =
            rel.create_table_from_file("default", "t", FileFormat::Csv, true, None, csv.as_bytes()).await.unwrap();
        assert_eq!(result.imported, 2, "rows 1 and 4 succeed");
        assert_eq!(result.failed, 2);
        let rows: Vec<u64> = result.errors.iter().map(|e| e.row).collect();
        assert_eq!(rows, vec![2, 3]);
        assert!(result.errors[0].error.to_lowercase().contains("field") || result.errors[0].error.contains('3'));

        let (_, sel) = select_all(&rel, "SELECT id FROM t ORDER BY id").await;
        assert_eq!(sel, vec![vec![ScalarValue::Integer(1)], vec![ScalarValue::Integer(4)]]);
    }

    // 7b. Invalid UTF-8 in a data row fails just that row; the import
    //     continues (spec §7 test 7).
    #[tokio::test]
    async fn test_invalid_utf8_row_fails_but_import_continues() {
        let (rel, _dir) = make_engine().await;
        let mut body = b"id,label\n1,ok\n2,".to_vec();
        body.push(0xFF); // a lone byte that is not valid UTF-8 on its own
        body.extend_from_slice(b"\n3,fine\n");

        let result = rel.create_table_from_file("default", "t", FileFormat::Csv, true, None, &body).await.unwrap();
        assert_eq!(result.imported, 2, "rows 1 and 3 succeed");
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors[0].row, 2);
    }

    // Valid multi-byte UTF-8 (as opposed to the invalid bytes above) is not a
    // row error: a TEXT value round-trips exactly (project convention: a
    // non-German multi-byte example, not literal invalid encoding).
    #[tokio::test]
    async fn test_multibyte_utf8_value_roundtrips() {
        let (rel, _dir) = make_engine().await;
        let csv = "id,label\n1,cl\u{e9}\n2,\u{1F600}\n";
        let result =
            rel.create_table_from_file("default", "t", FileFormat::Csv, true, None, csv.as_bytes()).await.unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.columns.iter().find(|c| c.name == "label").unwrap().col_type, ColumnType::Text);

        let (_, rows) = select_all(&rel, "SELECT label FROM t ORDER BY _row").await;
        assert_eq!(rows[0][0], ScalarValue::Text("cl\u{e9}".to_string()));
        assert_eq!(rows[1][0], ScalarValue::Text("\u{1F600}".to_string()));
    }

    // 8. Top-level failures (spec §1/§7 test 8): an existing table name, an
    //    empty file, too many columns, and an unknown `?pk=` column each
    //    fail before any table is created.
    #[tokio::test]
    async fn test_top_level_failures_create_nothing() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        let err = rel
            .create_table_from_file("default", "t", FileFormat::Csv, true, None, b"a,b\n1,2\n")
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TableAlreadyExists { .. }), "got: {err}");

        let err = rel.create_table_from_file("default", "empty", FileFormat::Csv, true, None, b"").await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
        assert!(rel.get_object("default", "empty").is_err(), "no table created");

        let (rel2, _dir2) = make_engine_with(RelStoreConfig { max_columns: 2, ..RelStoreConfig::default() }).await;
        let err = rel2
            .create_table_from_file("default", "wide", FileFormat::Csv, true, None, b"a,b,c\n1,2,3\n")
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "got: {err}");
        assert!(rel2.get_object("default", "wide").is_err(), "no table created");

        let err = rel
            .create_table_from_file("default", "u", FileFormat::Csv, true, Some("ghost"), b"a,b\n1,2\n")
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
        assert!(rel.get_object("default", "u").is_err(), "no table created");
    }

    // 10. A header column literally named `_row` without `?pk=_row` -> 400
    //     (InvalidSchema); with `?pk=_row` it is accepted and used as-is,
    //     not replaced by a generated row number (spec §7 test 10).
    #[tokio::test]
    async fn test_row_header_conflict_without_pk_row() {
        let (rel, _dir) = make_engine().await;
        let err = rel
            .create_table_from_file("default", "t", FileFormat::Csv, true, None, b"_row,name\n1,a\n")
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
        assert!(rel.get_object("default", "t").is_err());

        let result = rel
            .create_table_from_file("default", "t2", FileFormat::Csv, true, Some("_row"), b"_row,name\n5,a\n")
            .await
            .unwrap();
        assert_eq!(result.columns.len(), 2);
        assert!(result.columns.iter().find(|c| c.name == "_row").unwrap().primary_key);
        let (_, rows) = select_all(&rel, "SELECT _row FROM t2").await;
        assert_eq!(rows[0][0], ScalarValue::Integer(5), "uses the file's own value, not a generated row number");
    }
}
