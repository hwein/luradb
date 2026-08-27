//! Catalog/Row-Browse + Row-Write REST handlers (spec rel/010).
//!
//! GET  /store-api/rel/{domain}/tables            -> list_tables
//! GET  /store-api/rel/{domain}/tables/{t}         -> get_table
//! GET  /store-api/rel/{domain}/views              -> list_views
//! GET  /store-api/rel/{domain}/tables/{t}/rows     -> browse_rows
//! GET  /store-api/rel/{domain}/tables/{t}/rows/{pk} -> get_row
//! POST /store-api/rel/{domain}/tables/{t}/rows     -> insert_row
//! PUT  /store-api/rel/{domain}/tables/{t}/rows/{pk} -> update_row
//! DELETE /store-api/rel/{domain}/tables/{t}/rows/{pk} -> delete_row
//! GET  /store-api/rel/{domain}/tables/{t}/count    -> count_rows
//!
//! All eight compile onto the existing rel/005 (DML) / rel/006 (SELECT)
//! bound plans (`RelEngine::{browse_rows,get_row,insert_row,update_row,
//! delete_row}`, `src/engines/rel/rest_browse.rs`/`rest_write.rs`) — no
//! second query/write path. Auth is path-/method-based only (rel/011, not
//! built here); `rel_engine(&state)?` + a rate-limit charge guard every
//! handler, matching rel/009's `/sql` handler.

use crate::api::rel::{column_type_name, compute_link_auth, dml_result_json, rel_engine};
use crate::api::{middleware::ApiError, AppState, CountResponse};
use crate::auth::middleware::{AuthOutcome, AuthUser};
use crate::engines::rel::{
    scalar_to_json, CatalogEntry, ColumnType, DefaultValue, ExpandedBlock, RelEngine, RelStoreError, ScalarValue,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use utoipa::ToSchema;

/// Charges one op against the domain's rate-limit budget (spec §8) before
/// any engine I/O. There is no SQL statement to classify here (unlike
/// `/sql`'s `execute_sql`), so the HTTP method alone decides the bucket:
/// GET -> read, POST/PUT/DELETE -> write.
fn check_budget(engine: &RelEngine, state: &AppState, domain: &str, write: bool) -> Result<(), ApiError> {
    if engine.check_domain_budget(domain, write) {
        Ok(())
    } else {
        state.metrics.record_rate_limit_rejection(domain);
        Err(RelStoreError::RateLimited { domain: domain.to_string() }.into())
    }
}

// ── Catalog Browsing (spec §2) ───────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct TableLinks {
    #[serde(rename = "self")]
    pub self_: String,
    pub rows: String,
}

#[derive(Serialize, ToSchema)]
pub struct TableSummary {
    pub name: String,
    #[serde(rename = "_links")]
    pub links: TableLinks,
}

#[derive(Serialize, ToSchema)]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
    pub nullable: bool,
    pub primary_key: bool,
    pub autoincrement: bool,
    pub unique: bool,
    pub references: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub default: Option<Value>,
}

#[derive(Serialize, ToSchema)]
pub struct IndexInfo {
    pub name: String,
    pub column: String,
    pub unique: bool,
}

#[derive(Serialize, ToSchema)]
pub struct TableDetail {
    pub name: String,
    pub columns: Vec<ColumnInfo>,
    pub indexes: Vec<IndexInfo>,
    pub created_at: u64,
    #[serde(rename = "_links")]
    pub links: TableLinks,
}

#[derive(Serialize, ToSchema)]
pub struct ViewSummary {
    pub name: String,
    pub sql: String,
    pub created_at: u64,
}

fn table_links(domain: &str, name: &str) -> TableLinks {
    TableLinks {
        self_: format!("/store-api/rel/{domain}/tables/{name}"),
        rows: format!("/store-api/rel/{domain}/tables/{name}/rows"),
    }
}

/// `None` -> field omitted (no DEFAULT clause); the other three cases are
/// distinguishable JSON shapes (spec §2).
fn default_to_json(d: &DefaultValue) -> Option<Value> {
    match d {
        DefaultValue::None => None,
        DefaultValue::Null => Some(Value::Null),
        DefaultValue::Literal(v) => Some(scalar_to_json(v)),
        DefaultValue::CurrentTimestamp => Some(Value::String("CURRENT_TIMESTAMP".to_string())),
    }
}

#[utoipa::path(
    get,
    path = "/store-api/rel/{domain}/tables",
    params(("domain" = String, Path, description = "Relational domain")),
    responses(
        (status = 200, description = "Tables of the domain", body = Vec<TableSummary>),
        (status = 404, description = "Domain not found"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Browse"
)]
/// Lists the tables of a domain (views are listed separately, `GET …/views`).
pub async fn list_tables(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Vec<TableSummary>>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, false)?;
    let out = engine
        .list_objects(&domain)?
        .into_iter()
        .filter_map(|e| match e {
            CatalogEntry::Table(t) => Some(TableSummary { links: table_links(&domain, &t.name), name: t.name }),
            CatalogEntry::View(_) => None,
        })
        .collect();
    Ok(Json(out))
}

#[utoipa::path(
    get,
    path = "/store-api/rel/{domain}/tables/{table}",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
    ),
    responses(
        (status = 200, description = "Table schema detail", body = TableDetail),
        (status = 404, description = "Domain or table not found (a view is not a table)"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Browse"
)]
/// Returns a table's schema (columns, indexes) plus HATEOAS links. A view
/// name answers 404 here — use `GET …/views` for views.
pub async fn get_table(
    State(state): State<AppState>,
    Path((domain, table)): Path<(String, String)>,
) -> Result<Json<TableDetail>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, false)?;
    let schema = match engine.get_object(&domain, &table)? {
        CatalogEntry::Table(t) => t,
        CatalogEntry::View(_) => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                format!("404 Not Found: '{table}' is a view, not a table"),
            ))
        }
    };
    let columns = schema
        .columns
        .iter()
        .map(|c| ColumnInfo {
            name: c.name.clone(),
            col_type: column_type_name(c.col_type).to_string(),
            nullable: c.nullable,
            primary_key: c.primary_key,
            autoincrement: c.autoincrement,
            unique: c.unique,
            references: c.references.clone(),
            default: default_to_json(&c.default),
        })
        .collect();
    let indexes = schema
        .indexes
        .iter()
        .map(|ix| IndexInfo { name: ix.name.clone(), column: ix.column.clone(), unique: ix.unique })
        .collect();
    Ok(Json(TableDetail {
        name: schema.name.clone(),
        columns,
        indexes,
        created_at: schema.created_at,
        links: table_links(&domain, &schema.name),
    }))
}

#[utoipa::path(
    get,
    path = "/store-api/rel/{domain}/views",
    params(("domain" = String, Path, description = "Relational domain")),
    responses(
        (status = 200, description = "Views of the domain, incl. raw SQL text", body = Vec<ViewSummary>),
        (status = 404, description = "Domain not found"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Browse"
)]
/// Lists the views of a domain, including their raw (unmodified) SQL text.
pub async fn list_views(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Vec<ViewSummary>>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, false)?;
    let out = engine
        .list_objects(&domain)?
        .into_iter()
        .filter_map(|e| match e {
            CatalogEntry::View(v) => Some(ViewSummary { name: v.name, sql: v.sql, created_at: v.created_at }),
            CatalogEntry::Table(_) => None,
        })
        .collect();
    Ok(Json(out))
}

// ── Row-Browse (spec §3/§4/§6) ───────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RowsResponse {
    /// One JSON object per row (catalog column order in principle; `serde_json`'s
    /// default map is unordered/alphabetical here, see rel_browse.rs module docs),
    /// with an optional `_expanded` block (spec §6).
    #[schema(value_type = Vec<Object>)]
    pub rows: Vec<Value>,
    pub row_count: usize,
    pub limit: u64,
    pub offset: u64,
    pub limit_applied: bool,
}

const RESERVED_QUERY_PARAMS: [&str; 3] = ["expand", "limit", "offset"];

fn parse_query_i64(params: &HashMap<String, String>, key: &str) -> Result<Option<i64>, ApiError> {
    match params.get(key) {
        None => Ok(None),
        Some(raw) => raw.parse::<i64>().map(Some).map_err(|_| {
            ApiError::new(StatusCode::BAD_REQUEST, format!("400 Bad Request: '{key}' must be an integer"))
        }),
    }
}

fn parse_expand_param(params: &HashMap<String, String>) -> Vec<String> {
    match params.get("expand") {
        None => Vec::new(),
        Some(s) if s.is_empty() => Vec::new(),
        Some(s) => s.split(',').map(str::to_string).collect(),
    }
}

/// One row as a JSON object: `{column: scalar_to_json(value), …}`, plus a
/// transposed `_expanded` block (spec §6) — the column-wise `ExpandedBlock`
/// holds one resolved value per row, in row order; this picks out row
/// `row_idx`'s entry for every resolved column.
fn row_to_object(
    columns: &[(String, ColumnType)],
    row: &[ScalarValue],
    expanded: Option<&ExpandedBlock>,
    row_idx: usize,
) -> Value {
    let mut obj = Map::with_capacity(columns.len() + 1);
    for ((name, _), value) in columns.iter().zip(row) {
        obj.insert(name.clone(), scalar_to_json(value));
    }
    if let Some(expanded) = expanded {
        let mut block = Map::with_capacity(expanded.len());
        for (name, values) in expanded {
            block.insert(name.clone(), values[row_idx].clone());
        }
        obj.insert("_expanded".to_string(), Value::Object(block));
    }
    Value::Object(obj)
}

/// Handler-side 413 guard (spec §7), checked *after* serialization — the
/// same KISS pattern as `/sql` (rel.rs), especially relevant for expand
/// fan-out whose size isn't known ahead of time.
fn enforce_response_size(engine: &RelEngine, value: &Value) -> Result<(), ApiError> {
    let size = serde_json::to_vec(value)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .len();
    if size > engine.max_response_bytes() {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "413 Payload Too Large: response exceeds max_response_bytes; reduce limit/expand",
        ));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/store-api/rel/{domain}/tables/{table}/rows",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
        ("expand" = Option<String>, Query, description = "Comma-separated REFERENCES columns to resolve, or \"*\" for all"),
        ("limit" = Option<i64>, Query, description = "Max rows to return (falls back to the configured default, capped at the configured max)"),
        ("offset" = Option<i64>, Query, description = "Rows to skip"),
    ),
    responses(
        (status = 200, description = "Matching rows as objects, with row_count/limit/offset/limit_applied", body = RowsResponse),
        (status = 400, description = "Unknown filter column, or a filter/limit/offset parse/type error"),
        (status = 404, description = "Domain or table not found"),
        (status = 410, description = "Domain is being deleted"),
        (status = 413, description = "Response exceeds max_response_bytes"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Browse"
)]
/// Lists rows of `table`. Every query parameter other than `expand`/`limit`/
/// `offset` is an equality filter on the like-named column (`?col=value`,
/// AND-combined); parse errors and unknown filter columns answer 400. This
/// compiles onto the same bound `*`-SELECT plan `/sql` would use.
pub async fn browse_rows(
    State(state): State<AppState>,
    Path((domain, table)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    auth_user: Option<Extension<AuthUser>>,
) -> Result<Json<Value>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, false)?;

    let limit = parse_query_i64(&params, "limit")?;
    let offset = parse_query_i64(&params, "offset")?;
    let expand = parse_expand_param(&params);
    let filters: HashMap<String, String> =
        params.into_iter().filter(|(k, _)| !RESERVED_QUERY_PARAMS.contains(&k.as_str())).collect();

    let link_auth = compute_link_auth(
        &state,
        auth_outcome.map(|Extension(o)| o),
        auth_user.map(|Extension(u)| u).as_ref(),
        &domain,
    )
    .await;

    let (result, expanded, applied_limit, applied_offset) =
        engine.browse_rows(&domain, &table, &filters, &expand, limit, offset, link_auth).await?;

    let rows: Vec<Value> = result
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| row_to_object(&result.columns, row, expanded.as_ref(), i))
        .collect();
    let response = json!({
        "rows": rows,
        "row_count": rows.len(),
        "limit": applied_limit,
        "offset": applied_offset,
        "limit_applied": result.limit_applied,
    });
    enforce_response_size(engine, &response)?;
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/store-api/rel/{domain}/tables/{table}/rows/{pk}",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
        ("pk" = String, Path, description = "Primary key value"),
        ("expand" = Option<String>, Query, description = "Comma-separated REFERENCES columns to resolve, or \"*\""),
    ),
    responses(
        (status = 200, description = "The row as an object, with an optional _expanded block", body = Object),
        (status = 400, description = "PK parse/type error"),
        (status = 404, description = "Domain, table, or row not found"),
        (status = 410, description = "Domain is being deleted"),
        (status = 413, description = "Response exceeds max_response_bytes"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Browse"
)]
/// Fetches a single row by primary key — the same PK-point SELECT plan
/// `/sql`'s `WHERE pk = ?` would use.
pub async fn get_row(
    State(state): State<AppState>,
    Path((domain, table, pk)): Path<(String, String, String)>,
    Query(params): Query<HashMap<String, String>>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    auth_user: Option<Extension<AuthUser>>,
) -> Result<Json<Value>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, false)?;
    let expand = parse_expand_param(&params);

    let link_auth = compute_link_auth(
        &state,
        auth_outcome.map(|Extension(o)| o),
        auth_user.map(|Extension(u)| u).as_ref(),
        &domain,
    )
    .await;

    let Some((result, expanded)) = engine.get_row(&domain, &table, &pk, &expand, link_auth).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: row '{pk}' not found")));
    };
    let obj = row_to_object(&result.columns, &result.rows[0], expanded.as_ref(), 0);
    enforce_response_size(engine, &obj)?;
    Ok(Json(obj))
}

#[utoipa::path(
    get,
    path = "/store-api/rel/{domain}/tables/{table}/count",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
    ),
    responses(
        (status = 200, description = "Row count. A full key scan under the hood — cost grows linearly with table size; meant for on-demand use, not high-frequency polling.", body = CountResponse),
        (status = 404, description = "Domain or table not found (a view has no count resource, same as `rows`)"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Browse"
)]
/// Counts the rows of `table` — the same residual-free access path `SELECT
/// COUNT(*) FROM table` would use via `/sql`, without a SQL round trip. A
/// view answers 404 here, same as `GET …/rows` (no row-level resource in v1).
pub async fn count_rows(
    State(state): State<AppState>,
    Path((domain, table)): Path<(String, String)>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    auth_user: Option<Extension<AuthUser>>,
) -> Result<Json<CountResponse>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, false)?;

    let link_auth = compute_link_auth(
        &state,
        auth_outcome.map(|Extension(o)| o),
        auth_user.map(|Extension(u)| u).as_ref(),
        &domain,
    )
    .await;

    let count = engine.count_rows(&domain, &table, link_auth).await?;
    Ok(Json(CountResponse { count }))
}

// ── Row-Writes (spec §5) ─────────────────────────────────────────────────────

/// PK value for the `Location` header's final path segment (spec §5):
/// INTEGER as plain decimal, TEXT percent-encoded (it may contain `/`,
/// spaces, non-ASCII, …). The PK is always INTEGER or TEXT (rel/003 §4).
fn pk_path_segment(pk: &ScalarValue) -> String {
    match pk {
        ScalarValue::Integer(i) => i.to_string(),
        ScalarValue::Text(s) => percent_encode_path_segment(s),
        other => unreachable!("primary key is always Integer or Text, got {other:?}"),
    }
}

fn percent_encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[utoipa::path(
    post,
    path = "/store-api/rel/{domain}/tables/{table}/rows",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
    ),
    request_body = Object,
    responses(
        (status = 201, description = "Row inserted", body = Object),
        (status = 400, description = "NOT NULL/type/schema violation"),
        (status = 403, description = "Missing read access to a linked KV/JSON domain (rel/016)"),
        (status = 404, description = "Domain, table, or referenced body column not found"),
        (status = 409, description = "PK collision, unique violation, or missing REFERENCES target"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Rows"
)]
/// Inserts one row from a JSON object body (`{column: value, …}`). An omitted
/// AUTOINCREMENT primary key is assigned the next sequence value (rel/005
/// §9); this compiles onto the exact same bound INSERT plan `/sql` would use.
pub async fn insert_row(
    State(state): State<AppState>,
    Path((domain, table)): Path<(String, String)>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    auth_user: Option<Extension<AuthUser>>,
    Json(body): Json<Map<String, Value>>,
) -> Result<Response, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, true)?;

    let link_auth = compute_link_auth(
        &state,
        auth_outcome.map(|Extension(o)| o),
        auth_user.map(|Extension(u)| u).as_ref(),
        &domain,
    )
    .await;

    let result = engine.insert_row(&domain, &table, &body, link_auth).await?;
    let pk = result.last_pk.as_ref().expect("single-row INSERT always yields last_pk (rel/005 §9)");
    let location = format!("/store-api/rel/{domain}/tables/{table}/rows/{}", pk_path_segment(pk));
    Ok((StatusCode::CREATED, [(header::LOCATION, location)], Json(dml_result_json(&result))).into_response())
}

#[utoipa::path(
    put,
    path = "/store-api/rel/{domain}/tables/{table}/rows/{pk}",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
        ("pk" = String, Path, description = "Primary key value"),
    ),
    request_body = Object,
    responses(
        (status = 200, description = "Row updated", body = Object),
        (status = 400, description = "NOT NULL/type/schema violation, or body primary key != path primary key"),
        (status = 403, description = "Missing read access to a linked KV/JSON domain (rel/016)"),
        (status = 404, description = "Domain, table, column, or row not found"),
        (status = 409, description = "Unique violation, or missing REFERENCES target"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Rows"
)]
/// Partially updates a row by primary key: only the columns named in the
/// body are set, everything else stays unchanged (spec §5). Not an upsert —
/// a PK the table doesn't have answers 404, never a create.
pub async fn update_row(
    State(state): State<AppState>,
    Path((domain, table, pk)): Path<(String, String, String)>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    auth_user: Option<Extension<AuthUser>>,
    Json(body): Json<Map<String, Value>>,
) -> Result<Json<Value>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, true)?;

    let link_auth = compute_link_auth(
        &state,
        auth_outcome.map(|Extension(o)| o),
        auth_user.map(|Extension(u)| u).as_ref(),
        &domain,
    )
    .await;

    let result = engine.update_row(&domain, &table, &pk, &body, link_auth).await?;
    if result.affected == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: row '{pk}' not found")));
    }
    Ok(Json(dml_result_json(&result)))
}

#[utoipa::path(
    delete,
    path = "/store-api/rel/{domain}/tables/{table}/rows/{pk}",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("table" = String, Path, description = "Table name"),
        ("pk" = String, Path, description = "Primary key value"),
    ),
    responses(
        (status = 200, description = "Row deleted", body = Object),
        (status = 400, description = "PK parse/type error"),
        (status = 404, description = "Domain, table, or row not found"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Rows"
)]
/// Deletes a row by primary key. Hanging REFERENCES from other tables are
/// not blocked by this (rel/005 §11) — they resolve to `null` afterwards.
pub async fn delete_row(
    State(state): State<AppState>,
    Path((domain, table, pk)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain, true)?;

    let result = engine.delete_row(&domain, &table, &pk).await?;
    if result.affected == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: row '{pk}' not found")));
    }
    Ok(Json(dml_result_json(&result)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::storage::{file_manager::FileManager, manifest::ManifestManager, vlog::VLog};
    use axum::body::to_bytes;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use std::sync::Arc;
    use tower::util::ServiceExt;

    // ── Harness (mirrors src/api/rel.rs's own test harness) ─────────────────

    async fn make_state(rel_config: Option<RelStoreConfig>, auth_enabled: bool) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let kv_dir = dir.path().join("kv");
        std::fs::create_dir_all(&kv_dir).unwrap();
        let wal_path = kv_dir.join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = kv_dir.join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(&kv_dir).await.unwrap());
        let mm = Arc::new(ManifestManager::new(&kv_dir));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let auth_cache = Arc::new(crate::auth::AuthCache::new(Arc::clone(&engine)));
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            DomainRegistry::recover(Arc::clone(&engine), DomainConfig::default(), Arc::clone(&metrics))
                .await
                .unwrap(),
        );
        let rel_engine = match rel_config {
            None => None,
            Some(cfg) => {
                let cfg = RelStoreConfig {
                    wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
                    vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
                    sstable_dir: dir.path().join("rel_sst").to_string_lossy().into_owned(),
                    ..cfg
                };
                // KV wired (same instance), JSON disabled — enough for KVREF
                // DDL/expand shape; JSONREF resolution is covered in cross_engine.rs.
                let resolver = crate::engines::rel::CrossEngineResolver::new(
                    Some(Arc::clone(&registry)),
                    None,
                    Arc::clone(&metrics),
                );
                Some(RelEngine::bootstrap(&cfg, Arc::clone(&metrics), resolver).await.unwrap())
            }
        };
        let state = AppState {
            registry,
            auth_cache,
            auth_enabled,
            metrics,
            json_engine: None,
            rel_engine,
            shm_manager: None,
            backup_manager: None,
            log_access: None,
        };
        (state, dir)
    }

    async fn make_app(rel_config: Option<RelStoreConfig>) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = make_state(rel_config, false).await;
        (crate::api::create_router(state, Arc::new(vec![])), dir)
    }

    async fn make_default_app() -> (axum::Router, tempfile::TempDir) {
        make_app(Some(RelStoreConfig::default())).await
    }

    /// Raw request; returns status, an optional `Location` header, and the
    /// body text (JSON or plain-text error message).
    async fn request_full(
        app: &axum::Router,
        method: Method,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, Option<String>, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        let req = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(b.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let location = resp.headers().get(header::LOCATION).map(|v| v.to_str().unwrap().to_string());
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, location, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn request(app: &axum::Router, method: Method, uri: &str, body: Option<&str>) -> (StatusCode, String) {
        let (status, _, text) = request_full(app, method, uri, body).await;
        (status, text)
    }

    async fn req_json(app: &axum::Router, method: Method, uri: &str, body: Option<&str>) -> (StatusCode, Value) {
        let (status, text) = request(app, method, uri, body).await;
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"_raw": text}));
        (status, value)
    }

    async fn req_json_with_location(
        app: &axum::Router,
        method: Method,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, Option<String>, Value) {
        let (status, location, text) = request_full(app, method, uri, body).await;
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"_raw": text}));
        (status, location, value)
    }

    async fn sql(app: &axum::Router, domain: &str, body: &str) -> (StatusCode, Value) {
        req_json(app, Method::POST, &format!("/store-api/rel/{domain}/sql"), Some(body)).await
    }

    /// `orders.customer_id` REFERENCES `customers`; order 3's customer is
    /// deleted afterward, leaving a genuine hanging link (mirrors rel/009's
    /// own `setup_orders` fixture).
    async fn setup_customers_orders(app: &axum::Router) {
        sql(app, "default", r#"{"sql": "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)"}"#).await;
        sql(
            app,
            "default",
            r#"{"sql": "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER REFERENCES customers, amount INTEGER, note TEXT, status TEXT NOT NULL DEFAULT 'pending', payload KVREF)"}"#,
        )
        .await;
        sql(app, "default", r#"{"sql": "CREATE INDEX orders_amount_idx ON orders (amount)"}"#).await;
        sql(app, "default", r#"{"sql": "INSERT INTO customers VALUES (7, 'alice'), (99, 'ghost')"}"#).await;
        sql(
            app,
            "default",
            r#"{"sql": "INSERT INTO orders (id, customer_id, amount, note, payload) VALUES (1, 7, 10, 'a', NULL), (2, NULL, 20, 'b', NULL), (3, 99, 30, 'c', NULL)"}"#,
        )
        .await;
        let (status, body) = sql(app, "default", r#"{"sql": "DELETE FROM customers WHERE id = 99"}"#).await;
        assert_eq!(status, StatusCode::OK, "setup delete must succeed: {body}");
    }

    // 1. Catalog: GET tables -> list with _links; GET tables/{t} -> TableDetail
    //    (canonical type, nullable/primary_key/autoincrement/references/default);
    //    GET views -> list incl. raw sql; unknown table -> 404; a view under
    //    tables/{t} -> 404.
    #[tokio::test]
    async fn test_catalog_browse() {
        let (app, _dir) = make_default_app().await;
        setup_customers_orders(&app).await;

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let arr = body.as_array().unwrap();
        let orders_summary = arr.iter().find(|t| t["name"] == json!("orders")).unwrap();
        assert_eq!(orders_summary["_links"]["self"], json!("/store-api/rel/default/tables/orders"));
        assert_eq!(orders_summary["_links"]["rows"], json!("/store-api/rel/default/tables/orders/rows"));

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/orders", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["_links"]["self"], json!("/store-api/rel/default/tables/orders"));
        assert_eq!(body["_links"]["rows"], json!("/store-api/rel/default/tables/orders/rows"));
        let cols = body["columns"].as_array().unwrap();
        let col = |name: &str| cols.iter().find(|c| c["name"] == json!(name)).unwrap();
        assert_eq!(col("customer_id")["type"], json!("INTEGER"));
        assert_eq!(col("customer_id")["references"], json!("customers"));
        assert_eq!(col("customer_id")["nullable"], json!(true));
        assert_eq!(col("id")["primary_key"], json!(true));
        assert_eq!(col("id")["autoincrement"], json!(true));
        assert_eq!(col("payload")["type"], json!("KVREF"));
        assert_eq!(col("status")["default"], json!("pending"));
        assert!(col("note").get("default").is_none(), "no DEFAULT clause -> field omitted");

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/views", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 0);
        sql(&app, "default", r#"{"sql": "CREATE VIEW v1 AS SELECT * FROM orders"}"#).await;
        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/views", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let views = body.as_array().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0]["name"], json!("v1"));
        assert!(views[0]["sql"].as_str().unwrap().to_uppercase().contains("SELECT"));

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/ghost", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/v1", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a view is not a table");

        // Row-browse on a view name: also 404 (a view has no /rows resource),
        // not the write path's 400 NotWritable — this is a read.
        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/v1/rows", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a view has no rows resource");
        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/v1/rows/1", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a view has no rows resource");
    }

    // 2. Row-Browse without filters: default_limit applies; explicit limit >
    //    max_limit capped -> limit_applied = true; offset correct.
    #[tokio::test]
    async fn test_browse_rows_pagination() {
        let (app, _dir) =
            make_app(Some(RelStoreConfig { default_limit: 2, max_limit: 3, ..RelStoreConfig::default() })).await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1),(2),(3),(4),(5)"}"#).await;

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 2, "default_limit=2 applies");
        assert_eq!(body["row_count"], json!(2));
        assert_eq!(body["limit"], json!(2));
        assert_eq!(body["offset"], json!(0));
        assert_eq!(body["limit_applied"], json!(true), "more rows exist past default_limit");
        assert!(body["rows"][0].as_object().unwrap().contains_key("id"));

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?limit=100", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 3, "capped by max_limit=3");
        assert_eq!(body["limit"], json!(3));
        assert_eq!(body["limit_applied"], json!(true));

        let (status, body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?limit=2&offset=3", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut ids: Vec<i64> = body["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, vec![4, 5]);
        assert_eq!(body["offset"], json!(3));
        assert_eq!(body["limit_applied"], json!(false), "exactly 2 rows remained after offset 3 of 5");

        // Parse errors.
        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?limit=abc", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?offset=abc", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // 3. `?col=` filters: INTEGER/TEXT/BOOLEAN/TIMESTAMP parsed; multiple =
    //    AND; a PK filter uses the PK point, an indexed column its index —
    //    same result as the equivalent /sql; parse/type error -> 400; unknown
    //    filter column -> 400.
    #[tokio::test]
    async fn test_browse_rows_col_filters() {
        let (app, _dir) = make_default_app().await;
        sql(
            &app,
            "default",
            r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER, label TEXT, active BOOLEAN, ts TIMESTAMP)"}"#,
        )
        .await;
        sql(&app, "default", r#"{"sql": "CREATE INDEX t_tag_idx ON t (tag)"}"#).await;
        sql(
            &app,
            "default",
            r#"{"sql": "INSERT INTO t VALUES (1, 5, 'a', true, '2024-01-01T00:00:00Z'), (2, 5, 'b', false, '2024-02-01T00:00:00Z'), (3, 9, 'a', true, NULL)"}"#,
        )
        .await;

        // INTEGER filter via the tag index; same result set as /sql.
        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?tag=5", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut ids: Vec<i64> = body["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        ids.sort();
        let (_, sql_body) = sql(&app, "default", r#"{"sql": "SELECT id FROM t WHERE tag = 5 ORDER BY id"}"#).await;
        let sql_ids: Vec<i64> = sql_body["rows"].as_array().unwrap().iter().map(|r| r[0].as_i64().unwrap()).collect();
        assert_eq!(ids, sql_ids);

        // PK filter -> PK point.
        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?id=1", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 1);

        // BOOLEAN + TEXT, multiple filters = AND.
        let (status, body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?active=true&label=a", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut ids: Vec<i64> = body["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 3]);

        // TIMESTAMP filter, ISO-8601 (colon percent-encoded for URI safety).
        let (status, body) = req_json(
            &app,
            Method::GET,
            "/store-api/rel/default/tables/t/rows?ts=2024-01-01T00%3A00%3A00Z",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 1);
        assert_eq!(body["rows"][0]["id"], json!(1));

        // Parse/type error.
        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?tag=notanumber", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Unknown filter column.
        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?ghost=1", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // 4. expand REFERENCES: `?expand=customer_id` -> `_expanded.customer_id`
    //    object|null per row; NULL link -> null; hanging link -> null.
    #[tokio::test]
    async fn test_browse_rows_expand_references() {
        let (app, _dir) = make_default_app().await;
        setup_customers_orders(&app).await;

        let (status, body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows?expand=customer_id", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows = body["rows"].as_array().unwrap();
        let by_id = |id: i64| rows.iter().find(|r| r["id"] == json!(id)).unwrap();
        assert_eq!(by_id(1)["_expanded"]["customer_id"], json!({"id": 7, "name": "alice"}));
        assert_eq!(by_id(2)["_expanded"]["customer_id"], Value::Null, "NULL link");
        assert_eq!(by_id(3)["_expanded"]["customer_id"], Value::Null, "hanging link (customer deleted)");
    }

    // 5. expand=*: every projected link column resolved — REFERENCES *and*
    //    KVREF/JSONREF (rel/012 no longer skips them); _expanded omitted where
    //    a table has no link columns at all.
    #[tokio::test]
    async fn test_browse_rows_expand_wildcard() {
        let (app, _dir) = make_default_app().await;
        setup_customers_orders(&app).await;

        let (status, body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows?expand=*", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows = body["rows"].as_array().unwrap();
        let row1 = rows.iter().find(|r| r["id"] == json!(1)).unwrap();
        assert_eq!(row1["_expanded"]["customer_id"], json!({"id": 7, "name": "alice"}));
        assert_eq!(row1["_expanded"]["payload"], Value::Null, "KVREF column now resolved (NULL cell -> null)");

        let (status, body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/customers/rows?expand=*", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        for row in body["rows"].as_array().unwrap() {
            assert!(row.get("_expanded").is_none(), "no REFERENCES columns on customers -> no _expanded");
        }
    }

    // 6. expand errors: unknown/non-link column -> 400 InvalidExpand; expand
    //    columns over max_join_depth -> 400 JoinDepthExceeded. (KVREF/JSONREF
    //    now resolve — see test 5; no more CrossEngineExpand 400.)
    #[tokio::test]
    async fn test_browse_rows_expand_errors() {
        let (app, _dir) =
            make_app(Some(RelStoreConfig { max_join_depth: 0, ..RelStoreConfig::default() })).await;
        setup_customers_orders(&app).await;

        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows?expand=nope", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unknown column");

        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows?expand=id", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "id is not a REFERENCES column");

        // max_join_depth=0: a single expand column (Browse has no joins of
        // its own) already exceeds it.
        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows?expand=customer_id", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "expand column alone exceeds max_join_depth=0");
    }

    // 7. Single row: GET rows/{pk} -> object (INTEGER and TEXT PK parsed); PK
    //    parse error -> 400; missing row -> 404; ?expand= as in Row-Browse.
    #[tokio::test]
    async fn test_get_row_single() {
        let (app, _dir) = make_default_app().await;
        setup_customers_orders(&app).await;

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows/1", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], json!(1));
        assert_eq!(body["amount"], json!(10));

        let (status, _) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows/notanumber", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows/9999", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        sql(&app, "default", r#"{"sql": "CREATE TABLE tags (name TEXT PRIMARY KEY)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO tags VALUES ('alpha')"}"#).await;
        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/tags/rows/alpha", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], json!("alpha"));

        let (status, body) = req_json(
            &app,
            Method::GET,
            "/store-api/rel/default/tables/orders/rows/1?expand=customer_id",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["_expanded"]["customer_id"], json!({"id": 7, "name": "alice"}));
    }

    // 8. POST (INSERT): AUTOINCREMENT PK omitted -> 201 + Location + assigned
    //    last_pk; explicit PK accepted; NOT NULL -> 400; PK collision -> 409;
    //    missing REFERENCES target -> 409 (identical codes to /sql).
    #[tokio::test]
    async fn test_insert_row() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO customers VALUES (7, 'alice')"}"#).await;
        sql(
            &app,
            "default",
            r#"{"sql": "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER REFERENCES customers, amount INTEGER NOT NULL)"}"#,
        )
        .await;

        let (status, location, body) = req_json_with_location(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/orders/rows",
            Some(r#"{"customer_id": 7, "amount": 50}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["affected"], json!(1));
        let new_pk = body["last_pk"].as_i64().unwrap();
        assert_eq!(location.unwrap(), format!("/store-api/rel/default/tables/orders/rows/{new_pk}"));

        let (status, _, body) = req_json_with_location(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/orders/rows",
            Some(r#"{"id": 500, "customer_id": 7, "amount": 1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["last_pk"], json!(500));

        let (status, _, _) = req_json_with_location(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/orders/rows",
            Some(r#"{"customer_id": 7}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "amount NOT NULL, omitted, no default");

        let (status, _, _) = req_json_with_location(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/orders/rows",
            Some(r#"{"id": 500, "customer_id": 7, "amount": 1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "PK collision");

        let (status, _, _) = req_json_with_location(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/orders/rows",
            Some(r#"{"customer_id": 9999, "amount": 1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "missing REFERENCES target");
    }

    // 9. PUT (partial update): named column changed, others untouched;
    //    body-PK == path-PK allowed (not in SET); body-PK != path-PK -> 400;
    //    nonexistent PK -> 404; constraints as /sql UPDATE.
    #[tokio::test]
    async fn test_update_row_partial() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, 10, 'x')"}"#).await;

        let (status, body) =
            req_json(&app, Method::PUT, "/store-api/rel/default/tables/t/rows/1", Some(r#"{"a": 99}"#)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["affected"], json!(1));
        assert_eq!(body["last_pk"], Value::Null);
        let (_, row) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows/1", None).await;
        assert_eq!(row["a"], json!(99));
        assert_eq!(row["b"], json!("x"), "untouched column stays");

        let (status, _) = req_json(
            &app,
            Method::PUT,
            "/store-api/rel/default/tables/t/rows/1",
            Some(r#"{"id": 1, "a": 5}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body PK == path PK is allowed");

        let (status, _) = req_json(
            &app,
            Method::PUT,
            "/store-api/rel/default/tables/t/rows/1",
            Some(r#"{"id": 2, "a": 1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body PK != path PK");

        let (status, _) =
            req_json(&app, Method::PUT, "/store-api/rel/default/tables/t/rows/9999", Some(r#"{"a": 1}"#)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "PUT is not an upsert");
    }

    // 10. DELETE: existing row -> 200 + index entries gone; nonexistent -> 404.
    #[tokio::test]
    async fn test_delete_row() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER)"}"#).await;
        sql(&app, "default", r#"{"sql": "CREATE INDEX t_tag_idx ON t (tag)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, 5)"}"#).await;

        let (status, body) = req_json(&app, Method::DELETE, "/store-api/rel/default/tables/t/rows/1", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["affected"], json!(1));

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows/1", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, sql_body) = sql(&app, "default", r#"{"sql": "SELECT id FROM t WHERE tag = 5"}"#).await;
        assert_eq!(sql_body["rows"], json!([]), "index entries must be gone too");

        let (status, _) = req_json(&app, Method::DELETE, "/store-api/rel/default/tables/t/rows/1", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "already deleted");
    }

    // 11. Object serialization: TIMESTAMP -> ISO-8601 "…Z", NULL -> null;
    //     a column literally named "_expanded" is shadowed by the resolved
    //     block once expand is active.
    #[tokio::test]
    async fn test_row_object_serialization() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, ts TIMESTAMP, note TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, '2024-03-05T12:30:45.500Z', NULL)"}"#).await;

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows/1", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ts"], json!("2024-03-05T12:30:45.500Z"));
        assert_eq!(body["note"], Value::Null);
        assert_eq!(body["id"], json!(1));
        assert_eq!(body.as_object().unwrap().len(), 3);

        sql(&app, "default", r#"{"sql": "CREATE TABLE parent (id INTEGER PRIMARY KEY)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO parent VALUES (1)"}"#).await;
        sql(
            &app,
            "default",
            r#"{"sql": "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent, _expanded TEXT)"}"#,
        )
        .await;
        sql(&app, "default", r#"{"sql": "INSERT INTO child VALUES (1, 1, 'own value')"}"#).await;
        let (status, body) = req_json(
            &app,
            Method::GET,
            "/store-api/rel/default/tables/child/rows/1?expand=parent_id",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["_expanded"],
            json!({"parent_id": {"id": 1}}),
            "the resolved block shadows the same-named column's own value"
        );
    }

    // 12. max_response_bytes: a Row-Browse response over a tiny cap -> 413.
    #[tokio::test]
    async fn test_max_response_bytes_413() {
        let (app, _dir) =
            make_app(Some(RelStoreConfig { max_response_bytes: 40, ..RelStoreConfig::default() })).await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, 'a reasonably long text value')"}"#).await;

        let (status, body) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows", None).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        let msg = body["_raw"].as_str().unwrap_or_default().to_lowercase();
        assert!(msg.contains("limit") || msg.contains("expand"), "{msg}");
    }

    // 13. Rate limit: GET draws the read bucket, POST/PUT/DELETE the write
    //     bucket (separate); exhaustion -> 429 + Retry-After.
    #[tokio::test]
    async fn test_rate_limit_429() {
        let (state, _dir) = make_state(Some(RelStoreConfig::default()), false).await;
        let engine = state.rel_engine.clone().unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;

        engine.drain_domain_budget_for_test("default", true);
        let (status, body) = req_json(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/t/rows",
            Some(r#"{"id": 1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows", None).await;
        assert_eq!(status, StatusCode::OK, "read bucket unaffected by a drained write bucket");

        engine.drain_domain_budget_for_test("default", false);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/store-api/rel/default/tables/t/rows")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "1");
    }

    // 14. Error mapping: one case each of 400/404/409 via Browse/Row
    //     endpoints (413/429 covered by their own dedicated tests above) —
    //     no new engine variant, all via the existing rel/009 match.
    #[tokio::test]
    async fn test_error_mapping_status_classes() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, tag INTEGER NOT NULL)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, 5)"}"#).await;

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/rows?ghost=1", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/ghost/rows", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = req_json(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/t/rows",
            Some(r#"{"id": 1, "tag": 1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    // 15. Disabled engine: rel Browse/Row paths are not registered at all (404).
    #[tokio::test]
    async fn test_disabled_engine_routes_absent() {
        let (app, _dir) = make_app(None).await;
        let (status, _) = request(&app, Method::GET, "/store-api/rel/default/tables", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = request(&app, Method::GET, "/store-api/rel/default/tables/t/rows", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = request(&app, Method::POST, "/store-api/rel/default/tables/t/rows", Some("{}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // 16. Same plan as /sql (regression, no second path): `?col=` browse
    //     yields the same row set as the equivalent SELECT; POST yields the
    //     same DmlResult/error codes as the equivalent INSERT.
    #[tokio::test]
    async fn test_same_plan_as_sql_regression() {
        let (app, _dir) = make_default_app().await;
        setup_customers_orders(&app).await;

        let (_, sql_body) =
            sql(&app, "default", r#"{"sql": "SELECT * FROM orders WHERE customer_id = 7 ORDER BY id"}"#).await;
        let (status, browse_body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/orders/rows?customer_id=7", None).await;
        assert_eq!(status, StatusCode::OK, "{browse_body}");
        let mut browse_ids: Vec<i64> =
            browse_body["rows"].as_array().unwrap().iter().map(|r| r["id"].as_i64().unwrap()).collect();
        browse_ids.sort();
        let sql_ids: Vec<i64> = sql_body["rows"].as_array().unwrap().iter().map(|r| r[0].as_i64().unwrap()).collect();
        assert_eq!(browse_ids, sql_ids);

        let (_, sql_dml) =
            sql(&app, "default", r#"{"sql": "INSERT INTO customers (id, name) VALUES (500, 'x')"}"#).await;
        let (status, rest_dml) = req_json(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/customers/rows",
            Some(r#"{"id": 501, "name": "y"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(sql_dml["affected"], rest_dml["affected"]);

        let (sql_status, _) =
            sql(&app, "default", r#"{"sql": "INSERT INTO customers (id, name) VALUES (500, 'dup')"}"#).await;
        let (rest_status, _) = req_json(
            &app,
            Method::POST,
            "/store-api/rel/default/tables/customers/rows",
            Some(r#"{"id": 501, "name": "dup"}"#),
        )
        .await;
        assert_eq!(sql_status, StatusCode::CONFLICT);
        assert_eq!(rest_status, StatusCode::CONFLICT, "same error code as the equivalent /sql INSERT");
    }

    // ── Spec general/017: rel object-count endpoint ──────────────────────────

    // Test 6: empty table -> 0; after 3 INSERT -> 3; after 1 DELETE -> 2.
    #[tokio::test]
    async fn test_count_rows_basic_lifecycle() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        let uri = "/store-api/rel/default/tables/t/count";

        let (status, body) = req_json(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["count"], json!(0));

        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1), (2), (3)"}"#).await;
        let (status, body) = req_json(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["count"], json!(3));

        sql(&app, "default", r#"{"sql": "DELETE FROM t WHERE id = 1"}"#).await;
        let (status, body) = req_json(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["count"], json!(2));
    }

    // Test 7: unknown table -> 404; a view -> 404, not 400 (proof that
    // count_rows resolves the schema via browse_table, the read-side
    // resolver, not the write path's require_table); unknown/deleting domain
    // -> 404/410; disabled engine -> the route doesn't exist at all.
    #[tokio::test]
    async fn test_count_rows_not_found_view_and_domain_errors() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        sql(&app, "default", r#"{"sql": "CREATE VIEW v AS SELECT * FROM t"}"#).await;

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/ghost/count", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/v/count", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a view has no count resource, not 400");

        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/ghost/tables/t/count", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown domain");

        request(&app, Method::POST, "/store-api/rel/domains", Some(r#"{"name": "gone"}"#)).await;
        request(&app, Method::DELETE, "/store-api/rel/domains/gone", None).await;
        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/gone/tables/t/count", None).await;
        assert_eq!(status, StatusCode::GONE, "deleting domain");

        let (app_disabled, _dir2) = make_app(None).await;
        let (status, _) =
            request(&app_disabled, Method::GET, "/store-api/rel/default/tables/t/count", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "rel engine disabled -> route absent");
    }

    // Test 8: exhausted read budget -> 429 via the check_budget path (same
    // mechanism as Row-Browse's own rate-limit test).
    #[tokio::test]
    async fn test_count_rows_rate_limit_429() {
        let (state, _dir) = make_state(Some(RelStoreConfig::default()), false).await;
        let engine = state.rel_engine.clone().unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;

        engine.drain_domain_budget_for_test("default", false);
        let (status, _) = req_json(&app, Method::GET, "/store-api/rel/default/tables/t/count", None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    // Test 9: the REST count matches `SELECT COUNT(*) FROM t` via `/sql` —
    // the residual-free branch of exec_count vs. count_rows, same numbers.
    #[tokio::test]
    async fn test_count_rows_matches_sql_count_star() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1), (2), (3), (4)"}"#).await;

        let (status, body) =
            req_json(&app, Method::GET, "/store-api/rel/default/tables/t/count", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (_, sql_body) = sql(&app, "default", r#"{"sql": "SELECT COUNT(*) FROM t"}"#).await;
        assert_eq!(body["count"], sql_body["rows"][0][0]);
    }

    // Test 10: a Read grant on the rel domain (`rel:{domain}` namespace)
    // allows the count; no grant -> 403.
    #[tokio::test]
    async fn test_count_rows_auth_scoping() {
        use crate::auth::{hash_api_key, AccessLevel, DomainPermission, UserRecord, UserRole};

        let (state, _dir) = make_state(Some(RelStoreConfig::default()), true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let send = |method: Method, uri: &str, body: Option<&str>, bearer: &str| {
            let mut builder = Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {bearer}"));
            let req = if let Some(b) = body {
                builder = builder.header("content-type", "application/json");
                builder.body(Body::from(b.to_string())).unwrap()
            } else {
                builder.body(Body::empty()).unwrap()
            };
            app.clone().oneshot(req)
        };

        let admin_key = "lura_test_admin_key";
        cache
            .upsert_user(UserRecord {
                name: "boss".to_string(),
                api_key_hash: hash_api_key(admin_key),
                role: UserRole::Admin,
                created_at: 0,
            })
            .await
            .unwrap();
        let resp = send(Method::POST, "/store-api/rel/domains", Some(r#"{"name": "shop"}"#), admin_key)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = send(
            Method::POST,
            "/store-api/rel/shop/sql",
            Some(r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#),
            admin_key,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let user_key = "lura_test_worker_key";
        cache
            .upsert_user(UserRecord {
                name: "worker".to_string(),
                api_key_hash: hash_api_key(user_key),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();

        let resp = send(Method::GET, "/store-api/rel/shop/tables/t/count", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no permission on rel:shop yet");

        cache
            .set_permission(DomainPermission {
                username: "worker".to_string(),
                domain: "rel:shop".to_string(),
                access: AccessLevel::Read,
            })
            .await
            .unwrap();
        let resp = send(Method::GET, "/store-api/rel/shop/tables/t/count", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Read grant must allow the count");
    }
}
