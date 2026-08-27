//! JSON-store REST handlers (spec json/009): documents, indexes, search,
//! bulk load/export, re-indexing.

use crate::api::{middleware::ApiError, AppState, CountResponse};
use crate::engines::json::bulk::{document_to_ndjson_line, document_to_value};
use crate::engines::json::query::DEFAULT_LIMIT;
use crate::engines::json::{
    etag_value, ExpectedVersion, FilterCondition, IndexDefinition, IndexFieldType, JsonEngine,
    JsonStoreError, ListOptions, SearchQuery,
};
use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use utoipa::ToSchema;

// ── Error mapping (spec json/009 §6) ─────────────────────────────────────────

impl From<JsonStoreError> for ApiError {
    fn from(e: JsonStoreError) -> Self {
        let status = match &e {
            JsonStoreError::DocumentNotFound { .. } => StatusCode::NOT_FOUND,
            JsonStoreError::DomainNotFound(_) => StatusCode::NOT_FOUND,
            JsonStoreError::DomainDeleting(_) => StatusCode::GONE,
            JsonStoreError::DomainAlreadyExists(_) => StatusCode::CONFLICT,
            JsonStoreError::InvalidDomainName(_) => StatusCode::BAD_REQUEST,
            JsonStoreError::InvalidKey(_) => StatusCode::BAD_REQUEST,
            JsonStoreError::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            JsonStoreError::IndexAlreadyExists { .. } => StatusCode::CONFLICT,
            // Deleting a missing index is a 404; the search handler
            // pre-translates unindexed filter fields to 400 itself.
            JsonStoreError::IndexNotFound { .. } => StatusCode::NOT_FOUND,
            JsonStoreError::InvalidIndexField(_) => StatusCode::BAD_REQUEST,
            JsonStoreError::InvalidFilter(_) => StatusCode::BAD_REQUEST,
            JsonStoreError::ReindexInProgress { .. } => StatusCode::CONFLICT,
            JsonStoreError::VersionConflict { .. } => StatusCode::CONFLICT,
            JsonStoreError::SerializationError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            JsonStoreError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::new(status, e.to_string())
    }
}

/// Resolves the JSON engine or fails with 503 when `json.enabled = false`.
pub(crate) fn json_engine(state: &AppState) -> Result<&Arc<JsonEngine>, ApiError> {
    state.json_engine.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "503 Service Unavailable: JSON engine is disabled (json.enabled = false)",
        )
    })
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateIndexRequest {
    /// JSON field path, dot notation for nested fields (e.g. "address.city").
    pub field: String,
    /// Value type: "string" | "number" | "boolean".
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Serialize, ToSchema)]
pub struct IndexResponse {
    pub field: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub created_at: u64,
}

impl From<IndexDefinition> for IndexResponse {
    fn from(d: IndexDefinition) -> Self {
        let field_type = match d.field_type {
            IndexFieldType::String => "string",
            IndexFieldType::Number => "number",
            IndexFieldType::Boolean => "boolean",
        };
        IndexResponse { field: d.field, field_type: field_type.to_string(), created_at: d.created_at }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SearchRequest {
    /// Field → value (Eq) or `{"$gt": …}` / `$gte` / `$lt` / `$lte` / `$eq`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub filter: serde_json::Map<String, Value>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct SearchResponse {
    /// Matching documents incl. `_key`/`_version` metadata.
    #[schema(value_type = Vec<Object>)]
    pub documents: Vec<Value>,
    pub total: u64,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Serialize, ToSchema)]
pub struct BulkErrorEntry {
    /// Document key or "line N" for parse errors.
    pub key: String,
    pub error: String,
}

#[derive(Serialize, ToSchema)]
pub struct BulkLoadResponse {
    pub imported: u64,
    pub failed: u64,
    pub errors: Vec<BulkErrorEntry>,
}

#[derive(Deserialize, ToSchema)]
pub struct ListParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub keys_only: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct DocumentListResponse {
    /// Loaded documents incl. `_key`/`_version` (empty when keys_only).
    #[schema(value_type = Vec<Object>)]
    pub documents: Vec<Value>,
    /// Document keys of the page.
    pub keys: Vec<String>,
    pub total: u64,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Deserialize, ToSchema, Default)]
pub struct ReindexRequest {
    /// Optional: re-index only this field's index. Omit for all indexes.
    pub field: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ReindexAcceptedResponse {
    pub task_id: String,
}

/// Reads the optional `If-Match: "<etag>"` header (RFC 7232, json/011). The
/// ETag is the opaque `{generation:x}-{version}` value from a prior read.
fn parse_if_match(headers: &HeaderMap) -> Result<Option<ExpectedVersion>, ApiError> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let raw = value.to_str().map_err(|_| {
        ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: invalid If-Match header")
    })?;
    let trimmed = raw.trim().trim_matches('"');
    trimmed
        .split_once('-')
        .and_then(|(g, v)| {
            Some(ExpectedVersion {
                generation: u64::from_str_radix(g, 16).ok()?,
                version: v.parse().ok()?,
            })
        })
        .map(Some)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("400 Bad Request: If-Match must be an ETag from a prior read, got '{raw}'"),
            )
        })
}

// ── Document CRUD ─────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/json/{domain}/documents",
    params(("domain" = String, Path, description = "JSON domain")),
    request_body = Object,
    responses(
        (status = 201, description = "Document created with generated UUIDv4 key"),
        (status = 404, description = "Domain not found"),
        (status = 413, description = "Payload too large"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Stores a document under a system-generated UUIDv4 key (create-only).
pub async fn create_document(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(content): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let engine = json_engine(&state)?;
    let doc = engine.create_document(&domain, content).await?;
    Ok((StatusCode::CREATED, Json(document_to_value(&doc))))
}

#[utoipa::path(
    put,
    path = "/store-api/json/{domain}/documents/{key}",
    params(
        ("domain" = String, Path, description = "JSON domain"),
        ("key" = String, Path, description = "Document key"),
    ),
    request_body = Object,
    responses(
        (status = 200, description = "Document updated"),
        (status = 201, description = "Document created"),
        (status = 400, description = "Invalid key or If-Match header"),
        (status = 404, description = "Domain not found, or If-Match on missing document"),
        (status = 409, description = "Version conflict (If-Match mismatch)"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Upserts a document. With an `If-Match: "<etag>"` header the write is a
/// conditional update that fails with 409 on a version mismatch.
pub async fn put_document(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
    headers: HeaderMap,
    Json(content): Json<Value>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let engine = json_engine(&state)?;
    let expected_version = parse_if_match(&headers)?;
    let doc = engine
        .put_document_with_version(&domain, &key, content, expected_version)
        .await?;
    let status = if doc.version == 1 { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(document_to_value(&doc))))
}

#[utoipa::path(
    get,
    path = "/store-api/json/{domain}/documents/{key}",
    params(
        ("domain" = String, Path, description = "JSON domain"),
        ("key" = String, Path, description = "Document key"),
    ),
    responses(
        (status = 200, description = "Document content with _key/_version metadata"),
        (status = 404, description = "Document or domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Reads a document; `_key`/`_version` are top-level fields and an opaque
/// `ETag` is exposed for use with `If-Match` (json/011).
pub async fn get_document(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let engine = json_engine(&state)?;
    let doc = engine.get_document(&domain, &key).await?.ok_or_else(|| {
        JsonStoreError::DocumentNotFound { domain: domain.clone(), key: key.clone() }
    })?;
    let etag = format!("\"{}\"", etag_value(doc.generation, doc.version));
    Ok(([(header::ETAG, etag)], Json(document_to_value(&doc))).into_response())
}

#[utoipa::path(
    delete,
    path = "/store-api/json/{domain}/documents/{key}",
    params(
        ("domain" = String, Path, description = "JSON domain"),
        ("key" = String, Path, description = "Document key"),
    ),
    responses(
        (status = 204, description = "Document deleted"),
        (status = 404, description = "Document or domain not found"),
        (status = 409, description = "Version conflict (If-Match mismatch)"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Deletes a document and its index entries. Supports conditional delete via
/// `If-Match: "<etag>"`.
pub async fn delete_document(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let engine = json_engine(&state)?;
    let expected_version = parse_if_match(&headers)?;
    if engine
        .delete_document_with_version(&domain, &key, expected_version)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(JsonStoreError::DocumentNotFound { domain, key }.into())
    }
}

#[utoipa::path(
    get,
    path = "/store-api/json/{domain}/documents",
    params(
        ("domain" = String, Path, description = "JSON domain"),
        ("limit" = Option<u32>, Query, description = "Page size (default 50, max 1000)"),
        ("offset" = Option<u32>, Query, description = "Documents to skip"),
        ("keys_only" = Option<bool>, Query, description = "Return only keys, no content"),
    ),
    responses(
        (status = 200, description = "Paginated document list", body = DocumentListResponse),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Lists documents of a domain without filters (natural key order).
pub async fn list_documents(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<DocumentListResponse>, ApiError> {
    let engine = json_engine(&state)?;
    let options = ListOptions {
        limit: params.limit.unwrap_or(DEFAULT_LIMIT),
        offset: params.offset.unwrap_or(0),
        keys_only: params.keys_only.unwrap_or(false),
    };
    let result = engine.list_documents(&domain, options).await?;
    Ok(Json(DocumentListResponse {
        documents: result.documents.iter().map(document_to_value).collect(),
        keys: result.keys,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

#[utoipa::path(
    get,
    path = "/store-api/json/{domain}/documents/count",
    params(("domain" = String, Path, description = "JSON domain")),
    responses(
        (status = 200, description = "Document count", body = CountResponse),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Counts all documents of a domain (key scan only).
pub async fn count_documents(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<CountResponse>, ApiError> {
    let engine = json_engine(&state)?;
    let count = engine.count_documents(&domain).await?;
    Ok(Json(CountResponse { count }))
}

// ── Index management ─────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/json/{domain}/indexes",
    params(("domain" = String, Path, description = "JSON domain")),
    request_body = CreateIndexRequest,
    responses(
        (status = 201, description = "Index definition created", body = IndexResponse),
        (status = 400, description = "Invalid field or type"),
        (status = 409, description = "Index already exists"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Indexes"
)]
/// Creates an index definition. Existing documents are NOT back-indexed —
/// trigger a re-index for that.
pub async fn create_index(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(body): Json<CreateIndexRequest>,
) -> Result<(StatusCode, Json<IndexResponse>), ApiError> {
    let engine = json_engine(&state)?;
    let field_type = match body.field_type.as_str() {
        "string" => IndexFieldType::String,
        "number" => IndexFieldType::Number,
        "boolean" => IndexFieldType::Boolean,
        other => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("400 Bad Request: unknown index type '{other}' (string|number|boolean)"),
            ))
        }
    };
    let def = engine.create_index(&domain, &body.field, field_type).await?;
    Ok((StatusCode::CREATED, Json(def.into())))
}

#[utoipa::path(
    get,
    path = "/store-api/json/{domain}/indexes",
    params(("domain" = String, Path, description = "JSON domain")),
    responses(
        (status = 200, description = "Index definitions of the domain", body = Vec<IndexResponse>),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Indexes"
)]
/// Lists all index definitions of a domain.
pub async fn list_indexes(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Vec<IndexResponse>>, ApiError> {
    let engine = json_engine(&state)?;
    let defs = engine.get_indexes(&domain)?;
    Ok(Json(defs.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    delete,
    path = "/store-api/json/{domain}/indexes/{field}",
    params(
        ("domain" = String, Path, description = "JSON domain"),
        ("field" = String, Path, description = "Indexed field path"),
    ),
    responses(
        (status = 204, description = "Index definition removed"),
        (status = 404, description = "Index or domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Indexes"
)]
/// Removes an index definition.
pub async fn delete_index(
    State(state): State<AppState>,
    Path((domain, field)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let engine = json_engine(&state)?;
    engine.delete_index(&domain, &field).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Search ────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/json/{domain}/search",
    params(("domain" = String, Path, description = "JSON domain")),
    request_body = SearchRequest,
    responses(
        (status = 200, description = "Matching documents", body = SearchResponse),
        (status = 400, description = "Invalid filter or unindexed field"),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Searches documents via indexed fields. Filters: `"field": value` for
/// equality or `"field": {"$gt": …}` for ranges; multiple fields are ANDed.
pub async fn search_documents(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(body): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, ApiError> {
    let engine = json_engine(&state)?;
    let query = build_search_query(body)?;
    let result = engine.search_documents(&domain, query).await.map_err(|e| match e {
        JsonStoreError::IndexNotFound { domain, field } => ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("400 Bad Request: field '{field}' is not indexed in domain '{domain}'"),
        ),
        other => other.into(),
    })?;
    Ok(Json(SearchResponse {
        documents: result.documents.iter().map(document_to_value).collect(),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

fn build_search_query(req: SearchRequest) -> Result<SearchQuery, ApiError> {
    let mut filters = HashMap::new();
    for (field, value) in req.filter {
        let condition = match &value {
            Value::Object(map) if map.keys().any(|k| k.starts_with('$')) => {
                if map.len() != 1 {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        format!("400 Bad Request: filter for '{field}' must contain exactly one operator"),
                    ));
                }
                let (op, operand) = map.iter().next().unwrap();
                match op.as_str() {
                    "$eq" => FilterCondition::Eq(operand.clone()),
                    "$gt" => FilterCondition::Gt(operand.clone()),
                    "$gte" => FilterCondition::Gte(operand.clone()),
                    "$lt" => FilterCondition::Lt(operand.clone()),
                    "$lte" => FilterCondition::Lte(operand.clone()),
                    other => {
                        return Err(ApiError::new(
                            StatusCode::BAD_REQUEST,
                            format!("400 Bad Request: unknown filter operator '{other}'"),
                        ))
                    }
                }
            }
            _ => FilterCondition::Eq(value.clone()),
        };
        filters.insert(field, condition);
    }
    Ok(SearchQuery {
        filters,
        limit: req.limit.unwrap_or(DEFAULT_LIMIT),
        offset: req.offset.unwrap_or(0),
    })
}

// ── Bulk operations ───────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/json/{domain}/bulk",
    params(("domain" = String, Path, description = "JSON domain")),
    request_body(content = String, description = "NDJSON — one document per line, optional _key field"),
    responses(
        (status = 200, description = "Import summary", body = BulkLoadResponse),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Imports documents from an NDJSON body in atomic batches.
pub async fn bulk_load(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    body: String,
) -> Result<Json<BulkLoadResponse>, ApiError> {
    let engine = json_engine(&state)?;
    let result = engine.bulk_load_ndjson(&domain, &body).await?;
    Ok(Json(BulkLoadResponse {
        imported: result.imported,
        failed: result.failed,
        errors: result
            .errors
            .into_iter()
            .map(|(key, error)| BulkErrorEntry { key, error })
            .collect(),
    }))
}

#[utoipa::path(
    get,
    path = "/store-api/json/{domain}/export",
    params(("domain" = String, Path, description = "JSON domain")),
    responses(
        (status = 200, description = "NDJSON stream of all documents", content_type = "application/x-ndjson"),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Streams all documents of a domain as NDJSON without full buffering.
pub async fn export_documents(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Response, ApiError> {
    let engine = json_engine(&state)?;
    let stream = engine.bulk_export(&domain).await?;
    let body_stream = stream.map(|doc| {
        let mut line = document_to_ndjson_line(&doc);
        line.push('\n');
        Ok::<_, std::convert::Infallible>(Bytes::from(line))
    });
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(body_stream))
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(response)
}

// ── Re-indexing ───────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/json/{domain}/reindex",
    params(("domain" = String, Path, description = "JSON domain")),
    request_body(content = ReindexRequest, description = "Optional field restriction"),
    responses(
        (status = 202, description = "Re-index started", body = ReindexAcceptedResponse),
        (status = 400, description = "Malformed request body"),
        (status = 404, description = "Domain not found"),
        (status = 409, description = "Re-index already running for this domain"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Indexes"
)]
/// Starts a background re-index of the domain (all indexes, or one field).
pub async fn trigger_reindex(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Json<ReindexAcceptedResponse>), ApiError> {
    let engine = json_engine(&state)?;
    // Parsed manually: Option<Json<T>> (axum 0.7) maps EVERY rejection —
    // broken JSON, wrong types, missing content-type — to None, silently
    // turning a bad field-specific request into a full re-index.
    let request: ReindexRequest = if body.iter().all(u8::is_ascii_whitespace) {
        ReindexRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("400 Bad Request: invalid re-index body: {e}"),
            )
        })?
    };
    let result = match request.field {
        Some(field) => engine.reindex_index(&domain, &field)?,
        None => engine.reindex_domain(&domain)?,
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(ReindexAcceptedResponse { task_id: result.task_id }),
    ))
}

#[utoipa::path(
    get,
    path = "/store-api/json/{domain}/reindex/{task_id}",
    params(
        ("domain" = String, Path, description = "JSON domain"),
        ("task_id" = String, Path, description = "Re-index task id"),
    ),
    responses(
        (status = 200, description = "Current re-index status"),
        (status = 404, description = "Unknown task id for this domain"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Indexes"
)]
/// Returns the status of a re-index task. Tasks are domain-scoped: a task id
/// of another domain answers 404 (tenant isolation).
pub async fn reindex_status(
    State(state): State<AppState>,
    Path((domain, task_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let engine = json_engine(&state)?;
    let status = engine.get_reindex_status(&domain, &task_id).ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: unknown re-index task '{task_id}'"))
    })?;
    let value = serde_json::to_value(&status)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JsonStoreConfig;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::storage::{file_manager::FileManager, manifest::ManifestManager, vlog::VLog};
    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use serde_json::json;
    use tower::util::ServiceExt;

    async fn make_state(
        json_enabled: bool,
        auth_enabled: bool,
    ) -> (AppState, tempfile::TempDir) {
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
        let json_engine = if json_enabled {
            let config = JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("json_sst").to_string_lossy().into_owned(),
                reindex_pause_ms: 0,
                ..JsonStoreConfig::default()
            };
            Some(JsonEngine::bootstrap(&config).await.unwrap())
        } else {
            None
        };
        let auth_cache = Arc::new(crate::auth::AuthCache::new(Arc::clone(&engine)));
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            DomainRegistry::recover(engine, DomainConfig::default(), Arc::clone(&metrics))
                .await
                .unwrap(),
        );
        let state = AppState {
            registry,
            auth_cache,
            auth_enabled,
            metrics,
            json_engine,
            rel_engine: None,
            shm_manager: None,
            backup_manager: None,
            log_access: None,
            event_bus: Arc::new(crate::core::events::GlobalEventBus::new(256, 1024)),
        };
        (state, dir)
    }

    async fn make_app(json_enabled: bool) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = make_state(json_enabled, false).await;
        (crate::api::create_router(state, Arc::new(vec![])), dir)
    }

    async fn request(
        app: &axum::Router,
        method: Method,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        let req = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(b.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    // 1. POST document → 201 with generated _key, GET roundtrip.
    #[tokio::test]
    async fn test_post_document_roundtrip() {
        let (app, _dir) = make_app(true).await;
        let (status, body) = request(
            &app, Method::POST, "/store-api/json/default/documents",
            Some(r#"{"city": "Essen"}"#),
        ).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let created: Value = serde_json::from_str(&body).unwrap();
        let key = created["_key"].as_str().unwrap();
        assert_eq!(key.len(), 36);
        assert_eq!(created["_version"], json!(1));

        let (status, body) = request(
            &app, Method::GET, &format!("/store-api/json/default/documents/{key}"), None,
        ).await;
        assert_eq!(status, StatusCode::OK);
        let fetched: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(fetched["city"], json!("Essen"));
    }

    // 2. PUT → 201 on create, 200 on update, version increments.
    #[tokio::test]
    async fn test_put_document_upsert() {
        let (app, _dir) = make_app(true).await;
        let uri = "/store-api/json/default/documents/k1";
        let (status, _) = request(&app, Method::PUT, uri, Some(r#"{"n": 1}"#)).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, body) = request(&app, Method::PUT, uri, Some(r#"{"n": 2}"#)).await;
        assert_eq!(status, StatusCode::OK);
        let doc: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["_version"], json!(2));
    }

    // 3. DELETE → 204, then GET/DELETE → 404.
    #[tokio::test]
    async fn test_delete_document() {
        let (app, _dir) = make_app(true).await;
        let uri = "/store-api/json/default/documents/gone";
        request(&app, Method::PUT, uri, Some("{}")).await;
        let (status, _) = request(&app, Method::DELETE, uri, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = request(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = request(&app, Method::DELETE, uri, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // 4. Index create → 201, duplicate → 409, bad type → 400.
    #[tokio::test]
    async fn test_index_endpoints() {
        let (app, _dir) = make_app(true).await;
        let uri = "/store-api/json/default/indexes";
        let body = r#"{"field": "city", "type": "string"}"#;
        let (status, _) = request(&app, Method::POST, uri, Some(body)).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = request(&app, Method::POST, uri, Some(body)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = request(&app, Method::POST, uri, Some(r#"{"field": "x", "type": "uuid"}"#)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, body) = request(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK);
        let list: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        let (status, _) = request(&app, Method::DELETE, "/store-api/json/default/indexes/city", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = request(&app, Method::DELETE, "/store-api/json/default/indexes/city", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // 5. Search over an indexed field; unindexed filter → 400.
    #[tokio::test]
    async fn test_search_endpoint() {
        let (app, _dir) = make_app(true).await;
        request(&app, Method::POST, "/store-api/json/default/indexes",
            Some(r#"{"field": "city", "type": "string"}"#)).await;
        request(&app, Method::PUT, "/store-api/json/default/documents/a",
            Some(r#"{"city": "Essen"}"#)).await;
        request(&app, Method::PUT, "/store-api/json/default/documents/b",
            Some(r#"{"city": "Berlin"}"#)).await;
        let (status, body) = request(&app, Method::POST, "/store-api/json/default/search",
            Some(r#"{"filter": {"city": "Essen"}}"#)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let result: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(result["total"], json!(1));
        assert_eq!(result["documents"][0]["_key"], json!("a"));
        let (status, _) = request(&app, Method::POST, "/store-api/json/default/search",
            Some(r#"{"filter": {"nope": 1}}"#)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // 6. Bulk load returns the import summary.
    #[tokio::test]
    async fn test_bulk_endpoint() {
        let (app, _dir) = make_app(true).await;
        let ndjson = "{\"_key\": \"b1\", \"n\": 1}\n{\"_key\": \"b2\", \"n\": 2}\nnot-json\n";
        let (status, body) = request(&app, Method::POST, "/store-api/json/default/bulk", Some(ndjson)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let result: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(result["imported"], json!(2));
        assert_eq!(result["failed"], json!(1));
    }

    // 7. Export streams NDJSON.
    #[tokio::test]
    async fn test_export_endpoint() {
        let (app, _dir) = make_app(true).await;
        request(&app, Method::PUT, "/store-api/json/default/documents/e1", Some(r#"{"n": 1}"#)).await;
        request(&app, Method::PUT, "/store-api/json/default/documents/e2", Some(r#"{"n": 2}"#)).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/store-api/json/default/export")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-ndjson"
        );
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| serde_json::from_str::<Value>(l).is_ok()));
    }

    // 8. Re-index: 202 with task id, status reaches completed.
    #[tokio::test]
    async fn test_reindex_endpoint() {
        let (app, _dir) = make_app(true).await;
        request(&app, Method::PUT, "/store-api/json/default/documents/r1", Some(r#"{"city": "Essen"}"#)).await;
        request(&app, Method::POST, "/store-api/json/default/indexes",
            Some(r#"{"field": "city", "type": "string"}"#)).await;
        let (status, body) = request(&app, Method::POST, "/store-api/json/default/reindex", None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let accepted: Value = serde_json::from_str(&body).unwrap();
        let task_id = accepted["task_id"].as_str().unwrap().to_string();

        let uri = format!("/store-api/json/default/reindex/{task_id}");
        for _ in 0..200 {
            let (status, body) = request(&app, Method::GET, &uri, None).await;
            assert_eq!(status, StatusCode::OK);
            let s: Value = serde_json::from_str(&body).unwrap();
            if s["state"] == json!("completed") {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("re-index did not complete");
    }

    // 8b. Malformed re-index bodies → 400 instead of silently starting a
    //     full re-index; whitespace-only bodies still mean "all indexes".
    #[tokio::test]
    async fn test_reindex_invalid_body_rejected() {
        let (app, _dir) = make_app(true).await;
        let uri = "/store-api/json/default/reindex";
        let (status, body) = request(&app, Method::POST, uri, Some(r#"{"field": 123}"#)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = request(&app, Method::POST, uri, Some("not-json")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = request(&app, Method::POST, uri, Some(" \n\t")).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    }

    // 8c. Re-index status is domain-scoped: a task id queried under another
    //     domain answers 404 (tenant isolation), under its own domain 200.
    #[tokio::test]
    async fn test_reindex_status_scoped_to_domain() {
        let (app, _dir) = make_app(true).await;
        request(&app, Method::POST, "/store-api/json/domains", Some(r#"{"name": "other"}"#)).await;
        let (status, body) = request(&app, Method::POST, "/store-api/json/default/reindex", None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let task_id = serde_json::from_str::<Value>(&body).unwrap()["task_id"]
            .as_str().unwrap().to_string();
        let (status, _) = request(
            &app, Method::GET, &format!("/store-api/json/other/reindex/{task_id}"), None,
        ).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = request(
            &app, Method::GET, &format!("/store-api/json/default/reindex/{task_id}"), None,
        ).await;
        assert_eq!(status, StatusCode::OK);
    }

    // 6b. Bulk bodies beyond axum's 2 MB default pass (bulk_body_limit_bytes).
    //     Lines fail per-document validation, so no big engine writes happen —
    //     the point is that the request is not cut off with 413.
    #[tokio::test]
    async fn test_bulk_body_over_default_limit_accepted() {
        let (app, _dir) = make_app(true).await;
        let line = format!("{{\"pad\": \"{}\"}}\n", "x".repeat(600 * 1024));
        let body = line.repeat(5); // ~3 MB
        let (status, resp) =
            request(&app, Method::POST, "/store-api/json/default/bulk", Some(&body)).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let result: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(result["imported"], json!(0));
        assert_eq!(result["failed"], json!(5));
    }

    // 9. Disabled engine → 503 on every JSON route.
    #[tokio::test]
    async fn test_disabled_engine_returns_503() {
        let (app, _dir) = make_app(false).await;
        let (status, body) = request(&app, Method::GET, "/store-api/json/domains", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("disabled"), "{body}");
        let (status, _) = request(&app, Method::GET, "/store-api/json/default/documents/x", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // 11. Listing and counting endpoints (spec json/010).
    #[tokio::test]
    async fn test_listing_and_count_endpoints() {
        let (app, _dir) = make_app(true).await;
        for i in 0..5 {
            request(&app, Method::PUT, &format!("/store-api/json/default/documents/x{i}"),
                Some(r#"{"a": 1}"#)).await;
        }
        let (status, body) = request(
            &app, Method::GET,
            "/store-api/json/default/documents?limit=2&offset=1", None,
        ).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let list: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["total"], json!(5));
        assert_eq!(list["keys"].as_array().unwrap().len(), 2);
        assert_eq!(list["documents"].as_array().unwrap().len(), 2);

        let (status, body) = request(
            &app, Method::GET,
            "/store-api/json/default/documents?keys_only=true", None,
        ).await;
        assert_eq!(status, StatusCode::OK);
        let list: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list["keys"].as_array().unwrap().len(), 5);
        assert!(list["documents"].as_array().unwrap().is_empty());

        let (status, body) = request(
            &app, Method::GET, "/store-api/json/default/documents/count", None,
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["count"], json!(5));

        // Domain detail includes the document count.
        let (status, body) = request(&app, Method::GET, "/store-api/json/domains/default", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["document_count"], json!(5));
    }

    /// GET the document and return its ETag header value (with quotes).
    async fn fetch_etag(app: &axum::Router, uri: &str) -> String {
        let req = Request::builder().method(Method::GET).uri(uri).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.headers().get(header::ETAG).unwrap().to_str().unwrap().to_string()
    }

    // 12. ETag/If-Match: conditional update and delete (spec json/011).
    #[tokio::test]
    async fn test_etag_if_match_flow() {
        let (app, _dir) = make_app(true).await;
        let uri = "/store-api/json/default/documents/occ";
        request(&app, Method::PUT, uri, Some(r#"{"n": 1}"#)).await;

        // ETag is the opaque "{generation:x}-{version}" value.
        let etag_v1 = fetch_etag(&app, uri).await;
        assert!(
            etag_v1.starts_with('"') && etag_v1.ends_with("-1\""),
            "unexpected ETag format: {etag_v1}"
        );
        let generation = etag_v1.trim_matches('"').split_once('-').unwrap().0.to_string();

        let req = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("content-type", "application/json")
            .header("if-match", etag_v1.clone())
            .body(Body::from(r#"{"n": 2}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Stale If-Match → 409 with the actual ETag value in the body.
        let req = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("content-type", "application/json")
            .header("if-match", etag_v1.clone())
            .body(Body::from(r#"{"n": 3}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains(&format!("actual \"{generation}-2\"")), "{body}");

        // Legacy bare-version If-Match values are rejected as 400.
        let req = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("content-type", "application/json")
            .header("if-match", "\"2\"")
            .body(Body::from(r#"{"n": 3}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .header("if-match", etag_v1)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .header("if-match", format!("\"{generation}-2\""))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // 15. ABA guard (json/011): a stale ETag of a deleted incarnation must
    //     not match after delete + recreate of the same key.
    #[tokio::test]
    async fn test_stale_etag_across_recreate_rejected() {
        let (app, _dir) = make_app(true).await;
        let uri = "/store-api/json/default/documents/aba";
        request(&app, Method::PUT, uri, Some(r#"{"n": 1}"#)).await;
        let stale_etag = fetch_etag(&app, uri).await;

        let (status, _) = request(&app, Method::DELETE, uri, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = request(&app, Method::PUT, uri, Some(r#"{"n": 2}"#)).await;
        assert_eq!(status, StatusCode::CREATED, "recreate starts at version 1 again");

        let req = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("content-type", "application/json")
            .header("if-match", stale_etag.clone())
            .body(Body::from(r#"{"n": 3}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "stale ETag must not match the new incarnation"
        );

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .header("if-match", stale_etag)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let (status, body) = request(&app, Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(r#""n":2"#), "lost update must not happen: {body}");
    }

    // 13. Auth scoping: KV permissions do not grant JSON access (spec json/012).
    #[tokio::test]
    async fn test_auth_scoping_kv_vs_json() {
        use crate::auth::{hash_api_key, AccessLevel, DomainPermission, UserRecord, UserRole};

        let (state, _dir) = make_state(true, true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let user_key = "lura_test_user_key";
        cache
            .upsert_user(UserRecord {
                name: "worker".to_string(),
                api_key_hash: hash_api_key(user_key),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        // KV write permission on "default" — but NO JSON permission.
        cache
            .set_permission(DomainPermission {
                username: "worker".to_string(),
                domain: "default".to_string(),
                access: AccessLevel::Write,
            })
            .await
            .unwrap();

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

        // KV path resolves the permission (extract_domain fix): 404, not 403.
        let resp = send(Method::GET, "/store-api/kv/default/keys/nope", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Same domain name in the JSON store is NOT covered by the KV permission.
        let resp = send(Method::GET, "/store-api/json/default/documents", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Read permission on the JSON namespace: search works, bulk does not.
        cache
            .set_permission(DomainPermission {
                username: "worker".to_string(),
                domain: "json:default".to_string(),
                access: AccessLevel::Read,
            })
            .await
            .unwrap();
        let resp = send(Method::POST, "/store-api/json/default/search",
            Some(r#"{"filter": {}}"#), user_key).await.unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN, "search must pass with read permission");
        let resp = send(Method::POST, "/store-api/json/default/bulk", Some("{}"), user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "bulk needs write permission");

        // Write permission unlocks bulk; domain management stays admin-only.
        cache
            .set_permission(DomainPermission {
                username: "worker".to_string(),
                domain: "json:default".to_string(),
                access: AccessLevel::Write,
            })
            .await
            .unwrap();
        let resp = send(Method::POST, "/store-api/json/default/bulk",
            Some(r#"{"_key": "a", "n": 1}"#), user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(Method::GET, "/store-api/json/domains", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Admin has full access everywhere.
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
        let resp = send(Method::GET, "/store-api/json/domains", None, admin_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 16. Domain management is admin-only for write methods (spec kv/012):
    //     a write permission on a domain must not allow purging it.
    #[tokio::test]
    async fn test_auth_scoping_domain_management_admin_only() {
        use crate::auth::{hash_api_key, AccessLevel, DomainPermission, UserRecord, UserRole};

        let (state, _dir) = make_state(false, true).await;
        let cache = Arc::clone(&state.auth_cache);
        let registry = Arc::clone(&state.registry);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        registry.create_domain("orders").await.unwrap();

        let user_key = "lura_test_user_key";
        cache
            .upsert_user(UserRecord {
                name: "worker".to_string(),
                api_key_hash: hash_api_key(user_key),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        cache
            .set_permission(DomainPermission {
                username: "worker".to_string(),
                domain: "orders".to_string(),
                access: AccessLevel::Write,
            })
            .await
            .unwrap();

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

        // Reading domain metadata stays open to permission holders …
        let resp = send(Method::GET, "/store-api/domains/orders", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // … but the destructive purge is admin-only despite write permission.
        let resp = send(Method::DELETE, "/store-api/domains/orders", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Creating domains stays admin-only too.
        let resp = send(Method::POST, "/store-api/domains",
            Some(r#"{"name": "own"}"#), user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // The domain must still exist (no purge was started).
        let resp = send(Method::GET, "/store-api/domains/orders", None, user_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Admins keep full domain-lifecycle access.
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
        let resp = send(Method::DELETE, "/store-api/domains/orders", None, admin_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    // 17. Usernames and JSON permission domains share the domain charset:
    //     ':' in a username would make the persisted perm key ambiguous,
    //     invalid JSON domain names would create dead permissions.
    #[tokio::test]
    async fn test_auth_name_and_permission_domain_validation() {
        use crate::auth::{hash_api_key, UserRecord, UserRole};

        let (state, _dir) = make_state(false, true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

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

        // ':' in a username collides with the perm-key separator → 400.
        let resp = send(Method::POST, "/store-api/auth/users",
            Some(r#"{"name": "svc:json"}"#), admin_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // The full allowed charset is accepted.
        let resp = send(Method::POST, "/store-api/auth/users",
            Some(r#"{"name": "svc-json_1"}"#), admin_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // JSON permissions skip the existence check but not the name rules.
        let resp = send(Method::POST, "/store-api/auth/users/svc-json_1/permissions",
            Some(r#"{"domain": "my data", "access": "read", "store_type": "json"}"#),
            admin_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = send(Method::POST, "/store-api/auth/users/svc-json_1/permissions",
            Some(r#"{"domain": "data", "access": "read", "store_type": "json"}"#),
            admin_key).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 14. TrustedPeer extension (UDS UCred bypass, perf/001) skips bearer auth.
    #[tokio::test]
    async fn test_trusted_peer_bypasses_auth() {
        let (state, _dir) = make_state(true, true).await;
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/store-api/json/domains")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/store-api/json/domains")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(crate::auth::middleware::TrustedPeer);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 10. JSON domain endpoints.
    #[tokio::test]
    async fn test_json_domain_endpoints() {
        let (app, _dir) = make_app(true).await;
        let (status, _) = request(&app, Method::POST, "/store-api/json/domains",
            Some(r#"{"name": "api-dom"}"#)).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, body) = request(&app, Method::GET, "/store-api/json/domains", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("api-dom"));
        let (status, _) = request(&app, Method::GET, "/store-api/json/domains/api-dom", None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = request(&app, Method::DELETE, "/store-api/json/domains/api-dom", None).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        // While the purge runs, the domain answers 410 Gone (spec json/013).
        let (status, body) = request(&app, Method::GET, "/store-api/json/domains/api-dom", None).await;
        assert_eq!(status, StatusCode::GONE, "{body}");
        let (status, _) = request(&app, Method::PUT, "/store-api/json/api-dom/documents/x", Some("{}")).await;
        assert_eq!(status, StatusCode::GONE);
    }
}
