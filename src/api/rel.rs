//! `/sql` REST handler + `RelStoreError` → HTTP mapping (spec rel/009).
//!
//! POST /store-api/rel/{domain}/sql — executes exactly one LuraSQL statement
//! (200 | 400 | 404 | 409 | 410 | 413 | 429 | 503).

use crate::api::{middleware::ApiError, AppState};
use crate::auth::middleware::{enforce_sql_level, AuthOutcome};
use crate::auth::AccessLevel;
use crate::engines::rel::{
    scalar_to_json, ColumnType, DmlResult, RelEngine, RelStoreError, SqlOutcome, StatementClass,
};
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use utoipa::ToSchema;

// ── Error mapping (spec rel/009 §8) ──────────────────────────────────────────

impl From<RelStoreError> for ApiError {
    fn from(e: RelStoreError) -> Self {
        let status = match &e {
            // 400 — frontend/DDL/DML/SELECT/JOIN/expand input errors.
            RelStoreError::StatementTooLong { .. }
            | RelStoreError::EmptyStatement
            | RelStoreError::MultipleStatements
            | RelStoreError::Syntax { .. }
            | RelStoreError::NullComparison { .. }
            | RelStoreError::ParameterCountMismatch { .. }
            | RelStoreError::InvalidSchema(_)
            | RelStoreError::TypeMismatch { .. }
            | RelStoreError::LimitExceeded { .. }
            | RelStoreError::InvalidDomainName(_)
            | RelStoreError::InvalidIdentifier(_)
            | RelStoreError::NotWritable { .. }
            | RelStoreError::NotNull { .. }
            | RelStoreError::PrimaryKeyImmutable { .. }
            | RelStoreError::TextTooLong { .. }
            | RelStoreError::RowTooLarge { .. }
            | RelStoreError::KeyTooLong { .. }
            | RelStoreError::SortBufferExceeded { .. }
            | RelStoreError::JoinDepthExceeded { .. }
            | RelStoreError::UnindexedJoin { .. }
            | RelStoreError::UnindexedJoinScanExceeded { .. }
            | RelStoreError::AmbiguousColumn { .. }
            | RelStoreError::InvalidExpand(_) => StatusCode::BAD_REQUEST,
            // 404 — domain/table/column/index/object not found.
            RelStoreError::DomainNotFound(_)
            | RelStoreError::TableNotFound { .. }
            | RelStoreError::ColumnNotFound { .. }
            | RelStoreError::IndexNotFound { .. }
            | RelStoreError::ObjectNotFound { .. } => StatusCode::NOT_FOUND,
            // 409 — name collisions, uniqueness/link/dependency conflicts.
            RelStoreError::DomainAlreadyExists(_)
            | RelStoreError::TableAlreadyExists { .. }
            | RelStoreError::ColumnAlreadyExists { .. }
            | RelStoreError::IndexAlreadyExists { .. }
            | RelStoreError::ColumnIndexedOrPrimaryKey { .. }
            | RelStoreError::DuplicateKey { .. }
            | RelStoreError::UniqueViolation { .. }
            | RelStoreError::LinkTargetMissing { .. }
            | RelStoreError::SequenceExhausted { .. }
            | RelStoreError::ObjectAlreadyExists { .. }
            | RelStoreError::ViewDependencyConflict { .. }
            | RelStoreError::CrossEngineTargetUnavailable { .. }
            | RelStoreError::CrossEngineLinkMissing { .. } => StatusCode::CONFLICT,
            // 410 — domain marked for deletion (rel/013 purges it later).
            RelStoreError::DomainDeleting(_) => StatusCode::GONE,
            // 429 — per-domain request budget exhausted (rel/009 §7).
            RelStoreError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            // 500 — practically-unreachable resource exhaustion, or a wrapped
            // serialization/storage error (spec's "any otherwise
            // unclassified variant").
            RelStoreError::IdSpaceExhausted(_)
            | RelStoreError::SerializationError(_)
            | RelStoreError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::new(status, e.to_string())
    }
}

/// Resolves the rel engine or fails with 503 when `rel.enabled = false`. With
/// conditional router registration (`create_router`, spec §1) the rel routes
/// don't even exist in that case, so this never actually fires in normal
/// operation — kept as a defensive guard (parity with `json_engine`) in case
/// a path is ever reachable while `rel_engine` is `None`.
pub(crate) fn rel_engine(state: &AppState) -> Result<&Arc<RelEngine>, ApiError> {
    state.rel_engine.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "503 Service Unavailable: relational engine is disabled (rel.enabled = false)",
        )
    })
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SqlRequest {
    /// Exactly one LuraSQL statement (more → 400 `MultipleStatements`, rel/004).
    pub sql: String,
    /// Positional parameters (JSON array), bound to the `?` placeholders
    /// (rel/004/005). Omitted ⇒ empty array.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub params: Vec<Value>,
    /// REFERENCES columns to resolve into embedded objects, or `["*"]` for
    /// all of them (§5). Only valid for SELECT; non-empty on DML/DDL → 400.
    #[serde(default)]
    pub expand: Vec<String>,
}

// ── Wire serialization (spec §3/§4) ─────────────────────────────────────────

/// Canonical wire type name (`ColumnType` → `columns[i].type`, spec §4).
/// `pub(super)`: reused by the catalog-browse DTOs (rel/010 `rel_browse.rs`).
pub(super) fn column_type_name(t: ColumnType) -> &'static str {
    match t {
        ColumnType::Integer => "INTEGER",
        ColumnType::Real => "REAL",
        ColumnType::Text => "TEXT",
        ColumnType::Boolean => "BOOLEAN",
        ColumnType::Timestamp => "TIMESTAMP",
        ColumnType::KvRef => "KVREF",
        ColumnType::JsonRef => "JSONREF",
    }
}

/// Builds the `200 OK` body for a statement's `SqlOutcome`, in the response
/// shape its class dictates (spec §3): DDL `{"ok":true}`; DML
/// `{"affected","last_pk"}`; SELECT `{"columns","rows","row_count",
/// "limit_applied","expanded"?}` — rows as **arrays** (not objects), since
/// same-named columns from a JOIN (`l.id`/`r.id`) would collide as object keys.
fn build_response(outcome: SqlOutcome) -> Value {
    match outcome {
        SqlOutcome::Ddl => json!({ "ok": true }),
        SqlOutcome::Dml(r) => dml_result_json(&r),
        SqlOutcome::Select { result, expanded } => {
            let columns: Vec<Value> = result
                .columns
                .iter()
                .map(|(name, ty)| json!({ "name": name, "type": column_type_name(*ty) }))
                .collect();
            let rows: Vec<Value> = result
                .rows
                .iter()
                .map(|row| Value::Array(row.iter().map(scalar_to_json).collect()))
                .collect();
            let mut body = json!({
                "columns": columns,
                "row_count": result.rows.len(),
                "limit_applied": result.limit_applied,
                "rows": rows,
            });
            // Present only when at least one column was actually resolved (§5).
            if let Some(expanded) = expanded {
                let expanded_obj: serde_json::Map<String, Value> =
                    expanded.into_iter().map(|(name, values)| (name, Value::Array(values))).collect();
                body.as_object_mut()
                    .expect("body is always a JSON object")
                    .insert("expanded".to_string(), Value::Object(expanded_obj));
            }
            body
        }
    }
}

/// Wire form of a `DmlResult` (spec §3): `{"affected","last_pk"}`. `pub(super)`:
/// reused as-is by the row-write handlers (rel/010 `rel_browse.rs`) for
/// POST/PUT/DELETE responses.
pub(super) fn dml_result_json(r: &DmlResult) -> Value {
    json!({
        "affected": r.affected,
        "last_pk": r.last_pk.as_ref().map(scalar_to_json).unwrap_or(Value::Null),
    })
}

// ── Handler ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/rel/{domain}/sql",
    params(("domain" = String, Path, description = "Relational domain")),
    request_body = SqlRequest,
    responses(
        (status = 200, description = "Statement result. Shape depends on the statement class — \
            DDL: {\"ok\":true}; INSERT/UPDATE/DELETE: {\"affected\",\"last_pk\"}; SELECT: \
            {\"columns\":[{\"name\",\"type\"}],\"rows\":[[...]],\"row_count\",\"limit_applied\",\
            \"expanded\"?}. `rows` are arrays (not objects) so same-named JOIN columns don't collide.",
            body = Object),
        (status = 400, description = "Syntax, type, parameter-count, or expand error"),
        (status = 403, description = "Access level too low for this statement (rel/011)"),
        (status = 404, description = "Domain, table, column, or index not found"),
        (status = 409, description = "Conflict — duplicate key, unique violation, name collision, …"),
        (status = 410, description = "Domain is being deleted"),
        (status = 413, description = "Response exceeds max_response_bytes"),
        (status = 429, description = "Per-domain request budget exceeded"),
        (status = 503, description = "Relational engine disabled"),
    ),
    tag = "Relational Store"
)]
/// Executes exactly one LuraSQL statement against `domain` and returns its
/// typed result. `expand` resolves REFERENCES columns of a SELECT into
/// embedded objects (or `"*"` for every REFERENCES column).
pub async fn execute_sql(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    Json(body): Json<SqlRequest>,
) -> Result<Json<Value>, ApiError> {
    let engine = rel_engine(&state)?;

    // rel/011 auth seam: classify (parse-only) then enforce the exact
    // statement-class level *before* execute_sql runs it — this is the real
    // authorization, since the middleware only demanded Read for `/sql`.
    // Doubles the parse (classify + execute_sql's own); accepted (rel/011 §4/§9).
    let required = match engine.classify(&body.sql)? {
        StatementClass::Read => AccessLevel::Read,
        StatementClass::Write => AccessLevel::Write,
        StatementClass::Ddl => AccessLevel::Ddl,
    };
    enforce_sql_level(state.auth_enabled, auth_outcome.map(|Extension(o)| o), required)
        .map_err(|resp| ApiError::new(resp.status(), "Forbidden"))?;

    let outcome = engine.execute_sql(&domain, &body.sql, &body.params, &body.expand).await?;
    let response = build_response(outcome);

    // 413 (spec §6): a handler-side check after serialization, not an
    // `RelStoreError` variant — mirrors other handler-side `ApiError::new`
    // cases (json.rs).
    let size = serde_json::to_vec(&response)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .len();
    if size > engine.max_response_bytes() {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "413 Payload Too Large: response exceeds max_response_bytes; reduce LIMIT",
        ));
    }
    Ok(Json(response))
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
    use axum::response::IntoResponse;
    use tower::util::ServiceExt;

    /// `rel_config = None` ⇒ `rel.enabled = false`; `Some(cfg)` ⇒ enabled
    /// with `cfg`'s limits (paths are always freshly assigned into a temp dir).
    /// `auth_enabled` toggles the auth middleware layer (rel/011 tests need it on).
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
                // KV wired (same instance AppState uses), JSON disabled in this
                // harness — enough for KVREF DDL/expand; JSONREF is covered by
                // the rel/012 tests in cross_engine.rs.
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
        };
        (state, dir)
    }

    async fn make_app(rel_config: Option<RelStoreConfig>) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = make_state(rel_config, false).await;
        (crate::api::create_router(state, Arc::new(vec![])), dir)
    }

    /// The default rel config, enabled.
    async fn make_default_app() -> (axum::Router, tempfile::TempDir) {
        make_app(Some(RelStoreConfig::default())).await
    }

    async fn request(app: &axum::Router, method: Method, uri: &str, body: Option<&str>) -> (StatusCode, String) {
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

    async fn sql(app: &axum::Router, domain: &str, body: &str) -> (StatusCode, Value) {
        let (status, text) = request(app, Method::POST, &format!("/store-api/rel/{domain}/sql"), Some(body)).await;
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"_raw": text}));
        (status, value)
    }

    // 1. Domain roundtrip: create → 201; list contains it with state=active;
    //    detail → 200; duplicate → 409; invalid names → 400.
    #[tokio::test]
    async fn test_domain_roundtrip() {
        let (app, _dir) = make_default_app().await;
        let (status, body) =
            request(&app, Method::POST, "/store-api/rel/domains", Some(r#"{"name": "shop"}"#)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let created: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(created["state"], json!("active"));

        let (status, body) = request(&app, Method::GET, "/store-api/rel/domains", None).await;
        assert_eq!(status, StatusCode::OK);
        let list: Value = serde_json::from_str(&body).unwrap();
        let entry = list.as_array().unwrap().iter().find(|d| d["name"] == json!("shop")).unwrap();
        assert_eq!(entry["state"], json!("active"));

        let (status, _) = request(&app, Method::GET, "/store-api/rel/domains/shop", None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) =
            request(&app, Method::POST, "/store-api/rel/domains", Some(r#"{"name": "shop"}"#)).await;
        assert_eq!(status, StatusCode::CONFLICT);

        for bad in [r#"{"name": "bad name!"}"#, r#"{"name": "domains"}"#] {
            let (status, body) = request(&app, Method::POST, "/store-api/rel/domains", Some(bad)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        }
    }

    // 2. Domain delete: DELETE → 202; detail afterwards → 410 with status
    //    info; SQL against the deleted domain → 410 (require_active).
    #[tokio::test]
    async fn test_domain_delete_then_410() {
        let (app, _dir) = make_default_app().await;
        request(&app, Method::POST, "/store-api/rel/domains", Some(r#"{"name": "gone"}"#)).await;

        let (status, _) = request(&app, Method::DELETE, "/store-api/rel/domains/gone", None).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let (status, body) = request(&app, Method::GET, "/store-api/rel/domains/gone", None).await;
        assert_eq!(status, StatusCode::GONE, "{body}");
        assert!(body.contains("deleting"), "{body}");

        let (status, body) = sql(&app, "gone", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        assert_eq!(status, StatusCode::GONE, "{body}");

        // A repeated DELETE of an already-deleting domain is also 410.
        let (status, _) = request(&app, Method::DELETE, "/store-api/rel/domains/gone", None).await;
        assert_eq!(status, StatusCode::GONE);
    }

    // 3. DDL: CREATE TABLE -> 200 {"ok":true}; unknown domain -> 404;
    //    Deleting domain -> 410.
    #[tokio::test]
    async fn test_ddl_response_and_errors() {
        let (app, _dir) = make_default_app().await;
        let (status, body) =
            sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"ok": true}));

        let (status, _) = sql(&app, "ghost", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        request(&app, Method::POST, "/store-api/rel/domains", Some(r#"{"name": "d1"}"#)).await;
        request(&app, Method::DELETE, "/store-api/rel/domains/d1", None).await;
        let (status, _) = sql(&app, "d1", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        assert_eq!(status, StatusCode::GONE);
    }

    // 4. DML response forms: single-row INSERT -> affected/last_pk; multi-row
    //    -> last_pk null; UPDATE/DELETE -> affected; PK collision -> 409;
    //    NOT NULL violation -> 400.
    #[tokio::test]
    async fn test_dml_response_forms() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)"}"#).await;

        let (status, body) = sql(&app, "default", r#"{"sql": "INSERT INTO t (name) VALUES ('a')"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"affected": 1, "last_pk": 1}));

        let (status, body) =
            sql(&app, "default", r#"{"sql": "INSERT INTO t (name) VALUES ('b'), ('c')"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({"affected": 2, "last_pk": null}));

        let (status, body) =
            sql(&app, "default", r#"{"sql": "UPDATE t SET name = 'z' WHERE id = 1"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["affected"], json!(1));

        let (status, body) = sql(&app, "default", r#"{"sql": "DELETE FROM t WHERE id = 1"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["affected"], json!(1));

        let (status, _) =
            sql(&app, "default", r#"{"sql": "INSERT INTO t (id, name) VALUES (2, 'dup')"}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = sql(&app, "default", r#"{"sql": "INSERT INTO t (id) VALUES (99)"}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // 5. SELECT response shape: canonical types; rows as arrays; row_count /
    //    limit_applied; same-named JOIN columns yield two entries.
    #[tokio::test]
    async fn test_select_response_shape() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE l (id INTEGER PRIMARY KEY, name TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE r (id INTEGER PRIMARY KEY, note TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO l VALUES (1, 'a')"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO r VALUES (1, 'x')"}"#).await;

        let (status, body) = sql(&app, "default", r#"{"sql": "SELECT * FROM l"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["columns"],
            json!([{"name": "id", "type": "INTEGER"}, {"name": "name", "type": "TEXT"}])
        );
        assert_eq!(body["rows"], json!([[1, "a"]]));
        assert_eq!(body["row_count"], json!(1));
        assert_eq!(body["limit_applied"], json!(false));

        let (status, body) =
            sql(&app, "default", r#"{"sql": "SELECT l.id, r.id FROM l LEFT JOIN r ON l.id = r.id"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["columns"], json!([{"name": "id", "type": "INTEGER"}, {"name": "id", "type": "INTEGER"}]));
        assert_eq!(body["rows"], json!([[1, 1]]));
    }

    // 6. params: positional binding; wrong count -> 400; NULL comparison ->
    //    400; TIMESTAMP as ISO string and as millis store the same value.
    #[tokio::test]
    async fn test_params_binding() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER, ts TIMESTAMP)"}"#)
            .await;

        let (status, body) =
            sql(&app, "default", r#"{"sql": "INSERT INTO t (id, v) VALUES (?, ?)", "params": [1, 42]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) =
            sql(&app, "default", r#"{"sql": "SELECT v FROM t WHERE id = ?", "params": [1]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"], json!([[42]]));

        let (status, _) =
            sql(&app, "default", r#"{"sql": "SELECT v FROM t WHERE id = ?", "params": []}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = sql(&app, "default", r#"{"sql": "SELECT v FROM t WHERE v = ?", "params": [null]}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        sql(&app, "default", r#"{"sql": "INSERT INTO t (id, ts) VALUES (2, '2024-01-01T00:00:00Z')"}"#).await;
        sql(
            &app,
            "default",
            r#"{"sql": "INSERT INTO t (id, ts) VALUES (3, ?)", "params": [1704067200000]}"#,
        )
        .await;
        let (_, body) = sql(&app, "default", r#"{"sql": "SELECT ts FROM t WHERE id = 2 OR id = 3 ORDER BY id"}"#).await;
        assert_eq!(body["rows"][0], body["rows"][1], "ISO string and millis must store the same value");
    }

    // 7. TIMESTAMP output: ISO-8601 UTC string with Z; roundtrip stable;
    //    NULL -> null.
    #[tokio::test]
    async fn test_timestamp_output_roundtrip() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, ts TIMESTAMP)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, '2024-03-05T12:30:45.500Z')"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (2, NULL)"}"#).await;

        let (status, body) = sql(&app, "default", r#"{"sql": "SELECT ts FROM t WHERE id = 1"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let first = body["rows"][0][0].as_str().unwrap().to_string();
        assert_eq!(first, "2024-03-05T12:30:45.500Z");

        // Roundtrip: feed the emitted string back in as a param, expect the
        // exact same output again.
        let (_, body2) = sql(
            &app,
            "default",
            &format!(r#"{{"sql": "SELECT ts FROM t WHERE ts = ?", "params": ["{first}"]}}"#),
        )
        .await;
        assert_eq!(body2["rows"][0][0], json!(first));

        let (_, body_null) = sql(&app, "default", r#"{"sql": "SELECT ts FROM t WHERE id = 2"}"#).await;
        assert_eq!(body_null["rows"][0][0], Value::Null);
    }

    // 8. COUNT(*): one column {"name":"count","type":"INTEGER"}, one row [n].
    #[tokio::test]
    async fn test_count_star_response() {
        let (app, _dir) = make_default_app().await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1), (2), (3)"}"#).await;

        let (status, body) = sql(&app, "default", r#"{"sql": "SELECT COUNT(*) FROM t"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["columns"], json!([{"name": "count", "type": "INTEGER"}]));
        assert_eq!(body["rows"], json!([[3]]));
    }

    /// `orders.customer_id` REFERENCES `customers`: INSERT validates the link
    /// target exists (rel/005), so a "dangling link" row can only be created
    /// by inserting against a *real* row and deleting it afterwards — not by
    /// inserting a bad id directly (that fails the INSERT itself, tolerant
    /// links are about deletes, not constraint bypass; concept 3.4).
    async fn setup_orders(app: &axum::Router) {
        sql(app, "default", r#"{"sql": "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)"}"#).await;
        sql(
            app,
            "default",
            r#"{"sql": "CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers, payload KVREF)"}"#,
        )
        .await;
        sql(app, "default", r#"{"sql": "INSERT INTO customers VALUES (7, 'alice'), (99, 'ghost')"}"#).await;
        // payload (KVREF) is NULL here: cross-engine writes are now validated
        // (rel/012 §2) and no KV keys are seeded in this harness — real KVREF
        // resolution is covered by the rel/012 tests in cross_engine.rs.
        let (status, body) = sql(
            app,
            "default",
            r#"{"sql": "INSERT INTO orders VALUES (1, 7, NULL), (2, NULL, NULL), (3, 99, NULL)"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "setup insert must succeed: {body}");
        // No FK-based delete restriction (concept 3.4) — this leaves order 3's
        // customer_id=99 as a genuine hanging link.
        let (status, body) = sql(app, "default", r#"{"sql": "DELETE FROM customers WHERE id = 99"}"#).await;
        assert_eq!(status, StatusCode::OK, "setup delete must succeed: {body}");
    }

    // 9. expand REFERENCES point lookup: resolved object; NULL link -> null;
    //    dangling link (target row missing) -> null.
    #[tokio::test]
    async fn test_expand_references_point_lookup() {
        let (app, _dir) = make_default_app().await;
        setup_orders(&app).await;

        let (status, body) = sql(
            &app,
            "default",
            r#"{"sql": "SELECT * FROM orders ORDER BY id", "expand": ["customer_id"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let expanded = &body["expanded"]["customer_id"];
        assert_eq!(expanded[0], json!({"id": 7, "name": "alice"}));
        assert_eq!(expanded[1], Value::Null, "NULL link");
        assert_eq!(expanded[2], Value::Null, "dangling link (customer 999 doesn't exist)");
    }

    // 10. expand "*": resolves every projected link column — REFERENCES *and*
    //     KVREF/JSONREF (rel/012 no longer skips them). payload is NULL on all
    //     rows here, so it resolves to null entries.
    #[tokio::test]
    async fn test_expand_wildcard() {
        let (app, _dir) = make_default_app().await;
        setup_orders(&app).await;

        let (status, body) =
            sql(&app, "default", r#"{"sql": "SELECT * FROM orders ORDER BY id", "expand": ["*"]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["expanded"]["customer_id"][0], json!({"id": 7, "name": "alice"}));
        assert_eq!(
            body["expanded"]["payload"], json!([null, null, null]),
            "KVREF column is now resolved by wildcard (rel/012): {body}"
        );
    }

    // 11. expand KVREF explicitly named now resolves (rel/012 live) — no
    //     longer a 400 CrossEngineExpand.
    #[tokio::test]
    async fn test_expand_cross_engine_explicit_resolves() {
        let (app, _dir) = make_default_app().await;
        setup_orders(&app).await;

        let (status, body) =
            sql(&app, "default", r#"{"sql": "SELECT * FROM orders ORDER BY id", "expand": ["payload"]}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["expanded"]["payload"], json!([null, null, null]), "{body}");
    }

    // 12. expand validation: unknown/non-projected column -> 400; non-link
    //     column -> 400; expand on DML -> 400.
    #[tokio::test]
    async fn test_expand_validation_errors() {
        let (app, _dir) = make_default_app().await;
        setup_orders(&app).await;

        let (status, _) =
            sql(&app, "default", r#"{"sql": "SELECT id FROM orders", "expand": ["customer_id"]}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "customer_id isn't projected here");

        let (status, _) =
            sql(&app, "default", r#"{"sql": "SELECT * FROM orders", "expand": ["nope"]}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = sql(&app, "default", r#"{"sql": "SELECT * FROM orders", "expand": ["id"]}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "id is not a REFERENCES column");

        let (status, _) = sql(
            &app,
            "default",
            r#"{"sql": "INSERT INTO customers VALUES (1, 'x')", "expand": ["id"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "expand is only valid for SELECT");
        // The rejected INSERT must not have committed regardless (checked
        // *before* dispatch/execution, not after — a client seeing 400 must
        // not have unknowingly written data).
        let (_, count_body) = sql(&app, "default", r#"{"sql": "SELECT COUNT(*) FROM customers WHERE id = 1"}"#).await;
        assert_eq!(count_body["rows"], json!([[0]]), "expand-on-DML must reject before executing, not after");
    }

    // 13. max_join_depth accounting: JOINs + expand columns over the limit ->
    //     400 JoinDepthExceeded.
    #[tokio::test]
    async fn test_expand_max_join_depth() {
        let (app, _dir) = make_app(Some(RelStoreConfig { max_join_depth: 1, ..RelStoreConfig::default() })).await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE b (id INTEGER PRIMARY KEY)"}"#).await;
        sql(
            &app,
            "default",
            r#"{"sql": "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b)"}"#,
        )
        .await;
        sql(&app, "default", r#"{"sql": "INSERT INTO b VALUES (1)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO a VALUES (1, 1)"}"#).await;

        // The join alone is within max_join_depth=1.
        let (status, body) =
            sql(&app, "default", r#"{"sql": "SELECT a.id, a.b_id FROM a LEFT JOIN b ON a.b_id = b.id"}"#).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // +1 expand column pushes 1 (join) + 1 (expand) = 2 over max=1.
        let (status, body) = sql(
            &app,
            "default",
            r#"{"sql": "SELECT a.id, a.b_id FROM a LEFT JOIN b ON a.b_id = b.id", "expand": ["b_id"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    // 14. max_response_bytes: a response (incl. expanded) over the cap -> 413
    //     with a LIMIT hint.
    #[tokio::test]
    async fn test_max_response_bytes_413() {
        let (app, _dir) =
            make_app(Some(RelStoreConfig { max_response_bytes: 40, ..RelStoreConfig::default() })).await;
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)"}"#).await;
        sql(&app, "default", r#"{"sql": "INSERT INTO t VALUES (1, 'a reasonably long text value')"}"#).await;

        let (status, body) = sql(&app, "default", r#"{"sql": "SELECT * FROM t"}"#).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        let msg = body["_raw"].as_str().unwrap_or_default();
        assert!(msg.to_lowercase().contains("limit"), "{msg}");
    }

    // 15. Rate limit: draining the domain's write budget -> 429 with
    //     Retry-After; SELECT draws the read bucket, DML/DDL the write
    //     bucket (separate — one draining does not affect the other);
    //     record_rate_limit_rejection increments.
    #[tokio::test]
    async fn test_rate_limit_429() {
        let (state, _dir) = make_state(Some(RelStoreConfig::default()), false).await;
        let engine = state.rel_engine.clone().unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));
        sql(&app, "default", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#).await;

        // Drain the write bucket and lock its refill (default 500 write
        // IOPS) via drain_for_test — deterministically 429 regardless of
        // scheduler/CPU load, and still needs no new config knob (spec §12
        // explicitly rules one out).
        engine.drain_domain_budget_for_test("default", true);

        // A SELECT (read bucket) must still go through — separate buckets.
        let (status, body) = sql(&app, "default", r#"{"sql": "SELECT * FROM t"}"#).await;
        assert_eq!(status, StatusCode::OK, "read bucket must be unaffected by a drained write bucket: {body}");

        let req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/rel/default/sql")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"sql": "INSERT INTO t VALUES (1)"}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "1");

        // Now drain read too, confirming SELECT gets rejected on its own bucket.
        engine.drain_domain_budget_for_test("default", false);
        let (status, _) = sql(&app, "default", r#"{"sql": "SELECT * FROM t"}"#).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    // 16. Error mapping: one case per status class via /sql and the domain
    //     endpoints.
    #[tokio::test]
    async fn test_error_mapping_status_classes() {
        let (app, _dir) = make_default_app().await;
        // 400
        let (status, _) = sql(&app, "default", r#"{"sql": ""}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // 404
        let (status, _) = sql(&app, "default", r#"{"sql": "SELECT * FROM ghost_table"}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // 409
        sql(&app, "default", r#"{"sql": "CREATE TABLE dup (id INTEGER PRIMARY KEY)"}"#).await;
        let (status, _) = sql(&app, "default", r#"{"sql": "CREATE TABLE dup (id INTEGER PRIMARY KEY)"}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);
        // 410
        request(&app, Method::POST, "/store-api/rel/domains", Some(r#"{"name": "d410"}"#)).await;
        request(&app, Method::DELETE, "/store-api/rel/domains/d410", None).await;
        let (status, _) = sql(&app, "d410", r#"{"sql": "CREATE TABLE x (id INTEGER PRIMARY KEY)"}"#).await;
        assert_eq!(status, StatusCode::GONE);
        // 413 and 429 are covered by their own dedicated tests (need custom config/state).
    }

    // 17. Disabled engine: rel paths are not registered at all (404, axum
    //     default for an unmatched route); the `rel_engine` guard itself
    //     answers 503 when called directly (defensive path).
    #[tokio::test]
    async fn test_disabled_engine_routes_absent_and_guard_503() {
        let (app, _dir) = make_app(None).await;
        let (status, _) = request(&app, Method::GET, "/store-api/rel/domains", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "route must not exist when rel.enabled = false");
        let (status, _) = sql(&app, "default", r#"{"sql": "SELECT 1"}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (state, _dir2) = make_state(None, false).await;
        match rel_engine(&state) {
            Ok(_) => panic!("rel_engine guard must fail when rel_engine is None"),
            Err(err) => assert_eq!(err.into_response().status(), StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    // 18. Exactly one statement: "...;..." -> 400 MultipleStatements; empty
    //     sql -> 400 EmptyStatement.
    #[tokio::test]
    async fn test_exactly_one_statement() {
        let (app, _dir) = make_default_app().await;
        let (status, _) = sql(
            &app,
            "default",
            r#"{"sql": "CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY)"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = sql(&app, "default", r#"{"sql": ""}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // rel/011 §8 item 8: middleware auth over real rel routes. A Read grant
    // passes a SELECT via /sql (the middleware's /sql exception only demands
    // Read) but the handler's enforce_sql_level still blocks DDL — that's the
    // actual authorization (Masterplan contradiction 4). A Read grant is
    // rejected on the path-based row-write route; no permission -> 403;
    // Admin/TrustedPeer bypass both checks via AuthOutcome::Full.
    #[tokio::test]
    async fn test_auth_rel_domain_scoping() {
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

        // Admin sets up the domain and a table (worker below won't have DDL).
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

        // Regular user, Read-only grant on the rel domain (namespace "rel:shop").
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
                domain: "rel:shop".to_string(),
                access: AccessLevel::Read,
            })
            .await
            .unwrap();

        // SELECT via /sql: middleware's /sql exception requires only Read,
        // and the handler's enforce_sql_level(Read >= Read) passes too.
        let resp = send(Method::POST, "/store-api/rel/shop/sql", Some(r#"{"sql": "SELECT * FROM t"}"#), user_key)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Path-based row write needs Write; a Read grant isn't enough (rel/010 route).
        let resp = send(Method::POST, "/store-api/rel/shop/tables/t/rows", Some(r#"{"id": 1}"#), user_key)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // DDL via /sql: middleware passes (Read minimum), but enforce_sql_level
        // requires Ddl > granted Read -> 403. This is the real authorization.
        let resp = send(
            Method::POST,
            "/store-api/rel/shop/sql",
            Some(r#"{"sql": "CREATE TABLE t2 (id INTEGER PRIMARY KEY)"}"#),
            user_key,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // No rel permission at all -> 403.
        let outsider_key = "lura_test_outsider_key";
        cache
            .upsert_user(UserRecord {
                name: "outsider".to_string(),
                api_key_hash: hash_api_key(outsider_key),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        let resp = send(Method::POST, "/store-api/rel/shop/sql", Some(r#"{"sql": "SELECT * FROM t"}"#), outsider_key)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Admin bypasses both checks (AuthOutcome::Full), even for DDL.
        let resp = send(
            Method::POST,
            "/store-api/rel/shop/sql",
            Some(r#"{"sql": "CREATE TABLE t3 (id INTEGER PRIMARY KEY)"}"#),
            admin_key,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // TrustedPeer bypasses too (Full) — insert the marker directly, since
        // there's no UDS listener in this harness (perf/001; json.rs pattern).
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/rel/shop/sql")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"sql": "CREATE TABLE t4 (id INTEGER PRIMARY KEY)"}"#))
            .unwrap();
        req.extensions_mut().insert(crate::auth::middleware::TrustedPeer);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // rel/011 §8 item 9: set_permission accepts access="ddl" and
    // store_type="rel" without requiring the domain to exist yet; an invalid
    // access value -> 400; remove_permission with ?store_type=rel removes it.
    #[tokio::test]
    async fn test_auth_handlers_rel_ddl_permission() {
        use crate::auth::{hash_api_key, AccessLevel, UserRecord, UserRole};

        let (state, _dir) = make_state(Some(RelStoreConfig::default()), true).await;
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
        cache
            .upsert_user(UserRecord {
                name: "worker".to_string(),
                api_key_hash: hash_api_key("lura_test_worker_key"),
                role: UserRole::User,
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

        // Invalid access value -> 400.
        let resp = send(
            Method::POST,
            "/store-api/auth/users/worker/permissions",
            Some(r#"{"domain": "shop", "access": "xxx", "store_type": "rel"}"#),
            admin_key,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // "ddl" + "rel", domain doesn't exist yet -> still 200 (no existence check).
        let resp = send(
            Method::POST,
            "/store-api/auth/users/worker/permissions",
            Some(r#"{"domain": "shop", "access": "ddl", "store_type": "rel"}"#),
            admin_key,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(cache.get_permission("worker", "rel:shop").await, Some(AccessLevel::Ddl));

        // Removing it via ?store_type=rel drops the rel:shop entry.
        let resp = send(
            Method::DELETE,
            "/store-api/auth/users/worker/permissions/shop?store_type=rel",
            None,
            admin_key,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(cache.get_permission("worker", "rel:shop").await, None);
    }
}
