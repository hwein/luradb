//! Create-Table-from-File REST handler (spec rel/019).
//!
//! POST /store-api/rel/{domain}/tables/from-file -- uploads a CSV/TSV file,
//! creates a new relational table with inferred column types, and imports
//! its rows in one request; the rel counterpart of the JSON bulk load
//! (json/007).

use crate::api::rel::{column_type_name, rel_engine};
use crate::api::{middleware::ApiError, AppState};
use crate::auth::middleware::{enforce_sql_level, AuthOutcome};
use crate::auth::AccessLevel;
use crate::engines::rel::{FileFormat, RelEngine, RelStoreError};
use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;
use std::collections::HashMap;
use utoipa::ToSchema;

/// Charges one op against the domain's write budget (spec rel/009 §7), same
/// as every other rel handler (`rel_browse.rs`'s own `check_budget`).
fn check_budget(engine: &RelEngine, state: &AppState, domain: &str) -> Result<(), ApiError> {
    if engine.check_domain_budget(domain, true) {
        Ok(())
    } else {
        state.metrics.record_rate_limit_rejection(domain);
        Err(RelStoreError::RateLimited { domain: domain.to_string() }.into())
    }
}

// ── DTOs (spec §5) ───────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct CreateFromFileColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
    pub primary_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_header: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateFromFileErrorEntry {
    pub row: u64,
    pub error: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreateFromFileResponse {
    pub table: String,
    pub columns: Vec<CreateFromFileColumn>,
    pub imported: u64,
    pub failed: u64,
    pub errors: Vec<CreateFromFileErrorEntry>,
}

// ── Handler ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/rel/{domain}/tables/from-file",
    params(
        ("domain" = String, Path, description = "Relational domain"),
        ("name" = String, Query, description = "Name of the table to create"),
        ("format" = String, Query, description = "\"csv\" or \"tsv\" -- no format sniffing"),
        ("header" = Option<bool>, Query, description = "Whether the first line is a header row (default true)"),
        ("pk" = Option<String>, Query, description = "Existing (normalized) column to use as primary key; omitted -> synthetic `_row` column"),
    ),
    request_body(content = String, description = "Raw CSV/TSV file bytes -- Content-Type is not enforced, `format` decides"),
    responses(
        (status = 201, description = "Table created and its rows imported (imported/failed counts, per-row error log)", body = CreateFromFileResponse),
        (status = 400, description = "Missing/invalid name or format, empty file, too many columns, invalid header UTF-8, or an unknown pk column", body = String, content_type = "text/plain"),
        (status = 403, description = "Missing DDL access on the domain", body = String, content_type = "text/plain"),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 409, description = "A table or view with that name already exists", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
        (status = 413, description = "Body exceeds rel.import_body_limit_bytes", body = String, content_type = "text/plain"),
        (status = 429, description = "Per-domain request budget exceeded", body = String, content_type = "text/plain"),
        (status = 503, description = "Relational engine disabled", body = String, content_type = "text/plain"),
    ),
    tag = "Relational Import"
)]
/// Creates a relational table from an uploaded CSV/TSV file: infers one
/// LuraDB type per column (spec §5.1), then imports every row through the
/// existing DML write path -- a row that fails is logged, the import
/// continues (spec §5.2). Requires DDL access, enforced the same way the
/// `/sql` handler enforces a DDL statement (rel/011 pattern).
pub async fn create_table_from_file(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    auth_outcome: Option<Extension<AuthOutcome>>,
    body: Bytes,
) -> Result<(StatusCode, Json<CreateFromFileResponse>), ApiError> {
    let engine = rel_engine(&state)?;
    check_budget(engine, &state, &domain)?;

    enforce_sql_level(state.auth_enabled, auth_outcome.map(|Extension(o)| o), AccessLevel::Ddl)
        .map_err(|resp| ApiError::new(resp.status(), "Forbidden"))?;

    let name = params.get("name").filter(|s| !s.is_empty()).ok_or_else(|| {
        ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: 'name' query parameter is required")
    })?;
    let format = match params.get("format").map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("csv") => FileFormat::Csv,
        Some("tsv") => FileFormat::Tsv,
        _ => return Err(ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: 'format' must be 'csv' or 'tsv'")),
    };
    let header = match params.get("header").map(String::as_str) {
        None | Some("true") => true,
        Some("false") => false,
        Some(_) => {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: 'header' must be 'true' or 'false'"))
        }
    };
    let pk = params.get("pk").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = engine.create_table_from_file(&domain, name, format, header, pk, &body).await?;
    let response = CreateFromFileResponse {
        table: result.table,
        columns: result
            .columns
            .into_iter()
            .map(|c| CreateFromFileColumn {
                name: c.name,
                col_type: column_type_name(c.col_type).to_string(),
                primary_key: c.primary_key,
                source_header: c.source_header,
            })
            .collect(),
        imported: result.imported,
        failed: result.failed,
        errors: result.errors.into_iter().map(|e| CreateFromFileErrorEntry { row: e.row, error: e.error }).collect(),
    };
    Ok((StatusCode::CREATED, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::storage::{file_manager::FileManager, manifest::ManifestManager, vlog::VLog};
    use axum::body::to_bytes;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use serde_json::json;
    use tower::util::ServiceExt;

    /// Mirrors `rel.rs`'s/`rel_browse.rs`'s own harness exactly.
    async fn make_state(rel_config: Option<crate::config::RelStoreConfig>, auth_enabled: bool) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let kv_dir = dir.path().join("kv");
        std::fs::create_dir_all(&kv_dir).unwrap();
        let wal_path = kv_dir.join("wal.log");
        let wal = std::sync::Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = kv_dir.join("vlog.log");
        let vlog = std::sync::Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = std::sync::Arc::new(FileManager::new(&kv_dir).await.unwrap());
        let mm = std::sync::Arc::new(ManifestManager::new(&kv_dir));
        let engine = std::sync::Arc::new(
            LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let auth_cache = std::sync::Arc::new(crate::auth::AuthCache::new(std::sync::Arc::clone(&engine)));
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = std::sync::Arc::new(
            DomainRegistry::recover(std::sync::Arc::clone(&engine), DomainConfig::default(), std::sync::Arc::clone(&metrics))
                .await
                .unwrap(),
        );
        let rel_engine = match rel_config {
            None => None,
            Some(cfg) => {
                let cfg = crate::config::RelStoreConfig {
                    wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
                    vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
                    sstable_dir: dir.path().join("rel_sst").to_string_lossy().into_owned(),
                    ..cfg
                };
                let resolver = crate::engines::rel::CrossEngineResolver::new(
                    Some(std::sync::Arc::clone(&registry)),
                    None,
                    std::sync::Arc::clone(&metrics),
                );
                Some(RelEngine::bootstrap(&cfg, std::sync::Arc::clone(&metrics), resolver).await.unwrap())
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
            event_bus: std::sync::Arc::new(crate::core::events::GlobalEventBus::new(256, 1024)),
            config: std::sync::Arc::new(crate::config::LuraConfig::default()),
            config_path: "test.toml".to_string(),
            config_file_loaded: false,
        };
        (state, dir)
    }

    async fn make_app(rel_config: Option<crate::config::RelStoreConfig>) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = make_state(rel_config, false).await;
        (crate::api::create_router(state, std::sync::Arc::new(vec![])), dir)
    }

    async fn make_default_app() -> (axum::Router, tempfile::TempDir) {
        make_app(Some(crate::config::RelStoreConfig::default())).await
    }

    async fn upload(
        app: &axum::Router,
        domain: &str,
        query: &str,
        body: &[u8],
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("/store-api/rel/{domain}/tables/from-file?{query}"))
            .header("content-type", "text/csv");
        if let Some(key) = bearer {
            builder = builder.header("authorization", format!("Bearer {key}"));
        }
        let resp = app.clone().oneshot(builder.body(Body::from(body.to_vec())).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"_raw": text}));
        (status, value)
    }

    async fn create_domain(app: &axum::Router, name: &str, bearer: &str) -> StatusCode {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/rel/domains")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"name": "{name}"}}"#)))
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    // 1. Success response shape: 201 with `table`/`columns`/`imported`/
    //    `failed`/`errors`, matching the spec §5 example.
    #[tokio::test]
    async fn test_upload_success_response_shape() {
        let (app, _dir) = make_default_app().await;
        let (status, body) = upload(&app, "default", "name=sales&format=csv", b"id,amount\n1,10\n2,20\n", None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["table"], json!("sales"));
        assert_eq!(body["imported"], json!(2));
        assert_eq!(body["failed"], json!(0));
        assert_eq!(body["errors"], json!([]));

        let cols = body["columns"].as_array().unwrap();
        let row_col = cols.iter().find(|c| c["name"] == json!("_row")).unwrap();
        assert_eq!(row_col["type"], json!("INTEGER"));
        assert_eq!(row_col["primary_key"], json!(true));
        assert!(row_col.get("source_header").is_none(), "no source_header for the synthetic column");
        let amount_col = cols.iter().find(|c| c["name"] == json!("amount")).unwrap();
        assert_eq!(amount_col["type"], json!("INTEGER"));
        assert_eq!(amount_col["source_header"], json!("amount"));
    }

    // Query validation: missing name/format, and an unknown format/header
    // value, all -> 400.
    #[tokio::test]
    async fn test_query_param_validation() {
        let (app, _dir) = make_default_app().await;
        let body = b"a,b\n1,2\n";
        let (status, _) = upload(&app, "default", "format=csv", body, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "missing name");
        let (status, _) = upload(&app, "default", "name=t", body, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "missing format");
        let (status, _) = upload(&app, "default", "name=t&format=xml", body, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unknown format");
        let (status, _) = upload(&app, "default", "name=t&format=csv&header=nope", body, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "invalid header value");
    }

    // 8. Table already exists -> 409 (existing table untouched); unknown
    //    domain -> 404 (spec §7 test 8, HTTP half).
    #[tokio::test]
    async fn test_conflict_and_domain_not_found() {
        let (app, _dir) = make_default_app().await;
        let (status, body) = upload(&app, "default", "name=t&format=csv", b"a\n1\n", None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = upload(&app, "default", "name=t&format=csv", b"a\n1\n", None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        let (status, _) = upload(&app, "ghost", "name=t&format=csv", b"a\n1\n", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Body over the configured limit -> 413 (axum's DefaultBodyLimit layer,
    // sized from `rel.import_body_limit_bytes`).
    #[tokio::test]
    async fn test_body_over_limit_413() {
        let (app, _dir) =
            make_app(Some(crate::config::RelStoreConfig { import_body_limit_bytes: 16, ..Default::default() })).await;
        let big = format!("a,b\n{}", "1,2\n".repeat(10));
        let (status, _) = upload(&app, "default", "name=t&format=csv", big.as_bytes(), None).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    // 9. Auth: DDL access is required -- a Write-only grant is rejected, a
    //    Ddl grant and Admin both succeed (spec §7 test 9, rel/011 pattern).
    #[tokio::test]
    async fn test_auth_requires_ddl() {
        use crate::auth::{hash_api_key, AccessLevel, DomainPermission, UserRecord, UserRole};

        let (state, _dir) = make_state(Some(crate::config::RelStoreConfig::default()), true).await;
        let cache = std::sync::Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, std::sync::Arc::new(vec![]));

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
        assert_eq!(create_domain(&app, "shop", admin_key).await, StatusCode::CREATED);

        let write_key = "lura_test_write_key";
        cache
            .upsert_user(UserRecord {
                name: "writer".to_string(),
                api_key_hash: hash_api_key(write_key),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        cache
            .set_permission(DomainPermission {
                username: "writer".to_string(),
                domain: "rel:shop".to_string(),
                access: AccessLevel::Write,
            })
            .await
            .unwrap();
        let (status, body) = upload(&app, "shop", "name=t&format=csv", b"a\n1\n", Some(write_key)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "Write alone must not allow creating a table: {body}");

        let ddl_key = "lura_test_ddl_key";
        cache
            .upsert_user(UserRecord {
                name: "ddl_user".to_string(),
                api_key_hash: hash_api_key(ddl_key),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        cache
            .set_permission(DomainPermission {
                username: "ddl_user".to_string(),
                domain: "rel:shop".to_string(),
                access: AccessLevel::Ddl,
            })
            .await
            .unwrap();
        let (status, body) = upload(&app, "shop", "name=t&format=csv", b"a\n1\n", Some(ddl_key)).await;
        assert_eq!(status, StatusCode::CREATED, "a Ddl grant must succeed: {body}");

        let (status, body) = upload(&app, "shop", "name=t2&format=csv", b"a\n1\n", Some(admin_key)).await;
        assert_eq!(status, StatusCode::CREATED, "Admin must succeed: {body}");
    }

    // Disabled engine: the route is not registered at all (404, axum's
    // default for an unmatched route) -- same contract as every other rel route.
    #[tokio::test]
    async fn test_disabled_engine_route_absent() {
        let (app, _dir) = make_app(None).await;
        let (status, _) = upload(&app, "default", "name=t&format=csv", b"a\n1\n", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
