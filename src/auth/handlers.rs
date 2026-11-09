//! REST handlers for user management and domain permissions.
//!
//! All endpoints require Admin role (enforced by AuthMiddleware before these handlers run),
//! except `whoami` — reachable by any authenticated caller (whitelisted in `middleware.rs`).
//!
//! GET    /store-api/auth/whoami                          → whoami        (200 | 401)
//! POST   /store-api/auth/users                           → create_user   (201 | 409)
//! GET    /store-api/auth/users                           → list_users    (200, incl. permissions)
//! DELETE /store-api/auth/users/:name                     → delete_user   (204 | 404)
//! POST   /store-api/auth/users/:name/permissions         → set_permission (200 | 400 | 404)
//! DELETE /store-api/auth/users/:name/permissions/:domain → remove_permission (204 | 400 | 404)
//! POST   /store-api/auth/users/:name/rotate-key          → rotate_key    (200 | 404)

use crate::auth::middleware::{split_permission_domain, McpInternal, TrustedPeer};
use crate::auth::{
    generate_api_key, hash_api_key, now_secs, AccessLevel, AuthCache, UserRecord, UserRole, MAX_USER_NAME_LENGTH,
};
use crate::control::{AuthChange, ControlPlane, Engine, Lifecycle};
use axum::{
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

#[derive(Clone)]
pub struct AuthState {
    pub cache: Arc<AuthCache>,
    /// Runs every change to the auth records.
    pub control: Arc<ControlPlane>,
    /// Mirrors `AppState::auth_enabled` (`api/mod.rs`) — needed by `whoami`
    /// to report the `Disabled` pseudo-role when the `auth_layer` middleware
    /// isn't in the router at all.
    pub auth_enabled: bool,
}

/// Caller identity. `role` is the only discriminator between the four cases —
/// see `whoami` for the full mapping; `name` is `null` whenever no
/// `UserRecord` backs the caller (`TrustedPeer`, `Disabled`).
#[derive(Serialize, ToSchema)]
pub struct WhoamiResponse {
    pub name: Option<String>,
    /// `"Admin"`, `"User"`, or a pseudo-role: `"TrustedPeer"` (UDS peer
    /// authenticated by the kernel) or `"Disabled"`
    /// (`auth.enabled = false`).
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// Username (1-50 chars, only [a-zA-Z0-9_-]).
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreateUserResponse {
    pub name: String,
    pub role: String,
    /// API key (visible only once — cannot be retrieved afterward).
    pub api_key: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserListItem {
    pub name: String,
    pub role: String,
    pub created_at: u64,
    /// Domain permission matrix — see `list_users` doc for `role == "Admin"` semantics.
    pub permissions: Vec<PermissionItem>,
}

/// One entry of a user's domain permission matrix. `engine`/`access` are
/// lowercase and match the write-endpoint vocabulary exactly — usable as-is
/// in a follow-up request.
#[derive(Serialize, ToSchema)]
pub struct PermissionItem {
    pub domain: String,
    /// `"kv"`, `"json"` or `"rel"`; missing for a permission on the whole domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// `"read"`, `"write"`, or `"ddl"`.
    pub access: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetPermissionRequest {
    /// Domain name.
    pub domain: String,
    /// Access level: `"read"`, `"write"` or `"ddl"`; `"ddl"` acts as
    /// `"write"` on keys and documents.
    pub access: String,
    /// Limits the permission to one engine of the domain: `"kv"`, `"json"`
    /// or `"rel"`. Without it, the permission covers the whole domain.
    pub engine: Option<String>,
}

#[derive(Deserialize)]
pub struct RemovePermissionParams {
    engine: Option<String>,
    /// Refused with `400`.
    store_type: Option<String>,
}

#[derive(Deserialize)]
pub struct SetPermissionParams {
    allow_missing: Option<bool>,
    /// Refused with `400`.
    store_type: Option<String>,
}

/// The answer to a request that still names `store_type`.
const STORE_TYPE_REFUSED: &str = "400 Bad Request: 'store_type' is no longer accepted, use 'engine'";

/// Resolves the optional `engine` field; `None` is the whole domain.
fn parse_engine(value: Option<&str>) -> Result<Option<Engine>, Box<Response>> {
    match value {
        None => Ok(None),
        Some("kv") => Ok(Some(Engine::Kv)),
        Some("json") => Ok(Some(Engine::Json)),
        Some("rel") => Ok(Some(Engine::Rel)),
        Some(other) => Err(Box::new(err(
            StatusCode::BAD_REQUEST,
            &format!("400 Bad Request: engine must be 'kv', 'json' or 'rel', got '{other}'"),
        ))),
    }
}

/// The request body, or `400` with the reason it is unusable.
fn permission_request(body: Result<Json<serde_json::Value>, JsonRejection>) -> Result<SetPermissionRequest, Box<Response>> {
    let bad_request = |reason: &str| Box::new(err(StatusCode::BAD_REQUEST, &format!("400 Bad Request: {reason}")));
    let Json(value) = body.map_err(|rejection| bad_request(&rejection.body_text()))?;
    if value.get("store_type").is_some() {
        return Err(Box::new(err(StatusCode::BAD_REQUEST, STORE_TYPE_REFUSED)));
    }
    serde_json::from_value(value).map_err(|e| bad_request(&e.to_string()))
}

#[derive(Serialize, ToSchema)]
pub struct RotateKeyResponse {
    pub name: String,
    /// New API key (visible only once — cannot be retrieved afterward).
    pub api_key: String,
}

/// Rule for usernames: non-empty, max 50 chars, only [a-zA-Z0-9_-] (same
/// charset as domain names). Keeps the persisted
/// `__sys:auth:perm:{user}:{grant}` key unambiguous — a ':' in a name would
/// collide with the key separator.
pub(crate) fn valid_name(name: &str) -> bool {
    crate::control::domains::is_valid_name(name, MAX_USER_NAME_LENGTH)
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

#[utoipa::path(
    get,
    path = "/store-api/auth/whoami",
    responses(
        (status = 200, description = "Caller identity — name (if any) and role", body = WhoamiResponse),
        (status = 401, description = "Missing or invalid API key", body = String, content_type = "text/plain"),
    ),
    tag = "Auth"
)]
/// Returns the caller's own identity. Unlike every other endpoint under this
/// tag, reachable by any authenticated caller — not admin-only (the
/// `auth_layer` middleware whitelists this path, see `middleware.rs`).
///
/// Checked in order: `auth.enabled = false` → `Disabled`; a `TrustedPeer`
/// (UDS peer authenticated by the kernel) → `TrustedPeer`;
/// otherwise the Bearer key is resolved to its `UserRecord` → `Admin`/`User`.
/// A `401` past the `auth_layer` middleware (which already validates the key)
/// can only mean a middleware bug — fail-closed, analogous to `enforce_sql_level`.
pub async fn whoami(
    State(state): State<AuthState>,
    trusted: Option<Extension<TrustedPeer>>,
    mcp_internal: Option<Extension<McpInternal>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !state.auth_enabled {
        return Json(WhoamiResponse {
            name: None,
            role: "Disabled".to_string(),
        })
        .into_response();
    }
    if trusted.is_some() {
        return Json(WhoamiResponse {
            name: None,
            role: "TrustedPeer".to_string(),
        })
        .into_response();
    }
    if let Some(user) = state.cache.resolve_bearer(&headers, mcp_internal.is_some(), now_secs()).await {
        return Json(WhoamiResponse {
            name: Some(user.name),
            role: format!("{:?}", user.role),
        })
        .into_response();
    }
    err(StatusCode::UNAUTHORIZED, "Unauthorized")
}

#[utoipa::path(
    post,
    path = "/store-api/auth/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created. API key is shown once in the response.", body = CreateUserResponse),
        (status = 409, description = "User already exists", body = String, content_type = "text/plain"),
        (status = 400, description = "Invalid name", body = String, content_type = "text/plain"),
    ),
    tag = "Auth"
)]
/// Creates a new user with the `User` role.
/// The API key is returned **only in this response** and is not stored afterward.
/// Only admins may call this endpoint.
pub async fn create_user(
    State(state): State<AuthState>,
    Json(body): Json<CreateUserRequest>,
) -> Response {
    let name = body.name.trim().to_string();
    if !valid_name(&name) {
        return err(StatusCode::BAD_REQUEST, "name must be 1-50 chars of [a-zA-Z0-9_-]");
    }

    if state.cache.get_user_by_name(&name).await.is_some() {
        return err(StatusCode::CONFLICT, "409 Conflict: user already exists");
    }

    let api_key = generate_api_key();
    let hash = hash_api_key(&api_key);
    let record = UserRecord {
        name: name.clone(),
        api_key_hash: hash,
        role: UserRole::User,
        created_at: now_secs(),
    };

    if let Err(e) = state.control.change_auth(AuthChange::UpsertUser(record)).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }

    (
        StatusCode::CREATED,
        Json(CreateUserResponse {
            name,
            role: "User".to_string(),
            api_key,
        }),
    )
        .into_response()
}

/// Lowercase wire form of `AccessLevel`. Output-only: the persisted/derived
/// `Serialize` impl stays PascalCase (`access_level_serde_round_trip`, `mod.rs`).
fn access_level_str(level: AccessLevel) -> &'static str {
    match level {
        AccessLevel::Read => "read",
        AccessLevel::Write => "write",
        AccessLevel::Ddl => "ddl",
    }
}

#[utoipa::path(
    get,
    path = "/store-api/auth/users",
    responses(
        (status = 200, description = "List of all users (without API keys), including their domain permissions", body = Vec<UserListItem>),
    ),
    tag = "Auth"
)]
/// Returns all created users (admins and regular users) with their domain
/// permission matrix. API keys are not included.
///
/// For `role == "Admin"`, `permissions` is meaningless for access control:
/// admins have unconditional access regardless of its contents. It
/// is usually empty for an admin but not guaranteed to be — e.g. a user
/// promoted to admin via `luradb.toml` keeps any permissions set before the
/// promotion. Never read an empty array as "no access" or a non-empty one as
/// a restriction on an Admin row.
///
/// The list reflects the permission table as stored — it is not cross-checked
/// against existing domains, so an entry set with `?allow_missing=true` for a
/// domain not created yet is shown too. Deleting a domain removes the
/// permissions on it.
pub async fn list_users(State(state): State<AuthState>) -> Json<Vec<UserListItem>> {
    let users = state.cache.all_users().await;
    let mut items = Vec::with_capacity(users.len());
    for r in users {
        let mut permissions: Vec<PermissionItem> = state
            .cache
            .permissions_for_user(&r.name)
            .await
            .into_iter()
            .map(|p| {
                let (engine, domain) = split_permission_domain(&p.domain);
                PermissionItem {
                    domain: domain.to_string(),
                    engine: engine.map(|engine| engine.as_str().to_string()),
                    access: access_level_str(p.access).to_string(),
                }
            })
            .collect();
        // Deterministic order: permissions_for_user iterates a HashMap.
        permissions.sort_by(|a, b| (&a.engine, &a.domain).cmp(&(&b.engine, &b.domain)));
        items.push(UserListItem {
            name: r.name,
            role: format!("{:?}", r.role),
            created_at: r.created_at,
            permissions,
        });
    }
    Json(items)
}

#[utoipa::path(
    delete,
    path = "/store-api/auth/users/{name}",
    params(("name" = String, Path, description = "Username")),
    responses(
        (status = 204, description = "User and all permissions deleted"),
        (status = 404, description = "User not found", body = String, content_type = "text/plain"),
    ),
    tag = "Auth"
)]
/// Deletes a user and all of their domain permissions.
/// The user's API key becomes invalid immediately — in-flight requests with the old key then get `401`.
pub async fn delete_user(
    State(state): State<AuthState>,
    Path(name): Path<String>,
) -> Response {
    if state.cache.get_user_by_name(&name).await.is_none() {
        return err(StatusCode::NOT_FOUND, "404 Not Found: user not found");
    }
    match state.control.change_auth(AuthChange::RemoveUser(name)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/store-api/auth/users/{name}/permissions",
    params(
        ("name" = String, Path, description = "Username"),
        ("allow_missing" = Option<bool>, Query, description = "Skip the domain existence check (pre-provisioning). Default false."),
    ),
    request_body = SetPermissionRequest,
    responses(
        (status = 200, description = "Permission set"),
        (status = 404, description = "User or domain not found", body = String, content_type = "text/plain"),
        (status = 400, description = "Invalid access, engine or domain value, an unknown field, or `store_type`, which is no longer accepted (use `engine`)", body = String, content_type = "text/plain"),
    ),
    tag = "Auth"
)]
/// Sets or overwrites a user's access permission on a domain: without
/// `engine` on the whole domain (keys, documents and tables), with `engine`
/// on that engine only. `access` must be `"read"`, `"write"`, or `"ddl"` —
/// each level includes the lower ones; `"ddl"` acts as `"write"` on keys and
/// documents. A user holds either a permission on the whole domain or
/// permissions on engines: one on the whole domain replaces the user's engine
/// permissions on it, and one on an engine turns a permission on the whole
/// domain into one of the same level per engine first, then sets the named
/// engine. The domain must exist and be active, whatever its engines;
/// `?allow_missing=true` skips that check.
pub async fn set_permission(
    State(state): State<AuthState>,
    Path(name): Path<String>,
    axum::extract::Query(params): axum::extract::Query<SetPermissionParams>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    if params.store_type.is_some() {
        return err(StatusCode::BAD_REQUEST, STORE_TYPE_REFUSED);
    }
    let body = match permission_request(body) {
        Ok(body) => body,
        Err(resp) => return *resp,
    };
    if state.cache.get_user_by_name(&name).await.is_none() {
        return err(StatusCode::NOT_FOUND, "404 Not Found: user not found");
    }
    let engine = match parse_engine(body.engine.as_deref()) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if let Err(e) = state.control.check_name(&body.domain) {
        return err(StatusCode::BAD_REQUEST, &format!("400 Bad Request: {e}"));
    }
    let active = state.control.directory().get(&body.domain).is_some_and(|entry| entry.state == Lifecycle::Active);
    if !active && !params.allow_missing.unwrap_or(false) {
        return err(StatusCode::NOT_FOUND, "404 Not Found: domain not found");
    }
    let access = match body.access.to_lowercase().as_str() {
        "read" => AccessLevel::Read,
        "write" => AccessLevel::Write,
        "ddl" => AccessLevel::Ddl,
        _ => return err(StatusCode::BAD_REQUEST, "access must be 'read', 'write' or 'ddl'"),
    };
    let change = AuthChange::SetPermission { username: name, domain: body.domain, engine, access };
    match state.control.change_auth(change).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[utoipa::path(
    delete,
    path = "/store-api/auth/users/{name}/permissions/{domain}",
    params(
        ("name" = String, Path, description = "Username"),
        ("domain" = String, Path, description = "Domain name"),
        ("engine" = Option<String>, Query, description = "'kv', 'json' or 'rel': revoke the permission on that engine only. Without it, every permission of the user on the domain."),
    ),
    responses(
        (status = 204, description = "Permission revoked"),
        (status = 400, description = "Invalid engine, or `store_type`, which is no longer accepted (use `engine`)", body = String, content_type = "text/plain"),
        (status = 404, description = "Neither a permission on the domain nor on the engine", body = String, content_type = "text/plain"),
    ),
    tag = "Auth"
)]
/// Revokes a user's permissions on a domain: without `engine` every one —
/// on the whole domain and on its engines —, with `?engine=` the one on that
/// engine. A permission on the whole domain then becomes one of the same
/// level on each of the other two engines. Afterwards, the user's requests
/// to what was revoked get `403 Forbidden`.
pub async fn remove_permission(
    State(state): State<AuthState>,
    Path((name, domain)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<RemovePermissionParams>,
) -> Response {
    if params.store_type.is_some() {
        return err(StatusCode::BAD_REQUEST, STORE_TYPE_REFUSED);
    }
    let engine = match parse_engine(params.engine.as_deref()) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if state.cache.effective(&name, &domain, engine).await.is_none() {
        return err(StatusCode::NOT_FOUND, "404 Not Found: permission not found");
    }
    match state.control.change_auth(AuthChange::RemovePermission { username: name, domain, engine }).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/store-api/auth/users/{name}/rotate-key",
    params(("name" = String, Path, description = "Username")),
    responses(
        (status = 200, description = "New API key generated (visible once)", body = RotateKeyResponse),
        (status = 404, description = "User not found", body = String, content_type = "text/plain"),
    ),
    tag = "Auth"
)]
/// Generates a new API key for the user and immediately invalidates the old one.
/// The new key is returned **only in this response**.
/// Use this after key leaks or for regular key rotation.
pub async fn rotate_key(
    State(state): State<AuthState>,
    Path(name): Path<String>,
) -> Response {
    if state.cache.get_user_by_name(&name).await.is_none() {
        return err(StatusCode::NOT_FOUND, "404 Not Found: user not found");
    }
    let new_key = generate_api_key();
    let new_hash = hash_api_key(&new_key);
    let change = AuthChange::RotateKey { name: name.clone(), new_hash };
    match state.control.change_auth(change).await {
        Ok(()) => Json(RotateKeyResponse {
            name,
            api_key: new_key,
        })
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::json::JsonEngine;
    use crate::engines::rel::RelEngine;

    #[test]
    fn parse_engine_accepts_kv_json_rel_and_none_for_the_whole_domain() {
        assert!(matches!(parse_engine(None), Ok(None)));
        assert!(matches!(parse_engine(Some("kv")), Ok(Some(Engine::Kv))));
        assert!(matches!(parse_engine(Some("json")), Ok(Some(Engine::Json))));
        assert!(matches!(parse_engine(Some("rel")), Ok(Some(Engine::Rel))));
        assert!(parse_engine(Some("xxx")).is_err());
    }

    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use tower::util::ServiceExt;

    async fn make_app(auth_enabled: bool) -> (axum::Router, Arc<AuthCache>, tempfile::TempDir) {
        let (app, auth_cache, _json, _rel, dir) = make_app_with_engines(auth_enabled, false, false).await;
        (app, auth_cache, dir)
    }

    /// Like `make_app`, but also boots the JSON/rel engines when requested
    /// and returns their handles so a test can check a domain's state.
    async fn make_app_with_engines(
        auth_enabled: bool,
        json_enabled: bool,
        rel_enabled: bool,
    ) -> (
        axum::Router,
        Arc<AuthCache>,
        Option<Arc<JsonEngine>>,
        Option<Arc<RelEngine>>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let kv_dir = dir.path().join("kv");
        std::fs::create_dir_all(&kv_dir).unwrap();
        let wal_path = kv_dir.join("wal.log");
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = kv_dir.join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(&kv_dir).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(&kv_dir));
        let engine = Arc::new(
            crate::engines::lsm::engine::LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            crate::engines::lsm::DomainRegistry::recover(
                Arc::clone(&engine),
                crate::engines::lsm::domain::DomainConfig::default(),
                Arc::clone(&metrics),
            )
            .await
            .unwrap(),
        );
        let json_engine = if json_enabled {
            let config = crate::config::JsonStoreConfig {
                wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("json_sst").to_string_lossy().into_owned(),
                ..crate::config::JsonStoreConfig::default()
            };
            Some(JsonEngine::bootstrap(&config, Arc::clone(&metrics)).await.unwrap())
        } else {
            None
        };
        let rel_engine = if rel_enabled {
            let cfg = crate::config::RelStoreConfig {
                wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("rel_sst").to_string_lossy().into_owned(),
                ..crate::config::RelStoreConfig::default()
            };
            let resolver = crate::engines::rel::CrossEngineResolver::new(
                Some(Arc::clone(&registry)),
                None,
                Arc::clone(&metrics),
            );
            Some(RelEngine::bootstrap(&cfg, Arc::clone(&metrics), resolver).await.unwrap())
        } else {
            None
        };
        let (control, auth_cache) = crate::control::testing::start(
            dir.path(),
            Arc::clone(&registry),
            json_engine.clone(),
            rel_engine.clone(),
            Arc::new(crate::core::events::GlobalEventBus::new(256, 1024)),
        )
        .await;
        let state = crate::api::AppState {
            registry,
            auth_cache: Arc::clone(&auth_cache),
            auth_enabled,
            metrics,
            json_engine: json_engine.clone(),
            rel_engine: rel_engine.clone(),
            shm_manager: None,
            backup_manager: None,
            log_access: None,
            control,
            config: Arc::new(crate::config::LuraConfig::default()),
            config_path: "test.toml".to_string(),
            config_file_loaded: false,
        };
        let app = crate::api::router_inline(state, Arc::new(vec![]));
        (app, auth_cache, json_engine, rel_engine, dir)
    }

    async fn send(app: &axum::Router, method: Method, uri: &str, body: Body) -> axum::http::Response<Body> {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn json_body(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn add_user(cache: &AuthCache, name: &str, key: &str, role: UserRole) {
        cache
            .upsert_user(UserRecord {
                name: name.to_string(),
                api_key_hash: hash_api_key(key),
                role,
                created_at: 0,
            })
            .await
            .unwrap();
    }

    // Auth sample: a real 404 (unknown user)
    // carries a non-empty plaintext body — schema and reality agree.
    #[test]
    fn test_delete_missing_user_404_has_nonempty_plaintext_body() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_app(false).await;
            let resp = send(&app, Method::DELETE, "/store-api/auth/users/ghost", Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            let content_type =
                resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap().to_str().unwrap().to_string();
            assert!(content_type.starts_with("text/plain"), "{content_type}");
            let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let body = String::from_utf8_lossy(&bytes);
            assert!(!body.is_empty(), "404 body must not be empty");
            assert!(
                serde_json::from_str::<serde_json::Value>(&body).is_err(),
                "body must be plain text, not JSON: {body}"
            );
        })
    }

    // Test 2: user without any grant -> permissions: [].
    #[test]
    fn list_users_permissions_empty_for_user_without_grants() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(false).await;
            add_user(&auth_cache, "alice", "lura_alice", UserRole::User).await;

            let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json_body(resp).await;
            let alice = body.as_array().unwrap().iter().find(|u| u["name"] == "alice").unwrap();
            assert_eq!(alice["permissions"], serde_json::json!([]));
        })
    }

    // Tests 3 + 4: set kv/json/rel and the whole domain -> list shows all
    // four with correct engine/domain (prefix stripped, no engine on the whole
    // domain); "ddl" on the rel entry round-trips lowercase despite the
    // PascalCase persisted form.
    #[test]
    fn list_users_permissions_roundtrip_every_engine_and_the_whole_domain() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(false).await;
            add_user(&auth_cache, "bob", "lura_bob", UserRole::User).await;
            for name in ["kvdom", "jsondom", "reldom", "alldom"] {
                create_domain(&app, name).await;
            }

            for body in [
                serde_json::json!({"domain": "kvdom", "access": "read", "engine": "kv"}),
                serde_json::json!({"domain": "jsondom", "access": "write", "engine": "json"}),
                serde_json::json!({"domain": "reldom", "access": "ddl", "engine": "rel"}),
                serde_json::json!({"domain": "alldom", "access": "write"}),
            ] {
                let resp = send(
                    &app,
                    Method::POST,
                    "/store-api/auth/users/bob/permissions",
                    Body::from(body.to_string()),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK, "{body}");
            }

            let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
            let body = json_body(resp).await;
            let bob = body.as_array().unwrap().iter().find(|u| u["name"] == "bob").unwrap();
            assert_eq!(
                bob["permissions"],
                serde_json::json!([
                    {"domain": "alldom", "access": "write"},
                    {"domain": "jsondom", "engine": "json", "access": "write"},
                    {"domain": "kvdom", "engine": "kv", "access": "read"},
                    {"domain": "reldom", "engine": "rel", "access": "ddl"},
                ])
            );
        })
    }

    // Test 5: role == "Admin" doesn't force an empty array, and doesn't force
    // a non-empty one either — the response reflects only the table.
    #[test]
    fn list_users_permissions_for_admin_reflects_table_not_role() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(false).await;
            add_user(&auth_cache, "root", "lura_root", UserRole::Admin).await;
            create_domain(&app, "jsondom").await;

            let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
            let body = json_body(resp).await;
            let root = body.as_array().unwrap().iter().find(|u| u["name"] == "root").unwrap();
            assert_eq!(root["permissions"], serde_json::json!([]));

            // set_permission never checks the target's role.
            let resp = send(
                &app,
                Method::POST,
                "/store-api/auth/users/root/permissions",
                Body::from(serde_json::json!({"domain": "jsondom", "access": "read", "engine": "json"}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);

            let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
            let body = json_body(resp).await;
            let root = body.as_array().unwrap().iter().find(|u| u["name"] == "root").unwrap();
            assert_eq!(
                root["permissions"],
                serde_json::json!([{"domain": "jsondom", "engine": "json", "access": "read"}])
            );
        })
    }

    // Test 6: multiple permissions come back in a fixed (engine, domain) order.
    #[test]
    fn list_users_permissions_sorted_deterministically() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(false).await;
            add_user(&auth_cache, "carol", "lura_carol", UserRole::User).await;
            for name in ["aaa", "bbb", "zzz"] {
                create_domain(&app, name).await;
            }

            for (engine, domain) in [(Some("rel"), "zzz"), (Some("kv"), "bbb"), (None, "zzz"), (Some("json"), "aaa"), (Some("kv"), "aaa")] {
                let resp = send(
                    &app,
                    Method::POST,
                    "/store-api/auth/users/carol/permissions",
                    Body::from(serde_json::json!({"domain": domain, "access": "read", "engine": engine}).to_string()),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
            let body = json_body(resp).await;
            let carol = body.as_array().unwrap().iter().find(|u| u["name"] == "carol").unwrap();
            let actual: Vec<(Option<&str>, &str)> = carol["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p["engine"].as_str(), p["domain"].as_str().unwrap()))
                .collect();
            // (engine, domain), the whole domain first, then "json" < "kv" < "rel";
            // the grant on all of zzz replaced the one on its rel engine.
            assert_eq!(actual, vec![(None, "zzz"), (Some("json"), "aaa"), (Some("kv"), "aaa"), (Some("kv"), "bbb")]);
        })
    }

    // Test 7: a non-admin key is still forbidden on GET /auth/users
    // (extract_domain("/store-api/auth/users") stays None).
    #[test]
    fn list_users_forbidden_for_non_admin_key() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(true).await;
            let key = "lura_worker_key";
            add_user(&auth_cache, "worker", key, UserRole::User).await;

            let resp = app
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/store-api/auth/users")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        })
    }

    // Test 8: deleting a domain removes the permissions on it, and a new
    // domain of the same name starts without any.
    #[test]
    fn deleting_a_domain_removes_the_permissions_on_it() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(false).await;
            add_user(&auth_cache, "dana", "lura_dana", UserRole::User).await;
            add_user(&auth_cache, "eve", "lura_eve", UserRole::User).await;
            create_domain(&app, "stays").await;

            let resp = send(
                &app,
                Method::POST,
                "/store-api/domains",
                Body::from(serde_json::json!({"name": "gonesoon"}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);

            for (user, grant) in [
                ("dana", serde_json::json!({"domain": "gonesoon", "access": "write"})),
                ("eve", serde_json::json!({"domain": "gonesoon", "access": "read", "engine": "kv"})),
                ("eve", serde_json::json!({"domain": "gonesoon", "access": "write", "engine": "json"})),
                ("eve", serde_json::json!({"domain": "stays", "access": "read", "engine": "kv"})),
            ] {
                let uri = format!("/store-api/auth/users/{user}/permissions");
                assert_eq!(send(&app, Method::POST, &uri, Body::from(grant.to_string())).await.status(), StatusCode::OK);
            }

            let resp = send(&app, Method::DELETE, "/store-api/domains/gonesoon", Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::ACCEPTED);

            let permissions_of = |user: &'static str| {
                let app = app.clone();
                async move {
                    let body = json_body(send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await).await;
                    body.as_array().unwrap().iter().find(|u| u["name"] == user).unwrap()["permissions"].clone()
                }
            };
            assert_eq!(permissions_of("dana").await, serde_json::json!([]));
            assert_eq!(permissions_of("eve").await, serde_json::json!([{"domain": "stays", "engine": "kv", "access": "read"}]));
        })
    }

    // Test 1: admin key -> 200 with its own name and role "Admin".
    #[test]
    fn whoami_admin_key_returns_name_and_role() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(true).await;
            let key = "lura_whoami_admin";
            add_user(&auth_cache, "root", key, UserRole::Admin).await;

            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/store-api/auth/whoami")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json_body(resp).await;
            assert_eq!(body, serde_json::json!({"name": "root", "role": "Admin"}));
        })
    }

    // Test 2: scoped user without any domain permission -> 200 with its name
    // and role "User" -- not 403 (the fallback extract_domain would give
    // without the whitelist entry; this is the point of the endpoint).
    #[test]
    fn whoami_scoped_user_without_permissions_returns_user_role_not_403() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app(true).await;
            let key = "lura_whoami_user";
            add_user(&auth_cache, "alice", key, UserRole::User).await;

            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/store-api/auth/whoami")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json_body(resp).await;
            assert_eq!(body, serde_json::json!({"name": "alice", "role": "User"}));
        })
    }

    // Test 3: no header -> 401; invalid key -> 401 (the auth_layer middleware
    // rejects both before the whitelist branch is ever reached).
    #[test]
    fn whoami_requires_valid_key() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_app(true).await;

            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/store-api/auth/whoami")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/store-api/auth/whoami")
                        .header("authorization", "Bearer lura_does_not_exist")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        })
    }

    // Test 4: TrustedPeer extension set (as the UDS accept loop would) -> 200,
    // name null, role "TrustedPeer" -- no UserRecord involved at all.
    #[test]
    fn whoami_trusted_peer_returns_pseudo_role() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_app(true).await;

            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/store-api/auth/whoami")
                        .extension(TrustedPeer)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json_body(resp).await;
            assert_eq!(body, serde_json::json!({"name": null, "role": "TrustedPeer"}));
        })
    }

    // Test 5: auth.enabled = false -> 200, name null, role "Disabled", no key
    // needed (the auth_layer middleware isn't even in the router).
    #[test]
    fn whoami_disabled_when_auth_off() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_app(false).await;

            let resp = send(&app, Method::GET, "/store-api/auth/whoami", Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json_body(resp).await;
            assert_eq!(body, serde_json::json!({"name": null, "role": "Disabled"}));
        })
    }

    // Test 6: auth.enabled = false AND TrustedPeer set -> still "Disabled" --
    // the global switch takes precedence (checked first in the handler).
    #[test]
    fn whoami_disabled_takes_precedence_over_trusted_peer() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_app(false).await;

            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/store-api/auth/whoami")
                        .extension(TrustedPeer)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = json_body(resp).await;
            assert_eq!(body, serde_json::json!({"name": null, "role": "Disabled"}));
        })
    }

    // Test 7 (/version still reachable, whitelist not broken) is covered by
    // `version_requires_valid_key_any_role` in middleware.rs, which exercises
    // the exact same whitelist branch whoami uses.

    /// POSTs a permission grant; returns only the status (body is irrelevant
    /// to every test below). `allow_missing` becomes `?allow_missing=` when `Some`.
    async fn set_perm(
        app: &axum::Router,
        user: &str,
        domain: &str,
        engine: Option<&str>,
        allow_missing: Option<bool>,
    ) -> StatusCode {
        let uri = match allow_missing {
            Some(v) => format!("/store-api/auth/users/{user}/permissions?allow_missing={v}"),
            None => format!("/store-api/auth/users/{user}/permissions"),
        };
        let body = serde_json::json!({"domain": domain, "access": "read", "engine": engine});
        send(app, Method::POST, &uri, Body::from(body.to_string())).await.status()
    }

    /// Creates the domain `name` through the API.
    async fn create_domain(app: &axum::Router, name: &str) {
        let body = Body::from(serde_json::json!({ "name": name }).to_string());
        let resp = send(app, Method::POST, "/store-api/domains", body).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{name}");
    }

    /// Status and text body of a response.
    async fn text_of(resp: axum::http::Response<Body>) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Like `send`, but with a Bearer key -- needed once `auth_enabled = true`.
    async fn authed(
        app: &axum::Router,
        key: &str,
        method: Method,
        uri: &str,
        body: Option<&str>,
    ) -> axum::http::Response<Body> {
        let mut builder = Request::builder().method(method).uri(uri).header("authorization", format!("Bearer {key}"));
        let req = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(b.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        app.clone().oneshot(req).await.unwrap()
    }

    const GRANTS: [Option<&str>; 4] = [None, Some("kv"), Some("json"), Some("rel")];

    // Every engine and the whole domain check the domain record: an active
    // domain -> 200; a missing one -> 404, also while its engine is off;
    // missing + allow_missing=true -> 200.
    #[test]
    fn set_permission_checks_the_domain_record_for_every_engine() {
        crate::core::engine_runtime::block_on(async {
            for (json, rel) in [(true, true), (false, false)] {
                let (app, auth_cache, _json, _rel, _dir) = make_app_with_engines(false, json, rel).await;
                add_user(&auth_cache, "alice", "lura_alice", UserRole::User).await;
                create_domain(&app, "dom").await;
                for engine in GRANTS {
                    let case = format!("{engine:?}, engines on: {json}");
                    assert_eq!(set_perm(&app, "alice", "dom", engine, None).await, StatusCode::OK, "{case}");
                    assert_eq!(set_perm(&app, "alice", "ghost", engine, None).await, StatusCode::NOT_FOUND, "{case}");
                    assert_eq!(set_perm(&app, "alice", "ghost", engine, Some(true)).await, StatusCode::OK, "{case}");
                }
            }
        })
    }

    // An invalid domain name -> 400 under the domain-name rule, for every
    // engine and the whole domain, with or without allow_missing.
    #[test]
    fn set_permission_checks_the_name_by_the_domain_rule() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _json, _rel, _dir) = make_app_with_engines(false, false, false).await;
            add_user(&auth_cache, "erin", "lura_erin", UserRole::User).await;
            let long_name = "a".repeat(51);

            for bad in ["a:b", "", long_name.as_str()] {
                for engine in GRANTS {
                    for allow_missing in [None, Some(true)] {
                        let status = set_perm(&app, "erin", bad, engine, allow_missing).await;
                        assert_eq!(status, StatusCode::BAD_REQUEST, "{engine:?} {bad:?} {allow_missing:?}");
                    }
                }
            }
            let uri = "/store-api/auth/users/erin/permissions";
            let body = serde_json::json!({"domain": "a:b", "access": "read"}).to_string();
            let (status, text) = text_of(send(&app, Method::POST, uri, Body::from(body)).await).await;
            assert_eq!(
                (status, text.as_str()),
                (StatusCode::BAD_REQUEST, "400 Bad Request: invalid domain name 'a:b': allowed are [a-zA-Z0-9_-], 1 to 50 characters")
            );
        })
    }

    // Test 6: unknown user -> 404 before any domain check, even with
    // allow_missing=true (order unchanged, handlers.rs user check runs first).
    #[test]
    fn set_permission_unknown_user_404_even_with_allow_missing() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _json, _rel, _dir) = make_app_with_engines(false, false, false).await;

            assert_eq!(set_perm(&app, "ghost_user", "dom", Some("kv"), None).await, StatusCode::NOT_FOUND);
            assert_eq!(set_perm(&app, "ghost_user", "dom", None, Some(true)).await, StatusCode::NOT_FOUND);
        })
    }

    // Test 7: allow_missing=true pre-provisions a permission that becomes
    // effective once the domain is created -- grant-before-create keeps
    // working, now as an explicit opt-in instead of a side effect of missing
    // validation.
    #[test]
    fn set_permission_allow_missing_roundtrip_activates_on_domain_creation() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _json, _rel, _dir) = make_app_with_engines(true, true, false).await;
            add_user(&auth_cache, "root", "lura_root", UserRole::Admin).await;
            add_user(&auth_cache, "alice", "lura_alice", UserRole::User).await;

            let resp = authed(
                &app,
                "lura_root",
                Method::POST,
                "/store-api/auth/users/alice/permissions?allow_missing=true",
                Some(&serde_json::json!({"domain": "predom", "access": "write", "engine": "json"}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);

            // Domain doesn't exist yet: the auth layer already lets alice through
            // on her pre-provisioned grant -- the handler alone answers 404.
            let resp = authed(
                &app,
                "lura_alice",
                Method::POST,
                "/store-api/json/predom/documents",
                Some(&serde_json::json!({"x": 1}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            let resp = authed(
                &app,
                "lura_root",
                Method::POST,
                "/store-api/domains",
                Some(&serde_json::json!({"name": "predom"}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);

            let resp = authed(
                &app,
                "lura_alice",
                Method::POST,
                "/store-api/json/predom/documents",
                Some(&serde_json::json!({"x": 1}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        })
    }

    // Test 8: a domain in Deleting state answers 404 without allow_missing,
    // for every engine and the whole domain. This harness never spawns a
    // purger, so the state can't race the assertion below.
    #[test]
    fn set_permission_deleting_domain_answers_404() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, json, rel, _dir) = make_app_with_engines(false, true, true).await;
            add_user(&auth_cache, "frank", "lura_frank", UserRole::User).await;
            create_domain(&app, "doomed").await;
            let resp = send(&app, Method::DELETE, "/store-api/domains/doomed", Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            assert_eq!(
                json.unwrap().get_domain_any("doomed").map(|d| d.state),
                Some(crate::engines::json::JsonDomainState::Deleting)
            );
            assert_eq!(
                rel.unwrap().get_domain_any("doomed").map(|d| d.state),
                Some(crate::engines::rel::RelDomainState::Deleting)
            );
            for engine in GRANTS {
                assert_eq!(set_perm(&app, "frank", "doomed", engine, None).await, StatusCode::NOT_FOUND, "{engine:?}");
            }
        })
    }

    const LISTING_ADMIN_KEY: &str = "lura_listing_admin";
    const LISTING_USER_KEY: &str = "lura_listing_worker";
    const DOMAIN_LISTING: &str = "/store-api/domains";

    /// Auth-on app with an admin, the user `worker` (no grants yet) and the
    /// domains `a`, `b`, `c`, `x`, beside the default one.
    async fn listing_fixture() -> (axum::Router, Arc<AuthCache>, tempfile::TempDir) {
        let (app, cache, _json, _rel, dir) = make_app_with_engines(true, true, true).await;
        add_user(&cache, "boss", LISTING_ADMIN_KEY, UserRole::Admin).await;
        add_user(&cache, "worker", LISTING_USER_KEY, UserRole::User).await;
        for name in ["a", "b", "c", "x"] {
            let body = serde_json::json!({ "name": name }).to_string();
            let resp = authed(&app, LISTING_ADMIN_KEY, Method::POST, DOMAIN_LISTING, Some(&body)).await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{name}");
        }
        (app, cache, dir)
    }

    /// Stores the grant `domain` (a stored key, see `permission_domain`) of `worker` as it is.
    async fn grant(cache: &AuthCache, domain: &str, access: AccessLevel) {
        let permission =
            crate::auth::DomainPermission { username: "worker".to_string(), domain: domain.to_string(), access };
        cache.set_permission(permission).await.unwrap();
    }

    async fn listed_names(app: &axum::Router, key: &str, uri: &str) -> Vec<String> {
        let resp = authed(app, key, Method::GET, uri, None).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let body = json_body(resp).await;
        body.as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap().to_string()).collect()
    }

    // A permission in any engine shows the domain: the key-value grant on
    // `a`, the JSON grant on `b` and the relational one on `c`.
    #[test]
    fn the_domain_listing_shows_the_domains_with_a_permission_in_any_engine() {
        crate::core::engine_runtime::block_on(async {
            let (app, cache, _dir) = listing_fixture().await;
            grant(&cache, "a", AccessLevel::Read).await;
            grant(&cache, "json:b", AccessLevel::Write).await;
            grant(&cache, "rel:c", AccessLevel::Ddl).await;
            assert_eq!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await, ["a", "b", "c"]);

            let resp = authed(&app, LISTING_USER_KEY, Method::GET, DOMAIN_LISTING, None).await;
            let body = json_body(resp).await;
            assert_eq!(body[1]["name"], "b");
            assert_eq!(body[1]["state"], "active");
            assert_eq!(body[1]["require_conditional_writes"], serde_json::json!({"kv": false, "json": false}));
            assert!(body[1]["created_at"].is_u64());
            assert!(body[1].get("document_count").is_none());
        })
    }

    #[test]
    fn the_domain_listing_is_empty_without_matching_permissions() {
        crate::core::engine_runtime::block_on(async {
            let (app, cache, _dir) = listing_fixture().await;
            assert!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await.is_empty());

            // Grants on domains that do not exist add no entries.
            grant(&cache, "ghost", AccessLevel::Read).await;
            grant(&cache, "json:ghost", AccessLevel::Read).await;
            grant(&cache, "rel:ghost", AccessLevel::Read).await;
            assert!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await.is_empty());
        })
    }

    #[test]
    fn the_domain_listing_shows_active_domains_only() {
        crate::core::engine_runtime::block_on(async {
            let (app, cache, _dir) = listing_fixture().await;
            grant(&cache, "a", AccessLevel::Read).await;
            grant(&cache, "json:x", AccessLevel::Read).await;
            assert_eq!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await, ["a", "x"]);

            let resp = authed(&app, LISTING_ADMIN_KEY, Method::DELETE, "/store-api/domains/x", None).await;
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            assert_eq!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await, ["a"]);
            assert_eq!(listed_names(&app, LISTING_ADMIN_KEY, DOMAIN_LISTING).await, ["a", "b", "c", "default"]);
        })
    }

    #[test]
    fn the_domain_listing_shows_everything_to_admin_and_trusted_peer() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = listing_fixture().await;
            let expected = ["a", "b", "c", "default", "x"];
            assert_eq!(listed_names(&app, LISTING_ADMIN_KEY, DOMAIN_LISTING).await, expected);

            let resp = app
                .clone()
                .oneshot(Request::builder().uri(DOMAIN_LISTING).extension(TrustedPeer).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(json_body(resp).await.as_array().unwrap().len(), expected.len());
        })
    }

    #[test]
    fn the_domain_listing_is_unfiltered_when_auth_is_off() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _json, _rel, _dir) = make_app_with_engines(false, true, true).await;
            create_domain(&app, "b").await;
            let resp = send(&app, Method::GET, DOMAIN_LISTING, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let names: Vec<_> = json_body(resp).await.as_array().unwrap().iter().map(|d| d["name"].clone()).collect();
            assert_eq!(names, ["b", "default"]);
        })
    }

    #[test]
    fn the_domain_listing_needs_a_key_and_stays_read_only_for_users() {
        crate::core::engine_runtime::block_on(async {
            let (app, cache, _dir) = listing_fixture().await;
            grant(&cache, "a", AccessLevel::Ddl).await;
            grant(&cache, "json:b", AccessLevel::Ddl).await;
            grant(&cache, "rel:c", AccessLevel::Ddl).await;

            let resp = send(&app, Method::GET, DOMAIN_LISTING, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let resp = authed(&app, LISTING_USER_KEY, Method::HEAD, DOMAIN_LISTING, None).await;
            assert_eq!(resp.status(), StatusCode::OK, "HEAD");
            let resp = authed(&app, LISTING_USER_KEY, Method::POST, DOMAIN_LISTING, Some(r#"{"name": "own"}"#)).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "POST");

            // The rest of the management surface stays admin-only.
            let resp = send(&app, Method::GET, "/store-api/metrics", Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let resp = authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/metrics", None).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            let resp = authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/config", None).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);

            assert_eq!(listed_names(&app, LISTING_ADMIN_KEY, DOMAIN_LISTING).await, ["a", "b", "c", "default", "x"]);
        })
    }

    // The detail follows a permission in any engine, and without one it is
    // 403 before 404 and 410; the domain metrics likewise.
    #[test]
    fn the_domain_detail_follows_a_permission_in_any_engine() {
        crate::core::engine_runtime::block_on(async {
            let (app, cache, _dir) = listing_fixture().await;
            grant(&cache, "a", AccessLevel::Write).await;
            grant(&cache, "json:b", AccessLevel::Read).await;
            grant(&cache, "rel:c", AccessLevel::Read).await;
            let status = |key: &'static str, method: Method, uri: &'static str| {
                let app = app.clone();
                async move { authed(&app, key, method, uri, None).await.status() }
            };

            for uri in ["/store-api/domains/a", "/store-api/domains/b", "/store-api/domains/c"] {
                assert_eq!(status(LISTING_USER_KEY, Method::GET, uri).await, StatusCode::OK, "{uri}");
            }
            let resp = authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/domains/b", None).await;
            let body = json_body(resp).await;
            assert_eq!((body["name"].clone(), body["state"].clone()), (serde_json::json!("b"), serde_json::json!("active")));
            assert_ne!(status(LISTING_USER_KEY, Method::GET, "/store-api/metrics/domains/b").await, StatusCode::FORBIDDEN);

            assert_eq!(authed(&app, LISTING_ADMIN_KEY, Method::DELETE, "/store-api/domains/x", None).await.status(), StatusCode::ACCEPTED);
            for uri in ["/store-api/domains/x", "/store-api/domains/ghost", "/store-api/metrics/domains/x"] {
                assert_eq!(status(LISTING_USER_KEY, Method::GET, uri).await, StatusCode::FORBIDDEN, "{uri}");
            }
            assert_eq!(status(LISTING_ADMIN_KEY, Method::GET, "/store-api/domains/x").await, StatusCode::GONE);
            assert_eq!(status(LISTING_ADMIN_KEY, Method::GET, "/store-api/domains/ghost").await, StatusCode::NOT_FOUND);

            // Deleting stays admin-only, even with a Write grant.
            assert_eq!(status(LISTING_USER_KEY, Method::DELETE, "/store-api/domains/a").await, StatusCode::FORBIDDEN);
            assert_eq!(status(LISTING_USER_KEY, Method::GET, "/store-api/domains/a").await, StatusCode::OK);
        })
    }

    // The domain routes of the JSON and the relational engine are gone.
    #[test]
    fn the_engine_domain_routes_are_gone() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = listing_fixture().await;
            for (method, uri) in [
                (Method::GET, "/store-api/json/domains"),
                (Method::POST, "/store-api/json/domains"),
                (Method::GET, "/store-api/json/domains/a"),
                (Method::DELETE, "/store-api/json/domains/a"),
                (Method::GET, "/store-api/rel/domains"),
                (Method::POST, "/store-api/rel/domains"),
                (Method::GET, "/store-api/rel/domains/a"),
                (Method::DELETE, "/store-api/rel/domains/a"),
            ] {
                let resp = authed(&app, LISTING_ADMIN_KEY, method.clone(), uri, Some(r#"{"name": "n"}"#)).await;
                assert!(
                    matches!(resp.status(), StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED),
                    "{method} {uri}: {}",
                    resp.status()
                );
            }
            assert_eq!(listed_names(&app, LISTING_ADMIN_KEY, DOMAIN_LISTING).await, ["a", "b", "c", "default", "x"]);
        })
    }

    // The four domain routes with their answers and texts.
    #[test]
    fn the_domain_routes_answer_with_their_statuses_and_texts() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _json, _rel, _dir) = make_app_with_engines(false, true, true).await;
            let call = |method: Method, uri: &'static str, body: &'static str| {
                let app = app.clone();
                async move { text_of(send(&app, method, uri, Body::from(body)).await).await }
            };

            let (status, body) = call(Method::POST, "/store-api/domains", r#"{"name": "shop", "require_conditional_writes": {"kv": true}}"#).await;
            assert_eq!(status, StatusCode::CREATED);
            let created: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(created["require_conditional_writes"], serde_json::json!({"kv": true, "json": false}));
            assert_eq!(created["state"], "active");
            assert_eq!(
                call(Method::POST, "/store-api/domains", r#"{"name": "shop"}"#).await,
                (StatusCode::CONFLICT, "409 Conflict: domain 'shop' already exists".to_string())
            );
            assert_eq!(
                call(Method::POST, "/store-api/domains", r#"{"name": "shop", "require_conditional_writes": true}"#).await,
                (
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request: require_conditional_writes must be an object {\"kv\": bool, \"json\": bool}".to_string()
                )
            );
            let (status, body) = call(Method::POST, "/store-api/domains", "{not json").await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.starts_with("400 Bad Request: "), "{body}");
            assert_eq!(
                call(Method::POST, "/store-api/domains", r#"{"name": "bad name"}"#).await,
                (
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request: invalid domain name 'bad name': allowed are [a-zA-Z0-9_-], 1 to 50 characters".to_string()
                )
            );
            let (status, _) = call(Method::POST, "/store-api/domains", r#"{"name": "domains"}"#).await;
            assert_eq!(status, StatusCode::CREATED, "the name domains is free");

            let (status, body) = call(Method::GET, "/store-api/domains/shop", "").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["name"], "shop");
            assert_eq!(
                call(Method::GET, "/store-api/domains/ghost", "").await,
                (StatusCode::NOT_FOUND, "404 Not Found: domain 'ghost' not found".to_string())
            );
            assert_eq!(
                call(Method::DELETE, "/store-api/domains/ghost", "").await,
                (StatusCode::NOT_FOUND, "404 Not Found: domain 'ghost' not found".to_string())
            );
            assert_eq!(call(Method::DELETE, "/store-api/domains/shop", "").await.0, StatusCode::ACCEPTED);
            let gone = (StatusCode::GONE, "410 Gone: domain 'shop' is being deleted".to_string());
            assert_eq!(call(Method::GET, "/store-api/domains/shop", "").await, gone);
            assert_eq!(call(Method::DELETE, "/store-api/domains/shop", "").await, gone);
            assert_eq!(
                call(Method::POST, "/store-api/domains", r#"{"name": "shop"}"#).await,
                (StatusCode::CONFLICT, "409 Conflict: domain 'shop' is being deleted".to_string())
            );
            let (status, body) = call(Method::GET, "/store-api/kv/shop/keys/k", "").await;
            assert_eq!(status, StatusCode::GONE, "{body}");
        })
    }

    /// `listing_fixture` with a key `k`, a document `d` and a table `t` in
    /// the domain `a`.
    async fn data_fixture() -> (axum::Router, Arc<AuthCache>, tempfile::TempDir) {
        let (app, cache, dir) = listing_fixture().await;
        for (method, uri, body) in [
            (Method::PUT, "/store-api/kv/a/keys/k", "clé"),
            (Method::PUT, "/store-api/json/a/documents/d", r#"{"n": 1}"#),
            (Method::POST, "/store-api/rel/a/sql", r#"{"sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}"#),
        ] {
            let resp = authed(&app, LISTING_ADMIN_KEY, method, uri, Some(body)).await;
            assert!(resp.status().is_success(), "{uri}: {}", resp.status());
        }
        (app, cache, dir)
    }

    /// POSTs `grant` as a permission of `worker`, as the admin.
    async fn permit(app: &axum::Router, grant: serde_json::Value) -> (StatusCode, String) {
        let uri = "/store-api/auth/users/worker/permissions";
        text_of(authed(app, LISTING_ADMIN_KEY, Method::POST, uri, Some(&grant.to_string())).await).await
    }

    /// DELETEs the permissions of `worker` on `domain`, `query` appended, as the admin.
    async fn revoke(app: &axum::Router, domain: &str, query: &str) -> (StatusCode, String) {
        let uri = format!("/store-api/auth/users/worker/permissions/{domain}{query}");
        text_of(authed(app, LISTING_ADMIN_KEY, Method::DELETE, &uri, None).await).await
    }

    /// The permissions of `worker` as `GET …/users` lists them.
    async fn worker_permissions(app: &axum::Router) -> serde_json::Value {
        let body = json_body(authed(app, LISTING_ADMIN_KEY, Method::GET, "/store-api/auth/users", None).await).await;
        body.as_array().unwrap().iter().find(|u| u["name"] == "worker").unwrap()["permissions"].clone()
    }

    /// Whether `worker` passes: a success is a pass, `403` none, anything else a failed test.
    async fn passes(app: &axum::Router, method: Method, uri: &str, body: Option<&str>) -> bool {
        let resp = authed(app, LISTING_USER_KEY, method.clone(), uri, body).await;
        match resp.status() {
            status if status.is_success() => true,
            StatusCode::FORBIDDEN => false,
            status => panic!("{method} {uri}: {status} {}", text_of(resp).await.1),
        }
    }

    /// What `worker` may do in the domain `a`: read, write, each per engine
    /// (kv, json, rel), and run DDL in LuraSQL. `round` keeps rows and tables apart.
    async fn reach(app: &axum::Router, round: u32) -> ([bool; 3], [bool; 3], bool) {
        let sql = |statement: String| serde_json::json!({ "sql": statement }).to_string();
        let read = [
            passes(app, Method::GET, "/store-api/kv/a/keys/k", None).await,
            passes(app, Method::GET, "/store-api/json/a/documents/d", None).await,
            passes(app, Method::POST, "/store-api/rel/a/sql", Some(&sql("SELECT * FROM t".into()))).await,
        ];
        let write = [
            passes(app, Method::PUT, "/store-api/kv/a/keys/k", Some("clé")).await,
            passes(app, Method::PUT, "/store-api/json/a/documents/d", Some(r#"{"n": 2}"#)).await,
            passes(app, Method::POST, "/store-api/rel/a/sql", Some(&sql(format!("INSERT INTO t VALUES ({round})")))).await,
        ];
        let create = sql(format!("CREATE TABLE t{round} (id INTEGER PRIMARY KEY)"));
        (read, write, passes(app, Method::POST, "/store-api/rel/a/sql", Some(&create)).await)
    }

    // A permission on the whole domain holds in all three engines at its
    // level; ddl acts as write on keys and documents.
    #[test]
    fn a_domain_permission_holds_in_every_engine_at_its_level() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = data_fixture().await;
            let (all, none) = ([true; 3], [false; 3]);
            for (round, access, expected) in [
                (1, "read", (all, none, false)),
                (2, "write", (all, all, false)),
                (3, "ddl", (all, all, true)),
            ] {
                assert_eq!(permit(&app, serde_json::json!({"domain": "a", "access": access})).await.0, StatusCode::OK);
                assert_eq!(reach(&app, round).await, expected, "{access}");
            }
            assert_eq!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await, ["a"]);
            assert_eq!(authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/domains/a", None).await.status(), StatusCode::OK);
            let metrics = authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/metrics/domains/a", None).await;
            assert_ne!(metrics.status(), StatusCode::FORBIDDEN);
            assert_eq!(authed(&app, LISTING_USER_KEY, Method::DELETE, "/store-api/domains/a", None).await.status(), StatusCode::FORBIDDEN);
        })
    }

    // A permission on one engine holds there only; with only a JSON one, the
    // domain still shows in the listing and its detail.
    #[test]
    fn an_engine_permission_holds_in_its_engine_only() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = data_fixture().await;
            let grant = serde_json::json!({"domain": "a", "access": "write", "engine": "json"});
            assert_eq!(permit(&app, grant).await.0, StatusCode::OK);
            assert_eq!(reach(&app, 1).await, ([false, true, false], [false, true, false], false));
            assert_eq!(listed_names(&app, LISTING_USER_KEY, DOMAIN_LISTING).await, ["a"]);
            assert_eq!(authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/domains/a", None).await.status(), StatusCode::OK);
            let metrics = authed(&app, LISTING_USER_KEY, Method::GET, "/store-api/metrics/domains/a", None).await;
            assert_ne!(metrics.status(), StatusCode::FORBIDDEN);
        })
    }

    // A user with write on the key-value engine, then read on the whole
    // domain, writes no key: the domain grant replaced the engine grant.
    #[test]
    fn a_domain_permission_downgrades_an_engine_permission() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = data_fixture().await;
            permit(&app, serde_json::json!({"domain": "a", "access": "write", "engine": "kv"})).await;
            assert!(passes(&app, Method::PUT, "/store-api/kv/a/keys/k", Some("clé")).await);
            permit(&app, serde_json::json!({"domain": "a", "access": "read"})).await;
            assert!(!passes(&app, Method::PUT, "/store-api/kv/a/keys/k", Some("clé")).await);
            assert!(passes(&app, Method::GET, "/store-api/kv/a/keys/k", None).await);
        })
    }

    #[test]
    fn a_domain_permission_replaces_the_engine_permissions_and_an_engine_one_splits_it() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = listing_fixture().await;
            for engine in ["kv", "json", "rel"] {
                permit(&app, serde_json::json!({"domain": "a", "access": "read", "engine": engine})).await;
            }
            permit(&app, serde_json::json!({"domain": "b", "access": "read", "engine": "kv"})).await;
            assert_eq!(permit(&app, serde_json::json!({"domain": "a", "access": "write"})).await.0, StatusCode::OK);
            assert_eq!(
                worker_permissions(&app).await,
                serde_json::json!([{"domain": "a", "access": "write"}, {"domain": "b", "engine": "kv", "access": "read"}])
            );

            let grant = serde_json::json!({"domain": "a", "access": "ddl", "engine": "rel"});
            assert_eq!(permit(&app, grant).await.0, StatusCode::OK);
            assert_eq!(
                worker_permissions(&app).await,
                serde_json::json!([
                    {"domain": "a", "engine": "json", "access": "write"},
                    {"domain": "a", "engine": "kv", "access": "write"},
                    {"domain": "b", "engine": "kv", "access": "read"},
                    {"domain": "a", "engine": "rel", "access": "ddl"},
                ])
            );
        })
    }

    // Taking the key-value engine away from a user with the whole domain
    // leaves that user the other two engines at the same level.
    #[test]
    fn revoking_one_engine_of_a_domain_permission_leaves_the_other_two() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = data_fixture().await;
            permit(&app, serde_json::json!({"domain": "a", "access": "write"})).await;
            assert_eq!(revoke(&app, "a", "?engine=kv").await.0, StatusCode::NO_CONTENT);
            assert_eq!(
                worker_permissions(&app).await,
                serde_json::json!([
                    {"domain": "a", "engine": "json", "access": "write"},
                    {"domain": "a", "engine": "rel", "access": "write"},
                ])
            );
            assert_eq!(reach(&app, 1).await, ([false, true, true], [false, true, true], false));
        })
    }

    #[test]
    fn revoking_answers_404_without_a_permission_on_the_engine_or_the_domain() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = listing_fixture().await;
            let missing = (StatusCode::NOT_FOUND, "404 Not Found: permission not found".to_string());
            assert_eq!(revoke(&app, "a", "?engine=kv").await, missing);
            assert_eq!(revoke(&app, "a", "").await, missing);
            permit(&app, serde_json::json!({"domain": "a", "access": "read", "engine": "json"})).await;
            assert_eq!(revoke(&app, "a", "?engine=kv").await, missing);
            assert_eq!(revoke(&app, "a", "?engine=json").await.0, StatusCode::NO_CONTENT);
        })
    }

    #[test]
    fn revoking_without_an_engine_removes_every_permission_on_the_domain() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = listing_fixture().await;
            permit(&app, serde_json::json!({"domain": "a", "access": "read", "engine": "json"})).await;
            permit(&app, serde_json::json!({"domain": "a", "access": "write", "engine": "rel"})).await;
            permit(&app, serde_json::json!({"domain": "b", "access": "read"})).await;
            assert_eq!(revoke(&app, "a", "").await.0, StatusCode::NO_CONTENT);
            assert_eq!(worker_permissions(&app).await, serde_json::json!([{"domain": "b", "access": "read"}]));
            assert_eq!(revoke(&app, "b", "").await.0, StatusCode::NO_CONTENT);
            assert_eq!(worker_permissions(&app).await, serde_json::json!([]));
        })
    }

    // `store_type` answers 400 with a fixed text, in the body and in either
    // query; so do an unknown field and an unknown engine.
    #[test]
    fn store_type_and_unknown_fields_are_refused() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = listing_fixture().await;
            let refused = (StatusCode::BAD_REQUEST, STORE_TYPE_REFUSED.to_string());
            assert_eq!(STORE_TYPE_REFUSED, "400 Bad Request: 'store_type' is no longer accepted, use 'engine'");
            for store_type in ["kv", "json"] {
                let grant = serde_json::json!({"domain": "a", "access": "read", "store_type": store_type});
                assert_eq!(permit(&app, grant).await, refused, "{store_type}");
            }
            let grant = serde_json::json!({"domain": "a", "access": "read"}).to_string();
            let uri = "/store-api/auth/users/worker/permissions?store_type=kv";
            assert_eq!(text_of(authed(&app, LISTING_ADMIN_KEY, Method::POST, uri, Some(&grant)).await).await, refused);
            assert_eq!(revoke(&app, "a", "?store_type=kv").await, refused);
            assert_eq!(worker_permissions(&app).await, serde_json::json!([]), "nothing was granted");

            let (status, text) = permit(&app, serde_json::json!({"domain": "a", "access": "read", "scope": "kv"})).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(text.starts_with("400 Bad Request: unknown field `scope`"), "{text}");
            let (status, text) = permit(&app, serde_json::json!({"domain": "a", "access": "read", "engine": "sql"})).await;
            assert_eq!(
                (status, text.as_str()),
                (StatusCode::BAD_REQUEST, "400 Bad Request: engine must be 'kv', 'json' or 'rel', got 'sql'")
            );
            assert_eq!(revoke(&app, "a", "?engine=sql").await.0, StatusCode::BAD_REQUEST);
            let (status, text) =
                text_of(authed(&app, LISTING_ADMIN_KEY, Method::POST, "/store-api/auth/users/worker/permissions", Some("{")).await)
                    .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(text.starts_with("400 Bad Request: "), "{text}");
        })
    }

    // User names stay limited to 50 characters.
    #[test]
    fn a_user_name_over_50_characters_answers_400() {
        crate::core::engine_runtime::block_on(async {
            let (app, _cache, _dir) = make_app(false).await;
            for (name, expected) in [("u".repeat(50), StatusCode::CREATED), ("u".repeat(51), StatusCode::BAD_REQUEST)] {
                let body = Body::from(serde_json::json!({ "name": name }).to_string());
                assert_eq!(send(&app, Method::POST, "/store-api/auth/users", body).await.status(), expected);
            }
        })
    }
}
