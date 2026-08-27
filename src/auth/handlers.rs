//! REST handlers for user management and domain permissions.
//!
//! All endpoints require Admin role (enforced by AuthMiddleware before these handlers run).
//!
//! POST   /store-api/auth/users                           → create_user   (201 | 409)
//! GET    /store-api/auth/users                           → list_users    (200, incl. permissions)
//! DELETE /store-api/auth/users/:name                     → delete_user   (204 | 404)
//! POST   /store-api/auth/users/:name/permissions         → set_permission (200 | 404)
//! DELETE /store-api/auth/users/:name/permissions/:domain → remove_permission (204 | 404)
//! POST   /store-api/auth/users/:name/rotate-key          → rotate_key    (200 | 404)

use crate::auth::middleware::{split_permission_domain, StoreType};
use crate::auth::{generate_api_key, hash_api_key, AccessLevel, AuthCache, DomainPermission, UserRecord, UserRole};
use crate::engines::lsm::DomainRegistry;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

// ── Shared handler state ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AuthState {
    pub cache: Arc<AuthCache>,
    pub registry: Arc<DomainRegistry>,
}

// ── Request / response types ──────────────────────────────────────────────────

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

/// One entry of a user's domain permission matrix. `store_type`/`access` are
/// lowercase and match the write-endpoint vocabulary exactly (`parse_store_type`,
/// `access` parsing in `set_permission`) — usable as-is in a follow-up request.
#[derive(Serialize, ToSchema)]
pub struct PermissionItem {
    pub domain: String,
    /// `"kv"`, `"json"`, or `"rel"`.
    pub store_type: String,
    /// `"read"`, `"write"`, or `"ddl"`.
    pub access: String,
}

#[derive(Deserialize, ToSchema)]
pub struct SetPermissionRequest {
    /// Domain name.
    pub domain: String,
    /// Access level: `"read"`, `"write"` or `"ddl"` (spec rel/011).
    pub access: String,
    /// Store type of the domain: `"kv"` (default), `"json"` (spec json/012) or `"rel"` (spec rel/011).
    pub store_type: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct RemovePermissionParams {
    /// Store type of the domain: `"kv"` (default), `"json"` or `"rel"`.
    pub store_type: Option<String>,
}

/// Resolves the optional store_type field to the permission namespace.
fn parse_store_type(value: &Option<String>) -> Result<StoreType, Response> {
    match value.as_deref() {
        None | Some("kv") => Ok(StoreType::Kv),
        Some("json") => Ok(StoreType::Json),
        Some("rel") => Ok(StoreType::Rel),
        Some(other) => Err(err(
            StatusCode::BAD_REQUEST,
            &format!("store_type must be 'kv', 'json' or 'rel', got '{other}'"),
        )),
    }
}

#[derive(Serialize, ToSchema)]
pub struct RotateKeyResponse {
    pub name: String,
    /// New API key (visible only once — cannot be retrieved afterward).
    pub api_key: String,
}

/// Shared rule for usernames and permission domain names: non-empty, max 50
/// chars, only [a-zA-Z0-9_-] (same charset as domain names). Keeps the
/// persisted `__sys:auth:perm:{user}:{domain}` key unambiguous — a ':' in a
/// name would collide with the key separator.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 50
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn err(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/auth/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created. API key is shown once in the response.", body = CreateUserResponse),
        (status = 409, description = "User already exists"),
        (status = 400, description = "Invalid name"),
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

    if let Err(e) = state.cache.upsert_user(record).await {
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

/// Lowercase wire form of `StoreType`, matching `parse_store_type`'s input vocabulary.
fn store_type_str(store_type: StoreType) -> &'static str {
    match store_type {
        StoreType::Kv => "kv",
        StoreType::Json => "json",
        StoreType::Rel => "rel",
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
/// admins have unconditional access regardless of its contents (kv/012). It
/// is usually empty for an admin but not guaranteed to be — e.g. a user
/// promoted to admin via `luradb.toml` keeps any permissions set before the
/// promotion. Never read an empty array as "no access" or a non-empty one as
/// a restriction on an Admin row.
///
/// The list reflects the permission table as stored — it is not cross-checked
/// against existing domains, so an entry for a since-deleted (or not-yet-created)
/// domain is shown unchanged.
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
                let (store_type, domain) = split_permission_domain(&p.domain);
                PermissionItem {
                    domain: domain.to_string(),
                    store_type: store_type_str(store_type).to_string(),
                    access: access_level_str(p.access).to_string(),
                }
            })
            .collect();
        // Deterministic order: permissions_for_user iterates a HashMap.
        permissions.sort_by(|a, b| (&a.store_type, &a.domain).cmp(&(&b.store_type, &b.domain)));
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
        (status = 404, description = "User not found"),
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
    match state.cache.remove_user(&name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/store-api/auth/users/{name}/permissions",
    params(("name" = String, Path, description = "Username")),
    request_body = SetPermissionRequest,
    responses(
        (status = 200, description = "Permission set"),
        (status = 404, description = "User or domain not found"),
        (status = 400, description = "Invalid access or domain value"),
    ),
    tag = "Auth"
)]
/// Sets or overwrites a user's access permission on a domain.
/// `access` must be `"read"`, `"write"`, or `"ddl"` — each level includes the
/// lower ones. For `kv` the domain must exist; `json`/`rel` only check the name.
pub async fn set_permission(
    State(state): State<AuthState>,
    Path(name): Path<String>,
    Json(body): Json<SetPermissionRequest>,
) -> Response {
    if state.cache.get_user_by_name(&name).await.is_none() {
        return err(StatusCode::NOT_FOUND, "404 Not Found: user not found");
    }
    let store_type = match parse_store_type(&body.store_type) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // JSON/rel domains skip the existence check: permissions must be settable
    // even while the engine is disabled or the domain doesn't exist yet (spec
    // json/012 §6, rel/011 §8). The name must still be a possible domain
    // name, or the permission could never match.
    match store_type {
        StoreType::Kv => {
            if state.registry.get_domain(&body.domain).await.unwrap_or(None).is_none() {
                return err(StatusCode::NOT_FOUND, "404 Not Found: domain not found");
            }
        }
        StoreType::Json | StoreType::Rel => {
            if !valid_name(&body.domain) {
                return err(StatusCode::BAD_REQUEST, "domain must be 1-50 chars of [a-zA-Z0-9_-]");
            }
        }
    }
    let access = match body.access.to_lowercase().as_str() {
        "read" => AccessLevel::Read,
        "write" => AccessLevel::Write,
        "ddl" => AccessLevel::Ddl,
        _ => return err(StatusCode::BAD_REQUEST, "access must be 'read', 'write' or 'ddl'"),
    };
    let perm = DomainPermission {
        username: name,
        domain: crate::auth::middleware::permission_domain(store_type, &body.domain),
        access,
    };
    match state.cache.set_permission(perm).await {
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
        ("store_type" = Option<String>, Query, description = "'kv' (default), 'json' or 'rel'"),
    ),
    responses(
        (status = 204, description = "Permission revoked"),
        (status = 404, description = "Permission not found"),
    ),
    tag = "Auth"
)]
/// Revokes a user's access permission on a specific domain.
/// `?store_type=json`/`rel` revokes a JSON/rel domain permission (default: kv).
/// After this call, the user's requests to this domain get `403 Forbidden`.
pub async fn remove_permission(
    State(state): State<AuthState>,
    Path((name, domain)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<RemovePermissionParams>,
) -> Response {
    let store_type = match parse_store_type(&params.store_type) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let perm_domain = crate::auth::middleware::permission_domain(store_type, &domain);
    if state.cache.get_permission(&name, &perm_domain).await.is_none() {
        return err(StatusCode::NOT_FOUND, "404 Not Found: permission not found");
    }
    match state.cache.remove_permission(&name, &perm_domain).await {
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
        (status = 404, description = "User not found"),
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
    match state.cache.rotate_key(&name, &new_hash).await {
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

    #[test]
    fn parse_store_type_accepts_kv_json_rel() {
        assert!(matches!(parse_store_type(&None), Ok(StoreType::Kv)));
        assert!(matches!(parse_store_type(&Some("kv".to_string())), Ok(StoreType::Kv)));
        assert!(matches!(parse_store_type(&Some("json".to_string())), Ok(StoreType::Json)));
        assert!(matches!(parse_store_type(&Some("rel".to_string())), Ok(StoreType::Rel)));
        assert!(parse_store_type(&Some("xxx".to_string())).is_err());
    }

    // ── list_users permissions (spec general/015) ───────────────────────────

    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use tower::util::ServiceExt;

    async fn make_app(auth_enabled: bool) -> (axum::Router, Arc<AuthCache>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(dir.path()));
        let engine = Arc::new(
            crate::engines::lsm::engine::LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let auth_cache = Arc::new(AuthCache::new(Arc::clone(&engine)));
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            crate::engines::lsm::DomainRegistry::recover(
                engine,
                crate::engines::lsm::domain::DomainConfig::default(),
                Arc::clone(&metrics),
            )
            .await
            .unwrap(),
        );
        let state = crate::api::AppState {
            registry,
            auth_cache: Arc::clone(&auth_cache),
            auth_enabled,
            metrics,
            json_engine: None,
            rel_engine: None,
            shm_manager: None,
            backup_manager: None,
            log_access: None,
        };
        let app = crate::api::create_router(state, Arc::new(vec![]));
        (app, auth_cache, dir)
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

    // Test 2: user without any grant -> permissions: [].
    #[tokio::test]
    async fn list_users_permissions_empty_for_user_without_grants() {
        let (app, auth_cache, _dir) = make_app(false).await;
        add_user(&auth_cache, "alice", "lura_alice", UserRole::User).await;

        let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let alice = body.as_array().unwrap().iter().find(|u| u["name"] == "alice").unwrap();
        assert_eq!(alice["permissions"], serde_json::json!([]));
    }

    // Tests 3 + 4: set kv/json/rel -> list shows all three with correct
    // store_type/domain (prefix stripped); "ddl" on the rel entry round-trips
    // lowercase despite the PascalCase persisted form.
    #[tokio::test]
    async fn list_users_permissions_roundtrip_all_store_types() {
        let (app, auth_cache, _dir) = make_app(false).await;
        add_user(&auth_cache, "bob", "lura_bob", UserRole::User).await;

        let resp = send(
            &app,
            Method::POST,
            "/store-api/domains",
            Body::from(serde_json::json!({"name": "kvdom"}).to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        for body in [
            serde_json::json!({"domain": "kvdom", "access": "read"}),
            serde_json::json!({"domain": "jsondom", "access": "write", "store_type": "json"}),
            serde_json::json!({"domain": "reldom", "access": "ddl", "store_type": "rel"}),
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
        let perms = bob["permissions"].as_array().unwrap();
        assert_eq!(perms.len(), 3);
        assert!(perms
            .iter()
            .any(|p| p["domain"] == "kvdom" && p["store_type"] == "kv" && p["access"] == "read"));
        assert!(perms
            .iter()
            .any(|p| p["domain"] == "jsondom" && p["store_type"] == "json" && p["access"] == "write"));
        assert!(perms
            .iter()
            .any(|p| p["domain"] == "reldom" && p["store_type"] == "rel" && p["access"] == "ddl"));
    }

    // Test 5: role == "Admin" doesn't force an empty array, and doesn't force
    // a non-empty one either — the response reflects only the table.
    #[tokio::test]
    async fn list_users_permissions_for_admin_reflects_table_not_role() {
        let (app, auth_cache, _dir) = make_app(false).await;
        add_user(&auth_cache, "root", "lura_root", UserRole::Admin).await;

        let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
        let body = json_body(resp).await;
        let root = body.as_array().unwrap().iter().find(|u| u["name"] == "root").unwrap();
        assert_eq!(root["permissions"], serde_json::json!([]));

        // set_permission never checks the target's role.
        let resp = send(
            &app,
            Method::POST,
            "/store-api/auth/users/root/permissions",
            Body::from(serde_json::json!({"domain": "jsondom", "access": "read", "store_type": "json"}).to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
        let body = json_body(resp).await;
        let root = body.as_array().unwrap().iter().find(|u| u["name"] == "root").unwrap();
        assert_eq!(
            root["permissions"],
            serde_json::json!([{"domain": "jsondom", "store_type": "json", "access": "read"}])
        );
    }

    // Test 6: multiple permissions come back in a fixed (store_type, domain) order.
    #[tokio::test]
    async fn list_users_permissions_sorted_deterministically() {
        let (app, auth_cache, _dir) = make_app(false).await;
        add_user(&auth_cache, "carol", "lura_carol", UserRole::User).await;

        for (store_type, domain) in [("rel", "zzz"), ("kv", "bbb"), ("json", "aaa"), ("kv", "aaa")] {
            if store_type == "kv" {
                let resp = send(
                    &app,
                    Method::POST,
                    "/store-api/domains",
                    Body::from(serde_json::json!({"name": domain}).to_string()),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::CREATED);
            }
            let resp = send(
                &app,
                Method::POST,
                "/store-api/auth/users/carol/permissions",
                Body::from(serde_json::json!({"domain": domain, "access": "read", "store_type": store_type}).to_string()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
        let body = json_body(resp).await;
        let carol = body.as_array().unwrap().iter().find(|u| u["name"] == "carol").unwrap();
        let actual: Vec<(&str, &str)> = carol["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["store_type"].as_str().unwrap(), p["domain"].as_str().unwrap()))
            .collect();
        // (store_type, domain), lexicographic: "json" < "kv" < "rel".
        assert_eq!(actual, vec![("json", "aaa"), ("kv", "aaa"), ("kv", "bbb"), ("rel", "zzz")]);
    }

    // Test 7: a non-admin key is still forbidden on GET /auth/users (unchanged
    // by this spec -- extract_domain("/store-api/auth/users") stays None).
    #[tokio::test]
    async fn list_users_forbidden_for_non_admin_key() {
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
    }

    // Test 8: a permission on a since-deleted KV domain still shows up
    // unchanged -- the read path doesn't cross-check the registry.
    #[tokio::test]
    async fn list_users_shows_phantom_permission_after_domain_deleted() {
        let (app, auth_cache, _dir) = make_app(false).await;
        add_user(&auth_cache, "dana", "lura_dana", UserRole::User).await;

        let resp = send(
            &app,
            Method::POST,
            "/store-api/domains",
            Body::from(serde_json::json!({"name": "gonesoon"}).to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = send(
            &app,
            Method::POST,
            "/store-api/auth/users/dana/permissions",
            Body::from(serde_json::json!({"domain": "gonesoon", "access": "write"}).to_string()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::DELETE, "/store-api/domains/gonesoon", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp = send(&app, Method::GET, "/store-api/auth/users", Body::empty()).await;
        let body = json_body(resp).await;
        let dana = body.as_array().unwrap().iter().find(|u| u["name"] == "dana").unwrap();
        assert_eq!(
            dana["permissions"],
            serde_json::json!([{"domain": "gonesoon", "store_type": "kv", "access": "write"}])
        );
    }
}
