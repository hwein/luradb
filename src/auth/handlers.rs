//! REST handlers for user management and domain permissions.
//!
//! All endpoints require Admin role (enforced by AuthMiddleware before these handlers run).
//!
//! POST   /store-api/auth/users                           → create_user   (201 | 409)
//! GET    /store-api/auth/users                           → list_users    (200)
//! DELETE /store-api/auth/users/:name                     → delete_user   (204 | 404)
//! POST   /store-api/auth/users/:name/permissions         → set_permission (200 | 404)
//! DELETE /store-api/auth/users/:name/permissions/:domain → remove_permission (204 | 404)
//! POST   /store-api/auth/users/:name/rotate-key          → rotate_key    (200 | 404)

use crate::auth::middleware::StoreType;
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
fn valid_name(name: &str) -> bool {
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

#[utoipa::path(
    get,
    path = "/store-api/auth/users",
    responses(
        (status = 200, description = "List of all users (without API keys)", body = Vec<UserListItem>),
    ),
    tag = "Auth"
)]
/// Returns all created users (admins and regular users).
/// API keys are not included — only name, role, and creation timestamp.
pub async fn list_users(State(state): State<AuthState>) -> Json<Vec<UserListItem>> {
    let users = state.cache.all_users().await;
    let items = users
        .into_iter()
        .map(|r| UserListItem {
            name: r.name,
            role: format!("{:?}", r.role),
            created_at: r.created_at,
        })
        .collect();
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
}
