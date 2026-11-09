//! Domain-management REST handlers. A domain holds data in every engine; it
//! is created, listed, described and deleted once.
//!
//! POST   /store-api/domains              → create_domain  (201 | 400 | 409)
//! GET    /store-api/domains              → list_domains   (200)
//! GET    /store-api/domains/{name}       → get_domain     (200 | 403 | 404 | 410)
//! DELETE /store-api/domains/{name}       → delete_domain  (202 | 404 | 410)

use crate::api::{middleware::ApiError, AppState};
use crate::auth::middleware::{split_permission_domain, AuthOutcome, AuthUser};
use crate::control::{ConditionalWrites, DomainEntry, DomainError, Lifecycle};
use axum::{
    extract::{rejection::JsonRejection, Extension, Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use utoipa::ToSchema;

/// Which domains a caller may see.
pub(crate) struct DomainFilter(Option<HashSet<String>>);

impl DomainFilter {
    /// Admins, trusted peers and auth-off setups see every domain; a user sees
    /// the domains they hold a permission on, on the whole domain or on any
    /// engine. Auth on with
    /// neither outcome nor user is a middleware bug: fail closed.
    pub(crate) async fn for_caller(
        state: &AppState,
        outcome: Option<Extension<AuthOutcome>>,
        user: Option<Extension<AuthUser>>,
    ) -> Result<Self, ApiError> {
        if !state.auth_enabled || matches!(outcome, Some(Extension(AuthOutcome::Full))) {
            return Ok(Self(None));
        }
        let Some(Extension(AuthUser(name))) = user else {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "403 Forbidden: no authenticated user"));
        };
        let names = state
            .auth_cache
            .permissions_for_user(&name)
            .await
            .iter()
            .map(|permission| split_permission_domain(&permission.domain).1.to_string())
            .collect();
        Ok(Self(Some(names)))
    }

    pub(crate) fn allows(&self, name: &str) -> bool {
        self.0.as_ref().is_none_or(|names| names.contains(name))
    }
}

/// Whether single-object writes over REST need `If-Match` or
/// `If-None-Match: *`, per engine.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, ToSchema)]
pub struct ConditionalWritesSetting {
    /// PUT, DELETE and PATCH …/null on single keys; default false.
    #[serde(default)]
    pub kv: bool,
    /// PUT and DELETE on single documents; default false.
    #[serde(default)]
    pub json: bool,
}

impl From<ConditionalWritesSetting> for ConditionalWrites {
    fn from(setting: ConditionalWritesSetting) -> Self {
        ConditionalWrites { kv: setting.kv, json: setting.json }
    }
}

impl From<ConditionalWrites> for ConditionalWritesSetting {
    fn from(setting: ConditionalWrites) -> Self {
        ConditionalWritesSetting { kv: setting.kv, json: setting.json }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateDomainRequest {
    /// Domain name: [a-zA-Z0-9_-], 1 to `domains.max_name_length` (default 50) characters.
    pub name: String,
    /// Without a precondition, such writes answer 428. Fixed at creation;
    /// missing fields are false.
    #[serde(default)]
    pub require_conditional_writes: Option<ConditionalWritesSetting>,
}

#[derive(Serialize, ToSchema)]
pub struct DomainResponse {
    pub name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Lifecycle state: "active" or "deleting" (background purge running).
    pub state: String,
    pub require_conditional_writes: ConditionalWritesSetting,
}

impl From<&DomainEntry> for DomainResponse {
    fn from(d: &DomainEntry) -> Self {
        DomainResponse {
            name: d.name.clone(),
            created_at: d.created_at,
            state: d.state.as_str().to_string(),
            require_conditional_writes: d.require_conditional_writes.into(),
        }
    }
}

const NOT_AN_OBJECT: &str = "require_conditional_writes must be an object {\"kv\": bool, \"json\": bool}";

/// The request body, or `400` with the reason it is unusable.
fn create_request(body: Result<Json<serde_json::Value>, JsonRejection>) -> Result<CreateDomainRequest, ApiError> {
    let bad_request = |reason: &str| ApiError::new(StatusCode::BAD_REQUEST, format!("400 Bad Request: {reason}"));
    let Json(value) = body.map_err(|rejection| bad_request(&rejection.body_text()))?;
    if value.get("require_conditional_writes").is_some_and(|v| !v.is_object() && !v.is_null()) {
        return Err(bad_request(NOT_AN_OBJECT));
    }
    serde_json::from_value(value).map_err(|e| bad_request(&e.to_string()))
}

#[utoipa::path(
    post,
    path = "/store-api/domains",
    operation_id = "create_domain",
    request_body = CreateDomainRequest,
    responses(
        (status = 201, description = "Domain created in every engine", body = DomainResponse),
        (status = 400, description = "Invalid domain name, unusable body, or `require_conditional_writes` not an object", body = String, content_type = "text/plain"),
        (status = 409, description = "Domain exists, also while it is being deleted", body = String, content_type = "text/plain"),
        (status = 500, description = "An engine could not create its part; the domain is deleted again", body = String, content_type = "text/plain"),
    ),
    tag = "Domains"
)]
/// Creates a domain, which holds keys, documents and tables in the key-value,
/// JSON and relational engines. With `require_conditional_writes`,
/// single-object writes over REST of the engines it names must carry
/// `If-Match` or `If-None-Match: *`; bulk operations and other write paths
/// are not affected.
pub async fn create_domain(
    State(state): State<AppState>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    let request = create_request(body)?;
    let setting = request.require_conditional_writes.unwrap_or_default().into();
    match state.control.create_domain(&request.name, setting).await {
        Ok(domain) => Ok((StatusCode::CREATED, Json(DomainResponse::from(&domain)))),
        Err(e @ DomainError::Deleting(_)) => Err(ApiError::new(StatusCode::CONFLICT, format!("409 Conflict: {e}"))),
        Err(e) => Err(e.into()),
    }
}

#[utoipa::path(
    get,
    path = "/store-api/domains",
    operation_id = "list_domains",
    responses(
        (status = 200, description = "The active domains the key holds any permission on", body = Vec<DomainResponse>),
    ),
    tag = "Domains"
)]
/// Returns the active domains, by name. Admin keys see all of them; any other
/// key sees the domains it holds a permission on in any engine (an empty list
/// without any).
pub async fn list_domains(
    State(state): State<AppState>,
    outcome: Option<Extension<AuthOutcome>>,
    user: Option<Extension<AuthUser>>,
) -> Result<Json<Vec<DomainResponse>>, ApiError> {
    let filter = DomainFilter::for_caller(&state, outcome, user).await?;
    let directory = state.control.directory();
    let active = directory.domains().filter(|d| d.state == Lifecycle::Active && filter.allows(&d.name));
    Ok(Json(active.map(DomainResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/store-api/domains/{name}",
    operation_id = "get_domain",
    params(("name" = String, Path, description = "Domain name")),
    responses(
        (status = 200, description = "Domain found", body = DomainResponse),
        (status = 403, description = "Forbidden — no permission on the domain in any engine (also when it does not exist)", body = String, content_type = "text/plain"),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted (background purge running)", body = String, content_type = "text/plain"),
    ),
    tag = "Domains"
)]
/// Returns a domain. Needs a permission on the domain in any engine (admin
/// keys always pass). A domain in `deleting` state answers 410 Gone.
pub async fn get_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<DomainResponse>, ApiError> {
    let directory = state.control.directory();
    match directory.get(&name) {
        None => Err(DomainError::NotFound(name).into()),
        Some(d) if d.state == Lifecycle::Deleting => Err(DomainError::Deleting(name).into()),
        Some(d) => Ok(Json(DomainResponse::from(d))),
    }
}

#[utoipa::path(
    delete,
    path = "/store-api/domains/{name}",
    operation_id = "delete_domain",
    params(("name" = String, Path, description = "Domain name")),
    responses(
        (status = 202, description = "Deletion accepted — background purge of every engine follows"),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is already being deleted", body = String, content_type = "text/plain"),
    ),
    tag = "Domains"
)]
/// Deletes a domain with its keys, documents, tables and views. The domain
/// becomes inaccessible immediately; the purge runs in the background, and
/// the name stays taken until it is done.
pub async fn delete_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.control.delete_domain(&name).await?;
    Ok(StatusCode::ACCEPTED)
}
