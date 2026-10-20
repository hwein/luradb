//! Domain-management REST handlers.
//!
//! POST   /store-api/domains              → create_domain  (201 Created)
//! GET    /store-api/domains              → list_domains   (200 OK)
//! GET    /store-api/domains/{name}       → get_domain     (200 OK | 404)
//! DELETE /store-api/domains/{name}       → delete_domain  (202 Accepted | 404)

use crate::api::{middleware::ApiError, AppState};
use crate::control::{DomainEntry, Engine, Lifecycle};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateDomainRequest {
    /// User-visible domain name (max 50 chars, [a-zA-Z0-9_-]).
    pub name: String,
    /// When true, PUT, DELETE and PATCH …/null on single keys need `If-Match` or
    /// `If-None-Match: *` and answer 428 without. Fixed at creation; default false.
    #[serde(default)]
    pub require_conditional_writes: bool,
}

#[derive(Serialize, ToSchema)]
pub struct DomainResponse {
    /// User-visible domain name.
    pub name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Whether single-key writes need `If-Match` or `If-None-Match: *` (else 428).
    pub require_conditional_writes: bool,
}

impl From<crate::engines::lsm::Domain> for DomainResponse {
    fn from(d: crate::engines::lsm::Domain) -> Self {
        DomainResponse {
            name: d.name,
            created_at: d.created_at,
            require_conditional_writes: d.require_conditional_writes,
        }
    }
}

impl From<&DomainEntry> for DomainResponse {
    fn from(d: &DomainEntry) -> Self {
        DomainResponse {
            name: d.name.clone(),
            created_at: d.created_at,
            require_conditional_writes: d.require_conditional_writes,
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/domains",
    request_body = CreateDomainRequest,
    responses(
        (status = 201, description = "Domain created", body = DomainResponse),
        (status = 409, description = "Domain already exists", body = String, content_type = "text/plain"),
        (status = 400, description = "Invalid domain name", body = String, content_type = "text/plain"),
    ),
    tag = "Domains"
)]
/// Creates a new logical domain (isolated KV namespace).
/// Domain names must be unique, max 50 chars, and match `[a-zA-Z0-9_-]`.
/// With `require_conditional_writes`, single-key writes over REST (PUT, DELETE, PATCH …/null) must
/// carry `If-Match` or `If-None-Match: *`; bulk operations and other write paths are not affected.
pub async fn create_domain(
    State(state): State<AppState>,
    Json(body): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    let domain = state.control.create_domain(Engine::Kv, &body.name, body.require_conditional_writes).await?;
    Ok((StatusCode::CREATED, Json(DomainResponse::from(&domain))))
}

#[utoipa::path(
    get,
    path = "/store-api/domains",
    responses(
        (status = 200, description = "List of active domains", body = Vec<DomainResponse>),
    ),
    tag = "Domains"
)]
/// Returns all active domains with their names and creation timestamps.
pub async fn list_domains(
    State(state): State<AppState>,
) -> Result<Json<Vec<DomainResponse>>, ApiError> {
    let directory = state.control.directory();
    let active = directory.domains(Engine::Kv).filter(|d| d.state == Lifecycle::Active);
    Ok(Json(active.map(DomainResponse::from).collect()))
}

#[utoipa::path(
    get,
    path = "/store-api/domains/{name}",
    params(("name" = String, Path, description = "Domain name")),
    responses(
        (status = 200, description = "Domain found", body = DomainResponse),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
    ),
    tag = "Domains"
)]
/// Returns metadata for a single domain by name. Returns 404 if it does not exist.
pub async fn get_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<DomainResponse>, ApiError> {
    let domain = state
        .registry
        .get_domain(&name)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("404 Not Found: Domain '{}' not found", name)))?;
    Ok(Json(DomainResponse::from(domain)))
}

#[utoipa::path(
    delete,
    path = "/store-api/domains/{name}",
    params(("name" = String, Path, description = "Domain name")),
    responses(
        (status = 202, description = "Deletion accepted — background purge started"),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
    ),
    tag = "Domains"
)]
/// Schedules a domain and all its data for deletion.
/// The domain becomes immediately inaccessible; the actual purge runs in the background.
pub async fn delete_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.control.delete_domain(Engine::Kv, &name).await?;
    Ok(StatusCode::ACCEPTED)
}
