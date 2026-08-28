//! Domain-management REST handlers.
//!
//! POST   /store-api/domains              → create_domain  (201 Created)
//! GET    /store-api/domains              → list_domains   (200 OK)
//! GET    /store-api/domains/{name}       → get_domain     (200 OK | 404)
//! DELETE /store-api/domains/{name}       → delete_domain  (202 Accepted | 404)

use crate::api::{middleware::ApiError, AppState};
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
}

#[derive(Serialize, ToSchema)]
pub struct DomainResponse {
    /// User-visible domain name.
    pub name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

impl From<crate::engines::lsm::Domain> for DomainResponse {
    fn from(d: crate::engines::lsm::Domain) -> Self {
        DomainResponse { name: d.name, created_at: d.created_at }
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
pub async fn create_domain(
    State(state): State<AppState>,
    Json(body): Json<CreateDomainRequest>,
) -> Result<(StatusCode, Json<DomainResponse>), ApiError> {
    let domain = state.registry.create_domain(&body.name).await.map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(DomainResponse::from(domain))))
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
    let domains = state.registry.list_domains().await.map_err(ApiError::from)?;
    Ok(Json(domains.into_iter().map(DomainResponse::from).collect()))
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
    state.registry.delete_domain(&name).await.map_err(ApiError::from)?;
    Ok(StatusCode::ACCEPTED)
}
