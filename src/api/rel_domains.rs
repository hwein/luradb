//! rel-domain REST handlers (spec rel/009 §2, pattern `json_domains.rs`).
//!
//! POST   /store-api/rel/domains          → create_domain  (201 | 409 | 400)
//! GET    /store-api/rel/domains          → list_domains   (200)
//! GET    /store-api/rel/domains/{name}   → get_domain     (200 | 404 | 410)
//! DELETE /store-api/rel/domains/{name}   → delete_domain  (202 | 404 | 410)

use crate::api::rel::rel_engine;
use crate::api::{middleware::ApiError, AppState};
use crate::engines::rel::{RelDomain, RelDomainState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateRelDomainRequest {
    /// Domain name (max 50 chars, `[a-zA-Z0-9_-]`; `"domains"` is reserved).
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct RelDomainResponse {
    pub name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Lifecycle state: "active" or "deleting" (background purge running, rel/013).
    /// Always present — so rel/013's later `list_domains` visibility change
    /// (surfacing `Deleting` domains too) needs no REST-contract change.
    pub state: String,
}

impl From<RelDomain> for RelDomainResponse {
    fn from(d: RelDomain) -> Self {
        let state = match d.state {
            RelDomainState::Active => "active",
            RelDomainState::Deleting => "deleting",
        };
        RelDomainResponse { name: d.name, created_at: d.created_at, state: state.to_string() }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/rel/domains",
    request_body = CreateRelDomainRequest,
    responses(
        (status = 201, description = "Relational domain created", body = RelDomainResponse),
        (status = 409, description = "Domain already exists", body = String, content_type = "text/plain"),
        (status = 400, description = "Invalid domain name", body = String, content_type = "text/plain"),
        (status = 503, description = "Relational engine disabled", body = String, content_type = "text/plain"),
    ),
    tag = "Relational Domains"
)]
/// Creates a new relational domain (isolated table/view namespace, separate
/// from KV and JSON domains).
pub async fn create_domain(
    State(state): State<AppState>,
    Json(body): Json<CreateRelDomainRequest>,
) -> Result<(StatusCode, Json<RelDomainResponse>), ApiError> {
    let engine = rel_engine(&state)?;
    let domain = engine.create_domain(&body.name).await?;
    Ok((StatusCode::CREATED, Json(domain.into())))
}

#[utoipa::path(
    get,
    path = "/store-api/rel/domains",
    responses(
        (status = 200, description = "List of active relational domains", body = Vec<RelDomainResponse>),
        (status = 503, description = "Relational engine disabled", body = String, content_type = "text/plain"),
    ),
    tag = "Relational Domains"
)]
/// Returns all active relational domains.
pub async fn list_domains(State(state): State<AppState>) -> Result<Json<Vec<RelDomainResponse>>, ApiError> {
    let engine = rel_engine(&state)?;
    Ok(Json(engine.list_domains().into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/store-api/rel/domains/{name}",
    params(("name" = String, Path, description = "Relational domain name")),
    responses(
        (status = 200, description = "Domain found", body = RelDomainResponse),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted (background purge running)", body = String, content_type = "text/plain"),
        (status = 503, description = "Relational engine disabled", body = String, content_type = "text/plain"),
    ),
    tag = "Relational Domains"
)]
/// Returns metadata for a single relational domain. A domain in `deleting`
/// state answers 410 Gone (rel/013 finishes the physical purge).
pub async fn get_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<RelDomainResponse>, ApiError> {
    let engine = rel_engine(&state)?;
    let domain = engine.get_domain_any(&name).ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: rel domain '{name}' not found"))
    })?;
    if domain.state == RelDomainState::Deleting {
        return Err(ApiError::new(
            StatusCode::GONE,
            format!("410 Gone: rel domain '{name}' is being deleted (state: deleting)"),
        ));
    }
    Ok(Json(domain.into()))
}

#[utoipa::path(
    delete,
    path = "/store-api/rel/domains/{name}",
    params(("name" = String, Path, description = "Relational domain name")),
    responses(
        (status = 202, description = "Deletion accepted — background purge follows (rel/013)"),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is already being deleted", body = String, content_type = "text/plain"),
        (status = 503, description = "Relational engine disabled", body = String, content_type = "text/plain"),
    ),
    tag = "Relational Domains"
)]
/// Marks a relational domain as deleting. Its tables/views become
/// inaccessible immediately; physical cleanup follows in rel/013.
pub async fn delete_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let engine = rel_engine(&state)?;
    engine.delete_domain(&name).await?;
    Ok(StatusCode::ACCEPTED)
}
