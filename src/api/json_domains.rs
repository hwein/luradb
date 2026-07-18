//! JSON-domain REST handlers (spec json/009).
//!
//! POST   /store-api/json/domains          → create_domain  (201 | 409 | 400)
//! GET    /store-api/json/domains          → list_domains   (200)
//! GET    /store-api/json/domains/{name}   → get_domain     (200 | 404)
//! DELETE /store-api/json/domains/{name}   → delete_domain  (202 | 404)

use crate::api::json::json_engine;
use crate::api::{middleware::ApiError, AppState};
use crate::engines::json::{JsonDomain, JsonDomainState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateJsonDomainRequest {
    /// User-visible domain name (max 50 chars, [a-zA-Z0-9_-]).
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct JsonDomainResponse {
    pub name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Lifecycle state: "active" or "deleting" (background purge running).
    pub state: String,
    /// Number of documents — only set on the detail endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_count: Option<u64>,
}

impl From<JsonDomain> for JsonDomainResponse {
    fn from(d: JsonDomain) -> Self {
        let state = match d.state {
            JsonDomainState::Active => "active",
            JsonDomainState::Deleting => "deleting",
        };
        JsonDomainResponse {
            name: d.name,
            created_at: d.created_at,
            state: state.to_string(),
            document_count: None,
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/json/domains",
    request_body = CreateJsonDomainRequest,
    responses(
        (status = 201, description = "JSON domain created", body = JsonDomainResponse),
        (status = 409, description = "Domain already exists"),
        (status = 400, description = "Invalid domain name"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Creates a new JSON domain (isolated document namespace, separate from KV domains).
pub async fn create_domain(
    State(state): State<AppState>,
    Json(body): Json<CreateJsonDomainRequest>,
) -> Result<(StatusCode, Json<JsonDomainResponse>), ApiError> {
    let engine = json_engine(&state)?;
    let domain = engine.create_domain(&body.name).await?;
    Ok((StatusCode::CREATED, Json(domain.into())))
}

#[utoipa::path(
    get,
    path = "/store-api/json/domains",
    responses(
        (status = 200, description = "List of active JSON domains", body = Vec<JsonDomainResponse>),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Returns all active JSON domains.
pub async fn list_domains(
    State(state): State<AppState>,
) -> Result<Json<Vec<JsonDomainResponse>>, ApiError> {
    let engine = json_engine(&state)?;
    Ok(Json(engine.list_domains().into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    get,
    path = "/store-api/json/domains/{name}",
    params(("name" = String, Path, description = "JSON domain name")),
    responses(
        (status = 200, description = "Domain found", body = JsonDomainResponse),
        (status = 404, description = "Domain not found"),
        (status = 410, description = "Domain is being deleted (background purge running)"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Returns metadata for a single JSON domain, including its document count.
/// Domains in `deleting` state answer with 410 Gone.
pub async fn get_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<JsonDomainResponse>, ApiError> {
    let engine = json_engine(&state)?;
    let domain = engine.get_domain_any(&name).ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: JSON domain '{name}' not found"))
    })?;
    if domain.state == JsonDomainState::Deleting {
        return Err(ApiError::new(
            StatusCode::GONE,
            format!("410 Gone: JSON domain '{name}' is being deleted (state: deleting)"),
        ));
    }
    let mut response = JsonDomainResponse::from(domain);
    response.document_count = Some(engine.count_documents(&name).await?);
    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/store-api/json/domains/{name}",
    params(("name" = String, Path, description = "JSON domain name")),
    responses(
        (status = 202, description = "Deletion accepted — background purge follows"),
        (status = 404, description = "Domain not found"),
        (status = 503, description = "JSON engine disabled"),
    ),
    tag = "JSON Document Store"
)]
/// Marks a JSON domain as deleting. Documents become inaccessible immediately.
pub async fn delete_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let engine = json_engine(&state)?;
    engine.delete_domain(&name).await?;
    Ok(StatusCode::ACCEPTED)
}
