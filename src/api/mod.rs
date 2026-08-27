//! API module — AppState, router assembly, and sub-module exports.

pub mod backup;
pub mod domains;
pub mod json;
pub mod json_domains;
pub mod kv;
pub mod kvpair;
pub mod logs;
pub mod metrics;
pub mod middleware;
pub mod rel;
pub mod rel_browse;
pub mod rel_domains;

use crate::auth::{handlers::AuthState, middleware::auth_layer, AuthCache};
use crate::backup::BackupManager;
use crate::engines::json::JsonEngine;
use crate::engines::lsm::DomainRegistry;
use crate::engines::rel::RelEngine;
use crate::ipc::ShmManager;
use crate::metrics::MetricsStore;
use axum::{
    extract::DefaultBodyLimit,
    middleware::from_fn_with_state,
    routing::{delete, get, patch, post, put},
    Router,
};
use middleware::{proxy_fn, ParsedCidr};
use std::sync::Arc;
use utoipa::{openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme}, Modify, OpenApi};

// ── Security scheme (Modify hook) ─────────────────────────────────────────────

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "API key as configured in `luradb.toml` (admins), or as received on user creation / key rotation. Only required when `auth.enabled = true`.",
                    ))
                    .build(),
            ),
        );
    }
}

// ── API contract version (Modify hook) ────────────────────────────────────────

/// API contract version (SemVer) — independent of the server version in Cargo.toml.
/// Bump rules: COMPATIBILITY.md in the private concepts repo. Single source of
/// truth; the OpenAPI contract and GET /version both read from here.
pub const API_VERSION: &str = "0.3.1";

struct VersionInfo;

impl Modify for VersionInfo {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info.version = API_VERSION.to_string();
        openapi
            .info
            .extensions
            .get_or_insert_with(Default::default)
            .insert(
                "x-luradb-server-version".to_string(),
                serde_json::json!(env!("CARGO_PKG_VERSION")),
            );
    }
}

// ── AppState ──────────────────────────────────────────────────────────────────

/// Shared application state injected into every Axum handler.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<DomainRegistry>,
    pub auth_cache: Arc<AuthCache>,
    pub auth_enabled: bool,
    pub metrics: Arc<MetricsStore>,
    /// `None` when the JSON engine is disabled via `json.enabled = false`.
    pub json_engine: Option<Arc<JsonEngine>>,
    /// `None` when the relational engine is disabled via `rel.enabled = false`.
    pub rel_engine: Option<Arc<RelEngine>>,
    /// `None` when `shm.enabled = false` (spec perf/006).
    pub shm_manager: Option<Arc<ShmManager>>,
    /// `None` when `backup.enabled = false` (spec general/006) — routes stay
    /// registered either way; handlers answer 503 (plaintext `ApiError`).
    pub backup_manager: Option<Arc<BackupManager>>,
    /// `None` when `log.http_access = false` (spec general/005) — routes stay
    /// registered either way; handlers answer 503 (plaintext `ApiError`).
    pub log_access: Option<logs::LogAccessState>,
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Builds the full domain + KV + auth router with the given app state.
pub fn create_router(state: AppState, trusted_cidrs: Arc<Vec<ParsedCidr>>) -> Router {
    let auth_state = AuthState {
        cache: Arc::clone(&state.auth_cache),
        registry: Arc::clone(&state.registry),
        auth_enabled: state.auth_enabled,
    };

    let mut store_router = Router::new()
        // Metrics (admin / domain user)
        .route("/metrics", get(metrics::get_metrics))
        .route("/metrics/domains/:name", get(metrics::get_domain_metrics))
        // Domain management
        .route("/domains", post(domains::create_domain).get(domains::list_domains))
        .route("/domains/:name", get(domains::get_domain).delete(domains::delete_domain))
        // KV operations (engine → domain → resource)
        .route(
            "/kv/:domain/keys/:key",
            put(kv::put_key).get(kv::get_key).delete(kv::delete_key),
        )
        .route("/kv/:domain/keys/:key/null", patch(kv::set_null))
        .route("/kv/:domain/keys", get(kv::scan_keys))
        .route("/kv/:domain/watch", get(kv::watch))
        // JSON document store (handlers answer 503 when the engine is disabled)
        .route(
            "/json/domains",
            post(json_domains::create_domain).get(json_domains::list_domains),
        )
        .route(
            "/json/domains/:name",
            get(json_domains::get_domain).delete(json_domains::delete_domain),
        )
        .route(
            "/json/:domain/documents",
            post(json::create_document).get(json::list_documents),
        )
        .route("/json/:domain/documents/count", get(json::count_documents))
        .route(
            "/json/:domain/documents/:key",
            put(json::put_document).get(json::get_document).delete(json::delete_document),
        )
        .route("/json/:domain/indexes", post(json::create_index).get(json::list_indexes))
        .route("/json/:domain/indexes/:field", delete(json::delete_index))
        .route("/json/:domain/search", post(json::search_documents))
        // Bulk imports exceed axum's 2 MB default body limit; when the JSON
        // engine is disabled the safe default stays (route answers 503).
        .route(
            "/json/:domain/bulk",
            post(json::bulk_load).layer(DefaultBodyLimit::max(
                state
                    .json_engine
                    .as_ref()
                    .map_or(2 * 1024 * 1024, |e| e.bulk_body_limit_bytes()),
            )),
        )
        .route("/json/:domain/export", get(json::export_documents))
        .route("/json/:domain/reindex", post(json::trigger_reindex))
        .route("/json/:domain/reindex/:task_id", get(json::reindex_status))
        // Backup & Restore (spec general/006). Always registered — like the
        // JSON engine (and unlike rel), `backup.enabled = false` is a
        // handler-level 503, not a router-level absence, so on/off never
        // changes the contract's route surface.
        .route("/backups", post(backup::create_backup).get(backup::list_backups))
        .route("/backups/upload", post(backup::upload_backup))
        .route("/backups/:id", get(backup::get_backup).delete(backup::delete_backup))
        .route("/backups/:id/download", get(backup::download_backup))
        .route("/backups/:id/restore", post(backup::restore_backup))
        .route("/restores/:id", get(backup::get_restore_status))
        // Log Access (spec general/005). Always registered — like backup and
        // the JSON engine — so `log.http_access = false` stays a handler-level
        // 503, keeping 404 free for "wrong URL / old server".
        .route("/logs", get(logs::get_logs))
        .route("/logs/files", get(logs::list_files))
        .with_state(state.clone());

    // Relational store (spec rel/009 §1): registered *only* when the engine
    // is enabled — unlike json/009, a disabled rel engine means the whole
    // rel REST surface is absent (axum default 404), not a 503 per handler.
    // A disabled engine means no rel data can exist at all, so conditional
    // registration is the KISS choice: it keeps the router free of routes
    // that could never do anything but reject.
    if state.rel_engine.is_some() {
        let rel_routes = Router::new()
            .route(
                "/rel/domains",
                post(rel_domains::create_domain).get(rel_domains::list_domains),
            )
            .route(
                "/rel/domains/:name",
                get(rel_domains::get_domain).delete(rel_domains::delete_domain),
            )
            .route("/rel/:domain/sql", post(rel::execute_sql))
            // Browse/Row REST surface (spec rel/010): registered in this
            // same conditional sub-router, not a second merge point.
            .route("/rel/:domain/tables", get(rel_browse::list_tables))
            .route("/rel/:domain/tables/:table", get(rel_browse::get_table))
            .route("/rel/:domain/views", get(rel_browse::list_views))
            .route(
                "/rel/:domain/tables/:table/rows",
                get(rel_browse::browse_rows).post(rel_browse::insert_row),
            )
            .route(
                "/rel/:domain/tables/:table/rows/:pk",
                get(rel_browse::get_row).put(rel_browse::update_row).delete(rel_browse::delete_row),
            )
            .with_state(state.clone());
        store_router = store_router.merge(rel_routes);
    }

    let auth_router = Router::new()
        .route("/auth/whoami", get(crate::auth::handlers::whoami))
        .route(
            "/auth/users",
            post(crate::auth::handlers::create_user).get(crate::auth::handlers::list_users),
        )
        .route("/auth/users/:name", delete(crate::auth::handlers::delete_user))
        .route(
            "/auth/users/:name/permissions",
            post(crate::auth::handlers::set_permission),
        )
        .route(
            "/auth/users/:name/permissions/:domain",
            delete(crate::auth::handlers::remove_permission),
        )
        .route(
            "/auth/users/:name/rotate-key",
            post(crate::auth::handlers::rotate_key),
        )
        .with_state(auth_state);

    let mut router = Router::new()
        // Heartbeat at root (infra convention for load balancers / k8s probes)
        .route("/health", get(metrics::health).with_state(state.clone()))
        // Version handshake at root, next to /health (spec 004 §7) — reads
        // only constants, no engine access, so no state needed.
        .route("/version", get(metrics::version))
        .nest("/store-api", store_router.merge(auth_router));

    if state.auth_enabled {
        router = router.layer(from_fn_with_state(
            Arc::clone(&state.auth_cache),
            auth_layer,
        ));
    }

    // Proxy layer is outermost: runs first, sets ClientIp on every request.
    router = router.layer(from_fn_with_state(trusted_cidrs, proxy_fn));

    router
}

// ── OpenAPI / Swagger ─────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(
        // Metrics / Heartbeat
        metrics::health,
        metrics::version,
        metrics::get_metrics,
        metrics::get_domain_metrics,
        // Domain management
        domains::create_domain,
        domains::list_domains,
        domains::get_domain,
        domains::delete_domain,
        // KV operations
        kv::put_key,
        kv::get_key,
        kv::delete_key,
        kv::set_null,
        kv::scan_keys,
        kv::watch,
        // JSON domains
        json_domains::create_domain,
        json_domains::list_domains,
        json_domains::get_domain,
        json_domains::delete_domain,
        // JSON documents / search / bulk / re-index
        json::create_document,
        json::put_document,
        json::get_document,
        json::delete_document,
        json::list_documents,
        json::count_documents,
        json::create_index,
        json::list_indexes,
        json::delete_index,
        json::search_documents,
        json::bulk_load,
        json::export_documents,
        json::trigger_reindex,
        json::reindex_status,
        // Relational domains
        rel_domains::create_domain,
        rel_domains::list_domains,
        rel_domains::get_domain,
        rel_domains::delete_domain,
        // Relational SQL
        rel::execute_sql,
        // Relational Browse (catalog + rows)
        rel_browse::list_tables,
        rel_browse::get_table,
        rel_browse::list_views,
        rel_browse::browse_rows,
        rel_browse::get_row,
        // Relational Rows (writes)
        rel_browse::insert_row,
        rel_browse::update_row,
        rel_browse::delete_row,
        // Auth / User management
        crate::auth::handlers::whoami,
        crate::auth::handlers::create_user,
        crate::auth::handlers::list_users,
        crate::auth::handlers::delete_user,
        crate::auth::handlers::set_permission,
        crate::auth::handlers::remove_permission,
        crate::auth::handlers::rotate_key,
        // Backup & Restore
        backup::create_backup,
        backup::list_backups,
        backup::get_backup,
        backup::download_backup,
        backup::delete_backup,
        backup::upload_backup,
        backup::restore_backup,
        backup::get_restore_status,
        // Log Access
        logs::get_logs,
        logs::list_files,
    ),
    modifiers(&BearerAuth, &VersionInfo),
    components(
        schemas(
            metrics::VersionResponse,
            domains::CreateDomainRequest,
            domains::DomainResponse,
            json_domains::CreateJsonDomainRequest,
            json_domains::JsonDomainResponse,
            json::CreateIndexRequest,
            json::IndexResponse,
            json::SearchRequest,
            json::SearchResponse,
            json::ListParams,
            json::DocumentListResponse,
            json::CountResponse,
            json::BulkErrorEntry,
            json::BulkLoadResponse,
            json::ReindexRequest,
            json::ReindexAcceptedResponse,
            rel_domains::CreateRelDomainRequest,
            rel_domains::RelDomainResponse,
            rel::SqlRequest,
            rel_browse::TableSummary,
            rel_browse::TableLinks,
            rel_browse::TableDetail,
            rel_browse::ColumnInfo,
            rel_browse::IndexInfo,
            rel_browse::ViewSummary,
            rel_browse::RowsResponse,
            crate::auth::handlers::WhoamiResponse,
            crate::auth::handlers::CreateUserRequest,
            crate::auth::handlers::CreateUserResponse,
            crate::auth::handlers::UserListItem,
            crate::auth::handlers::PermissionItem,
            crate::auth::handlers::SetPermissionRequest,
            crate::auth::handlers::RotateKeyResponse,
            backup::CreateBackupRequest,
            backup::BackupAcceptedResponse,
            backup::BackupSummaryResponse,
            backup::RunningBackupInfo,
            backup::BackupListResponse,
            backup::BackupDetailResponse,
            backup::RestoreRequest,
            backup::RestoreAcceptedResponse,
            backup::RestoreErrorEntry,
            backup::RestoreStatusResponse,
            logs::LogQuery,
            logs::LogResponse,
            logs::LogFileInfo,
            logs::LogFilesResponse,
        )
    ),
    security(("bearer_auth" = [])),
    tags(
        (name = "Metrics", description = "Heartbeat and performance metrics"),
        (name = "Domains", description = "Domain lifecycle — create, list, get, delete"),
        (name = "Key-Value Store", description = "Domain-scoped key-value operations"),
        (name = "JSON Document Store", description = "Domain-scoped JSON document operations"),
        (name = "JSON Indexes", description = "Index management for JSON domains"),
        (name = "Relational Domains", description = "Relational domain lifecycle"),
        (name = "Relational Store", description = "Domain-scoped LuraSQL execution"),
        (name = "Relational Browse", description = "Catalog and row browsing for relational domains"),
        (name = "Relational Rows", description = "Row-level writes on relational tables"),
        (name = "Auth", description = "User management and domain permissions — admins only, except GET /auth/whoami (any authenticated caller)"),
        (name = "Backup", description = "Logical backup & restore — admins only"),
        (name = "Logs", description = "Read-only log tail and file listing — admins only, opt-in via log.http_access"),
    ),
    info(
        title = "LuraDB API",
        description = "REST-native multi-model database — KeyValue and JSON engines. \
            `version` is the API contract version (see API_VERSION), independent of the \
            server version; the latter is in the `x-luradb-server-version` extension. \
            Runtime check: GET /version."
    )
)]
pub struct ApiDoc;

// ── Contract drift gate (spec 004 §5) ──────────────────────────────────────────

#[cfg(test)]
mod contract_tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn contract_file_is_up_to_date() {
        let generated = format!("{}\n", ApiDoc::openapi().to_pretty_json().unwrap());
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/api/openapi.json");
        let committed = std::fs::read_to_string(path).expect(
            "api/openapi.json missing — generate with: cargo run -- --dump-openapi > api/openapi.json",
        );
        assert_eq!(
            generated, committed,
            "api/openapi.json is stale. Regenerate: \
             cargo run -- --dump-openapi > api/openapi.json — and check whether info.version \
             needs a bump and whether COMPATIBILITY.md in the concepts repo \
             needs a new line."
        );
    }

    #[test]
    fn contract_carries_server_version_extension() {
        let json = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(
            json["info"]["x-luradb-server-version"],
            serde_json::json!(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn contract_version_is_api_version_and_semver() {
        let json = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(json["info"]["version"], serde_json::json!(API_VERSION));

        let segments: Vec<&str> = API_VERSION.split('.').collect();
        assert_eq!(segments.len(), 3, "API_VERSION must be SemVer (X.Y.Z): {API_VERSION}");
        for segment in segments {
            assert!(
                !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()),
                "SemVer segment is not purely numeric: {segment}"
            );
        }
    }

    #[test]
    fn contract_contains_version_path_with_bearer_security() {
        let json = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let security = &json["paths"]["/version"]["get"]["security"];
        let requirements = security.as_array().expect("/version GET has a security array");
        assert!(
            requirements
                .iter()
                .any(|req| req.as_object().is_some_and(|o| o.contains_key("bearer_auth"))),
            "/version must carry bearer_auth security, was: {security}"
        );
    }
}

// ── Router↔Contract coverage gate (spec general/009) ──────────────────────────

#[cfg(test)]
mod router_coverage_tests {
    use super::*;
    use std::collections::BTreeSet;
    use utoipa::OpenApi;

    const HTTP_METHODS: [&str; 8] =
        ["get", "post", "put", "delete", "patch", "head", "options", "trace"];

    /// Strips `//` comments (string literals are kept, including `\"` escapes),
    /// so that commented-out routes and comment text don't fool the parser.
    fn without_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut chars = src.chars().peekable();
        let mut in_string = false;
        while let Some(c) = chars.next() {
            if in_string {
                out.push(c);
                match c {
                    '\\' => {
                        if let Some(d) = chars.next() {
                            out.push(d);
                        }
                    }
                    '"' => in_string = false,
                    _ => {}
                }
            } else if c == '"' {
                in_string = true;
                out.push(c);
            } else if c == '/' && chars.peek() == Some(&'/') {
                for d in chars.by_ref() {
                    if d == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Comment-free source text of `create_router` — from the signature to the
    /// closing brace in column 0 (rustfmt invariant).
    fn create_router_source() -> String {
        let src = without_comments(include_str!("mod.rs"));
        let start = src.find("fn create_router").expect("fn create_router not found");
        let end = src[start..]
            .find("\n}")
            .expect("end of create_router function not found");
        src[start..start + end].to_string()
    }

    /// Byte index of the closing parenthesis of the already-opened call.
    fn paren_end(src: &str) -> usize {
        let mut depth = 1u32;
        let mut in_string = false;
        for (i, c) in src.char_indices() {
            match c {
                '"' => in_string = !in_string,
                '(' if !in_string => depth += 1,
                ')' if !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        return i;
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced parentheses in create_router");
    }

    /// HTTP method calls (`get(…)`, `.post(…)`, …) in a `.route` argument list.
    fn http_methods(args: &str) -> Vec<String> {
        let bytes = args.as_bytes();
        let mut found = Vec::new();
        let mut in_string = false;
        let mut i = 0;
        while i < bytes.len() {
            if in_string {
                in_string = bytes[i] != b'"';
                i += 1;
            } else if bytes[i] == b'"' {
                in_string = true;
                i += 1;
            } else if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &args[start..i];
                if HTTP_METHODS.contains(&word) && bytes.get(i) == Some(&b'(') {
                    found.push(word.to_string());
                }
            } else {
                i += 1;
            }
        }
        found
    }

    /// axum `:param` → OpenAPI `{param}`.
    fn normalize_path(path: &str) -> String {
        path.split('/')
            .map(|seg| match seg.strip_prefix(':') {
                Some(name) => format!("{{{name}}}"),
                None => seg.to_string(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// All `.route("<path>", …)` registrations of a source-text section,
    /// as (method, prefix+path) pairs.
    fn route_pairs(section: &str, prefix: &str) -> BTreeSet<(String, String)> {
        let mut pairs = BTreeSet::new();
        let mut rest = section;
        while let Some(pos) = rest.find(".route(") {
            rest = &rest[pos + ".route(".len()..];
            let args = &rest[..paren_end(rest)];
            let path_start = args.find('"').expect(".route without a path literal") + 1;
            let path_end = path_start + args[path_start..].find('"').expect("path literal not terminated");
            let path = format!("{prefix}{}", normalize_path(&args[path_start..path_end]));
            let methods = http_methods(args);
            assert!(!methods.is_empty(), "no HTTP method detected in .route({path:?}, …)");
            for method in methods {
                pairs.insert((method, path.clone()));
            }
            rest = &rest[args.len()..];
        }
        pairs
    }

    /// (method, path) pairs of the contract definition. Deliberately `ApiDoc::openapi()`
    /// instead of `api/openapi.json`: the drift gate above keeps the definition and the
    /// file identical, so a stale file turns exactly one test red instead of two.
    fn contract_pairs() -> BTreeSet<(String, String)> {
        let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let mut pairs = BTreeSet::new();
        for (path, item) in doc["paths"].as_object().expect("contract without paths") {
            for method in item.as_object().expect("path item is not an object").keys() {
                if HTTP_METHODS.contains(&method.as_str()) {
                    pairs.insert((method.clone(), path.clone()));
                }
            }
        }
        pairs
    }

    /// The drift gate only guarantees definition == file; a route registered in
    /// `create_router` without a `paths(...)` entry would be silently missing on
    /// both sides. Axum offers no router introspection, hence the source-text parse.
    /// Swagger's runtime routes and the hello route (main.rs) are deliberately not
    /// part of the contract and live outside `create_router`.
    #[test]
    fn every_registered_route_matches_contract_exactly() {
        let body = create_router_source();

        // Guard the structural assumptions: fail loudly on a create_router
        // refactor instead of silently mis-parsing.
        assert_eq!(body.matches(".nest(").count(), 1, "nesting changed — adjust the parser");
        assert!(body.contains(".nest(\"/store-api\""), "nest prefix changed — adjust the parser");
        for bypass in [".route_service(", ".nest_service(", ".fallback("] {
            assert!(!body.contains(bypass), "{bypass} registers routes past the parser");
        }
        for (i, _) in body.match_indices(".merge(") {
            let arg = &body[i + ".merge(".len()..];
            let arg = &arg[..arg.find(')').expect(".merge without a closing parenthesis")];
            assert!(
                body.contains(&format!("let {arg} = Router::new()"))
                    || body.contains(&format!("let mut {arg} = Router::new()")),
                ".merge({arg}): not a locally built router — the parser won't see its routes"
            );
        }

        let root_at = body
            .find("let mut router = Router::new()")
            .expect("root router marker not found — adjust the parser");
        let (nested, root) = body.split_at(root_at);
        let mut registered = route_pairs(nested, "/store-api");
        registered.extend(route_pairs(root, ""));
        assert!(!registered.is_empty(), "parser found no .route registrations");

        let contract = contract_pairs();
        let not_in_contract: Vec<_> = registered.difference(&contract).collect();
        let not_registered: Vec<_> = contract.difference(&registered).collect();
        assert!(
            not_in_contract.is_empty() && not_registered.is_empty(),
            "Router registration and OpenAPI contract diverge.\n\
             Registered but missing from the contract — add a #[utoipa::path] + paths(...) entry: {not_in_contract:?}\n\
             In the contract but not registered — stale paths(...) entry or missing .route(): {not_registered:?}"
        );
    }
}
