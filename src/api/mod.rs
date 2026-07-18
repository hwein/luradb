//! API module — AppState, router assembly, and sub-module exports.

pub mod domains;
pub mod json;
pub mod json_domains;
pub mod kv;
pub mod kvpair;
pub mod metrics;
pub mod middleware;
pub mod rel;
pub mod rel_browse;
pub mod rel_domains;

use crate::auth::{handlers::AuthState, middleware::auth_layer, AuthCache};
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
                        "API Key wie in `luradb.toml` konfiguriert (Admins) oder wie bei User-Anlage / Key-Rotation erhalten. Nur bei `auth.enabled = true` erforderlich.",
                    ))
                    .build(),
            ),
        );
    }
}

// ── API contract version (Modify hook) ────────────────────────────────────────

/// API-Contract-Version (SemVer) — unabhängig von der Server-Version in Cargo.toml.
/// Bump-Regeln: api/COMPATIBILITY.md. Einzige Quelle; OpenAPI-Contract
/// und GET /version lesen von hier.
pub const API_VERSION: &str = "0.2.0";

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
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Builds the full domain + KV + auth router with the given app state.
pub fn create_router(state: AppState, trusted_cidrs: Arc<Vec<ParsedCidr>>) -> Router {
    let auth_state = AuthState {
        cache: Arc::clone(&state.auth_cache),
        registry: Arc::clone(&state.registry),
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
        crate::auth::handlers::create_user,
        crate::auth::handlers::list_users,
        crate::auth::handlers::delete_user,
        crate::auth::handlers::set_permission,
        crate::auth::handlers::remove_permission,
        crate::auth::handlers::rotate_key,
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
            crate::auth::handlers::CreateUserRequest,
            crate::auth::handlers::CreateUserResponse,
            crate::auth::handlers::UserListItem,
            crate::auth::handlers::SetPermissionRequest,
            crate::auth::handlers::RotateKeyResponse,
        )
    ),
    security(("bearer_auth" = [])),
    tags(
        (name = "Metrics", description = "Heartbeat und Performance-Metriken"),
        (name = "Domains", description = "Domain lifecycle — create, list, get, delete"),
        (name = "Key-Value Store", description = "Domain-scoped key-value operations"),
        (name = "JSON Document Store", description = "Domain-scoped JSON document operations"),
        (name = "JSON Indexes", description = "Index management for JSON domains"),
        (name = "Relational Domains", description = "Relational domain lifecycle"),
        (name = "Relational Store", description = "Domain-scoped LuraSQL execution"),
        (name = "Relational Browse", description = "Catalog and row browsing for relational domains"),
        (name = "Relational Rows", description = "Row-level writes on relational tables"),
        (name = "Auth", description = "User-Verwaltung und Domain-Permissions — nur für Admins"),
    ),
    info(
        title = "LuraDB API",
        description = "REST-native multi-model database — KeyValue- und JSON-Engine. \
            `version` ist die API-Contract-Version (siehe API_VERSION), unabhängig von der \
            Server-Version; letztere steht in der Extension `x-luradb-server-version`. \
            Kompatibilitäts-Ranges: api/COMPATIBILITY.md. Laufzeit-Check: GET /version."
    )
)]
pub struct ApiDoc;

// ── Contract drift gate (spec 004 §5) ──────────────────────────────────────────

#[cfg(test)]
mod contract_tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn contract_datei_ist_aktuell() {
        let generated = format!("{}\n", ApiDoc::openapi().to_pretty_json().unwrap());
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/api/openapi.json");
        let committed = std::fs::read_to_string(path).expect(
            "api/openapi.json fehlt — erzeugen mit: cargo run -- --dump-openapi > api/openapi.json",
        );
        assert_eq!(
            generated, committed,
            "api/openapi.json ist nicht aktuell. Regenerieren: \
             cargo run -- --dump-openapi > api/openapi.json — und pruefen, ob info.version \
             gebumpt werden muss (SemVer-Regeln: api/COMPATIBILITY.md) und ob \
             api/COMPATIBILITY.md eine neue Zeile braucht."
        );
    }

    #[test]
    fn contract_traegt_server_version_extension() {
        let json = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(
            json["info"]["x-luradb-server-version"],
            serde_json::json!(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn contract_version_ist_api_version_und_semver() {
        let json = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(json["info"]["version"], serde_json::json!(API_VERSION));

        let segments: Vec<&str> = API_VERSION.split('.').collect();
        assert_eq!(segments.len(), 3, "API_VERSION muss SemVer (X.Y.Z) sein: {API_VERSION}");
        for segment in segments {
            assert!(
                !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()),
                "SemVer-Segment nicht rein numerisch: {segment}"
            );
        }
    }

    #[test]
    fn contract_enthaelt_version_pfad_mit_bearer_security() {
        let json = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let security = &json["paths"]["/version"]["get"]["security"];
        let requirements = security.as_array().expect("/version GET hat security-Array");
        assert!(
            requirements
                .iter()
                .any(|req| req.as_object().is_some_and(|o| o.contains_key("bearer_auth"))),
            "/version muss bearer_auth security tragen, war: {security}"
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

    /// `//`-Kommentare entfernen (String-Literale bleiben, inkl. `\"`-Escapes),
    /// damit auskommentierte Routen und Kommentartext den Parse nicht täuschen.
    fn ohne_kommentare(src: &str) -> String {
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

    /// Kommentarfreier Quelltext von `create_router` — Signatur bis zur
    /// schließenden Klammer auf Spalte 0 (rustfmt-Invariante).
    fn create_router_quelltext() -> String {
        let src = ohne_kommentare(include_str!("mod.rs"));
        let start = src.find("fn create_router").expect("fn create_router nicht gefunden");
        let ende = src[start..]
            .find("\n}")
            .expect("Funktionsende von create_router nicht gefunden");
        src[start..start + ende].to_string()
    }

    /// Byte-Index der schließenden Klammer des bereits geöffneten Aufrufs.
    fn klammer_ende(src: &str) -> usize {
        let mut tiefe = 1u32;
        let mut in_string = false;
        for (i, c) in src.char_indices() {
            match c {
                '"' => in_string = !in_string,
                '(' if !in_string => tiefe += 1,
                ')' if !in_string => {
                    tiefe -= 1;
                    if tiefe == 0 {
                        return i;
                    }
                }
                _ => {}
            }
        }
        panic!("unbalancierte Klammern in create_router");
    }

    /// HTTP-Methoden-Aufrufe (`get(…)`, `.post(…)`, …) in einer `.route`-Argumentliste.
    fn http_methoden(args: &str) -> Vec<String> {
        let bytes = args.as_bytes();
        let mut gefunden = Vec::new();
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
                let wort = &args[start..i];
                if HTTP_METHODS.contains(&wort) && bytes.get(i) == Some(&b'(') {
                    gefunden.push(wort.to_string());
                }
            } else {
                i += 1;
            }
        }
        gefunden
    }

    /// axum-`:param` → OpenAPI-`{param}`.
    fn normalisiert(pfad: &str) -> String {
        pfad.split('/')
            .map(|seg| match seg.strip_prefix(':') {
                Some(name) => format!("{{{name}}}"),
                None => seg.to_string(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Alle `.route("<pfad>", …)`-Registrierungen eines Quelltext-Abschnitts
    /// als (Methode, Präfix+Pfad)-Paare.
    fn routen_paare(abschnitt: &str, prefix: &str) -> BTreeSet<(String, String)> {
        let mut paare = BTreeSet::new();
        let mut rest = abschnitt;
        while let Some(pos) = rest.find(".route(") {
            rest = &rest[pos + ".route(".len()..];
            let args = &rest[..klammer_ende(rest)];
            let von = args.find('"').expect(".route ohne Pfad-Literal") + 1;
            let bis = von + args[von..].find('"').expect("Pfad-Literal nicht terminiert");
            let pfad = format!("{prefix}{}", normalisiert(&args[von..bis]));
            let methoden = http_methoden(args);
            assert!(!methoden.is_empty(), "keine HTTP-Methode in .route({pfad:?}, …) erkannt");
            for methode in methoden {
                paare.insert((methode, pfad.clone()));
            }
            rest = &rest[args.len()..];
        }
        paare
    }

    /// (Methode, Pfad)-Paare der Contract-Definition. Bewusst `ApiDoc::openapi()`
    /// statt `api/openapi.json`: das Drift-Gate oben hält Definition und Datei
    /// identisch, so wird bei veralteter Datei genau ein Test rot statt zwei.
    fn contract_paare() -> BTreeSet<(String, String)> {
        let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let mut paare = BTreeSet::new();
        for (pfad, item) in doc["paths"].as_object().expect("Contract ohne paths") {
            for methode in item.as_object().expect("Path-Item kein Objekt").keys() {
                if HTTP_METHODS.contains(&methode.as_str()) {
                    paare.insert((methode.clone(), pfad.clone()));
                }
            }
        }
        paare
    }

    /// Das Drift-Gate sichert nur Definition == Datei; eine in `create_router`
    /// registrierte Route ohne `paths(...)`-Eintrag fehlte still auf beiden
    /// Seiten. Axum bietet keine Router-Introspektion, daher Quelltext-Parse.
    /// Swagger-Laufzeitrouten und Hello-Route (main.rs) sind bewusst kein
    /// Contract-Bestandteil und liegen außerhalb von `create_router`.
    #[test]
    fn jede_registrierte_route_steht_methodengenau_im_contract() {
        let body = create_router_quelltext();

        // Struktur-Annahmen absichern: bei Umbau von create_router laut
        // fehlschlagen statt still falsch parsen.
        assert_eq!(body.matches(".nest(").count(), 1, "Nesting geändert — Parse anpassen");
        assert!(body.contains(".nest(\"/store-api\""), "Nest-Präfix geändert — Parse anpassen");
        for weg in [".route_service(", ".nest_service(", ".fallback("] {
            assert!(!body.contains(weg), "{weg} registriert Routen am Parser vorbei");
        }
        for (i, _) in body.match_indices(".merge(") {
            let arg = &body[i + ".merge(".len()..];
            let arg = &arg[..arg.find(')').expect(".merge ohne schließende Klammer")];
            assert!(
                body.contains(&format!("let {arg} = Router::new()"))
                    || body.contains(&format!("let mut {arg} = Router::new()")),
                ".merge({arg}): kein lokal gebauter Router — Parse sieht dessen Routen nicht"
            );
        }

        let wurzel_ab = body
            .find("let mut router = Router::new()")
            .expect("Root-Router-Marker nicht gefunden — Parse anpassen");
        let (genestet, wurzel) = body.split_at(wurzel_ab);
        let mut registriert = routen_paare(genestet, "/store-api");
        registriert.extend(routen_paare(wurzel, ""));
        assert!(!registriert.is_empty(), "Parser fand keine .route-Registrierungen");

        let contract = contract_paare();
        let ohne_contract: Vec<_> = registriert.difference(&contract).collect();
        let ohne_route: Vec<_> = contract.difference(&registriert).collect();
        assert!(
            ohne_contract.is_empty() && ohne_route.is_empty(),
            "Router-Registrierung und OpenAPI-Contract weichen ab.\n\
             Registriert, aber nicht im Contract — #[utoipa::path] + paths(...)-Eintrag ergänzen: {ohne_contract:?}\n\
             Im Contract, aber nicht registriert — paths(...)-Leiche oder fehlende .route(): {ohne_route:?}"
        );
    }
}
