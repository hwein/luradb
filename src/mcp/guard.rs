//! The checks in front of `/mcp`: the `Origin` of browser clients, and a
//! valid credential on every request, checked by the same auth layer as a
//! REST request.

use super::internal::{Call, Internal};
use super::tools::Role;
use crate::auth::middleware::bearer_token;
use axum::body::{to_bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// Largest JSON-RPC request body `/mcp` takes.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// Refuses a request whose `Origin` is not exactly one of `allowed`; a
/// request without `Origin` passes. Guards against DNS rebinding.
pub(crate) async fn check_origin(State(allowed): State<Arc<Vec<String>>>, req: Request, next: Next) -> Response {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        if !allowed.iter().any(|entry| entry.as_bytes() == origin.as_bytes()) {
            return (StatusCode::FORBIDDEN, "Forbidden: Origin is not allowed").into_response();
        }
    }
    next.run(req).await
}

/// The caller's role, for `tools/list`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Caller(pub(crate) Role);

/// Carries the verdict of a tool call or resource read on the caller's
/// credential back to [`authenticate`]: those methods are checked by their
/// own internal requests, not by an extra `whoami`.
#[derive(Clone)]
pub(crate) struct AuthProbe(Arc<Mutex<Option<oneshot::Sender<bool>>>>);

impl AuthProbe {
    fn new() -> (Self, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        (Self(Arc::new(Mutex::new(Some(tx)))), rx)
    }

    /// Reports whether the internal requests accepted the credential; only
    /// the first report counts.
    pub(crate) fn report(&self, accepted: bool) {
        if let Some(tx) = self.0.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(accepted);
        }
    }
}

/// What [`authenticate`] needs.
pub(crate) struct Gate {
    pub(crate) internal: Internal,
    pub(crate) auth_enabled: bool,
    /// Protected resource metadata URL for the challenge, with OAuth on.
    pub(crate) resource_metadata: Option<String>,
}

impl Gate {
    /// 401 with the Bearer challenge; `rejected` names a credential that was
    /// sent but not accepted.
    fn challenge(&self, rejected: bool) -> Response {
        let mut params = Vec::new();
        if rejected {
            params.push("error=\"invalid_token\"".to_string());
        }
        if let Some(url) = &self.resource_metadata {
            params.push(format!("resource_metadata=\"{url}\""));
        }
        let value = if params.is_empty() { "Bearer".to_string() } else { format!("Bearer {}", params.join(", ")) };
        let mut resp = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        if let Ok(value) = HeaderValue::from_str(&value) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, value);
        }
        resp
    }
}

/// JSON-RPC method of a single request body, if it is one.
fn rpc_method(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    Some(value.get("method")?.as_str()?.to_string())
}

/// Lets a request to `/mcp` in only with a valid credential: `tools/call`
/// and `resources/read` through their own internal requests (an answer 401
/// there turns the whole response into 401), every other request through an
/// internal `whoami`, whose role it hands on for `tools/list`. With auth off
/// everything passes with the role `Disabled`.
pub(crate) async fn authenticate(State(gate): State<Arc<Gate>>, mut req: Request, next: Next) -> Response {
    if !gate.auth_enabled {
        req.extensions_mut().insert(Caller(Role::Disabled));
        return next.run(req).await;
    }
    let authorization = bearer_token(req.headers()).and(req.headers().get(header::AUTHORIZATION)).cloned();
    let Some(authorization) = authorization else {
        return gate.challenge(false);
    };
    let (mut parts, body) = req.into_parts();
    let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    let (body, method) = if parts.method == Method::POST {
        match to_bytes(body, MAX_REQUEST_BYTES).await {
            Ok(bytes) => {
                let method = rpc_method(&bytes);
                (Body::from(bytes), method)
            }
            Err(_) => {
                return match gate.role(&authorization, peer).await {
                    Some(_) => (StatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response(),
                    None => gate.challenge(true),
                }
            }
        }
    } else {
        (body, None)
    };
    if matches!(method.as_deref(), Some("tools/call" | "resources/read")) {
        let (probe, verdict) = AuthProbe::new();
        parts.extensions.insert(probe);
        let resp = next.run(Request::from_parts(parts, body)).await;
        return match verdict.await {
            Ok(true) => resp,
            Ok(false) => gate.challenge(true),
            // Refused before the handler ran: the credential is still checked.
            Err(_) => match gate.role(&authorization, peer).await {
                Some(_) => resp,
                None => gate.challenge(true),
            },
        };
    }
    match gate.role(&authorization, peer).await {
        Some(role) => {
            parts.extensions.insert(Caller(role));
            next.run(Request::from_parts(parts, body)).await
        }
        None => gate.challenge(true),
    }
}

impl Gate {
    /// The role of `authorization` from an internal `whoami`; `None` when it
    /// is not accepted.
    async fn role(&self, authorization: &HeaderValue, peer: Option<SocketAddr>) -> Option<Role> {
        let reply = self.internal.run(&Call::get("/store-api/auth/whoami".into()), Some(authorization), peer).await;
        reply.json().filter(|_| reply.status == StatusCode::OK).as_ref().and_then(Role::from_whoami)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn origin_status(allowed: &[&str], origin: Option<&str>) -> StatusCode {
        let allowed = Arc::new(allowed.iter().map(|o| o.to_string()).collect::<Vec<_>>());
        let app = Router::new().route("/mcp", get(|| async { "ok" })).layer(from_fn_with_state(allowed, check_origin));
        let mut req = Request::builder().uri("/mcp");
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap().status()
    }

    #[tokio::test]
    async fn requests_without_origin_pass() {
        assert_eq!(origin_status(&[], None).await, StatusCode::OK);
        assert_eq!(origin_status(&["https://app.example.com"], None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_origin_in_the_list_passes_exactly() {
        let allowed = ["https://app.example.com", "http://localhost:5173"];
        assert_eq!(origin_status(&allowed, Some("http://localhost:5173")).await, StatusCode::OK);
        assert_eq!(origin_status(&allowed, Some("https://app.example.com")).await, StatusCode::OK);
        for other in ["http://app.example.com", "https://app.example.com:8443", "http://localhost:5174", "null"] {
            assert_eq!(origin_status(&allowed, Some(other)).await, StatusCode::FORBIDDEN, "{other}");
        }
    }

    #[tokio::test]
    async fn an_empty_list_refuses_every_origin() {
        assert_eq!(origin_status(&[], Some("http://localhost:3100")).await, StatusCode::FORBIDDEN);
    }

    #[test]
    fn the_challenge_names_the_metadata_and_a_rejected_token() {
        let gate = |metadata: Option<&str>| Gate {
            internal: Internal::new(Router::new()),
            auth_enabled: true,
            resource_metadata: metadata.map(String::from),
        };
        let www = |resp: Response| {
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            resp.headers()[header::WWW_AUTHENTICATE].to_str().unwrap().to_string()
        };
        assert_eq!(www(gate(None).challenge(false)), "Bearer");
        assert_eq!(www(gate(None).challenge(true)), "Bearer error=\"invalid_token\"");
        let url = "https://db.example.com/.well-known/oauth-protected-resource";
        assert_eq!(www(gate(Some(url)).challenge(false)), format!("Bearer resource_metadata=\"{url}\""));
        assert_eq!(
            www(gate(Some(url)).challenge(true)),
            format!("Bearer error=\"invalid_token\", resource_metadata=\"{url}\"")
        );
    }

    // A body over the limit gets 413 only once the credential is accepted;
    // an invalid one still gets the 401 challenge.
    #[tokio::test]
    async fn an_oversized_body_is_refused_after_the_credential_check() {
        async fn whoami(req: Request) -> Response {
            match req.headers().get(header::AUTHORIZATION) {
                Some(value) if value == "Bearer lura_good" => axum::Json(serde_json::json!({"role": "Admin"})).into_response(),
                _ => StatusCode::UNAUTHORIZED.into_response(),
            }
        }
        let gate = Arc::new(Gate {
            internal: Internal::new(Router::new().route("/store-api/auth/whoami", get(whoami))),
            auth_enabled: true,
            resource_metadata: None,
        });
        let app = Router::new().route("/mcp", axum::routing::post(|| async { "ok" })).layer(from_fn_with_state(gate, authenticate));
        let big = vec![b' '; MAX_REQUEST_BYTES + 1];
        for (key, expected) in [("lura_bad", StatusCode::UNAUTHORIZED), ("lura_good", StatusCode::PAYLOAD_TOO_LARGE)] {
            let req = Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .body(Body::from(big.clone()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), expected, "{key}");
            assert_eq!(resp.headers().contains_key(header::WWW_AUTHENTICATE), expected == StatusCode::UNAUTHORIZED, "{key}");
        }
    }

    #[test]
    fn the_method_is_read_from_a_single_request() {
        assert_eq!(rpc_method(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#).as_deref(), Some("tools/call"));
        assert_eq!(rpc_method(br#"[{"method":"tools/call"}]"#), None);
        assert_eq!(rpc_method(b"not json"), None);
    }
}
