//! Internal requests: the REST requests a tool, a resource or an OAuth
//! endpoint is made of, run through the frontend layers and the bridge of
//! the MCP listener exactly like a REST request, without a network hop.

use crate::auth::middleware::McpInternal;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::Router;
use serde_json::Value;
use std::net::SocketAddr;
use tower::ServiceExt;

/// Largest answer body a tool or resource returns.
pub(crate) const MAX_RESULT_BYTES: usize = 1024 * 1024;

/// One internal REST request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Call {
    pub(crate) method: Method,
    /// Path with every segment percent-encoded.
    pub(crate) path: String,
    pub(crate) query: Vec<(&'static str, String)>,
    pub(crate) body: Option<CallBody>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CallBody {
    Json(Value),
    Text(String),
}

impl Call {
    pub(crate) fn get(path: String) -> Self {
        Self { method: Method::GET, path, query: Vec::new(), body: None }
    }

    pub(crate) fn new(method: Method, path: String) -> Self {
        Self { method, path, query: Vec::new(), body: None }
    }

    pub(crate) fn query(mut self, name: &'static str, value: Option<String>) -> Self {
        if let Some(value) = value {
            self.query.push((name, value));
        }
        self
    }

    pub(crate) fn json(mut self, body: Value) -> Self {
        self.body = Some(CallBody::Json(body));
        self
    }

    pub(crate) fn text(mut self, body: String) -> Self {
        self.body = Some(CallBody::Text(body));
        self
    }

    /// Path and query as the request target.
    pub(crate) fn target(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let query: Vec<String> = self.query.iter().map(|(name, value)| format!("{name}={}", encode(value))).collect();
        format!("{}?{}", self.path, query.join("&"))
    }
}

/// The answer to an internal request; `body` is `None` when it exceeds
/// [`MAX_RESULT_BYTES`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: Option<Bytes>,
}

impl Reply {
    pub(crate) fn json(&self) -> Option<Value> {
        self.body.as_ref().and_then(|body| serde_json::from_slice(body).ok())
    }

    pub(crate) fn text(&self) -> String {
        self.body.as_ref().map(|body| String::from_utf8_lossy(body).into_owned()).unwrap_or_default()
    }
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The MCP listener's way into the bridge: the frontend layers in front of a
/// bridge of its own.
#[derive(Clone)]
pub(crate) struct Internal {
    router: Router,
}

impl Internal {
    pub(crate) fn new(router: Router) -> Self {
        Self { router }
    }

    /// Runs `call` with the caller's `Authorization` header and peer address.
    pub(crate) async fn run(&self, call: &Call, authorization: Option<&HeaderValue>, peer: Option<SocketAddr>) -> Reply {
        let mut builder = Request::builder().method(call.method.clone()).uri(call.target());
        if let Some(authorization) = authorization {
            builder = builder.header(header::AUTHORIZATION, authorization);
        }
        let body = match &call.body {
            None => Body::empty(),
            Some(CallBody::Json(value)) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            Some(CallBody::Text(text)) => {
                builder = builder.header(header::CONTENT_TYPE, "text/plain; charset=utf-8");
                Body::from(text.clone())
            }
        };
        let mut req = match builder.body(body) {
            Ok(req) => req,
            Err(e) => {
                return Reply {
                    status: StatusCode::BAD_REQUEST,
                    body: Some(Bytes::from(format!("invalid request: {e}"))),
                }
            }
        };
        req.extensions_mut().insert(McpInternal);
        if let Some(peer) = peer {
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        #[cfg(test)]
        test_hook::count(call, authorization);
        let Ok(resp) = self.router.clone().oneshot(req).await;
        let status = resp.status();
        let body = to_bytes(resp.into_body(), MAX_RESULT_BYTES).await.ok();
        Reply { status, body }
    }
}

/// Counts the internal requests per `Authorization` header; tests share the
/// process, so each uses a key of its own.
#[cfg(test)]
pub(crate) mod test_hook {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn counts() -> &'static Mutex<HashMap<String, Vec<String>>> {
        static COUNTS: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
        COUNTS.get_or_init(Default::default)
    }

    pub(super) fn count(call: &Call, authorization: Option<&HeaderValue>) {
        let key = authorization.and_then(|value| value.to_str().ok()).unwrap_or_default().to_string();
        counts().lock().unwrap().entry(key).or_default().push(format!("{} {}", call.method, call.path));
    }

    /// The internal requests made so far with `Authorization: Bearer <key>`.
    pub(crate) fn calls_with(key: &str) -> Vec<String> {
        counts().lock().unwrap().get(&format!("Bearer {key}")).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_keeps_unreserved_characters_and_escapes_the_rest() {
        assert_eq!(encode("a-Z_0.9~"), "a-Z_0.9~");
        assert_eq!(encode("a/b c?"), "a%2Fb%20c%3F");
        assert_eq!(encode("clé"), "cl%C3%A9");
    }

    #[test]
    fn target_appends_the_query_encoded() {
        let call = Call::get("/store-api/kv/d/keys".into())
            .query("prefix", Some("a b".into()))
            .query("limit", None)
            .query("offset", Some("2".into()));
        assert_eq!(call.target(), "/store-api/kv/d/keys?prefix=a%20b&offset=2");
        assert_eq!(Call::get("/health".into()).target(), "/health");
    }

    // The request carries the caller's Authorization header unchanged, its
    // peer address, the MCP marker and the body with its content type.
    #[tokio::test]
    async fn run_passes_the_caller_on() {
        use axum::extract::Request;
        use axum::routing::put;
        async fn echo(req: Request) -> axum::Json<Value> {
            let (parts, body) = req.into_parts();
            let value_of = |name| parts.headers.get(name).map(|v: &HeaderValue| v.to_str().unwrap().to_string());
            axum::Json(json!({
                "target": parts.uri.to_string(),
                "authorization": value_of(header::AUTHORIZATION),
                "content_type": value_of(header::CONTENT_TYPE),
                "peer": parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0.to_string()),
                "internal": parts.extensions.get::<McpInternal>().is_some(),
                "body": String::from_utf8(to_bytes(body, 1024).await.unwrap().to_vec()).unwrap(),
            }))
        }
        let internal = Internal::new(Router::new().route("/store-api/kv/d/keys/{key}", put(echo)));
        let call = Call::new(Method::PUT, "/store-api/kv/d/keys/cl%C3%A9".into()).query("ttl", Some("5".into())).text("✓".into());
        let authorization = HeaderValue::from_static("Bearer lura_key");
        let peer: SocketAddr = "192.0.2.7:4711".parse().unwrap();
        let reply = internal.run(&call, Some(&authorization), Some(peer)).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            reply.json(),
            Some(json!({
                "target": "/store-api/kv/d/keys/cl%C3%A9?ttl=5",
                "authorization": "Bearer lura_key",
                "content_type": "text/plain; charset=utf-8",
                "peer": "192.0.2.7:4711",
                "internal": true,
                "body": "✓",
            }))
        );
    }

    #[tokio::test]
    async fn an_answer_above_the_cap_has_no_body() {
        let big = || async { "x".repeat(MAX_RESULT_BYTES + 1) };
        let internal = Internal::new(Router::new().route("/big", axum::routing::get(big)));
        let reply = internal.run(&Call::get("/big".into()), None, None).await;
        assert_eq!((reply.status, reply.body), (StatusCode::OK, None));
    }

    #[test]
    fn reply_reads_json_and_text() {
        let reply = Reply { status: StatusCode::OK, body: Some(Bytes::from(r#"{"a":1}"#)) };
        assert_eq!(reply.json(), Some(json!({"a": 1})));
        let reply = Reply { status: StatusCode::OK, body: Some(Bytes::from("clé")) };
        assert_eq!((reply.json(), reply.text()), (None, "clé".to_string()));
    }
}
