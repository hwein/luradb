//! OAuth 2.1 on the MCP listener, with LuraDB as its own authorization
//! server: metadata (RFC 9728, RFC 8414), Dynamic Client Registration
//! (RFC 7591) for public clients, the authorization code flow with PKCE
//! S256 where the user signs in once with an API key, refresh and
//! revocation (RFC 7009). The state lives behind internal routes on the
//! control plane; this module keeps none of it but the failed sign-ins and
//! the recent registrations.

use super::internal::{encode, Call, Internal, Reply};
use crate::api::middleware::ClientIp;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::rejection::{FormRejection, JsonRejection, QueryRejection};
use axum::extract::{Extension, Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Failed sign-ins from one sender (see [`ip_key`]) after which the sign-in
/// page answers 429 ...
const MAX_FAILED_SIGN_INS: usize = 5;
/// ... for this long after the first of them.
const FAILURE_WINDOW_SECS: u64 = 15 * 60;
/// Longest client name a registration may carry.
const MAX_CLIENT_NAME_CHARS: usize = 100;
/// Most redirect URIs a registration may carry ...
const MAX_REDIRECT_URIS: usize = 10;
/// ... each at most this long.
const MAX_REDIRECT_URI_CHARS: usize = 2048;
/// Registrations one sender (see [`ip_key`]) may make ...
const MAX_REGISTRATIONS: usize = 10;
/// ... within this long.
const REGISTRATION_WINDOW_SECS: u64 = 60 * 60;

const PAGE_CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'";

pub(crate) struct OAuth {
    internal: Internal,
    /// Issuer, without a trailing slash.
    public_url: String,
    /// `scheme://host[:port]` of `public_url`; the sign-in form posts from there.
    origin: String,
    // Where RFC 8414 and RFC 9728 place the metadata for `public_url`, as
    // sent, not decoded.
    authorization_server_path: String,
    protected_resource_path: String,
    /// Binds the sign-in form's CSRF token to its request.
    csrf_key: [u8; 32],
    failures: Failures,
    registrations: Registrations,
}

impl OAuth {
    pub(crate) fn new(internal: Internal, public_url: &str) -> Self {
        let public_url = public_url.trim_end_matches('/').to_string();
        let origin = origin_of(&public_url);
        let path = path_of(&public_url);
        let authorization_server_path = format!("/.well-known/oauth-authorization-server{path}");
        let protected_resource_path = format!("/.well-known/oauth-protected-resource{path}/mcp");
        Self {
            internal,
            public_url,
            origin,
            authorization_server_path,
            protected_resource_path,
            csrf_key: rand::thread_rng().gen(),
            failures: Failures::default(),
            registrations: Registrations::default(),
        }
    }

    fn resource(&self) -> String {
        resource_url(&self.public_url)
    }

    pub(crate) fn resource_metadata_url(public_url: &str) -> String {
        format!("{}/.well-known/oauth-protected-resource", public_url.trim_end_matches('/'))
    }

    fn csrf(&self, params: &AuthorizeParams) -> String {
        let fields = [
            &params.client_id,
            &params.redirect_uri,
            &params.response_type,
            &params.code_challenge,
            &params.code_challenge_method,
            &params.state,
            &params.resource,
        ];
        let data: Vec<&str> = fields.iter().map(|f| f.as_deref().unwrap_or_default()).collect();
        let inner = Sha256::digest(data.join("\n").as_bytes());
        hex::encode(Sha256::new().chain_update(self.csrf_key).chain_update(inner).finalize())
    }
}

/// The resource (RFC 8707) of the MCP listener at `public_url`, which its
/// tokens are bound to.
pub(crate) fn resource_url(public_url: &str) -> String {
    format!("{}/mcp", public_url.trim_end_matches('/'))
}

/// The `Origin` a browser sends for pages under `public_url`: scheme and
/// host in lower case, without the scheme's default port.
fn origin_of(public_url: &str) -> String {
    let Some((scheme, rest)) = public_url.split_once("://") else { return public_url.to_string() };
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split('/').next().unwrap_or_default().to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    let authority = authority.strip_suffix(default_port).unwrap_or(&authority);
    format!("{scheme}://{authority}")
}

/// The path of `public_url`: empty, or from the first `/` after the authority.
fn path_of(public_url: &str) -> &str {
    let rest = public_url.split_once("://").map_or(public_url, |(_, rest)| rest);
    rest.find('/').map_or("", |i| &rest[i..])
}

/// Failed and pending sign-ins by [`ip_key`], as Unix seconds.
#[derive(Default)]
struct Failures(Mutex<HashMap<IpAddr, Vec<u64>>>);

impl Failures {
    fn recent(map: &mut HashMap<IpAddr, Vec<u64>>, key: IpAddr, now: u64) -> usize {
        map.retain(|_, times| {
            times.retain(|t| now.saturating_sub(*t) < FAILURE_WINDOW_SECS);
            !times.is_empty()
        });
        map.get(&key).map_or(0, Vec::len)
    }

    fn blocked(&self, ip: IpAddr, now: u64) -> bool {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Self::recent(&mut map, ip_key(ip), now) >= MAX_FAILED_SIGN_INS
    }

    /// Counts an attempt as failed before it is checked, unless `ip` is
    /// blocked: concurrent attempts then never exceed the limit.
    fn reserve(&self, ip: IpAddr, now: u64) -> bool {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let key = ip_key(ip);
        if Self::recent(&mut map, key, now) >= MAX_FAILED_SIGN_INS {
            return false;
        }
        map.entry(key).or_default().push(now);
        true
    }

    /// Takes back the attempt reserved at `now`; it did not fail.
    fn release(&self, ip: IpAddr, now: u64) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(times) = map.get_mut(&ip_key(ip)) {
            if let Some(i) = times.iter().rposition(|t| *t == now) {
                times.remove(i);
            }
        }
    }
}

/// Recent and pending registrations by [`ip_key`], as Unix seconds.
#[derive(Default)]
struct Registrations(Mutex<RegistrationTimes>);

#[derive(Default)]
struct RegistrationTimes {
    by_key: HashMap<IpAddr, Vec<u64>>,
    /// When keys without a recent registration were last dropped.
    swept: u64,
}

/// The key a client IP's registrations and failed sign-ins count under: an
/// IPv4 address as it is, also mapped into IPv6; an IPv6 address by its /64
/// prefix, as one subscriber usually gets a whole /64.
fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        },
    }
}

impl Registrations {
    /// Counts a registration from `ip` before it is made, unless the limit
    /// is reached: concurrent registrations then never exceed it. Refused,
    /// it returns the seconds until the oldest counted one runs out.
    fn reserve(&self, ip: IpAddr, now: u64) -> Result<(), u64> {
        let recent = |t: &u64| now.saturating_sub(*t) < REGISTRATION_WINDOW_SECS;
        let mut times = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // Sweeping all keys once per window keeps each call cheap and the
        // map to the keys of the last two windows.
        if now.saturating_sub(times.swept) >= REGISTRATION_WINDOW_SECS {
            times.by_key.retain(|_, list| {
                list.retain(recent);
                !list.is_empty()
            });
            times.swept = now;
        }
        let list = times.by_key.entry(ip_key(ip)).or_default();
        list.retain(recent);
        if list.len() >= MAX_REGISTRATIONS {
            let oldest = list.iter().min().copied().unwrap_or(now);
            return Err((oldest + REGISTRATION_WINDOW_SECS).saturating_sub(now));
        }
        list.push(now);
        Ok(())
    }

    /// Takes back the registration reserved at `now`; it was not made.
    fn release(&self, ip: IpAddr, now: u64) {
        let mut times = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let key = ip_key(ip);
        if let Some(list) = times.by_key.get_mut(&key) {
            if let Some(i) = list.iter().rposition(|t| *t == now) {
                list.remove(i);
            }
            if list.is_empty() {
                times.by_key.remove(&key);
            }
        }
    }
}

/// The client IP: as resolved behind trusted proxies, else the peer.
fn request_ip(client_ip: Option<Extension<ClientIp>>, peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> IpAddr {
    client_ip
        .map(|Extension(ip)| ip.0)
        .or_else(|| peer.map(|Extension(info)| info.0.ip()))
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

pub(crate) fn routes(oauth: Arc<OAuth>) -> Router {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-authorization-server", get(authorization_server))
        // The public path comes from the config and may hold characters
        // axum reads as a pattern, so it is compared, not routed. Other
        // methods get the 404 of an unknown route, not 405.
        .route("/.well-known/oauth-protected-resource/{*rest}", get(protected_resource_at).fallback(not_found))
        .route("/.well-known/oauth-authorization-server/{*rest}", get(authorization_server_at).fallback(not_found))
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize_page).post(authorize_submit))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .with_state(oauth)
}

async fn protected_resource(State(oauth): State<Arc<OAuth>>) -> Json<Value> {
    Json(json!({
        "resource": oauth.resource(),
        "authorization_servers": [oauth.public_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }))
}

async fn authorization_server(State(oauth): State<Arc<OAuth>>) -> Json<Value> {
    let url = &oauth.public_url;
    Json(json!({
        "issuer": url,
        "authorization_endpoint": format!("{url}/oauth/authorize"),
        "token_endpoint": format!("{url}/oauth/token"),
        "registration_endpoint": format!("{url}/oauth/register"),
        "revocation_endpoint": format!("{url}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [],
    }))
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn protected_resource_at(State(oauth): State<Arc<OAuth>>, uri: Uri) -> Response {
    if uri.path() != oauth.protected_resource_path {
        return StatusCode::NOT_FOUND.into_response();
    }
    protected_resource(State(oauth)).await.into_response()
}

async fn authorization_server_at(State(oauth): State<Arc<OAuth>>, uri: Uri) -> Response {
    if uri.path() != oauth.authorization_server_path {
        return StatusCode::NOT_FOUND.into_response();
    }
    authorization_server(State(oauth)).await.into_response()
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = json!({ "error": error, "error_description": description });
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// `https://`, or `http://` on a loopback host, without a fragment.
fn redirect_uri_allowed(uri: &str) -> bool {
    let Some((scheme, rest)) = uri.split_once("://") else { return false };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    !host.is_empty() && !uri.contains(['#', '@']) && (scheme == "https" || (scheme == "http" && loopback))
}

/// The client name and redirect URIs of a registration request, or the
/// RFC 7591 error.
fn registration(body: &Value) -> Result<(String, Vec<String>), (&'static str, String)> {
    let invalid = |description: &str| ("invalid_client_metadata", description.to_string());
    let name = body.get("client_name").and_then(Value::as_str).filter(|name| !name.trim().is_empty());
    let Some(name) = name else { return Err(invalid("client_name is required")) };
    if name.chars().count() > MAX_CLIENT_NAME_CHARS {
        return Err(invalid(&format!("client_name is longer than {MAX_CLIENT_NAME_CHARS} characters")));
    }
    if let Some(method) = body.get("token_endpoint_auth_method") {
        if method != "none" {
            return Err(invalid("only public clients (token_endpoint_auth_method \"none\") can register"));
        }
    }
    let uris: Option<Vec<String>> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|uris| uris.iter().filter_map(|uri| uri.as_str().map(String::from)).collect());
    let Some(uris) = uris.filter(|uris| !uris.is_empty()) else {
        return Err(("invalid_redirect_uri", "redirect_uris is required".to_string()));
    };
    if uris.len() > MAX_REDIRECT_URIS {
        return Err(("invalid_redirect_uri", format!("redirect_uris may name at most {MAX_REDIRECT_URIS} URIs")));
    }
    if uris.iter().any(|uri| uri.chars().count() > MAX_REDIRECT_URI_CHARS) {
        return Err(("invalid_redirect_uri", format!("a redirect URI may be at most {MAX_REDIRECT_URI_CHARS} characters long")));
    }
    if let Some(bad) = uris.iter().find(|uri| !redirect_uri_allowed(uri)) {
        return Err(("invalid_redirect_uri", format!("'{bad}' must be https:// or http:// on a loopback host")));
    }
    Ok((name.to_string(), uris))
}

async fn register(
    State(oauth): State<Arc<OAuth>>,
    client_ip: Option<Extension<ClientIp>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    // RFC 7591 wants 400 for every registration error, a wrong Content-Type too.
    let body = match body {
        Ok(Json(body)) if body.is_object() => body,
        Ok(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", "the body must be a JSON object"),
        Err(rejection) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", &rejection.body_text()),
    };
    let (name, uris) = match registration(&body) {
        Ok(registered) => registered,
        Err((error, description)) => return oauth_error(StatusCode::BAD_REQUEST, error, &description),
    };
    let ip = request_ip(client_ip, peer);
    let now = crate::auth::now_secs();
    if let Err(retry_after) = oauth.registrations.reserve(ip, now) {
        let mut resp =
            oauth_error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable", "too many registrations; try again later");
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
        return resp;
    }
    let call = Call::new(Method::POST, "/store-api/auth/oauth/clients".into())
        .json(json!({ "client_name": name, "redirect_uris": uris }));
    let reply = oauth.internal.run(&call, None, None).await;
    let Some(client) = reply.json().filter(|_| reply.status == StatusCode::CREATED) else {
        oauth.registrations.release(ip, now);
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &reply.text());
    };
    let body = json!({
        "client_id": client["client_id"],
        "client_id_issued_at": client["created_at"],
        "client_name": client["client_name"],
        "redirect_uris": client["redirect_uris"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    });
    (StatusCode::CREATED, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// The authorization request, as query (page) or form (submission).
#[derive(Debug, Default, Deserialize)]
struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    resource: Option<String>,
}

#[derive(Deserialize)]
struct AuthorizeForm {
    #[serde(flatten)]
    params: AuthorizeParams,
    csrf: Option<String>,
    api_key: Option<String>,
    decision: Option<String>,
}

/// An authorization request that passed every check.
struct Valid {
    client_name: String,
    redirect_uri: String,
    code_challenge: String,
}

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

fn html(status: StatusCode, body: String) -> Response {
    let mut resp = (status, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(PAGE_CSP));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn document(title: &str, content: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head>\n<body>\n<h1>{title}</h1>\n{content}\n</body></html>\n"
    )
}

/// A failed request whose redirect URI is not proven: shown, never redirected.
fn error_page(message: &str) -> Response {
    html(StatusCode::BAD_REQUEST, document("Sign-in failed", &format!("<p>{}</p>", escape(message))))
}

/// Sends the browser back to the client with `params` added to `redirect_uri`.
fn redirect(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let query: Vec<String> = params.iter().map(|(name, value)| format!("{name}={}", encode(value))).collect();
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!("{redirect_uri}{separator}{}", query.join("&"));
    match HeaderValue::from_str(&location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => error_page("the redirect URI is not valid"),
    }
}

fn redirect_error(redirect_uri: &str, state: Option<&str>, error: &str, description: &str) -> Response {
    let mut params = vec![("error", error), ("error_description", description)];
    if let Some(state) = state {
        params.push(("state", state));
    }
    redirect(redirect_uri, &params)
}

impl OAuth {
    /// Checks an authorization request: errors before a registered redirect
    /// URI is proven come back as a page, later ones as a redirect.
    async fn check(&self, params: &AuthorizeParams) -> Result<Valid, Box<Response>> {
        let Some(client_id) = params.client_id.as_deref().filter(|id| !id.is_empty()) else {
            return Err(Box::new(error_page("The request names no client (client_id).")));
        };
        let reply = self.internal.run(&Call::get(format!("/store-api/auth/oauth/clients/{}", encode(client_id))), None, None).await;
        let Some(client) = reply.json().filter(|_| reply.status == StatusCode::OK) else {
            return Err(Box::new(error_page("The client is not registered.")));
        };
        let registered: Vec<&str> =
            client["redirect_uris"].as_array().map(|uris| uris.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let Some(redirect_uri) = params.redirect_uri.as_deref().filter(|uri| registered.contains(uri)) else {
            return Err(Box::new(error_page("The redirect URI is not registered for this client.")));
        };
        let refuse = |error: &str, description: &str| {
            Err(Box::new(redirect_error(redirect_uri, params.state.as_deref(), error, description)))
        };
        if params.response_type.as_deref() != Some("code") {
            return refuse("unsupported_response_type", "response_type must be code");
        }
        let Some(code_challenge) = params.code_challenge.as_deref().filter(|c| !c.is_empty()) else {
            return refuse("invalid_request", "code_challenge is required (PKCE)");
        };
        if params.code_challenge_method.as_deref() != Some("S256") {
            return refuse("invalid_request", "code_challenge_method must be S256");
        }
        if params.resource.as_deref().is_some_and(|resource| resource != self.resource()) {
            return refuse("invalid_target", "resource must be this MCP server");
        }
        Ok(Valid {
            client_name: client["client_name"].as_str().unwrap_or_default().to_string(),
            redirect_uri: redirect_uri.to_string(),
            code_challenge: code_challenge.to_string(),
        })
    }

    fn sign_in_page(&self, valid: &Valid, params: &AuthorizeParams, error: Option<&str>) -> Response {
        let host = valid.redirect_uri.split_once("://").map_or("", |(_, rest)| rest.split(['/', '?']).next().unwrap_or_default());
        let hidden = [
            ("response_type", &params.response_type),
            ("client_id", &params.client_id),
            ("redirect_uri", &params.redirect_uri),
            ("code_challenge", &params.code_challenge),
            ("code_challenge_method", &params.code_challenge_method),
            ("state", &params.state),
            ("resource", &params.resource),
        ];
        let mut fields: String = hidden
            .iter()
            .filter_map(|(name, value)| value.as_deref().map(|value| (name, value)))
            .map(|(name, value)| format!("<input type=\"hidden\" name=\"{name}\" value=\"{}\">\n", escape(value)))
            .collect();
        fields.push_str(&format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">\n", self.csrf(params)));
        let error = error.map(|e| format!("<p><strong>{}</strong></p>\n", escape(e))).unwrap_or_default();
        let content = format!(
            "<p><strong>{}</strong> asks for access to this LuraDB with the permissions of your API key; it will be sent back to <strong>{}</strong>.</p>\n{error}<form method=\"post\" action=\"authorize\">\n{fields}<p><label for=\"api_key\">API key</label><br><input type=\"password\" id=\"api_key\" name=\"api_key\" autocomplete=\"off\" required></p>\n<p><button type=\"submit\" name=\"decision\" value=\"allow\">Allow access</button> <button type=\"submit\" name=\"decision\" value=\"deny\" formnovalidate>Deny</button></p>\n</form>",
            escape(&valid.client_name),
            escape(host),
        );
        html(StatusCode::OK, document("Sign in to LuraDB", &content))
    }
}

async fn authorize_page(
    State(oauth): State<Arc<OAuth>>,
    params: Result<Query<AuthorizeParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = params else { return error_page("The request parameters are not valid.") };
    match oauth.check(&params).await {
        Ok(valid) => oauth.sign_in_page(&valid, &params, None),
        Err(resp) => *resp,
    }
}

fn too_many_failures() -> Response {
    (StatusCode::TOO_MANY_REQUESTS, "Too many failed sign-ins; try again later").into_response()
}

async fn authorize_submit(
    State(oauth): State<Arc<OAuth>>,
    headers: HeaderMap,
    client_ip: Option<Extension<ClientIp>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    form: Result<Form<AuthorizeForm>, FormRejection>,
) -> Response {
    if headers.get(header::ORIGIN).map(HeaderValue::as_bytes) != Some(oauth.origin.as_bytes()) {
        return (StatusCode::FORBIDDEN, "Forbidden: the sign-in form must be sent from this server").into_response();
    }
    let ip = request_ip(client_ip, peer);
    let now = crate::auth::now_secs();
    if oauth.failures.blocked(ip, now) {
        return too_many_failures();
    }
    let Ok(Form(form)) = form else {
        return error_page("The form is not valid.");
    };
    let valid = match oauth.check(&form.params).await {
        Ok(valid) => valid,
        Err(resp) => return *resp,
    };
    if form.csrf.as_deref() != Some(oauth.csrf(&form.params).as_str()) {
        return error_page("The form has expired or was not sent from the sign-in page; start again.");
    }
    let state = form.params.state.as_deref();
    if form.decision.as_deref() != Some("allow") {
        return redirect_error(&valid.redirect_uri, state, "access_denied", "the user denied access");
    }
    let api_key = form.api_key.unwrap_or_default();
    let authorization = HeaderValue::from_str(&format!("Bearer {}", api_key.trim())).ok();
    let call = Call::new(Method::POST, "/store-api/auth/oauth/codes".into()).json(json!({
        "client_id": form.params.client_id,
        "redirect_uri": valid.redirect_uri,
        "code_challenge": valid.code_challenge,
        "resource": oauth.resource(),
    }));
    if !oauth.failures.reserve(ip, now) {
        return too_many_failures();
    }
    let reply = match authorization {
        Some(authorization) if !api_key.trim().is_empty() => oauth.internal.run(&call, Some(&authorization), None).await,
        _ => Reply { status: StatusCode::UNAUTHORIZED, body: None },
    };
    if reply.status == StatusCode::UNAUTHORIZED {
        return oauth.sign_in_page(&valid, &form.params, Some("The API key is not valid."));
    }
    oauth.failures.release(ip, now);
    let Some(code) = reply.json().filter(|_| reply.status == StatusCode::CREATED).and_then(|v| v["code"].as_str().map(String::from)) else {
        return redirect_error(&valid.redirect_uri, state, "server_error", "no code could be issued");
    };
    let mut params = vec![("code", code.as_str())];
    if let Some(state) = state {
        params.push(("state", state));
    }
    redirect(&valid.redirect_uri, &params)
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    client_id: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
}

/// Hands the internal route's answer on, JSON body and status as they are.
fn pass_on(reply: Reply) -> Response {
    let mut resp = (reply.status, reply.body.unwrap_or_default()).into_response();
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn token(State(oauth): State<Arc<OAuth>>, form: Result<Form<TokenForm>, FormRejection>) -> Response {
    let Ok(Form(form)) = form else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "the body must be form-encoded");
    };
    if form.resource.as_deref().is_some_and(|resource| resource != oauth.resource()) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_target", "resource must be this MCP server");
    }
    let Some(grant_type) = form.grant_type else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing parameter 'grant_type'");
    };
    if !matches!(grant_type.as_str(), "authorization_code" | "refresh_token") {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
    }
    let call = Call::new(Method::POST, "/store-api/auth/oauth/tokens".into()).json(json!({
        "grant_type": grant_type,
        "client_id": form.client_id,
        "code": form.code,
        "code_verifier": form.code_verifier,
        "redirect_uri": form.redirect_uri,
        "refresh_token": form.refresh_token,
    }));
    pass_on(oauth.internal.run(&call, None, None).await)
}

#[derive(Deserialize)]
struct RevokeForm {
    token: Option<String>,
}

async fn revoke(State(oauth): State<Arc<OAuth>>, form: Result<Form<RevokeForm>, FormRejection>) -> Response {
    let Some(token) = form.ok().and_then(|Form(form)| form.token).filter(|token| !token.is_empty()) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing parameter 'token'");
    };
    let call = Call::new(Method::POST, "/store-api/auth/oauth/revoke".into()).json(json!({ "token": token }));
    let reply = oauth.internal.run(&call, None, None).await;
    if reply.status.is_success() {
        StatusCode::OK.into_response()
    } else {
        oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &reply.text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_must_be_https_or_loopback_http() {
        for good in ["https://app.example.com/cb", "http://localhost:9000/cb", "http://127.0.0.1/cb", "http://[::1]:8080/cb?x=1"] {
            assert!(redirect_uri_allowed(good), "{good}");
        }
        for bad in ["http://app.example.com/cb", "ftp://x/cb", "https://app.example.com/cb#frag", "app.example.com/cb", "https:///cb", "https://user@app.example.com/cb"] {
            assert!(!redirect_uri_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn a_registration_needs_a_name_and_valid_redirect_uris() {
        let ok = registration(&json!({"client_name": "Agent ✓", "redirect_uris": ["http://127.0.0.1:9/cb"]}));
        assert_eq!(ok, Ok(("Agent ✓".to_string(), vec!["http://127.0.0.1:9/cb".to_string()])));
        let cases = [
            (json!({"redirect_uris": ["https://a.example/cb"]}), "invalid_client_metadata"),
            (json!({"client_name": "x".repeat(101), "redirect_uris": ["https://a.example/cb"]}), "invalid_client_metadata"),
            (json!({"client_name": "a", "redirect_uris": ["https://a.example/cb"], "token_endpoint_auth_method": "client_secret_basic"}), "invalid_client_metadata"),
            (json!({"client_name": "a"}), "invalid_redirect_uri"),
            (json!({"client_name": "a", "redirect_uris": []}), "invalid_redirect_uri"),
            (json!({"client_name": "a", "redirect_uris": ["http://a.example/cb"]}), "invalid_redirect_uri"),
        ];
        for (body, error) in cases {
            assert_eq!(registration(&body).unwrap_err().0, error, "{body}");
        }
        assert!(registration(&json!({"client_name": "é".repeat(100), "redirect_uris": ["https://a.example/cb"]})).is_ok());
    }

    #[test]
    fn a_registration_names_at_most_ten_redirect_uris_of_2048_characters() {
        let uri = |i: usize, len: usize| {
            let start = format!("https://a.example/{i}/");
            format!("{start}{}", "x".repeat(len - start.len()))
        };
        let uris: Vec<String> = (0..MAX_REDIRECT_URIS).map(|i| uri(i, MAX_REDIRECT_URI_CHARS)).collect();
        let ok = registration(&json!({"client_name": "a", "redirect_uris": uris}));
        assert_eq!(ok.map(|(_, registered)| registered), Ok(uris));

        let too_many: Vec<String> = (0..=MAX_REDIRECT_URIS).map(|i| uri(i, 30)).collect();
        let (error, description) = registration(&json!({"client_name": "a", "redirect_uris": too_many})).unwrap_err();
        assert_eq!(error, "invalid_redirect_uri");
        assert!(description.contains("10"), "{description}");

        let too_long = [uri(0, MAX_REDIRECT_URI_CHARS + 1)];
        let (error, description) = registration(&json!({"client_name": "a", "redirect_uris": too_long})).unwrap_err();
        assert_eq!(error, "invalid_redirect_uri");
        assert!(description.contains("2048") && description.len() < 100, "{description}");
    }

    #[test]
    fn ten_registrations_per_ip_within_an_hour() {
        let registrations = Registrations::default();
        let (ip, other) = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        for i in 0..MAX_REGISTRATIONS as u64 {
            assert_eq!(registrations.reserve(ip, 1000 + i), Ok(()));
        }
        // The oldest, from 1000, runs out at 1000 + window.
        assert_eq!(registrations.reserve(ip, 1100), Err(REGISTRATION_WINDOW_SECS - 100));
        assert_eq!(registrations.reserve(other, 1100), Ok(()));
        assert_eq!(registrations.reserve(ip, 1000 + REGISTRATION_WINDOW_SECS - 1), Err(1));
        assert_eq!(registrations.reserve(ip, 1000 + REGISTRATION_WINDOW_SECS), Ok(()));
        assert!(registrations.reserve(ip, 1000 + REGISTRATION_WINDOW_SECS).is_err());
    }

    #[test]
    fn a_failed_registration_is_released() {
        let registrations = Registrations::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        for _ in 0..MAX_REGISTRATIONS {
            assert_eq!(registrations.reserve(ip, 1000), Ok(()));
        }
        assert!(registrations.reserve(ip, 1000).is_err());
        registrations.release(ip, 1000);
        assert_eq!(registrations.reserve(ip, 1000), Ok(()));
        assert!(registrations.reserve(ip, 1000).is_err());
    }

    #[test]
    fn ipv6_counts_per_64_and_mapped_ipv4_as_ipv4() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(ip_key(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(ip_key(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(ip_key(ip("192.0.2.1")), ip("192.0.2.1"));

        let registrations = Registrations::default();
        for i in 0..MAX_REGISTRATIONS {
            assert_eq!(registrations.reserve(ip(&format!("2001:db8:1:2::{:x}", i + 1)), 1000), Ok(()));
        }
        assert!(registrations.reserve(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"), 1000).is_err());
        assert_eq!(registrations.reserve(ip("2001:db8:1:3::1"), 1000), Ok(()));

        for _ in 0..MAX_REGISTRATIONS {
            assert_eq!(registrations.reserve(ip("::ffff:192.0.2.1"), 1000), Ok(()));
        }
        assert!(registrations.reserve(ip("192.0.2.1"), 1000).is_err());
        registrations.release(ip("192.0.2.1"), 1000);
        assert_eq!(registrations.reserve(ip("::ffff:192.0.2.1"), 1000), Ok(()));
    }

    // Keys whose registrations ran out are dropped, so the counter holds
    // only the recent ones.
    #[test]
    fn keys_without_recent_registrations_are_dropped() {
        let registrations = Registrations::default();
        for i in 0..100u8 {
            assert_eq!(registrations.reserve(IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)), 1000), Ok(()));
        }
        let later = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(registrations.reserve(later, 1000 + 2 * REGISTRATION_WINDOW_SECS), Ok(()));
        let times = registrations.0.lock().unwrap();
        assert_eq!(times.by_key.keys().collect::<Vec<_>>(), [&later]);
        drop(times);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(registrations.reserve(ip, 5000), Ok(()));
        registrations.release(ip, 5000);
        assert!(!registrations.0.lock().unwrap().by_key.contains_key(&ip));
    }

    #[test]
    fn five_failures_within_fifteen_minutes_block_the_ip() {
        let failures = Failures::default();
        let (ip, other) = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        for i in 0..MAX_FAILED_SIGN_INS as u64 {
            assert!(!failures.blocked(ip, 1000 + i));
            assert!(failures.reserve(ip, 1000 + i));
        }
        assert!(failures.blocked(ip, 1010));
        assert!(!failures.reserve(ip, 1010));
        assert!(!failures.blocked(other, 1010));
        assert!(failures.blocked(ip, 1000 + FAILURE_WINDOW_SECS - 1));
        assert!(!failures.blocked(ip, 1000 + MAX_FAILED_SIGN_INS as u64 - 1 + FAILURE_WINDOW_SECS));
    }

    #[test]
    fn failures_count_per_64_and_mapped_ipv4_as_ipv4() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let failures = Failures::default();
        for i in 0..MAX_FAILED_SIGN_INS {
            let from = ip(&format!("2001:db8:1:2::{:x}", 1 + i % 2));
            assert!(failures.reserve(from, 1000 + i as u64));
        }
        assert!(failures.blocked(ip("2001:db8:1:2:ffff::3"), 1010));
        assert!(!failures.reserve(ip("2001:db8:1:2:ffff::3"), 1010));
        assert!(!failures.blocked(ip("2001:db8:1:3::1"), 1010));
        assert!(failures.reserve(ip("2001:db8:1:3::1"), 1010));

        for i in 0..MAX_FAILED_SIGN_INS {
            assert!(failures.reserve(ip("::ffff:192.0.2.1"), 1000 + i as u64));
        }
        assert!(failures.blocked(ip("192.0.2.1"), 1010));
        assert!(!failures.reserve(ip("192.0.2.1"), 1010));
        failures.release(ip("192.0.2.1"), 1000);
        assert!(!failures.blocked(ip("::ffff:192.0.2.1"), 1010));
    }

    // Attempts in flight hold their place: no more than five are ever
    // checked, and one that succeeds hands its place back.
    #[test]
    fn attempts_in_flight_count_until_released() {
        let failures = Failures::default();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..MAX_FAILED_SIGN_INS {
            assert!(failures.reserve(ip, 1000));
        }
        assert!(!failures.reserve(ip, 1000));
        failures.release(ip, 1000);
        assert!(!failures.blocked(ip, 1000));
        assert!(failures.reserve(ip, 1000));
        assert!(!failures.reserve(ip, 1000));
    }

    // The cache checks tokens against the same resource the listener issues
    // them for, with or without a trailing slash in the config.
    #[test]
    fn the_resource_ignores_a_trailing_slash() {
        let internal = Internal::new(Router::new());
        assert_eq!(OAuth::new(internal, "https://db.example.com:3100/").resource(), "https://db.example.com:3100/mcp");
        assert_eq!(resource_url("https://db.example.com:3100"), resource_url("https://db.example.com:3100//"));
    }

    // As a browser sends it: lower case, without the scheme's default port.
    #[test]
    fn the_origin_of_the_public_url_is_canonical() {
        for (public_url, origin) in [
            ("https://DB.Example.com", "https://db.example.com"),
            ("HTTPS://db.example.com:443/", "https://db.example.com"),
            ("http://localhost:80", "http://localhost"),
            ("http://localhost:3100", "http://localhost:3100"),
            ("https://db.example.com:8443/base/", "https://db.example.com:8443"),
            ("http://[::1]:3100", "http://[::1]:3100"),
        ] {
            assert_eq!(origin_of(public_url), origin, "{public_url}");
        }
    }

    #[test]
    fn the_metadata_paths_insert_the_well_known_segment_before_the_public_path() {
        for (public_url, path) in [
            ("https://db.example.com", ""),
            ("https://db.example.com:8443/", ""),
            ("https://db.example.com:8443/luradb/", "/luradb"),
            ("http://[::1]:3100/a/b%20c", "/a/b%20c"),
        ] {
            let oauth = OAuth::new(Internal::new(Router::new()), public_url);
            assert_eq!(oauth.authorization_server_path, format!("/.well-known/oauth-authorization-server{path}"));
            assert_eq!(oauth.protected_resource_path, format!("/.well-known/oauth-protected-resource{path}/mcp"));
        }
    }

    #[test]
    fn redirects_add_their_parameters_encoded() {
        let resp = redirect("http://127.0.0.1:9/cb?x=1", &[("code", "c"), ("state", "a b&c")]);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers()[header::LOCATION], "http://127.0.0.1:9/cb?x=1&code=c&state=a%20b%26c");
    }

    #[test]
    fn page_text_is_escaped() {
        assert_eq!(escape("<b>\"x\" & 'y'</b>"), "&lt;b&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/b&gt;");
    }
}
