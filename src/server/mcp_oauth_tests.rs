//! OAuth on the MCP listener, end to end: registration, sign-in with an API
//! key, code exchange with PKCE, refresh, revocation, written by hand as a
//! client and a browser send them.

use super::mcp_tests::{create_user, http, mcp_config, rest_call, rest_ok, with_admin, Client};
use super::tests::{exchange, request};
use super::*;

const PUBLIC_URL: &str = "http://localhost:3100";
const REDIRECT: &str = "http://127.0.0.1:9000/callback";
const VERIFIER: &str = "a-pkce-verifier-with-enough-entropy-0123456789-clé";

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(b).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(name, value)| format!("{name}={}", encode(value))).collect::<Vec<_>>().join("&")
}

fn post_form(path: &str, body: &str, origin: Option<&str>) -> String {
    let mut headers = vec![("Content-Type", "application/x-www-form-urlencoded")];
    if let Some(origin) = origin {
        headers.push(("Origin", origin));
    }
    http("POST", path, &headers, body)
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| line.strip_prefix(&format!("{name}: "))).map(str::trim)
}

/// The value of the query parameter `name` in `url`.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    let value = query.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}=")))?;
    let mut bytes = Vec::new();
    let mut chars = value.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'%' {
            let hex = [*chars.next()?, *chars.next()?];
            bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}

fn json_of(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(body)))
}

/// OAuth on, with an admin.
fn oauth_config(dir: &Path, admin_key: &str) -> LuraConfig {
    mcp_config(dir, |cfg| {
        with_admin(cfg, admin_key);
        cfg.mcp.oauth_enabled = true;
        cfg.mcp.public_url = PUBLIC_URL.to_string();
    })
}

fn with_oauth<F, Fut>(admin_key: &str, client: F)
where
    F: FnOnce(SocketAddr, SocketAddr) -> Fut,
    Fut: Future<Output = ()>,
{
    let dir = tempfile::TempDir::new().unwrap();
    let server = Server::start(Arc::new(oauth_config(dir.path(), admin_key)), &dir.path().join("luradb.toml")).unwrap();
    let (rest, mcp) = (server.http_addr.unwrap(), server.mcp_addr.unwrap());
    tokio::runtime::Runtime::new().unwrap().block_on(client(rest, mcp));
    server.shutdown().unwrap();
}

async fn register(mcp: SocketAddr) -> String {
    let body = json!({ "client_name": "Agent 🦒", "redirect_uris": [REDIRECT] }).to_string();
    let (status, body) = request(mcp, &http("POST", "/oauth/register", &[("Content-Type", "application/json")], &body)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    json_of(&body)["client_id"].as_str().unwrap().to_string()
}

fn authorize_params(client_id: &str, method: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", REDIRECT.to_string()),
        ("code_challenge", crate::auth::oauth::s256(VERIFIER)),
        ("code_challenge_method", method.to_string()),
        ("state", "xyz ✓".to_string()),
        ("resource", format!("{PUBLIC_URL}/mcp")),
    ]
}

fn as_pairs<'a>(params: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    params.iter().map(|(name, value)| (*name, value.as_str())).collect()
}

/// The sign-in page: status, head, HTML.
async fn sign_in_page(mcp: SocketAddr, params: &[(&'static str, String)]) -> (u16, String, String) {
    let target = format!("/oauth/authorize?{}", form(&as_pairs(params)));
    let (status, head, body) = exchange(mcp, &http("GET", &target, &[], "")).await;
    (status, head, String::from_utf8_lossy(&body).into_owned())
}

fn csrf_of(page: &str) -> String {
    let start = page.find("name=\"csrf\" value=\"").expect("csrf field") + "name=\"csrf\" value=\"".len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

/// Submits the sign-in form: status, head, body.
async fn submit(mcp: SocketAddr, params: &[(&'static str, String)], extra: &[(&str, &str)]) -> (u16, String, String) {
    let mut pairs = as_pairs(params);
    pairs.extend_from_slice(extra);
    let (status, head, body) = exchange(mcp, &post_form("/oauth/authorize", &form(&pairs), Some(PUBLIC_URL))).await;
    (status, head, String::from_utf8_lossy(&body).into_owned())
}

/// Signs in with `api_key` and returns the code.
async fn sign_in(mcp: SocketAddr, client_id: &str, api_key: &str) -> String {
    let params = authorize_params(client_id, "S256");
    let (status, _, page) = sign_in_page(mcp, &params).await;
    assert_eq!(status, 200, "{page}");
    let csrf = csrf_of(&page);
    let (status, head, body) = submit(mcp, &params, &[("csrf", &csrf), ("api_key", api_key), ("decision", "allow")]).await;
    assert_eq!(status, 302, "{head}{body}");
    let location = header(&head, "location").unwrap();
    assert!(location.starts_with(REDIRECT), "{location}");
    assert_eq!(query_param(location, "state").as_deref(), Some("xyz ✓"));
    query_param(location, "code").expect("a code")
}

async fn token(mcp: SocketAddr, pairs: &[(&str, &str)]) -> (u16, Value) {
    let (status, body) = request(mcp, &post_form("/oauth/token", &form(pairs), None)).await;
    (status, json_of(&body))
}

async fn exchange_code(mcp: SocketAddr, client_id: &str, code: &str, verifier: &str) -> (u16, Value) {
    token(
        mcp,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("code_verifier", verifier),
            ("resource", &format!("{PUBLIC_URL}/mcp")),
        ],
    )
    .await
}

async fn refresh(mcp: SocketAddr, client_id: &str, refresh_token: &str) -> (u16, Value) {
    token(mcp, &[("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("client_id", client_id)]).await
}

/// The `whoami` tool on a new session with `access_token`: HTTP status and
/// the user's name.
async fn whoami(mcp: SocketAddr, access_token: &str) -> (u16, Option<String>) {
    let mut client = Client::new(mcp, Some(access_token));
    let initialized = client.initialize().await;
    if initialized.status != 200 {
        return (initialized.status, None);
    }
    let answer = client.call("whoami", json!({})).await;
    let name = answer.message.as_ref().and_then(|m| m["result"]["structuredContent"]["name"].as_str().map(String::from));
    (answer.status, name)
}

#[test]
fn both_metadata_documents_describe_this_server() {
    with_oauth("lura_oauth_meta_admin", |_, mcp| async move {
        let (status, body) = request(mcp, &http("GET", "/.well-known/oauth-protected-resource", &[], "")).await;
        assert_eq!(status, 200);
        let resource = json_of(&body);
        assert_eq!(resource["resource"], json!(format!("{PUBLIC_URL}/mcp")));
        assert_eq!(resource["authorization_servers"], json!([PUBLIC_URL]));
        assert_eq!(resource["bearer_methods_supported"], json!(["header"]));

        let (status, body) = request(mcp, &http("GET", "/.well-known/oauth-authorization-server", &[], "")).await;
        assert_eq!(status, 200);
        let server = json_of(&body);
        assert_eq!(server["issuer"], json!(PUBLIC_URL));
        for (field, path) in [
            ("authorization_endpoint", "/oauth/authorize"),
            ("token_endpoint", "/oauth/token"),
            ("registration_endpoint", "/oauth/register"),
            ("revocation_endpoint", "/oauth/revoke"),
        ] {
            assert_eq!(server[field], json!(format!("{PUBLIC_URL}{path}")), "{field}");
        }
        assert_eq!(server["response_types_supported"], json!(["code"]));
        assert_eq!(server["grant_types_supported"], json!(["authorization_code", "refresh_token"]));
        assert_eq!(server["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(server["token_endpoint_auth_methods_supported"], json!(["none"]));
        assert_eq!(server["scopes_supported"], json!([]));

        // The challenge without a credential points there.
        let answer = Client::new(mcp, None).initialize().await;
        assert_eq!(answer.status, 401);
        let challenge = format!("resource_metadata=\"{PUBLIC_URL}/.well-known/oauth-protected-resource\"");
        assert!(header(&answer.head, "www-authenticate").unwrap().contains(&challenge), "{}", answer.head);
    });
}

#[test]
fn registration_takes_valid_redirect_uris_only() {
    with_oauth("lura_oauth_register_admin", |_, mcp| async move {
        assert_eq!(register(mcp).await.len(), 64);
        let body = json!({ "client_name": "x", "redirect_uris": ["http://evil.example.com/cb"] }).to_string();
        let (status, body) = request(mcp, &http("POST", "/oauth/register", &[("Content-Type", "application/json")], &body)).await;
        assert_eq!(status, 400);
        assert_eq!(json_of(&body)["error"], json!("invalid_redirect_uri"));
    });
}

// The complete flow: register, sign in with an API key, exchange the code
// with its verifier, call a tool with the token; the token is no API key on
// the REST listener.
#[test]
fn the_code_flow_ends_in_a_tool_call_with_the_token() {
    let admin_key = "lura_oauth_flow_admin";
    with_oauth(admin_key, |rest, mcp| async move {
        let key = create_user(rest, admin_key, "zoe-agent").await;
        let client_id = register(mcp).await;
        let code = sign_in(mcp, &client_id, &key).await;
        let (status, tokens) = exchange_code(mcp, &client_id, &code, VERIFIER).await;
        assert_eq!(status, 200, "{tokens}");
        assert_eq!(tokens["token_type"], json!("Bearer"));
        assert_eq!(tokens["expires_in"], json!(3600));
        let access = tokens["access_token"].as_str().unwrap();
        assert!(access.starts_with("lura_at_") && tokens["refresh_token"].as_str().unwrap().starts_with("lura_rt_"));

        assert_eq!(whoami(mcp, access).await, (200, Some("zoe-agent".to_string())));
        let mut client = Client::new(mcp, Some(access));
        assert_eq!(client.initialize().await.status, 200);

        let (status, _) = request(rest, &rest_call("GET", "/store-api/auth/whoami", Some(access), "")).await;
        assert_eq!(status, 401, "an access token is no API key over REST");

        // A code works once.
        let (status, error) = exchange_code(mcp, &client_id, &code, VERIFIER).await;
        assert_eq!((status, error["error"].clone()), (400, json!("invalid_grant")));
    });
}

#[test]
fn plain_pkce_and_a_wrong_verifier_are_refused() {
    let admin_key = "lura_oauth_pkce_admin";
    with_oauth(admin_key, |_, mcp| async move {
        let client_id = register(mcp).await;
        let (status, head, _) = sign_in_page(mcp, &authorize_params(&client_id, "plain")).await;
        assert_eq!(status, 302);
        let location = header(&head, "location").unwrap();
        assert_eq!(query_param(location, "error").as_deref(), Some("invalid_request"), "{location}");
        assert_eq!(query_param(location, "state").as_deref(), Some("xyz ✓"));

        let code = sign_in(mcp, &client_id, admin_key).await;
        let (status, error) = exchange_code(mcp, &client_id, &code, "another-verifier-of-sufficient-length-000000").await;
        assert_eq!((status, error["error"].clone()), (400, json!("invalid_grant")));
    });
}

// Errors before the redirect URI is proven are shown, not redirected.
#[test]
fn an_unknown_client_or_redirect_uri_gets_an_error_page() {
    with_oauth("lura_oauth_page_admin", |_, mcp| async move {
        let client_id = register(mcp).await;
        let (status, head, _) = sign_in_page(mcp, &authorize_params("unknown", "S256")).await;
        assert_eq!(status, 400);
        assert!(header(&head, "location").is_none());
        let mut params = authorize_params(&client_id, "S256");
        params[2].1 = "http://127.0.0.1:9000/elsewhere".to_string();
        let (status, head, _) = sign_in_page(mcp, &params).await;
        assert_eq!(status, 400);
        assert!(header(&head, "location").is_none());

        let (status, head, page) = sign_in_page(mcp, &authorize_params(&client_id, "S256")).await;
        assert_eq!(status, 200);
        assert_eq!(header(&head, "content-security-policy"), Some("default-src 'none'; style-src 'self'; form-action 'self'"));
        assert_eq!(header(&head, "x-frame-options"), Some("deny"));
        assert!(page.contains("Agent 🦒") && page.contains("127.0.0.1:9000") && !page.contains("<script"), "{page}");
    });
}

#[test]
fn the_sign_in_form_needs_its_csrf_token_and_origin() {
    let admin_key = "lura_oauth_csrf_admin";
    with_oauth(admin_key, |_, mcp| async move {
        let client_id = register(mcp).await;
        let params = authorize_params(&client_id, "S256");
        let (_, _, page) = sign_in_page(mcp, &params).await;
        let csrf = csrf_of(&page);
        for extra in [vec![], vec![("csrf", "0".repeat(64))]] {
            let mut fields: Vec<(&str, &str)> = extra.iter().map(|(n, v)| (*n, v.as_str())).collect();
            fields.extend([("api_key", admin_key), ("decision", "allow")]);
            let (status, _, _) = submit(mcp, &params, &fields).await;
            assert_eq!(status, 400);
        }
        let mut pairs = as_pairs(&params);
        pairs.extend([("csrf", csrf.as_str()), ("api_key", admin_key), ("decision", "allow")]);
        for origin in [None, Some("http://evil.example.com")] {
            let (status, _) = request(mcp, &post_form("/oauth/authorize", &form(&pairs), origin)).await;
            assert_eq!(status, 403, "{origin:?}");
        }
        let (status, head, _) = submit(mcp, &params, &[("csrf", &csrf), ("api_key", admin_key), ("decision", "deny")]).await;
        assert_eq!(status, 302);
        assert_eq!(query_param(header(&head, "location").unwrap(), "error").as_deref(), Some("access_denied"));
    });
}

#[test]
fn five_wrong_api_keys_block_the_sign_in() {
    with_oauth("lura_oauth_limit_admin", |_, mcp| async move {
        let client_id = register(mcp).await;
        let params = authorize_params(&client_id, "S256");
        let (_, _, page) = sign_in_page(mcp, &params).await;
        let csrf = csrf_of(&page);
        for attempt in 1..=5 {
            let (status, _, page) = submit(mcp, &params, &[("csrf", &csrf), ("api_key", "lura_wrong"), ("decision", "allow")]).await;
            assert_eq!(status, 200, "attempt {attempt}");
            assert!(page.contains("The API key is not valid."), "{page}");
        }
        let (status, _, _) = submit(mcp, &params, &[("csrf", &csrf), ("api_key", "lura_wrong"), ("decision", "allow")]).await;
        assert_eq!(status, 429);
    });
}

#[test]
fn refreshing_rotates_and_reusing_an_old_refresh_token_revokes_the_grant() {
    let admin_key = "lura_oauth_refresh_admin";
    with_oauth(admin_key, |_, mcp| async move {
        let client_id = register(mcp).await;
        let code = sign_in(mcp, &client_id, admin_key).await;
        let (_, first) = exchange_code(mcp, &client_id, &code, VERIFIER).await;
        let first_refresh = first["refresh_token"].as_str().unwrap();
        let (status, second) = refresh(mcp, &client_id, first_refresh).await;
        assert_eq!(status, 200, "{second}");
        let second_access = second["access_token"].as_str().unwrap();
        assert_eq!(whoami(mcp, second_access).await.0, 200);

        let (status, error) = refresh(mcp, &client_id, first_refresh).await;
        assert_eq!((status, error["error"].clone()), (400, json!("invalid_grant")));
        assert_eq!(whoami(mcp, second_access).await.0, 401);
        assert_eq!(whoami(mcp, first["access_token"].as_str().unwrap()).await.0, 401);
        let (status, _) = refresh(mcp, &client_id, second["refresh_token"].as_str().unwrap()).await;
        assert_eq!(status, 400);
    });
}

#[test]
fn revoked_tokens_and_deleted_users_end_access() {
    let admin_key = "lura_oauth_revoke_admin";
    with_oauth(admin_key, |rest, mcp| async move {
        let key = create_user(rest, admin_key, "short-lived").await;
        let client_id = register(mcp).await;
        let code = sign_in(mcp, &client_id, &key).await;
        let (_, tokens) = exchange_code(mcp, &client_id, &code, VERIFIER).await;
        let access = tokens["access_token"].as_str().unwrap().to_string();
        let (status, _) = request(mcp, &post_form("/oauth/revoke", &form(&[("token", &access)]), None)).await;
        assert_eq!(status, 200);
        assert_eq!(whoami(mcp, &access).await.0, 401);

        let code = sign_in(mcp, &client_id, &key).await;
        let (_, tokens) = exchange_code(mcp, &client_id, &code, VERIFIER).await;
        let access = tokens["access_token"].as_str().unwrap().to_string();
        assert_eq!(whoami(mcp, &access).await.0, 200);
        rest_ok(rest, "DELETE", "/store-api/auth/users/short-lived", admin_key, "").await;
        let answer = Client::new(mcp, Some(&access)).call("whoami", json!({})).await;
        assert_eq!(answer.status, 401);
        assert!(header(&answer.head, "www-authenticate").unwrap().contains("error=\"invalid_token\""), "{}", answer.head);
    });
}

// Over the REST listener the internal OAuth routes do not exist, with or
// without a key.
#[test]
fn the_internal_oauth_routes_are_not_found_over_rest() {
    let admin_key = "lura_oauth_internal_admin";
    with_oauth(admin_key, |rest, _| async move {
        for key in [None, Some(admin_key)] {
            for (method, path) in [
                ("POST", "/store-api/auth/oauth/clients"),
                ("GET", "/store-api/auth/oauth/clients/x"),
                ("POST", "/store-api/auth/oauth/codes"),
                ("POST", "/store-api/auth/oauth/tokens"),
                ("POST", "/store-api/auth/oauth/revoke"),
            ] {
                let (status, _) = request(rest, &rest_call(method, path, key, "{}")).await;
                assert_eq!(status, 404, "{method} {path} {key:?}");
            }
        }
    });
}

#[test]
fn tokens_survive_a_restart() {
    let admin_key = "lura_oauth_restart_admin";
    let dir = tempfile::TempDir::new().unwrap();
    let start = || Server::start(Arc::new(oauth_config(dir.path(), admin_key)), &dir.path().join("luradb.toml")).unwrap();
    let client = tokio::runtime::Runtime::new().unwrap();

    let server = start();
    let mcp = server.mcp_addr.unwrap();
    let (client_id, tokens) = client.block_on(async {
        let client_id = register(mcp).await;
        let code = sign_in(mcp, &client_id, admin_key).await;
        let tokens = exchange_code(mcp, &client_id, &code, VERIFIER).await.1;
        (client_id, tokens)
    });
    server.shutdown().unwrap();

    let server = start();
    let mcp = server.mcp_addr.unwrap();
    client.block_on(async {
        assert_eq!(whoami(mcp, tokens["access_token"].as_str().unwrap()).await, (200, Some(ADMIN_NAME.to_string())));
        let (status, _) = refresh(mcp, &client_id, tokens["refresh_token"].as_str().unwrap()).await;
        assert_eq!(status, 200);
    });
    server.shutdown().unwrap();
}

// Tokens outlive a restart, but not one with OAuth switched off; API keys
// keep working.
#[test]
fn tokens_stop_working_once_oauth_is_off() {
    let admin_key = "lura_oauth_off_admin";
    let dir = tempfile::TempDir::new().unwrap();
    let client = tokio::runtime::Runtime::new().unwrap();

    let server = Server::start(Arc::new(oauth_config(dir.path(), admin_key)), &dir.path().join("luradb.toml")).unwrap();
    let mcp = server.mcp_addr.unwrap();
    let tokens = client.block_on(async {
        let client_id = register(mcp).await;
        let code = sign_in(mcp, &client_id, admin_key).await;
        exchange_code(mcp, &client_id, &code, VERIFIER).await.1
    });
    server.shutdown().unwrap();

    let off = mcp_config(dir.path(), |cfg| with_admin(cfg, admin_key));
    let server = Server::start(Arc::new(off), &dir.path().join("luradb.toml")).unwrap();
    let mcp = server.mcp_addr.unwrap();
    client.block_on(async {
        let access = tokens["access_token"].as_str().unwrap();
        assert_eq!(whoami(mcp, access).await.0, 401);
        let answer = Client::new(mcp, Some(access)).call("whoami", json!({})).await;
        assert_eq!(answer.status, 401);
        assert_eq!(whoami(mcp, admin_key).await, (200, Some(ADMIN_NAME.to_string())));
    });
    server.shutdown().unwrap();
}

const ADMIN_NAME: &str = "admin";
