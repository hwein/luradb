//! OAuth state of the MCP listener, where LuraDB is its own authorization
//! server: registered clients, authorization codes and tokens. Kept in the
//! system store beside the auth records, codes and tokens only by their
//! SHA-256 hash and with a TTL, and changed on the control plane like every
//! auth record.
//!
//! A token carries no permissions of its own: it stands for the user and the
//! API key hash it was issued for, and becomes invalid as soon as the user is
//! deleted or the key rotated.
//!
//! The internal routes under `/store-api/auth/oauth/` take requests from the
//! MCP listener only; for everyone else they do not exist.
//!
//! POST /store-api/auth/oauth/clients       → register_client (201)
//! GET  /store-api/auth/oauth/clients/{id}  → get_client      (200 | 404)
//! POST /store-api/auth/oauth/codes         → issue_code      (201 | 400 | 401)
//! POST /store-api/auth/oauth/tokens        → issue_token     (200 | 400)
//! POST /store-api/auth/oauth/revoke        → revoke          (200)

use super::handlers::AuthState;
use super::middleware::{bearer_token, McpInternal};
use super::{hash_api_key, now_secs, AuthCache, UserRecord};
use crate::control::AuthChange;
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::StorageEngine;
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

/// Prefix of an access token; such a token is valid on MCP requests only.
pub const ACCESS_TOKEN_PREFIX: &str = "lura_at_";
/// Prefix of a refresh token.
pub const REFRESH_TOKEN_PREFIX: &str = "lura_rt_";
/// An authorization code is valid this long, once.
pub const CODE_TTL_SECS: u64 = 60;
/// An access token is valid this long.
pub const ACCESS_TTL_SECS: u64 = 60 * 60;
/// A refresh token is valid this long, or until it is used.
pub const REFRESH_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// A registered client is kept this long unless a code is issued for it;
/// after its first code it stays.
pub const CLIENT_TTL_SECS: u64 = 24 * 60 * 60;

const PREFIX_CLIENT: &str = "__sys:oauth:client:";
const PREFIX_TOKEN: &str = "__sys:oauth:token:";

/// A client registered by Dynamic Client Registration: a public client
/// without a secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: u64,
    /// Unix seconds; none once a code was issued for the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl OAuthClient {
    fn live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Code,
    Access,
    Refresh,
}

/// A code or token, stored under its hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub kind: TokenKind,
    pub user: String,
    /// The user's API key hash when the grant was made.
    pub key_hash: String,
    pub client_id: String,
    /// The resource the tokens are for.
    pub resource: String,
    /// Every code and token of one grant shares it.
    pub family: String,
    /// Unix seconds.
    pub expires_at: u64,
    /// A code's redirect URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// A code's PKCE challenge (S256).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    /// A refresh token that was already exchanged: using it again revokes
    /// the whole grant.
    #[serde(default)]
    pub rotated: bool,
}

/// Clients and tokens by id and hash.
#[derive(Debug, Default)]
pub(super) struct OAuthState {
    clients: HashMap<String, OAuthClient>,
    tokens: HashMap<String, TokenRecord>,
}

/// Why a token request is refused; the `error` codes of RFC 6749.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    #[error("{0}")]
    InvalidGrant(&'static str),
    #[error("{0}")]
    InvalidRequest(String),
}

impl OAuthError {
    fn code(&self) -> &'static str {
        match self {
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::InvalidRequest(_) => "invalid_request",
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.code(), "error_description": self.to_string() });
        (StatusCode::BAD_REQUEST, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
    }
}

/// Exchanges an authorization code for a new access and refresh token.
pub struct RedeemCode {
    pub code_hash: String,
    pub code_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub access_hash: String,
    pub refresh_hash: String,
    pub now: u64,
}

impl fmt::Debug for RedeemCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedeemCode")
            .field("code_hash", &self.code_hash)
            .field("code_verifier", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("access_hash", &self.access_hash)
            .field("refresh_hash", &self.refresh_hash)
            .field("now", &self.now)
            .finish()
    }
}

/// Exchanges a refresh token for a new pair; the old one is used up.
#[derive(Debug)]
pub struct Refresh {
    pub refresh_hash: String,
    pub client_id: String,
    pub access_hash: String,
    pub new_refresh_hash: String,
    pub now: u64,
}

/// 256 random bits, hex.
fn random_hex() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// A new token with `prefix`: the token and its hash.
fn new_token(prefix: &str) -> (String, String) {
    let token = format!("{prefix}{}", random_hex());
    let hash = hash_api_key(&token);
    (token, hash)
}

/// Base64url without padding (RFC 4648, section 5), as PKCE uses it.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The PKCE S256 challenge of `verifier`.
pub fn s256(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

fn client_key(id: &str) -> Vec<u8> {
    format!("{PREFIX_CLIENT}{id}").into_bytes()
}

fn token_key(hash: &str) -> Vec<u8> {
    format!("{PREFIX_TOKEN}{hash}").into_bytes()
}

/// Reads the OAuth state from the system store; expired codes and tokens
/// are gone there already.
pub(super) async fn load(engine: &LsmStorageEngine) -> anyhow::Result<OAuthState> {
    let mut state = OAuthState::default();
    for key in engine.scan_keys(PREFIX_CLIENT.as_bytes()).await? {
        if let Some(bytes) = engine.get(&key).await? {
            if let Ok(client) = serde_json::from_slice::<OAuthClient>(&bytes) {
                state.clients.insert(client.client_id.clone(), client);
            }
        }
    }
    for key in engine.scan_keys(PREFIX_TOKEN.as_bytes()).await? {
        if let Some(bytes) = engine.get(&key).await? {
            if let Ok(record) = serde_json::from_slice::<TokenRecord>(&bytes) {
                let hash = String::from_utf8_lossy(&key[PREFIX_TOKEN.len()..]).into_owned();
                state.tokens.insert(hash, record);
            }
        }
    }
    Ok(state)
}

impl AuthCache {
    /// The user behind the request's Bearer credential: an API key, or with
    /// OAuth on and on a request of the MCP listener (`mcp_internal`) an
    /// access token that has not expired, of a user whose API key is
    /// unchanged since.
    pub async fn resolve_bearer(&self, headers: &HeaderMap, mcp_internal: bool, now: u64) -> Option<UserRecord> {
        let token = bearer_token(headers)?;
        let hash = hash_api_key(token);
        if !token.starts_with(ACCESS_TOKEN_PREFIX) {
            return self.get_user_by_key_hash(&hash).await;
        }
        if !mcp_internal || !self.oauth_enabled {
            return None;
        }
        let record = self.oauth.read().await.tokens.get(&hash).cloned()?;
        if record.kind != TokenKind::Access || record.expires_at <= now {
            return None;
        }
        self.granted_user(&record).await
    }

    /// The user of a grant, while its API key is the one it was made with.
    async fn granted_user(&self, record: &TokenRecord) -> Option<UserRecord> {
        let user = self.get_user_by_name(&record.user).await?;
        (user.api_key_hash == record.key_hash).then_some(user)
    }

    /// The client `client_id`, unless it expired before `now`.
    pub async fn oauth_client(&self, client_id: &str, now: u64) -> Option<OAuthClient> {
        self.oauth.read().await.clients.get(client_id).filter(|client| client.live(now)).cloned()
    }

    /// Stores `client` registered at `now`, with a TTL while it has an
    /// expiry.
    async fn put_client(&self, client: &OAuthClient, now: u64) -> anyhow::Result<()> {
        let (key, value) = (client_key(&client.client_id), serde_json::to_vec(client)?);
        match client.expires_at {
            Some(expires_at) => self.engine.put_with_ttl(&key, &value, expires_at.saturating_sub(now).max(1)).await,
            None => self.engine.put(&key, &value).await,
        }
    }

    /// Stores a new client, and drops the expired clients from the cache.
    pub(crate) async fn register_client(&self, client: OAuthClient) -> anyhow::Result<()> {
        let now = client.created_at;
        let mut state = self.oauth.write().await;
        self.put_client(&client, now).await?;
        state.clients.retain(|_, c| c.live(now));
        state.clients.insert(client.client_id.clone(), client);
        Ok(())
    }

    /// Stores `record` under `hash` until it expires, and drops the
    /// expired records from the cache.
    async fn put_token(&self, state: &mut OAuthState, hash: String, record: TokenRecord, now: u64) -> anyhow::Result<()> {
        let ttl = record.expires_at.saturating_sub(now).max(1);
        self.engine.put_with_ttl(&token_key(&hash), &serde_json::to_vec(&record)?, ttl).await?;
        state.tokens.retain(|_, r| r.expires_at > now);
        state.tokens.insert(hash, record);
        Ok(())
    }

    async fn drop_token(&self, state: &mut OAuthState, hash: &str) -> anyhow::Result<()> {
        self.engine.delete(&token_key(hash)).await?;
        state.tokens.remove(hash);
        Ok(())
    }

    /// Drops every code and token of `family`.
    async fn revoke_family(&self, state: &mut OAuthState, family: &str) -> anyhow::Result<()> {
        let hashes: Vec<String> =
            state.tokens.iter().filter(|(_, r)| r.family == family).map(|(hash, _)| hash.clone()).collect();
        for hash in hashes {
            self.drop_token(state, &hash).await?;
        }
        Ok(())
    }

    /// Stores a code; the client's first one makes the client permanent.
    pub(crate) async fn issue_code(&self, hash: String, record: TokenRecord, now: u64) -> anyhow::Result<()> {
        let mut state = self.oauth.write().await;
        let expiring = state.clients.get(&record.client_id).filter(|c| c.expires_at.is_some()).cloned();
        if let Some(mut client) = expiring {
            client.expires_at = None;
            self.put_client(&client, now).await?;
            state.clients.insert(client.client_id.clone(), client);
        }
        self.put_token(&mut state, hash, record, now).await
    }

    /// A new access and refresh token of the grant behind `grant`.
    async fn put_pair(
        &self,
        state: &mut OAuthState,
        grant: &TokenRecord,
        access_hash: String,
        refresh_hash: String,
        now: u64,
    ) -> anyhow::Result<()> {
        let issued = |kind, ttl| TokenRecord {
            kind,
            expires_at: now + ttl,
            redirect_uri: None,
            code_challenge: None,
            rotated: false,
            ..grant.clone()
        };
        self.put_token(state, access_hash, issued(TokenKind::Access, ACCESS_TTL_SECS), now).await?;
        self.put_token(state, refresh_hash, issued(TokenKind::Refresh, REFRESH_TTL_SECS), now).await
    }

    pub(crate) async fn redeem_code(&self, redeem: RedeemCode) -> anyhow::Result<()> {
        let mut state = self.oauth.write().await;
        let code = state.tokens.get(&redeem.code_hash).cloned();
        let Some(code) = code.filter(|c| c.kind == TokenKind::Code && c.expires_at > redeem.now) else {
            return Err(OAuthError::InvalidGrant("the authorization code is invalid, used or expired").into());
        };
        // A code is used up by any attempt.
        self.drop_token(&mut state, &redeem.code_hash).await?;
        if code.client_id != redeem.client_id || code.redirect_uri.as_deref() != Some(redeem.redirect_uri.as_str()) {
            return Err(OAuthError::InvalidGrant("the code was issued to another client or redirect URI").into());
        }
        if code.code_challenge.as_deref() != Some(s256(&redeem.code_verifier).as_str()) {
            return Err(OAuthError::InvalidGrant("the code verifier does not match the code challenge").into());
        }
        if self.granted_user(&code).await.is_none() {
            return Err(OAuthError::InvalidGrant("the user or its API key changed").into());
        }
        self.put_pair(&mut state, &code, redeem.access_hash, redeem.refresh_hash, redeem.now).await
    }

    pub(crate) async fn refresh(&self, refresh: Refresh) -> anyhow::Result<()> {
        let mut state = self.oauth.write().await;
        let current = state.tokens.get(&refresh.refresh_hash).cloned();
        let Some(mut current) = current.filter(|r| r.kind == TokenKind::Refresh && r.expires_at > refresh.now) else {
            return Err(OAuthError::InvalidGrant("the refresh token is invalid or expired").into());
        };
        if current.rotated {
            self.revoke_family(&mut state, &current.family).await?;
            return Err(OAuthError::InvalidGrant("the refresh token was already used; the grant is revoked").into());
        }
        if current.client_id != refresh.client_id {
            return Err(OAuthError::InvalidGrant("the refresh token was issued to another client").into());
        }
        if self.granted_user(&current).await.is_none() {
            self.revoke_family(&mut state, &current.family).await?;
            return Err(OAuthError::InvalidGrant("the user or its API key changed").into());
        }
        current.rotated = true;
        self.put_token(&mut state, refresh.refresh_hash, current.clone(), refresh.now).await?;
        self.put_pair(&mut state, &current, refresh.access_hash, refresh.new_refresh_hash, refresh.now).await
    }

    /// Revokes a token: an access token alone, a refresh token with its
    /// whole grant. An unknown token is no error (RFC 7009).
    pub(crate) async fn revoke_token(&self, hash: &str) -> anyhow::Result<()> {
        let mut state = self.oauth.write().await;
        let Some(record) = state.tokens.get(hash).cloned() else { return Ok(()) };
        match record.kind {
            TokenKind::Refresh => self.revoke_family(&mut state, &record.family).await,
            TokenKind::Access | TokenKind::Code => self.drop_token(&mut state, hash).await,
        }
    }
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

#[derive(Deserialize)]
pub struct RegisterClientRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

pub async fn register_client(
    State(state): State<AuthState>,
    internal: Option<Extension<McpInternal>>,
    Json(body): Json<RegisterClientRequest>,
) -> Response {
    if internal.is_none() {
        return not_found();
    }
    let now = now_secs();
    let client = OAuthClient {
        client_id: random_hex(),
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        created_at: now,
        expires_at: Some(now + CLIENT_TTL_SECS),
    };
    match state.control.change_auth(AuthChange::RegisterClient(client.clone())).await {
        Ok(()) => (StatusCode::CREATED, Json(client)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn get_client(
    State(state): State<AuthState>,
    internal: Option<Extension<McpInternal>>,
    Path(id): Path<String>,
) -> Response {
    match (internal, state.cache.oauth_client(&id, now_secs()).await) {
        (Some(_), Some(client)) => Json(client).into_response(),
        _ => not_found(),
    }
}

#[derive(Deserialize)]
pub struct IssueCodeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub resource: String,
}

/// Issues a code for the user whose API key is the request's Bearer
/// credential; only an API key, never a token, signs in.
pub async fn issue_code(
    State(state): State<AuthState>,
    internal: Option<Extension<McpInternal>>,
    headers: HeaderMap,
    Json(body): Json<IssueCodeRequest>,
) -> Response {
    if internal.is_none() {
        return not_found();
    }
    let user = match bearer_token(&headers) {
        Some(key) => state.cache.get_user_by_key_hash(&hash_api_key(key)).await,
        None => None,
    };
    let Some(user) = user else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    };
    let now = now_secs();
    if state.cache.oauth_client(&body.client_id, now).await.is_none() {
        return (StatusCode::BAD_REQUEST, "unknown client").into_response();
    }
    let code = random_hex();
    let record = TokenRecord {
        kind: TokenKind::Code,
        user: user.name,
        key_hash: user.api_key_hash,
        client_id: body.client_id,
        resource: body.resource,
        family: random_hex(),
        expires_at: now + CODE_TTL_SECS,
        redirect_uri: Some(body.redirect_uri),
        code_challenge: Some(body.code_challenge),
        rotated: false,
    };
    match state.control.change_auth(AuthChange::IssueCode { hash: hash_api_key(&code), record, now }).await {
        Ok(()) => (StatusCode::CREATED, Json(json!({ "code": code }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
}

fn required(value: Option<String>, name: &str) -> Result<String, OAuthError> {
    value.filter(|v| !v.is_empty()).ok_or_else(|| OAuthError::InvalidRequest(format!("missing parameter '{name}'")))
}

/// The token endpoint: `authorization_code` with PKCE, and `refresh_token`.
pub async fn issue_token(
    State(state): State<AuthState>,
    internal: Option<Extension<McpInternal>>,
    Json(body): Json<TokenRequest>,
) -> Response {
    if internal.is_none() {
        return not_found();
    }
    let (access, access_hash) = new_token(ACCESS_TOKEN_PREFIX);
    let (refresh, refresh_hash) = new_token(REFRESH_TOKEN_PREFIX);
    let now = now_secs();
    let change = (|| -> Result<AuthChange, OAuthError> {
        let client_id = required(body.client_id, "client_id")?;
        match body.grant_type.as_str() {
            "authorization_code" => Ok(AuthChange::RedeemCode(RedeemCode {
                code_hash: hash_api_key(&required(body.code, "code")?),
                code_verifier: required(body.code_verifier, "code_verifier")?,
                client_id,
                redirect_uri: required(body.redirect_uri, "redirect_uri")?,
                access_hash,
                refresh_hash,
                now,
            })),
            "refresh_token" => Ok(AuthChange::Refresh(Refresh {
                refresh_hash: hash_api_key(&required(body.refresh_token, "refresh_token")?),
                client_id,
                access_hash,
                new_refresh_hash: refresh_hash,
                now,
            })),
            other => Err(OAuthError::InvalidRequest(format!("unsupported grant_type '{other}'"))),
        }
    })();
    let change = match change {
        Ok(change) => change,
        Err(e) => return e.into_response(),
    };
    match state.control.change_auth(change).await {
        Ok(()) => {
            let body = json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": ACCESS_TTL_SECS,
                "refresh_token": refresh,
            });
            (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
        }
        Err(e) => match e.downcast::<OAuthError>() {
            Ok(oauth) => oauth.into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
    }
}

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token: String,
}

pub async fn revoke(
    State(state): State<AuthState>,
    internal: Option<Extension<McpInternal>>,
    Json(body): Json<RevokeRequest>,
) -> Response {
    if internal.is_none() {
        return not_found();
    }
    match state.control.change_auth(AuthChange::RevokeToken { hash: hash_api_key(&body.token) }).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::UserRole;
    use axum::http::{header, HeaderValue};

    // RFC 7636, appendix B.
    #[test]
    fn s256_matches_the_rfc_example() {
        assert_eq!(s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn base64url_pads_nothing() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    async fn cache() -> (AuthCache, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = crate::control::system::open(dir.path()).await.unwrap();
        let cache = AuthCache::new(engine, true);
        cache
            .upsert_user(UserRecord {
                name: "zoé".into(),
                api_key_hash: hash_api_key("lura_zoe"),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        (cache, dir)
    }

    const NOW: u64 = 1_000_000;
    const VERIFIER: &str = "a-verifier-of-at-least-forty-three-characters-0123456789";

    /// A code issued at `now`.
    fn code_at(now: u64) -> TokenRecord {
        TokenRecord {
            kind: TokenKind::Code,
            user: "zoé".into(),
            key_hash: hash_api_key("lura_zoe"),
            client_id: "client".into(),
            resource: "https://db.example.com/mcp".into(),
            family: "family".into(),
            expires_at: now + CODE_TTL_SECS,
            redirect_uri: Some("http://127.0.0.1:9000/cb".into()),
            code_challenge: Some(s256(VERIFIER)),
            rotated: false,
        }
    }

    fn redeem(now: u64, verifier: &str) -> RedeemCode {
        RedeemCode {
            code_hash: hash_api_key("code"),
            code_verifier: verifier.into(),
            client_id: "client".into(),
            redirect_uri: "http://127.0.0.1:9000/cb".into(),
            access_hash: hash_api_key("lura_at_1"),
            refresh_hash: hash_api_key("lura_rt_1"),
            now,
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).unwrap());
        headers
    }

    fn grant_error(e: anyhow::Error) -> OAuthError {
        e.downcast::<OAuthError>().unwrap()
    }

    #[test]
    fn a_code_turns_into_tokens_once() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            cache.redeem_code(redeem(NOW + 1, VERIFIER)).await.unwrap();
            let user = cache.resolve_bearer(&bearer("lura_at_1"), true, NOW + 2).await;
            assert_eq!(user.map(|u| u.name), Some("zoé".to_string()));
            let again = cache.redeem_code(redeem(NOW + 2, VERIFIER)).await.unwrap_err();
            assert!(matches!(grant_error(again), OAuthError::InvalidGrant(_)));
        })
    }

    #[test]
    fn an_expired_code_or_a_wrong_verifier_is_refused() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            let late = cache.redeem_code(redeem(NOW + CODE_TTL_SECS, VERIFIER)).await.unwrap_err();
            assert!(matches!(grant_error(late), OAuthError::InvalidGrant(_)));

            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            let wrong = cache.redeem_code(redeem(NOW + 1, "another-verifier")).await.unwrap_err();
            assert!(matches!(grant_error(wrong), OAuthError::InvalidGrant(_)));
            // The failed attempt used the code up.
            let retry = cache.redeem_code(redeem(NOW + 2, VERIFIER)).await.unwrap_err();
            assert!(matches!(grant_error(retry), OAuthError::InvalidGrant(_)));
        })
    }

    #[test]
    fn an_access_token_counts_only_on_mcp_requests_and_until_it_expires() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            cache.redeem_code(redeem(NOW, VERIFIER)).await.unwrap();
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), false, NOW).await.is_none());
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), true, NOW + ACCESS_TTL_SECS - 1).await.is_some());
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), true, NOW + ACCESS_TTL_SECS).await.is_none());
            // A refresh token is no access token.
            assert!(cache.resolve_bearer(&bearer("lura_rt_1"), true, NOW).await.is_none());
            assert!(cache.resolve_bearer(&bearer("lura_zoe"), false, NOW).await.is_some());
        })
    }

    #[test]
    fn a_rotated_key_or_a_deleted_user_ends_the_tokens() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            cache.redeem_code(redeem(NOW, VERIFIER)).await.unwrap();
            cache.rotate_key("zoé", &hash_api_key("lura_zoe_2")).await.unwrap();
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), true, NOW).await.is_none());
            cache.rotate_key("zoé", &hash_api_key("lura_zoe")).await.unwrap();
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), true, NOW).await.is_some());
            cache.remove_user("zoé").await.unwrap();
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), true, NOW).await.is_none());
        })
    }

    fn refresh(token: &str, next: &str, now: u64) -> Refresh {
        Refresh {
            refresh_hash: hash_api_key(token),
            client_id: "client".into(),
            access_hash: hash_api_key(&format!("lura_at_{next}")),
            new_refresh_hash: hash_api_key(&format!("lura_rt_{next}")),
            now,
        }
    }

    #[test]
    fn refreshing_rotates_and_reuse_revokes_the_grant() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            cache.redeem_code(redeem(NOW, VERIFIER)).await.unwrap();
            cache.refresh(refresh("lura_rt_1", "2", NOW + 10)).await.unwrap();
            assert!(cache.resolve_bearer(&bearer("lura_at_2"), true, NOW + 10).await.is_some());

            let reused = cache.refresh(refresh("lura_rt_1", "3", NOW + 20)).await.unwrap_err();
            assert!(matches!(grant_error(reused), OAuthError::InvalidGrant(_)));
            for token in ["lura_at_1", "lura_at_2", "lura_at_3"] {
                assert!(cache.resolve_bearer(&bearer(token), true, NOW + 20).await.is_none(), "{token}");
            }
            let after = cache.refresh(refresh("lura_rt_2", "4", NOW + 30)).await.unwrap_err();
            assert!(matches!(grant_error(after), OAuthError::InvalidGrant(_)));
        })
    }

    #[test]
    fn revoking_a_refresh_token_ends_its_grant() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            cache.issue_code(hash_api_key("code"), code_at(NOW), NOW).await.unwrap();
            cache.redeem_code(redeem(NOW, VERIFIER)).await.unwrap();
            cache.revoke_token(&hash_api_key("lura_rt_1")).await.unwrap();
            assert!(cache.resolve_bearer(&bearer("lura_at_1"), true, NOW).await.is_none());
            cache.revoke_token(&hash_api_key("lura_unknown")).await.unwrap();
        })
    }

    #[test]
    fn clients_and_tokens_survive_a_reload() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            let client = OAuthClient {
                client_id: "client".into(),
                client_name: "Agent ✓".into(),
                redirect_uris: vec!["http://127.0.0.1:9000/cb".into()],
                created_at: 1,
                expires_at: None,
            };
            cache.register_client(client.clone()).await.unwrap();
            let now = now_secs();
            cache.issue_code(hash_api_key("code"), code_at(now), now).await.unwrap();
            cache.redeem_code(redeem(now, VERIFIER)).await.unwrap();

            let reloaded = AuthCache::new(std::sync::Arc::clone(&cache.engine), true);
            reloaded.load_from_engine().await.unwrap();
            assert_eq!(reloaded.oauth_client("client", now).await, Some(client));
            assert!(reloaded.resolve_bearer(&bearer("lura_at_1"), true, now_secs()).await.is_some());
        })
    }

    fn client_at(id: &str, now: u64) -> OAuthClient {
        OAuthClient {
            client_id: id.into(),
            client_name: "Agent ✓".into(),
            redirect_uris: vec!["http://127.0.0.1:9000/cb".into()],
            created_at: now,
            expires_at: Some(now + CLIENT_TTL_SECS),
        }
    }

    /// The `expire_at` of the stored client (0 = no TTL).
    async fn stored_expiry(cache: &AuthCache, id: &str) -> u64 {
        let (found, expire_at) = cache.engine.get_latest_with_expiry(&client_key(id)).await.unwrap();
        assert!(found.into_option().is_some(), "{id} is not stored");
        expire_at
    }

    // A client nobody signed in with expires, also across a reload; its
    // first code makes a client permanent.
    #[test]
    fn a_client_without_a_code_expires() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            let expired = NOW + CLIENT_TTL_SECS;
            cache.register_client(client_at("client", NOW)).await.unwrap();
            cache.register_client(client_at("idle", NOW)).await.unwrap();
            assert_ne!(stored_expiry(&cache, "client").await, 0);
            assert!(cache.oauth_client("client", expired - 1).await.is_some());
            assert!(cache.oauth_client("client", expired).await.is_none());

            cache.issue_code(hash_api_key("code"), code_at(NOW + 1), NOW + 1).await.unwrap();
            assert_eq!(stored_expiry(&cache, "client").await, 0);
            assert_eq!(cache.oauth_client("client", expired).await.and_then(|c| c.expires_at), None);
            assert!(cache.oauth_client("idle", expired).await.is_none());

            let reloaded = AuthCache::new(std::sync::Arc::clone(&cache.engine), true);
            reloaded.load_from_engine().await.unwrap();
            assert!(reloaded.oauth_client("client", expired).await.is_some());
            assert_eq!(reloaded.oauth_client("idle", NOW + 1).await, Some(client_at("idle", NOW)));
            assert!(reloaded.oauth_client("idle", expired).await.is_none());

            // The next registration drops it from the cache.
            reloaded.register_client(client_at("next", expired)).await.unwrap();
            let clients = &reloaded.oauth.read().await.clients;
            assert!(clients.contains_key("client") && clients.contains_key("next") && !clients.contains_key("idle"));
        })
    }

    #[test]
    fn debug_hides_the_code_verifier() {
        let printed = format!("{:?}", AuthChange::RedeemCode(redeem(NOW, VERIFIER)));
        assert!(!printed.contains(VERIFIER) && printed.contains("http://127.0.0.1:9000/cb"), "{printed}");
    }

    #[test]
    fn with_oauth_off_no_access_token_counts() {
        crate::core::engine_runtime::block_on(async {
            let (cache, _dir) = cache().await;
            let now = now_secs();
            cache.issue_code(hash_api_key("code"), code_at(now), now).await.unwrap();
            cache.redeem_code(redeem(now, VERIFIER)).await.unwrap();

            let off = AuthCache::new(std::sync::Arc::clone(&cache.engine), false);
            off.load_from_engine().await.unwrap();
            assert!(off.resolve_bearer(&bearer("lura_at_1"), true, now_secs()).await.is_none());
            assert!(off.resolve_bearer(&bearer("lura_zoe"), true, now_secs()).await.is_some());
        })
    }
}
