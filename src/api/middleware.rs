//! API error mapping, shared response helpers, and trusted-proxy middleware.
//!
//! Errors from the domain/engine layer embed an HTTP status code as a numeric
//! prefix in the message string (e.g. "404 Not Found: …"). `ApiError` reads
//! that prefix and produces the appropriate HTTP response, including a
//! `Retry-After: 1` header for 429 responses.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

// ── ApiError ──────────────────────────────────────────────────────────────────

/// Unified API error that maps anyhow errors to HTTP responses.
pub struct ApiError(StatusCode, String);

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError(status, message.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        let msg = e.to_string();
        let status = if msg.starts_with("429") {
            StatusCode::TOO_MANY_REQUESTS
        } else if msg.starts_with("410") {
            StatusCode::GONE
        } else if msg.starts_with("409") {
            StatusCode::CONFLICT
        } else if msg.starts_with("404") {
            StatusCode::NOT_FOUND
        } else if msg.starts_with("413") {
            StatusCode::PAYLOAD_TOO_LARGE
        } else if msg.starts_with("400") {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        ApiError(status, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (self.0, self.1).into_response();
        if self.0 == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, "1".parse().unwrap());
        }
        resp
    }
}

// ── Trusted Proxy Middleware ──────────────────────────────────────────────────

/// The resolved real client IP address, set by [`proxy_fn`] on every request.
/// Downstream handlers and loggers can read this from request extensions.
#[derive(Clone, Debug)]
pub struct ClientIp(pub IpAddr);

/// A parsed CIDR range (network address + prefix length).
#[derive(Clone, Debug)]
pub struct ParsedCidr {
    ip: IpAddr,
    prefix_len: u8,
}

impl ParsedCidr {
    /// Parses a CIDR string like `"192.168.0.0/16"` or a plain IP (`"127.0.0.1"`).
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str.parse()?;
            let prefix_len: u8 = prefix_str.parse()?;
            Ok(Self { ip, prefix_len })
        } else {
            let ip: IpAddr = s.parse()?;
            let prefix_len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Self { ip, prefix_len })
        }
    }

    /// Returns `true` if `addr` falls within this CIDR range.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.ip, addr) {
            (IpAddr::V4(net), IpAddr::V4(check)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(self.prefix_len as u32);
                (u32::from(net) >> shift) == (u32::from(check) >> shift)
            }
            (IpAddr::V6(net), IpAddr::V6(check)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let shift = 128u32.saturating_sub(self.prefix_len as u32);
                (u128::from(net) >> shift) == (u128::from(check) >> shift)
            }
            _ => false,
        }
    }
}

/// Parses a slice of CIDR strings into [`ParsedCidr`] values.
/// Called once at startup; any parse error aborts the server.
pub fn parse_cidrs(strings: &[String]) -> anyhow::Result<Vec<ParsedCidr>> {
    strings.iter().map(|s| ParsedCidr::parse(s)).collect()
}

/// Returns `true` for RFC-1918 private, loopback, and link-local addresses.
fn is_private_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10                                    // 10.0.0.0/8
            || (o[0] == 172 && (o[1] & 0xf0) == 16)     // 172.16.0.0/12
            || (o[0] == 192 && o[1] == 168)              // 192.168.0.0/16
            || (o[0] == 169 && o[1] == 254)              // 169.254.0.0/16
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            (seg[0] & 0xfe00) == 0xfc00  // fc00::/7 ULA
            || (seg[0] & 0xffc0) == 0xfe80  // fe80::/10 link-local
        }
    }
}

/// Extracts the real client IP from forwarded headers.
/// Tries `X-Real-IP` first, then scans `X-Forwarded-For` right-to-left
/// for the rightmost non-private IP. Falls back to `fallback`.
fn real_ip_from_headers(headers: &axum::http::HeaderMap, fallback: IpAddr) -> IpAddr {
    if let Some(ip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let entries: Vec<&str> = xff.split(',').collect();
        for part in entries.iter().rev() {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                if !is_private_ip(ip) {
                    return ip;
                }
            }
        }
    }

    fallback
}

/// Axum middleware (`from_fn_with_state`) that resolves the real client IP.
///
/// - Trusted peer → reads `X-Real-IP` / `X-Forwarded-For` headers.
/// - Untrusted peer or empty CIDR list → uses the direct connection IP.
/// - Sets [`ClientIp`] in request extensions for downstream use.
pub async fn proxy_fn(
    State(cidrs): State<Arc<Vec<ParsedCidr>>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer_ip = connect_info
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let client_ip = if !cidrs.is_empty() && cidrs.iter().any(|c| c.contains(peer_ip)) {
        real_ip_from_headers(request.headers(), peer_ip)
    } else {
        peer_ip
    };

    tracing::debug!(client_ip = %client_ip, peer_ip = %peer_ip, "request");
    request.extensions_mut().insert(ClientIp(client_ip));
    next.run(request).await
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn make_xff(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(ip).unwrap());
        h
    }

    fn make_xri(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_str(ip).unwrap());
        h
    }

    // ── CIDR matching ──────────────────────────────────────────────────────

    #[test]
    fn cidr_v4_exact() {
        let c = ParsedCidr::parse("127.0.0.1").unwrap();
        assert!(c.contains("127.0.0.1".parse().unwrap()));
        assert!(!c.contains("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn cidr_v4_range() {
        let c = ParsedCidr::parse("192.168.0.0/16").unwrap();
        assert!(c.contains("192.168.1.5".parse().unwrap()));
        assert!(!c.contains("192.169.0.1".parse().unwrap()));
    }

    #[test]
    fn cidr_v6_exact() {
        let c = ParsedCidr::parse("::1").unwrap();
        assert!(c.contains("::1".parse().unwrap()));
        assert!(!c.contains("::2".parse().unwrap()));
    }

    // ── Spec test 1: trusted proxy → client_ip from X-Forwarded-For ───────

    #[test]
    fn trusted_proxy_xff_gives_real_ip() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let cidrs = vec![ParsedCidr::parse("127.0.0.1").unwrap()];
        let headers = make_xff("1.2.3.4");

        let client_ip = if !cidrs.is_empty() && cidrs.iter().any(|c| c.contains(peer)) {
            real_ip_from_headers(&headers, peer)
        } else {
            peer
        };

        assert_eq!(client_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_proxy_xri_gives_real_ip() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let cidrs = vec![ParsedCidr::parse("127.0.0.1").unwrap()];
        let headers = make_xri("5.6.7.8");

        let client_ip = if !cidrs.is_empty() && cidrs.iter().any(|c| c.contains(peer)) {
            real_ip_from_headers(&headers, peer)
        } else {
            peer
        };

        assert_eq!(client_ip, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    // ── Spec test 2: non-trusted peer → headers ignored ───────────────────

    #[test]
    fn non_trusted_proxy_xff_ignored() {
        let peer: IpAddr = "5.6.7.8".parse().unwrap();
        let cidrs = vec![ParsedCidr::parse("127.0.0.1").unwrap()];
        let headers = make_xff("1.2.3.4");

        let client_ip = if !cidrs.is_empty() && cidrs.iter().any(|c| c.contains(peer)) {
            real_ip_from_headers(&headers, peer)
        } else {
            peer
        };

        assert_eq!(client_ip, peer);
    }

    // ── Spec test 3: empty trusted_proxies → headers never evaluated ───────

    #[test]
    fn empty_trusted_proxies_uses_peer_ip() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let cidrs: Vec<ParsedCidr> = vec![];
        let headers = make_xff("1.2.3.4");

        let client_ip = if !cidrs.is_empty() && cidrs.iter().any(|c| c.contains(peer)) {
            real_ip_from_headers(&headers, peer)
        } else {
            peer
        };

        assert_eq!(client_ip, peer);
    }

    // ── Spec general/007 test 4: error-mapping ──────────────────────────────

    #[test]
    fn api_error_maps_400_prefix_to_bad_request() {
        let err = ApiError::from(anyhow::anyhow!("400 Bad Request: key must be valid UTF-8"));
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }
}
