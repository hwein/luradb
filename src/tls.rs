//! Native TLS listener (spec general/011).
//!
//! Serves the same Axum router as the plain TCP listener, over TLS on a
//! separate port. Accept-loop pattern mirrors `src/uds.rs`: `TcpListener::
//! accept` -> `TlsAcceptor::accept` (handshake timeout) -> `TokioIo` ->
//! `auto::Builder::serve_connection_with_upgrades`.

use axum::extract::connect_info::ConnectInfo;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// TLS handshake must complete within this long or the connection is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Loads the certificate chain and private key from PEM files and builds a
/// `TlsAcceptor` offering `h2` and `http/1.1` via ALPN. Both files must be
/// readable and parsable — the exact failure is reported so an operator can
/// fix the config without guessing.
pub fn load_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    // Idempotent: rustls requires a process-wide default crypto provider
    // before `ServerConfig::builder()` can be called. A rejected second
    // install (e.g. repeated calls across tests in one process) just means
    // one is already active — safe to ignore.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("cannot open server.tls_cert_path '{cert_path}': {e}"))?;
    let cert_chain: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("cannot parse server.tls_cert_path '{cert_path}': {e}"))?;
    anyhow::ensure!(
        !cert_chain.is_empty(),
        "server.tls_cert_path '{cert_path}' contains no certificate"
    );

    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("cannot open server.tls_key_path '{key_path}': {e}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| anyhow::anyhow!("cannot parse server.tls_key_path '{key_path}': {e}"))?
        .ok_or_else(|| anyhow::anyhow!("server.tls_key_path '{key_path}' contains no private key"))?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("invalid TLS certificate/key pair: {e}"))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Accept loop serving the router over TLS until `shutdown` flips, then
/// drains in-flight connections (5s cap) before returning — mirrors
/// `uds::serve_uds`.
pub async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            // Reap finished tasks so the set does not grow with connection count.
            Some(_) = connections.join_next() => {}
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("[tls] accept error: {e}");
                        // Backoff so fd exhaustion (EMFILE) cannot busy-loop.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let router = router.clone();
                connections.spawn(async move {
                    let tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            tracing::debug!("[tls] handshake error from {peer_addr}: {e}");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!("[tls] handshake timed out from {peer_addr}");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls_stream);
                    // ConnectInfo<SocketAddr> — same type the plain HTTP listener
                    // injects — so rate-limiter/trusted-proxy middleware see the
                    // real peer IP over HTTPS too.
                    let service =
                        hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                            req.extensions_mut().insert(ConnectInfo(peer_addr));
                            router.clone().oneshot(req)
                        });
                    if let Err(e) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        tracing::debug!("[tls] connection error: {e}");
                    }
                });
            }
        }
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(5), drain).await.is_err() {
        tracing::warn!("[tls] connection drain timed out, aborting remaining tasks");
        connections.shutdown().await;
    }
    tracing::info!("[tls] listener stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    fn fixture_path(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    fn fixture_cert_path() -> String {
        fixture_path("server.crt")
    }

    fn fixture_key_path() -> String {
        fixture_path("server.key")
    }

    #[test]
    fn test_load_tls_acceptor_valid_fixture() {
        assert!(load_tls_acceptor(&fixture_cert_path(), &fixture_key_path()).is_ok());
    }

    #[test]
    fn test_load_tls_acceptor_missing_cert_file() {
        // TlsAcceptor is not Debug, so unwrap_err() needs a Debug Ok type.
        let err = load_tls_acceptor("/nonexistent-dir-xyz/server.crt", &fixture_key_path())
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("tls_cert_path"), "{err}");
    }

    #[test]
    fn test_load_tls_acceptor_missing_key_file() {
        let err = load_tls_acceptor(&fixture_cert_path(), "/nonexistent-dir-xyz/server.key")
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("tls_key_path"), "{err}");
    }

    #[test]
    fn test_load_tls_acceptor_broken_cert() {
        let dir = tempfile::TempDir::new().unwrap();
        let cert_path = dir.path().join("broken.crt");
        std::fs::write(
            &cert_path,
            b"-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let err = load_tls_acceptor(&cert_path.to_string_lossy(), &fixture_key_path())
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("tls_cert_path"), "{err}");
    }

    #[test]
    fn test_load_tls_acceptor_broken_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("broken.key");
        std::fs::write(
            &key_path,
            b"-----BEGIN PRIVATE KEY-----\nnot-valid-base64!!!\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let err = load_tls_acceptor(&fixture_cert_path(), &key_path.to_string_lossy())
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("tls_key_path"), "{err}");
    }

    // Builds a rustls ClientConfig trusting the fixture's self-signed cert
    // (it is its own root), offering exactly the given ALPN protocols.
    fn test_client_config(alpn_protocols: Vec<Vec<u8>>) -> Arc<ClientConfig> {
        let cert_file = std::fs::File::open(fixture_cert_path()).unwrap();
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<_, _>>()
            .unwrap();
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).unwrap();
        }
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        Arc::new(config)
    }

    // Full accept-loop roundtrip (HTTP/1.1 request/response over TLS), plus
    // proof that ALPN can negotiate both protocol strings the listener
    // offers (spec general/011 Tests: "ALPN-Verhandlung h2 und http/1.1").
    #[tokio::test]
    async fn test_tls_e2e_roundtrip_and_alpn() {
        let acceptor = load_tls_acceptor(&fixture_cert_path(), &fixture_key_path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_tls(listener, acceptor, router, rx));

        // http/1.1: negotiate it explicitly and do a real request/response.
        let connector = tokio_rustls::TlsConnector::from(test_client_config(vec![b"http/1.1".to_vec()]));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        tls.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("pong"), "{response}");

        // h2: a separate connection offering only h2 must negotiate h2 —
        // proves HTTP/2 is genuinely reachable via ALPN, not just preferred.
        let connector = tokio_rustls::TlsConnector::from(test_client_config(vec![b"h2".to_vec()]));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    // HTTP and HTTPS must serve the same router at the same time, each on
    // its own port (spec general/011 Tests: "Parallelbetrieb").
    #[tokio::test]
    async fn test_tls_and_plain_http_serve_concurrently() {
        let acceptor = load_tls_acceptor(&fixture_cert_path(), &fixture_key_path()).unwrap();
        let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_listener.local_addr().unwrap();

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (tx, rx) = watch::channel(false);
        let tls_handle = tokio::spawn(serve_tls(tls_listener, acceptor, router.clone(), rx));
        let http_handle =
            tokio::spawn(async move { axum::serve(http_listener, router.into_make_service()).await });

        let mut tcp = tokio::net::TcpStream::connect(http_addr).await.unwrap();
        tcp.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        tcp.read_to_end(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("pong"));

        // HTTPS, while the plain listener above is still up and was just used.
        let connector = tokio_rustls::TlsConnector::from(test_client_config(vec![b"http/1.1".to_vec()]));
        let tcp = tokio::net::TcpStream::connect(tls_addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("pong"));

        tx.send(true).unwrap();
        tls_handle.await.unwrap();
        http_handle.abort();
    }
}
