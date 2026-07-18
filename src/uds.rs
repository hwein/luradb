//! Unix Domain Socket transport (spec perf/001).
//!
//! Serves the same Axum router as the TCP listener. Local processes skip the
//! kernel TCP/IP stack entirely; peers whose UID is in `auth.trusted_uids`
//! are authenticated via kernel-verified peer credentials (no API key).

use crate::auth::middleware::TrustedPeer;
use axum::extract::connect_info::ConnectInfo;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{unix::UCred, UnixListener};
use tokio::sync::watch;
use tower::ServiceExt;

/// Connection info attached to every UDS request (kernel-verified peer creds).
#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    pub peer_cred: Option<UCred>,
    pub peer_addr: Arc<tokio::net::unix::SocketAddr>,
}

/// Validates the path, removes a stale socket file from a previous run,
/// binds the listener, and applies the configured filesystem mode.
pub fn prepare_uds_socket(path: &str, mode: Option<u32>) -> anyhow::Result<UnixListener> {
    let p = Path::new(path);
    anyhow::ensure!(p.is_absolute(), "unix_socket_path must be absolute: {path}");
    let parent = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("unix_socket_path has no parent directory: {path}"))?;
    anyhow::ensure!(
        parent.is_dir(),
        "parent directory of unix_socket_path does not exist: {}",
        parent.display()
    );
    // Only ever remove a leftover socket — never a foreign file at a misconfigured path.
    if let Ok(meta) = std::fs::symlink_metadata(p) {
        anyhow::ensure!(
            meta.file_type().is_socket(),
            "unix_socket_path exists and is not a socket: {path}"
        );
        std::fs::remove_file(p)?;
    }
    let listener = UnixListener::bind(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode.unwrap_or(0o660)))?;
    Ok(listener)
}

/// Best-effort removal of the socket file on shutdown.
pub fn remove_socket_file(path: &str) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!("[uds] could not remove socket file {path}: {e}");
    }
}

/// Accept loop serving the router over UDS until `shutdown` flips, then
/// drains in-flight connections (5s cap) before returning — callers may
/// only shut the storage engines down after this future completes.
///
/// Trusted-UID detection happens here (not in the auth middleware): the
/// kernel-provided `UCred` is only available at accept time, and a request
/// extension cannot be forged by clients.
pub async fn serve_uds(
    listener: UnixListener,
    router: Router,
    trusted_uids: Arc<Vec<u32>>,
    auth_enabled: bool,
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
                        tracing::warn!("[uds] accept error: {e}");
                        // Backoff so fd exhaustion (EMFILE) cannot busy-loop.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let peer_cred = stream.peer_cred().ok();
                let trusted = auth_enabled
                    && peer_cred.is_some_and(|c| trusted_uids.contains(&c.uid()));
                let connect_info = UdsConnectInfo {
                    peer_cred,
                    peer_addr: Arc::new(peer_addr),
                };
                let router = router.clone();
                connections.spawn(async move {
                    let io = TokioIo::new(stream);
                    let service =
                        hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                            req.extensions_mut().insert(ConnectInfo(connect_info.clone()));
                            if trusted {
                                req.extensions_mut().insert(TrustedPeer);
                            }
                            router.clone().oneshot(req)
                        });
                    if let Err(e) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        tracing::debug!("[uds] connection error: {e}");
                    }
                });
            }
        }
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(5), drain).await.is_err() {
        tracing::warn!("[uds] connection drain timed out, aborting remaining tasks");
        connections.shutdown().await;
    }
    tracing::info!("[uds] listener stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Stale socket file is replaced, mode is applied, requests round-trip,
    // shutdown stops the loop and the file gets removed.
    #[tokio::test]
    async fn test_uds_end_to_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock = dir.path().join("test.sock");
        let path = sock.to_string_lossy().into_owned();
        // Bind+drop leaves a stale socket file behind, like a crashed previous run.
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        assert!(sock.exists());

        let listener = prepare_uds_socket(&path, Some(0o600)).unwrap();
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_uds(listener, router, Arc::new(vec![]), false, rx));

        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("200 OK"), "{response}");
        assert!(response.contains("pong"), "{response}");

        tx.send(true).unwrap();
        handle.await.unwrap();
        remove_socket_file(&path);
        assert!(!sock.exists());
    }

    #[tokio::test]
    async fn test_prepare_rejects_relative_and_missing_parent() {
        assert!(prepare_uds_socket("relative.sock", None).is_err());
        assert!(prepare_uds_socket("/nonexistent-dir-xyz/luradb.sock", None).is_err());
        // A regular file at the path must be rejected, not deleted.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("regular.txt");
        std::fs::write(&file, b"keep me").unwrap();
        assert!(prepare_uds_socket(&file.to_string_lossy(), None).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    }

    // serve_uds must not return before in-flight requests finished (drain on shutdown).
    #[tokio::test]
    async fn test_uds_shutdown_drains_inflight_connection() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock = dir.path().join("drain.sock");
        let listener = prepare_uds_socket(&sock.to_string_lossy(), None).unwrap();

        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_in_handler = done.clone();
        let router = Router::new().route(
            "/slow",
            get(move || {
                let started_tx = started_tx.clone();
                let done = done_in_handler.clone();
                async move {
                    let _ = started_tx.send(());
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    done.store(true, std::sync::atomic::Ordering::SeqCst);
                    "done"
                }
            }),
        );
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(serve_uds(listener, router, Arc::new(vec![]), false, rx));

        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        started_rx.recv().await.unwrap(); // request is now in-flight
        tx.send(true).unwrap();
        handle.await.unwrap();
        assert!(
            done.load(std::sync::atomic::Ordering::SeqCst),
            "serve_uds returned before the in-flight request completed"
        );
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.contains("done"), "{response}");
    }
}
