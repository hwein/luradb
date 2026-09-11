//! Process topology (spec perf/018a A1): the storage engines run on one
//! engine thread (tokio-uring), HTTP/TLS termination and the frontend layers
//! on a multi-threaded frontend runtime, with the engine bridge in between.

mod engine;

use crate::{
    api::{self, middleware::ParsedCidr, ApiDoc},
    auth::{middleware::docs_auth_layer, AuthCache},
    bridge::{self, EngineDispatch, Job, ShipService},
    config::LuraConfig,
    core::coop,
    cors, tls, uds,
};
use axum::{
    extract::connect_info::ConnectInfo, http::Extensions, middleware::from_fn_with_state, response::Json,
    routing::get, Router,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::{json, Value};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tower::ServiceExt;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Handed from the engine thread to the frontend once the engines are up (A1.3).
struct Ready {
    dispatch: mpsc::Sender<Job>,
    auth_cache: Arc<AuthCache>,
    trusted_cidrs: Arc<Vec<ParsedCidr>>,
}

/// Entry point that starts the whole topology in-process.
pub struct Server;

/// A running server; [`ServerHandle::shutdown`] stops it in the A6 order.
pub struct ServerHandle {
    /// Bound address of the plain HTTP listener; `None` when it is disabled.
    pub http_addr: Option<SocketAddr>,
    listeners: Listeners,
    frontend: Runtime,
    engine: std::thread::JoinHandle<()>,
}

impl Server {
    /// Boots the engine thread and, only once it reports ready, the listeners
    /// on the frontend runtime. A failed step stops what already runs.
    pub fn start(config: Arc<LuraConfig>, config_path: &Path) -> anyhow::Result<ServerHandle> {
        let cores = coop::available_cores();
        let workers = frontend_workers(config.multicore.frontend_workers, cores);
        let frontend = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .max_blocking_threads(coop::permit_count(config.multicore.cpu_offload_threads, cores))
            .thread_name("luradb-frontend")
            .enable_all()
            .build()?;
        tracing::info!(
            "Frontend runtime: {workers} workers; engine thread: 1; bridge capacity: {}",
            config.multicore.engine_queue_capacity
        );

        let (engine, ready) = spawn_engine(Arc::clone(&config), config_path.to_path_buf())?;
        match frontend.block_on(run_frontend(ready, &config)) {
            Ok(listeners) => Ok(ServerHandle { http_addr: listeners.http_addr, listeners, frontend, engine }),
            Err(e) => {
                // The failed start dropped the bridge sender: the engine shuts down.
                drop(frontend);
                let _ = engine.join();
                Err(e)
            }
        }
    }
}

impl ServerHandle {
    /// Serves until `signal` resolves, then shuts down.
    pub fn run_until(self, signal: impl Future<Output = ()>) -> anyhow::Result<()> {
        self.frontend.block_on(signal);
        self.shutdown()
    }

    /// Stops and drains the listeners, ends the frontend runtime — which drops
    /// the last bridge sender and so ends the engine loop — and joins the
    /// engine thread once it has shut the engines down (A6). Must not be
    /// called from within an async context.
    pub fn shutdown(self) -> anyhow::Result<()> {
        let ServerHandle { listeners, frontend, engine, .. } = self;
        frontend.block_on(listeners.stop());
        drop(frontend);
        engine.join().map_err(|_| anyhow::anyhow!("the engine thread panicked"))
    }
}

/// Worker threads of the frontend runtime: `configured`, or with `0` an
/// eighth of the cores, 1 to 4 (spec perf/018a A5).
fn frontend_workers(configured: usize, cores: usize) -> usize {
    if configured > 0 {
        configured
    } else {
        (cores / 8).clamp(1, 4)
    }
}

/// Starts the engine thread and waits until it reports ready (A1.1, A1.3).
fn spawn_engine(
    config: Arc<LuraConfig>,
    config_path: PathBuf,
) -> anyhow::Result<(std::thread::JoinHandle<()>, Ready)> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("luradb-engine".to_string())
        .spawn(move || tokio_uring::start(run_engine(config, config_path, ready_tx)))?;
    match ready_rx.recv() {
        Ok(Ok(ready)) => Ok((thread, ready)),
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        Err(_) => {
            let _ = thread.join();
            Err(anyhow::anyhow!("the engine thread stopped during startup"))
        }
    }
}

/// Body of the engine thread: bootstrap, report, serve the bridge until the
/// frontend lets go of it, then shut the engines down.
async fn run_engine(
    config: Arc<LuraConfig>,
    config_path: PathBuf,
    ready_tx: std::sync::mpsc::Sender<anyhow::Result<Ready>>,
) {
    // Before the bootstrap: a capacity the channel rejects must fail while
    // nothing runs yet — afterwards it would leave SHM segments, background
    // tasks and the storage thread behind.
    let (dispatch, jobs) = mpsc::channel(config.multicore.engine_queue_capacity);
    let engine = match engine::bootstrap_engine(&config, &config_path).await {
        Ok(engine) => engine,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let ready = Ready {
        dispatch,
        auth_cache: Arc::clone(&engine.auth_cache),
        trusted_cidrs: Arc::clone(&engine.trusted_cidrs),
    };
    if ready_tx.send(Ok(ready)).is_ok() {
        bridge::serve_engine(jobs, engine.router).await;
    }
    engine::graceful_shutdown(engine.teardown).await;
}

async fn hello_handler(message: String) -> Json<Value> {
    Json(json!({ "message": message }))
}

/// The frontend router (spec perf/018a A2): Swagger and the hello route are
/// answered here; everything else passes the frontend layers into the engine
/// bridge. The frontend knows no single API route.
fn build_router(
    cfg: &LuraConfig,
    auth_cache: Arc<AuthCache>,
    trusted_cidrs: Arc<Vec<ParsedCidr>>,
    dispatch: EngineDispatch,
) -> Router {
    let mut app = Router::new();

    if cfg.server.swagger_enabled {
        // Swagger UI is registered here, not inside api::create_router, so it
        // needs its own auth layer (spec general/014) — the general/009
        // router-contract gate would otherwise trip on docs routes with no
        // contract entry. `docs_auth_layer` wraps this whole sub-router, so
        // every path SwaggerUi registers under `swagger_url` (index, redirect,
        // static assets) is covered without listing them individually.
        let mut docs_router = Router::new().merge(
            SwaggerUi::new(cfg.server.swagger_url.clone())
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        );
        if cfg.auth.enabled {
            docs_router = docs_router.layer(from_fn_with_state(Arc::clone(&auth_cache), docs_auth_layer));
        }
        app = app.merge(docs_router);
    }

    if cfg.server.hello_enabled {
        let msg = cfg.server.hello_message.clone();
        app = app.route("/", get(move || hello_handler(msg)));
    }

    let engine = Router::new().fallback_service(ShipService::new(dispatch));
    let auth = cfg.auth.enabled.then_some(auth_cache);
    app = app.fallback_service(api::frontend_layers(engine, auth, trusted_cidrs));

    // Outermost layer (spec general/020 §Platzierung): runs before auth on
    // every request, including Swagger/hello above, which live outside
    // create_router and would otherwise miss it.
    if let Some(cors) = cors::build_layer(&cfg.cors) {
        if cfg.cors.allowed_origins.iter().any(|o| o == "*") {
            tracing::warn!(
                "cors.allowed_origins is \"*\" — Access-Control-Allow-Origin is sent on every response, including requests without an Origin header. A valid API key is still required for access."
            );
        }
        app = app.layer(cors);
    }

    app
}

/// Connection builder of every listener. HTTP/2 serves one stream at a time
/// per connection, so requests on a connection keep their order (A4);
/// clients get parallelism from several connections.
fn connection_builder() -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http2().max_concurrent_streams(1);
    builder
}

/// Serves one accepted connection of any listener until it ends, or until
/// `shutdown` flips — then hyper closes it gracefully (GOAWAY on h2,
/// `Connection: close` on HTTP/1.1) and an in-flight request still finishes,
/// instead of the drain having to wait out its cap (A6). `extend` adds the
/// listener's connection info to every request.
pub(crate) async fn serve_connection<I, F>(
    io: I,
    router: Router,
    extend: F,
    mut shutdown: watch::Receiver<bool>,
    tag: &str,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    F: Fn(&mut Extensions) + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        extend(req.extensions_mut());
        router.clone().oneshot(req)
    });
    let builder = connection_builder();
    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    let mut closing = false;
    let result = loop {
        tokio::select! {
            result = conn.as_mut() => break result,
            // Disabled afterwards: the flip is only reported once, and a
            // dropped sender would otherwise resolve in a busy loop.
            _ = shutdown.changed(), if !closing => {
                closing = true;
                conn.as_mut().graceful_shutdown();
            }
        }
    };
    if let Err(e) = result {
        tracing::debug!("[{tag}] connection error: {e}");
    }
}

/// The running accept loops, stopped together by [`Listeners::stop`].
struct Listeners {
    http_addr: Option<SocketAddr>,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    uds_path: Option<String>,
}

impl Listeners {
    /// Signals every accept loop at once, so their 5 s drain caps overlap
    /// instead of stacking, and waits for all of them.
    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        if let Some(path) = &self.uds_path {
            uds::remove_socket_file(path);
        }
    }
}

/// Binds every enabled listener, then serves the frontend router on them
/// (A1.2, A1.4). Nothing is spawned before all binds succeeded.
async fn run_frontend(ready: Ready, config: &LuraConfig) -> anyhow::Result<Listeners> {
    let app = build_router(config, ready.auth_cache, ready.trusted_cidrs, EngineDispatch::Engine(ready.dispatch));
    let bind: IpAddr = config
        .server
        .bind_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid bind_address '{}': {}", config.server.bind_address, e))?;

    let uds_listener = match &config.server.unix_socket_path {
        Some(path) => Some((uds::prepare_uds_socket(path)?, path)),
        None => None,
    };
    let tls_listener = if config.server.tls_enabled {
        let acceptor = tls::load_tls_acceptor(&config.server.tls_cert_path, &config.server.tls_key_path)?;
        let listener = TcpListener::bind(SocketAddr::from((bind, config.server.tls_port))).await?;
        Some((listener, acceptor))
    } else {
        None
    };
    let http_listener = if config.server.http_enabled {
        Some(TcpListener::bind(SocketAddr::from((bind, config.server.port))).await?)
    } else {
        tracing::info!("HTTP listener disabled by config (server.http_enabled = false).");
        None
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = Vec::new();
    if let Some((listener, path)) = uds_listener {
        tracing::info!("UDS listener active on {}", path);
        let trusted_uids = Arc::new(config.auth.trusted_uids.clone());
        tasks.push(tokio::spawn(uds::serve_uds(
            listener,
            app.clone(),
            trusted_uids,
            config.auth.enabled,
            shutdown_rx.clone(),
        )));
    }
    if let Some((listener, acceptor)) = tls_listener {
        tracing::info!("Listening on https://{}", listener.local_addr()?);
        tasks.push(tokio::spawn(tls::serve_tls(listener, acceptor, app.clone(), shutdown_rx.clone())));
    }
    let mut http_addr = None;
    if let Some(listener) = http_listener {
        let addr = listener.local_addr()?;
        tracing::info!("Listening on http://{}", addr);
        http_addr = Some(addr);
        tasks.push(tokio::spawn(serve_http(listener, app, shutdown_rx)));
    }

    Ok(Listeners { http_addr, shutdown_tx, tasks, uds_path: config.server.unix_socket_path.clone() })
}

/// Plain HTTP accept loop, same pattern as `tls::serve_tls` minus the
/// handshake: serves until `shutdown` flips, then drains in-flight
/// connections (5 s cap) before returning.
async fn serve_http(listener: TcpListener, router: Router, mut shutdown: watch::Receiver<bool>) {
    let mut connections = JoinSet::new();
    let connection_shutdown = shutdown.clone();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            // Reap finished tasks so the set does not grow with connection count.
            Some(_) = connections.join_next() => {}
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("[http] accept error: {e}");
                        // Backoff so fd exhaustion (EMFILE) cannot busy-loop.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Only a streamed body can still reach hyper after its response
                // head, so head and body may leave as separate writes; Nagle
                // would hold back the second until the client's (delayed) ACK.
                let _ = stream.set_nodelay(true);
                connections.spawn(serve_connection(
                    TokioIo::new(stream),
                    router.clone(),
                    // Same ConnectInfo<SocketAddr> as the TLS listener, for the
                    // trusted-proxy middleware.
                    move |ext: &mut Extensions| {
                        ext.insert(ConnectInfo(peer_addr));
                    },
                    connection_shutdown.clone(),
                    "http",
                ));
            }
        }
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(5), drain).await.is_err() {
        tracing::warn!("[http] connection drain timed out, aborting remaining tasks");
        connections.shutdown().await;
    }
    tracing::info!("[http] listener stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn frontend_workers_auto_and_explicit() {
        assert_eq!(frontend_workers(0, 64), 4);
        assert_eq!(frontend_workers(0, 32), 4);
        assert_eq!(frontend_workers(0, 16), 2);
        assert_eq!(frontend_workers(0, 8), 1);
        assert_eq!(frontend_workers(0, 1), 1);
        assert_eq!(frontend_workers(3, 32), 3);
        assert_eq!(frontend_workers(6, 2), 6);
    }

    async fn make_test_state(auth_enabled: bool) -> (api::AppState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(dir.path()));
        let engine = Arc::new(
            crate::engines::lsm::engine::LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let auth_cache = Arc::new(AuthCache::new(Arc::clone(&engine)));
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            crate::engines::lsm::DomainRegistry::recover(
                engine,
                crate::engines::lsm::domain::DomainConfig::default(),
                Arc::clone(&metrics),
            )
            .await
            .unwrap(),
        );
        let state = api::AppState {
            registry,
            auth_cache,
            auth_enabled,
            metrics,
            json_engine: None,
            rel_engine: None,
            shm_manager: None,
            backup_manager: None,
            log_access: None,
            event_bus: Arc::new(crate::core::events::GlobalEventBus::new(256, 1024)),
            config: Arc::new(LuraConfig::default()),
            config_path: "test.toml".to_string(),
            config_file_loaded: false,
        };
        (state, dir)
    }

    // Test 10 (spec general/020 §Tests): the CorsLayer must sit outside both
    // the frontend auth_layer AND the Swagger sub-router's docs_auth_layer.
    // Regression-critical: if the layer moved inward (e.g. into
    // create_router), a request to the Swagger docs route would never reach
    // it — docs_auth_layer would 401 first, with no CORS header.
    #[tokio::test]
    async fn cors_layer_wraps_swagger_and_survives_401() {
        let mut cfg = LuraConfig::default();
        cfg.server.swagger_enabled = true;
        cfg.auth.enabled = true;
        cfg.cors.enabled = true;
        cfg.cors.allowed_origins = vec!["https://example.com".to_string()];

        let (state, _dir) = make_test_state(true).await;
        let auth_cache = Arc::clone(&state.auth_cache);
        let app = build_router(&cfg, auth_cache, Arc::new(vec![]), EngineDispatch::Inline(api::create_router(state)));

        // (a) Preflight without Authorization -> 200 with the CORS header,
        // even though this path sits behind docs_auth_layer.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api-docs/openapi.json")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );

        // (b) GET with an allowed Origin but no Authorization -> 401 from
        // docs_auth_layer, but still carrying the CORS header — proof the
        // layer sits outside that auth check, not inside it.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api-docs/openapi.json")
                    .header("origin", "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }

    // A2/A3: auth runs on the frontend, in front of the bridge — the engine
    // router behind it carries no auth layer of its own, so a 401 here can
    // only come from the frontend router.
    #[tokio::test]
    async fn frontend_router_enforces_auth_in_front_of_the_engine() {
        let mut cfg = LuraConfig::default();
        cfg.auth.enabled = true;
        let (state, _dir) = make_test_state(true).await;
        let auth_cache = Arc::clone(&state.auth_cache);
        let admin_key = "lura_test_frontend_admin_key";
        auth_cache
            .upsert_user(crate::auth::UserRecord {
                name: "admin".to_string(),
                api_key_hash: crate::auth::hash_api_key(admin_key),
                role: crate::auth::UserRole::Admin,
                created_at: 0,
            })
            .await
            .unwrap();
        let app = build_router(
            &cfg,
            Arc::clone(&auth_cache),
            Arc::new(vec![]),
            EngineDispatch::Inline(api::create_router(state)),
        );

        let status = |uri: &str, key: Option<&str>| {
            let mut req = Request::builder().uri(uri);
            if let Some(key) = key {
                req = req.header("authorization", format!("Bearer {key}"));
            }
            let app = app.clone();
            let req = req.body(Body::empty()).unwrap();
            async move { app.oneshot(req).await.unwrap().status() }
        };
        assert_eq!(status("/store-api/config", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(status("/store-api/config", Some(admin_key)).await, StatusCode::OK);
        assert_eq!(status("/health", None).await, StatusCode::OK);
    }

    // ── In-process E2E (Server::start) ───────────────────────────────────────

    /// Loopback dev mode (auth off), HTTP on an ephemeral port, backups on,
    /// JSON and relational engines off, every data path under `dir`.
    fn test_config(dir: &Path) -> LuraConfig {
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let mut cfg = LuraConfig::default();
        cfg.server.port = 0;
        cfg.storage.db_path = path("luradb.db");
        cfg.storage.wal_path = path("luradb.wal");
        cfg.storage.vlog_path = path("luradb.vlog");
        cfg.storage.sstable_dir = path("sstables");
        cfg.json.enabled = false;
        cfg.rel.enabled = false;
        cfg.backup.enabled = true;
        cfg.backup.dir = path("backups");
        cfg
    }

    /// Starts a server, runs `client` against its HTTP address on a separate
    /// client runtime, then shuts the server down through its handle.
    fn with_server<F, Fut>(client: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: Future<Output = ()>,
    {
        let dir = tempfile::TempDir::new().unwrap();
        let server = Server::start(Arc::new(test_config(dir.path())), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        tokio::runtime::Runtime::new().unwrap().block_on(client(addr));
        // Returns only after the frontend runtime is gone and the engine
        // thread has run its graceful shutdown and exited.
        server.shutdown().unwrap();
    }

    fn get(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
    }

    fn with_body(method: &str, path: &str, body: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Splits the first HTTP/1.1 response off `raw`: status, body (chunked or
    /// Content-Length framing, else the rest) and the bytes after it.
    fn next_response(raw: &[u8]) -> (u16, Vec<u8>, &[u8]) {
        let head_end = find(raw, b"\r\n\r\n").expect("response head") + 4;
        let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
        let status = head[9..12].parse().unwrap();
        let mut rest = &raw[head_end..];
        if head.contains("transfer-encoding: chunked") {
            let mut body = Vec::new();
            loop {
                let line_end = find(rest, b"\r\n").expect("chunk size line");
                let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16).unwrap();
                rest = &rest[line_end + 2..];
                if size == 0 {
                    return (status, body, &rest[2..]);
                }
                body.extend_from_slice(&rest[..size]);
                rest = &rest[size + 2..];
            }
        }
        let len = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map_or(rest.len(), |value| value.trim().parse().unwrap());
        (status, rest[..len].to_vec(), &rest[len..])
    }

    /// The lower-cased head of the answer to one request on a fresh connection.
    async fn response_head(addr: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let head_end = find(&buf, b"\r\n\r\n").expect("response head") + 4;
        String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase()
    }

    /// One request (with `Connection: close`) on a fresh connection.
    async fn request(addr: SocketAddr, raw: &str) -> (u16, Vec<u8>) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let (status, body, _) = next_response(&buf);
        (status, body)
    }

    /// Reads from `stream` into `seen` until `needle` shows up in it.
    async fn read_until(stream: &mut TcpStream, seen: &mut Vec<u8>, needle: &[u8]) {
        let mut buf = [0u8; 4096];
        while find(seen, needle).is_none() {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before {:?}: {}", String::from_utf8_lossy(needle), String::from_utf8_lossy(seen));
            seen.extend_from_slice(&buf[..n]);
        }
    }

    // Test 5: the full topology in-process — plain requests, a streamed
    // response (SSE) and a streamed request body cross the bridge; the
    // handle's shutdown ends both runtimes.
    #[test]
    fn server_serves_and_streams_both_ways_then_shuts_down() {
        with_server(|addr| async move {
            let (status, _) = request(addr, &get("/health")).await;
            assert_eq!(status, 200);

            let (status, _) = request(addr, &with_body("PUT", "/store-api/kv/default/keys/e2e", "clé ✓")).await;
            assert_eq!(status, 200);
            let (status, value) = request(addr, &get("/store-api/kv/default/keys/e2e")).await;
            assert_eq!((status, value.as_slice()), (200, "clé ✓".as_bytes()));

            // Response relay: the SSE head arrives once the handler has
            // subscribed, so the event below cannot be missed.
            let mut events = TcpStream::connect(addr).await.unwrap();
            events.write_all(b"GET /store-api/events HTTP/1.1\r\nHost: test\r\n\r\n").await.unwrap();
            let mut seen = Vec::new();
            read_until(&mut events, &mut seen, b"\r\n\r\n").await;
            assert!(seen.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&seen));
            let (status, _) = request(addr, &with_body("POST", "/store-api/domains", r#"{"name":"e2e"}"#)).await;
            assert_eq!(status, 201);
            read_until(&mut events, &mut seen, b"\"domain\":\"e2e\"").await;
            assert!(find(&seen, b"event: domain_created").is_some(), "{}", String::from_utf8_lossy(&seen));
            drop(events);

            // Request relay: an archive the server made itself, uploaded back
            // with its body split over two writes.
            let (status, body) = request(addr, &with_body("POST", "/store-api/backups", r#"{"scope":"all"}"#)).await;
            assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
            let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
            let mut finished = false;
            for _ in 0..200 {
                let (status, body) = request(addr, &get(&format!("/store-api/backups/{id}"))).await;
                assert_eq!(status, 200);
                if serde_json::from_slice::<Value>(&body).unwrap()["state"] != json!("running") {
                    finished = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(finished, "backup '{id}' did not finish within the poll budget");
            let (status, archive) = request(addr, &get(&format!("/store-api/backups/{id}/download"))).await;
            assert_eq!(status, 200);

            let (first, second) = archive.split_at(archive.len() / 2);
            let mut upload = TcpStream::connect(addr).await.unwrap();
            let head = format!(
                "POST /store-api/backups/upload HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                archive.len()
            );
            upload.write_all(&[head.as_bytes(), first].concat()).await.unwrap();
            upload.write_all(second).await.unwrap();
            let mut raw = Vec::new();
            upload.read_to_end(&mut raw).await.unwrap();
            let (status, body, _) = next_response(&raw);
            assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
        });
    }

    // A complete answer leaves the frontend framed by its length, the way it
    // did before the bridge: Content-Length instead of chunked, none at all
    // where the status forbids a body, and HEAD keeps the length of the body
    // it does not send.
    #[test]
    fn complete_answers_go_out_with_their_length() {
        with_server(|addr| async move {
            let key = "/store-api/kv/default/keys/framed";
            let (status, _) = request(addr, &with_body("PUT", key, "framed-value")).await;
            assert_eq!(status, 200);

            let head = response_head(addr, &get(key)).await;
            assert!(head.contains("content-length: 12"), "{head}");
            assert!(!head.contains("transfer-encoding"), "{head}");

            let raw = format!("HEAD {key} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
            let head = response_head(addr, &raw).await;
            assert!(head.contains("content-length: 12"), "{head}");

            let (status, _) = request(addr, &with_body("PATCH", &format!("{key}/null"), "")).await;
            assert_eq!(status, 200);
            let head = response_head(addr, &get(key)).await;
            assert!(head.starts_with("http/1.1 204"), "{head}");
            assert!(!head.contains("content-length"), "{head}");
        });
    }

    // A1.5: a bridge capacity the channel cannot take down must fail the
    // in-process start before the engines, SHM and background tasks are up.
    #[test]
    fn unusable_bridge_capacity_fails_before_anything_boots() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.engine_queue_capacity = 0;
        let db_path = PathBuf::from(cfg.storage.db_path.clone());
        assert!(Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).is_err());
        assert!(!db_path.exists(), "the engine booted before the bridge channel existed");
    }

    // A live keep-alive connection learns about the shutdown: hyper closes it
    // instead of the drain having to wait out its 5 s cap.
    #[test]
    fn shutdown_closes_idle_keep_alive_connections() {
        let dir = tempfile::TempDir::new().unwrap();
        let server = Server::start(Arc::new(test_config(dir.path())), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let client = tokio::runtime::Runtime::new().unwrap();

        // One answered request, then the connection stays open and idle.
        let mut stream = client.block_on(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n").await.unwrap();
            let mut seen = Vec::new();
            read_until(&mut stream, &mut seen, b"\r\n\r\n").await;
            assert!(seen.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&seen));
            stream
        });

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || done_tx.send(server.shutdown().is_ok()));
        // Upper bound against hanging, well below the 5 s drain cap.
        assert_eq!(
            done_rx.recv_timeout(Duration::from_secs(3)),
            Ok(true),
            "shutdown waited out the drain cap instead of closing the idle connection"
        );

        // Closed by the server, not just left dangling.
        client.block_on(async move {
            let mut rest = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
                .await
                .expect("connection stayed open after shutdown")
                .unwrap();
        });
    }

    // Test 6: a PUT and a GET of the same key, pipelined in one write on one
    // HTTP/1.1 connection, are processed in arrival order.
    #[test]
    fn pipelined_http1_requests_keep_their_order() {
        with_server(|addr| async move {
            let put = "PUT /store-api/kv/default/keys/order HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nfirst";
            let get = get("/store-api/kv/default/keys/order");
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(format!("{put}{get}").as_bytes()).await.unwrap();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await.unwrap();
            let (put_status, _, rest) = next_response(&raw);
            let (get_status, value, _) = next_response(rest);
            assert_eq!((put_status, get_status), (200, 200));
            assert_eq!(value, b"first");
        });
    }

    /// Opens a raw h2c connection and reads SETTINGS_MAX_CONCURRENT_STREAMS
    /// from the server's first SETTINGS frame.
    async fn server_max_concurrent_streams(addr: SocketAddr) -> Option<u32> {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // Client preface plus an empty SETTINGS frame.
        stream.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0").await.unwrap();
        loop {
            let mut header = [0u8; 9];
            stream.read_exact(&mut header).await.unwrap();
            let mut payload = vec![0u8; u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize];
            stream.read_exact(&mut payload).await.unwrap();
            let (frame_type, ack) = (header[3], header[4] & 1 == 1);
            if frame_type == 4 && !ack {
                return payload
                    .chunks_exact(6)
                    .find(|setting| setting[..2] == [0, 3])
                    .map(|setting| u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]));
            }
        }
    }

    fn h2_request(addr: SocketAddr, method: &str, path: &str, body: &'static str) -> Request<Body> {
        Request::builder().method(method).uri(format!("http://{addr}{path}")).body(Body::from(body)).unwrap()
    }

    // Test 6b: over h2c the server announces MAX_CONCURRENT_STREAMS = 1, so a
    // PUT and a GET of the same key, opened as two streams without waiting
    // for the first answer, run one after the other.
    #[test]
    fn http2_streams_on_one_connection_keep_their_order() {
        with_server(|addr| async move {
            assert_eq!(server_max_concurrent_streams(addr).await, Some(1));

            let tcp = TcpStream::connect(addr).await.unwrap();
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp)).await.unwrap();
            tokio::spawn(conn);
            // A first exchange puts the server's SETTINGS, stream limit
            // included, into effect on the client before the two streams.
            let resp = sender.send_request(h2_request(addr, "GET", "/health", "")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            let put = sender.send_request(h2_request(addr, "PUT", "/store-api/kv/default/keys/h2", "second"));
            let get = sender.send_request(h2_request(addr, "GET", "/store-api/kv/default/keys/h2", ""));
            let (put, get) = tokio::join!(put, get);
            assert_eq!(put.unwrap().status(), StatusCode::OK);
            let get = get.unwrap();
            assert_eq!(get.status(), StatusCode::OK);
            let value = axum::body::to_bytes(Body::new(get.into_body()), usize::MAX).await.unwrap();
            assert_eq!(value, "second");
        });
    }
}
