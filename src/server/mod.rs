//! Process topology: the storage engines run on N data shards, each a thread
//! (compio) with its own engine instances that serves the write requests of
//! its domains; a control-plane thread recovers the engines, runs the control
//! plane and serves the writes without a domain; the other read requests run
//! on a multi-threaded reader pool against the shards' engines; and HTTP/TLS
//! termination, the frontend layers and the point reads on a multi-threaded
//! frontend runtime, with the bridge in between.

mod control;
mod layout;
#[cfg(test)]
mod mcp_oauth_tests;
#[cfg(test)]
mod mcp_tests;
mod migrate;
pub(crate) mod recovery;
mod shard;
#[cfg(test)]
mod write_phases;

pub use migrate::migrate_shards;

use crate::{
    api::{self, middleware::ParsedCidr, ApiDoc},
    auth::{middleware::docs_auth_layer, AuthCache},
    bridge::{self, EngineDispatch, Job, Lane, ShardRouter},
    config::LuraConfig,
    core::{coop, engine_runtime},
    cors, tls, uds,
};
use axum::{
    extract::connect_info::ConnectInfo, http::Extensions, middleware::from_fn_with_state, response::Json,
    routing::get, Router,
};
use control::Ready;
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

/// Entry point that starts the whole topology in-process.
pub struct Server;

/// A running server; [`ServerHandle::shutdown`] stops it in order.
pub struct ServerHandle {
    /// Bound address of the plain HTTP listener; `None` when it is disabled.
    pub http_addr: Option<SocketAddr>,
    /// Bound address of the MCP listener; `None` when it is disabled.
    pub mcp_addr: Option<SocketAddr>,
    listeners: Listeners,
    frontend: Runtime,
    /// Runs the MCP listener when it is enabled.
    mcp: Option<Runtime>,
    reader: Runtime,
    /// Keep the shards' and the control plane's request loops running until
    /// the reader pool is down.
    shards: Vec<Lane>,
    control: mpsc::UnboundedSender<Job>,
    control_thread: std::thread::JoinHandle<()>,
}

/// Requests still running on the reader pool or the MCP runtime get this
/// long to end on shutdown.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

impl Server {
    /// Boots the control-plane thread, which starts the data shards, and,
    /// only once it reports them ready, the reader pool and the listeners on
    /// the frontend runtime. A failed step stops what already runs.
    pub fn start(config: Arc<LuraConfig>, config_path: &Path) -> anyhow::Result<ServerHandle> {
        let cores = coop::available_cores();
        let (workers, auto_shards, _) = core_split(&config, cores);
        let frontend = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .max_blocking_threads(coop::permit_count(config.multicore.cpu_offload_threads, cores))
            .thread_name("luradb-frontend")
            .enable_all()
            .build()?;
        let mcp = if config.mcp.enabled {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(crate::mcp::RUNTIME_WORKERS)
                .thread_name("luradb-mcp")
                .enable_all()
                .build()?;
            Some(runtime)
        } else {
            None
        };

        let (control_thread, ready) =
            spawn_control(Arc::clone(&config), config_path.to_path_buf(), auto_shards, frontend.handle().clone())?;
        let shards = ready.shards.len();
        let readers = reader_threads(config.multicore.reader_threads, cores, workers, shards);
        tracing::info!(
            "{cores} cores: {workers} frontend workers, {shards} data shards, {readers} reader threads; \
             shard queue capacity: {}",
            config.multicore.shard_queue_capacity
        );
        let reader = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(readers)
            .thread_name("luradb-reader")
            .enable_all()
            .build()
        {
            Ok(reader) => reader,
            Err(e) => {
                // No reader pool yet: dropping the only senders shuts the
                // shards and the control plane down.
                drop(ready);
                let _ = control_thread.join();
                return Err(e.into());
            }
        };
        let capacity = config.multicore.reader_queue_capacity;
        tracing::info!("Reader pool queue capacity: {capacity}");
        let (reader_lane, reader_jobs) = Lane::new(capacity);
        let pool = ready
            .states
            .iter()
            .zip(&ready.shards)
            .map(|(state, lane)| (api::create_router(state.clone()), EngineDispatch::Engine(lane.clone())))
            .collect();
        reader.spawn(bridge::serve_reader(reader_jobs, pool));

        let (shard_lanes, control) = (ready.shards.clone(), ready.control.clone());
        let mcp_handle = mcp.as_ref().map(|mcp| mcp.handle().clone());
        match frontend.block_on(run_frontend(ready, reader_lane, &config, mcp_handle)) {
            Ok(listeners) => Ok(ServerHandle {
                http_addr: listeners.http_addr,
                mcp_addr: listeners.mcp_addr,
                listeners,
                frontend,
                mcp,
                reader,
                shards: shard_lanes,
                control,
                control_thread,
            }),
            Err(e) => {
                // The failed start dropped the frontend's senders; the request
                // loops end only once the reader pool is down. The frontend
                // runtime drops after the control-plane thread, whose shards
                // run inside its handle.
                reader.shutdown_timeout(RUNTIME_SHUTDOWN);
                drop((shard_lanes, control));
                let _ = control_thread.join();
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

    /// Stops and drains the listeners, ends the MCP runtime and the reader
    /// pool, and only then drops the pool's senders, the last ones: the
    /// request loops end after the reads, the shards' first. Then joins the
    /// control-plane thread once it has drained the shards and shut the
    /// engines down, and ends the frontend runtime last: the shard and
    /// control-plane threads run inside its handle. Must not be called from
    /// within an async context.
    pub fn shutdown(self) -> anyhow::Result<()> {
        let ServerHandle { listeners, frontend, mcp, reader, shards, control, control_thread, .. } = self;
        frontend.block_on(listeners.stop());
        if let Some(mcp) = mcp {
            mcp.shutdown_timeout(RUNTIME_SHUTDOWN);
        }
        reader.shutdown_timeout(RUNTIME_SHUTDOWN);
        drop(shards);
        drop(control);
        let joined = control_thread.join();
        drop(frontend);
        joined.map_err(|_| anyhow::anyhow!("the control-plane thread panicked"))
    }
}

/// Worker threads of the frontend runtime: `configured`, or with `0` a sixth
/// of the cores, 2 to 4, on hosts with at least 4 cores, otherwise 1.
fn frontend_workers(configured: usize, cores: usize) -> usize {
    if configured > 0 {
        configured
    } else if cores >= 4 {
        (cores / 6).clamp(2, 4)
    } else {
        1
    }
}

/// Data shards: `configured`, or with `0` a quarter of the cores, 1 to 8.
fn data_shards(configured: u16, cores: usize) -> u16 {
    if configured > 0 {
        configured
    } else {
        (cores / 4).clamp(1, 8) as u16
    }
}

/// Worker threads of the reader pool: `configured`, or with `0` the cores
/// left after two, the `shards` and the `frontend` workers, at least 1.
fn reader_threads(configured: usize, cores: usize, frontend: usize, shards: usize) -> usize {
    if configured > 0 {
        configured
    } else {
        cores.saturating_sub(2 + frontend + shards).max(1)
    }
}

/// Frontend workers, data shards and reader threads on `cores` for a new
/// data directory: as configured, `0` resolved automatically.
fn core_split(config: &LuraConfig, cores: usize) -> (usize, u16, usize) {
    let multicore = &config.multicore;
    let frontend = frontend_workers(multicore.frontend_workers, cores);
    let shards = data_shards(multicore.shards, cores);
    (frontend, shards, reader_threads(multicore.reader_threads, cores, frontend, usize::from(shards)))
}

/// Wakes from other threads a shard's or the control plane's runtime has room
/// for (see [`engine_runtime::build`]), one slot per task: as many as the
/// storage hub's request channel and a shard's lane hold waiting jobs, plus
/// compio's default for the background tasks. Running request tasks have no
/// bound of their own.
fn remote_wakes(config: &LuraConfig) -> usize {
    config.storage.wal_queue_capacity
        + config.multicore.shard_queue_capacity
        + engine_runtime::DEFAULT_REMOTE_WAKES
}

/// Starts the control-plane thread and waits until it reports every data
/// shard ready — `auto_shards` of them for a new data directory. The thread
/// enters `frontend`'s handle for its whole life: `coop::offload`,
/// `tokio::fs` and the IPC sockets need a tokio context.
fn spawn_control(
    config: Arc<LuraConfig>,
    config_path: PathBuf,
    auto_shards: u16,
    frontend: tokio::runtime::Handle,
) -> anyhow::Result<(std::thread::JoinHandle<()>, Ready)> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new().name("luradb-control".to_string()).spawn(move || {
        let _frontend = frontend.enter();
        match engine_runtime::build(remote_wakes(&config)) {
            Ok(rt) => {
                engine_runtime::run(&rt, control::run(config, config_path, auto_shards, frontend.clone(), ready_tx))
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
            }
        }
    })?;
    match ready_rx.recv() {
        Ok(Ok(ready)) => Ok((thread, ready)),
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        Err(_) => {
            let _ = thread.join();
            Err(anyhow::anyhow!("the control-plane thread stopped during startup"))
        }
    }
}

async fn hello_handler(message: String) -> Json<Value> {
    Json(json!({ "message": message }))
}

/// The frontend router: Swagger and the hello route are
/// answered here; everything else passes the frontend layers into the bridge.
/// The frontend knows no single API route.
fn build_router(
    cfg: &LuraConfig,
    auth_cache: Arc<AuthCache>,
    trusted_cidrs: Arc<Vec<ParsedCidr>>,
    ship: ShardRouter,
) -> Router {
    let mut app = Router::new();

    if cfg.server.swagger_enabled {
        // Swagger UI is registered here, not inside api::create_router, so it
        // needs its own auth layer — the router-contract gate would
        // otherwise trip on docs routes with no contract entry.
        // `docs_auth_layer` wraps this whole sub-router, so every path
        // SwaggerUi registers under `swagger_url` (index, redirect, static
        // assets) is covered without listing them individually.
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

    let bridge = Router::new().fallback_service(ship);
    let auth = cfg.auth.enabled.then_some(auth_cache);
    app = app.fallback_service(api::frontend_layers(bridge, auth, trusted_cidrs));

    // Outermost layer: runs before auth on
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
/// per connection, so requests on a connection keep their order;
/// clients get parallelism from several connections.
fn connection_builder() -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http2().max_concurrent_streams(1);
    builder
}

/// Serves one accepted connection of any listener until it ends, or until
/// `shutdown` flips — then hyper closes it gracefully (GOAWAY on h2,
/// `Connection: close` on HTTP/1.1) and an in-flight request still finishes,
/// instead of the drain having to wait out its cap. `extend` adds the
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
        #[cfg(test)]
        crate::core::write_trace::arrive(req.extensions_mut());
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
    mcp_addr: Option<SocketAddr>,
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

/// Binds every enabled listener, then serves the frontend router on them;
/// `reader` leads to the reader pool, point reads stay on the frontend
/// unless they would touch the disk. With `mcp`, the MCP listener runs there
/// with a bridge of its own that sends every read to the reader pool: a
/// read waiting for the disk would hold up its one worker. Nothing is
/// spawned before all binds succeeded.
#[allow(clippy::disallowed_methods, reason = "runs on the frontend runtime")]
async fn run_frontend(
    ready: Ready,
    reader: Lane,
    config: &LuraConfig,
    mcp: Option<tokio::runtime::Handle>,
) -> anyhow::Result<Listeners> {
    let Ready { shards, control, states, trusted_cidrs } = ready;
    let auth_cache = Arc::clone(&states[0].auth_cache);
    let resources = states[0].control.resources().clone();
    let mcp_internal = mcp.is_some().then(|| {
        let bridge = ShardRouter::new(shards.iter().cloned().map(EngineDispatch::Engine).collect())
            .with_control(EngineDispatch::Control(control.clone()))
            .with_reader(reader.clone())
            .with_resources(resources.clone());
        let auth = config.auth.enabled.then(|| Arc::clone(&auth_cache));
        let internal = api::frontend_layers(Router::new().fallback_service(bridge), auth, Arc::clone(&trusted_cidrs));
        (internal, Arc::clone(&trusted_cidrs))
    });
    let ship = ShardRouter::new(shards.into_iter().map(EngineDispatch::Engine).collect())
        .with_control(EngineDispatch::Control(control))
        .with_reader(reader)
        .with_inline(states.into_iter().map(api::create_router).collect())
        .with_resources(resources);
    let app = build_router(config, auth_cache, trusted_cidrs, ship);
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
    // Bound here, registered on the MCP runtime once its loop runs there.
    let mcp_listener = match &mcp {
        Some(_) => {
            let listener = std::net::TcpListener::bind(SocketAddr::from((bind, config.mcp.port)))?;
            listener.set_nonblocking(true)?;
            Some(listener)
        }
        None => None,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = Vec::new();
    let mut mcp_addr = None;
    if let (Some(runtime), Some(listener), Some((internal, cidrs))) = (mcp, mcp_listener, mcp_internal) {
        let addr = listener.local_addr()?;
        let acceptor = tls_listener.as_ref().map(|(_, acceptor)| acceptor.clone());
        let scheme = if acceptor.is_some() { "https" } else { "http" };
        tracing::info!("MCP listening on {scheme}://{addr}/mcp");
        mcp_addr = Some(addr);
        let app = {
            let _mcp = runtime.enter();
            crate::mcp::router(config, internal, cidrs, shutdown_rx.clone())
        };
        tasks.push(runtime.spawn(serve_mcp(listener, acceptor, app, shutdown_rx.clone())));
    }
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

    Ok(Listeners { http_addr, mcp_addr, shutdown_tx, tasks, uds_path: config.server.unix_socket_path.clone() })
}

/// The MCP listener's accept loop, HTTPS with `acceptor`, on the MCP runtime.
async fn serve_mcp(
    listener: std::net::TcpListener,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    app: Router,
    shutdown: watch::Receiver<bool>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("[mcp] listener failed: {e}");
            return;
        }
    };
    match acceptor {
        Some(acceptor) => tls::serve_tls(listener, acceptor, app, shutdown).await,
        None => serve_http(listener, app, shutdown).await,
    }
}

/// Plain HTTP accept loop, same pattern as `tls::serve_tls` minus the
/// handshake: serves until `shutdown` flips, then drains in-flight
/// connections (5 s cap) before returning.
#[allow(clippy::disallowed_methods, reason = "runs on the frontend runtime")]
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

/// Bootstrap and shutdown events of the in-process servers, by their system
/// directory: tests share the process.
#[cfg(test)]
pub(crate) mod test_hook {
    use crate::control::resources::{tests::FakeProbe, Probe, ResourceWatch};
    use crate::control::ShardOwners;
    use crate::metrics::MetricsStore;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    fn probes() -> &'static Mutex<HashMap<String, Arc<FakeProbe>>> {
        static PROBES: OnceLock<Mutex<HashMap<String, Arc<FakeProbe>>>> = OnceLock::new();
        PROBES.get_or_init(Default::default)
    }

    /// The server on `system_dir`, started after this call, reads disk space
    /// and memory from `probe`.
    pub(crate) fn use_probe(system_dir: &str, probe: Arc<FakeProbe>) {
        probes().lock().unwrap().insert(system_dir.to_string(), probe);
    }

    /// The probe of the server on `system_dir`: the one set for it, or a
    /// roomy fake.
    pub(crate) fn probe(system_dir: &str) -> Arc<dyn Probe> {
        probes().lock().unwrap().get(system_dir).cloned().unwrap_or_else(FakeProbe::new)
    }

    type Watch = Arc<parking_lot::Mutex<ResourceWatch>>;

    fn watches() -> &'static Mutex<HashMap<String, Watch>> {
        static WATCHES: OnceLock<Mutex<HashMap<String, Watch>>> = OnceLock::new();
        WATCHES.get_or_init(Default::default)
    }

    pub(crate) fn register_watch(system_dir: &str, watch: Watch) {
        watches().lock().unwrap().insert(system_dir.to_string(), watch);
    }

    /// One tick of the resource watch of the server on `system_dir`, as its
    /// loop runs once a second.
    pub(crate) fn tick_resources(system_dir: &str) {
        let watch = watches().lock().unwrap().get(system_dir).cloned().expect("a running resource watch");
        watch.lock().tick();
    }

    fn events() -> &'static Mutex<HashMap<String, Vec<String>>> {
        static EVENTS: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
        EVENTS.get_or_init(Default::default)
    }

    pub(crate) fn record(system_dir: &str, event: String) {
        events().lock().unwrap().entry(system_dir.to_string()).or_default().push(event);
    }

    /// The events of the server on `system_dir`, in order.
    pub(crate) fn recorded(system_dir: &str) -> Vec<String> {
        events().lock().unwrap().get(system_dir).cloned().unwrap_or_default()
    }

    fn silent() -> &'static Mutex<Vec<(String, usize)>> {
        static SILENT: OnceLock<Mutex<Vec<(String, usize)>>> = OnceLock::new();
        SILENT.get_or_init(Default::default)
    }

    /// Data shard `shard` of the server on `system_dir`, started after this
    /// call, leaves the pings of the control plane unanswered.
    pub(crate) fn silence_pings(system_dir: &str, shard: usize) {
        silent().lock().unwrap().push((system_dir.to_string(), shard));
    }

    pub(crate) fn pings_silenced(system_dir: &str, shard: usize) -> bool {
        silent().lock().unwrap().iter().any(|(dir, k)| dir == system_dir && *k == shard)
    }

    /// How long `GET /health` waits for the ping of `shard`: not at all for a
    /// silenced one, which times out at once, and long for the others, so a
    /// loaded runner never turns a live shard into a timeout.
    pub(crate) fn ping_timeout(system_dir: &str, shard: usize, production: Duration) -> Duration {
        if pings_silenced(system_dir, shard) {
            Duration::ZERO
        } else {
            production.max(Duration::from_secs(60))
        }
    }

    fn metrics_stores() -> &'static Mutex<HashMap<String, Vec<Arc<MetricsStore>>>> {
        static STORES: OnceLock<Mutex<HashMap<String, Vec<Arc<MetricsStore>>>>> = OnceLock::new();
        STORES.get_or_init(Default::default)
    }

    pub(crate) fn register_metrics(system_dir: &str, store: Arc<MetricsStore>) {
        metrics_stores().lock().unwrap().entry(system_dir.to_string()).or_default().push(store);
    }

    /// Commits the current second of the metrics windows of every data shard
    /// of the server on `system_dir`, as their tickers do once a second.
    pub(crate) fn tick_metrics(system_dir: &str) {
        let stores = metrics_stores().lock().unwrap().get(system_dir).cloned().unwrap_or_default();
        for store in stores {
            store.tick_all();
        }
    }

    fn shard_owners() -> &'static Mutex<HashMap<(String, usize), ShardOwners>> {
        static OWNERS: OnceLock<Mutex<HashMap<(String, usize), ShardOwners>>> = OnceLock::new();
        OWNERS.get_or_init(Default::default)
    }

    /// Data shard `shard` of the server on `system_dir` serves `owners` until
    /// [`forget_owners`].
    pub(crate) fn register_owners(system_dir: &str, shard: usize, owners: ShardOwners) {
        shard_owners().lock().unwrap().insert((system_dir.to_string(), shard), owners);
    }

    pub(crate) fn forget_owners(system_dir: &str, shard: usize) {
        shard_owners().lock().unwrap().remove(&(system_dir.to_string(), shard));
    }

    /// The engines of data shard `shard` of the running server on `system_dir`.
    pub(crate) fn owners(system_dir: &str, shard: usize) -> ShardOwners {
        shard_owners().lock().unwrap().get(&(system_dir.to_string(), shard)).cloned().expect("a running data shard")
    }

    fn faults() -> &'static Mutex<Vec<(String, &'static str)>> {
        static FAULTS: OnceLock<Mutex<Vec<(String, &'static str)>>> = OnceLock::new();
        FAULTS.get_or_init(Default::default)
    }

    /// The next shard migration fails once, at `point` in `dir`: the system
    /// directory during the copy, a data root after its swap.
    pub(crate) fn fail_migration_at(dir: &str, point: &'static str) {
        faults().lock().unwrap().push((dir.to_string(), point));
    }

    pub(crate) fn migration_fault(dir: &str, point: &'static str) -> anyhow::Result<()> {
        let mut faults = faults().lock().unwrap();
        match faults.iter().position(|(at_dir, at)| at_dir == dir && *at == point) {
            Some(i) => {
                faults.remove(i);
                anyhow::bail!("injected fault {point}")
            }
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use futures::FutureExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// The write-ahead log at `path` is one segment that holds its header and
    /// no record.
    fn holds_only_its_header(path: impl AsRef<Path>) -> bool {
        let segments = crate::core::wal::segments_in(path.as_ref()).unwrap();
        let [(_, segment)] = &segments[..] else { return false };
        let log = std::fs::read(segment).unwrap();
        log.len() as u64 == crate::core::wal::WAL_HEADER_LEN && log.starts_with(&crate::core::wal::WAL_MAGIC)
    }

    /// The bytes of every segment of the write-ahead log at `path`, in order,
    /// without one a checkpoint prepared after the last one written.
    fn log_bytes(path: impl AsRef<Path>) -> Vec<u8> {
        let segments = crate::core::wal::segments_in(path.as_ref()).unwrap();
        let mut segments: Vec<Vec<u8>> = segments.into_iter().map(|(_, segment)| std::fs::read(segment).unwrap()).collect();
        if segments.len() > 1 && segments.last().unwrap().len() as u64 == crate::core::wal::WAL_HEADER_LEN {
            segments.pop();
        }
        segments.concat()
    }

    #[test]
    fn frontend_workers_auto_and_explicit() {
        assert_eq!(frontend_workers(0, 32), 4);
        assert_eq!(frontend_workers(0, 24), 4);
        assert_eq!(frontend_workers(0, 18), 3);
        assert_eq!(frontend_workers(0, 12), 2);
        assert_eq!(frontend_workers(0, 6), 2);
        assert_eq!(frontend_workers(0, 4), 2);
        assert_eq!(frontend_workers(0, 3), 1);
        assert_eq!(frontend_workers(0, 2), 1);
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
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(256, 1024));
        let (control, auth_cache) = crate::control::testing::start(dir.path(), Arc::clone(&registry), None, None, bus).await;
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
            control,
            config: Arc::new(LuraConfig::default()),
            config_path: "test.toml".to_string(),
            config_file_loaded: false,
        };
        (state, dir)
    }

    // The CorsLayer must sit outside both
    // the frontend auth_layer AND the Swagger sub-router's docs_auth_layer.
    // Regression-critical: if the layer moved inward (e.g. into
    // create_router), a request to the Swagger docs route would never reach
    // it — docs_auth_layer would 401 first, with no CORS header.
    #[test]
    fn cors_layer_wraps_swagger_and_survives_401() {
        crate::core::engine_runtime::block_on(async {
            let mut cfg = LuraConfig::default();
            cfg.server.swagger_enabled = true;
            cfg.auth.enabled = true;
            cfg.cors.enabled = true;
            cfg.cors.allowed_origins = vec!["https://example.com".to_string()];

            let (state, _dir) = make_test_state(true).await;
            let auth_cache = Arc::clone(&state.auth_cache);
            let ship = ShardRouter::new(vec![EngineDispatch::Inline(api::create_router(state))]);
            let app = build_router(&cfg, auth_cache, Arc::new(vec![]), ship);

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
        })
    }

    // Auth runs on the frontend, in front of the bridge — the engine
    // router behind it carries no auth layer of its own, so a 401 here can
    // only come from the frontend router.
    #[test]
    fn frontend_router_enforces_auth_in_front_of_the_engine() {
        crate::core::engine_runtime::block_on(async {
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
                ShardRouter::new(vec![EngineDispatch::Inline(api::create_router(state))]),
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
        })
    }

    /// Data shards of the in-process servers: `LURADB_TEST_SHARDS`, 1 when
    /// unset, so the suite runs once per shard count.
    fn test_shards() -> u16 {
        std::env::var("LURADB_TEST_SHARDS").ok().and_then(|n| n.parse().ok()).unwrap_or(1)
    }

    /// Loopback dev mode (auth off), HTTP on an ephemeral port, backups on,
    /// JSON and relational engines off, two reader threads, the data shards
    /// of [`test_shards`], every data path under `dir`.
    pub(super) fn test_config(dir: &Path) -> LuraConfig {
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let mut cfg = LuraConfig::default();
        cfg.server.port = 0;
        cfg.storage.db_path = path("luradb.db");
        cfg.storage.wal_path = path("luradb.wal");
        cfg.storage.vlog_path = path("luradb.vlog");
        cfg.storage.sstable_dir = path("sstables");
        cfg.storage.system_dir = path("sys");
        cfg.json.enabled = false;
        cfg.json.wal_path = path("json.wal");
        cfg.json.vlog_path = path("json.vlog");
        cfg.json.sstable_dir = path("json_sstables");
        cfg.rel.enabled = false;
        cfg.rel.wal_path = path("rel.wal");
        cfg.rel.vlog_path = path("rel.vlog");
        cfg.rel.sstable_dir = path("rel_sstables");
        cfg.backup.enabled = true;
        cfg.backup.dir = path("backups");
        cfg.multicore.reader_threads = 2;
        cfg.multicore.shards = test_shards();
        cfg
    }

    /// Starts a server, runs `client` against its HTTP address on a separate
    /// client runtime, then shuts the server down through its handle.
    fn with_server<F, Fut>(client: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: Future<Output = ()>,
    {
        with_tuned_server(|_| {}, client);
    }

    /// [`with_server`] on the test config as changed by `tune`.
    fn with_tuned_server<F, Fut>(tune: impl FnOnce(&mut LuraConfig), client: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: Future<Output = ()>,
    {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        tune(&mut cfg);
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        tokio::runtime::Runtime::new().unwrap().block_on(client(addr));
        // Returns only after the frontend runtime is gone and the engine
        // thread has run its graceful shutdown and exited.
        server.shutdown().unwrap();
    }

    pub(super) fn get(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
    }

    pub(super) fn with_body(method: &str, path: &str, body: &str) -> String {
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
        let (head, body, rest) = split_response(raw);
        (head[9..12].parse().unwrap(), body, rest)
    }

    /// [`next_response`] with the lower-cased head in place of the status.
    fn split_response(raw: &[u8]) -> (String, Vec<u8>, &[u8]) {
        let head_end = find(raw, b"\r\n\r\n").expect("response head") + 4;
        let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
        let mut rest = &raw[head_end..];
        if head.contains("transfer-encoding: chunked") {
            let mut body = Vec::new();
            loop {
                let line_end = find(rest, b"\r\n").expect("chunk size line");
                let size = usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16).unwrap();
                rest = &rest[line_end + 2..];
                if size == 0 {
                    return (head, body, &rest[2..]);
                }
                body.extend_from_slice(&rest[..size]);
                rest = &rest[size + 2..];
            }
        }
        let len = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map_or(rest.len(), |value| value.trim().parse().unwrap());
        (head, rest[..len].to_vec(), &rest[len..])
    }

    /// The thread that ran the request, from the bridge's test-hook header in
    /// a lower-cased response head.
    fn thread_of(head: &str) -> &str {
        head.lines()
            .find_map(|line| line.strip_prefix(bridge::test_hook::THREAD)?.strip_prefix(": "))
            .unwrap_or_else(|| panic!("no thread header in {head}"))
            .trim()
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
    pub(super) async fn request(addr: SocketAddr, raw: &(impl AsRef<[u8]> + ?Sized)) -> (u16, Vec<u8>) {
        let (status, _, body) = exchange(addr, raw).await;
        (status, body)
    }

    /// [`request`], with the lower-cased response head as well.
    pub(super) async fn exchange(addr: SocketAddr, raw: &(impl AsRef<[u8]> + ?Sized)) -> (u16, String, Vec<u8>) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw.as_ref()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let (head, body, _) = split_response(&buf);
        (head[9..12].parse().unwrap(), head, body)
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
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
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

    // A bootstrap that fails once the shards and their background tasks run
    // still ends every thread, with its I/O tasks run out, and reports the
    // error.
    #[test]
    fn a_bootstrap_failing_after_the_engines_started_ends_the_engine_thread() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.proxy.trusted_proxies = vec!["not-a-cidr".to_string()];
        let err = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).err().expect("the start must fail");
        assert!(format!("{err:#}").contains("trusted_proxies"), "{err:#}");
        assert!(dir.path().join("sstables").exists(), "the engines booted before the failure");
    }

    /// The key-value engine on `cfg`'s paths, as a server opens it: those of
    /// `shard`, or with `None` those of a data directory without shards; and
    /// the hub that writes its log once a server made that a directory of
    /// segments; a log that is none yet stays a single file, as an earlier
    /// version wrote it.
    pub(super) async fn open_kv_engine(
        cfg: &LuraConfig,
        shard: Option<usize>,
    ) -> (Arc<crate::engines::lsm::engine::LsmStorageEngine>, Option<crate::core::storage_thread::TestHub>) {
        use crate::core::storage_thread::{TestHub, WalTarget};
        let wal_path = PathBuf::from(&cfg.storage.wal_path);
        let hub = wal_path.is_dir().then(|| TestHub::start(&[(WalTarget::Kv, &wal_path)]));
        let (vlog_path, sstable_dir) = match shard {
            Some(k) => (
                layout::shard_file(Path::new(&cfg.storage.vlog_path), k),
                layout::shard_dir(Path::new(&cfg.storage.sstable_dir), k),
            ),
            None => (PathBuf::from(&cfg.storage.vlog_path), PathBuf::from(&cfg.storage.sstable_dir)),
        };
        let wal = Arc::new(match &hub {
            Some(hub) => hub.wal(WalTarget::Kv),
            None => crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap(),
        });
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(&sstable_dir).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(&sstable_dir));
        let options = crate::engines::lsm::engine::LsmEngineOptions::default();
        let engine = crate::engines::lsm::engine::LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, options);
        (Arc::new(engine.await.unwrap()), hub)
    }

    // An older data directory keeps its users in the key-value engine: the
    // first start moves them into the system store, the next one finds
    // nothing left to move, and both serve them. Such a directory has one
    // shard.
    #[test]
    fn the_first_start_moves_auth_records_out_of_the_key_value_engine() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 1;
        let record = crate::auth::UserRecord {
            name: "zoé".to_string(),
            api_key_hash: crate::auth::hash_api_key("lura_zoe"),
            role: crate::auth::UserRole::User,
            created_at: 1,
        };
        engine_runtime::block_on(async {
            let (kv, _hub) = open_kv_engine(&cfg, None).await;
            kv.put("__sys:auth:user:zoé".as_bytes(), &serde_json::to_vec(&record).unwrap()).await.unwrap();
            kv.shutdown().await;
        });

        let cfg = Arc::new(cfg);
        for start in ["first", "second"] {
            let server = Server::start(Arc::clone(&cfg), &dir.path().join("luradb.toml")).unwrap();
            let addr = server.http_addr.expect("HTTP listener enabled");
            let (status, users) =
                tokio::runtime::Runtime::new().unwrap().block_on(request(addr, &get("/store-api/auth/users")));
            server.shutdown().unwrap();
            assert_eq!(status, 200, "{start} start");
            let users: Value = serde_json::from_slice(&users).unwrap();
            assert_eq!(users[0]["name"], json!("zoé"), "{start} start: {users}");

            engine_runtime::block_on(async {
                use crate::engines::StorageEngine;
                let (kv, _hub) = open_kv_engine(&cfg, Some(0)).await;
                assert!(kv.scan_keys(b"__sys:auth:").await.unwrap().is_empty(), "{start} start");
                kv.shutdown().await;
                let (system, _hub) = open_system_store(&cfg).await;
                assert!(system.get("__sys:auth:user:zoé".as_bytes()).await.unwrap().is_some(), "{start} start");
                system.shutdown().await;
            });
        }
    }

    /// The system store on `cfg`'s paths, after a start of the server, and
    /// the hub that writes its log.
    async fn open_system_store(
        cfg: &LuraConfig,
    ) -> (Arc<crate::engines::lsm::engine::LsmStorageEngine>, crate::core::storage_thread::TestHub) {
        use crate::core::storage_thread::{TestHub, WalTarget};
        let dir = Path::new(&cfg.storage.system_dir);
        let hub = TestHub::start(&[(WalTarget::Sys, &dir.join(crate::control::system::WAL_FILE))]);
        (crate::control::system::open_with_wal(dir, hub.wal(WalTarget::Sys)).await.unwrap(), hub)
    }

    /// A data directory from before the shard layout, its default domain
    /// holding `key` in an SSTable.
    fn legacy_data_directory(cfg: &LuraConfig, key: &[u8]) {
        engine_runtime::block_on(async {
            let (kv, _hub) = open_kv_engine(cfg, None).await;
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let registry = crate::engines::lsm::DomainRegistry::recover(
                Arc::clone(&kv),
                crate::engines::lsm::domain::DomainConfig::default(),
                metrics,
            )
            .await
            .unwrap();
            registry.store("default").await.unwrap().put(key, "clé".as_bytes()).await.unwrap();
            kv.shutdown().await;
        });
        std::fs::write(&cfg.storage.db_path, b"").unwrap();
    }

    // The first start moves the files of an older data directory into
    // shard_0/ and records the layout; the next start moves nothing. Both
    // serve the data.
    #[test]
    fn the_first_start_moves_the_data_into_shard_0() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 1;
        legacy_data_directory(&cfg, b"moved");
        let (vlog, sstables, db) = (
            PathBuf::from(&cfg.storage.vlog_path),
            PathBuf::from(&cfg.storage.sstable_dir),
            PathBuf::from(&cfg.storage.db_path),
        );
        let legacy_tables: Vec<_> = std::fs::read_dir(&sstables).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert!(legacy_tables.iter().any(|name| name == "MANIFEST"), "{legacy_tables:?}");

        let cfg = Arc::new(cfg);
        for start in ["first", "second"] {
            let server = Server::start(Arc::clone(&cfg), &dir.path().join("luradb.toml")).unwrap();
            let addr = server.http_addr.expect("HTTP listener enabled");
            let (status, value) =
                tokio::runtime::Runtime::new().unwrap().block_on(request(addr, &get("/store-api/kv/default/keys/moved")));
            server.shutdown().unwrap();
            assert_eq!((status, value.as_slice()), (200, "clé".as_bytes()), "{start} start");

            assert!(!vlog.exists() && !db.exists(), "{start} start");
            assert!(layout::shard_file(&vlog, 0).is_file() && layout::shard_file(&db, 0).is_file(), "{start} start");
            for table in &legacy_tables {
                assert!(!sstables.join(table).exists(), "{start} start: {table:?}");
            }
            let moved: Vec<_> =
                std::fs::read_dir(layout::shard_dir(&sstables, 0)).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert!(moved.iter().any(|name| name == "MANIFEST"), "{start} start: {moved:?}");
            engine_runtime::block_on(async {
                let (system, _hub) = open_system_store(&cfg).await;
                assert!(crate::control::system::layout_is_sharded(&system).await.unwrap(), "{start} start");
                system.shutdown().await;
            });
        }
    }

    // An older data directory was written by one shard: a start with two
    // refuses before it moves anything.
    #[test]
    fn an_older_data_directory_is_not_opened_with_two_shards() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        legacy_data_directory(&cfg, b"kept");
        cfg.multicore.shards = 2;
        let err = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).err().expect("the start must fail");
        assert!(
            format!("{err:#}").contains("shard count changed (stored 1, configured 2) — run `luradb --migrate-shards 2`"),
            "{err:#}"
        );
        let cfg = test_config(dir.path());
        assert!(Path::new(&cfg.storage.vlog_path).is_file(), "nothing moved");
        assert!(!layout::shard_dir(Path::new(&cfg.storage.sstable_dir), 0).exists(), "nothing moved");
    }

    // With `shards = 0`, an older data directory starts with the one shard it
    // was written with, whatever the host's cores.
    #[test]
    fn an_older_data_directory_starts_with_one_shard_on_auto() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        legacy_data_directory(&cfg, b"kept");
        cfg.multicore.shards = 0;
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let (status, value) =
            tokio::runtime::Runtime::new().unwrap().block_on(request(addr, &get("/store-api/kv/default/keys/kept")));
        server.shutdown().unwrap();
        assert_eq!((status, value.as_slice()), (200, "clé".as_bytes()));
    }

    // Data laid out for another shard count is not opened at all.
    #[test]
    fn a_start_with_a_changed_shard_count_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 1;
        engine_runtime::block_on(async {
            let system = crate::control::system::open(Path::new(&cfg.storage.system_dir)).await.unwrap();
            crate::control::system::check_shard_count(&system, 2).await.unwrap();
            system.shutdown().await;
        });

        let err = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).err().expect("the start must fail");
        assert!(
            format!("{err:#}").contains("shard count changed (stored 2, configured 1) — run `luradb --migrate-shards 1`"),
            "{err:#}"
        );
        assert!(std::fs::read_dir(dir.path().join("sstables")).unwrap().next().is_none(), "no engine was opened");
    }

    // The guard compares against the configured shard count.
    #[test]
    fn a_start_with_more_shards_than_the_data_was_written_with_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 1;
        engine_runtime::block_on(async {
            let system = crate::control::system::open(Path::new(&cfg.storage.system_dir)).await.unwrap();
            crate::control::system::check_shard_count(&system, 1).await.unwrap();
            system.shutdown().await;
        });

        cfg.multicore.shards = 2;
        let err = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).err().expect("the start must fail");
        assert!(format!("{err:#}").contains("shard count changed (stored 1, configured 2)"), "{err:#}");
    }

    // No engine runs without the storage thread: when it cannot open a
    // write-ahead log, the start fails and says so.
    #[test]
    fn a_storage_thread_that_cannot_start_fails_the_start() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let log = Path::new(&cfg.storage.wal_path);
        std::fs::create_dir_all(log).unwrap();
        std::fs::write(crate::core::wal::segment_path(log, 1), b"not a segment header").unwrap();
        let err = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).err().expect("the start must fail");
        assert!(format!("{err:#}").contains("the storage thread failed to start"), "{err:#}");
        assert!(std::fs::read_dir(dir.path().join("sstables")).unwrap().next().is_none(), "no engine was opened");
    }

    // Bootstrap barrier: every shard reports ready before any is released to
    // start its purgers and sweepers; the hub stops once, at the end.
    #[test]
    fn no_shard_starts_its_loops_before_every_shard_is_ready() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 2;
        cfg.json.enabled = true;
        cfg.rel.enabled = true;
        let system_dir = cfg.storage.system_dir.clone();
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let events = test_hook::recorded(&system_dir);
        let first_release = events.iter().position(|e| e.ends_with("released")).expect("a released shard");
        for shard in 0..2 {
            let ready = events.iter().position(|e| *e == format!("shard {shard} ready")).expect("a ready shard");
            assert!(ready < first_release, "{events:?}");
        }
        assert_eq!(events.iter().filter(|e| e.ends_with("released")).count(), 2, "{events:?}");

        server.shutdown().unwrap();
        let events = test_hook::recorded(&system_dir);
        assert_eq!(events.iter().filter(|e| *e == "hub shutdown").count(), 1, "{events:?}");
    }

    // With shared memory on, every data shard count starts, and shutdown
    // stops the publisher, the dispatcher and the registration listener and
    // unlinks the segments before any shard drains.
    #[test]
    fn shared_memory_stops_before_the_shards_drain() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        let sock = dir.path().join("shm.sock");
        cfg.shm.enabled = true;
        cfg.shm.instance_id = format!("shutdown-order-{}", std::process::id());
        cfg.shm.registration_socket_path = sock.to_string_lossy().into_owned();
        cfg.shm.data_buffer_size = 1 << 20;
        let (system_dir, shards) = (cfg.storage.system_dir.clone(), cfg.multicore.shards);
        let state = format!("/dev/shm/luradb_{}_state", cfg.shm.instance_id);
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        assert!(sock.exists() && Path::new(&state).exists(), "shared memory is up");

        server.shutdown().unwrap();
        assert!(!sock.exists() && !Path::new(&state).exists(), "shared memory is gone");
        let events = test_hook::recorded(&system_dir);
        let stopped = events.iter().position(|e| e == "shm stopped").expect("shared memory stopped");
        for shard in 0..shards {
            let draining = format!("shard {shard} draining");
            let draining = events.iter().position(|e| *e == draining).expect("a draining shard");
            assert!(stopped < draining, "{events:?}");
        }
    }

    // Shutdown stops the control plane's loops, the write-ahead log
    // checkpoints among them, before any shard drains: a checkpoint in
    // progress ends before the final flush and the cut at the stop.
    #[test]
    fn the_log_checkpoints_stop_before_the_shards_drain() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 2;
        let system_dir = cfg.storage.system_dir.clone();
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();

        server.shutdown().unwrap();
        let events = test_hook::recorded(&system_dir);
        let stopped = events.iter().position(|e| e == "system loops stopped").expect("the loops stopped");
        for shard in 0..2 {
            let draining = format!("shard {shard} draining");
            let draining = events.iter().position(|e| *e == draining).expect("a draining shard");
            assert!(stopped < draining, "{events:?}");
        }
    }

    // Shutdown barrier: the JSON engine of shard 1 cannot flush (a fault in
    // its SSTable directory), so the JSON write-ahead log stays for the
    // next start, while the key-value and relational ones, flushed on both
    // shards, are cut back; the hub stops once. The next start recovers the
    // document from the log.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    fn a_failed_flush_on_one_shard_keeps_only_that_engine_s_log() {
        use crate::control::slots::domain_name_for_shard;
        use crate::storage::test_fault;
        let name = domain_name_for_shard(1, 2, 13);
        let dir = tempfile::TempDir::new().unwrap();
        let tuned = || {
            let mut cfg = test_config(dir.path());
            cfg.multicore.shards = 2;
            cfg.json.enabled = true;
            cfg.rel.enabled = true;
            cfg
        };
        let cfg = tuned();
        let document = format!("/store-api/json/{name}/documents/kept");
        let client = tokio::runtime::Runtime::new().unwrap();

        let server = Server::start(Arc::new(tuned()), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        client.block_on(async {
            let create = json!({ "name": name }).to_string();
            assert_eq!(request(addr, &with_body("POST", "/store-api/json/domains", &create)).await.0, 201);
            assert_eq!(request(addr, &with_body("PUT", &document, r#"{"n": 1}"#)).await.0, 201);
            assert_eq!(request(addr, &with_body("PUT", "/store-api/kv/default/keys/k", "v")).await.0, 200);
        });
        let unwritable = layout::shard_dir(Path::new(&cfg.json.sstable_dir), 1);
        test_fault::fail_writes_in(&unwritable);
        server.shutdown().unwrap();
        test_fault::allow_writes_in(&unwritable);

        assert!(!holds_only_its_header(&cfg.json.wal_path), "the JSON log stays");
        assert!(holds_only_its_header(&cfg.storage.wal_path), "the key-value log is cut back");
        assert!(holds_only_its_header(&cfg.rel.wal_path), "the relational log is cut back");
        let events = test_hook::recorded(&cfg.storage.system_dir);
        assert_eq!(events.iter().filter(|e| *e == "hub shutdown").count(), 1, "{events:?}");

        let server = Server::start(Arc::new(tuned()), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let (status, body) = client.block_on(request(addr, &get(&document)));
        server.shutdown().unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    }

    // A failed sync stops the server, which keeps the log: with the SSTable
    // directory of the JSON engine of shard 1 unsyncable, the stop keeps the
    // JSON log byte for byte while the others are cut back, and a start that
    // replays it stops before it truncates anything. Once the directory
    // syncs again, the next start recovers the document.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    fn a_failed_sync_keeps_the_engine_s_log_at_the_stop_and_fails_the_start() {
        use crate::control::slots::domain_name_for_shard;
        use crate::storage::test_fault;
        let name = domain_name_for_shard(1, 2, 13);
        let dir = tempfile::TempDir::new().unwrap();
        let tuned = || {
            let mut cfg = test_config(dir.path());
            cfg.multicore.shards = 2;
            cfg.json.enabled = true;
            cfg.rel.enabled = true;
            cfg
        };
        let cfg = tuned();
        let document = format!("/store-api/json/{name}/documents/kept");
        let client = tokio::runtime::Runtime::new().unwrap();

        let server = Server::start(Arc::new(tuned()), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        client.block_on(async {
            let create = json!({ "name": name }).to_string();
            assert_eq!(request(addr, &with_body("POST", "/store-api/json/domains", &create)).await.0, 201);
            assert_eq!(request(addr, &with_body("PUT", &document, r#"{"n": 1}"#)).await.0, 201);
            assert_eq!(request(addr, &with_body("PUT", "/store-api/kv/default/keys/k", "v")).await.0, 200);
        });
        let json_log = log_bytes(&cfg.json.wal_path);
        let unsyncable = layout::shard_dir(Path::new(&cfg.json.sstable_dir), 1);
        test_fault::fail_syncs_of(&unsyncable);
        server.shutdown().unwrap();

        assert_eq!(log_bytes(&cfg.json.wal_path), json_log, "the JSON log stays as it was");
        assert!(holds_only_its_header(&cfg.storage.wal_path), "the key-value log is cut back");
        assert!(holds_only_its_header(&cfg.rel.wal_path), "the relational log is cut back");

        let started = Server::start(Arc::new(tuned()), &dir.path().join("luradb.toml"));
        test_fault::allow_syncs_of(&unsyncable);
        let err = started.err().expect("the start must fail");
        assert!(format!("{err:#}").contains(&format!("data sync failed on {}", unsyncable.display())), "{err:#}");
        assert_eq!(log_bytes(&cfg.json.wal_path), json_log, "the failed start truncates nothing");

        let server = Server::start(Arc::new(tuned()), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let (status, body) = client.block_on(request(addr, &get(&document)));
        server.shutdown().unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    }

    // The hub opens a WAL for the enabled engines only: with JSON and
    // relational off, no directory of theirs appears.
    #[test]
    fn disabled_engines_get_no_write_ahead_log() {
        let dir = tempfile::TempDir::new().unwrap();
        let server = Server::start(Arc::new(test_config(dir.path())), &dir.path().join("luradb.toml")).unwrap();
        let cfg = test_config(dir.path());
        assert!(Path::new(&cfg.storage.wal_path).is_dir());
        assert!(Path::new(&cfg.storage.system_dir).join(crate::control::system::WAL_FILE).is_dir());
        assert!(!Path::new(&cfg.json.wal_path).exists());
        assert!(!Path::new(&cfg.rel.wal_path).exists());
        server.shutdown().unwrap();
    }

    // With the IoEngine on or off, every engine writes its WAL through the
    // storage hub, shared by all shards: each log holds its engine's writes
    // until the shutdown, which cuts every one back after the final flush.
    // Switched on, the IoEngine may still be absent: its registered buffers
    // need lockable memory a test host does not guarantee.
    #[test]
    fn every_engine_writes_its_wal_through_the_storage_hub() {
        for io_engine in [false, true] {
            let dir = tempfile::TempDir::new().unwrap();
            let tuned = || {
                let mut cfg = test_config(dir.path());
                cfg.io_engine.enabled = io_engine;
                cfg.json.enabled = true;
                cfg.rel.enabled = true;
                cfg
            };
            let cfg = tuned();
            let wals = [cfg.storage.wal_path.clone(), cfg.json.wal_path.clone(), cfg.rel.wal_path.clone()];
            let server = Server::start(Arc::new(tuned()), &dir.path().join("luradb.toml")).unwrap();
            let addr = server.http_addr.expect("HTTP listener enabled");
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let writes = [
                    with_body("PUT", "/store-api/kv/default/keys/hub-probe", "clé"),
                    with_body("PUT", "/store-api/json/default/documents/hub-probe", r#"{"n": 1}"#),
                    with_body("POST", "/store-api/rel/default/sql", r#"{"sql": "CREATE TABLE probe (id INTEGER PRIMARY KEY)"}"#),
                ];
                for write in writes {
                    let (status, body) = request(addr, &write).await;
                    assert!(status < 300, "{status}: {}", String::from_utf8_lossy(&body));
                }
            });
            for wal in &wals {
                let len = log_bytes(wal).len() as u64;
                assert!(len > crate::core::wal::WAL_HEADER_LEN, "io_engine {io_engine}: {wal} holds no write");
            }
            server.shutdown().unwrap();
            for wal in &wals {
                assert!(holds_only_its_header(wal), "io_engine {io_engine}: {wal}");
            }
        }
    }

    // A shard capacity the channel cannot take down must fail the
    // in-process start before the engines, SHM and background tasks are up.
    #[test]
    fn unusable_bridge_capacity_fails_before_anything_boots() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shard_queue_capacity = 0;
        let db_path = PathBuf::from(cfg.storage.db_path.clone());
        assert!(Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).is_err());
        assert!(!db_path.exists(), "the engine booted before the bridge channel existed");
    }

    // A live keep-alive connection learns about the shutdown: hyper closes it
    // instead of the drain having to wait out its 5 s cap.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
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
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
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

    // Automatic split: the frontend workers, a quarter of the cores as data
    // shards, 1 to 8, and the reader threads from what is left.
    #[test]
    fn core_split_resolves_auto_from_the_core_count() {
        let auto = LuraConfig::default();
        let split = [2, 3, 4, 8, 12, 32, 64].map(|cores| core_split(&auto, cores));
        assert_eq!(split, [(1, 1, 1), (1, 1, 1), (2, 1, 1), (2, 2, 2), (2, 3, 5), (4, 8, 18), (4, 8, 50)]);
    }

    // Configured values stand; shared memory does not change the split.
    #[test]
    fn core_split_keeps_configured_values_and_ignores_shm() {
        let mut config = LuraConfig::default();
        config.shm.enabled = true;
        assert_eq!(core_split(&config, 32), (4, 8, 18));
        config.multicore.shards = 3;
        config.multicore.frontend_workers = 1;
        config.multicore.reader_threads = 2;
        assert_eq!(core_split(&config, 32), (1, 3, 2));
    }

    #[test]
    fn reader_threads_auto_and_explicit() {
        assert_eq!(reader_threads(0, 32, 4, 1), 25);
        assert_eq!(reader_threads(0, 32, 4, 8), 18);
        assert_eq!(reader_threads(0, 12, 2, 1), 7);
        assert_eq!(reader_threads(0, 12, 1, 1), 8);
        assert_eq!(reader_threads(0, 4, 1, 1), 1);
        assert_eq!(reader_threads(0, 2, 1, 1), 1);
        assert_eq!(reader_threads(0, 1, 1, 1), 1);
        assert_eq!(reader_threads(3, 32, 4, 1), 3);
        assert_eq!(reader_threads(6, 2, 1, 2), 6);
    }

    // With two reader threads, a point GET and the probes run on the frontend
    // thread that holds the connection, any other read on a reader thread and
    // a PUT on the engine thread.
    #[test]
    fn point_reads_run_on_the_frontend_other_reads_on_reader_threads_and_writes_on_the_engine() {
        with_server(|addr| async move {
            let key = "/store-api/kv/default/keys/where";
            let (status, head, _) = exchange(addr, &with_body("PUT", key, "v")).await;
            assert_eq!((status, thread_of(&head)), (200, "luradb-shard-0"));
            for point in [key, "/health", "/version"] {
                let (status, head, _) = exchange(addr, &get(point)).await;
                assert_eq!(status, 200, "{point}");
                assert!(thread_of(&head).starts_with("luradb-frontend"), "{point}: {head}");
            }
            let (status, head, _) = exchange(addr, &get(&format!("{key}/meta"))).await;
            assert_eq!(status, 200);
            assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
        });
    }

    // A point read of a key flushed to an SSTable whose block is not cached
    // yet runs on a reader thread, which caches the block; the same read then
    // stays on the frontend, as does one of a key still in the MemTable.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    fn a_point_read_of_an_uncached_sstable_block_runs_on_the_pool_then_inline() {
        with_tuned_server(
            // One flush: 300 inline values of 512 bytes outgrow 128 KiB once.
            |cfg| cfg.lsm.memtable_size_threshold = 128 * 1024,
            |addr| async move {
                let value = |i: usize| format!("{i:0>512}");
                for i in 0..300 {
                    let put = with_body("PUT", &format!("/store-api/kv/default/keys/cold-{i}"), &value(i));
                    assert_eq!(request(addr, &put).await.0, 200);
                }
                let mut flushed = false;
                for _ in 0..500 {
                    let (status, body) = request(addr, &get("/health")).await;
                    assert_eq!(status, 200);
                    if serde_json::from_slice::<Value>(&body).unwrap()["l0_sstable_count"].as_u64().unwrap() >= 1 {
                        flushed = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert!(flushed, "no SSTable was flushed within the poll budget");

                let cold = get("/store-api/kv/default/keys/cold-7");
                let (status, head, body) = exchange(addr, &cold).await;
                assert_eq!((status, body), (200, value(7).into_bytes()));
                assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
                let (status, head, body) = exchange(addr, &cold).await;
                assert_eq!((status, body), (200, value(7).into_bytes()));
                assert!(thread_of(&head).starts_with("luradb-frontend"), "{head}");

                let warm = "/store-api/kv/default/keys/warm";
                assert_eq!(request(addr, &with_body("PUT", warm, "fresh")).await.0, 200);
                let (status, head, body) = exchange(addr, &get(warm)).await;
                assert_eq!((status, body.as_slice()), (200, b"fresh".as_slice()));
                assert!(thread_of(&head).starts_with("luradb-frontend"), "{head}");
            },
        );
    }

    /// [`with_tuned_server`], handing `client` the engines of the data shard
    /// that owns the domain `name` too.
    fn with_owner_of<F, Fut>(name: &str, tune: impl FnOnce(&mut LuraConfig), client: F)
    where
        F: FnOnce(SocketAddr, crate::control::ShardOwners) -> Fut,
        Fut: Future<Output = ()>,
    {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        tune(&mut cfg);
        let shard = usize::from(crate::control::slots::shard_of_domain(name, cfg.multicore.shards));
        let system_dir = cfg.storage.system_dir.clone();
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let owners = test_hook::owners(&system_dir, shard);
        tokio::runtime::Runtime::new().unwrap().block_on(client(addr, owners));
        server.shutdown().unwrap();
    }

    /// Waits until `engine` has an SSTable on level 0.
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    async fn until_flushed(engine: &crate::engines::lsm::engine::LsmStorageEngine) {
        // Upper bound against hanging only.
        for _ in 0..1500 {
            if engine.heartbeat_data().l0_sstable_count >= 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no SSTable was flushed within the poll budget");
    }

    // With a budget of one read token and its refill locked, a point read of
    // a key whose SSTable block is not cached gives up on the frontend and
    // runs again on the pool: it takes the one token once and answers, and
    // the next read finds the budget spent.
    #[test]
    fn a_cold_point_read_handed_to_the_pool_takes_one_read_token() {
        let tune = |cfg: &mut LuraConfig| {
            // One flush: 300 inline values of 512 bytes outgrow 128 KiB once.
            cfg.lsm.memtable_size_threshold = 128 * 1024;
            cfg.rate_limit.default_read_iops = 1;
        };
        with_owner_of("default", tune, |addr, owners| async move {
            let value = |i: usize| format!("{i:0>512}");
            for i in 0..300 {
                let put = with_body("PUT", &format!("/store-api/kv/default/keys/cold-{i}"), &value(i));
                assert_eq!(request(addr, &put).await.0, 200);
            }
            until_flushed(owners.kv.engine()).await;
            owners.kv.store("default").await.unwrap().lock_read_refill_for_test();

            let cold = get("/store-api/kv/default/keys/cold-7");
            let (status, head, body) = exchange(addr, &cold).await;
            let body = String::from_utf8(body).unwrap();
            assert_eq!(status, 200, "{body}");
            assert_eq!(body, value(7));
            assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
            assert_eq!(request(addr, &cold).await.0, 429);
        });
    }

    // The same for a row of a relational table: its read gives the token
    // back when it gives up on the frontend.
    #[test]
    fn a_cold_row_read_handed_to_the_pool_takes_one_read_token() {
        let tune = |cfg: &mut LuraConfig| {
            cfg.rel.enabled = true;
            cfg.rate_limit.default_read_iops = 1;
        };
        with_owner_of("default", tune, |addr, owners| async move {
            let sql = |statement: &str| with_body("POST", "/store-api/rel/default/sql", &json!({ "sql": statement }).to_string());
            assert_eq!(request(addr, &sql("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")).await.0, 200);
            assert_eq!(request(addr, &sql("INSERT INTO t VALUES (1, 'clé'), (2, '✓')")).await.0, 200);
            let rel = owners.rel.expect("the relational engine runs");
            {
                // As a write past the MemTable threshold does.
                let _drain = rel.engine().drain_writes().await;
                rel.engine().freeze_active_memtable();
            }
            until_flushed(rel.engine()).await;
            rel.lock_read_refill_for_test("default");

            let row = get("/store-api/rel/default/tables/t/rows/1");
            let (status, head, body) = exchange(addr, &row).await;
            let body = String::from_utf8(body).unwrap();
            assert_eq!(status, 200, "{body}");
            assert!(body.contains("clé"), "{body}");
            assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
            assert_eq!(request(addr, &row).await.0, 429);
        });
    }

    // Test 3: SQL arrives on the pool; write statements answer from the
    // engine thread, a SELECT and a parse error from the pool.
    #[test]
    fn sql_writes_run_on_the_engine_thread_and_selects_on_the_pool() {
        with_tuned_server(
            |cfg| cfg.rel.enabled = true,
            |addr| async move {
                let steps = [
                    ("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)", 200, true),
                    ("INSERT INTO t VALUES (1, 'clé')", 200, true),
                    ("SELECT name FROM t", 200, false),
                    ("SELEC name FROM t", 400, false),
                ];
                for (statement, expected, on_engine) in steps {
                    let body = format!(r#"{{"sql": "{statement}"}}"#);
                    let (status, head, answer) =
                        exchange(addr, &with_body("POST", "/store-api/rel/default/sql", &body)).await;
                    let answer = String::from_utf8_lossy(&answer).into_owned();
                    assert_eq!(status, expected, "{statement}: {answer}");
                    let thread = thread_of(&head);
                    if on_engine {
                        assert_eq!(thread, "luradb-shard-0", "{statement}");
                    } else {
                        assert!(thread.starts_with("luradb-reader"), "{statement}: {thread}");
                    }
                    if statement.starts_with("SELECT") {
                        assert!(answer.contains("clé"), "{answer}");
                    }
                }
            },
        );
    }

    // A point GET on the frontend thread and a read on the pool, pipelined
    // right behind a PUT of the same key on one connection, both see the PUT.
    #[test]
    fn reads_on_the_frontend_and_the_pool_see_the_write_before_them_on_the_connection() {
        with_server(|addr| async move {
            let put = "PUT /store-api/kv/default/keys/ryw HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nfirst";
            let point = "GET /store-api/kv/default/keys/ryw HTTP/1.1\r\nHost: test\r\n\r\n";
            let meta = get("/store-api/kv/default/keys/ryw/meta");
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(format!("{put}{point}{meta}").as_bytes()).await.unwrap();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await.unwrap();
            let (put_head, _, rest) = split_response(&raw);
            let (point_head, value, rest) = split_response(rest);
            let (meta_head, _, _) = split_response(rest);
            assert_eq!(thread_of(&put_head), "luradb-shard-0");
            assert!(point_head.starts_with("http/1.1 200"), "{point_head}");
            assert!(thread_of(&point_head).starts_with("luradb-frontend"), "{point_head}");
            assert_eq!(value, b"first");
            // The key's metadata exists only once the PUT is in.
            assert!(meta_head.starts_with("http/1.1 200"), "{meta_head}");
            assert!(thread_of(&meta_head).starts_with("luradb-reader"), "{meta_head}");
        });
    }

    /// Blocks every arriving thread until released, and records which
    /// threads arrived. Waits are bounded only against a hang.
    #[derive(Default)]
    struct Rendezvous {
        state: std::sync::Mutex<(Vec<(String, std::thread::ThreadId)>, bool)>,
        changed: std::sync::Condvar,
    }

    impl Rendezvous {
        const HANG: Duration = Duration::from_secs(30);

        fn arrive_and_wait(&self) {
            let current = std::thread::current();
            let mut state = self.state.lock().unwrap();
            state.0.push((current.name().unwrap_or_default().to_string(), current.id()));
            self.changed.notify_all();
            drop(self.changed.wait_timeout_while(state, Self::HANG, |(_, released)| !*released).unwrap());
        }

        fn arrivals_once(&self, count: usize) -> Vec<(String, std::thread::ThreadId)> {
            let state = self.state.lock().unwrap();
            let (state, _) =
                self.changed.wait_timeout_while(state, Self::HANG, |(arrived, _)| arrived.len() < count).unwrap();
            state.0.clone()
        }

        fn release(&self) {
            self.state.lock().unwrap().1 = true;
            self.changed.notify_all();
        }
    }

    // Four key scans on four connections, once answered, each block their
    // reader thread in a hold until released — they can only all arrive if
    // four reader threads run them side by side — while a PUT goes through on
    // the engine thread. Scans, not point GETs: a held point GET would block a
    // frontend worker, not a reader thread.
    #[test]
    fn four_reads_run_side_by_side_while_a_write_goes_through() {
        let gate = Arc::new(Rendezvous::default());
        let hold_gate = Arc::clone(&gate);
        bridge::test_hook::register_hold("perf-018b-parallel", move |_| {
            let gate = Arc::clone(&hold_gate);
            async move { gate.arrive_and_wait() }.boxed()
        });
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.reader_threads = 4;
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let client = tokio::runtime::Runtime::new().unwrap();

        let keys = "/store-api/kv/default/keys";
        assert_eq!(client.block_on(request(addr, &with_body("PUT", &format!("{keys}/parallel-1"), "v"))).0, 200);
        let held = format!(
            "GET {keys}?prefix=parallel HTTP/1.1\r\nHost: test\r\n{}: perf-018b-parallel\r\nConnection: close\r\n\r\n",
            bridge::test_hook::HOLD
        );
        let gets: Vec<_> = (0..4).map(|_| client.spawn({
            let held = held.clone();
            async move { exchange(addr, &held).await }
        })).collect();
        let arrived = gate.arrivals_once(4);
        assert_eq!(arrived.len(), 4, "the four reads were not in flight at once: {arrived:?}");
        let threads: std::collections::HashSet<_> = arrived.iter().map(|(_, id)| *id).collect();
        assert_eq!(threads.len(), 4, "{arrived:?}");
        assert!(arrived.iter().all(|(name, _)| name.starts_with("luradb-reader")), "{arrived:?}");

        let (status, head, _) = client.block_on(exchange(addr, &with_body("PUT", &format!("{keys}/parallel-2"), "w")));
        assert_eq!((status, thread_of(&head)), (200, "luradb-shard-0"));

        gate.release();
        // Scanned before the hold, so before the second PUT.
        for get in gets {
            let (status, head, body) = client.block_on(get).unwrap();
            assert_eq!(status, 200);
            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["keys"], json!(["parallel-1"]));
            assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
        }
        server.shutdown().unwrap();
    }

    /// The data shard of a lower-cased response head, from the bridge's
    /// test-hook header.
    pub(super) fn shard_in(head: &str) -> &str {
        head.lines()
            .find_map(|line| line.strip_prefix(bridge::test_hook::SHARD)?.strip_prefix(": "))
            .unwrap_or_else(|| panic!("no shard header in {head}"))
            .trim()
    }

    pub(super) fn sql_body(statement: &str) -> String {
        json!({ "sql": statement }).to_string()
    }

    // Two data shards, each domain placed on its shard by name: its writes
    // run on the shard's thread, its reads on the pool and its point reads
    // inline, both against the shard's engines. A domain's key-value, JSON
    // and relational parts share the shard, so a relational link into its
    // key-value domain resolves there.
    #[test]
    fn requests_run_on_the_shard_of_their_domain() {
        use crate::control::slots::domain_name_for_shard;
        let names = [domain_name_for_shard(0, 2, 5), domain_name_for_shard(1, 2, 5)];
        with_tuned_server(
            |cfg| {
                cfg.multicore.shards = 2;
                cfg.json.enabled = true;
                cfg.rel.enabled = true;
            },
            |addr| async move {
                for (shard, name) in names.iter().enumerate() {
                    let thread = format!("luradb-shard-{shard}");
                    let create = json!({ "name": name }).to_string();
                    for path in ["/store-api/domains", "/store-api/json/domains", "/store-api/rel/domains"] {
                        let (status, head, body) = exchange(addr, &with_body("POST", path, &create)).await;
                        assert_eq!(status, 201, "{path}: {}", String::from_utf8_lossy(&body));
                        assert_eq!(thread_of(&head), "luradb-control", "{path}");
                        let (status, head, body) = exchange(addr, &get(&format!("{path}/{name}"))).await;
                        assert_eq!(status, 200, "{path}/{name}: {}", String::from_utf8_lossy(&body));
                        assert_eq!(shard_in(&head), shard.to_string(), "{path}/{name}");
                    }

                    let key = format!("/store-api/kv/{name}/keys/ref");
                    let (status, head, _) = exchange(addr, &with_body("PUT", &key, "clé")).await;
                    assert_eq!((status, thread_of(&head)), (200, thread.as_str()));
                    let document = format!("/store-api/json/{name}/documents/d");
                    let (status, head, _) = exchange(addr, &with_body("PUT", &document, r#"{"n": 1}"#)).await;
                    assert_eq!((status, thread_of(&head)), (201, thread.as_str()));
                    let sql = format!("/store-api/rel/{name}/sql");
                    for statement in ["CREATE TABLE t (id INTEGER PRIMARY KEY, payload KVREF)", "INSERT INTO t VALUES (1, 'ref')"] {
                        let (status, head, body) = exchange(addr, &with_body("POST", &sql, &sql_body(statement))).await;
                        assert_eq!(status, 200, "{statement}: {}", String::from_utf8_lossy(&body));
                        assert_eq!(thread_of(&head), thread, "{statement}");
                    }

                    let (status, head, body) = exchange(addr, &get(&format!("/store-api/kv/{name}/keys"))).await;
                    assert_eq!(status, 200);
                    assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
                    assert_eq!(shard_in(&head), shard.to_string());
                    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["keys"], json!(["ref"]));

                    let (status, head, body) = exchange(addr, &get(&key)).await;
                    assert_eq!((status, body.as_slice()), (200, "clé".as_bytes()));
                    assert!(thread_of(&head).starts_with("luradb-frontend"), "{head}");
                    assert_eq!(shard_in(&head), shard.to_string());

                    let select = json!({ "sql": "SELECT * FROM t", "expand": ["payload"] }).to_string();
                    let (status, head, body) = exchange(addr, &with_body("POST", &sql, &select)).await;
                    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
                    assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
                    assert_eq!(shard_in(&head), shard.to_string());
                    let expanded = &serde_json::from_slice::<Value>(&body).unwrap()["expanded"]["payload"][0];
                    assert_eq!(*expanded, json!({ "exists": true, "value": "clé", "encoding": "utf8" }));
                }
            },
        );
    }

    /// The sorted keys of a JSON object.
    fn keys_of(value: &Value) -> Vec<String> {
        let mut keys: Vec<_> = value.as_object().unwrap_or_else(|| panic!("not an object: {value}")).keys().cloned().collect();
        keys.sort();
        keys
    }

    // Writes on domains of both shards: the scrape sums them exactly — the
    // lifetime counter at once, the engine and domain windows once the
    // shards' windows have committed their second — in the shape a scrape
    // of one shard has.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    fn metrics_sum_the_writes_of_every_shard() {
        use crate::control::slots::domain_name_for_shard;
        let names = [domain_name_for_shard(0, 2, 31), domain_name_for_shard(1, 2, 31)];
        let dir = std::cell::RefCell::new(String::new());
        let system_dir = &dir;
        with_tuned_server(
            |cfg| {
                cfg.multicore.shards = 2;
                *dir.borrow_mut() = cfg.storage.system_dir.clone();
            },
            |addr| async move {
                for (shard, name) in names.iter().enumerate() {
                    let create = json!({ "name": name }).to_string();
                    assert_eq!(request(addr, &with_body("POST", "/store-api/domains", &create)).await.0, 201);
                    for i in 0..=shard {
                        let put = with_body("PUT", &format!("/store-api/kv/{name}/keys/k{i}"), "clé");
                        assert_eq!(request(addr, &put).await.0, 200);
                    }
                }
                let scrape = || async {
                    let (status, body) = request(addr, &get("/store-api/metrics")).await;
                    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
                    serde_json::from_slice::<Value>(&body).unwrap()
                };
                let body = scrape().await;
                assert_eq!(body["system"]["total_writes"], 3, "{body}");
                crate::server::test_hook::tick_metrics(&system_dir.borrow());
                let body = scrape().await;
                assert_eq!(body["system"]["total_writes"], 3, "{body}");
                assert_eq!(body["engines"]["kv"]["write_ops"], 3, "{body}");
                assert_eq!(body["engines"]["kv"]["window_secs"], 60, "{body}");
                for (shard, name) in names.iter().enumerate() {
                    let domain = body["domains"].as_array().unwrap().iter().find(|d| d["domain"] == json!(name));
                    assert_eq!(domain.expect("a domain of each shard")["write_ops"], shard + 1, "{body}");
                }

                let shape = [
                    ("", vec!["backup", "block_cache", "domains", "engines", "resources", "shm", "system"]),
                    ("/resources", vec!["disk", "memory", "state"]),
                    ("/system", vec!["compaction_runs", "janitor_runs", "memtable_size_bytes", "total_reads", "total_writes"]),
                    ("/engines", vec!["json", "kv", "rel"]),
                    ("/engines/kv", vec![
                        "read_latency_us_p50", "read_latency_us_p95", "read_latency_us_p99", "read_ops", "window_secs",
                        "write_latency_us_p50", "write_latency_us_p95", "write_latency_us_p99", "write_ops",
                    ]),
                    ("/domains/0", vec![
                        "cache_hit_rate", "domain", "rate_limit_rejections", "read_latency_us_p50", "read_latency_us_p99",
                        "read_ops", "window_secs", "write_ops",
                    ]),
                    ("/block_cache", vec![
                        "current_bytes", "hits", "main_evictions", "main_hits", "misses", "small_evictions", "small_hits",
                    ]),
                    ("/shm", vec!["clients_kicked_total", "snapshot_consecutive_skips", "snapshot_publish_skips_total", "snapshot_publishes_total"]),
                ];
                for (pointer, expected) in shape {
                    assert_eq!(keys_of(body.pointer(pointer).unwrap()), expected, "{pointer}");
                }
            },
        );
    }

    // The domain lists of all three engines name the domains of every shard,
    // in name order, as with a single shard.
    #[test]
    fn domain_lists_name_the_domains_of_every_shard_in_order() {
        use crate::control::slots::domain_name_for_shard;
        let names: Vec<String> =
            (0..3).flat_map(|seed| [domain_name_for_shard(1, 2, seed), domain_name_for_shard(0, 2, seed)]).collect();
        let mut expected: Vec<String> = names.iter().cloned().chain(["default".to_string()]).collect();
        expected.sort();
        for shards in [1, 2] {
            let (names, expected) = (names.clone(), expected.clone());
            with_tuned_server(
                |cfg| {
                    cfg.multicore.shards = shards;
                    cfg.json.enabled = true;
                    cfg.rel.enabled = true;
                },
                |addr| async move {
                    for path in ["/store-api/domains", "/store-api/json/domains", "/store-api/rel/domains"] {
                        for name in &names {
                            let create = json!({ "name": name }).to_string();
                            assert_eq!(request(addr, &with_body("POST", path, &create)).await.0, 201, "{path} {name}");
                        }
                        let (status, body) = request(addr, &get(path)).await;
                        assert_eq!(status, 200, "{path}");
                        let listed: Vec<String> = serde_json::from_slice::<Vec<Value>>(&body)
                            .unwrap()
                            .iter()
                            .map(|domain| domain["name"].as_str().unwrap().to_string())
                            .collect();
                        assert_eq!(listed, expected, "{shards} shards: {path}");
                    }
                },
            );
        }
    }

    // A permission on a domain of shard 1 finds the domain in every engine;
    // one on a missing domain is still refused.
    #[test]
    fn a_permission_finds_a_domain_of_any_shard() {
        use crate::control::slots::domain_name_for_shard;
        let name = domain_name_for_shard(1, 2, 43);
        with_tuned_server(
            |cfg| {
                cfg.multicore.shards = 2;
                cfg.json.enabled = true;
                cfg.rel.enabled = true;
            },
            |addr| async move {
                let user = with_body("POST", "/store-api/auth/users", &json!({ "name": "ines" }).to_string());
                assert_eq!(request(addr, &user).await.0, 201);
                let create = json!({ "name": name }).to_string();
                for path in ["/store-api/domains", "/store-api/json/domains", "/store-api/rel/domains"] {
                    assert_eq!(request(addr, &with_body("POST", path, &create)).await.0, 201, "{path}");
                }
                for store_type in ["kv", "json", "rel"] {
                    for (domain, expected) in [(name.as_str(), 200), ("ghost", 404)] {
                        let grant = json!({ "domain": domain, "access": "read", "store_type": store_type }).to_string();
                        let (status, body) =
                            request(addr, &with_body("POST", "/store-api/auth/users/ines/permissions", &grant)).await;
                        assert_eq!(status, expected, "{store_type} {domain}: {}", String::from_utf8_lossy(&body));
                    }
                }
            },
        );
    }

    /// The body of `path` once its `state` is no longer `running`.
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    async fn when_finished(addr: SocketAddr, path: &str) -> Value {
        for _ in 0..500 {
            let (status, body) = request(addr, &get(path)).await;
            assert_eq!(status, 200, "{path}: {}", String::from_utf8_lossy(&body));
            let body: Value = serde_json::from_slice(&body).unwrap();
            if body["state"] != json!("running") {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{path} did not finish within the poll budget");
    }

    // A backup taken on two shards restores into one shard and into three:
    // every key with its expiry, every document with its index and every
    // user with its permission comes back, and each domain is read on the
    // shard that owns it on the target.
    #[test]
    fn a_backup_of_two_shards_restores_into_one_and_into_three() {
        use crate::control::slots::shard_of_domain;
        // One domain on each of the two shards, neither on shard 0 of three.
        let on = |two: u16, three: u16| {
            (0u64..).map(|i| format!("r{i}")).find(|n| shard_of_domain(n, 2) == two && shard_of_domain(n, 3) == three)
        };
        let names = [on(0, 1).unwrap(), on(1, 2).unwrap()];
        let with_shards = |shards: u16| {
            move |cfg: &mut LuraConfig| {
                cfg.multicore.shards = shards;
                cfg.json.enabled = true;
            }
        };
        let (mut archive, mut expiries, mut users) = (Vec::new(), Vec::new(), Value::Null);
        let source = (&mut archive, &mut expiries, &mut users, &names);
        with_tuned_server(with_shards(2), |addr| async move {
            let (archive, expiries, users, names) = source;
            // The default domains would make the restore wait for their purge.
            for path in ["/store-api/domains/default", "/store-api/json/domains/default"] {
                let delete = format!("DELETE {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
                assert_eq!(request(addr, &delete).await.0, 202, "{path}");
            }
            for name in names {
                let create = json!({ "name": name }).to_string();
                for path in ["/store-api/domains", "/store-api/json/domains"] {
                    assert_eq!(request(addr, &with_body("POST", path, &create)).await.0, 201, "{path}");
                }
                let kv = format!("/store-api/kv/{name}/keys");
                assert_eq!(request(addr, &with_body("PUT", &format!("{kv}/k"), &format!("clé {name}"))).await.0, 200);
                assert_eq!(request(addr, &with_body("PUT", &format!("{kv}/session?ttl=86400"), "tok")).await.0, 200);
                let (status, meta) = request(addr, &get(&format!("{kv}/session/meta"))).await;
                assert_eq!(status, 200);
                expiries.push(serde_json::from_slice::<Value>(&meta).unwrap()["expires_at"].clone());
                let index = json!({ "field": "city", "type": "string" }).to_string();
                assert_eq!(request(addr, &with_body("POST", &format!("/store-api/json/{name}/indexes"), &index)).await.0, 201);
                for (key, city) in [("d1", "Lyon"), ("d2", "Porto")] {
                    let doc = json!({ "city": city }).to_string();
                    let put = with_body("PUT", &format!("/store-api/json/{name}/documents/{key}"), &doc);
                    assert_eq!(request(addr, &put).await.0, 201);
                }
            }
            let user = with_body("POST", "/store-api/auth/users", &json!({ "name": "ines" }).to_string());
            assert_eq!(request(addr, &user).await.0, 201);
            let grant = json!({ "domain": names[1], "access": "read", "store_type": "json" }).to_string();
            assert_eq!(request(addr, &with_body("POST", "/store-api/auth/users/ines/permissions", &grant)).await.0, 200);
            *users = serde_json::from_slice(&request(addr, &get("/store-api/auth/users")).await.1).unwrap();

            let start = json!({ "scope": "all", "include_auth": true }).to_string();
            let (status, body) = request(addr, &with_body("POST", "/store-api/backups", &start)).await;
            assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
            let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
            let detail = when_finished(addr, &format!("/store-api/backups/{id}")).await;
            assert_eq!((detail["state"].clone(), detail["shards"].clone()), (json!("complete"), json!(2)), "{detail}");
            let (status, bytes) = request(addr, &get(&format!("/store-api/backups/{id}/download"))).await;
            assert_eq!(status, 200);
            *archive = bytes;
        });

        for target in [1u16, 3] {
            let (archive, expiries, users, names) = (&archive, &expiries, &users, &names);
            with_tuned_server(with_shards(target), |addr| async move {
                let upload = format!(
                    "POST /store-api/backups/upload HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    archive.len()
                );
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream.write_all(&[upload.as_bytes(), archive.as_slice()].concat()).await.unwrap();
                let mut raw = Vec::new();
                stream.read_to_end(&mut raw).await.unwrap();
                let (status, body, _) = next_response(&raw);
                assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
                let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();

                let restore = json!({ "include_auth": true }).to_string();
                let (status, body) = request(addr, &with_body("POST", &format!("/store-api/backups/{id}/restore"), &restore)).await;
                assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
                let restore_id = serde_json::from_slice::<Value>(&body).unwrap()["restore_id"].as_str().unwrap().to_string();
                let status = when_finished(addr, &format!("/store-api/restores/{restore_id}")).await;
                assert_eq!((status["state"].clone(), status["failed"].clone()), (json!("complete"), json!(0)), "{status}");

                for (name, expiry) in names.iter().zip(expiries) {
                    let owner = shard_of_domain(name, target).to_string();
                    let kv = format!("/store-api/kv/{name}/keys");
                    let (status, head, value) = exchange(addr, &get(&format!("{kv}/k"))).await;
                    assert_eq!((status, value), (200, format!("clé {name}").into_bytes()), "{target} shards");
                    assert_eq!(shard_in(&head), owner, "{name} on {target} shards");
                    let (status, meta) = request(addr, &get(&format!("{kv}/session/meta"))).await;
                    assert_eq!(status, 200);
                    assert_eq!(serde_json::from_slice::<Value>(&meta).unwrap()["expires_at"], *expiry);

                    let search = json!({ "filter": { "city": "Lyon" } }).to_string();
                    let (status, head, found) =
                        exchange(addr, &with_body("POST", &format!("/store-api/json/{name}/search"), &search)).await;
                    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&found));
                    assert_eq!(shard_in(&head), owner);
                    let found: Value = serde_json::from_slice(&found).unwrap();
                    assert_eq!((found["total"].clone(), found["documents"][0]["_key"].clone()), (json!(1), json!("d1")));
                    let (status, _) = request(addr, &get(&format!("/store-api/json/{name}/documents/d2"))).await;
                    assert_eq!(status, 200);
                }
                let restored: Value = serde_json::from_slice(&request(addr, &get("/store-api/auth/users")).await.1).unwrap();
                assert_eq!(restored, *users, "{target} shards");
            });
        }
    }

    /// The `shards` list of a `/health` body.
    fn shard_statuses(body: &[u8]) -> Value {
        serde_json::from_slice::<Value>(body).unwrap()["shards"].clone()
    }

    // Every shard answers its ping: 200, each one `ok`, and the report sums
    // the domains of both shards.
    #[test]
    fn health_reports_every_shard() {
        use crate::control::slots::domain_name_for_shard;
        with_tuned_server(
            |cfg| cfg.multicore.shards = 2,
            |addr| async move {
                for shard in [0, 1] {
                    let create = json!({ "name": domain_name_for_shard(shard, 2, 41) }).to_string();
                    assert_eq!(request(addr, &with_body("POST", "/store-api/domains", &create)).await.0, 201);
                }
                let (status, body) = request(addr, &get("/health")).await;
                assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
                assert_eq!(shard_statuses(&body), json!([{ "id": 0, "status": "ok" }, { "id": 1, "status": "ok" }]));
                let body = serde_json::from_slice::<Value>(&body).unwrap();
                assert_eq!((&body["status"], &body["domain_count"]), (&json!("ok"), &json!(3)));
            },
        );
    }

    // Test 4 (health): while disk space runs short, /health stays 200 with
    // status `degraded` and names the volume in `resources`; the metrics
    // carry the same block.
    #[test]
    fn health_stays_200_and_degraded_while_disk_space_runs_short() {
        use crate::control::resources::tests::{FakeProbe, GB};
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let system_dir = cfg.storage.system_dir.clone();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        test_hook::use_probe(&system_dir, Arc::clone(&probe));
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (status, body) = request(addr, &get("/health")).await;
            let body = serde_json::from_slice::<Value>(&body).unwrap();
            assert_eq!((status, &body["status"], &body["resources"]["state"]), (200, &json!("ok"), &json!("ok")));

            probe.set_free(dir.path(), 9 * GB);
            test_hook::tick_resources(&system_dir);
            let (status, body) = request(addr, &get("/health")).await;
            let body = serde_json::from_slice::<Value>(&body).unwrap();
            assert_eq!((status, &body["status"]), (200, &json!("degraded")), "{body}");
            let disk = &body["resources"]["disk"][0];
            assert_eq!((&body["resources"]["state"], &disk["state"]), (&json!("warning"), &json!("warning")), "{body}");
            assert_eq!((&disk["size_bytes"], &disk["free_bytes"]), (&json!(100 * GB), &json!(9 * GB)));
            assert_eq!(body["resources"]["memory"]["state"], json!("ok"));

            let (status, body) = request(addr, &get("/store-api/metrics")).await;
            let body = serde_json::from_slice::<Value>(&body).unwrap();
            assert_eq!((status, &body["resources"]["state"]), (200, &json!("warning")), "{body}");
        });
        server.shutdown().unwrap();
    }

    // Test 4 (server): while disk space runs short, the writes of every
    // engine, domain changes and restores answer 507 with Retry-After: 5, an
    // SQL INSERT too, which the engine refuses; the engines of a shard refuse
    // their writes themselves. Reads, health, metrics, backup download and
    // deletion, new users and their API keys go on; a backup runs into a
    // backup directory on a volume with room and is refused once that volume
    // runs short too. Back above the resume threshold, writes go in again.
    #[test]
    fn writes_answer_507_while_disk_space_runs_short_and_reads_go_on() {
        use crate::control::resources::{tests::{FakeProbe, GB}, WriteBlocked};
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.json.enabled = true;
        cfg.rel.enabled = true;
        let system_dir = cfg.storage.system_dir.clone();
        let backups = PathBuf::from(&cfg.backup.dir);
        std::fs::create_dir_all(&backups).unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        probe.mount(&backups, 100 * GB, 50 * GB);
        test_hook::use_probe(&system_dir, Arc::clone(&probe));
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let delete = |path: &str| format!("DELETE {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        let backup = with_body("POST", "/store-api/backups", &json!({ "scope": "all" }).to_string());
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            assert_eq!(request(addr, &with_body("PUT", "/store-api/kv/default/keys/k", "clé")).await.0, 200);
            let sql = |statement: &str| with_body("POST", "/store-api/rel/default/sql", &sql_body(statement));
            assert_eq!(request(addr, &sql("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")).await.0, 200);
            let index = json!({ "field": "city", "type": "string" }).to_string();
            assert_eq!(request(addr, &with_body("POST", "/store-api/json/default/indexes", &index)).await.0, 201);
            let document = json!({ "city": "Lyon" }).to_string();
            assert!(request(addr, &with_body("PUT", "/store-api/json/default/documents/kept", &document)).await.0 < 300);
            let (status, body) = request(addr, &backup).await;
            assert_eq!(status, 202, "{}", String::from_utf8_lossy(&body));
            let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
            assert_eq!(when_finished(addr, &format!("/store-api/backups/{id}")).await["state"], json!("complete"));

            probe.set_free(dir.path(), GB);
            test_hook::tick_resources(&system_dir);
            let refused = [
                with_body("PUT", "/store-api/kv/default/keys/k", "v"),
                delete("/store-api/kv/default/keys/k"),
                with_body("POST", "/store-api/domains", &json!({ "name": "more" }).to_string()),
                delete("/store-api/domains/default"),
                with_body("PUT", "/store-api/json/default/documents/d", &document),
                delete("/store-api/json/default/documents/kept"),
                with_body("POST", "/store-api/json/default/bulk", "{}"),
                with_body("POST", "/store-api/json/default/reindex", "{}"),
                sql("INSERT INTO t VALUES (1, 'clé')"),
                sql("CREATE TABLE u (id INTEGER PRIMARY KEY)"),
                with_body("POST", "/store-api/rel/default/tables/from-file?name=imported&format=csv", "id,v\n1,clé\n"),
                with_body("POST", &format!("/store-api/backups/{id}/restore"), "{}"),
            ];
            for raw in refused {
                let (status, head, body) = exchange(addr, &raw).await;
                let body = String::from_utf8_lossy(&body);
                assert_eq!(status, 507, "{raw}: {body}");
                assert!(head.to_ascii_lowercase().contains("retry-after: 5"), "{raw}: {head}");
                assert_eq!(body, "507 Insufficient Storage: write blocked: disk space below threshold, retry in 5 s");
            }
            let owners = test_hook::owners(&system_dir, 0);
            let engines = [owners.kv.engine(), owners.json.as_ref().unwrap().engine(), owners.rel.as_ref().unwrap().engine()];
            for engine in engines {
                assert!(WriteBlocked::in_chain(&engine.put(b"raw", b"v").await.unwrap_err()).is_some());
            }

            let (status, value) = request(addr, &get("/store-api/kv/default/keys/k")).await;
            assert_eq!((status, value.as_slice()), (200, "clé".as_bytes()));
            assert_eq!(request(addr, &sql("SELECT v FROM t")).await.0, 200);
            let search = json!({ "filter": { "city": "Lyon" } }).to_string();
            assert_eq!(request(addr, &with_body("POST", "/store-api/json/default/search", &search)).await.0, 200);
            let (status, body) = request(addr, &get("/health")).await;
            let body = serde_json::from_slice::<Value>(&body).unwrap();
            assert_eq!((status, &body["status"], &body["resources"]["state"]), (200, &json!("degraded"), &json!("blocked")));
            assert_eq!(request(addr, &get("/store-api/metrics")).await.0, 200);
            assert_eq!(request(addr, &get(&format!("/store-api/backups/{id}/download"))).await.0, 200);
            let user = with_body("POST", "/store-api/auth/users", &json!({ "name": "ines" }).to_string());
            assert_eq!(request(addr, &user).await.0, 201);
            assert_eq!(request(addr, &with_body("POST", "/store-api/auth/users/ines/rotate-key", "")).await.0, 200);

            let (status, body) = request(addr, &backup).await;
            assert_eq!(status, 202, "onto a volume with room: {}", String::from_utf8_lossy(&body));
            let second = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
            assert_eq!(when_finished(addr, &format!("/store-api/backups/{second}")).await["state"], json!("complete"));
            probe.set_free(&backups, 5 * GB);
            test_hook::tick_resources(&system_dir);
            assert_eq!(request(addr, &backup).await.0, 507, "onto a volume below its warn threshold");
            assert!(request(addr, &delete(&format!("/store-api/backups/{second}"))).await.0 < 300);

            probe.set_free(dir.path(), 50 * GB);
            probe.set_free(&backups, 50 * GB);
            test_hook::tick_resources(&system_dir);
            test_hook::tick_resources(&system_dir);
            assert_eq!(request(addr, &with_body("PUT", "/store-api/kv/default/keys/k", "v")).await.0, 200);
            assert_eq!(request(addr, &sql("INSERT INTO t VALUES (1, 'clé')")).await.0, 200);
        });
        server.shutdown().unwrap();
    }

    // Test 8: a start on a volume with less free space than the write-ahead
    // log recovering onto it fails with `NoRoomToRecover`, the exit code 4
    // error, before any engine opens. With room for the log, a start below
    // the block threshold refuses writes from the outset.
    #[test]
    fn a_start_without_room_to_recover_fails_with_exit_code_4() {
        use crate::control::resources::{tests::{FakeProbe, GB}, NoRoomToRecover};
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let log = Path::new(&cfg.storage.wal_path);
        let segment = crate::core::wal::segment_path(log, 1);
        std::fs::create_dir_all(log).unwrap();
        std::fs::write(&segment, crate::core::wal::wal_header(0)).unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 15);
        test_hook::use_probe(&cfg.storage.system_dir, Arc::clone(&probe));
        let cfg = Arc::new(cfg);

        let err = Server::start(Arc::clone(&cfg), &dir.path().join("luradb.toml")).err().expect("the start must fail");
        assert!(err.downcast_ref::<NoRoomToRecover>().is_some(), "{err:#}");
        assert!(std::fs::read_dir(dir.path().join("sstables")).unwrap().next().is_none(), "no engine was opened");

        probe.set_free(dir.path(), GB);
        let server = Server::start(cfg, &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let put = with_body("PUT", "/store-api/kv/default/keys/k", "v");
        let (status, _) = tokio::runtime::Runtime::new().unwrap().block_on(request(addr, &put));
        server.shutdown().unwrap();
        assert_eq!(status, 507);
    }

    // Shard 1 leaves its pings unanswered: /health answers 503 once the
    // ping times out, with the full report naming shard 1.
    #[test]
    fn health_answers_503_naming_a_silent_shard() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 2;
        test_hook::silence_pings(&cfg.storage.system_dir, 1);
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let (status, body) = tokio::runtime::Runtime::new().unwrap().block_on(request(addr, &get("/health")));
        server.shutdown().unwrap();
        assert_eq!(status, 503, "{}", String::from_utf8_lossy(&body));
        assert_eq!(shard_statuses(&body), json!([{ "id": 0, "status": "ok" }, { "id": 1, "status": "timeout" }]));
        let body = serde_json::from_slice::<Value>(&body).unwrap();
        assert_eq!((&body["status"], &body["version"]), (&json!("degraded"), &json!(env!("CARGO_PKG_VERSION"))));
    }

    // Shard 0's lane of one, held by a write: the next write for a domain of
    // shard 0 answers 503 with Retry-After, one for shard 1 goes through.
    // With the only reader thread held by a read, the reader lane of one
    // takes one more read and turns the other away alike.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
    fn a_full_lane_answers_503_while_the_other_shard_serves() {
        use crate::control::slots::domain_name_for_shard;
        let (a, b) = (domain_name_for_shard(0, 2, 9), domain_name_for_shard(1, 2, 9));
        let gate = Arc::new(Rendezvous::default());
        let hold_gate = Arc::clone(&gate);
        bridge::test_hook::register_hold("full-lane", move |_| {
            let gate = Arc::clone(&hold_gate);
            async move { gate.arrive_and_wait() }.boxed()
        });
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.multicore.shards = 2;
        cfg.multicore.shard_queue_capacity = 1;
        cfg.multicore.reader_queue_capacity = 1;
        cfg.multicore.reader_threads = 1;
        let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let client = tokio::runtime::Runtime::new().unwrap();
        for name in [&a, &b] {
            let create = json!({ "name": name }).to_string();
            assert_eq!(client.block_on(request(addr, &with_body("POST", "/store-api/domains", &create))).0, 201);
        }
        let held = |method: &str, path: String| {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: test\r\n{}: full-lane\r\nContent-Length: 1\r\nConnection: close\r\n\r\nv",
                bridge::test_hook::HOLD
            )
        };

        let raw = held("PUT", format!("/store-api/kv/{a}/keys/held"));
        let write = client.spawn(async move { exchange(addr, &raw).await });
        gate.arrivals_once(1);
        let (status, head, _) = client.block_on(exchange(addr, &with_body("PUT", &format!("/store-api/kv/{a}/keys/next"), "v")));
        assert_eq!(status, 503, "{head}");
        assert!(head.contains("retry-after: 1"), "{head}");
        let (status, _) = client.block_on(request(addr, &with_body("PUT", &format!("/store-api/kv/{b}/keys/next"), "v")));
        assert_eq!(status, 200);

        let raw = held("GET", format!("/store-api/kv/{b}/keys"));
        let read = client.spawn(async move { exchange(addr, &raw).await });
        gate.arrivals_once(2);
        // One of the two waits in the lane until the reader thread is free,
        // the other is turned away at once.
        let reads = [0, 1].map(|_| {
            let raw = get(&format!("/store-api/kv/{a}/keys"));
            client.spawn(async move { exchange(addr, &raw).await })
        });
        let (turned_away, _, waiting) = client.block_on(futures::future::select_all(reads));
        let (status, head, _) = turned_away.unwrap();
        assert_eq!(status, 503, "{head}");
        assert!(head.contains("retry-after: 1"), "{head}");

        gate.release();
        assert_eq!(client.block_on(write).unwrap().0, 200);
        assert_eq!(client.block_on(read).unwrap().0, 200);
        assert_eq!(client.block_on(waiting.into_iter().next().unwrap()).unwrap().0, 200);
        server.shutdown().unwrap();
    }

    // Test 7: the KV watch and the event stream run on the pool; a PUT
    // reaches the watcher, a new domain the event stream.
    #[test]
    fn watch_and_event_streams_run_on_the_pool() {
        with_server(|addr| async move {
            let open = |path: &'static str| async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes()).await.unwrap();
                let mut seen = Vec::new();
                read_until(&mut stream, &mut seen, b"\r\n\r\n").await;
                let head_end = find(&seen, b"\r\n\r\n").unwrap();
                let head = String::from_utf8_lossy(&seen[..head_end]).to_ascii_lowercase();
                assert!(head.starts_with("http/1.1 200"), "{head}");
                assert!(thread_of(&head).starts_with("luradb-reader"), "{head}");
                (stream, seen)
            };

            // The head arrives once the handler has subscribed, so the
            // changes below cannot be missed.
            let (mut watch, mut seen) = open("/store-api/kv/default/watch").await;
            let (status, _) = request(addr, &with_body("PUT", "/store-api/kv/default/keys/watched", "v")).await;
            assert_eq!(status, 200);
            read_until(&mut watch, &mut seen, b"data: watched").await;
            assert!(find(&seen, b"event: set").is_some(), "{}", String::from_utf8_lossy(&seen));

            let (mut events, mut seen) = open("/store-api/events").await;
            let (status, _) = request(addr, &with_body("POST", "/store-api/domains", r#"{"name":"pooled"}"#)).await;
            assert_eq!(status, 201);
            read_until(&mut events, &mut seen, b"\"domain\":\"pooled\"").await;
            assert!(find(&seen, b"event: domain_created").is_some(), "{}", String::from_utf8_lossy(&seen));
        });
    }

    /// Reports on drop whether the engine loop was still running by then: the
    /// weak sender upgrades only while some sender keeps the loop alive.
    struct EngineProbe(mpsc::WeakSender<Job>, std::sync::mpsc::Sender<bool>);

    impl Drop for EngineProbe {
        fn drop(&mut self) {
            let _ = self.1.send(self.0.upgrade().is_some());
        }
    }

    // A read still running at shutdown — answered, its request
    // with the engine sender it carried already gone — ends with the reader
    // pool, and only then does the engine shut down: when the read is
    // dropped, the engine loop still runs.
    #[test]
    fn shutdown_ends_running_reads_before_the_engine() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        bridge::test_hook::register_hold("perf-018b-shutdown", move |engine| {
            let probe = EngineProbe(engine.expect("a POST on the pool"), dropped_tx.clone());
            let entered = entered_tx.clone();
            async move {
                let _probe = probe;
                let _ = entered.send(());
                std::future::pending::<()>().await
            }
            .boxed()
        });
        let dir = tempfile::TempDir::new().unwrap();
        let server = Server::start(Arc::new(test_config(dir.path())), &dir.path().join("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let client = tokio::runtime::Runtime::new().unwrap();

        // A POST read: only those carry the way on to the engine thread.
        let body = r#"{"sql": "SELECT 1"}"#;
        let held = format!(
            "POST /store-api/rel/default/sql HTTP/1.1\r\nHost: test\r\n{}: perf-018b-shutdown\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            bridge::test_hook::HOLD,
            body.len()
        );
        let stream = client.block_on(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(held.as_bytes()).await.unwrap();
            stream
        });
        // Upper bounds against hanging only.
        entered_rx.recv_timeout(Duration::from_secs(30)).expect("the read never started");
        // The client gives up, so the listener drain need not wait for it.
        drop(stream);

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || done_tx.send(server.shutdown().is_ok()));
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(30)), Ok(true), "shutdown did not finish");
        assert_eq!(dropped_rx.try_recv(), Ok(true), "the engine shut down while a read was still running");
    }
}
