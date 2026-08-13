use axum::{response::Json, routing::get, Router};
use clap::Parser;
use crate::{
    api::{ApiDoc, AppState},
    auth::{reconcile_admins, AuthCache},
    config::{resolve_config_path, LuraConfig},
    core::{
        buffer_pool::BufferPoolManager,
        disk_manager::DiskManager,
        io_engine::{IoEngine, VLOG_LOGICAL_ID, WAL_LOGICAL_ID},
        storage_thread::{StorageHandle, StorageThread, StorageThreadConfig},
    },
    engines::json::JsonEngine,
    engines::lsm::{
        compaction::CompactionConfig,
        domain::{DomainConfig, DomainPurger, DomainRegistry},
        engine::{LsmEngineConfig, LsmEngineOptions, LsmStorageEngine},
        janitor::JanitorConfig,
    },
    engines::rel::RelEngine,
    ipc::ShmManager,
    metrics::{MetricsConfig, MetricsStore, MetricsTicker},
    storage::vlog::VLog,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::signal;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// Declare modules
pub mod api;
pub mod auth;
pub mod backup;
pub mod config;
pub mod core;
pub mod engines;
pub mod ipc;
pub mod logging;
pub mod metrics;
pub mod storage;
pub mod tls;
pub mod uds;

#[derive(Parser)]
#[command(about = "LuraDB – Linux-first, REST-native multi-model database")]
struct Cli {
    /// Path to the TOML configuration file. Default: ./luradb.toml if present,
    /// else /etc/luradb/luradb.toml if present, else ./luradb.toml (defaults).
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Prints the OpenAPI contract as JSON to stdout and exits.
    #[arg(long)]
    dump_openapi: bool,
}

async fn hello_handler(message: String) -> Json<Value> {
    Json(json!({ "message": message }))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received. Starting graceful shutdown...");
}

// --- Build sub-configs from LuraConfig ---
fn build_engine_configs(
    cfg: &LuraConfig,
) -> (LsmEngineConfig, CompactionConfig, JanitorConfig, DomainConfig, Arc<MetricsStore>) {
    let engine_config = LsmEngineConfig {
        vlog_inline_threshold: cfg.lsm.vlog_inline_threshold,
        memtable_size_threshold: cfg.lsm.memtable_size_threshold,
        max_key_length: cfg.lsm.max_key_length,
        max_value_size: cfg.lsm.max_value_size,
        flush_check_interval_ms: cfg.lsm.flush_check_interval_ms,
        compaction_check_interval_ms: cfg.lsm.compaction_check_interval_ms,
        wal_event_channel_capacity: cfg.lsm.wal_event_channel_capacity,
        use_mmap: cfg.lsm.use_mmap,
    };
    let compaction_config = CompactionConfig {
        l0_compaction_threshold: cfg.compaction.l0_threshold,
        l1_max_size: cfg.compaction.l1_max_size,
        level_size_ratio: cfg.compaction.level_size_ratio,
        max_sstable_size: cfg.compaction.max_sstable_size,
        low_watermark: None,
    };
    let janitor_config = JanitorConfig {
        check_interval_secs: cfg.janitor.check_interval_secs,
        dead_bytes_threshold: cfg.janitor.dead_bytes_threshold,
        min_vlog_size_bytes: cfg.janitor.min_vlog_size_bytes,
    };
    let domain_config = DomainConfig {
        max_name_length: cfg.domains.max_name_length,
        max_user_key_length: cfg.domains.max_user_key_length,
        default_domain: cfg.domains.default_domain.clone(),
        default_read_iops: cfg.rate_limit.default_read_iops,
        default_write_iops: cfg.rate_limit.default_write_iops,
        default_max_storage_bytes: cfg.rate_limit.default_max_storage_bytes,
        purger_batch_size: cfg.domains.purger_batch_size,
        purger_interval_secs: cfg.domains.purger_interval_secs,
    };
    let metrics_config = MetricsConfig {
        window_secs: cfg.metrics.window_secs,
        ticker_interval_ms: cfg.metrics.ticker_interval_ms,
    };
    let metrics = MetricsStore::new(metrics_config);
    (engine_config, compaction_config, janitor_config, domain_config, metrics)
}

// --- Storage thread (perf/005): dedicated OS thread driving a SQPOLL
// io_uring ring. When io_engine.enabled it owns the WAL/VLog files and
// performs their I/O; otherwise the tokio::fs paths in `main` stay in use.
fn start_storage_thread(
    cfg: &LuraConfig,
    wal_path: &std::path::Path,
    vlog_path: &std::path::Path,
) -> (Option<StorageThread>, Option<StorageHandle>) {
    let mut storage_thread: Option<StorageThread> = None;
    let storage_handle: Option<StorageHandle> = if cfg.io_engine.enabled {
        let st_config = StorageThreadConfig {
            sqpoll_enabled: cfg.io_engine.sqpoll_enabled,
            sqpoll_idle_ms: cfg.io_engine.sqpoll_idle_ms,
            ring_depth: cfg.io_engine.ring_depth,
            channel_capacity: cfg.io_engine.request_channel_capacity,
            cpu: cfg.io_engine.storage_thread_cpu,
        };
        match StorageThread::new(st_config, wal_path.to_path_buf(), vlog_path.to_path_buf()) {
            Ok((st, handle)) => {
                storage_thread = Some(st);
                Some(handle)
            }
            Err(e) => {
                tracing::warn!("Storage thread disabled: {e}. Falling back to tokio::fs I/O.");
                None
            }
        }
    } else {
        None
    };
    (storage_thread, storage_handle)
}

// --- IoEngine (spec perf/004) — scaffolding, not on the hot path yet ---
async fn init_io_engine(
    cfg: &LuraConfig,
    wal_path: &std::path::Path,
    vlog_path: &std::path::Path,
) -> Option<IoEngine> {
    let mut io_engine = if cfg.io_engine.enabled {
        match IoEngine::new(cfg.io_engine.registered_buffer_count, cfg.io_engine.registered_buffer_size) {
            Ok(engine) => {
                tracing::info!(
                    "IoEngine ready: {} registered buffers x {} bytes.",
                    cfg.io_engine.registered_buffer_count,
                    cfg.io_engine.registered_buffer_size
                );
                Some(engine)
            }
            Err(e) => {
                tracing::warn!("IoEngine disabled: {e}. Continuing without registered buffers.");
                None
            }
        }
    } else {
        None
    };
    if let Some(mut engine) = io_engine.take() {
        let res = match engine.register_file(WAL_LOGICAL_ID, wal_path).await {
            Ok(()) => engine.register_file(VLOG_LOGICAL_ID, vlog_path).await,
            err => err,
        };
        match res {
            Ok(()) => io_engine = Some(engine),
            Err(e) => tracing::warn!(
                "IoEngine disabled: WAL/VLog registration failed: {e}. Continuing without registered buffers."
            ),
        }
    }
    io_engine
}

// --- JSON engine (dedicated second LSM instance) ---
async fn init_json_engine(cfg: &LuraConfig) -> anyhow::Result<Option<Arc<JsonEngine>>> {
    if cfg.json.enabled {
        cfg.json.validate_paths(&cfg.storage)?;
        let engine = JsonEngine::bootstrap(&cfg.json).await?;
        tracing::info!("JSON engine ready.");
        Ok(Some(engine))
    } else {
        tracing::info!("JSON engine disabled by config.");
        Ok(None)
    }
}

// --- Relational engine (dedicated third LSM instance) ---
async fn init_rel_engine(
    cfg: &LuraConfig,
    registry: &Arc<DomainRegistry>,
    json_engine: &Option<Arc<JsonEngine>>,
    metrics: &Arc<MetricsStore>,
) -> anyhow::Result<Option<Arc<RelEngine>>> {
    if cfg.rel.enabled {
        cfg.rel.validate_paths(&cfg.storage, &cfg.json)?;
        // Cross-engine bridge (spec rel/012 §1): both target handles exist
        // here, before the rel bootstrap — a pure startup-sequence wiring.
        let resolver = crate::engines::rel::CrossEngineResolver::new(
            Some(Arc::clone(registry)),
            json_engine.clone(),
            Arc::clone(metrics),
        );
        let engine = RelEngine::bootstrap(&cfg.rel, Arc::clone(metrics), resolver).await?;
        tracing::info!("Relational engine ready.");
        Ok(Some(engine))
    } else {
        tracing::info!("Relational engine disabled by config.");
        Ok(None)
    }
}

// --- Backup manager + scheduler (spec general/006) ---
// Spawns its own scheduler task directly (like `start_shm` spawns its own
// background tasks) rather than going through `spawn_background_tasks`,
// since it needs `shutdown_flag`, which that function only returns once it
// is done.
fn init_backup(
    cfg: &LuraConfig,
    registry: &Arc<DomainRegistry>,
    json_engine: &Option<Arc<JsonEngine>>,
    shutdown_flag: &Arc<AtomicBool>,
) -> anyhow::Result<Option<Arc<backup::BackupManager>>> {
    if !cfg.backup.enabled {
        tracing::info!("Backup disabled by config.");
        return Ok(None);
    }
    // Startup warning (spec general/006): anyone who reaches the port can
    // then pull full data exports.
    if !cfg.auth.enabled {
        tracing::warn!(
            "backup.enabled is true but auth.enabled is false — any client that reaches this port can create and download full backups."
        );
    }
    let manager = backup::BackupManager::new(&cfg.backup, Arc::clone(registry), json_engine.clone())?;
    let scheduler = Arc::new(backup::scheduler::BackupScheduler::new(
        Arc::clone(&manager),
        &cfg.backup.schedule,
        Arc::clone(shutdown_flag),
    )?);
    tokio::spawn(async move { scheduler.run().await });
    tracing::info!("Backup manager ready ({} schedule(s)).", cfg.backup.schedule.len());
    Ok(Some(manager))
}

// --- Log Access (spec general/005) ---
// `LogConfig::validate` already guarantees `path` is non-empty whenever
// `http_access` is true, so no further checking is needed here.
fn init_log_access(cfg: &LuraConfig) -> Option<api::logs::LogAccessState> {
    if !cfg.log.http_access {
        tracing::info!("Log HTTP access disabled by config.");
        return None;
    }
    // Startup warning (spec general/005): with auth off, these endpoints
    // are reachable by anyone who reaches the port.
    if !cfg.auth.enabled {
        tracing::warn!(
            "log.http_access is true but auth.enabled is false — any client that reaches this port can read log files."
        );
    }
    tracing::info!("Log HTTP access ready.");
    Some(api::logs::LogAccessState {
        dir: std::path::PathBuf::from(&cfg.log.path),
        format: cfg.log.format.clone(),
    })
}

fn spawn_background_tasks(
    cfg: &LuraConfig,
    lsm_store: &Arc<LsmStorageEngine>,
    registry: &Arc<DomainRegistry>,
    metrics: &Arc<MetricsStore>,
    json_engine: &Option<Arc<JsonEngine>>,
    rel_engine: &Option<Arc<RelEngine>>,
    purger_batch_size: usize,
    purger_interval_secs: u64,
) -> Arc<AtomicBool> {
    // --- Metrics ticker (background) ---
    let ticker = MetricsTicker::new(Arc::clone(metrics));
    tokio::spawn(async move { ticker.run().await });
    tracing::info!("Metrics ticker started.");

    // --- Domain purger (background) ---
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // --- Log janitor (background) ---
    if !cfg.log.path.is_empty() && cfg.log.retention_days > 0 {
        let janitor = logging::LogJanitor::new(&cfg.log.path, cfg.log.retention_days);
        let janitor_shutdown = Arc::clone(&shutdown_flag);
        tokio::spawn(async move { janitor.run(janitor_shutdown).await });
    }

    let purger = Arc::new(DomainPurger::new(
        Arc::clone(lsm_store),
        Arc::clone(registry),
        Arc::clone(&shutdown_flag),
        purger_batch_size,
        purger_interval_secs,
    ));
    tokio::spawn(async move { purger.run().await });

    // --- JSON domain purger (background) ---
    if let Some(engine) = json_engine {
        let json_purger = Arc::new(crate::engines::json::JsonDomainPurger::new(
            Arc::clone(engine),
            Arc::clone(&shutdown_flag),
            cfg.json.purger_batch_size,
            cfg.json.purger_interval_secs,
        ));
        tokio::spawn(async move { json_purger.run().await });
    }

    // --- Cross-engine sweeper (background, spec rel/012 §5) ---
    if let Some(engine) = rel_engine {
        if engine.cross_engine_has_target() {
            let sweeper = Arc::new(crate::engines::rel::RelCrossEngineSweeper::new(
                Arc::clone(engine),
                Arc::clone(&shutdown_flag),
                cfg.rel.cross_engine_sweep_batch_size,
                cfg.rel.cross_engine_sweep_interval_secs,
            ));
            tokio::spawn(async move { sweeper.run().await });
        }
    }

    // --- Relational domain purger (background, spec rel/013 §7) ---
    if let Some(engine) = rel_engine {
        let rel_purger = Arc::new(crate::engines::rel::RelDomainPurger::new(
            Arc::clone(engine),
            Arc::clone(&shutdown_flag),
            cfg.rel.purger_batch_size,
            cfg.rel.purger_interval_secs,
        ));
        tokio::spawn(async move { rel_purger.run().await });
    }

    shutdown_flag
}

// Replaces five loose `Option` variables (see `start_shm`/`stop_shm`).
struct ShmServices {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    reg_task: tokio::task::JoinHandle<()>,
    dispatcher_task: tokio::task::JoinHandle<()>,
    publisher_task: tokio::task::JoinHandle<()>,
    reg_socket: String,
}

// --- Shared Memory IPC (spec perf/006, 007) + SHM multi-client: registration
// listener + command dispatcher (spec perf/008 Multi-Client). Each client
// registers over its own UDS and gets a dedicated cmd/resp ring quartet; the
// dispatcher polls them all. Started only when SHM is enabled.
async fn start_shm(
    cfg: &LuraConfig,
    registry: &Arc<DomainRegistry>,
    lsm_store: &Arc<LsmStorageEngine>,
) -> anyhow::Result<(Option<Arc<ShmManager>>, Option<ShmServices>)> {
    let shm_manager: Option<Arc<ShmManager>> = if cfg.shm.enabled {
        let manager = ShmManager::new(cfg.shm.clone())?;
        if let Some(state) = manager.get_segment("state") {
            anyhow::ensure!(
                state.len() >= crate::ipc::StateHeader::SIZE,
                "shm.state_size ({}) is smaller than the state header ({} bytes)",
                state.len(),
                crate::ipc::StateHeader::SIZE
            );
            // Initialize the state header (spec perf/007 §7). Safe: the
            // segment outlives `manager` and is only touched via StateHeader.
            unsafe { crate::ipc::StateHeader::from_ptr(state.as_ptr(), state.len()) }.init();
        }
        tracing::info!(
            "SHM manager ready (instance '{}'): state/data_a/data_b segments created.",
            cfg.shm.instance_id
        );
        Some(Arc::new(manager))
    } else {
        None
    };

    // `registry` is cloned here, before it moves into AppState below in `main`.
    let shm_services = if cfg.shm.enabled {
        let reg_path = cfg.shm.resolved_registration_socket_path();
        let listener = ipc::prepare_registration_socket(&reg_path)?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        let dispatcher = ipc::ShmDispatcher::new(Arc::clone(registry));
        let dispatcher_task = tokio::spawn(dispatcher.run(events_rx, shutdown_rx.clone()));

        // RCU read-snapshot publisher (spec perf/009): rebuilds the SHM
        // double-buffer snapshot on an interval and after every flush.
        // Spawned on the tokio-uring executor since SnapshotWriter is !Send.
        let publisher = ipc::SnapshotPublisher::new(
            ipc::SnapshotBuilder::new(
                Arc::clone(registry),
                Arc::clone(lsm_store),
                cfg.shm.data_buffer_size,
            ),
            Arc::clone(shm_manager.as_ref().expect("shm_manager present when shm.enabled")),
            std::time::Duration::from_millis(cfg.shm.snapshot_interval_ms),
            ipc::PUBLISH_WAIT_TIMEOUT_US,
            lsm_store.flush_notify(),
            shutdown_rx.clone(),
        );
        let publisher_task = tokio_uring::spawn(publisher.run());
        tracing::info!(
            "SHM snapshot publisher active (interval {} ms)",
            cfg.shm.snapshot_interval_ms
        );

        let reg_config = ipc::RegistrationConfig {
            instance_id: cfg.shm.instance_id.clone(),
            ring_size: cfg.shm.command_buffer_size,
            segment_mode: cfg.shm.segment_mode,
            auth_enabled: cfg.auth.enabled,
            trusted_uids: Arc::new(cfg.auth.trusted_uids.clone()),
        };
        let reg_task = tokio::spawn(ipc::serve_registration(listener, reg_config, events_tx, shutdown_rx));
        tracing::info!("SHM registration listener active on {reg_path}");
        Some(ShmServices { shutdown_tx, reg_task, dispatcher_task, publisher_task, reg_socket: reg_path })
    } else {
        None
    };

    Ok((shm_manager, shm_services))
}

async fn stop_shm(services: Option<ShmServices>) {
    // Stop the SHM registration listener and command dispatcher before the
    // engine shuts down (the dispatcher runs commands against it). The
    // dispatcher task drops its ClientConnections on exit, unlinking every
    // per-client segment; the registration socket file is removed here.
    if let Some(services) = services {
        let _ = services.shutdown_tx.send(true);
        let _ = services.reg_task.await;
        let _ = services.dispatcher_task.await;
        // Join the snapshot publisher before the engine shuts down (its build
        // step reads the engine).
        let _ = services.publisher_task.await;
        uds::remove_socket_file(&services.reg_socket);
    }
}

fn build_router(cfg: &LuraConfig, state: AppState, trusted_cidrs: Arc<Vec<crate::api::middleware::ParsedCidr>>) -> Router {
    let mut app = Router::new();

    if cfg.server.swagger_enabled {
        app = app.merge(
            SwaggerUi::new(cfg.server.swagger_url.clone())
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        );
    }

    if cfg.server.hello_enabled {
        let msg = cfg.server.hello_message.clone();
        app = app.route("/", get(move || hello_handler(msg)));
    }

    app = app.merge(api::create_router(state, trusted_cidrs));
    app
}

// --- UDS listener (parallel to TCP, same router — spec perf/001) ---
fn spawn_uds_listener(
    cfg: &LuraConfig,
    app: &Router,
    uds_path: &Option<String>,
) -> anyhow::Result<(Option<tokio::task::JoinHandle<()>>, tokio::sync::watch::Sender<bool>)> {
    let (uds_shutdown_tx, uds_shutdown_rx) = tokio::sync::watch::channel(false);
    let mut uds_task = None;
    if let Some(path) = uds_path {
        let uds_listener = uds::prepare_uds_socket(path, cfg.server.unix_socket_mode)?;
        tracing::info!("UDS listener active on {}", path);
        let uds_router = app.clone();
        let trusted_uids = Arc::new(cfg.auth.trusted_uids.clone());
        let auth_on = cfg.auth.enabled;
        let rx = uds_shutdown_rx.clone();
        uds_task = Some(tokio::spawn(uds::serve_uds(uds_listener, uds_router, trusted_uids, auth_on, rx)));
    }
    Ok((uds_task, uds_shutdown_tx))
}

// --- TLS listener (parallel to HTTP, same router — spec general/011) ---
async fn spawn_tls_listener(
    cfg: &LuraConfig,
    app: &Router,
    bind: std::net::IpAddr,
) -> anyhow::Result<(Option<tokio::task::JoinHandle<()>>, tokio::sync::watch::Sender<bool>)> {
    let (tls_shutdown_tx, tls_shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tls_task = None;
    if cfg.server.tls_enabled {
        let acceptor = tls::load_tls_acceptor(&cfg.server.tls_cert_path, &cfg.server.tls_key_path)?;
        let addr = SocketAddr::from((bind, cfg.server.tls_port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Listening on https://{}", addr);
        let tls_router = app.clone();
        tls_task = Some(tokio::spawn(tls::serve_tls(listener, acceptor, tls_router, tls_shutdown_rx)));
    }
    Ok((tls_task, tls_shutdown_tx))
}

async fn graceful_shutdown(
    uds_shutdown_tx: tokio::sync::watch::Sender<bool>,
    uds_task: Option<tokio::task::JoinHandle<()>>,
    uds_path: Option<String>,
    tls_shutdown_tx: tokio::sync::watch::Sender<bool>,
    tls_task: Option<tokio::task::JoinHandle<()>>,
    shm_services: Option<ShmServices>,
    shutdown_flag: Arc<AtomicBool>,
    lsm_store: Arc<LsmStorageEngine>,
    json_engine: Option<Arc<JsonEngine>>,
    rel_engine: Option<Arc<RelEngine>>,
    shm_manager: Option<Arc<ShmManager>>,
    buffer_pool: Arc<BufferPoolManager>,
    storage_thread: Option<StorageThread>,
) {
    // Stop the UDS/TLS accept loops and wait for them to drain in-flight
    // connections — engine shutdown below would race them otherwise. Both
    // signals fire before either await, so the two 5s drain caps overlap
    // instead of stacking.
    let _ = uds_shutdown_tx.send(true);
    let _ = tls_shutdown_tx.send(true);
    if let Some(task) = uds_task {
        let _ = task.await;
    }
    if let Some(task) = tls_task {
        let _ = task.await;
    }
    if let Some(path) = &uds_path {
        uds::remove_socket_file(path);
    }

    stop_shm(shm_services).await;

    // --- Shutdown ---
    tracing::info!("Shutting down LSM engine...");
    shutdown_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    lsm_store.shutdown().await;
    tracing::info!("LSM engine shutdown complete.");

    if let Some(json) = &json_engine {
        tracing::info!("Shutting down JSON engine...");
        json.shutdown().await;
        tracing::info!("JSON engine shutdown complete.");
    }

    if let Some(rel) = &rel_engine {
        tracing::info!("Shutting down relational engine...");
        rel.shutdown().await;
        tracing::info!("Relational engine shutdown complete.");
    }

    if let Some(shm) = &shm_manager {
        tracing::info!("Shutting down SHM manager...");
        shm.shutdown();
        tracing::info!("SHM manager shutdown complete.");
    }

    if let Err(e) = buffer_pool.flush_all_pages().await {
        tracing::error!("Failed to flush pages: {}", e);
    }

    // Storage thread last: the engine flush above still routed WAL/VLog I/O
    // through it. Drains pending requests, then joins.
    if let Some(mut st) = storage_thread {
        tracing::info!("Shutting down storage thread...");
        st.shutdown();
        tracing::info!("Storage thread shutdown complete.");
    }

    tracing::info!("Shutdown complete.");
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.dump_openapi {
        println!("{}", ApiDoc::openapi().to_pretty_json().expect("OpenAPI spec must serialize"));
        return Ok(());
    }
    let config_path = resolve_config_path(cli.config, |p| p.exists());
    let config = Arc::new(LuraConfig::load(&config_path)?);
    config.server.validate()?;
    config.log.validate()?;
    config.backup.validate(&config.storage, &config.json, &config.rel)?;
    let _log_guard = logging::init_logging(&config.log)?;

    tokio_uring::start(async move {
        tracing::info!("Starting LuraDB...");
        if config_path.exists() {
            tracing::info!("Config loaded from {}", config_path.display());
        } else {
            tracing::info!("No config file found at {}, using defaults", config_path.display());
        }

        let (engine_config, compaction_config, janitor_config, domain_config, metrics) =
            build_engine_configs(&config);

        // --- Storage stack ---
        let disk_manager = DiskManager::new(&config.storage.db_path).await?;
        let buffer_pool = Arc::new(BufferPoolManager::new(config.buffer_pool.pool_size, disk_manager));

        let wal_path = std::path::PathBuf::from(&config.storage.wal_path);
        let vlog_path = std::path::PathBuf::from(&config.storage.vlog_path);

        let (storage_thread, storage_handle) = start_storage_thread(&config, &wal_path, &vlog_path);

        let wal = Arc::new(match &storage_handle {
            Some(handle) => crate::core::wal::WriteAheadLog::with_storage_handle(handle.clone()),
            None => crate::core::wal::WriteAheadLog::new(&config.storage.wal_path).await?,
        });
        let vlog = Arc::new(match &storage_handle {
            Some(handle) => VLog::with_storage_handle(&vlog_path, handle.clone(), 1),
            None => VLog::new(&config.storage.vlog_path).await?,
        });
        let file_manager =
            Arc::new(crate::storage::file_manager::FileManager::new(&config.storage.sstable_dir).await?);
        let manifest_manager =
            Arc::new(crate::storage::manifest::ManifestManager::new(&config.storage.sstable_dir));

        let mut io_engine = init_io_engine(&config, &wal_path, &vlog_path).await;

        let block_cache_config = crate::config::BlockCacheConfig {
            capacity_bytes: config.block_cache.capacity_bytes,
            small_ratio: config.block_cache.small_ratio,
            ghost_capacity: config.block_cache.ghost_capacity,
        };

        let mut lsm_engine = LsmStorageEngine::new(
            wal,
            wal_path,
            vlog,
            vlog_path,
            file_manager,
            manifest_manager,
            LsmEngineOptions {
                engine: engine_config,
                compaction: compaction_config,
                janitor: janitor_config,
                block_cache: block_cache_config,
            },
        )
        .await?;
        // perf/005: route SSTable-flush writes through the storage thread and
        // let the Janitor reopen the VLog through it after GC.
        if let Some(handle) = &storage_handle {
            lsm_engine.set_storage_handle(handle.clone());
            // perf/013: if recovery found an active generation > 1, point the
            // thread at it too instead of leaving it on generation 1 until
            // the next GC cycle. Safe here: `LsmStorageEngine::new` above
            // already awaited WAL recovery to completion.
            lsm_engine.route_active_vlog_to_thread(handle).await?;
        }
        let lsm_store = Arc::new(lsm_engine);
        if let Some(engine) = io_engine.as_mut() {
            lsm_store.register_sstables_with_io_engine(engine).await?;
        }
        lsm_store.start_background_tasks();
        tracing::info!("Storage engine ready.");

        // --- Domain registry ---
        let purger_batch_size = domain_config.purger_batch_size;
        let purger_interval_secs = domain_config.purger_interval_secs;
        let registry = Arc::new(
            DomainRegistry::recover(Arc::clone(&lsm_store), domain_config, Arc::clone(&metrics)).await?,
        );
        tracing::info!("Domain registry recovered.");

        let json_engine = init_json_engine(&config).await?;
        let rel_engine = init_rel_engine(&config, &registry, &json_engine, &metrics).await?;

        let shutdown_flag = spawn_background_tasks(
            &config,
            &lsm_store,
            &registry,
            &metrics,
            &json_engine,
            &rel_engine,
            purger_batch_size,
            purger_interval_secs,
        );

        let backup_manager = init_backup(&config, &registry, &json_engine, &shutdown_flag)?;
        let log_access = init_log_access(&config);

        // --- Auth cache ---
        let auth_cache = Arc::new(AuthCache::new(Arc::clone(&lsm_store)));
        auth_cache.load_from_engine().await?;
        reconcile_admins(&auth_cache, &config.auth.admins, config.auth.enabled).await?;
        tracing::info!("Auth cache loaded.");

        // --- Trusted proxy CIDRs ---
        let trusted_cidrs = Arc::new(
            crate::api::middleware::parse_cidrs(&config.proxy.trusted_proxies)
                .map_err(|e| anyhow::anyhow!("Invalid trusted_proxies config: {}", e))?,
        );

        let (shm_manager, shm_services) = start_shm(&config, &registry, &lsm_store).await?;

        // --- Router ---
        let state = AppState {
            registry,
            auth_cache,
            auth_enabled: config.auth.enabled,
            metrics,
            json_engine: json_engine.clone(),
            rel_engine: rel_engine.clone(),
            shm_manager: shm_manager.clone(),
            backup_manager,
            log_access,
        };
        let app = build_router(&config, state, trusted_cidrs);

        let bind: std::net::IpAddr = config.server.bind_address.parse()
            .map_err(|e| anyhow::anyhow!("Invalid bind_address '{}': {}", config.server.bind_address, e))?;

        let uds_path = config.server.unix_socket_path.clone();
        let (uds_task, uds_shutdown_tx) = spawn_uds_listener(&config, &app, &uds_path)?;
        let (tls_task, tls_shutdown_tx) = spawn_tls_listener(&config, &app, bind).await?;

        if config.server.http_enabled {
            let addr = SocketAddr::from((bind, config.server.port));
            tracing::info!("Listening on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        } else {
            tracing::info!("HTTP listener disabled by config (server.http_enabled = false).");
            shutdown_signal().await;
        }

        graceful_shutdown(
            uds_shutdown_tx,
            uds_task,
            uds_path,
            tls_shutdown_tx,
            tls_task,
            shm_services,
            shutdown_flag,
            lsm_store,
            json_engine,
            rel_engine,
            shm_manager,
            buffer_pool,
            storage_thread,
        )
        .await;

        Ok(())
    })
}
