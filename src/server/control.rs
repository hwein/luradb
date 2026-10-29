//! The control-plane thread: starts the storage hub and the system store,
//! moves an old data directory into the shard layout, recovers every
//! engine's write-ahead log onto the data shards' instances, starts the
//! shards and releases them once the control plane is attached to all of
//! them. It then serves the requests without a domain and the shared-memory
//! clients, drops the write-ahead log segments the SSTables hold and, at the
//! end, stops shared memory, drains the shards, truncates each write-ahead
//! log whose engine flushed on every shard to one empty segment, and stops
//! the hub.

use super::{
    layout,
    recovery::{self, EngineFiles},
    shard::{self, ShardBoot, ShardStart},
};
use crate::{
    api::{self, middleware::ParsedCidr, AppState},
    auth::{reconcile_admins, AuthCache},
    backup,
    bridge::{self, Job, Lane},
    config::{BlockCacheConfig, LuraConfig},
    control::{
        checkpoint::{Holder, WalCheckpoint, WAL_CHECKPOINT_INTERVAL},
        resources::{self, ResourceWatch, Resources, RESOURCE_WATCH_INTERVAL},
        system, ControlPlane, Engine, Owners, Shard, ShardCommand, ShardOwners,
    },
    core::{
        coop,
        storage_thread::{self, StorageHandle, StorageThread, StorageThreadConfig, WalTarget},
        wal::WriteAheadLog,
    },
    engines::json::JsonEngine,
    engines::lsm::{
        compaction::CompactionConfig,
        domain::DomainConfig,
        engine::{LsmEngineConfig, LsmEngineOptions, LsmStorageEngine},
        janitor::JanitorConfig,
        TtlSweeper,
    },
    engines::rel::RelEngine,
    ipc::{self, ShmManager},
    logging,
    uds,
};
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{mpsc, oneshot};

/// Handed from the control-plane thread to the frontend once every shard
/// runs: the lanes to the shards, by index, the way to the control plane,
/// and the API state of each shard, from which the reader pool and the point
/// reads build their routers.
pub(super) struct Ready {
    pub(super) shards: Vec<Lane>,
    pub(super) control: mpsc::UnboundedSender<Job>,
    pub(super) states: Vec<AppState>,
    pub(super) trusted_cidrs: Arc<Vec<ParsedCidr>>,
}

/// Body of the control-plane thread: bootstrap, report, serve the requests
/// without a domain until the frontend lets go of the control plane, then
/// shut everything down.
pub(super) async fn run(
    config: Arc<LuraConfig>,
    config_path: PathBuf,
    auto_shards: u16,
    frontend: tokio::runtime::Handle,
    ready_tx: std::sync::mpsc::Sender<anyhow::Result<Ready>>,
) {
    let booted = bootstrap(&config, &config_path, auto_shards, &frontend).await;
    let (cluster, (shards, states, trusted_cidrs)) = match booted {
        Ok(started) => started,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let (control, control_jobs) = mpsc::unbounded_channel();
    let router = api::create_router(states[0].clone());
    let ready = Ready { shards, control, states, trusted_cidrs };
    if ready_tx.send(Ok(ready)).is_ok() {
        bridge::serve_engine(control_jobs, router).await;
    }
    cluster.shutdown().await;
}

/// A data shard's thread as the control plane holds it.
struct ShardThread {
    commands: mpsc::UnboundedSender<ShardCommand>,
    thread: std::thread::JoinHandle<()>,
}

/// Everything [`Cluster::shutdown`] stops.
struct Cluster {
    shards: Vec<ShardThread>,
    /// Stops the control plane's own loops: metrics, log janitor, backups.
    loops: Arc<AtomicBool>,
    /// Each enabled engine's write-ahead log.
    wals: Vec<(Engine, WriteAheadLog)>,
    system_store: Arc<LsmStorageEngine>,
    /// Watches disk space and memory, checkpoints the write-ahead logs and
    /// removes the expired OAuth codes and tokens from the system store.
    system_loops: shard::Loops,
    shm_manager: Option<Arc<ShmManager>>,
    shm: Option<ShmServices>,
    storage_thread: StorageThread,
    /// Released last, once every file is closed.
    lock: system::DataLock,
    #[cfg(test)]
    system_dir: String,
}

impl Cluster {
    /// Stops the log checkpoints, the system store's sweeper and shared
    /// memory, then drains every shard — the shard's requests end first — and
    /// truncates the write-ahead log of each engine whose final flush
    /// succeeded on all shards; then shuts the system store down, stops the
    /// storage hub, once, joins the shard threads and only then lets go of
    /// the data directories.
    async fn shutdown(self) {
        #[cfg(test)]
        let system_dir = self.system_dir.clone();
        let Cluster { shards, loops, wals, system_store, system_loops, shm_manager, shm, mut storage_thread, lock, .. } =
            self;
        loops.store(true, Ordering::Relaxed);
        // A checkpoint in progress ends here, before the shards drain.
        system_loops.stop().await;
        #[cfg(test)]
        super::test_hook::record(&system_dir, "system loops stopped".to_string());

        // The publisher and the dispatcher take cuts and write through the
        // shards: both end before the shards drain.
        if let Some(shm) = shm {
            shm.stop().await;
        }
        if let Some(shm) = &shm_manager {
            shm.shutdown();
            #[cfg(test)]
            super::test_hook::record(&system_dir, "shm stopped".to_string());
        }

        tracing::info!("Draining the data shards...");
        let mut replies = Vec::with_capacity(shards.len());
        for shard in &shards {
            let (reply, flushed) = oneshot::channel();
            let _ = shard.commands.send(ShardCommand::Drain { reply });
            replies.push(flushed);
        }
        let mut failed: Vec<Engine> = Vec::new();
        for (k, reply) in replies.into_iter().enumerate() {
            match reply.await {
                Ok(flushed) => {
                    for (engine, result) in flushed {
                        if let Err(e) = result {
                            tracing::error!("Shard {k}, {} engine: {e:#}", engine.as_str());
                            failed.push(engine);
                        }
                    }
                }
                Err(_) => {
                    tracing::error!("Shard {k} did not report its final flush.");
                    failed.extend(wals.iter().map(|(engine, _)| *engine));
                }
            }
        }
        for (engine, wal) in &wals {
            if failed.contains(engine) {
                tracing::error!("The {} write-ahead log stays for the next start to replay.", engine.as_str());
            } else if let Err(e) = wal.truncate().await {
                tracing::error!("Truncating the {} write-ahead log failed: {e}", engine.as_str());
            }
        }

        tracing::info!("Shutting down system store...");
        system_store.shutdown().await;
        // The hub last: the shards and the system store wrote through it.
        #[cfg(test)]
        super::test_hook::record(&system_dir, "hub shutdown".to_string());
        storage_thread.shutdown();
        for shard in shards {
            if shard.thread.join().is_err() {
                tracing::error!("A data shard thread panicked.");
            }
        }
        drop((system_store, lock));
        tracing::info!("Shutdown complete.");
    }

    /// Stops what started of a bootstrap that failed: the shards — those
    /// waiting for their release flush their engines and end — and the hub.
    /// The write-ahead logs stay for the next start.
    fn abort(shards: Vec<ShardThread>, starts: Vec<oneshot::Sender<ShardStart>>, mut storage_thread: StorageThread) {
        drop(starts);
        for shard in shards {
            drop(shard.commands);
            let _ = shard.thread.join();
        }
        storage_thread.shutdown();
    }
}

/// How the fixed memory budgets split across the data shards.
pub(super) struct MemorySplit {
    /// Block cache of each engine instance; an engine's budget splits evenly.
    block_cache_bytes: usize,
    /// Pages of each shard's buffer pool.
    buffer_pool_pages: usize,
}

impl MemorySplit {
    pub(super) fn of(config: &LuraConfig, shards: u16) -> Self {
        let shards = usize::from(shards);
        Self {
            block_cache_bytes: BlockCacheConfig::default().capacity_bytes / shards,
            buffer_pool_pages: (config.buffer_pool.pool_size / shards).max(1),
        }
    }

    pub(super) fn block_cache(&self) -> BlockCacheConfig {
        BlockCacheConfig { capacity_bytes: self.block_cache_bytes, ..BlockCacheConfig::default() }
    }

    /// The start-log lines reporting the split, one per shard.
    fn report(&self, config: &LuraConfig, shards: u16) -> Vec<String> {
        let io_engine = config.io_engine.enabled && shards == 1;
        let mut lines: Vec<String> = (0..shards)
            .map(|shard| {
                format!(
                    "Shard {shard}: block cache {} KiB per engine; MemTable threshold {} bytes per engine; \
                     buffer pool {} pages; registered I/O buffers {}.",
                    self.block_cache_bytes / 1024,
                    config.lsm.memtable_size_threshold,
                    self.buffer_pool_pages,
                    if io_engine && shard == 0 { "on" } else { "off" }
                )
            })
            .collect();
        if config.io_engine.enabled && shards > 1 {
            lines.push("io_engine.enabled has no effect with more than one data shard.".to_string());
        }
        lines
    }
}

/// The lanes to the shards, the shards' API states and the trusted CIDRs.
type Started = (Vec<Lane>, Vec<AppState>, Arc<Vec<ParsedCidr>>);

/// Boots the hub, the system store and the data shards — as many as the data
/// directory has, for a new one `auto_shards` — then the control plane over
/// them, and releases the shards. Returns what shuts down and what the
/// frontend needs. A failed step stops what already runs.
async fn bootstrap(
    config: &Arc<LuraConfig>,
    config_path: &Path,
    auto_shards: u16,
    frontend: &tokio::runtime::Handle,
) -> anyhow::Result<(Cluster, Started)> {
    // First: a capacity the channel rejects must fail while nothing runs yet.
    let capacity = config.multicore.shard_queue_capacity;
    let shard_0 = Lane::new(capacity);
    let wal_limit = config.storage.wal_max_bytes()?;

    // Before any data file opens: the data directories, the volumes they lie
    // on, the room to recover there and the memory budget.
    let base = std::env::current_dir().context("reading the working directory")?;
    #[cfg(not(test))]
    let probe: Arc<dyn resources::Probe> = Arc::new(resources::SystemProbe);
    // Tests read a roomy fake unless they set one for the server.
    #[cfg(test)]
    let probe = super::test_hook::probe(&config.storage.system_dir);
    let (watch, notices) = ResourceWatch::start(config, &base, probe)?;
    resources::log(&notices);
    coop::init(config.multicore.cpu_offload_threads);

    // The storage hub before every engine: it writes all their WALs. The
    // system store's directory must exist before the hub opens its WAL there.
    compio::fs::create_dir_all(&config.storage.system_dir)
        .await
        .with_context(|| format!("create storage.system_dir {}", config.storage.system_dir))?;
    let lock = system::lock_data_dir(Path::new(&config.storage.system_dir))?;
    let (storage_thread, hub) = start_storage_thread(config)?;

    // The system store before the engines: data laid out for another shard
    // count, or halfway through a change of it, must not be opened at all.
    let system_wal = WriteAheadLog::with_storage_handle(hub.clone(), WalTarget::Sys);
    let system_store = system::open_with_wal(Path::new(&config.storage.system_dir), system_wal).await?;
    system::refuse_pending_migration(&system_store).await?;
    let shards = layout::shard_count(config, &system_store, auto_shards).await?;
    layout::migrate(config, &system_store, shards).await?;
    system::check_shard_count(&system_store, shards).await?;
    tracing::info!("System store ready.");
    if let Some(notice) = watch.fixed_memory_notice(&resources::fixed_memory(config, shards)) {
        resources::log(&[notice]);
    }
    let (lanes, jobs): (Vec<Lane>, Vec<_>) =
        std::iter::once(shard_0).chain((1..shards).map(|_| Lane::new(capacity))).unzip();

    // Every log is recovered once, onto the instances of all shards, and cut
    // back only once every engine has flushed what it recovered.
    let memory = MemorySplit::of(config, shards);
    for line in memory.report(config, shards) {
        tracing::info!("{line}");
    }
    let wal = |target: WalTarget| {
        let hub = hub.clone();
        move || WriteAheadLog::with_storage_handle(hub.clone(), target)
    };
    let kv_files = EngineFiles {
        wal: PathBuf::from(&config.storage.wal_path),
        vlog: PathBuf::from(&config.storage.vlog_path),
        sstables: PathBuf::from(&config.storage.sstable_dir),
    };
    // Each data instance refuses its client writes while the watch says so.
    let resources = watch.resources();
    let gated = |options: LsmEngineOptions| LsmEngineOptions { resources: resources.clone(), ..options };
    let kv_gated = || gated(kv_options(config, &memory));
    let kv = recovery::open_sharded(&kv_files, shards, wal(WalTarget::Kv), kv_gated).await?;
    let mut wals = vec![(Engine::Kv, WriteAheadLog::with_storage_handle(hub.clone(), WalTarget::Kv))];
    let json = if config.json.enabled {
        let files = EngineFiles {
            wal: PathBuf::from(&config.json.wal_path),
            vlog: PathBuf::from(&config.json.vlog_path),
            sstables: PathBuf::from(&config.json.sstable_dir),
        };
        let options = || gated(JsonEngine::lsm_options(&config.json, memory.block_cache()));
        wals.push((Engine::Json, WriteAheadLog::with_storage_handle(hub.clone(), WalTarget::Json)));
        Some(recovery::open_sharded(&files, shards, wal(WalTarget::Json), options).await?)
    } else {
        tracing::info!("JSON engine disabled by config.");
        None
    };
    let rel = if config.rel.enabled {
        let files = EngineFiles {
            wal: PathBuf::from(&config.rel.wal_path),
            vlog: PathBuf::from(&config.rel.vlog_path),
            sstables: PathBuf::from(&config.rel.sstable_dir),
        };
        let options = || gated(RelEngine::lsm_options(&config.rel, memory.block_cache()));
        wals.push((Engine::Rel, WriteAheadLog::with_storage_handle(hub.clone(), WalTarget::Rel)));
        Some(recovery::open_sharded(&files, shards, wal(WalTarget::Rel), options).await?)
    } else {
        tracing::info!("Relational engine disabled by config.");
        None
    };
    for (_, wal) in &wals {
        wal.truncate().await?;
    }

    // Each data shard takes over its instances and reports ready.
    let mut threads = Vec::with_capacity(usize::from(shards));
    let mut readies = Vec::with_capacity(usize::from(shards));
    let mut starts = Vec::with_capacity(usize::from(shards));
    for (k, jobs) in jobs.into_iter().enumerate() {
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (ready, ready_rx) = oneshot::channel();
        let (start, start_rx) = oneshot::channel();
        let boot = ShardBoot {
            shard: k,
            shards,
            config: Arc::clone(config),
            kv: Arc::clone(&kv[k]),
            json: json.as_ref().map(|json| Arc::clone(&json[k])),
            rel: rel.as_ref().map(|rel| Arc::clone(&rel[k])),
            buffer_pool_pages: memory.buffer_pool_pages,
            jobs,
            commands: commands_rx,
            ready,
            start: start_rx,
        };
        match shard::spawn(boot, frontend.clone()) {
            Ok(thread) => {
                threads.push(ShardThread { commands, thread });
                readies.push(ready_rx);
                starts.push(start);
            }
            Err(e) => {
                Cluster::abort(threads, starts, storage_thread);
                return Err(e);
            }
        }
    }
    drop((kv, json, rel));

    let prepared = prepare_control(config, config_path, &threads, readies, &system_store, resources).await;
    let Prepared { states, trusted_cidrs, loops, shm_manager } = match prepared {
        Ok(prepared) => prepared,
        Err(e) => {
            Cluster::abort(threads, starts, storage_thread);
            return Err(e);
        }
    };

    // The first reading before any client or background writer runs; the
    // shards' own start writes, a default domain for one, went in before.
    let watch = Arc::new(parking_lot::Mutex::new(watch));
    resources::log(&watch.lock().tick());
    #[cfg(test)]
    super::test_hook::register_watch(&config.storage.system_dir, Arc::clone(&watch));

    // Released, the shards start their purgers and sweepers; then SHM.
    let mut reports = Vec::with_capacity(starts.len());
    for (start, state) in starts.into_iter().zip(&states) {
        let (started, report) = oneshot::channel();
        let _ = start.send(ShardStart { state: state.clone(), started });
        reports.push(report);
    }
    let mut system_loops = shard::Loops::new();
    system_loops.spawn("ResourceWatch", RESOURCE_WATCH_INTERVAL, move || {
        let watch = Arc::clone(&watch);
        async move {
            resources::log(&watch.lock().tick());
            Ok(())
        }
    });
    let logs = wals
        .iter()
        .map(|(engine, _)| (Holder::Shards(*engine), WalTarget::from(*engine)))
        .chain([(Holder::System, WalTarget::Sys)])
        .map(|(holder, target)| (holder, WriteAheadLog::with_storage_handle(hub.clone(), target)))
        .collect();
    let checkpoint = Arc::new(WalCheckpoint::new(Arc::clone(&states[0].control), logs, wal_limit));
    system_loops.spawn("WalCheckpoint", WAL_CHECKPOINT_INTERVAL, move || {
        let checkpoint = Arc::clone(&checkpoint);
        async move { checkpoint.tick().await }
    });
    if config.mcp.enabled && config.mcp.oauth_enabled && config.ttl_sweeper.enabled {
        let sweeper = Arc::new(TtlSweeper::new(Arc::clone(&system_store), config.ttl_sweeper.batch_size));
        let interval = std::time::Duration::from_secs(config.ttl_sweeper.interval_secs);
        system_loops.spawn("SystemTtlSweeper", interval, move || {
            let sweeper = Arc::clone(&sweeper);
            async move { sweeper.sweep_tick().await }
        });
    }
    let mut cluster = Cluster {
        shards: threads,
        loops,
        wals,
        system_store,
        system_loops,
        shm_manager,
        shm: None,
        storage_thread,
        lock,
        #[cfg(test)]
        system_dir: config.storage.system_dir.clone(),
    };
    let started = async {
        for report in reports {
            report.await.map_err(|_| anyhow::anyhow!("a data shard stopped during startup"))?;
        }
        cluster.shm_manager.as_ref().map(|manager| start_shm(config, manager, &states[0])).transpose()
    }
    .await;
    match started {
        Ok(shm) => cluster.shm = shm,
        Err(e) => {
            // The shards serve their lanes once released: those must go first.
            drop(lanes);
            cluster.shutdown().await;
            return Err(e);
        }
    }
    Ok((cluster, (lanes, states, trusted_cidrs)))
}

/// What the control plane prepared for the release of the shards.
struct Prepared {
    states: Vec<AppState>,
    trusted_cidrs: Arc<Vec<ParsedCidr>>,
    loops: Arc<AtomicBool>,
    shm_manager: Option<Arc<ShmManager>>,
}

/// Everything between the shards' reports and their release: the auth move
/// and cache, the control plane attached to every shard, the control plane's
/// own loops, backups, log access, the trusted CIDRs and SHM.
async fn prepare_control(
    config: &Arc<LuraConfig>,
    config_path: &Path,
    threads: &[ShardThread],
    readies: Vec<oneshot::Receiver<anyhow::Result<ShardOwners>>>,
    system_store: &Arc<LsmStorageEngine>,
    resources: Resources,
) -> anyhow::Result<Prepared> {
    let mut owners = Vec::with_capacity(readies.len());
    for ready in readies {
        owners.push(ready.await.map_err(|_| anyhow::anyhow!("a data shard stopped during startup"))??);
    }
    tracing::info!("{} data shard(s) ready.", owners.len());
    system::migrate_auth(owners[0].kv.engine(), system_store).await?;

    // The auth cache on the system store, after the auth move above.
    let oauth_resource =
        (config.mcp.enabled && config.mcp.oauth_enabled).then(|| crate::mcp::resource_url(&config.mcp.public_url));
    let auth_cache = Arc::new(AuthCache::new(Arc::clone(system_store), oauth_resource));
    auth_cache.load_from_engine().await?;
    reconcile_admins(&auth_cache, &config.auth.admins, config.auth.enabled).await?;
    tracing::info!("Auth cache loaded.");

    // The control plane is attached to every engine of every shard before
    // the shards start their purgers and before the listener accepts
    // requests: a purge finished behind its back would never reach the
    // directory or the event stream.
    let event_bus = Arc::new(crate::core::events::GlobalEventBus::new(
        config.events.channel_capacity,
        config.events.replay_buffer_size,
    ));
    let shards = owners
        .iter()
        .zip(threads)
        .map(|(owners, thread)| Shard { owners: owners.clone(), commands: thread.commands.clone() })
        .collect();
    let owners_auth = Owners { shards, auth: Arc::clone(&auth_cache) };
    let control = ControlPlane::start(owners_auth, Arc::clone(system_store), event_bus, resources).await?;

    let loops = spawn_loops(config);
    let backup_manager = init_backup(config, &control, &loops);
    let log_access = init_log_access(config);
    let trusted_cidrs = crate::api::middleware::parse_cidrs(&config.proxy.trusted_proxies)
        .map_err(|e| anyhow::anyhow!("Invalid trusted_proxies config: {}", e));
    let (backup_manager, trusted_cidrs) = match (backup_manager, trusted_cidrs) {
        (Ok(backup_manager), Ok(trusted_cidrs)) => (backup_manager, Arc::new(trusted_cidrs)),
        (Err(e), _) | (_, Err(e)) => {
            loops.store(true, Ordering::Relaxed);
            return Err(e);
        }
    };
    let shm_manager = match init_shm(config) {
        Ok(shm_manager) => shm_manager,
        Err(e) => {
            loops.store(true, Ordering::Relaxed);
            return Err(e);
        }
    };

    let states = owners
        .into_iter()
        .map(|owners| AppState {
            metrics: Arc::clone(owners.kv.metrics()),
            registry: owners.kv,
            auth_cache: Arc::clone(&auth_cache),
            auth_enabled: config.auth.enabled,
            json_engine: owners.json,
            rel_engine: owners.rel,
            shm_manager: shm_manager.clone(),
            backup_manager: backup_manager.clone(),
            log_access: log_access.clone(),
            control: Arc::clone(&control),
            config: Arc::clone(config),
            config_path: config_path.display().to_string(),
            config_file_loaded: config_path.exists(),
        })
        .collect();
    Ok(Prepared { states, trusted_cidrs, loops, shm_manager })
}

/// Settings of the key-value engine's domain layer.
pub(super) fn domain_config(cfg: &LuraConfig) -> DomainConfig {
    DomainConfig {
        max_name_length: cfg.domains.max_name_length,
        max_user_key_length: cfg.domains.max_user_key_length,
        default_domain: cfg.domains.default_domain.clone(),
        default_read_iops: cfg.rate_limit.default_read_iops,
        default_write_iops: cfg.rate_limit.default_write_iops,
        default_max_storage_bytes: cfg.rate_limit.default_max_storage_bytes,
        purger_batch_size: cfg.domains.purger_batch_size,
        purger_interval_secs: cfg.domains.purger_interval_secs,
        max_bulk_delete_keys: cfg.domains.max_bulk_delete_keys,
    }
}

/// Options of the key-value engine's LSM instances.
pub(super) fn kv_options(cfg: &LuraConfig, memory: &MemorySplit) -> LsmEngineOptions {
    LsmEngineOptions {
        engine: LsmEngineConfig {
            vlog_inline_threshold: cfg.lsm.vlog_inline_threshold,
            memtable_size_threshold: cfg.lsm.memtable_size_threshold,
            max_key_length: cfg.lsm.max_key_length,
            max_value_size: cfg.lsm.max_value_size,
            flush_check_interval_ms: cfg.lsm.flush_check_interval_ms,
            compaction_check_interval_ms: cfg.lsm.compaction_check_interval_ms,
            wal_event_channel_capacity: cfg.lsm.wal_event_channel_capacity,
            watch_replay_buffer_size: cfg.lsm.watch_replay_buffer_size,
            ..LsmEngineConfig::default()
        },
        compaction: CompactionConfig {
            l0_compaction_threshold: cfg.compaction.l0_threshold,
            l1_max_size: cfg.compaction.l1_max_size,
            level_size_ratio: cfg.compaction.level_size_ratio,
            max_sstable_size: cfg.compaction.max_sstable_size,
            low_watermark: None,
            bottommost: true,
        },
        janitor: JanitorConfig {
            check_interval_secs: cfg.janitor.check_interval_secs,
            dead_bytes_threshold: cfg.janitor.dead_bytes_threshold,
            min_vlog_size_bytes: cfg.janitor.min_vlog_size_bytes,
        },
        block_cache: memory.block_cache(),
        ..LsmEngineOptions::default()
    }
}

/// The storage hub: a dedicated OS thread driving a SQPOLL io_uring ring. It
/// owns the WAL of every enabled engine and writes them all; no engine
/// runs without it.
pub(super) fn start_storage_thread(cfg: &LuraConfig) -> anyhow::Result<(StorageThread, StorageHandle)> {
    let st_config = StorageThreadConfig {
        sqpoll_enabled: storage_thread::SQPOLL_ENABLED,
        sqpoll_idle_ms: storage_thread::SQPOLL_IDLE_MS,
        ring_depth: storage_thread::RING_DEPTH,
        channel_capacity: cfg.storage.wal_queue_capacity,
        cpu: storage_thread::STORAGE_THREAD_CPU,
        segment_bytes: storage_thread::WAL_SEGMENT_BYTES,
    };
    let mut wals = vec![
        (WalTarget::Kv, PathBuf::from(&cfg.storage.wal_path)),
        (WalTarget::Sys, Path::new(&cfg.storage.system_dir).join(system::WAL_FILE)),
    ];
    if cfg.json.enabled {
        wals.push((WalTarget::Json, PathBuf::from(&cfg.json.wal_path)));
    }
    if cfg.rel.enabled {
        wals.push((WalTarget::Rel, PathBuf::from(&cfg.rel.wal_path)));
    }
    StorageThread::new(st_config, wals).context("the storage thread failed to start")
}

/// The control plane's own loops — the log janitor, and the backup scheduler
/// once started; they stop once the returned flag is set.
fn spawn_loops(cfg: &LuraConfig) -> Arc<AtomicBool> {
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    if !cfg.log.path.is_empty() && cfg.log.retention_days > 0 {
        let janitor = logging::LogJanitor::new(&cfg.log.path, cfg.log.retention_days);
        let janitor_shutdown = Arc::clone(&shutdown_flag);
        compio::runtime::spawn(async move { janitor.run(janitor_shutdown).await }).detach();
    }
    shutdown_flag
}

/// The backup manager, with its scheduler on the control-plane thread.
/// Backups and restores reach every data shard through the control plane.
fn init_backup(
    cfg: &LuraConfig,
    control: &Arc<ControlPlane>,
    shutdown_flag: &Arc<AtomicBool>,
) -> anyhow::Result<Option<Arc<backup::BackupManager>>> {
    if !cfg.backup.enabled {
        tracing::info!("Backup disabled by config.");
        return Ok(None);
    }
    // Anyone who reaches the port can then pull full data exports.
    if !cfg.auth.enabled {
        tracing::warn!(
            "backup.enabled is true but auth.enabled is false — any client that reaches this port can create and download full backups."
        );
    }
    let manager = backup::BackupManager::new(&cfg.backup, Arc::clone(control))?;
    let scheduler = Arc::new(backup::scheduler::BackupScheduler::new(
        Arc::clone(&manager),
        &cfg.backup.schedule,
        Arc::clone(shutdown_flag),
    )?);
    compio::runtime::spawn(async move { scheduler.run().await }).detach();
    tracing::info!("Backup manager ready ({} schedule(s)).", cfg.backup.schedule.len());
    Ok(Some(manager))
}

// `LogConfig::validate` already guarantees `path` is non-empty whenever
// `http_access` is true, so no further checking is needed here.
fn init_log_access(cfg: &LuraConfig) -> Option<api::logs::LogAccessState> {
    if !cfg.log.http_access {
        tracing::info!("Log HTTP access disabled by config.");
        return None;
    }
    // With auth off, these endpoints are reachable by anyone who reaches
    // the port.
    if !cfg.auth.enabled {
        tracing::warn!(
            "log.http_access is true but auth.enabled is false — any client that reaches this port can read log files."
        );
    }
    tracing::info!("Log HTTP access ready.");
    Some(api::logs::LogAccessState { dir: std::path::PathBuf::from(&cfg.log.path), format: cfg.log.format.clone() })
}

/// The shared-memory segments, when SHM is enabled; the control plane runs
/// their services.
fn init_shm(cfg: &LuraConfig) -> anyhow::Result<Option<Arc<ShmManager>>> {
    if !cfg.shm.enabled {
        return Ok(None);
    }
    let manager = ShmManager::new(cfg.shm.clone())?;
    if let Some(state) = manager.get_segment("state") {
        // Safe: the segment outlives `manager` and is only touched via StateHeader.
        unsafe { crate::ipc::StateHeader::from_ptr(state.as_ptr(), state.len()) }.init();
    }
    tracing::info!("SHM manager ready (instance '{}'): state/data_a/data_b segments created.", cfg.shm.instance_id);
    Ok(Some(Arc::new(manager)))
}

/// The SHM services, tasks of the control-plane thread.
struct ShmServices {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    reg_task: compio::runtime::JoinHandle<()>,
    dispatcher_task: compio::runtime::JoinHandle<()>,
    publisher_task: compio::runtime::JoinHandle<()>,
    reg_socket: String,
}

impl ShmServices {
    /// Joins the services; the dispatcher drops its client connections on
    /// exit, unlinking every per-client segment, and the registration socket
    /// file is removed here.
    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.reg_task.await;
        let _ = self.dispatcher_task.await;
        let _ = self.publisher_task.await;
        uds::remove_socket_file(&self.reg_socket);
    }
}

/// Starts the registration listener, the command dispatcher and the snapshot
/// publisher over all data shards. Each client registers over its own UDS
/// and gets a dedicated cmd/resp ring quartet; the dispatcher polls them all.
/// The publisher counts into the metrics of shard 0's `state`.
fn start_shm(cfg: &LuraConfig, manager: &Arc<ShmManager>, state: &AppState) -> anyhow::Result<ShmServices> {
    let reg_path = cfg.shm.resolved_registration_socket_path();
    let listener = ipc::prepare_registration_socket(&reg_path)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let dispatcher = ipc::ShmDispatcher::new(Arc::clone(&state.control));
    let dispatcher_task = compio::runtime::spawn(dispatcher.run(events_rx, shutdown_rx.clone()));

    // Reader slots of the registered clients: the registration listener
    // leases them, the publisher scans them.
    let readers = Arc::new(ipc::ReaderRegistry::new());

    // RCU read-snapshot publisher: checks on an interval and after every
    // flush, rebuilds the SHM double-buffer snapshot only after a change,
    // and disconnects clients that block it longer than the kick threshold.
    // A task of this thread's own runtime: SnapshotWriter is !Send.
    let publisher = ipc::SnapshotPublisher::new(
        ipc::SnapshotBuilder::new(Arc::clone(&state.control), cfg.shm.data_buffer_size),
        Arc::clone(manager),
        std::time::Duration::from_millis(cfg.shm.snapshot_interval_ms),
        ipc::PUBLISH_WAIT_TIMEOUT_US,
        Arc::clone(&readers),
        Arc::clone(&state.metrics),
        std::time::Duration::from_secs(cfg.shm.kick_blocking_client_after_secs),
        shutdown_rx.clone(),
    );
    let publisher_task = compio::runtime::spawn(publisher.run());
    tracing::info!("SHM snapshot publisher active (interval {} ms)", cfg.shm.snapshot_interval_ms);

    let reg_config = ipc::RegistrationConfig {
        instance_id: cfg.shm.instance_id.clone(),
        ring_size: ipc::CLIENT_RING_SIZE,
        segment_mode: ipc::SEGMENT_MODE,
        auth_enabled: cfg.auth.enabled,
        trusted_uids: Arc::new(cfg.auth.trusted_uids.clone()),
        readers,
    };
    let reg_task = compio::runtime::spawn(ipc::serve_registration(listener, reg_config, events_tx, shutdown_rx));
    tracing::info!("SHM registration listener active on {reg_path}");
    Ok(ShmServices { shutdown_tx, reg_task, dispatcher_task, publisher_task, reg_socket: reg_path })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The block cache of each engine and the buffer pool split evenly
    // across the shards; the MemTable threshold stays per instance.
    #[test]
    fn the_memory_budgets_split_across_the_shards() {
        let mut config = LuraConfig::default();
        config.buffer_pool.pool_size = 1024;
        let one = MemorySplit::of(&config, 1);
        assert_eq!((one.block_cache_bytes, one.buffer_pool_pages), (64 * 1024 * 1024, 1024));
        let four = MemorySplit::of(&config, 4);
        assert_eq!((four.block_cache_bytes, four.buffer_pool_pages), (16 * 1024 * 1024, 256));
        assert_eq!(four.block_cache().capacity_bytes, 16 * 1024 * 1024);
        assert_eq!(kv_options(&config, &four).engine.memtable_size_threshold, config.lsm.memtable_size_threshold);

        config.buffer_pool.pool_size = 3;
        assert_eq!(MemorySplit::of(&config, 4).buffer_pool_pages, 1, "every shard keeps a page");
    }

    // The start log reports each shard's share; registered I/O buffers stay
    // with a single shard.
    #[test]
    fn the_start_log_reports_the_split_of_every_shard() {
        let mut config = LuraConfig::default();
        config.buffer_pool.pool_size = 1024;
        config.lsm.memtable_size_threshold = 4_194_304;
        config.io_engine.enabled = true;
        assert_eq!(
            MemorySplit::of(&config, 2).report(&config, 2),
            [
                "Shard 0: block cache 32768 KiB per engine; MemTable threshold 4194304 bytes per engine; \
                 buffer pool 512 pages; registered I/O buffers off.",
                "Shard 1: block cache 32768 KiB per engine; MemTable threshold 4194304 bytes per engine; \
                 buffer pool 512 pages; registered I/O buffers off.",
                "io_engine.enabled has no effect with more than one data shard.",
            ]
        );
        assert_eq!(
            MemorySplit::of(&config, 1).report(&config, 1),
            ["Shard 0: block cache 65536 KiB per engine; MemTable threshold 4194304 bytes per engine; \
              buffer pool 1024 pages; registered I/O buffers on."]
        );
    }
}
