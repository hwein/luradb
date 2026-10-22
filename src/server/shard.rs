//! A data shard's thread: takes over the engine instances the control plane
//! recovered for it, runs their background tasks, its domain purgers and
//! sweepers, its metrics ticker and the requests of its domains on its own
//! compio runtime, and flushes its engines when the control plane drains it.

use super::layout;
use crate::{
    api::{self, AppState},
    bridge::{self, Job},
    config::LuraConfig,
    control::{self, slots, Engine, ShardCommand, ShardOwners},
    core::{
        buffer_pool::BufferPoolManager,
        disk_manager::DiskManager,
        engine_runtime,
        io_engine::{IoEngine, REGISTERED_BUFFER_COUNT, REGISTERED_BUFFER_SIZE, VLOG_LOGICAL_ID, WAL_LOGICAL_ID},
    },
    engines::json::{domain as json_domain, JsonEngine},
    engines::lsm::{
        domain::{DomainPurger, DomainRegistry},
        engine::LsmStorageEngine,
        rate_limiter::DomainQuota,
        ttl_sweeper::TtlSweeper,
    },
    engines::rel::{domain as rel_domain, RelEngine},
    metrics::{MetricsConfig, MetricsStore, MetricsTicker},
};
use anyhow::Context;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

/// Everything a data shard's thread starts from.
pub(super) struct ShardBoot {
    pub(super) shard: usize,
    pub(super) shards: u16,
    pub(super) config: Arc<LuraConfig>,
    pub(super) kv: Arc<LsmStorageEngine>,
    pub(super) json: Option<Arc<LsmStorageEngine>>,
    pub(super) rel: Option<Arc<LsmStorageEngine>>,
    pub(super) buffer_pool_pages: usize,
    pub(super) jobs: mpsc::Receiver<Job>,
    pub(super) commands: mpsc::UnboundedReceiver<ShardCommand>,
    /// The shard's engines once they are up.
    pub(super) ready: oneshot::Sender<anyhow::Result<ShardOwners>>,
    /// The release; dropped unsent, the shard shuts down.
    pub(super) start: oneshot::Receiver<ShardStart>,
}

/// The release of a data shard by the control plane: its API state, and
/// where it reports that its loops run.
pub(super) struct ShardStart {
    pub(super) state: AppState,
    pub(super) started: oneshot::Sender<()>,
}

/// Starts the thread of data shard `boot.shard`. It enters `frontend`'s
/// handle for its whole life: `coop::offload`, `tokio::fs` and the IPC
/// sockets need a tokio context.
pub(super) fn spawn(boot: ShardBoot, frontend: tokio::runtime::Handle) -> anyhow::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("luradb-shard-{}", boot.shard))
        .spawn(move || {
            let _frontend = frontend.enter();
            match engine_runtime::build(super::remote_wakes(&boot.config)) {
                Ok(rt) => engine_runtime::run(&rt, run(boot)),
                Err(e) => {
                    let _ = boot.ready.send(Err(e));
                }
            }
        })
        .context("failed to start a data shard thread")
}

/// The shard's engine instances and the storage stack beside them.
struct Storage {
    instances: Vec<(Engine, Arc<LsmStorageEngine>)>,
    buffer_pool: Option<Arc<BufferPoolManager>>,
    /// Registered buffers and files stay alive for the whole run; dropping
    /// this closes their descriptors (a blocking `close(2)` each).
    io_engine: Option<IoEngine>,
}

async fn run(boot: ShardBoot) {
    let mut instances = vec![(Engine::Kv, Arc::clone(&boot.kv))];
    instances.extend(boot.json.clone().map(|json| (Engine::Json, json)));
    instances.extend(boot.rel.clone().map(|rel| (Engine::Rel, rel)));
    for (_, instance) in &instances {
        instance.start_background_tasks();
    }
    let mut storage = Storage { instances, buffer_pool: None, io_engine: None };
    let opened = open(&mut storage, &boot).await;
    let ShardBoot { config, jobs, commands, ready, start, .. } = boot;
    #[cfg(test)]
    let shard = boot.shard;
    let owners = match opened {
        Ok(owners) => owners,
        Err(e) => {
            let _ = ready.send(Err(e));
            close(&storage).await;
            return;
        }
    };
    #[cfg(test)]
    super::test_hook::record(&config.storage.system_dir, format!("shard {shard} ready"));
    if ready.send(Ok(owners.clone())).is_err() {
        close(&storage).await;
        return;
    }
    let Ok(ShardStart { state, started }) = start.await else {
        close(&storage).await;
        return;
    };

    #[cfg(test)]
    super::test_hook::record(&config.storage.system_dir, format!("shard {shard} released"));
    compio::runtime::spawn(MetricsTicker::new(Arc::clone(owners.kv.metrics())).run()).detach();
    #[cfg(test)]
    super::test_hook::register_metrics(&config.storage.system_dir, Arc::clone(owners.kv.metrics()));
    let loops = spawn_loops(&config, &owners);
    let _ = started.send(());
    let serving = compio::runtime::spawn(bridge::serve_engine(jobs, api::create_router(state)));
    #[cfg(test)]
    let commands = if super::test_hook::pings_silenced(&config.storage.system_dir, shard) {
        unanswered_pings(commands)
    } else {
        commands
    };
    let drained = control::serve_shard(owners, commands).await;
    #[cfg(test)]
    super::test_hook::record(&config.storage.system_dir, format!("shard {shard} draining"));

    // Every sender of the shard's lane is gone by now; the request loop ends
    // after dropping the requests still in flight.
    let _ = serving.await;
    loops.stop().await;
    let flushed = close(&storage).await;
    if let Some(reply) = drained {
        let _ = reply.send(flushed);
    }
    drop(storage.io_engine);
}

/// Puts the page store, the registered buffers (shard 0 of a single one
/// only) and the domain layers, with a metrics store of their own, on the
/// shard's instances. Only the shard that owns the default domain creates it.
async fn open(storage: &mut Storage, boot: &ShardBoot) -> anyhow::Result<ShardOwners> {
    let ShardBoot { shard, shards, config, kv, json, rel, buffer_pool_pages, .. } = boot;
    let (shard, shards) = (*shard, *shards);
    let metrics = MetricsStore::new(MetricsConfig::default());
    let owns = |name: &str| usize::from(slots::shard_of_domain(name, shards)) == shard;

    let db_path = layout::shard_file(Path::new(&config.storage.db_path), shard);
    let disk_manager = DiskManager::new(&db_path).await?;
    storage.buffer_pool = Some(Arc::new(BufferPoolManager::new(*buffer_pool_pages, disk_manager)));
    if shard == 0 && shards == 1 {
        let vlog_path = layout::shard_file(Path::new(&config.storage.vlog_path), 0);
        storage.io_engine = init_io_engine(config, Path::new(&config.storage.wal_path), &vlog_path).await;
        if let Some(io_engine) = storage.io_engine.as_mut() {
            kv.register_sstables_with_io_engine(io_engine).await?;
        }
    }

    let domain_config = super::control::domain_config(config);
    let owns_kv_default = owns(&domain_config.default_domain);
    let registry = Arc::new(
        DomainRegistry::recover_on_shard(Arc::clone(kv), domain_config, Arc::clone(&metrics), owns_kv_default).await?,
    );
    let json = match json {
        Some(json) => Some(
            JsonEngine::open(&config.json, Arc::clone(json), Arc::clone(&metrics), owns(json_domain::DEFAULT_DOMAIN))
                .await?,
        ),
        None => None,
    };
    let rel = match rel {
        Some(rel) => {
            // Same-named KV and JSON domains live on this shard too.
            let resolver = crate::engines::rel::CrossEngineResolver::new(
                Some(Arc::clone(&registry)),
                json.clone(),
                Arc::clone(&metrics),
            );
            let quota = DomainQuota {
                read_iops: config.rate_limit.default_read_iops,
                write_iops: config.rate_limit.default_write_iops,
                max_storage_bytes: config.rate_limit.default_max_storage_bytes,
            };
            let owns_default = owns(rel_domain::DEFAULT_DOMAIN);
            Some(RelEngine::open(&config.rel, quota, Arc::clone(rel), Arc::clone(&metrics), resolver, owns_default).await?)
        }
        None => None,
    };
    Ok(ShardOwners { kv: registry, json, rel })
}

/// Stops the instances' background tasks and flushes each instance once its
/// writes in flight have applied, then the page store; the result of each
/// instance's flush.
async fn close(storage: &Storage) -> Vec<(Engine, anyhow::Result<()>)> {
    let mut flushed = Vec::with_capacity(storage.instances.len());
    for (engine, instance) in &storage.instances {
        instance.quiesce_writes().await;
        flushed.push((*engine, instance.shutdown_flush().await));
    }
    if let Some(buffer_pool) = &storage.buffer_pool {
        if let Err(e) = buffer_pool.flush_all_pages().await {
            tracing::error!("Failed to flush pages: {}", e);
        }
    }
    flushed
}

/// The registered buffers, with the WAL and the value log registered.
async fn init_io_engine(cfg: &LuraConfig, wal_path: &Path, vlog_path: &Path) -> Option<IoEngine> {
    if !cfg.io_engine.enabled {
        return None;
    }
    let mut engine = match IoEngine::new(REGISTERED_BUFFER_COUNT, REGISTERED_BUFFER_SIZE) {
        Ok(engine) => engine,
        Err(e) => {
            tracing::warn!("IoEngine disabled: {e}. Continuing without registered buffers.");
            return None;
        }
    };
    let registered = match engine.register_file(WAL_LOGICAL_ID, wal_path).await {
        Ok(()) => engine.register_file(VLOG_LOGICAL_ID, vlog_path).await,
        err => err,
    };
    match registered {
        Ok(()) => {
            tracing::info!(
                "IoEngine ready: {REGISTERED_BUFFER_COUNT} registered buffers x {REGISTERED_BUFFER_SIZE} bytes."
            );
            Some(engine)
        }
        Err(e) => {
            tracing::warn!(
                "IoEngine disabled: WAL/VLog registration failed: {e}. Continuing without registered buffers."
            );
            None
        }
    }
}

/// Purgers and sweepers of a shard or the control plane: each a task that
/// runs a tick, then sleeps its interval, until [`Loops::stop`].
pub(super) struct Loops {
    /// Dropped to wake every loop out of its sleep.
    stop: watch::Sender<()>,
    tasks: Vec<compio::runtime::JoinHandle<()>>,
}

impl Loops {
    pub(super) fn new() -> Self {
        Self { stop: watch::channel(()).0, tasks: Vec::new() }
    }

    /// Runs `tick` every `interval`; a failed tick is logged.
    pub(super) fn spawn<F, Fut>(&mut self, name: &'static str, interval: Duration, tick: F)
    where
        F: Fn() -> Fut + 'static,
        Fut: Future<Output = anyhow::Result<()>> + 'static,
    {
        let mut stop = self.stop.subscribe();
        self.tasks.push(compio::runtime::spawn(async move {
            loop {
                if let Err(e) = tick().await {
                    tracing::warn!("[{name}] {e:#}");
                }
                tokio::select! {
                    _ = compio::time::sleep(interval) => {}
                    _ = stop.changed() => break,
                }
            }
        }));
    }

    /// Returns once every loop has ended the tick it was in.
    pub(super) async fn stop(self) {
        drop(self.stop);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Spawns the shard's purgers and sweepers.
fn spawn_loops(cfg: &LuraConfig, owners: &ShardOwners) -> Loops {
    let mut loops = Loops::new();
    let lsm_store = owners.kv.engine();

    let purger = Arc::new(DomainPurger::new(Arc::clone(lsm_store), Arc::clone(&owners.kv), cfg.domains.purger_batch_size));
    loops.spawn("DomainPurger", Duration::from_secs(cfg.domains.purger_interval_secs), move || {
        let purger = Arc::clone(&purger);
        async move { purger.purge_tick().await }
    });

    // KV only: JSON and rel never write an `expire_at`.
    if cfg.ttl_sweeper.enabled {
        let sweeper = Arc::new(TtlSweeper::new(Arc::clone(lsm_store), cfg.ttl_sweeper.batch_size));
        loops.spawn("TtlSweeper", Duration::from_secs(cfg.ttl_sweeper.interval_secs), move || {
            let sweeper = Arc::clone(&sweeper);
            async move { sweeper.sweep_tick().await }
        });
    }

    if let Some(engine) = &owners.json {
        let json_purger = Arc::new(crate::engines::json::JsonDomainPurger::new(
            Arc::clone(engine),
            crate::engines::json::purger::PURGER_BATCH_SIZE,
        ));
        let interval = Duration::from_secs(crate::engines::json::purger::PURGER_INTERVAL_SECS);
        loops.spawn("JsonDomainPurger", interval, move || {
            let purger = Arc::clone(&json_purger);
            async move { purger.purge_tick().await }
        });
    }

    if let Some(engine) = &owners.rel {
        if engine.cross_engine_has_target() {
            let sweeper = Arc::new(crate::engines::rel::RelCrossEngineSweeper::new(
                Arc::clone(engine),
                crate::engines::rel::cross_engine::SWEEP_BATCH_SIZE,
            ));
            let interval = Duration::from_secs(crate::engines::rel::cross_engine::SWEEP_INTERVAL_SECS);
            loops.spawn("RelCrossEngineSweeper", interval, move || {
                let sweeper = Arc::clone(&sweeper);
                async move { sweeper.sweep_tick().await }
            });
        }
        let rel_purger = Arc::new(crate::engines::rel::RelDomainPurger::new(
            Arc::clone(engine),
            crate::engines::rel::purger::PURGER_BATCH_SIZE,
        ));
        let interval = Duration::from_secs(crate::engines::rel::purger::PURGER_INTERVAL_SECS);
        loops.spawn("RelDomainPurger", interval, move || {
            let purger = Arc::clone(&rel_purger);
            async move { purger.purge_tick().await }
        });
    }

    loops
}

/// Relays `commands` but keeps every ping unanswered until the control plane
/// lets go of the shard.
#[cfg(test)]
fn unanswered_pings(mut commands: mpsc::UnboundedReceiver<ShardCommand>) -> mpsc::UnboundedReceiver<ShardCommand> {
    let (relay, relayed) = mpsc::unbounded_channel();
    compio::runtime::spawn(async move {
        let mut pings = Vec::new();
        while let Some(command) = commands.recv().await {
            match command {
                ShardCommand::Ping { reply } => pings.push(reply),
                command => {
                    if relay.send(command).is_err() {
                        break;
                    }
                }
            }
        }
    })
    .detach();
    relayed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::engine::{LsmEngineOptions, TestHook, TestHooks};
    use crate::engines::StorageEngine;

    /// A key-value instance with its own log under `dir`, and that log.
    async fn instance(dir: &Path, hooks: TestHooks) -> (Arc<LsmStorageEngine>, Arc<WriteAheadLog>) {
        let (wal_path, vlog_path) = (dir.join("wal.log"), dir.join("vlog.log"));
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(dir).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(dir));
        let options = LsmEngineOptions::default();
        let mut engine =
            LsmStorageEngine::new(Arc::clone(&wal), wal_path, vlog, vlog_path, fm, mm, options).await.unwrap();
        engine.hooks = hooks;
        (Arc::new(engine), wal)
    }

    // A loop's write that is in the log but not yet in the MemTable when the
    // shard shuts down, and the write its tick makes a while later, are both
    // flushed before the log is cut back: a restart finds them.
    #[test]
    fn the_writes_of_a_tick_in_progress_at_shutdown_survive_a_restart() {
        engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hook = Arc::new(TestHook::default());
            let hooks = TestHooks { before_kv_pair_apply: Some((b"held".to_vec(), Arc::clone(&hook))), ..Default::default() };
            let (kv, wal) = instance(dir.path(), hooks).await;
            let mut loops = Loops::new();
            let writer = Arc::clone(&kv);
            loops.spawn("writer", Duration::from_secs(3600), move || {
                let kv = Arc::clone(&writer);
                async move {
                    kv.put(b"held", b"v").await?;
                    for _ in 0..50 {
                        tokio::task::yield_now().await;
                    }
                    kv.put(b"later", b"v").await
                }
            });
            hook.reached.notified().await;

            let storage = Storage { instances: vec![(Engine::Kv, Arc::clone(&kv))], buffer_pool: None, io_engine: None };
            let shutdown = compio::runtime::spawn(async move {
                loops.stop().await;
                close(&storage).await
            });
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            hook.release.notify_one();
            let flushed = shutdown.await.unwrap();
            assert!(flushed.iter().all(|(_, result)| result.is_ok()));
            // As the control plane does once every shard flushed.
            wal.truncate().await.unwrap();
            drop(kv);

            let (kv, _) = instance(dir.path(), TestHooks::default()).await;
            for key in ["held", "later"] {
                assert_eq!(kv.get(key.as_bytes()).await.unwrap(), Some(b"v".to_vec()), "{key}");
            }
        })
    }
}
