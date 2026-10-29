//! Control plane: runs the rare, global mutations — domain create and delete
//! in every engine, auth changes — one at a time on a single worker task,
//! holds the directory of all domains, owns the system store, is the one
//! publisher of the global event stream and takes consistent cuts, metrics
//! samples and write-ahead log checkpoints across the data shards.

pub mod checkpoint;
pub mod resources;
pub mod slots;
pub mod system;

use crate::auth::oauth::{OAuthClient, RedeemCode, Refresh, TokenRecord};
use crate::auth::{AuthCache, DomainPermission, UserRecord};
use crate::core::events::GlobalEventBus;
use crate::engines::json::{JsonDomain, JsonDomainState, JsonEngine, JsonStoreError};
use crate::engines::lsm::domain::{Domain, DomainRegistry, DomainState};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::reader::{RegistrySnapshot, Snapshot};
use crate::engines::rel::{RelDomain, RelDomainState, RelEngine, RelStoreError};
use crate::metrics::MetricsSample;
use anyhow::Context;
use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Storage engine a domain lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Engine {
    Kv,
    Json,
    Rel,
}

impl Engine {
    /// The engine's tag on the global event stream.
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::Kv => "kv",
            Engine::Json => "json",
            Engine::Rel => "rel",
        }
    }
}

/// The write-ahead log an engine writes on the storage hub.
impl From<Engine> for crate::core::storage_thread::WalTarget {
    fn from(engine: Engine) -> Self {
        match engine {
            Engine::Kv => Self::Kv,
            Engine::Json => Self::Json,
            Engine::Rel => Self::Rel,
        }
    }
}

/// Lifecycle state of a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Active,
    /// Takes no requests; the purger removes its data.
    Deleting,
}

impl Lifecycle {
    /// The state as the domain endpoints show it.
    pub fn as_str(self) -> &'static str {
        match self {
            Lifecycle::Active => "active",
            Lifecycle::Deleting => "deleting",
        }
    }
}

/// A domain as the directory lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEntry {
    pub name: String,
    pub engine: Engine,
    pub state: Lifecycle,
    pub slot: u16,
    /// Unix seconds.
    pub created_at: u64,
    /// Always false for relational domains, which have no such setting.
    pub require_conditional_writes: bool,
}

impl DomainEntry {
    fn new(engine: Engine, name: &str, state: Lifecycle, created_at: u64, require_conditional_writes: bool) -> Self {
        Self {
            name: name.to_string(),
            engine,
            state,
            slot: slots::slot_of_domain(name),
            created_at,
            require_conditional_writes,
        }
    }

    fn kv(d: &Domain) -> Self {
        let state = match d.state {
            DomainState::Active => Lifecycle::Active,
            DomainState::Deleting => Lifecycle::Deleting,
        };
        Self::new(Engine::Kv, &d.name, state, d.created_at, d.require_conditional_writes)
    }

    fn json(d: &JsonDomain) -> Self {
        let state = match d.state {
            JsonDomainState::Active => Lifecycle::Active,
            JsonDomainState::Deleting => Lifecycle::Deleting,
        };
        Self::new(Engine::Json, &d.name, state, d.created_at, d.require_conditional_writes)
    }

    fn rel(d: &RelDomain) -> Self {
        let state = match d.state {
            RelDomainState::Active => Lifecycle::Active,
            RelDomainState::Deleting => Lifecycle::Deleting,
        };
        Self::new(Engine::Rel, &d.name, state, d.created_at, false)
    }
}

/// Every domain of every engine; read-only, replaced as a whole on change.
#[derive(Debug, Clone, Default)]
pub struct Directory {
    entries: BTreeMap<(Engine, String), DomainEntry>,
    generation: u64,
}

impl Directory {
    async fn of(shards: &[Shard]) -> anyhow::Result<Self> {
        let mut directory = Self::default();
        for Shard { owners, .. } in shards {
            let kv = owners.kv.list_domains().await?.into_iter().chain(owners.kv.list_deleting_domains());
            kv.for_each(|d| directory.insert(DomainEntry::kv(&d)));
            if let Some(json) = &owners.json {
                json.list_domains().iter().for_each(|d| directory.insert(DomainEntry::json(d)));
            }
            if let Some(rel) = &owners.rel {
                rel.list_domains().iter().for_each(|d| directory.insert(DomainEntry::rel(d)));
            }
        }
        Ok(directory)
    }

    /// The domains of `engine`, ordered by name.
    pub fn domains(&self, engine: Engine) -> impl Iterator<Item = &DomainEntry> {
        self.entries.values().filter(move |entry| entry.engine == engine)
    }

    pub fn get(&self, engine: Engine, name: &str) -> Option<&DomainEntry> {
        self.entries.get(&(engine, name.to_string()))
    }

    /// Counts the changes since the start: equal generations, equal directories.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn insert(&mut self, entry: DomainEntry) {
        self.entries.insert((entry.engine, entry.name.clone()), entry);
    }

    fn set_deleting(&mut self, engine: Engine, name: &str) {
        if let Some(entry) = self.entries.get_mut(&(engine, name.to_string())) {
            entry.state = Lifecycle::Deleting;
        }
    }

    fn remove(&mut self, engine: Engine, name: &str) {
        self.entries.remove(&(engine, name.to_string()));
    }
}

/// A failed domain create or delete, in the error type of its engine.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("{0}")]
    Kv(anyhow::Error),
    #[error(transparent)]
    Json(#[from] JsonStoreError),
    #[error(transparent)]
    Rel(#[from] RelStoreError),
    /// The engine is disabled by config.
    #[error("the {} engine is disabled", .0.as_str())]
    Disabled(Engine),
    /// The worker that runs the commands is gone.
    #[error("the control plane is not running")]
    Stopped,
}

/// A change to the auth records.
#[derive(Debug)]
pub enum AuthChange {
    UpsertUser(UserRecord),
    /// Removes the user and all its permissions.
    RemoveUser(String),
    RotateKey { name: String, new_hash: String },
    SetPermission(DomainPermission),
    RemovePermission { username: String, domain: String },
    RegisterClient(OAuthClient),
    IssueCode { hash: String, record: TokenRecord, now: u64 },
    RedeemCode(RedeemCode),
    Refresh(Refresh),
    RevokeToken { hash: String },
}

enum Command {
    CreateDomain {
        engine: Engine,
        name: String,
        require_conditional_writes: bool,
        reply: oneshot::Sender<Result<DomainEntry, DomainError>>,
    },
    DeleteDomain { engine: Engine, name: String, reply: oneshot::Sender<Result<(), DomainError>> },
    FinalizeDeletion { engine: Engine, name: String, reply: oneshot::Sender<anyhow::Result<()>> },
    ChangeAuth { change: AuthChange, reply: oneshot::Sender<anyhow::Result<()>> },
}

/// The engines of one data shard.
#[derive(Clone)]
pub struct ShardOwners {
    pub kv: Arc<DomainRegistry>,
    pub json: Option<Arc<JsonEngine>>,
    pub rel: Option<Arc<RelEngine>>,
}

impl ShardOwners {
    /// The LSM instance of `engine`; `None` when the engine is disabled.
    fn instance(&self, engine: Engine) -> Option<&Arc<LsmStorageEngine>> {
        match engine {
            Engine::Kv => Some(self.kv.engine()),
            Engine::Json => self.json.as_ref().map(|json| json.engine()),
            Engine::Rel => self.rel.as_ref().map(|rel| rel.engine()),
        }
    }

    async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        match engine {
            Engine::Kv => self.kv.finalize_domain_deletion(name).await,
            Engine::Json => {
                Ok(self.json.as_ref().ok_or(DomainError::Disabled(Engine::Json))?.finalize_deletion(name).await?)
            }
            Engine::Rel => Ok(self.rel.as_ref().ok_or(DomainError::Disabled(Engine::Rel))?.finalize_deletion(name).await?),
        }
    }

    async fn quiesce(&self, engine: Engine) {
        match engine {
            Engine::Kv => self.kv.engine().quiesce_writes().await,
            Engine::Json => {
                if let Some(json) = &self.json {
                    json.quiesce_writes().await;
                }
            }
            Engine::Rel => {
                if let Some(rel) = &self.rel {
                    rel.quiesce_writes().await;
                }
            }
        }
    }
}

/// A command the control plane sends to a data shard; the commands run on
/// the shard's thread, one after the other, but a `Quiesce` waits in a task
/// of its own.
pub enum ShardCommand {
    /// Answers once every write of `engine` admitted so far has applied;
    /// later ones see the current domain state. Waits beside the commands
    /// after it.
    Quiesce { engine: Engine, reply: oneshot::Sender<()> },
    /// Removes the deleted domain `name` of `engine`, whose data the purger
    /// has removed.
    FinalizeDeletion { engine: Engine, name: String, reply: oneshot::Sender<anyhow::Result<()>> },
    /// Registers a snapshot of `engine` at once and answers with it.
    Pin { engine: Engine, reply: oneshot::Sender<RegistrySnapshot> },
    /// Holds back the writes of `engine` once the ones in flight have
    /// applied and says so on `drained`; once `register` fires, registers a
    /// snapshot, lets the writes go on and answers with the snapshot.
    Confirm {
        engine: Engine,
        drained: oneshot::Sender<()>,
        register: oneshot::Receiver<()>,
        reply: oneshot::Sender<RegistrySnapshot>,
    },
    /// Like `Confirm` for every engine of the shard: once `sample` fires,
    /// answers with a sample of the shard's metrics, taken while its writes
    /// are held back.
    Sample { drained: oneshot::Sender<()>, sample: oneshot::Receiver<()>, reply: oneshot::Sender<MetricsSample> },
    /// Raises the flushed LSN of the instance of `engine` to `up_to`, an LSN
    /// durable in the engine's write-ahead log, in a task of its own beside
    /// the commands after it, and answers with the result.
    Persist { engine: Engine, up_to: u64, reply: oneshot::Sender<anyhow::Result<()>> },
    /// Applies `write` to the key-value domain `domain` in a task of its own,
    /// beside the commands after it, and answers with the result.
    WriteKv { domain: String, write: KvWrite, reply: oneshot::Sender<anyhow::Result<()>> },
    /// Answers at once, behind the commands before it but not behind the
    /// wait of a `Quiesce`.
    Ping { reply: oneshot::Sender<()> },
    /// Ends the command loop once every `Quiesce` before it has answered;
    /// the shard then shuts its engines down and answers with the result of
    /// each one's final flush.
    Drain { reply: DrainReply },
}

/// Where a shard reports the final flush of each of its engines.
pub type DrainReply = oneshot::Sender<Vec<(Engine, anyhow::Result<()>)>>;

/// A single-key write to a key-value domain, as the domain's store runs it.
#[derive(Debug)]
pub enum KvWrite {
    /// `ttl_secs` 0 = no expiry.
    Put { key: Vec<u8>, value: Vec<u8>, ttl_secs: u64 },
    Delete { key: Vec<u8> },
    SetNull { key: Vec<u8> },
}

impl KvWrite {
    async fn apply(self, registry: &DomainRegistry, domain: &str) -> anyhow::Result<()> {
        let store = registry.store(domain).await?;
        match self {
            KvWrite::Put { key, value, ttl_secs: 0 } => store.put(&key, &value).await,
            KvWrite::Put { key, value, ttl_secs } => store.put_with_ttl(&key, &value, ttl_secs).await,
            KvWrite::Delete { key } => store.delete(&key).await,
            KvWrite::SetNull { key } => store.set_null(&key).await,
        }
    }
}

/// Runs the commands for the shard of `owners` until a `Drain` arrives, and
/// hands that one back; `None` once the control plane is gone.
pub async fn serve_shard(owners: ShardOwners, mut commands: mpsc::UnboundedReceiver<ShardCommand>) -> Option<DrainReply> {
    let mut quiesces: Vec<compio::runtime::JoinHandle<()>> = Vec::new();
    while let Some(command) = commands.recv().await {
        match command {
            ShardCommand::Quiesce { engine, reply } => {
                quiesces.retain(|quiesce| !quiesce.is_finished());
                let owners = owners.clone();
                quiesces.push(compio::runtime::spawn(async move {
                    owners.quiesce(engine).await;
                    let _ = reply.send(());
                }));
            }
            ShardCommand::FinalizeDeletion { engine, name, reply } => {
                let _ = reply.send(owners.finalize_deletion(engine, &name).await);
            }
            ShardCommand::Pin { engine, reply } => {
                if let Some(instance) = owners.instance(engine) {
                    let _ = reply.send(instance.snapshot().await);
                }
            }
            ShardCommand::Confirm { engine, drained, register, reply } => {
                if let Some(instance) = owners.instance(engine) {
                    let drain = instance.drain_writes().await;
                    let _ = drained.send(());
                    let _ = register.await;
                    let snapshot = instance.snapshot().await;
                    drop(drain);
                    let _ = reply.send(snapshot);
                }
            }
            ShardCommand::Sample { drained, sample, reply } => {
                let mut drains = Vec::with_capacity(3);
                for engine in [Engine::Kv, Engine::Json, Engine::Rel] {
                    if let Some(instance) = owners.instance(engine) {
                        drains.push(instance.drain_writes().await);
                    }
                }
                let _ = drained.send(());
                let _ = sample.await;
                // A write on this thread counts itself right after it applies,
                // before the drain can take over: each is in or out with its count.
                let taken = owners.kv.metrics().sample();
                drop(drains);
                let _ = reply.send(taken);
            }
            ShardCommand::Persist { engine, up_to, reply } => {
                let instance = owners.instance(engine).cloned();
                compio::runtime::spawn(async move {
                    let persisted = match instance {
                        Some(instance) => instance.raise_flushed_lsn(up_to).await,
                        None => Err(DomainError::Disabled(engine).into()),
                    };
                    let _ = reply.send(persisted);
                })
                .detach();
            }
            ShardCommand::WriteKv { domain, write, reply } => {
                let registry = Arc::clone(&owners.kv);
                compio::runtime::spawn(async move {
                    let _ = reply.send(write.apply(&registry, &domain).await);
                })
                .detach();
            }
            ShardCommand::Ping { reply } => {
                let _ = reply.send(());
            }
            ShardCommand::Drain { reply } => {
                for quiesce in quiesces {
                    let _ = quiesce.await;
                }
                return Some(reply);
            }
        }
    }
    None
}

/// A data shard as the control plane reaches it: its engines, and the
/// channel to its thread for what must run there.
#[derive(Clone)]
pub struct Shard {
    pub owners: ShardOwners,
    pub commands: mpsc::UnboundedSender<ShardCommand>,
}

impl Shard {
    async fn request<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> ShardCommand) -> anyhow::Result<T> {
        let (reply, answer) = oneshot::channel();
        self.commands.send(command(reply)).map_err(|_| anyhow::anyhow!("the data shard is not running"))?;
        answer.await.map_err(|_| anyhow::anyhow!("the data shard did not answer"))
    }
}

/// What the control plane runs its commands against: every data shard, by
/// index, and the auth records.
pub struct Owners {
    pub shards: Vec<Shard>,
    pub auth: Arc<AuthCache>,
}

/// A consistent cut through one engine across all data shards: one read
/// snapshot per shard, all taken while every shard held its writes back.
/// Holds the snapshots registered until it drops.
pub struct Cut {
    /// The engine's write-ahead log up to this LSN is in the cut; writes that
    /// applied a later record before the cut was taken are in it too.
    pub s: u64,
    /// The read snapshot of each data shard, by shard index.
    pub reads: Vec<(u16, RegistrySnapshot)>,
    /// The system store as of the cut.
    pub system: RegistrySnapshot,
}

impl Cut {
    /// The read snapshot of data shard `shard`.
    pub fn read_of(&self, shard: u16) -> &Snapshot {
        self.reads[usize::from(shard)].1.snapshot()
    }

    /// The newest stamp among the shards' read snapshots.
    pub fn max_stamp(&self) -> u64 {
        self.reads.iter().map(|(_, read)| read.snapshot().timestamp().as_u64()).max().unwrap_or(0)
    }
}

pub struct ControlPlane {
    commands: mpsc::UnboundedSender<Command>,
    directory: RwLock<Arc<Directory>>,
    bus: Arc<GlobalEventBus>,
    system: Arc<LsmStorageEngine>,
    shards: Vec<Shard>,
    /// One held round at a time: two whose commands reach the shards in
    /// different orders would each hold one shard and wait for the other.
    rounds: tokio::sync::Mutex<()>,
    /// Set while a restore job runs; see [`Self::restore_running`].
    restoring: AtomicBool,
    /// The last ping sent to each data shard, by shard index.
    pings: Mutex<Vec<Option<Shared<BoxFuture<'static, bool>>>>>,
    resources: resources::Resources,
}

/// Marks a restore as running until it drops, on every exit path.
pub(crate) struct RestoreRunning<'a>(&'a ControlPlane);

impl Drop for RestoreRunning<'_> {
    fn drop(&mut self) {
        self.0.restoring.store(false, Ordering::SeqCst);
    }
}

impl ControlPlane {
    /// Reads the owners' domains into the directory, attaches itself to the
    /// engines of every shard — before any purger runs, so none finishes a
    /// deletion behind its back — and starts the worker on the current
    /// runtime.
    pub async fn start(
        owners: Owners,
        system: Arc<LsmStorageEngine>,
        bus: Arc<GlobalEventBus>,
        resources: resources::Resources,
    ) -> anyhow::Result<Arc<Self>> {
        let Owners { shards, auth } = owners;
        let (commands, inbox) = mpsc::unbounded_channel();
        let control = Arc::new(Self {
            commands,
            directory: RwLock::new(Arc::new(Directory::of(&shards).await?)),
            bus,
            system,
            pings: Mutex::new(vec![None; shards.len()]),
            shards,
            rounds: tokio::sync::Mutex::new(()),
            restoring: AtomicBool::new(false),
            resources,
        });
        for Shard { owners, .. } in &control.shards {
            owners.kv.attach_control_plane(Arc::clone(&control));
            if let Some(json) = &owners.json {
                json.attach_control_plane(Arc::clone(&control));
            }
            if let Some(rel) = &owners.rel {
                rel.attach_control_plane(Arc::clone(&control));
            }
        }
        let worker = Worker { auth, control: Arc::clone(&control) };
        compio::runtime::spawn(worker.run(inbox)).detach();
        Ok(control)
    }

    /// The data shard that owns the domain `name`.
    fn owner(&self, name: &str) -> &Shard {
        &self.shards[usize::from(self.shard_of(name))]
    }

    /// How many data shards run.
    pub fn shard_count(&self) -> u16 {
        u16::try_from(self.shards.len()).expect("at most u16::MAX data shards")
    }

    /// Index of the data shard that owns the domain `name`.
    pub fn shard_of(&self, name: &str) -> u16 {
        slots::shard_of_domain(name, self.shard_count())
    }

    /// Takes a consistent cut through `engine` across all data shards. Every
    /// shard first registers a snapshot, which keeps the versions the cut
    /// may need from compaction; `s` is read after that. Then every shard
    /// lets its writes in flight apply and holds new ones back, and only once
    /// all of them do, each registers its read snapshot and lets its writes
    /// go on: a write confirmed before another one that is in the cut is in
    /// it too. Waits for at most one group commit per shard.
    pub async fn consistent_cut(&self, engine: Engine) -> anyhow::Result<Cut> {
        let pins = futures::future::try_join_all(
            self.shards.iter().map(|shard| shard.request(|reply| ShardCommand::Pin { engine, reply })),
        )
        .await
        .with_context(|| format!("pin the {} engine", engine.as_str()))?;
        let system = self.system.snapshot().await;
        let s = self.shards[0]
            .owners
            .instance(engine)
            .with_context(|| format!("the {} engine is disabled", engine.as_str()))?
            .wal_head_lsn()
            .await?;
        let (_, reads) = self
            .held_round(|drained, register, reply| ShardCommand::Confirm { engine, drained, register, reply }, async {})
            .await?;
        // The pins go only now: the read snapshots protect the versions from here.
        drop(pins);
        let reads = (0u16..).zip(reads).collect();
        Ok(Cut { s, reads, system })
    }

    /// Samples the metrics of every data shard while all of them hold their
    /// writes back, once the ones in flight have applied, and merges the
    /// samples: a write is in a sample or not, never half, and in every later
    /// one. Reads count as they come. Waits for at most one group commit per
    /// shard.
    pub async fn sample_metrics(&self) -> anyhow::Result<MetricsSample> {
        let (_, samples) =
            self.held_round(|drained, sample, reply| ShardCommand::Sample { drained, sample, reply }, async {}).await?;
        samples
            .into_iter()
            .reduce(|mut all, sample| {
                all.merge(sample);
                all
            })
            .context("no data shard runs")
    }

    /// The flushed LSN of the instance of `engine` on each data shard, by
    /// shard index; `None` when the engine is disabled.
    pub fn flushed_lsns(&self, engine: Engine) -> Option<Vec<u64>> {
        self.shard_owners().map(|owners| owners.instance(engine).map(|instance| instance.flushed_lsn())).collect()
    }

    /// Raises the flushed LSN of the instance of `engine` to `up_to` on the
    /// data shards `shards`, all at once; `up_to` must be durable in the
    /// engine's write-ahead log.
    pub async fn persist_up_to(&self, engine: Engine, shards: &[usize], up_to: u64) -> anyhow::Result<()> {
        let persisted = futures::future::join_all(
            shards.iter().map(|&k| self.shards[k].request(|reply| ShardCommand::Persist { engine, up_to, reply })),
        )
        .await;
        for (k, persisted) in shards.iter().zip(persisted) {
            persisted
                .and_then(|persisted| persisted)
                .with_context(|| format!("shard {k} could not persist the {} engine", engine.as_str()))?;
        }
        Ok(())
    }

    /// Sends every data shard the command `make` builds from its three
    /// channels, waits until all of them hold their writes back, runs
    /// `while_held`, then lets them go on and returns its output and their
    /// answers, by shard index. Rounds run one after the other.
    async fn held_round<T, R>(
        &self,
        make: impl Fn(oneshot::Sender<()>, oneshot::Receiver<()>, oneshot::Sender<T>) -> ShardCommand,
        while_held: impl std::future::Future<Output = R>,
    ) -> anyhow::Result<(R, Vec<T>)> {
        let _round = self.rounds.lock().await;
        let mut drained = Vec::with_capacity(self.shards.len());
        let mut releases = Vec::with_capacity(self.shards.len());
        let mut answers = Vec::with_capacity(self.shards.len());
        for shard in &self.shards {
            let (drained_tx, drained_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let (reply, answer) = oneshot::channel();
            shard
                .commands
                .send(make(drained_tx, release_rx, reply))
                .map_err(|_| anyhow::anyhow!("the data shard is not running"))?;
            drained.push(drained_rx);
            releases.push(release_tx);
            answers.push(answer);
        }
        futures::future::try_join_all(drained).await.context("a data shard did not hold its writes back")?;
        let held = while_held.await;
        for release in releases {
            let _ = release.send(());
        }
        let answers = futures::future::try_join_all(answers).await.context("a data shard did not answer")?;
        Ok((held, answers))
    }

    /// The engines of every data shard, by shard index.
    pub fn shard_owners(&self) -> impl Iterator<Item = &ShardOwners> {
        self.shards.iter().map(|shard| &shard.owners)
    }

    /// The engines of the data shard that owns the domain `name`.
    pub fn owners_of(&self, name: &str) -> &ShardOwners {
        &self.owner(name).owners
    }

    /// Applies `write` to the key-value domain `domain` on the thread of the
    /// data shard that owns it.
    pub async fn write_kv(&self, domain: &str, write: KvWrite) -> anyhow::Result<()> {
        self.owner(domain).request(|reply| ShardCommand::WriteKv { domain: domain.to_string(), write, reply }).await?
    }

    /// Pings every data shard over its command channel, all at once: by
    /// shard index, whether it answered within `timeout(index)`. A shard has
    /// at most one ping outstanding: a call while it is unanswered waits for
    /// that one, and a call after its answer sends a new one.
    #[allow(clippy::disallowed_methods, reason = "called by GET /health, which runs on the frontend runtime")]
    pub async fn ping_shards(&self, timeout: impl Fn(usize) -> std::time::Duration) -> Vec<bool> {
        let pings: Vec<_> = {
            let mut slots = self.pings.lock();
            self.shards
                .iter()
                .zip(slots.iter_mut())
                .map(|(shard, slot)| {
                    // Polls once: an answer that arrived before this call is no answer to it.
                    if slot.as_ref().is_none_or(|ping| ping.clone().now_or_never().is_some()) {
                        let (reply, answer) = oneshot::channel();
                        *slot = shard
                            .commands
                            .send(ShardCommand::Ping { reply })
                            .is_ok()
                            .then(|| answer.map(|answered| answered.is_ok()).boxed().shared());
                    }
                    slot.clone()
                })
                .collect()
        };
        let pings = pings.into_iter().enumerate().map(|(index, ping)| {
            let timeout = timeout(index);
            async move {
                match ping {
                    Some(ping) => tokio::time::timeout(timeout, ping).await.unwrap_or(false),
                    None => false,
                }
            }
        });
        futures::future::join_all(pings).await
    }

    pub fn resources(&self) -> &resources::Resources {
        &self.resources
    }

    /// The current directory; later changes do not show in it.
    pub fn directory(&self) -> Arc<Directory> {
        Arc::clone(&self.directory.read())
    }

    pub fn event_bus(&self) -> &Arc<GlobalEventBus> {
        &self.bus
    }

    pub fn system_store(&self) -> &Arc<LsmStorageEngine> {
        &self.system
    }

    /// Whether a restore job runs. A restore that replaces a domain leaves it
    /// briefly deleted, so the link sweep of the relational engine waits
    /// meanwhile instead of clearing links to it for good.
    pub fn restore_running(&self) -> bool {
        self.restoring.load(Ordering::SeqCst)
    }

    /// Marks a restore as running until the returned guard drops.
    pub(crate) fn mark_restore_running(&self) -> RestoreRunning<'_> {
        self.restoring.store(true, Ordering::SeqCst);
        RestoreRunning(self)
    }

    /// Creates a domain; `require_conditional_writes` has no effect on a
    /// relational domain.
    pub async fn create_domain(
        &self,
        engine: Engine,
        name: &str,
        require_conditional_writes: bool,
    ) -> Result<DomainEntry, DomainError> {
        self.request(|reply| Command::CreateDomain { engine, name: name.to_string(), require_conditional_writes, reply })
            .await
    }

    /// Deletes a domain in two phases: it turns away new requests at once,
    /// and the call returns only after the writes already admitted ended.
    /// The purger removes its data afterwards.
    pub async fn delete_domain(&self, engine: Engine, name: &str) -> Result<(), DomainError> {
        self.request(|reply| Command::DeleteDomain { engine, name: name.to_string(), reply }).await
    }

    /// Removes a deleted domain whose data the purger has removed.
    pub(crate) async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        self.request(|reply| Command::FinalizeDeletion { engine, name: name.to_string(), reply }).await
    }

    pub async fn change_auth(&self, change: AuthChange) -> anyhow::Result<()> {
        self.request(|reply| Command::ChangeAuth { change, reply }).await
    }

    /// Publishes one event on the global event stream; this and
    /// [`Self::publish_global_many`] are the stream's only entries.
    pub fn publish_global(&self, engine: Engine, kind: &'static str, domain: &str, object: Option<String>) {
        self.bus.publish(engine.as_str(), kind, domain, object);
    }

    /// Publishes `events` as adjacent events with no foreign one between them.
    pub fn publish_global_many(&self, engine: Engine, domain: &str, events: &[(&'static str, Option<String>)]) {
        self.bus.publish_many(engine.as_str(), domain, events);
    }

    async fn request<T, E: From<DomainError>>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T, E>>) -> Command,
    ) -> Result<T, E> {
        let (reply, answer) = oneshot::channel();
        self.commands.send(command(reply)).map_err(|_| DomainError::Stopped)?;
        answer.await.map_err(|_| DomainError::Stopped)?
    }

    fn change_directory(&self, change: impl FnOnce(&mut Directory)) {
        let mut current = self.directory.write();
        let directory = Arc::make_mut(&mut current);
        change(directory);
        directory.generation += 1;
    }
}

/// Runs the commands, one after the other, each against the data shard that
/// owns its domain.
struct Worker {
    auth: Arc<AuthCache>,
    control: Arc<ControlPlane>,
}

impl Worker {
    async fn run(self, mut inbox: mpsc::UnboundedReceiver<Command>) {
        while let Some(command) = inbox.recv().await {
            // A caller that gave up does not stop its command.
            match command {
                Command::CreateDomain { engine, name, require_conditional_writes, reply } => {
                    let _ = reply.send(self.create_domain(engine, &name, require_conditional_writes).await);
                }
                Command::DeleteDomain { engine, name, reply } => {
                    let _ = reply.send(self.delete_domain(engine, &name).await);
                }
                Command::FinalizeDeletion { engine, name, reply } => {
                    let _ = reply.send(self.finalize_deletion(engine, &name).await);
                }
                Command::ChangeAuth { change, reply } => {
                    let _ = reply.send(self.change_auth(change).await);
                }
            }
        }
    }

    fn json<'a>(&self, owner: &'a Shard) -> Result<&'a Arc<JsonEngine>, DomainError> {
        owner.owners.json.as_ref().ok_or(DomainError::Disabled(Engine::Json))
    }

    fn rel<'a>(&self, owner: &'a Shard) -> Result<&'a Arc<RelEngine>, DomainError> {
        owner.owners.rel.as_ref().ok_or(DomainError::Disabled(Engine::Rel))
    }

    async fn create_domain(
        &self,
        engine: Engine,
        name: &str,
        require_conditional_writes: bool,
    ) -> Result<DomainEntry, DomainError> {
        let owner = self.control.owner(name);
        let entry = match engine {
            Engine::Kv => DomainEntry::kv(
                &owner.owners.kv.create_domain_with(name, require_conditional_writes).await.map_err(DomainError::Kv)?,
            ),
            Engine::Json => DomainEntry::json(
                &self
                    .json(owner)?
                    .create_domain_with(name, require_conditional_writes)
                    .await
                    .map_err(DomainError::Json)?,
            ),
            Engine::Rel => DomainEntry::rel(&self.rel(owner)?.create_domain(name).await.map_err(DomainError::Rel)?),
        };
        self.control.change_directory(|d| d.insert(entry.clone()));
        self.control.publish_global(engine, "domain_created", name, None);
        Ok(entry)
    }

    async fn delete_domain(&self, engine: Engine, name: &str) -> Result<(), DomainError> {
        let owner = self.control.owner(name);
        match engine {
            Engine::Kv => owner.owners.kv.delete_domain(name).await.map_err(DomainError::Kv)?,
            Engine::Json => self.json(owner)?.delete_domain(name).await.map_err(DomainError::Json)?,
            Engine::Rel => self.rel(owner)?.delete_domain(name).await.map_err(DomainError::Rel)?,
        }
        self.control.change_directory(|d| d.set_deleting(engine, name));
        // Writes that passed the domain check before it turned `Deleting`;
        // the owner drains its engine on its own thread.
        owner.request(|reply| ShardCommand::Quiesce { engine, reply }).await.map_err(|_| DomainError::Stopped)?;
        self.control.publish_global(engine, "domain_deleted", name, None);
        Ok(())
    }

    async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        let owner = self.control.owner(name);
        owner.request(|reply| ShardCommand::FinalizeDeletion { engine, name: name.to_string(), reply }).await??;
        self.control.change_directory(|d| d.remove(engine, name));
        self.control.publish_global(engine, "domain_purged", name, None);
        Ok(())
    }

    async fn change_auth(&self, change: AuthChange) -> anyhow::Result<()> {
        let auth = &self.auth;
        match change {
            AuthChange::UpsertUser(record) => auth.upsert_user(record).await,
            AuthChange::RemoveUser(name) => auth.remove_user(&name).await,
            AuthChange::RotateKey { name, new_hash } => auth.rotate_key(&name, &new_hash).await,
            AuthChange::SetPermission(perm) => auth.set_permission(perm).await,
            AuthChange::RemovePermission { username, domain } => auth.remove_permission(&username, &domain).await,
            AuthChange::RegisterClient(client) => auth.register_client(client).await,
            AuthChange::IssueCode { hash, record, now } => auth.issue_code(hash, record, now).await,
            AuthChange::RedeemCode(redeem) => auth.redeem_code(redeem).await,
            AuthChange::Refresh(refresh) => auth.refresh(refresh).await,
            AuthChange::RevokeToken { hash } => auth.revoke_token(&hash).await,
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::path::Path;

    /// A control plane over the given owners as its one data shard, with a
    /// system store of its own under `dir/sys` and an auth cache on it.
    pub(crate) async fn start(
        dir: &Path,
        kv: Arc<DomainRegistry>,
        json: Option<Arc<JsonEngine>>,
        rel: Option<Arc<RelEngine>>,
        bus: Arc<GlobalEventBus>,
    ) -> (Arc<ControlPlane>, Arc<AuthCache>) {
        start_shards(dir, vec![ShardOwners { kv, json, rel }], bus).await
    }

    /// A control plane over `shards`, each serving its commands in a task on
    /// the current runtime, with a system store of its own under `dir/sys`
    /// and an auth cache on it.
    pub(crate) async fn start_shards(
        dir: &Path,
        shards: Vec<ShardOwners>,
        bus: Arc<GlobalEventBus>,
    ) -> (Arc<ControlPlane>, Arc<AuthCache>) {
        let shards = shards
            .into_iter()
            .map(|owners| {
                let (commands, inbox) = mpsc::unbounded_channel();
                compio::runtime::spawn(serve_shard(owners.clone(), inbox)).detach();
                Shard { owners, commands }
            })
            .collect();
        start_over(dir, shards, bus).await
    }

    /// A control plane over `shards` as they are, with a system store of its
    /// own under `dir/sys` and an auth cache on it.
    pub(super) async fn start_over(
        dir: &Path,
        shards: Vec<Shard>,
        bus: Arc<GlobalEventBus>,
    ) -> (Arc<ControlPlane>, Arc<AuthCache>) {
        let system = system::open(&dir.join("sys")).await.unwrap();
        let auth = Arc::new(AuthCache::new(Arc::clone(&system), None));
        let owners = Owners { shards, auth: Arc::clone(&auth) };
        (ControlPlane::start(owners, system, bus, Default::default()).await.unwrap(), auth)
    }

    /// A key-value domain registry on an engine of its own under `dir/kv`.
    pub(crate) async fn kv_registry(dir: &Path) -> Arc<DomainRegistry> {
        use crate::engines::lsm::engine::LsmEngineOptions;
        let dir = dir.join("kv");
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(&dir).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(&dir));
        let (wal_path, vlog_path) = (dir.join("wal.log"), dir.join("vlog.log"));
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let engine = Arc::new(
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, LsmEngineOptions::default()).await.unwrap(),
        );
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let config = crate::engines::lsm::domain::DomainConfig::default();
        Arc::new(DomainRegistry::recover(engine, config, metrics).await.unwrap())
    }

    /// The files of the key-value shards of [`kv_shards`] under `dir`, laid
    /// out as the server lays them out.
    pub(crate) fn kv_shard_files(dir: &Path) -> crate::server::recovery::EngineFiles {
        let base = dir.join("kv-shards");
        crate::server::recovery::EngineFiles { wal: dir.join("kv.wal"), vlog: base.join("vlog"), sstables: base }
    }

    /// `n` data shards' key-value engines writing one log through `hub`,
    /// `tune` applied to engine `k` before it is shared; only the shard that
    /// owns the default domain creates it.
    pub(crate) async fn kv_shards(
        dir: &Path,
        hub: &crate::core::storage_thread::TestHub,
        n: u16,
        mut tune: impl FnMut(usize, &mut LsmStorageEngine),
    ) -> Vec<ShardOwners> {
        use crate::engines::lsm::engine::LsmEngineOptions;
        let files = kv_shard_files(dir);
        let mut shards = Vec::new();
        for k in 0..usize::from(n) {
            let wal = Arc::new(hub.wal(crate::core::storage_thread::WalTarget::Kv));
            let mut engine = crate::server::recovery::open_instance(&files, k, wal, LsmEngineOptions::default())
                .await
                .unwrap();
            tune(k, &mut engine);
            let owns_default = usize::from(slots::shard_of_domain("default", n)) == k;
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let config = crate::engines::lsm::domain::DomainConfig::default();
            let registry =
                DomainRegistry::recover_on_shard(Arc::new(engine), config, metrics, owns_default).await.unwrap();
            shards.push(ShardOwners { kv: Arc::new(registry), json: None, rel: None });
        }
        shards
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{hash_api_key, UserRole};
    use crate::control::checkpoint::Report;
    use crate::core::events::GlobalEvent;
    use crate::engines::lsm::domain::DomainPurger;
    use crate::engines::lsm::reader::GetResult;
    use crate::engines::StorageEngine;
    use serde_json::json;
    use std::time::Duration;
    use tokio::sync::broadcast;

    /// All three engines in one temp dir, a control plane over them, and a
    /// subscription to its event stream.
    struct Fixture {
        kv: Arc<DomainRegistry>,
        json: Arc<JsonEngine>,
        rel: Arc<RelEngine>,
        auth: Arc<AuthCache>,
        control: Arc<ControlPlane>,
        events: broadcast::Receiver<GlobalEvent>,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        async fn new() -> Self {
            let (f, serving) = Self::serving().await;
            serving.detach();
            f
        }

        /// A fixture whose data shard serves its commands in the task returned
        /// beside it.
        async fn serving() -> (Self, compio::runtime::JoinHandle<Option<DrainReply>>) {
            let dir = tempfile::TempDir::new().unwrap();
            let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let kv = testing::kv_registry(dir.path()).await;
            let json_config = crate::config::JsonStoreConfig {
                wal_path: path("json.wal"),
                vlog_path: path("json.vlog"),
                sstable_dir: path("json_sstables"),
                ..Default::default()
            };
            let json = JsonEngine::bootstrap(&json_config, Arc::clone(&metrics)).await.unwrap();
            let rel_config = crate::config::RelStoreConfig {
                wal_path: path("rel.wal"),
                vlog_path: path("rel.vlog"),
                sstable_dir: path("rel_sstables"),
                ..Default::default()
            };
            let resolver = crate::engines::rel::CrossEngineResolver::disabled(Arc::clone(&metrics));
            let rel = RelEngine::bootstrap(&rel_config, metrics, resolver).await.unwrap();
            let bus = Arc::new(GlobalEventBus::new(64, 64));
            let events = bus.subscribe();
            let owners = ShardOwners { kv: Arc::clone(&kv), json: Some(Arc::clone(&json)), rel: Some(Arc::clone(&rel)) };
            let (commands, inbox) = mpsc::unbounded_channel();
            let serving = compio::runtime::spawn(serve_shard(owners.clone(), inbox));
            let (control, auth) = testing::start_over(dir.path(), vec![Shard { owners, commands }], bus).await;
            (Self { kv, json, rel, auth, control, events, _dir: dir }, serving)
        }

        fn state(&self, engine: Engine, name: &str) -> Option<Lifecycle> {
            self.control.directory().get(engine, name).map(|entry| entry.state)
        }

        /// Waits until `name` is `Deleting` — the delete's first phase ran.
        async fn until_deleting(&self, engine: Engine, name: &str) {
            let wait = async {
                while self.state(engine, name) != Some(Lifecycle::Deleting) {
                    tokio::task::yield_now().await;
                }
            };
            // Upper bound against hanging only.
            compio::time::timeout(Duration::from_secs(30), wait).await.expect("the domain never turned Deleting");
        }

        fn next_event(&mut self) -> (&'static str, &'static str, String) {
            let event = self.events.try_recv().expect("an event");
            (event.engine, event.kind, event.domain)
        }

        /// Whether a ping sent to the data shard now is answered while every
        /// runnable task gets a few turns.
        async fn ping_answers(&self) -> bool {
            let ping = compio::runtime::spawn({
                let control = Arc::clone(&self.control);
                async move { control.shards[0].request(|reply| ShardCommand::Ping { reply }).await }
            });
            settle().await;
            ping.is_finished() && ping.await.unwrap().is_ok()
        }
    }

    /// Gives every runnable task a few turns.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn purger(f: &Fixture) -> DomainPurger {
        DomainPurger::new(Arc::clone(f.kv.engine()), Arc::clone(&f.kv), 100)
    }

    #[test]
    fn a_kv_delete_waits_for_in_flight_writes_and_then_hands_over_to_the_purger() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain(Engine::Kv, "doomed", false).await.unwrap();
            f.kv.store("doomed").await.unwrap().put(b"k", "clé ✓".as_bytes()).await.unwrap();
            assert_eq!(f.next_event(), ("kv", "domain_created", "doomed".to_string()));

            let in_flight = f.kv.engine().in_flight_write_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain(Engine::Kv, "doomed").await }
            });
            f.until_deleting(Engine::Kv, "doomed").await;
            settle().await;
            assert!(!delete.is_finished(), "the delete must wait for the write in flight");
            assert!(f.ping_answers().await, "the shard answers a ping while the delete waits");
            assert!(!delete.is_finished(), "the delete must wait for the write in flight");
            let refused = f.kv.store("doomed").await.err().expect("a new write must be refused");
            assert!(refused.to_string().starts_with("410"), "{refused}");
            assert!(f.events.try_recv().is_err(), "no domain_deleted before the drain");

            drop(in_flight);
            delete.await.unwrap().unwrap();
            assert_eq!(f.next_event(), ("kv", "domain_deleted", "doomed".to_string()));

            let purger = purger(&f);
            purger.purge_tick().await.unwrap(); // tombstones the key
            purger.purge_tick().await.unwrap(); // finalizes
            assert_eq!(f.next_event(), ("kv", "domain_purged", "doomed".to_string()));
            assert_eq!(f.state(Engine::Kv, "doomed"), None);
            assert!(f.kv.get_domain("doomed").await.unwrap().is_none());
        })
    }

    const KV_GONE: &str = "410 Gone: Domain 'doomed' is being deleted";

    #[test]
    fn a_kv_write_that_reaches_its_guard_during_the_delete_is_refused() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain(Engine::Kv, "doomed", false).await.unwrap();
            let store = f.kv.store("doomed").await.unwrap();
            let late = f.kv.store("doomed").await.unwrap();
            let prefix = store.domain().system_prefix.clone();

            let in_flight = f.kv.engine().in_flight_write_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain(Engine::Kv, "doomed").await }
            });
            f.until_deleting(Engine::Kv, "doomed").await;
            let late_write = compio::runtime::spawn(async move { late.put(b"late", b"v").await });
            settle().await;
            assert!(!delete.is_finished(), "the delete must wait for the write in flight");

            drop(in_flight);
            delete.await.unwrap().unwrap();
            assert_eq!(late_write.await.unwrap().unwrap_err().to_string(), KV_GONE);
            assert_eq!(store.put(b"again", b"v").await.unwrap_err().to_string(), KV_GONE);
            assert_eq!(f.state(Engine::Kv, "doomed"), Some(Lifecycle::Deleting), "refused before the finalize");
            assert!(f.kv.engine().scan_keys(&prefix).await.unwrap().is_empty());
        })
    }

    #[test]
    fn a_kv_store_taken_before_the_delete_stays_refused_after_the_purge() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain(Engine::Kv, "doomed", false).await.unwrap();
            let store = f.kv.store("doomed").await.unwrap();
            store.put(b"k", b"v").await.unwrap();
            let prefix = store.domain().system_prefix.clone();

            f.control.delete_domain(Engine::Kv, "doomed").await.unwrap();
            let purger = purger(&f);
            purger.purge_tick().await.unwrap(); // tombstones the key
            purger.purge_tick().await.unwrap(); // finalizes
            assert_eq!(f.state(Engine::Kv, "doomed"), None);

            assert_eq!(store.put(b"late", b"v").await.unwrap_err().to_string(), KV_GONE);
            assert!(f.kv.engine().scan_keys(&prefix).await.unwrap().is_empty());

            f.control.create_domain(Engine::Kv, "doomed", false).await.unwrap();
            assert_eq!(store.put(b"late", b"v").await.unwrap_err().to_string(), KV_GONE);
            let reborn = f.kv.store("doomed").await.unwrap();
            assert!(reborn.scan_keys(b"").await.unwrap().is_empty(), "no orphan in the new domain");
        })
    }

    #[test]
    fn a_json_delete_waits_for_a_held_document_lock_and_then_hands_over_to_the_purger() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain(Engine::Json, "doomed", false).await.unwrap();
            f.json.put_document("doomed", "k", json!({"n": 1})).await.unwrap();
            f.next_event();

            let lock = f.json.doc_write_lock_for_test("doomed", "held").await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain(Engine::Json, "doomed").await }
            });
            f.until_deleting(Engine::Json, "doomed").await;
            settle().await;
            assert!(!delete.is_finished(), "the delete must wait for the held document lock");
            assert!(f.ping_answers().await, "the shard answers a ping while the delete waits");
            assert!(!delete.is_finished(), "the delete must wait for the held document lock");
            let late_write = compio::runtime::spawn({
                let json = Arc::clone(&f.json);
                async move { json.put_document("doomed", "late", json!({"n": 2})).await }
            });
            assert!(f.events.try_recv().is_err(), "no domain_deleted before the drain");

            drop(lock);
            delete.await.unwrap().unwrap();
            let refused = late_write.await.unwrap().unwrap_err();
            assert!(matches!(refused, JsonStoreError::DomainDeleting(_)), "got: {refused}");
            assert_eq!(f.next_event(), ("json", "domain_deleted", "doomed".to_string()));

            let purger = crate::engines::json::JsonDomainPurger::new(Arc::clone(&f.json), 100);
            purger.purge_tick().await.unwrap();
            purger.purge_tick().await.unwrap();
            assert_eq!(f.next_event(), ("json", "domain_purged", "doomed".to_string()));
            assert_eq!(f.state(Engine::Json, "doomed"), None);
        })
    }

    #[test]
    fn a_rel_delete_waits_for_the_write_guard_and_then_hands_over_to_the_purger() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain(Engine::Rel, "doomed", false).await.unwrap();
            f.rel.execute("doomed", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
            assert_eq!(f.next_event(), ("rel", "domain_created", "doomed".to_string()));
            assert_eq!(f.next_event(), ("rel", "table_created", "doomed".to_string()));

            let guard = f.rel.write_guard_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain(Engine::Rel, "doomed").await }
            });
            f.until_deleting(Engine::Rel, "doomed").await;
            settle().await;
            assert!(!delete.is_finished(), "the delete must wait for the write guard");
            assert!(f.ping_answers().await, "the shard answers a ping while the delete waits");
            assert!(!delete.is_finished(), "the delete must wait for the write guard");
            let late_write = compio::runtime::spawn({
                let rel = Arc::clone(&f.rel);
                async move { rel.execute("doomed", "INSERT INTO t VALUES (1)", &[]).await }
            });
            assert!(f.events.try_recv().is_err(), "no domain_deleted before the drain");

            drop(guard);
            delete.await.unwrap().unwrap();
            let refused = late_write.await.unwrap().unwrap_err();
            assert!(matches!(refused, RelStoreError::DomainDeleting(_)), "got: {refused}");
            assert_eq!(f.next_event(), ("rel", "domain_deleted", "doomed".to_string()));

            let purger = crate::engines::rel::RelDomainPurger::new(Arc::clone(&f.rel), 100);
            purger.purge_tick().await.unwrap();
            purger.purge_tick().await.unwrap();
            assert_eq!(f.next_event(), ("rel", "domain_purged", "doomed".to_string()));
            assert_eq!(f.state(Engine::Rel, "doomed"), None);
        })
    }

    // A delete waiting for the relational write guard on the only shard does
    // not hold up a metrics round there.
    #[test]
    fn a_metrics_round_ends_while_a_delete_waits() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain(Engine::Rel, "doomed", false).await.unwrap();
            let guard = f.rel.write_guard_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain(Engine::Rel, "doomed").await }
            });
            f.until_deleting(Engine::Rel, "doomed").await;
            settle().await;

            // Upper bound against hanging only.
            compio::time::timeout(Duration::from_secs(30), f.control.sample_metrics())
                .await
                .expect("the round waits for the delete")
                .unwrap();
            assert!(!delete.is_finished(), "the delete must wait for the write guard");
            drop(guard);
            delete.await.unwrap().unwrap();
        })
    }

    // A drain that reaches the shard while a delete waits for the relational
    // write guard ends the command loop only once the delete's wait is over;
    // the delete then succeeds.
    #[test]
    fn a_drain_waits_for_a_delete_in_progress() {
        crate::core::engine_runtime::block_on(async {
            let (mut f, serving) = Fixture::serving().await;
            f.control.create_domain(Engine::Rel, "doomed", false).await.unwrap();
            assert_eq!(f.next_event(), ("rel", "domain_created", "doomed".to_string()));
            let guard = f.rel.write_guard_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain(Engine::Rel, "doomed").await }
            });
            f.until_deleting(Engine::Rel, "doomed").await;
            let (reply, _flushed) = oneshot::channel();
            f.control.shards[0].commands.send(ShardCommand::Drain { reply }).unwrap();
            settle().await;
            assert!(!serving.is_finished(), "the drain waits for the delete");
            assert!(!delete.is_finished(), "the delete must wait for the write guard");

            drop(guard);
            assert!(serving.await.unwrap().is_some(), "the loop ends with the drain");
            delete.await.unwrap().unwrap();
            assert_eq!(f.next_event(), ("rel", "domain_deleted", "doomed".to_string()));
        })
    }

    #[test]
    fn concurrent_creates_of_one_name_have_exactly_one_winner_in_every_engine() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            for engine in [Engine::Kv, Engine::Json, Engine::Rel] {
                let creates = (0..8).map(|_| f.control.create_domain(engine, "contested", false));
                let created = futures::future::join_all(creates).await;
                assert_eq!(created.iter().filter(|r| r.is_ok()).count(), 1, "{engine:?}");
            }
        })
    }

    #[test]
    fn concurrent_deletes_of_one_domain_have_exactly_one_winner() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain(Engine::Rel, "contested", false).await.unwrap();
            let deletes = (0..8).map(|_| f.control.delete_domain(Engine::Rel, "contested"));
            let results = futures::future::join_all(deletes).await;
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            for result in results.into_iter().filter_map(Result::err) {
                assert!(matches!(result, DomainError::Rel(RelStoreError::DomainDeleting(_))), "got: {result:?}");
            }
        })
    }

    #[test]
    fn a_delete_sent_during_a_create_runs_after_it() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            let create = f.control.create_domain(Engine::Kv, "racy", false);
            let delete = f.control.delete_domain(Engine::Kv, "racy");
            let (created, deleted) = futures::future::join(create, delete).await;
            created.unwrap();
            deleted.unwrap();
            assert_eq!(f.state(Engine::Kv, "racy"), Some(Lifecycle::Deleting));
            assert_eq!(f.next_event(), ("kv", "domain_created", "racy".to_string()));
            assert_eq!(f.next_event(), ("kv", "domain_deleted", "racy".to_string()));
        })
    }

    #[test]
    fn lifecycle_events_carry_engine_domain_and_time() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            for engine in [Engine::Kv, Engine::Json, Engine::Rel] {
                f.control.create_domain(engine, "evdom", false).await.unwrap();
                f.control.delete_domain(engine, "evdom").await.unwrap();
                for kind in ["domain_created", "domain_deleted"] {
                    let event = f.events.try_recv().unwrap();
                    assert_eq!((event.engine, event.kind, event.domain.as_str()), (engine.as_str(), kind, "evdom"));
                    assert_eq!(event.object, None);
                    assert!(event.ts > 0);
                }
            }
        })
    }

    #[test]
    fn failed_lifecycle_commands_publish_nothing() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            let duplicate = f.control.create_domain(Engine::Rel, "default", false).await.unwrap_err();
            assert!(matches!(duplicate, DomainError::Rel(RelStoreError::DomainAlreadyExists(_))), "{duplicate:?}");
            let missing = f.control.delete_domain(Engine::Json, "ghost").await.unwrap_err();
            assert!(matches!(missing, DomainError::Json(JsonStoreError::DomainNotFound(_))), "{missing:?}");
            let invalid = f.control.create_domain(Engine::Kv, "bad name!", false).await.unwrap_err();
            assert!(matches!(invalid, DomainError::Kv(_)), "{invalid:?}");
            assert!(f.events.try_recv().is_err());
        })
    }

    #[test]
    fn lifecycle_states_read_as_the_api_shows_them() {
        assert_eq!(Lifecycle::Active.as_str(), "active");
        assert_eq!(Lifecycle::Deleting.as_str(), "deleting");
    }

    #[test]
    fn a_domain_error_reads_as_its_cause() {
        let errors = [
            (DomainError::Kv(anyhow::anyhow!("400 Bad Request: bad name")), "400 Bad Request: bad name"),
            (DomainError::Json(JsonStoreError::DomainNotFound("ghost".to_string())), "domain 'ghost' not found"),
            (DomainError::Rel(RelStoreError::DomainDeleting("doomed".to_string())), "domain 'doomed' is being deleted"),
            (DomainError::Disabled(Engine::Json), "the json engine is disabled"),
            (DomainError::Stopped, "the control plane is not running"),
        ];
        for (error, text) in errors {
            assert_eq!(error.to_string(), text);
        }
    }

    #[test]
    fn the_directory_lists_every_domain_with_its_state_and_slot() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            for engine in [Engine::Kv, Engine::Json, Engine::Rel] {
                assert_eq!(f.state(engine, "default"), Some(Lifecycle::Active), "{engine:?}");
            }

            f.control.create_domain(Engine::Kv, "alpha", true).await.unwrap();
            let before_delete = f.control.directory();
            f.control.delete_domain(Engine::Kv, "alpha").await.unwrap();

            let alpha = before_delete.get(Engine::Kv, "alpha").unwrap();
            assert_eq!(alpha.state, Lifecycle::Active, "an earlier view keeps its state");
            assert_eq!(alpha.slot, slots::slot_of_domain("alpha"));
            assert!(alpha.require_conditional_writes);
            assert!(alpha.created_at > 0);
            assert_eq!(f.state(Engine::Kv, "alpha"), Some(Lifecycle::Deleting));
            assert_eq!(f.state(Engine::Json, "alpha"), None, "engines do not share domains");
            let kv_names: Vec<_> = f.control.directory().domains(Engine::Kv).map(|d| d.name.clone()).collect();
            assert_eq!(kv_names, ["alpha", "default"]);
        })
    }

    #[test]
    fn a_purger_attached_before_its_spawn_still_reports_the_purge() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            let purger = DomainPurger::new(Arc::clone(f.kv.engine()), Arc::clone(&f.kv), 1);

            f.control.create_domain(Engine::Kv, "late-purge", false).await.unwrap();
            f.control.delete_domain(Engine::Kv, "late-purge").await.unwrap();
            f.next_event();
            f.next_event();
            purger.purge_tick().await.unwrap();
            assert_eq!(f.next_event(), ("kv", "domain_purged", "late-purge".to_string()));
        })
    }

    #[test]
    fn auth_changes_land_in_the_system_store_and_the_cache() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            let record = UserRecord {
                name: "alice".to_string(),
                api_key_hash: hash_api_key("lura_alice"),
                role: UserRole::User,
                created_at: 0,
            };
            f.control.change_auth(AuthChange::UpsertUser(record)).await.unwrap();
            f.control.change_auth(AuthChange::RotateKey { name: "alice".to_string(), new_hash: "rotated".to_string() })
                .await
                .unwrap();

            assert_eq!(f.auth.get_user_by_name("alice").await.unwrap().api_key_hash, "rotated");
            assert!(f.control.system_store().get(b"__sys:auth:user:alice").await.unwrap().is_some());
            assert!(f.kv.engine().get(b"__sys:auth:user:alice").await.unwrap().is_none());

            f.control.change_auth(AuthChange::RemoveUser("alice".to_string())).await.unwrap();
            assert!(f.auth.get_user_by_name("alice").await.is_none());
            assert!(f.control.system_store().get(b"__sys:auth:user:alice").await.unwrap().is_none());
        })
    }

    /// Two key-value shards and a control plane over them, with the hub
    /// their log runs through and each shard's engine. Every command reaches
    /// a shard through a relay that records it; a shard's relay holds its
    /// `Confirm` back while `hold_confirms` of that shard is set, and keeps
    /// its `Sample`s back while `hold_samples` is set, to pass them on in
    /// reverse order once it is cleared; likewise its `Ping`s while
    /// `hold_pings` is set, in order. It holds a `Persist` back while
    /// `hold_persists` is set and drops it unanswered while `drop_persists`
    /// is set.
    struct TwoShards {
        control: Arc<ControlPlane>,
        engines: Vec<Arc<LsmStorageEngine>>,
        registries: Vec<Arc<DomainRegistry>>,
        commands: Arc<std::sync::Mutex<Vec<(usize, &'static str)>>>,
        hold_confirms: Vec<tokio::sync::watch::Sender<bool>>,
        hold_samples: Vec<tokio::sync::watch::Sender<bool>>,
        hold_pings: Vec<tokio::sync::watch::Sender<bool>>,
        hold_persists: Vec<tokio::sync::watch::Sender<bool>>,
        drop_persists: Vec<tokio::sync::watch::Sender<bool>>,
        hub: crate::core::storage_thread::TestHub,
        dir: tempfile::TempDir,
    }

    /// The name of a shard command, as [`TwoShards`] records it.
    fn command_name(command: &ShardCommand) -> &'static str {
        match command {
            ShardCommand::Quiesce { .. } => "quiesce",
            ShardCommand::FinalizeDeletion { .. } => "finalize",
            ShardCommand::Pin { .. } => "pin",
            ShardCommand::Confirm { .. } => "confirm",
            ShardCommand::Sample { .. } => "sample",
            ShardCommand::Persist { .. } => "persist",
            ShardCommand::WriteKv { .. } => "write",
            ShardCommand::Ping { .. } => "ping",
            ShardCommand::Drain { .. } => "drain",
        }
    }

    impl TwoShards {
        async fn new(tune: impl FnMut(usize, &mut LsmStorageEngine)) -> Self {
            Self::with_segments(tune, crate::core::storage_thread::WAL_SEGMENT_BYTES).await
        }

        /// [`Self::new`] with log segments of `segment_bytes`.
        async fn with_segments(tune: impl FnMut(usize, &mut LsmStorageEngine), segment_bytes: u64) -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = crate::core::storage_thread::TestHub::with_segment_bytes(
                &[(crate::core::storage_thread::WalTarget::Kv, &dir.path().join("kv.wal"))],
                segment_bytes,
            );
            let owners = testing::kv_shards(dir.path(), &hub, 2, tune).await;
            let engines = owners.iter().map(|shard| Arc::clone(shard.kv.engine())).collect();
            let registries = owners.iter().map(|shard| Arc::clone(&shard.kv)).collect();
            let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut hold_confirms = Vec::new();
            let mut hold_samples = Vec::new();
            let mut hold_pings = Vec::new();
            let mut hold_persists = Vec::new();
            let mut drop_persists = Vec::new();
            let mut shards = Vec::new();
            for (k, owners) in owners.into_iter().enumerate() {
                let (to_shard, inbox) = mpsc::unbounded_channel();
                compio::runtime::spawn(serve_shard(owners.clone(), inbox)).detach();
                let (hold, mut held) = tokio::sync::watch::channel(false);
                hold_confirms.push(hold);
                let (hold, mut samples_held) = tokio::sync::watch::channel(false);
                hold_samples.push(hold);
                let (hold, mut pings_held) = tokio::sync::watch::channel(false);
                hold_pings.push(hold);
                let (hold, mut persists_held) = tokio::sync::watch::channel(false);
                hold_persists.push(hold);
                let (dropping, persists_dropped) = tokio::sync::watch::channel(false);
                drop_persists.push(dropping);
                let (relay, mut relayed) = mpsc::unbounded_channel::<ShardCommand>();
                let log = Arc::clone(&commands);
                compio::runtime::spawn(async move {
                    let mut kept = Vec::new();
                    let mut kept_pings = Vec::new();
                    loop {
                        tokio::select! {
                            command = relayed.recv() => {
                                let Some(command) = command else { break };
                                let name = command_name(&command);
                                log.lock().unwrap().push((k, name));
                                if name == "confirm" {
                                    let _ = held.wait_for(|held| !held).await;
                                }
                                if name == "persist" {
                                    let _ = persists_held.wait_for(|held| !held).await;
                                }
                                if name == "persist" && *persists_dropped.borrow() {
                                    drop(command);
                                } else if name == "sample" && *samples_held.borrow() {
                                    kept.push(command);
                                } else if name == "ping" && *pings_held.borrow() {
                                    kept_pings.push(command);
                                } else if to_shard.send(command).is_err() {
                                    break;
                                }
                            }
                            Ok(()) = samples_held.changed() => {
                                if !*samples_held.borrow_and_update() {
                                    for command in kept.drain(..).rev() {
                                        let _ = to_shard.send(command);
                                    }
                                }
                            }
                            Ok(()) = pings_held.changed() => {
                                if !*pings_held.borrow_and_update() {
                                    for command in kept_pings.drain(..) {
                                        let _ = to_shard.send(command);
                                    }
                                }
                            }
                        }
                    }
                })
                .detach();
                shards.push(Shard { owners, commands: relay });
            }
            let bus = Arc::new(GlobalEventBus::new(64, 64));
            let (control, _) = testing::start_over(dir.path(), shards, bus).await;
            Self {
                control,
                engines,
                registries,
                commands,
                hold_confirms,
                hold_samples,
                hold_pings,
                hold_persists,
                drop_persists,
                hub,
                dir,
            }
        }

        fn wal_path(&self) -> std::path::PathBuf {
            self.dir.path().join("kv.wal")
        }

        /// The segments of the key-value log on disk: each one's number and
        /// size.
        fn segment_files(&self) -> Vec<(u64, u64)> {
            crate::core::wal::segments_in(&self.wal_path())
                .unwrap()
                .into_iter()
                .map(|(n, path)| (n, std::fs::metadata(path).unwrap().len()))
                .collect()
        }

        /// Whether the key-value log is one segment that holds its header
        /// alone.
        fn holds_only_a_header(&self) -> bool {
            matches!(self.segment_files()[..], [(_, crate::core::wal::WAL_HEADER_LEN)])
        }

        /// Checkpoint ticks over the key-value log, capped at `limit` bytes.
        fn checkpoints(&self, limit: u64) -> Arc<checkpoint::WalCheckpoint> {
            let wal = self.hub.wal(crate::core::storage_thread::WalTarget::Kv);
            let logs = vec![(checkpoint::Holder::Shards(Engine::Kv), wal)];
            Arc::new(checkpoint::WalCheckpoint::new(Arc::clone(&self.control), logs, limit))
        }

        /// Drops everything without a flush or a cut, as a crash does, and
        /// recovers both shards' instances from the files left behind, on a
        /// new hub.
        async fn crash(self) -> (Vec<Arc<LsmStorageEngine>>, crate::core::storage_thread::TestHub, tempfile::TempDir) {
            use crate::core::storage_thread::{TestHub, WalTarget};
            let dir = self.dir;
            drop(self.hub);
            let hub = TestHub::start(&[(WalTarget::Kv, &dir.path().join("kv.wal"))]);
            let files = testing::kv_shard_files(dir.path());
            let options = crate::engines::lsm::engine::LsmEngineOptions::default;
            let engines = crate::server::recovery::open_sharded(&files, 2, || hub.wal(WalTarget::Kv), options)
                .await
                .unwrap();
            (engines, hub, dir)
        }

        fn state(&self, name: &str) -> Option<Lifecycle> {
            self.control.directory().get(Engine::Kv, name).map(|entry| entry.state)
        }

        /// The commands shard `k` got so far, by name.
        fn commands_of(&self, k: usize) -> Vec<&'static str> {
            self.commands.lock().unwrap().iter().filter(|(shard, _)| *shard == k).map(|(_, name)| *name).collect()
        }
    }

    /// `key` as `snapshot` of a cut sees it on `engine`.
    async fn seen(engine: &LsmStorageEngine, key: &str, snapshot: &RegistrySnapshot) -> bool {
        engine.get_with_snapshot(key.as_bytes(), snapshot.snapshot()).await.unwrap()
            != crate::engines::lsm::reader::GetResult::Absent
    }

    // With no write in flight, every shard confirms at once.
    #[test]
    fn a_cut_over_idle_shards_returns_at_once() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::new(|_, _| {}).await;
            s.engines[0].put(b"k", b"v").await.unwrap();
            let cut = s.control.consistent_cut(Engine::Kv).await.unwrap();
            assert_eq!(cut.reads.iter().map(|(shard, _)| *shard).collect::<Vec<_>>(), [0, 1]);
            assert!(cut.s >= 1);
            assert!(seen(&s.engines[0], "k", &cut.reads[0].1).await);
        })
    }

    // Writers in flight on both shards — their records in the log, not yet
    // applied — hold the cut back until they apply, and are in it; every
    // earlier write is in it, a write after it is not and gets an LSN past s.
    #[test]
    fn a_cut_waits_for_the_writes_in_flight_and_holds_every_record_up_to_s() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::engine::TestHook;
            let hooks = [Arc::new(TestHook::default()), Arc::new(TestHook::default())];
            let s = TwoShards::new(|k, engine| {
                engine.hooks.before_kv_pair_apply = Some((format!("held-{k}").into_bytes(), Arc::clone(&hooks[k])));
            })
            .await;
            for (k, engine) in s.engines.iter().enumerate() {
                engine.put(format!("before-{k}").as_bytes(), b"v").await.unwrap();
            }
            let writers: Vec<_> = s
                .engines
                .iter()
                .enumerate()
                .map(|(k, engine)| {
                    let engine = Arc::clone(engine);
                    compio::runtime::spawn(async move { engine.put(format!("held-{k}").as_bytes(), b"v").await })
                })
                .collect();
            for hook in &hooks {
                hook.reached.notified().await;
            }

            let cut = compio::runtime::spawn({
                let control = Arc::clone(&s.control);
                async move { control.consistent_cut(Engine::Kv).await }
            });
            settle().await;
            assert!(!cut.is_finished(), "the cut waits for the writes in flight");
            for hook in &hooks {
                hook.release.notify_one();
            }
            let cut = cut.await.unwrap().unwrap();
            for writer in writers {
                writer.await.unwrap().unwrap();
            }
            s.engines[0].put(b"after-0", b"v").await.unwrap();

            assert!(cut.s >= 4, "two writes before and two in flight are in the log: {}", cut.s);
            assert!(s.engines[0].wal_head_lsn().await.unwrap() > cut.s);
            for (shard, snapshot) in &cut.reads {
                let engine = &s.engines[usize::from(*shard)];
                for key in [format!("before-{shard}"), format!("held-{shard}")] {
                    assert!(seen(engine, &key, snapshot).await, "{key}");
                }
            }
            assert!(!seen(&s.engines[0], "after-0", &cut.reads[0].1).await);
        })
    }

    // Round after round, a writer confirms a write on shard 0 and then makes
    // one on shard 1 while a cut is taken: a cut that holds the second write
    // holds the first. Round 0 cuts between the two writes, round 1 while the
    // second is held in flight, the rest after a varying number of yields.
    #[test]
    fn a_write_confirmed_before_one_in_the_cut_is_in_the_cut_too() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::engine::TestHook;
            const ROUNDS: usize = 100;
            let hook = Arc::new(TestHook::default());
            let s = TwoShards::new(|k, engine| {
                if k == 1 {
                    engine.hooks.before_kv_pair_apply = Some((b"b-1".to_vec(), Arc::clone(&hook)));
                }
            })
            .await;
            let (mut a_only, mut both) = (0, 0);
            let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
            for i in 0..ROUNDS {
                let (a_done, a_confirmed) = tokio::sync::oneshot::channel();
                let (go, gate) = tokio::sync::oneshot::channel::<()>();
                let writer = compio::runtime::spawn({
                    let engines = s.engines.clone();
                    async move {
                        engines[0].put(format!("a-{i}").as_bytes(), b"v").await.unwrap();
                        let _ = a_done.send(());
                        gate.await.unwrap();
                        engines[1].put(format!("b-{i}").as_bytes(), b"v").await.unwrap();
                    }
                });
                let cut = if i == 0 {
                    a_confirmed.await.unwrap();
                    let cut = s.control.consistent_cut(Engine::Kv).await.unwrap();
                    go.send(()).unwrap();
                    cut
                } else if i == 1 {
                    go.send(()).unwrap();
                    hook.reached.notified().await;
                    let cut = compio::runtime::spawn({
                        let control = Arc::clone(&s.control);
                        async move { control.consistent_cut(Engine::Kv).await }
                    });
                    settle().await;
                    hook.release.notify_one();
                    cut.await.unwrap().unwrap()
                } else {
                    go.send(()).unwrap();
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    for _ in 0..state % 16 {
                        tokio::task::yield_now().await;
                    }
                    s.control.consistent_cut(Engine::Kv).await.unwrap()
                };
                let a = seen(&s.engines[0], &format!("a-{i}"), &cut.reads[0].1).await;
                let b = seen(&s.engines[1], &format!("b-{i}"), &cut.reads[1].1).await;
                assert!(a || !b, "b-{i} without a-{i}");
                a_only += usize::from(a && !b);
                both += usize::from(a && b);
                writer.await.unwrap();
            }
            assert!(a_only > 0, "no cut fell between the two writes");
            assert!(both > 0, "no cut held both writes");
        })
    }

    // A batch on shard 1 parked halfway through its MemTable inserts, its
    // record already in the log, holds the cut's drain back; the cut then
    // holds the whole batch, never half of it, and s covers its record.
    #[test]
    fn a_batch_half_applied_during_the_drain_is_in_the_cut_whole() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::engine::{BatchOp, ThreadHook};
            let (hook, reached, release) = ThreadHook::new();
            let s = TwoShards::new(|k, engine| {
                if k == 1 {
                    engine.hooks.batch_first_applied = Some(Arc::clone(&hook));
                }
            })
            .await;
            let batch = {
                let engine = Arc::clone(&s.engines[1]);
                let ops = ["x", "y"].map(|key| BatchOp::Put { key: key.as_bytes().to_vec(), value: b"v".to_vec() });
                std::thread::spawn(move || crate::core::engine_runtime::block_on(engine.write_batch(ops.to_vec())))
            };
            reached.recv().unwrap();
            let logged = s.engines[1].wal_head_lsn().await.unwrap();

            let cut = compio::runtime::spawn({
                let control = Arc::clone(&s.control);
                async move { control.consistent_cut(Engine::Kv).await }
            });
            settle().await;
            assert!(!cut.is_finished(), "the cut waits for the batch");
            release.send(()).unwrap();
            batch.join().unwrap().unwrap();
            let cut = cut.await.unwrap().unwrap();

            assert!(cut.s >= logged, "s {} below the batch record {logged}", cut.s);
            for key in ["x", "y"] {
                assert!(seen(&s.engines[1], key, &cut.reads[1].1).await, "{key}");
            }
        })
    }

    // A domain write held in flight on shard 1, its record in the log but not
    // yet applied, holds a metrics sample back until it applies; the sample
    // then counts it with the writes of shard 0, and the next sample counts
    // it again, once.
    #[test]
    fn a_metrics_sample_waits_for_a_write_in_flight_and_counts_it_once() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::engine::TestHook;
            let [a, b] = [0, 1].map(|shard| slots::domain_name_for_shard(shard, 2, 21));
            let held = [format!("d:{:016x}:", crate::engines::lsm::domain::fnv64(b.as_bytes())).as_bytes(), b"held"].concat();
            let hook = Arc::new(TestHook::default());
            let s = TwoShards::new(|k, engine| {
                if k == 1 {
                    engine.hooks.before_kv_pair_apply = Some((held.clone(), Arc::clone(&hook)));
                }
            })
            .await;
            for name in [&a, &b] {
                s.control.create_domain(Engine::Kv, name, false).await.unwrap();
            }
            for key in [b"k1", b"k2"] {
                s.registries[0].store(&a).await.unwrap().put(key, b"v").await.unwrap();
            }
            assert_eq!(s.control.sample_metrics().await.unwrap().total_writes, 2);

            let store = s.registries[1].store(&b).await.unwrap();
            let writer = compio::runtime::spawn(async move { store.put(b"held", b"v").await });
            hook.reached.notified().await;
            let sample = compio::runtime::spawn({
                let control = Arc::clone(&s.control);
                async move { control.sample_metrics().await }
            });
            settle().await;
            assert!(!sample.is_finished(), "the sample waits for the write in flight");
            hook.release.notify_one();
            writer.await.unwrap().unwrap();
            let during = sample.await.unwrap().unwrap();
            let after = s.control.sample_metrics().await.unwrap();
            assert_eq!((during.total_writes, after.total_writes), (3, 3));
            assert_eq!(s.commands_of(1), ["sample", "sample", "sample"]);
        })
    }

    // Two metrics samples asked for at once take their rounds one after the
    // other: shard 1 keeps the samples it has back and then runs them in
    // reverse order, and still both end and count every write.
    #[test]
    fn two_metrics_samples_at_once_both_end() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::new(|_, _| {}).await;
            for (k, name) in [0, 1].map(|shard| slots::domain_name_for_shard(shard, 2, 21)).iter().enumerate() {
                s.control.create_domain(Engine::Kv, name, false).await.unwrap();
                s.registries[k].store(name).await.unwrap().put(b"k", b"v").await.unwrap();
            }

            s.hold_samples[1].send_replace(true);
            let samples: Vec<_> = (0..2)
                .map(|_| {
                    let control = Arc::clone(&s.control);
                    compio::runtime::spawn(async move { control.sample_metrics().await })
                })
                .collect();
            // Upper bound against hanging only.
            let limit = Duration::from_secs(30);
            let first_held = async {
                while !s.commands_of(1).contains(&"sample") {
                    tokio::task::yield_now().await;
                }
            };
            compio::time::timeout(limit, first_held).await.expect("no sample reaches shard 1");
            settle().await;
            s.hold_samples[1].send_replace(false);
            let samples = compio::time::timeout(limit, futures::future::join_all(samples))
                .await
                .expect("the two samples deadlock");
            for sample in samples {
                assert_eq!(sample.unwrap().unwrap().total_writes, 2);
            }
        })
    }

    // While a cut has pinned shard 0 but not yet taken its read there, a
    // newer version is written and flushed beside an older one and the two
    // are compacted: the pin keeps the older one, the cut reads the newer
    // one. Once the cut is gone, the next compaction drops the older one.
    #[test]
    fn a_cut_keeps_the_versions_it_reads_from_compaction() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::reader::{GetResult, Snapshot};
            let s = TwoShards::new(|_, _| {}).await;
            let engine = &s.engines[0];
            let flush = || async {
                engine.freeze_active_memtable();
                engine.flush_memtable().await.unwrap();
            };
            engine.put(b"k", b"old").await.unwrap();
            flush().await;

            s.hold_confirms[0].send_replace(true);
            let cut = compio::runtime::spawn({
                let control = Arc::clone(&s.control);
                async move { control.consistent_cut(Engine::Kv).await }
            });
            while !s.commands_of(0).contains(&"confirm") {
                tokio::task::yield_now().await;
            }
            let pinned = Snapshot::new(engine.snapshot_registry().low_watermark().expect("shard 0 is pinned"));
            engine.put(b"k", b"new").await.unwrap();
            flush().await;
            engine.compact_level(0).await.unwrap();
            assert_eq!(engine.get_with_snapshot(b"k", &pinned).await.unwrap(), GetResult::Present(b"old".to_vec()));

            s.hold_confirms[0].send_replace(false);
            let cut = cut.await.unwrap().unwrap();
            let read = engine.get_with_snapshot(b"k", cut.reads[0].1.snapshot()).await.unwrap();
            assert_eq!(read, GetResult::Present(b"new".to_vec()));

            drop(cut);
            engine.compact_level(1).await.unwrap();
            let read = engine.get_with_snapshot(b"k", &pinned).await.unwrap();
            assert_eq!(read, GetResult::Absent, "the old version is gone");
        })
    }

    // A delete drains the writes of its domain's shard on that shard's
    // thread: a write in flight there holds it up, one on the other shard
    // does not. Only the owner's purger removes the data, and the owner's
    // command loop finishes the deletion.
    #[test]
    fn a_delete_drains_the_owner_shard_and_only_its_purger_purges() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::new(|_, _| {}).await;
            let [first, second] = [17, 18].map(|seed| slots::domain_name_for_shard(1, 2, seed));
            for name in [&first, &second] {
                s.control.create_domain(Engine::Kv, name, false).await.unwrap();
                s.registries[1].store(name).await.unwrap().put(b"k", b"v").await.unwrap();
            }

            let elsewhere = s.engines[0].in_flight_write_for_test().await;
            s.control.delete_domain(Engine::Kv, &first).await.unwrap();
            drop(elsewhere);

            let in_flight = s.engines[1].in_flight_write_for_test().await;
            let delete = compio::runtime::spawn({
                let (control, name) = (Arc::clone(&s.control), second.clone());
                async move { control.delete_domain(Engine::Kv, &name).await }
            });
            while s.state(&second) != Some(Lifecycle::Deleting) {
                tokio::task::yield_now().await;
            }
            settle().await;
            assert!(!delete.is_finished(), "the delete waits for the write in flight on the owner");
            drop(in_flight);
            delete.await.unwrap().unwrap();

            let purge =
                |shard: usize| DomainPurger::new(Arc::clone(&s.engines[shard]), Arc::clone(&s.registries[shard]), 100);
            for _ in 0..2 {
                purge(0).purge_tick().await.unwrap();
            }
            assert_eq!(s.state(&first), Some(Lifecycle::Deleting), "shard 0 does not own it");
            for _ in 0..2 {
                purge(1).purge_tick().await.unwrap();
            }
            assert_eq!(s.state(&first), None);
            assert_eq!(s.state(&second), None);
            assert_eq!(s.commands_of(1), ["quiesce", "quiesce", "finalize", "finalize"]);
            assert!(s.commands_of(0).is_empty(), "{:?}", s.commands_of(0));
        })
    }

    // A thousand health checks at once while both shards hold their pings
    // back send one ping to each. Once that one is answered, the next check
    // sends a new one and does not take the old answer for its own.
    #[test]
    fn concurrent_health_checks_send_one_ping_per_shard() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::new(|_, _| {}).await;
            let pings = |k| s.commands_of(k).iter().filter(|name| **name == "ping").count();
            let hold = |held: bool| {
                for hold in &s.hold_pings {
                    hold.send_replace(held);
                }
            };

            hold(true);
            let checks = (0..1000).map(|_| s.control.ping_shards(|_| Duration::ZERO));
            for answered in futures::future::join_all(checks).await {
                assert_eq!(answered, [false, false]);
            }
            settle().await;
            assert_eq!((pings(0), pings(1)), (1, 1));

            hold(false);
            settle().await;
            hold(true);
            assert_eq!(s.control.ping_shards(|_| Duration::ZERO).await, [false, false], "an earlier answer must not count");
            settle().await;
            assert_eq!((pings(0), pings(1)), (2, 2));

            hold(false);
            // Upper bound against hanging only.
            assert_eq!(s.control.ping_shards(|_| Duration::from_secs(30)).await, [true, true]);
        })
    }

    /// The key `key` of the domain `domain`, as the domain layer writes it.
    fn data_key(domain: &str, key: &str) -> Vec<u8> {
        format!("d:{:016x}:{key}", crate::engines::lsm::domain::fnv64(domain.as_bytes())).into_bytes()
    }

    /// A domain of each of the two shards.
    fn two_domains() -> [String; 2] {
        [0, 1].map(|k| slots::domain_name_for_shard(k, 2, 5))
    }

    /// What a read of each key returns on the instance of its shard.
    async fn reads(engines: &[Arc<LsmStorageEngine>], keys: &[(usize, Vec<u8>)]) -> Vec<(GetResult, u64, u64)> {
        let mut reads = Vec::with_capacity(keys.len());
        for (k, key) in keys {
            reads.push(engines[*k].get_latest_with_stamp(key).await.unwrap());
        }
        reads
    }

    /// Waits until shard `k` got its `count`-th `Persist`.
    async fn until_persists(s: &TwoShards, k: usize, count: usize) {
        let wait = async {
            while s.commands_of(k).iter().filter(|name| **name == "persist").count() < count {
                tokio::task::yield_now().await;
            }
        };
        // Upper bound against hanging only.
        compio::time::timeout(Duration::from_secs(30), wait).await.expect("no persist reaches the shard");
    }

    const LARGE: &str = "clé ✓ value stored in the value log ";
    /// The segment size of the logs in these tests.
    const SEGMENT: u64 = 2048;
    /// What the age check of the checkpoint waits for.
    const FIVE_MINUTES: Duration = Duration::from_secs(5 * 60);

    // Writes of every kind on both shards over many segments, a tick after
    // each round, with a cap of three segments: each tick leaves the
    // segments below the cap, a write while a shard persists stays in the
    // log, and after a crash every confirmed write is there with its value
    // and stamp and every deleted one is gone.
    #[test]
    fn a_crash_after_writes_past_the_cap_keeps_every_confirmed_write() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::engine::BatchOp;
            const LIMIT: u64 = 3 * SEGMENT;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(LIMIT);
            let total = || s.segment_files().iter().map(|(_, bytes)| bytes).sum::<u64>();
            let domains = two_domains();
            let large = LARGE.repeat(40);
            let (mut keys, mut deleted, mut round) = (Vec::new(), Vec::new(), 0);
            while s.segment_files()[0].0 < 6 {
                for (k, engine) in s.engines.iter().enumerate() {
                    let key = |name: &str| data_key(&domains[k], &format!("{name}-{round}"));
                    engine.put(&key("small"), "clé".as_bytes()).await.unwrap();
                    engine.put(&key("large"), large.as_bytes()).await.unwrap();
                    engine.set_null(&key("nulled")).await.unwrap();
                    engine.put(&key("gone"), b"v").await.unwrap();
                    engine.delete(&key("gone")).await.unwrap();
                    let batch = vec![
                        BatchOp::Put { key: key("batch"), value: b"1".to_vec() },
                        BatchOp::Delete { key: key("small") },
                    ];
                    engine.write_batch(batch).await.unwrap();
                    keys.extend(["large", "nulled", "batch"].map(|name| (k, key(name))));
                    deleted.extend(["small", "gone"].map(|name| (k, key(name))));
                }
                assert_eq!(checkpoints.run().await, []);
                // A prepared segment holds its header alone.
                assert!(total() < LIMIT + crate::core::wal::WAL_HEADER_LEN, "round {round}: {:?}", s.segment_files());
                round += 1;
                assert!(round < 100, "no segment goes: {:?}", s.segment_files());
            }

            // Shard 1 is behind on the segment that closes here, so a tick
            // with the smallest cap drops every closed segment and has shard
            // 1 persist on the way.
            let before = data_key(&domains[1], "before");
            s.engines[1].put(&before, b"v").await.unwrap();
            keys.push((1, before));
            s.hub.wal(crate::core::storage_thread::WalTarget::Kv).rotate().await.unwrap();
            let persists = s.commands_of(1).iter().filter(|name| **name == "persist").count();
            s.hold_persists[1].send_replace(true);
            let tick = compio::runtime::spawn({
                let checkpoints = s.checkpoints(1);
                async move { checkpoints.run().await }
            });
            until_persists(&s, 1, persists + 1).await;
            let during = data_key(&domains[1], "during");
            s.engines[1].put(&during, b"v").await.unwrap();
            keys.push((1, during.clone()));
            s.hold_persists[1].send_replace(false);
            assert_eq!(tick.await.unwrap(), []);
            // The segment appended to, read alone: the one prepared after it
            // starts at LSN 0 until the hub opens it.
            let segments = s.hub.wal(crate::core::storage_thread::WalTarget::Kv).segments().await.unwrap();
            let active = crate::core::wal::segment_path(&segments.dir, segments.active().segment);
            let mut reader = crate::core::wal::recover(active).await.unwrap();
            let mut last = None;
            while let Some(entry) = reader.next().await {
                last = Some(entry.unwrap().1);
            }
            assert_eq!(last.as_ref().map(|entry| entry.key()), Some(during.as_slice()));

            let confirmed = reads(&s.engines, &keys).await;
            let (engines, _hub, _dir) = s.crash().await;
            assert_eq!(reads(&engines, &keys).await, confirmed);
            for read in reads(&engines, &deleted).await {
                assert_eq!(read.0, GetResult::Absent);
            }
        })
    }

    // A write whose value log append failed after its record went into the
    // log goes with its segment, which the age check closes and drops:
    // after a crash it is gone, and the confirmed writes are there.
    #[test]
    fn a_write_whose_value_failed_is_gone_after_its_segment_and_a_crash() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::new(|_, _| {}).await;
            let [domain, _] = two_domains();
            let (failed, kept) = (data_key(&domain, "failed"), data_key(&domain, "kept"));
            let large = LARGE.repeat(40);
            let engine = &s.engines[0];
            let active = Arc::clone(&engine.version().active_vlog);
            let full = Arc::new(crate::storage::vlog::VLog::new("/dev/full").await.unwrap());
            engine.install(|v| v.with_active_vlog(full, engine.last_applied_lsn()));
            assert!(engine.put(&failed, large.as_bytes()).await.is_err());
            engine.install(|v| v.with_active_vlog(active, engine.last_applied_lsn()));
            engine.put(&kept, large.as_bytes()).await.unwrap();
            let checkpoints = s.checkpoints(u64::MAX);
            checkpoints.skew_clock(FIVE_MINUTES);
            assert_eq!(checkpoints.run().await, []);
            assert!(s.holds_only_a_header());

            let (engines, _hub, _dir) = s.crash().await;
            assert_eq!(engines[0].get(&failed).await.unwrap(), None);
            assert_eq!(engines[0].get(&kept).await.unwrap(), Some(large.into_bytes()));
        })
    }

    // Values of a dropped segment that a value log cleanup moves afterwards
    // are all there after a crash.
    #[test]
    fn values_moved_by_a_cleanup_after_a_dropped_segment_survive_a_crash() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::new(|_, _| {}).await;
            let [domain, _] = two_domains();
            let keys: Vec<_> = (0..3).map(|i| (0, data_key(&domain, &format!("large-{i}")))).collect();
            for (round, value) in ["old", "new"].iter().enumerate() {
                for (_, key) in &keys[round..] {
                    s.engines[0].put(key, format!("{value} {}", LARGE.repeat(40)).as_bytes()).await.unwrap();
                }
            }
            let checkpoints = s.checkpoints(u64::MAX);
            checkpoints.skew_clock(FIVE_MINUTES);
            assert_eq!(checkpoints.run().await, []);
            assert!(s.holds_only_a_header());
            let config = crate::engines::lsm::janitor::JanitorConfig {
                check_interval_secs: 3600,
                dead_bytes_threshold: 0.0,
                min_vlog_size_bytes: 0,
            };
            assert!(s.engines[0].build_janitor(config).run_gc().await.unwrap().ran);

            let confirmed = reads(&s.engines, &keys).await;
            let (engines, _hub, _dir) = s.crash().await;
            assert_eq!(reads(&engines, &keys).await, confirmed);
            assert!(confirmed.iter().all(|read| matches!(read.0, GetResult::Present(_))));
        })
    }

    /// Writes on both shards until the key-value log of `s` has segments
    /// before the one appended to; the keys written, by shard.
    async fn fill_segments(s: &TwoShards, segments: u64) -> Vec<(usize, Vec<u8>)> {
        let domains = two_domains();
        let mut keys = Vec::new();
        for i in 0.. {
            if s.segment_files().iter().filter(|(_, bytes)| *bytes > crate::core::wal::WAL_HEADER_LEN).count() as u64
                >= segments
            {
                break;
            }
            for (k, domain) in domains.iter().enumerate() {
                let key = data_key(domain, &format!("k{i}"));
                s.engines[k].put(&key, LARGE.repeat(8).as_bytes()).await.unwrap();
                keys.push((k, key));
            }
        }
        keys
    }

    /// The bytes of every segment of the key-value log of `s`, in order.
    fn log_bytes(s: &TwoShards) -> Vec<u8> {
        crate::core::wal::segments_in(&s.wal_path()).unwrap().into_iter().flat_map(|(_, path)| std::fs::read(path).unwrap()).collect()
    }

    // Records over three segments: while shard 0 has none of its records in
    // SSTables, no segment goes, even once shard 1 has all of its there;
    // once shard 0 flushes too, every segment before the one appended to
    // goes, each removal synced, and after a crash every write is there.
    #[test]
    fn a_segment_goes_once_every_shard_has_its_records_in_sstables() {
        crate::core::engine_runtime::block_on(async {
            use crate::storage::test_trace;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(u64::MAX);
            let keys = fill_segments(&s, 3).await;
            let active = s.hub.wal(crate::core::storage_thread::WalTarget::Kv).segments().await.unwrap().active().segment;

            s.engines[1].flush_all_memtables().await.unwrap();
            assert_eq!(checkpoints.run().await, []);
            assert_eq!(s.segment_files()[0].0, 1, "shard 0 has none of its records in SSTables");

            s.engines[0].flush_all_memtables().await.unwrap();
            test_trace::watch(&s.wal_path());
            assert_eq!(checkpoints.run().await, []);
            assert_eq!(s.segment_files()[0].0, active);
            let removals: Vec<String> = (1..active).flat_map(|n| [format!("unlink {n:08}.wal"), "sync .".to_string()]).collect();
            let steps = test_trace::steps(&s.wal_path());
            assert!(steps.starts_with(&removals), "{steps:?}");

            let confirmed = reads(&s.engines, &keys).await;
            let (engines, _hub, _dir) = s.crash().await;
            assert_eq!(reads(&engines, &keys).await, confirmed);
        })
    }

    // Test 6: while the shards refuse writes, a checkpoint tick still has
    // them persist and drops every segment before the one appended to.
    #[test]
    fn segments_go_while_the_shards_refuse_writes() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let keys = fill_segments(&s, 3).await;
            let active = s.hub.wal(crate::core::storage_thread::WalTarget::Kv).segments().await.unwrap().active().segment;
            for engine in &s.engines {
                engine.resources().block_for_test(false, false);
                assert!(engine.writes_refused());
            }

            assert_eq!(s.checkpoints(1).run().await, []);
            assert_eq!(s.segment_files()[0].0, active);

            let confirmed = reads(&s.engines, &keys).await;
            let (engines, _hub, _dir) = s.crash().await;
            assert_eq!(reads(&engines, &keys).await, confirmed);
        })
    }

    // A removal that fails fails the tick and keeps the segment's file; the
    // next tick removes it and reports that, and every write is there.
    #[test]
    fn a_failed_removal_is_retried_by_the_next_tick() {
        crate::core::engine_runtime::block_on(async {
            use crate::storage::test_fault;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(u64::MAX);
            let keys = fill_segments(&s, 2).await;
            for engine in &s.engines {
                engine.flush_all_memtables().await.unwrap();
            }
            let log = log_bytes(&s);
            let dir = std::fs::canonicalize(s.wal_path()).unwrap();
            test_fault::fail_writes_in(&dir);
            let reports = checkpoints.run().await;
            test_fault::allow_writes_in(&dir);

            assert!(matches!(&reports[..], [Report::Stuck { log: "kv", bytes: Some(_), .. }]), "{reports:?}");
            assert_eq!(log_bytes(&s), log, "the log stays whole");
            assert_eq!(checkpoints.run().await, [Report::Recovered { log: "kv", failures: 1 }]);
            assert!(s.segment_files()[0].0 > 1);

            let (engines, _hub, _dir) = s.crash().await;
            for (k, key) in &keys {
                assert!(engines[*k].get(key).await.unwrap().is_some());
            }
        })
    }

    // With a cap of three segments, shard 0 writes and flushes while shard 1
    // wrote nothing: once the cap is reached only shard 1, behind on the
    // oldest segment, gets a Persist; shard 0 is not held back, a write
    // there goes through meanwhile. Shard 1 raises its flushed LSN without an
    // SSTable, and the segment goes. The segments never pass the cap by more
    // than the largest record, also one larger than a segment.
    #[test]
    fn the_cap_has_only_the_shards_behind_persist() {
        crate::core::engine_runtime::block_on(async {
            const LIMIT: u64 = 3 * SEGMENT;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(LIMIT);
            let total = || s.segment_files().iter().map(|(_, bytes)| bytes).sum::<u64>();
            let [domain, _] = two_domains();
            let tables = || {
                let dir = testing::kv_shard_files(s.dir.path()).sstables.join("shard_1");
                std::fs::read_dir(dir).unwrap().filter(|e| e.as_ref().unwrap().path().extension() == Some("sst".as_ref())).count()
            };
            let shard_1_tables = tables();
            let mut keys = Vec::new();
            for i in 0..40 {
                let value = if i == 20 { LARGE.repeat(150) } else { LARGE.repeat(8) };
                let key = data_key(&domain, &format!("k{i}"));
                s.engines[0].put(&key, value.as_bytes()).await.unwrap();
                keys.push((0, key));
                s.engines[0].flush_all_memtables().await.unwrap();
                let bound = LIMIT + SEGMENT.max(value.len() as u64 + 128);
                assert!(total() <= bound, "write {i}: {:?}", s.segment_files());
                assert_eq!(checkpoints.run().await, []);
            }
            assert!(s.segment_files()[0].0 > 1, "no segment went: {:?}", s.segment_files());
            assert!(!s.commands_of(0).contains(&"persist"), "{:?}", s.commands_of(0));
            assert!(s.commands_of(1).contains(&"persist"));
            assert_eq!(tables(), shard_1_tables, "shard 1 had nothing to write");

            // The segment closed here ends past the flushed LSN of shard 1.
            s.hub.wal(crate::core::storage_thread::WalTarget::Kv).rotate().await.unwrap();
            s.hold_persists[1].send_replace(true);
            let persists = s.commands_of(1).iter().filter(|name| **name == "persist").count();
            let tick = compio::runtime::spawn({
                let checkpoints = s.checkpoints(1);
                async move { checkpoints.run().await }
            });
            until_persists(&s, 1, persists + 1).await;
            let during = data_key(&domain, "during");
            s.engines[0].put(&during, b"v").await.unwrap();
            keys.push((0, during));
            s.hold_persists[1].send_replace(false);
            assert_eq!(tick.await.unwrap(), []);

            let confirmed = reads(&s.engines, &keys).await;
            let (engines, _hub, _dir) = s.crash().await;
            assert_eq!(reads(&engines, &keys).await, confirmed);
        })
    }

    // Right after a rotation the segment appended to holds its header alone;
    // the next tick prepares the one after it all the same, so the hub finds
    // it however soon the segment fills.
    #[test]
    fn the_tick_after_a_rotation_prepares_the_next_segment_at_once() {
        crate::core::engine_runtime::block_on(async {
            let header = crate::core::wal::WAL_HEADER_LEN;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(u64::MAX);
            let [domain, _] = two_domains();
            s.engines[0].put(&data_key(&domain, "k"), b"v").await.unwrap();
            s.hub.wal(crate::core::storage_thread::WalTarget::Kv).rotate().await.unwrap();
            assert_eq!(s.segment_files()[1..], [(2, header)]);

            assert_eq!(checkpoints.run().await, []);
            assert_eq!(s.segment_files()[1..], [(2, header), (3, header)]);
        })
    }

    // With a cap of three segments and two full closed ones, the segments
    // stay below the cap, yet the closed ones plus a full one reach it: the
    // tick has both shards, behind on the oldest segment, persist and drops
    // it, so the segment that fills until the next tick keeps the log within
    // a segment of the cap.
    #[test]
    fn the_cap_has_the_shards_persist_a_segment_before_it_is_reached() {
        crate::core::engine_runtime::block_on(async {
            const LIMIT: u64 = 3 * SEGMENT;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(LIMIT);
            let wal = s.hub.wal(crate::core::storage_thread::WalTarget::Kv);
            let closed_bytes = |segments: &crate::core::storage_thread::WalSegments| {
                segments.closed().iter().map(|segment| segment.bytes).sum::<u64>()
            };
            fill_segments(&s, 3).await;
            let segments = wal.segments().await.unwrap();
            assert!(segments.total_bytes() < LIMIT, "{segments:?}");
            assert!(closed_bytes(&segments) + SEGMENT >= LIMIT, "{segments:?}");

            assert_eq!(checkpoints.run().await, []);
            assert!(s.segment_files()[0].0 > 1, "no segment went: {:?}", s.segment_files());
            assert!(s.commands_of(0).contains(&"persist"), "{:?}", s.commands_of(0));
            assert!(s.commands_of(1).contains(&"persist"), "{:?}", s.commands_of(1));
            let segments = wal.segments().await.unwrap();
            assert!(closed_bytes(&segments) + SEGMENT < LIMIT, "{segments:?}");
        })
    }

    // The age check on an injected clock: a segment with records, five
    // minutes open, is closed, the shard behind on it persists, and the log
    // is one empty segment; an empty one stays however old; one written to
    // once a minute is closed after five minutes all the same. Each next
    // segment is prepared, never created by the hub.
    #[test]
    fn a_segment_with_records_goes_after_five_minutes() {
        crate::core::engine_runtime::block_on(async {
            use crate::storage::test_trace;
            let s = TwoShards::new(|_, _| {}).await;
            test_trace::watch(&s.wal_path());
            let checkpoints = s.checkpoints(u64::MAX);
            let [_, domain] = two_domains();
            let key = |i: u32| data_key(&domain, &format!("k{i}"));
            s.engines[1].put(&key(0), b"v").await.unwrap();
            checkpoints.skew_clock(FIVE_MINUTES - Duration::from_secs(60));
            assert_eq!(checkpoints.run().await, []);
            assert_eq!(s.segment_files()[0].0, 1);
            checkpoints.skew_clock(FIVE_MINUTES);
            assert_eq!(checkpoints.run().await, []);
            assert!(s.holds_only_a_header());
            assert_eq!(s.segment_files()[0].0, 2);
            assert!(s.commands_of(1).contains(&"persist"));

            checkpoints.skew_clock(2 * FIVE_MINUTES);
            assert_eq!(checkpoints.run().await, []);
            let header = crate::core::wal::WAL_HEADER_LEN;
            assert_eq!(s.segment_files(), [(2, header), (3, header)], "an empty segment stays, the next one prepared");

            checkpoints.skew_clock(Duration::ZERO);
            for minute in 1..=5 {
                s.engines[1].put(&key(minute), b"v").await.unwrap();
                checkpoints.skew_clock(Duration::from_secs(60 * u64::from(minute)));
                assert_eq!(checkpoints.run().await, []);
                assert_eq!(s.segment_files()[0].0 == 2, minute < 5, "minute {minute}");
            }
            assert!(s.holds_only_a_header());
            let steps = test_trace::steps(&s.wal_path());
            assert!(!steps.iter().any(|step| step.starts_with("create ")), "{steps:?}");

            let (engines, _hub, _dir) = s.crash().await;
            for i in 0..=5 {
                assert_eq!(engines[1].get(&key(i)).await.unwrap(), Some(b"v".to_vec()), "k{i}");
            }
        })
    }

    // A flush that fails on shard 1 fails the checkpoint: no segment goes.
    // Once the flush works again, the next tick drops the segments and
    // reports that.
    #[test]
    fn a_failed_flush_on_one_shard_leaves_the_log_whole_until_the_next_tick() {
        crate::core::engine_runtime::block_on(async {
            use crate::storage::test_fault;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(SEGMENT);
            fill_segments(&s, 2).await;
            let log = log_bytes(&s);
            let total = s.hub.wal(crate::core::storage_thread::WalTarget::Kv).segments().await.unwrap().total_bytes();
            let unwritable = testing::kv_shard_files(s.dir.path()).sstables.join("shard_1");
            test_fault::fail_writes_in(&unwritable);
            let reports = checkpoints.run().await;
            test_fault::allow_writes_in(&unwritable);

            assert!(
                matches!(&reports[..], [Report::Stuck { log: "kv", bytes: Some(bytes), .. }] if *bytes == total),
                "{reports:?}"
            );
            assert!(log_bytes(&s).starts_with(&log), "no segment went");
            assert_eq!(checkpoints.run().await, [Report::Recovered { log: "kv", failures: 1 }]);
            assert!(s.segment_files()[0].0 > 1);
        })
    }

    // A log whose checkpoint fails tick after tick is reported on the first
    // failure and once every 60 ticks: twice in 120 ticks; the first tick
    // that succeeds reports that once.
    #[test]
    fn a_checkpoint_failing_120_times_is_reported_twice() {
        crate::core::engine_runtime::block_on(async {
            use crate::storage::test_fault;
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(SEGMENT);
            fill_segments(&s, 2).await;
            let unwritable = testing::kv_shard_files(s.dir.path()).sstables.join("shard_1");
            test_fault::fail_writes_in(&unwritable);
            let mut reports = Vec::new();
            for _ in 0..120 {
                reports.extend(checkpoints.run().await);
            }
            test_fault::allow_writes_in(&unwritable);

            assert_eq!(reports.len(), 2, "{reports:?}");
            assert!(reports.iter().all(|report| matches!(report, Report::Stuck { log: "kv", .. })));
            assert_eq!(checkpoints.run().await, [Report::Recovered { log: "kv", failures: 120 }]);
            assert_eq!(checkpoints.run().await, []);
        })
    }

    // A shard that does not answer its Persist fails the tick and keeps
    // every segment.
    #[test]
    fn a_shard_without_an_answer_keeps_every_segment() {
        crate::core::engine_runtime::block_on(async {
            let s = TwoShards::with_segments(|_, _| {}, SEGMENT).await;
            let checkpoints = s.checkpoints(SEGMENT);
            fill_segments(&s, 2).await;
            s.drop_persists[1].send_replace(true);
            let log = log_bytes(&s);
            let reports = checkpoints.run().await;
            assert!(matches!(&reports[..], [Report::Stuck { log: "kv", .. }]), "{reports:?}");
            assert!(log_bytes(&s).starts_with(&log), "no segment went");
            assert_eq!(s.segment_files()[0].0, 1);
        })
    }

    /// A control plane with no worker behind it; the receiver is the worker's end.
    async fn without_worker(dir: &tempfile::TempDir) -> (ControlPlane, mpsc::UnboundedReceiver<Command>) {
        let (commands, inbox) = mpsc::unbounded_channel();
        let control = ControlPlane {
            commands,
            directory: RwLock::default(),
            bus: Arc::new(GlobalEventBus::new(16, 16)),
            system: system::open(&dir.path().join("sys")).await.unwrap(),
            shards: Vec::new(),
            rounds: tokio::sync::Mutex::new(()),
            restoring: AtomicBool::new(false),
            pings: Mutex::default(),
            resources: Default::default(),
        };
        (control, inbox)
    }

    #[test]
    fn every_command_fails_once_the_worker_is_gone() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (control, inbox) = without_worker(&dir).await;
            drop(inbox);

            let created = control.create_domain(Engine::Kv, "orphan", false).await.unwrap_err();
            assert!(matches!(created, DomainError::Stopped), "{created:?}");
            let deleted = control.delete_domain(Engine::Kv, "orphan").await.unwrap_err();
            assert!(matches!(deleted, DomainError::Stopped), "{deleted:?}");
            let record = UserRecord {
                name: "alice".to_string(),
                api_key_hash: hash_api_key("lura_alice"),
                role: UserRole::User,
                created_at: 0,
            };
            let changed = control.change_auth(AuthChange::UpsertUser(record)).await.unwrap_err();
            assert_eq!(changed.to_string(), "the control plane is not running");
            let finalized = control.finalize_deletion(Engine::Kv, "orphan").await.unwrap_err();
            assert_eq!(finalized.to_string(), "the control plane is not running");
        })
    }

    #[test]
    fn a_command_dropped_unanswered_fails() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (control, inbox) = without_worker(&dir).await;
            // Queued first, then dropped with the inbox, as when the worker panics.
            let create = control.create_domain(Engine::Kv, "orphan", false);
            let (created, ()) = futures::future::join(create, async move { drop(inbox) }).await;
            assert!(matches!(created, Err(DomainError::Stopped)), "{created:?}");
        })
    }
}
