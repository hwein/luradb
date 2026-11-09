//! Control plane: runs the rare, global mutations — domain create, delete
//! and engine clears across the engines, auth changes — one at a time on a
//! single worker task, holds the directory of all domains, owns the system
//! store, is the one publisher of the global event stream and takes
//! consistent cuts, metrics samples and write-ahead log checkpoints across
//! the data shards.

pub mod checkpoint;
pub mod domains;
pub mod resources;
pub mod slots;
pub mod system;

use crate::auth::oauth::{OAuthClient, RedeemCode, Refresh, TokenRecord};
use crate::auth::{AccessLevel, AuthCache, UserRecord};
use crate::core::events::GlobalEventBus;
use crate::engines::json::{JsonDomainState, JsonEngine};
use crate::engines::lsm::domain::{DomainRegistry, DomainState};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::reader::{RegistrySnapshot, Snapshot};
use crate::engines::rel::{RelDomainState, RelEngine};
use crate::metrics::MetricsSample;
use anyhow::Context;
pub use domains::{ConditionalWrites, DomainRules};
use domains::DomainRecord;
use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Storage engine that holds a part of every domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Kv,
    Json,
    Rel,
}

impl Engine {
    /// Every engine, in the order a domain's parts are created.
    pub const ALL: [Engine; 3] = [Engine::Kv, Engine::Json, Engine::Rel];

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

/// Lifecycle state of a domain, or of its part in one engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
    pub state: Lifecycle,
    pub slot: u16,
    /// Unix seconds.
    pub created_at: u64,
    pub require_conditional_writes: ConditionalWrites,
    /// The engines whose data of the domain is still to be removed.
    pub purging: Vec<Engine>,
}

impl DomainEntry {
    fn new(name: &str, record: &DomainRecord) -> Self {
        Self {
            name: name.to_string(),
            state: record.state,
            slot: slots::slot_of_domain(name),
            created_at: record.created_at,
            require_conditional_writes: record.require_conditional_writes,
            purging: record.purging.clone(),
        }
    }

    fn record(&self) -> DomainRecord {
        DomainRecord {
            state: self.state,
            created_at: self.created_at,
            require_conditional_writes: self.require_conditional_writes,
            purging: self.purging.clone(),
        }
    }

    /// The state of the domain's part in `engine`: deleting while that part
    /// is still to be removed.
    pub fn state_in(&self, engine: Engine) -> Lifecycle {
        self.record().state_in(engine)
    }
}

/// Every domain, by name; read-only, replaced as a whole on change.
#[derive(Debug, Clone, Default)]
pub struct Directory {
    entries: BTreeMap<String, DomainEntry>,
    generation: u64,
}

impl Directory {
    async fn of(system: &LsmStorageEngine) -> anyhow::Result<Self> {
        let records = domains::load_all(system).await?;
        let entries = records.iter().map(|(name, record)| (name.clone(), DomainEntry::new(name, record))).collect();
        Ok(Self { entries, generation: 0 })
    }

    /// Every domain, ordered by name.
    pub fn domains(&self) -> impl Iterator<Item = &DomainEntry> {
        self.entries.values()
    }

    pub fn get(&self, name: &str) -> Option<&DomainEntry> {
        self.entries.get(name)
    }

    /// Counts the changes since the start: equal generations, equal directories.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn insert(&mut self, entry: DomainEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    fn remove(&mut self, name: &str) {
        self.entries.remove(name);
    }
}

/// A failed domain command.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("invalid domain name '{name}': allowed are [a-zA-Z0-9_-], 1 to {max} characters")]
    InvalidName { name: String, max: usize },
    #[error("domain '{0}' already exists")]
    Exists(String),
    #[error("domain '{0}' is being deleted")]
    Deleting(String),
    #[error("domain '{0}' not found")]
    NotFound(String),
    /// A step in the system store or an engine failed.
    #[error("{0:#}")]
    Failed(anyhow::Error),
    /// The worker that runs the commands is gone.
    #[error("the control plane is not running")]
    Stopped,
}

/// A domain's record in one engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EngineRecord {
    pub state: Lifecycle,
    pub created_at: u64,
    pub require_conditional_writes: bool,
}

impl EngineRecord {
    fn of(state: Lifecycle, created_at: u64, require_conditional_writes: bool) -> Self {
        Self { state, created_at, require_conditional_writes }
    }
}

fn lifecycle_kv(state: &DomainState) -> Lifecycle {
    match state {
        DomainState::Active => Lifecycle::Active,
        DomainState::Deleting => Lifecycle::Deleting,
    }
}

fn lifecycle_json(state: &JsonDomainState) -> Lifecycle {
    match state {
        JsonDomainState::Active => Lifecycle::Active,
        JsonDomainState::Deleting => Lifecycle::Deleting,
    }
}

fn lifecycle_rel(state: &RelDomainState) -> Lifecycle {
    match state {
        RelDomainState::Active => Lifecycle::Active,
        RelDomainState::Deleting => Lifecycle::Deleting,
    }
}

/// A change to the auth records.
#[derive(Debug)]
pub enum AuthChange {
    UpsertUser(UserRecord),
    /// Removes the user and all its permissions.
    RemoveUser(String),
    RotateKey { name: String, new_hash: String },
    /// Grants `access` on `engine` of `domain`, `None` the whole domain; a
    /// user holds either a grant on the whole domain or engine grants.
    SetPermission { username: String, domain: String, engine: Option<Engine>, access: AccessLevel },
    /// Revokes the grant on `engine` of `domain`; `None` revokes every grant
    /// on the domain.
    RemovePermission { username: String, domain: String, engine: Option<Engine> },
    RegisterClient(OAuthClient),
    IssueCode { hash: String, record: TokenRecord, now: u64 },
    RedeemCode(RedeemCode),
    Refresh(Refresh),
    RevokeToken { hash: String },
}

enum Command {
    CreateDomain {
        name: String,
        require_conditional_writes: ConditionalWrites,
        reply: oneshot::Sender<Result<DomainEntry, DomainError>>,
    },
    DeleteDomain { name: String, reply: oneshot::Sender<Result<(), DomainError>> },
    ClearEngine {
        engine: Engine,
        name: String,
        require_conditional_writes: Option<bool>,
        reply: oneshot::Sender<Result<(), DomainError>>,
    },
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

    /// The enabled engines, in the order a domain's parts are created.
    pub(crate) fn engines(&self) -> Vec<Engine> {
        Engine::ALL.into_iter().filter(|engine| self.instance(*engine).is_some()).collect()
    }

    /// The record of `name` in `engine`, in any state.
    pub(crate) fn record(&self, engine: Engine, name: &str) -> Option<EngineRecord> {
        match engine {
            Engine::Kv => self
                .kv
                .get_domain_any(name)
                .map(|d| EngineRecord::of(lifecycle_kv(&d.state), d.created_at, d.require_conditional_writes)),
            Engine::Json => self.json.as_ref()?.get_domain_any(name).map(|d| {
                EngineRecord::of(lifecycle_json(&d.state), d.created_at, d.require_conditional_writes)
            }),
            Engine::Rel => {
                self.rel.as_ref()?.get_domain_any(name).map(|d| EngineRecord::of(lifecycle_rel(&d.state), d.created_at, false))
            }
        }
    }

    /// Every record of `engine`, by name.
    pub(crate) async fn records(&self, engine: Engine) -> anyhow::Result<Vec<(String, EngineRecord)>> {
        let names: Vec<String> = match engine {
            Engine::Kv => {
                let active = self.kv.list_domains().await?.into_iter();
                active.chain(self.kv.list_deleting_domains()).map(|d| d.name).collect()
            }
            Engine::Json => self.json.iter().flat_map(|json| json.list_domains()).map(|d| d.name).collect(),
            Engine::Rel => self.rel.iter().flat_map(|rel| rel.list_domains()).map(|d| d.name).collect(),
        };
        Ok(names.into_iter().filter_map(|name| self.record(engine, &name).map(|record| (name, record))).collect())
    }

    /// Writes an empty record of `name` in the enabled `engine`.
    pub(crate) async fn create_record(&self, engine: Engine, name: &str, require_conditional_writes: bool) -> anyhow::Result<()> {
        match engine {
            Engine::Kv => self.kv.create_domain_with(name, require_conditional_writes).await.map(drop),
            Engine::Json => Ok(self.json()?.create_domain_with(name, require_conditional_writes).await.map(drop)?),
            Engine::Rel => Ok(self.rel()?.create_domain(name).await.map(drop)?),
        }
    }

    /// Turns the active record of `name` in the enabled `engine` deleting.
    pub(crate) async fn mark_deleting(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        match engine {
            Engine::Kv => self.kv.delete_domain(name).await,
            Engine::Json => Ok(self.json()?.delete_domain(name).await?),
            Engine::Rel => Ok(self.rel()?.delete_domain(name).await?),
        }
    }

    fn json(&self) -> anyhow::Result<&Arc<JsonEngine>> {
        self.json.as_ref().context("the json engine is disabled")
    }

    fn rel(&self) -> anyhow::Result<&Arc<RelEngine>> {
        self.rel.as_ref().context("the rel engine is disabled")
    }

    async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        match engine {
            Engine::Kv => self.kv.finalize_domain_deletion(name).await,
            Engine::Json => Ok(self.json()?.finalize_deletion(name).await?),
            Engine::Rel => Ok(self.rel()?.finalize_deletion(name).await?),
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
                        None => Err(anyhow::anyhow!("the {} engine is disabled", engine.as_str())),
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
    /// The last ping sent to each data shard, by shard index.
    pings: Mutex<Vec<Option<Shared<BoxFuture<'static, bool>>>>>,
    resources: resources::Resources,
    max_name_length: usize,
}

impl ControlPlane {
    /// Reads the domain records into the directory, attaches itself to the
    /// engines of every shard — before any purger runs, so none finishes a
    /// deletion behind its back — and starts the worker on the current
    /// runtime. Domain names are valid up to `max_name_length`.
    pub async fn start(
        owners: Owners,
        system: Arc<LsmStorageEngine>,
        bus: Arc<GlobalEventBus>,
        resources: resources::Resources,
        max_name_length: usize,
    ) -> anyhow::Result<Arc<Self>> {
        let Owners { shards, auth } = owners;
        let (commands, inbox) = mpsc::unbounded_channel();
        let control = Arc::new(Self {
            commands,
            directory: RwLock::new(Arc::new(Directory::of(&system).await?)),
            bus,
            system,
            pings: Mutex::new(vec![None; shards.len()]),
            shards,
            rounds: tokio::sync::Mutex::new(()),
            resources,
            max_name_length,
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
        let worker = Worker { auth, control: Arc::clone(&control), abandoned: Mutex::default() };
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

    /// The longest valid domain name.
    pub fn max_name_length(&self) -> usize {
        self.max_name_length
    }

    /// Fails unless `name` is a valid domain name.
    pub fn check_name(&self, name: &str) -> Result<(), DomainError> {
        if domains::is_valid_name(name, self.max_name_length) {
            Ok(())
        } else {
            Err(DomainError::InvalidName { name: name.to_string(), max: self.max_name_length })
        }
    }

    /// Creates a domain in every enabled engine.
    pub async fn create_domain(
        &self,
        name: &str,
        require_conditional_writes: ConditionalWrites,
    ) -> Result<DomainEntry, DomainError> {
        self.request(|reply| Command::CreateDomain { name: name.to_string(), require_conditional_writes, reply }).await
    }

    /// Deletes a domain in two phases: it turns away new requests at once,
    /// and the call returns only after the writes already admitted ended.
    /// The purgers remove its data afterwards.
    pub async fn delete_domain(&self, name: &str) -> Result<(), DomainError> {
        self.request(|reply| Command::DeleteDomain { name: name.to_string(), reply }).await
    }

    /// Empties the part of the active domain `name` in `engine`, as a delete
    /// does, and gives it an empty part again once the purger is done; the
    /// domain and its other parts stay. `require_conditional_writes`, when
    /// set, becomes the engine's setting for the new part.
    pub(crate) async fn clear_engine(
        &self,
        engine: Engine,
        name: &str,
        require_conditional_writes: Option<bool>,
    ) -> Result<(), DomainError> {
        self.request(|reply| Command::ClearEngine { engine, name: name.to_string(), require_conditional_writes, reply })
            .await
    }

    /// Removes the deleted part of `name` in `engine`, whose data the purger
    /// has removed.
    pub(crate) async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        self.request(|reply| Command::FinalizeDeletion { engine, name: name.to_string(), reply }).await
    }

    pub async fn change_auth(&self, change: AuthChange) -> anyhow::Result<()> {
        self.request(|reply| Command::ChangeAuth { change, reply }).await
    }

    /// Publishes one event of an object in `engine` on the global event
    /// stream; this, [`Self::publish_global_many`] and the domain events of
    /// the worker are the stream's only entries.
    pub fn publish_global(&self, engine: Engine, kind: &'static str, domain: &str, object: Option<String>) {
        self.bus.publish(Some(engine.as_str()), kind, domain, object);
    }

    /// Publishes `events` as adjacent events with no foreign one between them.
    pub fn publish_global_many(&self, engine: Engine, domain: &str, events: &[(&'static str, Option<String>)]) {
        self.bus.publish_many(engine.as_str(), domain, events);
    }

    fn publish_domain(&self, kind: &'static str, domain: &str) {
        self.bus.publish(None, kind, domain, None);
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
    /// The domains whose create failed in this run: no event announced them,
    /// none reports their fall.
    abandoned: Mutex<std::collections::HashSet<String>>,
}

impl Worker {
    async fn run(self, mut inbox: mpsc::UnboundedReceiver<Command>) {
        while let Some(command) = inbox.recv().await {
            // A caller that gave up does not stop its command.
            match command {
                Command::CreateDomain { name, require_conditional_writes, reply } => {
                    let _ = reply.send(self.create_domain(&name, require_conditional_writes).await);
                }
                Command::DeleteDomain { name, reply } => {
                    let _ = reply.send(self.delete_domain(&name).await);
                }
                Command::ClearEngine { engine, name, require_conditional_writes, reply } => {
                    let _ = reply.send(self.clear_engine(engine, &name, require_conditional_writes).await);
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

    /// The directory entry of `name`, unless it is missing or deleting.
    fn active(&self, name: &str) -> Result<DomainEntry, DomainError> {
        match self.control.directory().get(name) {
            None => Err(DomainError::NotFound(name.to_string())),
            Some(entry) if entry.state == Lifecycle::Deleting => Err(DomainError::Deleting(name.to_string())),
            Some(entry) => Ok(entry.clone()),
        }
    }

    /// Writes `record` of `name` and shows it in the directory.
    async fn store(&self, name: &str, record: &DomainRecord) -> anyhow::Result<()> {
        domains::put(&self.control.system, name, record).await?;
        self.control.change_directory(|d| d.insert(DomainEntry::new(name, record)));
        Ok(())
    }

    /// Like [`Self::store`], and removes every permission on the domain in
    /// the same write.
    async fn store_without_permissions(&self, name: &str, record: &DomainRecord) -> anyhow::Result<()> {
        self.auth.remove_domain(name, domains::put_op(name, record)?).await?;
        self.control.change_directory(|d| d.insert(DomainEntry::new(name, record)));
        Ok(())
    }

    /// Lets every write of `engines` admitted so far end, each on the
    /// owner's thread; all quiesces reach the shard before the first wait.
    async fn quiesce(&self, owner: &Shard, engines: &[Engine]) -> Result<(), DomainError> {
        let quiesces = engines.iter().map(|&engine| owner.request(move |reply| ShardCommand::Quiesce { engine, reply }));
        futures::future::try_join_all(quiesces).await.map_err(|_| DomainError::Stopped)?;
        Ok(())
    }

    /// The domain record first, then its part in each enabled engine; a
    /// failed part deletes what was created, without an event.
    async fn create_domain(
        &self,
        name: &str,
        require_conditional_writes: ConditionalWrites,
    ) -> Result<DomainEntry, DomainError> {
        self.control.check_name(name)?;
        match self.control.directory().get(name) {
            Some(entry) if entry.state == Lifecycle::Deleting => return Err(DomainError::Deleting(name.to_string())),
            Some(_) => return Err(DomainError::Exists(name.to_string())),
            None => {}
        }
        let owners = &self.control.owner(name).owners;
        let mut record = DomainRecord::new(crate::engines::lsm::domain::now_secs(), require_conditional_writes);
        domains::put(&self.control.system, name, &record).await.map_err(DomainError::Failed)?;
        for engine in owners.engines() {
            if let Err(e) = owners.create_record(engine, name, require_conditional_writes.of(engine)).await {
                if let Err(undo) = self.abandon(name, &mut record).await {
                    tracing::warn!("domain '{name}': removing the failed create failed: {undo:#}");
                }
                return Err(DomainError::Failed(e));
            }
        }
        let entry = DomainEntry::new(name, &record);
        self.control.change_directory(|d| d.insert(entry.clone()));
        self.control.publish_domain("domain_created", name);
        Ok(entry)
    }

    /// Takes a failed create down the delete path; the engines that never
    /// got their part have nothing to purge. The record turns deleting
    /// before any part does, so a crash in between leaves no live domain.
    async fn abandon(&self, name: &str, record: &mut DomainRecord) -> anyhow::Result<()> {
        let owners = &self.control.owner(name).owners;
        let enabled = owners.engines();
        record.state = Lifecycle::Deleting;
        record.purging = Engine::ALL
            .into_iter()
            .filter(|engine| !enabled.contains(engine) || owners.record(*engine, name).is_some())
            .collect();
        if record.purging.is_empty() {
            return self.auth.remove_domain(name, domains::remove_op(name)).await;
        }
        self.abandoned.lock().insert(name.to_string());
        self.store_without_permissions(name, record).await?;
        for engine in enabled {
            if owners.record(engine, name).is_some_and(|part| part.state == Lifecycle::Active) {
                owners.mark_deleting(engine, name).await?;
            }
        }
        Ok(())
    }

    async fn delete_domain(&self, name: &str) -> Result<(), DomainError> {
        let mut record = self.active(name)?.record();
        record.state = Lifecycle::Deleting;
        record.purging = Engine::ALL.to_vec();
        // The directory follows the record before any engine does: a purger
        // that finishes early never reads it active. The permissions go with it.
        self.store_without_permissions(name, &record).await.map_err(DomainError::Failed)?;
        let owner = self.control.owner(name);
        let engines = owner.owners.engines();
        for &engine in &engines {
            // A part an engine clear already deletes stays as it is.
            if owner.owners.record(engine, name).is_some_and(|part| part.state == Lifecycle::Active) {
                owner.owners.mark_deleting(engine, name).await.map_err(DomainError::Failed)?;
            }
        }
        // Writes that passed the domain check before it turned `Deleting`.
        self.quiesce(owner, &engines).await?;
        self.control.publish_domain("domain_deleted", name);
        Ok(())
    }

    async fn clear_engine(
        &self,
        engine: Engine,
        name: &str,
        require_conditional_writes: Option<bool>,
    ) -> Result<(), DomainError> {
        let mut record = self.active(name)?.record();
        if let Some(value) = require_conditional_writes {
            record.require_conditional_writes.set(engine, value);
        }
        record.add_purging(engine);
        self.store(name, &record).await.map_err(DomainError::Failed)?;
        let owner = self.control.owner(name);
        let enabled = owner.owners.instance(engine).is_some();
        if enabled && owner.owners.record(engine, name).is_some_and(|part| part.state == Lifecycle::Active) {
            owner.owners.mark_deleting(engine, name).await.map_err(DomainError::Failed)?;
        }
        if enabled {
            self.quiesce(owner, &[engine]).await?;
        }
        Ok(())
    }

    /// Removes the purged part of `name` in `engine`. An active domain gets
    /// an empty part there again; a deleted one falls with its last part.
    async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        let owner = self.control.owner(name);
        owner.request(|reply| ShardCommand::FinalizeDeletion { engine, name: name.to_string(), reply }).await??;
        let Some(entry) = self.control.directory().get(name).cloned() else { return Ok(()) };
        let mut record = entry.record();
        record.purging.retain(|e| *e != engine);
        if record.state == Lifecycle::Active {
            // The record first: a crash before the part leaves one the start creates empty.
            self.store(name, &record).await?;
            owner.owners.create_record(engine, name, record.require_conditional_writes.of(engine)).await
        } else if record.purging.is_empty() {
            // Again: permissions may have been set while the domain was deleting.
            self.auth.remove_domain(name, domains::remove_op(name)).await?;
            owner.owners.kv.metrics().remove_domain(name);
            self.control.change_directory(|d| d.remove(name));
            if !self.abandoned.lock().remove(name) {
                self.control.publish_domain("domain_purged", name);
            }
            Ok(())
        } else {
            self.store(name, &record).await
        }
    }

    async fn change_auth(&self, change: AuthChange) -> anyhow::Result<()> {
        let auth = &self.auth;
        match change {
            AuthChange::UpsertUser(record) => auth.upsert_user(record).await,
            AuthChange::RemoveUser(name) => auth.remove_user(&name).await,
            AuthChange::RotateKey { name, new_hash } => auth.rotate_key(&name, &new_hash).await,
            AuthChange::SetPermission { username, domain, engine, access } => {
                auth.change_permission(&username, &domain, engine, Some(access)).await
            }
            AuthChange::RemovePermission { username, domain, engine } => {
                auth.change_permission(&username, &domain, engine, None).await
            }
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
    /// own under `dir/sys` and an auth cache on it, after the reconciliation
    /// a start runs.
    pub(super) async fn start_over(
        dir: &Path,
        shards: Vec<Shard>,
        bus: Arc<GlobalEventBus>,
    ) -> (Arc<ControlPlane>, Arc<AuthCache>) {
        let system = system::open(&dir.join("sys")).await.unwrap();
        let rules = DomainRules::default();
        let owners: Vec<_> = shards.iter().map(|shard| shard.owners.clone()).collect();
        domains::reconcile(&system, &owners, &rules).await.unwrap();
        let auth = Arc::new(AuthCache::new(Arc::clone(&system), None));
        let owners = Owners { shards, auth: Arc::clone(&auth) };
        (ControlPlane::start(owners, system, bus, Default::default(), rules.max_name_length).await.unwrap(), auth)
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

    /// A key-value, a JSON and a relational engine under `dir`, the last two
    /// with a default domain of their own, as engines of one data shard.
    pub(crate) async fn all_engines(dir: &Path) -> ShardOwners {
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let kv = kv_registry(dir).await;
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
        ShardOwners { kv, json: Some(json), rel: Some(rel) }
    }

    /// The files of the key-value shards of [`kv_shards`] under `dir`, laid
    /// out as the server lays them out.
    pub(crate) fn kv_shard_files(dir: &Path) -> crate::server::recovery::EngineFiles {
        let base = dir.join("kv-shards");
        crate::server::recovery::EngineFiles { wal: dir.join("kv.wal"), vlog: base.join("vlog"), sstables: base }
    }

    /// `n` data shards' key-value engines writing one log through `hub`,
    /// `tune` applied to engine `k` before it is shared.
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
            let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
            let config = crate::engines::lsm::domain::DomainConfig::default();
            let registry = DomainRegistry::recover(Arc::new(engine), config, metrics).await.unwrap();
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

        fn state(&self, name: &str) -> Option<Lifecycle> {
            self.control.directory().get(name).map(|entry| entry.state)
        }

        fn purging(&self, name: &str) -> Vec<Engine> {
            self.control.directory().get(name).map(|entry| entry.purging.clone()).unwrap_or_default()
        }

        /// The domain record of `name` in the system store.
        async fn record(&self, name: &str) -> Option<DomainRecord> {
            domains::load_all(&self.control.system).await.unwrap().remove(name)
        }

        /// The state of the record of `name` in each engine.
        fn parts(&self, name: &str) -> [Option<Lifecycle>; 3] {
            let owners = &self.control.shards[0].owners;
            Engine::ALL.map(|engine| owners.record(engine, name).map(|part| part.state))
        }

        /// Waits until `name` and its part in every engine are `Deleting` —
        /// the delete's first phase ran.
        async fn until_deleting(&self, name: &str) {
            let wait = async {
                while self.state(name) != Some(Lifecycle::Deleting)
                    || self.parts(name) != [Some(Lifecycle::Deleting); 3]
                {
                    tokio::task::yield_now().await;
                }
            };
            // Upper bound against hanging only.
            compio::time::timeout(Duration::from_secs(10), wait).await.expect("the domain never turned Deleting");
        }

        fn next_event(&mut self) -> (Option<&'static str>, &'static str, String) {
            let event = self.events.try_recv().expect("an event");
            (event.engine, event.kind, event.domain)
        }

        /// Two ticks of the purger of `engine`: one removes the data, one
        /// finishes the deletion.
        async fn purge(&self, engine: Engine) {
            for _ in 0..2 {
                match engine {
                    Engine::Kv => purger(self).purge_tick().await.unwrap(),
                    Engine::Json => {
                        crate::engines::json::JsonDomainPurger::new(Arc::clone(&self.json), 100).purge_tick().await.unwrap()
                    }
                    Engine::Rel => {
                        crate::engines::rel::RelDomainPurger::new(Arc::clone(&self.rel), 100).purge_tick().await.unwrap()
                    }
                }
            }
        }

        async fn purge_all(&self) {
            for engine in Engine::ALL {
                self.purge(engine).await;
            }
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
    fn a_create_writes_the_domain_record_and_a_part_in_every_engine() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            assert!(f.events.try_recv().is_err(), "the start creates the default domain without an event");
            assert_eq!(f.parts("default"), [Some(Lifecycle::Active); 3]);
            let setting = ConditionalWrites { kv: true, json: false };
            let created = f.control.create_domain("shop", setting).await.unwrap();
            assert_eq!((created.state, created.require_conditional_writes), (Lifecycle::Active, setting));
            assert!(created.purging.is_empty());

            let record = f.record("shop").await.expect("a domain record");
            assert_eq!((record.state, record.require_conditional_writes), (Lifecycle::Active, setting));
            assert_eq!(f.parts("shop"), [Some(Lifecycle::Active); 3]);
            assert!(f.kv.get_domain("shop").await.unwrap().unwrap().require_conditional_writes);
            assert!(!f.json.get_domain("shop").unwrap().require_conditional_writes);
            assert_eq!(f.next_event(), (None, "domain_created", "shop".to_string()));
            assert!(f.events.try_recv().is_err(), "one event for the domain");
        })
    }

    // A part that cannot be created takes the domain down the delete path:
    // no event, the name stays taken until the purgers are done.
    #[test]
    fn a_create_failing_in_json_or_rel_deletes_what_it_created_without_events() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.json.create_domain_with("clash-json", false).await.unwrap();
            f.rel.create_domain("clash-rel").await.unwrap();
            for (name, failed) in [("clash-json", Engine::Json), ("clash-rel", Engine::Rel)] {
                f.control.change_auth(grant("ana", name, None, AccessLevel::Read)).await.unwrap();
                let refused = f.control.create_domain(name, Default::default()).await.unwrap_err();
                assert!(matches!(refused, DomainError::Failed(_)), "{name}: {refused:?}");
                assert_eq!(f.state(name), Some(Lifecycle::Deleting), "{name}");
                assert_eq!(f.auth.effective("ana", name, None).await, None, "{name}: a grant set beforehand goes");
                assert!(stored_permissions(&f).await.is_empty(), "{name}");
                let again = f.control.create_domain(name, Default::default()).await.unwrap_err();
                assert!(matches!(again, DomainError::Deleting(_)), "{name}: {again:?}");
                let expected = match failed {
                    Engine::Json => [Some(Lifecycle::Deleting), Some(Lifecycle::Deleting), None],
                    _ => [Some(Lifecycle::Deleting), Some(Lifecycle::Deleting), Some(Lifecycle::Deleting)],
                };
                assert_eq!(f.parts(name), expected, "{name}");
            }
            f.purge_all().await;
            for name in ["clash-json", "clash-rel"] {
                assert_eq!(f.state(name), None, "{name}");
                assert_eq!(f.record(name).await, None, "{name}");
            }
            assert!(f.events.try_recv().is_err(), "no event for a failed create");
            f.control.create_domain("clash-json", Default::default()).await.unwrap();
            assert_eq!(f.next_event(), (None, "domain_created", "clash-json".to_string()));
        })
    }

    // A delete marks the record and every engine deleting, waits for the
    // writes of each engine, and the domain falls once the last purger is done.
    #[test]
    fn a_delete_purges_every_engine_and_the_domain_falls_after_the_last_one() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            f.kv.store("doomed").await.unwrap().put(b"k", "clé ✓".as_bytes()).await.unwrap();
            f.json.put_document("doomed", "d", json!({"n": 1})).await.unwrap();
            f.rel.execute("doomed", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
            f.next_event();
            f.next_event();

            f.control.delete_domain("doomed").await.unwrap();
            let record = f.record("doomed").await.unwrap();
            assert_eq!((record.state, record.purging), (Lifecycle::Deleting, Engine::ALL.to_vec()));
            assert_eq!(f.parts("doomed"), [Some(Lifecycle::Deleting); 3]);
            assert_eq!(f.next_event(), (None, "domain_deleted", "doomed".to_string()));

            for (engine, left) in [(Engine::Kv, vec![Engine::Json, Engine::Rel]), (Engine::Json, vec![Engine::Rel])] {
                f.purge(engine).await;
                assert_eq!(f.purging("doomed"), left);
                assert!(f.events.try_recv().is_err(), "no domain_purged before the last purger");
            }
            f.purge(Engine::Rel).await;
            assert_eq!(f.next_event(), (None, "domain_purged", "doomed".to_string()));
            assert_eq!((f.state("doomed"), f.record("doomed").await), (None, None));
            assert_eq!(f.parts("doomed"), [None; 3]);
        })
    }

    #[test]
    fn a_deleting_name_refuses_a_create_and_a_second_delete() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            f.control.delete_domain("doomed").await.unwrap();
            let created = f.control.create_domain("doomed", Default::default()).await.unwrap_err();
            assert!(matches!(created, DomainError::Deleting(_)), "{created:?}");
            let deleted = f.control.delete_domain("doomed").await.unwrap_err();
            assert!(matches!(deleted, DomainError::Deleting(_)), "{deleted:?}");
            let missing = f.control.delete_domain("ghost").await.unwrap_err();
            assert!(matches!(missing, DomainError::NotFound(_)), "{missing:?}");
        })
    }

    // Clearing an engine empties its part like a delete does; the purger
    // gives it an empty part again, and the domain stays, without an event.
    #[test]
    fn clearing_an_engine_empties_its_part_and_keeps_the_domain() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain("shop", Default::default()).await.unwrap();
            f.next_event();
            f.kv.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
            f.json.put_document("shop", "d", json!({"n": 1})).await.unwrap();

            f.control.clear_engine(Engine::Kv, "shop", Some(true)).await.unwrap();
            assert_eq!((f.state("shop"), f.purging("shop")), (Some(Lifecycle::Active), vec![Engine::Kv]));
            assert_eq!(f.parts("shop"), [Some(Lifecycle::Deleting), Some(Lifecycle::Active), Some(Lifecycle::Active)]);
            let refused = f.kv.store("shop").await.err().expect("the cleared part takes no request");
            assert!(refused.to_string().starts_with("410"), "{refused}");
            assert!(f.json.get_document("shop", "d").await.unwrap().is_some());

            f.purge(Engine::Kv).await;
            assert_eq!((f.state("shop"), f.purging("shop")), (Some(Lifecycle::Active), vec![]));
            assert_eq!(f.parts("shop"), [Some(Lifecycle::Active); 3]);
            let store = f.kv.store("shop").await.unwrap();
            assert!(store.scan_keys(b"").await.unwrap().is_empty());
            assert!(store.domain().require_conditional_writes, "the setting the clear brought");
            assert!(f.record("shop").await.unwrap().require_conditional_writes.kv);
            assert!(f.json.get_document("shop", "d").await.unwrap().is_some());
            assert!(f.events.try_recv().is_err(), "a clear sends no event");
        })
    }

    // A clear while the part of an earlier clear is still being purged
    // leaves that part as it is.
    #[test]
    fn clearing_an_engine_again_before_its_purge_succeeds() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("shop", Default::default()).await.unwrap();
            for _ in 0..2 {
                f.control.clear_engine(Engine::Json, "shop", None).await.unwrap();
            }
            assert_eq!(f.purging("shop"), [Engine::Json]);
            assert_eq!(f.parts("shop"), [Some(Lifecycle::Active), Some(Lifecycle::Deleting), Some(Lifecycle::Active)]);

            f.purge(Engine::Json).await;
            assert_eq!(f.parts("shop"), [Some(Lifecycle::Active); 3]);
        })
    }

    #[test]
    fn a_kv_delete_waits_for_in_flight_writes_and_then_hands_over_to_the_purger() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            f.kv.store("doomed").await.unwrap().put(b"k", "clé ✓".as_bytes()).await.unwrap();
            assert_eq!(f.next_event(), (None, "domain_created", "doomed".to_string()));

            let in_flight = f.kv.engine().in_flight_write_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain("doomed").await }
            });
            f.until_deleting("doomed").await;
            settle().await;
            assert!(!delete.is_finished(), "the delete must wait for the write in flight");
            assert!(f.ping_answers().await, "the shard answers a ping while the delete waits");
            assert!(!delete.is_finished(), "the delete must wait for the write in flight");
            let refused = f.kv.store("doomed").await.err().expect("a new write must be refused");
            assert!(refused.to_string().starts_with("410"), "{refused}");
            assert!(f.events.try_recv().is_err(), "no domain_deleted before the drain");

            drop(in_flight);
            delete.await.unwrap().unwrap();
            assert_eq!(f.next_event(), (None, "domain_deleted", "doomed".to_string()));

            f.purge_all().await;
            assert_eq!(f.next_event(), (None, "domain_purged", "doomed".to_string()));
            assert_eq!(f.state("doomed"), None);
            assert!(f.kv.get_domain("doomed").await.unwrap().is_none());
        })
    }

    const KV_GONE: &str = "410 Gone: Domain 'doomed' is being deleted";

    #[test]
    fn a_kv_write_that_reaches_its_guard_during_the_delete_is_refused() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            let store = f.kv.store("doomed").await.unwrap();
            let late = f.kv.store("doomed").await.unwrap();
            let prefix = store.domain().system_prefix.clone();

            let in_flight = f.kv.engine().in_flight_write_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain("doomed").await }
            });
            f.until_deleting("doomed").await;
            let late_write = compio::runtime::spawn(async move { late.put(b"late", b"v").await });
            settle().await;
            assert!(!delete.is_finished(), "the delete must wait for the write in flight");

            drop(in_flight);
            delete.await.unwrap().unwrap();
            assert_eq!(late_write.await.unwrap().unwrap_err().to_string(), KV_GONE);
            assert_eq!(store.put(b"again", b"v").await.unwrap_err().to_string(), KV_GONE);
            assert_eq!(f.state("doomed"), Some(Lifecycle::Deleting), "refused before the finalize");
            assert!(f.kv.engine().scan_keys(&prefix).await.unwrap().is_empty());
        })
    }

    #[test]
    fn a_kv_store_taken_before_the_delete_stays_refused_after_the_purge() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            let store = f.kv.store("doomed").await.unwrap();
            store.put(b"k", b"v").await.unwrap();
            let prefix = store.domain().system_prefix.clone();

            f.control.delete_domain("doomed").await.unwrap();
            f.purge_all().await;
            assert_eq!(f.state("doomed"), None);

            assert_eq!(store.put(b"late", b"v").await.unwrap_err().to_string(), KV_GONE);
            assert!(f.kv.engine().scan_keys(&prefix).await.unwrap().is_empty());

            f.control.create_domain("doomed", Default::default()).await.unwrap();
            assert_eq!(store.put(b"late", b"v").await.unwrap_err().to_string(), KV_GONE);
            let reborn = f.kv.store("doomed").await.unwrap();
            assert!(reborn.scan_keys(b"").await.unwrap().is_empty(), "no orphan in the new domain");
        })
    }

    #[test]
    fn a_json_delete_waits_for_a_held_document_lock_and_then_hands_over_to_the_purger() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            f.json.put_document("doomed", "k", json!({"n": 1})).await.unwrap();
            f.next_event();

            let lock = f.json.doc_write_lock_for_test("doomed", "held").await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain("doomed").await }
            });
            f.until_deleting("doomed").await;
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
            assert!(matches!(refused, crate::engines::json::JsonStoreError::DomainDeleting(_)), "got: {refused}");
            assert_eq!(f.next_event(), (None, "domain_deleted", "doomed".to_string()));

            f.purge_all().await;
            assert_eq!(f.next_event(), (None, "domain_purged", "doomed".to_string()));
            assert_eq!(f.state("doomed"), None);
        })
    }

    #[test]
    fn a_rel_delete_waits_for_the_write_guard_and_then_hands_over_to_the_purger() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            f.rel.execute("doomed", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
            assert_eq!(f.next_event(), (None, "domain_created", "doomed".to_string()));
            assert_eq!(f.next_event(), (Some("rel"), "table_created", "doomed".to_string()));

            let guard = f.rel.write_guard_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain("doomed").await }
            });
            f.until_deleting("doomed").await;
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
            assert!(matches!(refused, crate::engines::rel::RelStoreError::DomainDeleting(_)), "got: {refused}");
            assert_eq!(f.next_event(), (None, "domain_deleted", "doomed".to_string()));

            f.purge_all().await;
            assert_eq!(f.next_event(), (None, "domain_purged", "doomed".to_string()));
            assert_eq!(f.state("doomed"), None);
        })
    }

    // A delete waiting for the relational write guard on the only shard does
    // not hold up a metrics round there.
    #[test]
    fn a_metrics_round_ends_while_a_delete_waits() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            let guard = f.rel.write_guard_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain("doomed").await }
            });
            f.until_deleting("doomed").await;
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
            f.control.create_domain("doomed", Default::default()).await.unwrap();
            assert_eq!(f.next_event(), (None, "domain_created", "doomed".to_string()));
            let guard = f.rel.write_guard_for_test().await;
            let delete = compio::runtime::spawn({
                let control = Arc::clone(&f.control);
                async move { control.delete_domain("doomed").await }
            });
            f.until_deleting("doomed").await;
            let (reply, _flushed) = oneshot::channel();
            f.control.shards[0].commands.send(ShardCommand::Drain { reply }).unwrap();
            settle().await;
            assert!(!serving.is_finished(), "the drain waits for the delete");
            assert!(!delete.is_finished(), "the delete must wait for the write guard");

            drop(guard);
            assert!(serving.await.unwrap().is_some(), "the loop ends with the drain");
            delete.await.unwrap().unwrap();
            assert_eq!(f.next_event(), (None, "domain_deleted", "doomed".to_string()));
        })
    }

    #[test]
    fn concurrent_creates_of_one_name_have_exactly_one_winner() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            let creates = (0..8).map(|_| f.control.create_domain("contested", Default::default()));
            let created = futures::future::join_all(creates).await;
            assert_eq!(created.iter().filter(|r| r.is_ok()).count(), 1);
            for result in created.into_iter().filter_map(Result::err) {
                assert!(matches!(result, DomainError::Exists(_)), "got: {result:?}");
            }
        })
    }

    #[test]
    fn concurrent_deletes_of_one_domain_have_exactly_one_winner() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("contested", Default::default()).await.unwrap();
            let deletes = (0..8).map(|_| f.control.delete_domain("contested"));
            let results = futures::future::join_all(deletes).await;
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            for result in results.into_iter().filter_map(Result::err) {
                assert!(matches!(result, DomainError::Deleting(_)), "got: {result:?}");
            }
        })
    }

    #[test]
    fn a_delete_sent_during_a_create_runs_after_it() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            let create = f.control.create_domain("racy", Default::default());
            let delete = f.control.delete_domain("racy");
            let (created, deleted) = futures::future::join(create, delete).await;
            created.unwrap();
            deleted.unwrap();
            assert_eq!(f.state("racy"), Some(Lifecycle::Deleting));
            assert_eq!(f.next_event(), (None, "domain_created", "racy".to_string()));
            assert_eq!(f.next_event(), (None, "domain_deleted", "racy".to_string()));
        })
    }

    #[test]
    fn lifecycle_events_carry_domain_and_time_without_an_engine() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            f.control.create_domain("evdom", Default::default()).await.unwrap();
            f.control.delete_domain("evdom").await.unwrap();
            f.purge_all().await;
            for kind in ["domain_created", "domain_deleted", "domain_purged"] {
                let event = f.events.try_recv().unwrap();
                assert_eq!((event.engine, event.kind, event.domain.as_str()), (None, kind, "evdom"));
                assert_eq!(event.object, None);
                assert!(event.ts > 0);
            }
            assert!(f.events.try_recv().is_err(), "one event each for the domain");
        })
    }

    #[test]
    fn failed_lifecycle_commands_publish_nothing() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            let duplicate = f.control.create_domain("default", Default::default()).await.unwrap_err();
            assert!(matches!(duplicate, DomainError::Exists(_)), "{duplicate:?}");
            let missing = f.control.delete_domain("ghost").await.unwrap_err();
            assert!(matches!(missing, DomainError::NotFound(_)), "{missing:?}");
            let missing = f.control.clear_engine(Engine::Json, "ghost", None).await.unwrap_err();
            assert!(matches!(missing, DomainError::NotFound(_)), "{missing:?}");
            for bad in ["", "bad name!", "a:b", &"a".repeat(51)] {
                let invalid = f.control.create_domain(bad, Default::default()).await.unwrap_err();
                assert!(matches!(invalid, DomainError::InvalidName { max: 50, .. }), "{bad:?}: {invalid:?}");
            }
            assert!(f.events.try_recv().is_err());
        })
    }

    // The name rule is the same in every engine; "domains" is a name like
    // any other.
    #[test]
    fn a_name_of_the_longest_length_and_the_name_domains_work_in_every_engine() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            assert_eq!(f.control.max_name_length(), 50);
            for name in ["a".repeat(50), "domains".to_string(), "b_-9".to_string()] {
                f.control.create_domain(&name, Default::default()).await.unwrap();
                assert_eq!(f.parts(&name), [Some(Lifecycle::Active); 3], "{name}");
            }
            f.json.put_document("domains", "d", json!({"n": 1})).await.unwrap();
            f.rel.execute("domains", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
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
            (
                DomainError::InvalidName { name: "a:b".to_string(), max: 50 },
                "invalid domain name 'a:b': allowed are [a-zA-Z0-9_-], 1 to 50 characters",
            ),
            (DomainError::Exists("shop".to_string()), "domain 'shop' already exists"),
            (DomainError::NotFound("ghost".to_string()), "domain 'ghost' not found"),
            (DomainError::Deleting("doomed".to_string()), "domain 'doomed' is being deleted"),
            (DomainError::Failed(anyhow::anyhow!("disk gone")), "disk gone"),
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
            assert_eq!(f.state("default"), Some(Lifecycle::Active));

            let setting = ConditionalWrites { kv: true, json: true };
            f.control.create_domain("alpha", setting).await.unwrap();
            let before_delete = f.control.directory();
            f.control.delete_domain("alpha").await.unwrap();

            let alpha = before_delete.get("alpha").unwrap();
            assert_eq!(alpha.state, Lifecycle::Active, "an earlier view keeps its state");
            assert_eq!(alpha.slot, slots::slot_of_domain("alpha"));
            assert_eq!(alpha.require_conditional_writes, setting);
            assert!(alpha.created_at > 0);
            assert_eq!(f.state("alpha"), Some(Lifecycle::Deleting));
            assert_eq!(f.control.directory().get("alpha").unwrap().state_in(Engine::Json), Lifecycle::Deleting);
            let names: Vec<_> = f.control.directory().domains().map(|d| d.name.clone()).collect();
            assert_eq!(names, ["alpha", "default"]);
        })
    }

    #[test]
    fn a_purger_attached_before_its_spawn_still_reports_the_purge() {
        crate::core::engine_runtime::block_on(async {
            let mut f = Fixture::new().await;
            let purger = DomainPurger::new(Arc::clone(f.kv.engine()), Arc::clone(&f.kv), 1);

            f.control.create_domain("late-purge", Default::default()).await.unwrap();
            f.control.delete_domain("late-purge").await.unwrap();
            f.next_event();
            f.next_event();
            purger.purge_tick().await.unwrap();
            f.purge(Engine::Json).await;
            f.purge(Engine::Rel).await;
            assert_eq!(f.next_event(), (None, "domain_purged", "late-purge".to_string()));
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

    fn grant(username: &str, domain: &str, engine: Option<Engine>, access: AccessLevel) -> AuthChange {
        AuthChange::SetPermission { username: username.to_string(), domain: domain.to_string(), engine, access }
    }

    /// The stored permission keys, without their prefix.
    async fn stored_permissions(f: &Fixture) -> Vec<String> {
        let keys = f.control.system_store().scan_keys(crate::auth::PREFIX_PERM.as_bytes()).await.unwrap();
        keys.iter().map(|key| String::from_utf8_lossy(&key[crate::auth::PREFIX_PERM.len()..]).into_owned()).collect()
    }

    // The delete removes the grants of every user on the domain with the
    // record turning deleting, before any purger ran; a new domain of the
    // same name starts without any.
    #[test]
    fn deleting_a_domain_removes_every_permission_on_it() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            for name in ["shop", "keep"] {
                f.control.create_domain(name, Default::default()).await.unwrap();
            }
            for change in [
                grant("ana", "shop", None, AccessLevel::Write),
                grant("ben", "shop", Some(Engine::Json), AccessLevel::Read),
                grant("ben", "shop", Some(Engine::Rel), AccessLevel::Ddl),
                grant("ben", "keep", Some(Engine::Kv), AccessLevel::Read),
            ] {
                f.control.change_auth(change).await.unwrap();
            }

            f.control.delete_domain("shop").await.unwrap();
            assert_eq!(f.state("shop"), Some(Lifecycle::Deleting));
            for user in ["ana", "ben"] {
                assert_eq!(f.auth.effective(user, "shop", None).await, None, "{user}");
            }
            assert_eq!(stored_permissions(&f).await, ["ben:keep"]);

            f.purge_all().await;
            assert_eq!(f.state("shop"), None);
            f.control.create_domain("shop", Default::default()).await.unwrap();
            assert_eq!(f.auth.effective("ana", "shop", Some(Engine::Kv)).await, None);
            assert_eq!(f.auth.effective("ben", "keep", Some(Engine::Kv)).await, Some(AccessLevel::Read));
        })
    }

    // A grant set while the domain is deleting goes when its record falls.
    #[test]
    fn a_permission_set_while_the_domain_is_deleting_goes_with_its_record() {
        crate::core::engine_runtime::block_on(async {
            let f = Fixture::new().await;
            f.control.create_domain("shop", Default::default()).await.unwrap();
            f.control.delete_domain("shop").await.unwrap();
            f.control.change_auth(grant("ana", "shop", None, AccessLevel::Read)).await.unwrap();
            f.control.change_auth(grant("ana", "keep", Some(Engine::Json), AccessLevel::Read)).await.unwrap();
            f.purge(Engine::Kv).await;
            f.purge(Engine::Json).await;
            assert_eq!(f.auth.effective("ana", "shop", None).await, Some(AccessLevel::Read), "still deleting");

            f.purge(Engine::Rel).await;
            assert_eq!(f.state("shop"), None);
            assert_eq!(f.auth.effective("ana", "shop", None).await, None);
            assert_eq!(stored_permissions(&f).await, ["ana:json:keep"]);
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
            self.checkpoints_with(limit, Arc::default())
        }

        /// [`Self::checkpoints`] serving the flush requests of `relief`.
        fn checkpoints_with(&self, limit: u64, relief: Arc<resources::Relief>) -> Arc<checkpoint::WalCheckpoint> {
            let wal = self.hub.wal(crate::core::storage_thread::WalTarget::Kv);
            let logs = vec![(checkpoint::Holder::Shards(Engine::Kv), wal)];
            Arc::new(checkpoint::WalCheckpoint::new(Arc::clone(&self.control), logs, limit, relief))
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
            self.control.directory().get(name).map(|entry| entry.state)
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
                s.control.create_domain(name, Default::default()).await.unwrap();
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
                s.control.create_domain(name, Default::default()).await.unwrap();
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
                s.control.create_domain(name, Default::default()).await.unwrap();
                s.registries[1].store(name).await.unwrap().put(b"k", b"v").await.unwrap();
            }

            let elsewhere = s.engines[0].in_flight_write_for_test().await;
            s.control.delete_domain(&first).await.unwrap();
            drop(elsewhere);

            let in_flight = s.engines[1].in_flight_write_for_test().await;
            let delete = compio::runtime::spawn({
                let (control, name) = (Arc::clone(&s.control), second.clone());
                async move { control.delete_domain(&name).await }
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
            assert_eq!(s.control.directory().get(&first).unwrap().purging, Engine::ALL, "shard 0 does not own it");
            for _ in 0..2 {
                purge(1).purge_tick().await.unwrap();
            }
            // The disabled engines stay to purge until a start with them on.
            for name in [&first, &second] {
                let entry = s.control.directory().get(name).cloned().unwrap();
                assert_eq!((entry.state, entry.purging), (Lifecycle::Deleting, vec![Engine::Json, Engine::Rel]));
            }
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

    /// Shard `k`'s `Persist`s so far.
    fn persists(s: &TwoShards, k: usize) -> usize {
        s.commands_of(k).iter().filter(|name| **name == "persist").count()
    }

    /// One write on each shard.
    async fn write_on_both(s: &TwoShards, key: &str) {
        for (k, domain) in two_domains().iter().enumerate() {
            s.engines[k].put(&data_key(domain, key), b"v").await.unwrap();
        }
    }

    // Without a flush request, records in a young segment stay; with one,
    // the tick closes the segment, has every shard persist once, drops the
    // segment and marks the request done.
    #[test]
    fn a_flush_request_closes_a_young_segment() {
        crate::core::engine_runtime::block_on(async {
            use std::sync::atomic::Ordering;
            let s = TwoShards::new(|_, _| {}).await;
            let relief = Arc::new(resources::Relief::default());
            let checkpoints = s.checkpoints_with(u64::MAX, Arc::clone(&relief));
            write_on_both(&s, "k").await;
            assert_eq!(checkpoints.run().await, []);
            assert_eq!(s.segment_files()[0].0, 1);
            assert_eq!((persists(&s, 0), persists(&s, 1)), (0, 0));

            relief.requested.store(1, Ordering::Release);
            assert_eq!(checkpoints.run().await, []);
            assert!(s.holds_only_a_header(), "{:?}", s.segment_files());
            assert_eq!(s.segment_files()[0].0, 2);
            assert_eq!((persists(&s, 0), persists(&s, 1)), (1, 1));
            assert_eq!(relief.flushed.load(Ordering::Acquire), 1);
        })
    }

    // A flush request with the records in a closed segment and none in the
    // one appended to raises every shard to the last LSN without a
    // rotation and drops the closed segment; a request with no record left
    // to persist leaves the log alone. Both are marked done.
    #[test]
    fn a_flush_request_persists_a_closed_segment_without_a_rotation() {
        crate::core::engine_runtime::block_on(async {
            use std::sync::atomic::Ordering;
            let s = TwoShards::new(|_, _| {}).await;
            let wal = s.hub.wal(crate::core::storage_thread::WalTarget::Kv);
            let relief = Arc::new(resources::Relief::default());
            let checkpoints = s.checkpoints_with(u64::MAX, Arc::clone(&relief));
            write_on_both(&s, "k").await;
            wal.rotate().await.unwrap();
            let active = wal.segments().await.unwrap().active().segment;

            relief.requested.store(1, Ordering::Release);
            assert_eq!(checkpoints.run().await, []);
            assert_eq!(wal.segments().await.unwrap().active().segment, active, "no rotation");
            assert_eq!(s.segment_files()[0].0, active, "the closed segment went");
            assert_eq!((persists(&s, 0), persists(&s, 1)), (1, 1));
            assert_eq!(relief.flushed.load(Ordering::Acquire), 1);

            let segments = s.segment_files();
            relief.requested.store(2, Ordering::Release);
            assert_eq!(checkpoints.run().await, []);
            assert_eq!((persists(&s, 0), persists(&s, 1)), (1, 1), "nothing left to persist");
            assert_eq!(s.segment_files(), segments);
            assert_eq!(relief.flushed.load(Ordering::Acquire), 2);
        })
    }

    // A shard that does not answer the Persist of a flush request fails the
    // tick; the request is marked done all the same.
    #[test]
    fn a_failed_flush_request_is_marked_done() {
        crate::core::engine_runtime::block_on(async {
            use std::sync::atomic::Ordering;
            let s = TwoShards::new(|_, _| {}).await;
            let relief = Arc::new(resources::Relief::default());
            let checkpoints = s.checkpoints_with(u64::MAX, Arc::clone(&relief));
            write_on_both(&s, "k").await;
            s.drop_persists[1].send_replace(true);
            relief.requested.store(1, Ordering::Release);
            let reports = checkpoints.run().await;
            assert!(matches!(&reports[..], [Report::Stuck { log: "kv", .. }]), "{reports:?}");
            assert_eq!(relief.flushed.load(Ordering::Acquire), 1);
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
            pings: Mutex::default(),
            resources: Default::default(),
            max_name_length: 50,
        };
        (control, inbox)
    }

    #[test]
    fn every_command_fails_once_the_worker_is_gone() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (control, inbox) = without_worker(&dir).await;
            drop(inbox);

            let created = control.create_domain("orphan", Default::default()).await.unwrap_err();
            assert!(matches!(created, DomainError::Stopped), "{created:?}");
            let deleted = control.delete_domain("orphan").await.unwrap_err();
            assert!(matches!(deleted, DomainError::Stopped), "{deleted:?}");
            let cleared = control.clear_engine(Engine::Kv, "orphan", None).await.unwrap_err();
            assert!(matches!(cleared, DomainError::Stopped), "{cleared:?}");
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
            let create = control.create_domain("orphan", Default::default());
            let (created, ()) = futures::future::join(create, async move { drop(inbox) }).await;
            assert!(matches!(created, Err(DomainError::Stopped)), "{created:?}");
        })
    }
}
