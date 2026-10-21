//! Control plane: runs the rare, global mutations — domain create and delete
//! in every engine, auth changes — one at a time on a single worker task,
//! holds the directory of all domains, owns the system store and is the one
//! publisher of the global event stream.

pub mod slots;
pub mod system;

use crate::auth::{AuthCache, DomainPermission, UserRecord};
use crate::core::events::GlobalEventBus;
use crate::engines::json::{JsonDomain, JsonDomainState, JsonEngine, JsonStoreError};
use crate::engines::lsm::domain::{Domain, DomainRegistry, DomainState};
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::rel::{RelDomain, RelDomainState, RelEngine, RelStoreError};
use parking_lot::RwLock;
use std::collections::BTreeMap;
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
}

impl Directory {
    async fn of(owners: &Owners) -> anyhow::Result<Self> {
        let mut directory = Self::default();
        let kv = owners.kv.list_domains().await?.into_iter().chain(owners.kv.list_deleting_domains());
        kv.for_each(|d| directory.insert(DomainEntry::kv(&d)));
        if let Some(json) = &owners.json {
            json.list_domains().iter().for_each(|d| directory.insert(DomainEntry::json(d)));
        }
        if let Some(rel) = &owners.rel {
            rel.list_domains().iter().for_each(|d| directory.insert(DomainEntry::rel(d)));
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

/// What the control plane runs its commands against.
pub struct Owners {
    pub kv: Arc<DomainRegistry>,
    pub json: Option<Arc<JsonEngine>>,
    pub rel: Option<Arc<RelEngine>>,
    pub auth: Arc<AuthCache>,
}

pub struct ControlPlane {
    commands: mpsc::UnboundedSender<Command>,
    directory: RwLock<Arc<Directory>>,
    bus: Arc<GlobalEventBus>,
    system: Arc<LsmStorageEngine>,
}

impl ControlPlane {
    /// Reads the owners' domains into the directory, attaches itself to the
    /// owners — before any purger runs, so none finishes a deletion behind
    /// its back — and starts the worker on the current runtime.
    pub async fn start(owners: Owners, system: Arc<LsmStorageEngine>, bus: Arc<GlobalEventBus>) -> anyhow::Result<Arc<Self>> {
        let (commands, inbox) = mpsc::unbounded_channel();
        let control = Arc::new(Self {
            commands,
            directory: RwLock::new(Arc::new(Directory::of(&owners).await?)),
            bus,
            system,
        });
        owners.kv.attach_control_plane(Arc::clone(&control));
        if let Some(json) = &owners.json {
            json.attach_control_plane(Arc::clone(&control));
        }
        if let Some(rel) = &owners.rel {
            rel.attach_control_plane(Arc::clone(&control));
        }
        let worker = Worker { owners, control: Arc::clone(&control) };
        compio::runtime::spawn(worker.run(inbox)).detach();
        Ok(control)
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
        change(Arc::make_mut(&mut self.directory.write()));
    }
}

/// Runs the commands, one after the other.
struct Worker {
    owners: Owners,
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

    fn json(&self) -> Result<&Arc<JsonEngine>, DomainError> {
        self.owners.json.as_ref().ok_or(DomainError::Disabled(Engine::Json))
    }

    fn rel(&self) -> Result<&Arc<RelEngine>, DomainError> {
        self.owners.rel.as_ref().ok_or(DomainError::Disabled(Engine::Rel))
    }

    async fn create_domain(
        &self,
        engine: Engine,
        name: &str,
        require_conditional_writes: bool,
    ) -> Result<DomainEntry, DomainError> {
        let entry = match engine {
            Engine::Kv => DomainEntry::kv(
                &self.owners.kv.create_domain_with(name, require_conditional_writes).await.map_err(DomainError::Kv)?,
            ),
            Engine::Json => DomainEntry::json(
                &self.json()?.create_domain_with(name, require_conditional_writes).await.map_err(DomainError::Json)?,
            ),
            Engine::Rel => DomainEntry::rel(&self.rel()?.create_domain(name).await.map_err(DomainError::Rel)?),
        };
        self.control.change_directory(|d| d.insert(entry.clone()));
        self.control.publish_global(engine, "domain_created", name, None);
        Ok(entry)
    }

    async fn delete_domain(&self, engine: Engine, name: &str) -> Result<(), DomainError> {
        match engine {
            Engine::Kv => self.owners.kv.delete_domain(name).await.map_err(DomainError::Kv)?,
            Engine::Json => self.json()?.delete_domain(name).await.map_err(DomainError::Json)?,
            Engine::Rel => self.rel()?.delete_domain(name).await.map_err(DomainError::Rel)?,
        }
        self.control.change_directory(|d| d.set_deleting(engine, name));
        // Writes that passed the domain check before it turned `Deleting`.
        match engine {
            Engine::Kv => self.owners.kv.engine().quiesce_writes().await,
            Engine::Json => self.json()?.quiesce_writes().await,
            Engine::Rel => self.rel()?.quiesce_writes().await,
        }
        self.control.publish_global(engine, "domain_deleted", name, None);
        Ok(())
    }

    async fn finalize_deletion(&self, engine: Engine, name: &str) -> anyhow::Result<()> {
        match engine {
            Engine::Kv => self.owners.kv.finalize_domain_deletion(name).await?,
            Engine::Json => self.json()?.finalize_deletion(name).await?,
            Engine::Rel => self.rel()?.finalize_deletion(name).await?,
        }
        self.control.change_directory(|d| d.remove(engine, name));
        self.control.publish_global(engine, "domain_purged", name, None);
        Ok(())
    }

    async fn change_auth(&self, change: AuthChange) -> anyhow::Result<()> {
        let auth = &self.owners.auth;
        match change {
            AuthChange::UpsertUser(record) => auth.upsert_user(record).await,
            AuthChange::RemoveUser(name) => auth.remove_user(&name).await,
            AuthChange::RotateKey { name, new_hash } => auth.rotate_key(&name, &new_hash).await,
            AuthChange::SetPermission(perm) => auth.set_permission(perm).await,
            AuthChange::RemovePermission { username, domain } => auth.remove_permission(&username, &domain).await,
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::path::Path;

    /// A control plane over the given owners, with a system store of its own
    /// under `dir/sys` and an auth cache on it.
    pub(crate) async fn start(
        dir: &Path,
        kv: Arc<DomainRegistry>,
        json: Option<Arc<JsonEngine>>,
        rel: Option<Arc<RelEngine>>,
        bus: Arc<GlobalEventBus>,
    ) -> (Arc<ControlPlane>, Arc<AuthCache>) {
        let system = system::open(&dir.join("sys")).await.unwrap();
        let auth = Arc::new(AuthCache::new(Arc::clone(&system)));
        let owners = Owners { kv, json, rel, auth: Arc::clone(&auth) };
        (ControlPlane::start(owners, system, bus).await.unwrap(), auth)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{hash_api_key, UserRole};
    use crate::core::events::GlobalEvent;
    use crate::engines::lsm::domain::DomainPurger;
    use crate::engines::StorageEngine;
    use serde_json::json;
    use std::sync::atomic::AtomicBool;
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
            let (control, auth) =
                testing::start(dir.path(), Arc::clone(&kv), Some(Arc::clone(&json)), Some(Arc::clone(&rel)), bus).await;
            Self { kv, json, rel, auth, control, events, _dir: dir }
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
    }

    /// Gives every runnable task a few turns.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    fn purger(f: &Fixture) -> DomainPurger {
        DomainPurger::new(Arc::clone(f.kv.engine()), Arc::clone(&f.kv), Arc::new(AtomicBool::new(false)), 100, 1)
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

            let purger = crate::engines::json::JsonDomainPurger::new(
                Arc::clone(&f.json),
                Arc::new(AtomicBool::new(false)),
                100,
                1,
            );
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

            let purger =
                crate::engines::rel::RelDomainPurger::new(Arc::clone(&f.rel), Arc::new(AtomicBool::new(false)), 100, 1);
            purger.purge_tick().await.unwrap();
            purger.purge_tick().await.unwrap();
            assert_eq!(f.next_event(), ("rel", "domain_purged", "doomed".to_string()));
            assert_eq!(f.state(Engine::Rel, "doomed"), None);
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
            let shutdown = Arc::new(AtomicBool::new(false));
            let purger = Arc::new(DomainPurger::new(
                Arc::clone(f.kv.engine()),
                Arc::clone(&f.kv),
                Arc::clone(&shutdown),
                1,
                1,
            ));
            compio::runtime::spawn(purger.run()).detach();

            f.control.create_domain(Engine::Kv, "late-purge", false).await.unwrap();
            f.control.delete_domain(Engine::Kv, "late-purge").await.unwrap();
            f.next_event();
            f.next_event();
            let purged = compio::time::timeout(Duration::from_secs(30), f.events.recv())
                .await
                .expect("timed out waiting for domain_purged")
                .unwrap();
            assert_eq!((purged.kind, purged.domain.as_str()), ("domain_purged", "late-purge"));
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
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

    /// A control plane with no worker behind it; the receiver is the worker's end.
    async fn without_worker(dir: &tempfile::TempDir) -> (ControlPlane, mpsc::UnboundedReceiver<Command>) {
        let (commands, inbox) = mpsc::unbounded_channel();
        let control = ControlPlane {
            commands,
            directory: RwLock::default(),
            bus: Arc::new(GlobalEventBus::new(16, 16)),
            system: system::open(&dir.path().join("sys")).await.unwrap(),
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
