//! The domain records: one per domain in the system store, which every
//! enabled engine's own record follows; the name rule all engines share; and
//! the reconciliation at each start that brings the engines in line with the
//! records.

use super::{slots, Engine, EngineRecord, Lifecycle, ShardOwners};
use crate::engines::lsm::engine::{LsmEngineConfig, LsmStorageEngine};
use crate::engines::StorageEngine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const PREFIX: &[u8] = b"__sys:meta:domain:";

/// Whether single-object writes over REST need a precondition, per engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalWrites {
    #[serde(default)]
    pub kv: bool,
    #[serde(default)]
    pub json: bool,
}

impl ConditionalWrites {
    /// The setting of `engine`; the relational engine has none.
    pub fn of(self, engine: Engine) -> bool {
        match engine {
            Engine::Kv => self.kv,
            Engine::Json => self.json,
            Engine::Rel => false,
        }
    }

    pub(crate) fn set(&mut self, engine: Engine, value: bool) {
        match engine {
            Engine::Kv => self.kv = value,
            Engine::Json => self.json = value,
            Engine::Rel => {}
        }
    }
}

/// A domain as the system store keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DomainRecord {
    pub state: Lifecycle,
    /// Unix seconds.
    pub created_at: u64,
    pub require_conditional_writes: ConditionalWrites,
    /// The engines whose data of the domain is still to be removed.
    pub purging: Vec<Engine>,
}

impl DomainRecord {
    pub(crate) fn new(created_at: u64, require_conditional_writes: ConditionalWrites) -> Self {
        Self { state: Lifecycle::Active, created_at, require_conditional_writes, purging: Vec::new() }
    }

    /// The state the record of `engine` must have.
    pub(crate) fn state_in(&self, engine: Engine) -> Lifecycle {
        if self.state == Lifecycle::Deleting || self.purging.contains(&engine) {
            Lifecycle::Deleting
        } else {
            Lifecycle::Active
        }
    }

    pub(crate) fn add_purging(&mut self, engine: Engine) {
        if !self.purging.contains(&engine) {
            self.purging.push(engine);
            self.purging.sort();
        }
    }
}

/// The settings of `[domains]` that hold for the whole domain.
#[derive(Debug, Clone)]
pub struct DomainRules {
    pub default_domain: String,
    pub max_name_length: usize,
}

impl Default for DomainRules {
    fn default() -> Self {
        Self { default_domain: "default".to_string(), max_name_length: 50 }
    }
}

fn key(name: &str) -> Vec<u8> {
    [PREFIX, name.as_bytes()].concat()
}

/// Every domain record of the system store, by name.
pub(crate) async fn load_all(system: &LsmStorageEngine) -> anyhow::Result<BTreeMap<String, DomainRecord>> {
    let mut records = BTreeMap::new();
    for raw in system.scan_keys(PREFIX).await? {
        let Some(value) = system.get(&raw).await? else { continue };
        let name = String::from_utf8(raw[PREFIX.len()..].to_vec())?;
        records.insert(name, serde_json::from_slice(&value)?);
    }
    Ok(records)
}

pub(crate) async fn put(system: &LsmStorageEngine, name: &str, record: &DomainRecord) -> anyhow::Result<()> {
    system.put(&key(name), &serde_json::to_vec(record)?).await
}

pub(crate) async fn remove(system: &LsmStorageEngine, name: &str) -> anyhow::Result<()> {
    system.delete(&key(name)).await
}

/// The longest name `domains.max_name_length` may allow: the longest key a
/// domain name goes into, a permission of a user with the longest name,
/// must fit the system store's key limit.
pub fn max_name_length_limit() -> usize {
    let permission = crate::auth::PREFIX_PERM.len() + crate::auth::MAX_USER_NAME_LENGTH + ":domain:".len();
    LsmEngineConfig::default().max_key_length - permission
}

/// Whether `name` is a valid domain name: `[a-zA-Z0-9_-]`, 1 to `max` long.
pub fn is_valid_name(name: &str, max: usize) -> bool {
    (1..=max).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// What one reconciliation changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reconciled {
    pub adopted: usize,
    pub created: usize,
    pub resumed: usize,
}

impl Reconciled {
    /// The start-log line.
    fn line(&self) -> String {
        format!(
            "domain reconciliation: {} domains adopted, {} engine records created, {} purges resumed",
            self.adopted, self.created, self.resumed
        )
    }
}

/// Brings the engine records of every enabled engine in line with the domain
/// records, before the shards serve and before any event can go out:
/// engine records without a domain record get one, an engine that must
/// purge is marked for its purger, a missing engine record is created, and
/// the default domain is created when it has no record.
pub(crate) async fn reconcile(
    system: &LsmStorageEngine,
    shards: &[ShardOwners],
    rules: &DomainRules,
) -> anyhow::Result<Reconciled> {
    let mut done = Reconciled::default();
    let mut records = load_all(system).await?;
    let count = u16::try_from(shards.len())?;
    let owner = |name: &str| &shards[usize::from(slots::shard_of_domain(name, count))];

    let mut found: BTreeMap<String, Vec<(Engine, EngineRecord)>> = BTreeMap::new();
    for shard in shards {
        for engine in shard.engines() {
            for (name, record) in shard.records(engine).await? {
                found.entry(name).or_default().push((engine, record));
            }
        }
    }
    for (name, engines) in found {
        if records.contains_key(&name) {
            continue;
        }
        let record = adopt(&engines);
        put(system, &name, &record).await?;
        records.insert(name, record);
        done.adopted += 1;
    }

    for (name, record) in &mut records {
        let owners = owner(name);
        let before = record.clone();
        for engine in owners.engines() {
            let purge = record.state_in(engine) == Lifecycle::Deleting;
            match (purge, owners.record(engine, name).map(|r| r.state)) {
                (true, None) => {
                    record.purging.retain(|e| *e != engine);
                    if record.state == Lifecycle::Active {
                        owners.create_record(engine, name, record.require_conditional_writes.of(engine)).await?;
                        done.created += 1;
                    }
                }
                (true, Some(state)) => {
                    if state == Lifecycle::Active {
                        owners.mark_deleting(engine, name).await?;
                    }
                    record.add_purging(engine);
                    done.resumed += 1;
                }
                (false, None) => {
                    owners.create_record(engine, name, record.require_conditional_writes.of(engine)).await?;
                    done.created += 1;
                }
                (false, Some(Lifecycle::Deleting)) => {
                    record.add_purging(engine);
                    done.resumed += 1;
                }
                (false, Some(Lifecycle::Active)) => {}
            }
        }
        if record.state == Lifecycle::Deleting && record.purging.is_empty() {
            remove(system, name).await?;
        } else if *record != before {
            put(system, name, record).await?;
        }
    }
    records.retain(|_, record| record.state == Lifecycle::Active || !record.purging.is_empty());

    if !records.contains_key(&rules.default_domain) {
        let name = &rules.default_domain;
        let owners = owner(name);
        let record = DomainRecord::new(crate::engines::lsm::domain::now_secs(), ConditionalWrites::default());
        put(system, name, &record).await?;
        for engine in owners.engines() {
            owners.create_record(engine, name, false).await?;
            done.created += 1;
        }
    }

    tracing::info!("{}", done.line());
    Ok(done)
}

/// The domain record of engine records that have none.
fn adopt(engines: &[(Engine, EngineRecord)]) -> DomainRecord {
    let created_at = engines.iter().map(|(_, r)| r.created_at).min().unwrap_or_default();
    let deleting: Vec<Engine> =
        engines.iter().filter(|(_, r)| r.state == Lifecycle::Deleting).map(|(engine, _)| *engine).collect();
    let mut record = DomainRecord::new(created_at, ConditionalWrites::default());
    if deleting.len() == engines.len() {
        record.state = Lifecycle::Deleting;
    }
    for (engine, r) in engines {
        record.require_conditional_writes.set(*engine, r.require_conditional_writes);
    }
    for engine in deleting {
        record.add_purging(engine);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{system, testing, ControlPlane, Owners, Shard};
    use crate::core::events::GlobalEventBus;
    use std::path::Path;
    use std::sync::Arc;

    /// The engines of one data shard and a system store, under `dir`.
    async fn start_of(dir: &Path) -> (ShardOwners, Arc<LsmStorageEngine>) {
        (testing::all_engines(dir).await, system::open(&dir.join("sys")).await.unwrap())
    }

    async fn run(system: &LsmStorageEngine, owners: &ShardOwners, rules: &DomainRules) -> Reconciled {
        reconcile(system, std::slice::from_ref(owners), rules).await.unwrap()
    }

    /// The state of the part of `name` in each engine.
    fn parts(owners: &ShardOwners, name: &str) -> [Option<Lifecycle>; 3] {
        Engine::ALL.map(|engine| owners.record(engine, name).map(|part| part.state))
    }

    /// Every enabled engine has the part each domain record asks for: in
    /// the record's state, or none while nothing is left to purge there.
    async fn assert_in_line(system: &LsmStorageEngine, owners: &ShardOwners) {
        for (name, record) in load_all(system).await.unwrap() {
            for engine in owners.engines() {
                let part = owners.record(engine, &name).map(|part| part.state);
                let expected = record.state_in(engine);
                assert!(
                    part == Some(expected) || (part.is_none() && !record.purging.contains(&engine)),
                    "{name} in {engine:?}: {part:?} for {record:?}"
                );
            }
        }
    }

    /// A control plane over `owners` and `system`, as a start brings it up
    /// after the reconciliation, with a subscription to its events.
    async fn control_over(
        owners: &ShardOwners,
        system: &Arc<LsmStorageEngine>,
    ) -> (Arc<ControlPlane>, tokio::sync::broadcast::Receiver<crate::core::events::GlobalEvent>) {
        let (commands, inbox) = tokio::sync::mpsc::unbounded_channel();
        compio::runtime::spawn(crate::control::serve_shard(owners.clone(), inbox)).detach();
        let bus = Arc::new(GlobalEventBus::new(64, 64));
        let events = bus.subscribe();
        let auth = Arc::new(crate::auth::AuthCache::new(Arc::clone(system), None));
        let shards = vec![Shard { owners: owners.clone(), commands }];
        let control = ControlPlane::start(Owners { shards, auth }, Arc::clone(system), bus, Default::default(), 50);
        (control.await.unwrap(), events)
    }

    /// Two ticks of the purger of every engine of `owners`.
    async fn purge(owners: &ShardOwners) {
        for _ in 0..2 {
            crate::engines::lsm::domain::DomainPurger::new(Arc::clone(owners.kv.engine()), Arc::clone(&owners.kv), 100)
                .purge_tick()
                .await
                .unwrap();
            let json = Arc::clone(owners.json.as_ref().unwrap());
            crate::engines::json::JsonDomainPurger::new(json, 100).purge_tick().await.unwrap();
            let rel = Arc::clone(owners.rel.as_ref().unwrap());
            crate::engines::rel::RelDomainPurger::new(rel, 100).purge_tick().await.unwrap();
        }
    }

    // Domain records whose engines are out of line: `a` without its JSON
    // part, `b` with a JSON part left deleting by a clear that crashed, `c`
    // deleting with its relational part still active. The start brings each
    // engine in line, and the purgers finish what is to purge.
    #[test]
    fn the_start_brings_every_engine_in_line_with_the_domain_records() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (owners, system) = start_of(dir.path()).await;
            let rules = DomainRules::default();
            run(&system, &owners, &rules).await;

            put(&system, "a", &DomainRecord::new(1, ConditionalWrites::default())).await.unwrap();
            for engine in [Engine::Kv, Engine::Rel] {
                owners.create_record(engine, "a", false).await.unwrap();
            }
            put(&system, "b", &DomainRecord::new(1, ConditionalWrites::default())).await.unwrap();
            for engine in Engine::ALL {
                owners.create_record(engine, "b", false).await.unwrap();
            }
            owners.mark_deleting(Engine::Json, "b").await.unwrap();
            let mut c = DomainRecord::new(1, ConditionalWrites::default());
            (c.state, c.purging) = (Lifecycle::Deleting, vec![Engine::Kv]);
            put(&system, "c", &c).await.unwrap();
            for engine in [Engine::Kv, Engine::Rel] {
                owners.create_record(engine, "c", false).await.unwrap();
            }
            owners.mark_deleting(Engine::Kv, "c").await.unwrap();

            let done = run(&system, &owners, &rules).await;
            assert_eq!(done, Reconciled { adopted: 0, created: 1, resumed: 3 });
            assert_eq!(done.line(), "domain reconciliation: 0 domains adopted, 1 engine records created, 3 purges resumed");
            assert_in_line(&system, &owners).await;
            let records = load_all(&system).await.unwrap();
            assert_eq!(parts(&owners, "a"), [Some(Lifecycle::Active); 3]);
            assert_eq!(records["b"].purging, [Engine::Json]);
            assert_eq!(records["c"].purging, [Engine::Kv, Engine::Rel]);
            assert_eq!(parts(&owners, "c"), [Some(Lifecycle::Deleting), None, Some(Lifecycle::Deleting)]);

            let (_control, mut events) = control_over(&owners, &system).await;
            purge(&owners).await;
            let records = load_all(&system).await.unwrap();
            assert!(records["b"].purging.is_empty());
            assert_eq!(parts(&owners, "b"), [Some(Lifecycle::Active); 3]);
            assert!(!records.contains_key("c"));
            assert_eq!(parts(&owners, "c"), [None; 3]);
            assert_in_line(&system, &owners).await;
            let event = events.try_recv().unwrap();
            assert_eq!((event.kind, event.domain.as_str()), ("domain_purged", "c"), "the delete before the start ends");
            assert!(events.try_recv().is_err(), "the start and the clear send no event");
        })
    }

    // A data directory from before the domain records: names of one
    // engine, a name deleting in one engine and active in another, a name
    // deleting everywhere. The first start adopts each name once, with its
    // state, setting and oldest creation time; the second changes nothing.
    #[test]
    fn the_first_start_adopts_the_names_of_every_engine_and_the_second_changes_nothing() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (owners, system) = start_of(dir.path()).await;
            owners.kv.create_domain_with("kv-only", true).await.unwrap();
            owners.json.as_ref().unwrap().create_domain_with("json-only", true).await.unwrap();
            owners.rel.as_ref().unwrap().create_domain("rel-only").await.unwrap();
            owners.kv.create_domain_with("mixed", false).await.unwrap();
            owners.json.as_ref().unwrap().create_domain_with("mixed", false).await.unwrap();
            owners.mark_deleting(Engine::Kv, "mixed").await.unwrap();
            for engine in [Engine::Kv, Engine::Rel] {
                owners.create_record(engine, "gone", false).await.unwrap();
                owners.mark_deleting(engine, "gone").await.unwrap();
            }
            let oldest = |name: &str| {
                Engine::ALL.iter().filter_map(|engine| owners.record(*engine, name)).map(|part| part.created_at).min()
            };
            let mixed_created = oldest("mixed").unwrap();

            let rules = DomainRules::default();
            // The default domain the JSON and relational fixtures hold counts as found.
            let done = run(&system, &owners, &rules).await;
            assert_eq!(done, Reconciled { adopted: 6, created: 8, resumed: 3 });
            let records = load_all(&system).await.unwrap();
            let names: Vec<_> = records.keys().map(String::as_str).collect();
            assert_eq!(names, ["default", "gone", "json-only", "kv-only", "mixed", "rel-only"]);
            assert_eq!(records["kv-only"].require_conditional_writes, ConditionalWrites { kv: true, json: false });
            assert_eq!(records["json-only"].require_conditional_writes, ConditionalWrites { kv: false, json: true });
            for name in ["kv-only", "json-only", "rel-only", "default"] {
                assert_eq!((records[name].state, records[name].purging.as_slice()), (Lifecycle::Active, &[][..]), "{name}");
                assert_eq!(parts(&owners, name), [Some(Lifecycle::Active); 3], "{name}");
            }
            assert_eq!((records["mixed"].state, records["mixed"].purging.as_slice()), (Lifecycle::Active, &[Engine::Kv][..]));
            assert_eq!(records["mixed"].created_at, mixed_created);
            assert_eq!(
                (records["gone"].state, records["gone"].purging.as_slice()),
                (Lifecycle::Deleting, &[Engine::Kv, Engine::Rel][..])
            );
            assert_eq!(parts(&owners, "gone"), [Some(Lifecycle::Deleting), None, Some(Lifecycle::Deleting)]);
            assert!(owners.kv.get_domain("kv-only").await.unwrap().unwrap().require_conditional_writes);
            assert!(!owners.json.as_ref().unwrap().get_domain("kv-only").unwrap().require_conditional_writes);
            assert_in_line(&system, &owners).await;

            let again = run(&system, &owners, &rules).await;
            assert_eq!((again.adopted, again.created), (0, 0));
            assert_eq!(load_all(&system).await.unwrap(), records, "the second start changes nothing");
        })
    }

    // A start that stopped after the first domain record it wrote: the next
    // one adopts the rest and keeps the one it finds, without a second record.
    #[test]
    fn a_start_after_a_reconciliation_cut_short_finishes_it_without_doubling() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (owners, system) = start_of(dir.path()).await;
            for name in ["first", "second"] {
                owners.kv.create_domain_with(name, false).await.unwrap();
            }
            let written = DomainRecord::new(7, ConditionalWrites::default());
            put(&system, "first", &written).await.unwrap();

            let done = run(&system, &owners, &DomainRules::default()).await;
            assert_eq!(done.adopted, 2, "second and the fixtures' default");
            let records = load_all(&system).await.unwrap();
            assert_eq!(records.len(), 3);
            assert_eq!(records["first"].created_at, 7, "the record found stays");
            for name in ["first", "second"] {
                assert_eq!(parts(&owners, name), [Some(Lifecycle::Active); 3], "{name}");
            }
        })
    }

    // The JSON engine off at the first start, on at the second: its names
    // are adopted then, and its parts of domains adopted meanwhile follow
    // their records.
    #[test]
    fn an_engine_switched_on_later_brings_its_names_in() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (owners, system) = start_of(dir.path()).await;
            let json = owners.json.clone().unwrap();
            json.create_domain_with("json-only", false).await.unwrap();
            for name in ["both", "cleared"] {
                owners.kv.create_domain_with(name, false).await.unwrap();
                json.create_domain_with(name, false).await.unwrap();
            }
            json.delete_domain("cleared").await.unwrap();
            let without_json = ShardOwners { json: None, ..owners.clone() };
            let rules = DomainRules::default();

            run(&system, &without_json, &rules).await;
            let records = load_all(&system).await.unwrap();
            assert!(!records.contains_key("json-only"));
            assert!(records["cleared"].purging.is_empty(), "the JSON part is not seen yet");

            let done = run(&system, &owners, &rules).await;
            assert_eq!((done.adopted, done.resumed), (1, 1));
            let records = load_all(&system).await.unwrap();
            assert_eq!(records["json-only"].state, Lifecycle::Active);
            assert_eq!(records["cleared"].purging, [Engine::Json]);
            assert_eq!(parts(&owners, "both"), [Some(Lifecycle::Active); 3]);
            assert_in_line(&system, &owners).await;
        })
    }

    // The default domain comes from `domains.default_domain` in every
    // engine; a `default` of an earlier data directory stays beside it as a
    // domain like any other. A deleting default domain comes back only once
    // its record fell.
    #[test]
    fn the_start_creates_the_configured_default_domain_once_its_record_is_gone() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (owners, system) = start_of(dir.path()).await;
            let rules = DomainRules { default_domain: "main".to_string(), ..DomainRules::default() };
            run(&system, &owners, &rules).await;
            let records = load_all(&system).await.unwrap();
            assert_eq!(records.keys().collect::<Vec<_>>(), ["default", "main"]);
            assert_eq!(parts(&owners, "main"), [Some(Lifecycle::Active); 3]);
            assert_eq!(parts(&owners, "default"), [Some(Lifecycle::Active); 3]);

            let mut deleting = records["main"].clone();
            (deleting.state, deleting.purging) = (Lifecycle::Deleting, Engine::ALL.to_vec());
            put(&system, "main", &deleting).await.unwrap();
            for engine in Engine::ALL {
                owners.mark_deleting(engine, "main").await.unwrap();
            }
            let before_the_purge = run(&system, &owners, &rules).await;
            assert_eq!(before_the_purge.created, 0);
            assert_eq!(load_all(&system).await.unwrap()["main"].state, Lifecycle::Deleting);

            for engine in Engine::ALL {
                owners.finalize_deletion(engine, "main").await.unwrap();
            }
            let after_the_purge = run(&system, &owners, &rules).await;
            assert_eq!(after_the_purge.created, 3);
            assert_eq!(load_all(&system).await.unwrap()["main"].state, Lifecycle::Active);
            assert_eq!(parts(&owners, "main"), [Some(Lifecycle::Active); 3]);
        })
    }

    #[test]
    fn a_valid_name_is_one_to_max_characters_of_the_allowed_set() {
        assert!(is_valid_name("a", 50) && is_valid_name("Zz-_09", 50) && is_valid_name("domains", 50));
        assert!(is_valid_name(&"a".repeat(80), 80));
        for bad in ["", "a b", "a:b", "clé", "a/b"] {
            assert!(!is_valid_name(bad, 50), "{bad:?}");
        }
        assert!(!is_valid_name(&"a".repeat(51), 50));
        assert_eq!(max_name_length_limit(), 438);
    }
}
