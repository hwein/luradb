//! Backup and restore of relational domains, end to end: archives written
//! by `writer` from servers of one or more data shards, restored by
//! `restore` into fresh servers and compared through SQL and the catalog.

use super::restore::{run_restore, RestoreMode, RestoreOutcome, RestoreParams};
use super::writer::{resolve_scope, run_backup, BackupParams};
use super::{BackupError, BackupManager, BackupScope, RestoreState};
use crate::config::{BackupConfig, BlockCacheConfig, JsonStoreConfig, RelStoreConfig};
use crate::control::{slots, testing, ControlPlane, Engine, Lifecycle, ShardOwners};
use crate::core::wal::WriteAheadLog;
use crate::engines::json::{JsonDomainPurger, JsonEngine};
use crate::engines::lsm::domain::{DomainConfig, DomainPurger, DomainRegistry};
use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
use crate::engines::lsm::rate_limiter::DomainQuota;
use crate::engines::lsm::reader::GetResult;
use crate::engines::rel::{
    CrossEngineResolver, ExecOutcome, FileFormat, LinkAuth, RelCrossEngineSweeper, RelDomainPurger, RelEngine,
    ScalarValue, SqlOutcome,
};
use crate::metrics::{MetricsConfig, MetricsStore};
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// An LSM instance of its own under `dir`.
async fn lsm(dir: &Path, options: LsmEngineOptions) -> Arc<LsmStorageEngine> {
    let fm = Arc::new(FileManager::new(dir).await.unwrap());
    let mm = Arc::new(ManifestManager::new(dir));
    let (wal_path, vlog_path) = (dir.join("wal"), dir.join("vlog"));
    let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
    let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
    Arc::new(LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, options).await.unwrap())
}

/// A server in a temp dir: `shards` data shards, each with a key-value
/// engine and, when asked for, a JSON and a relational engine whose links
/// reach the engines of its shard; only the owner of `default` creates it.
struct Server {
    control: Arc<ControlPlane>,
    owners: Vec<ShardOwners>,
    _dir: tempfile::TempDir,
}

async fn server(shards: u16, json: bool, rel: bool) -> Server {
    let dir = tempfile::TempDir::new().unwrap();
    let rel_root = rel.then(|| dir.path().join("rel"));
    server_on(dir, rel_root.as_deref(), shards, json).await
}

/// [`server`] whose relational engines keep their data under `rel_root`,
/// when given, so a later server can reopen it.
async fn server_on(dir: tempfile::TempDir, rel_root: Option<&Path>, shards: u16, json: bool) -> Server {
    let metrics = MetricsStore::new(MetricsConfig::default());
    let mut owners = Vec::new();
    for k in 0..shards {
        let owns_default = slots::shard_of_domain("default", shards) == k;
        let at = dir.path().join(format!("shard-{k}"));
        let kv_engine = lsm(&at.join("kv"), LsmEngineOptions::default()).await;
        let kv = Arc::new(
            DomainRegistry::recover_on_shard(kv_engine, DomainConfig::default(), Arc::clone(&metrics), owns_default)
                .await
                .unwrap(),
        );
        let json = match json {
            true => {
                let engine = lsm(&at.join("json"), LsmEngineOptions::default()).await;
                engine.start_background_tasks();
                let config = JsonStoreConfig::default();
                Some(JsonEngine::open(&config, engine, Arc::clone(&metrics), owns_default).await.unwrap())
            }
            false => None,
        };
        let rel = match rel_root {
            Some(root) => {
                let config = RelStoreConfig::default();
                let options = RelEngine::lsm_options(&config, BlockCacheConfig::default());
                let engine = lsm(&root.join(format!("shard-{k}")), options).await;
                engine.start_background_tasks();
                let resolver = CrossEngineResolver::new(Some(Arc::clone(&kv)), json.clone(), Arc::clone(&metrics));
                let quota = DomainQuota::default();
                Some(RelEngine::open(&config, quota, engine, Arc::clone(&metrics), resolver, owns_default).await.unwrap())
            }
            None => None,
        };
        owners.push(ShardOwners { kv, json, rel });
    }
    let bus = Arc::new(crate::core::events::GlobalEventBus::new(64, 64));
    let (control, _) = testing::start_shards(dir.path(), owners.clone(), bus).await;
    Server { control, owners, _dir: dir }
}

impl Server {
    async fn create(&self, engine: Engine, name: &str) {
        self.control.create_domain(engine, name, false).await.unwrap();
    }

    fn rel(&self, domain: &str) -> &Arc<RelEngine> {
        self.control.owners_of(domain).rel.as_ref().unwrap()
    }

    fn json(&self, domain: &str) -> &Arc<JsonEngine> {
        self.control.owners_of(domain).json.as_ref().unwrap()
    }

    async fn sql(&self, domain: &str, sql: &str, params: &[Value]) -> ExecOutcome {
        self.rel(domain).execute(domain, sql, params).await.unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    async fn rows(&self, domain: &str, sql: &str) -> Vec<Vec<ScalarValue>> {
        match self.sql(domain, sql, &[]).await {
            ExecOutcome::Select(result) => result.rows,
            other => panic!("{sql}: expected rows, got {other:?}"),
        }
    }

    /// The tables and views of `domain` without the ids and stamps a restore
    /// assigns afresh, by name.
    fn catalog(&self, domain: &str) -> Vec<Value> {
        let mut entries: Vec<Value> = self
            .rel(domain)
            .list_objects(domain)
            .unwrap()
            .iter()
            .map(|entry| {
                let mut value = serde_json::to_value(entry).unwrap();
                let object = value.as_object_mut().unwrap();
                for field in ["table_id", "schema_version", "created_at", "next_col_id"] {
                    object.remove(field);
                }
                for (list, id) in [("columns", "col_id"), ("indexes", "index_id")] {
                    for item in object.get_mut(list).and_then(Value::as_array_mut).into_iter().flatten() {
                        item.as_object_mut().unwrap().remove(id);
                    }
                }
                value
            })
            .collect();
        entries.sort_by_key(|entry| entry["name"].as_str().unwrap().to_string());
        entries
    }

    /// Backs `scope` up into `out` as `id`, unthrottled; the archive's path.
    async fn backup(&self, out: &Path, id: &str, scope: BackupScope) -> PathBuf {
        let resolved = resolve_scope(&scope, &self.control).unwrap();
        let params = BackupParams {
            dir: out,
            id,
            scope: &scope,
            include_auth: false,
            schedule: None,
            resolved: &resolved,
            control: &self.control,
            scan_batch_size: 7,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();
        out.join(format!("{id}.ndjson"))
    }

    async fn restore(
        &self,
        out: &Path,
        id: &str,
        mode: RestoreMode,
        into_domain: Option<&str>,
    ) -> anyhow::Result<RestoreOutcome> {
        run_restore(RestoreParams {
            dir: out,
            backup_id: id,
            mode,
            into_domain,
            include_auth: false,
            control: &self.control,
            scan_batch_size: 7,
            scan_pause_ms: 0,
        })
        .await
    }

    /// Runs the purgers of every engine of every shard until the handle drops.
    fn purging(&self) -> compio::runtime::JoinHandle<()> {
        let kv: Vec<_> =
            self.owners.iter().map(|o| DomainPurger::new(Arc::clone(o.kv.engine()), Arc::clone(&o.kv), 100)).collect();
        let json: Vec<_> = self.owners.iter().filter_map(|o| o.json.clone()).map(|j| JsonDomainPurger::new(j, 100)).collect();
        let rel: Vec<_> = self.owners.iter().filter_map(|o| o.rel.clone()).map(|r| RelDomainPurger::new(r, 100)).collect();
        compio::runtime::spawn(async move {
            loop {
                for purger in &kv {
                    let _ = purger.purge_tick().await;
                }
                for purger in &json {
                    let _ = purger.purge_tick().await;
                }
                for purger in &rel {
                    let _ = purger.purge_tick().await;
                }
                compio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    }
}

/// The parsed lines of an archive.
fn archive_lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

/// The `rel-domain` names of an archive, in order.
fn rel_domains_of(path: &Path) -> Vec<String> {
    archive_lines(path)
        .into_iter()
        .filter(|line| line["t"] == "rel-domain")
        .map(|line| line["name"].as_str().unwrap().to_string())
        .collect()
}

fn has_rel_lines(path: &Path) -> bool {
    archive_lines(path).iter().any(|line| line["t"].as_str().unwrap().starts_with("rel-"))
}

/// Rewrites `path` from `body` plus a matching checksum line.
fn reseal(path: &Path, body: &[String]) {
    let mut hasher = Sha256::new();
    for line in body {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    let checksum = json!({"t": "checksum", "sha256": hex::encode(hasher.finalize()), "lines": body.len() as u64});
    let mut content = body.join("\n");
    content.push('\n');
    content.push_str(&checksum.to_string());
    content.push('\n');
    std::fs::write(path, content).unwrap();
}

fn backup_error(err: &anyhow::Error) -> Option<&BackupError> {
    err.downcast_ref::<BackupError>()
}

/// The last primary key an insert handed out.
fn last_pk(outcome: ExecOutcome) -> Option<ScalarValue> {
    match outcome {
        ExecOutcome::Dml(result) => result.last_pk,
        other => panic!("expected DML, got {other:?}"),
    }
}

/// Builds the domain `shop` on `src`.
async fn build_shop(src: &Server) {
    src.create(Engine::Rel, "shop").await;
    let ddl = [
        "CREATE TABLE parent (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE, ratio REAL DEFAULT 1.5, \
         note TEXT DEFAULT 'it''s', missing TEXT DEFAULT NULL, stamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
         flag BOOLEAN NOT NULL)",
        "CREATE TABLE child (name TEXT PRIMARY KEY, parent_id INTEGER REFERENCES parent, score REAL, \
         born TIMESTAMP, label TEXT)",
        "CREATE INDEX child_score_idx ON child (score)",
        "CREATE UNIQUE INDEX child_label_uniq ON child (label)",
        "CREATE TABLE old_name (id INTEGER PRIMARY KEY, email TEXT UNIQUE)",
        "ALTER TABLE old_name RENAME TO renamed",
        "CREATE VIEW v_parent AS SELECT id, code, ratio FROM parent",
        "CREATE VIEW v_top AS SELECT id, code FROM v_parent",
    ];
    for sql in ddl {
        src.sql("shop", sql, &[]).await;
    }

    // Timestamps before 1970 and past the year 9999, REAL with a fraction
    // and at 1e300, multi-byte text, NULLs.
    for i in 1..=25i64 {
        let ratio = if i == 3 { 1e300 } else { i as f64 * 0.25 + 0.125 };
        let stamp = match i {
            1 => json!(-12_345_678_901i64),
            2 => json!(320_000_000_000_000i64),
            _ => json!(1_700_000_000_000i64 + i),
        };
        let sql = if i % 4 == 0 {
            "INSERT INTO parent (code, ratio, flag) VALUES (?, ?, ?)"
        } else {
            "INSERT INTO parent (code, ratio, flag, stamp) VALUES (?, ?, ?, ?)"
        };
        let mut params = vec![json!(format!("p{i}-clé-🦀")), json!(ratio), json!(i % 2 == 0)];
        if i % 4 != 0 {
            params.push(stamp);
        }
        src.sql("shop", sql, &params).await;
    }
    for i in 1..=15i64 {
        let parent = if i % 5 == 0 { Value::Null } else { json!(i) };
        let label = if i % 3 == 0 { Value::Null } else { json!(format!("ünïque-{i}")) };
        let born = json!(-86_400_000i64 * 400 * i);
        src.sql(
            "shop",
            "INSERT INTO child (name, parent_id, score, born, label) VALUES (?, ?, ?, ?, ?)",
            &[json!(format!("c{i:02}")), parent, json!(i as f64 / 3.0), born, label],
        )
        .await;
        if i == 10 {
            src.sql("shop", "ALTER TABLE child ADD COLUMN extra TEXT DEFAULT 'filler'", &[]).await;
            src.sql("shop", "ALTER TABLE child ADD COLUMN gone INTEGER", &[]).await;
        }
    }
    src.sql("shop", "ALTER TABLE child DROP COLUMN gone", &[]).await;
    src.sql("shop", "INSERT INTO renamed VALUES (1, 'a@example.com'), (2, NULL)", &[]).await;
    src.rel("shop")
        .create_table_from_file("shop", "imported", FileFormat::Csv, true, None, "key,order\nalpha,1\nbeta,2\n".into())
        .await
        .unwrap();
    // The high-water mark stays above every key that is left.
    src.sql("shop", "DELETE FROM parent WHERE id = 25", &[]).await;
}

const SHOP_QUERIES: [&str; 6] = [
    "SELECT * FROM parent ORDER BY id",
    "SELECT * FROM child ORDER BY name",
    "SELECT * FROM renamed ORDER BY id",
    "SELECT * FROM imported ORDER BY _row",
    "SELECT * FROM v_parent ORDER BY id",
    "SELECT * FROM v_top ORDER BY id",
];

// A relational domain restores into a fresh server as it was: rows of
// every table and view, the catalog, the behavior of implicit indexes
// and the next AUTOINCREMENT key.
#[test]
fn a_relational_domain_round_trips_with_schema_and_rows() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, false, true).await;
        build_shop(&src).await;

        let out = tempfile::TempDir::new().unwrap();
        src.backup(out.path(), "bk_shop", BackupScope::Domain("shop".to_string())).await;
        let dst = server(1, false, true).await;
        let outcome = dst.restore(out.path(), "bk_shop", RestoreMode::FailIfExists, None).await.unwrap();
        assert_eq!((outcome.imported, outcome.failed), (24 + 15 + 2 + 2, 0));

        for query in SHOP_QUERIES {
            let rows = src.rows("shop", query).await;
            assert!(!rows.is_empty(), "{query}");
            assert_eq!(dst.rows("shop", query).await, rows, "{query}");
        }
        assert_eq!(dst.catalog("shop"), src.catalog("shop"));

        // The implicit index of a renamed table no longer counts as implicit,
        // the one of an unrenamed table still does.
        for sql in ["DROP INDEX parent_code_key", "DROP INDEX old_name_email_key"] {
            let (in_src, in_dst) = (src.rel("shop").execute("shop", sql, &[]).await, dst.rel("shop").execute("shop", sql, &[]).await);
            assert_eq!(in_dst.is_ok(), in_src.is_ok(), "{sql}");
        }
        assert!(dst.rel("shop").execute("shop", "DROP INDEX parent_code_key", &[]).await.is_err());

        let insert = "INSERT INTO parent (code, flag) VALUES ('next', true)";
        assert_eq!(last_pk(src.sql("shop", insert, &[]).await), Some(ScalarValue::Integer(26)));
        assert_eq!(last_pk(dst.sql("shop", insert, &[]).await), Some(ScalarValue::Integer(26)));
    })
}

// The archive form of a table: SQL type names, defaults by kind, every
// index under its stored name, TIMESTAMP as integer milliseconds, NULL
// explicit, and the high-water mark after the rows of its table.
#[test]
fn the_archive_holds_tables_rows_and_high_water_marks_in_their_own_form() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, false, true).await;
        build_shop(&src).await;
        let out = tempfile::TempDir::new().unwrap();
        let path = src.backup(out.path(), "bk_form", BackupScope::RelDomain("shop".to_string())).await;
        let lines = archive_lines(&path);
        let kinds: Vec<&str> = lines.iter().map(|l| l["t"].as_str().unwrap()).collect();

        let parent = lines.iter().find(|l| l["t"] == "rel-table" && l["name"] == "parent").unwrap();
        assert_eq!(parent["columns"][0], json!({"name": "id", "type": "INTEGER", "nullable": false,
            "primary_key": true, "autoincrement": true, "unique": false}));
        assert_eq!(parent["columns"][2]["default"], json!({"kind": "literal", "value": 1.5}));
        assert_eq!(parent["columns"][3]["default"], json!({"kind": "literal", "value": "it's"}));
        assert_eq!(parent["columns"][4]["default"], json!({"kind": "null"}));
        assert_eq!(parent["columns"][5]["default"], json!({"kind": "current_timestamp"}));
        assert_eq!(parent["indexes"], json!([{"name": "parent_code_key", "column": "code", "unique": true}]));
        let renamed = lines.iter().find(|l| l["t"] == "rel-table" && l["name"] == "renamed").unwrap();
        assert_eq!(renamed["indexes"][0]["name"], "old_name_email_key");

        let first = lines.iter().find(|l| l["t"] == "rel-row" && l["table"] == "parent").unwrap();
        assert_eq!(first["row"]["stamp"], json!(-12_345_678_901i64));
        assert_eq!(first["row"]["missing"], Value::Null);
        let seq = lines.iter().find(|l| l["t"] == "rel-seq").unwrap();
        assert_eq!((seq["table"].as_str(), seq["hw"].as_u64()), (Some("parent"), Some(25)));

        let pos = |t: &str| kinds.iter().position(|k| *k == t).unwrap();
        let last = |t: &str| kinds.iter().rposition(|k| *k == t).unwrap();
        assert!(pos("rel-domain") < pos("rel-table") && last("rel-table") < pos("rel-view"));
        assert!(last("rel-view") < pos("rel-row") && pos("rel-seq") < last("rel-row"));
        assert_eq!(kinds.last(), Some(&"checksum"));
    })
}

// Catalog states that DDL never builds in one go restore as they were: a
// REFERENCES cycle, a REFERENCES to a dropped table, a view over a join
// whose index was dropped since.
#[test]
fn cycles_dangling_references_and_unbindable_views_restore() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, false, true).await;
        src.create(Engine::Rel, "edge").await;
        for sql in [
            "CREATE TABLE b (id INTEGER PRIMARY KEY, code INTEGER)",
            "CREATE TABLE a (id INTEGER PRIMARY KEY, b_id INTEGER REFERENCES b, code INTEGER)",
            "ALTER TABLE b ADD COLUMN a_id INTEGER REFERENCES a",
            "CREATE TABLE gone (id INTEGER PRIMARY KEY)",
            "CREATE TABLE dangling (id INTEGER PRIMARY KEY, gone_id INTEGER REFERENCES gone)",
            "INSERT INTO gone VALUES (1)",
            "INSERT INTO dangling VALUES (1, 1)",
            "DROP TABLE gone",
            "CREATE INDEX b_code_idx ON b (code)",
            "CREATE VIEW joined AS SELECT a.id, b.code FROM a LEFT JOIN b ON a.code = b.code",
            "DROP INDEX b_code_idx",
            "INSERT INTO b VALUES (1, 7, NULL)",
            "INSERT INTO a VALUES (1, 1, 7)",
            "UPDATE b SET a_id = 1 WHERE id = 1",
        ] {
            src.sql("edge", sql, &[]).await;
        }

        let out = tempfile::TempDir::new().unwrap();
        src.backup(out.path(), "bk_edge", BackupScope::RelDomain("edge".to_string())).await;
        let dst = server(1, false, true).await;
        dst.restore(out.path(), "bk_edge", RestoreMode::FailIfExists, None).await.unwrap();

        assert_eq!(dst.catalog("edge"), src.catalog("edge"));
        for query in ["SELECT * FROM a ORDER BY id", "SELECT * FROM b ORDER BY id", "SELECT * FROM dangling ORDER BY id"] {
            assert_eq!(dst.rows("edge", query).await, src.rows("edge", query).await, "{query}");
        }
    })
}

// Which scopes carry relational domains.
#[test]
fn scopes_select_relational_domains() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, true, true).await;
        for name in ["d1", "d2"] {
            src.create(Engine::Rel, name).await;
            src.sql(name, "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await;
            src.sql(name, "INSERT INTO t VALUES (1)", &[]).await;
        }
        src.create(Engine::Kv, "d1").await;
        let out = tempfile::TempDir::new().unwrap();

        let all = src.backup(out.path(), "bk_all", BackupScope::All).await;
        assert_eq!(rel_domains_of(&all), ["d1", "d2", "default"]);
        assert!(archive_lines(&all).iter().any(|l| l["t"] == "rel-row"));
        let domain = src.backup(out.path(), "bk_domain", BackupScope::Domain("d1".to_string())).await;
        assert_eq!(rel_domains_of(&domain), ["d1"]);
        assert!(archive_lines(&domain).iter().any(|l| l["t"] == "kv-domain" && l["name"] == "d1"));
        let rel = src.backup(out.path(), "bk_rel", BackupScope::Rel).await;
        assert_eq!(rel_domains_of(&rel), ["d1", "d2", "default"]);
        assert!(!archive_lines(&rel).iter().any(|l| l["t"] == "kv-domain" || l["t"] == "json-domain"));
        let one = src.backup(out.path(), "bk_one", BackupScope::RelDomain("d2".to_string())).await;
        assert_eq!(rel_domains_of(&one), ["d2"]);
        assert!(archive_lines(&one).iter().filter(|l| l["t"] == "rel-row").all(|l| l["domain"] == "d2"));
        for (id, scope) in [("bk_kv", BackupScope::Kv), ("bk_json", BackupScope::Json)] {
            assert!(!has_rel_lines(&src.backup(out.path(), id, scope).await), "{id}");
        }
        let err = resolve_scope(&BackupScope::RelDomain("nope".to_string()), &src.control).unwrap_err();
        assert!(matches!(err, BackupError::DomainNotFound(_)), "{err}");

        let off = server(1, false, false).await;
        for scope in [BackupScope::Rel, BackupScope::RelDomain("d1".to_string())] {
            let err = resolve_scope(&scope, &off.control).unwrap_err();
            assert!(matches!(err, BackupError::RelEngineDisabled), "{err}");
        }
        assert!(!has_rel_lines(&off.backup(out.path(), "bk_off", BackupScope::All).await));
    })
}

/// The `(domain, id)` of every relational row of an archive.
fn rel_rows(path: &Path) -> std::collections::HashSet<(String, i64)> {
    archive_lines(path)
        .into_iter()
        .filter(|line| line["t"] == "rel-row")
        .map(|line| (line["domain"].as_str().unwrap().to_string(), line["row"]["id"].as_i64().unwrap()))
        .collect()
}

// Round after round, a writer confirms an insert into a domain of shard
// 0 and then makes one into a domain of shard 1 while a backup runs: an
// archive that holds the second insert holds the first. Round 0 backs up
// between the two inserts, round 1 after both, the rest after a varying
// number of yields from a fixed seed.
#[test]
fn an_archive_with_a_later_relational_write_holds_every_one_confirmed_before_it() {
    crate::core::engine_runtime::block_on(async {
        const ROUNDS: i64 = 40;
        let src = server(2, false, true).await;
        let [a, b] = [0, 1].map(|shard| slots::domain_name_for_shard(shard, 2, 23));
        for name in [&a, &b] {
            src.create(Engine::Rel, name).await;
            src.sql(name, "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await;
        }
        let rels = Arc::new([Arc::clone(src.rel(&a)), Arc::clone(src.rel(&b))]);
        let names = Arc::new([a.clone(), b.clone()]);

        let out = tempfile::TempDir::new().unwrap();
        let (mut a_only, mut both) = (0, 0);
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for i in 0..ROUNDS {
            let id = format!("bk_cut_{i}");
            let (a_done, a_confirmed) = tokio::sync::oneshot::channel();
            let (go, gate) = tokio::sync::oneshot::channel::<()>();
            let mut writer = Some(compio::runtime::spawn({
                let (rels, names) = (Arc::clone(&rels), Arc::clone(&names));
                async move {
                    rels[0].execute(&names[0], "INSERT INTO t VALUES (?)", &[json!(i)]).await.unwrap();
                    let _ = a_done.send(());
                    gate.await.unwrap();
                    rels[1].execute(&names[1], "INSERT INTO t VALUES (?)", &[json!(i)]).await.unwrap();
                }
            }));
            let path = match i {
                0 => {
                    a_confirmed.await.unwrap();
                    let path = src.backup(out.path(), &id, BackupScope::Rel).await;
                    go.send(()).unwrap();
                    path
                }
                1 => {
                    go.send(()).unwrap();
                    writer.take().unwrap().await.unwrap();
                    src.backup(out.path(), &id, BackupScope::Rel).await
                }
                _ => {
                    go.send(()).unwrap();
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    for _ in 0..state % 16 {
                        tokio::task::yield_now().await;
                    }
                    src.backup(out.path(), &id, BackupScope::Rel).await
                }
            };
            if let Some(writer) = writer {
                writer.await.unwrap();
            }

            let rows = rel_rows(&path);
            let (has_a, has_b) = (rows.contains(&(a.clone(), i)), rows.contains(&(b.clone(), i)));
            assert!(has_a || !has_b, "round {i}: the insert into {b} without the one into {a}");
            a_only += usize::from(has_a && !has_b);
            both += usize::from(has_a && has_b);
        }
        assert!(a_only > 0, "no backup fell between the two inserts");
        assert!(both > 0, "no backup held both inserts");
    })
}

// An archive of two data shards restores into one and into three: every
// relational domain lands on the shard that owns it there, with its rows.
#[test]
fn relational_domains_restore_into_another_shard_count() {
    crate::core::engine_runtime::block_on(async {
        let src = server(2, false, true).await;
        // Only the domains of this test go into the archive.
        src.control.delete_domain(Engine::Rel, "default").await.unwrap();
        let names: Vec<String> = (0..6).map(|i| slots::domain_name_for_shard(i % 2, 2, 50 + u64::from(i))).collect();
        for name in &names {
            src.create(Engine::Rel, name).await;
            src.sql(name, "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)", &[]).await;
            src.sql(name, "INSERT INTO t (v) VALUES (?), (?), (?)", &[json!(name), json!("x"), json!("é")]).await;
        }
        let out = tempfile::TempDir::new().unwrap();
        src.backup(out.path(), "bk_shards", BackupScope::Rel).await;

        for n in [1u16, 3] {
            let dst = server(n, false, true).await;
            dst.restore(out.path(), "bk_shards", RestoreMode::FailIfExists, None).await.unwrap();
            for name in &names {
                let owner = usize::from(slots::shard_of_domain(name, n));
                for (k, owners) in dst.owners.iter().enumerate() {
                    let has = owners.rel.as_ref().unwrap().get_domain(name).is_some();
                    assert_eq!(has, k == owner, "{name} on shard {k} of {n}");
                }
                let query = "SELECT * FROM t ORDER BY id";
                assert_eq!(dst.rows(name, query).await, src.rows(name, query).await, "{name} into {n} shards");
            }
        }
    })
}

/// The `expand` objects of `column` for `SELECT * FROM <table> ORDER BY id`.
async fn expanded(server: &Server, domain: &str, table: &str, column: &str) -> Vec<Value> {
    let sql = format!("SELECT * FROM {table} ORDER BY id");
    let outcome =
        server.rel(domain).execute_sql(domain, &sql, &[], &[column.to_string()], LinkAuth::full()).await.unwrap();
    match outcome {
        SqlOutcome::Select { expanded: Some(block), .. } => block.into_iter().next().unwrap().1,
        other => panic!("expected an expanded SELECT, got {other:?}"),
    }
}

/// KV domain `d` with key `k1`, JSON domain `d` with document `doc1`.
async fn link_targets(server: &Server) {
    server.create(Engine::Kv, "d").await;
    server.owners_kv("d").store("d").await.unwrap().put(b"k1", b"v1").await.unwrap();
    server.create(Engine::Json, "d").await;
    server.json("d").put_document("d", "doc1", json!({"n": 1})).await.unwrap();
}

impl Server {
    fn owners_kv(&self, domain: &str) -> &Arc<DomainRegistry> {
        &self.control.owners_of(domain).kv
    }
}

// Links of a relational table to the KV and JSON domain of its name
// resolve again after `domain:<name>` restores all three.
#[test]
fn links_resolve_after_restoring_every_engine_of_a_domain() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, true, true).await;
        link_targets(&src).await;
        src.create(Engine::Rel, "d").await;
        src.sql("d", "CREATE TABLE links (id INTEGER PRIMARY KEY, kv KVREF, doc JSONREF)", &[]).await;
        src.sql("d", "INSERT INTO links VALUES (1, 'k1', 'doc1')", &[]).await;

        let out = tempfile::TempDir::new().unwrap();
        src.backup(out.path(), "bk_links", BackupScope::Domain("d".to_string())).await;
        let dst = server(1, true, true).await;
        dst.restore(out.path(), "bk_links", RestoreMode::FailIfExists, None).await.unwrap();

        assert_eq!(expanded(&dst, "d", "links", "kv").await, [json!({"exists": true, "value": "v1", "encoding": "utf8"})]);
        assert_eq!(expanded(&dst, "d", "links", "doc").await, [json!({"exists": true, "document": {"n": 1}})]);
    })
}

// A server running with the JSON engine off still backs links up as
// stored, and they resolve where the JSON domain exists.
#[test]
fn links_to_a_disabled_engine_are_backed_up_as_stored() {
    crate::core::engine_runtime::block_on(async {
        let rel_root = tempfile::TempDir::new().unwrap();
        let before = server_on(tempfile::TempDir::new().unwrap(), Some(rel_root.path()), 1, true).await;
        before.create(Engine::Json, "d").await;
        before.json("d").put_document("d", "doc1", json!({"n": 1})).await.unwrap();
        before.create(Engine::Rel, "d").await;
        before.sql("d", "CREATE TABLE jl (id INTEGER PRIMARY KEY, doc JSONREF)", &[]).await;
        before.sql("d", "INSERT INTO jl VALUES (1, 'doc1')", &[]).await;
        before.rel("d").shutdown().await;

        let after = server_on(tempfile::TempDir::new().unwrap(), Some(rel_root.path()), 1, false).await;
        assert_eq!(after.rows("d", "SELECT * FROM jl").await, [[ScalarValue::Integer(1), ScalarValue::Null]]);
        let out = tempfile::TempDir::new().unwrap();
        let path = after.backup(out.path(), "bk_raw", BackupScope::RelDomain("d".to_string())).await;
        let row = archive_lines(&path).into_iter().find(|l| l["t"] == "rel-row").unwrap();
        assert_eq!(row["row"]["doc"], "doc1");

        let dst = server(1, true, true).await;
        dst.create(Engine::Json, "d").await;
        dst.json("d").put_document("d", "doc1", json!({"n": 2})).await.unwrap();
        dst.restore(out.path(), "bk_raw", RestoreMode::FailIfExists, None).await.unwrap();
        assert_eq!(expanded(&dst, "d", "jl", "doc").await, [json!({"exists": true, "document": {"n": 2}})]);
    })
}

// Restoring only the relational domain into a server without the KV and
// JSON domain of its name succeeds; its links read as missing.
#[test]
fn links_without_their_target_domain_read_as_missing_after_a_restore() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, true, true).await;
        link_targets(&src).await;
        src.create(Engine::Rel, "d").await;
        src.sql("d", "CREATE TABLE links (id INTEGER PRIMARY KEY, kv KVREF, doc JSONREF)", &[]).await;
        src.sql("d", "INSERT INTO links VALUES (1, 'k1', 'doc1')", &[]).await;

        let out = tempfile::TempDir::new().unwrap();
        src.backup(out.path(), "bk_rel_only", BackupScope::RelDomain("d".to_string())).await;
        let dst = server(1, true, true).await;
        dst.restore(out.path(), "bk_rel_only", RestoreMode::FailIfExists, None).await.unwrap();
        assert_eq!(
            dst.rows("d", "SELECT * FROM links").await,
            [[ScalarValue::Integer(1), ScalarValue::Null, ScalarValue::Null]]
        );
    })
}

/// Waits until the directory shows `name` of `engine` as `Deleting`.
async fn until_deleting(control: &ControlPlane, engine: Engine, name: &str) {
    let wait = async {
        while control.directory().get(engine, name).map(|d| d.state) != Some(Lifecycle::Deleting) {
            tokio::task::yield_now().await;
        }
    };
    // Upper bound against hanging only.
    compio::time::timeout(Duration::from_secs(30), wait).await.expect("the domain never turned Deleting");
}

// While a restore replaces the KV domain that links of a relational table
// point to, a sweep of orphaned links leaves them alone.
#[test]
fn the_link_sweep_waits_while_a_restore_replaces_a_domain() {
    crate::core::engine_runtime::block_on(async {
        let server = Arc::new(server(1, false, true).await);
        server.create(Engine::Kv, "d").await;
        server.owners_kv("d").store("d").await.unwrap().put(b"k1", b"v1").await.unwrap();
        server.create(Engine::Rel, "d").await;
        server.sql("d", "CREATE TABLE kl (id INTEGER PRIMARY KEY, k KVREF)", &[]).await;
        server.sql("d", "INSERT INTO kl VALUES (1, 'k1')", &[]).await;
        let out = tempfile::TempDir::new().unwrap();
        server.backup(out.path(), "bk_kv", BackupScope::KvDomain("d".to_string())).await;

        let restore = compio::runtime::spawn({
            let (server, out) = (Arc::clone(&server), out.path().to_path_buf());
            async move { server.restore(&out, "bk_kv", RestoreMode::Replace, None).await }
        });
        until_deleting(&server.control, Engine::Kv, "d").await;
        assert!(server.control.restore_running());
        RelCrossEngineSweeper::new(Arc::clone(server.rel("d")), 100).sweep_tick().await.unwrap();

        let purging = server.purging();
        restore.await.unwrap().unwrap();
        drop(purging);
        assert!(!server.control.restore_running());
        let row = [ScalarValue::Integer(1), ScalarValue::Text("k1".to_string())];
        assert_eq!(server.rows("d", "SELECT * FROM kl").await, [row]);
    })
}

/// Domain `m` with table `t` holding `rows` rows.
async fn table_m(server: &Server, table: &str, rows: i64) {
    server.create(Engine::Rel, "m").await;
    server.sql("m", &format!("CREATE TABLE {table} (id INTEGER PRIMARY KEY)"), &[]).await;
    for i in 1..=rows {
        server.sql("m", &format!("INSERT INTO {table} VALUES (?)"), &[json!(i)]).await;
    }
}

// Restore modes for a relational domain: fail_if_exists leaves an
// existing one alone, replace swaps it, into_domain renames it, and a
// server without the relational engine refuses the archive untouched.
#[test]
fn restore_modes_apply_to_relational_domains() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, false, true).await;
        table_m(&src, "fresh", 3).await;
        src.create(Engine::Kv, "m").await;
        let out = tempfile::TempDir::new().unwrap();
        src.backup(out.path(), "bk_m", BackupScope::Domain("m".to_string())).await;
        let rows = src.rows("m", "SELECT * FROM fresh ORDER BY id").await;

        let dst = server(1, false, true).await;
        table_m(&dst, "stale", 2).await;
        let err = dst.restore(out.path(), "bk_m", RestoreMode::FailIfExists, None).await.unwrap_err();
        assert!(matches!(backup_error(&err), Some(BackupError::DomainExists(_))), "{err}");
        assert_eq!(dst.rows("m", "SELECT * FROM stale").await.len(), 2);
        assert!(dst.rel("m").get_object("m", "fresh").is_err());
        assert!(dst.owners_kv("m").get_domain("m").await.unwrap().is_none(), "nothing applied");

        let purging = dst.purging();
        dst.restore(out.path(), "bk_m", RestoreMode::Replace, None).await.unwrap();
        drop(purging);
        assert!(dst.rel("m").get_object("m", "stale").is_err(), "replace drops the old tables");
        assert_eq!(dst.rows("m", "SELECT * FROM fresh ORDER BY id").await, rows);

        dst.restore(out.path(), "bk_m", RestoreMode::FailIfExists, Some("m2")).await.unwrap();
        assert_eq!(dst.rows("m2", "SELECT * FROM fresh ORDER BY id").await, rows);

        let off = server(1, false, false).await;
        let err = off.restore(out.path(), "bk_m", RestoreMode::FailIfExists, None).await.unwrap_err();
        assert!(matches!(backup_error(&err), Some(BackupError::RelEngineDisabled)), "{err}");
        assert!(off.owners_kv("m").get_domain("m").await.unwrap().is_none(), "nothing applied");
    })
}

// Archives without relational lines, of format version 1 and 2,
// restore as before on a server with the relational engine.
#[test]
fn archives_without_relational_lines_restore_as_before() {
    crate::core::engine_runtime::block_on(async {
        let out = tempfile::TempDir::new().unwrap();
        let v1 = json!({
            "t": "manifest", "format_version": 1, "id": "bk_v1", "created_at": 1_700_000_000u64,
            "luradb_version": "0.4.0", "scope": "kv:shop", "include_auth": false, "kv_snapshot_ts": 1,
            "json_snapshot_ts": 0, "encoding": "hex", "schedule": null,
        });
        let v2 = json!({
            "t": "manifest", "format_version": 2, "id": "bk_v2", "created_at": 1_700_000_000u64,
            "luradb_version": "0.5.0", "scope": "kv:shop", "include_auth": false, "kv_snapshot_ts": 1,
            "json_snapshot_ts": 0, "encoding": "hex", "schedule": null, "shards": 2,
            "lsn_cut": {"kv": 4, "json": 0},
        });
        let domain = json!({"t": "kv-domain", "name": "shop", "created_at": 1_700_000_000u64});
        let entry = json!({"t": "kv", "domain": "shop", "k": hex::encode(b"k"), "v": hex::encode(b"v"), "expires_at": 0});
        for (id, manifest) in [("bk_v1", v1), ("bk_v2", v2)] {
            let body = [manifest.to_string(), domain.to_string(), entry.to_string()];
            reseal(&out.path().join(format!("{id}.ndjson")), &body);
            let dst = server(1, true, true).await;
            let outcome = dst.restore(out.path(), id, RestoreMode::FailIfExists, None).await.unwrap();
            assert_eq!((outcome.imported, outcome.failed), (1, 0), "{id}");
            let store = dst.owners_kv("shop").store("shop").await.unwrap();
            assert_eq!(store.get(b"k").await.unwrap(), GetResult::Present(b"v".to_vec()), "{id}");
        }
    })
}

// A relational row the engine refuses fails the whole restore job,
// naming domain and table, and the restore no longer counts as running.
#[test]
fn a_refused_relational_row_fails_the_restore_job() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, false, true).await;
        src.create(Engine::Rel, "f").await;
        src.sql("f", "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL)", &[]).await;
        src.sql("f", "INSERT INTO t VALUES (1, 'ok'), (2, 'fine')", &[]).await;
        let dir = tempfile::TempDir::new().unwrap();
        let path = src.backup(dir.path(), "bk_bad_row", BackupScope::RelDomain("f".to_string())).await;
        let body: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .take_while(|line| !line.contains("\"t\":\"checksum\""))
            .map(|line| line.replace("\"name\":\"fine\"", "\"name\":null"))
            .collect();
        reseal(&path, &body);

        let dst = server(1, false, true).await;
        let config = BackupConfig { enabled: true, dir: dir.path().to_string_lossy().into_owned(), schedule: Vec::new() };
        let manager = BackupManager::new(&config, Arc::clone(&dst.control)).unwrap();
        let (id, job) = manager.start_restore("bk_bad_row", RestoreMode::FailIfExists, None, false).await.unwrap();
        job.await.unwrap();

        let status = manager.get_restore_status(&id).unwrap();
        assert_eq!(status.state, RestoreState::Failed);
        let (_, message) = status.errors.last().unwrap();
        assert!(message.contains("'f'") && message.contains("'t'"), "{message}");
        assert!(!dst.control.restore_running());
    })
}

/// A view the engine refuses, here for the name of a table, fails the
/// restore, naming domain and view.
#[test]
fn a_refused_view_fails_the_restore_naming_the_view() {
    crate::core::engine_runtime::block_on(async {
        let src = server(1, false, true).await;
        src.create(Engine::Rel, "f").await;
        src.sql("f", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await;
        src.sql("f", "CREATE VIEW v AS SELECT id FROM t", &[]).await;
        let dir = tempfile::TempDir::new().unwrap();
        let path = src.backup(dir.path(), "bk_bad_view", BackupScope::RelDomain("f".to_string())).await;
        let body: Vec<String> = archive_lines(&path)
            .into_iter()
            .filter(|line| line["t"] != "checksum")
            .map(|mut line| {
                if line["t"] == "rel-view" {
                    line["name"] = json!("t");
                }
                line.to_string()
            })
            .collect();
        reseal(&path, &body);

        let dst = server(1, false, true).await;
        let err = dst.restore(dir.path(), "bk_bad_view", RestoreMode::FailIfExists, None).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("'f'") && message.contains("view 't'"), "{message}");
    })
}
