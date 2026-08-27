//! Relational engine — runs on its own dedicated LSM instance so relational
//! workloads (bulk imports, compaction) never impact KV/JSON performance.

pub mod ast;
pub mod binder;
pub mod catalog;
pub mod cross_engine;
pub mod ddl;
pub mod dml;
pub mod domain;
pub mod error;
pub mod eval;
pub mod expand;
pub mod join;
pub mod keys;
pub mod lexer;
pub mod parser;
pub mod plan;
pub mod purger;
pub mod rest_browse;
pub mod rest_exec;
pub mod rest_write;
pub mod row;
pub mod select;
pub mod types;
pub mod view;

pub use ast::StatementClass;
pub use binder::DdlPlan;
pub use catalog::{
    CatalogEntry, CatalogLimits, ColumnDef, ColumnInput, DefaultValue, IndexMeta, RelCatalog,
    TableInput, TableSchema, ViewSchema,
};
pub use cross_engine::{CrossEngineResolver, LinkAuth, RelCrossEngineSweeper};
pub use ddl::DdlOutcome;
pub use dml::{DmlResult, SelectResult};
pub use domain::{RelDomain, RelDomainState};
pub use error::RelStoreError;
pub use purger::RelDomainPurger;
pub use rest_exec::{ExpandedBlock, SqlOutcome};
pub use types::{encode_sortable, scalar_to_json, ColumnType, ScalarValue};

/// The result of `RelEngine::execute`, tagged by statement class (spec §14).
#[derive(Debug)]
pub enum ExecOutcome {
    Ddl(DdlOutcome),
    Dml(DmlResult),
    Select(SelectResult),
}

use crate::config::RelStoreConfig;
use crate::core::events::GlobalEventBus;
use crate::core::wal::WriteAheadLog;
use crate::engines::lsm::compaction::CompactionConfig;
use crate::engines::lsm::engine::{LsmEngineConfig, LsmEngineOptions, LsmStorageEngine};
use crate::engines::lsm::janitor::JanitorConfig;
use crate::engines::lsm::rate_limiter::RateLimiter;
use crate::metrics::MetricsStore;
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use anyhow::Result;
use domain::RelDomainRegistry;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Central entry point for all relational-store operations. For now it
/// wraps the dedicated LSM instance plus domain management (rel/002) —
/// catalog (rel/003) and the SQL frontend (rel/004+) follow in later specs.
pub struct RelEngine {
    engine: Arc<LsmStorageEngine>,
    domains: Arc<RelDomainRegistry>,
    catalog: Arc<RelCatalog>,
    metrics: Arc<MetricsStore>,
    /// Bridge to the same-named KV/JSON domains (spec rel/012). Fixed at
    /// bootstrap, never hot-swapped; the sole holder of kv/json handles.
    cross_engine: Arc<CrossEngineResolver>,
    /// SQL frontend guard (spec rel/004 §1): rejects longer statements
    /// before lexing even starts.
    max_statement_len: usize,
    /// Per-table write locks for the atomic DML path (spec rel/005 §8.1).
    table_locks: dml::TableLocks,
    /// Engine-global write serialization for the rel/013 finalization guard
    /// (§3): rel/005 has only per-table locks, so the DML-commit and
    /// cross-engine-sweep paths hold this around their `write_batch` + a domain
    /// re-check, and the purger holds it around its emptiness check +
    /// finalization — no in-flight row write can land after a domain is
    /// finalized (which would orphan a `ROW:` key into a recreated same-name
    /// domain sharing the FNV `system_prefix`).
    write_guard: tokio::sync::Mutex<()>,
    /// DML write-path guards (spec rel/005 §8/§16).
    max_text_len: usize,
    max_row_size: usize,
    max_key_length: usize,
    /// SELECT executor limits (spec rel/006 §12).
    default_limit: usize,
    max_limit: usize,
    max_sort_rows: usize,
    /// JOIN governance (spec rel/007 §8/§11).
    max_join_depth: usize,
    allow_unindexed_joins: bool,
    /// REST response cap (spec rel/009 §6): checked handler-side, after
    /// serialization, so it stays a plain getter here.
    max_response_bytes: usize,
    /// Lazily-filled per-domain rate limiters (spec rel/009 §7) — mirrors the
    /// KV `DomainRegistry`'s `runtimes` map: a separate, name-keyed structure,
    /// not a field of the serialized `RelDomain` (rel/002's invariant stays
    /// intact). `parking_lot::RwLock`: sync-only critical sections, never
    /// held across an `.await`.
    rate_limiters: RwLock<HashMap<String, Arc<RateLimiter>>>,
    /// Global lifecycle/DDL event bus (spec general/018 §1) — backs the
    /// central DDL dispatch in `execute_checked`; domain lifecycle events are
    /// published by `domains` itself. Unset in unit tests and a standalone-
    /// built engine, which then publish nothing.
    event_bus: OnceLock<Arc<GlobalEventBus>>,
}

impl RelEngine {
    /// Creates the dedicated relational LSM instance from `config`, starts its
    /// background tasks, and recovers the domain registry (rel/002) and the
    /// catalog (rel/003).
    pub async fn bootstrap(
        config: &RelStoreConfig,
        metrics: Arc<MetricsStore>,
        cross_engine: Arc<CrossEngineResolver>,
    ) -> Result<Arc<Self>> {
        let wal_path = PathBuf::from(&config.wal_path);
        let vlog_path = PathBuf::from(&config.vlog_path);
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await?);
        let vlog = Arc::new(VLog::new(&vlog_path).await?);
        let file_manager = Arc::new(FileManager::new(&config.sstable_dir).await?);
        let manifest_manager = Arc::new(ManifestManager::new(&config.sstable_dir));

        let engine_config = LsmEngineConfig {
            vlog_inline_threshold: config.lsm.vlog_inline_threshold,
            memtable_size_threshold: config.lsm.memtable_size_threshold,
            max_key_length: config.lsm.max_key_length,
            max_value_size: config.lsm.max_value_size,
            flush_check_interval_ms: config.lsm.flush_check_interval_ms,
            compaction_check_interval_ms: config.lsm.compaction_check_interval_ms,
            wal_event_channel_capacity: config.lsm.wal_event_channel_capacity,
            use_mmap: config.lsm.use_mmap,
            watch_replay_buffer_size: 0, // no watch endpoint on the relational engine (spec kv/024 §3)
        };
        let compaction_config = CompactionConfig {
            l0_compaction_threshold: config.compaction.l0_threshold,
            l1_max_size: config.compaction.l1_max_size,
            level_size_ratio: config.compaction.level_size_ratio,
            max_sstable_size: config.compaction.max_sstable_size,
            low_watermark: None,
        };
        let janitor_config = JanitorConfig {
            check_interval_secs: config.janitor.check_interval_secs,
            dead_bytes_threshold: config.janitor.dead_bytes_threshold,
            min_vlog_size_bytes: config.janitor.min_vlog_size_bytes,
        };
        let block_cache_config = crate::config::BlockCacheConfig {
            capacity_bytes: config.block_cache.capacity_bytes,
            small_ratio: config.block_cache.small_ratio,
            ghost_capacity: config.block_cache.ghost_capacity,
        };

        let engine = Arc::new(
            LsmStorageEngine::new(
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
            .await?,
        );
        engine.start_background_tasks();
        let domains = Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await?);
        let limits = CatalogLimits {
            max_columns: config.max_columns,
            max_indexes_per_table: config.max_indexes_per_table,
            max_tables_per_domain: config.max_tables_per_domain,
        };
        let catalog = Arc::new(RelCatalog::recover(Arc::clone(&engine), limits, Arc::clone(&metrics)).await?);
        Ok(Arc::new(Self {
            engine,
            domains,
            catalog,
            metrics,
            cross_engine,
            max_statement_len: config.max_statement_len,
            table_locks: dml::TableLocks::default(),
            write_guard: tokio::sync::Mutex::new(()),
            max_text_len: config.max_text_len,
            max_row_size: config.max_row_size,
            max_key_length: config.lsm.max_key_length,
            default_limit: config.default_limit,
            max_limit: config.max_limit,
            max_sort_rows: config.max_sort_rows,
            max_join_depth: config.max_join_depth,
            allow_unindexed_joins: config.allow_unindexed_joins,
            max_response_bytes: config.max_response_bytes,
            rate_limiters: RwLock::new(HashMap::new()),
            event_bus: OnceLock::new(),
        }))
    }

    /// The dedicated relational LSM instance.
    pub fn engine(&self) -> &Arc<LsmStorageEngine> {
        &self.engine
    }

    /// Wires the global event bus (spec general/018 §1): its own `OnceLock`
    /// backs the central DDL dispatch, and it forwards to `domains` for the
    /// domain lifecycle events.
    pub fn attach_event_bus(&self, bus: Arc<GlobalEventBus>) {
        self.domains.attach_event_bus(Arc::clone(&bus));
        let _ = self.event_bus.set(bus);
    }

    /// Gracefully shuts down the underlying LSM instance.
    pub async fn shutdown(&self) {
        self.engine.shutdown().await;
    }

    // ── Domain management (spec rel/002) ───────────────────────────────────────

    /// Creates a new rel domain.
    pub async fn create_domain(&self, name: &str) -> Result<RelDomain, RelStoreError> {
        self.domains.create_domain(name).await
    }

    /// Looks up an active rel domain.
    pub fn get_domain(&self, name: &str) -> Option<RelDomain> {
        self.domains.get_domain(name)
    }

    /// Looks up a rel domain regardless of its state (spec rel/009 §2): the
    /// REST detail handler's 410-vs-404 distinction needs `Deleting` domains
    /// too, unlike `get_domain`. Mirrors `JsonEngine::get_domain_any`.
    pub fn get_domain_any(&self, name: &str) -> Option<RelDomain> {
        self.domains.get_domain_any(name)
    }

    /// Lists all rel domains, `Deleting` ones included (each with its `state`,
    /// spec rel/013 §1); `get_domain`/`require_active` stay active-only.
    pub fn list_domains(&self) -> Vec<RelDomain> {
        self.domains.list_domains()
    }

    /// Marks a rel domain as deleting; the purger (rel/013) cleans up later.
    pub async fn delete_domain(&self, name: &str) -> Result<(), RelStoreError> {
        self.domains.delete_domain(name).await
    }

    // ── Catalog (spec rel/003) ─────────────────────────────────────────────────

    /// Programmatic catalog API for the DDL/REST layers (rel/004+).
    pub fn catalog(&self) -> &Arc<RelCatalog> {
        &self.catalog
    }

    /// Creates a table in `domain` from a validated `input`.
    pub async fn create_table(
        &self,
        domain: &str,
        input: TableInput,
    ) -> Result<TableSchema, RelStoreError> {
        self.catalog.create_table(&self.domains, domain, input).await
    }

    /// Creates a view storing its raw SELECT text (unvalidated; binding → rel/008).
    pub async fn create_view(
        &self,
        domain: &str,
        name: &str,
        sql: &str,
    ) -> Result<ViewSchema, RelStoreError> {
        self.catalog.create_view(&self.domains, domain, name, sql).await
    }

    /// Fetches a table or view by name.
    pub fn get_object(&self, domain: &str, name: &str) -> Result<CatalogEntry, RelStoreError> {
        self.catalog.get(&self.domains, domain, name)
    }

    /// Lists all catalog objects (tables + views) of a domain.
    pub fn list_objects(&self, domain: &str) -> Result<Vec<CatalogEntry>, RelStoreError> {
        self.catalog.list(&self.domains, domain)
    }

    /// Drops a table or view (a pure catalog delete; ids are not reused).
    pub async fn drop_object(&self, domain: &str, name: &str) -> Result<(), RelStoreError> {
        self.catalog.drop_object(&self.domains, domain, name).await
    }

    // ── REST-edge limits (spec rel/009 §6/§7) ───────────────────────────────────

    /// `max_response_bytes` getter (spec §6): the `/sql` handler checks the
    /// serialized response length against this after building it.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Drops a domain's lazily-created rate limiter (spec rel/009 §7). The
    /// rel/013 purger calls this once a domain is finalized, mirroring the KV
    /// registry's `runtimes` cleanup: a recreated same-name domain then starts
    /// with a fresh bucket instead of inheriting the old (possibly drained) one.
    pub(crate) fn drop_domain_rate_limiter(&self, domain: &str) {
        self.rate_limiters.write().remove(domain);
    }

    #[cfg(test)]
    pub(crate) fn has_rate_limiter(&self, domain: &str) -> bool {
        self.rate_limiters.read().contains_key(domain)
    }

    // ── Cross-engine links (spec rel/012) ───────────────────────────────────────

    /// Whether at least one target engine is wired — the sweeper is only worth
    /// spawning then (§5 startup integration).
    pub fn cross_engine_has_target(&self) -> bool {
        self.cross_engine.has_target()
    }

    /// DDL engine-enabled check (spec §2): a `KVREF`/`JSONREF` column may only
    /// be created when its target engine is enabled (the domain may still be
    /// absent — that first fails at the DML value check). `domain` = `None`
    /// since DDL is domain-agnostic here.
    fn check_ddl_link_engines(&self, plan: &DdlPlan) -> Result<(), RelStoreError> {
        let types: &[ColumnType] = match plan {
            DdlPlan::CreateTable(input) => {
                return input.columns.iter().try_for_each(|c| self.check_link_engine(c.col_type));
            }
            DdlPlan::AddColumn { column, .. } => std::slice::from_ref(&column.col_type),
            _ => return Ok(()),
        };
        types.iter().try_for_each(|t| self.check_link_engine(*t))
    }

    fn check_link_engine(&self, ct: ColumnType) -> Result<(), RelStoreError> {
        let engine = match ct {
            ColumnType::KvRef if !self.cross_engine.kv_enabled() => "kv",
            ColumnType::JsonRef if !self.cross_engine.json_enabled() => "json",
            _ => return Ok(()),
        };
        Err(RelStoreError::CrossEngineTargetUnavailable { engine: engine.to_string(), domain: None })
    }

    // ── SQL frontend & DDL (spec rel/004) ───────────────────────────────────────

    /// Runs one LuraSQL statement end to end: `max_statement_len` guard →
    /// lex → parse → bind (front-end guards for every class; full AST →
    /// catalog-input translation for DDL) → execute. Table/index DDL,
    /// `CREATE`/`DROP VIEW` (rel/008 `view.rs`, needs the raw SQL text so is
    /// intercepted here rather than in `execute_dml`), INSERT/UPDATE/DELETE,
    /// and SELECT (incl. `LEFT JOIN` and view-inlining) all execute for real.
    pub async fn execute(
        &self,
        domain: &str,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<ExecOutcome, RelStoreError> {
        self.execute_checked(domain, sql, params, LinkAuth::full(), |_class| Ok(())).await
    }

    /// Shared core of [`Self::execute`] and the REST-edge
    /// [`Self::execute_sql`] (rel/009 `rest_exec.rs`): identical lex/parse/
    /// bind/dispatch, with one seam — `mid` runs right after classification,
    /// before binding/dispatch ever touches the engine, so a caller can gate
    /// the statement (rate limit here; rel/011 adds statement-level auth at
    /// the same seam) without a second parse. `execute` passes a no-op `mid`
    /// and `LinkAuth::full()`, so its behavior/signature are unchanged.
    /// `auth` flows into `execute_dml` for cross-engine link masking/
    /// validation (spec rel/016).
    pub(crate) async fn execute_checked(
        &self,
        domain: &str,
        sql: &str,
        params: &[serde_json::Value],
        auth: LinkAuth,
        mid: impl FnOnce(StatementClass) -> Result<(), RelStoreError> + Send,
    ) -> Result<ExecOutcome, RelStoreError> {
        let tokens = lexer::tokenize(sql, self.max_statement_len).map_err(|e| {
            self.metrics.record_rel_frontend_parse_error();
            e
        })?;
        let param_count = lexer::count_params(&tokens);
        let stmt = parser::parse(&tokens).map_err(|e| {
            self.metrics.record_rel_frontend_parse_error();
            e
        })?;
        let class = stmt.class();

        self.metrics.record_rel_frontend_statement(match class {
            StatementClass::Read => "read",
            StatementClass::Write => "write",
            StatementClass::Ddl => "ddl",
        });

        mid(class)?;

        // The whole dispatch is captured before returning (spec general/018
        // §4 point 10): `ExecOutcome::Ddl` arises at three separate arms
        // below, so binding the match's value here — rather than a `?` on
        // each arm feeding straight into an early return — is the only way a
        // later fourth arm can't slip past the event publish.
        let outcome = match binder::bind(stmt, param_count, params)? {
            // CREATE INDEX runs the backfill-aware path (spec rel/005 §13).
            binder::BoundStatement::Ddl(DdlPlan::CreateIndex { table, name, column, unique }) => ddl::execute_create_index(
                &self.engine,
                &self.catalog,
                &self.domains,
                &self.metrics,
                &self.table_locks,
                self.max_key_length,
                domain,
                &table,
                &name,
                &column,
                unique,
            )
            .await
            .map(ExecOutcome::Ddl)?,
            binder::BoundStatement::Ddl(plan) => {
                self.check_ddl_link_engines(&plan)?;
                ddl::execute(&self.catalog, &self.domains, &self.metrics, domain, plan)
                    .await
                    .map(ExecOutcome::Ddl)?
            }
            // CREATE/DROP VIEW need the raw `sql` text (rel/008 §3: the stored
            // view body is the *raw* SELECT substring, not a re-serialized
            // AST) — routed here rather than into `execute_dml`, which only
            // sees the bound `Statement`, not the original source string.
            binder::BoundStatement::Pending { stmt, .. } => match stmt {
                ast::Statement::CreateView(cv) => {
                    view::execute_create_view(self, domain, cv, sql).await.map(ExecOutcome::Ddl)?
                }
                ast::Statement::DropView(dv) => {
                    view::execute_drop_view(self, domain, dv).await.map(ExecOutcome::Ddl)?
                }
                other => self.execute_dml(domain, other, params, auth).await?,
            },
        };
        if let ExecOutcome::Ddl(ddl_outcome) = &outcome {
            self.publish_ddl_event(domain, ddl_outcome);
        }
        Ok(outcome)
    }

    /// Maps a successfully executed `DdlOutcome` to its global-event-stream
    /// `kind`/`object` and publishes it (spec general/018 §2/§4 point 10). A
    /// `RENAME TABLE` (`TableAltered` with `renamed_from: Some(old)`)
    /// publishes two adjacent events instead of one (§2.1): `table_dropped`
    /// for the name that no longer exists, `table_created` for the one that
    /// now does — correct for every client without new field knowledge.
    fn publish_ddl_event(&self, domain: &str, outcome: &DdlOutcome) {
        let Some(bus) = self.event_bus.get() else { return };
        match outcome {
            DdlOutcome::TableCreated(schema) => bus.publish("rel", "table_created", domain, Some(schema.name.clone())),
            DdlOutcome::TableAltered { schema, renamed_from: Some(old) } => bus.publish_many(
                "rel",
                domain,
                &[("table_dropped", Some(old.clone())), ("table_created", Some(schema.name.clone()))],
            ),
            DdlOutcome::TableAltered { schema, renamed_from: None } => {
                bus.publish("rel", "table_altered", domain, Some(schema.name.clone()))
            }
            DdlOutcome::TableDropped { name } => bus.publish("rel", "table_dropped", domain, Some(name.clone())),
            DdlOutcome::IndexCreated(meta) => bus.publish("rel", "index_created", domain, Some(meta.name.clone())),
            DdlOutcome::IndexDropped { name } => bus.publish("rel", "index_dropped", domain, Some(name.clone())),
            DdlOutcome::ViewCreated(view) => bus.publish("rel", "view_created", domain, Some(view.name.clone())),
            DdlOutcome::ViewDropped { name } => bus.publish("rel", "view_dropped", domain, Some(name.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_engine() -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("rel_sstables").to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        };
        let metrics = MetricsStore::new(crate::metrics::MetricsConfig::default());
        let cross_engine = CrossEngineResolver::disabled(Arc::clone(&metrics));
        let engine = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();
        (engine, dir)
    }

    // 5. Bootstrap creates a working third LSM instance (put/get roundtrip).
    #[tokio::test]
    async fn test_bootstrap_put_get_roundtrip() {
        let (rel, _dir) = make_engine().await;
        rel.engine().put(b"row:1", b"{}").await.unwrap();
        let snap = rel.engine().snapshot();
        let got = rel
            .engine()
            .get_with_snapshot(b"row:1", snap.snapshot())
            .await
            .unwrap()
            .into_option();
        assert_eq!(got, Some(b"{}".to_vec()));
        rel.shutdown().await;
    }

    // 6. Bootstrap creates the sstable directory if it does not exist (nested).
    #[tokio::test]
    async fn test_bootstrap_creates_sstable_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let sstable_dir = dir.path().join("nested").join("sstables");
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: sstable_dir.to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        };
        let metrics = MetricsStore::new(crate::metrics::MetricsConfig::default());
        let cross_engine = CrossEngineResolver::disabled(Arc::clone(&metrics));
        let rel = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();
        assert!(sstable_dir.is_dir());
        rel.shutdown().await;
    }

    // 7. shutdown() after bootstrap runs cleanly.
    #[tokio::test]
    async fn test_shutdown_after_bootstrap() {
        let (rel, _dir) = make_engine().await;
        rel.shutdown().await;
    }

    // 8. Domain management (rel/002) wires through RelEngine's public API:
    //    the default domain exists right after bootstrap, and
    //    create/get/list/delete all delegate to the registry.
    #[tokio::test]
    async fn test_engine_delegates_domain_management() {
        let (rel, _dir) = make_engine().await;
        assert!(rel.get_domain("default").is_some());

        let created = rel.create_domain("tenant-a").await.unwrap();
        assert_eq!(created.system_prefix.len(), 16);
        assert!(rel.list_domains().iter().any(|d| d.name == "tenant-a"));

        rel.delete_domain("tenant-a").await.unwrap();
        assert!(rel.get_domain("tenant-a").is_none());
        rel.shutdown().await;
    }

    // 9. Catalog (rel/003) wires through RelEngine's public API.
    #[tokio::test]
    async fn test_engine_delegates_catalog() {
        let (rel, _dir) = make_engine().await;
        let mut pk = ColumnInput::new("id", ColumnType::Integer);
        pk.primary_key = true;
        let input = TableInput {
            name: "items".to_string(),
            columns: vec![pk],
        };
        let schema = rel.create_table("default", input).await.unwrap();
        assert_eq!(schema.table_id, 1);

        rel.create_view("default", "v", "SELECT * FROM items").await.unwrap();
        assert_eq!(rel.list_objects("default").unwrap().len(), 2);
        assert!(matches!(rel.get_object("default", "items").unwrap(), CatalogEntry::Table(_)));

        rel.drop_object("default", "items").await.unwrap();
        assert!(rel.get_object("default", "items").is_err());
        rel.shutdown().await;
    }

    // ── SQL frontend & DDL end-to-end (spec rel/004) ────────────────────────────

    async fn make_engine_with(overrides: RelStoreConfig) -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("rel_sstables").to_string_lossy().into_owned(),
            ..overrides
        };
        let metrics = MetricsStore::new(crate::metrics::MetricsConfig::default());
        let cross_engine = CrossEngineResolver::disabled(Arc::clone(&metrics));
        let engine = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();
        (engine, dir)
    }

    // 2. max_statement_len guard fires end-to-end, before lexing.
    #[tokio::test]
    async fn test_execute_statement_too_long() {
        let (rel, _dir) = make_engine_with(RelStoreConfig {
            max_statement_len: 10,
            ..RelStoreConfig::default()
        })
        .await;
        let err = rel.execute("default", "SELECT * FROM t", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::StatementTooLong { max: 10, .. }), "got: {err}");
        rel.shutdown().await;
    }

    // 3. Empty input -> EmptyStatement; two statements -> MultipleStatements;
    //    a single trailing ';' is fine.
    #[tokio::test]
    async fn test_execute_statement_boundaries() {
        let (rel, _dir) = make_engine().await;
        let err = rel.execute("default", "", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::EmptyStatement), "got: {err}");

        let err = rel
            .execute(
                "default",
                "CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY)",
                &[],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::MultipleStatements), "got: {err}");

        rel.execute("default", "CREATE TABLE a (id INTEGER PRIMARY KEY);", &[])
            .await
            .unwrap();
        rel.shutdown().await;
    }

    // 8+9+10 (wiring sanity): the NULL-bind guard and parameter-count check
    // fire through the real `execute` entry point, before dispatch ever picks
    // an execution path (SELECT itself is never executed).
    #[tokio::test]
    async fn test_execute_null_guard_and_param_count_wiring() {
        let (rel, _dir) = make_engine().await;

        let err = rel.execute("default", "SELECT * FROM t WHERE id = NULL", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");

        let err = rel
            .execute("default", "SELECT * FROM t WHERE id = ?", &[serde_json::Value::Null])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::NullComparison { .. }), "got: {err}");

        let err = rel.execute("default", "SELECT * FROM t WHERE id = ?", &[]).await.unwrap_err();
        assert!(
            matches!(err, RelStoreError::ParameterCountMismatch { expected: 1, actual: 0 }),
            "got: {err}"
        );
        rel.shutdown().await;
    }

    // 11. CREATE TABLE without a PK, or with two -> InvalidSchema.
    #[tokio::test]
    async fn test_execute_create_table_pk_rules() {
        let (rel, _dir) = make_engine().await;
        let err = rel.execute("default", "CREATE TABLE t (a INTEGER)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let err = rel
            .execute("default", "CREATE TABLE t (a INTEGER PRIMARY KEY, b INTEGER PRIMARY KEY)", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
        rel.shutdown().await;
    }

    // 12. AUTOINCREMENT on a TEXT PK -> InvalidSchema; on an INTEGER PK -> ok.
    #[tokio::test]
    async fn test_execute_autoincrement_rules() {
        let (rel, _dir) = make_engine().await;
        let err = rel
            .execute("default", "CREATE TABLE t (a TEXT PRIMARY KEY AUTOINCREMENT)", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        rel.execute("default", "CREATE TABLE t (a INTEGER PRIMARY KEY AUTOINCREMENT)", &[])
            .await
            .unwrap();
        rel.shutdown().await;
    }

    // 13. REFERENCES: matching PK type ok; mismatch -> TypeMismatch; missing
    //     target table -> TableNotFound.
    #[tokio::test]
    async fn test_execute_references_rules() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE parent (id INTEGER PRIMARY KEY)", &[])
            .await
            .unwrap();
        rel.execute(
            "default",
            "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent)",
            &[],
        )
        .await
        .unwrap();

        let err = rel
            .execute(
                "default",
                "CREATE TABLE bad (id INTEGER PRIMARY KEY, parent_id TEXT REFERENCES parent)",
                &[],
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TypeMismatch { .. }), "got: {err}");

        let err = rel
            .execute("default", "CREATE TABLE bad2 (id INTEGER PRIMARY KEY, x INTEGER REFERENCES ghost)", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");
        rel.shutdown().await;
    }

    // 14. CREATE TABLE on a name already used by a table or a view ->
    //     TableAlreadyExists; more than max_columns columns -> LimitExceeded.
    #[tokio::test]
    async fn test_execute_create_table_collision_and_column_limit() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        let err = rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::TableAlreadyExists { .. }), "got: {err}");

        rel.create_view("default", "v", "SELECT 1").await.unwrap();
        let err = rel.execute("default", "CREATE TABLE v (id INTEGER PRIMARY KEY)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::TableAlreadyExists { .. }), "got: {err}");
        rel.shutdown().await;

        let (rel2, _dir2) = make_engine_with(RelStoreConfig {
            max_columns: 2,
            ..RelStoreConfig::default()
        })
        .await;
        let err = rel2
            .execute("default", "CREATE TABLE t (a INTEGER PRIMARY KEY, b INTEGER, c INTEGER)", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "got: {err}");
        rel2.shutdown().await;
    }

    // 15. ADD COLUMN ... NOT NULL without DEFAULT -> InvalidSchema; with a
    //     literal DEFAULT -> ok.
    #[tokio::test]
    async fn test_execute_add_column_not_null_requires_default() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();

        let err = rel
            .execute("default", "ALTER TABLE t ADD COLUMN name TEXT NOT NULL", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        rel.execute("default", "ALTER TABLE t ADD COLUMN name TEXT NOT NULL DEFAULT 'x'", &[])
            .await
            .unwrap();
        rel.shutdown().await;
    }

    // 16. DROP COLUMN on the PK or an indexed column -> ColumnIndexedOrPrimaryKey
    //     (409); a plain column drops fine.
    #[tokio::test]
    async fn test_execute_drop_column_pk_or_indexed() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY, tag TEXT, note TEXT)", &[])
            .await
            .unwrap();
        rel.execute("default", "CREATE INDEX t_tag_idx ON t (tag)", &[]).await.unwrap();

        let err = rel.execute("default", "ALTER TABLE t DROP COLUMN id", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnIndexedOrPrimaryKey { .. }), "got: {err}");
        let err = rel.execute("default", "ALTER TABLE t DROP COLUMN tag", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnIndexedOrPrimaryKey { .. }), "got: {err}");

        rel.execute("default", "ALTER TABLE t DROP COLUMN note", &[]).await.unwrap();
        rel.shutdown().await;
    }

    // 17. RENAME COLUMN / RENAME TO; name collisions -> 409; PK/indexed
    //     columns may be renamed.
    #[tokio::test]
    async fn test_execute_rename_column_and_table() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY, tag TEXT, other TEXT)", &[])
            .await
            .unwrap();
        rel.execute("default", "CREATE INDEX t_tag_idx ON t (tag)", &[]).await.unwrap();

        rel.execute("default", "ALTER TABLE t RENAME COLUMN id TO pk", &[]).await.unwrap();
        rel.execute("default", "ALTER TABLE t RENAME COLUMN tag TO label", &[]).await.unwrap();

        let err = rel
            .execute("default", "ALTER TABLE t RENAME COLUMN other TO label", &[])
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnAlreadyExists { .. }), "got: {err}");

        rel.execute("default", "CREATE TABLE u (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        let err = rel.execute("default", "ALTER TABLE t RENAME TO u", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::TableAlreadyExists { .. }), "got: {err}");

        rel.execute("default", "ALTER TABLE t RENAME TO t2", &[]).await.unwrap();
        rel.shutdown().await;
    }

    // 18. CREATE INDEX over max_indexes_per_table -> LimitExceeded; duplicate
    //     name -> IndexAlreadyExists; missing column -> ColumnNotFound; DROP
    //     INDEX on a missing name -> IndexNotFound.
    #[tokio::test]
    async fn test_execute_index_limits_and_errors() {
        let (rel, _dir) = make_engine_with(RelStoreConfig {
            max_indexes_per_table: 1,
            ..RelStoreConfig::default()
        })
        .await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER)", &[])
            .await
            .unwrap();
        rel.execute("default", "CREATE INDEX idx_a ON t (a)", &[]).await.unwrap();

        let err = rel.execute("default", "CREATE INDEX idx_b ON t (b)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "got: {err}");

        let err = rel.execute("default", "CREATE INDEX idx_a ON t (b)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::IndexAlreadyExists { .. }), "got: {err}");

        let err = rel.execute("default", "CREATE INDEX idx_c ON t (ghost)", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnNotFound { .. }), "got: {err}");

        let err = rel.execute("default", "DROP INDEX ghost_idx", &[]).await.unwrap_err();
        assert!(matches!(err, RelStoreError::IndexNotFound { .. }), "got: {err}");

        rel.execute("default", "DROP INDEX idx_a", &[]).await.unwrap();
        rel.shutdown().await;
    }

    // 19 (superseded by rel/006-008): full-table scan/COUNT(*)/ORDER BY/non-PK
    // WHERE, LEFT JOIN, and now CREATE/DROP VIEW + SELECT-through-a-view all
    // execute for real (see select.rs/join.rs/view.rs for dedicated coverage);
    // this is just a wiring smoke test through the real `execute()` entry point.
    #[tokio::test]
    async fn test_execute_join_and_view_now_execute() {
        let (rel, _dir) = make_engine().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        rel.execute("default", "CREATE TABLE u (id INTEGER PRIMARY KEY)", &[]).await.unwrap();

        // LEFT JOIN on a PK executes for real (rel/007).
        rel.execute("default", "SELECT * FROM t LEFT JOIN u ON t.id = u.id", &[]).await.unwrap();

        // CREATE VIEW binds/validates and stores the raw text (rel/008).
        rel.execute("default", "CREATE VIEW v AS SELECT * FROM t", &[]).await.unwrap();

        // SELECT through a view inlines to the base table (rel/008).
        rel.execute("default", "SELECT * FROM v", &[]).await.unwrap();

        // DROP VIEW removes it (rel/008).
        rel.execute("default", "DROP VIEW v", &[]).await.unwrap();
        assert!(rel.get_object("default", "v").is_err());
        rel.shutdown().await;
    }

    // ── Spec general/018: global lifecycle event bus ────────────────────────

    async fn make_engine_with_bus() -> (Arc<RelEngine>, Arc<crate::core::events::GlobalEventBus>, tempfile::TempDir) {
        let (rel, dir) = make_engine().await;
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(64, 64));
        rel.attach_event_bus(Arc::clone(&bus));
        (rel, bus, dir)
    }

    // Test 3: CREATE TABLE, ALTER TABLE (add/rename column), CREATE INDEX,
    // DROP INDEX, CREATE VIEW, DROP VIEW, DROP TABLE -> one event each with
    // the right kind/object.
    #[tokio::test]
    async fn test_rel_ddl_publishes_one_event_per_statement_with_matching_kind_and_object() {
        let (rel, bus, _dir) = make_engine_with_bus().await;
        let mut rx = bus.subscribe();

        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)", &[]).await.unwrap();
        rel.execute("default", "ALTER TABLE t ADD COLUMN b INTEGER", &[]).await.unwrap();
        rel.execute("default", "ALTER TABLE t RENAME COLUMN b TO c", &[]).await.unwrap();
        rel.execute("default", "CREATE INDEX t_a_idx ON t (a)", &[]).await.unwrap();
        rel.execute("default", "DROP INDEX t_a_idx", &[]).await.unwrap();
        rel.execute("default", "CREATE VIEW v AS SELECT * FROM t", &[]).await.unwrap();
        rel.execute("default", "DROP VIEW v", &[]).await.unwrap();
        rel.execute("default", "DROP TABLE t", &[]).await.unwrap();

        let expected = [
            ("table_created", Some("t")),
            ("table_altered", Some("t")),
            ("table_altered", Some("t")),
            ("index_created", Some("t_a_idx")),
            ("index_dropped", Some("t_a_idx")),
            ("view_created", Some("v")),
            ("view_dropped", Some("v")),
            ("table_dropped", Some("t")),
        ];
        for (kind, object) in expected {
            let event = rx.try_recv().unwrap();
            assert_eq!(event.engine, "rel");
            assert_eq!(event.kind, kind);
            assert_eq!(event.object.as_deref(), object, "kind {kind}");
            assert_eq!(event.domain, "default");
        }
        assert!(rx.try_recv().is_err(), "no extra events expected");
    }

    // Test 3a: RENAME TABLE publishes exactly two events -- table_dropped
    // (old name) immediately followed by table_created (new name), with
    // consecutive sequences (spec §2.1).
    #[tokio::test]
    async fn test_rename_table_publishes_two_consecutive_events() {
        let (rel, bus, _dir) = make_engine_with_bus().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        let mut rx = bus.subscribe();

        rel.execute("default", "ALTER TABLE t RENAME TO t2", &[]).await.unwrap();

        let dropped = rx.try_recv().unwrap();
        let created = rx.try_recv().unwrap();
        assert_eq!(dropped.kind, "table_dropped");
        assert_eq!(dropped.object.as_deref(), Some("t"));
        assert_eq!(created.kind, "table_created");
        assert_eq!(created.object.as_deref(), Some("t2"));
        assert_eq!(created.seq, dropped.seq + 1, "must be consecutive sequences");
        assert!(rx.try_recv().is_err(), "exactly two events, nothing else");
    }

    // Test 4: a failed DDL (table already exists, view with a dependency,
    // duplicate domain name) publishes no event; a following successful
    // statement still publishes normally.
    #[tokio::test]
    async fn test_failed_ddl_publishes_no_event() {
        let (rel, bus, _dir) = make_engine_with_bus().await;
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY, a INTEGER)", &[]).await.unwrap();
        rel.execute("default", "CREATE VIEW v AS SELECT a FROM t", &[]).await.unwrap();
        let mut rx = bus.subscribe();

        // Table already exists.
        assert!(rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.is_err());
        // DROP COLUMN on a column `v` explicitly depends on.
        assert!(rel.execute("default", "ALTER TABLE t DROP COLUMN a", &[]).await.is_err());
        // Duplicate domain name.
        assert!(rel.create_domain("default").await.is_err());

        assert!(rx.try_recv().is_err(), "a failed DDL must publish nothing");

        // A subsequent successful statement still works and publishes normally.
        rel.execute("default", "CREATE TABLE u (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        let event = rx.try_recv().unwrap();
        assert_eq!(event.kind, "table_created");
        assert_eq!(event.object.as_deref(), Some("u"));
    }

    // Test 2 (rel slice): after a purge run, domain_purged appears, after
    // domain_deleted.
    #[tokio::test]
    async fn test_domain_purge_event_published_after_domain_deleted() {
        let (rel, bus, _dir) = make_engine_with_bus().await;
        let mut rx = bus.subscribe();

        rel.create_domain("purge-ev").await.unwrap();
        rx.try_recv().unwrap(); // domain_created, not under test here
        rel.delete_domain("purge-ev").await.unwrap();

        let purger = RelDomainPurger::new(Arc::clone(&rel), Arc::new(std::sync::atomic::AtomicBool::new(false)), 100, 5);
        purger.purge_tick().await.unwrap(); // empty domain: finalizes immediately

        let deleted = rx.try_recv().unwrap();
        assert_eq!(deleted.kind, "domain_deleted");
        let purged = rx.try_recv().unwrap();
        assert_eq!(purged.kind, "domain_purged");
        assert_eq!(purged.domain, "purge-ev");
    }

    // Test 12 (rel slice): DDL without a bus attached succeeds unchanged, no panic.
    #[tokio::test]
    async fn test_rel_ddl_without_event_bus_attached_succeeds_without_panic() {
        let (rel, _dir) = make_engine().await; // no attach_event_bus call
        rel.execute("default", "CREATE TABLE t (id INTEGER PRIMARY KEY)", &[]).await.unwrap();
        rel.execute("default", "ALTER TABLE t ADD COLUMN a INTEGER", &[]).await.unwrap();
        rel.execute("default", "DROP TABLE t", &[]).await.unwrap();
    }
}
