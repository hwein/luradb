//! Catalog for the relational store (spec rel/003).
//!
//! A `CAT:` entry describes a table **or** a view (shared per-domain namespace).
//! This is a purely programmatic Rust API — no SQL; the DDL frontend (rel/004)
//! and the write path (rel/005) call into it. Pattern: `IndexRegistry` (json/004)
//! — in-memory cache + LSM persistence + `ddl_lock`. Table/index ids come from a
//! persistent, strictly monotonic per-domain counter whose bump is committed in
//! the **same** `WriteBatch` as the consuming catalog mutation (crash-safe,
//! never reused — a fresh id after `DROP`+re-`CREATE` avoids colliding with
//! orphaned `ROW:`/`IDX:` ranges not yet purged by rel/013).

use super::domain::{RelDomain, RelDomainRegistry};
use super::error::RelStoreError;
use super::types::{ColumnType, ScalarValue};
use crate::engines::lsm::domain::now_secs;
use crate::engines::lsm::engine::{BatchOp, LsmStorageEngine};
use crate::engines::StorageEngine;
use crate::metrics::MetricsStore;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

const CAT_PREFIX: &[u8] = b"CAT:";
const SYS_CATALOG_SEQ_PREFIX: &[u8] = b"__sys:rel_catalog_seq:";
const MAX_IDENTIFIER_LEN: usize = 50;

// ── Identifier rules (concept 3.5) ─────────────────────────────────────────────

/// Normalizes (lowercases) and validates a table/view/column/index identifier:
/// `[a-z_][a-z0-9_]{0,49}`. Stricter than the domain-name rule (no `-`).
fn normalize_identifier(name: &str) -> Result<String, RelStoreError> {
    let lower = name.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTIFIER_LEN {
        return Err(RelStoreError::InvalidIdentifier(format!(
            "'{name}' must be 1..={MAX_IDENTIFIER_LEN} characters"
        )));
    }
    let first = bytes[0];
    if first != b'_' && !first.is_ascii_lowercase() {
        return Err(RelStoreError::InvalidIdentifier(format!(
            "'{name}' must start with a letter or underscore"
        )));
    }
    if !bytes
        .iter()
        .all(|&b| b == b'_' || b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(RelStoreError::InvalidIdentifier(format!(
            "'{name}' may only contain [a-z0-9_]"
        )));
    }
    Ok(lower)
}

// ── LSM keys ───────────────────────────────────────────────────────────────────

/// `CAT:{system_prefix}:{name}` — both parts are colon-free, so the key is
/// unambiguously parseable.
fn cat_key(system_prefix: &[u8], name: &str) -> Vec<u8> {
    let mut k = CAT_PREFIX.to_vec();
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k.extend_from_slice(name.as_bytes());
    k
}

/// `__sys:rel_catalog_seq:{domain}` — the per-domain id counter (self-hosted).
fn seq_key(domain: &str) -> Vec<u8> {
    let mut k = SYS_CATALOG_SEQ_PREFIX.to_vec();
    k.extend_from_slice(domain.as_bytes());
    k
}

/// Splits a `CAT:` key into `(system_prefix, name)`.
fn parse_cat_key(key: &[u8]) -> Option<(Vec<u8>, String)> {
    let rest = key.strip_prefix(CAT_PREFIX)?;
    let pos = rest.iter().position(|&b| b == b':')?;
    let name = std::str::from_utf8(&rest[pos + 1..]).ok()?.to_string();
    Some((rest[..pos].to_vec(), name))
}

// ── Data model ─────────────────────────────────────────────────────────────────

/// `None` = no clause; `Null` = explicit `DEFAULT NULL`; `Literal` = a typed
/// constant; `CurrentTimestamp` = `CURRENT_TIMESTAMP` (Timestamp columns only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum DefaultValue {
    #[default]
    None,
    Null,
    Literal(ScalarValue),
    CurrentTimestamp,
}

/// A stored column definition. `col_id` is a stable handle across schema changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub col_id: u16,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
    pub autoincrement: bool,
    pub unique: bool,
    pub default: DefaultValue,
    /// Target table name of a `REFERENCES` clause (rel-internal smart link).
    pub references: Option<String>,
}

/// A single-column index (v1). A `UNIQUE` column produces an implicit one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexMeta {
    pub name: String,
    pub index_id: u32,
    pub column: String,
    pub unique: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub name: String,
    pub table_id: u32,
    pub schema_version: u16,
    pub columns: Vec<ColumnDef>,
    pub indexes: Vec<IndexMeta>,
    pub created_at: u64,
    /// Next `col_id` to hand out on `ADD COLUMN` — tracked separately from
    /// `columns` so a `DROP COLUMN` (which removes the entry outright) can
    /// never cause a later `ADD COLUMN` to reuse a retired id (rel/004 §8:
    /// stale `ROW:` bytes for a dropped column must never be misread as a
    /// same-numbered new column before the next row rewrite purges them).
    #[serde(default = "default_next_col_id")]
    pub next_col_id: u16,
}

/// Backfill for `TableSchema` values serialized before `next_col_id` existed
/// (none in practice — fresh dev store — but keeps `recover()` infallible).
fn default_next_col_id() -> u16 {
    1
}

impl TableSchema {
    /// Type of the (single) primary-key column.
    pub fn primary_key_type(&self) -> Option<ColumnType> {
        self.columns.iter().find(|c| c.primary_key).map(|c| c.col_type)
    }
}

/// A view: only the raw SELECT text is stored here. Binding/validation/inlining
/// land in rel/008. A view has no `table_id` (no rows/indexes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSchema {
    pub name: String,
    pub sql: String,
    pub created_at: u64,
}

/// A catalog object: a table or a view. They share one per-domain namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogEntry {
    Table(TableSchema),
    View(ViewSchema),
}

impl CatalogEntry {
    pub fn name(&self) -> &str {
        match self {
            CatalogEntry::Table(t) => &t.name,
            CatalogEntry::View(v) => &v.name,
        }
    }
}

// ── Create-table input (no ids yet; the catalog assigns them) ──────────────────

#[derive(Debug, Clone)]
pub struct ColumnInput {
    pub name: String,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
    pub autoincrement: bool,
    pub unique: bool,
    pub default: DefaultValue,
    pub references: Option<String>,
}

impl ColumnInput {
    /// A nullable, non-key column with no default — tweak fields as needed.
    pub fn new(name: &str, col_type: ColumnType) -> Self {
        Self {
            name: name.to_string(),
            col_type,
            nullable: true,
            primary_key: false,
            autoincrement: false,
            unique: false,
            default: DefaultValue::None,
            references: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TableInput {
    pub name: String,
    pub columns: Vec<ColumnInput>,
}

/// Catalog limits (concept 8, from the `[rel]` config).
#[derive(Debug, Clone, Copy)]
pub struct CatalogLimits {
    pub max_columns: usize,
    pub max_indexes_per_table: usize,
    pub max_tables_per_domain: usize,
}

/// The set of catalog-live object ids of a domain — every `table_id` plus
/// every `index_id` (rel/013 §2 orphan sweep). An id `≤` the high-water mark
/// but absent here is an orphan candidate (a dropped table/index; ids are
/// never reused, rel/003).
pub(crate) struct LiveIds(HashSet<u32>);

impl LiveIds {
    /// Whether `id` still belongs to a live table or index.
    pub(crate) fn contains(&self, id: u32) -> bool {
        self.0.contains(&id)
    }
}

/// RAII cleanup for an index id reserved by [`RelCatalog::create_index_reserve`]
/// but not yet catalog-visible (rel/013 F1). `ddl.rs` holds it across the index
/// backfill: its `Drop` frees the reservation on any early abort (`KeyTooLong`,
/// `UniqueViolation`, a scan error), so the orphaned `IDX:` bytes become
/// reapable again. The success path calls [`disarm`](Self::disarm) after
/// `create_index_commit`, which already freed the reservation and made the
/// index catalog-live.
pub(crate) struct IndexReservationGuard {
    reserved: Arc<parking_lot::Mutex<HashSet<(Vec<u8>, u32)>>>,
    key: (Vec<u8>, u32),
    armed: bool,
}

impl IndexReservationGuard {
    /// Success path: the reservation is already gone (freed by
    /// `create_index_commit`), so drop without touching the set.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for IndexReservationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.reserved.lock().remove(&self.key);
        }
    }
}

// ── RelCatalog ─────────────────────────────────────────────────────────────────

pub struct RelCatalog {
    /// system_prefix → (object name → entry). Keyed by prefix so recovery is
    /// self-contained (no registry lookup needed to rebuild it).
    entries: RwLock<HashMap<Vec<u8>, HashMap<String, CatalogEntry>>>,
    /// domain name → highest id handed out so far (0 = none).
    seq: RwLock<HashMap<String, u32>>,
    /// `(system_prefix, id)` reserved between `create_index_reserve` and
    /// `create_index_commit`: the id is already past the high-water mark but
    /// not yet catalog-live, so the rel/013 orphan sweep must spare it and its
    /// in-flight `IDX:` backfill (rel/013 F1). Never persisted — after a crash
    /// the set is empty and the then-orphaned bytes are reaped normally.
    reserved_ids: Arc<parking_lot::Mutex<HashSet<(Vec<u8>, u32)>>>,
    engine: Arc<LsmStorageEngine>,
    /// Serializes check-then-act catalog mutations (general/003).
    ddl_lock: Mutex<()>,
    limits: CatalogLimits,
    metrics: Arc<MetricsStore>,
}

impl RelCatalog {
    /// Rebuilds the cache and the id counters by scanning the `CAT:` and
    /// `__sys:rel_catalog_seq:` prefixes.
    pub async fn recover(
        engine: Arc<LsmStorageEngine>,
        limits: CatalogLimits,
        metrics: Arc<MetricsStore>,
    ) -> anyhow::Result<Self> {
        let entries = scan_catalog_entries(&engine).await?;
        let seq = scan_seq_counters(&engine).await?;
        Ok(Self {
            entries: RwLock::new(entries),
            seq: RwLock::new(seq),
            reserved_ids: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            engine,
            ddl_lock: Mutex::new(()),
            limits,
            metrics,
        })
    }

    /// Validates and creates a table, assigning `table_id` and `index_id`s from
    /// the per-domain counter; the counter bump and the `CAT:` entry are
    /// committed in one atomic `WriteBatch`.
    pub async fn create_table(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        input: TableInput,
    ) -> Result<TableSchema, RelStoreError> {
        let name = normalize_identifier(&input.name)?;
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        if self
            .entries
            .read()
            .get(&prefix)
            .is_some_and(|m| m.contains_key(&name))
        {
            return Err(RelStoreError::TableAlreadyExists {
                domain: dom.name.clone(),
                name,
            });
        }

        let (columns, unique_columns) = self.validate_columns(&prefix, &dom.name, &input)?;

        if columns.len() > self.limits.max_columns {
            return Err(RelStoreError::LimitExceeded {
                which: "max_columns".to_string(),
                max: self.limits.max_columns,
            });
        }
        if unique_columns.len() > self.limits.max_indexes_per_table {
            return Err(RelStoreError::LimitExceeded {
                which: "max_indexes_per_table".to_string(),
                max: self.limits.max_indexes_per_table,
            });
        }
        let object_count = self.entries.read().get(&prefix).map_or(0, |m| m.len());
        if object_count >= self.limits.max_tables_per_domain {
            return Err(RelStoreError::LimitExceeded {
                which: "max_tables_per_domain".to_string(),
                max: self.limits.max_tables_per_domain,
            });
        }

        // Reserve 1 table_id + one index_id per unique column.
        let last = self.last_allocated_id(&dom.name, &prefix);
        let need = 1 + unique_columns.len() as u64;
        let new_last = (last as u64)
            .checked_add(need)
            .filter(|v| *v <= u32::MAX as u64)
            .ok_or_else(|| RelStoreError::IdSpaceExhausted(dom.name.clone()))? as u32;
        let table_id = last + 1;
        let indexes: Vec<IndexMeta> = unique_columns
            .iter()
            .enumerate()
            .map(|(i, column)| IndexMeta {
                name: format!("{name}_{column}_key"),
                index_id: last + 2 + i as u32,
                column: column.clone(),
                unique: true,
            })
            .collect();

        let next_col_id = columns.len() as u16 + 1;
        let schema = TableSchema {
            name: name.clone(),
            table_id,
            schema_version: 1,
            columns,
            indexes,
            created_at: now_secs(),
            next_col_id,
        };
        let entry = CatalogEntry::Table(schema.clone());

        self.engine
            .write_batch(vec![
                BatchOp::Put {
                    key: seq_key(&dom.name),
                    value: serde_json::to_vec(&new_last)?,
                },
                BatchOp::Put {
                    key: cat_key(&prefix, &name),
                    value: serde_json::to_vec(&entry)?,
                },
            ])
            .await?;

        self.seq.write().insert(dom.name.clone(), new_last);
        let count = self.cache_insert(prefix, name, entry);
        self.metrics.record_rel_ddl_create();
        self.metrics.set_rel_catalog_objects(&dom.name, count as u64);
        Ok(schema)
    }

    /// Stores a view's raw SELECT text unvalidated (binding → rel/008). Views
    /// consume no id. This is the storage primitive rel/008 calls after binding.
    pub async fn create_view(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        name: &str,
        sql: &str,
    ) -> Result<ViewSchema, RelStoreError> {
        self.create_view_checked(domains, domain, name, sql, |_| Ok(())).await
    }

    /// Like [`create_view`], but runs `validate` against the domain's current
    /// object map under the *same* `ddl_lock` acquisition, before the
    /// collision/limit checks (spec rel/008 §3): CREATE VIEW's deep bind and
    /// its storage thus run in one atomic critical section — no concurrent
    /// DDL can invalidate the view between validation and storage.
    pub async fn create_view_checked(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        name: &str,
        sql: &str,
        validate: impl FnOnce(&HashMap<String, CatalogEntry>) -> Result<(), RelStoreError>,
    ) -> Result<ViewSchema, RelStoreError> {
        let name = normalize_identifier(name)?;
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let current = self.entries.read().get(&prefix).cloned().unwrap_or_default();
        validate(&current)?;

        if current.contains_key(&name) {
            return Err(RelStoreError::ObjectAlreadyExists {
                domain: dom.name.clone(),
                name,
            });
        }
        if current.len() >= self.limits.max_tables_per_domain {
            return Err(RelStoreError::LimitExceeded {
                which: "max_tables_per_domain".to_string(),
                max: self.limits.max_tables_per_domain,
            });
        }

        let view = ViewSchema {
            name: name.clone(),
            sql: sql.to_string(),
            created_at: now_secs(),
        };
        let entry = CatalogEntry::View(view.clone());
        self.engine
            .put(&cat_key(&prefix, &name), &serde_json::to_vec(&entry)?)
            .await?;

        let count = self.cache_insert(prefix, name, entry);
        self.metrics.record_rel_ddl_create();
        self.metrics.set_rel_catalog_objects(&dom.name, count as u64);
        Ok(view)
    }

    /// Fetches a table or view by name (case-insensitive). `404` if absent.
    pub fn get(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        name: &str,
    ) -> Result<CatalogEntry, RelStoreError> {
        let dom = domains.require_active(domain)?;
        let key = name.to_ascii_lowercase();
        self.entries
            .read()
            .get(&dom.system_prefix)
            .and_then(|m| m.get(&key))
            .cloned()
            .ok_or(RelStoreError::ObjectNotFound {
                domain: dom.name,
                name: key,
            })
    }

    /// Lists all catalog objects (tables + views) of the domain.
    pub fn list(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
    ) -> Result<Vec<CatalogEntry>, RelStoreError> {
        let dom = domains.require_active(domain)?;
        Ok(self
            .entries
            .read()
            .get(&dom.system_prefix)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default())
    }

    /// Removes a catalog object. Ids are **not** released (the counter only
    /// moves forward). Physical `ROW:`/`IDX:`/`SEQ:` cleanup → rel/013.
    ///
    /// Named `drop_object`, not `drop`: an inherent `drop` is shadowed by
    /// `<Arc<Self> as Drop>::drop` in method resolution (the store is held as
    /// `Arc<RelCatalog>`), which would make the method uncallable.
    pub async fn drop_object(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        name: &str,
    ) -> Result<(), RelStoreError> {
        self.drop_object_checked(domains, domain, name, |_, _| Ok(())).await
    }

    /// Like [`drop_object`], but runs `check` — under the same `ddl_lock`
    /// acquisition as the delete — with both the just-removed [`CatalogEntry`]
    /// and the *prospective* per-domain map (the current one with `name`
    /// removed). The removed entry lets `DROP TABLE`/`DROP VIEW` verify the
    /// object's *kind* atomically with the delete, closing the check-then-lock
    /// TOCTOU where a concurrent re-`CREATE` of the same name as a different
    /// kind could otherwise be dropped by mistake (004 TOCTOU); the map lets a
    /// view depending on `name` be caught atomically too (spec rel/008 §7).
    pub async fn drop_object_checked(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        name: &str,
        check: impl FnOnce(&CatalogEntry, &HashMap<String, CatalogEntry>) -> Result<(), RelStoreError>,
    ) -> Result<(), RelStoreError> {
        let key = name.to_ascii_lowercase();
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut prospective = self.entries.read().get(&prefix).cloned().unwrap_or_default();
        let removed = match prospective.remove(&key) {
            Some(entry) => entry,
            None => {
                return Err(RelStoreError::ObjectNotFound {
                    domain: dom.name,
                    name: key,
                })
            }
        };
        check(&removed, &prospective)?;

        self.engine.delete(&cat_key(&prefix, &key)).await?;
        let count = {
            let mut cache = self.entries.write();
            match cache.get_mut(&prefix) {
                Some(m) => {
                    m.remove(&key);
                    m.len()
                }
                None => 0,
            }
        };
        self.metrics.record_rel_ddl_drop();
        self.metrics.set_rel_catalog_objects(&dom.name, count as u64);
        Ok(())
    }

    /// Removes every `CAT:` entry and the id counter of a domain — called by
    /// the rel/013 domain purger during finalization, after the data keys are
    /// gone.
    pub(crate) async fn purge_domain_definitions(
        &self,
        domain: &RelDomain,
    ) -> Result<(), RelStoreError> {
        let _guard = self.ddl_lock.lock().await;
        let mut scan = CAT_PREFIX.to_vec();
        scan.extend_from_slice(&domain.system_prefix);
        scan.push(b':');
        for key in self.engine.scan_keys(&scan).await? {
            self.engine.delete(&key).await?;
        }
        self.engine.delete(&seq_key(&domain.name)).await?;
        self.entries.write().remove(&domain.system_prefix);
        self.seq.write().remove(&domain.name);
        self.metrics.set_rel_catalog_objects(&domain.name, 0);
        Ok(())
    }

    /// The live object ids (table + index) of a domain (rel/013 §2 orphan
    /// sweep). Cache-only read. Empty for an unknown / catalog-empty domain.
    pub(crate) fn live_object_ids(&self, domain: &RelDomain) -> LiveIds {
        let mut ids = HashSet::new();
        if let Some(map) = self.entries.read().get(&domain.system_prefix) {
            for entry in map.values() {
                if let CatalogEntry::Table(t) = entry {
                    ids.insert(t.table_id);
                    ids.extend(t.indexes.iter().map(|ix| ix.index_id));
                }
            }
        }
        LiveIds(ids)
    }

    /// The domain's catalog id high-water mark (`__sys:rel_catalog_seq:{name}`),
    /// the upper bound of all ids ever handed out; `0` if it never allocated one
    /// (rel/013 §2). Cache-only read.
    pub(crate) fn allocated_id_high_watermark(&self, domain: &RelDomain) -> u32 {
        self.seq.read().get(&domain.name).copied().unwrap_or(0)
    }

    /// Whether `(prefix, id)` is currently reserved by an in-flight
    /// `create_index_reserve` (rel/013 F1). The rel/013 orphan sweep calls this
    /// to spare a reserved-but-not-yet-catalog-live index id. Lock held only
    /// for the probe.
    pub(crate) fn is_id_reserved(&self, prefix: &[u8], id: u32) -> bool {
        self.reserved_ids.lock().contains(&(prefix.to_vec(), id))
    }

    /// A cleanup guard for an id already reserved by `create_index_reserve`
    /// (rel/013 F1) — see [`IndexReservationGuard`]. `ddl.rs` builds one right
    /// after reserving so a backfill abort frees the reservation via `Drop`.
    pub(crate) fn index_reservation_guard(&self, prefix: &[u8], id: u32) -> IndexReservationGuard {
        IndexReservationGuard {
            reserved: Arc::clone(&self.reserved_ids),
            key: (prefix.to_vec(), id),
            armed: true,
        }
    }

    // ── internals ──────────────────────────────────────────────────────────────

    /// The highest live table/index id under `prefix` (`0` if none).
    fn max_live_id(&self, prefix: &[u8]) -> u32 {
        self.entries.read().get(prefix).map_or(0, |m| {
            m.values()
                .filter_map(|e| match e {
                    CatalogEntry::Table(t) => t
                        .indexes
                        .iter()
                        .map(|ix| ix.index_id)
                        .chain(std::iter::once(t.table_id))
                        .max(),
                    CatalogEntry::View(_) => None,
                })
                .max()
                .unwrap_or(0)
        })
    }

    /// The domain's last-allocated id: the persisted `__sys:rel_catalog_seq`
    /// counter, floored to [`max_live_id`](Self::max_live_id). The floor makes
    /// a lost or corrupt SEQ value (which `scan_seq_counters` silently skips,
    /// leaving the domain at `0`) unable to reissue an id that a live
    /// `table_id`/`index_id` already occupies — the collision that would smear
    /// a fresh table over an existing `ROW:`/`IDX:` range (003-F1).
    fn last_allocated_id(&self, domain_name: &str, prefix: &[u8]) -> u32 {
        let persisted = self.seq.read().get(domain_name).copied().unwrap_or(0);
        persisted.max(self.max_live_id(prefix))
    }

    /// Inserts into the cache and returns the domain's new object count.
    fn cache_insert(&self, prefix: Vec<u8>, name: String, entry: CatalogEntry) -> usize {
        let mut cache = self.entries.write();
        let m = cache.entry(prefix).or_default();
        m.insert(name, entry);
        m.len()
    }

    /// The prospective per-domain map for an in-place table-schema change
    /// (`DROP COLUMN`/`RENAME COLUMN`, spec rel/008 §7): current entries with
    /// `schema`'s own (already-mutated, not yet persisted) form substituted in.
    fn table_prospective(&self, prefix: &[u8], schema: &TableSchema) -> HashMap<String, CatalogEntry> {
        let mut prospective = self.entries.read().get(prefix).cloned().unwrap_or_default();
        prospective.insert(schema.name.clone(), CatalogEntry::Table(schema.clone()));
        prospective
    }

    /// Validates all columns and returns `(stored columns, unique column names)`.
    fn validate_columns(
        &self,
        prefix: &[u8],
        domain_name: &str,
        input: &TableInput,
    ) -> Result<(Vec<ColumnDef>, Vec<String>), RelStoreError> {
        let mut columns = Vec::with_capacity(input.columns.len());
        let mut unique_columns = Vec::new();
        let mut seen = HashSet::new();
        let mut pk_count = 0usize;

        for (idx, col) in input.columns.iter().enumerate() {
            let cname = normalize_identifier(&col.name)?;
            if !seen.insert(cname.clone()) {
                return Err(RelStoreError::InvalidSchema(format!(
                    "duplicate column '{cname}'"
                )));
            }

            let (def, is_pk) = self.build_column_def(prefix, domain_name, idx, col)?;
            if is_pk {
                pk_count += 1;
            }
            // The PK *is* the row key — a `PRIMARY KEY UNIQUE` column needs no
            // separate unique index (004-F4).
            if col.unique && !is_pk {
                unique_columns.push(cname);
            }
            columns.push(def);
        }

        if pk_count != 1 {
            return Err(RelStoreError::InvalidSchema(format!(
                "table '{}' must have exactly one primary key (has {pk_count})",
                input.name
            )));
        }
        Ok((columns, unique_columns))
    }

    /// Validates one column beyond the duplicate-name check — PK type,
    /// AUTOINCREMENT, DEFAULT, REFERENCES, in that order — and builds its
    /// `ColumnDef`. Returns whether it is a primary key, for the caller's
    /// `pk_count` aggregation.
    fn build_column_def(
        &self,
        prefix: &[u8],
        domain_name: &str,
        idx: usize,
        col: &ColumnInput,
    ) -> Result<(ColumnDef, bool), RelStoreError> {
        let cname = normalize_identifier(&col.name)?;
        if col.primary_key && !matches!(col.col_type, ColumnType::Integer | ColumnType::Text) {
            return Err(RelStoreError::InvalidSchema(format!(
                "primary key '{cname}' must be Integer or Text"
            )));
        }
        if col.autoincrement && !(col.primary_key && col.col_type == ColumnType::Integer) {
            return Err(RelStoreError::InvalidSchema(format!(
                "AUTOINCREMENT requires an Integer primary key ('{cname}')"
            )));
        }
        Self::check_default(&cname, col.col_type, &col.default)?;
        let references =
            self.resolve_references(prefix, domain_name, &cname, col.col_type, &col.references)?;

        Ok((
            ColumnDef {
                name: cname,
                col_id: (idx + 1) as u16,
                col_type: col.col_type,
                nullable: !col.primary_key && col.nullable, // PK is implicitly NOT NULL
                primary_key: col.primary_key,
                autoincrement: col.autoincrement,
                unique: col.unique,
                default: col.default.clone(),
                references,
            },
            col.primary_key,
        ))
    }

    /// Checks a `DEFAULT` clause against its column's type — shared by
    /// `CREATE TABLE` (`validate_columns`) and `ALTER TABLE ADD COLUMN`.
    fn check_default(
        cname: &str,
        col_type: ColumnType,
        default: &DefaultValue,
    ) -> Result<(), RelStoreError> {
        match default {
            DefaultValue::None | DefaultValue::Null => Ok(()),
            DefaultValue::Literal(v) => {
                if v.matches_type(col_type) {
                    Ok(())
                } else {
                    Err(RelStoreError::TypeMismatch {
                        context: format!("DEFAULT of column '{cname}'"),
                        expected: format!("{col_type:?}"),
                        actual: scalar_kind(v).to_string(),
                    })
                }
            }
            DefaultValue::CurrentTimestamp => {
                if col_type == ColumnType::Timestamp {
                    Ok(())
                } else {
                    Err(RelStoreError::InvalidSchema(format!(
                        "CURRENT_TIMESTAMP default requires a Timestamp column ('{cname}')"
                    )))
                }
            }
        }
    }

    /// Resolves and type-checks a `REFERENCES` target — shared by `CREATE
    /// TABLE` and `ALTER TABLE ADD COLUMN`. `KVREF`/`JSONREF` columns skip
    /// target validation (their existence check lands in rel/012).
    fn resolve_references(
        &self,
        prefix: &[u8],
        domain_name: &str,
        cname: &str,
        col_type: ColumnType,
        references: &Option<String>,
    ) -> Result<Option<String>, RelStoreError> {
        let Some(target) = references else {
            return Ok(None);
        };
        if matches!(col_type, ColumnType::KvRef | ColumnType::JsonRef) {
            return Ok(Some(target.clone()));
        }
        let target = target.to_ascii_lowercase();
        match self.entries.read().get(prefix).and_then(|m| m.get(&target)) {
            None => Err(RelStoreError::TableNotFound {
                domain: domain_name.to_string(),
                name: target,
            }),
            Some(CatalogEntry::View(_)) => Err(RelStoreError::InvalidSchema(format!(
                "REFERENCES target '{target}' is a view, not a table"
            ))),
            Some(CatalogEntry::Table(t)) => {
                let pk_type = t.primary_key_type().ok_or_else(|| {
                    RelStoreError::InvalidSchema(format!(
                        "REFERENCES target '{target}' has no primary key"
                    ))
                })?;
                if col_type.physical_type() == pk_type.physical_type() {
                    Ok(Some(target))
                } else {
                    Err(RelStoreError::TypeMismatch {
                        context: format!("column '{cname}' REFERENCES '{target}'"),
                        expected: format!("{pk_type:?}"),
                        actual: format!("{col_type:?}"),
                    })
                }
            }
        }
    }

    /// Looks up a table (not a view) by name, ready for `ALTER`/`CREATE INDEX`
    /// mutation. Rejects a same-named view exactly like a missing table —
    /// from the SQL DDL's point of view there is no *table* by that name.
    fn require_table(
        &self,
        prefix: &[u8],
        domain_name: &str,
        name: &str,
    ) -> Result<TableSchema, RelStoreError> {
        match self.entries.read().get(prefix).and_then(|m| m.get(name)) {
            Some(CatalogEntry::Table(t)) => Ok(t.clone()),
            Some(CatalogEntry::View(_)) | None => Err(RelStoreError::TableNotFound {
                domain: domain_name.to_string(),
                name: name.to_string(),
            }),
        }
    }

    /// Persists an updated `TableSchema` (one `Put`, no id/seq change) and
    /// refreshes the in-memory cache. Used by every `ALTER`/index primitive.
    async fn persist_table(&self, prefix: &[u8], schema: &TableSchema) -> Result<(), RelStoreError> {
        let entry = CatalogEntry::Table(schema.clone());
        self.engine
            .put(&cat_key(prefix, &schema.name), &serde_json::to_vec(&entry)?)
            .await?;
        self.entries
            .write()
            .entry(prefix.to_vec())
            .or_default()
            .insert(schema.name.clone(), entry);
        Ok(())
    }

    /// True if any table in the domain already has an index of this name
    /// (index names share one domain-wide namespace, addressed by `DROP
    /// INDEX name` alone — no table qualifier).
    fn index_name_taken(&self, prefix: &[u8], name: &str) -> bool {
        self.entries.read().get(prefix).is_some_and(|m| {
            m.values().any(|e| match e {
                CatalogEntry::Table(t) => t.indexes.iter().any(|ix| ix.name == name),
                CatalogEntry::View(_) => false,
            })
        })
    }

    /// Finds the table owning a domain-wide-unique index name.
    fn find_index_owner(&self, prefix: &[u8], name: &str) -> Option<TableSchema> {
        self.entries.read().get(prefix).and_then(|m| {
            m.values().find_map(|e| match e {
                CatalogEntry::Table(t) if t.indexes.iter().any(|ix| ix.name == name) => {
                    Some(t.clone())
                }
                _ => None,
            })
        })
    }

    // ── DDL primitives beyond CREATE TABLE (spec rel/004 §8) ────────────────
    //
    // Each is self-validating and atomic under `ddl_lock`, mirroring
    // `create_table`'s established shape: resolve the domain, re-check
    // everything from a consistent cache snapshot, mutate, persist, update
    // the cache. `schema_version` only moves on ADD/DROP COLUMN (concept 5.2).

    /// `ALTER TABLE ... ADD COLUMN` — appends one column. Rejects
    /// `PRIMARY KEY`/`AUTOINCREMENT`/`UNIQUE` (v1: a unique column is added
    /// via a subsequent `CREATE UNIQUE INDEX`) and a `NOT NULL` column
    /// without a literal `DEFAULT` (existing rows would read back `NULL`).
    pub async fn add_column(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        column: ColumnInput,
    ) -> Result<TableSchema, RelStoreError> {
        let table_name = normalize_identifier(table)?;
        let col_name = normalize_identifier(&column.name)?;
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut schema = self.require_table(&prefix, &dom.name, &table_name)?;
        if schema.columns.iter().any(|c| c.name == col_name) {
            return Err(RelStoreError::ColumnAlreadyExists {
                table: table_name,
                name: col_name,
            });
        }
        if schema.columns.len() >= self.limits.max_columns {
            return Err(RelStoreError::LimitExceeded {
                which: "max_columns".to_string(),
                max: self.limits.max_columns,
            });
        }
        if column.primary_key || column.autoincrement || column.unique {
            return Err(RelStoreError::InvalidSchema(
                "ADD COLUMN does not support PRIMARY KEY/AUTOINCREMENT/UNIQUE in v1; \
                 add a UNIQUE index with CREATE UNIQUE INDEX instead"
                    .to_string(),
            ));
        }
        if column.nullable {
            // nullable: any DEFAULT (or none) is fine.
        } else if !matches!(column.default, DefaultValue::Literal(_)) {
            return Err(RelStoreError::InvalidSchema(format!(
                "ADD COLUMN '{col_name}' NOT NULL requires a literal DEFAULT \
                 (DEFAULT NULL / DEFAULT CURRENT_TIMESTAMP do not satisfy it)"
            )));
        }
        Self::check_default(&col_name, column.col_type, &column.default)?;
        let references = self.resolve_references(
            &prefix,
            &dom.name,
            &col_name,
            column.col_type,
            &column.references,
        )?;

        let col_id = schema.next_col_id;
        schema.next_col_id = schema.next_col_id.checked_add(1).ok_or_else(|| {
            RelStoreError::IdSpaceExhausted(format!("table '{table_name}' column ids"))
        })?;
        schema.schema_version += 1;
        schema.columns.push(ColumnDef {
            name: col_name,
            col_id,
            col_type: column.col_type,
            nullable: column.nullable,
            primary_key: false,
            autoincrement: false,
            unique: false,
            default: column.default,
            references,
        });

        self.persist_table(&prefix, &schema).await?;
        self.metrics.record_rel_ddl_create();
        Ok(schema)
    }

    /// `ALTER TABLE ... DROP COLUMN` — the column must be neither the primary
    /// key nor indexed (drop the index first). Orphaned row bytes are only
    /// reclaimed on the next row rewrite (concept 5.4), not here.
    pub async fn drop_column(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        column: &str,
    ) -> Result<TableSchema, RelStoreError> {
        self.drop_column_checked(domains, domain, table, column, |_| Ok(())).await
    }

    /// Like [`drop_column`], but runs `check` against the prospective
    /// per-domain map (the column already dropped from the table's schema)
    /// under the same `ddl_lock` acquisition as the mutation (spec rel/008 §7).
    pub async fn drop_column_checked(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        column: &str,
        check: impl FnOnce(&HashMap<String, CatalogEntry>) -> Result<(), RelStoreError>,
    ) -> Result<TableSchema, RelStoreError> {
        let table_name = normalize_identifier(table)?;
        let col_name = column.to_ascii_lowercase();
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut schema = self.require_table(&prefix, &dom.name, &table_name)?;
        let col = schema
            .columns
            .iter()
            .find(|c| c.name == col_name)
            .ok_or_else(|| RelStoreError::ColumnNotFound {
                table: table_name.clone(),
                name: col_name.clone(),
            })?;
        if col.primary_key || schema.indexes.iter().any(|ix| ix.column == col_name) {
            return Err(RelStoreError::ColumnIndexedOrPrimaryKey {
                table: table_name,
                column: col_name,
            });
        }

        schema.columns.retain(|c| c.name != col_name);
        schema.schema_version += 1;
        check(&self.table_prospective(&prefix, &schema))?;
        self.persist_table(&prefix, &schema).await?;
        self.metrics.record_rel_ddl_drop();
        Ok(schema)
    }

    /// `ALTER TABLE ... RENAME COLUMN`. A PK/indexed column may be renamed —
    /// data keys are addressed by `col_id`, not by name (concept 5.2).
    pub async fn rename_column(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        from: &str,
        to: &str,
    ) -> Result<TableSchema, RelStoreError> {
        self.rename_column_checked(domains, domain, table, from, to, |_| Ok(())).await
    }

    /// Like [`rename_column`], but runs `check` against the prospective
    /// per-domain map (the column already renamed) under the same `ddl_lock`
    /// acquisition as the mutation (spec rel/008 §7).
    #[allow(clippy::too_many_arguments)]
    pub async fn rename_column_checked(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        from: &str,
        to: &str,
        check: impl FnOnce(&HashMap<String, CatalogEntry>) -> Result<(), RelStoreError>,
    ) -> Result<TableSchema, RelStoreError> {
        let table_name = normalize_identifier(table)?;
        let from_name = from.to_ascii_lowercase();
        let to_name = normalize_identifier(to)?;
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut schema = self.require_table(&prefix, &dom.name, &table_name)?;
        if !schema.columns.iter().any(|c| c.name == from_name) {
            return Err(RelStoreError::ColumnNotFound {
                table: table_name,
                name: from_name,
            });
        }
        if from_name != to_name && schema.columns.iter().any(|c| c.name == to_name) {
            return Err(RelStoreError::ColumnAlreadyExists {
                table: table_name,
                name: to_name,
            });
        }

        for c in schema.columns.iter_mut() {
            if c.name == from_name {
                c.name = to_name.clone();
            }
        }
        // `references` stays untouched: it holds *table* names, which a
        // column rename never affects.
        for ix in schema.indexes.iter_mut() {
            if ix.column == from_name {
                ix.column = to_name.clone();
            }
        }
        check(&self.table_prospective(&prefix, &schema))?;
        self.persist_table(&prefix, &schema).await?;
        Ok(schema)
    }

    /// `ALTER TABLE ... RENAME TO` — `table_id` is stable, only the name
    /// (and its `CAT:` key) changes.
    pub async fn rename_table(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        to: &str,
    ) -> Result<TableSchema, RelStoreError> {
        self.rename_table_checked(domains, domain, table, to, |_| Ok(())).await
    }

    /// Like [`rename_table`], but runs `check` against the prospective
    /// per-domain map (the table already renamed) under the same `ddl_lock`
    /// acquisition as the mutation (spec rel/008 §7).
    pub async fn rename_table_checked(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        to: &str,
        check: impl FnOnce(&HashMap<String, CatalogEntry>) -> Result<(), RelStoreError>,
    ) -> Result<TableSchema, RelStoreError> {
        let table_name = normalize_identifier(table)?;
        let to_name = normalize_identifier(to)?;
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut schema = self.require_table(&prefix, &dom.name, &table_name)?;
        if to_name != table_name
            && self
                .entries
                .read()
                .get(&prefix)
                .is_some_and(|m| m.contains_key(&to_name))
        {
            return Err(RelStoreError::TableAlreadyExists {
                domain: dom.name.clone(),
                name: to_name,
            });
        }

        schema.name = to_name.clone();
        let mut prospective = self.entries.read().get(&prefix).cloned().unwrap_or_default();
        prospective.remove(&table_name);
        prospective.insert(to_name.clone(), CatalogEntry::Table(schema.clone()));
        check(&prospective)?;

        let entry = CatalogEntry::Table(schema.clone());
        self.engine
            .write_batch(vec![
                BatchOp::Delete {
                    key: cat_key(&prefix, &table_name),
                },
                BatchOp::Put {
                    key: cat_key(&prefix, &to_name),
                    value: serde_json::to_vec(&entry)?,
                },
            ])
            .await?;
        {
            let mut cache = self.entries.write();
            let m = cache.entry(prefix).or_default();
            m.remove(&table_name);
            m.insert(to_name, entry);
        }
        Ok(schema)
    }

    /// Step 1 of the backfill-aware `CREATE INDEX` (spec rel/005 §13.0):
    /// validates the index, assigns its `index_id`, and **durably commits the
    /// id counter first** — before any `IDX:` entry is backfilled — so a crash
    /// during backfill can only burn the id (harmless orphan bytes the purger
    /// reaps), never let it be reissued to poison the new index. The
    /// `IndexMeta` becomes catalog-visible only in `create_index_commit`.
    pub async fn create_index_reserve(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        name: &str,
        column: &str,
        unique: bool,
    ) -> Result<(RelDomain, TableSchema, IndexMeta), RelStoreError> {
        let table_name = normalize_identifier(table)?;
        let index_name = normalize_identifier(name)?;
        let col_name = column.to_ascii_lowercase();
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let schema = self.require_table(&prefix, &dom.name, &table_name)?;
        if !schema.columns.iter().any(|c| c.name == col_name) {
            return Err(RelStoreError::ColumnNotFound { table: table_name, name: col_name });
        }
        if self.index_name_taken(&prefix, &index_name) {
            return Err(RelStoreError::IndexAlreadyExists {
                domain: dom.name.clone(),
                name: index_name,
            });
        }
        if schema.indexes.len() >= self.limits.max_indexes_per_table {
            return Err(RelStoreError::LimitExceeded {
                which: "max_indexes_per_table".to_string(),
                max: self.limits.max_indexes_per_table,
            });
        }

        let last = self.last_allocated_id(&dom.name, &prefix);
        let new_last = last
            .checked_add(1)
            .ok_or_else(|| RelStoreError::IdSpaceExhausted(dom.name.clone()))?;
        let meta = IndexMeta { name: index_name, index_id: new_last, column: col_name, unique };

        self.engine
            .write_batch(vec![BatchOp::Put {
                key: seq_key(&dom.name),
                value: serde_json::to_vec(&new_last)?,
            }])
            .await?;
        self.seq.write().insert(dom.name.clone(), new_last);
        // Reserve the id so the rel/013 orphan sweep spares its soon-to-be
        // backfilled IDX bytes until create_index_commit makes the index live
        // (rel/013 F1). Inserted only after the seq bump succeeds, so a failed
        // reserve leaks nothing; ddl.rs owns cleanup via the reservation guard.
        self.reserved_ids.lock().insert((prefix.clone(), new_last));
        Ok((dom, schema, meta))
    }

    /// Step 4 of the backfill-aware `CREATE INDEX` (spec rel/005 §13.4): makes
    /// the index catalog-visible **after** its entries are durably backfilled
    /// — never a visible index with missing entries.
    pub async fn create_index_commit(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        table: &str,
        meta: IndexMeta,
    ) -> Result<TableSchema, RelStoreError> {
        let table_name = normalize_identifier(table)?;
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut schema = self.require_table(&prefix, &dom.name, &table_name)?;
        // Re-checks under ddl_lock: the lock was free during the backfill, so a
        // same-named index (or the last free slot) may have been committed in
        // between. The backfilled IDX bytes then become orphans — the same
        // purger-fodder pattern as a crash between reserve and commit.
        if self.index_name_taken(&prefix, &meta.name) {
            return Err(RelStoreError::IndexAlreadyExists {
                domain: dom.name.clone(),
                name: meta.name,
            });
        }
        if schema.indexes.len() >= self.limits.max_indexes_per_table {
            return Err(RelStoreError::LimitExceeded {
                which: "max_indexes_per_table".to_string(),
                max: self.limits.max_indexes_per_table,
            });
        }
        let index_id = meta.index_id;
        schema.indexes.push(meta);
        self.persist_table(&prefix, &schema).await?;
        // The index is catalog-live now (live_object_ids covers it), so free
        // its reservation (rel/013 F1).
        self.reserved_ids.lock().remove(&(prefix, index_id));
        self.metrics.record_rel_ddl_create();
        Ok(schema)
    }

    /// `DROP INDEX` — addressed by name alone (domain-wide namespace).
    /// The implicit index backing a `UNIQUE` column constraint cannot be
    /// dropped (v1): it is tied to the constraint, not freestanding.
    pub async fn drop_index(
        &self,
        domains: &RelDomainRegistry,
        domain: &str,
        name: &str,
    ) -> Result<(), RelStoreError> {
        let index_name = name.to_ascii_lowercase();
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut schema = self.find_index_owner(&prefix, &index_name).ok_or_else(|| {
            RelStoreError::IndexNotFound {
                domain: dom.name.clone(),
                name: index_name.clone(),
            }
        })?;
        let ix = schema
            .indexes
            .iter()
            .find(|ix| ix.name == index_name)
            .expect("find_index_owner guarantees the index exists");
        // Only the *implicit* constraint index — the one create_table auto-named
        // `{table}_{column}_key` — is tied to a UNIQUE column and undroppable; a
        // separately named explicit UNIQUE index on the same column is droppable
        // (004-F5: identify it by that name, not by `unique` alone).
        let implicit_name = format!("{}_{}_key", schema.name, ix.column);
        if ix.name == implicit_name && schema.columns.iter().any(|c| c.name == ix.column && c.unique) {
            return Err(RelStoreError::InvalidSchema(format!(
                "index '{index_name}' backs the UNIQUE constraint on column '{}' and cannot be dropped (v1)",
                ix.column
            )));
        }
        schema.indexes.retain(|ix| ix.name != index_name);
        self.persist_table(&prefix, &schema).await?;
        self.metrics.record_rel_ddl_drop();
        Ok(())
    }
}

/// Scans the `CAT:` prefix into `system_prefix → (name → entry)` for
/// [`RelCatalog::recover`]. A key that doesn't split into `(prefix, name)`
/// and an entry that isn't valid `CatalogEntry` JSON are logged and skipped —
/// one bad record must not fail recovery.
async fn scan_catalog_entries(
    engine: &LsmStorageEngine,
) -> anyhow::Result<HashMap<Vec<u8>, HashMap<String, CatalogEntry>>> {
    let mut entries: HashMap<Vec<u8>, HashMap<String, CatalogEntry>> = HashMap::new();
    for key in engine.scan_keys(CAT_PREFIX).await? {
        let Some(bytes) = engine.get(&key).await? else {
            continue;
        };
        let entry = match serde_json::from_slice::<CatalogEntry>(&bytes) {
            Ok(entry) => entry,
            Err(e) => {
                tracing::warn!("[RelCatalog] cannot deserialize catalog entry at {:?}: {e}", key);
                continue;
            }
        };
        let Some((prefix, name)) = parse_cat_key(&key) else {
            tracing::warn!("[RelCatalog] unparseable CAT key {:?}", key);
            continue;
        };
        entries.entry(prefix).or_default().insert(name, entry);
    }
    Ok(entries)
}

/// Scans the `__sys:rel_catalog_seq:` prefix into `domain name → counter` for
/// [`RelCatalog::recover`]. Same tolerance as [`scan_catalog_entries`], via
/// [`parse_seq_entry`].
async fn scan_seq_counters(engine: &LsmStorageEngine) -> anyhow::Result<HashMap<String, u32>> {
    let mut seq = HashMap::new();
    for key in engine.scan_keys(SYS_CATALOG_SEQ_PREFIX).await? {
        let Some(bytes) = engine.get(&key).await? else {
            continue;
        };
        if let Some((name, last)) = parse_seq_entry(&key, &bytes) {
            seq.insert(name, last);
        }
    }
    Ok(seq)
}

/// Parses one `__sys:rel_catalog_seq:{name}` entry into `(name, counter)`.
/// `None` on a non-UTF8 name suffix or a non-`u32` value.
fn parse_seq_entry(key: &[u8], bytes: &[u8]) -> Option<(String, u32)> {
    let name = key
        .strip_prefix(SYS_CATALOG_SEQ_PREFIX)
        .and_then(|n| std::str::from_utf8(n).ok())?;
    let last = serde_json::from_slice::<u32>(bytes).ok()?;
    Some((name.to_string(), last))
}

/// Debug-style type name of a scalar value, for `TypeMismatch` error messages.
fn scalar_kind(v: &ScalarValue) -> &'static str {
    match v {
        ScalarValue::Integer(_) => "Integer",
        ScalarValue::Real(_) => "Real",
        ScalarValue::Text(_) => "Text",
        ScalarValue::Boolean(_) => "Boolean",
        ScalarValue::Timestamp(_) => "Timestamp",
        ScalarValue::Null => "Null",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::metrics::MetricsConfig;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;

    fn default_limits() -> CatalogLimits {
        CatalogLimits {
            max_columns: 128,
            max_indexes_per_table: 16,
            max_tables_per_domain: 256,
        }
    }

    async fn make_engine(dir: &std::path::Path) -> Arc<LsmStorageEngine> {
        let wal_path = dir.join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir));
        Arc::new(
            LsmStorageEngine::new(
                wal,
                wal_path,
                vlog,
                vlog_path,
                fm,
                mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        )
    }

    async fn make_catalog_with(
        limits: CatalogLimits,
    ) -> (
        Arc<LsmStorageEngine>,
        Arc<RelDomainRegistry>,
        Arc<RelCatalog>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = make_engine(dir.path()).await;
        let domains = Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap());
        let metrics = MetricsStore::new(MetricsConfig::default());
        let catalog = Arc::new(
            RelCatalog::recover(Arc::clone(&engine), limits, metrics)
                .await
                .unwrap(),
        );
        (engine, domains, catalog, dir)
    }

    async fn make_catalog() -> (
        Arc<LsmStorageEngine>,
        Arc<RelDomainRegistry>,
        Arc<RelCatalog>,
        tempfile::TempDir,
    ) {
        make_catalog_with(default_limits()).await
    }

    fn pk_int(name: &str) -> ColumnInput {
        let mut c = ColumnInput::new(name, ColumnType::Integer);
        c.primary_key = true;
        c
    }
    fn pk_text(name: &str) -> ColumnInput {
        let mut c = ColumnInput::new(name, ColumnType::Text);
        c.primary_key = true;
        c
    }
    fn col(name: &str) -> ColumnInput {
        ColumnInput::new(name, ColumnType::Integer)
    }
    fn uniq(name: &str) -> ColumnInput {
        let mut c = ColumnInput::new(name, ColumnType::Integer);
        c.unique = true;
        c
    }
    fn table(name: &str, columns: Vec<ColumnInput>) -> TableInput {
        TableInput {
            name: name.to_string(),
            columns,
        }
    }

    // 1. create_table -> get returns it; list contains it.
    #[tokio::test]
    async fn test_create_get_list() {
        let (_e, d, c, _dir) = make_catalog().await;
        let schema = c
            .create_table(&d, "default", table("users", vec![pk_int("id"), col("age")]))
            .await
            .unwrap();
        assert_eq!(schema.name, "users");
        assert_eq!(schema.table_id, 1);
        assert_eq!(schema.schema_version, 1);
        assert_eq!(schema.columns[0].col_id, 1);
        assert_eq!(schema.columns[1].col_id, 2);

        let got = c.get(&d, "default", "users").unwrap();
        assert_eq!(got.name(), "users");
        assert!(matches!(got, CatalogEntry::Table(_)));
        assert_eq!(c.list(&d, "default").unwrap().len(), 1);
    }

    // 2. Name collision -> 409: table vs table (case-insensitive) and table vs view.
    #[tokio::test]
    async fn test_name_collision_shared_namespace() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id")]))
            .await
            .unwrap();
        let err = c
            .create_table(&d, "default", table("T", vec![pk_int("id")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TableAlreadyExists { .. }), "got: {err}");
        let err = c.create_view(&d, "default", "t", "SELECT 1").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ObjectAlreadyExists { .. }), "got: {err}");
    }

    // 3. create on unknown domain -> 404; on a Deleting domain -> 410.
    #[tokio::test]
    async fn test_create_domain_states() {
        let (_e, d, c, _dir) = make_catalog().await;
        let err = c
            .create_table(&d, "ghost", table("t", vec![pk_int("id")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::DomainNotFound(_)), "got: {err}");

        d.create_domain("temp").await.unwrap();
        d.delete_domain("temp").await.unwrap();
        let err = c
            .create_table(&d, "temp", table("t", vec![pk_int("id")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::DomainDeleting(_)), "got: {err}");
    }

    // 4. drop -> neither in get nor list.
    #[tokio::test]
    async fn test_drop_removes_object() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("gone", vec![pk_int("id")]))
            .await
            .unwrap();
        c.drop_object(&d, "default", "gone").await.unwrap();
        let err = c.get(&d, "default", "gone").unwrap_err();
        assert!(matches!(err, RelStoreError::ObjectNotFound { .. }), "got: {err}");
        assert!(c.list(&d, "default").unwrap().is_empty());
        let err = c.drop_object(&d, "default", "gone").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ObjectNotFound { .. }), "got: {err}");
    }

    // 5. Identifier validation: valid ok; uppercase lowercased; bad names rejected.
    #[tokio::test]
    async fn test_identifier_validation() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("valid_name1", vec![pk_int("id")]))
            .await
            .unwrap();
        let s = c
            .create_table(&d, "default", table("MixedCase", vec![pk_int("ID")]))
            .await
            .unwrap();
        assert_eq!(s.name, "mixedcase");
        assert_eq!(s.columns[0].name, "id");

        for bad in ["1leading", "has-dash", "has space", "has:colon", &"x".repeat(51)] {
            let err = c
                .create_table(&d, "default", table(bad, vec![pk_int("id")]))
                .await
                .unwrap_err();
            assert!(matches!(err, RelStoreError::InvalidIdentifier(_)), "'{bad}' got: {err}");
        }
    }

    // 7. PK rules: exactly one PK; missing/multiple/wrong-type; AUTOINCREMENT.
    #[tokio::test]
    async fn test_primary_key_rules() {
        let (_e, d, c, _dir) = make_catalog().await;
        let err = c
            .create_table(&d, "default", table("nopk", vec![col("a")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let err = c
            .create_table(&d, "default", table("twopk", vec![pk_int("a"), pk_int("b")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let mut real_pk = ColumnInput::new("a", ColumnType::Real);
        real_pk.primary_key = true;
        let err = c
            .create_table(&d, "default", table("realpk", vec![real_pk]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let mut ai_text = pk_text("a");
        ai_text.autoincrement = true;
        let err = c
            .create_table(&d, "default", table("aitext", vec![ai_text]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let mut ai_ok = pk_int("a");
        ai_ok.autoincrement = true;
        let ok = c
            .create_table(&d, "default", table("aiok", vec![ai_ok]))
            .await
            .unwrap();
        assert!(ok.columns[0].autoincrement);
        assert!(!ok.columns[0].nullable, "PK is implicitly NOT NULL");
    }

    // 8. REFERENCES: valid + type match ok; unknown target; type mismatch;
    //    KVREF accepted without target validation; reference to a view rejected.
    #[tokio::test]
    async fn test_references() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("parent", vec![pk_int("id")]))
            .await
            .unwrap();

        let mut fk = ColumnInput::new("parent_id", ColumnType::Integer);
        fk.references = Some("parent".to_string());
        c.create_table(&d, "default", table("child", vec![pk_int("id"), fk]))
            .await
            .unwrap();

        let mut ghost = ColumnInput::new("x", ColumnType::Integer);
        ghost.references = Some("ghost".to_string());
        let err = c
            .create_table(&d, "default", table("c2", vec![pk_int("id"), ghost]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");

        let mut mism = ColumnInput::new("x", ColumnType::Text);
        mism.references = Some("parent".to_string());
        let err = c
            .create_table(&d, "default", table("c3", vec![pk_int("id"), mism]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TypeMismatch { .. }), "got: {err}");

        // KVREF column: accepted, no target validation.
        c.create_table(
            &d,
            "default",
            table("c4", vec![pk_int("id"), ColumnInput::new("blob", ColumnType::KvRef)]),
        )
        .await
        .unwrap();

        c.create_view(&d, "default", "v1", "SELECT 1").await.unwrap();
        let mut ref_view = ColumnInput::new("x", ColumnType::Integer);
        ref_view.references = Some("v1".to_string());
        let err = c
            .create_table(&d, "default", table("c5", vec![pk_int("id"), ref_view]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
    }

    // 9. Limits: max_columns, max_indexes_per_table, max_tables_per_domain.
    #[tokio::test]
    async fn test_limits() {
        let (_e, d, c, _dir) = make_catalog_with(CatalogLimits {
            max_columns: 2,
            max_indexes_per_table: 16,
            max_tables_per_domain: 256,
        })
        .await;
        let err = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), col("a"), col("b")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "columns: {err}");

        let (_e, d, c, _dir) = make_catalog_with(CatalogLimits {
            max_columns: 128,
            max_indexes_per_table: 1,
            max_tables_per_domain: 256,
        })
        .await;
        let err = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), uniq("a"), uniq("b")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "indexes: {err}");

        let (_e, d, c, _dir) = make_catalog_with(CatalogLimits {
            max_columns: 128,
            max_indexes_per_table: 16,
            max_tables_per_domain: 1,
        })
        .await;
        c.create_table(&d, "default", table("t1", vec![pk_int("id")]))
            .await
            .unwrap();
        let err = c
            .create_table(&d, "default", table("t2", vec![pk_int("id")]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "tables: {err}");
        // A view also counts against the table limit.
        let err = c.create_view(&d, "default", "v", "SELECT 1").await.unwrap_err();
        assert!(matches!(err, RelStoreError::LimitExceeded { .. }), "views count: {err}");
    }

    // 10. Ids are monotonic and never reused; the counter survives recover.
    #[tokio::test]
    async fn test_id_monotonic_and_survives_recover() {
        let (e, d, c, _dir) = make_catalog().await;
        let t1 = c
            .create_table(&d, "default", table("t", vec![pk_int("id")]))
            .await
            .unwrap();
        c.drop_object(&d, "default", "t").await.unwrap();
        let t2 = c
            .create_table(&d, "default", table("t", vec![pk_int("id")]))
            .await
            .unwrap();
        assert!(t2.table_id > t1.table_id, "re-created table must get a fresh id");

        let metrics = MetricsStore::new(MetricsConfig::default());
        let c2 = RelCatalog::recover(Arc::clone(&e), default_limits(), metrics)
            .await
            .unwrap();
        let t3 = c2
            .create_table(&d, "default", table("u", vec![pk_int("id")]))
            .await
            .unwrap();
        assert!(t3.table_id > t2.table_id, "counter must continue past recover");
    }

    // 17. Recovery: table + view + id counter survive a fresh recover.
    #[tokio::test]
    async fn test_recovery_of_entries_and_counter() {
        let (e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("tbl", vec![pk_int("id")]))
            .await
            .unwrap();
        c.create_view(&d, "default", "vw", "SELECT * FROM tbl")
            .await
            .unwrap();

        let metrics = MetricsStore::new(MetricsConfig::default());
        let c2 = RelCatalog::recover(Arc::clone(&e), default_limits(), metrics)
            .await
            .unwrap();
        assert!(matches!(c2.get(&d, "default", "tbl").unwrap(), CatalogEntry::Table(_)));
        match c2.get(&d, "default", "vw").unwrap() {
            CatalogEntry::View(v) => assert_eq!(v.sql, "SELECT * FROM tbl"),
            other => panic!("expected view, got {other:?}"),
        }
        assert_eq!(c2.list(&d, "default").unwrap().len(), 2);
        let next = c2
            .create_table(&d, "default", table("tbl2", vec![pk_int("id")]))
            .await
            .unwrap();
        assert!(next.table_id > 1, "counter must survive recover");
    }

    // 18. create_view stores raw SQL; get returns the View; view vs table -> 409.
    #[tokio::test]
    async fn test_create_view() {
        let (_e, d, c, _dir) = make_catalog().await;
        let sql = "SELECT a, b FROM t WHERE x > 1";
        let v = c.create_view(&d, "default", "myview", sql).await.unwrap();
        assert_eq!(v.sql, sql);
        match c.get(&d, "default", "myview").unwrap() {
            CatalogEntry::View(vw) => assert_eq!(vw.sql, sql),
            other => panic!("expected view, got {other:?}"),
        }

        c.create_table(&d, "default", table("shared", vec![pk_int("id")]))
            .await
            .unwrap();
        let err = c.create_view(&d, "default", "shared", "SELECT 1").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ObjectAlreadyExists { .. }), "got: {err}");
    }

    // ── DDL primitives beyond CREATE TABLE (spec rel/004 §8) ────────────────────

    // 19. add_column: col_id is "highest existing + 1", never reused after a
    //     DROP COLUMN + ADD COLUMN cycle; schema_version bumps only on
    //     ADD/DROP COLUMN (not RENAME COLUMN/RENAME TO/CREATE|DROP INDEX).
    #[tokio::test]
    async fn test_add_column_col_id_and_schema_version() {
        let (_e, d, c, _dir) = make_catalog().await;
        let schema = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), col("a")]))
            .await
            .unwrap();
        assert_eq!(schema.schema_version, 1);
        assert_eq!(schema.next_col_id, 3);

        let schema = c
            .add_column(&d, "default", "t", ColumnInput::new("b", ColumnType::Integer))
            .await
            .unwrap();
        assert_eq!(schema.schema_version, 2);
        assert_eq!(schema.columns.last().unwrap().col_id, 3);
        assert_eq!(schema.next_col_id, 4);

        let schema = c.drop_column(&d, "default", "t", "b").await.unwrap();
        assert_eq!(schema.schema_version, 3);
        assert!(!schema.columns.iter().any(|col| col.name == "b"));

        // Re-adding a column must not reuse col_id 3 (it belonged to 'b').
        let schema = c
            .add_column(&d, "default", "t", ColumnInput::new("c", ColumnType::Integer))
            .await
            .unwrap();
        assert_eq!(schema.schema_version, 4);
        assert_eq!(
            schema.columns.last().unwrap().col_id,
            4,
            "must not reuse the dropped column's col_id"
        );

        // RENAME COLUMN/RENAME TO/CREATE INDEX/DROP INDEX must not bump schema_version.
        let schema = c.rename_column(&d, "default", "t", "c", "c2").await.unwrap();
        assert_eq!(schema.schema_version, 4);
        let schema = c.rename_table(&d, "default", "t", "t2").await.unwrap();
        assert_eq!(schema.schema_version, 4);
        let (_dom, _schema, meta) = c
            .create_index_reserve(&d, "default", "t2", "t2_a_idx", "a", false)
            .await
            .unwrap();
        c.create_index_commit(&d, "default", "t2", meta.clone()).await.unwrap();
        let CatalogEntry::Table(schema) = c.get(&d, "default", "t2").unwrap() else {
            panic!("expected a table")
        };
        assert_eq!(schema.schema_version, 4);
        c.drop_index(&d, "default", &meta.name).await.unwrap();
        let CatalogEntry::Table(schema) = c.get(&d, "default", "t2").unwrap() else {
            panic!("expected a table")
        };
        assert_eq!(schema.schema_version, 4);
    }

    // 20. next_col_id survives recover().
    #[tokio::test]
    async fn test_next_col_id_survives_recover() {
        let (e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id")])).await.unwrap();
        c.add_column(&d, "default", "t", ColumnInput::new("a", ColumnType::Integer))
            .await
            .unwrap();

        let metrics = MetricsStore::new(MetricsConfig::default());
        let c2 = RelCatalog::recover(Arc::clone(&e), default_limits(), metrics).await.unwrap();
        let schema = c2
            .add_column(&d, "default", "t", ColumnInput::new("b", ColumnType::Integer))
            .await
            .unwrap();
        // Columns so far: id(1), a(2) -> next_col_id was 3 going into recover.
        assert_eq!(schema.columns.last().unwrap().col_id, 3, "next_col_id must survive recover");
    }

    // 21. add_column rejects PRIMARY KEY/AUTOINCREMENT/UNIQUE and a bare
    //     NOT NULL without a literal DEFAULT; table/column existence checks.
    #[tokio::test]
    async fn test_add_column_validation() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id")])).await.unwrap();

        let err = c.add_column(&d, "default", "ghost", col("a")).await.unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");

        let err = c.add_column(&d, "default", "t", pk_int("id")).await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnAlreadyExists { .. }), "got: {err}");

        let mut bad_pk = col("x");
        bad_pk.primary_key = true;
        let err = c.add_column(&d, "default", "t", bad_pk).await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let mut not_null_no_default = ColumnInput::new("y", ColumnType::Text);
        not_null_no_default.nullable = false;
        let err = c
            .add_column(&d, "default", "t", not_null_no_default)
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");

        let mut not_null_with_default = ColumnInput::new("z", ColumnType::Text);
        not_null_with_default.nullable = false;
        not_null_with_default.default = DefaultValue::Literal(ScalarValue::Text("x".to_string()));
        c.add_column(&d, "default", "t", not_null_with_default).await.unwrap();
    }

    // 22. drop_column: missing column -> ColumnNotFound; PK/indexed -> 409.
    #[tokio::test]
    async fn test_drop_column_validation() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id"), uniq("u"), col("a")]))
            .await
            .unwrap();

        let err = c.drop_column(&d, "default", "t", "ghost").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnNotFound { .. }), "got: {err}");

        let err = c.drop_column(&d, "default", "t", "id").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnIndexedOrPrimaryKey { .. }), "got: {err}");

        // 'u' carries an implicit unique index from CREATE TABLE.
        let err = c.drop_column(&d, "default", "t", "u").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnIndexedOrPrimaryKey { .. }), "got: {err}");

        c.drop_column(&d, "default", "t", "a").await.unwrap();
    }

    // 23. rename_column/rename_table: collisions -> 409; missing -> 404.
    #[tokio::test]
    async fn test_rename_column_and_table_validation() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id"), col("a"), col("b")]))
            .await
            .unwrap();
        c.create_table(&d, "default", table("u", vec![pk_int("id")])).await.unwrap();

        let err = c.rename_column(&d, "default", "t", "ghost", "z").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnNotFound { .. }), "got: {err}");
        let err = c.rename_column(&d, "default", "t", "a", "b").await.unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnAlreadyExists { .. }), "got: {err}");
        c.rename_column(&d, "default", "t", "a", "a2").await.unwrap();

        let err = c.rename_table(&d, "default", "ghost", "z").await.unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");
        let err = c.rename_table(&d, "default", "t", "u").await.unwrap_err();
        assert!(matches!(err, RelStoreError::TableAlreadyExists { .. }), "got: {err}");
        let renamed = c.rename_table(&d, "default", "t", "t2").await.unwrap();
        assert_eq!(renamed.name, "t2");
        assert!(c.get(&d, "default", "t").is_err());
        assert!(c.get(&d, "default", "t2").is_ok());
    }

    // 24. create_index_reserve/commit + drop_index: domain-wide unique names;
    //     missing table/column/index.
    #[tokio::test]
    async fn test_create_and_drop_index_validation() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id"), col("a")]))
            .await
            .unwrap();

        let err = c
            .create_index_reserve(&d, "default", "ghost", "idx", "a", false)
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");
        let err = c
            .create_index_reserve(&d, "default", "t", "idx", "ghost", false)
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::ColumnNotFound { .. }), "got: {err}");

        let (_dom, _schema, meta) = c
            .create_index_reserve(&d, "default", "t", "t_a_idx", "a", false)
            .await
            .unwrap();
        assert!(!meta.unique);
        c.create_index_commit(&d, "default", "t", meta).await.unwrap();

        let err = c
            .create_index_reserve(&d, "default", "t", "t_a_idx", "a", true)
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::IndexAlreadyExists { .. }), "got: {err}");

        let err = c.drop_index(&d, "default", "ghost_idx").await.unwrap_err();
        assert!(matches!(err, RelStoreError::IndexNotFound { .. }), "got: {err}");
        c.drop_index(&d, "default", "t_a_idx").await.unwrap();
        let err = c.drop_index(&d, "default", "t_a_idx").await.unwrap_err();
        assert!(matches!(err, RelStoreError::IndexNotFound { .. }), "got: {err}");
    }

    // 24b. The reserve→commit gap re-checks the name under ddl_lock: a
    //      same-named index committed in between fails at commit instead of
    //      producing a duplicate catalog entry.
    #[tokio::test]
    async fn test_create_index_commit_rechecks_name() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id"), col("a")]))
            .await
            .unwrap();

        let (_d1, _s1, m1) =
            c.create_index_reserve(&d, "default", "t", "dup", "a", false).await.unwrap();
        let (_d2, _s2, m2) =
            c.create_index_reserve(&d, "default", "t", "dup", "a", false).await.unwrap();
        c.create_index_commit(&d, "default", "t", m1).await.unwrap();

        let err = c.create_index_commit(&d, "default", "t", m2).await.unwrap_err();
        assert!(matches!(err, RelStoreError::IndexAlreadyExists { .. }), "got: {err}");
        let CatalogEntry::Table(t) = c.get(&d, "default", "t").unwrap() else {
            panic!("expected a table")
        };
        assert_eq!(t.indexes.len(), 1, "no duplicate index entry");
    }

    // 25. rename_column must not rewrite REFERENCES entries: they hold *table*
    //     names, and a column may share its name with a referenced table.
    #[tokio::test]
    async fn test_rename_column_keeps_references_target() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("parent", vec![pk_int("id")]))
            .await
            .unwrap();
        let mut fk = ColumnInput::new("parent", ColumnType::Integer);
        fk.references = Some("parent".to_string());
        c.create_table(&d, "default", table("child", vec![pk_int("id"), fk]))
            .await
            .unwrap();

        let schema = c
            .rename_column(&d, "default", "child", "parent", "daddy")
            .await
            .unwrap();
        let col = schema.columns.iter().find(|c| c.name == "daddy").unwrap();
        assert_eq!(
            col.references.as_deref(),
            Some("parent"),
            "REFERENCES must keep pointing at the table"
        );
    }

    // 26. drop_index refuses the implicit index backing a UNIQUE column
    //     constraint (v1: tied to the constraint, not freestanding).
    #[tokio::test]
    async fn test_drop_index_rejects_implicit_unique_index() {
        let (_e, d, c, _dir) = make_catalog().await;
        let schema = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), uniq("u")]))
            .await
            .unwrap();
        let implicit = schema.indexes[0].name.clone();

        let err = c.drop_index(&d, "default", &implicit).await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "got: {err}");
        let CatalogEntry::Table(t) = c.get(&d, "default", "t").unwrap() else {
            panic!("expected a table")
        };
        assert_eq!(t.indexes.len(), 1, "the implicit index must still exist");
    }

    // ── Prep work (spec quality/008): recover's tolerant skip paths ─────────────

    // 27. A CAT: key with no ':' after the prefix cannot be split into
    //     (system_prefix, name) -> skipped (tracing::warn), other entries
    //     recover normally.
    #[tokio::test]
    async fn test_recover_skips_unparseable_cat_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = make_engine(dir.path()).await;
        let domains = Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap());
        let metrics = MetricsStore::new(MetricsConfig::default());
        let catalog = RelCatalog::recover(Arc::clone(&engine), default_limits(), metrics)
            .await
            .unwrap();
        catalog
            .create_table(&domains, "default", table("good", vec![pk_int("id")]))
            .await
            .unwrap();

        let mut bad_key = CAT_PREFIX.to_vec();
        bad_key.extend_from_slice(b"nocolonhere");
        let entry = CatalogEntry::View(ViewSchema {
            name: "x".to_string(),
            sql: "SELECT 1".to_string(),
            created_at: 0,
        });
        engine.put(&bad_key, &serde_json::to_vec(&entry).unwrap()).await.unwrap();

        let metrics2 = MetricsStore::new(MetricsConfig::default());
        let recovered = RelCatalog::recover(Arc::clone(&engine), default_limits(), metrics2)
            .await
            .unwrap();
        assert!(matches!(
            recovered.get(&domains, "default", "good").unwrap(),
            CatalogEntry::Table(_)
        ));
        assert_eq!(
            recovered.list(&domains, "default").unwrap().len(),
            1,
            "the unparseable-key entry must not surface anywhere"
        );
    }

    // 28. A CAT: entry whose key parses fine but whose value is not valid
    //     CatalogEntry JSON -> skipped (tracing::warn), other entries recover
    //     normally.
    #[tokio::test]
    async fn test_recover_skips_corrupt_catalog_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = make_engine(dir.path()).await;
        let domains = Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap());
        let metrics = MetricsStore::new(MetricsConfig::default());
        let catalog = RelCatalog::recover(Arc::clone(&engine), default_limits(), metrics)
            .await
            .unwrap();
        catalog
            .create_table(&domains, "default", table("good", vec![pk_int("id")]))
            .await
            .unwrap();

        let dom = domains.require_active("default").unwrap();
        engine
            .put(&cat_key(&dom.system_prefix, "badentry"), b"not valid json")
            .await
            .unwrap();

        let metrics2 = MetricsStore::new(MetricsConfig::default());
        let recovered = RelCatalog::recover(Arc::clone(&engine), default_limits(), metrics2)
            .await
            .unwrap();
        assert!(matches!(
            recovered.get(&domains, "default", "good").unwrap(),
            CatalogEntry::Table(_)
        ));
        assert_eq!(
            recovered.list(&domains, "default").unwrap().len(),
            1,
            "the corrupt-JSON entry must not surface anywhere"
        );
    }

    // 29. A __sys:rel_catalog_seq: value that is not valid u32 JSON -> skipped,
    //     other domains' counters recover normally, recover() itself never fails.
    #[tokio::test]
    async fn test_recover_skips_corrupt_seq_value() {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = make_engine(dir.path()).await;
        let domains = Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap());
        domains.create_domain("gamma").await.unwrap();

        let metrics = MetricsStore::new(MetricsConfig::default());
        let catalog = RelCatalog::recover(Arc::clone(&engine), default_limits(), metrics)
            .await
            .unwrap();
        catalog
            .create_table(&domains, "default", table("t", vec![pk_int("id")]))
            .await
            .unwrap();
        engine.put(&seq_key("gamma"), b"not-a-number").await.unwrap();

        let metrics2 = MetricsStore::new(MetricsConfig::default());
        let recovered = RelCatalog::recover(Arc::clone(&engine), default_limits(), metrics2)
            .await
            .unwrap();
        let default_dom = domains.require_active("default").unwrap();
        let gamma_dom = domains.require_active("gamma").unwrap();
        assert_eq!(
            recovered.allocated_id_high_watermark(&default_dom),
            1,
            "the valid counter must survive"
        );
        assert_eq!(
            recovered.allocated_id_high_watermark(&gamma_dom),
            0,
            "the corrupt seq value must be skipped, not crash recover"
        );
    }

    // ── Prep work (spec quality/008): validate_columns/check_default error paths ─

    // 30. Two columns normalizing to the same name -> InvalidSchema("duplicate
    //     column ..."), before any other column check runs.
    #[tokio::test]
    async fn test_duplicate_column_rejected() {
        let (_e, d, c, _dir) = make_catalog().await;
        let err = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), col("dup"), col("dup")]))
            .await
            .unwrap_err();
        match &err {
            RelStoreError::InvalidSchema(msg) => {
                assert!(msg.contains("duplicate column"), "got: {msg}")
            }
            other => panic!("expected InvalidSchema, got: {other}"),
        }
    }

    // 31. check_default: a literal DEFAULT whose type does not match the
    //     column's type -> TypeMismatch.
    #[tokio::test]
    async fn test_default_type_mismatch_rejected() {
        let (_e, d, c, _dir) = make_catalog().await;
        let mut bad_default = col("a"); // Integer column
        bad_default.default = DefaultValue::Literal(ScalarValue::Text("x".to_string()));
        let err = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), bad_default]))
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TypeMismatch { .. }), "got: {err}");
    }

    // 32. check_default: DEFAULT CURRENT_TIMESTAMP on a non-Timestamp column
    //     -> InvalidSchema.
    #[tokio::test]
    async fn test_current_timestamp_default_requires_timestamp_column() {
        let (_e, d, c, _dir) = make_catalog().await;
        let mut bad_default = col("a"); // Integer column
        bad_default.default = DefaultValue::CurrentTimestamp;
        let err = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), bad_default]))
            .await
            .unwrap_err();
        match &err {
            RelStoreError::InvalidSchema(msg) => {
                assert!(msg.contains("CURRENT_TIMESTAMP"), "got: {msg}")
            }
            other => panic!("expected InvalidSchema, got: {other}"),
        }
    }

    // ── Fixes ───────────────────────────────────────────────────────────────────

    // 33. (013-F1) An index id is reserved across create_index_reserve→commit;
    //     a backfill abort (guard drop) frees it, and so does commit — the
    //     rel/013 orphan sweep queries is_id_reserved to spare the id meanwhile.
    #[tokio::test]
    async fn test_index_reservation_lifecycle() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_table(&d, "default", table("t", vec![pk_int("id"), col("a")]))
            .await
            .unwrap();
        let prefix = d.require_active("default").unwrap().system_prefix;

        let (_dom, _schema, meta) =
            c.create_index_reserve(&d, "default", "t", "idx", "a", false).await.unwrap();
        assert!(c.is_id_reserved(&prefix, meta.index_id), "reserved between reserve and commit");

        // A backfill abort: the ddl.rs guard's Drop frees the reservation.
        let guard = c.index_reservation_guard(&prefix, meta.index_id);
        drop(guard);
        assert!(!c.is_id_reserved(&prefix, meta.index_id), "freed after the guard drops");

        // A committed index frees its reservation even while a guard is held.
        let (_dom2, _s2, meta2) =
            c.create_index_reserve(&d, "default", "t", "idx2", "a", false).await.unwrap();
        let guard2 = c.index_reservation_guard(&prefix, meta2.index_id);
        let id2 = meta2.index_id;
        assert!(c.is_id_reserved(&prefix, id2));
        c.create_index_commit(&d, "default", "t", meta2).await.unwrap();
        assert!(!c.is_id_reserved(&prefix, id2), "commit frees the reservation");
        guard2.disarm();
    }

    // 34. (004 TOCTOU) drop_object_checked hands `check` the removed entry, so a
    //     DROP-TABLE-style guard rejects a view atomically under the ddl_lock
    //     and the view survives — the check-then-lock race can no longer delete
    //     the wrong kind. (This test cannot compile against the pre-fix
    //     closure, which never saw the removed entry.)
    #[tokio::test]
    async fn test_drop_object_checked_guards_kind_atomically() {
        let (_e, d, c, _dir) = make_catalog().await;
        c.create_view(&d, "default", "v", "SELECT 1").await.unwrap();

        let err = c
            .drop_object_checked(&d, "default", "v", |removed, _| match removed {
                CatalogEntry::Table(_) => Ok(()),
                CatalogEntry::View(_) => Err(RelStoreError::TableNotFound {
                    domain: "default".to_string(),
                    name: "v".to_string(),
                }),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");
        assert!(
            matches!(c.get(&d, "default", "v").unwrap(), CatalogEntry::View(_)),
            "the view must survive a rejected kind-mismatched drop"
        );
    }

    // 35. (003-F1) A lost/corrupt SEQ value must not let recovery reissue a
    //     live id: recover() floors the counter to the highest live id, so the
    //     next CREATE TABLE gets a fresh id, never colliding with existing rows.
    #[tokio::test]
    async fn test_seq_floor_survives_corrupt_seq_after_recover() {
        let (e, d, c, _dir) = make_catalog().await;
        let t1 = c.create_table(&d, "default", table("t", vec![pk_int("id")])).await.unwrap();
        assert_eq!(t1.table_id, 1);

        // Corrupt the persisted counter: scan_seq_counters skips it, dropping
        // the domain to 0 while its table_id=1 loads normally.
        e.put(&seq_key("default"), b"not-a-number").await.unwrap();

        let metrics = MetricsStore::new(MetricsConfig::default());
        let c2 = RelCatalog::recover(Arc::clone(&e), default_limits(), metrics).await.unwrap();
        let t2 = c2.create_table(&d, "default", table("u", vec![pk_int("id")])).await.unwrap();
        assert!(
            t2.table_id > t1.table_id,
            "new table_id {} must exceed the live {} (no id reuse)",
            t2.table_id,
            t1.table_id
        );
    }

    // 36. (004-F4) PRIMARY KEY UNIQUE on one column adds no redundant unique
    //     index (the PK is the row key) and consumes no extra index_id.
    #[tokio::test]
    async fn test_pk_unique_creates_no_index() {
        let (_e, d, c, _dir) = make_catalog().await;
        let mut id = pk_int("id");
        id.unique = true;
        let schema = c.create_table(&d, "default", table("t", vec![id])).await.unwrap();
        assert!(schema.indexes.is_empty(), "PRIMARY KEY UNIQUE must not add an implicit index");
        let dom = d.require_active("default").unwrap();
        assert_eq!(
            c.allocated_id_high_watermark(&dom),
            schema.table_id,
            "only the table_id is consumed, no index_id"
        );
    }

    // 37. (004-F5) A separately named explicit UNIQUE index on an already-UNIQUE
    //     column is droppable; only the implicit constraint index (t_e_key) is
    //     protected. Pre-fix, drop_index rejected the explicit one too.
    #[tokio::test]
    async fn test_drop_explicit_unique_index_on_unique_column() {
        let (_e, d, c, _dir) = make_catalog().await;
        let schema = c
            .create_table(&d, "default", table("t", vec![pk_int("id"), uniq("e")]))
            .await
            .unwrap();
        let implicit = schema.indexes[0].name.clone();
        assert_eq!(implicit, "t_e_key");

        let (_dom, _s, meta) =
            c.create_index_reserve(&d, "default", "t", "extra", "e", true).await.unwrap();
        c.create_index_commit(&d, "default", "t", meta).await.unwrap();

        c.drop_index(&d, "default", "extra").await.unwrap();
        let err = c.drop_index(&d, "default", &implicit).await.unwrap_err();
        assert!(matches!(err, RelStoreError::InvalidSchema(_)), "implicit index stays protected: {err}");
    }
}
