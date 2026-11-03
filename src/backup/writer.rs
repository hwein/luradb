//! Backup export pipeline: scope resolution, one consistent cut per engine
//! across the data shards, and the NDJSON writer (manifest -> kv-domains ->
//! kv-pairs -> json-domains -> index-definitions -> docs -> rel-domains ->
//! tables -> views -> rows -> auth -> checksum).

use super::{BackupError, BackupScope};
use crate::auth::{DomainPermission, UserRecord, PREFIX_PERM, PREFIX_USER};
use crate::control::{ControlPlane, Cut, DomainEntry, Engine, Lifecycle};
use crate::core::coop::YieldEvery;
use crate::engines::json::IndexFieldType;
use crate::engines::lsm::domain::now_secs;
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::{GetResult, Snapshot};
use crate::engines::rel::{CatalogEntry, ColumnDef, DefaultValue, ScalarValue, TableSchema};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use crate::core::engine_runtime::{self, spawn_io};
use std::path::Path;
use std::sync::Arc;

/// Version 2 adds `shards` and `lsn_cut` to the manifest.
pub(crate) const FORMAT_VERSION: u32 = 2;

/// Whether restore reads archives of `format_version`.
pub(crate) fn is_supported_format(format_version: u32) -> bool {
    (1..=FORMAT_VERSION).contains(&format_version)
}

/// Keys exported between two yields.
const EXPORT_KEY_YIELD_INTERVAL: u32 = 1024;

/// The first line of an archive. Fields a version 1 archive lacks read as 0.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ManifestLine {
    pub t: String,
    pub format_version: u32,
    pub id: String,
    pub created_at: u64,
    pub luradb_version: String,
    pub scope: String,
    pub include_auth: bool,
    /// The newest read-snapshot stamp among the data shards.
    pub kv_snapshot_ts: u64,
    pub json_snapshot_ts: u64,
    #[serde(default)]
    pub rel_snapshot_ts: u64,
    pub encoding: String,
    pub schedule: Option<String>,
    /// Data shards of the server that wrote the archive; restore ignores it.
    #[serde(default)]
    pub shards: u16,
    #[serde(default)]
    pub lsn_cut: LsnCut,
}

/// Per engine, the write-ahead-log position every write of the archive is at
/// or below; 0 for an engine outside the scope.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LsnCut {
    pub kv: u64,
    pub json: u64,
    #[serde(default)]
    pub rel: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct KvDomainLine {
    pub t: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct KvLine {
    pub t: String,
    pub domain: String,
    pub k: String,
    pub v: Option<String>,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonDomainLine {
    pub t: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JsonIndexLine {
    pub t: String,
    pub domain: String,
    pub field: String,
    pub field_type: IndexFieldType,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DocLine {
    pub t: String,
    pub domain: String,
    pub key: String,
    pub version: u64,
    pub content: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelDomainLine {
    pub t: String,
    pub name: String,
    pub created_at: u64,
}

/// A table's schema in the archive's own form: no internal ids, types by SQL
/// name, every index under its stored name.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelTableLine {
    pub t: String,
    pub domain: String,
    pub name: String,
    pub columns: Vec<RelColumn>,
    pub indexes: Vec<RelIndex>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
    pub nullable: bool,
    pub primary_key: bool,
    pub autoincrement: bool,
    pub unique: bool,
    /// Absent: no default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<RelDefault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RelDefault {
    Null,
    CurrentTimestamp,
    Literal { value: Value },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelIndex {
    pub name: String,
    pub column: String,
    pub unique: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelViewLine {
    pub t: String,
    pub domain: String,
    pub name: String,
    pub sql: String,
}

/// One row, every column of the table by name.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelRowLine {
    pub t: String,
    pub domain: String,
    pub table: String,
    pub row: Map<String, Value>,
}

/// The AUTOINCREMENT high-water mark of a table: the next insert without a
/// key gets `hw + 1`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RelSeqLine {
    pub t: String,
    pub domain: String,
    pub table: String,
    pub hw: u64,
}

impl RelTableLine {
    fn new(domain: &str, schema: &TableSchema) -> Self {
        Self {
            t: "rel-table".to_string(),
            domain: domain.to_string(),
            name: schema.name.clone(),
            columns: schema.columns.iter().map(RelColumn::new).collect(),
            indexes: schema
                .indexes
                .iter()
                .map(|ix| RelIndex { name: ix.name.clone(), column: ix.column.clone(), unique: ix.unique })
                .collect(),
        }
    }
}

impl RelColumn {
    fn new(c: &ColumnDef) -> Self {
        let default = match &c.default {
            DefaultValue::None => None,
            DefaultValue::Null => Some(RelDefault::Null),
            DefaultValue::CurrentTimestamp => Some(RelDefault::CurrentTimestamp),
            DefaultValue::Literal(v) => Some(RelDefault::Literal { value: rel_value(v) }),
        };
        Self {
            name: c.name.clone(),
            col_type: c.col_type.sql_name().to_string(),
            nullable: c.nullable,
            primary_key: c.primary_key,
            autoincrement: c.autoincrement,
            unique: c.unique,
            default,
            references: c.references.clone(),
        }
    }
}

/// A relational value as the archive holds it; TIMESTAMP as integer
/// milliseconds, which covers its whole range.
pub(crate) fn rel_value(v: &ScalarValue) -> Value {
    match v {
        ScalarValue::Integer(i) | ScalarValue::Timestamp(i) => Value::from(*i),
        ScalarValue::Real(f) => Value::from(*f),
        ScalarValue::Text(s) => Value::from(s.clone()),
        ScalarValue::Boolean(b) => Value::from(*b),
        ScalarValue::Null => Value::Null,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ChecksumLine {
    pub t: String,
    pub sha256: String,
    pub lines: u64,
}

#[derive(Serialize)]
struct AuthUserLine<'a> {
    t: &'static str,
    #[serde(flatten)]
    record: &'a UserRecord,
}

#[derive(Serialize)]
struct AuthPermLine<'a> {
    t: &'static str,
    #[serde(flatten)]
    perm: &'a DomainPermission,
}

/// The concrete domains a scope resolves to, from the directory of every
/// data shard, each engine's in name order and only `Active` ones. Either
/// list can be empty for any scope — every domain of an engine may be
/// deleted at runtime — and only means there is no *domain* data to export;
/// auth records live outside any domain and still need the KV cut.
#[derive(Debug, Default)]
pub(crate) struct ResolvedScope {
    pub kv_domains: Vec<DomainEntry>,
    pub json_domains: Vec<DomainEntry>,
    pub rel_domains: Vec<DomainEntry>,
}

/// A disabled engine has no domain in the directory, so `all` and
/// `domain:<name>` leave it out on their own.
pub(crate) fn resolve_scope(scope: &BackupScope, control: &ControlPlane) -> Result<ResolvedScope, BackupError> {
    let directory = control.directory();
    let json_enabled = control.shard_owners().any(|owners| owners.json.is_some());
    let rel_enabled = control.shard_owners().any(|owners| owners.rel.is_some());
    let all = |engine| -> Vec<DomainEntry> {
        directory.domains(engine).filter(|d| d.state == Lifecycle::Active).cloned().collect()
    };
    let one = |engine, name: &str| directory.get(engine, name).filter(|d| d.state == Lifecycle::Active).cloned();
    let not_found = |name: &String| BackupError::DomainNotFound(name.clone());
    match scope {
        BackupScope::All => Ok(ResolvedScope {
            kv_domains: all(Engine::Kv),
            json_domains: all(Engine::Json),
            rel_domains: all(Engine::Rel),
        }),
        BackupScope::Kv => Ok(ResolvedScope { kv_domains: all(Engine::Kv), ..ResolvedScope::default() }),
        BackupScope::Json => {
            if !json_enabled {
                return Err(BackupError::JsonEngineDisabled);
            }
            Ok(ResolvedScope { json_domains: all(Engine::Json), ..ResolvedScope::default() })
        }
        BackupScope::Rel => {
            if !rel_enabled {
                return Err(BackupError::RelEngineDisabled);
            }
            Ok(ResolvedScope { rel_domains: all(Engine::Rel), ..ResolvedScope::default() })
        }
        BackupScope::KvDomain(name) => {
            let d = one(Engine::Kv, name).ok_or_else(|| not_found(name))?;
            Ok(ResolvedScope { kv_domains: vec![d], ..ResolvedScope::default() })
        }
        BackupScope::JsonDomain(name) => {
            if !json_enabled {
                return Err(BackupError::JsonEngineDisabled);
            }
            let d = one(Engine::Json, name).ok_or_else(|| not_found(name))?;
            Ok(ResolvedScope { json_domains: vec![d], ..ResolvedScope::default() })
        }
        BackupScope::RelDomain(name) => {
            if !rel_enabled {
                return Err(BackupError::RelEngineDisabled);
            }
            let d = one(Engine::Rel, name).ok_or_else(|| not_found(name))?;
            Ok(ResolvedScope { rel_domains: vec![d], ..ResolvedScope::default() })
        }
        BackupScope::Domain(name) => {
            let resolved = ResolvedScope {
                kv_domains: one(Engine::Kv, name).into_iter().collect(),
                json_domains: one(Engine::Json, name).into_iter().collect(),
                rel_domains: one(Engine::Rel, name).into_iter().collect(),
            };
            if resolved.kv_domains.is_empty() && resolved.json_domains.is_empty() && resolved.rel_domains.is_empty() {
                return Err(not_found(name));
            }
            Ok(resolved)
        }
    }
}

pub(crate) struct BackupParams<'a> {
    pub dir: &'a Path,
    pub id: &'a str,
    pub scope: &'a BackupScope,
    pub include_auth: bool,
    pub schedule: Option<&'a str>,
    pub resolved: &'a ResolvedScope,
    /// Takes the cuts; each domain is read on the instance of its owner, the
    /// auth records on the system store.
    pub control: &'a ControlPlane,
    pub scan_batch_size: usize,
    pub scan_pause_ms: u64,
}

/// Runs the full export: `<id>.ndjson.part` -> fsync -> rename to
/// `<id>.ndjson` -> fsync of the directory. On any error the `.part` file is
/// removed and the error propagates for
/// the caller to log.
pub(crate) async fn run_backup(params: BackupParams<'_>) -> anyhow::Result<()> {
    let part_path = params.dir.join(format!("{}.ndjson.part", params.id));
    let final_path = params.dir.join(format!("{}.ndjson", params.id));

    match write_backup_file(&part_path, &params).await {
        Ok(()) => {
            let dir = params.dir.to_path_buf();
            spawn_io(async move {
                compio::fs::rename(&part_path, &final_path).await?;
                // The rename must be durable too: success here lets retention
                // delete an older generation right away.
                compio::fs::File::open(&dir).await?.sync_all().await
            })
            .await?;
            Ok(())
        }
        Err(e) => {
            let _ = spawn_io(async move { compio::fs::remove_file(part_path).await }).await;
            Err(e)
        }
    }
}

/// The `.part` file, appended to through a buffer on the engine ring.
struct PartFile {
    file: Arc<std::fs::File>,
    buf: Vec<u8>,
    pos: u64,
}

/// Bytes buffered before they go out as one write.
const PART_BUFFER: usize = 8 * 1024;

impl PartFile {
    async fn create(path: &Path) -> std::io::Result<Self> {
        let mut options = compio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let file = engine_runtime::open(path.to_path_buf(), options).await?;
        Ok(Self { file: Arc::new(file), buf: Vec::with_capacity(PART_BUFFER), pos: 0 })
    }

    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() >= PART_BUFFER {
            self.flush().await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        let data = std::mem::replace(&mut self.buf, Vec::with_capacity(PART_BUFFER));
        let len = data.len() as u64;
        engine_runtime::write_all_at(&self.file, data, self.pos).await?;
        self.pos += len;
        Ok(())
    }

    async fn sync_all(&self) -> std::io::Result<()> {
        engine_runtime::sync(&self.file, false).await
    }
}

async fn write_backup_file(part_path: &Path, params: &BackupParams<'_>) -> anyhow::Result<()> {
    // include_auth only ever applies to all/kv -- other scopes silently
    // ignore the flag.
    let export_auth = params.include_auth && matches!(params.scope, BackupScope::All | BackupScope::Kv);

    // One cut per engine, held for the whole export so compaction keeps every
    // version it reads; it holds back no write. `None` when that engine has
    // nothing to export in this scope. The auth records come from the system
    // store as of the KV cut. The relational cut comes first: a link that
    // exists in it then finds its target in the later ones.
    let rel_cut = if !params.resolved.rel_domains.is_empty() {
        Some(params.control.consistent_cut(Engine::Rel).await?)
    } else {
        None
    };
    let kv_cut = if !params.resolved.kv_domains.is_empty() || export_auth {
        Some(params.control.consistent_cut(Engine::Kv).await?)
    } else {
        None
    };
    let json_cut = if !params.resolved.json_domains.is_empty() {
        Some(params.control.consistent_cut(Engine::Json).await?)
    } else {
        None
    };

    let mut out = PartFile::create(part_path).await?;
    let mut hasher = Sha256::new();
    let mut lines: u64 = 0;

    let manifest = ManifestLine {
        t: "manifest".to_string(),
        format_version: FORMAT_VERSION,
        id: params.id.to_string(),
        created_at: now_secs(),
        luradb_version: env!("CARGO_PKG_VERSION").to_string(),
        scope: params.scope.as_string(),
        include_auth: export_auth,
        kv_snapshot_ts: kv_cut.as_ref().map_or(0, Cut::max_stamp),
        json_snapshot_ts: json_cut.as_ref().map_or(0, Cut::max_stamp),
        rel_snapshot_ts: rel_cut.as_ref().map_or(0, Cut::max_stamp),
        encoding: "hex".to_string(),
        schedule: params.schedule.map(|s| s.to_string()),
        shards: params.control.shard_count(),
        lsn_cut: LsnCut {
            kv: kv_cut.as_ref().map_or(0, |cut| cut.s),
            json: json_cut.as_ref().map_or(0, |cut| cut.s),
            rel: rel_cut.as_ref().map_or(0, |cut| cut.s),
        },
    };
    write_line(&mut out, &mut hasher, &mut lines, &manifest).await?;

    // Binding section order: kv sections, then json sections, then rel
    // sections, then auth, then the checksum line.
    if let Some(cut) = &kv_cut {
        write_kv_section(&mut out, &mut hasher, &mut lines, params, cut).await?;
    }

    if let Some(cut) = &json_cut {
        write_json_section(&mut out, &mut hasher, &mut lines, params, cut).await?;
    }

    if let Some(cut) = &rel_cut {
        write_rel_section(&mut out, &mut hasher, &mut lines, params, cut).await?;
    }

    if let (true, Some(cut)) = (export_auth, &kv_cut) {
        write_auth_section(&mut out, &mut hasher, &mut lines, params.control.system_store(), cut.system.snapshot())
            .await?;
    }

    let sha256 = hex::encode(hasher.finalize());
    let checksum_bytes = serde_json::to_vec(&ChecksumLine { t: "checksum".to_string(), sha256, lines })?;
    out.write_all(&checksum_bytes).await?;
    out.write_all(b"\n").await?;

    out.flush().await?;
    out.sync_all().await?;
    Ok(())
}

async fn write_kv_section(
    out: &mut PartFile,
    hasher: &mut Sha256,
    lines: &mut u64,
    params: &BackupParams<'_>,
    cut: &Cut,
) -> anyhow::Result<()> {
    for domain in &params.resolved.kv_domains {
        write_line(
            out,
            hasher,
            lines,
            &KvDomainLine { t: "kv-domain".to_string(), name: domain.name.clone(), created_at: domain.created_at },
        )
        .await?;

        let snapshot = cut.read_of(params.control.shard_of(&domain.name));
        let store = params.control.owners_of(&domain.name).kv.store(&domain.name).await?;
        let keys = store.scan_keys_with_snapshot(b"", snapshot).await?;
        let mut coop = YieldEvery::new(EXPORT_KEY_YIELD_INTERVAL);
        for (i, key) in keys.iter().enumerate() {
            coop.tick().await;
            let (result, expires_at) = store.get_with_snapshot(key, snapshot).await?;
            let v = match result {
                GetResult::Present(bytes) => Some(hex::encode(bytes)),
                GetResult::Null => None,
                // Raced away between the scan and the read despite the
                // shared snapshot -- should not happen, skip defensively.
                GetResult::Absent => continue,
            };
            write_line(
                out,
                hasher,
                lines,
                &KvLine { t: "kv".to_string(), domain: domain.name.clone(), k: hex::encode(key), v, expires_at },
            )
            .await?;
            maybe_pause(i, params.scan_batch_size, params.scan_pause_ms).await;
        }
    }
    Ok(())
}

/// Exports the auth records of the system store as of `snapshot`.
async fn write_auth_section(
    out: &mut PartFile,
    hasher: &mut Sha256,
    lines: &mut u64,
    engine: &LsmStorageEngine,
    snapshot: &Snapshot,
) -> anyhow::Result<()> {
    let mut coop = YieldEvery::new(EXPORT_KEY_YIELD_INTERVAL);
    let user_keys = engine.scan_keys_with_snapshot(PREFIX_USER.as_bytes(), snapshot).await?;
    for key in &user_keys {
        coop.tick().await;
        let (result, _) = engine.get_with_expiry(key, snapshot).await?;
        if let GetResult::Present(bytes) = result {
            let record: UserRecord = serde_json::from_slice(&bytes)?;
            write_line(out, hasher, lines, &AuthUserLine { t: "auth-user", record: &record }).await?;
        }
    }

    let perm_keys = engine.scan_keys_with_snapshot(PREFIX_PERM.as_bytes(), snapshot).await?;
    for key in &perm_keys {
        coop.tick().await;
        let (result, _) = engine.get_with_expiry(key, snapshot).await?;
        if let GetResult::Present(bytes) = result {
            let perm: DomainPermission = serde_json::from_slice(&bytes)?;
            write_line(out, hasher, lines, &AuthPermLine { t: "auth-perm", perm: &perm }).await?;
        }
    }
    Ok(())
}

async fn write_json_section(
    out: &mut PartFile,
    hasher: &mut Sha256,
    lines: &mut u64,
    params: &BackupParams<'_>,
    cut: &Cut,
) -> anyhow::Result<()> {
    for domain in &params.resolved.json_domains {
        write_line(
            out,
            hasher,
            lines,
            &JsonDomainLine { t: "json-domain".to_string(), name: domain.name.clone(), created_at: domain.created_at },
        )
        .await?;

        let snapshot = cut.read_of(params.control.shard_of(&domain.name));
        let json = params.control.owners_of(&domain.name).json.as_ref().context("the JSON engine is disabled")?;
        for def in json.get_indexes_with_snapshot(&domain.name, snapshot).await? {
            write_line(
                out,
                hasher,
                lines,
                &JsonIndexLine {
                    t: "json-index".to_string(),
                    domain: domain.name.clone(),
                    field: def.field,
                    field_type: def.field_type,
                },
            )
            .await?;
        }

        let keys = json.scan_document_keys_with_snapshot(&domain.name, snapshot).await?;
        let mut coop = YieldEvery::new(EXPORT_KEY_YIELD_INTERVAL);
        for (i, key) in keys.iter().enumerate() {
            coop.tick().await;
            if let Some(doc) = json.get_document_with_snapshot(&domain.name, key, snapshot).await? {
                write_line(
                    out,
                    hasher,
                    lines,
                    &DocLine {
                        t: "doc".to_string(),
                        domain: domain.name.clone(),
                        key: doc.key,
                        version: doc.version,
                        content: doc.content,
                    },
                )
                .await?;
            }
            maybe_pause(i, params.scan_batch_size, params.scan_pause_ms).await;
        }
    }
    Ok(())
}

/// Per relational domain: the domain, its tables by id, its views by creation
/// (then name), then per table its rows in key order and, with an
/// AUTOINCREMENT column, its high-water mark.
async fn write_rel_section(
    out: &mut PartFile,
    hasher: &mut Sha256,
    lines: &mut u64,
    params: &BackupParams<'_>,
    cut: &Cut,
) -> anyhow::Result<()> {
    for domain in &params.resolved.rel_domains {
        let name = &domain.name;
        write_line(
            out,
            hasher,
            lines,
            &RelDomainLine { t: "rel-domain".to_string(), name: name.clone(), created_at: domain.created_at },
        )
        .await?;

        let snapshot = cut.read_of(params.control.shard_of(name));
        let rel = params.control.owners_of(name).rel.as_ref().context("the relational engine is disabled")?;
        let mut tables = Vec::new();
        let mut views = Vec::new();
        for entry in rel.catalog_at(name, snapshot).await? {
            match entry {
                CatalogEntry::Table(t) => tables.push(t),
                CatalogEntry::View(v) => views.push(v),
            }
        }
        tables.sort_by_key(|t| t.table_id);
        views.sort_by(|a, b| (a.created_at, &a.name).cmp(&(b.created_at, &b.name)));

        for table in &tables {
            write_line(out, hasher, lines, &RelTableLine::new(name, table)).await?;
        }
        for view in views {
            let line = RelViewLine { t: "rel-view".to_string(), domain: name.clone(), name: view.name, sql: view.sql };
            write_line(out, hasher, lines, &line).await?;
        }

        let mut coop = YieldEvery::new(EXPORT_KEY_YIELD_INTERVAL);
        for table in &tables {
            let mut scan = rel.rows_at(name, table, snapshot).await?;
            let mut i = 0;
            loop {
                let group = scan.next_group(params.scan_batch_size).await?;
                if group.is_empty() {
                    break;
                }
                for values in group {
                    coop.tick().await;
                    let row = table.columns.iter().zip(&values).map(|(c, v)| (c.name.clone(), rel_value(v))).collect();
                    let line =
                        RelRowLine { t: "rel-row".to_string(), domain: name.clone(), table: table.name.clone(), row };
                    write_line(out, hasher, lines, &line).await?;
                    maybe_pause(i, params.scan_batch_size, params.scan_pause_ms).await;
                    i += 1;
                }
            }
            if table.columns.iter().any(|c| c.autoincrement) {
                let hw = rel.autoincrement_hw_at(name, table.table_id, snapshot).await?;
                let line = RelSeqLine { t: "rel-seq".to_string(), domain: name.clone(), table: table.name.clone(), hw };
                write_line(out, hasher, lines, &line).await?;
            }
        }
    }
    Ok(())
}

/// Serializes one line, appends `\n`, writes it, and feeds the exact bytes,
/// including the trailing newline, into the running checksum.
async fn write_line(
    out: &mut PartFile,
    hasher: &mut Sha256,
    lines: &mut u64,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    out.write_all(&bytes).await?;
    hasher.update(&bytes);
    *lines += 1;
    Ok(())
}

pub(crate) async fn maybe_pause(i: usize, batch_size: usize, pause_ms: u64) {
    if batch_size > 0 && (i + 1).is_multiple_of(batch_size) {
        compio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JsonStoreConfig;
    use crate::control::{slots, testing};
    use crate::engines::json::JsonEngine;
    use crate::engines::lsm::domain::{fnv64, DomainRegistry};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use serde_json::json;

    /// A control plane over one data shard with a key-value engine and, when
    /// asked for, a JSON engine; its system store holds the auth records.
    struct Fixture {
        control: Arc<ControlPlane>,
        kv: Arc<DomainRegistry>,
        json: Option<Arc<JsonEngine>>,
        _dir: tempfile::TempDir,
    }

    async fn fixture(with_json: bool) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let kv = testing::kv_registry(dir.path()).await;
        let json = if with_json { Some(json_engine(dir.path()).await) } else { None };
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(16, 16));
        let (control, _) = testing::start(dir.path(), Arc::clone(&kv), json.clone(), None, bus).await;
        Fixture { control, kv, json, _dir: dir }
    }

    async fn json_engine(dir: &Path) -> Arc<JsonEngine> {
        let config = JsonStoreConfig {
            wal_path: dir.join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.join("json_sstables").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        };
        let metrics = MetricsStore::new(MetricsConfig::default());
        JsonEngine::bootstrap(&config, metrics).await.unwrap()
    }

    impl Fixture {
        async fn create(&self, engine: Engine, name: &str) {
            self.control.create_domain(engine, name, false).await.unwrap();
        }

        fn json(&self) -> &Arc<JsonEngine> {
            self.json.as_ref().unwrap()
        }
    }

    /// Backs `scope` up from `control` into `out` as `id`, unthrottled.
    async fn backup(control: &ControlPlane, out: &Path, id: &str, scope: BackupScope, include_auth: bool) {
        let resolved = resolve_scope(&scope, control).unwrap();
        let params = BackupParams {
            dir: out,
            id,
            scope: &scope,
            include_auth,
            schedule: None,
            resolved: &resolved,
            control,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();
    }

    fn manifest_of(content: &str) -> ManifestLine {
        serde_json::from_str(content.lines().next().unwrap()).unwrap()
    }

    // A version 2 manifest reads back as written; one of version 1, without
    // the fields version 2 added, still reads, with zero shards and a zero
    // LSN cut, and both versions are restorable.
    #[test]
    fn a_v2_manifest_round_trips_and_a_v1_manifest_still_reads() {
        let manifest = ManifestLine {
            t: "manifest".to_string(),
            format_version: FORMAT_VERSION,
            id: "bk_x".to_string(),
            created_at: 1_700_000_000,
            luradb_version: "0.0.0".to_string(),
            scope: "all".to_string(),
            include_auth: true,
            kv_snapshot_ts: 7,
            json_snapshot_ts: 9,
            rel_snapshot_ts: 11,
            encoding: "hex".to_string(),
            schedule: Some("nightly".to_string()),
            shards: 3,
            lsn_cut: LsnCut { kv: 41, json: 12, rel: 5 },
        };
        let line = serde_json::to_string(&manifest).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["format_version"], json!(2));
        assert_eq!(value["shards"], json!(3));
        assert_eq!(value["lsn_cut"], json!({"kv": 41, "json": 12, "rel": 5}));
        assert_eq!(value["rel_snapshot_ts"], json!(11));
        let back: ManifestLine = serde_json::from_str(&line).unwrap();
        assert_eq!((back.shards, back.lsn_cut), (3, LsnCut { kv: 41, json: 12, rel: 5 }));
        assert_eq!((back.kv_snapshot_ts, back.json_snapshot_ts, back.schedule.as_deref()), (7, 9, Some("nightly")));

        // A version 2 manifest written before relational data was archived.
        let v2 = json!({
            "t": "manifest", "format_version": 2, "id": "bk_v2", "created_at": 1, "luradb_version": "0.5.0",
            "scope": "all", "include_auth": false, "kv_snapshot_ts": 5, "json_snapshot_ts": 6, "encoding": "hex",
            "schedule": null, "shards": 2, "lsn_cut": {"kv": 3, "json": 4},
        });
        let older: ManifestLine = serde_json::from_value(v2).unwrap();
        assert_eq!((older.rel_snapshot_ts, older.lsn_cut), (0, LsnCut { kv: 3, json: 4, rel: 0 }));

        let v1 = json!({
            "t": "manifest", "format_version": 1, "id": "bk_old", "created_at": 1, "luradb_version": "0.4.0",
            "scope": "kv", "include_auth": false, "kv_snapshot_ts": 5, "json_snapshot_ts": 0, "encoding": "hex",
            "schedule": null,
        });
        let old: ManifestLine = serde_json::from_value(v1).unwrap();
        assert_eq!((old.format_version, old.kv_snapshot_ts, old.shards, old.lsn_cut), (1, 5, 0, LsnCut::default()));
        assert_eq!([0, 1, 2, 3].map(is_supported_format), [false, true, true, false]);
    }

    // 1. resolve_scope: `all` picks up every active KV domain.
    #[test]
    fn test_resolve_all_scope_kv_only() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            fx.create(Engine::Kv, "shop").await;
            let resolved = resolve_scope(&BackupScope::All, &fx.control).unwrap();
            let names: Vec<_> = resolved.kv_domains.iter().map(|d| d.name.clone()).collect();
            assert_eq!(names, ["default", "shop"]);
            assert!(resolved.json_domains.is_empty(), "no json engine given");
        })
    }

    // 2. resolve_scope: kv:<domain> on a missing domain -> DomainNotFound.
    #[test]
    fn test_resolve_kv_domain_missing_errors() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            let err = resolve_scope(&BackupScope::KvDomain("nope".to_string()), &fx.control).unwrap_err();
            assert!(matches!(err, BackupError::DomainNotFound(d) if d == "nope"));
        })
    }

    // 3. resolve_scope: json/json:<domain> with no JSON engine -> JsonEngineDisabled.
    #[test]
    fn test_resolve_json_scope_without_engine_errors() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            let err = resolve_scope(&BackupScope::Json, &fx.control).unwrap_err();
            assert!(matches!(err, BackupError::JsonEngineDisabled));
            let err = resolve_scope(&BackupScope::JsonDomain("x".to_string()), &fx.control).unwrap_err();
            assert!(matches!(err, BackupError::JsonEngineDisabled));
        })
    }

    // 4. resolve_scope: domain:<name> present in only one engine backs up only that one.
    #[test]
    fn test_resolve_domain_scope_single_engine() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(true).await;
            fx.create(Engine::Kv, "only-kv").await;
            let resolved = resolve_scope(&BackupScope::Domain("only-kv".to_string()), &fx.control).unwrap();
            assert_eq!(resolved.kv_domains.len(), 1);
            assert!(resolved.json_domains.is_empty());
        })
    }

    // 5. resolve_scope: domain:<name> missing in both engines -> DomainNotFound.
    #[test]
    fn test_resolve_domain_scope_missing_everywhere() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(true).await;
            let err = resolve_scope(&BackupScope::Domain("nope".to_string()), &fx.control).unwrap_err();
            assert!(matches!(err, BackupError::DomainNotFound(_)));
        })
    }

    // 6. run_backup: kv-only roundtrip produces a well-formed, checksummed
    //    NDJSON file with the expected line shapes and section order, under
    //    a version 2 manifest that names the shard count and the cut.
    #[test]
    fn test_run_backup_kv_only_writes_valid_ndjson() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            fx.create(Engine::Kv, "shop").await;
            let store = fx.kv.store("shop").await.unwrap();
            store.put(b"order:1", b"hello").await.unwrap();
            store.put_with_ttl(b"session", b"tok", 3600).await.unwrap();
            store.set_null(b"nulled").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_test", BackupScope::KvDomain("shop".to_string()), false).await;

            let content = std::fs::read_to_string(out_dir.path().join("bk_test.ndjson")).unwrap();
            assert!(!out_dir.path().join("bk_test.ndjson.part").exists());
            let raw_lines: Vec<&str> = content.lines().collect();
            // manifest + kv-domain + 3 kv pairs (order:1, session, nulled) + checksum.
            assert_eq!(raw_lines.len(), 6);

            let manifest: ManifestLine = serde_json::from_str(raw_lines[0]).unwrap();
            assert_eq!(manifest.t, "manifest");
            assert_eq!(manifest.format_version, 2);
            assert_eq!(manifest.scope, "kv:shop");
            assert_eq!(manifest.encoding, "hex");
            assert_eq!(manifest.shards, 1);
            assert!(manifest.lsn_cut.kv >= 3, "three writes are in the log: {:?}", manifest.lsn_cut);
            assert_eq!(manifest.lsn_cut.json, 0, "no JSON domain in the scope");
            assert!(manifest.kv_snapshot_ts > 0);

            let dom: KvDomainLine = serde_json::from_str(raw_lines[1]).unwrap();
            assert_eq!(dom.name, "shop");

            let kv_lines: Vec<KvLine> = raw_lines[2..5].iter().map(|l| serde_json::from_str(l).unwrap()).collect();
            let by_key: std::collections::HashMap<String, KvLine> =
                kv_lines.into_iter().map(|l| (String::from_utf8(hex::decode(&l.k).unwrap()).unwrap(), l)).collect();

            let order = &by_key["order:1"];
            assert_eq!(String::from_utf8(hex::decode(order.v.as_ref().unwrap()).unwrap()).unwrap(), "hello");
            assert_eq!(order.expires_at, 0);

            let session = &by_key["session"];
            assert!(session.expires_at > now_secs());

            let nulled = &by_key["nulled"];
            assert!(nulled.v.is_none(), "set_null must round-trip as v:null");

            let checksum: ChecksumLine = serde_json::from_str(raw_lines[5]).unwrap();
            assert_eq!(checksum.lines, 5);
        })
    }

    // 7. Snapshot consistency: a write committed after run_backup has
    //    already taken its cut (but is still mid-export) must not appear in
    //    the output. Uses scan_batch_size=1 + a real pause to open a window
    //    mid-export in which a concurrent write is injected.
    #[test]
    fn test_run_backup_snapshot_excludes_writes_during_export() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            fx.create(Engine::Kv, "shop").await;
            let store = fx.kv.store("shop").await.unwrap();
            store.put(b"a1", b"v1").await.unwrap();
            store.put(b"a2", b"v2").await.unwrap();

            let resolved = resolve_scope(&BackupScope::KvDomain("shop".to_string()), &fx.control).unwrap();
            let out_dir = tempfile::TempDir::new().unwrap();
            let out_path = out_dir.path().to_path_buf();
            let control = Arc::clone(&fx.control);

            let backup_task = compio::runtime::spawn(async move {
                let scope = BackupScope::KvDomain("shop".to_string());
                let params = BackupParams {
                    dir: &out_path,
                    id: "bk_snap",
                    scope: &scope,
                    include_auth: false,
                    schedule: None,
                    resolved: &resolved,
                    control: &control,
                    scan_batch_size: 1,
                    scan_pause_ms: 300,
                };
                run_backup(params).await.unwrap();
            });

            // Let the job take its cut and enter its first pause window.
            compio::time::sleep(std::time::Duration::from_millis(100)).await;
            store.put(b"after", b"v3").await.unwrap();
            backup_task.await.unwrap();

            let content = std::fs::read_to_string(out_dir.path().join("bk_snap.ndjson")).unwrap();
            let exported_keys: std::collections::HashSet<String> = content
                .lines()
                .filter_map(|l| serde_json::from_str::<KvLine>(l).ok())
                .map(|l| String::from_utf8(hex::decode(&l.k).unwrap()).unwrap())
                .collect();
            assert!(exported_keys.contains("a1") && exported_keys.contains("a2"));
            assert!(!exported_keys.contains("after"), "a write during the export must not leak into the snapshot");
        })
    }

    // 8. include_auth is only effective for all/kv scopes.
    #[test]
    fn test_include_auth_ignored_for_domain_scope() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            fx.create(Engine::Kv, "shop").await;
            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_authflag", BackupScope::KvDomain("shop".to_string()), true).await;
            let content = std::fs::read_to_string(out_dir.path().join("bk_authflag.ndjson")).unwrap();
            assert!(!manifest_of(&content).include_auth, "kv:<domain> must not export auth even if requested");
        })
    }

    // 8b. include_auth=true on an all/kv scope does export auth-user/auth-perm
    //     lines, with the UserRecord/DomainPermission fields intact.
    #[test]
    fn test_backup_include_auth_true_exports_auth_lines() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            let engine = fx.control.system_store();
            let record = UserRecord {
                name: "carol".to_string(),
                api_key_hash: "abc123".to_string(),
                role: crate::auth::UserRole::Admin,
                created_at: 1_700_000_000,
            };
            engine.put(b"__sys:auth:user:carol", &serde_json::to_vec(&record).unwrap()).await.unwrap();
            let perm = DomainPermission {
                username: "carol".to_string(),
                domain: "shop".to_string(),
                access: crate::auth::AccessLevel::Write,
            };
            engine
                .put(format!("{PREFIX_PERM}carol:shop").as_bytes(), &serde_json::to_vec(&perm).unwrap())
                .await
                .unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_authtrue", BackupScope::All, true).await;

            let content = std::fs::read_to_string(out_dir.path().join("bk_authtrue.ndjson")).unwrap();
            assert!(manifest_of(&content).include_auth);

            let user_line = content.lines().find(|l| l.contains("\"auth-user\"")).expect("auth-user line must be present");
            let restored: UserRecord = serde_json::from_str(user_line).unwrap();
            assert_eq!(restored.name, "carol");
            assert_eq!(restored.api_key_hash, "abc123");

            let perm_line = content.lines().find(|l| l.contains("\"auth-perm\"")).expect("auth-perm line must be present");
            let restored_perm: DomainPermission = serde_json::from_str(perm_line).unwrap();
            assert_eq!(restored_perm.username, "carol");
            assert_eq!(restored_perm.domain, "shop");
        })
    }

    // 8c. Auth records live outside every domain: an `all` backup taken while
    //     no KV domain exists at all must still export them (regression: the
    //     KV snapshot was only acquired for non-empty domain lists, so the
    //     auth section was silently skipped while the manifest still
    //     announced include_auth).
    #[test]
    fn test_backup_exports_auth_without_any_kv_domain() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            fx.control.delete_domain(Engine::Kv, "default").await.unwrap();
            let record = UserRecord {
                name: "erin".to_string(),
                api_key_hash: "cafe".to_string(),
                role: crate::auth::UserRole::Admin,
                created_at: 1_700_000_000,
            };
            fx.control
                .system_store()
                .put(format!("{PREFIX_USER}erin").as_bytes(), &serde_json::to_vec(&record).unwrap())
                .await
                .unwrap();

            let resolved = resolve_scope(&BackupScope::All, &fx.control).unwrap();
            assert!(resolved.kv_domains.is_empty(), "test setup: no domain must be left");

            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_authnodomain", BackupScope::All, true).await;

            let content = std::fs::read_to_string(out_dir.path().join("bk_authnodomain.ndjson")).unwrap();
            let user_line = content.lines().find(|l| l.contains("\"auth-user\"")).expect("auth-user line must be present");
            let restored: UserRecord = serde_json::from_str(user_line).unwrap();
            assert_eq!(restored.name, "erin");
        })
    }

    // 9. JSON domain export: index definitions and documents are exported
    //    with the expected line shapes.
    #[test]
    fn test_run_backup_json_domain_with_index_and_docs() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(true).await;
            fx.create(Engine::Json, "catalog").await;
            fx.json().create_index("catalog", "city", IndexFieldType::String).await.unwrap();
            fx.json().put_document("catalog", "d1", json!({"city": "Lyon"})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_json", BackupScope::JsonDomain("catalog".to_string()), false).await;
            let content = std::fs::read_to_string(out_dir.path().join("bk_json.ndjson")).unwrap();
            assert!(content.contains("\"t\":\"json-domain\""));
            assert!(content.contains("\"t\":\"json-index\""));
            assert!(content.contains("\"t\":\"doc\""));
            assert!(content.contains("\"field_type\":\"string\""));
            let manifest = manifest_of(&content);
            assert!(manifest.lsn_cut.json >= 1 && manifest.json_snapshot_ts > 0, "{:?}", manifest.lsn_cut);
            assert_eq!((manifest.lsn_cut.kv, manifest.kv_snapshot_ts), (0, 0), "no KV domain in the scope");
        })
    }

    // 9b. Binding section order: kv sections, then json sections, then auth,
    //     then the checksum line.
    #[test]
    fn test_backup_section_order_kv_json_auth_checksum() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(true).await;
            fx.create(Engine::Kv, "shop").await;
            fx.kv.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
            fx.create(Engine::Json, "catalog").await;
            fx.json().put_document("catalog", "d1", serde_json::json!({"n": 1})).await.unwrap();
            let record = UserRecord {
                name: "dave".to_string(),
                api_key_hash: "beef".to_string(),
                role: crate::auth::UserRole::User,
                created_at: 1,
            };
            fx.control.system_store().put(b"__sys:auth:user:dave", &serde_json::to_vec(&record).unwrap()).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_order", BackupScope::All, true).await;

            let content = std::fs::read_to_string(out_dir.path().join("bk_order.ndjson")).unwrap();
            let kinds: Vec<String> = content
                .lines()
                .map(|l| serde_json::from_str::<Value>(l).unwrap()["t"].as_str().unwrap().to_string())
                .collect();
            let pos = |t: &str| kinds.iter().position(|k| k == t).unwrap_or_else(|| panic!("no '{t}' line"));
            assert_eq!(kinds.first().map(String::as_str), Some("manifest"));
            assert!(pos("kv") < pos("json-domain"), "kv sections must precede json sections");
            assert!(pos("doc") < pos("auth-user"), "auth must come after the documents");
            assert_eq!(kinds.last().map(String::as_str), Some("checksum"));
        })
    }

    // 10. Checksum line matches the file's own content and lists the right
    //     line count.
    #[test]
    fn test_checksum_line_is_valid() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            fx.create(Engine::Kv, "shop").await;
            let store = fx.kv.store("shop").await.unwrap();
            store.put(b"k1", b"v1").await.unwrap();
            store.put(b"k2", b"v2").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            backup(&fx.control, out_dir.path(), "bk_sum", BackupScope::KvDomain("shop".to_string()), false).await;

            let bytes = std::fs::read(out_dir.path().join("bk_sum.ndjson")).unwrap();
            let text = String::from_utf8(bytes.clone()).unwrap();
            let mut all_lines: Vec<&str> = text.lines().collect();
            let checksum_line = all_lines.pop().unwrap();
            let checksum: ChecksumLine = serde_json::from_str(checksum_line).unwrap();
            assert_eq!(checksum.lines, all_lines.len() as u64);

            let mut hasher = Sha256::new();
            for l in &all_lines {
                hasher.update(l.as_bytes());
                hasher.update(b"\n");
            }
            assert_eq!(hex::encode(hasher.finalize()), checksum.sha256);
        })
    }

    // 11. On a write failure the `.part` file is removed, not left behind.
    #[test]
    fn test_run_backup_cleans_up_part_file_on_error() {
        crate::core::engine_runtime::block_on(async {
            let fx = fixture(false).await;
            // A scope resolving to a KV domain that was deleted right after
            // resolution simulates a mid-job failure: `store()` on a Deleting
            // domain errors out inside the writer.
            fx.create(Engine::Kv, "gone").await;
            let resolved = resolve_scope(&BackupScope::KvDomain("gone".to_string()), &fx.control).unwrap();
            fx.control.delete_domain(Engine::Kv, "gone").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let scope = BackupScope::KvDomain("gone".to_string());
            let params = BackupParams {
                dir: out_dir.path(),
                id: "bk_fail",
                scope: &scope,
                include_auth: false,
                schedule: None,
                resolved: &resolved,
                control: &fx.control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            };
            assert!(run_backup(params).await.is_err());
            assert!(!out_dir.path().join("bk_fail.ndjson.part").exists());
            assert!(!out_dir.path().join("bk_fail.ndjson").exists());
        })
    }

    /// The (domain, key) pairs of the KV lines of an archive.
    fn exported_pairs(content: &str) -> std::collections::HashSet<(String, String)> {
        content
            .lines()
            .filter_map(|l| serde_json::from_str::<KvLine>(l).ok().filter(|l| l.t == "kv"))
            .map(|l| (l.domain, String::from_utf8(hex::decode(&l.k).unwrap()).unwrap()))
            .collect()
    }

    // Round after round, a writer confirms a write to a domain of shard 0 and
    // then makes one to a domain of shard 1 while a backup runs: an archive
    // that holds the second write holds the first. Round 0 backs up between
    // the two writes, round 1 while the second is held in flight, the rest
    // after a varying number of yields from a fixed seed. The domains of
    // both shards come in name order.
    #[test]
    fn an_archive_with_a_later_write_holds_every_write_confirmed_before_it() {
        crate::core::engine_runtime::block_on(async {
            use crate::engines::lsm::engine::TestHook;
            const ROUNDS: usize = 40;
            let dir = tempfile::TempDir::new().unwrap();
            let hub = crate::core::storage_thread::TestHub::start(&[(
                crate::core::storage_thread::WalTarget::Kv,
                &dir.path().join("kv.wal"),
            )]);
            let [a, b] = [0, 1].map(|shard| slots::domain_name_for_shard(shard, 2, 31));
            let held = [format!("d:{:016x}:", fnv64(b.as_bytes())).as_bytes(), b"b-1"].concat();
            let hook = Arc::new(TestHook::default());
            let owners = testing::kv_shards(dir.path(), &hub, 2, |k, engine| {
                if k == 1 {
                    engine.hooks.before_kv_pair_apply = Some((held.clone(), Arc::clone(&hook)));
                }
            })
            .await;
            let registries: Vec<_> = owners.iter().map(|owners| Arc::clone(&owners.kv)).collect();
            let bus = Arc::new(crate::core::events::GlobalEventBus::new(16, 16));
            let (control, _) = testing::start_shards(dir.path(), owners, bus).await;
            for name in [&a, &b] {
                control.create_domain(Engine::Kv, name, false).await.unwrap();
            }
            let stores = [registries[0].store(&a).await.unwrap(), registries[1].store(&b).await.unwrap()];
            let stores = Arc::new(stores);

            let out_dir = tempfile::TempDir::new().unwrap();
            let (mut a_only, mut both) = (0, 0);
            let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
            for i in 0..ROUNDS {
                let id = format!("bk_cut_{i}");
                let (a_done, a_confirmed) = tokio::sync::oneshot::channel();
                let (go, gate) = tokio::sync::oneshot::channel::<()>();
                let writer = compio::runtime::spawn({
                    let stores = Arc::clone(&stores);
                    async move {
                        stores[0].put(format!("a-{i}").as_bytes(), b"v").await.unwrap();
                        let _ = a_done.send(());
                        gate.await.unwrap();
                        stores[1].put(format!("b-{i}").as_bytes(), b"v").await.unwrap();
                    }
                });
                if i == 0 {
                    a_confirmed.await.unwrap();
                    backup(&control, out_dir.path(), &id, BackupScope::Kv, false).await;
                    go.send(()).unwrap();
                } else if i == 1 {
                    go.send(()).unwrap();
                    hook.reached.notified().await;
                    let job = compio::runtime::spawn({
                        let (control, out, id) = (Arc::clone(&control), out_dir.path().to_path_buf(), id.clone());
                        async move { backup(&control, &out, &id, BackupScope::Kv, false).await }
                    });
                    for _ in 0..50 {
                        tokio::task::yield_now().await;
                    }
                    assert!(!job.is_finished(), "the backup's cut waits for the write in flight");
                    hook.release.notify_one();
                    job.await.unwrap();
                } else {
                    go.send(()).unwrap();
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    for _ in 0..state % 16 {
                        tokio::task::yield_now().await;
                    }
                    backup(&control, out_dir.path(), &id, BackupScope::Kv, false).await;
                }
                writer.await.unwrap();

                let content = std::fs::read_to_string(out_dir.path().join(format!("{id}.ndjson"))).unwrap();
                let pairs = exported_pairs(&content);
                let has_a = pairs.contains(&(a.clone(), format!("a-{i}")));
                let has_b = pairs.contains(&(b.clone(), format!("b-{i}")));
                assert!(has_a || !has_b, "round {i}: b-{i} without a-{i}");
                a_only += usize::from(has_a && !has_b);
                both += usize::from(has_a && has_b);
                if i == 0 {
                    let names: Vec<String> = content
                        .lines()
                        .filter_map(|l| serde_json::from_str::<KvDomainLine>(l).ok().filter(|l| l.t == "kv-domain"))
                        .map(|l| l.name)
                        .collect();
                    let mut sorted = names.clone();
                    sorted.sort();
                    assert_eq!(names, sorted);
                    assert!(names.contains(&a) && names.contains(&b), "{names:?}");
                    assert_eq!(manifest_of(&content).shards, 2);
                }
            }
            assert!(a_only > 0, "no backup fell between the two writes");
            assert!(both > 0, "no backup held both writes");
        })
    }

    #[test]
    fn real_values_come_back_from_the_archive_bit_for_bit() {
        use crate::engines::rel::dml::coerce_json;
        use crate::engines::rel::ColumnType;

        let mut values = vec![
            f64::MIN_POSITIVE,
            f64::from_bits(1),
            f64::from_bits(0x000f_ffff_ffff_ffff),
            f64::MAX,
            f64::MIN,
            f64::EPSILON,
            0.1 + 0.2,
            -0.0,
            0.0,
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        while values.len() < 10_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let f = f64::from_bits(state);
            if f.is_finite() {
                values.push(f);
            }
        }
        for f in values {
            let line = serde_json::to_string(&rel_value(&ScalarValue::Real(f))).unwrap();
            let parsed: Value = serde_json::from_str(&line).unwrap();
            let back = coerce_json(ColumnType::Real, &parsed, "r").unwrap();
            let ScalarValue::Real(back) = back else { panic!("{f:e}: got {back:?}") };
            assert_eq!(back.to_bits(), f.to_bits(), "{f:e} came back as {back:e} via {line}");
        }
    }
}
