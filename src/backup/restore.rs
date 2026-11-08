//! Restore pipeline: a full checksum-verification pass,
//! domain preparation (`fail_if_exists`/`replace`), then a streaming apply
//! pass in archive order (domains already exist by then -> indexes -> data).

use super::writer::{
    is_supported_format, maybe_pause, ChecksumLine, DocLine, JsonDomainLine, JsonIndexLine, KvDomainLine, KvLine,
    ManifestLine, RelDefault, RelDomainLine, RelRowLine, RelSeqLine, RelTableLine, RelViewLine,
};
use super::{BackupError, MAX_LINE_BYTES};
use crate::auth::middleware::split_permission_domain;
use crate::auth::{DomainPermission, UserRecord};
use crate::control::{AuthChange, ConditionalWrites, ControlPlane, Engine, Lifecycle};
use crate::engines::json::JsonEngine;
use crate::engines::lsm::domain::{now_secs, DomainStore};
use crate::engines::rel::dml::coerce_json;
use crate::engines::rel::{ColumnInput, ColumnType, DefaultValue, IndexInput, RelEngine, TableInput};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use crate::core::engine_runtime;
use std::time::{Duration, Instant};

/// Poll interval while waiting for the purgers in `replace` mode. They run
/// as independent background tasks; this loop only observes their progress.
const PURGE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Deadline for that wait. Without it a stalled purger parks the restore
/// forever and its job slot stays taken for the process lifetime; generous
/// enough that a large domain on a slow disk still finishes in time.
const PURGE_WAIT_TIMEOUT: Duration = Duration::from_secs(600);

/// Cap on the per-record errors kept in [`RestoreOutcome::errors`]. The list
/// is retained in the restore registry for the process lifetime and returned
/// in full by `GET /restores/{id}`; `failed` still counts every failure.
const MAX_REPORTED_ERRORS: usize = 100;

/// Cap on the key label of a single error entry (keys can be long).
const MAX_ERROR_KEY_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMode {
    FailIfExists,
    Replace,
}

pub(crate) struct RestoreParams<'a> {
    pub dir: &'a Path,
    pub backup_id: &'a str,
    pub mode: RestoreMode,
    pub into_domain: Option<&'a str>,
    pub include_auth: bool,
    /// Creates the target domains or clears their engines, leads each one to
    /// the engines of the data shard that owns it here, and takes the auth
    /// records as auth changes.
    pub control: &'a ControlPlane,
    pub scan_batch_size: usize,
    pub scan_pause_ms: u64,
}

#[derive(Debug, Default)]
pub(crate) struct RestoreOutcome {
    pub imported: u64,
    pub skipped: u64,
    pub failed: u64,
    pub errors: Vec<(String, String)>,
}

impl RestoreOutcome {
    fn fail(&mut self, key: impl Into<String>, reason: impl Into<String>) {
        self.failed += 1;
        if self.errors.len() < MAX_REPORTED_ERRORS {
            self.errors.push((short_label(key.into()), reason.into()));
        }
    }
}

/// Shortens an error entry's key label, cutting on a char boundary.
fn short_label(mut key: String) -> String {
    if key.len() > MAX_ERROR_KEY_LEN {
        let mut end = MAX_ERROR_KEY_LEN;
        while !key.is_char_boundary(end) {
            end -= 1;
        }
        key.truncate(end);
    }
    key
}

/// Runs the full restore: checksum-verify the archive, prepare (create or
/// replace) every target domain, then stream-apply the data. Each domain
/// goes to the data shard that owns it on this server, whatever shard count
/// wrote the archive. Per-entry KV and JSON failures are counted in the
/// returned [`RestoreOutcome`] and the job keeps going; an `Err` here means
/// an engine-level failure or a failed relational line aborted the whole
/// job.
pub(crate) async fn run_restore(params: RestoreParams<'_>) -> anyhow::Result<RestoreOutcome> {
    let path = params.dir.join(format!("{}.ndjson", params.backup_id));

    let scan = verify_and_scan(&path).await?;
    // An archive with JSON or relational data cannot be applied without that
    // engine — silently dropping it would be data loss. Its domain lines
    // alone need no engine.
    if scan.json_data && !json_enabled(params.control) {
        return Err(BackupError::JsonEngineDisabled.into());
    }
    if scan.rel_data && !params.control.shard_owners().any(|owners| owners.rel.is_some()) {
        return Err(BackupError::RelEngineDisabled.into());
    }
    let remap = build_remap(params.into_domain, &scan)?;

    prepare_domains(&scan, params.mode, &remap, params.control).await?;

    apply_pass(&path, &remap, &params).await
}

fn json_enabled(control: &ControlPlane) -> bool {
    control.shard_owners().any(|owners| owners.json.is_some())
}

/// The JSON engine of the data shard that owns `domain`.
fn json_of<'c>(control: &'c ControlPlane, domain: &str) -> anyhow::Result<&'c Arc<JsonEngine>> {
    control.owners_of(domain).json.as_ref().ok_or_else(|| BackupError::JsonEngineDisabled.into())
}

/// The relational engine of the data shard that owns `domain`.
fn rel_of<'c>(control: &'c ControlPlane, domain: &str) -> anyhow::Result<&'c Arc<RelEngine>> {
    control.owners_of(domain).rel.as_ref().ok_or_else(|| BackupError::RelEngineDisabled.into())
}

pub(crate) struct ArchiveScan {
    /// Every domain of the archive with the engines it has domain lines of
    /// and, from version 3 on, their `require_conditional_writes`; domain
    /// lines of one name in several engines are one domain.
    domains: BTreeMap<String, Vec<(Engine, Option<bool>)>>,
    /// Whether the archive holds JSON or relational data lines.
    json_data: bool,
    rel_data: bool,
    /// Exposed for the "manifest fields" response of POST
    /// /backups/upload — restore itself only needs the domains above.
    pub(crate) manifest: ManifestLine,
}

/// Full read pass ahead of any write: verifies the SHA-256 checksum line
/// and, along the way, collects every kv-, json- and rel-domain line — needed
/// up front so `fail_if_exists`/`replace` and the `into_domain` single-name
/// check can run before any write in pass 2. Data lines naming an
/// undeclared domain are rejected here: the apply pass takes its target from
/// the data line, so an archive could otherwise write past those checks into
/// a live domain. Also reused as-is by the upload endpoint's validation pass
/// (`crate::api::backup`), which only needs the checksum/manifest check.
pub(crate) async fn verify_and_scan(path: &Path) -> anyhow::Result<ArchiveScan> {
    let mut reader = ArchiveReader::open(path).await?;

    let mut hasher = Sha256::new();
    let mut line_count: u64 = 0;
    let mut domains: BTreeMap<String, Vec<(Engine, Option<bool>)>> = BTreeMap::new();
    let mut kv_domains: Vec<String> = Vec::new();
    let mut json_domains: Vec<String> = Vec::new();
    let mut rel_domains: Vec<String> = Vec::new();
    let mut kv_refs: HashSet<String> = HashSet::new();
    let mut json_refs: HashSet<String> = HashSet::new();
    let mut rel_refs: HashSet<String> = HashSet::new();
    let mut saw_checksum = false;
    let mut manifest_line: Option<ManifestLine> = None;
    let mut raw: Vec<u8> = Vec::new();

    while read_line_capped(&mut reader, &mut raw).await? > 0 {
        // The writer never emits blank lines; rejecting them keeps the
        // guarantee exact that every file byte before the checksum line went
        // into the hash.
        if raw.iter().all(|b| b.is_ascii_whitespace()) {
            return Err(BackupError::InvalidBackupFile("blank line in backup archive".to_string()).into());
        }
        let value: Value = serde_json::from_slice(&raw).map_err(|e| {
            BackupError::InvalidBackupFile(format!("malformed line in backup archive: {e}"))
        })?;
        let t = value.get("t").and_then(|v| v.as_str()).unwrap_or("").to_string();

        if line_count == 0 {
            if t != "manifest" {
                return Err(BackupError::InvalidBackupFile(
                    "backup archive does not start with a manifest line".to_string(),
                )
                .into());
            }
            let manifest: ManifestLine = parse_line(value.clone())?;
            if !is_supported_format(manifest.format_version) {
                return Err(BackupError::UnsupportedFormatVersion(manifest.format_version).into());
            }
            manifest_line = Some(manifest);
        }

        if t == "checksum" {
            let checksum: ChecksumLine = parse_line(value)?;
            if checksum.lines != line_count {
                return Err(BackupError::InvalidBackupFile(format!(
                    "checksum line count mismatch: header says {}, file has {line_count}",
                    checksum.lines
                ))
                .into());
            }
            let computed = hex::encode(hasher.finalize());
            if computed != checksum.sha256 {
                return Err(BackupError::InvalidBackupFile("checksum mismatch".to_string()).into());
            }
            // Anything after the checksum line is outside the verified
            // range and would otherwise reach the apply pass unchecked.
            if read_line_capped(&mut reader, &mut raw).await? > 0 {
                return Err(BackupError::InvalidBackupFile(
                    "data after the checksum line".to_string(),
                )
                .into());
            }
            saw_checksum = true;
            break;
        }

        match t.as_str() {
            "kv-domain" => {
                let line: KvDomainLine = parse_line(value)?;
                domains.entry(line.name.clone()).or_default().push((Engine::Kv, line.require_conditional_writes));
                kv_domains.push(line.name);
            }
            "json-domain" => {
                let line: JsonDomainLine = parse_line(value)?;
                domains.entry(line.name.clone()).or_default().push((Engine::Json, line.require_conditional_writes));
                json_domains.push(line.name);
            }
            "rel-domain" => {
                let line: RelDomainLine = parse_line(value)?;
                domains.entry(line.name.clone()).or_default().push((Engine::Rel, None));
                rel_domains.push(line.name);
            }
            "kv" => collect_ref(&value, &mut kv_refs),
            "doc" | "json-index" => collect_ref(&value, &mut json_refs),
            "rel-table" | "rel-view" | "rel-row" | "rel-seq" => collect_ref(&value, &mut rel_refs),
            _ => {}
        }

        hasher.update(&raw);
        line_count += 1;
    }

    if !saw_checksum {
        return Err(
            BackupError::InvalidBackupFile("backup archive is incomplete (missing checksum line)".to_string())
                .into(),
        );
    }

    for name in &kv_refs {
        if !kv_domains.contains(name) {
            return Err(BackupError::InvalidBackupFile(format!(
                "kv data for undeclared domain '{name}'"
            ))
            .into());
        }
    }
    for name in &json_refs {
        if !json_domains.contains(name) {
            return Err(BackupError::InvalidBackupFile(format!(
                "json data for undeclared domain '{name}'"
            ))
            .into());
        }
    }
    if let Some(name) = rel_refs.iter().find(|name| !rel_domains.contains(name)) {
        return Err(BackupError::InvalidBackupFile(format!("relational data for undeclared domain '{name}'")).into());
    }

    Ok(ArchiveScan {
        domains,
        json_data: !json_refs.is_empty(),
        rel_data: !rel_refs.is_empty(),
        manifest: manifest_line.expect("checked above: the first line is always a manifest when saw_checksum is true"),
    })
}

fn parse_line<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, BackupError> {
    serde_json::from_value(value)
        .map_err(|e| BackupError::InvalidBackupFile(format!("malformed line in backup archive: {e}")))
}

/// Records the domain a data line writes to, so the scan can check it against
/// the declared domains.
fn collect_ref(value: &Value, refs: &mut HashSet<String>) {
    if let Some(domain) = value.get("domain").and_then(|v| v.as_str()) {
        if !refs.contains(domain) {
            refs.insert(domain.to_string());
        }
    }
}

/// The archive, read in chunks on the engine ring.
struct ArchiveReader {
    file: Arc<std::fs::File>,
    pos: u64,
    buf: Vec<u8>,
    start: usize,
}

/// Bytes read from the archive at a time.
const ARCHIVE_CHUNK: usize = 8 * 1024;

impl ArchiveReader {
    async fn open(path: &Path) -> std::io::Result<Self> {
        let mut options = compio::fs::OpenOptions::new();
        options.read(true);
        let file = engine_runtime::open(path.to_path_buf(), options).await?;
        Ok(Self { file: Arc::new(file), pos: 0, buf: Vec::new(), start: 0 })
    }

    /// The bytes not consumed yet, read on once all are; empty at the end.
    async fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.start == self.buf.len() {
            self.buf = engine_runtime::read_at(&self.file, ARCHIVE_CHUNK, self.pos).await?;
            self.pos += self.buf.len() as u64;
            self.start = 0;
        }
        Ok(&self.buf[self.start..])
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
    }
}

/// Reads one `\n`-terminated line (terminator included, absent at EOF) into
/// `buf` and returns its length; 0 means end of file. Lines longer than
/// [`MAX_LINE_BYTES`] are rejected instead of being buffered whole.
async fn read_line_capped(reader: &mut ArchiveReader, buf: &mut Vec<u8>) -> anyhow::Result<usize> {
    buf.clear();
    loop {
        let (consumed, done) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                break;
            }
            match available.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    buf.extend_from_slice(&available[..=i]);
                    (i + 1, true)
                }
                None => {
                    buf.extend_from_slice(available);
                    (available.len(), false)
                }
            }
        };
        reader.consume(consumed);
        if buf.len() > MAX_LINE_BYTES {
            return Err(BackupError::InvalidBackupFile(format!(
                "line in backup archive exceeds {MAX_LINE_BYTES} bytes"
            ))
            .into());
        }
        if done {
            break;
        }
    }
    Ok(buf.len())
}

/// Validates `into_domain` (only legal when the archive
/// contains exactly one domain *name*, counting every engine together — a
/// `domain:*` export has the same name in each section) and returns the
/// `(archived_name, target_name)` substitution to apply everywhere.
fn build_remap(into_domain: Option<&str>, scan: &ArchiveScan) -> anyhow::Result<Option<(String, String)>> {
    let Some(target) = into_domain else { return Ok(None) };
    let mut names = scan.domains.keys();
    match (names.next(), names.next()) {
        (Some(only), None) => Ok(Some((only.clone(), target.to_string()))),
        _ => Err(BackupError::RemapRequiresSingleDomain.into()),
    }
}

fn remapped<'a>(remap: &'a Option<(String, String)>, archived_name: &'a str) -> &'a str {
    match remap {
        Some((from, to)) if from == archived_name => to,
        _ => archived_name,
    }
}

/// Phase A (checks only, nothing is written yet) then phase B (create every
/// missing target domain, or, with `replace`, clear the engines the archive
/// has of an existing one) — kept as two full sweeps so `fail_if_exists`
/// truly aborts before the first write: if any domain in phase A already
/// exists, we return before phase B ever runs.
async fn prepare_domains(
    scan: &ArchiveScan,
    mode: RestoreMode,
    remap: &Option<(String, String)>,
    control: &ControlPlane,
) -> anyhow::Result<()> {
    if mode == RestoreMode::FailIfExists {
        if let Some(name) = scan.domains.keys().map(|name| remapped(remap, name)).find(|t| control.directory().get(t).is_some()) {
            return Err(BackupError::DomainExists(name.to_string()).into());
        }
    }

    for (name, engines) in &scan.domains {
        let target = remapped(remap, name);
        let existing = control.directory().get(target).map(|entry| entry.state);
        match (mode, existing) {
            (RestoreMode::FailIfExists, Some(_)) => return Err(BackupError::DomainExists(target.to_string()).into()),
            (RestoreMode::Replace, Some(Lifecycle::Active)) => replace_engines(target, engines, control).await?,
            (_, existing) => {
                if existing.is_some() {
                    wait_for_purge(target, PURGE_WAIT_TIMEOUT, || control.directory().get(target).is_none()).await?;
                }
                let mut setting = ConditionalWrites::default();
                for (engine, value) in engines {
                    setting.set(*engine, value.unwrap_or(false));
                }
                control.create_domain(target, setting).await?;
            }
        }
    }
    Ok(())
}

/// Clears each engine of `target` that `engines` names, through the control
/// plane, and waits until each enabled one is active again; the domain and
/// its other engines stay as they are. Archives before version 3 keep the
/// engines' `require_conditional_writes`.
async fn replace_engines(target: &str, engines: &[(Engine, Option<bool>)], control: &ControlPlane) -> anyhow::Result<()> {
    for (engine, setting) in engines {
        control.clear_engine(*engine, target, *setting).await?;
    }
    let owners = control.owners_of(target);
    let enabled = owners.engines();
    wait_for_purge(target, PURGE_WAIT_TIMEOUT, || {
        let directory = control.directory();
        let Some(entry) = directory.get(target) else { return true };
        !entry.purging.iter().any(|engine| enabled.contains(engine))
            && engines
                .iter()
                .filter(|(engine, _)| enabled.contains(engine))
                .all(|(engine, _)| owners.record(*engine, target).is_some_and(|part| part.state == Lifecycle::Active))
    })
    .await?;
    if control.directory().get(target).is_none() {
        return Err(BackupError::DomainNotFound(target.to_string()).into());
    }
    Ok(())
}

/// Polls `is_gone` until the purgers finished. Bounded by `timeout`: a
/// stalled purger must not park the restore (and its job slot) for the
/// process lifetime.
async fn wait_for_purge(name: &str, timeout: Duration, is_gone: impl Fn() -> bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if is_gone() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!("domain '{name}' is still being purged"));
        }
        compio::time::sleep(PURGE_POLL_INTERVAL).await;
    }
}

/// Streams the archive top to bottom and applies each line. Domains/indexes
/// are already prepared, so `kv-domain`/`json-domain`/`manifest`/`checksum`
/// lines are no-ops here. KV writes are throttled individually (a pause
/// every `scan_batch_size` entries); JSON documents are grouped into
/// per-domain batches and imported via [`JsonEngine::bulk_load`] (its
/// index entries are maintained synchronously, like `load_batch`), flushed
/// on a domain change, a full batch, or end of stream. Relational rows are
/// grouped the same way per table; relational tables, views and
/// AUTOINCREMENT marks apply one by one.
async fn apply_pass(
    path: &Path,
    remap: &Option<(String, String)>,
    params: &RestoreParams<'_>,
) -> anyhow::Result<RestoreOutcome> {
    let RestoreParams { include_auth, control, scan_batch_size, scan_pause_ms, .. } = *params;
    let mut reader = ArchiveReader::open(path).await?;
    let mut line: Vec<u8> = Vec::new();

    let mut outcome = RestoreOutcome::default();
    let now = now_secs();

    let mut kv_stores: HashMap<String, DomainStore> = HashMap::new();
    let mut kv_count: usize = 0;

    let mut doc_domain: Option<String> = None;
    let mut doc_batch: Vec<(Option<String>, Value)> = Vec::new();

    let mut rel_rows = RelRowBatch::default();

    while read_line_capped(&mut reader, &mut line).await? > 0 {
        let raw = std::str::from_utf8(&line)?;
        if raw.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            // Structural validity was already confirmed by verify_and_scan.
            Err(_) => continue,
        };
        let t = value.get("t").and_then(|v| v.as_str()).unwrap_or("").to_string();

        match t.as_str() {
            "kv" => {
                let line: KvLine = match serde_json::from_value(value) {
                    Ok(l) => l,
                    Err(e) => {
                        outcome.fail("kv", format!("malformed kv line: {e}"));
                        continue;
                    }
                };
                let target = remapped(remap, &line.domain).to_string();
                if !kv_stores.contains_key(&target) {
                    let store = control.owners_of(&target).kv.store(&target).await?;
                    kv_stores.insert(target.clone(), store);
                }
                let store = kv_stores.get(&target).unwrap();
                apply_kv_line(store, &line, now, &mut outcome).await;
                maybe_pause(kv_count, scan_batch_size, scan_pause_ms).await;
                kv_count += 1;
            }
            "json-index" => {
                flush_doc_batch(&mut doc_domain, &mut doc_batch, control, &mut outcome).await?;
                let line: JsonIndexLine = match serde_json::from_value(value) {
                    Ok(l) => l,
                    Err(e) => {
                        outcome.fail("json-index", format!("malformed index line: {e}"));
                        continue;
                    }
                };
                let target = remapped(remap, &line.domain).to_string();
                if let Err(e) = json_of(control, &target)?.create_index(&target, &line.field, line.field_type).await {
                    outcome.fail(format!("{target}.{}", line.field), e.to_string());
                }
            }
            "doc" => {
                let line: DocLine = match serde_json::from_value(value) {
                    Ok(l) => l,
                    Err(e) => {
                        outcome.fail("doc", format!("malformed doc line: {e}"));
                        continue;
                    }
                };
                let target = remapped(remap, &line.domain).to_string();
                if doc_domain.as_deref() != Some(target.as_str()) {
                    flush_doc_batch(&mut doc_domain, &mut doc_batch, control, &mut outcome).await?;
                    doc_domain = Some(target);
                }
                doc_batch.push((Some(line.key), line.content));
                if doc_batch.len() >= scan_batch_size.max(1) {
                    flush_doc_batch(&mut doc_domain, &mut doc_batch, control, &mut outcome).await?;
                    compio::time::sleep(Duration::from_millis(scan_pause_ms)).await;
                }
            }
            "rel-domain" | "rel-table" | "rel-view" | "rel-row" | "rel-seq" => {
                flush_doc_batch(&mut doc_domain, &mut doc_batch, control, &mut outcome).await?;
                if t == "rel-row" {
                    let line: RelRowLine = parse_line(value)?;
                    let target = (remapped(remap, &line.domain).to_string(), line.table);
                    if rel_rows.target.as_ref() != Some(&target) {
                        rel_rows.flush(control, &mut outcome).await?;
                        rel_rows.target = Some(target);
                    }
                    rel_rows.rows.push(line.row);
                    if rel_rows.rows.len() >= scan_batch_size.max(1) {
                        rel_rows.flush(control, &mut outcome).await?;
                        compio::time::sleep(Duration::from_millis(scan_pause_ms)).await;
                    }
                } else {
                    rel_rows.flush(control, &mut outcome).await?;
                    apply_rel_schema_line(&t, value, remap, control).await?;
                }
            }
            "auth-user" => {
                flush_doc_batch(&mut doc_domain, &mut doc_batch, control, &mut outcome).await?;
                rel_rows.flush(control, &mut outcome).await?;
                if include_auth {
                    apply_auth_user(&value, control, &mut outcome).await;
                }
            }
            "auth-perm" => {
                if include_auth {
                    apply_auth_perm(&value, control, &mut outcome).await;
                }
            }
            // The checksum line marks the verified end of the archive
            // (verify_and_scan guarantees nothing follows it).
            "checksum" => break,
            // manifest / kv-domain / json-domain: handled in preparation.
            _ => {}
        }
    }

    flush_doc_batch(&mut doc_domain, &mut doc_batch, control, &mut outcome).await?;
    rel_rows.flush(control, &mut outcome).await?;
    Ok(outcome)
}

/// Relational rows of one table, buffered to go to the engine as one group.
#[derive(Default)]
struct RelRowBatch {
    /// `(domain, table)` the rows belong to.
    target: Option<(String, String)>,
    rows: Vec<Map<String, Value>>,
}

impl RelRowBatch {
    /// Inserts the buffered rows; a failure aborts the restore, since an
    /// archive of this engine must restore in full.
    async fn flush(&mut self, control: &ControlPlane, outcome: &mut RestoreOutcome) -> anyhow::Result<()> {
        let Some((domain, table)) = &self.target else { return Ok(()) };
        if self.rows.is_empty() {
            return Ok(());
        }
        let rows = std::mem::take(&mut self.rows);
        let inserted = rel_of(control, domain)
            .map_err(|e| rel_failure(domain, "table", table, e))?
            .restore_rows(domain, table, rows)
            .await
            .map_err(|e| rel_failure(domain, "table", table, e))?;
        outcome.imported += inserted;
        Ok(())
    }
}

/// The error that aborts a restore at a relational line, naming domain and
/// object, `kind` being `table` or `view`, in its one-line text.
fn rel_failure(domain: &str, kind: &str, object: &str, cause: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("relational domain '{domain}', {kind} '{object}': {cause}")
}

/// Applies a `rel-table`, `rel-view` or `rel-seq` line; `rel-domain` lines
/// were handled when the domains were prepared.
async fn apply_rel_schema_line(
    t: &str,
    value: Value,
    remap: &Option<(String, String)>,
    control: &ControlPlane,
) -> anyhow::Result<()> {
    match t {
        "rel-table" => {
            let line: RelTableLine = parse_line(value)?;
            let domain = remapped(remap, &line.domain);
            let failure = |e: &dyn std::fmt::Display| rel_failure(domain, "table", &line.name, e);
            let (input, indexes) = table_input(&line).map_err(|e| failure(&e))?;
            rel_of(control, domain)
                .map_err(|e| failure(&e))?
                .restore_table(domain, input, indexes)
                .await
                .map_err(|e| failure(&e))?;
        }
        "rel-view" => {
            let line: RelViewLine = parse_line(value)?;
            let domain = remapped(remap, &line.domain);
            let failure = |e: &dyn std::fmt::Display| rel_failure(domain, "view", &line.name, e);
            rel_of(control, domain)
                .map_err(|e| failure(&e))?
                .create_view(domain, &line.name, &line.sql)
                .await
                .map_err(|e| failure(&e))?;
        }
        "rel-seq" => {
            let line: RelSeqLine = parse_line(value)?;
            let domain = remapped(remap, &line.domain);
            let failure = |e: &dyn std::fmt::Display| rel_failure(domain, "table", &line.table, e);
            rel_of(control, domain)
                .map_err(|e| failure(&e))?
                .raise_autoincrement(domain, &line.table, line.hw)
                .await
                .map_err(|e| failure(&e))?;
        }
        _ => {}
    }
    Ok(())
}

/// The catalog input of an archived table.
fn table_input(line: &RelTableLine) -> anyhow::Result<(TableInput, Vec<IndexInput>)> {
    let mut columns = Vec::with_capacity(line.columns.len());
    for c in &line.columns {
        let col_type = ColumnType::from_sql_name(&c.col_type)
            .ok_or_else(|| anyhow::anyhow!("unknown type '{}' of column '{}'", c.col_type, c.name))?;
        let default = match &c.default {
            None => DefaultValue::None,
            Some(RelDefault::Null) => DefaultValue::Null,
            Some(RelDefault::CurrentTimestamp) => DefaultValue::CurrentTimestamp,
            Some(RelDefault::Literal { value }) => DefaultValue::Literal(coerce_json(col_type, value, &c.name)?),
        };
        columns.push(ColumnInput {
            name: c.name.clone(),
            col_type,
            nullable: c.nullable,
            primary_key: c.primary_key,
            autoincrement: c.autoincrement,
            unique: c.unique,
            default,
            references: c.references.clone(),
        });
    }
    let indexes = line
        .indexes
        .iter()
        .map(|ix| IndexInput { name: ix.name.clone(), column: ix.column.clone(), unique: ix.unique })
        .collect();
    Ok((TableInput { name: line.name.clone(), columns }, indexes))
}

async fn apply_kv_line(store: &DomainStore, line: &KvLine, now: u64, outcome: &mut RestoreOutcome) {
    let key = match hex::decode(&line.k) {
        Ok(b) => b,
        Err(e) => {
            outcome.fail(line.k.clone(), format!("bad hex key: {e}"));
            return;
        }
    };
    let result = match &line.v {
        None => store.set_null_unthrottled(&key).await,
        Some(v_hex) => {
            let val = match hex::decode(v_hex) {
                Ok(b) => b,
                Err(e) => {
                    outcome.fail(String::from_utf8_lossy(&key), format!("bad hex value: {e}"));
                    return;
                }
            };
            if line.expires_at != 0 && line.expires_at <= now {
                outcome.skipped += 1;
                return;
            }
            let expire_at = (line.expires_at != 0).then_some(line.expires_at);
            store.put_unthrottled(&key, &val, expire_at).await
        }
    };
    match result {
        Ok(()) => outcome.imported += 1,
        Err(e) => outcome.fail(String::from_utf8_lossy(&key), e.to_string()),
    }
}

/// Flushes the buffered per-domain document batch via `bulk_load` on the
/// domain's owner shard. An `Err` here is an engine-level failure and aborts
/// the restore job; per-document validation issues are already folded into
/// `BulkLoadResult` and do not propagate.
async fn flush_doc_batch(
    domain: &mut Option<String>,
    batch: &mut Vec<(Option<String>, Value)>,
    control: &ControlPlane,
    outcome: &mut RestoreOutcome,
) -> anyhow::Result<()> {
    if batch.is_empty() {
        *domain = None;
        return Ok(());
    }
    let dom = domain.take().expect("a non-empty batch always has its domain set");
    let items = std::mem::take(batch);
    let result = json_of(control, &dom)?.bulk_load(&dom, items).await?;
    outcome.imported += result.imported;
    outcome.failed += result.failed;
    let room = MAX_REPORTED_ERRORS.saturating_sub(outcome.errors.len());
    outcome.errors.extend(result.errors.into_iter().take(room));
    Ok(())
}

async fn apply_auth_user(value: &Value, control: &ControlPlane, outcome: &mut RestoreOutcome) {
    let record: UserRecord = match serde_json::from_value(value.clone()) {
        Ok(r) => r,
        Err(e) => {
            outcome.fail("auth-user", format!("malformed auth-user line: {e}"));
            return;
        }
    };
    let name = record.name.clone();
    match control.change_auth(AuthChange::UpsertUser(record)).await {
        Ok(()) => outcome.imported += 1,
        Err(e) => outcome.fail(name, e.to_string()),
    }
}

async fn apply_auth_perm(value: &Value, control: &ControlPlane, outcome: &mut RestoreOutcome) {
    let perm: DomainPermission = match serde_json::from_value(value.clone()) {
        Ok(p) => p,
        Err(e) => {
            outcome.fail("auth-perm", format!("malformed auth-perm line: {e}"));
            return;
        }
    };
    let label = format!("{}:{}", perm.username, perm.domain);
    // The grant as POST …/permissions sets it: the archive cannot hold a user
    // with both a whole-domain grant and engine grants afterwards.
    let (engine, domain) = split_permission_domain(&perm.domain);
    let change =
        AuthChange::SetPermission { username: perm.username, domain: domain.to_string(), engine, access: perm.access };
    match control.change_auth(change).await {
        Ok(()) => outcome.imported += 1,
        Err(e) => outcome.fail(label, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthCache, PREFIX_PERM};
    use crate::backup::writer::{resolve_scope, run_backup, BackupParams};
    use crate::backup::BackupScope;
    use crate::config::JsonStoreConfig;
    use crate::control::testing;
    use crate::engines::json::{IndexFieldType, JsonDomainPurger};
    use crate::engines::lsm::domain::{DomainConfig, DomainPurger, DomainRegistry};
    use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
    use crate::engines::lsm::reader::GetResult;
    use crate::engines::StorageEngine;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use serde_json::json;
    use std::path::PathBuf;

    /// One server's engines in a temp dir: a key-value engine, a JSON engine
    /// when asked for, and a control plane over both as its one data shard.
    struct Instance {
        control: Arc<ControlPlane>,
        kv: Arc<DomainRegistry>,
        json: Option<Arc<JsonEngine>>,
        auth: Arc<AuthCache>,
        _dir: tempfile::TempDir,
    }

    async fn instance(with_json: bool) -> Instance {
        instance_with(DomainConfig::default(), with_json).await
    }

    async fn instance_with(config: DomainConfig, with_json: bool) -> Instance {
        let dir = tempfile::TempDir::new().unwrap();
        let kv_dir = dir.path().join("kv");
        let wal_path = kv_dir.join("wal.log");
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(&kv_dir).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(&kv_dir));
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = kv_dir.join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let engine = Arc::new(
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, LsmEngineOptions::default()).await.unwrap(),
        );
        let metrics = MetricsStore::new(MetricsConfig::default());
        let kv = Arc::new(DomainRegistry::recover(engine, config, metrics).await.unwrap());
        let json = match with_json {
            true => {
                let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
                let config = JsonStoreConfig {
                    wal_path: at("json.wal"),
                    vlog_path: at("json.vlog"),
                    sstable_dir: at("json_sstables"),
                    ..JsonStoreConfig::default()
                };
                Some(JsonEngine::bootstrap(&config, MetricsStore::new(MetricsConfig::default())).await.unwrap())
            }
            false => None,
        };
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(16, 16));
        let (control, auth) = testing::start(dir.path(), Arc::clone(&kv), json.clone(), None, bus).await;
        Instance { control, kv, json, auth, _dir: dir }
    }

    impl Instance {
        async fn create(&self, name: &str) {
            self.control.create_domain(name, Default::default()).await.unwrap();
        }

        async fn store(&self, name: &str) -> DomainStore {
            self.kv.store(name).await.unwrap()
        }

        fn json(&self) -> &Arc<JsonEngine> {
            self.json.as_ref().unwrap()
        }

        /// Backs `scope` up into `out` as `id` and returns the archive's path.
        async fn backup(&self, out: &Path, id: &str, scope: BackupScope, include_auth: bool) -> PathBuf {
            let resolved = resolve_scope(&scope, &self.control).unwrap();
            let params = BackupParams {
                dir: out,
                id,
                scope: &scope,
                include_auth,
                schedule: None,
                resolved: &resolved,
                control: &self.control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            };
            run_backup(params).await.unwrap();
            out.join(format!("{id}.ndjson"))
        }

        /// Restores the archive `id` in `out` into this instance, unthrottled.
        async fn restore(
            &self,
            out: &Path,
            id: &str,
            mode: RestoreMode,
            into_domain: Option<&str>,
            include_auth: bool,
        ) -> anyhow::Result<RestoreOutcome> {
            self.restore_throttled(out, id, mode, into_domain, include_auth, (500, 0)).await
        }

        /// [`Self::restore`] with a pause of `throttle.1` ms after every
        /// `throttle.0` entries.
        async fn restore_throttled(
            &self,
            out: &Path,
            id: &str,
            mode: RestoreMode,
            into_domain: Option<&str>,
            include_auth: bool,
            (scan_batch_size, scan_pause_ms): (usize, u64),
        ) -> anyhow::Result<RestoreOutcome> {
            let restore = run_restore(RestoreParams {
                dir: out,
                backup_id: id,
                mode,
                into_domain,
                include_auth,
                control: &self.control,
                scan_batch_size,
                scan_pause_ms,
            });
            // Upper bound against hanging only: a stalled purge holds a restore for minutes.
            compio::time::timeout(Duration::from_secs(10), restore).await.expect("the restore never ends")
        }

        /// Runs the purgers of this instance until the handle drops, so a
        /// deletion in `replace` mode finishes.
        fn purging(&self) -> compio::runtime::JoinHandle<()> {
            let kv_purger = DomainPurger::new(Arc::clone(self.kv.engine()), Arc::clone(&self.kv), 100);
            let json_purger = self.json.clone().map(|json| JsonDomainPurger::new(json, 100));
            compio::runtime::spawn(async move {
                loop {
                    let _ = kv_purger.purge_tick().await;
                    if let Some(purger) = &json_purger {
                        let _ = purger.purge_tick().await;
                    }
                    compio::time::sleep(Duration::from_millis(20)).await;
                }
            })
        }
    }

    /// Rewrites `path` from `body` plus a matching checksum line, so an
    /// edited archive verifies again (a hand-crafted archive is exactly the
    /// case the scan's own checks have to survive).
    fn reseal(path: &Path, body: &[String]) {
        let mut hasher = Sha256::new();
        for line in body {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        let checksum =
            json!({"t": "checksum", "sha256": hex::encode(hasher.finalize()), "lines": body.len() as u64});
        let mut content = body.join("\n");
        content.push('\n');
        content.push_str(&checksum.to_string());
        content.push('\n');
        std::fs::write(path, content).unwrap();
    }

    fn is_invalid_file(err: &anyhow::Error) -> bool {
        err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::InvalidBackupFile(_)))
    }

    // 1. Roundtrip: kv:<domain> export -> restore into an empty instance ->
    //    identical content, including TTL and a set_null entry.
    #[test]
    fn test_roundtrip_kv_domain() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            let store = src.store("shop").await;
            store.put(b"order:1", b"hello").await.unwrap();
            store.put_with_ttl(b"session", b"tok", 3600).await.unwrap();
            store.set_null(b"nulled").await.unwrap();
            // Values carry no UTF-8 guarantee -- exercise a genuinely binary
            // value, including a NUL byte.
            let binary_value: &[u8] = &[0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd];
            store.put(b"binary", binary_value).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_rt", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance(false).await;
            let outcome = dst.restore(out_dir.path(), "bk_rt", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!(outcome.imported, 4);
            assert_eq!(outcome.failed, 0);

            let restored = dst.store("shop").await;
            assert_eq!(restored.get(b"order:1").await.unwrap(), GetResult::Present(b"hello".to_vec()));
            assert_eq!(restored.get(b"nulled").await.unwrap(), GetResult::Null);
            assert_eq!(restored.get(b"binary").await.unwrap(), GetResult::Present(binary_value.to_vec()));
            let snapshot = dst.kv.engine().snapshot().await;
            let (result, expires_at) = restored.get_with_snapshot(b"session", snapshot.snapshot()).await.unwrap();
            assert_eq!(result, GetResult::Present(b"tok".to_vec()));
            assert!(expires_at > now_secs());
        })
    }

    // 2. Roundtrip: json:<domain> export -> restore -> documents and index
    //    definitions survive, and search over the restored index works.
    #[test]
    fn test_roundtrip_json_domain_with_index() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("catalog").await;
            src.json().create_index("catalog", "city", IndexFieldType::String).await.unwrap();
            src.json().put_document("catalog", "d1", json!({"city": "Lyon"})).await.unwrap();
            src.json().put_document("catalog", "d2", json!({"city": "Porto"})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_json", BackupScope::JsonDomain("catalog".to_string()), false).await;

            let dst = instance(true).await;
            let outcome = dst.restore(out_dir.path(), "bk_json", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!(outcome.imported, 2);
            assert_eq!(outcome.failed, 0);

            assert_eq!(dst.json().get_indexes("catalog").unwrap().len(), 1);
            let query = crate::engines::json::SearchQuery {
                filters: std::collections::HashMap::from([(
                    "city".to_string(),
                    crate::engines::json::FilterCondition::Eq(json!("Lyon")),
                )]),
                ..Default::default()
            };
            let found = dst.json().search_documents("catalog", query).await.unwrap();
            assert_eq!(found.total, 1, "search over the restored index must find the restored document");
        })
    }

    // 2b. Restore: an archive line for a legacy document that still carries
    //     a reserved top-level field (the kind of data a live write can no
    //     longer produce) counts as a per-line restore failure; the rest of
    //     the domain restores normally.
    #[test]
    fn test_restore_rejects_legacy_document_with_reserved_field() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("legacy").await;
            src.json().put_document("legacy", "ok", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path =
                src.backup(out_dir.path(), "bk_legacy", BackupScope::JsonDomain("legacy".to_string()), false).await;

            // Inject a second "doc" line with a reserved top-level field
            // directly into the archive and reseal the checksum.
            let content = std::fs::read_to_string(&path).unwrap();
            let mut body: Vec<String> = content
                .lines()
                .take_while(|l| !l.contains("\"t\":\"checksum\""))
                .map(String::from)
                .collect();
            let bad_doc = json!({
                "t": "doc", "domain": "legacy", "key": "bad", "version": 1,
                "content": {"_key": "smuggled", "n": 2},
            });
            body.push(bad_doc.to_string());
            reseal(&path, &body);

            let dst = instance(true).await;
            let outcome =
                dst.restore(out_dir.path(), "bk_legacy", RestoreMode::FailIfExists, None, false).await.unwrap();

            assert_eq!(outcome.imported, 1, "the clean document still restores");
            assert_eq!(outcome.failed, 1, "the reserved-field document is a restore failure, not a crash");
            assert!(dst.json().get_document("legacy", "ok").await.unwrap().is_some());
            assert!(dst.json().get_document("legacy", "bad").await.unwrap().is_none());
        })
    }

    // 3. Roundtrip: domain:<name> touches both engines.
    #[test]
    fn test_roundtrip_domain_scope_both_engines() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();
            src.json().put_document("shop", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_dom", BackupScope::Domain("shop".to_string()), false).await;

            let dst = instance(true).await;
            let outcome = dst.restore(out_dir.path(), "bk_dom", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!(outcome.imported, 2, "one kv pair + one document");
            assert!(dst.kv.get_domain("shop").await.unwrap().is_some());
            assert!(dst.json().get_domain("shop").is_some());
        })
    }

    // 3b. Roundtrip: `all` scope backs up every domain (incl. the default one
    //     a start creates) of both engines in a single archive. Since
    //     `all`/`kv` always include "default", and a fresh instance always has
    //     one too, `replace` mode is used here.
    #[test]
    fn test_roundtrip_all_scope() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("shop").await;
            src.store("default").await.put(b"root-key", b"root-val").await.unwrap();
            src.store("shop").await.put(b"k", b"v").await.unwrap();
            src.create("catalog").await;
            src.json().put_document("default", "d0", json!({"n": 0})).await.unwrap();
            src.json().put_document("catalog", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_all", BackupScope::All, false).await;

            let dst = instance(true).await;
            let _purging = dst.purging();
            let outcome = dst.restore(out_dir.path(), "bk_all", RestoreMode::Replace, None, false).await.unwrap();

            assert_eq!(outcome.imported, 4, "2 kv pairs + 2 documents");
            assert_eq!(dst.store("default").await.get(b"root-key").await.unwrap(), GetResult::Present(b"root-val".to_vec()));
            assert_eq!(dst.store("shop").await.get(b"k").await.unwrap(), GetResult::Present(b"v".to_vec()));
            assert!(dst.json().get_document("default", "d0").await.unwrap().is_some());
            assert!(dst.json().get_document("catalog", "d1").await.unwrap().is_some());
        })
    }

    // 4. Already-expired TTL entries are skipped on restore, not imported.
    #[test]
    fn test_expired_ttl_entry_is_skipped() {
        crate::core::engine_runtime::block_on(async {
            // The writer never exports an expired entry, so the archive is
            // written by hand with an expiry stamp long past.
            let out_dir = tempfile::TempDir::new().unwrap();
            let manifest = json!({
                "t": "manifest", "format_version": 2, "id": "bk_ttl", "created_at": 1_700_000_000u64,
                "luradb_version": "0.4.0", "scope": "kv:shop", "include_auth": false, "kv_snapshot_ts": 1,
                "json_snapshot_ts": 0, "encoding": "hex", "schedule": null, "shards": 1,
                "lsn_cut": {"kv": 1, "json": 0},
            });
            let domain = json!({"t": "kv-domain", "name": "shop", "created_at": 1_700_000_000u64});
            let entry = json!({
                "t": "kv", "domain": "shop", "k": hex::encode(b"soon-gone"), "v": hex::encode(b"v"),
                "expires_at": 1_700_000_001u64,
            });
            reseal(
                &out_dir.path().join("bk_ttl.ndjson"),
                &[manifest.to_string(), domain.to_string(), entry.to_string()],
            );

            let dst = instance(false).await;
            let outcome = dst.restore(out_dir.path(), "bk_ttl", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!(outcome.imported, 0);
            assert_eq!(outcome.skipped, 1);
            assert_eq!(dst.store("shop").await.get(b"soon-gone").await.unwrap(), GetResult::Absent);
        })
    }

    // 5. Checksum: a corrupted/truncated archive is rejected before any write.
    #[test]
    fn test_corrupted_checksum_rejected() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_bad", BackupScope::KvDomain("shop".to_string()), false).await;

            let mut content = std::fs::read_to_string(&path).unwrap();
            content = content.replace("\"k\":\"6b\"", "\"k\":\"6c\""); // flip the exported key's hex
            std::fs::write(&path, content).unwrap();

            let dst = instance(false).await;
            let err = dst.restore(out_dir.path(), "bk_bad", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(is_invalid_file(&err));
            assert!(dst.kv.get_domain("shop").await.unwrap().is_none(), "target must stay untouched");
        })
    }

    // 5b. A truncated archive (no checksum line at all) is "incomplete" and refused.
    #[test]
    fn test_missing_checksum_line_rejected() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_trunc", BackupScope::KvDomain("shop".to_string()), false).await;
            let content = std::fs::read_to_string(&path).unwrap();
            let truncated: String = content.lines().take_while(|l| !l.contains("\"checksum\"")).collect::<Vec<_>>().join("\n");
            std::fs::write(&path, truncated + "\n").unwrap();

            let dst = instance(false).await;
            let err = dst.restore(out_dir.path(), "bk_trunc", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(is_invalid_file(&err));
        })
    }

    // 6a. fail_if_exists aborts before the first write when a target domain
    //     already exists; the target is left completely unchanged.
    #[test]
    fn test_fail_if_exists_aborts_before_first_write() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k1", b"v1").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_exists", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance(false).await;
            dst.create("shop").await;
            dst.store("shop").await.put(b"pre-existing", b"untouched").await.unwrap();

            let err =
                dst.restore(out_dir.path(), "bk_exists", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::DomainExists(_))));

            let store = dst.store("shop").await;
            assert_eq!(store.get(b"pre-existing").await.unwrap(), GetResult::Present(b"untouched".to_vec()));
            assert_eq!(store.get(b"k1").await.unwrap(), GetResult::Absent, "no data from the archive must land");
        })
    }

    // 6b. replace clears the target domain's part of the archive's engine,
    //     importing the archive's content only (old content is gone).
    #[test]
    fn test_replace_mode_wipes_target_first() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"new-key", b"new-val").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_replace", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance(false).await;
            dst.create("shop").await;
            dst.store("shop").await.put(b"old-key", b"old-val").await.unwrap();

            let _purging = dst.purging();
            let outcome = dst.restore(out_dir.path(), "bk_replace", RestoreMode::Replace, None, false).await.unwrap();
            assert_eq!(outcome.imported, 1);

            let store = dst.store("shop").await;
            assert_eq!(store.get(b"new-key").await.unwrap(), GetResult::Present(b"new-val".to_vec()));
            assert_eq!(store.get(b"old-key").await.unwrap(), GetResult::Absent, "replace must wipe the old content");
        })
    }

    // 6c. replace mode also wipes the JSON part of an existing target
    //     domain first (mirrors test 6b for the JSON engine's own purger).
    #[test]
    fn test_replace_mode_wipes_json_target_first() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("catalog").await;
            src.json().put_document("catalog", "new", json!({"n": 2})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_jreplace", BackupScope::JsonDomain("catalog".to_string()), false).await;

            let dst = instance(true).await;
            dst.create("catalog").await;
            dst.json().put_document("catalog", "old", json!({"n": 1})).await.unwrap();

            let _purging = dst.purging();
            let outcome = dst.restore(out_dir.path(), "bk_jreplace", RestoreMode::Replace, None, false).await.unwrap();
            assert_eq!(outcome.imported, 1);

            assert!(dst.json().get_document("catalog", "new").await.unwrap().is_some());
            assert!(dst.json().get_document("catalog", "old").await.unwrap().is_none(), "replace must wipe the old content");
        })
    }

    // 6d. replace also waits for a purge another engine still runs on the
    //     target domain: a key-value replace beside a JSON clear ends only
    //     once the JSON part is back.
    #[test]
    fn test_replace_mode_waits_for_the_purge_of_another_engine() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();
            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_kv", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance(true).await;
            dst.create("shop").await;
            dst.control.clear_engine(Engine::Json, "shop", None).await.unwrap();
            let kv_purger = DomainPurger::new(Arc::clone(dst.kv.engine()), Arc::clone(&dst.kv), 100);
            let kv_purging = compio::runtime::spawn(async move {
                loop {
                    let _ = kv_purger.purge_tick().await;
                    compio::time::sleep(Duration::from_millis(20)).await;
                }
            });
            let mut restore = std::pin::pin!(dst.restore(out_dir.path(), "bk_kv", RestoreMode::Replace, None, false));
            // Nothing purges the JSON part yet: the restore cannot end, whatever the bound.
            let early = compio::time::timeout(Duration::from_secs(2), restore.as_mut()).await;
            assert!(early.is_err(), "the restore ended while the JSON part was still being purged");

            drop(kv_purging);
            let _purging = dst.purging();
            assert_eq!(restore.await.unwrap().imported, 1);
            assert_eq!(dst.store("shop").await.get(b"k").await.unwrap(), GetResult::Present(b"v".to_vec()));
        })
    }

    // 7. into_domain remaps kv:<domain>/json:<domain>; domain:<name> remaps
    //    the name in both engines at once.
    #[test]
    fn test_into_domain_remap_single_engine() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_remap", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance(false).await;
            let outcome = dst
                .restore(out_dir.path(), "bk_remap", RestoreMode::FailIfExists, Some("shop-restored"), false)
                .await
                .unwrap();
            assert_eq!(outcome.imported, 1);
            assert!(dst.kv.get_domain("shop").await.unwrap().is_none());
            assert_eq!(dst.store("shop-restored").await.get(b"k").await.unwrap(), GetResult::Present(b"v".to_vec()));
        })
    }

    #[test]
    fn test_into_domain_remap_domain_scope_both_engines() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();
            src.json().put_document("shop", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_remap2", BackupScope::Domain("shop".to_string()), false).await;

            let dst = instance(true).await;
            dst.restore(out_dir.path(), "bk_remap2", RestoreMode::FailIfExists, Some("shop2"), false).await.unwrap();

            assert!(dst.kv.get_domain("shop2").await.unwrap().is_some());
            assert!(dst.json().get_domain("shop2").is_some());
            assert!(dst.kv.get_domain("shop").await.unwrap().is_none());
            assert!(dst.json().get_domain("shop").is_none());
        })
    }

    // 7b. into_domain on a multi-domain archive -> RemapRequiresSingleDomain.
    #[test]
    fn test_into_domain_rejects_multi_domain_archive() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("a").await;
            src.create("b").await;
            src.store("a").await.put(b"k", b"v").await.unwrap();
            src.store("b").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_multi", BackupScope::Kv, false).await;

            let dst = instance(false).await;
            let err = dst
                .restore(out_dir.path(), "bk_multi", RestoreMode::FailIfExists, Some("only-one"), false)
                .await
                .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::RemapRequiresSingleDomain)));
        })
    }

    // 8. include_auth=false (default) ignores auth lines even if present;
    //    true upserts them.
    #[test]
    fn test_include_auth_opt_in() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            let system = src.control.system_store();
            let record = UserRecord {
                name: "alice".to_string(),
                api_key_hash: "deadbeef".to_string(),
                role: crate::auth::UserRole::User,
                created_at: now_secs(),
            };
            system.put(b"__sys:auth:user:alice", &serde_json::to_vec(&record).unwrap()).await.unwrap();
            let perm = DomainPermission { username: "alice".to_string(), domain: "shop".to_string(), access: crate::auth::AccessLevel::Read };
            system
                .put(format!("{PREFIX_PERM}alice:shop").as_bytes(), &serde_json::to_vec(&perm).unwrap())
                .await
                .unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_auth", BackupScope::All, true).await;

            // A scope="all" archive always contains "default" (every start
            // creates it), so restoring into a fresh instance needs `replace`
            // -- `fail_if_exists` would legitimately reject it.
            async fn replace_restore(out_dir: &Path, include_auth: bool) -> (Instance, RestoreOutcome) {
                let dst = instance(false).await;
                let purging = dst.purging();
                let outcome = dst.restore(out_dir, "bk_auth", RestoreMode::Replace, None, include_auth).await.unwrap();
                drop(purging);
                (dst, outcome)
            }

            // Default (false): auth lines are ignored.
            let (dst, _) = replace_restore(out_dir.path(), false).await;
            assert!(dst.control.system_store().get(b"__sys:auth:user:alice").await.unwrap().is_none());

            // true: auth lines are upserted into the system store.
            let (dst, outcome) = replace_restore(out_dir.path(), true).await;
            assert!(outcome.imported >= 2, "kv default domain data + 2 auth records");
            let system = dst.control.system_store();
            let raw = system.get(b"__sys:auth:user:alice").await.unwrap().unwrap();
            let restored: UserRecord = serde_json::from_slice(&raw).unwrap();
            assert_eq!(restored.api_key_hash, "deadbeef");
            assert!(system.get(format!("{PREFIX_PERM}alice:shop").as_bytes()).await.unwrap().is_some());
            assert!(dst.kv.engine().get(b"__sys:auth:user:alice").await.unwrap().is_none(), "nothing lands in the KV engine");
        })
    }

    // 8a. An archive of format version 1, written before the system store
    //     existed — the auth lines are the same — restores its auth records
    //     into the system store.
    #[test]
    fn test_older_archive_restores_auth_into_the_system_store() {
        crate::core::engine_runtime::block_on(async {
            let out_dir = tempfile::TempDir::new().unwrap();
            let path = out_dir.path().join("bk_old.ndjson");
            let manifest = json!({
                "t": "manifest", "format_version": 1, "id": "bk_old", "created_at": 1_700_000_000u64,
                "luradb_version": "0.4.0", "scope": "kv", "include_auth": true, "kv_snapshot_ts": 1,
                "json_snapshot_ts": 0, "encoding": "hex", "schedule": null,
            });
            let user = json!({"t": "auth-user", "name": "zoé", "api_key_hash": "f00d", "role": "User", "created_at": 1});
            let perm = json!({"t": "auth-perm", "username": "zoé", "domain": "json:shop", "access": "Write"});
            reseal(&path, &[manifest.to_string(), user.to_string(), perm.to_string()]);

            let dst = instance(false).await;
            let outcome = dst.restore(out_dir.path(), "bk_old", RestoreMode::FailIfExists, None, true).await.unwrap();

            assert_eq!((outcome.imported, outcome.failed), (2, 0));
            let system = dst.control.system_store();
            assert!(system.get("__sys:auth:user:zoé".as_bytes()).await.unwrap().is_some());
            assert!(system.get("__sys:auth:perm:zoé:json:shop".as_bytes()).await.unwrap().is_some());
            assert!(dst.kv.engine().scan_keys(b"__sys:auth:").await.unwrap().is_empty());
            assert_eq!(dst.auth.get_user_by_name("zoé").await.unwrap().api_key_hash, "f00d", "the cache knows the user");
            let json = Some(crate::control::Engine::Json);
            assert_eq!(dst.auth.effective("zoé", "shop", json).await, Some(crate::auth::AccessLevel::Write));
            assert_eq!(dst.auth.effective("zoé", "shop", Some(crate::control::Engine::Kv)).await, None);
        })
    }

    /// The permission keys of `dst`'s system store, without their prefix.
    async fn stored_permissions(dst: &Instance) -> Vec<String> {
        let keys = dst.control.system_store().scan_keys(PREFIX_PERM.as_bytes()).await.unwrap();
        keys.iter().map(|key| String::from_utf8_lossy(&key[PREFIX_PERM.len()..]).into_owned()).collect()
    }

    fn perm_line(domain: &str, access: &str) -> Value {
        json!({"t": "auth-perm", "username": "zoé", "domain": domain, "access": access})
    }

    // A version 2 archive, from before whole-domain grants, holds key-value
    // grants without a prefix: they come back as key-value grants only.
    #[test]
    fn a_v2_archive_grant_without_a_prefix_stays_a_key_value_grant() {
        crate::core::engine_runtime::block_on(async {
            let out_dir = tempfile::TempDir::new().unwrap();
            v2_archive(&out_dir.path().join("bk_v2.ndjson"), "kv", &[perm_line("shop", "Write")]);
            let dst = instance(false).await;
            let outcome = dst.restore(out_dir.path(), "bk_v2", RestoreMode::FailIfExists, None, true).await.unwrap();

            assert_eq!((outcome.imported, outcome.failed), (1, 0));
            assert_eq!(stored_permissions(&dst).await, ["zoé:shop"]);
            let level = |engine| dst.auth.effective("zoé", "shop", Some(engine));
            assert_eq!(level(Engine::Kv).await, Some(crate::auth::AccessLevel::Write));
            assert_eq!(level(Engine::Json).await, None);
            assert_eq!(level(Engine::Rel).await, None);
        })
    }

    // A grant on the whole domain goes into the archive under its own key
    // and comes back as one.
    #[test]
    fn a_domain_grant_goes_through_a_backup_and_back() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            let grant = AuthChange::SetPermission {
                username: "zoé".to_string(),
                domain: "shop".to_string(),
                engine: None,
                access: crate::auth::AccessLevel::Write,
            };
            src.control.change_auth(grant).await.unwrap();
            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_domain_grant", BackupScope::All, true).await;
            assert!(std::fs::read_to_string(path).unwrap().contains(r#""domain":"domain:shop""#));

            let dst = instance(false).await;
            let purging = dst.purging();
            dst.restore(out_dir.path(), "bk_domain_grant", RestoreMode::Replace, None, true).await.unwrap();
            drop(purging);
            assert_eq!(stored_permissions(&dst).await, ["zoé:domain:shop"]);
            assert_eq!(dst.auth.effective("zoé", "shop", Some(Engine::Rel)).await, Some(crate::auth::AccessLevel::Write));
        })
    }

    // An archive with a grant on the whole domain and one on an engine of the
    // same user restores as the two requests would set them, in archive
    // order: never both kinds side by side.
    #[test]
    fn a_restore_leaves_a_user_either_a_domain_grant_or_engine_grants() {
        crate::core::engine_runtime::block_on(async {
            let cases = [
                ([perm_line("domain:shop", "Read"), perm_line("json:shop", "Write")], vec!["zoé:json:shop", "zoé:rel:shop", "zoé:shop"]),
                ([perm_line("json:shop", "Write"), perm_line("domain:shop", "Read")], vec!["zoé:domain:shop"]),
            ];
            for (lines, expected) in cases {
                let out_dir = tempfile::TempDir::new().unwrap();
                v2_archive(&out_dir.path().join("bk_v2.ndjson"), "kv", &lines);
                let dst = instance(false).await;
                let outcome = dst.restore(out_dir.path(), "bk_v2", RestoreMode::FailIfExists, None, true).await.unwrap();
                assert_eq!((outcome.imported, outcome.failed), (2, 0));
                assert_eq!(stored_permissions(&dst).await, expected);
            }
        })
    }

    // 9. Cross-check: backing up with include_auth=false never even writes
    //    auth lines (writer-side gate), independent of the restore-side gate
    //    tested above.
    #[test]
    fn test_backup_include_auth_false_excludes_auth_lines() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            let record = UserRecord {
                name: "bob".to_string(),
                api_key_hash: "cafe".to_string(),
                role: crate::auth::UserRole::Admin,
                created_at: now_secs(),
            };
            src.control.system_store().put(b"__sys:auth:user:bob", &serde_json::to_vec(&record).unwrap()).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_noauth", BackupScope::All, false).await;
            let content = std::fs::read_to_string(path).unwrap();
            assert!(!content.contains("auth-user"));
        })
    }

    // 10. ID-adjacent path safety: a backup_id containing traversal
    //     characters never resolves outside `dir` (defense in depth; HTTP
    //     400 mapping is the API layer's job).
    #[test]
    fn test_run_restore_rejects_traversal_like_id_via_missing_file() {
        crate::core::engine_runtime::block_on(async {
            let dst = instance(false).await;
            let out_dir = tempfile::TempDir::new().unwrap();
            let err = dst.restore(out_dir.path(), "../../etc/passwd", RestoreMode::FailIfExists, None, false).await;
            assert!(err.is_err(), "no such archive under dir -- open() fails, nothing is read");
        })
    }

    // 11. Batch throttling: many kv entries with a small scan_batch_size and
    //     a real pause still import everything correctly.
    #[test]
    fn test_restore_respects_small_batch_size() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            let store = src.store("shop").await;
            for i in 0..5 {
                store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_batch", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance(false).await;
            let outcome = dst
                .restore_throttled(out_dir.path(), "bk_batch", RestoreMode::FailIfExists, None, false, (2, 5))
                .await
                .unwrap();
            assert_eq!(outcome.imported, 5);
        })
    }

    // 12. Restore KV writes bypass the domain rate limiter (an admin
    //     maintenance operation): with a 1-write/s quota, all five entries
    //     still land instead of being dropped as per-entry failures.
    #[test]
    fn test_restore_bypasses_domain_rate_limiter() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            let store = src.store("shop").await;
            for i in 0..5 {
                store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_rl", BackupScope::KvDomain("shop".to_string()), false).await;

            let dst = instance_with(DomainConfig { default_write_iops: 1, ..DomainConfig::default() }, false).await;
            let outcome = dst.restore(out_dir.path(), "bk_rl", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!(outcome.imported, 5, "a 1-write/s quota must not drop restore entries");
            assert_eq!(outcome.failed, 0);
        })
    }

    // 13. Lines appended after the checksum line are outside the verified
    //     range -> the whole archive is invalid, nothing is applied.
    #[test]
    fn test_data_after_checksum_line_rejected() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_trail", BackupScope::KvDomain("shop".to_string()), false).await;
            let mut content = std::fs::read_to_string(&path).unwrap();
            content.push_str("{\"t\":\"kv\",\"domain\":\"shop\",\"k\":\"6578747261\",\"v\":\"6578747261\",\"expires_at\":0}\n");
            std::fs::write(&path, content).unwrap();

            let dst = instance(false).await;
            let err = dst.restore(out_dir.path(), "bk_trail", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(is_invalid_file(&err));
            assert!(dst.kv.get_domain("shop").await.unwrap().is_none(), "nothing must be applied");
        })
    }

    // 13b. Blank lines never occur in writer output; an injected one voids
    //      the byte-exact checksum guarantee and is rejected.
    #[test]
    fn test_blank_line_in_archive_rejected() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_blank", BackupScope::KvDomain("shop".to_string()), false).await;
            let content = std::fs::read_to_string(&path).unwrap();
            let mut file_lines: Vec<&str> = content.lines().collect();
            file_lines.insert(1, "");
            std::fs::write(&path, file_lines.join("\n") + "\n").unwrap();

            let dst = instance(false).await;
            let err = dst.restore(out_dir.path(), "bk_blank", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(is_invalid_file(&err));
        })
    }

    // 14. An archive carrying JSON sections cannot be restored without the
    //     JSON engine -- hard error instead of silently dropping that data.
    #[test]
    fn test_restore_json_archive_without_engine_rejected() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            src.create("catalog").await;
            src.json().put_document("catalog", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_nojson", BackupScope::JsonDomain("catalog".to_string()), false).await;

            let dst = instance(false).await;
            let err = dst.restore(out_dir.path(), "bk_nojson", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::JsonEngineDisabled)));
        })
    }

    // 15. A data line naming a domain the archive never declares is refused:
    //     the apply pass takes its target from the data line, so such an
    //     archive would write straight into a live domain, past both the
    //     fail_if_exists and the replace handling.
    #[test]
    fn test_data_line_for_undeclared_domain_rejected() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(false).await;
            src.create("shop").await;
            src.store("shop").await.put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = src.backup(out_dir.path(), "bk_undecl", BackupScope::KvDomain("shop".to_string()), false).await;

            // Retarget the data line at an undeclared domain (the declaration
            // line carries `name`, not `domain`, so it stays "shop") and reseal.
            let content = std::fs::read_to_string(&path).unwrap();
            let body: Vec<String> = content
                .lines()
                .take_while(|l| !l.contains("\"t\":\"checksum\""))
                .map(|l| l.replace("\"domain\":\"shop\"", "\"domain\":\"live\""))
                .collect();
            reseal(&path, &body);

            let dst = instance(false).await;
            dst.create("live").await;
            dst.store("live").await.put(b"production", b"untouched").await.unwrap();

            let err = dst.restore(out_dir.path(), "bk_undecl", RestoreMode::FailIfExists, None, false).await.unwrap_err();
            assert!(is_invalid_file(&err));

            let store = dst.store("live").await;
            assert_eq!(store.get(b"production").await.unwrap(), GetResult::Present(b"untouched".to_vec()));
            assert_eq!(store.get(b"k").await.unwrap(), GetResult::Absent, "no archive data must land");
        })
    }

    // 16. The reported error list is capped (it is kept in RAM for the
    //     process lifetime and serialized by GET /restores/{id}), while
    //     `failed` keeps counting every record.
    #[test]
    fn test_error_list_is_capped_and_labels_shortened() {
        let mut outcome = RestoreOutcome::default();
        for i in 0..MAX_REPORTED_ERRORS + 50 {
            outcome.fail(format!("key{i}"), "boom");
        }
        assert_eq!(outcome.failed, MAX_REPORTED_ERRORS as u64 + 50);
        assert_eq!(outcome.errors.len(), MAX_REPORTED_ERRORS);

        // A 3-byte char forces the cut off the byte cap onto a char boundary.
        let mut outcome = RestoreOutcome::default();
        outcome.fail("€".repeat(1000), "boom");
        assert!(outcome.errors[0].0.len() <= MAX_ERROR_KEY_LEN);
        assert!(outcome.errors[0].0.chars().all(|c| c == '€'));
    }

    // 17. The replace-mode wait on the purger is bounded: a purge that never
    //     finishes fails the restore instead of parking it (and its job slot)
    //     for the process lifetime.
    #[test]
    fn test_purge_wait_is_bounded() {
        crate::core::engine_runtime::block_on(async {
            let err = wait_for_purge("shop", Duration::from_millis(120), || false).await.unwrap_err();
            assert!(err.to_string().contains("still being purged"), "{err}");

            wait_for_purge("shop", Duration::from_millis(120), || true).await.unwrap();
        })
    }

    /// An archive of format version 2, written by hand: its manifest, then
    /// `lines`.
    fn v2_archive(path: &Path, scope: &str, lines: &[Value]) {
        let manifest = json!({
            "t": "manifest", "format_version": 2, "id": "bk_v2", "created_at": 1_700_000_000u64,
            "luradb_version": "0.5.0", "scope": scope, "include_auth": false, "kv_snapshot_ts": 1,
            "json_snapshot_ts": 1, "encoding": "hex", "schedule": null, "shards": 1, "lsn_cut": {"kv": 1, "json": 1},
        });
        let body: Vec<String> = std::iter::once(&manifest).chain(lines).map(Value::to_string).collect();
        reseal(path, &body);
    }

    fn setting_of(dst: &Instance, name: &str) -> ConditionalWrites {
        dst.control.directory().get(name).expect("the domain exists").require_conditional_writes
    }

    // A version 3 archive carries require_conditional_writes of each engine
    // into the domain it creates.
    #[test]
    fn a_v3_archive_restores_the_conditional_writes_setting() {
        crate::core::engine_runtime::block_on(async {
            let src = instance(true).await;
            let setting = ConditionalWrites { kv: true, json: false };
            src.control.create_domain("strict", setting).await.unwrap();
            let out_dir = tempfile::TempDir::new().unwrap();
            src.backup(out_dir.path(), "bk_rcw", BackupScope::Domain("strict".to_string()), false).await;

            let dst = instance(true).await;
            dst.restore(out_dir.path(), "bk_rcw", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!(setting_of(&dst, "strict"), setting);
            assert!(dst.kv.get_domain("strict").await.unwrap().unwrap().require_conditional_writes);
            assert!(!dst.json().get_domain("strict").unwrap().require_conditional_writes);
        })
    }

    // The domain lines of one name in a version 2 archive, one per engine,
    // become one domain, without conditional writes.
    #[test]
    fn a_v2_archive_with_domain_lines_per_engine_restores_one_domain() {
        crate::core::engine_runtime::block_on(async {
            let out_dir = tempfile::TempDir::new().unwrap();
            v2_archive(
                &out_dir.path().join("bk_v2.ndjson"),
                "domain:shop",
                &[
                    json!({"t": "kv-domain", "name": "shop", "created_at": 1}),
                    json!({"t": "kv", "domain": "shop", "k": hex::encode("clé"), "v": hex::encode(b"v"), "expires_at": 0}),
                    json!({"t": "json-domain", "name": "shop", "created_at": 1}),
                    json!({"t": "doc", "domain": "shop", "key": "d", "version": 1, "content": {"n": 1}}),
                ],
            );
            let dst = instance(true).await;
            let outcome = dst.restore(out_dir.path(), "bk_v2", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert_eq!((outcome.imported, outcome.failed), (2, 0));
            let names: Vec<_> = dst.control.directory().domains().map(|d| d.name.clone()).collect();
            assert_eq!(names, ["default", "shop"]);
            assert_eq!(setting_of(&dst, "shop"), ConditionalWrites::default());
            assert_eq!(dst.store("shop").await.get("clé".as_bytes()).await.unwrap(), GetResult::Present(b"v".to_vec()));
            assert!(dst.json().get_document("shop", "d").await.unwrap().is_some());
        })
    }

    // A domain line of an engine that is off is no reason to abort; its
    // data would be.
    #[test]
    fn a_domain_line_of_a_disabled_engine_does_not_abort_the_restore() {
        crate::core::engine_runtime::block_on(async {
            let out_dir = tempfile::TempDir::new().unwrap();
            let lines = [
                json!({"t": "kv-domain", "name": "shop", "created_at": 1}),
                json!({"t": "json-domain", "name": "shop", "created_at": 1}),
            ];
            v2_archive(&out_dir.path().join("bk_v2.ndjson"), "domain:shop", &lines);
            let dst = instance(false).await;
            dst.restore(out_dir.path(), "bk_v2", RestoreMode::FailIfExists, None, false).await.unwrap();
            assert!(dst.kv.get_domain("shop").await.unwrap().is_some());

            let doc = json!({"t": "doc", "domain": "shop", "key": "d", "version": 1, "content": {"n": 1}});
            v2_archive(&out_dir.path().join("bk_v2.ndjson"), "domain:shop", &[lines[0].clone(), lines[1].clone(), doc]);
            let err = dst.restore(out_dir.path(), "bk_v2", RestoreMode::Replace, None, false).await.unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::JsonEngineDisabled)));
        })
    }

    // Replacing from a version 2 archive keeps the replaced engine's
    // conditional-writes setting; a version 3 archive brings its own.
    #[test]
    fn a_replace_from_a_v2_archive_keeps_the_conditional_writes_setting() {
        crate::core::engine_runtime::block_on(async {
            let out_dir = tempfile::TempDir::new().unwrap();
            let kv_line = json!({"t": "kv", "domain": "strict", "k": hex::encode(b"k"), "v": hex::encode(b"v"), "expires_at": 0});
            v2_archive(
                &out_dir.path().join("bk_v2.ndjson"),
                "kv:strict",
                &[json!({"t": "kv-domain", "name": "strict", "created_at": 1}), kv_line],
            );
            let dst = instance(false).await;
            dst.control.create_domain("strict", ConditionalWrites { kv: true, json: true }).await.unwrap();
            let _purging = dst.purging();
            dst.restore(out_dir.path(), "bk_v2", RestoreMode::Replace, None, false).await.unwrap();
            assert_eq!(setting_of(&dst, "strict"), ConditionalWrites { kv: true, json: true });
            let store = dst.store("strict").await;
            assert!(store.domain().require_conditional_writes);
            assert_eq!(store.get(b"k").await.unwrap(), GetResult::Present(b"v".to_vec()));

            let src = instance(false).await;
            src.create("strict").await;
            src.backup(out_dir.path(), "bk_v3", BackupScope::KvDomain("strict".to_string()), false).await;
            dst.restore(out_dir.path(), "bk_v3", RestoreMode::Replace, None, false).await.unwrap();
            assert_eq!(setting_of(&dst, "strict"), ConditionalWrites { kv: false, json: true });
            assert!(!dst.store("strict").await.domain().require_conditional_writes);
        })
    }
}
