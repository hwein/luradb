//! Restore pipeline (spec general/006): a full checksum-verification pass,
//! domain preparation (`fail_if_exists`/`replace`), then a streaming apply
//! pass in archive order (domains already exist by then -> indexes -> data).

use super::writer::{
    maybe_pause, ChecksumLine, DocLine, JsonDomainLine, JsonIndexLine, KvDomainLine, KvLine, ManifestLine,
    FORMAT_VERSION,
};
use super::{BackupError, MAX_LINE_BYTES};
use crate::auth::{DomainPermission, UserRecord};
use crate::control::{AuthChange, ControlPlane, Engine};
use crate::engines::json::{JsonDomainState, JsonEngine};
use crate::engines::lsm::domain::{now_secs, DomainRegistry, DomainStore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use crate::core::engine_runtime;
use std::time::{Duration, Instant};

/// Poll interval while waiting for the domain purger to finalize a deletion
/// in `replace` mode. The purger itself runs as an independent background
/// task (spec general/003 pattern); this loop only observes its progress.
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
    pub kv_registry: &'a Arc<DomainRegistry>,
    pub json_engine: &'a Option<Arc<JsonEngine>>,
    /// Creates and deletes the target domains and takes the auth records as
    /// auth changes.
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
/// replace) every target domain, then stream-apply the data. Per-entry
/// failures are counted in the returned [`RestoreOutcome`] and the job keeps
/// going; an `Err` here means an engine-level failure aborted the whole job
/// (spec general/006: engine errors abort the restore).
pub(crate) async fn run_restore(params: RestoreParams<'_>) -> anyhow::Result<RestoreOutcome> {
    let path = params.dir.join(format!("{}.ndjson", params.backup_id));

    let scan = verify_and_scan(&path).await?;
    // An archive with JSON sections cannot be applied without the JSON
    // engine — silently dropping those sections would be data loss.
    if !scan.json_domains.is_empty() && params.json_engine.is_none() {
        return Err(BackupError::JsonEngineDisabled.into());
    }
    let remap = build_remap(params.into_domain, &scan)?;

    prepare_domains(&scan, params.mode, &remap, params.kv_registry, params.json_engine, params.control).await?;

    apply_pass(&path, &remap, &params).await
}

// ── Pass 1: checksum verification + domain-name collection ─────────────

pub(crate) struct ArchiveScan {
    kv_domains: Vec<String>,
    json_domains: Vec<String>,
    /// Exposed for the upload endpoint's "manifest fields" response (spec
    /// general/006 POST /backups/upload) — restore itself only needs the
    /// domain-name lists above.
    pub(crate) manifest: ManifestLine,
}

/// Full read pass (spec general/006: a complete read pass ahead of any
/// write): verifies the SHA-256 checksum line and, along the way, collects
/// every kv-domain/json-domain name — needed up front so `fail_if_exists`/
/// `replace` and the `into_domain` single-name check can run before any
/// write in pass 2. Data lines naming an undeclared domain are rejected
/// here: the apply pass takes its target from the data line, so an archive
/// could otherwise write past those checks into a live domain. Also reused
/// as-is by the upload endpoint's validation pass (`crate::api::backup`),
/// which only needs the checksum/manifest check.
pub(crate) async fn verify_and_scan(path: &Path) -> anyhow::Result<ArchiveScan> {
    let mut reader = ArchiveReader::open(path).await?;

    let mut hasher = Sha256::new();
    let mut line_count: u64 = 0;
    let mut kv_domains: Vec<String> = Vec::new();
    let mut json_domains: Vec<String> = Vec::new();
    let mut kv_refs: HashSet<String> = HashSet::new();
    let mut json_refs: HashSet<String> = HashSet::new();
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
            if manifest.format_version != FORMAT_VERSION {
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
                kv_domains.push(line.name);
            }
            "json-domain" => {
                let line: JsonDomainLine = parse_line(value)?;
                json_domains.push(line.name);
            }
            "kv" => collect_ref(&value, &mut kv_refs),
            "doc" | "json-index" => collect_ref(&value, &mut json_refs),
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

    Ok(ArchiveScan {
        kv_domains,
        json_domains,
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

/// Validates `into_domain` (spec general/006: only legal when the archive
/// contains exactly one domain *name*, counting kv/json together — a
/// `domain:*` export has the same name in both sections) and returns the
/// `(archived_name, target_name)` substitution to apply everywhere.
fn build_remap(into_domain: Option<&str>, scan: &ArchiveScan) -> anyhow::Result<Option<(String, String)>> {
    let Some(target) = into_domain else { return Ok(None) };

    let mut names: HashSet<&str> = HashSet::new();
    for name in &scan.kv_domains {
        names.insert(name.as_str());
    }
    for name in &scan.json_domains {
        names.insert(name.as_str());
    }
    if names.len() != 1 {
        return Err(BackupError::RemapRequiresSingleDomain.into());
    }
    let only = *names.iter().next().unwrap();
    Ok(Some((only.to_string(), target.to_string())))
}

fn remapped<'a>(remap: &'a Option<(String, String)>, archived_name: &'a str) -> &'a str {
    match remap {
        Some((from, to)) if from == archived_name => to,
        _ => archived_name,
    }
}

// ── Domain preparation ───────────────────────────────────────────────────

/// Phase A (checks / replace-deletes only, no domain is created yet) then
/// Phase B (create every target domain) — kept as two full sweeps so
/// `fail_if_exists` truly aborts before the first write: if any domain in
/// phase A already exists, we return before phase B ever runs.
async fn prepare_domains(
    scan: &ArchiveScan,
    mode: RestoreMode,
    remap: &Option<(String, String)>,
    kv_registry: &Arc<DomainRegistry>,
    json_engine: &Option<Arc<JsonEngine>>,
    control: &ControlPlane,
) -> anyhow::Result<()> {
    for name in &scan.kv_domains {
        ready_kv_domain(remapped(remap, name), mode, kv_registry, control).await?;
    }
    if let Some(json) = json_engine {
        for name in &scan.json_domains {
            ready_json_domain(remapped(remap, name), mode, json, control).await?;
        }
    }

    for name in &scan.kv_domains {
        control.create_domain(Engine::Kv, remapped(remap, name), false).await?;
    }
    if json_engine.is_some() {
        for name in &scan.json_domains {
            control.create_domain(Engine::Json, remapped(remap, name), false).await?;
        }
    }

    Ok(())
}

async fn ready_kv_domain(
    target: &str,
    mode: RestoreMode,
    kv_registry: &Arc<DomainRegistry>,
    control: &ControlPlane,
) -> anyhow::Result<()> {
    let active = kv_registry.get_domain(target).await?;
    let deleting = kv_registry.list_deleting_domains().into_iter().any(|d| d.name == target);
    match mode {
        RestoreMode::FailIfExists => {
            if active.is_some() || deleting {
                return Err(BackupError::DomainExists(target.to_string()).into());
            }
            Ok(())
        }
        RestoreMode::Replace => {
            if active.is_some() {
                control.delete_domain(Engine::Kv, target).await?;
                wait_for_kv_domain_gone(target, kv_registry).await?;
            } else if deleting {
                wait_for_kv_domain_gone(target, kv_registry).await?;
            }
            Ok(())
        }
    }
}

async fn wait_for_kv_domain_gone(name: &str, kv_registry: &Arc<DomainRegistry>) -> anyhow::Result<()> {
    wait_for_purge(name, PURGE_WAIT_TIMEOUT, || {
        !kv_registry.list_deleting_domains().into_iter().any(|d| d.name == name)
    })
    .await
}

async fn ready_json_domain(
    target: &str,
    mode: RestoreMode,
    json: &Arc<JsonEngine>,
    control: &ControlPlane,
) -> anyhow::Result<()> {
    let existing = json.get_domain_any(target);
    match mode {
        RestoreMode::FailIfExists => {
            if existing.is_some() {
                return Err(BackupError::DomainExists(target.to_string()).into());
            }
            Ok(())
        }
        RestoreMode::Replace => {
            match existing {
                Some(d) if d.state == JsonDomainState::Active => {
                    control.delete_domain(Engine::Json, target).await?;
                    wait_for_json_domain_gone(target, json).await?;
                }
                Some(_) => wait_for_json_domain_gone(target, json).await?,
                None => {}
            }
            Ok(())
        }
    }
}

async fn wait_for_json_domain_gone(name: &str, json: &Arc<JsonEngine>) -> anyhow::Result<()> {
    wait_for_purge(name, PURGE_WAIT_TIMEOUT, || {
        !matches!(json.get_domain_any(name), Some(d) if d.state == JsonDomainState::Deleting)
    })
    .await
}

/// Polls `is_gone` until the purger finished the deletion. Bounded by
/// `timeout`: a stalled purger must not park the restore (and its job slot)
/// for the process lifetime.
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

// ── Pass 2: streaming apply ─────────────────────────────────────────────

/// Streams the archive top to bottom and applies each line. Domains/indexes
/// are already prepared, so `kv-domain`/`json-domain`/`manifest`/`checksum`
/// lines are no-ops here. KV writes are throttled individually (a pause
/// every `scan_batch_size` entries); JSON documents are grouped into
/// per-domain batches and imported via [`JsonEngine::bulk_load`] (spec:
/// index entries are maintained synchronously, like `load_batch`), flushed
/// on a domain change, a full batch, or end of stream.
async fn apply_pass(
    path: &Path,
    remap: &Option<(String, String)>,
    params: &RestoreParams<'_>,
) -> anyhow::Result<RestoreOutcome> {
    let RestoreParams { include_auth, kv_registry, json_engine, control, scan_batch_size, scan_pause_ms, .. } = *params;
    let mut reader = ArchiveReader::open(path).await?;
    let mut line: Vec<u8> = Vec::new();

    let mut outcome = RestoreOutcome::default();
    let now = now_secs();

    let mut kv_stores: HashMap<String, DomainStore> = HashMap::new();
    let mut kv_count: usize = 0;

    let mut doc_domain: Option<String> = None;
    let mut doc_batch: Vec<(Option<String>, Value)> = Vec::new();

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
                    let store = kv_registry.store(&target).await?;
                    kv_stores.insert(target.clone(), store);
                }
                let store = kv_stores.get(&target).unwrap();
                apply_kv_line(store, &line, now, &mut outcome).await;
                maybe_pause(kv_count, scan_batch_size, scan_pause_ms).await;
                kv_count += 1;
            }
            "json-index" => {
                flush_doc_batch(&mut doc_domain, &mut doc_batch, json_engine, &mut outcome).await?;
                if let Some(json) = json_engine {
                    let line: JsonIndexLine = match serde_json::from_value(value) {
                        Ok(l) => l,
                        Err(e) => {
                            outcome.fail("json-index", format!("malformed index line: {e}"));
                            continue;
                        }
                    };
                    let target = remapped(remap, &line.domain).to_string();
                    if let Err(e) = json.create_index(&target, &line.field, line.field_type).await {
                        outcome.fail(format!("{target}.{}", line.field), e.to_string());
                    }
                }
            }
            "doc" => {
                if json_engine.is_some() {
                    let line: DocLine = match serde_json::from_value(value) {
                        Ok(l) => l,
                        Err(e) => {
                            outcome.fail("doc", format!("malformed doc line: {e}"));
                            continue;
                        }
                    };
                    let target = remapped(remap, &line.domain).to_string();
                    if doc_domain.as_deref() != Some(target.as_str()) {
                        flush_doc_batch(&mut doc_domain, &mut doc_batch, json_engine, &mut outcome).await?;
                        doc_domain = Some(target);
                    }
                    doc_batch.push((Some(line.key), line.content));
                    if doc_batch.len() >= scan_batch_size.max(1) {
                        flush_doc_batch(&mut doc_domain, &mut doc_batch, json_engine, &mut outcome).await?;
                        compio::time::sleep(Duration::from_millis(scan_pause_ms)).await;
                    }
                }
            }
            "auth-user" => {
                flush_doc_batch(&mut doc_domain, &mut doc_batch, json_engine, &mut outcome).await?;
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

    flush_doc_batch(&mut doc_domain, &mut doc_batch, json_engine, &mut outcome).await?;
    Ok(outcome)
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

/// Flushes the buffered per-domain document batch via `bulk_load`. An `Err`
/// here is an engine-level failure and aborts the restore job; per-document
/// validation issues are already folded into `BulkLoadResult` and do not
/// propagate.
async fn flush_doc_batch(
    domain: &mut Option<String>,
    batch: &mut Vec<(Option<String>, Value)>,
    json_engine: &Option<Arc<JsonEngine>>,
    outcome: &mut RestoreOutcome,
) -> anyhow::Result<()> {
    if batch.is_empty() {
        *domain = None;
        return Ok(());
    }
    let dom = domain.take().expect("a non-empty batch always has its domain set");
    let items = std::mem::take(batch);
    if let Some(json) = json_engine {
        let result = json.bulk_load(&dom, items).await?;
        outcome.imported += result.imported;
        outcome.failed += result.failed;
        let room = MAX_REPORTED_ERRORS.saturating_sub(outcome.errors.len());
        outcome.errors.extend(result.errors.into_iter().take(room));
    }
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
    match control.change_auth(AuthChange::SetPermission(perm)).await {
        Ok(()) => outcome.imported += 1,
        Err(e) => outcome.fail(label, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::PREFIX_PERM;
    use crate::backup::writer::{self, resolve_scope, BackupParams, ResolvedScope};
    use crate::backup::BackupScope;
    use crate::config::JsonStoreConfig;
    use crate::engines::json::IndexFieldType;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
    use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
    use crate::engines::lsm::reader::GetResult;
    use crate::engines::json::JsonDomainPurger;
    use crate::engines::StorageEngine;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use crate::core::wal::WriteAheadLog;
    use serde_json::json;
    use std::sync::atomic::AtomicBool;

    async fn make_kv_registry() -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        make_kv_registry_with_config(DomainConfig::default()).await
    }

    async fn make_kv_registry_with_config(
        config: DomainConfig,
    ) -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, LsmEngineOptions::default())
                .await
                .unwrap(),
        );
        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry =
            Arc::new(DomainRegistry::recover(Arc::clone(&engine), config, metrics).await.unwrap());
        (engine, registry, dir)
    }

    async fn make_json_engine() -> (Arc<JsonEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        };
        let metrics = MetricsStore::new(MetricsConfig::default());
        (JsonEngine::bootstrap(&config, metrics).await.unwrap(), dir)
    }

    /// The system store of the instance whose files are in `dir`.
    async fn system_store(dir: &tempfile::TempDir) -> Arc<LsmStorageEngine> {
        crate::control::system::open(&dir.path().join("sys")).await.unwrap()
    }

    /// A control plane over `kv` and `json`, with its system store in `dir`.
    async fn control_over(
        dir: &tempfile::TempDir,
        kv: &Arc<DomainRegistry>,
        json: &Option<Arc<JsonEngine>>,
    ) -> Arc<ControlPlane> {
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(16, 16));
        crate::control::testing::start(dir.path(), Arc::clone(kv), json.clone(), None, bus).await.0
    }

    /// Runs a backup of `scope` from `kv`/`json`, auth from `system`, into
    /// `out_dir`, returning the archive's path.
    async fn make_backup(
        out_dir: &Path,
        id: &str,
        scope: BackupScope,
        include_auth: bool,
        kv: &Arc<DomainRegistry>,
        json: &Option<Arc<JsonEngine>>,
        system: &Arc<LsmStorageEngine>,
    ) -> std::path::PathBuf {
        let resolved: ResolvedScope = resolve_scope(&scope, kv, json).await.unwrap();
        let params = BackupParams {
            dir: out_dir,
            id,
            scope: &scope,
            include_auth,
            schedule: None,
            resolved: &resolved,
            kv_registry: kv,
            json_engine: json,
            system_store: system,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        writer::run_backup(params).await.unwrap();
        out_dir.join(format!("{id}.ndjson"))
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

    // 1. Roundtrip: kv:<domain> export -> restore into an empty instance ->
    //    identical content, including TTL and a set_null entry.
    #[test]
    fn test_roundtrip_kv_domain() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            let store = kv_src.store("shop").await.unwrap();
            store.put(b"order:1", b"hello").await.unwrap();
            store.put_with_ttl(b"session", b"tok", 3600).await.unwrap();
            store.set_null(b"nulled").await.unwrap();
            // Values carry no UTF-8 guarantee (spec general/006 backup format) --
            // exercise a genuinely binary value, including a NUL byte.
            let binary_value: &[u8] = &[0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd];
            store.put(b"binary", binary_value).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = make_backup(
                out_dir.path(),
                "bk_rt",
                BackupScope::KvDomain("shop".to_string()),
                false,
                &kv_src,
                &None,
                &system_store(&_d1).await,
            )
            .await;

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_rt",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 4);
            assert_eq!(outcome.failed, 0);
            drop(path);

            let restored = kv_dst.store("shop").await.unwrap();
            assert_eq!(restored.get(b"order:1").await.unwrap(), GetResult::Present(b"hello".to_vec()));
            assert_eq!(restored.get(b"nulled").await.unwrap(), GetResult::Null);
            assert_eq!(restored.get(b"binary").await.unwrap(), GetResult::Present(binary_value.to_vec()));
            let (result, expires_at) = restored.get_with_snapshot(b"session", kv_dst.engine().snapshot().snapshot()).await.unwrap();
            assert_eq!(result, GetResult::Present(b"tok".to_vec()));
            assert!(expires_at > now_secs());
        })
    }

    // 2. Roundtrip: json:<domain> export -> restore -> documents and index
    //    definitions survive, and search over the restored index works.
    #[test]
    fn test_roundtrip_json_domain_with_index() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            json_src.create_domain("catalog").await.unwrap();
            json_src.create_index("catalog", "city", IndexFieldType::String).await.unwrap();
            json_src.put_document("catalog", "d1", json!({"city": "Essen"})).await.unwrap();
            json_src.put_document("catalog", "d2", json!({"city": "Berlin"})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            make_backup(
                out_dir.path(),
                "bk_json",
                BackupScope::JsonDomain("catalog".to_string()),
                false,
                &kv,
                &json_src_opt,
                &system_store(&_d1).await,
            )
            .await;

            let (json_dst, _d3) = make_json_engine().await;
            let json_dst_opt = Some(Arc::clone(&json_dst));
            let control = control_over(&_d3, &kv, &json_dst_opt).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_json",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv,
                json_engine: &json_dst_opt,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 2);
            assert_eq!(outcome.failed, 0);

            assert_eq!(json_dst.get_indexes("catalog").unwrap().len(), 1);
            let query = crate::engines::json::SearchQuery {
                filters: std::collections::HashMap::from([(
                    "city".to_string(),
                    crate::engines::json::FilterCondition::Eq(json!("Essen")),
                )]),
                ..Default::default()
            };
            let found = json_dst.search_documents("catalog", query).await.unwrap();
            assert_eq!(found.total, 1, "search over the restored index must find the restored document");
        })
    }

    // 2b. Restore: an archive line for a legacy document that still carries
    //     a reserved top-level field (the kind of pre-json/017 data a live
    //     write can no longer produce) counts as a per-line restore failure;
    //     the rest of the domain restores normally (spec json/017 §3 test 8).
    #[test]
    fn test_restore_rejects_legacy_document_with_reserved_field() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            json_src.create_domain("legacy").await.unwrap();
            json_src.put_document("legacy", "ok", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            let path = make_backup(
                out_dir.path(),
                "bk_legacy",
                BackupScope::JsonDomain("legacy".to_string()),
                false,
                &kv,
                &json_src_opt,
                &system_store(&_d1).await,
            )
            .await;

            // Inject a second "doc" line with a reserved top-level field
            // directly into the archive and reseal the checksum -- exactly the
            // kind of document a live write can no longer produce.
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

            let (json_dst, _d3) = make_json_engine().await;
            let json_dst_opt = Some(Arc::clone(&json_dst));
            let control = control_over(&_d3, &kv, &json_dst_opt).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_legacy",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv,
                json_engine: &json_dst_opt,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();

            assert_eq!(outcome.imported, 1, "the clean document still restores");
            assert_eq!(outcome.failed, 1, "the reserved-field document is a restore failure, not a crash");
            assert!(json_dst.get_document("legacy", "ok").await.unwrap().is_some());
            assert!(json_dst.get_document("legacy", "bad").await.unwrap().is_none());
        })
    }

    // 3. Roundtrip: domain:<name> touches both engines.
    #[test]
    fn test_roundtrip_domain_scope_both_engines() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            kv_src.create_domain("shop").await.unwrap();
            json_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
            json_src.put_document("shop", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            let system = system_store(&_d1).await;
            make_backup(out_dir.path(), "bk_dom", BackupScope::Domain("shop".to_string()), false, &kv_src, &json_src_opt, &system)
                .await;

            let (_engine2, kv_dst, _d3) = make_kv_registry().await;
            let (json_dst, _d4) = make_json_engine().await;
            let json_dst_opt = Some(Arc::clone(&json_dst));
            let control = control_over(&_d3, &kv_dst, &json_dst_opt).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_dom",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &json_dst_opt,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 2, "one kv pair + one document");
            assert!(kv_dst.get_domain("shop").await.unwrap().is_some());
            assert!(json_dst.get_domain("shop").is_some());
        })
    }

    // 3b. Roundtrip: `all` scope backs up every kv AND json domain (incl. the
    //     auto-created "default" one) in a single archive. Since `all`/`kv`
    //     always include "default", and a freshly-recovered registry always
    //     has one too, `replace` mode is used here (mirrors
    //     `test_include_auth_opt_in`'s reasoning).
    #[test]
    fn test_roundtrip_all_scope() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("default").await.unwrap().put(b"root-key", b"root-val").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
            json_src.create_domain("catalog").await.unwrap();
            json_src.put_document("default", "d0", json!({"n": 0})).await.unwrap();
            json_src.put_document("catalog", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            make_backup(out_dir.path(), "bk_all", BackupScope::All, false, &kv_src, &json_src_opt, &system_store(&_d1).await)
                .await;

            let (engine2, kv_dst, _d3) = make_kv_registry().await;
            let (json_dst, _d4) = make_json_engine().await;
            let json_dst_opt = Some(Arc::clone(&json_dst));
            let control = control_over(&_d3, &kv_dst, &json_dst_opt).await;

            let kv_shutdown = Arc::new(AtomicBool::new(false));
            let kv_purger = Arc::new(crate::engines::lsm::domain::DomainPurger::new(
                Arc::clone(&engine2),
                Arc::clone(&kv_dst),
                Arc::clone(&kv_shutdown),
                100,
                1,
            ));
            let json_shutdown = Arc::new(AtomicBool::new(false));
            let json_purger = Arc::new(JsonDomainPurger::new(Arc::clone(&json_dst), Arc::clone(&json_shutdown), 100, 1));
            let purger_task = compio::runtime::spawn({
                let kv_purger = Arc::clone(&kv_purger);
                let json_purger = Arc::clone(&json_purger);
                async move {
                    while !kv_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = kv_purger.purge_tick().await;
                        let _ = json_purger.purge_tick().await;
                        compio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            });

            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_all",
                mode: RestoreMode::Replace,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &json_dst_opt,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            json_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            drop(purger_task);

            assert_eq!(outcome.imported, 4, "2 kv pairs + 2 documents");
            assert_eq!(
                kv_dst.store("default").await.unwrap().get(b"root-key").await.unwrap(),
                GetResult::Present(b"root-val".to_vec())
            );
            assert_eq!(kv_dst.store("shop").await.unwrap().get(b"k").await.unwrap(), GetResult::Present(b"v".to_vec()));
            assert!(json_dst.get_document("default", "d0").await.unwrap().is_some());
            assert!(json_dst.get_document("catalog", "d1").await.unwrap().is_some());
        })
    }

    // 4. Already-expired TTL entries are skipped on restore, not imported.
    #[test]
    fn test_expired_ttl_entry_is_skipped() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put_with_ttl(b"soon-gone", b"v", 1).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_ttl", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;
            // Polls the expiry clock: a backwards clock correction cuts a fixed
            // sleep short before the stamp is reached.
            let deadline = now_secs() + 1 + 1;
            while now_secs() < deadline {
                compio::time::sleep(Duration::from_millis(50)).await;
            }

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_ttl",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 0);
            assert_eq!(outcome.skipped, 1);
            assert_eq!(kv_dst.store("shop").await.unwrap().get(b"soon-gone").await.unwrap(), GetResult::Absent);
        })
    }

    // 5. Checksum: a corrupted/truncated archive is rejected before any write.
    #[test]
    fn test_corrupted_checksum_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = make_backup(out_dir.path(), "bk_bad", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;

            let mut content = std::fs::read_to_string(&path).unwrap();
            content = content.replace("\"k\":\"6b\"", "\"k\":\"6c\""); // flip the exported key's hex
            std::fs::write(&path, content).unwrap();

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_bad",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::InvalidBackupFile(_))));
            assert!(kv_dst.get_domain("shop").await.unwrap().is_none(), "target must stay untouched");
        })
    }

    // 5b. A truncated archive (no checksum line at all) is "incomplete" and refused.
    #[test]
    fn test_missing_checksum_line_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = make_backup(out_dir.path(), "bk_trunc", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;
            let content = std::fs::read_to_string(&path).unwrap();
            let truncated: String = content.lines().take_while(|l| !l.contains("\"checksum\"")).collect::<Vec<_>>().join("\n");
            std::fs::write(&path, truncated + "\n").unwrap();

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_trunc",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::InvalidBackupFile(_))));
        })
    }

    // 6a. fail_if_exists aborts before the first write when a target domain
    //     already exists; the target is left completely unchanged.
    #[test]
    fn test_fail_if_exists_aborts_before_first_write() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k1", b"v1").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_exists", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            kv_dst.create_domain("shop").await.unwrap();
            kv_dst.store("shop").await.unwrap().put(b"pre-existing", b"untouched").await.unwrap();

            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_exists",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::DomainExists(_))));

            let store = kv_dst.store("shop").await.unwrap();
            assert_eq!(store.get(b"pre-existing").await.unwrap(), GetResult::Present(b"untouched".to_vec()));
            assert_eq!(store.get(b"k1").await.unwrap(), GetResult::Absent, "no data from the archive must land");
        })
    }

    // 6b. replace deletes and recreates the target domain, importing the
    //     archive's content only (old content is gone).
    #[test]
    fn test_replace_mode_wipes_target_first() {
        crate::core::engine_runtime::block_on(async {
            let (_engine1, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"new-key", b"new-val").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_replace", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;

            let (engine2, kv_dst, _d2) = make_kv_registry().await;
            kv_dst.create_domain("shop").await.unwrap();
            kv_dst.store("shop").await.unwrap().put(b"old-key", b"old-val").await.unwrap();
            let control = control_over(&_d2, &kv_dst, &None).await;

            // Drive the KV purger in the background so replace's delete+wait converges.
            let shutdown = Arc::new(AtomicBool::new(false));
            let purger = Arc::new(crate::engines::lsm::domain::DomainPurger::new(
                Arc::clone(&engine2),
                Arc::clone(&kv_dst),
                Arc::clone(&shutdown),
                100,
                1,
            ));
            let purger_task = compio::runtime::spawn({
                let purger = Arc::clone(&purger);
                async move {
                    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = purger.purge_tick().await;
                        compio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            });

            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_replace",
                mode: RestoreMode::Replace,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            drop(purger_task);
            assert_eq!(outcome.imported, 1);

            let store = kv_dst.store("shop").await.unwrap();
            assert_eq!(store.get(b"new-key").await.unwrap(), GetResult::Present(b"new-val".to_vec()));
            assert_eq!(store.get(b"old-key").await.unwrap(), GetResult::Absent, "replace must wipe the old content");
        })
    }

    // 7. into_domain remaps kv:<domain>/json:<domain>; domain:<name> remaps
    //    the name in both engines at once.
    #[test]
    fn test_into_domain_remap_single_engine() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_remap", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_remap",
                mode: RestoreMode::FailIfExists,
                into_domain: Some("shop-restored"),
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 1);
            assert!(kv_dst.get_domain("shop").await.unwrap().is_none());
            assert_eq!(
                kv_dst.store("shop-restored").await.unwrap().get(b"k").await.unwrap(),
                GetResult::Present(b"v".to_vec())
            );
        })
    }

    #[test]
    fn test_into_domain_remap_domain_scope_both_engines() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            kv_src.create_domain("shop").await.unwrap();
            json_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
            json_src.put_document("shop", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            let system = system_store(&_d1).await;
            make_backup(out_dir.path(), "bk_remap2", BackupScope::Domain("shop".to_string()), false, &kv_src, &json_src_opt, &system)
                .await;

            let (_engine2, kv_dst, _d3) = make_kv_registry().await;
            let (json_dst, _d4) = make_json_engine().await;
            let json_dst_opt = Some(Arc::clone(&json_dst));
            let control = control_over(&_d3, &kv_dst, &json_dst_opt).await;
            run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_remap2",
                mode: RestoreMode::FailIfExists,
                into_domain: Some("shop2"),
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &json_dst_opt,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();

            assert!(kv_dst.get_domain("shop2").await.unwrap().is_some());
            assert!(json_dst.get_domain("shop2").is_some());
            assert!(kv_dst.get_domain("shop").await.unwrap().is_none());
            assert!(json_dst.get_domain("shop").is_none());
        })
    }

    // 7b. into_domain on a multi-domain archive -> RemapRequiresSingleDomain.
    #[test]
    fn test_into_domain_rejects_multi_domain_archive() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("a").await.unwrap();
            kv_src.create_domain("b").await.unwrap();
            kv_src.store("a").await.unwrap().put(b"k", b"v").await.unwrap();
            kv_src.store("b").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_multi", BackupScope::Kv, false, &kv_src, &None, &system_store(&_d1).await).await;

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_multi",
                mode: RestoreMode::FailIfExists,
                into_domain: Some("only-one"),
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
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
            let (_, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            let system = system_store(&_d1).await;
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
            make_backup(out_dir.path(), "bk_auth", BackupScope::All, true, &kv_src, &None, &system).await;

            // A scope="all" archive always contains "default" (every registry
            // auto-creates it), so restoring into a freshly-recovered registry
            // needs `replace` -- `fail_if_exists` would legitimately reject it
            // because "default" already exists in the target too.
            async fn run_replace_restore(
                out_dir: &Path,
                include_auth: bool,
            ) -> (Arc<LsmStorageEngine>, Arc<ControlPlane>, RestoreOutcome, tempfile::TempDir) {
                let (engine, kv_dst, dir) = make_kv_registry().await;
                let control = control_over(&dir, &kv_dst, &None).await;
                let shutdown = Arc::new(AtomicBool::new(false));
                let purger = Arc::new(crate::engines::lsm::domain::DomainPurger::new(
                    Arc::clone(&engine),
                    Arc::clone(&kv_dst),
                    Arc::clone(&shutdown),
                    100,
                    1,
                ));
                let purger_task = compio::runtime::spawn({
                    let purger = Arc::clone(&purger);
                    async move {
                        while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                            let _ = purger.purge_tick().await;
                            compio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                });
                let outcome = run_restore(RestoreParams {
                    dir: out_dir,
                    backup_id: "bk_auth",
                    mode: RestoreMode::Replace,
                    into_domain: None,
                    include_auth,
                    kv_registry: &kv_dst,
                    json_engine: &None,
                    control: &control,
                    scan_batch_size: 500,
                    scan_pause_ms: 0,
                })
                .await
                .unwrap();
                drop(purger_task);
                (engine, control, outcome, dir)
            }

            // Default (false): auth lines are ignored.
            let (_engine2, control2, _outcome, _keep2) = run_replace_restore(out_dir.path(), false).await;
            assert!(control2.system_store().get(b"__sys:auth:user:alice").await.unwrap().is_none());

            // true: auth lines are upserted into the system store.
            let (engine3, control3, outcome, _keep3) = run_replace_restore(out_dir.path(), true).await;
            assert!(outcome.imported >= 2, "kv default domain data + 2 auth records");
            let system3 = control3.system_store();
            let raw = system3.get(b"__sys:auth:user:alice").await.unwrap().unwrap();
            let restored: UserRecord = serde_json::from_slice(&raw).unwrap();
            assert_eq!(restored.api_key_hash, "deadbeef");
            assert!(system3.get(format!("{PREFIX_PERM}alice:shop").as_bytes()).await.unwrap().is_some());
            assert!(engine3.get(b"__sys:auth:user:alice").await.unwrap().is_none(), "nothing lands in the KV engine");
        })
    }

    // 8a. An archive written before the system store existed — the auth
    //     lines are the same — restores its auth records into the system store.
    #[test]
    fn test_older_archive_restores_auth_into_the_system_store() {
        crate::core::engine_runtime::block_on(async {
            let out_dir = tempfile::TempDir::new().unwrap();
            let path = out_dir.path().join("bk_old.ndjson");
            let manifest = json!({
                "t": "manifest", "format_version": FORMAT_VERSION, "id": "bk_old", "created_at": 1_700_000_000u64,
                "luradb_version": "0.4.0", "scope": "kv", "include_auth": true, "kv_snapshot_ts": 1,
                "json_snapshot_ts": 0, "encoding": "hex", "schedule": null,
            });
            let user = json!({"t": "auth-user", "name": "zoé", "api_key_hash": "f00d", "role": "User", "created_at": 1});
            let perm = json!({"t": "auth-perm", "username": "zoé", "domain": "json:shop", "access": "Write"});
            reseal(&path, &[manifest.to_string(), user.to_string(), perm.to_string()]);

            let (engine, kv_dst, dir) = make_kv_registry().await;
            let bus = Arc::new(crate::core::events::GlobalEventBus::new(16, 16));
            let (control, auth) = crate::control::testing::start(dir.path(), Arc::clone(&kv_dst), None, None, bus).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_old",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: true,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();

            assert_eq!((outcome.imported, outcome.failed), (2, 0));
            let system = control.system_store();
            assert!(system.get("__sys:auth:user:zoé".as_bytes()).await.unwrap().is_some());
            assert!(system.get("__sys:auth:perm:zoé:json:shop".as_bytes()).await.unwrap().is_some());
            assert!(engine.scan_keys(b"__sys:auth:").await.unwrap().is_empty());
            assert_eq!(auth.get_user_by_name("zoé").await.unwrap().api_key_hash, "f00d", "the cache knows the user");
            assert_eq!(auth.get_permission("zoé", "json:shop").await, Some(crate::auth::AccessLevel::Write));
        })
    }

    // 9. Cross-check: backing up with include_auth=false never even writes
    //    auth lines (writer-side gate), independent of the restore-side gate
    //    tested above.
    #[test]
    fn test_backup_include_auth_false_excludes_auth_lines() {
        crate::core::engine_runtime::block_on(async {
            let (_, kv_src, _d1) = make_kv_registry().await;
            let system = system_store(&_d1).await;
            let record = UserRecord {
                name: "bob".to_string(),
                api_key_hash: "cafe".to_string(),
                role: crate::auth::UserRole::Admin,
                created_at: now_secs(),
            };
            system.put(b"__sys:auth:user:bob", &serde_json::to_vec(&record).unwrap()).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = make_backup(out_dir.path(), "bk_noauth", BackupScope::All, false, &kv_src, &None, &system).await;
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
            let (_engine, kv_dst, _d1) = make_kv_registry().await;
            let control = control_over(&_d1, &kv_dst, &None).await;
            let out_dir = tempfile::TempDir::new().unwrap();
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "../../etc/passwd",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await;
            assert!(err.is_err(), "no such archive under dir -- open() fails, nothing is read");
        })
    }

    // 11. Batch throttling: many kv entries with a small scan_batch_size and
    //     a real pause still import everything correctly.
    #[test]
    fn test_restore_respects_small_batch_size() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            let store = kv_src.store("shop").await.unwrap();
            for i in 0..5 {
                store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_batch", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_batch",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 2,
                scan_pause_ms: 5,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 5);
        })
    }

    // 12. Restore KV writes bypass the domain rate limiter (spec general/006
    //     authorization section: admin maintenance operation): with a 1-write/s
    //     quota, all five entries still land instead of being dropped as
    //     per-entry failures.
    #[test]
    fn test_restore_bypasses_domain_rate_limiter() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            let store = kv_src.store("shop").await.unwrap();
            for i in 0..5 {
                store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }

            let out_dir = tempfile::TempDir::new().unwrap();
            make_backup(out_dir.path(), "bk_rl", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;

            let (_engine2, kv_dst, _d2) = make_kv_registry_with_config(DomainConfig {
                default_write_iops: 1,
                ..DomainConfig::default()
            })
            .await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_rl",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            assert_eq!(outcome.imported, 5, "a 1-write/s quota must not drop restore entries");
            assert_eq!(outcome.failed, 0);
        })
    }

    // 13. Lines appended after the checksum line are outside the verified
    //     range -> the whole archive is invalid, nothing is applied.
    #[test]
    fn test_data_after_checksum_line_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = make_backup(out_dir.path(), "bk_trail", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;
            let mut content = std::fs::read_to_string(&path).unwrap();
            content.push_str("{\"t\":\"kv\",\"domain\":\"shop\",\"k\":\"6578747261\",\"v\":\"6578747261\",\"expires_at\":0}\n");
            std::fs::write(&path, content).unwrap();

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_trail",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::InvalidBackupFile(_))));
            assert!(kv_dst.get_domain("shop").await.unwrap().is_none(), "nothing must be applied");
        })
    }

    // 13b. Blank lines never occur in writer output; an injected one voids
    //      the byte-exact checksum guarantee and is rejected.
    #[test]
    fn test_blank_line_in_archive_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path = make_backup(out_dir.path(), "bk_blank", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await).await;
            let content = std::fs::read_to_string(&path).unwrap();
            let mut file_lines: Vec<&str> = content.lines().collect();
            file_lines.insert(1, "");
            std::fs::write(&path, file_lines.join("\n") + "\n").unwrap();

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_blank",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::InvalidBackupFile(_))));
        })
    }

    // 14. An archive carrying JSON sections cannot be restored without the
    //     JSON engine -- hard error instead of silently dropping that data.
    #[test]
    fn test_restore_json_archive_without_engine_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            json_src.create_domain("catalog").await.unwrap();
            json_src.put_document("catalog", "d1", json!({"n": 1})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            make_backup(
                out_dir.path(),
                "bk_nojson",
                BackupScope::JsonDomain("catalog".to_string()),
                false,
                &kv,
                &json_src_opt,
                &system_store(&_d1).await,
            )
            .await;

            let (_engine2, kv_dst, _d3) = make_kv_registry().await;
            let control = control_over(&_d3, &kv_dst, &None).await;
            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_nojson",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::JsonEngineDisabled)));
        })
    }

    // 6c. replace mode also wipes an existing JSON target domain first
    //     (mirrors test 6b for the JSON engine's own purger).
    #[test]
    fn test_replace_mode_wipes_json_target_first() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv, _d1) = make_kv_registry().await;
            let (json_src, _d2) = make_json_engine().await;
            json_src.create_domain("catalog").await.unwrap();
            json_src.put_document("catalog", "new", json!({"n": 2})).await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let json_src_opt = Some(Arc::clone(&json_src));
            make_backup(
                out_dir.path(),
                "bk_jreplace",
                BackupScope::JsonDomain("catalog".to_string()),
                false,
                &kv,
                &json_src_opt,
                &system_store(&_d1).await,
            )
            .await;

            let (json_dst, _d3) = make_json_engine().await;
            json_dst.create_domain("catalog").await.unwrap();
            json_dst.put_document("catalog", "old", json!({"n": 1})).await.unwrap();
            let json_dst_opt = Some(Arc::clone(&json_dst));
            let control = control_over(&_d3, &kv, &json_dst_opt).await;

            let shutdown = Arc::new(AtomicBool::new(false));
            let purger = Arc::new(JsonDomainPurger::new(Arc::clone(&json_dst), Arc::clone(&shutdown), 100, 1));
            let purger_task = compio::runtime::spawn({
                let purger = Arc::clone(&purger);
                async move {
                    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = purger.purge_tick().await;
                        compio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            });

            let outcome = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_jreplace",
                mode: RestoreMode::Replace,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv,
                json_engine: &json_dst_opt,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap();
            drop(purger_task);
            assert_eq!(outcome.imported, 1);

            assert!(json_dst.get_document("catalog", "new").await.unwrap().is_some());
            assert!(json_dst.get_document("catalog", "old").await.unwrap().is_none(), "replace must wipe the old content");
        })
    }

    // 15. A data line naming a domain the archive never declares is refused:
    //     the apply pass takes its target from the data line, so such an
    //     archive would write straight into a live domain, past both the
    //     fail_if_exists and the replace handling.
    #[test]
    fn test_data_line_for_undeclared_domain_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (_engine, kv_src, _d1) = make_kv_registry().await;
            kv_src.create_domain("shop").await.unwrap();
            kv_src.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

            let out_dir = tempfile::TempDir::new().unwrap();
            let path =
                make_backup(out_dir.path(), "bk_undecl", BackupScope::KvDomain("shop".to_string()), false, &kv_src, &None, &system_store(&_d1).await)
                    .await;

            // Retarget the data line at an undeclared domain (the declaration
            // line carries `name`, not `domain`, so it stays "shop") and reseal.
            let content = std::fs::read_to_string(&path).unwrap();
            let body: Vec<String> = content
                .lines()
                .take_while(|l| !l.contains("\"t\":\"checksum\""))
                .map(|l| l.replace("\"domain\":\"shop\"", "\"domain\":\"live\""))
                .collect();
            reseal(&path, &body);

            let (_engine2, kv_dst, _d2) = make_kv_registry().await;
            let control = control_over(&_d2, &kv_dst, &None).await;
            kv_dst.create_domain("live").await.unwrap();
            kv_dst.store("live").await.unwrap().put(b"production", b"untouched").await.unwrap();

            let err = run_restore(RestoreParams {
                dir: out_dir.path(),
                backup_id: "bk_undecl",
                mode: RestoreMode::FailIfExists,
                into_domain: None,
                include_auth: false,
                kv_registry: &kv_dst,
                json_engine: &None,
                control: &control,
                scan_batch_size: 500,
                scan_pause_ms: 0,
            })
            .await
            .unwrap_err();
            assert!(err.downcast_ref::<BackupError>().is_some_and(|e| matches!(e, BackupError::InvalidBackupFile(_))));

            let store = kv_dst.store("live").await.unwrap();
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
}
