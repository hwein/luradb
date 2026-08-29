//! Backup export pipeline (spec general/006): scope resolution, snapshot
//! acquisition, and the NDJSON writer (manifest -> kv-domains -> kv-pairs ->
//! json-domains -> index-definitions -> docs -> auth -> checksum).

use super::{BackupError, BackupScope};
use crate::auth::{DomainPermission, UserRecord, PREFIX_PERM, PREFIX_USER};
use crate::engines::json::{IndexFieldType, JsonDomain, JsonDomainState, JsonEngine};
use crate::engines::lsm::domain::{now_secs, Domain, DomainRegistry};
use crate::engines::lsm::{GetResult, RegistrySnapshot};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub(crate) const FORMAT_VERSION: u32 = 1;

// ── Wire format (shared with `restore`) ─────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ManifestLine {
    pub t: String,
    pub format_version: u32,
    pub id: String,
    pub created_at: u64,
    pub luradb_version: String,
    pub scope: String,
    pub include_auth: bool,
    pub kv_snapshot_ts: u64,
    pub json_snapshot_ts: u64,
    pub encoding: String,
    pub schedule: Option<String>,
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

// ── Scope resolution ─────────────────────────────────────────────────────

/// The concrete domains a scope resolves to, already filtered to `Active`
/// state (spec general/006: `Deleting` domains are skipped). Either list can
/// be empty for any scope — every domain of an engine may be deleted at
/// runtime — and only means there is no *domain* data to export; auth
/// records live outside any domain and still need the KV snapshot.
#[derive(Debug)]
pub(crate) struct ResolvedScope {
    pub kv_domains: Vec<Domain>,
    pub json_domains: Vec<JsonDomain>,
}

pub(crate) async fn resolve_scope(
    scope: &BackupScope,
    kv_registry: &Arc<DomainRegistry>,
    json_engine: &Option<Arc<JsonEngine>>,
) -> Result<ResolvedScope, BackupError> {
    match scope {
        BackupScope::All => {
            let kv_domains = kv_registry.list_domains().await.map_err(BackupError::Other)?;
            let json_domains = match json_engine {
                Some(j) => j
                    .list_domains()
                    .into_iter()
                    .filter(|d| d.state == JsonDomainState::Active)
                    .collect(),
                None => Vec::new(),
            };
            Ok(ResolvedScope { kv_domains, json_domains })
        }
        BackupScope::Kv => {
            let kv_domains = kv_registry.list_domains().await.map_err(BackupError::Other)?;
            Ok(ResolvedScope { kv_domains, json_domains: Vec::new() })
        }
        BackupScope::Json => {
            let j = json_engine.as_ref().ok_or(BackupError::JsonEngineDisabled)?;
            let json_domains = j
                .list_domains()
                .into_iter()
                .filter(|d| d.state == JsonDomainState::Active)
                .collect();
            Ok(ResolvedScope { kv_domains: Vec::new(), json_domains })
        }
        BackupScope::KvDomain(name) => {
            let d = kv_registry
                .get_domain(name)
                .await
                .map_err(BackupError::Other)?
                .ok_or_else(|| BackupError::DomainNotFound(name.clone()))?;
            Ok(ResolvedScope { kv_domains: vec![d], json_domains: Vec::new() })
        }
        BackupScope::JsonDomain(name) => {
            let j = json_engine.as_ref().ok_or(BackupError::JsonEngineDisabled)?;
            let d = j.get_domain(name).ok_or_else(|| BackupError::DomainNotFound(name.clone()))?;
            Ok(ResolvedScope { kv_domains: Vec::new(), json_domains: vec![d] })
        }
        BackupScope::Domain(name) => {
            let kv_d = kv_registry.get_domain(name).await.map_err(BackupError::Other)?;
            let json_d = match json_engine {
                Some(j) => j.get_domain(name),
                None => None,
            };
            if kv_d.is_none() && json_d.is_none() {
                return Err(BackupError::DomainNotFound(name.clone()));
            }
            Ok(ResolvedScope {
                kv_domains: kv_d.into_iter().collect(),
                json_domains: json_d.into_iter().collect(),
            })
        }
    }
}

// ── Backup job ────────────────────────────────────────────────────────────

pub(crate) struct BackupParams<'a> {
    pub dir: &'a Path,
    pub id: &'a str,
    pub scope: &'a BackupScope,
    pub include_auth: bool,
    pub schedule: Option<&'a str>,
    pub resolved: &'a ResolvedScope,
    pub kv_registry: &'a Arc<DomainRegistry>,
    pub json_engine: &'a Option<Arc<JsonEngine>>,
    pub scan_batch_size: usize,
    pub scan_pause_ms: u64,
}

/// Runs the full export: `<id>.ndjson.part` -> fsync -> rename to
/// `<id>.ndjson` -> fsync of the directory. On any error the `.part` file is
/// removed (spec general/006 job flow step 5) and the error propagates for
/// the caller to log.
pub(crate) async fn run_backup(params: BackupParams<'_>) -> anyhow::Result<()> {
    let part_path = params.dir.join(format!("{}.ndjson.part", params.id));
    let final_path = params.dir.join(format!("{}.ndjson", params.id));

    match write_backup_file(&part_path, &params).await {
        Ok(()) => {
            tokio::fs::rename(&part_path, &final_path).await?;
            // The rename must be durable too: success here lets retention
            // delete an older generation right away.
            tokio::fs::File::open(params.dir).await?.sync_all().await?;
            Ok(())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part_path).await;
            Err(e)
        }
    }
}

async fn write_backup_file(part_path: &PathBuf, params: &BackupParams<'_>) -> anyhow::Result<()> {
    // include_auth only ever applies to all/kv (spec: auth records live in
    // the KV instance) -- other scopes silently ignore the flag.
    let export_auth = params.include_auth && matches!(params.scope, BackupScope::All | BackupScope::Kv);

    // One registered snapshot per engine, held for the whole export so the
    // compaction low watermark keeps every visible version around (spec
    // general/006 consistency guarantee). `None` when that engine has
    // nothing to export in this scope, so no snapshot (and no GC
    // back-pressure) is taken for it. Auth records sit on the raw KV engine
    // outside every domain, so they need the KV snapshot on their own.
    let kv_snapshot: Option<RegistrySnapshot> =
        if !params.resolved.kv_domains.is_empty() || export_auth {
            Some(params.kv_registry.engine().snapshot())
        } else {
            None
        };
    let json_snapshot: Option<RegistrySnapshot> = if !params.resolved.json_domains.is_empty() {
        params.json_engine.as_ref().map(|j| j.engine().snapshot())
    } else {
        None
    };

    let file = tokio::fs::File::create(part_path).await?;
    let mut out = tokio::io::BufWriter::new(file);
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
        kv_snapshot_ts: kv_snapshot.as_ref().map(|s| s.snapshot().timestamp().as_u64()).unwrap_or(0),
        json_snapshot_ts: json_snapshot.as_ref().map(|s| s.snapshot().timestamp().as_u64()).unwrap_or(0),
        encoding: "hex".to_string(),
        schedule: params.schedule.map(|s| s.to_string()),
    };
    write_line(&mut out, &mut hasher, &mut lines, &manifest).await?;

    // Binding section order (spec general/006 backup format): kv sections,
    // then json sections, then auth, then the checksum line.
    write_kv_section(&mut out, &mut hasher, &mut lines, params, kv_snapshot.as_ref()).await?;

    write_json_section(&mut out, &mut hasher, &mut lines, params, json_snapshot.as_ref()).await?;

    if export_auth {
        let snap = kv_snapshot.as_ref().expect("export_auth implies a kv snapshot");
        write_auth_section(&mut out, &mut hasher, &mut lines, params.kv_registry, snap).await?;
    }

    let sha256 = hex::encode(hasher.finalize());
    let checksum_bytes = serde_json::to_vec(&ChecksumLine { t: "checksum".to_string(), sha256, lines })?;
    out.write_all(&checksum_bytes).await?;
    out.write_all(b"\n").await?;

    out.flush().await?;
    out.get_ref().sync_all().await?;
    Ok(())
}

async fn write_kv_section<W: tokio::io::AsyncWrite + Unpin>(
    out: &mut W,
    hasher: &mut Sha256,
    lines: &mut u64,
    params: &BackupParams<'_>,
    kv_snapshot: Option<&RegistrySnapshot>,
) -> anyhow::Result<()> {
    let Some(snap) = kv_snapshot else { return Ok(()) };

    for domain in &params.resolved.kv_domains {
        write_line(
            out,
            hasher,
            lines,
            &KvDomainLine { t: "kv-domain".to_string(), name: domain.name.clone(), created_at: domain.created_at },
        )
        .await?;

        let store = params.kv_registry.store(&domain.name).await?;
        let keys = store.scan_keys_with_snapshot(b"", snap.snapshot()).await?;
        for (i, key) in keys.iter().enumerate() {
            let (result, expires_at) = store.get_with_snapshot(key, snap.snapshot()).await?;
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

async fn write_auth_section<W: tokio::io::AsyncWrite + Unpin>(
    out: &mut W,
    hasher: &mut Sha256,
    lines: &mut u64,
    kv_registry: &Arc<DomainRegistry>,
    snap: &RegistrySnapshot,
) -> anyhow::Result<()> {
    let engine = kv_registry.engine();

    let user_keys = engine.scan_keys_with_snapshot(PREFIX_USER.as_bytes(), snap.snapshot()).await?;
    for key in &user_keys {
        let (result, _) = engine.get_with_expiry(key, snap.snapshot()).await?;
        if let GetResult::Present(bytes) = result {
            let record: UserRecord = serde_json::from_slice(&bytes)?;
            write_line(out, hasher, lines, &AuthUserLine { t: "auth-user", record: &record }).await?;
        }
    }

    let perm_keys = engine.scan_keys_with_snapshot(PREFIX_PERM.as_bytes(), snap.snapshot()).await?;
    for key in &perm_keys {
        let (result, _) = engine.get_with_expiry(key, snap.snapshot()).await?;
        if let GetResult::Present(bytes) = result {
            let perm: DomainPermission = serde_json::from_slice(&bytes)?;
            write_line(out, hasher, lines, &AuthPermLine { t: "auth-perm", perm: &perm }).await?;
        }
    }
    Ok(())
}

async fn write_json_section<W: tokio::io::AsyncWrite + Unpin>(
    out: &mut W,
    hasher: &mut Sha256,
    lines: &mut u64,
    params: &BackupParams<'_>,
    json_snapshot: Option<&RegistrySnapshot>,
) -> anyhow::Result<()> {
    let Some(snap) = json_snapshot else { return Ok(()) };
    let json = params.json_engine.as_ref().expect("json snapshot implies json_engine is Some");

    for domain in &params.resolved.json_domains {
        write_line(
            out,
            hasher,
            lines,
            &JsonDomainLine { t: "json-domain".to_string(), name: domain.name.clone(), created_at: domain.created_at },
        )
        .await?;

        for def in json.get_indexes_with_snapshot(&domain.name, snap.snapshot()).await? {
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

        let keys = json.scan_document_keys_with_snapshot(&domain.name, snap.snapshot()).await?;
        for (i, key) in keys.iter().enumerate() {
            if let Some(doc) = json.get_document_with_snapshot(&domain.name, key, snap.snapshot()).await? {
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

/// Serializes one line, appends `\n`, writes it, and feeds the exact bytes,
/// including the trailing newline, into the running checksum (spec
/// general/006 backup format).
async fn write_line<W: tokio::io::AsyncWrite + Unpin>(
    out: &mut W,
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
    if batch_size > 0 && (i + 1) % batch_size == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JsonStoreConfig;
    use crate::engines::json::IndexFieldType;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
    use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use crate::core::wal::WriteAheadLog;
    use serde_json::json;

    async fn make_kv_registry() -> (Arc<DomainRegistry>, tempfile::TempDir) {
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
            Arc::new(DomainRegistry::recover(Arc::clone(&engine), DomainConfig::default(), metrics).await.unwrap());
        (registry, dir)
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

    // 1. resolve_scope: `all` picks up every active KV domain.
    #[tokio::test]
    async fn test_resolve_all_scope_kv_only() {
        let (kv, _dir) = make_kv_registry().await;
        kv.create_domain("shop").await.unwrap();
        let resolved = resolve_scope(&BackupScope::All, &kv, &None).await.unwrap();
        let names: Vec<_> = resolved.kv_domains.iter().map(|d| d.name.clone()).collect();
        assert!(names.contains(&"default".to_string()));
        assert!(names.contains(&"shop".to_string()));
        assert!(resolved.json_domains.is_empty(), "no json engine given");
    }

    // 2. resolve_scope: kv:<domain> on a missing domain -> DomainNotFound.
    #[tokio::test]
    async fn test_resolve_kv_domain_missing_errors() {
        let (kv, _dir) = make_kv_registry().await;
        let err = resolve_scope(&BackupScope::KvDomain("nope".to_string()), &kv, &None)
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::DomainNotFound(d) if d == "nope"));
    }

    // 3. resolve_scope: json/json:<domain> with no JSON engine -> JsonEngineDisabled.
    #[tokio::test]
    async fn test_resolve_json_scope_without_engine_errors() {
        let (kv, _dir) = make_kv_registry().await;
        let err = resolve_scope(&BackupScope::Json, &kv, &None).await.unwrap_err();
        assert!(matches!(err, BackupError::JsonEngineDisabled));
        let err = resolve_scope(&BackupScope::JsonDomain("x".to_string()), &kv, &None)
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::JsonEngineDisabled));
    }

    // 4. resolve_scope: domain:<name> present in only one engine backs up only that one.
    #[tokio::test]
    async fn test_resolve_domain_scope_single_engine() {
        let (kv, _dir1) = make_kv_registry().await;
        let (json, _dir2) = make_json_engine().await;
        kv.create_domain("only-kv").await.unwrap();
        let resolved = resolve_scope(&BackupScope::Domain("only-kv".to_string()), &kv, &Some(Arc::clone(&json)))
            .await
            .unwrap();
        assert_eq!(resolved.kv_domains.len(), 1);
        assert!(resolved.json_domains.is_empty());
    }

    // 5. resolve_scope: domain:<name> missing in both engines -> DomainNotFound.
    #[tokio::test]
    async fn test_resolve_domain_scope_missing_everywhere() {
        let (kv, _dir1) = make_kv_registry().await;
        let (json, _dir2) = make_json_engine().await;
        let err = resolve_scope(&BackupScope::Domain("nope".to_string()), &kv, &Some(json))
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::DomainNotFound(_)));
    }

    // 6. run_backup: kv-only roundtrip produces a well-formed, checksummed
    //    NDJSON file with the expected line shapes and section order.
    #[tokio::test]
    async fn test_run_backup_kv_only_writes_valid_ndjson() {
        let (kv, _dir1) = make_kv_registry().await;
        kv.create_domain("shop").await.unwrap();
        let store = kv.store("shop").await.unwrap();
        store.put(b"order:1", b"hello").await.unwrap();
        store.put_with_ttl(b"session", b"tok", 3600).await.unwrap();
        store.set_null(b"nulled").await.unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let resolved = resolve_scope(&BackupScope::KvDomain("shop".to_string()), &kv, &None).await.unwrap();
        let scope = BackupScope::KvDomain("shop".to_string());
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_test",
            scope: &scope,
            include_auth: false,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &None,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();

        let content = std::fs::read_to_string(out_dir.path().join("bk_test.ndjson")).unwrap();
        assert!(!out_dir.path().join("bk_test.ndjson.part").exists());
        let raw_lines: Vec<&str> = content.lines().collect();
        // manifest + kv-domain + 3 kv pairs (order:1, session, nulled) + checksum.
        assert_eq!(raw_lines.len(), 6);

        let manifest: ManifestLine = serde_json::from_str(raw_lines[0]).unwrap();
        assert_eq!(manifest.t, "manifest");
        assert_eq!(manifest.scope, "kv:shop");
        assert_eq!(manifest.encoding, "hex");

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
    }

    // 7. Snapshot consistency: a write committed after run_backup has
    //    already acquired its snapshot (but is still mid-export) must not
    //    appear in the output (spec general/006 consistency guarantee). Uses
    //    scan_batch_size=1 + a real pause to open a window mid-export in
    //    which a concurrent write is injected.
    #[tokio::test]
    async fn test_run_backup_snapshot_excludes_writes_during_export() {
        let (kv, _dir1) = make_kv_registry().await;
        kv.create_domain("shop").await.unwrap();
        let store = kv.store("shop").await.unwrap();
        store.put(b"a1", b"v1").await.unwrap();
        store.put(b"a2", b"v2").await.unwrap();

        let resolved = resolve_scope(&BackupScope::KvDomain("shop".to_string()), &kv, &None).await.unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out_path = out_dir.path().to_path_buf();
        let kv_for_task = Arc::clone(&kv);

        let backup_task = tokio::spawn(async move {
            let scope = BackupScope::KvDomain("shop".to_string());
            let params = BackupParams {
                dir: &out_path,
                id: "bk_snap",
                scope: &scope,
                include_auth: false,
                schedule: None,
                resolved: &resolved,
                kv_registry: &kv_for_task,
                json_engine: &None,
                scan_batch_size: 1,
                scan_pause_ms: 300,
            };
            run_backup(params).await.unwrap();
        });

        // Let the job acquire its snapshot and enter its first pause window.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
    }

    // 8. include_auth is only effective for all/kv scopes.
    #[tokio::test]
    async fn test_include_auth_ignored_for_domain_scope() {
        let (kv, _dir1) = make_kv_registry().await;
        kv.create_domain("shop").await.unwrap();
        let resolved = resolve_scope(&BackupScope::KvDomain("shop".to_string()), &kv, &None).await.unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let scope = BackupScope::KvDomain("shop".to_string());
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_authflag",
            scope: &scope,
            include_auth: true,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &None,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();
        let content = std::fs::read_to_string(out_dir.path().join("bk_authflag.ndjson")).unwrap();
        let manifest_line = content.lines().next().unwrap();
        let manifest: ManifestLine = serde_json::from_str(manifest_line).unwrap();
        assert!(!manifest.include_auth, "kv:<domain> must not export auth even if requested");
    }

    // 8b. include_auth=true on an all/kv scope does export auth-user/auth-perm
    //     lines, with the UserRecord/DomainPermission fields intact.
    #[tokio::test]
    async fn test_backup_include_auth_true_exports_auth_lines() {
        let (kv, _dir1) = make_kv_registry().await;
        let engine = kv.engine();
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

        let resolved = resolve_scope(&BackupScope::All, &kv, &None).await.unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let scope = BackupScope::All;
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_authtrue",
            scope: &scope,
            include_auth: true,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &None,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();

        let content = std::fs::read_to_string(out_dir.path().join("bk_authtrue.ndjson")).unwrap();
        let manifest: ManifestLine = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert!(manifest.include_auth);

        let user_line = content.lines().find(|l| l.contains("\"auth-user\"")).expect("auth-user line must be present");
        let restored: UserRecord = serde_json::from_str(user_line).unwrap();
        assert_eq!(restored.name, "carol");
        assert_eq!(restored.api_key_hash, "abc123");

        let perm_line = content.lines().find(|l| l.contains("\"auth-perm\"")).expect("auth-perm line must be present");
        let restored_perm: DomainPermission = serde_json::from_str(perm_line).unwrap();
        assert_eq!(restored_perm.username, "carol");
        assert_eq!(restored_perm.domain, "shop");
    }

    // 8c. Auth records live outside every domain: an `all` backup taken while
    //     no KV domain exists at all must still export them (regression: the
    //     KV snapshot was only acquired for non-empty domain lists, so the
    //     auth section was silently skipped while the manifest still
    //     announced include_auth).
    #[tokio::test]
    async fn test_backup_exports_auth_without_any_kv_domain() {
        let (kv, _dir1) = make_kv_registry().await;
        kv.delete_domain("default").await.unwrap();
        let record = UserRecord {
            name: "erin".to_string(),
            api_key_hash: "cafe".to_string(),
            role: crate::auth::UserRole::Admin,
            created_at: 1_700_000_000,
        };
        kv.engine()
            .put(format!("{PREFIX_USER}erin").as_bytes(), &serde_json::to_vec(&record).unwrap())
            .await
            .unwrap();

        let resolved = resolve_scope(&BackupScope::All, &kv, &None).await.unwrap();
        assert!(resolved.kv_domains.is_empty(), "test setup: no domain must be left");

        let out_dir = tempfile::TempDir::new().unwrap();
        let scope = BackupScope::All;
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_authnodomain",
            scope: &scope,
            include_auth: true,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &None,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();

        let content = std::fs::read_to_string(out_dir.path().join("bk_authnodomain.ndjson")).unwrap();
        let user_line = content.lines().find(|l| l.contains("\"auth-user\"")).expect("auth-user line must be present");
        let restored: UserRecord = serde_json::from_str(user_line).unwrap();
        assert_eq!(restored.name, "erin");
    }

    // 9. JSON domain export: index definitions and documents are exported
    //    with the expected line shapes.
    #[tokio::test]
    async fn test_run_backup_json_domain_with_index_and_docs() {
        let (kv, _dir1) = make_kv_registry().await;
        let (json, _dir2) = make_json_engine().await;
        json.create_domain("catalog").await.unwrap();
        json.create_index("catalog", "city", IndexFieldType::String).await.unwrap();
        json.put_document("catalog", "d1", json!({"city": "Essen"})).await.unwrap();

        let resolved =
            resolve_scope(&BackupScope::JsonDomain("catalog".to_string()), &kv, &Some(Arc::clone(&json)))
                .await
                .unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let scope = BackupScope::JsonDomain("catalog".to_string());
        let json_engine_opt = Some(json);
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_json",
            scope: &scope,
            include_auth: false,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &json_engine_opt,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();
        let content = std::fs::read_to_string(out_dir.path().join("bk_json.ndjson")).unwrap();
        assert!(content.contains("\"t\":\"json-domain\""));
        assert!(content.contains("\"t\":\"json-index\""));
        assert!(content.contains("\"t\":\"doc\""));
        assert!(content.contains("\"field_type\":\"string\""));
    }

    // 9b. Binding section order (spec general/006 backup format): kv
    //     sections, then json sections, then auth, then the checksum line.
    #[tokio::test]
    async fn test_backup_section_order_kv_json_auth_checksum() {
        let (kv, _dir1) = make_kv_registry().await;
        let (json, _dir2) = make_json_engine().await;
        kv.create_domain("shop").await.unwrap();
        kv.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
        json.create_domain("catalog").await.unwrap();
        json.put_document("catalog", "d1", serde_json::json!({"n": 1})).await.unwrap();
        let record = UserRecord {
            name: "dave".to_string(),
            api_key_hash: "beef".to_string(),
            role: crate::auth::UserRole::User,
            created_at: 1,
        };
        kv.engine().put(b"__sys:auth:user:dave", &serde_json::to_vec(&record).unwrap()).await.unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let json_opt = Some(Arc::clone(&json));
        let resolved = resolve_scope(&BackupScope::All, &kv, &json_opt).await.unwrap();
        let scope = BackupScope::All;
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_order",
            scope: &scope,
            include_auth: true,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &json_opt,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();

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
    }

    // 10. Checksum line matches the file's own content and lists the right
    //     line count.
    #[tokio::test]
    async fn test_checksum_line_is_valid() {
        let (kv, _dir1) = make_kv_registry().await;
        kv.create_domain("shop").await.unwrap();
        let store = kv.store("shop").await.unwrap();
        store.put(b"k1", b"v1").await.unwrap();
        store.put(b"k2", b"v2").await.unwrap();

        let resolved = resolve_scope(&BackupScope::KvDomain("shop".to_string()), &kv, &None).await.unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let scope = BackupScope::KvDomain("shop".to_string());
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_sum",
            scope: &scope,
            include_auth: false,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &None,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        run_backup(params).await.unwrap();

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
    }

    // 11. On a write failure the `.part` file is removed, not left behind.
    #[tokio::test]
    async fn test_run_backup_cleans_up_part_file_on_error() {
        let (kv, _dir1) = make_kv_registry().await;
        // A scope resolving to a KV domain that was deleted right after
        // resolution simulates a mid-job failure: `store()` on a Deleting/
        // gone domain errors out inside the writer.
        kv.create_domain("gone").await.unwrap();
        let resolved = resolve_scope(&BackupScope::KvDomain("gone".to_string()), &kv, &None).await.unwrap();
        kv.delete_domain("gone").await.unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let scope = BackupScope::KvDomain("gone".to_string());
        let params = BackupParams {
            dir: out_dir.path(),
            id: "bk_fail",
            scope: &scope,
            include_auth: false,
            schedule: None,
            resolved: &resolved,
            kv_registry: &kv,
            json_engine: &None,
            scan_batch_size: 500,
            scan_pause_ms: 0,
        };
        assert!(run_backup(params).await.is_err());
        assert!(!out_dir.path().join("bk_fail.ndjson.part").exists());
        assert!(!out_dir.path().join("bk_fail.ndjson").exists());
    }
}
