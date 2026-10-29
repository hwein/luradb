//! Offline change of the shard count of a data directory. Every engine's
//! data is read from each instance of the current layout and written, under
//! its own stamps and expiries, into the instances of the new layout. Those
//! are built in a staging directory `migrate_<timestamp>/` inside every
//! directory that holds `shard_<k>/` directories, so each move is a
//! `rename` on one file system. Only then does a marker in the system store
//! go up; the new layout moves into place directory by directory, the old
//! one aside, and the stored shard count and the marker change in one write.
//! A server refuses to start while the marker stands, and a rerun of the
//! tool finishes the move. Write-ahead logs must be empty: the new layout
//! starts its log positions at 1.

use super::{
    control::{kv_options, start_storage_thread, MemorySplit},
    layout,
    recovery::{self, EngineFiles},
};
use crate::backup::cron::format_utc_timestamp;
use crate::config::LuraConfig;
use crate::control::{system, Engine};
use crate::core::{
    engine_runtime,
    storage_thread::{StorageHandle, WalTarget},
    wal::{self, WriteAheadLog},
};
use crate::engines::json::JsonEngine;
use crate::engines::lsm::{
    domain::now_secs,
    engine::{LsmEngineOptions, LsmStorageEngine},
    RawEntry, RawValue,
};
use crate::engines::rel::RelEngine;
use crate::storage::sync_dir;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where the old layout goes inside the staging directory.
const PREVIOUS: &str = "previous";

const NOT_SHARDED: &str = "the data directory has no shard layout yet — start the server once, then shut it down";

/// The marker a migration leaves in the system store until it has finished.
#[derive(Serialize, Deserialize)]
struct Marker {
    shards: u16,
    /// Name of the staging directory in every root.
    staging: String,
    roots: Vec<PathBuf>,
}

/// Changes the shard count of the data directory `config` names to
/// `shards`, or finishes a change to it that stopped halfway. The server
/// must be stopped, every write-ahead log empty, and the SSTable directory
/// of every enabled engine present.
pub fn migrate_shards(config: &LuraConfig, shards: u16) -> anyhow::Result<()> {
    anyhow::ensure!(shards > 0, "the shard count must be at least 1");
    let tokio = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build()?;
    let _tokio = tokio.enter();
    let runtime = engine_runtime::build(engine_runtime::DEFAULT_REMOTE_WAKES)?;
    engine_runtime::run(&runtime, migrate(config, shards))
}

async fn migrate(config: &LuraConfig, shards: u16) -> anyhow::Result<()> {
    let system_dir = Path::new(&config.storage.system_dir);
    anyhow::ensure!(system_dir.is_dir(), "no data directory at {}", system_dir.display());
    let _lock = system::lock_data_dir(system_dir).context("stop the server before changing the shard count")?;
    if ![0, shards].contains(&config.multicore.shards) {
        tracing::warn!(
            "[multicore].shards is {}; set it to {shards} or 0 before the server starts again.",
            config.multicore.shards
        );
    }
    for (engine, files) in engine_files(config) {
        let enabled = match engine {
            Engine::Kv => true,
            Engine::Json => config.json.enabled,
            Engine::Rel => config.rel.enabled,
        };
        // Every start of an enabled engine creates its SSTable directory; a
        // missing one means its data lies elsewhere (relative paths resolved
        // from another directory) or the engine never ran here. Checked
        // before the storage thread creates any file.
        if enabled && !files.sstables.is_dir() {
            let name = engine.as_str();
            anyhow::bail!(
                "{name} data not found at {} — run the tool from the directory the service runs in (relative paths \
                 count from there; the packaged service runs in /var/lib/luradb), or start the server once with the \
                 {name} engine enabled, shut it down, then rerun",
                std::env::current_dir()?.join(&files.sstables).display()
            );
        }
        let unflushed = wal::recover(&files.wal).await?.next().await.transpose()?.is_some();
        let way = if enabled {
            "start the server once to flush, then shut it down".to_string()
        } else {
            format!("enable the {} engine, start the server once to flush, shut it down, then rerun", engine.as_str())
        };
        anyhow::ensure!(
            !unflushed,
            "{} holds writes that are not flushed yet — {way}",
            files.wal.display()
        );
    }

    let (mut storage_thread, hub) = start_storage_thread(config)?;
    let opened = system::open_with_wal(system_dir, WriteAheadLog::with_storage_handle(hub.clone(), WalTarget::Sys)).await;
    let result = match opened {
        Ok(sys) => {
            let result = run(config, &sys, &hub, shards).await;
            sys.shutdown().await;
            result
        }
        Err(e) => Err(e),
    };
    storage_thread.shutdown();
    result
}

async fn run(config: &LuraConfig, sys: &LsmStorageEngine, hub: &StorageHandle, shards: u16) -> anyhow::Result<()> {
    if let Some(raw) = system::pending_migration(sys).await? {
        let marker: Marker = serde_json::from_slice(&raw).context("read the migration marker")?;
        anyhow::ensure!(
            marker.shards == shards,
            "the change to {0} shards is incomplete — finish it with --migrate-shards {0} first",
            marker.shards
        );
        tracing::info!("Finishing the change to {shards} data shards.");
        return switch(sys, &marker).await;
    }

    anyhow::ensure!(system::layout_is_sharded(sys).await?, NOT_SHARDED);
    let from = system::stored_shard_count(sys).await?.context(NOT_SHARDED)?;
    let engines: Vec<(Engine, EngineFiles)> =
        engine_files(config).into_iter().filter(|(_, files)| holds_data(files, from)).collect();
    let roots = roots(config, engines.iter().map(|(_, files)| files));
    for root in &roots {
        remove_stale_staging(root)?;
    }
    if from == shards {
        tracing::info!("The data directory already has {shards} data shards.");
        return Ok(());
    }

    let marker = Marker { shards, staging: format!("migrate_{}", format_utc_timestamp(now_secs())), roots };
    tracing::info!("Changing the data shards from {from} to {shards}.");
    if let Err(e) = build(config, hub, &engines, &marker.roots, from, &marker).await {
        for root in &marker.roots {
            let _ = std::fs::remove_dir_all(root.join(&marker.staging));
        }
        return Err(e);
    }
    system::mark_migration(sys, &serde_json::to_vec(&marker)?).await?;
    switch(sys, &marker).await
}

/// Each engine's configured files.
fn engine_files(config: &LuraConfig) -> [(Engine, EngineFiles); 3] {
    let files = |wal: &str, vlog: &str, sstables: &str| EngineFiles {
        wal: PathBuf::from(wal),
        vlog: PathBuf::from(vlog),
        sstables: PathBuf::from(sstables),
    };
    let (kv, json, rel) = (&config.storage, &config.json, &config.rel);
    [
        (Engine::Kv, files(&kv.wal_path, &kv.vlog_path, &kv.sstable_dir)),
        (Engine::Json, files(&json.wal_path, &json.vlog_path, &json.sstable_dir)),
        (Engine::Rel, files(&rel.wal_path, &rel.vlog_path, &rel.sstable_dir)),
    ]
}

/// Whether an instance of the engine on `files` ever ran on one of `shards`.
fn holds_data(files: &EngineFiles, shards: u16) -> bool {
    (0..usize::from(shards)).any(|k| layout::shard_dir(&files.sstables, k).is_dir())
}

/// `path`'s directory, `.` for a bare file name.
fn parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The directories holding `shard_<k>/` directories: the page files', and
/// the value logs' and SSTables' of the engines on `files`.
fn roots<'a>(config: &LuraConfig, files: impl Iterator<Item = &'a EngineFiles>) -> Vec<PathBuf> {
    let mut roots = vec![parent(Path::new(&config.storage.db_path))];
    for files in files {
        roots.push(parent(&files.vlog));
        roots.push(files.sstables.clone());
    }
    roots.sort();
    roots.dedup();
    roots
}

/// Removes the staging directories of a migration that stopped before its
/// marker went up, or that finished but could not clean up: directories
/// named `migrate_<timestamp>` that hold nothing but `shard_<k>/` and
/// `previous/` directories.
fn remove_stale_staging(root: &Path) -> anyhow::Result<()> {
    let Ok(entries) = std::fs::read_dir(root) else { return Ok(()) };
    for entry in entries {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if !name.starts_with("migrate_") || !path.is_dir() {
            continue;
        }
        if is_staging_name(name) && holds_only_layouts(&path)? {
            std::fs::remove_dir_all(&path).with_context(|| format!("remove {}", path.display()))?;
            tracing::info!("Removed the leftover staging directory {}.", path.display());
        } else {
            tracing::info!("Left {} alone: the migration tool did not write it.", path.display());
        }
    }
    Ok(())
}

/// Whether `name` is `migrate_YYYYMMDDTHHMMSSZ`.
fn is_staging_name(name: &str) -> bool {
    let Some(stamp) = name.strip_prefix("migrate_") else { return false };
    let b = stamp.as_bytes();
    b.len() == 16 && b[8] == b'T' && b[15] == b'Z' && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
}

/// Whether `dir` holds nothing but `shard_<k>/` and `previous/` directories.
fn holds_only_layouts(dir: &Path) -> anyhow::Result<bool> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().unwrap_or_default();
        if !entry.file_type()?.is_dir() || !(name == PREVIOUS || is_shard_name(name)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The files of the engine on `files` in the staging directory `staging`.
fn staged(files: &EngineFiles, staging: &str) -> EngineFiles {
    EngineFiles {
        wal: files.wal.clone(),
        vlog: parent(&files.vlog).join(staging).join(files.vlog.file_name().unwrap_or_default()),
        sstables: files.sstables.join(staging),
    }
}

fn options(config: &LuraConfig, engine: Engine, memory: &MemorySplit) -> LsmEngineOptions {
    match engine {
        Engine::Kv => kv_options(config, memory),
        Engine::Json => JsonEngine::lsm_options(&config.json, memory.block_cache()),
        Engine::Rel => RelEngine::lsm_options(&config.rel, memory.block_cache()),
    }
}

/// Builds the new layout in the staging directory of every root, then makes
/// it durable.
async fn build(
    config: &LuraConfig,
    hub: &StorageHandle,
    engines: &[(Engine, EngineFiles)],
    roots: &[PathBuf],
    from: u16,
    marker: &Marker,
) -> anyhow::Result<()> {
    for root in roots {
        for k in 0..usize::from(marker.shards) {
            let dir = layout::shard_dir(&root.join(&marker.staging), k);
            std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        }
    }
    let memory = MemorySplit::of(config, marker.shards);
    for (engine, files) in engines {
        let wal = Arc::new(WriteAheadLog::with_storage_handle(hub.clone(), (*engine).into()));
        copy(files, from, marker, &wal, || options(config, *engine, &memory))
            .await
            .with_context(|| format!("copy the {} engine", engine.as_str()))?;
        #[cfg(test)]
        super::test_hook::migration_fault(&config.storage.system_dir, "during the copy")?;
    }
    for root in roots {
        sync_tree(&root.join(&marker.staging))?;
        sync_dir(root)?;
        check_one_file_system(root, &root.join(&marker.staging), device)?;
    }
    Ok(())
}

/// The device `path` itself lies on, a symbolic link not followed.
fn device(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).map(|meta| meta.dev())
}

/// Fails unless `staging` and the `shard_<k>/` directories of `root` lie on
/// the file system of `root`: a `rename` moves nothing across, nor a mount
/// point.
fn check_one_file_system(root: &Path, staging: &Path, device: impl Fn(&Path) -> std::io::Result<u64>) -> anyhow::Result<()> {
    let device = |path: &Path| device(path).with_context(|| format!("stat {}", path.display()));
    let expected = device(root)?;
    for path in std::iter::once(staging.to_path_buf()).chain(shard_dirs(root)?) {
        anyhow::ensure!(
            device(&path)? == expected,
            "{} is on another file system than {} (a mount point?); the new layout can only be moved into place \
             within one file system",
            path.display(),
            root.display()
        );
    }
    Ok(())
}

/// Copies every key's newest version from the `from` instances on `files`
/// to the instance of the shard that owns it among those in the staging
/// directory. No record reaches `wal`.
async fn copy(
    files: &EngineFiles,
    from: u16,
    marker: &Marker,
    wal: &Arc<WriteAheadLog>,
    options: impl Fn() -> LsmEngineOptions,
) -> anyhow::Result<()> {
    let staged = staged(files, &marker.staging);
    let mut targets = Vec::with_capacity(usize::from(marker.shards));
    for k in 0..usize::from(marker.shards) {
        targets.push(recovery::open_instance(&staged, k, Arc::clone(wal), options()).await?);
    }
    let batch_bytes = options().engine.memtable_size_threshold;
    for k in 0..usize::from(from) {
        let source = recovery::open_instance(files, k, Arc::clone(wal), options()).await?;
        let snapshot = source.snapshot().await;
        let reader = source.build_reader();
        let mut batches: Vec<(Vec<RawEntry>, usize)> = targets.iter().map(|_| (Vec::new(), 0)).collect();
        for entry in reader.export_raw(snapshot.snapshot())? {
            let entry = entry?;
            let shard = recovery::owner(&entry.key, marker.shards)
                .with_context(|| format!("the key '{}' belongs to no domain", String::from_utf8_lossy(&entry.key)))?;
            let (batch, bytes) = &mut batches[shard];
            *bytes += entry.key.len() + if let RawValue::Bytes(value) = &entry.value { value.len() } else { 0 };
            batch.push(entry);
            if *bytes >= batch_bytes {
                targets[shard].import_raw(std::mem::take(batch)).await?;
                *bytes = 0;
            }
        }
        for (target, (batch, _)) in targets.iter().zip(batches) {
            if !batch.is_empty() {
                target.import_raw(batch).await?;
            }
        }
    }
    for target in &targets {
        target.shutdown_flush().await?;
    }
    Ok(())
}

/// Syncs every file and directory under `dir`, and `dir` itself.
fn sync_tree(dir: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            sync_tree(&path)?;
        } else {
            std::fs::File::open(&path)
                .and_then(|file| file.sync_all())
                .with_context(|| format!("sync {}", path.display()))?;
        }
    }
    sync_dir(dir)
}

/// Moves the new layout into place in every root of the marker, then records
/// the new shard count and drops the marker in one write, and only then
/// removes the old layout. Moves nothing unless every root is ready.
async fn switch(sys: &LsmStorageEngine, marker: &Marker) -> anyhow::Result<()> {
    for root in &marker.roots {
        check_ready(root, &root.join(&marker.staging), marker.shards)?;
    }
    for root in &marker.roots {
        swap(root, &root.join(&marker.staging), marker.shards)
            .with_context(|| format!("move the new layout into {}", root.display()))?;
        #[cfg(test)]
        super::test_hook::migration_fault(&root.to_string_lossy(), "after its swap")?;
    }
    system::complete_migration(sys, marker.shards).await?;
    for root in &marker.roots {
        let staging = root.join(&marker.staging);
        if let Err(e) = std::fs::remove_dir_all(&staging) {
            tracing::warn!("Removing the old layout in {} failed: {e}", staging.display());
        }
    }
    tracing::info!("Data shards: {}.", marker.shards);
    Ok(())
}

/// Fails unless the new layout of `root` waits in `staging` or has moved
/// into place already.
fn check_ready(root: &Path, staging: &Path, shards: u16) -> anyhow::Result<()> {
    let waiting = (0..usize::from(shards)).any(|k| layout::shard_dir(staging, k).is_dir());
    let moved =
        staging.join(PREVIOUS).is_dir() && (0..usize::from(shards)).all(|k| layout::shard_dir(root, k).is_dir());
    anyhow::ensure!(
        waiting || moved,
        "{} holds neither the new layout in {} nor one moved into place; nothing changed. Restore that directory \
         (relative data paths count from the directory the tool first ran in), then rerun --migrate-shards {shards}",
        root.display(),
        staging.display()
    );
    Ok(())
}

/// Moves the `shard_<k>/` directories of `root` into `staging/previous/`
/// and those of `staging` into `root`. Resumes where an earlier run
/// stopped: while every new directory still waits in `staging`, the ones in
/// `root` are old; once one has moved, the old ones are all gone.
fn swap(root: &Path, staging: &Path, shards: u16) -> anyhow::Result<()> {
    let waiting: Vec<usize> =
        (0..usize::from(shards)).filter(|&k| layout::shard_dir(staging, k).is_dir()).collect();
    if waiting.is_empty() {
        return Ok(());
    }
    if waiting.len() == usize::from(shards) {
        let previous = staging.join(PREVIOUS);
        std::fs::create_dir_all(&previous).with_context(|| format!("create {}", previous.display()))?;
        for old in shard_dirs(root)? {
            let to = previous.join(old.file_name().unwrap_or_default());
            std::fs::rename(&old, &to).with_context(|| format!("move {} to {}", old.display(), to.display()))?;
        }
        sync_dir(&previous)?;
        sync_dir(root)?;
    }
    for k in waiting {
        let (from, to) = (layout::shard_dir(staging, k), layout::shard_dir(root, k));
        anyhow::ensure!(!to.exists(), "{} exists already", to.display());
        std::fs::rename(&from, &to).with_context(|| format!("move {} to {}", from.display(), to.display()))?;
    }
    sync_dir(root)?;
    sync_dir(staging)
}

/// The `shard_<k>/` directories in `root`.
fn shard_dirs(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if is_shard_name(name) && path.is_dir() {
            dirs.push(path);
        }
    }
    Ok(dirs)
}

fn is_shard_name(name: &str) -> bool {
    name.strip_prefix("shard_").is_some_and(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{exchange, get, open_kv_engine, request, shard_in, sql_body, test_config, with_body};
    use super::super::{test_hook, Server};
    use super::*;
    use crate::control::slots::domain_name_for_shard;
    use crate::engines::lsm::domain::fnv64;
    use crate::engines::lsm::hlc::{HLCTimestamp, HybridLogicalClock};
    use serde_json::{json, Value};
    use std::future::Future;
    use std::net::SocketAddr;

    /// A domain on shard 0 of two and one on shard 1.
    fn two_domains() -> [String; 2] {
        [domain_name_for_shard(0, 2, 71), domain_name_for_shard(1, 2, 71)]
    }

    /// The test config of `dir` with every engine on and `shards` data
    /// shards, `0` for as many as the data directory was written with.
    fn config(dir: &Path, shards: u16) -> LuraConfig {
        let mut cfg = test_config(dir);
        cfg.json.enabled = true;
        cfg.rel.enabled = true;
        cfg.multicore.shards = shards;
        cfg
    }

    /// [`config`] with each engine's files and the system store in a
    /// directory of their own.
    fn split_config(dir: &Path, shards: u16) -> LuraConfig {
        let mut cfg = config(dir, shards);
        let at = |root: &str, name: &str| {
            std::fs::create_dir_all(dir.join(root)).unwrap();
            dir.join(root).join(name).to_string_lossy().into_owned()
        };
        (cfg.storage.db_path, cfg.storage.wal_path) = (at("kv", "luradb.db"), at("kv", "luradb.wal"));
        (cfg.storage.vlog_path, cfg.storage.sstable_dir) = (at("kv", "luradb.vlog"), at("kv", "sstables"));
        (cfg.json.wal_path, cfg.json.vlog_path, cfg.json.sstable_dir) =
            (at("json", "json.wal"), at("json", "json.vlog"), at("json", "sstables"));
        (cfg.rel.wal_path, cfg.rel.vlog_path, cfg.rel.sstable_dir) =
            (at("rel", "rel.wal"), at("rel", "rel.vlog"), at("rel", "sstables"));
        cfg.storage.system_dir = at("system", "sys");
        cfg
    }

    /// Runs `client` against a server on `config`, then shuts it down.
    fn serve<F, Fut, T>(config: LuraConfig, client: F) -> T
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: Future<Output = T>,
    {
        let server = Server::start(Arc::new(config), Path::new("luradb.toml")).unwrap();
        let addr = server.http_addr.expect("HTTP listener enabled");
        let out = tokio::runtime::Runtime::new().unwrap().block_on(client(addr));
        server.shutdown().unwrap();
        out
    }

    async fn expect(addr: SocketAddr, raw: &str, status: u16) {
        let (got, body) = request(addr, raw).await;
        assert_eq!(got, status, "{}: {}", raw.lines().next().unwrap(), String::from_utf8_lossy(&body));
    }

    fn delete(path: &str) -> String {
        format!("DELETE {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
    }

    /// Key-value, JSON and relational data in each of `names`: plain, large,
    /// NULL, deleted and expiring keys; indexed and deleted documents; a
    /// table with an index and an AUTOINCREMENT key, one row deleted.
    async fn fill(addr: SocketAddr, names: &[String]) {
        for name in names {
            let create = json!({ "name": name }).to_string();
            for path in ["/store-api/domains", "/store-api/json/domains", "/store-api/rel/domains"] {
                expect(addr, &with_body("POST", path, &create), 201).await;
            }
            let kv = format!("/store-api/kv/{name}/keys");
            expect(addr, &with_body("PUT", &format!("{kv}/k"), &format!("clé {name}")), 200).await;
            expect(addr, &with_body("PUT", &format!("{kv}/ttl?ttl=86400"), "tok"), 200).await;
            expect(addr, &with_body("PUT", &format!("{kv}/big"), &"✓".repeat(4096)), 200).await;
            expect(addr, &with_body("PATCH", &format!("{kv}/nulled/null"), ""), 200).await;
            expect(addr, &with_body("PUT", &format!("{kv}/gone"), "v"), 200).await;
            expect(addr, &delete(&format!("{kv}/gone")), 204).await;

            let json = format!("/store-api/json/{name}");
            let index = json!({ "field": "city", "type": "string" }).to_string();
            expect(addr, &with_body("POST", &format!("{json}/indexes"), &index), 201).await;
            for (key, city) in [("d1", "Lyon"), ("d2", "Porto"), ("d3", "Oslo")] {
                let doc = json!({ "city": city }).to_string();
                expect(addr, &with_body("PUT", &format!("{json}/documents/{key}"), &doc), 201).await;
            }
            expect(addr, &delete(&format!("{json}/documents/d3")), 204).await;

            let sql = format!("/store-api/rel/{name}/sql");
            for statement in [
                "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, city TEXT NOT NULL)",
                "CREATE INDEX t_city_idx ON t (city)",
                "INSERT INTO t (city) VALUES ('Lyon')",
                "INSERT INTO t (city) VALUES ('Porto')",
                "INSERT INTO t (city) VALUES ('Oslo')",
                "DELETE FROM t WHERE city = 'Oslo'",
            ] {
                expect(addr, &with_body("POST", &sql, &sql_body(statement)), 200).await;
            }
        }
    }

    /// The data key of `key` in the key-value domain `domain`.
    fn data_key(domain: &str, key: &str) -> Vec<u8> {
        format!("d:{:016x}:{key}", fnv64(domain.as_bytes())).into_bytes()
    }

    /// Writes an expired version of `expired` into `domain` on shard 0.
    fn expire_one(config: &LuraConfig, domain: &str) {
        crate::core::engine_runtime::block_on(async {
            let kv = open_kv_engine(config, Some(0)).await;
            kv.put_expired_for_test(&data_key(domain, "expired"), b"v").await.unwrap();
            kv.shutdown().await;
        });
    }

    /// Every answer a client gets about `names`, request by request.
    async fn observe(addr: SocketAddr, names: &[String]) -> Vec<(String, u16, String)> {
        let mut requests = vec![get("/store-api/domains"), get("/store-api/json/domains"), get("/store-api/rel/domains")];
        for name in names {
            let kv = format!("/store-api/kv/{name}/keys");
            requests.push(get(&kv));
            for key in ["k", "ttl", "big", "nulled", "gone", "expired"] {
                requests.push(get(&format!("{kv}/{key}")));
                requests.push(get(&format!("{kv}/{key}/meta")));
            }
            let json = format!("/store-api/json/{name}");
            requests.push(get(&format!("{json}/indexes")));
            requests.push(get(&format!("{json}/documents")));
            requests.push(get(&format!("{json}/documents/d3")));
            requests.push(with_body("POST", &format!("{json}/search"), &json!({ "filter": { "city": "Lyon" } }).to_string()));
            let sql = format!("/store-api/rel/{name}/sql");
            for statement in ["SELECT * FROM t ORDER BY id", "SELECT id FROM t WHERE city = 'Lyon'"] {
                requests.push(with_body("POST", &sql, &sql_body(statement)));
            }
        }
        let mut seen = Vec::with_capacity(requests.len());
        for raw in requests {
            let (status, body) = request(addr, &raw).await;
            let line = raw.lines().next().unwrap().to_string() + raw.rsplit("\r\n").next().unwrap_or_default();
            seen.push((line, status, String::from_utf8_lossy(&body).into_owned()));
        }
        seen
    }

    /// The data shard each of `names` is read on.
    async fn read_on(addr: SocketAddr, names: &[String]) -> Vec<String> {
        let mut shards = Vec::new();
        for name in names {
            let (status, head, _) = exchange(addr, &get(&format!("/store-api/kv/{name}/keys/k"))).await;
            assert_eq!(status, 200);
            shards.push(shard_in(&head).to_string());
        }
        shards
    }

    /// Whether `dir` holds SSTables.
    fn has_sstables(dir: &Path) -> bool {
        std::fs::read_dir(dir)
            .map(|entries| entries.flatten().any(|e| e.file_name().to_string_lossy().starts_with("sstable_")))
            .unwrap_or(false)
    }

    /// The names under `dir` that start with `migrate_`.
    fn staging_left(dirs: &[PathBuf]) -> Vec<PathBuf> {
        dirs.iter()
            .flat_map(|dir| std::fs::read_dir(dir).into_iter().flatten().flatten())
            .map(|entry| entry.path())
            .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with("migrate_"))
            .collect()
    }

    /// A data directory of one shard goes to two and back to one; after each
    /// step every answer is the one before, and with two shards the domains
    /// live on different shards. The relational key sequence carries on
    /// afterwards.
    #[test]
    fn a_migration_from_one_shard_to_two_and_back_keeps_every_answer() {
        let dir = tempfile::TempDir::new().unwrap();
        let names = two_domains();
        serve(config(dir.path(), 1), |addr| async move { fill(addr, &two_domains()).await });
        expire_one(&config(dir.path(), 1), &names[0]);
        let before = serve(config(dir.path(), 1), |addr| async move { observe(addr, &two_domains()).await });
        let count = |status: u16| before.iter().filter(|(_, got, _)| *got == status).count();
        // Per domain 13 answers with data, the NULL key, and 5 misses: the
        // deleted and expired keys with their metadata and the deleted document.
        assert_eq!((count(200), count(204), count(404)), (3 + 2 * 13, 2, 2 * 5), "{before:#?}");

        migrate_shards(&config(dir.path(), 0), 2).unwrap();
        let (after, shards) = serve(config(dir.path(), 0), |addr| async move {
            (observe(addr, &two_domains()).await, read_on(addr, &two_domains()).await)
        });
        assert_eq!(after, before, "after 1 -> 2");
        assert_eq!(shards, ["0", "1"]);
        let cfg = config(dir.path(), 0);
        for sstables in [&cfg.storage.sstable_dir, &cfg.json.sstable_dir, &cfg.rel.sstable_dir] {
            for k in 0..2 {
                assert!(has_sstables(&layout::shard_dir(Path::new(sstables), k)), "{sstables} shard {k}");
            }
        }

        migrate_shards(&config(dir.path(), 0), 1).unwrap();
        let (after, inserted) = serve(config(dir.path(), 0), |addr| async move {
            let seen = observe(addr, &two_domains()).await;
            let sql = format!("/store-api/rel/{}/sql", two_domains()[1]);
            expect(addr, &with_body("POST", &sql, &sql_body("INSERT INTO t (city) VALUES ('Kyiv')")), 200).await;
            let (_, rows) = request(addr, &with_body("POST", &sql, &sql_body("SELECT id FROM t WHERE city = 'Kyiv'"))).await;
            (seen, serde_json::from_slice::<Value>(&rows).unwrap())
        });
        assert_eq!(after, before, "after 2 -> 1");
        assert_eq!(inserted["rows"][0], json!([4]), "the key sequence carries on: {inserted}");
        assert!(!layout::shard_dir(Path::new(&cfg.storage.sstable_dir), 1).exists());
        assert!(staging_left(&[dir.path().to_path_buf(), PathBuf::from(&cfg.storage.sstable_dir)]).is_empty());
    }

    /// The ETag of a lower-cased response head as the stamp it carries.
    fn stamp_in(head: &str) -> u64 {
        let tag = head.lines().find_map(|line| line.strip_prefix("etag: ")).expect("an ETag");
        u64::from_str_radix(tag.trim().trim_matches('"'), 16).unwrap()
    }

    /// Data stamped far ahead of the clock keeps its stamps through the
    /// migration, and the first write afterwards on its new shard stamps
    /// above them.
    #[test]
    fn the_first_write_after_a_migration_stamps_above_the_moved_versions() {
        let dir = tempfile::TempDir::new().unwrap();
        let name = two_domains()[1].clone();
        let create = json!({ "name": name }).to_string();
        serve(config(dir.path(), 1), |addr| async move {
            expect(addr, &with_body("POST", "/store-api/domains", &create), 201).await;
        });
        let moved = crate::core::engine_runtime::block_on(async {
            let kv = open_kv_engine(&config(dir.path(), 1), Some(0)).await;
            let ahead = HybridLogicalClock::physical_time() + 10 * 24 * 3600 * 1000;
            kv.hlc().update(HLCTimestamp::from_components(ahead, 0)).unwrap();
            kv.put(&data_key(&name, "ahead"), b"v").await.unwrap();
            let stamp = kv.get_latest_with_stamp(&data_key(&name, "ahead")).await.unwrap().2;
            kv.shutdown().await;
            stamp
        });

        migrate_shards(&config(dir.path(), 0), 2).unwrap();
        let name = two_domains()[1].clone();
        let (kept, next) = serve(config(dir.path(), 0), |addr| async move {
            let kv = format!("/store-api/kv/{name}/keys");
            let (_, head, _) = exchange(addr, &get(&format!("{kv}/ahead"))).await;
            assert_eq!(shard_in(&head), "1");
            expect(addr, &with_body("PUT", &format!("{kv}/after"), "v"), 200).await;
            let (_, after, _) = exchange(addr, &get(&format!("{kv}/after"))).await;
            (stamp_in(&head), stamp_in(&after))
        });
        assert_eq!(kept, moved, "the moved version keeps its stamp");
        assert!(next > moved, "{next:x} must be above {moved:x}");
    }

    /// With every engine and the system store in a directory of its own, a
    /// migration stopped after the first move leaves its marker, the server
    /// refuses to start, and a second run finishes it.
    #[test]
    fn a_migration_stopped_between_two_data_roots_is_finished_by_the_next_run() {
        let dir = tempfile::TempDir::new().unwrap();
        serve(split_config(dir.path(), 1), |addr| async move { fill(addr, &two_domains()).await });
        let before = serve(split_config(dir.path(), 1), |addr| async move { observe(addr, &two_domains()).await });
        let roots: Vec<PathBuf> =
            ["json", "json/sstables", "kv", "kv/sstables", "rel", "rel/sstables"].map(|root| dir.path().join(root)).to_vec();

        test_hook::fail_migration_at(&roots[0].to_string_lossy(), "after its swap");
        let err = migrate_shards(&split_config(dir.path(), 0), 2).unwrap_err();
        assert!(format!("{err:#}").contains("injected fault after its swap"), "{err:#}");
        assert!(layout::shard_dir(&roots[0], 1).is_dir(), "the first root is moved");
        assert!(!layout::shard_dir(&roots[2], 1).exists(), "the others are not");

        let err = Server::start(Arc::new(split_config(dir.path(), 0)), Path::new("luradb.toml")).err().expect("refused");
        assert!(format!("{err:#}").contains("shard migration incomplete — rerun the migration tool"), "{err:#}");

        migrate_shards(&split_config(dir.path(), 0), 2).unwrap();
        for root in &roots {
            let mut shards: Vec<String> =
                shard_dirs(root).unwrap().iter().map(|d| d.file_name().unwrap().to_string_lossy().into_owned()).collect();
            shards.sort();
            assert_eq!(shards, ["shard_0", "shard_1"], "{}", root.display());
        }
        assert!(staging_left(&roots).is_empty(), "{:?}", staging_left(&roots));
        let after = serve(split_config(dir.path(), 0), |addr| async move { observe(addr, &two_domains()).await });
        assert_eq!(after, before);
    }

    /// A root that holds neither its staging directory nor the moved layout
    /// stops a resumed run before any move and before the commit: the server
    /// still refuses to start, and once the staging directory is back the
    /// next run finishes the change.
    #[test]
    fn a_root_without_its_staging_directory_stops_the_move_before_the_commit() {
        let dir = tempfile::TempDir::new().unwrap();
        serve(split_config(dir.path(), 1), |addr| async move { fill(addr, &two_domains()).await });
        let before = serve(split_config(dir.path(), 1), |addr| async move { observe(addr, &two_domains()).await });
        let (waiting, lost) = (dir.path().join("json/sstables"), dir.path().join("kv"));
        test_hook::fail_migration_at(&dir.path().join("json").to_string_lossy(), "after its swap");
        migrate_shards(&split_config(dir.path(), 0), 2).unwrap_err();
        let staging = staging_left(std::slice::from_ref(&lost)).pop().expect("a staging directory");
        let aside = dir.path().join("aside");
        std::fs::rename(&staging, &aside).unwrap();

        let err = migrate_shards(&split_config(dir.path(), 0), 2).unwrap_err();
        assert!(format!("{err:#}").contains(&format!("{} holds neither", lost.display())), "{err:#}");
        assert!(!layout::shard_dir(&waiting, 1).exists(), "no further root moved");
        let err = Server::start(Arc::new(split_config(dir.path(), 0)), Path::new("luradb.toml")).err().expect("refused");
        assert!(format!("{err:#}").contains("shard migration incomplete"), "{err:#}");

        std::fs::rename(&aside, &staging).unwrap();
        migrate_shards(&split_config(dir.path(), 0), 2).unwrap();
        let after = serve(split_config(dir.path(), 0), |addr| async move { observe(addr, &two_domains()).await });
        assert_eq!(after, before);
    }

    /// The tool refuses to run beside the server and on a write-ahead log
    /// with unflushed writes; one that fails during the copy leaves the old
    /// layout, which starts as before.
    #[test]
    fn the_tool_refuses_a_running_server_and_unflushed_logs_and_a_failed_copy_changes_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let names = two_domains();
        let server = Server::start(Arc::new(config(dir.path(), 1)), Path::new("luradb.toml")).unwrap();
        let addr = server.http_addr.unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(fill(addr, &names));
        let err = migrate_shards(&config(dir.path(), 0), 2).unwrap_err();
        server.shutdown().unwrap();
        assert!(format!("{err:#}").contains("stop the server before changing the shard count"), "{err:#}");
        assert!(format!("{err:#}").contains("is in use by another LuraDB process"), "{err:#}");

        crate::core::engine_runtime::block_on(async {
            let kv = open_kv_engine(&config(dir.path(), 1), Some(0)).await;
            kv.put(&data_key(&names[0], "late"), b"v").await.unwrap();
            kv.stop_background_tasks().await;
        });
        let err = migrate_shards(&config(dir.path(), 0), 2).unwrap_err();
        assert!(format!("{err:#}").contains("start the server once to flush, then shut it down"), "{err:#}");
        let cfg = config(dir.path(), 1);
        let dirs = [dir.path().to_path_buf(), PathBuf::from(&cfg.storage.sstable_dir), PathBuf::from(&cfg.json.sstable_dir)];
        assert!(staging_left(&dirs).is_empty());

        let late = format!("/store-api/kv/{}/keys/late", names[0]);
        let before = serve(config(dir.path(), 1), |addr| async move {
            assert_eq!(request(addr, &get(&late)).await, (200, b"v".to_vec()), "the log was recovered");
            observe(addr, &two_domains()).await
        });

        test_hook::fail_migration_at(&cfg.storage.system_dir, "during the copy");
        let err = migrate_shards(&config(dir.path(), 0), 2).unwrap_err();
        assert!(format!("{err:#}").contains("injected fault during the copy"), "{err:#}");
        assert!(staging_left(&dirs).is_empty(), "{:?}", staging_left(&dirs));
        let after = serve(config(dir.path(), 1), |addr| async move { observe(addr, &two_domains()).await });
        assert_eq!(after, before);
    }

    /// Unflushed writes of an engine the config turns off name the way to
    /// flush them: the server leaves such a log alone.
    #[test]
    fn unflushed_writes_of_a_disabled_engine_name_how_to_flush_them() {
        let dir = tempfile::TempDir::new().unwrap();
        let names = two_domains();
        serve(config(dir.path(), 1), |_| async {});
        let mut on_json = config(dir.path(), 1);
        (on_json.storage.wal_path, on_json.storage.vlog_path, on_json.storage.sstable_dir) =
            (on_json.json.wal_path.clone(), on_json.json.vlog_path.clone(), on_json.json.sstable_dir.clone());
        crate::core::engine_runtime::block_on(async {
            let json = open_kv_engine(&on_json, Some(0)).await;
            json.put(&data_key(&names[0], "late"), b"v").await.unwrap();
            json.stop_background_tasks().await;
        });

        let mut json_off = config(dir.path(), 0);
        json_off.json.enabled = false;
        let err = migrate_shards(&json_off, 2).unwrap_err();
        let way = "enable the json engine, start the server once to flush, shut it down, then rerun";
        assert!(format!("{err:#}").contains(way), "{err:#}");
    }

    /// An enabled engine whose SSTable directory is not where the config
    /// points, by an absolute or a relative path, stops the tool before it
    /// creates or changes anything: the old layout starts as before.
    #[test]
    fn an_enabled_engine_without_its_data_directory_stops_the_tool_unchanged() {
        let dir = tempfile::TempDir::new().unwrap();
        serve(split_config(dir.path(), 1), |addr| async move { fill(addr, &two_domains()).await });
        let before = serve(split_config(dir.path(), 1), |addr| async move { observe(addr, &two_domains()).await });
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let in_empty = |name: &str| empty.join(name).to_string_lossy().into_owned();
        // Relative to the working directory, under a directory that does not
        // exist: nothing can be created there.
        let missing = PathBuf::from(format!("missing-{}", dir.path().file_name().unwrap().to_string_lossy()));
        let in_missing = |name: &str| missing.join(name).to_string_lossy().into_owned();

        let mut json_elsewhere = split_config(dir.path(), 0);
        (json_elsewhere.json.wal_path, json_elsewhere.json.vlog_path, json_elsewhere.json.sstable_dir) =
            (in_empty("json.wal"), in_empty("json.vlog"), in_empty("sstables"));
        let mut rel_elsewhere = split_config(dir.path(), 0);
        (rel_elsewhere.rel.wal_path, rel_elsewhere.rel.vlog_path, rel_elsewhere.rel.sstable_dir) =
            (in_empty("rel.wal"), in_empty("rel.vlog"), in_empty("sstables"));
        let mut rel_relative = split_config(dir.path(), 0);
        (rel_relative.rel.wal_path, rel_relative.rel.vlog_path, rel_relative.rel.sstable_dir) =
            (in_missing("rel.wal"), in_missing("rel.vlog"), in_missing("sstables"));
        let cases = [
            (json_elsewhere, "json", empty.join("sstables")),
            (rel_elsewhere, "rel", empty.join("sstables")),
            (rel_relative, "rel", std::env::current_dir().unwrap().join(&missing).join("sstables")),
        ];
        let roots: Vec<PathBuf> =
            ["json", "json/sstables", "kv", "kv/sstables", "rel", "rel/sstables"].map(|root| dir.path().join(root)).to_vec();

        for (cfg, engine, shown) in cases {
            let err = format!("{:#}", migrate_shards(&cfg, 2).unwrap_err());
            let found = format!("{engine} data not found at {} — run the tool from the directory", shown.display());
            assert!(err.contains(&found), "{err}");
            assert!(err.contains(&format!("start the server once with the {engine} engine enabled")), "{err}");
            assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0, "no file in {}", empty.display());
            assert!(!missing.exists(), "{} created", missing.display());
            assert!(staging_left(&roots).is_empty(), "{:?}", staging_left(&roots));
        }
        let (after, shards) = serve(split_config(dir.path(), 0), |addr| async move {
            (observe(addr, &two_domains()).await, read_on(addr, &two_domains()).await)
        });
        assert_eq!(after, before);
        assert_eq!(shards, ["0", "0"], "the stored shard count is still 1");
    }

    /// An enabled engine that never ran on the data directory stops the tool
    /// with the way to create its data; turned off, it is skipped and the
    /// other engines move.
    #[test]
    fn an_engine_that_never_ran_stops_the_tool_while_enabled_and_is_skipped_while_disabled() {
        let dir = tempfile::TempDir::new().unwrap();
        let rel_off = |shards: u16| {
            let mut cfg = config(dir.path(), shards);
            cfg.rel.enabled = false;
            cfg
        };
        serve(rel_off(1), |addr| async move {
            for name in &two_domains() {
                let create = json!({ "name": name }).to_string();
                expect(addr, &with_body("POST", "/store-api/domains", &create), 201).await;
                expect(addr, &with_body("POST", "/store-api/json/domains", &create), 201).await;
                expect(addr, &with_body("PUT", &format!("/store-api/kv/{name}/keys/k"), "v"), 200).await;
                let doc = json!({ "city": "Lyon" }).to_string();
                expect(addr, &with_body("PUT", &format!("/store-api/json/{name}/documents/d"), &doc), 201).await;
            }
        });
        let rel_dir = PathBuf::from(config(dir.path(), 0).rel.sstable_dir);
        assert!(!rel_dir.exists(), "the rel engine never ran");

        let err = format!("{:#}", migrate_shards(&config(dir.path(), 0), 2).unwrap_err());
        assert!(err.contains(&format!("rel data not found at {}", rel_dir.display())), "{err}");
        assert!(err.contains("start the server once with the rel engine enabled, shut it down, then rerun"), "{err}");

        migrate_shards(&rel_off(0), 2).unwrap();
        assert!(!rel_dir.exists());
        let cfg = rel_off(0);
        for sstables in [&cfg.storage.sstable_dir, &cfg.json.sstable_dir] {
            for k in 0..2 {
                assert!(has_sstables(&layout::shard_dir(Path::new(sstables), k)), "{sstables} shard {k}");
            }
        }
        let (shards, documents) = serve(rel_off(0), |addr| async move {
            let mut documents = Vec::new();
            for name in &two_domains() {
                documents.push(request(addr, &get(&format!("/store-api/json/{name}/documents/d"))).await.0);
            }
            (read_on(addr, &two_domains()).await, documents)
        });
        assert_eq!(shards, ["0", "1"]);
        assert_eq!(documents, [200, 200]);
    }

    /// Fills `dir` with a file named `content` holding it.
    fn mark(dir: &Path, content: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(content), content).unwrap();
    }

    /// A staging directory left by an earlier run goes on the next run, also
    /// on one for the shard count the data directory has already; a foreign
    /// `migrate_scripts/` and a staging name with foreign content stay.
    #[test]
    fn only_the_tools_own_leftover_staging_directories_are_removed() {
        let dir = tempfile::TempDir::new().unwrap();
        serve(config(dir.path(), 1), |_| async {});
        let leftover = |name: &str| {
            let staging = dir.path().join(name);
            mark(&layout::shard_dir(&staging.join(PREVIOUS), 0), "old");
            staging
        };
        mark(&dir.path().join("migrate_scripts"), "run.sh");
        mark(&dir.path().join("migrate_20260101T000000Z"), "notes");
        let stale = leftover("migrate_20260102T000000Z");
        migrate_shards(&config(dir.path(), 0), 2).unwrap();
        assert!(!stale.exists(), "removed on a run that changes the shard count");

        let stale = leftover("migrate_20260103T000000Z");
        migrate_shards(&config(dir.path(), 0), 2).unwrap();
        assert!(!stale.exists(), "removed on a run with the same shard count");
        assert!(dir.path().join("migrate_scripts").join("run.sh").is_file());
        assert!(dir.path().join("migrate_20260101T000000Z").join("notes").is_file());
    }

    // A root whose staging directory or one of whose shard directories lies
    // on another file system, a mount point, is refused before any move.
    #[test]
    fn a_root_spanning_two_file_systems_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let (root, staging) = (dir.path(), dir.path().join("migrate_x"));
        for k in 0..2 {
            mark(&layout::shard_dir(root, k), "old");
        }
        mark(&layout::shard_dir(&staging, 0), "new");
        check_one_file_system(root, &staging, device).unwrap();

        for foreign in [layout::shard_dir(root, 1), staging.clone()] {
            let device = |path: &Path| Ok(if path == foreign { 2 } else { 1 });
            let err = check_one_file_system(root, &staging, device).unwrap_err();
            assert!(format!("{err:#}").contains(&format!("{} is on another file system", foreign.display())), "{err:#}");
        }
    }

    // A move of the layouts that stopped after any of its renames finishes
    // on the next try: the old directories end up aside, the new ones in
    // place, and a further try changes nothing.
    #[test]
    fn a_swap_stopped_after_any_rename_finishes_on_the_next_try() {
        for done in 0..=5 {
            let dir = tempfile::TempDir::new().unwrap();
            let (root, staging) = (dir.path(), dir.path().join("migrate_x"));
            let previous = staging.join(PREVIOUS);
            for k in 0..2 {
                mark(&layout::shard_dir(root, k), "old");
            }
            for k in 0..3 {
                mark(&layout::shard_dir(&staging, k), "new");
            }
            std::fs::create_dir_all(&previous).unwrap();
            let renames = [
                (layout::shard_dir(root, 0), layout::shard_dir(&previous, 0)),
                (layout::shard_dir(root, 1), layout::shard_dir(&previous, 1)),
                (layout::shard_dir(&staging, 0), layout::shard_dir(root, 0)),
                (layout::shard_dir(&staging, 1), layout::shard_dir(root, 1)),
                (layout::shard_dir(&staging, 2), layout::shard_dir(root, 2)),
            ];
            for (from, to) in &renames[..done] {
                std::fs::rename(from, to).unwrap();
            }

            for _ in 0..2 {
                swap(root, &staging, 3).unwrap();
                for k in 0..3 {
                    assert!(layout::shard_dir(root, k).join("new").is_file(), "{done} renames done: shard {k}");
                    assert!(!layout::shard_dir(&staging, k).exists());
                }
                for k in 0..2 {
                    assert!(layout::shard_dir(&previous, k).join("old").is_file(), "{done} renames done: shard {k}");
                }
            }
        }
    }
}
