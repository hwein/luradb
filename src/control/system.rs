//! System store: an LSM instance of its own, under `storage.system_dir`, for
//! the keys that belong to no domain — auth records and the store's markers.
//! Beside it lies the lock that keeps a second process off the data.

use crate::auth::{PREFIX_PERM, PREFIX_USER};
use crate::core::wal::WriteAheadLog;
use crate::engines::lsm::engine::{BatchOp, LsmEngineConfig, LsmEngineOptions, LsmStorageEngine};
use crate::engines::StorageEngine;
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

/// Write-ahead log of the system store, inside `storage.system_dir`.
pub const WAL_FILE: &str = "wal";
/// Value log of the system store, inside `storage.system_dir`.
pub const VLOG_FILE: &str = "vlog";
/// SSTable directory of the system store, inside `storage.system_dir`.
pub const SSTABLE_DIR: &str = "sstables";

/// Shard count the data directories were last started with.
const SHARDS_KEY: &[u8] = b"__sys:meta:shards";
/// Set once the auth records moved out of the key-value engine.
const AUTH_MIGRATED_KEY: &[u8] = b"__sys:meta:auth_migrated";
/// Data directory layout; `2` keeps each data shard's files in `shard_<k>/`.
const LAYOUT_KEY: &[u8] = b"__sys:meta:layout";
const SHARDED_LAYOUT: &[u8] = b"2";
/// Set while a shard-count migration moves its new layout into place.
const MIGRATION_KEY: &[u8] = b"__sys:meta:migration";
/// Locked by the one process that uses the data directories.
const LOCK_FILE: &str = "lock";

/// Exclusive use of the data directories, held until it drops: the open
/// descriptor holds the lock.
pub struct DataLock {
    _file: std::fs::File,
}

/// Takes the lock in `dir`, the system store's directory, for this process;
/// fails while another process holds it.
pub fn lock_data_dir(dir: &Path) -> Result<DataLock> {
    use std::os::fd::AsRawFd;
    let path = dir.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            anyhow::bail!("{} is in use by another LuraDB process", dir.display());
        }
        anyhow::bail!("lock {}: {e}", path.display());
    }
    Ok(DataLock { _file: file })
}

/// The marker of a shard-count migration that has not finished.
pub async fn pending_migration(sys: &LsmStorageEngine) -> Result<Option<Vec<u8>>> {
    sys.get(MIGRATION_KEY).await
}

pub async fn mark_migration(sys: &LsmStorageEngine, marker: &[u8]) -> Result<()> {
    sys.put(MIGRATION_KEY, marker).await
}

/// Records `shards` as the shard count and drops the migration marker, in
/// one write.
pub async fn complete_migration(sys: &LsmStorageEngine, shards: u16) -> Result<()> {
    sys.write_batch(vec![
        BatchOp::Put { key: SHARDS_KEY.to_vec(), value: shards.to_string().into_bytes() },
        BatchOp::Delete { key: MIGRATION_KEY.to_vec() },
    ])
    .await
}

/// Refuses to start while a shard-count migration has not finished.
pub async fn refuse_pending_migration(sys: &LsmStorageEngine) -> Result<()> {
    if pending_migration(sys).await?.is_some() {
        anyhow::bail!("shard migration incomplete — rerun the migration tool");
    }
    Ok(())
}

/// Opens (or creates) the system store in `dir` with `wal`, the log at
/// `<dir>/wal`, and recovers it.
pub async fn open_with_wal(dir: &Path, wal: WriteAheadLog) -> Result<Arc<LsmStorageEngine>> {
    let sstable_dir = dir.join(SSTABLE_DIR);
    // Creates `dir` too, before the value log goes into it.
    let file_manager = Arc::new(FileManager::new(&sstable_dir).await?);
    let manifest_manager = Arc::new(ManifestManager::new(&sstable_dir));
    let wal_path = dir.join(WAL_FILE);
    let vlog_path = dir.join(VLOG_FILE);
    let wal = Arc::new(wal);
    let vlog = Arc::new(VLog::new(&vlog_path).await?);
    let options = LsmEngineOptions {
        engine: LsmEngineConfig { watch_replay_buffer_size: 0, ..LsmEngineConfig::default() },
        ..LsmEngineOptions::default()
    };
    let engine =
        Arc::new(LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, options).await?);
    engine.start_background_tasks();
    Ok(engine)
}

/// Tests only: [`open_with_wal`] on a local WAL committer instead of the
/// storage hub.
#[cfg(test)]
pub(crate) async fn open(dir: &Path) -> Result<Arc<LsmStorageEngine>> {
    std::fs::create_dir_all(dir)?;
    open_with_wal(dir, WriteAheadLog::new(dir.join(WAL_FILE)).await?).await
}

/// The shard count stored by an earlier start, if any.
pub async fn stored_shard_count(sys: &LsmStorageEngine) -> Result<Option<u16>> {
    let Some(raw) = sys.get(SHARDS_KEY).await? else { return Ok(None) };
    let text = std::str::from_utf8(&raw)?;
    Ok(Some(text.parse().map_err(|e| anyhow::anyhow!("invalid stored shard count '{text}': {e}"))?))
}

/// Refuses to start on data laid out for another shard count; a first
/// start records `configured`.
pub async fn check_shard_count(sys: &LsmStorageEngine, configured: u16) -> Result<()> {
    match stored_shard_count(sys).await? {
        None => sys.put(SHARDS_KEY, configured.to_string().as_bytes()).await,
        Some(stored) if stored == configured => Ok(()),
        Some(stored) => anyhow::bail!(
            "shard count changed (stored {stored}, configured {configured}) — run `luradb --migrate-shards {configured}`"
        ),
    }
}

/// Whether the data directories keep each shard's files in `shard_<k>/`.
pub async fn layout_is_sharded(sys: &LsmStorageEngine) -> Result<bool> {
    Ok(sys.get(LAYOUT_KEY).await?.as_deref() == Some(SHARDED_LAYOUT))
}

/// Records that the data directories keep each shard's files in `shard_<k>/`.
pub async fn mark_layout_sharded(sys: &LsmStorageEngine) -> Result<()> {
    sys.put(LAYOUT_KEY, SHARDED_LAYOUT).await
}

/// Moves the auth records from the key-value engine into the system store,
/// once: copy, then the marker, then delete the originals. A rerun after a
/// crash repeats whatever step did not finish; after the marker the system
/// store's records win and leftovers in the key-value engine are dropped.
pub async fn migrate_auth(kv: &LsmStorageEngine, sys: &LsmStorageEngine) -> Result<()> {
    let mut keys = kv.scan_keys(PREFIX_USER.as_bytes()).await?;
    keys.extend(kv.scan_keys(PREFIX_PERM.as_bytes()).await?);
    if sys.get(AUTH_MIGRATED_KEY).await?.is_none() {
        let mut copies = Vec::with_capacity(keys.len());
        for key in &keys {
            if let Some(value) = kv.get(key).await? {
                copies.push(BatchOp::Put { key: key.clone(), value });
            }
        }
        let copied = copies.len();
        sys.write_batch(copies).await?;
        sys.put(AUTH_MIGRATED_KEY, b"1").await?;
        if copied > 0 {
            tracing::info!("Auth records moved to the system store ({copied} keys).");
        }
    }
    kv.write_batch(keys.into_iter().map(|key| BatchOp::Delete { key }).collect()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage_thread::{TestHub, WalTarget};

    async fn reopen(engine: Arc<LsmStorageEngine>, dir: &Path) -> Arc<LsmStorageEngine> {
        engine.shutdown().await;
        drop(engine);
        open(dir).await.unwrap()
    }

    /// The system store in `dir`; with `on_hub` a fresh storage hub writes its WAL.
    async fn open_on(dir: &Path, on_hub: bool) -> (Arc<LsmStorageEngine>, Option<TestHub>) {
        if !on_hub {
            return (open(dir).await.unwrap(), None);
        }
        std::fs::create_dir_all(dir).unwrap();
        let hub = TestHub::start(&[(WalTarget::Sys, &dir.join(WAL_FILE))]);
        let sys = open_with_wal(dir, hub.wal(WalTarget::Sys)).await.unwrap();
        (sys, Some(hub))
    }

    #[test]
    fn open_lays_out_the_store_and_keeps_its_data_across_a_restart() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let tmp = tempfile::TempDir::new().unwrap();
                let dir = tmp.path().join("sys");
                let (sys, hub) = open_on(&dir, on_hub).await;
                assert!(dir.join(SSTABLE_DIR).is_dir());
                assert!(dir.join(WAL_FILE).is_file());

                sys.put(b"__sys:auth:user:alice", "clé ✓".as_bytes()).await.unwrap();
                sys.shutdown().await;
                drop(sys);
                drop(hub);
                let (sys, _hub) = open_on(&dir, on_hub).await;
                assert_eq!(sys.get(b"__sys:auth:user:alice").await.unwrap(), Some("clé ✓".as_bytes().to_vec()));
            }
        })
    }

    // Writes of a system store that stopped without a shutdown -- no flush,
    // no truncate -- come back from the WAL the storage hub wrote.
    #[test]
    fn unflushed_writes_come_back_from_the_hub_written_wal() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let dir = tmp.path().join("sys");
            let (sys, hub) = open_on(&dir, true).await;
            sys.put("__sys:auth:user:zoé".as_bytes(), b"zoe-record").await.unwrap();
            sys.stop_background_tasks().await;
            drop(sys);
            drop(hub);
            assert!(std::fs::metadata(dir.join(WAL_FILE)).unwrap().len() > 0, "the write is only in the WAL");

            let (sys, _hub) = open_on(&dir, true).await;
            assert_eq!(sys.get("__sys:auth:user:zoé".as_bytes()).await.unwrap(), Some(b"zoe-record".to_vec()));
            sys.shutdown().await;
        })
    }

    #[test]
    fn shard_count_is_recorded_on_first_start_and_survives_a_restart() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let sys = open(tmp.path()).await.unwrap();
            assert_eq!(stored_shard_count(&sys).await.unwrap(), None);

            check_shard_count(&sys, 3).await.unwrap();
            let sys = reopen(sys, tmp.path()).await;
            assert_eq!(stored_shard_count(&sys).await.unwrap(), Some(3));
            check_shard_count(&sys, 3).await.unwrap();
        })
    }

    #[test]
    fn a_changed_shard_count_refuses_the_start() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let sys = open(tmp.path()).await.unwrap();
            check_shard_count(&sys, 1).await.unwrap();

            let err = check_shard_count(&sys, 2).await.unwrap_err().to_string();
            assert_eq!(err, "shard count changed (stored 1, configured 2) — run `luradb --migrate-shards 2`");
            assert_eq!(stored_shard_count(&sys).await.unwrap(), Some(1), "the stored count stays");
        })
    }

    /// A key-value engine with one user, one permission and one unrelated key.
    async fn kv_with_auth(dir: &Path) -> Arc<LsmStorageEngine> {
        let kv = open(dir).await.unwrap();
        kv.put(b"__sys:auth:user:alice", b"alice-record").await.unwrap();
        kv.put(b"__sys:auth:perm:alice:shop", b"alice-perm").await.unwrap();
        kv.put(b"__sys:domain:shop", b"domain-record").await.unwrap();
        kv
    }

    async fn auth_keys(engine: &LsmStorageEngine) -> Vec<Vec<u8>> {
        let mut keys = engine.scan_keys(b"__sys:auth:").await.unwrap();
        keys.sort();
        keys
    }

    // With the system store's WAL local and on the storage hub.
    #[test]
    fn migration_moves_auth_records_and_leaves_everything_else() {
        crate::core::engine_runtime::block_on(async {
            for on_hub in [false, true] {
                let tmp = tempfile::TempDir::new().unwrap();
                let kv = kv_with_auth(&tmp.path().join("kv")).await;
                let (sys, _hub) = open_on(&tmp.path().join("sys"), on_hub).await;

                migrate_auth(&kv, &sys).await.unwrap();

                assert_eq!(sys.get(b"__sys:auth:user:alice").await.unwrap(), Some(b"alice-record".to_vec()));
                assert_eq!(sys.get(b"__sys:auth:perm:alice:shop").await.unwrap(), Some(b"alice-perm".to_vec()));
                assert_eq!(sys.get(AUTH_MIGRATED_KEY).await.unwrap(), Some(b"1".to_vec()));
                assert!(auth_keys(&kv).await.is_empty(), "the originals are gone");
                assert_eq!(kv.get(b"__sys:domain:shop").await.unwrap(), Some(b"domain-record".to_vec()));
            }
        })
    }

    #[test]
    fn a_migration_without_auth_records_still_sets_the_marker() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let kv = open(&tmp.path().join("kv")).await.unwrap();
            let sys = open(&tmp.path().join("sys")).await.unwrap();

            migrate_auth(&kv, &sys).await.unwrap();

            assert_eq!(sys.get(AUTH_MIGRATED_KEY).await.unwrap(), Some(b"1".to_vec()));
            assert!(auth_keys(&sys).await.is_empty());
        })
    }

    #[test]
    fn a_second_migration_changes_nothing() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let kv = kv_with_auth(&tmp.path().join("kv")).await;
            let sys = open(&tmp.path().join("sys")).await.unwrap();
            migrate_auth(&kv, &sys).await.unwrap();
            // A record changed after the move must not be touched again.
            sys.put(b"__sys:auth:user:alice", b"rotated").await.unwrap();

            migrate_auth(&kv, &sys).await.unwrap();

            assert_eq!(sys.get(b"__sys:auth:user:alice").await.unwrap(), Some(b"rotated".to_vec()));
            assert_eq!(auth_keys(&sys).await.len(), 2);
            assert!(auth_keys(&kv).await.is_empty());
        })
    }

    #[test]
    fn a_migration_interrupted_before_the_marker_is_repeated() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let kv = kv_with_auth(&tmp.path().join("kv")).await;
            let sys = open(&tmp.path().join("sys")).await.unwrap();
            // Crash after the copy: records in both stores, no marker.
            sys.put(b"__sys:auth:user:alice", b"alice-record").await.unwrap();
            sys.put(b"__sys:auth:perm:alice:shop", b"alice-perm").await.unwrap();

            migrate_auth(&kv, &sys).await.unwrap();

            assert_eq!(sys.get(AUTH_MIGRATED_KEY).await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(auth_keys(&sys).await.len(), 2);
            assert!(auth_keys(&kv).await.is_empty());
        })
    }

    #[test]
    fn a_migration_interrupted_after_the_marker_only_drops_the_leftovers() {
        crate::core::engine_runtime::block_on(async {
            let tmp = tempfile::TempDir::new().unwrap();
            let kv = kv_with_auth(&tmp.path().join("kv")).await;
            let sys = open(&tmp.path().join("sys")).await.unwrap();
            // Crash before the deletion: marker set, originals still there,
            // and the moved user record changed since.
            sys.put(b"__sys:auth:user:alice", b"rotated").await.unwrap();
            sys.put(b"__sys:auth:perm:alice:shop", b"alice-perm").await.unwrap();
            sys.put(AUTH_MIGRATED_KEY, b"1").await.unwrap();

            migrate_auth(&kv, &sys).await.unwrap();

            assert_eq!(sys.get(b"__sys:auth:user:alice").await.unwrap(), Some(b"rotated".to_vec()));
            assert_eq!(auth_keys(&sys).await.len(), 2);
            assert!(auth_keys(&kv).await.is_empty());
        })
    }
}
