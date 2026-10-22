//! Recovery of the sharded engines: each engine's write-ahead log is read
//! once, before the shards start, and every record goes to the instance of
//! the data shard that owns its key. The log is truncated only after every
//! instance has flushed what it was handed.

use super::layout;
use crate::auth::{PREFIX_PERM, PREFIX_USER};
use crate::control::slots;
use crate::core::wal::{self, WalEntry, WriteAheadLog};
use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine, Recovery};
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The configured files of one engine; the shards' files derive from them.
pub(super) struct EngineFiles {
    pub(super) wal: PathBuf,
    pub(super) vlog: PathBuf,
    pub(super) sstables: PathBuf,
}

/// Opens the `shards` instances of one engine, all on the log `wal` hands
/// out a handle to, and gives each the records of `files.wal` whose keys its
/// shard owns. Every instance has flushed its records when this returns; the
/// log is left for the caller to truncate.
pub(super) async fn open_sharded(
    files: &EngineFiles,
    shards: u16,
    wal: impl Fn() -> WriteAheadLog,
    options: impl Fn() -> LsmEngineOptions,
) -> anyhow::Result<Vec<Arc<LsmStorageEngine>>> {
    let recovered = wal::recover(&files.wal).await?;
    let routed = route(recovered.entries, shards).with_context(|| format!("recover {}", files.wal.display()))?;
    // Before the first append: new records continue the log's LSNs.
    wal().set_lsn_start(recovered.max_lsn).await?;
    let mut instances = Vec::with_capacity(routed.len());
    for (shard, entries) in routed.into_iter().enumerate() {
        let engine = open_instance(files, shard, Arc::new(wal()), options()).await?;
        engine.apply_recovered(entries, recovered.max_lsn).await?;
        instances.push(Arc::new(engine));
    }
    Ok(instances)
}

async fn open_instance(
    files: &EngineFiles,
    shard: usize,
    wal: Arc<WriteAheadLog>,
    options: LsmEngineOptions,
) -> anyhow::Result<LsmStorageEngine> {
    let vlog_path = layout::shard_file(&files.vlog, shard);
    let sstable_dir = layout::shard_dir(&files.sstables, shard);
    let vlog_dir = vlog_path.parent().unwrap_or(Path::new(""));
    if !vlog_dir.as_os_str().is_empty() {
        std::fs::create_dir_all(vlog_dir).with_context(|| format!("create {}", vlog_dir.display()))?;
    }
    let vlog = Arc::new(VLog::new(&vlog_path).await?);
    let file_manager = Arc::new(FileManager::new(&sstable_dir).await?);
    let manifest_manager = Arc::new(ManifestManager::new(&sstable_dir));
    let options = LsmEngineOptions { recovery: Recovery::External, ..options };
    LsmStorageEngine::new(wal, files.wal.clone(), vlog, vlog_path, file_manager, manifest_manager, options).await
}

/// Splits the records of one log among the data shards; a key that belongs
/// to no domain stops the start.
pub(super) fn route(entries: Vec<(u64, WalEntry)>, shards: u16) -> anyhow::Result<Vec<Vec<(u64, WalEntry)>>> {
    let mut routed: Vec<Vec<(u64, WalEntry)>> = (0..shards).map(|_| Vec::new()).collect();
    for (lsn, entry) in entries {
        let Some(shard) = owner(entry.key(), shards) else {
            anyhow::bail!(
                "record {lsn} holds the key '{}', which belongs to no domain",
                String::from_utf8_lossy(entry.key())
            );
        };
        routed[shard].push((lsn, entry));
    }
    Ok(routed)
}

/// Auth records in an engine's log predate the system store: they go to
/// shard 0, whose key-value engine hands them over to it.
fn owner(key: &[u8], shards: u16) -> Option<usize> {
    if key.starts_with(PREFIX_USER.as_bytes()) || key.starts_with(PREFIX_PERM.as_bytes()) {
        return Some(0);
    }
    slots::shard_of_key(key, shards).map(usize::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::slots::domain_name_for_shard;
    use crate::core::storage_thread::{TestHub, WalTarget};
    use crate::engines::lsm::domain::fnv64;
    use crate::engines::lsm::engine::BatchOp;
    use crate::engines::lsm::hlc::HLCTimestamp;
    use crate::engines::StorageEngine;

    fn files(dir: &Path) -> EngineFiles {
        EngineFiles { wal: dir.join("wal"), vlog: dir.join("vlog"), sstables: dir.join("sstables") }
    }

    /// An engine on `files` that writes its own log, as before shards.
    async fn single(files: &EngineFiles) -> LsmStorageEngine {
        std::fs::create_dir_all(files.wal.parent().unwrap()).unwrap();
        let wal = Arc::new(WriteAheadLog::new(&files.wal).await.unwrap());
        let vlog = Arc::new(VLog::new(&files.vlog).await.unwrap());
        let fm = Arc::new(FileManager::new(&files.sstables).await.unwrap());
        let mm = Arc::new(ManifestManager::new(&files.sstables));
        LsmStorageEngine::new(wal, files.wal.clone(), vlog, files.vlog.clone(), fm, mm, LsmEngineOptions::default())
            .await
            .unwrap()
    }

    fn data_key(domain: &str, key: &str) -> Vec<u8> {
        format!("d:{:016x}:{key}", fnv64(domain.as_bytes())).into_bytes()
    }

    /// Writes of every kind for `domain` that stay in the log: the writer
    /// stops without a flush.
    async fn crash_after_writes(files: &EngineFiles, domains: &[String]) -> Vec<(Vec<u8>, u64)> {
        let engine = single(files).await;
        let large = "clé ✓".repeat(400);
        for domain in domains {
            engine.put(format!("__sys:domain:{domain}").as_bytes(), b"{}").await.unwrap();
            engine.put(&data_key(domain, "small"), "clé".as_bytes()).await.unwrap();
            engine.put(&data_key(domain, "large"), large.as_bytes()).await.unwrap();
            engine.set_null(&data_key(domain, "nulled")).await.unwrap();
            engine.put(&data_key(domain, "gone"), b"v").await.unwrap();
            engine.delete(&data_key(domain, "gone")).await.unwrap();
            let batch = vec![
                BatchOp::Put { key: data_key(domain, "batch-a"), value: b"1".to_vec() },
                BatchOp::Delete { key: data_key(domain, "small") },
            ];
            engine.write_batch(batch).await.unwrap();
        }
        let mut stamps = Vec::new();
        for domain in domains {
            let key = data_key(domain, "large");
            stamps.push((key.clone(), engine.get_latest_with_stamp(&key).await.unwrap().2));
        }
        engine.stop_background_tasks().await;
        stamps
    }

    // Two shards: every record of the shared log lands on the instance of
    // its domain's shard and nowhere else, and new writes stamp above the
    // restored versions.
    #[test]
    fn records_go_to_the_shard_of_their_domain_and_new_writes_stamp_above_them() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let files = files(dir.path());
            let domains = [domain_name_for_shard(0, 2, 3), domain_name_for_shard(1, 2, 3)];
            let stamps = crash_after_writes(&files, &domains).await;

            let hub = TestHub::start(&[(WalTarget::Kv, &files.wal)]);
            let shards = open_sharded(&files, 2, || hub.wal(WalTarget::Kv), LsmEngineOptions::default).await.unwrap();
            for (shard, instance) in shards.iter().enumerate() {
                let (own, other) = (&domains[shard], &domains[1 - shard]);
                assert_eq!(instance.get(format!("__sys:domain:{own}").as_bytes()).await.unwrap(), Some(b"{}".to_vec()));
                assert_eq!(instance.get(format!("__sys:domain:{other}").as_bytes()).await.unwrap(), None);
                let mut keys = instance.scan_keys(b"d:").await.unwrap();
                keys.sort();
                let mut expected: Vec<_> = ["batch-a", "large", "nulled"].map(|key| data_key(own, key)).to_vec();
                expected.sort();
                assert_eq!(keys, expected, "shard {shard}");

                let (key, restored) = &stamps[shard];
                instance.put(key, b"after").await.unwrap();
                let (_, _, stamp) = instance.get_latest_with_stamp(key).await.unwrap();
                assert!(HLCTimestamp::new(stamp) > HLCTimestamp::new(*restored), "shard {shard}");
            }
        })
    }

    // A record whose key belongs to no domain stops the start.
    #[test]
    fn a_key_of_no_domain_stops_the_recovery() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let files = files(dir.path());
            let engine = single(&files).await;
            engine.put(b"hub-probe", b"v").await.unwrap();
            engine.stop_background_tasks().await;
            drop(engine);

            let hub = TestHub::start(&[(WalTarget::Kv, &files.wal)]);
            let err = open_sharded(&files, 2, || hub.wal(WalTarget::Kv), LsmEngineOptions::default)
                .await
                .err()
                .expect("the recovery must fail");
            assert!(format!("{err:#}").contains("'hub-probe', which belongs to no domain"), "{err:#}");
        })
    }

    /// Every file under `dir`, relative, with its bytes.
    fn tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(at) = pending.pop() {
            for entry in std::fs::read_dir(&at).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    found.push((path.strip_prefix(dir).unwrap().to_path_buf(), std::fs::read(&path).unwrap()));
                }
            }
        }
        found.sort();
        found
    }

    // One shard: recovering through the shared log writes the same value log
    // and the same SSTables, byte for byte, as an engine that recovers its
    // own log, and continues the same LSNs and clock.
    #[test]
    fn one_shard_recovers_byte_for_byte_like_an_engine_on_its_own_log() {
        crate::core::engine_runtime::block_on(async {
            let base = tempfile::TempDir::new().unwrap();
            let domains = [domain_name_for_shard(0, 1, 4), "default".to_string()];
            let own = files(&base.path().join("own"));
            crash_after_writes(&own, &domains).await;
            // The shard layout as the first start leaves it: the value log in shard_0/.
            let shared = files(&base.path().join("shared"));
            std::fs::create_dir_all(base.path().join("shared/shard_0")).unwrap();
            std::fs::copy(&own.wal, &shared.wal).unwrap();
            std::fs::copy(&own.vlog, layout::shard_file(&shared.vlog, 0)).unwrap();

            let alone = single(&own).await;
            let hub = TestHub::start(&[(WalTarget::Kv, &shared.wal)]);
            let shards = open_sharded(&shared, 1, || hub.wal(WalTarget::Kv), LsmEngineOptions::default).await.unwrap();
            let sharded = &shards[0];

            assert_eq!(tree(&own.sstables), tree(&shared.sstables.join("shard_0")));
            assert_eq!(std::fs::read(&own.vlog).unwrap(), std::fs::read(layout::shard_file(&shared.vlog, 0)).unwrap());
            assert_eq!(alone.last_applied_lsn(), sharded.last_applied_lsn());
            assert_eq!(alone.hlc().peek(), sharded.hlc().peek());
            for domain in &domains {
                for key in ["small", "large", "nulled", "gone", "batch-a"] {
                    let key = data_key(domain, key);
                    assert_eq!(
                        alone.get_latest_with_stamp(&key).await.unwrap(),
                        sharded.get_latest_with_stamp(&key).await.unwrap(),
                        "{}",
                        String::from_utf8_lossy(&key)
                    );
                }
            }
        })
    }
}
