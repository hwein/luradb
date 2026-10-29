//! Recovery of the sharded engines: each engine's write-ahead log is read
//! once, entry by entry, before the shards start, and every record goes to
//! the instance of the data shard that owns its key. The log is truncated
//! only after every instance has flushed what it was handed.

use super::layout;
use crate::auth::{PREFIX_PERM, PREFIX_USER};
use crate::control::slots;
use crate::core::wal::{WalEntry, WriteAheadLog};
use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine, Recovery};
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::ManifestManager;
use crate::storage::vlog::VLog;
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The configured files of one engine; the shards' files derive from them.
pub(crate) struct EngineFiles {
    pub(crate) wal: PathBuf,
    pub(crate) vlog: PathBuf,
    pub(crate) sstables: PathBuf,
}

/// Opens the `shards` instances of one engine, all on the log `wal` hands
/// out a handle to, and gives each the records of `files.wal` whose keys its
/// shard owns and that its SSTables do not hold yet. Every instance has
/// flushed its records when this returns; the log is left for the caller to
/// truncate.
pub(crate) async fn open_sharded(
    files: &EngineFiles,
    shards: u16,
    wal: impl Fn() -> WriteAheadLog,
    options: impl Fn() -> LsmEngineOptions,
) -> anyhow::Result<Vec<Arc<LsmStorageEngine>>> {
    let mut instances = Vec::with_capacity(usize::from(shards));
    for shard in 0..usize::from(shards) {
        instances.push(open_instance(files, shard, Arc::new(wal()), options()).await?);
    }
    let owner_of = |lsn: u64, entry: &WalEntry| {
        owner(entry.key(), shards).ok_or_else(|| {
            anyhow::anyhow!(
                "record {lsn} holds the key '{}', which belongs to no domain",
                String::from_utf8_lossy(entry.key())
            )
        })
    };
    LsmStorageEngine::replay_wal(&files.wal, &instances, owner_of)
        .await
        .with_context(|| format!("recover {}", files.wal.display()))?;
    Ok(instances.into_iter().map(Arc::new).collect())
}

/// The instance of data shard `shard` on `files`, recovered by the caller.
pub(crate) async fn open_instance(
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
    let options = LsmEngineOptions { recovery: Recovery::External, shard: shard as u16, ..options };
    LsmStorageEngine::new(wal, files.wal.clone(), vlog, vlog_path, file_manager, manifest_manager, options).await
}

/// Auth records in an engine's log predate the system store: they go to
/// shard 0, whose key-value engine hands them over to it.
pub(super) fn owner(key: &[u8], shards: u16) -> Option<usize> {
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
    use crate::engines::lsm::engine::{BatchOp, LsmEngineConfig};
    use crate::engines::lsm::reader::GetResult;
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

    // Each shard's instance streams its changes under an epoch of its own:
    // the boot epoch in the upper 48 bits, the shard in the lower 16. A
    // cursor of shard 0 resets on shard 1; the control plane's stream, shard
    // 0xFFFF, takes its own cursors as before.
    #[test]
    fn each_shard_streams_under_an_epoch_of_its_own() {
        crate::core::engine_runtime::block_on(async {
            use crate::core::events::{format_event_id, stream_epoch, GlobalEventBus, ResetReason, Resume, CONTROL_PLANE_SHARD, EVENTS_TAG};
            use crate::engines::lsm::WATCH_TAG;
            let dir = tempfile::TempDir::new().unwrap();
            let files = files(dir.path());
            let hub = TestHub::start(&[(WalTarget::Kv, &files.wal)]);
            let shards = open_sharded(&files, 2, || hub.wal(WalTarget::Kv), LsmEngineOptions::default).await.unwrap();
            let epochs = [shards[0].watch_epoch(), shards[1].watch_epoch()];
            let control = stream_epoch(CONTROL_PLANE_SHARD);
            assert_eq!([epochs[0] & 0xFFFF, epochs[1] & 0xFFFF, control & 0xFFFF], [0, 1, 0xFFFF]);
            assert_eq!([epochs[0] >> 16, epochs[1] >> 16], [control >> 16, control >> 16]);

            shards[0].put(&data_key(&domain_name_for_shard(0, 2, 3), "k"), b"v").await.unwrap();
            let cursor = format_event_id(WATCH_TAG, epochs[0], 1);
            assert!(matches!(shards[0].watch_decide_resume(Some(&cursor)), Resume::Replay { .. }));
            let moved = shards[1].watch_decide_resume(Some(&cursor));
            assert!(matches!(moved, Resume::Reset { reason: ResetReason::Restart, .. }));

            let bus = GlobalEventBus::new(16, 16);
            bus.publish("kv", "domain_created", "shop", None);
            let cursor = format_event_id(EVENTS_TAG, control, 1);
            assert!(matches!(bus.decide_resume(Some(&cursor)), Resume::Replay { .. }));
        })
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

    /// The SSTable files of shard `shard`, by name.
    fn tables(files: &EngineFiles, shard: usize) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(layout::shard_dir(&files.sstables, shard))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".sst"))
            .collect();
        names.sort();
        names
    }

    fn vlog_len(files: &EngineFiles, shard: usize) -> u64 {
        std::fs::metadata(layout::shard_file(&files.vlog, shard)).unwrap().len()
    }

    /// The newest version of each of `keys` on the instance of its shard.
    async fn versions(shards: &[Arc<LsmStorageEngine>], keys: &[(usize, Vec<u8>)]) -> Vec<(GetResult, u64, u64)> {
        let mut found = Vec::new();
        for (shard, key) in keys {
            found.push(shards[*shard].get_latest_with_stamp(key).await.unwrap());
        }
        found
    }

    // Each instance replays only the records after its flushed LSN: every
    // confirmed write is back with its stamp, deleted keys stay gone, the
    // value log grows only by the values after the flushes, and an instance
    // with nothing after its flush writes no table.
    #[test]
    fn each_instance_replays_only_the_records_after_its_flushed_lsn() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let files = files(dir.path());
            let domains = [domain_name_for_shard(0, 2, 3), domain_name_for_shard(1, 2, 3)];
            let hub = TestHub::start(&[(WalTarget::Kv, &files.wal)]);
            let shards = open_sharded(&files, 2, || hub.wal(WalTarget::Kv), LsmEngineOptions::default).await.unwrap();
            let large = "clé ✓".repeat(400);
            let mut keys = Vec::new();
            for round in 0..2 {
                for (shard, domain) in domains.iter().enumerate() {
                    let engine = &shards[shard];
                    let key = |name: &str| data_key(domain, &format!("{name}-{round}"));
                    engine.put(&key("small"), "clé".as_bytes()).await.unwrap();
                    engine.put(&key("large"), large.as_bytes()).await.unwrap();
                    engine.set_null(&key("nulled")).await.unwrap();
                    engine.put(&key("gone"), b"v").await.unwrap();
                    engine.delete(&key("gone")).await.unwrap();
                    let batch = vec![
                        BatchOp::Put { key: key("batch"), value: b"1".to_vec() },
                        BatchOp::Delete { key: key("small") },
                    ];
                    engine.write_batch(batch).await.unwrap();
                    keys.extend(["small", "large", "nulled", "gone", "batch"].map(|name| (shard, key(name))));
                    engine.flush_all_memtables().await.unwrap();
                }
            }
            let before_rest = vlog_len(&files, 0);
            let rest = data_key(&domains[0], "rest");
            shards[0].put(&rest, large.as_bytes()).await.unwrap();
            keys.push((0, rest));
            let rest_bytes = vlog_len(&files, 0) - before_rest;
            let confirmed = versions(&shards, &keys).await;
            let vlogs = [vlog_len(&files, 0), vlog_len(&files, 1)];
            let flushed = [tables(&files, 0), tables(&files, 1)];
            drop((shards, hub)); // crash

            let hub = TestHub::start(&[(WalTarget::Kv, &files.wal)]);
            let shards = open_sharded(&files, 2, || hub.wal(WalTarget::Kv), LsmEngineOptions::default).await.unwrap();
            assert_eq!(versions(&shards, &keys).await, confirmed);
            for ((_, key), (found, _, _)) in keys.iter().zip(versions(&shards, &keys).await) {
                let deleted = [&b"gone-0"[..], b"gone-1", b"small-0", b"small-1"].iter().any(|end| key.ends_with(end));
                assert_eq!(found == GetResult::Absent, deleted, "{}", String::from_utf8_lossy(key));
            }
            assert_eq!(vlog_len(&files, 0), vlogs[0] + rest_bytes, "the replay appended the value after the flushes");
            assert_eq!(vlog_len(&files, 1), vlogs[1], "nothing to replay on shard 1");
            assert_eq!(tables(&files, 0).len(), flushed[0].len() + 1);
            assert_eq!(tables(&files, 1), flushed[1]);
        })
    }

    /// Copies the files below `from` to `to`.
    fn copy_tree(from: &Path, to: &Path) {
        for (relative, bytes) in tree(from) {
            let target = to.join(relative);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, bytes).unwrap();
        }
    }

    // A log many MemTables long replays with bounded memory: each instance
    // flushes whenever its MemTable reaches the threshold, under the LSN of
    // the record read last, and ends with the same versions, stamps, LSN and
    // clock as a replay that flushes only at its end.
    #[test]
    fn a_long_log_replays_through_memtables_of_the_threshold() {
        const THRESHOLD: usize = 4096;
        const VALUE: usize = 100;
        crate::core::engine_runtime::block_on(async {
            let base = tempfile::TempDir::new().unwrap();
            std::fs::create_dir_all(base.path().join("streamed")).unwrap();
            let streamed = files(&base.path().join("streamed"));
            let domains = [domain_name_for_shard(0, 2, 3), domain_name_for_shard(1, 2, 3)];
            let mut keys = Vec::new();
            {
                let hub = TestHub::start(&[(WalTarget::Kv, &streamed.wal)]);
                let shards =
                    open_sharded(&streamed, 2, || hub.wal(WalTarget::Kv), LsmEngineOptions::default).await.unwrap();
                for i in 0..300 {
                    for (shard, domain) in domains.iter().enumerate() {
                        let key = data_key(domain, &format!("k{i:03}"));
                        let value = if i % 50 == 0 { "clé ✓".repeat(400) } else { format!("{i:0>VALUE$}") };
                        shards[shard].put(&key, value.as_bytes()).await.unwrap();
                        keys.push((shard, key));
                    }
                }
            } // crash
            let whole = files(&base.path().join("whole"));
            copy_tree(&base.path().join("streamed"), &base.path().join("whole"));
            assert!(std::fs::metadata(&streamed.wal).unwrap().len() > 2 * 8 * THRESHOLD as u64);

            let with_threshold = |threshold| {
                move || LsmEngineOptions {
                    engine: LsmEngineConfig { memtable_size_threshold: threshold, ..LsmEngineConfig::default() },
                    ..LsmEngineOptions::default()
                }
            };
            let hub = TestHub::start(&[(WalTarget::Kv, &streamed.wal)]);
            let shards = open_sharded(&streamed, 2, || hub.wal(WalTarget::Kv), with_threshold(THRESHOLD)).await.unwrap();
            let whole_hub = TestHub::start(&[(WalTarget::Kv, &whole.wal)]);
            let wholes =
                open_sharded(&whole, 2, || whole_hub.wal(WalTarget::Kv), with_threshold(usize::MAX)).await.unwrap();

            let max_lsn = shards[0].last_applied_lsn();
            assert_eq!(max_lsn, 600);
            let largest = keys[0].1.len() + 8 + VALUE;
            for shard in 0..2 {
                let instance = &shards[shard];
                let peak = instance.replay_peak.load(std::sync::atomic::Ordering::Relaxed);
                assert!(peak <= THRESHOLD + largest, "shard {shard}: {peak} bytes");
                let watermarks = instance.replay_watermarks.lock().clone();
                assert!(watermarks.len() >= 8, "shard {shard}: {watermarks:?}");
                assert!(watermarks.windows(2).all(|pair| pair[0] < pair[1]), "shard {shard}: {watermarks:?}");
                // The record read last before each flush is one of the other shard.
                assert!(watermarks.iter().all(|lsn| *lsn < max_lsn && lsn % 2 == shard as u64), "{watermarks:?}");
                assert_eq!(tables(&streamed, shard).len(), watermarks.len() + 1);
                assert_eq!(instance.flushed_lsn(), max_lsn);
                assert!(wholes[shard].replay_watermarks.lock().is_empty());
                assert_eq!(tables(&whole, shard).len(), 1);
                assert_eq!(instance.last_applied_lsn(), wholes[shard].last_applied_lsn());
                assert_eq!(instance.hlc().peek(), wholes[shard].hlc().peek());
            }
            assert_eq!(versions(&shards, &keys).await, versions(&wholes, &keys).await);
        })
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
