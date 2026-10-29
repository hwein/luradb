//! Write throughput and p99 write latency of the key-value engine on the
//! storage hub for each WAL queue capacity and number of parallel writers.
//! Prints the matrix; asserts nothing about speed. `#[ignore]`d -- run
//! explicitly, in release and without parallel builds or tests:
//! `cargo test --release --test wal_queue_capacity -- --ignored --nocapture`.
//! `LURADB_WAL_QUEUE_WRITES` sets the writes per cell (default 20 000).
//!
//! Measured once, 2026-10-21, release build, 20 000 writes per cell, the log
//! on ext4 (fdatasync-bound); writes/s and p99 per cell:
//!
//! | capacity | 1 writer      | 8 writers       | 64 writers       |
//! |----------|---------------|-----------------|------------------|
//! | 64       | 382 / 12.3 ms | 1 326 / 30.9 ms | 9 853 / 26.3 ms  |
//! | 256      | 351 / 13.3 ms | 1 775 / 16.6 ms | 9 510 / 26.1 ms  |
//! | 1024     | 394 / 11.3 ms | 1 792 / 17.1 ms | 9 223 / 21.8 ms  |
//! | 4096     | 371 / 12.4 ms | 1 651 / 18.3 ms | 10 239 / 21.6 ms |
//!
//! No capacity moves either figure beyond run-to-run noise: with no more
//! writers than slots the queue never fills. The default stays 1024.

use luradb::core::engine_runtime;
use luradb::core::storage_thread::{
    StorageThread, StorageThreadConfig, WalTarget, RING_DEPTH, SQPOLL_ENABLED, SQPOLL_IDLE_MS, STORAGE_THREAD_CPU,
    WAL_SEGMENT_BYTES,
};
use luradb::core::wal::WriteAheadLog;
use luradb::engines::lsm::engine::LsmEngineOptions;
use luradb::engines::lsm::LsmStorageEngine;
use luradb::storage::file_manager::FileManager;
use luradb::storage::manifest::ManifestManager;
use luradb::storage::vlog::VLog;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CAPACITIES: [usize; 4] = [64, 256, 1024, 4096];
const WRITERS: [usize; 3] = [1, 8, 64];
/// Below the inline threshold: each write is one WAL record, no vLog append.
const VALUE_LEN: usize = 100;

/// One cell: `writers` tasks share `writes` puts; returns (writes/s, p99).
async fn run_cell(capacity: usize, writers: usize, writes: usize) -> (f64, Duration) {
    let dir = tempfile::TempDir::new().unwrap();
    let wal_path = dir.path().join("wal.log");
    let config = StorageThreadConfig {
        sqpoll_enabled: SQPOLL_ENABLED,
        sqpoll_idle_ms: SQPOLL_IDLE_MS,
        ring_depth: RING_DEPTH,
        channel_capacity: capacity,
        cpu: STORAGE_THREAD_CPU,
        segment_bytes: WAL_SEGMENT_BYTES,
    };
    let (mut hub, handle) = StorageThread::new(config, vec![(WalTarget::Kv, wal_path.clone())]).unwrap();
    let wal = Arc::new(WriteAheadLog::with_storage_handle(handle, WalTarget::Kv));
    let vlog_path = dir.path().join("vlog.log");
    let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
    let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
    let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
    let engine = Arc::new(
        LsmStorageEngine::new(
            wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, LsmEngineOptions::default(),
        )
        .await
        .unwrap(),
    );
    engine.start_background_tasks();

    let per_writer = writes / writers;
    let start = Instant::now();
    let tasks: Vec<_> = (0..writers)
        .map(|w| {
            let engine = Arc::clone(&engine);
            compio::runtime::spawn(async move {
                let value = vec![b'v'; VALUE_LEN];
                let mut latencies = Vec::with_capacity(per_writer);
                for i in 0..per_writer {
                    let began = Instant::now();
                    engine.put(format!("w{w:02}-{i:08}").as_bytes(), &value).await.unwrap();
                    latencies.push(began.elapsed());
                }
                latencies
            })
        })
        .collect();
    let mut latencies = Vec::with_capacity(per_writer * writers);
    for task in tasks {
        latencies.extend(task.await.unwrap());
    }
    let elapsed = start.elapsed();

    engine.shutdown().await;
    hub.shutdown();
    latencies.sort_unstable();
    let p99 = latencies[latencies.len() * 99 / 100];
    (latencies.len() as f64 / elapsed.as_secs_f64(), p99)
}

#[test]
#[ignore]
fn wal_queue_capacity_matrix() {
    let writes = std::env::var("LURADB_WAL_QUEUE_WRITES").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000);
    let tokio = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let _tokio = tokio.enter();
    println!("capacity  writers  writes/s       p99");
    for capacity in CAPACITIES {
        // Sized as the server sizes it: a wake slot per queued write on top
        // of the default ones.
        let rt = engine_runtime::build(capacity + engine_runtime::DEFAULT_REMOTE_WAKES).unwrap();
        for writers in WRITERS {
            let (rate, p99) = engine_runtime::run(&rt, run_cell(capacity, writers, writes));
            println!("{capacity:>8}  {writers:>7}  {rate:>8.0}  {:>7.3} ms", p99.as_secs_f64() * 1e3);
        }
    }
}
