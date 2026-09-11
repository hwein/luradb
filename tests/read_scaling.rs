//! Read-scaling measurement for spec kv/031: point reads on one engine
//! instance from 1/2/4/8 threads, each thread on its own current-thread
//! runtime. Prints ops/s and p50 per thread count; asserts nothing about
//! speed. `#[ignore]`d -- run explicitly, in release and without parallel
//! builds or tests:
//! `cargo test --release --test read_scaling -- --ignored --nocapture`.
//!
//! Measured once, 2026-09-11, WSL2 on an AMD Ryzen 9 7945HX (32 threads),
//! rustc 1.97.0; before = the tree of this test's first commit, after = the
//! finished spec. ops/s over all threads, p50 per read:
//!
//! | threads | before ops/s | before p50 | after ops/s | after p50 |
//! |---------|--------------|------------|-------------|-----------|
//! | 1       | 260 367      | 3 714 ns   | 257 154     | 3 728 ns  |
//! | 2       | 168 222      | 7 120 ns   | 506 241     | 3 772 ns  |
//! | 4       | 116 613      | 18 459 ns  | 958 759     | 3 934 ns  |
//! | 8       | 107 289      | 51 859 ns  | 1 645 562   | 4 265 ns  |
//!
//! Gate (one reader thread at most 5 % slower than before): met, 257 154
//! ops/s against 236 405 in the first before run and 260 367 in this one.

use luradb::core::wal::WriteAheadLog;
use luradb::engines::lsm::engine::{BatchOp, LsmEngineOptions};
use luradb::engines::lsm::LsmStorageEngine;
use luradb::engines::StorageEngine;
use luradb::storage::file_manager::FileManager;
use luradb::storage::manifest::ManifestManager;
use luradb::storage::vlog::VLog;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const KEYS: usize = 50_000;
/// Below the inline threshold: reads go through the SSTable and block cache.
const VALUE_LEN: usize = 100;
const READS_PER_THREAD: usize = 200_000;
const ROUNDS: usize = 5;
const THREAD_COUNTS: [usize; 4] = [1, 2, 4, 8];

fn next_random(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// One round: `threads` readers start together; returns (ops/s, p50).
fn run_round(engine: &Arc<LsmStorageEngine>, keys: &Arc<Vec<Vec<u8>>>, threads: usize) -> (f64, Duration) {
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let engine = Arc::clone(engine);
            let keys = Arc::clone(keys);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                rt.block_on(async move {
                    let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (t as u64 + 1);
                    let mut latencies = Vec::with_capacity(READS_PER_THREAD);
                    barrier.wait();
                    let start = Instant::now();
                    for _ in 0..READS_PER_THREAD {
                        let key = &keys[(next_random(&mut rng) % KEYS as u64) as usize];
                        let op = Instant::now();
                        let value = engine.get(key).await.unwrap();
                        latencies.push(op.elapsed());
                        assert!(value.is_some());
                    }
                    (start, Instant::now(), latencies)
                })
            })
        })
        .collect();

    let mut first_start: Option<Instant> = None;
    let mut last_end: Option<Instant> = None;
    let mut latencies = Vec::with_capacity(threads * READS_PER_THREAD);
    for handle in handles {
        let (start, end, lat) = handle.join().unwrap();
        first_start = Some(first_start.map_or(start, |s| s.min(start)));
        last_end = Some(last_end.map_or(end, |e| e.max(end)));
        latencies.extend(lat);
    }
    let elapsed = last_end.unwrap() - first_start.unwrap();
    latencies.sort_unstable();
    let p50 = latencies[latencies.len() / 2];
    ((threads * READS_PER_THREAD) as f64 / elapsed.as_secs_f64(), p50)
}

#[tokio::test]
#[ignore]
async fn read_scaling() {
    let dir = tempfile::TempDir::new().unwrap();
    let wal_path = dir.path().join("wal.log");
    let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
    let vlog_path = dir.path().join("vlog.log");
    let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
    let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
    let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
    let engine = Arc::new(
        LsmStorageEngine::new(
            wal, wal_path, vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap(),
    );

    let keys: Arc<Vec<Vec<u8>>> = Arc::new((0..KEYS).map(|i| format!("key{i:08}").into_bytes()).collect());
    for chunk in keys.chunks(1_000) {
        let ops = chunk
            .iter()
            .map(|k| BatchOp::Put { key: k.clone(), value: vec![b'v'; VALUE_LEN] })
            .collect();
        engine.write_batch(ops).await.unwrap();
    }
    engine.flush_all_memtables().await.unwrap();
    engine.compact_level(0).await.unwrap();

    // Warm the block cache once, so every round reads the same cached state.
    for key in keys.iter() {
        assert!(engine.get(key).await.unwrap().is_some());
    }

    for threads in THREAD_COUNTS {
        let mut rounds: Vec<(f64, Duration)> = (0..ROUNDS).map(|_| run_round(&engine, &keys, threads)).collect();
        rounds.sort_by(|a, b| a.0.total_cmp(&b.0));
        let (ops, p50) = rounds[ROUNDS / 2];
        println!(
            "read_scaling: threads={threads} ops/s={ops:.0} p50={}ns (median of {ROUNDS} rounds, {READS_PER_THREAD} reads/thread)",
            p50.as_nanos()
        );
    }
}
