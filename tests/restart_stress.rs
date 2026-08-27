//! Amplifier stress harness for spec kv/026 (restart data-loss analysis),
//! §1 A1+A2. `#[ignore]`d -- run explicitly:
//! `cargo test --test restart_stress -- --ignored`.
//!
//! N independent engine instances each run M shutdown-restart cycles and M
//! drop-restart cycles while background engines keep flush/compaction/GC
//! busy, hunting for the still (non-panicking) data loss the spec
//! describes. Calibrate via env: LURADB_STRESS_N, LURADB_STRESS_M,
//! LURADB_STRESS_KEYS, LURADB_STRESS_BG_WRITERS, LURADB_STRESS_ARTIFACT_DIR.
//!
//! TempDir trap (spec kv/026 A2): no assert!/unwrap between a restart and
//! evidence conservation anywhere below -- every failure becomes a String
//! finding, snapshots (S1 before reopen, S2 after verify) are conserved
//! first, and the single panic! happens only at the very end.

use luradb::core::wal::WriteAheadLog;
use luradb::engines::lsm::LsmStorageEngine;
use luradb::engines::lsm::engine::{LsmEngineConfig, LsmEngineOptions};
use luradb::engines::StorageEngine;
use luradb::storage::file_manager::FileManager;
use luradb::storage::manifest::ManifestManager;
use luradb::storage::vlog::VLog;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const OP_TIMEOUT: Duration = Duration::from_secs(30);

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Short poll intervals raise the odds a background loop is mid-flush/
/// -compaction exactly when shutdown()/drop hits it (mirrors
/// `engine.rs::tests::test_restart_determinism_with_background_tasks`).
fn stress_engine_config() -> LsmEngineConfig {
    LsmEngineConfig {
        flush_check_interval_ms: 5,
        compaction_check_interval_ms: 5,
        ..Default::default()
    }
}

/// One (re)open on `dir` -- fresh WAL/VLog/FileManager/ManifestManager
/// handles each time, exactly what a real restart does (mirrors
/// `engine.rs::tests::engine_on`).
async fn open_engine(dir: &Path, config: LsmEngineConfig) -> anyhow::Result<LsmStorageEngine> {
    let wal_path = dir.join("wal.log");
    let wal = Arc::new(WriteAheadLog::new(&wal_path).await?);
    let vlog_path = dir.join("vlog.log");
    let vlog = Arc::new(VLog::new(&vlog_path).await?);
    let file_manager = Arc::new(FileManager::new(dir).await?);
    let manifest_manager = Arc::new(ManifestManager::new(dir));
    let opts = LsmEngineOptions { engine: config, ..Default::default() };
    LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, opts).await
}

/// Like [`open_engine`], but a slow/failed open becomes a labeled finding
/// instead of a hang or an unwrap (spec kv/026 A2: engine errors from
/// `new()` get the same no-panic treatment as a verify mismatch).
async fn open_engine_or_finding(dir: &Path, label: &str) -> Result<LsmStorageEngine, String> {
    match tokio::time::timeout(OP_TIMEOUT, open_engine(dir, stress_engine_config())).await {
        Ok(Ok(engine)) => Ok(engine),
        Ok(Err(e)) => Err(format!("{label}: reopen failed: {e}")),
        Err(_) => Err(format!("{label}: reopen did not complete within {OP_TIMEOUT:?}")),
    }
}

/// Like [`open_engine_or_finding`], for `shutdown()` -- never unwraps.
async fn shutdown_or_finding(engine: &LsmStorageEngine, label: &str) -> Option<String> {
    match tokio::time::timeout(OP_TIMEOUT, engine.shutdown()).await {
        Ok(()) => None,
        Err(_) => Some(format!("{label}: shutdown() did not complete within {OP_TIMEOUT:?}")),
    }
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Copies `dir`'s complete engine directory into `artifact_root/label`
/// (spec kv/026 A2 -- the S1/S2 pair is the only surviving evidence once
/// `new()` has unconditionally truncated the WAL, Fact 3).
fn snapshot(dir: &Path, artifact_root: &Path, label: &str) -> Result<PathBuf, String> {
    let dest = artifact_root.join(label);
    copy_dir_recursive(dir, &dest).map(|_| dest).map_err(|e| format!("{label}: snapshot failed: {e}"))
}

/// Checks every `expected` (key, value) pair via `get()`. Returns one
/// human-readable line per mismatch; empty means everything verified.
/// Assert/unwrap-free by design (spec kv/026 A2 TempDir trap, §Tests 3).
async fn verify_keys(engine: &LsmStorageEngine, expected: &[(Vec<u8>, Vec<u8>)]) -> Vec<String> {
    let mut findings = Vec::new();
    for (key, value) in expected {
        match engine.get(key).await {
            Ok(Some(got)) if &got == value => {}
            Ok(Some(got)) => findings.push(format!(
                "key {}: expected {} bytes, got {} bytes (value mismatch)",
                String::from_utf8_lossy(key), value.len(), got.len()
            )),
            Ok(None) => findings.push(format!("key {}: missing after restart", String::from_utf8_lossy(key))),
            Err(e) => findings.push(format!("key {}: get() failed: {e}", String::from_utf8_lossy(key))),
        }
    }
    findings
}

fn cycle_keys(instance: usize, family: &str, cycle: usize, count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let key = format!("i{instance}-{family}-c{cycle}-k{i}").into_bytes();
            let value = format!("v-{instance}-{family}-{cycle}-{i}").into_bytes();
            (key, value)
        })
        .collect()
}

/// Writes `cycle_keys(...)` into `engine`, returning the ones that
/// succeeded (safe to verify later) plus one finding per failed write.
async fn write_cycle_keys(
    engine: &LsmStorageEngine,
    instance: usize,
    family: &str,
    cycle: usize,
    key_count: usize,
    label_base: &str,
) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<String>) {
    let mut expected = Vec::new();
    let mut findings = Vec::new();
    for (key, value) in cycle_keys(instance, family, cycle, key_count) {
        match engine.put(&key, &value).await {
            Ok(()) => expected.push((key, value)),
            Err(e) => findings.push(format!(
                "{label_base}: write {} failed: {e}", String::from_utf8_lossy(&key)
            )),
        }
    }
    (expected, findings)
}

/// Shared tail of both restart families: verify against the reopened
/// engine, take S2, then either delete both snapshots immediately (no
/// finding) or leave them on disk (spec kv/026 A2: "nur im Fehlerfall
/// behalten"). Called directly by the §Tests 3 self-test below with a
/// deliberately wrong expectation.
async fn finish_cycle(
    new_engine: &LsmStorageEngine,
    dir: &Path,
    artifact_root: &Path,
    label_base: &str,
    expected: &[(Vec<u8>, Vec<u8>)],
    s1: Option<PathBuf>,
    mut findings: Vec<String>,
) -> Vec<String> {
    for f in verify_keys(new_engine, expected).await {
        findings.push(format!("{label_base}: {f}"));
    }

    let s2 = match snapshot(dir, artifact_root, &format!("{label_base}-S2")) {
        Ok(p) => Some(p),
        Err(e) => { findings.push(e); None }
    };

    if findings.is_empty() {
        if let Some(p) = &s1 { let _ = std::fs::remove_dir_all(p); }
        if let Some(p) = &s2 { let _ = std::fs::remove_dir_all(p); }
    } else {
        if let Some(p) = &s1 { findings.push(format!("{label_base}: S1 kept at {}", p.display())); }
        if let Some(p) = &s2 { findings.push(format!("{label_base}: S2 kept at {}", p.display())); }
    }
    findings
}

/// Family (a) -- spec kv/026 A1: `write -> shutdown().await -> S1 -> Re-Open
/// -> verify -> S2`, background tasks running like every real bootstrap
/// path. Returns the reopened engine for the next cycle (`None` if reopen
/// itself failed) plus this cycle's findings.
async fn run_shutdown_cycle(
    engine: Arc<LsmStorageEngine>,
    dir: &Path,
    artifact_root: &Path,
    instance: usize,
    cycle: usize,
    key_count: usize,
) -> (Option<Arc<LsmStorageEngine>>, Vec<String>) {
    let label_base = format!("shutdown-i{instance}-c{cycle}");
    let (expected, mut findings) =
        write_cycle_keys(&engine, instance, "shutdown", cycle, key_count, &label_base).await;

    if let Some(f) = shutdown_or_finding(&engine, &label_base).await {
        findings.push(f);
    }
    drop(engine);

    let s1 = match snapshot(dir, artifact_root, &format!("{label_base}-S1")) {
        Ok(p) => Some(p),
        Err(e) => { findings.push(e); None }
    };

    let new_engine = match open_engine_or_finding(dir, &label_base).await {
        Ok(e) => Arc::new(e),
        Err(f) => {
            findings.push(f);
            if let Some(p) = &s1 { findings.push(format!("{label_base}: S1 kept at {}", p.display())); }
            return (None, findings);
        }
    };
    new_engine.start_background_tasks();

    let findings = finish_cycle(&new_engine, dir, artifact_root, &label_base, &expected, s1, findings).await;
    (Some(new_engine), findings)
}

/// Family (b) -- spec kv/026 A1: `write -> drop -> S1 -> Re-Open -> verify
/// -> S2`, no background tasks (mirrors `engine_on` -- the raw-crash path).
async fn run_drop_cycle(
    engine: LsmStorageEngine,
    dir: &Path,
    artifact_root: &Path,
    instance: usize,
    cycle: usize,
    key_count: usize,
) -> (Option<LsmStorageEngine>, Vec<String>) {
    let label_base = format!("drop-i{instance}-c{cycle}");
    let (expected, mut findings) =
        write_cycle_keys(&engine, instance, "drop", cycle, key_count, &label_base).await;

    drop(engine); // no shutdown() -- family (b) is the raw-crash path (spec kv/026 A1)

    let s1 = match snapshot(dir, artifact_root, &format!("{label_base}-S1")) {
        Ok(p) => Some(p),
        Err(e) => { findings.push(e); None }
    };

    let new_engine = match open_engine_or_finding(dir, &label_base).await {
        Ok(e) => e,
        Err(f) => {
            findings.push(f);
            if let Some(p) = &s1 { findings.push(format!("{label_base}: S1 kept at {}", p.display())); }
            return (None, findings);
        }
    };

    let findings = finish_cycle(&new_engine, dir, artifact_root, &label_base, &expected, s1, findings).await;
    (Some(new_engine), findings)
}

struct InstanceOutcome {
    findings: Vec<String>,
    dir: TempDir,
}

/// Drives one of the N independent instances: M shutdown-family cycles,
/// then M drop-family cycles, all on the same TempDir.
async fn run_instance(instance: usize, artifact_root: PathBuf, m: usize, key_count: usize) -> InstanceOutcome {
    let dir = TempDir::new().expect("tempdir for stress instance");
    let mut findings = Vec::new();

    match open_engine_or_finding(dir.path(), &format!("instance {instance} shutdown-init")).await {
        Ok(engine) => {
            let engine = Arc::new(engine);
            engine.start_background_tasks();
            let mut current = Some(engine);
            for cycle in 0..m {
                let Some(engine) = current.take() else { break };
                let (next, cycle_findings) =
                    run_shutdown_cycle(engine, dir.path(), &artifact_root, instance, cycle, key_count).await;
                findings.extend(cycle_findings);
                current = next;
            }
            if let Some(engine) = current {
                let label = format!("instance {instance} shutdown-family teardown");
                if let Some(f) = shutdown_or_finding(&engine, &label).await {
                    findings.push(f);
                }
            }
        }
        Err(f) => findings.push(f),
    }

    match open_engine_or_finding(dir.path(), &format!("instance {instance} drop-init")).await {
        Ok(engine) => {
            let mut current = Some(engine);
            for cycle in 0..m {
                let Some(engine) = current.take() else { break };
                let (next, cycle_findings) =
                    run_drop_cycle(engine, dir.path(), &artifact_root, instance, cycle, key_count).await;
                findings.extend(cycle_findings);
                current = next;
            }
            // Final engine intentionally just dropped when this scope ends --
            // matches the family; no explicit shutdown.
        }
        Err(f) => findings.push(f),
    }

    InstanceOutcome { findings, dir }
}

/// Pure load generator (spec kv/026 A1: "während derselbe Prozess parallel
/// Schreib-/Flush-Last erzeugt") -- keeps flush/compaction/GC busy on its
/// own throwaway store while the main instances restart. Its own
/// correctness is out of scope; errors are swallowed on purpose.
async fn run_background_loader(id: usize, stop: Arc<AtomicBool>) {
    let Ok(dir) = TempDir::new() else { return };
    let config = LsmEngineConfig {
        // Small threshold: forces frequent freeze/flush churn from a
        // handful of small puts instead of the 4 MiB default.
        memtable_size_threshold: 2048,
        flush_check_interval_ms: 5,
        compaction_check_interval_ms: 5,
        ..Default::default()
    };
    let Ok(engine) = open_engine(dir.path(), config).await else { return };
    let engine = Arc::new(engine);
    engine.start_background_tasks();

    let mut i: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let key = format!("bg{id}-{i}").into_bytes();
        let _ = engine.put(&key, &[b'x'; 256]).await;
        if i % 4 == 0 {
            let _ = engine.flush_memtable().await;
        }
        i += 1;
        tokio::task::yield_now().await;
    }

    let _ = tokio::time::timeout(OP_TIMEOUT, engine.shutdown()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn restart_stress_amplifier() {
    let n = env_usize("LURADB_STRESS_N", 4);
    let m = env_usize("LURADB_STRESS_M", 5);
    let key_count = env_usize("LURADB_STRESS_KEYS", 10);
    let bg_writers = env_usize("LURADB_STRESS_BG_WRITERS", 2);

    let (artifact_root, owned_artifact_dir): (PathBuf, Option<TempDir>) =
        match std::env::var("LURADB_STRESS_ARTIFACT_DIR") {
            Ok(dir) => {
                let path = PathBuf::from(dir);
                std::fs::create_dir_all(&path).expect("create LURADB_STRESS_ARTIFACT_DIR");
                (path, None)
            }
            Err(_) => {
                let td = TempDir::new().expect("tempdir for stress artifacts");
                (td.path().to_path_buf(), Some(td))
            }
        };

    let stop = Arc::new(AtomicBool::new(false));
    let bg_handles: Vec<_> = (0..bg_writers)
        .map(|id| tokio::spawn(run_background_loader(id, Arc::clone(&stop))))
        .collect();

    let start = Instant::now();
    let instance_handles: Vec<_> = (0..n)
        .map(|instance| tokio::spawn(run_instance(instance, artifact_root.clone(), m, key_count)))
        .collect();

    let mut all_findings = Vec::new();
    let mut kept_dirs = Vec::new();
    for handle in instance_handles {
        match handle.await {
            Ok(outcome) => {
                if !outcome.findings.is_empty() {
                    all_findings.extend(outcome.findings);
                    kept_dirs.push(outcome.dir);
                }
            }
            Err(e) => all_findings.push(format!("instance task panicked/joined with error: {e}")),
        }
    }
    let elapsed = start.elapsed();

    stop.store(true, Ordering::Relaxed);
    for handle in bg_handles {
        let _ = handle.await;
    }

    let total_cycles = n * m * 2;
    println!(
        "restart_stress_amplifier: N={n} M={m} keys/cycle={key_count} bg_writers={bg_writers} \
total_cycles={total_cycles} elapsed={elapsed:?}"
    );

    if all_findings.is_empty() {
        return;
    }

    let mut kept_paths: Vec<PathBuf> = kept_dirs.into_iter().map(TempDir::keep).collect();
    match owned_artifact_dir {
        Some(td) => kept_paths.push(td.keep()),
        None => kept_paths.push(artifact_root),
    }

    let report = format!(
        "restart_stress_amplifier: {} finding(s) after {total_cycles} cycles ({elapsed:?}):\n{}\n\nKept evidence directories:\n{}",
        all_findings.len(),
        all_findings.join("\n"),
        kept_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("\n"),
    );
    panic!("{report}");
}

/// Spec kv/026 §Tests 3: plays through the conservation mechanism with an
/// artificially provoked verify failure (a deliberately wrong expected
/// value, not a real corruption) and checks the snapshot directories exist
/// -- and that `finish_cycle` never panics on its way there.
#[tokio::test]
async fn self_test_conserves_evidence_on_verify_mismatch() {
    let dir = TempDir::new().unwrap();
    let artifact_dir = TempDir::new().unwrap();

    let engine = open_engine(dir.path(), stress_engine_config()).await.unwrap();
    let key = b"self-test-key".to_vec();
    let value = b"self-test-value".to_vec();
    engine.put(&key, &value).await.unwrap();
    engine.shutdown().await;
    drop(engine);

    let s1 = snapshot(dir.path(), artifact_dir.path(), "self-test-S1").expect("S1 snapshot must succeed");

    let new_engine = open_engine(dir.path(), stress_engine_config()).await.unwrap();

    // Deliberately wrong expected value (spec kv/026 §Tests 3) -- forces a
    // mismatch without corrupting real engine state. Must not panic: both
    // verify_keys and finish_cycle only ever collect findings.
    let wrong_expected = vec![(key.clone(), b"WRONG-VALUE-INJECTED".to_vec())];
    let findings = finish_cycle(
        &new_engine, dir.path(), artifact_dir.path(), "self-test",
        &wrong_expected, Some(s1.clone()), Vec::new(),
    ).await;

    assert!(!findings.is_empty(), "the injected wrong value must be reported, not silently accepted");
    assert!(s1.exists(), "S1 must be conserved (not deleted) when a finding is present");
    let s2 = artifact_dir.path().join("self-test-S2");
    assert!(s2.exists(), "S2 must be conserved (not deleted) when a finding is present");
    assert!(s1.join("wal.log").exists(), "S1 must contain the copied WAL file");
}
