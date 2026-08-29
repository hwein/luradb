//! Two-process reader-liveness test for spec perf/012 (test strategy 9).
//!
//! The parent runs the server side: `ShmManager`, the registration listener,
//! the command dispatcher and the publisher's `SnapshotWriter`. The child is a
//! re-exec of this very test binary — `<bin> shm_reader_liveness_child --exact
//! --ignored`, addressed through env vars — that registers, maps `state` and
//! both data buffers read-only plus its own `cmd_hdr` read/write, pins a
//! snapshot and reports what it read.
//!
//! Asserted: (a) a publish onto the pinned buffer is skipped while the free one
//! still succeeds, (b) after `SIGKILL` the EOF path reclaims the slot and a
//! publish onto that buffer goes through again, (c) the bytes the child read
//! match the published snapshot exactly.

use luradb::config::ShmConfig;
use luradb::core::wal::WriteAheadLog;
use luradb::engines::lsm::domain::{DomainConfig, DomainRegistry};
use luradb::engines::lsm::engine::LsmEngineOptions;
use luradb::engines::lsm::LsmStorageEngine;
use luradb::ipc::{
    prepare_registration_socket, serve_registration, PublishOutcome, ReaderRegistry, ReaderSlot,
    RegistrationConfig, ShmDispatcher, ShmManager, ShmSegment, SnapshotGuard, SnapshotWriter,
    StateHeader, PUBLISH_WAIT_TIMEOUT_US, READER_SLOT_OFFSET,
};
use luradb::metrics::{MetricsConfig, MetricsStore};
use luradb::storage::file_manager::FileManager;
use luradb::storage::manifest::ManifestManager;
use luradb::storage::vlog::VLog;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROLE_ENV: &str = "LURADB_SHM012_ROLE";
const SOCK_ENV: &str = "LURADB_SHM012_SOCK";
const INSTANCE_ENV: &str = "LURADB_SHM012_INSTANCE";
const READY_ENV: &str = "LURADB_SHM012_READY";

/// Budget for every wait in this test. Deliberately generous: CI runners are far
/// slower than a workstation, and no assertion here is about elapsed time — only
/// about the state being reached eventually.
const WAIT_BUDGET: Duration = Duration::from_secs(60);
/// Upper bound on the child's lifetime, so a parent that dies before the kill
/// cannot leave a process behind.
const CHILD_MAX_LIFETIME: Duration = Duration::from_secs(300);

const SNAPSHOT_PINNED: &[u8] = b"snapshot-1: the child pins this one";
const SNAPSHOT_FREE: &[u8] = b"snapshot-2: lands on the free buffer";
const SNAPSHOT_BLOCKED: &[u8] = b"snapshot-3: wants the pinned buffer";

// ── Parent ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn shm_reader_liveness_across_processes() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sock = dir.path().join("reg.sock");
    let ready = dir.path().join("child-ready");
    let instance_id = format!("shm012-{}", std::process::id());

    let manager = ShmManager::new(shm_config(&instance_id, &sock)).expect("shm manager");
    let state = manager.get_segment("state").expect("state segment");
    let data_a = manager.get_segment("data_a").expect("data_a segment");
    let data_b = manager.get_segment("data_b").expect("data_b segment");
    // Safe: the segments outlive `manager`'s use here and are only touched
    // through `StateHeader` / the writer's raw pointers.
    let header = unsafe { StateHeader::from_ptr(state.as_ptr(), state.len()) };
    header.init();

    let readers = Arc::new(ReaderRegistry::new());
    let buf_len = data_a.len();
    // Safe: this test is the single writer; the two data buffers are distinct
    // mappings of `buf_len` bytes.
    let writer = unsafe {
        SnapshotWriter::new(
            header,
            data_a.as_ptr() as *mut u8,
            data_b.as_ptr() as *mut u8,
            buf_len,
            PUBLISH_WAIT_TIMEOUT_US,
            Arc::clone(&readers),
        )
    };

    let (registry, _db_dir) = make_registry().await;
    let listener = prepare_registration_socket(&sock.to_string_lossy()).expect("registration socket");
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let dispatcher = tokio::spawn(ShmDispatcher::new(registry).run(events_rx, shutdown_rx.clone()));
    let registration = tokio::spawn(serve_registration(
        listener,
        RegistrationConfig {
            instance_id: instance_id.clone(),
            ring_size: 4096,
            segment_mode: 0o600,
            auth_enabled: false,
            trusted_uids: Arc::new(Vec::new()),
            readers: Arc::clone(&readers),
        },
        events_tx,
        shutdown_rx,
    ));

    // Buffer A is active after init, so this lands in buffer B — the one the
    // child will pin.
    assert_eq!(writer.publish(SNAPSHOT_PINNED).unwrap(), PublishOutcome::Published);

    let mut child = ChildGuard(spawn_child(&sock, &instance_id, &ready));

    // (c) The child read the published snapshot byte for byte.
    let seen = wait_for_ready(&ready).await.expect("child never reported a pinned snapshot");
    assert_eq!(seen, SNAPSHOT_PINNED, "child read different bytes than were published");

    // (a) The free buffer still takes a publish; the pinned one is skipped.
    assert_eq!(writer.publish(SNAPSHOT_FREE).unwrap(), PublishOutcome::Published);
    assert_eq!(
        writer.publish(SNAPSHOT_BLOCKED).unwrap(),
        PublishOutcome::SkippedBusy { buffer: 1 },
        "a buffer pinned by a foreign process must never be overwritten"
    );
    assert_eq!(readers.blockers(1), vec![(1, 1)], "the child is the single blocker");

    // (b) SIGKILL: the EOF path deregisters the slot and publishing resumes.
    child.kill_and_reap();
    assert!(
        publish_until_published(&writer, SNAPSHOT_BLOCKED).await,
        "reader slot was never reclaimed after the client process was killed"
    );

    let _ = shutdown_tx.send(true);
    let _ = registration.await;
    let _ = dispatcher.await;
    manager.shutdown();
}

fn shm_config(instance_id: &str, sock: &Path) -> ShmConfig {
    ShmConfig {
        enabled: true,
        instance_id: instance_id.to_string(),
        state_size: 4096,
        data_buffer_size: 8192,
        command_buffer_size: 4096,
        segment_mode: 0o600,
        registration_socket_path: sock.to_string_lossy().to_string(),
        snapshot_interval_ms: 100,
    }
}

async fn make_registry() -> (Arc<DomainRegistry>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let wal_path = dir.path().join("wal.log");
    let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
    let vlog_path = dir.path().join("vlog.log");
    let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
    let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
    let manifest = Arc::new(ManifestManager::new(dir.path()));
    let engine = Arc::new(
        LsmStorageEngine::new(
            wal,
            wal_path,
            vlog,
            vlog_path,
            file_manager,
            manifest,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap(),
    );
    let metrics = MetricsStore::new(MetricsConfig::default());
    let registry =
        Arc::new(DomainRegistry::recover(engine, DomainConfig::default(), metrics).await.unwrap());
    (registry, dir)
}

/// Kills the child on drop, so a failing assertion cannot leak the process.
struct ChildGuard(Child);

impl ChildGuard {
    /// `Child::kill` is `SIGKILL` on Unix — the crash this test is about.
    fn kill_and_reap(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

fn spawn_child(sock: &Path, instance_id: &str, ready: &Path) -> Child {
    let exe = std::env::current_exe().expect("current test binary");
    Command::new(exe)
        .args(["shm_reader_liveness_child", "--exact", "--ignored", "--nocapture"])
        .env(ROLE_ENV, "child")
        .env(SOCK_ENV, sock)
        .env(INSTANCE_ENV, instance_id)
        .env(READY_ENV, ready)
        // Drop the child's libtest progress lines, keep its stderr so a panic in
        // the client role still surfaces in this test's output.
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn the client role of this test binary")
}

/// Waits for the child's ready file (written atomically via rename) and returns
/// its content. Retry with a budget, never a fixed sleep.
async fn wait_for_ready(ready: &Path) -> Option<Vec<u8>> {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        if let Ok(bytes) = std::fs::read(ready) {
            return Some(bytes);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Retries the publish until it succeeds or the budget runs out. The listener
/// task processes the child's EOF asynchronously, so the assertion is "publishes
/// eventually", never "within N milliseconds".
async fn publish_until_published(writer: &SnapshotWriter<'_>, data: &[u8]) -> bool {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        if writer.publish(data).unwrap() == PublishOutcome::Published {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── Child role ────────────────────────────────────────────────────────────────

/// The client process of the test above. `#[ignore]`d and gated on `ROLE_ENV`:
/// a plain `cargo test -- --ignored` runs it as a no-op.
///
/// A blocking `UnixStream` is enough for the one-line registration handshake, so
/// this role needs no async runtime — which keeps the re-exec trivial.
#[test]
#[ignore]
fn shm_reader_liveness_child() {
    let Ok(role) = std::env::var(ROLE_ENV) else { return };
    assert_eq!(role, "child");
    let sock = std::env::var(SOCK_ENV).expect(SOCK_ENV);
    let instance_id = std::env::var(INSTANCE_ENV).expect(INSTANCE_ENV);
    let ready = PathBuf::from(std::env::var(READY_ENV).expect(READY_ENV));

    let mut stream =
        std::os::unix::net::UnixStream::connect(&sock).expect("connect registration socket");
    stream.write_all(b"REGISTER\n").expect("write REGISTER");
    let mut line = String::new();
    BufReader::new(stream.try_clone().expect("clone socket"))
        .read_line(&mut line)
        .expect("read registration reply");
    let parts: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(parts.first().copied(), Some("OK"), "registration failed: {line:?}");

    // Mandatory mapping modes (spec perf/012 §10): state and both data buffers
    // read-only, our own cmd_hdr — which carries the reader slot — read/write.
    let cmd_hdr = ShmSegment::open(parts[3]).expect("open cmd_hdr read/write");
    let seg = |purpose: &str| {
        ShmSegment::open_readonly(&format!("/luradb_{instance_id}_{purpose}"))
            .unwrap_or_else(|e| panic!("open {purpose} read-only: {e}"))
    };
    let (state, data_a, data_b) = (seg("state"), seg("data_a"), seg("data_b"));

    // Safe: four live mappings, held until this process exits.
    let (header, slot, a, b) = unsafe {
        (
            StateHeader::from_ptr(state.as_ptr(), state.len()),
            ReaderSlot::from_ptr(
                cmd_hdr.as_ptr().add(READER_SLOT_OFFSET),
                cmd_hdr.len() - READER_SLOT_OFFSET,
            ),
            std::slice::from_raw_parts(data_a.as_ptr(), data_a.len()),
            std::slice::from_raw_parts(data_b.as_ptr(), data_b.len()),
        )
    };
    header.check_compatible().expect("protocol version 2");
    let guard = SnapshotGuard::acquire(header, slot, a, b).expect("acquire the published snapshot");

    // Report what we read (rename = the parent never sees a partial file), then
    // hold the pin — and the registration socket — until we are killed.
    let tmp = ready.with_extension("tmp");
    std::fs::write(&tmp, guard.data()).expect("write ready file");
    std::fs::rename(&tmp, &ready).expect("publish ready file");

    let deadline = Instant::now() + CHILD_MAX_LIFETIME;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}
