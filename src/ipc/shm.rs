//! POSIX shared-memory segments (`shm_open`/`ftruncate`/`mmap`) and their
//! lifecycle manager (spec perf/006).

use anyhow::{Context, Result};
use memmap2::{Mmap, MmapMut};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::config::ShmConfig;

/// A single mmap'd POSIX shared-memory segment (`/dev/shm/<name>`), mapped
/// read/write. Clients map `state`/`data_a`/`data_b` through
/// [`ShmSegment::open_readonly`] instead (spec perf/012 §10).
pub struct ShmSegment {
    name: String,
    mmap: MmapMut,
    size: usize,
    /// Owns the fd (closed exactly once, on drop). Kept beyond setup for
    /// spec perf/010's client hand-off (`SCM_RIGHTS`).
    file: File,
}

impl ShmSegment {
    /// Creates a named segment: `shm_open(O_CREAT|O_EXCL)`, `ftruncate`, then
    /// `mmap`. A segment left behind by a crashed previous run (`EEXIST`) is
    /// unlinked once and re-created.
    pub fn create(name: &str, size: usize, mode: u32) -> Result<Self> {
        let cname = CString::new(name).with_context(|| format!("invalid shm name '{name}'"))?;
        let fd = shm_open_or_recreate(&cname, name, mode)?;
        // Safe: `fd` is a fresh descriptor from the successful shm_open above
        // and isn't tracked anywhere else — `File` becomes its sole owner and
        // closes it exactly once on drop (no separate `RawFd` field that
        // could double-close it).
        let file = unsafe { File::from_raw_fd(fd) };

        if unsafe { libc::ftruncate(fd, size as libc::off_t) } < 0 {
            let err = errno_context(format!("ftruncate '{name}' to {size} bytes failed"));
            unsafe { libc::shm_unlink(cname.as_ptr()) };
            return Err(err);
        }

        // Safe: fd (kept alive via `file`) was just sized to `size` above.
        let mmap = match unsafe { memmap2::MmapOptions::new().len(size).map_mut(&file) } {
            Ok(m) => m,
            Err(e) => {
                unsafe { libc::shm_unlink(cname.as_ptr()) };
                return Err(anyhow::Error::from(e).context(format!("mmap '{name}' ({size} bytes) failed")));
            }
        };
        // A freshly shm_open(O_EXCL)+ftruncate'd segment is all-zero pages
        // already (kernel guarantee) — no memset (would fault in every page
        // of what defaults to 256 MB, for nothing; spec §2.4).

        Ok(Self { name: name.to_string(), mmap, size, file })
    }

    /// Opens an already-created segment read/write: crash-recovery
    /// re-attachment, a second handle in tests, and the client side of the
    /// per-client ring quartet (`cmd`/`cmd_hdr`/`resp`/`resp_hdr`, which carries
    /// the client's `ReaderSlot`). The size is read back via `fstat` rather than
    /// trusted from the caller.
    pub fn open(name: &str) -> Result<Self> {
        let cname = CString::new(name).with_context(|| format!("invalid shm name '{name}'"))?;
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0) };
        if fd < 0 {
            return Err(errno_context(format!("shm_open '{name}' failed")));
        }
        // Safe: sole owner of this fresh fd, same reasoning as in `create`.
        let file = unsafe { File::from_raw_fd(fd) };
        let size = file.metadata().with_context(|| format!("fstat '{name}' failed"))?.len() as usize;

        let mmap = unsafe { memmap2::MmapOptions::new().len(size).map_mut(&file) }
            .with_context(|| format!("mmap '{name}' ({size} bytes) failed"))?;

        Ok(Self { name: name.to_string(), mmap, size, file })
    }

    /// Opens an existing segment `O_RDONLY` / `PROT_READ` — the mandatory client
    /// mapping for `state`, `data_a` and `data_b` (spec perf/012 §10). A write
    /// through the returned mapping faults, which is the point: reader counters
    /// live in the client's own `cmd_hdr` page, not in `state`.
    pub fn open_readonly(name: &str) -> Result<ReadOnlySegment> {
        let cname = CString::new(name).with_context(|| format!("invalid shm name '{name}'"))?;
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0) };
        if fd < 0 {
            return Err(errno_context(format!("shm_open '{name}' read-only failed")));
        }
        // Safe: sole owner of this fresh fd, same reasoning as in `create`.
        let file = unsafe { File::from_raw_fd(fd) };
        let size = file.metadata().with_context(|| format!("fstat '{name}' failed"))?.len() as usize;

        let mmap = unsafe { memmap2::MmapOptions::new().len(size).map(&file) }
            .with_context(|| format!("mmap '{name}' ({size} bytes) read-only failed"))?;

        Ok(ReadOnlySegment { mmap, size, _file: file })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.mmap.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mmap.as_mut_ptr()
    }

    pub fn len(&self) -> usize {
        self.size
    }

    /// Name under `/dev/shm/` (e.g. `"/luradb_0_state"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Raw fd — retained for spec perf/010's `SCM_RIGHTS` client hand-off.
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// A `PROT_READ` mapping of an existing segment (see
/// [`ShmSegment::open_readonly`]). No `as_mut_ptr`, no fd hand-off: a client
/// only ever reads through it.
pub struct ReadOnlySegment {
    mmap: Mmap,
    size: usize,
    /// Owns the fd (closed exactly once, on drop).
    _file: File,
}

impl ReadOnlySegment {
    pub fn as_ptr(&self) -> *const u8 {
        self.mmap.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.size
    }
}

/// `shm_open(O_CREAT|O_EXCL)`; on `EEXIST` (stale segment from a crashed
/// previous run) unlinks once and retries.
fn shm_open_or_recreate(cname: &CString, name: &str, mode: u32) -> Result<RawFd> {
    let try_open =
        || unsafe { libc::shm_open(cname.as_ptr(), libc::O_CREAT | libc::O_RDWR | libc::O_EXCL, mode) };
    let mut fd = try_open();
    if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
        tracing::warn!("Cleaned up stale SHM segment: {name}");
        unsafe { libc::shm_unlink(cname.as_ptr()) };
        fd = try_open();
    }
    if fd < 0 {
        return Err(errno_context(format!("shm_open '{name}' failed")));
    }
    Ok(fd)
}

/// Wraps the current `errno` (via `last_os_error`) as an `anyhow::Error`.
fn errno_context(context: String) -> anyhow::Error {
    anyhow::Error::from(std::io::Error::last_os_error()).context(context)
}

/// Standard segment purposes created at startup. The command/response
/// ringbuffers are no longer global: spec perf/008's multi-client support
/// mints a dedicated `ClientShm` quartet per client instead.
const SEGMENT_PURPOSES: &[&str] = &["state", "data_a", "data_b"];

/// Owns every SHM segment and the instance lock file for one LuraDB process.
pub struct ShmManager {
    instance_id: String,
    segments: HashMap<String, ShmSegment>,
    config: ShmConfig,
    /// The instance lock: an `flock`-held fd kept open for the manager's whole
    /// life. Never read — the kernel releasing it on fd close / process exit is
    /// the entire point (auto-recovery after a crash, no owner PID to trust).
    _lock_file: File,
    /// Guards `shutdown()` so repeated calls (explicit + `Drop` fallback) are
    /// safe through a shared `Arc<ShmManager>` (`&self`, not `&mut self` —
    /// required since `AppState` clones the `Arc` per request).
    shut_down: AtomicBool,
}

impl ShmManager {
    /// Acquires the instance lock (fails if another live instance holds it),
    /// cleans up segments left behind by a crashed previous run, then
    /// creates the `state`/`data_a`/`data_b` segments.
    ///
    /// Lock acquisition runs before segment cleanup — reversing the order
    /// would let a second start unlink a *live* peer's active segments
    /// before the lock check ever gets a chance to reject it.
    pub fn new(config: ShmConfig) -> Result<Self> {
        config.validate()?;

        let lock_file = acquire_lock(&config.instance_id)?;
        // The manager owns the lock from here on, so every early return below
        // (cleanup or a failed segment create) drops it — releasing the flock
        // and unlinking any partial segments via `Drop`. No lock/file leak.
        let mut manager = Self {
            instance_id: config.instance_id.clone(),
            segments: HashMap::new(),
            config,
            _lock_file: lock_file,
            shut_down: AtomicBool::new(false),
        };
        cleanup_stale_segments(&manager.instance_id)?;

        let sizes = [
            manager.config.state_size,
            manager.config.data_buffer_size,
            manager.config.data_buffer_size,
        ];
        for (purpose, size) in SEGMENT_PURPOSES.iter().copied().zip(sizes) {
            manager
                .create_segment(purpose, size)
                .with_context(|| format!("failed to create '{purpose}' segment"))?;
        }

        Ok(manager)
    }

    /// Creates and registers a new segment named `/luradb_{instance_id}_{purpose}`.
    pub fn create_segment(&mut self, purpose: &str, size: usize) -> Result<&mut ShmSegment> {
        let name = format!("/luradb_{}_{}", self.instance_id, purpose);
        let segment = ShmSegment::create(&name, size, self.config.segment_mode)?;
        self.segments.insert(purpose.to_string(), segment);
        Ok(self.segments.get_mut(purpose).expect("just inserted"))
    }

    pub fn get_segment(&self, purpose: &str) -> Option<&ShmSegment> {
        self.segments.get(purpose)
    }

    /// Unlinks every segment and the lock file. Idempotent (safe to call
    /// explicitly and then again from `Drop`); cleanup errors are logged,
    /// not propagated (spec §5).
    pub fn shutdown(&self) {
        if self.shut_down.swap(true, Ordering::SeqCst) {
            return;
        }
        for segment in self.segments.values() {
            let Ok(cname) = CString::new(segment.name()) else { continue };
            if unsafe { libc::shm_unlink(cname.as_ptr()) } < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    tracing::warn!("Failed to unlink SHM segment {}: {err}", segment.name());
                }
            }
        }
        let lock = lock_path(&self.instance_id);
        if let Err(e) = std::fs::remove_file(&lock) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Failed to remove SHM lock file {}: {e}", lock.display());
            }
        }
    }
}

impl Drop for ShmManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Header segment size for a per-client ring — one page, minimal (spec §2).
/// `cmd_hdr` also carries the client's `ReaderSlot` (spec perf/012 §1).
pub const CLIENT_HDR_SIZE: usize = 4096;

/// The four per-client ring segments (spec perf/008 Multi-Client): a cmd ring
/// (client→server) and a resp ring (server→client), each a data segment plus a
/// one-page header segment. Owns all four and unlinks them on drop.
///
/// Deliberately not tracked by `ShmManager` — that lives behind an `Arc` in
/// `AppState` and `create_segment` needs `&mut`. A crash instead leaves these
/// for the prefix stale-scan (`cleanup_stale_segments`) to reap on restart.
pub struct ClientShm {
    cmd: ShmSegment,
    /// Behind an `Arc` because the publisher's `ReaderSlotHandle` holds a clone:
    /// the slot page must stay mapped even if the dispatcher drops this
    /// connection mid-scan (spec perf/012 §6).
    cmd_hdr: Arc<ShmSegment>,
    resp: ShmSegment,
    resp_hdr: ShmSegment,
}

impl ClientShm {
    /// Creates `/luradb_{instance_id}_{cmd,cmd_hdr,resp,resp_hdr}_{client_id}`.
    /// `ring_size` is the validated `command_buffer_size` (power-of-two page
    /// multiple, required by `DoubleMmapRegion`); headers are one page.
    pub fn create(instance_id: &str, client_id: u64, ring_size: usize, mode: u32) -> Result<Self> {
        let names = client_segment_names(instance_id, client_id);
        let build = || -> Result<Self> {
            Ok(Self {
                cmd: ShmSegment::create(&names[0], ring_size, mode)?,
                cmd_hdr: Arc::new(ShmSegment::create(&names[1], CLIENT_HDR_SIZE, mode)?),
                resp: ShmSegment::create(&names[2], ring_size, mode)?,
                resp_hdr: ShmSegment::create(&names[3], CLIENT_HDR_SIZE, mode)?,
            })
        };
        build().map_err(|e| {
            // Partial failure: unlink whatever landed (best effort; the
            // stale-scan is the backstop).
            for n in &names {
                if let Ok(c) = CString::new(n.as_str()) {
                    unsafe { libc::shm_unlink(c.as_ptr()) };
                }
            }
            e
        })
    }

    /// The four segment names, ordered cmd, cmd_hdr, resp, resp_hdr.
    pub fn segment_names(&self) -> [String; 4] {
        [
            self.cmd.name().to_string(),
            self.cmd_hdr.name().to_string(),
            self.resp.name().to_string(),
            self.resp_hdr.name().to_string(),
        ]
    }

    pub fn cmd(&self) -> &ShmSegment {
        &self.cmd
    }
    pub fn cmd_hdr(&self) -> &ShmSegment {
        &self.cmd_hdr
    }

    /// Shared handle on the `cmd_hdr` mapping — what a `ReaderSlotHandle` keeps
    /// alive while it points into that page.
    pub fn cmd_hdr_arc(&self) -> Arc<ShmSegment> {
        Arc::clone(&self.cmd_hdr)
    }
    pub fn resp(&self) -> &ShmSegment {
        &self.resp
    }
    pub fn resp_hdr(&self) -> &ShmSegment {
        &self.resp_hdr
    }
}

impl Drop for ClientShm {
    fn drop(&mut self) {
        for seg in [&self.cmd, &*self.cmd_hdr, &self.resp, &self.resp_hdr] {
            let Ok(cname) = CString::new(seg.name()) else { continue };
            if unsafe { libc::shm_unlink(cname.as_ptr()) } < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    tracing::warn!("Failed to unlink client SHM segment {}: {err}", seg.name());
                }
            }
        }
    }
}

fn client_segment_names(instance_id: &str, client_id: u64) -> [String; 4] {
    let n = |purpose: &str| format!("/luradb_{instance_id}_{purpose}_{client_id}");
    [n("cmd"), n("cmd_hdr"), n("resp"), n("resp_hdr")]
}

/// Scans `/dev/shm` for segments left behind by a crashed previous run of
/// this `instance_id` and unlinks them (spec §5.1). Only reached once the
/// instance lock is held, so any match here is guaranteed stale.
fn cleanup_stale_segments(instance_id: &str) -> Result<()> {
    let prefix = format!("luradb_{instance_id}_");
    let entries = match std::fs::read_dir("/dev/shm") {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        if !fname.starts_with(prefix.as_str()) {
            continue;
        }
        let shm_name = format!("/{fname}");
        if let Ok(cname) = CString::new(shm_name.as_str()) {
            if unsafe { libc::shm_unlink(cname.as_ptr()) } == 0 {
                tracing::warn!("Cleaned up stale SHM segment: {shm_name}");
            }
        }
    }
    Ok(())
}

fn lock_path(instance_id: &str) -> PathBuf {
    PathBuf::from(format!("/dev/shm/luradb_{instance_id}.lock"))
}

/// Acquires the per-instance lock via a non-blocking `flock` on the lock file,
/// returning the fd that must be held for the instance's lifetime. The kernel
/// releases the advisory lock when that fd closes or the process dies, so a
/// crash leaves no stale lock and there is no owner PID to identify, trust, or
/// reap. A live holder → `EWOULDBLOCK` → error; no holder → we take it,
/// whatever bytes a crashed run may have left in the file (content is ignored).
fn acquire_lock(instance_id: &str) -> Result<File> {
    let path = lock_path(instance_id);
    // The retry covers only the narrow window where a departing peer unlinks
    // the file (on its own shutdown) between our open and our flock, leaving us
    // holding an orphaned inode. Bounded, so a peer churning the file can never
    // spin us — unlike the old remove-and-retry loop.
    for _ in 0..10 {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("open SHM lock file {}", path.display()))?;

        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                anyhow::bail!(
                    "SHM instance '{instance_id}' is already in use by another running process"
                );
            }
            return Err(anyhow::Error::from(err)
                .context(format!("flock SHM lock file {}", path.display())));
        }

        // The lock only guards the instance while the path still names the
        // inode we locked. If a peer unlinked it between our open and flock we
        // hold an orphan — drop it (loop tail) and retry on the current file.
        let locked = file.metadata().ok().map(|m| m.ino());
        let current = std::fs::metadata(&path).ok().map(|m| m.ino());
        if locked.is_some() && locked == current {
            return Ok(file);
        }
    }
    anyhow::bail!("SHM instance '{instance_id}' lock file kept changing during acquisition")
}

#[cfg(test)]
mod tests {
    use super::super::protocol::{
        PublishOutcome, ReaderSlot, SnapshotGuard, SnapshotWriter, StateHeader, PUBLISH_WAIT_TIMEOUT_US,
        READER_SLOT_OFFSET,
    };
    use super::super::readers::{ReaderRegistry, ReaderSlotHandle};
    use super::*;
    use std::any::Any;
    use std::sync::atomic::AtomicU32;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Unique per-test tag: PID (unique per test *binary*/process) + a
    /// monotonic counter (unique per test *within* this binary) — keeps
    /// parallel `cargo test` runs from colliding on `/dev/shm` names.
    fn unique_tag(tag: &str) -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        // '-' separator: instance ids must not contain '_' (see ShmConfig::validate).
        format!("{}-{}-{}", std::process::id(), n, tag)
    }

    fn unique_name(tag: &str) -> String {
        format!("/luradb_test_{}", unique_tag(tag))
    }

    fn small_config(instance_id: &str) -> ShmConfig {
        ShmConfig {
            enabled: true,
            instance_id: instance_id.to_string(),
            state_size: 4096,
            data_buffer_size: 8192,
            command_buffer_size: 4096,
            segment_mode: 0o600,
            registration_socket_path: "/run/luradb/{instance_id}.sock".to_string(),
            snapshot_interval_ms: 100,
        }
    }

    /// Unlinks a segment name on drop, including on test panic — direct
    /// `ShmSegment::create()` tests bypass `ShmManager` (which would
    /// otherwise own this cleanup), so they guard it themselves.
    struct ShmCleanup(String);
    impl Drop for ShmCleanup {
        fn drop(&mut self) {
            if let Ok(cname) = CString::new(self.0.as_str()) {
                unsafe { libc::shm_unlink(cname.as_ptr()) };
            }
        }
    }

    // 1. ShmSegment::create() — segment exists under /dev/shm/, correct size.
    #[test]
    fn test_create_segment_exists_with_correct_size() {
        let name = unique_name("create");
        let _cleanup = ShmCleanup(name.clone());
        let seg = ShmSegment::create(&name, 8192, 0o600).unwrap();
        assert_eq!(seg.len(), 8192);

        let path = format!("/dev/shm/{}", &name[1..]);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 8192);
    }

    // 2. create() + open() — a second handle sees the same bytes.
    #[test]
    fn test_create_then_open_second_handle_reads_same_bytes() {
        let name = unique_name("open");
        let _cleanup = ShmCleanup(name.clone());
        let mut seg_a = ShmSegment::create(&name, 4096, 0o600).unwrap();
        let pattern = b"second-handle-data!";
        // Safe: pattern.len() is well within the 4096-byte mapping.
        unsafe {
            std::slice::from_raw_parts_mut(seg_a.as_mut_ptr(), pattern.len()).copy_from_slice(pattern);
        }

        let seg_b = ShmSegment::open(&name).unwrap();
        assert_eq!(seg_b.len(), 4096);
        // Safe: same size bound as above.
        let read_back = unsafe { std::slice::from_raw_parts(seg_b.as_ptr(), pattern.len()) };
        assert_eq!(read_back, pattern);
    }

    // 3. write via as_mut_ptr(), read via as_ptr() -> identical bytes.
    #[test]
    fn test_write_via_mut_ptr_read_via_ptr_roundtrip() {
        let name = unique_name("roundtrip");
        let _cleanup = ShmCleanup(name.clone());
        let mut seg = ShmSegment::create(&name, 4096, 0o600).unwrap();

        let pattern = b"hello-shm-0123456789";
        unsafe {
            std::slice::from_raw_parts_mut(seg.as_mut_ptr(), pattern.len()).copy_from_slice(pattern);
        }
        let read_back = unsafe { std::slice::from_raw_parts(seg.as_ptr(), pattern.len()) };
        assert_eq!(read_back, pattern);
    }

    // 4. ShmManager::new() with stale segments -> cleanup, then recreation.
    #[test]
    fn test_manager_new_cleans_up_stale_segments() {
        let instance_id = unique_tag("stale-seg");
        let stale_name = format!("/luradb_{instance_id}_state");
        {
            let stale = ShmSegment::create(&stale_name, 999, 0o600).unwrap();
            assert_eq!(stale.len(), 999);
            // Dropped here: unmaps + closes fd, but the /dev/shm entry stays
            // (no shm_unlink) — simulating a crashed previous run.
        }

        let manager = ShmManager::new(small_config(&instance_id)).unwrap();
        // Recreated at the configured size, not the stale 999 bytes.
        assert_eq!(manager.get_segment("state").unwrap().len(), 4096);
    }

    // 5. Lock file: second ShmManager with the same instance id -> error.
    #[test]
    fn test_second_manager_same_instance_fails_while_first_alive() {
        let instance_id = unique_tag("dup-lock");
        let config = small_config(&instance_id);
        let _manager1 = ShmManager::new(config.clone()).unwrap();

        let err = ShmManager::new(config).err().unwrap();
        assert!(err.to_string().contains("already in use"), "{err}");
    }

    // 6. Stale lock (file left over from a crash, but nobody holds the flock) ->
    //    recreation succeeds, then it's removed.
    #[test]
    fn test_stale_lock_is_cleaned_up_and_new_manager_succeeds() {
        let instance_id = unique_tag("stale-lock");
        let lock_path = format!("/dev/shm/luradb_{instance_id}.lock");
        // A crashed run leaves the file behind; the kernel already dropped its
        // flock on process death, so no live holder remains.
        std::fs::write(&lock_path, "leftover").unwrap();

        let manager = ShmManager::new(small_config(&instance_id)).unwrap();
        manager.shutdown();
        assert!(!std::path::Path::new(&lock_path).exists());
    }

    // FINDING 1 regression: a leftover lock file whose *content* is a very-much-
    // alive PID (pid 1, or an attacker-planted one in world-writable /dev/shm)
    // must NOT block startup — the flock scheme never consults the file's bytes.
    #[test]
    fn test_lock_with_live_pid_content_does_not_block_startup() {
        let instance_id = unique_tag("live-pid");
        let lock_path = format!("/dev/shm/luradb_{instance_id}.lock");
        std::fs::write(&lock_path, "1").unwrap();

        let manager = ShmManager::new(small_config(&instance_id)).unwrap();
        manager.shutdown();
        assert!(!std::path::Path::new(&lock_path).exists());
    }

    // The lock is released when its owning manager is dropped (kernel drops the
    // flock on fd close), so the same instance id restarts cleanly — the
    // crash-recovery case, with no PID guessing.
    #[test]
    fn test_lock_released_on_drop_allows_reacquire() {
        let instance_id = unique_tag("relock");
        {
            let _first = ShmManager::new(small_config(&instance_id)).unwrap();
        }
        let _second = ShmManager::new(small_config(&instance_id)).unwrap();
    }

    // 7. ShmManager::shutdown() -> all segments + lock file removed.
    #[test]
    fn test_shutdown_removes_segments_and_lock_file() {
        let instance_id = unique_tag("shutdown");
        let manager = ShmManager::new(small_config(&instance_id)).unwrap();

        manager.shutdown();

        for purpose in SEGMENT_PURPOSES {
            let path = format!("/dev/shm/luradb_{instance_id}_{purpose}");
            assert!(!std::path::Path::new(&path).exists(), "{purpose} segment should be gone");
        }
        let lock_path = format!("/dev/shm/luradb_{instance_id}.lock");
        assert!(!std::path::Path::new(&lock_path).exists());

        manager.shutdown(); // idempotent: must not panic or error
    }

    // ClientShm creates its four segments and unlinks all of them on drop.
    #[test]
    fn test_client_shm_creates_and_unlinks_quartet() {
        let instance_id = unique_tag("client");
        let names;
        {
            let shm = ClientShm::create(&instance_id, 7, 4096, 0o600).unwrap();
            names = shm.segment_names();
            assert_eq!(names[0], format!("/luradb_{instance_id}_cmd_7"));
            assert_eq!(names[1], format!("/luradb_{instance_id}_cmd_hdr_7"));
            assert_eq!(names[2], format!("/luradb_{instance_id}_resp_7"));
            assert_eq!(names[3], format!("/luradb_{instance_id}_resp_hdr_7"));
            for name in &names {
                let path = format!("/dev/shm/{}", &name[1..]);
                assert!(std::path::Path::new(&path).exists(), "{name} should exist while owned");
            }
        }
        for name in &names {
            let path = format!("/dev/shm/{}", &name[1..]);
            assert!(!std::path::Path::new(&path).exists(), "{name} should be unlinked after drop");
        }
    }

    // Spec perf/012 test 8: the mandatory client mapping modes (§10) —
    // state/data_a/data_b `PROT_READ`, the ReaderSlot page read/write. Reading a
    // published snapshot through the read-only mappings must work and must show
    // the pin in the slot; a write to `state` would fault here exactly as it
    // would in a foreign process.
    #[test]
    fn test_readonly_client_mapping_reads_published_snapshot() {
        let base = unique_name("ro");
        let names: Vec<String> =
            ["state", "data_a", "data_b", "cmd_hdr"].iter().map(|p| format!("{base}_{p}")).collect();
        let _cleanup: Vec<ShmCleanup> = names.iter().map(|n| ShmCleanup(n.clone())).collect();

        // Server side: read/write mappings plus the client's slot page.
        let state = ShmSegment::create(&names[0], 4096, 0o600).unwrap();
        let mut data_a = ShmSegment::create(&names[1], 4096, 0o600).unwrap();
        let mut data_b = ShmSegment::create(&names[2], 4096, 0o600).unwrap();
        let cmd_hdr = Arc::new(ShmSegment::create(&names[3], CLIENT_HDR_SIZE, 0o600).unwrap());
        // Safe: fresh mappings of the sizes asked for above, only ever read
        // through the types they are cast to.
        let header = unsafe { StateHeader::from_ptr(state.as_ptr(), state.len()) };
        header.init();
        let server_slot = unsafe {
            ReaderSlot::from_ptr(cmd_hdr.as_ptr().add(READER_SLOT_OFFSET), cmd_hdr.len() - READER_SLOT_OFFSET)
        };

        let registry = Arc::new(ReaderRegistry::new());
        // Safe: the slot lives inside the `cmd_hdr` mapping the handle keeps alive.
        let handle = unsafe {
            ReaderSlotHandle::new(
                1,
                server_slot as *const ReaderSlot,
                Arc::clone(&cmd_hdr) as Arc<dyn Any + Send + Sync>,
            )
        };
        let _lease = registry.register(handle);

        let buf_len = data_a.len();
        // Safe: single writer, two distinct mappings of `buf_len` bytes.
        let writer = unsafe {
            SnapshotWriter::new(
                header,
                data_a.as_mut_ptr(),
                data_b.as_mut_ptr(),
                buf_len,
                PUBLISH_WAIT_TIMEOUT_US,
                Arc::clone(&registry),
            )
        };
        let payload = b"read-only client snapshot";
        assert_eq!(writer.publish(payload).unwrap(), PublishOutcome::Published);

        // Client side: state/data read-only, cmd_hdr (and thus the slot) RW.
        let ro_state = ShmSegment::open_readonly(&names[0]).unwrap();
        let ro_a = ShmSegment::open_readonly(&names[1]).unwrap();
        let ro_b = ShmSegment::open_readonly(&names[2]).unwrap();
        let client_hdr = ShmSegment::open(&names[3]).unwrap();
        // Safe: all four are live mappings held for the rest of this test.
        let (client_header, client_slot, a, b) = unsafe {
            (
                StateHeader::from_ptr(ro_state.as_ptr(), ro_state.len()),
                ReaderSlot::from_ptr(
                    client_hdr.as_ptr().add(READER_SLOT_OFFSET),
                    client_hdr.len() - READER_SLOT_OFFSET,
                ),
                std::slice::from_raw_parts(ro_a.as_ptr(), ro_a.len()),
                std::slice::from_raw_parts(ro_b.as_ptr(), ro_b.len()),
            )
        };
        assert!(client_header.check_compatible().is_ok());

        let guard = SnapshotGuard::acquire(client_header, client_slot, a, b)
            .expect("snapshot readable through the read-only mappings");
        assert_eq!(guard.data(), payload);
        assert_eq!(server_slot.counter(1).load(Ordering::SeqCst), 1, "pin visible to the server");
        drop(guard);
        assert_eq!(server_slot.counter(1).load(Ordering::SeqCst), 0);
    }

    // 8. command_buffer_size not a power of two -> validation error (via ShmManager::new()).
    #[test]
    fn test_manager_new_rejects_non_power_of_two_command_buffer() {
        let instance_id = unique_tag("badcfg");
        let mut config = small_config(&instance_id);
        config.command_buffer_size = 3_000_000;
        let err = ShmManager::new(config).err().unwrap();
        assert!(err.to_string().contains("power of two"), "{err}");
    }
}
