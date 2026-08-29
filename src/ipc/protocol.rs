//! SHM state header and wait-free double-buffer protocol (spec perf/007,
//! reader liveness per spec perf/012).
//!
//! One writer (the LuraDB process) publishes snapshots into two alternating
//! data buffers; many reader processes read lock-free. The `state` segment
//! holds a [`StateHeader`] whose atomic `version` names the active buffer and
//! carries a monotonic publish sequence. The reader counters live per client in
//! a [`ReaderSlot`] inside that client's own `cmd_hdr` segment, so `state` stays
//! strictly read-only for clients; the writer scans the registered slots to
//! learn when an inactive buffer is safe to overwrite.

use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use super::readers::{ReaderRegistry, ReaderSlotHandle};
use super::ringbuffer::RingbufferHeader;

/// Recommended default for the writer's wait on a busy inactive buffer
/// (spec §2 step 2). The spec calls this "configurable"; it is a
/// [`SnapshotWriter::new`] parameter and this constant is the server default.
pub const PUBLISH_WAIT_TIMEOUT_US: u64 = 1000;

/// Reader retry budget for the acquire handshake (spec §3). One retry is the
/// realistic maximum (nanosecond flip window); the small budget only bounds a
/// pathological publish storm before giving up with `None`.
const ACQUIRE_MAX_RETRIES: usize = 5;

/// Byte offset of the [`ReaderSlot`] inside a client's `cmd_hdr` segment: right
/// behind the ring header, on its own cache line (spec perf/012 §1).
pub const READER_SLOT_OFFSET: usize = RingbufferHeader::SIZE;

/// Errors specific to the SHM state protocol.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("SHM state segment not initialized (magic {found:#018x} != {expected:#018x})")]
    BadMagic { found: u64, expected: u64 },
    #[error("SHM protocol version mismatch: client {client}, server {server}")]
    VersionMismatch { client: u16, server: u16 },
    #[error("snapshot data ({len} bytes) exceeds buffer capacity ({capacity} bytes)")]
    DataTooLarge { len: usize, capacity: usize },
}

/// Result of [`SnapshotWriter::publish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Snapshot written and version flipped.
    Published,
    /// Inactive buffer still had readers after the wait timeout; update skipped
    /// (the previous snapshot stays active). `buffer` names the blocked buffer,
    /// so the caller can ask the registry which clients pin it.
    SkippedBusy { buffer: u32 },
}

/// State header at the start of the `state` SHM segment.
///
/// `repr(C)` (shared across processes) and 64-byte aligned: one cache line,
/// written only by the publisher. Clients map this segment `PROT_READ`
/// (spec perf/012 §10) — nothing a client writes lives here.
#[repr(C, align(64))]
pub struct StateHeader {
    /// Bit 0: active buffer index (0 = data_a, 1 = data_b).
    /// Bits 1–63: monotonic publish sequence (bumped on every flip). Seeing the
    /// same full value twice both validates a read and rules out ABA over two
    /// flips (the sequence never repeats).
    pub version: AtomicU64,
    /// Valid byte length of buffer A's / buffer B's snapshot. Per-buffer, not a
    /// single field as the spec sketches: a global size is briefly ahead of
    /// `version` during a publish (size stored before the flip), so a reader on
    /// the still-active old buffer would read the new, larger size and tear.
    pub data_size_a: AtomicU64,
    pub data_size_b: AtomicU64,
    /// Magic (`LURADBSH`); written last at init so its presence implies a
    /// fully initialized header.
    pub magic: AtomicU64,
    /// Unix-epoch nanoseconds of the last publish (monitoring only).
    pub last_update_ns: AtomicU64,
    /// Wire-protocol version (compatibility gate, spec §6). A dedicated field
    /// rather than bits of `version`, so `version` keeps pure flip/sequence
    /// semantics (resolves the §1/§6 contradiction).
    pub protocol_version: AtomicU32,
    _pad0: [u8; 20],
}

impl StateHeader {
    /// `LURADBSH` in ASCII.
    pub const MAGIC: u64 = 0x4C55_5241_4442_5348;
    /// Current wire-protocol version. Bumped to 2 by spec perf/012: the reader
    /// counters left `StateHeader` for the per-client [`ReaderSlot`], so a
    /// version-1 client must fail the gate instead of writing into `state`.
    pub const PROTOCOL_VERSION: u16 = 0x0002;
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// All-zero header (valid: every field is an atomic or padding). For callers
    /// owning the header inline; the SHM path uses [`from_ptr`](Self::from_ptr)
    /// over the already-zeroed segment.
    pub fn zeroed() -> Self {
        Self {
            version: AtomicU64::new(0),
            data_size_a: AtomicU64::new(0),
            data_size_b: AtomicU64::new(0),
            magic: AtomicU64::new(0),
            last_update_ns: AtomicU64::new(0),
            protocol_version: AtomicU32::new(0),
            _pad0: [0; 20],
        }
    }

    /// Interprets the start of the `state` segment as a `StateHeader`.
    ///
    /// # Safety
    /// `ptr` must point to a live mapping of at least `len` bytes that outlives
    /// `'a` and is only ever accessed through this type.
    pub unsafe fn from_ptr<'a>(ptr: *const u8, len: usize) -> &'a Self {
        assert!(len >= Self::SIZE, "state segment too small: {len} < {}", Self::SIZE);
        // mmap is page-aligned, so 64-byte alignment holds; assert guards a
        // mis-offset segment.
        assert_eq!(ptr as usize % std::mem::align_of::<Self>(), 0, "state segment not 64-byte aligned");
        &*ptr.cast::<Self>()
    }

    /// Initializes the header (spec §7): zero the protocol fields, then publish
    /// `magic` last with `Release`.
    pub fn init(&self) {
        self.version.store(0, Ordering::Relaxed);
        self.data_size_a.store(0, Ordering::Relaxed);
        self.data_size_b.store(0, Ordering::Relaxed);
        self.last_update_ns.store(0, Ordering::Relaxed);
        self.protocol_version.store(Self::PROTOCOL_VERSION as u32, Ordering::Relaxed);
        self.magic.store(Self::MAGIC, Ordering::Release);
    }

    pub fn protocol_version(&self) -> u16 {
        self.protocol_version.load(Ordering::Acquire) as u16
    }

    /// Client compatibility gate (spec §6): initialized and matching protocol.
    pub fn check_compatible(&self) -> Result<(), ProtocolError> {
        let magic = self.magic.load(Ordering::Acquire);
        if magic != Self::MAGIC {
            return Err(ProtocolError::BadMagic { found: magic, expected: Self::MAGIC });
        }
        let server = self.protocol_version();
        if server != Self::PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch { client: Self::PROTOCOL_VERSION, server });
        }
        Ok(())
    }
}

/// One client's reader counters, living at [`READER_SLOT_OFFSET`] in that
/// client's `cmd_hdr` segment (spec perf/012 §1).
///
/// Own cache line: the publisher reads it during its scan while client and
/// dispatcher hammer the ring indices on the lines before it. Both counters
/// share this line on purpose — only the threads of *one* client touch them,
/// and cross-client false sharing is gone because slots live in different pages.
#[repr(C, align(64))]
pub struct ReaderSlot {
    pub readers_a: AtomicU32,
    pub readers_b: AtomicU32,
    _pad: [u8; 56],
}

impl ReaderSlot {
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// All-zero slot (a fresh shm segment is already this — nothing pinned).
    pub fn zeroed() -> Self {
        Self { readers_a: AtomicU32::new(0), readers_b: AtomicU32::new(0), _pad: [0; 56] }
    }

    /// Interprets `ptr` as a `ReaderSlot`.
    ///
    /// # Safety
    /// `ptr` must point to a live mapping of at least `len` bytes that outlives
    /// `'a` and is only ever accessed through this type.
    pub unsafe fn from_ptr<'a>(ptr: *const u8, len: usize) -> &'a Self {
        assert!(len >= Self::SIZE, "reader slot region too small: {len} < {}", Self::SIZE);
        assert_eq!(ptr as usize % std::mem::align_of::<Self>(), 0, "reader slot not 64-byte aligned");
        &*ptr.cast::<Self>()
    }

    /// Counter of buffer `idx` (0 = data_a, 1 = data_b).
    pub fn counter(&self, idx: usize) -> &AtomicU32 {
        if idx == 0 {
            &self.readers_a
        } else {
            &self.readers_b
        }
    }
}

fn data_size_for(header: &StateHeader, idx: usize) -> &AtomicU64 {
    if idx == 0 { &header.data_size_a } else { &header.data_size_b }
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// Server-side snapshot publisher (spec §2, §4). Holds the header by shared
/// reference and the two data buffers as raw pointers, so `publish(&self)` can
/// write through them without a long-lived `&mut` on the mapped segment.
pub struct SnapshotWriter<'a> {
    header: &'a StateHeader,
    data_a: *mut u8,
    data_b: *mut u8,
    buf_len: usize,
    wait_timeout: Duration,
    /// Slots of every registered client; scanned before each flip.
    readers: Arc<ReaderRegistry>,
}

impl<'a> SnapshotWriter<'a> {
    /// # Safety
    /// `data_a`/`data_b` must each be valid for writes of `buf_len` bytes for
    /// `'a`, must not alias each other or the `state` segment, and the caller
    /// must be the single writer for this instance.
    pub unsafe fn new(
        header: &'a StateHeader,
        data_a: *mut u8,
        data_b: *mut u8,
        buf_len: usize,
        wait_timeout_us: u64,
        readers: Arc<ReaderRegistry>,
    ) -> Self {
        Self {
            header,
            data_a,
            data_b,
            buf_len,
            wait_timeout: Duration::from_micros(wait_timeout_us),
            readers,
        }
    }

    /// Publishes a snapshot: pick the inactive buffer, wait for it to drain,
    /// copy, then flip the version (spec §2 steps 1–6).
    pub fn publish(&self, data: &[u8]) -> anyhow::Result<PublishOutcome> {
        if data.len() > self.buf_len {
            return Err(ProtocolError::DataTooLarge { len: data.len(), capacity: self.buf_len }.into());
        }
        let h = self.header;

        let version = h.version.load(Ordering::Acquire);
        let inactive_idx = 1 - (version & 1);

        if !self.wait_drained(inactive_idx as usize) {
            return Ok(PublishOutcome::SkippedBusy { buffer: inactive_idx as u32 });
        }

        let dst = if inactive_idx == 0 { self.data_a } else { self.data_b };
        // Safe: inactive buffer drained to 0 readers above, no other writer
        // exists, and `dst` is valid for buf_len >= data.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };

        data_size_for(h, inactive_idx as usize).store(data.len() as u64, Ordering::Release);
        // Release flip = the publish point: makes the buffer write and data_size
        // visible to any reader that acquire-loads this version.
        let new_version = (((version >> 1) + 1) << 1) | inactive_idx;
        h.version.store(new_version, Ordering::Release);
        h.last_update_ns.store(now_ns(), Ordering::Relaxed);
        Ok(PublishOutcome::Published)
    }

    /// Spins until no registered client pins buffer `idx`, or the timeout
    /// elapses (spec perf/012 §4).
    fn wait_drained(&self, idx: usize) -> bool {
        // Handle list cloned once, then scanned lock-free. A client registering
        // or leaving mid-scan is harmless (spec §7).
        let handles = self.readers.snapshot();
        // Full barrier so this scan and the preceding flip cannot both be missed
        // against a reader's counter bump + version re-read (StoreLoad/Dekker).
        // One fence covers the whole scan.
        fence(Ordering::SeqCst);
        if drained(&handles, idx) {
            return true;
        }
        let deadline = Instant::now() + self.wait_timeout;
        loop {
            std::hint::spin_loop();
            if drained(&handles, idx) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
        }
    }
}

/// True when no slot in `handles` pins buffer `idx`. Stops at the first blocker.
fn drained(handles: &[ReaderSlotHandle], idx: usize) -> bool {
    handles.iter().all(|h| h.slot().counter(idx).load(Ordering::Acquire) == 0)
}

/// Client-side snapshot reader (spec §3, §4). Pins its buffer in the client's
/// own [`ReaderSlot`] for its lifetime and releases it on `Drop`, keeping the
/// writer off that buffer.
pub struct SnapshotGuard<'a> {
    slot: &'a ReaderSlot,
    active_idx: u32,
    data: &'a [u8],
}

enum Attempt<'a> {
    Acquired(SnapshotGuard<'a>),
    Retry,
    Invalid,
}

impl<'a> SnapshotGuard<'a> {
    /// Acquires the active snapshot, or `None` if the header is uninitialized
    /// (bad magic) or no consistent snapshot could be captured within the retry
    /// budget. `slot` must be the caller's *registered* slot — an unregistered
    /// pin is invisible to the writer and therefore unprotected (spec §3).
    pub fn acquire(
        header: &'a StateHeader,
        slot: &'a ReaderSlot,
        data_a: &'a [u8],
        data_b: &'a [u8],
    ) -> Option<Self> {
        if header.magic.load(Ordering::Acquire) != StateHeader::MAGIC {
            return None;
        }
        for _ in 0..ACQUIRE_MAX_RETRIES {
            match try_acquire(header, slot, data_a, data_b) {
                Attempt::Acquired(g) => return Some(g),
                Attempt::Invalid => return None,
                Attempt::Retry => continue,
            }
        }
        None
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

fn try_acquire<'a>(
    header: &'a StateHeader,
    slot: &'a ReaderSlot,
    data_a: &'a [u8],
    data_b: &'a [u8],
) -> Attempt<'a> {
    let (v1, idx) = pin(header, slot);
    // Per-buffer size for the pinned buffer: the counter keeps the writer off it,
    // and a flip (which would change the size) is caught by revalidation below.
    let size = data_size_for(header, idx).load(Ordering::Acquire) as usize;
    if !revalidate(header, slot, v1, idx) {
        return Attempt::Retry;
    }
    let buf = if idx == 0 { data_a } else { data_b };
    match buf.get(..size) {
        Some(data) => Attempt::Acquired(SnapshotGuard { slot, active_idx: idx as u32, data }),
        None => {
            slot.counter(idx).fetch_sub(1, Ordering::Release);
            Attempt::Invalid
        }
    }
}

/// Steps 1–2: read the version and bump the active buffer's reader counter.
fn pin(header: &StateHeader, slot: &ReaderSlot) -> (u64, usize) {
    let v1 = header.version.load(Ordering::Acquire);
    let idx = (v1 & 1) as usize;
    slot.counter(idx).fetch_add(1, Ordering::AcqRel);
    (v1, idx)
}

/// Step 3: keep the counter iff the version is unchanged, else release it and
/// signal a retry.
fn revalidate(header: &StateHeader, slot: &ReaderSlot, v1: u64, idx: usize) -> bool {
    // Pairs with the writer's fence (Dekker): the writer sees our bump or we
    // see its flip here.
    fence(Ordering::SeqCst);
    if header.version.load(Ordering::Acquire) == v1 {
        true
    } else {
        slot.counter(idx).fetch_sub(1, Ordering::Release);
        false
    }
}

impl Drop for SnapshotGuard<'_> {
    fn drop(&mut self) {
        self.slot.counter(self.active_idx as usize).fetch_sub(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::super::readers::ReaderSlotLease;
    use super::*;
    use crate::ipc::CLIENT_HDR_SIZE;
    use std::any::Any;
    use std::ptr::addr_of;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const LEN: usize = 4096;

    /// Raw view of a header, one registered reader slot and the two buffers,
    /// shareable across scoped threads (models the cross-process mapping
    /// single-process tests can't have).
    #[derive(Clone, Copy)]
    struct Shared {
        header: *const StateHeader,
        slot: *const ReaderSlot,
        a: *mut u8,
        b: *mut u8,
        len: usize,
    }
    unsafe impl Send for Shared {}
    unsafe impl Sync for Shared {}

    impl Shared {
        fn header(&self) -> &StateHeader {
            unsafe { &*self.header }
        }
        fn slot(&self) -> &ReaderSlot {
            unsafe { &*self.slot }
        }
        fn writer(&self, timeout_us: u64, readers: Arc<ReaderRegistry>) -> SnapshotWriter<'_> {
            unsafe { SnapshotWriter::new(&*self.header, self.a, self.b, self.len, timeout_us, readers) }
        }
        fn bufs(&self) -> (&[u8], &[u8]) {
            unsafe {
                (std::slice::from_raw_parts(self.a, self.len), std::slice::from_raw_parts(self.b, self.len))
            }
        }
        fn acquire(&self) -> Option<SnapshotGuard<'_>> {
            let (a, b) = self.bufs();
            SnapshotGuard::acquire(self.header(), self.slot(), a, b)
        }
    }

    /// One registered client (= one slot, spec teststrategy preamble) plus the
    /// registry the writer scans. The slot allocation is the handle's `_owner`.
    struct Arena {
        header: Box<StateHeader>,
        slot: Arc<ReaderSlot>,
        registry: Arc<ReaderRegistry>,
        lease: Option<ReaderSlotLease>,
        a: Vec<u8>,
        b: Vec<u8>,
    }

    impl Arena {
        fn new() -> Self {
            let header = Box::new(StateHeader::zeroed());
            header.init();
            let slot = Arc::new(ReaderSlot::zeroed());
            let registry = Arc::new(ReaderRegistry::new());
            // Safe: the pointer targets the `ReaderSlot` inside `slot`, and the
            // handle keeps its own `Arc` clone of that allocation alive.
            let handle = unsafe {
                ReaderSlotHandle::new(
                    1,
                    Arc::as_ptr(&slot),
                    Arc::clone(&slot) as Arc<dyn Any + Send + Sync>,
                )
            };
            let lease = registry.register(handle);
            Self { header, slot, registry, lease: Some(lease), a: vec![0u8; LEN], b: vec![0u8; LEN] }
        }

        fn shared(&mut self) -> Shared {
            Shared {
                header: &*self.header as *const StateHeader,
                slot: Arc::as_ptr(&self.slot),
                a: self.a.as_mut_ptr(),
                b: self.b.as_mut_ptr(),
                len: LEN,
            }
        }

        fn registry(&self) -> Arc<ReaderRegistry> {
            Arc::clone(&self.registry)
        }

        /// Deregisters the client — the reclamation path of spec §7.
        fn drop_lease(&mut self) {
            self.lease = None;
        }
    }

    // 1. Layout of the per-client reader slot (spec perf/012 §1).
    #[test]
    fn test_reader_slot_layout() {
        assert_eq!(ReaderSlot::SIZE, 64);
        assert_eq!(std::mem::align_of::<ReaderSlot>(), 64);
        assert_eq!(READER_SLOT_OFFSET, RingbufferHeader::SIZE);
        assert_eq!(READER_SLOT_OFFSET, 128);
        assert!(READER_SLOT_OFFSET + ReaderSlot::SIZE <= CLIENT_HDR_SIZE);

        let slot = ReaderSlot::zeroed();
        let base = addr_of!(slot) as usize;
        assert_eq!(addr_of!(slot.readers_a) as usize - base, 0);
        assert_eq!(addr_of!(slot.readers_b) as usize - base, 4);

        // write_idx sits on cache line 0 of cmd_hdr, read_idx on line 1; the slot
        // must own a third line so the publisher's scan never false-shares with
        // the ring indices.
        let ring = RingbufferHeader::zeroed();
        let ring_base = addr_of!(ring) as usize;
        let write_line = (addr_of!(ring.write_idx) as usize - ring_base) / 64;
        let read_line = (addr_of!(ring.read_idx) as usize - ring_base) / 64;
        let slot_line = READER_SLOT_OFFSET / 64;
        assert_ne!(slot_line, write_line);
        assert_ne!(slot_line, read_line);
    }

    // 2. StateHeader after the migration: one cache line, no reader counters.
    #[test]
    fn test_state_header_layout_after_migration() {
        assert_eq!(std::mem::align_of::<StateHeader>(), 64);
        assert_eq!(StateHeader::SIZE, 64);

        let h = StateHeader::zeroed();
        let base = addr_of!(h) as usize;
        assert_eq!(addr_of!(h.version) as usize - base, 0);
        assert_eq!(addr_of!(h.data_size_a) as usize - base, 8);
        assert_eq!(addr_of!(h.data_size_b) as usize - base, 16);
        assert_eq!(addr_of!(h.magic) as usize - base, 24);
        assert_eq!(addr_of!(h.last_update_ns) as usize - base, 32);
        assert_eq!(addr_of!(h.protocol_version) as usize - base, 40);
    }

    // 2. Protocol version 2 is the gate that keeps a version-1 client out.
    #[test]
    fn test_protocol_version_two_rejects_version_one() {
        assert_eq!(StateHeader::PROTOCOL_VERSION, 2);
        let header = StateHeader::zeroed();
        header.init();
        assert!(header.check_compatible().is_ok());

        header.protocol_version.store(1, Ordering::Release);
        assert!(matches!(
            header.check_compatible(),
            Err(ProtocolError::VersionMismatch { client: 2, server: 1 })
        ));
    }

    // 3. Overlapping guards on one slot (invariant §2): nesting is legal, and the
    // writer stays off the buffer until the last of them is gone.
    #[test]
    fn test_overlapping_guards_on_one_slot() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());
        let (d1, d2, d3) = (b"first".as_slice(), b"second".as_slice(), b"third".as_slice());

        assert_eq!(w.publish(d1).unwrap(), PublishOutcome::Published); // buffer B active
        let g1 = s.acquire().unwrap();
        let g2 = s.acquire().unwrap();
        assert_eq!(s.slot().counter(1).load(Ordering::SeqCst), 2, "both guards pin buffer B");
        assert_eq!(g1.data(), d1);
        assert_eq!(g2.data(), d1);

        // d2 targets the inactive buffer A: no wait, pinned data untouched.
        assert_eq!(w.publish(d2).unwrap(), PublishOutcome::Published);
        assert_eq!(g1.data(), d1);

        // d3 targets buffer B: blocked while either guard lives.
        assert_eq!(w.publish(d3).unwrap(), PublishOutcome::SkippedBusy { buffer: 1 });
        drop(g1);
        assert_eq!(s.slot().counter(1).load(Ordering::SeqCst), 1);
        assert_eq!(w.publish(d3).unwrap(), PublishOutcome::SkippedBusy { buffer: 1 });
        drop(g2);
        assert_eq!(w.publish(d3).unwrap(), PublishOutcome::Published);
    }

    // 4. Single writer, single reader.
    #[test]
    fn test_single_writer_single_reader() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());
        let data = b"hello snapshot";
        assert_eq!(w.publish(data).unwrap(), PublishOutcome::Published);
        drop(w);

        let g = s.acquire().unwrap();
        assert_eq!(g.data(), data);
    }

    // 4. Single writer, 10 concurrent readers sharing one client slot.
    #[test]
    fn test_single_writer_multiple_readers() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());
        let data = b"shared snapshot payload";
        w.publish(data).unwrap();
        drop(w);

        std::thread::scope(|scope| {
            for _ in 0..10 {
                scope.spawn(move || {
                    let g = s.acquire().unwrap();
                    assert_eq!(g.data(), data);
                });
            }
        });
        assert_eq!(s.slot().counter(1).load(Ordering::SeqCst), 0, "every guard released its pin");
    }

    // 4./5. Writer skips a pinned buffer and publishes once the pin is gone; the
    // holding reader keeps reading valid data throughout.
    #[test]
    fn test_writer_skips_pinned_buffer_then_publishes() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());
        let (d1, d2, d3) = (b"first".as_slice(), b"second".as_slice(), b"third".as_slice());

        assert_eq!(w.publish(d1).unwrap(), PublishOutcome::Published); // buffer B active
        let g = s.acquire().unwrap();
        assert_eq!(g.data(), d1);

        // d2 targets the inactive buffer A: no wait.
        assert_eq!(w.publish(d2).unwrap(), PublishOutcome::Published);
        assert_eq!(g.data(), d1); // pinned buffer B untouched

        // d3 targets buffer B, which g still pins.
        assert_eq!(w.publish(d3).unwrap(), PublishOutcome::SkippedBusy { buffer: 1 });
        assert_eq!(g.data(), d1, "previous snapshot stays readable across the skip");
        drop(g);

        assert_eq!(w.publish(d3).unwrap(), PublishOutcome::Published);
        let g2 = s.acquire().unwrap();
        assert_eq!(g2.data(), d3);
    }

    // 6. Reclamation: a pin left behind by a dead client stops blocking the
    // writer as soon as its lease is dropped (deregistration = release).
    #[test]
    fn test_dropping_the_lease_reclaims_a_stuck_pin() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());

        // A client that pinned buffer B and then died, counter never released.
        s.slot().counter(1).fetch_add(1, Ordering::AcqRel);
        assert_eq!(w.publish(b"blocked").unwrap(), PublishOutcome::SkippedBusy { buffer: 1 });

        arena.drop_lease();
        assert_eq!(w.publish(b"reclaimed").unwrap(), PublishOutcome::Published);
        assert_eq!(
            s.slot().counter(1).load(Ordering::SeqCst),
            1,
            "the server never writes into a client's slot"
        );
    }

    /// Reader loop: every acquired snapshot must be a run of one repeated byte —
    /// any tear shows up as a mismatched byte. Runs until `stop` is set.
    fn read_until_stopped(s: Shared, stop: &AtomicBool, seen: &AtomicU64) {
        while !stop.load(Ordering::SeqCst) {
            if let Some(g) = s.acquire() {
                let d = g.data();
                if !d.is_empty() {
                    let first = d[0];
                    assert!(d.iter().all(|&x| x == first), "torn read");
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    /// Bounded wait until the reader has validated one snapshot, so the final
    /// assertion can't lose a scheduling race under load.
    fn wait_first_read(seen: &AtomicU64) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while seen.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
    }

    /// Writer storm: 5000 alternating single-marker payloads of varying length.
    fn publish_marker_storm(w: &SnapshotWriter, payload: &mut Vec<u8>) {
        for i in 0..5000u32 {
            let marker = 1 + (i % 250) as u8;
            let len = 1 + (i as usize % (LEN - 1));
            payload[..len].fill(marker);
            w.publish(&payload[..len]).unwrap();
            if i % 64 == 0 {
                std::thread::yield_now();
            }
        }
    }

    // 4. Rapid alternating publishes: reader never sees a torn snapshot. Each
    // snapshot is a run of one marker byte, so any tear shows up as a mismatched
    // byte. A prime-and-handshake start keeps the assertion off the scheduler.
    #[test]
    fn test_rapid_publishes_no_torn_reads() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let registry = arena.registry();
        let stop = AtomicBool::new(false);
        let seen = AtomicU64::new(0);

        std::thread::scope(|scope| {
            scope.spawn(|| read_until_stopped(s, &stop, &seen));

            let w = s.writer(5_000_000, registry);
            let mut payload = vec![7u8; LEN];
            w.publish(&payload).unwrap();
            wait_first_read(&seen);
            publish_marker_storm(&w, &mut payload);
            stop.store(true, Ordering::SeqCst);
        });

        assert!(seen.load(Ordering::SeqCst) > 0, "reader validated no snapshots");
    }

    // 4. Guard Drop returns the slot counter to 0.
    #[test]
    fn test_guard_drop_releases_counter() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());
        w.publish(b"x").unwrap();
        drop(w);

        let g = s.acquire().unwrap();
        let counter = s.slot().counter(g.active_idx as usize);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        drop(g);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // 4. Uninitialized header (bad magic) -> acquire returns None.
    #[test]
    fn test_acquire_returns_none_when_uninitialized() {
        let header = StateHeader::zeroed(); // not init()'ed: magic == 0
        let slot = ReaderSlot::zeroed();
        let a = vec![0u8; LEN];
        let b = vec![0u8; LEN];
        assert!(SnapshotGuard::acquire(&header, &slot, &a, &b).is_none());
    }

    // 4. Version flip between pin and revalidate -> counter released, retry.
    #[test]
    fn test_acquire_retries_on_version_flip() {
        let header = StateHeader::zeroed();
        header.init(); // version 0, buffer A active
        let slot = ReaderSlot::zeroed();

        let (v1, idx) = pin(&header, &slot);
        assert_eq!(idx, 0);
        assert_eq!(slot.readers_a.load(Ordering::SeqCst), 1);

        // Simulate a concurrent writer flip to buffer B.
        let flipped = (((v1 >> 1) + 1) << 1) | 1;
        header.version.store(flipped, Ordering::Release);

        assert!(!revalidate(&header, &slot, v1, idx), "must detect the flip");
        assert_eq!(slot.readers_a.load(Ordering::SeqCst), 0, "old counter released");

        // A fresh full acquire now targets buffer B and succeeds.
        let a = vec![0u8; LEN];
        let b = vec![0u8; LEN];
        let g = SnapshotGuard::acquire(&header, &slot, &a, &b).unwrap();
        assert_eq!(g.active_idx, 1);
    }

    // Publish larger than the buffer is a specific error.
    #[test]
    fn test_publish_rejects_oversized_data() {
        let mut arena = Arena::new();
        let s = arena.shared();
        let w = s.writer(PUBLISH_WAIT_TIMEOUT_US, arena.registry());
        let err = w.publish(&vec![0u8; LEN + 1]).unwrap_err();
        assert!(err.to_string().contains("exceeds buffer capacity"), "{err}");
    }

    // Protocol compatibility gate (spec §6).
    #[test]
    fn test_check_compatible() {
        let header = StateHeader::zeroed();
        assert!(matches!(header.check_compatible(), Err(ProtocolError::BadMagic { .. })));

        header.init();
        assert!(header.check_compatible().is_ok());

        header.protocol_version.store(999, Ordering::Release);
        assert!(matches!(header.check_compatible(), Err(ProtocolError::VersionMismatch { server: 999, .. })));
    }
}
