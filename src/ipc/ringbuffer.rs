//! Double-mmap SPSC command ringbuffer (spec perf/008 §1–4, §6).
//!
//! The data segment is mapped twice, back-to-back, so a length-prefixed frame
//! straddling the physical end wraps with no branch or modulo. Two monotonic
//! `u64` indices (`write`/`read`, on separate cache lines) give a lock-free
//! SPSC queue that uses the full capacity (`used = write - read`).

use anyhow::{ensure, Result};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

/// One POSIX-shm fd mapped twice, contiguously, into `2 * size` bytes of
/// virtual address space. The second half mirrors the first, so a write that
/// runs past `size` physically wraps to the start.
pub struct DoubleMmapRegion {
    base: *mut u8,
    size: usize,
}

impl DoubleMmapRegion {
    /// Maps `fd` twice over a single `2*size` reservation. `size` must be a
    /// power of two and a multiple of the page size. The `fd` stays owned by
    /// the caller — `Drop` unmaps but never closes it.
    ///
    /// # Safety
    /// `fd` must be a valid shm fd sized to at least `size` bytes and must stay
    /// open for the duration of this call.
    pub unsafe fn new(fd: RawFd, size: usize) -> Result<Self> {
        let page = page_size();
        ensure!(size >= page && size % page == 0, "ring size {size} is not a multiple of page size {page}");
        ensure!(size.is_power_of_two(), "ring size {size} is not a power of two");

        // Reserve 2*size of address space with no access — a placeholder we
        // overlay the real mappings onto with MAP_FIXED.
        let base = libc::mmap(
            std::ptr::null_mut(),
            2 * size,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );
        ensure!(
            base != libc::MAP_FAILED,
            "reserve {} bytes of address space failed: {}",
            2 * size,
            std::io::Error::last_os_error()
        );
        let base = base as *mut u8;

        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_SHARED | libc::MAP_FIXED;
        if libc::mmap(base as *mut libc::c_void, size, prot, flags, fd, 0) == libc::MAP_FAILED {
            let e = std::io::Error::last_os_error();
            libc::munmap(base as *mut libc::c_void, 2 * size);
            anyhow::bail!("first ring mapping failed: {e}");
        }
        if libc::mmap(base.add(size) as *mut libc::c_void, size, prot, flags, fd, 0) == libc::MAP_FAILED {
            let e = std::io::Error::last_os_error();
            libc::munmap(base as *mut libc::c_void, 2 * size);
            anyhow::bail!("second ring mapping failed: {e}");
        }
        Ok(Self { base, size })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.base
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.base
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for DoubleMmapRegion {
    fn drop(&mut self) {
        // Unmaps both overlays and any remaining reservation; the fd is the
        // caller's to close.
        unsafe { libc::munmap(self.base as *mut libc::c_void, 2 * self.size) };
    }
}

fn page_size() -> usize {
    // sysconf(_SC_PAGESIZE) is always a positive page size on Linux.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Ring metadata at the head of the header segment. `write_idx` and `read_idx`
/// sit on separate cache lines so the producer and consumer never false-share.
#[repr(C, align(128))]
pub struct RingbufferHeader {
    /// Producer-owned; consumer reads it with `Acquire`.
    pub write_idx: AtomicU64,
    _pad_w: [u8; 56],
    /// Consumer-owned; producer reads it with `Acquire`.
    pub read_idx: AtomicU64,
    _pad_r: [u8; 56],
}

impl RingbufferHeader {
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// All-zero header (a fresh shm segment is already this — an empty ring).
    pub fn zeroed() -> Self {
        Self {
            write_idx: AtomicU64::new(0),
            _pad_w: [0; 56],
            read_idx: AtomicU64::new(0),
            _pad_r: [0; 56],
        }
    }

    /// Interprets the head of a header segment as a `RingbufferHeader`.
    ///
    /// # Safety
    /// `ptr` must point to a live mapping of at least `SIZE` bytes, 128-byte
    /// aligned, outliving `'a`, and accessed only through this type.
    pub unsafe fn from_ptr<'a>(ptr: *const u8, len: usize) -> &'a Self {
        assert!(len >= Self::SIZE, "header segment too small: {len} < {}", Self::SIZE);
        assert_eq!(ptr as usize % std::mem::align_of::<Self>(), 0, "header segment not 128-byte aligned");
        &*ptr.cast::<Self>()
    }
}

/// A message could not be enqueued.
#[derive(Debug, Error, PartialEq)]
pub enum RingSendError {
    /// The consumer is behind; waiting for it to drain will make room.
    #[error("ring full: {needed} bytes needed, {available} available")]
    Full { needed: usize, available: usize },
    /// Larger than the whole ring — waiting never helps (own error so the client
    /// does not retry forever).
    #[error("message too large: {total} bytes exceeds ring capacity {capacity}")]
    TooLarge { total: usize, capacity: usize },
}

/// The framing written by an untrusted producer is inconsistent. The caller
/// logs it and stops this ring (spec §6, orchestrator note 2).
#[derive(Debug, Error, PartialEq)]
#[error("ring corrupt: {0}")]
pub struct RingCorrupt(&'static str);

/// SPSC producer over a double-mapped ring.
pub struct RingProducer {
    header: *const RingbufferHeader,
    data: DoubleMmapRegion,
    capacity: usize,
}

// SPSC: a producer is owned by exactly one thread; `header` targets a live
// shared mapping and only the producer writes `write_idx`.
unsafe impl Send for RingProducer {}

impl RingProducer {
    /// # Safety
    /// `header` must point to a live `RingbufferHeader` shared with the matching
    /// consumer, `data` must double-map the ring segment, and this must be the
    /// sole producer on that ring.
    pub unsafe fn new(header: *const RingbufferHeader, data: DoubleMmapRegion) -> Self {
        let capacity = data.size();
        Self { header, data, capacity }
    }

    /// Writes one length-prefixed frame. `Full` means retry after the consumer
    /// drains; `TooLarge` means the message can never fit.
    pub fn send(&mut self, message: &[u8]) -> Result<(), RingSendError> {
        let total = 4 + message.len();
        if total > self.capacity {
            return Err(RingSendError::TooLarge { total, capacity: self.capacity });
        }
        // Safe: header points to a live shared mapping for our lifetime.
        let h = unsafe { &*self.header };
        let write = h.write_idx.load(Ordering::Relaxed); // sole writer of write_idx
        let read = h.read_idx.load(Ordering::Acquire); // consumer publishes read_idx
        let used = write.wrapping_sub(read);
        // A well-behaved consumer keeps used <= capacity; a bogus read_idx (an
        // untrusted client on the response ring) is treated as full, never an
        // underflow.
        if used >= self.capacity as u64 {
            return Err(RingSendError::Full { needed: total, available: 0 });
        }
        let available = self.capacity - used as usize;
        if total > available {
            return Err(RingSendError::Full { needed: total, available });
        }

        let offset = (write & (self.capacity as u64 - 1)) as usize;
        let dst = unsafe { self.data.as_mut_ptr().add(offset) };
        let len_prefix = (message.len() as u32).to_le_bytes();
        // Safe: total <= capacity and offset < capacity, so [offset, offset+total)
        // lies inside the 2*capacity double mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(len_prefix.as_ptr(), dst, 4);
            std::ptr::copy_nonoverlapping(message.as_ptr(), dst.add(4), message.len());
        }
        // Release: publishes the frame to a consumer that Acquire-loads write_idx.
        h.write_idx.store(write.wrapping_add(total as u64), Ordering::Release);
        Ok(())
    }
}

/// SPSC consumer over a double-mapped ring.
pub struct RingConsumer {
    header: *const RingbufferHeader,
    data: DoubleMmapRegion,
    capacity: usize,
}

// SPSC: a consumer is owned by exactly one thread; only the consumer writes
// `read_idx`.
unsafe impl Send for RingConsumer {}

impl RingConsumer {
    /// # Safety
    /// As [`RingProducer::new`], but this must be the sole consumer on the ring.
    pub unsafe fn new(header: *const RingbufferHeader, data: DoubleMmapRegion) -> Self {
        let capacity = data.size();
        Self { header, data, capacity }
    }

    /// `Ok(None)` = empty; `Err` = corrupt framing from an untrusted producer.
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, RingCorrupt> {
        // Safe: header points to a live shared mapping for our lifetime.
        let h = unsafe { &*self.header };
        let read = h.read_idx.load(Ordering::Relaxed); // sole writer of read_idx
        let write = h.write_idx.load(Ordering::Acquire); // producer publishes write_idx
        if read == write {
            return Ok(None);
        }

        // The producer (an untrusted client on the command ring) controls
        // write_idx and the length prefix — bound both before touching memory.
        let used = write.wrapping_sub(read);
        if used > self.capacity as u64 {
            return Err(RingCorrupt("write index advanced past a full ring"));
        }
        if used < 4 {
            return Err(RingCorrupt("truncated length prefix"));
        }

        let offset = (read & (self.capacity as u64 - 1)) as usize;
        let src = unsafe { self.data.as_ptr().add(offset) };
        let mut prefix = [0u8; 4];
        // Safe: used >= 4 and offset < capacity, so [offset, offset+4) is mapped.
        unsafe { std::ptr::copy_nonoverlapping(src, prefix.as_mut_ptr(), 4) };
        let len = u32::from_le_bytes(prefix) as usize;
        let total = 4 + len as u64;
        if total > used {
            return Err(RingCorrupt("frame length exceeds available bytes"));
        }

        // total <= used <= capacity, so [offset, offset+total) lies in the
        // double mapping.
        let mut msg = vec![0u8; len];
        unsafe { std::ptr::copy_nonoverlapping(src.add(4), msg.as_mut_ptr(), len) };
        // Release: frees the slot once the producer Acquire-loads read_idx.
        h.read_idx.store(read.wrapping_add(total), Ordering::Release);
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ShmSegment;
    use std::ffi::CString;
    use std::ptr::addr_of;
    use std::sync::atomic::AtomicU32;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_name() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("/luradb_test_{}-{}-ring", std::process::id(), n)
    }

    /// A fresh shm segment that unlinks its `/dev/shm` name on drop
    /// (`ShmSegment::create` does not).
    struct TestSeg {
        seg: ShmSegment,
        name: String,
    }

    impl TestSeg {
        fn new(size: usize) -> Self {
            let name = unique_name();
            let seg = ShmSegment::create(&name, size, 0o600).unwrap();
            Self { seg, name }
        }
        fn fd(&self) -> RawFd {
            self.seg.fd()
        }
        fn corrupt(&mut self, off: usize, bytes: &[u8]) {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.seg.as_mut_ptr().add(off), bytes.len())
            };
        }
    }

    impl Drop for TestSeg {
        fn drop(&mut self) {
            if let Ok(c) = CString::new(self.name.as_str()) {
                unsafe { libc::shm_unlink(c.as_ptr()) };
            }
        }
    }

    struct Ring {
        prod: RingProducer,
        cons: RingConsumer,
        data: TestSeg,
        _hdr: TestSeg,
    }

    fn make_ring(size: usize) -> Ring {
        let data = TestSeg::new(size);
        let hdr = TestSeg::new(4096);
        let header =
            unsafe { RingbufferHeader::from_ptr(hdr.seg.as_ptr(), hdr.seg.len()) } as *const RingbufferHeader;
        let prod = unsafe { RingProducer::new(header, DoubleMmapRegion::new(data.fd(), size).unwrap()) };
        let cons = unsafe { RingConsumer::new(header, DoubleMmapRegion::new(data.fd(), size).unwrap()) };
        Ring { prod, cons, data, _hdr: hdr }
    }

    // 1. Double-mmap wrap-around: a write past the physical end reappears at 0.
    #[test]
    fn test_double_mmap_wraps_around() {
        let data = TestSeg::new(4096);
        let mut region = unsafe { DoubleMmapRegion::new(data.fd(), 4096).unwrap() };
        let size = region.size();
        let p = region.as_mut_ptr();
        // 10 bytes starting 5 before the end; the last 5 physically wrap to [0,5).
        unsafe {
            for i in 0..10u8 {
                *p.add(size - 5 + i as usize) = i + 1;
            }
        }
        unsafe {
            for i in 0..5u8 {
                assert_eq!(*region.as_ptr().add(i as usize), i + 6, "byte {i} did not wrap");
            }
        }
    }

    // 2. Single message roundtrip.
    #[test]
    fn test_send_recv_single_roundtrip() {
        let mut ring = make_ring(4096);
        assert_eq!(ring.cons.recv().unwrap(), None);
        ring.prod.send(b"hello ring").unwrap();
        assert_eq!(ring.cons.recv().unwrap(), Some(b"hello ring".to_vec()));
        assert_eq!(ring.cons.recv().unwrap(), None);
    }

    // 3. 10k messages, kept partly in flight to force many wraps — no loss.
    #[test]
    fn test_bulk_roundtrip_no_loss() {
        let mut ring = make_ring(4096);
        let mut sent = 0u32;
        let mut recvd = 0u32;
        while recvd < 10_000 {
            while sent < 10_000 && sent.wrapping_sub(recvd) < 128 {
                ring.prod.send(&sent.to_le_bytes()).unwrap();
                sent += 1;
            }
            let msg = ring.cons.recv().unwrap().expect("data pending");
            assert_eq!(u32::from_le_bytes(msg.try_into().unwrap()), recvd);
            recvd += 1;
        }
        assert_eq!(ring.cons.recv().unwrap(), None);
    }

    // 4. Full ring -> Full; after a recv frees a slot, send succeeds again.
    #[test]
    fn test_full_ring_then_drain() {
        let mut ring = make_ring(4096);
        let mut sent = 0;
        loop {
            match ring.prod.send(&[1, 2, 3, 4]) {
                Ok(()) => sent += 1,
                Err(RingSendError::Full { .. }) => break,
                Err(e) => panic!("unexpected: {e}"),
            }
        }
        assert_eq!(sent, 4096 / 8, "capacity/frame-size frames fit exactly");
        ring.cons.recv().unwrap().unwrap();
        ring.prod.send(&[9, 9, 9, 9]).unwrap();
        assert!(matches!(ring.prod.send(&[0, 0, 0, 0]), Err(RingSendError::Full { .. })));
    }

    // Oversized message is TooLarge (never Full) and leaves the ring usable.
    #[test]
    fn test_message_too_large_not_full() {
        let mut ring = make_ring(4096);
        assert!(matches!(ring.prod.send(&vec![0u8; 4096]), Err(RingSendError::TooLarge { .. })));
        let max = vec![7u8; 4096 - 4]; // total == capacity, the largest that fits
        ring.prod.send(&max).unwrap();
        assert_eq!(ring.cons.recv().unwrap(), Some(max));
    }

    // 5. Empty ring -> None.
    #[test]
    fn test_empty_ring_recv_none() {
        let mut ring = make_ring(4096);
        assert_eq!(ring.cons.recv().unwrap(), None);
    }

    // 6. Zero-length payload -> just the length prefix, decoded as empty.
    #[test]
    fn test_zero_length_payload() {
        let mut ring = make_ring(4096);
        ring.prod.send(b"").unwrap();
        assert_eq!(ring.cons.recv().unwrap(), Some(Vec::new()));
        assert_eq!(ring.cons.recv().unwrap(), None);
    }

    // Untrusted producer: a garbage write_idx is reported corrupt, not panicked.
    #[test]
    fn test_corrupt_write_index_detected() {
        let mut ring = make_ring(4096);
        let h = unsafe { &*(ring._hdr.seg.as_ptr() as *const RingbufferHeader) };
        h.write_idx.store(4096 * 2, Ordering::Release); // used > capacity
        assert!(ring.cons.recv().is_err());
    }

    // Untrusted producer: a length prefix larger than the frame is corrupt.
    #[test]
    fn test_corrupt_frame_length_detected() {
        let mut ring = make_ring(4096);
        ring.prod.send(&[1, 2, 3, 4]).unwrap(); // write_idx = 8
        ring.data.corrupt(0, &9999u32.to_le_bytes()); // len prefix now absurd
        assert!(matches!(ring.cons.recv(), Err(RingCorrupt(_))));
    }

    // 11. write_idx and read_idx live on distinct cache lines.
    #[test]
    fn test_indices_on_distinct_cache_lines() {
        let h = RingbufferHeader::zeroed();
        let base = addr_of!(h) as usize;
        let w = addr_of!(h.write_idx) as usize - base;
        let r = addr_of!(h.read_idx) as usize - base;
        assert_eq!(w, 0);
        assert_eq!(r, 64);
        assert_ne!(w / 64, r / 64, "write_idx and read_idx must not share a cache line");
        assert_eq!(RingbufferHeader::SIZE, 128);
        assert_eq!(std::mem::align_of::<RingbufferHeader>(), 128);
    }

    /// Producer side: send sequence numbers 0..n, yielding while the ring is full.
    fn produce_seq(prod: &mut RingProducer, n: u64) {
        for i in 0..n {
            loop {
                match prod.send(&i.to_le_bytes()) {
                    Ok(()) => break,
                    Err(RingSendError::Full { .. }) => std::thread::yield_now(),
                    Err(e) => panic!("unexpected send error: {e}"),
                }
            }
        }
    }

    /// Consumer side: receive n messages, asserting strict in-order delivery.
    fn consume_seq(cons: &mut RingConsumer, n: u64) {
        let mut expected = 0u64;
        while expected < n {
            match cons.recv() {
                Ok(Some(msg)) => {
                    let got = u64::from_le_bytes(msg.try_into().expect("8-byte payload"));
                    assert_eq!(got, expected, "out-of-order or lost message");
                    expected += 1;
                }
                Ok(None) => std::thread::yield_now(),
                Err(e) => panic!("corrupt ring: {e}"),
            }
        }
    }

    // 12. Producer thread + consumer thread, 100k sequence-numbered messages,
    // verified in order (stand-in for Miri/TSan, which can't map shm here).
    #[test]
    fn test_concurrent_producer_consumer() {
        const N: u64 = 100_000;
        let Ring { mut prod, mut cons, data, _hdr } = make_ring(4096);

        std::thread::scope(|scope| {
            scope.spawn(move || produce_seq(&mut prod, N));
            scope.spawn(move || consume_seq(&mut cons, N));
        });

        // Segments kept alive across the scope; touch them so they clearly outlive it.
        drop(data);
        drop(_hdr);
    }
}
