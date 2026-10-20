//! Multi-client registration listener.
//!
//! A dedicated UDS (separate from the REST socket) hands each client
//! its own cmd/resp ring quartet. Wire format is newline-framed text:
//!
//! ```text
//!   request : REGISTER\n
//!   success : OK <client_id> <cmd> <cmd_hdr> <resp> <resp_hdr>\n  + SCM_RIGHTS: doorbell pipe write end
//!   failure : ERR <message>\n
//! ```
//!
//! Segment names never contain spaces, so the reply is a single space-split
//! line. The success line carries the write end of the client's doorbell pipe
//! as `SCM_RIGHTS` ancillary data: after each cmd-ring send
//! the client writes one byte to it to wake the dispatcher. A client that
//! reads the line without `recvmsg` loses only the fd; the dispatcher's
//! fallback tick still serves it. After the reply the socket stays open purely for
//! liveness: a read of 0 bytes (EOF) or an error means the client is gone and
//! its segments drop. The server closes it to disconnect a client that keeps
//! the snapshot publisher blocked longer than `shm.kick_blocking_client_after_secs`.
//!
//! ## Trust model
//!
//! With `auth.enabled`, only UIDs in `auth.trusted_uids` may register — the same
//! kernel-verified peer-credential gate `serve_uds` uses. The ring protocol
//! carries no API key, so `trusted_uids` is the entire trust model here (stricter
//! than REST, which also honors API keys). With auth disabled, registration is
//! open, matching REST without auth.

use super::dispatcher::{ClientConnection, ClientEvent};
use super::readers::ReaderRegistry;
use crate::uds;
use anyhow::{Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Interest};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch, Notify};

const REGISTER_REQUEST: &str = "REGISTER";

/// Control-buffer bytes for one `SCM_RIGHTS` fd.
// Safe: pure arithmetic on a constant size.
const FD_CMSG_SPACE: usize = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;

/// What the listener needs to mint a client's segments.
pub struct RegistrationConfig {
    pub instance_id: String,
    /// Size of each per-client cmd/resp ring (production: `CLIENT_RING_SIZE`).
    pub ring_size: usize,
    pub segment_mode: u32,
    /// When true, only `trusted_uids` may register (peer-credential gate,
    /// consistent with the UDS REST path).
    pub auth_enabled: bool,
    /// UIDs allowed to register while `auth_enabled` (from `auth.trusted_uids`).
    pub trusted_uids: Arc<Vec<u32>>,
    /// Reader slots the snapshot publisher scans; one lease per live client
    /// (spec perf/012 §7).
    pub readers: Arc<ReaderRegistry>,
}

/// Creates the socket's parent directory if missing, then binds it (reusing the
/// UDS helper for stale-file handling + mode). A failure here is fatal:
/// `shm.enabled` means the operator asked for this feature.
pub fn prepare_registration_socket(path: &str) -> Result<UnixListener> {
    if let Some(parent) = Path::new(path).parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create registration socket directory {}", parent.display()))?;
    }
    uds::prepare_uds_socket(path)
}

/// Accept loop: one task per connection, until `shutdown` flips. Returning drops
/// their handles, cancelling the still-open per-connection liveness waits.
pub async fn serve_registration(
    listener: UnixListener,
    config: RegistrationConfig,
    events: mpsc::UnboundedSender<ClientEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let config = Arc::new(config);
    let next_id = Arc::new(AtomicU64::new(1));
    let mut conns = FuturesUnordered::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = conns.next() => {} // reap finished handlers
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((s, _)) => s,
                    Err(e) => {
                        tracing::warn!("[shm-reg] accept error: {e}");
                        compio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let client_id = next_id.fetch_add(1, Ordering::Relaxed);
                conns.push(compio::runtime::spawn(handle_connection(
                    stream,
                    client_id,
                    Arc::clone(&config),
                    events.clone(),
                    shutdown.clone(),
                )));
            }
        }
    }
    tracing::info!("[shm-reg] registration listener stopped");
}

async fn handle_connection(
    stream: tokio::net::UnixStream,
    client_id: u64,
    config: Arc<RegistrationConfig>,
    events: mpsc::UnboundedSender<ClientEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    // peer_cred must be read before the stream is split into halves.
    let peer_trusted = !config.auth_enabled || peer_is_trusted(&stream, &config.trusted_uids);

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // 1. Read the request line.
    let mut line = String::new();
    match reader.read_line(&mut line).await {
        Ok(0) => return, // client vanished before registering
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("[shm-reg] read error from client {client_id}: {e}");
            return;
        }
    }
    if line.trim() != REGISTER_REQUEST {
        let _ = write_half.write_all(b"ERR unknown request\n").await;
        return;
    }

    // 2. Trust gate (spec perf/008; same UID check as serve_uds). The ring
    // protocol has no API-key path, so with auth on only trusted_uids may mint a
    // quartet; reject everyone else without touching shm.
    if !peer_trusted {
        tracing::warn!("[shm-reg] rejecting unauthorized registration (client {client_id})");
        let _ = write_half.write_all(b"ERR unauthorized\n").await;
        return;
    }

    // 3. Mint the segment quartet + the server ring ends.
    let kick = Arc::new(Notify::new());
    let (conn, names, slot_handle, doorbell) =
        match ClientConnection::create(
            &config.instance_id,
            client_id,
            config.ring_size,
            config.segment_mode,
            Arc::clone(&kick),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[shm-reg] segment creation failed for client {client_id}: {e}");
                let _ = write_half.write_all(format!("ERR {e}\n").as_bytes()).await;
                return;
            }
        };

    // 4. Hand the server ends to the dispatcher (which now owns the segments).
    if events.send(ClientEvent::Connect(Box::new(conn))).is_err() {
        return; // dispatcher gone (shutdown); the channel dropped `conn`, unlinking
    }

    // 5. Register the reader slot — strictly before the reply (spec perf/012
    // §7): the client may pin as soon as it has read the `OK`, and a pin the
    // publisher cannot see would let it flip a buffer that is being read. The
    // event channel above is asynchronous and therefore no substitute. `lease`
    // frees the slot on every exit below, cancellation at an `.await` included.
    let lease = config.readers.register(slot_handle);

    // 6. Reply with the segment names, the doorbell's write end attached (spec
    // perf/014). Ours closes right after: only the client's copy stays open.
    let reply = format!("OK {} {} {} {} {}\n", client_id, names[0], names[1], names[2], names[3]);
    let sent = send_with_fd(&write_half, reply.as_bytes(), doorbell.as_fd()).await;
    drop(doorbell);
    if let Err(e) = sent {
        tracing::warn!("[shm-reg] reply to client {client_id} failed: {e}");
        drop(lease);
        let _ = events.send(ClientEvent::Disconnect(client_id));
        return;
    }

    // 7. Keep the socket open; EOF/error = disconnect. Also stop on shutdown,
    // and on a kick: the publisher disconnects a client that blocks it too long.
    let mut buf = [0u8; 32];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = kick.notified() => break,
            r = reader.read(&mut buf) => match r {
                Ok(0) | Err(_) => break, // EOF or error → client gone
                Ok(_) => {} // unexpected extra bytes: ignore
            }
        }
    }
    // Slot first, then the segments: the publisher must stop seeing this client
    // before the dispatcher tears the connection down.
    drop(lease);
    let _ = events.send(ClientEvent::Disconnect(client_id));
}

/// A peer is trusted iff its kernel-verified UID is in `trusted_uids` — the same
/// gate `serve_uds` applies. A missing UCred (should not happen on a UDS) counts
/// as untrusted.
fn peer_is_trusted(stream: &tokio::net::UnixStream, trusted_uids: &[u32]) -> bool {
    stream.peer_cred().is_ok_and(|c| trusted_uids.contains(&c.uid()))
}

/// Writes all of `bytes` with `fd` attached as `SCM_RIGHTS` to the first
/// chunk. A peer reading without `recvmsg` gets the bytes; the kernel then
/// closes the fd on its side.
async fn send_with_fd(half: &OwnedWriteHalf, bytes: &[u8], fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let stream: &tokio::net::UnixStream = half.as_ref();
    let mut sent = 0;
    while sent < bytes.len() {
        stream.writable().await?;
        let attach = (sent == 0).then_some(fd);
        match stream.try_io(Interest::WRITABLE, || sendmsg_once(stream.as_raw_fd(), &bytes[sent..], attach)) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// One non-blocking `sendmsg`, optionally carrying `fd` as `SCM_RIGHTS`.
fn sendmsg_once(sock: RawFd, bytes: &[u8], fd: Option<BorrowedFd<'_>>) -> std::io::Result<usize> {
    let mut iov = libc::iovec { iov_base: bytes.as_ptr() as *mut libc::c_void, iov_len: bytes.len() };
    // `u64` elements keep the buffer aligned for `cmsghdr`.
    let mut cmsg_buf = [0u64; FD_CMSG_SPACE.div_ceil(8)];
    // Safe: a zeroed msghdr is valid, every pointer targets a live local, and
    // header plus fd fit `cmsg_buf` (sized by CMSG_SPACE).
    let n = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = cmsg_buf.as_mut_ptr().cast();
            msg.msg_controllen = FD_CMSG_SPACE as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd.as_raw_fd());
        }
        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::ShmDispatcher;
    use super::super::protocol::{
        PublishOutcome, ReaderSlot, SnapshotWriter, StateHeader, PUBLISH_WAIT_TIMEOUT_US,
        READER_SLOT_OFFSET,
    };
    use super::super::ringbuffer::{DoubleMmapRegion, RingConsumer, RingProducer, RingbufferHeader};
    use super::super::shm::ShmSegment;
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::ipc::{ShmCommand, ShmGetValue, ShmResponse};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use crate::engines::lsm::domain::DomainRegistry;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Interest};
    use tokio::net::UnixStream;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_instance() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("regtest-{}-{n}", std::process::id())
    }

    async fn make_registry() -> (Arc<DomainRegistry>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            crate::engines::lsm::LsmStorageEngine::new(
                wal,
                wal_path,
                vlog,
                vlog_path,
                fm,
                mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry = Arc::new(
            DomainRegistry::recover(engine, crate::engines::lsm::domain::DomainConfig::default(), metrics)
                .await
                .unwrap(),
        );
        (registry, dir)
    }

    /// Spawns a registration listener + dispatcher on a tempdir socket.
    struct Server {
        sock: std::path::PathBuf,
        instance_id: String,
        readers: Arc<ReaderRegistry>,
        shutdown: watch::Sender<bool>,
        reg: compio::runtime::JoinHandle<()>,
        disp: compio::runtime::JoinHandle<()>,
        _sockdir: tempfile::TempDir,
    }

    async fn start_server(registry: Arc<DomainRegistry>, ring_size: usize) -> Server {
        start_server_with_auth(registry, ring_size, false, vec![]).await
    }

    async fn start_server_with_auth(
        registry: Arc<DomainRegistry>,
        ring_size: usize,
        auth_enabled: bool,
        trusted_uids: Vec<u32>,
    ) -> Server {
        let sockdir = tempfile::TempDir::new().unwrap();
        let sock = sockdir.path().join("reg.sock");
        let listener = prepare_registration_socket(&sock.to_string_lossy()).unwrap();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (sd_tx, sd_rx) = watch::channel(false);
        let instance_id = unique_instance();
        let readers = Arc::new(ReaderRegistry::new());
        let disp = compio::runtime::spawn(ShmDispatcher::new(registry).run(events_rx, sd_rx.clone()));
        let reg = compio::runtime::spawn(serve_registration(
            listener,
            RegistrationConfig {
                instance_id: instance_id.clone(),
                ring_size,
                segment_mode: 0o600,
                auth_enabled,
                trusted_uids: Arc::new(trusted_uids),
                readers: Arc::clone(&readers),
            },
            events_tx,
            sd_rx,
        ));
        Server { sock, instance_id, readers, shutdown: sd_tx, reg, disp, _sockdir: sockdir }
    }

    impl Server {
        async fn stop(self) {
            let _ = self.shutdown.send(true);
            let _ = self.reg.await;
            let _ = self.disp.await;
        }
    }

    async fn register(stream: &mut UnixStream) -> String {
        stream.write_all(b"REGISTER\n").await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        line
    }

    fn shm_path(name: &str) -> String {
        format!("/dev/shm/{}", &name[1..])
    }

    async fn poll_gone(name: &str) -> bool {
        for _ in 0..2000 {
            if !std::path::Path::new(&shm_path(name)).exists() {
                return true;
            }
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        false
    }

    /// Bounded wait for the registry to shrink to `n` entries: a lease is
    /// released inside the listener task, i.e. asynchronously to this test.
    async fn poll_registry_len(readers: &ReaderRegistry, n: usize) -> bool {
        for _ in 0..2000 {
            if readers.snapshot().len() == n {
                return true;
            }
            compio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// The client's view of its reader slot, mapped read/write from `cmd_hdr`.
    ///
    /// # Safety
    /// `cmd_hdr` must stay mapped for as long as the returned reference is used.
    unsafe fn client_slot(cmd_hdr: &ShmSegment) -> &ReaderSlot {
        ReaderSlot::from_ptr(cmd_hdr.as_ptr().add(READER_SLOT_OFFSET), cmd_hdr.len() - READER_SLOT_OFFSET)
    }

    /// Stand-in for the snapshot publisher: an in-process header plus two
    /// buffers, wired to the listener's reader registry.
    struct WriterArena {
        header: Box<StateHeader>,
        a: Vec<u8>,
        b: Vec<u8>,
        readers: Arc<ReaderRegistry>,
    }

    impl WriterArena {
        fn new(readers: Arc<ReaderRegistry>) -> Self {
            let header = Box::new(StateHeader::zeroed());
            header.init();
            Self { header, a: vec![0u8; 256], b: vec![0u8; 256], readers }
        }

        fn publish(&mut self, data: &[u8]) -> PublishOutcome {
            let len = self.a.len();
            // Safe: single writer, two distinct buffers of `len` bytes, header valid.
            let writer = unsafe {
                SnapshotWriter::new(
                    &self.header,
                    self.a.as_mut_ptr(),
                    self.b.as_mut_ptr(),
                    len,
                    PUBLISH_WAIT_TIMEOUT_US,
                    Arc::clone(&self.readers),
                )
            };
            writer.publish(data).unwrap()
        }
    }

    async fn recv_response(rx: &mut RingConsumer) -> ShmResponse {
        for _ in 0..2000 {
            if let Some(raw) = rx.recv().unwrap() {
                return ShmResponse::decode(&raw).unwrap();
            }
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("no response within timeout");
    }

    /// One `recvmsg` into `buf`: the byte count plus the fd passed as
    /// `SCM_RIGHTS` with these bytes, if any.
    fn recv_with_fd(sock: RawFd, buf: &mut [u8]) -> std::io::Result<(usize, Option<OwnedFd>)> {
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        let mut cmsg_buf = [0u64; 8];
        // Safe: a zeroed msghdr is valid and every pointer targets a live local;
        // a received SCM_RIGHTS fd is new and owned by nobody else.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&cmsg_buf) as _;
            let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut fd = None;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let raw = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>());
                    fd = Some(OwnedFd::from_raw_fd(raw));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            Ok((n as usize, fd))
        }
    }

    /// Registers like a doorbell-aware client (spec perf/014): the reply line
    /// via `recvmsg`, plus the doorbell pipe's write end attached to it.
    async fn register_with_doorbell(stream: &mut UnixStream) -> (String, OwnedFd) {
        stream.write_all(b"REGISTER\n").await.unwrap();
        let mut line = Vec::new();
        let mut doorbell = None;
        let mut buf = [0u8; 256];
        while !line.ends_with(b"\n") {
            stream.readable().await.unwrap();
            match stream.try_io(Interest::READABLE, || recv_with_fd(stream.as_raw_fd(), &mut buf)) {
                Ok((0, _)) => panic!("EOF before the full reply: {line:?}"),
                Ok((n, fd)) => {
                    line.extend_from_slice(&buf[..n]);
                    doorbell = doorbell.or(fd);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("recvmsg: {e}"),
            }
        }
        let line = String::from_utf8(line).unwrap();
        (line, doorbell.expect("doorbell fd attached to the reply"))
    }

    /// What a doorbell-aware client does after each cmd-ring send.
    fn ring(doorbell: &OwnedFd) {
        // Safe: a 1-byte write from a live local to a pipe end we own.
        let n = unsafe { libc::write(doorbell.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        assert_eq!(n, 1, "doorbell write");
    }

    /// The `pipe:[<inode>]` link of a pipe end: both ends of one pipe share it.
    fn pipe_link(fd: &OwnedFd) -> std::path::PathBuf {
        let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert!(link.to_string_lossy().starts_with("pipe:["), "a pipe end: {link:?}");
        link
    }

    /// How many fds of this process are open on the pipe with `link`.
    fn fds_on_pipe(link: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter(|e| std::fs::read_link(e.path()).is_ok_and(|l| l == link))
            .count()
    }

    /// Bounded wait for the fds on the pipe with `link` to drop to `n`: the
    /// server closes its own asynchronously to this test.
    async fn poll_fds_on_pipe(link: &Path, n: usize) -> bool {
        for _ in 0..2000 {
            if fds_on_pipe(link) == n {
                return true;
            }
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        false
    }

    /// A client's ring ends over the four segments named in its `OK` reply:
    /// producer on the cmd ring, consumer on the resp ring.
    struct ClientRings {
        tx: RingProducer,
        rx: RingConsumer,
        /// Declared last: the rings map into these segments.
        _segs: [ShmSegment; 4],
    }

    impl ClientRings {
        fn open(reply: &str) -> Self {
            let names: Vec<&str> = reply.split_whitespace().skip(2).collect();
            assert_eq!(names.len(), 4, "OK <id> + four names: {reply:?}");
            let segs: [ShmSegment; 4] = std::array::from_fn(|i| ShmSegment::open(names[i]).unwrap());
            let [cmd, cmd_hdr, resp, resp_hdr] = &segs;
            // Safe: header segments are page-sized server mappings, data
            // segments are sized to the ring, and `_segs` outlives the rings.
            let tx = unsafe {
                let h = RingbufferHeader::from_ptr(cmd_hdr.as_ptr(), cmd_hdr.len()) as *const RingbufferHeader;
                RingProducer::new(h, DoubleMmapRegion::new(cmd.fd(), cmd.len()).unwrap())
            };
            let rx = unsafe {
                let h = RingbufferHeader::from_ptr(resp_hdr.as_ptr(), resp_hdr.len()) as *const RingbufferHeader;
                RingConsumer::new(h, DoubleMmapRegion::new(resp.fd(), resp.len()).unwrap())
            };
            Self { tx, rx, _segs: segs }
        }
    }

    // The reply names a client_id and the four segments, which now exist.
    #[test]
    fn test_register_wire_format() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            let server = start_server(Arc::clone(&registry), 4096).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            let reply = register(&mut stream).await;
            let parts: Vec<&str> = reply.split_whitespace().collect();

            assert_eq!(parts[0], "OK");
            assert_eq!(parts.len(), 6, "OK <id> + four names: {reply:?}");
            assert_eq!(parts[1], "1", "first client_id is 1");
            assert_eq!(parts[2], format!("/luradb_{}_cmd_1", server.instance_id));
            assert_eq!(parts[3], format!("/luradb_{}_cmd_hdr_1", server.instance_id));
            assert_eq!(parts[4], format!("/luradb_{}_resp_1", server.instance_id));
            assert_eq!(parts[5], format!("/luradb_{}_resp_hdr_1", server.instance_id));
            for name in &parts[2..] {
                assert!(std::path::Path::new(&shm_path(name)).exists(), "{name} should exist while registered");
            }

            drop(stream);
            server.stop().await;
        })
    }

    // An unrecognised request is rejected and mints no segments.
    #[test]
    fn test_unknown_request_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            let server = start_server(Arc::clone(&registry), 4096).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            stream.write_all(b"HELLO\n").await.unwrap();
            let mut reply = String::new();
            BufReader::new(&mut stream).read_line(&mut reply).await.unwrap();
            assert!(reply.starts_with("ERR"), "{reply:?}");

            // No client_1 segment was created.
            assert!(
                !std::path::Path::new(&shm_path(&format!("/luradb_{}_cmd_1", server.instance_id))).exists()
            );
            drop(stream);
            server.stop().await;
        })
    }

    // With auth on, a trusted UID (this process's own) registers normally.
    #[test]
    fn test_auth_trusted_uid_registers() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            let uid = unsafe { libc::getuid() };
            let server = start_server_with_auth(Arc::clone(&registry), 4096, true, vec![uid]).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            let reply = register(&mut stream).await;
            assert!(reply.starts_with("OK"), "trusted uid should register: {reply:?}");

            drop(stream);
            server.stop().await;
        })
    }

    // With auth on, an untrusted UID is refused and no segment is minted.
    #[test]
    fn test_auth_untrusted_uid_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            // Trust only a different uid, so this process's connection is untrusted.
            let others = vec![unsafe { libc::getuid() }.wrapping_add(1)];
            let server = start_server_with_auth(Arc::clone(&registry), 4096, true, others).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            let reply = register(&mut stream).await;
            assert!(reply.starts_with("ERR unauthorized"), "{reply:?}");
            assert!(
                !std::path::Path::new(&shm_path(&format!("/luradb_{}_cmd_1", server.instance_id))).exists(),
                "no segment minted for an unauthorized client"
            );

            drop(stream);
            server.stop().await;
        })
    }

    // Spec perf/012 §7: the slot is in the registry before the client can read
    // the `OK` (and therefore before it can pin), and EOF on the registration
    // socket reclaims it — the next publish onto the pinned buffer goes through
    // without the server ever writing into the client's page.
    #[test]
    fn test_reader_slot_registered_before_reply_and_freed_on_eof() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            let server = start_server(Arc::clone(&registry), 4096).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            let reply = register(&mut stream).await;
            let names: Vec<String> = reply.split_whitespace().skip(2).map(String::from).collect();

            let slots = server.readers.snapshot();
            assert_eq!(slots.len(), 1, "slot registered before the OK reply");
            assert_eq!(slots[0].client_id, 1);

            // The client pins buffer B through its own cmd_hdr mapping and dies
            // without releasing it.
            let cmd_hdr = ShmSegment::open(&names[1]).unwrap();
            let slot = unsafe { client_slot(&cmd_hdr) };
            slot.counter(1).fetch_add(1, Ordering::AcqRel);

            let mut arena = WriterArena::new(Arc::clone(&server.readers));
            assert_eq!(arena.publish(b"blocked"), PublishOutcome::SkippedBusy { buffer: 1 });
            assert_eq!(server.readers.blockers(1), vec![(1, 1)]);

            drop(stream);
            assert!(poll_registry_len(&server.readers, 0).await, "EOF must release the lease");
            assert_eq!(arena.publish(b"reclaimed"), PublishOutcome::Published);
            assert_eq!(slot.counter(1).load(Ordering::SeqCst), 1, "the server never clears the slot");

            server.stop().await;
        })
    }

    // Spec perf/012 test 7: a connection task cancelled at an `.await` (what the
    // shutdown path does: the listener drops the compio handles of its
    // connection tasks) never reaches the code behind its EOF loop — only the
    // lease's Drop frees the slot.
    #[test]
    fn test_aborted_connection_task_releases_reader_slot() {
        crate::core::engine_runtime::block_on(async {
            let (client, server_side) = UnixStream::pair().unwrap();
            let readers = Arc::new(ReaderRegistry::new());
            let (events_tx, mut events_rx) = mpsc::unbounded_channel();
            let (_sd_tx, sd_rx) = watch::channel(false);
            let config = Arc::new(RegistrationConfig {
                instance_id: unique_instance(),
                ring_size: 4096,
                segment_mode: 0o600,
                auth_enabled: false,
                trusted_uids: Arc::new(Vec::new()),
                readers: Arc::clone(&readers),
            });
            let task = compio::runtime::spawn(handle_connection(server_side, 5, config, events_tx, sd_rx));

            let mut client = client;
            let reply = register(&mut client).await;
            let names: Vec<String> = reply.split_whitespace().skip(2).map(String::from).collect();
            // Hold the connection: dropping it would unlink the segments early.
            let _conn = events_rx.recv().await.expect("connect event");

            let cmd_hdr = ShmSegment::open(&names[1]).unwrap();
            let slot = unsafe { client_slot(&cmd_hdr) };
            slot.counter(1).fetch_add(1, Ordering::AcqRel);

            let mut arena = WriterArena::new(Arc::clone(&readers));
            assert_eq!(arena.publish(b"blocked"), PublishOutcome::SkippedBusy { buffer: 1 });

            // The client socket stays open, so nothing but the cancellation can free
            // the slot. Dropping the handle cancels the task; the runtime drops its
            // future — and with it the lease — in its next round.
            drop(task);
            tokio::task::yield_now().await;
            assert!(readers.snapshot().is_empty(), "cancelled task must release its lease");
            assert_eq!(arena.publish(b"reclaimed"), PublishOutcome::Published);
        })
    }

    // A kicked client is disconnected like one whose socket hit EOF: its
    // connection task ends, the lease is freed so the blocked buffer can be
    // published again, the dispatcher is told, and the client reads EOF.
    #[test]
    fn test_kick_disconnects_live_client_and_frees_its_pinned_buffer() {
        crate::core::engine_runtime::block_on(async {
            let (client, server_side) = UnixStream::pair().unwrap();
            let readers = Arc::new(ReaderRegistry::new());
            let (events_tx, mut events_rx) = mpsc::unbounded_channel();
            let (_sd_tx, sd_rx) = watch::channel(false);
            let config = Arc::new(RegistrationConfig {
                instance_id: unique_instance(),
                ring_size: 4096,
                segment_mode: 0o600,
                auth_enabled: false,
                trusted_uids: Arc::new(Vec::new()),
                readers: Arc::clone(&readers),
            });
            let task = compio::runtime::spawn(handle_connection(server_side, 5, config, events_tx, sd_rx));

            let mut client = client;
            let reply = register(&mut client).await;
            let names: Vec<String> = reply.split_whitespace().skip(2).map(String::from).collect();
            let Some(ClientEvent::Connect(_conn)) = events_rx.recv().await else { panic!("connect event") };

            // A live client: it pins buffer B, never releases it and keeps its
            // socket open.
            let cmd_hdr = ShmSegment::open(&names[1]).unwrap();
            let slot = unsafe { client_slot(&cmd_hdr) };
            slot.counter(1).fetch_add(1, Ordering::AcqRel);
            let mut arena = WriterArena::new(Arc::clone(&readers));
            assert_eq!(arena.publish(b"blocked"), PublishOutcome::SkippedBusy { buffer: 1 });

            readers.kick(5);
            let ended = compio::time::timeout(Duration::from_secs(20), task).await;
            assert!(ended.is_ok(), "the kicked connection task must end");
            assert!(readers.snapshot().is_empty(), "a kick must release the lease");
            assert!(matches!(events_rx.recv().await, Some(ClientEvent::Disconnect(5))));
            assert_eq!(arena.publish(b"unblocked"), PublishOutcome::Published);
            let mut buf = [0u8; 8];
            assert_eq!(client.read(&mut buf).await.unwrap(), 0, "the kicked client must read EOF");
        })
    }

    // Full loop: register, open the segments, drive Put+Get over the rings, then
    // disconnect and watch the segments get unlinked. A legacy client: it reads
    // the reply with `read_line`, never sees the doorbell fd and is served by
    // the fallback tick (spec perf/014 test 2).
    #[test]
    fn test_e2e_put_get_roundtrip_and_cleanup() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            registry.create_domain("d1").await.unwrap();
            let ring_size = 4096;
            let server = start_server(Arc::clone(&registry), ring_size).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            let reply = register(&mut stream).await;
            let names: Vec<String> = reply.split_whitespace().skip(2).map(String::from).collect();
            let (cmd_name, cmd_hdr_name, resp_name, resp_hdr_name) =
                (&names[0], &names[1], &names[2], &names[3]);

            // Client opens the four segments and builds its ring ends: producer on
            // the cmd ring, consumer on the resp ring.
            let cmd_seg = ShmSegment::open(cmd_name).unwrap();
            let cmd_hdr_seg = ShmSegment::open(cmd_hdr_name).unwrap();
            let resp_seg = ShmSegment::open(resp_name).unwrap();
            let resp_hdr_seg = ShmSegment::open(resp_hdr_name).unwrap();
            let mut client_tx = unsafe {
                let h = RingbufferHeader::from_ptr(cmd_hdr_seg.as_ptr(), cmd_hdr_seg.len()) as *const RingbufferHeader;
                RingProducer::new(h, DoubleMmapRegion::new(cmd_seg.fd(), cmd_seg.len()).unwrap())
            };
            let mut client_rx = unsafe {
                let h = RingbufferHeader::from_ptr(resp_hdr_seg.as_ptr(), resp_hdr_seg.len()) as *const RingbufferHeader;
                RingConsumer::new(h, DoubleMmapRegion::new(resp_seg.fd(), resp_seg.len()).unwrap())
            };

            // PUT then GET, each verified through the response ring.
            client_tx
                .send(
                    ShmCommand::Put {
                        request_id: 1,
                        domain: "d1".into(),
                        key: b"k".to_vec(),
                        value: b"v".to_vec(),
                        ttl_secs: 0,
                    }
                    .encode()
                    .as_slice(),
                )
                .unwrap();
            assert_eq!(recv_response(&mut client_rx).await, ShmResponse::Ok { request_id: 1 });

            client_tx
                .send(ShmCommand::Get { request_id: 2, domain: "d1".into(), key: b"k".to_vec() }.encode().as_slice())
                .unwrap();
            assert_eq!(
                recv_response(&mut client_rx).await,
                ShmResponse::GetOk { request_id: 2, value: ShmGetValue::Present(b"v".to_vec()) }
            );

            // Disconnect: drop the client mappings, then close the socket.
            drop(client_tx);
            drop(client_rx);
            drop((cmd_seg, cmd_hdr_seg, resp_seg, resp_hdr_seg));
            drop(stream);

            // The dispatcher unlinks all four on the disconnect event.
            for name in [cmd_name, cmd_hdr_name, resp_name, resp_hdr_name] {
                assert!(poll_gone(name).await, "{name} should be unlinked after disconnect");
            }

            server.stop().await;
        })
    }

    // Spec perf/014: a doorbell-aware client receives the doorbell's write end
    // with the `OK` line and rings it after every cmd-ring send; Put+Get
    // round-trip.
    #[test]
    fn test_e2e_doorbell_client_put_get_roundtrip() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            registry.create_domain("d1").await.unwrap();
            let server = start_server(Arc::clone(&registry), 4096).await;

            let mut stream = UnixStream::connect(&server.sock).await.unwrap();
            let (reply, doorbell) = register_with_doorbell(&mut stream).await;
            assert!(reply.starts_with("OK "), "{reply:?}");
            let mut client = ClientRings::open(&reply);

            let put = ShmCommand::Put {
                request_id: 1,
                domain: "d1".into(),
                key: "clé".into(),
                value: b"v".to_vec(),
                ttl_secs: 0,
            };
            client.tx.send(put.encode().as_slice()).unwrap();
            ring(&doorbell);
            assert_eq!(recv_response(&mut client.rx).await, ShmResponse::Ok { request_id: 1 });

            let get = ShmCommand::Get { request_id: 2, domain: "d1".into(), key: "clé".into() };
            client.tx.send(get.encode().as_slice()).unwrap();
            ring(&doorbell);
            assert_eq!(
                recv_response(&mut client.rx).await,
                ShmResponse::GetOk { request_id: 2, value: ShmGetValue::Present(b"v".to_vec()) }
            );

            drop(client);
            drop(stream);
            server.stop().await;
        })
    }

    // Spec perf/014 test 4: the disconnect teardown closes the server's doorbell
    // fds, cycle after cycle. Counted per pipe: a plain fd count would include
    // the fds of tests running in parallel.
    #[test]
    fn test_disconnect_closes_doorbell_fd() {
        crate::core::engine_runtime::block_on(async {
            let (registry, _dir) = make_registry().await;
            let server = start_server(Arc::clone(&registry), 4096).await;

            for cycle in 0..3 {
                let mut stream = UnixStream::connect(&server.sock).await.unwrap();
                let (reply, doorbell) = register_with_doorbell(&mut stream).await;
                assert!(reply.starts_with("OK "), "{reply:?}");
                let link = pipe_link(&doorbell);
                assert!(fds_on_pipe(&link) >= 2, "cycle {cycle}: the server holds the doorbell while registered");

                drop(stream);
                let closed = poll_fds_on_pipe(&link, 1).await;
                assert!(closed, "cycle {cycle}: server doorbell fd left open after disconnect");
            }

            server.stop().await;
        })
    }
}
