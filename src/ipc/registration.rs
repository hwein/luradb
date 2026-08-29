//! Multi-client registration listener (spec perf/008 Multi-Client).
//!
//! A dedicated UDS (separate from the perf/001 REST socket) hands each client
//! its own cmd/resp ring quartet. Wire format is newline-framed text:
//!
//! ```text
//!   request : REGISTER\n
//!   success : OK <client_id> <cmd> <cmd_hdr> <resp> <resp_hdr>\n
//!   failure : ERR <message>\n
//! ```
//!
//! Segment names never contain spaces, so the reply is a single space-split
//! line. After the reply the socket stays open purely for liveness: a read of
//! 0 bytes (EOF) or an error means the client is gone and its segments drop.
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
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};

const REGISTER_REQUEST: &str = "REGISTER";

/// What the listener needs to mint a client's segments.
pub struct RegistrationConfig {
    pub instance_id: String,
    /// Size of each per-client cmd/resp ring (= `command_buffer_size`).
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
    uds::prepare_uds_socket(path, None)
}

/// Accept loop: one task per connection, until `shutdown` flips. Returning drops
/// the `JoinSet`, aborting the still-open per-connection liveness waits.
pub async fn serve_registration(
    listener: UnixListener,
    config: RegistrationConfig,
    events: mpsc::UnboundedSender<ClientEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let config = Arc::new(config);
    let next_id = Arc::new(AtomicU64::new(1));
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next() => {} // reap finished handlers
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((s, _)) => s,
                    Err(e) => {
                        tracing::warn!("[shm-reg] accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let client_id = next_id.fetch_add(1, Ordering::Relaxed);
                conns.spawn(handle_connection(
                    stream,
                    client_id,
                    Arc::clone(&config),
                    events.clone(),
                    shutdown.clone(),
                ));
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
    let (conn, names, slot_handle) =
        match ClientConnection::create(&config.instance_id, client_id, config.ring_size, config.segment_mode) {
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

    // 6. Reply with the segment names.
    let reply = format!("OK {} {} {} {} {}\n", client_id, names[0], names[1], names[2], names[3]);
    if let Err(e) = write_half.write_all(reply.as_bytes()).await {
        tracing::warn!("[shm-reg] reply to client {client_id} failed: {e}");
        drop(lease);
        let _ = events.send(ClientEvent::Disconnect(client_id));
        return;
    }

    // 7. Keep the socket open; EOF/error = disconnect. Also stop on shutdown.
    let mut buf = [0u8; 32];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
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
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
        reg: tokio::task::JoinHandle<()>,
        disp: tokio::task::JoinHandle<()>,
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
        let disp = tokio::spawn(ShmDispatcher::new(registry).run(events_rx, sd_rx.clone()));
        let reg = tokio::spawn(serve_registration(
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
            tokio::time::sleep(Duration::from_millis(1)).await;
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
            tokio::time::sleep(Duration::from_millis(10)).await;
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
                    &*self.header,
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
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("no response within timeout");
    }

    // The reply names a client_id and the four segments, which now exist.
    #[tokio::test]
    async fn test_register_wire_format() {
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
    }

    // An unrecognised request is rejected and mints no segments.
    #[tokio::test]
    async fn test_unknown_request_rejected() {
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
    }

    // With auth on, a trusted UID (this process's own) registers normally.
    #[tokio::test]
    async fn test_auth_trusted_uid_registers() {
        let (registry, _dir) = make_registry().await;
        let uid = unsafe { libc::getuid() };
        let server = start_server_with_auth(Arc::clone(&registry), 4096, true, vec![uid]).await;

        let mut stream = UnixStream::connect(&server.sock).await.unwrap();
        let reply = register(&mut stream).await;
        assert!(reply.starts_with("OK"), "trusted uid should register: {reply:?}");

        drop(stream);
        server.stop().await;
    }

    // With auth on, an untrusted UID is refused and no segment is minted.
    #[tokio::test]
    async fn test_auth_untrusted_uid_rejected() {
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
    }

    // Spec perf/012 §7: the slot is in the registry before the client can read
    // the `OK` (and therefore before it can pin), and EOF on the registration
    // socket reclaims it — the next publish onto the pinned buffer goes through
    // without the server ever writing into the client's page.
    #[tokio::test]
    async fn test_reader_slot_registered_before_reply_and_freed_on_eof() {
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
    }

    // Spec perf/012 test 7: a connection task cancelled at an `.await` (what the
    // shutdown path does when it drops the listener's JoinSet) never reaches the
    // code behind its EOF loop — only the lease's Drop frees the slot.
    #[tokio::test]
    async fn test_aborted_connection_task_releases_reader_slot() {
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
        let task = tokio::spawn(handle_connection(server_side, 5, config, events_tx, sd_rx));

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
        // the slot. Awaiting the aborted handle resolves once the task's future
        // — and with it the lease — has been dropped.
        task.abort();
        let _ = task.await;
        assert!(readers.snapshot().is_empty(), "cancelled task must release its lease");
        assert_eq!(arena.publish(b"reclaimed"), PublishOutcome::Published);
    }

    // Full loop: register, open the segments, drive Put+Get over the rings, then
    // disconnect and watch the segments get unlinked.
    #[tokio::test]
    async fn test_e2e_put_get_roundtrip_and_cleanup() {
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
    }
}
