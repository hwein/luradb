//! Server-side command dispatcher.
//!
//! Owns one [`ClientConnection`] per registered client — each a cmd
//! `RingConsumer` plus a resp `RingProducer` over that client's shm quartet —
//! and polls them all in a single adaptive loop: no pause while any ring yields
//! work; once every ring is empty it parks until a client rings its doorbell
//! pipe or the fallback tick expires. New clients arrive over a channel from
//! the registration listener; a disconnect, or a corrupt cmd ring from one
//! client, drops just that connection (its `ClientShm` unlinks the segments,
//! its doorbell fd closes). Command semantics match the REST handlers in
//! `api::kv`: reads run here against the engines of the shard that owns the
//! domain, writes on that shard's thread.

use super::commands::{ShmCommand, ShmGetValue, ShmResponse};
use super::protocol::{ReaderSlot, READER_SLOT_OFFSET};
use super::readers::ReaderSlotHandle;
use super::ringbuffer::{
    DoubleMmapRegion, RingConsumer, RingCorrupt, RingProducer, RingSendError, RingbufferHeader,
};
use super::shm::ClientShm;
use crate::control::{ControlPlane, KvWrite};
use crate::engines::lsm::{DomainRegistry, DomainStore, GetResult};
use std::any::Any;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{mpsc, watch, Notify};

/// Longest idle wait without a doorbell: serves clients that never ring theirs
/// and covers lost wakeups.
const FALLBACK_TICK: Duration = Duration::from_millis(1);
/// Reads of 4 KiB per doorbell drain: empties a full default-size pipe
/// (64 KiB), yet a client refilling it concurrently cannot pin the drain.
const DOORBELL_DRAIN_READS: usize = 16;
/// Response-ring-full backoff: brief bounded retries before dropping the
/// response (flow control is out of scope).
const RESPOND_RETRIES: usize = 8;
/// Max commands drained from one client per poll pass. Bounds the work a single
/// client can force before the dispatcher round-robins to its peers and `run`
/// re-checks shutdown/connect events — a client that keeps its cmd ring full
/// (e.g. a Ping flood) can no longer monopolize the single runtime thread.
const DRAIN_BATCH: usize = 64;

/// Terminal outcome of pushing a frame onto a ring after bounded retries.
enum SendOutcome {
    Sent,
    Full,
    TooLarge,
}

/// One registered client: the server ends of its two rings plus the shm quartet
/// backing them.
pub struct ClientConnection {
    pub client_id: u64,
    consumer: RingConsumer,
    producer: RingProducer,
    /// Read end of the pipe the client writes a byte to after each cmd-ring
    /// send; `None` once the client closed its write end.
    doorbell: Option<AsyncFd<OwnedFd>>,
    /// Declared last: the rings (mappings into these segments) must drop before
    /// `_shm` closes the fds and unlinks the names. `None` in unit tests that
    /// wire raw rings without a quartet.
    _shm: Option<ClientShm>,
}

/// Connect/disconnect notifications from the registration listener. The large
/// `Connect` payload is boxed so the channel moves a pointer, not the whole
/// connection.
pub enum ClientEvent {
    Connect(Box<ClientConnection>),
    Disconnect(u64),
}

impl ClientConnection {
    /// Creates the client's shm quartet and wires the server ends — a consumer
    /// on the cmd ring, a producer on the resp ring — returning the four segment
    /// names to hand back over the registration socket, the handle on the
    /// client's reader slot (carrying `kick`, the connection task's disconnect
    /// signal) and the doorbell pipe's write end to pass to the client.
    pub fn create(
        instance_id: &str,
        client_id: u64,
        ring_size: usize,
        mode: u32,
        kick: Arc<Notify>,
    ) -> anyhow::Result<(Self, [String; 4], ReaderSlotHandle, OwnedFd)> {
        let shm = ClientShm::create(instance_id, client_id, ring_size, mode)?;
        let names = shm.segment_names();
        // Copyable handles: no borrow of `shm` outlives these, so `shm` can move
        // into the struct while the rings keep raw pointers into its mappings.
        let (cmd_hdr_ptr, cmd_hdr_len, cmd_fd) =
            (shm.cmd_hdr().as_ptr(), shm.cmd_hdr().len(), shm.cmd().fd());
        let (resp_hdr_ptr, resp_hdr_len, resp_fd) =
            (shm.resp_hdr().as_ptr(), shm.resp_hdr().len(), shm.resp().fd());
        // Safe: `_shm` outlives the rings (field order); header ptrs are
        // 128-byte-aligned page starts; data fds are sized to `ring_size` (a
        // validated power-of-two page multiple). Fresh segments are zeroed, i.e.
        // an empty ring and both reader counters at 0.
        let consumer = unsafe {
            let header = RingbufferHeader::from_ptr(cmd_hdr_ptr, cmd_hdr_len) as *const RingbufferHeader;
            RingConsumer::new(header, DoubleMmapRegion::new(cmd_fd, ring_size)?)
        };
        let producer = unsafe {
            let header = RingbufferHeader::from_ptr(resp_hdr_ptr, resp_hdr_len) as *const RingbufferHeader;
            RingProducer::new(header, DoubleMmapRegion::new(resp_fd, ring_size)?)
        };
        // Safe: the slot sits behind the ring header in the same page, and the
        // `Arc` clone keeps that mapping alive for the handle's whole life.
        let slot_handle = unsafe {
            let slot = ReaderSlot::from_ptr(
                cmd_hdr_ptr.add(READER_SLOT_OFFSET),
                cmd_hdr_len - READER_SLOT_OFFSET,
            ) as *const ReaderSlot;
            ReaderSlotHandle::new(client_id, slot, shm.cmd_hdr_arc() as Arc<dyn Any + Send + Sync>, kick)
        };
        let (doorbell, client_doorbell) = new_doorbell()?;
        let conn = Self { client_id, consumer, producer, doorbell: Some(doorbell), _shm: Some(shm) };
        Ok((conn, names, slot_handle, client_doorbell))
    }

    /// Drains up to `DRAIN_BATCH` currently-available commands, dispatching each
    /// and writing its response, then returns so the dispatcher can serve other
    /// clients and re-check shutdown. `Err` = the cmd ring framing is corrupt
    /// (untrusted producer); the caller drops this client.
    async fn drain(&mut self, control: &ControlPlane) -> Result<usize, RingCorrupt> {
        let mut processed = 0;
        while processed < DRAIN_BATCH {
            let Some(raw) = self.consumer.recv()? else { break };
            let response = match ShmCommand::decode(&raw) {
                Ok(cmd) => execute(control, cmd).await,
                Err(e) => {
                    // Well-framed but invalid payload: reject just this message,
                    // keep the ring alive (request_id unknown).
                    tracing::warn!("dropping malformed SHM command: {e}");
                    ShmResponse::Error { request_id: 0, code: 400, message: "malformed command".to_string() }
                }
            };
            self.respond(response).await;
            processed += 1;
        }
        Ok(processed)
    }

    /// Enqueues a response. A full ring drops it after bounded retries (no flow
    /// control). A response too large for the ring is replaced
    /// by a small 413 on the same request_id, so the client fails fast instead of
    /// blocking forever on a response that can never arrive.
    async fn respond(&mut self, response: ShmResponse) {
        let request_id = response_request_id(&response);
        let bytes = response.encode();
        match self.send_retrying(bytes.as_slice()).await {
            SendOutcome::Sent => {}
            SendOutcome::Full => tracing::warn!(
                "dropping {}-byte SHM response: resp ring still full after {RESPOND_RETRIES} retries",
                bytes.len()
            ),
            SendOutcome::TooLarge => {
                let err = ShmResponse::Error {
                    request_id,
                    code: 413,
                    message: format!("response exceeds resp ring capacity ({} bytes)", bytes.len()),
                };
                let err_bytes = err.encode();
                if !matches!(self.send_retrying(err_bytes.as_slice()).await, SendOutcome::Sent) {
                    tracing::warn!("dropping 413 for SHM request {request_id}: resp ring unavailable");
                }
            }
        }
    }

    /// Pushes one encoded frame, yielding and retrying a bounded number of times
    /// while the ring is full. `TooLarge` can never be retried away.
    async fn send_retrying(&mut self, bytes: &[u8]) -> SendOutcome {
        for _ in 0..RESPOND_RETRIES {
            match self.producer.send(bytes) {
                Ok(()) => return SendOutcome::Sent,
                Err(RingSendError::Full { .. }) => tokio::task::yield_now().await,
                Err(RingSendError::TooLarge { .. }) => return SendOutcome::TooLarge,
            }
        }
        SendOutcome::Full
    }

    /// Whether the doorbell rang; if so, drains the pipe. Readiness is cleared
    /// before the pipe is read, so a ring racing the drain re-arms it. EOF (the
    /// client closed its end) or an error retires the doorbell: the fallback
    /// tick serves this client from then on.
    fn drain_doorbell(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(doorbell) = &self.doorbell else { return false };
        let Poll::Ready(Ok(mut guard)) = doorbell.poll_read_ready(cx) else {
            return false;
        };
        guard.clear_ready();
        let mut buf = [0u8; 4096];
        let mut retire = false;
        for _ in 0..DOORBELL_DRAIN_READS {
            // Safe: a read into a live local buffer of its own length.
            let n = unsafe { libc::read(doorbell.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                continue;
            }
            retire = n == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock;
            break;
        }
        if retire {
            self.doorbell = None;
        }
        true
    }
}

/// A fresh doorbell pipe: the read end registered with the runtime's I/O
/// driver, plus the write end for the client. The ends are separate open file
/// descriptions, so flags the client sets on its end never reach ours.
fn new_doorbell() -> std::io::Result<(AsyncFd<OwnedFd>, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    // Safe: pipe2 fills the live two-int array; on success both fds are new
    // and owned by nobody else.
    let (read_end, write_end) = unsafe {
        if libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
    };
    // Safe: the AsyncFd owns the open read end and never closes or replaces
    // it while registered, so its raw fd stays the same until drop.
    let read_end = unsafe { AsyncFd::register_with_interest(read_end, Interest::READABLE) }?;
    Ok((read_end, write_end))
}

/// Polls every registered client's rings and dispatches their commands.
pub struct ShmDispatcher {
    clients: Vec<ClientConnection>,
    control: Arc<ControlPlane>,
    /// `FALLBACK_TICK` outside tests.
    idle_tick: Duration,
}

impl ShmDispatcher {
    pub fn new(control: Arc<ControlPlane>) -> Self {
        Self { clients: Vec::new(), control, idle_tick: FALLBACK_TICK }
    }

    /// A tick out of reach leaves the doorbell as the only idle wakeup.
    #[cfg(test)]
    fn with_idle_tick(control: Arc<ControlPlane>, idle_tick: Duration) -> Self {
        Self { idle_tick, ..Self::new(control) }
    }

    /// Runs until `shutdown` flips. Consumes `self`, so returning drops every
    /// `ClientConnection` — unlinking all per-client segments.
    pub async fn run(
        mut self,
        mut events: mpsc::UnboundedReceiver<ClientEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        loop {
            while let Ok(ev) = events.try_recv() {
                self.handle_event(ev);
            }
            if *shutdown.borrow() {
                break;
            }

            if self.poll_once().await {
                // Single-threaded runtime: stay cooperative under a client that
                // never lets its ring go empty (e.g. a Ping flood).
                tokio::task::yield_now().await;
            } else {
                // Every ring empty: park until a doorbell rings, the fallback
                // tick expires or shutdown. Either way the next iteration polls
                // every ring, and its try_recv absorbs connect/disconnect events.
                let tick = self.idle_tick;
                let doorbells = std::future::poll_fn(|cx| self.poll_doorbells(cx));
                tokio::select! {
                    _ = compio::time::timeout(tick, doorbells) => {}
                    _ = shutdown.changed() => {}
                }
            }
        }
        tracing::info!("SHM command dispatcher stopped ({} client(s) dropped)", self.clients.len());
    }

    /// One poll pass over all clients. Returns whether any ring had work. A
    /// client whose cmd ring is corrupt is dropped (only that client).
    async fn poll_once(&mut self) -> bool {
        let mut any_work = false;
        let mut corrupt: Vec<u64> = Vec::new();
        for conn in &mut self.clients {
            match conn.drain(&self.control).await {
                Ok(0) => {}
                Ok(_) => any_work = true,
                Err(e) => {
                    tracing::warn!("dropping SHM client {} (corrupt cmd ring): {e}", conn.client_id);
                    corrupt.push(conn.client_id);
                }
            }
        }
        if !corrupt.is_empty() {
            self.clients.retain(|c| !corrupt.contains(&c.client_id));
        }
        any_work
    }

    /// Ready once any client's doorbell has rung, draining every one that
    /// did. `&mut self` keeps the awaiting future `Send`: the rings are `Send`
    /// but not `Sync`.
    fn poll_doorbells(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut rang = false;
        for conn in &mut self.clients {
            rang |= conn.drain_doorbell(cx);
        }
        if rang {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn handle_event(&mut self, ev: ClientEvent) {
        match ev {
            ClientEvent::Connect(conn) => {
                tracing::info!("SHM client {} registered", conn.client_id);
                self.clients.push(*conn);
            }
            ClientEvent::Disconnect(id) => {
                let before = self.clients.len();
                self.clients.retain(|c| c.client_id != id);
                if self.clients.len() != before {
                    tracing::info!("SHM client {id} disconnected");
                }
            }
        }
    }
}

/// Flat delegation: each command arm is a private async helper, keeping this
/// function's cognitive complexity low. No atomics here — the ring atomics
/// live in `respond`/`send_retrying`.
async fn execute(control: &ControlPlane, cmd: ShmCommand) -> ShmResponse {
    match cmd {
        ShmCommand::Ping { request_id } => ShmResponse::Pong { request_id },
        ShmCommand::Get { request_id, domain, key } => {
            handle_get(&control.owners_of(&domain).kv, request_id, domain, key).await
        }
        ShmCommand::Put { request_id, domain, key, value, ttl_secs } => {
            handle_write(control, request_id, domain, KvWrite::Put { key, value, ttl_secs }).await
        }
        ShmCommand::Delete { request_id, domain, key } => {
            handle_write(control, request_id, domain, KvWrite::Delete { key }).await
        }
        ShmCommand::SetNull { request_id, domain, key } => {
            handle_write(control, request_id, domain, KvWrite::SetNull { key }).await
        }
        ShmCommand::ScanKeys { request_id, domain, prefix } => {
            handle_scan_keys(&control.owners_of(&domain).kv, request_id, domain, prefix).await
        }
    }
}

async fn handle_get(registry: &DomainRegistry, request_id: u64, domain: String, key: Vec<u8>) -> ShmResponse {
    let store = match resolve(registry, &domain, request_id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match store.get(&key).await {
        Ok(result) => {
            let value = match result {
                GetResult::Present(v) => ShmGetValue::Present(v),
                GetResult::Null => ShmGetValue::Null,
                GetResult::Absent => ShmGetValue::Absent,
            };
            ShmResponse::GetOk { request_id, value }
        }
        Err(e) => error_response(request_id, e),
    }
}

async fn handle_write(control: &ControlPlane, request_id: u64, domain: String, write: KvWrite) -> ShmResponse {
    match control.write_kv(&domain, write).await {
        Ok(()) => ShmResponse::Ok { request_id },
        Err(e) => error_response(request_id, e),
    }
}

async fn handle_scan_keys(registry: &DomainRegistry, request_id: u64, domain: String, prefix: Vec<u8>) -> ShmResponse {
    let store = match resolve(registry, &domain, request_id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match store.scan_keys(&prefix).await {
        Ok(keys) => ShmResponse::ScanResult { request_id, keys },
        Err(e) => error_response(request_id, e),
    }
}

async fn resolve(
    registry: &DomainRegistry,
    domain: &str,
    request_id: u64,
) -> Result<DomainStore, ShmResponse> {
    registry.store(domain).await.map_err(|e| error_response(request_id, e))
}

fn error_response(request_id: u64, err: anyhow::Error) -> ShmResponse {
    let message = err.to_string();
    ShmResponse::Error { request_id, code: http_code(&message), message }
}

/// Pulls the `request_id` carried by every `ShmResponse` variant — needed for
/// the too-large fallback in `respond`.
fn response_request_id(r: &ShmResponse) -> u64 {
    match r {
        ShmResponse::GetOk { request_id, .. }
        | ShmResponse::Ok { request_id }
        | ShmResponse::ScanResult { request_id, .. }
        | ShmResponse::Pong { request_id }
        | ShmResponse::Error { request_id, .. } => *request_id,
    }
}

/// Maps the engine layer's `"<code> …"` message prefixes to HTTP-analog status
/// codes — same convention as `api::middleware::ApiError`.
fn http_code(msg: &str) -> u32 {
    if msg.starts_with("429") {
        429
    } else if msg.starts_with("410") {
        410
    } else if msg.starts_with("409") {
        409
    } else if msg.starts_with("404") {
        404
    } else if msg.starts_with("400") {
        400
    } else {
        500
    }
}

#[cfg(test)]
mod tests {
    use super::super::ringbuffer::{DoubleMmapRegion, RingbufferHeader};
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::ipc::ShmSegment;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::io::RawFd;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_name() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("/luradb_test_{}-{}-disp", std::process::id(), n)
    }

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
    }

    impl Drop for TestSeg {
        fn drop(&mut self) {
            if let Ok(c) = CString::new(self.name.as_str()) {
                unsafe { libc::shm_unlink(c.as_ptr()) };
            }
        }
    }

    /// Builds a producer/consumer pair sharing one fresh data + header segment.
    fn ring_ends(size: usize) -> (RingProducer, RingConsumer, TestSeg, TestSeg) {
        let data = TestSeg::new(size);
        let hdr = TestSeg::new(4096);
        let header = unsafe { RingbufferHeader::from_ptr(hdr.seg.as_ptr(), hdr.seg.len()) }
            as *const RingbufferHeader;
        let tx = unsafe { RingProducer::new(header, DoubleMmapRegion::new(data.fd(), size).unwrap()) };
        let rx = unsafe { RingConsumer::new(header, DoubleMmapRegion::new(data.fd(), size).unwrap()) };
        (tx, rx, data, hdr)
    }

    /// A server-side connection over raw rings (no `ClientShm`) — the unit-test
    /// stand-in for what the registration listener builds in production — plus
    /// the client's write end of its doorbell pipe.
    fn raw_connection(
        client_id: u64,
        consumer: RingConsumer,
        producer: RingProducer,
    ) -> (ClientConnection, OwnedFd) {
        let (doorbell, client_doorbell) = new_doorbell().unwrap();
        let conn = ClientConnection { client_id, consumer, producer, doorbell: Some(doorbell), _shm: None };
        (conn, client_doorbell)
    }

    struct Harness {
        registry: Arc<DomainRegistry>,
        control: Arc<ControlPlane>,
        conn: ClientConnection,
        client_tx: RingProducer,
        client_rx: RingConsumer,
        _dir: tempfile::TempDir,
        _segs: [TestSeg; 4],
    }

    async fn harness() -> Harness {
        harness_sized(4096).await
    }

    async fn harness_sized(ring: usize) -> Harness {
        let (control, registry, dir) = make_control().await;
        harness_over(control, registry, dir, ring)
    }

    /// A client connected to a dispatcher over `control`; `registry` is the
    /// one the test checks.
    fn harness_over(
        control: Arc<ControlPlane>,
        registry: Arc<DomainRegistry>,
        dir: tempfile::TempDir,
        ring: usize,
    ) -> Harness {
        let (client_tx, server_rx, cd, ch) = ring_ends(ring);
        let (server_tx, client_rx, rd, rh) = ring_ends(ring);
        let (conn, _) = raw_connection(0, server_rx, server_tx);
        Harness { registry, control, conn, client_tx, client_rx, _dir: dir, _segs: [cd, ch, rd, rh] }
    }

    /// A control plane over a single data shard with the registry returned.
    async fn make_control() -> (Arc<ControlPlane>, Arc<DomainRegistry>, tempfile::TempDir) {
        let (registry, dir) = make_registry().await;
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(64, 64));
        let (control, _) = crate::control::testing::start(dir.path(), Arc::clone(&registry), None, None, bus).await;
        (control, registry, dir)
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
            DomainRegistry::recover(
                engine,
                crate::engines::lsm::domain::DomainConfig::default(),
                metrics,
            )
            .await
            .unwrap(),
        );
        (registry, dir)
    }

    async fn send_and_dispatch(h: &mut Harness, cmd: ShmCommand) -> ShmResponse {
        h.client_tx.send(cmd.encode().as_slice()).unwrap();
        h.conn.drain(&h.control).await.unwrap();
        let raw = h.client_rx.recv().unwrap().expect("a response frame");
        ShmResponse::decode(&raw).unwrap()
    }

    // Ping is answered without touching the registry.
    #[test]
    fn test_ping_pong() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            let resp = send_and_dispatch(&mut h, ShmCommand::Ping { request_id: 7 }).await;
            assert_eq!(resp, ShmResponse::Pong { request_id: 7 });
        })
    }

    // 8. GET command -> GetOk with the stored value on the response ring.
    #[test]
    fn test_dispatch_get() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();
            h.registry.store("d1").await.unwrap().put(b"k", b"v").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Get { request_id: 1, domain: "d1".into(), key: b"k".to_vec() },
            )
            .await;
            assert_eq!(
                resp,
                ShmResponse::GetOk { request_id: 1, value: ShmGetValue::Present(b"v".to_vec()) }
            );

            // Missing key -> GetOk { Absent }, not an error.
            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Get { request_id: 2, domain: "d1".into(), key: b"absent".to_vec() },
            )
            .await;
            assert_eq!(resp, ShmResponse::GetOk { request_id: 2, value: ShmGetValue::Absent });
        })
    }

    // 9. PUT command -> value lands in the engine, Ok response.
    #[test]
    fn test_dispatch_put() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Put {
                    request_id: 5,
                    domain: "d1".into(),
                    key: b"pk".to_vec(),
                    value: b"pv".to_vec(),
                    ttl_secs: 0,
                },
            )
            .await;
            assert_eq!(resp, ShmResponse::Ok { request_id: 5 });

            let stored = h.registry.store("d1").await.unwrap().get(b"pk").await.unwrap();
            assert_eq!(stored, GetResult::Present(b"pv".to_vec()));
        })
    }

    // DELETE dispatch path: Ok, and the key is gone afterwards.
    #[test]
    fn test_dispatch_delete() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();
            h.registry.store("d1").await.unwrap().put(b"dk", b"dv").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Delete { request_id: 3, domain: "d1".into(), key: b"dk".to_vec() },
            )
            .await;
            assert_eq!(resp, ShmResponse::Ok { request_id: 3 });

            let stored = h.registry.store("d1").await.unwrap().get(b"dk").await.unwrap();
            assert_eq!(stored, GetResult::Absent, "deleted key must be absent");
        })
    }

    // SETNULL dispatch path: Ok, and a subsequent GET reports the
    // explicit Null state — distinct from both Present and Absent.
    #[test]
    fn test_dispatch_set_null_then_get_null() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();
            h.registry.store("d1").await.unwrap().put(b"nk", b"nv").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::SetNull { request_id: 8, domain: "d1".into(), key: b"nk".to_vec() },
            )
            .await;
            assert_eq!(resp, ShmResponse::Ok { request_id: 8 });

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Get { request_id: 9, domain: "d1".into(), key: b"nk".to_vec() },
            )
            .await;
            assert_eq!(resp, ShmResponse::GetOk { request_id: 9, value: ShmGetValue::Null });
        })
    }

    // SCANKEYS dispatch path: ScanResult with the sorted prefix matches.
    #[test]
    fn test_dispatch_scan_keys() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();
            let store = h.registry.store("d1").await.unwrap();
            store.put(b"user:1", b"a").await.unwrap();
            store.put(b"user:2", b"b").await.unwrap();
            store.put(b"other", b"c").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::ScanKeys { request_id: 4, domain: "d1".into(), prefix: b"user:".to_vec() },
            )
            .await;
            match resp {
                ShmResponse::ScanResult { request_id, keys } => {
                    assert_eq!(request_id, 4);
                    assert_eq!(keys, vec![b"user:1".to_vec(), b"user:2".to_vec()]);
                }
                other => panic!("expected ScanResult, got {other:?}"),
            }
        })
    }

    // PUT with ttl_secs > 0 takes the put_with_ttl branch and answers Ok; the
    // value is stored.
    #[test]
    fn test_dispatch_put_with_ttl() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Put {
                    request_id: 6,
                    domain: "d1".into(),
                    key: b"tk".to_vec(),
                    value: b"tv".to_vec(),
                    ttl_secs: 3600,
                },
            )
            .await;
            assert_eq!(resp, ShmResponse::Ok { request_id: 6 });

            let stored = h.registry.store("d1").await.unwrap().get(b"tk").await.unwrap();
            assert_eq!(stored, GetResult::Present(b"tv".to_vec()));
        })
    }

    // 10. Unknown domain -> Error with code 404.
    #[test]
    fn test_dispatch_unknown_domain_is_404() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Get { request_id: 9, domain: "nope".into(), key: b"k".to_vec() },
            )
            .await;
            match resp {
                ShmResponse::Error { request_id, code, .. } => {
                    assert_eq!(request_id, 9);
                    assert_eq!(code, 404);
                }
                other => panic!("expected Error, got {other:?}"),
            }
        })
    }

    // With two data shards, the commands for a domain of shard 1 write to and
    // read from that shard's engine; a domain nobody has answers 404 as before.
    #[test]
    fn test_commands_for_a_domain_of_shard_1_reach_its_engine() {
        use crate::core::storage_thread::{TestHub, WalTarget};
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = TestHub::start(&[(WalTarget::Kv, &dir.path().join("kv.wal"))]);
            let shards = crate::control::testing::kv_shards(dir.path(), &hub, 2, |_, _| {}).await;
            let registries: Vec<_> = shards.iter().map(|shard| Arc::clone(&shard.kv)).collect();
            let bus = Arc::new(crate::core::events::GlobalEventBus::new(64, 64));
            let (control, _) = crate::control::testing::start_shards(dir.path(), shards, bus).await;
            let name = crate::control::slots::domain_name_for_shard(1, 2, 25);
            control.create_domain(crate::control::Engine::Kv, &name, false).await.unwrap();
            let mut h = harness_over(control, Arc::clone(&registries[1]), dir, 4096);

            let put = ShmCommand::Put {
                request_id: 1,
                domain: name.clone(),
                key: b"k".to_vec(),
                value: "clé".as_bytes().to_vec(),
                ttl_secs: 0,
            };
            assert_eq!(send_and_dispatch(&mut h, put).await, ShmResponse::Ok { request_id: 1 });
            let stored = registries[1].store(&name).await.unwrap().get(b"k").await.unwrap();
            assert_eq!(stored, GetResult::Present("clé".as_bytes().to_vec()));
            assert!(registries[0].store(&name).await.is_err(), "shard 0 does not have the domain");

            let get = ShmCommand::Get { request_id: 2, domain: name.clone(), key: b"k".to_vec() };
            assert_eq!(
                send_and_dispatch(&mut h, get).await,
                ShmResponse::GetOk { request_id: 2, value: ShmGetValue::Present("clé".as_bytes().to_vec()) }
            );
            let scan = ShmCommand::ScanKeys { request_id: 3, domain: name.clone(), prefix: Vec::new() };
            assert_eq!(
                send_and_dispatch(&mut h, scan).await,
                ShmResponse::ScanResult { request_id: 3, keys: vec![b"k".to_vec()] }
            );
            for cmd in [
                ShmCommand::Get { request_id: 4, domain: "nope".into(), key: b"k".to_vec() },
                ShmCommand::Delete { request_id: 4, domain: "nope".into(), key: b"k".to_vec() },
            ] {
                match send_and_dispatch(&mut h, cmd).await {
                    ShmResponse::Error { request_id: 4, code: 404, .. } => {}
                    other => panic!("expected a 404, got {other:?}"),
                }
            }
        })
    }

    // Well-framed but non-rkyv payload -> 400, and the ring keeps running.
    #[test]
    fn test_malformed_payload_is_400() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.client_tx.send(&[0xffu8, 0x00, 0x11, 0x22]).unwrap();
            h.conn.drain(&h.control).await.unwrap();
            let raw = h.client_rx.recv().unwrap().expect("a response");
            match ShmResponse::decode(&raw).unwrap() {
                ShmResponse::Error { code, .. } => assert_eq!(code, 400),
                other => panic!("expected Error, got {other:?}"),
            }
        })
    }

    // One drain processes at most DRAIN_BATCH commands, then returns so peers get
    // a turn and shutdown is re-checked — a client can't monopolize the runtime
    // thread by keeping its cmd ring full (Finding 1).
    #[test]
    fn test_drain_is_bounded_per_call() {
        crate::core::engine_runtime::block_on(async {
            // A ring wide enough to hold more than one batch of queued pings.
            let mut h = harness_sized(65536).await;
            let total = (DRAIN_BATCH + 10) as u64;
            for i in 0..total {
                h.client_tx.send(ShmCommand::Ping { request_id: i }.encode().as_slice()).unwrap();
            }
            assert_eq!(h.conn.drain(&h.control).await.unwrap(), DRAIN_BATCH, "first pass is capped");
            assert_eq!(h.conn.drain(&h.control).await.unwrap(), 10, "remainder served next pass");
        })
    }

    // A response too large for the resp ring becomes a 413 on the same
    // request_id, not a silent drop — the client must fail fast, not block
    // forever waiting for a response that can never fit (Finding 3).
    #[test]
    fn test_oversized_response_is_413() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();
            // A value far larger than the 4096-byte resp ring: its GetOk can't fit.
            let big = vec![0xabu8; 8192];
            h.registry.store("d1").await.unwrap().put(b"k", &big).await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Get { request_id: 77, domain: "d1".into(), key: b"k".to_vec() },
            )
            .await;
            match resp {
                ShmResponse::Error { request_id, code, .. } => {
                    assert_eq!(request_id, 77);
                    assert_eq!(code, 413);
                }
                other => panic!("expected 413 Error, got {other:?}"),
            }
        })
    }

    // A corrupt cmd ring drops only that client; healthy peers keep serving.
    // Segments held via `_`-prefixed bindings live to scope end; the rings' Drop
    // never dereferences them, so drop order among them is irrelevant.
    #[test]
    fn test_corrupt_ring_drops_only_that_client() {
        crate::core::engine_runtime::block_on(async {
            let (control, _, _dir) = make_control().await;
            let mut dispatcher = ShmDispatcher::new(control);

            let (mut a_tx, a_server_rx, _acd, _ach) = ring_ends(4096);
            let (a_server_tx, mut a_rx, _ard, _arh) = ring_ends(4096);
            let (_b_tx, b_server_rx, _bcd, bch) = ring_ends(4096);
            let (b_server_tx, _b_rx, _brd, _brh) = ring_ends(4096);
            dispatcher.clients.push(raw_connection(1, a_server_rx, a_server_tx).0);
            dispatcher.clients.push(raw_connection(2, b_server_rx, b_server_tx).0);

            // A sends a valid Ping; B's cmd write index is corrupted past the ring.
            a_tx.send(ShmCommand::Ping { request_id: 1 }.encode().as_slice()).unwrap();
            let b_header = unsafe { &*(bch.seg.as_ptr() as *const RingbufferHeader) };
            b_header.write_idx.store(4096 * 2, Ordering::Release);

            dispatcher.poll_once().await;

            assert_eq!(dispatcher.clients.len(), 1, "only the corrupt client is removed");
            assert_eq!(dispatcher.clients[0].client_id, 1);
            let raw = a_rx.recv().unwrap().expect("A's response");
            assert_eq!(ShmResponse::decode(&raw).unwrap(), ShmResponse::Pong { request_id: 1 });
        })
    }

    // Disconnect events remove exactly the named client.
    #[test]
    fn test_disconnect_event_removes_client() {
        crate::core::engine_runtime::block_on(async {
            let (control, _, _dir) = make_control().await;
            let mut dispatcher = ShmDispatcher::new(control);
            let (_tx, rx, _cd, _ch) = ring_ends(4096);
            let (tx2, _rx2, _rd, _rh) = ring_ends(4096);
            dispatcher.clients.push(raw_connection(42, rx, tx2).0);

            dispatcher.handle_event(ClientEvent::Disconnect(99)); // unknown id: no-op
            assert_eq!(dispatcher.clients.len(), 1);
            dispatcher.handle_event(ClientEvent::Disconnect(42));
            assert!(dispatcher.clients.is_empty());
        })
    }

    /// What a doorbell-aware client does after each cmd-ring send.
    fn ring(doorbell: &OwnedFd) {
        // Safe: a 1-byte write from a live local to a pipe end we own.
        let n = unsafe { libc::write(doorbell.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        assert_eq!(n, 1, "doorbell write");
    }

    async fn await_response(rx: &mut RingConsumer) -> ShmResponse {
        for _ in 0..2000 {
            if let Some(raw) = rx.recv().unwrap() {
                return ShmResponse::decode(&raw).unwrap();
            }
            compio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("no response within timeout");
    }

    /// One client on a running dispatcher that has answered a first Ping and
    /// parked again, every ring empty.
    struct Parked {
        client_tx: RingProducer,
        client_rx: RingConsumer,
        doorbell: OwnedFd,
        shutdown: watch::Sender<bool>,
        task: compio::runtime::JoinHandle<()>,
        _segs: [TestSeg; 4],
    }

    async fn park(dispatcher: ShmDispatcher) -> Parked {
        let (client_tx, server_rx, cd, ch) = ring_ends(4096);
        let (server_tx, client_rx, rd, rh) = ring_ends(4096);
        let (conn, doorbell) = raw_connection(1, server_rx, server_tx);
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        assert!(events_tx.send(ClientEvent::Connect(Box::new(conn))).is_ok());
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = compio::runtime::spawn(dispatcher.run(events_rx, shutdown_rx));
        let mut p = Parked { client_tx, client_rx, doorbell, shutdown, task, _segs: [cd, ch, rd, rh] };
        // Queued before the dispatcher first runs: its first pass answers it.
        p.client_tx.send(ShmCommand::Ping { request_id: 1 }.encode().as_slice()).unwrap();
        assert_eq!(await_response(&mut p.client_rx).await, ShmResponse::Pong { request_id: 1 });
        p
    }

    impl Parked {
        async fn stop(self) {
            self.shutdown.send(true).unwrap();
            self.task.await.unwrap();
        }
    }

    // Test 1: with the fallback tick out of reach, ringing the doorbell alone
    // wakes the parked dispatcher.
    #[test]
    fn test_doorbell_wakes_idle_dispatcher() {
        crate::core::engine_runtime::block_on(async {
            let (control, _, _dir) = make_control().await;
            let mut p = park(ShmDispatcher::with_idle_tick(control, Duration::from_secs(3600))).await;

            p.client_tx.send(ShmCommand::Ping { request_id: 2 }.encode().as_slice()).unwrap();
            ring(&p.doorbell);
            assert_eq!(await_response(&mut p.client_rx).await, ShmResponse::Pong { request_id: 2 });

            p.stop().await;
        })
    }

    // Test 2: a client that never rings its doorbell (legacy client) is still
    // served by the production fallback tick.
    #[test]
    fn test_fallback_tick_serves_client_without_doorbell() {
        crate::core::engine_runtime::block_on(async {
            let (control, _, _dir) = make_control().await;
            let mut p = park(ShmDispatcher::new(control)).await;

            p.client_tx.send(ShmCommand::Ping { request_id: 2 }.encode().as_slice()).unwrap();
            assert_eq!(await_response(&mut p.client_rx).await, ShmResponse::Pong { request_id: 2 });

            p.stop().await;
        })
    }

    // A client that closes its doorbell is served by the fallback tick from
    // then on, and the dispatcher keeps running.
    #[test]
    fn test_closed_doorbell_falls_back_to_tick() {
        crate::core::engine_runtime::block_on(async {
            let (control, _, _dir) = make_control().await;
            let mut p = park(ShmDispatcher::new(control)).await;

            drop(p.doorbell);
            for request_id in 2..4 {
                p.client_tx.send(ShmCommand::Ping { request_id }.encode().as_slice()).unwrap();
                assert_eq!(await_response(&mut p.client_rx).await, ShmResponse::Pong { request_id });
            }

            p.shutdown.send(true).unwrap();
            p.task.await.unwrap();
        })
    }

    // A closed doorbell wakes the dispatcher once and is then retired: its
    // read end would report EOF forever and spin the idle wait.
    #[test]
    fn test_closed_doorbell_wakes_once() {
        crate::core::engine_runtime::block_on(async {
            let (control, _, _dir) = make_control().await;
            let mut dispatcher = ShmDispatcher::new(control);
            let (_tx, rx, _cd, _ch) = ring_ends(4096);
            let (tx2, _rx2, _rd, _rh) = ring_ends(4096);
            let (conn, doorbell) = raw_connection(1, rx, tx2);
            dispatcher.clients.push(conn);

            drop(doorbell);
            std::future::poll_fn(|cx| dispatcher.poll_doorbells(cx)).await;
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(dispatcher.poll_doorbells(&mut cx).is_pending(), "a retired doorbell must stay silent");
        })
    }

    // Test 4: a "400 "-prefixed engine error maps to code 400 over SHM.
    #[test]
    fn http_code_maps_400_prefix() {
        assert_eq!(http_code("400 Bad Request: key must be valid UTF-8"), 400);
    }

    // Test 2: ShmCommand::Put with a non-UTF-8 key -> ShmResponse::Error { code: 400, .. }.
    #[test]
    fn test_dispatch_put_non_utf8_key_is_400() {
        crate::core::engine_runtime::block_on(async {
            let mut h = harness().await;
            h.registry.create_domain("d1").await.unwrap();

            let resp = send_and_dispatch(
                &mut h,
                ShmCommand::Put {
                    request_id: 11,
                    domain: "d1".into(),
                    key: vec![0xFF, 0xFE],
                    value: b"v".to_vec(),
                    ttl_secs: 0,
                },
            )
            .await;
            match resp {
                ShmResponse::Error { request_id, code, .. } => {
                    assert_eq!(request_id, 11);
                    assert_eq!(code, 400);
                }
                other => panic!("expected 400 Error, got {other:?}"),
            }
        })
    }
}
