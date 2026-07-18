//! Server-side command dispatcher (spec perf/008 §8 + Multi-Client).
//!
//! Owns one [`ClientConnection`] per registered client — each a cmd
//! `RingConsumer` plus a resp `RingProducer` over that client's shm quartet —
//! and polls them all in a single adaptive loop: no sleep while any ring yields
//! work, a short idle sleep once every ring is empty. New clients arrive over a
//! channel from the registration listener; a disconnect, or a corrupt cmd ring
//! from one client, drops just that connection (its `ClientShm` unlinks the
//! segments). Command semantics match the REST handlers in `api::kv`.

use super::commands::{ShmCommand, ShmResponse};
use super::ringbuffer::{
    DoubleMmapRegion, RingConsumer, RingCorrupt, RingProducer, RingSendError, RingbufferHeader,
};
use super::shm::ClientShm;
use crate::engines::lsm::{DomainRegistry, DomainStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Idle backoff between empty polls; skipped while commands keep arriving.
const POLL_IDLE_US: u64 = 10;
/// Response-ring-full backoff: brief bounded retries before dropping the
/// response (flow control is out of scope — spec Abgrenzung).
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
    /// names to hand back over the registration socket.
    pub fn create(
        instance_id: &str,
        client_id: u64,
        ring_size: usize,
        mode: u32,
    ) -> anyhow::Result<(Self, [String; 4])> {
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
        // an empty ring.
        let consumer = unsafe {
            let header = RingbufferHeader::from_ptr(cmd_hdr_ptr, cmd_hdr_len) as *const RingbufferHeader;
            RingConsumer::new(header, DoubleMmapRegion::new(cmd_fd, ring_size)?)
        };
        let producer = unsafe {
            let header = RingbufferHeader::from_ptr(resp_hdr_ptr, resp_hdr_len) as *const RingbufferHeader;
            RingProducer::new(header, DoubleMmapRegion::new(resp_fd, ring_size)?)
        };
        Ok((Self { client_id, consumer, producer, _shm: Some(shm) }, names))
    }

    /// Drains up to `DRAIN_BATCH` currently-available commands, dispatching each
    /// and writing its response, then returns so the dispatcher can serve other
    /// clients and re-check shutdown. `Err` = the cmd ring framing is corrupt
    /// (untrusted producer); the caller drops this client.
    async fn drain(&mut self, registry: &DomainRegistry) -> Result<usize, RingCorrupt> {
        let mut processed = 0;
        while processed < DRAIN_BATCH {
            let Some(raw) = self.consumer.recv()? else { break };
            let response = match ShmCommand::decode(&raw) {
                Ok(cmd) => execute(registry, cmd).await,
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
    /// control — spec Abgrenzung). A response too large for the ring is replaced
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
}

/// Polls every registered client's rings and dispatches their commands.
pub struct ShmDispatcher {
    clients: Vec<ClientConnection>,
    registry: Arc<DomainRegistry>,
}

impl ShmDispatcher {
    pub fn new(registry: Arc<DomainRegistry>) -> Self {
        Self { clients: Vec::new(), registry }
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
                // Every ring empty: idle for the poll interval (or wake early on
                // shutdown). New connect/disconnect events are absorbed by the
                // try_recv at the top of the next iteration.
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_micros(POLL_IDLE_US)) => {}
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
            match conn.drain(&self.registry).await {
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
/// function's cognitive complexity low (spec quality/003). No atomics here —
/// the ring atomics live in `respond`/`send_retrying`.
async fn execute(registry: &DomainRegistry, cmd: ShmCommand) -> ShmResponse {
    match cmd {
        ShmCommand::Ping { request_id } => ShmResponse::Pong { request_id },
        ShmCommand::Get { request_id, domain, key } => {
            handle_get(registry, request_id, domain, key).await
        }
        ShmCommand::Put { request_id, domain, key, value, ttl_secs } => {
            handle_put(registry, request_id, domain, key, value, ttl_secs).await
        }
        ShmCommand::Delete { request_id, domain, key } => {
            handle_delete(registry, request_id, domain, key).await
        }
        ShmCommand::ScanKeys { request_id, domain, prefix } => {
            handle_scan_keys(registry, request_id, domain, prefix).await
        }
    }
}

async fn handle_get(registry: &DomainRegistry, request_id: u64, domain: String, key: Vec<u8>) -> ShmResponse {
    let store = match resolve(registry, &domain, request_id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match store.get(&key).await {
        Ok(value) => ShmResponse::GetOk { request_id, value },
        Err(e) => error_response(request_id, e),
    }
}

async fn handle_put(
    registry: &DomainRegistry,
    request_id: u64,
    domain: String,
    key: Vec<u8>,
    value: Vec<u8>,
    ttl_secs: u64,
) -> ShmResponse {
    let store = match resolve(registry, &domain, request_id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let result = if ttl_secs == 0 {
        store.put(&key, &value).await
    } else {
        store.put_with_ttl(&key, &value, ttl_secs).await
    };
    match result {
        Ok(()) => ShmResponse::Ok { request_id },
        Err(e) => error_response(request_id, e),
    }
}

async fn handle_delete(registry: &DomainRegistry, request_id: u64, domain: String, key: Vec<u8>) -> ShmResponse {
    let store = match resolve(registry, &domain, request_id).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match store.delete(&key).await {
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
    /// stand-in for what the registration listener builds in production.
    fn raw_connection(client_id: u64, consumer: RingConsumer, producer: RingProducer) -> ClientConnection {
        ClientConnection { client_id, consumer, producer, _shm: None }
    }

    struct Harness {
        registry: Arc<DomainRegistry>,
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
        let (registry, dir) = make_registry().await;
        let (client_tx, server_rx, cd, ch) = ring_ends(ring);
        let (server_tx, client_rx, rd, rh) = ring_ends(ring);
        let conn = raw_connection(0, server_rx, server_tx);
        Harness { registry, conn, client_tx, client_rx, _dir: dir, _segs: [cd, ch, rd, rh] }
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
        h.conn.drain(&h.registry).await.unwrap();
        let raw = h.client_rx.recv().unwrap().expect("a response frame");
        ShmResponse::decode(&raw).unwrap()
    }

    // Ping is answered without touching the registry.
    #[tokio::test]
    async fn test_ping_pong() {
        let mut h = harness().await;
        let resp = send_and_dispatch(&mut h, ShmCommand::Ping { request_id: 7 }).await;
        assert_eq!(resp, ShmResponse::Pong { request_id: 7 });
    }

    // 8. GET command -> GetOk with the stored value on the response ring.
    #[tokio::test]
    async fn test_dispatch_get() {
        let mut h = harness().await;
        h.registry.create_domain("d1").await.unwrap();
        h.registry.store("d1").await.unwrap().put(b"k", b"v").await.unwrap();

        let resp = send_and_dispatch(
            &mut h,
            ShmCommand::Get { request_id: 1, domain: "d1".into(), key: b"k".to_vec() },
        )
        .await;
        assert_eq!(resp, ShmResponse::GetOk { request_id: 1, value: Some(b"v".to_vec()) });

        // Missing key -> GetOk { None }, not an error (spec §7).
        let resp = send_and_dispatch(
            &mut h,
            ShmCommand::Get { request_id: 2, domain: "d1".into(), key: b"absent".to_vec() },
        )
        .await;
        assert_eq!(resp, ShmResponse::GetOk { request_id: 2, value: None });
    }

    // 9. PUT command -> value lands in the engine, Ok response.
    #[tokio::test]
    async fn test_dispatch_put() {
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
        assert_eq!(stored, Some(b"pv".to_vec()));
    }

    // DELETE dispatch path: Ok, and the key is gone afterwards (spec quality/003
    // Vorarbeit — the Delete arm had no send_and_dispatch test).
    #[tokio::test]
    async fn test_dispatch_delete() {
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
        assert_eq!(stored, None, "deleted key must be absent");
    }

    // SCANKEYS dispatch path: ScanResult with the sorted prefix matches (spec
    // quality/003 Vorarbeit).
    #[tokio::test]
    async fn test_dispatch_scan_keys() {
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
    }

    // PUT with ttl_secs > 0 takes the put_with_ttl branch and answers Ok; the
    // value is stored (spec quality/003 Vorarbeit).
    #[tokio::test]
    async fn test_dispatch_put_with_ttl() {
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
        assert_eq!(stored, Some(b"tv".to_vec()));
    }

    // 10. Unknown domain -> Error with code 404.
    #[tokio::test]
    async fn test_dispatch_unknown_domain_is_404() {
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
    }

    // Well-framed but non-rkyv payload -> 400, and the ring keeps running.
    #[tokio::test]
    async fn test_malformed_payload_is_400() {
        let mut h = harness().await;
        h.client_tx.send(&[0xffu8, 0x00, 0x11, 0x22]).unwrap();
        h.conn.drain(&h.registry).await.unwrap();
        let raw = h.client_rx.recv().unwrap().expect("a response");
        match ShmResponse::decode(&raw).unwrap() {
            ShmResponse::Error { code, .. } => assert_eq!(code, 400),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // One drain processes at most DRAIN_BATCH commands, then returns so peers get
    // a turn and shutdown is re-checked — a client can't monopolize the runtime
    // thread by keeping its cmd ring full (Finding 1).
    #[tokio::test]
    async fn test_drain_is_bounded_per_call() {
        // A ring wide enough to hold more than one batch of queued pings.
        let mut h = harness_sized(65536).await;
        let total = (DRAIN_BATCH + 10) as u64;
        for i in 0..total {
            h.client_tx.send(ShmCommand::Ping { request_id: i }.encode().as_slice()).unwrap();
        }
        assert_eq!(h.conn.drain(&h.registry).await.unwrap(), DRAIN_BATCH, "first pass is capped");
        assert_eq!(h.conn.drain(&h.registry).await.unwrap(), 10, "remainder served next pass");
    }

    // A response too large for the resp ring becomes a 413 on the same
    // request_id, not a silent drop — the client must fail fast, not block
    // forever waiting for a response that can never fit (Finding 3).
    #[tokio::test]
    async fn test_oversized_response_is_413() {
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
    }

    // A corrupt cmd ring drops only that client; healthy peers keep serving.
    // Segments held via `_`-prefixed bindings live to scope end; the rings' Drop
    // never dereferences them, so drop order among them is irrelevant.
    #[tokio::test]
    async fn test_corrupt_ring_drops_only_that_client() {
        let (registry, _dir) = make_registry().await;
        let mut dispatcher = ShmDispatcher::new(Arc::clone(&registry));

        let (mut a_tx, a_server_rx, _acd, _ach) = ring_ends(4096);
        let (a_server_tx, mut a_rx, _ard, _arh) = ring_ends(4096);
        let (_b_tx, b_server_rx, _bcd, bch) = ring_ends(4096);
        let (b_server_tx, _b_rx, _brd, _brh) = ring_ends(4096);
        dispatcher.clients.push(raw_connection(1, a_server_rx, a_server_tx));
        dispatcher.clients.push(raw_connection(2, b_server_rx, b_server_tx));

        // A sends a valid Ping; B's cmd write index is corrupted past the ring.
        a_tx.send(ShmCommand::Ping { request_id: 1 }.encode().as_slice()).unwrap();
        let b_header = unsafe { &*(bch.seg.as_ptr() as *const RingbufferHeader) };
        b_header.write_idx.store(4096 * 2, Ordering::Release);

        dispatcher.poll_once().await;

        assert_eq!(dispatcher.clients.len(), 1, "only the corrupt client is removed");
        assert_eq!(dispatcher.clients[0].client_id, 1);
        let raw = a_rx.recv().unwrap().expect("A's response");
        assert_eq!(ShmResponse::decode(&raw).unwrap(), ShmResponse::Pong { request_id: 1 });
    }

    // Disconnect events remove exactly the named client.
    #[tokio::test]
    async fn test_disconnect_event_removes_client() {
        let (registry, _dir) = make_registry().await;
        let mut dispatcher = ShmDispatcher::new(Arc::clone(&registry));
        let (_tx, rx, _cd, _ch) = ring_ends(4096);
        let (tx2, _rx2, _rd, _rh) = ring_ends(4096);
        dispatcher.clients.push(raw_connection(42, rx, tx2));

        dispatcher.handle_event(ClientEvent::Disconnect(99)); // unknown id: no-op
        assert_eq!(dispatcher.clients.len(), 1);
        dispatcher.handle_event(ClientEvent::Disconnect(42));
        assert!(dispatcher.clients.is_empty());
    }

    // ── Spec general/007: UTF-8 key invariant ───────────────────────────────

    // Test 4: a "400 "-prefixed engine error maps to code 400 over SHM.
    #[test]
    fn http_code_maps_400_prefix() {
        assert_eq!(http_code("400 Bad Request: key must be valid UTF-8"), 400);
    }

    // Test 2: ShmCommand::Put with a non-UTF-8 key -> ShmResponse::Error { code: 400, .. }.
    #[tokio::test]
    async fn test_dispatch_put_non_utf8_key_is_400() {
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
    }
}
