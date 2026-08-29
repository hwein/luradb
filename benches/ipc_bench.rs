//! Integration benchmarks — spec perf/011.
//!
//! Scenarios A-D drive a real LuraDB server (child process) over TCP, UDS and
//! SHM (command ring + read snapshot). Scenarios E/F are in-process, no server.
//! `harness = false`: `main()` below drives Criterion (A, C, E, F) plus two
//! custom Instant-based loops (B throughput, D mixed p50/p95/p99/p999) that
//! Criterion isn't suited for. Results are written to `benches/results/latest.md`.

use axum::body::{to_bytes, Body};
use bytes::Bytes;
use criterion::{black_box, Criterion};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use luradb::core::storage_thread::{StorageThread, StorageThreadConfig};
use luradb::core::wal::WriteAheadLog;
use luradb::ipc::{
    DoubleMmapRegion, ReadOnlySegment, ReaderSlot, RingConsumer, RingProducer, RingbufferHeader,
    ShmCommand, ShmGetValue, ShmResponse, ShmSegment, ShmSnapshot, SnapshotGuard, StateHeader,
    READER_SLOT_OFFSET,
};
use luradb::storage::sstable::{SSTableBuilder, SSTableReader};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rkyv::{rancor, util::AlignedVec, Archived};
use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;

const BENCH_DOMAIN: &str = "bench";
const SEED_KEYS: usize = 10_000;
const VALUE_LEN: usize = 64;
const MIXED_DURATION: Duration = Duration::from_secs(10);
const MIXED_THREADS: usize = 4;
const MIXED_WRITE_FRACTION: f64 = 0.20;
/// Fixed seed for scenario D's per-thread RNG — reproducible runs (Finding 4).
const MIXED_RNG_SEED: u64 = 42;

// Spec perf/016 step 0 — multicore baseline (B1 contention, B2 scaling).
// `NOISE_DOMAIN` holds exactly as many keys as `bench`, so the noise operation
// costs the same in both B1 variants and only the *domain* differs.
const NOISE_DOMAIN: &str = "noisy";
const B1_DURATION: Duration = Duration::from_secs(10);
const B1_NOISE_CLIENTS: usize = 2;
const B2_DURATION: Duration = Duration::from_secs(5);
const B2_CLIENT_COUNTS: [usize; 4] = [1, 2, 4, 8];

// ── Criterion async glue (no "async_tokio" feature — see Cargo.toml comment) ──

#[derive(Clone, Copy)]
struct Rt<'a>(&'a Runtime);

impl<'a> criterion::async_executor::AsyncExecutor for Rt<'a> {
    fn block_on<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        self.0.block_on(future)
    }
}

// ── HTTP client: one hyper stack (client::conn::http1) for TCP and UDS ────────

async fn handshake1<S>(io: S) -> hyper::client::conn::http1::SendRequest<Body>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await.expect("http1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

struct HttpConn {
    sender: hyper::client::conn::http1::SendRequest<Body>,
    host: String,
}

impl HttpConn {
    async fn connect_tcp(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("tcp connect");
        let _ = stream.set_nodelay(true);
        Self { sender: handshake1(stream).await, host: addr.to_string() }
    }

    async fn connect_uds(path: &Path) -> Self {
        let stream = UnixStream::connect(path).await.expect("uds connect");
        Self { sender: handshake1(stream).await, host: "localhost".to_string() }
    }

    async fn send(&mut self, method: &str, path: &str, json: bool, body: Vec<u8>) -> (StatusCode, Bytes) {
        self.sender.ready().await.expect("connection not ready");
        let mut builder = Request::builder().method(method).uri(path).header("Host", self.host.as_str());
        if json {
            builder = builder.header("Content-Type", "application/json");
        }
        let body = if body.is_empty() { Body::empty() } else { Body::from(body) };
        let req = builder.body(body).expect("build request");
        let resp = self.sender.send_request(req).await.expect("send_request");
        let status = resp.status();
        let bytes = to_bytes(Body::new(resp.into_body()), usize::MAX).await.unwrap_or_default();
        (status, bytes)
    }

    async fn get(&mut self, path: &str) -> (StatusCode, Bytes) {
        self.send("GET", path, false, Vec::new()).await
    }

    async fn put(&mut self, path: &str, value: Vec<u8>) -> StatusCode {
        self.send("PUT", path, false, value).await.0
    }

    async fn post_json(&mut self, path: &str, body: Vec<u8>) -> StatusCode {
        self.send("POST", path, true, body).await.0
    }
}

async fn wait_health(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(stream) = TcpStream::connect(addr).await {
            let mut sender = handshake1(stream).await;
            if sender.ready().await.is_ok() {
                let req = Request::builder()
                    .method("GET")
                    .uri("/health")
                    .header("Host", "bench")
                    .body(Body::empty())
                    .unwrap();
                if let Ok(resp) = sender.send_request(req).await {
                    if resp.status().is_success() {
                        return true;
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── SHM command-ring client (mirrors the E2E test in ipc/registration.rs) ─────

struct ShmClient {
    tx: RingProducer,
    rx: RingConsumer,
    next_id: u64,
    /// Shared with this client's `ShmSnapshotClient`: the reader slot the server
    /// registered for us lives in this page (spec perf/012 §1).
    cmd_hdr: Arc<ShmSegment>,
    _segs: [ShmSegment; 3],
    /// Registration socket — MUST stay open for the dispatcher to keep this
    /// client's rings alive (EOF = disconnect = segments unlinked) and for the
    /// reader slot to stay registered (EOF = lease dropped).
    _keepalive: UnixStream,
}

impl ShmClient {
    async fn register(reg_sock: &str) -> Self {
        let mut stream = UnixStream::connect(reg_sock).await.expect("connect registration socket");
        stream.write_all(b"REGISTER\n").await.expect("write REGISTER");
        let mut line = String::new();
        {
            let mut reader = BufReader::new(&mut stream);
            reader.read_line(&mut line).await.expect("read registration reply");
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.first().copied(), Some("OK"), "registration failed: {line:?}");

        let cmd_seg = ShmSegment::open(parts[2]).expect("open cmd segment");
        let cmd_hdr_seg = Arc::new(ShmSegment::open(parts[3]).expect("open cmd_hdr segment"));
        let resp_seg = ShmSegment::open(parts[4]).expect("open resp segment");
        let resp_hdr_seg = ShmSegment::open(parts[5]).expect("open resp_hdr segment");

        // Safe: header segments are page-sized mappings from the server, the
        // data segments are sized to the registered ring_size, and this client
        // is the sole producer/consumer on its own quartet.
        let tx = unsafe {
            let h =
                RingbufferHeader::from_ptr(cmd_hdr_seg.as_ptr(), cmd_hdr_seg.len()) as *const RingbufferHeader;
            RingProducer::new(h, DoubleMmapRegion::new(cmd_seg.fd(), cmd_seg.len()).expect("map cmd"))
        };
        let rx = unsafe {
            let h =
                RingbufferHeader::from_ptr(resp_hdr_seg.as_ptr(), resp_hdr_seg.len()) as *const RingbufferHeader;
            RingConsumer::new(h, DoubleMmapRegion::new(resp_seg.fd(), resp_seg.len()).expect("map resp"))
        };

        Self {
            tx,
            rx,
            next_id: 1,
            cmd_hdr: cmd_hdr_seg,
            _segs: [cmd_seg, resp_seg, resp_hdr_seg],
            _keepalive: stream,
        }
    }

    /// Handle on the page holding this client's registered reader slot.
    fn cmd_hdr(&self) -> Arc<ShmSegment> {
        Arc::clone(&self.cmd_hdr)
    }

    fn call(&mut self, cmd: ShmCommand) -> ShmResponse {
        self.tx.send(cmd.encode().as_slice()).expect("ring send");
        // Bounded spin (Finding 5): a lost response or stuck dispatcher fails
        // loud instead of spinning the bench process at 100% CPU forever.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(raw) = self.rx.recv().expect("ring corrupt") {
                return ShmResponse::decode(&raw).expect("decode response");
            }
            assert!(Instant::now() < deadline, "ShmClient::call: no response within 5s (dispatcher hung?)");
            std::hint::spin_loop();
        }
    }

    fn get(&mut self, domain: &str, key: &[u8]) -> Option<Vec<u8>> {
        let id = self.next_id;
        self.next_id += 1;
        match self.call(ShmCommand::Get { request_id: id, domain: domain.to_string(), key: key.to_vec() }) {
            ShmResponse::GetOk { value: ShmGetValue::Present(v), .. } => Some(v),
            ShmResponse::GetOk { .. } => None,
            other => panic!("unexpected GET response: {other:?}"),
        }
    }

    fn put(&mut self, domain: &str, key: &[u8], value: &[u8]) {
        let id = self.next_id;
        self.next_id += 1;
        match self.call(ShmCommand::Put {
            request_id: id,
            domain: domain.to_string(),
            key: key.to_vec(),
            value: value.to_vec(),
            ttl_secs: 0,
        }) {
            ShmResponse::Ok { .. } => {}
            other => panic!("unexpected PUT response: {other:?}"),
        }
    }
}

// ── SHM snapshot client (mirrors the E2E test in ipc/snapshot.rs) ─────────────

/// The read path of a *registered* client: `state`/`data_a`/`data_b` mapped
/// `PROT_READ` (spec perf/012 §10), pinning through the reader slot in the
/// `cmd_hdr` page its `ShmClient` registered. A bench-local slot would be
/// invisible to the server's registry and would read unprotected.
struct ShmSnapshotClient {
    state: ReadOnlySegment,
    data_a: ReadOnlySegment,
    data_b: ReadOnlySegment,
    cmd_hdr: Arc<ShmSegment>,
}

impl ShmSnapshotClient {
    fn open(instance_id: &str, cmd_hdr: Arc<ShmSegment>) -> Self {
        let seg = |purpose: &str| {
            ShmSegment::open_readonly(&format!("/luradb_{instance_id}_{purpose}"))
                .unwrap_or_else(|e| panic!("open {purpose} segment read-only: {e}"))
        };
        Self { state: seg("state"), data_a: seg("data_a"), data_b: seg("data_b"), cmd_hdr }
    }

    fn header(&self) -> &StateHeader {
        // Safe: `state` is a live mapping >= StateHeader::SIZE (validated by the
        // server at startup) held for the lifetime of `self`.
        unsafe { StateHeader::from_ptr(self.state.as_ptr(), self.state.len()) }
    }

    fn slot(&self) -> &ReaderSlot {
        // Safe: the slot sits behind the ring header in the page `cmd_hdr` keeps
        // mapped for the lifetime of `self`.
        unsafe {
            ReaderSlot::from_ptr(
                self.cmd_hdr.as_ptr().add(READER_SLOT_OFFSET),
                self.cmd_hdr.len() - READER_SLOT_OFFSET,
            )
        }
    }

    fn bufs(&self) -> (&[u8], &[u8]) {
        // Safe: both are live mappings for the lifetime of `self`.
        unsafe {
            (
                std::slice::from_raw_parts(self.data_a.as_ptr(), self.data_a.len()),
                std::slice::from_raw_parts(self.data_b.as_ptr(), self.data_b.len()),
            )
        }
    }

    /// Zero-copy point lookup in the published snapshot. `None` on a miss, an
    /// unavailable snapshot, or a VLog-backed value (none exist in this bench —
    /// all values are 64 bytes, well under the inline threshold).
    fn get(&self, domain: &str, key: &[u8]) -> Option<Vec<u8>> {
        let (a, b) = self.bufs();
        let guard = SnapshotGuard::acquire(self.header(), self.slot(), a, b)?;
        let mut aligned: AlignedVec = AlignedVec::with_capacity(guard.data().len());
        aligned.extend_from_slice(guard.data());
        let archived =
            rkyv::access::<Archived<ShmSnapshot>, rancor::Error>(aligned.as_slice()).ok()?;
        let dom = archived.domains.iter().find(|d| d.name == domain)?;
        let idx = dom.entries.binary_search_by(|e| e.key.as_slice().cmp(key)).ok()?;
        let entry = &dom.entries[idx];
        if entry.is_vlog_pointer {
            return None;
        }
        Some(entry.value.to_vec())
    }
}

// ── Server lifecycle (child process) ──────────────────────────────────────────

struct BenchInstance {
    child: Child,
    pid: u32,
    tcp_addr: SocketAddr,
    uds_path: PathBuf,
    reg_sock_path: String,
    instance_id: String,
}

fn cleanup_tmp() {
    for p in [
        "/tmp/luradb_bench.wal",
        "/tmp/luradb_bench.vlog",
        "/tmp/luradb_bench.db",
        "/tmp/luradb_bench.sock",
        "/tmp/luradb_bench_reg.sock",
    ] {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_dir_all("/tmp/luradb_bench_sstables");
}

impl BenchInstance {
    fn start(rt: &Runtime, with_noise_domain: bool) -> Self {
        cleanup_tmp();
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/bench_config.toml");
        let log_path = "/tmp/luradb_bench_server.log";
        let log_out = std::fs::File::create(log_path).expect("create server log file");
        let log_err = log_out.try_clone().expect("clone log file handle");

        let child = Command::new(env!("CARGO_BIN_EXE_luradb"))
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::from(log_out))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn luradb server");
        let pid = child.id();
        let tcp_addr: SocketAddr = "127.0.0.1:3099".parse().unwrap();

        // Built before the health check so `Drop` guards the child if it fails
        // (Finding 1 — a panic here must not leak the server process).
        let instance = Self {
            child,
            pid,
            tcp_addr,
            uds_path: PathBuf::from("/tmp/luradb_bench.sock"),
            reg_sock_path: "/tmp/luradb_bench_reg.sock".to_string(),
            instance_id: "bench".to_string(),
        };

        let healthy = rt.block_on(wait_health(tcp_addr, Duration::from_secs(15)));
        assert!(healthy, "server did not become healthy within 15s — see {log_path}");

        rt.block_on(instance.seed(with_noise_domain));
        instance
    }

    async fn seed(&self, with_noise_domain: bool) {
        let mut admin = HttpConn::connect_tcp(self.tcp_addr).await;
        let status = admin.post_json("/store-api/domains", br#"{"name":"bench"}"#.to_vec()).await;
        assert_eq!(status, StatusCode::CREATED, "create bench domain");
        if with_noise_domain {
            let body = format!(r#"{{"name":"{NOISE_DOMAIN}"}}"#).into_bytes();
            let status = admin.post_json("/store-api/domains", body).await;
            assert_eq!(status, StatusCode::CREATED, "create noise domain");
        }

        let value = vec![b'v'; VALUE_LEN];
        let status = admin.put("/store-api/kv/bench/keys/bench_key", value.clone()).await;
        assert_eq!(status, StatusCode::OK, "seed bench_key");
        drop(admin);

        const SHARDS: usize = 8;
        let mut domains = vec![BENCH_DOMAIN];
        if with_noise_domain {
            domains.push(NOISE_DOMAIN);
        }
        let mut tasks = Vec::new();
        for domain in domains {
            for shard in 0..SHARDS {
                let addr = self.tcp_addr;
                let value = value.clone();
                tasks.push(tokio::spawn(async move {
                    let mut conn = HttpConn::connect_tcp(addr).await;
                    for i in (shard..SEED_KEYS).step_by(SHARDS) {
                        let path = format!("/store-api/kv/{domain}/keys/k{i:05}");
                        let status = conn.put(&path, value.clone()).await;
                        assert_eq!(status, StatusCode::OK, "seed put {domain}/k{i:05}");
                    }
                }));
            }
        }
        for t in tasks {
            t.await.expect("seed task panicked");
        }

        // Give the SHM snapshot publisher a chance to pick up the seed data —
        // scenario A's snapshot benchmark needs `bench_key` visible. Reading
        // needs a registration: the reader slot lives in the client's own
        // cmd_hdr page.
        let client = ShmClient::register(&self.reg_sock_path).await;
        let snap = ShmSnapshotClient::open(&self.instance_id, client.cmd_hdr());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if snap.get(BENCH_DOMAIN, b"bench_key").is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "SHM snapshot never picked up seed data");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn stop(mut self) {
        // Safe: `pid` names our own child process, kill(2) with SIGTERM only.
        unsafe { libc::kill(self.pid as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

impl Drop for BenchInstance {
    fn drop(&mut self) {
        // Finding 1: `std::process::Child` has no Drop of its own, so a panic
        // that skips `stop()` (failed health check, `assert!` in `seed()`, an
        // `.expect(...)` in a scenario) would otherwise leak the server process.
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// ── CPU accounting via /proc/<pid>/stat (no new dependency) ───────────────────

fn read_cpu_ticks(pid: u32) -> (u64, u64) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let Some(idx) = stat.rfind(')') else { return (0, 0) };
    let fields: Vec<&str> = stat[idx + 1..].split_whitespace().collect();
    let utime = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (utime, stime)
}

fn cpu_pct(before: (u64, u64), after: (u64, u64), elapsed: Duration) -> f64 {
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let cpu_secs = ((after.0.saturating_sub(before.0)) + (after.1.saturating_sub(before.1))) as f64 / clk_tck;
    cpu_secs / elapsed.as_secs_f64() * 100.0
}

// ── Scenario A: Point-Lookup Latency ──────────────────────────────────────────

fn scenario_a(c: &mut Criterion, rt: &Runtime, instance: &BenchInstance) {
    // Rc<RefCell<>>: an async closure returning a future that borrows a captured
    // variable can't satisfy FnMut (the future would "escape" the closure body).
    // Cloning the Rc into an `async move` block sidesteps that — cheap (refcount
    // bump only) next to a microseconds-scale GET/PUT.
    let tcp_conn = Rc::new(RefCell::new(rt.block_on(HttpConn::connect_tcp(instance.tcp_addr))));
    c.bench_function("bench_get_tcp", |b| {
        let conn = Rc::clone(&tcp_conn);
        b.to_async(Rt(rt)).iter(move || {
            let conn = Rc::clone(&conn);
            async move { black_box(conn.borrow_mut().get("/store-api/kv/bench/keys/bench_key").await) }
        });
    });

    let uds_conn = Rc::new(RefCell::new(rt.block_on(HttpConn::connect_uds(&instance.uds_path))));
    c.bench_function("bench_get_uds", |b| {
        let conn = Rc::clone(&uds_conn);
        b.to_async(Rt(rt)).iter(move || {
            let conn = Rc::clone(&conn);
            async move { black_box(conn.borrow_mut().get("/store-api/kv/bench/keys/bench_key").await) }
        });
    });

    let mut shm_client = rt.block_on(ShmClient::register(&instance.reg_sock_path));
    let snap_client = ShmSnapshotClient::open(&instance.instance_id, shm_client.cmd_hdr());
    c.bench_function("bench_get_shm_command", |b| {
        b.iter(|| black_box(shm_client.get(BENCH_DOMAIN, b"bench_key")));
    });

    c.bench_function("bench_get_shm_snapshot", |b| {
        b.iter(|| black_box(snap_client.get(BENCH_DOMAIN, b"bench_key")));
    });
}

// ── Scenario C: Write Latency ──────────────────────────────────────────────────

fn scenario_c(c: &mut Criterion, rt: &Runtime, instance: &BenchInstance) {
    let value = vec![b'w'; VALUE_LEN];

    let tcp_conn = Rc::new(RefCell::new(rt.block_on(HttpConn::connect_tcp(instance.tcp_addr))));
    let v = value.clone();
    c.bench_function("bench_put_tcp", |b| {
        let conn = Rc::clone(&tcp_conn);
        let v = v.clone();
        b.to_async(Rt(rt)).iter(move || {
            let conn = Rc::clone(&conn);
            let v = v.clone();
            async move { black_box(conn.borrow_mut().put("/store-api/kv/bench/keys/bench_write_key", v).await) }
        });
    });

    let uds_conn = Rc::new(RefCell::new(rt.block_on(HttpConn::connect_uds(&instance.uds_path))));
    let v = value.clone();
    c.bench_function("bench_put_uds", |b| {
        let conn = Rc::clone(&uds_conn);
        let v = v.clone();
        b.to_async(Rt(rt)).iter(move || {
            let conn = Rc::clone(&conn);
            let v = v.clone();
            async move { black_box(conn.borrow_mut().put("/store-api/kv/bench/keys/bench_write_key", v).await) }
        });
    });

    let mut shm_client = rt.block_on(ShmClient::register(&instance.reg_sock_path));
    c.bench_function("bench_put_shm", |b| {
        b.iter(|| shm_client.put(BENCH_DOMAIN, b"bench_write_key", &value));
    });
}

// ── Scenario B: Throughput (custom loop — 100k fixed ops, 4 workers) ──────────

fn scenario_b(rt: &Runtime, instance: &BenchInstance, filter: &Option<String>) -> Vec<(String, f64)> {
    const TOTAL_OPS: usize = 100_000;
    const THREADS: usize = 4;
    let per_thread = TOTAL_OPS / THREADS;
    let mut out = Vec::new();

    if wants(filter, "bench_throughput_tcp_4t") {
        let elapsed = rt.block_on(async {
            let mut conns = Vec::with_capacity(THREADS);
            for _ in 0..THREADS {
                conns.push(HttpConn::connect_tcp(instance.tcp_addr).await);
            }
            let start = Instant::now();
            let mut set = JoinSet::new();
            for mut conn in conns {
                set.spawn(async move {
                    for i in 0..per_thread {
                        let path = format!("/store-api/kv/bench/keys/k{:05}", i % SEED_KEYS);
                        black_box(conn.get(&path).await);
                    }
                });
            }
            while set.join_next().await.is_some() {}
            start.elapsed()
        });
        out.push(("bench_throughput_tcp_4t".to_string(), (per_thread * THREADS) as f64 / elapsed.as_secs_f64()));
    }

    if wants(filter, "bench_throughput_uds_4t") {
        let elapsed = rt.block_on(async {
            let mut conns = Vec::with_capacity(THREADS);
            for _ in 0..THREADS {
                conns.push(HttpConn::connect_uds(&instance.uds_path).await);
            }
            let start = Instant::now();
            let mut set = JoinSet::new();
            for mut conn in conns {
                set.spawn(async move {
                    for i in 0..per_thread {
                        let path = format!("/store-api/kv/bench/keys/k{:05}", i % SEED_KEYS);
                        black_box(conn.get(&path).await);
                    }
                });
            }
            while set.join_next().await.is_some() {}
            start.elapsed()
        });
        out.push(("bench_throughput_uds_4t".to_string(), (per_thread * THREADS) as f64 / elapsed.as_secs_f64()));
    }

    if wants(filter, "bench_throughput_shm_4t") {
        let instance_id = instance.instance_id.clone();
        // One registration per reader thread: each needs its own reader slot.
        let clients: Vec<ShmClient> =
            (0..THREADS).map(|_| rt.block_on(ShmClient::register(&instance.reg_sock_path))).collect();
        let start = Instant::now();
        std::thread::scope(|scope| {
            for (t, client) in clients.into_iter().enumerate() {
                let instance_id = instance_id.clone();
                scope.spawn(move || {
                    let snap = ShmSnapshotClient::open(&instance_id, client.cmd_hdr());
                    for i in 0..per_thread {
                        let key = format!("k{:05}", (i + t) % SEED_KEYS);
                        black_box(snap.get(BENCH_DOMAIN, key.as_bytes()));
                    }
                });
            }
        });
        let elapsed = start.elapsed();
        out.push(("bench_throughput_shm_4t".to_string(), (per_thread * THREADS) as f64 / elapsed.as_secs_f64()));
    }

    out
}

// ── Scenario D: Mixed Workload (custom loop — 80/20, p50/p95/p99/p999 + CPU) ──

struct MixedResult {
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    p999_us: f64,
    ops_per_sec: f64,
    cpu_pct: f64,
}

fn build_mixed_result(per_thread: Vec<Vec<u64>>, elapsed: Duration, cpu: f64) -> MixedResult {
    let mut all: Vec<u64> = per_thread.into_iter().flatten().collect();
    all.sort_unstable();
    let pct = |p: f64| -> f64 {
        if all.is_empty() {
            return 0.0;
        }
        let idx = ((p * all.len() as f64) as usize).min(all.len() - 1);
        all[idx] as f64 / 1000.0 // ns -> µs
    };
    MixedResult {
        p50_us: pct(0.50),
        p95_us: pct(0.95),
        p99_us: pct(0.99),
        p999_us: pct(0.999),
        ops_per_sec: all.len() as f64 / elapsed.as_secs_f64(),
        cpu_pct: cpu,
    }
}

fn run_mixed_tcp(rt: &Runtime, instance: &BenchInstance) -> MixedResult {
    let before = read_cpu_ticks(instance.pid);
    let t0 = Instant::now();
    let per_thread: Vec<Vec<u64>> = rt.block_on(async {
        let mut conns = Vec::with_capacity(MIXED_THREADS);
        for _ in 0..MIXED_THREADS {
            conns.push(HttpConn::connect_tcp(instance.tcp_addr).await);
        }
        let deadline = Instant::now() + MIXED_DURATION;
        let mut set = JoinSet::new();
        for (idx, mut conn) in conns.into_iter().enumerate() {
            set.spawn(async move {
                let mut rng = StdRng::seed_from_u64(MIXED_RNG_SEED + idx as u64);
                let value = vec![b'm'; VALUE_LEN];
                let mut lat = Vec::new();
                while Instant::now() < deadline {
                    let key = rng.gen_range(0..SEED_KEYS);
                    let write = rng.gen_bool(MIXED_WRITE_FRACTION);
                    let path = format!("/store-api/kv/bench/keys/k{key:05}");
                    let start = Instant::now();
                    if write {
                        conn.put(&path, value.clone()).await;
                    } else {
                        conn.get(&path).await;
                    }
                    lat.push(start.elapsed().as_nanos() as u64);
                }
                lat
            });
        }
        let mut all = Vec::new();
        while let Some(r) = set.join_next().await {
            all.push(r.expect("mixed tcp task panicked"));
        }
        all
    });
    let elapsed = t0.elapsed();
    let after = read_cpu_ticks(instance.pid);
    build_mixed_result(per_thread, elapsed, cpu_pct(before, after, elapsed))
}

fn run_mixed_uds(rt: &Runtime, instance: &BenchInstance) -> MixedResult {
    let before = read_cpu_ticks(instance.pid);
    let t0 = Instant::now();
    let per_thread: Vec<Vec<u64>> = rt.block_on(async {
        let mut conns = Vec::with_capacity(MIXED_THREADS);
        for _ in 0..MIXED_THREADS {
            conns.push(HttpConn::connect_uds(&instance.uds_path).await);
        }
        let deadline = Instant::now() + MIXED_DURATION;
        let mut set = JoinSet::new();
        for (idx, mut conn) in conns.into_iter().enumerate() {
            set.spawn(async move {
                let mut rng = StdRng::seed_from_u64(MIXED_RNG_SEED + idx as u64);
                let value = vec![b'm'; VALUE_LEN];
                let mut lat = Vec::new();
                while Instant::now() < deadline {
                    let key = rng.gen_range(0..SEED_KEYS);
                    let write = rng.gen_bool(MIXED_WRITE_FRACTION);
                    let path = format!("/store-api/kv/bench/keys/k{key:05}");
                    let start = Instant::now();
                    if write {
                        conn.put(&path, value.clone()).await;
                    } else {
                        conn.get(&path).await;
                    }
                    lat.push(start.elapsed().as_nanos() as u64);
                }
                lat
            });
        }
        let mut all = Vec::new();
        while let Some(r) = set.join_next().await {
            all.push(r.expect("mixed uds task panicked"));
        }
        all
    });
    let elapsed = t0.elapsed();
    let after = read_cpu_ticks(instance.pid);
    build_mixed_result(per_thread, elapsed, cpu_pct(before, after, elapsed))
}

/// SHM mixed workload: GET via the snapshot path, PUT via the command ring —
/// how a real SHM client would actually be used (fast read path, only writes
/// need the ring round-trip).
fn run_mixed_shm(rt: &Runtime, instance: &BenchInstance) -> MixedResult {
    let clients: Vec<ShmClient> =
        (0..MIXED_THREADS).map(|_| rt.block_on(ShmClient::register(&instance.reg_sock_path))).collect();
    let instance_id = instance.instance_id.clone();

    let before = read_cpu_ticks(instance.pid);
    let t0 = Instant::now();
    let deadline = t0 + MIXED_DURATION;
    let per_thread: Vec<Vec<u64>> = std::thread::scope(|scope| {
        let handles: Vec<_> = clients
            .into_iter()
            .enumerate()
            .map(|(idx, mut client)| {
                let instance_id = instance_id.clone();
                let cmd_hdr = client.cmd_hdr();
                scope.spawn(move || {
                    let mut rng = StdRng::seed_from_u64(MIXED_RNG_SEED + idx as u64);
                    let snap = ShmSnapshotClient::open(&instance_id, cmd_hdr);
                    let value = vec![b'm'; VALUE_LEN];
                    let mut lat = Vec::new();
                    while Instant::now() < deadline {
                        let key = rng.gen_range(0..SEED_KEYS);
                        let write = rng.gen_bool(MIXED_WRITE_FRACTION);
                        let k = format!("k{key:05}");
                        let start = Instant::now();
                        if write {
                            client.put(BENCH_DOMAIN, k.as_bytes(), &value);
                        } else {
                            black_box(snap.get(BENCH_DOMAIN, k.as_bytes()));
                        }
                        lat.push(start.elapsed().as_nanos() as u64);
                    }
                    lat
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("mixed shm thread panicked")).collect()
    });
    let elapsed = t0.elapsed();
    let after = read_cpu_ticks(instance.pid);
    build_mixed_result(per_thread, elapsed, cpu_pct(before, after, elapsed))
}

fn scenario_d(rt: &Runtime, instance: &BenchInstance, filter: &Option<String>) -> Vec<(String, MixedResult)> {
    let mut out = Vec::new();
    if wants(filter, "bench_mixed_tcp") {
        out.push(("bench_mixed_tcp".to_string(), run_mixed_tcp(rt, instance)));
    }
    if wants(filter, "bench_mixed_uds") {
        out.push(("bench_mixed_uds".to_string(), run_mixed_uds(rt, instance)));
    }
    if wants(filter, "bench_mixed_shm") {
        out.push(("bench_mixed_shm".to_string(), run_mixed_shm(rt, instance)));
    }
    out
}

// ── Scenario B1/B2: multicore baseline (spec perf/016 step 0) ─────────────────
//
// B1 measures how much a legitimate CPU-heavy operation delays small GETs. The
// noise operation is a full-domain `scan_keys` with a substring filter that
// matches nothing: it materializes every key of the domain server-side and
// returns an almost empty body, so the cost is CPU inside the server, not
// transfer. Two variants, same cost, different domain — that separates the
// contention a domain-sharded server would remove (noise in *another* domain)
// from the contention it would not (noise in the *same* domain).

struct LoadStats {
    p50_us: f64,
    p99_us: f64,
    p999_us: f64,
    ops_per_sec: f64,
    /// Server-process CPU over the run — 100% means one core fully busy.
    cpu_pct: f64,
    noise_ops: usize,
}

fn build_load_stats(mut lat: Vec<u64>, elapsed: Duration, cpu_pct: f64, noise_ops: usize) -> LoadStats {
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        if lat.is_empty() {
            return 0.0;
        }
        let idx = ((p * lat.len() as f64) as usize).min(lat.len() - 1);
        lat[idx] as f64 / 1000.0 // ns -> µs
    };
    LoadStats {
        p50_us: pct(0.50),
        p99_us: pct(0.99),
        p999_us: pct(0.999),
        ops_per_sec: lat.len() as f64 / elapsed.as_secs_f64(),
        cpu_pct,
        noise_ops,
    }
}

fn run_b1(rt: &Runtime, instance: &BenchInstance, noise_domain: Option<&str>) -> LoadStats {
    let addr = instance.tcp_addr;
    let noise_domain = noise_domain.map(str::to_string);
    let cpu_before = read_cpu_ticks(instance.pid);
    let wall = Instant::now();
    let stats = rt.block_on(async move {
        let deadline = Instant::now() + B1_DURATION;
        let noise_ops = Arc::new(AtomicUsize::new(0));
        let mut noise_tasks = JoinSet::new();
        if let Some(domain) = noise_domain {
            for _ in 0..B1_NOISE_CLIENTS {
                let counter = Arc::clone(&noise_ops);
                let path = format!("/store-api/kv/{domain}/keys?contains=zzzz&limit=1");
                noise_tasks.spawn(async move {
                    let mut conn = HttpConn::connect_tcp(addr).await;
                    while Instant::now() < deadline {
                        let (status, _) = conn.get(&path).await;
                        assert_eq!(status, StatusCode::OK, "b1 noise scan");
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }

        let mut conn = HttpConn::connect_tcp(addr).await;
        let mut lat = Vec::new();
        let start = Instant::now();
        while Instant::now() < deadline {
            let t = Instant::now();
            let (status, _) = conn.get("/store-api/kv/bench/keys/bench_key").await;
            assert_eq!(status, StatusCode::OK, "b1 foreground get");
            lat.push(t.elapsed().as_nanos() as u64);
        }
        let elapsed = start.elapsed();
        while noise_tasks.join_next().await.is_some() {}
        (lat, elapsed, noise_ops.load(Ordering::Relaxed))
    });
    let wall = wall.elapsed();
    let cpu = cpu_pct(cpu_before, read_cpu_ticks(instance.pid), wall);
    build_load_stats(stats.0, stats.1, cpu, stats.2)
}

fn scenario_b1(rt: &Runtime, instance: &BenchInstance, filter: &Option<String>) -> Vec<(String, LoadStats)> {
    let mut out = Vec::new();
    if wants(filter, "bench_b1_quiet") {
        out.push(("bench_b1_quiet".to_string(), run_b1(rt, instance, None)));
    }
    if wants(filter, "bench_b1_noise_other_domain") {
        out.push(("bench_b1_noise_other_domain".to_string(), run_b1(rt, instance, Some(NOISE_DOMAIN))));
    }
    if wants(filter, "bench_b1_noise_same_domain") {
        out.push(("bench_b1_noise_same_domain".to_string(), run_b1(rt, instance, Some(BENCH_DOMAIN))));
    }
    out
}

fn run_b2(rt: &Runtime, instance: &BenchInstance, clients: usize, write_fraction: f64) -> LoadStats {
    let addr = instance.tcp_addr;
    let cpu_before = read_cpu_ticks(instance.pid);
    let wall = Instant::now();
    let stats = rt.block_on(async move {
        let mut conns = Vec::with_capacity(clients);
        for _ in 0..clients {
            conns.push(HttpConn::connect_tcp(addr).await);
        }
        let deadline = Instant::now() + B2_DURATION;
        let start = Instant::now();
        let mut set = JoinSet::new();
        for (idx, mut conn) in conns.into_iter().enumerate() {
            set.spawn(async move {
                let mut rng = StdRng::seed_from_u64(MIXED_RNG_SEED + idx as u64);
                let value = vec![b'b'; VALUE_LEN];
                let mut lat = Vec::new();
                while Instant::now() < deadline {
                    let key = rng.gen_range(0..SEED_KEYS);
                    let write = write_fraction > 0.0 && rng.gen_bool(write_fraction);
                    let path = format!("/store-api/kv/bench/keys/k{key:05}");
                    let t = Instant::now();
                    if write {
                        conn.put(&path, value.clone()).await;
                    } else {
                        conn.get(&path).await;
                    }
                    lat.push(t.elapsed().as_nanos() as u64);
                }
                lat
            });
        }
        let mut all = Vec::new();
        while let Some(r) = set.join_next().await {
            all.extend(r.expect("b2 task panicked"));
        }
        (all, start.elapsed())
    });
    let wall = wall.elapsed();
    let cpu = cpu_pct(cpu_before, read_cpu_ticks(instance.pid), wall);
    build_load_stats(stats.0, stats.1, cpu, 0)
}

/// Two profiles: `read` is CPU-bound (no fsync in the path) and shows how far
/// the request path itself scales; `mixed` keeps the 80/20 write share, where
/// group commit — not core parallelism — drives most of the gain.
fn scenario_b2(
    rt: &Runtime,
    instance: &BenchInstance,
    filter: &Option<String>,
) -> Vec<(&'static str, usize, LoadStats)> {
    let mut out = Vec::new();
    for (profile, write_fraction) in [("read", 0.0), ("mixed", MIXED_WRITE_FRACTION)] {
        for clients in B2_CLIENT_COUNTS {
            if wants(filter, &format!("bench_b2_{profile}_{clients}c")) {
                out.push((profile, clients, run_b2(rt, instance, clients, write_fraction)));
            }
        }
    }
    out
}

// ── Scenario E: WAL Write Latency (in-process, no server) ─────────────────────

fn scenario_e(c: &mut Criterion, rt: &Runtime) {
    let data = vec![b'e'; VALUE_LEN];

    let dir_tokio = tempfile::TempDir::new().unwrap();
    let wal_tokio = Rc::new(rt.block_on(WriteAheadLog::new(dir_tokio.path().join("wal"))).unwrap());
    c.bench_function("bench_wal_append_tokio", |b| {
        let wal = Rc::clone(&wal_tokio);
        let d = data.clone();
        b.to_async(Rt(rt)).iter(move || {
            let wal = Rc::clone(&wal);
            let d = d.clone();
            async move { black_box(wal.append(&d).await.unwrap()) }
        });
    });

    let dir_io = tempfile::TempDir::new().unwrap();
    let st_config = StorageThreadConfig {
        sqpoll_enabled: true,
        sqpoll_idle_ms: 500,
        ring_depth: 256,
        channel_capacity: 1024,
        cpu: -1,
    };
    let (mut storage_thread, handle) =
        StorageThread::new(st_config, dir_io.path().join("wal"), dir_io.path().join("vlog"))
            .expect("start storage thread");
    let wal_io = Rc::new(WriteAheadLog::with_storage_handle(handle));
    c.bench_function("bench_wal_append_iouring", |b| {
        let wal = Rc::clone(&wal_io);
        let d = data.clone();
        b.to_async(Rt(rt)).iter(move || {
            let wal = Rc::clone(&wal);
            let d = d.clone();
            async move { black_box(wal.append(&d).await.unwrap()) }
        });
    });
    drop(wal_io);
    storage_thread.shutdown();
}

// ── Scenario F: SSTable Read Latency (in-process, no server) ──────────────────

fn build_test_sstable(n: usize) -> Vec<u8> {
    let mut builder = SSTableBuilder::new();
    for i in 0..n {
        builder.add_inline(format!("key{i:06}").into_bytes(), vec![b'f'; VALUE_LEN], 0);
    }
    builder.finish().expect("build test sstable")
}

fn scenario_f(c: &mut Criterion) {
    const N: usize = 5000;
    let bytes = build_test_sstable(N);
    let lookup_key = b"key002500";

    let reader_vec = SSTableReader::open(bytes.clone()).expect("open aligned-vec sstable");
    c.bench_function("bench_sstable_read_aligned_vec", |b| {
        b.iter(|| black_box(reader_vec.get(black_box(lookup_key)).unwrap()));
    });

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bench.sst");
    std::fs::write(&path, &bytes).unwrap();
    let reader_mmap = SSTableReader::open_mmap(&path).expect("open mmap sstable");
    c.bench_function("bench_sstable_read_mmap", |b| {
        b.iter(|| black_box(reader_mmap.get(black_box(lookup_key)).unwrap()));
    });
}

// ── Reporting: benches/results/latest.md ──────────────────────────────────────

fn criterion_mean_ns(id: &str) -> Option<f64> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/criterion").join(id).join("new/estimates.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("mean")?.get("point_estimate")?.as_f64()
}

fn fmt_us(ns: Option<f64>) -> String {
    match ns {
        Some(v) => format!("{:.2} µs", v / 1000.0),
        None => "N/A".to_string(),
    }
}

fn fmt_ops(ops: Option<f64>) -> String {
    match ops {
        Some(v) if v >= 1_000_000.0 => format!("{:.2}M/s", v / 1_000_000.0),
        Some(v) if v >= 1_000.0 => format!("{:.1}k/s", v / 1_000.0),
        Some(v) => format!("{v:.0}/s"),
        None => "N/A".to_string(),
    }
}

fn write_report(
    throughput: &[(String, f64)],
    mixed: &[(String, MixedResult)],
    b1: &[(String, LoadStats)],
    b2: &[(&'static str, usize, LoadStats)],
    filter: &Option<String>,
) {
    let thr = |name: &str| throughput.iter().find(|(n, _)| n == name).map(|(_, v)| *v);
    let mix = |name: &str| mixed.iter().find(|(n, _)| n == name).map(|(_, v)| v);
    let mix_fmt = |name: &str, f: fn(&MixedResult) -> String| mix(name).map(f).unwrap_or_else(|| "N/A".to_string());
    // Finding 2: a filtered run must not report stale on-disk estimates.json
    // data for ids it didn't measure this time under a fresh "Generated" stamp.
    let crit_mean =
        |id: &str| if wants(filter, id) { fmt_us(criterion_mean_ns(id)) } else { "N/A (not run)".to_string() };

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let mut md = String::new();
    md.push_str("# LuraDB IPC Benchmark Results (spec perf/011)\n\n");
    md.push_str(&format!("Generated: unix timestamp {now}\n\n"));

    md.push_str("## GET / PUT Latency + Throughput\n\n");
    md.push_str("| Scenario | TCP | UDS | SHM Cmd | SHM Snap |\n");
    md.push_str("|---|---|---|---|---|\n");
    md.push_str(&format!(
        "| GET Latency (mean, A) | {} | {} | {} | {} |\n",
        crit_mean("bench_get_tcp"),
        crit_mean("bench_get_uds"),
        crit_mean("bench_get_shm_command"),
        crit_mean("bench_get_shm_snapshot"),
    ));
    md.push_str(&format!(
        "| PUT Latency (mean, C) | {} | {} | {} | N/A |\n",
        crit_mean("bench_put_tcp"),
        crit_mean("bench_put_uds"),
        crit_mean("bench_put_shm"),
    ));
    md.push_str(&format!(
        "| GET Throughput 4T (B) | {} | {} | N/A | {} |\n",
        fmt_ops(thr("bench_throughput_tcp_4t")),
        fmt_ops(thr("bench_throughput_uds_4t")),
        fmt_ops(thr("bench_throughput_shm_4t")),
    ));

    md.push_str("\n## Mixed Workload — 80% GET / 20% PUT (D)\n\n");
    md.push_str(
        "SHM reads use the snapshot path, SHM writes use the command ring (how a real client would mix them).\n\n",
    );
    md.push_str("| Metric | TCP | UDS | SHM |\n");
    md.push_str("|---|---|---|---|\n");
    md.push_str(&format!(
        "| p50 | {} | {} | {} |\n",
        mix_fmt("bench_mixed_tcp", |m| format!("{:.2} µs", m.p50_us)),
        mix_fmt("bench_mixed_uds", |m| format!("{:.2} µs", m.p50_us)),
        mix_fmt("bench_mixed_shm", |m| format!("{:.2} µs", m.p50_us)),
    ));
    md.push_str(&format!(
        "| p95 | {} | {} | {} |\n",
        mix_fmt("bench_mixed_tcp", |m| format!("{:.2} µs", m.p95_us)),
        mix_fmt("bench_mixed_uds", |m| format!("{:.2} µs", m.p95_us)),
        mix_fmt("bench_mixed_shm", |m| format!("{:.2} µs", m.p95_us)),
    ));
    md.push_str(&format!(
        "| p99 | {} | {} | {} |\n",
        mix_fmt("bench_mixed_tcp", |m| format!("{:.2} µs", m.p99_us)),
        mix_fmt("bench_mixed_uds", |m| format!("{:.2} µs", m.p99_us)),
        mix_fmt("bench_mixed_shm", |m| format!("{:.2} µs", m.p99_us)),
    ));
    md.push_str(&format!(
        "| p999 | {} | {} | {} |\n",
        mix_fmt("bench_mixed_tcp", |m| format!("{:.2} µs", m.p999_us)),
        mix_fmt("bench_mixed_uds", |m| format!("{:.2} µs", m.p999_us)),
        mix_fmt("bench_mixed_shm", |m| format!("{:.2} µs", m.p999_us)),
    ));
    md.push_str(&format!(
        "| ops/sec | {} | {} | {} |\n",
        mix_fmt("bench_mixed_tcp", |m| fmt_ops(Some(m.ops_per_sec))),
        mix_fmt("bench_mixed_uds", |m| fmt_ops(Some(m.ops_per_sec))),
        mix_fmt("bench_mixed_shm", |m| fmt_ops(Some(m.ops_per_sec))),
    ));
    md.push_str(&format!(
        "| CPU % (server) | {} | {} | {} |\n",
        mix_fmt("bench_mixed_tcp", |m| format!("{:.1}%", m.cpu_pct)),
        mix_fmt("bench_mixed_uds", |m| format!("{:.1}%", m.cpu_pct)),
        mix_fmt("bench_mixed_shm", |m| format!("{:.1}%", m.cpu_pct)),
    ));

    md.push_str("\n## io_uring Validation (E/F)\n\n");
    md.push_str("| Benchmark | Old Path | New Path |\n");
    md.push_str("|---|---|---|\n");
    md.push_str(&format!(
        "| WAL Append (tokio::fs vs. storage-thread SQPOLL) | {} | {} |\n",
        crit_mean("bench_wal_append_tokio"),
        crit_mean("bench_wal_append_iouring"),
    ));
    md.push_str(&format!(
        "| SSTable Read (AlignedVec vs. mmap) | {} | {} |\n",
        crit_mean("bench_sstable_read_aligned_vec"),
        crit_mean("bench_sstable_read_mmap"),
    ));

    if !b1.is_empty() {
        md.push_str("\n## B1 — Contention latency (spec perf/016 step 0)\n\n");
        md.push_str(
            "Small GETs on domain `bench`, measured while a full-domain scan (`contains` filter, \
             matches nothing) runs in parallel. Both noise variants scan an equally sized domain — \
             only the domain differs.\n\n",
        );
        md.push_str("| Run | p50 | p99 | p999 | GET ops/sec | server CPU | noise scans |\n");
        md.push_str("|---|---|---|---|---|---|---|\n");
        for (name, s) in b1 {
            md.push_str(&format!(
                "| {} | {:.2} µs | {:.2} µs | {:.2} µs | {} | {:.0}% | {} |\n",
                name,
                s.p50_us,
                s.p99_us,
                s.p999_us,
                fmt_ops(Some(s.ops_per_sec)),
                s.cpu_pct,
                s.noise_ops,
            ));
        }
    }

    if !b2.is_empty() {
        md.push_str("\n## B2 — Throughput scaling (spec perf/016 step 0)\n\n");
        md.push_str(
            "`read`: 100% GET (CPU-bound, no fsync in the path). \
             `mixed`: 80% GET / 20% PUT — its gain is dominated by group commit, not by cores.\n\n",
        );
        md.push_str("| Profile | Clients | ops/sec | scaling vs. 1 client | p50 | p99 | server CPU |\n");
        md.push_str("|---|---|---|---|---|---|---|\n");
        for (profile, clients, s) in b2 {
            let base =
                b2.iter().find(|(p, c, _)| p == profile && *c == 1).map(|(_, _, s)| s.ops_per_sec);
            let scale = match base {
                Some(b) if b > 0.0 => format!("{:.2}x", s.ops_per_sec / b),
                _ => "N/A".to_string(),
            };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {:.2} µs | {:.2} µs | {:.0}% |\n",
                profile,
                clients,
                fmt_ops(Some(s.ops_per_sec)),
                scale,
                s.p50_us,
                s.p99_us,
                s.cpu_pct,
            ));
        }
    }

    let out_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/results/latest.md");
    std::fs::create_dir_all(out_path.parent().unwrap()).ok();
    std::fs::write(&out_path, md).expect("write benches/results/latest.md");
    println!("Wrote {}", out_path.display());
}

// ── main: staged filtering (cargo bench -- <filter>) + orchestration ──────────

fn cli_filter() -> Option<String> {
    std::env::args().skip(1).find(|a| !a.starts_with('-'))
}

/// Matches a *concrete* benchmark id against the CLI filter — same semantics
/// as Criterion's own `id.contains(filter)`.
fn wants(filter: &Option<String>, name: &str) -> bool {
    match filter {
        None => true,
        Some(f) => name.contains(f.as_str()),
    }
}

/// Matches a *category prefix* (e.g. "bench_get") against the CLI filter.
/// Bidirectional: covers both a broad filter ("bench_get") and a filter more
/// specific than the prefix ("bench_get_tcp", which extends "bench_get").
fn category_wanted(filter: &Option<String>, prefix: &str) -> bool {
    match filter {
        None => true,
        Some(f) => f.contains(prefix) || prefix.contains(f.as_str()),
    }
}

fn main() {
    let filter = cli_filter();
    let rt = Runtime::new().expect("build tokio runtime");

    let need_b1 = category_wanted(&filter, "bench_b1");
    let need_server = ["bench_get", "bench_put", "bench_throughput", "bench_mixed", "bench_b1", "bench_b2"]
        .iter()
        .any(|s| category_wanted(&filter, s));
    let need_wal = category_wanted(&filter, "bench_wal_append");
    let need_sstable = category_wanted(&filter, "bench_sstable_read");

    let mut criterion = Criterion::default()
        .sample_size(15)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .configure_from_args();

    let mut throughput = Vec::new();
    let mut mixed = Vec::new();
    let mut b1 = Vec::new();
    let mut b2 = Vec::new();

    if need_server {
        let instance = BenchInstance::start(&rt, need_b1);
        // Finding 1: catch a scenario panic so `stop()` still runs the graceful
        // shutdown (not just Drop's hard-kill fallback), then keep failing the
        // run — cleanup must never turn a real failure into a green exit.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenario_a(&mut criterion, &rt, &instance);
            scenario_c(&mut criterion, &rt, &instance);
            let throughput = scenario_b(&rt, &instance, &filter);
            let mixed = scenario_d(&rt, &instance, &filter);
            let b1 = scenario_b1(&rt, &instance, &filter);
            let b2 = scenario_b2(&rt, &instance, &filter);
            (throughput, mixed, b1, b2)
        }));
        instance.stop();
        match outcome {
            Ok((t, m, s1, s2)) => {
                throughput = t;
                mixed = m;
                b1 = s1;
                b2 = s2;
            }
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    if need_wal {
        scenario_e(&mut criterion, &rt);
    }
    if need_sstable {
        scenario_f(&mut criterion);
    }

    criterion.final_summary();
    write_report(&throughput, &mixed, &b1, &b2, &filter);
}
