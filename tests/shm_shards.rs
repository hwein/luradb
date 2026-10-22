//! Two-process test of shared memory over two data shards.
//!
//! The parent runs a server with two data shards and shared memory on, and
//! puts a key into a domain on each shard over HTTP. The child is a re-exec
//! of this very test binary — `<bin> shm_shards_child --exact --ignored`,
//! addressed through env vars — that registers as a client, reads the
//! published snapshot and sends commands through its rings.
//!
//! Asserted: (a) the client sees the domains of both shards in one snapshot,
//! sorted by name across the shards, with their values, (b) a read command
//! for the domain of shard 1 returns its value, a write command lands in that
//! domain, and an unknown domain answers 404.

use luradb::config::LuraConfig;
use luradb::control::slots::shard_of_domain;
use luradb::ipc::{
    DoubleMmapRegion, ReaderSlot, RingConsumer, RingProducer, RingbufferHeader, ShmCommand, ShmGetValue,
    ShmResponse, ShmSegment, ShmSnapshot, SnapshotGuard, StateHeader, READER_SLOT_OFFSET,
};
use luradb::server::Server;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROLE_ENV: &str = "LURADB_SHM_SHARDS_ROLE";
const SOCK_ENV: &str = "LURADB_SHM_SHARDS_SOCK";
const INSTANCE_ENV: &str = "LURADB_SHM_SHARDS_INSTANCE";
const DOMAINS_ENV: &str = "LURADB_SHM_SHARDS_DOMAINS";

/// Budget for every wait in this test. No assertion here is about elapsed
/// time — only about the state being reached eventually.
const WAIT_BUDGET: Duration = Duration::from_secs(60);

const WRITTEN: &[u8] = b"from the client";

#[test]
fn a_client_sees_the_domains_of_both_shards_and_writes_through_their_owner() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sock = dir.path().join("shm.sock");
    let instance_id = format!("shm-shards-{}", std::process::id());
    let config = Arc::new(config(dir.path(), &instance_id, &sock));
    let server = Server::start(config, &dir.path().join("luradb.toml")).expect("server");
    let addr = server.http_addr.expect("HTTP listener enabled");

    // "a-…" on shard 1 sorts before "b-…" on shard 0 and "default", also on
    // shard 0: a list per shard, one after the other, would not be in order.
    assert_eq!(shard_of_domain("default", 2), 0);
    let domains = [name_on("a", 1), name_on("b", 0)];
    for name in &domains {
        let create = format!(r#"{{"name":"{name}"}}"#);
        assert_eq!(request(addr, "POST", "/store-api/domains", create.as_bytes()).0, 201);
        let value = format!("value of {name}");
        assert_eq!(request(addr, "PUT", &format!("/store-api/kv/{name}/keys/k"), value.as_bytes()).0, 200);
    }

    let mut child = ChildGuard(spawn_child(&sock, &instance_id, &domains));
    let status = child.wait().expect("the client never finished");
    assert!(status.success(), "the client failed: {status}");

    let (status, body) = request(addr, "GET", &format!("/store-api/kv/{}/keys/written", domains[0]), b"");
    assert_eq!((status, body.as_slice()), (200, WRITTEN));
    server.shutdown().expect("shutdown");
}

/// Two data shards, shared memory on, HTTP on an ephemeral loopback port,
/// every data path under `dir`.
fn config(dir: &Path, instance_id: &str, sock: &Path) -> LuraConfig {
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let mut cfg = LuraConfig::default();
    cfg.server.port = 0;
    cfg.storage.db_path = path("luradb.db");
    cfg.storage.wal_path = path("luradb.wal");
    cfg.storage.vlog_path = path("luradb.vlog");
    cfg.storage.sstable_dir = path("sstables");
    cfg.storage.system_dir = path("sys");
    cfg.json.enabled = false;
    cfg.rel.enabled = false;
    cfg.multicore.shards = 2;
    cfg.multicore.reader_threads = 2;
    cfg.shm.enabled = true;
    cfg.shm.instance_id = instance_id.to_string();
    cfg.shm.registration_socket_path = sock.to_string_lossy().into_owned();
    cfg.shm.data_buffer_size = 1 << 20;
    cfg.shm.snapshot_interval_ms = 10;
    cfg
}

/// The first name `<prefix>-<i>` that data shard `shard` of two owns.
fn name_on(prefix: &str, shard: u16) -> String {
    (0..).map(|i| format!("{prefix}-{i}")).find(|name| shard_of_domain(name, 2) == shard).expect("a name")
}

/// One HTTP/1.1 request on a fresh connection: status and body.
fn request(addr: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response head") + 4;
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let status = head[9..12].parse().expect("status code");
    let len = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .map_or(raw.len() - head_end, |value| value.trim().parse().expect("content length"));
    (status, raw[head_end..head_end + len].to_vec())
}

/// Kills the child on drop, so a failing assertion cannot leak the process.
struct ChildGuard(Child);

impl ChildGuard {
    /// Waits for the child to exit, retrying with a budget.
    fn wait(&mut self) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + WAIT_BUDGET;
        while Instant::now() < deadline {
            if let Some(status) = self.0.try_wait().expect("child status") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_child(sock: &Path, instance_id: &str, domains: &[String]) -> Child {
    let exe = std::env::current_exe().expect("current test binary");
    Command::new(exe)
        .args(["shm_shards_child", "--exact", "--ignored", "--nocapture"])
        .env(ROLE_ENV, "child")
        .env(SOCK_ENV, sock)
        .env(INSTANCE_ENV, instance_id)
        .env(DOMAINS_ENV, domains.join(","))
        // Drop the child's libtest progress lines, keep its stderr so a failed
        // assertion in the client role still surfaces in this test's output.
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn the client role of this test binary")
}

/// The client process of the test above. `#[ignore]`d and gated on
/// `ROLE_ENV`: a plain `cargo test -- --ignored` runs it as a no-op. A
/// failed assertion ends the process with a failure status.
#[test]
#[ignore]
fn shm_shards_child() {
    let Ok(role) = std::env::var(ROLE_ENV) else { return };
    assert_eq!(role, "child");
    let sock = std::env::var(SOCK_ENV).expect(SOCK_ENV);
    let instance_id = std::env::var(INSTANCE_ENV).expect(INSTANCE_ENV);
    let domains: Vec<String> = std::env::var(DOMAINS_ENV).expect(DOMAINS_ENV).split(',').map(String::from).collect();

    // Held to the end: its EOF would disconnect this client.
    let mut stream = std::os::unix::net::UnixStream::connect(&sock).expect("connect registration socket");
    stream.write_all(b"REGISTER\n").expect("write REGISTER");
    let mut line = String::new();
    BufReader::new(stream.try_clone().expect("clone socket")).read_line(&mut line).expect("read registration reply");
    let parts: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(parts.first().copied(), Some("OK"), "registration failed: {line:?}");
    let [cmd, cmd_hdr, resp, resp_hdr] =
        [2, 3, 4, 5].map(|i| ShmSegment::open(parts[i]).unwrap_or_else(|e| panic!("open {}: {e}", parts[i])));
    let seg = |purpose: &str| {
        ShmSegment::open_readonly(&format!("/luradb_{instance_id}_{purpose}"))
            .unwrap_or_else(|e| panic!("open {purpose} read-only: {e}"))
    };
    let (state, data_a, data_b) = (seg("state"), seg("data_a"), seg("data_b"));

    // Safe: every mapping lives until this process exits; the header
    // segments are page-sized, the data segments sized to their rings.
    let (header, slot, a, b, mut tx, mut rx) = unsafe {
        (
            StateHeader::from_ptr(state.as_ptr(), state.len()),
            ReaderSlot::from_ptr(cmd_hdr.as_ptr().add(READER_SLOT_OFFSET), cmd_hdr.len() - READER_SLOT_OFFSET),
            std::slice::from_raw_parts(data_a.as_ptr(), data_a.len()),
            std::slice::from_raw_parts(data_b.as_ptr(), data_b.len()),
            RingProducer::new(
                RingbufferHeader::from_ptr(cmd_hdr.as_ptr(), cmd_hdr.len()) as *const RingbufferHeader,
                DoubleMmapRegion::new(cmd.fd(), cmd.len()).expect("map cmd ring"),
            ),
            RingConsumer::new(
                RingbufferHeader::from_ptr(resp_hdr.as_ptr(), resp_hdr.len()) as *const RingbufferHeader,
                DoubleMmapRegion::new(resp.fd(), resp.len()).expect("map resp ring"),
            ),
        )
    };
    header.check_compatible().expect("protocol version 2");

    // (a) One snapshot with both domains, sorted by name across the shards.
    let snapshot = wait_for_snapshot(header, slot, a, b, &domains).expect("no snapshot with both domains");
    let mut expected: Vec<&str> = domains.iter().map(String::as_str).chain(["default"]).collect();
    expected.sort_unstable();
    let names: Vec<&str> = snapshot.domains.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, expected);
    for name in &domains {
        let domain = snapshot.domains.iter().find(|d| d.name == *name).expect("domain in the snapshot");
        assert_eq!(domain.entries.len(), 1, "{name}");
        assert_eq!(domain.entries[0].value, format!("value of {name}").into_bytes(), "{name}");
    }

    // (b) Commands for the domain of shard 1.
    let on_shard_1 = &domains[0];
    let mut call = |cmd: ShmCommand| -> ShmResponse {
        tx.send(cmd.encode().as_slice()).expect("send command");
        let deadline = Instant::now() + WAIT_BUDGET;
        while Instant::now() < deadline {
            if let Some(raw) = rx.recv().expect("resp ring") {
                return ShmResponse::decode(&raw).expect("decode response");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("no response");
    };
    let get = |request_id, domain: &str, key: &[u8]| ShmCommand::Get {
        request_id,
        domain: domain.to_string(),
        key: key.to_vec(),
    };
    let value = format!("value of {on_shard_1}").into_bytes();
    assert_eq!(call(get(1, on_shard_1, b"k")), ShmResponse::GetOk { request_id: 1, value: ShmGetValue::Present(value) });
    let put = ShmCommand::Put {
        request_id: 2,
        domain: on_shard_1.clone(),
        key: b"written".to_vec(),
        value: WRITTEN.to_vec(),
        ttl_secs: 0,
    };
    assert_eq!(call(put), ShmResponse::Ok { request_id: 2 });
    assert_eq!(
        call(get(3, on_shard_1, b"written")),
        ShmResponse::GetOk { request_id: 3, value: ShmGetValue::Present(WRITTEN.to_vec()) }
    );
    match call(get(4, "no-such-domain", b"k")) {
        ShmResponse::Error { request_id: 4, code: 404, .. } => {}
        other => panic!("expected a 404, got {other:?}"),
    }
    drop(stream);
}

/// Reads the published snapshot until it holds every domain in `domains`
/// with an entry, retrying with a budget, never a fixed sleep.
fn wait_for_snapshot(
    header: &StateHeader,
    slot: &ReaderSlot,
    a: &[u8],
    b: &[u8],
    domains: &[String],
) -> Option<ShmSnapshot> {
    let deadline = Instant::now() + WAIT_BUDGET;
    while Instant::now() < deadline {
        if let Some(snapshot) = SnapshotGuard::acquire(header, slot, a, b).and_then(|guard| decode(guard.data())) {
            let holds = |name: &String| snapshot.domains.iter().any(|d| d.name == *name && !d.entries.is_empty());
            if domains.iter().all(holds) {
                return Some(snapshot);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// The snapshot in `bytes`, validated the way a client does; `None` before
/// the first publish.
fn decode(bytes: &[u8]) -> Option<ShmSnapshot> {
    let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    aligned.extend_from_slice(bytes);
    let archived = rkyv::access::<rkyv::Archived<ShmSnapshot>, rkyv::rancor::Error>(&aligned).ok()?;
    rkyv::deserialize::<ShmSnapshot, rkyv::rancor::Error>(archived).ok()
}
