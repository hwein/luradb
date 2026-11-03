//! Where a write's latency goes, with one engine writing alone and with three
//! writing at once: the full server in-process, each engine written by four
//! connections of sequential writes, every request traced (`core::write_trace`).
//! Prints p50/p99 per phase, the storage hub's submits by chain count, the
//! threads' CPU and an M/M/1 estimate of the engine thread's queue; asserts
//! only that every write was traced in full. `#[ignore]`d — run in release
//! with nothing else running:
//! `cargo test --release --lib write_phases -- --ignored --nocapture`.
//! `LURADB_WRITE_PHASES_SECS` sets the seconds per run (default 10),
//! `LURADB_WRITE_PHASES_RUNS` the runs per set (default 3); the data lives in
//! the temp directory (`TMPDIR`). `LURADB_WRITE_PHASES_TRACE=0` runs the same
//! load untraced and prints the client's ops/s, p50 and p99 alone: the
//! control for what the tracing costs.
//!
//! A submit in the hub table is one pass that puts chains on the ring.
//!
//! Measured 2026-10-22, release build on a 12-vCPU virtual machine; medians
//! of 3 runs per set, key-value writes, p50 in µs. "Before": the hub starts
//! new chains only once every chain on the ring is reaped; "after": it waits
//! on the ring at most 50 µs and starts chains for free files meanwhile.
//!
//! | tmpfs           | alone before | after | three before | after |
//! |-----------------|--------------|-------|--------------|-------|
//! | client          | 1768         | 1728  | 2435         | 2661  |
//! | traced in all   | 1162         | 1147  | 1745         | 1842  |
//! | 1 front         | 14           | 14    | 10           | 11    |
//! | 2 queue         | 141          | 147   | 266          | 292   |
//! | 3 to WAL        | 20           | 20    | 15           | 16    |
//! | 4 hub           | 652          | 655   | 984          | 979   |
//! | 4a hub queue    | 86           | 81    | 255          | 199   |
//! | 4b hub I/O      | 216          | 223   | 226          | 285   |
//! | 4c wake         | 99           | 99    | 185          | 163   |
//! | 3' after        | 8            | 8     | 9            | 10    |
//! | 5 reply         | 124          | 123   | 209          | 215   |
//!
//! | ext4            | alone before | after | three before | after |
//! |-----------------|--------------|-------|--------------|-------|
//! | client          | 4631         | 4382  | 6330         | 6332  |
//! | 4 hub           | 3306         | 2943  | 4694         | 4654  |
//! | 4a hub queue    | 852          | 729   | 1309         | 1248  |
//! | 4b hub I/O      | 1903         | 1732  | 2764         | 2681  |
//! | 4c wake         | 130          | 128   | 256          | 180   |
//!
//! Untraced, the client p50 alone and with three engines is 1710 / 2690 →
//! 1628 / 2360 µs on tmpfs and 4369 / 6351 → 4179 / 6465 µs on ext4; run to
//! run it varies by up to 15 %. The storage thread is 18 → 20 %
//! busy on tmpfs and 9 → 19 % on ext4, where the bounded wait wakes it
//! during each 1.8 ms fdatasync.

use super::{tests::test_config, Server};
use crate::config::LuraConfig;
use crate::core::write_trace::{self, Append, Batch, Stamps};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNS_PER_ENGINE: usize = 4;
/// 64 characters: the value of every write.
const TEXT: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Engine {
    Kv,
    Json,
    Rel,
}

const SETS: [(&str, &[Engine]); 2] = [("alone", &[Engine::Kv]), ("three", &[Engine::Kv, Engine::Json, Engine::Rel])];

impl Engine {
    fn label(self) -> &'static str {
        match self {
            Engine::Kv => "kv",
            Engine::Json => "json",
            Engine::Rel => "rel",
        }
    }

    fn domain(self) -> String {
        format!("phases{}", self.label())
    }

    fn of(path: &str) -> Option<Self> {
        let prefix = |e: &Engine| format!("/store-api/{}/", e.label());
        [Engine::Kv, Engine::Json, Engine::Rel].into_iter().find(|e| path.starts_with(&prefix(e)))
    }

    /// Creates the engine's domain, and the table of the relational writes.
    fn setup(self) -> Vec<String> {
        let name = format!(r#"{{"name":"{}"}}"#, self.domain());
        match self {
            Engine::Kv => vec![request("POST", "/store-api/domains", &name)],
            Engine::Json => vec![request("POST", "/store-api/json/domains", &name)],
            Engine::Rel => vec![
                request("POST", "/store-api/rel/domains", &name),
                request(
                    "POST",
                    &format!("/store-api/rel/{}/sql", self.domain()),
                    r#"{"sql":"CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"}"#,
                ),
            ],
        }
    }

    /// Write `i` of connection `conn`; keys never repeat.
    fn write(self, conn: usize, i: usize) -> String {
        let domain = self.domain();
        match self {
            Engine::Kv => request("PUT", &format!("/store-api/kv/{domain}/keys/c{conn}-{i}"), TEXT),
            Engine::Json => request(
                "PUT",
                &format!("/store-api/json/{domain}/documents/c{conn}-{i}"),
                &format!(r#"{{"n": {i}, "v": "{TEXT}"}}"#),
            ),
            Engine::Rel => request(
                "POST",
                &format!("/store-api/rel/{domain}/sql"),
                &format!(
                    r#"{{"sql": "INSERT INTO t (id, v) VALUES (?, ?)", "params": [{}, "{TEXT}"]}}"#,
                    conn * 100_000_000 + i
                ),
            ),
        }
    }
}

fn request(method: &str, path: &str, body: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// A keep-alive HTTP/1.1 connection for answers framed by Content-Length.
struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    async fn open(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        Self { stream, buf: Vec::new() }
    }

    async fn send(&mut self, raw: &[u8]) -> (u16, Vec<u8>) {
        self.stream.write_all(raw).await.unwrap();
        loop {
            if let Some(head_end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&self.buf[..head_end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |value| value.trim().parse().unwrap());
                let end = head_end + 4 + len;
                if self.buf.len() >= end {
                    let status = head[9..12].parse().unwrap();
                    let body = self.buf[head_end + 4..end].to_vec();
                    self.buf.drain(..end);
                    return (status, body);
                }
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed: {}", String::from_utf8_lossy(&self.buf));
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// All three engines on, rate limits out of the way, no flush during a run,
/// the SHM publisher on.
fn tune(cfg: &mut LuraConfig, dir: &Path, run: usize) {
    cfg.json.enabled = true;
    cfg.rel.enabled = true;
    cfg.multicore.reader_threads = 0;
    cfg.rate_limit.default_read_iops = 100_000_000;
    cfg.rate_limit.default_write_iops = 100_000_000;
    cfg.lsm.memtable_size_threshold = 16 * 1024 * 1024;
    cfg.io_engine.enabled = true;
    cfg.shm.enabled = true;
    cfg.shm.instance_id = format!("write-phases-{}-{run}", std::process::id());
    cfg.shm.registration_socket_path = dir.join("shm.sock").to_string_lossy().into_owned();
    cfg.shm.data_buffer_size = 64 * 1024 * 1024;
}

/// CPU seconds so far of this process's server threads, by thread name.
fn thread_cpu() -> HashMap<&'static str, f64> {
    // SAFETY: sysconf reads a constant.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let mut cpu = HashMap::new();
    for task in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let (Ok(comm), Ok(stat)) =
            (std::fs::read_to_string(task.path().join("comm")), std::fs::read_to_string(task.path().join("stat")))
        else {
            continue;
        };
        let groups = ["luradb-shard", "luradb-storage", "luradb-frontend", "luradb-reader"];
        let Some(group) = groups.into_iter().find(|g| comm.trim().starts_with(g)) else { continue };
        // utime and stime, fields 14 and 15, after the parenthesised name.
        let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..].split_whitespace().collect();
        let used = fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap();
        *cpu.entry(group).or_default() += used / ticks;
    }
    cpu
}

struct Run {
    /// Client-side latency of every write, per engine of the set.
    latencies: Vec<(Engine, Vec<Duration>)>,
    requests: Vec<Stamps>,
    batches: Vec<Batch>,
    /// CPU seconds per thread group during the load.
    cpu: HashMap<&'static str, f64>,
    wall: Duration,
}

fn run(engines: &[Engine], load_for: Duration, index: usize, trace: bool) -> Run {
    let dir = tempfile::TempDir::new().unwrap();
    let mut cfg = test_config(dir.path());
    tune(&mut cfg, dir.path(), index);
    let server = Server::start(Arc::new(cfg), &dir.path().join("luradb.toml")).unwrap();
    let addr = server.http_addr.expect("HTTP listener enabled");
    let client = tokio::runtime::Runtime::new().unwrap();
    client.block_on(setup(addr, engines));

    if trace {
        write_trace::start();
    }
    let before = thread_cpu();
    let started = Instant::now();
    let latencies = client.block_on(load(addr, engines, load_for));
    let wall = started.elapsed();
    let after = thread_cpu();
    let (requests, batches) = if trace { write_trace::stop() } else { Default::default() };
    drop(client);
    server.shutdown().unwrap();
    let cpu = after.iter().map(|(group, used)| (*group, used - before.get(group).copied().unwrap_or(0.0))).collect();
    Run { latencies, requests, batches, cpu, wall }
}

async fn setup(addr: SocketAddr, engines: &[Engine]) {
    let mut conn = Conn::open(addr).await;
    for raw in engines.iter().flat_map(|engine| engine.setup()) {
        let (status, body) = conn.send(raw.as_bytes()).await;
        assert!((200..300).contains(&status), "{raw}: {status} {}", String::from_utf8_lossy(&body));
    }
}

#[allow(clippy::disallowed_methods, reason = "the client runs on its own tokio runtime")]
async fn load(addr: SocketAddr, engines: &[Engine], load_for: Duration) -> Vec<(Engine, Vec<Duration>)> {
    let mut conns = Vec::new();
    for &engine in engines {
        for c in 0..CONNS_PER_ENGINE {
            conns.push((engine, c, Conn::open(addr).await));
        }
    }
    let deadline = Instant::now() + load_for;
    let writers: Vec<_> = conns
        .into_iter()
        .map(|(engine, c, mut conn)| {
            tokio::spawn(async move {
                let mut latencies = Vec::new();
                let mut i = 0;
                while Instant::now() < deadline {
                    let raw = engine.write(c, i);
                    let began = Instant::now();
                    let (status, body) = conn.send(raw.as_bytes()).await;
                    latencies.push(began.elapsed());
                    assert!((200..300).contains(&status), "{raw}: {status} {}", String::from_utf8_lossy(&body));
                    i += 1;
                }
                (engine, latencies)
            })
        })
        .collect();
    let mut out: Vec<(Engine, Vec<Duration>)> = engines.iter().map(|&engine| (engine, Vec::new())).collect();
    for writer in writers {
        let (engine, latencies) = writer.await.unwrap();
        out.iter_mut().find(|(e, _)| *e == engine).unwrap().1.extend(latencies);
    }
    out
}

/// Every write was traced once, with every stamp, in order.
fn assert_traced_in_full(run: &Run) {
    let writes: usize = run.latencies.iter().map(|(_, l)| l.len()).sum();
    assert_eq!(run.requests.len(), writes, "traced requests against client writes");
    for s in &run.requests {
        assert!(Engine::of(&s.path).is_some(), "{s:?}");
        let (Some(shipped), Some(taken), Some(answered), Some(done)) = (s.shipped, s.taken, s.answered, s.done) else {
            panic!("incomplete trace: {s:?}");
        };
        let (Some(first), Some(last)) = (s.appends.first(), s.appends.last()) else {
            panic!("no append traced: {s:?}");
        };
        assert!(s.arrived <= shipped && shipped <= taken && taken <= first.queued, "{s:?}");
        assert!(last.resumed <= answered && answered <= done, "{s:?}");
        for a in &s.appends {
            assert!(a.queued <= a.picked && a.picked <= a.answered && a.answered <= a.resumed, "{s:?}");
        }
    }
}

fn us(from: Instant, to: Instant) -> f64 {
    to.duration_since(from).as_secs_f64() * 1e6
}

const PHASES: [&str; 11] = [
    "client", "total", "1 front", "2 queue", "3 to WAL", "4 hub", "4a hub queue", "4b hub I/O", "4c wake", "3' after",
    "5 reply",
];

/// A traced write's phases in µs, in [`PHASES`] order after the client column.
fn phases(s: &Stamps) -> [f64; 10] {
    let (shipped, taken, answered, done) = (s.shipped.unwrap(), s.taken.unwrap(), s.answered.unwrap(), s.done.unwrap());
    let sum = |span: fn(&Append) -> f64| s.appends.iter().map(span).sum::<f64>();
    let to_wal = us(taken, s.appends[0].queued);
    let hub = sum(|a| us(a.queued, a.resumed));
    [
        us(s.arrived, done),
        us(s.arrived, shipped),
        us(shipped, taken),
        to_wal,
        hub,
        sum(|a| us(a.queued, a.picked)),
        sum(|a| us(a.picked, a.answered)),
        sum(|a| us(a.answered, a.resumed)),
        us(taken, answered) - to_wal - hub,
        us(answered, done),
    ]
}

fn quantile(values: &[f64], q: f64) -> f64 {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| !v.is_nan()).collect();
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted.sort_by(f64::total_cmp);
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

/// Rows of numbers under a head; the runs of a set give tables of one shape.
struct Table {
    title: String,
    head: Vec<&'static str>,
    rows: Vec<(String, Vec<f64>)>,
}

impl Table {
    fn median(runs: &[&Table]) -> Table {
        let first = runs[0];
        let rows = first
            .rows
            .iter()
            .enumerate()
            .map(|(r, (label, cells))| {
                let cell = |c: usize| quantile(&runs.iter().map(|t| t.rows[r].1[c]).collect::<Vec<_>>(), 0.5);
                (label.clone(), (0..cells.len()).map(cell).collect())
            })
            .collect();
        Table { title: format!("{} (median of {} runs)", first.title, runs.len()), head: first.head.clone(), rows }
    }

    fn print(&self) {
        println!("\n{}\n| row | {} |", self.title, self.head.join(" | "));
        println!("|---|{}", "---|".repeat(self.head.len()));
        for (label, cells) in &self.rows {
            let cells: Vec<String> =
                cells.iter().map(|v| if v.is_nan() { "–".into() } else { format!("{v:.0}") }).collect();
            println!("| {label} | {} |", cells.join(" | "));
        }
    }
}

/// Per engine: ops/s and the phases' p50, p99 and mean, in µs.
fn phase_table(set: &str, run: &Run) -> Table {
    let mut head = vec!["ops/s"];
    head.extend(PHASES);
    let mut rows = Vec::new();
    for (engine, latencies) in &run.latencies {
        let client: Vec<f64> = latencies.iter().map(|l| l.as_secs_f64() * 1e6).collect();
        let traced: Vec<[f64; 10]> =
            run.requests.iter().filter(|s| Engine::of(&s.path) == Some(*engine)).map(phases).collect();
        let ops = latencies.len() as f64 / run.wall.as_secs_f64();
        for (stat, pick) in [("p50", Some(0.5)), ("p99", Some(0.99)), ("mean", None)] {
            let of = |values: &[f64]| pick.map_or_else(|| mean(values), |q| quantile(values, q));
            let mut cells = vec![ops, of(&client)];
            cells.extend((0..10).map(|p| of(&traced.iter().map(|t| t[p]).collect::<Vec<_>>())));
            rows.push((format!("{} {stat}", engine.label()), cells));
        }
    }
    Table { title: format!("Phases, µs — {set}"), head, rows }
}

/// Per engine: ops/s and the client's p50 and p99, in µs.
fn client_table(set: &str, run: &Run) -> Table {
    let rows = run
        .latencies
        .iter()
        .map(|(engine, latencies)| {
            let client: Vec<f64> = latencies.iter().map(|l| l.as_secs_f64() * 1e6).collect();
            let ops = latencies.len() as f64 / run.wall.as_secs_f64();
            (engine.label().to_string(), vec![ops, quantile(&client, 0.5), quantile(&client, 0.99)])
        })
        .collect();
    Table { title: format!("Client, untraced, µs — {set}"), head: vec!["ops/s", "p50", "p99"], rows }
}

/// Per number of chains in a submit: how often, the submit's duration up to
/// its last completion, when its first and last fdatasync completed, each
/// fdatasync from its write's completion, and their sum per submit; in µs.
fn hub_table(set: &str, run: &Run) -> Table {
    let head = vec![
        "submits", "submit p50", "submit p99", "first sync p50", "last sync p50", "sync p50", "sync p99", "Σ sync p50",
    ];
    let rows = (1..=4)
        .map(|n| {
            let batches: Vec<&Batch> = run.batches.iter().filter(|b| b.chains.len() == n).collect();
            let mut spans = Vec::new();
            let (mut first, mut last, mut syncs, mut sums) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for b in &batches {
                let synced: Vec<f64> = b.chains.iter().filter_map(|c| c.1).map(|t| us(b.submitted, t)).collect();
                let done = b.chains.iter().flat_map(|c| [c.0, c.1]).flatten().map(|t| us(b.submitted, t));
                spans.push(done.fold(0.0, f64::max));
                first.push(synced.iter().copied().fold(f64::NAN, f64::min));
                last.push(synced.iter().copied().fold(f64::NAN, f64::max));
                let each: Vec<f64> =
                    b.chains.iter().filter_map(|c| Some(us(c.0?, c.1?))).collect();
                sums.push(each.iter().sum());
                syncs.extend(each);
            }
            let cells = vec![
                batches.len() as f64,
                quantile(&spans, 0.5),
                quantile(&spans, 0.99),
                quantile(&first, 0.5),
                quantile(&last, 0.5),
                quantile(&syncs, 0.5),
                quantile(&syncs, 0.99),
                quantile(&sums, 0.5),
            ];
            (format!("{n} chain(s)"), cells)
        })
        .collect();
    Table { title: format!("Storage hub submits, µs — {set}"), head, rows }
}

/// Thread CPU in percent of one core, and the data shards as an M/M/1
/// queue: writes/s, CPU per write, load, the queue's mean wait, and the
/// measured means of the two waits for a shard thread (queue, wake).
fn thread_table(set: &str, run: &Run) -> Table {
    let wall = run.wall.as_secs_f64();
    let pct = |group: &str| run.cpu.get(group).copied().unwrap_or(0.0) / wall * 100.0;
    let writes = run.requests.len() as f64;
    let rate = writes / wall;
    let service = run.cpu.get("luradb-shard").copied().unwrap_or(0.0) / writes;
    let load = rate * service;
    let traced: Vec<[f64; 10]> = run.requests.iter().map(phases).collect();
    let mean_of = |p: usize| mean(&traced.iter().map(|t| t[p]).collect::<Vec<_>>());
    let cells = vec![
        pct("luradb-shard"),
        pct("luradb-storage"),
        pct("luradb-frontend"),
        pct("luradb-reader"),
        rate,
        service * 1e6,
        load * 100.0,
        load / (1.0 - load) * service * 1e6,
        mean_of(2),
        mean_of(7),
    ];
    let head = vec![
        "engine %", "storage %", "frontend %", "reader %", "writes/s", "engine µs/write", "ρ %", "M/M/1 wait µs",
        "2 queue mean", "4c wake mean",
    ];
    Table { title: format!("Threads and M/M/1 — {set}"), head, rows: vec![("all".into(), cells)] }
}

fn env(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[test]
#[ignore]
fn write_latency_by_phase_alone_and_with_three_engines() {
    let load_for = Duration::from_secs(env("LURADB_WRITE_PHASES_SECS", 10) as u64);
    let runs = env("LURADB_WRITE_PHASES_RUNS", 3);
    let trace = env("LURADB_WRITE_PHASES_TRACE", 1) != 0;
    let mut tables: Vec<Vec<Vec<Table>>> = SETS.iter().map(|_| Vec::new()).collect();
    for r in 0..runs {
        for (s, (set, engines)) in SETS.iter().enumerate() {
            let run = run(engines, load_for, r * SETS.len() + s, trace);
            if !trace {
                tables[s].push(vec![client_table(set, &run)]);
                continue;
            }
            assert_traced_in_full(&run);
            println!("run {r} {set}: {} writes, {} hub submits", run.requests.len(), run.batches.len());
            tables[s].push(vec![phase_table(set, &run), hub_table(set, &run), thread_table(set, &run)]);
        }
    }
    for set in &tables {
        for kind in 0..set[0].len() {
            Table::median(&set.iter().map(|t| &t[kind]).collect::<Vec<_>>()).print();
        }
    }
}
