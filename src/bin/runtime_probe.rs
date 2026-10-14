//! Runtime probe (spec perf/019): measures compio as the engine-thread runtime
//! against today's tokio_uring, one subcommand per criterion. Prints Markdown
//! tables and exits non-zero when a checked criterion fails. Creates and
//! removes its own files in `--dir`.

use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, Subcommand};
use compio::buf::BufResult;
use compio::driver::{AsyncifyPool, OpCode, OpEntry, ProactorBuilder};
use compio::io::{AsyncReadAt, AsyncReadManagedAt, AsyncWriteAt};
use compio::runtime::{JoinError, Runtime, RuntimeBuilder};
use std::any::Any;
use std::future::Future;
use std::num::NonZeroU16;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch, Mutex, Notify, RwLock, Semaphore};
use tokio_uring::buf::fixed::{FixedBuf, FixedBufPool};

#[derive(Parser)]
#[command(about = "Validates compio as the engine-thread runtime against tokio_uring (spec perf/019)")]
struct Cli {
    /// Directory for the probe's own files; must be a real disk, not tmpfs.
    #[arg(long, global = true, default_value = ".")]
    dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// K1: setup flags of a shard ring; run under `strace -f -e trace=io_uring_setup`.
    K1,
    /// K2: tokio::sync wakes from a std::thread, timers, hub roundtrip latency.
    K2 {
        #[arg(long, default_value_t = 1_000_000)]
        roundtrips: usize,
    },
    /// K3: blocking-pool threads of N runtimes under the coop::offload cap.
    K3 {
        #[arg(long, default_value_t = 4)]
        runtimes: usize,
        /// Offloads per runtime.
        #[arg(long, default_value_t = 64)]
        offloads: usize,
        #[arg(long, default_value_t = 4)]
        cap: usize,
        /// CPU time of one offloaded closure.
        #[arg(long, default_value_t = 1000)]
        work_us: u64,
    },
    /// K6: 4-KiB pread latency and throughput on both runtimes (release build).
    K6 {
        #[arg(long, default_value_t = 256)]
        file_mib: u64,
        /// Reads per variant and round, split across the variant's tasks.
        #[arg(long, default_value_t = 200_000)]
        ops: usize,
        /// Rounds; variants run interleaved within a round.
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        /// Drops the file's page cache before every variant.
        #[arg(long)]
        cold: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!(
        "runtime_probe: compio 0.19.2 vs tokio-uring 0.5, kernel {}, {} cores",
        kernel_release(),
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    );
    if cfg!(debug_assertions) {
        println!("WARNING: debug build; measurements need `cargo build --release`");
    }
    match cli.command {
        Command::K1 => k1(&cli.dir),
        Command::K2 { roundtrips } => k2(roundtrips),
        Command::K3 { runtimes, offloads, cap, work_us } => k3(runtimes, offloads, cap, work_us),
        Command::K6 { file_mib, ops, rounds, cold } => k6(&cli.dir, file_mib, ops, rounds, cold),
    }
}

// --- shared helpers ---

const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const SHARD_RING_FLAGS: u32 =
    IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;

/// Ring of an engine/shard thread: no SQPOLL, which stays with the storage hub.
fn shard_proactor() -> ProactorBuilder {
    let mut proactor = ProactorBuilder::new();
    proactor.single_issuer(true).defer_taskrun(true).coop_taskrun(true).taskrun_flag(true);
    proactor
}

fn compio_runtime(proactor: ProactorBuilder) -> Result<Runtime> {
    RuntimeBuilder::new().with_proactor(proactor).build().context("failed to build the compio runtime")
}

/// Runs `fut` as a spawned task (not as the `block_on` future), so wakes take
/// the task-waker path an engine task takes.
fn compio_task<T: 'static>(rt: &Runtime, fut: impl Future<Output = T> + 'static) -> Result<T> {
    rt.block_on(rt.spawn(fut)).map_err(join_error)
}

fn join_error(e: JoinError) -> anyhow::Error {
    anyhow!("compio task failed: {e:?}")
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|e| format!("unknown ({e})"))
}

fn thread_count() -> Result<usize> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| anyhow!("no Threads: line in /proc/self/status"))
}

/// Selected `/proc/self/fdinfo` lines of an io_uring fd.
fn ring_fdinfo(ring_fd: RawFd) -> String {
    match std::fs::read_to_string(format!("/proc/self/fdinfo/{ring_fd}")) {
        Ok(info) => info
            .lines()
            .filter(|l| ["SqThread:", "SqThreadCpu:", "UserFiles:", "UserBufs:"].iter().any(|k| l.starts_with(k)))
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(", "),
        Err(e) => format!("unreadable: {e}"),
    }
}

/// Removes the probe's own file when dropped, also on early returns.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Runs `f` with the panic hook silenced; the probe reports caught panics itself.
fn quietly<T>(f: impl FnOnce() -> T) -> T {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = f();
    std::panic::set_hook(hook);
    out
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

fn ns(d: Duration) -> u32 {
    u32::try_from(d.as_nanos()).unwrap_or(u32::MAX)
}

fn micros(nanos: u32) -> String {
    format!("{:.2}", f64::from(nanos) / 1000.0)
}

fn millis(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1000.0)
}

fn delta(new: f64, old: f64) -> String {
    format!("{:+.1} %", (new / old - 1.0) * 100.0)
}

struct Summary {
    p50: u32,
    p99: u32,
    p999: u32,
}

/// Exact percentiles over all samples.
fn summarize(samples: &mut [u32]) -> Summary {
    samples.sort_unstable();
    let at = |q: f64| {
        let index = (samples.len().saturating_sub(1) as f64 * q).round() as usize;
        samples.get(index).copied().unwrap_or(0)
    };
    Summary { p50: at(0.50), p99: at(0.99), p999: at(0.999) }
}

fn print_table(title: &str, headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    println!("\n### {title}\n");
    println!("{}", table_row(headers.iter().copied(), &widths));
    println!("|{}|", widths.iter().map(|w| "-".repeat(w + 2)).collect::<Vec<_>>().join("|"));
    for row in rows {
        println!("{}", table_row(row.iter().map(String::as_str), &widths));
    }
}

fn table_row<'a>(cells: impl Iterator<Item = &'a str>, widths: &[usize]) -> String {
    let cells: Vec<String> = cells.zip(widths).map(|(cell, w)| format!(" {cell:<w$} ")).collect();
    format!("|{}|", cells.join("|"))
}

// --- K1: ring setup flags ---

const PAYLOAD: &[u8] = b"runtime probe payload";

fn k1(dir: &Path) -> Result<()> {
    println!("\n## K1 ring setup flags of a shard ring\n");
    let proactor = shard_proactor();
    println!("compio requested: {proactor:?}");
    println!(
        "expected compio io_uring_setup flags: {SHARD_RING_FLAGS:#x} = COOP_TASKRUN + TASKRUN_FLAG + SINGLE_ISSUER + DEFER_TASKRUN, SQPOLL ({IORING_SETUP_SQPOLL:#x}) unset"
    );
    println!("tokio_uring today: tokio_uring::start = io_uring::IoUring::builder() defaults, 256 entries, no setup flags");
    println!("effective flags: the io_uring_setup lines of the strace capture");
    println!("the 2-entry ring with flags=0 in the strace is compio's per-process opcode-support probe, not a shard ring");

    let compio_path = dir.join("runtime_probe_k1_compio.dat");
    let rt = compio_runtime(proactor)?;
    let (compio_io, foreign, fdinfo) = rt.block_on(async {
        let ring_fd = Runtime::with_current(|rt| rt.as_raw_fd());
        let io = compio_file_ops(&compio_path).await;
        (io, foreign_getevents(ring_fd), ring_fdinfo(ring_fd))
    });
    drop(rt);
    let tokio_uring_io = tokio_uring::start(tokio_uring_file_ops(&dir.join("runtime_probe_k1_tokio_uring.dat")));

    println!("compio ring fdinfo: {fdinfo}");
    let foreign = match foreign {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => "EEXIST: only the submitter may wait (DEFER_TASKRUN active)".to_string(),
        Ok(n) => format!("returned {n}: any thread may wait (DEFER_TASKRUN not active)"),
        Err(e) => format!("error: {e}"),
    };
    let outcome = |r: &Result<()>| match r {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("FAILED: {e:#}"),
    };
    print_table(
        "K1 result",
        &["runtime", "requested setup flags", "SQPOLL", "file ops", "result", "foreign-thread io_uring_enter(GETEVENTS)"],
        &[
            vec![
                "compio 0.19.2, shard ring".into(),
                format!("{SHARD_RING_FLAGS:#x}"),
                "off".into(),
                "open, write_at, fdatasync, read_at, ftruncate, statx, rename, unlink".into(),
                outcome(&compio_io),
                foreign,
            ],
            vec![
                "tokio_uring 0.5, today".into(),
                "0x0".into(),
                "off".into(),
                "open, write_at, fdatasync, read_at, rename, unlink".into(),
                outcome(&tokio_uring_io),
                "n/a (ring fd not exposed)".into(),
            ],
        ],
    );
    compio_io.context("compio file ops failed")?;
    tokio_uring_io.context("tokio_uring file ops failed")
}

async fn compio_file_ops(path: &Path) -> Result<()> {
    let renamed = path.with_extension("renamed");
    let _cleanup = (TempFile(path.to_path_buf()), TempFile(renamed.clone()));
    let mut file =
        compio::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path).await?;
    let BufResult(written, _) = file.write_at(PAYLOAD.to_vec(), 0).await;
    ensure!(written? == PAYLOAD.len(), "short write");
    file.sync_data().await?;
    let BufResult(read, buf) = file.read_at(Vec::with_capacity(PAYLOAD.len()), 0).await;
    read?;
    ensure!(buf == PAYLOAD, "read-back differs from the written bytes");
    file.set_len(0).await?;
    ensure!(file.metadata().await?.len() == 0, "ftruncate left bytes behind");
    file.close().await?;
    compio::fs::rename(path, &renamed).await?;
    compio::fs::remove_file(&renamed).await?;
    Ok(())
}

async fn tokio_uring_file_ops(path: &Path) -> Result<()> {
    let renamed = path.with_extension("renamed");
    let _cleanup = (TempFile(path.to_path_buf()), TempFile(renamed.clone()));
    let file = tokio_uring::fs::File::create(path).await?;
    let (written, _) = file.write_at(PAYLOAD.to_vec(), 0).submit().await;
    ensure!(written? == PAYLOAD.len(), "short write");
    file.sync_data().await?;
    file.close().await?;
    let file = tokio_uring::fs::File::open(path).await?;
    let (read, buf) = file.read_at(Vec::with_capacity(PAYLOAD.len()), 0).await;
    read?;
    ensure!(buf == PAYLOAD, "read-back differs from the written bytes");
    file.close().await?;
    tokio_uring::fs::rename(path, &renamed).await?;
    tokio_uring::fs::remove_file(&renamed).await?;
    Ok(())
}

/// `io_uring_enter(GETEVENTS)` from a thread that did not create the ring: a
/// DEFER_TASKRUN ring lets only its submitter wait and answers EEXIST.
fn foreign_getevents(ring_fd: RawFd) -> std::io::Result<i64> {
    const IORING_ENTER_GETEVENTS: libc::c_long = 1;
    std::thread::spawn(move || {
        // SAFETY: no SQEs are submitted and no argument struct is passed.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                libc::c_long::from(ring_fd),
                0 as libc::c_long,
                0 as libc::c_long,
                IORING_ENTER_GETEVENTS,
                std::ptr::null::<libc::c_void>(),
                0 as libc::c_long,
            )
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    })
    .join()
    .expect("the probe thread does not panic")
}

// --- K2: cross-runtime wakers ---

const RELEASE_DELAY: Duration = Duration::from_millis(20);
const WAKE_TIMEOUT: Duration = Duration::from_secs(5);
const TIMER: Duration = Duration::from_millis(10);
const ROUNDTRIP_WARMUP: usize = 10_000;

fn k2(roundtrips: usize) -> Result<()> {
    println!("\n## K2 cross-runtime wakers\n");
    let rt = compio_runtime(shard_proactor())?;

    let checks = compio_task(&rt, primitive_checks())?;
    let rows: Vec<Vec<String>> = checks
        .iter()
        .map(|(name, woken)| match woken {
            Ok(after) => vec![name.to_string(), "yes".into(), micros(ns(*after))],
            Err(e) => vec![name.to_string(), format!("NO: {e:#}"), "-".into()],
        })
        .collect();
    print_table(
        "tokio::sync released from a std::thread, awaited by a compio task",
        &["primitive", "task woken", "release -> resume (us)"],
        &rows,
    );

    let tokio_time = rt.block_on(async { tokio_time_without_context() });
    let timers = compio_task(&rt, compio_timers())?;
    let tokio_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build()?;
    let entered = {
        let _guard = tokio_rt.enter();
        compio_task(&rt, async {
            let start = Instant::now();
            tokio::time::sleep(TIMER).await;
            start.elapsed()
        })?
    };
    let mut timer_rows: Vec<Vec<String>> =
        tokio_time.into_iter().map(|(timer, result)| vec![timer.to_string(), result]).collect();
    timer_rows.extend([
        vec!["compio::time::sleep(10 ms)".into(), format!("woke after {}", millis(timers.slept))],
        vec![
            "compio::time::timeout(10 ms, pending)".into(),
            timers.expired_after.map_or("did not expire".into(), |d| format!("Elapsed after {}", millis(d))),
        ],
        vec![
            "compio::time::timeout(1 s, ready)".into(),
            if timers.ready_in_time { "Ok".into() } else { "Elapsed".into() },
        ],
        vec![
            "tokio::time::sleep(10 ms) with a separate tokio runtime's Handle entered".into(),
            format!("woke after {}", millis(entered)),
        ],
    ]);
    print_table("timers on the compio runtime", &["timer", "result"], &timer_rows);
    let yielded = compio_task(&rt, yield_lets_others_run())?;
    println!(
        "\ntokio::task::yield_now in a compio task: {}",
        match yielded {
            Ok(true) => "returns, a task spawned before it ran first".to_string(),
            Ok(false) => "returns, but a task spawned before it did not run".to_string(),
            Err(e) => format!("FAILED: {e:#}"),
        }
    );

    let mut compio_runs = compio_task(&rt, hub_roundtrips(roundtrips))??;
    drop(rt);
    let mut tokio_uring_runs = tokio_uring::start(async { tokio_uring::spawn(hub_roundtrips(roundtrips)).await })??;
    let mut rows = Vec::new();
    let mut summaries = Vec::new();
    for (name, run) in [("tokio_uring 0.5", &mut tokio_uring_runs), ("compio 0.19.2, shard ring", &mut compio_runs)] {
        let roundtrip = summarize(&mut run.roundtrip);
        let wake = summarize(&mut run.wake);
        rows.push(vec![
            name.to_string(),
            run.roundtrip.len().to_string(),
            micros(roundtrip.p50),
            micros(roundtrip.p99),
            micros(roundtrip.p999),
            micros(wake.p50),
            micros(wake.p99),
            format!("{:.0}", run.roundtrip.len() as f64 / run.elapsed.as_secs_f64()),
        ]);
        summaries.push((roundtrip, wake));
    }
    let (tu, co) = (&summaries[0], &summaries[1]);
    rows.push(vec![
        "compio vs tokio_uring".into(),
        "-".into(),
        delta(f64::from(co.0.p50), f64::from(tu.0.p50)),
        delta(f64::from(co.0.p99), f64::from(tu.0.p99)),
        delta(f64::from(co.0.p999), f64::from(tu.0.p999)),
        delta(f64::from(co.1.p50), f64::from(tu.1.p50)),
        delta(f64::from(co.1.p99), f64::from(tu.1.p99)),
        "-".into(),
    ]);
    print_table(
        "hub thread <-> runtime task: mpsc request, oneshot reply (K6 b/c)",
        &["runtime", "roundtrips", "rt p50 (us)", "rt p99 (us)", "rt p99.9 (us)", "wake p50 (us)", "wake p99 (us)", "roundtrips/s"],
        &rows,
    );
    println!("rt = task sends request until reply received; wake = hub sends oneshot until task resumes; {ROUNDTRIP_WARMUP} warm-up roundtrips excluded");

    let failed: Vec<&str> = checks.iter().filter(|(_, woken)| woken.is_err()).map(|(name, _)| *name).collect();
    ensure!(failed.is_empty(), "K2 failed: not woken: {failed:?}");
    println!("\nK2 primitives: all woken");
    Ok(())
}

async fn primitive_checks() -> Vec<(&'static str, Result<Duration>)> {
    vec![
        ("oneshot", check_oneshot().await),
        ("mpsc", check_mpsc().await),
        ("watch", check_watch().await),
        ("Notify", check_notify().await),
        ("Semaphore", check_semaphore().await),
        ("RwLock", check_rwlock().await),
        ("Mutex", check_mutex().await),
    ]
}

/// Runs `release` on a std::thread once the task had time to park, awaits
/// `woken` and returns the delay from the release to the task resuming.
async fn wake_from_thread(
    release: impl FnOnce() + Send + 'static,
    woken: impl Future<Output = Result<()>>,
) -> Result<Duration> {
    let thread = std::thread::spawn(move || {
        std::thread::sleep(RELEASE_DELAY);
        let released = Instant::now();
        release();
        released
    });
    compio::time::timeout(WAKE_TIMEOUT, woken)
        .await
        .map_err(|_| anyhow!("not woken within {WAKE_TIMEOUT:?}"))??;
    let resumed = Instant::now();
    let released = thread.join().map_err(|_| anyhow!("release thread panicked"))?;
    Ok(resumed.saturating_duration_since(released))
}

async fn check_oneshot() -> Result<Duration> {
    let (tx, rx) = oneshot::channel::<u32>();
    wake_from_thread(
        move || {
            let _ = tx.send(7);
        },
        async move {
            ensure!(rx.await? == 7, "wrong value");
            Ok(())
        },
    )
    .await
}

async fn check_mpsc() -> Result<Duration> {
    let (tx, mut rx) = mpsc::channel::<u32>(1);
    wake_from_thread(
        move || {
            let _ = tx.blocking_send(7);
        },
        async move {
            ensure!(rx.recv().await == Some(7), "wrong value");
            Ok(())
        },
    )
    .await
}

async fn check_watch() -> Result<Duration> {
    let (tx, mut rx) = watch::channel(0u32);
    wake_from_thread(
        move || {
            let _ = tx.send(7);
        },
        async move {
            rx.changed().await?;
            ensure!(*rx.borrow() == 7, "wrong value");
            Ok(())
        },
    )
    .await
}

async fn check_notify() -> Result<Duration> {
    let notify = Arc::new(Notify::new());
    let releaser = Arc::clone(&notify);
    wake_from_thread(move || releaser.notify_one(), async move {
        notify.notified().await;
        Ok(())
    })
    .await
}

async fn check_semaphore() -> Result<Duration> {
    let semaphore = Arc::new(Semaphore::new(0));
    let releaser = Arc::clone(&semaphore);
    wake_from_thread(move || releaser.add_permits(1), async move {
        let _permit = semaphore.acquire().await?;
        Ok(())
    })
    .await
}

async fn check_rwlock() -> Result<Duration> {
    let lock = Arc::new(RwLock::new(0u32));
    let mut guard = Arc::clone(&lock).write_owned().await;
    wake_from_thread(
        move || {
            *guard = 7;
            drop(guard);
        },
        async move {
            ensure!(*lock.read().await == 7, "reader saw a stale value");
            Ok(())
        },
    )
    .await
}

async fn check_mutex() -> Result<Duration> {
    let lock = Arc::new(Mutex::new(0u32));
    let mut guard = Arc::clone(&lock).lock_owned().await;
    wake_from_thread(
        move || {
            *guard = 7;
            drop(guard);
        },
        async move {
            ensure!(*lock.lock().await == 7, "locker saw a stale value");
            Ok(())
        },
    )
    .await
}

/// `tokio::time` on a thread without a tokio context, called on the compio thread.
fn tokio_time_without_context() -> [(&'static str, String); 2] {
    use futures::FutureExt;
    let describe = |outcome: std::thread::Result<()>| match outcome {
        Ok(()) => "works".to_string(),
        Err(payload) => format!("panics: {}", panic_message(&*payload)),
    };
    quietly(|| {
        let sleep = std::panic::catch_unwind(|| drop(tokio::time::sleep(TIMER)));
        let timeout = std::panic::catch_unwind(|| {
            drop(tokio::time::timeout(TIMER, std::future::pending::<()>()).now_or_never());
        });
        [
            ("tokio::time::sleep, no tokio context", describe(sleep)),
            ("tokio::time::timeout, no tokio context", describe(timeout)),
        ]
    })
}

/// `coop::YieldEvery` relies on `tokio::task::yield_now` handing the thread to
/// other tasks; outside a tokio scheduler it has to wake itself.
async fn yield_lets_others_run() -> Result<bool> {
    let ran = Rc::new(std::cell::Cell::new(false));
    let flag = Rc::clone(&ran);
    compio::runtime::spawn(async move { flag.set(true) }).detach();
    compio::time::timeout(WAKE_TIMEOUT, tokio::task::yield_now())
        .await
        .map_err(|_| anyhow!("yield_now did not return within {WAKE_TIMEOUT:?}"))?;
    Ok(ran.get())
}

struct CompioTimers {
    slept: Duration,
    expired_after: Option<Duration>,
    ready_in_time: bool,
}

async fn compio_timers() -> CompioTimers {
    let start = Instant::now();
    compio::time::sleep(TIMER).await;
    let slept = start.elapsed();
    let start = Instant::now();
    let expired_after =
        compio::time::timeout(TIMER, std::future::pending::<()>()).await.is_err().then(|| start.elapsed());
    let ready_in_time = compio::time::timeout(Duration::from_secs(1), async {}).await.is_ok();
    CompioTimers { slept, expired_after, ready_in_time }
}

struct Roundtrips {
    roundtrip: Vec<u32>,
    wake: Vec<u32>,
    elapsed: Duration,
}

/// Storage-hub pattern: the task sends a request over a bounded mpsc, a
/// std::thread answers over a oneshot stamped with its send time.
async fn hub_roundtrips(n: usize) -> Result<Roundtrips> {
    let (requests, mut inbox) = mpsc::channel::<oneshot::Sender<Instant>>(1);
    let hub = std::thread::Builder::new().name("probe-hub".into()).spawn(move || {
        while let Some(reply) = inbox.blocking_recv() {
            let _ = reply.send(Instant::now());
        }
    })?;
    let mut roundtrip = Vec::with_capacity(n);
    let mut wake = Vec::with_capacity(n);
    let mut start = Instant::now();
    for i in 0..ROUNDTRIP_WARMUP + n {
        if i == ROUNDTRIP_WARMUP {
            start = Instant::now();
        }
        let (reply, response) = oneshot::channel();
        let sent = Instant::now();
        requests.send(reply).await.map_err(|_| anyhow!("hub thread stopped"))?;
        let replied = response.await?;
        let resumed = Instant::now();
        if i >= ROUNDTRIP_WARMUP {
            roundtrip.push(ns(resumed - sent));
            wake.push(ns(resumed.saturating_duration_since(replied)));
        }
    }
    let elapsed = start.elapsed();
    drop(requests);
    hub.join().map_err(|_| anyhow!("hub thread panicked"))?;
    Ok(Roundtrips { roundtrip, wake, elapsed })
}

// --- K3: blocking pool ---

#[derive(Clone, Copy, PartialEq, Eq)]
enum OffloadVia {
    CoopTokioHandle,
    CoopTokioHandleCapped,
    CompioPerRuntime,
    CompioShared,
    CompioLimitOnly,
}

impl OffloadVia {
    fn label(self, cap: usize) -> String {
        match self {
            Self::CoopTokioHandle => "coop::offload, tokio Handle entered".into(),
            Self::CoopTokioHandleCapped => "coop::offload, capped tokio Handle entered".into(),
            Self::CompioPerRuntime => format!("{cap} permits + compio spawn_blocking"),
            Self::CompioShared => format!("{cap} permits + compio spawn_blocking, shared pool"),
            Self::CompioLimitOnly => "compio spawn_blocking, no permits".into(),
        }
    }

    fn pool(self, cap: usize) -> String {
        match self {
            Self::CoopTokioHandle => "blocking pool of one shared tokio runtime (max 512)".into(),
            Self::CoopTokioHandleCapped => format!("blocking pool of one shared tokio runtime (max_blocking_threads {cap})"),
            Self::CompioPerRuntime => "AsyncifyPool per runtime (thread_pool_limit 256 default)".into(),
            Self::CompioShared => format!("one AsyncifyPool via reuse_thread_pool (limit {cap})"),
            Self::CompioLimitOnly => format!("AsyncifyPool per runtime (thread_pool_limit {cap})"),
        }
    }

    fn uses_tokio(self) -> bool {
        matches!(self, Self::CoopTokioHandle | Self::CoopTokioHandleCapped)
    }

    fn pool_bound(self, runtimes: usize, cap: usize) -> usize {
        match self {
            Self::CoopTokioHandle | Self::CoopTokioHandleCapped | Self::CompioShared => cap,
            Self::CompioPerRuntime | Self::CompioLimitOnly => runtimes * cap,
        }
    }

    fn capped_by_permits(self) -> bool {
        self != Self::CompioLimitOnly
    }
}

struct K3Run {
    before: usize,
    peak: usize,
    after: usize,
    max_running: usize,
    wall: Duration,
}

fn k3(runtimes: usize, offloads: usize, cap: usize, work_us: u64) -> Result<()> {
    println!("\n## K3 blocking pool: {runtimes} runtimes x {offloads} offloads, permit cap {cap}, {work_us} us per closure\n");
    luradb::core::coop::init(cap);
    println!("coop::offload in a compio task without a tokio context: {}", coop_offload_without_tokio()?);

    let work = Duration::from_micros(work_us);
    let mut rows = Vec::new();
    let mut over_cap = Vec::new();
    for via in [
        OffloadVia::CoopTokioHandle,
        OffloadVia::CoopTokioHandleCapped,
        OffloadVia::CompioPerRuntime,
        OffloadVia::CompioShared,
        OffloadVia::CompioLimitOnly,
    ] {
        let run = run_k3(via, runtimes, offloads, cap, work)?;
        let bound = run.before + 1 + runtimes + usize::from(via.uses_tokio()) + via.pool_bound(runtimes, cap);
        if via.capped_by_permits() && run.max_running > cap {
            over_cap.push(via.label(cap));
        }
        rows.push(vec![
            via.label(cap),
            via.pool(cap),
            run.before.to_string(),
            run.peak.to_string(),
            run.after.to_string(),
            bound.to_string(),
            if run.peak <= bound { "yes".into() } else { "NO".into() },
            run.max_running.to_string(),
            millis(run.wall),
        ]);
    }
    print_table(
        "threads (/proc/self/status Threads:)",
        &["offload via", "blocking pool", "before", "peak", "after", "bound", "peak <= bound", "max concurrent closures", "wall"],
        &rows,
    );
    println!("bound = before + sampler thread + {runtimes} runtime threads + tokio worker (coop rows) + pool bound (cap, or runtimes x cap per-runtime)");
    println!("after = runtime threads joined + 200 ms; process-wide pools (tokio runtime, shared AsyncifyPool) still alive");
    ensure!(over_cap.is_empty(), "K3 permit cap exceeded: {over_cap:?}");
    Ok(())
}

fn coop_offload_without_tokio() -> Result<String> {
    let rt = compio_runtime(shard_proactor())?;
    let outcome = quietly(|| rt.block_on(rt.spawn(luradb::core::coop::offload(|| 1u8))));
    Ok(match outcome {
        Ok(_) => "runs".to_string(),
        Err(JoinError::Panicked(payload)) => format!("panics: {}", panic_message(&*payload)),
        Err(e) => format!("{e:?}"),
    })
}

/// Waits up to 2 s for the pool threads of a previous run to exit.
fn settled_thread_count() -> Result<usize> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut count = thread_count()?;
    while count > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
        count = thread_count()?;
    }
    Ok(count)
}

fn run_k3(via: OffloadVia, runtimes: usize, offloads: usize, cap: usize, work: Duration) -> Result<K3Run> {
    let before = settled_thread_count()?;
    let tokio_rt = match via {
        OffloadVia::CoopTokioHandle => {
            Some(tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build()?)
        }
        OffloadVia::CoopTokioHandleCapped => Some(
            tokio::runtime::Builder::new_multi_thread().worker_threads(1).max_blocking_threads(cap).enable_all().build()?,
        ),
        _ => None,
    };
    let shared_pool = AsyncifyPool::new(cap, Duration::from_secs(60));
    let permits = Arc::new(Semaphore::new(cap));
    let running = Arc::new(AtomicUsize::new(0));
    let max_running = Arc::new(AtomicUsize::new(0));
    let sampler = ThreadSampler::start();
    let start = Instant::now();
    let mut threads = Vec::with_capacity(runtimes);
    for i in 0..runtimes {
        let tokio_handle = tokio_rt.as_ref().map(|rt| rt.handle().clone());
        let shared_pool = shared_pool.clone();
        let (permits, running, max_running) = (Arc::clone(&permits), Arc::clone(&running), Arc::clone(&max_running));
        threads.push(std::thread::Builder::new().name(format!("probe-runtime-{i}")).spawn(move || -> Result<()> {
            let _tokio = tokio_handle.as_ref().map(|handle| handle.enter());
            let mut proactor = shard_proactor();
            match via {
                OffloadVia::CompioShared => {
                    proactor.reuse_thread_pool(shared_pool);
                }
                OffloadVia::CompioLimitOnly => {
                    proactor.thread_pool_limit(cap);
                }
                _ => {}
            }
            let rt = compio_runtime(proactor)?;
            let tasks: Vec<_> = (0..offloads)
                .map(|_| {
                    rt.spawn(offload_once(via, Arc::clone(&permits), Arc::clone(&running), Arc::clone(&max_running), work))
                })
                .collect();
            rt.block_on(async {
                for task in tasks {
                    task.await.map_err(join_error)??;
                }
                Ok::<_, anyhow::Error>(())
            })
        })?);
    }
    for thread in threads {
        thread.join().map_err(|_| anyhow!("runtime thread panicked"))??;
    }
    let wall = start.elapsed();
    std::thread::sleep(Duration::from_millis(200));
    let peak = sampler.stop();
    let after = thread_count()?;
    drop(tokio_rt);
    Ok(K3Run { before, peak, after, max_running: max_running.load(Ordering::SeqCst), wall })
}

async fn offload_once(
    via: OffloadVia,
    permits: Arc<Semaphore>,
    running: Arc<AtomicUsize>,
    max_running: Arc<AtomicUsize>,
    work: Duration,
) -> Result<()> {
    let job = move || {
        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
        max_running.fetch_max(now, Ordering::SeqCst);
        let end = Instant::now() + work;
        while Instant::now() < end {
            std::hint::spin_loop();
        }
        running.fetch_sub(1, Ordering::SeqCst);
    };
    match via {
        OffloadVia::CoopTokioHandle | OffloadVia::CoopTokioHandleCapped => luradb::core::coop::offload(job).await,
        OffloadVia::CompioPerRuntime | OffloadVia::CompioShared => {
            let _permit = permits.acquire().await?;
            compio::runtime::spawn_blocking(job).await.map_err(join_error)?;
        }
        OffloadVia::CompioLimitOnly => compio::runtime::spawn_blocking(job).await.map_err(join_error)?,
    }
    Ok(())
}

/// Samples `Threads:` every millisecond on its own thread, which the peak counts.
struct ThreadSampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<usize>,
}

impl ThreadSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut peak = 0;
            while !stopped.load(Ordering::Relaxed) {
                peak = peak.max(thread_count().expect("/proc/self/status is readable"));
                std::thread::sleep(Duration::from_millis(1));
            }
            peak
        });
        Self { stop, handle }
    }

    fn stop(self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("the sampler thread does not panic")
    }
}

// --- K6: 4-KiB pread ---

const PAGE: usize = 4096;
const PAGES_PER_MIB: u64 = (1 << 20) / PAGE as u64;
const MANAGED_BUFFERS: u16 = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum K6Runtime {
    TokioUring,
    Compio,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum K6Buffers {
    Plain,
    Fixed,
    Managed,
}

#[derive(Clone, Copy)]
struct K6Variant {
    runtime: K6Runtime,
    buffers: K6Buffers,
    tasks: usize,
}

impl K6Variant {
    fn runtime_name(self) -> &'static str {
        match self.runtime {
            K6Runtime::TokioUring => "tokio_uring",
            K6Runtime::Compio => "compio",
        }
    }

    fn buffers_name(self) -> &'static str {
        match (self.runtime, self.buffers) {
            (_, K6Buffers::Plain) => "plain Vec<u8>",
            (K6Runtime::TokioUring, K6Buffers::Fixed) => "registered: FixedBufPool + read_fixed_at",
            (K6Runtime::Compio, K6Buffers::Fixed) => "registered: probe's READ_FIXED op",
            (_, K6Buffers::Managed) => "managed: provided buffer ring",
        }
    }
}

struct K6Totals {
    samples: Vec<u32>,
    wall: Duration,
}

struct K6Result {
    variant: K6Variant,
    summary: Summary,
    ops_per_s: f64,
}

fn k6(dir: &Path, file_mib: u64, ops: usize, rounds: usize, cold: bool) -> Result<()> {
    println!("\n## K6 4-KiB pread, tokio_uring vs compio\n");
    let path = dir.join("runtime_probe_k6.dat");
    let _cleanup = TempFile(path.clone());
    write_probe_file(&path, file_mib)?;
    let pages = file_mib * PAGES_PER_MIB;
    if !cold {
        std::io::copy(&mut std::fs::File::open(&path)?, &mut std::io::sink())?;
    }
    println!("file: {} ({file_mib} MiB, {pages} pages), uniform random page-aligned offsets, buffered I/O", path.display());
    println!(
        "page cache before the first variant: {:.1} % resident ({})",
        resident_percent(&path)?,
        if cold { "cold: POSIX_FADV_DONTNEED before every variant" } else { "warm: file read once sequentially" }
    );
    println!("compio ring: shard flags, managed pool {MANAGED_BUFFERS} x 4 KiB; registered buffers via io_uring_register on the ring fd");
    println!("compio ring with 2 registered buffers: {}", compio_fixed_fdinfo()?);
    println!("{ops} reads per variant and round over {rounds} rounds, variants interleaved; latency = submit to completion in the task");

    let mut variants = Vec::new();
    for tasks in [1, 64] {
        for (runtime, buffers) in [
            (K6Runtime::TokioUring, K6Buffers::Plain),
            (K6Runtime::Compio, K6Buffers::Plain),
            (K6Runtime::TokioUring, K6Buffers::Fixed),
            (K6Runtime::Compio, K6Buffers::Fixed),
            (K6Runtime::Compio, K6Buffers::Managed),
        ] {
            variants.push(K6Variant { runtime, buffers, tasks });
        }
    }
    let mut totals: Vec<K6Totals> = variants.iter().map(|_| K6Totals { samples: Vec::new(), wall: Duration::ZERO }).collect();
    for round in 0..rounds {
        for (variant, total) in variants.iter().zip(&mut totals) {
            if cold {
                drop_page_cache(&path)?;
            }
            let (mut samples, wall) = run_k6_variant(*variant, &path, ops, pages, round)?;
            total.samples.append(&mut samples);
            total.wall += wall;
        }
    }
    println!("page cache after the last variant: {:.1} % resident", resident_percent(&path)?);

    let results: Vec<K6Result> = variants
        .iter()
        .zip(&mut totals)
        .map(|(variant, total)| K6Result {
            variant: *variant,
            ops_per_s: total.samples.len() as f64 / total.wall.as_secs_f64(),
            summary: summarize(&mut total.samples),
        })
        .collect();
    let rows: Vec<Vec<String>> = results
        .iter()
        .zip(&totals)
        .map(|(r, total)| {
            vec![
                r.variant.runtime_name().into(),
                r.variant.buffers_name().into(),
                r.variant.tasks.to_string(),
                total.samples.len().to_string(),
                micros(r.summary.p50),
                micros(r.summary.p99),
                micros(r.summary.p999),
                format!("{:.0}", r.ops_per_s),
            ]
        })
        .collect();
    print_table("4-KiB pread", &["runtime", "buffers", "tasks", "reads", "p50 (us)", "p99 (us)", "p99.9 (us)", "reads/s"], &rows);

    let find = |runtime: K6Runtime, buffers: K6Buffers, tasks: usize| {
        results
            .iter()
            .find(|r| r.variant.runtime == runtime && r.variant.buffers == buffers && r.variant.tasks == tasks)
            .expect("every compared variant ran")
    };
    let mut rows = Vec::new();
    for tasks in [1, 64] {
        for (base, candidate) in [
            (K6Buffers::Plain, K6Buffers::Plain),
            (K6Buffers::Fixed, K6Buffers::Fixed),
            (K6Buffers::Fixed, K6Buffers::Managed),
        ] {
            let old = find(K6Runtime::TokioUring, base, tasks);
            let new = find(K6Runtime::Compio, candidate, tasks);
            let regression = f64::from(new.summary.p50) > 1.1 * f64::from(old.summary.p50)
                || f64::from(new.summary.p99) > 1.1 * f64::from(old.summary.p99)
                || new.ops_per_s < 0.9 * old.ops_per_s;
            rows.push(vec![
                tasks.to_string(),
                old.variant.buffers_name().into(),
                new.variant.buffers_name().into(),
                delta(f64::from(new.summary.p50), f64::from(old.summary.p50)),
                delta(f64::from(new.summary.p99), f64::from(old.summary.p99)),
                delta(new.ops_per_s, old.ops_per_s),
                if regression { "YES".into() } else { "no".into() },
            ]);
        }
    }
    print_table(
        "compio vs tokio_uring (K6 a, limit: no regression > 10 %)",
        &["tasks", "tokio_uring", "compio", "p50", "p99", "reads/s", "regression > 10 %"],
        &rows,
    );
    Ok(())
}

fn run_k6_variant(variant: K6Variant, path: &Path, ops: usize, pages: u64, round: usize) -> Result<(Vec<u32>, Duration)> {
    let per_task = (ops / variant.tasks).max(1);
    // Seeds depend on round and task only, so both runtimes read the same offsets.
    let offsets: Vec<Vec<u64>> =
        (0..variant.tasks).map(|task| random_offsets((round * 1000 + task + 1) as u64, per_task, pages)).collect();
    match variant.runtime {
        K6Runtime::TokioUring => tokio_uring::start(tokio_uring_k6(path, variant.buffers, offsets)),
        K6Runtime::Compio => compio_k6(path, variant.buffers, offsets),
    }
}

async fn tokio_uring_k6(path: &Path, buffers: K6Buffers, offsets: Vec<Vec<u64>>) -> Result<(Vec<u32>, Duration)> {
    let file = Rc::new(tokio_uring::fs::File::open(path).await?);
    let pool = FixedBufPool::new(std::iter::repeat_with(|| Vec::with_capacity(PAGE)).take(offsets.len()));
    if buffers == K6Buffers::Fixed {
        pool.register()?;
    }
    let start = Instant::now();
    let mut tasks = Vec::with_capacity(offsets.len());
    for task_offsets in offsets {
        let fixed = match buffers {
            K6Buffers::Fixed => Some(pool.try_next(PAGE).ok_or_else(|| anyhow!("fixed buffer pool exhausted"))?),
            _ => None,
        };
        tasks.push(tokio_uring::spawn(tokio_uring_reads(Rc::clone(&file), fixed, task_offsets)));
    }
    let mut samples = Vec::new();
    for task in tasks {
        samples.extend(task.await??);
    }
    Ok((samples, start.elapsed()))
}

async fn tokio_uring_reads(
    file: Rc<tokio_uring::fs::File>,
    mut fixed: Option<FixedBuf>,
    offsets: Vec<u64>,
) -> Result<Vec<u32>> {
    let mut latencies = Vec::with_capacity(offsets.len());
    let mut plain = Vec::with_capacity(PAGE);
    for offset in offsets {
        let start = Instant::now();
        let tag = if let Some(buf) = fixed.take() {
            let (read, buf) = file.read_fixed_at(buf, offset).await;
            latencies.push(ns(start.elapsed()));
            ensure!(read? == PAGE, "short fixed read");
            let tag = page_tag(&buf);
            fixed = Some(buf);
            tag
        } else {
            let (read, buf) = file.read_at(plain, offset).await;
            latencies.push(ns(start.elapsed()));
            plain = buf;
            ensure!(read? == PAGE, "short read");
            page_tag(&plain)
        };
        ensure!(tag == offset / PAGE as u64, "read returned the wrong page");
    }
    Ok(latencies)
}

fn compio_k6(path: &Path, buffers: K6Buffers, offsets: Vec<Vec<u64>>) -> Result<(Vec<u32>, Duration)> {
    // Declared before the runtime so the registered memory outlives the ring.
    let mut fixed: Vec<Box<[u8]>> = match buffers {
        K6Buffers::Fixed => vec![vec![0u8; PAGE].into_boxed_slice(); offsets.len()],
        _ => Vec::new(),
    };
    let mut proactor = shard_proactor();
    proactor
        .buffer_pool_size(NonZeroU16::new(MANAGED_BUFFERS).expect("non-zero"))
        .buffer_pool_buffer_len(PAGE);
    let rt = compio_runtime(proactor)?;
    rt.block_on(async {
        let file = Rc::new(compio::fs::File::open(path).await?);
        let slots: Vec<Option<(*mut u8, u16)>> = if fixed.is_empty() {
            vec![None; offsets.len()]
        } else {
            register_buffers(Runtime::with_current(|rt| rt.as_raw_fd()), &mut fixed)?;
            fixed.iter_mut().enumerate().map(|(i, buf)| Some((buf.as_mut_ptr(), i as u16))).collect()
        };
        let start = Instant::now();
        let tasks: Vec<_> = offsets
            .into_iter()
            .zip(slots)
            .map(|(task_offsets, slot)| compio::runtime::spawn(compio_reads(Rc::clone(&file), buffers, slot, task_offsets)))
            .collect();
        let mut samples = Vec::new();
        for task in tasks {
            samples.extend(task.await.map_err(join_error)??);
        }
        Ok::<_, anyhow::Error>((samples, start.elapsed()))
    })
}

async fn compio_reads(
    file: Rc<compio::fs::File>,
    buffers: K6Buffers,
    fixed: Option<(*mut u8, u16)>,
    offsets: Vec<u64>,
) -> Result<Vec<u32>> {
    let mut latencies = Vec::with_capacity(offsets.len());
    let mut plain = Vec::with_capacity(PAGE);
    for offset in offsets {
        let start = Instant::now();
        let tag = match (buffers, fixed) {
            (K6Buffers::Fixed, Some((buf, index))) => {
                let op = ReadFixedAt { fd: file.as_raw_fd(), buf, len: PAGE as u32, index, offset };
                let BufResult(read, _) = compio::runtime::submit(op).await;
                latencies.push(ns(start.elapsed()));
                ensure!(read? == PAGE, "short fixed read");
                // SAFETY: the completed read filled this registered page.
                page_tag(unsafe { std::slice::from_raw_parts(buf, PAGE) })
            }
            (K6Buffers::Managed, _) => {
                let page = file.read_managed_at(PAGE, offset).await?;
                latencies.push(ns(start.elapsed()));
                let page = page.ok_or_else(|| anyhow!("unexpected end of file"))?;
                ensure!(page.len() == PAGE, "short managed read");
                page_tag(&page)
            }
            _ => {
                let BufResult(read, buf) = file.read_at(plain, offset).await;
                latencies.push(ns(start.elapsed()));
                plain = buf;
                ensure!(read? == PAGE, "short read");
                page_tag(&plain)
            }
        };
        ensure!(tag == offset / PAGE as u64, "read returned the wrong page");
    }
    Ok(latencies)
}

/// `IORING_OP_READ_FIXED` into a buffer registered by [`register_buffers`];
/// compio has neither the op nor buffer registration.
struct ReadFixedAt {
    fd: RawFd,
    buf: *mut u8,
    len: u32,
    index: u16,
    offset: u64,
}

// SAFETY: `buf` lies in memory registered on this ring that outlives the ring.
unsafe impl OpCode for ReadFixedAt {
    type Control = ();

    fn create_entry(&mut self, _: &mut Self::Control) -> OpEntry {
        io_uring_compio::opcode::ReadFixed::new(io_uring_compio::types::Fd(self.fd), self.buf, self.len, self.index)
            .offset(self.offset)
            .build()
            .into()
    }
}

/// Registers `bufs` as fixed buffers on the ring behind `ring_fd`; must run
/// on the ring's thread (SINGLE_ISSUER).
fn register_buffers(ring_fd: RawFd, bufs: &mut [Box<[u8]>]) -> Result<()> {
    const IORING_REGISTER_BUFFERS: libc::c_long = 0;
    let iovecs: Vec<libc::iovec> =
        bufs.iter_mut().map(|buf| libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }).collect();
    // SAFETY: `iovecs` describes live buffers; the kernel copies the array.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            libc::c_long::from(ring_fd),
            IORING_REGISTER_BUFFERS,
            iovecs.as_ptr(),
            iovecs.len() as libc::c_long,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("io_uring_register(IORING_REGISTER_BUFFERS) failed");
    }
    Ok(())
}

fn compio_fixed_fdinfo() -> Result<String> {
    let mut bufs = vec![vec![0u8; PAGE].into_boxed_slice(); 2];
    let rt = compio_runtime(shard_proactor())?;
    rt.block_on(async {
        let ring_fd = Runtime::with_current(|rt| rt.as_raw_fd());
        register_buffers(ring_fd, &mut bufs)?;
        Ok::<_, anyhow::Error>(ring_fdinfo(ring_fd))
    })
}

fn page_tag(page: &[u8]) -> u64 {
    u64::from_le_bytes(page[..8].try_into().expect("a page holds 8 bytes"))
}

/// Every 8 bytes of page `n` hold `n` (little endian), so a read can verify its page.
fn write_probe_file(path: &Path, mib: u64) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
    let mut chunk = vec![0u8; 1 << 20];
    for mib_index in 0..mib {
        for (i, page) in chunk.chunks_exact_mut(PAGE).enumerate() {
            let tag = (mib_index * PAGES_PER_MIB + i as u64).to_le_bytes();
            for word in page.chunks_exact_mut(8) {
                word.copy_from_slice(&tag);
            }
        }
        file.write_all(&chunk)?;
    }
    file.sync_all()?;
    Ok(())
}

fn random_offsets(seed: u64, n: usize, pages: u64) -> Vec<u64> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % pages) * PAGE as u64
        })
        .collect()
}

fn resident_percent(path: &Path) -> Result<f64> {
    let file = std::fs::File::open(path)?;
    let len = usize::try_from(file.metadata()?.len())?;
    // SAFETY: sysconf has no preconditions.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    // SAFETY: read-only shared mapping of an open file, unmapped below.
    let addr =
        unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0) };
    if addr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).context("mmap for mincore failed");
    }
    let mut resident = vec![0u8; len.div_ceil(page)];
    // SAFETY: `resident` holds one byte per page of the mapping.
    let rc = unsafe { libc::mincore(addr, len, resident.as_mut_ptr()) };
    let err = std::io::Error::last_os_error();
    // SAFETY: unmaps exactly the mapping created above.
    unsafe { libc::munmap(addr, len) };
    ensure!(rc == 0, "mincore failed: {err}");
    Ok(resident.iter().filter(|b| **b & 1 == 1).count() as f64 * 100.0 / resident.len() as f64)
}

fn drop_page_cache(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)?;
    // SAFETY: advice on an open descriptor.
    let rc = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    ensure!(rc == 0, "posix_fadvise(DONTNEED) failed: {}", std::io::Error::from_raw_os_error(rc));
    Ok(())
}
