//! The resource watch: once a second, the free space of every volume the
//! data paths lie on and the server's own anonymous memory, against the
//! configured thresholds. Its state warns, refuses writes while space or
//! memory runs short, and lets them in again once both recovered.

use crate::config::{LuraConfig, MIN_MEMORY_BUDGET};
use crate::control::system;
use crate::storage::write_failures::IoFailures;
use parking_lot::RwLock;
use serde::Serialize;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often the watch reads its probes.
pub const RESOURCE_WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// What a refused write tells the client to wait, in seconds.
pub const RETRY_AFTER_SECS: u64 = 5;
/// A state that lasts repeats its log line every this many ticks.
pub(crate) const REPEAT_TICKS: u64 = 60;
const MIN_DISK_FREE_BLOCK: u64 = 64 * 1024 * 1024;
/// Memory warns from, refuses writes from and resumes below these shares of
/// the budget, in percent.
const MEMORY_WARN_PERCENT: u64 = 80;
const MEMORY_BLOCK_PERCENT: u64 = 95;
const MEMORY_RESUME_PERCENT: u64 = 90;
/// While writes are refused for memory, the watch has the MemTables flushed
/// and free heap returned to the kernel on the first tick and every this
/// many ticks after it.
const MEMORY_RELIEF_EVERY: u64 = 10;

/// The flushes of every MemTable the watch asked for during a memory block,
/// and how many of them the write-ahead log checkpoint has done.
#[derive(Default)]
pub struct Relief {
    pub(crate) requested: AtomicU64,
    pub(crate) flushed: AtomicU64,
}

/// How the watch returns free heap to the kernel.
enum Trimmer {
    /// `malloc_trim` on a short-lived thread: it locks every arena in turn
    /// and must not hold up the control plane.
    Thread,
    #[cfg(test)]
    Inline(Box<dyn Fn() + Send + Sync>),
}

/// How the server stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Normal,
    Warning,
    Blocked,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Normal => "ok",
            Level::Warning => "warning",
            Level::Blocked => "blocked",
        }
    }
}

// The shared state byte: the level in the low two bits, then why writes are
// refused and whether a backup may run meanwhile.
const LEVEL_BITS: u8 = 0b11;
const FOR_DISK: u8 = 1 << 2;
const FOR_MEMORY: u8 = 1 << 3;
const BACKUP_ALLOWED: u8 = 1 << 4;

/// A write refused while disk space or memory runs short; the API answers it
/// with 507 Insufficient Storage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("507 Insufficient Storage: write blocked: {reason}, retry in {} s", RETRY_AFTER_SECS)]
pub struct WriteBlocked {
    reason: &'static str,
}

impl WriteBlocked {
    /// The refusal anywhere in `e`'s chain, which context may hide behind its
    /// own text.
    pub fn in_chain(e: &anyhow::Error) -> Option<Self> {
        e.chain().find_map(|cause| cause.downcast_ref::<Self>()).cloned()
    }
}

/// The resource state as writers, the bridge and the health report read it;
/// clones share it. A fresh one is normal and stays so unless a
/// [`ResourceWatch`] sets it, and reads free space from the host.
#[derive(Clone, Default)]
pub struct Resources(Arc<Shared>);

#[derive(Default)]
struct Shared {
    state: AtomicU8,
    report: RwLock<ResourceReport>,
    /// The watch's probe; the host's without a watch.
    probe: Option<Arc<dyn Probe>>,
    io: IoFailures,
}

impl Resources {
    pub(crate) fn with_probe(probe: Arc<dyn Probe>) -> Self {
        Self(Arc::new(Shared { probe: Some(probe), ..Shared::default() }))
    }

    fn state(&self) -> u8 {
        self.0.state.load(Ordering::Acquire)
    }

    pub fn level(&self) -> Level {
        level_of(self.state())
    }

    /// `Err` while writes are refused.
    pub fn check_write(&self) -> Result<(), WriteBlocked> {
        let state = self.state();
        if level_of(state) != Level::Blocked {
            return Ok(());
        }
        let reason = match (state & FOR_DISK != 0, state & FOR_MEMORY != 0) {
            (true, true) => "disk space below threshold and memory budget exhausted",
            (false, true) => "memory budget exhausted",
            _ => "disk space below threshold",
        };
        Err(WriteBlocked { reason })
    }

    /// Whether a backup may run: always while writes go in; while they are
    /// refused only into a backup directory on a volume of its own above the
    /// warn threshold, and not when memory is short.
    pub fn backup_allowed(&self) -> bool {
        self.level() != Level::Blocked || self.state() & BACKUP_ALLOWED != 0
    }

    /// The state for the health report and the metrics.
    pub fn report(&self) -> ResourceReport {
        self.0.report.read().clone()
    }

    /// The failed writes of the data files, for the health report.
    pub fn io(&self) -> &IoFailures {
        &self.0.io
    }

    /// The bytes free on the volume of `path`, which exists; `None` when
    /// they cannot be read.
    pub fn free_space(&self, path: &Path) -> Option<u64> {
        let space = match &self.0.probe {
            Some(probe) => probe.space(path),
            None => SystemProbe.space(path),
        };
        space.ok().map(|space| space.free)
    }

    #[cfg(test)]
    pub(crate) fn block_for_test(&self, memory: bool, backup_allowed: bool) {
        let reason = if memory { FOR_MEMORY } else { FOR_DISK };
        let backup = if backup_allowed { BACKUP_ALLOWED } else { 0 };
        self.0.state.store(Level::Blocked as u8 | reason | backup, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn unblock_for_test(&self) {
        self.0.state.store(Level::Normal as u8, Ordering::Release);
    }
}

fn level_of(state: u8) -> Level {
    match state & LEVEL_BITS {
        0 => Level::Normal,
        1 => Level::Warning,
        _ => Level::Blocked,
    }
}

/// Counts the runs a job skipped for want of disk space: the first of a row
/// and every 60th after it get a log line.
#[derive(Default)]
pub struct SpaceWait(std::sync::atomic::AtomicU64);

impl SpaceWait {
    /// Counts a skipped run; whether it gets a log line.
    pub fn skipped(&self) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed).is_multiple_of(REPEAT_TICKS)
    }

    /// The job ran: the next skip starts a new row.
    pub fn ran(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// `resources` of `GET /store-api/metrics`.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceReport {
    /// `ok`, `warning` (below a warn threshold) or `blocked` (writes refused).
    pub state: &'static str,
    /// Every volume a data path lies on.
    pub disk: Vec<DiskReport>,
    pub memory: MemoryReport,
}

impl Default for ResourceReport {
    fn default() -> Self {
        Self { state: Level::Normal.name(), disk: Vec::new(), memory: MemoryReport::default() }
    }
}

/// `resources` of `GET /health`: the states of the report, without volumes,
/// paths or numbers.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ResourceState {
    /// `ok`, `warning` (below a warn threshold) or `blocked` (writes refused).
    pub state: &'static str,
    /// The worst state of the data volumes: `ok`, `warning` or `blocked`.
    pub disk_state: &'static str,
    /// `ok`, `warning` or `blocked`.
    pub memory_state: &'static str,
}

impl From<&ResourceReport> for ResourceState {
    fn from(report: &ResourceReport) -> Self {
        let rank = |state: &str| match state {
            "blocked" => 2,
            "warning" => 1,
            _ => 0,
        };
        Self {
            state: report.state,
            disk_state: report.disk.iter().map(|disk| disk.state).max_by_key(|state| rank(state)).unwrap_or(Level::Normal.name()),
            memory_state: report.memory.state,
        }
    }
}

/// A volume in the resource report.
#[derive(Debug, Clone, Serialize)]
pub struct DiskReport {
    /// A data path on the volume.
    pub path: String,
    pub size_bytes: u64,
    /// Free to the server, without the space reserved for root.
    pub free_bytes: u64,
    /// `ok`, `warning` or `blocked`.
    pub state: &'static str,
}

/// The server's anonymous memory against its budget.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryReport {
    pub rss_anon_bytes: u64,
    pub budget_bytes: u64,
    /// `ok`, `warning` or `blocked`.
    pub state: &'static str,
}

impl Default for MemoryReport {
    fn default() -> Self {
        Self { rss_anon_bytes: 0, budget_bytes: 0, state: Level::Normal.name() }
    }
}

/// The volume a path lies on: its device, its size and the bytes free to
/// an unprivileged process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub device: u64,
    pub size: u64,
    pub free: u64,
}

/// Where the watch reads disk space and memory.
pub trait Probe: Send + Sync {
    /// The volume of `path`, which exists.
    fn space(&self, path: &Path) -> std::io::Result<Space>;
    /// `RssAnon` of this process.
    fn rss_anon(&self) -> std::io::Result<u64>;
    /// `MemTotal` and the `memory.max` of this process's cgroup, `None`
    /// without a limit.
    fn mem_limits(&self) -> std::io::Result<(u64, Option<u64>)>;
}

/// The probe of the host: `statvfs`, `/proc` and cgroup v2.
pub struct SystemProbe;

impl Probe for SystemProbe {
    fn space(&self, path: &Path) -> std::io::Result<Space> {
        let device = std::fs::metadata(path)?.dev();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // Safe: `stat` is plain old data that `statvfs` fills in.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let block = stat.f_frsize as u64;
        Ok(Space { device, size: stat.f_blocks as u64 * block, free: stat.f_bavail as u64 * block })
    }

    fn rss_anon(&self) -> std::io::Result<u64> {
        status_kib(&std::fs::read_to_string("/proc/self/status")?, "RssAnon:")
    }

    fn mem_limits(&self) -> std::io::Result<(u64, Option<u64>)> {
        let total = status_kib(&std::fs::read_to_string("/proc/meminfo")?, "MemTotal:")?;
        let limit = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|cgroups| cgroup_v2_path(&cgroups))
            .and_then(|path| std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max")).ok())
            .and_then(|max| memory_max(&max));
        Ok((total, limit))
    }
}

/// The value of a `<field> <n> kB` line of `/proc/self/status` or
/// `/proc/meminfo`, in bytes.
fn status_kib(text: &str, field: &str) -> std::io::Result<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kib| kib.parse::<u64>().ok())
        .map(|kib| kib * 1024)
        .ok_or_else(|| std::io::Error::other(format!("no {field} line")))
}

/// The cgroup v2 path in `/proc/self/cgroup` (`0::/path`).
fn cgroup_v2_path(cgroups: &str) -> Option<String> {
    cgroups.lines().find_map(|line| line.strip_prefix("0::")).map(|path| path.trim_end_matches('/').to_string())
}

/// A `memory.max`: bytes, or `None` for `max`.
fn memory_max(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// A notice for the server log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: tracing::Level,
    pub line: String,
}

impl Notice {
    fn info(line: String) -> Self {
        Self { level: tracing::Level::INFO, line }
    }

    fn warn(line: String) -> Self {
        Self { level: tracing::Level::WARN, line }
    }

    fn error(line: String) -> Self {
        Self { level: tracing::Level::ERROR, line }
    }
}

/// Writes `notices` to the server log.
pub fn log(notices: &[Notice]) {
    for notice in notices {
        match notice.level {
            tracing::Level::ERROR => tracing::error!("{}", notice.line),
            tracing::Level::WARN => tracing::warn!("{}", notice.line),
            _ => tracing::info!("{}", notice.line),
        }
    }
}

/// The exit code of a start refused with [`NoRoomToRecover`].
pub const EXIT_NO_ROOM_TO_RECOVER: u8 = 4;

/// A start with less free space than its recovery may write.
#[derive(Debug, thiserror::Error)]
#[error(
    "not enough free disk space to recover: {volume} has {free} bytes free, the start needs {needed} \
     (the write-ahead logs that recover onto the volume)"
)]
pub struct NoRoomToRecover {
    volume: String,
    free: u64,
    needed: u64,
}

/// A volume the watch reads, with its thresholds in bytes.
struct Volume {
    /// The first data path on it.
    path: PathBuf,
    device: u64,
    warn: u64,
    block: u64,
    resume: u64,
    space: Space,
}

/// The files of one engine the recovery reads and writes.
struct EngineFiles {
    wal: PathBuf,
    vlog: PathBuf,
    sstables: PathBuf,
}

/// How a probe value stands against its thresholds.
#[derive(Debug, Clone, Copy, Default)]
struct Reading {
    below_warn: bool,
    below_resume: bool,
    below_block: bool,
}

impl Reading {
    fn of_free(free: u64, volume: &Volume) -> Self {
        Self { below_warn: free < volume.warn, below_resume: free < volume.resume, below_block: free < volume.block }
    }

    fn of_memory(rss: u64, budget: u64) -> Self {
        let share = |percent: u64| u128::from(rss) * 100 >= u128::from(budget) * u128::from(percent);
        Self {
            below_warn: share(MEMORY_WARN_PERCENT),
            below_resume: share(MEMORY_RESUME_PERCENT),
            below_block: share(MEMORY_BLOCK_PERCENT),
        }
    }

    /// Its state in the report while the server is at `level`.
    fn state(self, level: Level) -> &'static str {
        if self.below_block || (level == Level::Blocked && self.below_resume) {
            Level::Blocked.name()
        } else if self.below_warn {
            Level::Warning.name()
        } else {
            Level::Normal.name()
        }
    }
}

/// Reads the probes once a tick, sets the state of its [`Resources`] and
/// says what the server log gets.
pub struct ResourceWatch {
    probe: Arc<dyn Probe>,
    volumes: Vec<Volume>,
    budget: u64,
    /// The volume of `backup.dir`, when backups are on.
    backup_device: Option<u64>,
    resources: Resources,
    level: Level,
    /// Why writes are refused: disk, memory.
    reasons: (bool, bool),
    ticks_in_state: u64,
    /// Ticks in a row the readings allowed the next better level.
    ticks_above: u32,
    rss: u64,
    relief: Arc<Relief>,
    /// Ticks so far of a block that holds for memory.
    memory_ticks: u64,
    /// The flush request the last trim followed.
    trimmed_for: u64,
    trimmer: Trimmer,
    trim_running: Arc<AtomicBool>,
}

impl ResourceWatch {
    /// The first step of a start, before any recovery: creates every data
    /// directory, relative ones under `base`, and the parents of the data
    /// files; finds the volumes they lie on and resolves the thresholds on
    /// each; refuses a volume the recovery writes to with less free than the
    /// write-ahead logs recovering onto it ([`NoRoomToRecover`]); resolves
    /// the memory budget. Returns the watch, whose state stays normal until
    /// its first [`Self::tick`], and its start lines.
    pub fn start(config: &LuraConfig, base: &Path, probe: Arc<dyn Probe>) -> anyhow::Result<(Self, Vec<Notice>)> {
        let paths = create_data_dirs(config, base)?;
        let [warn, block, resume] = config.resources.disk_thresholds()?;
        let mut volumes: Vec<Volume> = Vec::new();
        for path in &paths {
            let space = probe.space(path).map_err(|e| anyhow::anyhow!("reading the free space of {}: {e}", path.display()))?;
            if volumes.iter().any(|volume| volume.device == space.device) {
                continue;
            }
            let (warn, block, resume) = (warn.of(space.size), block.of(space.size), resume.of(space.size));
            anyhow::ensure!(
                block <= resume && resume <= warn && block >= MIN_DISK_FREE_BLOCK,
                "invalid config: resources thresholds on the volume of {} ({} bytes) resolve to \
                 disk_free_block {block}, disk_free_resume {resume} and disk_free_warn {warn} bytes; \
                 they need block <= resume <= warn and block >= {MIN_DISK_FREE_BLOCK} bytes",
                path.display(),
                space.size
            );
            volumes.push(Volume { path: path.clone(), device: space.device, warn, block, resume, space });
        }

        let engines = engine_files(config, base);
        for volume in &volumes {
            let on_volume = |path: &PathBuf| {
                existing(path).and_then(|path| probe.space(&path).ok()).is_some_and(|space| space.device == volume.device)
            };
            let needed: u64 = engines
                .iter()
                .filter(|engine| on_volume(&engine.sstables) || on_volume(&engine.vlog))
                .map(|engine| wal_bytes(&engine.wal))
                .sum();
            if volume.space.free < needed {
                return Err(NoRoomToRecover {
                    volume: volume.path.display().to_string(),
                    free: volume.space.free,
                    needed,
                }
                .into());
            }
        }

        let budget_threshold = config.resources.memory_budget()?;
        let (total, cgroup) = probe.mem_limits().map_err(|e| anyhow::anyhow!("reading the memory limits: {e}"))?;
        let limit = cgroup.map_or(total, |cgroup| cgroup.min(total));
        let budget = budget_threshold.of(limit);
        anyhow::ensure!(
            budget >= MIN_MEMORY_BUDGET,
            "invalid config: resources.memory_budget ({}) resolves to {budget} bytes of {limit}; \
             it must be at least 256 MiB",
            config.resources.memory_budget
        );

        let mut notices: Vec<Notice> = volumes
            .iter()
            .map(|v| {
                Notice::info(format!(
                    "Watching the volume of {}: {} bytes, {} free; warning below {} bytes free, \
                     writes refused below {}, resumed above {}.",
                    v.path.display(),
                    v.space.size,
                    v.space.free,
                    v.warn,
                    v.block,
                    v.resume
                ))
            })
            .collect();
        let source = if cgroup.is_some_and(|cgroup| cgroup < total) { "cgroup memory.max" } else { "MemTotal" };
        notices.push(Notice::info(format!(
            "Memory budget {budget} bytes of {limit} ({source}); warning from {MEMORY_WARN_PERCENT} %, \
             writes refused from {MEMORY_BLOCK_PERCENT} %, resumed below {MEMORY_RESUME_PERCENT} %."
        )));

        let backup_device = config
            .backup
            .enabled
            .then(|| probe.space(&base.join(&config.backup.dir)).ok().map(|space| space.device))
            .flatten();
        let watch = Self {
            resources: Resources::with_probe(Arc::clone(&probe)),
            probe,
            volumes,
            budget,
            backup_device,
            level: Level::Normal,
            reasons: (false, false),
            ticks_in_state: 0,
            ticks_above: 0,
            rss: 0,
            relief: Arc::default(),
            memory_ticks: 0,
            trimmed_for: 0,
            trimmer: Trimmer::Thread,
            trim_running: Arc::default(),
        };
        Ok((watch, notices))
    }

    pub fn resources(&self) -> Resources {
        self.resources.clone()
    }

    /// The flush requests, for the write-ahead log checkpoint to serve.
    pub fn relief(&self) -> Arc<Relief> {
        Arc::clone(&self.relief)
    }

    /// The warning about memory every instance takes regardless of load,
    /// when `items` sum to more than half the budget.
    pub fn fixed_memory_notice(&self, items: &[(&'static str, u64)]) -> Option<Notice> {
        let sum: u64 = items.iter().map(|(_, bytes)| bytes).sum();
        if sum * 2 <= self.budget {
            return None;
        }
        let listed: Vec<String> = items.iter().map(|(name, bytes)| format!("{name} {bytes}")).collect();
        Some(Notice::warn(format!(
            "The fixed memory of the server, {sum} bytes ({}), takes more than half the memory budget of {} bytes.",
            listed.join(", "),
            self.budget
        )))
    }

    /// Reads every probe, moves the state on, publishes it and relieves a
    /// memory block; returns the lines for the server log. A probe that
    /// fails keeps its last value.
    pub fn tick(&mut self) -> Vec<Notice> {
        for volume in &mut self.volumes {
            if let Ok(space) = self.probe.space(&volume.path) {
                volume.space = space;
            }
        }
        if let Ok(rss) = self.probe.rss_anon() {
            self.rss = rss;
        }
        let disk: Vec<Reading> = self.volumes.iter().map(|v| Reading::of_free(v.space.free, v)).collect();
        let memory = Reading::of_memory(self.rss, self.budget);
        let below = |test: fn(&Reading) -> bool| disk.iter().chain([&memory]).any(test);
        let (block, hold, warn) = (below(|r| r.below_block), below(|r| r.below_resume), below(|r| r.below_warn));

        let previous = self.level;
        // Readings that keep the level; better ones lead to the next better
        // level on the second tick in a row.
        let keeps = match previous {
            Level::Blocked => hold,
            Level::Warning => warn,
            Level::Normal => true,
        };
        self.level = if block {
            Level::Blocked
        } else if previous == Level::Normal {
            if warn { Level::Warning } else { Level::Normal }
        } else if keeps {
            previous
        } else {
            self.ticks_above += 1;
            match (previous, self.ticks_above >= 2) {
                (Level::Blocked, true) => Level::Warning,
                (Level::Warning, true) => Level::Normal,
                (level, _) => level,
            }
        };
        if keeps || self.level != previous {
            self.ticks_above = 0;
        }
        // A reason holds from its first tick below block until the block ends.
        if self.level == Level::Blocked {
            self.reasons.0 |= disk.iter().any(|r| r.below_block);
            self.reasons.1 |= memory.below_block;
        } else {
            self.reasons = (false, false);
        }
        self.ticks_in_state = if self.level == previous { self.ticks_in_state + 1 } else { 0 };
        self.publish(&disk, memory);
        let mut notices = self.notices(previous, &disk, memory);
        notices.extend(self.relieve());
        notices
    }

    /// During a block that holds for memory, asks for a flush of every
    /// MemTable on its first tick and every [`MEMORY_RELIEF_EVERY`] ticks,
    /// unless the last one is not done; once a flush is done, returns free
    /// heap to the kernel. The line for the first tick.
    fn relieve(&mut self) -> Option<Notice> {
        let mut entry = None;
        if self.reasons.1 {
            let requested = self.relief.requested.load(Ordering::Acquire);
            if self.memory_ticks.is_multiple_of(MEMORY_RELIEF_EVERY) && requested <= self.relief.flushed.load(Ordering::Acquire) {
                self.relief.requested.store(requested + 1, Ordering::Release);
            }
            if self.memory_ticks == 0 {
                entry = Some(Notice::info("Memory block: flushing MemTables and returning free heap to the kernel.".to_string()));
            }
            self.memory_ticks += 1;
        } else {
            self.memory_ticks = 0;
        }
        let requested = self.relief.requested.load(Ordering::Acquire);
        if requested > self.trimmed_for && self.relief.flushed.load(Ordering::Acquire) == requested && self.trim() {
            self.trimmed_for = requested;
        }
        entry
    }

    /// Starts a trim unless one runs; whether it started.
    fn trim(&self) -> bool {
        if self.trim_running.swap(true, Ordering::AcqRel) {
            return false;
        }
        let running = Arc::clone(&self.trim_running);
        match &self.trimmer {
            Trimmer::Thread => {
                let spawned = std::thread::Builder::new().name("luradb-trim".to_string()).spawn(move || {
                    // Safe: takes no pointers and only touches the allocator.
                    unsafe { libc::malloc_trim(0) };
                    running.store(false, Ordering::Release);
                });
                if spawned.is_err() {
                    self.trim_running.store(false, Ordering::Release);
                }
                spawned.is_ok()
            }
            #[cfg(test)]
            Trimmer::Inline(trim) => {
                trim();
                running.store(false, Ordering::Release);
                true
            }
        }
    }

    fn publish(&self, disk: &[Reading], memory: Reading) {
        let disk_reports: Vec<DiskReport> = self
            .volumes
            .iter()
            .zip(disk)
            .map(|(v, reading)| DiskReport {
                path: v.path.display().to_string(),
                size_bytes: v.space.size,
                free_bytes: v.space.free,
                state: reading.state(self.level),
            })
            .collect();
        let backup_volume_ok = self.backup_device.is_some_and(|device| {
            disk_reports.iter().zip(&self.volumes).any(|(report, v)| v.device == device && report.state == Level::Normal.name())
        });
        let mut state = self.level as u8;
        if self.level == Level::Blocked {
            state |= if self.reasons.0 { FOR_DISK } else { 0 } | if self.reasons.1 { FOR_MEMORY } else { 0 };
            if backup_volume_ok && !self.reasons.1 {
                state |= BACKUP_ALLOWED;
            }
        }
        let report = ResourceReport {
            state: self.level.name(),
            disk: disk_reports,
            memory: MemoryReport { rss_anon_bytes: self.rss, budget_bytes: self.budget, state: memory.state(self.level) },
        };
        *self.resources.0.report.write() = report;
        self.resources.0.state.store(state, Ordering::Release);
    }

    fn notices(&self, previous: Level, disk: &[Reading], memory: Reading) -> Vec<Notice> {
        let repeat = self.level == previous && self.ticks_in_state.is_multiple_of(REPEAT_TICKS);
        match (previous, self.level) {
            (Level::Blocked, Level::Warning) => vec![Notice::info(format!(
                "Writes are accepted again: every volume is above its resume threshold and memory below {MEMORY_RESUME_PERCENT} % of its budget.{}",
                self.reasons_line(disk, memory, |r| r.below_warn, |v| v.warn).map(|line| format!(" Still low: {line}.")).unwrap_or_default()
            ))],
            (Level::Warning, Level::Normal) => {
                vec![Notice::info("Disk space and memory are back above their warn thresholds.".to_string())]
            }
            (_, Level::Blocked) if previous != Level::Blocked || repeat => {
                // Between block and resume, the resources that hold the block.
                let reasons = self
                    .reasons_line(disk, memory, |r| r.below_block, |v| v.block)
                    .or_else(|| self.reasons_line(disk, memory, |r| r.below_resume, |v| v.resume))
                    .unwrap_or_default();
                vec![Notice::error(format!(
                    "Writes refused: {reasons}. Writes, deletes and new backups on a short volume answer 507 \
                     until every volume is above its resume threshold; reads, health, backup downloads and \
                     deletions and sign-ins go on."
                ))]
            }
            (_, Level::Warning) if previous != Level::Warning || repeat => {
                let reasons = self.reasons_line(disk, memory, |r| r.below_warn, |v| v.warn).unwrap_or_default();
                vec![Notice::warn(format!(
                    "Resources running short: {reasons}. Nothing is refused yet; writes are refused below the block threshold."
                ))]
            }
            _ => Vec::new(),
        }
    }

    /// The resources `short` holds for, each with its threshold.
    fn reasons_line(
        &self,
        disk: &[Reading],
        memory: Reading,
        short: fn(&Reading) -> bool,
        threshold: fn(&Volume) -> u64,
    ) -> Option<String> {
        let mut reasons: Vec<String> = self
            .volumes
            .iter()
            .zip(disk)
            .filter(|(_, reading)| short(reading))
            .map(|(v, _)| format!("disk {} free {} of {}, threshold {}", v.path.display(), v.space.free, v.space.size, threshold(v)))
            .collect();
        if short(&memory) {
            reasons.push(format!("memory rss {} of budget {}", self.rss, self.budget));
        }
        (!reasons.is_empty()).then(|| reasons.join("; "))
    }
}

/// The memory each instance holds regardless of load, by item.
pub fn fixed_memory(config: &LuraConfig, shards: u16) -> Vec<(&'static str, u64)> {
    let shards = u64::from(shards);
    let engines = 1 + u64::from(config.json.enabled) + u64::from(config.rel.enabled);
    let default_memtable = crate::engines::lsm::engine::LsmEngineConfig::default().memtable_size_threshold as u64;
    let block_cache = crate::config::BlockCacheConfig::default().capacity_bytes as u64;
    let memtables = 2 * shards * (config.lsm.memtable_size_threshold as u64 + (engines - 1) * default_memtable)
        + 2 * default_memtable;
    let mut items = vec![
        ("memtables", memtables),
        ("block caches", (engines + 1) * block_cache),
        ("buffer pool", (config.buffer_pool.pool_size * crate::core::page::PAGE_SIZE) as u64),
    ];
    if config.shm.enabled {
        items.push(("shared memory", 3 * config.shm.data_buffer_size as u64));
    }
    if config.io_engine.enabled && shards == 1 {
        use crate::core::io_engine::{REGISTERED_BUFFER_COUNT, REGISTERED_BUFFER_SIZE};
        items.push(("registered I/O buffers", (REGISTERED_BUFFER_COUNT * REGISTERED_BUFFER_SIZE) as u64));
    }
    items
}

/// Creates the configured data directories and the directories of the data
/// files, relative ones under `base`; returns every data path that exists,
/// or the directory of one that does not yet, symlinks resolved.
fn create_data_dirs(config: &LuraConfig, base: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let storage = &config.storage;
    let mut dirs = vec![&storage.sstable_dir, &storage.system_dir];
    let mut files = vec![&storage.db_path, &storage.wal_path, &storage.vlog_path];
    for (enabled, wal, vlog, sstables) in [
        (config.json.enabled, &config.json.wal_path, &config.json.vlog_path, &config.json.sstable_dir),
        (config.rel.enabled, &config.rel.wal_path, &config.rel.vlog_path, &config.rel.sstable_dir),
    ] {
        if enabled {
            dirs.push(sstables);
            files.extend([wal, vlog]);
        }
    }
    if config.backup.enabled {
        dirs.push(&config.backup.dir);
    }
    if !config.log.path.is_empty() {
        dirs.push(&config.log.path);
    }
    let create = |dir: &Path| {
        std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("creating the data directory {}: {e}", dir.display()))
    };
    for dir in &dirs {
        create(&base.join(dir))?;
    }
    // A write-ahead log is a directory the storage hub creates and syncs
    // itself; only its parent is made here.
    for file in &files {
        if let Some(parent) = base.join(file).parent() {
            create(parent)?;
        }
    }
    dirs.iter().chain(&files).map(|path| existing(&base.join(path)).ok_or_else(|| anyhow::anyhow!("{} vanished", path))).collect()
}

/// `path` with its symlinks resolved, or its directory when it does not
/// exist yet.
fn existing(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok().or_else(|| path.parent().and_then(|parent| std::fs::canonicalize(parent).ok()))
}

/// The files of every engine whose recovery runs at the start, the system
/// store's included.
fn engine_files(config: &LuraConfig, base: &Path) -> Vec<EngineFiles> {
    let system_dir = base.join(&config.storage.system_dir);
    let mut engines = vec![
        EngineFiles {
            wal: base.join(&config.storage.wal_path),
            vlog: base.join(&config.storage.vlog_path),
            sstables: base.join(&config.storage.sstable_dir),
        },
        EngineFiles {
            wal: system_dir.join(system::WAL_FILE),
            vlog: system_dir.join(system::VLOG_FILE),
            sstables: system_dir.join(system::SSTABLE_DIR),
        },
    ];
    if config.json.enabled {
        engines.push(EngineFiles {
            wal: base.join(&config.json.wal_path),
            vlog: base.join(&config.json.vlog_path),
            sstables: base.join(&config.json.sstable_dir),
        });
    }
    if config.rel.enabled {
        engines.push(EngineFiles {
            wal: base.join(&config.rel.wal_path),
            vlog: base.join(&config.rel.vlog_path),
            sstables: base.join(&config.rel.sstable_dir),
        });
    }
    engines
}

/// The bytes of the write-ahead log at `path`: its segments, or the file of
/// an earlier version, and a log moved aside for its first replay.
fn wal_bytes(path: &Path) -> u64 {
    let size = |path: &Path| std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
    let mut bytes = match std::fs::read_dir(path) {
        Ok(entries) => entries.filter_map(Result::ok).map(|entry| size(&entry.path())).sum(),
        Err(_) => size(path),
    };
    let mut migrating = path.as_os_str().to_owned();
    migrating.push(".migrating");
    bytes += size(Path::new(&migrating));
    bytes
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use parking_lot::Mutex;

    pub(crate) const GB: u64 = 1_000_000_000;
    const GIB: u64 = 1 << 30;

    /// Volumes by path prefix, the longest match counting, and memory, all
    /// set by the test; records every path it was asked about and whether
    /// it existed then.
    pub(crate) struct FakeProbe {
        volumes: Mutex<Vec<(PathBuf, Space)>>,
        rss: Mutex<u64>,
        limits: Mutex<(u64, Option<u64>)>,
        asked: Mutex<Vec<(PathBuf, bool)>>,
    }

    impl FakeProbe {
        /// One 100 GB volume with 50 GB free under `/`, 16 GiB of memory
        /// without a cgroup limit, no memory in use.
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                volumes: Mutex::new(vec![(PathBuf::from("/"), Space { device: 1, size: 100 * GB, free: 50 * GB })]),
                rss: Mutex::new(0),
                limits: Mutex::new((16 * GIB, None)),
                asked: Mutex::new(Vec::new()),
            })
        }

        /// A volume of its own below `root`.
        pub(crate) fn mount(&self, root: &Path, size: u64, free: u64) {
            let mut volumes = self.volumes.lock();
            let device = volumes.len() as u64 + 1;
            volumes.push((root.canonicalize().unwrap(), Space { device, size, free }));
        }

        pub(crate) fn set_free(&self, root: &Path, free: u64) {
            let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            for (path, space) in self.volumes.lock().iter_mut() {
                if *path == root {
                    space.free = free;
                }
            }
        }

        pub(crate) fn set_rss(&self, rss: u64) {
            *self.rss.lock() = rss;
        }

        fn set_limits(&self, total: u64, cgroup: Option<u64>) {
            *self.limits.lock() = (total, cgroup);
        }
    }

    impl Probe for FakeProbe {
        fn space(&self, path: &Path) -> std::io::Result<Space> {
            self.asked.lock().push((path.to_path_buf(), path.exists()));
            let volumes = self.volumes.lock();
            let (_, space) = volumes
                .iter()
                .filter(|(root, _)| path.starts_with(root))
                .max_by_key(|(root, _)| root.as_os_str().len())
                .expect("the root volume");
            Ok(*space)
        }

        fn rss_anon(&self) -> std::io::Result<u64> {
            Ok(*self.rss.lock())
        }

        fn mem_limits(&self) -> std::io::Result<(u64, Option<u64>)> {
            Ok(*self.limits.lock())
        }
    }

    /// A config whose data paths all lie below `dir`.
    pub(crate) fn config_in(dir: &Path) -> LuraConfig {
        let mut config = LuraConfig::default();
        let at = |name: &str| dir.join(name).to_string_lossy().into_owned();
        config.storage.db_path = at("db/luradb.db");
        config.storage.wal_path = at("wal/luradb.wal");
        config.storage.vlog_path = at("data/luradb.vlog");
        config.storage.sstable_dir = at("data/sstables");
        config.storage.system_dir = at("data/sys");
        config.json.enabled = false;
        config.rel.enabled = false;
        config
    }

    fn started(config: &LuraConfig, probe: &Arc<FakeProbe>) -> (ResourceWatch, Vec<Notice>) {
        ResourceWatch::start(config, Path::new("/"), Arc::clone(probe) as Arc<dyn Probe>).unwrap()
    }

    fn start_error(config: &LuraConfig, probe: &Arc<FakeProbe>) -> String {
        let probe = Arc::clone(probe) as Arc<dyn Probe>;
        ResourceWatch::start(config, Path::new("/"), probe).err().expect("a start error").to_string()
    }

    fn lines(notices: &[Notice], level: tracing::Level) -> Vec<&str> {
        notices.iter().filter(|n| n.level == level).map(|n| n.line.as_str()).collect()
    }

    // The host probe reads a volume, this process's anonymous memory and
    // the host's memory.
    #[test]
    fn test_the_system_probe_reads_the_host() {
        let dir = tempfile::TempDir::new().unwrap();
        let space = SystemProbe.space(dir.path()).unwrap();
        assert!(space.size > 0 && space.free <= space.size, "{space:?}");
        assert!(SystemProbe.rss_anon().unwrap() > 0);
        let (total, limit) = SystemProbe.mem_limits().unwrap();
        assert!(total > 0 && limit.is_none_or(|limit| limit > 0), "{total} {limit:?}");
    }

    // Test 1: thresholds resolve on each volume; an order broken only there,
    // a block threshold under 64 MiB and a memory budget under 256 MiB stop
    // the start, naming the volume and the bytes.
    #[test]
    fn test_thresholds_are_checked_per_volume_after_resolution() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let mut config = config_in(dir.path());
        probe.mount(dir.path(), 20 * GB, 15 * GB);
        config.resources.disk_free_warn = "15% max 10 GB".into();
        config.resources.disk_free_resume = "4 GB".into();
        let err = start_error(&config, &probe);
        assert!(err.contains(&dir.path().canonicalize().unwrap().display().to_string()), "{err}");
        assert!(err.contains("disk_free_warn 3000000000") && err.contains("disk_free_resume 4000000000"), "{err}");

        // On 200 GB the same thresholds keep their order.
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 200 * GB, 150 * GB);
        started(&config, &probe);

        let mut config = config_in(dir.path());
        config.resources.disk_free_block = "60 MiB".into();
        config.resources.disk_free_resume = "60 MiB".into();
        assert!(start_error(&config, &probe).contains("block >= 67108864"));

        let mut config = config_in(dir.path());
        config.resources.memory_budget = "1%".into();
        probe.set_limits(16 * GIB, None);
        let err = start_error(&config, &probe);
        assert!(err.contains("resources.memory_budget (1%)") && err.contains("at least 256 MiB"), "{err}");
    }

    // Test 2: below warn the server warns, below block it refuses writes; it
    // leaves the block after two ticks above resume and the warning after
    // two ticks above warn.
    #[test]
    fn test_the_state_moves_with_hysteresis() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        let (mut watch, _) = started(&config_in(dir.path()), &probe);
        let resources = watch.resources();
        let mut level_after = |free: u64| {
            probe.set_free(dir.path(), free);
            watch.tick();
            resources.level()
        };
        // Warn below 10 GB, block below 2 GB, resume above 4 GB.
        assert_eq!(level_after(50 * GB), Level::Normal);
        assert_eq!(level_after(9 * GB), Level::Warning);
        assert_eq!(level_after(19 * GB / 10), Level::Blocked);
        assert_eq!(level_after(3 * GB), Level::Blocked, "below resume");
        assert_eq!(level_after(5 * GB), Level::Blocked, "one tick above resume");
        assert_eq!(level_after(3 * GB), Level::Blocked, "below resume again");
        assert_eq!(level_after(5 * GB), Level::Blocked);
        assert_eq!(level_after(5 * GB), Level::Warning, "two ticks above resume");
        assert_eq!(level_after(11 * GB), Level::Warning);
        assert_eq!(level_after(11 * GB), Level::Normal, "two ticks above warn");
        assert_eq!(level_after(GB), Level::Blocked, "at once below block");
        assert_eq!(
            resources.check_write().unwrap_err().to_string(),
            "507 Insufficient Storage: write blocked: disk space below threshold, retry in 5 s"
        );
        assert!(!resources.backup_allowed());
    }

    // Test 2: of two volumes the worse one counts; the report shows each.
    #[test]
    fn test_the_worse_of_two_volumes_counts() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let config = config_in(dir.path());
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        probe.mount(&dir.path().join("wal"), 100 * GB, 50 * GB);
        let (mut watch, _) = started(&config, &probe);
        probe.set_free(&dir.path().join("wal"), GB);
        watch.tick();
        let report = watch.resources().report();
        assert_eq!(report.state, "blocked");
        let states: Vec<(&str, &str)> =
            report.disk.iter().map(|d| (d.path.rsplit('/').next().unwrap(), d.state)).collect();
        assert!(states.contains(&("wal", "blocked")) && states.iter().filter(|(_, s)| *s == "ok").count() == 1, "{states:?}");
    }

    // Test 2: anonymous memory above 95 % of the budget refuses writes for
    // memory alone while the disk lies between its block and resume
    // thresholds; with the disk below its block threshold too, the line
    // names both.
    #[test]
    fn test_memory_refuses_writes_and_both_reasons_are_named() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        let mut config = config_in(dir.path());
        config.resources.memory_budget = "1 GiB".into();
        let (mut watch, _) = started(&config, &probe);
        let resources = watch.resources();

        probe.set_free(dir.path(), 3 * GB);
        probe.set_rss(GIB * 96 / 100);
        let notices = watch.tick();
        assert_eq!(resources.level(), Level::Blocked);
        assert_eq!(
            resources.check_write().unwrap_err().to_string(),
            "507 Insufficient Storage: write blocked: memory budget exhausted, retry in 5 s"
        );
        let error = lines(&notices, tracing::Level::ERROR).concat();
        assert!(error.contains(&format!("memory rss {} of budget {GIB}", GIB * 96 / 100)), "{error}");
        assert!(!error.contains("disk "), "the disk is above its block threshold: {error}");

        probe.set_free(dir.path(), GB);
        for _ in 0..REPEAT_TICKS - 1 {
            watch.tick();
        }
        let error = lines(&watch.tick(), tracing::Level::ERROR).concat();
        assert!(error.contains("disk ") && error.contains("memory rss"), "{error}");
        assert!(resources.check_write().unwrap_err().to_string().contains("disk space below threshold and memory"));
    }

    // Test 2: the budget is a share of the cgroup's memory.max when that is
    // below MemTotal, of MemTotal when the cgroup has no limit.
    #[test]
    fn test_the_memory_budget_follows_the_lower_limit() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let config = config_in(dir.path());
        probe.set_limits(16 * GIB, Some(4 * GIB));
        let (mut watch, _) = started(&config, &probe);
        watch.tick();
        assert_eq!(watch.resources().report().memory.budget_bytes, 3 * GIB);

        probe.set_limits(16 * GIB, None);
        let (mut watch, _) = started(&config, &probe);
        watch.tick();
        assert_eq!(watch.resources().report().memory.budget_bytes, 12 * GIB);

        assert_eq!(memory_max("max\n"), None);
        assert_eq!(memory_max("4294967296\n"), Some(4 * GIB));
        assert_eq!(cgroup_v2_path("0::/system.slice/luradb.service\n").as_deref(), Some("/system.slice/luradb.service"));
        assert_eq!(cgroup_v2_path("0::/\n").as_deref(), Some(""));
        assert_eq!(status_kib("Name:\tluradb\nRssAnon:\t  2048 kB\n", "RssAnon:").unwrap(), 2048 * 1024);
        assert_eq!(status_kib("MemTotal:       16303284 kB\n", "MemTotal:").unwrap(), 16303284 * 1024);
    }

    // Test 3: a block of 180 ticks logs its ERROR line on entry and twice
    // more, its end an INFO line; the start logs each volume and the budget
    // in bytes.
    #[test]
    fn test_a_lasting_block_repeats_its_line_every_60_ticks() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        let (mut watch, start) = started(&config_in(dir.path()), &probe);
        let info = lines(&start, tracing::Level::INFO);
        assert_eq!(info.len(), 2, "{info:?}");
        assert!(info[0].contains("100000000000 bytes, 50000000000 free") && info[0].contains("refused below 2000000000"), "{info:?}");
        assert!(info[1].contains(&format!("Memory budget {} bytes", 12 * GIB)), "{info:?}");

        probe.set_free(dir.path(), GB);
        let mut notices = Vec::new();
        for _ in 0..180 {
            notices.extend(watch.tick());
        }
        let errors = lines(&notices, tracing::Level::ERROR);
        assert_eq!(errors.len(), 3, "{errors:?}");
        let volume = dir.path().join("data/sstables").canonicalize().unwrap();
        let reason = format!("Writes refused: disk {} free 1000000000 of 100000000000, threshold 2000000000", volume.display());
        assert!(errors[0].starts_with(&reason), "{}", errors[0]);

        probe.set_free(dir.path(), 50 * GB);
        let leaving: Vec<Notice> = (0..2).flat_map(|_| watch.tick()).collect();
        assert_eq!(lines(&leaving, tracing::Level::INFO).len(), 1, "{leaving:?}");
        assert!(lines(&leaving, tracing::Level::INFO)[0].starts_with("Writes are accepted again"));
    }

    // Test 4 (backup rule): during a disk block a backup may run into a
    // backup directory on another volume above warn, not into a short one
    // and not during a memory block.
    #[test]
    fn test_backups_run_during_a_block_only_onto_a_volume_with_room() {
        let dir = tempfile::TempDir::new().unwrap();
        let backups = dir.path().join("backups");
        std::fs::create_dir_all(&backups).unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        probe.mount(&backups, 100 * GB, 50 * GB);
        let mut config = config_in(dir.path());
        config.backup.enabled = true;
        config.backup.dir = backups.to_string_lossy().into_owned();
        config.resources.memory_budget = "1 GiB".into();
        let (mut watch, _) = started(&config, &probe);
        let resources = watch.resources();

        probe.set_free(dir.path(), GB);
        probe.set_rss(GIB * 92 / 100);
        watch.tick();
        assert_eq!(resources.level(), Level::Blocked);
        assert!(resources.backup_allowed(), "memory above its resume share is no reason of the block");

        probe.set_free(&backups, 5 * GB);
        watch.tick();
        assert!(!resources.backup_allowed(), "the backup volume is below warn");

        probe.set_free(&backups, 50 * GB);
        probe.set_free(dir.path(), 50 * GB);
        probe.set_rss(GIB);
        watch.tick();
        assert!(resources.check_write().unwrap_err().to_string().contains("memory"));
        assert!(!resources.backup_allowed(), "short of memory");
    }

    // Test 8: the start creates the data directories before it asks for any
    // volume; a volume the recovery writes to needs the write-ahead logs
    // recovering onto it, or the start fails with `NoRoomToRecover`. With
    // that room, a volume below the block threshold starts, and in the block.
    #[test]
    fn test_the_start_needs_room_to_recover_on_the_volume_of_the_tables() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = config_in(dir.path());
        let segments = dir.path().join("wal/luradb.wal");
        std::fs::create_dir_all(&segments).unwrap();
        std::fs::write(segments.join("00000001.wal"), vec![0u8; 3000]).unwrap();
        let data = dir.path().join("data");
        let wal = dir.path().join("wal");
        std::fs::create_dir_all(&data).unwrap();
        let probe = FakeProbe::new();
        probe.mount(dir.path(), 100 * GB, 50 * GB);
        probe.mount(&data, 100 * GB, 2999);
        probe.mount(&wal, 100 * GB, 50 * GB);
        let err = ResourceWatch::start(&config, Path::new("/"), Arc::clone(&probe) as Arc<dyn Probe>).err().unwrap();
        let refused = err.downcast_ref::<NoRoomToRecover>().expect("NoRoomToRecover");
        assert_eq!(refused.needed, 3000);
        assert!(err.to_string().starts_with("not enough free disk space to recover"), "{err}");
        for name in ["db", "data/sstables", "data/sys", "wal"] {
            assert!(dir.path().join(name).is_dir(), "{name}");
        }
        assert!(!probe.asked.lock().is_empty() && probe.asked.lock().iter().all(|(_, existed)| *existed));

        probe.set_free(&data, 3000);
        started(&config, &probe);

        probe.set_free(&data, GB);
        let (mut watch, _) = started(&config, &probe);
        watch.tick();
        assert_eq!(watch.resources().level(), Level::Blocked, "room to recover, below the block threshold");
    }

    // Test 6: a job that keeps waiting for disk space logs its first skip
    // and every 60th after it; a run starts a new row.
    #[test]
    fn test_waits_for_disk_space_log_like_a_lasting_state() {
        let wait = SpaceWait::default();
        let logged: Vec<bool> = (0..121).map(|_| wait.skipped()).collect();
        let at: Vec<usize> = logged.iter().enumerate().filter(|(_, &logged)| logged).map(|(i, _)| i).collect();
        assert_eq!(at, [0, 60, 120]);
        wait.ran();
        assert!(wait.skipped());
    }

    // Test 9: the systemd unit restarts after a failed sync but not after a
    // start without room to recover, and gives up after three starts in
    // five minutes.
    #[test]
    fn test_the_unit_keeps_exit_4_from_a_restart_loop() {
        const UNIT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/packaging/luradb.service"));
        let mut section = "";
        let mut settings = Vec::new();
        for line in UNIT.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
            match line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
                Some(name) => section = name,
                None => settings.push(format!("{section}: {line}")),
            }
        }
        for expected in [
            format!("Service: RestartPreventExitStatus={EXIT_NO_ROOM_TO_RECOVER}"),
            "Service: Restart=on-failure".to_string(),
            "Unit: StartLimitIntervalSec=300".to_string(),
            "Unit: StartLimitBurst=3".to_string(),
        ] {
            assert!(settings.contains(&expected), "{expected} missing in packaging/luradb.service: {settings:?}");
        }
        assert_eq!(crate::storage::EXIT_SYNC_FAILED, 3);
        assert!(!settings.iter().any(|s| s.contains("RestartPreventExitStatus") && s.contains('3')));
    }

    // Test 8: fixed memory above half the budget is a warning naming the items.
    #[test]
    fn test_fixed_memory_above_half_the_budget_warns() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let mut config = config_in(dir.path());
        config.resources.memory_budget = "256 MiB".into();
        let (watch, _) = started(&config, &probe);
        let items = fixed_memory(&config, 4);
        let notice = watch.fixed_memory_notice(&items).expect("a warning");
        assert_eq!(notice.level, tracing::Level::WARN);
        assert!(notice.line.contains("memtables") && notice.line.contains("block caches"), "{}", notice.line);

        config.resources.memory_budget = "64 GiB".into();
        let (watch, _) = started(&config, &probe);
        assert_eq!(watch.fixed_memory_notice(&items), None);
    }

    // The health states are the worst of all volumes, `ok` without one, and
    // the state of the memory.
    #[test]
    fn test_the_health_states_take_the_worst_volume() {
        let volume = |state| DiskReport { path: "/data".into(), size_bytes: 1, free_bytes: 1, state };
        let report = |disk: Vec<DiskReport>, memory: &'static str| ResourceReport {
            state: "warning",
            disk,
            memory: MemoryReport { rss_anon_bytes: 1, budget_bytes: 2, state: memory },
        };
        let states = |report: ResourceReport| serde_json::to_value(ResourceState::from(&report)).unwrap();

        assert_eq!(
            states(report(vec![volume("ok"), volume("blocked"), volume("warning")], "warning")),
            serde_json::json!({ "state": "warning", "disk_state": "blocked", "memory_state": "warning" })
        );
        assert_eq!(
            states(report(vec![volume("ok"), volume("warning")], "blocked")),
            serde_json::json!({ "state": "warning", "disk_state": "warning", "memory_state": "blocked" })
        );
        assert_eq!(
            states(report(Vec::new(), "ok")),
            serde_json::json!({ "state": "warning", "disk_state": "ok", "memory_state": "ok" })
        );
    }

    const RELIEF_LINE: &str = "Memory block: flushing MemTables and returning free heap to the kernel.";

    /// A watch over one volume below `dir` with a memory budget of 1 GiB,
    /// whose trims run inline, count in the counter returned and set the
    /// probe's memory to `rss_after_trim`.
    fn memory_watch(probe: &Arc<FakeProbe>, dir: &Path, rss_after_trim: u64) -> (ResourceWatch, Arc<AtomicU64>) {
        probe.mount(dir, 100 * GB, 50 * GB);
        let mut config = config_in(dir);
        config.resources.memory_budget = "1 GiB".into();
        let (mut watch, _) = started(&config, probe);
        let trims = Arc::new(AtomicU64::new(0));
        let (counted, probe) = (Arc::clone(&trims), Arc::clone(probe));
        watch.trimmer = Trimmer::Inline(Box::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            probe.set_rss(rss_after_trim);
        }));
        (watch, trims)
    }

    /// The ticks, counted from 1, that raised the flush request and those
    /// that trimmed, and every notice, over `ticks` ticks with `after`
    /// called after each one with its number.
    fn run_ticks(
        watch: &mut ResourceWatch,
        trims: &AtomicU64,
        ticks: u64,
        mut after: impl FnMut(u64, &Relief),
    ) -> (Vec<u64>, Vec<u64>, Vec<Notice>) {
        let relief = watch.relief();
        let (mut requests, mut trimmed, mut notices) = (Vec::new(), Vec::new(), Vec::new());
        for tick in 1..=ticks {
            let (requested, trimmed_before) = (relief.requested.load(Ordering::Acquire), trims.load(Ordering::Relaxed));
            notices.extend(watch.tick());
            if relief.requested.load(Ordering::Acquire) > requested {
                requests.push(tick);
            }
            if trims.load(Ordering::Relaxed) > trimmed_before {
                trimmed.push(tick);
            }
            after(tick, &relief);
        }
        (requests, trimmed, notices)
    }

    fn relief_lines(notices: &[Notice]) -> usize {
        lines(notices, tracing::Level::INFO).iter().filter(|line| **line == RELIEF_LINE).count()
    }

    // Test 1: a memory block asks for a flush on its first tick and trims
    // once that is done; the memory measured after the trim lifts the block
    // with the usual hysteresis, without a write.
    #[test]
    fn test_a_memory_block_lifts_after_a_flush_and_a_trim() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, trims) = memory_watch(&probe, dir.path(), GIB * 70 / 100);
        let resources = watch.resources();
        let relief = watch.relief();
        probe.set_rss(GIB * 96 / 100);

        let notices = watch.tick();
        assert_eq!(resources.level(), Level::Blocked);
        assert!(resources.check_write().unwrap_err().to_string().contains("memory budget exhausted"));
        assert_eq!(relief.requested.load(Ordering::Acquire), 1);
        assert_eq!(relief_lines(&notices), 1, "{notices:?}");
        relief.flushed.store(1, Ordering::Release);

        watch.tick();
        assert_eq!(trims.load(Ordering::Relaxed), 1);
        assert_eq!(resources.report().memory.rss_anon_bytes, GIB * 96 / 100, "measured before the trim");
        assert_eq!(resources.level(), Level::Blocked);

        watch.tick();
        assert_eq!((resources.level(), watch.ticks_above), (Level::Blocked, 1));
        watch.tick();
        assert_eq!(resources.level(), Level::Warning);
        watch.tick();
        assert_eq!((resources.level(), watch.ticks_above), (Level::Warning, 1));
        watch.tick();
        assert_eq!(resources.level(), Level::Normal);
        assert_eq!((trims.load(Ordering::Relaxed), relief.requested.load(Ordering::Acquire)), (1, 1));
    }

    // Test 2: a lasting memory block asks for a flush every ten ticks and
    // trims on the tick after each finished one; the INFO line comes once.
    #[test]
    fn test_a_lasting_memory_block_relieves_every_ten_ticks() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, trims) = memory_watch(&probe, dir.path(), GIB * 96 / 100);
        probe.set_rss(GIB * 96 / 100);
        let (requests, trimmed, notices) = run_ticks(&mut watch, &trims, 25, |_, relief| {
            relief.flushed.store(relief.requested.load(Ordering::Acquire), Ordering::Release);
        });
        assert_eq!(requests, [1, 11, 21]);
        assert_eq!(trimmed, [2, 12, 22]);
        assert_eq!(relief_lines(&notices), 1);
    }

    // Test 3: while the last flush is not done, no new one is asked for and
    // nothing is trimmed; once it is, the next tick trims and the next
    // request comes on its turn.
    #[test]
    fn test_no_new_request_or_trim_while_a_flush_runs() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, trims) = memory_watch(&probe, dir.path(), GIB * 96 / 100);
        probe.set_rss(GIB * 96 / 100);
        let relief = watch.relief();
        let (requests, trimmed, _) = run_ticks(&mut watch, &trims, 21, |tick, relief| {
            if tick == 11 {
                assert_eq!(relief.requested.load(Ordering::Acquire), 1);
            }
            if tick == 15 {
                relief.flushed.store(1, Ordering::Release);
            }
        });
        assert_eq!(requests, [1, 21]);
        assert_eq!(trimmed, [16]);
        assert_eq!(relief.requested.load(Ordering::Acquire), 2);
    }

    // Test 3a: memory short during a disk block adds its reason, and the
    // relief starts on that tick.
    #[test]
    fn test_relief_starts_when_memory_joins_a_disk_block() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, trims) = memory_watch(&probe, dir.path(), GIB * 96 / 100);
        let resources = watch.resources();
        let relief = watch.relief();
        let flushed = |_: u64, relief: &Relief| relief.flushed.store(relief.requested.load(Ordering::Acquire), Ordering::Release);
        probe.set_free(dir.path(), GB);
        let (requests, _, notices) = run_ticks(&mut watch, &trims, 4, flushed);
        assert_eq!(resources.level(), Level::Blocked);
        assert_eq!((requests, relief_lines(&notices)), (vec![], 0));

        probe.set_rss(GIB * 96 / 100);
        let notices = watch.tick();
        assert_eq!((relief.requested.load(Ordering::Acquire), relief_lines(&notices)), (1, 1));
        assert!(resources.check_write().unwrap_err().to_string().contains("disk space below threshold and memory"));
        relief.flushed.store(1, Ordering::Release);

        // Ticks 6 to 15.
        let (requests, _, notices) = run_ticks(&mut watch, &trims, 10, flushed);
        assert_eq!((requests, relief_lines(&notices)), (vec![10], 0));
    }

    // Test 4: a disk block alone asks for no flush and trims nothing.
    #[test]
    fn test_a_disk_block_alone_relieves_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, trims) = memory_watch(&probe, dir.path(), 0);
        probe.set_free(dir.path(), GB);
        let (requests, trimmed, notices) = run_ticks(&mut watch, &trims, 20, |_, relief| {
            relief.flushed.store(relief.requested.load(Ordering::Acquire), Ordering::Release);
        });
        assert_eq!(watch.resources().level(), Level::Blocked);
        assert_eq!((requests, trimmed, relief_lines(&notices)), (vec![], vec![], 0));
        assert_eq!(watch.relief().requested.load(Ordering::Acquire), 0);
    }

    // Test 6: a trim due while another runs waits for the next tick; it
    // runs once per request. The next request comes on its turn.
    #[test]
    fn test_one_trim_at_a_time() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, trims) = memory_watch(&probe, dir.path(), GIB * 96 / 100);
        probe.set_rss(GIB * 96 / 100);
        let relief = watch.relief();
        watch.tick();
        relief.flushed.store(1, Ordering::Release);
        watch.trim_running.store(true, Ordering::Release);
        watch.tick();
        assert_eq!((trims.load(Ordering::Relaxed), watch.trimmed_for), (0, 0));

        watch.trim_running.store(false, Ordering::Release);
        watch.tick();
        assert_eq!((trims.load(Ordering::Relaxed), watch.trimmed_for), (1, 1));
        for _ in 4..=11 {
            watch.tick();
        }
        assert_eq!((trims.load(Ordering::Relaxed), relief.requested.load(Ordering::Acquire)), (1, 2));
    }

    // The trim of a server runs on a thread of its own, which clears the
    // running flag when it is done.
    #[test]
    fn test_the_server_trims_on_a_thread_of_its_own() {
        let dir = tempfile::TempDir::new().unwrap();
        let probe = FakeProbe::new();
        let (mut watch, _) = memory_watch(&probe, dir.path(), 0);
        watch.trimmer = Trimmer::Thread;
        probe.set_rss(GIB * 96 / 100);
        watch.tick();
        watch.relief().flushed.store(1, Ordering::Release);
        watch.tick();
        assert_eq!(watch.trimmed_for, 1);
        // Upper bound against hanging only.
        let until = std::time::Instant::now() + Duration::from_secs(30);
        while watch.trim_running.load(Ordering::Acquire) {
            assert!(std::time::Instant::now() < until, "the trim thread does not end");
            std::thread::yield_now();
        }
    }
}
