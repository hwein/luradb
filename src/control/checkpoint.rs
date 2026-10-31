//! Keeps every write-ahead log short while the server runs, once a second
//! per log: drops each segment whose records all instances of its engine
//! have in their SSTables, keeps the segment after the one appended to
//! prepared from the moment that one is in use, and once the closed segments
//! plus a full one reach the size cap — or the current one holds records for
//! five minutes — has the instances behind raise their flushed LSN, so the
//! oldest segments can go. A flush request of the resource watch has them
//! raise it to the end of every log at once.

use super::resources::Relief;
use super::{ControlPlane, Engine};
use crate::core::storage_thread::{prepare_segment, WalSegments};
use crate::core::wal::{segment_path, WriteAheadLog, WAL_HEADER_LEN};
use anyhow::Context;
use parking_lot::Mutex;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often each log is looked at.
pub const WAL_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(1);

/// A segment that holds records this long is closed and dropped, so a
/// database with few writes keeps them in its log for no longer.
const SEGMENT_MAX_AGE: Duration = Duration::from_secs(5 * 60);

/// A log that keeps failing its checkpoint is reported on its first failure
/// and then once every this many ticks.
const REPORT_EVERY: u64 = 60;

/// Who persists what a log holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// The instances of an engine on every data shard.
    Shards(Engine),
    /// The system store, which writes its log alone.
    System,
}

impl Holder {
    fn name(self) -> &'static str {
        match self {
            Holder::Shards(engine) => engine.as_str(),
            Holder::System => "system",
        }
    }
}

struct Log {
    holder: Holder,
    wal: WriteAheadLog,
    /// Checkpoints failed in a row.
    failures: Mutex<u64>,
}

/// What a tick reports about one log.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Report {
    /// The checkpoint failed; `bytes` is the size of the log's segments, if
    /// it was read.
    Stuck { log: &'static str, bytes: Option<u64>, error: String },
    /// The checkpoint succeeded after `failures` failed ones.
    Recovered { log: &'static str, failures: u64 },
}

/// The checkpoints of every write-ahead log, one tick at a time.
pub struct WalCheckpoint {
    control: Arc<ControlPlane>,
    logs: Vec<Log>,
    /// The size cap of each log's segments: a tick keeps the closed segments
    /// a full one below it, so the segment that fills until the next tick
    /// acts stays within one segment of it.
    limit: u64,
    relief: Arc<Relief>,
    /// Added to the clock, so tests let segments age.
    #[cfg(test)]
    clock_skew: Mutex<Duration>,
}

impl WalCheckpoint {
    /// Checkpoints `logs`, each held by its [`Holder`], with `limit` bytes
    /// as the cap of its segments, and serves the flush requests of `relief`.
    pub fn new(control: Arc<ControlPlane>, logs: Vec<(Holder, WriteAheadLog)>, limit: u64, relief: Arc<Relief>) -> Self {
        let logs = logs.into_iter().map(|(holder, wal)| Log { holder, wal, failures: Mutex::new(0) }).collect();
        Self {
            control,
            logs,
            limit,
            relief,
            #[cfg(test)]
            clock_skew: Mutex::new(Duration::ZERO),
        }
    }

    /// Sets the clock of the age check `skew` ahead of the real one.
    #[cfg(test)]
    pub(crate) fn skew_clock(&self, skew: Duration) {
        *self.clock_skew.lock() = skew;
    }

    fn now(&self) -> Instant {
        #[cfg(test)]
        return Instant::now() + *self.clock_skew.lock();
        #[cfg(not(test))]
        Instant::now()
    }

    /// Checkpoints each log, one after the other, and logs what went wrong
    /// itself: a failure leaves the log whole, and the next tick tries again.
    pub async fn tick(&self) -> anyhow::Result<()> {
        for report in self.run().await {
            match report {
                Report::Stuck { log, bytes: Some(bytes), error } => {
                    tracing::warn!("[WalCheckpoint] the {log} write-ahead log stays at {bytes} bytes: {error}");
                }
                Report::Stuck { log, bytes: None, error } => {
                    tracing::warn!("[WalCheckpoint] the size of the {log} write-ahead log is unknown: {error}");
                }
                Report::Recovered { log, failures } => {
                    tracing::info!(
                        "[WalCheckpoint] the {log} write-ahead log drops its segments again after {failures} failed checkpoints."
                    );
                }
            }
        }
        Ok(())
    }

    /// One tick: what it has to report. A flush request waiting is done at
    /// its end, also when a log failed.
    pub(super) async fn run(&self) -> Vec<Report> {
        let requested = self.relief.requested.load(Ordering::Acquire);
        let flush = requested > self.relief.flushed.load(Ordering::Acquire);
        let mut reports = Vec::new();
        for log in &self.logs {
            let name = log.holder.name();
            let checkpointed = self.checkpoint(log, flush).await;
            let mut failures = log.failures.lock();
            match checkpointed {
                Ok(()) if *failures > 0 => {
                    reports.push(Report::Recovered { log: name, failures: std::mem::take(&mut *failures) });
                }
                Ok(()) => {}
                Err((bytes, e)) => {
                    *failures += 1;
                    if (*failures - 1).is_multiple_of(REPORT_EVERY) {
                        reports.push(Report::Stuck { log: name, bytes, error: format!("{e:#}") });
                    }
                }
            }
        }
        if flush {
            self.relief.flushed.store(requested, Ordering::Release);
        }
        reports
    }

    /// One checkpoint of `log`, with every record persisted when `flush`; a
    /// failure comes with the size of its segments, if they were read.
    async fn checkpoint(&self, log: &Log, flush: bool) -> Result<(), (Option<u64>, anyhow::Error)> {
        let segments = log.wal.segments().await.map_err(|e| (None, e.into()))?;
        let bytes = segments.total_bytes();
        self.maintain(log, segments, flush).await.map_err(|e| (Some(bytes), e))
    }

    async fn maintain(&self, log: &Log, mut segments: WalSegments, flush: bool) -> anyhow::Result<()> {
        // Files a failed removal left before the oldest segment the hub keeps.
        log.wal.drop_segments_before(&segments.dir, segments.segments[0].segment).await?;
        segments = self.drop_flushed(log, segments).await?;

        let active = *segments.active();
        prepare_next(&segments).await?;

        // A segment early: the one appended to fills, and another begins,
        // before the next tick gets the stragglers to persist.
        while bytes_once_full(&segments) >= self.limit {
            let Some(oldest) = segments.closed().first().copied() else { break };
            self.raise_behind(log, oldest.last_lsn).await?;
            segments = self.drop_flushed(log, segments).await?;
            anyhow::ensure!(
                segments.segments[0].segment > oldest.segment,
                "segment {} stays although every instance flushed its records",
                oldest.segment
            );
        }

        let age = self.now().saturating_duration_since(segments.active_since);
        // The last LSN of the segment appended to is durable.
        let last_lsn = segments.active().last_lsn;
        let needs_flush = flush && last_lsn > self.flushed_lsns(log.holder)?.into_iter().min().unwrap_or(0);
        if active.bytes > WAL_HEADER_LEN && (age >= SEGMENT_MAX_AGE || needs_flush) {
            prepare_next(&segments).await?;
            log.wal.rotate().await.context("closing the segment")?;
            let rotated = log.wal.segments().await?;
            if let Some(last) = rotated.closed().last() {
                self.raise_behind(log, last.last_lsn).await?;
            }
            self.drop_flushed(log, rotated).await?;
        } else if needs_flush {
            self.raise_behind(log, last_lsn).await?;
            self.drop_flushed(log, segments).await?;
        }
        Ok(())
    }

    /// Drops the oldest segments whose records every instance has in its
    /// SSTables, never the one appended to; returns the segments left.
    async fn drop_flushed(&self, log: &Log, segments: WalSegments) -> anyhow::Result<WalSegments> {
        let flushed = self.flushed_lsns(log.holder)?.into_iter().min().unwrap_or(0);
        let keep = segments.closed().iter().find(|closed| closed.last_lsn > flushed).unwrap_or(segments.active());
        if keep.segment == segments.segments[0].segment {
            return Ok(segments);
        }
        log.wal.drop_segments_before(&segments.dir, keep.segment).await?;
        Ok(log.wal.segments().await?)
    }

    /// Raises the flushed LSN of every instance below `up_to` to it.
    async fn raise_behind(&self, log: &Log, up_to: u64) -> anyhow::Result<()> {
        match log.holder {
            Holder::Shards(engine) => {
                let behind: Vec<usize> = self
                    .flushed_lsns(log.holder)?
                    .into_iter()
                    .enumerate()
                    .filter(|(_, flushed)| *flushed < up_to)
                    .map(|(k, _)| k)
                    .collect();
                self.control.persist_up_to(engine, &behind, up_to).await
            }
            Holder::System => {
                let system = self.control.system_store();
                if system.flushed_lsn() < up_to {
                    system.raise_flushed_lsn(up_to).await.context("the system store could not persist")?;
                }
                Ok(())
            }
        }
    }

    /// The flushed LSN of each instance that writes the log.
    fn flushed_lsns(&self, holder: Holder) -> anyhow::Result<Vec<u64>> {
        match holder {
            Holder::Shards(engine) => self
                .control
                .flushed_lsns(engine)
                .with_context(|| format!("the {} engine is disabled", engine.as_str())),
            Holder::System => Ok(vec![self.control.system_store().flushed_lsn()]),
        }
    }
}

/// The size of `segments` with the one appended to counted as full, or as
/// is when a record took it past that.
fn bytes_once_full(segments: &WalSegments) -> u64 {
    let closed: u64 = segments.closed().iter().map(|segment| segment.bytes).sum();
    closed + segments.active().bytes.max(segments.segment_bytes)
}

/// Prepares the segment after the active one of `segments` unless it exists.
async fn prepare_next(segments: &WalSegments) -> anyhow::Result<()> {
    let next = segments.active().segment + 1;
    if segment_path(&segments.dir, next).try_exists()? {
        return Ok(());
    }
    let dir = segments.dir.clone();
    tokio::task::spawn_blocking(move || prepare_segment(&dir, next)).await?.context("preparing the next segment")
}
