//! Keeps every write-ahead log short while the server runs: once a log
//! reaches [`WAL_CHECKPOINT_BYTES`], its engine persists everything it has
//! applied and the log is cut back to the records that came after.

use super::{ControlPlane, Engine};
use crate::core::wal::WriteAheadLog;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

/// A log this long is checkpointed. It bounds what a restart after a crash
/// reads into memory: about 6.6 MiB per MiB of log with small records.
pub const WAL_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;

/// How often each log's length is checked.
pub const WAL_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(1);

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
    /// The checkpoint failed; `bytes` is the log's length, if it was read.
    Stuck { log: &'static str, bytes: Option<u64>, error: String },
    /// The checkpoint succeeded after `failures` failed ones.
    Recovered { log: &'static str, failures: u64 },
}

/// The checkpoints of every write-ahead log, one tick at a time.
pub struct WalCheckpoint {
    control: Arc<ControlPlane>,
    logs: Vec<Log>,
    limit: u64,
}

impl WalCheckpoint {
    /// Checkpoints `logs`, each held by its [`Holder`].
    pub fn new(control: Arc<ControlPlane>, logs: Vec<(Holder, WriteAheadLog)>) -> Self {
        let logs = logs.into_iter().map(|(holder, wal)| Log { holder, wal, failures: Mutex::new(0) }).collect();
        Self { control, logs, limit: WAL_CHECKPOINT_BYTES }
    }

    /// Checkpoints at `limit` bytes instead.
    #[cfg(test)]
    pub(crate) fn with_limit(self, limit: u64) -> Self {
        Self { limit, ..self }
    }

    /// Checkpoints each log that reached the limit, one after the other, and
    /// logs what went wrong itself: a failure leaves the log whole, and the
    /// next tick tries again.
    pub async fn tick(&self) -> anyhow::Result<()> {
        for report in self.run().await {
            match report {
                Report::Stuck { log, bytes: Some(bytes), error } => {
                    tracing::warn!("[WalCheckpoint] the {log} write-ahead log stays at {bytes} bytes: {error}");
                }
                Report::Stuck { log, bytes: None, error } => {
                    tracing::warn!("[WalCheckpoint] the length of the {log} write-ahead log is unknown: {error}");
                }
                Report::Recovered { log, failures } => {
                    tracing::info!(
                        "[WalCheckpoint] the {log} write-ahead log is cut back again after {failures} failed checkpoints."
                    );
                }
            }
        }
        Ok(())
    }

    /// One tick: what it has to report.
    pub(super) async fn run(&self) -> Vec<Report> {
        let mut reports = Vec::new();
        for log in &self.logs {
            let name = log.holder.name();
            let checkpointed = self.checkpoint_if_full(log).await;
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
        reports
    }

    /// Checkpoints `log` once it reached the limit; a failure comes with the
    /// log's length, if it was read.
    async fn checkpoint_if_full(&self, log: &Log) -> Result<(), (Option<u64>, anyhow::Error)> {
        let bytes = log.wal.mark().await.map_err(|e| (None, e.into()))?.offset;
        if bytes < self.limit {
            return Ok(());
        }
        match log.holder {
            Holder::Shards(engine) => self.control.checkpoint(engine, &log.wal).await,
            Holder::System => self.control.system_store().checkpoint().await,
        }
        .map_err(|e| (Some(bytes), e))
    }
}
