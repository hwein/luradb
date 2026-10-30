//! Failed writes of the data files the server goes on using: how many in a
//! row each had, when they stop the server, and which file the health report
//! names meanwhile.

use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Failed writes in a row that stop the server; a read-only file system
/// stops it at the first.
pub const FAILURES_TO_STOP: u32 = 3;

/// The rows of failed writes going on, for the health report; clones share
/// them.
#[derive(Debug, Clone, Default)]
pub struct IoFailures(Arc<Mutex<Vec<(u64, IoReport)>>>);

impl IoFailures {
    /// The file with the most failed writes in a row; `None` while no row
    /// goes on.
    pub fn report(&self) -> Option<IoReport> {
        self.0.lock().iter().map(|(_, report)| report).max_by_key(|report| report.failures).cloned()
    }

    fn set(&self, id: u64, report: IoReport) {
        let mut rows = self.0.lock();
        match rows.iter_mut().find(|(row, _)| *row == id) {
            Some((_, current)) => *current = report,
            None => rows.push((id, report)),
        }
    }

    fn clear(&self, id: u64) {
        self.0.lock().retain(|(row, _)| *row != id);
    }
}

/// `io` of `GET /health`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct IoReport {
    /// The data file whose last write failed.
    pub path: String,
    /// Its failed writes in a row.
    pub failures: u32,
}

/// The failed writes in a row of one data file, or of the files one job
/// writes in turn: the appends of a write-ahead log or a value log, the
/// flushes of an engine. A success ends the row.
#[derive(Debug)]
pub struct WriteFailures {
    id: u64,
    in_a_row: AtomicU32,
    io: IoFailures,
}

impl WriteFailures {
    pub fn new(io: &IoFailures) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), in_a_row: AtomicU32::new(0), io: io.clone() }
    }

    pub fn succeeded(&self) {
        if self.in_a_row.load(Ordering::Relaxed) != 0 && self.in_a_row.swap(0, Ordering::Relaxed) != 0 {
            self.io.clear(self.id);
        }
    }

    /// Counts the failed write of `path`; whether it stops the server: on a
    /// read-only file system at once, with another I/O error at the
    /// [`FAILURES_TO_STOP`]th in a row. A full file system neither counts
    /// nor stops: writes are refused before the space runs out.
    pub fn stops_for(&self, path: &Path, error: &std::io::Error) -> bool {
        if error.raw_os_error() == Some(libc::ENOSPC) {
            return false;
        }
        let failures = self.in_a_row.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        self.io.set(self.id, IoReport { path: path.display().to_string(), failures });
        error.raw_os_error() == Some(libc::EROFS) || failures >= FAILURES_TO_STOP
    }
}

impl Drop for WriteFailures {
    fn drop(&mut self) {
        self.io.clear(self.id);
    }
}

/// The operation of a [`WriteError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedIo {
    /// A creation, write or rename.
    Write,
    Sync,
}

/// A failed write of the file `path` that counts towards
/// [`WriteFailures::stops_for`].
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct WriteError {
    pub path: PathBuf,
    pub error: std::io::Error,
    pub failed: FailedIo,
}

impl WriteError {
    /// The failed creation, write or rename of `path`, for `map_err`.
    pub fn of(path: &Path) -> impl FnOnce(std::io::Error) -> Self + '_ {
        move |error| Self { path: path.to_path_buf(), error, failed: FailedIo::Write }
    }

    /// The failed sync of `path`, for `map_err`.
    pub fn sync_of(path: &Path) -> impl FnOnce(std::io::Error) -> Self + '_ {
        move |error| Self { path: path.to_path_buf(), error, failed: FailedIo::Sync }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    fn eio() -> Error {
        Error::from_raw_os_error(libc::EIO)
    }

    // Another I/O error stops at the third failure in a row, a success in
    // between starts the row anew; the report names the file meanwhile.
    #[test]
    fn the_third_failure_in_a_row_stops() {
        let io = IoFailures::default();
        let failures = WriteFailures::new(&io);
        let path = Path::new("/data/vlog.log");
        assert!(!failures.stops_for(path, &eio()));
        assert!(!failures.stops_for(path, &Error::other("short write")));
        failures.succeeded();
        assert_eq!(io.report(), None);
        assert!(!failures.stops_for(path, &eio()));
        assert!(!failures.stops_for(path, &eio()));
        assert_eq!(io.report(), Some(IoReport { path: "/data/vlog.log".into(), failures: 2 }));
        assert!(failures.stops_for(path, &eio()));
    }

    // A read-only file system stops at once, a full one never.
    #[test]
    fn a_read_only_file_system_stops_at_once_a_full_one_never() {
        let io = IoFailures::default();
        let failures = WriteFailures::new(&io);
        for _ in 0..FAILURES_TO_STOP + 1 {
            assert!(!failures.stops_for(Path::new("/data/wal"), &Error::from_raw_os_error(libc::ENOSPC)));
        }
        assert_eq!(io.report(), None);
        assert!(failures.stops_for(Path::new("/data/wal"), &Error::from_raw_os_error(libc::EROFS)));
    }

    // The report names the file with the longest row; a dropped counter
    // leaves it.
    #[test]
    fn the_report_names_the_longest_row() {
        let io = IoFailures::default();
        let (wal, vlog) = (WriteFailures::new(&io), WriteFailures::new(&io));
        wal.stops_for(Path::new("/a/wal"), &eio());
        vlog.stops_for(Path::new("/b/vlog"), &eio());
        vlog.stops_for(Path::new("/b/vlog"), &eio());
        assert_eq!(io.report(), Some(IoReport { path: "/b/vlog".into(), failures: 2 }));
        drop(vlog);
        assert_eq!(io.report(), Some(IoReport { path: "/a/wal".into(), failures: 1 }));
    }
}
