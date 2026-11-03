pub mod format;
pub mod sstable;
pub mod vlog;
pub mod bloom;
pub mod file_manager;
pub mod manifest;
pub mod write_failures;
#[cfg(test)]
pub(crate) mod test_fault;
#[cfg(test)]
pub(crate) mod test_trace;

use anyhow::Context;
use std::path::{Path, PathBuf};

/// Makes the renames and removals in `dir` durable; blocks the calling thread.
pub fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    let sync = || {
        #[cfg(test)]
        test_fault::check_sync(dir)?;
        std::fs::File::open(dir)?.sync_all()
    };
    sync().with_context(|| format!("sync {}", dir.display()))?;
    #[cfg(test)]
    test_trace::record(dir, "sync");
    Ok(())
}

/// [`sync_dir`] for each of `dirs`, in order and each once, on the blocking
/// pool so the engine thread keeps serving.
pub async fn sync_dirs(dirs: &[&Path]) -> anyhow::Result<()> {
    match first_failed_sync(dirs).await? {
        Some((_, e)) => Err(e),
        None => Ok(()),
    }
}

/// [`sync_dirs`] for directories the server goes on using: a failed sync
/// stops it ([`fatal_sync_error`]).
pub async fn sync_dirs_or_stop(dirs: &[&Path]) -> anyhow::Result<()> {
    match first_failed_sync(dirs).await? {
        Some((dir, e)) => Err(fatal_sync_error(&dir, e.root_cause())),
        None => Ok(()),
    }
}

/// Syncs `dirs` as [`sync_dirs`] does, up to the first that fails.
async fn first_failed_sync(dirs: &[&Path]) -> anyhow::Result<Option<(PathBuf, anyhow::Error)>> {
    let mut unique: Vec<PathBuf> = Vec::with_capacity(dirs.len());
    for dir in dirs {
        if !unique.iter().any(|seen| seen == dir) {
            unique.push(dir.to_path_buf());
        }
    }
    let synced = tokio::task::spawn_blocking(move || {
        unique.into_iter().find_map(|dir| sync_dir(&dir).err().map(|e| (dir, e)))
    });
    Ok(synced.await?)
}

/// The exit code of a stop after a failed sync or lasting write failures.
pub const EXIT_SYNC_FAILED: u8 = 3;

/// Stops the server after a failed sync of a file or directory it would go
/// on using — a write-ahead log segment, a value log, a data directory, an
/// unsafe-end marker: the kernel may have dropped the pages it could not
/// write, and a second sync could then succeed without them. Writes the
/// failure to the server log and to stderr, flushes the log file and exits
/// with [`EXIT_SYNC_FAILED`]; the next start recovers from the write-ahead
/// log. In tests the stop is recorded and its error returned instead.
pub fn fatal_sync_error(path: &Path, error: &dyn std::fmt::Display) -> anyhow::Error {
    stop("sync", path, error)
}

/// Stops the server as [`fatal_sync_error`] does after writes of a data
/// file it goes on using failed for good
/// ([`write_failures::WriteFailures::stops_for`]): a restart heals a
/// passing fault of the device.
pub fn fatal_write_error(path: &Path, error: &dyn std::fmt::Display) -> anyhow::Error {
    stop("write", path, error)
}

fn stop(failed: &str, path: &Path, error: &dyn std::fmt::Display) -> anyhow::Error {
    let line = format!(
        "data {failed} failed on {}: {error}; stopping so the next start recovers from the write-ahead log",
        path.display()
    );
    tracing::error!("{line}");
    #[cfg(test)]
    {
        test_fault::record_stop(path);
        anyhow::anyhow!(line)
    }
    #[cfg(not(test))]
    {
        eprintln!("{line}");
        crate::logging::flush();
        std::process::exit(i32::from(EXIT_SYNC_FAILED))
    }
}
