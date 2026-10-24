pub mod format;
pub mod sstable;
pub mod vlog;
pub mod bloom;
pub mod file_manager;
pub mod manifest;
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
    let mut unique: Vec<PathBuf> = Vec::with_capacity(dirs.len());
    for dir in dirs {
        if !unique.iter().any(|seen| seen == dir) {
            unique.push(dir.to_path_buf());
        }
    }
    tokio::task::spawn_blocking(move || unique.iter().try_for_each(|dir| sync_dir(dir))).await?
}
