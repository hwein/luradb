//! Directories in which file creation fails, as in a read-only directory but
//! for any user, root included: tests share the process.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn dirs() -> &'static Mutex<HashSet<PathBuf>> {
    static DIRS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    DIRS.get_or_init(Default::default)
}

pub(crate) fn fail_writes_in(dir: &Path) {
    dirs().lock().unwrap().insert(dir.to_path_buf());
}

pub(crate) fn allow_writes_in(dir: &Path) {
    dirs().lock().unwrap().remove(dir);
}

/// Fails for a file directly in a registered directory; its subdirectories
/// stay writable, as with a read-only one.
pub(crate) fn check(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) if dirs().lock().unwrap().contains(dir) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("test fault: {}", path.display())))
        }
        _ => Ok(()),
    }
}
