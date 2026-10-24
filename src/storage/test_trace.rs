//! The syncs, manifest saves, deletions and log truncations on the files
//! below a watched directory, in order: tests share the process.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn traces() -> &'static Mutex<HashMap<PathBuf, Vec<String>>> {
    static TRACES: OnceLock<Mutex<HashMap<PathBuf, Vec<String>>>> = OnceLock::new();
    TRACES.get_or_init(Default::default)
}

/// Starts an empty trace of the steps on files below `root`.
pub(crate) fn watch(root: &Path) {
    traces().lock().unwrap().insert(root.to_path_buf(), Vec::new());
}

/// Appends `<step> <path relative to the root>` to the trace of every watched
/// root that holds `path`; the root itself shows as `.`.
pub(crate) fn record(path: &Path, step: &str) {
    for (root, trace) in traces().lock().unwrap().iter_mut() {
        if let Ok(relative) = path.strip_prefix(root) {
            let shown = if relative.as_os_str().is_empty() { Path::new(".") } else { relative };
            trace.push(format!("{step} {}", shown.display()));
        }
    }
}

/// The steps recorded below `root` since [`watch`], in order.
pub(crate) fn steps(root: &Path) -> Vec<String> {
    traces().lock().unwrap().get(root).cloned().unwrap_or_default()
}
