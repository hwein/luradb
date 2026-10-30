//! Directories in which file creation fails, as in a read-only directory but
//! for any user, root included, single files whose creation fails, files,
//! directories and files in a directory whose sync fails, writes that fail
//! with a given error, and the stops failed syncs and writes caused: tests
//! share the process.

use std::collections::{HashMap, HashSet};
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

fn unwritable() -> &'static Mutex<HashSet<PathBuf>> {
    static PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(Default::default)
}

/// Creating the file `path` fails until [`allow_writes_of`].
pub(crate) fn fail_writes_of(path: &Path) {
    unwritable().lock().unwrap().insert(path.to_path_buf());
}

pub(crate) fn allow_writes_of(path: &Path) {
    unwritable().lock().unwrap().remove(path);
}

/// Fails for a registered file and for a file directly in a registered
/// directory; its subdirectories stay writable, as with a read-only one.
pub(crate) fn check(path: &Path) -> io::Result<()> {
    let in_dir = path.parent().is_some_and(|dir| dirs().lock().unwrap().contains(dir));
    if in_dir || unwritable().lock().unwrap().contains(path) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("test fault: {}", path.display())));
    }
    Ok(())
}

fn unsyncable() -> &'static Mutex<HashSet<PathBuf>> {
    static PATHS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(Default::default)
}

/// Every sync of the file or directory `path` fails until [`allow_syncs_of`].
pub(crate) fn fail_syncs_of(path: &Path) {
    unsyncable().lock().unwrap().insert(path.to_path_buf());
}

pub(crate) fn allow_syncs_of(path: &Path) {
    unsyncable().lock().unwrap().remove(path);
}

fn failing_syncs() -> &'static Mutex<HashMap<PathBuf, u32>> {
    static SYNCS: OnceLock<Mutex<HashMap<PathBuf, u32>>> = OnceLock::new();
    SYNCS.get_or_init(Default::default)
}

/// The next `count` syncs of the files directly in the directory `dir` fail.
pub(crate) fn fail_next_syncs_in(dir: &Path, count: u32) {
    failing_syncs().lock().unwrap().insert(dir.to_path_buf(), count);
}

pub(crate) fn check_sync(path: &Path) -> io::Result<()> {
    let failed = || Err(io::Error::other(format!("test fault: sync of {}", path.display())));
    if unsyncable().lock().unwrap().contains(path) {
        return failed();
    }
    let mut syncs = failing_syncs().lock().unwrap();
    if let Some(dir) = path.parent() {
        if let Some(left) = syncs.get_mut(dir) {
            if *left <= 1 {
                syncs.remove(dir);
            } else {
                *left -= 1;
            }
            return failed();
        }
    }
    Ok(())
}

fn failing_writes() -> &'static Mutex<HashMap<PathBuf, (i32, u32)>> {
    static WRITES: OnceLock<Mutex<HashMap<PathBuf, (i32, u32)>>> = OnceLock::new();
    WRITES.get_or_init(Default::default)
}

/// The next `count` writes of the file `path`, or of the files directly in
/// the directory `path`, fail with the OS error `errno` and write nothing.
pub(crate) fn fail_next_writes(path: &Path, errno: i32, count: u32) {
    failing_writes().lock().unwrap().insert(path.to_path_buf(), (errno, count));
}

pub(crate) fn check_write(path: &Path) -> io::Result<()> {
    let mut writes = failing_writes().lock().unwrap();
    for key in [Some(path), path.parent()].into_iter().flatten() {
        if let Some((errno, left)) = writes.get_mut(key) {
            let (errno, done) = (*errno, *left <= 1);
            *left = left.saturating_sub(1);
            if done {
                writes.remove(key);
            }
            return Err(io::Error::from_raw_os_error(errno));
        }
    }
    Ok(())
}

fn stops() -> &'static Mutex<Vec<PathBuf>> {
    static STOPS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    STOPS.get_or_init(Default::default)
}

/// A stop after a failed sync or failed writes of `path`, in place of the
/// process exit.
pub(crate) fn record_stop(path: &Path) {
    stops().lock().unwrap().push(path.to_path_buf());
}

/// The paths below `root` whose failed syncs or writes stopped the server,
/// in order.
pub(crate) fn stops_under(root: &Path) -> Vec<PathBuf> {
    stops().lock().unwrap().iter().filter(|path| path.starts_with(root)).cloned().collect()
}
