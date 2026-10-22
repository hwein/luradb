//! Data directory layout: every engine keeps the files of data shard `k` —
//! value log, SSTables, page file — in a `shard_<k>/` directory beside the
//! configured path; its write-ahead log stays a single file. A data directory
//! from before this layout moves into `shard_0/` on the first start.

use crate::config::LuraConfig;
use crate::control::system;
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::storage::vlog::{discover_generations, generation_path};
use anyhow::Context;
use std::path::{Path, PathBuf};

/// `<dir>/shard_<shard>`.
pub(crate) fn shard_dir(dir: &Path, shard: usize) -> PathBuf {
    dir.join(format!("shard_{shard}"))
}

/// `path` with `shard_<shard>/` inserted before its file name.
pub(crate) fn shard_file(path: &Path, shard: usize) -> PathBuf {
    let dir = path.parent().unwrap_or(Path::new(""));
    shard_dir(dir, shard).join(path.file_name().unwrap_or_default())
}

/// The data shards to start with: as configured, or with `0` as many as the
/// data directory was written with — one laid out without shard directories
/// was written with one — and `auto` for a new one.
pub(super) async fn shard_count(config: &LuraConfig, sys: &LsmStorageEngine, auto: u16) -> anyhow::Result<u16> {
    if config.multicore.shards > 0 {
        return Ok(config.multicore.shards);
    }
    let stored = match system::stored_shard_count(sys).await? {
        Some(stored) => stored,
        None if !system::layout_is_sharded(sys).await? && !legacy_files(config).await?.is_empty() => 1,
        None => return Ok(auto),
    };
    tracing::info!("Data shards: {stored}, as the data directory was written; the shard migration tool changes it.");
    Ok(stored)
}

/// Moves the files of a data directory laid out without shard directories
/// into `shard_0/` and records the layout, once: a later start finds the
/// marker and moves nothing. Such data was written by one shard, so a start
/// with more is refused before anything moves, and so is one that finds a
/// file both in its old place and in `shard_0/`. The shard count is stored
/// before anything moves, so the marker never stands without it. Every move
/// is a `rename` on the same file system; a start interrupted halfway moves
/// the rest.
pub(super) async fn migrate(config: &LuraConfig, sys: &LsmStorageEngine, shards: u16) -> anyhow::Result<()> {
    if system::layout_is_sharded(sys).await? {
        return Ok(());
    }
    let moves = legacy_files(config).await?;
    if !moves.is_empty() && shards != 1 {
        anyhow::bail!("shard count changed (stored 1, configured {shards}) — run the shard migration tool");
    }
    system::check_shard_count(sys, shards).await?;
    if let Some((from, to)) = moves.iter().find(|(_, to)| to.exists()) {
        anyhow::bail!(
            "{} and {} both exist — keep the current one, remove the other and start again",
            from.display(),
            to.display()
        );
    }
    for (from, to) in &moves {
        let target_dir = to.parent().unwrap_or(Path::new(""));
        std::fs::create_dir_all(target_dir).with_context(|| format!("create {}", target_dir.display()))?;
        std::fs::rename(from, to).with_context(|| format!("move {} to {}", from.display(), to.display()))?;
    }
    let mut dirs: Vec<&Path> =
        moves.iter().flat_map(|(from, to)| [from.parent(), to.parent()]).flatten().collect();
    dirs.sort();
    dirs.dedup();
    for dir in dirs {
        sync_dir(dir)?;
    }
    if !moves.is_empty() {
        tracing::info!("Data directory layout: {} files moved into shard_0/.", moves.len());
    }
    system::mark_layout_sharded(sys).await
}

/// The files of the layout without shard directories that exist, each with
/// its place in `shard_0/`.
async fn legacy_files(config: &LuraConfig) -> anyhow::Result<Vec<(PathBuf, PathBuf)>> {
    let roots = [
        (&config.storage.vlog_path, &config.storage.sstable_dir),
        (&config.json.vlog_path, &config.json.sstable_dir),
        (&config.rel.vlog_path, &config.rel.sstable_dir),
    ];
    let mut files = vec![PathBuf::from(&config.storage.db_path)];
    for (vlog, sstables) in roots {
        let vlog = Path::new(vlog);
        files.push(vlog.to_path_buf());
        for id in discover_generations(vlog).await? {
            files.push(generation_path(vlog, id));
        }
        let sstables = Path::new(sstables);
        if sstables.is_dir() {
            for entry in std::fs::read_dir(sstables)? {
                let path = entry?.path();
                if path.is_file() && is_sstable_dir_file(&path) {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    files.dedup();
    Ok(files
        .into_iter()
        .filter(|file| file.is_file())
        .map(|file| {
            let to = shard_file(&file, 0);
            (file, to)
        })
        .collect())
}

/// SSTables, their temporary files and the manifest.
fn is_sstable_dir_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    name.starts_with("MANIFEST") || name.starts_with("sstable_")
}

/// Makes the renames in `dir` durable.
fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("sync {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_paths_insert_the_shard_directory() {
        assert_eq!(shard_file(Path::new("/data/luradb.vlog"), 0), PathBuf::from("/data/shard_0/luradb.vlog"));
        assert_eq!(shard_file(Path::new("luradb.db"), 3), PathBuf::from("shard_3/luradb.db"));
        assert_eq!(shard_dir(Path::new("/data/sstables"), 1), PathBuf::from("/data/sstables/shard_1"));
    }

    // A file found both in its old place and in shard_0/ stops the start
    // before anything moves: neither copy is overwritten.
    #[test]
    fn a_file_in_both_places_stops_the_move() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let config = super::super::tests::test_config(dir.path());
            let (db, vlog) = (Path::new(&config.storage.db_path), Path::new(&config.storage.vlog_path));
            std::fs::write(db, b"").unwrap();
            std::fs::write(vlog, b"old").unwrap();
            let moved = shard_file(vlog, 0);
            std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
            std::fs::write(&moved, b"new").unwrap();
            let sys = system::open(Path::new(&config.storage.system_dir)).await.unwrap();

            let err = migrate(&config, &sys, 1).await.unwrap_err();
            let expected = format!("{} and {} both exist", vlog.display(), moved.display());
            assert!(format!("{err:#}").contains(&expected), "{err:#}");
            assert!(db.is_file() && !shard_file(db, 0).exists(), "nothing moved");
            assert_eq!((std::fs::read(vlog).unwrap(), std::fs::read(&moved).unwrap()), (b"old".to_vec(), b"new".to_vec()));
            assert!(!system::layout_is_sharded(&sys).await.unwrap());
            sys.shutdown().await;
        })
    }

    /// The data shards to start with on a 12-core host.
    async fn on_twelve_cores(config: &LuraConfig, sys: &LsmStorageEngine) -> anyhow::Result<u16> {
        shard_count(config, sys, super::super::core_split(config, 12).1).await
    }

    // With `shards = 0`, a data directory keeps the shard count it was
    // written with — one laid out without shard directories was written with
    // one — and only a new one gets the count for the cores.
    #[test]
    fn auto_keeps_the_shard_count_of_an_existing_data_directory() {
        crate::core::engine_runtime::block_on(async {
            for (existing, expected) in [("stored", 1), ("legacy", 1), ("new", 3)] {
                let dir = tempfile::TempDir::new().unwrap();
                let mut config = super::super::tests::test_config(dir.path());
                config.multicore.shards = 0;
                let sys = system::open(Path::new(&config.storage.system_dir)).await.unwrap();
                match existing {
                    "stored" => system::check_shard_count(&sys, 1).await.unwrap(),
                    "legacy" => std::fs::write(&config.storage.db_path, b"").unwrap(),
                    _ => {}
                }
                assert_eq!(on_twelve_cores(&config, &sys).await.unwrap(), expected, "{existing}");
                sys.shutdown().await;
            }
        })
    }

    // A first start that stops right after the move, before the shard count
    // is checked, comes back with the one shard the data was written with.
    #[test]
    fn a_start_stopped_after_the_move_keeps_one_shard() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut config = super::super::tests::test_config(dir.path());
            config.multicore.shards = 0;
            std::fs::write(&config.storage.db_path, b"").unwrap();
            let system_dir = Path::new(&config.storage.system_dir);
            let sys = system::open(system_dir).await.unwrap();
            let shards = on_twelve_cores(&config, &sys).await.unwrap();
            migrate(&config, &sys, shards).await.unwrap();
            sys.shutdown().await;

            let sys = system::open(system_dir).await.unwrap();
            assert!(legacy_files(&config).await.unwrap().is_empty(), "moved into shard_0/");
            assert_eq!(on_twelve_cores(&config, &sys).await.unwrap(), 1);
            sys.shutdown().await;
        })
    }

    // A configured count is taken as it is; with shared memory on, auto
    // keeps the two shards the data directory was written with.
    #[test]
    fn a_configured_count_wins_and_shared_memory_keeps_two_stored_shards() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut config = super::super::tests::test_config(dir.path());
            let sys = system::open(Path::new(&config.storage.system_dir)).await.unwrap();
            system::check_shard_count(&sys, 2).await.unwrap();

            config.multicore.shards = 1;
            assert_eq!(on_twelve_cores(&config, &sys).await.unwrap(), 1);
            config.multicore.shards = 0;
            config.shm.enabled = true;
            assert_eq!(on_twelve_cores(&config, &sys).await.unwrap(), 2);
            sys.shutdown().await;
        })
    }
}
