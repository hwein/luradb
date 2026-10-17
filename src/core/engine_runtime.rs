//! The engine thread's runtime (spec perf/020): compio on one io_uring ring
//! with `SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN | TASKRUN_FLAG`, inside
//! the handle of a tokio runtime that keeps `coop::offload`, `tokio::fs` and
//! the IPC sockets working. File I/O runs in [`spawn_io`] tasks, which
//! [`run`] lets finish before the runtime can drop (compio #1102).

use compio::buf::{BufResult, IntoInner};
use compio::driver::{op, ProactorBuilder};
use compio::fs::OpenOptions;
use compio::runtime::{JoinError, JoinHandle, Runtime, RuntimeBuilder};
use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};

/// Start error on kernels whose io_uring rejects the ring flags.
const KERNEL_TOO_OLD: &str = "LuraDB requires Linux kernel 6.1 or newer (io_uring DEFER_TASKRUN)";

/// compio's default wake slots: the test harness's runtime gets them, the
/// server's runtime adds them for its background tasks.
pub const DEFAULT_REMOTE_WAKES: usize = 64;

/// Builds an engine runtime. `remote_wakes` sizes compio's queue for wakes
/// from other threads; below compio 0.20 it is fixed, and a waker finding it
/// full spins until the engine thread drains it (compio #1044).
pub fn build(remote_wakes: usize) -> anyhow::Result<Runtime> {
    let mut proactor = ProactorBuilder::new();
    proactor.single_issuer(true).defer_taskrun(true).coop_taskrun(true).taskrun_flag(true);
    RuntimeBuilder::new()
        .with_proactor(proactor)
        .sync_queue_size(remote_wakes)
        .build()
        .map_err(startup_error)
}

/// Maps a failed runtime build to the start error: `EINVAL` from
/// `io_uring_setup` means the kernel does not know the ring flags.
fn startup_error(e: std::io::Error) -> anyhow::Error {
    let context = if e.raw_os_error() == Some(libc::EINVAL) {
        KERNEL_TOO_OLD
    } else {
        "failed to set up the engine thread's io_uring ring"
    };
    anyhow::Error::new(e).context(context)
}

/// Runs `main` on `rt` and then every [`spawn_io`] task to its end, so the
/// runtime drops without I/O in flight.
pub fn run<F: Future>(rt: &Runtime, main: F) -> F::Output {
    rt.block_on(async {
        let out = main.await;
        std::future::poll_fn(io_idle).await;
        out
    })
}

/// Test harness: [`run`] on a fresh engine runtime with the same ring flags,
/// inside the handle of one tokio runtime shared by the whole process.
pub fn block_on<F: Future>(main: F) -> F::Output {
    static TOKIO: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let tokio = TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to build the test harness's tokio runtime")
    });
    let _tokio = tokio.enter();
    let rt = build(DEFAULT_REMOTE_WAKES).expect("failed to build the engine runtime");
    run(&rt, main)
}

/// Runs `io` as its own task on the engine runtime. Dropping the returned
/// handle detaches the task instead of cancelling it, so a write runs to its
/// end; the handle is `Send` even though compio's file types are not.
pub fn spawn_io<F>(io: F) -> IoTask<F::Output>
where
    F: Future + 'static,
{
    let pending = IoPending::start();
    IoTask(Some(compio::runtime::spawn(async move {
        let _pending = pending;
        io.await
    })))
}

/// Handle of a [`spawn_io`] task; resolves to its output.
pub struct IoTask<T>(Option<JoinHandle<T>>);

impl<T> Future for IoTask<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let handle = self.0.as_mut().expect("IoTask polled after completion");
        let result = std::task::ready!(Pin::new(handle).poll(cx));
        self.0 = None;
        Poll::Ready(match result {
            Ok(out) => out,
            Err(JoinError::Panicked(payload)) => std::panic::resume_unwind(payload),
            Err(JoinError::Cancelled) => panic!("the engine runtime cancelled an I/O task"),
        })
    }
}

impl<T> Drop for IoTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.detach();
        }
    }
}

// compio's file type is `!Send`. Engine structures shared with other threads
// keep a std file instead and do their I/O through the functions below, on
// the engine ring as I/O tasks.

/// Opens `path` with `options` and returns a duplicate of the descriptor.
pub fn open(path: PathBuf, options: OpenOptions) -> IoTask<io::Result<std::fs::File>> {
    spawn_io(async move {
        let file = options.open(path).await?;
        Ok(std::fs::File::from(file.as_fd().try_clone_to_owned()?))
    })
}

/// Reads up to `len` bytes at `pos`; fewer only at the end of the file.
pub fn read_at(file: &Arc<std::fs::File>, len: usize, pos: u64) -> IoTask<io::Result<Vec<u8>>> {
    let file = Arc::clone(file);
    spawn_io(async move {
        let BufResult(read, done) =
            compio::runtime::submit(op::ReadAt::new(file, pos, Vec::with_capacity(len))).await;
        let read = read?;
        let mut buf = done.into_inner();
        // SAFETY: the kernel filled the first `read` bytes of the capacity.
        unsafe { buf.set_len(read) };
        Ok(buf)
    })
}

/// Writes all of `data` at `pos`.
pub fn write_all_at(file: &Arc<std::fs::File>, mut data: Vec<u8>, mut pos: u64) -> IoTask<io::Result<()>> {
    let file = Arc::clone(file);
    spawn_io(async move {
        while !data.is_empty() {
            let BufResult(written, done) =
                compio::runtime::submit(op::WriteAt::new(Arc::clone(&file), pos, data)).await;
            data = done.into_inner();
            match written? {
                0 => return Err(io::ErrorKind::WriteZero.into()),
                n => {
                    data.drain(..n);
                    pos += n as u64;
                }
            }
        }
        Ok(())
    })
}

/// `fsync`, or `fdatasync` with `datasync`.
pub fn sync(file: &Arc<std::fs::File>, datasync: bool) -> IoTask<io::Result<()>> {
    let file = Arc::clone(file);
    spawn_io(async move { compio::runtime::submit(op::Sync::new(file, datasync)).await.0.map(|_| ()) })
}

/// [`spawn_io`] tasks of this thread's runtime that have not ended yet.
#[derive(Default)]
struct IoTasks {
    pending: usize,
    idle: Option<Waker>,
}

thread_local! {
    static IO_TASKS: RefCell<IoTasks> = RefCell::default();
}

/// Counts one [`spawn_io`] task from its spawn until its future is dropped.
struct IoPending;

impl IoPending {
    fn start() -> Self {
        IO_TASKS.with_borrow_mut(|tasks| tasks.pending += 1);
        IoPending
    }
}

impl Drop for IoPending {
    fn drop(&mut self) {
        let _ = IO_TASKS.try_with(|tasks| {
            let mut tasks = tasks.borrow_mut();
            tasks.pending -= 1;
            if tasks.pending == 0 {
                if let Some(waker) = tasks.idle.take() {
                    waker.wake();
                }
            }
        });
    }
}

fn io_idle(cx: &mut Context<'_>) -> Poll<()> {
    IO_TASKS.with_borrow_mut(|tasks| {
        if tasks.pending == 0 {
            Poll::Ready(())
        } else {
            tasks.idle = Some(cx.waker().clone());
            Poll::Pending
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // R4: the ring setup's EINVAL becomes the start error naming the minimum
    // kernel; any other errno keeps a generic message.
    #[test]
    fn einval_from_the_ring_setup_names_the_minimum_kernel() {
        let err = startup_error(std::io::Error::from_raw_os_error(libc::EINVAL));
        assert_eq!(err.to_string(), "LuraDB requires Linux kernel 6.1 or newer (io_uring DEFER_TASKRUN)");

        let err = startup_error(std::io::Error::from_raw_os_error(libc::ENOMEM));
        assert!(!err.to_string().contains("6.1"), "{err}");
        assert!(format!("{err:#}").contains("io_uring"), "{err:#}");
    }

    // The harness runs compio tasks and timers, and the tokio facilities the
    // engine still uses: the blocking pool and tokio::fs.
    #[test]
    fn the_harness_runs_compio_tasks_and_the_entered_tokio_handle() {
        block_on(async {
            let task = compio::runtime::spawn(async {
                compio::time::sleep(Duration::from_millis(1)).await;
                std::thread::current().id()
            });
            assert_eq!(task.await.unwrap(), std::thread::current().id());

            let offloaded = crate::core::coop::offload(|| std::thread::current().id()).await;
            assert_ne!(offloaded, std::thread::current().id());

            let dir = tempfile::TempDir::new().unwrap();
            tokio::fs::write(dir.path().join("f"), "clé").await.unwrap();
            assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), "clé".as_bytes());
        });
    }

    // Step 8: an I/O task whose handle is dropped still runs to its end, and
    // `run` returns only after it did — the runtime never drops mid-write.
    #[test]
    fn a_dropped_io_task_finishes_before_the_runtime_returns() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("late");
        let write_path = path.clone();
        block_on(async move {
            drop(spawn_io(async move {
                compio::time::sleep(Duration::from_millis(20)).await;
                let compio::BufResult(res, _) = compio::fs::write(&write_path, b"written".to_vec()).await;
                res.unwrap();
            }));
        });
        assert_eq!(std::fs::read(&path).unwrap(), b"written");
    }

    // A std file opened through compio takes positional writes and reads on
    // the engine ring; a read past the end returns what is there.
    #[test]
    fn a_shared_file_writes_and_reads_positionally() {
        block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            let file = Arc::new(open(dir.path().join("f"), options).await.unwrap());

            write_all_at(&file, "clé ✓".as_bytes().to_vec(), 3).await.unwrap();
            write_all_at(&file, b"abc".to_vec(), 0).await.unwrap();
            sync(&file, true).await.unwrap();

            assert_eq!(read_at(&file, 64, 0).await.unwrap(), "abcclé ✓".as_bytes());
            assert_eq!(read_at(&file, 2, 3).await.unwrap(), b"cl");
        });
    }

    // An I/O task's handle is `Send`, its output arrives, and its panic
    // reaches the awaiting caller.
    #[test]
    fn an_io_task_hands_back_its_output_and_its_panic() {
        fn assert_send<T: Send>(_: &T) {}
        block_on(async {
            let task = spawn_io(async { 7 });
            assert_send(&task);
            assert_eq!(task.await, 7);

            let caught = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(spawn_io(async {
                panic!("boom");
            })))
            .await;
            assert!(caught.is_err());
        });
    }
}
