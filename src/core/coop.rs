//! Cooperative scheduling helpers: yielding, bounded offloading, and reads
//! that give up rather than wait for the disk.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

/// The state of one [`inline_read`].
#[derive(Default)]
struct InlineRead {
    /// Set once a read there would have waited for the disk.
    gave_up: Cell<bool>,
    /// Run if the read gives up; see [`on_give_up`].
    on_give_up: RefCell<Vec<Box<dyn FnOnce() + Send>>>,
}

tokio::task_local! {
    static INLINE_READ: InlineRead;
}

/// Runs `fut` as a read that must not wait for the disk; also returns whether
/// it gave up because it would have had to ([`would_block`]), after running
/// what it registered with [`on_give_up`]. Task-local, so it follows `fut`
/// from one worker thread to the next.
pub async fn inline_read<F: Future>(fut: F) -> (F::Output, bool) {
    INLINE_READ
        .scope(InlineRead::default(), async {
            let out = fut.await;
            let (gave_up, on_give_up) = INLINE_READ.with(|read| (read.gave_up.get(), read.on_give_up.take()));
            if gave_up {
                on_give_up.into_iter().for_each(|f| f());
            }
            (out, gave_up)
        })
        .await
}

/// True inside [`inline_read`], which then reports the read as given up: the
/// caller must fail instead of waiting for the disk. False anywhere else.
pub fn would_block() -> bool {
    INLINE_READ.try_with(|read| read.gave_up.set(true)).is_ok()
}

/// True inside [`inline_read`]; unlike [`would_block`], it does not give the read up.
pub fn in_inline_scope() -> bool {
    INLINE_READ.try_with(|_| ()).is_ok()
}

/// Inside [`inline_read`], runs `f` once the read ends if it gave up, so
/// that the read can undo what it did before; anywhere else drops `f`.
pub fn on_give_up(f: impl FnOnce() + Send + 'static) {
    let _ = INLINE_READ.try_with(|read| read.on_give_up.borrow_mut().push(Box::new(f)));
}

#[cfg(test)]
type ResidencyHook = Box<dyn Fn(&[u8]) -> bool>;

#[cfg(test)]
thread_local! {
    static RESIDENCY: RefCell<Option<ResidencyHook>> = const { RefCell::new(None) };
}

/// Lets [`resident`] answer with `hook` on this thread instead of asking the
/// kernel; `None` asks the kernel again.
#[cfg(test)]
pub(crate) fn set_residency(hook: Option<ResidencyHook>) {
    RESIDENCY.with(|residency| *residency.borrow_mut() = hook);
}

/// True if every page that `bytes`, a slice of a memory mapping, overlaps is
/// in memory, so that reading it cannot wait for the disk. One `mincore`
/// call per 64 pages; a failed call counts as not resident.
pub fn resident(bytes: &[u8]) -> bool {
    #[cfg(test)]
    if let Some(answer) = RESIDENCY.with(|residency| residency.borrow().as_ref().map(|hook| hook(bytes))) {
        return answer;
    }
    let page = page_size();
    let end = bytes.as_ptr() as usize + bytes.len();
    let mut addr = bytes.as_ptr() as usize & !(page - 1);
    let mut pages = [0u8; 64];
    while addr < end {
        let len = (end - addr).min(pages.len() * page);
        // SAFETY: `addr` is page-aligned and `addr..addr + len` lies in the
        // mapping that holds `bytes`; `pages` has room for every page of it.
        if unsafe { libc::mincore(addr as *mut libc::c_void, len, pages.as_mut_ptr()) } != 0 {
            return false;
        }
        if pages[..len.div_ceil(page)].iter().any(|state| state & 1 == 0) {
            return false;
        }
        addr += len;
    }
    true
}

fn page_size() -> usize {
    // sysconf(_SC_PAGESIZE) is always a positive power of two on Linux.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Hands the thread back every `every` ticks.
pub struct YieldEvery {
    every: u32,
    n: u32,
}

impl YieldEvery {
    /// `every` of `0` is clamped to `1`, so a zero still yields on every tick.
    pub fn new(every: u32) -> Self {
        Self { every: every.max(1), n: 0 }
    }

    /// Counts one unit of work and yields on every `every`-th call.
    pub async fn tick(&mut self) {
        self.n = self.n.wrapping_add(1);
        if self.n.is_multiple_of(self.every) {
            tokio::task::yield_now().await;
        }
    }
}

/// Process-wide permits for [`offload`]. Installed by [`init`] from the
/// config; a caller that runs before it (tests) falls back to the auto count.
static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Resolves the configured permit count: `0` means auto — every core beyond
/// the request-path thread and one core of headroom.
pub(crate) fn permit_count(configured: usize, cores: usize) -> usize {
    if configured > 0 {
        configured
    } else {
        cores.saturating_sub(2).max(1)
    }
}

pub fn available_cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn permits() -> &'static Arc<Semaphore> {
    PERMITS.get_or_init(|| Arc::new(Semaphore::new(permit_count(0, available_cores()))))
}

/// Sets the process-wide [`offload`] cap; called once at engine bootstrap.
pub fn init(configured: usize) {
    let n = permit_count(configured, available_cores());
    if PERMITS.set(Arc::new(Semaphore::new(n))).is_ok() {
        tracing::info!("CPU offload permits: {n}");
    } else {
        tracing::warn!("CPU offload permits already installed; configured value {n} ignored");
    }
}

/// Runs a `Send`-able pure computation on the blocking pool, bounded by a
/// process-wide permit count. Callers
/// above the cap wait for a permit — there is no error path.
pub async fn offload<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    run_bounded(Arc::clone(permits()), f).await
}

/// [`offload`] against an explicit permit pool — the internal seam the cap
/// test uses, so it never depends on the process-wide `OnceLock`.
async fn run_bounded<T: Send + 'static>(
    permits: Arc<Semaphore>,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let _permit = permits.acquire().await.expect("the offload semaphore is never closed");
    tokio::task::spawn_blocking(f).await.expect("offloaded closure panicked")
}

/// Test-only interleaving harness: spawns `long` and
/// then `small` onto the engine runtime and returns their completion order.
/// `small` can only finish first if `long` hands the thread back.
#[cfg(test)]
pub(crate) async fn completion_order<L, S>(long: L, small: S) -> Vec<&'static str>
where
    L: std::future::Future<Output = ()> + 'static,
    S: std::future::Future<Output = ()> + 'static,
{
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let long_order = Arc::clone(&order);
    let long = compio::runtime::spawn(async move {
        long.await;
        long_order.lock().unwrap().push("long");
    });
    let small_order = Arc::clone(&order);
    let small = compio::runtime::spawn(async move {
        small.await;
        small_order.lock().unwrap().push("small");
    });
    long.await.unwrap();
    small.await.unwrap();
    let out = order.lock().unwrap().clone();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    // 1. `tick` hands the thread back on exactly every `every`-th call: a task
    // spawned before the ticking can only set its flag while we are yielded.
    #[tokio::test]
    #[allow(clippy::disallowed_methods, reason = "a tokio runtime, like the reader pool")]
    async fn test_yield_every_yields_on_every_nth_tick() {
        let flag = Arc::new(AtomicBool::new(false));
        let observer = Arc::clone(&flag);
        tokio::spawn(async move { observer.store(true, Ordering::SeqCst) });

        let mut coop = YieldEvery::new(3);
        coop.tick().await;
        assert!(!flag.load(Ordering::SeqCst), "tick 1 must not yield");
        coop.tick().await;
        assert!(!flag.load(Ordering::SeqCst), "tick 2 must not yield");
        coop.tick().await;
        assert!(flag.load(Ordering::SeqCst), "tick 3 must yield");

        // Second cycle: the counter keeps running, so tick 6 yields again.
        flag.store(false, Ordering::SeqCst);
        let observer = Arc::clone(&flag);
        tokio::spawn(async move { observer.store(true, Ordering::SeqCst) });
        coop.tick().await;
        coop.tick().await;
        assert!(!flag.load(Ordering::SeqCst), "ticks 4 and 5 must not yield");
        coop.tick().await;
        assert!(flag.load(Ordering::SeqCst), "tick 6 must yield");
    }

    // 2a. The closure runs off the runtime thread.
    #[tokio::test]
    async fn test_offload_runs_on_a_blocking_thread() {
        let runtime_thread = std::thread::current().id();
        let blocking_thread = offload(move || std::thread::current().id()).await;
        assert_ne!(runtime_thread, blocking_thread);
    }

    // 2b. One permit serializes: the second offload starts only after the
    // first released its permit. Observed via `is_finished`, not timing.
    #[tokio::test]
    #[allow(clippy::disallowed_methods, reason = "a tokio runtime, like the reader pool")]
    async fn test_offload_waits_for_a_free_permit() {
        let permits = Arc::new(Semaphore::new(1));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let first = tokio::spawn(run_bounded(Arc::clone(&permits), move || {
            release_rx.recv().expect("the test releases the blocked closure");
        }));
        let second = tokio::spawn(run_bounded(Arc::clone(&permits), || ()));

        // Both tasks get polled; the first holds the only permit while its
        // closure blocks, so the second is still parked on `acquire`.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(!second.is_finished(), "the second offload must wait for a permit");

        release_tx.send(()).unwrap();
        first.await.unwrap();
        second.await.unwrap();
    }

    // Only a read inside `inline_read` learns to give up instead of waiting
    // for the disk; its scope reports that across awaits, and the next scope
    // starts afresh.
    #[tokio::test]
    async fn test_inline_read_reports_a_read_that_would_block() {
        assert!(!would_block());

        let (inside, gave_up) = inline_read(async {
            tokio::task::yield_now().await;
            let nested = async { would_block() }.await;
            tokio::task::yield_now().await;
            nested
        })
        .await;
        assert!(inside && gave_up);

        let ((), gave_up) = inline_read(async { tokio::task::yield_now().await }).await;
        assert!(!gave_up);
        assert!(!would_block());
    }

    // Asking whether a read runs inline does not give it up.
    #[tokio::test]
    async fn test_in_inline_scope_does_not_give_the_read_up() {
        assert!(!in_inline_scope());
        let (inside, gave_up) = inline_read(async { in_inline_scope() }).await;
        assert!(inside && !gave_up);
    }

    // An untouched anonymous page is not in memory until written; a range is
    // resident only if every page it overlaps is, also past one `mincore` batch.
    #[test]
    fn test_resident_reports_only_ranges_whose_pages_are_all_in_memory() {
        let page = page_size();
        let mut map = memmap2::MmapMut::map_anon(200 * page).unwrap();
        map[150 * page] = 1;
        map[199 * page] = 1;
        assert!(resident(&map[150 * page..151 * page]));
        assert!(resident(&map[150 * page + 100..150 * page + 200]));
        assert!(!resident(&map[149 * page + 10..150 * page + 5]));
        assert!(!resident(&map[150 * page..152 * page]));
        assert!(!resident(&map[..]));
        assert!(resident(&map[150 * page..150 * page]));
        for i in 0..200 {
            map[i * page] = 1;
        }
        assert!(resident(&map[..]));
        assert!(resident(&map[10..]));
    }

    // What a read registers runs once it gives up; not when it ends without
    // giving up, nor outside an inline read, nor when it is dropped unfinished.
    #[tokio::test]
    async fn test_on_give_up_runs_only_for_a_read_that_gave_up() {
        let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let register = || {
            let ran = Arc::clone(&ran);
            on_give_up(move || {
                ran.fetch_add(1, Ordering::SeqCst);
            });
        };

        let ((), gave_up) = inline_read(async {
            register();
            tokio::task::yield_now().await;
            would_block();
        })
        .await;
        assert!(gave_up);
        assert_eq!(ran.load(Ordering::SeqCst), 1);

        let ((), gave_up) = inline_read(async {
            register();
            tokio::task::yield_now().await;
        })
        .await;
        assert!(!gave_up);
        register();
        assert_eq!(ran.load(Ordering::SeqCst), 1);

        // Dropped before it ends, as when the client goes away.
        let dropped = inline_read(async {
            register();
            would_block();
            std::future::pending::<()>().await;
        });
        assert!(futures::FutureExt::now_or_never(dropped).is_none());
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    // `0` resolves to the auto count, anything else is taken verbatim.
    #[test]
    fn test_permit_count_auto_and_explicit() {
        assert_eq!(permit_count(0, 32), 30);
        assert_eq!(permit_count(0, 3), 1);
        assert_eq!(permit_count(0, 2), 1);
        assert_eq!(permit_count(0, 1), 1);
        assert_eq!(permit_count(7, 32), 7);
        assert_eq!(permit_count(7, 1), 7);
    }
}
