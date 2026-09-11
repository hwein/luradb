//! Cooperative scheduling helpers for the single request-path thread
//! (spec perf/017).

use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

/// Hands the thread back every `every` ticks (spec perf/017).
pub struct YieldEvery {
    every: u32,
    n: u32,
}

impl YieldEvery {
    /// `every` of `0` is clamped to `1` — the modulo below would divide by zero.
    pub fn new(every: u32) -> Self {
        Self { every: every.max(1), n: 0 }
    }

    /// Counts one unit of work and yields on every `every`-th call.
    pub async fn tick(&mut self) {
        self.n = self.n.wrapping_add(1);
        if self.n % self.every == 0 {
            tokio::task::yield_now().await;
        }
    }
}

/// Process-wide permits for [`offload`]. Installed by [`init`] from the
/// config; a caller that runs before it (tests) falls back to the auto count.
static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Resolves the configured permit count: `0` means auto — every core beyond
/// the request-path thread and one core of headroom (spec perf/017 A5).
fn permit_count(configured: usize, cores: usize) -> usize {
    if configured > 0 {
        configured
    } else {
        cores.saturating_sub(2).max(1)
    }
}

pub(crate) fn available_cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn permits() -> &'static Arc<Semaphore> {
    PERMITS.get_or_init(|| Arc::new(Semaphore::new(permit_count(0, available_cores()))))
}

/// Sets the process-wide [`offload`] cap; called once from `main`.
pub fn init(configured: usize) {
    let n = permit_count(configured, available_cores());
    if PERMITS.set(Arc::new(Semaphore::new(n))).is_ok() {
        tracing::info!("CPU offload permits: {n}");
    } else {
        tracing::warn!("CPU offload permits already installed; configured value {n} ignored");
    }
}

/// Runs a `Send`-able pure computation on the blocking pool, bounded by a
/// process-wide permit count (spec perf/017 A4 / concept 007 §4.9). Callers
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

/// Test-only interleaving harness (spec perf/017 §Tests): spawns `long` and
/// then `small` onto the current-thread runtime and returns their completion
/// order. `small` can only finish first if `long` hands the thread back.
#[cfg(test)]
pub(crate) async fn completion_order<L, S>(long: L, small: S) -> Vec<&'static str>
where
    L: std::future::Future<Output = ()> + Send + 'static,
    S: std::future::Future<Output = ()> + Send + 'static,
{
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let long_order = Arc::clone(&order);
    let long = tokio::spawn(async move {
        long.await;
        long_order.lock().unwrap().push("long");
    });
    let small_order = Arc::clone(&order);
    let small = tokio::spawn(async move {
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

    // A5: `0` resolves to the auto count, anything else is taken verbatim.
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
