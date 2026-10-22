//! Test-only timestamps along a request's way through the server: arrival on
//! the frontend, handover to the last bridge channel, start and end of the
//! handler there, each write-ahead-log append from queueing in the storage hub
//! to its writer resuming, and the answer back on the frontend; plus the
//! completion times of the hub's write and fdatasync chains. Records nothing
//! until [`start`] turns it on.

use crate::core::storage_thread::WalTarget;
use axum::http::{request, Extensions};
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;
use tokio::sync::oneshot;

static ON: AtomicBool = AtomicBool::new(false);
static REQUESTS: Mutex<Vec<Stamps>> = Mutex::new(Vec::new());
static BATCHES: Mutex<Vec<Batch>> = Mutex::new(Vec::new());
/// (engine, LSN) of each append the hub answered → (batch taken, answered).
type HubStamps = HashMap<(u8, u64), (Instant, Instant)>;
static HUB: LazyLock<Mutex<HubStamps>> = LazyLock::new(Default::default);

tokio::task_local! {
    static CURRENT: Trace;
}

/// One request's stamps.
#[derive(Debug, Clone)]
pub(crate) struct Stamps {
    pub(crate) path: String,
    pub(crate) arrived: Instant,
    /// Handed to the last bridge channel it took; a SQL write takes the
    /// reader pool's first, then the engine thread's.
    pub(crate) shipped: Option<Instant>,
    /// The last handler started: the one behind that channel.
    pub(crate) taken: Option<Instant>,
    /// The first handler returned: the innermost one.
    pub(crate) answered: Option<Instant>,
    pub(crate) appends: Vec<Append>,
    /// The answer is back on the frontend.
    pub(crate) done: Option<Instant>,
}

/// One write-ahead-log append of a request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Append {
    pub(crate) queued: Instant,
    /// The hub took the batch with it.
    pub(crate) picked: Instant,
    /// The hub answered it.
    pub(crate) answered: Instant,
    /// The writer runs again.
    pub(crate) resumed: Instant,
}

/// One submit of the hub: per chain, when its write and its fdatasync completed.
#[derive(Debug, Clone)]
pub(crate) struct Batch {
    pub(crate) submitted: Instant,
    pub(crate) chains: Vec<(Option<Instant>, Option<Instant>)>,
}

#[derive(Clone, Copy)]
struct Arrived(Instant);

/// The stamps of a request, shared by every thread it passes.
#[derive(Clone)]
pub(crate) struct Trace(Arc<Mutex<Stamps>>);

impl Trace {
    fn stamp(&self, f: impl FnOnce(&mut Stamps)) {
        f(&mut self.0.lock().unwrap());
    }
}

/// Clears what earlier measurements left and starts recording.
pub(crate) fn start() {
    REQUESTS.lock().unwrap().clear();
    BATCHES.lock().unwrap().clear();
    HUB.lock().unwrap().clear();
    ON.store(true, Ordering::SeqCst);
}

/// Stops recording; returns the requests answered and the hub's submits since [`start`].
pub(crate) fn stop() -> (Vec<Stamps>, Vec<Batch>) {
    ON.store(false, Ordering::SeqCst);
    (std::mem::take(&mut REQUESTS.lock().unwrap()), std::mem::take(&mut BATCHES.lock().unwrap()))
}

fn on() -> bool {
    ON.load(Ordering::Relaxed)
}

/// A request arrives on the frontend.
pub(crate) fn arrive(extensions: &mut Extensions) {
    if on() {
        extensions.insert(Arrived(Instant::now()));
    }
}

/// A request goes into a bridge channel. The first handover of an arrived
/// request starts its trace and returns it to [`reply`].
pub(crate) fn ship(mut parts: request::Parts) -> (request::Parts, Option<Trace>) {
    let now = Instant::now();
    if let Some(trace) = parts.extensions.get::<Trace>() {
        trace.stamp(|s| s.shipped = Some(now));
        return (parts, None);
    }
    let Some(Arrived(arrived)) = parts.extensions.get::<Arrived>().copied() else { return (parts, None) };
    let stamps = Stamps {
        path: parts.uri.path().to_string(),
        arrived,
        shipped: Some(now),
        taken: None,
        answered: None,
        appends: Vec::new(),
        done: None,
    };
    let trace = Trace(Arc::new(Mutex::new(stamps)));
    parts.extensions.insert(trace.clone());
    (parts, Some(trace))
}

/// Waits for the answer to a request [`ship`] started a trace for, then records it.
pub(crate) fn reply<F: Future>(trace: Option<Trace>, answer: F) -> impl Future<Output = F::Output> {
    async move {
        let answer = answer.await;
        if let Some(trace) = trace {
            trace.stamp(|s| s.done = Some(Instant::now()));
            REQUESTS.lock().unwrap().push(trace.0.lock().unwrap().clone());
        }
        answer
    }
}

/// The trace a handler's request carries, read before routing consumes it.
pub(crate) fn of(extensions: &Extensions) -> Option<Trace> {
    extensions.get::<Trace>().cloned()
}

/// Runs a handler with its request's trace at hand for [`wal_wait`].
pub(crate) fn within<F: Future>(trace: Option<Trace>, handler: F) -> impl Future<Output = F::Output> {
    async move {
        let Some(trace) = trace else { return handler.await };
        trace.stamp(|s| s.taken = Some(Instant::now()));
        let out = CURRENT.scope(trace.clone(), handler).await;
        trace.stamp(|s| {
            s.answered.get_or_insert_with(Instant::now);
        });
        out
    }
}

type Appended = Result<anyhow::Result<(u64, u64)>, oneshot::error::RecvError>;

/// Waits for an append to `engine`'s log queued right after this call and
/// adds its stamps to the trace of the handler running it.
pub(crate) fn wal_wait(
    engine: WalTarget,
    rx: oneshot::Receiver<anyhow::Result<(u64, u64)>>,
) -> impl Future<Output = Appended> {
    let queued = Instant::now();
    async move {
        let appended = rx.await;
        if let (true, Ok(Ok((_, lsn)))) = (on(), &appended) {
            let resumed = Instant::now();
            if let Some((picked, answered)) = HUB.lock().unwrap().remove(&(engine as u8, *lsn)) {
                let append = Append { queued, picked, answered, resumed };
                let _ = CURRENT.try_with(|trace| trace.stamp(|s| s.appends.push(append)));
            }
        }
        appended
    }
}

/// Now, while recording.
pub(crate) fn now() -> Option<Instant> {
    on().then(Instant::now)
}

/// The hub answers the appends with `lsns` to `engine`'s log, from a batch it took at `picked`.
pub(crate) fn hub_answered(picked: Option<Instant>, engine: WalTarget, lsns: impl Iterator<Item = u64>) {
    let Some(picked) = picked else { return };
    let answered = Instant::now();
    let mut hub = HUB.lock().unwrap();
    for lsn in lsns {
        hub.insert((engine as u8, lsn), (picked, answered));
    }
}

/// A submit of the hub, shared by its chains; recorded once its last chain is done.
struct Shared(RefCell<Batch>);

impl Drop for Shared {
    fn drop(&mut self) {
        let batch = self.0.get_mut();
        if !batch.chains.is_empty() {
            BATCHES.lock().unwrap().push(batch.clone());
        }
    }
}

/// The submit the hub starts, while recording.
pub(crate) struct SubmitStamps(Option<Rc<Shared>>);

impl SubmitStamps {
    pub(crate) fn start() -> Self {
        Self(now().map(|submitted| Rc::new(Shared(RefCell::new(Batch { submitted, chains: Vec::new() })))))
    }

    /// The stamps of the submit's next chain.
    pub(crate) fn chain(&self) -> ChainStamps {
        ChainStamps(self.0.as_ref().map(|shared| {
            let mut batch = shared.0.borrow_mut();
            batch.chains.push((None, None));
            (Rc::clone(shared), batch.chains.len() - 1)
        }))
    }
}

/// When one chain's write and fdatasync completed.
#[derive(Default)]
pub(crate) struct ChainStamps(Option<(Rc<Shared>, usize)>);

impl ChainStamps {
    pub(crate) fn complete(&self, synced: bool) {
        let Some((shared, chain)) = &self.0 else { return };
        let stamps = &mut shared.0.borrow_mut().chains[*chain];
        let now = Some(Instant::now());
        if synced {
            stamps.1 = now;
        } else {
            stamps.0 = now;
        }
    }
}
