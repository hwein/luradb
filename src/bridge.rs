//! Engine bridge: routes each request by its domain to the data shard that
//! owns it. Point reads are answered right on the frontend thread that holds
//! the connection, against that shard's engines; every other request is
//! shipped from the frontend runtime — the other reads to the reader pool,
//! writes to the shard's thread, writes without a domain to the control
//! plane — relaying both body streams frame by frame. A point read that would
//! touch the disk is handed to the pool instead.

use crate::api::middleware::ApiError;
use crate::auth::middleware::extract_domain;
use crate::control::slots;
use crate::core::coop;
use axum::body::{Body, BodyDataStream, Bytes, HttpBody};
use axum::http::{header, request, response, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use compio::runtime::JoinError;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, Stream, StreamExt};
use std::convert::Infallible;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tower::{Service, ServiceExt};

/// Body frames buffered per direction and request.
const BODY_FRAMES: usize = 16;

type Frame = Result<Bytes, axum::Error>;

/// One request on its way to a data shard, the control plane or the reader
/// pool.
pub struct Job {
    parts: request::Parts,
    body: Option<mpsc::Receiver<Frame>>,
    reply: oneshot::Sender<(response::Parts, Payload)>,
    /// The data shard whose engines answer it on the reader pool.
    shard: usize,
    /// The request's place in its [`Lane`], free again once it is answered,
    /// or on the reader pool once the pool takes it up.
    slot: Option<OwnedSemaphorePermit>,
}

/// The way to a request loop that takes at most `capacity` requests at once,
/// running or waiting (the reader pool's: waiting only): a request beyond
/// that is answered 503 at once.
#[derive(Clone)]
pub struct Lane {
    jobs: mpsc::Sender<Job>,
    slots: Arc<Semaphore>,
}

impl Lane {
    /// A lane of `capacity` requests, at least 1, and its loop's end.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<Job>) {
        let (jobs, inbox) = mpsc::channel(capacity);
        (Self { jobs, slots: Arc::new(Semaphore::new(capacity)) }, inbox)
    }

    /// Sends `job` on, unless the lane is full or its loop has ended.
    fn try_send(&self, mut job: Job) -> Result<(), Refused> {
        let Ok(slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Err(Refused::Full);
        };
        job.slot = Some(slot);
        self.jobs.try_send(job).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Refused::Full,
            mpsc::error::TrySendError::Closed(_) => Refused::Closed,
        })
    }
}

/// Why a request loop did not take a request.
enum Refused {
    Full,
    Closed,
}

impl Refused {
    fn into_response(self) -> Response {
        match self {
            Refused::Full => overloaded(),
            Refused::Closed => bridge_unavailable(),
        }
    }
}

/// The receiving end of a request loop: a [`Lane`]'s, or the unbounded one
/// of the control plane.
pub enum Inbox {
    Lane(mpsc::Receiver<Job>),
    Control(mpsc::UnboundedReceiver<Job>),
}

impl Inbox {
    async fn recv(&mut self) -> Option<Job> {
        match self {
            Inbox::Lane(jobs) => jobs.recv().await,
            Inbox::Control(jobs) => jobs.recv().await,
        }
    }
}

impl From<mpsc::Receiver<Job>> for Inbox {
    fn from(jobs: mpsc::Receiver<Job>) -> Self {
        Inbox::Lane(jobs)
    }
}

impl From<mpsc::UnboundedReceiver<Job>> for Inbox {
    fn from(jobs: mpsc::UnboundedReceiver<Job>) -> Self {
        Inbox::Control(jobs)
    }
}

/// The answer's body on its way back. An answer that is complete when the
/// handler returns travels inside the reply, so the frontend hands hyper a
/// body of known length instead of an open stream.
enum Payload {
    Full(Bytes),
    Stream(mpsc::Receiver<Frame>),
}

impl Payload {
    fn into_body(self) -> Body {
        match self {
            Payload::Full(data) => Body::from(data),
            Payload::Stream(rx) => Body::from_stream(frames(rx)),
        }
    }
}

/// Where a request runs: on the frontend thread that holds the connection, on
/// the reader pool or on the engine thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    /// A point read — one key, document or row — or a probe: short enough that
    /// the handover to another thread would cost more than the read itself.
    ReadInline,
    /// Every other read, scans and streams included.
    Read,
    Write,
}

/// Classifies a request by method and path alone: GET and HEAD read — inline
/// for a single key, document or row and for `/health` and `/version`,
/// otherwise on the pool — as do the JSON search and the SQL route, whose
/// handler sends write statements on to the engine thread itself.
/// `auth::middleware::is_write_request` carries the same two POST exceptions;
/// a new read-only POST route belongs in both.
pub fn route_class(method: &Method, path: &str) -> RouteClass {
    let read_post = |engine: &str, action: &str| {
        path.strip_prefix("/store-api/")
            .and_then(|rest| rest.strip_prefix(engine))
            .and_then(|rest| rest.strip_suffix(action))
            .is_some_and(|domain| !domain.is_empty() && !domain.contains('/'))
    };
    if method == Method::GET || method == Method::HEAD {
        if is_point_read(path) {
            RouteClass::ReadInline
        } else {
            RouteClass::Read
        }
    } else if method == Method::POST && (read_post("json/", "/search") || read_post("rel/", "/sql")) {
        RouteClass::Read
    } else {
        RouteClass::Write
    }
}

fn is_point_read(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    let non_empty = |segment: &str| !segment.is_empty();
    match segments[..] {
        ["", "health" | "version"] => true,
        ["", "store-api", "kv", domain, "keys", key] => non_empty(domain) && non_empty(key),
        // The router takes `documents/count` for the counter, never as a key.
        ["", "store-api", "json", domain, "documents", key] => non_empty(domain) && non_empty(key) && key != "count",
        ["", "store-api", "rel", domain, "tables", table, "rows", pk] => non_empty(domain) && non_empty(table) && non_empty(pk),
        _ => false,
    }
}

/// Where [`ShardRouter`] hands a request neither the inline routers nor the
/// reader pool take.
#[derive(Clone)]
pub enum EngineDispatch {
    /// Calls the router on the caller's runtime (tests).
    Inline(Router),
    /// Ships each request to [`serve_engine`] on a data shard's thread.
    Engine(Lane),
    /// Ships each request to [`serve_engine`] on the control plane's thread,
    /// which takes every one.
    Control(mpsc::UnboundedSender<Job>),
}

/// Frontend end of the bridge, mounted as the frontend router's fallback:
/// finds the data shard of each request's domain and runs the request where
/// its [`RouteClass`] says — a point read as a plain call on the caller's
/// task against that shard's engines, handed over only if it would touch the
/// disk.
#[derive(Clone)]
pub struct ShardRouter {
    /// The writes of shard `k` go to `shards[k]`, and so does everything else
    /// without a reader pool.
    shards: Vec<EngineDispatch>,
    /// Takes the writes without a domain when set; without it shard 0 does.
    control: Option<EngineDispatch>,
    /// Takes the reads the inline routers leave or give up on when set.
    reader: Option<Lane>,
    /// Answers the point reads of shard `k` with `inline[k]` when set;
    /// without them they go with the other reads.
    inline: Option<Vec<Router>>,
}

impl ShardRouter {
    /// A router over the data shards behind `shards`, by shard index.
    pub fn new(shards: Vec<EngineDispatch>) -> Self {
        assert!(!shards.is_empty() && shards.len() <= usize::from(u16::MAX), "1 to 65535 data shards");
        Self { shards, control: None, reader: None, inline: None }
    }

    /// Ships the writes without a domain to `control`.
    pub fn with_control(self, control: EngineDispatch) -> Self {
        Self { control: Some(control), ..self }
    }

    /// Ships the reads not answered inline ([`route_class`]), and the point
    /// reads that gave up there, to [`serve_reader`] over `reader`.
    pub fn with_reader(self, reader: Lane) -> Self {
        Self { reader: Some(reader), ..self }
    }

    /// Answers point reads ([`RouteClass::ReadInline`]) of shard `k` with
    /// `routers[k]` on the calling thread; one that would touch the disk
    /// goes to the reader pool.
    pub fn with_inline(self, routers: Vec<Router>) -> Self {
        assert_eq!(routers.len(), self.shards.len(), "one inline router per data shard");
        Self { inline: Some(routers), ..self }
    }

    /// The data shard of the domain `path` names; `None` for a path without
    /// a domain.
    fn shard_of(&self, path: &str) -> Option<usize> {
        let domain = extract_domain(path).map(|(_, domain, _)| domain).or_else(|| managed_domain(path))?;
        let shards = self.shards.len() as u16;
        Some(usize::from(slots::shard_of_domain(domain, shards)))
    }
}

/// The JSON or relational domain a domain-management path names; auth
/// treats these paths as admin-only and so sees no domain in them.
fn managed_domain(path: &str) -> Option<&str> {
    let mut segments = path.strip_prefix("/store-api/")?.split('/');
    match (segments.next(), segments.next(), segments.next()) {
        (Some("json" | "rel"), Some("domains"), Some(name)) if !name.is_empty() => Some(name),
        _ => None,
    }
}

impl Service<Request<Body>> for ShardRouter {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let path = req.uri().path();
        let class = route_class(req.method(), path);
        let domain_shard = self.shard_of(path);
        // Reads without a domain see shard 0's engines.
        let shard = domain_shard.unwrap_or(0);
        if let (RouteClass::ReadInline, Some(routers)) = (class, &self.inline) {
            return read_inline(routers[shard].clone(), self.reader.clone(), shard, req).map(Ok).boxed();
        }
        if let Some(reader) = &self.reader {
            if class != RouteClass::Write {
                return ship(Target::Lane(reader.clone()), shard, req).map(Ok).boxed();
            }
        }
        let target = match (&self.control, domain_shard) {
            (Some(control), None) if class == RouteClass::Write => control,
            _ => &self.shards[shard],
        };
        dispatch(target, shard, req)
    }
}

/// Runs `req` where `target` says.
fn dispatch(target: &EngineDispatch, shard: usize, req: Request<Body>) -> BoxFuture<'static, Result<Response, Infallible>> {
    match target {
        EngineDispatch::Inline(router) => router.clone().oneshot(req).boxed(),
        EngineDispatch::Engine(lane) => ship(Target::Lane(lane.clone()), shard, req).map(Ok).boxed(),
        EngineDispatch::Control(jobs) => ship(Target::Control(jobs.clone()), shard, req).map(Ok).boxed(),
    }
}

/// Answers a point read of `shard` with `router` on the calling thread.
/// With a reader pool, a read that would wait for the disk gives up there and
/// runs again on the pool; without one, it reads on the caller.
async fn read_inline(router: Router, reader: Option<Lane>, shard: usize, req: Request<Body>) -> Response {
    let Some(reader) = reader else {
        return answer(router, req).await;
    };
    let (parts, body) = req.into_parts();
    let head = parts.clone();
    match coop::inline_read(answer(router, Request::from_parts(parts, body))).await {
        (resp, false) => {
            #[cfg(test)]
            let resp = test_hook::tag_shard(resp, shard);
            resp
        }
        // Point reads take nothing from the body.
        (_, true) => ship(Target::Lane(reader), shard, Request::from_parts(head, Body::empty())).await,
    }
}

/// Where [`ship`] sends a request.
enum Target {
    Lane(Lane),
    Control(mpsc::UnboundedSender<Job>),
}

async fn ship(target: Target, shard: usize, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    #[cfg(test)]
    let (parts, traced) = crate::core::write_trace::ship(parts);
    let (reply, reply_rx) = oneshot::channel();
    let job = Job { parts, body: relay_request_body(body), reply, shard, slot: None };
    let sent = match target {
        Target::Lane(lane) => lane.try_send(job),
        Target::Control(jobs) => jobs.send(job).map_err(|_| Refused::Closed),
    };
    // Every loop ends once its last sender is gone; the target, dropped here,
    // holds none longer than needed.
    if let Err(refused) = sent {
        return refused.into_response();
    }
    #[cfg(test)]
    let reply_rx = crate::core::write_trace::reply(traced, reply_rx);
    match reply_rx.await {
        Ok((parts, payload)) => Response::from_parts(parts, payload.into_body()),
        Err(_) => bridge_unavailable(),
    }
}

fn bridge_unavailable() -> Response {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable: the server is shutting down")
        .into_response()
}

/// A full lane: the client may try again in a second.
fn overloaded() -> Response {
    let mut resp =
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable: the server is overloaded, retry later")
            .into_response();
    resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    resp
}

/// Relays the request body from the frontend; an empty body needs neither a
/// channel nor a task.
#[allow(clippy::disallowed_methods, reason = "runs on the frontend runtime")]
fn relay_request_body(body: Body) -> Option<mpsc::Receiver<Frame>> {
    if body.is_end_stream() {
        return None;
    }
    let (tx, rx) = mpsc::channel(BODY_FRAMES);
    tokio::spawn(relay(body.into_data_stream(), tx));
    Some(rx)
}

/// Engine end of the bridge: runs every shipped request on the calling
/// (data shard or control plane) thread's compio runtime, each in its own
/// task so long handlers interleave. Returns once the last sender is gone,
/// after dropping the requests still in flight, so none of them runs into the
/// engine shutdown. A [`Lane`] keeps the requests in flight to its capacity.
///
/// The loop itself is a runtime task: woken from a frontend thread, it runs
/// in the runtime's next scheduling round, even while other handlers keep
/// yielding. Dropping `serve_engine` early cancels the loop.
pub async fn serve_engine(jobs: impl Into<Inbox>, router: Router) {
    if let Err(JoinError::Panicked(payload)) = compio::runtime::spawn(engine_loop(jobs.into(), router)).await {
        std::panic::resume_unwind(payload);
    }
}

async fn engine_loop(mut jobs: Inbox, router: Router) {
    let mut in_flight = FuturesUnordered::new();
    // One clone per request task, held by its future.
    let live = Rc::new(());
    loop {
        tokio::select! {
            job = jobs.recv() => match job {
                Some(job) => {
                    let (live, router) = (Rc::clone(&live), router.clone());
                    in_flight.push(compio::runtime::spawn(async move {
                        let _live = live;
                        handle(job, router).await
                    }));
                }
                None => break,
            },
            // Reap finished tasks so the set does not grow with request count.
            Some(_) = in_flight.next() => {}
        }
    }
    // Dropping a handle cancels its task; the runtime drops a cancelled
    // task's future on its next round.
    drop(in_flight);
    while Rc::strong_count(&live) > 1 {
        tokio::task::yield_now().await;
    }
}

/// Reader end of the bridge: runs every shipped read request in its own task
/// on the calling multi-threaded runtime, with the router of the data shard
/// it names, against the same shared engines as the shard's thread. A
/// request leaves its [`Lane`] once taken up here, so the lane bounds only
/// the requests waiting. Returns once the last sender is gone; the requests
/// still in flight end with the runtime. POST requests carry an
/// [`EngineForward`] to their shard's dispatch: the SQL route, the only read
/// that forwards, is a POST.
#[allow(clippy::disallowed_methods, reason = "runs on the reader pool")]
pub async fn serve_reader(mut jobs: mpsc::Receiver<Job>, shards: Vec<(Router, EngineDispatch)>) {
    while let Some(mut job) = jobs.recv().await {
        drop(job.slot.take());
        let (router, engine) = &shards[job.shard];
        if job.parts.method == Method::POST {
            let forward = EngineForward { engine: engine.clone(), shard: job.shard, head: job.parts.clone() };
            job.parts.extensions.insert(forward);
        }
        tokio::spawn(handle(job, router.clone()));
    }
}

/// A read request's way on to its data shard's thread, as an extension of
/// POST requests on the reader pool only. It keeps the request head as the
/// pool received it: routing strips the URI prefix and adds extensions of its
/// own, which a second routing pass would misread.
#[derive(Clone)]
pub struct EngineForward {
    engine: EngineDispatch,
    shard: usize,
    head: request::Parts,
}

impl EngineForward {
    /// Sends the request on to the data shard's thread with `body` as its
    /// body and returns the shard's answer unchanged.
    pub async fn send(self, body: Bytes) -> Response {
        let req = Request::from_parts(self.head, Body::from(body));
        let Ok(resp) = dispatch(&self.engine, self.shard, req).await;
        resp
    }
}

/// Runs `req` through `router` on the calling thread.
async fn answer(router: Router, req: Request<Body>) -> Response {
    #[cfg(test)]
    let hold = test_hook::hold(&req);
    #[cfg(test)]
    let trace = crate::core::write_trace::of(req.extensions());
    let routed = router.oneshot(req);
    #[cfg(test)]
    let routed = crate::core::write_trace::within(trace, routed);
    let Ok(resp) = routed.await;
    #[cfg(test)]
    hold.await;
    #[cfg(test)]
    let resp = test_hook::tag_thread(resp);
    resp
}

/// Answers `job` with `router` and relays the answer; its lane slot is free
/// again once the answer is complete, before it goes back, or, streamed, once
/// the body has left.
async fn handle(job: Job, router: Router) {
    #[cfg(test)]
    let shard = job.shard;
    let Job { parts, body, reply, slot, .. } = job;
    let body = body.map_or_else(Body::empty, |rx| Body::from_stream(frames(rx)));
    let resp = answer(router, Request::from_parts(parts, body)).await;
    #[cfg(test)]
    let resp = test_hook::tag_shard(resp, shard);
    let (parts, mut body) = resp.into_parts();

    // A body that is already complete rides along in the reply. Bodies without
    // an exact length (SSE, backup download, bulk export) take the stream path,
    // as does one that is not ready in a single poll.
    let mut first = None;
    if body.is_end_stream() {
        drop(slot);
        let _ = reply.send((parts, Payload::Full(Bytes::new())));
        return;
    }
    if body.size_hint().exact().is_some() {
        match futures::poll!(std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx))) {
            Poll::Ready(None) => {
                drop(slot);
                let _ = reply.send((parts, Payload::Full(Bytes::new())));
                return;
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) if body.is_end_stream() => {
                    drop(slot);
                    let _ = reply.send((parts, Payload::Full(data)));
                    return;
                }
                Ok(data) => first = Some(Ok(data)),
                // Trailers are not relayed; the rest still is.
                Err(_) => {}
            },
            Poll::Ready(Some(Err(e))) => first = Some(Err(e)),
            Poll::Pending => {}
        }
    }

    let _slot = slot;
    let (tx, rx) = mpsc::channel(BODY_FRAMES);
    if reply.send((parts, Payload::Stream(rx))).is_err() {
        return;
    }
    if let Some(frame) = first {
        let failed = frame.is_err();
        // Same rule as in `relay`: a failed frame is the last one.
        if tx.send(frame).await.is_err() || failed {
            return;
        }
    }
    // Polled here, never on a frontend thread: body streams may read the engines.
    relay(body.into_data_stream(), tx).await;
}

/// Forwards frames until the stream ends or fails, or the receiver is gone.
async fn relay(mut stream: BodyDataStream, tx: mpsc::Sender<Frame>) {
    while let Some(frame) = stream.next().await {
        let failed = frame.is_err();
        if tx.send(frame).await.is_err() || failed {
            break;
        }
    }
}

fn frames(mut rx: mpsc::Receiver<Frame>) -> impl Stream<Item = Frame> {
    futures::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

/// Test hooks inside [`answer`], on whichever thread runs the request; the
/// in-process server tests reach them through headers.
#[cfg(test)]
pub(crate) mod test_hook {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    /// Response header naming the thread that ran the request. Set only where
    /// it is still missing, so an answer forwarded from a shard's thread
    /// keeps the shard's name.
    pub(crate) const THREAD: &str = "x-luradb-thread";
    /// Response header naming the data shard a shipped request or a point
    /// read was routed to; set like [`THREAD`].
    pub(crate) const SHARD: &str = "x-luradb-shard";
    /// Request header naming a hold from [`register_hold`]; the request waits
    /// in it once the router has answered it, before the answer goes back.
    pub(crate) const HOLD: &str = "x-luradb-hold";

    /// Gets a weak sender to the shard's thread when the request carries an
    /// [`EngineForward`]; it does not keep the shard's loop running.
    type Hold = Arc<dyn Fn(Option<mpsc::WeakSender<Job>>) -> BoxFuture<'static, ()> + Send + Sync>;

    fn holds() -> &'static Mutex<HashMap<String, Hold>> {
        static HOLDS: OnceLock<Mutex<HashMap<String, Hold>>> = OnceLock::new();
        HOLDS.get_or_init(Default::default)
    }

    /// Registers `hold` under `name`, unique per test: tests share the process.
    pub(crate) fn register_hold(
        name: &str,
        hold: impl Fn(Option<mpsc::WeakSender<Job>>) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) {
        holds().lock().unwrap().insert(name.to_string(), Arc::new(hold));
    }

    /// The hold `req` names, taken before routing consumes the request.
    pub(super) fn hold(req: &Request<Body>) -> BoxFuture<'static, ()> {
        let hold = req.headers().get(HOLD).and_then(|name| holds().lock().unwrap().get(name.to_str().unwrap()).cloned());
        let engine = req.extensions().get::<EngineForward>().and_then(|forward| match &forward.engine {
            EngineDispatch::Engine(lane) => Some(lane.jobs.downgrade()),
            EngineDispatch::Inline(_) | EngineDispatch::Control(_) => None,
        });
        hold.map_or_else(|| async {}.boxed(), |hold| hold(engine))
    }

    pub(super) fn tag_thread(mut resp: Response) -> Response {
        if !resp.headers().contains_key(THREAD) {
            let name = std::thread::current().name().unwrap_or("unnamed").to_string();
            resp.headers_mut().insert(THREAD, name.parse().unwrap());
        }
        resp
    }

    pub(super) fn tag_shard(mut resp: Response, shard: usize) -> Response {
        if !resp.headers().contains_key(SHARD) {
            resp.headers_mut().insert(SHARD, shard.into());
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::engine_runtime;
    use axum::http::header;
    use axum::routing::{get, post};
    use futures::stream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// `serve_engine` on its own engine runtime thread, like the engine
    /// thread in production.
    fn engine_thread(router: Router) -> (Lane, std::thread::JoinHandle<()>) {
        let (tx, rx) = Lane::new(8);
        let thread = std::thread::spawn(move || engine_runtime::block_on(serve_engine(rx, router)));
        (tx, thread)
    }

    /// `serve_reader` on its own multi-threaded runtime (workers named
    /// `test-reader`), like the reader pool in production.
    fn reader_pool(router: Router, engine: EngineDispatch) -> (Lane, std::thread::JoinHandle<()>) {
        let (tx, rx) = Lane::new(8);
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("test-reader")
                .enable_all()
                .build()
                .unwrap()
                .block_on(serve_reader(rx, vec![(router, engine)]));
        });
        (tx, thread)
    }

    fn get_req(path: &str) -> Request<Body> {
        Request::get(path).body(Body::empty()).unwrap()
    }

    fn three_frames(parts: [&'static str; 3]) -> Body {
        Body::from_stream(stream::iter(parts.map(|p| Ok::<_, Infallible>(Bytes::from_static(p.as_bytes())))))
    }

    async fn frames_of(body: Body) -> Vec<Bytes> {
        body.into_data_stream().map(|frame| frame.unwrap()).collect().await
    }

    // Test 1: handlers run on the engine thread, not the caller's; request and
    // response bodies cross the bridge frame by frame, complete and in order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requests_run_on_the_engine_thread_and_bodies_cross_frame_by_frame() {
        let router = Router::new()
            .route("/thread", get(|| async { format!("{:?}", std::thread::current().id()) }))
            .route(
                "/echo",
                post(|body: Body| async move {
                    let frames = frames_of(body).await;
                    frames.iter().map(|f| String::from_utf8_lossy(f).into_owned()).collect::<Vec<_>>().join("|")
                }),
            )
            .route("/stream", get(|| async { three_frames(["x", "y", "z"]) }));
        let (tx, engine) = engine_thread(router);
        let engine_id = format!("{:?}", engine.thread().id());
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);

        let resp = ship.clone().oneshot(get_req("/thread")).await.unwrap();
        let handler_thread = String::from_utf8(frames_of(resp.into_body()).await.concat()).unwrap();
        assert_eq!(handler_thread, engine_id);
        assert_ne!(handler_thread, format!("{:?}", std::thread::current().id()));

        let req = Request::post("/echo").body(three_frames(["a", "b", "c"])).unwrap();
        let resp = ship.clone().oneshot(req).await.unwrap();
        assert_eq!(frames_of(resp.into_body()).await.concat(), b"a|b|c");

        let resp = ship.clone().oneshot(get_req("/stream")).await.unwrap();
        assert_eq!(frames_of(resp.into_body()).await, ["x", "y", "z"].map(|s| Bytes::from_static(s.as_bytes())));

        drop(ship);
        engine.join().unwrap();
    }

    /// Ships one more job from outside any runtime, the way a frontend thread
    /// does, and returns once it sits in the channel.
    fn send_from_another_thread(tx: Lane, path: &'static str) {
        let (queued, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (parts, _) = Request::get(path).body(Body::empty()).unwrap().into_parts();
            let (reply, reply_rx) = oneshot::channel();
            tx.jobs.blocking_send(Job { parts, body: relay_request_body(Body::empty()), reply, shard: 0, slot: None }).unwrap();
            // The answer is unused; the receiver only has to outlive the send.
            queued.send(reply_rx).unwrap();
        });
        wait.recv().unwrap();
    }

    // The engine loop is a runtime task, so a request that arrives while other
    // handlers keep yielding starts in the runtime's next scheduling round,
    // long before they are done. compio queues it behind the tasks that are
    // ready by then (at most 61 per round), unlike tokio, whose deferred
    // yields let it run before their next slice.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::disallowed_methods, reason = "the callers play the frontend runtime")]
    async fn a_request_arriving_mid_round_starts_while_yielding_handlers_run() {
        const ROUNDS: usize = 200;
        let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        // A sender inside the router would hold the bridge channel open for
        // good; the first handler takes it out and hands it to the thread.
        let late = Arc::new(std::sync::Mutex::new(None::<Lane>));
        let (handler_log, handler_late) = (Arc::clone(&log), Arc::clone(&late));
        let router = Router::new().route(
            "/step/{name}",
            get(move |axum::extract::Path(name): axum::extract::Path<String>| {
                let (log, late) = (Arc::clone(&handler_log), Arc::clone(&handler_late));
                async move {
                    for round in 0..ROUNDS {
                        log.lock().unwrap().push(format!("{name}{round}"));
                        if round == 0 {
                            if let Some(tx) = late.lock().unwrap().take() {
                                send_from_another_thread(tx, "/step/c");
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                }
            }),
        );
        let (tx, engine) = engine_thread(router);
        *late.lock().unwrap() = Some(tx.clone());
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);
        let a = tokio::spawn(ship.clone().oneshot(get_req("/step/a")));
        let b = tokio::spawn(ship.clone().oneshot(get_req("/step/b")));
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        drop(ship);
        engine.join().unwrap();

        let log = log.lock().unwrap();
        let at = |step: &str| log.iter().position(|e| e == step).expect(step);
        let last = ROUNDS - 1;
        assert!(at("c0") < at(&format!("a{last}")) && at("c0") < at(&format!("b{last}")), "{log:?}");
    }

    // A request without a body reaches the engine as an empty body, not as a
    // stream that will only ever end. The handler answers with the shape it
    // sees: an assertion inside it would only show up as a 503.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_empty_request_body_crosses_the_bridge_without_a_channel() {
        let router = Router::new().route(
            "/shape",
            get(|body: Body| async move { format!("{} {:?}", body.is_end_stream(), body.size_hint().exact()) }),
        );
        let (tx, engine) = engine_thread(router);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);

        let body = ship.clone().oneshot(get_req("/shape")).await.unwrap().into_body();
        assert_eq!(frames_of(body).await.concat(), b"true Some(0)");

        drop(ship);
        engine.join().unwrap();
    }

    /// An engine body that announces an exact length but hands out its frames
    /// one poll at a time, following a script. `None` in the script is a
    /// `Pending` poll; running out of script ends the body.
    struct ScriptedBody {
        script: std::collections::VecDeque<Option<Frame>>,
        polls: Arc<AtomicUsize>,
    }

    impl ScriptedBody {
        fn new(script: impl IntoIterator<Item = Option<Frame>>, polls: &Arc<AtomicUsize>) -> Self {
            Self { script: script.into_iter().collect(), polls: Arc::clone(polls) }
        }
    }

    impl HttpBody for ScriptedBody {
        type Data = Bytes;
        type Error = axum::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, axum::Error>>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            match self.script.pop_front() {
                None => Poll::Ready(None),
                Some(None) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(Some(Ok(data))) => Poll::Ready(Some(Ok(hyper::body::Frame::data(data)))),
                Some(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            }
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            hyper::body::SizeHint::with_exact(6)
        }
    }

    /// A router whose only route answers with `body`, built fresh per call.
    fn body_route(path: &str, body: impl Fn() -> Body + Clone + Send + Sync + 'static) -> Router {
        Router::new().route(path, get(move || { let body = body(); async move { body } }))
    }

    // A complete answer crosses the bridge inside the reply: the frontend hands
    // hyper a body of known length, and an empty one where the status forbids a
    // body at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn complete_answers_cross_the_bridge_in_one_message() {
        let router = Router::new()
            .route("/hello", get(|| async { "hello" }))
            .route("/nothing", get(|| async { StatusCode::NO_CONTENT }));
        let (tx, engine) = engine_thread(router);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);

        let body = ship.clone().oneshot(get_req("/hello")).await.unwrap().into_body();
        assert_eq!(body.size_hint().exact(), Some(5));
        assert_eq!(frames_of(body).await.concat(), b"hello");

        let resp = ship.clone().oneshot(get_req("/nothing")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp.into_body().is_end_stream());

        drop(ship);
        engine.join().unwrap();
    }

    // A body of known length that is not ready in one poll keeps the stream
    // path: every frame arrives in order and the frontend body has no length.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sized_body_that_needs_more_polls_still_streams() {
        let polls = Arc::new(AtomicUsize::new(0));
        let script = polls.clone();
        let router = body_route("/late", move || {
            Body::new(ScriptedBody::new(
                [None, Some(Ok(Bytes::from_static(b"one"))), Some(Ok(Bytes::from_static(b"two")))],
                &script,
            ))
        });
        let (tx, engine) = engine_thread(router);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);

        let body = ship.clone().oneshot(get_req("/late")).await.unwrap().into_body();
        assert_eq!(body.size_hint().exact(), None);
        assert_eq!(frames_of(body).await, [Bytes::from_static(b"one"), Bytes::from_static(b"two")]);

        drop(ship);
        engine.join().unwrap();
    }

    // A failing first frame of a sized body reaches the frontend and ends the
    // answer there, without another poll — the relay stops at the first error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_first_frame_ends_the_body_without_another_poll() {
        let polls = Arc::new(AtomicUsize::new(0));
        let script = polls.clone();
        let router = body_route("/broken", move || {
            let failed = Err(axum::Error::new(std::io::Error::other("engine body failed")));
            Body::new(ScriptedBody::new([Some(failed)], &script))
        });
        let (tx, engine) = engine_thread(router);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);

        let mut body = ship.clone().oneshot(get_req("/broken")).await.unwrap().into_body().into_data_stream();
        let failed = body.next().await.unwrap().unwrap_err();
        assert!(failed.to_string().contains("engine body failed"), "{failed}");
        assert!(body.next().await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 1);

        drop(ship);
        engine.join().unwrap();
    }

    // GET and HEAD are reads everywhere, and so are the two POSTs that only
    // read; everything else is a write. Of the reads, one key, document or row
    // and the two probes run inline, their path neighbours on the pool.
    #[test]
    fn route_class_keeps_point_reads_inline_and_sends_other_reads_to_the_pool() {
        use RouteClass::{Read, ReadInline, Write};
        let cases = [
            (Method::GET, "/store-api/kv/x/keys/k", ReadInline),
            (Method::HEAD, "/store-api/kv/x/keys/k", ReadInline),
            (Method::GET, "/store-api/json/x/documents/d", ReadInline),
            (Method::HEAD, "/store-api/json/x/documents/d", ReadInline),
            (Method::GET, "/store-api/rel/x/tables/t/rows/1", ReadInline),
            (Method::GET, "/health", ReadInline),
            (Method::HEAD, "/version", ReadInline),
            (Method::GET, "/store-api/kv/x/keys", Read),
            (Method::GET, "/store-api/kv/x/keys/", Read),
            (Method::GET, "/store-api/kv/x/keys/k/meta", Read),
            (Method::HEAD, "/store-api/kv/x/keys/k/meta", Read),
            (Method::GET, "/store-api/json/x/documents", Read),
            (Method::GET, "/store-api/json/x/documents/count", Read),
            (Method::GET, "/store-api/rel/x/tables/t/rows", Read),
            (Method::GET, "/store-api/rel/x/tables/t/count", Read),
            (Method::GET, "/store-api/kv/x/watch", Read),
            (Method::POST, "/store-api/json/x/search", Read),
            (Method::POST, "/store-api/rel/x/sql", Read),
            (Method::POST, "/store-api/domains", Write),
            (Method::PUT, "/store-api/kv/x/keys/k", Write),
            (Method::DELETE, "/store-api/json/x/documents/d", Write),
            (Method::PUT, "/store-api/rel/x/tables/t/rows/1", Write),
            (Method::POST, "/store-api/json/x/documents", Write),
            (Method::POST, "/store-api/rel/x/tables/from-file", Write),
            (Method::POST, "/store-api/json/x/y/search", Write),
            (Method::OPTIONS, "/store-api/domains", Write),
        ];
        for (method, path, class) in cases {
            assert_eq!(route_class(&method, path), class, "{method} {path}");
        }
    }

    async fn text_of(resp: Response) -> String {
        String::from_utf8(frames_of(resp.into_body()).await.concat()).unwrap()
    }

    // With a reader pool, reads run on its workers and
    // writes still on the engine thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reads_run_on_the_reader_pool_and_writes_on_the_engine_thread() {
        let thread = || async {
            let current = std::thread::current();
            format!("{} {:?}", current.name().unwrap_or_default(), current.id())
        };
        let router = Router::new().route("/where", get(thread).post(thread));
        let (engine_tx, engine) = engine_thread(router.clone());
        let engine_id = format!("{:?}", engine.thread().id());
        let (reader_tx, reader) = reader_pool(router, EngineDispatch::Engine(engine_tx.clone()));
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_reader(reader_tx);

        let read = text_of(ship.clone().oneshot(get_req("/where")).await.unwrap()).await;
        assert!(read.starts_with("test-reader "), "{read}");
        let write = text_of(ship.clone().oneshot(Request::post("/where").body(Body::empty()).unwrap()).await.unwrap()).await;
        assert!(write.ends_with(&format!(" {engine_id}")), "{write}");

        drop(ship);
        reader.join().unwrap();
        engine.join().unwrap();
    }

    /// A router that answers every route with `shard` and the thread it ran on.
    fn shard_router(shard: &'static str) -> Router {
        let answer = move || async move { format!("{shard} {}", std::thread::current().name().unwrap_or_default()) };
        Router::new()
            .route("/store-api/kv/{domain}/keys/{key}", get(answer).put(answer))
            .route("/store-api/kv/{domain}/keys", get(answer))
            .route("/store-api/domains", get(answer).post(answer))
            .route("/store-api/json/domains/{name}", get(answer).delete(answer))
    }

    /// `serve_engine` with `router` on a thread named `name`.
    fn named_engine_thread(name: &str, router: Router) -> (Lane, std::thread::JoinHandle<()>) {
        let (tx, rx) = Lane::new(8);
        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || engine_runtime::block_on(serve_engine(rx, router)))
            .unwrap();
        (tx, thread)
    }

    // Two data shards: a write runs on the thread of its domain's shard, a
    // read on the pool and a point read on the caller, both against that
    // shard's router; a write without a domain goes to the control plane,
    // a read without one to shard 0's router on the pool. Domains are
    // placed on their shard by name.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn requests_go_to_the_shard_of_their_domain() {
        use crate::control::slots::domain_name_for_shard;
        let (a, b) = (domain_name_for_shard(0, 2, 23), domain_name_for_shard(1, 2, 23));
        let (shard0, thread0) = named_engine_thread("test-shard-0", shard_router("s0"));
        let (shard1, thread1) = named_engine_thread("test-shard-1", shard_router("s1"));
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let control = std::thread::Builder::new()
            .name("test-control".to_string())
            .spawn(move || engine_runtime::block_on(serve_engine(control_rx, shard_router("s0"))))
            .unwrap();
        let shards = vec![EngineDispatch::Engine(shard0.clone()), EngineDispatch::Engine(shard1.clone())];
        let (reader_tx, reader) = {
            let (tx, rx) = Lane::new(8);
            let pool = vec![(shard_router("s0"), shards[0].clone()), (shard_router("s1"), shards[1].clone())];
            let thread = std::thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("test-reader")
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(serve_reader(rx, pool));
            });
            (tx, thread)
        };
        let ship = ShardRouter::new(shards)
            .with_control(EngineDispatch::Control(control_tx))
            .with_reader(reader_tx)
            .with_inline(vec![shard_router("s0"), shard_router("s1")]);
        let call = |method: Method, path: String| {
            let req = Request::builder().method(method).uri(path).body(Body::empty()).unwrap();
            let ship = ship.clone();
            async move { text_of(ship.oneshot(req).await.unwrap()).await }
        };
        let caller = std::thread::current().name().unwrap().to_string();

        assert_eq!(call(Method::PUT, format!("/store-api/kv/{a}/keys/k")).await, "s0 test-shard-0");
        assert_eq!(call(Method::PUT, format!("/store-api/kv/{b}/keys/k")).await, "s1 test-shard-1");
        assert_eq!(call(Method::GET, format!("/store-api/kv/{a}/keys")).await, "s0 test-reader");
        assert_eq!(call(Method::GET, format!("/store-api/kv/{b}/keys")).await, "s1 test-reader");
        assert_eq!(call(Method::GET, format!("/store-api/kv/{b}/keys/k")).await, format!("s1 {caller}"));
        assert_eq!(call(Method::POST, "/store-api/domains".to_string()).await, "s0 test-control");
        assert_eq!(call(Method::GET, "/store-api/domains".to_string()).await, "s0 test-reader");
        // Auth sees no domain in a JSON or relational domain's management path; routing does.
        assert_eq!(call(Method::GET, format!("/store-api/json/domains/{b}")).await, "s1 test-reader");
        assert_eq!(call(Method::DELETE, format!("/store-api/json/domains/{b}")).await, "s1 test-shard-1");

        drop((ship, shard0, shard1));
        reader.join().unwrap();
        for thread in [thread0, thread1, control] {
            thread.join().unwrap();
        }
    }

    // With an inline router, a point read runs on the caller's thread without
    // a handover, the other reads still on the pool and writes on the engine
    // thread; without one, point reads stay on the pool.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn point_reads_run_on_the_caller_with_an_inline_router() {
        let thread = || async {
            let current = std::thread::current();
            format!("{} {:?}", current.name().unwrap_or_default(), current.id())
        };
        let router = Router::new()
            .route("/store-api/kv/{domain}/keys/{key}", get(thread).put(thread))
            .route("/store-api/kv/{domain}/keys/{key}/meta", get(thread));
        let (engine_tx, engine) = engine_thread(router.clone());
        let engine_id = format!("{:?}", engine.thread().id());
        let (reader_tx, reader) = reader_pool(router.clone(), EngineDispatch::Engine(engine_tx.clone()));
        let pooled = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_reader(reader_tx);
        let ship = pooled.clone().with_inline(vec![router]);
        let caller = std::thread::current();

        let point = ship.clone().oneshot(get_req("/store-api/kv/x/keys/k")).await.unwrap();
        assert_eq!(point.headers()[test_hook::THREAD], caller.name().unwrap());
        assert_eq!(text_of(point).await, format!("{} {:?}", caller.name().unwrap(), caller.id()));
        let meta = text_of(ship.clone().oneshot(get_req("/store-api/kv/x/keys/k/meta")).await.unwrap()).await;
        assert!(meta.starts_with("test-reader "), "{meta}");
        let put = Request::put("/store-api/kv/x/keys/k").body(Body::empty()).unwrap();
        let write = text_of(ship.clone().oneshot(put).await.unwrap()).await;
        assert!(write.ends_with(&format!(" {engine_id}")), "{write}");

        let point = text_of(pooled.clone().oneshot(get_req("/store-api/kv/x/keys/k")).await.unwrap()).await;
        assert!(point.starts_with("test-reader "), "{point}");

        drop((ship, pooled));
        reader.join().unwrap();
        engine.join().unwrap();
    }

    // A point read that would wait for the disk gives up on the caller and
    // runs again on the pool with the same headers and extensions, and the
    // pool's answer is the only one the client gets. Without a pool there is
    // nowhere to hand it, so it reads on the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_point_read_that_would_block_runs_again_on_the_pool() {
        use axum::extract::Extension;
        use axum::http::HeaderMap;

        #[derive(Clone)]
        struct Caller(&'static str);

        let gave_up = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&gave_up);
        let router = Router::new().route(
            "/store-api/kv/{domain}/keys/{key}",
            get(move |Extension(caller): Extension<Caller>, headers: HeaderMap| {
                let counter = Arc::clone(&counter);
                async move {
                    if coop::would_block() {
                        counter.fetch_add(1, Ordering::SeqCst);
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    let thread = std::thread::current().name().unwrap_or_default().to_string();
                    format!("{thread} {} {}", caller.0, headers["x-probe"].to_str().unwrap()).into_response()
                }
            }),
        );
        let probe = || {
            let mut req = Request::get("/store-api/kv/x/keys/k").header("x-probe", "1").body(Body::empty()).unwrap();
            req.extensions_mut().insert(Caller("alice"));
            req
        };
        let (engine_tx, engine) = engine_thread(router.clone());
        let (reader_tx, reader) = reader_pool(router.clone(), EngineDispatch::Engine(engine_tx.clone()));
        let without_pool = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_inline(vec![router]);
        let pooled = without_pool.clone().with_reader(reader_tx);

        let resp = pooled.clone().oneshot(probe()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[test_hook::THREAD], "test-reader");
        assert_eq!(text_of(resp).await, "test-reader alice 1");
        assert_eq!(gave_up.load(Ordering::SeqCst), 1);

        let resp = without_pool.clone().oneshot(probe()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(text_of(resp).await, format!("{} alice 1", std::thread::current().name().unwrap()));
        assert_eq!(gave_up.load(Ordering::SeqCst), 1);

        drop((pooled, without_pool));
        reader.join().unwrap();
        engine.join().unwrap();
    }

    // A pool handler sends its request on to the engine
    // thread as the pool received it — URI, path parameters, extensions and
    // body — and relays the answer unchanged; the engine side gets no way
    // to forward again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pool_handler_forwards_its_request_to_the_engine_thread_unchanged() {
        use axum::extract::{Extension, OriginalUri, Path};

        #[derive(Clone)]
        struct Caller(&'static str);

        let engine_router = Router::new().nest(
            "/store-api",
            Router::new().route(
                "/rel/{domain}/sql",
                post(
                    |Path(domain): Path<String>,
                     OriginalUri(uri): OriginalUri,
                     Extension(caller): Extension<Caller>,
                     forward: Option<Extension<EngineForward>>,
                     body: Bytes| async move {
                        let body = String::from_utf8_lossy(&body).into_owned();
                        let text = format!("{domain} {uri} {} {} {body}", caller.0, forward.is_some());
                        (StatusCode::CREATED, [("x-engine", "yes")], text)
                    },
                ),
            ),
        );
        let reader_router = Router::new().nest(
            "/store-api",
            Router::new().route(
                "/rel/{domain}/sql",
                post(|Extension(forward): Extension<EngineForward>, body: Bytes| forward.send(body)),
            ),
        );
        let (engine_tx, engine) = engine_thread(engine_router);
        let (reader_tx, reader) = reader_pool(reader_router, EngineDispatch::Engine(engine_tx.clone()));
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_reader(reader_tx);

        let mut req = Request::post("/store-api/rel/x/sql").body(Body::from("clé ✓")).unwrap();
        req.extensions_mut().insert(Caller("alice"));
        let resp = ship.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers()["x-engine"], "yes");
        assert_eq!(text_of(resp).await, "x /store-api/rel/x/sql alice false clé ✓");

        drop(ship);
        reader.join().unwrap();
        engine.join().unwrap();
    }

    // Of the reads, only POSTs carry the way on to the
    // engine thread — the SQL route, the only one that forwards, is a POST.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_post_reads_carry_an_engine_forward() {
        let has_forward = |forward: Option<axum::extract::Extension<EngineForward>>| async move {
            forward.is_some().to_string()
        };
        let router = Router::new().route("/store-api/rel/x/sql", get(has_forward).post(has_forward));
        let (engine_tx, _engine_rx) = Lane::new(1);
        let (reader_tx, reader) = reader_pool(router, EngineDispatch::Engine(engine_tx.clone()));
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_reader(reader_tx);

        let read = |method: Method| {
            let req = Request::builder().method(method).uri("/store-api/rel/x/sql").body(Body::empty()).unwrap();
            ship.clone().oneshot(req)
        };
        assert_eq!(text_of(read(Method::GET).await.unwrap()).await, "false");
        assert_eq!(text_of(read(Method::POST).await.unwrap()).await, "true");

        drop(ship);
        reader.join().unwrap();
    }

    // A closed reader channel answers 503 like the
    // engine channel does.
    #[tokio::test]
    async fn closed_reader_channel_answers_503_text_plain() {
        let (engine_tx, _engine_rx) = Lane::new(1);
        let (reader_tx, reader_rx) = Lane::new(1);
        drop(reader_rx);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_reader(reader_tx);
        let resp = ship.oneshot(get_req("/any")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let content_type = resp.headers()[header::CONTENT_TYPE].to_str().unwrap().to_string();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        assert!(text_of(resp).await.starts_with("503 Service Unavailable"));
    }

    /// Asserts the answer of a full lane: 503 in the plaintext `ApiError`
    /// format, with `Retry-After: 1`.
    async fn assert_overloaded(resp: Response) {
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "1");
        let content_type = resp.headers()[header::CONTENT_TYPE].to_str().unwrap().to_string();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        assert!(text_of(resp).await.starts_with("503 Service Unavailable"));
    }

    // A reader lane of one with a read waiting in it turns the next one away
    // with 503 and Retry-After; once the pool takes reads up, they go through.
    #[tokio::test]
    #[allow(clippy::disallowed_methods, reason = "the reader end runs on a tokio runtime, like the reader pool")]
    async fn a_full_reader_lane_answers_503_with_retry_after() {
        let (engine_tx, _engine_rx) = Lane::new(1);
        let (reader_tx, reader_rx) = Lane::new(1);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx.clone())]).with_reader(reader_tx);
        let mut first = std::pin::pin!(ship.clone().oneshot(get_req("/a")));
        assert!(futures::poll!(first.as_mut()).is_pending());
        assert_overloaded(ship.clone().oneshot(get_req("/b")).await.unwrap()).await;

        let router = Router::new().route("/a", get(|| async { "a" })).route("/b", get(|| async { "b" }));
        tokio::spawn(serve_reader(reader_rx, vec![(router, EngineDispatch::Engine(engine_tx))]));
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        assert_eq!(ship.oneshot(get_req("/b")).await.unwrap().status(), StatusCode::OK);
    }

    // Streams the pool is still sending do not count against its lane: with
    // more of them open than the lane holds, a read still goes through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::disallowed_methods, reason = "the reader end runs on a tokio runtime, like the reader pool")]
    async fn open_streams_beyond_the_reader_lane_do_not_hold_up_a_read() {
        let router = Router::new()
            .route("/stream", get(|| async { Body::from_stream(stream::pending::<Result<Bytes, Infallible>>()) }))
            .route("/a", get(|| async { "a" }));
        let (engine_tx, _engine_rx) = Lane::new(1);
        let (reader_tx, reader_rx) = Lane::new(2);
        tokio::spawn(serve_reader(reader_rx, vec![(router, EngineDispatch::Engine(engine_tx.clone()))]));
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(engine_tx)]).with_reader(reader_tx);

        let mut streams = Vec::new();
        for _ in 0..3 {
            let resp = ship.clone().oneshot(get_req("/stream")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            streams.push(resp);
        }
        let read = ship.oneshot(get_req("/a")).await.unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(text_of(read).await, "a");
    }

    // Test 2: a closed bridge channel (engine shutting down) answers 503 in
    // the plaintext `ApiError` format.
    #[tokio::test]
    async fn closed_engine_channel_answers_503_text_plain() {
        let (tx, rx) = Lane::new(1);
        drop(rx);
        let resp = ShardRouter::new(vec![EngineDispatch::Engine(tx)]).oneshot(get_req("/any")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let content_type = resp.headers()[header::CONTENT_TYPE].to_str().unwrap().to_string();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        let body = String::from_utf8(frames_of(resp.into_body()).await.concat()).unwrap();
        assert!(body.starts_with("503 Service Unavailable"), "{body}");
    }

    // Test 3: once the frontend drops a response (client gone), the engine
    // side stops polling that body at its next send attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_response_stops_the_engine_side_body() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&polls);
        let router = Router::new()
            .route(
                "/endless",
                get(move || {
                    let counter = Arc::clone(&counter);
                    async move {
                        Body::from_stream(stream::poll_fn(move |_| {
                            counter.fetch_add(1, Ordering::SeqCst);
                            Poll::Ready(Some(Ok::<_, Infallible>(Bytes::from_static(b"x"))))
                        }))
                    }
                }),
            )
            .route(
                "/yield",
                get(|| async {
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                }),
            );
        let (tx, engine) = engine_thread(router);
        let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);

        let resp = ship.clone().oneshot(get_req("/endless")).await.unwrap();
        let mut body = resp.into_body().into_data_stream();
        assert_eq!(body.next().await.unwrap().unwrap(), "x");
        drop(body);

        // Each round trip runs the engine loop and yields there several times.
        ship.clone().oneshot(get_req("/yield")).await.unwrap();
        let settled = polls.load(Ordering::SeqCst);
        for _ in 0..3 {
            ship.clone().oneshot(get_req("/yield")).await.unwrap();
        }
        assert_eq!(polls.load(Ordering::SeqCst), settled);

        drop(ship);
        engine.join().unwrap();
    }

    // A shard lane of one holding a request turns the next one away with 503
    // and Retry-After; once the shard has answered, a request goes through
    // again.
    #[test]
    fn a_full_shard_lane_answers_503_with_retry_after() {
        engine_runtime::block_on(async {
            let (tx, rx) = Lane::new(1);
            let ship = ShardRouter::new(vec![EngineDispatch::Engine(tx)]);
            let put = |path| Request::put(path).body(Body::empty()).unwrap();
            let mut first = std::pin::pin!(ship.clone().oneshot(put("/a")));
            assert!(futures::poll!(first.as_mut()).is_pending());
            assert_overloaded(ship.clone().oneshot(put("/b")).await.unwrap()).await;

            let router = Router::new().route("/a", axum::routing::put(|| async { "a" })).route("/b", axum::routing::put(|| async { "b" }));
            compio::runtime::spawn(serve_engine(rx, router)).detach();
            assert_eq!(first.await.unwrap().status(), StatusCode::OK);
            // A sender stays: the loop drops what is in flight once the last one is gone.
            assert_eq!(ship.clone().oneshot(put("/b")).await.unwrap().status(), StatusCode::OK);
        });
    }

    // The engine loop ends once the last sender is gone and drops the
    // requests still in flight before it returns, so none of them can reach
    // the engines during their shutdown; their callers get 503.
    #[test]
    #[allow(clippy::disallowed_methods, reason = "the caller plays the frontend runtime")]
    fn engine_loop_drops_in_flight_requests_when_it_ends() {
        engine_runtime::block_on(async {
            let started = Arc::new(tokio::sync::Notify::new());
            let alive = Arc::new(());
            let (handler_started, handler_alive) = (Arc::clone(&started), Arc::clone(&alive));
            let router = Router::new().route(
                "/hang",
                get(move || {
                    let (started, guard) = (Arc::clone(&handler_started), Arc::clone(&handler_alive));
                    async move {
                        let _guard = guard;
                        started.notify_one();
                        std::future::pending::<()>().await
                    }
                }),
            );
            let (tx, rx) = Lane::new(1);
            let engine = compio::runtime::spawn(serve_engine(rx, router));
            let caller = tokio::spawn(ShardRouter::new(vec![EngineDispatch::Engine(tx.clone())]).oneshot(get_req("/hang")));
            started.notified().await;

            drop(tx);
            engine.await.unwrap();
            assert_eq!(Arc::strong_count(&alive), 1, "the in-flight handler outlived the engine loop");
            assert_eq!(caller.await.unwrap().unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
        });
    }
}
