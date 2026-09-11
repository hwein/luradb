//! Engine bridge (spec perf/018a A2): ships each request from the frontend
//! runtime to the engine thread over one bounded channel and relays both
//! body streams frame by frame.

use crate::api::middleware::ApiError;
use axum::body::{Body, BodyDataStream, Bytes, HttpBody};
use axum::http::{request, response, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::future::BoxFuture;
use futures::{FutureExt, Stream, StreamExt};
use std::convert::Infallible;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tower::{Service, ServiceExt};

/// Body frames buffered per direction and request.
const BODY_FRAMES: usize = 16;

type Frame = Result<Bytes, axum::Error>;

/// One request on its way to the engine thread.
pub struct Job {
    parts: request::Parts,
    body: Option<mpsc::Receiver<Frame>>,
    reply: oneshot::Sender<(response::Parts, Payload)>,
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

/// Where [`ShipService`] hands its requests.
#[derive(Clone)]
pub enum EngineDispatch {
    /// Calls the router on the caller's runtime (tests).
    Inline(Router),
    /// Ships each request to [`serve_engine`] over the bounded bridge channel.
    Engine(mpsc::Sender<Job>),
}

/// Frontend end of the bridge, mounted as the frontend router's fallback.
#[derive(Clone)]
pub struct ShipService {
    dispatch: EngineDispatch,
}

impl ShipService {
    pub fn new(dispatch: EngineDispatch) -> Self {
        Self { dispatch }
    }
}

impl Service<Request<Body>> for ShipService {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match &self.dispatch {
            EngineDispatch::Inline(router) => router.clone().oneshot(req).boxed(),
            EngineDispatch::Engine(jobs) => ship(jobs.clone(), req).map(Ok).boxed(),
        }
    }
}

async fn ship(jobs: mpsc::Sender<Job>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let (reply, reply_rx) = oneshot::channel();
    // A full channel makes this wait: backpressure onto the connection.
    let sent = jobs.send(Job { parts, body: relay_request_body(body), reply }).await;
    // The engine loop ends once the last sender is gone (A6); hold none longer than needed.
    drop(jobs);
    if sent.is_err() {
        return engine_unavailable();
    }
    match reply_rx.await {
        Ok((parts, payload)) => Response::from_parts(parts, payload.into_body()),
        Err(_) => engine_unavailable(),
    }
}

fn engine_unavailable() -> Response {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "503 Service Unavailable: the server is shutting down")
        .into_response()
}

/// Relays the request body from the frontend; an empty body needs neither a
/// channel nor a task.
fn relay_request_body(body: Body) -> Option<mpsc::Receiver<Frame>> {
    if body.is_end_stream() {
        return None;
    }
    let (tx, rx) = mpsc::channel(BODY_FRAMES);
    tokio::spawn(relay(body.into_data_stream(), tx));
    Some(rx)
}

/// Engine end of the bridge: runs every shipped request on the calling
/// (engine) thread, each in its own task so long handlers interleave. Returns
/// once the last sender is gone, after dropping the requests still in flight,
/// so none of them runs into the engine shutdown (A6).
///
/// The loop itself is a runtime task, not this future: a task woken from a
/// frontend thread runs as soon as the local queue drains, while this future
/// is polled only after the yielded tasks have been queued again. Dropping
/// `serve_engine` early therefore detaches the loop instead of ending it.
pub async fn serve_engine(jobs: mpsc::Receiver<Job>, router: Router) {
    if let Err(e) = tokio::spawn(engine_loop(jobs, router)).await {
        if e.is_panic() {
            std::panic::resume_unwind(e.into_panic());
        }
    }
}

async fn engine_loop(mut jobs: mpsc::Receiver<Job>, router: Router) {
    let mut in_flight = JoinSet::new();
    loop {
        tokio::select! {
            job = jobs.recv() => match job {
                Some(job) => {
                    in_flight.spawn(handle(job, router.clone()));
                }
                None => break,
            },
            // Reap finished tasks so the set does not grow with request count.
            Some(_) = in_flight.join_next() => {}
        }
    }
    in_flight.shutdown().await;
}

async fn handle(job: Job, router: Router) {
    let body = job.body.map_or_else(Body::empty, |rx| Body::from_stream(frames(rx)));
    let req = Request::from_parts(job.parts, body);
    let Ok(resp) = router.oneshot(req).await;
    let (parts, mut body) = resp.into_parts();

    // A body that is already complete rides along in the reply. Bodies without
    // an exact length (SSE, backup download, bulk export) take the stream path,
    // as does one that is not ready in a single poll.
    let mut first = None;
    if body.is_end_stream() {
        let _ = job.reply.send((parts, Payload::Full(Bytes::new())));
        return;
    }
    if body.size_hint().exact().is_some() {
        match futures::poll!(std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx))) {
            Poll::Ready(None) => {
                let _ = job.reply.send((parts, Payload::Full(Bytes::new())));
                return;
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) if body.is_end_stream() => {
                    let _ = job.reply.send((parts, Payload::Full(data)));
                    return;
                }
                Ok(data) => first = Some(Ok(data)),
                // Trailers are not relayed (A2); the rest still is.
                Err(_) => {}
            },
            Poll::Ready(Some(Err(e))) => first = Some(Err(e)),
            Poll::Pending => {}
        }
    }

    let (tx, rx) = mpsc::channel(BODY_FRAMES);
    if job.reply.send((parts, Payload::Stream(rx))).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use axum::routing::{get, post};
    use futures::stream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// `serve_engine` on its own current-thread runtime thread, like the
    /// engine thread in production.
    fn engine_thread(router: Router) -> (mpsc::Sender<Job>, std::thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(8);
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(serve_engine(rx, router));
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
        let ship = ShipService::new(EngineDispatch::Engine(tx));

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
    fn send_from_another_thread(tx: mpsc::Sender<Job>, path: &'static str) {
        let (queued, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (parts, _) = Request::get(path).body(Body::empty()).unwrap().into_parts();
            let (reply, reply_rx) = oneshot::channel();
            tx.blocking_send(Job { parts, body: relay_request_body(Body::empty()), reply }).unwrap();
            // The answer is unused; the receiver only has to outlive the send.
            queued.send(reply_rx).unwrap();
        });
        wait.recv().unwrap();
    }

    // The engine loop is a runtime task, so a request that arrives while other
    // handlers are yielding gets its slice right after the running round. As
    // the loop's own future, it was polled only after the yielded tasks had
    // been queued again, which cost every request a full round.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_arriving_mid_round_runs_before_the_next_yield_round() {
        let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        // A sender inside the router would hold the bridge channel open for
        // good; the first handler takes it out and hands it to the thread.
        let late = Arc::new(std::sync::Mutex::new(None::<mpsc::Sender<Job>>));
        let (handler_log, handler_late) = (Arc::clone(&log), Arc::clone(&late));
        let router = Router::new().route(
            "/step/:name",
            get(move |axum::extract::Path(name): axum::extract::Path<String>| {
                let (log, late) = (Arc::clone(&handler_log), Arc::clone(&handler_late));
                async move {
                    for round in 0..2 {
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
        let ship = ShipService::new(EngineDispatch::Engine(tx));
        let a = tokio::spawn(ship.clone().oneshot(get_req("/step/a")));
        let b = tokio::spawn(ship.clone().oneshot(get_req("/step/b")));
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        drop(ship);
        engine.join().unwrap();

        // Indices, not the exact order: the deferred tasks wake LIFO.
        let log = log.lock().unwrap();
        let at = |step: &str| log.iter().position(|e| e == step).expect(step);
        assert!(at("c0") < at("a1") && at("c0") < at("b1"), "{log:?}");
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
        let ship = ShipService::new(EngineDispatch::Engine(tx));

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
    fn body_route(path: &str, body: impl Fn() -> Body + Clone + Send + 'static) -> Router {
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
        let ship = ShipService::new(EngineDispatch::Engine(tx));

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
        let ship = ShipService::new(EngineDispatch::Engine(tx));

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
        let ship = ShipService::new(EngineDispatch::Engine(tx));

        let mut body = ship.clone().oneshot(get_req("/broken")).await.unwrap().into_body().into_data_stream();
        let failed = body.next().await.unwrap().unwrap_err();
        assert!(failed.to_string().contains("engine body failed"), "{failed}");
        assert!(body.next().await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 1);

        drop(ship);
        engine.join().unwrap();
    }

    // Test 2: a closed bridge channel (engine shutting down) answers 503 in
    // the plaintext `ApiError` format.
    #[tokio::test]
    async fn closed_engine_channel_answers_503_text_plain() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let resp = ShipService::new(EngineDispatch::Engine(tx)).oneshot(get_req("/any")).await.unwrap();
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
        let ship = ShipService::new(EngineDispatch::Engine(tx));

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

    // Test 4: a full bridge channel holds the next request back instead of
    // rejecting it; it goes through once the engine takes the queued job.
    #[tokio::test]
    async fn full_engine_channel_holds_requests_back() {
        let (tx, rx) = mpsc::channel(1);
        let ship = ShipService::new(EngineDispatch::Engine(tx));
        let mut first = std::pin::pin!(ship.clone().oneshot(get_req("/a")));
        let mut second = std::pin::pin!(ship.clone().oneshot(get_req("/b")));
        assert!(futures::poll!(first.as_mut()).is_pending());
        assert!(futures::poll!(second.as_mut()).is_pending());
        assert_eq!(rx.len(), 1, "the second request must wait for a free slot");

        let router = Router::new().route("/a", get(|| async { "a" })).route("/b", get(|| async { "b" }));
        tokio::spawn(serve_engine(rx, router));
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        assert_eq!(second.await.unwrap().status(), StatusCode::OK);
    }

    // A6: the engine loop ends once the last sender is gone and drops the
    // requests still in flight before it returns, so none of them can reach
    // the engines during their shutdown; their callers get 503.
    #[tokio::test]
    async fn engine_loop_drops_in_flight_requests_when_it_ends() {
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
        let (tx, rx) = mpsc::channel(1);
        let engine = tokio::spawn(serve_engine(rx, router));
        let caller = tokio::spawn(ShipService::new(EngineDispatch::Engine(tx.clone())).oneshot(get_req("/hang")));
        started.notified().await;

        drop(tx);
        engine.await.unwrap();
        assert_eq!(Arc::strong_count(&alive), 1, "the in-flight handler outlived the engine loop");
        assert_eq!(caller.await.unwrap().unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
