//! Shared infrastructure for resumable SSE streams (spec kv/024): a
//! per-process stream epoch and a sequenced replay ring. Generic over the
//! event type `T` so a second stream source (spec general/018) can reuse it
//! with its own tag and its own `SeqRing` instance — sequences are per
//! stream source, never shared across two `SeqRing`s.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::OnceLock;
use tokio::sync::broadcast;

/// Per-process stream epoch. Random, not clock-based: a restart within the
/// same second (or a clock that went backwards) must never reuse an epoch.
pub fn stream_epoch() -> u64 {
    static EPOCH: OnceLock<u64> = OnceLock::new();
    *EPOCH.get_or_init(rand::random::<u64>)
}

/// Parses `<tag>-<epoch:016x>-<seq>`, verifying `tag` matches `expected_tag`
/// (spec kv/024 §1: without the tag check, an id meant for a different
/// stream could pass the epoch check and produce a false "gapless"). Returns
/// `None` for any structurally invalid or wrong-tag id.
pub fn parse_event_id(raw: &str, expected_tag: &str) -> Option<(u64, u64)> {
    let mut parts = raw.splitn(3, '-');
    if parts.next()? != expected_tag {
        return None;
    }
    let epoch = u64::from_str_radix(parts.next()?, 16).ok()?;
    let seq: u64 = parts.next()?.parse().ok()?;
    Some((epoch, seq))
}

/// Formats an SSE `id:` value: `<tag>-<epoch:016x>-<seq>`.
pub fn format_event_id(tag: &str, epoch: u64, seq: u64) -> String {
    format!("{tag}-{epoch:016x}-{seq}")
}

/// Why a stream could not (or would not) guarantee a gapless resume —
/// carried as `{"reason": ...}` in an `event: reset` body (spec kv/024 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetReason {
    /// The stream's epoch doesn't match the client's id — the process
    /// restarted since that id was issued.
    Restart,
    /// The requested id is older than the ring's replay window (or the ring
    /// is disabled, `cap == 0`).
    WindowExceeded,
    /// A broadcast receiver missed messages (slow consumer).
    Lagged,
    /// The id is unparseable, carries a foreign tag, or names a sequence
    /// that was never issued (from the future).
    UnknownId,
}

/// Outcome of a resume decision (spec kv/024 §4.2/§4.3).
pub enum Resume<T> {
    /// No id was presented — behave exactly like a fresh, non-resuming watch.
    Live,
    /// Gaplessness cannot be guaranteed; the caller must emit `event: reset`
    /// before continuing live. `head` is the current sequence head, used as
    /// the reset event's own `id:` (spec kv/024 §5).
    Reset { reason: ResetReason, head: u64 },
    /// Gapless replay of these events (in ascending seq order), then live.
    /// `head` is the sequence at the moment of the snapshot — events
    /// arriving live with `seq <= head` are duplicates of this replay.
    Replay { events: Vec<T>, head: u64 },
}

struct Inner<T> {
    /// Sequence assigned to the *next* published event. Starts at 1 — `seq
    /// == 0` never occurs and means "from the beginning" in a client id.
    next_seq: u64,
    /// Ring capacity. `0` disables replay storage without disabling
    /// sequencing (`id:` fields exist regardless).
    cap: usize,
    buf: VecDeque<(u64, T)>,
}

/// Assigns sequence numbers for one stream source and keeps a bounded
/// replay ring. `publish`/`publish_many` push into the ring and send on the
/// broadcast channel inside the same lock section, so broadcast delivery
/// order is always sequence order — required for `snapshot_since`'s
/// replay-then-live handoff to be gapless (spec kv/024 §2).
pub struct SeqRing<T> {
    inner: Mutex<Inner<T>>,
}

impl<T: Clone> SeqRing<T> {
    /// `buf` starts empty (not pre-allocated to `cap`), so an unused ring
    /// (e.g. `cap == 0` on the json/rel engines) costs no memory.
    pub fn new(cap: usize) -> Self {
        Self { inner: Mutex::new(Inner { next_seq: 1, cap, buf: VecDeque::new() }) }
    }

    /// Assigns the next sequence, rings it (if `cap > 0`), and broadcasts it
    /// — all under one lock, so no concurrent writer can be reordered
    /// between assignment and send. Returns the assigned sequence.
    pub fn publish(&self, tx: &broadcast::Sender<T>, make: impl FnOnce(u64) -> T) -> u64 {
        let mut inner = self.inner.lock();
        let seq = inner.next_seq;
        inner.next_seq += 1;
        let event = make(seq);
        Self::ring_push(&mut inner, seq, &event);
        let _ = tx.send(event);
        seq
    }

    /// Same as [`Self::publish`], but assigns `n` consecutive sequences in
    /// one lock section — no other writer's event can land between them, so
    /// an atomic multi-op write (e.g. `write_batch`) stays contiguous in the
    /// stream too (spec kv/024 §2).
    pub fn publish_many(&self, tx: &broadcast::Sender<T>, n: usize, mut make: impl FnMut(u64) -> T) {
        if n == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        for _ in 0..n {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            let event = make(seq);
            Self::ring_push(&mut inner, seq, &event);
            let _ = tx.send(event);
        }
    }

    fn ring_push(inner: &mut Inner<T>, seq: u64, event: &T) {
        if inner.cap == 0 {
            return;
        }
        if inner.buf.len() == inner.cap {
            inner.buf.pop_front();
        }
        inner.buf.push_back((seq, event.clone()));
    }

    /// Current sequence head (`next_seq - 1`; `0` on a never-published
    /// ring) — the `id:` a `reset` event carries (spec kv/024 §5).
    pub fn head(&self) -> u64 {
        self.inner.lock().next_seq - 1
    }

    /// Resume decision for a client-supplied `last` sequence (spec kv/024
    /// §4.2). The row order below is binding: `cap == 0` is checked *before*
    /// the window rows — with a disabled ring, `lo == next_seq == hi + 1`,
    /// so `last == hi` would satisfy neither `last > hi` nor `last + 1 <
    /// lo`, and without this early return `snapshot_since` would silently
    /// return an empty-but-gapless replay a disabled ring cannot back up.
    pub fn snapshot_since(&self, last: u64) -> Resume<T> {
        let inner = self.inner.lock();
        let hi = inner.next_seq - 1;
        if inner.cap == 0 {
            return Resume::Reset { reason: ResetReason::WindowExceeded, head: hi };
        }
        let lo = inner.next_seq - inner.buf.len() as u64;
        if last > hi {
            return Resume::Reset { reason: ResetReason::UnknownId, head: hi };
        }
        if last + 1 < lo {
            return Resume::Reset { reason: ResetReason::WindowExceeded, head: hi };
        }
        let events = inner.buf.iter().filter(|(seq, _)| *seq > last).map(|(_, e)| e.clone()).collect();
        Resume::Replay { events, head: hi }
    }

    /// Full resume decision from a raw client-supplied id (spec kv/024
    /// §4.2, rows "kein Header" through "epoch !="): parses `raw_id` against
    /// `tag`, checks it against `current_epoch`, then defers to
    /// [`Self::snapshot_since`]. `current_epoch` is an explicit parameter
    /// (rather than reading [`stream_epoch`] internally) so the restart row
    /// is unit-testable without an actual process restart.
    pub fn decide_resume(&self, raw_id: Option<&str>, tag: &str, current_epoch: u64) -> Resume<T> {
        let Some(raw) = raw_id else { return Resume::Live };
        let Some((epoch, last)) = parse_event_id(raw, tag) else {
            return Resume::Reset { reason: ResetReason::UnknownId, head: self.head() };
        };
        if epoch != current_epoch {
            return Resume::Reset { reason: ResetReason::Restart, head: self.head() };
        }
        self.snapshot_since(last)
    }
}

// ── Global lifecycle/DDL event stream (spec general/018) ────────────────────

/// Tag for `GET /store-api/events` ids — distinguishes them from `WATCH_TAG`
/// (`w`, spec kv/024), which shares the same epoch/sequence format but is a
/// separate stream with its own sequence (spec general/018 §5).
pub const EVENTS_TAG: &str = "g";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// One lifecycle/DDL event (spec general/018 §1/§2): a domain created/
/// deleted/purged, or (rel/json) table/view/index DDL. `seq` is excluded from
/// the wire JSON (`#[serde(skip)]`) — it only backs the SSE `id:` field and
/// the live-stream replay-overlap check (spec §5), never the payload itself.
#[derive(Debug, Clone, Serialize)]
pub struct GlobalEvent {
    #[serde(skip)]
    pub seq: u64,
    pub engine: &'static str,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    pub ts: u64,
}

/// AppState-wide broadcast of lifecycle/DDL events across the KV, JSON and
/// relational engines (spec general/018 §1) — a `SeqRing` of its own, tagged
/// `g`, entirely independent of any per-domain KV watch (`WATCH_TAG`, `w`).
pub struct GlobalEventBus {
    tx: broadcast::Sender<GlobalEvent>,
    log: SeqRing<GlobalEvent>,
}

impl GlobalEventBus {
    pub fn new(channel_capacity: usize, replay_buffer_size: usize) -> Self {
        let (tx, _rx) = broadcast::channel(channel_capacity);
        Self { tx, log: SeqRing::new(replay_buffer_size) }
    }

    /// Subscribes to the live channel. Callers must subscribe *before*
    /// taking a replay snapshot (spec §5, kv/024 §4.3) so nothing published
    /// in between is lost — only re-delivered, which the caller discards via
    /// the replay's own `head`.
    pub fn subscribe(&self) -> broadcast::Receiver<GlobalEvent> {
        self.tx.subscribe()
    }

    /// Current sequence head — the `id:` a live-triggered `reset` carries
    /// (spec §5), as opposed to one from the initial resume decision, which
    /// already carries its own `head`.
    pub fn head(&self) -> u64 {
        self.log.head()
    }

    /// Full resume decision for `GET /store-api/events` (spec §5): parses
    /// and validates against `EVENTS_TAG`/the process epoch, then defers to
    /// the replay ring.
    pub fn decide_resume(&self, raw_id: Option<&str>) -> Resume<GlobalEvent> {
        self.log.decide_resume(raw_id, EVENTS_TAG, stream_epoch())
    }

    /// Publishes one event, filling `seq`/`ts` and delegating to
    /// `SeqRing::publish` — same mutex-coupled sequence/broadcast ordering as
    /// kv/024 (spec §1).
    pub fn publish(&self, engine: &'static str, kind: &'static str, domain: &str, object: Option<String>) {
        let domain = domain.to_string();
        self.log.publish(&self.tx, |seq| GlobalEvent {
            seq,
            engine,
            kind,
            domain: domain.clone(),
            object: object.clone(),
            ts: now_secs(),
        });
    }

    /// Publishes `events.len()` consecutive events sharing one `ts` (spec
    /// §1: `RENAME TABLE` needs two events, `table_dropped` then
    /// `table_created`, that land adjacent in the stream with no foreign
    /// event between them — `engine`/`domain` are shared since one
    /// `publish_many` call always comes from one DDL statement on one domain).
    pub fn publish_many(&self, engine: &'static str, domain: &str, events: &[(&'static str, Option<String>)]) {
        let ts = now_secs();
        let mut items = events.iter();
        self.log.publish_many(&self.tx, events.len(), |seq| {
            let (kind, object) = items.next().expect("publish_many: make is called exactly events.len() times");
            GlobalEvent { seq, engine, kind: *kind, domain: domain.to_string(), object: object.clone(), ts }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_of(cap: usize) -> (SeqRing<u32>, broadcast::Sender<u32>) {
        let (tx, _rx) = broadcast::channel(64);
        (SeqRing::new(cap), tx)
    }

    #[test]
    fn test_stream_epoch_is_stable_within_process() {
        assert_eq!(stream_epoch(), stream_epoch());
    }

    #[test]
    fn test_format_and_parse_roundtrip() {
        let id = format_event_id("w", 0x9f2c14ab77d0e105, 4711);
        assert_eq!(id, "w-9f2c14ab77d0e105-4711");
        assert_eq!(parse_event_id(&id, "w"), Some((0x9f2c14ab77d0e105, 4711)));
    }

    #[test]
    fn test_parse_rejects_foreign_tag_and_garbage() {
        let id = format_event_id("g", 1, 1);
        assert_eq!(parse_event_id(&id, "w"), None, "foreign tag must not parse under a different expected tag");
        assert_eq!(parse_event_id("garbage", "w"), None);
        assert_eq!(parse_event_id("w-not-hex-1", "w"), None);
        assert_eq!(parse_event_id("w-01-not-a-number", "w"), None);
    }

    // publish/publish_many assign strictly increasing sequences starting at 1.
    #[test]
    fn test_publish_assigns_monotonic_sequences_starting_at_one() {
        let (ring, tx) = ring_of(10);
        assert_eq!(ring.publish(&tx, |seq| seq as u32), 1);
        assert_eq!(ring.publish(&tx, |seq| seq as u32), 2);
        ring.publish_many(&tx, 3, |seq| seq as u32);
        assert_eq!(ring.head(), 5);
    }

    // publish_many assigns n consecutive sequences in one call.
    #[test]
    fn test_publish_many_consecutive() {
        let (ring, tx) = ring_of(10);
        let mut seen = Vec::new();
        ring.publish_many(&tx, 4, |seq| {
            seen.push(seq);
            seq as u32
        });
        assert_eq!(seen, vec![1, 2, 3, 4]);
    }

    // A full ring evicts the oldest entry (bounded memory).
    #[test]
    fn test_ring_evicts_oldest_when_full() {
        let (ring, tx) = ring_of(3);
        for i in 1..=5u32 {
            ring.publish(&tx, |_| i);
        }
        match ring.snapshot_since(0) {
            Resume::Reset { reason: ResetReason::WindowExceeded, .. } => {}
            _ => panic!("expected window_exceeded for a fully-evicted range, got a different Resume"),
        }
        // After 5 publishes into a cap=3 ring, seq 3..=5 are the ones still
        // held (1 and 2 were evicted) -- last == 2 sits exactly at the
        // eviction boundary, so it's still a gapless replay of what remains.
        match ring.snapshot_since(2) {
            Resume::Replay { events, head } => {
                assert_eq!(events, vec![3, 4, 5]);
                assert_eq!(head, 5);
            }
            _ => panic!("expected a replay"),
        }
    }

    // cap == 0 still assigns sequences (id: fields always exist) but never
    // stores anything, and every snapshot is window_exceeded (spec §2, §4.2).
    #[test]
    fn test_cap_zero_sequences_but_never_replays() {
        let (ring, tx) = ring_of(0);
        let seq = ring.publish(&tx, |seq| seq as u32);
        assert_eq!(seq, 1);
        assert_eq!(ring.head(), 1);
        match ring.snapshot_since(1) {
            Resume::Reset { reason: ResetReason::WindowExceeded, head } => assert_eq!(head, 1),
            _ => panic!("cap == 0 must always reset, even for last == head"),
        }
    }

    // An empty-but-active ring resumes gaplessly at its own head (spec §4.2:
    // "Bei aktivem, aber noch leerem Ring greift dieselbe Arithmetik korrekt").
    #[test]
    fn test_fresh_ring_last_equals_head_is_gapless_empty_replay() {
        let ring: SeqRing<u32> = SeqRing::new(10);
        match ring.snapshot_since(0) {
            Resume::Replay { events, head } => {
                assert!(events.is_empty());
                assert_eq!(head, 0);
            }
            _ => panic!("expected a (trivially empty) gapless replay"),
        }
    }

    // last > hi ("from the future") is unknown_id, not window_exceeded.
    #[test]
    fn test_last_from_the_future_is_unknown_id() {
        let (ring, tx) = ring_of(10);
        ring.publish(&tx, |seq| seq as u32);
        match ring.snapshot_since(99) {
            Resume::Reset { reason: ResetReason::UnknownId, .. } => {}
            _ => panic!("expected unknown_id"),
        }
    }

    // decide_resume: no id -> Live; epoch mismatch -> Restart, with the
    // epoch supplied as an explicit parameter (testable without a real
    // process restart, spec kv/024 Tests #4).
    #[test]
    fn test_decide_resume_no_id_is_live() {
        let ring: SeqRing<u32> = SeqRing::new(10);
        assert!(matches!(ring.decide_resume(None, "w", 42), Resume::Live));
    }

    #[test]
    fn test_decide_resume_epoch_mismatch_is_restart() {
        let (ring, tx) = ring_of(10);
        ring.publish(&tx, |seq| seq as u32);
        let id = format_event_id("w", 111, 1);
        match ring.decide_resume(Some(&id), "w", 222) {
            Resume::Reset { reason: ResetReason::Restart, head } => assert_eq!(head, 1),
            _ => panic!("expected restart on epoch mismatch"),
        }
        // Same id, matching epoch -> gapless (empty) replay, not a reset.
        match ring.decide_resume(Some(&id), "w", 111) {
            Resume::Replay { events, .. } => assert!(events.is_empty()),
            _ => panic!("expected a gapless replay once the epoch matches"),
        }
    }

    #[test]
    fn test_decide_resume_wrong_tag_is_unknown_id() {
        let (ring, tx) = ring_of(10);
        ring.publish(&tx, |seq| seq as u32);
        let id = format_event_id("g", stream_epoch(), 1);
        match ring.decide_resume(Some(&id), "w", stream_epoch()) {
            Resume::Reset { reason: ResetReason::UnknownId, .. } => {}
            _ => panic!("expected unknown_id for a foreign tag"),
        }
    }

    // Broadcast delivery order matches sequence order even under concurrent
    // publishers (spec kv/024 §2: publish couples ring-push and send under
    // one lock, so no writer can be reordered between them).
    #[test]
    fn test_broadcast_order_matches_sequence_order() {
        let (ring, tx) = ring_of(0);
        let ring = std::sync::Arc::new(ring);
        let mut rx = tx.subscribe();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let ring = std::sync::Arc::clone(&ring);
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                ring.publish(&tx, |seq| seq as u32);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let mut received = Vec::new();
        for _ in 0..8 {
            received.push(rx.try_recv().unwrap());
        }
        let mut sorted = received.clone();
        sorted.sort_unstable();
        assert_eq!(received, sorted, "broadcast order must equal sequence order: {received:?}");
    }

    // ── GlobalEventBus (spec general/018) ───────────────────────────────────

    #[test]
    fn test_global_event_bus_publish_populates_fields_and_advances_head() {
        let bus = GlobalEventBus::new(16, 16);
        let mut rx = bus.subscribe();
        bus.publish("kv", "domain_created", "sales", None);
        let event = rx.try_recv().unwrap();
        assert_eq!(event.seq, 1);
        assert_eq!(event.engine, "kv");
        assert_eq!(event.kind, "domain_created");
        assert_eq!(event.domain, "sales");
        assert_eq!(event.object, None);
        assert!(event.ts > 0);
        assert_eq!(bus.head(), 1);
    }

    // publish_many assigns consecutive sequences and one shared ts across
    // the whole call (spec §1: RENAME TABLE's two events).
    #[test]
    fn test_global_event_bus_publish_many_consecutive_seq_and_shared_ts() {
        let bus = GlobalEventBus::new(16, 16);
        let mut rx = bus.subscribe();
        bus.publish_many(
            "rel",
            "sales",
            &[("table_dropped", Some("old".to_string())), ("table_created", Some("new".to_string()))],
        );
        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert_eq!((first.seq, first.kind, first.object.as_deref()), (1, "table_dropped", Some("old")));
        assert_eq!((second.seq, second.kind, second.object.as_deref()), (2, "table_created", Some("new")));
        assert_eq!(first.ts, second.ts, "publish_many events must share one ts");
    }

    #[test]
    fn test_global_event_serializes_with_type_field_and_omits_absent_object_and_seq() {
        let bus = GlobalEventBus::new(16, 16);
        let mut rx = bus.subscribe();
        bus.publish("kv", "domain_created", "sales", None);
        let event = rx.try_recv().unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "domain_created");
        assert!(json.get("object").is_none(), "absent object must be omitted, got {json}");
        assert!(json.get("seq").is_none(), "seq is wire-internal only, must not appear in data");
    }

    // A watch id (WATCH_TAG "w") must never validate against the global
    // stream's own tag (spec §5) — mirrors kv/024's tag-isolation guarantee.
    #[test]
    fn test_global_event_bus_decide_resume_rejects_foreign_tag() {
        let bus = GlobalEventBus::new(16, 16);
        bus.publish("kv", "domain_created", "sales", None);
        let foreign = format_event_id("w", stream_epoch(), 1);
        match bus.decide_resume(Some(&foreign)) {
            Resume::Reset { reason: ResetReason::UnknownId, .. } => {}
            _ => panic!("expected unknown_id for a foreign tag"),
        }
    }
}
