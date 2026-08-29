use tokio::sync::broadcast;

/// SSE stream tag for the KV watch (spec kv/024 §1) — distinguishes its
/// event ids from other resumable streams (e.g. general/018's `g`) sharing
/// the same `<tag>-<epoch>-<seq>` wire format.
pub const WATCH_TAG: &str = "w";

#[derive(Debug, Clone)]
pub enum OpType {
    Set,
    Delete,
}

#[derive(Debug, Clone)]
pub struct WalEvent {
    /// Engine-wide, monotonically increasing stream sequence (spec kv/024
    /// §1) — distinct from the MVCC timestamp; orders the stream, not the
    /// writes (two concurrent writers on the same key may publish out of
    /// timestamp order).
    pub seq: u64,
    pub key: Vec<u8>,
    pub op: OpType,
}

/// Message carried on a domain's relay channel (spec kv/024 §6). `Gap`
/// replaces the old silent `continue` on a lagged relay-side receive: the
/// domain-filtered stream is not sequence-contiguous by construction
/// (foreign-domain events create normal seq gaps), so a lag can only be
/// signaled explicitly, never inferred from the sequence.
#[derive(Debug, Clone)]
pub enum WatchMessage {
    Event(WalEvent),
    Gap,
}

/// Creates a new broadcast channel for WAL events.
pub fn channel(capacity: usize) -> (broadcast::Sender<WalEvent>, broadcast::Receiver<WalEvent>) {
    broadcast::channel(capacity)
}
