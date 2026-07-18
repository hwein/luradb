use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum OpType {
    Set,
    Delete,
}

#[derive(Debug, Clone)]
pub struct WalEvent {
    pub key: Vec<u8>,
    pub op: OpType,
}

/// Creates a new broadcast channel for WAL events.
pub fn channel(capacity: usize) -> (broadcast::Sender<WalEvent>, broadcast::Receiver<WalEvent>) {
    broadcast::channel(capacity)
}
