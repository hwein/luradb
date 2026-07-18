//! Shared-memory infrastructure for the local IPC bypass: segment lifecycle,
//! crash recovery and lock management (spec perf/006), the state header and
//! wait-free double-buffer protocol (spec perf/007), the SPSC command
//! ringbuffer with its dispatcher (spec perf/008), and the RCU read snapshots
//! published into the double buffer (spec perf/009).

mod commands;
mod dispatcher;
mod protocol;
mod registration;
mod ringbuffer;
mod shm;
mod snapshot;

pub use crate::config::ShmConfig;
pub use commands::{DecodeError, ShmCommand, ShmResponse};
pub use dispatcher::{ClientConnection, ClientEvent, ShmDispatcher};
pub use protocol::{
    ProtocolError, PublishOutcome, SnapshotGuard, SnapshotWriter, StateHeader, PUBLISH_WAIT_TIMEOUT_US,
};
pub use registration::{prepare_registration_socket, serve_registration, RegistrationConfig};
pub use ringbuffer::{
    DoubleMmapRegion, RingConsumer, RingCorrupt, RingProducer, RingSendError, RingbufferHeader,
};
pub use shm::{ClientShm, ShmManager, ShmSegment};
pub use snapshot::{
    ShmDomainIndex, ShmEntry, ShmSnapshot, SnapshotBuilder, SnapshotPublisher,
};
