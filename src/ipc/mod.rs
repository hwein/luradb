//! Shared-memory infrastructure for the local IPC bypass: segment lifecycle,
//! crash recovery and lock management (spec perf/006), the state header and
//! wait-free double-buffer protocol (spec perf/007), the SPSC command
//! ringbuffer with its dispatcher (spec perf/008), the RCU read snapshots
//! published into the double buffer (spec perf/009), and the per-client reader
//! slots with their registration lifecycle (spec perf/012).

mod commands;
mod dispatcher;
mod protocol;
mod readers;
mod registration;
mod ringbuffer;
mod shm;
mod snapshot;

pub use crate::config::ShmConfig;
pub use commands::{DecodeError, ShmCommand, ShmGetValue, ShmResponse};
pub use dispatcher::{ClientConnection, ClientEvent, ShmDispatcher};
pub use protocol::{
    ProtocolError, PublishOutcome, ReaderSlot, SnapshotGuard, SnapshotWriter, StateHeader,
    PUBLISH_WAIT_TIMEOUT_US, READER_SLOT_OFFSET,
};
pub use readers::{ReaderRegistry, ReaderSlotHandle, ReaderSlotLease};
pub use registration::{prepare_registration_socket, serve_registration, RegistrationConfig};
pub use ringbuffer::{
    DoubleMmapRegion, RingConsumer, RingCorrupt, RingProducer, RingSendError, RingbufferHeader,
};
pub use shm::{ClientShm, ReadOnlySegment, ShmManager, ShmSegment, CLIENT_HDR_SIZE};
pub use snapshot::{
    ShmDomainIndex, ShmEntry, ShmSnapshot, SnapshotBuilder, SnapshotPublisher,
};
