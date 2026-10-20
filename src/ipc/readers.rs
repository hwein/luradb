//! Registry of the per-client reader slots the publisher scans.
//!
//! The dispatcher's `Vec<ClientConnection>` is task-local and out of reach for
//! the publisher task, so registration and publisher share this small registry
//! instead. A client's entry is held by a [`ReaderSlotLease`]: dropping it —
//! on EOF, on a kick, on an error path, or when the connection task is
//! aborted at an `.await` — *is* the reclamation.

use std::any::Any;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;

use super::protocol::ReaderSlot;

/// Publisher-side handle on one client's [`ReaderSlot`].
#[derive(Clone)]
pub struct ReaderSlotHandle {
    pub client_id: u64,
    slot: *const ReaderSlot,
    /// Keeps the page `slot` lives in alive: the client's `cmd_hdr` mapping in
    /// production, a test-owned allocation in unit tests. `shm_unlink` only
    /// removes the name — the mapping lives until the last `Arc` is gone.
    _owner: Arc<dyn Any + Send + Sync>,
    /// Wakes the client's connection task to disconnect it.
    kick: Arc<Notify>,
}

// Safe: `slot` points at atomics inside the mapping `_owner` keeps alive, and
// every access goes through `&AtomicU32`.
unsafe impl Send for ReaderSlotHandle {}
unsafe impl Sync for ReaderSlotHandle {}

impl ReaderSlotHandle {
    /// # Safety
    /// `slot` must point at a live, 64-byte-aligned `ReaderSlot` inside the
    /// mapping (or allocation) that `owner` keeps alive.
    pub unsafe fn new(
        client_id: u64,
        slot: *const ReaderSlot,
        owner: Arc<dyn Any + Send + Sync>,
        kick: Arc<Notify>,
    ) -> Self {
        Self { client_id, slot, _owner: owner, kick }
    }

    pub fn slot(&self) -> &ReaderSlot {
        // Safe: the constructor's contract plus `_owner` keeping the mapping alive.
        unsafe { &*self.slot }
    }
}

/// Every registered client's slot. Cloned once per publish, then scanned
/// lock-free.
#[derive(Default)]
pub struct ReaderRegistry {
    slots: Mutex<Vec<ReaderSlotHandle>>,
}

impl ReaderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `handle` and returns the lease whose `Drop` removes it again.
    pub fn register(self: &Arc<Self>, handle: ReaderSlotHandle) -> ReaderSlotLease {
        let client_id = handle.client_id;
        self.lock().push(handle);
        ReaderSlotLease { registry: Arc::clone(self), client_id }
    }

    /// Clone of the current handle list — the publisher's scan input.
    pub fn snapshot(&self) -> Vec<ReaderSlotHandle> {
        self.lock().clone()
    }

    /// Clients currently pinning `buffer`, with their pin counts (warn and kick paths).
    pub fn blockers(&self, buffer: u32) -> Vec<(u64, u32)> {
        self.lock()
            .iter()
            .filter_map(|h| {
                let n = h.slot().counter(buffer as usize).load(std::sync::atomic::Ordering::Acquire);
                (n != 0).then_some((h.client_id, n))
            })
            .collect()
    }

    /// Disconnects `client_id` as if its socket had hit EOF: its connection
    /// task drops the lease and closes the socket. The signal waits if the task
    /// is not listening yet; an unknown id is ignored.
    pub fn kick(&self, client_id: u64) {
        if let Some(h) = self.lock().iter().find(|h| h.client_id == client_id) {
            h.kick.notify_one();
        }
    }

    fn remove(&self, client_id: u64) {
        self.lock().retain(|h| h.client_id != client_id);
    }

    /// A poisoned lock is used anyway: the payload is a plain `Vec`, and the
    /// publisher must not die of an unrelated panic.
    fn lock(&self) -> MutexGuard<'_, Vec<ReaderSlotHandle>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Registration lifetime of one client's slot. Frees it on drop — including
/// when the connection task is aborted at an `.await` (spec §7).
pub struct ReaderSlotLease {
    registry: Arc<ReaderRegistry>,
    client_id: u64,
}

impl Drop for ReaderSlotLease {
    fn drop(&mut self) {
        self.registry.remove(self.client_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::sync::atomic::Ordering;

    fn handle(client_id: u64, slot: &Arc<ReaderSlot>, kick: Arc<Notify>) -> ReaderSlotHandle {
        // Safe: the pointer targets the slot inside `slot`, and the handle keeps
        // its own clone of that allocation alive.
        unsafe {
            ReaderSlotHandle::new(
                client_id,
                Arc::as_ptr(slot),
                Arc::clone(slot) as Arc<dyn Any + Send + Sync>,
                kick,
            )
        }
    }

    #[test]
    fn test_register_snapshot_and_lease_drop() {
        let registry = Arc::new(ReaderRegistry::new());
        let slot = Arc::new(ReaderSlot::zeroed());

        let lease = registry.register(handle(7, &slot, Arc::default()));
        let snap = registry.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].client_id, 7);

        drop(lease);
        assert!(registry.snapshot().is_empty(), "lease drop deregisters the slot");
    }

    // The handle outlives the registration and still points at a live slot: the
    // `Arc` in `_owner` is what keeps the page mapped during a running scan.
    #[test]
    fn test_handle_keeps_slot_alive_after_deregistration() {
        let registry = Arc::new(ReaderRegistry::new());
        let held = {
            let slot = Arc::new(ReaderSlot::zeroed());
            slot.readers_b.store(3, Ordering::Release);
            let lease = registry.register(handle(1, &slot, Arc::default()));
            let snap = registry.snapshot();
            drop(lease);
            snap
        };
        assert_eq!(held[0].slot().counter(1).load(Ordering::Acquire), 3);
    }

    #[test]
    fn test_blockers_lists_only_pinning_clients() {
        let registry = Arc::new(ReaderRegistry::new());
        let idle = Arc::new(ReaderSlot::zeroed());
        let busy = Arc::new(ReaderSlot::zeroed());
        busy.readers_a.store(2, Ordering::Release);

        let _l1 = registry.register(handle(1, &idle, Arc::default()));
        let _l2 = registry.register(handle(2, &busy, Arc::default()));

        assert_eq!(registry.blockers(0), vec![(2, 2)]);
        assert!(registry.blockers(1).is_empty());
    }

    #[test]
    fn test_kick_signals_only_the_named_client() {
        let registry = Arc::new(ReaderRegistry::new());
        let slot = Arc::new(ReaderSlot::zeroed());
        let (kick_1, kick_2) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        let _l1 = registry.register(handle(1, &slot, Arc::clone(&kick_1)));
        let _l2 = registry.register(handle(2, &slot, Arc::clone(&kick_2)));

        registry.kick(2);
        registry.kick(99); // not registered: ignored

        // The signal is kept until the connection task next waits for it.
        assert!(kick_2.notified().now_or_never().is_some(), "client 2 kicked");
        assert!(kick_1.notified().now_or_never().is_none(), "client 1 untouched");
    }
}
