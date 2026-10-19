use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use super::BlobStoreError;
use super::{BlobTransferId, BlobVariantId};
use crate::StoreError;

/// Process-local bounds for Blob operations which must exclude reclamation.
///
/// These limits are deliberately not durable policy. They describe the
/// maximum concurrency of the embedding process and are reconstructed on
/// every open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct BlobLeaseLimits {
    application_pages: usize,
    network_sessions: usize,
    blob_workers: usize,
}

impl BlobLeaseLimits {
    pub const DEFAULT: Self = Self {
        application_pages: 1,
        network_sessions: 1,
        blob_workers: 1,
    };

    pub const fn new(
        application_pages: usize,
        network_sessions: usize,
        blob_workers: usize,
    ) -> Result<Self, BlobLeaseLimitError> {
        if application_pages == 0 || network_sessions == 0 || blob_workers == 0 {
            return Err(BlobLeaseLimitError);
        }
        let Some(partial) = application_pages.checked_add(network_sessions) else {
            return Err(BlobLeaseLimitError);
        };
        if partial.checked_add(blob_workers).is_none() {
            return Err(BlobLeaseLimitError);
        }
        Ok(Self {
            application_pages,
            network_sessions,
            blob_workers,
        })
    }

    pub const fn application_pages(self) -> usize {
        self.application_pages
    }

    pub const fn network_sessions(self) -> usize {
        self.network_sessions
    }

    pub const fn blob_workers(self) -> usize {
        self.blob_workers
    }
}

impl Default for BlobLeaseLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct BlobLeaseLimitError;

/// Opaque process-local lease retained by one local Blob publication attempt.
///
/// Dropping this value cancels the attempt's exclusion claim. It contains no
/// durable or wire-visible holder identity.
#[derive(Debug)]
pub(crate) struct BlobLocalImportLease {
    _handle: Arc<BlobLeaseHandle>,
}

impl BlobLocalImportLease {
    pub(crate) fn new(handle: Arc<BlobLeaseHandle>) -> Self {
        Self { _handle: handle }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // Staging generations become production admission inputs in Task 3.
pub(crate) enum BlobLeaseTarget {
    Variant(BlobVariantId),
    Staging(BlobTransferId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobLeaseKind {
    LocalImport,
    ApplicationPageRead,
    CarrierRange,
    CarrierExtent,
    InternalChunkWork,
}

impl BlobLeaseKind {
    const fn index(self) -> usize {
        match self {
            Self::LocalImport => 0,
            Self::ApplicationPageRead => 1,
            Self::CarrierRange => 2,
            Self::CarrierExtent => 3,
            Self::InternalChunkWork => 4,
        }
    }

    pub(crate) fn can_reuse_as(self, requested: Self) -> bool {
        self == requested
            || matches!(
                (self, requested),
                (Self::LocalImport, Self::InternalChunkWork)
                    | (Self::InternalChunkWork, Self::LocalImport)
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Admission-only errors become production paths in Task 3.
pub(crate) enum BlobLeaseAcquireError {
    Capacity,
    DeletePending,
    GenerationChanged,
    ActiveLeases,
    GenerationExhausted,
    Poisoned,
}

pub(crate) fn store_error(error: BlobLeaseAcquireError) -> StoreError {
    StoreError::Blob(match error {
        BlobLeaseAcquireError::DeletePending => BlobStoreError::VariantDeleting,
        BlobLeaseAcquireError::Capacity => BlobStoreError::LeaseCapacity,
        BlobLeaseAcquireError::GenerationChanged | BlobLeaseAcquireError::ActiveLeases => {
            BlobStoreError::VariantDeleting
        }
        BlobLeaseAcquireError::GenerationExhausted => {
            BlobStoreError::SchemaInvariant("Blob lease generation is exhausted")
        }
        BlobLeaseAcquireError::Poisoned => {
            BlobStoreError::SchemaInvariant("Blob lease registry is poisoned")
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BlobLeaseGeneration(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct BlobLeaseKey {
    owner: [u8; 32],
    target: BlobLeaseTarget,
}

#[derive(Clone, Copy, Debug)]
struct LeaseEntry {
    active: usize,
    active_by_kind: [usize; 5],
    delete_pending: bool,
    generation: BlobLeaseGeneration,
    watches: usize,
}

#[derive(Debug, Default)]
struct LeaseState {
    next_generation: u64,
    entries: HashMap<BlobLeaseKey, LeaseEntry>,
    watches: usize,
    application_pages: usize,
    network_sessions: usize,
    blob_workers: usize,
}

// One maintenance worker may inspect one exact deletion candidate at a time.
// Keeping this bound separate from operation slots prevents candidate scans
// from retaining an unbounded set of otherwise inactive target identities.
const MAX_DELETE_WATCHES: usize = 1;

#[derive(Debug)]
struct RegistryInner {
    limits: BlobLeaseLimits,
    state: Mutex<LeaseState>,
}

/// Bounded, process-local exclusion authority for Blob reads and mutation work.
#[derive(Clone, Debug)]
pub(crate) struct BlobLifecycleLeaseRegistry {
    inner: Arc<RegistryInner>,
}

impl BlobLifecycleLeaseRegistry {
    pub(crate) fn new(limits: BlobLeaseLimits) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                limits,
                state: Mutex::new(LeaseState::default()),
            }),
        }
    }

    pub(crate) fn acquire(
        &self,
        owner: [u8; 32],
        target: BlobLeaseTarget,
        kind: BlobLeaseKind,
    ) -> Result<BlobLeaseGuard, BlobLeaseAcquireError> {
        let key = BlobLeaseKey { owner, target };
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| BlobLeaseAcquireError::Poisoned)?;
        if state
            .entries
            .get(&key)
            .is_some_and(|entry| entry.delete_pending)
        {
            return Err(BlobLeaseAcquireError::DeletePending);
        }
        let (used, limit) = match kind {
            BlobLeaseKind::ApplicationPageRead => {
                (state.application_pages, self.inner.limits.application_pages)
            }
            BlobLeaseKind::CarrierRange | BlobLeaseKind::CarrierExtent => {
                (state.network_sessions, self.inner.limits.network_sessions)
            }
            BlobLeaseKind::LocalImport | BlobLeaseKind::InternalChunkWork => {
                (state.blob_workers, self.inner.limits.blob_workers)
            }
        };
        if used >= limit {
            return Err(BlobLeaseAcquireError::Capacity);
        }
        let generation = allocate_generation(&mut state)?;
        let entry = state.entries.entry(key).or_insert(LeaseEntry {
            active: 0,
            active_by_kind: [0; 5],
            delete_pending: false,
            generation,
            watches: 0,
        });
        entry.generation = generation;
        entry.active = entry
            .active
            .checked_add(1)
            .ok_or(BlobLeaseAcquireError::Capacity)?;
        entry.active_by_kind[kind.index()] = entry.active_by_kind[kind.index()]
            .checked_add(1)
            .ok_or(BlobLeaseAcquireError::Capacity)?;
        match kind {
            BlobLeaseKind::ApplicationPageRead => state.application_pages += 1,
            BlobLeaseKind::CarrierRange | BlobLeaseKind::CarrierExtent => {
                state.network_sessions += 1;
            }
            BlobLeaseKind::LocalImport | BlobLeaseKind::InternalChunkWork => {
                state.blob_workers += 1;
            }
        }
        Ok(BlobLeaseGuard {
            registry: self.clone(),
            key,
            kind,
            generation,
            released: false,
        })
    }

    /// Pins one exact target identity while a deletion candidate is checked.
    ///
    /// Only this target's generation participates in admission. Unrelated
    /// traffic cannot invalidate the token, and the fixed watch bound prevents
    /// candidate scans from retaining unbounded inactive identities.
    #[allow(dead_code)] // Consumed by exact manifest admission in Task 3.
    pub(crate) fn snapshot(
        &self,
        owner: [u8; 32],
        target: BlobLeaseTarget,
    ) -> Result<BlobLeaseSnapshot, BlobLeaseAcquireError> {
        let key = BlobLeaseKey { owner, target };
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| BlobLeaseAcquireError::Poisoned)?;
        if state.watches >= MAX_DELETE_WATCHES {
            return Err(BlobLeaseAcquireError::Capacity);
        }
        let generation = match state.entries.get(&key) {
            Some(entry) if entry.delete_pending => {
                return Err(BlobLeaseAcquireError::DeletePending);
            }
            Some(entry) => entry.generation,
            None => allocate_generation(&mut state)?,
        };
        let entry = state.entries.entry(key).or_insert(LeaseEntry {
            active: 0,
            active_by_kind: [0; 5],
            delete_pending: false,
            generation,
            watches: 0,
        });
        entry.watches = entry
            .watches
            .checked_add(1)
            .ok_or(BlobLeaseAcquireError::Capacity)?;
        state.watches += 1;
        Ok(BlobLeaseSnapshot {
            registry: self.clone(),
            key,
            generation,
            consumed: false,
        })
    }

    /// Provisionally closes process-local acquisition for one exact target.
    ///
    /// The returned guard restores the exact target entry on drop until the
    /// caller confirms that the durable manifest transaction committed. The
    /// depot coordination lock must span snapshot, admission, commit, and
    /// confirmation, so there is never an acquisition window between the
    /// process-local fence and the durable authority.
    #[allow(dead_code)] // Consumed by exact manifest admission in Task 3.
    pub(crate) fn try_mark_delete_pending(
        &self,
        mut snapshot: BlobLeaseSnapshot,
    ) -> Result<BlobDeleteAdmissionGuard, BlobLeaseAcquireError> {
        if !Arc::ptr_eq(&self.inner, &snapshot.registry.inner) {
            return Err(BlobLeaseAcquireError::GenerationChanged);
        }
        let key = snapshot.key;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| BlobLeaseAcquireError::Poisoned)?;
        let current = state
            .entries
            .get(&key)
            .copied()
            .ok_or(BlobLeaseAcquireError::GenerationChanged)?;
        if current.generation != snapshot.generation || current.watches != 1 || state.watches != 1 {
            return Err(BlobLeaseAcquireError::GenerationChanged);
        }
        if current.active != 0 {
            return Err(BlobLeaseAcquireError::ActiveLeases);
        }
        if current.delete_pending {
            return Err(BlobLeaseAcquireError::DeletePending);
        }
        let generation = allocate_generation(&mut state)?;
        let mut before = current;
        before.watches -= 1;
        let entry = state
            .entries
            .get_mut(&key)
            .expect("validated watched entry remains under registry lock");
        entry.delete_pending = true;
        entry.generation = generation;
        snapshot.consumed = true;
        Ok(BlobDeleteAdmissionGuard {
            registry: self.clone(),
            key,
            before: Some(before),
            generation,
            durable: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn active_leases(&self, owner: [u8; 32], target: BlobLeaseTarget) -> usize {
        self.inner
            .state
            .lock()
            .expect("lease registry")
            .entries
            .get(&BlobLeaseKey { owner, target })
            .map_or(0, |entry| entry.active)
    }

    #[cfg(test)]
    pub(crate) fn active_leases_of_kind(
        &self,
        owner: [u8; 32],
        target: BlobLeaseTarget,
        kind: BlobLeaseKind,
    ) -> usize {
        let state = self.inner.state.lock().expect("lease registry");
        let Some(entry) = state.entries.get(&BlobLeaseKey { owner, target }) else {
            return 0;
        };
        entry.active_by_kind[kind.index()]
    }

    #[cfg(test)]
    fn total_active(&self) -> usize {
        let state = self.inner.state.lock().expect("lease registry");
        state.application_pages + state.network_sessions + state.blob_workers
    }

    #[cfg(test)]
    pub(crate) fn stored_entries(&self) -> usize {
        self.inner
            .state
            .lock()
            .expect("lease registry")
            .entries
            .len()
    }

    #[cfg(test)]
    pub(crate) fn active_watches(&self) -> usize {
        self.inner.state.lock().expect("lease registry").watches
    }
}

fn allocate_generation(
    state: &mut LeaseState,
) -> Result<BlobLeaseGeneration, BlobLeaseAcquireError> {
    state.next_generation = state
        .next_generation
        .checked_add(1)
        .ok_or(BlobLeaseAcquireError::GenerationExhausted)?;
    Ok(BlobLeaseGeneration(state.next_generation))
}

/// Exact-target comparison token retained across deletion-candidate checks.
#[derive(Debug)]
pub(crate) struct BlobLeaseSnapshot {
    registry: BlobLifecycleLeaseRegistry,
    key: BlobLeaseKey,
    generation: BlobLeaseGeneration,
    consumed: bool,
}

impl Drop for BlobLeaseSnapshot {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        let Ok(mut state) = self.registry.inner.state.lock() else {
            return;
        };
        if state.watches == 0 {
            return;
        }
        let remove = {
            let Some(entry) = state.entries.get_mut(&self.key) else {
                return;
            };
            if entry.watches == 0 {
                return;
            }
            entry.watches -= 1;
            entry.active == 0 && !entry.delete_pending && entry.watches == 0
        };
        state.watches -= 1;
        if remove {
            state.entries.remove(&self.key);
        }
    }
}

/// Reversible process-local half of durable deletion admission.
#[derive(Debug)]
pub(crate) struct BlobDeleteAdmissionGuard {
    registry: BlobLifecycleLeaseRegistry,
    key: BlobLeaseKey,
    before: Option<LeaseEntry>,
    #[allow(dead_code)] // Retained for admission diagnostics in the next increment.
    generation: BlobLeaseGeneration,
    durable: bool,
}

impl BlobDeleteAdmissionGuard {
    /// Hands authority to the already-committed durable manifest.
    #[allow(dead_code)] // Used by the Task 2 store race seam and Task 3 production admission.
    pub(crate) fn durable_committed(mut self) -> Result<(), BlobLeaseAcquireError> {
        let mut state = self
            .registry
            .inner
            .state
            .lock()
            .map_err(|_| BlobLeaseAcquireError::Poisoned)?;
        let pending = state.entries.get(&self.key).is_some_and(|entry| {
            entry.delete_pending
                && entry.active == 0
                && entry.active_by_kind == [0; 5]
                && entry.watches == 1
                && entry.generation == self.generation
        }) && state.watches == 1;
        if !pending {
            return Err(BlobLeaseAcquireError::GenerationChanged);
        }
        state.entries.remove(&self.key);
        state.watches -= 1;
        self.durable = true;
        Ok(())
    }
}

impl Drop for BlobDeleteAdmissionGuard {
    fn drop(&mut self) {
        if self.durable {
            return;
        }
        let Ok(mut state) = self.registry.inner.state.lock() else {
            // A poisoned registry fails closed for the remaining process. The
            // store cannot safely admit further deletion work in this state.
            return;
        };
        let pending = state.entries.get(&self.key).is_some_and(|entry| {
            entry.delete_pending
                && entry.active == 0
                && entry.active_by_kind == [0; 5]
                && entry.watches == 1
                && entry.generation == self.generation
        }) && state.watches == 1;
        if pending {
            let Some(mut before) = self.before else {
                return;
            };
            let Ok(generation) = allocate_generation(&mut state) else {
                // Exhaustion is fail-closed: retain both the provisional
                // deletion fence and its watch slot for this process.
                return;
            };
            if before.active != 0 || before.watches != 0 {
                before.generation = generation;
                state.entries.insert(self.key, before);
            } else {
                state.entries.remove(&self.key);
            }
            state.watches -= 1;
        }
    }
}

#[derive(Debug)]
pub(crate) struct BlobLeaseGuard {
    registry: BlobLifecycleLeaseRegistry,
    key: BlobLeaseKey,
    kind: BlobLeaseKind,
    #[allow(dead_code)] // Exposed to Task 3 admission/recheck diagnostics.
    generation: BlobLeaseGeneration,
    released: bool,
}

#[derive(Debug)]
pub(crate) struct BlobLeaseHandle {
    guard: Mutex<BlobLeaseGuard>,
}

impl BlobLeaseHandle {
    pub(crate) fn new(guard: BlobLeaseGuard) -> Self {
        Self {
            guard: Mutex::new(guard),
        }
    }

    pub(crate) fn target(&self) -> Result<BlobLeaseTarget, BlobLeaseAcquireError> {
        self.guard
            .lock()
            .map(|guard| guard.target())
            .map_err(|_| BlobLeaseAcquireError::Poisoned)
    }

    pub(crate) fn kind(&self) -> Result<BlobLeaseKind, BlobLeaseAcquireError> {
        self.guard
            .lock()
            .map(|guard| guard.kind())
            .map_err(|_| BlobLeaseAcquireError::Poisoned)
    }

    pub(crate) fn rebind_target(
        &self,
        target: BlobLeaseTarget,
    ) -> Result<(), BlobLeaseAcquireError> {
        self.guard
            .lock()
            .map_err(|_| BlobLeaseAcquireError::Poisoned)?
            .rebind_target(target)
    }
}

impl BlobLeaseGuard {
    #[allow(dead_code)] // Exposed to Task 3 admission/recheck diagnostics.
    pub(crate) const fn generation(&self) -> BlobLeaseGeneration {
        self.generation
    }

    pub(crate) const fn target(&self) -> BlobLeaseTarget {
        self.key.target
    }

    pub(crate) const fn kind(&self) -> BlobLeaseKind {
        self.kind
    }

    fn rebind_target(&mut self, target: BlobLeaseTarget) -> Result<(), BlobLeaseAcquireError> {
        if self.key.target == target {
            return Ok(());
        }
        if self.released || self.kind != BlobLeaseKind::LocalImport {
            return Err(BlobLeaseAcquireError::ActiveLeases);
        }
        let next_key = BlobLeaseKey {
            owner: self.key.owner,
            target,
        };
        let mut state = self
            .registry
            .inner
            .state
            .lock()
            .map_err(|_| BlobLeaseAcquireError::Poisoned)?;
        if state
            .entries
            .get(&next_key)
            .is_some_and(|entry| entry.delete_pending)
        {
            return Err(BlobLeaseAcquireError::DeletePending);
        }
        let old = state
            .entries
            .get(&self.key)
            .copied()
            .ok_or(BlobLeaseAcquireError::GenerationChanged)?;
        if old.delete_pending || old.active == 0 || old.active_by_kind[self.kind.index()] == 0 {
            return Err(BlobLeaseAcquireError::GenerationChanged);
        }
        let old_generation = allocate_generation(&mut state)?;
        let next_generation = allocate_generation(&mut state)?;
        let old = state
            .entries
            .get_mut(&self.key)
            .expect("validated lease entry remains under registry lock");
        old.active -= 1;
        old.active_by_kind[self.kind.index()] -= 1;
        old.generation = old_generation;
        if old.active == 0 && old.watches == 0 {
            state.entries.remove(&self.key);
        }
        let next = state.entries.entry(next_key).or_insert(LeaseEntry {
            active: 0,
            active_by_kind: [0; 5],
            delete_pending: false,
            generation: next_generation,
            watches: 0,
        });
        next.generation = next_generation;
        next.active = next
            .active
            .checked_add(1)
            .ok_or(BlobLeaseAcquireError::Capacity)?;
        next.active_by_kind[self.kind.index()] = next.active_by_kind[self.kind.index()]
            .checked_add(1)
            .ok_or(BlobLeaseAcquireError::Capacity)?;
        self.key = next_key;
        self.generation = next_generation;
        Ok(())
    }

    fn release(&mut self) {
        if self.released {
            return;
        }
        let Ok(mut state) = self.registry.inner.state.lock() else {
            // Poisoning is process-local only. The durable manifest remains the
            // authority after restart; leaking the slot fails closed in-process.
            return;
        };
        let Ok(generation) = allocate_generation(&mut state) else {
            // Generation exhaustion is fail-closed: retain the active entry
            // and its capacity slot for the remainder of this process.
            return;
        };
        let inactive = {
            let Some(entry) = state.entries.get_mut(&self.key) else {
                return;
            };
            if entry.active == 0 || entry.delete_pending {
                return;
            }
            entry.active -= 1;
            entry.active_by_kind[self.kind.index()] -= 1;
            entry.generation = generation;
            entry.active == 0 && entry.watches == 0
        };
        match self.kind {
            BlobLeaseKind::ApplicationPageRead => state.application_pages -= 1,
            BlobLeaseKind::CarrierRange | BlobLeaseKind::CarrierExtent => {
                state.network_sessions -= 1;
            }
            BlobLeaseKind::LocalImport | BlobLeaseKind::InternalChunkWork => {
                state.blob_workers -= 1;
            }
        }
        if inactive {
            state.entries.remove(&self.key);
        }
        self.released = true;
    }
}

impl Drop for BlobLeaseGuard {
    fn drop(&mut self) {
        self.release();
    }
}

type BlobStreamWriters = Mutex<HashSet<aster_mesh::BlobPublicationStreamId>>;
type BlobStreamWriterOwners = Mutex<HashMap<[u8; 32], Weak<BlobStreamWriters>>>;

static BLOB_STREAM_WRITER_OWNERS: OnceLock<BlobStreamWriterOwners> = OnceLock::new();

/// One exclusive writer per stream, shared by Store handles for the same
/// owner-bound database. Weak owner entries do not retain closed stores; a
/// session that outlives its Store keeps exclusion across a same-file reopen.
pub(crate) struct BlobStreamWriterLeaseRegistry {
    writers: Arc<BlobStreamWriters>,
}

impl BlobStreamWriterLeaseRegistry {
    pub(crate) fn for_owner(owner_binding: [u8; 32]) -> Result<Self, StoreError> {
        let mut owners = BLOB_STREAM_WRITER_OWNERS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| store_error(BlobLeaseAcquireError::Poisoned))?;
        owners.retain(|_, writers| writers.strong_count() != 0);
        let writers = match owners.get(&owner_binding).and_then(Weak::upgrade) {
            Some(writers) => writers,
            None => {
                let writers = Arc::new(Mutex::new(HashSet::new()));
                owners.insert(owner_binding, Arc::downgrade(&writers));
                writers
            }
        };
        Ok(Self { writers })
    }

    pub(crate) fn acquire(
        &self,
        stream_id: aster_mesh::BlobPublicationStreamId,
    ) -> Result<BlobStreamWriterLease, StoreError> {
        let mut writers = self
            .writers
            .lock()
            .map_err(|_| store_error(BlobLeaseAcquireError::Poisoned))?;
        if !writers.insert(stream_id) {
            return Err(store_error(BlobLeaseAcquireError::Capacity));
        }
        Ok(BlobStreamWriterLease {
            writers: Arc::clone(&self.writers),
            stream_id,
        })
    }
}

pub(crate) struct BlobStreamWriterLease {
    writers: Arc<BlobStreamWriters>,
    stream_id: aster_mesh::BlobPublicationStreamId,
}

impl BlobStreamWriterLease {
    pub(crate) fn require_registry(
        &self,
        registry: &BlobStreamWriterLeaseRegistry,
    ) -> Result<(), StoreError> {
        if !Arc::ptr_eq(&self.writers, &registry.writers) {
            return Err(StoreError::Blob(BlobStoreError::ReservationChanged));
        }
        Ok(())
    }
}

impl Drop for BlobStreamWriterLease {
    fn drop(&mut self) {
        let mut writers = self
            .writers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        writers.remove(&self.stream_id);
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;
    use crate::blob::{BlobTransferId, BlobVariantId};

    fn owner() -> [u8; 32] {
        [0x51; 32]
    }

    fn variant(seed: u8) -> BlobLeaseTarget {
        BlobLeaseTarget::Variant(BlobVariantId::from_bytes([seed; 32]))
    }

    fn staging(seed: u8) -> BlobLeaseTarget {
        BlobLeaseTarget::Staging(BlobTransferId::new([seed; 32]))
    }

    fn registry() -> BlobLifecycleLeaseRegistry {
        BlobLifecycleLeaseRegistry::new(
            BlobLeaseLimits::new(2, 2, 2).expect("bounded lease limits"),
        )
    }

    #[test]
    fn blob_lease_snapshot_blocks_manifest_admission_until_release() {
        let registry = registry();
        let target = variant(1);
        let lease = registry
            .acquire(owner(), target, BlobLeaseKind::InternalChunkWork)
            .expect("work lease");
        let active = registry.snapshot(owner(), target).expect("active snapshot");
        assert!(matches!(
            registry.try_mark_delete_pending(active),
            Err(BlobLeaseAcquireError::ActiveLeases)
        ));

        drop(lease);
        let released = registry
            .snapshot(owner(), target)
            .expect("released snapshot");
        let admission = registry
            .try_mark_delete_pending(released)
            .expect("deletion wins after release");
        assert!(matches!(
            registry.acquire(owner(), target, BlobLeaseKind::ApplicationPageRead),
            Err(BlobLeaseAcquireError::DeletePending)
        ));
        admission
            .durable_committed()
            .expect("durable authority replaces provisional fence");
    }

    #[test]
    fn blob_admission_and_delete_pending_race_has_exactly_one_winner() {
        let registry = registry();
        let target = variant(0x31);
        let snapshot = registry.snapshot(owner(), target).expect("snapshot");
        let start = Arc::new(std::sync::Barrier::new(3));
        let release = Arc::new(std::sync::Barrier::new(2));
        let (acquired_send, acquired_receive) = std::sync::mpsc::sync_channel(1);
        let (delete_send, delete_receive) = std::sync::mpsc::sync_channel(1);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                start.wait();
                let lease = registry.acquire(owner(), target, BlobLeaseKind::InternalChunkWork);
                acquired_send
                    .send(lease.is_ok())
                    .expect("report lease contender");
                if let Ok(lease) = lease {
                    release.wait();
                    drop(lease);
                }
            });
            scope.spawn(|| {
                start.wait();
                let result = registry.try_mark_delete_pending(snapshot);
                delete_send
                    .send(result.is_ok())
                    .expect("report deletion contender");
                if let Ok(admission) = result {
                    release.wait();
                    drop(admission);
                }
            });
            start.wait();
            let acquired = acquired_receive.recv().expect("lease result");
            let deleted = delete_receive.recv().expect("delete result");
            assert_ne!(acquired, deleted, "exactly one contender must win");
            if acquired || deleted {
                release.wait();
            }
        });
    }

    #[test]
    fn blob_lease_cancel_and_panic_release_capacity_and_entries() {
        let registry = registry();
        let target = variant(2);
        let cancelled = registry
            .acquire(owner(), target, BlobLeaseKind::LocalImport)
            .expect("cancelled lease");
        drop(cancelled);
        assert_eq!(registry.stored_entries(), 0);

        let unwind = catch_unwind(AssertUnwindSafe({
            let registry = registry.clone();
            move || {
                let _guard = registry
                    .acquire(owner(), target, BlobLeaseKind::LocalImport)
                    .expect("panic lease");
                panic!("simulated cancellation unwind");
            }
        }));
        assert!(unwind.is_err());
        assert_eq!(registry.active_leases(owner(), target), 0);
        assert_eq!(registry.stored_entries(), 0);
    }

    #[test]
    fn blob_lease_acquire_release_between_snapshot_and_admission_changes_generation() {
        let registry = registry();
        let target = variant(0x20);
        let before = registry.snapshot(owner(), target).expect("snapshot");

        drop(
            registry
                .acquire(owner(), target, BlobLeaseKind::InternalChunkWork)
                .expect("intervening lease"),
        );

        assert!(matches!(
            registry.try_mark_delete_pending(before),
            Err(BlobLeaseAcquireError::GenerationChanged)
        ));
    }

    #[test]
    fn blob_lease_rebind_into_watched_target_changes_exact_generation() {
        let registry = registry();
        let target = variant(0x24);
        let before = registry.snapshot(owner(), target).expect("target snapshot");
        let mut lease = registry
            .acquire(owner(), staging(0x25), BlobLeaseKind::LocalImport)
            .expect("staging lease");

        lease
            .rebind_target(target)
            .expect("rebind into exact watched variant");

        assert!(matches!(
            registry.try_mark_delete_pending(before),
            Err(BlobLeaseAcquireError::GenerationChanged)
        ));
        drop(lease);
        assert_eq!(registry.stored_entries(), 0);
    }

    #[test]
    fn blob_lease_snapshot_ignores_unrelated_activity() {
        let registry = registry();
        let target = variant(0x21);
        let before = registry.snapshot(owner(), target).expect("snapshot");

        let unrelated = registry
            .acquire(owner(), staging(0x22), BlobLeaseKind::CarrierRange)
            .expect("unrelated lease");
        drop(unrelated);
        let admission = registry
            .try_mark_delete_pending(before)
            .expect("unrelated churn cannot invalidate exact target");
        drop(admission);
    }

    #[test]
    fn blob_lease_registry_is_bounded_across_exact_variant_and_staging_targets() {
        let registry = BlobLifecycleLeaseRegistry::new(
            BlobLeaseLimits::new(1, 1, 1).expect("one lease per class"),
        );
        let page = registry
            .acquire(owner(), variant(3), BlobLeaseKind::ApplicationPageRead)
            .expect("application page");
        assert!(matches!(
            registry.acquire(owner(), variant(4), BlobLeaseKind::ApplicationPageRead),
            Err(BlobLeaseAcquireError::Capacity)
        ));
        let carrier = registry
            .acquire(owner(), staging(3), BlobLeaseKind::CarrierRange)
            .expect("carrier lease");
        let worker = registry
            .acquire(owner(), staging(4), BlobLeaseKind::InternalChunkWork)
            .expect("worker lease");
        assert_eq!(registry.total_active(), 3);
        drop((page, carrier, worker));
        assert_eq!(registry.total_active(), 0);
        assert_eq!(registry.stored_entries(), 0);
    }

    #[test]
    fn blob_stream_lifecycle_extent_shares_the_network_session_limit() {
        let registry = BlobLifecycleLeaseRegistry::new(
            BlobLeaseLimits::new(2, 1, 2).expect("one network session"),
        );
        let extent = registry
            .acquire(owner(), variant(0x31), BlobLeaseKind::CarrierExtent)
            .expect("profile-5 extent lease");
        assert!(matches!(
            registry.acquire(owner(), staging(0x32), BlobLeaseKind::CarrierRange),
            Err(BlobLeaseAcquireError::Capacity)
        ));
        drop(extent);
        let range = registry
            .acquire(owner(), staging(0x32), BlobLeaseKind::CarrierRange)
            .expect("profile-4 range after extent release");
        drop(range);
    }

    #[test]
    fn blob_lease_registry_does_not_retain_unique_inactive_targets() {
        let registry = registry();
        for seed in 0..10_000u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_be_bytes());
            drop(
                registry
                    .acquire(
                        owner(),
                        BlobLeaseTarget::Variant(BlobVariantId::from_bytes(bytes)),
                        BlobLeaseKind::ApplicationPageRead,
                    )
                    .expect("sequential bounded page lease"),
            );
        }
        assert_eq!(registry.total_active(), 0);
        assert_eq!(registry.stored_entries(), 0);
    }

    #[test]
    fn blob_delete_candidate_watch_stays_charged_through_provisional_admission() {
        let registry = registry();
        let active = registry
            .acquire(owner(), variant(0x60), BlobLeaseKind::ApplicationPageRead)
            .expect("unrelated active lease");
        let watched = registry
            .snapshot(owner(), variant(0x61))
            .expect("first exact watch");
        assert_eq!(registry.active_watches(), 1);
        let admission = registry
            .try_mark_delete_pending(watched)
            .expect("provisional admission");
        assert_eq!(registry.active_watches(), 1);
        assert!(registry.stored_entries() <= registry.total_active() + 1);
        assert!(matches!(
            registry.snapshot(owner(), variant(0x62)),
            Err(BlobLeaseAcquireError::Capacity)
        ));

        drop(admission);
        assert_eq!(registry.active_watches(), 0);
        assert_eq!(registry.stored_entries(), registry.total_active());
        let committed = registry
            .snapshot(owner(), variant(0x62))
            .and_then(|snapshot| registry.try_mark_delete_pending(snapshot))
            .expect("rollback releases watch slot");
        assert_eq!(registry.active_watches(), 1);
        committed
            .durable_committed()
            .expect("durable commit releases watch slot");
        assert_eq!(registry.active_watches(), 0);
        drop(active);
        assert_eq!(registry.stored_entries(), 0);
        drop(
            registry
                .snapshot(owner(), variant(0x63))
                .expect("commit releases watch slot"),
        );
        assert_eq!(registry.active_watches(), 0);
        assert_eq!(registry.stored_entries(), 0);
    }

    #[test]
    fn blob_delete_admission_drop_restores_target_before_image() {
        let registry = registry();
        let target = variant(0x23);
        let before = registry.snapshot(owner(), target).expect("snapshot");
        let admission = registry
            .try_mark_delete_pending(before)
            .expect("provisional admission");
        assert!(matches!(
            registry.acquire(owner(), target, BlobLeaseKind::ApplicationPageRead),
            Err(BlobLeaseAcquireError::DeletePending)
        ));
        drop(admission);
        assert_eq!(registry.stored_entries(), 0);
        drop(
            registry
                .acquire(owner(), target, BlobLeaseKind::ApplicationPageRead)
                .expect("rollback restores acquisition"),
        );
    }

    #[test]
    fn blob_lease_kind_counts_are_exact_per_target_and_class() {
        let registry = registry();
        let first = variant(0x41);
        let second = variant(0x42);
        let first_page = registry
            .acquire(owner(), first, BlobLeaseKind::ApplicationPageRead)
            .expect("first page");
        let second_page = registry
            .acquire(owner(), second, BlobLeaseKind::ApplicationPageRead)
            .expect("second page");

        assert_eq!(
            registry.active_leases_of_kind(owner(), first, BlobLeaseKind::ApplicationPageRead),
            1
        );
        assert_eq!(
            registry.active_leases_of_kind(owner(), second, BlobLeaseKind::ApplicationPageRead),
            1
        );
        assert_eq!(
            registry.active_leases_of_kind(owner(), first, BlobLeaseKind::CarrierRange),
            0
        );

        drop((first_page, second_page));
    }

    #[test]
    fn blob_import_lease_precedes_staging_and_survives_until_commit_or_cancel() {
        let registry = registry();
        let target = variant(5);
        let lease = registry
            .acquire(owner(), target, BlobLeaseKind::LocalImport)
            .expect("lease before durable staging");
        assert_eq!(registry.active_leases(owner(), target), 1);
        let during = registry.snapshot(owner(), target).expect("snapshot");
        assert!(matches!(
            registry.try_mark_delete_pending(during),
            Err(BlobLeaseAcquireError::ActiveLeases)
        ));
        drop(lease);
        assert_eq!(registry.active_leases(owner(), target), 0);
    }
}
