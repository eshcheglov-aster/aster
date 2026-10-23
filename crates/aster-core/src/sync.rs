//! Idempotent anti-entropy reducer and peer-neutral transfer checkpoints.
//!
//! The reducer owns protocol state, never sockets or storage.  Callers apply a
//! `SyncEvent`, perform returned `SyncAction`s, and acknowledge durable writes
//! with another event.  Pending (unacknowledged) writes are deliberately not
//! checkpointed; after a crash they are requested again.  Acknowledged byte
//! ranges and completed-chunk bitmaps are checkpointed without a peer address,
//! allowing a later contact with any peer to resume the object.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::inventory::{
    InventoryChild, InventoryError, InventoryNode, MAX_NIBBLES, NibblePrefix, SparseInventory,
};
use crate::model::ItemId;
use crate::wire::{
    self, ByteRange, ChildSummary, Data, Digest32, Interest, Limits, Message, Node, ObjectId,
    ObjectKind, Offer, Probe, Receipt, Summary, Value, Want, WantItem, WireError,
};

const SNAPSHOT_VERSION: u64 = 2;
const MAX_PROGRESS_RANGES: usize = 4_095;
const MAX_BITMAP_BYTES: usize = 1_048_576;
const MAX_ROOT_OFFER_HISTORY: usize = 8;

mod snapshot_key {
    pub const VERSION: u64 = 0;
    pub const REVISION: u64 = 1;
    pub const WANTS: u64 = 2;

    pub const WANT_ID: u64 = 0;
    pub const WANT_TOTAL: u64 = 1;
    pub const WANT_CHUNK_SIZE: u64 = 2;
    pub const WANT_RANGES: u64 = 3;
    pub const WANT_BITMAP: u64 = 4;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncError {
    Wire(WireError),
    Inventory(InventoryError),
    InvalidConfig(&'static str),
    NoActiveExchange,
    ExchangeMismatch { expected: u64, received: u64 },
    SnapshotMismatch,
    TotalLengthMismatch { expected: u64, received: u64 },
    UnsolicitedData(ObjectId),
    InvalidStoreExtent,
    ProgressTooFragmented,
    ProgressTooLarge,
    WantLimit,
    OfferLimit,
    ProbeLimit,
    InventoryNotSelected(InventoryPurpose),
    InventorySelectionMismatch,
    BitmapMismatch,
    InvalidSnapshot(&'static str),
    RevisionExhausted,
    SemanticVersionChanged { expected: u16, received: u16 },
}

impl From<WireError> for SyncError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<InventoryError> for SyncError {
    fn from(value: InventoryError) -> Self {
        Self::Inventory(value)
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SyncError {}

const DEFAULT_MAX_OFFER_IDS: usize = 256;
const MAX_OFFER_IDS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncConfig {
    /// Maximum identifiers per OFFER message, not per reconciliation.
    pub max_offer_ids: usize,
    /// Maximum object requests per WANT message.
    pub max_want_items: usize,
    /// Unit used by the durable completed-chunk bitmap.
    pub progress_chunk_size: u32,
    /// Hard bound on peer-neutral pending objects.
    pub max_durable_wants: usize,
    /// Hard bound on one contact's in-memory Merkle walk.
    pub max_probe_nodes: usize,
    /// If false, DATA must be preceded by a durable want.
    pub accept_unsolicited_data: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_offer_ids: DEFAULT_MAX_OFFER_IDS,
            max_want_items: 128,
            progress_chunk_size: 64 * 1024,
            max_durable_wants: 10_000,
            max_probe_nodes: 65_536,
            accept_unsolicited_data: false,
        }
    }
}

impl SyncConfig {
    pub fn validate(&self) -> Result<(), SyncError> {
        if self.max_offer_ids == 0 || self.max_offer_ids > MAX_OFFER_IDS {
            return Err(SyncError::InvalidConfig("maximum offer identifiers"));
        }
        if self.max_want_items == 0 || self.max_want_items > 4_096 {
            return Err(SyncError::InvalidConfig("maximum want items"));
        }
        if self.progress_chunk_size == 0 {
            return Err(SyncError::InvalidConfig("progress chunk size"));
        }
        if self.max_durable_wants == 0 {
            return Err(SyncError::InvalidConfig("maximum durable wants"));
        }
        if self.max_probe_nodes == 0 {
            return Err(SyncError::InvalidConfig("maximum probe nodes"));
        }
        Ok(())
    }
}

/// Retained authorization and subscription selector for one reconciliation
/// direction.  It is the only input from which an inventory view may be built.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InterestFilter {
    pub topics: Vec<String>,
    pub scopes: Vec<String>,
    pub min_priority: u8,
}

impl InterestFilter {
    fn from_interest(interest: &Interest) -> Self {
        Self {
            topics: interest.topics.clone(),
            scopes: interest.scopes.clone(),
            min_priority: interest.min_priority,
        }
    }
}

/// The two independently filtered directions of a full-duplex contact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InventoryPurpose {
    /// Our existing authorized baseline for the interest we sent.
    ReceiveBaseline,
    /// Envelopes the authenticated peer is authorized to learn about.
    ServePeer,
}

/// Durable progress for one immutable object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WantProgress {
    total_len: Option<u64>,
    chunk_size: u32,
    received: Vec<ByteRange>,
}

impl WantProgress {
    pub fn new(chunk_size: u32) -> Result<Self, SyncError> {
        if chunk_size == 0 {
            return Err(SyncError::InvalidConfig("progress chunk size"));
        }
        Ok(Self {
            total_len: None,
            chunk_size,
            received: Vec::new(),
        })
    }

    pub fn total_len(&self) -> Option<u64> {
        self.total_len
    }

    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub fn received_ranges(&self) -> &[ByteRange] {
        &self.received
    }

    pub fn set_total_len(&mut self, total_len: u64) -> Result<bool, SyncError> {
        match self.total_len {
            Some(expected) if expected != total_len => Err(SyncError::TotalLengthMismatch {
                expected,
                received: total_len,
            }),
            Some(_) => Ok(false),
            None => {
                self.total_len = Some(total_len);
                Ok(true)
            }
        }
    }

    pub fn mark_received(&mut self, range: ByteRange) -> Result<bool, SyncError> {
        let total = self
            .total_len
            .ok_or(SyncError::InvalidSnapshot("range without total length"))?;
        if range.start >= range.end || range.end > total {
            return Err(SyncError::InvalidStoreExtent);
        }
        if range_is_covered(&self.received, range) {
            return Ok(false);
        }
        let merged = insert_range(&self.received, range);
        if merged.len() > MAX_PROGRESS_RANGES {
            return Err(SyncError::ProgressTooFragmented);
        }
        self.received = merged;
        Ok(true)
    }

    pub fn is_complete(&self) -> bool {
        match self.total_len {
            Some(0) => true,
            Some(total) => {
                self.received.len() == 1
                    && self.received[0].start == 0
                    && self.received[0].end == total
            }
            None => false,
        }
    }

    pub fn missing_ranges(&self) -> Vec<ByteRange> {
        let Some(total) = self.total_len else {
            return Vec::new();
        };
        let mut missing = Vec::new();
        let mut cursor = 0_u64;
        for received in &self.received {
            if cursor < received.start {
                missing.push(ByteRange {
                    start: cursor,
                    end: received.start,
                });
            }
            cursor = received.end;
        }
        if cursor < total {
            missing.push(ByteRange {
                start: cursor,
                end: total,
            });
        }
        missing
    }

    /// MSB-first bitmap.  Bit `n` is one only when the entire logical chunk is
    /// durably present.  Exact partial coverage remains in `received_ranges`.
    pub fn completed_bitmap(&self) -> Result<Vec<u8>, SyncError> {
        let Some(total) = self.total_len else {
            return Ok(Vec::new());
        };
        if total == 0 {
            return Ok(Vec::new());
        }
        let unit = u64::from(self.chunk_size);
        let chunks = total / unit + u64::from(total % unit != 0);
        let byte_count = chunks / 8 + u64::from(chunks % 8 != 0);
        let byte_count = usize::try_from(byte_count).map_err(|_| SyncError::ProgressTooLarge)?;
        if byte_count > MAX_BITMAP_BYTES {
            return Err(SyncError::ProgressTooLarge);
        }
        let mut bitmap = vec![0_u8; byte_count];
        for chunk in 0..chunks {
            let start = chunk.checked_mul(unit).ok_or(SyncError::ProgressTooLarge)?;
            let end = start.saturating_add(unit).min(total);
            if range_is_covered(&self.received, ByteRange { start, end }) {
                let index = usize::try_from(chunk).map_err(|_| SyncError::ProgressTooLarge)?;
                bitmap[index / 8] |= 0x80 >> (index % 8);
            }
        }
        Ok(bitmap)
    }

    fn to_want_item(&self, object_id: ObjectId, need_forwarding: bool) -> WantItem {
        WantItem {
            object_id,
            total_len: self.total_len,
            missing: self.missing_ranges(),
            need_forwarding,
        }
    }
}

/// Peer-neutral durable object requests.  No session, transport, or peer
/// identifier is stored here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DurableWants {
    entries: BTreeMap<ObjectId, WantProgress>,
}

impl DurableWants {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&mut self, id: ObjectId, chunk_size: u32) -> Result<bool, SyncError> {
        if self.entries.contains_key(&id) {
            return Ok(false);
        }
        self.entries.insert(id, WantProgress::new(chunk_size)?);
        Ok(true)
    }

    pub fn remove(&mut self, id: &ObjectId) -> Option<WantProgress> {
        self.entries.remove(id)
    }

    pub fn get(&self, id: &ObjectId) -> Option<&WantProgress> {
        self.entries.get(id)
    }

    pub fn get_mut(&mut self, id: &ObjectId) -> Option<&mut WantProgress> {
        self.entries.get_mut(id)
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        self.entries.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ObjectId, &WantProgress)> {
        self.entries.iter()
    }

    fn wire_items(&self) -> Vec<WantItem> {
        self.entries
            .iter()
            .map(|(id, progress)| {
                progress.to_want_item(*id, id.kind().supports_forwarding_metadata())
            })
            .collect()
    }
}

/// Crash-safe serialization unit.  Restoring it discards peer/session state
/// and unacknowledged writes while preserving every durable range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncSnapshot {
    pub revision: u64,
    pub wants: DurableWants,
}

impl SyncSnapshot {
    pub fn encode(&self, limits: Limits) -> Result<Vec<u8>, SyncError> {
        let mut wants = Vec::with_capacity(self.wants.len());
        for (id, progress) in self.wants.iter() {
            let ranges = Value::Array(
                progress
                    .received_ranges()
                    .iter()
                    .map(|range| {
                        Value::Array(vec![
                            Value::Unsigned(range.start),
                            Value::Unsigned(range.end),
                        ])
                    })
                    .collect(),
            );
            wants.push(Value::Map(vec![
                (
                    snapshot_key::WANT_ID,
                    Value::Bytes(id.to_wire_bytes().to_vec()),
                ),
                (
                    snapshot_key::WANT_TOTAL,
                    progress
                        .total_len()
                        .map(Value::Unsigned)
                        .unwrap_or(Value::Null),
                ),
                (
                    snapshot_key::WANT_CHUNK_SIZE,
                    Value::Unsigned(u64::from(progress.chunk_size())),
                ),
                (snapshot_key::WANT_RANGES, ranges),
                (
                    snapshot_key::WANT_BITMAP,
                    Value::Bytes(progress.completed_bitmap()?),
                ),
            ]));
        }
        Ok(wire::encode_value(
            &Value::Map(vec![
                (snapshot_key::VERSION, Value::Unsigned(SNAPSHOT_VERSION)),
                (snapshot_key::REVISION, Value::Unsigned(self.revision)),
                (snapshot_key::WANTS, Value::Array(wants)),
            ]),
            limits,
        )?)
    }

    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self, SyncError> {
        let value = wire::decode_value(bytes, limits)?;
        let map = snapshot_map(&value)?;
        snapshot_keys(map, &[0, 1, 2])?;
        let version = snapshot_unsigned(snapshot_required(map, snapshot_key::VERSION)?)?;
        if version != SNAPSHOT_VERSION {
            return Err(SyncError::InvalidSnapshot("version"));
        }
        let revision = snapshot_unsigned(snapshot_required(map, snapshot_key::REVISION)?)?;
        let values = snapshot_array(snapshot_required(map, snapshot_key::WANTS)?)?;
        let mut entries = BTreeMap::new();
        for value in values {
            let want = snapshot_map(value)?;
            snapshot_keys(want, &[0, 1, 2, 3, 4])?;
            let id: ObjectId = match snapshot_required(want, snapshot_key::WANT_ID)? {
                Value::Bytes(bytes) => ObjectId::from_wire_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| SyncError::InvalidSnapshot("object identifier"))?,
                )
                .ok_or(SyncError::InvalidSnapshot("object kind"))?,
                _ => return Err(SyncError::InvalidSnapshot("object identifier type")),
            };
            let total_len = match snapshot_required(want, snapshot_key::WANT_TOTAL)? {
                Value::Null => None,
                value => Some(snapshot_unsigned(value)?),
            };
            let chunk_size = u32::try_from(snapshot_unsigned(snapshot_required(
                want,
                snapshot_key::WANT_CHUNK_SIZE,
            )?)?)
            .map_err(|_| SyncError::InvalidSnapshot("chunk size"))?;
            if chunk_size == 0 {
                return Err(SyncError::InvalidSnapshot("chunk size"));
            }
            let mut ranges = Vec::new();
            for value in snapshot_array(snapshot_required(want, snapshot_key::WANT_RANGES)?)? {
                let pair = snapshot_array(value)?;
                if pair.len() != 2 {
                    return Err(SyncError::InvalidSnapshot("range arity"));
                }
                ranges.push(ByteRange {
                    start: snapshot_unsigned(&pair[0])?,
                    end: snapshot_unsigned(&pair[1])?,
                });
            }
            if ranges.len() > MAX_PROGRESS_RANGES {
                return Err(SyncError::ProgressTooFragmented);
            }
            wire::validate_ranges(&ranges, total_len)?;
            if total_len.is_none() && !ranges.is_empty() {
                return Err(SyncError::InvalidSnapshot("ranges without total"));
            }
            let bitmap = match snapshot_required(want, snapshot_key::WANT_BITMAP)? {
                Value::Bytes(bytes) => bytes,
                _ => return Err(SyncError::InvalidSnapshot("bitmap type")),
            };
            let progress = WantProgress {
                total_len,
                chunk_size,
                received: ranges,
            };
            if progress.completed_bitmap()?.as_slice() != bitmap.as_slice() {
                return Err(SyncError::BitmapMismatch);
            }
            if entries.insert(id, progress).is_some() {
                return Err(SyncError::InvalidSnapshot("duplicate want"));
            }
        }
        Ok(Self {
            revision,
            wants: DurableWants { entries },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncEvent {
    Start {
        exchange_id: u64,
        topics: Vec<String>,
        scopes: Vec<String>,
        min_priority: u8,
    },
    Receive(Message),
    /// Result of an authenticated, policy-filtered engine query requested by
    /// `SelectInventory`.  Supplying an unrequested or differently filtered
    /// view is rejected.
    InventorySelected {
        exchange_id: u64,
        request_id: u64,
        purpose: InventoryPurpose,
        filter: InterestFilter,
        inventory: SparseInventory,
    },
    /// The storage layer has atomically persisted this exact extent.
    ChunkStored {
        object_id: ObjectId,
        total_len: u64,
        range: ByteRange,
    },
    /// A pending storage action failed and may be requested again.
    ChunkStoreFailed {
        object_id: ObjectId,
        range: ByteRange,
    },
    /// Kind-specific verification and atomic backend commit succeeded.
    ObjectCommitted {
        object_id: ObjectId,
        /// Source data envelopes carry a semantic item identity. Controls and
        /// Blob chunk carriers do not.
        item_id: Option<ItemId>,
    },
    /// The complete object was moved from unauthenticated transfer staging into
    /// a bounded, durable dependency-pending area. It is deliberately absent
    /// from inventory and application state until the backend later promotes
    /// it after every exact dependency authenticates.
    ObjectDeferred {
        object_id: ObjectId,
        dependencies: Vec<ObjectId>,
    },
    /// The complete exact carrier is durably isolated without trusted semantic
    /// metadata because no authenticated dependency currently identifies it.
    /// It is absent from inventory and application state, and transport
    /// staging can be retired without inventing a dependency identifier.
    ObjectQuarantined {
        object_id: ObjectId,
    },
    /// Terminal identity, route, or source-authentication failure. Durable
    /// staging has already been atomically discarded, so reset the peer-neutral
    /// request to unknown length with no acknowledged ranges.
    ObjectRejected {
        object_id: ObjectId,
    },
    /// Notification for an object produced or learned outside this reducer.
    LocalObjectAdded {
        object_id: ObjectId,
    },
    LocalObjectRemoved {
        object_id: ObjectId,
    },
    /// Durable local state or authorization changed outside this reducer. The
    /// backend remains authoritative for object membership, so invalidate both
    /// selected views and request fresh authenticated selections without
    /// inventing an object identity.
    LocalInventoryChanged,
    /// A durable peer acknowledgement changed only the representation-specific
    /// inventory that this contact may serve. Preserve the independently
    /// authorized receive baseline and its live Merkle traversal.
    ServeInventoryChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncAction {
    Send(Message),
    /// Ask the authenticated runtime/engine boundary for an authorized view.
    /// No SUMMARY or NODE can be produced until this action is satisfied.
    SelectInventory {
        request_id: u64,
        purpose: InventoryPurpose,
        filter: InterestFilter,
    },
    /// Persist bytes before reporting `ChunkStored`.  Bytes never enter a
    /// checkpoint until that acknowledgement arrives.
    StoreChunk {
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Read the requested immutable object/ranges and emit DATA externally.
    Serve(WantItem),
    /// Verify and atomically commit one complete typed transfer object.
    CompleteObject {
        object_id: ObjectId,
        total_len: u64,
        /// Present only for a source envelope, where it is separately bound to
        /// this adjacency and exchange. Blob carriers rely on their
        /// source-authenticated route commitment and carry no hop wrapper.
        forwarding: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExchangeState {
    id: u64,
    local_interest: Option<InterestFilter>,
    peer_interest: Option<InterestFilter>,
    peer_max_offers: Option<u32>,
    selection_requested: BTreeMap<InventoryPurpose, u64>,
    pending_summary: Option<Summary>,
    remote_snapshot: Option<(Digest32, u64)>,
    pending_root_probe: Option<RootProbeExpectation>,
    /// Recently issued root probes and whether their complete response was
    /// validated. The retained filter prevents a late response from crossing
    /// an interest-policy change.
    root_offer_history: Vec<RootOfferRecord>,
    probes_sent: BTreeSet<(u64, NibblePrefix)>,
    expected_nodes: BTreeMap<(u64, NibblePrefix), (Digest32, u64)>,
    summary_sent: Option<(Digest32, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootProbeExpectation {
    snapshot_id: u64,
    root_hash: Digest32,
    item_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RootOfferRecord {
    expectation: RootProbeExpectation,
    filter: InterestFilter,
    validated: bool,
}

impl ExchangeState {
    fn new(id: u64) -> Self {
        Self {
            id,
            local_interest: None,
            peer_interest: None,
            peer_max_offers: None,
            selection_requested: BTreeMap::new(),
            pending_summary: None,
            remote_snapshot: None,
            pending_root_probe: None,
            root_offer_history: Vec::new(),
            probes_sent: BTreeSet::new(),
            expected_nodes: BTreeMap::new(),
            summary_sent: None,
        }
    }
}

/// Deterministic reducer state.  Equality is intentionally observable in
/// tests: duplicate and reordered events must converge to the same state.
#[derive(Clone)]
pub struct SyncState {
    config: SyncConfig,
    inventory: SparseInventory,
    wants: DurableWants,
    durable_revision: u64,
    next_selection_id: u64,
    active: Option<ExchangeState>,
    receive_inventory: Option<SparseInventory>,
    serve_inventory: Option<SparseInventory>,
    pending_writes: BTreeMap<ObjectId, Vec<ByteRange>>,
    forwarding: BTreeMap<ObjectId, Vec<u8>>,
    commit_pending: BTreeSet<ObjectId>,
    semantic_version: u16,
}

impl SyncState {
    pub fn new(config: SyncConfig, inventory: SparseInventory) -> Result<Self, SyncError> {
        config.validate()?;
        Ok(Self {
            config,
            inventory,
            wants: DurableWants::new(),
            durable_revision: 0,
            next_selection_id: 1,
            active: None,
            receive_inventory: None,
            serve_inventory: None,
            pending_writes: BTreeMap::new(),
            forwarding: BTreeMap::new(),
            commit_pending: BTreeSet::new(),
            semantic_version: wire::SEMANTIC_PROTOCOL_V1,
        })
    }

    pub fn restore(
        config: SyncConfig,
        inventory: SparseInventory,
        snapshot: SyncSnapshot,
    ) -> Result<Self, SyncError> {
        config.validate()?;
        if snapshot.wants.len() > config.max_durable_wants {
            return Err(SyncError::WantLimit);
        }
        Ok(Self {
            config,
            inventory,
            wants: snapshot.wants,
            durable_revision: snapshot.revision,
            next_selection_id: 1,
            active: None,
            receive_inventory: None,
            serve_inventory: None,
            pending_writes: BTreeMap::new(),
            forwarding: BTreeMap::new(),
            commit_pending: BTreeSet::new(),
            semantic_version: wire::SEMANTIC_PROTOCOL_V1,
        })
    }

    pub fn snapshot(&self) -> SyncSnapshot {
        SyncSnapshot {
            revision: self.durable_revision,
            wants: self.wants.clone(),
        }
    }

    pub fn inventory(&self) -> &SparseInventory {
        &self.inventory
    }

    #[cfg(test)]
    pub(crate) fn selected_serve_inventory(&self) -> Option<&SparseInventory> {
        self.serve_inventory.as_ref()
    }

    pub fn wants(&self) -> &DurableWants {
        &self.wants
    }

    /// Rebuilds the current peer-neutral request for one incomplete object.
    /// Runtime retry logic calls this at the retry deadline so already durable
    /// ranges are never requested merely because an older WANT was retained.
    pub(crate) fn retry_want_item(&self, object_id: ObjectId) -> Option<WantItem> {
        if !object_id
            .kind()
            .is_allowed_in_semantic_version(self.semantic_version)
        {
            return None;
        }
        self.wants.get(&object_id).and_then(|progress| {
            let need_forwarding = object_id.kind().supports_forwarding_metadata()
                && !self.forwarding.contains_key(&object_id);
            let item = progress.to_want_item(object_id, need_forwarding);
            (item.total_len.is_none() || !item.missing.is_empty() || item.need_forwarding)
                .then_some(item)
        })
    }

    pub fn durable_revision(&self) -> u64 {
        self.durable_revision
    }

    pub fn active_exchange_id(&self) -> Option<u64> {
        self.active.as_ref().map(|exchange| exchange.id)
    }

    pub(crate) fn local_min_priority(&self) -> Option<u8> {
        self.active
            .as_ref()
            .and_then(|exchange| exchange.local_interest.as_ref())
            .map(|filter| filter.min_priority)
    }

    pub fn max_durable_wants(&self) -> usize {
        self.config.max_durable_wants
    }

    /// Hydrates exact ranges already acknowledged by durable storage. This is
    /// intentionally independent of a reducer snapshot so a brand-new runtime
    /// can recover after process loss from the storage authority itself.
    pub fn hydrate_durable_progress(
        &mut self,
        entries: impl IntoIterator<Item = (ObjectId, u64, Vec<ByteRange>)>,
    ) -> Result<(), SyncError> {
        self.hydrate_durable_progress_for_semantic_version(entries, wire::SEMANTIC_PROTOCOL_V1)
    }

    pub(crate) fn hydrate_durable_progress_for_semantic_version(
        &mut self,
        entries: impl IntoIterator<Item = (ObjectId, u64, Vec<ByteRange>)>,
        semantic_version: u16,
    ) -> Result<(), SyncError> {
        wire::validate_semantic_version(semantic_version)?;
        if self.active.is_some() {
            return Err(SyncError::InvalidSnapshot(
                "durable progress hydration during active exchange",
            ));
        }
        for (object_id, total_len, ranges) in entries {
            if !object_id
                .kind()
                .is_allowed_in_semantic_version(semantic_version)
            {
                continue;
            }
            if self.inventory.contains(&object_id) {
                continue;
            }
            if !self.wants.contains(&object_id) {
                if self.wants.len() >= self.config.max_durable_wants {
                    return Err(SyncError::WantLimit);
                }
                self.wants
                    .request(object_id, self.config.progress_chunk_size)?;
            }
            let progress = self
                .wants
                .get_mut(&object_id)
                .ok_or(SyncError::InvalidSnapshot("hydrated want missing"))?;
            progress.set_total_len(total_len)?;
            for range in ranges {
                progress.mark_received(range)?;
            }
        }
        Ok(())
    }

    pub fn apply(&mut self, event: SyncEvent) -> Result<Vec<SyncAction>, SyncError> {
        self.apply_for_semantic_version(event, self.semantic_version)
    }

    pub(crate) fn apply_for_semantic_version(
        &mut self,
        event: SyncEvent,
        semantic_version: u16,
    ) -> Result<Vec<SyncAction>, SyncError> {
        validate_event_for_semantic_version(&event, semantic_version)?;
        if self.active.is_some() && self.semantic_version != semantic_version {
            return Err(SyncError::SemanticVersionChanged {
                expected: self.semantic_version,
                received: semantic_version,
            });
        }
        self.semantic_version = semantic_version;
        match event {
            SyncEvent::Start {
                exchange_id,
                topics,
                scopes,
                min_priority,
            } => self.start(exchange_id, topics, scopes, min_priority),
            SyncEvent::Receive(message) => self.receive(message),
            SyncEvent::InventorySelected {
                exchange_id,
                request_id,
                purpose,
                filter,
                inventory,
            } => self.inventory_selected(exchange_id, request_id, purpose, filter, inventory),
            SyncEvent::ChunkStored {
                object_id,
                total_len,
                range,
            } => self.chunk_stored(object_id, total_len, range),
            SyncEvent::ChunkStoreFailed { object_id, range } => {
                self.chunk_store_failed(object_id, range)
            }
            SyncEvent::ObjectCommitted { object_id, item_id } => {
                self.object_committed(object_id, item_id)
            }
            SyncEvent::ObjectDeferred {
                object_id,
                dependencies,
            } => self.object_deferred(object_id, dependencies),
            SyncEvent::ObjectQuarantined { object_id } => self.object_quarantined(object_id),
            SyncEvent::ObjectRejected { object_id } => self.object_rejected(object_id),
            SyncEvent::LocalObjectAdded { object_id } => self.local_added(object_id),
            SyncEvent::LocalObjectRemoved { object_id } => self.local_removed(object_id),
            SyncEvent::LocalInventoryChanged => self.inventory_changed(),
            SyncEvent::ServeInventoryChanged => self.serve_inventory_changed(),
        }
    }

    fn start(
        &mut self,
        exchange_id: u64,
        topics: Vec<String>,
        scopes: Vec<String>,
        min_priority: u8,
    ) -> Result<Vec<SyncAction>, SyncError> {
        let interest = Interest {
            exchange_id,
            topics,
            scopes,
            min_priority,
            max_offers: u32::try_from(self.config.max_offer_ids)
                .map_err(|_| SyncError::InvalidConfig("maximum offer identifiers"))?,
        };
        let message = Message::Interest(interest.clone());
        validate_outbound(&message, self.semantic_version)?;
        let filter = InterestFilter::from_interest(&interest);

        self.receive_inventory = None;
        self.forwarding.clear();
        self.commit_pending.clear();
        if self.active.as_ref().map(|exchange| exchange.id) == Some(exchange_id) {
            // Joining an exchange that the peer already opened must retain the
            // independent serve direction, including its pending authorized
            // inventory selection. Only our receive direction is restarted.
            let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
            let filter_changed = exchange.local_interest.as_ref() != Some(&filter);
            if filter_changed {
                exchange
                    .root_offer_history
                    .retain(|record| record.validated);
            }
            exchange.local_interest = Some(filter.clone());
            exchange.pending_summary = None;
            exchange.remote_snapshot = None;
            exchange.pending_root_probe = None;
            exchange.probes_sent.clear();
            exchange.expected_nodes.clear();
            exchange
                .selection_requested
                .remove(&InventoryPurpose::ReceiveBaseline);
        } else {
            self.serve_inventory = None;
            let mut exchange = ExchangeState::new(exchange_id);
            exchange.local_interest = Some(filter.clone());
            self.active = Some(exchange);
        }
        let mut actions = vec![SyncAction::Send(message)];
        self.push_selection(InventoryPurpose::ReceiveBaseline, filter, &mut actions)?;
        self.push_resume_actions(&mut actions);
        Ok(actions)
    }

    fn receive(&mut self, message: Message) -> Result<Vec<SyncAction>, SyncError> {
        // Constructed messages receive the same validation as decoded bytes.
        validate_outbound(&message, self.semantic_version)?;
        if let Message::Interest(interest) = &message {
            if self.active.as_ref().map(|exchange| exchange.id) != Some(interest.exchange_id) {
                self.active = Some(ExchangeState::new(interest.exchange_id));
                self.receive_inventory = None;
                self.serve_inventory = None;
            }
        } else {
            self.ensure_exchange(message.exchange_id())?;
        }

        let mut actions = Vec::new();
        match message {
            Message::Interest(interest) => {
                let peer_max_offers = interest.max_offers;
                let filter = InterestFilter::from_interest(&interest);
                let changed = self
                    .active
                    .as_ref()
                    .and_then(|exchange| exchange.peer_interest.as_ref())
                    != Some(&filter);
                if changed {
                    self.serve_inventory = None;
                    let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
                    exchange.peer_interest = Some(filter.clone());
                    exchange.summary_sent = None;
                    exchange
                        .selection_requested
                        .remove(&InventoryPurpose::ServePeer);
                }
                self.active
                    .as_mut()
                    .ok_or(SyncError::NoActiveExchange)?
                    .peer_max_offers = Some(peer_max_offers);
                self.push_selection(InventoryPurpose::ServePeer, filter, &mut actions)?;
                if !changed && self.serve_inventory.is_some() {
                    self.push_summary(&mut actions, true)?;
                }
            }
            Message::Summary(summary) => self.receive_summary(summary, &mut actions)?,
            Message::Probe(probe) => self.receive_probe(probe, &mut actions)?,
            Message::Node(node) => self.receive_node(node, &mut actions)?,
            Message::Offer(offer) => self.receive_offer(offer, &mut actions)?,
            Message::Want(want) => {
                // Durable progress is intentionally peer-neutral, so a fresh
                // contact may optimistically ask this node for an object it
                // never advertised. Serve only from the current authenticated,
                // policy-filtered view. Silence leaves the requester's bounded
                // WANT retryable here or through a different peer.
                if let Some(inventory) = &self.serve_inventory {
                    for item in want.items {
                        if inventory.contains(&item.object_id) {
                            actions.push(SyncAction::Serve(item));
                        }
                    }
                }
            }
            Message::Data(data) => self.receive_data(data, &mut actions)?,
            Message::Receipt(_) => {
                // Receipts are advisory for send scheduling.  Replaying one
                // cannot mutate the receiver's durable truth.
            }
        }
        Ok(actions)
    }

    fn inventory_selected(
        &mut self,
        exchange_id: u64,
        request_id: u64,
        purpose: InventoryPurpose,
        filter: InterestFilter,
        inventory: SparseInventory,
    ) -> Result<Vec<SyncAction>, SyncError> {
        self.ensure_exchange(exchange_id)?;
        let expected = match purpose {
            InventoryPurpose::ReceiveBaseline => self
                .active
                .as_ref()
                .and_then(|exchange| exchange.local_interest.as_ref()),
            InventoryPurpose::ServePeer => self
                .active
                .as_ref()
                .and_then(|exchange| exchange.peer_interest.as_ref()),
        };
        if expected != Some(&filter)
            || self
                .active
                .as_ref()
                .and_then(|exchange| exchange.selection_requested.get(&purpose))
                != Some(&request_id)
        {
            return Err(SyncError::InventorySelectionMismatch);
        }
        self.active
            .as_mut()
            .ok_or(SyncError::NoActiveExchange)?
            .selection_requested
            .remove(&purpose);

        let mut actions = Vec::new();
        match purpose {
            InventoryPurpose::ReceiveBaseline => {
                self.receive_inventory = Some(inventory);
                let (pending, resume) = {
                    let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
                    let pending = exchange.pending_summary.take();
                    let resume = pending.is_none().then(|| {
                        exchange
                            .root_offer_history
                            .iter()
                            .rev()
                            .find(|record| !record.validated && record.filter == filter)
                            .map(|record| record.expectation)
                    });
                    (pending, resume.flatten())
                };
                if let Some(summary) = pending {
                    self.receive_summary(summary, &mut actions)?;
                } else if let Some(expectation) = resume {
                    // A refresh retired the live traversal, but an exact root
                    // response may already be in flight. Reissue only the
                    // newest unanswered commitment after the backend has
                    // selected a fresh authorized baseline. This restores the
                    // full active-response checks; history alone never admits
                    // new durable work.
                    self.active
                        .as_mut()
                        .ok_or(SyncError::NoActiveExchange)?
                        .remote_snapshot = Some((expectation.root_hash, expectation.snapshot_id));
                    self.push_probe(
                        NibblePrefix::root(),
                        expectation.snapshot_id,
                        expectation.root_hash,
                        expectation.item_count,
                        &mut actions,
                    )?;
                }
            }
            InventoryPurpose::ServePeer => {
                self.serve_inventory = Some(inventory);
                self.active
                    .as_mut()
                    .ok_or(SyncError::NoActiveExchange)?
                    .summary_sent = None;
                self.push_summary(&mut actions, false)?;
            }
        }
        Ok(actions)
    }

    fn receive_summary(
        &mut self,
        summary: Summary,
        actions: &mut Vec<SyncAction>,
    ) -> Result<(), SyncError> {
        if self.receive_inventory.is_none() {
            self.active
                .as_mut()
                .ok_or(SyncError::NoActiveExchange)?
                .pending_summary = Some(summary);
            return Ok(());
        }
        let remote = (summary.root_hash, summary.snapshot_id);
        let changed = self
            .active
            .as_ref()
            .and_then(|exchange| exchange.remote_snapshot)
            != Some(remote);
        if changed {
            let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
            let replacement = RootProbeExpectation {
                snapshot_id: summary.snapshot_id,
                root_hash: summary.root_hash,
                item_count: summary.item_count,
            };
            if let Some(filter) = exchange.local_interest.clone() {
                // A newer SUMMARY supersedes every unanswered root commitment
                // for this receive filter. Otherwise a later local refresh
                // could reissue an older Probe and admit its delayed OFFER.
                // Validated records remain bounded exact replay no-ops, and an
                // already-retained exact replacement may be reused below.
                exchange.root_offer_history.retain(|record| {
                    record.validated || record.filter != filter || record.expectation == replacement
                });
            }
            exchange.remote_snapshot = Some(remote);
            exchange.pending_root_probe = None;
            exchange.probes_sent.clear();
            exchange.expected_nodes.clear();
        }
        // A root probe is also the authenticated causal acknowledgement for a
        // SUMMARY. Even equal inventories perform this constant-cost exchange
        // so a sender can retire retries without relying on silence as an ACK.
        self.push_probe(
            NibblePrefix::root(),
            summary.snapshot_id,
            summary.root_hash,
            summary.item_count,
            actions,
        )?;
        Ok(())
    }

    fn receive_probe(
        &mut self,
        probe: Probe,
        actions: &mut Vec<SyncAction>,
    ) -> Result<(), SyncError> {
        let prefix = NibblePrefix::new(probe.prefix, probe.prefix_nibbles)?;
        let Some(serve_inventory) = self.serve_inventory.as_ref() else {
            // A local commit or acknowledgement can invalidate the served
            // snapshot while the peer's retained PROBE is still in flight.
            // Keep the authenticated peer filter authoritative, ensure its
            // replacement selection remains requested, and let the retained
            // PROBE or the fresh SUMMARY resume causally after selection.
            let filter = self
                .active
                .as_ref()
                .and_then(|exchange| exchange.peer_interest.clone())
                .ok_or(SyncError::InventoryNotSelected(InventoryPurpose::ServePeer))?;
            self.push_selection(InventoryPurpose::ServePeer, filter, actions)?;
            return Ok(());
        };
        if probe.snapshot_id != serve_inventory.snapshot_id() {
            self.push_summary(actions, true)?;
            return Ok(());
        }
        let exchange_id = self.exchange_id()?;
        let peer_max_offers = self
            .active
            .as_ref()
            .and_then(|exchange| exchange.peer_max_offers)
            .ok_or(SyncError::NoActiveExchange)?;
        if prefix.is_empty()
            && serve_inventory.item_count() <= u64::from(peer_max_offers)
            && serve_inventory.item_count()
                <= u64::try_from(self.config.max_offer_ids)
                    .map_err(|_| SyncError::InvalidConfig("maximum offer identifiers"))?
        {
            actions.push(SyncAction::Send(Message::Offer(Offer {
                exchange_id,
                object_ids: serve_inventory.ids_under(&prefix, self.config.max_offer_ids),
                snapshot_id: probe.snapshot_id,
            })));
            return Ok(());
        }
        let node = serve_inventory.node(&prefix);
        actions.push(SyncAction::Send(Message::Node(Node {
            exchange_id,
            prefix: node.prefix.packed().to_vec(),
            prefix_nibbles: node.prefix.len(),
            hash: node.hash,
            item_count: node.item_count,
            children: node
                .children
                .into_iter()
                .map(|child| ChildSummary {
                    nibble: child.nibble,
                    hash: child.hash,
                    item_count: child.item_count,
                })
                .collect(),
            snapshot_id: probe.snapshot_id,
        })));
        Ok(())
    }

    fn receive_node(&mut self, node: Node, actions: &mut Vec<SyncAction>) -> Result<(), SyncError> {
        let Some(remote_snapshot) = self
            .active
            .as_ref()
            .and_then(|exchange| exchange.remote_snapshot)
        else {
            // A local inventory refresh invalidates the active traversal.
            // Authenticated NODE responses already in flight belong to that
            // retired traversal and cannot safely mutate the replacement.
            return Ok(());
        };
        if node.snapshot_id != remote_snapshot.1 {
            // A delayed node from an earlier inventory is harmless.
            return Ok(());
        }
        let prefix = NibblePrefix::new(node.prefix, node.prefix_nibbles)?;
        let expected = self
            .active
            .as_ref()
            .and_then(|exchange| {
                exchange
                    .expected_nodes
                    .get(&(node.snapshot_id, prefix.clone()))
            })
            .copied();
        let Some(expected) = expected else {
            if self.active.as_ref().is_some_and(|exchange| {
                exchange.root_offer_history.iter().any(|record| {
                    record.validated && record.expectation.snapshot_id == node.snapshot_id
                })
            }) {
                // A complete root OFFER retires the whole traversal. NODE
                // responses already in flight for that resolved snapshot are
                // authenticated but have no remaining state to advance.
                return Ok(());
            }
            return Err(SyncError::SnapshotMismatch);
        };
        if expected != (node.hash, node.item_count) {
            return Err(SyncError::SnapshotMismatch);
        }
        let remote = InventoryNode {
            prefix: prefix.clone(),
            hash: node.hash,
            item_count: node.item_count,
            children: node
                .children
                .into_iter()
                .map(|child| InventoryChild {
                    nibble: child.nibble,
                    hash: child.hash,
                    item_count: child.item_count,
                })
                .collect(),
        };
        remote.verify()?;
        let local = self
            .receive_inventory
            .as_ref()
            .ok_or(SyncError::InventoryNotSelected(
                InventoryPurpose::ReceiveBaseline,
            ))?
            .node(&prefix);
        if remote.hash == local.hash {
            self.clear_pending_root_probe(node.snapshot_id, &prefix, expected);
            return Ok(());
        }

        if prefix.len() == MAX_NIBBLES {
            let id = prefix.to_object_id()?;
            match (local.item_count, remote.item_count) {
                (0, 1) => {
                    if self.request_object(id)? {
                        self.bump_revision()?;
                    }
                    self.push_want_ids(&[id], actions);
                }
                (1, 0) => {}
                _ => {
                    return Err(SyncError::Inventory(InventoryError::InvalidNode(
                        "leaf mismatch",
                    )));
                }
            }
            self.clear_pending_root_probe(node.snapshot_id, &prefix, expected);
            return Ok(());
        }

        for nibble in 0..16_u8 {
            let remote_child = remote.children.iter().find(|child| child.nibble == nibble);
            let local_child = local.children.iter().find(|child| child.nibble == nibble);
            if remote_child.map(|child| child.hash) == local_child.map(|child| child.hash) {
                continue;
            }
            let child_prefix = prefix.child(nibble)?;
            if let Some(remote_child) = remote_child {
                self.push_probe(
                    child_prefix.clone(),
                    node.snapshot_id,
                    remote_child.hash,
                    remote_child.item_count,
                    actions,
                )?;
            }
        }
        self.clear_pending_root_probe(node.snapshot_id, &prefix, expected);
        Ok(())
    }

    fn receive_offer(
        &mut self,
        offer: Offer,
        actions: &mut Vec<SyncAction>,
    ) -> Result<(), SyncError> {
        if offer.object_ids.len() > self.config.max_offer_ids {
            return Err(SyncError::OfferLimit);
        }
        let offered_count =
            u64::try_from(offer.object_ids.len()).map_err(|_| SyncError::OfferLimit)?;
        let offered_inventory = SparseInventory::from_ids(offer.object_ids.iter().copied());
        let commitment = RootProbeExpectation {
            snapshot_id: offer.snapshot_id,
            root_hash: offered_inventory.root_hash(),
            item_count: offered_count,
        };
        let pending = self
            .active
            .as_ref()
            .and_then(|exchange| exchange.pending_root_probe);
        let matching_record = self.active.as_ref().and_then(|exchange| {
            let filter = exchange.local_interest.as_ref()?;
            exchange
                .root_offer_history
                .iter()
                .position(|record| record.expectation == commitment && &record.filter == filter)
        });
        let Some(record_index) = matching_record else {
            return Err(SyncError::SnapshotMismatch);
        };
        let active_response = pending == Some(commitment);
        if !active_response {
            let record = &self
                .active
                .as_ref()
                .ok_or(SyncError::NoActiveExchange)?
                .root_offer_history[record_index];
            if record.validated {
                // The original response already passed the root/count/list
                // commitment and admitted all derived durable work. A fresh
                // authenticated retransmission is therefore an exact no-op.
                return Ok(());
            }
            // Merely retaining a bounded record proves that a Probe once
            // existed, not that its traversal is still current. Only a fresh
            // authorized baseline may restore it to active state above.
            return Err(SyncError::SnapshotMismatch);
        } else {
            let remote_snapshot = self
                .active
                .as_ref()
                .and_then(|exchange| exchange.remote_snapshot)
                .ok_or(SyncError::SnapshotMismatch)?;
            let root = NibblePrefix::root();
            let expected_node = self.active.as_ref().and_then(|exchange| {
                exchange
                    .expected_nodes
                    .get(&(offer.snapshot_id, root.clone()))
                    .copied()
            });
            let root_was_probed = self.active.as_ref().is_some_and(|exchange| {
                exchange
                    .probes_sent
                    .contains(&(offer.snapshot_id, root.clone()))
            });
            if remote_snapshot != (commitment.root_hash, commitment.snapshot_id)
                || expected_node != Some((commitment.root_hash, commitment.item_count))
                || !root_was_probed
            {
                return Err(SyncError::SnapshotMismatch);
            }
        }

        let newly_requested = {
            let receive_inventory =
                self.receive_inventory
                    .as_ref()
                    .ok_or(SyncError::InventoryNotSelected(
                        InventoryPurpose::ReceiveBaseline,
                    ))?;
            offer
                .object_ids
                .iter()
                .copied()
                .filter(|id| !receive_inventory.contains(id) && !self.wants.contains(id))
                .collect::<Vec<_>>()
        };
        let wants_after = self
            .wants
            .len()
            .checked_add(newly_requested.len())
            .ok_or(SyncError::WantLimit)?;
        if wants_after > self.config.max_durable_wants {
            return Err(SyncError::WantLimit);
        }
        let revision_increment =
            u64::try_from(newly_requested.len()).map_err(|_| SyncError::RevisionExhausted)?;
        self.durable_revision
            .checked_add(revision_increment)
            .ok_or(SyncError::RevisionExhausted)?;

        for id in &newly_requested {
            let inserted = self.request_object(*id)?;
            debug_assert!(inserted);
            self.bump_revision()?;
        }
        let requested = {
            let receive_inventory =
                self.receive_inventory
                    .as_ref()
                    .ok_or(SyncError::InventoryNotSelected(
                        InventoryPurpose::ReceiveBaseline,
                    ))?;
            offer
                .object_ids
                .into_iter()
                .filter(|id| {
                    !receive_inventory.contains(id)
                        && self
                            .wants
                            .get(id)
                            .is_some_and(|progress| !progress.is_complete())
                })
                .collect::<Vec<_>>()
        };
        self.push_want_ids(&requested, actions);
        let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
        if exchange.pending_root_probe == Some(commitment) {
            exchange.pending_root_probe = None;
        }
        exchange
            .probes_sent
            .retain(|(snapshot_id, _)| *snapshot_id != commitment.snapshot_id);
        exchange
            .expected_nodes
            .retain(|(snapshot_id, _), _| *snapshot_id != commitment.snapshot_id);
        exchange.root_offer_history[record_index].validated = true;
        Ok(())
    }

    fn receive_data(&mut self, data: Data, actions: &mut Vec<SyncAction>) -> Result<(), SyncError> {
        if self.inventory.contains(&data.object_id) {
            // A DATA retry can arrive after the first copy committed but its
            // authenticated RECEIPT was lost. Re-acknowledge durable truth so
            // the sender can retire that adjacency-local retry; do not apply
            // or store the object again.
            actions.push(SyncAction::Send(Message::Receipt(Receipt {
                exchange_id: data.exchange_id,
                object_id: data.object_id,
                total_len: data.total_len,
                received: (data.total_len > 0)
                    .then_some(ByteRange {
                        start: 0,
                        end: data.total_len,
                    })
                    .into_iter()
                    .collect(),
                complete: true,
            })));
            return Ok(());
        }
        if !self.wants.contains(&data.object_id) {
            if !self.config.accept_unsolicited_data {
                return Err(SyncError::UnsolicitedData(data.object_id));
            }
            if self.request_object(data.object_id)? {
                self.bump_revision()?;
            }
        }
        let total_changed = self
            .wants
            .get_mut(&data.object_id)
            .ok_or(SyncError::UnsolicitedData(data.object_id))?
            .set_total_len(data.total_len)?;
        if total_changed {
            self.bump_revision()?;
        }
        if !data.forwarding.is_empty() {
            self.forwarding
                .insert(data.object_id, data.forwarding.clone());
        }
        if data.total_len == 0 {
            self.push_complete_if_ready(data.object_id, actions);
            return Ok(());
        }

        let payload_len =
            u64::try_from(data.payload.len()).map_err(|_| SyncError::InvalidStoreExtent)?;
        let end = data
            .offset
            .checked_add(payload_len)
            .ok_or(SyncError::InvalidStoreExtent)?;
        let extent = ByteRange {
            start: data.offset,
            end,
        };
        let (received, complete) = {
            let progress = self
                .wants
                .get(&data.object_id)
                .expect("want was established");
            (progress.received_ranges().to_vec(), progress.is_complete())
        };
        let pending = self
            .pending_writes
            .get(&data.object_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let pieces = uncovered_ranges(extent, &received, pending);
        let duplicate_is_durable =
            extent.start < extent.end && pieces.is_empty() && range_is_covered(&received, extent);
        let mut updated_pending = pending.to_vec();
        for piece in &pieces {
            updated_pending = insert_range(&updated_pending, *piece);
        }
        if updated_pending.len() > MAX_PROGRESS_RANGES {
            return Err(SyncError::ProgressTooFragmented);
        }
        if !pieces.is_empty() {
            self.pending_writes.insert(data.object_id, updated_pending);
        }
        for piece in pieces {
            let relative_start = usize::try_from(piece.start - data.offset)
                .map_err(|_| SyncError::InvalidStoreExtent)?;
            let relative_end = usize::try_from(piece.end - data.offset)
                .map_err(|_| SyncError::InvalidStoreExtent)?;
            actions.push(SyncAction::StoreChunk {
                object_id: data.object_id,
                total_len: data.total_len,
                offset: piece.start,
                bytes: data.payload[relative_start..relative_end].to_vec(),
            });
        }
        if duplicate_is_durable && let Some(exchange_id) = self.active_exchange_id() {
            // The first partial RECEIPT may have been omitted under bounded
            // one-shot queue pressure. Re-acknowledge current durable truth
            // when the retained sender retries an already-covered DATA range;
            // never acknowledge bytes that exist only in pending writes.
            actions.push(SyncAction::Send(Message::Receipt(Receipt {
                exchange_id,
                object_id: data.object_id,
                total_len: data.total_len,
                received,
                complete,
            })));
        }
        self.push_complete_if_ready(data.object_id, actions);
        Ok(())
    }

    fn chunk_stored(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        range: ByteRange,
    ) -> Result<Vec<SyncAction>, SyncError> {
        let Some(progress) = self.wants.get_mut(&object_id) else {
            // Duplicate completion after commit is a harmless no-op.
            if self.inventory.contains(&object_id) {
                return Ok(Vec::new());
            }
            return Err(SyncError::UnsolicitedData(object_id));
        };
        progress.set_total_len(total_len)?;
        if range.start >= range.end || range.end > total_len {
            return Err(SyncError::InvalidStoreExtent);
        }
        if let Some(pending) = self.pending_writes.get_mut(&object_id) {
            *pending = subtract_range(pending, range);
            if pending.is_empty() {
                self.pending_writes.remove(&object_id);
            }
        }
        let changed = progress.mark_received(range)?;
        if !changed {
            return Ok(Vec::new());
        }
        let complete = progress.is_complete();
        let received = progress.received_ranges().to_vec();
        self.bump_revision()?;
        let mut actions = Vec::new();
        if let Some(exchange_id) = self.active_exchange_id() {
            actions.push(SyncAction::Send(Message::Receipt(Receipt {
                exchange_id,
                object_id,
                total_len,
                received,
                complete,
            })));
        }
        if complete {
            self.push_complete_if_ready(object_id, &mut actions);
        } else {
            // Durable progress changes the exact missing ranges. Refresh the
            // retained WANT immediately instead of waiting for its existing
            // exponential retry deadline; otherwise bounded sender pressure
            // can turn every omitted tail into a full backoff interval.
            self.push_want_ids(&[object_id], &mut actions);
        }
        Ok(actions)
    }

    fn chunk_store_failed(
        &mut self,
        object_id: ObjectId,
        range: ByteRange,
    ) -> Result<Vec<SyncAction>, SyncError> {
        if let Some(pending) = self.pending_writes.get_mut(&object_id) {
            *pending = subtract_range(pending, range);
            if pending.is_empty() {
                self.pending_writes.remove(&object_id);
            }
        }
        let mut actions = Vec::new();
        self.push_want_ids(&[object_id], &mut actions);
        Ok(actions)
    }

    fn object_committed(
        &mut self,
        object_id: ObjectId,
        _item_id: Option<ItemId>,
    ) -> Result<Vec<SyncAction>, SyncError> {
        if self.inventory.contains(&object_id) {
            return Ok(Vec::new());
        }
        let Some(progress) = self.wants.get(&object_id) else {
            return Err(SyncError::UnsolicitedData(object_id));
        };
        if !progress.is_complete() {
            return Err(SyncError::InvalidStoreExtent);
        }
        self.inventory.insert(object_id);
        if let Some(receive_inventory) = self.receive_inventory.as_mut() {
            receive_inventory.insert(object_id);
        }
        self.wants.remove(&object_id);
        self.pending_writes.remove(&object_id);
        self.forwarding.remove(&object_id);
        self.commit_pending.remove(&object_id);
        self.bump_revision()?;
        // Preserve the live remote snapshot/probe walk so a multi-object
        // reconciliation does not discard sibling leaves after the first
        // commit. Only the independently authorized serve direction needs a
        // fresh backend selection because the new object may now be relayable.
        self.serve_inventory_changed()
    }

    fn object_deferred(
        &mut self,
        object_id: ObjectId,
        mut dependencies: Vec<ObjectId>,
    ) -> Result<Vec<SyncAction>, SyncError> {
        if self.inventory.contains(&object_id) {
            return Err(SyncError::InvalidStoreExtent);
        }
        let Some(progress) = self.wants.get(&object_id) else {
            return Err(SyncError::UnsolicitedData(object_id));
        };
        if !progress.is_complete() || dependencies.is_empty() {
            return Err(SyncError::InvalidStoreExtent);
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        if dependencies.contains(&object_id) {
            return Err(SyncError::InvalidStoreExtent);
        }

        let missing = dependencies
            .into_iter()
            .filter(|dependency| !self.inventory.contains(dependency))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            // A backend may defer only on an actually missing exact dependency;
            // otherwise the object must be committed or terminally rejected.
            return Err(SyncError::InvalidStoreExtent);
        }
        let requested = missing
            .iter()
            .copied()
            .filter(|dependency| !self.wants.contains(dependency))
            .collect::<Vec<_>>();
        let wants_after_retiring_object = self.wants.len().saturating_sub(1);
        if wants_after_retiring_object.saturating_add(requested.len())
            > self.config.max_durable_wants
        {
            return Err(SyncError::WantLimit);
        }

        // The backend has crash-atomically moved the exact completed bytes to
        // its dependency-pending partition. Retire transport staging without
        // advertising or semantically accepting the object.
        self.wants.remove(&object_id);
        self.pending_writes.remove(&object_id);
        self.forwarding.remove(&object_id);
        self.commit_pending.remove(&object_id);
        self.bump_revision()?;

        for dependency in &requested {
            let inserted = self.request_object(*dependency)?;
            debug_assert!(inserted);
        }
        let mut actions = Vec::new();
        self.push_want_ids(&requested, &mut actions);
        Ok(actions)
    }

    fn object_quarantined(&mut self, object_id: ObjectId) -> Result<Vec<SyncAction>, SyncError> {
        if self.inventory.contains(&object_id) {
            return Err(SyncError::InvalidStoreExtent);
        }
        let Some(progress) = self.wants.get(&object_id) else {
            return Err(SyncError::UnsolicitedData(object_id));
        };
        if !progress.is_complete() {
            return Err(SyncError::InvalidStoreExtent);
        }

        self.wants.remove(&object_id);
        self.pending_writes.remove(&object_id);
        self.forwarding.remove(&object_id);
        self.commit_pending.remove(&object_id);
        self.bump_revision()?;
        Ok(Vec::new())
    }

    fn object_rejected(&mut self, object_id: ObjectId) -> Result<Vec<SyncAction>, SyncError> {
        if self.inventory.contains(&object_id) {
            return Err(SyncError::InvalidStoreExtent);
        }
        if self.wants.remove(&object_id).is_none() {
            return Err(SyncError::UnsolicitedData(object_id));
        }
        self.pending_writes.remove(&object_id);
        self.forwarding.remove(&object_id);
        self.commit_pending.remove(&object_id);
        self.wants
            .request(object_id, self.config.progress_chunk_size)?;
        self.bump_revision()?;
        let mut actions = Vec::new();
        self.push_want_ids(&[object_id], &mut actions);
        Ok(actions)
    }

    fn local_added(&mut self, object_id: ObjectId) -> Result<Vec<SyncAction>, SyncError> {
        if !self.inventory.insert(object_id) {
            return Ok(Vec::new());
        }
        if self.wants.remove(&object_id).is_some() {
            self.bump_revision()?;
        }
        self.pending_writes.remove(&object_id);
        self.forwarding.remove(&object_id);
        self.commit_pending.remove(&object_id);
        self.inventory_changed()
    }

    fn local_removed(&mut self, object_id: ObjectId) -> Result<Vec<SyncAction>, SyncError> {
        if !self.inventory.remove(&object_id) {
            return Ok(Vec::new());
        }
        self.inventory_changed()
    }

    fn inventory_changed(&mut self) -> Result<Vec<SyncAction>, SyncError> {
        self.receive_inventory = None;
        self.serve_inventory = None;
        let (local_filter, peer_filter) = if let Some(exchange) = self.active.as_mut() {
            let filters = (
                exchange.local_interest.clone(),
                exchange.peer_interest.clone(),
            );
            exchange.selection_requested.clear();
            exchange.pending_summary = None;
            exchange.remote_snapshot = None;
            exchange.pending_root_probe = None;
            // Keep the bounded commitment while disabling the live traversal.
            // A fresh authorized receive selection explicitly reissues at most
            // the newest matching unanswered root Probe before its response
            // can create work. Validated commitments remain safe no-ops.
            exchange.probes_sent.clear();
            exchange.expected_nodes.clear();
            exchange.summary_sent = None;
            filters
        } else {
            (None, None)
        };
        let mut actions = Vec::new();
        if let Some(filter) = local_filter {
            self.push_selection(
                InventoryPurpose::ReceiveBaseline,
                filter.clone(),
                &mut actions,
            )?;
            let exchange_id = self.exchange_id()?;
            let interest = Message::Interest(Interest {
                exchange_id,
                topics: filter.topics,
                scopes: filter.scopes,
                min_priority: filter.min_priority,
                max_offers: u32::try_from(self.config.max_offer_ids)
                    .map_err(|_| SyncError::InvalidConfig("maximum offer identifiers"))?,
            });
            validate_outbound(&interest, self.semantic_version)?;
            actions.push(SyncAction::Send(interest));
        }
        if let Some(filter) = peer_filter {
            self.push_selection(InventoryPurpose::ServePeer, filter, &mut actions)?;
        }
        Ok(actions)
    }

    fn serve_inventory_changed(&mut self) -> Result<Vec<SyncAction>, SyncError> {
        self.serve_inventory = None;
        let peer_filter = self
            .active
            .as_ref()
            .and_then(|exchange| exchange.peer_interest.clone());
        if let Some(exchange) = self.active.as_mut() {
            exchange.summary_sent = None;
            exchange
                .selection_requested
                .remove(&InventoryPurpose::ServePeer);
        }
        let mut actions = Vec::new();
        if let Some(filter) = peer_filter {
            self.push_selection(InventoryPurpose::ServePeer, filter, &mut actions)?;
        }
        Ok(actions)
    }

    fn push_selection(
        &mut self,
        purpose: InventoryPurpose,
        filter: InterestFilter,
        actions: &mut Vec<SyncAction>,
    ) -> Result<(), SyncError> {
        let already_selected = match purpose {
            InventoryPurpose::ReceiveBaseline => self.receive_inventory.is_some(),
            InventoryPurpose::ServePeer => self.serve_inventory.is_some(),
        };
        if already_selected {
            return Ok(());
        }
        if let Some(exchange) = self.active.as_mut() {
            if exchange.selection_requested.contains_key(&purpose) {
                return Ok(());
            }
            let request_id = self.next_selection_id;
            self.next_selection_id = self
                .next_selection_id
                .checked_add(1)
                .ok_or(SyncError::RevisionExhausted)?;
            exchange.selection_requested.insert(purpose, request_id);
            actions.push(SyncAction::SelectInventory {
                request_id,
                purpose,
                filter,
            });
            Ok(())
        } else {
            Err(SyncError::NoActiveExchange)
        }
    }

    fn push_summary(
        &mut self,
        actions: &mut Vec<SyncAction>,
        force: bool,
    ) -> Result<(), SyncError> {
        let inventory = self
            .serve_inventory
            .as_ref()
            .ok_or(SyncError::InventoryNotSelected(InventoryPurpose::ServePeer))?;
        let root = inventory.root_hash();
        let snapshot_id = inventory.snapshot_id();
        let item_count = inventory.item_count();
        let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
        if !force && exchange.summary_sent == Some((root, snapshot_id)) {
            return Ok(());
        }
        exchange.summary_sent = Some((root, snapshot_id));
        actions.push(SyncAction::Send(Message::Summary(Summary {
            exchange_id: exchange.id,
            root_hash: root,
            item_count,
            snapshot_id,
        })));
        Ok(())
    }

    fn push_probe(
        &mut self,
        prefix: NibblePrefix,
        snapshot_id: u64,
        expected_hash: Digest32,
        expected_count: u64,
        actions: &mut Vec<SyncAction>,
    ) -> Result<(), SyncError> {
        let exchange = self.active.as_mut().ok_or(SyncError::NoActiveExchange)?;
        let key = (snapshot_id, prefix.clone());
        if let Some(previous) = exchange.expected_nodes.get(&key) {
            if *previous != (expected_hash, expected_count) {
                return Err(SyncError::SnapshotMismatch);
            }
        } else {
            if exchange.probes_sent.len() >= self.config.max_probe_nodes {
                return Err(SyncError::ProbeLimit);
            }
            exchange
                .expected_nodes
                .insert(key, (expected_hash, expected_count));
        }
        if !exchange.probes_sent.insert((snapshot_id, prefix.clone())) {
            return Ok(());
        }
        if prefix.is_empty() {
            let expectation = RootProbeExpectation {
                snapshot_id,
                root_hash: expected_hash,
                item_count: expected_count,
            };
            exchange.pending_root_probe = Some(expectation);
            let filter = exchange
                .local_interest
                .clone()
                .ok_or(SyncError::NoActiveExchange)?;
            if !exchange
                .root_offer_history
                .iter()
                .any(|record| record.expectation == expectation && record.filter == filter)
            {
                if exchange.root_offer_history.len() == MAX_ROOT_OFFER_HISTORY {
                    exchange.root_offer_history.remove(0);
                }
                exchange.root_offer_history.push(RootOfferRecord {
                    expectation,
                    filter,
                    validated: false,
                });
            }
        }
        actions.push(SyncAction::Send(Message::Probe(Probe {
            exchange_id: exchange.id,
            prefix: prefix.packed().to_vec(),
            prefix_nibbles: prefix.len(),
            snapshot_id,
        })));
        Ok(())
    }

    fn clear_pending_root_probe(
        &mut self,
        snapshot_id: u64,
        prefix: &NibblePrefix,
        expected: (Digest32, u64),
    ) {
        if !prefix.is_empty() {
            return;
        }
        let Some(exchange) = self.active.as_mut() else {
            return;
        };
        let expectation = RootProbeExpectation {
            snapshot_id,
            root_hash: expected.0,
            item_count: expected.1,
        };
        if exchange.pending_root_probe == Some(expectation) {
            exchange.pending_root_probe = None;
        }
        // A validated root NODE selects ordinary Merkle descent and retires
        // the alternative complete-root OFFER response for this Probe. A
        // delayed OFFER must not revive work after the traversal advanced.
        let local_filter = exchange.local_interest.clone();
        exchange.root_offer_history.retain(|record| {
            record.validated
                || record.expectation != expectation
                || local_filter.as_ref() != Some(&record.filter)
        });
    }

    fn push_want_ids(&self, ids: &[ObjectId], actions: &mut Vec<SyncAction>) {
        let Some(exchange_id) = self.active_exchange_id() else {
            return;
        };
        let mut items: Vec<_> = ids
            .iter()
            .filter_map(|id| {
                self.wants.get(id).map(|progress| {
                    let need_forwarding = id.kind().supports_forwarding_metadata()
                        && !self.forwarding.contains_key(id);
                    progress.to_want_item(*id, need_forwarding)
                })
            })
            .filter(|item| {
                item.total_len.is_none() || !item.missing.is_empty() || item.need_forwarding
            })
            .collect();
        items.sort_by_key(|item| item.object_id);
        items.dedup_by_key(|item| item.object_id);
        for chunk in items.chunks(self.config.max_want_items) {
            actions.push(SyncAction::Send(Message::Want(Want {
                exchange_id,
                items: chunk.to_vec(),
            })));
        }
    }

    fn push_resume_actions(&mut self, actions: &mut Vec<SyncAction>) {
        let ids: Vec<_> = self
            .wants
            .wire_items()
            .into_iter()
            .filter(|item| {
                item.object_id
                    .kind()
                    .is_allowed_in_semantic_version(self.semantic_version)
            })
            .map(|item| item.object_id)
            .collect();
        for object_id in &ids {
            self.push_complete_if_ready(*object_id, actions);
        }
        self.push_want_ids(&ids, actions);
    }

    fn ensure_exchange(&self, received: u64) -> Result<(), SyncError> {
        let expected = self.exchange_id()?;
        if expected != received {
            return Err(SyncError::ExchangeMismatch { expected, received });
        }
        Ok(())
    }

    fn exchange_id(&self) -> Result<u64, SyncError> {
        self.active
            .as_ref()
            .map(|exchange| exchange.id)
            .ok_or(SyncError::NoActiveExchange)
    }

    fn bump_revision(&mut self) -> Result<(), SyncError> {
        self.durable_revision = self
            .durable_revision
            .checked_add(1)
            .ok_or(SyncError::RevisionExhausted)?;
        Ok(())
    }

    fn push_complete_if_ready(&mut self, object_id: ObjectId, actions: &mut Vec<SyncAction>) {
        let total_len = self
            .wants
            .get(&object_id)
            .filter(|progress| progress.is_complete())
            .and_then(WantProgress::total_len);
        let forwarding = match object_id.kind() {
            kind if kind.supports_forwarding_metadata() => self.forwarding.get(&object_id).cloned(),
            ObjectKind::BlobChunk | ObjectKind::BridgeAuthorization => Some(Vec::new()),
            ObjectKind::SourceEnvelope
            | ObjectKind::SourceBatchProof
            | ObjectKind::BridgeRouteWrapper => unreachable!("guarded forwarding kind"),
        };
        if let (Some(total_len), Some(forwarding)) = (total_len, forwarding)
            && self.commit_pending.insert(object_id)
        {
            actions.push(SyncAction::CompleteObject {
                object_id,
                total_len,
                forwarding,
            });
        }
    }

    fn request_object(&mut self, object_id: ObjectId) -> Result<bool, SyncError> {
        if self.wants.contains(&object_id) {
            return Ok(false);
        }
        if self.wants.len() >= self.config.max_durable_wants {
            return Err(SyncError::WantLimit);
        }
        self.wants
            .request(object_id, self.config.progress_chunk_size)
    }

    /// Restores peer-neutral dependency requests for objects already moved to a
    /// durable pending partition before process loss. No pending object's own
    /// identity is inserted into inventory by this operation.
    pub(crate) fn hydrate_dependency_wants_for_semantic_version(
        &mut self,
        dependencies: impl IntoIterator<Item = ObjectId>,
        semantic_version: u16,
    ) -> Result<(), SyncError> {
        wire::validate_semantic_version(semantic_version)?;
        if self.active.is_some() {
            return Err(SyncError::InvalidSnapshot(
                "dependency hydration during active exchange",
            ));
        }
        let mut dependencies = dependencies.into_iter().collect::<Vec<_>>();
        dependencies.sort_unstable();
        dependencies.dedup();
        let dependencies = dependencies
            .into_iter()
            .filter(|dependency| {
                dependency
                    .kind()
                    .is_allowed_in_semantic_version(semantic_version)
                    && !self.inventory.contains(dependency)
                    && !self.wants.contains(dependency)
            })
            .collect::<Vec<_>>();
        if self.wants.len().saturating_add(dependencies.len()) > self.config.max_durable_wants {
            return Err(SyncError::WantLimit);
        }
        for dependency in dependencies {
            if !self.request_object(dependency)? {
                return Err(SyncError::InvalidSnapshot(
                    "dependency want changed during hydration",
                ));
            }
        }
        Ok(())
    }
}

fn validate_outbound(message: &Message, semantic_version: u16) -> Result<(), SyncError> {
    wire::encode_message_for_semantic_version(message, semantic_version, Limits::default())?;
    Ok(())
}

fn validate_event_for_semantic_version(
    event: &SyncEvent,
    semantic_version: u16,
) -> Result<(), SyncError> {
    wire::validate_semantic_version(semantic_version)?;
    let validate_id = |object_id: ObjectId| {
        if object_id
            .kind()
            .is_allowed_in_semantic_version(semantic_version)
        {
            Ok(())
        } else {
            Err(SyncError::Wire(WireError::ObjectKindRequiresSemanticV2(
                object_id.kind(),
            )))
        }
    };
    match event {
        SyncEvent::Receive(message) => {
            wire::validate_message_for_semantic_version(message, semantic_version)?;
            Ok(())
        }
        SyncEvent::InventorySelected { inventory, .. } => {
            if inventory.filtered_for_semantic_version(semantic_version) == *inventory {
                Ok(())
            } else {
                Err(SyncError::Wire(WireError::ObjectKindRequiresSemanticV2(
                    ObjectKind::SourceBatchProof,
                )))
            }
        }
        SyncEvent::ChunkStored { object_id, .. }
        | SyncEvent::ChunkStoreFailed { object_id, .. }
        | SyncEvent::ObjectCommitted { object_id, .. }
        | SyncEvent::ObjectDeferred { object_id, .. }
        | SyncEvent::ObjectQuarantined { object_id }
        | SyncEvent::ObjectRejected { object_id }
        | SyncEvent::LocalObjectAdded { object_id }
        | SyncEvent::LocalObjectRemoved { object_id } => {
            validate_id(*object_id)?;
            if let SyncEvent::ObjectDeferred { dependencies, .. } = event {
                if dependencies.is_empty() {
                    return Err(SyncError::InvalidStoreExtent);
                }
                for dependency in dependencies {
                    validate_id(*dependency)?;
                }
            }
            Ok(())
        }
        SyncEvent::Start { .. }
        | SyncEvent::LocalInventoryChanged
        | SyncEvent::ServeInventoryChanged => Ok(()),
    }
}

fn insert_range(existing: &[ByteRange], added: ByteRange) -> Vec<ByteRange> {
    let mut out = Vec::with_capacity(existing.len() + 1);
    let mut merged = added;
    let mut inserted = false;
    for range in existing {
        if range.end < merged.start {
            out.push(*range);
        } else if merged.end < range.start {
            if !inserted {
                out.push(merged);
                inserted = true;
            }
            out.push(*range);
        } else {
            merged.start = merged.start.min(range.start);
            merged.end = merged.end.max(range.end);
        }
    }
    if !inserted {
        out.push(merged);
    }
    out
}

fn subtract_range(existing: &[ByteRange], removed: ByteRange) -> Vec<ByteRange> {
    let mut out = Vec::new();
    for range in existing {
        if removed.end <= range.start || removed.start >= range.end {
            out.push(*range);
            continue;
        }
        if range.start < removed.start {
            out.push(ByteRange {
                start: range.start,
                end: removed.start.min(range.end),
            });
        }
        if removed.end < range.end {
            out.push(ByteRange {
                start: removed.end.max(range.start),
                end: range.end,
            });
        }
    }
    out
}

fn uncovered_ranges(
    extent: ByteRange,
    received: &[ByteRange],
    pending: &[ByteRange],
) -> Vec<ByteRange> {
    let mut blockers = Vec::with_capacity(received.len() + pending.len());
    blockers.extend_from_slice(received);
    blockers.extend_from_slice(pending);
    blockers.sort_by_key(|range| range.start);
    let mut cursor = extent.start;
    let mut out = Vec::new();
    for blocker in blockers {
        if blocker.end <= cursor || blocker.start >= extent.end {
            continue;
        }
        if blocker.start > cursor {
            out.push(ByteRange {
                start: cursor,
                end: blocker.start.min(extent.end),
            });
        }
        cursor = cursor.max(blocker.end).min(extent.end);
        if cursor == extent.end {
            break;
        }
    }
    if cursor < extent.end {
        out.push(ByteRange {
            start: cursor,
            end: extent.end,
        });
    }
    out
}

fn range_is_covered(existing: &[ByteRange], wanted: ByteRange) -> bool {
    existing
        .iter()
        .any(|range| range.start <= wanted.start && range.end >= wanted.end)
}

fn snapshot_map(value: &Value) -> Result<&[(u64, Value)], SyncError> {
    match value {
        Value::Map(map) => Ok(map),
        _ => Err(SyncError::InvalidSnapshot("map type")),
    }
}

fn snapshot_array(value: &Value) -> Result<&[Value], SyncError> {
    match value {
        Value::Array(array) => Ok(array),
        _ => Err(SyncError::InvalidSnapshot("array type")),
    }
}

fn snapshot_unsigned(value: &Value) -> Result<u64, SyncError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(SyncError::InvalidSnapshot("unsigned type")),
    }
}

fn snapshot_required(map: &[(u64, Value)], key: u64) -> Result<&Value, SyncError> {
    map.binary_search_by_key(&key, |entry| entry.0)
        .map(|index| &map[index].1)
        .map_err(|_| SyncError::InvalidSnapshot("missing field"))
}

fn snapshot_keys(map: &[(u64, Value)], allowed: &[u64]) -> Result<(), SyncError> {
    for (key, _) in map {
        if *key <= wire::registry::MAX_CRITICAL_KEY && !allowed.contains(key) {
            return Err(SyncError::Wire(WireError::UnknownCriticalKey(*key)));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_identifier_limits_keep_the_production_default_and_fail_closed() {
        assert_eq!(SyncConfig::default().max_offer_ids, 256);
        for max_offer_ids in [0, MAX_OFFER_IDS + 1] {
            let result = SyncState::new(
                SyncConfig {
                    max_offer_ids,
                    ..SyncConfig::default()
                },
                SparseInventory::new(),
            );
            assert!(matches!(
                result,
                Err(SyncError::InvalidConfig("maximum offer identifiers"))
            ));
        }
    }

    fn id(byte: u8) -> ObjectId {
        ObjectId::for_envelope(crate::wire::EnvelopeId::from_bytes([byte; 32]))
    }

    fn selectors(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}-{index:04}"))
            .collect()
    }

    fn start(state: &mut SyncState, exchange_id: u64) {
        state
            .apply(SyncEvent::Start {
                exchange_id,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
            })
            .unwrap();
    }

    fn selection(actions: &[SyncAction], purpose: InventoryPurpose) -> (u64, InterestFilter) {
        actions
            .iter()
            .find_map(|action| match action {
                SyncAction::SelectInventory {
                    request_id,
                    purpose: actual,
                    filter,
                } if *actual == purpose => Some((*request_id, filter.clone())),
                _ => None,
            })
            .expect("selection action")
    }

    fn start_with_baseline(state: &mut SyncState, exchange_id: u64, inventory: SparseInventory) {
        let actions = state
            .apply(SyncEvent::Start {
                exchange_id,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
            })
            .unwrap();
        let (request_id, filter) = selection(&actions, InventoryPurpose::ReceiveBaseline);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory,
            })
            .unwrap();
    }

    fn pending_root_offer(
        state: &mut SyncState,
        exchange_id: u64,
        remote: &SparseInventory,
    ) -> Offer {
        let actions = state
            .apply(SyncEvent::Receive(Message::Summary(Summary {
                exchange_id,
                root_hash: remote.root_hash(),
                item_count: remote.item_count(),
                snapshot_id: remote.snapshot_id(),
            })))
            .unwrap();
        assert_eq!(
            actions,
            vec![SyncAction::Send(Message::Probe(Probe {
                exchange_id,
                prefix: Vec::new(),
                prefix_nibbles: 0,
                snapshot_id: remote.snapshot_id(),
            }))]
        );
        Offer {
            exchange_id,
            object_ids: remote.ids_under(&NibblePrefix::root(), remote.len()),
            snapshot_id: remote.snapshot_id(),
        }
    }

    fn assert_rejected_offer_preserves_state(
        state: &mut SyncState,
        offer: Offer,
        expected: SyncError,
    ) {
        let before = state.clone();
        assert_eq!(
            state.apply(SyncEvent::Receive(Message::Offer(offer))),
            Err(expected)
        );
        assert_eq!(state.snapshot(), before.snapshot());
        assert_eq!(state.active, before.active);
        assert_eq!(state.inventory, before.inventory);
        assert_eq!(state.receive_inventory, before.receive_inventory);
        assert_eq!(state.serve_inventory, before.serve_inventory);
        assert_eq!(state.pending_writes, before.pending_writes);
        assert_eq!(state.forwarding, before.forwarding);
        assert_eq!(state.commit_pending, before.commit_pending);
    }

    #[test]
    fn local_interest_work_is_rejected_before_inventory_selection() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let error = state
            .apply(SyncEvent::Start {
                exchange_id: 17,
                topics: selectors("topic", 65),
                scopes: selectors("scope", 64),
                min_priority: 0,
            })
            .unwrap_err();
        assert_eq!(
            error,
            SyncError::Wire(WireError::InterestWorkLimit {
                actual: 65 * 64,
                maximum: wire::MAX_INTEREST_WORK,
            })
        );
        assert!(state.active.is_none());
        assert_eq!(state.next_selection_id, 1);
    }

    #[test]
    fn selected_v1_rejects_extended_references_before_reducer_effects() {
        let object_id = ObjectId::new(ObjectKind::SourceBatchProof, [0x33; 32]);
        let messages = [
            Message::Offer(Offer {
                exchange_id: 11,
                object_ids: vec![object_id],
                snapshot_id: 1,
            }),
            Message::Want(Want {
                exchange_id: 11,
                items: vec![WantItem {
                    object_id,
                    total_len: None,
                    missing: Vec::new(),
                    need_forwarding: false,
                }],
            }),
            Message::Data(Data {
                exchange_id: 11,
                object_id,
                total_len: 1,
                offset: 0,
                payload: vec![1],
                forwarding: Vec::new(),
            }),
            Message::Receipt(Receipt {
                exchange_id: 11,
                object_id,
                total_len: 1,
                received: vec![ByteRange { start: 0, end: 1 }],
                complete: true,
            }),
        ];

        for message in messages {
            let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
            start(&mut state, 11);
            let before = state.snapshot();
            let result = state.apply_for_semantic_version(
                SyncEvent::Receive(message),
                wire::SEMANTIC_PROTOCOL_V1,
            );
            assert_eq!(
                result,
                Err(SyncError::Wire(WireError::ObjectKindRequiresSemanticV2(
                    ObjectKind::SourceBatchProof
                )))
            );
            assert_eq!(state.snapshot(), before);
            assert!(!state.inventory().contains(&object_id));
            assert!(state.pending_writes.is_empty());
            assert!(state.commit_pending.is_empty());
        }

        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start(&mut state, 11);
        assert_eq!(
            state.apply_for_semantic_version(
                SyncEvent::ObjectCommitted {
                    object_id,
                    item_id: None,
                },
                wire::SEMANTIC_PROTOCOL_V1,
            ),
            Err(SyncError::Wire(WireError::ObjectKindRequiresSemanticV2(
                ObjectKind::SourceBatchProof
            )))
        );
        assert!(!state.inventory().contains(&object_id));
    }

    #[test]
    fn summary_is_impossible_until_retained_interest_is_selected() {
        let global = SparseInventory::from_ids([id(1), id(2)]);
        let mut state = SyncState::new(SyncConfig::default(), global).unwrap();
        let start_actions = state
            .apply(SyncEvent::Start {
                exchange_id: 7,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: 2,
            })
            .unwrap();
        assert!(
            !start_actions
                .iter()
                .any(|action| matches!(action, SyncAction::Send(Message::Summary(_))))
        );
        let (receive_request, receive_filter) =
            selection(&start_actions, InventoryPurpose::ReceiveBaseline);
        assert_eq!(receive_filter.topics, vec!["alpha"]);
        assert_eq!(receive_filter.scopes, vec!["mission/team"]);
        assert_eq!(receive_filter.min_priority, 2);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 7,
                request_id: receive_request,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter: receive_filter,
                inventory: SparseInventory::from_ids([id(1)]),
            })
            .unwrap();

        let peer_interest = Message::Interest(Interest {
            exchange_id: 7,
            topics: vec!["bravo".into()],
            scopes: vec!["mission/team".into()],
            min_priority: 1,
            max_offers: 8,
        });
        let actions = state.apply(SyncEvent::Receive(peer_interest)).unwrap();
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, SyncAction::Send(Message::Summary(_))))
        );
        let (serve_request, serve_filter) = selection(&actions, InventoryPurpose::ServePeer);
        let selected = SparseInventory::from_ids([id(2)]);
        let expected_root = selected.root_hash();
        let actions = state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 7,
                request_id: serve_request,
                purpose: InventoryPurpose::ServePeer,
                filter: serve_filter,
                inventory: selected,
            })
            .unwrap();
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Summary(Summary { root_hash, .. })) if *root_hash == expected_root
        )));
        assert_ne!(expected_root, state.inventory().root_hash());
    }

    #[test]
    fn same_exchange_start_preserves_pending_peer_inventory_selection() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let peer_actions = state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 12,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: 1,
                max_offers: 8,
            })))
            .unwrap();
        let (serve_request, serve_filter) = selection(&peer_actions, InventoryPurpose::ServePeer);

        let local_actions = state
            .apply(SyncEvent::Start {
                exchange_id: 12,
                topics: vec!["bravo".into()],
                scopes: vec!["mission/team".into()],
                min_priority: 2,
            })
            .unwrap();
        let (receive_request, receive_filter) =
            selection(&local_actions, InventoryPurpose::ReceiveBaseline);

        let serve_actions = state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 12,
                request_id: serve_request,
                purpose: InventoryPurpose::ServePeer,
                filter: serve_filter,
                inventory: SparseInventory::from_ids([id(1)]),
            })
            .unwrap();
        assert!(serve_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Summary(Summary {
                exchange_id: 12,
                ..
            }))
        )));
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 12,
                request_id: receive_request,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter: receive_filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
    }

    #[test]
    fn local_inventory_change_reselects_both_authenticated_directions() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let local_actions = state
            .apply(SyncEvent::Start {
                exchange_id: 13,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: 1,
            })
            .unwrap();
        let (receive_request, receive_filter) =
            selection(&local_actions, InventoryPurpose::ReceiveBaseline);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 13,
                request_id: receive_request,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter: receive_filter,
                inventory: SparseInventory::from_ids([id(1)]),
            })
            .unwrap();
        let peer_actions = state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 13,
                topics: vec!["bravo".into()],
                scopes: vec!["mission/team".into()],
                min_priority: 2,
                max_offers: 8,
            })))
            .unwrap();
        let (serve_request, serve_filter) = selection(&peer_actions, InventoryPurpose::ServePeer);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 13,
                request_id: serve_request,
                purpose: InventoryPurpose::ServePeer,
                filter: serve_filter,
                inventory: SparseInventory::from_ids([id(2)]),
            })
            .unwrap();
        assert!(state.selected_serve_inventory().is_some());

        let actions = state.apply(SyncEvent::LocalInventoryChanged).unwrap();
        let purposes = actions
            .iter()
            .filter_map(|action| match action {
                SyncAction::SelectInventory { purpose, .. } => Some(*purpose),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            purposes,
            BTreeSet::from([
                InventoryPurpose::ReceiveBaseline,
                InventoryPurpose::ServePeer,
            ])
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Interest(Interest {
                exchange_id: 13,
                ..
            }))
        )));
        assert!(state.selected_serve_inventory().is_none());
    }

    #[test]
    fn serve_inventory_change_preserves_live_receive_traversal() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 131, SparseInventory::from_ids([id(1)]));
        let remote = SparseInventory::from_ids([id(2), id(3)]);
        state
            .apply(SyncEvent::Receive(Message::Summary(Summary {
                exchange_id: 131,
                root_hash: remote.root_hash(),
                item_count: remote.item_count(),
                snapshot_id: remote.snapshot_id(),
            })))
            .unwrap();

        let peer_actions = state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 131,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
                max_offers: 8,
            })))
            .unwrap();
        let (serve_request, serve_filter) = selection(&peer_actions, InventoryPurpose::ServePeer);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 131,
                request_id: serve_request,
                purpose: InventoryPurpose::ServePeer,
                filter: serve_filter,
                inventory: SparseInventory::from_ids([id(1)]),
            })
            .unwrap();

        let receive_inventory = state.receive_inventory.clone();
        let exchange = state.active.as_ref().expect("active exchange");
        let pending_summary = exchange.pending_summary.clone();
        let remote_snapshot = exchange.remote_snapshot;
        let pending_root_probe = exchange.pending_root_probe;
        let root_offer_history = exchange.root_offer_history.clone();
        let probes_sent = exchange.probes_sent.clone();
        let expected_nodes = exchange.expected_nodes.clone();

        let actions = state.apply(SyncEvent::ServeInventoryChanged).unwrap();

        assert_eq!(state.receive_inventory, receive_inventory);
        let exchange = state.active.as_ref().expect("active exchange");
        assert_eq!(exchange.pending_summary, pending_summary);
        assert_eq!(exchange.remote_snapshot, remote_snapshot);
        assert_eq!(exchange.pending_root_probe, pending_root_probe);
        assert_eq!(exchange.root_offer_history, root_offer_history);
        assert_eq!(exchange.probes_sent, probes_sent);
        assert_eq!(exchange.expected_nodes, expected_nodes);
        assert!(state.serve_inventory.is_none());
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::SelectInventory {
                purpose: InventoryPurpose::ServePeer,
                ..
            }
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            SyncAction::SelectInventory {
                purpose: InventoryPurpose::ReceiveBaseline,
                ..
            } | SyncAction::Send(Message::Interest(_))
        )));
    }

    #[test]
    fn delayed_probe_waits_for_pending_serve_inventory_reselection() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let peer_actions = state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 14,
                topics: vec!["alpha".into()],
                scopes: vec!["mission/team".into()],
                min_priority: 1,
                max_offers: 8,
            })))
            .unwrap();
        let (request_id, filter) = selection(&peer_actions, InventoryPurpose::ServePeer);
        let old_inventory = SparseInventory::from_ids([id(1)]);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 14,
                request_id,
                purpose: InventoryPurpose::ServePeer,
                filter,
                inventory: old_inventory.clone(),
            })
            .unwrap();

        let refresh_actions = state.apply(SyncEvent::LocalInventoryChanged).unwrap();
        let (request_id, filter) = selection(&refresh_actions, InventoryPurpose::ServePeer);
        let delayed_actions = state
            .apply(SyncEvent::Receive(Message::Probe(Probe {
                exchange_id: 14,
                prefix: Vec::new(),
                prefix_nibbles: 0,
                snapshot_id: old_inventory.snapshot_id(),
            })))
            .unwrap();
        assert!(delayed_actions.is_empty());

        let replacement = SparseInventory::from_ids([id(1), id(2)]);
        let selected_actions = state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 14,
                request_id,
                purpose: InventoryPurpose::ServePeer,
                filter,
                inventory: replacement.clone(),
            })
            .unwrap();
        assert!(selected_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Summary(Summary { snapshot_id, .. }))
                if *snapshot_id == replacement.snapshot_id()
        )));
    }

    #[test]
    fn root_probe_offer_respects_current_peer_and_local_limits() {
        let inventory = SparseInventory::from_ids([id(1), id(2)]);
        let mut state = SyncState::new(
            SyncConfig {
                max_offer_ids: 2,
                ..SyncConfig::default()
            },
            SparseInventory::new(),
        )
        .unwrap();
        let actions = state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 41,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
                max_offers: 1,
            })))
            .unwrap();
        let (request_id, filter) = selection(&actions, InventoryPurpose::ServePeer);
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 41,
                request_id,
                purpose: InventoryPurpose::ServePeer,
                filter,
                inventory: inventory.clone(),
            })
            .unwrap();

        let root_probe = Message::Probe(Probe {
            exchange_id: 41,
            prefix: Vec::new(),
            prefix_nibbles: 0,
            snapshot_id: inventory.snapshot_id(),
        });
        assert!(matches!(
            state
                .apply(SyncEvent::Receive(root_probe.clone()))
                .unwrap()
                .as_slice(),
            [SyncAction::Send(Message::Node(Node {
                prefix_nibbles: 0,
                ..
            }))]
        ));

        state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 41,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
                max_offers: 2,
            })))
            .unwrap();
        assert_eq!(
            state.apply(SyncEvent::Receive(root_probe)).unwrap(),
            vec![SyncAction::Send(Message::Offer(Offer {
                exchange_id: 41,
                object_ids: vec![id(1), id(2)],
                snapshot_id: inventory.snapshot_id(),
            }))]
        );

        let mut locally_bounded = SyncState::new(
            SyncConfig {
                max_offer_ids: 1,
                ..SyncConfig::default()
            },
            SparseInventory::new(),
        )
        .unwrap();
        let actions = locally_bounded
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 42,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
                max_offers: 2,
            })))
            .unwrap();
        let (request_id, filter) = selection(&actions, InventoryPurpose::ServePeer);
        locally_bounded
            .apply(SyncEvent::InventorySelected {
                exchange_id: 42,
                request_id,
                purpose: InventoryPurpose::ServePeer,
                filter,
                inventory: inventory.clone(),
            })
            .unwrap();
        assert!(matches!(
            locally_bounded
                .apply(SyncEvent::Receive(Message::Probe(Probe {
                    exchange_id: 42,
                    prefix: Vec::new(),
                    prefix_nibbles: 0,
                    snapshot_id: inventory.snapshot_id(),
                })))
                .unwrap()
                .as_slice(),
            [SyncAction::Send(Message::Node(Node {
                prefix_nibbles: 0,
                ..
            }))]
        ));
    }

    #[test]
    fn want_serving_requires_current_policy_filtered_inventory() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let actions = state
            .apply(SyncEvent::Receive(Message::Interest(Interest {
                exchange_id: 43,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
                max_offers: 2,
            })))
            .unwrap();
        let (request_id, filter) = selection(&actions, InventoryPurpose::ServePeer);
        let selected = id(1);
        let unadvertised = id(2);
        let want = |object_id| WantItem {
            object_id,
            total_len: None,
            missing: Vec::new(),
            need_forwarding: true,
        };

        assert!(
            state
                .apply(SyncEvent::Receive(Message::Want(Want {
                    exchange_id: 43,
                    items: vec![want(selected)],
                })))
                .unwrap()
                .is_empty(),
            "a WANT cannot bypass the pending policy selection"
        );
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 43,
                request_id,
                purpose: InventoryPurpose::ServePeer,
                filter,
                inventory: SparseInventory::from_ids([selected]),
            })
            .unwrap();
        assert_eq!(
            state
                .apply(SyncEvent::Receive(Message::Want(Want {
                    exchange_id: 43,
                    items: vec![want(selected), want(unadvertised)],
                })))
                .unwrap(),
            vec![SyncAction::Serve(want(selected))]
        );

        let refresh = state.apply(SyncEvent::ServeInventoryChanged).unwrap();
        let (request_id, filter) = selection(&refresh, InventoryPurpose::ServePeer);
        assert!(
            state
                .apply(SyncEvent::Receive(Message::Want(Want {
                    exchange_id: 43,
                    items: vec![want(selected)],
                })))
                .unwrap()
                .is_empty(),
            "an invalidated served snapshot cannot authorize an in-flight WANT"
        );
        state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 43,
                request_id,
                purpose: InventoryPurpose::ServePeer,
                filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
        assert!(
            state
                .apply(SyncEvent::Receive(Message::Want(Want {
                    exchange_id: 43,
                    items: vec![want(selected)],
                })))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn complete_root_offer_is_hash_validated_before_requesting_missing_objects() {
        let local = SparseInventory::from_ids([id(1)]);
        let remote = SparseInventory::from_ids([id(1), id(2)]);
        let mut state = SyncState::new(SyncConfig::default(), local.clone()).unwrap();
        start_with_baseline(&mut state, 43, local);
        let offer = pending_root_offer(&mut state, 43, &remote);

        let actions = state
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        assert_eq!(state.durable_revision(), 1);
        assert!(!state.wants().contains(&id(1)));
        assert!(state.wants().contains(&id(2)));
        assert_eq!(
            actions,
            vec![SyncAction::Send(Message::Want(Want {
                exchange_id: 43,
                items: vec![WantItem {
                    object_id: id(2),
                    total_len: None,
                    missing: Vec::new(),
                    need_forwarding: true,
                }],
            }))]
        );
        assert_eq!(
            state
                .active
                .as_ref()
                .and_then(|exchange| exchange.pending_root_probe),
            None
        );
        let exchange = state.active.as_ref().unwrap();
        assert!(
            !exchange
                .probes_sent
                .iter()
                .any(|(snapshot_id, _)| *snapshot_id == remote.snapshot_id())
        );
        assert!(
            !exchange
                .expected_nodes
                .keys()
                .any(|(snapshot_id, _)| *snapshot_id == remote.snapshot_id())
        );
    }

    #[test]
    fn complete_root_offer_uses_authorized_receive_baseline_for_held_objects() {
        let held = id(1);
        let durable_baseline = SparseInventory::from_ids([held]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 61, durable_baseline.clone());
        let offer = pending_root_offer(&mut state, 61, &durable_baseline);

        assert!(state.inventory.is_empty());
        assert!(
            state
                .receive_inventory
                .as_ref()
                .is_some_and(|inventory| inventory.contains(&held))
        );

        let actions = state
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();

        assert!(state.wants().is_empty());
        assert!(
            !actions.iter().any(|action| matches!(
                action,
                SyncAction::Send(Message::Want(Want { items, .. })) if !items.is_empty()
            )),
            "a durable baseline object must not be requested again"
        );
    }

    #[test]
    fn validated_single_item_offer_is_idempotent_after_local_commit_refresh() {
        let remote = SparseInventory::from_ids([id(1)]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 54, SparseInventory::new());
        let offer = pending_root_offer(&mut state, 54, &remote);
        state
            .apply(SyncEvent::Receive(Message::Offer(offer.clone())))
            .unwrap();
        state
            .apply(SyncEvent::LocalObjectAdded { object_id: id(1) })
            .unwrap();

        let before_duplicate = state.clone();
        assert!(
            state
                .apply(SyncEvent::Receive(Message::Offer(offer.clone())))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.snapshot(), before_duplicate.snapshot());
        assert_eq!(state.active, before_duplicate.active);
        assert_eq!(state.inventory, before_duplicate.inventory);

        let mut truncated = offer.clone();
        truncated.object_ids.clear();
        assert_rejected_offer_preserves_state(&mut state, truncated, SyncError::SnapshotMismatch);
        let mut forged = offer;
        forged.object_ids[0] = id(2);
        assert_rejected_offer_preserves_state(&mut state, forged, SyncError::SnapshotMismatch);
    }

    #[test]
    fn late_unanswered_offer_requires_the_same_interest_and_fresh_authorized_baseline() {
        let remote = SparseInventory::from_ids([id(1)]);
        let mut same_interest =
            SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut same_interest, 56, SparseInventory::new());
        let offer = pending_root_offer(&mut same_interest, 56, &remote);
        let restart_actions = same_interest
            .apply(SyncEvent::Start {
                exchange_id: 56,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
            })
            .unwrap();
        assert_rejected_offer_preserves_state(
            &mut same_interest,
            offer.clone(),
            SyncError::SnapshotMismatch,
        );
        let (request_id, filter) = selection(&restart_actions, InventoryPurpose::ReceiveBaseline);
        let resume_actions = same_interest
            .apply(SyncEvent::InventorySelected {
                exchange_id: 56,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
        assert!(resume_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Probe(Probe {
                exchange_id: 56,
                prefix_nibbles: 0,
                ..
            }))
        )));
        same_interest
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        assert!(same_interest.wants().contains(&id(1)));

        let mut changed_interest =
            SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut changed_interest, 57, SparseInventory::new());
        let offer = pending_root_offer(&mut changed_interest, 57, &remote);
        let changed_actions = changed_interest
            .apply(SyncEvent::Start {
                exchange_id: 57,
                topics: vec!["different".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
            })
            .unwrap();
        let (request_id, filter) = selection(&changed_actions, InventoryPurpose::ReceiveBaseline);
        changed_interest
            .apply(SyncEvent::InventorySelected {
                exchange_id: 57,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
        assert_rejected_offer_preserves_state(
            &mut changed_interest,
            offer,
            SyncError::SnapshotMismatch,
        );

        let mut changed_authority =
            SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut changed_authority, 58, SparseInventory::new());
        let offer = pending_root_offer(&mut changed_authority, 58, &remote);
        let refresh_actions = changed_authority
            .apply(SyncEvent::LocalInventoryChanged)
            .unwrap();
        assert_rejected_offer_preserves_state(
            &mut changed_authority,
            offer.clone(),
            SyncError::SnapshotMismatch,
        );
        let (request_id, filter) = selection(&refresh_actions, InventoryPurpose::ReceiveBaseline);
        let resume_actions = changed_authority
            .apply(SyncEvent::InventorySelected {
                exchange_id: 58,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
        assert!(resume_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Probe(Probe {
                exchange_id: 58,
                prefix_nibbles: 0,
                ..
            }))
        )));
        changed_authority
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        assert!(changed_authority.wants().contains(&id(1)));
    }

    #[test]
    fn offer_first_retires_traversal_and_ignores_delayed_root_node() {
        let remote = SparseInventory::from_ids([id(1)]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 55, SparseInventory::new());
        let offer = pending_root_offer(&mut state, 55, &remote);
        state
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        let node = remote.node(&NibblePrefix::root());
        let before_node = state.clone();
        assert!(
            state
                .apply(SyncEvent::Receive(Message::Node(Node {
                    exchange_id: 55,
                    prefix: Vec::new(),
                    prefix_nibbles: 0,
                    hash: node.hash,
                    item_count: node.item_count,
                    children: node
                        .children
                        .into_iter()
                        .map(|child| ChildSummary {
                            nibble: child.nibble,
                            hash: child.hash,
                            item_count: child.item_count,
                        })
                        .collect(),
                    snapshot_id: remote.snapshot_id(),
                })))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.snapshot(), before_node.snapshot());
        assert_eq!(state.active, before_node.active);
    }

    #[test]
    fn invalid_root_offers_preserve_traversal_and_durable_state() {
        let remote = SparseInventory::from_ids([id(1), id(2)]);

        let mut unsolicited =
            SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut unsolicited, 44, SparseInventory::new());
        assert_rejected_offer_preserves_state(
            &mut unsolicited,
            Offer {
                exchange_id: 44,
                object_ids: vec![id(1), id(2)],
                snapshot_id: remote.snapshot_id(),
            },
            SyncError::SnapshotMismatch,
        );

        let mut stale = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut stale, 45, SparseInventory::new());
        let mut stale_offer = pending_root_offer(&mut stale, 45, &remote);
        stale_offer.snapshot_id = stale_offer.snapshot_id.wrapping_add(1);
        assert_rejected_offer_preserves_state(&mut stale, stale_offer, SyncError::SnapshotMismatch);

        let mut truncated = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut truncated, 46, SparseInventory::new());
        let mut truncated_offer = pending_root_offer(&mut truncated, 46, &remote);
        truncated_offer.object_ids.pop();
        assert_rejected_offer_preserves_state(
            &mut truncated,
            truncated_offer,
            SyncError::SnapshotMismatch,
        );

        let mut forged = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut forged, 47, SparseInventory::new());
        let mut forged_offer = pending_root_offer(&mut forged, 47, &remote);
        forged_offer.object_ids[1] = id(3);
        assert_rejected_offer_preserves_state(
            &mut forged,
            forged_offer,
            SyncError::SnapshotMismatch,
        );

        for (exchange_id, object_ids) in [(48, vec![id(2), id(1)]), (49, vec![id(1), id(1)])] {
            let mut noncanonical =
                SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
            start_with_baseline(&mut noncanonical, exchange_id, SparseInventory::new());
            pending_root_offer(&mut noncanonical, exchange_id, &remote);
            assert_rejected_offer_preserves_state(
                &mut noncanonical,
                Offer {
                    exchange_id,
                    object_ids,
                    snapshot_id: remote.snapshot_id(),
                },
                SyncError::Wire(WireError::NonCanonicalSet("offered identifiers")),
            );
        }

        let mut oversized = SyncState::new(
            SyncConfig {
                max_offer_ids: 1,
                ..SyncConfig::default()
            },
            SparseInventory::new(),
        )
        .unwrap();
        start_with_baseline(&mut oversized, 50, SparseInventory::new());
        let oversized_offer = pending_root_offer(&mut oversized, 50, &remote);
        assert_rejected_offer_preserves_state(
            &mut oversized,
            oversized_offer,
            SyncError::OfferLimit,
        );
    }

    #[test]
    fn valid_root_offer_resource_failure_is_transactional() {
        let remote = SparseInventory::from_ids([id(1)]);
        let mut wants = DurableWants::new();
        wants
            .request(id(9), SyncConfig::default().progress_chunk_size)
            .unwrap();
        let mut bounded = SyncState::restore(
            SyncConfig {
                max_durable_wants: 1,
                ..SyncConfig::default()
            },
            SparseInventory::new(),
            SyncSnapshot { revision: 7, wants },
        )
        .unwrap();
        start_with_baseline(&mut bounded, 52, SparseInventory::new());
        let offer = pending_root_offer(&mut bounded, 52, &remote);
        assert_rejected_offer_preserves_state(&mut bounded, offer, SyncError::WantLimit);

        let mut exhausted = SyncState::restore(
            SyncConfig::default(),
            SparseInventory::new(),
            SyncSnapshot {
                revision: u64::MAX,
                wants: DurableWants::new(),
            },
        )
        .unwrap();
        start_with_baseline(&mut exhausted, 53, SparseInventory::new());
        let offer = pending_root_offer(&mut exhausted, 53, &remote);
        assert_rejected_offer_preserves_state(&mut exhausted, offer, SyncError::RevisionExhausted);
    }

    #[test]
    fn root_node_retires_unvalidated_offer_history_and_rejects_delayed_offer() {
        let remote = SparseInventory::from_ids([id(1)]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 51, SparseInventory::new());
        let delayed_offer = pending_root_offer(&mut state, 51, &remote);
        let node = remote.node(&NibblePrefix::root());
        state
            .apply(SyncEvent::Receive(Message::Node(Node {
                exchange_id: 51,
                prefix: Vec::new(),
                prefix_nibbles: 0,
                hash: node.hash,
                item_count: node.item_count,
                children: node
                    .children
                    .into_iter()
                    .map(|child| ChildSummary {
                        nibble: child.nibble,
                        hash: child.hash,
                        item_count: child.item_count,
                    })
                    .collect(),
                snapshot_id: remote.snapshot_id(),
            })))
            .unwrap();
        assert_eq!(
            state
                .active
                .as_ref()
                .and_then(|exchange| exchange.pending_root_probe),
            None
        );
        assert!(
            state
                .active
                .as_ref()
                .is_some_and(|exchange| exchange.root_offer_history.is_empty())
        );
        assert_rejected_offer_preserves_state(
            &mut state,
            delayed_offer,
            SyncError::SnapshotMismatch,
        );
    }

    #[test]
    fn changed_summary_retires_superseded_offer_before_node_and_refresh() {
        let inventory_a = SparseInventory::from_ids([id(1)]);
        let inventory_b = SparseInventory::from_ids([id(2)]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 59, SparseInventory::new());
        let delayed_offer_a = pending_root_offer(&mut state, 59, &inventory_a);
        let commitment_a = RootProbeExpectation {
            snapshot_id: inventory_a.snapshot_id(),
            root_hash: inventory_a.root_hash(),
            item_count: inventory_a.item_count(),
        };

        let replacement_actions = state
            .apply(SyncEvent::Receive(Message::Summary(Summary {
                exchange_id: 59,
                root_hash: inventory_b.root_hash(),
                item_count: inventory_b.item_count(),
                snapshot_id: inventory_b.snapshot_id(),
            })))
            .unwrap();
        assert!(replacement_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Probe(Probe {
                exchange_id: 59,
                snapshot_id,
                prefix_nibbles: 0,
                ..
            })) if *snapshot_id == inventory_b.snapshot_id()
        )));
        assert!(state.active.as_ref().is_some_and(|exchange| {
            exchange
                .root_offer_history
                .iter()
                .all(|record| record.validated || record.expectation != commitment_a)
        }));

        let node_b = inventory_b.node(&NibblePrefix::root());
        state
            .apply(SyncEvent::Receive(Message::Node(Node {
                exchange_id: 59,
                prefix: Vec::new(),
                prefix_nibbles: 0,
                hash: node_b.hash,
                item_count: node_b.item_count,
                children: node_b
                    .children
                    .into_iter()
                    .map(|child| ChildSummary {
                        nibble: child.nibble,
                        hash: child.hash,
                        item_count: child.item_count,
                    })
                    .collect(),
                snapshot_id: inventory_b.snapshot_id(),
            })))
            .unwrap();
        assert!(
            state
                .active
                .as_ref()
                .is_some_and(|exchange| exchange.root_offer_history.is_empty())
        );

        let refresh_actions = state.apply(SyncEvent::LocalInventoryChanged).unwrap();
        let (request_id, filter) = selection(&refresh_actions, InventoryPurpose::ReceiveBaseline);
        let selected_actions = state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 59,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
        assert!(!selected_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Probe(Probe {
                prefix_nibbles: 0,
                ..
            }))
        )));
        assert_rejected_offer_preserves_state(
            &mut state,
            delayed_offer_a,
            SyncError::SnapshotMismatch,
        );
    }

    #[test]
    fn root_offer_history_is_capped_resumes_newest_and_rejects_evicted_offer() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 60, SparseInventory::new());
        let commitment_count = MAX_ROOT_OFFER_HISTORY + 2;
        let mut offers = Vec::with_capacity(commitment_count);

        for index in 0..commitment_count {
            let byte = u8::try_from(index + 1).expect("small bounded test index");
            let inventory = SparseInventory::from_ids([id(byte)]);
            let offer = pending_root_offer(&mut state, 60, &inventory);
            offers.push(offer.clone());
            if index + 1 < commitment_count {
                state
                    .apply(SyncEvent::Receive(Message::Offer(offer)))
                    .unwrap();
            }
            assert!(state.active.as_ref().is_some_and(|exchange| {
                exchange.root_offer_history.len() <= MAX_ROOT_OFFER_HISTORY
            }));
        }

        let oldest_evicted = offers.first().cloned().expect("oldest OFFER");
        let newest_unanswered = offers.last().cloned().expect("newest OFFER");
        assert_eq!(
            state
                .active
                .as_ref()
                .expect("active exchange")
                .root_offer_history
                .len(),
            MAX_ROOT_OFFER_HISTORY
        );

        let refresh_actions = state.apply(SyncEvent::LocalInventoryChanged).unwrap();
        let (request_id, filter) = selection(&refresh_actions, InventoryPurpose::ReceiveBaseline);
        let resume_actions = state
            .apply(SyncEvent::InventorySelected {
                exchange_id: 60,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory: SparseInventory::new(),
            })
            .unwrap();
        assert!(resume_actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Probe(Probe {
                exchange_id: 60,
                snapshot_id,
                prefix_nibbles: 0,
                ..
            })) if *snapshot_id == newest_unanswered.snapshot_id
        )));
        state
            .apply(SyncEvent::Receive(Message::Offer(
                newest_unanswered.clone(),
            )))
            .unwrap();
        assert!(
            state
                .wants()
                .contains(newest_unanswered.object_ids.first().expect("newest object"))
        );
        assert_eq!(
            state
                .active
                .as_ref()
                .expect("active exchange")
                .root_offer_history
                .len(),
            MAX_ROOT_OFFER_HISTORY
        );

        assert_rejected_offer_preserves_state(
            &mut state,
            oldest_evicted,
            SyncError::SnapshotMismatch,
        );
    }

    #[test]
    fn stale_or_unrequested_inventory_selection_is_rejected() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let actions = state
            .apply(SyncEvent::Start {
                exchange_id: 4,
                topics: vec!["alpha".into()],
                scopes: vec!["mission".into()],
                min_priority: 0,
            })
            .unwrap();
        let (request_id, mut filter) = selection(&actions, InventoryPurpose::ReceiveBaseline);
        filter.topics = vec!["different".into()];
        assert_eq!(
            state.apply(SyncEvent::InventorySelected {
                exchange_id: 4,
                request_id,
                purpose: InventoryPurpose::ReceiveBaseline,
                filter,
                inventory: SparseInventory::new(),
            }),
            Err(SyncError::InventorySelectionMismatch)
        );
    }

    #[test]
    fn range_progress_has_exact_ranges_and_bitmap() {
        let mut progress = WantProgress::new(4).unwrap();
        progress.set_total_len(10).unwrap();
        progress
            .mark_received(ByteRange { start: 8, end: 10 })
            .unwrap();
        progress
            .mark_received(ByteRange { start: 0, end: 4 })
            .unwrap();
        progress
            .mark_received(ByteRange { start: 4, end: 6 })
            .unwrap();
        assert_eq!(progress.completed_bitmap().unwrap(), vec![0xa0]);
        assert_eq!(
            progress.missing_ranges(),
            vec![ByteRange { start: 6, end: 8 }]
        );
    }

    #[test]
    fn snapshot_round_trip_and_bitmap_tamper_rejection() {
        let mut wants = DurableWants::new();
        wants.request(id(1), 4).unwrap();
        let progress = wants.get_mut(&id(1)).unwrap();
        progress.set_total_len(8).unwrap();
        progress
            .mark_received(ByteRange { start: 0, end: 4 })
            .unwrap();
        let snapshot = SyncSnapshot { revision: 3, wants };
        let encoded = snapshot.encode(Limits::default()).unwrap();
        assert_eq!(
            SyncSnapshot::decode(&encoded, Limits::default()).unwrap(),
            snapshot
        );

        let mut value = wire::decode_value(&encoded, Limits::default()).unwrap();
        if let Value::Map(root) = &mut value
            && let Value::Array(wants) = &mut root[2].1
            && let Value::Map(want) = &mut wants[0]
        {
            want[4].1 = Value::Bytes(vec![0]);
        }
        let tampered = wire::encode_value(&value, Limits::default()).unwrap();
        assert_eq!(
            SyncSnapshot::decode(&tampered, Limits::default()),
            Err(SyncError::BitmapMismatch)
        );
    }

    #[test]
    fn duplicate_and_reordered_data_only_store_missing_bytes_once() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 10, SparseInventory::new());
        let remote = SparseInventory::from_ids([id(1)]);
        let offer = pending_root_offer(&mut state, 10, &remote);
        state
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();

        let second = Message::Data(Data {
            exchange_id: 10,
            object_id: id(1),
            total_len: 8,
            offset: 4,
            payload: b"efgh".to_vec(),
            forwarding: b"forward".to_vec(),
        });
        let first_actions = state.apply(SyncEvent::Receive(second.clone())).unwrap();
        assert!(matches!(
            first_actions.as_slice(),
            [SyncAction::StoreChunk { offset: 4, .. }]
        ));
        assert!(state.apply(SyncEvent::Receive(second)).unwrap().is_empty());
        state
            .apply(SyncEvent::ChunkStored {
                object_id: id(1),
                total_len: 8,
                range: ByteRange { start: 4, end: 8 },
            })
            .unwrap();

        let overlapping = Message::Data(Data {
            exchange_id: 10,
            object_id: id(1),
            total_len: 8,
            offset: 2,
            payload: b"cdef".to_vec(),
            forwarding: b"forward".to_vec(),
        });
        let actions = state.apply(SyncEvent::Receive(overlapping)).unwrap();
        assert!(matches!(
            actions.as_slice(),
            [SyncAction::StoreChunk { offset: 2, bytes, .. }] if bytes == b"cd"
        ));
    }

    #[test]
    fn checkpoint_resumes_missing_ranges_with_a_different_exchange() {
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        start_with_baseline(&mut state, 10, SparseInventory::new());
        let remote = SparseInventory::from_ids([id(2)]);
        let offer = pending_root_offer(&mut state, 10, &remote);
        state
            .apply(SyncEvent::Receive(Message::Offer(offer)))
            .unwrap();
        state
            .apply(SyncEvent::Receive(Message::Data(Data {
                exchange_id: 10,
                object_id: id(2),
                total_len: 8,
                offset: 4,
                payload: b"efgh".to_vec(),
                forwarding: b"forward".to_vec(),
            })))
            .unwrap();
        state
            .apply(SyncEvent::ChunkStored {
                object_id: id(2),
                total_len: 8,
                range: ByteRange { start: 4, end: 8 },
            })
            .unwrap();

        let encoded = state.snapshot().encode(Limits::default()).unwrap();
        let snapshot = SyncSnapshot::decode(&encoded, Limits::default()).unwrap();
        let mut restored =
            SyncState::restore(SyncConfig::default(), SparseInventory::new(), snapshot).unwrap();
        let actions = restored
            .apply(SyncEvent::Start {
                exchange_id: 99,
                topics: vec!["mission".into()],
                scopes: vec!["team".into()],
                min_priority: 0,
            })
            .unwrap();
        let want = actions.iter().find_map(|action| match action {
            SyncAction::Send(Message::Want(want)) => Some(want),
            _ => None,
        });
        assert_eq!(
            want.unwrap().items,
            vec![WantItem {
                object_id: id(2),
                total_len: Some(8),
                missing: vec![ByteRange { start: 0, end: 4 }],
                need_forwarding: true,
            }]
        );
    }

    #[test]
    fn duplicate_completion_is_idempotent() {
        let config = SyncConfig {
            accept_unsolicited_data: true,
            ..SyncConfig::default()
        };
        let mut state = SyncState::new(config, SparseInventory::new()).unwrap();
        start(&mut state, 1);
        state
            .apply(SyncEvent::Receive(Message::Data(Data {
                exchange_id: 1,
                object_id: id(3),
                total_len: 4,
                offset: 0,
                payload: b"data".to_vec(),
                forwarding: b"forward".to_vec(),
            })))
            .unwrap();
        let actions = state
            .apply(SyncEvent::ChunkStored {
                object_id: id(3),
                total_len: 4,
                range: ByteRange { start: 0, end: 4 },
            })
            .unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, SyncAction::CompleteObject { .. }))
        );
        assert!(
            state
                .apply(SyncEvent::ChunkStored {
                    object_id: id(3),
                    total_len: 4,
                    range: ByteRange { start: 0, end: 4 },
                })
                .unwrap()
                .is_empty()
        );
        state
            .apply(SyncEvent::ObjectCommitted {
                object_id: id(3),
                item_id: Some([0x33; 32]),
            })
            .unwrap();
        assert!(
            state
                .apply(SyncEvent::ObjectCommitted {
                    object_id: id(3),
                    item_id: Some([0x33; 32]),
                })
                .unwrap()
                .is_empty()
        );
        assert!(state.inventory().contains(&id(3)));
    }

    #[test]
    fn duplicate_data_after_commit_reissues_complete_receipt() {
        let object_id = id(9);
        let mut state = SyncState::new(
            SyncConfig::default(),
            SparseInventory::from_ids([object_id]),
        )
        .unwrap();
        start(&mut state, 12);
        let actions = state
            .apply(SyncEvent::Receive(Message::Data(Data {
                exchange_id: 12,
                object_id,
                total_len: 4,
                offset: 0,
                payload: b"data".to_vec(),
                forwarding: b"forward".to_vec(),
            })))
            .unwrap();
        assert_eq!(
            actions,
            vec![SyncAction::Send(Message::Receipt(Receipt {
                exchange_id: 12,
                object_id,
                total_len: 4,
                received: vec![ByteRange { start: 0, end: 4 }],
                complete: true,
            }))]
        );
    }

    #[test]
    fn duplicate_durable_partial_data_reissues_current_receipt() {
        let object_id = id(10);
        let mut state = SyncState::new(
            SyncConfig {
                accept_unsolicited_data: true,
                ..SyncConfig::default()
            },
            SparseInventory::new(),
        )
        .unwrap();
        start(&mut state, 13);
        let data = Message::Data(Data {
            exchange_id: 13,
            object_id,
            total_len: 8,
            offset: 0,
            payload: b"part".to_vec(),
            forwarding: b"forward".to_vec(),
        });
        let first = state.apply(SyncEvent::Receive(data.clone())).unwrap();
        assert!(first.iter().any(|action| matches!(
            action,
            SyncAction::StoreChunk {
                object_id: stored,
                offset: 0,
                bytes,
                ..
            } if *stored == object_id && bytes == b"part"
        )));
        assert!(
            state
                .apply(SyncEvent::Receive(data.clone()))
                .unwrap()
                .is_empty(),
            "bytes covered only by a pending write are not acknowledged"
        );
        let stored_actions = state
            .apply(SyncEvent::ChunkStored {
                object_id,
                total_len: 8,
                range: ByteRange { start: 0, end: 4 },
            })
            .unwrap();
        assert_eq!(
            stored_actions,
            vec![
                SyncAction::Send(Message::Receipt(Receipt {
                    exchange_id: 13,
                    object_id,
                    total_len: 8,
                    received: vec![ByteRange { start: 0, end: 4 }],
                    complete: false,
                })),
                SyncAction::Send(Message::Want(Want {
                    exchange_id: 13,
                    items: vec![WantItem {
                        object_id,
                        total_len: Some(8),
                        missing: vec![ByteRange { start: 4, end: 8 }],
                        need_forwarding: false,
                    }],
                })),
            ]
        );

        assert_eq!(
            state.apply(SyncEvent::Receive(data)).unwrap(),
            vec![SyncAction::Send(Message::Receipt(Receipt {
                exchange_id: 13,
                object_id,
                total_len: 8,
                received: vec![ByteRange { start: 0, end: 4 }],
                complete: false,
            }))]
        );
    }

    #[test]
    fn terminal_rejection_resets_known_length_ranges_and_forwarding() {
        let config = SyncConfig {
            accept_unsolicited_data: true,
            ..SyncConfig::default()
        };
        let mut state = SyncState::new(config, SparseInventory::new()).unwrap();
        start(&mut state, 7);
        state
            .apply(SyncEvent::Receive(Message::Data(Data {
                exchange_id: 7,
                object_id: id(0x44),
                total_len: 8,
                offset: 0,
                payload: b"poisoned".to_vec(),
                forwarding: b"authenticated-hop".to_vec(),
            })))
            .unwrap();
        state
            .apply(SyncEvent::ChunkStored {
                object_id: id(0x44),
                total_len: 8,
                range: ByteRange { start: 0, end: 8 },
            })
            .unwrap();

        let actions = state
            .apply(SyncEvent::ObjectRejected {
                object_id: id(0x44),
            })
            .unwrap();
        let progress = state.wants().get(&id(0x44)).unwrap();
        assert_eq!(progress.total_len(), None);
        assert!(progress.received_ranges().is_empty());
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Want(Want { items, .. }))
                if items == &[WantItem {
                    object_id: id(0x44),
                    total_len: None,
                    missing: Vec::new(),
                    need_forwarding: true,
                }]
        )));
    }

    #[test]
    fn completed_dependency_pending_object_is_not_accepted_or_inventoried() {
        let compact = id(0x61);
        let proof = ObjectId::new(ObjectKind::SourceBatchProof, [0x62; 32]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        state
            .hydrate_durable_progress_for_semantic_version(
                [(compact, 8, vec![ByteRange { start: 0, end: 8 }])],
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();
        state
            .apply_for_semantic_version(
                SyncEvent::Start {
                    exchange_id: 19,
                    topics: vec!["mission".into()],
                    scopes: vec!["team".into()],
                    min_priority: 0,
                },
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();

        let actions = state
            .apply_for_semantic_version(
                SyncEvent::ObjectDeferred {
                    object_id: compact,
                    dependencies: vec![proof, proof],
                },
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();

        assert!(!state.inventory().contains(&compact));
        assert!(!state.wants().contains(&compact));
        assert!(state.wants().contains(&proof));
        assert!(actions.iter().any(|action| matches!(
            action,
            SyncAction::Send(Message::Want(Want { items, .. }))
                if items.len() == 1 && items[0].object_id == proof
        )));
    }

    #[test]
    fn completed_quarantined_object_retires_transport_without_visibility() {
        let source = id(0x69);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        state
            .hydrate_durable_progress_for_semantic_version(
                [(source, 8, vec![ByteRange { start: 0, end: 8 }])],
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();
        state
            .apply_for_semantic_version(
                SyncEvent::Start {
                    exchange_id: 23,
                    topics: vec!["mission".into()],
                    scopes: vec!["team".into()],
                    min_priority: 0,
                },
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();

        let actions = state
            .apply_for_semantic_version(
                SyncEvent::ObjectQuarantined { object_id: source },
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();

        assert!(actions.is_empty());
        assert!(!state.inventory().contains(&source));
        assert!(!state.wants().contains(&source));
    }

    #[test]
    fn dependency_hydration_is_version_gated_and_peer_neutral() {
        let proof = ObjectId::new(ObjectKind::SourceBatchProof, [0x71; 32]);
        let authorization = ObjectId::new(ObjectKind::BridgeAuthorization, [0x72; 32]);
        let mut v1 = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        v1.hydrate_dependency_wants_for_semantic_version(
            [proof, authorization],
            wire::SEMANTIC_PROTOCOL_V1,
        )
        .unwrap();
        assert!(v1.wants().is_empty());

        let mut v2 = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        v2.hydrate_dependency_wants_for_semantic_version(
            [authorization, proof, proof],
            wire::SEMANTIC_PROTOCOL_V2,
        )
        .unwrap();
        assert_eq!(v2.wants().len(), 2);
        assert!(v2.wants().contains(&proof));
        assert!(v2.wants().contains(&authorization));
    }

    #[test]
    fn selected_v1_rejects_v2_dependency_before_reducer_effects() {
        let compact = id(0x81);
        let proof = ObjectId::new(ObjectKind::SourceBatchProof, [0x82; 32]);
        let mut state = SyncState::new(SyncConfig::default(), SparseInventory::new()).unwrap();
        let before = state.snapshot();
        let result = state.apply_for_semantic_version(
            SyncEvent::ObjectDeferred {
                object_id: compact,
                dependencies: vec![proof],
            },
            wire::SEMANTIC_PROTOCOL_V1,
        );
        assert!(matches!(
            result,
            Err(SyncError::Wire(WireError::ObjectKindRequiresSemanticV2(
                ObjectKind::SourceBatchProof
            )))
        ));
        assert_eq!(state.snapshot(), before);
        assert!(state.inventory().is_empty());
    }

    #[test]
    fn dependency_limit_failure_leaves_completed_object_progress_unchanged() {
        let compact = id(0x91);
        let proof = ObjectId::new(ObjectKind::SourceBatchProof, [0x92; 32]);
        let authorization = ObjectId::new(ObjectKind::BridgeAuthorization, [0x93; 32]);
        let mut state = SyncState::new(
            SyncConfig {
                max_durable_wants: 1,
                ..SyncConfig::default()
            },
            SparseInventory::new(),
        )
        .unwrap();
        state
            .hydrate_durable_progress_for_semantic_version(
                [(compact, 4, vec![ByteRange { start: 0, end: 4 }])],
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();
        state
            .apply_for_semantic_version(
                SyncEvent::Start {
                    exchange_id: 29,
                    topics: vec!["mission".into()],
                    scopes: vec!["team".into()],
                    min_priority: 0,
                },
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();

        assert!(matches!(
            state.apply_for_semantic_version(
                SyncEvent::ObjectDeferred {
                    object_id: compact,
                    dependencies: vec![proof, authorization],
                },
                wire::SEMANTIC_PROTOCOL_V2,
            ),
            Err(SyncError::WantLimit)
        ));
        let progress = state.wants().get(&compact).unwrap();
        assert!(progress.is_complete());
        assert!(!state.wants().contains(&proof));
        assert!(!state.wants().contains(&authorization));
    }
}
