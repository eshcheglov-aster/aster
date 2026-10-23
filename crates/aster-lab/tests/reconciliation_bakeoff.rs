//! Test-only comparison of Aster's exact reconciliation reducer with public
//! set-reconciliation candidates. Candidate frames never reach production
//! decoders or transport code from this harness.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::error::Error;
use std::io;
use std::time::Instant;

use aster_mesh::inventory::SparseInventory;
use aster_mesh::sync::{
    InterestFilter, InventoryPurpose, SyncAction, SyncConfig, SyncEvent, SyncState,
};
use aster_mesh::wire::{self, Limits, Message, ObjectId, ObjectKind};
use negentropy::{Id, Negentropy, NegentropyStorageVector};

const EXCHANGE_ID: u64 = 0x0041_5354_4552;
const NEGENTROPY_FRAME_LIMIT: u64 = 4_096;
const MAX_INVENTORY_ITEMS: usize = 100_000;
const MAX_ASTER_MESSAGES: u64 = 1_000_000;
const MAX_CANDIDATE_MESSAGES: u64 = 100_000;
const MATRIX_CARDINALITIES: [usize; 5] = [1, 256, 1_000, 10_000, 100_000];
const MATRIX_BASE_DELTAS_EACH: [usize; 5] = [0, 1, 10, 100, 1_000];
const V1_OBJECT_KINDS: [ObjectKind; 2] = [ObjectKind::SourceEnvelope, ObjectKind::BlobChunk];

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug)]
enum Shape {
    Uniform,
    Clustered,
}

impl Shape {
    const ALL: [Self; 2] = [Self::Uniform, Self::Clustered];

    const fn label(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::Clustered => "clustered",
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Difference {
    only_left: BTreeSet<ObjectId>,
    only_right: BTreeSet<ObjectId>,
}

#[derive(Debug, Default)]
struct ProtocolMetrics {
    build_ns: u128,
    reconcile_ns: u128,
    messages: u64,
    logical_message_depth: u64,
    encoded_bytes: u64,
    maximum_message_bytes: u64,
    peak_pending_encoded_bytes: u64,
    interest_bytes: u64,
    inventory_bytes: u64,
    want_bytes: u64,
}

#[derive(Debug, Default)]
struct Measurement {
    difference: Difference,
    metrics: ProtocolMetrics,
}

fn invalid(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn checked_len(value: usize) -> TestResult<u64> {
    u64::try_from(value).map_err(|_| invalid("measurement exceeded u64"))
}

fn validate_inventory_sizes(left: usize, right: usize) -> TestResult<()> {
    if left > MAX_INVENTORY_ITEMS || right > MAX_INVENTORY_ITEMS {
        return Err(invalid(format!(
            "inventory exceeds the {MAX_INVENTORY_ITEMS}-item bake-off ceiling"
        )));
    }
    Ok(())
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn fixture_id(index: usize, shape: Shape) -> TestResult<ObjectId> {
    let index = u64::try_from(index).map_err(|_| invalid("fixture index exceeds u64"))?;
    let mut digest = [0_u8; 32];
    match shape {
        Shape::Uniform => {
            for lane in 0_u64..3 {
                let start = usize::try_from(lane * 8)
                    .map_err(|_| invalid("fixture lane conversion failed"))?;
                digest[start..start + 8].copy_from_slice(
                    &splitmix64(index ^ lane.wrapping_mul(0xd6e8_feb8_6659_fd93)).to_be_bytes(),
                );
            }
            // Retaining the full index makes uniqueness deterministic rather
            // than relying on the pseudo-random fixture prefix not colliding.
            digest[24..].copy_from_slice(&index.to_be_bytes());
        }
        Shape::Clustered => {
            digest[..24].fill(0x42);
            digest[24..].copy_from_slice(&index.to_be_bytes());
        }
    }
    Ok(ObjectId::new(ObjectKind::SourceEnvelope, digest))
}

fn balanced_fixture(
    items_each: usize,
    delta_each: usize,
    shape: Shape,
) -> TestResult<(BTreeSet<ObjectId>, BTreeSet<ObjectId>)> {
    validate_inventory_sizes(items_each, items_each)?;
    if delta_each > items_each {
        return Err(invalid("per-side difference exceeds inventory size"));
    }
    let common = items_each - delta_each;
    let mut left = BTreeSet::new();
    let mut right = BTreeSet::new();
    for index in 0..common {
        let id = fixture_id(index, shape)?;
        left.insert(id);
        right.insert(id);
    }
    for index in common..items_each {
        left.insert(fixture_id(index, shape)?);
    }
    for index in items_each..items_each + delta_each {
        right.insert(fixture_id(index, shape)?);
    }
    if left.len() != items_each || right.len() != items_each {
        return Err(invalid("fixture generator produced a duplicate identifier"));
    }
    Ok((left, right))
}

fn exact_difference(left: &BTreeSet<ObjectId>, right: &BTreeSet<ObjectId>) -> Difference {
    Difference {
        only_left: left.difference(right).copied().collect(),
        only_right: right.difference(left).copied().collect(),
    }
}

fn grouped_digests(inventory: &BTreeSet<ObjectId>) -> BTreeMap<ObjectKind, Vec<[u8; 32]>> {
    let mut grouped = BTreeMap::<ObjectKind, Vec<[u8; 32]>>::new();
    for object_id in inventory {
        grouped
            .entry(object_id.kind())
            .or_default()
            .push(*object_id.digest());
    }
    grouped
}

fn negentropy_storage(ids: &[[u8; 32]]) -> TestResult<NegentropyStorageVector> {
    let mut storage = NegentropyStorageVector::with_capacity(ids.len());
    for id in ids {
        storage.insert(0, Id::from_byte_array(*id))?;
    }
    storage.seal()?;
    Ok(storage)
}

fn count_candidate_message(metrics: &mut ProtocolMetrics, message: &[u8]) -> TestResult<()> {
    let bytes = checked_len(message.len())?;
    if bytes > NEGENTROPY_FRAME_LIMIT {
        return Err(invalid("candidate exceeded its configured frame limit"));
    }
    metrics.messages = metrics
        .messages
        .checked_add(1)
        .ok_or_else(|| invalid("candidate message count overflow"))?;
    if metrics.messages > MAX_CANDIDATE_MESSAGES {
        return Err(invalid("candidate exceeded the message ceiling"));
    }
    metrics.encoded_bytes = metrics
        .encoded_bytes
        .checked_add(bytes)
        .ok_or_else(|| invalid("candidate byte count overflow"))?;
    metrics.maximum_message_bytes = metrics.maximum_message_bytes.max(bytes);
    // The honest driver is strictly alternating, so only one complete raw
    // candidate frame is pending at a time.
    metrics.peak_pending_encoded_bytes = metrics.peak_pending_encoded_bytes.max(bytes);
    Ok(())
}

struct CandidateKindStorage {
    kind: ObjectKind,
    left: NegentropyStorageVector,
    right: NegentropyStorageVector,
}

fn reconcile_candidate_direction(
    storage: &CandidateKindStorage,
    client_is_left: bool,
    measurement: &mut Measurement,
) -> TestResult<()> {
    let (client_storage, server_storage) = if client_is_left {
        (&storage.left, &storage.right)
    } else {
        (&storage.right, &storage.left)
    };
    let mut client = Negentropy::borrowed(client_storage, NEGENTROPY_FRAME_LIMIT)?;
    let mut server = Negentropy::borrowed(server_storage, NEGENTROPY_FRAME_LIMIT)?;
    let mut session_depth = 0_u64;
    let mut query = client.initiate()?;
    count_candidate_message(&mut measurement.metrics, &query)?;
    session_depth = session_depth
        .checked_add(1)
        .ok_or_else(|| invalid("candidate logical depth overflow"))?;
    loop {
        let response = server.reconcile(&query)?;
        count_candidate_message(&mut measurement.metrics, &response)?;
        session_depth = session_depth
            .checked_add(1)
            .ok_or_else(|| invalid("candidate logical depth overflow"))?;

        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        let next = client.reconcile_with_ids(&response, &mut have_ids, &mut need_ids)?;
        let have_ids = have_ids
            .into_iter()
            .map(|id| ObjectId::new(storage.kind, id.to_bytes()));
        let need_ids = need_ids
            .into_iter()
            .map(|id| ObjectId::new(storage.kind, id.to_bytes()));
        if client_is_left {
            measurement.difference.only_left.extend(have_ids);
            measurement.difference.only_right.extend(need_ids);
        } else {
            measurement.difference.only_right.extend(have_ids);
            measurement.difference.only_left.extend(need_ids);
        }
        let Some(next) = next else {
            break;
        };
        query = next;
        count_candidate_message(&mut measurement.metrics, &query)?;
        session_depth = session_depth
            .checked_add(1)
            .ok_or_else(|| invalid("candidate logical depth overflow"))?;
    }
    measurement.metrics.logical_message_depth =
        measurement.metrics.logical_message_depth.max(session_depth);
    Ok(())
}

fn measure_negentropy(
    left: &BTreeSet<ObjectId>,
    right: &BTreeSet<ObjectId>,
) -> TestResult<Measurement> {
    validate_inventory_sizes(left.len(), right.len())?;
    if left
        .iter()
        .chain(right.iter())
        .any(|id| !V1_OBJECT_KINDS.contains(&id.kind()))
    {
        return Err(invalid("candidate fixture contains a non-v1 object kind"));
    }

    let build_started = Instant::now();
    let left_by_kind = grouped_digests(left);
    let right_by_kind = grouped_digests(right);
    let mut storages = Vec::with_capacity(V1_OBJECT_KINDS.len());
    for kind in V1_OBJECT_KINDS {
        let left_ids = left_by_kind.get(&kind).map(Vec::as_slice).unwrap_or(&[]);
        let right_ids = right_by_kind.get(&kind).map(Vec::as_slice).unwrap_or(&[]);
        storages.push(CandidateKindStorage {
            kind,
            left: negentropy_storage(left_ids)?,
            right: negentropy_storage(right_ids)?,
        });
    }

    let mut measurement = Measurement::default();
    measurement.metrics.build_ns = build_started.elapsed().as_nanos();
    let reconcile_started = Instant::now();
    for storage in &storages {
        // The crate exposes differences only to its initiator. Fixed forward
        // and reverse sessions let both peers learn their missing identifiers,
        // matching Aster's full-duplex baseline without inventing an unmeasured
        // result wrapper.
        reconcile_candidate_direction(storage, true, &mut measurement)?;
        reconcile_candidate_direction(storage, false, &mut measurement)?;
    }
    measurement.metrics.reconcile_ns = reconcile_started.elapsed().as_nanos();
    Ok(measurement)
}

#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

impl Side {
    const fn other(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

struct PendingMessage {
    receiver: Side,
    encoded: Vec<u8>,
    encoded_len: u64,
    depth: u64,
}

struct AsterHarness {
    left: SyncState,
    right: SyncState,
    left_inventory: SparseInventory,
    right_inventory: SparseInventory,
    pending: VecDeque<PendingMessage>,
    queued_bytes: u64,
    difference: Difference,
    metrics: ProtocolMetrics,
}

impl AsterHarness {
    fn new(left_inventory: SparseInventory, right_inventory: SparseInventory) -> TestResult<Self> {
        Ok(Self {
            left: SyncState::new(SyncConfig::default(), SparseInventory::new())?,
            right: SyncState::new(SyncConfig::default(), SparseInventory::new())?,
            left_inventory,
            right_inventory,
            pending: VecDeque::new(),
            queued_bytes: 0,
            difference: Difference::default(),
            metrics: ProtocolMetrics::default(),
        })
    }

    fn start_actions(&mut self, side: Side) -> TestResult<Vec<SyncAction>> {
        let event = SyncEvent::Start {
            exchange_id: EXCHANGE_ID,
            topics: vec!["bakeoff".into()],
            scopes: vec!["lab".into()],
            min_priority: 0,
        };
        Ok(match side {
            Side::Left => self.left.apply(event)?,
            Side::Right => self.right.apply(event)?,
        })
    }

    fn receive(&mut self, side: Side, message: Message) -> TestResult<Vec<SyncAction>> {
        Ok(match side {
            Side::Left => self.left.apply(SyncEvent::Receive(message))?,
            Side::Right => self.right.apply(SyncEvent::Receive(message))?,
        })
    }

    fn select_inventory(
        &mut self,
        side: Side,
        request_id: u64,
        purpose: InventoryPurpose,
        filter: InterestFilter,
    ) -> TestResult<Vec<SyncAction>> {
        let inventory = match side {
            Side::Left => self.left_inventory.clone(),
            Side::Right => self.right_inventory.clone(),
        };
        let event = SyncEvent::InventorySelected {
            exchange_id: EXCHANGE_ID,
            request_id,
            purpose,
            filter,
            inventory,
        };
        Ok(match side {
            Side::Left => self.left.apply(event)?,
            Side::Right => self.right.apply(event)?,
        })
    }

    fn enqueue(&mut self, sender: Side, depth: u64, message: Message) -> TestResult<()> {
        let encoded = wire::encode_message(&message, Limits::default())?;
        let encoded_len = checked_len(encoded.len())?;
        self.metrics.messages = self
            .metrics
            .messages
            .checked_add(1)
            .ok_or_else(|| invalid("Aster message count overflow"))?;
        if self.metrics.messages > MAX_ASTER_MESSAGES {
            return Err(invalid("Aster reducer exceeded the message ceiling"));
        }
        self.metrics.encoded_bytes = self
            .metrics
            .encoded_bytes
            .checked_add(encoded_len)
            .ok_or_else(|| invalid("Aster byte count overflow"))?;
        self.metrics.maximum_message_bytes = self.metrics.maximum_message_bytes.max(encoded_len);
        match &message {
            Message::Interest(_) => {
                self.metrics.interest_bytes = self
                    .metrics
                    .interest_bytes
                    .checked_add(encoded_len)
                    .ok_or_else(|| invalid("Aster interest byte count overflow"))?;
            }
            Message::Summary(_) | Message::Probe(_) | Message::Node(_) | Message::Offer(_) => {
                self.metrics.inventory_bytes = self
                    .metrics
                    .inventory_bytes
                    .checked_add(encoded_len)
                    .ok_or_else(|| invalid("Aster inventory byte count overflow"))?;
            }
            Message::Want(_) => {
                self.metrics.want_bytes = self
                    .metrics
                    .want_bytes
                    .checked_add(encoded_len)
                    .ok_or_else(|| invalid("Aster want byte count overflow"))?;
            }
            Message::Data(_) | Message::Receipt(_) => {
                return Err(invalid("bake-off unexpectedly entered object transfer"));
            }
        }
        self.queued_bytes = self
            .queued_bytes
            .checked_add(encoded_len)
            .ok_or_else(|| invalid("Aster queued byte count overflow"))?;
        self.metrics.peak_pending_encoded_bytes = self
            .metrics
            .peak_pending_encoded_bytes
            .max(self.queued_bytes);
        let next_depth = depth
            .checked_add(1)
            .ok_or_else(|| invalid("Aster logical depth overflow"))?;
        self.metrics.logical_message_depth = self.metrics.logical_message_depth.max(next_depth);
        self.pending.push_back(PendingMessage {
            receiver: sender.other(),
            encoded,
            encoded_len,
            depth: next_depth,
        });
        Ok(())
    }

    fn process_actions(
        &mut self,
        side: Side,
        depth: u64,
        actions: Vec<SyncAction>,
    ) -> TestResult<()> {
        let mut work: VecDeque<_> = actions.into_iter().collect();
        while let Some(action) = work.pop_front() {
            match action {
                SyncAction::Send(message) => self.enqueue(side, depth, message)?,
                SyncAction::SelectInventory {
                    request_id,
                    purpose,
                    filter,
                } => {
                    work.extend(self.select_inventory(side, request_id, purpose, filter)?);
                }
                SyncAction::Serve(item) => match side {
                    Side::Left => {
                        self.difference.only_left.insert(item.object_id);
                    }
                    Side::Right => {
                        self.difference.only_right.insert(item.object_id);
                    }
                },
                SyncAction::StoreChunk { .. } | SyncAction::CompleteObject { .. } => {
                    return Err(invalid("bake-off unexpectedly entered object storage"));
                }
            }
        }
        Ok(())
    }

    fn run(mut self) -> TestResult<Measurement> {
        let left_actions = self.start_actions(Side::Left)?;
        self.process_actions(Side::Left, 0, left_actions)?;
        let right_actions = self.start_actions(Side::Right)?;
        self.process_actions(Side::Right, 0, right_actions)?;

        while let Some(pending) = self.pending.pop_front() {
            self.queued_bytes = self
                .queued_bytes
                .checked_sub(pending.encoded_len)
                .ok_or_else(|| invalid("Aster queued byte accounting underflow"))?;
            let message = wire::decode_message(&pending.encoded, Limits::default())?;
            let actions = self.receive(pending.receiver, message)?;
            self.process_actions(pending.receiver, pending.depth, actions)?;
        }
        Ok(Measurement {
            difference: self.difference,
            metrics: self.metrics,
        })
    }
}

fn measure_aster(left: &BTreeSet<ObjectId>, right: &BTreeSet<ObjectId>) -> TestResult<Measurement> {
    validate_inventory_sizes(left.len(), right.len())?;
    let build_started = Instant::now();
    let left_inventory = SparseInventory::from_ids(left.iter().copied());
    let right_inventory = SparseInventory::from_ids(right.iter().copied());
    let build_ns = build_started.elapsed().as_nanos();
    let reconcile_started = Instant::now();
    let mut measurement = AsterHarness::new(left_inventory, right_inventory)?.run()?;
    measurement.metrics.build_ns = build_ns;
    measurement.metrics.reconcile_ns = reconcile_started.elapsed().as_nanos();
    Ok(measurement)
}

fn assert_exact(expected: &Difference, actual: &Measurement, algorithm: &str) -> TestResult<()> {
    if &actual.difference != expected {
        return Err(invalid(format!(
            "{algorithm} did not reproduce the exact set difference"
        )));
    }
    Ok(())
}

fn assert_candidate_matches_oracle(
    items_each: usize,
    delta_each: usize,
    shape: Shape,
) -> TestResult<()> {
    let (left, right) = balanced_fixture(items_each, delta_each, shape)?;
    let expected = exact_difference(&left, &right);
    assert_exact(&expected, &measure_aster(&left, &right)?, "Aster")?;
    assert_exact(&expected, &measure_negentropy(&left, &right)?, "Negentropy")?;
    Ok(())
}

#[test]
fn exact_oracle_matches_one_uniform_item_without_delta() -> TestResult<()> {
    assert_candidate_matches_oracle(1, 0, Shape::Uniform)
}

#[test]
fn exact_oracle_matches_one_clustered_item_with_full_delta() -> TestResult<()> {
    assert_candidate_matches_oracle(1, 1, Shape::Clustered)
}

#[test]
fn exact_oracle_matches_thirty_two_uniform_items_with_one_delta() -> TestResult<()> {
    assert_candidate_matches_oracle(32, 1, Shape::Uniform)
}

#[test]
fn exact_oracle_matches_two_hundred_fifty_six_clustered_items_with_ten_delta() -> TestResult<()> {
    assert_candidate_matches_oracle(256, 10, Shape::Clustered)
}

#[test]
fn exact_oracle_matches_five_hundred_twelve_uniform_items_with_majority_delta() -> TestResult<()> {
    assert_candidate_matches_oracle(512, 257, Shape::Uniform)
}

#[test]
fn exact_oracle_matches_one_thousand_uniform_items_with_ten_delta() -> TestResult<()> {
    assert_candidate_matches_oracle(1_000, 10, Shape::Uniform)
}

#[test]
fn candidate_preserves_full_typed_identity() -> TestResult<()> {
    let digest = [0x5a; 32];
    let left = BTreeSet::from([ObjectId::new(ObjectKind::SourceEnvelope, digest)]);
    let right = BTreeSet::from([ObjectId::new(ObjectKind::BlobChunk, digest)]);
    let expected = exact_difference(&left, &right);
    assert_exact(&expected, &measure_negentropy(&left, &right)?, "Negentropy")?;

    // Fixed public v1 sessions must also account for empty inventories and a
    // kind populated only by the remote side. Session selection may not use an
    // omniscient union of the two peers' contents.
    let empty = measure_negentropy(&BTreeSet::new(), &BTreeSet::new())?;
    assert_eq!(empty.metrics.messages, 8);
    let remote_blob = BTreeSet::from([ObjectId::new(ObjectKind::BlobChunk, [0x6b; 32])]);
    let expected = exact_difference(&BTreeSet::new(), &remote_blob);
    assert_exact(
        &expected,
        &measure_negentropy(&BTreeSet::new(), &remote_blob)?,
        "Negentropy",
    )?;
    Ok(())
}

#[test]
fn aster_baseline_counts_real_encoded_sync_messages() -> TestResult<()> {
    let (left, right) = balanced_fixture(32, 3, Shape::Uniform)?;
    let measurement = measure_aster(&left, &right)?;
    assert!(measurement.metrics.messages > 0);
    assert!(measurement.metrics.encoded_bytes > 0);
    assert!(measurement.metrics.interest_bytes > 0);
    assert!(measurement.metrics.inventory_bytes > 0);
    assert!(measurement.metrics.want_bytes > 0);
    assert_eq!(
        measurement.metrics.encoded_bytes,
        measurement.metrics.interest_bytes
            + measurement.metrics.inventory_bytes
            + measurement.metrics.want_bytes
    );
    assert!(measurement.metrics.maximum_message_bytes <= measurement.metrics.encoded_bytes);
    assert!(
        measurement.metrics.peak_pending_encoded_bytes >= measurement.metrics.maximum_message_bytes
    );
    Ok(())
}

#[test]
fn candidate_bound_rejects_before_protocol_state() {
    assert!(validate_inventory_sizes(MAX_INVENTORY_ITEMS + 1, 0).is_err());
    assert!(validate_inventory_sizes(0, MAX_INVENTORY_ITEMS + 1).is_err());
    assert!(validate_inventory_sizes(MAX_INVENTORY_ITEMS, MAX_INVENTORY_ITEMS).is_ok());
}

fn configured_matrix_maximum() -> TestResult<usize> {
    let value = match env::var("ASTER_BAKEOFF_MAX_ITEMS") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => "1000".into(),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(invalid("ASTER_BAKEOFF_MAX_ITEMS must be valid UTF-8"));
        }
    };
    let parsed = value
        .parse::<usize>()
        .map_err(|_| invalid("ASTER_BAKEOFF_MAX_ITEMS must be an integer"))?;
    if parsed == 0 || parsed > MAX_INVENTORY_ITEMS {
        return Err(invalid(format!(
            "ASTER_BAKEOFF_MAX_ITEMS must be between 1 and {MAX_INVENTORY_ITEMS}"
        )));
    }
    Ok(parsed)
}

fn parse_algorithm_errors_allowed(value: Option<&str>) -> TestResult<bool> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err(invalid(
            "ASTER_BAKEOFF_ALLOW_ALGORITHM_ERRORS must be 0 or 1",
        )),
    }
}

fn algorithm_errors_are_allowed() -> TestResult<bool> {
    match env::var("ASTER_BAKEOFF_ALLOW_ALGORITHM_ERRORS") {
        Ok(value) => parse_algorithm_errors_allowed(Some(&value)),
        Err(env::VarError::NotPresent) => parse_algorithm_errors_allowed(None),
        Err(env::VarError::NotUnicode(_)) => Err(invalid(
            "ASTER_BAKEOFF_ALLOW_ALGORITHM_ERRORS must be valid UTF-8",
        )),
    }
}

const fn matrix_should_fail(
    oracle_mismatches: u64,
    algorithm_errors: u64,
    algorithm_errors_allowed: bool,
) -> bool {
    oracle_mismatches > 0 || (algorithm_errors > 0 && !algorithm_errors_allowed)
}

fn matrix_deltas(items_each: usize) -> BTreeSet<usize> {
    let mut deltas: BTreeSet<_> = MATRIX_BASE_DELTAS_EACH
        .into_iter()
        .filter(|delta| *delta <= items_each)
        .collect();
    deltas.insert(items_each / 10);
    deltas.insert(items_each / 2);
    deltas.insert(items_each);
    deltas
}

#[derive(Clone, Copy)]
enum Algorithm {
    Aster,
    Negentropy,
}

impl Algorithm {
    const fn label(self) -> &'static str {
        match self {
            Self::Aster => "aster_merkle",
            Self::Negentropy => "negentropy_0_5_2",
        }
    }

    const fn byte_scope(self) -> &'static str {
        match self {
            Self::Aster => "aster_sync_cbor",
            Self::Negentropy => "negentropy_raw_payload",
        }
    }

    const fn production_exact_verification_required(self) -> bool {
        matches!(self, Self::Negentropy)
    }

    const fn includes_object_requests(self) -> bool {
        matches!(self, Self::Aster)
    }
}

const fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn emit_measurement(
    algorithm: Algorithm,
    shape: Shape,
    items_each: usize,
    delta_each: usize,
    measurement: &Measurement,
    oracle_match: bool,
) {
    let metrics = &measurement.metrics;
    println!(
        "ASTER_RECONCILE_BAKEOFF\tversion=2\tstatus=ok\tprofile={}\talgorithm={}\tshape={}\titems_each={items_each}\trequested_delta_each={delta_each}\tsymmetric_difference={}\tbuild_ns={}\treconcile_ns={}\tmessages={}\tlogical_message_depth={}\tresult_visibility=both_peers\tincludes_object_requests={}\tbyte_scope={}\tencoded_bytes={}\tmaximum_message_bytes={}\tpeak_pending_encoded_bytes={}\tinterest_bytes={}\tinventory_bytes={}\twant_bytes={}\toracle_match={oracle_match}\tproduction_exact_verification_required={}\tfallback_exercised=false",
        build_profile(),
        algorithm.label(),
        shape.label(),
        measurement.difference.only_left.len() + measurement.difference.only_right.len(),
        metrics.build_ns,
        metrics.reconcile_ns,
        metrics.messages,
        metrics.logical_message_depth,
        algorithm.includes_object_requests(),
        algorithm.byte_scope(),
        metrics.encoded_bytes,
        metrics.maximum_message_bytes,
        metrics.peak_pending_encoded_bytes,
        metrics.interest_bytes,
        metrics.inventory_bytes,
        metrics.want_bytes,
        algorithm.production_exact_verification_required(),
    );
}

fn emit_error(
    algorithm: Algorithm,
    shape: Shape,
    items_each: usize,
    delta_each: usize,
    error: &(dyn Error + Send + Sync),
) {
    let detail = error.to_string().replace(['\t', '\n', '\r', ' '], "_");
    println!(
        "ASTER_RECONCILE_BAKEOFF\tversion=2\tstatus=error\tprofile={}\talgorithm={}\tshape={}\titems_each={items_each}\trequested_delta_each={delta_each}\terror={detail}",
        build_profile(),
        algorithm.label(),
        shape.label(),
    );
}

#[test]
#[ignore = "explicit local performance experiment"]
fn emit_reconciliation_bakeoff_matrix() -> TestResult<()> {
    assert_eq!(MATRIX_CARDINALITIES.last(), Some(&MAX_INVENTORY_ITEMS));
    let maximum = configured_matrix_maximum()?;
    let algorithm_errors_allowed = algorithm_errors_are_allowed()?;
    let mut oracle_mismatches = 0_u64;
    let mut algorithm_errors = 0_u64;
    let mut rows = 0_u64;
    for shape in Shape::ALL {
        for items_each in MATRIX_CARDINALITIES
            .into_iter()
            .filter(|items| *items <= maximum)
        {
            for delta_each in matrix_deltas(items_each) {
                let (left, right) = balanced_fixture(items_each, delta_each, shape)?;
                let expected = exact_difference(&left, &right);
                match measure_aster(&left, &right) {
                    Ok(aster) => {
                        rows = rows.saturating_add(1);
                        let oracle_match = aster.difference == expected;
                        oracle_mismatches += u64::from(!oracle_match);
                        emit_measurement(
                            Algorithm::Aster,
                            shape,
                            items_each,
                            delta_each,
                            &aster,
                            oracle_match,
                        );
                    }
                    Err(error) => {
                        rows = rows.saturating_add(1);
                        algorithm_errors = algorithm_errors.saturating_add(1);
                        emit_error(
                            Algorithm::Aster,
                            shape,
                            items_each,
                            delta_each,
                            error.as_ref(),
                        );
                    }
                }

                match measure_negentropy(&left, &right) {
                    Ok(candidate) => {
                        rows = rows.saturating_add(1);
                        let oracle_match = candidate.difference == expected;
                        oracle_mismatches += u64::from(!oracle_match);
                        emit_measurement(
                            Algorithm::Negentropy,
                            shape,
                            items_each,
                            delta_each,
                            &candidate,
                            oracle_match,
                        );
                    }
                    Err(error) => {
                        rows = rows.saturating_add(1);
                        algorithm_errors = algorithm_errors.saturating_add(1);
                        emit_error(
                            Algorithm::Negentropy,
                            shape,
                            items_each,
                            delta_each,
                            error.as_ref(),
                        );
                    }
                }
            }
        }
    }
    println!(
        "ASTER_RECONCILE_BAKEOFF\tversion=2\tstatus=summary\tprofile={}\trows={rows}\toracle_mismatches={oracle_mismatches}\talgorithm_errors={algorithm_errors}\talgorithm_errors_allowed={algorithm_errors_allowed}",
        build_profile(),
    );
    if matrix_should_fail(
        oracle_mismatches,
        algorithm_errors,
        algorithm_errors_allowed,
    ) {
        return Err(invalid(format!(
            "reconciliation matrix failed: {oracle_mismatches} oracle mismatches and {algorithm_errors} algorithm errors"
        )));
    }
    Ok(())
}

#[test]
fn algorithm_error_reporting_requires_an_explicit_opt_in() {
    assert!(!parse_algorithm_errors_allowed(None).unwrap());
    assert!(!parse_algorithm_errors_allowed(Some("0")).unwrap());
    assert!(parse_algorithm_errors_allowed(Some("1")).unwrap());
    assert!(parse_algorithm_errors_allowed(Some("true")).is_err());

    assert!(!matrix_should_fail(0, 0, false));
    assert!(matrix_should_fail(0, 1, false));
    assert!(!matrix_should_fail(0, 1, true));
    assert!(matrix_should_fail(1, 0, false));
    assert!(matrix_should_fail(1, 0, true));
    assert!(matrix_should_fail(1, 1, true));
}
