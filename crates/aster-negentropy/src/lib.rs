//! Bounded Negentropy reconciliation over canonical Aster item inventories.
//!
//! Negentropy owns identifier-set difference only. This crate maps every full
//! [`ItemId`] to the upstream protocol with timestamp zero, so ordering cannot
//! depend on a wall clock, insertion ordinal, or replica-local state. Object
//! request, transfer, acceptance, policy, and durable session progression remain
//! responsibilities of the composition layer.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

use aster_profile::{InventorySnapshot, ItemId};
use negentropy::{Id, Negentropy, NegentropyStorageVector};

/// Smallest frame limit supported by Negentropy 0.5.2.
pub const MIN_FRAME_SIZE_LIMIT: usize = 4_096;
/// Largest frame limit accepted by this production wrapper.
pub const MAX_FRAME_SIZE_LIMIT: usize = 1_048_576;
/// Default on-wire Negentropy frame limit.
pub const DEFAULT_FRAME_SIZE_LIMIT: usize = 4_096;
/// Largest configurable number of request/response rounds in one session.
pub const MAX_ROUND_LIMIT: u32 = 4_096;
/// Default maximum request/response rounds in one session.
pub const DEFAULT_ROUND_LIMIT: u32 = 256;
/// Largest configurable local or discovered remote inventory cardinality.
pub const MAX_CARDINALITY_LIMIT: usize = 1_000_000;
/// Default maximum local or discovered remote inventory cardinality.
pub const DEFAULT_CARDINALITY_LIMIT: usize = 100_000;

type Engine = Negentropy<'static, NegentropyStorageVector>;

/// Explicit resource limits for one reconciliation session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationLimits {
    frame_size: usize,
    rounds: u32,
    cardinality: usize,
}

impl ReconciliationLimits {
    /// Validates and constructs session limits.
    pub fn new(
        frame_size: usize,
        rounds: u32,
        cardinality: usize,
    ) -> Result<Self, ReconciliationError> {
        if !(MIN_FRAME_SIZE_LIMIT..=MAX_FRAME_SIZE_LIMIT).contains(&frame_size) {
            return Err(ReconciliationError::InvalidFrameLimit { frame_size });
        }
        if rounds == 0 || rounds > MAX_ROUND_LIMIT {
            return Err(ReconciliationError::InvalidRoundLimit { rounds });
        }
        if cardinality == 0 || cardinality > MAX_CARDINALITY_LIMIT {
            return Err(ReconciliationError::InvalidCardinalityLimit { cardinality });
        }
        Ok(Self {
            frame_size,
            rounds,
            cardinality,
        })
    }

    /// Returns the maximum encoded frame size in bytes.
    pub const fn frame_size(self) -> usize {
        self.frame_size
    }

    /// Returns the maximum request/response rounds.
    pub const fn rounds(self) -> u32 {
        self.rounds
    }

    /// Returns the maximum local or discovered remote item count.
    pub const fn cardinality(self) -> usize {
        self.cardinality
    }
}

impl Default for ReconciliationLimits {
    fn default() -> Self {
        Self {
            frame_size: DEFAULT_FRAME_SIZE_LIMIT,
            rounds: DEFAULT_ROUND_LIMIT,
            cardinality: DEFAULT_CARDINALITY_LIMIT,
        }
    }
}

/// Canonical set difference from the initiator's point of view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Difference {
    /// Complete identifiers present only in the initiator's local inventory.
    pub local_only: Vec<ItemId>,
    /// Complete identifiers present only in the responder's remote inventory.
    pub remote_only: Vec<ItemId>,
}

impl Difference {
    /// Returns true when both inventories have equal membership.
    pub fn is_empty(&self) -> bool {
        self.local_only.is_empty() && self.remote_only.is_empty()
    }
}

/// The next action after an initiator processes a response frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitiatorStep {
    /// Send the contained Negentropy frame to the same responder.
    Continue(Vec<u8>),
    /// Set reconciliation is complete.
    Complete(Difference),
}

/// Errors from bounded set reconciliation.
#[derive(Debug)]
pub enum ReconciliationError {
    /// Configured frame size is outside the supported bounded range.
    InvalidFrameLimit { frame_size: usize },
    /// Configured round count is zero or exceeds the hard ceiling.
    InvalidRoundLimit { rounds: u32 },
    /// Configured cardinality is zero or exceeds the hard ceiling.
    InvalidCardinalityLimit { cardinality: usize },
    /// A local inventory exceeds the configured cardinality.
    InventoryLimitExceeded { cardinality: usize, limit: usize },
    /// A frame exceeds the configured byte limit.
    FrameLimitExceeded { length: usize, limit: usize },
    /// An encoded ID list would exceed the configured cardinality.
    FrameCardinalityExceeded { cardinality: usize, limit: usize },
    /// Accumulated set-difference output exceeds the configured cardinality.
    DifferenceLimitExceeded {
        local_only: usize,
        remote_only: usize,
        limit: usize,
    },
    /// The session exhausted its request/response round budget.
    RoundLimitExceeded { limit: u32 },
    /// The received Negentropy frame is structurally invalid.
    MalformedFrame(&'static str),
    /// The initiator was asked to process a response before producing its first frame.
    NotInitiated,
    /// The initiator session was used after it completed.
    AlreadyComplete,
    /// Negentropy 0.5.2 rejected an otherwise bounded operation.
    Upstream(negentropy::Error),
}

impl fmt::Display for ReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameLimit { frame_size } => write!(
                formatter,
                "frame limit {frame_size} is outside {MIN_FRAME_SIZE_LIMIT}..={MAX_FRAME_SIZE_LIMIT}"
            ),
            Self::InvalidRoundLimit { rounds } => {
                write!(
                    formatter,
                    "round limit {rounds} is outside 1..={MAX_ROUND_LIMIT}"
                )
            }
            Self::InvalidCardinalityLimit { cardinality } => write!(
                formatter,
                "cardinality limit {cardinality} is outside 1..={MAX_CARDINALITY_LIMIT}"
            ),
            Self::InventoryLimitExceeded { cardinality, limit } => {
                write!(
                    formatter,
                    "inventory cardinality {cardinality} exceeds limit {limit}"
                )
            }
            Self::FrameLimitExceeded { length, limit } => {
                write!(formatter, "frame length {length} exceeds limit {limit}")
            }
            Self::FrameCardinalityExceeded { cardinality, limit } => write!(
                formatter,
                "frame ID-list cardinality {cardinality} exceeds limit {limit}"
            ),
            Self::DifferenceLimitExceeded {
                local_only,
                remote_only,
                limit,
            } => write!(
                formatter,
                "difference cardinality local={local_only} remote={remote_only} exceeds per-side limit {limit}"
            ),
            Self::RoundLimitExceeded { limit } => {
                write!(formatter, "reconciliation exceeded its {limit}-round limit")
            }
            Self::MalformedFrame(reason) => {
                write!(formatter, "malformed Negentropy frame: {reason}")
            }
            Self::NotInitiated => formatter.write_str("initiator has not produced its first frame"),
            Self::AlreadyComplete => formatter.write_str("reconciliation is already complete"),
            Self::Upstream(error) => write!(formatter, "Negentropy error: {error}"),
        }
    }
}

impl Error for ReconciliationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Upstream(error) => Some(error),
            _ => None,
        }
    }
}

impl From<negentropy::Error> for ReconciliationError {
    fn from(error: negentropy::Error) -> Self {
        Self::Upstream(error)
    }
}

/// Stateful initiating half of a bounded Negentropy exchange.
pub struct Initiator {
    engine: Engine,
    limits: ReconciliationLimits,
    rounds: u32,
    initiated: bool,
    complete: bool,
    local_only: Vec<Id>,
    remote_only: Vec<Id>,
}

impl Initiator {
    /// Creates an initiator from a canonical local inventory.
    pub fn new(
        inventory: &InventorySnapshot,
        limits: ReconciliationLimits,
    ) -> Result<Self, ReconciliationError> {
        validate_inventory(inventory, limits)?;
        Ok(Self {
            engine: build_engine(inventory, limits)?,
            limits,
            rounds: 0,
            initiated: false,
            complete: false,
            local_only: Vec::new(),
            remote_only: Vec::new(),
        })
    }

    /// Produces the first frame to send to the responder.
    pub fn initiate(&mut self) -> Result<Vec<u8>, ReconciliationError> {
        let frame = self.engine.initiate()?;
        validate_frame(&frame, self.limits)?;
        self.initiated = true;
        Ok(frame)
    }

    /// Processes one response and returns either the next frame or the final difference.
    pub fn reconcile_response(
        &mut self,
        response: &[u8],
    ) -> Result<InitiatorStep, ReconciliationError> {
        if !self.initiated {
            return Err(ReconciliationError::NotInitiated);
        }
        if self.complete {
            return Err(ReconciliationError::AlreadyComplete);
        }
        validate_frame(response, self.limits)?;
        spend_round(&mut self.rounds, self.limits)?;

        let next = self.engine.reconcile_with_ids(
            response,
            &mut self.local_only,
            &mut self.remote_only,
        )?;
        validate_difference_cardinality(
            self.local_only.len(),
            self.remote_only.len(),
            self.limits,
        )?;

        if let Some(frame) = next {
            validate_frame(&frame, self.limits)?;
            return Ok(InitiatorStep::Continue(frame));
        }

        self.complete = true;
        let mut local_only = convert_ids(&self.local_only);
        let mut remote_only = convert_ids(&self.remote_only);
        local_only.sort_unstable();
        local_only.dedup();
        remote_only.sort_unstable();
        remote_only.dedup();
        validate_difference_cardinality(local_only.len(), remote_only.len(), self.limits)?;

        Ok(InitiatorStep::Complete(Difference {
            local_only,
            remote_only,
        }))
    }

    /// Returns the number of response frames processed so far.
    pub const fn rounds(&self) -> u32 {
        self.rounds
    }
}

/// Stateful responding half of a bounded Negentropy exchange.
pub struct Responder {
    engine: Engine,
    limits: ReconciliationLimits,
    rounds: u32,
}

impl Responder {
    /// Creates a responder from a canonical local inventory.
    pub fn new(
        inventory: &InventorySnapshot,
        limits: ReconciliationLimits,
    ) -> Result<Self, ReconciliationError> {
        validate_inventory(inventory, limits)?;
        Ok(Self {
            engine: build_engine(inventory, limits)?,
            limits,
            rounds: 0,
        })
    }

    /// Processes one initiator query and returns one response frame.
    pub fn reconcile_query(&mut self, query: &[u8]) -> Result<Vec<u8>, ReconciliationError> {
        validate_frame(query, self.limits)?;
        spend_round(&mut self.rounds, self.limits)?;
        let response = self.engine.reconcile(query)?;
        validate_frame(&response, self.limits)?;
        Ok(response)
    }

    /// Returns the number of query frames processed so far.
    pub const fn rounds(&self) -> u32 {
        self.rounds
    }
}

fn validate_inventory(
    inventory: &InventorySnapshot,
    limits: ReconciliationLimits,
) -> Result<(), ReconciliationError> {
    if inventory.len() > limits.cardinality {
        return Err(ReconciliationError::InventoryLimitExceeded {
            cardinality: inventory.len(),
            limit: limits.cardinality,
        });
    }
    Ok(())
}

fn build_engine(
    inventory: &InventorySnapshot,
    limits: ReconciliationLimits,
) -> Result<Engine, ReconciliationError> {
    let mut storage = NegentropyStorageVector::with_capacity(inventory.len());
    for key in inventory.reconciliation_keys() {
        storage.insert(0, Id::from_byte_array(*key.as_bytes()))?;
    }
    storage.seal()?;
    Ok(Negentropy::owned(storage, limits.frame_size as u64)?)
}

fn spend_round(rounds: &mut u32, limits: ReconciliationLimits) -> Result<(), ReconciliationError> {
    if *rounds >= limits.rounds {
        return Err(ReconciliationError::RoundLimitExceeded {
            limit: limits.rounds,
        });
    }
    *rounds += 1;
    Ok(())
}

fn validate_difference_cardinality(
    local_only: usize,
    remote_only: usize,
    limits: ReconciliationLimits,
) -> Result<(), ReconciliationError> {
    if local_only > limits.cardinality || remote_only > limits.cardinality {
        return Err(ReconciliationError::DifferenceLimitExceeded {
            local_only,
            remote_only,
            limit: limits.cardinality,
        });
    }
    Ok(())
}

fn convert_ids(ids: &[Id]) -> Vec<ItemId> {
    ids.iter().map(|id| ItemId::new(id.to_bytes())).collect()
}

// Validate the upstream frame grammar before handing untrusted counts to
// Negentropy. Keep Aster's frame/cardinality budgets independent of upstream's
// own validation, including its 0.5.2 fix for truncated ID-list allocations.
fn validate_frame(frame: &[u8], limits: ReconciliationLimits) -> Result<(), ReconciliationError> {
    if frame.len() > limits.frame_size {
        return Err(ReconciliationError::FrameLimitExceeded {
            length: frame.len(),
            limit: limits.frame_size,
        });
    }
    let Some((_, body)) = frame.split_first() else {
        return Err(ReconciliationError::MalformedFrame(
            "missing protocol version",
        ));
    };
    let mut input = body;
    let mut listed_ids = 0usize;

    while !input.is_empty() {
        let _timestamp_delta = take_varint(&mut input)?;
        let bound_length = usize::try_from(take_varint(&mut input)?)
            .map_err(|_| ReconciliationError::MalformedFrame("bound length overflows usize"))?;
        if bound_length > 32 {
            return Err(ReconciliationError::MalformedFrame(
                "bound identifier prefix exceeds 32 bytes",
            ));
        }
        take_bytes(&mut input, bound_length)?;

        match take_varint(&mut input)? {
            0 => {}
            1 => {
                take_bytes(&mut input, 16)?;
            }
            2 => {
                let count = usize::try_from(take_varint(&mut input)?).map_err(|_| {
                    ReconciliationError::FrameCardinalityExceeded {
                        cardinality: usize::MAX,
                        limit: limits.cardinality,
                    }
                })?;
                listed_ids = listed_ids.checked_add(count).ok_or(
                    ReconciliationError::FrameCardinalityExceeded {
                        cardinality: usize::MAX,
                        limit: limits.cardinality,
                    },
                )?;
                if listed_ids > limits.cardinality {
                    return Err(ReconciliationError::FrameCardinalityExceeded {
                        cardinality: listed_ids,
                        limit: limits.cardinality,
                    });
                }
                let bytes = count
                    .checked_mul(32)
                    .ok_or(ReconciliationError::MalformedFrame(
                        "ID-list byte length overflows usize",
                    ))?;
                take_bytes(&mut input, bytes)?;
            }
            _ => return Err(ReconciliationError::MalformedFrame("unknown range mode")),
        }
    }

    Ok(())
}

fn take_varint(input: &mut &[u8]) -> Result<u64, ReconciliationError> {
    let mut value = 0u64;
    for index in 0..10 {
        let Some((&byte, rest)) = input.split_first() else {
            return Err(ReconciliationError::MalformedFrame(
                "truncated variable integer",
            ));
        };
        *input = rest;
        value = value
            .checked_mul(128)
            .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
            .ok_or(ReconciliationError::MalformedFrame(
                "variable integer overflows u64",
            ))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        if index == 9 {
            return Err(ReconciliationError::MalformedFrame(
                "variable integer exceeds ten bytes",
            ));
        }
    }
    Err(ReconciliationError::MalformedFrame(
        "unterminated variable integer",
    ))
}

fn take_bytes<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], ReconciliationError> {
    if input.len() < length {
        return Err(ReconciliationError::MalformedFrame("truncated field"));
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(byte: u8) -> ItemId {
        ItemId::new([byte; 32])
    }

    fn numbered_item(number: u32) -> ItemId {
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&number.to_be_bytes());
        ItemId::new(bytes)
    }

    fn reconcile(local: InventorySnapshot, remote: InventorySnapshot) -> (Difference, u32) {
        let limits = ReconciliationLimits::default();
        let mut initiator = Initiator::new(&local, limits).expect("create initiator");
        let mut responder = Responder::new(&remote, limits).expect("create responder");
        let mut query = initiator.initiate().expect("initial frame");

        loop {
            let response = responder.reconcile_query(&query).expect("response frame");
            match initiator
                .reconcile_response(&response)
                .expect("process response")
            {
                InitiatorStep::Continue(next) => query = next,
                InitiatorStep::Complete(difference) => {
                    assert_eq!(initiator.rounds(), responder.rounds());
                    return (difference, initiator.rounds());
                }
            }
        }
    }

    #[test]
    fn equal_inventories_have_no_difference() {
        let inventory = InventorySnapshot::new([item(1), item(2), item(3)]);
        let (difference, rounds) = reconcile(inventory.clone(), inventory);
        assert!(difference.is_empty());
        assert!(rounds > 0);
    }

    #[test]
    fn shifted_overlap_uses_timestamp_zero_and_full_id_ordering() {
        let shared = item(0x78);
        let local = InventorySnapshot::new([shared, item(0x88)]);
        let remote = InventorySnapshot::new([item(0x5f), shared]);

        assert_eq!(local.iter().position(|id| *id == shared), Some(0));
        assert_eq!(remote.iter().position(|id| *id == shared), Some(1));
        let (difference, _) = reconcile(local, remote);
        assert_eq!(difference.local_only, vec![item(0x88)]);
        assert_eq!(difference.remote_only, vec![item(0x5f)]);
    }

    #[test]
    fn fully_divergent_inventories_report_both_canonical_sides() {
        let local = InventorySnapshot::new([item(1), item(3), item(5)]);
        let remote = InventorySnapshot::new([item(2), item(4), item(6)]);
        let (difference, _) = reconcile(local, remote);
        assert_eq!(difference.local_only, vec![item(1), item(3), item(5)]);
        assert_eq!(difference.remote_only, vec![item(2), item(4), item(6)]);
    }

    #[test]
    fn large_shifted_inventories_complete_across_multiple_bounded_rounds() {
        let local = InventorySnapshot::new((0..512).map(numbered_item));
        let remote = InventorySnapshot::new((256..768).map(numbered_item));
        let (difference, rounds) = reconcile(local, remote);

        assert!(rounds > 1);
        assert_eq!(
            difference.local_only,
            (0..256).map(numbered_item).collect::<Vec<_>>()
        );
        assert_eq!(
            difference.remote_only,
            (512..768).map(numbered_item).collect::<Vec<_>>()
        );
    }

    #[test]
    fn local_inventory_cardinality_is_bounded_before_engine_construction() {
        let limits = ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, 8, 2).expect("limits");
        let inventory = InventorySnapshot::new([item(1), item(2), item(3)]);
        assert!(matches!(
            Initiator::new(&inventory, limits),
            Err(ReconciliationError::InventoryLimitExceeded {
                cardinality: 3,
                limit: 2
            })
        ));
    }

    #[test]
    fn hostile_declared_id_count_is_rejected_before_upstream_allocation() {
        let limits = ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, 8, 1).expect("limits");
        let inventory = InventorySnapshot::default();
        let mut responder = Responder::new(&inventory, limits).expect("responder");
        // version, max bound, empty ID prefix, ID-list mode, declared count 2
        let frame = [0x61, 0, 0, 2, 2];
        assert!(matches!(
            responder.reconcile_query(&frame),
            Err(ReconciliationError::FrameCardinalityExceeded {
                cardinality: 2,
                limit: 1
            })
        ));
        assert_eq!(responder.rounds(), 0);
    }

    #[test]
    fn oversized_frame_is_rejected_without_spending_a_round() {
        let limits = ReconciliationLimits::default();
        let inventory = InventorySnapshot::default();
        let mut responder = Responder::new(&inventory, limits).expect("responder");
        let frame = vec![0; limits.frame_size() + 1];
        assert!(matches!(
            responder.reconcile_query(&frame),
            Err(ReconciliationError::FrameLimitExceeded { .. })
        ));
        assert_eq!(responder.rounds(), 0);
    }

    #[test]
    fn responder_enforces_the_round_limit() {
        let limits = ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, 1, 8).expect("limits");
        let inventory = InventorySnapshot::new([item(1)]);
        let mut initiator = Initiator::new(&inventory, limits).expect("initiator");
        let mut responder = Responder::new(&inventory, limits).expect("responder");
        let query = initiator.initiate().expect("query");

        responder.reconcile_query(&query).expect("first response");
        assert!(matches!(
            responder.reconcile_query(&query),
            Err(ReconciliationError::RoundLimitExceeded { limit: 1 })
        ));
    }

    #[test]
    fn initiator_enforces_the_round_limit_during_a_multiround_exchange() {
        let limits = ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, 1, 2_000).expect("limits");
        let local = InventorySnapshot::new((0..512).map(numbered_item));
        let remote = InventorySnapshot::new((256..768).map(numbered_item));
        let mut initiator = Initiator::new(&local, limits).expect("initiator");
        let mut responder = Responder::new(&remote, limits).expect("responder");
        let query = initiator.initiate().expect("initial query");
        let response = responder.reconcile_query(&query).expect("first response");
        let InitiatorStep::Continue(_) = initiator
            .reconcile_response(&response)
            .expect("first initiator round")
        else {
            panic!("large divergent inventory unexpectedly completed in one round");
        };

        assert!(matches!(
            initiator.reconcile_response(&[0x61]),
            Err(ReconciliationError::RoundLimitExceeded { limit: 1 })
        ));
    }

    #[test]
    fn limits_reject_unbounded_or_excessive_values() {
        assert!(matches!(
            ReconciliationLimits::new(0, 1, 1),
            Err(ReconciliationError::InvalidFrameLimit { .. })
        ));
        assert!(matches!(
            ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, 0, 1),
            Err(ReconciliationError::InvalidRoundLimit { .. })
        ));
        assert!(matches!(
            ReconciliationLimits::new(MIN_FRAME_SIZE_LIMIT, 1, 0),
            Err(ReconciliationError::InvalidCardinalityLimit { .. })
        ));
    }
}
