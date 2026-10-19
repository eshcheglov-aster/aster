//! Semantic-v9/profile-5 Blob stream runtime.
//!
//! Network attempts may receive ahead, but only Store-confirmed cumulative
//! checkpoints update the public durable position or recovery authority.

use crate::application::{
    BlobStreamTerminalCategory, BlobStreamTransferPhase, BlobStreamTransferStatus,
};
use crate::{
    frame::{BlobInterest, BlobPublicationResumeV1, BlobStreamPlanSelectionV1, BlobStreamPlanV1},
    mission::MissionSession,
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, MAX_STREAM_EXTENT_BYTES, StreamAction, StreamDataV1,
        StreamDirection, StreamFrame, StreamOpenV1, StreamReceiverState, StreamResultCode,
        StreamSenderState, decode_owned_data_for_context,
    },
    stream_transport::{
        AttemptOpenRequest, AuthenticatedPeerSupport, AuthenticatedSupportSource,
        IrohQuicV1Adapter, StreamAttempt, StreamReceiveAttempt, StreamTransportAdapter,
        StreamTransportError, StreamTransportId, TransferRequirements, TransportCandidate,
        TransportSelector,
    },
};
use aster_mesh::{
    BlobStreamDecryptor, BlobStreamLayout, EncryptedBlobStreamSegment,
    VerifiedBlobStreamFinalCommitment, VerifiedBlobStreamOpen, VerifiedBlobTransferPlan,
};
use aster_redb_store::{
    BlobOperationKey, BlobStreamCheckpoint, BlobStreamCommitOutcome, BlobStreamCryptoResume,
    BlobStreamPackSession, BlobStreamPublication, BlobStreamReservationRequest, BlobStreamSource,
    BlobTransferId, BlobVariantId, ControlPolicySnapshot, MutableTransferCursorClass,
    MutableTransferCursorMode, Store, VerifiedBlobStreamCheckpointBatch,
};
use sha2::{Digest as _, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

#[cfg(test)]
use super::TestBlobContactFault;
use super::{
    AuthenticatedBlobRouteClaim, BlobContactMode, BlobStreamReceiveCandidates, BlobStreamTransport,
    CompletedBlobStreamSource, DeferredFiniteBlobStreamAdmission, EventDirection, EventLaneGuard,
    MutableApplyDisposition, NodeError, PendingBlobRecoveryDisposition, ReferenceEnvelopeSealer,
    abort_pending_blob_with_cached_claim, blob_source_projection_for_contact,
    cache_staged_blob_after_transition, contact_custody_sample, contact_mutable_route_cache,
    custody_finalization_charge_ms, load_completed_blob_stream_source, load_pending_blob_plan,
    pending_blob_claim_is_current, recover_and_finalize_pending_blob,
    require_contact_policy_current,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobStreamAttemptMetrics {
    pub(super) transport: BlobStreamTransport,
    pub(super) received_bytes: u64,
    pub(super) retransmitted_bytes: u64,
    pub(super) receive_limit_bytes: u64,
    pub(super) checkpoint_bytes: u64,
    pub(super) checkpoint_latency_ms: u64,
    pub(super) writer_commits: u32,
    pub(super) failover_recoveries: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobStreamAttemptOutcome {
    pub(super) code: StreamResultCode,
    pub(super) metrics: BlobStreamAttemptMetrics,
}

const STREAM_ATTEMPT_DEADLINE: Duration = Duration::from_secs(30 * 60);
// Retained-source credit remains independent of completed-pack disk grouping.
const STREAM_RECEIVE_WINDOW_BYTES: u64 = 32 * 1_048_576;
// Parse/decrypt bounded callbacks, but amortize pack/journal/Store sync across
// several callbacks. Only cached Store-confirmed authority refills the credit.
// The larger window bounds unacknowledged file bytes, not one parser allocation.
const STREAM_CHECKPOINT_BATCH_BYTES: u32 = 15 * 1_048_576;
const PACK_STREAM_RECEIVE_WINDOW_BYTES: u64 = 512 * 1_048_576;
const PACK_STREAM_CHECKPOINT_GROUP_BYTES: u64 = 240 * 1_048_576;
// Evaluated on every callback; EOF and impending credit exhaustion also flush.
const PACK_STREAM_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);
// Retained carrier checkpoints use a different Store API with a smaller cap.
// Completed-pack tuning must never advertise more than that API can commit.
const RETAINED_STREAM_CHECKPOINT_BATCH_BYTES: u32 =
    aster_redb_store::MAX_BLOB_STREAM_CHECKPOINT_BATCH_BYTES as u32;
const _: () = assert!(
    aster_redb_store::MAX_BLOB_STREAM_CHECKPOINT_BATCH_BYTES <= u32::MAX as usize
        && RETAINED_STREAM_CHECKPOINT_BATCH_BYTES <= MAX_STREAM_CHECKPOINT_BATCH_BYTES
        && RETAINED_STREAM_CHECKPOINT_BATCH_BYTES as u64 + MAX_STREAM_EXTENT_BYTES as u64
            <= STREAM_RECEIVE_WINDOW_BYTES
);
const STREAM_RECORD_BUDGET_BYTES: usize = 256;
const PACK_STREAM_MAX_EXTENT_BYTES: u32 = MAX_STREAM_EXTENT_BYTES as u32;
const _: () = assert!(
    PACK_STREAM_CHECKPOINT_GROUP_BYTES
        + STREAM_CHECKPOINT_BATCH_BYTES as u64
        + (MAX_STREAM_EXTENT_BYTES as u64)
        < PACK_STREAM_RECEIVE_WINDOW_BYTES
);

#[cfg(test)]
pub(super) const fn completed_pack_checkpoint_test_bounds() -> (u64, u64) {
    (
        PACK_STREAM_CHECKPOINT_GROUP_BYTES,
        STREAM_CHECKPOINT_BATCH_BYTES as u64,
    )
}

// File/journal/Store commits are synchronous. Release the runtime worker so
// QUIC can buffer the next bounded batch while these durability barriers run.
// Embedded current-thread runtimes retain their existing synchronous behavior.
fn blocking_store_step<T>(run: impl FnOnce() -> T) -> T {
    if matches!(
        tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    ) {
        tokio::task::block_in_place(run)
    } else {
        run()
    }
}

pub(super) struct CompletedPackStreamSource {
    // Scheduling hint only; it never establishes peer possession or authority.
    scheduling_cursor: Option<[u8; 32]>,
    pub(super) publication: BlobStreamPublication,
    pub(super) open: VerifiedBlobStreamOpen,
    pub(super) commitment: VerifiedBlobStreamFinalCommitment,
}

pub(super) fn select_completed_pack_source(
    store: &Store,
    mission: &MissionSession,
    verifier: &ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    peer_interest: &BlobInterest,
) -> Result<Option<CompletedPackStreamSource>, NodeError> {
    guard.check(store)?;
    let peer = mission.peer().mission_id();
    let commitments = mission.peer_route_grant_commitments();
    let scheduling_cursor = store.mutable_transfer_cursor(
        peer,
        MutableTransferCursorClass::BlobStream,
        MutableTransferCursorMode::OfferToPeer,
    )?;
    let mut publications = store.blob_stream_publications_with_policy(guard.policy())?;
    publications.sort_unstable_by_key(|publication| *publication.stream_id().as_bytes());
    let start = scheduling_cursor.map_or(0, |cursor| {
        publications.partition_point(|publication| publication.stream_id().as_bytes() <= &cursor)
    });
    publications.rotate_left(start);
    for publication in publications {
        let open = verifier.verify_blob_stream_open(publication.authenticated_open())?;
        let candidate = open.open();
        // Completed packs carry publisher clock samples, but no receiver-local
        // custody anchor. Finite network publications use the retained path.
        if candidate.ttl_ms().is_some() {
            continue;
        }
        let Some(selector) = peer_interest
            .selector(candidate.topic(), candidate.scope())
            .filter(|selector| selector.epoch() == candidate.content_epoch())
        else {
            continue;
        };
        if !verifier.peer_can_route(
            peer,
            commitments,
            candidate.scope(),
            candidate.content_epoch(),
        ) || !verifier.peer_can_open_blob_content(
            peer,
            commitments,
            candidate.scope(),
            candidate.topic(),
            candidate.content_epoch(),
            selector.content_proof(),
        ) {
            continue;
        }
        let commitment = verifier
            .verify_blob_stream_commitment(&open, publication.authenticated_commitment())?;
        if open.open() != publication.open() || commitment.commitment() != publication.commitment()
        {
            return Err(protocol(
                "completed pack publication differs from publisher authority",
            ));
        }
        return Ok(Some(CompletedPackStreamSource {
            scheduling_cursor,
            publication,
            open,
            commitment,
        }));
    }
    Ok(None)
}

pub(super) enum ReceivedPackStream {
    Receiving(Box<ReceivingPackStream>),
    Complete(Box<CompletedPackAdmission>),
}

pub(super) struct CompletedPackAdmission {
    source: CompletedPackStreamSource,
    resume: BlobStreamCryptoResume,
}

pub(super) struct ReceivingPackStream {
    pub(super) open: VerifiedBlobStreamOpen,
    pub(super) commitment: VerifiedBlobStreamFinalCommitment,
    pub(super) pack: BlobStreamPackSession,
    pub(super) decryptor: BlobStreamDecryptor,
}

impl ReceivedPackStream {
    pub(super) fn resume_authority(&self, direction: EventDirection) -> BlobPublicationResumeV1 {
        let (open, resume) = match self {
            Self::Receiving(stream) => (&stream.open, stream.pack.crypto_resume()),
            Self::Complete(completed) => (&completed.source.open, completed.resume.clone()),
        };
        let progress = resume.progress();
        let initial = progress.generation() == 0;
        BlobPublicationResumeV1 {
            direction,
            stream_id: *open.open().stream_id().as_bytes(),
            open_digest: open.open().digest(),
            durable_plaintext_offset: progress.durable_plaintext_offset(),
            durable_wire_offset: progress.durable_wire_offset(),
            next_segment_index: progress.next_segment_index(),
            plaintext_commitment: if initial {
                [1; 32]
            } else {
                resume.plaintext_checkpoint().commitment()
            },
            ciphertext_commitment: if initial {
                [1; 32]
            } else {
                resume.ciphertext_checkpoint().commitment()
            },
            checkpoint_generation: progress.generation(),
        }
    }
}

pub(super) fn admit_completed_pack_source(
    store: &Store,
    mission: &MissionSession,
    verifier: &ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    local_interest: &BlobInterest,
    signed_open: &[u8],
    signed_commitment: &[u8],
) -> Result<ReceivedPackStream, NodeError> {
    guard.check(store)?;
    let open = verifier.verify_blob_stream_open(signed_open)?;
    let intent = open.open();
    if intent.ttl_ms().is_some() {
        return Err(protocol(
            "finite completed-pack admission requires receiver-local custody authority",
        ));
    }
    local_interest
        .selector(intent.topic(), intent.scope())
        .filter(|selector| selector.epoch() == intent.content_epoch())
        .ok_or_else(|| protocol("publisher-signed stream is outside local interest"))?;
    let peer = mission.peer().mission_id();
    let commitments = mission.peer_route_grant_commitments();
    if !verifier.peer_can_route(peer, commitments, intent.scope(), intent.content_epoch()) {
        return Err(protocol(
            "forwarding peer lacks signed-stream route entitlement",
        ));
    }
    // Completed admissions do not instantiate a decryptor, so retain the same
    // local content-grant requirement explicitly before either admission path.
    if !verifier.can_open_blob_content(intent.scope(), intent.topic(), intent.content_epoch()) {
        return Err(protocol("receiver lacks signed-stream content entitlement"));
    }
    let commitment = verifier.verify_blob_stream_commitment(&open, signed_commitment)?;
    let operation = BlobOperationKey::new(intent.operation_key().to_vec())?;
    if let Some(publication) =
        store.blob_stream_for_operation_with_policy(guard.policy(), &operation)?
    {
        let resume = store.completed_blob_stream_crypto_resume_with_policy(
            guard.policy(),
            &publication,
            &open,
            &commitment,
        )?;
        return Ok(ReceivedPackStream::Complete(Box::new(
            CompletedPackAdmission {
                source: CompletedPackStreamSource {
                    scheduling_cursor: None,
                    publication,
                    open,
                    commitment,
                },
                resume,
            },
        )));
    }
    let (reservation, _) = store.reserve_blob_stream_with_policy(
        guard.policy(),
        BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::AuthenticatedPeer(peer),
        },
        &open,
    )?;
    let pack = store.open_blob_stream_pack_session(guard.policy(), &reservation, &open)?;
    let resume = pack.crypto_resume();
    let progress = resume.progress();
    let decryptor = if progress.generation() == 0 {
        verifier.begin_blob_stream_decrypt(&open)?
    } else {
        verifier.resume_blob_stream_decrypt(
            &open,
            progress.durable_plaintext_offset(),
            resume.ciphertext_checkpoint(),
        )?
    };
    Ok(ReceivedPackStream::Receiving(Box::new(
        ReceivingPackStream {
            open,
            commitment,
            pack,
            decryptor,
        },
    )))
}

fn completed_pack_result_digest(
    stream_id: [u8; 32],
    blob_id: [u8; 32],
    code: StreamResultCode,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-pack-stream/result/v1\0");
    digest.update(stream_id);
    digest.update(blob_id);
    digest.update([code as u8]);
    digest.finalize().into()
}

fn pack_attempt_flow(total: u64) -> Result<(u32, u32, u64), NodeError> {
    if total == 0 {
        return Ok((1, 1, 2));
    }
    if total == 1 {
        return Err(protocol("completed pack wire length is too short"));
    }
    let max_extent = total
        .saturating_div(2)
        .max(1)
        .min(u64::from(PACK_STREAM_MAX_EXTENT_BYTES)) as u32;
    let checkpoint_batch =
        (total - u64::from(max_extent)).min(u64::from(STREAM_CHECKPOINT_BATCH_BYTES)) as u32;
    let minimum_window = u64::from(max_extent) + u64::from(checkpoint_batch);
    let window = PACK_STREAM_RECEIVE_WINDOW_BYTES
        .max(minimum_window)
        .min(total);
    Ok((max_extent, checkpoint_batch, window))
}

fn pack_frame_count(total: u64) -> u64 {
    // Data-frame count plus bounded allowance for the signed terminal,
    // protected open/result records, and post-quantum mission envelopes.
    total
        .div_ceil(u64::from(PACK_STREAM_MAX_EXTENT_BYTES))
        .saturating_add(64)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_completed_pack(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    guard: &EventLaneGuard,
    direction: EventDirection,
    source: CompletedPackStreamSource,
    resume: BlobPublicationResumeV1,
    profile_digest: [u8; 32],
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    guard.check(store)?;
    let total = source.publication.wire_len();
    let segment_count = source.commitment.commitment().segment_count();
    let computed =
        EncryptedBlobStreamSegment::packed_wire_len(source.open.open().total_len(), segment_count)
            .ok_or_else(|| protocol("completed pack wire length overflow"))?;
    if computed != total {
        return Err(protocol(
            "completed pack length differs from canonical segment records",
        ));
    }
    let mut reader = store.open_blob_stream_read_session_with_policy(
        guard.policy(),
        &source.publication,
        &source.open,
        &source.commitment,
    )?;
    let transfer = *source.publication.stream_id().as_bytes();
    let source_id = BlobTransferId::new(transfer);
    if resume.direction != direction
        || resume.stream_id != transfer
        || resume.open_digest != source.open.open().digest()
    {
        return Err(protocol("completed pack resume identity differs"));
    }
    reader.resume_at(resume.next_segment_index, resume.durable_wire_offset)?;
    let generation = resume.checkpoint_generation;
    let nonce = attempt_nonce(mission.session_id(), direction, transfer, generation);
    let open = StreamOpenV1 {
        class: crate::stream_transfer::StreamClass::Blob,
        direction: expected_direction(direction),
        session_transcript: mission.session_id(),
        exchange_id: exchange_id(mission.session_id(), direction, source_id),
        transfer_id: transfer,
        open_digest: source.open.open().digest(),
        source_transfer_id: [0; 32],
        publication_id: *source.publication.blob_id().as_bytes(),
        variant_id: [0; 32],
        total_len: total,
        attempt_nonce: nonce,
        checkpoint_generation: generation,
        custody_digest: None,
    };
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .open_attempt(open_request(total, pack_frame_count(total))?)
        .await
        .map_err(transport)?;
    let selection = BlobStreamPlanSelectionV1 {
        source_id,
        next_carrier_index: resume.next_segment_index,
        durable_offset: resume.durable_wire_offset,
        checkpoint_generation: generation,
    };
    let mut buffered = Vec::new();
    let mut buffered_offset = 0_usize;
    let mut wire_offset = resume.durable_wire_offset;
    let signed_commitment = source.publication.authenticated_commitment().to_vec();
    let code = drive_sender_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        open,
        selection,
        Some(resume),
        source.open.open().total_len(),
        signed_commitment,
        move |offset, maximum| {
            if offset != wire_offset || maximum == 0 {
                return Err(protocol("completed pack reader cursor differs"));
            }
            let mut output = Vec::with_capacity(maximum);
            while output.len() < maximum {
                if buffered_offset == buffered.len() {
                    buffered.clear();
                    buffered_offset = 0;
                    let Some(segment) = reader.next_encrypted_segment()? else {
                        break;
                    };
                    let len = u32::try_from(segment.len())
                        .map_err(|_| protocol("encrypted segment length exceeds u32"))?;
                    buffered.extend_from_slice(&len.to_be_bytes());
                    buffered.extend_from_slice(&segment);
                }
                if output.is_empty() && buffered_offset == 0 && buffered.len() <= maximum {
                    output.append(&mut buffered);
                    buffered_offset = 0;
                    break;
                }
                let take = (maximum - output.len()).min(buffered.len() - buffered_offset);
                output.extend_from_slice(&buffered[buffered_offset..buffered_offset + take]);
                buffered_offset += take;
            }
            if output.is_empty() {
                return Err(protocol("completed pack ended before declared wire length"));
            }
            wire_offset = wire_offset
                .checked_add(output.len() as u64)
                .ok_or_else(|| protocol("completed pack reader offset overflow"))?;
            Ok(output)
        },
    )
    .await?;
    if matches!(
        code,
        StreamResultCode::Promoted | StreamResultCode::AlreadyPresent
    ) {
        guard.check(store)?;
        // A concurrent successful contact may already have moved the hint.
        // Failed CAS preserves its newer position; settlement remains valid.
        let _ = store.compare_and_advance_mutable_transfer_cursor(
            mission.peer().mission_id(),
            MutableTransferCursorClass::BlobStream,
            MutableTransferCursorMode::OfferToPeer,
            source.scheduling_cursor,
            transfer,
        )?;
    }
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes: 0,
            retransmitted_bytes: 0,
            receive_limit_bytes: 0,
            checkpoint_bytes: total,
            checkpoint_latency_ms: 0,
            writer_commits: 0,
            failover_recoveries: 0,
        },
    })
}

struct PackReceiveState {
    stream: ReceivingPackStream,
    buffered: Vec<u8>,
    buffered_consumed: usize,
    appended_wire_offset: u64,
    durable_resume: BlobStreamCryptoResume,
    appended_since_checkpoint: bool,
    last_checkpoint_at: std::time::Instant,
}

pub(super) async fn receive_completed_pack(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    guard: &EventLaneGuard,
    direction: EventDirection,
    received: ReceivedPackStream,
    profile_digest: [u8; 32],
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    guard.check(store)?;
    let received = match received {
        ReceivedPackStream::Receiving(received) => *received,
        ReceivedPackStream::Complete(completed) => {
            return settle_existing_pack(
                store,
                connection,
                mission,
                guard,
                direction,
                *completed,
                profile_digest,
            )
            .await;
        }
    };
    let intent_total_len = received.open.open().total_len();
    let intent_digest = received.open.open().digest();
    let transfer = *received.open.open().stream_id().as_bytes();
    let segment_count = received.commitment.commitment().segment_count();
    let total = EncryptedBlobStreamSegment::packed_wire_len(intent_total_len, segment_count)
        .ok_or_else(|| protocol("received pack wire length overflow"))?;
    let crypto_resume = received.pack.crypto_resume();
    let progress = crypto_resume.progress();
    let durable_wire_offset = progress.durable_wire_offset();
    let remaining = total
        .checked_sub(durable_wire_offset)
        .ok_or_else(|| protocol("receiver durable offset exceeds completed pack"))?;
    let (max_extent, checkpoint_batch, relative_limit) = pack_attempt_flow(remaining)?;
    let generation = progress.generation();
    let initial_limit = durable_wire_offset
        .checked_add(relative_limit)
        .ok_or_else(|| protocol("receiver absolute credit overflow"))?
        .max(durable_wire_offset);
    let initial_checkpoint = crate::stream_transfer::StreamCheckpointAuthorityV1 {
        durable_plaintext_offset: progress.durable_plaintext_offset(),
        durable_ciphertext_offset: durable_wire_offset,
        next_segment_index: progress.next_segment_index(),
        plaintext_commitment: if generation == 0 {
            [1; 32]
        } else {
            crypto_resume.plaintext_checkpoint().commitment()
        },
        ciphertext_commitment: if generation == 0 {
            [1; 32]
        } else {
            crypto_resume.ciphertext_checkpoint().commitment()
        },
        checkpoint_generation: generation,
        absolute_receive_limit: initial_limit,
    };
    let nonce = attempt_nonce(mission.session_id(), direction, transfer, generation);
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .accept_attempt(open_request(total, pack_frame_count(total))?)
        .await
        .map_err(transport)?;
    let state = Mutex::new(Some(PackReceiveState {
        stream: received,
        buffered: Vec::new(),
        buffered_consumed: 0,
        appended_wire_offset: durable_wire_offset,
        durable_resume: crypto_resume,
        appended_since_checkpoint: false,
        last_checkpoint_at: std::time::Instant::now(),
    }));
    let writer_commits = AtomicU32::new(0);
    let received_bytes = AtomicU64::new(0);
    let greatest_receive_limit = AtomicU64::new(initial_limit);
    let greatest_checkpoint_latency_ms = AtomicU64::new(0);
    #[cfg(test)]
    let checkpoint_fault_cache = super::CONTACT_EVENT_ROUTE_CACHE
        .try_with(Arc::clone)
        .map_err(|_| protocol("completed pack test lacks its contact cache"))?;
    let code = drive_receiver_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        nonce,
        transfer,
        intent_digest,
        total,
        durable_wire_offset,
        generation,
        Some(initial_checkpoint),
        None,
        initial_limit,
        max_extent,
        checkpoint_batch,
        |_, frames| {
            let mut slot = state
                .lock()
                .map_err(|_| protocol("pack receive state lock poisoned"))?;
            let current = slot
                .as_mut()
                .ok_or_else(|| protocol("pack receive state already promoted"))?;
            for frame in frames {
                current.buffered.extend_from_slice(&frame.bytes);
                received_bytes.store(
                    received_bytes
                        .load(Ordering::Relaxed)
                        .checked_add(frame.bytes.len() as u64)
                        .ok_or_else(|| protocol("received pack byte count overflow"))?,
                    Ordering::Relaxed,
                );
            }

            let mut record_cursor = current.buffered_consumed;
            let mut segments = Vec::new();
            let mut record_ranges = Vec::new();
            loop {
                let available = current.buffered.len().saturating_sub(record_cursor);
                if available < 4 {
                    break;
                }
                let segment_len = u32::from_be_bytes(
                    current.buffered[record_cursor..record_cursor + 4]
                        .try_into()
                        .expect("four-byte segment length"),
                ) as usize;
                let record_len = 4_usize
                    .checked_add(segment_len)
                    .ok_or_else(|| protocol("received segment length overflow"))?;
                if segment_len == 0 || segment_len > 2 * 1024 * 1024 {
                    return Err(protocol("received encrypted segment length is invalid"));
                }
                if available < record_len {
                    break;
                }
                let record_end = record_cursor
                    .checked_add(record_len)
                    .ok_or_else(|| protocol("received segment end overflow"))?;
                segments.push(
                    EncryptedBlobStreamSegment::decode(
                        &current.buffered[record_cursor + 4..record_end],
                    )
                    .map_err(protocol)?,
                );
                record_ranges.push((record_cursor + 4, record_end, record_len));
                record_cursor = record_end;
            }

            let authenticated = current
                .stream
                .decryptor
                .decrypt_segment_batch_checkpointed(&segments)
                .map_err(protocol)?;
            for ((segment, (encoded_start, record_end, record_len)), (plaintext, checkpoint)) in
                segments.iter().zip(record_ranges).zip(authenticated)
            {
                current.stream.pack.append_authenticated_encoded_segment(
                    &plaintext,
                    segment,
                    &current.buffered[encoded_start..record_end],
                    checkpoint,
                )?;
                current.buffered_consumed = record_end;
                current.appended_wire_offset = current
                    .appended_wire_offset
                    .checked_add(record_len as u64)
                    .ok_or_else(|| protocol("received appended wire offset overflow"))?;
                current.appended_since_checkpoint = true;
            }
            if current.buffered_consumed == current.buffered.len() {
                current.buffered.clear();
                current.buffered_consumed = 0;
            } else if current.buffered_consumed != 0 {
                current.buffered.drain(..current.buffered_consumed);
                current.buffered_consumed = 0;
            }
            let durable_wire_offset = current.durable_resume.progress().durable_wire_offset();
            let pending_wire_bytes = current
                .appended_wire_offset
                .checked_sub(durable_wire_offset)
                .ok_or_else(|| protocol("appended pack precedes durable checkpoint"))?;
            #[cfg(test)]
            if checkpoint_fault_cache
                .test_blob_contact_fault_pending(TestBlobContactFault::GroupedPackDeferredAppend)
            {
                // This exact-contact regression exercises byte-threshold grouping
                // even on slow debug hosts; ordinary tests retain the 2s clock.
                current.last_checkpoint_at = std::time::Instant::now();
            }
            let flush = pending_wire_bytes >= PACK_STREAM_CHECKPOINT_GROUP_BYTES
                || current.appended_wire_offset == total
                || current.last_checkpoint_at.elapsed() >= PACK_STREAM_CHECKPOINT_INTERVAL
                || pending_wire_bytes
                    .saturating_add(u64::from(checkpoint_batch))
                    .saturating_add(u64::from(max_extent))
                    >= PACK_STREAM_RECEIVE_WINDOW_BYTES;
            if !flush {
                current.stream.pack.advance_background_writeback()?;
            }
            if current.appended_since_checkpoint && flush {
                let checkpoint_started = std::time::Instant::now();
                current.stream.pack.checkpoint(store, guard.policy())?;
                greatest_checkpoint_latency_ms.fetch_max(
                    u64::try_from(checkpoint_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                // crypto_resume() exposes current accumulators, so cache it
                // only after the file, journal and Store checkpoint commit.
                current.durable_resume = current.stream.pack.crypto_resume();
                current.appended_since_checkpoint = false;
                current.last_checkpoint_at = std::time::Instant::now();
                writer_commits.store(
                    writer_commits
                        .load(Ordering::Relaxed)
                        .checked_add(1)
                        .ok_or_else(|| protocol("pack writer commit count overflow"))?,
                    Ordering::Relaxed,
                );
            }
            #[cfg(test)]
            if !flush
                && durable_wire_offset != 0
                && pending_wire_bytes != 0
                && checkpoint_fault_cache
                    .fire_test_blob_contact_fault(TestBlobContactFault::GroupedPackDeferredAppend)
            {
                *checkpoint_fault_cache
                    .blob_contact_fault
                    .as_ref()
                    .expect("fired grouped pack fault")
                    .grouped_pack_checkpoint
                    .lock()
                    .expect("grouped pack observation lock") = Some((
                    current.durable_resume.clone(),
                    current.appended_wire_offset,
                    current.buffered.len(),
                ));
                return Err(protocol(
                    "injected failure after grouped pack deferred append",
                ));
            }
            // Parser callbacks stay bounded at 15 MiB. Until a grouped Store
            // commit completes, send an exact heartbeat of prior authority;
            // appended bytes never advance the advertised durable credit.
            let resume = &current.durable_resume;
            let progress = resume.progress();
            let durable_wire_offset = progress.durable_wire_offset();
            let initial_authority = progress.generation() == 0
                && progress.durable_plaintext_offset() == 0
                && durable_wire_offset == 0;
            let limit = durable_wire_offset
                .saturating_add(PACK_STREAM_RECEIVE_WINDOW_BYTES)
                .min(total)
                .max(initial_limit);
            greatest_receive_limit.fetch_max(limit, Ordering::Relaxed);
            Ok(crate::stream_transfer::StreamCheckpointAuthorityV1 {
                durable_plaintext_offset: progress.durable_plaintext_offset(),
                durable_ciphertext_offset: durable_wire_offset,
                next_segment_index: progress.next_segment_index(),
                plaintext_commitment: if initial_authority {
                    [1; 32]
                } else {
                    resume.plaintext_checkpoint().commitment()
                },
                ciphertext_commitment: if initial_authority {
                    [1; 32]
                } else {
                    resume.ciphertext_checkpoint().commitment()
                },
                checkpoint_generation: progress.generation(),
                absolute_receive_limit: limit,
            })
        },
        |_, finish| {
            let mut slot = state
                .lock()
                .map_err(|_| protocol("pack receive state lock poisoned"))?;
            let current = slot
                .take()
                .ok_or_else(|| protocol("pack receive state already promoted"))?;
            if !current.buffered.is_empty()
                || current.buffered_consumed != 0
                || current.appended_wire_offset != total
                || current.durable_resume.progress().durable_wire_offset() != total
                || current.appended_since_checkpoint
                || finish.final_plaintext_offset != current.stream.open.open().total_len()
                || finish.final_ciphertext_offset != total
                || finish.signed_commitment != current.stream.commitment.authenticated_bytes()
            {
                return Err(protocol("completed pack finish authority differs"));
            }
            let final_sample = current.stream.commitment.commitment().final_custody();
            let promotion = current.stream.pack.finish_and_promote(
                store,
                guard.policy(),
                &current.stream.commitment,
                final_sample,
            )?;
            let code = if promotion.duplicate() {
                StreamResultCode::AlreadyPresent
            } else {
                StreamResultCode::Promoted
            };
            let blob_id = *promotion.blob_id().as_bytes();
            Ok((
                code,
                blob_id,
                completed_pack_result_digest(transfer, blob_id, code),
            ))
        },
    )
    .await?;
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes: received_bytes.load(Ordering::Relaxed),
            retransmitted_bytes: 0,
            receive_limit_bytes: greatest_receive_limit.load(Ordering::Relaxed),
            checkpoint_bytes: total,
            checkpoint_latency_ms: greatest_checkpoint_latency_ms.load(Ordering::Relaxed),
            writer_commits: writer_commits.load(Ordering::Relaxed),
            failover_recoveries: 0,
        },
    })
}

/// A completed publication still performs the authenticated terminal handshake.
/// No writer or reservation is opened and any payload is rejected.
async fn settle_existing_pack(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    guard: &EventLaneGuard,
    direction: EventDirection,
    completed: CompletedPackAdmission,
    profile_digest: [u8; 32],
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    let source = completed.source;
    let progress = completed.resume.progress();
    let total = source.publication.wire_len();
    let transfer = *source.open.open().stream_id().as_bytes();
    let generation = progress.generation();
    let (max_extent, checkpoint_batch, window) = pack_attempt_flow(0)?;
    let limit = total
        .checked_add(window)
        .ok_or_else(|| protocol("completed receiver credit overflow"))?;
    let authority = crate::stream_transfer::StreamCheckpointAuthorityV1 {
        durable_plaintext_offset: progress.durable_plaintext_offset(),
        durable_ciphertext_offset: total,
        next_segment_index: progress.next_segment_index(),
        plaintext_commitment: completed.resume.plaintext_checkpoint().commitment(),
        ciphertext_commitment: completed.resume.ciphertext_checkpoint().commitment(),
        checkpoint_generation: generation,
        absolute_receive_limit: limit,
    };
    let nonce = attempt_nonce(mission.session_id(), direction, transfer, generation);
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .accept_attempt(open_request(total, pack_frame_count(total))?)
        .await
        .map_err(transport)?;
    let code = drive_receiver_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        nonce,
        transfer,
        source.open.open().digest(),
        total,
        total,
        generation,
        Some(authority),
        None,
        limit,
        max_extent,
        checkpoint_batch,
        |_, _| Err(protocol("completed publication cannot receive more data")),
        |_, finish| {
            guard.check(store)?;
            store.completed_blob_stream_crypto_resume_with_policy(
                guard.policy(),
                &source.publication,
                &source.open,
                &source.commitment,
            )?;
            if finish.final_plaintext_offset != source.open.open().total_len()
                || finish.final_ciphertext_offset != total
                || finish.signed_commitment != source.commitment.authenticated_bytes()
            {
                return Err(protocol("completed pack finish authority differs"));
            }
            let code = StreamResultCode::AlreadyPresent;
            let blob_id = *source.publication.blob_id().as_bytes();
            Ok((
                code,
                blob_id,
                completed_pack_result_digest(transfer, blob_id, code),
            ))
        },
    )
    .await?;
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes: 0,
            retransmitted_bytes: 0,
            receive_limit_bytes: limit,
            checkpoint_bytes: total,
            checkpoint_latency_ms: 0,
            writer_commits: 0,
            failover_recoveries: 0,
        },
    })
}

fn protocol(error: impl std::fmt::Display) -> NodeError {
    NodeError::Protocol(format!("Blob stream: {error}"))
}

fn transport(error: StreamTransportError) -> NodeError {
    let category = match error {
        StreamTransportError::Ineligible => "ineligible",
        StreamTransportError::Timeout => "timeout",
        StreamTransportError::Closed => "closed",
        StreamTransportError::Bounds => "bounds",
    };
    protocol(format_args!("transport {category}"))
}

fn result_digest(
    source: BlobTransferId,
    manifest_digest: [u8; 32],
    code: StreamResultCode,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/result/v1\0");
    digest.update(source.as_bytes());
    digest.update(manifest_digest);
    digest.update([code as u8]);
    digest.finalize().into()
}

fn bind_stream_open_custody_digest(
    source_digest: [u8; 32],
    custody_digest: Option<[u8; 32]>,
) -> [u8; 32] {
    let Some(custody_digest) = custody_digest else {
        return source_digest;
    };
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/retained-open-custody/v1\0");
    digest.update(source_digest);
    digest.update([1]);
    digest.update(custody_digest);
    digest.finalize().into()
}

fn require_stream_open_custody_digest(
    source_digest: [u8; 32],
    expected: Option<[u8; 32]>,
    received_open_digest: [u8; 32],
) -> Result<(), NodeError> {
    if bind_stream_open_custody_digest(source_digest, expected) == received_open_digest {
        Ok(())
    } else {
        Err(protocol(
            "stream open digest differs from authenticated source or custody prelude",
        ))
    }
}

fn exchange_id(session: [u8; 32], direction: EventDirection, source: BlobTransferId) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/exchange/v1\0");
    digest.update(session);
    digest.update([match direction {
        EventDirection::ToSessionInitiator => 1,
        EventDirection::ToSessionResponder => 2,
    }]);
    digest.update(source.as_bytes());
    u64::from_be_bytes(digest.finalize()[..8].try_into().expect("SHA-256 prefix"))
}

fn selected_iroh_adapter(
    connection: &aster_iroh::Connection,
) -> Result<IrohQuicV1Adapter, NodeError> {
    let adapter = IrohQuicV1Adapter::new(connection.clone());
    let requirements = TransferRequirements::default();
    let candidates = [TransportCandidate {
        id: adapter.id(),
        locally_enabled: true,
        policy_allowed: true,
        peer_support: Some(AuthenticatedPeerSupport::new(
            AuthenticatedSupportSource::ProvisionedPeer,
            true,
        )),
        reliable_ordered: true,
        full_duplex: true,
        health: adapter.health(),
        configured_priority: 0,
    }];
    let selected = TransportSelector::rank(requirements, &candidates)
        .into_iter()
        .next()
        .ok_or_else(|| protocol("no authenticated eligible transport"))?;
    if selected.id != StreamTransportId::IrohQuicV1 || !adapter.eligibility(requirements) {
        return Err(protocol("selected transport adapter is unavailable"));
    }
    Ok(adapter)
}

fn stream_budgets(total_len: u64, carrier_count: u64) -> Result<(usize, usize), NodeError> {
    let records = carrier_count
        .checked_add(4)
        .ok_or_else(|| protocol("stream record count overflow"))?;
    let overhead = records
        .checked_mul(STREAM_RECORD_BUDGET_BYTES as u64)
        .ok_or_else(|| protocol("stream framing budget overflow"))?;
    let data = total_len
        .checked_add(overhead)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| protocol("stream data budget exceeds this platform"))?;
    let control = overhead
        .checked_add(64 * 1024)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| protocol("stream control budget exceeds this platform"))?;
    Ok((data, control))
}

fn open_request(total_len: u64, carrier_count: u64) -> Result<AttemptOpenRequest, NodeError> {
    let (max_data_bytes, max_control_bytes) = stream_budgets(total_len, carrier_count)?;
    Ok(AttemptOpenRequest {
        deadline: tokio::time::Instant::now() + STREAM_ATTEMPT_DEADLINE,
        max_data_bytes,
        max_control_bytes,
    })
}

/// Derives a fresh attempt nonce from the authenticated mission session and
/// exact logical transfer. Both endpoints can derive it before opening the
/// first protected stream record; a reconnect necessarily changes `session`.
pub(super) fn attempt_nonce(
    session: [u8; 32],
    direction: EventDirection,
    transfer: [u8; 32],
    checkpoint_generation: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/attempt-nonce/v1\0");
    digest.update(session);
    digest.update([match direction {
        EventDirection::ToSessionInitiator => 1,
        EventDirection::ToSessionResponder => 2,
    }]);
    digest.update(transfer);
    digest.update(checkpoint_generation.to_be_bytes());
    digest.finalize().into()
}

const ATTEMPT_PROTECTED_RECORD: u8 = 0xa0;
const ATTEMPT_DIRECT_DATA_RECORD: u8 = 0xa1;

fn encode_direct_data_record(frame: StreamFrame) -> Result<Vec<u8>, NodeError> {
    if !matches!(frame, StreamFrame::Data(_)) {
        return Err(protocol("direct attempt record is not stream data"));
    }
    let encoded = frame.encode_for_context(9, 5).map_err(protocol)?;
    let mut record = Vec::with_capacity(1 + encoded.len());
    record.push(ATTEMPT_DIRECT_DATA_RECORD);
    record.extend_from_slice(&encoded);
    Ok(record)
}

fn decode_direct_data_record(record: Vec<u8>) -> Result<StreamFrame, NodeError> {
    let Some(&kind) = record.first() else {
        return Err(protocol("empty attempt record"));
    };
    if kind != ATTEMPT_DIRECT_DATA_RECORD {
        return Err(protocol("attempt record is not direct stream data"));
    }
    let encoded = bytes::Bytes::from(record).slice(1..);
    let frame = decode_owned_data_for_context(9, 5, encoded).map_err(protocol)?;
    if !matches!(frame, StreamFrame::Data(_)) {
        return Err(protocol("direct attempt record is not stream data"));
    }
    Ok(frame)
}

fn protect(
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    nonce: [u8; 32],
    frame: StreamFrame,
) -> Result<Vec<u8>, NodeError> {
    if matches!(frame, StreamFrame::Data(_)) {
        return encode_direct_data_record(frame);
    }
    let plaintext = frame.encode_for_context(9, 5).map_err(protocol)?;
    let protected = mission
        .seal_v9_blob_application_frame(profile_digest, direction, nonce, &plaintext)
        .map_err(NodeError::from)?;
    let mut record = Vec::with_capacity(1 + protected.len());
    record.push(ATTEMPT_PROTECTED_RECORD);
    record.extend_from_slice(&protected);
    Ok(record)
}

fn open_control(
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    nonce: [u8; 32],
    record: Vec<u8>,
) -> Result<StreamFrame, NodeError> {
    let Some((&kind, encoded)) = record.split_first() else {
        return Err(protocol("empty attempt record"));
    };
    if kind == ATTEMPT_DIRECT_DATA_RECORD {
        return decode_direct_data_record(record);
    }
    if kind != ATTEMPT_PROTECTED_RECORD {
        return Err(protocol("unknown attempt record kind"));
    }
    let plaintext =
        mission.open_v9_blob_application_frame(profile_digest, direction, nonce, encoded)?;
    let frame = StreamFrame::decode_for_context(9, 5, &plaintext).map_err(protocol)?;
    if matches!(frame, StreamFrame::Data(_)) {
        return Err(protocol("stream data used protected attempt record"));
    }
    Ok(frame)
}

/// Drives one sender attempt over the selected adapter. The supplied reader
/// is synchronous and bounded: it must release all Store/depot authority before
/// this function awaits network I/O.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_sender_attempt<R>(
    attempt: Arc<dyn StreamAttempt>,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    open: StreamOpenV1,
    expected_checkpoint: BlobStreamPlanSelectionV1,
    expected_resume: Option<BlobPublicationResumeV1>,
    final_plaintext_offset: u64,
    signed_commitment: Vec<u8>,
    mut read_extent: R,
) -> Result<StreamResultCode, NodeError>
where
    R: FnMut(u64, usize) -> Result<Vec<u8>, NodeError>,
{
    let nonce = open.attempt_nonce;
    let total = open.total_len;
    let mut state = StreamSenderState::new(open.transfer_id, nonce, total);
    let protected = protect(
        mission,
        profile_digest,
        direction,
        nonce,
        StreamFrame::Open(open),
    )?;
    attempt.send_data(&protected).await.map_err(transport)?;

    let accepted = attempt
        .receive_control()
        .await
        .map_err(transport)?
        .ok_or_else(|| protocol("control stream closed before acceptance"))?;
    let StreamFrame::Accept(accepted) =
        open_control(mission, profile_digest, direction, nonce, accepted)?
    else {
        return Err(protocol("first control record is not acceptance"));
    };
    if accepted.durable_ciphertext_offset != expected_checkpoint.durable_offset
        || accepted.checkpoint_generation != expected_checkpoint.checkpoint_generation
    {
        return Err(protocol(
            "acceptance differs from the authenticated pre-open plan",
        ));
    }
    if expected_resume.is_some_and(|resume| {
        accepted.durable_plaintext_offset != resume.durable_plaintext_offset
            || accepted.durable_ciphertext_offset != resume.durable_wire_offset
            || accepted.next_segment_index != resume.next_segment_index
            || accepted.plaintext_commitment != resume.plaintext_commitment
            || accepted.ciphertext_commitment != resume.ciphertext_commitment
            || accepted.checkpoint_generation != resume.checkpoint_generation
    }) {
        return Err(protocol(
            "acceptance differs from receiver pre-open resume authority",
        ));
    }
    state.accept(accepted).map_err(protocol)?;

    let mut finish_sent = false;
    loop {
        if state.next_offset() < total && state.next_offset() < state.receive_limit() {
            let available = state.receive_limit() - state.next_offset();
            let maximum = usize::try_from(available.min(u64::from(state.max_extent_bytes())))
                .map_err(|_| protocol("extent bound exceeds usize"))?;
            let bytes = read_extent(state.next_offset(), maximum)?;
            match state.send_extent(bytes).map_err(protocol)? {
                StreamAction::Send(frame) => {
                    let protected = protect(mission, profile_digest, direction, nonce, frame)?;
                    attempt.send_data(&protected).await.map_err(transport)?;
                    continue;
                }
                StreamAction::Retry(_) => {}
                _ => return Err(protocol("sender produced an invalid data transition")),
            }
        } else if state.next_offset() == total && !finish_sent {
            let StreamAction::Send(frame) = state
                .finish_bound(final_plaintext_offset, signed_commitment.clone())
                .map_err(protocol)?
            else {
                return Err(protocol("sender produced an invalid finish transition"));
            };
            let protected = protect(mission, profile_digest, direction, nonce, frame)?;
            attempt.send_data(&protected).await.map_err(transport)?;
            finish_sent = true;
        }

        let control = attempt
            .receive_control()
            .await
            .map_err(transport)?
            .ok_or_else(|| protocol("control stream closed before settlement"))?;
        match open_control(mission, profile_digest, direction, nonce, control)? {
            StreamFrame::Checkpoint(checkpoint) => {
                state.checkpoint(checkpoint).map_err(protocol)?;
            }
            StreamFrame::Result(result) if finish_sent => {
                let (StreamAction::Send(ack), StreamAction::Terminal(code)) =
                    state.result(result).map_err(protocol)?
                else {
                    return Err(protocol("sender produced an invalid result transition"));
                };
                let protected = protect(mission, profile_digest, direction, nonce, ack)?;
                attempt.send_data(&protected).await.map_err(transport)?;
                attempt.finish_data().await.map_err(transport)?;
                if attempt
                    .receive_control()
                    .await
                    .map_err(transport)?
                    .is_some()
                {
                    return Err(protocol("control record followed terminal settlement"));
                }
                return Ok(code);
            }
            _ => return Err(protocol("unexpected control record")),
        }
    }
}

fn expected_direction(direction: EventDirection) -> StreamDirection {
    match direction {
        EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
        EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
    }
}

fn stream_open(
    mission: &MissionSession,
    direction: EventDirection,
    source: BlobTransferId,
    loaded: &CompletedBlobStreamSource,
    layout: &BlobStreamLayout,
    checkpoint_generation: u64,
) -> StreamOpenV1 {
    let transfer = *source.as_bytes();
    let nonce = attempt_nonce(
        mission.session_id(),
        direction,
        transfer,
        checkpoint_generation,
    );
    StreamOpenV1 {
        class: crate::stream_transfer::StreamClass::Blob,
        direction: expected_direction(direction),
        session_transcript: mission.session_id(),
        exchange_id: exchange_id(mission.session_id(), direction, source),
        transfer_id: transfer,
        open_digest: *loaded.blob.blob_id().as_bytes(),
        source_transfer_id: transfer,
        publication_id: *loaded.blob.blob_id().as_bytes(),
        variant_id: *BlobVariantId::for_content(
            loaded.blob.blob_id(),
            loaded.plan.manifest().content_group(),
            loaded.plan.manifest().content_epoch(),
        )
        .as_bytes(),
        total_len: layout.total_encoded_len(),
        attempt_nonce: nonce,
        checkpoint_generation,
        custody_digest: None,
    }
}

pub(super) fn select_receive_plan(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    direction: EventDirection,
    local_interest: &BlobInterest,
    candidates: &BlobStreamReceiveCandidates,
    initial_finite: Option<&DeferredFiniteBlobStreamAdmission>,
) -> Result<BlobStreamPlanV1, NodeError> {
    guard.check(store)?;
    if let Some(initial) = initial_finite {
        if local_interest
            .selector(initial.blob.topic(), initial.blob.scope())
            .filter(|selector| selector.epoch() == initial.blob.key_epoch())
            .is_none()
        {
            return Err(protocol(
                "initial finite source is outside the authenticated local interest",
            ));
        }
        let layout = BlobStreamLayout::from_plan(&initial.plan).map_err(protocol)?;
        if !layout.contains_checkpoint(0, 0) {
            return Err(protocol("initial finite source has no zero checkpoint"));
        }
        return Ok(BlobStreamPlanV1 {
            direction,
            selection: Some(BlobStreamPlanSelectionV1 {
                source_id: initial.source,
                next_carrier_index: 0,
                durable_offset: 0,
                checkpoint_generation: 1,
            }),
        });
    }
    // Only the exact reconciliation snapshot establishes that this peer has
    // the completed source. A global pending source may belong to another peer.
    // Freshly admitted metadata takes priority so its deferred cursor remains
    // bound to the transfer that actually completes.
    for &source in candidates.sources() {
        let Some(retained) =
            blob_source_projection_for_contact(store, source, BlobContactMode::StreamV1)?
        else {
            continue;
        };
        if retained.retention != aster_redb_store::BlobSourceRetention::Pending {
            continue;
        }
        let projection = retained.source;
        if local_interest
            .selector(&projection.topic, &projection.scope)
            .filter(|selector| selector.epoch() == projection.epoch)
            .is_none()
        {
            if pending_blob_claim_is_current(
                store,
                verifier,
                &projection,
                BlobContactMode::StreamV1,
            )? {
                abort_pending_blob_with_cached_claim(store, verifier, source)?;
            }
            continue;
        }
        let Some((_blob, _, plan)) =
            load_pending_blob_plan(store, verifier, source, BlobContactMode::StreamV1)?
        else {
            continue;
        };
        let layout = BlobStreamLayout::from_plan(&plan).map_err(protocol)?;
        let checkpoint = store.blob_stream_checkpoint_with_policy(guard.policy(), source, &plan)?;
        if !layout.contains_checkpoint(
            checkpoint.next_carrier_index,
            checkpoint.durable_encoded_offset,
        ) {
            return Err(protocol(
                "durable checkpoint is outside the selected Blob layout",
            ));
        }
        return Ok(BlobStreamPlanV1 {
            direction,
            selection: Some(BlobStreamPlanSelectionV1 {
                source_id: source,
                next_carrier_index: checkpoint.next_carrier_index,
                durable_offset: checkpoint.durable_encoded_offset,
                checkpoint_generation: checkpoint.generation,
            }),
        });
    }
    Ok(BlobStreamPlanV1 {
        direction,
        selection: None,
    })
}

fn load_authorized_send_source(
    store: &Store,
    mission: &MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    selection: BlobStreamPlanSelectionV1,
    peer_interest: &BlobInterest,
) -> Result<(CompletedBlobStreamSource, BlobStreamLayout), NodeError> {
    guard.check(store)?;
    let loaded = load_completed_blob_stream_source(store, verifier, selection.source_id)?
        .ok_or_else(|| protocol("selected completed source is unavailable"))?;
    let layout = BlobStreamLayout::from_plan(&loaded.plan).map_err(protocol)?;
    if !layout.contains_checkpoint(selection.next_carrier_index, selection.durable_offset) {
        return Err(protocol(
            "pre-open checkpoint is outside the completed Blob layout",
        ));
    }
    let selector = peer_interest
        .selector(loaded.blob.topic(), loaded.blob.scope())
        .filter(|selector| selector.epoch() == loaded.blob.key_epoch())
        .ok_or_else(|| protocol("pre-open source is outside peer interest"))?;
    let peer = mission.peer().mission_id();
    let commitments = mission.peer_route_grant_commitments();
    if !verifier.peer_can_route(
        peer,
        commitments,
        loaded.blob.scope(),
        loaded.blob.key_epoch(),
    ) || !verifier.peer_can_open_blob_content(
        peer,
        commitments,
        loaded.blob.scope(),
        loaded.blob.topic(),
        loaded.blob.key_epoch(),
        selector.content_proof(),
    ) {
        return Err(protocol("peer lost exact pre-open Blob entitlement"));
    }
    Ok((loaded, layout))
}

pub(super) fn validate_send_plan(
    store: &Store,
    mission: &MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    selection: BlobStreamPlanSelectionV1,
    peer_interest: &BlobInterest,
) -> Result<(), NodeError> {
    load_authorized_send_source(store, mission, verifier, guard, selection, peer_interest)?;
    Ok(())
}

/// Sends one exact durable source selected by the receiver's authenticated
/// pre-open plan.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    direction: EventDirection,
    selection: BlobStreamPlanSelectionV1,
    peer_interest: &BlobInterest,
    profile_digest: [u8; 32],
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    let source = selection.source_id;
    let (loaded, layout) =
        load_authorized_send_source(store, mission, verifier, guard, selection, peer_interest)?;
    let mut open = stream_open(
        mission,
        direction,
        source,
        &loaded,
        &layout,
        selection.checkpoint_generation,
    );
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .open_attempt(open_request(
            layout.total_encoded_len(),
            layout.carrier_count(),
        )?)
        .await
        .map_err(transport)?;
    if loaded.blob.ttl_ms().is_some() {
        let sample = contact_custody_sample()?
            .ok_or_else(|| protocol("finite stream send lacks a local custody sample"))?;
        let exact_len = u64::try_from(loaded.sealed.len())
            .map_err(|_| protocol("finite stream source length exceeds u64"))?;
        let finalization_charge_ms = custody_finalization_charge_ms(exact_len)?;
        let context = mission.mint_blob_custody_send_context_v2(
            direction,
            open.exchange_id,
            open.attempt_nonce,
            finalization_charge_ms,
        )?;
        let Some(authorized) = store.authorize_finite_blob_stream_v9_send_with_policy(
            guard.policy(),
            &loaded.projection,
            loaded.retention,
            &loaded.blob,
            &loaded.sealed,
            context,
            sample,
        )?
        else {
            return Err(NodeError::CustodySendSkipped);
        };
        let (claim, prepared) = authorized
            .into_claim_v2(&loaded.blob, &loaded.sealed)
            .map_err(|error| {
                protocol(format_args!("invalid outbound custody-v2 claim: {error}"))
            })?;
        open.custody_digest = Some(claim.digest());
        let protected_claim = mission.seal_blob_custody_frame_v2(
            profile_digest,
            direction,
            open.attempt_nonce,
            &claim,
        )?;
        #[cfg(test)]
        let protected_claim = {
            let mut protected_claim = protected_claim;
            let cache = contact_mutable_route_cache(verifier)?;
            if cache.fire_test_blob_contact_fault(TestBlobContactFault::StreamCustodyPreludeTamper)
            {
                let last = protected_claim
                    .last_mut()
                    .ok_or_else(|| protocol("custody prelude is empty"))?;
                *last ^= 1;
            }
            protected_claim
        };
        guard.check(store)?;
        let final_sample = contact_custody_sample()?
            .ok_or_else(|| protocol("finite stream finalization lacks a local custody sample"))?;
        if !store.finalize_finite_blob_send_with_policy(
            guard.policy(),
            prepared,
            &loaded.blob,
            &loaded.sealed,
            final_sample,
        )? {
            return Err(NodeError::CustodySendSkipped);
        }
        require_contact_policy_current()?;
        // The canonical StreamOpen carries one digest. Bind the authenticated
        // finite prelude there rather than in the local-only custody field.
        open.open_digest = bind_stream_open_custody_digest(open.open_digest, open.custody_digest);
        attempt
            .send_data(&protected_claim)
            .await
            .map_err(transport)?;
    }
    let policy = *guard.policy();
    let completion = loaded.completion.clone();
    let plan = &loaded.plan;
    #[cfg(test)]
    let source_fault_cache = contact_mutable_route_cache(verifier)?;
    let code = drive_sender_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        open,
        selection,
        None,
        layout.total_encoded_len(),
        vec![1],
        move |offset, maximum| {
            let layout = BlobStreamLayout::from_plan(plan).map_err(protocol)?;
            let next_carrier_index = layout
                .carrier_index_at_offset(offset)
                .ok_or_else(|| protocol("sender offset is not a carrier boundary"))?;
            let checkpoint = BlobStreamCheckpoint {
                next_carrier_index,
                durable_encoded_offset: offset,
                generation: selection.checkpoint_generation,
            };
            let extent = store
                .read_completed_blob_stream_extent_with_policy(
                    &policy,
                    &completion,
                    plan,
                    checkpoint,
                    maximum,
                )?
                .ok_or_else(|| protocol("completed source ended before declared length"))?;
            #[cfg(test)]
            if source_fault_cache.fire_test_blob_contact_fault(TestBlobContactFault::RangePostcheck)
            {
                return Err(NodeError::FatalBlobCoherence(
                    "injected Blob stream source read coherence failure".into(),
                ));
            }
            Ok(extent.encoded_bytes())
        },
    )
    .await?;
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes: 0,
            retransmitted_bytes: 0,
            receive_limit_bytes: 0,
            checkpoint_bytes: selection.durable_offset,
            checkpoint_latency_ms: 0,
            writer_commits: 0,
            failover_recoveries: 0,
        },
    })
}

fn retained_receive_limit(layout: &BlobStreamLayout, durable_offset: u64) -> u64 {
    let limit = durable_offset.saturating_add(STREAM_RECEIVE_WINDOW_BYTES);
    if limit < layout.total_encoded_len() {
        // Positive credit must end on a carrier boundary: retained sources
        // cannot split one authenticated carrier across network extents.
        layout.carrier_boundary_at_or_before(limit).1
    } else {
        // Credit is receiver allocation, not a declaration of Blob length.
        // Keep a full window for a small final carrier or a completed resume;
        // the stream state separately rejects data past the declared length.
        limit
    }
}

/// Receives one exact durable source selected by the receiver's authenticated
/// pre-open plan, commits bounded whole-carrier batches, and promotes only
/// after the final durable checkpoint.
#[allow(clippy::too_many_arguments)]
pub(super) async fn receive(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    direction: EventDirection,
    selection: BlobStreamPlanSelectionV1,
    profile_digest: [u8; 32],
    initial_finite: Option<DeferredFiniteBlobStreamAdmission>,
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    guard.check(store)?;
    let source = selection.source_id;
    let (blob, manifest_bytes, plan, initial_sealed) = match initial_finite {
        Some(initial) if initial.source == source => (
            initial.blob,
            initial.manifest_bytes,
            initial.plan,
            Some(initial.sealed),
        ),
        Some(_) => {
            return Err(protocol(
                "initial finite admission differs from selected source",
            ));
        }
        None => {
            let (blob, manifest_bytes, plan) =
                load_pending_blob_plan(store, verifier, source, BlobContactMode::StreamV1)?
                    .ok_or_else(|| protocol("selected pending source is unavailable"))?;
            (blob, manifest_bytes, plan, None)
        }
    };
    let initial_admission = initial_sealed.is_some();
    let finite = blob.ttl_ms().is_some();
    let layout = BlobStreamLayout::from_plan(&plan).map_err(protocol)?;
    let checkpoint = if initial_admission {
        BlobStreamCheckpoint {
            next_carrier_index: 0,
            durable_encoded_offset: 0,
            generation: 1,
        }
    } else {
        store.blob_stream_checkpoint_with_policy(guard.policy(), source, &plan)?
    };
    if checkpoint.next_carrier_index != selection.next_carrier_index
        || checkpoint.durable_encoded_offset != selection.durable_offset
        || checkpoint.generation != selection.checkpoint_generation
    {
        return Err(protocol(
            "durable checkpoint changed after the pre-open plan",
        ));
    }
    let nonce = attempt_nonce(
        mission.session_id(),
        direction,
        *source.as_bytes(),
        checkpoint.generation,
    );
    let receive_limit = retained_receive_limit(&layout, checkpoint.durable_encoded_offset);
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .accept_attempt(open_request(
            layout.total_encoded_len(),
            layout.carrier_count(),
        )?)
        .await
        .map_err(transport)?;
    let expected_custody_digest = if finite {
        let sealed = match initial_sealed {
            Some(sealed) => sealed,
            None => {
                store
                    .custody_v2_pending_blob_source(source)?
                    .ok_or_else(|| {
                        protocol("finite pending source became unavailable before custody")
                    })?
                    .sealed
            }
        };
        let protected_claim = attempt
            .receive_data()
            .await
            .map_err(transport)?
            .ok_or_else(|| protocol("data stream closed before finite custody prelude"))?;
        let (claim, contact) = mission.open_blob_custody_frame_v2(
            profile_digest,
            direction,
            nonce,
            &protected_claim,
        )?;
        if claim.session_transcript() != mission.session_id()
            || claim.exchange_id() != exchange_id(mission.session_id(), direction, source)
            || claim.source_transfer_id().as_bytes() != source.as_bytes()
        {
            return Err(protocol(
                "finite custody prelude differs from planned transfer",
            ));
        }
        let digest = claim.digest();
        let cache = contact_mutable_route_cache(verifier)?;
        let _lifecycle = cache.lock_blob_lifecycle()?;
        if initial_admission {
            let receiver_sample = contact_custody_sample()?
                .ok_or_else(|| protocol("finite stream admission lacks a local custody sample"))?;
            store.stage_verified_finite_blob_stream_v9_with_policy(
                guard.policy(),
                &blob,
                &sealed,
                &plan,
                claim,
                contact,
                receiver_sample,
            )?;
            cache_staged_blob_after_transition(
                store,
                verifier,
                &cache,
                source,
                &blob,
                &manifest_bytes,
                &sealed,
                BlobContactMode::StreamV1,
            )?;
        } else {
            store.upgrade_pending_blob_to_stream_v9(
                guard.policy(),
                source,
                &blob,
                &sealed,
                &plan,
                Some((claim, contact)),
            )?;
        }
        let retained = store
            .custody_v2_blob_source_projection(source)?
            .ok_or_else(|| protocol("finite source disappeared after custody age merge"))?;
        if retained.retention != aster_redb_store::BlobSourceRetention::Pending {
            return Err(protocol(
                "finite custody age merge changed source retention",
            ));
        }
        if !initial_admission {
            let refreshed = AuthenticatedBlobRouteClaim::from_verified_for_contact(
                store,
                &blob,
                &sealed,
                &retained.source,
                retained.retention,
                None,
                BlobContactMode::StreamV1,
            )?;
            cache.insert_blob(verifier, refreshed)?;
        }
        let admitted = store.blob_stream_checkpoint_with_policy(guard.policy(), source, &plan)?;
        if admitted != checkpoint {
            return Err(protocol(
                "finite custody admission changed the selected checkpoint",
            ));
        }
        Some(digest)
    } else {
        None
    };
    let policy = *guard.policy();
    let commit_plan = &plan;
    let promote_plan = &plan;
    let promote_blob = blob.clone();
    let promote_manifest = manifest_bytes.clone();
    let manifest_digest = *plan.manifest_digest();
    let mut expected_checkpoint = checkpoint;
    let mut received_bytes = 0_u64;
    let mut greatest_receive_limit = receive_limit;
    let mut greatest_checkpoint_latency_ms = 0_u64;
    let mut writer_commits = 0_u32;
    #[cfg(test)]
    let checkpoint_fault_cache = contact_mutable_route_cache(verifier)?;
    #[cfg(test)]
    let receiver_identity = verifier.identity();
    let code = drive_receiver_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        nonce,
        *source.as_bytes(),
        *blob.blob_id().as_bytes(),
        layout.total_encoded_len(),
        checkpoint.durable_encoded_offset,
        checkpoint.generation,
        None,
        expected_custody_digest,
        receive_limit,
        MAX_STREAM_EXTENT_BYTES as u32,
        RETAINED_STREAM_CHECKPOINT_BATCH_BYTES,
        |_, frames| {
            guard.check(store)?;
            #[cfg(test)]
            if checkpoint_fault_cache
                .fire_test_blob_contact_fault(TestBlobContactFault::AppendCoherence)
            {
                return Err(NodeError::FatalBlobCoherence(
                    "injected Blob stream append coherence failure".into(),
                ));
            }
            let commit_started = std::time::Instant::now();
            let next = commit_received_batch(
                store,
                &policy,
                source,
                commit_plan,
                expected_checkpoint,
                frames,
                RETAINED_STREAM_CHECKPOINT_BATCH_BYTES as usize,
            )?;
            #[cfg(test)]
            super::blob_progress_test::record_stream_checkpoint(
                receiver_identity,
                &blob,
                source,
                commit_plan,
                expected_checkpoint.next_carrier_index,
                next.next_carrier_index,
            );
            #[cfg(test)]
            if checkpoint_fault_cache
                .fire_test_blob_contact_fault(TestBlobContactFault::StreamAfterCheckpoint)
            {
                return Err(protocol("injected failure after durable checkpoint"));
            }
            greatest_checkpoint_latency_ms = greatest_checkpoint_latency_ms
                .max(u64::try_from(commit_started.elapsed().as_millis()).unwrap_or(u64::MAX));
            writer_commits = writer_commits
                .checked_add(1)
                .ok_or_else(|| protocol("writer commit count overflow"))?;
            received_bytes = frames.iter().try_fold(received_bytes, |total, frame| {
                total
                    .checked_add(frame.bytes.len() as u64)
                    .ok_or_else(|| protocol("received byte count overflow"))
            })?;
            expected_checkpoint = next;
            let new_limit = retained_receive_limit(&layout, next.durable_encoded_offset);
            greatest_receive_limit = greatest_receive_limit.max(new_limit);
            Ok(crate::stream_transfer::StreamCheckpointAuthorityV1 {
                durable_plaintext_offset: next.durable_encoded_offset,
                durable_ciphertext_offset: next.durable_encoded_offset,
                next_segment_index: next.next_carrier_index,
                plaintext_commitment: [1; 32],
                ciphertext_commitment: [1; 32],
                checkpoint_generation: next.generation,
                absolute_receive_limit: new_limit,
            })
        },
        |_, _| {
            guard.check(store)?;
            let mut work = Vec::new();
            let disposition = recover_and_finalize_pending_blob(
                store,
                guard,
                verifier,
                source,
                &promote_blob,
                &promote_manifest,
                promote_plan,
                &mut work,
                BlobContactMode::StreamV1,
            )?
            .ok_or_else(|| protocol("complete stream did not reach promotion"))?;
            let code = match disposition {
                PendingBlobRecoveryDisposition::Apply(MutableApplyDisposition::Inserted) => {
                    StreamResultCode::Promoted
                }
                PendingBlobRecoveryDisposition::Apply(MutableApplyDisposition::Duplicate) => {
                    StreamResultCode::AlreadyPresent
                }
                PendingBlobRecoveryDisposition::Apply(
                    MutableApplyDisposition::DeferredCapacity,
                )
                | PendingBlobRecoveryDisposition::DeferredLease => {
                    StreamResultCode::DeferredCapacity
                }
            };
            let digest = result_digest(source, manifest_digest, code);
            Ok((code, digest, digest))
        },
    )
    .await?;
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes,
            retransmitted_bytes: 0,
            receive_limit_bytes: greatest_receive_limit,
            checkpoint_bytes: expected_checkpoint.durable_encoded_offset,
            checkpoint_latency_ms: greatest_checkpoint_latency_ms,
            writer_commits,
            // A nonzero reopen is recovery, but it is not cross-transport
            // failover while IrohQuicV1 is the only production adapter.
            failover_recoveries: 0,
        },
    })
}

/// Verifies every received separator-free extent against the exact plan and
/// commits one Store batch. No network await occurs in this function.
pub(super) fn commit_received_batch(
    store: &Store,
    policy: &ControlPolicySnapshot,
    source: BlobTransferId,
    plan: &VerifiedBlobTransferPlan,
    expected: BlobStreamCheckpoint,
    frames: &[StreamDataV1],
    advertised_batch_bytes: usize,
) -> Result<BlobStreamCheckpoint, NodeError> {
    let mut next_carrier = expected.next_carrier_index;
    let mut next_offset = expected.durable_encoded_offset;
    let mut extents = Vec::with_capacity(frames.len());
    for frame in frames {
        if frame.offset != next_offset {
            return Err(protocol("received batch is not contiguous"));
        }
        let extent = plan
            .verify_stream_bytes(
                next_carrier,
                next_offset,
                &frame.bytes,
                MAX_STREAM_EXTENT_BYTES,
            )
            .map_err(protocol)?;
        next_carrier = extent.next_carrier_index();
        next_offset = next_offset
            .checked_add(extent.encoded_len())
            .ok_or_else(|| protocol("received batch offset overflow"))?;
        extents.push(extent);
    }
    let batch = VerifiedBlobStreamCheckpointBatch::from_extents(extents, advertised_batch_bytes)?;
    match store.commit_blob_stream_batch_with_policy(policy, source, plan, expected, batch)? {
        BlobStreamCommitOutcome::Advanced(checkpoint)
        | BlobStreamCommitOutcome::Duplicate(checkpoint)
        | BlobStreamCommitOutcome::Complete(checkpoint) => Ok(checkpoint),
    }
}

/// Drives one receiver attempt. `persist_batch` and `promote` are synchronous
/// boundaries by design, ensuring no Store/depot guard survives a network
/// await. The batch callback must return the exact cumulative durable
/// checkpoint and replenished absolute receive limit.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_receiver_attempt<P, M>(
    attempt: Arc<dyn StreamReceiveAttempt>,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    expected_nonce: [u8; 32],
    expected_transfer: [u8; 32],
    expected_open_digest: [u8; 32],
    expected_total_len: u64,
    durable_offset: u64,
    checkpoint_generation: u64,
    initial_authority: Option<crate::stream_transfer::StreamCheckpointAuthorityV1>,
    expected_custody_digest: Option<[u8; 32]>,
    absolute_receive_limit: u64,
    max_extent_bytes: u32,
    checkpoint_batch_bytes: u32,
    mut persist_batch: P,
    mut promote: M,
) -> Result<StreamResultCode, NodeError>
where
    P: FnMut(
        &StreamOpenV1,
        &[StreamDataV1],
    ) -> Result<crate::stream_transfer::StreamCheckpointAuthorityV1, NodeError>,
    M: FnMut(
        &StreamOpenV1,
        &crate::stream_transfer::StreamFinishV1,
    ) -> Result<(StreamResultCode, [u8; 32], [u8; 32]), NodeError>,
{
    if max_extent_bytes == 0
        || max_extent_bytes as usize > MAX_STREAM_EXTENT_BYTES
        || checkpoint_batch_bytes == 0
        || checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES
    {
        return Err(protocol("receiver configuration is out of bounds"));
    }
    let protected = attempt
        .receive_data()
        .await
        .map_err(transport)?
        .ok_or_else(|| protocol("data stream closed before open"))?;
    let StreamFrame::Open(mut open) = open_control(
        mission,
        profile_digest,
        direction,
        expected_nonce,
        protected,
    )?
    else {
        return Err(protocol("first data record is not open"));
    };
    if open.attempt_nonce != expected_nonce
        || open.transfer_id != expected_transfer
        || open.session_transcript != mission.session_id()
        || open.direction != expected_direction(direction)
        || open.checkpoint_generation != checkpoint_generation
    {
        return Err(protocol("open authority differs from expected transfer"));
    }
    open.total_len = expected_total_len;
    require_stream_open_custody_digest(
        expected_open_digest,
        expected_custody_digest,
        open.open_digest,
    )?;
    let mut state = if let Some(authority) = initial_authority {
        if authority.durable_ciphertext_offset != durable_offset
            || authority.checkpoint_generation != checkpoint_generation
            || authority.absolute_receive_limit != absolute_receive_limit
        {
            return Err(protocol("initial receiver authority differs"));
        }
        StreamReceiverState::new_from_authority(
            &open,
            authority,
            max_extent_bytes,
            checkpoint_batch_bytes,
        )
        .map_err(protocol)?
    } else {
        StreamReceiverState::new(
            &open,
            durable_offset,
            checkpoint_generation,
            absolute_receive_limit,
            max_extent_bytes,
        )
        .map_err(protocol)?
    };
    let accept = if initial_authority.is_some() {
        state.accept_authority().map_err(protocol)?
    } else {
        state.accept(checkpoint_batch_bytes).map_err(protocol)?
    };
    let StreamAction::Send(accept) = accept else {
        return Err(protocol("receiver produced an invalid accept transition"));
    };
    let protected = protect(mission, profile_digest, direction, expected_nonce, accept)?;
    attempt.send_control(&protected).await.map_err(transport)?;

    let mut pending = Vec::new();
    let mut pending_bytes = 0_u64;
    let mut terminal_code = None;
    loop {
        let protected = attempt
            .receive_data()
            .await
            .map_err(transport)?
            .ok_or_else(|| protocol("data stream closed before settlement"))?;
        match open_control(
            mission,
            profile_digest,
            direction,
            expected_nonce,
            protected,
        )? {
            StreamFrame::Data(data) => {
                let StreamAction::Persist { through } = state.data(&data).map_err(protocol)? else {
                    return Err(protocol("receiver produced an invalid data transition"));
                };
                let data_bytes = data.bytes.len() as u64;
                let combined = pending_bytes
                    .checked_add(data_bytes)
                    .ok_or_else(|| protocol("receiver batch byte overflow"))?;
                if !pending.is_empty() && combined > u64::from(checkpoint_batch_bytes) {
                    let prior_through = data.offset;
                    let authority = blocking_store_step(|| persist_batch(&open, &pending))?;
                    if authority.durable_ciphertext_offset > prior_through {
                        return Err(protocol("Store checkpoint differs from received batch"));
                    }
                    let StreamAction::Send(checkpoint) =
                        state.persisted_authority(authority).map_err(protocol)?
                    else {
                        return Err(protocol(
                            "receiver produced an invalid checkpoint transition",
                        ));
                    };
                    pending.clear();
                    pending_bytes = 0;
                    let protected = protect(
                        mission,
                        profile_digest,
                        direction,
                        expected_nonce,
                        checkpoint,
                    )?;
                    attempt.send_control(&protected).await.map_err(transport)?;
                }
                pending_bytes = pending_bytes
                    .checked_add(data_bytes)
                    .ok_or_else(|| protocol("receiver batch byte overflow"))?;
                pending.push(data);
                if pending_bytes >= u64::from(checkpoint_batch_bytes) || through == open.total_len {
                    let authority = blocking_store_step(|| persist_batch(&open, &pending))?;
                    if authority.durable_ciphertext_offset > through
                        || (through == open.total_len
                            && authority.durable_ciphertext_offset != through)
                    {
                        return Err(protocol("Store checkpoint differs from received batch"));
                    }
                    let StreamAction::Send(checkpoint) =
                        state.persisted_authority(authority).map_err(protocol)?
                    else {
                        return Err(protocol(
                            "receiver produced an invalid checkpoint transition",
                        ));
                    };
                    pending.clear();
                    pending_bytes = 0;
                    let protected = protect(
                        mission,
                        profile_digest,
                        direction,
                        expected_nonce,
                        checkpoint,
                    )?;
                    attempt.send_control(&protected).await.map_err(transport)?;
                }
            }
            StreamFrame::Finish(finish) => {
                if !pending.is_empty() {
                    return Err(protocol("finish crossed an uncommitted receiver batch"));
                }
                let finish_authority = finish.clone();
                let (result, code) = match state.finish(finish).map_err(protocol)? {
                    StreamAction::Promote => {
                        let (code, blob_id, digest) =
                            blocking_store_step(|| promote(&open, &finish_authority))?;
                        let StreamAction::Send(result) = state
                            .promoted_blob(code, blob_id, digest)
                            .map_err(protocol)?
                        else {
                            return Err(protocol("receiver produced an invalid result transition"));
                        };
                        (result, code)
                    }
                    StreamAction::Send(result) => {
                        let code = terminal_code
                            .ok_or_else(|| protocol("replayed finish lost terminal authority"))?;
                        (result, code)
                    }
                    _ => return Err(protocol("receiver produced an invalid finish transition")),
                };
                let protected =
                    protect(mission, profile_digest, direction, expected_nonce, result)?;
                attempt.send_control(&protected).await.map_err(transport)?;
                terminal_code = Some(code);
            }
            StreamFrame::ResultAck(ack) => {
                let code = terminal_code
                    .ok_or_else(|| protocol("result acknowledgement preceded result"))?;
                let StreamAction::Terminal(code) = state.result_ack(ack, code).map_err(protocol)?
                else {
                    return Err(protocol(
                        "receiver produced an invalid acknowledgement transition",
                    ));
                };
                if attempt.receive_data().await.map_err(transport)?.is_some() {
                    return Err(protocol("data record followed terminal settlement"));
                }
                attempt.finish_control().await.map_err(transport)?;
                return Ok(code);
            }
            _ => return Err(protocol("unexpected data record")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobStreamProgress {
    total_bytes: u64,
    received_bytes: u64,
    durable_bytes: u64,
    started_ms: u64,
    last_sample_ms: u64,
    last_sample_bytes: u64,
    rolling_bytes_per_second: u64,
    phase: BlobStreamTransferPhase,
    terminal: Option<BlobStreamTerminalCategory>,
}

impl BlobStreamProgress {
    pub(super) fn new(total_bytes: u64, now_ms: u64) -> Result<Self, &'static str> {
        if total_bytes == 0 {
            return Err("Blob stream total is zero");
        }
        Ok(Self {
            total_bytes,
            received_bytes: 0,
            durable_bytes: 0,
            started_ms: now_ms,
            last_sample_ms: now_ms,
            last_sample_bytes: 0,
            rolling_bytes_per_second: 0,
            phase: BlobStreamTransferPhase::Negotiating,
            terminal: None,
        })
    }

    pub(super) fn accepted(&mut self) {
        self.phase = BlobStreamTransferPhase::Receiving;
    }

    pub(super) fn received(&mut self, through: u64) -> Result<(), &'static str> {
        if through < self.received_bytes || through > self.total_bytes {
            return Err("Blob stream received position regressed or overflowed");
        }
        self.received_bytes = through;
        Ok(())
    }

    pub(super) fn durable(&mut self, through: u64, now_ms: u64) -> Result<(), &'static str> {
        if through < self.durable_bytes
            || through > self.received_bytes
            || now_ms < self.last_sample_ms
        {
            return Err("Blob stream durable position or clock regressed");
        }
        let elapsed = now_ms.saturating_sub(self.last_sample_ms);
        let advanced = through.saturating_sub(self.last_sample_bytes);
        if let Some(bytes_per_second) = advanced.saturating_mul(1_000).checked_div(elapsed) {
            self.rolling_bytes_per_second = bytes_per_second;
            self.last_sample_ms = now_ms;
            self.last_sample_bytes = through;
        }
        self.durable_bytes = through;
        if through == self.total_bytes {
            self.phase = BlobStreamTransferPhase::Finalizing;
        }
        Ok(())
    }

    pub(super) fn settling(&mut self) -> Result<(), &'static str> {
        if self.durable_bytes != self.total_bytes {
            return Err("Blob stream settled before durable completion");
        }
        self.phase = BlobStreamTransferPhase::Settling;
        Ok(())
    }

    pub(super) fn complete(&mut self) -> Result<(), &'static str> {
        if self.phase != BlobStreamTransferPhase::Settling {
            return Err("Blob stream completed before settlement");
        }
        self.phase = BlobStreamTransferPhase::Complete;
        Ok(())
    }

    pub(super) fn terminal(&mut self, category: BlobStreamTerminalCategory) {
        self.phase = BlobStreamTransferPhase::Terminal;
        self.terminal = Some(category);
    }

    pub(super) const fn status(&self) -> BlobStreamTransferStatus {
        BlobStreamTransferStatus {
            phase: self.phase,
            total_bytes: self.total_bytes,
            durable_bytes: self.durable_bytes,
            throughput_bytes_per_second: self.rolling_bytes_per_second,
            terminal: self.terminal,
        }
    }

    pub(super) const fn recovery_offset(&self) -> u64 {
        self.durable_bytes
    }

    #[allow(dead_code)]
    pub(super) const fn elapsed_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.started_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableDatabase as _;

    #[test]
    fn live_blob_stream_v9_data_record_is_direct_and_explicitly_typed() {
        let frame = StreamFrame::Data(StreamDataV1 {
            transfer_id: [0x11; 32],
            attempt_nonce: [0x22; 32],
            sequence: 3,
            offset: 1_048_576,
            bytes: vec![0x33; 64].into(),
        });
        let encoded = encode_direct_data_record(frame.clone()).expect("encode direct data");
        assert_eq!(encoded.first(), Some(&ATTEMPT_DIRECT_DATA_RECORD));
        assert_eq!(
            decode_direct_data_record(encoded).expect("decode direct data"),
            frame
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_pack_finite_publications_are_withheld_and_rejected_before_reservation() {
        use std::{fs, os::unix::fs::PermissionsExt as _};

        use crate::{
            MutableSourceInterests, NodeApplication, NodeConfig, SourceInterestSelector,
            application::{
                BlobPublishOptions, BlobPublishRequest, BlobPublishStreamRequest, Priority,
            },
            mission::{
                MissionPeerBinding, MissionSessionInitiator, MissionSessionResponder,
                UnprotectedReferenceMission,
            },
            start_node,
        };
        use aster_mesh::{ProvisioningAccess, ReferenceProvisioner, Scope, Topic};
        use redb::ReadableTableMetadata as _;

        static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
        struct TestRoot(std::path::PathBuf);
        impl Drop for TestRoot {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = TestRoot(std::env::temp_dir().join(format!(
            "aster-finite-pack-boundary-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        )));
        let source_root = root.0.join("source");
        let receiver_root = root.0.join("receiver");
        for path in [&source_root, &receiver_root] {
            fs::create_dir_all(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let topic = Topic::new("finite-pack-boundary").unwrap();
        let scope = Scope::new("test/finite-pack-boundary").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xd1; 32]).unwrap();
        let source_credentials = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, std::slice::from_ref(&access))
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let receiver_credentials = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(2, &[access])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let authority = source_credentials.mission_authority_id();
        let node = start_node(NodeConfig {
            state: source_root.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission: source_credentials.clone(),
            peers: Vec::new(),
            mutable_interests: Default::default(),
            sync_interval: Duration::from_secs(60),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        for (operation, options) in [
            (
                b"finite-pack".as_slice(),
                BlobPublishOptions::finite_ttl_ms(60_000).unwrap(),
            ),
            (b"durable-pack".as_slice(), BlobPublishOptions::durable()),
        ] {
            let mut stream = node
                .selected_blobs()
                .open_publish_stream(BlobPublishStreamRequest {
                    publication: BlobPublishRequest {
                        operation_key: operation.to_vec(),
                        topic: topic.clone(),
                        scope: scope.clone(),
                        priority: Priority::Routine,
                        media_type: None,
                        schema_id: Vec::new(),
                    },
                    options,
                    total_len: 8,
                })
                .await
                .unwrap();
            stream
                .write(0, zeroize::Zeroizing::new(vec![0x71; 8]))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        }
        node.shutdown().await.unwrap();
        let source_store =
            Store::open_for_mission(source_root.join(super::super::STORE_FILE), authority).unwrap();
        let receiver_path = receiver_root.join(super::super::STORE_FILE);
        let receiver_store = Store::open_for_mission(&receiver_path, authority).unwrap();
        let source_verifier =
            ReferenceEnvelopeSealer::open(source_credentials.fresh_bundle().unwrap()).unwrap();
        let receiver_verifier =
            ReferenceEnvelopeSealer::open(receiver_credentials.fresh_bundle().unwrap()).unwrap();
        let source_carrier = aster_iroh::SecretKey::generate().public();
        let receiver_carrier = aster_iroh::SecretKey::generate().public();
        let (initiator, first) = MissionSessionInitiator::start(
            source_credentials.fresh_bundle().unwrap(),
            MissionPeerBinding::new(receiver_carrier, receiver_credentials.identity()),
            receiver_carrier,
        )
        .unwrap();
        let responder = MissionSessionResponder::open(
            receiver_credentials.fresh_bundle().unwrap(),
            MissionPeerBinding::new(source_carrier, source_credentials.identity()),
            source_carrier,
        )
        .unwrap();
        let (responder, second) = responder.receive_client(first.as_bytes()).unwrap();
        let (initiator, third) = initiator.receive_server(second.as_bytes()).unwrap();
        let (receiver_session, fourth) = responder.receive_client_auth(third.as_bytes()).unwrap();
        let source_session = initiator.receive_finished(fourth.as_bytes()).unwrap();
        let source_guard = EventLaneGuard::capture(
            Arc::new(tokio::sync::RwLock::new(())).read_owned().await,
            &source_store,
            source_credentials.identity(),
            receiver_credentials.identity(),
            0,
        )
        .unwrap();
        let receiver_guard = EventLaneGuard::capture(
            Arc::new(tokio::sync::RwLock::new(())).read_owned().await,
            &receiver_store,
            receiver_credentials.identity(),
            source_credentials.identity(),
            0,
        )
        .unwrap();
        let interest = super::super::protected_blob_interest(
            &receiver_store,
            &receiver_verifier,
            &MutableSourceInterests::default()
                .with_blob(vec![SourceInterestSelector::new(topic, scope, false)]),
            true,
        )
        .unwrap();
        let publications = source_store
            .blob_stream_publications_with_policy(source_guard.policy())
            .unwrap();
        let finite = publications
            .iter()
            .find(|publication| publication.open().ttl_ms().is_some())
            .unwrap();
        let durable = publications
            .iter()
            .find(|publication| publication.open().ttl_ms().is_none())
            .unwrap();
        // With two candidates this cursor ensures the finite one is visited first.
        source_store
            .compare_and_advance_mutable_transfer_cursor(
                receiver_credentials.identity(),
                MutableTransferCursorClass::BlobStream,
                MutableTransferCursorMode::OfferToPeer,
                None,
                *durable.stream_id().as_bytes(),
            )
            .unwrap();
        let selected = select_completed_pack_source(
            &source_store,
            &source_session,
            &source_verifier,
            &source_guard,
            &interest,
        )
        .unwrap()
        .expect("durable candidate remains available after a finite candidate");
        assert_eq!(selected.publication.stream_id(), durable.stream_id());
        let before = receiver_store.blob_stats().unwrap();
        let error = match admit_completed_pack_source(
            &receiver_store,
            &receiver_session,
            &receiver_verifier,
            &receiver_guard,
            &interest,
            finite.authenticated_open(),
            finite.authenticated_commitment(),
        ) {
            Ok(_) => panic!("finite completed pack must not acquire receiver custody"),
            Err(error) => error,
        };
        assert!(
            matches!(error, NodeError::Protocol(ref message)
                if message == "Blob stream: finite completed-pack admission requires receiver-local custody authority"),
            "unexpected finite admission rejection: {error:?}",
        );
        assert_eq!(receiver_store.blob_stats().unwrap(), before);
        drop(receiver_guard);
        drop(receiver_store);
        let database = redb::Database::open(receiver_path).unwrap();
        let read = database.begin_read().unwrap();
        for name in [
            "aster.blob-stream-reservations.v1",
            "aster.blob-stream-operations.v1",
            "aster.blob-stream-publications.v1",
        ] {
            let table = read
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new(name))
                .unwrap();
            assert_eq!(
                table.len().unwrap(),
                0,
                "rejected finite admission mutated {name}"
            );
        }
    }

    #[test]
    fn completed_pack_flow_uses_the_full_bounded_data_extent() {
        let record = EncryptedBlobStreamSegment::packed_wire_len(
            aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64,
            1,
        )
        .expect("record length");
        let (maximum, _, _) = pack_attempt_flow(record * 2).expect("pack flow");
        assert_eq!(maximum as usize, MAX_STREAM_EXTENT_BYTES);
        assert!(u64::from(maximum) < record);
    }

    #[test]
    fn live_blob_stream_v9_open_requires_exact_finite_custody_digest() {
        let source = [0x60; 32];
        let exact = [0x61; 32];
        let bound = bind_stream_open_custody_digest(source, Some(exact));
        let wrong = bind_stream_open_custody_digest(source, Some([0x62; 32]));
        assert!(require_stream_open_custody_digest(source, None, source).is_ok());
        assert!(require_stream_open_custody_digest(source, Some(exact), bound).is_ok());
        assert!(require_stream_open_custody_digest(source, Some(exact), source).is_err());
        assert!(require_stream_open_custody_digest(source, None, bound).is_err());
        assert!(require_stream_open_custody_digest(source, Some(exact), wrong).is_err());
        assert!(require_stream_open_custody_digest([0x63; 32], Some(exact), bound).is_err());
    }

    #[test]
    fn live_blob_stream_v9_attempt_nonce_binds_session_direction_transfer_and_checkpoint() {
        let base = attempt_nonce([1; 32], EventDirection::ToSessionResponder, [2; 32], 7);
        assert_ne!(base, [0; 32]);
        assert_eq!(
            base,
            attempt_nonce([1; 32], EventDirection::ToSessionResponder, [2; 32], 7,)
        );
        assert_ne!(
            base,
            attempt_nonce([1; 32], EventDirection::ToSessionInitiator, [2; 32], 7,)
        );
        assert_ne!(
            base,
            attempt_nonce([1; 32], EventDirection::ToSessionResponder, [3; 32], 7,)
        );
        assert_ne!(
            base,
            attempt_nonce([4; 32], EventDirection::ToSessionResponder, [2; 32], 8,)
        );
    }

    #[test]
    fn live_blob_stream_v9_status_uses_only_durable_checkpoint_authority() {
        let mut progress = BlobStreamProgress::new(16 * 1_048_576, 10).expect("progress");
        progress.accepted();
        progress.received(8 * 1_048_576).expect("received tail");
        assert_eq!(progress.status().durable_bytes, 0);
        assert_eq!(progress.recovery_offset(), 0);

        progress
            .durable(4 * 1_048_576, 1_010)
            .expect("first durable batch");
        assert_eq!(progress.recovery_offset(), 4 * 1_048_576);
        assert_eq!(progress.status().throughput_bytes_per_second, 4 * 1_048_576);

        // An unchanged credit/checkpoint heartbeat cannot manufacture durable
        // progress or become failover authority.
        progress
            .durable(4 * 1_048_576, 2_010)
            .expect("unchanged heartbeat");
        assert_eq!(progress.recovery_offset(), 4 * 1_048_576);
        assert_eq!(progress.status().throughput_bytes_per_second, 0);

        progress.received(16 * 1_048_576).expect("received all");
        progress
            .durable(16 * 1_048_576, 3_010)
            .expect("final durable batch");
        assert_eq!(progress.status().phase, BlobStreamTransferPhase::Finalizing);
        progress.settling().expect("settlement");
        progress.complete().expect("complete");
        assert_eq!(progress.status().phase, BlobStreamTransferPhase::Complete);
    }

    #[test]
    fn live_blob_stream_v9_status_rejects_regression_and_sanitizes_terminal() {
        let mut progress = BlobStreamProgress::new(1024, 0).expect("progress");
        progress.accepted();
        progress.received(512).expect("received");
        progress.durable(512, 10).expect("durable");
        assert!(progress.received(511).is_err());
        assert!(progress.durable(513, 11).is_err());
        assert!(progress.complete().is_err());
        progress.terminal(BlobStreamTerminalCategory::Transport);
        assert_eq!(
            progress.status().terminal,
            Some(BlobStreamTerminalCategory::Transport)
        );
    }
}
