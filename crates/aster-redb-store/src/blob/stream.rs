//! Profile-5 whole-carrier stream layout, batching, and durable checkpoints.

use super::pack::{
    BlobPackCheckpoint, BlobPackCompletion, BlobPackReader, BlobPackWriter, PACK_HEADER_LEN,
    PinnedBlobPackRoot, recover_blob_pack,
};
use super::*;
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BlobId, BlobPublicationStreamId, BlobStore as CoreBlobStore,
    BlobStreamFinalCommitment, BlobStreamLayout, BlobStreamOpen, CustodySample, Dot,
    MAX_CAUSAL_CONTEXT_ENTRIES, NodeId, OwnedBlobStreamExtent, VerifiedBlobStreamExtent,
    VerifiedBlobStreamFinalCommitment, VerifiedBlobStreamOpen, VerifiedBlobTransferObject,
    VersionVector,
};
use std::time::Duration;

pub const DEFAULT_BLOB_STREAM_CHECKPOINT_BATCH_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BLOB_STREAM_CHECKPOINT_BATCH_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_BLOB_STREAM_CHECKPOINT_INTERVAL: Duration = Duration::from_millis(250);

const CHECKPOINT_VERSION: u8 = 1;
const CHECKPOINT_BYTES: usize = 1 + 8 + 8 + 8;
const PROVISIONAL_MAGIC: &[u8; 8] = b"ASTRPR01";
const PUBLICATION_MAGIC: &[u8; 8] = b"ASTRPB01";
const PROVISIONAL_VERSION: u8 = 1;
const PACK_RECORD_OVERHEAD: u64 = 186;
const PACK_FIXED_RESERVATION_BYTES: u64 = 82 + 2 * BlobPackCheckpoint::ENCODED_LEN as u64 + 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamSource {
    LocalApplication,
    AuthenticatedPeer(NodeId),
}

#[derive(Clone, Copy, Debug)]
pub struct BlobStreamReservationRequest<'a> {
    pub operation: &'a BlobOperationKey,
    pub source: BlobStreamSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamReservation {
    stream_id: BlobPublicationStreamId,
    open_digest: [u8; 32],
    operation: Vec<u8>,
    source: BlobStreamSource,
    reserved_bytes: u64,
    open: BlobStreamOpen,
    authenticated_open: Vec<u8>,
}

impl BlobStreamReservation {
    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStreamDurableProgress {
    generation: u64,
    next_segment_index: u64,
    durable_plaintext_offset: u64,
    durable_pack_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamPromotion {
    stream_id: BlobPublicationStreamId,
    blob_id: BlobId,
    acceptance_marker: u64,
    duplicate: bool,
}

/// Durable application-visible projection of one completed Blob stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamPublication {
    open: BlobStreamOpen,
    commitment: BlobStreamFinalCommitment,
    authenticated_open: Vec<u8>,
    authenticated_commitment: Vec<u8>,
    blob_id: BlobId,
    acceptance_marker: u64,
    pack_len: u64,
    descriptor_digest: [u8; 32],
}

impl BlobStreamPublication {
    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.open.stream_id()
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }

    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }

    pub fn authenticated_open(&self) -> &[u8] {
        &self.authenticated_open
    }

    pub fn authenticated_commitment(&self) -> &[u8] {
        &self.authenticated_commitment
    }

    pub const fn acceptance_marker(&self) -> u64 {
        self.acceptance_marker
    }

    pub const fn pack_len(&self) -> u64 {
        self.pack_len
    }

    /// Exact length of the length-prefixed encrypted segment records. The
    /// receiver recreates the canonical fixed pack header locally.
    pub const fn wire_len(&self) -> u64 {
        self.pack_len - PACK_HEADER_LEN
    }
}

#[derive(Clone, Debug)]
pub struct BlobStreamCryptoResume {
    progress: BlobStreamDurableProgress,
    plaintext_checkpoint: aster_mesh::BlobStreamAccumulatorCheckpoint,
    ciphertext_checkpoint: aster_mesh::BlobStreamAccumulatorCheckpoint,
}

impl BlobStreamCryptoResume {
    pub const fn progress(&self) -> BlobStreamDurableProgress {
        self.progress
    }

    pub fn ciphertext_checkpoint(&self) -> aster_mesh::BlobStreamAccumulatorCheckpoint {
        self.ciphertext_checkpoint.clone()
    }

    pub fn plaintext_checkpoint(&self) -> aster_mesh::BlobStreamAccumulatorCheckpoint {
        self.plaintext_checkpoint.clone()
    }
}

pub struct BlobStreamPackSession {
    writer: BlobPackWriter,
    reservation: BlobStreamReservation,
    progress: BlobStreamDurableProgress,
    // Drop the writer before releasing exclusion, including on cancellation.
    writer_lease: super::lease::BlobStreamWriterLease,
}

/// Store-owned sequential reader over one authenticated completed pack.
pub struct BlobStreamReadSession {
    reader: BlobPackReader,
    next_index: u64,
}

impl BlobStreamReadSession {
    pub fn resume_at(
        &mut self,
        next_segment_index: u64,
        wire_offset: u64,
    ) -> Result<(), StoreError> {
        self.reader.resume_at(next_segment_index, wire_offset)?;
        self.next_index = next_segment_index;
        Ok(())
    }

    pub fn next_encrypted_segment(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        let mut encoded = Vec::new();
        if !self.reader.read_segment(self.next_index, &mut encoded)? {
            return Ok(None);
        }
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        Ok(Some(encoded))
    }
}

impl BlobStreamPackSession {
    pub const fn progress(&self) -> BlobStreamDurableProgress {
        self.progress
    }

    pub fn crypto_resume(&self) -> BlobStreamCryptoResume {
        BlobStreamCryptoResume {
            progress: self.progress,
            plaintext_checkpoint: self.writer.plaintext_checkpoint(),
            ciphertext_checkpoint: self.writer.ciphertext_checkpoint(),
        }
    }

    pub fn append_segment(
        &mut self,
        plaintext: &[u8],
        segment: &aster_mesh::EncryptedBlobStreamSegment,
    ) -> Result<(), StoreError> {
        self.writer.append_segment(plaintext, segment)
    }

    pub fn append_encoded_segment(
        &mut self,
        plaintext: &[u8],
        segment: &aster_mesh::EncryptedBlobStreamSegment,
        encoded: &[u8],
    ) -> Result<(), StoreError> {
        self.writer
            .append_encoded_segment(plaintext, segment, encoded)
    }

    pub fn append_authenticated_encoded_segment(
        &mut self,
        plaintext: &[u8],
        segment: &aster_mesh::EncryptedBlobStreamSegment,
        encoded: &[u8],
        authenticated: aster_mesh::AuthenticatedBlobStreamSegmentCheckpoint,
    ) -> Result<(), StoreError> {
        if authenticated.segment_index() != segment.index()
            || authenticated.ciphertext_len() != segment.ciphertext().len()
        {
            return Err(StoreError::Blob(BlobStoreError::DepotIntegrity(
                "authenticated Blob segment checkpoint differs",
            )));
        }
        self.writer.append_authenticated_encoded_segment(
            plaintext,
            segment,
            encoded,
            authenticated.into_checkpoint(),
        )
    }

    /// Opportunistically writes back received bytes without acknowledging
    /// them. At most one owned worker exists, and checkpoint/finish/drop join it.
    #[doc(hidden)]
    pub fn advance_background_writeback(&mut self) -> Result<(), StoreError> {
        self.writer.advance_background_writeback()
    }

    pub fn checkpoint(
        &mut self,
        store: &Store,
        policy: &ControlPolicySnapshot,
    ) -> Result<BlobStreamDurableProgress, StoreError> {
        self.writer_lease
            .require_registry(&store.blob_stream_writer_leases)?;
        let checkpoint = self.writer.checkpoint()?;
        self.progress = store.commit_blob_pack_checkpoint_with_policy(
            policy,
            &self.reservation,
            self.progress,
            checkpoint,
        )?;
        Ok(self.progress)
    }

    pub fn final_roots(&self) -> Result<([u8; 32], [u8; 32]), StoreError> {
        self.writer.final_roots()
    }

    pub fn finish_and_promote(
        self,
        store: &Store,
        policy: &ControlPolicySnapshot,
        commitment: &VerifiedBlobStreamFinalCommitment,
        final_sample: Option<CustodySample>,
    ) -> Result<BlobStreamPromotion, StoreError> {
        self.writer_lease
            .require_registry(&store.blob_stream_writer_leases)?;
        let Self {
            writer,
            reservation,
            progress: _,
            writer_lease,
        } = self;
        let completion = writer.finish(commitment)?;
        let promoted = store.promote_blob_stream_with_policy(
            policy,
            &reservation,
            commitment,
            completion,
            final_sample,
        );
        // The completion descriptor alone is not durable publication authority.
        // Exclude retries until promotion has committed or failed.
        drop(writer_lease);
        promoted
    }
}

impl BlobStreamPromotion {
    pub const fn stream_id(self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn blob_id(self) -> BlobId {
        self.blob_id
    }

    pub const fn acceptance_marker(self) -> u64 {
        self.acceptance_marker
    }

    pub const fn duplicate(self) -> bool {
        self.duplicate
    }
}

impl BlobStreamDurableProgress {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn next_segment_index(self) -> u64 {
        self.next_segment_index
    }

    pub const fn durable_plaintext_offset(self) -> u64 {
        self.durable_plaintext_offset
    }

    pub const fn durable_pack_len(self) -> u64 {
        self.durable_pack_len
    }

    /// Durable bytes of canonical encrypted segment records, excluding the
    /// local-only fixed pack header.
    pub const fn durable_wire_offset(self) -> u64 {
        if self.durable_pack_len == 0 {
            0
        } else {
            self.durable_pack_len - PACK_HEADER_LEN
        }
    }
}

struct ProvisionalBlobStream {
    reservation: BlobStreamReservation,
    open: BlobStreamOpen,
    checkpoint: Option<BlobPackCheckpoint>,
}

type CompletedBlobStream = BlobStreamPublication;

pub(super) fn audit_blob_stream_authority_rows(
    reservations: &impl ReadableTable<&'static [u8], &'static [u8]>,
    operations: &impl ReadableTable<&'static [u8], &'static [u8]>,
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    mission_authority: Option<NodeId>,
) -> Result<(), StoreError> {
    let authority =
        if reservations.len()? == 0 && operations.len()? == 0 && publications.len()? == 0 {
            mission_authority.unwrap_or([0; 32])
        } else {
            mission_authority.ok_or(StoreError::MissionNotBound)?
        };
    for row in reservations.iter()? {
        let (key, value) = row?;
        let provisional = ProvisionalBlobStream::decode(value.value())?;
        if key.value() != provisional.open.stream_id().as_bytes()
            || provisional.open.mission_id() != &authority
            || operations
                .get(provisional.open.operation_key())?
                .is_none_or(|stream| stream.value() != key.value())
        {
            return Err(provisional_schema_error());
        }
    }
    for row in publications.iter()? {
        let (key, value) = row?;
        let completed = CompletedBlobStream::decode(value.value())?;
        if key.value() != completed.open.stream_id().as_bytes()
            || completed.open.mission_id() != &authority
            || operations
                .get(completed.open.operation_key())?
                .is_none_or(|stream| stream.value() != key.value())
        {
            return Err(provisional_schema_error());
        }
    }
    let authority_rows = reservations
        .len()?
        .checked_add(publications.len()?)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if operations.len()? != authority_rows {
        return Err(provisional_schema_error());
    }
    for row in operations.iter()? {
        let (operation, stream) = row?;
        if operation.value().is_empty()
            || operation.value().len() > MAX_BLOB_OPERATION_KEY_BYTES
            || stream.value().len() != 32
            || (reservations.get(stream.value())?.is_none()
                && publications.get(stream.value())?.is_none())
        {
            return Err(provisional_schema_error());
        }
    }
    Ok(())
}

pub(super) fn completed_blob_stream_usage(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<(u64, u64, u64), StoreError> {
    let mut rows = 0_u64;
    let mut bytes = 0_u64;
    let mut last_marker = 0_u64;
    for row in publications.iter()? {
        let (_, value) = row?;
        let completed = CompletedBlobStream::decode(value.value())?;
        rows = rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        bytes = bytes
            .checked_add(completed.pack_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        last_marker = last_marker.max(completed.acceptance_marker);
    }
    Ok((rows, bytes, last_marker))
}

pub(super) fn audit_completed_blob_stream_causal_rows(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    accepted_dots: &impl ReadableTable<&'static [u8], &'static [u8]>,
    publisher_high: &impl ReadableTable<&'static [u8], u64>,
    frontier: &impl ReadableTable<&'static [u8], u64>,
    shared: &mut StateAuditSnapshot,
) -> Result<(u64, u64, u64), StoreError> {
    let usage = completed_blob_stream_usage(publications)?;
    for row in publications.iter()? {
        let (_, value) = row?;
        let completed = CompletedBlobStream::decode(value.value())?;
        let open = completed.open;
        let dot = Dot {
            publisher: open.publisher(),
            counter: open.publisher_counter(),
        };
        let semantic_id = open.digest();
        let dot_key = accepted_dot_key(dot).to_vec();
        if shared
            .expected_dots
            .insert(dot_key.clone(), semantic_id)
            .is_some()
        {
            return Err(provisional_schema_error());
        }
        if accepted_dots
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
            != Some(semantic_id)
        {
            return Err(provisional_schema_error());
        }
        if publisher_high
            .get(dot.publisher.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(provisional_schema_error());
        }
        shared
            .expected_publisher_high
            .entry(dot.publisher.to_vec())
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        let frontier_key = causal_frontier_key(open.topic(), open.scope(), dot.publisher)?;
        if frontier
            .get(frontier_key.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(provisional_schema_error());
        }
        shared
            .expected_frontier
            .entry(frontier_key)
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        shared
            .domain_publishers
            .entry(event_domain_prefix(open.topic(), open.scope())?)
            .or_default()
            .insert(dot.publisher);
    }
    Ok(usage)
}

impl ProvisionalBlobStream {
    fn progress(&self) -> BlobStreamDurableProgress {
        self.checkpoint
            .as_ref()
            .map_or(BlobStreamDurableProgress::default(), |checkpoint| {
                BlobStreamDurableProgress {
                    generation: checkpoint.generation(),
                    next_segment_index: checkpoint.next_index(),
                    durable_plaintext_offset: checkpoint.plaintext_offset(),
                    durable_pack_len: checkpoint.pack_len(),
                }
            })
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let open = self.open.encode();
        let authenticated_open = &self.reservation.authenticated_open;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(BlobPackCheckpoint::encode)
            .unwrap_or_default();
        let open_len = u16::try_from(open.len()).map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob stream open is oversized",
            ))
        })?;
        let checkpoint_len = u32::try_from(checkpoint.len()).map_err(|_| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob stream checkpoint is oversized",
            ))
        })?;
        let authenticated_open_len =
            u32::try_from(authenticated_open.len()).map_err(|_| provisional_schema_error())?;
        let mut encoded =
            Vec::with_capacity(100 + open.len() + authenticated_open.len() + checkpoint.len());
        encoded.extend_from_slice(PROVISIONAL_MAGIC);
        encoded.push(PROVISIONAL_VERSION);
        match self.reservation.source {
            BlobStreamSource::LocalApplication => {
                encoded.push(0);
                encoded.extend_from_slice(&[0; 32]);
            }
            BlobStreamSource::AuthenticatedPeer(peer) => {
                encoded.push(1);
                encoded.extend_from_slice(&peer);
            }
        }
        encoded.extend_from_slice(&self.reservation.reserved_bytes.to_be_bytes());
        encoded.extend_from_slice(&open_len.to_be_bytes());
        encoded.extend_from_slice(&open);
        encoded.extend_from_slice(&authenticated_open_len.to_be_bytes());
        encoded.extend_from_slice(authenticated_open);
        encoded.extend_from_slice(&checkpoint_len.to_be_bytes());
        encoded.extend_from_slice(&checkpoint);
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() < 56
            || &encoded[..8] != PROVISIONAL_MAGIC
            || encoded[8] != PROVISIONAL_VERSION
        {
            return Err(provisional_schema_error());
        }
        let source = match encoded[9] {
            0 if encoded[10..42] == [0; 32] => BlobStreamSource::LocalApplication,
            1 => BlobStreamSource::AuthenticatedPeer(read_array(encoded, 10)?),
            _ => return Err(provisional_schema_error()),
        };
        let reserved_bytes = read_u64(encoded, 42)?;
        let open_len = usize::from(read_u16(encoded, 50)?);
        let open_start = 52_usize;
        let open_end = open_start
            .checked_add(open_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let authenticated_open_len = usize::try_from(read_u32(encoded, open_end)?)
            .map_err(|_| provisional_schema_error())?;
        let authenticated_open_start = open_end + 4;
        let authenticated_open_end = authenticated_open_start
            .checked_add(authenticated_open_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let checkpoint_len = usize::try_from(read_u32(encoded, authenticated_open_end)?)
            .map_err(|_| provisional_schema_error())?;
        let checkpoint_start = authenticated_open_end + 4;
        let checkpoint_end = checkpoint_start
            .checked_add(checkpoint_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if checkpoint_end != encoded.len() || reserved_bytes == 0 || authenticated_open_len == 0 {
            return Err(provisional_schema_error());
        }
        let open = BlobStreamOpen::decode(
            encoded
                .get(open_start..open_end)
                .ok_or_else(provisional_schema_error)?,
        )
        .map_err(|_| provisional_schema_error())?;
        let checkpoint = if checkpoint_len == 0 {
            None
        } else {
            Some(BlobPackCheckpoint::decode(
                encoded
                    .get(checkpoint_start..checkpoint_end)
                    .ok_or_else(provisional_schema_error)?,
            )?)
        };
        let reservation = BlobStreamReservation {
            stream_id: open.stream_id(),
            open_digest: open.digest(),
            operation: open.operation_key().to_vec(),
            source,
            reserved_bytes,
            open: open.clone(),
            authenticated_open: encoded[authenticated_open_start..authenticated_open_end].to_vec(),
        };
        if checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint.stream_id() != open.stream_id()
                || checkpoint.open_digest() != &open.digest()
                || checkpoint.total_len() != open.total_len()
        }) {
            return Err(provisional_schema_error());
        }
        Ok(Self {
            reservation,
            open,
            checkpoint,
        })
    }
}

impl CompletedBlobStream {
    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() < 161
            || &encoded[..8] != PUBLICATION_MAGIC
            || encoded[8] != PROVISIONAL_VERSION
        {
            return Err(provisional_schema_error());
        }
        let stream_id = BlobPublicationStreamId::from_bytes(read_array(encoded, 9)?)
            .map_err(|_| provisional_schema_error())?;
        let open_digest: [u8; 32] = read_array(encoded, 41)?;
        let blob_id = BlobId::from_bytes(read_array(encoded, 73)?);
        let descriptor_digest = read_array(encoded, 105)?;
        let pack_len = read_u64(encoded, 137)?;
        let acceptance_marker = read_u64(encoded, 145)?;
        let open_len =
            usize::try_from(read_u32(encoded, 153)?).map_err(|_| provisional_schema_error())?;
        let open_start = 157_usize;
        let open_end = open_start
            .checked_add(open_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let commitment_len = usize::try_from(read_u32(encoded, open_end)?)
            .map_err(|_| provisional_schema_error())?;
        let commitment_start = open_end + 4;
        let commitment_end = commitment_start
            .checked_add(commitment_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let authenticated_open_len = usize::try_from(read_u32(encoded, commitment_end)?)
            .map_err(|_| provisional_schema_error())?;
        let authenticated_open_start = commitment_end + 4;
        let authenticated_open_end = authenticated_open_start
            .checked_add(authenticated_open_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let authenticated_commitment_len =
            usize::try_from(read_u32(encoded, authenticated_open_end)?)
                .map_err(|_| provisional_schema_error())?;
        let authenticated_commitment_start = authenticated_open_end + 4;
        let authenticated_commitment_end = authenticated_commitment_start
            .checked_add(authenticated_commitment_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if authenticated_commitment_end != encoded.len()
            || descriptor_digest == [0; 32]
            || pack_len == 0
            || acceptance_marker == 0
            || authenticated_open_len == 0
            || authenticated_commitment_len == 0
        {
            return Err(provisional_schema_error());
        }
        let open = BlobStreamOpen::decode(
            encoded
                .get(open_start..open_end)
                .ok_or_else(provisional_schema_error)?,
        )
        .map_err(|_| provisional_schema_error())?;
        let commitment = BlobStreamFinalCommitment::decode(
            encoded
                .get(commitment_start..commitment_end)
                .ok_or_else(provisional_schema_error)?,
        )
        .map_err(|_| provisional_schema_error())?;
        if open.stream_id() != stream_id
            || open.digest() != open_digest
            || commitment.stream_id() != stream_id
            || commitment.open_digest() != &open_digest
            || commitment.blob_id() != blob_id
            || commitment.total_len() != open.total_len()
            || commitment.ttl_ms() != open.ttl_ms()
        {
            return Err(provisional_schema_error());
        }
        Ok(Self {
            open,
            commitment,
            authenticated_open: encoded[authenticated_open_start..authenticated_open_end].to_vec(),
            authenticated_commitment: encoded
                [authenticated_commitment_start..authenticated_commitment_end]
                .to_vec(),
            blob_id,
            acceptance_marker,
            pack_len,
            descriptor_digest,
        })
    }
}

/// One receiver-durable carrier boundary for an exact pending source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStreamCheckpoint {
    pub next_carrier_index: u64,
    pub durable_encoded_offset: u64,
    pub generation: u64,
}

impl BlobStreamCheckpoint {
    pub(crate) fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        let mut bytes = [0; CHECKPOINT_BYTES];
        bytes[0] = CHECKPOINT_VERSION;
        bytes[1..9].copy_from_slice(&self.next_carrier_index.to_be_bytes());
        bytes[9..17].copy_from_slice(&self.durable_encoded_offset.to_be_bytes());
        bytes[17..25].copy_from_slice(&self.generation.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let bytes: [u8; CHECKPOINT_BYTES] = bytes.try_into().map_err(|_| checkpoint_error())?;
        if bytes[0] != CHECKPOINT_VERSION {
            return Err(checkpoint_error());
        }
        Ok(Self {
            next_carrier_index: u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
            durable_encoded_offset: u64::from_be_bytes(bytes[9..17].try_into().unwrap()),
            generation: u64::from_be_bytes(bytes[17..25].try_into().unwrap()),
        })
    }
}

/// Complete verified carriers accumulated across one or more bounded extents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamCheckpointBatch {
    first_carrier_index: u64,
    encoded_offset: u64,
    carriers: Vec<VerifiedBlobTransferObject>,
    encoded_len: u64,
}

impl VerifiedBlobStreamCheckpointBatch {
    pub fn from_extents(
        extents: impl IntoIterator<Item = VerifiedBlobStreamExtent>,
        advertised_limit: usize,
    ) -> Result<Self, StoreError> {
        let limit = advertised_limit.min(MAX_BLOB_STREAM_CHECKPOINT_BATCH_BYTES);
        if limit == 0 {
            return Err(checkpoint_error());
        }
        let mut first = None;
        let mut next = 0_u64;
        let mut offset = 0_u64;
        let mut encoded_len = 0_u64;
        let mut carriers = Vec::new();
        for extent in extents {
            if first.is_none() {
                first = Some(extent.first_carrier_index());
                next = extent.first_carrier_index();
                offset = extent.encoded_offset();
            }
            if extent.first_carrier_index() != next
                || extent.encoded_offset()
                    != offset
                        .checked_add(encoded_len)
                        .ok_or_else(checkpoint_error)?
            {
                return Err(checkpoint_error());
            }
            encoded_len = encoded_len
                .checked_add(extent.encoded_len())
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            if encoded_len > limit as u64 {
                return Err(checkpoint_error());
            }
            next = extent.next_carrier_index();
            carriers.extend_from_slice(extent.carriers());
        }
        let first_carrier_index = first.ok_or_else(checkpoint_error)?;
        if carriers.is_empty() || encoded_len == 0 {
            return Err(checkpoint_error());
        }
        Ok(Self {
            first_carrier_index,
            encoded_offset: offset,
            carriers,
            encoded_len,
        })
    }

    pub const fn first_carrier_index(&self) -> u64 {
        self.first_carrier_index
    }
    pub const fn encoded_offset(&self) -> u64 {
        self.encoded_offset
    }
    pub const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }
    pub fn carriers(&self) -> &[VerifiedBlobTransferObject] {
        &self.carriers
    }
    pub fn next_carrier_index(&self) -> u64 {
        self.first_carrier_index
            .saturating_add(self.carriers.len() as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamCommitOutcome {
    Advanced(BlobStreamCheckpoint),
    Duplicate(BlobStreamCheckpoint),
    Complete(BlobStreamCheckpoint),
}

/// Result of the one-way pending-source provenance transition into profile 5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamProvenanceUpgrade {
    AlreadyV9(BlobStreamCheckpoint),
    Upgraded(BlobStreamCheckpoint),
}

fn checkpoint_error() -> StoreError {
    blob_error(BlobStoreError::InvalidCarrierRange(
        "Blob stream checkpoint is not one exact forward carrier boundary",
    ))
}

fn provisional_schema_error() -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(
        "provisional Blob stream row is malformed",
    ))
}

fn stream_reserved_bytes(total_len: u64) -> Result<u64, StoreError> {
    let segment_count = total_len
        .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        / BLOB_STREAM_SEGMENT_BYTES as u64;
    total_len
        .checked_add(
            segment_count
                .checked_mul(PACK_RECORD_OVERHEAD)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )
        .and_then(|bytes| bytes.checked_add(PACK_FIXED_RESERVATION_BYTES))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, StoreError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, StoreError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, StoreError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], StoreError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(provisional_schema_error)
}

fn require_stream_policy_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
    policy: &ControlPolicySnapshot,
    open: &BlobStreamOpen,
) -> Result<(), StoreError> {
    require_control_policy_write(write, authority, policy)?;
    if open.mission_id() != &authority {
        return Err(StoreError::MissionAuthorityMismatch {
            bound: authority,
            received: *open.mission_id(),
        });
    }
    if control_principal_revoked_write(write, open.publisher())? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(
            open.publisher(),
        )));
    }
    let current_epoch = write
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(open.scope().as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    if open.content_epoch() < current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: current_epoch,
            received: open.content_epoch(),
        }));
    }
    if open.content_epoch() > current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochNotActive {
            current: current_epoch,
            received: open.content_epoch(),
        }));
    }
    let current_revision = policy.head().map_or(1, |(revision, _)| revision);
    if open.policy_revision() != current_revision {
        return Err(StoreError::ControlPolicyChanged);
    }
    Ok(())
}

fn require_stream_policy_read(
    read: &redb::ReadTransaction,
    authority: NodeId,
    policy: &ControlPolicySnapshot,
    open: &BlobStreamOpen,
) -> Result<(), StoreError> {
    require_control_policy_read(read, authority, policy)?;
    if open.mission_id() != &authority {
        return Err(StoreError::MissionAuthorityMismatch {
            bound: authority,
            received: *open.mission_id(),
        });
    }
    if control_principal_revoked_read(read, open.publisher())? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(
            open.publisher(),
        )));
    }
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(open.scope().as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    if open.content_epoch() < current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: current_epoch,
            received: open.content_epoch(),
        }));
    }
    if open.content_epoch() > current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochNotActive {
            current: current_epoch,
            received: open.content_epoch(),
        }));
    }
    if open.policy_revision() != policy.head().map_or(1, |(revision, _)| revision) {
        return Err(StoreError::ControlPolicyChanged);
    }
    Ok(())
}

fn require_local_stream_causal_write(
    write: &redb::WriteTransaction,
    open: &BlobStreamOpen,
) -> Result<(), StoreError> {
    let previous_counter = write
        .open_table(PUBLISHER_HIGH_WATER)?
        .get(open.publisher().as_slice())?
        .map_or(0, |value| value.value());
    if previous_counter.checked_add(1) != Some(open.publisher_counter()) {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    let prefix = event_domain_prefix(open.topic(), open.scope())?;
    let upper = blob_content_prefix_upper_bound(&prefix)?;
    let frontier = write.open_table(CAUSAL_FRONTIER)?;
    let mut context = VersionVector::default();
    let mut direct_publishers = 0_usize;
    for row in frontier.range::<&[u8]>((
        std::ops::Bound::<&[u8]>::Included(prefix.as_slice()),
        std::ops::Bound::<&[u8]>::Excluded(upper.as_slice()),
    ))? {
        let (key, value) = row?;
        let key = key.value();
        if key.len() != prefix.len() + 32 || value.value() == 0 {
            return Err(provisional_schema_error());
        }
        direct_publishers = direct_publishers
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if direct_publishers > MAX_CAUSAL_CONTEXT_ENTRIES {
            return Err(provisional_schema_error());
        }
        let publisher = key[prefix.len()..]
            .try_into()
            .map_err(|_| provisional_schema_error())?;
        context.observe(Dot {
            publisher,
            counter: value.value(),
        });
    }
    if context != *open.causal_context()
        || (context.counter(&open.publisher()) == 0
            && direct_publishers == MAX_CAUSAL_CONTEXT_ENTRIES)
    {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    Ok(())
}

fn encode_stream_publication(
    reservation: &BlobStreamReservation,
    commitment: &VerifiedBlobStreamFinalCommitment,
    completion: &BlobPackCompletion,
    acceptance_marker: u64,
) -> Result<Vec<u8>, StoreError> {
    let open_bytes = reservation.open.encode();
    let open_len = u32::try_from(open_bytes.len()).map_err(|_| provisional_schema_error())?;
    let commitment_bytes = commitment.commitment().encode();
    let commitment_len =
        u32::try_from(commitment_bytes.len()).map_err(|_| provisional_schema_error())?;
    let authenticated_open = &reservation.authenticated_open;
    let authenticated_commitment = commitment.authenticated_bytes();
    let authenticated_open_len =
        u32::try_from(authenticated_open.len()).map_err(|_| provisional_schema_error())?;
    let authenticated_commitment_len =
        u32::try_from(authenticated_commitment.len()).map_err(|_| provisional_schema_error())?;
    let mut encoded = Vec::with_capacity(
        169 + open_bytes.len()
            + commitment_bytes.len()
            + authenticated_open.len()
            + authenticated_commitment.len(),
    );
    encoded.extend_from_slice(PUBLICATION_MAGIC);
    encoded.push(PROVISIONAL_VERSION);
    encoded.extend_from_slice(reservation.stream_id.as_bytes());
    encoded.extend_from_slice(&reservation.open_digest);
    encoded.extend_from_slice(commitment.commitment().blob_id().as_bytes());
    encoded.extend_from_slice(completion.descriptor_digest());
    encoded.extend_from_slice(&completion.pack_len().to_be_bytes());
    encoded.extend_from_slice(&acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&open_len.to_be_bytes());
    encoded.extend_from_slice(&open_bytes);
    encoded.extend_from_slice(&commitment_len.to_be_bytes());
    encoded.extend_from_slice(&commitment_bytes);
    encoded.extend_from_slice(&authenticated_open_len.to_be_bytes());
    encoded.extend_from_slice(authenticated_open);
    encoded.extend_from_slice(&authenticated_commitment_len.to_be_bytes());
    encoded.extend_from_slice(authenticated_commitment);
    Ok(encoded)
}

fn stream_publication_matches(
    encoded: &[u8],
    reservation: &BlobStreamReservation,
    commitment: &VerifiedBlobStreamFinalCommitment,
    completion: &BlobPackCompletion,
) -> Result<Option<u64>, StoreError> {
    let completed = CompletedBlobStream::decode(encoded)?;
    if encoded
        == encode_stream_publication(
            reservation,
            commitment,
            completion,
            completed.acceptance_marker,
        )?
    {
        Ok(Some(completed.acceptance_marker))
    } else {
        Ok(None)
    }
}

impl Store {
    /// Returns completed pack-backed stream publications from one settled
    /// control-policy snapshot. Callers must still apply their peer-specific
    /// route/content authorization before disclosing an entry.
    pub fn blob_stream_publications_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
    ) -> Result<Vec<BlobStreamPublication>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let publications = read.open_table(BLOB_STREAM_PUBLICATIONS)?;
        let mut completed = Vec::with_capacity(
            usize::try_from(publications.len()?)
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in publications.iter()? {
            let (_, encoded) = row?;
            let publication = CompletedBlobStream::decode(encoded.value())?;
            if publication.open.mission_id() != &authority {
                return Err(provisional_schema_error());
            }
            completed.push(publication);
        }
        completed.sort_unstable_by_key(|publication| publication.acceptance_marker());
        Ok(completed)
    }

    /// Selects the newest completed stream publication for exact immutable content.
    pub fn blob_stream_for_content_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        topic: &aster_mesh::Topic,
        scope: &aster_mesh::Scope,
        blob_id: BlobId,
    ) -> Result<Option<BlobStreamPublication>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let publications = read.open_table(BLOB_STREAM_PUBLICATIONS)?;
        let mut selected: Option<BlobStreamPublication> = None;
        for row in publications.iter()? {
            let (_, encoded) = row?;
            let candidate = CompletedBlobStream::decode(encoded.value())?;
            if candidate.blob_id == blob_id
                && candidate.open.topic() == topic
                && candidate.open.scope() == scope
                && selected
                    .as_ref()
                    .is_none_or(|current| candidate.acceptance_marker > current.acceptance_marker)
            {
                selected = Some(candidate);
            }
        }
        Ok(selected)
    }

    /// Rechecks one exact completed stream projection without scanning content peers.
    pub fn require_blob_stream_publication_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        publication: &BlobStreamPublication,
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let encoded = read
            .open_table(BLOB_STREAM_PUBLICATIONS)?
            .get(publication.stream_id().as_bytes().as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        if CompletedBlobStream::decode(&encoded)? != *publication {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        Ok(())
    }

    /// Opens a sequential pack reader only after the caller re-verifies both signed authorities.
    pub fn open_blob_stream_read_session_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        publication: &BlobStreamPublication,
        open: &VerifiedBlobStreamOpen,
        commitment: &VerifiedBlobStreamFinalCommitment,
    ) -> Result<BlobStreamReadSession, StoreError> {
        self.require_blob_stream_publication_with_policy(policy, publication)?;
        if open.open() != publication.open()
            || open.authenticated_bytes() != publication.authenticated_open()
            || commitment.commitment() != publication.commitment()
            || commitment.authenticated_bytes() != publication.authenticated_commitment()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let completion = BlobPackCompletion::from_completed(
            publication.open.digest(),
            publication.open.stream_id(),
            publication.open.total_len(),
            publication.pack_len,
            publication.commitment.segment_count(),
            publication.descriptor_digest,
        );
        let root = PinnedBlobPackRoot::open_existing(self)?;
        Ok(BlobStreamReadSession {
            reader: BlobPackReader::open(&root, &completion)?,
            next_index: 0,
        })
    }

    /// Restores terminal resume authority without reopening a completed pack for
    /// append or creating a reservation. Both signed authorities, the completed
    /// descriptor, and the checkpoint's final roots must match the publication.
    pub fn completed_blob_stream_crypto_resume_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        publication: &BlobStreamPublication,
        open: &VerifiedBlobStreamOpen,
        commitment: &VerifiedBlobStreamFinalCommitment,
    ) -> Result<BlobStreamCryptoResume, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_stream_policy_read(&read, authority, policy, open.open())?;
        let _reader =
            self.open_blob_stream_read_session_with_policy(policy, publication, open, commitment)?;
        let root = PinnedBlobPackRoot::open_existing(self)?;
        let checkpoint = recover_blob_pack(&root, open.open().digest())?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let signed = commitment.commitment();
        if checkpoint.stream_id() != open.open().stream_id()
            || checkpoint.open_digest() != &open.open().digest()
            || checkpoint.total_len() != open.open().total_len()
            || checkpoint.plaintext_offset() != open.open().total_len()
            || checkpoint.next_index() != signed.segment_count()
            || checkpoint.pack_len() != publication.pack_len()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let plaintext_checkpoint = checkpoint.plaintext_checkpoint();
        let ciphertext_checkpoint = checkpoint.ciphertext_checkpoint();
        for (accumulator, expected) in [
            (&plaintext_checkpoint, signed.plaintext_root()),
            (&ciphertext_checkpoint, signed.ciphertext_root()),
        ] {
            let root = aster_mesh::BlobStreamAccumulator::restore(accumulator.clone())
                .and_then(|restored| restored.finish(accumulator.total_len()))
                .map_err(|_| blob_error(BlobStoreError::CompletionMismatch))?;
            if &root != expected {
                return Err(blob_error(BlobStoreError::CompletionMismatch));
            }
        }
        Ok(BlobStreamCryptoResume {
            progress: BlobStreamDurableProgress {
                generation: checkpoint.generation(),
                next_segment_index: checkpoint.next_index(),
                durable_plaintext_offset: checkpoint.plaintext_offset(),
                durable_pack_len: checkpoint.pack_len(),
            },
            plaintext_checkpoint,
            ciphertext_checkpoint,
        })
    }

    /// Resolves a completed stream operation under one exact settled policy.
    /// Provisional operations return `None` so the caller can resume them.
    pub fn blob_stream_for_operation_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        operation: &BlobOperationKey,
    ) -> Result<Option<BlobStreamPublication>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let Some(stream_id) = read
            .open_table(BLOB_STREAM_OPERATIONS)?
            .get(operation.as_bytes())?
            .map(|value| value.value().to_vec())
        else {
            return Ok(None);
        };
        let Some(encoded) = read
            .open_table(BLOB_STREAM_PUBLICATIONS)?
            .get(stream_id.as_slice())?
            .map(|value| value.value().to_vec())
        else {
            return Ok(None);
        };
        let publication = CompletedBlobStream::decode(&encoded)?;
        if publication.open.operation_key() != operation.as_bytes()
            || publication.open.mission_id() != &authority
            || publication.open.stream_id().as_bytes().as_slice() != stream_id.as_slice()
        {
            return Err(provisional_schema_error());
        }
        Ok(Some(publication))
    }

    /// Reserves bounded provisional capacity for one verified Blob stream.
    /// Exact replay returns the same opaque reservation and durable progress.
    pub fn reserve_blob_stream_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: BlobStreamReservationRequest<'_>,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<(BlobStreamReservation, BlobStreamDurableProgress), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let authenticated_open = open.authenticated_bytes().to_vec();
        let open = open.open();
        if request.operation.as_bytes() != open.operation_key() {
            return Err(blob_error(BlobStoreError::OperationConflict));
        }
        let reserved_bytes = stream_reserved_bytes(open.total_len())?;
        if reserved_bytes > self.blob_depot_limits.max_bytes() {
            return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                current: 0,
                incoming: reserved_bytes,
                limit: self.blob_depot_limits.max_bytes(),
            }));
        }

        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        require_stream_policy_write(&write, authority, policy, open)?;

        let stream_id = open.stream_id();
        let stream_key = stream_id.as_bytes().as_slice();
        if let Some(existing) = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(stream_key)?
            .map(|row| row.value().to_vec())
        {
            let existing = ProvisionalBlobStream::decode(&existing)?;
            if existing.open != *open
                || existing.reservation.authenticated_open != authenticated_open
                || existing.reservation.source != request.source
                || existing.reservation.operation != request.operation.as_bytes()
            {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            return Ok((existing.reservation.clone(), existing.progress()));
        }

        if let Some(bound_stream) = write
            .open_table(BLOB_STREAM_OPERATIONS)?
            .get(request.operation.as_bytes())?
        {
            if bound_stream.value() != stream_key {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            return Err(provisional_schema_error());
        }

        if request.source == BlobStreamSource::LocalApplication {
            require_local_stream_causal_write(&write, open)?;
        }

        // Physical depot reservation does not authorize logical publication
        // capacity. Preflight the exact canonical pack charge against all
        // ordinary classes, including the protected control/tombstone reserve.
        let pack_bytes = aster_mesh::EncryptedBlobStreamSegment::packed_wire_len(
            open.total_len(),
            open.total_len().div_ceil(BLOB_STREAM_SEGMENT_BYTES as u64),
        )
        .and_then(|bytes| bytes.checked_add(PACK_HEADER_LEN))
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        require_ordinary_aggregate_capacity(
            &write,
            &write.open_table(METADATA)?,
            self.limits,
            1,
            pack_bytes,
        )?;

        let (current_rows, current_bytes) = {
            let reservations = write.open_table(BLOB_STREAM_RESERVATIONS)?;
            let mut rows = 0_u64;
            let mut bytes = 0_u64;
            for row in reservations.iter()? {
                let (_, value) = row?;
                let existing = ProvisionalBlobStream::decode(value.value())?;
                rows = rows
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
                bytes = bytes
                    .checked_add(existing.reservation.reserved_bytes)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            }
            (rows, bytes)
        };
        if current_rows >= self.blob_depot_limits.max_variants() {
            return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
                current: current_rows,
                limit: self.blob_depot_limits.max_variants(),
            }));
        }
        let updated_bytes = current_bytes
            .checked_add(reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if updated_bytes > self.blob_depot_limits.max_bytes() {
            return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                current: current_bytes,
                incoming: reserved_bytes,
                limit: self.blob_depot_limits.max_bytes(),
            }));
        }

        let reservation = BlobStreamReservation {
            stream_id: open.stream_id(),
            open_digest: open.digest(),
            operation: request.operation.as_bytes().to_vec(),
            source: request.source,
            reserved_bytes,
            open: open.clone(),
            authenticated_open,
        };
        let provisional = ProvisionalBlobStream {
            reservation: reservation.clone(),
            open: open.clone(),
            checkpoint: None,
        };
        write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .insert(stream_key, provisional.encode()?.as_slice())?;
        write
            .open_table(BLOB_STREAM_OPERATIONS)?
            .insert(request.operation.as_bytes(), stream_key)?;
        write.commit()?;
        Ok((reservation, BlobStreamDurableProgress::default()))
    }

    pub fn open_blob_stream_pack_session(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobStreamReservation,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<BlobStreamPackSession, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        // Exclude another session before reading its checkpoint, so a writer
        // that just promoted cannot leave us using a stale provisional row.
        let writer_lease = self
            .blob_stream_writer_leases
            .acquire(reservation.stream_id)?;
        let encoded = {
            let read = self.database.begin_read()?;
            require_control_policy_read(&read, authority, policy)?;
            read.open_table(BLOB_STREAM_RESERVATIONS)?
                .get(reservation.stream_id.as_bytes().as_slice())?
                .map(|row| row.value().to_vec())
                .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?
        };
        let provisional = ProvisionalBlobStream::decode(&encoded)?;
        if provisional.reservation != *reservation || provisional.open != *open.open() {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let root = PinnedBlobPackRoot::open(self)?;
        let writer = if let Some(checkpoint) = &provisional.checkpoint {
            BlobPackWriter::resume(&root, checkpoint)?
        } else {
            // Open the owner-bound capability before taking the redb write
            // lock: depot opening may need its own initialization transaction.
            let retry_root = super::depot::open_blob_pack_root(self, false)?;
            let write = self.database.begin_write()?;
            enforce_live_write(&write)?;
            require_stream_policy_write(&write, authority, policy, &provisional.open)?;
            let key = reservation.stream_id.as_bytes().as_slice();
            let current = write
                .open_table(BLOB_STREAM_RESERVATIONS)?
                .get(key)?
                .map(|row| row.value().to_vec());
            let operation_stream = write
                .open_table(BLOB_STREAM_OPERATIONS)?
                .get(reservation.operation.as_slice())?
                .map(|row| row.value().to_vec());
            if current.as_deref() != Some(encoded.as_slice())
                || operation_stream.as_deref() != Some(key)
                || write
                    .open_table(BLOB_STREAM_PUBLICATIONS)?
                    .get(key)?
                    .is_some()
            {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
            if let Some(journal) = recover_blob_pack(&root, reservation.open_digest)?
                && (journal.stream_id() != reservation.stream_id
                    || journal.total_len() != provisional.open.total_len())
            {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
            // The first journal can be durable before its redb checkpoint.
            // Only redb authorizes acknowledged progress; an exact reservation
            // with no checkpoint may restart from zero. Keep the write lock
            // until cleanup finishes so a committed checkpoint or publication
            // cannot appear between authorization and removal.
            super::depot::discard_uncheckpointed_blob_pack(
                &retry_root,
                reservation.open_digest,
                reservation.reserved_bytes,
                BlobPackCheckpoint::ENCODED_LEN as u64,
            )?;
            let writer = BlobPackWriter::create(&root, open)?;
            drop(write);
            writer
        };
        Ok(BlobStreamPackSession {
            writer,
            reservation: reservation.clone(),
            progress: provisional.progress(),
            writer_lease,
        })
    }

    #[allow(dead_code)] // Invoked by the actor-owned receive session in Task 5.
    pub(crate) fn commit_blob_pack_checkpoint_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobStreamReservation,
        expected: BlobStreamDurableProgress,
        checkpoint: BlobPackCheckpoint,
    ) -> Result<BlobStreamDurableProgress, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        let key = reservation.stream_id.as_bytes().as_slice();
        let encoded = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let mut provisional = ProvisionalBlobStream::decode(&encoded)?;
        require_stream_policy_write(&write, authority, policy, &provisional.open)?;
        if provisional.reservation != *reservation
            || provisional.progress() != expected
            || checkpoint.stream_id() != reservation.stream_id
            || checkpoint.open_digest() != &reservation.open_digest
            || checkpoint.total_len() != provisional.open.total_len()
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        if let Some(current) = &provisional.checkpoint {
            if current.encode() == checkpoint.encode() {
                return Ok(provisional.progress());
            }
            if checkpoint.generation() != current.generation() + 1
                || checkpoint.next_index() < current.next_index()
                || checkpoint.plaintext_offset() < current.plaintext_offset()
                || checkpoint.pack_len() < current.pack_len()
            {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
        } else if checkpoint.generation() != 1 {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        provisional.checkpoint = Some(checkpoint);
        let progress = provisional.progress();
        write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .insert(key, provisional.encode()?.as_slice())?;
        write.commit()?;
        Ok(progress)
    }

    #[allow(dead_code)] // Invoked by the actor-owned receive session in Task 5.
    pub(crate) fn promote_blob_stream_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobStreamReservation,
        commitment: &VerifiedBlobStreamFinalCommitment,
        completion: BlobPackCompletion,
        final_sample: Option<CustodySample>,
    ) -> Result<BlobStreamPromotion, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let final_commitment = commitment.commitment();
        let key = reservation.stream_id.as_bytes().as_slice();
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;

        if let Some(existing) = write
            .open_table(BLOB_STREAM_PUBLICATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec())
        {
            let Some(acceptance_marker) =
                stream_publication_matches(&existing, reservation, commitment, &completion)?
            else {
                return Err(blob_error(BlobStoreError::OperationConflict));
            };
            return Ok(BlobStreamPromotion {
                stream_id: reservation.stream_id,
                blob_id: final_commitment.blob_id(),
                acceptance_marker,
                duplicate: true,
            });
        }

        let encoded = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let provisional = ProvisionalBlobStream::decode(&encoded)?;
        require_stream_policy_write(&write, authority, policy, &provisional.open)?;
        let checkpoint = provisional
            .checkpoint
            .as_ref()
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        if provisional.reservation != *reservation
            || final_commitment.open_digest() != &reservation.open_digest
            || final_commitment.stream_id() != reservation.stream_id
            || final_commitment.total_len() != provisional.open.total_len()
            || final_commitment.ttl_ms() != provisional.open.ttl_ms()
            || final_commitment.final_custody() != final_sample
            || completion.open_digest() != &reservation.open_digest
            || completion.stream_id() != reservation.stream_id
            || completion.total_len() != provisional.open.total_len()
            || completion.segment_count() != final_commitment.segment_count()
            || checkpoint.next_index() != completion.segment_count()
            || checkpoint.plaintext_offset() != completion.total_len()
            || checkpoint.pack_len() != completion.pack_len()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        match (
            provisional.open.ttl_ms(),
            provisional.open.initial_custody(),
            final_sample,
        ) {
            (None, None, None) => {}
            (Some(ttl_ms), Some(initial), Some(final_sample))
                if initial.clock_id == final_sample.clock_id
                    && final_sample.tick_ms >= initial.tick_ms
                    && final_sample.tick_ms - initial.tick_ms < ttl_ms => {}
            (Some(_), Some(_), Some(_)) => {
                return Err(blob_error(BlobStoreError::ExpiredOrRetired));
            }
            _ => return Err(blob_error(BlobStoreError::CompletionMismatch)),
        }

        let dot = Dot {
            publisher: provisional.open.publisher(),
            counter: provisional.open.publisher_counter(),
        };
        let semantic_id = provisional.open.digest();
        let dot_key = accepted_dot_key(dot);
        if let Some(accepted) = write.open_table(ACCEPTED_DOTS)?.get(dot_key.as_slice())? {
            if accepted.value() != semantic_id {
                return Err(StoreError::CausalEquivocation {
                    publisher: dot.publisher,
                    counter: dot.counter,
                });
            }
            return Err(provisional_schema_error());
        }
        ensure_frontier_capacity(
            &write,
            provisional.open.topic(),
            provisional.open.scope(),
            dot.publisher,
            SemanticDataClass::Blob,
        )?;
        let acceptance_marker = {
            let mut metadata = write.open_table(METADATA)?;
            // The provisional reservation owns physical depot space. Other
            // classes can consume logical capacity while bytes are arriving,
            // so recheck before the atomic visibility/accounting transition.
            require_ordinary_aggregate_capacity(
                &write,
                &metadata,
                self.limits,
                1,
                completion.pack_len(),
            )?;
            let current_items = metadata
                .get(BLOB_ITEM_COUNT)?
                .map_or(0, |value| value.value());
            let current_bytes = metadata
                .get(BLOB_TOTAL_BYTES)?
                .map_or(0, |value| value.value());
            let previous_marker = metadata
                .get(LAST_BLOB_ACCEPTANCE_MARKER)?
                .map_or(0, |value| value.value());
            let marker = previous_marker
                .checked_add(1)
                .ok_or(StoreError::AcceptanceMarkerExhausted)?;
            metadata.insert(
                BLOB_ITEM_COUNT,
                current_items
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(
                BLOB_TOTAL_BYTES,
                current_bytes
                    .checked_add(completion.pack_len())
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )?;
            metadata.insert(LAST_BLOB_ACCEPTANCE_MARKER, marker)?;
            marker
        };

        let publication =
            encode_stream_publication(reservation, commitment, &completion, acceptance_marker)?;
        write
            .open_table(BLOB_STREAM_PUBLICATIONS)?
            .insert(key, publication.as_slice())?;
        write
            .open_table(ACCEPTED_DOTS)?
            .insert(dot_key.as_slice(), semantic_id.as_slice())?;
        update_causal_high_water(
            &write,
            dot.publisher,
            provisional.open.topic(),
            provisional.open.scope(),
            dot.counter,
        )?;
        write.open_table(BLOB_STREAM_RESERVATIONS)?.remove(key)?;
        write.commit()?;
        Ok(BlobStreamPromotion {
            stream_id: reservation.stream_id,
            blob_id: final_commitment.blob_id(),
            acceptance_marker,
            duplicate: false,
        })
    }

    /// Stages a new durable semantic-v9/profile-5 source under the configured
    /// physical depot byte/chunk limits and creates its initial checkpoint in
    /// the same transaction.
    pub fn stage_verified_durable_blob_stream_v9_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobSourceStageOutcome, StoreError> {
        if blob.ttl_ms().is_some() {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "finite Blob stream requires authenticated custody-v2 authority",
            )));
        }
        self.stage_verified_blob_source_with_lifetime_and_profile(
            policy,
            blob,
            sealed,
            plan,
            None,
            BlobNetworkAdmissionProfile::StreamV1,
        )
    }

    /// Stages a new finite semantic-v9/profile-5 source while preserving the
    /// authenticated lower-bound age and a receiver-local continuity sample.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_verified_finite_blob_stream_v9_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
        claim: BlobCustodyClaimV2,
        contact: AuthenticatedBlobCustodyContactV2,
        receiver_sample: aster_mesh::CustodySample,
    ) -> Result<BlobSourceStageOutcome, StoreError> {
        let transfer = BlobTransferId::new(blob.envelope_id());
        let verified = claim
            .verify_authenticated_source(
                contact,
                claim.exchange_id(),
                BlobCustodyTransferId::from_exact_hash(*transfer.as_bytes()),
                blob,
                sealed,
                0,
            )
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let admission = VerifiedFiniteBlobAdmission {
            source_transfer_id: *verified.source_transfer_id().as_bytes(),
            source_len: verified.source_len(),
            publication_id: verified.publication_id(),
            blob_id: verified.blob_id(),
            priority: verified.priority(),
            ttl_ms: verified.ttl_ms(),
            forwarding_age_ms: verified.forwarding_age_ms(),
            receiver_sample,
            provenance: BlobFiniteProvenance::NetworkV1 {
                semantic_version: 9,
                profile_id: aster_mesh::TransferProfileId::BlobStreamV1 as u16,
            },
        };
        self.stage_verified_blob_source_with_lifetime_and_profile(
            policy,
            blob,
            sealed,
            plan,
            Some(admission),
            BlobNetworkAdmissionProfile::StreamV1,
        )
    }

    /// Test-only semantic-v9 finite staging seam. Runtime callers must use
    /// [`Self::stage_verified_finite_blob_stream_v9_with_policy`] with an
    /// authenticated custody-v2 contact.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn test_stage_verified_finite_blob_stream_v9_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
        forwarding_age_ms: u64,
        receiver_sample: aster_mesh::CustodySample,
    ) -> Result<BlobSourceStageOutcome, StoreError> {
        let ttl_ms = blob.ttl_ms().ok_or_else(|| {
            blob_error(BlobStoreError::InvalidPublication(
                "finite Blob stream fixture is missing its signed TTL",
            ))
        })?;
        let admission = VerifiedFiniteBlobAdmission::for_test_with_network_provenance(
            blob.envelope_id(),
            u64::try_from(sealed.len()).map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            blob.item_id(),
            blob.blob_id(),
            blob.priority(),
            ttl_ms,
            forwarding_age_ms,
            receiver_sample,
            9,
            aster_mesh::TransferProfileId::BlobStreamV1 as u16,
        );
        self.stage_verified_blob_source_with_lifetime_and_profile(
            policy,
            blob,
            sealed,
            plan,
            Some(admission),
            BlobNetworkAdmissionProfile::StreamV1,
        )
    }

    /// Atomically upgrades an exact profile-4 pending source to semantic-v9
    /// profile-5 authority. Finite work must carry a freshly authenticated,
    /// non-younger v2 claim; durable work carries no synthetic TTL authority.
    pub fn upgrade_pending_blob_to_stream_v9(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
        finite: Option<(BlobCustodyClaimV2, AuthenticatedBlobCustodyContactV2)>,
    ) -> Result<BlobStreamProvenanceUpgrade, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        blob.verify_exact_manifest(plan.manifest_bytes())
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if BlobTransferId::new(blob.envelope_id()) != source
            || plan.source_envelope().into_bytes() != *source.as_bytes()
            || plan.manifest() != blob.manifest()
            || plan.manifest_digest() != blob.manifest_digest()
            || plan.physical_lineage() != blob.physical_lineage()
        {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }

        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        let encoded = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        let mut pending = decode_pending_blob_source(&encoded)?;
        require_pending_matches_verified_source(&pending, blob, sealed)?;
        require_pending_blob_plan(&pending, plan)?;
        require_blob_lifetime_visible_write(&write, pending.metadata.lifetime)?;
        enforce_blob_policy_write(&write, authority, policy, &pending.metadata.header)?;
        pressure::require_pending_source_write(&write, source, &pending)?;
        pressure::require_variant_write(&write, pending.metadata.variant_id)?;

        let existing_checkpoint = write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?;
        let already_v9 = match pending.metadata.lifetime {
            BlobLifetime::Durable => existing_checkpoint.is_some(),
            BlobLifetime::Finite { provenance, .. } => {
                existing_checkpoint.is_some()
                    && matches!(
                        provenance,
                        BlobFiniteProvenance::NetworkV1 {
                            semantic_version: 9,
                            profile_id
                        } if profile_id == aster_mesh::TransferProfileId::BlobStreamV1 as u16
                    )
            }
        };
        if already_v9 {
            match pending.metadata.lifetime {
                BlobLifetime::Durable => {
                    if finite.is_some() {
                        return Err(blob_error(BlobStoreError::PendingSourceConflict));
                    }
                }
                BlobLifetime::Finite {
                    ttl_ms,
                    mut age,
                    provenance,
                } => {
                    let old_lifetime = pending.metadata.lifetime;
                    let (claim, contact) =
                        finite.ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
                    let verified = claim
                        .verify_authenticated_source(
                            contact,
                            claim.exchange_id(),
                            BlobCustodyTransferId::from_exact_hash(*source.as_bytes()),
                            blob,
                            sealed,
                            age.cumulative_age_ms,
                        )
                        .map_err(|error| {
                            blob_error(BlobStoreError::Verification(error.to_string()))
                        })?;
                    if verified.ttl_ms() != ttl_ms {
                        return Err(blob_error(BlobStoreError::PendingSourceConflict));
                    }
                    age.cumulative_age_ms = age.cumulative_age_ms.max(verified.forwarding_age_ms());
                    pending.metadata.lifetime = BlobLifetime::Finite {
                        ttl_ms,
                        age,
                        provenance,
                    };
                    pending.metadata.lifetime = lifecycle::project_lifetime_for_policy_write(
                        &write,
                        pending.metadata.lifetime,
                    )?;
                    lifecycle::replace_policy_ttl_deadline_write(
                        &write,
                        source,
                        lifecycle::TtlDeadlineKind::PendingSource,
                        Some(old_lifetime),
                        Some(pending.metadata.lifetime),
                        self.blob_lifecycle_limits,
                    )?;
                    pending.authenticated_source_binding =
                        pending_blob_authenticated_source_binding(
                            &pending.metadata,
                            &pending.sealed,
                        )?;
                    let replacement = encode_pending_blob_source(&pending)?;
                    write
                        .open_table(BLOB_PENDING_SOURCES)?
                        .insert(source.as_bytes().as_slice(), replacement.as_slice())?;
                    pressure::rekey_pending_source_lifetime_write(&write, source, &pending)?;
                    write.commit()?;
                }
            }
            return Ok(BlobStreamProvenanceUpgrade::AlreadyV9(
                existing_checkpoint.unwrap_or_default(),
            ));
        }

        let old_lifetime = pending.metadata.lifetime;
        match pending.metadata.lifetime {
            BlobLifetime::Durable => {
                if finite.is_some() {
                    return Err(blob_error(BlobStoreError::PendingSourceConflict));
                }
            }
            BlobLifetime::Finite {
                ttl_ms,
                mut age,
                provenance,
            } => {
                let upgradable = match provenance {
                    BlobFiniteProvenance::Local => true,
                    BlobFiniteProvenance::NetworkV1 {
                        semantic_version: 8,
                        profile_id,
                    } => profile_id == aster_mesh::TransferProfileId::BlobRangesStreamV1 as u16,
                    BlobFiniteProvenance::NetworkV1 { .. } => false,
                };
                if !upgradable {
                    return Err(blob_error(BlobStoreError::PendingSourceConflict));
                }
                let (claim, contact) =
                    finite.ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
                let verified = claim
                    .verify_authenticated_source(
                        contact,
                        claim.exchange_id(),
                        BlobCustodyTransferId::from_exact_hash(*source.as_bytes()),
                        blob,
                        sealed,
                        age.cumulative_age_ms,
                    )
                    .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
                if verified.ttl_ms() != ttl_ms {
                    return Err(blob_error(BlobStoreError::PendingSourceConflict));
                }
                age.cumulative_age_ms = age.cumulative_age_ms.max(verified.forwarding_age_ms());
                pending.metadata.lifetime = BlobLifetime::Finite {
                    ttl_ms,
                    age,
                    provenance: BlobFiniteProvenance::NetworkV1 {
                        semantic_version: 9,
                        profile_id: aster_mesh::TransferProfileId::BlobStreamV1 as u16,
                    },
                };
            }
        }
        pending.metadata.lifetime =
            lifecycle::project_lifetime_for_policy_write(&write, pending.metadata.lifetime)?;
        lifecycle::replace_policy_ttl_deadline_write(
            &write,
            source,
            lifecycle::TtlDeadlineKind::PendingSource,
            Some(old_lifetime),
            Some(pending.metadata.lifetime),
            self.blob_lifecycle_limits,
        )?;
        pending.authenticated_source_binding =
            pending_blob_authenticated_source_binding(&pending.metadata, &pending.sealed)?;
        let replacement = encode_pending_blob_source(&pending)?;
        write
            .open_table(BLOB_PENDING_SOURCES)?
            .insert(source.as_bytes().as_slice(), replacement.as_slice())?;
        pressure::rekey_pending_source_lifetime_write(&write, source, &pending)?;

        let previous = existing_checkpoint.unwrap_or_default();
        let checkpoint = BlobStreamCheckpoint {
            generation: previous
                .generation
                .checked_add(1)
                .ok_or_else(checkpoint_error)?,
            ..previous
        };
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if !layout.contains_checkpoint(
            checkpoint.next_carrier_index,
            checkpoint.durable_encoded_offset,
        ) {
            return Err(checkpoint_error());
        }
        let encoded = checkpoint.encode();
        write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .insert(source.as_bytes().as_slice(), encoded.as_slice())?;
        write.commit()?;
        Ok(BlobStreamProvenanceUpgrade::Upgraded(checkpoint))
    }

    /// Loads the one constant-sized cumulative checkpoint for a pending source.
    pub fn blob_stream_checkpoint_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobStreamCheckpoint, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let pending = read
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| decode_pending_blob_source(row.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        require_blob_contact_eligibility(
            pending.metadata.lifetime,
            BlobContactEligibility::CustodyV2,
        )?;
        require_blob_lifetime_visible_read(&read, pending.metadata.lifetime)?;
        enforce_blob_policy_read(&read, authority, policy, &pending.metadata.header)?;
        require_pending_blob_plan(&pending, plan)?;
        let checkpoint = read
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?
            .unwrap_or_default();
        if checkpoint.generation == 0 {
            return Err(blob_error(BlobStoreError::ReadPlanChanged));
        }
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if !layout.contains_checkpoint(
            checkpoint.next_carrier_index,
            checkpoint.durable_encoded_offset,
        ) {
            return Err(checkpoint_error());
        }
        Ok(checkpoint)
    }

    /// Installs a bounded whole-carrier batch and advances the cumulative
    /// checkpoint only after every carrier is durable.
    pub fn commit_blob_stream_batch_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        plan: &VerifiedBlobTransferPlan,
        expected: BlobStreamCheckpoint,
        batch: VerifiedBlobStreamCheckpointBatch,
    ) -> Result<BlobStreamCommitOutcome, StoreError> {
        let current = self.blob_stream_checkpoint_with_policy(policy, source, plan)?;
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let batch_end = batch
            .encoded_offset()
            .checked_add(batch.encoded_len())
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if batch.next_carrier_index() == current.next_carrier_index
            && batch_end == current.durable_encoded_offset
            && batch.first_carrier_index() < current.next_carrier_index
        {
            // A crash may commit the terminal markers/checkpoint immediately
            // before the idempotent finalization transaction. Exact replay
            // completes that last local step without moving the checkpoint.
            if current.next_carrier_index == layout.carrier_count() {
                let variant = blob_variant_id(
                    plan.manifest().id(),
                    plan.manifest().content_group(),
                    plan.manifest().content_epoch(),
                );
                let mut depot = BlobDepot::open_network_mutation(self, false)?;
                depot.acquire_carrier_extent_lease(variant)?;
                CoreBlobStore::begin_blob_with_lineage(
                    &mut depot,
                    plan.manifest(),
                    plan.physical_lineage(),
                )?;
                CoreBlobStore::finalize_blob(
                    &mut depot,
                    plan.manifest().id(),
                    *plan.manifest_digest(),
                )?;
            }
            return Ok(BlobStreamCommitOutcome::Duplicate(current));
        }
        if current != expected
            || batch.first_carrier_index() != current.next_carrier_index
            || batch.encoded_offset() != current.durable_encoded_offset
            || !layout.contains_checkpoint(batch.next_carrier_index(), batch_end)
        {
            return Err(checkpoint_error());
        }

        let variant = blob_variant_id(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        );
        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        depot.acquire_carrier_extent_lease(variant)?;
        CoreBlobStore::begin_blob_with_lineage(
            &mut depot,
            plan.manifest(),
            plan.physical_lineage(),
        )?;
        for (position, carrier) in batch.carriers().iter().enumerate() {
            let index = batch
                .first_carrier_index()
                .checked_add(position as u64)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            if carrier.index() != index {
                return Err(checkpoint_error());
            }
        }
        let prepared = depot.prepare_verified_stream_batch(batch.carriers())?;
        let complete = batch.next_carrier_index() == layout.carrier_count();

        let checkpoint = BlobStreamCheckpoint {
            next_carrier_index: batch.next_carrier_index(),
            durable_encoded_offset: batch_end,
            generation: current
                .generation
                .checked_add(1)
                .ok_or_else(checkpoint_error)?,
        };
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| decode_pending_blob_source(row.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        require_blob_contact_eligibility(
            pending.metadata.lifetime,
            BlobContactEligibility::CustodyV2,
        )?;
        require_blob_lifetime_visible_write(&write, pending.metadata.lifetime)?;
        enforce_blob_policy_write(
            &write,
            self.require_bound_mission()?,
            policy,
            &pending.metadata.header,
        )?;
        require_pending_blob_plan(&pending, plan)?;
        let durable = write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?
            .unwrap_or_default();
        if durable != current {
            return Err(checkpoint_error());
        }
        depot::commit_prepared_stream_markers_write(&write, variant, &prepared)?;
        let encoded = checkpoint.encode();
        write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .insert(source.as_bytes().as_slice(), encoded.as_slice())?;
        write.commit()?;
        if complete {
            CoreBlobStore::finalize_blob(
                &mut depot,
                plan.manifest().id(),
                *plan.manifest_digest(),
            )?;
        }
        drop(depot);
        Ok(if complete {
            BlobStreamCommitOutcome::Complete(checkpoint)
        } else {
            BlobStreamCommitOutcome::Advanced(checkpoint)
        })
    }

    /// Reads complete canonical carriers from one authenticated local source.
    pub fn read_completed_blob_stream_extent_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        completion: &BlobDepotCompletion,
        plan: &VerifiedBlobTransferPlan,
        checkpoint: BlobStreamCheckpoint,
        max_bytes: usize,
    ) -> Result<Option<OwnedBlobStreamExtent>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if completion.blob_id() != plan.manifest().id()
            || completion.manifest_digest() != plan.manifest_digest()
            || completion.physical_lineage() != plan.physical_lineage().binding()
            || completion.chunk_count() != plan.manifest().chunk_count()
            || completion.total_len() != plan.manifest().total_len()
            || completion.variant_id()
                != BlobVariantId::for_content(
                    plan.manifest().id(),
                    plan.manifest().content_group(),
                    plan.manifest().content_epoch(),
                )
            || !layout.contains_checkpoint(
                checkpoint.next_carrier_index,
                checkpoint.durable_encoded_offset,
            )
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let source = BlobTransferId::new(plan.source_envelope().into_bytes());
        let read = self.database.begin_read()?;
        let stored = completed_blob_range_source_snapshot_read(&read, source)
            .map_err(|error| {
                blob_preflight_decode_error(error, "completed Blob stream source is malformed")
            })?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        require_blob_contact_eligibility(
            stored.metadata.lifetime,
            BlobContactEligibility::CustodyV2,
        )?;
        require_blob_lifetime_visible_read(&read, stored.metadata.lifetime)?;
        enforce_blob_policy_read(&read, authority, policy, &stored.metadata.header)?;
        drop(read);
        let variant = blob_variant_id(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        );
        let mut depot = self.blob_depot()?;
        depot.acquire_carrier_extent_lease(variant)?;
        CoreBlobStore::select_blob_for_read_with_lineage(
            &mut depot,
            plan.manifest(),
            plan.physical_lineage(),
        )?;
        plan.read_stream_extent(&mut depot, checkpoint.next_carrier_index, max_bytes)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::{
        BlobMetadata, BlobStreamOpen, Priority, ProvisioningAccess, ReferenceEnvelopeSealer,
        ReferenceProvisioner, Scope, Topic,
    };
    use zeroize::Zeroizing;

    static NEXT_PROVISIONAL_ROOT: AtomicU64 = AtomicU64::new(0);

    struct ProvisionalFixture {
        path: PathBuf,
        store: Store,
        publisher: ReferenceEnvelopeSealer,
        open: VerifiedBlobStreamOpen,
        operation: BlobOperationKey,
    }

    impl Drop for ProvisionalFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn provisional_fixture(seed: u8) -> ProvisionalFixture {
        provisional_fixture_with_len(seed, 8)
    }

    fn provisional_fixture_with_len(seed: u8, total_len: u64) -> ProvisionalFixture {
        let topic = Topic::new("provisional-pack").expect("topic");
        let scope = Scope::new("mission/provisional-pack").expect("scope");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_control_authority(1, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let operation = BlobOperationKey::new(format!("provisional-{seed}")).expect("operation");
        let authorization_digest = publisher
            .blob_stream_authorization_digest(&scope, 1)
            .expect("route authorization");
        let open = BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([seed; 32]).expect("stream ID"),
            publisher.identity(),
            operation.as_bytes().to_vec(),
            publisher.mission_authority_id(),
            1,
            VersionVector::default(),
            topic,
            scope,
            BlobMetadata::new(
                Some("application/octet-stream".into()),
                b"provisional".to_vec(),
            )
            .expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            authorization_digest,
            [0x45; 32],
        )
        .expect("open");
        let signed = publisher.seal_blob_stream_open(&open).expect("sign open");
        let open = publisher
            .verify_blob_stream_open(&signed)
            .expect("verify open");
        let path = std::env::temp_dir().join(format!(
            "aster-stream-provisional-{}-{}",
            std::process::id(),
            NEXT_PROVISIONAL_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create root");
        let store =
            Store::open_for_mission(path.join("state.redb"), publisher.mission_authority_id())
                .expect("store");
        ProvisionalFixture {
            path,
            store,
            publisher,
            open,
            operation,
        }
    }

    #[test]
    fn blob_stream_checkpoint_encoding_is_constant_sized_and_canonical() {
        let checkpoint = BlobStreamCheckpoint {
            next_carrier_index: 17,
            durable_encoded_offset: 1_u64 << 30,
            generation: 9,
        };
        let encoded = checkpoint.encode();
        assert_eq!(encoded.len(), CHECKPOINT_BYTES);
        assert_eq!(BlobStreamCheckpoint::decode(&encoded).unwrap(), checkpoint);
        assert!(BlobStreamCheckpoint::decode(&encoded[..24]).is_err());
    }

    #[test]
    fn blob_stream_provisional_reservation_is_idempotent_and_invisible() {
        let fixture = provisional_fixture(0x71);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let request = BlobStreamReservationRequest {
            operation: &fixture.operation,
            source: BlobStreamSource::LocalApplication,
        };
        let first = fixture
            .store
            .reserve_blob_stream_with_policy(&policy, request, &fixture.open)
            .expect("first reservation");
        let second = fixture
            .store
            .reserve_blob_stream_with_policy(&policy, request, &fixture.open)
            .expect("duplicate reservation");
        assert_eq!(first, second);
        assert_eq!(first.1, BlobStreamDurableProgress::default());

        let read = fixture.store.database.begin_read().expect("read");
        assert_eq!(
            read.open_table(BLOB_PUBLICATIONS).unwrap().len().unwrap(),
            0
        );
        assert_eq!(
            read.open_table(BLOB_PENDING_SOURCES)
                .unwrap()
                .len()
                .unwrap(),
            0
        );
        assert_eq!(
            read.open_table(BLOB_STREAM_RESERVATIONS)
                .unwrap()
                .len()
                .unwrap(),
            1
        );
    }

    #[test]
    fn blob_stream_provisional_conflicting_source_fails() {
        let fixture = provisional_fixture(0x72);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        fixture
            .store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            )
            .expect("reservation");
        assert!(
            fixture
                .store
                .reserve_blob_stream_with_policy(
                    &policy,
                    BlobStreamReservationRequest {
                        operation: &fixture.operation,
                        source: BlobStreamSource::AuthenticatedPeer([0x99; 32]),
                    },
                    &fixture.open,
                )
                .is_err()
        );
    }

    #[test]
    fn blob_stream_quota_rejects_large_open_before_reserving_depot_capacity() {
        let fixture = provisional_fixture_with_len(0x81, 96 * 1024 * 1024 + 37);
        let database = fixture.path.join("limited.redb");
        let depot_limits = BlobDepotLimits::new(
            512 * 1024 * 1024,
            BlobDepotLimits::DEFAULT.max_chunks(),
            BlobDepotLimits::DEFAULT.max_variants(),
        )
        .expect("large physical depot");
        let authority = fixture.publisher.mission_authority_id();
        let store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &database,
            StoreLimits::default(),
            depot_limits,
            authority,
        )
        .expect("limited store");
        let policy = store.control_policy_snapshot().expect("policy");
        assert!(matches!(
            store.reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            ),
            Err(StoreError::PayloadByteLimitExceeded { .. })
        ));
        let read = store.database.begin_read().expect("reservation audit");
        assert!(
            read.open_table(BLOB_STREAM_RESERVATIONS)
                .unwrap()
                .is_empty()
                .unwrap()
        );
        assert!(
            read.open_table(BLOB_STREAM_OPERATIONS)
                .unwrap()
                .is_empty()
                .unwrap()
        );
        drop(read);
        drop(store);
        Store::open_with_limits_and_blob_depot_limits_for_mission(
            &database,
            StoreLimits::default(),
            depot_limits,
            authority,
        )
        .expect("rejection leaves store reopenable");
    }

    #[test]
    fn blob_stream_quota_admission_includes_existing_payload_and_item_usage() {
        let fixture = provisional_fixture(0x82);
        let pack_bytes = aster_mesh::EncryptedBlobStreamSegment::packed_wire_len(8, 1).unwrap()
            + PACK_HEADER_LEN;
        let (reserved_items, reserved_bytes) =
            custody::custody_emergency_reserve(StoreLimits::default());
        for item_limit in [false, true] {
            let limits = if item_limit {
                StoreLimits::new(reserved_items + 1, DEFAULT_MAX_TOTAL_PAYLOAD_BYTES)
            } else {
                StoreLimits::new(DEFAULT_MAX_ITEMS, reserved_bytes + pack_bytes + 16)
            }
            .expect("aggregate limits");
            let database = fixture.path.join(format!("admission-{item_limit}.redb"));
            let store = Store::open_with_limits_for_mission(
                &database,
                limits,
                fixture.publisher.mission_authority_id(),
            )
            .expect("limited store");
            store
                .apply(ItemId::new([0x82; 32]), &[0x82; 17])
                .expect("existing payload");
            let policy = store.control_policy_snapshot().expect("policy");
            let result = store.reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            );
            if item_limit {
                assert!(matches!(result, Err(StoreError::ItemLimitExceeded { .. })));
            } else {
                assert!(matches!(
                    result,
                    Err(StoreError::PayloadByteLimitExceeded { .. })
                ));
            }
            let read = store.database.begin_read().expect("reservation audit");
            assert!(
                read.open_table(BLOB_STREAM_RESERVATIONS)
                    .unwrap()
                    .is_empty()
                    .unwrap()
            );
        }
    }

    #[test]
    fn blob_stream_quota_promotion_rechecks_capacity_and_exact_fit_reopens() {
        let fixture = provisional_fixture(0x83);
        let pack_bytes = aster_mesh::EncryptedBlobStreamSegment::packed_wire_len(8, 1).unwrap()
            + PACK_HEADER_LEN;
        let (_, reserved_bytes) = custody::custody_emergency_reserve(StoreLimits::default());
        let limits = StoreLimits::new(DEFAULT_MAX_ITEMS, reserved_bytes + pack_bytes + 16)
            .expect("aggregate limit");
        for late_payload_bytes in [16, 17] {
            let directory = fixture.path.join(format!("promotion-{late_payload_bytes}"));
            std::fs::create_dir(&directory).expect("receiver directory");
            let database = directory.join("state.redb");
            let authority = fixture.publisher.mission_authority_id();
            let store = Store::open_with_limits_for_mission(&database, limits, authority)
                .expect("limited store");
            let policy = store.control_policy_snapshot().expect("policy");
            let (reservation, _) = store
                .reserve_blob_stream_with_policy(
                    &policy,
                    BlobStreamReservationRequest {
                        operation: &fixture.operation,
                        source: BlobStreamSource::LocalApplication,
                    },
                    &fixture.open,
                )
                .expect("capacity available at reservation");
            let mut session = store
                .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
                .expect("session");
            let plaintext = [0x83; 8];
            let mut encryptor = fixture
                .publisher
                .begin_blob_stream_encrypt(&fixture.open)
                .expect("encryptor");
            let segment = encryptor
                .encrypt_segment(0, 0, Zeroizing::new(plaintext.to_vec()))
                .expect("segment");
            session
                .append_segment(&plaintext, &segment)
                .expect("append");
            session.checkpoint(&store, &policy).expect("checkpoint");
            let (plaintext_root, ciphertext_root) = session.final_roots().expect("roots");
            let commitment = BlobStreamFinalCommitment::new(
                &fixture.open,
                plaintext_root,
                ciphertext_root,
                1,
                None,
            )
            .expect("commitment");
            let signed = fixture
                .publisher
                .seal_blob_stream_commitment(&commitment)
                .expect("sign");
            let commitment = fixture
                .publisher
                .verify_blob_stream_commitment(&fixture.open, &signed)
                .expect("verify");
            // Another class may consume capacity after the provisional reservation.
            store
                .apply(ItemId::new([0x83; 32]), &vec![0x83; late_payload_bytes])
                .expect("late payload");
            let (retried, progress) = store
                .reserve_blob_stream_with_policy(
                    &policy,
                    BlobStreamReservationRequest {
                        operation: &fixture.operation,
                        source: BlobStreamSource::LocalApplication,
                    },
                    &fixture.open,
                )
                .expect("existing reservation remains idempotent at full capacity");
            assert_eq!(retried, reservation);
            assert_eq!(progress.durable_plaintext_offset(), 8);
            let result = session.finish_and_promote(&store, &policy, &commitment, None);
            let accepted = late_payload_bytes == 16;
            if accepted {
                assert_eq!(result.expect("exact fit promotes").acceptance_marker(), 1);
            } else {
                assert!(matches!(
                    result,
                    Err(StoreError::PayloadByteLimitExceeded { .. })
                ));
            }
            let read = store.database.begin_read().expect("promotion audit");
            assert_eq!(
                read.open_table(BLOB_STREAM_PUBLICATIONS)
                    .unwrap()
                    .len()
                    .unwrap(),
                u64::from(accepted)
            );
            assert_eq!(
                read.open_table(BLOB_STREAM_RESERVATIONS)
                    .unwrap()
                    .len()
                    .unwrap(),
                u64::from(!accepted)
            );
            assert_eq!(
                read.open_table(METADATA)
                    .unwrap()
                    .get(LAST_BLOB_ACCEPTANCE_MARKER)
                    .unwrap()
                    .map_or(0, |row| row.value()),
                u64::from(accepted)
            );
            drop(read);
            drop(store);
            let reopened = Store::open_with_limits_for_mission(&database, limits, authority)
                .expect("quota-respecting store reopens");
            let usage = reopened.aggregate_usage().expect("aggregate usage");
            assert_eq!(
                usage.payload_bytes,
                late_payload_bytes as u64 + if accepted { pack_bytes } else { 0 }
            );
            assert_eq!(
                reopened.blob_stats().expect("Blob audit").publications,
                u64::from(accepted)
            );
        }
    }

    #[test]
    fn blob_stream_background_writeback_drop_joins_before_releasing_writer_lease() {
        let fixture = provisional_fixture(0x74);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial) = fixture
            .store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            )
            .expect("reservation");
        let mut session = fixture
            .store
            .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
            .expect("first writer");
        let (release, released) = std::sync::mpsc::channel();
        let (joining, join_started) = std::sync::mpsc::channel();
        session.writer.test_install_background_writeback(
            std::thread::spawn(move || {
                released.recv().expect("release background worker");
                Ok(())
            }),
            joining,
        );
        assert_eq!(
            session.progress(),
            initial,
            "background work creates no durable progress"
        );
        let dropping = std::thread::spawn(move || drop(session));
        join_started
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("Drop entered the pending worker join");
        let competing =
            fixture
                .store
                .open_blob_stream_pack_session(&policy, &reservation, &fixture.open);
        release.send(()).expect("let owned worker finish");
        dropping.join().expect("session drop finishes");
        assert!(
            competing.is_err(),
            "writer lease must remain held throughout Drop join"
        );
        let reopened = fixture
            .store
            .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
            .expect("retry after joined Drop");
        assert_eq!(reopened.progress(), initial);
    }

    #[test]
    fn blob_stream_checkpoint_transaction_advances_only_durable_authority() {
        use super::super::pack::{BlobPackWriter, PinnedBlobPackRoot};

        let fixture = provisional_fixture(0x73);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial) = fixture
            .store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            )
            .expect("reservation");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::create(&root, &fixture.open).expect("pack writer");
        let mut encryptor = fixture
            .publisher
            .begin_blob_stream_encrypt(&fixture.open)
            .expect("encryptor");
        let segment = encryptor
            .encrypt_segment(0, 0, Zeroizing::new(vec![0x33; 8]))
            .expect("segment");
        writer.append_segment(&[0x33; 8], &segment).expect("append");
        let checkpoint = writer.checkpoint().expect("durable pack checkpoint");
        let advanced = fixture
            .store
            .commit_blob_pack_checkpoint_with_policy(
                &policy,
                &reservation,
                initial,
                checkpoint.clone(),
            )
            .expect("commit checkpoint");
        assert_eq!(advanced.generation(), 1);
        assert_eq!(advanced.next_segment_index(), 1);
        assert_eq!(advanced.durable_plaintext_offset(), 8);
        assert_eq!(
            fixture
                .store
                .commit_blob_pack_checkpoint_with_policy(
                    &policy,
                    &reservation,
                    advanced,
                    checkpoint,
                )
                .expect("duplicate checkpoint"),
            advanced
        );
        assert!(
            fixture
                .store
                .commit_blob_pack_checkpoint_with_policy(
                    &policy,
                    &reservation,
                    initial,
                    writer.checkpoint().expect("next durable checkpoint"),
                )
                .is_err()
        );
    }

    #[test]
    fn blob_stream_promotion_is_the_single_visibility_switch() {
        use super::super::pack::{BlobPackWriter, PinnedBlobPackRoot};
        use aster_mesh::{
            BlobStreamAccumulator, BlobStreamAccumulatorDomain, BlobStreamFinalCommitment,
        };

        let fixture = provisional_fixture(0x74);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, initial) = fixture
            .store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            )
            .expect("reservation");
        let root = PinnedBlobPackRoot::open(&fixture.store).expect("pack root");
        let mut writer = BlobPackWriter::create(&root, &fixture.open).expect("writer");
        let plaintext = vec![0x41; 8];
        let mut encryptor = fixture
            .publisher
            .begin_blob_stream_encrypt(&fixture.open)
            .expect("encryptor");
        let segment = encryptor
            .encrypt_segment(0, 0, Zeroizing::new(plaintext.clone()))
            .expect("segment");
        writer.append_segment(&plaintext, &segment).expect("append");
        let checkpoint = writer.checkpoint().expect("checkpoint");
        fixture
            .store
            .commit_blob_pack_checkpoint_with_policy(&policy, &reservation, initial, checkpoint)
            .expect("commit checkpoint");
        let mut plaintext_accumulator =
            BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        plaintext_accumulator
            .push_segment(0, &plaintext)
            .expect("plaintext accumulator");
        let mut ciphertext_accumulator =
            BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Ciphertext);
        ciphertext_accumulator
            .push_segment(0, segment.ciphertext())
            .expect("ciphertext accumulator");
        let commitment = BlobStreamFinalCommitment::new(
            &fixture.open,
            plaintext_accumulator.finish(8).expect("plaintext root"),
            ciphertext_accumulator
                .finish(segment.ciphertext().len() as u64)
                .expect("ciphertext root"),
            1,
            None,
        )
        .expect("commitment");
        let signed = fixture
            .publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("sign commitment");
        let commitment = fixture
            .publisher
            .verify_blob_stream_commitment(&fixture.open, &signed)
            .expect("verify commitment");
        let completion = writer.finish(&commitment).expect("pack completion");
        let expected_pack_len = completion.pack_len();
        let promoted = fixture
            .store
            .promote_blob_stream_with_policy(
                &policy,
                &reservation,
                &commitment,
                completion.clone(),
                None,
            )
            .expect("promotion");
        assert!(!promoted.duplicate());
        assert_eq!(promoted.blob_id(), commitment.commitment().blob_id());
        assert_eq!(promoted.acceptance_marker(), 1);

        let read = fixture.store.database.begin_read().expect("read");
        let publications = read.open_table(BLOB_STREAM_PUBLICATIONS).unwrap();
        assert_eq!(publications.len().unwrap(), 1);
        let encoded = publications
            .get(fixture.open.open().stream_id().as_bytes().as_slice())
            .unwrap()
            .expect("completed stream row");
        assert_eq!(
            CompletedBlobStream::decode(encoded.value())
                .expect("completed stream")
                .open,
            *fixture.open.open()
        );
        assert_eq!(
            read.open_table(BLOB_STREAM_RESERVATIONS)
                .unwrap()
                .len()
                .unwrap(),
            0
        );
        assert_eq!(
            read.open_table(BLOB_PUBLICATIONS).unwrap().len().unwrap(),
            0
        );
        drop(read);
        let stats = fixture
            .store
            .blob_stats()
            .expect("stream publication stats");
        assert_eq!(stats.publications, 1);
        assert_eq!(stats.acceptance_markers, 1);
        assert_eq!(stats.last_acceptance_marker, 1);
        assert_eq!(stats.total_sealed_bytes, expected_pack_len);
        let publication = fixture
            .store
            .blob_stream_for_operation_with_policy(&policy, &fixture.operation)
            .expect("completed operation")
            .expect("completed publication");
        assert!(matches!(
            fixture
                .store
                .open_blob_stream_pack_session(&policy, &reservation, &fixture.open),
            Err(StoreError::Blob(BlobStoreError::ReservationChanged))
        ));
        let resume = fixture
            .store
            .completed_blob_stream_crypto_resume_with_policy(
                &policy,
                &publication,
                &fixture.open,
                &commitment,
            )
            .expect("completed checkpoint can settle a repeated offer");
        assert_eq!(resume.progress().durable_plaintext_offset(), 8);
        assert_eq!(resume.progress().next_segment_index(), 1);
        assert_eq!(resume.progress().durable_pack_len(), expected_pack_len);
        let mismatched =
            BlobStreamFinalCommitment::new(&fixture.open, [0x91; 32], [0x92; 32], 1, None)
                .expect("different commitment for the same signed open");
        let signed_mismatch = fixture
            .publisher
            .seal_blob_stream_commitment(&mismatched)
            .expect("sign different commitment");
        let mismatched = fixture
            .publisher
            .verify_blob_stream_commitment(&fixture.open, &signed_mismatch)
            .expect("authenticated different commitment");
        assert!(matches!(
            fixture
                .store
                .completed_blob_stream_crypto_resume_with_policy(
                    &policy,
                    &publication,
                    &fixture.open,
                    &mismatched,
                ),
            Err(StoreError::Blob(BlobStoreError::CompletionMismatch))
        ));
        let read = fixture.store.database.begin_read().expect("strict read");
        let mut shared = StateAuditSnapshot::default();
        let inspection = inspect_blob_tables_read_with_shared(&read, &mut shared)
            .expect("strict stream publication inspection");
        assert_eq!(inspection.stats.publications, 1);
        let duplicate = fixture
            .store
            .promote_blob_stream_with_policy(&policy, &reservation, &commitment, completion, None)
            .expect("duplicate promotion");
        assert!(duplicate.duplicate());
        assert_eq!(duplicate.acceptance_marker(), 1);
        assert_eq!(
            fixture
                .store
                .blob_stats()
                .expect("duplicate stream publication stats")
                .last_acceptance_marker,
            1
        );
        drop(read);
        // A retained completion must not bypass a publisher revocation that
        // would reject a new reservation for the same authenticated intent.
        let write = fixture
            .store
            .database
            .begin_write()
            .expect("revocation write");
        let revoked = encode_revocation_index(
            fixture.publisher.mission_authority_id(),
            1,
            ControlTransferId::new([0x93; 32]),
        );
        write
            .open_table(CONTROL_REVOCATIONS)
            .expect("revocations")
            .insert(
                fixture.open.open().publisher().as_slice(),
                revoked.as_slice(),
            )
            .expect("revoke completed publisher");
        write.commit().expect("commit revocation");
        assert!(matches!(
            fixture
                .store
                .completed_blob_stream_crypto_resume_with_policy(
                    &policy,
                    &publication,
                    &fixture.open,
                    &commitment,
                ),
            Err(StoreError::Blob(BlobStoreError::PublisherRevoked(_)))
        ));
    }

    #[test]
    fn blob_stream_retries_first_checkpoint_crash_before_redb_commit_after_reopen() {
        for temp_before_rename in [false, true] {
            let fixture = provisional_fixture(if temp_before_rename { 0x77 } else { 0x76 });
            let receiver_path = fixture.path.join("receiver");
            std::fs::create_dir(&receiver_path).expect("receiver root");
            let database_path = receiver_path.join("state.redb");
            let authority = fixture.publisher.mission_authority_id();
            let store = Store::open_for_mission(&database_path, authority).expect("receiver");
            let policy = store.control_policy_snapshot().expect("policy");
            let (reservation, _) = store
                .reserve_blob_stream_with_policy(
                    &policy,
                    BlobStreamReservationRequest {
                        operation: &fixture.operation,
                        source: BlobStreamSource::LocalApplication,
                    },
                    &fixture.open,
                )
                .expect("reservation");
            let mut session = store
                .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
                .expect("session");
            let plaintext = vec![0x52; 8];
            let mut encryptor = fixture
                .publisher
                .begin_blob_stream_encrypt(&fixture.open)
                .expect("encryptor");
            let segment = encryptor
                .encrypt_segment(0, 0, Zeroizing::new(plaintext.clone()))
                .expect("segment");
            session
                .append_segment(&plaintext, &segment)
                .expect("append");
            if temp_before_rename {
                super::super::depot::inject_test_fault(
                    &receiver_path,
                    super::super::depot::DepotFaultPoint::TempSynced,
                );
                assert!(session.writer.checkpoint().is_err());
            } else {
                let journal = session.writer.checkpoint().expect("journal before redb");
                assert_eq!(journal.generation(), 1);
                assert_eq!(journal.plaintext_offset(), 8);
            }
            // The pack/journal barrier happened without the store transaction
            // that would authorize reporting any of these bytes as durable.
            assert_eq!(session.progress(), BlobStreamDurableProgress::default());
            drop(session);
            drop(store);

            let store = Store::open_for_mission(&database_path, authority).expect("reopen");
            let policy = store.control_policy_snapshot().expect("reopened policy");
            let (retried, progress) = store
                .reserve_blob_stream_with_policy(
                    &policy,
                    BlobStreamReservationRequest {
                        operation: &fixture.operation,
                        source: BlobStreamSource::LocalApplication,
                    },
                    &fixture.open,
                )
                .expect("same operation retry");
            assert_eq!(retried, reservation);
            assert_eq!(progress, BlobStreamDurableProgress::default());
            let mut restarted = store
                .open_blob_stream_pack_session(&policy, &retried, &fixture.open)
                .expect("discard only unacknowledged crash artifacts");
            assert_eq!(restarted.progress(), BlobStreamDurableProgress::default());
            let root = PinnedBlobPackRoot::open_existing(&store).expect("root");
            assert!(
                recover_blob_pack(&root, reservation.open_digest)
                    .unwrap()
                    .is_none()
            );
            restarted
                .append_segment(&plaintext, &segment)
                .expect("replayed segment");
            let durable = restarted
                .checkpoint(&store, &policy)
                .expect("first committed checkpoint");
            assert_eq!(durable.generation(), 1);
            assert_eq!(durable.durable_plaintext_offset(), 8);
            assert_eq!(store.blob_stats().expect("stats").last_acceptance_marker, 0);
        }
    }

    #[test]
    fn blob_stream_active_writer_excludes_retry_through_journal_commit_and_store_reopen() {
        for reopen_while_active in [false, true] {
            let fixture = provisional_fixture(if reopen_while_active { 0x7a } else { 0x79 });
            let receiver_path = fixture.path.join("receiver");
            std::fs::create_dir(&receiver_path).expect("receiver root");
            let database_path = receiver_path.join("state.redb");
            let authority = fixture.publisher.mission_authority_id();
            let mut store = std::sync::Arc::new(
                Store::open_for_mission(&database_path, authority).expect("receiver"),
            );
            let policy = store.control_policy_snapshot().expect("policy");
            let (reservation, _) = store
                .reserve_blob_stream_with_policy(
                    &policy,
                    BlobStreamReservationRequest {
                        operation: &fixture.operation,
                        source: BlobStreamSource::LocalApplication,
                    },
                    &fixture.open,
                )
                .expect("reservation");
            let mut active = store
                .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
                .expect("active writer");
            let plaintext = vec![0x61; 8];
            let mut encryptor = fixture
                .publisher
                .begin_blob_stream_encrypt(&fixture.open)
                .expect("encryptor");
            let segment = encryptor
                .encrypt_segment(0, 0, Zeroizing::new(plaintext.clone()))
                .expect("segment");
            active.append_segment(&plaintext, &segment).expect("append");
            let foreign_policy = fixture
                .store
                .control_policy_snapshot()
                .expect("foreign policy");
            assert!(matches!(
                active.checkpoint(&fixture.store, &foreign_policy),
                Err(StoreError::Blob(BlobStoreError::ReservationChanged))
            ));
            let checkpoint = active
                .writer
                .checkpoint()
                .expect("journal before redb commit");
            assert_eq!(checkpoint.generation(), 1);
            let expected_roots = active.final_roots().expect("active roots");
            if reopen_while_active {
                // The session owns its exclusion even if the caller releases
                // the Store, then reopens the exact owner-bound database.
                drop(store);
                store = std::sync::Arc::new(
                    Store::open_for_mission(&database_path, authority)
                        .expect("reopen with active session"),
                );
            }
            let policy = store.control_policy_snapshot().expect("current policy");
            let other_contact = std::sync::Arc::clone(&store);
            assert!(matches!(
                other_contact.open_blob_stream_pack_session(&policy, &reservation, &fixture.open),
                Err(StoreError::Blob(BlobStoreError::LeaseCapacity))
            ));
            drop(other_contact);
            active.progress = store
                .commit_blob_pack_checkpoint_with_policy(
                    &policy,
                    &reservation,
                    active.progress,
                    checkpoint,
                )
                .expect("active writer commits its still-linked pack");
            let durable = active.progress();
            assert_eq!(durable.durable_plaintext_offset(), 8);
            drop(active);
            drop(store);
            let store = Store::open_for_mission(&database_path, authority).expect("final reopen");
            let policy = store.control_policy_snapshot().expect("final policy");
            // A new session can acquire the stream only after the first writer
            // and its pack descriptor have been dropped.
            let resumed = store
                .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
                .expect("resume after writer release");
            assert_eq!(resumed.progress(), durable);
            assert_eq!(
                resumed.final_roots().expect("resumed roots"),
                expected_roots
            );
        }
    }

    #[test]
    fn blob_stream_uncheckpointed_retry_preserves_unknown_artifacts() {
        let fixture = provisional_fixture(0x78);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            )
            .expect("reservation");
        let session = fixture
            .store
            .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
            .expect("session");
        drop(session);
        let digest = reservation
            .open_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let pack_directory = fixture
            .path
            .join("blob-depot-v1")
            .join("stream-packs-v1")
            .join(digest);
        let pack = pack_directory.join("segments.pack");
        let before = std::fs::read(&pack).expect("pack header");
        for name in ["unrecognized", ".aster-blob-tmp-not-a-sequence"] {
            let unknown = pack_directory.join(name);
            std::fs::write(&unknown, b"retain me").expect("unknown artifact");
            assert!(
                fixture
                    .store
                    .open_blob_stream_pack_session(&policy, &reservation, &fixture.open,)
                    .is_err()
            );
            assert_eq!(
                std::fs::read(&unknown).expect("unknown retained"),
                b"retain me"
            );
            assert_eq!(std::fs::read(&pack).expect("known pack retained"), before);
            std::fs::remove_file(unknown).expect("remove test artifact");
        }
        #[cfg(unix)]
        {
            let outside = fixture.path.join("outside");
            std::fs::write(&outside, b"retain outside").expect("outside artifact");
            let temp = pack_directory.join(".aster-blob-tmp-1-1");
            std::os::unix::fs::symlink(&outside, &temp).expect("temp symlink");
            assert!(
                fixture
                    .store
                    .open_blob_stream_pack_session(&policy, &reservation, &fixture.open,)
                    .is_err()
            );
            assert!(
                std::fs::symlink_metadata(&temp)
                    .expect("symlink retained")
                    .is_symlink()
            );
            assert_eq!(
                std::fs::read(outside).expect("outside retained"),
                b"retain outside"
            );
            assert_eq!(std::fs::read(&pack).expect("pack retained"), before);
        }
    }

    #[test]
    fn blob_stream_pack_session_restores_crypto_and_plaintext_frontiers() {
        let fixture = provisional_fixture(0x75);
        let policy = fixture.store.control_policy_snapshot().expect("policy");
        let (reservation, _) = fixture
            .store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &fixture.operation,
                    source: BlobStreamSource::LocalApplication,
                },
                &fixture.open,
            )
            .expect("reservation");
        let mut session = fixture
            .store
            .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
            .expect("session");
        let plaintext = vec![0x52; 8];
        let mut encryptor = fixture
            .publisher
            .begin_blob_stream_encrypt(&fixture.open)
            .expect("encryptor");
        let segment = encryptor
            .encrypt_segment(0, 0, Zeroizing::new(plaintext.clone()))
            .expect("segment");
        session
            .append_segment(&plaintext, &segment)
            .expect("session append");
        let durable = session
            .checkpoint(&fixture.store, &policy)
            .expect("session checkpoint");
        assert_eq!(durable.durable_plaintext_offset(), 8);
        let expected_roots = session.final_roots().expect("roots");
        // A newer journal without a matching redb commit cannot erase or
        // advance the already acknowledged checkpoint on retry.
        let uncommitted = session.writer.checkpoint().expect("uncommitted journal");
        assert_eq!(uncommitted.generation(), durable.generation() + 1);
        drop(session);

        let resumed = fixture
            .store
            .open_blob_stream_pack_session(&policy, &reservation, &fixture.open)
            .expect("resumed session");
        assert_eq!(resumed.progress(), durable);
        assert_eq!(
            resumed.final_roots().expect("resumed roots"),
            expected_roots
        );
        let crypto = resumed.crypto_resume();
        let _encryptor = fixture
            .publisher
            .resume_blob_stream_encrypt(
                &fixture.open,
                crypto.progress().durable_plaintext_offset(),
                crypto.ciphertext_checkpoint(),
            )
            .expect("resume encryption without plaintext replay");
    }
}
