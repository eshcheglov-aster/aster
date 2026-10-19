//! Incremental primitives for the semantic-v9/profile-5 streaming Blob format.
//!
//! This module owns only canonical, checkpointable protocol state. It never
//! serializes implementation-private hash state and never stages a complete
//! plaintext Blob.

use crate::{
    blob::{BlobError, BlobId, BlobMetadata},
    custody::CustodySample,
    model::{Dot, MAX_CAUSAL_CONTEXT_ENTRIES, NodeId, Priority, Scope, Topic, VersionVector},
    source_blob::BlobStreamProviderSeal,
};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Maximum plaintext carried by one independently authenticated stream segment.
pub const BLOB_STREAM_SEGMENT_BYTES: usize = 1024 * 1024;

const BLOB_STREAM_FORMAT_VERSION: u16 = 1;
const BLOB_STREAM_PACK_FORMAT_VERSION: u16 = 1;
const BLOB_STREAM_OPEN_MAGIC: &[u8; 8] = b"ASTRBO01";
const BLOB_STREAM_SEGMENT_MAGIC: &[u8; 8] = b"ASTRBS01";
const BLOB_STREAM_COMMITMENT_MAGIC: &[u8; 8] = b"ASTRBF01";
const BLOB_STREAM_OPEN_DIGEST_DOMAIN: &[u8] = b"aster/blob-stream/open/v1";
const BLOB_STREAM_METADATA_DOMAIN: &[u8] = b"aster/blob-stream/metadata/v1";
const BLOB_STREAM_ID_DOMAIN: &[u8] = b"aster/blob-stream/blob-id/v1";
const BLOB_STREAM_KEY_SALT: &[u8] = b"aster/blob-stream/key/v1";
const BLOB_STREAM_KEY_INFO: &[u8] = b"aster/blob-stream/aead-key/v1";
const BLOB_STREAM_NONCE_INFO: &[u8] = b"aster/blob-stream/base-nonce/v1";
const MAX_BLOB_STREAM_OPERATION_KEY_BYTES: usize = 256;
const MAX_BLOB_STREAM_OPEN_BYTES: usize = 2048 + 40 * MAX_CAUSAL_CONTEXT_ENTRIES;
const GCM_TAG_BYTES: usize = 16;
const GCM_NONCE_BYTES: usize = 12;

/// Fresh logical identity for one provisional publication.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobPublicationStreamId([u8; 32]);

impl BlobPublicationStreamId {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, BlobError> {
        if bytes == [0_u8; 32] {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical publisher intent that authorizes bounded provisional admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamOpen {
    stream_id: BlobPublicationStreamId,
    publisher: NodeId,
    operation_key: Vec<u8>,
    mission_id: [u8; 32],
    publisher_counter: u64,
    causal_context: VersionVector,
    topic: Topic,
    scope: Scope,
    metadata: BlobMetadata,
    priority: Priority,
    ttl_ms: Option<u64>,
    initial_custody: Option<CustodySample>,
    total_len: u64,
    content_epoch: u64,
    policy_revision: u64,
    authorization_digest: [u8; 32],
    publication_salt: [u8; 32],
}

impl BlobStreamOpen {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream_id: BlobPublicationStreamId,
        publisher: NodeId,
        operation_key: Vec<u8>,
        mission_id: [u8; 32],
        publisher_counter: u64,
        causal_context: VersionVector,
        topic: Topic,
        scope: Scope,
        metadata: BlobMetadata,
        priority: Priority,
        ttl_ms: Option<u64>,
        initial_custody: Option<CustodySample>,
        total_len: u64,
        content_epoch: u64,
        policy_revision: u64,
        authorization_digest: [u8; 32],
        publication_salt: [u8; 32],
    ) -> Result<Self, BlobError> {
        if publisher == [0_u8; 32]
            || operation_key.is_empty()
            || operation_key.len() > MAX_BLOB_STREAM_OPERATION_KEY_BYTES
            || mission_id == [0_u8; 32]
            || publisher_counter == 0
            || causal_context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
            || causal_context.iter().any(|(context_publisher, counter)| {
                *counter == 0 || (*context_publisher == publisher && *counter >= publisher_counter)
            })
            || total_len == 0
            || content_epoch == 0
            || policy_revision == 0
            || authorization_digest == [0_u8; 32]
            || publication_salt == [0_u8; 32]
            || ttl_ms == Some(0)
            || ttl_ms.is_some() != initial_custody.is_some()
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            stream_id,
            publisher,
            operation_key,
            mission_id,
            publisher_counter,
            causal_context,
            topic,
            scope,
            metadata,
            priority,
            ttl_ms,
            initial_custody,
            total_len,
            content_epoch,
            policy_revision,
            authorization_digest,
            publication_salt,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(512);
        encoded.extend_from_slice(BLOB_STREAM_OPEN_MAGIC);
        encoded.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&BLOB_STREAM_PACK_FORMAT_VERSION.to_be_bytes());
        encoded.extend_from_slice(self.stream_id.as_bytes());
        encoded.extend_from_slice(&self.publisher);
        push_u16_bytes(&mut encoded, &self.operation_key).expect("validated operation key");
        encoded.extend_from_slice(&self.mission_id);
        encoded.extend_from_slice(&self.publisher_counter.to_be_bytes());
        encoded.extend_from_slice(&(self.causal_context.len() as u32).to_be_bytes());
        for (publisher, counter) in self.causal_context.iter() {
            encoded.extend_from_slice(publisher);
            encoded.extend_from_slice(&counter.to_be_bytes());
        }
        push_u16_bytes(&mut encoded, self.topic.as_str().as_bytes()).expect("validated topic");
        push_u16_bytes(&mut encoded, self.scope.as_str().as_bytes()).expect("validated scope");
        encode_metadata(&mut encoded, &self.metadata).expect("validated metadata");
        encoded.push(self.priority as u8);
        encode_optional_u64(&mut encoded, self.ttl_ms);
        encode_optional_custody(&mut encoded, self.initial_custody);
        encoded.extend_from_slice(&self.total_len.to_be_bytes());
        encoded.extend_from_slice(&self.content_epoch.to_be_bytes());
        encoded.extend_from_slice(&self.policy_revision.to_be_bytes());
        encoded.extend_from_slice(&self.authorization_digest);
        encoded.extend_from_slice(&self.publication_salt);
        debug_assert!(encoded.len() <= MAX_BLOB_STREAM_OPEN_BYTES);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        if encoded.len() > MAX_BLOB_STREAM_OPEN_BYTES {
            return Err(BlobError::InvalidManifest);
        }
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_OPEN_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
            || reader.u16()? != BLOB_STREAM_PACK_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)?;
        let publisher = reader.array()?;
        let operation_key = reader
            .u16_bytes(MAX_BLOB_STREAM_OPERATION_KEY_BYTES)?
            .to_vec();
        let mission_id = reader.array()?;
        let publisher_counter = reader.u64()?;
        let context_len = usize::try_from(reader.u32()?).map_err(|_| BlobError::LengthOverflow)?;
        if context_len > MAX_CAUSAL_CONTEXT_ENTRIES {
            return Err(BlobError::InvalidManifest);
        }
        let mut causal_context = VersionVector::default();
        for _ in 0..context_len {
            let context_publisher = reader.array()?;
            let context_counter = reader.u64()?;
            if context_counter == 0 || causal_context.counter(&context_publisher) != 0 {
                return Err(BlobError::InvalidManifest);
            }
            causal_context.observe(Dot {
                publisher: context_publisher,
                counter: context_counter,
            });
        }
        let topic = Topic::new(reader.u16_string(128)?).map_err(|_| BlobError::InvalidManifest)?;
        let scope = Scope::new(reader.u16_string(128)?).map_err(|_| BlobError::InvalidManifest)?;
        let metadata = decode_metadata(&mut reader)?;
        let priority = Priority::from_wire(reader.u8()?).ok_or(BlobError::InvalidManifest)?;
        let ttl_ms = decode_optional_u64(&mut reader)?;
        let initial_custody = decode_optional_custody(&mut reader)?;
        let total_len = reader.u64()?;
        let content_epoch = reader.u64()?;
        let policy_revision = reader.u64()?;
        let authorization_digest = reader.array()?;
        let publication_salt = reader.array()?;
        reader.finish()?;
        Self::new(
            stream_id,
            publisher,
            operation_key,
            mission_id,
            publisher_counter,
            causal_context,
            topic,
            scope,
            metadata,
            priority,
            ttl_ms,
            initial_custody,
            total_len,
            content_epoch,
            policy_revision,
            authorization_digest,
            publication_salt,
        )
    }

    pub fn digest(&self) -> [u8; 32] {
        hash_parts(BLOB_STREAM_OPEN_DIGEST_DOMAIN, &[&self.encode()])
    }

    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }

    pub const fn publisher_counter(&self) -> u64 {
        self.publisher_counter
    }

    pub const fn causal_context(&self) -> &VersionVector {
        &self.causal_context
    }

    pub fn operation_key(&self) -> &[u8] {
        &self.operation_key
    }

    pub const fn mission_id(&self) -> &[u8; 32] {
        &self.mission_id
    }

    pub fn topic(&self) -> &Topic {
        &self.topic
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn metadata(&self) -> &BlobMetadata {
        &self.metadata
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn content_epoch(&self) -> u64 {
        self.content_epoch
    }

    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }

    pub const fn initial_custody(&self) -> Option<CustodySample> {
        self.initial_custody
    }

    pub const fn authorization_digest(&self) -> &[u8; 32] {
        &self.authorization_digest
    }
}

/// Provider-authenticated publication intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamOpen {
    open: BlobStreamOpen,
    mission_authority_id: NodeId,
    authenticated_bytes: Vec<u8>,
}

impl VerifiedBlobStreamOpen {
    pub(crate) fn from_provider(
        open: BlobStreamOpen,
        mission_authority_id: NodeId,
        authenticated_bytes: Vec<u8>,
        _seal: BlobStreamProviderSeal,
    ) -> Self {
        Self {
            open,
            mission_authority_id,
            authenticated_bytes,
        }
    }

    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }

    pub(crate) const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    /// Returns the exact provider-authenticated envelope that produced this capability.
    pub fn authenticated_bytes(&self) -> &[u8] {
        &self.authenticated_bytes
    }
}

/// One independently authenticated encrypted stream segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBlobStreamSegment {
    stream_id: BlobPublicationStreamId,
    open_digest: [u8; 32],
    index: u64,
    offset: u64,
    plaintext_len: u32,
    total_len: u64,
    content_epoch: u64,
    previous_ciphertext_commitment: [u8; 32],
    nonce: [u8; GCM_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl EncryptedBlobStreamSegment {
    const FIXED_ENCODED_BYTES: u64 =
        (8 + 2 + 32 + 32 + 8 + 8 + 4 + 4 + 8 + 8 + 32 + GCM_NONCE_BYTES) as u64;

    /// Exact wire length of canonical length-prefixed encrypted records for a
    /// completed stream. This excludes the local pack header.
    pub fn packed_wire_len(total_plaintext: u64, segment_count: u64) -> Option<u64> {
        let per_segment = Self::FIXED_ENCODED_BYTES
            .checked_add(GCM_TAG_BYTES as u64)?
            .checked_add(4)?;
        total_plaintext.checked_add(segment_count.checked_mul(per_segment)?)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = self.aad();
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    /// Verifies that bytes already admitted by the decoder are the canonical
    /// encoding of this segment without allocating another ciphertext-sized
    /// buffer.
    pub fn validate_encoding(&self, encoded: &[u8]) -> Result<(), BlobError> {
        let aad = self.aad();
        let expected_len = aad
            .len()
            .checked_add(self.ciphertext.len())
            .ok_or(BlobError::LengthOverflow)?;
        if encoded.len() != expected_len
            || encoded.get(..aad.len()) != Some(aad.as_slice())
            || encoded.get(aad.len()..) != Some(self.ciphertext.as_slice())
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(())
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        let fixed =
            usize::try_from(Self::FIXED_ENCODED_BYTES).map_err(|_| BlobError::LengthOverflow)?;
        if encoded.len() < fixed + GCM_TAG_BYTES
            || encoded.len() > fixed + BLOB_STREAM_SEGMENT_BYTES + GCM_TAG_BYTES
        {
            return Err(BlobError::InvalidManifest);
        }
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_SEGMENT_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)?;
        let open_digest = reader.array()?;
        let index = reader.u64()?;
        let offset = reader.u64()?;
        let plaintext_len = reader.u32()?;
        let ciphertext_len =
            usize::try_from(reader.u32()?).map_err(|_| BlobError::LengthOverflow)?;
        let total_len = reader.u64()?;
        let content_epoch = reader.u64()?;
        let previous_ciphertext_commitment = reader.array()?;
        let nonce = reader.array()?;
        let expected_offset = index
            .checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64)
            .ok_or(BlobError::LengthOverflow)?;
        let end = offset
            .checked_add(u64::from(plaintext_len))
            .ok_or(BlobError::LengthOverflow)?;
        if open_digest == [0_u8; 32]
            || plaintext_len == 0
            || usize::try_from(plaintext_len).map_err(|_| BlobError::LengthOverflow)?
                > BLOB_STREAM_SEGMENT_BYTES
            || ciphertext_len
                != usize::try_from(plaintext_len).map_err(|_| BlobError::LengthOverflow)?
                    + GCM_TAG_BYTES
            || total_len == 0
            || content_epoch == 0
            || offset != expected_offset
            || end > total_len
            || (end < total_len && plaintext_len as usize != BLOB_STREAM_SEGMENT_BYTES)
            || previous_ciphertext_commitment == [0_u8; 32]
            || nonce == [0_u8; GCM_NONCE_BYTES]
        {
            return Err(BlobError::InvalidManifest);
        }
        let ciphertext = reader.take(ciphertext_len)?.to_vec();
        reader.finish()?;
        Ok(Self {
            stream_id,
            open_digest,
            index,
            offset,
            plaintext_len,
            total_len,
            content_epoch,
            previous_ciphertext_commitment,
            nonce,
            ciphertext,
        })
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(192);
        aad.extend_from_slice(BLOB_STREAM_SEGMENT_MAGIC);
        aad.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        aad.extend_from_slice(self.stream_id.as_bytes());
        aad.extend_from_slice(&self.open_digest);
        aad.extend_from_slice(&self.index.to_be_bytes());
        aad.extend_from_slice(&self.offset.to_be_bytes());
        aad.extend_from_slice(&self.plaintext_len.to_be_bytes());
        aad.extend_from_slice(
            &self
                .plaintext_len
                .checked_add(GCM_TAG_BYTES as u32)
                .expect("segment bound")
                .to_be_bytes(),
        );
        aad.extend_from_slice(&self.total_len.to_be_bytes());
        aad.extend_from_slice(&self.content_epoch.to_be_bytes());
        aad.extend_from_slice(&self.previous_ciphertext_commitment);
        aad.extend_from_slice(&self.nonce);
        aad
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }

    pub const fn plaintext_len(&self) -> u32 {
        self.plaintext_len
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn previous_ciphertext_commitment(&self) -> [u8; 32] {
        self.previous_ciphertext_commitment
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Provider-owned state for ordered independent segment encryption.
pub struct BlobStreamEncryptor {
    open: VerifiedBlobStreamOpen,
    key: Zeroizing<[u8; 32]>,
    base_nonce: Zeroizing<[u8; GCM_NONCE_BYTES]>,
    next_index: u64,
    next_offset: u64,
    ciphertext_accumulator: BlobStreamAccumulator,
}

impl BlobStreamEncryptor {
    pub(crate) fn from_key(
        open: &VerifiedBlobStreamOpen,
        content_grant_seed: [u8; 32],
    ) -> Result<Self, BlobError> {
        let content_grant_seed = Zeroizing::new(content_grant_seed);
        let (key, base_nonce) = derive_stream_key(&content_grant_seed, open.open())?;
        Ok(Self {
            open: open.clone(),
            key: Zeroizing::new(key),
            base_nonce: Zeroizing::new(base_nonce),
            next_index: 0,
            next_offset: 0,
            ciphertext_accumulator: BlobStreamAccumulator::new(
                BlobStreamAccumulatorDomain::Ciphertext,
            ),
        })
    }

    pub(crate) fn from_key_checkpoint(
        open: &VerifiedBlobStreamOpen,
        content_grant_seed: [u8; 32],
        next_offset: u64,
        checkpoint: BlobStreamAccumulatorCheckpoint,
    ) -> Result<Self, BlobError> {
        if checkpoint.domain() != BlobStreamAccumulatorDomain::Ciphertext
            || next_offset > open.open.total_len
        {
            return Err(BlobError::InvalidManifest);
        }
        let mut encryptor = Self::from_key(open, content_grant_seed)?;
        encryptor.next_index = checkpoint.next_index();
        encryptor.next_offset = next_offset;
        encryptor.ciphertext_accumulator = BlobStreamAccumulator::restore(checkpoint)?;
        Ok(encryptor)
    }

    pub fn encrypt_segment(
        &mut self,
        index: u64,
        offset: u64,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<EncryptedBlobStreamSegment, BlobError> {
        if index != self.next_index || offset != self.next_offset {
            return Err(BlobError::InvalidChunkIndex);
        }
        if plaintext.is_empty() || plaintext.len() > BLOB_STREAM_SEGMENT_BYTES {
            return Err(BlobError::InvalidChunkSize);
        }
        let plaintext_len =
            u32::try_from(plaintext.len()).map_err(|_| BlobError::LengthOverflow)?;
        let end = offset
            .checked_add(u64::from(plaintext_len))
            .ok_or(BlobError::LengthOverflow)?;
        if end > self.open.open.total_len
            || (end < self.open.open.total_len && plaintext.len() != BLOB_STREAM_SEGMENT_BYTES)
        {
            return Err(BlobError::InvalidChunkSize);
        }
        let nonce = segment_nonce(&self.base_nonce, index);
        let previous_ciphertext_commitment =
            checkpoint_commitment(&self.ciphertext_accumulator.checkpoint());
        let mut segment = EncryptedBlobStreamSegment {
            stream_id: self.open.open.stream_id,
            open_digest: self.open.open.digest(),
            index,
            offset,
            plaintext_len,
            total_len: self.open.open.total_len,
            content_epoch: self.open.open.content_epoch,
            previous_ciphertext_commitment,
            nonce,
            ciphertext: Vec::new(),
        };
        let mut key_array = Array(*self.key);
        let cipher = Aes256Gcm::new(&key_array);
        key_array.as_mut_slice().zeroize();
        let nonce_array = Array(nonce);
        segment.ciphertext = cipher
            .encrypt(
                &nonce_array,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &segment.aad(),
                },
            )
            .map_err(|_| BlobError::AuthenticationFailed)?;
        self.ciphertext_accumulator
            .push_segment(index, &segment.ciphertext)?;
        self.next_index = index.checked_add(1).ok_or(BlobError::LengthOverflow)?;
        self.next_offset = end;
        Ok(segment)
    }
}

/// Provider-owned state for ordered independent segment authentication.
pub struct BlobStreamDecryptor {
    open: VerifiedBlobStreamOpen,
    key: Zeroizing<[u8; 32]>,
    base_nonce: Zeroizing<[u8; GCM_NONCE_BYTES]>,
    next_index: u64,
    next_offset: u64,
    ciphertext_accumulator: BlobStreamAccumulator,
}

/// Provider-minted proof that one exact segment passed AEAD verification and
/// advanced the ordered ciphertext accumulator to this checkpoint.
#[derive(Debug)]
pub struct AuthenticatedBlobStreamSegmentCheckpoint {
    segment_index: u64,
    ciphertext_len: usize,
    checkpoint: BlobStreamAccumulatorCheckpoint,
}

/// Plaintext and ordered ciphertext checkpoint produced by authenticating one
/// segment in a bounded batch.
pub type AuthenticatedBlobStreamSegment =
    (Zeroizing<Vec<u8>>, AuthenticatedBlobStreamSegmentCheckpoint);

impl AuthenticatedBlobStreamSegmentCheckpoint {
    pub const fn segment_index(&self) -> u64 {
        self.segment_index
    }

    pub const fn ciphertext_len(&self) -> usize {
        self.ciphertext_len
    }

    pub fn into_checkpoint(self) -> BlobStreamAccumulatorCheckpoint {
        self.checkpoint
    }
}

impl BlobStreamDecryptor {
    pub(crate) fn from_key(
        open: &VerifiedBlobStreamOpen,
        content_grant_seed: [u8; 32],
    ) -> Result<Self, BlobError> {
        let content_grant_seed = Zeroizing::new(content_grant_seed);
        let (key, base_nonce) = derive_stream_key(&content_grant_seed, open.open())?;
        Ok(Self {
            open: open.clone(),
            key: Zeroizing::new(key),
            base_nonce: Zeroizing::new(base_nonce),
            next_index: 0,
            next_offset: 0,
            ciphertext_accumulator: BlobStreamAccumulator::new(
                BlobStreamAccumulatorDomain::Ciphertext,
            ),
        })
    }

    pub(crate) fn from_key_checkpoint(
        open: &VerifiedBlobStreamOpen,
        content_grant_seed: [u8; 32],
        next_offset: u64,
        checkpoint: BlobStreamAccumulatorCheckpoint,
    ) -> Result<Self, BlobError> {
        if checkpoint.domain() != BlobStreamAccumulatorDomain::Ciphertext
            || next_offset > open.open.total_len
        {
            return Err(BlobError::InvalidManifest);
        }
        let mut decryptor = Self::from_key(open, content_grant_seed)?;
        decryptor.next_index = checkpoint.next_index();
        decryptor.next_offset = next_offset;
        decryptor.ciphertext_accumulator = BlobStreamAccumulator::restore(checkpoint)?;
        Ok(decryptor)
    }

    pub fn decrypt_segment(
        &mut self,
        segment: &EncryptedBlobStreamSegment,
    ) -> Result<Zeroizing<Vec<u8>>, BlobError> {
        let expected_previous = checkpoint_commitment(&self.ciphertext_accumulator.checkpoint());
        let expected_nonce = segment_nonce(&self.base_nonce, self.next_index);
        if segment.stream_id != self.open.open.stream_id
            || segment.open_digest != self.open.open.digest()
            || segment.index != self.next_index
            || segment.offset != self.next_offset
            || segment.total_len != self.open.open.total_len
            || segment.content_epoch != self.open.open.content_epoch
            || segment.previous_ciphertext_commitment != expected_previous
            || segment.nonce != expected_nonce
            || segment.ciphertext.len() != segment.plaintext_len as usize + GCM_TAG_BYTES
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let end = segment
            .offset
            .checked_add(u64::from(segment.plaintext_len))
            .ok_or(BlobError::LengthOverflow)?;
        if end > self.open.open.total_len
            || (end < self.open.open.total_len
                && segment.plaintext_len as usize != BLOB_STREAM_SEGMENT_BYTES)
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let plaintext = self.decrypt_payload(segment)?;
        self.ciphertext_accumulator
            .push_segment(segment.index, &segment.ciphertext)?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(BlobError::LengthOverflow)?;
        self.next_offset = end;
        Ok(Zeroizing::new(plaintext))
    }

    fn decrypt_payload(&self, segment: &EncryptedBlobStreamSegment) -> Result<Vec<u8>, BlobError> {
        let mut key_array = Array(*self.key);
        let cipher = Aes256Gcm::new(&key_array);
        key_array.as_mut_slice().zeroize();
        let nonce_array = Array(segment.nonce);
        let plaintext = cipher
            .decrypt(
                &nonce_array,
                Payload {
                    msg: &segment.ciphertext,
                    aad: &segment.aad(),
                },
            )
            .map_err(|_| BlobError::AuthenticationFailed)?;
        if plaintext.len() != segment.plaintext_len as usize {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(plaintext)
    }

    /// Decrypts one ordered segment and returns the exact authenticated
    /// ciphertext checkpoint produced by that operation. Internal Store users
    /// can persist this checkpoint without hashing the ciphertext a second
    /// time.
    pub fn decrypt_segment_checkpointed(
        &mut self,
        segment: &EncryptedBlobStreamSegment,
    ) -> Result<(Zeroizing<Vec<u8>>, AuthenticatedBlobStreamSegmentCheckpoint), BlobError> {
        let plaintext = self.decrypt_segment(segment)?;
        Ok((
            plaintext,
            AuthenticatedBlobStreamSegmentCheckpoint {
                segment_index: segment.index,
                ciphertext_len: segment.ciphertext.len(),
                checkpoint: self.ciphertext_accumulator.checkpoint(),
            },
        ))
    }

    /// Decrypts a bounded ordered batch while authenticating independent AEAD
    /// segments concurrently. Ordered ciphertext commitments are prepared on
    /// cloned state, so any failed segment leaves the decryptor retryable.
    pub fn decrypt_segment_batch_checkpointed(
        &mut self,
        segments: &[EncryptedBlobStreamSegment],
    ) -> Result<Vec<AuthenticatedBlobStreamSegment>, BlobError> {
        if segments.len() <= 1 {
            return segments
                .iter()
                .map(|segment| self.decrypt_segment_checkpointed(segment))
                .collect();
        }

        let mut next_index = self.next_index;
        let mut next_offset = self.next_offset;
        for segment in segments {
            let expected_nonce = segment_nonce(&self.base_nonce, next_index);
            if segment.stream_id != self.open.open.stream_id
                || segment.open_digest != self.open.open.digest()
                || segment.index != next_index
                || segment.offset != next_offset
                || segment.total_len != self.open.open.total_len
                || segment.content_epoch != self.open.open.content_epoch
                || segment.nonce != expected_nonce
                || segment.ciphertext.len() != segment.plaintext_len as usize + GCM_TAG_BYTES
            {
                return Err(BlobError::AuthenticationFailed);
            }
            let end = segment
                .offset
                .checked_add(u64::from(segment.plaintext_len))
                .ok_or(BlobError::LengthOverflow)?;
            if end > self.open.open.total_len
                || (end < self.open.open.total_len
                    && segment.plaintext_len as usize != BLOB_STREAM_SEGMENT_BYTES)
            {
                return Err(BlobError::AuthenticationFailed);
            }
            next_index = next_index.checked_add(1).ok_or(BlobError::LengthOverflow)?;
            next_offset = end;
        }

        let authenticated = std::thread::scope(|scope| {
            let workers = std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(segments.len());
            let chunk_size = segments.len().div_ceil(workers);
            let handles = segments
                .chunks(chunk_size)
                .map(|chunk| {
                    scope.spawn(|| {
                        chunk
                            .iter()
                            .map(|segment| {
                                let plaintext = Zeroizing::new(self.decrypt_payload(segment)?);
                                let ciphertext_leaf = accumulator_leaf(
                                    BlobStreamAccumulatorDomain::Ciphertext,
                                    segment.index,
                                    &segment.ciphertext,
                                )?;
                                Ok((plaintext, ciphertext_leaf))
                            })
                            .collect::<Result<Vec<_>, BlobError>>()
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().map_err(|_| BlobError::AuthenticationFailed)?)
                .collect::<Result<Vec<_>, BlobError>>()
                .map(|chunks| chunks.into_iter().flatten().collect::<Vec<_>>())
        })?;

        let mut ciphertext_accumulator = self.ciphertext_accumulator.clone();
        let mut plaintexts = Vec::with_capacity(segments.len());
        let mut checkpoints = Vec::with_capacity(segments.len());
        for (segment, (plaintext, ciphertext_leaf)) in segments.iter().zip(authenticated) {
            let expected_previous = checkpoint_commitment(&ciphertext_accumulator.checkpoint());
            if segment.previous_ciphertext_commitment != expected_previous {
                return Err(BlobError::AuthenticationFailed);
            }
            ciphertext_accumulator.push_prehashed_segment(
                segment.index,
                segment.ciphertext.len(),
                ciphertext_leaf,
            )?;
            plaintexts.push(plaintext);
            checkpoints.push(AuthenticatedBlobStreamSegmentCheckpoint {
                segment_index: segment.index,
                ciphertext_len: segment.ciphertext.len(),
                checkpoint: ciphertext_accumulator.checkpoint(),
            });
        }

        self.ciphertext_accumulator = ciphertext_accumulator;
        self.next_index = next_index;
        self.next_offset = next_offset;
        Ok(plaintexts.into_iter().zip(checkpoints).collect())
    }

    /// Authenticates the complete ordered ciphertext stream against its signed commitment.
    pub fn finish(self, commitment: &VerifiedBlobStreamFinalCommitment) -> Result<(), BlobError> {
        let commitment = commitment.commitment();
        let ciphertext_len = self
            .next_offset
            .checked_add(
                self.next_index
                    .checked_mul(GCM_TAG_BYTES as u64)
                    .ok_or(BlobError::LengthOverflow)?,
            )
            .ok_or(BlobError::LengthOverflow)?;
        let ciphertext_root = self.ciphertext_accumulator.finish(ciphertext_len)?;
        if commitment.open_digest != self.open.open.digest()
            || commitment.stream_id != self.open.open.stream_id
            || commitment.total_len != self.next_offset
            || commitment.segment_count != self.next_index
            || commitment.ciphertext_root != ciphertext_root
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(())
    }
}

/// Publisher-authenticated final binding for one complete stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamFinalCommitment {
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    segment_count: u64,
    plaintext_root: [u8; 32],
    ciphertext_root: [u8; 32],
    blob_id: BlobId,
    metadata_commitment: [u8; 32],
    content_epoch: u64,
    ttl_ms: Option<u64>,
    final_custody: Option<CustodySample>,
}

impl BlobStreamFinalCommitment {
    pub fn new(
        open: &VerifiedBlobStreamOpen,
        plaintext_root: [u8; 32],
        ciphertext_root: [u8; 32],
        segment_count: u64,
        final_custody: Option<CustodySample>,
    ) -> Result<Self, BlobError> {
        let open = open.open();
        let expected_segments = open
            .total_len
            .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
            .ok_or(BlobError::LengthOverflow)?
            / BLOB_STREAM_SEGMENT_BYTES as u64;
        let custody_valid = match (open.ttl_ms, open.initial_custody, final_custody) {
            (None, None, None) => true,
            (Some(_), Some(initial), Some(final_sample)) => {
                initial.clock_id == final_sample.clock_id && final_sample.tick_ms >= initial.tick_ms
            }
            _ => false,
        };
        if plaintext_root == [0_u8; 32]
            || ciphertext_root == [0_u8; 32]
            || segment_count != expected_segments
            || !custody_valid
        {
            return Err(BlobError::InvalidManifest);
        }
        let metadata_commitment = metadata_commitment(&open.metadata);
        let blob_id = derive_stream_blob_id(plaintext_root, open.total_len, metadata_commitment);
        Ok(Self {
            open_digest: open.digest(),
            stream_id: open.stream_id,
            total_len: open.total_len,
            segment_count,
            plaintext_root,
            ciphertext_root,
            blob_id,
            metadata_commitment,
            content_epoch: open.content_epoch,
            ttl_ms: open.ttl_ms,
            final_custody,
        })
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub const fn segment_count(&self) -> u64 {
        self.segment_count
    }

    pub const fn ciphertext_root(&self) -> &[u8; 32] {
        &self.ciphertext_root
    }

    pub const fn plaintext_root(&self) -> &[u8; 32] {
        &self.plaintext_root
    }

    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }

    pub const fn final_custody(&self) -> Option<CustodySample> {
        self.final_custody
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(320);
        encoded.extend_from_slice(BLOB_STREAM_COMMITMENT_MAGIC);
        encoded.extend_from_slice(&BLOB_STREAM_FORMAT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&BLOB_STREAM_PACK_FORMAT_VERSION.to_be_bytes());
        encoded.extend_from_slice(&self.open_digest);
        encoded.extend_from_slice(self.stream_id.as_bytes());
        encoded.extend_from_slice(&self.total_len.to_be_bytes());
        encoded.extend_from_slice(&self.segment_count.to_be_bytes());
        encoded.extend_from_slice(&self.plaintext_root);
        encoded.extend_from_slice(&self.ciphertext_root);
        encoded.extend_from_slice(self.blob_id.as_bytes());
        encoded.extend_from_slice(&self.metadata_commitment);
        encoded.extend_from_slice(&self.content_epoch.to_be_bytes());
        encode_optional_u64(&mut encoded, self.ttl_ms);
        encode_optional_custody(&mut encoded, self.final_custody);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        let mut reader = StreamReader::new(encoded);
        if reader.take(8)? != BLOB_STREAM_COMMITMENT_MAGIC
            || reader.u16()? != BLOB_STREAM_FORMAT_VERSION
            || reader.u16()? != BLOB_STREAM_PACK_FORMAT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let open_digest = reader.array()?;
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)?;
        let total_len = reader.u64()?;
        let segment_count = reader.u64()?;
        let plaintext_root = reader.array()?;
        let ciphertext_root = reader.array()?;
        let blob_id = BlobId::from_bytes(reader.array()?);
        let metadata_commitment = reader.array()?;
        let content_epoch = reader.u64()?;
        let ttl_ms = decode_optional_u64(&mut reader)?;
        let final_custody = decode_optional_custody(&mut reader)?;
        reader.finish()?;
        let expected_segments = total_len
            .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
            .ok_or(BlobError::LengthOverflow)?
            / BLOB_STREAM_SEGMENT_BYTES as u64;
        if total_len == 0
            || segment_count != expected_segments
            || open_digest == [0_u8; 32]
            || plaintext_root == [0_u8; 32]
            || ciphertext_root == [0_u8; 32]
            || content_epoch == 0
            || ttl_ms == Some(0)
            || ttl_ms.is_some() != final_custody.is_some()
            || blob_id != derive_stream_blob_id(plaintext_root, total_len, metadata_commitment)
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            open_digest,
            stream_id,
            total_len,
            segment_count,
            plaintext_root,
            ciphertext_root,
            blob_id,
            metadata_commitment,
            content_epoch,
            ttl_ms,
            final_custody,
        })
    }
}

/// Provider-authenticated final commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamFinalCommitment {
    commitment: BlobStreamFinalCommitment,
    authenticated_bytes: Vec<u8>,
}

impl VerifiedBlobStreamFinalCommitment {
    pub(crate) fn from_provider(
        commitment: BlobStreamFinalCommitment,
        authenticated_bytes: Vec<u8>,
        _seal: BlobStreamProviderSeal,
    ) -> Self {
        Self {
            commitment,
            authenticated_bytes,
        }
    }

    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }

    /// Returns the exact provider-authenticated envelope that produced this capability.
    pub fn authenticated_bytes(&self) -> &[u8] {
        &self.authenticated_bytes
    }
}

const ACCUMULATOR_LEVELS: usize = u64::BITS as usize;
const ACCUMULATOR_CHECKPOINT_MAGIC: &[u8; 8] = b"ASTRBA01";
const ACCUMULATOR_CHECKPOINT_VERSION: u16 = 1;
const ACCUMULATOR_CHECKPOINT_ENCODED_LEN: usize =
    8 + 2 + 1 + 1 + 8 + 8 + 8 + ACCUMULATOR_LEVELS * 32;
const ACCUMULATOR_LEAF_DOMAIN: &[u8] = b"aster/blob-stream/merkle-leaf/v1";
const ACCUMULATOR_NODE_DOMAIN: &[u8] = b"aster/blob-stream/merkle-node/v1";
const ACCUMULATOR_EMPTY_DOMAIN: &[u8] = b"aster/blob-stream/merkle-empty/v1";
const ACCUMULATOR_FINAL_DOMAIN: &[u8] = b"aster/blob-stream/merkle-final/v1";

/// Independent identity trees maintained by the streaming format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlobStreamAccumulatorDomain {
    Plaintext = 1,
    Ciphertext = 2,
}

impl BlobStreamAccumulatorDomain {
    fn decode(value: u8) -> Result<Self, BlobError> {
        match value {
            1 => Ok(Self::Plaintext),
            2 => Ok(Self::Ciphertext),
            _ => Err(BlobError::InvalidManifest),
        }
    }

    const fn maximum_record_len(self) -> usize {
        match self {
            Self::Plaintext => BLOB_STREAM_SEGMENT_BYTES,
            Self::Ciphertext => BLOB_STREAM_SEGMENT_BYTES + 16,
        }
    }
}

/// Fixed-width durable state for an incremental stream identity tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamAccumulatorCheckpoint {
    domain: BlobStreamAccumulatorDomain,
    saw_short_record: bool,
    next_index: u64,
    total_len: u64,
    occupied: u64,
    frontier: [[u8; 32]; ACCUMULATOR_LEVELS],
}

impl BlobStreamAccumulatorCheckpoint {
    pub const fn domain(&self) -> BlobStreamAccumulatorDomain {
        self.domain
    }

    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Stable commitment carried by profile-5 resume/checkpoint records.
    pub fn commitment(&self) -> [u8; 32] {
        checkpoint_commitment(self)
    }

    /// Encodes a constant-sized checkpoint independent of Blob length.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(ACCUMULATOR_CHECKPOINT_ENCODED_LEN);
        encoded.extend_from_slice(ACCUMULATOR_CHECKPOINT_MAGIC);
        encoded.extend_from_slice(&ACCUMULATOR_CHECKPOINT_VERSION.to_be_bytes());
        encoded.push(self.domain as u8);
        encoded.push(u8::from(self.saw_short_record));
        encoded.extend_from_slice(&self.next_index.to_be_bytes());
        encoded.extend_from_slice(&self.total_len.to_be_bytes());
        encoded.extend_from_slice(&self.occupied.to_be_bytes());
        for hash in self.frontier {
            encoded.extend_from_slice(&hash);
        }
        debug_assert_eq!(encoded.len(), ACCUMULATOR_CHECKPOINT_ENCODED_LEN);
        encoded
    }

    /// Decodes and structurally validates one canonical checkpoint.
    pub fn decode(encoded: &[u8]) -> Result<Self, BlobError> {
        if encoded.len() != ACCUMULATOR_CHECKPOINT_ENCODED_LEN
            || &encoded[..8] != ACCUMULATOR_CHECKPOINT_MAGIC
            || u16::from_be_bytes([encoded[8], encoded[9]]) != ACCUMULATOR_CHECKPOINT_VERSION
        {
            return Err(BlobError::InvalidManifest);
        }
        let domain = BlobStreamAccumulatorDomain::decode(encoded[10])?;
        let saw_short_record = match encoded[11] {
            0 => false,
            1 => true,
            _ => return Err(BlobError::InvalidManifest),
        };
        let next_index = u64::from_be_bytes(
            encoded[12..20]
                .try_into()
                .map_err(|_| BlobError::InvalidManifest)?,
        );
        let total_len = u64::from_be_bytes(
            encoded[20..28]
                .try_into()
                .map_err(|_| BlobError::InvalidManifest)?,
        );
        let occupied = u64::from_be_bytes(
            encoded[28..36]
                .try_into()
                .map_err(|_| BlobError::InvalidManifest)?,
        );
        let mut frontier = [[0_u8; 32]; ACCUMULATOR_LEVELS];
        for (level, hash) in frontier.iter_mut().enumerate() {
            let start = 36 + level * 32;
            hash.copy_from_slice(&encoded[start..start + 32]);
        }
        let checkpoint = Self {
            domain,
            saw_short_record,
            next_index,
            total_len,
            occupied,
            frontier,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn validate(&self) -> Result<(), BlobError> {
        if self.occupied != self.next_index {
            return Err(BlobError::InvalidManifest);
        }
        for (level, hash) in self.frontier.iter().enumerate() {
            let populated = self.occupied & (1_u64 << level) != 0;
            if populated == (*hash == [0_u8; 32]) {
                return Err(BlobError::InvalidManifest);
            }
        }

        let maximum = u64::try_from(self.domain.maximum_record_len())
            .map_err(|_| BlobError::LengthOverflow)?;
        let full_len = self
            .next_index
            .checked_mul(maximum)
            .ok_or(BlobError::LengthOverflow)?;
        if self.next_index == 0 {
            if self.total_len != 0 || self.saw_short_record {
                return Err(BlobError::InvalidManifest);
            }
        } else if self.saw_short_record {
            let minimum = self
                .next_index
                .checked_sub(1)
                .and_then(|count| count.checked_mul(maximum))
                .and_then(|bytes| bytes.checked_add(1))
                .ok_or(BlobError::LengthOverflow)?;
            if self.total_len < minimum || self.total_len >= full_len {
                return Err(BlobError::InvalidManifest);
            }
        } else if self.total_len != full_len {
            return Err(BlobError::InvalidManifest);
        }
        Ok(())
    }
}

/// Incremental Merkle frontier whose durable representation is fixed width.
#[derive(Clone, Debug)]
pub struct BlobStreamAccumulator {
    domain: BlobStreamAccumulatorDomain,
    saw_short_record: bool,
    next_index: u64,
    total_len: u64,
    occupied: u64,
    frontier: [[u8; 32]; ACCUMULATOR_LEVELS],
}

impl BlobStreamAccumulator {
    pub fn new(domain: BlobStreamAccumulatorDomain) -> Self {
        Self {
            domain,
            saw_short_record: false,
            next_index: 0,
            total_len: 0,
            occupied: 0,
            frontier: [[0_u8; 32]; ACCUMULATOR_LEVELS],
        }
    }

    pub fn push_segment(&mut self, index: u64, bytes: &[u8]) -> Result<(), BlobError> {
        let hash = accumulator_leaf(self.domain, index, bytes)?;
        self.push_prehashed_segment(index, bytes.len(), hash)
    }

    fn push_prehashed_segment(
        &mut self,
        index: u64,
        record_len: usize,
        mut hash: [u8; 32],
    ) -> Result<(), BlobError> {
        if index != self.next_index {
            return Err(BlobError::InvalidChunkIndex);
        }
        let maximum = self.domain.maximum_record_len();
        if record_len == 0 || record_len > maximum || self.saw_short_record {
            return Err(BlobError::InvalidChunkSize);
        }
        let next_index = self
            .next_index
            .checked_add(1)
            .ok_or(BlobError::LengthOverflow)?;
        let next_total = self
            .total_len
            .checked_add(u64::try_from(record_len).map_err(|_| BlobError::LengthOverflow)?)
            .ok_or(BlobError::LengthOverflow)?;

        let mut level = 0_usize;
        while self.occupied & (1_u64 << level) != 0 {
            hash = accumulator_node(self.domain, &self.frontier[level], &hash);
            self.frontier[level] = [0_u8; 32];
            level = level.checked_add(1).ok_or(BlobError::LengthOverflow)?;
            if level == ACCUMULATOR_LEVELS {
                return Err(BlobError::LengthOverflow);
            }
        }
        self.frontier[level] = hash;
        self.next_index = next_index;
        self.total_len = next_total;
        self.occupied = next_index;
        self.saw_short_record = record_len < maximum;
        Ok(())
    }

    pub fn checkpoint(&self) -> BlobStreamAccumulatorCheckpoint {
        BlobStreamAccumulatorCheckpoint {
            domain: self.domain,
            saw_short_record: self.saw_short_record,
            next_index: self.next_index,
            total_len: self.total_len,
            occupied: self.occupied,
            frontier: self.frontier,
        }
    }

    pub fn restore(checkpoint: BlobStreamAccumulatorCheckpoint) -> Result<Self, BlobError> {
        checkpoint.validate()?;
        Ok(Self {
            domain: checkpoint.domain,
            saw_short_record: checkpoint.saw_short_record,
            next_index: checkpoint.next_index,
            total_len: checkpoint.total_len,
            occupied: checkpoint.occupied,
            frontier: checkpoint.frontier,
        })
    }

    pub fn finish(self, total_len: u64) -> Result<[u8; 32], BlobError> {
        if total_len != self.total_len {
            return Err(BlobError::LengthOverflow);
        }
        let mut root = None;
        for level in (0..ACCUMULATOR_LEVELS).rev() {
            if self.occupied & (1_u64 << level) != 0 {
                root = Some(match root {
                    None => self.frontier[level],
                    Some(right) => accumulator_node(self.domain, &self.frontier[level], &right),
                });
            }
        }
        let merkle_root = root.unwrap_or_else(|| accumulator_empty(self.domain));
        let mut finalizer = Sha256::new();
        finalizer.update(ACCUMULATOR_FINAL_DOMAIN);
        finalizer.update([self.domain as u8]);
        finalizer.update(total_len.to_be_bytes());
        finalizer.update(self.next_index.to_be_bytes());
        finalizer.update(merkle_root);
        Ok(finalizer.finalize().into())
    }
}

fn accumulator_leaf(
    domain: BlobStreamAccumulatorDomain,
    index: u64,
    bytes: &[u8],
) -> Result<[u8; 32], BlobError> {
    let mut hasher = Sha256::new();
    hasher.update(ACCUMULATOR_LEAF_DOMAIN);
    hasher.update([domain as u8]);
    hasher.update(index.to_be_bytes());
    hasher.update(
        u32::try_from(bytes.len())
            .map_err(|_| BlobError::LengthOverflow)?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn accumulator_node(
    domain: BlobStreamAccumulatorDomain,
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCUMULATOR_NODE_DOMAIN);
    hasher.update([domain as u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn accumulator_empty(domain: BlobStreamAccumulatorDomain) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCUMULATOR_EMPTY_DOMAIN);
    hasher.update([domain as u8]);
    hasher.finalize().into()
}

fn checkpoint_commitment(checkpoint: &BlobStreamAccumulatorCheckpoint) -> [u8; 32] {
    hash_parts(b"aster/blob-stream/checkpoint/v1", &[&checkpoint.encode()])
}

fn derive_stream_key(
    content_grant_seed: &[u8; 32],
    open: &BlobStreamOpen,
) -> Result<([u8; 32], [u8; GCM_NONCE_BYTES]), BlobError> {
    let mut salt = Vec::with_capacity(BLOB_STREAM_KEY_SALT.len() + open.publication_salt.len());
    salt.extend_from_slice(BLOB_STREAM_KEY_SALT);
    salt.extend_from_slice(&open.publication_salt);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), content_grant_seed);
    let open_digest = open.digest();
    let mut key = [0_u8; 32];
    let mut key_info = Vec::with_capacity(BLOB_STREAM_KEY_INFO.len() + open_digest.len());
    key_info.extend_from_slice(BLOB_STREAM_KEY_INFO);
    key_info.extend_from_slice(&open_digest);
    hkdf.expand(&key_info, &mut key)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    let mut base_nonce = [0_u8; GCM_NONCE_BYTES];
    let mut nonce_info = Vec::with_capacity(BLOB_STREAM_NONCE_INFO.len() + open_digest.len());
    nonce_info.extend_from_slice(BLOB_STREAM_NONCE_INFO);
    nonce_info.extend_from_slice(&open_digest);
    hkdf.expand(&nonce_info, &mut base_nonce)
        .map_err(|_| BlobError::AuthenticationFailed)?;
    Ok((key, base_nonce))
}

fn segment_nonce(base_nonce: &[u8; GCM_NONCE_BYTES], index: u64) -> [u8; GCM_NONCE_BYTES] {
    let mut nonce = *base_nonce;
    let encoded_index = index.to_be_bytes();
    for (target, source) in nonce[4..].iter_mut().zip(encoded_index) {
        *target ^= source;
    }
    nonce
}

fn metadata_commitment(metadata: &BlobMetadata) -> [u8; 32] {
    let mut encoded = Vec::new();
    encode_metadata(&mut encoded, metadata).expect("validated metadata");
    hash_parts(BLOB_STREAM_METADATA_DOMAIN, &[&encoded])
}

fn derive_stream_blob_id(
    plaintext_root: [u8; 32],
    total_len: u64,
    metadata_commitment: [u8; 32],
) -> BlobId {
    derive_stream_blob_id_for_format(
        BLOB_STREAM_FORMAT_VERSION,
        plaintext_root,
        total_len,
        metadata_commitment,
    )
}

fn derive_stream_blob_id_for_format(
    format_version: u16,
    plaintext_root: [u8; 32],
    total_len: u64,
    metadata_commitment: [u8; 32],
) -> BlobId {
    BlobId::from_bytes(hash_parts(
        BLOB_STREAM_ID_DOMAIN,
        &[
            &format_version.to_be_bytes(),
            &total_len.to_be_bytes(),
            &plaintext_root,
            &metadata_commitment,
        ],
    ))
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn push_u16_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), BlobError> {
    let len = u16::try_from(bytes.len()).map_err(|_| BlobError::LengthOverflow)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_metadata(output: &mut Vec<u8>, metadata: &BlobMetadata) -> Result<(), BlobError> {
    match metadata.media_type() {
        None => output.push(0),
        Some(media_type) => {
            output.push(1);
            push_u16_bytes(output, media_type.as_bytes())?;
        }
    }
    push_u16_bytes(output, metadata.schema_id())
}

fn decode_metadata(reader: &mut StreamReader<'_>) -> Result<BlobMetadata, BlobError> {
    let media_type = match reader.u8()? {
        0 => None,
        1 => Some(reader.u16_string(crate::MAX_BLOB_MEDIA_TYPE_BYTES)?),
        _ => return Err(BlobError::InvalidMetadata),
    };
    let schema_id = reader.u16_bytes(crate::MAX_BLOB_SCHEMA_ID_BYTES)?.to_vec();
    BlobMetadata::new(media_type, schema_id)
}

fn encode_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_optional_u64(reader: &mut StreamReader<'_>) -> Result<Option<u64>, BlobError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.u64()?)),
        _ => Err(BlobError::InvalidManifest),
    }
}

fn encode_optional_custody(output: &mut Vec<u8>, value: Option<CustodySample>) {
    match value {
        None => output.push(0),
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.clock_id);
            output.extend_from_slice(&value.tick_ms.to_be_bytes());
        }
    }
}

fn decode_optional_custody(
    reader: &mut StreamReader<'_>,
) -> Result<Option<CustodySample>, BlobError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(CustodySample {
            clock_id: reader.array()?,
            tick_ms: reader.u64()?,
        })),
        _ => Err(BlobError::InvalidManifest),
    }
}

struct StreamReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> StreamReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BlobError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(BlobError::LengthOverflow)?;
        let output = self
            .bytes
            .get(self.position..end)
            .ok_or(BlobError::InvalidManifest)?;
        self.position = end;
        Ok(output)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BlobError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BlobError::InvalidManifest)
    }

    fn u8(&mut self) -> Result<u8, BlobError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BlobError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, BlobError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, BlobError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u16_bytes(&mut self, maximum: usize) -> Result<&'a [u8], BlobError> {
        let len = usize::from(self.u16()?);
        if len > maximum {
            return Err(BlobError::InvalidManifest);
        }
        self.take(len)
    }

    fn u16_string(&mut self, maximum: usize) -> Result<String, BlobError> {
        let bytes = self.u16_bytes(maximum)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| BlobError::InvalidManifest)
    }

    fn finish(self) -> Result<(), BlobError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(BlobError::InvalidManifest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BLOB_STREAM_FORMAT_VERSION, BLOB_STREAM_SEGMENT_BYTES, BlobPublicationStreamId,
        BlobStreamAccumulator, BlobStreamAccumulatorCheckpoint, BlobStreamAccumulatorDomain,
        BlobStreamDecryptor, BlobStreamEncryptor, BlobStreamFinalCommitment, BlobStreamOpen,
        VerifiedBlobStreamOpen, derive_stream_blob_id_for_format,
    };
    use crate::{
        BlobError, BlobMetadata, CustodySample, Dot, Priority, Scope, Topic, VersionVector,
    };
    use zeroize::Zeroizing;

    fn digest(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut output = [0_u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("literal hex");
        }
        output
    }

    fn open_with_metadata(media_type: Option<&str>, schema_id: &[u8]) -> VerifiedBlobStreamOpen {
        let open = BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream ID"),
            [0x22; 32],
            b"operation-1".to_vec(),
            [0x33; 32],
            7,
            VersionVector::default(),
            Topic::new("imagery").expect("topic"),
            Scope::new("alpha/team").expect("scope"),
            BlobMetadata::new(media_type.map(str::to_owned), schema_id.to_vec()).expect("metadata"),
            Priority::Immediate,
            Some(60_000),
            Some(CustodySample {
                clock_id: [0x44; 16],
                tick_ms: 9,
            }),
            BLOB_STREAM_SEGMENT_BYTES as u64 + 4,
            3,
            5,
            [0x55; 32],
            [0x66; 32],
        )
        .expect("open");
        VerifiedBlobStreamOpen {
            mission_authority_id: *open.mission_id(),
            open,
            authenticated_bytes: vec![1],
        }
    }

    #[test]
    fn blob_stream_accumulator_matches_one_shot_root() {
        let cases: Vec<(Vec<Vec<u8>>, &str)> = vec![
            (
                vec![],
                "a1ff379d6de0d1438955314af89b65b51bec76984075275dad0ae58aca812fb3",
            ),
            (
                vec![b"x".to_vec()],
                "67d3f1c078bcea6a249fd3cbdf3697bd8f7bf02238d101ce388a88a4dbd10ea0",
            ),
            (
                vec![vec![0_u8; BLOB_STREAM_SEGMENT_BYTES]],
                "de36573424a996db0c21f9bbc6f8b4e9fcfac1fcc33c7480ee2b8b00230414f1",
            ),
            (
                vec![vec![0_u8; BLOB_STREAM_SEGMENT_BYTES], b"x".to_vec()],
                "90918ec2d2b58ab3eefb4a86ea0107c710f53020f2c31fe33848a5d002e9708f",
            ),
        ];

        for (segments, expected) in cases {
            let mut accumulator =
                BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
            let mut total_len = 0_u64;
            for (index, segment) in segments.iter().enumerate() {
                accumulator
                    .push_segment(index as u64, segment)
                    .expect("valid segment");
                total_len += segment.len() as u64;
            }
            assert_eq!(
                accumulator.finish(total_len).expect("final root"),
                digest(expected)
            );
        }
    }

    #[test]
    fn blob_stream_accumulator_restores_fixed_width_checkpoint() {
        let empty = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        let empty_checkpoint = empty.checkpoint();

        let mut partial = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        partial
            .push_segment(0, &vec![0x41; BLOB_STREAM_SEGMENT_BYTES])
            .expect("first segment");
        let populated_checkpoint = partial.checkpoint();

        assert_eq!(
            empty_checkpoint.encode().len(),
            populated_checkpoint.encode().len()
        );
        assert_eq!(
            BlobStreamAccumulatorCheckpoint::decode(&populated_checkpoint.encode())
                .expect("canonical checkpoint"),
            populated_checkpoint
        );

        let mut restored = BlobStreamAccumulator::restore(populated_checkpoint).expect("restore");
        restored.push_segment(1, b"tail").expect("tail segment");

        let mut uninterrupted = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        uninterrupted
            .push_segment(0, &vec![0x41; BLOB_STREAM_SEGMENT_BYTES])
            .expect("first segment");
        uninterrupted
            .push_segment(1, b"tail")
            .expect("tail segment");

        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 + 4;
        assert_eq!(
            restored.finish(total_len).expect("restored root"),
            uninterrupted.finish(total_len).expect("one-shot root")
        );
    }

    #[test]
    fn blob_stream_accumulator_rejects_gap_duplicate_and_length_overflow() {
        let mut gaps = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        assert!(matches!(
            gaps.push_segment(1, b"gap"),
            Err(BlobError::InvalidChunkIndex)
        ));
        gaps.push_segment(0, b"final").expect("first segment");
        assert!(matches!(
            gaps.push_segment(0, b"duplicate"),
            Err(BlobError::InvalidChunkIndex)
        ));
        assert!(matches!(
            gaps.push_segment(1, b"after-short"),
            Err(BlobError::InvalidChunkSize)
        ));

        let mut oversized = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        assert!(matches!(
            oversized.push_segment(0, &vec![0_u8; BLOB_STREAM_SEGMENT_BYTES + 1]),
            Err(BlobError::InvalidChunkSize)
        ));

        let mut wrong_length = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        wrong_length.push_segment(0, b"x").expect("segment");
        assert!(matches!(
            wrong_length.finish(u64::MAX),
            Err(BlobError::LengthOverflow)
        ));
    }

    #[test]
    fn blob_stream_segment_round_trips_with_independent_aead() {
        let open = open_with_metadata(Some("image/tiff"), b"schema-a");
        let mut encryptor = BlobStreamEncryptor::from_key(&open, [0x77; 32]).expect("encryptor");
        let mut decryptor = BlobStreamDecryptor::from_key(&open, [0x77; 32]).expect("decryptor");

        let first_plaintext = Zeroizing::new(vec![0x81; BLOB_STREAM_SEGMENT_BYTES]);
        let first = encryptor
            .encrypt_segment(0, 0, first_plaintext)
            .expect("first encrypted segment");
        let tail = encryptor
            .encrypt_segment(
                1,
                BLOB_STREAM_SEGMENT_BYTES as u64,
                Zeroizing::new(b"tail".to_vec()),
            )
            .expect("tail encrypted segment");

        assert_eq!(
            super::EncryptedBlobStreamSegment::decode(&first.encode()).expect("decode segment"),
            first
        );
        let mut zero_epoch = first.encode();
        zero_epoch[106..114].fill(0);
        assert!(super::EncryptedBlobStreamSegment::decode(&zero_epoch).is_err());

        assert_eq!(
            decryptor
                .decrypt_segment(&first)
                .expect("first plaintext")
                .as_slice(),
            vec![0x81; BLOB_STREAM_SEGMENT_BYTES]
        );
        assert_eq!(
            decryptor
                .decrypt_segment(&tail)
                .expect("tail plaintext")
                .as_slice(),
            b"tail"
        );

        let mut tampered = tail.clone();
        tampered.ciphertext[0] ^= 0x80;
        let mut fresh = BlobStreamDecryptor::from_key(&open, [0x77; 32]).expect("decryptor");
        fresh.decrypt_segment(&first).expect("first plaintext");
        assert!(matches!(
            fresh.decrypt_segment(&tampered),
            Err(BlobError::AuthenticationFailed)
        ));
    }

    #[test]
    fn blob_stream_segment_batch_matches_sequential_and_is_failure_atomic() {
        let open = open_with_metadata(Some("image/tiff"), b"schema-a");
        let mut encryptor = BlobStreamEncryptor::from_key(&open, [0x77; 32]).expect("encryptor");
        let first = encryptor
            .encrypt_segment(0, 0, Zeroizing::new(vec![0x81; BLOB_STREAM_SEGMENT_BYTES]))
            .expect("first encrypted segment");
        let tail = encryptor
            .encrypt_segment(
                1,
                BLOB_STREAM_SEGMENT_BYTES as u64,
                Zeroizing::new(b"tail".to_vec()),
            )
            .expect("tail encrypted segment");
        let segments = [first, tail];

        let mut sequential =
            BlobStreamDecryptor::from_key(&open, [0x77; 32]).expect("sequential decryptor");
        let expected = segments
            .iter()
            .map(|segment| {
                sequential
                    .decrypt_segment_checkpointed(segment)
                    .expect("sequential segment")
            })
            .collect::<Vec<_>>();

        let mut batched =
            BlobStreamDecryptor::from_key(&open, [0x77; 32]).expect("batch decryptor");
        let actual = batched
            .decrypt_segment_batch_checkpointed(&segments)
            .expect("authenticated batch");
        assert_eq!(actual.len(), expected.len());
        for ((actual_plaintext, actual_checkpoint), (expected_plaintext, expected_checkpoint)) in
            actual.iter().zip(&expected)
        {
            assert_eq!(actual_plaintext.as_slice(), expected_plaintext.as_slice());
            assert_eq!(
                actual_checkpoint.segment_index,
                expected_checkpoint.segment_index
            );
            assert_eq!(
                actual_checkpoint.ciphertext_len,
                expected_checkpoint.ciphertext_len
            );
            assert_eq!(actual_checkpoint.checkpoint, expected_checkpoint.checkpoint);
        }

        let mut tampered = segments.clone();
        tampered[1].ciphertext[0] ^= 0x80;
        let mut retryable =
            BlobStreamDecryptor::from_key(&open, [0x77; 32]).expect("retryable decryptor");
        assert!(matches!(
            retryable.decrypt_segment_batch_checkpointed(&tampered),
            Err(BlobError::AuthenticationFailed)
        ));
        let retried = retryable
            .decrypt_segment_batch_checkpointed(&segments)
            .expect("valid retry after failed batch");
        assert_eq!(retried.len(), 2);
        assert_eq!(
            retried[0].0.as_slice(),
            vec![0x81; BLOB_STREAM_SEGMENT_BYTES]
        );
        assert_eq!(retried[1].0.as_slice(), b"tail");
    }

    #[test]
    fn blob_stream_segment_rejects_wrong_open_offset_index_nonce_and_epoch() {
        let open = open_with_metadata(Some("image/tiff"), b"schema-a");
        let mut encryptor = BlobStreamEncryptor::from_key(&open, [0x77; 32]).expect("encryptor");
        let segment = encryptor
            .encrypt_segment(0, 0, Zeroizing::new(vec![0x73; BLOB_STREAM_SEGMENT_BYTES]))
            .expect("segment");

        let mut wrong_open = open.clone();
        wrong_open.open.publication_salt[0] ^= 1;
        let mut wrong_open_decryptor =
            BlobStreamDecryptor::from_key(&wrong_open, [0x77; 32]).expect("decryptor");
        assert!(matches!(
            wrong_open_decryptor.decrypt_segment(&segment),
            Err(BlobError::AuthenticationFailed)
        ));

        for mutation in ["offset", "index", "nonce", "epoch"] {
            let mut changed = segment.clone();
            match mutation {
                "offset" => changed.offset = 1,
                "index" => changed.index = 1,
                "nonce" => changed.nonce[0] ^= 1,
                "epoch" => changed.content_epoch += 1,
                _ => unreachable!(),
            }
            let mut decryptor =
                BlobStreamDecryptor::from_key(&open, [0x77; 32]).expect("decryptor");
            assert!(
                decryptor.decrypt_segment(&changed).is_err(),
                "accepted {mutation}"
            );
        }
    }

    #[test]
    fn blob_stream_final_commitment_binds_both_roots_and_metadata() {
        let base = open_with_metadata(Some("image/tiff"), b"schema-a");
        assert_eq!(
            BlobStreamOpen::decode(&base.open.encode()).expect("decode open"),
            base.open
        );
        let base_open_digest = base.open.digest();
        macro_rules! assert_open_field_bound {
            ($mutation:expr) => {{
                let mut changed = base.open.clone();
                $mutation(&mut changed);
                assert_ne!(changed.digest(), base_open_digest);
            }};
        }
        assert_open_field_bound!(
            |open: &mut BlobStreamOpen| open.stream_id = BlobPublicationStreamId([0x12; 32])
        );
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.publisher[0] ^= 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.operation_key.push(1));
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.mission_id[0] ^= 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.publisher_counter += 1);
        assert_open_field_bound!(
            |open: &mut BlobStreamOpen| open.causal_context.observe(Dot {
                publisher: [0x77; 32],
                counter: 4,
            })
        );
        assert_open_field_bound!(
            |open: &mut BlobStreamOpen| open.topic = Topic::new("other").expect("topic")
        );
        assert_open_field_bound!(
            |open: &mut BlobStreamOpen| open.scope = Scope::new("other").expect("scope")
        );
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.metadata =
            BlobMetadata::new(Some("other/type".into()), b"schema-a".to_vec()).expect("metadata"));
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.priority = Priority::Flash);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.ttl_ms = Some(60_001));
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open
            .initial_custody
            .as_mut()
            .expect("custody")
            .tick_ms += 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.total_len += 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.content_epoch += 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.policy_revision += 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.authorization_digest[0] ^= 1);
        assert_open_field_bound!(|open: &mut BlobStreamOpen| open.publication_salt[0] ^= 1);

        let base_commitment = BlobStreamFinalCommitment::new(
            &base,
            [0x91; 32],
            [0x92; 32],
            2,
            Some(CustodySample {
                clock_id: [0x44; 16],
                tick_ms: 10,
            }),
        )
        .expect("commitment");
        assert_eq!(
            BlobStreamFinalCommitment::decode(&base_commitment.encode()).expect("decode"),
            base_commitment
        );
        let mut wrong_segment_count = base_commitment.encode();
        wrong_segment_count[84..92].copy_from_slice(&3_u64.to_be_bytes());
        assert!(BlobStreamFinalCommitment::decode(&wrong_segment_count).is_err());

        let changed_plaintext = BlobStreamFinalCommitment::new(
            &base,
            [0x93; 32],
            [0x92; 32],
            2,
            Some(CustodySample {
                clock_id: [0x44; 16],
                tick_ms: 10,
            }),
        )
        .expect("commitment");
        let changed_ciphertext = BlobStreamFinalCommitment::new(
            &base,
            [0x91; 32],
            [0x94; 32],
            2,
            Some(CustodySample {
                clock_id: [0x44; 16],
                tick_ms: 10,
            }),
        )
        .expect("commitment");
        let changed_media = BlobStreamFinalCommitment::new(
            &open_with_metadata(Some("application/octet-stream"), b"schema-a"),
            [0x91; 32],
            [0x92; 32],
            2,
            Some(CustodySample {
                clock_id: [0x44; 16],
                tick_ms: 10,
            }),
        )
        .expect("commitment");
        let changed_schema = BlobStreamFinalCommitment::new(
            &open_with_metadata(Some("image/tiff"), b"schema-b"),
            [0x91; 32],
            [0x92; 32],
            2,
            Some(CustodySample {
                clock_id: [0x44; 16],
                tick_ms: 10,
            }),
        )
        .expect("commitment");

        for changed in [changed_plaintext, changed_media, changed_schema] {
            assert_ne!(changed.blob_id(), base_commitment.blob_id());
        }
        assert_eq!(changed_ciphertext.blob_id(), base_commitment.blob_id());
        assert_ne!(changed_ciphertext, base_commitment);
        assert_ne!(
            derive_stream_blob_id_for_format(
                BLOB_STREAM_FORMAT_VERSION,
                [0x91; 32],
                base.open.total_len + 1,
                base_commitment.metadata_commitment,
            ),
            base_commitment.blob_id()
        );
        assert_ne!(
            derive_stream_blob_id_for_format(
                BLOB_STREAM_FORMAT_VERSION + 1,
                [0x91; 32],
                base.open.total_len,
                base_commitment.metadata_commitment,
            ),
            base_commitment.blob_id()
        );
    }
}
