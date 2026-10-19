//! Append-only encrypted Blob stream packs and crash-safe checkpoint authority.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use aster_mesh::{
    BlobPublicationStreamId, BlobStreamAccumulator, BlobStreamAccumulatorCheckpoint,
    BlobStreamAccumulatorDomain, EncryptedBlobStreamSegment, VerifiedBlobStreamFinalCommitment,
    VerifiedBlobStreamOpen,
};
use sha2::{Digest, Sha256};

use super::depot::{OwnedDirectory, open_blob_pack_root};
use super::{BlobStoreError, blob_error};
use crate::{Store, StoreError};

const PACK_MAGIC: &[u8; 8] = b"ASTRPK01";
const PACK_VERSION: u16 = 1;
pub(super) const PACK_HEADER_LEN: u64 = 82;
const PACK_FILE: &str = "segments.pack";
const JOURNAL_ZERO: &str = "checkpoint.0";
const JOURNAL_ONE: &str = "checkpoint.1";
const COMPLETION_FILE: &str = "completion";
const CHECKPOINT_MAGIC: &[u8; 8] = b"ASTRCP01";
const COMPLETION_MAGIC: &[u8; 8] = b"ASTRCM01";
const ACCUMULATOR_CHECKPOINT_LEN: usize = 8 + 2 + 1 + 1 + 8 + 8 + 8 + 64 * 32;
const MAX_SEGMENT_RECORD_LEN: usize = 2 * 1024 * 1024;
const BACKGROUND_WRITEBACK_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) struct PinnedBlobPackRoot {
    directory: OwnedDirectory,
}

impl PinnedBlobPackRoot {
    pub(crate) fn open(store: &Store) -> Result<Self, StoreError> {
        Ok(Self {
            directory: open_blob_pack_root(store, true)?,
        })
    }

    pub(crate) fn open_existing(store: &Store) -> Result<Self, StoreError> {
        Ok(Self {
            directory: open_blob_pack_root(store, false)?,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlobPackCheckpoint {
    generation: u64,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    plaintext_offset: u64,
    pack_len: u64,
    plaintext: BlobStreamAccumulatorCheckpoint,
    ciphertext: BlobStreamAccumulatorCheckpoint,
}

impl BlobPackCheckpoint {
    pub(crate) const ENCODED_LEN: usize =
        8 + 2 + 8 + 32 + 32 + 8 + 8 + 8 + 8 + 4 + 2 * ACCUMULATOR_CHECKPOINT_LEN + 32;

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn next_index(&self) -> u64 {
        self.next_index
    }

    pub(crate) const fn pack_len(&self) -> u64 {
        self.pack_len
    }

    pub(super) const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub(super) const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub(super) const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub(super) const fn plaintext_offset(&self) -> u64 {
        self.plaintext_offset
    }

    pub(super) fn plaintext_checkpoint(&self) -> BlobStreamAccumulatorCheckpoint {
        self.plaintext.clone()
    }

    pub(super) fn ciphertext_checkpoint(&self) -> BlobStreamAccumulatorCheckpoint {
        self.ciphertext.clone()
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let plaintext = self.plaintext.encode();
        let ciphertext = self.ciphertext.encode();
        debug_assert_eq!(plaintext.len(), ACCUMULATOR_CHECKPOINT_LEN);
        debug_assert_eq!(ciphertext.len(), ACCUMULATOR_CHECKPOINT_LEN);
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.open_digest);
        bytes.extend_from_slice(self.stream_id.as_bytes());
        bytes.extend_from_slice(&self.total_len.to_be_bytes());
        bytes.extend_from_slice(&self.next_index.to_be_bytes());
        bytes.extend_from_slice(&self.plaintext_offset.to_be_bytes());
        bytes.extend_from_slice(&self.pack_len.to_be_bytes());
        bytes.extend_from_slice(&(ACCUMULATOR_CHECKPOINT_LEN as u32).to_be_bytes());
        bytes.extend_from_slice(&plaintext);
        bytes.extend_from_slice(&ciphertext);
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        debug_assert_eq!(bytes.len(), Self::ENCODED_LEN);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        const ACCUMULATOR_OFFSET: usize = 118;
        if bytes.len() != Self::ENCODED_LEN
            || &bytes[..8] != CHECKPOINT_MAGIC
            || read_u16(bytes, 8)? != PACK_VERSION
            || read_u32(bytes, 114)? as usize != ACCUMULATOR_CHECKPOINT_LEN
            || <[u8; 32]>::from(Sha256::digest(&bytes[..bytes.len() - 32]))
                != bytes[bytes.len() - 32..]
        {
            return Err(integrity("Blob pack checkpoint is malformed"));
        }
        let checkpoint = Self {
            generation: read_u64(bytes, 10)?,
            open_digest: read_array(bytes, 18)?,
            stream_id: BlobPublicationStreamId::from_bytes(read_array(bytes, 50)?)
                .map_err(|_| integrity("Blob pack checkpoint stream ID is invalid"))?,
            total_len: read_u64(bytes, 82)?,
            next_index: read_u64(bytes, 90)?,
            plaintext_offset: read_u64(bytes, 98)?,
            pack_len: read_u64(bytes, 106)?,
            plaintext: BlobStreamAccumulatorCheckpoint::decode(
                &bytes[ACCUMULATOR_OFFSET..ACCUMULATOR_OFFSET + ACCUMULATOR_CHECKPOINT_LEN],
            )
            .map_err(|_| integrity("Blob pack accumulator checkpoint is invalid"))?,
            ciphertext: BlobStreamAccumulatorCheckpoint::decode(
                &bytes[ACCUMULATOR_OFFSET + ACCUMULATOR_CHECKPOINT_LEN
                    ..ACCUMULATOR_OFFSET + 2 * ACCUMULATOR_CHECKPOINT_LEN],
            )
            .map_err(|_| integrity("Blob pack accumulator checkpoint is invalid"))?,
        };
        if checkpoint.generation == 0
            || checkpoint.open_digest == [0; 32]
            || checkpoint.total_len == 0
            || checkpoint.plaintext_offset > checkpoint.total_len
            || checkpoint.pack_len < PACK_HEADER_LEN
            || checkpoint.plaintext.domain() != BlobStreamAccumulatorDomain::Plaintext
            || checkpoint.ciphertext.domain() != BlobStreamAccumulatorDomain::Ciphertext
            || checkpoint.plaintext.next_index() != checkpoint.next_index
            || checkpoint.plaintext.total_len() != checkpoint.plaintext_offset
            || checkpoint.ciphertext.next_index() != checkpoint.next_index
        {
            return Err(integrity("Blob pack checkpoint invariants failed"));
        }
        Ok(checkpoint)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlobPackCompletion {
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    pack_len: u64,
    segment_count: u64,
    descriptor_digest: [u8; 32],
}

impl BlobPackCompletion {
    pub(super) const fn from_completed(
        open_digest: [u8; 32],
        stream_id: BlobPublicationStreamId,
        total_len: u64,
        pack_len: u64,
        segment_count: u64,
        descriptor_digest: [u8; 32],
    ) -> Self {
        Self {
            open_digest,
            stream_id,
            total_len,
            pack_len,
            segment_count,
            descriptor_digest,
        }
    }

    pub(super) const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub(super) const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub(super) const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub(super) const fn pack_len(&self) -> u64 {
        self.pack_len
    }

    pub(super) const fn segment_count(&self) -> u64 {
        self.segment_count
    }

    pub(super) const fn descriptor_digest(&self) -> &[u8; 32] {
        &self.descriptor_digest
    }
}

pub(crate) struct BlobPackWriter {
    directory: OwnedDirectory,
    data: File,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    next_offset: u64,
    pack_len: u64,
    generation: u64,
    plaintext: BlobStreamAccumulator,
    ciphertext: BlobStreamAccumulator,
    background_writeback: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    writeback_started_len: u64,
    writeback_failed: bool,
    #[cfg(test)]
    writeback_join_started: Option<std::sync::mpsc::Sender<()>>,
    #[cfg(test)]
    data_barriers: u64,
    #[cfg(test)]
    journal_barriers: u64,
}

impl BlobPackWriter {
    pub(crate) fn create(
        root: &PinnedBlobPackRoot,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<Self, StoreError> {
        let open = open.open();
        let open_digest = open.digest();
        let directory = root
            .directory
            .open_child_directory(&hex32(&open_digest), true)?;
        let mut data = directory.open_private_rw_file(PACK_FILE, true)?;
        let mut header = Vec::with_capacity(PACK_HEADER_LEN as usize);
        header.extend_from_slice(PACK_MAGIC);
        header.extend_from_slice(&PACK_VERSION.to_be_bytes());
        header.extend_from_slice(&open_digest);
        header.extend_from_slice(open.stream_id().as_bytes());
        header.extend_from_slice(&open.total_len().to_be_bytes());
        data.write_all(&header)
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        Ok(Self {
            directory,
            data,
            open_digest,
            stream_id: open.stream_id(),
            total_len: open.total_len(),
            next_index: 0,
            next_offset: 0,
            pack_len: PACK_HEADER_LEN,
            generation: 0,
            plaintext: BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext),
            ciphertext: BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Ciphertext),
            background_writeback: None,
            writeback_started_len: PACK_HEADER_LEN,
            writeback_failed: false,
            #[cfg(test)]
            writeback_join_started: None,
            #[cfg(test)]
            data_barriers: 0,
            #[cfg(test)]
            journal_barriers: 0,
        })
    }

    pub(crate) fn resume(
        root: &PinnedBlobPackRoot,
        checkpoint: &BlobPackCheckpoint,
    ) -> Result<Self, StoreError> {
        let directory = root
            .directory
            .open_child_directory(&hex32(&checkpoint.open_digest), false)?;
        let mut data = directory.open_private_rw_file(PACK_FILE, false)?;
        validate_pack_header(
            &mut data,
            &checkpoint.open_digest,
            checkpoint.stream_id,
            checkpoint.total_len,
        )?;
        if data
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?
            .len()
            < checkpoint.pack_len
        {
            return Err(integrity("Blob pack is shorter than durable checkpoint"));
        }
        data.set_len(checkpoint.pack_len)
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        data.seek(SeekFrom::Start(checkpoint.pack_len))
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        Ok(Self {
            directory,
            data,
            open_digest: checkpoint.open_digest,
            stream_id: checkpoint.stream_id,
            total_len: checkpoint.total_len,
            next_index: checkpoint.next_index,
            next_offset: checkpoint.plaintext_offset,
            pack_len: checkpoint.pack_len,
            generation: checkpoint.generation,
            plaintext: BlobStreamAccumulator::restore(checkpoint.plaintext.clone())
                .map_err(|_| integrity("Blob pack plaintext accumulator cannot be restored"))?,
            ciphertext: BlobStreamAccumulator::restore(checkpoint.ciphertext.clone())
                .map_err(|_| integrity("Blob pack accumulator cannot be restored"))?,
            background_writeback: None,
            writeback_started_len: checkpoint.pack_len,
            writeback_failed: false,
            #[cfg(test)]
            writeback_join_started: None,
            #[cfg(test)]
            data_barriers: 0,
            #[cfg(test)]
            journal_barriers: 0,
        })
    }

    pub(crate) fn append_segment(
        &mut self,
        plaintext: &[u8],
        segment: &EncryptedBlobStreamSegment,
    ) -> Result<(), StoreError> {
        let encoded = segment.encode();
        self.append_encoded_segment(plaintext, segment, &encoded)
    }

    pub(crate) fn append_encoded_segment(
        &mut self,
        plaintext: &[u8],
        segment: &EncryptedBlobStreamSegment,
        encoded: &[u8],
    ) -> Result<(), StoreError> {
        self.append_encoded_segment_inner(plaintext, segment, encoded, None)
    }

    pub(crate) fn append_authenticated_encoded_segment(
        &mut self,
        plaintext: &[u8],
        segment: &EncryptedBlobStreamSegment,
        encoded: &[u8],
        ciphertext_checkpoint: BlobStreamAccumulatorCheckpoint,
    ) -> Result<(), StoreError> {
        self.append_encoded_segment_inner(plaintext, segment, encoded, Some(ciphertext_checkpoint))
    }

    fn append_encoded_segment_inner(
        &mut self,
        plaintext: &[u8],
        segment: &EncryptedBlobStreamSegment,
        encoded: &[u8],
        authenticated_ciphertext_checkpoint: Option<BlobStreamAccumulatorCheckpoint>,
    ) -> Result<(), StoreError> {
        let expected_plaintext_next = segment
            .index()
            .checked_add(1)
            .ok_or_else(|| integrity("Blob pack segment index overflow"))?;
        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| integrity("Blob pack plaintext segment length overflows"))?;
        if plaintext_len != segment.plaintext_len()
            || self.plaintext.checkpoint().next_index() != segment.index()
            || self.plaintext.checkpoint().total_len() != segment.offset()
            || segment.stream_id() != self.stream_id
            || segment.open_digest() != &self.open_digest
            || segment.total_len() != self.total_len
            || segment.index() != self.next_index
            || segment.offset() != self.next_offset
            || segment.previous_ciphertext_commitment() != self.ciphertext.checkpoint().commitment()
        {
            return Err(integrity("Blob pack segment does not extend this stream"));
        }
        let encoded_len = u32::try_from(encoded.len())
            .map_err(|_| integrity("Blob pack segment length overflows"))?;
        if encoded.is_empty() || encoded.len() > MAX_SEGMENT_RECORD_LEN {
            return Err(integrity("Blob pack segment exceeds record bound"));
        }
        segment
            .validate_encoding(encoded)
            .map_err(|_| integrity("Blob pack segment encoding differs"))?;
        let next_index = expected_plaintext_next;
        let next_offset = self
            .next_offset
            .checked_add(u64::from(segment.plaintext_len()))
            .ok_or_else(|| integrity("Blob pack plaintext offset overflow"))?;
        let next_pack_len = self
            .pack_len
            .checked_add(4 + u64::from(encoded_len))
            .ok_or_else(|| integrity("Blob pack byte length overflow"))?;
        let mut next_plaintext = self.plaintext.clone();
        next_plaintext
            .push_segment(segment.index(), plaintext)
            .map_err(|_| integrity("Blob pack plaintext accumulator rejected segment"))?;
        let next_ciphertext = if let Some(checkpoint) = authenticated_ciphertext_checkpoint {
            let expected_ciphertext_len = self
                .ciphertext
                .checkpoint()
                .total_len()
                .checked_add(segment.ciphertext().len() as u64)
                .ok_or_else(|| integrity("Blob pack ciphertext length overflow"))?;
            if checkpoint.domain() != aster_mesh::BlobStreamAccumulatorDomain::Ciphertext
                || checkpoint.next_index() != next_index
                || checkpoint.total_len() != expected_ciphertext_len
            {
                return Err(integrity(
                    "authenticated Blob ciphertext checkpoint differs",
                ));
            }
            BlobStreamAccumulator::restore(checkpoint)
                .map_err(|_| integrity("authenticated Blob ciphertext checkpoint is invalid"))?
        } else {
            let mut accumulator = self.ciphertext.clone();
            accumulator
                .push_segment(segment.index(), segment.ciphertext())
                .map_err(|_| integrity("Blob pack ciphertext accumulator rejected segment"))?;
            accumulator
        };
        let append = self
            .data
            .write_all(&encoded_len.to_be_bytes())
            .and_then(|()| self.data.write_all(encoded));
        if let Err(error) = append {
            let _ = self.data.set_len(self.pack_len);
            let _ = self.data.seek(SeekFrom::Start(self.pack_len));
            return Err(blob_error(BlobStoreError::Io(error)));
        }
        self.plaintext = next_plaintext;
        self.ciphertext = next_ciphertext;
        self.next_index = next_index;
        self.next_offset = next_offset;
        self.pack_len = next_pack_len;
        Ok(())
    }

    pub(super) fn ciphertext_checkpoint(&self) -> BlobStreamAccumulatorCheckpoint {
        self.ciphertext.checkpoint()
    }

    pub(super) fn plaintext_checkpoint(&self) -> BlobStreamAccumulatorCheckpoint {
        self.plaintext.checkpoint()
    }

    pub(super) fn final_roots(&self) -> Result<([u8; 32], [u8; 32]), StoreError> {
        if self.next_offset != self.total_len {
            return Err(integrity("Blob pack is not complete"));
        }
        let plaintext_root = self
            .plaintext
            .clone()
            .finish(self.total_len)
            .map_err(|_| integrity("Blob pack plaintext root is incomplete"))?;
        let ciphertext_checkpoint = self.ciphertext.checkpoint();
        let ciphertext_root = self
            .ciphertext
            .clone()
            .finish(ciphertext_total_len(&ciphertext_checkpoint)?)
            .map_err(|_| integrity("Blob pack ciphertext root is incomplete"))?;
        Ok((plaintext_root, ciphertext_root))
    }

    /// Starts at most one owned data writeback while the receiver processes
    /// later callbacks. This never creates checkpoint or publication authority.
    pub(crate) fn advance_background_writeback(&mut self) -> Result<(), StoreError> {
        if self
            .background_writeback
            .as_ref()
            .is_some_and(|task| task.is_finished())
        {
            self.join_background_writeback()?;
        }
        if self.writeback_failed {
            return Err(integrity("previous Blob pack background writeback failed"));
        }
        if self.background_writeback.is_some()
            || self.pack_len.saturating_sub(self.writeback_started_len) < BACKGROUND_WRITEBACK_BYTES
        {
            return Ok(());
        }
        let start = || {
            let data = self.data.try_clone()?;
            std::thread::Builder::new()
                .name("aster-blob-writeback".to_owned())
                .stack_size(256 * 1024)
                .spawn(move || data.sync_data())
        };
        match start() {
            Ok(task) => {
                self.background_writeback = Some(task);
                self.writeback_started_len = self.pack_len;
                Ok(())
            }
            Err(error) => {
                self.writeback_failed = true;
                Err(blob_error(BlobStoreError::Io(error)))
            }
        }
    }

    fn join_background_writeback(&mut self) -> Result<(), StoreError> {
        if let Some(task) = self.background_writeback.take() {
            #[cfg(test)]
            if let Some(started) = self.writeback_join_started.take() {
                let _ = started.send(());
            }
            let result = match task.join() {
                Ok(result) => result.map_err(|error| blob_error(BlobStoreError::Io(error))),
                Err(_) => Err(integrity("Blob pack background writeback worker panicked")),
            };
            if result.is_err() {
                self.writeback_failed = true;
                return result;
            }
        }
        if self.writeback_failed {
            return Err(integrity("previous Blob pack background writeback failed"));
        }
        Ok(())
    }

    pub(crate) fn checkpoint(&mut self) -> Result<BlobPackCheckpoint, StoreError> {
        // Joining the early writeback does not replace the exact foreground
        // barrier: bytes appended while it ran must also be durable before
        // the journal and redb checkpoint can acknowledge this frontier.
        self.join_background_writeback()?;
        self.data
            .sync_data()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        #[cfg(test)]
        {
            self.data_barriers += 1;
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| integrity("Blob pack checkpoint generation overflow"))?;
        let checkpoint = BlobPackCheckpoint {
            generation,
            open_digest: self.open_digest,
            stream_id: self.stream_id,
            total_len: self.total_len,
            next_index: self.next_index,
            plaintext_offset: self.next_offset,
            pack_len: self.pack_len,
            plaintext: self.plaintext.checkpoint(),
            ciphertext: self.ciphertext.checkpoint(),
        };
        let slot = if generation & 1 == 0 {
            JOURNAL_ZERO
        } else {
            JOURNAL_ONE
        };
        self.directory.write_atomic(slot, &checkpoint.encode())?;
        #[cfg(test)]
        {
            self.journal_barriers += 1;
        }
        self.generation = generation;
        self.writeback_started_len = self.pack_len;
        Ok(checkpoint)
    }

    pub(crate) fn finish(
        mut self,
        commitment: &VerifiedBlobStreamFinalCommitment,
    ) -> Result<BlobPackCompletion, StoreError> {
        let checkpoint = self.checkpoint()?;
        let commitment = commitment.commitment();
        let ciphertext_len = ciphertext_total_len(&checkpoint.ciphertext)?;
        let plaintext_root = self
            .plaintext
            .clone()
            .finish(self.total_len)
            .map_err(|_| integrity("Blob pack plaintext root is incomplete"))?;
        let ciphertext_root = self
            .ciphertext
            .clone()
            .finish(ciphertext_len)
            .map_err(|_| integrity("Blob pack ciphertext root is incomplete"))?;
        if commitment.open_digest() != &self.open_digest
            || commitment.stream_id() != self.stream_id
            || commitment.total_len() != self.total_len
            || commitment.segment_count() != self.next_index
            || commitment.plaintext_root() != &plaintext_root
            || commitment.ciphertext_root() != &ciphertext_root
            || self.next_offset != self.total_len
        {
            return Err(integrity(
                "Blob pack final commitment does not match durable bytes",
            ));
        }
        let commitment_bytes = commitment.encode();
        let mut descriptor = Vec::with_capacity(128 + commitment_bytes.len());
        descriptor.extend_from_slice(COMPLETION_MAGIC);
        descriptor.extend_from_slice(&PACK_VERSION.to_be_bytes());
        descriptor.extend_from_slice(&self.open_digest);
        descriptor.extend_from_slice(self.stream_id.as_bytes());
        descriptor.extend_from_slice(&self.total_len.to_be_bytes());
        descriptor.extend_from_slice(&self.pack_len.to_be_bytes());
        descriptor.extend_from_slice(&self.next_index.to_be_bytes());
        descriptor.extend_from_slice(&(commitment_bytes.len() as u32).to_be_bytes());
        descriptor.extend_from_slice(&commitment_bytes);
        let checksum: [u8; 32] = Sha256::digest(&descriptor).into();
        descriptor.extend_from_slice(&checksum);
        self.directory.write_atomic(COMPLETION_FILE, &descriptor)?;
        Ok(BlobPackCompletion {
            open_digest: self.open_digest,
            stream_id: self.stream_id,
            total_len: self.total_len,
            pack_len: self.pack_len,
            segment_count: self.next_index,
            descriptor_digest: checksum,
        })
    }

    #[cfg(test)]
    pub(super) fn test_install_background_writeback(
        &mut self,
        task: std::thread::JoinHandle<std::io::Result<()>>,
        joining: std::sync::mpsc::Sender<()>,
    ) {
        assert!(self.background_writeback.is_none());
        self.background_writeback = Some(task);
        self.writeback_join_started = Some(joining);
    }

    #[cfg(test)]
    fn test_barriers(&self) -> (u64, u64) {
        (self.data_barriers, self.journal_barriers)
    }
}

impl Drop for BlobPackWriter {
    fn drop(&mut self) {
        // Cancellation may not leave a detached sync holding the old pack
        // inode after the session releases its exclusive writer lease.
        let _ = self.join_background_writeback();
    }
}

pub(crate) struct BlobPackReader {
    data: File,
    completion: BlobPackCompletion,
    next_index: u64,
    cursor: u64,
}

impl BlobPackReader {
    pub(crate) fn open(
        root: &PinnedBlobPackRoot,
        completion: &BlobPackCompletion,
    ) -> Result<Self, StoreError> {
        let directory = root
            .directory
            .open_child_directory(&hex32(&completion.open_digest), false)?;
        let descriptor = directory
            .read_private_file_if_present(COMPLETION_FILE, 8 * 1024)?
            .ok_or_else(|| integrity("Blob pack completion descriptor is missing"))?;
        validate_completion_descriptor(&descriptor, completion)?;
        let mut data = directory.open_private_read_file(PACK_FILE)?;
        validate_pack_header(
            &mut data,
            &completion.open_digest,
            completion.stream_id,
            completion.total_len,
        )?;
        if data
            .metadata()
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?
            .len()
            < completion.pack_len
        {
            return Err(integrity("completed Blob pack is truncated"));
        }
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        Ok(Self {
            data,
            completion: completion.clone(),
            next_index: 0,
            cursor: PACK_HEADER_LEN,
        })
    }

    pub(crate) fn read_segment(
        &mut self,
        index: u64,
        output: &mut Vec<u8>,
    ) -> Result<bool, StoreError> {
        if index != self.next_index {
            return Err(integrity(
                "Blob pack reader requires sequential segment indexes",
            ));
        }
        if index == self.completion.segment_count {
            return Ok(false);
        }
        if index > self.completion.segment_count || self.cursor + 4 > self.completion.pack_len {
            return Err(integrity("Blob pack reader exceeded completion boundary"));
        }
        let mut len = [0_u8; 4];
        self.data
            .read_exact(&mut len)
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0
            || len > MAX_SEGMENT_RECORD_LEN
            || self.cursor + 4 + len as u64 > self.completion.pack_len
        {
            return Err(integrity("Blob pack record length is invalid"));
        }
        output.clear();
        output.resize(len, 0);
        self.data
            .read_exact(output)
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        let segment = EncryptedBlobStreamSegment::decode(output)
            .map_err(|_| integrity("Blob pack record is not a canonical encrypted segment"))?;
        if segment.index() != index
            || segment.stream_id() != self.completion.stream_id
            || segment.open_digest() != &self.completion.open_digest
        {
            return Err(integrity("Blob pack record identity mismatch"));
        }
        self.next_index += 1;
        self.cursor += 4 + len as u64;
        Ok(true)
    }

    pub(crate) fn resume_at(
        &mut self,
        next_index: u64,
        wire_offset: u64,
    ) -> Result<(), StoreError> {
        let cursor = PACK_HEADER_LEN
            .checked_add(wire_offset)
            .ok_or_else(|| integrity("Blob pack reader resume offset overflow"))?;
        if next_index > self.completion.segment_count
            || cursor > self.completion.pack_len
            || ((next_index == self.completion.segment_count)
                != (cursor == self.completion.pack_len))
        {
            return Err(integrity("Blob pack reader resume boundary differs"));
        }
        self.data
            .seek(SeekFrom::Start(cursor))
            .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
        self.next_index = next_index;
        self.cursor = cursor;
        Ok(())
    }
}

pub(crate) fn recover_blob_pack(
    root: &PinnedBlobPackRoot,
    open_digest: [u8; 32],
) -> Result<Option<BlobPackCheckpoint>, StoreError> {
    let directory = match root
        .directory
        .open_child_directory(&hex32(&open_digest), false)
    {
        Ok(directory) => directory,
        Err(StoreError::Blob(BlobStoreError::Io(error)))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut newest: Option<BlobPackCheckpoint> = None;
    for slot in [JOURNAL_ZERO, JOURNAL_ONE] {
        let Some(bytes) =
            directory.read_private_file_if_present(slot, BlobPackCheckpoint::ENCODED_LEN as u64)?
        else {
            continue;
        };
        let checkpoint = match BlobPackCheckpoint::decode(&bytes) {
            Ok(checkpoint) if checkpoint.open_digest == open_digest => checkpoint,
            Ok(_) => return Err(integrity("Blob pack checkpoint belongs to another stream")),
            Err(_) => continue,
        };
        if newest
            .as_ref()
            .is_none_or(|current| checkpoint.generation > current.generation)
        {
            newest = Some(checkpoint);
        }
    }
    Ok(newest)
}

/// Removes the fixed, bounded artifact set for one provisional or completed
/// stream pack. Unknown entries keep the directory non-empty and fail closed.
#[cfg(test)]
pub(crate) fn delete_blob_pack(
    root: &PinnedBlobPackRoot,
    open_digest: [u8; 32],
) -> Result<(), StoreError> {
    let name = hex32(&open_digest);
    let directory = match root.directory.open_child_directory(&name, false) {
        Ok(directory) => directory,
        Err(StoreError::Blob(BlobStoreError::Io(error)))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    for file in [COMPLETION_FILE, JOURNAL_ZERO, JOURNAL_ONE, PACK_FILE] {
        directory.remove_if_exists(file, false)?;
    }
    root.directory.remove_if_exists(&name, true)
}

fn validate_pack_header(
    data: &mut File,
    open_digest: &[u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
) -> Result<(), StoreError> {
    data.seek(SeekFrom::Start(0))
        .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
    let mut header = [0_u8; PACK_HEADER_LEN as usize];
    data.read_exact(&mut header)
        .map_err(|error| blob_error(BlobStoreError::Io(error)))?;
    if &header[..8] != PACK_MAGIC
        || read_u16(&header, 8)? != PACK_VERSION
        || &header[10..42] != open_digest
        || &header[42..74] != stream_id.as_bytes()
        || read_u64(&header, 74)? != total_len
    {
        return Err(integrity("Blob pack header identity mismatch"));
    }
    Ok(())
}

fn validate_completion_descriptor(
    bytes: &[u8],
    completion: &BlobPackCompletion,
) -> Result<(), StoreError> {
    if bytes.len() < 134
        || &bytes[..8] != COMPLETION_MAGIC
        || read_u16(bytes, 8)? != PACK_VERSION
        || bytes[10..42] != completion.open_digest
        || &bytes[42..74] != completion.stream_id.as_bytes()
        || read_u64(bytes, 74)? != completion.total_len
        || read_u64(bytes, 82)? != completion.pack_len
        || read_u64(bytes, 90)? != completion.segment_count
    {
        return Err(integrity(
            "Blob pack completion descriptor identity mismatch",
        ));
    }
    let commitment_len = read_u32(bytes, 98)? as usize;
    if bytes.len() != 102 + commitment_len + 32 {
        return Err(integrity("Blob pack completion descriptor length mismatch"));
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes[..bytes.len() - 32]).into();
    if checksum != completion.descriptor_digest || bytes[bytes.len() - 32..] != checksum {
        return Err(integrity(
            "Blob pack completion descriptor checksum mismatch",
        ));
    }
    Ok(())
}

fn ciphertext_total_len(checkpoint: &BlobStreamAccumulatorCheckpoint) -> Result<u64, StoreError> {
    read_u64(&checkpoint.encode(), 20)
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
        .ok_or_else(|| integrity("Blob pack metadata is truncated"))
}

fn integrity(reason: &'static str) -> StoreError {
    blob_error(BlobStoreError::DepotIntegrity(reason))
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::{
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobStreamFinalCommitment, BlobStreamOpen,
        Priority, ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
        VersionVector,
    };
    use zeroize::Zeroizing;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-blob-pack-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create pack test root");
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("state.redb")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct StreamFixture {
        _root: TestRoot,
        pack_root: PinnedBlobPackRoot,
        open: VerifiedBlobStreamOpen,
        plaintexts: Vec<Vec<u8>>,
        segments: Vec<EncryptedBlobStreamSegment>,
        final_commitment: VerifiedBlobStreamFinalCommitment,
    }

    impl StreamFixture {
        fn stream_directory(&self) -> PathBuf {
            self._root
                .0
                .join("blob-depot-v1")
                .join("stream-packs-v1")
                .join(hex32(&self.open.open().digest()))
        }
    }

    fn stream_fixture(seed: u8) -> StreamFixture {
        let topic = Topic::new("pack").expect("topic");
        let scope = Scope::new("mission/pack").expect("scope");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_control_authority(1, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 + 7;
        let authorization_digest = publisher
            .blob_stream_authorization_digest(&scope, 1)
            .expect("route authorization");
        let open = BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([seed; 32]).expect("stream ID"),
            publisher.identity(),
            b"pack-test".to_vec(),
            publisher.mission_authority_id(),
            1,
            VersionVector::default(),
            topic,
            scope,
            BlobMetadata::new(Some("application/octet-stream".into()), b"pack".to_vec())
                .expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            authorization_digest,
            [0x55; 32],
        )
        .expect("open");
        let signed_open = publisher.seal_blob_stream_open(&open).expect("sign open");
        let open = publisher
            .verify_blob_stream_open(&signed_open)
            .expect("verify open");
        let plaintexts = [vec![0x31; BLOB_STREAM_SEGMENT_BYTES], vec![0x32; 7]];
        let mut encryptor = publisher
            .begin_blob_stream_encrypt(&open)
            .expect("encryptor");
        let mut plaintext_accumulator =
            BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Plaintext);
        let mut ciphertext_accumulator =
            BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Ciphertext);
        let mut segments = Vec::new();
        let mut offset = 0_u64;
        for (index, plaintext) in plaintexts.into_iter().enumerate() {
            plaintext_accumulator
                .push_segment(index as u64, &plaintext)
                .expect("plaintext accumulator");
            let segment = encryptor
                .encrypt_segment(index as u64, offset, Zeroizing::new(plaintext.clone()))
                .expect("encrypt segment");
            ciphertext_accumulator
                .push_segment(index as u64, segment.ciphertext())
                .expect("ciphertext accumulator");
            offset += plaintext.len() as u64;
            segments.push(segment);
        }
        let plaintext_root = plaintext_accumulator
            .finish(total_len)
            .expect("plaintext root");
        let ciphertext_len = segments
            .iter()
            .map(|segment| segment.ciphertext().len() as u64)
            .sum();
        let ciphertext_root = ciphertext_accumulator
            .finish(ciphertext_len)
            .expect("ciphertext root");
        let commitment =
            BlobStreamFinalCommitment::new(&open, plaintext_root, ciphertext_root, 2, None)
                .expect("commitment");
        let signed = publisher
            .seal_blob_stream_commitment(&commitment)
            .expect("sign commitment");
        let final_commitment = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .expect("verify commitment");
        let root = TestRoot::new();
        let store = Store::open_for_mission(root.database(), publisher.mission_authority_id())
            .expect("store");
        let pack_root = PinnedBlobPackRoot::open(&store).expect("pack root");
        StreamFixture {
            _root: root,
            pack_root,
            open,
            plaintexts: vec![vec![0x31; BLOB_STREAM_SEGMENT_BYTES], vec![0x32; 7]],
            segments,
            final_commitment,
        }
    }

    fn append_fixture_segment(writer: &mut BlobPackWriter, fixture: &StreamFixture, index: usize) {
        writer
            .append_segment(&fixture.plaintexts[index], &fixture.segments[index])
            .expect("append segment");
    }

    #[test]
    fn blob_pack_rejected_append_does_not_advance_either_frontier() {
        let fixture = stream_fixture(0x60);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        let wrong_plaintext = vec![0x44; fixture.plaintexts[0].len()];

        assert!(
            writer
                .append_segment(
                    &wrong_plaintext[..wrong_plaintext.len() - 1],
                    &fixture.segments[0]
                )
                .is_err()
        );
        append_fixture_segment(&mut writer, &fixture, 0);
        let checkpoint = writer.checkpoint().expect("checkpoint after retry");
        assert_eq!(checkpoint.next_index(), 1);
        assert_eq!(
            checkpoint.plaintext_offset(),
            fixture.plaintexts[0].len() as u64
        );
    }

    #[test]
    fn blob_pack_appends_the_verified_original_encoding_without_reencoding() {
        let fixture = stream_fixture(0x6a);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        let encoded = fixture.segments[0].encode();
        writer
            .append_encoded_segment(&fixture.plaintexts[0], &fixture.segments[0], &encoded)
            .expect("append original encoding");

        let mut mismatched = fixture.segments[1].encode();
        mismatched[0] ^= 1;
        assert!(
            writer
                .append_encoded_segment(&fixture.plaintexts[1], &fixture.segments[1], &mismatched,)
                .is_err()
        );
    }

    #[test]
    fn blob_pack_adopts_authenticated_ciphertext_checkpoint_without_rehashing() {
        let fixture = stream_fixture(0x6b);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        let mut authenticated = BlobStreamAccumulator::new(BlobStreamAccumulatorDomain::Ciphertext);
        for (index, segment) in fixture.segments.iter().enumerate() {
            authenticated
                .push_segment(index as u64, segment.ciphertext())
                .expect("authenticated ciphertext checkpoint");
            writer
                .append_authenticated_encoded_segment(
                    &fixture.plaintexts[index],
                    segment,
                    &segment.encode(),
                    authenticated.checkpoint(),
                )
                .expect("append authenticated original encoding");
        }

        writer
            .finish(&fixture.final_commitment)
            .expect("authenticated checkpoint retains the signed final root");
    }

    #[test]
    fn blob_pack_background_writeback_never_creates_checkpoint_authority() {
        let fixture = stream_fixture(0x71);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        append_fixture_segment(&mut writer, &fixture, 0);
        let data = writer.data.try_clone().expect("background descriptor");
        writer.background_writeback = Some(std::thread::spawn(move || data.sync_data()));
        writer
            .join_background_writeback()
            .expect("background completion");
        assert_eq!(writer.generation, 0);
        assert_eq!(writer.test_barriers(), (0, 0));
        assert!(
            recover_blob_pack(&fixture.pack_root, fixture.open.open().digest())
                .expect("no background journal")
                .is_none()
        );
        let checkpoint = writer.checkpoint().expect("foreground checkpoint");
        assert_eq!(checkpoint.generation(), 1);
        assert_eq!(writer.test_barriers(), (1, 1));
        assert_eq!(writer.writeback_started_len, checkpoint.pack_len());
        drop(writer);
        let mut resumed = BlobPackWriter::resume(&fixture.pack_root, &checkpoint).expect("resume");
        assert!(resumed.background_writeback.is_none());
        assert!(!resumed.writeback_failed);
        assert_eq!(resumed.writeback_started_len, checkpoint.pack_len());
        resumed
            .advance_background_writeback()
            .expect("no new bytes to write back");
        assert!(resumed.background_writeback.is_none());
        assert_eq!(resumed.generation, checkpoint.generation());
    }

    #[test]
    fn blob_pack_background_writeback_errors_and_panics_stay_fail_closed() {
        for panic_worker in [false, true] {
            let fixture = stream_fixture(if panic_worker { 0x73 } else { 0x72 });
            let mut writer =
                BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
            for index in 0..fixture.segments.len() {
                append_fixture_segment(&mut writer, &fixture, index);
            }
            writer.background_writeback = Some(std::thread::spawn(move || {
                assert!(!panic_worker, "injected background writeback panic");
                Err(std::io::Error::other(
                    "injected background writeback failure",
                ))
            }));
            assert!(writer.checkpoint().is_err());
            assert!(writer.background_writeback.is_none());
            assert!(writer.writeback_failed);
            assert!(writer.advance_background_writeback().is_err());
            assert!(
                writer.checkpoint().is_err(),
                "failure must survive a second checkpoint call"
            );
            assert_eq!(writer.generation, 0);
            assert_eq!(writer.test_barriers(), (0, 0));
            assert!(
                recover_blob_pack(&fixture.pack_root, fixture.open.open().digest())
                    .expect("failed worker cannot create a journal")
                    .is_none()
            );
            assert!(writer.finish(&fixture.final_commitment).is_err());
            assert!(!fixture.stream_directory().join(COMPLETION_FILE).exists());
        }
    }

    #[test]
    fn blob_pack_checkpoint_encoding_is_constant_sized() {
        assert_eq!(BlobPackCheckpoint::ENCODED_LEN, 4318);
    }

    #[test]
    fn blob_pack_appends_segments_without_per_segment_barrier() {
        let fixture = stream_fixture(0x61);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        for index in 0..fixture.segments.len() {
            append_fixture_segment(&mut writer, &fixture, index);
        }
        assert_eq!(writer.test_barriers(), (0, 0));
        let checkpoint = writer.checkpoint().expect("checkpoint");
        assert_eq!(writer.test_barriers(), (1, 1));
        assert_eq!(checkpoint.next_index(), 2);
    }

    #[test]
    fn blob_pack_checkpoint_is_constant_sized_and_monotonic() {
        let fixture = stream_fixture(0x62);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        append_fixture_segment(&mut writer, &fixture, 0);
        let first = writer.checkpoint().expect("first checkpoint");
        append_fixture_segment(&mut writer, &fixture, 1);
        let second = writer.checkpoint().expect("second checkpoint");
        assert_eq!(first.encode().len(), BlobPackCheckpoint::ENCODED_LEN);
        assert_eq!(second.encode().len(), BlobPackCheckpoint::ENCODED_LEN);
        assert!(second.generation() > first.generation());
        assert!(second.pack_len() > first.pack_len());
        let recovered = recover_blob_pack(&fixture.pack_root, fixture.open.open().digest())
            .expect("recover")
            .expect("checkpoint");
        assert_eq!(recovered.generation(), second.generation());
        assert_eq!(recovered.pack_len(), second.pack_len());
    }

    #[test]
    fn blob_pack_reader_streams_verified_segments() {
        let fixture = stream_fixture(0x63);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        for index in 0..fixture.segments.len() {
            append_fixture_segment(&mut writer, &fixture, index);
        }
        let completion = writer.finish(&fixture.final_commitment).expect("finish");
        let mut reader = BlobPackReader::open(&fixture.pack_root, &completion).expect("reader");
        let mut encoded = Vec::new();
        for (index, expected) in fixture.segments.iter().enumerate() {
            assert!(
                reader
                    .read_segment(index as u64, &mut encoded)
                    .expect("read segment")
            );
            assert_eq!(encoded, expected.encode());
        }
        assert!(!reader.read_segment(2, &mut encoded).expect("end of pack"));
    }

    #[test]
    fn blob_pack_crash_recovery_truncates_uncheckpointed_tail() {
        let fixture = stream_fixture(0x64);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        append_fixture_segment(&mut writer, &fixture, 0);
        let durable = writer.checkpoint().expect("durable checkpoint");
        append_fixture_segment(&mut writer, &fixture, 1);
        let tail_len = writer.pack_len;
        drop(writer);

        let recovered = recover_blob_pack(&fixture.pack_root, fixture.open.open().digest())
            .expect("recover")
            .expect("checkpoint");
        assert_eq!(recovered.pack_len(), durable.pack_len());
        assert!(tail_len > recovered.pack_len());
        let mut resumed =
            BlobPackWriter::resume(&fixture.pack_root, &recovered).expect("resume writer");
        assert_eq!(
            std::fs::metadata(fixture.stream_directory().join(PACK_FILE))
                .expect("pack metadata")
                .len(),
            durable.pack_len()
        );
        append_fixture_segment(&mut resumed, &fixture, 1);
        let next = resumed.checkpoint().expect("next checkpoint");
        assert_eq!(next.generation(), durable.generation() + 1);
        assert_eq!(next.next_index(), 2);
    }

    #[test]
    fn blob_pack_crash_recovery_ignores_torn_newer_journal_slot() {
        let fixture = stream_fixture(0x65);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        append_fixture_segment(&mut writer, &fixture, 0);
        let first = writer.checkpoint().expect("first checkpoint");
        append_fixture_segment(&mut writer, &fixture, 1);
        let second = writer.checkpoint().expect("second checkpoint");
        assert!(second.generation() > first.generation());
        drop(writer);

        let newer_slot = fixture.stream_directory().join(JOURNAL_ZERO);
        let newer = std::fs::OpenOptions::new()
            .write(true)
            .open(newer_slot)
            .expect("open newer slot");
        newer.set_len(37).expect("tear newer slot");
        newer.sync_all().expect("sync torn slot");

        let recovered = recover_blob_pack(&fixture.pack_root, fixture.open.open().digest())
            .expect("recover")
            .expect("older checkpoint");
        assert_eq!(recovered.generation(), first.generation());
        assert_eq!(recovered.pack_len(), first.pack_len());
    }

    #[test]
    fn blob_pack_descriptor_identity_mismatch_fails_closed() {
        let fixture = stream_fixture(0x66);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        for index in 0..fixture.segments.len() {
            append_fixture_segment(&mut writer, &fixture, index);
        }
        let completion = writer
            .finish(&fixture.final_commitment)
            .expect("completion");
        let descriptor_path = fixture.stream_directory().join(COMPLETION_FILE);
        let mut descriptor = std::fs::read(&descriptor_path).expect("read descriptor");
        descriptor[18] ^= 1;
        std::fs::write(&descriptor_path, descriptor).expect("replace descriptor bytes");
        assert!(BlobPackReader::open(&fixture.pack_root, &completion).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn blob_pack_symlink_substitution_fails_closed() {
        use std::os::unix::fs::symlink;

        let fixture = stream_fixture(0x67);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        append_fixture_segment(&mut writer, &fixture, 0);
        let checkpoint = writer.checkpoint().expect("checkpoint");
        drop(writer);
        let pack = fixture.stream_directory().join(PACK_FILE);
        let replacement = fixture._root.0.join("replacement");
        std::fs::write(&replacement, b"not a pack").expect("replacement");
        std::fs::remove_file(&pack).expect("remove pack");
        symlink(&replacement, &pack).expect("substitute symlink");
        assert!(BlobPackWriter::resume(&fixture.pack_root, &checkpoint).is_err());
    }

    #[test]
    fn blob_pack_deletion_is_bounded_and_idempotent() {
        let fixture = stream_fixture(0x68);
        let mut writer = BlobPackWriter::create(&fixture.pack_root, &fixture.open).expect("writer");
        for index in 0..fixture.segments.len() {
            append_fixture_segment(&mut writer, &fixture, index);
        }
        writer
            .finish(&fixture.final_commitment)
            .expect("completion");
        let digest = fixture.open.open().digest();
        delete_blob_pack(&fixture.pack_root, digest).expect("first deletion");
        assert!(!fixture.stream_directory().exists());
        delete_blob_pack(&fixture.pack_root, digest).expect("idempotent deletion");
    }
}
