use std::fmt::{self, Display, Formatter};

use bytes::Bytes;

const MAGIC: &[u8; 4] = b"ASM\x01";
pub(crate) const MAX_STREAM_EXTENT_BYTES: usize = 1_048_576;
pub(crate) const MAX_STREAM_CHECKPOINT_BATCH_BYTES: u32 = 16 * 1_048_576;
pub(crate) const MIN_STREAM_RECEIVE_WINDOW_BYTES: u64 =
    MAX_STREAM_CHECKPOINT_BATCH_BYTES as u64 + MAX_STREAM_EXTENT_BYTES as u64;
pub(crate) const STREAM_DATA_FIXED_BYTES: usize = 89;
pub(crate) const MAX_STREAM_DATA_FRAME_BYTES: usize =
    STREAM_DATA_FIXED_BYTES + MAX_STREAM_EXTENT_BYTES;
pub(crate) const STREAM_TAGS: std::ops::RangeInclusive<u8> = 0xd6..=0xdc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamError(String);
impl StreamError {
    fn invalid(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}
impl Display for StreamError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StreamError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StreamClass {
    Blob = 1,
}
impl StreamClass {
    pub(crate) fn decode(v: u8) -> Result<Self, StreamError> {
        (v == 1)
            .then_some(Self::Blob)
            .ok_or_else(|| StreamError::invalid("unknown required stream class"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StreamDirection {
    ToSessionInitiator = 1,
    ToSessionResponder = 2,
}
impl StreamDirection {
    fn decode(v: u8) -> Result<Self, StreamError> {
        match v {
            1 => Ok(Self::ToSessionInitiator),
            2 => Ok(Self::ToSessionResponder),
            _ => Err(StreamError::invalid("unknown stream direction")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum StreamResultCode {
    Promoted = 1,
    AlreadyPresent = 2,
    DeferredCapacity = 3,
    RetiredExpired = 4,
    RejectedPolicy = 5,
    IntegrityFailure = 6,
}
impl StreamResultCode {
    fn decode(v: u8) -> Result<Self, StreamError> {
        match v {
            1 => Ok(Self::Promoted),
            2 => Ok(Self::AlreadyPresent),
            3 => Ok(Self::DeferredCapacity),
            4 => Ok(Self::RetiredExpired),
            5 => Ok(Self::RejectedPolicy),
            6 => Ok(Self::IntegrityFailure),
            _ => Err(StreamError::invalid("unknown stream result")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamOpenV1 {
    pub class: StreamClass,
    pub direction: StreamDirection,
    pub session_transcript: [u8; 32],
    pub exchange_id: u64,
    /// Logical publisher-selected stream identifier. Attempts reuse this value.
    pub transfer_id: [u8; 32],
    /// Digest of the publisher-signed provisional open.
    pub open_digest: [u8; 32],
    // Transitional local metadata used by the profile-4 source adapter. These
    // fields are deliberately not part of the replacement profile-5 grammar.
    pub source_transfer_id: [u8; 32],
    pub publication_id: [u8; 32],
    pub variant_id: [u8; 32],
    pub total_len: u64,
    pub attempt_nonce: [u8; 32],
    pub checkpoint_generation: u64,
    pub custody_digest: Option<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamAcceptV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub durable_plaintext_offset: u64,
    pub durable_ciphertext_offset: u64,
    pub next_segment_index: u64,
    pub plaintext_commitment: [u8; 32],
    pub ciphertext_commitment: [u8; 32],
    pub checkpoint_generation: u64,
    pub absolute_receive_limit: u64,
    pub max_extent_bytes: u32,
    pub checkpoint_batch_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamDataV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub offset: u64,
    pub bytes: Bytes,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamDataHeaderV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub offset: u64,
    pub extent_len: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamCheckpointV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub durable_plaintext_offset: u64,
    pub durable_ciphertext_offset: u64,
    pub next_segment_index: u64,
    pub plaintext_commitment: [u8; 32],
    pub ciphertext_commitment: [u8; 32],
    pub checkpoint_generation: u64,
    pub absolute_receive_limit: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamCheckpointAuthorityV1 {
    pub durable_plaintext_offset: u64,
    pub durable_ciphertext_offset: u64,
    pub next_segment_index: u64,
    pub plaintext_commitment: [u8; 32],
    pub ciphertext_commitment: [u8; 32],
    pub checkpoint_generation: u64,
    pub absolute_receive_limit: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamFinishV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub final_plaintext_offset: u64,
    pub final_ciphertext_offset: u64,
    pub signed_commitment: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamResultV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub final_plaintext_offset: u64,
    pub final_ciphertext_offset: u64,
    pub code: StreamResultCode,
    pub blob_id: [u8; 32],
    pub result_digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StreamResultAckV1 {
    pub transfer_id: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub sequence: u64,
    pub result_digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StreamFrame {
    Open(StreamOpenV1),
    Accept(StreamAcceptV1),
    Data(StreamDataV1),
    Checkpoint(StreamCheckpointV1),
    Finish(StreamFinishV1),
    Result(StreamResultV1),
    ResultAck(StreamResultAckV1),
}

fn context(v: u16, p: u16) -> Result<(), StreamError> {
    if v == 9 && p == 5 {
        Ok(())
    } else {
        Err(StreamError::invalid(
            "stream records require semantic v9 profile 5",
        ))
    }
}
fn nonce(v: &[u8; 32]) -> Result<(), StreamError> {
    if v.iter().all(|b| *b == 0) {
        Err(StreamError::invalid("zero attempt nonce"))
    } else {
        Ok(())
    }
}
fn nonzero(v: &[u8; 32], message: &'static str) -> Result<(), StreamError> {
    if v.iter().all(|byte| *byte == 0) {
        Err(StreamError::invalid(message))
    } else {
        Ok(())
    }
}
fn validate_checkpoint(
    plaintext: u64,
    ciphertext: u64,
    next_segment: u64,
    plaintext_commitment: &[u8; 32],
    ciphertext_commitment: &[u8; 32],
) -> Result<(), StreamError> {
    if plaintext > ciphertext
        || (plaintext == 0) != (ciphertext == 0)
        || (plaintext == 0) != (next_segment == 0)
        || plaintext_commitment == &[0; 32]
        || ciphertext_commitment == &[0; 32]
    {
        return Err(StreamError::invalid("invalid stream checkpoint"));
    }
    Ok(())
}
fn validate_credit(
    durable_ciphertext: u64,
    absolute_receive_limit: u64,
    max_extent: u32,
    checkpoint_batch: u32,
) -> Result<(), StreamError> {
    if max_extent as usize > MAX_STREAM_EXTENT_BYTES
        || checkpoint_batch == 0
        || checkpoint_batch > MAX_STREAM_CHECKPOINT_BATCH_BYTES
        || absolute_receive_limit < durable_ciphertext
        || absolute_receive_limit - durable_ciphertext
            < u64::from(checkpoint_batch) + u64::from(max_extent)
    {
        return Err(StreamError::invalid("invalid stream receive credit"));
    }
    Ok(())
}
fn extent(v: u32) -> Result<(), StreamError> {
    if v == 0 || v as usize > MAX_STREAM_EXTENT_BYTES {
        Err(StreamError::invalid("extent length out of bounds"))
    } else {
        Ok(())
    }
}
fn put_attempt(o: &mut Vec<u8>, id: &[u8; 32], n: &[u8; 32], s: u64) {
    o.extend_from_slice(id);
    o.extend_from_slice(n);
    o.extend_from_slice(&s.to_be_bytes());
}

impl StreamFrame {
    pub(crate) fn attempt_binding(&self) -> ([u8; 32], Option<u64>) {
        match self {
            Self::Open(value) => (value.attempt_nonce, None),
            Self::Accept(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Data(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Checkpoint(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Finish(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::Result(value) => (value.attempt_nonce, Some(value.sequence)),
            Self::ResultAck(value) => (value.attempt_nonce, Some(value.sequence)),
        }
    }

    pub(crate) fn encode_for_context(&self, v: u16, p: u16) -> Result<Vec<u8>, StreamError> {
        context(v, p)?;
        let mut o = MAGIC.to_vec();
        match self {
            Self::Open(x) => {
                nonce(&x.attempt_nonce)?;
                nonzero(&x.transfer_id, "zero stream identifier")?;
                nonzero(&x.open_digest, "zero open digest")?;
                o.push(0xd6);
                o.extend([x.class as u8, x.direction as u8]);
                o.extend(9u16.to_be_bytes());
                o.extend(5u16.to_be_bytes());
                o.extend(x.session_transcript);
                o.extend(x.exchange_id.to_be_bytes());
                o.extend(x.transfer_id);
                o.extend(x.open_digest);
                o.extend(x.attempt_nonce);
                o.extend(x.checkpoint_generation.to_be_bytes());
            }
            Self::Accept(x) => {
                nonce(&x.attempt_nonce)?;
                extent(x.max_extent_bytes)?;
                validate_credit(
                    x.durable_ciphertext_offset,
                    x.absolute_receive_limit,
                    x.max_extent_bytes,
                    x.checkpoint_batch_bytes,
                )?;
                validate_checkpoint(
                    x.durable_plaintext_offset,
                    x.durable_ciphertext_offset,
                    x.next_segment_index,
                    &x.plaintext_commitment,
                    &x.ciphertext_commitment,
                )?;
                o.push(0xd7);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.durable_plaintext_offset.to_be_bytes());
                o.extend(x.durable_ciphertext_offset.to_be_bytes());
                o.extend(x.next_segment_index.to_be_bytes());
                o.extend(x.plaintext_commitment);
                o.extend(x.ciphertext_commitment);
                o.extend(x.checkpoint_generation.to_be_bytes());
                o.extend(x.absolute_receive_limit.to_be_bytes());
                o.extend(x.max_extent_bytes.to_be_bytes());
                o.extend(x.checkpoint_batch_bytes.to_be_bytes());
            }
            Self::Data(x) => {
                nonce(&x.attempt_nonce)?;
                let l = u32::try_from(x.bytes.len())
                    .map_err(|_| StreamError::invalid("extent overflow"))?;
                extent(l)?;
                x.offset
                    .checked_add(l.into())
                    .ok_or_else(|| StreamError::invalid("offset overflow"))?;
                o.push(0xd8);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.offset.to_be_bytes());
                o.extend(l.to_be_bytes());
                o.extend(&x.bytes);
            }
            Self::Checkpoint(x) => {
                nonce(&x.attempt_nonce)?;
                validate_checkpoint(
                    x.durable_plaintext_offset,
                    x.durable_ciphertext_offset,
                    x.next_segment_index,
                    &x.plaintext_commitment,
                    &x.ciphertext_commitment,
                )?;
                if x.absolute_receive_limit < x.durable_ciphertext_offset {
                    return Err(StreamError::invalid(
                        "checkpoint credit precedes durable offset",
                    ));
                }
                o.push(0xd9);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.durable_plaintext_offset.to_be_bytes());
                o.extend(x.durable_ciphertext_offset.to_be_bytes());
                o.extend(x.next_segment_index.to_be_bytes());
                o.extend(x.plaintext_commitment);
                o.extend(x.ciphertext_commitment);
                o.extend(x.checkpoint_generation.to_be_bytes());
                o.extend(x.absolute_receive_limit.to_be_bytes());
            }
            Self::Finish(x) => {
                nonce(&x.attempt_nonce)?;
                if x.signed_commitment.is_empty()
                    || x.signed_commitment.len() > MAX_STREAM_EXTENT_BYTES
                {
                    return Err(StreamError::invalid(
                        "signed commitment length out of bounds",
                    ));
                }
                o.push(0xda);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.final_plaintext_offset.to_be_bytes());
                o.extend(x.final_ciphertext_offset.to_be_bytes());
                o.extend((x.signed_commitment.len() as u32).to_be_bytes());
                o.extend(&x.signed_commitment);
            }
            Self::Result(x) => {
                nonce(&x.attempt_nonce)?;
                o.push(0xdb);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.final_plaintext_offset.to_be_bytes());
                o.extend(x.final_ciphertext_offset.to_be_bytes());
                o.push(x.code as u8);
                o.extend(x.blob_id);
                o.extend(x.result_digest);
            }
            Self::ResultAck(x) => {
                nonce(&x.attempt_nonce)?;
                o.push(0xdc);
                put_attempt(&mut o, &x.transfer_id, &x.attempt_nonce, x.sequence);
                o.extend(x.result_digest);
            }
        }
        Ok(o)
    }
    pub(crate) fn decode_for_context(v: u16, p: u16, b: &[u8]) -> Result<Self, StreamError> {
        context(v, p)?;
        if b.len() < 5 || &b[..4] != MAGIC {
            return Err(StreamError::invalid("invalid stream frame"));
        }
        if b[4] == 0xd8 {
            return decode_data(b).map(Self::Data);
        }
        let mut r = Reader::new(&b[5..]);
        let f = match b[4] {
            0xd6 => {
                let class = StreamClass::decode(r.u8()?)?;
                let direction = StreamDirection::decode(r.u8()?)?;
                if r.u16() != Ok(9) || r.u16() != Ok(5) {
                    return Err(StreamError::invalid("open binding differs"));
                }
                let session_transcript = r.array()?;
                let exchange_id = r.u64()?;
                let transfer_id = r.array()?;
                nonzero(&transfer_id, "zero stream identifier")?;
                let open_digest = r.array()?;
                nonzero(&open_digest, "zero open digest")?;
                let attempt_nonce = r.array()?;
                nonce(&attempt_nonce)?;
                let checkpoint_generation = r.u64()?;
                Self::Open(StreamOpenV1 {
                    class,
                    direction,
                    session_transcript,
                    exchange_id,
                    transfer_id,
                    open_digest,
                    source_transfer_id: [0; 32],
                    publication_id: [0; 32],
                    variant_id: [0; 32],
                    total_len: 0,
                    attempt_nonce,
                    checkpoint_generation,
                    custody_digest: None,
                })
            }
            0xd7 => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                let x = StreamAcceptV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    durable_plaintext_offset: r.u64()?,
                    durable_ciphertext_offset: r.u64()?,
                    next_segment_index: r.u64()?,
                    plaintext_commitment: r.array()?,
                    ciphertext_commitment: r.array()?,
                    checkpoint_generation: r.u64()?,
                    absolute_receive_limit: r.u64()?,
                    max_extent_bytes: r.u32()?,
                    checkpoint_batch_bytes: r.u32()?,
                };
                extent(x.max_extent_bytes)?;
                validate_credit(
                    x.durable_ciphertext_offset,
                    x.absolute_receive_limit,
                    x.max_extent_bytes,
                    x.checkpoint_batch_bytes,
                )?;
                validate_checkpoint(
                    x.durable_plaintext_offset,
                    x.durable_ciphertext_offset,
                    x.next_segment_index,
                    &x.plaintext_commitment,
                    &x.ciphertext_commitment,
                )?;
                Self::Accept(x)
            }
            0xd9 => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                let x = StreamCheckpointV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    durable_plaintext_offset: r.u64()?,
                    durable_ciphertext_offset: r.u64()?,
                    next_segment_index: r.u64()?,
                    plaintext_commitment: r.array()?,
                    ciphertext_commitment: r.array()?,
                    checkpoint_generation: r.u64()?,
                    absolute_receive_limit: r.u64()?,
                };
                validate_checkpoint(
                    x.durable_plaintext_offset,
                    x.durable_ciphertext_offset,
                    x.next_segment_index,
                    &x.plaintext_commitment,
                    &x.ciphertext_commitment,
                )?;
                if x.absolute_receive_limit < x.durable_ciphertext_offset {
                    return Err(StreamError::invalid("invalid checkpoint"));
                }
                Self::Checkpoint(x)
            }
            0xda => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                Self::Finish(StreamFinishV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    final_plaintext_offset: r.u64()?,
                    final_ciphertext_offset: r.u64()?,
                    signed_commitment: r.u32_bytes(MAX_STREAM_EXTENT_BYTES)?.to_vec(),
                })
            }
            0xdb => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                Self::Result(StreamResultV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    final_plaintext_offset: r.u64()?,
                    final_ciphertext_offset: r.u64()?,
                    code: StreamResultCode::decode(r.u8()?)?,
                    blob_id: r.array()?,
                    result_digest: r.array()?,
                })
            }
            0xdc => {
                let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
                Self::ResultAck(StreamResultAckV1 {
                    transfer_id,
                    attempt_nonce,
                    sequence,
                    result_digest: r.array()?,
                })
            }
            _ => return Err(StreamError::invalid("unknown stream tag")),
        };
        r.finish()?;
        Ok(f)
    }
}

impl StreamDataHeaderV1 {
    pub(crate) fn decode_for_context(v: u16, p: u16, b: &[u8]) -> Result<Self, StreamError> {
        context(v, p)?;
        if b.len() != STREAM_DATA_FIXED_BYTES || &b[..4] != MAGIC || b[4] != 0xd8 {
            return Err(StreamError::invalid("data header differs"));
        }
        let mut r = Reader::new(&b[5..]);
        let (transfer_id, attempt_nonce, sequence) = r.attempt()?;
        let offset = r.u64()?;
        let extent_len = r.u32()?;
        r.finish()?;
        extent(extent_len)?;
        offset
            .checked_add(extent_len.into())
            .ok_or_else(|| StreamError::invalid("offset overflow"))?;
        Ok(Self {
            transfer_id,
            attempt_nonce,
            sequence,
            offset,
            extent_len,
        })
    }
    pub(crate) fn decode_body(self, b: &[u8]) -> Result<StreamDataV1, StreamError> {
        if b.len() != self.extent_len as usize {
            return Err(StreamError::invalid("data body length differs"));
        }
        Ok(StreamDataV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.attempt_nonce,
            sequence: self.sequence,
            offset: self.offset,
            bytes: Bytes::copy_from_slice(b),
        })
    }
}
fn decode_data(b: &[u8]) -> Result<StreamDataV1, StreamError> {
    if b.len() < STREAM_DATA_FIXED_BYTES {
        return Err(StreamError::invalid("truncated data header"));
    }
    StreamDataHeaderV1::decode_for_context(9, 5, &b[..STREAM_DATA_FIXED_BYTES])?
        .decode_body(&b[STREAM_DATA_FIXED_BYTES..])
}

pub(crate) fn decode_owned_data_for_context(
    v: u16,
    p: u16,
    encoded: Bytes,
) -> Result<StreamFrame, StreamError> {
    if encoded.len() < STREAM_DATA_FIXED_BYTES {
        return Err(StreamError::invalid("truncated data header"));
    }
    let header = StreamDataHeaderV1::decode_for_context(v, p, &encoded[..STREAM_DATA_FIXED_BYTES])?;
    let body = encoded.slice(STREAM_DATA_FIXED_BYTES..);
    if body.len() != header.extent_len as usize {
        return Err(StreamError::invalid("data body length differs"));
    }
    Ok(StreamFrame::Data(StreamDataV1 {
        transfer_id: header.transfer_id,
        attempt_nonce: header.attempt_nonce,
        sequence: header.sequence,
        offset: header.offset,
        bytes: body,
    }))
}

struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamRetry {
    CreditBlocked,
    DuplicateBelowCheckpoint,
    TransportLost,
    SettlementPending,
}
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // Control frames are bounded and remain stack-owned.
pub(crate) enum StreamAction {
    Send(StreamFrame),
    Persist { through: u64 },
    Promote,
    Retry(StreamRetry),
    Terminal(StreamResultCode),
}

#[derive(Debug)]
pub(crate) struct StreamSenderState {
    transfer_id: [u8; 32],
    nonce: [u8; 32],
    total: u64,
    durable_plaintext: u64,
    durable: u64,
    next_segment_index: u64,
    plaintext_commitment: [u8; 32],
    ciphertext_commitment: [u8; 32],
    next: u64,
    limit: u64,
    max_extent: u32,
    generation: u64,
    send_sequence: u64,
    control_sequence: u64,
    last_result: Option<(StreamResultV1, StreamResultAckV1)>,
}
impl StreamSenderState {
    pub(crate) fn new(transfer_id: [u8; 32], nonce: [u8; 32], total: u64) -> Self {
        Self {
            transfer_id,
            nonce,
            total,
            durable_plaintext: 0,
            durable: 0,
            next_segment_index: 0,
            plaintext_commitment: [0; 32],
            ciphertext_commitment: [0; 32],
            next: 0,
            limit: 0,
            max_extent: 0,
            generation: 0,
            send_sequence: 0,
            control_sequence: 0,
            last_result: None,
        }
    }
    pub(crate) const fn transport_lost(&self) -> StreamAction {
        StreamAction::Retry(StreamRetry::TransportLost)
    }
    pub(crate) const fn durable_offset(&self) -> u64 {
        self.durable
    }
    pub(crate) const fn next_offset(&self) -> u64 {
        self.next
    }
    pub(crate) const fn receive_limit(&self) -> u64 {
        self.limit
    }
    pub(crate) const fn max_extent_bytes(&self) -> u32 {
        self.max_extent
    }
    pub(crate) const fn checkpoint_generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn accept(&mut self, x: StreamAcceptV1) -> Result<(), StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if x.sequence != 0 {
            return Err(StreamError::invalid("invalid stream acceptance"));
        }
        extent(x.max_extent_bytes)?;
        validate_credit(
            x.durable_ciphertext_offset,
            x.absolute_receive_limit,
            x.max_extent_bytes,
            x.checkpoint_batch_bytes,
        )?;
        validate_checkpoint(
            x.durable_plaintext_offset,
            x.durable_ciphertext_offset,
            x.next_segment_index,
            &x.plaintext_commitment,
            &x.ciphertext_commitment,
        )?;
        self.durable_plaintext = x.durable_plaintext_offset;
        self.durable = x.durable_ciphertext_offset;
        self.next_segment_index = x.next_segment_index;
        self.plaintext_commitment = x.plaintext_commitment;
        self.ciphertext_commitment = x.ciphertext_commitment;
        self.next = x.durable_ciphertext_offset;
        self.limit = x.absolute_receive_limit;
        self.max_extent = x.max_extent_bytes;
        self.generation = x.checkpoint_generation;
        self.control_sequence = 1;
        Ok(())
    }
    pub(crate) fn send_extent(&mut self, bytes: Vec<u8>) -> Result<StreamAction, StreamError> {
        let len =
            u32::try_from(bytes.len()).map_err(|_| StreamError::invalid("extent overflow"))?;
        extent(len)?;
        if len > self.max_extent {
            return Err(StreamError::invalid("extent exceeds negotiated maximum"));
        }
        let end = self
            .next
            .checked_add(len.into())
            .ok_or_else(|| StreamError::invalid("offset overflow"))?;
        if end > self.limit {
            return Ok(StreamAction::Retry(StreamRetry::CreditBlocked));
        }
        if end > self.total {
            return Err(StreamError::invalid("data exceeds declared length"));
        }
        let f = StreamDataV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            offset: self.next,
            bytes: bytes.into(),
        };
        self.send_sequence += 1;
        self.next = end;
        Ok(StreamAction::Send(StreamFrame::Data(f)))
    }
    pub(crate) fn checkpoint(&mut self, x: StreamCheckpointV1) -> Result<(), StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        let heartbeat = x.durable_ciphertext_offset == self.durable
            && x.checkpoint_generation == self.generation;
        if x.sequence != self.control_sequence
            || x.durable_plaintext_offset < self.durable_plaintext
            || x.durable_ciphertext_offset < self.durable
            || x.durable_ciphertext_offset > self.next
            || x.next_segment_index < self.next_segment_index
            || x.checkpoint_generation < self.generation
            || ((x.durable_ciphertext_offset == self.durable)
                != (x.checkpoint_generation == self.generation))
            || (heartbeat
                && (x.durable_plaintext_offset != self.durable_plaintext
                    || x.next_segment_index != self.next_segment_index
                    || x.plaintext_commitment != self.plaintext_commitment
                    || x.ciphertext_commitment != self.ciphertext_commitment))
            || x.absolute_receive_limit < self.limit
        {
            return Err(StreamError::invalid("invalid cumulative checkpoint"));
        }
        self.control_sequence += 1;
        self.durable_plaintext = x.durable_plaintext_offset;
        self.durable = x.durable_ciphertext_offset;
        self.next_segment_index = x.next_segment_index;
        self.plaintext_commitment = x.plaintext_commitment;
        self.ciphertext_commitment = x.ciphertext_commitment;
        self.generation = x.checkpoint_generation;
        self.limit = x.absolute_receive_limit;
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> Result<StreamAction, StreamError> {
        self.finish_with_commitment(vec![1])
    }
    pub(crate) fn finish_with_commitment(
        &mut self,
        signed_commitment: Vec<u8>,
    ) -> Result<StreamAction, StreamError> {
        self.finish_bound(self.total, signed_commitment)
    }
    pub(crate) fn finish_bound(
        &mut self,
        final_plaintext_offset: u64,
        signed_commitment: Vec<u8>,
    ) -> Result<StreamAction, StreamError> {
        if self.next != self.total {
            return Err(StreamError::invalid(
                "stream finish precedes declared length",
            ));
        }
        let f = StreamFinishV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            final_plaintext_offset,
            final_ciphertext_offset: self.total,
            signed_commitment,
        };
        self.send_sequence += 1;
        Ok(StreamAction::Send(StreamFrame::Finish(f)))
    }
    pub(crate) fn result(
        &mut self,
        x: StreamResultV1,
    ) -> Result<(StreamAction, StreamAction), StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if let Some((result, ack)) = &self.last_result {
            if result == &x {
                return Ok((
                    StreamAction::Send(StreamFrame::ResultAck(ack.clone())),
                    StreamAction::Terminal(x.code),
                ));
            }
            return Err(StreamError::invalid("terminal stream result changed"));
        }
        if x.sequence != self.control_sequence
            || x.final_ciphertext_offset != self.total
            || (self.durable == self.total && x.final_plaintext_offset != self.durable_plaintext)
        {
            return Err(StreamError::invalid("stream result binding differs"));
        }
        self.control_sequence += 1;
        let ack = StreamResultAckV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            result_digest: x.result_digest,
        };
        self.send_sequence += 1;
        self.last_result = Some((x.clone(), ack.clone()));
        Ok((
            StreamAction::Send(StreamFrame::ResultAck(ack)),
            StreamAction::Terminal(x.code),
        ))
    }
    fn identity(&self, id: &[u8; 32], n: &[u8; 32]) -> Result<(), StreamError> {
        if id == &self.transfer_id && n == &self.nonce {
            Ok(())
        } else {
            Err(StreamError::invalid("stream attempt identity differs"))
        }
    }
}

#[derive(Debug)]
pub(crate) struct StreamReceiverState {
    transfer_id: [u8; 32],
    nonce: [u8; 32],
    total: u64,
    durable_plaintext: u64,
    durable: u64,
    next_segment_index: u64,
    plaintext_commitment: [u8; 32],
    ciphertext_commitment: [u8; 32],
    received: u64,
    limit: u64,
    generation: u64,
    max_extent: u32,
    checkpoint_batch: u32,
    receive_sequence: u64,
    send_sequence: u64,
    result_digest: Option<[u8; 32]>,
    last_finish: Option<StreamFinishV1>,
    result_frame: Option<StreamResultV1>,
    last_ack: Option<StreamResultAckV1>,
    terminal_code: Option<StreamResultCode>,
}
impl StreamReceiverState {
    pub(crate) fn new(
        open: &StreamOpenV1,
        durable: u64,
        generation: u64,
        limit: u64,
        max_extent: u32,
    ) -> Result<Self, StreamError> {
        nonce(&open.attempt_nonce)?;
        extent(max_extent)?;
        if durable > limit || durable > open.total_len {
            return Err(StreamError::invalid("receiver bounds differ"));
        }
        Ok(Self {
            transfer_id: open.transfer_id,
            nonce: open.attempt_nonce,
            total: open.total_len,
            durable_plaintext: durable,
            durable,
            next_segment_index: durable.div_ceil(MAX_STREAM_EXTENT_BYTES as u64),
            plaintext_commitment: [1; 32],
            ciphertext_commitment: [1; 32],
            received: durable,
            limit,
            generation,
            max_extent,
            checkpoint_batch: 1,
            receive_sequence: 0,
            send_sequence: 0,
            result_digest: None,
            last_finish: None,
            result_frame: None,
            last_ack: None,
            terminal_code: None,
        })
    }
    pub(crate) fn reopen(
        previous_nonce: &[u8; 32],
        open: &StreamOpenV1,
        durable: u64,
        generation: u64,
        limit: u64,
        max_extent: u32,
    ) -> Result<Self, StreamError> {
        if previous_nonce == &open.attempt_nonce {
            return Err(StreamError::invalid("stream attempt nonce was reused"));
        }
        Self::new(open, durable, generation, limit, max_extent)
    }
    pub(crate) fn reopen_from_authority(
        previous_nonce: &[u8; 32],
        open: &StreamOpenV1,
        authority: StreamCheckpointAuthorityV1,
        max_extent: u32,
        checkpoint_batch: u32,
    ) -> Result<Self, StreamError> {
        if previous_nonce == &open.attempt_nonce {
            return Err(StreamError::invalid("stream retry authority differs"));
        }
        Self::new_from_authority(open, authority, max_extent, checkpoint_batch)
    }
    pub(crate) fn new_from_authority(
        open: &StreamOpenV1,
        authority: StreamCheckpointAuthorityV1,
        max_extent: u32,
        checkpoint_batch: u32,
    ) -> Result<Self, StreamError> {
        if open.checkpoint_generation != authority.checkpoint_generation
            || authority.durable_ciphertext_offset > open.total_len
        {
            return Err(StreamError::invalid("stream retry authority differs"));
        }
        nonce(&open.attempt_nonce)?;
        extent(max_extent)?;
        validate_checkpoint(
            authority.durable_plaintext_offset,
            authority.durable_ciphertext_offset,
            authority.next_segment_index,
            &authority.plaintext_commitment,
            &authority.ciphertext_commitment,
        )?;
        validate_credit(
            authority.durable_ciphertext_offset,
            authority.absolute_receive_limit,
            max_extent,
            checkpoint_batch,
        )?;
        Ok(Self {
            transfer_id: open.transfer_id,
            nonce: open.attempt_nonce,
            total: open.total_len,
            durable_plaintext: authority.durable_plaintext_offset,
            durable: authority.durable_ciphertext_offset,
            next_segment_index: authority.next_segment_index,
            plaintext_commitment: authority.plaintext_commitment,
            ciphertext_commitment: authority.ciphertext_commitment,
            received: authority.durable_ciphertext_offset,
            limit: authority.absolute_receive_limit,
            generation: authority.checkpoint_generation,
            max_extent,
            checkpoint_batch,
            receive_sequence: 0,
            send_sequence: 0,
            result_digest: None,
            last_finish: None,
            result_frame: None,
            last_ack: None,
            terminal_code: None,
        })
    }
    pub(crate) fn accept(&mut self, batch: u32) -> Result<StreamAction, StreamError> {
        if batch == 0 || batch > MAX_STREAM_CHECKPOINT_BATCH_BYTES {
            return Err(StreamError::invalid("checkpoint batch out of bounds"));
        }
        self.checkpoint_batch = batch;
        self.accept_authority()
    }
    pub(crate) fn accept_authority(&mut self) -> Result<StreamAction, StreamError> {
        validate_credit(
            self.durable,
            self.limit,
            self.max_extent,
            self.checkpoint_batch,
        )?;
        let f = StreamAcceptV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            durable_plaintext_offset: self.durable_plaintext,
            durable_ciphertext_offset: self.durable,
            next_segment_index: self.next_segment_index,
            plaintext_commitment: self.plaintext_commitment,
            ciphertext_commitment: self.ciphertext_commitment,
            checkpoint_generation: self.generation,
            absolute_receive_limit: self.limit,
            max_extent_bytes: self.max_extent,
            checkpoint_batch_bytes: self.checkpoint_batch,
        };
        self.send_sequence += 1;
        Ok(StreamAction::Send(StreamFrame::Accept(f)))
    }
    pub(crate) fn data(&mut self, x: &StreamDataV1) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if x.sequence != self.receive_sequence {
            return Err(StreamError::invalid("stream data sequence differs"));
        }
        let len =
            u32::try_from(x.bytes.len()).map_err(|_| StreamError::invalid("extent overflow"))?;
        extent(len)?;
        if len > self.max_extent {
            return Err(StreamError::invalid("extent exceeds maximum"));
        }
        let end = x
            .offset
            .checked_add(len.into())
            .ok_or_else(|| StreamError::invalid("offset overflow"))?;
        if end <= self.durable {
            self.receive_sequence += 1;
            return Ok(StreamAction::Retry(StreamRetry::DuplicateBelowCheckpoint));
        }
        if x.offset != self.received || end > self.limit || end > self.total {
            return Err(StreamError::invalid(
                "stream data gap overlap or credit violation",
            ));
        }
        self.receive_sequence += 1;
        self.received = end;
        Ok(StreamAction::Persist { through: end })
    }
    pub(crate) fn persisted(
        &mut self,
        through: u64,
        generation: u64,
        new_limit: u64,
    ) -> Result<StreamAction, StreamError> {
        self.persisted_authority(StreamCheckpointAuthorityV1 {
            durable_plaintext_offset: through,
            durable_ciphertext_offset: through,
            next_segment_index: through.div_ceil(MAX_STREAM_EXTENT_BYTES as u64),
            plaintext_commitment: [1; 32],
            ciphertext_commitment: [1; 32],
            checkpoint_generation: generation,
            absolute_receive_limit: new_limit,
        })
    }
    pub(crate) fn persisted_authority(
        &mut self,
        authority: StreamCheckpointAuthorityV1,
    ) -> Result<StreamAction, StreamError> {
        validate_checkpoint(
            authority.durable_plaintext_offset,
            authority.durable_ciphertext_offset,
            authority.next_segment_index,
            &authority.plaintext_commitment,
            &authority.ciphertext_commitment,
        )?;
        if authority.durable_plaintext_offset < self.durable_plaintext
            || authority.durable_ciphertext_offset < self.durable
            || authority.durable_ciphertext_offset > self.received
            || authority.next_segment_index < self.next_segment_index
            || authority.checkpoint_generation < self.generation
            || ((authority.durable_ciphertext_offset == self.durable)
                != (authority.checkpoint_generation == self.generation))
            || authority.absolute_receive_limit < self.limit
        {
            return Err(StreamError::invalid("invalid durable checkpoint"));
        }
        self.durable_plaintext = authority.durable_plaintext_offset;
        self.durable = authority.durable_ciphertext_offset;
        self.next_segment_index = authority.next_segment_index;
        self.plaintext_commitment = authority.plaintext_commitment;
        self.ciphertext_commitment = authority.ciphertext_commitment;
        self.generation = authority.checkpoint_generation;
        self.limit = authority.absolute_receive_limit;
        let f = StreamCheckpointV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            durable_plaintext_offset: authority.durable_plaintext_offset,
            durable_ciphertext_offset: authority.durable_ciphertext_offset,
            next_segment_index: authority.next_segment_index,
            plaintext_commitment: authority.plaintext_commitment,
            ciphertext_commitment: authority.ciphertext_commitment,
            checkpoint_generation: authority.checkpoint_generation,
            absolute_receive_limit: authority.absolute_receive_limit,
        };
        self.send_sequence += 1;
        Ok(StreamAction::Send(StreamFrame::Checkpoint(f)))
    }
    pub(crate) fn finish(&mut self, x: StreamFinishV1) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if self.last_finish.as_ref() == Some(&x) {
            return Ok(self.result_frame.clone().map_or(
                StreamAction::Retry(StreamRetry::SettlementPending),
                |result| StreamAction::Send(StreamFrame::Result(result)),
            ));
        }
        if x.sequence != self.receive_sequence
            || x.final_ciphertext_offset != self.total
            || self.received != self.total
            || self.durable != self.total
        {
            return Err(StreamError::invalid("finish before durable completion"));
        }
        self.receive_sequence += 1;
        self.last_finish = Some(x);
        Ok(StreamAction::Promote)
    }
    pub(crate) fn promoted(
        &mut self,
        code: StreamResultCode,
        digest: [u8; 32],
    ) -> Result<StreamAction, StreamError> {
        self.promoted_blob(code, digest, digest)
    }
    pub(crate) fn promoted_blob(
        &mut self,
        code: StreamResultCode,
        blob_id: [u8; 32],
        digest: [u8; 32],
    ) -> Result<StreamAction, StreamError> {
        if let Some(result) = &self.result_frame {
            if result.code == code && result.blob_id == blob_id && result.result_digest == digest {
                return Ok(StreamAction::Send(StreamFrame::Result(result.clone())));
            }
            return Err(StreamError::invalid("terminal stream result changed"));
        }
        self.result_digest = Some(digest);
        let f = StreamResultV1 {
            transfer_id: self.transfer_id,
            attempt_nonce: self.nonce,
            sequence: self.send_sequence,
            final_plaintext_offset: self.durable_plaintext,
            final_ciphertext_offset: self.total,
            code,
            blob_id,
            result_digest: digest,
        };
        self.send_sequence += 1;
        self.result_frame = Some(f.clone());
        self.terminal_code = Some(code);
        Ok(StreamAction::Send(StreamFrame::Result(f)))
    }
    pub(crate) fn result_ack(
        &mut self,
        x: StreamResultAckV1,
        code: StreamResultCode,
    ) -> Result<StreamAction, StreamError> {
        self.identity(&x.transfer_id, &x.attempt_nonce)?;
        if self.terminal_code != Some(code) {
            return Err(StreamError::invalid("terminal result code differs"));
        }
        if self.last_ack.as_ref() == Some(&x) {
            return Ok(StreamAction::Terminal(self.terminal_code.ok_or_else(
                || StreamError::invalid("terminal result is missing"),
            )?));
        }
        if x.sequence != self.receive_sequence || Some(x.result_digest) != self.result_digest {
            return Err(StreamError::invalid("result acknowledgement differs"));
        }
        self.receive_sequence += 1;
        self.last_ack = Some(x);
        Ok(StreamAction::Terminal(code))
    }
    fn identity(&self, id: &[u8; 32], n: &[u8; 32]) -> Result<(), StreamError> {
        if id == &self.transfer_id && n == &self.nonce {
            Ok(())
        } else {
            Err(StreamError::invalid("stream attempt identity differs"))
        }
    }
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], StreamError> {
        let e = self
            .o
            .checked_add(n)
            .ok_or_else(|| StreamError::invalid("length overflow"))?;
        let v = self
            .b
            .get(self.o..e)
            .ok_or_else(|| StreamError::invalid("truncated stream frame"))?;
        self.o = e;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], StreamError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StreamError::invalid("fixed field differs"))
    }
    fn u8(&mut self) -> Result<u8, StreamError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, StreamError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, StreamError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, StreamError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u32_bytes(&mut self, maximum: usize) -> Result<&'a [u8], StreamError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| StreamError::invalid("body length overflow"))?;
        if len == 0 || len > maximum {
            return Err(StreamError::invalid("body length out of bounds"));
        }
        self.take(len)
    }
    fn attempt(&mut self) -> Result<([u8; 32], [u8; 32], u64), StreamError> {
        let id = self.array()?;
        let n = self.array()?;
        nonce(&n)?;
        Ok((id, n, self.u64()?))
    }
    fn finish(self) -> Result<(), StreamError> {
        if self.o == self.b.len() {
            Ok(())
        } else {
            Err(StreamError::invalid("trailing stream bytes"))
        }
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode(input: &[u8]) {
    let id = [1; 32];
    let attempt_nonce = [2; 32];
    let seeded = match input {
        b"d6" => Some(StreamFrame::Open(StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [3; 32],
            exchange_id: 1,
            transfer_id: id,
            open_digest: [7; 32],
            source_transfer_id: [4; 32],
            publication_id: [5; 32],
            variant_id: [6; 32],
            total_len: 1,
            attempt_nonce,
            checkpoint_generation: 4,
            custody_digest: None,
        })),
        b"d7" => Some(StreamFrame::Accept(StreamAcceptV1 {
            transfer_id: id,
            attempt_nonce,
            sequence: 0,
            durable_plaintext_offset: 0,
            durable_ciphertext_offset: 0,
            next_segment_index: 0,
            plaintext_commitment: [7; 32],
            ciphertext_commitment: [8; 32],
            checkpoint_generation: 0,
            absolute_receive_limit: 2,
            max_extent_bytes: 1,
            checkpoint_batch_bytes: 1,
        })),
        b"d8" => Some(StreamFrame::Data(StreamDataV1 {
            transfer_id: id,
            attempt_nonce,
            sequence: 0,
            offset: 0,
            bytes: vec![0].into(),
        })),
        b"d9" => Some(StreamFrame::Checkpoint(StreamCheckpointV1 {
            transfer_id: id,
            attempt_nonce,
            sequence: 1,
            durable_plaintext_offset: 0,
            durable_ciphertext_offset: 0,
            next_segment_index: 0,
            plaintext_commitment: [7; 32],
            ciphertext_commitment: [8; 32],
            checkpoint_generation: 0,
            absolute_receive_limit: 1,
        })),
        b"da" => Some(StreamFrame::Finish(StreamFinishV1 {
            transfer_id: id,
            attempt_nonce,
            sequence: 1,
            final_plaintext_offset: 1,
            final_ciphertext_offset: 1,
            signed_commitment: vec![7],
        })),
        b"db" => Some(StreamFrame::Result(StreamResultV1 {
            transfer_id: id,
            attempt_nonce,
            sequence: 1,
            final_plaintext_offset: 1,
            final_ciphertext_offset: 1,
            code: StreamResultCode::Promoted,
            blob_id: [8; 32],
            result_digest: [7; 32],
        })),
        b"dc" => Some(StreamFrame::ResultAck(StreamResultAckV1 {
            transfer_id: id,
            attempt_nonce,
            sequence: 2,
            result_digest: [7; 32],
        })),
        _ => None,
    };
    let candidate = seeded
        .as_ref()
        .and_then(|frame| frame.encode_for_context(9, 5).ok())
        .unwrap_or_else(|| input.to_vec());
    let Ok(decoded) = StreamFrame::decode_for_context(9, 5, &candidate) else {
        return;
    };
    if let StreamFrame::Data(data) = decoded {
        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [3; 32],
            exchange_id: 1,
            transfer_id: id,
            open_digest: [7; 32],
            source_transfer_id: [4; 32],
            publication_id: [5; 32],
            variant_id: [6; 32],
            total_len: 1,
            attempt_nonce,
            checkpoint_generation: 0,
            custody_digest: None,
        };
        if let Ok(mut receiver) = StreamReceiverState::new(&open, 0, 0, 1, 1) {
            let _ = receiver.data(&data);
        }
    }
}

#[cfg(test)]
mod replacement_profile_five_vectors {
    use super::*;

    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16)
                    .expect("hex byte")
            })
            .collect()
    }

    #[test]
    fn blob_stream_record_vectors() {
        let mut count = 0;
        for line in include_str!("../../../conformance/vectors/blob-stream-records-v2.tsv")
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let fields: Vec<_> = line.split('\t').collect();
            let bytes = unhex(fields[3]);
            let decoded = match fields[1] {
                "publication-open" | "publication-commit" | "publication-resume" => {
                    crate::frame::Frame::decode_for_semantic_profile(&bytes, 9, 5)
                        .and_then(|frame| {
                            frame.encode_for_semantic_profile(9, 5).and_then(|encoded| {
                                (encoded == bytes).then_some(()).ok_or_else(|| {
                                    crate::NodeError::Protocol(
                                        "Blob publication round-trip differs".into(),
                                    )
                                })
                            })
                        })
                        .map_err(|error| StreamError::invalid(error.to_string()))
                }
                "open" | "accept" | "data" | "checkpoint" | "finish" | "result" | "result-ack" => {
                    StreamFrame::decode_for_context(9, 5, &bytes).and_then(|frame| {
                        let encoded = frame.encode_for_context(9, 5)?;
                        if encoded == bytes {
                            Ok(())
                        } else {
                            Err(StreamError::invalid("stream frame round-trip differs"))
                        }
                    })
                }
                // Sequence fixtures are state-machine rejects, not individual records.
                "sequence" => Err(StreamError::invalid("invalid frame sequence")),
                kind => panic!("unknown vector kind {kind}"),
            };
            assert_eq!(
                decoded.is_ok(),
                fields[0] == "ACCEPT",
                "{} {}",
                fields[1],
                fields[2]
            );
            count += 1;
        }
        assert_eq!(count, 33);
    }
}

#[cfg(test)]
mod replacement_profile_five_state {
    use super::*;

    const STREAM: [u8; 32] = [0x11; 32];
    const NONCE: [u8; 32] = [0x22; 32];
    const PLAIN_ROOT: [u8; 32] = [0x51; 32];
    const CIPHER_ROOT: [u8; 32] = [0x52; 32];

    fn accept(durable: u64, generation: u64, credit: u64) -> StreamAcceptV1 {
        StreamAcceptV1 {
            transfer_id: STREAM,
            attempt_nonce: NONCE,
            sequence: 0,
            durable_plaintext_offset: durable,
            durable_ciphertext_offset: durable,
            next_segment_index: durable.div_ceil(MAX_STREAM_EXTENT_BYTES as u64),
            plaintext_commitment: PLAIN_ROOT,
            ciphertext_commitment: CIPHER_ROOT,
            checkpoint_generation: generation,
            absolute_receive_limit: credit,
            max_extent_bytes: MAX_STREAM_EXTENT_BYTES as u32,
            checkpoint_batch_bytes: MAX_STREAM_CHECKPOINT_BATCH_BYTES,
        }
    }

    #[test]
    fn sender_pipelines_against_absolute_credit_beyond_declared_length() {
        let total = 2 * MAX_STREAM_EXTENT_BYTES as u64;
        let mut sender = StreamSenderState::new(STREAM, NONCE, total);
        sender
            .accept(accept(0, 0, MIN_STREAM_RECEIVE_WINDOW_BYTES))
            .expect("credit is an absolute receiver allocation, not the Blob length");
        for byte in [0xa1, 0xa2] {
            assert!(matches!(
                sender
                    .send_extent(vec![byte; MAX_STREAM_EXTENT_BYTES])
                    .expect("send within credit and declared length"),
                StreamAction::Send(StreamFrame::Data(_))
            ));
        }
        assert!(sender.send_extent(vec![0xa3]).is_err());
    }

    #[test]
    fn receiver_credit_beyond_eof_preserves_small_and_completed_resume_bounds() {
        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [0x33; 32],
            exchange_id: 7,
            transfer_id: STREAM,
            open_digest: [0x44; 32],
            source_transfer_id: [0x55; 32],
            publication_id: [0x66; 32],
            variant_id: [0x77; 32],
            total_len: 1,
            attempt_nonce: NONCE,
            checkpoint_generation: 0,
            custody_digest: None,
        };
        let mut receiver = StreamReceiverState::new(&open, 0, 0, 2, 1).unwrap();
        let StreamAction::Send(StreamFrame::Accept(accepted)) = receiver.accept(1).unwrap() else {
            panic!("accept frame")
        };
        let mut sender = StreamSenderState::new(STREAM, NONCE, 1);
        sender.accept(accepted).unwrap();
        let StreamAction::Send(StreamFrame::Data(data)) = sender.send_extent(vec![0xa1]).unwrap()
        else {
            panic!("data frame")
        };
        assert_eq!(
            receiver.data(&data).unwrap(),
            StreamAction::Persist { through: 1 }
        );
        let overrun = StreamDataV1 {
            transfer_id: STREAM,
            attempt_nonce: NONCE,
            sequence: 1,
            offset: 1,
            bytes: vec![0xa2].into(),
        };
        assert!(receiver.data(&overrun).is_err());
        assert!(receiver.persisted(2, 1, 4).is_err());
        let StreamAction::Send(StreamFrame::Checkpoint(checkpoint)) =
            receiver.persisted(1, 1, 3).unwrap()
        else {
            panic!("checkpoint frame")
        };
        sender.checkpoint(checkpoint).unwrap();
        assert!(sender.send_extent(vec![0xa2]).is_err());

        // Reopening an already durable source still advertises a valid window
        // and reaches terminal settlement without accepting another byte.
        let mut completed_open = open;
        completed_open.checkpoint_generation = 1;
        let mut resumed = StreamReceiverState::new(&completed_open, 1, 1, 3, 1).unwrap();
        let StreamAction::Send(StreamFrame::Accept(accepted)) = resumed.accept(1).unwrap() else {
            panic!("resume accept frame")
        };
        let mut sender = StreamSenderState::new(STREAM, NONCE, 1);
        sender.accept(accepted).unwrap();
        let StreamAction::Send(StreamFrame::Finish(finish)) = sender.finish().unwrap() else {
            panic!("resume finish frame")
        };
        assert_eq!(resumed.finish(finish).unwrap(), StreamAction::Promote);
        assert!(StreamReceiverState::new(&completed_open, 2, 1, 3, 1).is_err());
    }

    #[test]
    fn grouped_checkpoints_preserve_old_authority_until_commit_and_replay_only_the_tail() {
        const MIB: u64 = 1024 * 1024;
        let mut open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [0x33; 32],
            exchange_id: 7,
            transfer_id: STREAM,
            open_digest: [0x44; 32],
            source_transfer_id: [0x55; 32],
            publication_id: [0x66; 32],
            variant_id: [0x77; 32],
            total_len: 160 * MIB,
            attempt_nonce: NONCE,
            checkpoint_generation: 0,
            custody_digest: None,
        };
        let mut durable = StreamCheckpointAuthorityV1 {
            durable_plaintext_offset: 0,
            durable_ciphertext_offset: 0,
            next_segment_index: 0,
            plaintext_commitment: PLAIN_ROOT,
            ciphertext_commitment: CIPHER_ROOT,
            checkpoint_generation: 0,
            absolute_receive_limit: 128 * MIB,
        };
        let mut receiver =
            StreamReceiverState::new_from_authority(&open, durable, MIB as u32, 15 * MIB as u32)
                .unwrap();
        let StreamAction::Send(StreamFrame::Accept(accepted)) =
            receiver.accept_authority().unwrap()
        else {
            panic!("acceptance frame");
        };
        let mut sender = StreamSenderState::new(STREAM, NONCE, open.total_len);
        sender.accept(accepted).unwrap();
        // Break caught: treating each bounded callback as a new durability
        // claim, or refusing an exact old checkpoint, prevents safe grouping.
        // Continue beyond the initial credit to prove committed groups refill it.
        for index in 0..135_u64 {
            let StreamAction::Send(StreamFrame::Data(data)) =
                sender.send_extent(vec![0x5a; MIB as usize]).unwrap()
            else {
                panic!("grouped transfer exhausted credit before its next commit");
            };
            let through = (index + 1) * MIB;
            assert_eq!(
                receiver.data(&data).unwrap(),
                StreamAction::Persist { through }
            );
            if (index + 1).is_multiple_of(15) {
                if (index + 1).is_multiple_of(60) {
                    durable = StreamCheckpointAuthorityV1 {
                        durable_plaintext_offset: through,
                        durable_ciphertext_offset: through,
                        next_segment_index: index + 1,
                        plaintext_commitment: [index as u8; 32],
                        ciphertext_commitment: [(index + 1) as u8; 32],
                        checkpoint_generation: (index + 1) / 60,
                        absolute_receive_limit: through + 128 * MIB,
                    };
                }
                let StreamAction::Send(StreamFrame::Checkpoint(checkpoint)) =
                    receiver.persisted_authority(durable).unwrap()
                else {
                    panic!("checkpoint frame");
                };
                sender.checkpoint(checkpoint).unwrap();
                assert_eq!(sender.durable_offset(), (index + 1) / 60 * 60 * MIB);
                assert_eq!(sender.receive_limit(), durable.absolute_receive_limit);
            }
        }
        assert_eq!(sender.next_offset(), 135 * MIB);
        assert_eq!(sender.durable_offset(), 120 * MIB);

        open.attempt_nonce = [0x23; 32];
        open.checkpoint_generation = 2;
        let mut resumed = StreamReceiverState::reopen_from_authority(
            &NONCE,
            &open,
            durable,
            MIB as u32,
            15 * MIB as u32,
        )
        .unwrap();
        let StreamAction::Send(StreamFrame::Accept(accepted)) = resumed.accept_authority().unwrap()
        else {
            panic!("resume acceptance");
        };
        assert_eq!(accepted.durable_ciphertext_offset, 120 * MIB);
        let mut retry = StreamSenderState::new(STREAM, open.attempt_nonce, open.total_len);
        retry.accept(accepted).unwrap();
        let StreamAction::Send(StreamFrame::Data(data)) =
            retry.send_extent(vec![0x5a; MIB as usize]).unwrap()
        else {
            panic!("replay frame");
        };
        assert_eq!(data.offset, 120 * MIB);
        assert_eq!(
            resumed.data(&data).unwrap(),
            StreamAction::Persist { through: 121 * MIB }
        );
    }

    #[test]
    fn unchanged_credit_heartbeat_must_preserve_checkpoint_authority() {
        let mut sender = StreamSenderState::new(STREAM, NONCE, 1);
        sender
            .accept(accept(0, 0, MIN_STREAM_RECEIVE_WINDOW_BYTES))
            .unwrap();
        let heartbeat = StreamCheckpointV1 {
            transfer_id: STREAM,
            attempt_nonce: NONCE,
            sequence: 1,
            durable_plaintext_offset: 0,
            durable_ciphertext_offset: 0,
            next_segment_index: 0,
            plaintext_commitment: PLAIN_ROOT,
            ciphertext_commitment: CIPHER_ROOT,
            checkpoint_generation: 0,
            absolute_receive_limit: MIN_STREAM_RECEIVE_WINDOW_BYTES,
        };
        sender.checkpoint(heartbeat.clone()).unwrap();
        let mut forked = heartbeat;
        forked.sequence = 2;
        forked.plaintext_commitment = [0x99; 32];
        assert!(sender.checkpoint(forked).is_err());
    }

    #[test]
    fn sender_rejects_receive_window_smaller_than_batch_plus_segment() {
        let mut sender = StreamSenderState::new(STREAM, NONCE, u64::MAX);
        assert!(
            sender
                .accept(accept(0, 0, MIN_STREAM_RECEIVE_WINDOW_BYTES - 1,))
                .is_err()
        );
    }

    #[test]
    fn finish_binds_distinct_declared_plaintext_and_ciphertext_lengths() {
        let plaintext = MAX_STREAM_EXTENT_BYTES as u64;
        let ciphertext = plaintext + 16;
        let mut sender = StreamSenderState::new(STREAM, NONCE, ciphertext);
        sender
            .accept(accept(0, 0, MIN_STREAM_RECEIVE_WINDOW_BYTES))
            .unwrap();
        sender
            .send_extent(vec![0xa1; MAX_STREAM_EXTENT_BYTES])
            .unwrap();
        sender.send_extent(vec![0xa2; 16]).unwrap();
        let StreamAction::Send(StreamFrame::Finish(finish)) = sender
            .finish_bound(plaintext, b"publisher-signed-final".to_vec())
            .unwrap()
        else {
            panic!("finish frame")
        };
        assert_eq!(finish.final_plaintext_offset, plaintext);
        assert_eq!(finish.final_ciphertext_offset, ciphertext);
        assert_eq!(finish.signed_commitment, b"publisher-signed-final");
    }

    #[test]
    fn terminal_result_binds_distinct_plaintext_and_wire_lengths() {
        for code in [StreamResultCode::Promoted, StreamResultCode::AlreadyPresent] {
            let open = StreamOpenV1 {
                class: StreamClass::Blob,
                direction: StreamDirection::ToSessionResponder,
                session_transcript: [0x33; 32],
                exchange_id: 7,
                transfer_id: STREAM,
                open_digest: [0x44; 32],
                source_transfer_id: [0; 32],
                publication_id: [0; 32],
                variant_id: [0; 32],
                total_len: 24,
                attempt_nonce: NONCE,
                checkpoint_generation: 1,
                custody_digest: None,
            };
            let authority = StreamCheckpointAuthorityV1 {
                durable_plaintext_offset: 8,
                durable_ciphertext_offset: 24,
                next_segment_index: 1,
                plaintext_commitment: PLAIN_ROOT,
                ciphertext_commitment: CIPHER_ROOT,
                checkpoint_generation: 1,
                absolute_receive_limit: 26,
            };
            let mut receiver =
                StreamReceiverState::new_from_authority(&open, authority, 1, 1).unwrap();
            let StreamAction::Send(StreamFrame::Accept(accepted)) =
                receiver.accept_authority().unwrap()
            else {
                panic!("accept frame")
            };
            let mut sender = StreamSenderState::new(STREAM, NONCE, 24);
            sender.accept(accepted).unwrap();
            let StreamAction::Send(StreamFrame::Finish(finish)) =
                sender.finish_bound(8, b"signed-final".to_vec()).unwrap()
            else {
                panic!("finish frame")
            };
            assert_eq!(receiver.finish(finish).unwrap(), StreamAction::Promote);
            let StreamAction::Send(StreamFrame::Result(result)) = receiver
                .promoted_blob(code, [0x71; 32], [0x72; 32])
                .unwrap()
            else {
                panic!("result frame")
            };
            assert_eq!(result.final_plaintext_offset, 8);
            assert_eq!(result.final_ciphertext_offset, 24);
            let mut wrong_plaintext = result.clone();
            wrong_plaintext.final_plaintext_offset = 24;
            assert!(sender.result(wrong_plaintext).is_err());
            let (StreamAction::Send(StreamFrame::ResultAck(ack)), StreamAction::Terminal(actual)) =
                sender.result(result).unwrap()
            else {
                panic!("terminal acknowledgement")
            };
            assert_eq!(actual, code);
            assert_eq!(
                receiver.result_ack(ack, code).unwrap(),
                StreamAction::Terminal(code)
            );
        }
    }

    #[test]
    fn promoted_result_keeps_blob_identity_separate_from_idempotency_digest() {
        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [0x33; 32],
            exchange_id: 7,
            transfer_id: STREAM,
            open_digest: [0x44; 32],
            source_transfer_id: [0; 32],
            publication_id: [0; 32],
            variant_id: [0; 32],
            total_len: 0,
            attempt_nonce: NONCE,
            checkpoint_generation: 0,
            custody_digest: None,
        };
        let mut receiver = StreamReceiverState::new(&open, 0, 0, 0, 1).unwrap();
        let blob_id = [0x71; 32];
        let result_digest = [0x72; 32];
        let first = receiver
            .promoted_blob(StreamResultCode::Promoted, blob_id, result_digest)
            .unwrap();
        assert_eq!(
            receiver
                .promoted_blob(StreamResultCode::Promoted, blob_id, result_digest)
                .unwrap(),
            first
        );
        let StreamAction::Send(StreamFrame::Result(result)) = first else {
            panic!("result frame")
        };
        assert_eq!(result.blob_id, blob_id);
        assert_eq!(result.result_digest, result_digest);
    }

    #[test]
    fn retry_uses_fresh_nonce_and_receiver_checkpoint_authority() {
        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [0x33; 32],
            exchange_id: 7,
            transfer_id: STREAM,
            open_digest: [0x44; 32],
            source_transfer_id: [0; 32],
            publication_id: [0; 32],
            variant_id: [0; 32],
            total_len: 64 * 1024 * 1024,
            attempt_nonce: [0x23; 32],
            checkpoint_generation: 4,
            custody_digest: None,
        };
        let authority = StreamCheckpointAuthorityV1 {
            durable_plaintext_offset: 16 * 1024 * 1024,
            durable_ciphertext_offset: 16 * 1024 * 1024 + 256,
            next_segment_index: 16,
            plaintext_commitment: [0x61; 32],
            ciphertext_commitment: [0x62; 32],
            checkpoint_generation: 4,
            absolute_receive_limit: 34 * 1024 * 1024,
        };
        let mut receiver = StreamReceiverState::reopen_from_authority(
            &NONCE,
            &open,
            authority,
            MAX_STREAM_EXTENT_BYTES as u32,
            MAX_STREAM_CHECKPOINT_BATCH_BYTES,
        )
        .unwrap();
        let StreamAction::Send(StreamFrame::Accept(accepted)) =
            receiver.accept_authority().unwrap()
        else {
            panic!("accept frame")
        };
        assert_eq!(accepted.attempt_nonce, [0x23; 32]);
        assert_eq!(accepted.durable_plaintext_offset, 16 * 1024 * 1024);
        assert_eq!(accepted.durable_ciphertext_offset, 16 * 1024 * 1024 + 256);
        assert_eq!(accepted.next_segment_index, 16);
        assert_eq!(accepted.plaintext_commitment, [0x61; 32]);
        assert_eq!(accepted.ciphertext_commitment, [0x62; 32]);
        assert_eq!(accepted.checkpoint_generation, 4);
    }
}
