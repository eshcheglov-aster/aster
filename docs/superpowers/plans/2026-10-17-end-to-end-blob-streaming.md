# End-to-End Blob Streaming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Clean Room — Privileged**

**Goal:** Replace Aster's staged, carrier-per-file Blob path with a single-pass, crash-resumable pipeline whose non-transport stages have measured headroom above the selected transport on the supported CM4 profile.

**Architecture:** Semantic v9/profile 5 admits a publisher-signed provisional intent, incrementally hashes and encrypts fixed-size segments, fans ciphertext into an append-only local pack and the active transport, and promotes only after a publisher-signed final commitment. Receiver credit advances from constant-sized durable pack checkpoints; application reads hold one authenticated session and stream sequentially without per-frame database writes.

**Tech Stack:** Rust 2024, Tokio, AES-256-GCM/HKDF-SHA-256, domain-separated SHA-256 Merkle accumulators, redb 4.2, ConnectRPC/protobuf bidirectional streaming, Iroh/QUIC, Python stdlib conformance oracle, Linux filesystem durability primitives, Raspberry Pi CM4 validation.

**Spec:** `docs/superpowers/specs/2026-10-17-end-to-end-blob-streaming-design.md`

## Global Constraints

- Semantic v9/profile 5 is replaced in place; do not preserve its unqualified frame grammar, vectors, pending state, or carrier-per-file layout.
- Semantic v7/v8/profile 4 remains byte-identical, but profile-4 partial state never resumes as profile 5.
- One successful publish reads each plaintext byte once and never creates a whole-Blob plaintext staging file.
- The profile-5 segment maximum is exactly 1 MiB; total length, offsets, counts, and allocation arithmetic are checked.
- Streaming memory, open descriptors, metadata, and recovery work are bounded independently of total Blob length.
- Provisional content is neither inventory-visible, application-readable, nor forwardable until the signed final commitment promotes it.
- No durable transaction or filesystem barrier occurs per application frame, transport frame, or segment.
- The initial durability threshold is 16 MiB with a 250-ms maximum interval; receive credit always exceeds the batch by at least one maximum segment.
- The pack, checkpoint journal, and final descriptor remain encrypted-content storage; plaintext never lands in the depot.
- Durable Blobs perform no custody-clock write during application reads; finite reads persist continuity only at bounded lifecycle checkpoints.
- The application API remains transport-blind and one transport carries data per logical attempt.
- Do not claim transport-limited operation unless end-to-end payload is at least 80% of same-path raw transport and every measured non-transport stage sustains at least 125% of that raw rate.
- Keep work local until explicitly asked to push; use focused local tests and CI evidence rather than a full local suite.

## File Structure

- `crates/aster-core/src/blob_stream.rs`: profile-5 IDs, signed intent/commitment bodies, fixed-width Merkle accumulator, segment encryption/decryption, and canonical pack-record codec.
- `crates/aster-core/src/source_blob.rs`: provider-owned signing, verification, content-key derivation, and streaming encryptor/decryptor construction.
- `crates/aster-core/src/lib.rs`: exports only the provider-safe streaming types and constants required by Store and node integration.
- `crates/aster-node/src/stream_transfer.rs`: transport-attempt frames, bounds, sender/receiver state machines, credit, checkpoint, and settlement.
- `crates/aster-node/src/frame.rs`: mission-protected provisional-open/final-commit records and semantic-v9 dispatch.
- `conformance/blob_stream_oracle.py` and `conformance/vectors/blob-stream-records-v1.tsv`: independent canonical vectors for the replacement grammar.
- `crates/aster-redb-store/src/blob/pack.rs`: pinned append-only pack, alternating checkpoint journal, final descriptor, recovery, sequential reader, and deletion primitives.
- `crates/aster-redb-store/src/blob/stream.rs`: provisional reservation/checkpoint/promotion transactions and idempotent operation binding.
- `crates/aster-redb-store/src/blob.rs`: profile-5 tables, quota/status integration, lifecycle/pressure roots, and exported Store interfaces.
- `crates/aster-redb-store/src/blob/deletion.rs`, `lifecycle.rs`, and `pressure.rs`: bounded cleanup and policy handling for provisional/final packs.
- `crates/aster-node/src/application/blob_stream.rs`: actor-owned local publish/read sessions and fixed buffer-budget permits.
- `crates/aster-node/src/application/blob.rs`: public selected-handle types and command routing; legacy profile-4 implementation remains isolated.
- `proto/aster/application/v1alpha1/aster.proto`: bidirectional publish responses and resume/checkpoint messages; authenticated read response remains server-streamed.
- `crates/aster-agent/src/blob_service.rs`: bridges ConnectRPC frames directly to node sessions without whole-file staging.
- `crates/asterctl/src/blob_publish.rs` and `blob_read.rs`: seekable resume, bounded request/response flow, and single final destination durability barrier.
- `crates/aster-node/src/runtime/blob_stream.rs`: provisional live fan-out, completed-pack forwarding, receiver pipeline, final settlement, and retry.
- `crates/aster-node/src/stream_transport.rs`: unchanged adapter contract plus stage-independent attempt progress; selector semantics remain transport-neutral.
- `crates/aster-node/src/runtime.rs`: status aggregation, lifecycle scheduling, and contact integration.
- `crates/aster-node/examples/blob_benchmark.rs` and `docs/validation/blob-streaming-performance.md`: stage benchmarks and retained physical evidence.

## Review Focus

- A client disconnects after the agent has accepted bytes but before a checkpoint: exact operation reopen returns only the durable offset, and replay neither duplicates nor skips content. Covered in Task 6.
- A finite publication expires between provisional open and final commitment: transfer time counts toward age and promotion rejects it without visibility. Covered in Task 4.
- The pack data barrier succeeds but the checkpoint journal or redb commit tears: reopen selects the last complete generation and ignores/truncates the unacknowledged tail. Covered in Task 3.
- A slow network falls behind local publication by more than the live buffer budget: the network cursor switches to the durable pack without blocking local completion or re-encrypting content. Covered in Task 7.
- A publisher sends a valid signed open and a conflicting signed finish for the same operation/stream ID: the Store retains a bounded conflict fence and never promotes either conflicting result. Covered in Task 4.

---

### Task 1: Incremental content identity and encrypted segment format

**Files:**
- Create: `crates/aster-core/src/blob_stream.rs`
- Modify: `crates/aster-core/src/source_blob.rs`
- Modify: `crates/aster-core/src/lib.rs`
- Test: inline unit tests in `crates/aster-core/src/blob_stream.rs`

**Interfaces:**
- Consumes: existing `BlobId`, `BlobMetadata`, `BlobPhysicalLineage`, `NodeId`, `Topic`, `Scope`, AES-GCM/HKDF/SHA-256 helpers.
- Produces: `BLOB_STREAM_SEGMENT_BYTES = 1_048_576`, `BlobPublicationStreamId`, `BlobStreamOpen`, `VerifiedBlobStreamOpen`, `BlobStreamAccumulator`, `BlobStreamAccumulatorCheckpoint`, `BlobStreamEncryptor`, `BlobStreamDecryptor`, `EncryptedBlobStreamSegment`, `BlobStreamFinalCommitment`, `VerifiedBlobStreamFinalCommitment`, and canonical encode/decode methods used by Tasks 2-7. Only `ReferenceEnvelopeSealer` can mint either `Verified*` capability or key-bearing stream state.

Exact public/provider-safe signatures:

```rust
impl BlobStreamAccumulator {
    pub fn new(domain: BlobStreamAccumulatorDomain) -> Self;
    pub fn push_segment(&mut self, index: u64, bytes: &[u8]) -> Result<(), BlobError>;
    pub fn checkpoint(&self) -> BlobStreamAccumulatorCheckpoint;
    pub fn restore(checkpoint: BlobStreamAccumulatorCheckpoint) -> Result<Self, BlobError>;
    pub fn finish(self, total_len: u64) -> Result<[u8; 32], BlobError>;
}

impl BlobStreamOpen {
    pub fn new(
        stream_id: BlobPublicationStreamId,
        publisher: NodeId,
        operation_key: Vec<u8>,
        mission_id: [u8; 32],
        publisher_counter: u64,
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
    ) -> Result<Self, BlobError>;
    pub fn encode(&self) -> Vec<u8>;
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobError>;
    pub fn digest(&self) -> [u8; 32];
}

impl BlobStreamFinalCommitment {
    pub fn new(
        open: &VerifiedBlobStreamOpen,
        plaintext_root: [u8; 32],
        ciphertext_root: [u8; 32],
        segment_count: u64,
        final_custody: Option<CustodySample>,
    ) -> Result<Self, BlobError>;
    pub fn blob_id(&self) -> BlobId;
    pub fn encode(&self) -> Vec<u8>;
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobError>;
}

impl ReferenceEnvelopeSealer {
    pub fn seal_blob_stream_open(
        &self,
        open: &BlobStreamOpen,
    ) -> Result<Vec<u8>, EnvelopeError>;
    pub fn verify_blob_stream_open(
        &self,
        signed_open: &[u8],
    ) -> Result<VerifiedBlobStreamOpen, EnvelopeError>;
    pub fn seal_blob_stream_commitment(
        &self,
        commitment: &BlobStreamFinalCommitment,
    ) -> Result<Vec<u8>, EnvelopeError>;
    pub fn verify_blob_stream_commitment(
        &self,
        open: &VerifiedBlobStreamOpen,
        signed_commitment: &[u8],
    ) -> Result<VerifiedBlobStreamFinalCommitment, EnvelopeError>;
    pub fn begin_blob_stream_encrypt(
        &self,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<BlobStreamEncryptor, EnvelopeError>;
    pub fn begin_blob_stream_decrypt(
        &self,
        open: &VerifiedBlobStreamOpen,
    ) -> Result<BlobStreamDecryptor, EnvelopeError>;
}

impl BlobStreamEncryptor {
    pub fn encrypt_segment(
        &mut self,
        index: u64,
        offset: u64,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<EncryptedBlobStreamSegment, BlobError>;
}

impl BlobStreamDecryptor {
    pub fn decrypt_segment(
        &mut self,
        segment: &EncryptedBlobStreamSegment,
    ) -> Result<Zeroizing<Vec<u8>>, BlobError>;
}
```

- [ ] **Step 1: Write failing accumulator and checkpoint tests**

Add tests named `blob_stream_accumulator_matches_one_shot_root`, `blob_stream_accumulator_restores_fixed_width_checkpoint`, and `blob_stream_accumulator_rejects_gap_duplicate_and_length_overflow`. Use literal roots for empty, one-byte, exactly 1-MiB, and 1-MiB-plus-one fixtures; assert checkpoint encoding has one fixed byte length regardless of populated tree depth.

- [ ] **Step 2: Run the accumulator tests and verify RED**

Run: `cargo test --locked -p aster-core blob_stream_accumulator --lib`

Expected: compile failure because the profile-5 accumulator types do not exist.

- [ ] **Step 3: Implement the fixed-width Merkle accumulator**

Implement `BlobStreamAccumulator::new(domain: BlobStreamAccumulatorDomain)`, `push_segment(&mut self, index: u64, bytes: &[u8])`, `checkpoint(&self) -> BlobStreamAccumulatorCheckpoint`, `restore(checkpoint)`, and `finish(self, total_len: u64) -> [u8; 32]`. Use domain-separated SHA-256 leaf/node/empty/final domains and a fixed array sufficient for checked `u64` byte lengths at 1-MiB segments; never serialize `sha2` internal state.

- [ ] **Step 4: Run accumulator tests and verify GREEN**

Run: `cargo test --locked -p aster-core blob_stream_accumulator --lib`

Expected: all named tests pass.

- [ ] **Step 5: Write failing segment crypto and binding tests**

Add `blob_stream_segment_round_trips_with_independent_aead`, `blob_stream_segment_rejects_wrong_open_offset_index_nonce_and_epoch`, and `blob_stream_final_commitment_binds_both_roots_and_metadata`. Mutation-check every canonical field and assert the derived `BlobId` changes when plaintext, length, segment format, media type, or schema ID changes.

- [ ] **Step 6: Run the segment tests and verify RED**

Run: `cargo test --locked -p aster-core blob_stream_segment --lib`

Expected: compile failure because segment encryption and final commitment are absent.

- [ ] **Step 7: Implement the stream format and crypto state**

Add constructors that validate nonzero declared length, nonzero publisher counter/policy revision, finite-TTL custody sample, 1-MiB maximum segments, exact contiguous offsets, checked nonce derivation, and bounded metadata. Derive the provisional content key inside `ReferenceEnvelopeSealer` from provider-owned scope/epoch material plus the signed publication salt; bind the open digest and segment header as AEAD associated data. A transport attempt nonce is not part of the publisher-signed open and instead belongs to Task 2 `StreamOpenV1`, permitting retry without resigning the logical publication. Keep key-bearing constructors private and zeroize key/plaintext buffers on drop.

- [ ] **Step 8: Run focused core tests**

Run: `cargo test --locked -p aster-core blob_stream --lib`

Expected: all accumulator, segment, commitment, and mutation tests pass.

- [ ] **Step 9: Commit**

```bash
git add crates/aster-core/src/blob_stream.rs crates/aster-core/src/source_blob.rs crates/aster-core/src/lib.rs
git commit -m "feat(blob): add single-pass stream cryptography"
```

### Task 2: Replace semantic-v9/profile-5 wire grammar and vectors

**Files:**
- Modify: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/aster-node/src/frame.rs`
- Modify: `conformance/blob_stream_oracle.py`
- Modify: `conformance/vectors/blob-stream-records-v1.tsv`
- Modify: `docs/protocol.md`
- Test: inline tests in `stream_transfer.rs` and `frame.rs`

**Interfaces:**
- Consumes: Task 1 canonical open/commitment IDs, accumulator commitment, lengths, and segment-record bounds.
- Produces: replacement `BlobPublicationOpenV1 { signed_open: Vec<u8> }` and `BlobPublicationCommitV1 { signed_commitment: Vec<u8> }` mission records and `StreamOpenV1`, `StreamAcceptV1`, `StreamDataV1`, `StreamCheckpointV1`, `StreamFinishV1`, `StreamResultV1`, `StreamResultAckV1` attempt records for Tasks 4 and 7. `StreamOpenV1` binds the logical open digest to a fresh nonzero attempt nonce and authenticated session; retries reuse the signed logical open but never its attempt nonce. Mission decoding passes the signed bytes to Task 1 `ReferenceEnvelopeSealer` verification and can obtain `Verified*` capabilities only from that boundary.

- [ ] **Step 1: Extend the independent oracle first**

Replace the old carrier-plan vectors with literal Python-stdlib construction for publisher-signed open/commitment records and all seven attempt frames. Add accept vectors at 0, one segment, 16 MiB, and final offset; add reject vectors for zero IDs/nonces, wrong semantic/profile, gap/overlap, overflow, credit regression, accumulator mismatch, trailing bytes, and oversized frame body.

- [ ] **Step 2: Regenerate the corpus and verify current Rust is RED**

Run: `python3 conformance/blob_stream_oracle.py --write`

Run: `cargo test --locked -p aster-node blob_stream_record_vectors --lib`

Expected: vector test fails because the existing carrier grammar cannot decode the replacement corpus.

- [ ] **Step 3: Implement canonical mission and attempt codecs**

Retain semantic `9`, profile `5`, and tags `0xd6..0xde`, but replace their field layouts. Parse every fixed header and declared body length before allocation; `StreamDataV1` may split/combine canonical segment bytes but is capped by the 1-MiB body bound. `StreamAcceptV1` and `StreamCheckpointV1` carry durable plaintext/ciphertext offsets, fixed accumulator commitment, checkpoint generation, and absolute receive limit.

- [ ] **Step 4: Replace sender and receiver transition tests**

Assert positive-credit pipelining, unchanged-credit heartbeat, cumulative checkpoint monotonicity, receive-window `>= batch + segment`, finish only at declared length, retry from receiver authority, and idempotent result acknowledgement. Delete tests that encode carrier-count or existing-manifest assumptions for profile 5; retain profile-4 tests unchanged.

- [ ] **Step 5: Run codec, state-machine, oracle, and profile-4 regression tests**

Run: `python3 conformance/blob_stream_oracle.py`

Run: `cargo test --locked -p aster-node stream_transfer --lib`

Run: `cargo test --locked -p aster-node blob_ranges_stream --lib`

Expected: all pass and the independent corpus matches exactly.

- [ ] **Step 6: Update the normative protocol text**

Document exact field order, domains, bounds, signature inputs, accumulator encoding, credit equations, checkpoint ordering, final promotion, and the explicit incompatibility of old development profile-5 state. Remove claims that profile 5 transports existing carrier objects or requires a manifest before bytes.

- [ ] **Step 7: Commit**

```bash
git add crates/aster-node/src/stream_transfer.rs crates/aster-node/src/frame.rs conformance/blob_stream_oracle.py conformance/vectors/blob-stream-records-v1.tsv docs/protocol.md
git commit -m "feat(protocol): define end-to-end Blob stream"
```

### Task 3: Append-only pack and crash-safe checkpoint journal

**Files:**
- Create: `crates/aster-redb-store/src/blob/pack.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Test: inline tests in `crates/aster-redb-store/src/blob/pack.rs`

**Interfaces:**
- Consumes: Task 1 `EncryptedBlobStreamSegment` and fixed accumulator checkpoint.
- Produces: `PinnedBlobPackRoot`, `BlobPackWriter`, `BlobPackReader`, `BlobPackCheckpoint`, `BlobPackCompletion`, and recovery for Tasks 4-7. `PinnedBlobPackRoot` is created only by the hardened depot opener and owns the directory descriptor used by every relative no-follow operation.

Exact Store-private signatures:

```rust
impl BlobPackWriter {
    pub(crate) fn create(root: &PinnedBlobPackRoot, open: &VerifiedBlobStreamOpen) -> Result<Self, StoreError>;
    pub(crate) fn resume(root: &PinnedBlobPackRoot, checkpoint: &BlobPackCheckpoint) -> Result<Self, StoreError>;
    pub(crate) fn append_segment(&mut self, segment: &EncryptedBlobStreamSegment) -> Result<(), StoreError>;
    pub(crate) fn checkpoint(&mut self) -> Result<BlobPackCheckpoint, StoreError>;
    pub(crate) fn finish(self, commitment: &VerifiedBlobStreamFinalCommitment) -> Result<BlobPackCompletion, StoreError>;
}

impl BlobPackReader {
    pub(crate) fn open(root: &PinnedBlobPackRoot, completion: &BlobPackCompletion) -> Result<Self, StoreError>;
    pub(crate) fn read_segment(&mut self, index: u64, output: &mut Vec<u8>) -> Result<bool, StoreError>;
}
```

- [ ] **Step 1: Write failing sequential pack tests**

Add `blob_pack_appends_segments_without_per_segment_barrier`, `blob_pack_checkpoint_is_constant_sized_and_monotonic`, and `blob_pack_reader_streams_verified_segments`. Test-only counters must assert one pack data barrier plus one journal barrier per explicit checkpoint and zero redb commits inside `append_segment`.

- [ ] **Step 2: Run pack tests and verify RED**

Run: `cargo test --locked -p aster-redb-store blob_pack --lib`

Expected: compile failure because `blob::pack` is absent.

- [ ] **Step 3: Implement pinned pack files and alternating journal slots**

Use directory-relative, no-follow opens consistent with existing depot hardening. `append_segment` writes canonical records sequentially and updates only process memory. `checkpoint` performs pack data durability first, writes the inactive fixed-size journal generation with checksum, durably commits it, then returns authority for the Store transaction. `finish` durably writes an immutable completion descriptor at its stable stream-relative path before promotion; the descriptor remains invisible provisional state until Task 4's single redb promotion transaction points the semantic row at it.

- [ ] **Step 4: Write and run crash-point tests**

Add deterministic faults before pack barrier, after pack barrier, during journal write, after journal barrier, during completion-descriptor write, after descriptor durability, and before the promotion transaction. `recover_blob_pack` must choose the newest complete journal generation, validate stream/open/format identity, truncate or ignore any tail beyond its pack length, and treat an unreferenced completion descriptor as provisional GC input rather than published content.

Run: `cargo test --locked -p aster-redb-store blob_pack_crash --lib`

Expected: all crash states reopen at the prior or new complete checkpoint, never an intermediate offset.

- [ ] **Step 5: Add bounded deletion and descriptor tests**

Assert provisional cleanup, completed-pack deletion, descriptor/pack identity mismatch, symlink substitution, non-regular file, oversized journal, and path traversal all fail closed or enter the existing bounded retry category without exposing paths.

Run: `cargo test --locked -p aster-redb-store blob_pack_ --lib`

Expected: all pack tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-redb-store/src/blob/pack.rs crates/aster-redb-store/src/blob.rs
git commit -m "feat(store): add checkpointed Blob packs"
```

### Task 4: Provisional Store authority, lifecycle, and atomic promotion

**Files:**
- Modify: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob/pressure.rs`
- Modify: `crates/aster-redb-store/src/blob/deletion.rs`
- Test: inline Store tests in the same modules

**Interfaces:**
- Consumes: Task 1 open/final commitment and Task 3 checkpoint/completion capabilities.
- Produces: `BlobStreamReservationRequest`, `BlobStreamReservation`, `BlobStreamDurableProgress`, `BlobStreamPromotion`, and the following Store methods for Tasks 5 and 7. The request contains exactly `{ operation: &'a BlobOperationKey, source: BlobStreamSource }`, where `BlobStreamSource` is `LocalApplication` or `AuthenticatedPeer(NodeId)`; `operation` must exactly match the bounded key in the verified open, while publisher, mission, selector, metadata, priority, TTL/custody sample, declared length, epoch, policy revision, and authorization digest come only from that verified open:

```rust
pub fn reserve_blob_stream_with_policy(
    &self,
    policy: &ControlPolicySnapshot,
    request: BlobStreamReservationRequest<'_>,
    open: &VerifiedBlobStreamOpen,
) -> Result<(BlobStreamReservation, BlobStreamDurableProgress), StoreError>;

pub fn commit_blob_pack_checkpoint_with_policy(
    &self,
    policy: &ControlPolicySnapshot,
    reservation: &BlobStreamReservation,
    expected: BlobStreamDurableProgress,
    checkpoint: BlobPackCheckpoint,
) -> Result<BlobStreamDurableProgress, StoreError>;

pub fn promote_blob_stream_with_policy(
    &self,
    policy: &ControlPolicySnapshot,
    reservation: &BlobStreamReservation,
    commitment: &VerifiedBlobStreamFinalCommitment,
    completion: BlobPackCompletion,
    final_sample: Option<CustodySample>,
) -> Result<BlobStreamPromotion, StoreError>;
```

- [ ] **Step 1: Write failing provisional invisibility and idempotency tests**

Assert a signed open reserves declared bytes and one variant, exact replay returns the same reservation/progress, conflicting operation/open fails, and provisional state is absent from content lookup, inventory, subscriptions, application reads, and forwarding selection.

- [ ] **Step 2: Run provisional tests and verify RED**

Run: `cargo test --locked -p aster-redb-store blob_stream_provisional --lib`

Expected: compile failure because reservation APIs and tables are absent.

- [ ] **Step 3: Implement constant-sized provisional rows and quota reservation**

Replace profile-5 carrier checkpoint authority with one provisional row keyed by `BlobPublicationStreamId`, one operation binding, one current pack checkpoint, and one terminal/conflict disposition. Bump only the profile-5/depot schema required for the new layout; reject old unqualified profile-5 state with an explicit incompatible-development-schema error rather than migrating it.

- [ ] **Step 4: Write failing checkpoint transaction tests**

Assert only a Task 3 durable checkpoint capability can advance offsets; generation, roots, pack length, lifecycle generation, or stream mismatch fails; duplicate commit is idempotent; redb commit failure does not acknowledge pack progress; and writer-commit count grows per batch rather than per segment.

- [ ] **Step 5: Implement checkpoint authority and exact operation recovery**

`commit_blob_pack_checkpoint_with_policy` atomically updates quota usage, current journal generation, offsets, and accumulator commitment after rechecking policy/deletion/lifecycle. Return the receiver-authoritative durable offset used by local and network resume.

- [ ] **Step 6: Write failing finish, TTL, conflict, and promotion tests**

Cover exact duplicate finish, different finish for one stream/operation, wrong publisher signature, roots/length/count mismatch, policy change, deletion fence, finite TTL expiring during transfer, non-younger finite age, and promotion crashes before/after the single semantic transaction. A durable completion descriptor without that transaction remains invisible and reclaimable; a committed semantic row always names the already-durable descriptor.

- [ ] **Step 7: Implement signed final promotion**

Require Task 1's `VerifiedBlobStreamFinalCommitment`, validate the already-durable `BlobPackCompletion`, derive the exact `BlobId`, and in one redb transaction convert the reservation to a completed publication that names that descriptor while retaining bounded replay/conflict evidence. That transaction is the only visibility switch. Signature verification remains in the node's provider-owned verifier; the Store cannot construct the verified capability. Never read plaintext or enumerate per-segment rows during promotion.

- [ ] **Step 8: Integrate pressure, cleanup, and lifecycle scheduling**

Make provisional reservations explicit GC/pressure roots; allow only authorized lower-priority eviction; stop new credit after expiry/invalidation; clean abandoned packs through existing bounded row/file/byte budgets; and keep permanent fences consistent with completed operations.

- [ ] **Step 9: Run focused Store suites**

Run: `cargo test --locked -p aster-redb-store blob_stream_ --lib`

Run: `cargo test --locked -p aster-redb-store blob_pack_ --lib`

Expected: provisional, checkpoint, promotion, lifecycle, pressure, deletion, and crash tests pass.

- [ ] **Step 10: Commit**

```bash
git add crates/aster-redb-store/src/blob/stream.rs crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/lifecycle.rs crates/aster-redb-store/src/blob/pressure.rs crates/aster-redb-store/src/blob/deletion.rs
git commit -m "feat(store): promote provisional Blob streams"
```

### Task 5: Actor-owned local publish and read sessions

**Files:**
- Create: `crates/aster-node/src/application/blob_stream.rs`
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Test: inline application tests and `crates/aster-node/src/runtime/blob_ranges_stream_live_tests.rs` for legacy isolation

**Interfaces:**
- Consumes: Tasks 1, 3, and 4 Store/crypto/session primitives.
- Produces these exact application interfaces for Task 6 and durable-pack progress for Task 7. `BlobPublishStreamRequest` contains exactly `{ publication: BlobPublishRequest, options: BlobPublishOptions, total_len: u64 }`, reusing the established operation/selector/metadata validation:

```rust
impl SelectedBlobHandle {
    pub async fn open_publish_stream(
        &self,
        request: BlobPublishStreamRequest,
    ) -> Result<SelectedBlobPublishStream, ApplicationError>;
    pub async fn open_read_stream(
        &self,
        request: BlobReadRequest,
    ) -> Result<SelectedBlobReadStream, ApplicationError>;
}

impl SelectedBlobPublishStream {
    pub const fn durable_offset(&self) -> u64;
    pub async fn write(&mut self, offset: u64, bytes: Zeroizing<Vec<u8>>) -> Result<BlobPublishProgress, ApplicationError>;
    pub async fn finish(self) -> Result<BlobPublishResult, ApplicationError>;
}

impl SelectedBlobReadStream {
    pub async fn next(&mut self, max_bytes: usize) -> Result<Option<BlobReadFrame>, ApplicationError>;
}
```

- [ ] **Step 1: Write failing publish-session tests**

Add tests proving open reserves but does not publish, `write` accepts contiguous bounded bytes with backpressure, checkpoints only at 16 MiB/250 ms/final tail, exact operation reopen returns the Store durable offset, finish promotes, cancellation leaves resumable provisional state, and a successful 64-MiB publish reads source bytes exactly once.

- [ ] **Step 2: Run publish-session tests and verify RED**

Run: `cargo test --locked -p aster-node selected_blob_publish_stream --lib`

Expected: compile failure because stream handle/commands are absent.

- [ ] **Step 3: Implement bounded actor commands and buffer permits**

Add `OpenPublishStream`, `AppendPublishStream`, `FinishPublishStream`, and `AbortPublishStream` commands. Use a global byte semaphore and per-stream ordered state; perform blocking pack/crypto work on the existing joined blocking worker. A full network branch may detach to its durable pack cursor rather than holding a live buffer or blocking local completion.

- [ ] **Step 4: Write failing read-session tests**

Assert one admission authenticates the completed descriptor, sequential `next(max_bytes)` calls do not open redb write transactions for durable content, finite content checkpoints custody only at configured byte/time cadence, policy change stops later output, buffers zeroize, and peak live plaintext is bounded by permits rather than Blob length.

- [ ] **Step 5: Implement authenticated sequential reads**

Add `OpenReadStream`, `NextReadStream`, and `CloseReadStream` commands backed by one `BlobPackReader` and bounded lifecycle lease. Revalidate authority at byte/time checkpoints and before successful EOF; keep frame size independent of segment and pack layout.

- [ ] **Step 6: Run application and legacy profile-4 tests**

Run: `cargo test --locked -p aster-node selected_blob_ --lib`

Run: `cargo test --locked -p aster-node blob_ranges_stream_live --lib`

Expected: new stream tests pass and profile-4 bytes/behavior remain unchanged.

- [ ] **Step 7: Commit**

```bash
git add crates/aster-node/src/application/blob_stream.rs crates/aster-node/src/application.rs crates/aster-node/src/application/blob.rs crates/aster-node/src/runtime/blob_ranges_stream_live_tests.rs
git commit -m "feat(node): stream Blob application sessions"
```

### Task 6: Bidirectional agent publish, resumable CLI, and streaming read

**Files:**
- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `crates/aster-agent/src/blob_service.rs`
- Modify: `crates/aster-agent/src/lib.rs`
- Modify: `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/tests/real_node_connect.rs`
- Modify: `crates/asterctl/src/blob_publish.rs`
- Modify: `crates/asterctl/src/blob_read.rs`
- Modify: `crates/asterctl/src/client.rs`
- Modify: `crates/asterctl/tests/blob.rs`

**Interfaces:**
- Consumes: Task 5 node publish/read sessions.
- Produces: bidirectional `PublishBlob` accepted/checkpoint/complete responses, operation-key resume from a durable offset, and direct streaming `ReadBlob` frames for operators.

- [x] **Step 1: Write failing protobuf/grammar tests**

Change `PublishBlob` to bidirectional streaming. Request variants are `metadata`, `data { offset, bytes }`, and `finish`; response variants are `accepted { durable_offset, canonical_frame_bytes }`, `checkpoint { durable_offset }`, and `complete { publication }`. Require metadata first, every non-terminal data frame to have exactly the advertised canonical size, the terminal data frame to carry the exact remainder, and exactly one finish after declared bytes. Tests reject data-before-accept, offset gaps, noncanonical data frames, premature finish, extra frames, and mismatched complete metadata.

- [x] **Step 2: Regenerate bindings and verify RED**

Run: `cargo test --locked -p aster-agent blob_upload --lib`

The crate build script regenerates ConnectRPC bindings from `proto/aster/application/v1alpha1/aster.proto` in `OUT_DIR`.

Expected: service tests fail until the bidi bridge is implemented.

- [x] **Step 3: Replace whole-file staging with direct node-session bridging**

Delete `PinnedStagingDirectory`, `PreparedUpload`, and `BlockingUploadWriter` from the profile-5 route. After metadata, open Task 5 session, send `accepted`, forward bounded frames under ConnectRPC backpressure, emit only Store-authoritative checkpoints, and send `complete` after promotion. On disconnect retain resumable Store state; never acknowledge non-durable bytes as resume authority.

- [x] **Step 4: Write the disconnect/reopen integration test from Review Focus**

In a non-ignored real-node/agent HTTP/2 test, force a deterministic durability
checkpoint, disconnect after accepted non-checkpointed bytes, reopen with the
same operation key, assert the returned offset equals that exact checkpoint,
seek/replay from that offset, and verify the final `BlobId` and bytes exactly.
Keep the larger multi-batch disconnect case in the ignored release performance
test so routine CI proves protocol correctness without making throughput-scale
work part of the fast gate.

- [x] **Step 5: Implement seekable CLI resume and mutation checks**

`asterctl` sends metadata, waits for `accepted`, seeks the already-open regular file to `durable_offset`, streams `(offset, bytes)` frames, and verifies checkpoints never regress or exceed sent data. Continue checking source length and descriptor identity through completion so replacement/truncation fails visibly.

- [x] **Step 6: Bridge `ReadBlob` to one Task 5 read session**

Remove page-by-page node admission. Stream bounded plaintext responses from `SelectedBlobReadStream`, keep metadata stable, and close the session on client cancellation. The CLI retains its owner-only temporary output, exact offset validation, one final file sync, no-replace rename, and directory sync.

- [x] **Step 7: Run focused agent/CLI tests**

Run: `cargo test --locked -p aster-agent blob --lib --tests`

Run: `cargo test --locked -p asterctl blob --lib --tests`

Expected: grammar, disconnect/resume, cancellation, no-replace output, exact hash, and bounded-frame tests pass.

- [x] **Step 8: Commit**

```bash
git add proto/aster/application/v1alpha1/aster.proto crates/aster-agent/src/blob_service.rs crates/aster-agent/src/lib.rs crates/aster-agent/src/event_service.rs crates/aster-agent/tests/real_node_connect.rs crates/asterctl/src/blob_publish.rs crates/asterctl/src/blob_read.rs crates/asterctl/src/client.rs crates/asterctl/tests/blob.rs
git commit -m "feat(agent): expose resumable Blob streams"
```

### Task 7: Network fan-out, completed-pack forwarding, and resume

**Files:**
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/stream_transport.rs`
- Modify: `crates/aster-node/src/mission.rs`
- Test: focused runtime tests in `crates/aster-node/src/runtime/blob_stream.rs`

**Interfaces:**
- Consumes: Task 2 state machines, Task 4 receiver authority, Task 5 live/durable pack cursor.
- Produces: end-to-end provisional sender/receiver attempts, finalized forwarding, resume/failover, and atomic settlement used by Task 8 qualification.

- [ ] **Step 1: Write failing provisional-transfer tests**

Test authenticated signed-open admission before bytes, concurrent segment receipt before local finalization, no remote visibility before finish, final commitment promotion, and source failure leaving a resumable provisional pack. Reject a session-authenticated but unsigned open.

- [ ] **Step 2: Run provisional runtime tests and verify RED**

Run: `cargo test --locked -p aster-node blob_stream_provisional_contact --lib`

Expected: failures because runtime still requires an existing finalized source/manifest.

- [ ] **Step 3: Implement live fan-out and receiver pipeline**

Attach a transport cursor to Task 5 publication progress. Consume live encrypted buffers while current; if the network falls behind the buffer budget, release them and continue from the local durable pack cursor. Receiver verifies segments, appends Task 3 pack, advances Task 4 checkpoints, and replenishes absolute credit without per-segment control turns.

- [ ] **Step 4: Add and implement completed-pack forwarding tests**

An alternate authorized peer must present the original publisher-signed open and final commitment before credit, stream stored ciphertext without decrypt/re-encrypt, and settle the exact publication. Mutation of either signature, pack descriptor, policy, or physical lineage fails before visibility.

- [ ] **Step 5: Add retry, slow-network, and failover tests**

Cover disconnect before/after checkpoint, receiver checkpoint ahead of sender live cursor, retransmitted tail bounded by batch/window, fresh attempt nonce, replayed old frames, zero-credit heartbeat, positive-credit stall, cancellation, and single-active-transport enforcement. The Review Focus slow-network test asserts local publish completes while the transport drains later from pack.

- [ ] **Step 6: Implement retry/failover against receiver authority**

On every attempt authenticate peer/session/profile, obtain exact receiver checkpoint and accumulator commitment, restore sender cursor, and resume on a segment boundary. Preserve logical open/commit identities and finite age; never resume profile-5 state through profile 4.

- [ ] **Step 7: Run focused runtime and transport tests**

Run: `cargo test --locked -p aster-node blob_stream_ --lib`

Run: `cargo test --locked -p aster-node stream_transport --lib`

Expected: provisional, forwarding, resume, backpressure, lifecycle, and selector tests pass.

- [ ] **Step 8: Commit**

```bash
git add crates/aster-node/src/runtime/blob_stream.rs crates/aster-node/src/runtime.rs crates/aster-node/src/stream_transport.rs crates/aster-node/src/mission.rs
git commit -m "feat(blob): pipeline packs over selected transport"
```

### Task 8: Stage metrics and transport-limited release benchmarks

**Files:**
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/application/blob_stream.rs`
- Modify: `crates/aster-node/examples/blob_benchmark.rs`
- Modify: `docs/validation/blob-streaming-performance.md`

**Interfaces:**
- Consumes: Tasks 5-7 stage and checkpoint events.
- Produces: bounded `BlobStreamPerformanceSnapshot` and ignored release benchmarks that calculate the 80%/125% acceptance ratios.

- [ ] **Step 1: Write failing metric-accounting tests**

Assert exact bytes/time for application input/output, hash, encrypt, pack write/read, verify, and transport; buffer occupancy/backpressure; checkpoint barriers/commits; retransmitted bytes; first-byte/checkpoint/promotion times; transport/attempt/failover; and overflow-fail-atomic behavior. Metrics contain no identity, path, key, or peer error text.

- [ ] **Step 2: Run metrics tests and verify RED**

Run: `cargo test --locked -p aster-node blob_stream_performance --lib`

Expected: compile failure because stage snapshots are absent.

- [ ] **Step 3: Implement bounded stage instrumentation**

Use monotonic durations and checked counters. Record writer commits and filesystem barriers from actual Store/pack outcomes, not estimates. Expose only a bounded local status snapshot; keep transport choice out of the application Blob API.

- [ ] **Step 4: Replace carrier benchmark with pack pipeline benchmarks**

Add ignored release cases for 64, 256, 800, and 1024 MiB selected by a bounded environment value. Measure raw selected transport with identical frame/window bounds, each non-transport stage independently, and complete end-to-end replication. Print machine-readable rates plus `end_to_end/raw_transport` and `stage/raw_transport` ratios.

- [ ] **Step 5: Run targeted release benchmarks**

Run: `ASTER_TEST_BLOB_STREAM_MIB=256 cargo test --release --locked -p aster-node end_to_end_blob_stream_pipeline --lib -- --ignored --nocapture`

Expected: exact reconstruction, bounded RSS/counters, commit/barrier count proportional to 16-MiB checkpoints, and reported ratios. Do not claim qualification from a workstation result.

- [ ] **Step 6: Update retained performance evidence**

Record command, commit, platform, payload, stage rates, ratios, elapsed times, RSS, checkpoint count, retransmission, and limitations. Preserve the 1.55/1.85-MiB/s results as the rejected-architecture baseline.

- [ ] **Step 7: Commit**

```bash
git add crates/aster-node/src/runtime/blob_stream.rs crates/aster-node/src/runtime.rs crates/aster-node/src/application/blob_stream.rs crates/aster-node/examples/blob_benchmark.rs docs/validation/blob-streaming-performance.md
git commit -m "perf(blob): measure end-to-end stream stages"
```

### Task 9: Focused verification and CM4 qualification

**Files:**
- Modify: `docs/validation/blob-streaming-performance.md`
- Create after successful run: `docs/validation/evidence/2026-10-17-cm4-end-to-end-blob-streaming.md`

**Interfaces:**
- Consumes: all implementation tasks and the three previously identified CM4 devices.
- Produces: retained two-CM4 development evidence and, only when credentials are available on all devices, three-CM4 qualification evidence.

- [ ] **Step 1: Run formatting, compile, and focused suites**

Run: `cargo fmt --check`

Run: `cargo check --locked -p aster-core -p aster-redb-store -p aster-node -p aster-agent -p asterctl`

Run the focused commands from Tasks 1-8. Use CI for the full workspace suite as previously directed; list every skipped or failing check explicitly.

- [ ] **Step 2: Run two-CM4 64-MiB instrumentation sanity**

Install identical local candidate binaries on `rpi4-1` and `rpi4-2` in the isolated validation state. Retain raw-transport and stage metrics, exact source/output SHA-256, service health, RSS, checkpoint/barrier counts, and proof that no carrier-per-file tree or plaintext staging file was created.

- [ ] **Step 3: Run 256-MiB stable-rate comparison**

Verify rate does not decay with size, end-to-end/raw transport is at least 80%, every non-transport stage is at least 125% of raw transport, and the limiting-stage trace names transport. If a ratio fails, stop qualification and return to the owning task rather than increasing buffers blindly.

- [ ] **Step 4: Run interruption/resume validation**

Interrupt after at least two checkpoints, restart the affected process, resume the exact operation/transfer, and retain receiver-authoritative offset plus retransmitted-tail evidence. Tail bytes must not exceed the advertised durability batch/window and final SHA-256 must match.

- [ ] **Step 5: Run exact 800-MiB and at least 1-GiB validation**

Retain publish, time-to-first-byte, replication, promotion, read, total end-to-end times, per-stage rates, transport ratio, RSS, service health, Blob ID, operation key, source/output SHA-256, and cleanup state. Both sizes must satisfy the design acceptance criteria.

- [ ] **Step 6: Handle the third CM4 boundary honestly**

Use `rpi4-3` only if valid test mission credentials are provisioned through an authorized workflow. Otherwise document two-device development evidence and leave alternate-peer/failover qualification open; do not copy credentials from another device.

- [ ] **Step 7: Commit retained evidence**

```bash
git add docs/validation/blob-streaming-performance.md docs/validation/evidence/2026-10-17-cm4-end-to-end-blob-streaming.md
git commit -m "docs(blob): retain CM4 streaming qualification"
```

## Completion Gate

Before requesting review, verify that no profile-5 successful path calls `prepare_blob`, creates a plaintext staging file, writes one physical file per segment, commits redb per segment/application frame, or opens a new read authority per response frame. Search results are diagnostic; behavioral tests and retained counters are the acceptance authority.

The branch is ready for review only when focused tests pass, CI evidence is green or every unrelated failure is named, the two-CM4 800-MiB and 1-GiB results meet the ratios, and the working tree contains no unrelated changes. Do not push until explicitly authorized.
