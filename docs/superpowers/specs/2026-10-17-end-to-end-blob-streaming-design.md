# Clean Room — Privileged

# End-to-End Blob Streaming Design

Date: 2026-10-17

Status: approved written specification; implementation planning complete

Supersedes: `2026-10-14-blob-streaming-transport-design.md`

## Purpose

Aster must transfer an 800-MiB to 1+-GiB Blob in operationally relevant time.
The first semantic-v9/profile-5 implementation proved that a long-lived
transport stream alone is insufficient. Its raw stream transported hundreds
of MiB/s on loopback and its production network driver reached approximately
11 MiB/s on a development host, while the complete CM4 application path
published at 1.55 MiB/s and read at 1.85 MiB/s.

That gap is architectural. The implementation stages the complete application
input, rereads it to prepare and encrypt thousands of 64-KiB carriers, persists
each carrier as a separate file with multiple durability operations, and
reconstructs authorization and storage state at each read page. It therefore
turns storage transaction latency into the dominant cost even when the
transport is healthy.

This design replaces that path with one bounded pipeline from application
input through encryption, transport, receiver persistence, and application
output. It removes protocol-induced stop-and-wait and per-carrier durability
costs. Within a declared hardware and network qualification envelope, every
non-transport stage must demonstrate sufficient throughput headroom that the
selected transport is the limiting steady-state stage.

## Claim boundary

No architecture can make transport the physical bottleneck on every possible
machine and link. End-to-end throughput is the minimum of source I/O, hashing,
content encryption, transport, receiver I/O, verification, and destination
I/O. This design therefore makes two precise claims:

1. Aster introduces no synchronous per-frame, per-segment, or per-page control
   or durability barrier in steady state.
2. A supported deployment profile is qualified only when its measured
   non-transport stages sustain more throughput than its fastest supported
   transport under the same resource limits.

Transport-only ceiling measurements are diagnostic evidence, not acceptance
evidence.

## Compatibility and allocation

Semantic v9/profile 5 has not been released or qualified. Its current frame
grammar, carrier mapping, and depot layout are not compatibility authorities.
This design redefines the still-development semantic-v9/profile-5 path and
replaces its vectors and fixtures. Isolated development state may be reset.

Semantic v7/v8 and profile 4 remain historical protocols for peers that
negotiate them, but the new streaming path does not reuse their range layout,
carrier files, progress records, or size limits. A profile-4 partial transfer
cannot be promoted or resumed as profile 5. It restarts through profile 5 after
new admission or completes through profile 4.

No migration of unqualified profile-5 pending data is required. Persisted
completed Blobs from an earlier development build must be explicitly reimported
or the development depot reset; silently interpreting their physical layout as
the new format is forbidden.

## Goals

The implementation must:

1. accept application input incrementally without a whole-Blob staging file;
2. read each plaintext byte once in the successful publish path;
3. hash, encrypt, persist, and transmit concurrently with bounded buffers;
4. store streamed ciphertext in sequential packs rather than one file and
   database transaction per cryptographic segment;
5. acknowledge only cumulative verified durable progress;
6. resume after transport or process failure from a constant-sized durable
   checkpoint;
7. keep provisional content invisible and non-forwardable until a final signed
   commitment establishes the immutable Blob identity;
8. stream authenticated reads without reconstructing policy, database, or
   depot state for each response frame;
9. keep memory, open files, metadata, and recovery work bounded independently
   of Blob length;
10. retain transport-neutral application APIs and automatic selection of one
    data-carrying transport per attempt; and
11. support at least 2 GiB when configured storage capacity permits.

## Non-goals

This increment does not add multipath striping, cross-peer swarming, erasure
coding, compression, out-of-order sparse resume, speculative duplicate
transfer, or Event activation. The framing and pipeline may be reused by a
later Event profile, but Blob is the first enabled data class.

It also does not promise that loopback QUIC is slower than local storage on a
CM4. Qualification instead declares the supported transport envelope and
proves stage headroom for that envelope.

## Considered approaches

### Selected: provisional single-pass publication with a signed final commitment

The publisher authenticates a bounded publication intent before content. The
intent authorizes resource reservation but does not claim a final `BlobId`.
Plaintext then flows once through an incremental content accumulator and
segment encryption pipeline. The receiver durably checkpoints a sequential
ciphertext pack. A final publisher-signed commitment binds the exact intent,
length, layout, plaintext root, ciphertext root, and immutable `BlobId`.

This is the only considered approach that can overlap application ingestion,
cryptography, storage, and network transfer without trusting an identity that
cannot be known until the final byte has been read.

### Rejected: pre-hash and then stream

Pre-hashing preserves the existing manifest-first model but necessarily reads
the complete source before transport and reads it again for encryption. It can
be faster than the current carrier store, but it is not an end-to-end stream
and cannot overlap initial network transfer with application ingestion.

### Rejected: batch the existing carrier-per-file depot

Larger transactions reduce redb overhead but retain thousands of small files,
per-file durability costs, per-carrier lookup, and whole-source staging. This
can improve a benchmark without removing the architectural bottleneck observed
on the CM4s.

### Rejected: increase the canonical carrier size

A larger carrier reduces operation count but couples crypto, resume, storage,
and transport scheduling to one fixed size. It still requires carrier-specific
metadata and does not create a single-pass publication protocol.

## End-to-end pipeline

One publication is a bounded asynchronous pipeline:

```text
application input
  -> fixed segmenter and plaintext accumulator
  -> content encryption
  -> bounded encrypted-segment fan-out
       -> local sequential pack writer
       -> transport send queue
  -> receiver verification
  -> receiver sequential pack writer
  -> cumulative durable checkpoint
  -> signed final commitment
  -> atomic promotion
  -> authenticated application read stream
```

Stages communicate through a fixed pool of reusable buffers. Backpressure
propagates from the slowest downstream stage to the application input. No stage
allocates in proportion to total Blob length or waits for an ordinary
per-segment request/response exchange.

Local persistence and network transmission may consume the same encrypted
segment concurrently. Implementations must avoid an avoidable third copy;
zero-copy transport is optional because transport libraries may require owned
buffers, but buffer ownership remains bounded.

A slow or disconnected network branch must not indefinitely block local
publication. Once an encrypted segment is durably checkpointed in the local
pack, the network branch may release its live buffer and continue later from a
pack cursor. While the network keeps pace it consumes the live buffer directly;
when it falls behind, the final pack is the bounded spool and authoritative
source. This switch does not decrypt, re-encrypt, or create another whole-Blob
staging artifact.

The publisher may complete locally while no peer is reachable. The same pack
is subsequently streamed without decrypting and re-encrypting it. When a peer
is reachable during publication, provisional transfer may run concurrently and
be finalized by the same signed commitment.

## Identities and authenticated provisional admission

The final `BlobId` cannot be honestly known at stream open. Profile 5 therefore
uses two identities:

- `publication_stream_id`: a fresh random 256-bit identifier bound by the
  publisher to the operation key and mission; each network attempt separately
  binds that logical stream to its authenticated session and attempt nonce; and
- `BlobId`: the immutable final content identity derived at finish.

`PublishStreamOpenV1` is signed by the source publisher and is additionally
carried in an authenticated, integrity-protected Aster control context. The
signature permits an admitted receiver to verify the source intent before
accepting provisional content; session protection alone is insufficient. The
open binds:

- publisher and idempotent operation key;
- topic, scope, priority, media type, schema ID, and optional TTL;
- declared total plaintext length;
- segment and pack-format versions;
- publication stream ID; the transport-attempt `StreamOpen` separately binds a
  fresh attempt nonce so a retry can preserve the publisher-signed intent;
- content-encryption epoch and provisional encryption parameters;
- policy revision and required authorization context; and
- a digest of all canonical open fields.

Admission verifies authority, policy, TTL support, declared length, quotas,
concurrency limits, and replay state before granting byte credit. It creates a
provisional root keyed by the stream ID. That root is not a publication, does
not enter Blob inventory, cannot be forwarded as content, and cannot satisfy an
application read.

A publisher cannot use provisional admission to claim custody completion. An
abandoned stream remains bounded provisional state subject to explicit
retention and pressure policy.

The provisional content key is derived from the authorized scope/content
epoch plus a random publication salt bound by the signed open. It cannot depend
on the final `BlobId`, which is not yet available. The key and nonce domains
are distinct from historical Blob formats.

For a finite publication, the signed open establishes the TTL and initial
trusted custody-clock sample. Time spent publishing and provisionally
transferring counts toward age. The final commitment must repeat the same TTL
and prove a non-younger age; finishing cannot rejuvenate an expired stream.

## Segment and content format

The streaming segment is a cryptographic verification unit, not a file or a
transaction. The initial profile uses a fixed 1-MiB maximum plaintext segment;
the final segment may be shorter. This size is versioned and is not negotiated
upward by an untrusted peer.

Each segment record binds:

- publication stream ID;
- zero-based segment index and plaintext offset;
- plaintext and ciphertext lengths;
- declared total plaintext length;
- content epoch and format version;
- previous accumulator commitment; and
- an independent AEAD tag.

Nonce derivation is deterministic from a per-publication random base nonce and
the segment index, with checked exhaustion. Associated data binds the canonical
open digest and the segment fields. Reordering, overlap, truncation, replay
under another stream, or substitution under another intent fails verification.

The plaintext and ciphertext identities use domain-separated incremental
Merkle accumulators over fixed segment records. An accumulator checkpoint uses
a fixed-width canonical array sized for the protocol's maximum checked Blob
length, so durable checkpoint size is constant for the selected profile even
though only O(log segment count) slots are populated. It is independently
testable.
The final `BlobId` binds at least the plaintext root, total plaintext length,
segment format, and application metadata commitment. The signed final
commitment also binds the ciphertext root and encryption parameters.

The exact hash and AEAD algorithms, domains, encodings, and test vectors become
normative in `docs/protocol.md`. They must support incremental computation and
checkpoint restoration without serializing implementation-private hash state.

## Sequential pack storage

Each provisional or completed variant uses a small bounded set of files:

1. an append-only ciphertext pack containing canonical segment records;
2. a compact checkpoint journal with alternating generations; and
3. an atomically installed final descriptor after promotion.

The pack is append-only until finalization. Segment offsets are deterministic
from the fixed layout except for the final segment, so ordinary reads do not
need one database row per segment. If an auxiliary index is required by a
future variable-size format, it is appended and checkpointed in blocks rather
than represented as per-segment redb rows.

The protocol permits a bounded durability batch up to 16 MiB. The first
production selection is 7 MiB inside an 8-MiB receive window, retaining one
maximum 1-MiB extent of headroom after measured 4-MiB and 7-MiB comparisons.
The writer writes sequentially, issues one data durability barrier for the
pack, then atomically commits one checkpoint generation containing:

- durable plaintext and ciphertext offsets;
- next segment index;
- plaintext and ciphertext accumulator states;
- pack length and format identity;
- stream/open digest;
- lifecycle generation; and
- checksum of the checkpoint record.

The threshold is locally configurable within protocol bounds. The receive
window must always exceed the maximum durability batch by at least one maximum
segment, preventing credit/checkpoint deadlock.

No durable database transaction or filesystem barrier occurs per wire frame or
per segment. Database state tracks the provisional root, quota reservation,
current checkpoint generation, and terminal disposition. A checkpoint commit
may update those constant-sized fields once per batch.

After a crash, bytes beyond the last valid checkpoint are truncated or ignored.
They were never acknowledged. Replay starts at the checkpoint's exact segment
and accumulator state. Alternating checkpoint generations prevent a torn
checkpoint from becoming authority.

## Transport stream

The transport adapter provides an authenticated peer binding plus a reliable,
ordered, full-duplex byte stream. Aster owns framing, credit, checkpoint,
lifecycle, and settlement semantics.

The attempt grammar contains:

- `StreamOpen`: exact provisional or finalized publication identity, open
  digest, attempt nonce, and receiver-known checkpoint generation;
- `StreamAccept`: receiver-authoritative durable offset, restored accumulator
  commitment, and absolute byte credit;
- `StreamData`: one or more canonical segment records, bounded before body
  allocation;
- `StreamCheckpoint`: cumulative durable offsets, accumulator commitment,
  generation, and replenished absolute credit;
- `StreamFinish`: final roots and publisher-signed commitment;
- `StreamResult`: promotion or typed terminal outcome; and
- `StreamResultAck`: idempotent settlement acknowledgement.

Before a completed-publication attempt, the mission protocol exchanges the
publisher-signed open and final commitment and obtains a receiver-authored
resume authority. That authority binds the exact stream/open identity, durable
plaintext and pack offsets, next segment, both accumulator commitments, and
checkpoint generation. It replaces the earlier carrier-oriented plan: the
sender seeks the immutable pack directly to the durable wire offset and sends
only the missing suffix. If every byte is already durable, the same grammar
performs settlement without replaying data.

Data frames are scheduling envelopes. They may split or combine segment
records subject to bounded parser memory; neither frame nor segment boundaries
cause synchronous persistence. The sender may keep enough frames in flight to
fill the receiver-advertised window and transport bandwidth-delay product.

Attempt control records remain mission-AEAD protected. Data records use an
explicit direct-data outer kind on the same authenticated QUIC attempt and
carry canonical segment-AEAD-protected pack bytes without a second
whole-extent mission encryption and allocation. A direct record may contain
only `StreamData`; a protected record may contain only control. The signed
publication commitments, attempt tuple, segment verification, durable
checkpoint, and final promotion checks remain mandatory.

Credit is an absolute maximum accepted ciphertext offset. Duplicate or
reordered control frames cannot mint capacity. Checkpoints are cumulative and
never move backward. While storage is catching up, the reverse control stream
remains live and may send authenticated no-credit heartbeats.

Transport loss discards only the uncheckpointed tail. A new attempt uses a
fresh nonce and authenticated session binding, restores the receiver checkpoint
and accumulator commitment, and resumes on a segment boundary. It never trusts
the sender's estimate of progress.

The original publisher may send provisional segments before finalization. A
forwarding peer may send only a completed publication: it supplies the
publisher-signed open and final commitment before data credit, then streams the
same stored ciphertext pack without decryption or re-encryption. A forwarding
peer cannot manufacture or amend either publisher signature.

## Final commitment and promotion

`PublishStreamFinishV1` is signed by the source publisher and canonically binds:

- the complete `PublishStreamOpenV1` digest;
- publication stream ID and operation key;
- exact plaintext length and segment count;
- plaintext Merkle root and resulting `BlobId`;
- ciphertext Merkle root, pack format, content epoch, and encryption binding;
- topic, scope, priority, media type, schema ID, and TTL;
- publisher causal identity; and
- final policy/lifecycle context required by the selected protocol.

Before promotion the receiver:

1. durably checkpoints the final pack length and accumulators;
2. verifies the publisher signature and all open/finish bindings;
3. verifies the derived `BlobId`, roots, lengths, and segment count;
4. rechecks authorization, policy, TTL, quota, deletion fences, and lifecycle;
5. atomically converts the provisional root and quota reservation into the
   completed publication and installs the final descriptor; and
6. only then returns success and exposes inventory/application visibility.

Failure cannot expose partial content. An exact duplicate finish is idempotent.
A conflicting finish for the same stream ID or operation key is a terminal
integrity conflict and preserves bounded evidence.

## Local application publish stream

The agent API uses the same pipeline rather than staging a complete file before
calling the node. `PublishBlob` is bidirectional. Its first request carries
metadata and declared length; the first response carries the exact accepted and
durable resume offset and the canonical request-frame size. Subsequent requests
carry contiguous `(offset, bytes)` data frames of exactly that size, except that
the terminal data frame carries the exact remainder, followed by one explicit
finish. This canonical shape bounds frame-count work independently of Blob size;
it intentionally does not advertise arbitrary smaller request frames. Responses carry only monotonic
Store-authoritative checkpoints, followed by exactly one completed publication
receipt after promotion. EOF before finish, data gaps, offset replay, a second
metadata or finish, and frames after finish are malformed. The node returns
cumulative accepted and durable offsets so an interrupted seekable client can
reopen the idempotent operation and resume from local durable state.

`asterctl` reads its source file sequentially from the requested offset. It
does not copy the complete source into agent staging. A non-seekable producer
may restart only from zero unless it implements the resume contract; this does
not weaken receiver progress.

Successful publication returns only after local final commitment and promotion.
Peer replication may finish before, concurrently with, or after that response,
but provisional remote bytes remain invisible until they receive and verify
the final commitment.

## Authenticated application read stream

A read request establishes one bounded read session. Admission authenticates
the selected completed publication, opens its final descriptor and pack, and
pins only a bounded read lease. The session then sequentially reads, verifies,
decrypts, and emits application frames through a reusable buffer pool.

Authorization and lifecycle are revalidated at bounded byte or time
checkpoints and before final success, not by opening a database write
transaction for every response frame. Durable Blobs perform no custody-clock
writes. Finite Blobs project current age from the trusted clock and persist
continuity only at the lifecycle checkpoint cadence required by policy.

Output frame size is a transport/application scheduling choice and does not
change storage or cryptographic units. `asterctl` writes sequentially to one
owner-controlled temporary output, performs one final file durability barrier,
and atomically publishes it without replacement.

## Lifecycle and resource bounds

Provisional admission reserves declared physical bytes and one variant slot,
but does not preallocate memory or metadata per segment. The reservation is
released or converted atomically at terminal disposition.

Each active stage holds only its current bounded buffer/pack lease. No stream
holds a whole-Blob lifecycle lease. Retirement or policy invalidation stops new
credit; an already admitted bounded buffer may finish, after which the stream
returns the typed lifecycle outcome.

The implementation defines and enforces global and per-stream limits for:

- active publication/read streams;
- total reusable buffer bytes;
- queued but uncheckpointed bytes;
- open pack descriptors;
- provisional roots and retained conflict evidence;
- checkpoint journal records; and
- storage worker concurrency.

Every success, error, cancellation, disconnect, shutdown, and panic-unwind path
releases permits and leases. Valid durable partial work is retained according
to storage policy rather than an arbitrary network inactivity timeout.

## Automatic transport selection

Transport selection remains internal and transport-blind to Blob APIs. Aster
intersects locally enabled adapters with authenticated peer capabilities and
policy, ranks them from retained health evidence, and selects one usable
adapter per attempt. A healthy stream is not interrupted merely to chase a
higher theoretical rate.

On retry Aster may select another eligible adapter, but it reuses the same
logical stream/open digest and receiver checkpoint under a fresh attempt nonce
and authenticated session. No two adapters carry data concurrently for the
same logical attempt.

The first milestone may register only Iroh and therefore proves the selector
seam, not cross-transport superiority. Best-available selection is claimed only
after a second production adapter is independently qualified.

## Error model

Errors distinguish:

- malformed or unsupported stream format;
- authentication, signature, or accumulator failure;
- conflicting operation, stream, or final commitment;
- policy, authorization, TTL, or deletion-fence rejection;
- declared-size or quota rejection;
- temporary buffer, writer, or storage backpressure;
- checkpoint corruption or unavailable resume state;
- transport establishment, closure, or stall; and
- local source/destination I/O failure.

Peer-visible errors are typed and sanitized. Local logs may include stage and
checkpoint diagnostics but never plaintext, content keys, credentials, raw
paths, or unsanitized peer text.

## Performance observability

Each completed or failed stream records bounded counters and histograms for:

- application bytes accepted/emitted;
- plaintext hash, content-encryption, pack-write, pack-read, verification, and
  transport byte rates;
- buffer-pool occupancy and backpressure duration by stage;
- frames, segments, durability checkpoints, and retransmitted bytes;
- checkpoint data-barrier and metadata-commit latency;
- time to first byte, first durable checkpoint, local promotion, remote
  promotion, and application completion;
- transport adapter, attempt count, and failover count; and
- peak RSS and open pack descriptors during qualification.

Stage instrumentation must make the limiting stage observable. A result cannot
claim transport-limited operation merely because aggregate throughput improved.

## Performance acceptance

The first supported CM4 profile is accepted only if all of the following hold:

1. Exact 800-MiB and at least 1-GiB payloads publish, replicate, and read with
   matching SHA-256 and final `BlobId` evidence.
2. Peak resident memory remains within the declared fixed streaming budget and
   does not grow with Blob length.
3. Database commits and filesystem durability barriers grow with checkpoint
   batches, not segment or application-frame count.
4. No whole-Blob staging file or second plaintext pass occurs on the successful
   publish path.
5. A forced interruption resumes from the last durable checkpoint with a
   retransmitted tail bounded by the advertised batch/window.
6. The sender and receiver each demonstrate hash, encryption, verification,
   and sequential pack I/O capacity above the selected transport's sustained
   payload rate for the declared deployment profile.
7. On the same devices and network path, sustained end-to-end payload rate is
   at least 80% of the raw selected-transport payload rate measured with the
   same frame/window bounds. Hashing, encryption, verification, pack write,
   and pack read microbenchmarks each sustain at least 125% of that raw rate.
   If either ratio fails, the run is not transport-limited and does not qualify.
8. No stage exhibits a per-segment latency multiplier; throughput remains
   approximately stable from 256 MiB through 1 GiB.

The previous 1.55-MiB/s publish and 1.85-MiB/s read results are regression
baselines that the new architecture must exceed, not acceptable profile-5
evidence.

## Verification strategy

Implementation proceeds test-first at independently observable boundaries:

- canonical open, segment, checkpoint, finish, and result vectors;
- incremental accumulator equivalence and checkpoint restoration;
- AEAD substitution, reordering, truncation, duplicate, and cross-stream
  rejection;
- provisional content invisibility and non-forwardability;
- exact duplicate finish and conflicting finish behavior;
- pack crash points before data barrier, after data barrier, between checkpoint
  generations, and around promotion;
- bounded buffer permits under success, cancellation, error, and panic;
- backpressure without deadlock when the durability batch fills;
- local publish resume for a seekable source;
- remote resume and bounded tail retransmission;
- finite-TTL expiry and policy change during a stream;
- authenticated sequential read without per-frame writer transactions;
- deterministic selector behavior and single-active-transport enforcement; and
- targeted release performance tests with retained stage metrics.

The physical validation sequence is 64 MiB for instrumentation sanity, 256 MiB
for stable-rate comparison, 800 MiB for the customer regression, and at least
1 GiB for the required large-object boundary. Full repository tests are left to
CI; local verification uses focused protocol, store, node, agent, and CLI tests.

## Implementation boundaries

The work is delivered in vertical increments:

1. canonical incremental accumulator and profile-5 frame grammar;
2. append-only pack plus crash-safe checkpoint journal;
3. single-pass local application publish and authenticated read sessions;
4. transport pipeline with credit, resume, and final settlement;
5. lifecycle, pressure, and cleanup integration;
6. stage metrics and local release benchmarks; and
7. two-CM4 then three-CM4 physical qualification.

An increment is not considered complete if it converts data back through the
legacy carrier-per-file depot, stages the entire plaintext, or acknowledges
progress that is not represented by the durable pack checkpoint.

## Requirement alignment

This design preserves immutable content identity, publisher authentication,
encrypted at-rest/in-flight content, bounded resources, durable restart,
transport abstraction, idempotent operations, policy/lifecycle enforcement,
and atomic application visibility. It changes when final content identity is
established: authenticated provisional admission precedes bytes, while the
publisher-signed immutable content commitment follows the final byte.

That ordering is necessary for a genuine single-pass stream. Security derives
from never treating provisional bytes as a Blob and from binding the final
signature to the complete open intent and both incremental roots.

## Approval record

The user rejected compatibility with the carrier-per-file profile-5
implementation as a design constraint after CM4 validation measured only
1.55/1.85 MiB/s. The approved direction is a protocol-level streaming design
whose non-transport stages are pipelined and qualified with enough headroom for
transport to be the limiting stage in the supported deployment envelope.
