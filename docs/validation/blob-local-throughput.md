# Local Blob throughput investigation

Clean Room — Privileged.

## Scope and provenance

Local branch `perf/blob-local-throughput` starts at main
`fcf9f1b054f9623b61435659994fad0bc6c51779`. It incorporates the existing Aster
stream implementation from PR #97, commit
`04005b4e8c17a65e8f53a56e7510bc2d75efd59b`, and the changes described below.
Nothing was pushed. This is a semantic-v9/profile-5 stream implementation;
the throughput results do not apply to older Blob profiles or mixed versions.

The requested threshold is interpreted as **100,000,000 plaintext bytes per
second (100 MB/s)**. MB/s below is decimal; fixture sizes in MiB are binary.

## Current acceptance result

The final delivery build passed the fixed six-run series on this host. The slowest
run measured **137.050 MB/s**. Every run completed with zero contact errors,
direct-only transport and a complete SHA-256 match after receiver reopen.

| Fixture | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| 256 MiB | 279.252 MB/s | 230.951 MB/s | 169.775 MB/s |
| 512 MiB | 137.050 MB/s | 158.230 MB/s | 140.165 MB/s |

Executable SHA-256:
`ba6821c4acea8e9f46bd996ffb1cc5a53fbc81048f6751ddb5fb6965fb87ba49`.
Receipts are `delivery-final-{256,512}m-{1,2,3}.json`;
`delivery-final-acceptance.json`
checks the minimum across all six, the single executable hash, full plaintext
hash verification and both nodes' contact receipts. All use `running` timing
described below, which includes final publication commit and contact scheduling.
Free disk was approximately 9.36 GB. Builds and tests were quiescent.

The release build also produced `aster`, `aster-agent` and `asterctl`, retained
in `artifacts/blob-local-throughput/bin-delivery/`; exact hashes and the build
source manifest are in `delivery-binaries.json`. This benchmark is built in the
same Cargo invocation as those applications:

```sh
cargo build --release --locked -p aster-node -p aster-agent -p asterctl \
  --bin aster --bin aster-agent --bin asterctl --example blob_stream_throughput
```

The subsequent source change repaired only the new publication-wake test
fixture; production code was unchanged. The tested source manifest is
`243f9890f758384c5058666b2d069a84a4ece54240a1df488f09373a3a8b3a57`.
The complete workspace run plus the repaired regression, final foundation,
Clippy, doctests and integration checks are documented under Validation status.

The earlier standalone candidate also passed a fixed six-run series:
256 MiB at 156.549, 152.147 and 126.155 MB/s; 512 MiB at 102.862, 132.557 and
104.419 MB/s. Its executable SHA-256 was
`54522267d9068702192004b47fefac42e5eaf4dcb5cac353f6f0a927cf9e331b`
(`candidate-acceptance.json`, approximately 9.45 GB free). Its distinct binary
is not substituted for the final delivery measurement above. Earlier failed
experiments below remain part of the evidence; they are not included as
successful acceptance runs. These observed series establish the threshold for
this host and workload, not a minimum across arbitrary hardware or disk load.

## Causes and changes

- Main's legacy Blob path repeatedly commits small ranges and transfers a
  bounded set per contact. Its retained 8 MiB baseline took 16.72 seconds
  (0.50 MB/s), including contact scheduling. The existing stream implementation
  removes this per-range/per-contact bottleneck for new stream publications.
- The release profile optimized for executable size (`opt-level = "z"`). It
  now uses `opt-level = 3` for the encryption, hashing and transport hot paths.
- Each ordered QUIC response waits for FIN acknowledgment before the next
  exchange. Default delayed ACKs accumulated about 1.1–1.24 seconds per empty
  authenticated contact. Requesting a 1 ms maximum ACK delay reduced those
  contacts to approximately 0.13–0.26 seconds. Packet and reordering thresholds,
  completion waits, stream concurrency and admission checks remain unchanged;
  peers without ACK_FREQUENCY support ignore the request.
- An 8 MiB application window with a 7 MiB checkpoint batch left too little
  data in flight during a durable commit. Completed packs now use 512 MiB of
  application credit and a 240 MiB durable-checkpoint grouping threshold while
  parser/append callbacks remain bounded at 15 MiB. Each callback also flushes
  at EOF, before credit exhaustion, or when 2 seconds have elapsed since the last
  checkpoint; this is a callback check, not an independent flush timer. The
  entire Store-confirmed checkpoint authority is cached: intermediate callbacks
  repeat that authority without advancing durable offsets, roots or credit.
  Retained sources keep 32 MiB credit and their separate 8 MiB Store batch cap.
  QUIC retains 16 MiB per-stream and 32 MiB connection receive/send windows,
  independently of the unchanged frame admission limit.
- Synchronous file, journal and database barriers now use `block_in_place`
  on a multithread Tokio runtime so transport work can continue during disk
  waits. Current-thread embedded runtimes retain the synchronous path.
- Deferred network receive callbacks can start one owned background data sync
  after 32 MiB of new pack bytes. It overlaps disk work with later receive and
  verification work; it never publishes checkpoint authority. Checkpoint joins
  the worker and still performs the original foreground data sync, journal sync
  and Store commit. Cancellation joins before releasing the exclusive writer
  lease. Local publication and retained-source append paths do not start it.
- An idle Blob maintenance turn now uses a fresh read-only snapshot to skip
  work only when all relevant maintenance tables are empty, schema/pressure
  state is current, and clock continuity is already anchored. Startup still
  performs maintenance, and the generic runtime custody observation remains
  unconditional. No remembered idle flag can hide later work.
- A successful new live Blob publication now wakes the existing bounded peer
  contact scheduler immediately. Previously it could wait for the next 500 ms
  synchronization tick. Failed operations, exact retries, reads and upload
  chunks do not emit this notification; concurrent publications coalesce.
- Simultaneous contact rejection now uses a distinct QUIC application close
  code and exact reason. A non-preferred outgoing attempt recognizes that
  explicit cancellation even if it finishes before the matching inbound contact
  is accepted. It adds no successful or authenticated contact receipt. Ordinary
  closes, protocol/authentication/storage errors and task panics remain errors.
- Repeated completed-pack contacts now settle as `AlreadyPresent`, without
  writing the payload again. Terminal results distinguish plaintext length
  from encrypted wire length. A durable per-peer scheduling cursor rotates
  completed publications so the first Blob cannot starve later ones.
- An interrupted first checkpoint can be retried when a journal was persisted
  before the database commit. Recovery validates the exact reservation and
  private pack entries, preserves unknown artifacts, and holds an exclusive
  per-stream writer lease through promotion, including Store reopen.
- Retained and finite-lifetime sources keep their authenticated resume path.
  Selection is restricted to the current peer's exact reconciliation inventory
  and new admission, so an unrelated interrupted source cannot block another
  peer. Retained carrier batches keep the Store's separate 8 MiB bound.
- An upload handle now owns cleanup while its open reply is queued. Cancellation
  before delivery releases the singleton upload slot; cleanup survives a full
  worker queue. A completed operation cannot have two simultaneous handle owners.
  Once Finish is queued, the actor owns cleanup, preventing cancellation of an
  old reply from closing a later retry handle.
- Finite RPC publications retain the established private-file staging and
  custody-aware retained path. They restart upload at offset zero after a
  disconnect and retain operation-key idempotency. Durable RPC publications use
  the new exact-offset stream path. The finite size limit is the lesser of the
  configured publication quota and the existing legacy finite limit.
  Staged finite chunks report accepted-only progress with durable offset zero,
  keeping active uploads alive past the response idle bound without advertising
  resumability. The CLI requires monotone offsets and actual progress in at least
  one offset, while retaining sent-byte and total-length bounds.
- Local finite completed-pack reads and completed retries check signed custody
  age, expiry and clock continuity. The new completed-pack network path withholds
  and rejects finite publications because it lacks receiver-local custody
  authority; retained finite transfers continue through custody-v2.
- Stream admission now checks the ordinary aggregate Store quota as well as
  physical depot capacity. Promotion rechecks the exact pack charge atomically
  because other classes may consume capacity during upload. This prevents a
  successful oversized publication from making the Store fail its next reopen;
  existing-reservation and duplicate-publication retries remain idempotent.
- Native gRPC early errors keep status and typed details together in terminal
  trailers, avoiding ConnectRPC 0.9.1's premature initial-header error return.
  Header-only response bodies retain their sole status source.

Durable acknowledgments still follow pack data sync, atomic journal sync and
database commit. Grouping reduces their frequency without removing a barrier or
acknowledging appended-only data. The experimental journal rewrite and file
preallocation were not adopted.

## Reproducible measurement

`crates/aster-node/examples/blob_stream_throughput.rs` starts two actual Nodes
over direct loopback Iroh QUIC, using separate disk-backed stores in one
benchmark process and Tokio runtime. It publishes
deterministic non-repeating data before starting the transfer timer. The timer
includes connected-node startup, authentication, transfer and durable receiver
visibility. It excludes initial publication and subsequent verification.
Throughput uses `transfer_until_ready_ns`; the later 600 ms settlement wait,
shutdown and verification are excluded. After shutdown, the receiver store is
reopened and the entire plaintext is read and checked against the source
SHA-256. Contact errors or relay fallback fail the benchmark.

```sh
cargo build --release --locked -p aster-node --example blob_stream_throughput
umask 077
target/release/examples/blob_stream_throughput \
  /path/on-the-test-disk/new-empty-fixture 536870912 120
```

The optional fourth argument `running` starts both nodes and settles an empty
authenticated contact before publication. Its timer starts immediately before
the publisher's `finish()` call, before any completed publication is visible to
the network. It includes final source commit, contact scheduling, the complete
transfer and receiver durable visibility; it excludes node startup and initial
source writes. The default `cold` mode retains the startup-inclusive timing
above. Both modes perform the same full hash check after receiver reopen.

```sh
target/release/examples/blob_stream_throughput \
  /path/on-the-test-disk/another-new-fixture 536870912 120 running
```

The optional `ASTER_BENCH_WORKERS` controls only the benchmark runtime. With
it unset, the runtime uses Tokio's production default. These runs used 12
workers, a 1 GiB payload quota and a 1 GiB depot quota. The depot quota
accommodates the complete encrypted fixture, including its metadata overhead.

Host: AMD Ryzen 5 230, 6 cores / 12 logical CPUs, Linux, ext4 on local NVMe.
All measurements below use that disk, direct loopback transport and full
plaintext SHA-256 verification after receiver reopen; no RAM disk was used.
Builds and tests were quiescent during throughput runs. Generated fixtures were
removed after successful verification; logs and JSON receipts remain locally
under `artifacts/blob-local-throughput/`. Removing this investigation's obsolete
build caches restored about 10.6 GB free before the previous production repeats;
the latest grouped diagnostic receipts record about 9.6 GB free. Earlier low-free-space
runs are historical evidence, not the current disk state.

### Previous production candidate: threshold not met

Executable SHA-256:
`aa48a51c39917bda1e264abe61404ce725efbc60ca409e29544762427db9211a`.
This candidate includes the 1 ms ACK-delay request but checkpoints each bounded
append batch.

| Receipt | Plaintext size | Durable-ready throughput |
| --- | ---: | ---: |
| `delivery-512m-1.json` | 512 MiB | 194.419 MB/s |
| `delivery-512m-2.json` | 512 MiB | 88.659 MB/s |
| `delivery-512m-3.json` | 512 MiB | 77.208 MB/s |
| `delivery-256m-1.json` | 256 MiB | 68.851 MB/s |

Every receipt has matching complete hashes, zero contact errors and no pending
receiver source after reopen. The slower repeats fail the requested minimum;
the fast first result does not establish sustained 100 MB/s.

### Grouped checkpoint diagnostic: initial positive evidence

Diagnostic executable SHA-256:
`43387fb671638a518c414152c9a471bf74c1dff48c3548490b1bf653c9f6ccaf`.
The isolated snapshot enables 60 MiB checkpoint grouping with 128 MiB application
credit. These are diagnostic receipts, not measurements of the final rebuilt
production executable.

| Receipt | Plaintext size | Durable-ready throughput |
| --- | ---: | ---: |
| `grouped-current-60-512m-1.json` | 512 MiB | 216.883 MB/s |
| `grouped-current-60-512m-2.json` | 512 MiB | 117.486 MB/s |
| `grouped-current-60-512m-3.json` | 512 MiB | 114.751 MB/s |
| `grouped-current-60-256m-1.json` | 256 MiB | 138.309 MB/s |
| `grouped-current-off-512m-1.json` (same binary, grouping disabled) | 512 MiB | 106.631 MB/s |

All five runs completed with full hash matches, zero contact errors and clean
receiver reopen. The four grouped runs exceed 100 MB/s. The production source
contains the same bounded grouping and cached-authority behavior, but the later
production repeats below failed the minimum. These diagnostic results therefore
do not establish final production acceptance.

### Production grouping candidate: slower repeats still miss the target

Executable SHA-256:
`c1db04be94f272e58513aa5e287aa2300287c7cb852448b24e242ec7f278d03c`.

| Receipt | Plaintext size | Durable-ready throughput |
| --- | ---: | ---: |
| `accepted-512m-1.json` | 512 MiB | 115.086 MB/s |
| `accepted-512m-2.json` | 512 MiB | 77.883 MB/s |
| `accepted-512m-3.json` | 512 MiB | 102.005 MB/s |
| `accepted-256m-1.json` | 256 MiB | 75.549 MB/s |

The receipt label records the attempted acceptance series, not a passing result.
All hashes and reopened stores verified, but the minimum was not met. The older
successful diagnostic executable then measured 85.927 MB/s in the same current
environment (`comparison-diagnostic-60-512m.json`). Startup-inclusive production
runs measured 91.610 and 82.640 MB/s at 512 and 256 MiB. After removing this task's
cache archives from tmpfs and deleting its obsolete debug caches, available RAM
rose from about 3.6 to 5.7 GiB and free disk was about 9.6 GB. The same executable
then measured 93.521 and 118.072 MB/s (`accepted-unpressured-*`), still insufficient.

Current storage-only probes measured 110–118 MB/s with 60 MiB sync groups and
110–140 MB/s with 128 MiB groups. These differ from the earlier 161–174 MB/s probe;
changing grouping alone does not establish a universal storage throughput floor.

A payload-free `fsync`/`fdatasync` trace (`accepted-sync-trace-1.strace`) confirmed
8 receiver data checkpoints plus the final barrier: no premature timer flushes.
During the 4.847-second first-to-last receiver pack-sync interval, pack syncs took
3.117 summed syscall seconds. Idle Blob maintenance on both peers added 24 redb
syncs totaling 0.863 syscall seconds, overlapping data I/O. These durations must
not be added as elapsed time. The idle-maintenance change targets these empty
turns while preserving the generic runtime custody-clock observation.

### Idle maintenance and larger checkpoint groups

Skipping provably empty maintenance reduced background commits, but did not
alone meet the target: `idle-512m-{1,2,3}.json` measured 84.946, 94.607 and
102.103 MB/s, and `idle-256m-1.json` measured 91.436 MB/s. The corresponding
binary SHA-256 is
`fbb26963dc9903cb00e7af4c74303d50cd43dff5fa4caa88626a8f454d6e18a4`.
Its sync-only trace reduced publisher redb syncs during the receiver pack-sync
interval from 27 to 10. Disk latency varied between runs; this is evidence of
less background work, not a standalone throughput guarantee.

Increasing the grouping threshold to 240 MiB, application credit to 512 MiB
and callback flush interval to 2 seconds produced 128.258, 117.143 and
110.917 MB/s at 512 MiB (`large-group-512m-{1,2,3}.json`), but 97.661 MB/s
at 256 MiB (`large-group-256m-1.json`). All hashes and reopens passed. Binary
SHA-256: `ee11b6bf68c0b60b3618feb9354e5e5d0bcb708af323c0f3e9140a11d50307b0`.
This series still failed the requested minimum. A separate instrumented
256 MiB run showed only about 4 ms for the short final pack-sync tail, which
did not support further increasing the grouping threshold.

The final scheduling change removes the wait for the next ordinary contact
tick after a successful new publication. Its independent source review found
no change to emission-policy, contact-concurrency or fatal-worker handling.
Binary `58c6dab65996cbad72bd2ba088c383de339d56c9c309a44b8b5d61a6f0cebbfa`
measured 115.629, 122.418 and 140.208 MB/s at 512 MiB, but the subsequent
256 MiB repeats measured 87.233 and 109.636 MB/s. Another 256 MiB run reached
readiness in 2.230 seconds but failed receipt validation: collision cancellation
raced a task that had already returned the peer's clean close. It is retained
as a failed run, not a throughput acceptance result. The first attempted fix recognized only
the exact clean-close error on a task already marked as collision-cancelled;
fatal errors, other errors and task panics remain visible.

The instrumented `wake-256m-trace` measured 94.100 MB/s. Its first receiver
pack sync took 1.395 seconds of 2.853 seconds until readiness. A forced
publication wake bypasses the non-preferred peer fallback timer; that timer
does not explain this delay. A separate paced disk-only experiment compared
foreground sync against one owned in-flight background sync with the same
final barrier. Baseline runs measured 87.255, 179.090 and 122.218 MB/s;
overlapped runs measured 119.345, 141.269 and 164.296 MB/s. This motivates
testing overlapped writeback in the receiver, but is not Blob acceptance.

The first overlapped-writeback candidate
(`40007fc8aa18c7733e51424a09bccc9ff774767d29287b662309cc556c1e3d9c`)
passed two 256 MiB runs at 121.406 and 107.917 MB/s and two 512 MiB runs at
105.131 and 148.672 MB/s. One run of each size failed the zero-contact-error
check: the remote collision close arrived before the local inbound contact
could mark cancellation. The failed runs reached readiness in 0.985 and
5.457 seconds respectively, but full post-reopen verification did not execute;
neither is acceptance evidence. Their synthetic fixtures were discarded after
diagnosis to restore disk space; all logs and failed receipts remain intact.
The collision handling therefore needs an explicit peer collision signal,
independent of the race between local inbound acceptance and task completion.

### Earlier evidence and rejected experiments

Earlier stream candidates measured about 55–97 MB/s on slower repeats; moving
node startup outside the timer did not resolve that limit. The ACK-delay change
substantially reduced empty-contact latency, but its diagnostic repeats still
varied from 108.11 to 79.24 MB/s. Window tuning, journal rewriting, preallocation
and an earlier grouping experiment did not independently establish the target.
Those experiments do not supersede the current-source grouped receipts above.

The latest phase diagnostic (`phases-final-512m.log`) attributes 3.640 of 5.089
receiver seconds to checkpoint work, versus 0.363 s copying/decoding, 0.148 s
decrypting, 0.527 s appending and 0.329 s awaiting data. A contemporaneous raw
512 MiB disk probe with `fdatasync` every 15 MiB measured about 174, 173 and
161 MB/s (`disk-probe-delivery-15m.json`). These storage-only results and the
Blob phase timings support reducing checkpoint frequency; they are not Blob
acceptance results or proof that free space alone caused the slower repeats.

## Resource and compatibility boundaries

The larger flow-control windows allow more bounded buffering per connection;
they are not a global resident-memory limit. Default high connection concurrency
can therefore use more memory than before. Completed-pack callbacks remain
bounded at 15 MiB; the 240 MiB grouping threshold can be crossed by one callback
before flushing. Appended data above the cached durable checkpoint remains
replayable after interruption and never advances advertised durable authority.
The 512 MiB credit, frame limits and flush-before-credit-exhaustion check bound
that work. Retained sources retain 32 MiB credit and 8 MiB checkpoint batches.
Background writeback adds at most one file descriptor and one thread with a
256 KiB requested stack per active receiving pack. Existing inbound/outbound
contact caps bound the node's active receiver count. It allocates no buffer
proportional to the checkpoint group. Cancellation and shutdown may wait for
the outstanding disk sync; no worker is detached.

The new `BlobStream` scheduling cursor uses persisted class tag 4, distinct
from the existing Blob cursor. An older binary that does not recognize tag 4
cannot read that cursor table after a stream contact writes it. Do not downgrade
an affected store in place without a compatible migration.

Retained-source selection adds protected semantic-v9 frame tags `0xe1`/`0xe2`;
finite retained opens bind their authenticated custody digest into `open_digest`.
Both peers must use this coherent v9 implementation. Earlier development v9
snapshots are not wire-compatible with this restored phase. Semantic v7/v8
framing and the independently negotiated profile-4 path remain unchanged.

The benchmark exercises same-host direct transport, not separate physical
machines, WAN paths, relay throughput, multiple simultaneous transfers, or
steady-state operation across different storage devices or free-space levels.

## Validation status

Validation completed before the latest production grouping change:

- `mise-check-delivery.log`: full `mise check` passed, including **2,454 tests
  passed and 3 skipped**, doctests and integration checks.
- `finite-progress-final.log`: the later finite-upload progress changes passed
  **190 focused tests**, including active upload beyond the response-idle bound
  and retry from offset zero. Foundation and Clippy checks also passed
  (`foundation-final-progress.log`, `clippy-final-progress.log`).
- `fuzz-final-decoders.json` / `.log`: `selected_frame_decode` and
  `stream_transfer_decode` each completed **10,000 fuzz runs**.

The grouped candidate and quota fixes subsequently passed five focused tests,
including interrupted transfer, durable reopen, quota races and idempotent retry
(`grouped-quota-focused-2.log`). Its complete all-feature workspace run passed
2,460 tests and failed one test, with 3 skipped (`mise-check-accepted-final.log`).
The failure was a test enqueue-order race in
`blob_gc_yields_to_operational_priority_gate`: the spawned subscription had not
necessarily entered its channel before the actor timer was released. Explicitly
polling the future once before releasing the actor repaired the ordering; the
test then passed 30/30 stress repeats (`maintenance-race-fixed.log`). This test-only
change produced byte-identical release executables.

Foundation, all-workspace/all-target/all-feature Clippy, doctests and the complete
integration task passed after that repair (`*-accepted-race-fixed.log`,
`doctests-accepted-final.log`, `integration-accepted-final.log`). The integration
build was interrupted once for disk space and subsequently completed from the
start. `validation-accepted.json` retains exact log hashes. This is composite
verification, not a claim that the failed monolithic gate exited successfully.

The final production version, including idle maintenance, publication wake,
explicit collision cancellation and owned background writeback, passed the
six-run candidate performance acceptance above. Its final foundation and
all-target/all-feature Clippy checks passed. The complete workspace run then
passed **2,474 tests**, failed one new fixture, and skipped 3
(`mise-check-writeback-final.log`). The failed non-preferred publication-wake
fixture incorrectly used `ReceiveOnly`, which intentionally omits mutable
classes. Only the test was repaired: both peers now use normal emission,
settle their initial empty contact, and must transfer both publications before
either periodic contact or election fallback can run. Byte checks and zero
contact-error assertions remain mandatory. Both publication-wake tests then
passed 10 stress iterations each (**20/20 executions**). Foundation, Clippy,
doctests and the entire integration task passed after that test-only repair,
including both real-process scenarios, C/C++ header checks, Rust/Python
conformance, Python bindings and laboratory tests, Go bindings and generated
agent bindings. Logs are `publication-wake-final-stress.log` and
`{foundation,clippy,doctests,integration}-delivery-final.log`.
`validation-delivery-final.json` records their exact hashes and exit codes.
This is composite verification; the failed monolithic command is not
represented as a successful gate.

Public component provenance: `iroh` 1.3.0 and `noq` 1.3.0 from their public
crates.io packages, `redb` 4.3.0 from crates.io, and `negentropy` 0.5.2 from
<https://crates.io/crates/negentropy/0.5.2>. Exact locked sources and checksums
are recorded in `Cargo.lock`; no new transport dependency was introduced by
the throughput tuning itself. RPC fixture diagnosis also inspected `connectrpc`
0.9.1 from <https://github.com/connectrpc/connect-rust>. Its early header-only
errors remain conservatively classified as unknown outcomes by the CLI; a
terminal typed rejection is required for the stronger known-rejection result.
