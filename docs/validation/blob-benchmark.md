# Selected Blob loopback benchmark

This diagnostic measures the real selected-node file-publication and direct-Iroh
Blob path. It is bounded maintenance toward roadmap P2-2 measurement, not a
requirements-credit receipt, WAN qualification, or a production throughput SLA.
No requirements evidence or maturity status changes.

## Reproduce

Use the pinned mise toolchain and **separate target directories/checkouts** for
baseline and candidate. Copy the exact same example to the baseline checkout;
leave its production files unchanged. Build both before measuring:

```sh
mise exec -- sh tools/with-test-resources.sh cargo build \
  --release --offline --locked -p aster-node --example blob_benchmark
python3 tools/test_blob_benchmark.py
python3 tools/blob_benchmark.py \
  --variant baseline /absolute/baseline /absolute/baseline/target/release/examples/blob_benchmark \
  --variant fixed /absolute/candidate /absolute/candidate/target/release/examples/blob_benchmark \
  --output /durable/new-results --state /scratch/new-fixtures
```

Both output and fixture directories must be new; previous evidence is never
reused or overwritten. Python 3.11+ is required. Fixtures contain only synthetic
public-reference mission identities, generated source data and test stores.
Keep them outside version control. The runner applies an owner-only umask.

Default campaign: 8 KiB, 96 KiB and 1 MiB (three samples each), then 4, 8, 16,
24, 32, 48 and 64 MiB (one each), for 16 samples per variant. Sizes use binary
units. `--sizes` selects a subset in exact bytes. For example, `--sizes 8192
98304` runs the two small sizes. Baseline/candidate runs alternate by sample;
no builds or competing benchmark runs should run during measurement. Large
samples below 64 MiB have a receive bound of 180 seconds per MiB (at least 180
seconds), permitting completion of the deliberately slow baseline. The 64 MiB
case is an explicitly bounded 180-second progress experiment, **not** a
completed-throughput test. The outer watchdog adds 180 seconds for publication,
verification and shutdown; an external timeout is a failed run, not throughput.

The example can also be invoked directly as `blob_benchmark NEW_DIRECTORY BYTES
RECEIVE_DEADLINE_SECONDS`. An oversized regular file exercises the public API's
resource-limit rejection; it is not transferred and no limits are raised.

## Exact boundaries

- Two node actors in one process, two Tokio workers, independent stores and
  synthetic identities; explicit loopback peer addresses. This is not the agent
  RPC path and not two physical hosts. Identities and ephemeral ports vary.
- `NodeConfig::new` defaults: 500 ms scheduler, unchanged contact/range/storage
  budgets and ACK configuration. Only the benchmark Blob topic/scope is selected.
- Input generation uses the fixed SplitMix64 output permutation of an aligned
  word counter (test data only, never credentials). Every aligned 64-KiB chunk
  differs throughout the live 64-MiB ceiling; a short-period repeating fixture
  would risk measuring deduplication instead of distinct-chunk movement.
  Generation, source SHA-256 and file fsync occur before publication.
  `publication_ns` brackets the awaited live file publication.
- `transfer_until_ready_ns` starts immediately before connected-node startup and
  ends on the first successful receiver read (20 ms readiness polling). It
  includes startup, authentication, synchronization and readiness observation,
  not publication or the following accounting settle.
- `transfer_ns` additionally includes an explicit 600 ms accounting settle,
  both node shutdowns and receiver Store reopen/invariant checks. It is **not**
  pure network time. The settle can add empty contacts to receipt counts.
- `verification_ns` is a new peerless receiver actor's complete paged plaintext
  read and SHA-256 check. Every page's ID, publisher, length and offset is
  asserted; verified bytes must equal source bytes. No peer can repair the
  reopened receiver during verification.
- `total_ns` spans publication through completed verification (including the
  intermediate shutdown), excluding initial setup and final verification-node
  shutdown. Python process time is a separate wider boundary.
- Timeout results retain observed duration, fetched **encrypted carrier** bytes,
  pending source and durable chunk/staging counts. They have no completed
  plaintext goodput or completion time. Rejection is separately classified.
- The example asserts all connected contacts are direct, with zero relay,
  unknown-path or error contacts. Raw receipts retain the exact counts.

Each sample immediately writes stdout, stderr and fsynced JSON. The runner
captures AC state, battery state, power profile and all CPU governors before and
after every run; it never changes power settings. Inspect these before pooling
samples: power-state changes require separate campaigns. Machine metadata,
source-file hashes (including untracked additions), Git revision/diff, example
and binary hashes, compiler and actual release profile are retained. The default
release profile optimizes size (`opt-level=z`, thin LTO, one codegen unit), not
maximum throughput. Normal OS caches and background desktop load remain; this
is not an idle-host or cold-cache guarantee.

At completion final source and binary identities are retained and compared before
publishing `summary.json` or `summary.csv`. A mismatch leaves raw receipts and
`source-after.json` as diagnostic evidence without publishing normal summaries.
The summaries are recomputed from retained individual JSON files, with verified
sample counts. Readiness medians use
Python's `statistics.median` over **completed samples only**, and expose both
sample and completed counts. A one-sample row is one observation, not a robust
latency distribution. Never compare readiness against settle-inclusive transfer.

## Response ACK pipeline contract

Intermediate responder calls finish their QUIC stream and retain its `stopped()`
completion rather than serially waiting for a delayed transport ACK. A
connection-shared queue holds at most 16 completion handles; one additional
response may be waiting for a slot. Capacity is reusable after acknowledgements,
not a session-lifetime exchange limit. No per-response tasks are spawned and
existing QUIC flow control/retransmission bounds remain in force. Cloned
responders serialize through the same queue lock.

Every retained completion still checks transport error, STOP_SENDING and its
bounded ACK wait. Errors are surfaced on subsequent submission or completion;
intermediate `Ok(false)` means the response was handed to QUIC, **not** confirmed
application consumption. Final `Ok(true)` drains all transport completions,
preserving one-shot callers' final-response delivery behavior. The explicit
final consumed marker and close handshake remain mandatory for application
completion; ACK alone is not evidence of consumption. Failed or cancelled
responder operations close the connection rather than allowing uncertain state
to be reused. Dropping the connection cancels retained handles without detached
tasks. Scheduler pacing, ranges per contact, wire framing, storage limits and
transport-wide ACK frequency are unchanged.

Deterministic oneshot-controlled regressions check ACK-independent continuation,
backpressure/reuse and final delivery errors. Real loopback tests cover repeated
exchanges, final consumption, STOP_SENDING, cancellation and completion timeout.
These tests are not proof under every loss, high-RTT, reordering or WAN condition.

## Historical loopback comparison (not a current-main measurement)

The six-size campaign used baseline revision
`5f119e1156be15585a5a0dc12c3793737f46af7d` and the same revision plus the ACK
pipeline, before this change was ported to upstream main
`f4f93c6e76b3ab0d1505d9036bc1a5a8412029d6`. These are not measurements of the
ported branch or its newer Event/uni-turn implementation. No performance rerun
on the newer base is claimed. The user shortened the sweep to end at 16 MiB.

| Payload | Samples/variant | Baseline ready, s | Pipeline ready, s | Speedup | Time reduction |
|---|---:|---:|---:|---:|---:|
| 8 KiB | 3 | 1.270938 | 0.616083 | 2.063× | 51.53% |
| 96 KiB | 3 | 11.726621 | 7.568562 | 1.549× | 35.46% |
| 1 MiB | 3 | 119.752435 | 76.177302 | 1.572× | 36.39% |
| 4 MiB | 1 | 479.872735 | 305.209808 | 1.572× | 36.40% |
| 8 MiB | 1 | 959.866305 | 609.912628 | 1.574× | 36.46% |
| 16 MiB | 1 | 1920.067876 | 1200.021176 | 1.600× | 37.50% |

All 24 runs completed with full plaintext verification after reopen and direct
contacts only. Source and binary identities matched across that campaign.
Host AC was online, battery Full, profiles balanced and governors powersave;
one peripheral HID++ battery entry disappeared during the last sample, without
a host power-control change. Three repetitions through 1 MiB use medians;
larger rows are single samples. The environment was one Linux x86_64 ThinkPad
E14 (Ryzen 5 230), normal caches/background desktop load, size-optimized release
builds. No WAN, loss, power-loss or production throughput claim follows.

Remaining failure-state coverage gaps include cancellation during partial
write/backpressure with queued completions, deferred intermediate STOP_SENDING,
queued ACK timeout and concurrent connection clones. Existing focused tests
do not establish those cases.
