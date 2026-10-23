# Blob range streaming loopback measurement

This diagnostic compares upstream main with the optional receipt-free Blob
range-stream profile on one host. It adds no requirements credit, WAN
qualification, or production throughput guarantee. The Rust fixture is copied
unchanged from the prior ACK experiment; no ACK production code is imported.

## Reproduce

Build the identical `crates/aster-node/examples/blob_benchmark.rs` in separate
baseline and feature checkouts with separate Cargo targets:

```sh
CARGO_NET_OFFLINE=true mise exec -- sh tools/with-test-resources.sh \
  cargo build --release --offline --locked -p aster-node --example blob_benchmark
python3 tools/test_blob_benchmark.py
python3 tools/blob_benchmark.py \
  --variant baseline /absolute/baseline /absolute/baseline-binary \
  --variant stream /absolute/feature /absolute/feature-binary \
  --output /durable/new-results --state /scratch/new-state
```

The default campaign is exactly one run per variant at 16 KiB, 64 KiB, 256
KiB, and 1 MiB: eight real runs, alternating baseline then feature at each
size. A 300-second receive bound applies per run, plus an outer 180-second
allowance. `--sizes` restricts the selected campaign without adding
repetitions. Finish all builds and tests before timing; do not edit measured
sources during the campaign. The selected campaign name is retained in
`metadata.json` together with the exact cases and source/binary identities.

Select the explicit 100 MiB scale campaign with:

```sh
python3 tools/blob_benchmark.py \
  --campaign scale \
  --variant baseline /absolute/baseline /absolute/baseline-binary \
  --variant stream /absolute/feature /absolute/feature-binary \
  --output /durable/new-scale-results --state /scratch/new-scale-state
```

The current production network admission limit is 64 MiB. Therefore, the 100
MiB campaign currently qualifies the exact resource-limit rejection and its
retained receipt; it is not evidence of a successful 100 MiB network transfer.
A successful above-limit network campaign requires a separately reviewed
production-limit change.

The core streaming pipeline retains its original generated 101 MiB + 123 byte
workload as an ignored qualification test. Run only that workload explicitly:

```sh
mise run qualify-generated-blob
```

On the retained hosted baseline the original default form took about 91
seconds. For the explicit qualification, budget five warm minutes, two CPU
cores, at least 2 GiB of available memory, and at least 1 GiB of temporary
disk; cold compilation and dependency download are separate. Nextest writes
terminal output, while the test uses an isolated temporary fixture and removes
it after success. Capture the command output and machine/resource metadata in
the validation record if the result will support an engineering decision.

The default correctness test uses eight full 64 KiB chunks plus a partial
chunk. It still proves seven-chunk interruption, bounded buffers, exact resume,
deduplication, manifest and full-content verification, tail and cross-chunk
ranges, and tamper rejection without allocating a production-scale fixture.

The selected runtime also retains a local valid-Blob fixture one byte above the
64 MiB network-admission limit. Run that allocation-heavy boundary explicitly:

```sh
mise run qualify-local-blob-above-network-limit
```

Budget two warm minutes, two CPU cores, 1 GiB of available memory, and 1 GiB of
temporary disk. The test proves that a valid local Blob remains readable while
network admission rejects its size; it does not transfer the Blob or provide
throughput, device, or production qualification.

The separate `--campaign scale` benchmark runs real 100 MiB cases for both
provided variants. Allow the per-run 300-second receive bound plus the runner's
outer allowance, at least 4 GiB of memory, and enough scratch/output capacity
for both binaries, state directories, logs, and receipts (4 GiB free is a
practical minimum). Raw stdout/stderr and fsynced receipts are stored beneath
the `--output` directory; mutable stores live beneath `--state`. The ignored
pipeline qualification and the scale campaign are non-default engineering
evidence. They add no requirements credit and are not production or device
qualification unless their exact artifacts are admitted through the retained
validation process.

## Timing and verification boundaries

- Two real node actors in one process, two Tokio workers, independent stores,
  synthetic reference identities, and explicit direct-loopback Iroh addresses.
  Production `NodeConfig` defaults retain the 500 ms scheduler interval.
- Deterministic SplitMix64-counter fixture generation makes aligned 64-KiB
  chunks distinct, avoiding a repeating-data deduplication bias. Source file
  generation, SHA-256, and fsync precede publication.
- `publication_ns` brackets awaited peerless local file publication. Successful
  publication means local durable acceptance, not remote delivery.
- `transfer_until_ready_ns` brackets connected-node startup through first
  successful receiver read, polled every 20 ms. It excludes publication.
- `transfer_ns` additionally includes a fixed 600 ms receipt-accounting settle,
  both node shutdowns, and receiver Store reopen with invariant checks. It is
  not pure network time.
- `verification_ns` includes a new peerless receiver actor and full paged
  plaintext read/SHA-256 verification. Every page's identity, publisher, length,
  and offset is checked; no network repair is possible after reopen.
- `total_ns` spans publication through full verification, including intermediate
  shutdown, but excludes fixture setup and final verification-node shutdown.
- Successful runs require only direct contacts, no contact errors, no pending
  source, no residual carrier prefix or staging bytes, and exact final full
  plaintext SHA-256. Timeouts remain incomplete observations, never throughput.

The runner persists each stdout/stderr and fsynced JSON receipt immediately.
It records read-only AC/battery/profile/governor snapshots before and after
individual runs. Source and binary identities must remain unchanged before
normal summaries are published; mismatch retains raw evidence without summary.
Inspect power stability before comparing samples. Default release builds use
`opt-level=z`, thin LTO, and one codegen unit. Normal OS caches and desktop load
remain; neither idle-host nor cold-cache conditions are claimed.

Report local publication, synchronization readiness, settle-inclusive transfer,
and verification separately. One sample is an observation, not a distribution.
The harness's unit tests use explicitly synthetic subprocess receipts solely to
test summary validation; these are not performance measurements.
