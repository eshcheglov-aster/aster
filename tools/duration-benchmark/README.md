# Event publication and delivery benchmark

Run Aster agents on loopback, publish Events through
`AsterApplicationServiceClient::publish_numbered_events`, and check each confirmed
Event's ID and full payload on every agent, including its publisher. Each agent
publishes at the configured rate. Missing that rate does not fail the run.

## Build and run

From the repository root, with its pinned mise toolchain:

```sh
mise exec -- cargo build --release --locked -p aster-agent \
  --features client,acceptance-test-provider --bin aster-agent-acceptance-fixture \
  -p aster-node --bin aster
mise exec -- cargo build --release --locked --manifest-path tools/duration-benchmark/Cargo.toml
python3 tools/duration-benchmark/controller.py \
  --fixture target/release/aster-agent-acceptance-fixture \
  --initializer target/release/aster \
  --generator tools/duration-benchmark/target/release/aster-duration-benchmark \
  --output "$TMPDIR/duration-benchmark-my-run" \
  --agents 5 --duration-seconds 60 --events-per-second 10
```

Choose a new output directory outside the checkout. These commands build release
binaries with the repository's size-optimized settings. Compare release results
with release results; debug runs check correctness, not release performance.

The controller uses `aster playground-init` to create participant identities and
mission bundles. It installs those test credentials in each acceptance fixture
and connects every agent to every other agent over loopback. It uses the existing
signing implementation and leaves host networking unchanged. These fixtures use
unprotected test credentials; do not use them in production.

| Option | Default | Meaning |
|---|---:|---|
| `--agents` | 2 | Total agents, 2–16 |
| `--duration-seconds` | 60 | Publication duration, 0.01–600 seconds |
| `--events-per-second` | 10 | Events/s **per agent**, 1–100000; `max` = unlimited (no pacing). `0` remains a supported alias; positive fractional rates below 1 also remain accepted |
| `--overall-seconds` | 1800 | Total benchmark timeout in seconds, greater than duration and at most 86400 |
| `--payload-bytes` | 256 | Full Event payload size, 8–1024 bytes |
| `--max-attempts` | 100000 | Publication attempt limit per agent, 1–100000; also bounds retained measurements |

The overall timeout excludes builds, provisioning and initial session/subscription
setup. The generator allows 120 seconds for that setup. Reaching the attempt limit
before completing the offered schedule produces an incomplete measurement; the
generator still waits for accepted Events. The same attempt limit applies without
pacing.

The example offers 10 Events/second from each of five agents for 60 seconds:
600 attempts per agent, 3000 total, at 50 Events/second in aggregate. Each payload
identifies its publisher. Each fresh publication session starts its own contiguous
operation sequence. All publication and delivery timestamps use the Rust
generator's monotonic clock.

## Publication contract and timeouts

* Each agent uses one authenticated generated client and one retained HTTP/2 gRPC
  publication stream. The client sends bearer headers on each HTTP request,
  including the stream and acknowledgement requests. A publication session does
  not replace transport authentication.
* Each fresh fixture must return an empty `BeginEventPublicationSession` snapshot.
  The generator checks the session, frontier and revision, then calls
  `CompleteEventPublicationRecovery` before changing data. It does not reconnect,
  reclaim sessions or retry publications with unknown outcomes.
* Each agent can have up to eight publications in flight. The generated
  client's `into_split()` separates paced sends from ordered response handling;
  result-acknowledgement RPCs run alongside them. A publication holds one slot
  until the generator verifies and synchronizes its receipt and acknowledges the
  result. Releasing one slot permits the next due send without waiting for the
  rest of the window. This benchmark limit covers both pending responses and
  pending result acknowledgements; it is not a negotiated protocol limit.
* The public API buffers eight publication operations
  (`crates/aster-agent/src/event_service.rs::PUBLISH_EVENTS_WINDOW`), permits
  messages up to 1 MiB, and caps each requested RPC deadline at **900 seconds**.
  The generated clients request `min(overall, 900)` seconds. The durable Store
  permits 4096 outstanding results per client. These API limits are independent
  of the benchmark window and pre-authentication connection limits.
* The 900-second RPC limit also applies to the retained publication stream. That
  stream can expire before the default 1800-second overall timeout if publication
  or settlement stalls. Raising the overall timeout does not extend the stream.
  The generator stops and records `incomplete` with an error such as
  `publication_receive` or `publication_send`. Those codes identify the failed
  stage, not whether a server deadline or another transport failure caused it.
  `overall_timeout` means the generator's own deadline expired.
* Before sending, the generator writes and synchronizes an intent with the
  sequence and deterministic payload parameters. It records and synchronizes each
  accepted ID before acknowledging the publication result. Consumers check all
  payload bytes, keep first-observation timestamps, and synchronize delivery
  records before `AcknowledgeEvent`. The generator also synchronizes new journal
  directory entries. These journals retain benchmark evidence; the benchmark
  does not test restart or physical power-loss recovery.
* Only `ResourceExhaustion` and `OperationCapacityExhausted` publication outcomes
  count as capacity rejections. The generator records and abandons the rejected
  sequence, then stops with `capacity_rejection_pipeline_stopped`. Rejection
  leaves the Store frontier unchanged, so later sends may leave sequence gaps.
  The generator does not replay them or assume their outcomes. Other application,
  transport, framing, authentication, payload and acknowledgement errors also
  stop the run and retain partial measurements.

Pacing uses `start + index / rate`. Slow sends can delay later sends; the generator
does not add a minimum interval after a send or fail on schedule lag. It starts
no new sends at or after the publication cutoff. A send in progress may finish
later. After publication ends, it waits for in-flight results and for every agent
to observe all confirmed accepted IDs, up to the overall timeout.

## Reports

Open `report.html` offline. It contains SVG charts for per-process CPU and memory
(RSS), aggregate accepted Events in each publication second, and delivery progress
per agent. Every chart starts at publication (0 s), ends at measurement completion
including delivery drain, and uses the same X ticks. A dashed line marks the
configured publication end. Rate bins cover only the publication interval;
a fractional final bin divides its count by its interval length. CSV retains
raw bin counts. Resource lines stop at their last available sample.

New measurements record `publication_start_monotonic_s` by bracketing the actual
Rust publication `Instant` with Linux `CLOCK_MONOTONIC` reads. The anchor is the
bracket midpoint; `publication_clock_uncertainty_s` retains its half-width.
Python `time.monotonic()` uses the same host clock. Resource X coordinates subtract
that anchor; setup samples and samples after `elapsed_s` are omitted from plots,
not raw exports. CPU values remain averages over their original sampling intervals,
so the first plotted value can span publication start. Old measurements without
an explicit anchor show aligned resource data as unavailable; the report never
estimates publication start from the first sample or process launch.

The controller samples `/proc/PID/stat` once per second and at process completion,
without waiting for RPCs. It computes CPU changes only between samples with the
same PID and process start ticks; **100% CPU means one core**. Agent processes and
the Rust generator have separate series. Generator CPU excludes the Python
controller. Missing process samples remain null.

| File | Contents |
|---|---|
| `measurement.json` | Attempts, accepted IDs, delivery observations, errors and configuration; no credential paths or values |
| `publication-*.jsonl`, `delivery-*.jsonl` | Synchronized evidence journals without secrets |
| `resources.jsonl`, `resources.csv` | Raw per-process resource samples |
| `attempts.csv`, `accepted-eps.csv`, `delivery.csv` | Attempt, aggregate acceptance and delivery data |
| `summary.json`, `summary.md` | Numeric summary and Actions table |
| `provenance.json`, `source-snapshot/` | Repository HEAD, binary hashes and benchmark sources at launch |

Build logs link source revisions to binaries. The controller records hashes but
cannot infer which source produced a caller-supplied executable.

### Counts and latency

Publication counts combine all agents. Accepted responses within `[0, duration)`
count toward the publication rate; responses at or after the endpoint count as
accepted after publication. Aggregate rate divides the total accepted during
publication by its duration, not by agent count.

* **Capacity rejected** (`rejected`): the agent returned a capacity rejection.
* **Outcome unknown** (`unresolved`): the generator recorded a send start but no
  confirmed acceptance or capacity rejection. This does not prove server receipt.
* **Not sent** (`unsent`): the generator created an intent but recorded no send start.
* **Scheduled attempts not generated** (`not_generated`): in paced mode, scheduled
  attempts across all publishers with no intent before cutoff. Unpaced mode has no
  finite scheduled count.

`send_started_s` marks the start of frame construction/submission.
`send_completed_s` marks return from the stream send operation, not server receipt.
Publication response latency runs from send start to the client-observed response,
including local queues, transport and server work. Its median and nearest-rank p95
include accepted responses after publication ends.

**Pending** means confirmed accepted Events not yet observed by that agent.

Delivery latency runs from that same send start to the consumer's first
observation, including polling delay. Each agent's median and nearest-rank p95 use
only observed confirmed IDs; `delivery.csv` retains each sample. Delivery
completion measures the time from publication end until the agent has observed
all confirmed IDs, with a minimum of zero. No accepted Events means no completion
time. Consumers retain first-observation timestamps through final collection.

**Incomplete** means the run stopped before completing its checks. Events not yet
observed at timeout are not evidence of loss. The report shows unavailable values
when it has no measurement; JSON and CSV keep full numeric precision.

**Do not upload `private/`.** It contains test tokens, provisioning bundles, state,
configurations and raw process logs. The controller keeps it for diagnosis, stops
only its own child processes, and leaves fixture directories on disk.

The benchmark uses an independent Cargo workspace and leaves the production SDK,
CLI, runtime, protobuf definitions and root manifests unchanged.

## Manual GitHub Actions run

Select **Benchmark: Event publication and delivery**
(`.github/workflows/diagnostic-runtime-volume.yml`) and choose the published ref.
The five inputs set agent count, publication duration, per-agent rate (`max` or `0`
for no pacing), payload bytes and overall timeout. Defaults match
the local controller, including **1800 seconds** overall. CI caps that timeout at
3600 seconds and fixes the per-agent attempt limit at 100000.

GitHub lists the workflow name and form from the default branch. Until that branch
contains this version, dispatch the registered filename against the published ref:

```sh
gh workflow run diagnostic-runtime-volume.yml --repo OWNER/REPO --ref REF \
  -f agents=5 -f duration_seconds=60 -f events_per_second=0 \
  -f payload_bytes=256 -f overall_seconds=1800
```

The workflow validates inputs, checks formatting, then builds the acceptance
fixture, initializer and generator in release mode with `--locked`. Cargo caches
contain downloads and build outputs. Agents run as native Linux processes on
loopback. This workflow does not run the former Docker profiles, resource limits,
network impairments or outage/recovery scenarios.

CI allows 30 minutes for the release build and 75 minutes for provisioning and
execution, with process-group termination as a fallback and time for artifact
upload. A hard timeout may prevent final reports. CI uploads available logs and
partial files; normal generator deadlines retain incomplete measurements. The
Actions summary shows results when available. Incomplete runs exit nonzero;
missing the offered rate alone does not.

CI uploads only the listed JSON, CSV, HTML, resource, provenance and workflow log
files. It excludes `private/`, raw agent and generator logs, publication/delivery
journals and `source-snapshot/`. The local source snapshot contains only benchmark
sources listed in `provenance.json`; the published ref supplies those sources in
CI. The nested `.gitignore` excludes local `*.log` files from staging.
