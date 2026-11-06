# Native duration benchmark

Run unchanged Aster agents on loopback, publish Events through the existing
`AsterApplicationServiceClient::publish_numbered_events` stream, and verify each
confirmed Event's ID and complete payload on every agent. This is an observational
benchmark: failing to sustain the offered rate does not fail the run.

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

The output directory must not exist. Keep it outside the checkout. These commands
produce release measurements. Earlier debug runs are correctness evidence only. The nested crate
matches the repository's size-optimized release settings. Do not mix debug and
release measurements.

The controller calls the existing `aster playground-init` for distinct participant
identities and mission bundles. It then prepares each unchanged acceptance fixture,
installs those test credentials, and configures a loopback full mesh. It does not
implement signing or change host networking. These unprotected synthetic fixtures
are not a production credential provider.

Options:

| Option | Default | Meaning |
|---|---:|---|
| `--agents` | 2 | Total agents, 2–16 |
| `--duration-seconds` | 60 | Publication interval, 0.01–600 seconds |
| `--events-per-second` | 10 | Offered rate **per agent**; `max` or `0` removes pacing |
| `--window` | 8 | Per-agent send-through-result-ack credit bound, configurable 1–8 |
| `--overall-seconds` | 1800 | Publication start through settlement and delivery, greater than duration, at most 86400 seconds |
| `--payload-bytes` | 256 | Deterministic complete Event payload, 8–1024 bytes |
| `--max-attempts` | 100000 | Per-agent bound on generated intents and retained Event measurements, 1–100000 |

The overall clock excludes builds, provisioning and initial session/subscription
setup. Setup has a separate 120-second bound. Reaching the attempt bound before
all scheduled work produces an incomplete measurement; already accepted Events
still drain. Max mode has this same explicit bound.

The old implementation offered a TOTAL rate from agent 0: 60 seconds at 20/s
meant 1200 scheduled positions, not 1200 per agent. The corrected workload offers
10/s independently from each of five agents: 600 each, 3000 total, 50/s aggregate.
Every accepted Event must be observed on every agent, including its publisher.
Payload identities include the publisher; operation sequences remain contiguous
and local to each fresh publication session. All latency timestamps share the
Rust generator's monotonic origin; they do not subtract independent process clocks.

## Stream and durability boundaries

* Each agent publishes through one retained native HTTP/2 gRPC publication stream.
  Each agent has a persistent authenticated generated client. Bearer headers go
  on each HTTP request, including the publication stream and acknowledgement
  requests; a publication session is not transport authentication.
* Fresh fixtures must return an empty initial `BeginEventPublicationSession`
  snapshot. The generator validates session, frontier and revision, then calls
  `CompleteEventPublicationRecovery` before any mutations. It does not reconnect,
  reclaim sessions, or retry uncertain publications.
* The default application window is eight per agent. The existing generated
  client's `into_split()` allows paced sends and ordered receipt handling to run
  concurrently. Separate result-ack RPCs also run concurrently. Each frame owns
  one credit until its verified, synchronized receipt is acknowledged. Returning
  one credit immediately permits the next due frame; there is no batch barrier.
  This bounds both unreceived frames and unacknowledged results together. It is a
  benchmark admission choice, not a negotiated wire credit or pre-auth limit.
* The existing server buffers eight publication operations
  (`crates/aster-agent/src/event_service.rs::PUBLISH_EVENTS_WINDOW`). Its message
  ceiling is 1 MiB and its maximum requested RPC deadline is 900 seconds. The
  generated clients request `min(overall, 900)` seconds. The durable Store permits
  4096 outstanding results per client. None of these numbers comes from the
  pre-authentication connection limit. These are baseline API limits, not limits
  introduced by this tool. The 900-second limit applies to each RPC, including
  the retained publication stream: it can expire before the default 1800-second
  overall deadline if publication or settlement stalls. A longer overall timeout
  does not extend that stream. The generator stops without reconnecting or replaying
  uncertain work and records `incomplete` with a stage error such as
  `publication_receive` or `publication_send` in `measurement.json`. These stage
  errors do not distinguish a server deadline from other transport failures;
  `overall_timeout` means the generator's own deadline expired.
* Before sending, the generator writes and synchronizes an intent containing the
  original sequence and deterministic payload parameters. It records and
  synchronizes the accepted ID before acknowledging the publication result.
  Consumers compare all payload bytes, retain first-observation timestamps, and
  synchronize delivery records before `AcknowledgeEvent`. New journal directory
  entries are synchronized too. These are benchmark evidence journals, not a
  restart/recovery SDK; this benchmark does not qualify physical power-loss
  recovery.
* Only structured publication `ResourceExhaustion` and
  `OperationCapacityExhausted` outcomes count as capacity rejections. The
  generator records and abandons that rejected sequence, then stops with explicit
  `capacity_rejection_pipeline_stopped` partial evidence. A rejection leaves the
  Store frontier unchanged: later already-sent sequences may be gaps. This tool
  does not silently replay them or claim their outcomes. Other application,
  transport, framing, authentication, content and acknowledgement failures stop
  the measurement and retain partial statistics.

Pacing uses the original absolute deadline `start + index / rate`, with no minimum
interval after an actual send and no lag failure threshold. Slow calls can delay
later deadlines. No new send begins after the publication cutoff; an already
started send may complete later. After the interval, the generator settles its
in-flight operations and waits for **all confirmed accepted IDs on every agent**.
There is no separate short delivery cutoff. The overall timeout returns incomplete
progress, not a claim of Event loss.

## Reports

Open `report.html` without a web server or Internet access. It contains offline SVG
charts for per-process CPU, RSS, accepted Events in each publication second, and
confirmed delivery progress. Resource charts use their own sample origin and
include generator setup. Publication/delivery charts use publication start.
Resources come from `/proc/PID/stat` once per second and at process completion,
independently of RPCs. CPU deltas require the same PID and start ticks; 100% means
one core. Agent processes and the Rust generator appear separately. Missing final
process samples stay null. The Python controller is not included in generator CPU.

* `measurement.json`: publication attempts, accepted IDs, delivery observations,
  errors and configuration without credential paths or values.
* `publication-*.jsonl`, `delivery-*.jsonl`: synchronized non-secret evidence.
* `resources.jsonl`, `resources.csv`: raw per-process samples.
* `attempts.csv`, `accepted-eps.csv`, `delivery.csv`, `summary.json`, `summary.md`:
  numeric data and a short summary suitable for an Actions summary.
* `provenance.json`, `source-snapshot/`: repository HEAD, binary hashes and the
  benchmark sources present at launch. Build logs establish which sources produced
  the supplied executables; the controller cannot infer that from an arbitrary
  caller-supplied binary.

Acceptance uses the half-open interval `[0, duration)`. Accepted responses observed
later, definite capacity rejections, uncertain sends, and journaled-but-unsent
intents have separate counts. In paced mode, `not_generated` counts scheduled
positions across all publishers never instantiated before cutoff. Max mode has no finite offered count.
`send_started_s` starts immediately before frame construction/submission;
`send_completed_s` records return from the native stream's send operation, not
proof of server receipt. Response latency subtracts the former from client-observed
response time, including local queuing and network/server work. Median and
nearest-rank p95 use accepted responses, including responses after publication ends.
Per-agent delivery latency runs from the original publication send invocation to
first consumer observation, including polling delay. `delivery.csv` retains each
sample; the summary and HTML contain its median and nearest-rank p95. Partial-run
percentiles include only observed confirmed IDs, not pending Events.
Delivery completion is the last first-observation timestamp among confirmed IDs,
minus publication end, floored at zero. An empty accepted set has no completion
time. Consumers' first-observation timestamps survive final snapshot collection.

**Do not upload `private/`.** It contains synthetic tokens, provisioning bundles,
state, configurations and raw process logs. The controller retains this directory
for diagnosis, stops only its own children, and deletes no fixture directories.

## Tests

```sh
mise exec -- cargo test --locked --manifest-path tools/duration-benchmark/Cargo.toml
python3 -m unittest discover -s tools/duration-benchmark -v
```

Rust tests drive the actual generated client against a local HTTP/2 fixture for
multiple frames on one stream, per-request authentication, structured rejections
and abandonment, late acceptance, malformed outcomes, disconnect and timeout.
They also cover exact-ID convergence, delivery-before-receipt payload checking,
absolute scheduling and configuration bounds. Python tests cover CPU identity,
process disappearance, cutoff/empty-window accounting and offline JSON/CSV/SVG
agreement. Real multi-agent runs remain a separate verification step.

This directory is an independent Cargo workspace. SDK, CLI, runtime, protobuf
and root manifests remain unchanged.

## Manual GitHub Actions run

Select **Diagnostic: manual runtime-volume test**
(`.github/workflows/diagnostic-runtime-volume.yml`) and choose the published ref.
The six inputs map to the controller options above: agents, publication duration,
per-agent rate (including `max`), payload bytes, window and overall timeout.
Defaults match the local controller, including **1800 seconds** overall. CI caps
that timeout at 3600 seconds and keeps the per-agent attempt bound at 100000.
It validates inputs before compiling, tests the benchmark, and builds both the
unchanged acceptance fixture/initializer and the isolated generator in release
mode with `--locked`. Cargo caches contain only downloads and build outputs.

The workflow runs native Linux processes in a loopback full mesh. The former
Docker profiles, CPU/memory limits, bandwidth shaping, network impairments and
outage/recovery scenarios are **not implemented by this controller** and have no
form inputs. Adding any of them requires a separate scope decision; selecting this
workflow does not run or qualify those old scenarios.

CI allows 30 minutes for the release build and 75 minutes for provisioning plus
execution, with a process-group termination fallback and time for artifact upload.
A hard timeout can prevent final reports; available logs and partial files remain
eligible for upload. Normal generator deadlines retain incomplete measurements.
The Actions summary includes the generated summary when available. An incomplete
run exits nonzero; missing the offered rate alone does not.

Artifacts use an explicit file allowlist: JSON measurements/controller status and
summary, CSV tables, HTML, resource samples, binary/source-hash provenance, and
workflow build/preflight/controller logs. CI does not upload `private/`, raw agent
or generator logs, publication/delivery journals, or `source-snapshot/`. The source
snapshot contains only the benchmark source files listed in `provenance.json`,
not generated fixture data; the published Git ref supplies those sources in CI.
Local `*.log` files stay on disk but the nested `.gitignore` excludes them from
staging. Run `python3 tools/duration-benchmark/test_workflow.py -v` to verify input
mapping, shell argument boundaries, failure propagation and the upload allowlist.
