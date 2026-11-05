# Aster path-lab

## Opt-in Event load, scale and network-fault diagnostic

`tools/aster_path_diagnostic.py` shares the delivery image, production agents,
Connect JSON client and owned-container cleanup with the smoke below. It runs
four independent two-agent workloads by default, with 2..20 agents supported:

| Profile | All WAN egress interfaces |
| --- | --- |
| baseline | No configured delay, loss, rate limit or reordering |
| impaired | 40 ms delay, 5 ms jitter, 1% loss, 100 Mbit/s |
| reorder | The impaired profile plus 10% reordering |
| outage | Baseline, then 100% loss for 10 seconds starting after 20 seconds |

Each endpoint offers durable 1-KiB Events at 10 Events/second for 60 seconds
by default. Use `--events-per-second max` for unpaced publication. All agents
publish and configure all other agents as peers, with one routed WAN segment
per agent. Consumers poll and acknowledge deliveries alongside the publishers.

The benchmark starts after initial SDK recovery. One monotonic interval bounds
new publications; already sent operations can settle during the bounded delivery
observation window. Backpressure reduces the measured rate without a one-second
lag failure or a catch-up burst. The eight-entry durable journal window, stream
rotation, original-sequence replay, authentication and acknowledgement rules remain.

The report separates attempts submitted by the generator, accepted responses
observed during the interval, later accepted responses, definite rejections and
unknown outcomes. Unknown includes queued submissions without a confirmed result
at cutoff, not just transmitted requests. Actual Events/s divides accepted-during
by the configured duration. In duration mode, structured resource-exhaustion and
operation-capacity rejections are counted and the interval continues. After the
application records a rejection, the SDK durably abandons that original sequence
and replays any later outstanding intents unchanged. Malformed, authentication,
infrastructure and transport failures remain explicit run errors, never inferred
rejections. A completed run has no throughput or delivery pass/fail threshold.
Content mismatches, agent failures, cleanup and provenance errors produce nonzero exits.

Delivery observation ends at publication end plus `--restore-deadline-seconds`,
including for outage runs. Each agent's unique deliveries and missing accepted
Events use that cutoff. The duration outage profile applies and restores loss
while ordinary workload Events continue; it does not inject separate witness
publications into the active SDK stream. Finally agents stop and reopen without
peers, with WAN cut, to check retained contents. Cleanup removes disposable
credentials and journals; telemetry artifacts are not resumable journals.

`--events-per-agent` retains the legacy count-driven correctness diagnostic,
including its one-second pacing failure and outage witnesses. Do not combine
that option with `max`; the manual Actions form uses duration mode only.

```sh
docker build --file docker/path-lab/Dockerfile.delivery \
  --tag aster-path-delivery:local .
python3 tools/aster_path_diagnostic.py --output artifacts/path-diagnostic
python3 tools/test_aster_path_diagnostic.py
```

### Workload and resource controls

```sh
# Five agents offering 10 Events/s each for 60 seconds.
python3 tools/aster_path_diagnostic.py --output artifacts/scale-5 \
  --agents 5 --duration-seconds 60 --profiles baseline
# Unpaced load, with CPU and RAM constrained per container.
python3 tools/aster_path_diagnostic.py --output artifacts/load-limited \
  --duration-seconds 60 --events-per-second max --profiles baseline \
  --cpu-limit 1 --memory-mib 1024 --restore-deadline-seconds 600 \
  --storage-max-items 50000 --storage-mib 512
```

| Option | Default | Bounds |
| --- | --- | --- |
| `--agents` | 2 | 2..20 |
| `--duration-seconds` | 60 | 1..1800; combined budgets apply |
| `--events-per-agent` | omitted | Legacy count mode, 1..10000 |
| `--payload-bytes` | 1024 | 1..4096 |
| `--events-per-second` | 10 | 1..100 per agent, or `max` |
| `--bandwidth-kbit` | omitted (profile default) | integer 0..1000000 kbit/s per WAN egress; 0 = no limit |
| `--cpu-limit` | 0 (unrestricted) | 0, or 0.1..64 cores |
| `--memory-mib` | 0 (unrestricted) | 0, or 64..16384 MiB |
| `--restore-deadline-seconds` | 120 | 1..600 |
| `--storage-max-items` | 10000 | 4161..1000000 per agent |
| `--storage-mib` | 64 | 64..4096 MiB per agent |

Bandwidth is a maximum netem rate on **each WAN egress**, shared by traffic
headed to that agent (not a per-peer or campaign-wide budget). With two agents
this limits each direction independently. Manual input `bandwidth_kbit` is
optional text so blank and zero remain distinct: blank preserves the table's
profile defaults; `0` removes even the impaired/reorder profiles' default
100-Mbit/s cap. A positive integer overrides every selected profile, including
baseline and outage restoration; outage still drops 100% of traffic while active.
The CLI accepts `--bandwidth-kbit 3` without rounding to Mbit/s. Its upper bound
matches the existing 1000-Mbit/s limit. `--rate-mbit` remains backward compatible
(1..1000, default 100, impaired/reorder only); explicit `--bandwidth-kbit` takes
precedence. Every explicit override is checked against tc JSON bytes/second
readback on every interface after replacement, and retained in receipt configuration
and qdisc evidence. Low bandwidth can exceed existing startup/delivery deadlines;
this field alone makes no low-rate usefulness or qualification claim.

Store limits are explicit startup overrides, retained through peerless restart;
production defaults are unchanged. MiB is converted to `max_payload_bytes`.
These are aggregate store allowances, not plaintext Event capacity: control and
tombstone reserves plus signed/encrypted record overhead consume space too.
The default 64 MiB is insufficient for 10,000 Events per agent in a two-agent
run. Raising a quota permits an experiment, not a promise that its workload,
rate, deadline or RAM budget will pass. The legacy evaluation agent accepts the
paired `--storage-max-items` / `--storage-max-payload-bytes` flags; the supported
customer configuration already exposes `storage.max_items/max_payload_bytes`.

An explicit legacy Event count derives its publication window from count/rate.
Duration mode is the default. Publication takes
at most 1800 seconds. The sum of publication and delivery windows across
profiles cannot exceed 2400 seconds. The controller rejects combinations whose
`agents² × (Events + 1) × (3 × payload bytes + 1024)` exceed its 256-MiB
receipt/IPC budget. For `max`, preflight estimates 100 Events/s; a runtime
telemetry guard rejects runs exceeding the smaller of 10,000 submissions per
agent and the receipt budget. That diagnostic-capacity error invalidates a run,
not a product throughput result. These harness bounds do not assert product capacities.

CPU/RAM limits apply to each agent container, including its local publication
and consumption helpers, not just the agent PID. RAM-limited containers have no
swap allowance. Docker HostConfig readback must match CPU, memory and swap
settings before publication, together with Linux cgroup-v2 kernel readback.
Unsupported cgroup layouts fail closed. The controller checks final container
exit/OOM state and cgroup OOM-kill counters; samples measure the agent PID separately. A Docker daemon that
cannot enforce the requested limits is not a qualifying resource environment.

### Manual GitHub Actions launch

Choose **Actions → Diagnostic: load, scale and network faults → Run workflow**, then
select the source branch and bounded workload/resource inputs. `.github/workflows/diagnostic-runtime-volume.yml` must exist on
the default branch before GitHub exposes the launch button. This replaces the
archived runtime-volume launch; it does not revive that implementation or run
on pushes, pull requests, or as part of `CI / required`.

The Ubuntu 24.04 job builds `Dockerfile.delivery` from the selected checkout,
using the same digest-pinned Rust base, locked Cargo dependencies and Debian
snapshot as the delivery smoke. It then runs the selected profiles,
without privileged containers or host networking. There are no free-form shell
inputs or pre-existing local image dependencies.

Inputs are validated before building, passed through environment variables and
quoted arguments, and bounded again by the controller. The Job Summary contains
Markdown tables with run completion/errors, requested inputs and per-agent counts,
publication-response latency and sampled peak RSS. Download `report.html` for
offline CPU, RAM and Events/s graphs on a common timeline. Agent, Python generator
and persistent SDK-helper processes have separate graphs. CPU uses actual elapsed
time within the same PID/start-time lifetime; 100% means one core. An independent
observer samples procfs each second even when status RPCs are slow. Missing
samples stay unavailable, not zero. RSS peaks are sampled, not absolute peaks.

Latency covers generator submission through the client-observed accepted response,
including local queueing; it is not delivery latency or server-only RPC time.
Median and nearest-rank p95 use all observed accepted responses, not a recent ring.
`benchmark.json`, `resources.csv` and `publications.csv` contain allowlisted numeric
telemetry without Event payloads or credentials. Summary and artifact upload are
always attempted; hard runner cancellation can prevent either.

For a fork that already registers this workflow filename on its default branch,
dispatch the published feature ref without merging it into default:

```sh
gh workflow run diagnostic-runtime-volume.yml --repo OWNER/aster \
  --ref feature/122-diagnostic-scale \
  -f agents=2 -f duration=3 -f payload=32 -f rate=1 -f profile=baseline \
  -f cpu=0 -f memory=0 -f deadline=30 -f storage_items=50000 -f storage_mib=512
```

The default-branch form can still show the older input-free definition; dispatch
by CLI against the feature ref for its new inputs. If the filename is not yet
registered, default-branch registration requires a separately approved change.
The canonical build verifies TLS normally. A local intercepting proxy's private
CA is not part of the pinned base image; such a host needs an explicitly trusted
build environment, not a TLS bypass or a silent local-image fallback.

Download **aster-path-diagnostic-<commit SHA>-<run attempt>** from the run's
Artifacts section (14-day retention). Its root contains `receipt.json`, per-profile
JSON and `preflight.log`, `build.log`, and `controller.log` as available. Upload
is attempted even after failures and command timeouts; a build failure has no
runtime receipt. The receipt records source/image identities and cleanup results.
The build is bounded to 30 minutes, the controller to 50 minutes plus five minutes
for termination/owned-resource cleanup, and the job to 90 minutes. The controller's
own per-profile deadlines normally expire earlier. Private ownership directories
and credentials are never uploaded. A hard kill or runner loss can prevent final
cleanup/report writes or upload; the disposable hosted runner is the final
containment boundary. No TLS bypass or alternate-image fallback is used if the
canonical build fails; inspect `build.log` instead.

This diagnostic needs access to the local rootful Linux Docker Engine and kernel
veth/netem support, but **not host root, sudo or host NET_ADMIN**. It creates veths
inside owned containers using NET_ADMIN-only setup helpers and a read-only bind
of the owned WAN container's network namespace. No host interface, route, qdisc,
firewall, SYS_ADMIN capability or privileged container is used. Unlike the short
smoke, the per-agent and WAN setup helpers and CHOWN-only provisioner remain for the bounded
run, so they can change impairments and reclaim private credentials. Agents and
namespace holders remain UID/GID 10001 with all capabilities dropped. No network
path bypasses WAN. The diagnostic source helper is bound read-only into nodes;
the production executable comes from the delivery image. All five local Python
helpers (diagnostic, benchmark reporting, numbered publisher, Connect client, and Docker controller)
are copied at campaign start and mounted read-only; every container is created
from the resolved immutable image ID, not the mutable tag.

`--help` lists bounded workload, impairment, sampling and recovery parameters.
`--profiles baseline` selects a shorter development run; the default runs all
four profiles. Duration receipts contain allowlisted counters, response timings,
resource histories, configuration and completion/error indicators. Legacy count
receipts also retain application status, qdisc readbacks and exact Event contents.
Application delivery backlog is **not an Iroh send queue**. `receipt.json` records the image
ID, source HEAD, complete tracked delta against HEAD (including staged changes),
and individual helper digests (including relevant untracked helpers). Source
and helper identities are rechecked throughout and after cleanup; completed
receipts require final campaign validation. The provisioner
wipes private credentials;
owned-resource cleanup must then succeed before ownership metadata is removed.
Failed cleanup retains its ownership locator. No credentials are included in the receipt.

The sustained publisher uses one persistent SDK owner per agent and the native
`PublishNumberedEvents` stream with a rolling eight-entry durable journal.
Receipt reception, individually paced sends, and result acknowledgements run
concurrently. Each acknowledged journal slot can accept the next original intent;
there is no full-batch receipt/application/acknowledgement barrier. The bounded
IPC source and result channels each hold at most eight entries. Every receipt is
journaled before exposure, and the controller applies it before signalling the
SDK to acknowledge it. One-off witnesses and the unary CLI remain unary.

The network window is eight unacknowledged stream frames, **not** six concurrent
unary lanes and not a reservation of unauthenticated connection slots. Duration
mode spaces fresh sends from their actual previous send, records lag and skips
missed slots. It never creates a queue of missed deadlines to catch up later.

In legacy count mode, at 10
Events/s each fresh frame is due at `start + index / 10`; the SDK retains this
absolute schedule throughout the source and its eight-second stream rotations.
Wake jitter can shorten subsequent intervals rather than accumulate as drift;
normal on-time operation sends individual frames at their deadlines, not batches.
Catch-up is bounded by the eight-entry window and unchanged one-second cutoff.
More than one second of send-admission lag fails the workload; it is
not an RPC completion deadline. Journal preparation, result application and
acknowledgement consume the same schedule budget. Consumption remains independent.
Authentication remains per stream under the existing server contract.

Failed streams retry only the original numbered intent within the SDK's bounded
retry budget. After exhaustion, recovery records committed results but leaves
pending intents journaled for explicit recovery; it does not publish replacements
or turn a legacy pacing failure into a pass. Closing a workload cancels its helper
and retains uncertain journal entries. Legacy telemetry includes maximum `schedule-lag`
and the final 128 payload-free SDK boundary timestamps (journaled, send, receipt,
saved, acknowledged, and stream opening). Their clock starts at schedule creation.
Receipt wait includes transport and server work; saved-to-ack includes application
IPC, acknowledgement RPC and durable removal. Neither is server-only execution.
Original-sequence replays retain their identity and do not advance the fresh
schedule. Replay waits still consume schedule budget: a pacing failure alone is
not an Aster capacity measurement.

The controller drains helper stdout concurrently with bounded IPC writes, with
at most eight queued responses plus one bounded response being read. Rust stdout
writes run off the async reactor. A large receipt cannot deadlock a caller still
filling the input window; IPC deadlines and terminate/kill cleanup remain active.

Connect JSON calls have a 30-second timeout; the persistent numbered helper uses
`asterctl --timeout 10` with a 35-second IPC bound per command. Duration-stream
observation instead ends at publication end plus the configured drain, retaining
unresolved results as unknown without a new publication or late recovery attempt. The peerless query
has a separate 180-second deadline per node, and each profile has an overall
publication + restoration + 420-second deadline. These are diagnostic bounds,
not changed application capacities.

A compatible locally assembled image can be selected with `--image` and labelled
with `--build-kind local-debug` or `--build-kind local-release`. Keep its build
log, Dockerfile, binary hashes and package versions alongside the receipt;
these runs are not the canonical digest-pinned release image. In particular,
debug-build throughput is not interchangeable with release-build throughput.

These are one-host diagnostics, not target-hardware thresholds, physical-link
qualification, deterministic packet-loss sequences, or new requirements credit.
The opt-in workload does not run as part of `mise run check`; its controller
regressions do. The original one-Event smoke behavior below is unchanged.

The path-lab is a bounded Linux-only network-emulation scaffold for the
Linux/Event customer-readiness profile. It uses Containerlab only for topology
orchestration and Linux `netem` for packet-path impairment. Product nodes and
additional `nftables`, address, interface, relay, and process lifecycle actions
are intentionally deferred to later focused increments.

This initial smoke proves only that:

- one exact scenario is parsed into non-shell argument vectors;
- the three-node linked topology deploys;
- delay, jitter, loss, and rate are applied to the selected interface;
- Containerlab JSON read-back matches the configured values; and
- the topology is destroyed before a passing receipt is emitted.

It is not Aster delivery evidence, a retained customer receipt, a NAT or relay
result, a resource-bound result, or physical-network qualification.
The scenario seed identifies this manifest and is retained for later actions;
Containerlab `0.79.0` does not expose a packet-loss RNG seed through its netem
command, so this smoke does not claim a deterministic packet-loss sequence.

## Public tool boundary

- Containerlab `0.79.0`, BSD-3-Clause, from
  <https://github.com/srl-labs/containerlab/releases/tag/v0.79.0>.
- Linux amd64 tarball SHA-256:
  `f90d36d58bb6c4afd3b3a4dca006b81594c6d16f7a04be0184b03f44291085a2`.
- The generic node image reuses the repository's existing digest-pinned Rust
  base without adding another package dependency.

## Validate without privileged execution

```sh
python3 tools/aster_path_lab.py \
  docker/path-lab/scenarios/netem-readback-smoke.json
```

Validation is platform-independent and prints a canonical command plan. It does
not execute Containerlab.

## Execute on Linux

The execution host must provide Docker, Linux `netem`, root privileges, and the
exact Containerlab release above.

```sh
docker build --pull=false --network=none --file docker/path-lab/Dockerfile \
  --tag aster-path-lab:local .
python3 tools/aster_path_lab.py \
  docker/path-lab/scenarios/netem-readback-smoke.json \
  --execute \
  --containerlab /usr/local/bin/containerlab
```

The command prints canonical JSON only after read-back and cleanup succeed.
Failures are sanitized and return status 2.

## Real-Event delivery slice

This separate slice replaces **delivery-only** Containerlab orchestration with
fixed Docker/Linux network namespaces. The original smoke above, its topology,
and its CI lane are unchanged. No Rust or Event-helper protocol changes are made.

```
node-a eth0 (10.77.1.2/29) -- veth -- wan1 (10.77.1.1/29)
                                      WAN (forwarding)
node-b eth0 (10.77.2.2/29) -- veth -- wan2 (10.77.2.1/29)
```

All three holders use Docker `--network none`. Two veth pairs are created directly
in their network namespaces; neither end is placed in the host network namespace.
There are no Docker bridges or bridge gateways in this path, so Docker's internal-
bridge forwarding policy is not bypassed or weakened. Endpoints install the other
segment and default routes through WAN's `.1`, with exact gateway/source/device
`ip route get` read-back. WAN has no external interface or default route.
There is no common endpoint management network, host networking,
port publication, external relay, or Internet path. Real `aster-agent` mesh
sockets bind to the endpoint `.2:4433` addresses; the existing Event helper uses
the local `127.0.0.1:8181` API inside each endpoint.

### Privilege and ownership boundary

- Every container uses explicit `--cap-drop ALL`, numeric UID/GID, and
  `--security-opt no-new-privileges`; Docker log storage is disabled.
- Three namespace holders run as `10001:10001`, with a 600-second lifetime and
  no added capabilities. Both agents run under the same nonroot capability-free
  identity. The live oracle reads `/proc/1/status` on all three holders and the
  actual `aster-agent` PID's status on each endpoint; all five capability sets
  must be zero and `NoNewPrivs` must be one.
- The networkless, transient provisioner uses `0:0` plus **CHOWN only**. It creates
  owner-only reference credentials and hands each private mount root and state
  subtree to UID 10001. Only the provisioner sees both endpoint directories;
  it exits and is removed before application operations.
- Three transient route/netem helpers use `0:0` plus **NET_ADMIN only**, sharing
  only the target holder's network namespace. No long-lived container retains
  NET_ADMIN, CHOWN, or other capabilities. Helpers have bounded commands, an
  attached start deadline, explicit exit-code checks, removal, and absence checks.
- The already-root Linux controller runs exactly two bounded host `ip link add`
  commands (five seconds each), with both `netns` targets explicit in each command.
  Target namespace files are pinned by open descriptors after exact owned CID,
  random run label, running state, `none` network mode, nsfs type, and distinct
  non-host inode checks. Docker metadata is rechecked before use. Descriptor paths,
  not reusable container PIDs or names, target link creation; descriptors close on
  success and failure before container cleanup. This requires host NET_ADMIN and
  access to Docker's namespace files under the existing root-controller boundary.
  It adds no SYS_ADMIN, host PID namespace, privileged container, namespace mount,
  host route, host forwarding sysctl, or firewall change. Unsupported namespace
  layout/nsfs or denied link creation fails closed; there is no privilege fallback.
- Each run owns a private `0700` directory. Docker creates `0600` cidfiles under
  an explicit `077` child umask. Only bounded, regular, non-symlink, single-link,
  owner-matching files containing full 64-lowercase-hex IDs authorize operations.
  A partial create's valid cidfile is recovered even when the CLI fails.
  Historical network IDs remain cleanup-only state; this path creates no Docker
  network. Per-run labels permit
  residue detection, **not** name-authorized deletion. Existing cidfiles are
  refused before contacting Docker; no global prune or name-based removal exists.

### Oracle and limits

Both WAN egress interfaces are resolved by their assigned IPs, never interface
order. Each receives `tc netem limit 1000 delay 40ms 5ms loss 1% rate 100mbit`.
Strict `tc qdisc show` read-back must match the ordered configured fields before
publication. A pass additionally requires node B to observe the
exact Event ID, logical key, and payload published by node A.

The receipt distinguishes **configured state read-back** from measured packet
behavior. It records the one-host container limitation and does not claim recovery,
actual packet-loss occurrence, measured latency, resource qualification, physical
readiness, NAT, relay behavior, or the full P1 profile. The fixed seed `104729`
identifies this scenario; it does not seed the kernel's packet selection.
No requirement evidence status or retained-receipt baseline moves.

Scenario input must be a regular non-symlink file and is capped at 16 KiB.
Scenario and command read-back JSON allow at most 64 nested arrays/objects,
counting the root container as one. A non-recursive scan enforces this before
JSON decoding, independent of the Python version's decoder recursion threshold;
brackets inside strings (including escaped quotes/backslashes) do not count.
Over-depth input fails with a sanitized nesting-bound error. Existing UTF-8,
syntax, duplicate-field, and nonfinite-constant rejection remains in force.
Command output (stdout plus stderr) is capped at 2 MiB,
peer input at 200 bytes, PID input at 16 bytes, and each process-status read at
8 KiB. Provisioning accepts only two generated credential files, each at most
64 KiB, and stops directory inventory on a third entry. Commands have explicit
deadlines (at most 90 seconds plus a five-second failure-reap bound); readiness
has at most 40 two-second attempts per endpoint. Endpoint/network helpers also bound
individual `ip`/`tc` calls to five seconds. This is a smoke, not a general scenario
scheduler or a resource benchmark.

Cleanup attempts every owned container and any previously captured network ID independently,
checks exact-ID absence after each removal, and checks run-label residue. Removing
all holders/helpers releases the namespaces, veth pairs, and qdiscs; there is no
separate privileged netem reset container. Only after these attempts does it
remove and check absence of the credential directory **if absence is confirmed**.
Any removal/read-back
failure prevents a pass. A create whose returned ID/cidfile cannot be validated
is **not** deleted by a guessed name; labelled residue is reported as a failure.
Errors expose fixed stage/code/cleanup tokens, not daemon output or credentials.

Private recovery state lives at `/run/lock/aster-path-delivery/recovery` (`0700`),
with a `0600` ownership manifest and original cidfiles/data. Manifest replacement
uses an exclusive unique temporary, file fsync, atomic replacement, and directory
fsync. An interrupted temporary does not block the next ownership checkpoint.
Persistence failures cannot skip owned-container cleanup and retain the fixed
recovery locator instead of exposing raw filesystem errors. A Docker create or
veth setup timeout is not proof that creation stopped: the manifest stays
ambiguous even after an immediately empty daemon listing. Daemon outages or
unconfirmed absence also retain the directory, and a new run refuses to overwrite it.

There is no automatic recovery/delete command. An operator must resolve any
in-flight creation, validate retained private CID ownership and run-label residue,
and verify absence of every owned resource before retiring the original data.
Never delete by guessed names or remove the recovery directory to bypass this gate.
`/run` is volatile: this supports investigation after controller interruption or
daemon failure, **not host reboot or power-loss recovery**. A killed controller
may print no locator; the fixed path above and the next run's `recovery-pending`
diagnostic identify the retained state.

### Validate and execute

```sh
python3 tools/test_aster_path_delivery.py
mise run path-delivery-plan
```

Execution requires a rootful, non-user-remapped **local Linux Docker Engine** at
`unix:///var/run/docker.sock`, root controller privileges, host `iproute2`, Linux
nsfs `NS_GET_NSTYPE`, and kernel veth/netem support.
Remote contexts, rootless Docker, and macOS execution are rejected. The fixed
subnets exist only in the fresh isolated namespaces, not host Docker networks.
A private advisory lock serializes this fixed scenario. Existing recovery state
blocks another run rather than touching unrelated resources.

```sh
docker build --file docker/path-lab/Dockerfile.delivery \
  --tag aster-path-delivery:local .
sudo python3 tools/aster_path_delivery.py \
  docker/path-lab/scenarios/event-delivery-netem.json \
  --execute --docker /usr/bin/docker
```

The delivery build uses the sibling `Dockerfile.delivery.dockerignore`, not an
expanded root `.dockerignore`. Its deny-all allowlist admits only the local
`COPY` inputs (the Rust/proto/vendor trees, manifests, notices, Debian sources,
two controller modules, and four named delivery helpers) plus their parent
directories. Re-including a parent alone also re-includes descendants under
Docker's matching rules: `lab/**`, `tools/**`, `docker/**`, and
`docker/path-lab/**` therefore re-exclude descendants immediately after each
parent entry, before the exact required files are re-included. The complete
`crates`, `proto`, and `third-party` trees intentionally remain admitted; this
is not a credential filter within those required trees. There is no wildcard
re-inclusion of other tools, scenarios, or `delivery-*.py` files. The root and
`lab/Dockerfile.dockerignore` retain the exact reviewed lab contract. Docker
still sends the selected Dockerfile and ignore file as build metadata even
though they are not admitted as copyable context inputs.

The delivery CI lane runs controller contracts and the plan before building and
executing the real image. Unit tests use an explicit fake daemon because they run
without Linux/Docker: **they do not prove Docker or network execution**. A live
Linux run is still required to validate Docker capability application, runtime
package formatting, nsfs pinning, cross-namespace veth creation, forwarding, and
real Event delivery. No such Linux execution is implied by the Python regressions.

### Tool provenance for this slice

The implementation uses only Clean Team repository code and standard tooling:
Docker Engine/CLI ([Moby](https://github.com/moby/moby)), Linux network namespaces
and netem, and Debian `iproute2`/Python. No new package resolver or topology
framework is introduced. The image retains the repository's exact Rust base
SHA-256 and the existing Debian bookworm snapshot `20260803T000000Z` from
[`lab/debian.sources`](../../lab/debian.sources). Exact installed iproute2 and
Python versions are written to
`/usr/share/licenses/aster/runtime-package-inventory.tsv` during image build.
Docker Engine and kernel versions are printed by the delivery CI job; they are
host tooling, not falsely presented as version-pinned product dependencies.
No live image package or host version is asserted by a plan-only run.

Public Docker build-context documentation checked on 2026-09-10:
[Docker Docs: filename and location](https://docs.docker.com/build/concepts/context/#filename-and-location)
and [matching](https://docs.docker.com/build/concepts/context/#matching).
These document the sibling `<Dockerfile>.dockerignore` naming rule, precedence
over the root policy, context-root-relative patterns, and automatic transmission
of excluded build metadata. The public documentation was retrieved directly from
Docker Docs (the older `/build/building/context/` URL redirects to this page);
no upstream source code or new dependency was imported into the repository.
Public Moby [patternmatcher v0.6.0](https://github.com/moby/patternmatcher/blob/v0.6.0/patternmatcher.go)
and [ignorefile normalization](https://github.com/moby/patternmatcher/blob/v0.6.0/ignorefile/ignorefile.go)
were also inspected to check parent-match propagation and trailing-slash
normalization. Source inspection is not executed matching evidence. The focused
regression checks the exact ordered policy and an independent inventory of all
local `COPY` sources; it does not subtract parent entries to infer exclusions,
emulate Docker matching, or claim an executed image build.

An optional credential-free context probe exercises Docker itself:

```sh
python3 tools/probe_delivery_docker_context.py --execute
```

It reads only the delivery ignore policy from the repository and generates all
other inputs in a temporary context: required-file sentinels, nested sentinels
in each full tree, and unrelated/hidden sentinels under the restricted parents.
A conflicting root deny-all policy checks sibling-policy precedence. A synthetic
`FROM scratch` / `COPY . /` build exports locally, without a base-image pull,
container execution, or repository context copy. The complete exported path set
(including directories) and required sentinel contents must match exactly;
build metadata and unrelated sentinels must not be copyable. The probe uses an
empty temporary Docker config and the fixed local Unix socket, not user contexts
or credentials. It requires Docker with BuildKit local-export support and may
leave synthetic build cache; it does not prune shared daemon state.

Without `--execute`, a Docker CLI, or an accessible local Engine it prints
`NOT RUN` and exits 77, never a pass. Build/export failure exits 1. Docker was
unavailable for this local revision, so the real context probe and delivery
image build remain **not run**; Python CLI/text-contract tests are not substitutes.
Even a probe pass establishes only synthetic context behavior, not compilation,
capabilities, network behavior, or real Event delivery.

Public interface references checked for the veth revision (2026-09-10):
[ip-link(8)](https://man7.org/linux/man-pages/man8/ip-link.8.html),
[veth(4)](https://man7.org/linux/man-pages/man4/veth.4.html), and
[NS_GET_NSTYPE(2const)](https://man7.org/linux/man-pages/man2/NS_GET_NSTYPE.2const.html).
The Linux man-pages references identify version 6.19; these are interface
references, not a claim about the execution host version. Host iproute2 and Linux
remain FOSS lab tooling (GPL-2.0 family), not newly linked product dependencies.
