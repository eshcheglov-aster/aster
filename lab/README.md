# Aster OrbStack laboratory controller

`orchestrate.py` is the reproducible host-side controller for the task-created
`aster-lab` executable. It uses only the Python standard library and invokes
Docker with argument arrays; it never invokes a command shell.

The controller is a dry run unless `--execute` is present. A dry run is a
**structural preview**, not a byte-for-byte command transcript: run IDs,
ownership labels, immutable image IDs, isolated mounts, and collision-preflight
results exist only during execution. No controller command intentionally pulls
an image. Every `docker run` includes `--pull=never`, and `build` always uses
`--pull=false` after proving that the pinned base image is local.

## Safety model

- Docker context must be exactly `orbstack`.
- Docker and the inspected runtime image must normalize to ARM64; other
  architectures fail preflight instead of being compared as equivalent runs.
- Names are fixed under `aster-lab-`; concurrent reuse fails preflight.
- Fixed CIDRs are checked for mutual overlap and against custom Docker IPAM
  configurations before creation. Docker performs the final atomic overlap
  check at creation time.
- Networks use `--internal`; no host port is published.
- Application scenarios use a read-only root filesystem, a private cgroup
  namespace, `no-new-privileges`, and `--cap-drop=ALL`.
- NAT endpoint scaffolds receive `NET_ADMIN` so the controller can replace their
  default routes. The two NAT routers are also the capture points and receive
  exactly `NET_ADMIN`, `NET_RAW`, `SETUID`, and `SETGID`: the last two permit
  the packaged tcpdump process to drop explicitly to its `tcpdump` account
  after opening the capture socket and output file. Infrastructure receives no
  added capability. All other scenarios receive no added capability.
- Every execution creates a new mode-0700 evidence directory. Existing scenario
  directories are never reused.
- The controller receipt area is never mounted into a container. Each role sees
  only its assigned mode-0700 writable directory beneath `outputs/`. Most roles
  mount `outputs/<role>/` at `/output`; each selected live node instead mounts
  only `outputs/provision/node-a` or `outputs/provision/node-b` at exactly
  `/output/node-a` or `/output/node-b`, matching the canonical path used by
  stopped provisioning and preserving the Store's Blob owner binding. Each
  selected live node additionally sees only its own owner-only bundle as the
  exact writable file `/run/secrets/node.bundle`.
  This narrow exception is required because the production loader retains one
  read/write, exclusively locked descriptor for optional exact-inode software
  erasure. The node cannot see the peer state, peer bundle, parent provisioning
  directory, another role's output, or controller receipts; relay certificate
  mounts remain read-only.
- Preflight validates image provenance labels against the current admitted
  source hashes, resolves the tag to one `sha256:` image ID, and every container
  runs that immutable ID. Post-start inspection verifies the image, limits,
  capabilities, user, network, and exact bind-mount set.
- Cleanup reads the run manifest, accepts only an exact allowlist, verifies the
  run/role/ownership labels on each live object, removes containers before
  networks, and never removes an image, volume, or evidence directory. Cleanup
  re-verifies the OrbStack daemon; a failed list/inspect is an error, never
  interpreted as "absent".
- The build preflight requires both deny-all policies, `.dockerignore` and
  `lab/Dockerfile.dockerignore`, to match the reviewed form byte-for-byte. It
  rejects symbolic links, hidden directories, and unreviewed hidden files within
  admitted `crates/` inputs, records SHA-256 for every admitted file, then copies
  those exact bytes into a new sealed context inside the evidence directory.
  Docker never rereads the live workspace for that build.

OrbStack currently reports `DOCKER_INSECURE_NO_IPTABLES_RAW`. Consequently, the
lab does not use Docker-published ports or treat Docker's bridge firewall as a
NAT/security oracle. NAT rules live explicitly inside the two router network
namespaces, and captures occur on their WAN interfaces.

## Validate the controller

These checks do not contact Docker:

```sh
python3 -m py_compile lab/orchestrate.py
python3 -m unittest discover -s lab/tests -v
```

## Build

Preview the operation's structure:

```sh
python3 lab/orchestrate.py build
```

Attempt a build whose Dockerfile `RUN` steps receive BuildKit
`--network=none`. This succeeds only if every required build layer is already
cached:

```sh
python3 lab/orchestrate.py build --execute
```

For a first clean build, explicitly authorize dependency acquisition:

```sh
python3 lab/orchestrate.py build --allow-build-network --execute
```

Connected mode uses `--network=default --no-cache --pull=false`. The pinned base
must still exist locally, while Cargo crates locked by `Cargo.lock` and Debian
packages from the task-provided snapshot source may be acquired. The sealed
input manifest, aggregate digest, full plain build stream, metadata, base-image
identity, and final image identity are retained as acquisition/build receipts.
If the fixed image tag already exists, rebuilding also requires the explicit
`--replace-image` option.

The final image contains
`/usr/share/aster-lab/runtime-package-inventory.tsv`, generated by `dpkg-query`
for the five admitted runtime utilities: `iproute2`, `iputils-ping`, `nftables`,
`procps`, and `tcpdump`. After resolving the final immutable image ID, the
controller reads that file in an offline, read-only, capability-free container,
validates the exact package set and canonical row format, and preserves it as
`runtime-package-inventory.tsv` in the build evidence directory with its SHA-256
in `events.jsonl`. This is a version receipt for the explicitly installed
runtime utilities, not a complete transitive package SBOM.

`--network=none` constrains declared Dockerfile `RUN` networking. Together with
the local pinned base, `--pull=false`, and no remote frontend, it is a materially
offline build path for this Dockerfile; it is not packet-level proof that the
Docker/BuildKit daemon emitted no traffic. Such a claim requires an independently
isolated or captured daemon egress boundary.

## Retired single-contact scenarios

The `MeshService` implementation and its exclusive lab commands are removed:
`transfer`, `route-only-event`, `blob-recovery`, `scale`, `shard-worker`,
`node-udp`, `node-rendezvous`, `node-discovery`, `node-relay`, and `provision`.
The Python `self-contained`, `two-node`, `scale`, and `resource` entrypoints
are also removed. Their historical results remain evidence for their original
implementation and revision.

Useful load/resource and impaired-link scenarios are deferred to
[issue #105](https://github.com/defenseunicorns/aster/issues/105), linked to
[issue #74](https://github.com/defenseunicorns/aster/issues/74), with resource
diagnostics coordinated in [issue #73](https://github.com/defenseunicorns/aster/issues/73).
No workloads were ported in this retirement. The default 101-MiB large-Blob
workload is retired and is explicitly outside that follow-up.

The historical virtual 3,000-bit/s, 50%-loss transfer experiment did not converge
within 120 seconds and was terminated. That negative result remains unchanged;
it is not current Iroh acceptance evidence. The retained 2026-08-21 route-only
Phase-0 result likewise describes the old deterministic in-memory carrier.
Its retained provenance is source revision
`9a8a87e11785c98fd1069cb2338c4076f4c728cb`, source-diff SHA-256
`796fac56ef87b1b16062ebfb1514bc0a15135fd72b01c51582a29dcbe2256ad8`,
and binary SHA-256
`ebb712065ce2006bdf6c112c989977b854ed51dfae445c02cc602d4d35294bad`.
That A→B→C control covered opaque custody, relay reopen, exact source identity,
and consumer acknowledgement; it did not establish live IP discovery, NAT,
or concurrent-contact behavior.

Native `mesh-*` commands, independent rendezvous/relay infrastructure, Gate H,
selected NAT/relay helpers, and reducer/component tests remain available.

## Automatic three-process LAN mesh demo

Proposal 0001's shared controller runs the complete local A→B→C demonstration
with three independent processes and stores. It is a dry run unless
`--execute` is present. Given a Linux release binary, one command provisions
the nodes, publishes a random command Event, discovers A↔B without peer
locators, stops A, restarts route-only B, discovers B↔C, delivers and
application-acknowledges the exact source item, reconnects A to check duplicate
suppression, writes the receipt, and removes only its temporary networks and
containers:

```sh
python3 lab/ip_mesh_experiment.py \
  --arm native --scenario primary \
  --binary target-linux/release/aster-lab \
  --root lab/runs/manual-native-ip-mesh \
  --trials 1 --execute
```

The final human-checkable result is
`lab/runs/manual-native-ip-mesh/trial-01/result.json`. A passing receipt must
show `passed=true`, the same ItemID and EnvelopeID through custody and delivery,
application acknowledgement, no post-ack redelivery, duplicate suppression,
internal-only networks, and `a_c_contact_count=0`.

This is the retained native LAN oracle governed by
[Decision 0022](../docs/decisions/0022-ip-mesh-experiment-no-selection.md).
It deliberately does not claim manual peering, NAT traversal, connectivity
relay fallback, or fair large-peer scheduling. The historical Iroh and
rust-libp2p comparison binaries and exact commands are bound to experiment
checkpoint `117770259680d89e5fbd1ff1f6c3df9f3e646e6c`; they are not continuing
production dependencies.

## Five-unit NAT topology

Fixed networks and addresses:

| Segment | Network | Addresses |
|---|---|---|
| LAN A | `aster-lab-lan-a`, `10.250.1.0/24` | node A `.10`, NAT A `.1` |
| WAN | `aster-lab-wan`, `10.250.0.0/24` | NAT A `.11`, NAT B `.12`, infra `.20` |
| LAN B | `aster-lab-lan-b`, `10.250.2.0/24` | node B `.10`, NAT B `.1` |

### Selected Iroh NAT acceptance

`selected-iroh-nat-run` is the fail-closed selected-runtime acceptance path for
this topology. A preview is mutation-free; execution builds the dedicated
locked selected image, runs its Linux helper tests, then executes the direct
and controlled-relay cells into a fresh external evidence root:

```sh
python3 lab/orchestrate.py selected-iroh-nat-run --profile all

python3 lab/orchestrate.py selected-iroh-nat-run --profile all --execute \
  --allow-build-network \
  --evidence-root /private/tmp/aster-selected-iroh-nat
```

Each live node has a fixed 30-second run budget established before endpoint
setup and READY. The selected acceptance command requests an immediate contact
and, when startup leaves enough budget, one nominal repeat at 15.001 seconds;
the next nominal interval falls after the terminal deadline.
Acceptance remains semantic rather than count-based: each endpoint must record
one exact role-bound Event transfer followed by an exact zero-difference
contact, empty stderr, zero contact errors, the expected Direct or Relay path,
and a complete terminal inventory. The remaining quiet portion of the run
budget also lets both WAN capture streams retire their final packet batches
before bounded capture shutdown. A slow or failed contact still fails the
existing deadline, stderr, transfer, no-op, counter, or capture checks; it is
never reclassified as planned-shutdown success.

Both WAN captures request tcpdump `--immediate-mode` delivery and
packet-buffered pcap writes. Finalization requires exactly one terminal
captured, received-by-filter, and dropped counter per capture, captured equal to
received, zero drops, and the parsed pcap packet count equal to captured. Exact
nft-to-pcap equality remains mandatory; no capture-tail discount is permitted.

The direct cell's lower-carrier-ID node is the runtime-selected contact
initiator. Stateful nftables therefore has complementary first-flow evidence:
the initiator router must record positive SNAT and exact-zero DNAT, while the
responder router must record positive DNAT and exact-zero SNAT. Both routers
must independently record positive forward-in and forward-out counters exactly
equal to their parsed WAN packet directions. The controller derives the active
NAT hook from the exact homogeneous `CONTACT direction` receipts instead of
requiring both conntrack creation hooks to fire on reply traffic.

This is bounded one-host Linux-network-namespace evidence with operator-known
static external mappings. It does not prove endpoint discovery or hole
punching, physical or public-internet NAT behavior, a temporal direct-first
fallback, an independently operated relay, mixed implementations, BTLE, or
target-device resource limits. The restrictive cell separately proves use of
the explicitly pinned local HTTPS relay while direct UDP is blocked; it is not
relabeled as physical relay deployment.

Create a deterministic full-cone mapping scaffold:

```sh
python3 lab/orchestrate.py nat-up --profile cone
python3 lab/orchestrate.py nat-up --profile cone --execute
```

Or create a relay-only restrictive scaffold and shape each router's WAN egress:

```sh
python3 lab/orchestrate.py nat-up --profile restrictive \
  --shape-bps 3000 --loss-percent 50 --seed 424242

python3 lab/orchestrate.py nat-up --profile restrictive \
  --shape-bps 3000 --loss-percent 50 --seed 424242 --execute
```

`--seed` is a requested netem seed, not an unconditional determinism claim.
The controller first attempts the seeded form and records whether the installed
`tc` accepted it. The pinned Debian `iproute2` 6.1.0 build rejects the `seed`
token; only that exact unsupported-token response permits a retry without the
token, after which `nat-runtime.json` records `netem_seed_status=unsupported`
and `netem_seed=null`. That kernel loss process is stochastic. The separately
retired seeded carrier results describe their original deterministic loss model.

`nat-up` resolves interface names by assigned address rather than assuming
`eth0`/`eth1`, installs namespace-owned nftables rules, records qdisc statistics,
starts pcap capture on both WAN interfaces, and runs the combined unprivileged
UDP-rendezvous/TCP-relay service on WAN `.20`. It intentionally leaves the five
units running and prints the evidence directory used for cleanup.

Readiness is fail-closed: infrastructure must remain running and emit
`ASTER_LAB_INFRA_READY`, and each router must have a live `tcpdump` process plus
a complete pcap global header before `nat-topology-ready` is recorded. On
cleanup, the controller sends `SIGINT` to both capture processes, waits for them
to exit, validates both pcap headers, captures terminal qdisc and nftables
counters, preserves final infrastructure/container logs, gracefully stops the
five units, and only then removes them. A host/VM crash before cleanup can still
leave an incomplete capture and is not claimed as finalized evidence.
If normal finalization fails, cleanup fails closed and retains the resources so
the evidence can be inspected or finalization retried.

Finalization is two-phase and retryable. Before signaling either capture, the
controller atomically publishes a start marker that binds the terminal qdisc,
nftables, and infrastructure-log receipts by SHA-256. The final marker also
binds each flushed pcap by path, size, and SHA-256. A retry accepts an
already-stopped capture only after validating those bound receipts; cleanup
revalidates the final marker before it can authorize resource removal.

At present this command proves only that the controlled topology was created.
It does **not** claim NAT acceptance: although the combined infrastructure is
live, a full result additionally requires live nodes using `node-rendezvous` and
`node-relay`, negative direct-path probes in restrictive mode, authenticated
application convergence, and capture assertions. Do not relabel a topology-only
run as direct traversal or relay-fallback evidence.

Remove the exact owned objects later with:

```sh
python3 lab/orchestrate.py cleanup /absolute/path/to/the/nat-run
python3 lab/orchestrate.py cleanup /absolute/path/to/the/nat-run --execute
```

The second command refuses any object whose current ownership labels differ
from that run's immutable controller manifest.

## Evidence layout

Every executed operation creates a directory named approximately:

```text
lab/runs/<timestamp>-<scenario>-<run-id>/
```

It contains:

- `controller.json`: immutable run identity and exact planned resources;
- `commands.jsonl`: ordered argument arrays, timings, return codes, and hashes
  of any standard input;
- `command-NNNN.stdout` / `.stderr`: uncombined command output;
- `events.jsonl`: append-only creation, assertion, and cleanup events;
- Docker capability and exact image-identity receipts;
- for builds, the canonical `runtime-package-inventory.tsv` receipt from the
  final immutable image;
- `scenario-request.json`, followed by parameter-specific host cross-checks;
- isolated `outputs/<role>/` trees containing only that role's scenario state,
  receipts, metrics, or capture;
- logs, initial/final qdisc data, final nftables counters, and NAT finalization
  as applicable.

Evidence directories are never deleted by cleanup. External archival/signature
of a receipt root remains a separate gate.
The provisioning output contains mode-0600 **simulation** bundles and capability
files; archive and disclose that output as protected test material even though
it is not production credential material.

## Claim boundaries

Passing these commands can support controlled reference-to-reference software
evidence. It cannot establish physical BTLE/RF behavior, battery behavior, FIPS
validation, independent-SUT interoperability, signed downgrade policy,
representative embedded hardware, universal NAT traversal, or external evidence
anchoring.
