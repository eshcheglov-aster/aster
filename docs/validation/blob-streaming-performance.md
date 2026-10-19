# Blob streaming performance evidence

This file records development evidence for semantic v9/profile 5. It is not
device qualification and does not replace the three-CM4 acceptance run.

The subsequent [local throughput investigation](blob-local-throughput.md)
records release-profile and flow-control tuning, recovery fixes, and a final
six-run disk-backed loopback series at 137.050–279.252 MB/s, with its hardware,
workload, compatibility and validation boundaries.

## 2026-10-18 completed-pack direct-stream loopback

A focused optimized production-driver run now transfers the immutable
encrypted pack directly from its stored wire offset. Attempt control remains
mission protected; data is explicitly typed and retains authenticated QUIC,
segment AEAD verification, publisher-signed open/final commitments, and
durable-checkpoint enforcement. The receiver appends the verified original
encoding without decrypt/re-encode, and compacts its receive buffer in batches.

| Payload | Contact elapsed | Contact rate | Verified read | Total elapsed |
| ---: | ---: | ---: | ---: | ---: |
| 32 MiB | 1.731 s | 18.5 MiB/s | 0.468 s | 2.200 s |
| 128 MiB, direct-pack baseline | 3.750 s | 34.1 MiB/s | 1.991 s | 5.741 s |
| 128 MiB, shared authenticated ciphertext checkpoint | 3.556 s | 36.0 MiB/s | 1.996 s | 5.552 s |
| 128 MiB, zero-copy direct-data decode | 3.530 s | 36.3 MiB/s | 1.906 s | 5.437 s |
| 128 MiB, bounded parallel segment authentication | 2.532 s | 50.6 MiB/s | 1.940 s | 4.473 s |
| 128 MiB, parallel AEAD and ciphertext leaf hashing | 2.395 s | 53.4 MiB/s | 2.032 s | 4.428 s |
| 256 MiB, 4-MiB batch, first/warm | 3.781 / 3.621 s | 67.7 / 70.7 MiB/s | 4.028 / 4.009 s | 7.810 / 7.631 s |
| 256 MiB, 7-MiB batch, first/warm | 3.346 / 3.356 s | 76.5 / 76.3 MiB/s | 4.043 / 3.996 s | 7.389 / 7.353 s |

The same 32-MiB path before direct data and batched compaction took 2.509 s in
contact and 2.977 s total, so contact time fell by approximately 31%. A 16-MiB
optimized run before the direct-data change took 2.099 s total (about 7.6
MiB/s). All measured runs completed byte-for-byte verification. A 64-MiB
attempt reached the development fixture Store's default encrypted-payload cap;
that was an admission limit rather than a transport failure.

This remains workstation loopback development evidence, not physical-device
qualification. At 18.5 MiB/s the production path is still far below the
previous 363.4-MiB/s raw Iroh ceiling, so it is not yet valid to claim that the
transport is the only bottleneck. Resume tests separately prove that a
half-complete durable pack sends only its missing suffix and a fully durable
pack settles with zero data bytes.

The larger fixture uses explicit 1-GiB Store/depot limits so the measurement is
not capped by the conservative 64-MiB default. All 37 receiver pack commits in
the optimized 128-MiB run measured below 1 ms, ruling out durable checkpoint
latency as the workstation bottleneck. Reusing the decryptor's authenticated
post-segment ciphertext checkpoint in the pack writer removed a redundant full
ciphertext SHA-256 pass and reduced contact time by 5.2%. Comparing the 32-MiB
and 128-MiB measurements indicates substantial fixed contact/authentication
cost. Authenticating the independently sealed segments concurrently within a
bounded durability batch reduced the immediately preceding 128-MiB
contact time by 28.3% and raised measured payload rate from 36.3 to 50.6 MiB/s.
Moving each ciphertext identity-leaf hash into the same worker as its AEAD
verification reduced contact time by a further 5.4% to 2.395 s. Ordered
metadata validation, Merkle-frontier advancement, pack append, and durable
commit remain serialized; accumulator state is advanced only after the entire
AEAD batch succeeds. A tampered middle segment is therefore failure-atomic and
the same decryptor can retry the valid batch.
Direct-data decoding now retains the transport-owned allocation through the
state machine and persistence batch, removing another payload-sized allocation
and copy per extent. Its workstation elapsed-time improvement was small (0.7%
against the immediately preceding run), but it reduces bounded memory traffic
that is more consequential on CM4-class devices.

The current production path is still well below the 363.4-MiB/s raw Iroh
loopback ceiling. Plaintext content-identity hashing and pack writes remain in
the ordered receiver path. An experiment that also passed a provider-minted
plaintext checkpoint to persistence was rejected: its 2.479-s contact time was
3.5% slower than the simpler ciphertext-prehash variant. Physical CM4
measurements are required before choosing the next optimization or making a
transport-limited claim.

The 256-MiB warm run shows that the path does not decay with object size. A
7-MiB checkpoint threshold inside the existing 8-MiB receive window retains
one complete 1-MiB extent beyond the batch, satisfying the checked anti-deadlock
invariant. It reduced receiver commits from 73 to 43 and improved the two
contact samples to 3.346/3.356 s while every measured commit remained below
1 ms. The resulting simple workstation-only projections are about 10.5 seconds
for 800 MiB and 13.4 seconds for 1 GiB. The post-promotion verified read shown
in the table is test-only and is not part of contact delivery latency.

## 2026-10-18 bidirectional application-RPC loopback

The profile-5 application boundary now uses a bidirectional `PublishBlob`
grammar: metadata is followed by a Store-authoritative accepted offset,
offset-bearing 64-KiB data frames, monotonic durable checkpoints, an explicit
finish frame, and a terminal publication receipt. The agent feeds these frames
directly into the single-pass node stream; `asterctl` seeks an already-open
regular file to the accepted durable offset before sending payload bytes.

A release-only real-node benchmark exercised the complete local path (HTTP/2
gRPC client, agent grammar and backpressure, application actor, encryption,
append-only pack, durable checkpoints, promotion, and completion response):

| Payload | Elapsed | Rate | Durable checkpoint responses |
| ---: | ---: | ---: | ---: |
| 64 MiB | 1.632833 s | 39.20 MiB/s | 6 |

This is approximately 25.3 times the earlier 1.55-MiB/s CM4 application
publish baseline. It is workstation loopback evidence, not a CM4, radio,
Jetson, replication, or transport-limited qualification result. It does show
that the new application streaming protocol does not reintroduce the old
whole-file staging or per-frame transaction bottleneck.

The same run forced an interruption after sending 16 MiB plus a partial 64-KiB
tail. The 250-ms checkpoint cadence had durably committed 11 MiB. Reopening the
same operation returned exactly that Store-authoritative offset, replayed
5,308,416 bytes, and completed a 20-MiB publication. This caught and fixed an
actor-session lifecycle defect where a dropped publish handle had previously
left accepted-but-nondurable state active.

Reproduction command:

```text
cargo test --release --locked -p aster-agent --all-features real_node_blob_bidi_stream_benchmark -- --ignored --nocapture
```

## 2026-10-16 local loopback ceilings

The merged semantic-v8/profile-4 selected-stack benchmark transferred 64 MiB
at approximately 0.475 MiB/s, reaching receiver readiness in 134.725 seconds.
Linear extrapolation is about 28 minutes for 800 MiB and 36 minutes for 1 GiB.
That result rejects profile 4 for the requested large-object operating range.

Two optimized measurement-only profile-5 ceiling tests were then run:

| Measurement | Bytes | Elapsed | Rate |
| --- | ---: | ---: | ---: |
| Canonical StreamData encode plus decode, 1-MiB bounded extents | 1,073,741,824 | 1.145 s | 894.3 MiB/s |
| Direct loopback Iroh long-lived data stream with concurrent reverse 8-MiB checkpoints | 1,073,741,824 | 2.818 s | 363.4 MiB/s |

The Iroh test sent 1,024 bounded 1-MiB extents and observed the final cumulative
checkpoint on the reverse stream. Resident transfer buffers were independent of
the 1-GiB total. The transport result is roughly 75 times the corrected
profile-4 payload rate and puts the loopback transport-only projection near 2.2
seconds for 800 MiB and 2.8 seconds for 1 GiB.

These are ceilings, not end-to-end claims. They exclude source authentication,
Blob encryption/decryption, carrier verification, lifecycle checks, durable
files/redb checkpoint batches, application promotion, lossy links, and CM4
hardware. The production driver must be measured with those costs before an
operational deadline is claimed.

Reproduction commands:

```text
cargo test --offline --locked --release -p aster-node stream_codec_ceiling_processes_one_gib_in_bounded_extents --lib -- --ignored --nocapture
cargo test --offline --locked --release -p aster-iroh concurrent_stream_ceiling_transfers_one_gib_with_reverse_checkpoints -- --ignored --nocapture
```

## 2026-10-17 production-driver loopback

The semantic-v9/profile-5 production path was measured with source metadata,
mission/profile negotiation, receiver-authored pre-open planning, whole-carrier
verification, 4-MiB durable checkpoint batches, redb/file persistence,
promotion, result acknowledgement, and authenticated Iroh transport enabled.
Fixture publication is outside the reported contact elapsed time.

| Payload | Contact elapsed | Payload rate | Linear 800-MiB projection | Linear 1-GiB projection |
| ---: | ---: | ---: | ---: | ---: |
| 16 MiB | 2.167 s | 7.38 MiB/s | 108 s | 139 s |
| 64 MiB | 5.301 s | 12.07 MiB/s | 66 s | 85 s |
| 256 MiB | 23.342 s | 10.97 MiB/s | 73 s | 93 s |

The first 256-MiB run failed before carrier I/O because three metadata/load
boundaries still applied profile 4's fixed 64-MiB/1,024-chunk ceiling after
profile-5 projection admission had correctly used configured depot limits. The
same focused run passed after all three boundaries were routed through the
authenticated contact mode and configured profile-5 limits. This is retained
as a size-dependent regression finding, not discarded as benchmark noise.

An 8-MiB checkpoint-batch experiment was rejected. Carrier-boundary alignment
can make an 8-MiB absolute receive window slightly smaller than an 8-MiB batch,
so neither endpoint reaches the transition that grants more credit. The driver
therefore retained 4-MiB batches at this stage and added a compile-time
invariant requiring room for a maximum extent beyond the batch threshold. A
later measured optimization above selects 7 MiB while preserving that full
extent of headroom. The original experiment also exposed that
the inbound wrapper still used the legacy 30-second total deadline; inbound and
outbound Blob contacts now select the same bounded Blob-aware deadline. A final
256-MiB rerun passed in 23.514 seconds after both corrections.

These results demonstrate the production driver's local feasibility and are
roughly 19–25 times faster than the measured profile-4 baseline. They do not
qualify UAS radio behavior or Raspberry Pi CM4/Jetson performance. The required
three-CM4 run remains the device acceptance authority.

The deterministic test defaults to 16 MiB. Development measurements can select
a bounded 1–256 MiB payload through `ASTER_TEST_BLOB_STREAM_MIB`; the cap avoids
turning an accidental environment value into an unbounded local allocation.
The production receiver now retains bounded completed-contact metrics for the
selected transport, attempt count, authenticated received bytes, greatest
absolute receive limit and durable checkpoint, maximum checkpoint commit
latency, and writer-commit count. Reopen is not counted as cross-transport
failover while Iroh is the only production adapter. These counters make the
same quantities observable during the eventual three-CM4 procedure without
placing transport details in the public Blob application API.

A post-instrumentation 256-MiB release rerun completed in 23.721 seconds
(10.79 MiB/s), within one percent of the preceding 23.514-second run. The
bounded per-checkpoint observations therefore showed no material loopback
throughput regression in this fixture.

```text
ASTER_TEST_BLOB_STREAM_MIB=256 cargo test --release --locked -p aster-node live_blob_stream_v9_completes_retained_sixteen_mib_shape_in_one_contact --lib -- --nocapture
```

## 2026-10-17 two-CM4 development validation

This is local development evidence, not the required three-device qualification
receipt. The existing protected mission on `rpi4-2` published to `rpi4-1` over
their ZeroTier addresses. Both devices are Raspberry Pi CM4 Rev 1.1 systems
running aarch64 Debian 13 and kernel 6.18.39. Their isolated validation depots
were configured for 3 GiB, 65,536 chunks, and 16 variants.

The first 800-MiB attempt exposed two application-protocol limits outside the
profile-5 carrier driver: Blob RPCs inherited the ordinary 30-second total
deadline, and upload metadata still used the legacy 64-MiB profile-4 ceiling.
Focused regressions now give Blob RPC streams a bounded 30-minute total deadline
and derive upload admission from the running node's configured depot byte and
selected-profile chunk capacity.

The corrected publisher admitted and durably committed a fresh 800-MiB Blob:

| Leg | Device | Bytes | Elapsed | Rate | Sampled agent RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| local RPC publish and durable commit | `rpi4-2` | 838,860,800 | 515 s | 1.55 MiB/s | at most 49,940 KiB |
| authenticated receiver RPC read and atomic output publication | `rpi4-1` | 838,860,800 | 433 s | 1.85 MiB/s | at most 46,476 KiB |

The initial receiver read used 64-KiB application pages and progressed at only
about 10 MiB/min while replication was active. The selected live read boundary
now returns a bounded 1-MiB authenticated window, spanning at most 17 canonical
chunks when unaligned, and rechecks authorization between windows. Upload frames
remain 64 KiB. The final uncontended read was roughly ten times faster than the
initial observation and retained bounded process memory.

The source and receiver output both had SHA-256
`0b369a7ba0bd446b5d687657a9faadc5702abc387a88fdd26b798fcc80d93420`.
The committed Blob ID was
`EVy5o+y8B30+1D0XP90kfhbVBaWkKNS9vjpcToEjfRM=` and operation key was
`cm4-v9-800m-a61d22d5`. Exact receiver reconstruction proves inter-node
replication completed, but this run did not retain a precise convergence
timestamp: `rpi4-1` had intermittent overlay reachability during transfer and
the read probe was intentionally stopped while diagnosing contention. The
publish-plus-read sum is 948 seconds (15m48s), but it excludes asynchronous
peer convergence and therefore is not an end-to-end delivery latency claim.

The candidate binaries used for the final read were built from local commit
`fa5a4791cc81` and had SHA-256
`44623ac637fdc910b6fd0ae4f607bfc04a74d932c7533984da14e505e747fbf9`
(`aster-agent`) and
`f7d40acf51b8a6f211de478313bc71e4656f2b91093c09f19037d2ec0c4ee39f`
(`asterctl`). Both services remained active after validation.

The third prior CM4 was reachable and its hardware/platform preflight was
recorded, but it had no installed mission credentials. Fresh credential
provisioning was not authorized, so alternate-peer/failover, exact convergence
latency, a 1-GiB run, interruption/resume, and three-device qualification remain
open. This evidence supports feasibility and catches size-dependent application
limits; it does not establish UAS radio, Jetson, mixed-implementation, relay, or
release acceptance.
