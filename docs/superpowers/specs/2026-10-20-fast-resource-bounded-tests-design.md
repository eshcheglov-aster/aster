# Fast, resource-bounded correctness test architecture

**Status:** Approved in chat and written-spec review on 2026-10-20; timing policy revised per owner review to advisory measurement and problem tagging

**Capability tracks:** engineering quality and delivery confidence

**Evidence boundary:** test architecture and current-code regression evidence only

## Intent

Aster's default correctness suite must be practical for developers to run on a
normal local workstation. A test that proves a page boundary, resumability, or
large-object behavior must exercise the relevant state transition without
allocating production-scale data merely because the production constant is
large. Physical scale, throughput, and endurance remain important, but they
belong in explicit qualification or benchmark commands with their own retained
evidence rather than in the default correctness suite.

This change preserves functional coverage while making execution time and
resource use explicit design constraints. It does not weaken production
limits, alter the wire protocol, or promote any requirement status.

Success means:

- every default correctness test completes in at most 10 seconds on its
  required supported runner after compilation;
- a warm, complete all-feature Rust workspace correctness run completes in at
  most 5 minutes with the repository's default two nextest threads;
- no existing correctness assertion or failure mode is silently removed;
- boundary tests use the smallest fixture that crosses the boundary under test;
- production constants are asserted independently from the parameterized test
  limits;
- the local and required-CI Rust suites contain the same correctness tests,
  with CI partitioning changing scheduling only;
- default test execution does not allocate production-scale blobs, page-sized
  object populations, or repeated real-process topologies unless that scale is
  itself the behavior under test; and
- physical-scale, performance, and endurance exercises remain available under
  explicit, documented qualification or benchmark commands.

The time budgets exclude dependency acquisition and cold compilation. Those
costs remain visible in CI job timings but are not properties of individual
tests. Qualification and benchmark programs are not called or presented as
default correctness tests.

## Evidence and requirements boundary

This is bounded engineering maintenance. It changes how existing behavior is
tested, not the behavior or maturity that Aster claims. In particular:

- current unit and integration assertions remain current-code regression
  evidence;
- a smaller parameterized fixture is not physical-scale evidence;
- an opt-in scale run is not requirement evidence unless its inputs, platform,
  outputs, and acceptance criteria are retained through the existing
  validation process;
- no requirement identifier, status, roadmap maturity, or acceptance record is
  changed by this work; and
- the current evaluation-only implementation boundary remains unchanged.

The before/after report must record test counts, failures, slowest durations,
cumulative test time, wall time, and the disposition of every previously slow
test. Those measurements demonstrate maintenance quality only.

## Test taxonomy

### Default correctness tests

Default tests answer whether a behavior is correct. They run in normal local
validation and every required pull-request lane. Their fixtures are derived
from the smallest value that reaches each semantic state:

- `limit` for exact-bound behavior;
- `limit + 1` for pagination, overflow, and continuation behavior;
- enough chunks to cover first, middle, last, resume, deduplication, range, and
  corruption paths for streaming behavior; and
- the smallest topology that demonstrates the routing or process boundary.

Defaults must be deterministic, isolated, and bounded in elapsed time, memory,
temporary storage, open files, processes, and sockets. Repetition is permitted
only when the repeated cases are independently scheduled tests or when one
small in-process table-driven test remains comfortably within budget.

### Production-limit contract tests

Production constants remain directly asserted in small, non-allocating tests.
For example, a test can assert that the production custody page remains 1,024
without creating 1,025 signed Events. These tests protect accidental limit
changes while parameterized correctness tests protect the algorithm on both
sides of a boundary.

The same production code path must consume both production and test limits.
Tests may inject internal limits; they must not use a test-only algorithm,
storage format, or protocol.

### Qualification and benchmark programs

Scale, throughput, soak, and resource-envelope work moves to explicit harnesses
outside default `cargo test` execution. Examples include a 100 MiB or 1 GiB
Blob, a complete 1,024-entry page, a 23-process mesh scenario, and hardware
measurements on CM4 devices. Each command must state:

- the scale or workload it executes;
- expected runtime and minimum machine resources;
- metrics and artifacts it produces;
- pass/fail criteria, when it is a qualification rather than a benchmark; and
- whether it is manual, scheduled, or release-gated.

Removing a scale fixture from the default suite is complete only after its
explicit replacement command and documentation exist. Required pull-request
checks do not run unbounded qualification workloads. Scheduled qualification
failures remain visible and actionable, but they do not silently expand the
default developer loop.

## Internal limit injection

Algorithms whose correctness currently depends on large production constants
will accept a private, immutable limits value at the narrowest useful internal
boundary. Production constructors supply the existing constants. Test helpers
may supply smaller positive values.

Limit injection must satisfy these invariants:

1. validation rejects zero or internally inconsistent values;
2. production constructors cannot accidentally inherit a test value;
3. the algorithm, persistence operations, protocol messages, and error paths
   are identical for production and test limits;
4. a direct contract test pins every production default affected by the
   refactor; and
5. public APIs and wire representations do not expose test controls.

Prefer one cohesive component limits object when several related operations
share a bound. Avoid global mutable overrides and environment variables because
they make parallel tests order-dependent. When a constant only controls fixture
construction and not behavior, shrink the fixture directly rather than adding
configuration.

## Matrix decomposition

Long serial tests that execute independent cases will become individually named
tests over shared helpers. Nextest can then schedule cases fairly, report the
specific failing case, and avoid rerunning an entire matrix after one failure.
Cases may remain grouped only when they share one required state transition or
when splitting them would change the behavior being tested.

Decomposition must not replace semantic assertions with snapshots or reduce
the set of injected failures. Shared setup helpers should return typed fixtures
and expose only the controls needed by the case. Cleanup remains owned by each
test so one timeout or panic cannot leak a process, task, port, or temporary
directory into another test.

## Initial slow-test migrations

Retained nextest timing identified six tests over 60 seconds. Their required
coverage and replacement shape are:

| Current test | Behavior retained | Default correctness replacement | Scale replacement |
| --- | --- | --- | --- |
| `custody_reanchors_more_than_one_page_transactionally_across_reopen` | exact page boundary, partial transactional progress, reopen, and completion | inject a page limit of 2 and use 3 entries; separately assert the production limit is 1,024 | optional full-page store qualification |
| `finite_blob_late_exact_load_lifetime_loss_is_ordinary` | every expiry/discontinuity fault outcome and ordinary lifetime loss | expose the 20 cases as individually scheduled tests over one shared helper, then minimize each fixture | none unless resource behavior is separately claimed |
| `generated_100mb_blob_is_bounded_resumable_deduplicated_and_verified` | multi-chunk preparation, bounded buffering, resume, deduplication, full verification, range reads, and tamper rejection | use the minimum chunk count covering first/middle/last and every asserted branch | explicit large-Blob benchmark or qualification, including 1 GiB where required |
| `interrupted_event_page_preserves_prefix_and_reconnects_only_the_remainder` | interruption after a page, durable prefix, reopen, and exact remainder | inject a small sender page limit and use `limit + 1` Events; separately pin the production limit | optional production-page qualification |
| `active_two_way_sync_converges_across_root_offer_boundary` | below, at, and above the reconciliation boundary | split the three cases; inject a smaller fanout only if it drives the identical production path, otherwise optimize setup and repeated set work while retaining the exact constant | optional high-cardinality reconciliation benchmark |
| `four_real_processes_propagate_controls_without_authority_and_exclude_captured_leaf` | CLI wiring plus control propagation, authority exclusion, and captured-leaf exclusion | keep a minimal real-process wiring smoke and cover protocol semantics in focused component tests | preserve the complete 11-phase, 23-process scenario as an explicit mesh qualification |

Each migration must first inventory the original assertions and then map every
assertion to a replacement test or qualification check. The review diff must
make this mapping obvious.

## Timing measurement and problem tagging

The 10-second value is an optimization target and reporting threshold, not a
test gate. The default and CI nextest profiles do not terminate a test because
of elapsed time, and a duration above the target does not fail an otherwise
functional CI run.

The existing JUnit artifacts and bounded slow-test summary remain the source
for aggregate evidence. The timing tool tags every completed test above 10
seconds with its full identity and elapsed time in the job summary and emits a
GitHub warning annotation when requested by CI. It exits successfully after
reporting duration problems; malformed, missing, or invalid timing data still
fails because no trustworthy measurement was produced. Raw retained reports
provide auditable timing history and allow platform variance to be compared
without hiding it behind a pass/fail threshold.

The 5-minute warm-suite target is evaluated from nextest wall time, not the sum
of individual test durations. CI partition durations remain useful operational
data but cannot substitute for an occasional unpartitioned warm measurement.
No timeout increase, retry, partition-count increase, or test exclusion counts
as a performance improvement merely because it changes the reported timing.

## Resource policy

The existing resource wrapper continues to disable incremental compilation,
cap build jobs, bound test threads, remove debug information from test builds,
and establish the file-descriptor floor required by bounded network fixtures.
The refactor adds these rules:

- correctness fixtures allocate only the minimum boundary-derived population;
- payloads use deterministic generated content rather than retained large
  files;
- tests stream payloads instead of constructing duplicate full-size buffers
  unless duplicate ownership is the exact behavior under test;
- real-process and socket-heavy tests use explicit nextest resource groups;
- group limits describe genuine shared resources, not a workaround for hidden
  global state;
- spawned children and background tasks have bounded shutdown and are reaped on
  success, error, panic, and timeout; and
- temporary storage is scoped per test and removed by fixture ownership.

Before and after the migration, one representative unpartitioned run will
record peak resident memory, peak temporary-disk use, maximum child-process
count, and maximum open descriptors where the runner permits reliable
measurement. Those baselines determine whether a later numeric resource gate is
portable. This design does not invent an unevidenced absolute memory threshold;
code review and retained measurements identify production-scale allocation that
does not belong in default correctness tests.

## Local and CI workflow

`mise run check-workspace-tests` remains the canonical local Rust correctness
command. Required Linux CI runs exactly that population in two nextest slices
and one slice runs doctests. Partitioning is scheduling only: filters may not
create CI-only or local-only correctness coverage.

The required macOS job continues to compile every target and execute focused
platform contracts. The scheduled full macOS workflow remains a portability
qualification until its complete correctness population is both fast and
resource-bounded; the implementation plan must evaluate whether it can then
reuse the canonical nextest profile without duplicating compilation.

Repository Python, shell, binding, conformance, and real-process checks follow
the same principle. During implementation they will be timed and classified as
correctness, policy, compile-only, or qualification work. Any correctness check
over 10 seconds must be decomposed or minimized; any intentional scale check
must move behind an explicit qualification command. Compilation and lint time
are reported separately from test execution.

## Failure handling and diagnostics

- A malformed or missing timing report fails the timing policy check rather
  than reporting success.
- A test over the reporting target produces a non-failing problem tag with its
  identity, observed duration, and 10-second target.
- An invalid injected limit fails at construction with a specific diagnostic.
- A leaked child or incomplete cleanup fails its owning fixture instead of
  relying on a later test to expose the leak.
- A scheduled qualification timeout reports incomplete qualification; it does
  not change correctness-suite status or requirement maturity.
- Platform variance is investigated from retained raw timing before changing a
  reporting target. Permanent timing allowlists are not part of this design.

## Compatibility and security

This refactor does not change public APIs, protocol messages, durable schemas,
transport selection, authorization, cryptographic validation, or production
limits. Private limit injection must not bypass validation or weaken bounds.
Reduced fixtures still use authentic signing, encryption, storage, and parser
paths where the original test did.

Test cleanup is security-relevant: temporary credentials, sockets, and child
processes must retain current ownership and permission checks. Moving a workload
to qualification cannot remove adversarial assertions from required correctness
coverage; only its scale may move.

## Delivery sequence

Implementation proceeds in reviewable increments:

1. add characterization tests for timing-policy diagnostics and production
   constants;
2. minimize the large Blob fixture and create the explicit large-Blob harness;
3. introduce private page-limit injection for custody and Event pagination;
4. split the finite-Blob fault matrix into independently scheduled cases;
5. refactor reconciliation boundary setup without weakening the exact boundary
   contract;
6. separate minimal real-process CLI wiring from full mesh qualification;
7. inventory and classify the remaining repository checks, applying the same
   limit to any additional slow correctness checks;
8. enable 10-second problem tagging in the retained timing report without a
   duration gate;
9. update the engineering runbook with local, CI-equivalent, benchmark, and
   qualification examples; and
10. retain before/after timing and resource evidence in the pull request.

Each increment uses test-driven changes and focused verification. The final
branch runs formatting, policy checks, Clippy, the complete canonical
correctness population, doctests, and the relevant explicit qualification
harnesses. Expensive qualification is not repeated after documentation-only
changes unless those changes affect its command or acceptance logic.

## Non-goals

This work does not:

- change a production capacity, page, chunk, fanout, or protocol limit;
- claim 1 GiB transfer throughput, CM4 performance, or physical-mesh maturity;
- delete scale validation instead of relocating and documenting it;
- make a slow test appear fast through retries, increased parallelism, larger
  timeouts, ignored results, or less coverage;
- merge distinct failure cases solely to reduce the reported test count;
- optimize cold dependency downloads or compilation under the 5-minute test
  target; or
- change the current Aster implementation or release boundary.
