# Fast, Resource-Bounded Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve Aster's correctness coverage while making every default test complete within 10 seconds and the warm all-feature Rust workspace suite complete within 5 minutes using bounded fixtures and resources.

**Architecture:** Default correctness tests exercise the smallest fixture that crosses each semantic boundary, while non-allocating contract tests pin production limits. Independent fault cases become separately scheduled tests, and intentionally physical-scale workloads remain available only through explicit ignored qualification targets or benchmark commands. Retained JUnit data measures the result and tags tests above the 10-second target without terminating them or failing functional CI.

**Tech Stack:** Rust 1.97.1, Tokio, cargo-nextest 0.9.145, Python 3.13 JUnit policy tooling, mise, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-10-20-fast-resource-bounded-tests-design.md`

## Global Constraints

- Optimize every default correctness test toward at most 10 seconds on its required supported runner after compilation; report and tag misses without gating execution.
- A warm unpartitioned `cargo nextest run --locked --workspace --all-features --test-threads 2` must complete in at most 5 minutes.
- Local and required-CI Rust runs must contain the same correctness population; CI slicing changes scheduling only.
- Use the smallest boundary-derived fixture and separately assert unchanged production constants.
- Test controls remain private and immutable; no environment-driven or global mutable limit overrides.
- The production algorithm, validation, persistence, wire path, public API, durable schema, and runtime limits remain unchanged.
- Existing correctness assertions must map to a default replacement or an explicit qualification assertion before the old test changes.
- No retry, timeout increase, extra CI slice, permanent allowlist, or ignored failure may satisfy a timing budget.
- No requirement status, capability maturity, or retained acceptance evidence changes.
- All commits are signed; keep the branch local until the user explicitly authorizes a push.

## Review Focus

- A zero or above-production injected page/offer limit must fail closed, while production constructors still select exactly 1,024 custody rows, 256 Event page entries, and 256 offer identifiers; Task 4 adds these contract and invalid-input assertions for each limit-owning component.
- A JUnit duration equal to 10.000 seconds is not tagged and any finite duration above it is tagged with the full test identity without a nonzero exit; malformed, empty, negative, NaN, and infinite reports fail closed in Task 2.
- A split fault case that panics or times out must still reap tasks, child processes, stores, sockets, and temporary directories without poisoning another case; Tasks 5 and 7 add sequential-after-failure cleanup regressions.
- Qualification workloads must remain runnable but must neither enter default nextest execution nor silently disappear; Tasks 3 and 7 add selection-policy tests for both outcomes.
- Platform or runner variance must remain visible through raw JUnit evidence and problem tags, never timing allowlists; Task 11 tests the reporting configuration and records an unpartitioned verification run.

---

### Task 1: Retain the complete timing baseline and assertion map

**Files:**
- Create: `docs/superpowers/reports/2026-10-20-fast-test-baseline.md`
- Modify: `docs/validation/ci.md`

**Interfaces:**
- Consumes: JUnit artifacts from hosted run `39425460770`, partitions 1 and 2
- Produces: the authoritative 34-test over-10-second inventory and the assertion-disposition checklist used by Tasks 3–7

- [ ] **Step 1: Write the baseline report with failing acceptance assertions**

Record both artifact identities, 1,160 recorded cases per partition, cumulative times of 1,219.112 seconds and 1,132.535 seconds, and a table containing every test above 10 seconds. For each row, require columns for original assertions, replacement default test, scale qualification when applicable, and final hosted duration; leave only the final duration unchecked.

- [ ] **Step 2: Verify the inventory is complete**

Run the timing summarizer with `--limit 100` on both retained JUnit files and compare every row above 10 seconds to the report. Expected: 18 partition-1 rows, 16 partition-2 rows, and no unmatched identity.

- [ ] **Step 3: Document the evidence boundary**

Update `docs/validation/ci.md` to distinguish default correctness, production-limit contracts, and explicit qualification/benchmark execution. State that fixture minimization neither adds nor removes requirements credit.

- [ ] **Step 4: Verify documentation integrity**

Run: `git diff --check && python3 tools/check-implementation-requirements.py`

Expected: PASS; no requirement status or evidence path changes.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/reports/2026-10-20-fast-test-baseline.md docs/validation/ci.md
git commit -S -m "docs(test): retain slow-suite baseline"
```

### Task 2: Measure and tag the 10-second target deterministically

**Files:**
- Modify: `.github/scripts/summarize-nextest-junit.py`
- Modify: `.github/scripts/test-nextest-timing.py`

**Interfaces:**
- Consumes: nextest JUnit `<testcase time>` values
- Produces: `summarize(source: Path, partition: str, limit: int, problem_seconds: float | None) -> tuple[str, list[tuple[float, str]]]`, with deterministic non-failing problem tags ready for Task 11

- [ ] **Step 1: Write failing timing-policy tests**

Add tests named `test_does_not_tag_duration_equal_to_target`, `test_tags_every_duration_above_target_without_failing`, and `test_rejects_negative_nan_infinite_empty_and_malformed_reports`. Assert `10.000` is untagged, `10.001` exits zero and appears in the problem table with its classname/name identity and target, and no successful summary is published for invalid input.

- [ ] **Step 2: Run the policy tests to verify failure**

Run: `python3 .github/scripts/test-nextest-timing.py`

Expected: FAIL because `--problem-seconds` and problem tagging do not exist.

- [ ] **Step 3: Implement the policy parser and CLI**

Add `positive_finite_seconds(value: str) -> float`, add optional `--problem-seconds`, return sorted problem rows from `summarize`, and add optional `--github-annotations`. Write the bounded summary and warning annotations but return zero for duration problems. Keep current report-only callers compatible and malformed reports fail-closed.

- [ ] **Step 4: Run focused verification**

Run: `python3 .github/scripts/test-nextest-timing.py`

Expected: PASS, including the exact boundary and malformed-input cases.

- [ ] **Step 5: Commit**

```bash
git add .github/scripts/summarize-nextest-junit.py .github/scripts/test-nextest-timing.py
git commit -S -m "test(ci): classify slow test timings"
```

### Task 3: Replace the production-scale core Blob fixture

**Files:**
- Modify: `crates/aster-core/src/blob.rs`
- Modify: `tools/blob_benchmark.py`
- Modify: `tools/test_blob_benchmark.py`
- Modify: `docs/validation/blob-benchmark.md`

**Interfaces:**
- Consumes: `MAX_BLOB_CHUNK_SIZE`, the existing generated source/store fixture, and the retained Blob benchmark runner
- Produces: a fast eight-plus-partial-chunk correctness test and explicit 100 MiB qualification selection

- [ ] **Step 1: Add failing qualification-selection tests**

Extend `test_blob_benchmark.py` to assert a named scale campaign can select 100 MiB while the default four-size campaign remains unchanged and invalid/unlisted sizes fail closed.

- [ ] **Step 2: Run the focused tests to verify the missing scale selection**

Run: `python3 tools/test_blob_benchmark.py`

Expected: FAIL because the scale profile does not exist.

- [ ] **Step 3: Minimize the core Blob correctness fixture**

Rename it `generated_multichunk_blob_is_bounded_resumable_deduplicated_and_verified`, use `8 * MAX_BLOB_CHUNK_SIZE + 123`, and retain every current assertion: seven-chunk interruption, bounded buffers, resume, deduplication, manifest digest, full verification, tail range, cross-chunk range, and tamper rejection. Preserve a separately ignored `qualify_generated_100mb_blob_pipeline` with the original 101 MiB + 123 workload and an explicit nextest ignored-only command in the benchmark documentation.

- [ ] **Step 4: Add explicit Blob scale selection**

Add a named `scale` campaign to `tools/blob_benchmark.py` without changing the default campaign. The runner must retain the selected profile in metadata and preserve source/binary identity validation. Document that sizes above the current network admission limit exercise rejection unless a future production-limit change is separately approved; do not change that limit here.

- [ ] **Step 5: Verify default and qualification selection**

Run the renamed/minimized Rust test, `python3 tools/test_blob_benchmark.py`, and `cargo nextest list -p aster-core --all-features`. Expected: the default replacement passes; the ignored 100 MiB qualification is listed but not run by the default filter.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-core/src/blob.rs tools/blob_benchmark.py tools/test_blob_benchmark.py docs/validation/blob-benchmark.md
git commit -S -m "test(blob): separate correctness from scale"
```

### Task 4: Replace paging and reconciliation scale with semantic boundaries

**Files:**
- Modify: `crates/aster-core/src/runtime.rs`
- Modify: `crates/aster-core/src/sync.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-node/src/runtime.rs`

**Interfaces:**
- Consumes: existing `SyncConfig::max_offer_ids`, `TestCustodyPreopenRace::EventPageTargetEntries`, and custody collection `limit`
- Produces: `assert_two_way_sync_converges(item_count: usize, max_offer_ids: usize)` and fast exact/over-boundary paging tests

- [ ] **Step 1: Add production-contract and invalid-limit tests**

Assert `SyncConfig::default().max_offer_ids == 256`, `MAX_CUSTODY_PAGE == 1_024`, and `EVENT_PAGE_SENDER_TARGET_ENTRIES == 256`. Assert `SyncConfig` and custody collection reject zero and above-production limits; replace the Event page test hook's silent clamping with a test-setup error for zero or above 256.

- [ ] **Step 2: Minimize custody and Event pagination fixtures**

Use `const TEST_PAGE: usize = 2` and three Events in `custody_reanchors_more_than_one_page_transactionally_across_reopen`. In `interrupted_event_page_preserves_prefix_and_reconnects_only_the_remainder`, add `EventPageTargetEntries(2)` to both contact hook vectors and publish three Events. Retain partial commit, reopen, exact remainder, receipt, cursor, and final-content assertions.

- [ ] **Step 3: Parameterize and split reconciliation boundary cases**

Extract `assert_two_way_sync_converges(item_count, max_offer_ids)`. Create three independent tests for item counts 3, 4, and 5 with `max_offer_ids = 4`; preserve authentication, convergence, exact ingested sets, request bounds, and empty wants. Keep the production `256` contract test non-allocating.

- [ ] **Step 4: Run focused verification**

Run the custody, interrupted-page, three reconciliation, production-contract, and invalid-limit tests. Expected: PASS and every default case completes under 10 seconds.

- [ ] **Step 5: Commit**

```bash
git add crates/aster-core/src/runtime.rs crates/aster-core/src/sync.rs crates/aster-redb-store/src/lib.rs crates/aster-node/src/runtime.rs
git commit -S -m "test: use semantic paging boundaries"
```

### Task 5: Decompose serial runtime matrices into isolated cases

**Files:**
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/runtime/blob_ranges_stream_boundary_tests.rs`
- Modify: `crates/aster-node/src/runtime/blob_ranges_stream_lanes_tests.rs`

**Interfaces:**
- Consumes: existing contact helpers, fault enums, and task-local test hooks
- Produces: one async helper per matrix and one independently named `#[tokio::test]` per fault/direction combination

- [ ] **Step 1: Characterize every matrix assertion**

Before changing loops, add helper-level tests or comments mapping all cases for: eight carrier-boundary lifetime losses, twenty late exact-load losses, eighteen protected receive rejections, wrong-settlement variants, four adjacent-finalization variants, five Event page sender races, Blob coherence faults, and finite page-authentication windows.

- [ ] **Step 2: Extract exact case helpers**

Create helpers with these signatures: `assert_finite_blob_lifetime_case(label, boundary, fault)`, `assert_finite_blob_late_load_case(label, window, fault)`, `assert_blob_receive_rejection_case(direction, fault)`, `assert_blob_wrong_settlement_case(case)`, `assert_blob_finalization_case(kind, direction)`, and `assert_event_page_sender_race_case(case)`. Each helper owns and removes its stores and contact state.

- [ ] **Step 3: Generate independently scheduled tests**

Use local declarative macros only to create named test functions; do not retain an outer serial loop. Each function invokes exactly one helper case and preserves the original assertions. Add a regression that runs two cases sequentially after an injected helper error and proves the second case obtains clean stores, task-local hooks, and ports.

- [ ] **Step 4: Minimize repeated setup without sharing mutable state**

Reduce Blob payloads to the minimum chunk/range count required by each fault. Replace fixed `0..32` progress loops with a helper that exits on the asserted boundary and fails with bounded diagnostic state when the production maximum is exhausted; do not add sleeps or retries.

- [ ] **Step 5: Verify every generated identity and assertion count**

Run `cargo nextest list -p aster-node --all-features` and compare generated case names to the characterization list. Then run the new case filters with `--test-threads 2`. Expected: every former matrix case appears once and passes independently.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-node/src/runtime.rs crates/aster-node/src/runtime/blob_ranges_stream_boundary_tests.rs crates/aster-node/src/runtime/blob_ranges_stream_lanes_tests.rs
git commit -S -m "test(node): schedule stream fault cases independently"
```

### Task 6: Remove scale and duplicated work from remaining node correctness tests

**Files:**
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/runtime/blob_ranges_stream_boundary_tests.rs`
- Modify: `crates/aster-node/src/runtime/blob_ranges_stream_lanes_tests.rs`

**Interfaces:**
- Consumes: task-local Event page target, preaccounted contact capacity, synthesized Blob claim metadata, and existing small-payload contact helpers
- Produces: fast semantic tests for the remaining `aster-node::runtime` entries in the 34-test baseline

- [ ] **Step 1: Add fast synthetic over-limit claim construction**

Add `AuthenticatedBlobRouteClaim::with_total_len_for_test(self, total_len: u64) -> Self` plus a cache insertion helper under `cfg(test)`. Rewrite `oversized_blob_direct_range_is_withheld_before_authentication_or_depot_access` to use a small verified source and a synthetic `MAX_NETWORK_BLOB_BYTES + 1` cached claim for the ordering assertions, without allocating or encrypting 64 MiB. Preserve the original valid local-only oversized publication as an ignored exact qualification, so the default test proves pre-auth/no-depot/no-cursor ordering and the qualification proves the production-scale premise.

- [ ] **Step 2: Separate near-limit serialization from small real transfer**

Split `current_stack_near_two_mib_events_each_direction` into a fast exact serialization-boundary test and a small bidirectional real-contact test. Preserve the actual near-2-MiB end-to-end case as ignored qualification. The default tests still assert envelope overhead, inclusive `MAX_OBJECT_BYTES`, source authentication, byte equality, both directions, and correct receipts.

- [ ] **Step 3: Bound saturated Event and mutable-lane fixtures**

Use task-local target/capacity hooks so `v7_saturated_events_preserve_all_later_lanes_and_bridge_deferral_progress`, `blob_ranges_stream_saturated_six_mutable_directions`, and `v7_saturated_events...` reach scheduled/unscheduled and later-lane states with the smallest populations. Separately assert production capacities; retain every lane receipt and deferral-progress assertion.

- [ ] **Step 4: Split state/record and source-rotation scenarios**

Extract independent tests from `live_mutable_handles_converge_disconnected_state_and_record_then_resolve`, `blob_ranges_stream_publication_capacity_rotates_two_installed_sources`, `blob_source_carrier_reopen_resumes_exact_complement_from_different_peer`, and `stale_pending_blob_cleanup_removes_visibility_but_retains_reserved_staging`. Reuse immutable setup builders only; each case owns its stores and cleanup.

- [ ] **Step 5: Run all formerly slow node runtime identities**

Run a nextest expression selecting the `aster-node::runtime` identities from the baseline with `--test-threads 2`. Expected: all pass, none reaches 10 seconds, and no test is retried.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-node/src/runtime.rs crates/aster-node/src/runtime/blob_ranges_stream_boundary_tests.rs crates/aster-node/src/runtime/blob_ranges_stream_lanes_tests.rs
git commit -S -m "test(node): minimize correctness workloads"
```

### Task 7: Separate real-process correctness smoke from mesh qualification

**Files:**
- Modify: `crates/aster-node/tests/mesh_cli.rs`
- Modify: `.config/nextest.toml`
- Modify: `mise.toml`
- Modify: `docs/quickstart/mesh-cli.md`
- Modify: `.github/scripts/test-ci-test-lanes.py`

**Interfaces:**
- Consumes: existing `aster demo` CLI scenarios and `mesh-cli-process` nextest group
- Produces: `mise run qualify-control-mesh`, explicit ignored qualification tests, and default real-process smokes under 10 seconds

- [ ] **Step 1: Pin default/qualification selection behavior**

Extend `test-ci-test-lanes.py` to assert required CI never uses `--run-ignored`, while the mise qualification task selects only the exact ignored control scenario with one test thread.

- [ ] **Step 2: Preserve full scenarios as explicit qualification**

Mark the 23-process control scenario and other multi-phase full-demo acceptance tests from the baseline as ignored with actionable reasons. Add `qualify-control-mesh` and `qualify-ping-pong-mesh` tasks that run exact ignored identities, serially, through the resource wrapper. Preserve all existing stdout, log, authority-exclusion, captured-node, restart, and process-count assertions.

- [ ] **Step 3: Add minimal public-binary wiring smokes**

Use the smallest existing CLI modes to prove argument parsing, child startup, real Iroh bind/contact, clean shutdown, and result grammar without replaying the full 8-, 11-, or 23-process scenarios. Component tests remain responsible for control propagation and policy semantics.

- [ ] **Step 4: Prove cleanup isolation**

Add a test-only forced child failure followed by a successful smoke using the same serialized group. Assert no child remains, the second run binds successfully, and each fixture root is independently removed.

- [ ] **Step 5: Verify selection and commands**

Run default `aster-node::mesh_cli` tests, then run each qualification task once. Expected: default cases each finish under 10 seconds; ignored scenarios retain their exact prior assertions and pass explicitly.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-node/tests/mesh_cli.rs .config/nextest.toml mise.toml docs/quickstart/mesh-cli.md .github/scripts/test-ci-test-lanes.py
git commit -S -m "test(mesh): separate smoke from qualification"
```

### Task 8: Eliminate deliberate wall-clock waits

**Files:**
- Modify: `crates/asterctl/tests/cli.rs`
- Modify: `crates/asterctl/tests/operation_key.rs`
- Modify: `crates/aster-agent/tests/real_node_connect.rs`

**Interfaces:**
- Consumes: public configurable CLI timeout and millisecond Event TTL
- Produces: bounded timeout/expiry correctness tests without changing production defaults

- [ ] **Step 1: Shorten configurable timeout tests without changing defaults**

Pass `--timeout=1` in `stalled_agent_is_bounded_by_the_request_deadline` and both generated-operation-key timeout cases; keep a server hold longer than one second and assert the same deadline and no-retry diagnostics. Do not change the production 10-second default.

- [ ] **Step 2: Use a bounded live-agent TTL fixture**

Set the platform compatibility fixture TTL to the shortest value that leaves a measured pre-expiry margin on hosted runners, target 3 seconds, and keep the 50 ms post-expiry crossing. Preserve zero-TTL rejection, tombstone rejection, retry identity, changed-request conflict, query/poll visibility, retirement, capacity release, and platform-specific authorization assertions.

- [ ] **Step 3: Run focused verification**

Run the three exact baseline identities with two nextest threads. Expected: identical timeout/expiry assertions and every identity under 10 seconds.

- [ ] **Step 4: Commit**

```bash
git add crates/asterctl/tests/cli.rs crates/asterctl/tests/operation_key.rs crates/aster-agent/tests/real_node_connect.rs
git commit -S -m "test: replace wall-clock defaults with bounded fixtures"
```

### Task 9: Scan provider binaries once per marker set

**Files:**
- Modify: `crates/aster-agent/tests/systemd_provider_binary.rs`
- Modify: `crates/aster-compose-credentials/tests/compose_binary.rs`

**Interfaces:**
- Consumes: immutable package-specific binary paths
- Produces: `MarkerReport` and one-pass provider-isolation assertions

- [ ] **Step 1: Add failing multi-marker scan tests**

Use a synthetic byte fixture containing markers across scan-buffer boundaries. Assert all required markers are reported present, every forbidden marker is reported by exact bytes, absent required markers are returned exactly once, and an unreadable path returns its I/O error.

- [ ] **Step 2: Implement a single-pass marker report**

Replace repeated whole-binary `windows()` passes with `find_binary_markers(path: &Path, required: &[&[u8]], forbidden: &[&[u8]]) -> io::Result<MarkerReport>` in each package test, where `MarkerReport { missing_required: Vec<Vec<u8>>, present_forbidden: Vec<Vec<u8>> }`. Read the binary once with enough overlap for the longest marker, scan all markers per block, and return exact markers for diagnostics.

- [ ] **Step 3: Preserve provider-isolation assertions**

Update the systemd and Compose binary tests to assert both report vectors are empty, then retain the existing forbidden CLI/provider invocation checks.

- [ ] **Step 4: Run and commit**

Run both exact baseline identities. Expected: PASS under 10 seconds.

```bash
git add crates/aster-agent/tests/systemd_provider_binary.rs crates/aster-compose-credentials/tests/compose_binary.rs
git commit -S -m "test(agent): scan provider binaries once"
```

### Task 10: Minimize lab scenarios and split reconciliation cases

**Files:**
- Modify: `crates/aster-lab/src/lib.rs`
- Modify: `crates/aster-lab/src/mesh_experiment.rs`
- Modify: `crates/aster-lab/tests/reconciliation_bakeoff.rs`

**Interfaces:**
- Consumes: existing scenario bounds and deterministic fixture builders
- Produces: minimal multi-frame/recovery fixtures and `assert_candidate_matches_oracle(items_each: usize, delta_each: usize, shape: Shape) -> TestResult<()>`

- [ ] **Step 1: Add non-allocating production-limit contracts**

Assert the native command production maximum remains 1 MiB and the Blob recovery scenario continues to validate its documented upper bounds without executing those maxima.

- [ ] **Step 2: Minimize lab data**

Use the smallest multi-frame payload that exercises queued generation invalidation instead of `MAX_COMMAND_BYTES`. Reduce Blob recovery to the minimum chunk count that has a durable prefix and an alternate-peer remainder; retain reopen, partial-byte equality, alternate peer, and final convergence assertions.

- [ ] **Step 3: Split bake-off cases**

Expand the six reconciliation inputs into six independently named tests over `assert_candidate_matches_oracle(items_each, delta_each, shape)`. Preserve exact Aster and Negentropy oracle equality for every original tuple.

- [ ] **Step 4: Run focused package tests**

Run the exact `aster-lab` baseline identities with two nextest threads. Expected: all original assertions pass and each identity is under 10 seconds.

- [ ] **Step 5: Commit**

```bash
git add crates/aster-lab/src/lib.rs crates/aster-lab/src/mesh_experiment.rs crates/aster-lab/tests/reconciliation_bakeoff.rs
git commit -S -m "test(lab): minimize correctness scenarios"
```

### Task 11: Measure the suite and tag remaining timing problems

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/scripts/summarize-nextest-junit.py`
- Modify: `.github/scripts/test-nextest-timing.py`
- Modify: `.github/scripts/test-ci-test-lanes.py`
- Modify: any test file identified by the fresh timing run
- Modify: any default Python, shell, binding, conformance, or real-process check identified by the command inventory

**Interfaces:**
- Consumes: Task 2's committed optional policy and Tasks 3–10's minimized suite
- Produces: retained before/after measurements and non-failing problem tags for every over-10-second case

- [ ] **Step 1: Run the warm unpartitioned suite with JUnit retention**

Run the existing `ci` JUnit profile unpartitioned. Record wall time, cumulative time, peak RSS, temporary-disk delta, child-process high water, and open-descriptor high water where supported.

- [ ] **Step 2: Tag and investigate every remaining over-target identity**

Run the timing reporter against the fresh report with `--problem-seconds 10`. Expected: exit zero plus an exact problem table for any identities over 10 seconds. Add each tag to the baseline report, classify its scale/wait/matrix cause, apply the smallest-fixture or case-split rule in its owning file, and rerun that identity. Do not add timing allowlists.

- [ ] **Step 3: Time and classify every non-Rust default correctness command**

Enumerate the Python, shell, binding, conformance, and real-process commands reached by `check-foundation-core`, `check-compose-policy`, and `check-integration`. Run each command separately from a warm checkout with elapsed time and peak RSS retained in the baseline report. Classify compile-only and policy checks separately. Any correctness command over 10 seconds must be minimized, decomposed, or moved to an explicit qualification task with its semantic assertions retained in a fast component check; rerun each changed command individually.

- [ ] **Step 4: Add non-failing CI problem annotations**

Keep nextest profiles free of duration-based termination. Make the CI timing step pass `--problem-seconds 10 --github-annotations`; extend the lane contract tests to prove a 10.001-second fixture emits a warning and exits zero, while malformed timing still exits nonzero.

- [ ] **Step 5: Verify reporting, suite population, and measurements**

Run the timing tests, CI-lane tests, `cargo nextest list` for local/default and both CI slices, and the complete warm unpartitioned suite. Expected: equal union/population and zero functional failures; the report explicitly shows whether any test remains above 10 seconds and whether warm wall time meets 5 minutes, without changing the command's result for timing alone.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml .github/scripts/test-ci-test-lanes.py docs/superpowers/reports/2026-10-20-fast-test-baseline.md
# Add only the exact owning test files changed for fresh timing violations.
git commit -S -m "ci: tag slow tests in retained timing"
```

### Task 12: Update the engineering runbook and retain before/after evidence

**Files:**
- Modify: `docs/validation/ci.md`
- Modify: `docs/validation/blob-benchmark.md`
- Modify: `docs/quickstart/mesh-cli.md`
- Modify: `docs/superpowers/reports/2026-10-20-fast-test-baseline.md`
- Modify: `mise.toml`

**Interfaces:**
- Consumes: final commands and measurements from Tasks 3, 7, and 11
- Produces: reproducible local, CI-equivalent, benchmark, and qualification instructions

- [ ] **Step 1: Document the developer loop**

Include exact commands for focused tests, `mise run check-workspace-tests`, the two CI-equivalent slices, timing-report verification, and interpreting a non-failing over-10-second problem tag. State cold build/download time separately.

- [ ] **Step 2: Document explicit qualification**

Include expected runtime/resources and output locations for large-Blob and mesh qualifications. State that they are non-default, non-requirements-credit engineering evidence unless retained through the validation process.

- [ ] **Step 3: Complete the evidence table**

Fill every baseline row's replacement and final hosted duration. Add before/after cumulative/wall/resource totals, test counts, failures, ignored qualification counts, and raw artifact identities.

- [ ] **Step 4: Run documentation and task contract tests**

Run: `python3 .github/scripts/test-ci-test-lanes.py && python3 tools/test_blob_benchmark.py && python3 tools/check-implementation-requirements.py && git diff --check`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs mise.toml
git commit -S -m "docs(test): publish fast-suite runbook and evidence"
```

### Task 13: Final branch verification and review

**Files:**
- Modify only files required by verified failures

**Interfaces:**
- Consumes: complete implementation
- Produces: signed, locally verified branch ready for hosted CI when pushing is authorized

- [ ] **Step 1: Run focused policy and formatting checks**

Run: `cargo fmt --all -- --check`, all changed Python test scripts, `python3 tools/check-implementation-requirements.py`, and `git diff --check`.

- [ ] **Step 2: Run Rust static verification**

Run: `mise run check-clippy`.

Expected: PASS with no warnings.

- [ ] **Step 3: Run the canonical correctness population once**

Run: `mise run check-workspace-tests`.

Expected: all default tests and doctests pass; the timing report tags any test above 10 seconds without gating it and records whether warm nextest wall time meets 5 minutes.

- [ ] **Step 4: Run non-Rust focused integration checks**

Run changed binding, conformance, policy, and real-process smoke commands from `mise run check-foundation-core` and `mise run check-integration`; do not repeat full scale qualifications unless their implementation changed after Task 12.

- [ ] **Step 5: Request independent whole-branch review**

Review against the spec, baseline assertion map, protocol/production-limit compatibility, cleanup ownership, and evidence claims. Resolve every substantive finding with a focused regression.

- [ ] **Step 6: Verify signed history and local-only state**

Run `git log --show-signature main..HEAD`, `git status --short --branch`, and compare `HEAD` to `fork/refactor/ci-test-pipeline`. Expected: every new commit has a good signature, the worktree is clean, and the branch remains ahead locally without a push.
