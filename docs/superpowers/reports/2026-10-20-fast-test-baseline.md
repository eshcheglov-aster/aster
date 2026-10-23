# Fast-test baseline and assertion disposition

Date: 2026-10-20

This report is the authoritative inventory for the fast, resource-bounded test
work. It preserves the assertions exercised by every Rust test that took more
than 10 seconds in the retained hosted run. A test may be renamed or split only
when its row below has an equivalent default correctness replacement. Physical
scale may additionally move to an explicit qualification command, but it may
not replace default correctness coverage.

The 10-second value is an advisory reporting target. Crossing it produces a
problem tag, not a timeout, test termination, allowlist, retry, or CI failure.

## Source evidence

- GitHub Actions run: `39425460770`
- Partition 1 artifact: `rust-test-timing-1-09a9c792ea5f0f18e3e031743f56b606b8006458/junit.xml`
  - 1,160 recorded cases
  - 1,219.112 seconds cumulative test time
  - 18 cases above 10 seconds
- Partition 2 artifact: `rust-test-timing-2-09a9c792ea5f0f18e3e031743f56b606b8006458/junit.xml`
  - 1,160 recorded cases
  - 1,132.535 seconds cumulative test time
  - 16 cases above 10 seconds

## Current-branch focused measurements

These are warm local libtest measurements for the exact changed identities,
excluding compilation time. They are implementation evidence, not a substitute
for the fresh hosted JUnit population required to fill the final column below.
The owner explicitly excluded a complete local-suite rerun; the branch also
does not have the pinned `cargo-nextest` shim installed locally.

| Baseline identity or replacement set | Retained baseline | Focused current result |
| --- | ---: | ---: |
| Interrupted Event page | 88.735s | 3.28s |
| State/Record mutable convergence replacements | 34.937s | Serial pair 10.58s and 13.81s repeat; State 6.05s/6.04s, Record 4.52s/7.78s |
| Oversized Blob pre-authentication rejection | 49.023s | 1.45s |
| Six mutable Blob directions | 10.487s | 5.89s |
| Blob reopen/complement | 10.415s | 7.03s |
| Three stale-pending Blob replacements | 12.314s | 7.28s combined |
| Blob source fairness | 16.797s | 7.40s |
| Public-binary mesh smoke and failed-child cleanup | new replacement | 3.61s combined |
| Controlled relay | 10.189s | 7.47s |
| Protected-edge zeroization | 18.545s | 7.44s |
| CLI stalled-agent deadline | 11.012s | 2.01s |
| Generated operation-key timeout pair | 10.013s | 1.01s combined |
| Live-agent Event TTL | 11.580s | 4.45s |
| systemd provider-binary isolation | 12.694s | 8.21s |
| Compose provider-binary isolation | 18.186s | 8.49s |
| Gate-H queued-generation invalidation/recovery | 22.602s | 2.78s |
| Blob recovery/reopen/alternate peer | 13.445s | 2.46s |
| Six independently scheduled reconciliation cases | 11.511s combined | 4.50s combined with two threads |

The three full mesh demonstrations remain explicit qualifications and passed
locally with their original assertions: two-node Ping/Pong in 19.32s,
four-node Ping/Pong in 37.83s, and the control topology in 62.85s. They are
ignored by default and therefore are not duration problems in required CI.

The mutable live-path replacements deliberately retain production
`RunningNode` scheduling, application handles, authenticated contact receipts,
resolution propagation, and restart checks. Authenticated local fixture seeding
removes redundant network setup, and each live proof uses one bounded
two-worker Tokio runtime so the two carrier endpoints and hybrid-PQ work do not
serialize on one executor thread. The timing reporter must still tag any hosted
observation above 10 seconds; such observations are visible optimization
problems, not allowlisted exceptions or gates.

### Pending hosted measurement

- Run the complete unpartitioned `ci` profile and retain JUnit, wall time,
  cumulative time, peak RSS, temporary-disk delta, child-process high water,
  and descriptor high water.
- Confirm the union of the two CI slices equals the unpartitioned population.
- Time the 37 `check-foundation-core`, 2 `check-compose-policy`, and 16
  `check-integration` command entries separately. Classify compile-only and
  policy checks separately from correctness tests.
- Replace every `Pending hosted verification` cell only from those retained
  artifacts. Do not infer hosted timings from the focused local table.

CI now invokes the timing reporter with `--problem-seconds 10` and
`--github-annotations`. A test at 10.001 seconds emits a warning and exits
zero; malformed timing evidence still exits nonzero. This is measurement and
problem tagging only—there is no duration gate, allowlist, retry, or timeout.

The inventory was generated with the repository timing summarizer using
`--limit 100` against each raw JUnit document. Durations are observations from
that run, not performance guarantees.

## Assertion-disposition checklist

`Pending hosted verification` is intentionally the only incomplete field. The
replacement and qualification columns describe the required implementation;
they do not claim that later tasks are already complete.

| Partition | Baseline test and seconds | Original assertions retained | Required default correctness replacement | Explicit scale qualification, when applicable | Final hosted duration |
| --- | --- | --- | --- | --- | --- |
| 1 | `aster-core::blob::tests::generated_100mb_blob_is_bounded_resumable_deduplicated_and_verified` (91.464) | Generated source; seven-chunk interruption; bounded buffers; resume; deduplication; manifest digest; full verification; tail and cross-chunk ranges; tamper rejection. | Use `8 * MAX_BLOB_CHUNK_SIZE + 123` in `generated_multichunk_blob_is_bounded_resumable_deduplicated_and_verified`; retain every listed assertion. | Keep ignored `qualify_generated_100mb_blob_pipeline` and the named Blob `scale` campaign. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::interrupted_event_page_preserves_prefix_and_reconnects_only_the_remainder` (88.735) | Partial page commit, disconnect, reopen, exact remainder, receipt, cursor, and final content. | Inject page target 2 and publish 3 Events; independently assert the production target remains 256 and invalid overrides fail closed. | None; physical volume is not the behavior under test. | [ ] Pending hosted verification |
| 1 | `aster-core::runtime::tests::active_two_way_sync_converges_across_root_offer_boundary` (84.144) | Authentication, convergence in both directions, exact ingested sets, bounded requests, and empty terminal wants below/at/above the offer boundary. | Split counts 3, 4, and 5 around an injected offer limit of 4; independently assert the production limit remains 256. | None; the boundary is preserved with a smaller fixture. | [ ] Pending hosted verification |
| 1 | `aster-node::mesh_cli::four_real_processes_propagate_controls_without_authority_and_exclude_captured_leaf` (63.805) | Four-process wiring, control propagation, authority exclusion, captured-leaf exclusion, and clean shutdown. | A minimal real-process wiring smoke retains process/readiness/shutdown behavior; deterministic in-process tests retain topology and authorization assertions. | Keep the full four-process scenario as an ignored, explicitly selected qualification test. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::finite_blob_lifetime_loss_is_ordinary_at_every_carrier_boundary` (47.518) | Every carrier-boundary expiry outcome is ordinary, with correct prefix/cursor/settlement state and cleanup. | Split each boundary into an independent named test using the minimum multi-chunk Blob and shared setup/assertion helpers. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::live_mutable_handles_converge_disconnected_state_and_record_then_resolve` (34.937) | Disconnected publication, State convergence, Record conflict visibility, guarded resolution, and stable terminal state. | Split State and Record phases into focused tests; seed authenticated local conflicts without transport; retain one real direct `RunningNode` contact per class, exact path receipts, resolution propagation, and restart checks on a bounded two-worker runtime. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::v8_blob_protected_contact_rejection_matrix_is_receiver_state_neutral` (32.869) | Every protected-contact rejection reason fails closed and leaves receiver store, staging, cursors, and settlement neutral. | One independently scheduled test per rejection case through a shared assertion helper and minimum Blob fixture. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::mesh_cli::two_real_processes_use_the_same_stopped_state_ping_pong_plan` (21.834) | Two-process plan, readiness, exact ping-pong transfer, stopped state, and cleanup. | Minimal two-process wiring smoke ending on exact durable receipts rather than elapsed time. | Keep the complete operator-facing scenario as an ignored qualification test if it exceeds the target. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::blob_wrong_settlement_matrix_uses_real_claims_and_production_handlers` (19.294) | Each wrong settlement is rejected through real claims and production handlers without corrupting prefix, cursor, or terminal state. | Split matrix rows into independent named cases sharing immutable fixtures and minimum payloads. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::mesh_cli::live_zeroization_stops_a_configured_protected_edge_and_blocks_recontact` (18.545) | Live edge forms, zeroization stops it, recontact is blocked, denial is durable, and children are reaped. | Minimal real-process zeroization smoke driven by receipts, with deterministic policy details covered in process-free tests. | Retain a full topology qualification command if required for operational evidence. | [ ] Pending hosted verification |
| 1 | `aster-compose-credentials::compose_binary::compose_binary_has_only_the_compose_provider_and_no_legacy_mode` (18.186) | Built binary contains required Compose markers and excludes systemd/legacy-mode markers. | Build once and scan the binary once for the complete positive and negative marker set. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::blob_ranges_stream_publication_capacity_rotates_two_installed_sources` (16.797) | Publication capacity defers work, two installed sources rotate fairly, ranges remain exact, and completion settles once. | Inject the smallest capacity and range set that forces both sources to rotate; retain exact cursor and settlement assertions. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::v8_blob_carrier_adjacent_finalization_rejects_overrun_and_expiry_then_retries` (13.738) | Adjacent overrun and expiry reject finalization without mutation, then a valid retry completes exactly. | Split overrun and expiry into independent tests with minimum multi-chunk payloads and common retry assertions. | None. | [ ] Pending hosted verification |
| 1 | `aster-lab::legacy_lab::tests::blob_recovery_reopens_and_switches_to_alternate_peer` (13.445) | Interrupted recovery persists prefix, reopen requests the complement, alternate peer completes it, and digest verifies. | Use the minimum number and size of chunks needed for prefix/complement and peer-switch behavior. | None. | [ ] Pending hosted verification |
| 1 | `aster-node::runtime::tests::stale_pending_blob_cleanup_removes_visibility_but_retains_reserved_staging` (12.314) | Stale pending visibility disappears while reserved staging and accounting remain correct across cleanup/reopen. | Use the minimum Blob and directly controlled test clock; retain visibility, reservation, accounting, and reopen checks. | None. | [ ] Pending hosted verification |
| 1 | `aster-agent::real_node_connect::platform_compat_optional_event_ttl_is_enforced_by_the_live_agent` (11.580) | Live agent accepts optional TTL, exposes the Event before expiry, and removes/rejects it after expiry. | Use a private 3-second fixture TTL and readiness polling; retain the production default contract separately. | None. | [ ] Pending hosted verification |
| 1 | `aster-lab::reconciliation_bakeoff::candidate_and_real_aster_reducer_match_exact_oracle` (11.511) | Candidate and production reducers match the exact oracle for all six reconciliation cases. | Split the six cases into independently scheduled tests using one shared case assertion. | Keep aggregate bakeoff reporting as an explicit benchmark command, not a default test. | [ ] Pending hosted verification |
| 1 | `aster-node::mesh_cli::controlled_relay_selected_when_direct_candidate_unusable_then_noops` (10.189) | Unusable direct candidate selects controlled relay, exact sync completes, and later planning is a no-op. | Minimize payload and end on exact receipts; keep selection logic in deterministic process-free coverage. | Full real-process relay topology remains an explicit qualification when needed. | [ ] Pending hosted verification |
| 2 | `aster-redb-store::tests::custody_reanchors_more_than_one_page_transactionally_across_reopen` (124.763) | More-than-one-page collection, transactional reanchor, reopen durability, exact rows, and no duplication/loss. | Inject page size 2 and use 3 Events; independently assert production page size 1,024 and reject invalid test limits. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::finite_blob_late_exact_load_lifetime_loss_is_ordinary` (104.049) | Each late exact-load lifetime-loss point is ordinary and preserves exact storage, cursor, settlement, and cleanup state. | Split the 20 cases into independent tests with minimum payloads and a shared assertion helper. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::oversized_blob_direct_range_is_withheld_before_authentication_or_depot_access` (49.023) | Oversized range is withheld before authentication and before depot access, with no receiver mutation. | Use a synthetic cached oversized claim to prove ordering without allocating the payload; retain exact access counters and neutral state. | Keep an ignored valid local Blob above 64 MiB to qualify the physical allocation path. | [ ] Pending hosted verification |
| 2 | `aster-node::mesh_cli::four_real_processes_default_to_ping_pong_and_restart_cleanly` (41.663) | Default four-process topology, bidirectional transfer, stopped state, restart, retained data, and cleanup. | Minimal real-process restart smoke with tiny payload and receipt-driven completion; deterministic tests retain plan semantics. | Keep the complete four-process scenario as an ignored qualification test. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::v7_pages_authenticate_finite_sources_before_custody_finalization_window` (37.879) | Finite source is authenticated before custody finalization and failures do not advance state across the finalization window. | Split authentication/finalization cases and use the smallest page and payload that crosses the ordering boundary. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::live_blob_contact_coherence_faults_send_no_result_and_close_the_actor` (30.444) | Each coherence fault emits no result, closes the contact actor, preserves durable state, and reaps resources. | Split fault cases into independent tests with a shared minimum fixture; add a sequential-after-failure cleanup regression. | None. | [ ] Pending hosted verification |
| 2 | `aster-lab::mesh_experiment::tests::native_gate_h_signed_control_queued_generation_invalidation_and_recovery` (22.602) | Signed control queues, generation invalidation blocks stale work, recovery accepts current work, and results are exact. | Use the minimum multi-frame payload and split independent invalidation/recovery phases where isolation is semantic. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::v7_saturated_events_preserve_all_later_lanes_and_bridge_deferral_progress` (15.792) | Event saturation preserves all later lanes and bridge deferral later progresses without loss or starvation. | Inject the smallest queue capacity and item count that causes one saturation and later-lane progress. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::current_stack_near_two_mib_events_each_direction` (15.453) | Near-limit Event serializes and transfers in each direction with exact identity, payload, and receipts. | Test the near-2-MiB serialization boundary without networking, plus a small bidirectional network Event with the same protocol assertions. | Retain the actual near-limit end-to-end transfer as an ignored qualification test. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::event_page_boundary_authorization_selector_and_emission_races_fail_closed` (14.262) | Each authorization, selector, and emission race fails closed without cursor or storage mutation and can recover. | Split the five race cases into independent named tests with a page size of 2 and minimum Events. | None. | [ ] Pending hosted verification |
| 2 | `aster-agent::systemd_provider_binary::systemd_binary_accepts_only_schema_v1_and_has_no_compose_contract` (12.694) | Built binary contains schema-v1/systemd markers and excludes Compose/legacy contract markers. | Build once and scan the binary once for the complete positive and negative marker set. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::finite_route_only_restart_forwards_age_and_rejects_expiry_and_clock_loss` (11.929) | Route-only restart forwards age, rejects expired data and clock loss, and preserves exact durable state. | Use the controllable test clock and minimum TTL/payload; remove elapsed-time waiting while preserving restart assertions. | None. | [ ] Pending hosted verification |
| 2 | `asterctl::cli::stalled_agent_is_bounded_by_the_request_deadline` (11.012) | A stalled agent is aborted at the requested CLI deadline with the exact error and no retry. | Pass `--timeout=1` in the fixture and separately assert the unchanged production default. | None. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::blob_ranges_stream_saturated_six_mutable_directions` (10.487) | Six mutable directions saturate, preserve exact per-direction progress, avoid starvation, and eventually settle. | Use the smallest direction/capacity matrix that proves scheduling and split independent direction classes if needed. | Preserve a six-direction workload as an explicit benchmark only if it provides useful scheduler evidence. | [ ] Pending hosted verification |
| 2 | `aster-node::runtime::tests::blob_source_carrier_reopen_resumes_exact_complement_from_different_peer` (10.415) | Reopen retains prefix, requests only the complement from another peer, verifies digest, and settles once. | Use the minimum multi-chunk Blob and two peers required to exercise exact complement resumption. | None. | [ ] Pending hosted verification |
| 2 | `asterctl::operation_key::timeouts_preserve_the_generated_key_without_retrying` (10.013) | Timeout retains the generated operation key, performs no retry, and reports the exact failure. | Inject a short private request timeout and a deterministically stalled server; assert the production default separately. | None. | [ ] Pending hosted verification |

## Completion rule

Tasks 3–10 must update the implementation without weakening the mapped default
assertions. Task 11 remeasures the complete population and replaces each final
duration checkbox with hosted evidence. A row still above 10 seconds remains a
visible optimization problem; it does not become an execution gate.
