# Numbered-only Event publication switchover

> Clean Room — Privileged

- Initial baseline: refreshed `origin/main` at `23be27e`
- Rebased baseline: `origin/main` at `f4f93c6` (PR #52), 2026-10-09
- Branch: `feature/numbered-publication-switchover`
- Outcome: one numbered application-publication model, retaining native HTTP/2
  pipelining, shared durable commits, bounded retry/backpressure, finite Event
  custody, and the current semantic-v7 source/transfer behavior.
- Alignment: P1-1 bounded data lifecycle and P1 offline-first Event exchange.
- Status: complete; final repository verification passed. Application RPCs and normal native APIs expose only numbered
  publication. CLI, playground, demos, examples, Go acceptance producers,
  deployment tools and lab producers retain complete publication journals.
  Historical fixture writers are explicitly unavailable in normal node builds.

## Current baseline and scope

PR #54 merged ordinary publication pipelining at `1a356b5`. PR #53 merged
semantic-v7 receipt-free Event pages and custody authority integration in the
initial baseline. PR #52 adds the Compose credential provider and its status
metadata in the rebased baseline. Subscription listing, unsubscribe, query upper-bound,
bounded custody maintenance, and send-authorization changes are also present.
The earlier ownership-plan branch belongs to old history and is not a merge
base for this work. Preserve current content and retained historical receipts.

This is completion of the publication-model transition before Increment 2.
It does not add session ownership to subscription/delivery mutations, client
retirement, lost-journal recovery, or identity reclamation. It does not change
State/Record/Blob operation models or mesh source identity, causality, content
cryptography, reconciliation version, or carrier semantics.

There are no released consumers requiring compatibility with ordinary
publication. Remove the supported arbitrary-key Event publication path instead
of retaining a shim that maps keys to sequences or to permanent client IDs.
The latter would reintroduce unbounded history or exhaust client capacity.
Reject incompatible legacy publication stores without deleting or silently
migrating their contents, and document fresh-state initialization.

## Capabilities to preserve

- Native HTTP/2 bidirectional publication with ordered per-input outcomes,
  bounded in-flight windows, disconnect retry, and healthy session rotation.
- Unary publication and browser concurrent-unary fallback, subject to ordered
  first admission within each numbered client.
- Actor collection of already-admitted adjacent compatible work, bounded
  fairness, no artificial batching delay, Flash singleton behavior, and
  finite/durable cohort separation.
- One writer commit for a successful compatible cohort; custody continuity,
  TTL result retirement, result records, source counters, and recovery frontier
  commit consistently. Count writer commits that occur before an error.
- Exact retry and conflict detection while a result is retained; permanent
  rejection after acknowledgement compacts it. Preserve
  `Committed + Retired(reason)` after content expires.
- Independent synchronization following local durable admission, shutdown and
  zeroization boundaries, current policy/revocation checks, response bounds,
  capacity accounting, and source-route cache maintenance.

## Numbered pipeline semantics

The SDK journals complete intents and assigned sequences before transmission
and durably records committed results before exposing them. Transport failure
never means abandonment: replay the same client, session, sequence, and intent,
then reconcile with the agent after process restart. Stream reconnection alone
must not claim a new client session.

The server admits new operations only at `allocated_through + 1`. Therefore a
known precommit failure at N blocks later first admission for that same client
until N is repaired or explicitly abandoned. Failures for one client must not
block another client's valid first admission. Never advance the frontier merely
because a request was rejected or a stream disconnected.

Current SDK policy: preserve rejected work for explicit repair or abandonment.
The journal-backed pipeline stops at the first rejected response without
advancing its frontier or deleting that intent. An opt-in abandon-and-continue
policy remains a separate product choice; it is not required for the numbered
model transition. Ambiguous transport or postcommit failure always requires
recovery rather than abandonment. A failure-isolation claim must state this
per-client sequence boundary.

The three considered policies, their tradeoffs and implementation status are
recorded in [Decision 0044's rejection-policy alternatives](../../decisions/0044-pipeline-durable-event-publication.md#rejected-numbered-publication-options-and-chosen-policy).
SDK abandon-and-continue remains a possible opt-in policy; durable server-side
terminal rejection was considered but is not implemented. The future PR should
link that decision rather than serve as its only record.

Bound first-admission ordering in the SDK and service rather than depending on
response ordering alone. If later inputs arrive ahead of an unresolved earlier
input, return a sequence-gap outcome without mutation and retry only after the
frontier is resolved. Multi-client results remain paired with their original
inputs. A failure for an already committed operation must not be reported as
proof of noncommit.

## Implementation stages

1. **Grouped numbered durable authority.** Add numbered prepared-cohort commits
   sharing current reservations, verified Events, policy/custody guards, and
   stage logic. Validate session, sequence, intent, capacity, and recovery inside
   the writer. On cohort failure, roll back before ordered singleton isolation.
   Route admitted numbered actor work through that path and retain exact writer
   diagnostics. This foundation is implemented and committed.
2. **Numbered stream and durable SDK.** Carry numbered request/receipt types
   through the existing pipeline. Journal windows and responses transactionally;
   pair every response with its sequence; handle partial/lost responses without
   duplicate publication. Define the explicit rejection/abandonment policy.
   Keep reconnects within a process session and process recovery fenced.
3. **Application-facing caller transition.** Move CLI publication, Rust/Go
   examples, Atlas/Beacon/Cove controller, native node demos, agent acceptance
   clients, telemetry/path/Compose tools, and their fixtures to durable client
   sequences. Give each application a stable bounded identity and surviving
   journal. Distinguish application-journal recovery from node restart. Keep
   simple demo commands; do not expose session management to demo users.
4. **Legacy removal and store boundary.** Remove ordinary application RPCs,
   pipeline types, public native methods, arbitrary-key Event admission, and
   active legacy mode/counters. Retain only what is necessary to diagnose/refuse
   incompatible existing stores and preserve historical evidence. Search every
   live caller, generated client, example, CLI help/manpage, capacity report,
   and protocol document; do not relabel old evidence as numbered execution.
5. **Verification and evidence.** Run failure-path tests, full checks and fuzz,
   then update current documentation and exact requirement trace only where its
   claim boundary genuinely changes. No production or physical performance
   credit follows from retaining the old pipeline's source mechanisms.

## Required regression matrix

- Same-client contiguous cohort: one durable writer, original ordered receipts,
  frontier/result/reverse/accounting consistency, exact replay without writes.
- Failed/gapped or conflicting sibling: no partially committed cohort; ordered
  fallback; later same-client gap remains explicit; other clients remain usable.
- Takeover before or during commit: fenced mutations never advance source or
  client counters, and committed work remains recoverable by the successor.
- Lost stream result, partial session, healthy rotation, dropped HTTP/2 stream,
  process replacement, and journal fsync/commit failure.
- Durable/finite cohorts, TTL cleanup before result acknowledgement, retirement
  under an active transfer lease, custody continuity transitions, and Flash.
- Capacity saturation, exact snapshot/response bounds, result acknowledgement
  while an older operation remains outstanding, and count/byte headroom reuse.
- Source authorization failure, revoke/rekey/policy races, mixed-client and
  interleaved non-publication actor commands, shutdown and zeroization.
- Missing/corrupt journal, incompatible legacy store refusal without mutation,
  all public entry points numbered-only, CLI/demo restart and smoke acceptance.

Implemented regressions cover contiguous one-writer admission, exact replay,
rollback before gap fallback, stale-session isolation, lost and partial stream
responses, rotation/backpressure, journal persistence failures, and native/CLI/
Go/application restart. Legacy startup refusal checks all historical tables and
preserves original bytes, including unclean stores requiring allocator repair.
A private disposable copy supplies crash preflight inspection; both normal
startup checks and the acquired-writer check remain in place.

Historical Event, custody and NAT receipt validators remain frozen under
`tools/historical`. Current numbered executions use v2 evidence schemas without
relabeling retained v1 receipts. The shared state-subscription checker retains
its original exact inventory and empty-stderr boundary. No requirements IDs or
hash-bound baseline were changed, and no physical-host or performance credit is
added.

Initial verification: strict workspace Clippy and strict normal node/store Clippy
passed. All 1,724 workspace tests passed, with two platform skips; documentation
tests passed. Fuzz smoke passed all seven macOS-supported targets at 10,000 runs
each; two systemd targets require Linux. The migrated Connect shell example
passed explicit initialization and journal reopening against a real agent.
`mise run check` passed in full, including real three-node playground and hello
sessions; Go SIGKILL/restart, exact replay, conflict, acknowledgement and bounded
load journal reopening; bindings, conformance, 202 lab tests and regenerated
Go checks. Requirements trace validation passed: 348 baseline IDs and 137 exact
selected mappings.

The separate customer-agent process smoke gate
cannot execute with this macOS Python: `os.POSIX_SPAWN_CLOSEFROM` is unavailable.
The process-launch safety requirement is retained. Linux custody/NAT/packaged
qualification has not been performed.

Final gates: `mise run check`, `mise run fuzz-smoke`, generated proto/Go checks,
applicable real-process smoke tests, and
`python3 tools/check-implementation-requirements.py` when traceability changes.
Preserve the hash-bound baseline and historical manifests/receipts.

## Rebase onto PR #52 — 2026-10-09

All 22 switchover commits were replayed onto `f4f93c6`; range comparison preserved
their changes. Binary descriptor conflicts were resolved by regenerating the
combined schema and Go clients, preserving credential-generation status and
numbered-only publication. Configuration, credential loading, runtime provider
composition and Compose deployment files from PR #52 remain incorporated.

Verification exposed two existing portability issues in the newly merged code.
Test and non-secret example-plan temporary paths now resolve their macOS aliases
before passing canonical-path validation. Linux-only credential helpers and
test fixtures compile only on Linux; public unsupported-platform behavior stays
available elsewhere. Production path and credential checks were not relaxed,
and Linux behavior is unchanged by these platform gates.

Post-rebase verification passed: `mise run check` in full, including strict
workspace Clippy, 1,755 passing workspace tests (two platform skips),
documentation tests, real playground/hello sessions, Go SIGKILL/restart and
journal reopening, bindings/conformance, lab tests and reproducible generated
clients. All seven supported fuzz targets passed 10,000 runs each; two systemd
targets still require Linux. Requirements trace validation passed with the
upstream PR #52 additions: 348 baseline IDs and 140 exact selected mappings.
The earlier Linux process/physical qualification limitations still apply.

## 2026-10-16 current-main integration

Merged `main` through `fcf9f1b054f9623b61435659994fad0bc6c51779` into the
existing PR history. Preserved the upstream Blob lifecycle, pressure, streaming,
agent/CLI, dependency and CI-policy changes beside numbered-only Event
publication. Regenerated the combined schema descriptor and Go clients.

The numbered store-open path now carries explicit Blob lifecycle and lease
limits without bypassing legacy-publication preflight or writer refusal. The
numbered coalescing dispatcher uses the current Blob worker admission wrapper.
Regression coverage checks byte-preserving legacy refusal through that new
open path, combined agent numbered publication before unsupported Blob upload,
and rejection of mixed Blob/journal CLI commands. The real CLI smoke retains
numbered publication/retry and Linux-only Blob file checks. Linux-only upstream
test helpers are gated for strict macOS linting.

Verification on macOS passed: `mise run check`, with strict workspace Clippy,
2,155 passing workspace tests (two platform skips), documentation tests, real
playground/hello sessions, Go process-restart/exact-retry/conflict/acknowledgement/
bounded-load journal recovery, bindings, conformance, 203 lab tests, and
reproducible generated Go clients. The separate real-agent CLI smoke also passed.
Fuzz smoke passed seven supported targets at 10,000 runs each; the two systemd
admin/backup targets require Linux. Requirements trace validation passed with
348 baseline IDs and 140 exact selected mappings, preserving upstream evidence
changes. This integration adds no physical, Linux deployment, or production
qualification and changes no requirement evidence boundary of its own.

## 2026-10-19 rewritten-main migration

The rewritten `main` at `4e9df921f03dff2df069a34d676b2a16500d6b74`
has the same complete file tree as the prior `fcf9f1b` base:
`c0a306a40c902709cc81bc65b5f1ebd2558efa87`. The original PR base
`f4f93c6` remains an ancestor, so all 28 signed PR commits can be retained
without replay or replacement. Replacement merge `4524646` uses the rewritten
`main` as its second parent and preserves exactly the previously tested
`4eec24b` result tree, `6b0c42c9d8c5ee441a3a46fed18dc26118ec0aa0`.
None of the three unsigned commits rejected during the earlier push is an
ancestor of this replacement. All 106 inherited main commits newly reachable
from the PR head carry signatures.

This migration changes ancestry only. The full October 16 validation above,
including 2,155 passing workspace tests, real-agent CLI smoke, and seven fuzz
campaigns, applies to the identical implementation tree; it is not a new
execution or qualification claim. Historical source IDs, frozen receipts,
and requirement evidence boundaries remain intact. The October 19 `mise run check-foundation` gate passed on the migrated
checkout: formatting, schemas, requirements trace (348 baseline IDs and 140
exact selected mappings), retained receipts, policy, tool regressions, and
dependency boundaries. The replacement merge signature also verifies locally.

## 2026-10-19 Rust SDK journal bounds (P1)

Bounded SDK maintenance now limits each Rust publication journal to eight
retained entries and a 1 MiB logical serialized-state budget. Pending intents
and committed results awaiting acknowledgement both occupy slots. Accounting
includes metadata and entry keys, serialized intents/results, a 1,024-byte
result reserve per row, and worst-case claim/counter metadata. Every mutation
checks the complete post-update image inside the redb write transaction;
capacity rejection preserves the sequence frontier and retained rows.
Acknowledgement and confirmed removal reclaim capacity. Opening checks the
same limits before marking recovery incomplete, and individual JSON
encoding/decoding and recovery snapshots have bounded sizes. The logical
budget does not cap redb's physical file size or allocator overhead.

The SDK and CLI reject payloads above 65,536 bytes, matching the Go journal.
CLI preflight rejects oversized stdin before contacting the agent or assigning
an operation. Its complete encoded-request guard remains 1 MiB. The real
Connect/gRPC integration test sends the same 17 operations in retained batches
of eight, eight, and one, acknowledging each batch before assigning the next.
The independent eight-request network window and server/wire semantics retain
their existing boundaries.

Validation passed on macOS: 32 focused SDK tests, 11 CLI publication tests,
the real-agent restart/pipeline test, and `mise run check` in full. The complete
gate passed strict workspace Clippy, 2,161 workspace tests (two platform skips),
documentation, real playground/hello sessions, Go journal restart/exact-retry/
conflict/acknowledgement/bounded-load checks, bindings, conformance, 203 lab
tests, and generated-client reproduction. Seven supported codec fuzz targets
passed 10,000 runs each; the systemd admin/backup targets require Linux. SDK
journal and CLI boundaries are covered by deterministic regressions, including
exact-cap/cap-plus-one admission, concurrent last-slot admission, sequence/row
preservation, full-budget receipt/recovery/retirement, acknowledgement reuse,
and oversized saved metadata, rows, payloads, and entry counts.

This maintenance adds no requirement status, retained target observation,
physical performance, Linux deployment, or production qualification credit.

## 2026-10-19 Rust SDK initialization parent sync (P2)

Rust SDK journal initialization now synchronizes the parent directory after
committing the initial redb transaction with immediate durability, matching the
Go and native journal behavior. Parent open/sync errors propagate without
removing or replacing the initialized journal. Bare filenames use the current
directory. Parent lookup remains pathname-based; retaining the directory handle
used for creation against concurrent renames or path replacement is separate
hardening tracked in [issue #111](https://github.com/defenseunicorns/aster/issues/111).

Validation passed on macOS: all 35 SDK tests, including three new regressions
for committed initial state before the sync boundary, parent-sync failure with
retained/reopenable state, and bare-filename initialization. The complete
`mise run check` gate passed strict Clippy, 2,164 workspace tests (two platform
skips), documentation, real-client smoke checks, conformance, 203 lab tests,
bindings, and generated-client reproduction. No parser, framing, or envelope
behavior changed, so the P1 fuzz campaigns above were not rerun for this fix.
This maintenance adds no requirement-status or physical power-loss
qualification credit.

## 2026-10-19 Restore real pipeline window-refill coverage

The earlier P1 adaptation split 17 operations into eight/eight/one retained
batches and did not preserve refill coverage within one invocation. The real
Connect and gRPC integration now retains eight entries and uses the opt-in
`sdk-test-support` feature to lower only that test's network window to four.
Observations from the transport loop must show one stream, eight successful
sends, a maximum of four in flight, and multiple send batches. All results are
checked in order, acknowledged, and verified absent after reopen/recovery.
The production entry point still uses eight in flight, and journals still
retain at most eight entries. Test windows outside one through eight fail
before transport or journal mutation. Test configuration and observations are
absent without the explicit test-support feature.

Focused verification passed for both wire protocols with test support enabled
and with the production window; all 36 SDK tests passed. These are automated
same-implementation checks and add no physical performance or qualification
credit. The scheduling-test concern remains outside this follow-up.
