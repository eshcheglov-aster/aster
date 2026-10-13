# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Rust `BlobPublishOptions` and live/stopped `publish_with_options`, preserving
  durable `publish` calls. Publish/read results and Blob deliveries expose the
  original optional TTL. Zero is invalid; positive TTL is explicitly unsupported
  before source I/O or mutation until end-to-end finite Blob support lands.
  This does not change protobuf, RPC, CLI, storage, or wire semantics.

- Optional `before_acceptance_marker` filter for `QueryEvents` RPC call
- `asterctl unsubscribe` command to remove an Event subscription by ID.
- subsriptions option for asterctl to get Event subscriptions list
- `ListEventSubscriptions` RPC to list the node's Event subscriptions with their IDs, operation keys, and topic/scope filters.
- `asterctl` CLI utility.
- Local delivery and transfer status for State, Record, and Blob operations.
- Numbered Event publication with durable operation tracking and crash-safe recovery.
- Separately bounded, non-evictable Blob physical-lineage and publication-replay
  fences; typed publication/pending-source variant references; and exact
  lifecycle accounting with audit-first atomic predecessor migration.
- Persistent six-class Blob maintenance discovery with independently nonzero
  row/file/byte budgets, durable fair cursors, and automatic bounded startup and
  periodic background turns. This does not activate finite Blob TTL.
- Bounded Blob pressure recovery for the exact rejected publication,
  network-staging, or depot partition. It evicts only strictly lower-priority
  work in deterministic incomplete-before-completed order, then expiry class
  and finite deadline, exact completion fraction, acceptance order, and exact
  identity, and never skips an oversized first
  atomic candidate, reconciles local caches, and retries admission once.
  Deletion remains manifest-backed and resumable, with depot capacity charged
  until physical finalization. Finite Blob TTL remains inactive. Blob wire
  bytes, supported public Blob API, and CLI behavior are unchanged.

### Changed

- Upgrade dependencies: Iroh 1.3.0 (public DNS disabled)
- Reduced CI turnaround with Rust compiler caching and partitioned nextest runs.
- Prefiltered Event query candidates before authentication to avoid unnecessary verification work.
- Aligned the wire and envelope contract with semantic protocol version 6.
- Bounded indexed Event-custody expiry and retirement to a resumable 1,024-dependency-unit cleanup pass. Pressure eviction still scans all retained custody rows while keeping at most 1,024 candidates in scratch memory. New local and selected-reconciliation Events schedule coalesced prompt contact attempts, with failed attempts falling back to periodic retry; bridge propagation is unchanged. Custody schema v1/v2 stores require recreation, and the supporting measurements are current-code engineering evidence rather than target qualification.
- Reused custody authorization decisions within each send attempt.
- Continued accumulating only provable monotonic custody intervals after exact
  clock-continuity loss. Finite Event/RouteEvent rows remain withheld below TTL,
  re-anchor through the existing bounded expiration index across restarts, and
  expire once their conservative lower bound reaches TTL. The change is
  wire-neutral; finite Blob TTL and expiry remain separate follow-up work.
- Made local Blob admission, network staging, publication promotion, and pending
  abort transactionally update their lifecycle fences, typed roots, counters,
  and ordinary visibility without changing semantic-v5 wire bytes or public
  application behavior.

### Security

- Created Unix publication journals with owner-only permissions and rejected insecure existing journal files.

- Restricted `asterctl` plaintext RPC to loopback addresses before credential or payload loading.

- Hardened inbound handshakes and health admission against resource exhaustion.
