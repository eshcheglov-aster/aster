# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional `before_acceptance_marker` filter for `QueryEvents` RPC call
- `asterctl unsubscribe` command to remove an Event subscription by ID.
- subsriptions option for asterctl to get Event subscriptions list
- `ListEventSubscriptions` RPC to list the node's Event subscriptions with their IDs, operation keys, and topic/scope filters.
- `asterctl` CLI utility.
- Local delivery and transfer status for State, Record, and Blob operations.
- Numbered Event publication with durable operation tracking and crash-safe recovery.

### Changed

- Upgrade dependencies: Iroh 1.3.0 (public DNS disabled)
- Reduced CI turnaround with Rust compiler caching and partitioned nextest runs.
- Prefiltered Event query candidates before authentication to avoid unnecessary verification work.
- Aligned the wire and envelope contract with semantic protocol version 6.
- Bounded indexed Event-custody expiry and retirement to a resumable 1,024-dependency-unit cleanup pass. Pressure eviction still scans all retained custody rows while keeping at most 1,024 candidates in scratch memory. New local and selected-reconciliation Events schedule coalesced prompt contact attempts, with failed attempts falling back to periodic retry; bridge propagation is unchanged. Custody schema v1/v2 stores require recreation, and the supporting measurements are current-code engineering evidence rather than target qualification.
- Reused custody authorization decisions within each send attempt.

### Fixed

- Avoided serial transport-ACK waits between intermediate Blob responses while retaining bounded delivery tracking and final-response completion.
- Withheld benchmark summaries when the final source or binary identity changes.

### Security

- Created Unix publication journals with owner-only permissions and rejected insecure existing journal files.

- Restricted `asterctl` plaintext RPC to loopback addresses before credential or payload loading.

- Hardened inbound handshakes and health admission against resource exhaustion.
