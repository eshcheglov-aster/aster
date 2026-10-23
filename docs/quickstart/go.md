# Go quickstart

The Go module is a first-class cgo wrapper over Aster's native C ABI. Protocol,
storage, and cryptography remain in the Rust library.

**Time:** about ten minutes after Rust, Go, and a C toolchain are installed.

## Prerequisites

- A checkout of this repository
- The [shared Rust toolchain prerequisite](README.md#shared-toolchain-prerequisite)
- Go 1.26
- A C compiler supported by cgo

## Build the native library

From the repository root:

```sh
cargo build -p aster-ffi
```

For a source checkout, the `aster_workspace` build tag supplies the repository
library path and runtime search path:

```sh
go -C bindings/go run -tags aster_workspace ../../examples/go_basic.go ../testdata/non-production-provisioning.bundle /tmp/aster-go-example.db
```

For an installed native library, omit the build tag and provide the appropriate
build-time and runtime paths instead:

```sh
CGO_LDFLAGS="-L/path/to/lib" \
LD_LIBRARY_PATH="/path/to/lib" \
DYLD_LIBRARY_PATH="/path/to/lib" \
  go -C bindings/go run ../../examples/go_basic.go \
  ../testdata/non-production-provisioning.bundle \
  /tmp/aster-go-example.db
```

`LD_LIBRARY_PATH` is used on Linux and `DYLD_LIBRARY_PATH` on macOS.

The output contains a stable ItemID and the payload:

```text
item=<64 hexadecimal characters> payload={"lat":38.9,"lon":-77.0}
```

Read the fully commented source in
[`examples/go_basic.go`](../../examples/go_basic.go).

## What the important lines mean

```go
node, err := aster.Open(databasePath, provisioningBundle)
defer node.Close()
```

The node owns a native handle and durable local state. Close it explicitly;
finalizers are only a leak backstop.

```go
result, err := node.Publish(
    aster.State,
    "position.current",
    "mission/team/alpha",
    payload,
    aster.PublishOptions{LogicalKey: []byte("unit-7")},
)
```

This commits offline. A publish result does not imply that a remote peer has
received the item.

```go
deliveries, err := subscription.Poll(1)
err = subscription.Acknowledge(deliveries[0].Item.ItemID)
```

Poll delivers at least once. Acknowledge only after your application commits its
own work.

## Add Aster to a Go application

The module path is `defenseunicorns.com/aster/mesh`. During source integration,
use a `replace` directive that points to this checkout's `bindings/go` directory,
and arrange for the matching native library and C header to be available to the
build.

The wrapper is safe for concurrent method calls by serializing calls through one
coarse node mutex, and it copies native outputs into Go-owned values. It
intentionally exposes no transport selection, cryptographic provider, keys,
sealed objects, or sync frames.

## Go naming and option notes

- Import `defenseunicorns.com/aster/mesh` with the alias `aster`; the module path
  ends in `mesh`, but the package name is `aster`.
- The message-priority constant is `aster.PriorityMsg` because `Priority` names
  the type.
- `aster.PublishOptions.Tombstone` publishes a deletion marker for State or
  Record data. Tombstone retention is bounded; see [Core
  concepts](../concepts.md#deletion-with-tombstones).

## Replace the test fixture

The example bundle is public and disposable. `aster.Open` currently ingests the
unprotected inner bundle for compatibility and tests, and the Go binding has no
protected-provider entry point. It therefore does not yet satisfy operational
provisioning custody. A real deployment needs a unique artifact per node, an
admitted protection provider, persistent secret custody/recovery, and durable
counter state; do not represent the raw path as protected. See the
[protected-provisioning decision](../decisions/0013-protected-provisioning-boundary.md).

The fixture's grants and regeneration procedure are documented in
[Non-production binding test material](../../bindings/testdata/README.md).

## Next steps

- Read [Core concepts](../concepts.md) before choosing other data classes.
- Read the [Go binding reference](../../bindings/go/README.md).
- This binding exposes the offline reference application surface. For live
  synchronization, see the [local agent quickstart](connect-agent.md),
  [selected implementation boundary](../../README.md#current-implementation-boundary),
  and [Carriers and contacts](../transports.md).
- Run the binding tests:

  ```sh
  cargo build -p aster-ffi
  GOCACHE=/tmp/aster-mesh-go-cache \
    go -C bindings/go test -tags aster_workspace ./...
  ```
