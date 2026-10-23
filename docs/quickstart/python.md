# Python quickstart

The Python package is a small, typed `ctypes` wrapper around Aster's native C
ABI. Protocol, storage, and cryptography still run in the Rust library; the
binding does not reimplement them.

**Time:** about five minutes after the Rust toolchain is installed.

## Prerequisites

- A checkout of this repository
- The [shared Rust toolchain prerequisite](README.md#shared-toolchain-prerequisite)
- Python 3

No third-party Python package is required.

## Build the native library

From the repository root:

```sh
cargo build -p aster-ffi
```

The binding automatically looks in this checkout's `target/debug` and
`target/release` directories. If you install the library elsewhere, set
`ASTER_MESH_LIBRARY` to its complete path:

| Platform | Library name |
|---|---|
| Linux | `libaster_ffi.so` |
| macOS | `libaster_ffi.dylib` |
| Windows | `aster_ffi.dll` |

## Run the example

```sh
PYTHONPATH="$PWD/bindings/python" \
  python3 examples/python_basic.py --database /tmp/aster-python-example.db
```

The output contains a stable ItemID and the decoded payload:

```text
item=<64 hexadecimal characters> payload={"lat":38.9,"lon":-77.0}
```

The example uses the checked-in disposable bundle by default. Override it with
`--bundle /path/to/provisioning.bundle`.

Read the fully commented source in
[`examples/python_basic.py`](../../examples/python_basic.py).

## What the important lines mean

```python
with Node(str(database), provisioning) as node:
```

`Node` owns native resources and durable local state. The context manager closes
the native handle; it does not delete the database.

```python
result = node.publish(
    DataClass.STATE,
    "position.current",
    "mission/team/alpha",
    payload,
    logical_key=b"unit-7",
)
```

The call succeeds while offline. The publish result proves a local durable
commit. The logical key says which entity this State value describes.

```python
delivery = subscription.poll(limit=1)[0]
subscription.acknowledge(delivery)
```

Subscriptions are durable and at-least-once. Acknowledge only after application
processing succeeds.

## Use the package from another checkout

Until packaging is added, put `bindings/python` on `PYTHONPATH` or copy/install
the `aster_mesh` package through your build system. Always load the native
library built from the same source revision as the binding.

The Python surface exposes high-level application concepts only. It never
returns keys, credentials, sealed envelopes, provider handles, fragments, or
transport controls.

## Replace the test fixture

`bindings/testdata/non-production-provisioning.bundle` is public test material,
not an operational trust anchor. `Node` currently ingests the unprotected inner
bundle for compatibility and tests, and the Python binding has no protected-
provider entry point. It therefore does not yet satisfy operational
provisioning custody. A real integration needs a unique protected artifact,
persistent secret custody/recovery, and durable database storage; do not
represent the raw path as protected. See the
[protected-provisioning decision](../decisions/0013-protected-provisioning-boundary.md).

The fixture's grants and regeneration procedure are documented in
[Non-production binding test material](../../bindings/testdata/README.md).

## Next steps

- See [Core concepts](../concepts.md) for queries, conflicts, batches, streamed
  Blobs, bridges, and rekeying.
- Read the [Python binding reference](../../bindings/python/README.md).
- This binding exposes the offline reference application surface. For live
  synchronization, see the [local agent quickstart](connect-agent.md),
  [selected implementation boundary](../../README.md#current-implementation-boundary),
  and [Carriers and contacts](../transports.md).
- Run the binding tests:

  ```sh
  cargo build -p aster-ffi
  python3 -m unittest discover -s bindings/python/tests
  ```
