#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Start one nonroot, capability-free endpoint agent with one fixed peer."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys

STATE = Path("/clab/state")
PEER = re.compile(r"[0-9a-f]{64}@10\.77\.([1-9]|1[0-9]|20)\.2:4433=[0-9a-f]{64}")


def agent_argv(role: str, state: Path = Path("/clab/state")) -> list[str]:
    addresses = {f"node-{chr(97 + i)}": f"10.77.{i + 1}.2:4433" for i in range(20)}
    if role not in addresses:
        raise ValueError("unsupported agent role")
    try:
        raw = bounded_text(state / "peer", 4000)
        peers = raw.splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("peer configuration is unavailable") from error
    if not 1 <= len(peers) <= 19 or any(PEER.fullmatch(peer) is None for peer in peers):
        raise ValueError("peer configuration is malformed")
    segments = [int(PEER.fullmatch(peer).group(1)) for peer in peers]
    local = ord(role[-1]) - 96
    if set(segments) != set(range(1, len(peers) + 2)) - {local} or len(set(segments)) != len(peers):
        raise ValueError("peer configuration targets the wrong endpoint")
    storage = []
    items = os.environ.get('ASTER_DIAGNOSTIC_STORAGE_ITEMS')
    size = os.environ.get('ASTER_DIAGNOSTIC_STORAGE_BYTES')
    if items is not None or size is not None:
        if (items is None or size is None or re.fullmatch(r'[0-9]{1,7}', items) is None
                or re.fullmatch(r'[0-9]{1,10}', size) is None
                or not 4161 <= int(items) <= 1000000 or not 67108864 <= int(size) <= 4294967296):
            raise ValueError('invalid diagnostic storage limits')
        storage = ['--storage-max-items', items, '--storage-max-payload-bytes', size]
    return [
        "/usr/local/bin/aster-agent",
        "--state", str(state),
        "--mesh-bind", addresses[role],
        "--listen", "127.0.0.1:8181",
        "--mission-bundle-unprotected-reference", str(state / "mission.unprotected-reference.bundle"),
        "--client-token-file", str(state / "client.token"),
        *[arg for peer in peers for arg in ("--peer", peer)],
        "--sync-ms", "250",
        *storage,
    ]


def validate_privileges(text: str) -> None:
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    expected = {"Uid": ["10001"] * 4, "Gid": ["10001"] * 4, "NoNewPrivs": ["1"]}
    expected.update({key: ["0000000000000000"] for key in
                     ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")})
    if any(fields.get(key, "").split() != value for key, value in expected.items()):
        raise ValueError("privilege-mismatch")


def bounded_text(path: Path, limit: int) -> str:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file-oversized")
    return raw.decode("ascii")


def verify_live(role: str, proc: Path = Path("/proc"), state: Path = Path("/clab/state")) -> None:
    validate_privileges(bounded_text(proc / "1/status", 8192))
    if role == "wan":
        return
    if re.fullmatch(r"node-[a-t]", role) is None:
        raise ValueError("role-invalid")
    pid = bounded_text(state / "agent.pid", 16)
    if re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None:
        raise ValueError("agent-pid")
    text = bounded_text(proc / pid / "status", 8192)
    if "Name:\taster-agent\n" not in text:
        raise ValueError("agent-process")
    validate_privileges(text)


def main(argv: list[str]) -> int:
    if os.getuid() != 10001 or os.getgid() != 10001:
        print("delivery-agent: fixed nonroot role is required", file=sys.stderr)
        return 2
    try:
        if len(argv) == 2 and argv[0] == "verify":
            verify_live(argv[1])
            print("CAPABILITIES status=pass")
            return 0
        if len(argv) != 1:
            raise ValueError("role-invalid")
        command = agent_argv(argv[0], STATE)
        os.umask(0o077)
        (STATE / "agent.pid").write_text(str(os.getpid()), encoding="ascii")
        os.execv("/usr/local/bin/aster-agent", command)
    except (OSError, ValueError):
        print("delivery-agent: startup failed", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
