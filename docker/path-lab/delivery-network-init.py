#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Apply one fixed endpoint route inside a shared container network namespace."""

from __future__ import annotations

import sys
from aster_path_delivery import _run_command, _strict_json, ExecutionError


def commands(role: str, count: int = 2) -> list[list[str]]:
    if not 2 <= count <= 20 or role not in tuple(f"node-{chr(97 + i)}" for i in range(count)):
        raise ValueError("unsupported network role")
    local = ord(role[-1]) - 96
    remote = 2 if local == 1 else 1
    return [
        ["ip", "address", "add", f"10.77.{local}.2/29", "dev", "eth0"],
        ["ip", "link", "set", "dev", "eth0", "up"],
        ["ip", "route", "replace", f"10.77.{remote}.0/29", "via", f"10.77.{local}.1"],
        ["ip", "route", "replace", "default", "via", f"10.77.{local}.1"],
    ]


def configure(role: str, run=_run_command, count: int = 2) -> None:
    for operation in commands(role, count):
        run(operation, 5)
    local = ord(role[-1]) - 96
    remote = 2 if local == 1 else 1
    rows = _strict_json(run(["ip", "-j", "route", "get", f"10.77.{remote}.2"], 5), "route")
    if (not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get("dev") != "eth0"
            or rows[0].get("gateway") != f"10.77.{local}.1"
            or rows[0].get("prefsrc") != f"10.77.{local}.2"):
        raise ExecutionError("route-readback")


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print("delivery-network-init: exactly one role is required", file=sys.stderr)
        return 2
    try:
        configure(argv[0], count=int(argv[1]) if len(argv) == 2 else 2)
    except (ValueError, OSError, ExecutionError):
        print("delivery-network-init: fixed network setup failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
