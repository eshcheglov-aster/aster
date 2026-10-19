#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the implemented and normative semantic-version registries aligned."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = tuple(range(1, 10))
DEFAULT_OFFER = tuple(reversed(VERSIONS))
PROTOCOL_ROWS = {
    1: ("—", "stable Event and Blob-chunk transfer"),
    2: ("v1", "compact batch and bridge objects"),
    3: ("v2", "session custody record"),
    4: ("v3", "State and Record reconciliation"),
    5: ("v4", "historical direct Blob frame allocation"),
    6: ("v5 ordinary lanes byte-for-byte", "Event bridge transfer"),
    7: (
        "v6 byte-for-byte",
        "per-lane profiles, receipt-free Event pages, and durable Blob range streams",
    ),
    8: (
        "v7 byte-for-byte except the lane AAD domain and Blob custody fields",
        "authenticated finite Blob custody over `BlobRangesStreamV1`",
    ),
    9: (
        "v8 stable object and ordinary-lane bytes",
        "`BlobStreamV1` profile identity and reserved stream-record tags; runtime activation is separately gated",
    ),
}
CDDL_ALIASES = {
    1: "1 / 2",
    2: "semantic-v1-object-kind / 3 / 4 / 5",
    3: "semantic-v2-object-kind",
    4: "semantic-v3-object-kind",
    5: "semantic-v4-object-kind",
    6: "semantic-v5-object-kind",
    7: "semantic-v6-object-kind",
    8: "semantic-v7-object-kind",
    9: "semantic-v8-object-kind",
}
PROTOCOL_DEFAULT_OFFER_PATTERNS = (
    r"default semantic offer is\s*`\[([^\]]+)\]`",
    r"default descending offer is\s*`\[([^\]]+)\]`",
    r"default initiator offers\s+semantic versions\s*`\[([^\]]+)\]`",
)


class ContractViolation(ValueError):
    """A normative semantic-version declaration drifted from implementation."""


def fail(message: str) -> None:
    raise ContractViolation(message)


def require_version_sequence(
    text: str, pattern: str, expected: tuple[int, ...], label: str
) -> None:
    matches = re.findall(pattern, text, re.DOTALL)
    if len(matches) != 1:
        fail(f"{label} declaration must occur exactly once; found {len(matches)}")
    actual = tuple(int(version) for version in re.findall(r"\d+", matches[0]))
    if actual != expected:
        fail(f"{label} must be {expected}; found {actual}")


def parse_implementation(core: str) -> None:
    declarations = re.findall(
        r"^pub\(crate\) const SEMANTIC_PROTOCOL_V(\d+): u16 = (\d+);$",
        core,
        re.MULTILINE,
    )
    actual_versions = tuple(sorted(int(name) for name, _ in declarations))
    expected_versions = VERSIONS
    mismatched = [
        int(name) for name, value in declarations if int(name) != int(value)
    ]
    if actual_versions != expected_versions or mismatched:
        missing = tuple(sorted(set(expected_versions) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(expected_versions)))
        fail(
            "implementation versions must be exactly 1 through 9 with matching values; "
            f"missing {missing}, extra {extra}, mismatched {tuple(mismatched)}"
        )

    offer_match = re.search(
        r"SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS:\s*&\[u16\]\s*=\s*&\[(.*?)\];",
        core,
        re.DOTALL,
    )
    if offer_match is None:
        fail("implementation default offer declaration is missing")
    offer = tuple(
        int(version)
        for version in re.findall(r"SEMANTIC_PROTOCOL_V(\d+)", offer_match.group(1))
    )
    if offer != DEFAULT_OFFER:
        fail(f"implementation default offer must be {DEFAULT_OFFER}; found {offer}")


def parse_protocol(protocol: str) -> None:
    require_version_sequence(
        protocol,
        r"default and\s+highest-supported semantic-version surfaces report\s+(`\d+`)",
        (DEFAULT_OFFER[0],),
        "protocol highest-supported version",
    )
    for pattern in PROTOCOL_DEFAULT_OFFER_PATTERNS:
        require_version_sequence(
            protocol, pattern, DEFAULT_OFFER, "protocol default offer"
        )
    require_version_sequence(
        protocol,
        r"current handshake negotiates\s+semantic versions\s+(.+?)\s+and the complete suite",
        DEFAULT_OFFER,
        "protocol negotiated versions",
    )

    rows = {
        int(version): (inheritance.strip(), mechanics.strip())
        for version, inheritance, mechanics in re.findall(
            r"^\| `(\d+)` \| ([^|]+) \| ([^|]+) \|$",
            protocol,
            re.MULTILINE,
        )
    }
    actual_versions = tuple(sorted(rows))
    if actual_versions != VERSIONS:
        missing = tuple(sorted(set(VERSIONS) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(VERSIONS)))
        fail(
            "protocol registry must contain exactly semantic versions 1 through 9; "
            f"missing {missing}, extra {extra}"
        )
    if rows[6][0] != PROTOCOL_ROWS[6][0]:
        fail(
            "protocol v6 inheritance must preserve v5 ordinary lanes byte-for-byte; "
            f"found {rows[6][0]!r}"
        )
    if rows[7][0] != PROTOCOL_ROWS[7][0]:
        fail(
            "protocol v7 inheritance must preserve v6 byte-for-byte; "
            f"found {rows[7][0]!r}"
        )
    if rows[8][0] != PROTOCOL_ROWS[8][0]:
        fail(
            "protocol v8 inheritance must preserve v7 bytes except the lane AAD domain and Blob custody fields; "
            f"found {rows[8][0]!r}"
        )
    if rows[9][0] != PROTOCOL_ROWS[9][0]:
        fail(
            "protocol v9 inheritance must preserve v8 stable object and ordinary-lane bytes; "
            f"found {rows[9][0]!r}"
        )
    if rows != PROTOCOL_ROWS:
        fail(f"protocol registry semantics drifted; found {rows!r}")


def parse_envelope(envelope: str) -> None:
    require_version_sequence(
        envelope,
        r"(?m)^- Negotiated semantic versions:\s+default/highest\s+([^\n]+)$",
        DEFAULT_OFFER,
        "envelope version summary",
    )
    require_version_sequence(
        envelope,
        r"default semantic-version list is\s*`\[([^\]]+)\]`",
        DEFAULT_OFFER,
        "envelope default offer",
    )

    match = re.search(
        r"^selected_semantic_version\s+u16\s*=\s*([^\n]+)$",
        envelope,
        re.MULTILINE,
    )
    if match is None:
        fail("envelope selection registry is missing")
    selected = tuple(int(version) for version in re.findall(r"\d+", match.group(1)))
    if selected != VERSIONS:
        fail(f"envelope selection registry must be {VERSIONS}; found {selected}")


def parse_cddl(cddl: str) -> None:
    aliases = {
        int(version): expression.strip()
        for version, expression in re.findall(
            r"^semantic-v(\d+)-object-kind\s*=\s*([^\n]+)$",
            cddl,
            re.MULTILINE,
        )
    }
    actual_versions = tuple(sorted(aliases))
    if actual_versions != VERSIONS:
        missing = tuple(sorted(set(VERSIONS) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(VERSIONS)))
        fail(
            "CDDL object-kind aliases must cover exactly semantic versions 1 through 9; "
            f"missing {missing}, extra {extra}"
        )
    if aliases[6] != CDDL_ALIASES[6]:
        fail(
            "CDDL v6 inheritance must reuse the semantic-v5 object-kind registry; "
            f"found {aliases[6]!r}"
        )
    if aliases[7] != CDDL_ALIASES[7]:
        fail(
            "CDDL v7 inheritance must reuse the semantic-v6 object-kind registry; "
            f"found {aliases[7]!r}"
        )
    if aliases[8] != CDDL_ALIASES[8]:
        fail(
            "CDDL v8 inheritance must reuse the semantic-v7 object-kind registry; "
            f"found {aliases[8]!r}"
        )
    if aliases[9] != CDDL_ALIASES[9]:
        fail(
            "CDDL v9 inheritance must reuse the semantic-v8 object-kind registry; "
            f"found {aliases[9]!r}"
        )
    if aliases != CDDL_ALIASES:
        fail(f"CDDL object-kind registry drifted; found {aliases!r}")


def validate_contract_texts(
    core: str, protocol: str, envelope: str, cddl: str
) -> None:
    parse_implementation(core)
    parse_protocol(protocol)
    parse_envelope(envelope)
    parse_cddl(cddl)


def main() -> int:
    try:
        validate_contract_texts(
            (ROOT / "crates/aster-core/src/crypto.rs").read_text(),
            (ROOT / "docs/protocol.md").read_text(),
            (ROOT / "docs/envelope.md").read_text(),
            (ROOT / "docs/wire.cddl").read_text(),
        )
    except (ContractViolation, OSError) as error:
        print(f"protocol version contract check failed: {error}", file=sys.stderr)
        return 1
    print("protocol version contract check passed: semantic versions 1 through 9 align")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
