#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the semantic protocol-version contract."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


CHECKER_PATH = Path(__file__).with_name("check-protocol-version-contract.py")
SPEC = importlib.util.spec_from_file_location("protocol_version_contract", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def core_contract() -> str:
    constants = "\n".join(
        f"pub(crate) const SEMANTIC_PROTOCOL_V{version}: u16 = {version};"
        for version in range(1, 10)
    )
    offered = ",\n    ".join(
        f"SEMANTIC_PROTOCOL_V{version}" for version in range(9, 0, -1)
    )
    return f"""{constants}
pub(crate) const SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS: &[u16] = &[
    {offered},
];
"""


def protocol_contract() -> str:
    return """The default and highest-supported semantic-version surfaces report `9`.
The default semantic offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
The default descending offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
The default initiator offers semantic versions `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
The current handshake negotiates semantic versions `9`, `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1` and the complete suite `0x0001`.

| Semantic version | Inherits | Additional mechanics |
| --- | --- | --- |
| `1` | — | stable Event and Blob-chunk transfer |
| `2` | v1 | compact batch and bridge objects |
| `3` | v2 | session custody record |
| `4` | v3 | State and Record reconciliation |
| `5` | v4 | historical direct Blob frame allocation |
| `6` | v5 ordinary lanes byte-for-byte | Event bridge transfer |
| `7` | v6 byte-for-byte | per-lane profiles, receipt-free Event pages, and durable Blob range streams |
| `8` | v7 byte-for-byte except the lane AAD domain and Blob custody fields | authenticated finite Blob custody over `BlobRangesStreamV1` |
| `9` | v8 stable object and ordinary-lane bytes | `BlobStreamV1` profile identity and reserved stream-record tags; runtime activation is separately gated |
"""


def envelope_contract() -> str:
    return """- Negotiated semantic versions: default/highest `9`, compatibility `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`
The default semantic-version list is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
selected_semantic_version       u16 = 1, 2, 3, 4, 5, 6, 7, 8, or 9
"""


def cddl_contract() -> str:
    return """semantic-v1-object-kind = 1 / 2
semantic-v2-object-kind = semantic-v1-object-kind / 3 / 4 / 5
semantic-v3-object-kind = semantic-v2-object-kind
semantic-v4-object-kind = semantic-v3-object-kind
semantic-v5-object-kind = semantic-v4-object-kind
semantic-v6-object-kind = semantic-v5-object-kind
semantic-v7-object-kind = semantic-v6-object-kind
semantic-v8-object-kind = semantic-v7-object-kind
semantic-v9-object-kind = semantic-v8-object-kind
"""


class ProtocolVersionContractTests(unittest.TestCase):
    def validate(
        self,
        *,
        core: str | None = None,
        protocol: str | None = None,
        envelope: str | None = None,
        cddl: str | None = None,
    ) -> None:
        CHECKER.validate_contract_texts(
            core if core is not None else core_contract(),
            protocol if protocol is not None else protocol_contract(),
            envelope if envelope is not None else envelope_contract(),
            cddl if cddl is not None else cddl_contract(),
        )

    def test_v1_through_v9_contract_passes(self) -> None:
        self.validate()

    def test_each_missing_implementation_version_fails(self) -> None:
        for version in range(1, 10):
            with self.subTest(version=version):
                damaged = core_contract().replace(
                    f"pub(crate) const SEMANTIC_PROTOCOL_V{version}: u16 = {version};\n",
                    "",
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, f"implementation versions.*{version}"
                ):
                    self.validate(core=damaged)

    def test_noncanonical_default_offer_fails(self) -> None:
        damaged = core_contract().replace(
            "SEMANTIC_PROTOCOL_V9,\n    SEMANTIC_PROTOCOL_V8",
            "SEMANTIC_PROTOCOL_V8,\n    SEMANTIC_PROTOCOL_V9",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "default offer"):
            self.validate(core=damaged)

    def test_each_missing_protocol_registry_row_fails(self) -> None:
        for version in range(1, 10):
            with self.subTest(version=version):
                rows = protocol_contract().splitlines()
                damaged = "\n".join(
                    row for row in rows if not row.startswith(f"| `{version}` |")
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, f"protocol registry.*{version}"
                ):
                    self.validate(protocol=damaged)

    def test_each_protocol_default_offer_declaration_is_checked(self) -> None:
        declarations = (
            "default semantic offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`",
            "default descending offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`",
            "default initiator offers semantic versions `[9, 8, 7, 6, 5, 4, 3, 2, 1]`",
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                damaged = protocol_contract().replace(
                    declaration, declaration.replace("9, ", ""), 1
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, "protocol default offer"
                ):
                    self.validate(protocol=damaged)

    def test_protocol_negotiated_version_declaration_is_checked(self) -> None:
        damaged = protocol_contract().replace(
            "`9`, `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
            "`8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "protocol negotiated versions"
        ):
            self.validate(protocol=damaged)

    def test_protocol_highest_supported_surface_is_checked(self) -> None:
        damaged = protocol_contract().replace(
            "highest-supported semantic-version surfaces report `9`",
            "highest-supported semantic-version surfaces report `8`",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "protocol highest-supported version"
        ):
            self.validate(protocol=damaged)

    def test_v6_must_inherit_v5_ordinary_lanes_byte_for_byte(self) -> None:
        damaged = protocol_contract().replace(
            "v5 ordinary lanes byte-for-byte", "v5"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v6 inheritance"):
            self.validate(protocol=damaged)

    def test_v7_must_inherit_v6_byte_for_byte(self) -> None:
        damaged = protocol_contract().replace("v6 byte-for-byte", "v6")
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v7 inheritance"):
            self.validate(protocol=damaged)

    def test_v8_must_inherit_v7_except_its_allocated_surfaces(self) -> None:
        damaged = protocol_contract().replace(
            "v7 byte-for-byte except the lane AAD domain and Blob custody fields", "v7"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v8 inheritance"):
            self.validate(protocol=damaged)

    def test_v9_must_inherit_v8_stable_bytes(self) -> None:
        damaged = protocol_contract().replace(
            "v8 stable object and ordinary-lane bytes", "v8"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v9 inheritance"):
            self.validate(protocol=damaged)

    def test_truncated_envelope_selection_registry_fails(self) -> None:
        damaged = envelope_contract().replace(", 7, 8, or 9", "")
        with self.assertRaisesRegex(CHECKER.ContractViolation, "envelope selection"):
            self.validate(envelope=damaged)

    def test_truncated_envelope_default_offer_fails(self) -> None:
        damaged = envelope_contract().replace(
            "[9, 8, 7, 6, 5, 4, 3, 2, 1]", "[8, 7, 6, 5, 4, 3, 2, 1]"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "envelope default offer"):
            self.validate(envelope=damaged)

    def test_envelope_version_summary_is_checked(self) -> None:
        damaged = envelope_contract().replace(
            "default/highest `9`, compatibility `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
            "default/highest `8`, compatibility `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "envelope version summary"
        ):
            self.validate(envelope=damaged)

    def test_each_missing_cddl_alias_fails(self) -> None:
        for version in range(1, 10):
            with self.subTest(version=version):
                rows = cddl_contract().splitlines()
                damaged = "\n".join(
                    row
                    for row in rows
                    if not row.startswith(f"semantic-v{version}-object-kind =")
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, f"CDDL object-kind aliases.*{version}"
                ):
                    self.validate(cddl=damaged)

    def test_cddl_v6_must_inherit_v5_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v6-object-kind = semantic-v5-object-kind",
            "semantic-v6-object-kind = semantic-v4-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v6 inheritance"):
            self.validate(cddl=damaged)

    def test_cddl_v7_must_inherit_v6_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v7-object-kind = semantic-v6-object-kind",
            "semantic-v7-object-kind = semantic-v5-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v7 inheritance"):
            self.validate(cddl=damaged)

    def test_cddl_v8_must_inherit_v7_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v8-object-kind = semantic-v7-object-kind",
            "semantic-v8-object-kind = semantic-v6-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v8 inheritance"):
            self.validate(cddl=damaged)

    def test_cddl_v9_must_inherit_v8_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v9-object-kind = semantic-v8-object-kind",
            "semantic-v9-object-kind = semantic-v7-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v9 inheritance"):
            self.validate(cddl=damaged)


if __name__ == "__main__":
    unittest.main()
