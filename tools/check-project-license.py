#!/usr/bin/env python3
"""Enforce the repository's Apache-2.0-only first-party license policy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


EXPECTED_LICENSE = "Apache-2.0"
EXPECTED_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
EXPECTED_THIRD_PARTY_NOTICES_SHA256 = (
    "540785f9b3acfa31e2e509cbd1074310292d28976188a65ef5a85e08c6b228d5"
)
ROOT = Path(__file__).resolve().parents[1]
LICENSE = ROOT / "LICENSE"
THIRD_PARTY_NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
DISTRIBUTION_ROOTS = (
    ROOT / "bindings" / "c",
    ROOT / "bindings" / "go",
    ROOT / "bindings" / "python",
    ROOT / "tools" / "age-reference",
)


def fail(message: str) -> None:
    print(f"project-license policy failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def cargo_output(*args: str) -> str:
    completed = subprocess.run(
        ["cargo", *args],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr, end="")
        fail(f"cargo {' '.join(args)} exited with {completed.returncode}")
    return completed.stdout


def metadata(manifest_path: str | None = None) -> dict[str, object]:
    args = [
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        "--no-deps",
    ]
    if manifest_path is not None:
        args.extend(["--manifest-path", manifest_path])
    return json.loads(cargo_output(*args))


def validate_packages(
    document: dict[str, object], manifest_path: str | None = None
) -> int:
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("cargo metadata returned no first-party packages")

    count = 0
    for package in packages:
        if not isinstance(package, dict):
            fail("cargo metadata returned a malformed package record")

        name = package.get("name")
        if not isinstance(name, str):
            fail("cargo metadata returned a package without a name")
        if package.get("license") != EXPECTED_LICENSE:
            fail(f"{name} does not declare exactly {EXPECTED_LICENSE}")

        manifest = package.get("manifest_path")
        if not isinstance(manifest, str):
            fail(f"{name} does not report its manifest path")
        if package.get("license_file") is not None:
            fail(f"{name} must use SPDX metadata rather than license-file")

        package_license = Path(manifest).parent / "LICENSE"
        if not package_license.is_file():
            fail(f"{name} package root omits LICENSE")
        package_hash = hashlib.sha256(package_license.read_bytes()).hexdigest()
        if package_hash != EXPECTED_LICENSE_SHA256:
            fail(f"{name} package LICENSE differs from the canonical text")

        package_args = [
            "package",
            "--locked",
            "--offline",
            "--allow-dirty",
            "--list",
        ]
        if manifest_path is None:
            package_args.extend(["--package", name])
        else:
            package_args.extend(["--manifest-path", manifest_path])
        packaged_files = cargo_output(*package_args).splitlines()
        if "LICENSE" not in packaged_files:
            fail(f"{name} package archive omits LICENSE")
        count += 1

    return count


def main() -> None:
    root_license_files = sorted(path.name for path in ROOT.glob("LICENSE*"))
    if root_license_files != ["LICENSE"]:
        fail(f"expected only root LICENSE, found {root_license_files}")

    actual_hash = hashlib.sha256(LICENSE.read_bytes()).hexdigest()
    if actual_hash != EXPECTED_LICENSE_SHA256:
        fail("LICENSE is not the canonical Apache License 2.0 text")

    notices_hash = hashlib.sha256(THIRD_PARTY_NOTICES.read_bytes()).hexdigest()
    if notices_hash != EXPECTED_THIRD_PARTY_NOTICES_SHA256:
        fail("THIRD_PARTY_NOTICES.md differs from the reviewed exact-package text")

    package_count = validate_packages(metadata())
    package_count += validate_packages(
        metadata("fuzz/Cargo.toml"), "fuzz/Cargo.toml"
    )

    for distribution_root in DISTRIBUTION_ROOTS:
        distribution_license = distribution_root / "LICENSE"
        if not distribution_license.is_file():
            fail(f"{distribution_root.relative_to(ROOT)} omits LICENSE")
        distribution_hash = hashlib.sha256(distribution_license.read_bytes()).hexdigest()
        if distribution_hash != EXPECTED_LICENSE_SHA256:
            fail(f"{distribution_root.relative_to(ROOT)} has a noncanonical LICENSE")

    dockerfiles = (
        ROOT / "lab" / "Dockerfile",
        ROOT / "docker" / "lan-mvp" / "Dockerfile",
    )
    for dockerfile_path in dockerfiles:
        dockerfile = dockerfile_path.read_text(encoding="utf-8")
        if "COPY LICENSE /usr/share/licenses/aster/LICENSE" not in dockerfile:
            fail(f"{dockerfile_path.relative_to(ROOT)} does not include LICENSE")
        if (
            "COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/aster/THIRD_PARTY_NOTICES.md"
            not in dockerfile
        ):
            fail(
                f"{dockerfile_path.relative_to(ROOT)} does not include third-party notices"
            )
    docker_ignore_files = (
        ROOT / ".dockerignore",
        ROOT / "lab" / "Dockerfile.dockerignore",
        ROOT / "docker" / "lan-mvp" / "Dockerfile.dockerignore",
    )
    for ignore_file in docker_ignore_files:
        if "!LICENSE" not in ignore_file.read_text(encoding="utf-8").splitlines():
            fail(f"{ignore_file.relative_to(ROOT)} excludes LICENSE")
        if "!THIRD_PARTY_NOTICES.md" not in ignore_file.read_text(
            encoding="utf-8"
        ).splitlines():
            fail(f"{ignore_file.relative_to(ROOT)} excludes third-party notices")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "Licensed under the Apache License, Version 2.0. See `LICENSE`." not in readme:
        fail("README does not state the Apache License 2.0 policy")

    print(
        f"project-license policy passed for {package_count} packages: "
        f"{EXPECTED_LICENSE}, canonical LICENSE and reviewed third-party notices present"
    )


if __name__ == "__main__":
    main()
