#!/usr/bin/env python3
"""Prepare an ephemeral PEM backport candidate for cross-platform validation.

The checked-in application dependency and lockfile remain on their original Git
revision. This script changes only the validation checkout at runtime; its local
path dependency and generated candidate lockfile are not a shipped source pin.
Requires Python 3.11+, Git, and the selected Rust toolchain on PATH.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


UPSTREAM_URL = "https://github.com/Devolutions/IronRDP"
UPSTREAM_REV = "8e76c3168da578826d8fd707503655ea16bd3392"
UPSTREAM_SOURCE = f"git+{UPSTREAM_URL}?rev={UPSTREAM_REV}#{UPSTREAM_REV}"
LOCAL_SERVER = ".ci/ironrdp/crates/ironrdp-server"
PATCHED_FILES = {
    "crates/ironrdp-server/Cargo.toml",
    "crates/ironrdp-server/src/helper.rs",
}


def package_key(package: dict) -> tuple[str, str, str]:
    return package["name"], package["version"], package.get("source", "")


def package_index(packages: list[dict]) -> dict:
    result = {package_key(package): package for package in packages}
    if len(result) != len(packages):
        raise SystemExit("Duplicate package identities in the lockfile")
    return result


def require_same_packages(expected: list[dict], actual: list[dict], label: str) -> None:
    expected_index, actual_index = package_index(expected), package_index(actual)
    missing = sorted(expected_index.keys() - actual_index.keys())
    added = sorted(actual_index.keys() - expected_index.keys())
    changed = sorted(
        key for key in expected_index.keys() & actual_index.keys()
        if expected_index[key] != actual_index[key]
    )
    if missing or added or changed:
        raise SystemExit(
            f"Unexpected {label} change: missing={missing}; added={added}; changed={changed}"
        )


def candidate_manifest(original: bytes) -> bytes:
    manifest = tomllib.loads(original.decode("utf-8"))
    dependency = manifest["dependencies"]["ironrdp-server"]
    if dependency.get("git") != UPSTREAM_URL or dependency.get("rev") != UPSTREAM_REV:
        raise SystemExit("The application must start from the expected immutable IronRDP revision")
    if "path" in dependency:
        raise SystemExit("The application already contains a local IronRDP override")

    # Keep every other manifest field, including features/default-features,
    # unchanged. Fail if the checked-in source declaration needs a new review.
    source_fields = f'git = "{UPSTREAM_URL}", rev = "{UPSTREAM_REV}"'
    original_text = original.decode("utf-8")
    if original_text.count(source_fields) != 1:
        raise SystemExit("Expected one exact IronRDP source declaration in Cargo.toml")
    candidate_text = original_text.replace(source_fields, f'path = "{LOCAL_SERVER}"', 1)
    expected = copy.deepcopy(manifest)
    del expected["dependencies"]["ironrdp-server"]["git"]
    del expected["dependencies"]["ironrdp-server"]["rev"]
    expected["dependencies"]["ironrdp-server"]["path"] = LOCAL_SERVER
    if tomllib.loads(candidate_text) != expected:
        raise SystemExit("Candidate preparation changed unrelated manifest settings")
    return candidate_text.encode("utf-8")


def verify_lock_delta(original: dict, candidate: dict, metadata: dict, upstream: Path) -> None:
    old_packages, new_packages = original["package"], candidate["package"]
    pem_packages = [package for package in old_packages if package["name"] == "rustls-pemfile"]
    if len(pem_packages) != 1 or not pem_packages[0].get("source", "").startswith("registry+"):
        raise SystemExit("Expected exactly one original registry rustls-pemfile package")

    original_ironrdp = {
        (package["name"], package["version"])
        for package in old_packages if package.get("source") == UPSTREAM_SOURCE
    }
    if ("ironrdp-server", "0.13.0") not in original_ironrdp:
        raise SystemExit("Original lockfile does not use ironrdp-server 0.13.0 at the expected Git source")

    old_registry = [
        package for package in old_packages
        if package.get("source", "").startswith("registry+")
        and package["name"] != "rustls-pemfile"
    ]
    new_registry = [
        package for package in new_packages if package.get("source", "").startswith("registry+")
    ]
    require_same_packages(old_registry, new_registry, "registry package/checksum/dependency")

    original_paths = {
        (package["name"], package["version"])
        for package in old_packages if "source" not in package
    }
    candidate_paths = {
        (package["name"], package["version"])
        for package in new_packages if "source" not in package
    }
    if candidate_paths != original_paths | original_ironrdp:
        raise SystemExit("Candidate path package set does not exactly replace the original Git IronRDP set")

    # Normalize only the intentional source conversion and PEM dependency
    # removal. All remaining package fields and dependency edges must match.
    expected_packages = []
    removed_edges = 0
    for package in copy.deepcopy(old_packages):
        if package["name"] == "rustls-pemfile":
            continue
        if package.get("source") == UPSTREAM_SOURCE:
            del package["source"]
            if package["name"] == "ironrdp-server":
                dependencies = package.get("dependencies", [])
                retained = [dependency for dependency in dependencies if dependency.split()[0] != "rustls-pemfile"]
                removed_edges += len(dependencies) - len(retained)
                package["dependencies"] = retained
        expected_packages.append(package)
    if removed_edges != 1:
        raise SystemExit("Expected exactly one original ironrdp-server -> rustls-pemfile dependency edge")
    require_same_packages(expected_packages, new_packages, "normalized complete lockfile")
    if {key: value for key, value in original.items() if key != "package"} != {
        key: value for key, value in candidate.items() if key != "package"
    }:
        raise SystemExit("Candidate preparation changed unrelated lockfile metadata")

    resolved_ironrdp = set()
    for package in metadata["packages"]:
        identity = package["name"], package["version"]
        if identity in original_ironrdp:
            manifest_path = Path(package["manifest_path"]).resolve()
            if package["source"] is not None or not manifest_path.is_relative_to(upstream):
                raise SystemExit(f"IronRDP package is outside the patched checkout: {identity}")
            resolved_ironrdp.add(identity)
    if resolved_ironrdp != original_ironrdp:
        raise SystemExit("Resolved metadata does not contain every original IronRDP package")
    print(
        f"Candidate lock delta verified: {len(original_ironrdp)} coherent IronRDP path packages; "
        f"{len(old_registry)} unchanged registry entries; only rustls-pemfile and its edge removed",
        flush=True,
    )


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    upstream = root / ".ci" / "ironrdp"
    patch = root / "tests" / "fixtures" / "ironrdp-pemobject.patch"
    manifest_path, lock_path = root / "Cargo.toml", root / "Cargo.lock"
    original_manifest = manifest_path.read_bytes()
    original_lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    rewritten_manifest = candidate_manifest(original_manifest)

    checkout_root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=upstream, text=True,
    ).strip()
    if Path(checkout_root).resolve() != upstream.resolve():
        raise SystemExit(".ci/ironrdp must be a separate upstream Git checkout")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=upstream, text=True).strip()
    if head != UPSTREAM_REV:
        raise SystemExit(f"Unexpected IronRDP HEAD: {head}; expected {UPSTREAM_REV}")
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=upstream, text=True,
    )
    if status.strip():
        raise SystemExit("The upstream checkout must be clean before applying the candidate patch")

    print(
        "CANDIDATE VALIDATION ONLY: this local path backport does not change the shipped Git source pin.",
        flush=True,
    )
    print(f"Upstream HEAD: {head}; patch SHA-256: {hashlib.sha256(patch.read_bytes()).hexdigest()}", flush=True)
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=upstream, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=upstream, check=True)
    changed = set(subprocess.check_output(["git", "diff", "--name-only"], cwd=upstream, text=True).splitlines())
    if changed != PATCHED_FILES:
        raise SystemExit(f"Candidate patch changed unexpected upstream files: {sorted(changed)}")
    manifest_path.write_bytes(rewritten_manifest)

    # The only unlocked Cargo resolution in this workflow. Preserve the existing
    # lockfile so Cargo carries its registry pins across the Git -> path change.
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1"], cwd=root, text=True,
    ))
    candidate_lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    verify_lock_delta(original_lock, candidate_lock, metadata, upstream.resolve())
    subprocess.run([sys.executable, str(root / "tests" / "check_pem_graph.py")], cwd=root, check=True)
    print(
        "Candidate setup complete. All subsequent build, lint, test, and graph resolution must use --locked; "
        "the generated Cargo.toml/Cargo.lock are validation-only and must not be committed.",
        flush=True,
    )


if __name__ == "__main__":
    main()
