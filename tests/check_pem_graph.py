"""Reject rustls-pemfile anywhere in the lockfile or all-target dependency graph."""

import json
import pathlib
import subprocess
import tomllib


def main():
    lock_path = pathlib.Path("Cargo.lock")
    original = lock_path.read_bytes()
    try:
        packages = tomllib.loads(original.decode("utf-8"))["package"]
        if any(package["name"] == "rustls-pemfile" for package in packages):
            raise SystemExit("rustls-pemfile remains in the complete Cargo.lock")
        if any(
            dependency.split()[0] == "rustls-pemfile"
            for package in packages
            for dependency in package.get("dependencies", [])
        ):
            raise SystemExit("Cargo.lock retains a rustls-pemfile dependency edge")

        # Resolve first: a generic Cargo failure is never evidence of removal.
        # Without --filter-platform, metadata includes all target platforms.
        metadata = json.loads(subprocess.check_output([
            "cargo", "metadata", "--locked", "--format-version", "1",
        ], text=True))
        if any(package["name"] == "rustls-pemfile" for package in metadata["packages"]):
            raise SystemExit("rustls-pemfile remains in the resolved dependency graph")

        result = subprocess.run([
            "cargo", "tree", "--locked", "--target", "all",
            "--edges", "normal,build,dev", "--invert", "rustls-pemfile",
        ], capture_output=True, text=True)
        absent = "package ID specification `rustls-pemfile` did not match any packages"
        if result.returncode == 0 or absent not in result.stderr:
            raise SystemExit(
                "Expected Cargo's absent-package diagnostic, received:\n"
                + result.stdout + result.stderr
            )
        print(result.stderr.strip())
        print(f"Verified {len(packages)} locked packages: rustls-pemfile is absent")
    finally:
        if lock_path.read_bytes() != original:
            raise SystemExit("Dependency inspection unexpectedly changed Cargo.lock")


if __name__ == "__main__":
    main()
