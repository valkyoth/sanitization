#!/usr/bin/env python3
"""Publish the sanitization workspace crates in dependency order.

This script intentionally pauses after publishing dependency crates so crates.io
has time to index them before publishing dependents.

During preflight it also writes a local release-evidence snapshot to:

    target/release-evidence-<version>.json

Publish order:
1. sanitization-derive
2. wait for crates.io indexing
3. sanitization
4. wait for crates.io indexing
5. sanitization-arrayvec
6. sanitization-bytes
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - release host guard.
    print("Python 3.11+ is required because this script uses tomllib.", file=sys.stderr)
    raise


ROOT = Path(__file__).resolve().parents[1]

DEPENDENCY_STEPS = (
    ("sanitization-derive", True),
    ("sanitization", True),
)

FINAL_STEPS = (
    "sanitization-arrayvec",
    "sanitization-bytes",
)

ALL_PACKAGES = tuple(name for name, _ in DEPENDENCY_STEPS) + FINAL_STEPS


def run(command: list[str], *, dry_run: bool) -> None:
    print(f"+ {' '.join(command)}", flush=True)
    if dry_run:
        return
    subprocess.run(command, cwd=ROOT, check=True)


def capture(command: list[str]) -> str:
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest["workspace"]["package"]["version"]


def package_version(package: str) -> str:
    metadata = capture(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
        ]
    )
    import json

    parsed = json.loads(metadata)
    for entry in parsed["packages"]:
        if entry["name"] == package:
            return entry["version"]
    raise RuntimeError(f"package {package!r} not found in cargo metadata")


def require_clean_tree(*, allow_dirty: bool) -> None:
    if allow_dirty:
        return

    status = capture(["git", "status", "--porcelain"])
    if status:
        print("Refusing to publish from a dirty worktree:", file=sys.stderr)
        print(status, file=sys.stderr)
        print("Commit or stash changes, or pass --allow-dirty.", file=sys.stderr)
        sys.exit(1)


def verify_versions(expected_version: str) -> None:
    for package in ALL_PACKAGES:
        actual = package_version(package)
        if actual != expected_version:
            raise RuntimeError(
                f"{package} is version {actual}, expected {expected_version}"
            )


def check_release_tag(version: str, *, require_tag: bool) -> None:
    tag = f"v{version}"
    try:
        head = capture(["git", "rev-parse", "HEAD"])
        tagged_commit = capture(["git", "rev-list", "-n", "1", tag])
    except subprocess.CalledProcessError:
        message = f"Release tag {tag!r} was not found."
        if require_tag:
            print(f"Refusing to publish: {message}", file=sys.stderr)
            sys.exit(1)
        print(f"Warning: {message}", file=sys.stderr)
        return

    if head != tagged_commit:
        message = f"HEAD is not tagged as {tag} (HEAD {head}, {tag} {tagged_commit})."
        if require_tag:
            print(f"Refusing to publish: {message}", file=sys.stderr)
            sys.exit(1)
        print(f"Warning: {message}", file=sys.stderr)
        return

    print(f"Release tag {tag} points at HEAD.")


def wait_for_index(package: str, version: str, *, dry_run: bool) -> None:
    url = f"https://crates.io/crates/{package}/{version}"
    print()
    print(f"Published {package} {version}.")
    print(f"Wait until crates.io shows it here: {url}")
    print("Then press Enter to continue with dependent crates.")
    if dry_run:
        print("[dry-run] skipping wait")
        return
    input()


def publish(package: str, args: argparse.Namespace) -> None:
    command = ["cargo", "publish", "-p", package]
    if args.allow_dirty:
        command.append("--allow-dirty")
    if args.no_verify:
        command.append("--no-verify")
    run(command, dry_run=args.dry_run)


def write_release_evidence(version: str, *, dry_run: bool) -> None:
    output = ROOT / "target" / f"release-evidence-{version}.json"
    display = output.relative_to(ROOT)
    print(f"+ scripts/evidence-report.py > {display}", flush=True)
    if dry_run:
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    report = subprocess.check_output(
        ["scripts/evidence-report.py"],
        cwd=ROOT,
        text=True,
    )
    output.write_text(report, encoding="utf-8")
    print(f"Wrote {display}")


def run_preflight(args: argparse.Namespace) -> None:
    if args.skip_checks:
        print("Skipping preflight checks by request.")
        return

    run(["scripts/checks.sh"], dry_run=args.dry_run)
    run(["cargo", "test", "--workspace", "--all-features"], dry_run=args.dry_run)
    run(
        [
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        dry_run=args.dry_run,
    )
    write_release_evidence(args.version, dry_run=args.dry_run)


def selected_steps(start_at: str) -> tuple[str, ...]:
    try:
        index = ALL_PACKAGES.index(start_at)
    except ValueError as exc:
        raise RuntimeError(f"unknown package for --start-at: {start_at}") from exc
    return ALL_PACKAGES[index:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish sanitization workspace crates in crates.io order."
    )
    parser.add_argument(
        "--version",
        default=workspace_version(),
        help="Expected workspace/package version. Defaults to workspace version.",
    )
    parser.add_argument(
        "--start-at",
        default=ALL_PACKAGES[0],
        choices=ALL_PACKAGES,
        help="Resume publishing at a package if an earlier step already succeeded.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the release commands without running them or waiting.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow publishing from a dirty worktree and pass --allow-dirty to cargo.",
    )
    parser.add_argument(
        "--skip-checks",
        action="store_true",
        help="Skip local checks before publishing.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Pass --no-verify to cargo publish. Use only if you understand why.",
    )
    parser.add_argument(
        "--require-tag",
        action="store_true",
        help="Refuse to publish unless HEAD matches the v<version> release tag.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Do not ask for the initial confirmation.",
    )
    args = parser.parse_args()

    require_clean_tree(allow_dirty=args.allow_dirty or args.dry_run)
    verify_versions(args.version)
    check_release_tag(args.version, require_tag=args.require_tag)

    steps = selected_steps(args.start_at)

    print(f"Workspace root: {ROOT}")
    print(f"Release version: {args.version}")
    print("Publish sequence:")
    for package in steps:
        print(f"  - {package}")
    print()

    if not args.yes:
        answer = input("Type the release version to start publishing: ").strip()
        if answer != args.version:
            print("Version confirmation did not match; aborting.", file=sys.stderr)
            return 1

    run_preflight(args)

    for package in steps:
        publish(package, args)

        if package == "sanitization-derive":
            wait_for_index(package, args.version, dry_run=args.dry_run)
        elif package == "sanitization":
            wait_for_index(package, args.version, dry_run=args.dry_run)
            if not args.dry_run:
                print("Giving crates.io index a short extra settle window...")
                time.sleep(5)

    print()
    print("Release publish sequence completed.")
    print("Recommended follow-up:")
    print(f"  cargo info sanitization@{args.version}")
    print(f"  cargo info sanitization-derive@{args.version}")
    print(f"  cargo info sanitization-arrayvec@{args.version}")
    print(f"  cargo info sanitization-bytes@{args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
