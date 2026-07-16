#!/usr/bin/env python3
"""Verify the reviewed CP-01 source split against the 1.2.5 baseline."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/baselines/2.0/baseline-1.2.5.json"
CP01_REPORT = ROOT / "security/pentest/2.0-development/CP-01.md"
CP01_REPORT_PATH = CP01_REPORT.relative_to(ROOT).as_posix()
EXPECTED_SOURCE_SHA256 = (
    "df37c4d9e38ee8904830d404446400907415e4e5994848e110c7bd4ad033a5ce"
)

PUBLIC_DECLARATION = re.compile(
    r"^\s*pub\s+(?:unsafe\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|const|static|mod|use)\b"
)
UNSAFE_SITE = re.compile(r"\bunsafe\b")
MACRO_NAME = re.compile(r"^\s*macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)")

MODULE_FILES = {
    "src/canary.rs",
    "src/ct.rs",
    "src/interop.rs",
    "src/lib.rs",
    "src/mapped.rs",
    "src/mapped/guard_pages.rs",
    "src/mapped/memory_lock_native.rs",
    "src/mapped/memory_lock_wasm.rs",
    "src/owned.rs",
    "src/platform.rs",
    "src/tests.rs",
    "src/wipe_backend.rs",
}
STRUCTURAL_REEXPORTS = {
    "pub use mapped::*;",
    "pub use owned::*;",
    "pub use platform::*;",
    "pub use wipe_backend::unsafe_wipe;",
}


def fail(message: str) -> None:
    print(f"verify-2.0-module-split: {message}", file=sys.stderr)
    raise SystemExit(1)


def baseline_text(entry: str) -> str:
    return entry.split(":", 2)[-1]


def git_output(*args: str) -> str:
    process = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(f"git {' '.join(args)} failed: {process.stderr.strip()}")
    return process.stdout


def git_bytes(*args: str) -> bytes:
    process = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(
            f"git {' '.join(args)} failed: "
            f"{process.stderr.decode(errors='replace').strip()}"
        )
    return process.stdout


def reviewed_source_commit() -> str | None:
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"HEAD:{CP01_REPORT_PATH}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if exists.returncode != 0:
        return None

    matches = re.findall(
        r"^Reviewed-Through: ([0-9a-f]{40})$",
        git_bytes("show", f"HEAD:{CP01_REPORT_PATH}").decode(),
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        fail("CP-01 report must contain exactly one full Reviewed-Through hash")
    return matches[0]


def source_digest(commit: str | None) -> str:
    if commit is None:
        paths = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "crates/sanitization/src").rglob("*.rs")
        )
        contents = {
            path: (ROOT / path).read_bytes()
            for path in paths
        }
    else:
        paths = sorted(
            path
            for path in git_output(
                "ls-tree", "-r", "--name-only", commit, "--", "crates/sanitization/src"
            ).splitlines()
            if path.endswith(".rs")
        )
        contents = {
            path: git_bytes("show", f"{commit}:{path}")
            for path in paths
        }

    aggregate = hashlib.sha256()
    for path in paths:
        file_digest = hashlib.sha256(contents[path]).hexdigest()
        aggregate.update(f"{file_digest}  {path}\n".encode())
    return aggregate.hexdigest()


def normalize_public(declaration: str) -> str | None:
    if declaration in STRUCTURAL_REEXPORTS:
        return None
    if declaration in {"pub mod ct {", "pub mod ct;"}:
        return "pub mod ct"
    if declaration.startswith("pub fn try_allocate"):
        return "pub fn try_allocate"
    if declaration.startswith("pub fn allocate_from_array"):
        return "pub fn allocate_from_array"
    return declaration


def source_inventory() -> tuple[Counter[str], Counter[str]]:
    public: Counter[str] = Counter()
    unsafe: Counter[str] = Counter()

    for path in sorted(ROOT.glob("crates/*/src/**/*.rs")):
        macro_export_pending = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = " ".join(line.strip().split())
            if "#[macro_export]" in line:
                macro_export_pending = True
            elif macro_export_pending:
                macro = MACRO_NAME.match(line)
                if macro:
                    public[f"macro_rules! {macro.group(1)}"] += 1
                    macro_export_pending = False
                elif stripped and not stripped.startswith("#["):
                    macro_export_pending = False

            if PUBLIC_DECLARATION.match(line):
                normalized = normalize_public(stripped)
                if normalized is not None:
                    public[normalized] += 1
            if UNSAFE_SITE.search(line):
                unsafe[stripped] += 1

    return public, unsafe


def package_files(package: str) -> set[str]:
    process = subprocess.run(
        ["cargo", "package", "-p", package, "--allow-dirty", "--list"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        fail(f"cargo package failed for {package}: {process.stderr.strip()}")
    return set(process.stdout.splitlines())


def compare_counter(label: str, expected: Counter[str], actual: Counter[str]) -> None:
    if expected == actual:
        return
    removed = list((expected - actual).elements())
    added = list((actual - expected).elements())
    fail(f"{label} changed; removed={removed!r}, added={added!r}")


def main() -> None:
    reviewed_commit = reviewed_source_commit()
    actual_source_sha256 = source_digest(reviewed_commit)

    if actual_source_sha256 != EXPECTED_SOURCE_SHA256:
        source = reviewed_commit or "working tree"
        fail(
            f"reviewed Rust source digest changed for {source}; "
            f"expected={EXPECTED_SOURCE_SHA256}, actual={actual_source_sha256}"
        )

    if reviewed_commit is not None:
        print(f"verified CP-01 exact Rust source snapshot at {reviewed_commit}")
        return

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    current_public, current_unsafe = source_inventory()

    baseline_public = Counter(
        normalized
        for entry in baseline["public_source_declarations"]
        if (normalized := normalize_public(baseline_text(entry))) is not None
    )
    baseline_unsafe = Counter(
        baseline_text(entry) for entry in baseline["unsafe_source_sites"]
    )

    compare_counter("normalized public source inventory", baseline_public, current_public)
    compare_counter("unsafe source inventory", baseline_unsafe, current_unsafe)

    for package, expected_files in baseline["package_contents"].items():
        current_files = package_files(package)
        expected = set(expected_files)
        if package == "sanitization":
            expected = {path for path in expected if not path.startswith("src/")}
            expected.update(MODULE_FILES)
        if current_files != expected:
            fail(
                f"package file list changed for {package}; "
                f"removed={sorted(expected - current_files)!r}, "
                f"added={sorted(current_files - expected)!r}"
            )

    print("verified CP-01 normalized public source inventory")
    print("verified CP-01 unsafe source inventory")
    print("verified CP-01 workspace package file lists")
    print("verified CP-01 exact Rust source snapshot from the working tree")


if __name__ == "__main__":
    main()
