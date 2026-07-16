#!/usr/bin/env python3
"""Verify the behavior-preserving CP-01 source split against the 1.2.5 baseline."""

from __future__ import annotations

from collections import Counter
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs/baselines/2.0/baseline-1.2.5.json"

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


if __name__ == "__main__":
    main()
