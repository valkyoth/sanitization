#!/usr/bin/env python3
"""Validate the CP-22 API freeze and semver-review artifacts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CP21 = ROOT / "docs" / "baselines" / "2.0" / "cp21-public-api.json"
SEMVER = ROOT / "docs" / "baselines" / "2.0" / "cp22-semver-review.json"
MIGRATION = ROOT / "docs" / "migration-2.0.json"
PLAN = ROOT / "docs" / "IMPLEMENTATION_PLAN_2.0.0.md"
SCOPE = ROOT / "docs" / "SCOPE_2.0.0.md"


def fail(message: str) -> None:
    print(f"verify-2.0-api-freeze: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str], expected: set[int]) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if process.returncode not in expected:
        fail(f"{' '.join(command)} exited {process.returncode}: {process.stdout}")
    return process


parser = argparse.ArgumentParser()
parser.add_argument("--run-semver-tools", action="store_true")
arguments = parser.parse_args()

cp21 = json.loads(CP21.read_text(encoding="utf-8"))
if cp21.get("checkpoint") != "CP-21" or cp21.get("status") != "api-freeze-candidate":
    fail("CP-21 source-level API candidate metadata is invalid")

recorded_declarations = {
    entry.split(":", 2)[2]
    for entry in cp21.get("public_declarations", [])
    if not entry.split(":", 2)[2].startswith("macro_rules!")
}
current_declarations: set[str] = set()
pattern = re.compile(
    r"^\s*pub\s+(?:unsafe\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|const|static|mod|use)\b"
)
for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
    for line in path.read_text(encoding="utf-8").splitlines():
        if pattern.match(line):
            current_declarations.add(" ".join(line.strip().split()))
if current_declarations != recorded_declarations:
    added = sorted(current_declarations.difference(recorded_declarations))
    removed = sorted(recorded_declarations.difference(current_declarations))
    fail(f"source-level API changed after CP-21; added={added[:5]}, removed={removed[:5]}")

derive_manifest = tomllib.loads(
    (ROOT / "crates" / "sanitization-derive" / "Cargo.toml").read_text(encoding="utf-8")
)
syn = derive_manifest["dependencies"].get("syn")
if not isinstance(syn, dict) or syn.get("version") != "2.0.119":
    fail("sanitization-derive must pin syn compatibility to 2.0.119")
lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
if 'name = "syn"\nversion = "2.0.119"' not in lock:
    fail("workspace Cargo.lock does not resolve syn 2.0.119")

semver = json.loads(SEMVER.read_text(encoding="utf-8"))
expected_lints = {
    "derive_trait_impl_removed",
    "enum_missing",
    "enum_no_repr_variant_discriminant_changed",
    "enum_variant_added",
    "feature_missing",
    "function_missing",
    "inherent_method_missing",
    "module_missing",
    "struct_missing",
    "trait_method_return_value_added",
    "trait_missing",
}
if set(semver.get("breaking_lint_classes", [])) != expected_lints:
    fail("semver review lint classes are incomplete")

packages = semver.get("packages", {})
expected_packages = {
    "sanitization",
    "sanitization-arrayvec",
    "sanitization-bytes",
    "sanitization-crypto-interop",
    "sanitization-derive",
}
if set(packages) != expected_packages:
    fail("semver review does not cover every publishable package")
if packages["sanitization-arrayvec"].get("minor_result") != (
    "expected failure: inherent_method_const_removed"
):
    fail("arrayvec's intentional const removal is missing from the semver review")
if "proc-macro-only" not in packages["sanitization-derive"].get("major_result", ""):
    fail("derive's proc-macro-only semver disposition is missing")
if semver.get("public_api_tool") != "cargo-public-api 0.52.0":
    fail("semantic public API review tool is not pinned")

migration = json.loads(MIGRATION.read_text(encoding="utf-8"))
anchors = {change["anchor"] for change in migration.get("changes", [])}
if not set(semver.get("migration_anchors", [])).issubset(anchors):
    fail("a semver review category lacks a migration-guide anchor")

scope = SCOPE.read_text(encoding="utf-8")
for required in (
    "Public `ZeroValidPlainData`",
    "Target-Provided Erasure Backends",
    "Variable-Size Secure Arenas",
    "Expanded Platform Hardening",
):
    if required not in scope:
        fail(f"scope freeze is missing disposition: {required}")

plan = PLAN.read_text(encoding="utf-8")
if "| `CP-22` | Accepted |" not in plan or "| `CP-23` | Pentest |" not in plan:
    fail("implementation plan checkpoint states are not ready for CP-23 review")

if arguments.run_semver_tools:
    version = run(["cargo", "semver-checks", "--version"], {0}).stdout.strip()
    if version != semver["tool"]:
        fail(f"expected {semver['tool']}, found {version}")
    major = run(semver["major_command"].split(), {0})
    if "Summary no semver update required" not in major.stdout:
        fail("major semver comparison did not produce the accepted result")
    minor = run(semver["minor_command"].split(), {100})
    if "11 major and 0 minor checks failed" not in minor.stdout:
        fail("minor semver comparison no longer matches the reviewed break set")
    for lint in expected_lints:
        if f"failure {lint}:" not in minor.stdout:
            fail(f"minor semver comparison is missing {lint}")
    for package, review in packages.items():
        if package in {"sanitization", "sanitization-derive"}:
            continue
        package_major = run(review["major_command"].split(), {0})
        if "Summary no semver update required" not in package_major.stdout:
            fail(f"major semver comparison failed for {package}")
        expected_minor = {100} if package == "sanitization-arrayvec" else {0}
        package_minor = run(review["minor_command"].split(), expected_minor)
        if package == "sanitization-arrayvec":
            if "failure inherent_method_const_removed:" not in package_minor.stdout:
                fail("arrayvec semver comparison no longer reports the reviewed const removal")
        elif "Summary no semver update required" not in package_minor.stdout:
            fail(f"minor semver comparison failed for {package}")

print("CP-22 API freeze and semver review artifacts verified")
