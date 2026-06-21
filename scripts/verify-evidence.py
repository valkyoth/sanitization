#!/usr/bin/env python3
"""Validate the machine-readable CT evidence draft."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "ct-evidence.json"
LIB_RS = ROOT / "crates" / "sanitization" / "src" / "lib.rs"

REQUIRED_TOP_LEVEL = {
    "schema_version",
    "crate",
    "release_line",
    "status",
    "rust_min_version",
    "claim",
    "targets",
    "checks",
    "proofs",
    "release_candidate_requirements",
}


def fail(message: str) -> None:
    print(f"verify-evidence: {message}", file=sys.stderr)
    sys.exit(1)


def require_string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value:
        fail(f"{path} must be a non-empty string")


def require_string_list(value: Any, path: str) -> None:
    if not isinstance(value, list) or not value:
        fail(f"{path} must be a non-empty list")
    for index, item in enumerate(value):
        require_string(item, f"{path}[{index}]")


def kani_proofs() -> set[str]:
    source = LIB_RS.read_text(encoding="utf-8")
    return set(re.findall(r"fn\s+(prove_[A-Za-z0-9_]+)\s*\(", source))


def main() -> int:
    try:
        data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{EVIDENCE.name} is invalid JSON: {error}")

    if not isinstance(data, dict):
        fail("ct-evidence.json must contain a JSON object")

    missing = REQUIRED_TOP_LEVEL.difference(data)
    if missing:
        fail(f"missing required top-level keys: {', '.join(sorted(missing))}")

    if data["schema_version"] != 1:
        fail("schema_version must be 1")
    if data["crate"] != "sanitization":
        fail("crate must be sanitization")
    require_string(data["release_line"], "release_line")
    require_string(data["status"], "status")
    require_string(data["rust_min_version"], "rust_min_version")

    claim = data["claim"]
    if not isinstance(claim, dict):
        fail("claim must be an object")
    require_string(claim.get("summary"), "claim.summary")
    require_string_list(claim.get("claimed"), "claim.claimed")
    require_string_list(claim.get("not_claimed"), "claim.not_claimed")

    targets = data["targets"]
    if not isinstance(targets, list) or not targets:
        fail("targets must be a non-empty list")
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            fail(f"targets[{index}] must be an object")
        for key in ("target", "tier"):
            require_string(target.get(key), f"targets[{index}].{key}")
        for key in ("features", "barrier_strategy", "evidence", "limitations"):
            value = target.get(key)
            if not isinstance(value, list):
                fail(f"targets[{index}].{key} must be a list")
            for item_index, item in enumerate(value):
                require_string(item, f"targets[{index}].{key}[{item_index}]")

    checks = data["checks"]
    if not isinstance(checks, list) or not checks:
        fail("checks must be a non-empty list")
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            fail(f"checks[{index}] must be an object")
        require_string(check.get("name"), f"checks[{index}].name")
        require_string(check.get("command"), f"checks[{index}].command")
        require_string_list(check.get("coverage"), f"checks[{index}].coverage")

    listed_proofs = data["proofs"]
    require_string_list(listed_proofs, "proofs")
    actual_proofs = kani_proofs()
    listed_set = set(listed_proofs)
    missing_from_json = actual_proofs.difference(listed_set)
    missing_from_code = listed_set.difference(actual_proofs)
    if missing_from_json:
        fail(f"Kani proofs missing from JSON: {', '.join(sorted(missing_from_json))}")
    if missing_from_code:
        fail(f"JSON proofs missing from code: {', '.join(sorted(missing_from_code))}")

    require_string_list(
        data["release_candidate_requirements"], "release_candidate_requirements"
    )

    print("ct-evidence.json validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
