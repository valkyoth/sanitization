#!/usr/bin/env python3
"""Seed negative artifacts and require verification tooling to reject them."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def expect_failure(command: list[str], label: str) -> None:
    result = run(command)
    if result.returncode == 0:
        raise SystemExit(f"negative verification fixture unexpectedly passed: {label}")


with tempfile.TemporaryDirectory(prefix="sanitization-negative-evidence-") as directory:
    temp = Path(directory)

    invalid_evidence = json.loads(
        (ROOT / "docs" / "ct-evidence.json").read_text(encoding="utf-8")
    )
    invalid_evidence.pop("claim")
    evidence_path = temp / "ct-evidence.json"
    evidence_path.write_text(json.dumps(invalid_evidence), encoding="utf-8")
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-evidence.py"),
            str(evidence_path),
        ],
        "missing evidence claim",
    )

    invalid_ir = temp / "invalid.ll"
    invalid_ir.write_text(
        "define void @cp04_direct_exposure() {\n  ret void\n}\n",
        encoding="utf-8",
    )
    expect_failure(
        [
            "python3",
            str(ROOT / "scripts" / "verify-codegen-artifact.py"),
            str(invalid_ir),
        ],
        "missing path-specific probes",
    )

print("verification tooling rejected seeded negative fixtures")
