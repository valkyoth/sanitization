#!/usr/bin/env python3
"""Reject Miri-only behavior that can be selected outside crate unit tests."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "crates" / "sanitization" / "src"
MAPPED_BACKEND = SOURCE_ROOT / "mapped" / "memory_lock_native.rs"
CANARY_BACKEND = SOURCE_ROOT / "canary.rs"


def fail(message: str) -> None:
    print(f"Miri test-backend gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def cfg_expressions(source: str) -> list[str]:
    attributes = [
        match.group(1)
        for match in re.finditer(r"#\[cfg(?:_attr)?\((.*?)\)\]", source, re.DOTALL)
    ]
    expressions = [
        match.group(1)
        for match in re.finditer(r"(?<!#\[)cfg!\((.*?)\)", source, re.DOTALL)
    ]
    return attributes + expressions


def function_cfgs(source: str, name: str) -> list[str]:
    pattern = re.compile(
        rf"(?P<attrs>(?:\s*#\[[^\]]+\]\s*)+)"
        rf"(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+{re.escape(name)}\s*\("
    )
    return [compact(match.group("attrs")) for match in pattern.finditer(source)]


def verify_source_gates() -> None:
    for path in sorted(SOURCE_ROOT.rglob("*.rs")):
        if path.name == "tests.rs":
            continue
        source = path.read_text(encoding="utf-8")
        for expression in cfg_expressions(source):
            normalized = compact(expression)
            if "miri" in normalized and "test" not in normalized:
                fail(
                    f"{path.relative_to(ROOT)} has a Miri behavior gate without "
                    f"the crate-unit-test condition: cfg({normalized})"
                )

    backend = MAPPED_BACKEND.read_text(encoding="utf-8")
    for name in (
        "backend_page_granule",
        "backend_map_private",
        "backend_lock_mapping",
        "backend_mark_dontdump",
        "backend_mark_dontfork",
        "backend_mark_wipeonfork",
        "backend_unlock_mapping",
        "backend_unmap_private",
    ):
        cfgs = function_cfgs(backend, name)
        if len(cfgs) != 2:
            fail(f"expected native and modeled definitions for {name}, found {len(cfgs)}")
        if not any("#[cfg(all(miri,test))]" in cfg for cfg in cfgs):
            fail(f"{name} has no cfg(all(miri, test)) model definition")
        if not any("#[cfg(not(all(miri,test)))]" in cfg for cfg in cfgs):
            fail(f"{name} has no native complement to the unit-test model")

    canary = compact(CANARY_BACKEND.read_text(encoding="utf-8"))
    if "#[cfg(all(miri,test))]fnfill_for_miri" not in canary:
        fail("the deterministic canary generator is not restricted to Miri unit tests")
    if "#[cfg(not(all(miri,test)))]fill_inner(bytes)" not in canary:
        fail("normal builds do not unconditionally retain the native canary backend")


def verify_forged_cfg_build() -> None:
    env = os.environ.copy()
    env["RUSTFLAGS"] = f"{env.get('RUSTFLAGS', '')} --cfg miri".strip()
    command = [
        "cargo",
        "check",
        "--release",
        "-p",
        "sanitization",
        "--no-default-features",
        "--features",
        "memory-lock,random-canary,asm-compare,cache-flush,register-scrub",
        "--lib",
        "--target-dir",
        "target/miri-production-gate",
    ]
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode != 0:
        fail("a normal release build with --cfg miri did not retain native paths")


def main() -> int:
    verify_source_gates()
    verify_forged_cfg_build()
    print("Miri simulators are restricted to crate unit tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
