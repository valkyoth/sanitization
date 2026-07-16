#!/usr/bin/env python3
"""Structurally validate the downstream CP-19 LLVM IR probes."""

from __future__ import annotations

import re
import sys
from pathlib import Path


CLEAR_PROBES = {
    "cp05_clear_secret_box": ("clear_secret", "wipe_backend"),
    "cp19_clear_secret_vec": ("clear_secret", "wipe_backend"),
    "cp19_clear_secret_string": ("clear_secret", "wipe_backend"),
    "cp19_clear_locked": ("secure_clear", "wipe_backend"),
    "cp19_clear_guarded": ("clear_secret", "wipe_backend"),
    "cp19_clear_sealed": ("try_secure_sanitize", "clear_secret", "wipe_backend"),
    "cp19_clear_pool_slot": ("secure_clear", "wipe_backend"),
    "cp19_clear_derived_struct": ("secure_clear", "wipe_backend"),
    "cp19_clear_derived_enum": ("secure_clear", "wipe_backend"),
    "cp19_clear_tuple": ("secure_clear", "wipe_backend"),
    "cp19_clear_arrayvec": (
        "clear_secret",
        "secure_clear",
        "secure_sanitize",
        "sanitization::wipe::bytes",
    ),
}

CT_PROBES = (
    "cp19_ct_eq",
    "cp19_ct_cmp",
    "cp19_ct_copy",
    "cp19_ct_swap",
    "cp19_ct_lookup",
)


def fail(message: str) -> None:
    print(f"codegen artifact verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def function_body(ir: str, symbol: str) -> str:
    match = re.search(
        rf"^define [^@]*@{re.escape(symbol)}\([^{{]*\) [^{{]*\{{\n(.*?)^\}}",
        ir,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        alias = re.search(
            rf"^@{re.escape(symbol)} = .* alias .* ptr @([A-Za-z0-9_]+)$",
            ir,
            flags=re.MULTILINE,
        )
        if alias is not None:
            return function_body(ir, alias.group(1))
        fail(f"missing exported probe {symbol}")
    return match.group(1)


def main() -> int:
    if len(sys.argv) < 2:
        fail("usage: verify-codegen-artifact.py PATH_TO_LLVM_IR [...]")

    paths = [Path(argument) for argument in sys.argv[1:]]
    for path in paths:
        if not path.is_file():
            fail(f"LLVM IR artifact does not exist: {path}")
    ir = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    direct = function_body(ir, "cp04_direct_exposure")
    copied = function_body(ir, "cp04_copy_exposure")
    if re.search(r"alloca \[4096 x i8\]|llvm\.memcpy", direct):
        fail("direct fixed exposure created a full-size temporary")
    if not (
        re.search(r"alloca \[4096 x i8\]|llvm\.memcpy", copied)
        or "expose_array_copy" in copied
    ):
        fail("copy exposure no longer reaches its explicit-copy helper")

    for symbol, expected_paths in CLEAR_PROBES.items():
        body = function_body(ir, symbol)
        if not any(path in body for path in expected_paths) and "store volatile" not in body:
            fail(f"{symbol} does not reach a named cleanup path {expected_paths!r}")

    for symbol in CT_PROBES:
        body = function_body(ir, symbol)
        if re.search(r"\b(memcmp|bcmp)\b", body):
            fail(f"{symbol} was replaced with a forbidden comparison helper")

    for symbol in ("cp19_ct_eq", "cp19_ct_cmp"):
        body = function_body(ir, symbol)
        if 'asm sideeffect "", "r,~{memory}"' not in body:
            fail(f"{symbol} is missing the optimizer barrier")

    for symbol, expected_path in {
        "cp19_ct_copy": "conditional_copy",
        "cp19_ct_swap": "conditional_swap",
        "cp19_ct_lookup": "oblivious_lookup",
    }.items():
        body = function_body(ir, symbol)
        if expected_path not in body:
            fail(f"{symbol} does not reach {expected_path}")

    print(f"path-specific codegen probes verified across {len(paths)} LLVM IR artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
