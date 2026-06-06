#!/usr/bin/env bash
set -euo pipefail

cargo rustc --lib --release --all-features -- --emit=llvm-ir

ir_file="$(
    find target/release/deps -maxdepth 1 -name 'sanitization-*.ll' -print \
        | sort \
        | tail -n 1
)"

if [[ -z "${ir_file}" ]]; then
    echo "no sanitization LLVM IR file found" >&2
    exit 1
fi

if ! grep -q 'sanitization::wipe::volatile_wipe' "${ir_file}"; then
    echo "volatile wipe function missing from LLVM IR" >&2
    exit 1
fi

if ! grep -q 'store volatile i8 0' "${ir_file}"; then
    echo "volatile byte-zero stores missing from LLVM IR" >&2
    exit 1
fi

if ! grep -q 'sanitize_bytes_best_effort' "${ir_file}"; then
    echo "compatibility clear alias missing from LLVM IR" >&2
    exit 1
fi

echo "verified volatile wipe codegen in ${ir_file}"
