#!/usr/bin/env bash
set -euo pipefail

if ! cargo kani --version >/dev/null 2>&1; then
    echo "cargo kani is not available; skipping Kani verification"
    exit 0
fi

cargo kani --output-format=terse --no-default-features
cargo kani --output-format=terse --no-default-features --features alloc
cargo kani --output-format=terse --no-default-features --features std
