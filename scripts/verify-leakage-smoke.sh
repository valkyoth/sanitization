#!/usr/bin/env bash
set -euo pipefail

output="${TMPDIR:-/tmp}/sanitization-ct-leakage-smoke.json"

cargo check --manifest-path tools/ct-leakage/Cargo.toml
cargo check --manifest-path tools/ct-leakage/Cargo.toml --features asm-compare
cargo check --manifest-path tools/ct-leakage/Cargo.toml --features strict-compare
cargo run --release --manifest-path tools/ct-leakage/Cargo.toml -- \
    --samples 20 \
    --inner 2 \
    --warmup 2 \
    --threshold 1000000 \
    --output "$output" >/dev/null
python3 -m json.tool "$output" >/dev/null

printf 'ct leakage smoke check passed: %s\n' "$output"
