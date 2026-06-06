#!/usr/bin/env bash
set -euo pipefail

toolchain="${MIRI_TOOLCHAIN:-nightly}"

if ! cargo +"${toolchain}" miri --version >/dev/null 2>&1; then
    echo "cargo miri is unavailable for toolchain '${toolchain}'" >&2
    echo "install it with: rustup +${toolchain} component add miri" >&2
    exit 1
fi

cargo +"${toolchain}" miri test --no-default-features
cargo +"${toolchain}" miri test --features alloc
cargo +"${toolchain}" miri test --all-features
