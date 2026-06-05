#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo test
cargo test --features alloc
cargo test --features unsafe-wipe
cargo test --features unsafe-wipe,alloc
cargo test --all-features
cargo check --examples
cargo check --examples --features alloc
cargo check --examples --features unsafe-wipe
cargo check --examples --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --allow-dirty --list >/dev/null
