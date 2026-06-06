#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo test
cargo test --features alloc
cargo test --features std
cargo test --features memory-lock
cargo test --features asm-compare
cargo test --features cache-flush
cargo test --features guard-pages
cargo test --features unsafe-wipe
cargo test --features unsafe-wipe,alloc
cargo test --all-features
cargo check --examples
cargo check --examples --features alloc
cargo check --examples --features std
cargo check --examples --features memory-lock
cargo check --examples --features asm-compare
cargo check --examples --features cache-flush
cargo check --examples --features guard-pages
cargo check --examples --features unsafe-wipe
cargo check --examples --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
scripts/verify-codegen.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package --allow-dirty --list >/dev/null
