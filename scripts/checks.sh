#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
scripts/verify-action-pins.sh
scripts/test-latest-rust.py
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit --deny warnings
else
    printf 'skipping cargo audit; cargo-audit is not installed\n'
fi
cargo test -p sanitization-derive
cargo test
cargo test --features alloc
cargo test --features std
cargo test --features memory-lock
cargo test --features derive
cargo test --features strict-enum-derive
cargo test --features asm-compare
cargo test --features strict-compare
cargo test --features cache-flush
cargo test --features guard-pages
cargo test --features multi-pass-clear
cargo test --features unsafe-wipe
cargo test --features unsafe-wipe,alloc
cargo test --all-features
cargo test --workspace --all-features
cargo check --examples
cargo check --examples --features alloc
cargo check --examples --features std
cargo check --examples --features memory-lock
cargo check --examples --features derive
cargo check --examples --features asm-compare
cargo check --examples --features strict-compare
cargo check --examples --features cache-flush
cargo check --examples --features guard-pages
cargo check --examples --features multi-pass-clear
cargo check --examples --features unsafe-wipe
cargo check --examples --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p sanitization-derive --all-targets -- -D warnings
scripts/check-rust-version-matrix.sh
if cargo metadata --no-deps --format-version 1 >/dev/null 2>&1; then
    cargo test -p sanitization-crypto-interop --all-features
fi
scripts/verify-derive-failures.sh
scripts/verify-secret-exposure-failures.sh
scripts/verify-ct-declassification.sh
scripts/verify-leakage-smoke.sh
scripts/verify-evidence.py
scripts/test-release-readiness.sh
scripts/capture-2.0-baseline.py --check
scripts/verify-2.0-module-split.py
scripts/evidence-report.py >/dev/null

target_installed() {
    rustup target list --installed | grep -Fxq "$1"
}

check_installed_target() {
    target="$1"
    shift

    if target_installed "$target"; then
        cargo check --target "$target" "$@"
    else
        printf 'skipping target check for %s; target is not installed\n' "$target"
    fi
}

check_installed_target x86_64-unknown-linux-gnu --all-features --lib
check_installed_target aarch64-unknown-linux-gnu --features memory-lock,guard-pages,multi-pass-clear --lib
check_installed_target x86_64-apple-darwin --all-features --lib
check_installed_target aarch64-apple-darwin --all-features --lib
check_installed_target aarch64-apple-ios --all-features --lib
check_installed_target x86_64-apple-ios --all-features --lib
check_installed_target x86_64-pc-windows-gnu --all-features --lib
check_installed_target aarch64-linux-android --all-features --lib
check_installed_target x86_64-linux-android --all-features --lib
check_installed_target x86_64-unknown-freebsd --features memory-lock,guard-pages,multi-pass-clear --lib
check_installed_target wasm32-unknown-unknown --no-default-features --lib
check_installed_target wasm32-unknown-unknown --features alloc,memory-lock,wasm-compat,random-canary,multi-pass-clear --lib
check_installed_target wasm32-unknown-unknown --features wasm-compat,random-canary --lib
check_installed_target wasm32-wasip1 --features alloc,wasm-compat,random-canary,multi-pass-clear --lib
check_installed_target wasm32-wasip2 --features wasm-compat,random-canary --lib
check_installed_target thumbv7em-none-eabihf --no-default-features --lib

if target_installed wasm32-unknown-unknown; then
    if cargo check --target wasm32-unknown-unknown --features memory-lock --lib >/tmp/sanitization-wasm-memory-lock.log 2>&1; then
        printf 'wasm32 memory-lock without wasm-compat unexpectedly compiled\n'
        exit 1
    fi

    if cargo check --target wasm32-unknown-unknown --features wasm-compat,canary-check --lib >/tmp/sanitization-wasm-canary-check.log 2>&1; then
        printf 'wasm32 canary-check without random-canary unexpectedly compiled\n'
        exit 1
    fi

    if cargo check --target wasm32-unknown-unknown --features guard-pages --lib >/tmp/sanitization-wasm-guard-pages.log 2>&1; then
        printf 'wasm32 guard-pages unexpectedly compiled\n'
        exit 1
    fi
fi

scripts/verify-codegen.sh
scripts/verify-kani.sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p sanitization-derive --no-deps
cargo package -p sanitization-derive --allow-dirty --list >/dev/null
cargo package -p sanitization --allow-dirty --list >/dev/null
cargo package -p sanitization-arrayvec --allow-dirty --list >/dev/null
cargo package -p sanitization-bytes --allow-dirty --list >/dev/null
cargo package -p sanitization-crypto-interop --allow-dirty --list >/dev/null
