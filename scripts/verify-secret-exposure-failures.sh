#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run_expected_failure() {
    name="$1"
    features="$2"
    needle="$3"
    source="$4"
    case_dir="${tmpdir}/${name}"
    mkdir -p "${case_dir}/src"

    cat >"${case_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"

[dependencies]
sanitization = { path = "${root}/crates/sanitization", features = [${features}] }
EOF

    printf '%s\n' "${source}" >"${case_dir}/src/lib.rs"

    log="${case_dir}/cargo-check.log"
    if cargo check --manifest-path "${case_dir}/Cargo.toml" >"${log}" 2>&1; then
        printf 'expected %s to fail, but it compiled\n' "${name}" >&2
        exit 1
    fi

    if ! grep -Fq "${needle}" "${log}"; then
        printf 'expected %s failure to mention:\n%s\n\nactual output:\n' \
            "${name}" "${needle}" >&2
        cat "${log}" >&2
        exit 1
    fi
}

run_expected_failure \
    "secret-vec-shared-exposure-rejected" \
    '"alloc"' \
    '`Vec<u8>: StableSharedSecretStorage`' \
    'use sanitization::Secret;

pub fn expose() {
    let secret = Secret::new(vec![1_u8, 2, 3, 4]);
    secret.with_secret(|bytes| bytes.len());
}'

run_expected_failure \
    "secret-string-mutable-exposure-rejected" \
    '"alloc"' \
    '`String: StableMutableSecretStorage`' \
    'use sanitization::Secret;

pub fn expose() {
    let mut secret = Secret::new(String::from("secret"));
    secret.with_secret_mut(|text| text.push_str("-rotated"));
}'

run_expected_failure \
    "secret-interior-mutable-exposure-rejected" \
    '"std"' \
    '`Rotating: StableSharedSecretStorage`' \
    'use std::cell::RefCell;
use sanitization::{Secret, SecureSanitize};

struct Rotating {
    bytes: RefCell<Vec<u8>>,
}

impl SecureSanitize for Rotating {
    fn secure_sanitize(&mut self) {
        self.bytes.get_mut().secure_sanitize();
    }
}

pub fn expose() {
    let secret = Secret::new(Rotating {
        bytes: RefCell::new(vec![1, 2, 3, 4]),
    });
    secret.with_secret(|value| {
        value.bytes.replace(vec![9, 9, 9, 9]);
    });
}'

run_expected_failure \
    "custom-wipe-implementation-rejected" \
    '"alloc"' \
    'sealed trait' \
    'use sanitization::wipe::Wipe;

pub struct NoOpWipe([u8; 4]);

impl Wipe for NoOpWipe {
    fn wipe(&mut self) {}
}'

printf 'generic secret exposure failure checks passed\n'
