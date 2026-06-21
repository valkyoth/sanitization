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
        printf 'expected %s failure to mention:\n%s\n\nactual output:\n' "${name}" "${needle}" >&2
        cat "${log}" >&2
        exit 1
    fi
}

run_expected_failure \
    "ct-eq-enum-rejected" \
    '"derive"' \
    "ConstantTimeEq cannot be derived for enums" \
    'use sanitization::ConstantTimeEq;

#[derive(ConstantTimeEq)]
enum Bad {
    A([u8; 4]),
    B,
}'

run_expected_failure \
    "ct-select-skip-rejected" \
    '"derive"' \
    "#[sanitization(skip)] is not supported for ConditionallySelectable derives" \
    'use sanitization::ConditionallySelectable;

#[derive(ConditionallySelectable)]
struct Bad {
    secret: [u8; 4],
    #[sanitization(skip)]
    public: u8,
}'

run_expected_failure \
    "strict-enum-ack-required" \
    '"strict-enum-derive"' \
    "SecureSanitize enum derives are rejected by the strict-enum-derive feature" \
    'use sanitization::SecureSanitize;

#[derive(SecureSanitize)]
enum Bad {
    A([u8; 4]),
    B,
}'

printf 'derive failure checks passed\n'
