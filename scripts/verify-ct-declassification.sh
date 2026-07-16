#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if rg -n 'unwrap_u8|strict-ct' \
    "${root}/crates" \
    "${root}/tools" \
    "${root}/.github" \
    --glob '*.rs' \
    --glob 'Cargo.toml'
then
    printf 'legacy CT extraction or feature naming remains in active code\n' >&2
    exit 1
fi

run_expected_failure() {
    name="$1"
    needle="$2"
    source="$3"
    case_dir="${tmpdir}/${name}"
    mkdir -p "${case_dir}/src"

    cat >"${case_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"

[dependencies]
sanitization = { path = "${root}/crates/sanitization" }
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
    "choice-raw-extraction-rejected" \
    'no method named `unwrap_u8`' \
    'use sanitization::ct::Choice;

pub fn expose(choice: Choice) -> u8 {
    choice.unwrap_u8()
}'

run_expected_failure \
    "choice-equality-rejected" \
    'binary operation `==` cannot be applied to type `Choice`' \
    'use sanitization::ct::Choice;

pub fn compare(left: Choice, right: Choice) -> bool {
    left == right
}'

run_expected_failure \
    "ct-ordering-equality-rejected" \
    'binary operation `==` cannot be applied to type `CtOrdering`' \
    'use sanitization::ct::CtOrdering;

pub fn compare(left: CtOrdering, right: CtOrdering) -> bool {
    left == right
}'

run_expected_failure \
    "mask-raw-exposure-rejected" \
    'no method named `expose`' \
    'use sanitization::ct::{Choice, Mask};

pub fn expose() -> u32 {
    Mask::<u32>::from_choice(Choice::TRUE).expose()
}'

run_expected_failure \
    "mask-equality-rejected" \
    'binary operation `==` cannot be applied to type `sanitization::ct::Mask<u32>`' \
    'use sanitization::ct::{Choice, Mask};

pub fn compare() -> bool {
    Mask::<u32>::from_choice(Choice::FALSE)
        == Mask::<u32>::from_choice(Choice::TRUE)
}'

printf 'CT declassification failure checks passed\n'
