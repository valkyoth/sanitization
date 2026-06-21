#!/usr/bin/env bash
set -euo pipefail

emit_codegen() {
    rm -f \
        target/release/deps/sanitization-verify-codegen.d \
        target/release/deps/sanitization-verify-codegen.ll \
        target/release/deps/sanitization-verify-codegen.s \
        target/release/deps/libsanitization-verify-codegen.rlib \
        target/release/deps/libsanitization-verify-codegen.rmeta

    cargo rustc -p sanitization --lib --release --all-features -- \
        -C extra-filename=-verify-codegen \
        --emit=llvm-ir,asm
}

emit_codegen

ir_file="target/release/deps/sanitization-verify-codegen.ll"
asm_file="target/release/deps/sanitization-verify-codegen.s"

if [[ ! -f "${ir_file}" ]]; then
    echo "no sanitization LLVM IR file found" >&2
    exit 1
fi

if [[ ! -f "${asm_file}" ]]; then
    echo "no sanitization assembly file found" >&2
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

for symbol in \
    'sanitization::ct::conditional_copy' \
    'sanitization::ct::conditional_swap' \
    'sanitization::ct::select_slice'
do
    if ! grep -q "${symbol}" "${ir_file}"; then
        echo "native ct helper ${symbol} missing from LLVM IR" >&2
        exit 1
    fi
done

if ! grep -q 'asm sideeffect "", "r,~{memory}"' "${ir_file}"; then
    echo "native ct optimizer barrier missing from LLVM IR" >&2
    exit 1
fi

if ! grep -q 'sub i8 0' "${ir_file}"; then
    echo "native ct mask-generation pattern missing from LLVM IR" >&2
    exit 1
fi

if grep -Eq '\b(memcmp|bcmp)\b' "${ir_file}" "${asm_file}"; then
    echo "memcmp/bcmp call found in release codegen" >&2
    exit 1
fi

host="$(
    rustc -vV \
        | awk '/^host:/ { print $2 }'
)"

if [[ "${host}" == x86_64-* ]]; then
    if ! grep -q 'compare_asm' "${asm_file}"; then
        echo "x86_64 assembly comparison symbol missing from assembly" >&2
        exit 1
    fi

    if ! grep -Eq '\bmovzbl\b|\bmovzx\b' "${asm_file}"; then
        echo "x86_64 byte-load comparison instruction missing from assembly" >&2
        exit 1
    fi

    if ! grep -q 'clflush' "${asm_file}"; then
        echo "x86_64 cache flush instruction missing from assembly" >&2
        exit 1
    fi

    if ! grep -q 'mfence' "${asm_file}"; then
        echo "x86_64 cache flush fence missing from assembly" >&2
        exit 1
    fi

    echo "verified x86_64 architecture-specific codegen in ${asm_file}"
else
    echo "skipped architecture-specific codegen checks for ${host}"
fi

echo "verified volatile wipe codegen in ${ir_file}"
echo "verified native ct helper codegen in ${ir_file}"
