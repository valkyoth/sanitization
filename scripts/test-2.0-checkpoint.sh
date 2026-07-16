#!/usr/bin/env sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_script="$(pwd)/scripts/validate-2.0-checkpoint.sh"

assert_fails_with() {
    expected="$1"
    shift

    if "$@" >"$tmp/stdout" 2>"$tmp/stderr"; then
        echo "expected command to fail: $*" >&2
        exit 1
    fi

    if ! grep -q "$expected" "$tmp/stderr"; then
        echo "expected stderr to contain: $expected" >&2
        echo "actual stderr:" >&2
        cat "$tmp/stderr" >&2
        exit 1
    fi
}

make_fixture() {
    name="$1"
    repo="$tmp/$name"

    mkdir -p "$repo/docs" "$repo/scripts" "$repo/security/pentest/2.0-development"
    cat >"$repo/docs/IMPLEMENTATION_PLAN_2.0.0.md" <<'EOF'
### `CP-00`: Fixture
`security/pentest/2.0-development/CP-00.md`
### `CP-01`: Fixture
`security/pentest/2.0-development/CP-01.md`
EOF
    printf 'fixture\n' >"$repo/README.md"

    (
        cd "$repo"
        git init -q
        git config user.email "checkpoint@example.invalid"
        git config user.name "Checkpoint Test"
        git add README.md docs/IMPLEMENTATION_PLAN_2.0.0.md
        git commit -q -m "planning baseline"
        base="$(git rev-parse HEAD)"

        cp "$source_script" scripts/validate-2.0-checkpoint.sh
        sed -i "s/^CP00_BASE=.*/CP00_BASE='${base}'/" scripts/validate-2.0-checkpoint.sh
        chmod +x scripts/validate-2.0-checkpoint.sh
        git add scripts/validate-2.0-checkpoint.sh
        git commit -q -m "CP-00 implementation"
    )

    printf '%s\n' "$repo"
}

write_report() {
    checkpoint="$1"
    base="$2"
    reviewed="$3"
    review_type="${4:-targeted-external}"
    report="security/pentest/2.0-development/${checkpoint}.md"

    cat >"$report" <<EOF
Status: PASS
Checkpoint: ${checkpoint}
Base-Commit: ${base}
Reviewed-Through: ${reviewed}
Tester: Checkpoint Test
Review-Type: ${review_type}
Scope: Fixture checkpoint range.
Date: 2026-07-16
EOF
}

accept_cp00() {
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "Accept CP-00"
}

repo="$(make_fixture bad-checkpoint)"
(
    cd "$repo"
    assert_fails_with "usage: scripts/validate-2.0-checkpoint.sh CP-XX" \
        scripts/validate-2.0-checkpoint.sh CP-24
)

repo="$(make_fixture scratch-pentest)"
(
    cd "$repo"
    printf 'scratch\n' >PENTEST.md
    assert_fails_with "root PENTEST.md is temporary scratch input" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture missing-report)"
(
    cd "$repo"
    assert_fails_with "missing checkpoint report" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture uncommitted-report)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    assert_fails_with "checkpoint report must be committed at HEAD" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture malformed-report)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed" unsupported-review
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "bad report"
    assert_fails_with "unsupported Review-Type" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture malformed-hash)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1 | tr 'a-f' 'A-F')"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "bad hash report"
    assert_fails_with "Base-Commit must use a full lowercase hexadecimal hash" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture stale-reviewed-through)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$base"
    write_report CP-00 "$base" "$reviewed"
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "stale report"
    assert_fails_with "checkpoint range must contain at least one implementation commit" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture wrong-base)"
(
    cd "$repo"
    reviewed="$(git rev-parse HEAD)"
    printf 'unrelated\n' >unrelated.txt
    git add unrelated.txt
    git commit -q -m "extra implementation"
    reviewed="$(git rev-parse HEAD)"
    wrong_base="$(git rev-parse HEAD~1)"
    write_report CP-00 "$wrong_base" "$reviewed"
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "wrong base report"
    assert_fails_with "does not match expected" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture mixed-report-commit)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    printf 'changed\n' >>README.md
    git add README.md security/pentest/2.0-development/CP-00.md
    git commit -q -m "report plus source"
    assert_fails_with "checkpoint report commit may only change" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture cp00-ready)"
(
    cd "$repo"
    accept_cp00
    scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture cp01-ready)"
(
    cd "$repo"
    accept_cp00
    cp00_acceptance="$(git rev-parse HEAD)"

    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt
    git commit -q -m "CP-01 implementation"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-01 "$cp00_acceptance" "$reviewed" independent-audit
    git add security/pentest/2.0-development/CP-01.md
    git commit -q -m "Accept CP-01"

    scripts/validate-2.0-checkpoint.sh CP-01
)

repo="$(make_fixture cp01-wrong-base)"
(
    cd "$repo"
    accept_cp00
    wrong_base="$(git rev-parse HEAD~1)"

    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt
    git commit -q -m "CP-01 implementation"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-01 "$wrong_base" "$reviewed"
    git add security/pentest/2.0-development/CP-01.md
    git commit -q -m "Wrong CP-01 report"

    assert_fails_with "does not match expected" \
        scripts/validate-2.0-checkpoint.sh CP-01
)

repo="$(make_fixture cp01-modified-prior-report)"
(
    cd "$repo"
    accept_cp00
    cp00_acceptance="$(git rev-parse HEAD)"

    printf '\nmodified\n' >>security/pentest/2.0-development/CP-00.md
    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt security/pentest/2.0-development/CP-00.md
    git commit -q -m "CP-01 implementation with report tamper"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-01 "$cp00_acceptance" "$reviewed"
    git add security/pentest/2.0-development/CP-01.md
    git commit -q -m "CP-01 report"

    assert_fails_with "previous accepted report was modified" \
        scripts/validate-2.0-checkpoint.sh CP-01
)

echo "2.0 checkpoint validator tests passed"
