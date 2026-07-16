#!/usr/bin/env sh
set -eu

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_script="$(pwd)/scripts/validate-2.0-checkpoint.sh"
source_current_script="$(pwd)/scripts/validate-current-2.0-checkpoint.sh"

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
### `CP-02`: Fixture
`security/pentest/2.0-development/CP-02.md`
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
        cp "$source_current_script" scripts/validate-current-2.0-checkpoint.sh
        sed -i "s/^CP00_BASE=.*/CP00_BASE='${base}'/" scripts/validate-2.0-checkpoint.sh
        sed -i "s/^CP00_BASE=.*/CP00_BASE='${base}'/" scripts/validate-current-2.0-checkpoint.sh
        chmod +x \
            scripts/validate-2.0-checkpoint.sh \
            scripts/validate-current-2.0-checkpoint.sh
        git add \
            scripts/validate-2.0-checkpoint.sh \
            scripts/validate-current-2.0-checkpoint.sh
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

    mkdir -p security/pentest/2.0-development
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

accept_cp01() {
    cp00_acceptance="$(git rev-parse HEAD)"
    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt
    git commit -q -m "CP-01 implementation"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-01 "$cp00_acceptance" "$reviewed" independent-audit
    git add security/pentest/2.0-development/CP-01.md
    git commit -q -m "Accept CP-01"
}

repo="$(make_fixture bad-checkpoint)"
(
    cd "$repo"
    assert_fails_with "usage: scripts/validate-2.0-checkpoint.sh CP-XX \[commit\]" \
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
    assert_fails_with "checkpoint report must be committed at" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture uncommitted-report)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    assert_fails_with "checkpoint report must be committed at" \
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

repo="$(make_fixture working-tree-substitution)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    sed -i 's/^Status: PASS$/Status: FAIL/' \
        security/pentest/2.0-development/CP-00.md
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "committed failed report"
    sed -i 's/^Status: FAIL$/Status: PASS/' \
        security/pentest/2.0-development/CP-00.md

    assert_fails_with "Status must be PASS" \
        scripts/validate-2.0-checkpoint.sh CP-00
)

repo="$(make_fixture symlink-report)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    mv security/pentest/2.0-development/CP-00.md report-target.md
    ln -s "$(pwd)/report-target.md" \
        security/pentest/2.0-development/CP-00.md
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "symlink report"

    assert_fails_with "regular non-executable Git blob" \
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
    scripts/validate-current-2.0-checkpoint.sh
)

repo="$(make_fixture automatic-batched-tip)"
(
    cd "$repo"
    accept_cp00
    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt
    git commit -q -m "CP-01 implementation pushed with CP-00 acceptance"

    scripts/validate-current-2.0-checkpoint.sh
)

repo="$(make_fixture automatic-deleted-only-report)"
(
    cd "$repo"
    accept_cp00
    git rm -q security/pentest/2.0-development/CP-00.md
    git commit -q -m "delete only accepted report"

    assert_fails_with "checkpoint report must be committed at" \
        scripts/validate-current-2.0-checkpoint.sh
)

repo="$(make_fixture automatic-shallow-history)"
(
    cd "$repo"
    accept_cp00
    shallow="$tmp/automatic-shallow-history-clone"
    git clone -q --depth 1 "file://${repo}" "$shallow"
    (
        cd "$shallow"
        assert_fails_with "complete history through the CP-00 base is required" \
            scripts/validate-current-2.0-checkpoint.sh
    )
)

repo="$(make_fixture automatic-invalid-report)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    sed -i 's/^Status: PASS$/Status: FAIL/' \
        security/pentest/2.0-development/CP-00.md
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "invalid automatic report"

    assert_fails_with "Status must be PASS" \
        scripts/validate-current-2.0-checkpoint.sh
)

repo="$(make_fixture automatic-multiple-reports)"
(
    cd "$repo"
    printf 'one\n' >security/pentest/2.0-development/CP-00.md
    printf 'two\n' >security/pentest/2.0-development/CP-01.md
    git add security/pentest/2.0-development
    git commit -q -m "multiple reports"

    assert_fails_with "changes multiple checkpoint reports" \
        scripts/validate-current-2.0-checkpoint.sh
)

repo="$(make_fixture cp01-ready)"
(
    cd "$repo"
    accept_cp00
    accept_cp01

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

repo="$(make_fixture cp01-invalid-prior-metadata)"
(
    cd "$repo"
    base="$(git rev-parse HEAD~1)"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-00 "$base" "$reviewed"
    sed -i \
        -e 's/^Base-Commit: .*/Base-Commit: 0000000000000000000000000000000000000000/' \
        -e 's/^Tester: .*/Tester: /' \
        -e 's/^Review-Type: .*/Review-Type: unsupported/' \
        -e 's/^Scope: .*/Scope: /' \
        -e 's/^Date: .*/Date: invalid/' \
        security/pentest/2.0-development/CP-00.md
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "Accept malformed CP-00"
    malformed_acceptance="$(git rev-parse HEAD)"

    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt
    git commit -q -m "CP-01 implementation"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-01 "$malformed_acceptance" "$reviewed"
    git add security/pentest/2.0-development/CP-01.md
    git commit -q -m "CP-01 report"

    assert_fails_with "Tester must not be empty" \
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

    assert_fails_with "accepted checkpoint report was modified or replaced" \
        scripts/validate-2.0-checkpoint.sh CP-01
)

repo="$(make_fixture cp01-delete-readd-prior-report)"
(
    cd "$repo"
    accept_cp00

    git rm -q security/pentest/2.0-development/CP-00.md
    printf 'unreviewed security change\n' >security-change.txt
    git add security-change.txt
    git commit -q -m "delete report with unreviewed change"

    base="$(git rev-parse HEAD~3)"
    original_reviewed="$(git rev-parse HEAD~2)"
    write_report CP-00 "$base" "$original_reviewed"
    git add security/pentest/2.0-development/CP-00.md
    git commit -q -m "re-add prior report"
    forged_base="$(git rev-parse HEAD)"

    printf 'checkpoint one\n' >checkpoint-one.txt
    git add checkpoint-one.txt
    git commit -q -m "CP-01 implementation"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-01 "$forged_base" "$reviewed"
    git add security/pentest/2.0-development/CP-01.md
    git commit -q -m "CP-01 report after reset"

    assert_fails_with "accepted checkpoint report was modified or replaced" \
        scripts/validate-2.0-checkpoint.sh CP-01
)

repo="$(make_fixture cp02-modified-older-report)"
(
    cd "$repo"
    accept_cp00
    accept_cp01
    cp01_acceptance="$(git rev-parse HEAD)"

    printf '\nmodified during CP-02\n' \
        >>security/pentest/2.0-development/CP-00.md
    printf 'checkpoint two\n' >checkpoint-two.txt
    git add checkpoint-two.txt security/pentest/2.0-development/CP-00.md
    git commit -q -m "CP-02 implementation with older report tamper"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-02 "$cp01_acceptance" "$reviewed"
    git add security/pentest/2.0-development/CP-02.md
    git commit -q -m "CP-02 report"

    assert_fails_with "accepted checkpoint report was modified or replaced" \
        scripts/validate-2.0-checkpoint.sh CP-02
)

repo="$(make_fixture cp02-deleted-older-report)"
(
    cd "$repo"
    accept_cp00
    accept_cp01
    cp01_acceptance="$(git rev-parse HEAD)"

    git rm -q security/pentest/2.0-development/CP-00.md
    printf 'checkpoint two\n' >checkpoint-two.txt
    git add checkpoint-two.txt
    git commit -q -m "CP-02 implementation deleting older report"
    reviewed="$(git rev-parse HEAD)"
    write_report CP-02 "$cp01_acceptance" "$reviewed"
    git add security/pentest/2.0-development/CP-02.md
    git commit -q -m "CP-02 report"

    assert_fails_with "accepted checkpoint report was modified or replaced" \
        scripts/validate-2.0-checkpoint.sh CP-02
)

echo "2.0 checkpoint validator tests passed"
