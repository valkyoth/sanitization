#!/usr/bin/env sh
set -eu

CP00_BASE='62411d236f651159f82b4db6422f242488a9e94c'
PLAN='docs/IMPLEMENTATION_PLAN_2.0.0.md'
REPORT_DIR='security/pentest/2.0-development'

fail() {
    echo "validate-2.0-checkpoint: $1" >&2
    exit 1
}

regular_blob_mode() {
    commit="$1"
    path="$2"
    entry="$(git ls-tree "$commit" -- "$path")"
    mode="$(printf '%s\n' "$entry" | awk '{print $1}')"
    object_type="$(printf '%s\n' "$entry" | awk '{print $2}')"

    [ "$mode" = "100644" ] && [ "$object_type" = "blob" ]
}

committed_field() {
    source="$1"
    name="$2"
    count="$(grep -c "^${name}: " "$source" || true)"
    if [ "$count" -ne 1 ]; then
        fail "${report} must contain exactly one ${name} field"
    fi
    sed -n "s/^${name}: //p" "$source"
}

checkpoint="${1:-}"
case "$checkpoint" in
    CP-0[0-9] | CP-1[0-9] | CP-2[0-3]) ;;
    *)
        echo "usage: scripts/validate-2.0-checkpoint.sh CP-XX" >&2
        exit 2
        ;;
esac

report="${REPORT_DIR}/${checkpoint}.md"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
committed_report="$tmp/report"
previous_metadata="$tmp/previous-report"

if [ -f PENTEST.md ] || [ -f pentest.md ]; then
    fail "root PENTEST.md is temporary scratch input and must be removed"
fi

if [ ! -f "$PLAN" ]; then
    fail "missing implementation plan: ${PLAN}"
fi

if ! grep -Fq "### \`${checkpoint}\`:" "$PLAN"; then
    fail "checkpoint ${checkpoint} is not defined in ${PLAN}"
fi

if ! grep -Fq "\`${report}\`" "$PLAN"; then
    fail "report path ${report} is not registered in ${PLAN}"
fi

if [ ! -f "$report" ]; then
    fail "missing checkpoint report: ${report}"
fi

if ! git cat-file -e "HEAD:${report}" 2>/dev/null; then
    fail "checkpoint report must be committed at HEAD: ${report}"
fi

regular_blob_mode HEAD "$report" \
    || fail "checkpoint report must be a regular non-executable Git blob"

git show "HEAD:${report}" >"$committed_report" \
    || fail "could not read committed checkpoint report"

status="$(committed_field "$committed_report" Status)"
reported_checkpoint="$(committed_field "$committed_report" Checkpoint)"
base_commit="$(committed_field "$committed_report" Base-Commit)"
reviewed_through="$(committed_field "$committed_report" Reviewed-Through)"
tester="$(committed_field "$committed_report" Tester)"
review_type="$(committed_field "$committed_report" Review-Type)"
scope="$(committed_field "$committed_report" Scope)"
date="$(committed_field "$committed_report" Date)"

if [ "$status" != "PASS" ]; then
    fail "${report} Status must be PASS"
fi

if [ "$reported_checkpoint" != "$checkpoint" ]; then
    fail "${report} Checkpoint must be ${checkpoint}"
fi

if ! printf '%s\n' "$base_commit" | grep -Eq '^[0-9a-f]{40}$'; then
    fail "Base-Commit must use a full lowercase hexadecimal hash"
fi

if ! printf '%s\n' "$reviewed_through" | grep -Eq '^[0-9a-f]{40}$'; then
    fail "Reviewed-Through must use a full lowercase hexadecimal hash"
fi

[ -n "$tester" ] || fail "Tester must not be empty"
[ -n "$scope" ] || fail "Scope must not be empty"

case "$review_type" in
    targeted-internal | targeted-external | independent-audit | pentest | close-out) ;;
    *) fail "unsupported Review-Type: ${review_type}" ;;
esac

case "$date" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) fail "Date must use YYYY-MM-DD" ;;
esac

git cat-file -e "${base_commit}^{commit}" 2>/dev/null \
    || fail "Base-Commit ${base_commit} was not found"
git cat-file -e "${reviewed_through}^{commit}" 2>/dev/null \
    || fail "Reviewed-Through ${reviewed_through} was not found"

if [ "$base_commit" = "$reviewed_through" ]; then
    fail "checkpoint range must contain at least one implementation commit"
fi

if ! git merge-base --is-ancestor "$base_commit" "$reviewed_through"; then
    fail "Base-Commit is not an ancestor of Reviewed-Through"
fi

head_parent="$(git rev-parse HEAD^)"
if [ "$reviewed_through" != "$head_parent" ]; then
    fail "Reviewed-Through ${reviewed_through} does not match report parent ${head_parent}"
fi

changed_paths="$(git diff-tree --no-commit-id --name-only -r HEAD)"
if [ "$changed_paths" != "$report" ]; then
    fail "checkpoint report commit may only change ${report}"
fi

if [ "$checkpoint" = "CP-00" ]; then
    expected_base="$CP00_BASE"
else
    digits="${checkpoint#CP-}"
    number="$(printf '%s' "$digits" | sed 's/^0//')"
    previous_number="$((number - 1))"
    previous_checkpoint="$(printf 'CP-%02d' "$previous_number")"
    previous_report="${REPORT_DIR}/${previous_checkpoint}.md"

    if ! git cat-file -e "${reviewed_through}:${previous_report}" 2>/dev/null; then
        fail "previous accepted report is missing at Reviewed-Through: ${previous_report}"
    fi

    acceptance_commit="$(
        git log --first-parent --diff-filter=A --reverse --format=%H \
            "$reviewed_through" -- "$previous_report" |
            sed -n '1p'
    )"
    [ -n "$acceptance_commit" ] \
        || fail "could not locate acceptance commit for ${previous_checkpoint}"

    regular_blob_mode "$acceptance_commit" "$previous_report" \
        || fail "previous checkpoint report is not a regular Git blob"
    git show "${acceptance_commit}:${previous_report}" >"$previous_metadata" \
        || fail "could not read previous committed report"

    previous_status="$(committed_field "$previous_metadata" Status)"
    previous_reported_checkpoint="$(committed_field "$previous_metadata" Checkpoint)"
    previous_reviewed="$(committed_field "$previous_metadata" Reviewed-Through)"

    [ "$previous_status" = "PASS" ] \
        || fail "previous checkpoint report Status must be PASS"
    [ "$previous_reported_checkpoint" = "$previous_checkpoint" ] \
        || fail "previous checkpoint report identity is invalid"
    printf '%s\n' "$previous_reviewed" | grep -Eq '^[0-9a-f]{40}$' \
        || fail "previous report contains an invalid Reviewed-Through"
    git cat-file -e "${previous_reviewed}^{commit}" 2>/dev/null \
        || fail "previous Reviewed-Through ${previous_reviewed} was not found"

    acceptance_parent="$(git rev-parse "${acceptance_commit}^")"
    [ "$acceptance_parent" = "$previous_reviewed" ] \
        || fail "previous acceptance is not the direct child of Reviewed-Through"

    acceptance_paths="$(
        git diff-tree --no-commit-id --name-only -r "$acceptance_commit"
    )"
    [ "$acceptance_paths" = "$previous_report" ] \
        || fail "previous acceptance commit was not report-only"

    for commit in $(
        git rev-list --first-parent "${acceptance_commit}..${reviewed_through}"
    ); do
        changed_reports="$(
            git diff-tree --first-parent --no-commit-id --name-only -r \
                "$commit" -- "$REPORT_DIR"
        )"
        if [ -n "$changed_reports" ]; then
            fail "an accepted checkpoint report was modified or replaced"
        fi
    done

    if ! git diff --quiet "$acceptance_commit" "$reviewed_through" -- "$REPORT_DIR"; then
        fail "an accepted checkpoint report was modified or replaced"
    fi

    expected_base="$acceptance_commit"
fi

if [ "$base_commit" != "$expected_base" ]; then
    fail "Base-Commit ${base_commit} does not match expected ${expected_base}"
fi

range_count="$(git rev-list --count "${base_commit}..${reviewed_through}")"
if [ "$range_count" -lt 1 ]; then
    fail "review range contains no implementation commit"
fi

echo "validated ${checkpoint}: ${base_commit}..${reviewed_through}"
