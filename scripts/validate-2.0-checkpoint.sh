#!/usr/bin/env sh
set -eu

CP00_BASE='62411d236f651159f82b4db6422f242488a9e94c'
PLAN='docs/IMPLEMENTATION_PLAN_2.0.0.md'

fail() {
    echo "validate-2.0-checkpoint: $1" >&2
    exit 1
}

checkpoint="${1:-}"
case "$checkpoint" in
    CP-0[0-9] | CP-1[0-9] | CP-2[0-3]) ;;
    *)
        echo "usage: scripts/validate-2.0-checkpoint.sh CP-XX" >&2
        exit 2
        ;;
esac

report="security/pentest/2.0-development/${checkpoint}.md"

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

field() {
    name="$1"
    count="$(grep -c "^${name}: " "$report" || true)"
    if [ "$count" -ne 1 ]; then
        fail "${report} must contain exactly one ${name} field"
    fi
    sed -n "s/^${name}: //p" "$report"
}

status="$(field Status)"
reported_checkpoint="$(field Checkpoint)"
base_commit="$(field Base-Commit)"
reviewed_through="$(field Reviewed-Through)"
tester="$(field Tester)"
review_type="$(field Review-Type)"
scope="$(field Scope)"
date="$(field Date)"

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
    previous_report="security/pentest/2.0-development/${previous_checkpoint}.md"

    if ! git cat-file -e "${reviewed_through}:${previous_report}" 2>/dev/null; then
        fail "previous accepted report is missing at Reviewed-Through: ${previous_report}"
    fi

    expected_base="$(
        git log --diff-filter=A -1 --format=%H "$reviewed_through" -- "$previous_report"
    )"
    [ -n "$expected_base" ] \
        || fail "could not locate acceptance commit for ${previous_checkpoint}"

    if ! git diff --quiet "$expected_base" "$reviewed_through" -- "$previous_report"; then
        fail "previous accepted report was modified after ${expected_base}"
    fi
fi

if [ "$base_commit" != "$expected_base" ]; then
    fail "Base-Commit ${base_commit} does not match expected ${expected_base}"
fi

range_count="$(git rev-list --count "${base_commit}..${reviewed_through}")"
if [ "$range_count" -lt 1 ]; then
    fail "review range contains no implementation commit"
fi

echo "validated ${checkpoint}: ${base_commit}..${reviewed_through}"
