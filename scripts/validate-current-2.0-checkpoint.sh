#!/usr/bin/env sh
set -eu

REPORT_DIR='security/pentest/2.0-development'
CP00_BASE='62411d236f651159f82b4db6422f242488a9e94c'

fail() {
    echo "validate-current-2.0-checkpoint: $1" >&2
    exit 1
}

reports_at_head="$(
    git ls-tree -r --name-only HEAD -- "$REPORT_DIR" |
        grep -E "^${REPORT_DIR}/CP-[0-9][0-9]\.md$" || true
)"

if ! git cat-file -e "${CP00_BASE}^{commit}" 2>/dev/null; then
    if [ -n "$reports_at_head" ] || [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
        fail "complete history through the CP-00 base is required"
    fi
    exit 0
fi

git merge-base --is-ancestor "$CP00_BASE" HEAD \
    || fail "CP-00 base is not an ancestor of HEAD"

merge_commit="$(
    git rev-list --merges "${CP00_BASE}..HEAD" |
        sed -n '1p'
)"
[ -z "$merge_commit" ] \
    || fail "checkpoint history must be linear; merge commit ${merge_commit} is not permitted"

found_report_commit=false
for commit in $(
    git rev-list --reverse --first-parent "${CP00_BASE}..HEAD"
); do
    changed_reports="$(
        git diff-tree --root --first-parent --no-commit-id --name-only -r \
            "$commit" -- ":(glob)${REPORT_DIR}/CP-*.md"
    )"
    [ -n "$changed_reports" ] || continue
    found_report_commit=true

    count="$(
        printf '%s\n' "$changed_reports" |
            sed '/^$/d' |
            wc -l |
            tr -d ' '
    )"
    [ "$count" -eq 1 ] \
        || fail "commit ${commit} changes multiple checkpoint reports"

    report="$(printf '%s\n' "$changed_reports" | sed -n '1p')"
    case "$report" in
        "$REPORT_DIR"/CP-[0-9][0-9].md) ;;
        *) fail "unexpected checkpoint report path: ${report}" ;;
    esac

    checkpoint="$(basename "$report" .md)"
    scripts/validate-2.0-checkpoint.sh "$checkpoint" "$commit"
done

if [ -n "$reports_at_head" ] && ! $found_report_commit; then
    fail "permanent checkpoint reports exist without an acceptance commit"
fi
