#!/usr/bin/env sh
set -eu

REPORT_DIR='security/pentest/2.0-development'

fail() {
    echo "validate-current-2.0-checkpoint: $1" >&2
    exit 1
}

changed_reports="$(
    git diff-tree --no-commit-id --name-only -r HEAD -- \
        ":(glob)${REPORT_DIR}/CP-*.md"
)"

if [ -z "$changed_reports" ]; then
    exit 0
fi

count="$(printf '%s\n' "$changed_reports" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$count" -eq 1 ] || fail "exactly one checkpoint report may change"

report="$(printf '%s\n' "$changed_reports" | sed -n '1p')"
case "$report" in
    "$REPORT_DIR"/CP-[0-9][0-9].md) ;;
    *) fail "unexpected checkpoint report path: ${report}" ;;
esac

checkpoint="$(basename "$report" .md)"
scripts/validate-2.0-checkpoint.sh "$checkpoint"
