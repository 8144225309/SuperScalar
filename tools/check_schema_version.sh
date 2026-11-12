#!/usr/bin/env bash
# check_schema_version.sh — the persisted schema version moves one step at a time.
#
# Usage: tools/check_schema_version.sh BASE_REF
#
# Compares PERSIST_SCHEMA_VERSION in include/superscalar/persist.h of the
# working tree with its value at the merge-base of HEAD and BASE_REF (for a
# pull request: origin/<target branch>).  Passes if it is unchanged or one
# higher; fails if it went down, jumped by more than one, or cannot be read.
# Each schema version needs its own migration step, so a change of +2 means a
# version was skipped (or two branches each took the same number).
set -euo pipefail

BASE_REF=${1:?usage: $0 BASE_REF}
HDR=include/superscalar/persist.h

cd "$(git rev-parse --show-toplevel)"

version_of() {   # stdin: persist.h
    sed -n 's/^#define[[:space:]]\{1,\}PERSIST_SCHEMA_VERSION[[:space:]]\{1,\}\([0-9]\{1,\}\)[[:space:]]*$/\1/p'
}

MB=$(git merge-base HEAD "$BASE_REF") || { echo "FAIL: no merge-base of HEAD and $BASE_REF"; exit 1; }
BASE=$(git show "$MB:$HDR" | version_of)
HEAD_V=$(version_of < "$HDR")

if [ "$(printf '%s\n' "$BASE" | wc -l)" -ne 1 ] || [ -z "$BASE" ]; then
    echo "FAIL: cannot read PERSIST_SCHEMA_VERSION from $HDR at $MB"; exit 1
fi
if [ "$(printf '%s\n' "$HEAD_V" | wc -l)" -ne 1 ] || [ -z "$HEAD_V" ]; then
    echo "FAIL: cannot read PERSIST_SCHEMA_VERSION from $HDR"; exit 1
fi

if [ "$HEAD_V" -eq "$BASE" ]; then
    echo "PERSIST_SCHEMA_VERSION unchanged ($BASE, merge-base ${MB:0:12})"
elif [ "$HEAD_V" -eq $((BASE + 1)) ]; then
    echo "PERSIST_SCHEMA_VERSION $BASE -> $HEAD_V (merge-base ${MB:0:12})"
else
    echo "FAIL: PERSIST_SCHEMA_VERSION $BASE -> $HEAD_V (merge-base ${MB:0:12});"
    echo "      a change may only raise it by one, with its migration."
    exit 1
fi
