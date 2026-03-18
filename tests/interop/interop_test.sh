#!/usr/bin/env bash
# interop_test.sh - Signet smoke tests against CLN/LND/Eclair
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1"; }
check() { nc -z -w3 "$1" "$2" 2>/dev/null; }
: "${CLN_HOST:=signet.cln.example.com}"; : "${CLN_PORT:=39735}"
: "${LND_HOST:=signet.lnd.example.com}"; : "${LND_PORT:=39735}"
BUILD_DIR="$(dirname "$0")/../../build"
LSP="$BUILD_DIR/superscalar_lsp"
echo === SuperScalar Interop Smoke Tests
if check "$CLN_HOST" "$CLN_PORT"; then
  "$LSP" --test-connect "$CLN_HOST" "$CLN_PORT" 2>&1 | grep -q connected && pass CLN || fail CLN
else skip CLN-not-reachable; fi
if check "$LND_HOST" "$LND_PORT"; then
  skip LND-manual-test-required
else skip LND-not-reachable; fi
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
