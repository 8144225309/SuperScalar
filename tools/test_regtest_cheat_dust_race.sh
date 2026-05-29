#!/usr/bin/env bash
# test_regtest_cheat_dust_race.sh — #257 SF-CHEAT-DUST-RACE smoke test.
#
# Validates --cheat-dust-race on regtest:
#
#   1. LSP arms the cheat at startup ("LSP-CHEAT-DUST: armed" marker).
#   2. SS_CHEAT_DUST_RACE env var propagates to libsuperscalar (verified by
#      running the matching unit subset under the env override and observing
#      the LSP-CHEAT-DUST bypass markers in test_superscalar stderr).
#   3. The honest defense still rejects abusive feerates without the flag.
#
# The on-chain dance (set up borderline-amount HTLC, push update_fee, force
# close, watch the HTLC absorbed into commit fees) requires a multi-binary
# choreography that the existing regtest harness does not yet expose to
# external drivers. The cheat-engine harness lands here as the
# arm-and-validate-wiring smoke; the deep on-chain behavior is exercised
# by the DR1-DR7 unit suite (tests/test_dust_recovery.c) which directly
# drives htlc_commit_recv_update_fee with and without the env override.
#
# When the on-chain hook lands in a follow-up, this script's step (3) will
# be replaced by an LSP --demo --cheat-dust-race run that exercises the
# full force-close path.
#
# Usage: bash tools/test_regtest_cheat_dust_race.sh [BUILD_DIR]

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar-dust-race-impl/build-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
TEST_BIN="$BUILD_DIR/test_superscalar"

if [ ! -x "$LSP_BIN" ]; then
    echo "FAIL: superscalar_lsp not found at $LSP_BIN"
    exit 1
fi
if [ ! -x "$TEST_BIN" ]; then
    echo "FAIL: test_superscalar not found at $TEST_BIN"
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/ss-cheat-dust-race.XXXXXX)
LSP_LOG="$TMPDIR/lsp.log"
UNIT_LOG="$TMPDIR/unit.log"

cleanup() {
    cp "$LSP_LOG"  /tmp/cheat_dust_race_last_lsp.log  2>/dev/null || true
    cp "$UNIT_LOG" /tmp/cheat_dust_race_last_unit.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== SF-CHEAT-DUST-RACE (#257) regtest smoke ==="
echo "  BUILD_DIR : $BUILD_DIR"
echo "  LSP_BIN   : $LSP_BIN"
echo "  TEST_BIN  : $TEST_BIN"
echo

# ----------------------------------------------------------------------
# Step 1: --cheat-dust-race emits the arm marker
# ----------------------------------------------------------------------
echo "--- Step 1: --cheat-dust-race arms the cheat (stderr marker) ---"
# Use --help so the LSP exits immediately after arg parsing, then look for
# the arm marker.  --cheat-dust-race calls setenv + fprintf during arg
# parsing — the marker fires before the help text is printed.
"$LSP_BIN" --cheat-dust-race --help 2>"$LSP_LOG" 1>/dev/null || true

if grep -q "LSP-CHEAT-DUST: armed" "$LSP_LOG"; then
    echo "  PASS: arm marker present"
else
    echo "  FAIL: arm marker missing"
    echo "  LSP stderr (first 20 lines):"
    head -20 "$LSP_LOG"
    exit 1
fi

# ----------------------------------------------------------------------
# Step 2: --cheat-dust-race appears in --help
# ----------------------------------------------------------------------
echo
echo "--- Step 2: --cheat-dust-race appears in --help ---"
HELP_OUT=$("$LSP_BIN" --help 2>&1)
if grep -q "cheat-dust-race" <<<"$HELP_OUT"; then
    echo "  PASS: flag documented in --help"
else
    echo "  FAIL: flag missing from --help"
    exit 1
fi

# ----------------------------------------------------------------------
# Step 3: Unit suite under SS_CHEAT_DUST_RACE=1 emits bypass markers
# ----------------------------------------------------------------------
echo
echo "--- Step 3: htlc_commit cheat path emits LSP-CHEAT-DUST markers ---"
"$TEST_BIN" 2>"$UNIT_LOG" 1>"$TMPDIR/unit.out" || true

if grep -q "Results: " "$TMPDIR/unit.out"; then
    LINE=$(grep "Results: " "$TMPDIR/unit.out" | tail -1)
    echo "  unit results: $LINE"
fi

DR_BYPASS=$(grep -c "LSP-CHEAT-DUST: bypass" "$UNIT_LOG" || true)
DR_ACCEPT=$(grep -c "LSP-CHEAT-DUST: accept feerate" "$UNIT_LOG" || true)
DR_REJECT=$(grep -c "htlc_commit_recv_update_fee: REJECT" "$UNIT_LOG" || true)

echo "  LSP-CHEAT-DUST bypass markers   : $DR_BYPASS"
echo "  LSP-CHEAT-DUST accept markers   : $DR_ACCEPT"
echo "  honest REJECT markers (defense) : $DR_REJECT"

if [ "$DR_BYPASS" -ge 1 ] && [ "$DR_ACCEPT" -ge 1 ] && [ "$DR_REJECT" -ge 1 ]; then
    echo "  PASS: both cheat-bypass AND honest-reject paths exercised"
else
    echo "  FAIL: missing markers; saw bypass=$DR_BYPASS accept=$DR_ACCEPT reject=$DR_REJECT"
    echo "  unit stderr tail:"
    tail -40 "$UNIT_LOG"
    exit 1
fi

# ----------------------------------------------------------------------
# Step 4: The dust-recovery unit subset must report all PASS
# ----------------------------------------------------------------------
echo
echo "--- Step 4: dust-race unit suite (DR1-DR7) ---"
if grep -q "#257 SF-CHEAT-DUST-RACE" "$TMPDIR/unit.out"; then
    # Count the OK after each test_dust_race_ line.
    PASS=$(grep -c "test_dust_race_.* OK" "$TMPDIR/unit.out" || true)
    echo "  DR tests PASS: $PASS / 7"
    if [ "$PASS" -ge 7 ]; then
        echo "  PASS: all 7 dust-race units green"
    else
        echo "  FAIL: dust-race unit count $PASS < 7"
        grep -A2 "test_dust_race_" "$TMPDIR/unit.out" | head -40
        exit 1
    fi
else
    echo "  FAIL: SF-CHEAT-DUST-RACE section not found in unit output"
    exit 1
fi

echo
echo "=== SF-CHEAT-DUST-RACE smoke: PASS ==="
exit 0
