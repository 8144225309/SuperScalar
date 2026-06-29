#!/usr/bin/env bash
# test_regtest_close_retry.sh -- #48 Phase C proof. The LSP's bounded fresh-nonce
# retry must (1) RECOVER a cooperative close from a TRANSIENT bad partial sig, and
# (2) BOUNDED-ABORT a PERSISTENT one (clients then fall back to force-close).
#
# Drives the existing N-channel payment+close lifecycle (test_regtest_n64_payments.sh,
# small N) with the gated SS_CHEAT_CLOSE_BAD_PSIG fault injection (regtest-only via
# superscalar_cheat_allowed() -- inert on mainnet, #9):
#   =1 -> each client corrupts ONLY its first close psig  (transient)
#   =2 -> each client corrupts EVERY close psig           (persistent)
#
# Usage: bash tools/test_regtest_close_retry.sh [BUILD_DIR]
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LOG=/tmp/ss_regtest_n64_payments_lsp.log
N="${N_CLIENTS:-4}"; P="${PAYMENTS:-2}"
red(){ printf '\033[31m%s\033[0m\n' "$*"; }; green(){ printf '\033[32m%s\033[0m\n' "$*"; }

echo "=== [1/2] transient (SS_CHEAT_CLOSE_BAD_PSIG=1): close must RETRY then SUCCEED ==="
N_CLIENTS=$N PAYMENTS=$P SS_CHEAT_CLOSE_BAD_PSIG=1 bash "$DIR/test_regtest_n64_payments.sh" "$BUILD_DIR"
rc1=$?
nretry=$(grep -cE "re-running with fresh nonces|retrying with fresh nonces" "$LOG" 2>/dev/null || echo 0)
ncheat=$(grep -c "CHEAT] corrupting close psig" "$LOG" 2>/dev/null || echo 0)   # LSP log won't have it; clients do
[ "$rc1" -eq 0 ] || { red "FAIL transient: lifecycle rc=$rc1 (close did not recover)"; exit 1; }
[ "$nretry" -ge 1 ] || { red "FAIL transient: LSP never logged a retry (nretry=$nretry)"; exit 1; }
green "PASS transient: close RETRIED ($nretry x) and the full lifecycle SUCCEEDED"

echo "=== [2/2] persistent (SS_CHEAT_CLOSE_BAD_PSIG=2): close must BOUND then ABORT ==="
N_CLIENTS=$N PAYMENTS=$P SS_CHEAT_CLOSE_BAD_PSIG=2 bash "$DIR/test_regtest_n64_payments.sh" "$BUILD_DIR"
rc2=$?
nbound=$(grep -c "cooperative close failed after" "$LOG" 2>/dev/null || echo 0)
[ "$rc2" -ne 0 ] || { red "FAIL persistent: lifecycle unexpectedly succeeded (close should bound+abort)"; exit 1; }
[ "$nbound" -ge 1 ] || { red "FAIL persistent: LSP never logged the bounded abort (nbound=$nbound)"; exit 1; }
green "PASS persistent: close BOUNDED + ABORTED after the retry limit (clients fall back to force-close)"
echo "CLOSE_RETRY_TEST PASS"
