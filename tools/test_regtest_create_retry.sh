#!/usr/bin/env bash
# test_regtest_create_retry.sh -- #48 Phase D proof. The factory-CREATION bounded
# fresh-nonce retry must (1) RECOVER creation from a TRANSIENT bad client partial
# sig (re-init sessions + re-send PROPOSE_INTENT -> clients re-sign with fresh
# nonces -> aggregate verifies -> full lifecycle proceeds), and (2) BOUNDED-ABORT
# a PERSISTENT one (after SS_NONCE_RETRY_MAX rounds the LSP aborts before
# broadcast; nothing is committed on-chain, so the fallback is simply re-create).
#
# Drives the existing N-channel creation+payment+close lifecycle
# (test_regtest_n64_payments.sh, small N) with the gated SS_CHEAT_CREATE_BAD_PSIG
# fault injection (regtest-only via superscalar_cheat_allowed() -- inert on
# mainnet, #9):
#   =1 -> each client corrupts ONLY its first creation psig  (transient)
#   =2 -> each client corrupts EVERY creation psig           (persistent)
#
# Usage: bash tools/test_regtest_create_retry.sh [BUILD_DIR]
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LOG=/tmp/ss_regtest_n64_payments_lsp.log
N="${N_CLIENTS:-4}"; P="${PAYMENTS:-2}"
red(){ printf '\033[31m%s\033[0m\n' "$*"; }; green(){ printf '\033[32m%s\033[0m\n' "$*"; }

echo "=== [1/2] transient (SS_CHEAT_CREATE_BAD_PSIG=1): creation must RETRY then SUCCEED ==="
N_CLIENTS=$N PAYMENTS=$P SS_CHEAT_CREATE_BAD_PSIG=1 bash "$DIR/test_regtest_n64_payments.sh" "$BUILD_DIR"
rc1=$?
nretry=$(grep -cE "re-running with fresh nonces|factory creation retry" "$LOG" 2>/dev/null); nretry=${nretry:-0}
[ "$rc1" -eq 0 ] || { red "FAIL transient: lifecycle rc=$rc1 (creation did not recover)"; exit 1; }
[ "$nretry" -ge 1 ] || { red "FAIL transient: LSP never logged a creation retry (nretry=$nretry)"; exit 1; }
green "PASS transient: creation RETRIED ($nretry x) and the full lifecycle SUCCEEDED"

echo "=== [2/2] persistent (SS_CHEAT_CREATE_BAD_PSIG=2): creation must BOUND then ABORT ==="
N_CLIENTS=$N PAYMENTS=$P SS_CHEAT_CREATE_BAD_PSIG=2 bash "$DIR/test_regtest_n64_payments.sh" "$BUILD_DIR"
rc2=$?
nbound=$(grep -c "factory creation failed after" "$LOG" 2>/dev/null); nbound=${nbound:-0}
[ "$rc2" -ne 0 ] || { red "FAIL persistent: lifecycle unexpectedly succeeded (creation should bound+abort)"; exit 1; }
[ "$nbound" -ge 1 ] || { red "FAIL persistent: LSP never logged the bounded abort (nbound=$nbound)"; exit 1; }
green "PASS persistent: creation BOUNDED + ABORTED after the retry limit (fallback: re-create)"
echo "CREATE_RETRY_TEST PASS"
