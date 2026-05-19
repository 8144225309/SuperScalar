#!/usr/bin/env bash

# Self-respawn in own session so systemd-logind cleanup on SSH session end
# doesn't kill us mid-run (lesson from 2026-05-18 dual #112/#189 deaths).
# Skip if already respawned or if running interactively (stdin is a tty).
if [ -z "${_SS_TESTNET4_DETACHED:-}" ] && [ ! -t 0 ]; then
    export _SS_TESTNET4_DETACHED=1
    exec setsid "$0" "$@"
fi

# test_testnet4_splice.sh — BOLT-2 splice WIRE-CODEC SMOKE on real testnet4.
#
# CAVEAT: this is NOT a full BOLT-2 splice end-to-end.  SuperScalar's
# current splice implementation is a wire-codec stub (#198 SF-SPLICE-FULL
# tracks the real version).  In particular:
#   - LSP never contributes to the splice TX (acceptor_contribution = 0).
#   - LSP doesn't participate in building the splice TX (no interactive-tx).
#   - LSP doesn't sign the splice TX (no MuSig ceremony for splice).
#   - SPLICE_LOCKED records the new outpoint but keeps the old funding_amount.
#
# This runner exercises ONLY:
#   1. STFU/STFU_ACK quiescence flow.
#   2. SPLICE_INIT → SPLICE_ACK wire round-trip.
#   3. Client builds + broadcasts a splice TX externally (NOT collaborative).
#   4. SPLICE_LOCKED wire round-trip + channel outpoint update on the LSP side.
#
# PASS here means the wire codec works on testnet4.  It does NOT prove
# splice would work against an external Lightning peer (CLN/LND).  That
# requires the full implementation in #198.
#
# Wall time: ~30-60 min (depends on testnet4 block timing).

set -euo pipefail

# shellcheck source=test_diag_lib.sh
source "$(dirname "$0")/test_diag_lib.sh"

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

NETWORK="testnet4"
RPCUSER="${RPCUSER:-testnet4rpc}"
RPCPASS="${RPCPASS:-testnet4rpcpass123}"
RPCPORT="${RPCPORT:-48332}"
WALLET="${WALLET:-superscalar_test}"

PORT="${PORT:-9935}"
N_CLIENTS=1  # splice test = 1 client + LSP (was N=2 with only 1 launched — #193)
AMOUNT="${AMOUNT:-200000}"

TAG="ts_splice"
LSP_DB="/tmp/ss_t4_${TAG}.db"
LSP_LOG="/tmp/ss_t4_${TAG}_lsp.log"
DONE="/tmp/ss_t4_${TAG}.done"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

CLIENT_SECKEY="0000000000000000000000000000000000000000000000000000000000000002"

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$DONE"
# Also clean the client DB — stale schema (eg v36 left by a release-build
# run, then a build/ run tries to open it with v34 binary) hangs the test
# with "DB schema version > code version" at client startup.
rm -f "/tmp/ss_t4_${TAG}_c0.db" "/tmp/ss_t4_${TAG}_c0.db-shm" \
      "/tmp/ss_t4_${TAG}_c0.db-wal" "/tmp/ss_t4_${TAG}_c0.log"
diag_setup "ss_t4_${TAG}"
diag_enable_core_dumps

echo "=== testnet4 splice test ==="
echo "  port      : $PORT"
echo "  wallet    : $WALLET"
echo "  network   : $NETWORK"
echo "  funding   : $AMOUNT sats"

nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --clients "$N_CLIENTS" --arity 1 --amount "$AMOUNT" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate 1100 --lsp-balance-pct 100 \
    --confirm-timeout 86400 \
    --seckey 0000000000000000000000000000000000000000000000000000000000000001 \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    --demo --test-splice \
    --test-splice-client-seckey "$CLIENT_SECKEY" \
    > "$LSP_LOG" 2> "$(diag_stderr_path lsp)" &
LSP_PID=$!
diag_periodic "$LSP_PID" 60

for i in $(seq 1 30); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
done

nohup "$CLIENT_BIN" \
    --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
    --seckey "$CLIENT_SECKEY" --fee-rate 1100 --lsp-balance-pct 100 \
    --lsp-pubkey "$LSP_PUBKEY" --participant-id 1 \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c0.db" \
    > "/tmp/ss_t4_${TAG}_c0.log" 2> "$(diag_stderr_path client0)" &
CLIENT_PID=$!

diag_wait_lsp "$LSP_PID" "$LSP_LOG" "ss_t4_${TAG}"
EXIT=$DIAG_EXIT
pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true

echo "EXIT=$EXIT" > "$DONE"
echo "=== splice test done $(date) exit=$EXIT ===" >> "$DONE"
grep -E "SPLICE_LOCKED|splice.*confirmed|splice.*failed|SPLICE OK" "$LSP_LOG" | tail -5 >> "$DONE"
cat "$DONE"
exit $EXIT
