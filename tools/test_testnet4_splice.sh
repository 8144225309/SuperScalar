#!/usr/bin/env bash
# test_testnet4_splice.sh — BOLT-2 splice on real testnet4.
#
# Validates the splice protocol (STFU → SPLICE_INIT → SPLICE_ACK →
# SPLICE_CREATED → SPLICE_LOCKED) end-to-end on testnet4.  Regtest
# coverage exists via --test-splice in manual_tests.py; this is the
# real-chain counterpart.
#
# Pass criteria:
#   1. Factory funded + tree broadcast on testnet4
#   2. Splice-out 10k sats from channel[0] succeeds
#   3. Splice TX confirms on testnet4 chain
#   4. Both sides log "SPLICE_LOCKED"
#
# Wall time: ~30-60 min (depends on testnet4 block timing).

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build}"
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
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!

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
    > "/tmp/ss_t4_${TAG}_c0.log" 2>&1 &
CLIENT_PID=$!

wait $LSP_PID
EXIT=$?
pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true

echo "EXIT=$EXIT" > "$DONE"
echo "=== splice test done $(date) exit=$EXIT ===" >> "$DONE"
grep -E "SPLICE_LOCKED|splice.*confirmed|splice.*failed|SPLICE OK" "$LSP_LOG" | tail -5 >> "$DONE"
cat "$DONE"
exit $EXIT
