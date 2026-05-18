#!/usr/bin/env bash
# test_regtest_ptlc_restart.sh — TS-PTLC-RESTART (#109, SF-W-PTLC Phase 3c)
# Validate schema v30 PTLC persistence:
#   - add PTLC, register with watchtower (persists to DB)
#   - close + reopen persist DB (simulates LSP restart)
#   - load PTLCs from reopened DB
#   - verify fields match
#
# In-process scaffold (one LSP invocation). For true process-level restart,
# a 2-stage runner would split add-and-save from load-and-verify; that
# variant is left for the testnet4 deliverable.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

TAG="ptlc_restart"
PORT="${PORT:-29962}"
CLIENTS=4
ARITY=2
WALLET="${WALLET:-ss_cheat_leaf_miner}"
AMOUNT="${AMOUNT:-200000}"
LSPDB="/tmp/ss_rt_${TAG}.db"
LOG="/tmp/ss_rt_${TAG}_lsp.log"
DONE="/tmp/ss_rt_${TAG}.done"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
RPCUSER="${RPCUSER:-rpcuser}"
RPCPASS="${RPCPASS:-rpcpass}"
RPCPORT="${RPCPORT:-18443}"

bitcoin-cli -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" loadwallet "$WALLET" >/dev/null 2>&1 || true
rm -rf /tmp/ss_rt_${TAG}*
pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true

echo "=== --test-ptlc-restart regtest (#109, SF-W-PTLC Phase 3c) ==="
echo "  port=$PORT  clients=$CLIENTS  arity=$ARITY  amount=$AMOUNT"

nohup "$LSP_BIN" \
  --network regtest --port "$PORT" \
  --demo --test-ptlc-restart --lsp-balance-pct 50 \
  --clients "$CLIENTS" --arity "$ARITY" \
  --amount "$AMOUNT" --fee-rate 1100 --confirm-timeout 86400 \
  --seckey 0000000000000000000000000000000000000000000000000000000000000001 \
  --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
  --wallet "$WALLET" --db "$LSPDB" \
  > "$LOG" 2>&1 &
LSP_PID=$!

for i in $(seq 1 30); do
    sleep 1
    grep -q "listening" "$LOG" 2>/dev/null && break
done

for N in 1 2 3 4; do
    HEX=$(printf "%02x" $((N * 0x11)))
    SK=""
    for _ in $(seq 1 32); do SK="${SK}${HEX}"; done
    nohup "$CLIENT_BIN" \
      --network regtest --host 127.0.0.1 --port "$PORT" --daemon \
      --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 \
      --lsp-pubkey "$LSP_PUB" --participant-id "$N" \
      --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
      --wallet "$WALLET" --db "/tmp/ss_rt_${TAG}_c${N}.db" \
      > "/tmp/ss_rt_${TAG}_c${N}.log" 2>&1 &
    sleep 0.3
done

wait $LSP_PID
EXIT=$?
pkill -f "superscalar_client.*--port $PORT" 2>/dev/null || true
echo "EXIT=$EXIT" > "$DONE"

if [ "$EXIT" -eq 0 ] && grep -q "PTLC RESTART TEST PASSED" "$LOG"; then
    echo "=== PASS: TS-PTLC-RESTART ==="
    grep -E "PTLC RESTART|PTLC added|Watchtower entry|Persist DB|PTLC loaded|safety gate" "$LOG" | head -20
    exit 0
else
    echo "=== FAIL: exit=$EXIT, see $LOG ==="
    tail -40 "$LOG"
    exit 1
fi
