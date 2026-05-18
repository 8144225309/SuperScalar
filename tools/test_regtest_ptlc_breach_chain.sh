#!/usr/bin/env bash
# test_regtest_ptlc_breach_chain.sh — #184 Stage A: chain-level PTLC breach.
# Full trustless test: cheat broadcasts revoked commit with PTLC, watchtower
# detects + sweeps via PTLC penalty TX on real chain.

set -uo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

TAG="ptlc_breach_chain"
PORT="${PORT:-29964}"
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

# #154/#183: env var for client[0] seckey matching runner's participant-id=1
export SUPERSCALAR_TEST_CLIENT0_SECKEY=1111111111111111111111111111111111111111111111111111111111111111

bitcoin-cli -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" loadwallet "$WALLET" >/dev/null 2>&1 || true
rm -rf /tmp/ss_rt_${TAG}*
pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true

echo "=== --test-ptlc-breach-chain regtest (#184 Stage A) ==="
echo "  port=$PORT  clients=$CLIENTS  amount=$AMOUNT"

nohup "$LSP_BIN" \
  --network regtest --port "$PORT" \
  --demo --test-ptlc-breach-chain --lsp-balance-pct 50 \
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

if [ "$EXIT" -eq 0 ] && grep -q "PTLC BREACH CHAIN TEST PASSED" "$LOG"; then
    echo "=== PASS: PTLC BREACH CHAIN (#184 Stage A) ==="
    grep -E "PTLC BREACH CHAIN|^\[[0-9]+\]|broadcast_log|penalty=" "$LOG" | head -20
    exit 0
else
    echo "=== FAIL: exit=$EXIT ==="
    tail -50 "$LOG"
    exit 1
fi
