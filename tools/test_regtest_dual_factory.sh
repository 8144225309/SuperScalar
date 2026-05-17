#!/usr/bin/env bash
# test_regtest_dual_factory.sh — codify --test-dual-factory regtest run
# (SF-DUAL #166).
#
# The --test-dual-factory scaffold (tools/superscalar_lsp_pre_daemon_tests.inc)
# creates client keypairs with ds[31]=ci+2 (seckeys 0x00..02..05). Launchers
# MUST use matching 64-char seckeys or the factory_init in the scaffold uses
# wrong keys and bitcoind rejects with Invalid Schnorr at broadcast. This
# runner codifies the correct invocation so the regression won't recur.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

TAG="dual_factory"
PORT="${PORT:-29950}"
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
rm -f "$LSPDB"* "$LOG" "$DONE"
pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true
for i in $(seq 1 $CLIENTS); do rm -f /tmp/ss_rt_${TAG}_c${i}.db* /tmp/ss_rt_${TAG}_c${i}.log; done

echo "=== --test-dual-factory regtest (SF-DUAL #166) ==="
echo "  port=$PORT  clients=$CLIENTS  arity=$ARITY  amount=$AMOUNT"

nohup "$LSP_BIN" \
  --network regtest --port "$PORT" \
  --demo --test-dual-factory --lsp-balance-pct 50 \
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

# Critical: ds[31]=ci+2 seckey scheme matches the scaffold (#166 root cause).
for N in 1 2 3 4; do
    HEX_LAST=$(printf "%02x" $((N + 1)))
    SK="00000000000000000000000000000000000000000000000000000000000000${HEX_LAST}"
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
pkill -f "superscalar_client.*$PORT" 2>/dev/null || true
echo "EXIT=$EXIT" > "$DONE"

if [ "$EXIT" -eq 0 ] && grep -q "DUAL FACTORY TEST PASSED" "$LOG"; then
    echo "=== PASS: dual-factory test (Factory 0 + Factory 1 trees broadcast + confirmed) ==="
    exit 0
else
    echo "=== FAIL: exit=$EXIT, see $LOG ==="
    tail -30 "$LOG"
    exit 1
fi
