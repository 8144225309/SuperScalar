#!/usr/bin/env bash
# test_regtest_ptlc_basic.sh — TS-PTLC-BASIC (#107, SF-W-PTLC Phase 3a)
# Validate LSP-side PTLC happy path on regtest:
#   - --enable-ptlc-unsafe gate flips
#   - channel_add_ptlc succeeds + state machine fields populated
#   - channel_build_commitment_tx includes PTLC output
#   - channel_fail_ptlc transitions state correctly
#   - commitment TX rebuilds cleanly after fail
#
# This exercises only the LSP single-process scaffold; it does not require
# a real client peer (no presig/adapted_sig round-trip). That is covered
# by #172 (CLN-bLIP56 integration) and #173 (regtest end-to-end breach).

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

TAG="ptlc_basic"
PORT="${PORT:-29960}"
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

echo "=== --test-ptlc-basic regtest (#107, SF-W-PTLC Phase 3a) ==="
echo "  port=$PORT  clients=$CLIENTS  arity=$ARITY  amount=$AMOUNT"

# --test-ptlc-basic implies --enable-ptlc-unsafe (parser flips the gate).
nohup "$LSP_BIN" \
  --network regtest --port "$PORT" \
  --demo --test-ptlc-basic --lsp-balance-pct 50 \
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

# Standard repeated-byte client seckeys (matches default LSP scaffold).
for N in 1 2 3 4; do
    HEX=$(printf "%02x" $((N * 0x11)))    # 22, 33, 44, 55
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

if [ "$EXIT" -eq 0 ] && grep -q "PTLC BASIC TEST PASSED" "$LOG"; then
    echo "=== PASS: TS-PTLC-BASIC ==="
    grep -E "PTLC BASIC|PTLC added|PTLC failed|Commitment TX|safety gate" "$LOG" | head -20
    exit 0
else
    echo "=== FAIL: exit=$EXIT, see $LOG ==="
    tail -40 "$LOG"
    exit 1
fi
