#!/usr/bin/env bash
# test_regtest_ptlc_breach.sh — TS-PTLC-BREACH (#108, SF-W-PTLC Phase 3b)
# Validate PTLC watchtower feed end-to-end at the LSP entry point:
#   - safety gate enabled
#   - channel_add_ptlc succeeds
#   - watchtower_watch_revoked_commitment registers entry
#   - entry->n_ptlc_outputs populated from snapshot
#   - entry->ptlc_outputs[0] fields (amount, cltv) match the added PTLC
#   - channel_build_ptlc_penalty_tx builds a sweep TX from entry data
#
# Does NOT broadcast a cheat TX. The on-chain detection variant is in
# #173 (regtest end-to-end) and the testnet4 deliverable.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

TAG="ptlc_breach"
PORT="${PORT:-29961}"
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

echo "=== --test-ptlc-breach regtest (#108, SF-W-PTLC Phase 3b) ==="
echo "  port=$PORT  clients=$CLIENTS  arity=$ARITY  amount=$AMOUNT"

nohup "$LSP_BIN" \
  --network regtest --port "$PORT" \
  --demo --test-ptlc-breach --lsp-balance-pct 50 \
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

if [ "$EXIT" -eq 0 ] && grep -q "PTLC BREACH TEST PASSED" "$LOG"; then
    set +e
    # BIP-431 TRUC catch: this is an IN-PROCESS penalty builder (it does not depend on the
    # penalty landing on-chain), but a zero ptlc_penalty COUNT with no penalty TX means nothing
    # was actually built — the exact failure a marker-only check passes.
    # The PTLC-penalty markers for this in-process test are emitted in the CLIENT logs, not the
    # LSP log — grep both (LSP $LOG + /tmp/ss_rt_${TAG}_c*.log) so the TRUC count check is real.
    PLOGS="$LOG"; for cl in /tmp/ss_rt_${TAG}_c*.log; do [ -f "$cl" ] && PLOGS="$PLOGS $cl"; done
    PCNT=$(cat $PLOGS 2>/dev/null | grep -aoiE "ptlc_penalty=[0-9]+" | grep -oE "[0-9]+" | sort -rn | head -1)
    PEN_TXID=$(cat $PLOGS 2>/dev/null | grep -aoiE "PTLC penalty tx[^0-9a-f]*[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}" | grep -oE "[0-9a-f]{64}" | tail -1)
    echo "  ptlc_penalty count: ${PCNT:-0}; penalty txid: ${PEN_TXID:-none}"
    if [ "${PCNT:-0}" -lt 1 ] && [ -z "$PEN_TXID" ]; then
        echo "=== FAIL: PASSED marker but ptlc_penalty=0 AND no penalty TX built — marker-only false-pass (TRUC zero-value risk) ==="; tail -40 "$LOG"; exit 1
    fi
    echo "=== PASS: TS-PTLC-BREACH — ptlc_penalty=${PCNT:-?}, penalty TX ${PEN_TXID:-built} (in-process builder by design; not an on-chain-landing test) ==="
    grep -E "PTLC BREACH|PTLC added|entry registered|penalty TX|safety gate" "$LOG" | head -20
    exit 0
else
    echo "=== FAIL: exit=$EXIT, see $LOG ==="
    tail -40 "$LOG"
    exit 1
fi
