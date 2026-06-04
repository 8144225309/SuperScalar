#!/usr/bin/env bash
# test_regtest_soak_advances.sh — Gap 7 soak test.
#
# Drives N consecutive PS leaf advances against a single factory, then
# triggers a cheat from chain[1] (the oldest stale state) and verifies
# the watchtower can defend after a long advance chain.
#
# Validates:
#   - WT memory pressure under many entries (50 chain entries → 50 WT entries
#     registered via CL4 hydration)
#   - persistence performs reasonably across 50 ps_leaf_chains writes
#   - WT defense fires correctly when oldest state is broadcast as cheat

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
ADVANCE_COUNT="${ADVANCE_COUNT:-50}"   # 50 advances == long-soak

FUNDING_SATS=200000
LSP_PORT=29960
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-soak-advances.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/soak_advances_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/soak_advances_last_lsp.db  2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== SOAK TEST — $ADVANCE_COUNT advances on PS leaf ==="
echo "  N clients     : $N_CLIENTS"
echo "  side          : $SIDE"
echo "  advance count : $ADVANCE_COUNT"

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo
echo "--- LSP (--demo --test-leaf-advance --cheat-leaf $SIDE --advance-count $ADVANCE_COUNT) ---"
"$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 50 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --demo --test-leaf-advance --cheat-leaf $SIDE --advance-count $ADVANCE_COUNT \
    --max-conn-rate 1000 --max-handshakes 256 \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -20 "$LSP_LOG"; exit 1; }
done

for i in $(seq 0 $((N_CLIENTS - 1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.1
done

(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

echo
echo "--- Waiting for $ADVANCE_COUNT advances + cheat detection (timeout 1200s) ---"
START=$(date +%s)
for i in $(seq 1 600); do
    sleep 2
    grep -qE "LEAF ADVANCE TEST (PASSED|FAILED)" "$LSP_LOG" 2>/dev/null && break
    if [ $((i % 30)) -eq 0 ]; then
        ADV=$(grep -cE "PS leaf.*advanced" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}*2s, advances=$ADV / $ADVANCE_COUNT"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

wait $LSP_PID 2>/dev/null || true
END=$(date +%s)

echo
echo "=== Soak results ==="
ADV=$(grep -cE "PS leaf.*advanced" "$LSP_LOG" 2>/dev/null || echo 0)
CHAIN_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM ps_leaf_chains;" 2>/dev/null || echo "?")
echo "  advances completed : $ADV / $ADVANCE_COUNT"
echo "  ps_leaf_chains rows: $CHAIN_ROWS"
echo "  elapsed time       : $((END - START))s"
echo "  LSP peak RSS       : $(grep -m1 'LSP peak RSS' "$LSP_LOG" 2>/dev/null || echo n/a)"

echo
echo "=== Final result ==="
if grep -q "LEAF ADVANCE TEST PASSED" "$LSP_LOG" 2>/dev/null && [ "${ADV:-0}" -ge "$ADVANCE_COUNT" ]; then
    echo "  PASS: $ADVANCE_COUNT advances persisted, defense fired"
    exit 0
else
    echo "  FAIL: see /tmp/soak_advances_last_lsp.log"
    tail -30 "$LSP_LOG"
    exit 1
fi
