#!/usr/bin/env bash
# test_regtest_cheat_leaf_multistate.sh — multi-state PS leaf cheat on regtest.
#
# Validates CL3: --advance-count N drives N consecutive PS leaf advances.
# Same defense flow as cheat_leaf but with multiple chain entries.
#
# Each advance:
#   - real wire ceremony with running clients (CL1.F)
#   - LSP-internal WT registers OLD state (so cheat against any tier is detected)
#   - persist_save_ps_chain_entry appends to ps_leaf_chains
#
# Cheat path:
#   - LSP snapshots pre-advance leaf signed_tx (oldest reachable state)
#   - After N advances, broadcasts the snapshotted pre-PS state as "stale"
#   - WT detects (entry registered for pre-PS state) and broadcasts response_tx
#     (the new signed_tx for that state's successor) + poison TX.
#
# Sibling of test_regtest_cheat_leaf.sh (single-state PASS).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
ADVANCE_COUNT="${ADVANCE_COUNT:-3}"

FUNDING_SATS=100000
LSP_PORT=29952
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

TMPDIR=$(mktemp -d /tmp/ss-cheat-leaf-multistate.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/cheat_leaf_multistate_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_leaf_multistate_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_leaf_multistate_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_leaf_multistate_last_lsp.{log,db}"
}
trap cleanup EXIT

echo "=== PS LEAF CHEAT MULTI-STATE (regtest) ==="
echo "  N clients     : $N_CLIENTS"
echo "  side cheated  : $SIDE (0=left, 1=right)"
echo "  advance count : $ADVANCE_COUNT"
echo "  funding       : $FUNDING_SATS sats"

# --- bitcoind ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, chain at height $($BCLI getblockcount)"

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner ready, 101 fresh blocks"

# --- LSP ---
echo
echo "--- LSP daemon (--demo --test-leaf-advance --cheat-leaf $SIDE --advance-count $ADVANCE_COUNT) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --demo --test-leaf-advance --cheat-leaf $SIDE --advance-count $ADVANCE_COUNT \
    --lsp-balance-pct 100 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    if grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null; then
        echo "  LSP listening (PID=$LSP_PID)"; break; fi
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died"; tail -20 "$LSP_LOG"; exit 1; }
done

# --- Clients ---
for i in $(seq 0 $((N_CLIENTS - 1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); echo "  client[$i] PID=$!"
    sleep 0.5
done

# --- Background miner ---
(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

# --- Wait for outcome ---
echo
echo "--- Waiting for LEAF ADVANCE TEST {PASSED,FAILED} (timeout 600s) ---"
for i in $(seq 1 300); do
    sleep 2
    grep -qE "LEAF ADVANCE TEST (PASSED|FAILED)" "$LSP_LOG" 2>/dev/null && break
    if [ $((i % 15)) -eq 0 ]; then
        ADV=$(grep -cE "PS leaf.*advanced" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}*2s elapsed, $ADV advances done"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

wait $LSP_PID 2>/dev/null || true

# --- Verification ---
echo
echo "=== PS chain advances ==="
grep -E "PS leaf.*advanced|chain_len" "$LSP_LOG" | head -10
echo
echo "=== broadcast_log (multi-state cheat path) ==="
sqlite3 "$LSP_DB" "SELECT id, source, result, substr(txid,1,32) FROM broadcast_log ORDER BY id;" 2>/dev/null | head -25
echo
echo "=== ps_leaf_chains contents ==="
sqlite3 "$LSP_DB" "SELECT factory_id, leaf_node_idx, chain_pos, substr(txid,1,32), length(signed_tx_hex), chan_amount_sats FROM ps_leaf_chains;" 2>/dev/null

echo
echo "=== Final result ==="
if grep -q "LEAF ADVANCE TEST PASSED" "$LSP_LOG" 2>/dev/null; then
    ENTRIES=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM ps_leaf_chains;" 2>/dev/null)
    if [ "${ENTRIES:-0}" -ge "$ADVANCE_COUNT" ]; then
        echo "  PASS: multi-state advance + WT defense (ps_leaf_chains=$ENTRIES entries, expected >=$ADVANCE_COUNT)"
        exit 0
    else
        echo "  FAIL: only $ENTRIES chain entries persisted, expected >=$ADVANCE_COUNT"
        exit 1
    fi
else
    echo "  FAIL: LEAF ADVANCE TEST did not PASSED"
    tail -30 "$LSP_LOG"
    exit 1
fi
