#!/usr/bin/env bash
# test_regtest_cheat_leaf.sh — end-to-end PS leaf cheat on regtest.
#
# Validates CL1 + CL1.B + CL1.C: --cheat-leaf [SIDE] makes the LSP snapshot
# the pre-advance leaf signed_tx, advance the leaf, broadcast the parent
# path (excluding the cheated leaf) via broadcast_factory_tree_any_network,
# then broadcast the snapshotted stale leaf, wait 5 confs, and run
# watchtower_check.
#
# Watchtower must detect on-chain stale leaf and broadcast:
#   1. response_tx (the latest signed leaf state)
#   2. L-stock poison TX (redirects LSP's L-stock to clients)
#
# This is the LSP-internal-WT version (LSP cheats and detects).  Companion
# test test_regtest_cheat_daemon_leaf.sh handles the standalone-WT variant.
#
# Sibling of test_regtest_k2_subfactory_breach.sh (k² version, PASSING).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"   # 0=left, 1=right

FUNDING_SATS=100000
LSP_PORT=29950                # distinct from k² test (29949) and others
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

TMPDIR=$(mktemp -d /tmp/ss-cheat-leaf-regtest.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    cp "$LSP_LOG" /tmp/cheat_leaf_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_leaf_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_leaf_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_leaf_last_lsp.{log,db}, /tmp/cheat_leaf_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== PS LEAF CHEAT (regtest) ==="
echo "  build dir   : $BUILD_DIR"
echo "  N clients   : $N_CLIENTS"
echo "  side cheated: $SIDE (0=left, 1=right)"
echo "  funding     : $FUNDING_SATS sats"
echo "  bitcoind    : $REGTEST_CONF"
echo
echo "  Test will:"
echo "    1. Build PS arity=3 factory with $N_CLIENTS clients (1 client per leaf)"
echo "    2. Advance the chosen leaf, snapshotting pre-advance state"
echo "    3. LSP broadcasts parent path via broadcast_factory_tree_any_network"
echo "    4. LSP broadcasts STALE pre-advance leaf state"
echo "    5. LSP-internal watchtower_check fires"
echo "    6. Verify response_tx + L-stock poison TX broadcast"

# --- bitcoind check (use existing if running, else start) ---
echo
echo "--- bitcoind regtest check ---"
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do
        sleep 1
        $BCLI getblockchaininfo >/dev/null 2>&1 && break
    done
fi
echo "  bitcoind reachable, chain at height $($BCLI getblockcount)"

$BCLI -named createwallet wallet_name=ss_cheat_leaf_miner load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet ss_cheat_leaf_miner 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_leaf_miner -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready, generated 101 blocks (coinbase mature)"

# --- LSP daemon ---
echo
echo "--- LSP daemon (--demo --test-leaf-advance --cheat-leaf $SIDE) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest \
    --port $LSP_PORT \
    --clients $N_CLIENTS \
    --arity 3 \
    --amount $FUNDING_SATS \
    --fee-rate 1000 \
    --confirm-timeout 600 \
    --active-blocks 6 \
    --dying-blocks 4 \
    --step-blocks 1 \
    --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet ss_cheat_leaf_miner \
    --db "$LSP_DB" \
    --demo --test-leaf-advance --cheat-leaf $SIDE \
    --lsp-balance-pct 100 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

# Wait for LSP to be listening
for i in $(seq 1 60); do
    sleep 1
    if grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null; then
        echo "  LSP listening (PID=$LSP_PID, port=$LSP_PORT)"
        break
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP died before listening"
        tail -20 "$LSP_LOG"
        exit 1
    fi
done

# --- Clients ---
echo
echo "--- Starting $N_CLIENTS clients ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" \
        --network regtest \
        --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i + 1)) \
        --daemon \
        --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet ss_cheat_leaf_miner \
        --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    echo "  client[$i] PID=$CLIENT_PID"
    sleep 0.5
done

# --- Background miner: 1 block / 2s ---
(
    while kill -0 $LSP_PID 2>/dev/null; do
        "$BCLI" generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
MINE_PID=$!
PIDS+=($MINE_PID)

# --- Wait for test outcome ---
echo
echo "--- Waiting for leaf advance + cheat broadcast + WT response (timeout 600s) ---"
for i in $(seq 1 300); do
    sleep 2
    if grep -qE "LEAF ADVANCE TEST (PASSED|FAILED)" "$LSP_LOG" 2>/dev/null; then
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        MARKERS=$(grep -cE "CHEAT-LEAF|tree_node_[0-9]+ broadcast|watchtower_check|Stale pre-advance|response_tx" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}s elapsed, markers in LSP log: $MARKERS"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

LSP_EXIT=0
wait $LSP_PID 2>/dev/null || LSP_EXIT=$?
echo "--- LSP exit=$LSP_EXIT ---"

# --- Verification ---
echo
echo "=== Verifying CHEAT-LEAF broadcasts ==="
grep -E "Stale pre-advance leaf broadcast" "$LSP_LOG" | head -3 || echo "  (no stale broadcast logged)"
echo
echo "=== Verifying watchtower_check fired ==="
grep -E "watchtower_check returned" "$LSP_LOG" | head -3 || echo "  (watchtower_check not logged)"
echo
echo "=== broadcast_log entries ==="
sqlite3 "$LSP_DB" "SELECT id, source, result, substr(txid,1,32) FROM broadcast_log ORDER BY id;" 2>/dev/null | head -25

echo
echo "=== Final result ==="
if grep -q "LEAF ADVANCE TEST PASSED" "$LSP_LOG" 2>/dev/null; then
    echo "  PASS: PS leaf cheat detection end-to-end"
    exit 0
else
    echo "  FAIL: LEAF ADVANCE TEST did not PASSED"
    echo "  LSP log tail:"
    tail -30 "$LSP_LOG"
    exit 1
fi
