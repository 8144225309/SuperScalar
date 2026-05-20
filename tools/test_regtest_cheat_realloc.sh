#!/usr/bin/env bash
# test_regtest_cheat_realloc.sh — CL2 adversarial realloc test on regtest.
#
# Validates --cheat-realloc: after the LSP completes a leaf-realloc ceremony,
# it broadcasts the now-revoked pre-realloc leaf TX, and the watchtower must
# detect + respond with a penalty TX (LEAF REALLOC TEST PASS path).
#
# Source: docs/cheat-engine-catalog (CL2) and
# C:/pirq/dashboard-upgrade/LSP_TEAM_HANDOFF_CHEAT_DRIVERS.md.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# --test-realloc requires arity=2 + n_clients>=2 (per the SKIP gate in
# superscalar_lsp_post_daemon_tests.inc). Use N=2 (minimum).
N_CLIENTS=2
FUNDING_SATS=200000
LSP_PORT=29957                    # distinct from sibling tests
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

TMPDIR=$(mktemp -d /tmp/ss-cheat-realloc.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/cheat_realloc_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_realloc_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_realloc_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_realloc_last_lsp.{log,db}, /tmp/cheat_realloc_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== LEAF REALLOC CHEAT (CL2, regtest) ==="
echo "  build dir   : $BUILD_DIR"
echo "  N clients   : $N_CLIENTS"
echo "  funding     : $FUNDING_SATS sats"
echo "  bitcoind    : $REGTEST_CONF"
echo
echo "  Test will:"
echo "    1. Build arity=2 factory with 2 clients (3-of-3 leaf)"
echo "    2. LSP runs realloc ceremony (shifts 20% slot 1 -> slot 2)"
echo "    3. LSP snapshots pre-realloc leaf TX, broadcasts after realloc completes"
echo "    4. LSP-internal watchtower_check fires"
echo "    5. PASS = penalty TX broadcast + LEAF REALLOC TEST: PASS"

# --- bitcoind check ---
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

REORG_LOG="$TMPDIR/reorg.log"
REORG_PID=$(start_reorg_watcher "$REORG_LOG")
PIDS+=($REORG_PID)
echo "  reorg watcher PID=$REORG_PID"
$BCLI -named createwallet wallet_name=ss_cheat_leaf_miner load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet ss_cheat_leaf_miner 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_leaf_miner -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready, 101 fresh blocks"

# --- LSP ---
echo
echo "--- LSP daemon (--demo --test-realloc --cheat-realloc) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest \
    --port $LSP_PORT \
    --clients $N_CLIENTS \
    --arity 2 \
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
    --demo --test-realloc --cheat-realloc \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

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

# --- Background miner ---
(
    while kill -0 $LSP_PID 2>/dev/null; do
        "$BCLI" generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
MINE_PID=$!
PIDS+=($MINE_PID)

# --- Wait for outcome ---
echo
echo "--- Waiting for LEAF REALLOC TEST: PASS|FAIL (timeout 600s) ---"
for i in $(seq 1 300); do
    sleep 2
    if grep -qE "LEAF REALLOC TEST: (PASS|FAIL|SKIP)" "$LSP_LOG" 2>/dev/null; then
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        M=$(grep -cE "CL2 cheat-realloc|CL2 CHEAT-REALLOC|watchtower_check|BREACH" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}s elapsed, CL2 markers in LSP log: $M"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

LSP_EXIT=0
wait $LSP_PID 2>/dev/null || LSP_EXIT=$?
echo "--- LSP exit=$LSP_EXIT ---"

# --- Verification ---
echo
echo "=== CL2 cheat-realloc markers ==="
grep -E "CL2 cheat-realloc|CL2 CHEAT-REALLOC|watchtower_check" "$LSP_LOG" | head -10 || echo "  (none)"
echo
echo "=== broadcast_log entries ==="
sqlite3 "$LSP_DB" "SELECT id, source, result, substr(txid,1,32) FROM broadcast_log WHERE source LIKE '%realloc%' OR source LIKE '%poison%' OR source LIKE '%penalty%' ORDER BY id;" 2>/dev/null
echo
echo "=== breach_detections rows ==="
sqlite3 "$LSP_DB" "SELECT * FROM breach_detections ORDER BY id DESC LIMIT 5;" 2>/dev/null
echo
echo "=== Final result ==="
if grep -q "LEAF REALLOC TEST: PASS" "$LSP_LOG" 2>/dev/null && \
   grep -q "CL2 CHEAT-REALLOC: BREACH DETECTED" "$LSP_LOG" 2>/dev/null; then
    echo "  PASS: realloc cheat detected + penalty broadcast"
    exit 0
fi
echo "  FAIL: cheat-realloc defense did not fire as expected"
echo "  LSP log tail:"
tail -40 "$LSP_LOG"
exit 1
