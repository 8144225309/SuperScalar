#!/usr/bin/env bash
# test_regtest_cheat_lstock_buy.sh — SF-CHEAT-LSTOCK-BUY (#255) adversarial test on regtest.
#
# Validates --cheat-lstock-buy: after the LSP completes an honest L-stock
# buy-liquidity ceremony (which mutates the leaf signed_tx via lsp_realloc_leaf),
# it broadcasts the now-revoked pre-buy leaf TX, and the watchtower must
# detect + respond with a penalty TX (BUY LIQUIDITY TEST PASS path).
#
# Source: docs/cheat-engine-catalog (SF-CHEAT-LSTOCK-BUY).
# Mirrors tools/test_regtest_cheat_realloc.sh.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# --test-buy-liquidity requires arity=2 (per the SKIP gate in
# superscalar_lsp_post_daemon_tests.inc). Use N=2 (minimum).
N_CLIENTS=2
FUNDING_SATS=200000
LSP_PORT=29958                    # distinct from sibling cheat tests
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

TMPDIR=$(mktemp -d /tmp/ss-cheat-lstock-buy.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/cheat_lstock_buy_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_lstock_buy_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_lstock_buy_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_lstock_buy_last_lsp.{log,db}, /tmp/cheat_lstock_buy_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== L-STOCK BUY-LIQUIDITY CHEAT (SF-CHEAT-LSTOCK-BUY #255, regtest) ==="
echo "  build dir   : $BUILD_DIR"
echo "  N clients   : $N_CLIENTS"
echo "  funding     : $FUNDING_SATS sats"
echo "  bitcoind    : $REGTEST_CONF"
echo
echo "  Test will:"
echo "    1. Build arity=2 factory with 2 clients (3-of-3 leaf)"
echo "    2. LSP runs honest L-stock buy ceremony (1000 sats to client 0)"
echo "    3. LSP snapshots pre-buy leaf TX, broadcasts after buy completes"
echo "    4. LSP-internal watchtower_check fires"
echo "    5. PASS = penalty TX broadcast + BUY LIQUIDITY TEST: PASS"

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
$BCLI -named createwallet wallet_name=ss_cheat_lstock_miner load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet ss_cheat_lstock_miner 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_lstock_miner -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready, 101 fresh blocks"

# --- LSP ---
echo
echo "--- LSP daemon (--demo --test-buy-liquidity --cheat-lstock-buy) ---"
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
    --wallet ss_cheat_lstock_miner \
    --db "$LSP_DB" \
    --demo --cheat-lstock-buy \
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
        --wallet ss_cheat_lstock_miner \
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
echo "--- Waiting for BUY LIQUIDITY TEST: PASS|FAIL (timeout 600s) ---"
for i in $(seq 1 300); do
    sleep 2
    if grep -qE "BUY LIQUIDITY TEST: (PASS|FAIL|SKIP)" "$LSP_LOG" 2>/dev/null; then
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        M=$(grep -cE "CL\?-CHEAT-LSTOCK-BUY|watchtower_check|BREACH" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}s elapsed, SF-CHEAT-LSTOCK-BUY markers in LSP log: $M"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

LSP_EXIT=0
wait $LSP_PID 2>/dev/null || LSP_EXIT=$?
echo "--- LSP exit=$LSP_EXIT ---"

# --- Verification ---
echo
echo "=== SF-CHEAT-LSTOCK-BUY markers ==="
grep -E "CL\?-CHEAT-LSTOCK-BUY|watchtower_check" "$LSP_LOG" | head -15 || echo "  (none)"
echo
echo "=== broadcast_log entries ==="
sqlite3 "$LSP_DB" "SELECT id, source, result, substr(txid,1,32) FROM broadcast_log WHERE source LIKE '%lstock%' OR source LIKE '%poison%' OR source LIKE '%penalty%' OR source LIKE '%response%' ORDER BY id;" 2>/dev/null
echo
echo "=== breach_detections rows ==="
sqlite3 "$LSP_DB" "SELECT * FROM breach_detections ORDER BY id DESC LIMIT 5;" 2>/dev/null
echo
echo "=== Final result ==="
# PASS criterion: the WT must have DETECTED the cheat broadcast (FACTORY
# BREACH or BREACH DETECTED line) AND broadcast at least one defense TX
# (poison/penalty/response).  Detection can fire either via the
# watchtower_check() call from the test scaffold OR the WT's main-loop
# block scan -- both count.
BREACH_DETECTED=$(grep -E "FACTORY BREACH on node|CL\?-CHEAT-LSTOCK-BUY: BREACH DETECTED" "$LSP_LOG" 2>/dev/null | wc -l)
POISON_BROADCAST=$(grep -E "L-stock burn tx broadcast|poison TX broadcast|penalty.*broadcast|response_tx.*broadcast" "$LSP_LOG" 2>/dev/null | wc -l)

set +e
if [ "$BREACH_DETECTED" -ge 1 ] && [ "$POISON_BROADCAST" -ge 1 ]; then
    # OUTCOME (not just log-greps): confirm the lstock-buy defense txid ON-CHAIN + assert a real redistributed amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE (source LIKE '%lstock%' OR source LIKE '%poison%' OR source LIKE '%penalty%' OR source LIKE '%response%' OR source LIKE '%burn%') AND result='ok' AND length(txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(grep -aoiE "L-stock burn tx broadcast: *[0-9a-f]{64}|Latest state tx broadcast: *[0-9a-f]{64}|poison TX broadcast[^0-9a-f]*[0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { echo "  FAIL: breach detected + poison broadcast logged, but no defense txid found (broadcast_log/breach_detections/log)"; tail -25 "$LSP_LOG"; exit 1; }
    echo "  defense (lstock/poison) txid: $PEN_TXID — mining to confirm + verify redistribution"
    PRAW=""; for n in $(seq 1 10); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null); echo "$PRAW" | grep -q '"confirmations"' && break; done
    echo "$PRAW" | grep -q '"confirmations"' || { echo "  FAIL: defense $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
    echo "  defense confirmed on-chain; largest output ${PSATS:-0} sats"
    [ "${PSATS:-0}" -ge 1000 ] || { echo "  FAIL: defense output ${PSATS} sats <= dust — not a real redistribution"; exit 1; }
    echo "  PASS: WT detected breach (x$BREACH_DETECTED) + broadcast AND CONFIRMED defense $PEN_TXID (${PSATS} sats) — outcome verified, not just a log line"
    grep -E "FACTORY BREACH|L-stock burn|response_tx|watchtower registered OLD" "$LSP_LOG" | head -10
    exit 0
fi

echo "  FAIL: BREACH_DETECTED=$BREACH_DETECTED POISON_BROADCAST=$POISON_BROADCAST"
echo "  LSP log tail:"
tail -40 "$LSP_LOG"
exit 1
