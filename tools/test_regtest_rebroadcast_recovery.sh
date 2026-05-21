#!/usr/bin/env bash
# test_regtest_rebroadcast_recovery.sh — verify the #259 mempool-eviction
# recovery path actually fires.
#
# IMPORTANT: PR #302's regtest_resend_if_evicted runs inside
# regtest_wait_for_stable_confirmation, which is ONLY called by the LSP
# on non-regtest networks (the pure-regtest path just calls
# regtest_mine_blocks). To exercise the code path on a regtest chain we
# tell the LSP "--network signet" while pointing its RPC at the
# regtest bitcoind on port 18443. The LSP treats itself as signet
# (target_depth=3, runs the polling loop) but actually talks to our
# fast-mining regtest bitcoind. Best of both worlds.
#
# Pattern:
#   1. Start regtest bitcoind, mine 101 blocks
#   2. Launch LSP --demo + N clients with --network signet --rpcport 18443
#   3. Background miner mines a block every 2s (drives the ceremony)
#   4. When LSP logs "waiting for close tx to reach", capture close txid
#   5. STOP the background miner (we want a window where the close TX is
#      in mempool but not at target_depth=3 yet)
#   6. clearmempool (Bitcoin Core 28+ RPC) to force eviction
#   7. Wait up to 30s for the LSP's wait loop to detect (polls every 15s
#      on non-regtest; throttle sentinel allows the first resend to fire
#      immediately on the first iteration where eviction is observed)
#   8. Assert the "regtest_resend_if_evicted: ... re-broadcasting" log
#      line appeared on LSP stderr
#   9. Verify the TX is back in mempool after resend
#  10. Restart the background miner — close TX confirms — LSP exits PASS
#
# This is the regtest counterpart to the manual 3a V1 fix on testnet4
# (see PR #302 commit message).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
FUNDING_SATS=100000
LSP_PORT=29957
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-rebroadcast-recovery.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
LSP_ERR="$TMPDIR/lsp.err"

PIDS=()
MINER_PID=""

cleanup() {
    echo ""
    echo "=== cleanup ==="
    if [ -n "$MINER_PID" ]; then
        kill "$MINER_PID" 2>/dev/null || true
    fi
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/rebroadcast_recovery_last_lsp.log 2>/dev/null || true
    cp "$LSP_ERR" /tmp/rebroadcast_recovery_last_lsp.err 2>/dev/null || true
    cp "$LSP_DB"  /tmp/rebroadcast_recovery_last_lsp.db  2>/dev/null || true
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/rebroadcast_recovery_last_lsp.{log,err,db}"
}
trap cleanup EXIT

echo "=== REBROADCAST RECOVERY (#259, regtest) ==="
echo "  N clients : $N_CLIENTS"
echo "  port      : $LSP_PORT"
echo "  build dir : $BUILD_DIR"

# --- bitcoind reachable? ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, chain at height $($BCLI getblockcount)"

# --- need Bitcoin Core 28+ for clearmempool RPC ---
if ! $BCLI help clearmempool >/dev/null 2>&1; then
    echo "FAIL: this bitcoind does not support the 'clearmempool' RPC"
    echo "      (requires Bitcoin Core 28+); skipping this test"
    exit 0
fi

# --- miner wallet + initial blocks ---
MINER_WALLET="ss_rebroadcast_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner ready, 101 blocks"

# --- pre-flight: kill any stale LSP holding the port ---
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null || true
sleep 1

# --- launch LSP (--demo: factory + payment + cooperative close) ---
echo ""
echo "--- LSP daemon (--demo, $N_CLIENTS clients) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network signet --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --rpcport 18443 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --demo \
    > "$LSP_LOG" 2> "$LSP_ERR" &
LSP_PID=$!
PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died"; tail -20 "$LSP_LOG" "$LSP_ERR"; exit 1; }
done
echo "  LSP listening (PID=$LSP_PID)"

# --- clients ---
for i in $(seq 0 $((N_CLIENTS - 1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network signet --host 127.0.0.1 --port $LSP_PORT \
        --rpcport 18443 \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.3
done

# --- background miner; we'll stop + start this ---
start_miner() {
    (while kill -0 $LSP_PID 2>/dev/null; do
        $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done) &
    MINER_PID=$!
}
stop_miner() {
    if [ -n "$MINER_PID" ]; then
        kill "$MINER_PID" 2>/dev/null || true
        wait "$MINER_PID" 2>/dev/null || true
        MINER_PID=""
    fi
}

start_miner
echo "  background miner PID=$MINER_PID"

# --- wait until LSP starts polling close-tx confirmations ---
echo ""
echo "--- waiting for cooperative close broadcast ---"
CLOSE_TXID=""
for i in $(seq 1 300); do
    sleep 1
    if grep -q "waiting for close tx to reach" "$LSP_LOG" 2>/dev/null; then
        echo "  LSP entered confirmation-wait at iter $i"
        break
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP exited before broadcasting close"
        tail -30 "$LSP_LOG"; tail -30 "$LSP_ERR"; exit 1
    fi
done

CLOSE_TXID=$(sqlite3 "$LSP_DB" \
    "SELECT txid FROM broadcast_log WHERE source='cooperative_close' ORDER BY id DESC LIMIT 1;" 2>/dev/null)
if [ -z "$CLOSE_TXID" ]; then
    echo "FAIL: cooperative_close not found in broadcast_log"
    tail -30 "$LSP_LOG"
    exit 1
fi
echo "  close TX: $CLOSE_TXID"

# --- create the eviction window ---
echo ""
echo "--- injecting mempool eviction ---"
stop_miner

# Make sure close TX is currently in mempool before evicting
sleep 2
IN_MP_BEFORE=$($BCLI getmempoolentry "$CLOSE_TXID" 2>&1 | grep -c "size" || true)
if [ "$IN_MP_BEFORE" -lt 1 ]; then
    # TX may already be in a block — re-broadcast it to mempool first
    HEX=$($BCLI getrawtransaction "$CLOSE_TXID" 0 2>/dev/null || true)
    if [ -n "$HEX" ]; then
        $BCLI sendrawtransaction "$HEX" 2>&1 | head -3 || true
        sleep 1
    fi
fi

# Now wipe the mempool
$BCLI clearmempool >/dev/null 2>&1 || { echo "FAIL: clearmempool RPC failed"; exit 1; }
sleep 1

IN_MP_AFTER_CLEAR=$($BCLI getmempoolentry "$CLOSE_TXID" 2>&1 | grep -c "size" || true)
if [ "$IN_MP_AFTER_CLEAR" -gt 0 ]; then
    echo "FAIL: clearmempool did not remove our TX (still in mempool)"
    exit 1
fi
echo "  ✓ TX evicted from mempool"

# --- wait for the LSP's resend log line ---
echo ""
echo "--- waiting for regtest_resend_if_evicted to fire ---"
RESEND_OK=0
for i in $(seq 1 30); do
    sleep 1
    if grep -q "regtest_resend_if_evicted:" "$LSP_ERR" 2>/dev/null; then
        if grep "regtest_resend_if_evicted:" "$LSP_ERR" | head -3; then
            RESEND_OK=1
            echo "  ✓ resend log line found at iter $i"
            break
        fi
    fi
done

if [ "$RESEND_OK" -eq 0 ]; then
    echo "FAIL: no 're-broadcasting from wallet hex' log line within 30s"
    echo "--- LSP stderr (last 40 lines) ---"
    tail -40 "$LSP_ERR"
    echo "--- LSP stdout (last 20 lines) ---"
    tail -20 "$LSP_LOG"
    exit 1
fi

# --- verify TX is back in mempool ---
sleep 2
IN_MP_REPLAY=$($BCLI getmempoolentry "$CLOSE_TXID" 2>&1 | grep -c "size" || true)
if [ "$IN_MP_REPLAY" -lt 1 ]; then
    echo "FAIL: TX did not re-enter mempool after resend"
    exit 1
fi
echo "  ✓ TX back in mempool"

# --- restart miner, let LSP reach target depth + exit cleanly ---
echo ""
echo "--- restarting miner to drive confirmations ---"
start_miner

for i in $(seq 1 90); do
    sleep 2
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "  LSP exited at iter $i"
        break
    fi
done

if kill -0 $LSP_PID 2>/dev/null; then
    echo "FAIL: LSP did not exit within 180s after resend"
    tail -30 "$LSP_LOG"
    exit 1
fi

wait $LSP_PID 2>/dev/null
LSP_EXIT=$?

if [ $LSP_EXIT -ne 0 ]; then
    echo "FAIL: LSP exited non-zero ($LSP_EXIT)"
    tail -30 "$LSP_LOG"; tail -30 "$LSP_ERR"
    exit 1
fi

# --- final assertions ---
FINAL_CONF=$($BCLI getrawtransaction "$CLOSE_TXID" 1 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('confirmations', 0))" 2>/dev/null || echo 0)
if [ "$FINAL_CONF" -lt 1 ]; then
    echo "FAIL: close TX has $FINAL_CONF confs (expected ≥1)"
    exit 1
fi

echo ""
echo "=== PASS ==="
echo "  close txid     : $CLOSE_TXID"
echo "  resend log     : observed"
echo "  back in mempool: yes"
echo "  final confs    : $FINAL_CONF"
echo "  LSP exit       : 0"
exit 0
