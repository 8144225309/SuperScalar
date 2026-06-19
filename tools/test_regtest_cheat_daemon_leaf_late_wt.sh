#!/usr/bin/env bash
# test_regtest_cheat_daemon_leaf_late_wt.sh — Gap 4 explicit "late WT" test.
#
# Stretches the gap between cheat-confirmation and WT-startup to a known
# wide window so we explicitly validate the WT's startup-chain-scan path,
# not just the "WT poll detects new block" path.
#
# Flow:
#   1. LSP runs --cheat-daemon-leaf (advance + stale broadcast).
#   2. After CHEAT DAEMON COMPLETE marker, MINE EXTRA_BLOCKS additional
#      blocks before starting WT. Default 10 — well beyond the CL8
#      5-confirmation stable window, so the cheat is solidly buried.
#   3. NOW start standalone WT. Verify it scans + detects the breach
#      from chain history (not from a "new block" notification).
#   4. WT must broadcast response_tx + L-stock poison TX.
#
# Pass criterion: WT broadcasts the poison TX even though the cheat
# confirmed many blocks before WT started.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
EXTRA_BLOCKS="${EXTRA_BLOCKS:-10}"

FUNDING_SATS=100000
LSP_PORT=29958
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000006"
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000008"
    "0000000000000000000000000000000000000000000000000000000000000009"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

TMPDIR=$(mktemp -d /tmp/ss-cheat-daemon-leaf-late-wt.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
WT_LOG="$TMPDIR/wt.log"
WT_DB="$TMPDIR/wt.db"   # trustless WT db (no secrets); armed by the LSP's --wt-db

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/cheat_daemon_leaf_late_wt_last_lsp.log 2>/dev/null || true
    cp "$WT_LOG"  /tmp/cheat_daemon_leaf_late_wt_last_wt.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_daemon_leaf_late_wt_last_lsp.db  2>/dev/null || true
    [ -n "${REORG_LOG:-}" ] && cp "$REORG_LOG" /tmp/cheat_daemon_leaf_late_wt_last_reorg.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== PS LEAF CHEAT WITH LATE-ARRIVING STANDALONE WT (regtest) ==="
echo "  N clients      : $N_CLIENTS"
echo "  side cheated   : $SIDE"
echo "  extra blocks   : $EXTRA_BLOCKS (between cheat confirm and WT startup)"

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, height $($BCLI getblockcount)"

REORG_LOG="$TMPDIR/reorg.log"
REORG_PID=$(start_reorg_watcher "$REORG_LOG")
PIDS+=($REORG_PID)

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo
echo "--- LSP (--demo --cheat-daemon-leaf $SIDE) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" --wt-db "$WT_DB" \
    --demo --cheat-daemon-leaf $SIDE \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -20 "$LSP_LOG"; exit 1; }
done

for i in $(seq 0 $((N_CLIENTS - 1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.5
done

(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

echo
echo "--- Waiting for CHEAT DAEMON COMPLETE (timeout 360s) ---"
DAEMON_READY=0
for i in $(seq 1 180); do
    sleep 2
    if grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null; then
        DAEMON_READY=1
        echo "  CHEAT DAEMON COMPLETE marker observed"
        break
    fi
    if [ $((i % 30)) -eq 0 ]; then echo "  ... waiting (${i}*2s elapsed)"; fi
    kill -0 $LSP_PID 2>/dev/null || break
done
if [ $DAEMON_READY -eq 0 ]; then
    echo "FAIL: LSP did not reach CHEAT DAEMON COMPLETE in 360s"
    exit 1
fi

# Note when the cheat was confirmed
CHEAT_HEIGHT=$($BCLI getblockcount)
echo "  Chain at height $CHEAT_HEIGHT after CHEAT DAEMON COMPLETE"

# --- Gap 4 specific: mine EXTRA_BLOCKS more blocks BEFORE starting WT ---
echo
echo "--- Gap 4: mining $EXTRA_BLOCKS extra blocks before starting WT ---"
for i in $(seq 1 $EXTRA_BLOCKS); do
    $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
    sleep 1
done
END_HEIGHT=$($BCLI getblockcount)
echo "  Chain at height $END_HEIGHT — cheat is buried $((END_HEIGHT - CHEAT_HEIGHT)) blocks deep"

# Trustless: stop the LSP so wt.db WAL checkpoints; keep mining for the WT poll.
echo "  Stopping LSP (SIGTERM) so wt.db flushes for the standalone WT..."
kill -TERM $LSP_PID 2>/dev/null || true
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done
( for k in $(seq 1 80); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 3; done ) & PIDS+=($!)
# --- Standalone trustless Watchtower (--wt-db) — starting LATE ---
echo
echo "--- LATE Standalone trustless WT startup ---"
"$WT_BIN" \
    --network regtest \
    --wt-db "$WT_DB" \
    --poll-interval 5 \
    --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
echo "  WT PID=$WT_PID (starting against cheat that confirmed $EXTRA_BLOCKS blocks ago)"

echo
echo "--- Waiting for late-WT to detect + broadcast (timeout 120s) ---"
WT_FIRED=0
for i in $(seq 1 60); do
    sleep 2
    if grep -qE 'penalty tx\(s\) broadcast|L-stock burn tx broadcast: [0-9a-f]{64}' "$WT_LOG" 2>/dev/null; then
        WT_FIRED=1
        echo "  Late WT fired after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        ENTRIES=$(grep -cE "heartbeat" "$WT_LOG" 2>/dev/null || echo 0)
        echo "  ... waiting (${i}*2s elapsed, $ENTRIES heartbeats)"
    fi
    kill -0 $WT_PID 2>/dev/null || break
done

echo
echo "=== WT log tail ==="
tail -25 "$WT_LOG"

echo
echo "=== reorg events ==="
if [ -s "$REORG_LOG" ]; then cat "$REORG_LOG"; else echo "  (none)"; fi

echo
echo "=== Final result ==="
set +e
if [ "$WT_FIRED" -eq 1 ]; then
    # OUTCOME (not just a broadcast log line): confirm the WT's response/penalty txid ON-CHAIN + assert a real amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(grep -aoiE "Latest state tx broadcast: *[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}|L-stock burn tx broadcast: [0-9a-f]{64}|Sub-factory poison tx broadcast: *[0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { echo "  FAIL: late WT fired but no response/penalty txid found (breach_detections + WT log)"; tail -30 "$WT_LOG"; exit 1; }
    echo "  late WT response txid: $PEN_TXID — mining to confirm + verify payout"
    PRAW=""; for n in $(seq 1 10); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null); echo "$PRAW" | grep -q '"confirmations"' && break; done
    echo "$PRAW" | grep -q '"confirmations"' || { echo "  FAIL: late WT response $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
    echo "  late WT response confirmed on-chain; largest output ${PSATS:-0} sats"
    [ "${PSATS:-0}" -ge 1000 ] || { echo "  FAIL: late WT response output ${PSATS} sats <= dust — not a real recapture"; exit 1; }
    A2=$(pen_recovers_most "$PEN_TXID"); echo "  A-2 recovery ratio: $A2 (OK=outputs>=90% of swept inputs)"
    case "$A2" in LOW*) echo "  FAIL: late WT response recovers <90% of swept value ($A2) — value leaked/burned"; exit 1;; esac
    echo "  PASS: late-arriving WT defended after $EXTRA_BLOCKS-block delay — broadcast AND CONFIRMED its response ($PEN_TXID, ${PSATS} sats), outcome verified"
    exit 0
else
    echo "  FAIL: late WT did not broadcast penalty TXs"
    exit 1
fi
