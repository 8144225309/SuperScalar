#!/usr/bin/env bash
# test_regtest_same_height_reorg.sh — Issue #2 validation.
#
# Forces a SAME-HEIGHT reorg via bitcoin-cli invalidateblock + mine on a
# different chain, then verifies the standalone WT logs the
# SAME_HEIGHT reorg event AND triggers watchtower_on_reorg.
#
# Original CL6 design missed this — it only detected height-decrease.
# After Issue #2 fix, both code paths trigger re-validation.
#
# This is a synthetic forced reorg (not naturally occurring on regtest)
# to exercise the new detection logic deterministically.

set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-same-height-reorg.XXXXXX)
WT_DB="$TMPDIR/wt.db"
WT_LOG="$TMPDIR/wt.log"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$WT_LOG" /tmp/same_height_reorg_last_wt.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== Same-height reorg detection (Issue #2 validation) ==="

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)

# Ensure we have a mature chain (coinbase mature requires 100 confs)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
START_HEIGHT=$($BCLI getblockcount)
echo "  Starting at height $START_HEIGHT"

# Create an EMPTY watchtower DB (schema only) so the WT can start
# without needing a real LSP run upstream.
sqlite3 "$WT_DB" "CREATE TABLE broadcast_log (id INTEGER PRIMARY KEY, txid TEXT, source TEXT, raw_hex TEXT, result TEXT, broadcast_time DATETIME DEFAULT CURRENT_TIMESTAMP);" 2>/dev/null

# Start the WT.  ASAN_OPTIONS/LD_PRELOAD are required because the binary
# is built with -fsanitize=address; without preloading libasan.so.8 first,
# ASan aborts immediately with "runtime does not come first in initial
# library list".  Other tests (cheat_daemon_leaf, etc.) already do this;
# this test was missing it, which caused WT to die ~immediately and the
# test to falsely report "WT did not log SAME_HEIGHT reorg".
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$WT_BIN" \
    --network regtest \
    --wt-db "$WT_DB" \
    --poll-interval 2 \
    --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
echo "  WT started PID=$WT_PID"

# Let WT poll a few times to baseline its tip-hash state
sleep 8

BASELINE_HEIGHT=$($BCLI getblockcount)
BASELINE_HASH=$($BCLI getbestblockhash)
echo "  baseline: height=$BASELINE_HEIGHT hash=${BASELINE_HASH:0:16}..."

# Force a same-height reorg:
# 1. mine 1 block at height N
# 2. invalidateblock that block (chain rolls back to N-1)
# 3. mine 1 NEW block on the same chain at height N (different hash)
$BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null
H_BEFORE=$($BCLI getblockcount)
HASH_BEFORE=$($BCLI getbestblockhash)
echo "  mined: height=$H_BEFORE hash=${HASH_BEFORE:0:16}..."

# Wait for WT to see + update its last_hash to this new block
sleep 6

# Pause WT so it doesn't see the intermediate (height drop after invalidate
# but before remine) — we want SAME_HEIGHT detection, not HEIGHT_REGRESSION
kill -STOP $WT_PID

# Now invalidate + remine while WT is frozen
$BCLI invalidateblock "$HASH_BEFORE" >/dev/null
$BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null

# Resume WT — its next poll will see same height, different hash
kill -CONT $WT_PID
H_AFTER=$($BCLI getblockcount)
HASH_AFTER=$($BCLI getbestblockhash)
echo "  reorg: height=$H_AFTER hash=${HASH_AFTER:0:16}... (same height, different hash)"

if [ "$H_BEFORE" != "$H_AFTER" ]; then
    echo "FAIL: height differs after reorg (expected same)"
    exit 1
fi
if [ "$HASH_BEFORE" = "$HASH_AFTER" ]; then
    echo "FAIL: hash matches after reorg (expected different)"
    exit 1
fi

# Give WT time to poll + detect the reorg
echo "  waiting for WT to detect SAME_HEIGHT reorg..."
DETECTED=0
for i in $(seq 1 30); do
    sleep 2
    if grep -qE "REORG \(SAME_HEIGHT\)" "$WT_LOG" 2>/dev/null; then
        DETECTED=1
        echo "  WT detected SAME_HEIGHT reorg after ${i}*2s"
        break
    fi
done

echo
echo "=== WT log tail ==="
tail -15 "$WT_LOG"

echo
echo "=== Result ==="
if [ $DETECTED -eq 1 ]; then
    echo "  PASS: same-height reorg detected by WT"
    exit 0
else
    echo "  FAIL: WT did not log SAME_HEIGHT reorg"
    exit 1
fi
