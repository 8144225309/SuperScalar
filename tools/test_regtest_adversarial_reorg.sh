#!/usr/bin/env bash
# test_regtest_adversarial_reorg.sh — R4 mainnet pre-flight.
#
# Drives all THREE reorg kinds against the standalone superscalar_watchtower
# (R6, PR #204) via bitcoin-cli invalidateblock + generatetoaddress.  The WT
# must log each kind correctly and call watchtower_on_reorg.
#
#   1. HEIGHT_REGRESSION — invalidate the tip block; tip moves backward.
#   2. SAME_HEIGHT       — invalidate tip, remine a different block at
#                          the SAME height (different blockhash).
#   3. FORWARD_REORG     — note tip-at-height-N; invalidate block N;
#                          mine N+M blocks on the new chain; tip advances
#                          but the block at N is no longer canonical.
#
# Why regtest not signet: full chain control, deterministic, zero sat
# cost (signet budget is tight; reserved for organic-fee testing).
#
# Pairs with the older test_regtest_same_height_reorg.sh which covers
# only SAME_HEIGHT.  This script supersedes that one by also covering
# FORWARD_REORG (the dominant reorg shape on competitive chains) and
# HEIGHT_REGRESSION (rare but possible).

set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-adversarial-reorg.XXXXXX)
WT_DB="$TMPDIR/wt.db"
WT_LOG="$TMPDIR/wt.log"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$WT_LOG" /tmp/adversarial_reorg_last_wt.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== R4: adversarial reorg test (3 kinds vs standalone WT) ==="

# ---- bitcoind + wallet setup ----
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)

# Ensure mature chain
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
START_HEIGHT=$($BCLI getblockcount)
echo "  Starting at height $START_HEIGHT"

# Empty WT DB
sqlite3 "$WT_DB" "CREATE TABLE broadcast_log (id INTEGER PRIMARY KEY, txid TEXT, source TEXT, raw_hex TEXT, result TEXT, broadcast_time DATETIME DEFAULT CURRENT_TIMESTAMP);" 2>/dev/null

# Start standalone WT
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$WT_BIN" \
    --network regtest \
    --db "$WT_DB" \
    --poll-interval 15 \
    --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
echo "  WT started PID=$WT_PID"

# Let WT poll + baseline.  poll-interval=15s so we have a generous
# atomic window for invalidate+remine without the WT seeing the
# intermediate state.
sleep 20

ALL_PASS=1

# =====================================================================
# Scenario 1: HEIGHT_REGRESSION
#   Mine 1 block.  Pause WT.  Invalidate that block.  Resume WT.
#   WT sees tip went backward.
# =====================================================================
echo
echo "--- Scenario 1: HEIGHT_REGRESSION ---"
$BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null
H1=$($BCLI getblockcount)
HASH1=$($BCLI getbestblockhash)
echo "  mined: height=$H1 hash=${HASH1:0:16}..."
sleep 20  # let WT poll (poll-interval=15s) so it sees the new tip

: # (removed: kill -STOP caused ASan-instrumented WT to die under bash job-control. Long poll-interval gives us a wide enough window to invalidate+remine atomically.)  # freeze WT
$BCLI invalidateblock "$HASH1" >/dev/null
H_AFTER=$($BCLI getblockcount)
echo "  invalidated: tip now height=$H_AFTER (regressed)"
: # (removed: see kill -STOP note)

DETECTED_REGRESS=0
for i in $(seq 1 12); do
    sleep 5  # poll-interval=15s, so each detection should land in 1-2 iterations
    if grep -qE "REORG \(HEIGHT_REGRESSION\)" "$WT_LOG" 2>/dev/null; then
        DETECTED_REGRESS=1
        echo "  WT detected HEIGHT_REGRESSION after ${i}*2s"
        break
    fi
done
if [ $DETECTED_REGRESS -eq 1 ]; then
    echo "  PASS: HEIGHT_REGRESSION detected"
else
    echo "  FAIL: WT did not log HEIGHT_REGRESSION"
    ALL_PASS=0
fi

# Rebuild tip so WT settles to known baseline before next scenario
$BCLI generatetoaddress 2 "$MINE_ADDR" >/dev/null
sleep 20  # settle baseline between scenarios

# =====================================================================
# Scenario 2: SAME_HEIGHT
#   Mine 1 block.  Pause WT (so it doesn't see the regression).
#   Invalidate + remine at SAME height with new hash.  Resume WT.
#   WT sees same height but different hash.
# =====================================================================
echo
echo "--- Scenario 2: SAME_HEIGHT ---"
$BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null
H2=$($BCLI getblockcount)
HASH2_BEFORE=$($BCLI getbestblockhash)
echo "  mined: height=$H2 hash=${HASH2_BEFORE:0:16}..."
sleep 20  # let WT poll past intermediate state

: # (removed: kill -STOP caused ASan-instrumented WT to die under bash job-control. Long poll-interval gives us a wide enough window to invalidate+remine atomically.)  # freeze (hide the intermediate height drop)
$BCLI invalidateblock "$HASH2_BEFORE" >/dev/null
$BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null
H2_AFTER=$($BCLI getblockcount)
HASH2_AFTER=$($BCLI getbestblockhash)
if [ "$H2" != "$H2_AFTER" ]; then
    echo "  setup error: heights differ after reorg ($H2 vs $H2_AFTER)"
    ALL_PASS=0
fi
if [ "$HASH2_BEFORE" = "$HASH2_AFTER" ]; then
    echo "  setup error: hash unchanged after invalidate+remine"
    ALL_PASS=0
fi
echo "  reorg: height=$H2_AFTER hash=${HASH2_AFTER:0:16}... (same height, new hash)"
: # (removed: see kill -STOP note)

DETECTED_SAME=0
for i in $(seq 1 12); do
    sleep 5  # poll-interval=15s, so each detection should land in 1-2 iterations
    if grep -qE "REORG \(SAME_HEIGHT\)" "$WT_LOG" 2>/dev/null; then
        DETECTED_SAME=1
        echo "  WT detected SAME_HEIGHT after ${i}*2s"
        break
    fi
done
if [ $DETECTED_SAME -eq 1 ]; then
    echo "  PASS: SAME_HEIGHT detected"
else
    echo "  FAIL: WT did not log SAME_HEIGHT"
    ALL_PASS=0
fi

# Settle to fresh baseline
$BCLI generatetoaddress 2 "$MINE_ADDR" >/dev/null
sleep 20  # settle baseline between scenarios

# =====================================================================
# Scenario 3: FORWARD_REORG
#   Mine 1 block at height N (block_a).  Let WT see it.
#   Pause WT.  Invalidate block_a.  Mine 5 new blocks (different chain).
#   Resume WT.  WT sees tip advanced past N (to N+4), but the block at
#   height N is no longer block_a — FORWARD_REORG detected.
# =====================================================================
echo
echo "--- Scenario 3: FORWARD_REORG ---"
$BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null
H3=$($BCLI getblockcount)
HASH3_ORIG=$($BCLI getbestblockhash)
echo "  mined block_a: height=$H3 hash=${HASH3_ORIG:0:16}..."
sleep 20  # WT sees block_a as canonical at height $H3 (poll-interval=15s)

: # (removed: kill -STOP caused ASan-instrumented WT to die under bash job-control. Long poll-interval gives us a wide enough window to invalidate+remine atomically.)
$BCLI invalidateblock "$HASH3_ORIG" >/dev/null
$BCLI generatetoaddress 5 "$MINE_ADDR" >/dev/null
H3_AFTER=$($BCLI getblockcount)
HASH3_AT_H3=$($BCLI getblockhash $H3)
if [ "$HASH3_AT_H3" = "$HASH3_ORIG" ]; then
    echo "  setup error: block at height $H3 still original"
    ALL_PASS=0
fi
echo "  forward reorg: tip advanced to height=$H3_AFTER; block at $H3 is now ${HASH3_AT_H3:0:16}... (was ${HASH3_ORIG:0:16}...)"
: # (removed: see kill -STOP note)

DETECTED_FORWARD=0
for i in $(seq 1 12); do
    sleep 5  # poll-interval=15s, so each detection should land in 1-2 iterations
    if grep -qE "REORG \(FORWARD_REORG\)" "$WT_LOG" 2>/dev/null; then
        DETECTED_FORWARD=1
        echo "  WT detected FORWARD_REORG after ${i}*2s"
        break
    fi
done
if [ $DETECTED_FORWARD -eq 1 ]; then
    echo "  PASS: FORWARD_REORG detected"
else
    echo "  FAIL: WT did not log FORWARD_REORG"
    ALL_PASS=0
fi

# ---- Final report ----
echo
echo "=== WT log tail ==="
tail -25 "$WT_LOG"

echo
echo "=== R4 Result ==="
if [ $ALL_PASS -eq 1 ]; then
    echo "  PASS: all 3 reorg kinds detected (HEIGHT_REGRESSION + SAME_HEIGHT + FORWARD_REORG)"
    exit 0
else
    echo "  FAIL: at least one reorg kind not detected"
    exit 1
fi
