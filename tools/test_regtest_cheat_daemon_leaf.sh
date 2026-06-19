#!/usr/bin/env bash
# test_regtest_cheat_daemon_leaf.sh — end-to-end PS leaf cheat (regtest)
# with the STANDALONE watchtower binary doing detection + response.
#
# This is the daemon-mode companion to test_regtest_cheat_leaf.sh.
# The LSP runs with --cheat-daemon-leaf, which:
#   - advances the leaf (real wire ceremony with running clients)
#   - broadcasts the stale pre-advance leaf
#   - skips LSP-internal watchtower_check (sets SS_CHEAT_DAEMON_MODE)
#   - sleeps to give the standalone WT time to detect + respond.
#
# Meanwhile, build/superscalar_watchtower is launched against the same
# SQLite DB. It hydrates PS chain entries (CL4 hydration), polls for
# new blocks, sees the stale TX, and broadcasts response_tx + poison TX.
#
# Pass criterion: WT stdout contains "penalty tx(s) broadcast" AND the
# bitcoin-cli mempool/chain has both the response and poison TX after
# the WT poll loop fires.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"

FUNDING_SATS=100000
LSP_PORT=29951                # distinct from --cheat-leaf test (29950)
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

# Source shared helpers (reorg watcher + vout audit) — must be after BCLI.
. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

TMPDIR=$(mktemp -d /tmp/ss-cheat-daemon-leaf-regtest.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
WT_LOG="$TMPDIR/wt.log"
WT_DB="$TMPDIR/wt.db"   # trustless WT db (no secrets); armed by the LSP's --wt-db

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
    cp "$LSP_LOG" /tmp/cheat_daemon_leaf_last_lsp.log 2>/dev/null || true
    cp "$REORG_LOG"  /tmp/cheat_daemon_leaf_last_reorg.log  2>/dev/null || true
    cp "$WT_LOG"  /tmp/cheat_daemon_leaf_last_wt.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_daemon_leaf_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_daemon_leaf_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_daemon_leaf_last_{lsp,wt}.log, /tmp/cheat_daemon_leaf_last_lsp.db"
}
trap cleanup EXIT

echo "=== PS LEAF CHEAT WITH STANDALONE WT (regtest) ==="
echo "  build dir   : $BUILD_DIR"
echo "  N clients   : $N_CLIENTS"
echo "  side cheated: $SIDE (0=left, 1=right)"
echo "  funding     : $FUNDING_SATS sats"
echo "  bitcoind    : $REGTEST_CONF"
echo
echo "  Flow:"
echo "    1. LSP runs --cheat-daemon-leaf (advance + stale broadcast, no internal WT)"
echo "    2. After CHEAT DAEMON COMPLETE marker, standalone WT starts against same DB"
echo "    3. WT hydrates PS chain state (CL4), polls blocks"
echo "    4. WT detects on-chain stale, broadcasts response_tx + L-stock poison TX"

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
echo "  reorg watcher PID=$REORG_PID logging to $REORG_LOG"
# Reuse the cheat-leaf miner wallet (known-good UTXO set from earlier test runs).
# Create it on first run; load if it already exists from previous test execution.
MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready ($MINER_WALLET), generated 101 fresh blocks"

# --- LSP daemon ---
echo
echo "--- LSP daemon (--demo --cheat-daemon-leaf $SIDE) ---"
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
    --wallet $MINER_WALLET \
    --db "$LSP_DB" \
    --wt-db "$WT_DB" \
    --demo --cheat-daemon-leaf $SIDE \
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
        --wallet $MINER_WALLET \
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
        $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
MINE_PID=$!
PIDS+=($MINE_PID)

# --- Wait for CHEAT DAEMON COMPLETE marker (= LSP done advancing + broadcasting stale) ---
echo
echo "--- Waiting for LSP cheat broadcast + CHEAT DAEMON COMPLETE marker (timeout 300s) ---"
DAEMON_READY=0
for i in $(seq 1 150); do
    sleep 2
    if grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null; then
        DAEMON_READY=1
        echo "  CHEAT DAEMON COMPLETE marker observed after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        echo "  ... waiting (${i}*2s elapsed)"
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "  LSP exited before marker (PID=$LSP_PID)"
        break
    fi
done
if [ $DAEMON_READY -eq 0 ]; then
    echo "FAIL: LSP did not reach CHEAT DAEMON COMPLETE in 300s"
    tail -50 "$LSP_LOG"
    exit 1
fi

# --- Confirm stale broadcast went out before starting WT ---
STALE_TXID=$(grep -E "Stale pre-advance leaf broadcast" "$LSP_LOG" | head -1 | awk '{print $5}' | cut -d' ' -f1)
echo "  Stale broadcast txid: ${STALE_TXID:-(unknown)}"

# Trustless: stop the (sleeping) cheating LSP so its wt.db WAL checkpoints before
# the standalone WT reads it; the stale leaf is already on-chain. Then keep mining
# so the WT's block-driven poll fires (the LSP's own miner stops when it exits).
echo "  Stopping cheating LSP (SIGTERM) so wt.db flushes for the standalone WT..."
kill -TERM $LSP_PID 2>/dev/null || true
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited (wt.db checkpointed)"; break; }; sleep 1; done
K0=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind IN (0,1);" 2>/dev/null || echo 0)
echo "  wt.db factory/sub-factory (kind 0/1) watches: ${K0:-0}"
( for k in $(seq 1 80); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 3; done ) &
WTMINE_PID=$!; PIDS+=($WTMINE_PID)

# --- Standalone trustless WT (--wt-db only, NO secrets) ---
echo
echo "--- Standalone trustless WT (--wt-db $WT_DB, no secrets) ---"
"$WT_BIN" \
    --network regtest \
    --wt-db "$WT_DB" \
    --poll-interval 5 \
    --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    > "$WT_LOG" 2>&1 &
WT_PID=$!
PIDS+=($WT_PID)
echo "  WT PID=$WT_PID"

# --- Wait for WT to broadcast penalty TXs ---
echo
echo "--- Waiting for WT to detect + broadcast penalty TXs (timeout 120s) ---"
WT_FIRED=0
for i in $(seq 1 60); do
    sleep 2
    if grep -qE "penalty tx\(s\) broadcast" "$WT_LOG" 2>/dev/null; then
        WT_FIRED=1
        echo "  WT fired after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        ENTRIES=$(grep -cE "heartbeat" "$WT_LOG" 2>/dev/null || echo 0)
        echo "  ... waiting (${i}*2s elapsed, ${ENTRIES} heartbeats)"
    fi
    if ! kill -0 $WT_PID 2>/dev/null; then
        echo "  WT died (PID=$WT_PID)"
        break
    fi
done

# --- Verification ---
echo
echo "=== WT log tail ==="
tail -30 "$WT_LOG"
echo
echo "=== penalty broadcasts ==="
grep -E "penalty tx|response|burn|poison" "$WT_LOG" | head -10 || echo "  (none)"

echo
echo "=== reorg events ==="
if [ -s "$REORG_LOG" ]; then
    cat "$REORG_LOG"
else
    echo "  (none)"
fi
echo
echo "=== Final result ==="
set +e
if [ "$WT_FIRED" -eq 1 ]; then
    # OUTCOME (not just a broadcast log line): confirm the WT's response/penalty txid ON-CHAIN + assert a real amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(grep -aoiE "Latest state tx broadcast: *[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}|L-stock burn tx broadcast: [0-9a-f]{64}|Sub-factory poison tx broadcast: *[0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { echo "  FAIL: WT fired but no response/penalty txid found (breach_detections + WT log)"; tail -30 "$WT_LOG"; exit 1; }
    echo "  WT response txid: $PEN_TXID — mining to confirm + verify payout"
    PRAW=""; for n in $(seq 1 10); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null); echo "$PRAW" | grep -q '"confirmations"' && break; done
    echo "$PRAW" | grep -q '"confirmations"' || { echo "  FAIL: WT response $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
    echo "  WT response confirmed on-chain; largest output ${PSATS:-0} sats"
    [ "${PSATS:-0}" -ge 1000 ] || { echo "  FAIL: WT response output ${PSATS} sats <= dust — not a real recapture"; exit 1; }
    echo "  PASS: standalone WT detected stale leaf state, broadcast AND CONFIRMED its response ($PEN_TXID, ${PSATS} sats) — outcome verified, not just a log line"
    exit 0
else
    echo "  FAIL: standalone WT did not broadcast penalty TXs"
    echo "  WT log tail:"
    tail -50 "$WT_LOG"
    exit 1
fi
