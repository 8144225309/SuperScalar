#!/usr/bin/env bash
# test_regtest_cheat_daemon_leaf_multistate.sh — multi-state PS leaf cheat
# (regtest) with the STANDALONE watchtower binary doing detection +
# response.
#
# Validates CL3-K (broadcast chain[K] for K in [0, N-1] after N advances)
# AND CL4 standalone-WT path together — the missing daemon companion to
# test_regtest_cheat_leaf_multistate.sh.  The daemon variants for
# single-state (cheat_daemon_leaf) and sub-factory (cheat_daemon_subfactory)
# already exist; this fills the multi-state gap.
#
# The LSP runs with --cheat-daemon-leaf + --advance-count N + --cheat-state K,
# which:
#   - drives N consecutive PS leaf advances via the real wire ceremony
#   - snapshots chain[K] mid-loop (when K>0) or chain[0] pre-loop (K=0)
#   - broadcasts the snapshot AFTER all N advances complete (so it's a
#     stale state from the watchtower's perspective)
#   - skips LSP-internal watchtower_check (SS_CHEAT_DAEMON_MODE=1)
#   - sleeps to give the standalone WT time to detect + respond
#
# Meanwhile, build/superscalar_watchtower is launched against the same
# SQLite DB.  It hydrates PS chain entries (CL4 hydration), polls for new
# blocks, sees the stale TX, and broadcasts response_tx + poison TX.
#
# Pass criterion: WT stdout contains "penalty tx(s) broadcast" AND a
# matching breach_detections row is persisted.
#
# Env:
#   N_CLIENTS=4          number of client processes
#   SIDE=0|1             which leaf side to cheat (0=left default, 1=right)
#   ADVANCE_COUNT=3      how many advances to drive before broadcasting
#   CHEAT_STATE=0..N-1   which chain index to broadcast (CL3-K, 0 default)
#
# Sibling of:
#   - test_regtest_cheat_leaf_multistate.sh (multi-state, LSP-internal WT)
#   - test_regtest_cheat_daemon_leaf.sh     (single-state, standalone WT)

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
ADVANCE_COUNT="${ADVANCE_COUNT:-3}"
CHEAT_STATE="${CHEAT_STATE:-0}"

FUNDING_SATS=100000
LSP_PORT=29953                # distinct from 29950..29952 used by sibling tests
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

TMPDIR=$(mktemp -d /tmp/ss-cheat-daemon-leaf-multistate.XXXXXX)
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
    cp "$LSP_LOG" /tmp/cheat_daemon_leaf_multistate_last_lsp.log 2>/dev/null || true
    cp "$REORG_LOG"  /tmp/cheat_daemon_leaf_multistate_last_reorg.log  2>/dev/null || true
    cp "$WT_LOG"  /tmp/cheat_daemon_leaf_multistate_last_wt.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_daemon_leaf_multistate_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_daemon_leaf_multistate_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_daemon_leaf_multistate_last_{lsp,wt}.log, /tmp/cheat_daemon_leaf_multistate_last_lsp.db"
}
trap cleanup EXIT

echo "=== PS LEAF CHEAT MULTI-STATE WITH STANDALONE WT (regtest) ==="
echo "  build dir     : $BUILD_DIR"
echo "  N clients     : $N_CLIENTS"
echo "  side cheated  : $SIDE (0=left, 1=right)"
echo "  advance count : $ADVANCE_COUNT"
echo "  cheat state K : $CHEAT_STATE (CL3-K: 0=oldest stale chain[0]; >0 = middle state chain[K])"
echo "  funding       : $FUNDING_SATS sats"
echo "  bitcoind      : $REGTEST_CONF"
echo
echo "  Flow:"
echo "    1. LSP runs --cheat-daemon-leaf with N advances + --cheat-state K"
echo "    2. After CHEAT DAEMON COMPLETE marker, standalone WT starts against same DB"
echo "    3. WT hydrates PS chain state (CL4), polls blocks"
echo "    4. WT detects on-chain chain[K] stale broadcast, broadcasts response_tx + L-stock poison TX"

# --- bitcoind ---
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

# Reuse the cheat-leaf miner wallet (shared with sibling tests).
MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready ($MINER_WALLET), generated 101 fresh blocks"

# --- LSP daemon ---
echo
CHEAT_STATE_ARG=()
if [ "${CHEAT_STATE:-0}" -gt 0 ]; then
    CHEAT_STATE_ARG=(--cheat-state "$CHEAT_STATE")
fi
echo "--- LSP daemon (--demo --cheat-daemon-leaf $SIDE --advance-count $ADVANCE_COUNT ${CHEAT_STATE_ARG[*]:-}) ---"
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
    --demo --cheat-daemon-leaf $SIDE --advance-count $ADVANCE_COUNT \
    "${CHEAT_STATE_ARG[@]}" \
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

# --- Wait for CHEAT DAEMON COMPLETE marker ---
echo
echo "--- Waiting for LSP cheat broadcast + CHEAT DAEMON COMPLETE marker (timeout 600s) ---"
DAEMON_READY=0
EARLY_TIER_B=0
for i in $(seq 1 300); do
    sleep 2
    if grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null; then
        DAEMON_READY=1
        echo "  CHEAT DAEMON COMPLETE marker observed after ${i}*2s"
        break
    fi
    # Alternative defense outcome: Tier B neutralized the stale broadcast
    # before the cheat could land. The LSP never reaches CHEAT DAEMON
    # COMPLETE because the cheat-broadcast loop short-circuits.  Accept this
    # as a valid termination and let the final-result block apply the
    # Tier-B-neutralized PASS criterion.
    if grep -q "Tier B made stale state unspendable" "$LSP_LOG" 2>/dev/null; then
        EARLY_TIER_B=1
        echo "  Tier B neutralized stale state before cheat completed (alt outcome) after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        ADV=$(grep -cE "PS leaf.*advanced|advance [0-9]+/[0-9]+ done" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... waiting (${i}*2s elapsed, $ADV advances observed)"
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "  LSP exited before marker (PID=$LSP_PID)"
        break
    fi
done
if [ $DAEMON_READY -eq 0 ] && [ $EARLY_TIER_B -eq 0 ]; then
    echo "FAIL: LSP did not reach CHEAT DAEMON COMPLETE or Tier-B-defense marker in 600s"
    tail -50 "$LSP_LOG"
    exit 1
fi

# --- Stale broadcast confirmation (skipped on EARLY_TIER_B path) ---
if [ $EARLY_TIER_B -eq 1 ]; then
    echo
    echo "=== Final result (Tier-B-neutralized path) ==="
    echo "  SKIP: LSP-side Tier B neutralized the stale state before the cheat broadcast — the"
    echo "  standalone WT defense (this test's subject) was NOT exercised, so this run is"
    echo "  INCONCLUSIVE, NOT a PASS. Re-run with Tier-B rollover disabled to validate the WT."
    echo "  (cf. sibling cheat_leaf_multistate.sh: Tier-B-neutralized by itself is not a WT defense.)"
    exit 77
fi
STALE_TXID=$(grep -E "Stale pre-advance leaf broadcast" "$LSP_LOG" | head -1 | awk -F'broadcast: ' '{print $2}' | awk '{print $1}')
SNAPSHOT_AT=$(grep -E "CL3-K: snapshotted chain\[" "$LSP_LOG" | head -1 | sed -E 's/.*chain\[([0-9]+)\].*/\1/')
echo "  Stale broadcast txid: ${STALE_TXID:-(unknown)}"
echo "  Snapshot K value    : ${SNAPSHOT_AT:-0} (expected $CHEAT_STATE)"
if [ -n "$SNAPSHOT_AT" ] && [ "$SNAPSHOT_AT" != "$CHEAT_STATE" ]; then
    echo "  WARN: snapshotted K=$SNAPSHOT_AT does not match requested K=$CHEAT_STATE"
fi

# Trustless: stop the LSP so wt.db WAL checkpoints; keep mining for the WT poll.
echo "  Stopping LSP (SIGTERM) so wt.db flushes for the standalone WT..."
kill -TERM $LSP_PID 2>/dev/null || true
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done
MA2=$($BCLI -rpcwallet=ss_cheat_leaf_miner getnewaddress 2>/dev/null)
( for k in $(seq 1 80); do $BCLI generatetoaddress 1 "$MA2" >/dev/null 2>&1; sleep 3; done ) & PIDS+=($!)
# --- Standalone trustless Watchtower (--wt-db only) ---
echo
echo "--- Standalone trustless WT (--wt-db $WT_DB) ---"
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
echo "--- Waiting for WT to detect + broadcast penalty TXs (timeout 180s) ---"
WT_FIRED=0
for i in $(seq 1 90); do
    sleep 2
    if grep -qE "penalty tx\(s\) broadcast" "$WT_LOG" 2>/dev/null; then
        WT_FIRED=1
        echo "  WT fired after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        HEARTBEATS=$(grep -cE "heartbeat" "$WT_LOG" 2>/dev/null || echo 0)
        echo "  ... waiting (${i}*2s elapsed, ${HEARTBEATS} heartbeats)"
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
echo "=== breach_detections rows ==="
sqlite3 "$LSP_DB" "SELECT id, txid_seen, response_txid, timestamp FROM breach_detections;" 2>/dev/null | head -10 || echo "  (table empty or missing)"
echo
echo "=== ps_leaf_chains contents ==="
sqlite3 "$LSP_DB" "SELECT factory_id, leaf_node_idx, chain_pos, substr(txid,1,32), length(signed_tx_hex), chan_amount_sats FROM ps_leaf_chains;" 2>/dev/null
echo
echo "=== reorg events ==="
[ -s "$REORG_LOG" ] && cat "$REORG_LOG" || echo "  (none)"
echo
echo "=== Final result ==="
# This test validates the STANDALONE trustless WT. PASS requires the WT to have actually
# defended AND for that defense to CONFIRM on-chain — not a broadcast log line, and NOT an
# unrelated LSP-side Tier B rollover (a different mechanism that tells us nothing about the WT).
# cf. sibling cheat_leaf_multistate.sh: "Tier B made stale unspendable by itself is NOT a
# defense — counting it as PASS false-positives a broken WT."
set +e
TIER_B_NEUTRALIZED=$(grep -cE "Tier B made stale state unspendable|stale broadcast failed" "$LSP_LOG" 2>/dev/null | head -1)
TIER_B_NEUTRALIZED="${TIER_B_NEUTRALIZED:-0}"
if [ "$WT_FIRED" -eq 1 ]; then
    BREACHES=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM breach_detections;" 2>/dev/null || echo 0)
    # OUTCOME: confirm the WT's response/penalty txid ON-CHAIN + assert a real recapture amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(grep -aoiE "Latest state tx broadcast: *[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}|L-stock burn tx broadcast: [0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { echo "  FAIL: WT fired but no response/penalty txid found (breach_detections empty + no WT-log txid)"; tail -30 "$WT_LOG"; exit 1; }
    echo "  WT response txid: $PEN_TXID (breach_detections=$BREACHES rows) — mining to confirm + verify payout"
    $BCLI generatetoaddress 6 "$MINE_ADDR" >/dev/null 2>&1
    PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null)
    echo "$PRAW" | grep -q '"confirmations"' || { echo "  FAIL: WT response $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
    echo "  WT response confirmed on-chain; largest output ${PSATS:-0} sats"
    [ "${PSATS:-0}" -ge 1000 ] || { echo "  FAIL: WT response output ${PSATS} sats <= dust — not a real recapture (dust/zero?)"; exit 1; }
    echo "  PASS: standalone WT detected chain[$CHEAT_STATE] stale, broadcast AND CONFIRMED its response ($PEN_TXID, ${PSATS} sats) — outcome verified, not just a log line"
    exit 0
elif [ "$TIER_B_NEUTRALIZED" -ge 1 ]; then
    echo "  SKIP: LSP-side Tier B neutralized the stale state before the standalone WT could observe it."
    echo "  This run did NOT exercise the WT defense (a different valid mechanism won the race), so it is"
    echo "  INCONCLUSIVE for this test's subject — NOT a PASS. Re-run with Tier-B rollover disabled to validate the WT."
    exit 77
else
    echo "  FAIL: standalone WT did NOT broadcast a penalty for the leaf-multistate breach"
    echo "  WT log tail:"
    tail -50 "$WT_LOG"
    exit 1
fi
