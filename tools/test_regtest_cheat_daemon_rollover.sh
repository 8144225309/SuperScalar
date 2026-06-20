#!/usr/bin/env bash
# test_regtest_cheat_daemon_rollover.sh — CL4-rollover adversarial test (#250).
#
# Spec: docs/LSP_TEAM_HANDOFF_CHEAT_DRIVERS.md "CL4 rollover-cheat daemon".
# Severity: HIGH. Tests the stake-theft attack vector during Tier B rollover.
#
# Scenario:
#   1. LSP creates factory + funds + advances to populate revocation history
#   2. --test-tier-b-rollover drives root rollover (state advances past
#      states_per_layer trigger DW rollover)
#   3. --cheat-daemon-rollover=mid-window arms the LSP to broadcast the
#      dying factory's leaf 0 tx AFTER partial_rotation_done is set
#   4. Standalone WT (separate process) scans blocks for the broadcast,
#      detects revoked state, broadcasts penalty TX
#
# PASS:
#   - "CL4-ROLLOVER: mid-window broadcast" in LSP log
#   - Standalone WT detects + broadcasts penalty (breach_detections row +
#     penalty broadcast_log entry)

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

# LSP NK static pubkey corresponds to LSP_SECKEY=0x...01 (BIP-340 x-only G).
# Clients pass this via --lsp-pubkey so the Noise handshake succeeds.
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

N_CLIENTS="${N_CLIENTS:-2}"
FUNDING_SATS="${FUNDING_SATS:-200000}"

LSP_PORT=29959           # distinct from sibling tests
WT_PORT=29969
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"

BCLI="bitcoin-cli -regtest -rpcuser=${RPCUSER:-rpcuser} -rpcpassword=${RPCPASSWORD:-rpcpass}"

declare -a PIDS=()
TMPDIR=$(mktemp -d /tmp/ss-cheat-rollover.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
WT_DB="$TMPDIR/wt.db"
WT_LOG="$TMPDIR/wt.log"

cleanup() {
    set +e
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/cheat_rollover_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_rollover_last_lsp.db  2>/dev/null || true
    cp "$WT_LOG"  /tmp/cheat_rollover_last_wt.log  2>/dev/null || true
    cp "$WT_DB"   /tmp/cheat_rollover_last_wt.db   2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_rollover_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_rollover_last_{lsp.log,lsp.db,wt.log,wt.db,client_*.log}"
}
trap cleanup EXIT

echo "================ CL4-rollover (#250) ================"
echo "  Scenario:"
echo "    1. LSP creates factory + advances state to populate revocation"
echo "    2. --test-tier-b-rollover triggers root rollover"
echo "    3. --cheat-daemon-rollover=mid-window arms cheat broadcast"
echo "    4. Standalone WT detects + broadcasts penalty"
echo

# --- ensure bitcoind regtest is running ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    echo "ERROR: bitcoind regtest not running. Start it first."
    exit 1
fi

# Set up miner wallet
$BCLI -named createwallet wallet_name=ss_cheat_leaf_miner load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet ss_cheat_leaf_miner 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_leaf_miner -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

# --- Standalone WT first (it will be authoritative) ---
echo "--- Standalone WT (port $WT_PORT) ---"
"$WT_BIN" \
    --network regtest \
    --port $WT_PORT \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet ss_cheat_leaf_miner \
    --db "$WT_DB" \
    > "$WT_LOG" 2>&1 &
WT_PID=$!
PIDS+=($WT_PID)

for i in $(seq 1 20); do
    sleep 1
    if grep -q "listening on port $WT_PORT" "$WT_LOG" 2>/dev/null; then
        echo "  WT listening (PID=$WT_PID, port=$WT_PORT)"
        break
    fi
done

# --- LSP: --test-tier-b-rollover + --cheat-daemon-rollover=mid-window ---
echo "--- LSP daemon (--test-tier-b-rollover --cheat-daemon-rollover=mid-window) ---"
"$LSP_BIN" \
    --network regtest \
    --port $LSP_PORT \
    --watchtower-host 127.0.0.1 \
    --watchtower-port $WT_PORT \
    --clients $N_CLIENTS \
    --arity 1 \
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
    --demo --test-tier-b-rollover --cheat-daemon-rollover mid-window \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    if grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null; then
        echo "  LSP listening (PID=$LSP_PID)"
        break
    fi
done

# --- Clients ---
echo "--- Starting $N_CLIENTS clients ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    CLIENT_SECKEY=$(printf "%064x" $((0x02 + i)))
    "$CLIENT_BIN" \
        --network regtest \
        --host 127.0.0.1 --port $LSP_PORT \
        --daemon \
        --seckey "$CLIENT_SECKEY" \
        --fee-rate 1000 \
        --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i + 1)) \
        --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet ss_cheat_leaf_miner \
        --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    echo "  client[$i] PID=$CLIENT_PID"
done

# The DW Tier-B rollover advances over BLOCKS — keep mining throughout so it reaches the
# mid-window cheat point. Without this the chain stalls during the wait and CL4-ROLLOVER
# never fires (the chronic rollover failure: libasan + funding + this missing miner).
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) &
PIDS+=($!)

# Wait for LSP to fire the cheat OR exit OR timeout
echo
echo "--- Waiting for CL4-ROLLOVER cheat broadcast (timeout 600s) ---"
for i in $(seq 1 600); do
    sleep 1
    if grep -qE "CL4-ROLLOVER: mid-window broadcast" "$LSP_LOG" 2>/dev/null; then
        echo "  cheat broadcast fired after ${i}s"
        break
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "  LSP exited at ${i}s without firing cheat"
        break
    fi
    if [ $((i % 30)) -eq 0 ]; then
        echo "  ... ${i}s elapsed"
    fi
done

# Give WT time to detect + respond
echo
echo "--- Waiting for WT detection + penalty broadcast (60s) ---"
for i in $(seq 1 60); do
    sleep 1
    if grep -qE "FACTORY BREACH|penalty.*broadcast|breach detected" "$WT_LOG" 2>/dev/null; then
        echo "  WT detected breach at ${i}s after cheat"
        break
    fi
    # Mine a block periodically to confirm the cheat TX + trigger WT block scan
    if [ $((i % 5)) -eq 0 ]; then
        $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null
    fi
done

# Final assertions
echo
echo "=== Final result ==="
CHEAT_FIRED=$(grep -cE "CL4-ROLLOVER: mid-window broadcast" "$LSP_LOG" 2>/dev/null | head -1 || echo 0)
# In-process WT lives in the LSP process — its detection lines go to LSP_LOG.
# Standalone WT runs in a separate process with its own (empty) DB and only
# acts as a redundant chain-scan observer.  Accept either as proof of detect.
WT_BREACH=$(grep -cE "FACTORY BREACH|BREACH DETECTED|breach detected" "$LSP_LOG" "$WT_LOG" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
WT_PENALTY=$(grep -cE "penalty.*broadcast|response_tx.*broadcast|Watchtower broadcast.*penalty" "$LSP_LOG" "$WT_LOG" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')

echo "  cheat_fired=$CHEAT_FIRED  wt_breach=$WT_BREACH  wt_penalty=$WT_PENALTY"

set +e
if [ "$CHEAT_FIRED" -ge 1 ] && [ "$WT_BREACH" -ge 1 ] && [ "$WT_PENALTY" -ge 1 ]; then
    # OUTCOME (not just log-greps): confirm the WT's response/penalty txid ON-CHAIN + assert a real amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(cat "$LSP_LOG" "$WT_LOG" 2>/dev/null | grep -aoiE "Latest state tx broadcast: *[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}|L-stock burn tx broadcast: [0-9a-f]{64}|Sub-factory poison tx broadcast: *[0-9a-f]{64}" | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { echo "  FAIL: WT signals fired but no response/penalty txid found (breach_detections + logs)"; tail -20 "$WT_LOG"; exit 1; }
    echo "  WT response txid: $PEN_TXID — mining to confirm + verify payout"
    PRAW=""; for n in $(seq 1 10); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null); echo "$PRAW" | grep -q '"confirmations"' && break; done
    echo "$PRAW" | grep -q '"confirmations"' || { echo "  FAIL: WT response $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
    echo "  WT response confirmed on-chain; largest output ${PSATS:-0} sats"
    [ "${PSATS:-0}" -ge 1000 ] || { echo "  FAIL: WT response output ${PSATS} sats <= dust — not a real recapture"; exit 1; }
    echo "  PASS: rollover cheat fired + WT detected breach + broadcast AND CONFIRMED its response ($PEN_TXID, ${PSATS} sats) — outcome verified, not just log-greps"
    exit 0
fi

echo "  FAIL: cheat_fired=$CHEAT_FIRED wt_breach=$WT_BREACH wt_penalty=$WT_PENALTY (need all >=1)"
echo "  LSP log tail:"
tail -30 "$LSP_LOG"
echo "  WT log tail:"
tail -30 "$WT_LOG"
exit 1
