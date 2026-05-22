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
$BCLI -named createwallet wallet_name=ss_cheat_rollover_miner load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet ss_cheat_rollover_miner 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_rollover_miner -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

# --- Standalone WT first (it will be authoritative) ---
echo "--- Standalone WT (port $WT_PORT) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$WT_BIN" \
    --network regtest \
    --port $WT_PORT \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet ss_cheat_rollover_miner \
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
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
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
    --wallet ss_cheat_rollover_miner \
    --db "$LSP_DB" \
    --demo --test-tier-b-rollover --cheat-daemon-rollover=mid-window \
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
        --lsp-host 127.0.0.1 \
        --lsp-port $LSP_PORT \
        --seckey "$CLIENT_SECKEY" \
        --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet ss_cheat_rollover_miner \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    echo "  client[$i] PID=$CLIENT_PID"
done

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
WT_BREACH=$(grep -cE "FACTORY BREACH|breach detected" "$WT_LOG" 2>/dev/null | head -1 || echo 0)
WT_PENALTY=$(grep -cE "penalty.*broadcast|response_tx.*broadcast" "$WT_LOG" 2>/dev/null | head -1 || echo 0)

echo "  cheat_fired=$CHEAT_FIRED  wt_breach=$WT_BREACH  wt_penalty=$WT_PENALTY"

if [ "$CHEAT_FIRED" -ge 1 ] && [ "$WT_BREACH" -ge 1 ] && [ "$WT_PENALTY" -ge 1 ]; then
    echo "  PASS: cheat fired + WT detected breach + WT broadcast penalty"
    exit 0
fi

echo "  FAIL: cheat_fired=$CHEAT_FIRED wt_breach=$WT_BREACH wt_penalty=$WT_PENALTY (need all >=1)"
echo "  LSP log tail:"
tail -30 "$LSP_LOG"
echo "  WT log tail:"
tail -30 "$WT_LOG"
exit 1
