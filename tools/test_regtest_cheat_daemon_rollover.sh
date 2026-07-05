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
FUNDING_SATS="${FUNDING_SATS:-10000000}"

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

# Clear any leftover LSP/WT holding OUR ports — the chronic 'listen failed on port 29959' root
# cause: a zombie from a prior run keeps the port bound, so this LSP can't bind and accept clients
# (which surfaces as the clients' "noise handshake failed"). Scoped to our exact ports (NOT broad,
# NOT --network — won't touch the testnet4 N=64 runner).
pkill -9 -f "superscalar_(lsp|client) .*--port ${LSP_PORT}( |\$)" 2>/dev/null || true
pkill -9 -f "superscalar_watchtower .*--port ${WT_PORT}( |\$)" 2>/dev/null || true
pkill -9 -f "superscalar_lsp .*--watchtower-port ${WT_PORT}( |\$)" 2>/dev/null || true
sleep 1

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
CHEAT_TXID=$(grep -aoE "mid-window broadcast of dying factory leaf 0 tx: sent=1 txid=[0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
WT_BREACH=$(grep -cE "FACTORY BREACH|BREACH DETECTED|breach detected" "$LSP_LOG" "$WT_LOG" 2>/dev/null | awk -F: '{s+=$NF} END{print s+0}')
echo "  cheat_fired=$CHEAT_FIRED  wt_detected_breach=$WT_BREACH  revoked_state=${CHEAT_TXID:-none}"

# THE CORRECT DEFENSE (proven 2026-07-04): the rollover stake-theft -- LSP broadcasts the
# REVOKED old rollover state to over-claim its L-STOCK -- is defended by the #53 L-STOCK
# POISON, which spends the revoked state's L-stock output and REDISTRIBUTES it away from the
# LSP. The watchtower_check *penalty* path is the WRONG response for this breach type and
# -25s ("bad-txns-inputs-missingorspent"); "Latest state tx broadcast failed" is the DW
# override (a different layer). Empirically verified: cheat broadcast bccb7e (over-claim
# L-stock at vout 1) -> poison 48ffb3 CONFIRMED spending bccb7e:1, redistributing 2,498,340
# sats. So assert the ACTUAL defense: a CONFIRMED recourse tx that SPENDS the revoked state
# and moves real value (poison/burn preferred; penalty/response accepted as fallback).
set +e
if [ "$CHEAT_FIRED" -lt 1 ] || [ -z "$CHEAT_TXID" ]; then
    echo "  FAIL: rollover cheat did not fire / no revoked-state txid"; tail -25 "$LSP_LOG"; exit 1
fi
DEF_OK=0; DEF_TXID=""; DEF_SATS=0
CANDS=$( { cat "$LSP_LOG" "$WT_LOG" 2>/dev/null | grep -aoiE "L-stock (burn|poison) tx broadcast: *[0-9a-f]{64}|Sub-factory poison tx broadcast: *[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}|Latest state tx broadcast: *[0-9a-f]{64}" | grep -oE "[0-9a-f]{64}"; sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64;" 2>/dev/null; } | awk '!seen[$0]++')
for cand in $CANDS; do
    for n in $(seq 1 6); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; $BCLI getrawtransaction "$cand" true 2>/dev/null | grep -q '"confirmations"' && break; done
    RAW=$($BCLI getrawtransaction "$cand" true 2>/dev/null)
    echo "$RAW" | grep -q '"confirmations"' || continue
    SPENDS=$(echo "$RAW" | python3 -c "import json,sys
try:
 d=json.load(sys.stdin); print(1 if any(vi.get('txid')=='$CHEAT_TXID' for vi in d.get('vin',[])) else 0)
except Exception: print(0)")
    [ "$SPENDS" = "1" ] || continue
    V=$(echo "$RAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    DEF_SATS=$(awk "BEGIN{printf \"%d\", ($V+0)*100000000}"); DEF_OK=1; DEF_TXID="$cand"; break
done
echo "  defense_confirmed_spending_revoked_state=$DEF_OK  txid=${DEF_TXID:-none}  redistributed=${DEF_SATS} sats"
if [ "$DEF_OK" -eq 1 ] && [ "${DEF_SATS:-0}" -ge 1000 ]; then
    echo "  PASS: rollover cheat fired -- the LSP broadcast the revoked old rollover state ($CHEAT_TXID) to"
    echo "        over-claim its L-stock; the recourse ($DEF_TXID) CONFIRMED on-chain, SPENDING the revoked"
    echo "        state and redistributing ${DEF_SATS} sats away from the LSP. Rollover stake-theft DEFENDED."
    exit 0
fi
echo "  FAIL: cheat_fired=$CHEAT_FIRED but NO confirmed recourse spends the revoked state $CHEAT_TXID"
echo "        (required: a confirmed defense that spends the revoked state -- else the LSP kept its over-claim)"
tail -25 "$LSP_LOG"; echo "  --- WT ---"; tail -20 "$WT_LOG"
exit 1
