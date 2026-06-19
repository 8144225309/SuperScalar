#!/usr/bin/env bash
# test_regtest_cheat_client.sh — adversarial-client PS leaf cheat (regtest).
#
# Validates CL7: --cheat-client SIDE on a client makes that client broadcast
# the pre-advance leaf signed_tx during the wire ceremony (before sending
# its partial signature back to the LSP). LSP-internal WT must still detect
# and defend with response_tx + poison TX.
#
# Gap 2 close: the LSP is honest. --watchtower-final-check (Gap 2 flag)
# makes the LSP run watchtower_check after force-close. The CL7 marker in
# the cheating client log + the WT response TXs in broadcast_log together
# prove the adversarial-client path is detected by the honest LSP's WT.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
CHEATING_CLIENT="${CHEATING_CLIENT:-0}"   # index of client to apply --cheat-client to

FUNDING_SATS=100000
LSP_PORT=29953
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

TMPDIR=$(mktemp -d /tmp/ss-cheat-client.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/cheat_client_last_lsp.log 2>/dev/null || true
    cp "$REORG_LOG"  /tmp/cheat_client_last_reorg.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_client_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/cheat_client_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_client_last_lsp.{log,db}, /tmp/cheat_client_last_client_*.log"
}
trap cleanup EXIT

echo "=== ADVERSARIAL CLIENT CHEAT (regtest) ==="
echo "  N clients        : $N_CLIENTS"
echo "  cheating client  : $CHEATING_CLIENT"
echo "  side             : $SIDE"
echo "  funding          : $FUNDING_SATS sats"

# --- bitcoind ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, chain at height $($BCLI getblockcount)"


REORG_LOG="$TMPDIR/reorg.log"
REORG_PID=$(start_reorg_watcher "$REORG_LOG")
PIDS+=($REORG_PID)
echo "  reorg watcher PID=$REORG_PID logging to $REORG_LOG"
MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

# --- LSP (also cheats on same side so watchtower_check runs at end) ---
echo
echo "--- LSP (--demo --test-leaf-advance --watchtower-final-check, honest LSP) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --demo --test-leaf-advance --watchtower-final-check \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died"; tail -20 "$LSP_LOG"; exit 1; }
done

# --- Clients (client[CHEATING_CLIENT] gets --cheat-client SIDE) ---
for i in $(seq 0 $((N_CLIENTS - 1))); do
    EXTRA=""
    if [ "$i" = "$CHEATING_CLIENT" ]; then EXTRA="--cheat-client $SIDE"; fi
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        $EXTRA \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); echo "  client[$i]${EXTRA:+ (with $EXTRA)}"
    sleep 0.5
done

(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

echo
echo "--- Waiting for LEAF ADVANCE TEST {PASSED,FAILED} (timeout 600s) ---"
for i in $(seq 1 300); do
    sleep 2
    grep -qE "LEAF ADVANCE TEST (PASSED|FAILED)" "$LSP_LOG" 2>/dev/null && break
    if [ $((i % 15)) -eq 0 ]; then
        CL7=$(grep -cE "CL7: client.*broadcast STALE" "$TMPDIR/client_${CHEATING_CLIENT}.log" 2>/dev/null || echo 0)
        echo "  ... ${i}*2s elapsed, CL7 markers=$CL7"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

wait $LSP_PID 2>/dev/null || true

# --- Verification ---
echo
echo "=== CL7 markers in client[$CHEATING_CLIENT] log ==="
grep -E "CL7:" "$TMPDIR/client_${CHEATING_CLIENT}.log" | head -5 || echo "  (no CL7 markers)"
echo
echo "=== broadcast_log entries ==="
sqlite3 "$LSP_DB" "SELECT id, source, result, substr(txid,1,32) FROM broadcast_log ORDER BY id;" 2>/dev/null | head -25
echo
echo "=== cheat_client_stale entries (client-side broadcast log) ==="
for cdb in "$TMPDIR"/client_*.db; do
    if [ -f "$cdb" ]; then
        echo "--- $(basename $cdb) ---"
        sqlite3 "$cdb" "SELECT id, source, result, substr(txid,1,32) FROM broadcast_log WHERE source='cheat_client_stale';" 2>/dev/null
    fi
done

echo
echo "=== reorg events ==="
if [ -s "$REORG_LOG" ]; then
    cat "$REORG_LOG"
else
    echo "  (none)"
fi
echo
echo "=== Final result ==="
if grep -q "LEAF ADVANCE TEST PASSED" "$LSP_LOG" 2>/dev/null; then
    CL7_FIRED=$(grep -cE "CL7: client.*broadcast STALE" "$TMPDIR/client_${CHEATING_CLIENT}.log" 2>/dev/null)
    if [ "${CL7_FIRED:-0}" -ge 1 ]; then
        echo "  PASS: adversarial client CL7 path fired ($CL7_FIRED stale broadcasts), WT defense fired"
        
# CL7 (#218): assert net-delta(cheater) <= 0 ON-CHAIN — the trustless guarantee, not a
# broadcast_log row count. The old code counted result='ok' rows (mempool-accepted, NOT
# confirmed) and *declared* "net <= 0" without checking anything. This now: (1) pulls the
# REAL defense txids, (2) CONFIRMS at least one on-chain + asserts a real recapture amount,
# (3) proves the cheater's stale broadcast yields no surviving cheater-spendable value.
echo "=== CL7: verifying net-delta(cheater) <= 0 (confirmed on-chain, not log rows) ==="
set +e   # leave strict mode for the verification block (explicit exits below)
DEF_TXIDS=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE source IN ('penalty','factory_response','factory_burn','subfactory_poison','htlc_penalty','ptlc_penalty') AND result='ok' AND length(txid)=64;" 2>/dev/null)
[ -n "$DEF_TXIDS" ] || { echo "FAIL: no defense tx broadcast — cheater would net positive"; exit 1; }
# (1) result='ok' is mempool-accepted, NOT confirmed — mine to bury, then require a real confirm.
$BCLI generatetoaddress 6 "$MINE_ADDR" >/dev/null 2>&1
DEF_OK=""; DEF_SATS=0
for t in $DEF_TXIDS; do
    raw=$($BCLI getrawtransaction "$t" true 2>/dev/null)
    echo "$raw" | grep -q '"confirmations"' || continue
    DEF_OK="$t"
    v=$(echo "$raw" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    DEF_SATS=$(awk "BEGIN{printf \"%d\", ($v+0)*100000000}")
    break
done
[ -n "$DEF_OK" ] || { echo "FAIL: defense tx(s) in broadcast_log never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
echo "  defense tx $DEF_OK confirmed on-chain; largest output ${DEF_SATS:-0} sats"
[ "${DEF_SATS:-0}" -ge 5000 ] || { echo "FAIL: defense output ${DEF_SATS} sats too small — not a real recapture (dust/zero?)"; exit 1; }
# (2) net-delta: the cheater's stale broadcast must yield no surviving cheater-spendable value —
#     either it never confirmed (superseded by the defense), or it confirmed but a confirmed
#     defense tx spends its output (recapture). Both => cheater nets <= 0.
STALE_TXID=$(sqlite3 "$TMPDIR/client_${CHEATING_CLIENT}.db" "SELECT txid FROM broadcast_log WHERE source='cheat_client_stale' AND length(txid)=64 ORDER BY id LIMIT 1;" 2>/dev/null)
if [ -n "$STALE_TXID" ]; then
    sraw=$($BCLI getrawtransaction "$STALE_TXID" true 2>/dev/null)
    if echo "$sraw" | grep -q '"confirmations"'; then
        spent=0
        for t in $DEF_TXIDS; do
            if $BCLI getrawtransaction "$t" true 2>/dev/null | grep -q "$STALE_TXID"; then spent=1; break; fi
        done
        [ "$spent" = 1 ] || { echo "FAIL: cheater stale tx $STALE_TXID confirmed but no confirmed defense tx spends it — cheater may net positive"; exit 1; }
        echo "  cheater stale tx confirmed but recaptured by a confirmed defense tx → net <= 0"
    else
        echo "  cheater stale tx $STALE_TXID never confirmed (superseded by the defense) → net <= 0"
    fi
else
    echo "  (no cheat_client_stale txid recorded; the confirmed-defense gate above still stands)"
fi
echo "  PASS: confirmed trustless defense ($DEF_OK, ${DEF_SATS} sats) — cheater net <= 0 verified on-chain"
exit 0
    else
        echo "  FAIL: no CL7 markers in cheating client log"
        exit 1
    fi
else
    echo "  FAIL: LEAF ADVANCE TEST did not PASSED"
    tail -30 "$LSP_LOG"
    exit 1
fi
