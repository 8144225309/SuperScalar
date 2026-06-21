#!/usr/bin/env bash
# test_regtest_hashlock_poison_e2e.sh — #53 Phase 4c: hashlock L-stock poison
# end-to-end on regtest, through the LIVE LSP<->client daemon ceremony.
#
# This is the proof that Phases 1-3 work together:
#   1. LSP runs --enable-hashlock-poison --cheat-daemon-leaf: it builds a
#      hashlock-gated factory (Phase 3), then advances a PS leaf over the REAL
#      wire ceremony with running clients.  During the advance (Phases 1-2):
#        - the client mirrors the new-state hash H_new (builds the same SPK),
#        - both sides capture the superseded state's hash H_old,
#        - they co-sign the Leaf-P poison against H_old (script-path, untweaked),
#        - the LSP reveals secret_old (MSG_LSTOCK_REVEAL),
#        - the client verifies SHA256(secret)==H_old and PERSISTS the row
#          (l_stock_poison_reveals) with the template + the revealed secret.
#   2. The cheating LSP broadcasts the SUPERSEDED pre-advance leaf state on-chain
#      (trying to over-claim its L-stock at a revoked state).
#   3. The CLIENT recourse tool (superscalar_lstock_recover) loads the persisted
#      reveal, assembles the Leaf-P poison [agg_sig, secret, script, control
#      block], and we broadcast it.
#   4. ASSERT: the poison CONFIRMS on-chain and redistributes the L-stock
#      (a real, non-dust output) — the economic outcome, not just a marker.
#   5. ANTI-VACUITY: with the revealed secret removed, the tool REFUSES (exit 5)
#      — no reveal, no recourse (the #53 security property).
#
# Models the client-driven recourse (the secret-less standalone WT cannot
# assemble a hashlock poison alone — see #62).  Sibling of
# test_regtest_cheat_daemon_leaf.sh (the key-path-poison standalone-WT variant).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
REC_BIN="$BUILD_DIR/superscalar_lstock_recover"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"   # 0=left, 1=right

FUNDING_SATS=100000
LSP_PORT=29957                # distinct from cheat-leaf (29950) / daemon-leaf (29951)
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

TMPDIR=$(mktemp -d /tmp/ss-hashlock-e2e.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
MINER_WALLET="ss_hashlock_e2e_miner"

PIDS=()
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/hashlock_e2e_last_lsp.log 2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/hashlock_e2e_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== HASHLOCK L-STOCK POISON E2E (regtest, #53 Phase 4c) ==="
echo "  build dir : $BUILD_DIR"
echo "  N clients : $N_CLIENTS   side: $SIDE   funding: $FUNDING_SATS sats"
echo "  bitcoind  : $REGTEST_CONF"
echo

# --- bitcoind ---
echo "--- bitcoind regtest check ---"
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, height $($BCLI getblockcount)"

$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready, 101 blocks mined"

# --- LSP daemon (hashlock poison + cheat) ---
echo
echo "--- LSP daemon (--enable-hashlock-poison --cheat-daemon-leaf $SIDE) ---"
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
    --enable-hashlock-poison \
    --demo --cheat-daemon-leaf $SIDE \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening (PID=$LSP_PID)"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -20 "$LSP_LOG"; exit 1; }
done
grep -q "hashlock-gated L-stock poison ENABLED" "$LSP_LOG" || { echo "FAIL: hashlock poison not enabled in LSP"; tail -20 "$LSP_LOG"; exit 1; }
echo "  hashlock poison ENABLED confirmed in LSP log"

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
    PIDS+=($!)
    echo "  client[$i] PID=$!"
    sleep 0.5
done

# --- Background miner ---
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) &
PIDS+=($!)

# --- Wait for CHEAT DAEMON COMPLETE ---
echo
echo "--- Waiting for advance + stale broadcast + CHEAT DAEMON COMPLETE (timeout 360s) ---"
READY=0
for i in $(seq 1 180); do
    sleep 2
    grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { READY=1; echo "  CHEAT DAEMON COMPLETE after ${i}*2s"; break; }
    [ $((i % 15)) -eq 0 ] && echo "  ... ${i}*2s elapsed"
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done
[ $READY -eq 1 ] || { echo "FAIL: no CHEAT DAEMON COMPLETE in 360s"; tail -50 "$LSP_LOG"; exit 1; }

STALE_TXID=$(grep -E "Stale pre-advance leaf broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
echo "  Stale (superseded) leaf broadcast txid: ${STALE_TXID:-(unknown)}"
[ -n "$STALE_TXID" ] || { echo "FAIL: no stale broadcast txid"; tail -30 "$LSP_LOG"; exit 1; }

# Reveal fires DURING the advance (well before the marker); stop clients so their
# SQLite DBs are flushed before we read them.
echo "  Stopping clients so their persist DBs flush..."
for pid in "${PIDS[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
sleep 3

# --- Find the client that persisted the reveal ---
echo
echo "=== Locating the client-persisted reveal (l_stock_poison_reveals) ==="
REVEAL_DB=""; REVEAL_NODE=""; REVEAL_STATE=""
for i in $(seq 0 $((N_CLIENTS - 1))); do
    row=$(sqlite3 "$TMPDIR/client_${i}.db" \
        "SELECT node_idx||' '||state_counter FROM l_stock_poison_reveals WHERE revocation_secret IS NOT NULL ORDER BY state_counter ASC LIMIT 1;" 2>/dev/null || true)
    if [ -n "$row" ]; then
        REVEAL_DB="$TMPDIR/client_${i}.db"
        REVEAL_NODE=$(echo "$row" | awk '{print $1}')
        REVEAL_STATE=$(echo "$row" | awk '{print $2}')
        echo "  reveal persisted by client[$i]: node=$REVEAL_NODE state=$REVEAL_STATE db=$REVEAL_DB"
        break
    fi
done
[ -n "$REVEAL_DB" ] || { echo "FAIL: NO client persisted an l_stock_poison_reveals row — the reveal wire (Phase 2) did not fire"; exit 1; }

# --- Mine the stale leaf to maturity, then assemble + broadcast the poison ---
echo
echo "=== CLIENT recourse: assemble hashlock poison from persisted reveal ==="
$BCLI generatetoaddress 3 "$MINE_ADDR" >/dev/null 2>&1
POISON_HEX=$("$REC_BIN" --db "$REVEAL_DB" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" 2>/tmp/_rec.err) || {
    echo "FAIL: superscalar_lstock_recover failed (rc=$?)"; cat /tmp/_rec.err; exit 1; }
echo "  assembled poison (${#POISON_HEX} hex chars)"
POISON_TXID=$($BCLI sendrawtransaction "$POISON_HEX" 2>/tmp/_send.err) || {
    echo "FAIL: poison sendrawtransaction REJECTED"; cat /tmp/_send.err
    echo "  (mempool reject means the persisted template/secret did not yield a spend of the stale L-stock output)"; exit 1; }
echo "  POISON broadcast txid: $POISON_TXID"

# --- Confirm + amount ---
echo
echo "=== Verifying poison CONFIRMS + redistributes L-stock ==="
PRAW=""
for n in $(seq 1 10); do
    $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1
    PRAW=$($BCLI getrawtransaction "$POISON_TXID" true 2>/dev/null || true)
    echo "$PRAW" | grep -q '"confirmations"' && break
done
echo "$PRAW" | grep -q '"confirmations"' || { echo "FAIL: poison $POISON_TXID never CONFIRMED"; exit 1; }
PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
echo "  poison CONFIRMED; largest output ${PSATS:-0} sats"
[ "${PSATS:-0}" -ge 1000 ] || { echo "FAIL: poison output ${PSATS} sats <= dust — not a real L-stock recapture"; exit 1; }

# --- Anti-vacuity: no revealed secret -> no recourse ---
echo
echo "=== Anti-vacuity: tool must REFUSE when the secret is absent ==="
cp "$REVEAL_DB" "$TMPDIR/novax.db"
sqlite3 "$TMPDIR/novax.db" "UPDATE l_stock_poison_reveals SET revocation_secret=NULL;" 2>/dev/null
set +e
"$REC_BIN" --db "$TMPDIR/novax.db" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" >/dev/null 2>/tmp/_nv.err
NRC=$?
set -e
echo "  no-secret recourse exit=$NRC (expect 5)"; cat /tmp/_nv.err 2>/dev/null || true
[ "$NRC" = "5" ] || { echo "FAIL: tool did NOT refuse a missing reveal (anti-vacuity broken)"; exit 1; }

echo
echo "=== PASS: hashlock L-stock poison E2E ==="
echo "  advance->reveal->persist->assemble->broadcast->CONFIRM proven on regtest"
echo "  poison $POISON_TXID confirmed, ${PSATS} sats recaptured; no-reveal refused (exit 5)"
exit 0
