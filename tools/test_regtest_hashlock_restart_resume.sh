#!/usr/bin/env bash
# test_regtest_hashlock_restart_resume.sh — #59 LSP restart-resume proof.
#
# Proves a hashlock-poison factory SURVIVES an LSP restart (the gap: the seed was
# ephemeral + the reload never re-enabled hashlock). With the deterministic seed
# (factory_derive_lstock_seed: LSP key + funding outpoint) + the persisted
# use_hashlock_poison intent (schema v39), a restarted LSP re-derives the SAME seed
# and re-enables — no stored secret.
#
#   Run 1: LSP --enable-hashlock-poison --demo --test-leaf-advance + clients.
#          A PS leaf advances -> client persists an l_stock_poison_reveals row;
#          the factory is persisted with use_hashlock_poison=1. LSP exits.
#   Verify: factories.use_hashlock_poison == 1; a client persisted a reveal.
#   Run 2: restart LSP --enable-hashlock-poison --daemon with the SAME --db ->
#          recovery probe loads the factory, RE-DERIVES the seed + RE-ENABLES.
#   Verify: run-2 log shows the RE-ENABLED (seed re-derived) marker + listening;
#          the client's pre-restart poison is still assemblable (superscalar_lstock_recover).
#
# Combined with the unit proof that the derivation is deterministic (same inputs ->
# same seed), this shows the re-derived seed == the original, so the LSP resumes
# revealing + builds matching hashlock SPKs after restart.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
REC_BIN="$BUILD_DIR/superscalar_lstock_recover"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
FUNDING_SATS=100000
LSP_PORT=29959
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

ASAN_ENV="ASAN_OPTIONS=detect_leaks=0"
if ldd "$LSP_BIN" 2>/dev/null | grep -q libasan; then
    ASAN_ENV="ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8"
fi

TMPDIR=$(mktemp -d /tmp/ss-hashlock-restart.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp1.log"; LSP_LOG2="$TMPDIR/lsp2.log"
MINER_WALLET="ss_hashlock_restart_miner"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG"  /tmp/hashlock_restart_last_lsp1.log 2>/dev/null || true
    cp "$LSP_LOG2" /tmp/hashlock_restart_last_lsp2.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== HASHLOCK LSP RESTART-RESUME (regtest, #59) ==="
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner ready, height $($BCLI getblockcount)"

# --- Run 1: create + advance a hashlock factory, then exit ---
echo
echo "--- Run 1: LSP --enable-hashlock-poison --test-leaf-advance ---"
env $ASAN_ENV \
"$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --enable-hashlock-poison --demo --test-leaf-advance --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || break
done
for i in $(seq 0 $((N_CLIENTS - 1))); do
    env $ASAN_ENV \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i + 1)) --daemon --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} --wallet $MINER_WALLET \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.5
done
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) &
MINE_PID=$!; PIDS+=($MINE_PID)

echo "--- Waiting for run-1 advance + clean exit (timeout 400s) ---"
for i in $(seq 1 200); do
    sleep 2
    if ! kill -0 $LSP_PID 2>/dev/null; then echo "  run-1 LSP exited after $((i*2))s"; break; fi
done
kill -9 $MINE_PID 2>/dev/null || true
# stop clients so their DBs flush
for pid in "${PIDS[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
sleep 3

echo
echo "=== Verify run-1 persisted a hashlock factory + a client reveal ==="
UHP=$(sqlite3 "$LSP_DB" "SELECT use_hashlock_poison FROM factories WHERE id=0;" 2>/dev/null || echo "?")
echo "  factories.use_hashlock_poison = ${UHP:-?} (expect 1)"
[ "${UHP:-0}" = "1" ] || { echo "FAIL: factory did not persist use_hashlock_poison=1"; tail -25 "$LSP_LOG"; exit 1; }
REVEAL_DB=""; REVEAL_NODE=""; REVEAL_STATE=""
for i in $(seq 0 $((N_CLIENTS - 1))); do
    row=$(sqlite3 "$TMPDIR/client_${i}.db" "SELECT node_idx||' '||state_counter FROM l_stock_poison_reveals WHERE revocation_secret IS NOT NULL LIMIT 1;" 2>/dev/null || true)
    if [ -n "$row" ]; then REVEAL_DB="$TMPDIR/client_${i}.db"; REVEAL_NODE=$(echo "$row"|awk '{print $1}'); REVEAL_STATE=$(echo "$row"|awk '{print $2}'); echo "  client[$i] persisted reveal: node=$REVEAL_NODE state=$REVEAL_STATE"; break; fi
done
[ -n "$REVEAL_DB" ] || { echo "FAIL: no client persisted an l_stock_poison_reveals row in run 1"; exit 1; }

# --- Run 2: restart LSP with the SAME db -> recovery must re-derive + re-enable ---
echo
echo "--- Run 2: restart LSP (recovery mode, same --db) ---"
env $ASAN_ENV \
"$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --enable-hashlock-poison --daemon --lsp-balance-pct 50 \
    > "$LSP_LOG2" 2>&1 &
LSP_PID2=$!; PIDS+=($LSP_PID2)
RESUMED=0
for i in $(seq 1 60); do
    sleep 1
    if grep -q "hashlock L-stock poison RE-ENABLED" "$LSP_LOG2" 2>/dev/null; then RESUMED=1; echo "  RE-ENABLED marker observed after ${i}s"; break; fi
    kill -0 $LSP_PID2 2>/dev/null || { echo "  run-2 LSP exited early"; break; }
done
kill -9 $LSP_PID2 2>/dev/null || true

echo
echo "=== Verify restart-resume ==="
grep -E "found existing factory|RE-ENABLED|seed re-derived" "$LSP_LOG2" | head -4 || true
[ $RESUMED -eq 1 ] || { echo "FAIL: restarted LSP did NOT re-enable hashlock (seed re-derive)"; echo "--- run2 tail ---"; tail -30 "$LSP_LOG2"; exit 1; }

# The client's pre-restart poison must still be assemblable (unchanged by LSP restart).
$BCLI generatetoaddress 2 "$MINE_ADDR" >/dev/null 2>&1
HEX=$("$REC_BIN" --db "$REVEAL_DB" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" 2>/tmp/_rr.err) || {
    echo "FAIL: client poison no longer assembles after LSP restart"; cat /tmp/_rr.err; exit 1; }
echo "  client poison still assembles post-restart (${#HEX} hex chars)"

echo
echo "=== PASS: hashlock LSP restart-resume ==="
echo "  factory persisted use_hashlock_poison; restart re-derived the deterministic seed"
echo "  + re-enabled; client recourse intact across the LSP restart"
exit 0
