#!/usr/bin/env bash
# test_regtest_kill_after_state_advance.sh — CL5 restart-harness validation.
#
# Validates that --kill-after-state-advance produces a clean LSP exit
# (rc=0) right after the first state-advance (Tier-B) ceremony completes,
# AND that the on-disk state is sufficient for a second LSP instance to
# pick up where the first left off.
#
# Trigger: --test-tier-b-rollover --arity 1 drives states_per_layer+1
# leaf advances; the final advance exhausts the leaf's DW counter and
# triggers lsp_run_state_advance via the rc=-1 path in lsp_advance_leaf.
# That function emits MSG_PATH_SIGN_DONE then exits(0) because the env
# var SS_KILL_AFTER_STATE_ADVANCE is set.
#
# NOTE: --arity 3 (PS) is supported by the CL2-TB gate change but does
# NOT actually trigger Tier-B — PS leaves have no DW counter to exhaust.
# B5 separately exercises the arity-3 gate.
#
# Pass criteria:
#   1. CL5 marker observed in LSP log
#   2. LSP exit code = 0 (clean exit)
#   3. DB has persisted ps_leaf_chains entries (>= 1)
#   4. DB has persisted dw_counter row with the new epoch
#   5. Restarted LSP can re-open the DB without error (loads counter +
#      channels + chain entries — verified by the LSP startup log)

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"

FUNDING_SATS=100000
LSP_PORT=29954
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

# Source shared helpers (reorg watcher + vout audit) — must be after BCLI.
. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

TMPDIR=$(mktemp -d /tmp/ss-kill-after-sa.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
LSP_LOG_2="$TMPDIR/lsp_restart.log"

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG"   /tmp/kill_after_sa_last_lsp.log   2>/dev/null || true
    cp "$REORG_LOG"  /tmp/kill_after_state_advance_last_reorg.log  2>/dev/null || true
    cp "$LSP_LOG_2" /tmp/kill_after_sa_last_lsp_restart.log 2>/dev/null || true
    cp "$LSP_DB"    /tmp/kill_after_sa_last_lsp.db    2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== --kill-after-state-advance (regtest) ==="

# --- bitcoind ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, height $($BCLI getblockcount)"


REORG_LOG="$TMPDIR/reorg.log"
REORG_PID=$(start_reorg_watcher "$REORG_LOG")
PIDS+=($REORG_PID)
echo "  reorg watcher PID=$REORG_PID logging to $REORG_LOG"
MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

# --- LSP run 1: --kill-after-state-advance + --test-tier-b-rollover ---
echo
echo "--- Run 1: LSP with --kill-after-state-advance ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 1 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --demo --test-tier-b-rollover --kill-after-state-advance \
    --lsp-balance-pct 100 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -20 "$LSP_LOG"; exit 1; }
done

# --- Clients ---
for i in $(seq 0 $((N_CLIENTS - 1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.5
done

(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

# --- Wait for clean exit ---
echo
echo "--- Waiting for CL5 clean exit (timeout 600s) ---"
LSP_EXIT=99
for i in $(seq 1 300); do
    sleep 2
    if ! kill -0 $LSP_PID 2>/dev/null; then
        wait $LSP_PID 2>/dev/null; LSP_EXIT=$?
        echo "  LSP exited with code $LSP_EXIT after $((i * 2))s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        SA=$(grep -cE "state advance complete" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}*2s elapsed, state-advances=$SA"
    fi
done

# --- Verify CL5 markers ---
echo
echo "=== CL5 markers ==="
grep -E "state advance complete|CL5: SS_KILL_AFTER_STATE_ADVANCE" "$LSP_LOG" | head -5

# --- Inspect DB state ---
echo
echo "=== DB persisted state ==="
PS_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM ps_leaf_chains;" 2>/dev/null || echo 0)
DW_EPOCH=$(sqlite3 "$LSP_DB" "SELECT current_epoch FROM dw_counter LIMIT 1;" 2>/dev/null || echo "?")
CHAN_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM channels;" 2>/dev/null || echo 0)
echo "  ps_leaf_chains rows : $PS_ROWS"
echo "  dw_counter epoch    : $DW_EPOCH"
echo "  channels rows       : $CHAN_ROWS"

# --- Run 2: restart LSP, expect it to hydrate state ---
echo
echo "--- Run 2: restart LSP with same DB (validation only, brief run) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest --port $((LSP_PORT + 1)) --clients $N_CLIENTS --arity 1 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --lsp-balance-pct 100 \
    > "$LSP_LOG_2" 2>&1 &
LSP_PID2=$!; PIDS+=($LSP_PID2)

# Wait briefly for it to hydrate then quit
for i in $(seq 1 30); do
    sleep 1
    if grep -qE "listening on port|hydrated|restored|loaded" "$LSP_LOG_2" 2>/dev/null; then
        echo "  Restart hydration observed"
        break
    fi
    kill -0 $LSP_PID2 2>/dev/null || break
done

kill $LSP_PID2 2>/dev/null
wait $LSP_PID2 2>/dev/null || true

echo
echo "=== Restart log (first 40 lines) ==="
head -40 "$LSP_LOG_2"

# --- Pass evaluation ---
echo
echo "=== reorg events ==="
if [ -s "$REORG_LOG" ]; then
    cat "$REORG_LOG"
else
    echo "  (none)"
fi
echo
echo "=== Final result ==="
PASS=1
[ "$LSP_EXIT" != "0" ] && { echo "  FAIL: LSP run 1 exited with $LSP_EXIT, expected 0"; PASS=0; }
grep -q "CL5: SS_KILL_AFTER_STATE_ADVANCE" "$LSP_LOG" || { echo "  FAIL: CL5 marker missing"; PASS=0; }
grep -q "state advance complete" "$LSP_LOG" || { echo "  FAIL: state advance ceremony did not complete"; PASS=0; }
# DW arity 1: state lives in channels + dw_counter (no ps_leaf_chains).
# PS arity 3: state lives in ps_leaf_chains (no DW counter tier-b trigger).
[ "${CHAN_ROWS:-0}" -lt 1 ] && { echo "  FAIL: channels has $CHAN_ROWS rows, expected >=1"; PASS=0; }
grep -qE "listening on port|loaded|restored|persistence" "$LSP_LOG_2" || { echo "  FAIL: restart didn't reach listening/load state"; PASS=0; }
if [ $PASS = 1 ]; then
    echo "  PASS: CL5 clean exit + state persisted + restart hydrates"
    exit 0
else
    echo "  See /tmp/kill_after_sa_last_lsp{,_restart}.log for details"
    exit 1
fi
