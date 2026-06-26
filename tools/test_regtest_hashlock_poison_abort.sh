#!/usr/bin/env bash
# test_regtest_hashlock_poison_abort.sh — #53 Phase 5 degradation-abort assertion.
#
# Proves the fail-closed guard: when hashlock poison is ON but the Leaf-P poison
# for the superseded state is NOT co-signed, the client MUST REFUSE to advance
# (it would otherwise revoke the old state with no recourse = Scenario A/B).
#
# Mechanism: the LSP runs with SS_CHEAT_OMIT_POISON=1, which makes it skip poison
# prep — so it co-signs the new state but ships an LSP_RESPONSE with no poison
# fields.  The client detects the missing poison, hits the guard before shipping
# FINAL, and aborts ("no revoke without recourse").  ASSERT: the client logs the
# refusal AND no l_stock_poison_reveals row is persisted (the advance did not
# complete) AND the leaf did NOT reach CHEAT DAEMON COMPLETE.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
FUNDING_SATS=100000
LSP_PORT=29958
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

TMPDIR=$(mktemp -d /tmp/ss-hashlock-abort.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
MINER_WALLET="ss_hashlock_abort_miner"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/hashlock_abort_last_lsp.log 2>/dev/null || true
    cp "$TMPDIR/client_0.log" /tmp/hashlock_abort_last_client0.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== HASHLOCK POISON DEGRADATION-ABORT (regtest, #53 Phase 5) ==="
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner ready, height $($BCLI getblockcount)"

echo "--- LSP (--enable-hashlock-poison --cheat-daemon-leaf $SIDE, SS_CHEAT_OMIT_POISON=1) ---"
env $ASAN_ENV SS_CHEAT_OMIT_POISON=1 \
"$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --enable-hashlock-poison --demo --cheat-daemon-leaf $SIDE --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -20 "$LSP_LOG"; exit 1; }
done

echo "--- $N_CLIENTS clients ---"
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
PIDS+=($!)

echo "--- Waiting for the client refusal (timeout 180s) ---"
REFUSED=0
for i in $(seq 1 90); do
    sleep 2
    if grep -q "no revoke without recourse" "$TMPDIR"/client_*.log 2>/dev/null; then
        REFUSED=1; echo "  client refusal observed after ${i}*2s"; break
    fi
    # If the LSP somehow reached COMPLETE, the guard FAILED to fire.
    if grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null; then
        echo "FAIL: advance COMPLETED despite missing poison — guard did not fire"; exit 1
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at ${i}*2s (advance failed, as expected)"; break; }
done

echo
echo "=== Verifying fail-closed abort ==="
grep -hE "no revoke without recourse" "$TMPDIR"/client_*.log | head -2 || true
[ $REFUSED -eq 1 ] || { echo "FAIL: client did NOT log the fail-closed refusal"; echo "--- client_0 tail ---"; tail -25 "$TMPDIR/client_0.log"; exit 1; }

# The aborted advance must NOT have persisted any reveal row (no revocation).
TOTAL_REVEALS=0
for i in $(seq 0 $((N_CLIENTS - 1))); do
    n=$(sqlite3 "$TMPDIR/client_${i}.db" "SELECT count(*) FROM l_stock_poison_reveals;" 2>/dev/null || echo 0)
    TOTAL_REVEALS=$((TOTAL_REVEALS + ${n:-0}))
done
echo "  persisted reveal rows across clients: $TOTAL_REVEALS (expect 0 — advance aborted)"
[ "$TOTAL_REVEALS" = "0" ] || { echo "FAIL: a reveal was persisted despite the abort (revocation leaked)"; exit 1; }

# And the LSP must not have reached the cheat-complete marker.
if grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null; then
    echo "FAIL: LSP reached CHEAT DAEMON COMPLETE — advance was not aborted"; exit 1
fi

echo
echo "=== PASS: degradation-abort proven ==="
echo "  hashlock ON + poison omitted => client REFUSED to advance (no revoke without recourse);"
echo "  no reveal persisted, advance did not complete — fail-closed verified"
exit 0
