#!/usr/bin/env bash
# test_regtest_close_not_completed.sh — what client daemons do, and how they
# exit, when a cooperative close does not complete.
#
# An LSP and 2 client daemons run through factory creation and the demo
# payments; the LSP then proposes the cooperative close with nLockTime set to
# its chain height.
#
#   Client 1 was started with an RPC port nobody listens on, so it has no
#   chain tip.  It cannot verify the nLockTime.  That is not a refusal: it
#   must answer "try again", sign and record nothing, and keep running with
#   its channel intact.
#
#   Client 0 is honest and has chain access.  It sees the ceremony fail
#   before it signed anything.  It must exit non-zero and say that its
#   channel is still usable.
#
# The factory funding output must stay unspent.
#
# Usage: bash tools/test_regtest_close_not_completed.sh [BUILD_DIR]
# Env:   KEEP_LOGS=1 keeps the logs
# Wall time: typically <90s.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${1:-$SCRIPT_DIR/../build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

FUNDING_SATS=200000
LSP_PORT="${LSP_PORT:-29961}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
WALLET="ss_close_exit_miner"

REGTEST_CONF="${REGTEST_CONF:-$HOME/.bitcoin/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

D=$(mktemp -d /tmp/ss-close-exit.XXXXXX)
LSP_PID=""; MINER_PID=""; C0_PID=""; C1_PID=""

cleanup() {
    for p in "$LSP_PID" "$MINER_PID" "$C0_PID" "$C1_PID"; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null
    done
    if [ "${KEEP_LOGS:-0}" = "1" ]; then echo "logs kept in $D"; else rm -rf "$D"; fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    echo "--- LSP log (tail) ---";      tail -12 "$D/lsp.log" 2>/dev/null
    echo "--- client 0 log (tail) ---"; tail -8 "$D/client_0.log" 2>/dev/null
    echo "--- client 1 log (tail) ---"; tail -8 "$D/client_1.log" 2>/dev/null
    exit 1
}

# wait_exit PID SECONDS -> WAIT_RC is the exit status, or empty if still running
WAIT_RC=""
wait_exit() {
    local pid=$1 n=$2
    WAIT_RC=""
    for _ in $(seq 1 "$n"); do
        if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; WAIT_RC=$?; return; fi
        sleep 1
    done
}

[ -x "$LSP_BIN" ]    || { echo "FAIL: $LSP_BIN not built"; exit 2; }
[ -x "$CLIENT_BIN" ] || { echo "FAIL: $CLIENT_BIN not built"; exit 2; }
$BCLI getblockchaininfo >/dev/null 2>&1 || {
    echo "FAIL: bitcoind regtest not reachable via $REGTEST_CONF"; exit 2; }

$BCLI -named createwallet wallet_name="$WALLET" load_on_startup=false >/dev/null 2>&1 || true
$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m)
$BCLI -rpcwallet="$WALLET" generatetoaddress 101 "$MINE_ADDR" >/dev/null 2>&1 || true

echo "=== Cooperative close that does not complete: client behaviour ==="
echo "  build : $BUILD_DIR"
echo "  tip   : $($BCLI getblockcount)"

"$LSP_BIN" \
    --network regtest --port "$LSP_PORT" --clients 2 --arity 2 \
    --amount "$FUNDING_SATS" --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "${RPCUSER:-rpcuser}" --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wallet "$WALLET" --db "$D/lsp.db" \
    --demo --lsp-balance-pct 50 \
    > "$D/lsp.log" 2>&1 &
LSP_PID=$!
for _ in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$D/lsp.log" 2>/dev/null && break
    kill -0 "$LSP_PID" 2>/dev/null || fail "LSP died before listening"
done

"$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LSP_PORT" \
    --seckey "${CLIENT_SECKEYS[0]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
    --participant-id 1 --daemon \
    --rpcuser "${RPCUSER:-rpcuser}" --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wallet "$WALLET" --db "$D/client_0.db" \
    > "$D/client_0.log" 2>&1 &
C0_PID=$!
sleep 0.3
"$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LSP_PORT" \
    --seckey "${CLIENT_SECKEYS[1]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
    --participant-id 2 --daemon \
    --rpcport 1 \
    --db "$D/client_1.db" \
    > "$D/client_1.log" 2>&1 &
C1_PID=$!

(
    while kill -0 "$LSP_PID" 2>/dev/null; do
        $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
MINER_PID=$!

# The LSP gives up on the close and exits.
wait_exit "$LSP_PID" 300
[ -n "$WAIT_RC" ] || fail "LSP still running after 300s"
LSP_PID=""
grep -q "received CLOSE_PROPOSE" "$D/client_1.log" \
    || fail "client 1 never received a close proposal"
grep -q "cooperative close confirmed" "$D/lsp.log" && fail "the close completed"

# Client 0: the ceremony failed before it signed.  Not a clean exit, and the
# message must say the channel is still usable.
wait_exit "$C0_PID" 30
C0_RC=$WAIT_RC
[ -n "$C0_RC" ] || fail "client 0 still running 30s after the LSP left"
C0_PID=""
echo "  client 0 exit status   : $C0_RC  (want non-zero)"
[ "$C0_RC" -ne 0 ] || fail "client 0 exited 0 although the close did not complete"
grep -q "COOPERATIVE CLOSE NOT COMPLETED" "$D/client_0.log" \
    || fail "client 0 log lacks the not-completed summary"
grep -q "still usable" "$D/client_0.log" \
    || fail "client 0 log does not say the channel is still usable"

# Client 1: could not verify, so no refusal, no record, and it keeps running.
grep -q "cannot be verified" "$D/client_1.log" \
    || fail "client 1 did not report that it cannot verify the nLockTime"
grep -q "REFUSING cooperative close\|COOPERATIVE CLOSE REFUSED" "$D/client_1.log" \
    && fail "client 1 treated a missing chain tip as a refusal"
grep -q "still usable; staying connected" "$D/client_1.log" \
    || fail "client 1 log does not say it keeps serving the channel"
sleep 3
kill -0 "$C1_PID" 2>/dev/null \
    || fail "client 1 exited although it only could not verify the proposal"
echo "  client 1               : still running (want running)"
SIGNED=$(sqlite3 "$D/client_1.db" "SELECT count(*) FROM client_close_signed;" 2>/dev/null || echo "?")
echo "  client 1 signed closes : $SIGNED  (want 0)"
[ "$SIGNED" = "0" ] || fail "client 1 recorded a signed close"

# The factory was not closed.
FUND_TXID=$(grep -oE "funded [0-9]+ sats, txid: [0-9a-f]{64}" "$D/lsp.log" | grep -oE "[0-9a-f]{64}" | head -1)
FUND_VOUT=$(grep -oE "funding vout=[0-9]+" "$D/lsp.log" | grep -oE "[0-9]+" | head -1)
[ -n "$FUND_TXID" ] && [ -n "$FUND_VOUT" ] || fail "could not find the funding outpoint in the LSP log"
[ -n "$($BCLI gettxout "$FUND_TXID" "$FUND_VOUT" 2>/dev/null)" ] \
    || fail "factory funding output $FUND_TXID:$FUND_VOUT is spent"
echo "  funding output         : unspent"

echo
echo "=== PASS ==="
exit 0
