#!/usr/bin/env bash
# test_regtest_close_refusal_exit.sh — a client daemon that refuses a
# cooperative close must not report a clean exit.
#
#   1. LSP + 2 client daemons create an arity-2 factory and run the demo
#      payments.
#   2. The LSP proposes the cooperative close with nLockTime set to its chain
#      height.  Client 1 was started with an unreachable RPC port, so it has
#      no chain tip to judge that nLockTime by and refuses the close.
#   3. PASS when client 1 exits non-zero, its log says the close was refused
#      and points at --force-close, no close was signed by it, and the factory
#      funding output is still unspent.
#
# Usage: bash tools/test_regtest_close_refusal_exit.sh [BUILD_DIR]
# Wall time: typically <90s.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${1:-$SCRIPT_DIR/../build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS=2
FUNDING_SATS=200000
LSP_PORT="${LSP_PORT:-29961}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
WALLET="ss_close_refusal_miner"

REGTEST_CONF="${REGTEST_CONF:-$HOME/.bitcoin/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-close-refusal.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

LSP_PID=""
CLIENT_PIDS=()
MINER_PID=""

cleanup() {
    for p in "$LSP_PID" "$MINER_PID" "${CLIENT_PIDS[@]:-}"; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
    done
    if [ "${KEEP_LOGS:-0}" = "1" ]; then
        echo "logs kept in $TMPDIR"
    else
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    echo "--- LSP log (tail) ---";      tail -15 "$LSP_LOG" 2>/dev/null
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        echo "--- client $i log (tail) ---"; tail -8 "$TMPDIR/client_${i}.log" 2>/dev/null
    done
    exit 1
}

[ -x "$LSP_BIN" ]    || { echo "FAIL: $LSP_BIN not built"; exit 2; }
[ -x "$CLIENT_BIN" ] || { echo "FAIL: $CLIENT_BIN not built"; exit 2; }
$BCLI getblockchaininfo >/dev/null 2>&1 || {
    echo "FAIL: bitcoind regtest not reachable via $REGTEST_CONF"; exit 2; }

$BCLI -named createwallet wallet_name="$WALLET" load_on_startup=false >/dev/null 2>&1 || true
$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m)
$BCLI -rpcwallet="$WALLET" generatetoaddress 101 "$MINE_ADDR" >/dev/null 2>&1 || true

echo "=== Refused cooperative close: client exit status ==="
echo "  build : $BUILD_DIR"
echo "  tip   : $($BCLI getblockcount)"

"$LSP_BIN" \
    --network regtest --port "$LSP_PORT" --clients "$N_CLIENTS" --arity 2 \
    --amount "$FUNDING_SATS" --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "${RPCUSER:-rpcuser}" --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wallet "$WALLET" --db "$LSP_DB" \
    --demo --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 "$LSP_PID" 2>/dev/null || fail "LSP died before listening"
done

# Client 0: chain access through RPC.  Client 1: RPC port nobody listens on,
# so it cannot learn a chain tip.
"$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LSP_PORT" \
    --seckey "${CLIENT_SECKEYS[0]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
    --participant-id 1 --daemon \
    --rpcuser "${RPCUSER:-rpcuser}" --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wallet "$WALLET" --db "$TMPDIR/client_0.db" \
    > "$TMPDIR/client_0.log" 2>&1 &
CLIENT_PIDS+=($!)
sleep 0.3
"$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LSP_PORT" \
    --seckey "${CLIENT_SECKEYS[1]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
    --participant-id 2 --daemon \
    --rpcport 1 \
    --db "$TMPDIR/client_1.db" \
    > "$TMPDIR/client_1.log" 2>&1 &
CLIENT_PIDS+=($!)

(
    while kill -0 "$LSP_PID" 2>/dev/null; do
        $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
MINER_PID=$!

# Client 1 must leave on its own, with a non-zero status.
C1_RC=""
for i in $(seq 1 150); do
    sleep 2
    if ! kill -0 "${CLIENT_PIDS[1]}" 2>/dev/null; then
        wait "${CLIENT_PIDS[1]}"; C1_RC=$?
        break
    fi
    kill -0 "$LSP_PID" 2>/dev/null || { sleep 3; }
done
[ -n "$C1_RC" ] || fail "client 1 was still running after 300s"
echo "  client 1 exit status : $C1_RC  (want non-zero)"

C1_LOG="$TMPDIR/client_1.log"
grep -q "received CLOSE_PROPOSE" "$C1_LOG" \
    || fail "client 1 never received a close proposal"
grep -q "REFUSING cooperative close" "$C1_LOG" \
    || fail "client 1 did not refuse the close"
grep -q "COOPERATIVE CLOSE REFUSED" "$C1_LOG" \
    || fail "client 1 log lacks the refusal summary"
grep -q -- "--force-close" "$C1_LOG" \
    || fail "client 1 log does not point at --force-close"
[ "$C1_RC" -ne 0 ] || fail "client 1 exited 0 after refusing the close"

SIGNED=$(sqlite3 "$TMPDIR/client_1.db" "SELECT count(*) FROM client_close_signed;" 2>/dev/null || echo "?")
echo "  client 1 signed closes : $SIGNED  (want 0)"
[ "$SIGNED" = "0" ] || fail "client 1 recorded a signed close"

# The factory was not closed.
FUND_TXID=$(grep -oE "funded [0-9]+ sats, txid: [0-9a-f]{64}" "$LSP_LOG" | grep -oE "[0-9a-f]{64}" | head -1)
FUND_VOUT=$(grep -oE "funding vout=[0-9]+" "$LSP_LOG" | grep -oE "[0-9]+" | head -1)
[ -n "$FUND_TXID" ] && [ -n "$FUND_VOUT" ] || fail "could not find the funding outpoint in the LSP log"
UTXO=$($BCLI gettxout "$FUND_TXID" "$FUND_VOUT" 2>/dev/null)
[ -n "$UTXO" ] || fail "factory funding output $FUND_TXID:$FUND_VOUT is spent"
echo "  funding output         : unspent"

echo
echo "=== PASS: refused close reported with exit status $C1_RC ==="
exit 0
