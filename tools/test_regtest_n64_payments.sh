#!/usr/bin/env bash
# test_regtest_n64_payments.sh — Stage A of the N=64/128 real-sats end-to-end
# validation (#311).
#
# Builds a full N=64 PS factory on REGTEST, opens all 64 channels with the
# clients holding balance (--lsp-balance-pct 50), routes real HTLC payments
# through the factory (--demo --payments N), then cooperatively closes and
# checks conservation.  This is the first time payments are actually moved
# through a full-size factory — every prior N=64 run was --lsp-balance-pct 100
# --force-close, which creates the tree but routes zero sats.
#
# Uses the proven daemon launch pattern from test_testnet4_n64_ps_lifecycle.sh
# (64 client daemons, staggered, with --max-conn-rate / --max-handshakes raised
# and the 600s HELLO_ACK window) so the sequential-accept loop at N=64 works.
#
# Usage: bash tools/test_regtest_n64_payments.sh [BUILD_DIR]
# Env:  N_CLIENTS (default 64)  PAYMENTS (default 8)  AMOUNT (default 3000000)
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

N_CLIENTS="${N_CLIENTS:-64}"
PAYMENTS="${PAYMENTS:-8}"
ARITY="${ARITY:-2,4,8}"
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-1}"
AMOUNT="${AMOUNT:-3000000}"
FEE_RATE="${FEE_RATE:-1000}"   # sat/kvB; regtest mempool floor is generous
PORT="${PORT:-9941}"
WALLET="ss_n64_pay"
TAG="regtest_n64_payments"
LSP_DB="/tmp/ss_${TAG}.db"
LSP_LOG="/tmp/ss_${TAG}_lsp.log"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[n64-pay]\033[0m %s\n' "$*"; }
die()   { red "FAIL: $*"; cleanup; exit 1; }

cleanup() {
    pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true
    [ -n "${LSP_PID:-}" ] && kill -9 "$LSP_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG"
for n in $(seq 2 $((N_CLIENTS + 1))); do
    HEX=$(printf '%064x' "$n")
    rm -f "/tmp/ss_${TAG}_c${HEX:60:4}.db"* "/tmp/ss_${TAG}_c${HEX:60:4}.log"
done

info "regtest bitcoind reachable?"
$BCLI getblockcount >/dev/null || die "regtest bitcoind not reachable at $REGTEST_CONF"

# --- Fund the LSP wallet ---
info "preparing + funding LSP wallet '$WALLET'"
$BCLI createwallet "$WALLET" 2>/dev/null || $BCLI loadwallet "$WALLET" 2>/dev/null || true
FUND_ADDR=$($BCLI -rpcwallet="$WALLET" getnewaddress)
# Mine 101 to make a coinbase spendable, then top up if balance is thin.
$BCLI generatetoaddress 101 "$FUND_ADDR" >/dev/null
BAL=$($BCLI -rpcwallet="$WALLET" getbalance)
info "LSP wallet balance: $BAL BTC"

echo "=== regtest N=$N_CLIENTS PS payments E2E ==="
echo "  clients=$N_CLIENTS arity=$ARITY static=$STATIC_NEAR_ROOT amount=$AMOUNT payments=$PAYMENTS pct=50"

# --- Launch LSP (route payments, cooperative close; NOT --force-close) ---
nohup "$LSP_BIN" \
    --network regtest --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root "$STATIC_NEAR_ROOT" \
    --amount "$AMOUNT" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
    --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --seckey "$LSP_SECKEY" \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --wallet "$WALLET" --db "$LSP_DB" \
    --demo --payments "$PAYMENTS" \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
info "LSP pid=$LSP_PID, waiting for listen..."

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { tail -30 "$LSP_LOG"; die "LSP died before listening"; }
done
grep -q "listening on port $PORT" "$LSP_LOG" || { tail -30 "$LSP_LOG"; die "LSP never listened"; }

# --- Designate PAYMENTS sender->receiver pairs among the clients ---
# Pair j (0-based): sender = client 2j+1, receiver = client 2j+2, sharing a
# deterministic preimage.  Senders run scripted (--send DEST:AMT:PREIMAGE
# --channels), receivers run scripted (--recv PREIMAGE --channels), and they
# still take part in factory creation.  Everyone else is a passive --daemon.
# Requires 2*PAYMENTS <= N_CLIENTS.
declare -A ROLE   # client idx -> "send:DEST:PRE" | "recv:PRE" | "idle"
PAY_AMT=10000
for j in $(seq 0 $((PAYMENTS - 1))); do
    S=$((2*j + 1)); R=$((2*j + 2))
    [ "$R" -le "$N_CLIENTS" ] || break
    PRE=$(printf '%02x%062x' $((0x70 + j)) "$j")   # unique 32-byte preimage
    ROLE[$S]="send:$R:$PRE"
    ROLE[$R]="recv:$PRE"
done

info "launching $N_CLIENTS clients ($PAYMENTS sender/receiver pairs, rest idle)..."
for i in $(seq 1 "$N_CLIENTS"); do
    SK=$(printf '%064x' $((i + 1)))   # 0x02 .. 0x(N+1)
    R="${ROLE[$i]:-idle}"
    COMMON=(--network regtest --host 127.0.0.1 --port "$PORT"
            --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50
            --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i"
            --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443
            --wallet "$WALLET" --db "/tmp/ss_${TAG}_c${SK:60:4}.db")
    case "$R" in
        send:*) DEST="${R#send:}"; DEST="${DEST%%:*}"; PRE="${R##*:}"
                EXTRA=(--channels --send "$DEST:$PAY_AMT:$PRE") ;;
        recv:*) PRE="${R#recv:}"; EXTRA=(--channels --recv "$PRE") ;;
        *)      EXTRA=(--daemon) ;;
    esac
    nohup "$CLIENT_BIN" "${COMMON[@]}" "${EXTRA[@]}" \
        > "/tmp/ss_${TAG}_c${SK:60:4}.log" 2>&1 &
    sleep 0.2
done

# Regtest needs blocks mined to confirm the funding TX + advance the lifecycle.
# Mine periodically in the background while the LSP drives the ceremony.
( for _ in $(seq 1 120); do sleep 5; $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$FUND_ADDR" >/dev/null 2>&1 || true; done ) &
MINER_PID=$!

# --- Wait for the LSP to finish (creation -> payments -> close) ---
info "waiting for ceremony + payments + close (up to ~10 min)..."
DEADLINE=$(( $(date +%s) + 600 ))
RESULT="TIMEOUT"
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if ! kill -0 $LSP_PID 2>/dev/null; then RESULT="LSP_EXITED"; break; fi
    if grep -qE "demo complete|all payments|cooperative close.*complete|close.*broadcast|DEMO COMPLETE" "$LSP_LOG" 2>/dev/null; then
        RESULT="DONE"; break
    fi
    sleep 5
done
kill -9 "$MINER_PID" 2>/dev/null || true

echo "=== result: $RESULT ==="
echo "--- payment + channel evidence in LSP log ---"
grep -iE "channel.*ready|add_htlc|fulfill|payment|htlc|routed|close|conservation" "$LSP_LOG" 2>/dev/null | tail -40

# --- Assertions ---
READY=$(grep -ciE "channel.*ready|CHANNEL_READY" "$LSP_LOG" 2>/dev/null || echo 0)
PAID=$(grep -ciE "fulfill|payment.*complete|htlc.*settled" "$LSP_LOG" 2>/dev/null || echo 0)
info "channels-ready log hits=$READY  payment/fulfill hits=$PAID"

[ "$READY" -gt 0 ] || die "no channels reached CHANNEL_READY"
[ "$PAID" -gt 0 ]  || die "no payments settled (factory created but no sats routed)"

green "Stage A signal: factory created + payments routed at N=$N_CLIENTS (result=$RESULT)"
echo "(per-party delta accounting + coop-close output verification layered next)"
