#!/usr/bin/env bash
# test_regtest_n127_rotation.sh — async factory rotation at the design max.
#
# Proves the LAST unproven subsystem at N=127 (LSP + 127 clients = the full
# 128-signer group): --async-rotation readiness gating and the production
# rotation itself.  Creation/payments/cooperative-close at 127 are covered by
# test_regtest_n64_payments.sh; the crash-drill matrix covers rotation on the
# LEGACY SYNCHRONOUS path (no --async-rotation) at small N.  This drill covers
# the readiness-gated ASYNC path at scale, which is exactly where the old
# uint64_t readiness bitmaps were undefined for client_idx >= 64 (x86 wrap
# aliased bit i to i mod 64, so "64 of 127 ready" looked like "all ready" and
# rotation could fire prematurely).
#
# Async semantics under test: at DYING the LSP counts ONLINE clients as ready
# (they cooperate over their live connections) and queues requests for the
# offline, who ack with QUEUE_DONE when they reconnect; the ceremony fires
# ONLY via the readiness gate ("firing async rotation ceremony").  With all
# 127 clients online the fast path fires at the DYING transition itself.
#
# PASS requires:
#   1. factory DYING triggers auto-rotation queueing ("starting auto-rotation")
#   2. the readiness gate fires: "all 127 clients ready — firing async
#      rotation ceremony" present in the LSP log
#   3. the ceremony (Phase A) starts only AFTER the gate line
#   4. NO gate bypass: no legacy "retrying rotation for factory" direct fire
#   5. NO partial rotation (that is the EXPIRED fallback, not a clean pass)
#   6. rotation reaches Phase C (new factory creation) with no phase failures
#   7. every client logs "factory rotation complete" (127/127)
#
# Usage: bash tools/test_regtest_n127_rotation.sh [BUILD_DIR]
# Env:   N_CLIENTS (default 127)  ACTIVE_BLOCKS (default 25)
set -uo pipefail

BUILD_DIR="${1:-/root/ss-p6-main/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

N_CLIENTS="${N_CLIENTS:-127}"
ARITY="${ARITY:-2,4,8}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
FEE_RATE="${FEE_RATE:-1000}"
ACTIVE_BLOCKS="${ACTIVE_BLOCKS:-25}"
DYING_BLOCKS="${DYING_BLOCKS:-400}"
PORT="${PORT:-9947}"
WALLET="ss_n64_pay"
TAG="regtest_n127_rotation"
LSP_DB="/tmp/ss_${TAG}.db"
LSP_LOG="/tmp/ss_${TAG}_lsp.log"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[n127-rot]\033[0m %s\n' "$*"; }
die()   { red "FAIL: $*"; cleanup; exit 1; }

MINER_PID=""
cleanup() {
    [ -n "$MINER_PID" ] && kill "$MINER_PID" 2>/dev/null
    pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true
    [ -n "${LSP_PID:-}" ] && kill -9 "$LSP_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG"
rm -f /tmp/ss_${TAG}_c*.log /tmp/ss_${TAG}_c*.db /tmp/ss_${TAG}_c*.db-shm /tmp/ss_${TAG}_c*.db-wal

info "regtest bitcoind reachable?"
$BCLI getblockcount >/dev/null || die "regtest bitcoind not reachable at $REGTEST_CONF"

info "preparing + funding LSP wallet '$WALLET'"
$BCLI createwallet "$WALLET" 2>/dev/null || $BCLI loadwallet "$WALLET" 2>/dev/null || true
FUND_ADDR=$($BCLI -rpcwallet="$WALLET" getnewaddress)
$BCLI generatetoaddress 101 "$FUND_ADDR" >/dev/null
BAL=$($BCLI -rpcwallet="$WALLET" getbalance)
info "LSP wallet balance: $BAL BTC"

echo "=== regtest N=$N_CLIENTS ASYNC ROTATION drill ==="
echo "  clients=$N_CLIENTS arity=$ARITY amount=$AMOUNT active=$ACTIVE_BLOCKS dying=$DYING_BLOCKS"

nohup "$LSP_BIN" \
    --network regtest --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root 1 \
    --amount "$AMOUNT" \
    --active-blocks "$ACTIVE_BLOCKS" --dying-blocks "$DYING_BLOCKS" \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
    --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --seckey "$LSP_SECKEY" \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --wallet "$WALLET" --db "$LSP_DB" \
    --daemon --async-rotation \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
info "LSP pid=$LSP_PID (daemon + --async-rotation), waiting for listen..."

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { tail -30 "$LSP_LOG"; die "LSP died before listening"; }
done
grep -q "listening on port $PORT" "$LSP_LOG" || { tail -30 "$LSP_LOG"; die "LSP never listened"; }

info "launching $N_CLIENTS daemon clients..."
for i in $(seq 1 "$N_CLIENTS"); do
    SK=$(printf '%064x' $((i + 1)))
    nohup "$CLIENT_BIN" \
        --network regtest --host 127.0.0.1 --port "$PORT" \
        --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i" \
        --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
        --wallet "$WALLET" --db "/tmp/ss_${TAG}_c${SK:60:4}.db" \
        --daemon \
        > "/tmp/ss_${TAG}_c${SK:60:4}.log" 2>&1 &
    sleep 0.2
done

# Miner: advance the chain so the factory confirms, ages through ACTIVE and
# enters DYING, then keep mining so rotation's own funding TX confirms too.
( while true; do
    $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$FUND_ADDR" >/dev/null 2>&1 || true
    sleep 2
  done ) &
MINER_PID=$!

info "waiting for factory creation, DYING transition, 127/127 acks, rotation (up to 45 min)..."
DEADLINE=$(( $(date +%s) + 2700 ))
STAGE=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    sleep 15
    kill -0 $LSP_PID 2>/dev/null || break
    if [ $STAGE -lt 1 ] && grep -q "starting auto-rotation" "$LSP_LOG"; then
        info "stage 1: auto-rotation queued"; STAGE=1
    fi
    if [ $STAGE -lt 2 ] && grep -q "firing async rotation ceremony" "$LSP_LOG"; then
        info "stage 2: readiness gate fired"; STAGE=2
    fi
    DONE_COUNT=$(grep -l "factory rotation complete" /tmp/ss_${TAG}_c*.log 2>/dev/null | wc -l)
    if [ "$DONE_COUNT" -ge "$N_CLIENTS" ]; then
        info "stage 3: all $DONE_COUNT clients report rotation complete"; break
    fi
done

echo "=== assertions ==="
PASS=1
if grep -q "starting auto-rotation" "$LSP_LOG"; then
    green "  ok: DYING triggered auto-rotation"
else PASS=0; red "  FAIL: auto-rotation never started"; fi

if grep -q "all $N_CLIENTS clients ready — firing async rotation ceremony" "$LSP_LOG"; then
    green "  ok: readiness gate fired at $N_CLIENTS/$N_CLIENTS"
else PASS=0; red "  FAIL: readiness gate never fired"
     grep -o "async gate [0-9]*/$N_CLIENTS ready" "$LSP_LOG" | tail -1; fi

if grep -q "partial rotation" "$LSP_LOG"; then
    PASS=0; red "  FAIL: partial rotation fired (EXPIRED fallback, not a clean pass)"
else green "  ok: no partial-rotation fallback"; fi

if grep -q "retrying rotation for factory" "$LSP_LOG"; then
    PASS=0; red "  FAIL: legacy direct-fire retry ran (gate bypass still present)"
else green "  ok: no gate-bypassing direct retry"; fi

FIRE_LINE=$(grep -n "firing async rotation ceremony" "$LSP_LOG" | head -1 | cut -d: -f1)
PHASEA_LINE=$(grep -n "Phase A — PTLC key turnover" "$LSP_LOG" | head -1 | cut -d: -f1)
if [ -n "$FIRE_LINE" ] && [ -n "$PHASEA_LINE" ] && [ "$PHASEA_LINE" -gt "$FIRE_LINE" ]; then
    green "  ok: ceremony started only AFTER the gate (line $PHASEA_LINE > $FIRE_LINE)"
elif [ -z "$PHASEA_LINE" ]; then
    PASS=0; red "  FAIL: rotation ceremony never started"
else
    PASS=0; red "  FAIL: ceremony BEFORE gate (Phase A line $PHASEA_LINE, gate line ${FIRE_LINE:-none})"
fi

if grep -q "Phase C — creating new factory" "$LSP_LOG"; then
    green "  ok: rotation reached Phase C (new factory creation)"
else PASS=0; red "  FAIL: Phase C never reached"; fi

if grep -aE "rotate:.*failed" "$LSP_LOG" | grep -qva "clients cooperated"; then
    PASS=0; red "  FAIL: rotation phase failure in LSP log:"
    grep -aE "rotate:.*failed" "$LSP_LOG" | grep -va "clients cooperated" | head -3
else green "  ok: no rotation phase failures"; fi

DONE_COUNT=$(grep -l "factory rotation complete" /tmp/ss_${TAG}_c*.log 2>/dev/null | wc -l)
if [ "$DONE_COUNT" -eq "$N_CLIENTS" ]; then
    green "  ok: all $N_CLIENTS clients completed rotation"
else PASS=0; red "  FAIL: only $DONE_COUNT/$N_CLIENTS clients completed rotation"; fi

# Post-rotation accounting (#76): Phase D re-inits each channel's balance from
# the old factory.  funding_amount is the GROSS on-chain amount, so it must
# carry local+remote PLUS the base commit fee; setting it to the usable total
# made the conservation checker see a base_commit_fee deficit on every channel
# and freeze all new HTLCs.  Give the daemon loop a few poll ticks to run the
# checker post-rotation, then assert it stayed quiet.
sleep 20
if grep -qE "CONSERVATION VIOLATION|refusing new HTLCs" "$LSP_LOG"; then
    PASS=0; red "  FAIL: conservation alert AFTER rotation (post-rotation accounting freeze)"
    grep -aE "CONSERVATION VIOLATION|refusing new HTLCs" "$LSP_LOG" | head -2
else green "  ok: no post-rotation conservation alert (new HTLCs not frozen)"; fi

if [ "$PASS" -eq 1 ]; then
    green "PASS: N=$N_CLIENTS async rotation — queued on DYING, gated on $N_CLIENTS/$N_CLIENTS readiness, fired once, new factory created, all clients rotated."
    exit 0
else
    red "FAIL: see assertions above; LSP log tail:"
    tail -25 "$LSP_LOG"
    exit 1
fi
