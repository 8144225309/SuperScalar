#!/usr/bin/env bash
# test_regtest_rotation_fee_postpone.sh — a factory rotation that meets a fee
# spike is postponed without side effects and without using its retries,
# then completes once the spike is over.
#
# The LSP's fee estimator is an HTTP API served from a local file.  At the
# spike rate the cooperative close of the old factory (signed at rotation
# time, at the current estimate) would cost more than half its funding:
# every rotation attempt is postponed before the key turnover.  The new
# tree's pre-signed rate is the agreed term (--tree-fee-rate), not the
# estimate, so nothing else about the rotation follows the spike.
#
#   1. LSP + N clients build a factory (estimate 1 sat/vB); the estimate then
#      rises to SPIKE sat/vB before the factory reaches DYING.
#   2. Blocks are mined: from DYING on, the rotation is postponed on every
#      block, more often than rot_max_retries (3) failures would allow, with
#      no key turnover (no Phase A) and no distribution-TX fallback.
#   3. The estimate drops back to 1 sat/vB: the next attempt runs the whole
#      rotation (full cooperative close of the old factory, new factory).
#
# Env: REGTEST_CONF (required), N_CLIENTS (default 2), SPIKE (sat/vB,
# default 1000), POSTPONES (postponements to see before the drop, default
# 6), AMOUNT, PORT.
set -uo pipefail

BUILD_DIR="${1:-build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-2}"
SPIKE="${SPIKE:-1000}"
POSTPONES="${POSTPONES:-6}"
AMOUNT="${AMOUNT:-$((N_CLIENTS * 100000))}"
PORT="${PORT:-29983}"
API_PORT=$((PORT + 1))
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
# REGTEST_CONF: the node's bitcoin.conf (RPC credentials; bitcoind is
# started from it).  Required: no default location is guessed.
if [ -z "${REGTEST_CONF:-}" ] || [ ! -f "$REGTEST_CONF" ]; then
    echo "FAIL: REGTEST_CONF must name the regtest node's bitcoin.conf (got '${REGTEST_CONF:-}')" >&2
    exit 2
fi
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
WALLET="ss_rot_postpone_miner"

TMPDIR=$(mktemp -d /tmp/ss-rot-postpone.XXXXXX)
LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; grep -aE "LSP rotate|rotation|distribution TX|DYING|EXPIRED" "$LSP_LOG" 2>/dev/null | tail -30; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
sk(){ printf "00000000000000000000000000000000000000000000000000000000000000%02x" $(( $1 + 2 )); }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('confirmations',0))
except Exception: print(0)"; }
fees(){ echo "{\"fastestFee\":$1,\"halfHourFee\":$1,\"hourFee\":$1,\"economyFee\":1,\"minimumFee\":1}" > "$TMPDIR/www/fees.json"; }
npostponed(){ grep -ac "LSP rotate: rotation of factory 0 postponed, nothing changed" "$LSP_LOG"; }

# The harness checks confirmations of non-wallet txs: (re)start with -txindex.
$BCLI stop >/dev/null 2>&1 && for i in $(seq 1 30); do sleep 1; $BCLI getblockcount >/dev/null 2>&1 || break; done
sleep 1
bitcoind -conf="$REGTEST_CONF" -daemon -txindex=1 >/dev/null
for i in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockcount >/dev/null 2>&1 || fail "bitcoind did not start"
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false >/dev/null 2>&1 || $BCLI loadwallet $WALLET >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 110

mkdir -p "$TMPDIR/www"; fees 1
( cd "$TMPDIR/www" && exec python3 -m http.server $API_PORT --bind 127.0.0.1 ) > "$TMPDIR/http.log" 2>&1 &
PIDS+=($!); sleep 1

echo "=== rotation through a fee spike: clients=$N_CLIENTS amount=$AMOUNT spike=${SPIKE} sat/vB ==="
"$LSP_BIN" --network regtest --port $PORT --daemon --enable-rotation-experimental --clients $N_CLIENTS --arity 2 --amount $AMOUNT \
    --fee-rate 1100 --confirm-timeout 600 --step-blocks 2 --states-per-layer 2 \
    --active-blocks 10 --dying-blocks 80 --cltv-timeout $(( $($BCLI getblockcount) + 1000 )) \
    --fee-estimator "api:http://127.0.0.1:$API_PORT/fees.json" \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$TMPDIR/lsp.db" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || fail "LSP died before listening"; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon --enable-rotation-experimental \
        --seckey "$(sk $i)" --fee-rate 1100 --lsp-pubkey "$LSP_PUB" \
        --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
for i in $(seq 1 200); do sleep 2; grep -q "channels ready" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || fail "LSP died before factory ready"; done
grep -q "channels ready" "$LSP_LOG" || fail "factory never reached 'channels ready'"

echo "--- fee estimate rises to $SPIKE sat/vB (the LSP's cached estimate expires after 60 s) ---"
fees "$SPIKE"
sleep 65
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 3; done ) & MINER_PID=$!

for i in $(seq 1 200); do
    sleep 2
    kill -0 $LSP_PID 2>/dev/null || fail "LSP died"
    [ "$(npostponed)" -ge "$POSTPONES" ] && break
    grep -qa "broadcasting distribution TX" "$LSP_LOG" && fail "distribution-TX fallback during the spike"
done
NP=$(npostponed)
[ "$NP" -ge "$POSTPONES" ] || fail "rotation postponed only $NP time(s)"
grep -aE "LSP rotate: postponing" "$LSP_LOG" | head -1
echo "  rotation postponed $NP times (more than the 3 retries a failure gets)"
grep -qa "LSP rotate: Phase A" "$LSP_LOG" && fail "key turnover (Phase A) ran during the spike"
grep -qa "broadcasting distribution TX" "$LSP_LOG" && fail "distribution-TX fallback during the spike"
grep -qa "retry rotation FAILED\|auto-rotation FAILED" "$LSP_LOG" && fail "a postponement was counted as a failure"

echo "--- fee estimate back to 1 sat/vB ---"
fees 1
OK=0
for i in $(seq 1 150); do
    sleep 2
    kill -0 $LSP_PID 2>/dev/null || fail "LSP died"
    grep -qaE "LSP: (auto-rotation|retry rotation) complete" "$LSP_LOG" && { OK=1; break; }
    grep -qa "broadcasting distribution TX" "$LSP_LOG" && fail "distribution-TX fallback"
done
[ "$OK" = 1 ] || fail "rotation did not complete after the spike"
grep -qa "cannot be carried" "$LSP_LOG" && fail "a channel balance was not carried"
CLOSE=$(grep -aoE "LSP rotate: factory 0 closed: [0-9a-f]{64}" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}")
[ -n "$CLOSE" ] || fail "no cooperative close of the old factory"
[ "$(confs "$CLOSE")" -ge 1 ] || fail "close $CLOSE not confirmed"
NPA=$(grep -ac "LSP rotate: Phase A complete" "$LSP_LOG")
green "PASS: rotation postponed $NP times through a $SPIKE sat/vB spike (no key turnover, no retry used, no fallback); after it, one key turnover ($NPA x Phase A), old factory closed cooperatively ($CLOSE), new factory created"
exit 0
