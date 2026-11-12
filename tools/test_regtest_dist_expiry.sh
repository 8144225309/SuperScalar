#!/usr/bin/env bash
# test_regtest_dist_expiry.sh — the LSP's distribution TX at factory expiry is
# retried and re-bumped until it confirms.
#
# The node runs with a raised minimum relay feerate (MINRELAY sat/kvB) and a
# block minimum feerate (BLOCKMIN) above it, so a package at the relay floor
# sits in the mempool without being mined.  The tree (and the distribution
# TX) is signed at the default 0.1 sat/vB agreed rate.  The LSP's fee estimator is an HTTP
# API served from a local file, so the test can raise its rate mid-run.
#
#   1. LSP + N clients build a factory with a short lifetime; the clients
#      then go away (no rotation can happen).  The LSP runs with
#      --no-force-exit: it lets the distribution TX pay the members instead of
#      pushing them on chain before the end date.
#   2. The factory expires before its CLTV: the LSP holds the distribution
#      TX until its nLockTime.  The LSP is killed and restarted from its DB:
#      it still knows the factory expired and has the distribution TX, and
#      sends it at its nLockTime through the CPFP path, in as a package at
#      the relay floor, below BLOCKMIN: it is not mined.
#   3. The LSP is killed and restarted again, with the TX in the mempool.  The
#      API rate rises to RAISED sat/vB: on a following block the restarted
#      LSP re-bumps the package in the mempool and it confirms.
# Needs a node with -txindex (the drill restarts the node itself).
#
# Env: REGTEST_CONF (required), N_CLIENTS (default 2), MINRELAY (default 5000), BLOCKMIN (default
# 20000), RAISED (sat/vB, default 30), AMOUNT, PORT.
set -uo pipefail

BUILD_DIR="${1:-build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-2}"
MINRELAY="${MINRELAY:-5000}"
BLOCKMIN="${BLOCKMIN:-20000}"
RAISED="${RAISED:-30}"
AMOUNT="${AMOUNT:-$((N_CLIENTS * 100000))}"
PORT="${PORT:-29977}"
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
WALLET="ss_dist_expiry_miner"

TMPDIR=$(mktemp -d /tmp/ss-dist-expiry.XXXXXX)
LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; tail -30 "$LSP_LOG" 2>/dev/null; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
sk(){ printf "00000000000000000000000000000000000000000000000000000000000000%02x" $(( $1 + 2 )); }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('confirmations',0))
except Exception: print(0)"; }
fees(){ echo "{\"fastestFee\":$1,\"halfHourFee\":1,\"hourFee\":1,\"economyFee\":1,\"minimumFee\":1}" > "$TMPDIR/www/fees.json"; }

echo "--- (re)starting bitcoind -txindex -minrelaytxfee=$MINRELAY -blockmintxfee=$BLOCKMIN sat/kvB ---"
$BCLI stop >/dev/null 2>&1 && for i in $(seq 1 30); do sleep 1; $BCLI getblockcount >/dev/null 2>&1 || break; done
sleep 1
MR=$(python3 -c "print('%.8f' % ($MINRELAY / 1e8))"); BM=$(python3 -c "print('%.8f' % ($BLOCKMIN / 1e8))")
bitcoind -conf="$REGTEST_CONF" -daemon -txindex=1 -minrelaytxfee=$MR -blockmintxfee=$BM >/dev/null
for i in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockcount >/dev/null 2>&1 || fail "bitcoind did not start"
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false >/dev/null 2>&1 || $BCLI loadwallet $WALLET >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 110

mkdir -p "$TMPDIR/www"; fees 1
( cd "$TMPDIR/www" && exec python3 -m http.server $API_PORT --bind 127.0.0.1 ) > "$TMPDIR/http.log" 2>&1 &
PIDS+=($!); sleep 1

FUNDING_RATE=$((BLOCKMIN + 5000))
LSP_ARGS=(--network regtest --port $PORT --daemon --clients $N_CLIENTS --arity 2 --amount $AMOUNT
    --fee-rate $FUNDING_RATE --confirm-timeout 600 --step-blocks 2 --states-per-layer 2
    --active-blocks 20 --dying-blocks 10 --tree-fee-rate 100 --no-force-exit
    --fee-estimator "api:http://127.0.0.1:$API_PORT/fees.json"
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT"
    --wallet "$WALLET" --db "$TMPDIR/lsp.db")
NLSP=0
start_lsp(){
    NLSP=$((NLSP + 1))
    LSP_LOG="$TMPDIR/lsp$NLSP.log"
    "$LSP_BIN" "${LSP_ARGS[@]}" > "$LSP_LOG" 2>&1 &
    LSP_PID=$!; PIDS+=($LSP_PID)
}
# kill -9 the LSP and start it again from its DB (recovery)
restart_lsp(){
    kill -9 $LSP_PID 2>/dev/null; wait $LSP_PID 2>/dev/null
    start_lsp
    for i in $(seq 1 60); do
        sleep 1
        grep -qa "LSP recovery: entering daemon mode" "$LSP_LOG" 2>/dev/null && break
        kill -0 $LSP_PID 2>/dev/null || fail "restarted LSP died"
    done
    grep -qa "found existing factory in DB, entering recovery mode" "$LSP_LOG" || fail "restarted LSP did not recover from its DB"
    grep -aE "LSP recovery: (factory created at|distribution TX|the stored)" "$LSP_LOG" | head -2
    # the restarted LSP knows the factory has expired (no new lifetime): it
    # handles the expiry within its first blocks
    local hr=$($BCLI getblockcount)
    for i in $(seq 1 60); do
        grep -qaE "ladder factory [0-9]+ -> EXPIRED" "$LSP_LOG" && break
        [ $(( $($BCLI getblockcount) - hr )) -ge 10 ] && break
        sleep 1
    done
    grep -qaE "ladder factory [0-9]+ -> EXPIRED" "$LSP_LOG" || \
        fail "the restarted LSP did not see the factory expired ($(( $($BCLI getblockcount) - hr )) blocks after the restart)"
}

echo "=== distribution TX at expiry: clients=$N_CLIENTS minrelay=$MINRELAY blockmin=$BLOCKMIN raised=${RAISED} sat/vB, LSP restarted twice ==="
start_lsp
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || fail "LSP died before listening"; done
CPIDS=()
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon \
        --seckey "$(sk $i)" --fee-rate $FUNDING_RATE --lsp-pubkey "$LSP_PUB" \
        --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    CPIDS+=($!); PIDS+=($!); sleep 0.4
done
for i in $(seq 1 200); do sleep 2; grep -q "channels ready" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || fail "LSP died before factory ready"; done
grep -q "channels ready" "$LSP_LOG" || fail "factory never reached 'channels ready'"
grep -aE "tree fee rate|CLTV timeout" "$LSP_LOG" | head -2
CLTV=$(grep -aoE "CLTV timeout: block [0-9]+" "$LSP_LOG" | head -1 | grep -oE "[0-9]+$")
echo "--- clients go away; blocks every 2s until the factory expires ---"
for p in "${CPIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
touch "$TMPDIR/mining"
( while [ -f "$TMPDIR/mining" ]; do mine 1; sleep 2; done ) & MINER_PID=$!

# 1. expired, before the distribution TX's nLockTime: nothing is sent yet;
#    the LSP restarts
for i in $(seq 1 150); do
    sleep 1
    kill -0 $LSP_PID 2>/dev/null || fail "LSP died"
    grep -qa "EXPIRED" "$LSP_LOG" && break
done
grep -qa "EXPIRED" "$LSP_LOG" || fail "the factory never expired"
H=$($BCLI getblockcount)
NLOCK=$(grep -aoE "broadcast at its nLockTime \(block [0-9]+\)" "$LSP_LOG" | head -1 | grep -oE "[0-9]+")
grep -qaE "distribution TX [0-9a-f]{64} of factory [0-9]+ (not accepted|broadcast)" "$LSP_LOG" && \
    [ -n "$NLOCK" ] && [ "$H" -lt "$NLOCK" ] && fail "distribution TX sent before its nLockTime"
echo "  factory expired at height $H, distribution TX held until its nLockTime (${NLOCK:-?}, CLTV $CLTV): restarting the LSP"
restart_lsp

# 2. the restarted LSP sends it again until it is final; in as a package
DTX=""
for i in $(seq 1 150); do
    sleep 2
    kill -0 $LSP_PID 2>/dev/null || fail "LSP died"
    DTX=$(grep -aoE "distribution TX [0-9a-f]{64} of factory [0-9]+ broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}")
    [ -n "$DTX" ] && break
done
[ -n "$DTX" ] || fail "the restarted LSP never got its distribution TX into the mempool"
H=$($BCLI getblockcount)
echo "  distribution TX $DTX in the mempool at height $H (CLTV $CLTV), sent by the restarted LSP"
DH=$(grep -aoE "nLockTime: distribution TX $DTX" "$LSP_LOG" | head -1)
[ -n "$DH" ] || fail "the restarted LSP did not send it at its nLockTime"
grep -aE "CPFP: $DTX" "$LSP_LOG" | head -2
grep -qa "CPFP: $DTX .*sent as a package" "$LSP_LOG" || fail "distribution TX did not go in as a CPFP package under the raised relay floor"

# below the block minimum: blocks pass and it stays unconfirmed
H0=$($BCLI getblockcount)
for i in $(seq 1 60); do sleep 1; [ $(( $($BCLI getblockcount) - H0 )) -ge 3 ] && break; done
[ "$(confs "$DTX")" -ge 1 ] && fail "distribution TX confirmed below the block minimum feerate (setup)"
echo "  $(( $($BCLI getblockcount) - H0 )) blocks later still unconfirmed (package below the block minimum): restarting the LSP"

# 3. restarted while it sits in the mempool: the new LSP keeps it on its
#    retry list and re-bumps it when the estimate rises
restart_lsp
echo "--- fee estimate rises to $RAISED sat/vB ---"
fees "$RAISED"
OK=0
for i in $(seq 1 120); do
    sleep 2
    [ "$(confs "$DTX")" -ge 1 ] && { OK=1; break; }
done
grep -aE "CPFP: $DTX was in the mempool|distribution TX $DTX .*re-bumped|distribution TX $DTX .*confirmed" "$LSP_LOG" | head -4
[ "$OK" = 1 ] || fail "distribution TX not confirmed after the fee estimate rose"
grep -qa "distribution TX $DTX of factory [0-9]* re-bumped in the mempool" "$LSP_LOG" || fail "confirmed without a re-bump by the restarted LSP"
for i in $(seq 1 30); do grep -qa "distribution TX $DTX of factory [0-9]* confirmed" "$LSP_LOG" && break; sleep 2; done
grep -qa "distribution TX $DTX of factory [0-9]* confirmed" "$LSP_LOG" || fail "LSP did not see the confirmation"
rm -f "$TMPDIR/mining"
green "PASS: distribution TX at expiry: held until its nLockTime across an LSP restart, sent then by the restarted LSP, in as a package at the relay floor, re-bumped by the LSP restarted again when the estimate rose to $RAISED sat/vB, confirmed at height $($BCLI getblockcount)"
exit 0
