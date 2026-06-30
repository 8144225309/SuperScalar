#!/usr/bin/env bash
# test_regtest_fc_cost_replay.sh -- #329: validate the force-close cost CALCULATOR
# (dashboard query #72 / chainCostCell: treeTxCount * fee_per_tx) against a REAL
# on-chain force-close.
#
# Method: drive --force-close (the LSP broadcasts the full factory tree in
# parent->child order; broadcast_factory_tree logs each node to broadcast_log with
# source='tree_node_<i>' + raw_hex). Then for EVERY broadcast tree TX compute the
# ACTUAL on-chain fee (sum(input prevout values) - sum(output values)) and assert
# the summed actual fees match the calculator's projection (treeTxCount *
# fee_per_tx) within TOL_PCT.
#
# Scope: this validates the TREE chain-broadcast cost -- exactly the dashboard's
# "Chain-broadcast cost" column, which by documented design EXCLUDES channel
# commitments, HTLC/PTLC sweeps, penalty TXs, CPFP children, and factory-burn.
#
# Usage: bash tools/test_regtest_fc_cost_replay.sh [BUILD_DIR]
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-4}"; AMOUNT="${AMOUNT:-200000}"; PORT="${PORT:-29977}"
FEE="${FEE:-1100}"; ARITY="${ARITY:-2}"; TOL_PCT="${TOL_PCT:-10}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-fc-cost.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/fc_cost_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
# Canonical scaffold seckeys: byte = 0x22 + i*0x11 (must equal client_fills).
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
[ -n "$MINE_ADDR" ] || fail "could not get mine address (wallet $WALLET)"
mine 101

echo "=== #329 force-close cost: calculator vs on-chain replay (N=$N_CLIENTS amount=$AMOUNT fee-rate=$FEE) ==="
"$LSP_BIN" --network regtest --port $PORT --demo --force-close --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity $ARITY --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -20 "$LSP_LOG"; fail "LSP died early"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon --seckey "$(sk $i)" --fee-rate $FEE \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" \
        --rpcport "$RPORT" --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!
echo "--- waiting for --force-close tree broadcast + confirmations, then LSP exit (~6min) ---"
for i in $(seq 1 220); do sleep 2; kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited (${i}x2s)"; break; }; done
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done
kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""

echo "=== analysis ==="
FEE_PER_TX=$(sqlite3 "$LSP_DB" "SELECT fee_per_tx FROM factories LIMIT 1;" 2>/dev/null)
[ -n "$FEE_PER_TX" ] && [ "$FEE_PER_TX" -gt 0 ] 2>/dev/null || fail "no usable fee_per_tx in factories table (got '$FEE_PER_TX')"
COUNT=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM broadcast_log WHERE source LIKE 'tree_node_%' AND result='ok';" 2>/dev/null)
if [ "${COUNT:-0}" -lt 1 ]; then
    echo "--- broadcast_log dump ---"; sqlite3 "$LSP_DB" "SELECT source,result,substr(txid,1,16) FROM broadcast_log;" 2>/dev/null | head -20
    echo "--- LSP log tail ---"; tail -25 "$LSP_LOG"
    fail "no successful tree_node broadcasts (did --force-close broadcast the tree?)"
fi
sqlite3 "$LSP_DB" "SELECT raw_hex FROM broadcast_log WHERE source LIKE 'tree_node_%' AND result='ok';" > "$TMPDIR/tree_hex.txt" 2>/dev/null

ACTUAL=$(python3 - "$REGTEST_CONF" "$TMPDIR/tree_hex.txt" <<'PY'
import json, subprocess, sys
conf, hexfile = sys.argv[1], sys.argv[2]
def cli(*a): return subprocess.run(["bitcoin-cli","-regtest","-conf="+conf,*a],capture_output=True,text=True).stdout.strip()
hexes=[l.strip() for l in open(hexfile) if l.strip()]
omap={}; decoded=[]
for h in hexes:
    d=json.loads(cli("decoderawtransaction",h)); decoded.append(d)
    omap[d["txid"]]=[int(round(o["value"]*1e8)) for o in d["vout"]]
total=0
for d in decoded:
    out=sum(int(round(o["value"]*1e8)) for o in d["vout"])
    ins=0
    for vin in d["vin"]:
        pt, pv = vin["txid"], vin["vout"]
        if pt in omap: ins+=omap[pt][pv]
        else:
            raw=cli("getrawtransaction",pt,"true")
            ins+=int(round(json.loads(raw)["vout"][pv]["value"]*1e8))
    total += ins-out
print(total)
PY
)
[ -n "$ACTUAL" ] || fail "fee computation failed (python/bitcoin-cli)"
PROJECTED=$((COUNT * FEE_PER_TX))
DIFF=$(( ACTUAL>PROJECTED ? ACTUAL-PROJECTED : PROJECTED-ACTUAL ))
PCT=$(( PROJECTED>0 ? DIFF*100/PROJECTED : 999 ))
echo "  tree TXs broadcast (count)  : $COUNT"
echo "  budgeted fee_per_tx (sats)  : $FEE_PER_TX"
echo "  PROJECTED  (count*fee_per_tx): $PROJECTED sats"
echo "  ACTUAL on-chain tree fees   : $ACTUAL sats"
echo "  delta=$DIFF sats (${PCT}% of projection; tolerance ${TOL_PCT}%)"
echo "  scope NOTE: TREE chain-broadcast cost only -- EXCLUDES channel commitments, HTLC/PTLC sweeps, penalty TXs, CPFP children, factory-burn (per dashboard #72 design)."
[ "$PCT" -le "$TOL_PCT" ] || fail "calculator MISMATCH: actual $ACTUAL vs projected $PROJECTED (${PCT}% > ${TOL_PCT}%)"
green "PASS: force-close cost calculator validated -- actual tree fees ($ACTUAL sats) within ${TOL_PCT}% of projection ($PROJECTED sats) across $COUNT TXs"
echo "FC_COST_REPLAY_TEST PASS"
