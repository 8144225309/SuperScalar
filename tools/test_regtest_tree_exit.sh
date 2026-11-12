#!/usr/bin/env bash
# test_regtest_tree_exit.sh — unilateral exit of the WHOLE factory tree with real
# daemons, checking that every pre-signed tx relays and every party ends with
# what it is owed on chain.
#
# Build an N-client factory (LSP + N client daemons), let the demo move some
# balance, then kill every SuperScalar process.  Optionally restart bitcoind
# with a higher -minrelaytxfee so the pre-signed tree / commitment fees sit
# BELOW what the node accepts and only CPFP (submitpackage with a child
# spending the P2A anchor) can get them in.  Then every client runs
# --force-close from its own DB, repeatedly, until the whole tree and every
# commitment confirm.
#
# Checks:
#   - every tree node in the LSP DB confirms on chain;
#   - every client's latest commitment confirms; its to_local pays the client
#     its channel balance and its to_remote pays the LSP its balance less the
#     commitment fee;
#   - a client that never transacted holds no signed commitment (only the
#     first payment persists one); its channel output must stay unspent on
#     chain, so channels exited + channels left intact = all channels;
#   - every leaf L-stock output (the LSP's liquidity stock) is on chain, unspent;
#   - with MINRELAY set, at least one tree tx went in as a CPFP package;
#     without it, every tree tx relayed on its own.
# Needs a node with -txindex (confirmations of non-wallet txs).
#
# Env: REGTEST_CONF (required), ARITY (1|2|3=PS, default 2), N_CLIENTS (default 4),
# TREE_FEE_RATE (the factory's agreed pre-signed rate, --tree-fee-rate, sat/kvB,
# default 100; 0 = no fee, every tree tx needs a CPFP child), MINRELAY (sat/kvB
# to restart the node with before the exit, a fee spike after signing; default 0
# = unchanged), CLIENT_WALLET (1 = clients fund CPFP children from the bitcoind
# wallet, 0 = none of them has on-chain funds), NOWALLET (space-separated client
# indices that exit without a wallet coin: their children spend the anchor
# alone), SOLO (1 = the clients exit one at a time, in EXIT_ORDER, each running
# --force-close alone until its own commitment confirms), EXIT_ORDER (default
# 0..N-1), EXPECT_NOCOIN (client index that exits first without a wallet coin
# while the tree pays nothing (rate 0): its --force-close must exit 1 with the
# "needs a fee-paying child: no wallet coin" message, and it completes later,
# once others published the tree, its commitment's 240-sat anchor paying for
# itself), SWEEP (1 = after the exit every client sweeps its to_local with
# --sweep-to-local once the CSV matured), CLIENT_FEE_EST (client
# --fee-estimator on --force-close: its urgent rate is the CPFP target),
# CLIENT_MAX_TREE_RATE (the clients' --max-tree-fee-rate), EXPECT_REFUSE (1 =
# the clients must refuse to sign the proposed tree; checks the refusal and
# stops), EXPECT_STUCK (1 = with MINRELAY above what a pre-signed tx and its
# anchor-only child pay, and CLIENT_WALLET=0, every client's --force-close must
# exit 1 saying the tx needs a fee-paying child and no wallet coin is
# available), GRIEF (1 = after the first force-close pass, before any block,
# attach an anchor-only child to every tree tx in the mempool, as anyone can;
# the next passes, with CLIENT_FEE_EST raised, must replace those children;
# GRIEF=wallet: the same with children funded from a third party's own bitcoind
# wallet; needs TREE_FEE_RATE > 0), AMOUNT, PORT.
#
# Also checked on every run: no tree tx is ever in the mempool on an
# unconfirmed parent (TRUC: that would take the parent's only descendant slot,
# which its CPFP child needs); every tree tx and the co-signed distribution TX
# pay exactly the agreed rate for their size, with the anchor worth 0 at rate 0
# and 240 sat otherwise.  The evidence (txid, vsize, fee, package children) of
# every exit transaction is printed at the end.
set -uo pipefail

BUILD_DIR="${1:-build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

ARITY="${ARITY:-2}"
N_CLIENTS="${N_CLIENTS:-4}"
TREE_FEE_RATE="${TREE_FEE_RATE:-100}"
MINRELAY="${MINRELAY:-0}"
CLIENT_WALLET="${CLIENT_WALLET:-1}"
LSP_FEE_EST="${LSP_FEE_EST:-}"
FEST=(); [ -n "$LSP_FEE_EST" ] && FEST=(--fee-estimator "$LSP_FEE_EST")
CLIENT_MAX_TREE_RATE="${CLIENT_MAX_TREE_RATE:-}"
CMAX=(); [ -n "$CLIENT_MAX_TREE_RATE" ] && CMAX=(--max-tree-fee-rate "$CLIENT_MAX_TREE_RATE")
EXPECT_REFUSE="${EXPECT_REFUSE:-0}"
EXPECT_STUCK="${EXPECT_STUCK:-0}"
NOWALLET="${NOWALLET:-}"
SOLO="${SOLO:-0}"
EXIT_ORDER="${EXIT_ORDER:-$(seq -s ' ' 0 $((N_CLIENTS-1)))}"
EXPECT_NOCOIN="${EXPECT_NOCOIN:-}"
SWEEP="${SWEEP:-0}"
GRIEF="${GRIEF:-0}"
AMOUNT="${AMOUNT:-$((N_CLIENTS * 60000))}"
PORT="${PORT:-29975}"
FEE=1100
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
WALLET="ss_tree_exit_miner"

TMPDIR=$(mktemp -d /tmp/ss-tree-exit.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
sk(){ printf "00000000000000000000000000000000000000000000000000000000000000%02x" $(( $1 + 2 )); }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('confirmations',0))
except Exception: print(0)"; }
outval(){ $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c "import json,sys
try: print(int(round(json.load(sys.stdin)['vout'][$2]['value']*1e8)))
except Exception: print(-1)"; }

# (Re)start the node with -txindex and its default relay floor: a run with
# MINRELAY leaves it running with a raised -minrelaytxfee, and the next run on
# the same node (CI runs them in sequence) must not inherit that.
echo "--- (re)starting bitcoind -txindex from $REGTEST_CONF ---"
$BCLI stop >/dev/null 2>&1 && for i in $(seq 1 30); do sleep 1; $BCLI getblockcount >/dev/null 2>&1 || break; done
sleep 2
bitcoind -conf="$REGTEST_CONF" -daemon -txindex=1 >/dev/null
for i in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockcount >/dev/null 2>&1 || fail "bitcoind did not start"
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false >/dev/null 2>&1 || $BCLI loadwallet $WALLET >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 110

echo "=== tree exit: arity=$ARITY clients=$N_CLIENTS tree_fee_rate=$TREE_FEE_RATE minrelay=$MINRELAY client_wallet=$CLIENT_WALLET ==="
TFR=(--tree-fee-rate "$TREE_FEE_RATE")
# A long factory lifetime: no rotation or expiry while the test runs.
H0=$($BCLI getblockcount)
LIFE=(--cltv-timeout $((H0 + 5000)) --active-blocks 4000 --dying-blocks 500)
"$LSP_BIN" --network regtest --port $PORT --demo --daemon --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity $ARITY --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
    --step-blocks 2 --states-per-layer 2 "${TFR[@]}" "${LIFE[@]}" "${FEST[@]}" \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || { tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon \
        --keyfile "$TMPDIR/c${i}.key" --passphrase pw "${CMAX[@]}" \
        --fee-rate $FEE --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" \
        --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!

if [ "$EXPECT_REFUSE" = 1 ]; then
    for i in $(seq 1 120); do sleep 2; kill -0 $LSP_PID 2>/dev/null || break; grep -q "channels ready" "$LSP_LOG" && break; done
    grep -q "channels ready" "$LSP_LOG" && fail "factory was created although the clients should refuse its tree fee rate"
    NREF=$(grep -l "REFUSING — tree fee rate" "$TMPDIR"/c*.log 2>/dev/null | wc -l)
    grep -aE "tree fee rate" "$LSP_LOG" | head -1
    [ "$NREF" -ge 1 ] || { tail -20 "$TMPDIR/c0.log"; fail "no client refused the tree fee rate"; }
    green "PASS: $NREF/$N_CLIENTS clients refused to sign a tree at --tree-fee-rate $TREE_FEE_RATE above their --max-tree-fee-rate $CLIENT_MAX_TREE_RATE; no factory created"
    exit 0
fi
for i in $(seq 1 200); do sleep 2; grep -q "channels ready" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || { tail -40 "$LSP_LOG"; fail "LSP died before factory ready"; }; done
grep -q "channels ready" "$LSP_LOG" || { tail -40 "$LSP_LOG"; fail "factory never reached 'channels ready'"; }
grep -aE "tree fee rate" "$LSP_LOG" | head -1
grep -q "LSP: tree fee rate $TREE_FEE_RATE sat/kvB" "$LSP_LOG" \
    || fail "tree not built at the agreed $TREE_FEE_RATE sat/kvB"
# let the demo payments finish (--daemon keeps the factory open afterwards)
for i in $(seq 1 120); do sleep 2; grep -q "Demo Complete" "$LSP_LOG" 2>/dev/null && break; done
grep -q "Demo Complete" "$LSP_LOG" || { tail -30 "$LSP_LOG"; fail "demo never completed"; }
sleep 5
sleep 10
declare -a HAS
NHAS=0
for c in $(seq 0 $((N_CLIENTS-1))); do
    n=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT count(*) FROM signed_commitments;" 2>/dev/null || echo 0)
    if [ "${n:-0}" -ge 1 ]; then HAS[$c]=1; NHAS=$((NHAS+1)); else HAS[$c]=0; fi
done
echo "  clients holding a signed commitment: $NHAS/$N_CLIENTS"
[ "$NHAS" -ge 1 ] || fail "no client persisted a commitment"

grep -q "cooperative close" "$LSP_LOG" && fail "LSP closed the factory cooperatively; nothing to exit"
grep -qi "rotation complete" "$TMPDIR"/c0.log && fail "the factory rotated during the test"
echo "--- every SuperScalar process vanishes ---"
kill -9 "$MINER_PID" 2>/dev/null || true; MINER_PID=""
for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
PIDS=(); sleep 2

if [ "$MINRELAY" -gt 0 ]; then
    echo "--- restarting bitcoind with -minrelaytxfee=$MINRELAY sat/kvB ---"
    $BCLI stop >/dev/null 2>&1
    for i in $(seq 1 30); do sleep 1; $BCLI getblockcount >/dev/null 2>&1 || break; done
    sleep 2
    MR=$(python3 -c "print('%.8f' % ($MINRELAY / 1e8))")
    bitcoind -conf="$REGTEST_CONF" -daemon -txindex=1 -minrelaytxfee=$MR -blockmintxfee=0 >/dev/null
    for i in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
    $BCLI loadwallet $WALLET >/dev/null 2>&1 || true
    $BCLI getmempoolinfo | grep -E "minrelaytxfee|mempoolminfee"
fi

# expected balances, from each client's own DB
declare -a CTX CLOCAL CREMOTE
for i in $(seq 0 $((N_CLIENTS-1))); do
    [ "${HAS[$i]}" = 1 ] || { CTX[$i]=""; continue; }
    h=$(sqlite3 "$TMPDIR/c${i}.db" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;")
    CTX[$i]=$($BCLI decoderawtransaction "$h" | python3 -c "import json,sys; print(json.load(sys.stdin)['txid'])")
    CLOCAL[$i]=$(sqlite3 "$TMPDIR/c${i}.db" "SELECT local_amount FROM channels LIMIT 1;")
    CREMOTE[$i]=$(sqlite3 "$TMPDIR/c${i}.db" "SELECT remote_amount FROM channels LIMIT 1;")
done
mapfile -t TREE < <(sqlite3 "$LSP_DB" "SELECT txid FROM tree_nodes WHERE factory_id=0 ORDER BY node_index;")
echo "  tree nodes: ${#TREE[@]}, commitments: $NHAS"

# distribution TX: the co-signed one a client stored pays the tree rate for its size
TREE_RATE=$(grep -aoE "LSP: tree fee rate [0-9]+" "$LSP_LOG" | head -1 | grep -oE "[0-9]+$")
DHEX=$(sqlite3 "$TMPDIR/c0.db" "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id=0;" 2>/dev/null)
if [ -n "$DHEX" ] && [ -n "$TREE_RATE" ]; then
    FUND=$(sqlite3 "$LSP_DB" "SELECT funding_amount FROM factories WHERE id=0;")
    read -r DVS DOUT < <($BCLI decoderawtransaction "$DHEX" | python3 -c "import json,sys
d=json.load(sys.stdin); print(d['vsize'], sum(int(round(o['value']*1e8)) for o in d['vout']))")
    DFEE=$((FUND - DOUT)); DWANT=$(( (TREE_RATE * DVS + 999) / 1000 ))
    read -r DVER DANCH < <($BCLI decoderawtransaction "$DHEX" | python3 -c "import json,sys
d=json.load(sys.stdin); a=[o for o in d['vout'] if o['scriptPubKey']['hex']=='51024e73']
print(d['version'], int(round(a[-1]['value']*1e8)) if a and a[-1] is d['vout'][-1] else -1)")
    AWANT=240; [ "$TREE_RATE" = 0 ] && AWANT=0
    echo "  distribution TX: v$DVER, fee $DFEE sat for $DVS vB at $TREE_RATE sat/kvB (expected $DWANT), anchor $DANCH sat (expected $AWANT), funding $FUND"
    [ "$DFEE" -eq "$DWANT" ] || fail "distribution TX pays $DFEE, not $DWANT"
    [ "$DVER" = 3 ] && [ "$DANCH" = "$AWANT" ] || fail "distribution TX not v3 with one $AWANT-sat anchor last"
else
    fail "no co-signed distribution TX stored by client 0"
fi

# every tree tx pays exactly the agreed rate for its size, the anchor last
for t in "${TREE[@]}"; do
    h=$(sqlite3 "$LSP_DB" "SELECT signed_tx_hex FROM tree_nodes WHERE factory_id=0 AND txid='$t';")
    pin=$(sqlite3 "$LSP_DB" "SELECT input_amount FROM tree_nodes WHERE factory_id=0 AND txid='$t';")
    [ -n "$h" ] && [ -n "$pin" ] || fail "tree tx $t not in the LSP DB"
    r=$($BCLI decoderawtransaction "$h" | python3 -c "import json,sys
d=json.load(sys.stdin); a=[o for o in d['vout'] if o['scriptPubKey']['hex']=='51024e73']
print(d['version'], d['vsize'], sum(int(round(o['value']*1e8)) for o in d['vout']),
      int(round(a[0]['value']*1e8)) if a else -1, len(a))")
    set -- $r
    want=$(( (TREE_RATE * $2 + 999) / 1000 ))
    [ "$1" = 3 ] && [ $((pin - $3)) -eq "$want" ] || fail "tree tx $t: v$1 pays $((pin - $3)) for $2 vB, not $want"
    if [ "$5" -ge 1 ]; then
        [ "$5" = 1 ] && [ "$4" = "$AWANT" ] || fail "tree tx $t: $5 anchors worth $4"
    else
        [ "$TREE_RATE" -gt 0 ] || fail "tree tx $t has no anchor at rate 0"
    fi
done
echo "  tree txs: all v3, each paying exactly $TREE_FEE_RATE sat/kvB for its size"

# Anyone can spend a P2A anchor: attach a cheap child to every tree tx in the
# mempool that has none (TRUC child of a TRUC parent).  GRIEF=wallet: the
# child also spends a confirmed coin of the griefer's own wallet, into change.
GWALLET="ss_tree_exit_griefer"
if [ "$GRIEF" = wallet ]; then
    $BCLI -named createwallet wallet_name=$GWALLET load_on_startup=false >/dev/null 2>&1 || $BCLI loadwallet $GWALLET >/dev/null 2>&1 || true
    for k in 1 2 3 4; do
        $BCLI -rpcwallet=$WALLET -named sendtoaddress address="$($BCLI -rpcwallet=$GWALLET getnewaddress)" \
            amount=0.001 fee_rate=50 >/dev/null || fail "cannot fund the griefer wallet"
    done
    mine 1
fi
GRIEFED=(); GCHILD=()
grief_all(){
    for t in "${TREE[@]}"; do
        local dc
        dc=$($BCLI getmempoolentry "$t" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['descendantcount'])" 2>/dev/null)
        [ "$dc" = 1 ] || continue
        local n raw c
        n=$($BCLI getrawtransaction "$t" true | python3 -c "import json,sys
d=json.load(sys.stdin); print(next((o['n'] for o in d['vout'] if o['scriptPubKey']['hex']=='51024e73'), -1))")
        [ "$n" -ge 0 ] || continue
        if [ "$GRIEF" = wallet ]; then
            local u gaddr
            u=$($BCLI -rpcwallet=$GWALLET listunspent 1 | python3 -c "import json,sys
u=json.load(sys.stdin)[0]; print(u['txid'], u['vout'], '%.8f' % (u['amount'] + $AWANT / 1e8 - 0.000006))") || continue
            set -- $u
            gaddr=$($BCLI -rpcwallet=$GWALLET getnewaddress)
            raw=$($BCLI createrawtransaction "[{\"txid\":\"$t\",\"vout\":$n},{\"txid\":\"$1\",\"vout\":$2}]" "[{\"$gaddr\":$3}]")
            raw="03${raw:2}"
            raw=$($BCLI -rpcwallet=$GWALLET signrawtransactionwithwallet "$raw" \
                "[{\"txid\":\"$t\",\"vout\":$n,\"scriptPubKey\":\"51024e73\",\"amount\":$(python3 -c "print('%.8f' % ($AWANT / 1e8))")}]" \
                | python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])") || continue
        else
            raw=$($BCLI createrawtransaction "[{\"txid\":\"$t\",\"vout\":$n}]" '[{"data":"535341"}]')
            raw="03${raw:2}"
        fi
        c=$($BCLI sendrawtransaction "$raw" 0) || continue
        GRIEFED+=("$t"); GCHILD+=("$c")
        echo "  griefer child $c on tree tx $t"
    done
}

CLIENT_FEE_EST="${CLIENT_FEE_EST:-}"
nowallet(){ case " $NOWALLET " in *" $1 "*) return 0;; esac; [ "$CLIENT_WALLET" = 1 ] && return 1; return 0; }
# one --force-close run of client $1 (pass $2): FCRC[$1], fc_last_$1.log
fc_run(){
    local i=$1 pass=$2 opt=()
    nowallet "$i" || opt=(--wallet "$WALLET")
    if [ -n "$CLIENT_FEE_EST" ] && ! { [ "$GRIEF" != 0 ] && [ "$pass" = 1 ]; }; then
        opt+=(--fee-estimator "$CLIENT_FEE_EST")
    fi
    "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        "${opt[@]}" --force-close --db "$TMPDIR/c${i}.db" > "$TMPDIR/fc_last_${i}.log" 2>&1
    FCRC[$i]=$?
    cat "$TMPDIR/fc_last_${i}.log" >> "$TMPDIR/fc_${i}.log"
}
check_unconf_parents(){
    local t d
    for t in "${TREE[@]}"; do
        d=$($BCLI getmempoolentry "$t" 2>/dev/null | python3 -c "import json,sys; print(len(json.load(sys.stdin)['depends']))" 2>/dev/null)
        if [ -n "$d" ] && [ "$d" -gt 0 ]; then
            NUNCONF_PARENT=$((NUNCONF_PARENT+1)); red "  pass $1: tree tx $t in the mempool on an unconfirmed parent"
        fi
    done
}
count_confirmed(){
    TC=0; for t in "${TREE[@]}"; do [ "$(confs "$t")" -ge 1 ] && TC=$((TC+1)); done
    CC=0; for i in $(seq 0 $((N_CLIENTS-1))); do [ -n "${CTX[$i]}" ] && [ "$(confs "${CTX[$i]}")" -ge 1 ] && CC=$((CC+1)); done
}
NUNCONF_PARENT=0
NOCOIN_SEEN=0
TC=0; CC=0
if [ "$SOLO" = 1 ]; then
    echo "--- the clients exit one at a time ($EXIT_ORDER), each running --force-close alone ---"
    ORDER="$EXIT_ORDER"
    [ -n "$EXPECT_NOCOIN" ] && ORDER="$EXPECT_NOCOIN $EXIT_ORDER $EXPECT_NOCOIN"
    first=1
    for i in $ORDER; do
        [ -n "${CTX[$i]}" ] || { echo "  client $i holds no signed commitment: nothing to exit"; first=0; continue; }
        [ "$(confs "${CTX[$i]}")" -ge 1 ] && continue
        echo "  -- client $i ($(nowallet "$i" && echo 'no wallet coin' || echo 'wallet')) exits alone"
        for pass in $(seq 1 40); do
            fc_run "$i" "$pass"
            if [ "$first" = 1 ] && [ "$i" = "$EXPECT_NOCOIN" ]; then
                grep -a "CPFP: ERROR" "$TMPDIR/fc_last_${i}.log" | head -1
                grep -a "FORCE-CLOSE FAILED" "$TMPDIR/fc_last_${i}.log" | head -1
                [ "${FCRC[$i]}" = 1 ] &&
                grep -q "needs a fee-paying child: no wallet coin available" "$TMPDIR/fc_last_${i}.log" &&
                grep -q "FORCE-CLOSE FAILED" "$TMPDIR/fc_last_${i}.log" &&
                ! grep -q "FORCE-CLOSE COMPLETE" "$TMPDIR/fc_last_${i}.log" \
                    || { tail -15 "$TMPDIR/fc_last_${i}.log"; fail "client $i without a coin did not report its stuck exit (status ${FCRC[$i]})"; }
                green "  client $i, first to exit, no wallet coin, tree at rate 0: --force-close exits 1, 'needs a fee-paying child: no wallet coin available'"
                NOCOIN_SEEN=1
                mine 1
                break
            fi
            check_unconf_parents "$pass"
            mine 1
            if [ "$(confs "${CTX[$i]}")" -ge 1 ]; then
                echo "     client $i: commitment ${CTX[$i]} confirmed after $pass passes (rc ${FCRC[$i]})"
                break
            fi
        done
        first=0
    done
    count_confirmed
    # whatever tree txs no exiting client needed: the remaining clients' paths
    # are on chain once every commitment is; the rest stays in the DB
    echo "  tree $TC/${#TREE[@]} confirmed, commitments $CC/$NHAS (height $($BCLI getblockcount))"
else
echo "--- every client force-closes from its own DB, repeatedly, mining between passes ---"
for pass in $(seq 1 60); do
    for i in $(seq 0 $((N_CLIENTS-1))); do fc_run "$i" "$pass"; done
    if [ "$EXPECT_STUCK" = 1 ]; then
        NSTUCK=0
        for i in $(seq 0 $((N_CLIENTS-1))); do
            if [ "${FCRC[$i]}" = 1 ] &&
               grep -q "needs a fee-paying child: no wallet coin available" "$TMPDIR/fc_last_${i}.log" &&
               grep -q "FORCE-CLOSE FAILED" "$TMPDIR/fc_last_${i}.log" &&
               ! grep -q "FORCE-CLOSE COMPLETE" "$TMPDIR/fc_last_${i}.log"; then
                NSTUCK=$((NSTUCK+1))
            fi
        done
        echo "  pass $pass: $NSTUCK/$N_CLIENTS clients report a stuck exit (status 1, no wallet coin)"
        grep -a "CPFP: ERROR" "$TMPDIR/fc_last_0.log" | head -1
        if [ "$NSTUCK" -eq "$N_CLIENTS" ]; then
            green "PASS: without a wallet coin every client's exit stops with status 1 and says the pre-signed tx needs a fee-paying child (rate=$TREE_FEE_RATE minrelay=$MINRELAY)"
            exit 0
        fi
        [ "$pass" -ge 3 ] && { tail -15 "$TMPDIR/fc_last_0.log"; fail "the clients did not report the stuck exit"; }
        mine 3
        continue
    fi
    check_unconf_parents "$pass"
    if [ "$GRIEF" != 0 ] && [ "$pass" = 1 ]; then
        grief_all
        [ "${#GRIEFED[@]}" -ge 1 ] || fail "nothing in the mempool to grief"
        echo "  pass 1: ${#GRIEFED[@]} tree txs griefed; no block until the next pass"
        continue
    fi
    mine 3
    count_confirmed
    echo "  pass $pass: tree $TC/${#TREE[@]} confirmed, commitments $CC/$NHAS (height $($BCLI getblockcount))"
    [ "$TC" -eq "${#TREE[@]}" ] && [ "$CC" -eq "$NHAS" ] && break
done
fi

PKG=$(cat "$TMPDIR"/fc_*.log | grep -c "sent as a package")
ANCHOR_ONLY=$(cat "$TMPDIR"/fc_*.log | grep -c "anchor-only child")
TREE_PKG=0
for t in "${TREE[@]}"; do grep -q "CPFP: $t .*sent as a package" "$TMPDIR"/fc_*.log && TREE_PKG=$((TREE_PKG+1)); done
echo
echo "=== accounting ==="
echo "  CPFP packages: $PKG, of which tree txs: $TREE_PKG (anchor-only children: $ANCHOR_ONLY)"
OK=1
if [ "$SOLO" = 1 ]; then
    [ "$TC" -ge 1 ] || { red "  tree: nothing confirmed"; OK=0; }
    [ -z "$EXPECT_NOCOIN" ] || [ "$NOCOIN_SEEN" = 1 ] || { red "  the no-coin client never reported its stuck exit"; OK=0; }
else
    [ "$TC" -eq "${#TREE[@]}" ] || { red "  tree: only $TC/${#TREE[@]} nodes confirmed"; OK=0; }
fi
[ "$NUNCONF_PARENT" -eq 0 ] || { red "  $NUNCONF_PARENT tree txs were sent on an unconfirmed parent"; OK=0; }
if [ "$GRIEF" != 0 ]; then
    NB=0
    for k in "${!GRIEFED[@]}"; do
        t=${GRIEFED[$k]}; c=${GCHILD[$k]}
        grep -q "CPFP: $t was in the mempool .*replacing its child" "$TMPDIR"/fc_*.log && NB=$((NB+1))
        [ "$(confs "$c")" -ge 1 ] && { red "  griefer child $c confirmed"; OK=0; }
    done
    echo "  griefed tree txs re-bumped by replacing the griefer's child: $NB/${#GRIEFED[@]}"
    [ "$NB" -eq "${#GRIEFED[@]}" ] || OK=0
fi
[ "$CC" -eq "$NHAS" ] || { red "  commitments: only $CC/$NHAS confirmed"; OK=0; }
for i in $(seq 0 $((N_CLIENTS-1))); do
    [ -n "${CTX[$i]}" ] || continue
    tl=$(outval "${CTX[$i]}" 0); tr=$(outval "${CTX[$i]}" 1)
    lsp_owed=${CREMOTE[$i]}
    echo "  client $i: to_local $tl (owed ${CLOCAL[$i]}), LSP to_remote $tr (LSP balance $lsp_owed)"
    [ "$tl" = "${CLOCAL[$i]}" ] || { red "  client $i to_local $tl != balance ${CLOCAL[$i]}"; OK=0; }
    # to_remote = LSP balance less the 240-sat commitment anchor the LSP funds
    [ "$tr" -gt 0 ] && [ "$tr" -le "$lsp_owed" ] && [ "$tr" -ge $((lsp_owed - 240)) ] \
        || { red "  client $i: LSP to_remote $tr outside [$((lsp_owed-240)), $lsp_owed]"; OK=0; }
done
# L-stock: every leaf state's L-stock output is on chain and unspent;
# channel outputs: spent by a confirmed commitment or still unspent
NL=0; LS=0; CHU=0
while IFS='|' read -r txid nout amounts; do
    [ -z "$txid" ] && continue
    NL=$((NL+1))
    # L-stock = last non-anchor output (anchor = 240-sat P2A last)
    v=$($BCLI getrawtransaction "$txid" true | python3 -c "import json,sys
d=json.load(sys.stdin); o=[x for x in d['vout'] if x['scriptPubKey']['hex']!='51024e73']
print(o[-1]['n'], int(round(o[-1]['value']*1e8)))")
    set -- $v
    u=$($BCLI gettxout "$txid" "$1" | python3 -c "import json,sys
try: print(int(round(json.load(sys.stdin)['value']*1e8)))
except Exception: print(-1)")
    [ "$u" = "$2" ] && LS=$((LS+1)) || red "  leaf $txid L-stock vout $1 not unspent on chain"
    for v in $(seq 0 $(( $1 - 1 ))); do
        $BCLI gettxout "$txid" "$v" | grep -q value && CHU=$((CHU+1))
    done
done < <(sqlite3 "$LSP_DB" "SELECT t.txid, t.n_outputs, t.output_amounts FROM tree_nodes t WHERE t.factory_id=0 AND t.type='state' AND NOT EXISTS (SELECT 1 FROM tree_nodes c WHERE c.factory_id=0 AND c.parent_index=t.node_index);")
echo "  leaf L-stock outputs unspent on chain: $LS/$NL"
echo "  channels: $CC exited by commitment, $CHU left unspent on chain (of $N_CLIENTS)"
if [ "$SOLO" != 1 ]; then
    [ $((CC + CHU)) -eq "$N_CLIENTS" ] || { red "  channel outputs unaccounted for"; OK=0; }
    [ "$NL" -ge 1 ] && [ "$LS" -eq "$NL" ] || OK=0
fi
if [ "$TREE_FEE_RATE" = 0 ]; then
    # nothing pays a fee: every confirmed tree tx went in as a package
    [ "$TREE_PKG" -eq "$TC" ] || { red "  rate 0: only $TREE_PKG of $TC confirmed tree txs went in as packages"; OK=0; }
elif [ "$MINRELAY" -gt "$TREE_FEE_RATE" ] || [ -n "$CLIENT_FEE_EST" ]; then
    [ "$TREE_PKG" -ge 1 ] || { red "  min relay or fee estimate raised but no tree tx needed a package"; OK=0; }
else
    # the agreed rate meets the node's relay floor: every tree tx alone
    [ "$TREE_PKG" -eq 0 ] || { red "  $TREE_PKG tree txs needed a package without fee pressure"; OK=0; }
fi
if [ -n "$NOWALLET" ] && [ "$TREE_FEE_RATE" -gt 0 ] && [ "$MINRELAY" -gt "$TREE_FEE_RATE" ]; then
    NAO=0; for i in $NOWALLET; do grep -q "anchor-only child" "$TMPDIR/fc_${i}.log" && NAO=$((NAO+1)); done
    echo "  no-wallet clients that exited with anchor-only children: $NAO ($NOWALLET)"
    [ "$NAO" -ge 1 ] || { red "  no anchor-only child from a no-wallet client"; OK=0; }
fi

# evidence: every confirmed exit tx, its vsize and fee, and the package
# child that spent its anchor in the same block
python3 - "$REGTEST_CONF" "${TREE[@]}" -- "${CTX[@]}" <<'PYEOF' || true
import json, subprocess, sys
conf = sys.argv[1]
args = sys.argv[2:]
k = args.index('--')
tree, commits = args[:k], [c for c in args[k+1:] if c]
def cli(*a):
    p = subprocess.run(['bitcoin-cli', '-regtest', '-conf=' + conf] + list(a),
                       capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 else None
def sat(v): return int(round(v * 1e8))
def fee(tx):
    tin = 0
    for i in tx['vin']:
        p = cli('getrawtransaction', i['txid'], 'true')
        if not p: return None
        tin += sat(p['vout'][i['vout']]['value'])
    return tin - sum(sat(o['value']) for o in tx['vout'])
print('  %-10s %-64s %5s %7s %s' % ('kind', 'txid', 'vB', 'fee', 'package child (vB, fee)'))
for kind, ids in (('tree', tree), ('commitment', commits)):
    for t in ids:
        tx = cli('getrawtransaction', t, 'true')
        if not tx or not tx.get('blockhash'):
            continue
        anchor = next((o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'] == '51024e73'), None)
        child = ''
        if anchor is not None:
            blk = cli('getblock', tx['blockhash'], '2')
            for c in blk['tx']:
                if any(i.get('txid') == t and i.get('vout') == anchor for i in c['vin']):
                    child = '%s (%d vB, %s sat)' % (c['txid'], c['vsize'], fee(c))
        print('  %-10s %s %5d %7s %s' % (kind, t, tx['vsize'], fee(tx), child or 'alone'))
PYEOF

# --sweep-to-local: every exited client takes its to_local once the CSV matured
if [ "$SWEEP" = 1 ] && [ "$OK" = 1 ]; then
    echo "--- every exited client sweeps its to_local after the CSV ---"
    mine 145
    NSW=0; NEX=0
    for i in $(seq 0 $((N_CLIENTS-1))); do
        [ -n "${CTX[$i]}" ] && [ "$(confs "${CTX[$i]}")" -ge 1 ] || continue
        NEX=$((NEX+1))
        dest=$($BCLI -rpcwallet=$WALLET getaddressinfo "$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)" \
               | python3 -c "import json,sys; print(json.load(sys.stdin)['scriptPubKey'])")
        "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
            --keyfile "$TMPDIR/c${i}.key" --passphrase pw --sweep-to-local --sweep-dest "$dest" \
            --db "$TMPDIR/c${i}.db" > "$TMPDIR/sweep_${i}.log" 2>&1
        st=$(grep -aoE "to_local swept! txid = [0-9a-f]{64}" "$TMPDIR/sweep_${i}.log" | awk '{print $5}')
        [ -n "$st" ] || { tail -8 "$TMPDIR/sweep_${i}.log"; red "  client $i: no sweep"; OK=0; continue; }
        mine 1
        sv=$(outval "$st" 0)
        echo "  client $i: sweep $st confirmed $(confs "$st"), pays $sv of to_local ${CLOCAL[$i]}"
        [ "$(confs "$st")" -ge 1 ] && [ "$sv" -gt 0 ] && [ "$sv" -lt "${CLOCAL[$i]}" ] && NSW=$((NSW+1)) || OK=0
    done
    echo "  to_local swept: $NSW/$NEX"
fi
if [ "$OK" = 1 ]; then
    green "PASS: tree exit (arity=$ARITY clients=$N_CLIENTS tree_fee_rate=$TREE_FEE_RATE minrelay=$MINRELAY wallet=$CLIENT_WALLET nowallet='$NOWALLET' solo=$SOLO client_fee_est=${CLIENT_FEE_EST:-none} grief=$GRIEF sweep=$SWEEP): $TC/${#TREE[@]} tree txs + $CC commitments confirmed, balances paid, $CHU idle channels intact, $PKG CPFP packages ($TREE_PKG tree, $ANCHOR_ONLY anchor-only children)"
    exit 0
fi
for i in $(seq 0 $((N_CLIENTS-1))); do echo "--- fc_$i tail ---"; grep -aE "CPFP|error|fail" "$TMPDIR/fc_${i}.log" | tail -8; done
fail "tree exit did not complete"
