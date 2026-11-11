#!/usr/bin/env bash
# test_regtest_large_tree_exit.sh — unilateral client exit from a factory whose
# tree has more than 128 transactions (regtest, real daemons).
#
# One LSP and N client processes build a factory. A few clients pay each
# other, so they hold signed commitments. Then every SuperScalar process is
# stopped and the clients on the HIGHEST-index leaves exit on their own with
# `superscalar_client --force-close`, one pass per block, with nothing but
# their own DB and a bitcoind.
#
# Checks:
#   - the tree has more than 128 transactions, every leaf carries
#     CLIENTS_PER_LEAF channels, and the path of every exiting client contains
#     a node with index >= 128;
#   - no force-close pass reports an error, and none reports completion before
#     the commitment is published;
#   - every exiting client's commitment confirms and carries an output of
#     exactly that client's channel balance;
#   - the only tree transactions on chain are the ones on the exiting clients'
#     own paths (a client publishes its path, not the tree);
#   - conservation: unspent factory outputs + fees + anchors add up to the
#     factory funding, and nothing else spends a factory output.
#
# The script starts its own bitcoind (regtest, txindex) in a scratch directory
# and stops it again. Its config lowers the relay floor (minrelaytxfee and
# blockmintxfee, to RELAY_FLOOR = 0.1 sat/vB): a client commitment, and the
# root transaction of a wide static-near-root tree, pay less than Bitcoin
# Core's default 1 sat/vB floor and would not relay otherwise.
#
# Usage: bash tools/test_regtest_large_tree_exit.sh [BUILD_DIR]
# Env:   N_CLIENTS (72)  ARITY (2)  STATIC_NEAR_ROOT (0)  CLIENTS_PER_LEAF (2)
#        PAYMENTS (2)  AMOUNT (300000 sat per client)
#        The defaults are two-client leaves: 72 clients, 142 tree transactions.
#        One client per pseudo-Spilman leaf crosses 128 with fewer processes:
#          N_CLIENTS=36 ARITY=3 CLIENTS_PER_LEAF=1                        (142)
#          N_CLIENTS=64 ARITY=8,7,3 STATIC_NEAR_ROOT=2 CLIENTS_PER_LEAF=1 (153)
#        Those shapes only pass when a settled payment leaves the payer's and
#        the payee's leaf transaction untouched; the script stops with a
#        precondition failure when a leaf was replaced after the channel
#        opened.
#        PORT (29975) RPCPORT (18743) DEADLINE (1500 s) MAX_PASSES (120)
#        RELAY_FLOOR (0.000001 BTC/kvB)
#        WORK_DIR (mktemp) BTC_DIR ($WORK_DIR/bitcoind) KEEP_WORK (0)
#        EXIT_CLIENT_BIN: client binary for the force-close passes, e.g. a
#        sanitizer build (default: the one from BUILD_DIR)
set -uo pipefail

BUILD_DIR="${1:-build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
EXIT_CLIENT_BIN="${EXIT_CLIENT_BIN:-$CLIENT_BIN}"

N_CLIENTS="${N_CLIENTS:-72}"
ARITY="${ARITY:-2}"
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-0}"
CLIENTS_PER_LEAF="${CLIENTS_PER_LEAF:-2}"
PAYMENTS="${PAYMENTS:-2}"
PAY_AMT="${PAY_AMT:-10000}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 300000 ))}"
FEE_RATE="${FEE_RATE:-1000}"
PORT="${PORT:-29975}"
RPCPORT="${RPCPORT:-18743}"
DEADLINE="${DEADLINE:-1500}"
RELAY_FLOOR="${RELAY_FLOOR:-0.000001}"
MAX_PASSES="${MAX_PASSES:-120}"
RU=rpcuser; RP=rpcpass
WALLET=large_tree_exit
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { echo "[large-tree-exit] $*"; }

for b in "$LSP_BIN" "$CLIENT_BIN" "$EXIT_CLIENT_BIN"; do
    [ -x "$b" ] || { red "FAIL: $b not found (build first)"; exit 1; }
done
for t in bitcoind bitcoin-cli python3; do
    command -v "$t" >/dev/null || { red "FAIL: $t not in PATH"; exit 1; }
done
[ $(( 2 * PAYMENTS )) -le "$N_CLIENTS" ] || { red "FAIL: PAYMENTS too large"; exit 1; }

WORK="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/ss-large-tree-exit.XXXXXX")}"
BTC_DIR="${BTC_DIR:-$WORK/bitcoind}"
mkdir -p "$WORK" "$BTC_DIR"
BCLI="bitcoin-cli -regtest -datadir=$BTC_DIR"
RPC=(--rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPCPORT")
T0=$(date +%s)
PIDS=(); MINER_PID=""; NODE_UP=0

stop_daemons() {
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null
    MINER_PID=""
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
    PIDS=()
}
cleanup() {
    stop_daemons
    if [ "$NODE_UP" = 1 ]; then
        $BCLI stop >/dev/null 2>&1
        for _ in $(seq 1 30); do $BCLI getblockcount >/dev/null 2>&1 || break; sleep 1; done
    fi
    [ "${KEEP_WORK:-0}" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
    red "FAIL: $*"
    [ -f "$WORK/lsp.log" ] && { echo "--- LSP log tail ---"; tail -15 "$WORK/lsp.log"; }
    exit 1
}
elapsed() { echo $(( $(date +%s) - T0 )); }
mine() { $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
# wait_for PATTERN FILE WHAT: until the pattern appears; fails if the LSP dies
wait_for() {
    while ! grep -qE "$1" "$2" 2>/dev/null; do
        [ "$(elapsed)" -gt "$DEADLINE" ] && fail "deadline ${DEADLINE}s while waiting for $3"
        if ! kill -0 "$LSP_PID" 2>/dev/null; then
            sleep 1
            grep -qE "$1" "$2" 2>/dev/null && break
            fail "LSP exited while waiting for $3"
        fi
        sleep 1
    done
    info "$(elapsed)s: $3"
}

# ---- private regtest node ----
cat > "$BTC_DIR/bitcoin.conf" <<EOF
regtest=1
server=1
txindex=1
listen=0
fallbackfee=0.00001
minrelaytxfee=$RELAY_FLOOR
blockmintxfee=$RELAY_FLOOR
rpcthreads=8
rpcworkqueue=1024
[regtest]
rpcport=$RPCPORT
rpcuser=$RU
rpcpassword=$RP
EOF
bitcoind -regtest -datadir="$BTC_DIR" -daemon >/dev/null || fail "bitcoind did not start"
NODE_UP=1
for _ in $(seq 1 90); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockcount >/dev/null 2>&1 || fail "bitcoind RPC not reachable on port $RPCPORT"
$BCLI -named createwallet wallet_name=$WALLET >/dev/null || fail "createwallet"
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 110
H0=$($BCLI getblockcount)

echo "=== large-tree unilateral exit: N=$N_CLIENTS arity=$ARITY static-near-root=$STATIC_NEAR_ROOT clients-per-leaf=$CLIENTS_PER_LEAF payments=$PAYMENTS ==="

# ---- LSP ----
LSPARGS=(--network regtest --port "$PORT" --clients "$N_CLIENTS" --arity "$ARITY"
    --amount "$AMOUNT" --active-blocks 3000 --dying-blocks 300
    --cltv-timeout $(( H0 + 3500 )) --step-blocks 5 --states-per-layer 2
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 --confirm-timeout 3600
    --max-conn-rate 400 --max-handshakes 80 --seckey "$LSP_SECKEY" "${RPC[@]}"
    --wallet "$WALLET" --db "$WORK/lsp.db" --payments "$PAYMENTS" --daemon)
[ "$STATIC_NEAR_ROOT" -gt 0 ] && LSPARGS+=(--static-near-root "$STATIC_NEAR_ROOT")
"$LSP_BIN" "${LSPARGS[@]}" > "$WORK/lsp.log" 2>&1 </dev/null &
LSP_PID=$!; PIDS+=("$LSP_PID")
for _ in $(seq 1 60); do
    grep -q "listening" "$WORK/lsp.log" 2>/dev/null && break
    kill -0 "$LSP_PID" 2>/dev/null || fail "LSP died before listening"
    sleep 1
done
grep -q "listening" "$WORK/lsp.log" || fail "LSP never listened"

# ---- clients: the payments run between the highest-numbered clients, which
#      sit on the highest-index leaves (pair j: N-2j pays N-2j-1) ----
declare -A ROLE
EXIT_IDS=()
for j in $(seq 0 $(( PAYMENTS - 1 ))); do
    S=$(( N_CLIENTS - 2 * j )); R=$(( S - 1 ))
    PRE=$(printf '%02x%062x' $(( 0x70 + j )) "$j")
    ROLE[$S]="send:$(( R - 1 )):$PRE"; ROLE[$R]="recv:$PRE"
    EXIT_IDS+=("$S" "$R")
done
for i in $(seq 1 "$N_CLIENTS"); do
    R="${ROLE[$i]:-idle}"
    case "$R" in
        send:*) D="${R#send:}"; EXTRA=(--channels --send "${D%%:*}:$PAY_AMT:${R##*:}") ;;
        recv:*) EXTRA=(--channels --recv "${R#recv:}") ;;
        *)      EXTRA=(--daemon) ;;
    esac
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$PORT" \
        --seckey "$(printf '%064x' $(( i + 1 )))" --fee-rate "$FEE_RATE" \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id "$i" \
        "${RPC[@]}" --wallet "$WALLET" --db "$WORK/c$i.db" "${EXTRA[@]}" \
        > "$WORK/c$i.log" 2>&1 </dev/null &
    PIDS+=($!)
    sleep 0.2
done
info "$(elapsed)s: $N_CLIENTS clients launched"
( while true; do mine 1; sleep 3; done ) & MINER_PID=$!

wait_for "nodes signed" "$WORK/lsp.log" "factory tree signed"
wait_for "channels ready" "$WORK/lsp.log" "channels ready"
wait_for "all $PAYMENTS payments processed" "$WORK/lsp.log" "$PAYMENTS payments processed"
wait_for "entering daemon mode" "$WORK/lsp.log" "LSP idle"
sleep 5

# ---- the LSP and every client process go away ----
stop_daemons
info "$(elapsed)s: all SuperScalar processes stopped (height $($BCLI getblockcount))"

# ---- shape of the tree and the exiting clients' paths ----
python3 - "$WORK" "$N_CLIENTS" "$CLIENTS_PER_LEAF" "${EXIT_IDS[@]}" <<'PY' || fail "tree shape / exit path precondition"
import sys, os, sqlite3
from collections import Counter
work, n, per_leaf = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]); ids = [int(x) for x in sys.argv[4:]]
def q(db, sql):
    c = sqlite3.connect("file:%s?mode=ro" % os.path.join(work, db), uri=True, timeout=30)
    r = c.execute(sql).fetchall(); c.close(); return r
bad = 0
nodes = q("lsp.db", "SELECT node_index, txid FROM tree_nodes WHERE factory_id=0")
chans = q("lsp.db", "SELECT slot, funding_txid FROM channels WHERE factory_id=0")
txids = {t for _, t in nodes}
print("  tree transactions: %d" % len(nodes))
if len(nodes) <= 128:
    print("  FAIL: the tree has %d transactions; this test needs more than 128" % len(nodes)); bad = 1
leaves = Counter(t for _, t in chans)
print("  channels: %d on %d leaf transactions; channels per leaf -> leaves: %s" % (
    len(chans), len(leaves), dict(sorted(Counter(leaves.values()).items()))))
if len(chans) != n or max(leaves.values()) != per_leaf or not set(leaves) <= txids:
    print("  FAIL: expected %d channels on tree leaves with up to %d channel(s) each" % (n, per_leaf)); bad = 1
with open(os.path.join(work, "exit_paths.txt"), "w") as out:
    for i in ids:
        db = "c%d.db" % i
        tree = {r[0]: (r[1], r[2]) for r in q(db, "SELECT node_index, parent_index, txid FROM tree_nodes WHERE factory_id=0")}
        by_txid = {v[1]: k for k, v in tree.items()}
        fund = q(db, "SELECT funding_txid FROM channels WHERE factory_id=0")
        com = q(db, "SELECT COUNT(*) FROM signed_commitments")[0][0]
        if len(fund) != 1 or fund[0][0] not in by_txid:
            print("  FAIL: client %d: the transaction funding its channel is not a tree node in its own DB (leaf replaced after the channel opened?)" % i); bad = 1; continue
        if com < 1:
            print("  FAIL: client %d holds no signed commitment" % i); bad = 1
        path = []; at = by_txid[fund[0][0]]
        while at is not None and at >= 0 and len(path) <= len(tree):
            path.append(at); at = tree[at][0]
        path.reverse()
        print("  client %d: %d tree nodes in its DB, exit path %s" % (i, len(tree), path))
        if len(tree) != len(nodes):
            print("  FAIL: client %d stores %d tree nodes, the LSP %d" % (i, len(tree), len(nodes))); bad = 1
        if max(path) < 128:
            print("  FAIL: client %d: no node with index >= 128 on its path" % i); bad = 1
        out.write("%d %s\n" % (i, " ".join(tree[k][1] for k in path)))
sys.exit(bad)
PY

commit_txid() {
    python3 - "$WORK/c$1.db" <<'PY' | $BCLI -stdin decoderawtransaction 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["txid"])'
import sys, sqlite3
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True, timeout=30)
print(c.execute("SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1").fetchone()[0])
PY
}
confs() { $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations", 0))' 2>/dev/null || echo 0; }

declare -A CTXID DONE_RC
for i in "${EXIT_IDS[@]}"; do
    CTXID[$i]=$(commit_txid "$i")
    [ ${#CTXID[$i]} -eq 64 ] || fail "client $i: cannot read its commitment txid"
done

# ---- unilateral exit: one --force-close pass per client per block ----
force_close() {   # client id -> exit status of one pass
    "$EXIT_CLIENT_BIN" --network regtest --cli-path bitcoin-cli "${RPC[@]}" \
        --force-close --db "$WORK/c$1.db" >> "$WORK/fc_c$1.log" 2>&1
    local rc=$?
    echo "--- end pass rc=$rc height $($BCLI getblockcount) ---" >> "$WORK/fc_c$1.log"
    return $rc
}
info "clients ${EXIT_IDS[*]} force-close, one pass per block"
ALL=0; TS_EXIT=$(date +%s)
for pass in $(seq 1 "$MAX_PASSES"); do
    [ "$(elapsed)" -gt "$DEADLINE" ] && fail "deadline ${DEADLINE}s during the exit (pass $pass)"
    for i in "${EXIT_IDS[@]}"; do
        force_close "$i"; rc=$?
        if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
            tail -12 "$WORK/fc_c$i.log"
            fail "client $i: force-close pass $pass exited $rc (0 = commitment accepted, 2 = in progress)"
        fi
        if [ $rc -eq 0 ] && [ "$($BCLI getrawtransaction "${CTXID[$i]}" 2>/dev/null | wc -c)" -lt 10 ]; then
            tail -12 "$WORK/fc_c$i.log"
            fail "client $i: force-close reported completion but its commitment is neither in the mempool nor on chain"
        fi
    done
    mine 1
    ALL=1
    for i in "${EXIT_IDS[@]}"; do [ "$(confs "${CTXID[$i]}")" -ge 1 ] || ALL=0; done
    [ "$ALL" = 1 ] && break
done
info "$(elapsed)s: exit loop ended after $pass pass(es), $(( $(date +%s) - TS_EXIT ))s (height $($BCLI getblockcount))"
if [ "$ALL" != 1 ]; then
    for i in "${EXIT_IDS[@]}"; do
        echo "--- client $i: commitment confirmations $(confs "${CTXID[$i]}") ---"; tail -8 "$WORK/fc_c$i.log"
    done
    fail "not every commitment confirmed within $MAX_PASSES passes"
fi
# once everything is confirmed a further pass reports completion
for i in "${EXIT_IDS[@]}"; do
    force_close "$i"; rc=$?
    [ $rc -eq 0 ] || { tail -12 "$WORK/fc_c$i.log"; fail "client $i: pass after confirmation exited $rc, want 0"; }
    tail -3 "$WORK/fc_c$i.log" | grep -q "CLIENT FORCE-CLOSE COMPLETE" || fail "client $i: no COMPLETE line"
done
mine 2

# ---- on-chain checks ----
python3 - "$WORK" "$BTC_DIR" "${EXIT_IDS[@]}" <<'PY'
import sys, os, json, sqlite3, subprocess
work, btc = sys.argv[1], sys.argv[2]; ids = [int(x) for x in sys.argv[3:]]
P2A = "51024e73"
bad = 0
def ok(m): print("  ok   " + m)
def fail(m):
    global bad
    bad += 1; print("  FAIL " + m)
def cli(*a, inp=None):
    r = subprocess.run(["bitcoin-cli", "-regtest", "-datadir=" + btc] + list(a), input=inp, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None
def q(db, sql):
    c = sqlite3.connect("file:%s?mode=ro" % os.path.join(work, db), uri=True, timeout=30)
    r = c.execute(sql).fetchall(); c.close(); return r
def sats(v): return int(round(v * 1e8))
def rawtx(t):
    r = cli("getrawtransaction", t, "1")
    return json.loads(r) if r else None

fid, ftxid, fvout, F = q("lsp.db", "SELECT id, funding_txid, funding_vout, funding_amount FROM factories ORDER BY id")[-1]
tree = {t: idx for idx, t in q("lsp.db", "SELECT node_index, txid FROM tree_nodes WHERE factory_id=0")}
paths = {}
for line in open(os.path.join(work, "exit_paths.txt")):
    p = line.split(); paths[int(p[0])] = p[1:]
want_on_chain = set(t for p in paths.values() for t in p)

# every exiting client: commitment confirmed, one output of exactly its balance
commits = {}
for i in ids:
    db = "c%d.db" % i
    bal = q(db, "SELECT local_amount FROM channels WHERE factory_id=0")[0][0]
    hx = q(db, "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1")[0][0]
    d = json.loads(cli("-stdin", "decoderawtransaction", inp=hx))
    tx = rawtx(d["txid"])
    if not tx or tx.get("confirmations", 0) < 1:
        fail("client %d: commitment %s not confirmed" % (i, d["txid"])); continue
    commits[d["txid"]] = tx
    if tx["vin"][0]["txid"] != paths[i][-1]:
        fail("client %d: commitment does not spend its leaf" % i)
    outs = [sats(o["value"]) for o in tx["vout"] if o["scriptPubKey"]["hex"] != P2A]
    if bal in outs:
        ok("client %d: commitment %s confirmed (%d conf), to_local = %d sat = its balance; path max node index %d" % (
            i, d["txid"][:16], tx["confirmations"], bal, max(tree[t] for t in paths[i])))
    else:
        fail("client %d: commitment outputs %s, none equals its balance %d" % (i, outs, bal))

# which tree transactions are on chain
on_chain = {}
for t in tree:
    tx = rawtx(t)
    if tx and tx.get("confirmations", 0) >= 1: on_chain[t] = tx
if set(on_chain) == want_on_chain:
    ok("%d of %d tree transactions are on chain: exactly the exiting clients' own paths (%d of them with index >= 128)" % (
        len(on_chain), len(tree), sum(1 for t in on_chain if tree[t] >= 128)))
else:
    extra = sorted(tree[t] for t in set(on_chain) - want_on_chain)
    missing = sorted(tree[t] for t in want_on_chain - set(on_chain))
    fail("tree transactions on chain differ from the exit paths: off-path nodes %s, missing path nodes %s" % (extra, missing))

# conservation over the factory funding
ftx = rawtx(ftxid)
if not ftx or sats(ftx["vout"][fvout]["value"]) != F:
    fail("factory funding output on chain does not match funding_amount %d" % F)
known = dict(on_chain); known.update(commits)
h0 = json.loads(cli("getblockheader", ftx["blockhash"]))["height"]
spender = {}
for h in range(h0, int(cli("getblockcount")) + 1):
    for tx in json.loads(cli("getblock", cli("getblockhash", str(h)), "2"))["tx"]:
        for vin in tx["vin"]:
            if "txid" in vin: spender[(vin["txid"], vin["vout"])] = tx["txid"]
fees = unspent = anchors = n_unspent = 0
for t, tx in known.items():
    inv = 0
    for vin in tx["vin"]:
        if (vin["txid"], vin["vout"]) == (ftxid, fvout): inv += F
        elif vin["txid"] in known: inv += sats(known[vin["txid"]]["vout"][vin["vout"]]["value"])
        else: fail("transaction %s has an input from outside the factory" % t)
    fees += inv - sum(sats(o["value"]) for o in tx["vout"])
    for o in tx["vout"]:
        s = spender.get((t, o["n"])); v = sats(o["value"])
        if s is None:
            unspent += v; n_unspent += 1
        elif s not in known:
            if o["scriptPubKey"]["hex"] == P2A: anchors += v
            else: fail("output %s:%d (%d sat) was spent by %s, which is neither a tree node nor an exiting client's commitment" % (t, o["n"], v, s))
if spender.get((ftxid, fvout)) not in known:
    fail("the factory funding output was not spent by the tree root")
total = unspent + fees + anchors
if total == F and fees >= 0:
    ok("conservation: %d sat in %d unspent factory outputs + %d sat fees + %d sat anchors = funding %d sat" % (unspent, n_unspent, fees, anchors, F))
else:
    fail("conservation: unspent %d + fees %d + anchors %d = %d, funding %d" % (unspent, fees, anchors, total, F))
sys.exit(1 if bad else 0)
PY
RC=$?
if [ $RC -eq 0 ]; then
    green "PASS: ${#EXIT_IDS[@]} clients on the highest-index leaves of a $N_CLIENTS-client factory exited alone; total $(elapsed)s"
    exit 0
fi
for i in "${EXIT_IDS[@]}"; do echo "--- fc_c$i tail ---"; tail -6 "$WORK/fc_c$i.log"; done
red "FAIL: on-chain checks failed"
exit 1
