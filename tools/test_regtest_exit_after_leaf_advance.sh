#!/usr/bin/env bash
# test_regtest_exit_after_leaf_advance.sh — unilateral client exit after the
# LSP has advanced a leaf over the wire (regtest, real daemons).
#
# One LSP and N_CLIENTS client processes build a factory and run the LSP's
# demo payments. The LSP then drives one leaf advance on leaf 0 through the
# wire ceremony (--test-wire-leaf-advance). With ADVANCE=1 the clients are
# started with --test-allow-tree-advance and co-sign it; with ADVANCE=0 they
# are not, refuse it, and nothing advances (the control). As soon as the LSP
# reports the outcome, every SuperScalar process is killed, before the LSP
# can close the factory. Each client then runs `superscalar_client
# --force-close` from its own DB, one pass per block.
#
# Checks: the factory funding output is still unspent when the exit starts;
# with ADVANCE=1 the leaf really advanced in the clients' DBs; every client's
# latest commitment confirms with an output of exactly its channel balance;
# the last force-close pass exits 0. The run reports, per client, the exit
# status of every pass, which tree transactions reached the chain and where
# the exit stopped if it did not finish.
#
# The script starts its own bitcoind (regtest, txindex) in a scratch directory
# and stops it again. Its config lowers the relay floor (minrelaytxfee and
# blockmintxfee, to RELAY_FLOOR = 0.1 sat/vB): a client commitment pays less
# than Bitcoin Core's default 1 sat/vB floor and would not relay otherwise.
#
# Usage: bash tools/test_regtest_exit_after_leaf_advance.sh [BUILD_DIR]
# Env:   ARITY (3: one client per pseudo-Spilman leaf; 1: one client per DW
#        leaf)  ADVANCE (1)  N_CLIENTS (2)  MAX_PASSES (60)
#        PORT (29985) RPCPORT (18753) DEADLINE (900 s)
#        RELAY_FLOOR (0.000001 BTC/kvB)  WORK_DIR (mktemp)
#        BTC_DIR ($WORK_DIR/bitcoind)  KEEP_WORK (0)
set -uo pipefail

BUILD_DIR="${1:-build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

ARITY="${ARITY:-3}"
ADVANCE="${ADVANCE:-1}"
N_CLIENTS="${N_CLIENTS:-2}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
FEE_RATE="${FEE_RATE:-1000}"
PORT="${PORT:-29985}"
RPCPORT="${RPCPORT:-18753}"
DEADLINE="${DEADLINE:-900}"
MAX_PASSES="${MAX_PASSES:-60}"
RELAY_FLOOR="${RELAY_FLOOR:-0.000001}"
RU=rpcuser; RP=rpcpass
WALLET=exit_after_advance
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { echo "[exit-after-advance] $*"; }

for b in "$LSP_BIN" "$CLIENT_BIN"; do
    [ -x "$b" ] || { red "FAIL: $b not found (build first)"; exit 1; }
done
for t in bitcoind bitcoin-cli python3; do
    command -v "$t" >/dev/null || { red "FAIL: $t not in PATH"; exit 1; }
done

WORK="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/ss-exit-after-advance.XXXXXX")}"
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

cat > "$BTC_DIR/bitcoin.conf" <<EOF
regtest=1
server=1
txindex=1
listen=0
fallbackfee=0.00001
minrelaytxfee=$RELAY_FLOOR
blockmintxfee=$RELAY_FLOOR
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

echo "=== exit after leaf advance: arity=$ARITY advance=$ADVANCE clients=$N_CLIENTS ==="

"$LSP_BIN" --network regtest --port "$PORT" --clients "$N_CLIENTS" --arity "$ARITY" \
    --amount "$AMOUNT" --active-blocks 3000 --dying-blocks 300 \
    --cltv-timeout $(( H0 + 3500 )) --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" "${RPC[@]}" --wallet "$WALLET" --db "$WORK/lsp.db" \
    --demo --test-wire-leaf-advance > "$WORK/lsp.log" 2>&1 </dev/null &
LSP_PID=$!; PIDS+=("$LSP_PID")
for _ in $(seq 1 60); do
    grep -q "listening" "$WORK/lsp.log" 2>/dev/null && break
    kill -0 "$LSP_PID" 2>/dev/null || fail "LSP died before listening"
    sleep 1
done
grep -q "listening" "$WORK/lsp.log" || fail "LSP never listened"

ALLOW=(); [ "$ADVANCE" = 1 ] && ALLOW=(--test-allow-tree-advance)
for i in $(seq 1 "$N_CLIENTS"); do
    "$CLIENT_BIN" "${ALLOW[@]}" --network regtest --host 127.0.0.1 --port "$PORT" \
        --seckey "$(printf '%064x' $(( i + 1 )))" --fee-rate "$FEE_RATE" \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id "$i" \
        "${RPC[@]}" --wallet "$WALLET" --db "$WORK/c$i.db" --daemon \
        > "$WORK/c$i.log" 2>&1 </dev/null &
    PIDS+=($!)
    sleep 0.2
done
( while true; do mine 1; sleep 2; done ) & MINER_PID=$!

# The LSP closes the factory right after its tests: stop everything the
# moment the advance outcome is reported.
while ! grep -qE "POST-DAEMON WIRE LEAF ADVANCE: (PASS|FAIL)" "$WORK/lsp.log" 2>/dev/null; do
    [ "$(elapsed)" -gt "$DEADLINE" ] && fail "deadline ${DEADLINE}s waiting for the leaf advance"
    kill -0 "$LSP_PID" 2>/dev/null || fail "LSP exited before the leaf advance"
    sleep 0.2
done
stop_daemons
ADV_LINE=$(grep -oE "POST-DAEMON WIRE LEAF ADVANCE: (PASS|FAIL)[^=]*" "$WORK/lsp.log" | head -1)
info "$(elapsed)s: LSP reported '$ADV_LINE'; all SuperScalar processes stopped (height $($BCLI getblockcount))"
if [ "$ADVANCE" = 1 ]; then
    echo "$ADV_LINE" | grep -q PASS || fail "the leaf advance did not complete"
else
    echo "$ADV_LINE" | grep -q FAIL || fail "the clients did not refuse the leaf advance"
fi

# ---- state before the exit ----
python3 - "$WORK" "$BTC_DIR" "$N_CLIENTS" "$ADVANCE" > "$WORK/before.txt" <<'PY'
import sys, os, json, sqlite3, subprocess
work, btc, n, adv = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "1"
def cli(*a, inp=None):
    r = subprocess.run(["bitcoin-cli", "-regtest", "-datadir=" + btc] + list(a), input=inp, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None
def q(db, sql):
    c = sqlite3.connect("file:%s?mode=ro" % os.path.join(work, db), uri=True, timeout=30)
    try: return c.execute(sql).fetchall()
    except Exception as e: return "ERR " + str(e)
    finally: c.close()
fid, ftxid, fvout = q("lsp.db", "SELECT id, funding_txid, funding_vout FROM factories ORDER BY id")[-1]
print("FUNDING %s:%d unspent=%s" % (ftxid, fvout, "yes" if cli("gettxout", ftxid, str(fvout)) else "NO"))
for i in range(1, n + 1):
    db = "c%d.db" % i
    tree = {r[1]: r[0] for r in q(db, "SELECT node_index, txid FROM tree_nodes")}
    ch = q(db, "SELECT funding_txid, funding_vout, local_amount FROM channels")
    sc = q(db, "SELECT commitment_number, signed_tx_hex FROM signed_commitments")
    ps = q(db, "SELECT COUNT(*) FROM ps_leaf_chains")
    pi = q(db, "SELECT COUNT(*) FROM ps_initial_signed_states")
    prev = None
    if sc and not isinstance(sc, str):
        d = json.loads(cli("-stdin", "decoderawtransaction", inp=sc[0][1]))
        prev = d["vin"][0]["txid"]; ctxid = d["txid"]
    else:
        ctxid = None
    fund = ch[0][0] if ch else None
    print("CLIENT %d channel.funding=%s(in tree: %s) commitment cn=%s txid=%s spends=%s(in tree: %s) balance=%s ps_leaf_chains=%s ps_initial=%s" % (
        i, (fund or "-")[:16], "node %d" % tree[fund] if fund in tree else "NO",
        sc[0][0] if sc and not isinstance(sc, str) else "-", (ctxid or "-")[:16], (prev or "-")[:16],
        "node %d" % tree[prev] if prev in tree else "NO", ch[0][2] if ch else "-", ps, pi))
    print("COMMIT %d %s %s" % (i, ctxid or "-", ch[0][2] if ch else 0))
PY
cat "$WORK/before.txt" | grep -v '^COMMIT'
grep -q "^FUNDING .*unspent=yes" "$WORK/before.txt" || fail "the factory funding output was already spent before the exit"

# ---- each client exits alone, one pass per block ----
declare -A CTXID BAL CODES
while read -r _ i t b; do CTXID[$i]=$t; BAL[$i]=$b; done < <(grep '^COMMIT' "$WORK/before.txt")
confs() { $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations", 0))' 2>/dev/null || echo 0; }
ALL=0
for pass in $(seq 1 "$MAX_PASSES"); do
    for i in $(seq 1 "$N_CLIENTS"); do
        [ "$(confs "${CTXID[$i]}")" -ge 1 ] && continue
        "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli "${RPC[@]}" \
            --force-close --db "$WORK/c$i.db" >> "$WORK/fc_c$i.log" 2>&1
        rc=$?
        CODES[$i]="${CODES[$i]:-} $rc"
        echo "--- end pass $pass rc=$rc height $($BCLI getblockcount) ---" >> "$WORK/fc_c$i.log"
    done
    mine 1
    ALL=1
    for i in $(seq 1 "$N_CLIENTS"); do [ "$(confs "${CTXID[$i]}")" -ge 1 ] || ALL=0; done
    [ "$ALL" = 1 ] && break
done
for i in $(seq 1 "$N_CLIENTS"); do
    "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli "${RPC[@]}" \
        --force-close --db "$WORK/c$i.db" >> "$WORK/fc_c$i.log" 2>&1
    rc=$?
    CODES[$i]="${CODES[$i]:-} final:$rc"
done
mine 2

# ---- result ----
python3 - "$WORK" "$BTC_DIR" "$N_CLIENTS" <<'PY' > "$WORK/result.txt"
import sys, os, json, sqlite3, subprocess, re
work, btc, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
P2A = "51024e73"
def cli(*a, inp=None):
    r = subprocess.run(["bitcoin-cli", "-regtest", "-datadir=" + btc] + list(a), input=inp, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None
def q(db, sql):
    c = sqlite3.connect("file:%s?mode=ro" % os.path.join(work, db), uri=True, timeout=30)
    r = c.execute(sql).fetchall(); c.close(); return r
def conf(t):
    r = cli("getrawtransaction", t, "1")
    return json.loads(r).get("confirmations", 0) if r else -1
lsp_tree = {t: i for i, t in q("lsp.db", "SELECT node_index, txid FROM tree_nodes")}
for t, pos, node in q("lsp.db", "SELECT txid, chain_pos, leaf_node_idx FROM ps_leaf_chains"):
    lsp_tree.setdefault(t, "%d/chain%d" % (node, pos + 1))
for t, node in q("lsp.db", "SELECT txid, node_idx FROM ps_initial_signed_states"):
    lsp_tree.setdefault(t, "%d/chain0" % node)
on = sorted(str(v) for t, v in lsp_tree.items() if conf(t) >= 1)
print("TREE_ON_CHAIN %s" % (" ".join(on) or "none"))
bad = 0
for i in range(1, n + 1):
    db = "c%d.db" % i
    bal = q(db, "SELECT local_amount FROM channels")[0][0]
    hx = q(db, "SELECT signed_tx_hex FROM signed_commitments")[0][0]
    d = json.loads(cli("-stdin", "decoderawtransaction", inp=hx))
    c = conf(d["txid"]); prev = d["vin"][0]["txid"]
    outs = []
    tx = cli("getrawtransaction", d["txid"], "1")
    if tx: outs = [int(round(o["value"] * 1e8)) for o in json.loads(tx)["vout"] if o["scriptPubKey"]["hex"] != P2A]
    log = open(os.path.join(work, "fc_c%d.log" % i), errors="replace").read()
    last = [l for l in log.splitlines() if re.search(r"Force-close:|CLIENT FORCE-CLOSE|sendrawtransaction error|rejected|ERROR", l)]
    tail = " | ".join(dict.fromkeys(last[-8:]))
    ok = c >= 1 and bal in outs
    bad += not ok
    print("CLIENT %d commitment %s confirmations=%d spends %s (leaf on chain: %s, LSP knows it as node %s) to_local==balance(%d): %s" % (
        i, d["txid"][:16], c, prev[:16], "yes" if conf(prev) >= 1 else "no", lsp_tree.get(prev, "UNKNOWN"), bal, "yes" if bal in outs else "no"))
    print("CLIENT %d last force-close lines: %s" % (i, tail[:900]))
sys.exit(1 if bad else 0)
PY
RC=$?
cat "$WORK/result.txt"
for i in $(seq 1 "$N_CLIENTS"); do echo "CLIENT $i force-close exit codes:${CODES[$i]}"; done
FINAL_OK=1
for i in $(seq 1 "$N_CLIENTS"); do echo "${CODES[$i]}" | grep -q "final:0$" || FINAL_OK=0; done
if [ $RC -eq 0 ] && [ $FINAL_OK = 1 ]; then
    green "PASS: arity $ARITY, advance=$ADVANCE: every client exited alone with its balance; total $(elapsed)s"
    exit 0
fi
red "FAIL: arity $ARITY, advance=$ADVANCE: not every client exited with its balance and a final exit status 0"
exit 1
