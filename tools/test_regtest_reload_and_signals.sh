#!/usr/bin/env bash
# test_regtest_reload_and_signals.sh -- a refused reload stops the member, a
# stored signature is checked on reload, and SIGTERM stops the LSP.
#
# Real daemons on regtest, N = 4 members:
#
#   member_reload_refused  a member whose stored factory does not match its
#       signed tree (the shape lost) must stop with a non-zero exit and one
#       clear message, not retry the reload every second.
#   stored_signature  one byte of a stored tree signature is changed (the
#       txid does not cover the witness): the LSP and a member must refuse to
#       load that factory instead of finding the bad signature at broadcast
#       time.
#   term_waiting  SIGTERM to an LSP that waits for its members to connect, and
#       to one that waits for a silent member during the factory ceremony,
#       must end it at once with exit 1 and a database that holds no factory.
#
# The test starts its own bitcoind (private datadir and RPC port, default relay
# policy) and stops it on exit.
#
# Usage: bash tools/test_regtest_reload_and_signals.sh [BUILD_DIR]
#   BUILD_DIR    holds superscalar_lsp / superscalar_client (argument,
#                $BUILD_DIR, or ./build)
#   SCENARIOS    any of "member_reload_refused stored_signature term_waiting"
#   BITCOIND, BITCOIN_CLI   binaries (default: bitcoind / bitcoin-cli in PATH)
#   RPCPORT      RPC port of the private bitcoind (default 18771)
#   PORT         base LSP port (default 30711)
#   WORK_ROOT    parent of the work directory (default ${TMPDIR:-/tmp})
#   KEEP_TMP=1   keep the work directory
#
# Requires sqlite3 and python3 in PATH.
#   SCENARIOS    any of "lifecycle expiry rollover_refused" (default: all)
#   BITCOIND, BITCOIN_CLI   binaries (default: bitcoind / bitcoin-cli in PATH)
#   RPCPORT      RPC port of the private bitcoind (default 18771)
#   PORT         base LSP port (default 30711)
#   WORK_ROOT    parent of the work directory (default ${TMPDIR:-/tmp})
#   KEEP_TMP=1   keep the work directory
#
# Requires sqlite3 and python3 in PATH.
set -uo pipefail

BUILD_DIR="${1:-${BUILD_DIR:-build}}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
RPCPORT="${RPCPORT:-18771}"
PORT="${PORT:-30711}"
RU=rpcuser
RP=rpcpass
WALLET=ss_reload_sig
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

for b in "$LSP_BIN" "$CLIENT_BIN"; do
    [ -x "$b" ] || { echo "FAIL: missing binary $b"; exit 1; }
done
for t in "$BITCOIND" "$BITCOIN_CLI" sqlite3 python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "FAIL: $t not found"; exit 1; }
done

TMPD=$(mktemp -d "${WORK_ROOT:-${TMPDIR:-/tmp}}/ss-reload-sig.XXXXXX")
BTC_DIR="$TMPD/bitcoind"
mkdir -p "$BTC_DIR"
BCLI="$BITCOIN_CLI -regtest -datadir=$BTC_DIR -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPCPORT"
RPC_ARGS=(--rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPCPORT")

PIDS=()
MINER_PID=""
FAILS=0
kill_procs(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null
    MINER_PID=""
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
    PIDS=()
    exec 3>&- 2>/dev/null
    wait 2>/dev/null
}
cleanup(){
    kill_procs
    $BCLI stop >/dev/null 2>&1
    for _ in $(seq 1 20); do $BCLI getblockcount >/dev/null 2>&1 || break; sleep 1; done
    if [ "${KEEP_TMP:-0}" = 1 ] || [ "$FAILS" -gt 0 ]; then
        echo "work directory kept: $TMPD"
    else
        rm -rf "$TMPD"
    fi
}
trap cleanup EXIT

note_ok(){ printf '  ok   %s\n' "$*"; }
note_fail(){ printf '  FAIL %s\n' "$*"; FAILS=$((FAILS + 1)); }
mine(){ $BCLI generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
start_miner(){ ( while true; do mine 1; sleep 3; done ) & MINER_PID=$!; }
stop_miner(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null; wait "$MINER_PID" 2>/dev/null; MINER_PID=""; }
height(){ $BCLI getblockcount; }
sk(){ printf "%064x" $(( $1 + 2 )); }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations",0))' 2>/dev/null || echo 0; }

# txinfo <rawhex> <field> [args]: txid | in | locktime | pays <sats> |
#   shape <local> <remote> ("ok" for exactly {client <local> on its own
#   taproot script, the rest of <local>+<remote>, one P2A anchor}) |
#   outs (non-anchor output amounts, one per line) | outsum
txinfo(){
    $BCLI decoderawtransaction "$1" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin); f = sys.argv[1]
outs = [(int(round(o["value"] * 1e8)), o["scriptPubKey"]["hex"],
         o["scriptPubKey"].get("type", "")) for o in d["vout"]]
A = "51024e73"
if f == "txid": print(d["txid"])
elif f == "in": print("%s:%d" % (d["vin"][0]["txid"], d["vin"][0]["vout"]))
elif f == "locktime": print(d["locktime"])
elif f == "pays":
    w = int(sys.argv[2]); h = [i for i, o in enumerate(outs) if o[0] == w and o[1] != A]
    print(h[0] if h else -1)
elif f == "outs":
    for o in outs:
        if o[1] != A: print(o[0])
elif f == "outsum": print(sum(o[0] for o in outs if o[1] != A))
elif f == "shape":
    local, remote = int(sys.argv[2]), int(sys.argv[3])
    mine = [o for o in outs if o[0] == local and o[1] != A]
    p = []
    if len(outs) != 3: p.append("%d outputs, expected 3" % len(outs))
    if sum(1 for o in outs if o[1] == A) != 1: p.append("anchor count")
    if len(mine) != 1: p.append("%d outputs of %d sats" % (len(mine), local))
    if sum(o[0] for o in outs) != local + remote:
        p.append("outputs sum %d, balances %d" % (sum(o[0] for o in outs), local + remote))
    if len(mine) == 1 and (mine[0][2] != "witness_v1_taproot" or
                           sum(1 for o in outs if o[1] == mine[0][1]) != 1):
        p.append("client output not its own taproot script")
    print("ok" if not p else "; ".join(p))
' "${@:2}" 2>/dev/null
}

# --- private regtest node (default relay policy) --------------------------
"$BITCOIND" -regtest -datadir="$BTC_DIR" -daemon -server=1 -txindex=1 -listen=0 \
    -rpcuser=$RU -rpcpassword=$RP -rpcport="$RPCPORT" -fallbackfee=0.00001 >/dev/null \
    || { echo "FAIL: could not start bitcoind"; exit 1; }
for _ in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockcount >/dev/null 2>&1 || { echo "FAIL: bitcoind RPC not reachable on port $RPCPORT"; exit 1; }
echo "bitcoind: $("$BITCOIND" --version | head -1)"
$BCLI -named createwallet wallet_name=$WALLET >/dev/null 2>&1
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 101

# ---- per-run state ----
D=""; N=0; LPORT=0; LSP_PID=""; FIFO=""; PAY_QUIET=0
declare -a CPID INIT BAL
LSP_ARGS=()

waitlog(){   # waitlog <file> <fixed string> <seconds> [count]
    local f=$1 pat=$2 t=$3 want=${4:-1} n
    for _ in $(seq 1 "$t"); do
        n=$(grep -aFc -- "$pat" "$f" 2>/dev/null); n=${n:-0}
        [ "$n" -ge "$want" ] && return 0
        sleep 1
    done
    return 1
}
start_lsp(){
    stdbuf -oL "$LSP_BIN" "${LSP_ARGS[@]}" < "$FIFO" >> "$D/$1" 2>&1 &
    LSP_PID=$!
    PIDS+=("$LSP_PID")
}
start_client(){
    local i=$1
    stdbuf -oL "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LPORT" \
        --seckey "$(sk "$i")" --fee-rate 1000 --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUB" --participant-id $((i + 1)) "${RPC_ARGS[@]}" \
        --wallet "$WALLET" --db "$D/c$i.db" --daemon >> "$D/c$i.log" 2>&1 &
    CPID[$i]=$!
    PIDS+=("${CPID[$i]}")
}
cli(){ echo "$1" >&3; }
# pay <log> <from> <to> <sats>: client <from> pays client <to> through the LSP.
pay(){
    local log=$1 a=$2 b=$3 amt=$4
    local marker="Payment complete: client $a -> client $b ($amt sats)"
    local before; before=$(grep -aFc -- "$marker" "$D/$log" 2>/dev/null); before=${before:-0}
    cli "pay $a $b $amt"
    if waitlog "$D/$log" "$marker" 120 $((before + 1)); then
        BAL[$a]=$(( BAL[$a] - amt )); BAL[$b]=$(( BAL[$b] + amt ))
        [ "$PAY_QUIET" = 1 ] || note_ok "payment client $a -> client $b ($amt sats) settled"
    else
        note_fail "payment client $a -> client $b ($amt sats) did not settle"
        tail -5 "$D/$log" | sed 's/^/         /'
    fi
}

# ring <log> <base sats> <step>: member i pays member i+step (mod N),
# base+i sats, for every i.
ring(){
    local log=$1 base=$2 step=$3 i before=$FAILS
    PAY_QUIET=1
    for i in $(seq 0 $((N - 1))); do
        pay "$log" "$i" $(( (i + step + N) % N )) $((base + i))
    done
    PAY_QUIET=0
    [ "$FAILS" = "$before" ] && note_ok "ring of $N payments (member i pays member i$( [ "$step" -gt 0 ] && echo + )$step) settled"
}

# create_factory <dir> <port> <extra lsp args...>: LSP with no shape option,
# N clients, factory live.  Returns 1 when the factory never went live.
create_factory(){
    D=$1; LPORT=$2; shift 2
    mkdir -p "$D"
    FIFO="$D/lsp.fifo"; rm -f "$FIFO"; mkfifo "$FIFO"; exec 3<>"$FIFO"
    LSP_ARGS=(--network regtest --port "$LPORT" --clients "$N"
        --amount $(( N * 100000 + 300000 )) --fee-rate 1000 --lsp-balance-pct 50
        --confirm-timeout 900 --max-conn-rate 100000 --max-handshakes 256
        --seckey "$LSP_SECKEY" "${RPC_ARGS[@]}" --wallet "$WALLET"
        --db "$D/lsp.db" --daemon --cli "$@")
    start_lsp lsp1.log
    waitlog "$D/lsp1.log" "listening" 60 || { tail -20 "$D/lsp1.log"; note_fail "LSP never listened"; return 1; }
    local i
    for i in $(seq 0 $((N - 1))); do start_client "$i"; sleep 0.1; done
    start_miner
    local live=0
    for _ in $(seq 1 900); do
        grep -aq "entering daemon mode" "$D/lsp1.log" && { live=1; break; }
        kill -0 "$LSP_PID" 2>/dev/null || break   # the LSP refused or failed
        sleep 1
    done
    if [ "$live" != 1 ]; then
        tail -30 "$D/lsp1.log"; note_fail "N=$N: factory never went live"; return 1
    fi
    note_ok "N=$N: factory live with $N members"
    sleep 5
    for i in $(seq 0 $((N - 1))); do
        INIT[$i]=$(sqlite3 "$D/lsp.db" "SELECT remote_amount FROM channels WHERE slot=$i;")
        BAL[$i]=${INIT[$i]}
    done
    return 0
}


# ---- scenarios -------------------------------------------------------------
N=4

# a factory with one payment, then every daemon killed: $D holds the DBs
make_factory(){
    local port=$1 h
    h=$(height)
    create_factory "$TMPD/f$port" "$port" --cltv-timeout $((h + 2900 + 600)) \
        --active-blocks 2500 --dying-blocks 400 || return 1
    pay lsp1.log 0 1 5000
    sleep 4
    kill_procs
    return 0
}

# a consistent copy of a DB that was last written by a killed process
copy_db(){ rm -f "$2" "$2-wal" "$2-shm"; sqlite3 "$1" ".backup '$2'"; }

client_args(){   # client_args <i> <db> <port>
    echo --network regtest --host 127.0.0.1 --port "$3" --seckey "$(sk "$1")" \
        --fee-rate 1000 --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" \
        --participant-id $(( $1 + 1 )) "${RPC_ARGS[@]}" --wallet "$WALLET" \
        --db "$2" --daemon
}

# lsp_on_db <db> <log> <seconds>: the LSP on a copy of the factory's DB, run
# for at most <seconds> (then SIGKILL); echoes its exit code.
lsp_on_db(){
    local db=$1 log=$2 secs=$3 a=() k
    a=("${LSP_ARGS[@]}")
    for k in "${!a[@]}"; do
        [ "${a[$k]}" = "$D/lsp.db" ] && a[$k]="$db"
        [ "${a[$k]}" = "--cli" ] && unset 'a[k]'
    done
    timeout -s KILL "$secs" "$LSP_BIN" "${a[@]}" > "$log" 2>&1 < /dev/null
    echo $?
}

run_member_reload_refused(){
    echo; echo "--- member whose reload is refused stops ---"
    make_factory $((PORT + 1)) || return
    local db=$D/c0_bad.db rc n
    copy_db "$D/c0.db" "$db"
    sqlite3 "$db" "UPDATE factories SET static_threshold_depth = 0;"
    # nothing listens on this port: only the reload decides what happens
    timeout -s KILL 25 "$CLIENT_BIN" $(client_args 0 "$db" $((PORT + 90))) > "$D/c0_bad.log" 2>&1 < /dev/null
    rc=$?
    n=$(grep -ac "is not the signed tree" "$D/c0_bad.log")
    if [ "$rc" = 1 ] && [ "$n" -ge 1 ] && [ "$n" -le 2 ] &&
       grep -aq "stored factory was refused" "$D/c0_bad.log"; then
        note_ok "the member stopped with exit 1 after its reload was refused ($n refusal line(s))"
    else
        tail -6 "$D/c0_bad.log" | sed 's/^/         /'
        note_fail "member with a refused reload: rc=$rc, $n refusal line(s) (it must stop, not retry)"
    fi
}

# corrupt_sig <db> <node_index>: change one byte of the node's stored
# signature (the 64 bytes before the 4-byte nLockTime).
corrupt_sig(){
    python3 - "$1" "$2" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
h, = db.execute("SELECT signed_tx_hex FROM tree_nodes WHERE factory_id=0 AND node_index=?",
                (int(sys.argv[2]),)).fetchone()
pos = len(h) - 8 - 64 * 2 + 10          # inside the signature
c = "0" if h[pos] != "0" else "1"
db.execute("UPDATE tree_nodes SET signed_tx_hex=? WHERE factory_id=0 AND node_index=?",
           (h[:pos] + c + h[pos + 1:], int(sys.argv[2])))
db.commit()
PY
}

run_stored_signature(){
    echo; echo "--- a changed stored signature is refused on reload ---"
    make_factory $((PORT + 2)) || return
    local rc node
    # control: the untouched DB loads
    rc=$(lsp_on_db "$D/lsp.db" "$D/lsp_ok.log" 20)
    if [ "$rc" = 137 ] && grep -aq "entering recovery mode" "$D/lsp_ok.log"; then
        note_ok "control: the LSP loads the untouched factory"
    else tail -5 "$D/lsp_ok.log"; note_fail "control: LSP on the untouched DB, rc=$rc"; fi
    for node in 0 3; do
        copy_db "$D/lsp.db" "$D/lsp_sig$node.db"
        corrupt_sig "$D/lsp_sig$node.db" "$node"
        rc=$(lsp_on_db "$D/lsp_sig$node.db" "$D/lsp_sig$node.log" 20)
        if [ "$rc" = 1 ] && grep -aq "signature" "$D/lsp_sig$node.log" &&
           ! grep -aq "entering recovery mode" "$D/lsp_sig$node.log"; then
            note_ok "the LSP refuses a factory whose node $node signature was changed (rc=1)"
        else
            tail -6 "$D/lsp_sig$node.log" | sed 's/^/         /'
            note_fail "LSP on a DB with a changed node $node signature: rc=$rc"
        fi
        copy_db "$D/c0.db" "$D/c0_sig$node.db"
        corrupt_sig "$D/c0_sig$node.db" "$node"
        timeout -s KILL 20 "$CLIENT_BIN" $(client_args 0 "$D/c0_sig$node.db" $((PORT + 91))) \
            > "$D/c0_sig$node.log" 2>&1 < /dev/null
        rc=$?
        if [ "$rc" = 1 ] && grep -aq "signature" "$D/c0_sig$node.log"; then
            note_ok "a member refuses a factory whose node $node signature was changed (rc=1)"
        else
            tail -6 "$D/c0_sig$node.log" | sed 's/^/         /'
            note_fail "member on a DB with a changed node $node signature: rc=$rc"
        fi
    done
}

# term_check <rc> <log> <db> <label>: the LSP got SIGTERM and must be gone
term_check(){
    local rc=$1 log=$2 db=$3 label=$4 integ nf
    if [ "$rc" = 1 ]; then note_ok "$label: SIGTERM ended the LSP with exit 1"
    else tail -5 "$log" | sed 's/^/         /'; note_fail "$label: exit $rc after SIGTERM (137 = it ignored SIGTERM and was killed)"; fi
    if [ -f "$db" ]; then
        integ=$(sqlite3 "$db" "PRAGMA integrity_check;" 2>&1)
        nf=$(sqlite3 "$db" "SELECT COUNT(*) FROM factories;" 2>/dev/null)
        [ "$integ" = ok ] && [ "${nf:-0}" = 0 ] && note_ok "$label: the DB is intact and holds no factory" \
            || note_fail "$label: integrity '$integ', $nf factory row(s)"
    else
        note_ok "$label: no DB written"
    fi
}

# wait_exit <pid> <seconds>: sets WRC to the exit status; 137 when the
# process was still running after <seconds> and had to be killed
WRC=0
wait_exit(){
    local pid=$1 t=$2
    for _ in $(seq 1 "$t"); do
        kill -0 "$pid" 2>/dev/null || { wait "$pid"; WRC=$?; return; }
        sleep 1
    done
    kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    WRC=137
}

run_term_waiting(){
    echo; echo "--- SIGTERM stops an LSP that waits for its members ---"
    D="$TMPD/term"; mkdir -p "$D"; LPORT=$((PORT + 3))
    local rc i args=(--network regtest --port "$LPORT" --clients "$N"
        --amount $(( N * 100000 + 300000 )) --fee-rate 1000 --lsp-balance-pct 50
        --confirm-timeout 900 --max-conn-rate 100000 --max-handshakes 256
        --seckey "$LSP_SECKEY" "${RPC_ARGS[@]}" --wallet "$WALLET" --daemon)
    # 1. no member has connected
    stdbuf -oL "$LSP_BIN" "${args[@]}" --db "$D/a.db" > "$D/a.log" 2>&1 < /dev/null &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    waitlog "$D/a.log" "waiting for $N clients" 30 || note_fail "LSP never waited for its members"
    kill -TERM "$LSP_PID"
    wait_exit "$LSP_PID" 10; rc=$WRC
    term_check "$rc" "$D/a.log" "$D/a.db" "waiting for the first member"
    # 2. two of four connected, the others never come
    LPORT=$((PORT + 4))
    args[3]=$LPORT
    stdbuf -oL "$LSP_BIN" "${args[@]}" --db "$D/b.db" > "$D/b.log" 2>&1 < /dev/null &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    waitlog "$D/b.log" "waiting for $N clients" 30 || note_fail "LSP never waited for its members"
    start_client 0; start_client 1
    sleep 6
    kill -TERM "$LSP_PID"
    wait_exit "$LSP_PID" 10; rc=$WRC
    term_check "$rc" "$D/b.log" "$D/b.db" "two of four members connected"
    kill_procs
    # 3. all connected, one member is silent during the ceremony
    D="$TMPD/term2"; mkdir -p "$D"; LPORT=$((PORT + 5))
    args[3]=$LPORT
    stdbuf -oL "$LSP_BIN" "${args[@]}" --db "$D/c.db" > "$D/c.log" 2>&1 < /dev/null &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    waitlog "$D/c.log" "waiting for $N clients" 30 || note_fail "LSP never waited for its members"
    for i in 0 1 2 3; do start_client "$i"; sleep 0.1; done
    start_miner
    waitlog "$D/c.log" "all $N clients connected" 60 || note_fail "members did not connect"
    kill -STOP "${CPID[3]}"
    sleep 25
    kill -TERM "$LSP_PID"
    wait_exit "$LSP_PID" 15; rc=$WRC
    kill -CONT "${CPID[3]}" 2>/dev/null
    term_check "$rc" "$D/c.log" "$D/c.db" "a silent member during the factory ceremony"
    kill_procs
}

for s in ${SCENARIOS:-member_reload_refused stored_signature term_waiting}; do
    case "$s" in
        member_reload_refused) run_member_reload_refused ;;
        stored_signature)      run_stored_signature ;;
        term_waiting)          run_term_waiting ;;
        *) echo "unknown scenario $s"; FAILS=$((FAILS + 1)) ;;
    esac
done

echo
if [ "$FAILS" -eq 0 ]; then
    echo "=== PASS: a refused reload stops the member, a changed stored signature is refused on reload, SIGTERM stops a waiting LSP ==="
    exit 0
fi
echo "=== FAIL: $FAILS check(s) failed ==="
exit 1
