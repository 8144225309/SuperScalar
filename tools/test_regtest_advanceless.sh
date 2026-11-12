#!/usr/bin/env bash
# test_regtest_advanceless.sh — the advanceless default tree, end to end.
#
# Real daemons on regtest: one LSP started WITHOUT any shape option (so it
# builds the advanceless default: every interior level static, one member per
# pseudo-Spilman leaf) and N clients, for each N in N_LIST (default "4 64").
#
#   lifecycle   the default shape is built and signed; payments flow both
#               ways, then round a ring through every member; the LSP is
#               killed and restarted on its DB mid-way, and one client is
#               killed and restarted too; payments flow both ways again, and
#               round the ring the other way; then every daemon is killed and
#               EACH member exits alone from its own DB (--force-close), one
#               after the other.
#   expiry      a second factory; one payment; every daemon is killed; the
#               chain is mined to the distribution TX's nLockTime and a member
#               publishes that TX from its own DB.
#   rollover_refused  --demo --test-tier-b-rollover on the default tree: the
#               LSP must refuse the root rollover and run no Tier B.
#
# Checks:
#   - the LSP logs the advanceless default shape and ewt 0; its tree_nodes
#     rows have no relative lock (every state row and every static kickoff
#     at nSequence 0xfffffffe, every leaf kickoff at 0xffffffff), the
#     expected node count (N=4: 9, N=64: 137), and N pseudo-Spilman leaves;
#   - no advance, root tick or rollover is proposed or refused anywhere;
#   - every payment settles; after the restarts the LSP and the clients reload
#     the signed tree (no "refusing to load"), and the restarted LSP serves
#     payments again;
#   - balances: each member's balance in its DB equals its creation balance
#     plus what it received minus what it sent, and the LSP's DB agrees;
#   - exit: each member's latest commitment spends a leaf of its signed tree,
#     confirms, and pays that member exactly its balance; every transaction
#     on the member's path from the root is the signed one and is on chain;
#   - an LSP started on a copy of that DB with the factory's static depth
#     lost refuses to load it and exits 1 instead of starting a new factory;
#     with that factory marked closed it starts and waits for a new one;
#   - expiry: every member holds the same distribution TX; it confirms once
#     its nLockTime is reached and pays every member at least its creation
#     balance (the members' outputs add up to the factory funding less the
#     distribution fee and the anchor).
#
# The members publish the distribution TX themselves: here the script sends
# the signed TX stored in a member's DB (distribution_txs).  Without a
# client-side publisher the member needs that step done for it.
#
# The test starts its own bitcoind (private datadir and RPC port, default
# relay policy) and stops it on exit.
#
# Usage: bash tools/test_regtest_advanceless.sh [BUILD_DIR]
#   BUILD_DIR    holds superscalar_lsp / superscalar_client (argument,
#                $BUILD_DIR, or ./build)
#   N_LIST       member counts to run (default "4 64")
#   SCENARIOS    any of "lifecycle expiry rollover_refused" (default: all)
#   BITCOIND, BITCOIN_CLI   binaries (default: bitcoind / bitcoin-cli in PATH)
#   RPCPORT      RPC port of the private bitcoind (default 18761)
#   PORT         base LSP port (default 30611)
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
N_LIST="${N_LIST:-4 64}"
SCENARIOS="${SCENARIOS:-lifecycle expiry rollover_refused}"
RPCPORT="${RPCPORT:-18761}"
PORT="${PORT:-30611}"
RU=rpcuser
RP=rpcpass
WALLET=ss_advanceless
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

for b in "$LSP_BIN" "$CLIENT_BIN"; do
    [ -x "$b" ] || { echo "FAIL: missing binary $b"; exit 1; }
done
for t in "$BITCOIND" "$BITCOIN_CLI" sqlite3 python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "FAIL: $t not found"; exit 1; }
done

TMPD=$(mktemp -d "${WORK_ROOT:-${TMPDIR:-/tmp}}/ss-advanceless.XXXXXX")
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
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LPORT" \
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
    if ! waitlog "$D/lsp1.log" "entering daemon mode" 900; then
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

check_shape(){
    local log=$D/lsp1.log db=$D/lsp.db
    local line; line=$(grep -a "tree shape: advanceless default for $N clients" "$log" | head -1)
    if [ -n "$line" ]; then note_ok "LSP default shape: ${line#*for }"
    else note_fail "LSP did not log the advanceless default shape"; fi
    grep -aq "shape ewt = 0 blocks" "$log" && note_ok "shape ewt = 0 blocks" \
        || note_fail "shape ewt is not 0"
    local nodes bad ps want=""
    nodes=$(sqlite3 "$db" "SELECT COUNT(*) FROM tree_nodes;")
    bad=$(sqlite3 "$db" "SELECT COUNT(*) FROM tree_nodes WHERE NOT ((type='state' AND nsequence=4294967294) OR (type='kickoff' AND nsequence IN (4294967294, 4294967295)));")
    ps=$(sqlite3 "$db" "SELECT COUNT(*) FROM tree_nodes WHERE type='state';")
    case "$N" in 4) want=9 ;; 64) want=137 ;; esac
    if [ -z "$want" ] || [ "$nodes" = "$want" ]; then note_ok "signed tree: $nodes nodes"
    else note_fail "signed tree has $nodes nodes, expected $want"; fi
    [ "$bad" = 0 ] && note_ok "no transaction in the tree carries a relative lock" \
        || note_fail "$bad tree node(s) with a relative lock"
    [ "$ps" = "$N" ] && note_ok "$ps leaf states, one per member" \
        || note_fail "$ps leaf states for $N members"
}

check_db_balances(){
    local i got lsp_view n_bad=0
    for i in $(seq 0 $((N - 1))); do
        got=$(sqlite3 "$D/c$i.db" "SELECT local_amount FROM channels LIMIT 1;")
        lsp_view=$(sqlite3 "$D/lsp.db" "SELECT remote_amount FROM channels WHERE slot=$i;")
        if [ "$got" != "${BAL[$i]}" ] || [ "$lsp_view" != "${BAL[$i]}" ]; then
            note_fail "member $i balance: own DB $got, LSP DB $lsp_view, expected ${BAL[$i]}"
            n_bad=$((n_bad + 1))
        fi
    done
    [ "$n_bad" = 0 ] && note_ok "every member's balance (own DB and LSP DB) = creation balance + received - sent"
}

no_advance_anywhere(){
    local hits
    hits=$(cat "$D"/*.log 2>/dev/null | grep -acE "LEAF_ADVANCE_PROPOSE|STATE_ADVANCE|Tier B|rolled over|DW advanced to epoch|refused: this factory has no Decker-Wattenhofer")
    [ "$hits" = 0 ] && note_ok "no advance, root tick or rollover proposed or refused (all logs)" \
        || note_fail "$hits advance/rollover line(s) in the logs"
    hits=$(cat "$D"/*.log 2>/dev/null | grep -acE "refusing to load|is not the signed tree")
    [ "$hits" = 0 ] && note_ok "every reload rebuilt the signed tree" \
        || note_fail "a reload refused the tree ($hits line(s))"
}

# exit_member <i>: member i force-closes alone from its DB until its latest
# commitment confirms, then the commitment is checked against its balance.
exit_member(){
    local i=$1 db=$D/c$i.db pass hex ctxid in leaf c=0 v shape
    hex=$(sqlite3 "$db" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;")
    leaf=$(sqlite3 "$db" "SELECT funding_txid || ':' || funding_vout FROM channels LIMIT 1;")
    [ -n "$hex" ] || { note_fail "member $i has no signed commitment"; return; }
    ctxid=$(txinfo "$hex" txid); in=$(txinfo "$hex" in)
    if [ "$in" != "$leaf" ] || [ "$(sqlite3 "$db" "SELECT COUNT(*) FROM tree_nodes WHERE txid='${leaf%%:*}';")" != 1 ]; then
        note_fail "member $i commitment spends $in, its channel is $leaf (signed leaf: no)"
        return
    fi
    for pass in $(seq 1 60); do
        "$CLIENT_BIN" --network regtest --cli-path "$BITCOIN_CLI" "${RPC_ARGS[@]}" \
            --force-close --db "$db" >> "$D/fc_c$i.log" 2>&1
        mine 1
        c=$(confs "$ctxid"); [ "${c:-0}" -ge 1 ] && break
    done
    if [ "${c:-0}" -lt 1 ]; then
        note_fail "member $i commitment never confirmed ($pass passes)"
        $BCLI testmempoolaccept "[\"$hex\"]" | tr -d '\n ' | sed 's/^/         /'; echo
        return
    fi
    local j=$(sqlite3 "$db" "SELECT node_index FROM tree_nodes WHERE txid='${leaf%%:*}';") off=0 t
    while [ -n "$j" ] && [ "$j" -ge 0 ] 2>/dev/null; do
        t=$(sqlite3 "$db" "SELECT txid FROM tree_nodes WHERE node_index=$j;")
        [ "$(confs "$t")" -ge 1 ] || off=$((off + 1))
        j=$(sqlite3 "$db" "SELECT parent_index FROM tree_nodes WHERE node_index=$j;")
    done
    local remote; remote=$(sqlite3 "$db" "SELECT remote_amount FROM channels LIMIT 1;")
    v=$(txinfo "$hex" pays "${BAL[$i]}"); shape=$(txinfo "$hex" shape "${BAL[$i]}" "$remote")
    if [ "$off" = 0 ] && [ "${v:--1}" -ge 0 ] && [ "$shape" = ok ]; then
        EXIT_OK=$((EXIT_OK + 1))
    else
        note_fail "member $i exit: $off path tx(s) off chain; commitment outputs: ${shape:-?} (balance ${BAL[$i]})"
    fi
}

run_lifecycle(){
    echo; echo "--- N=$N lifecycle (defaults, restarts, every member exits alone) ---"
    local h; h=$(height)
    create_factory "$TMPD/life$N" $((PORT + 2 * N)) --cltv-timeout $((h + 3000)) \
        --active-blocks 2500 --dying-blocks 400 || { kill_procs; return; }
    check_shape
    local last=$((N - 1)) mid=$((N / 2))
    pay lsp1.log 0 1 5000
    pay lsp1.log 1 0 2100
    pay lsp1.log "$last" "$mid" 3300
    pay lsp1.log "$mid" "$last" 1200
    # a ring through every member before the restart: a member that has
    # never received an update holds no commitment to exit with and no LSP
    # per-commitment point to check a later one against
    ring lsp1.log 1000 1
    sleep 5

    # restart the LSP (SIGKILL, recovery from its DB)
    kill -9 "$LSP_PID"; wait "$LSP_PID" 2>/dev/null; sleep 2
    start_lsp lsp2.log
    if waitlog "$D/lsp2.log" "entering recovery mode" 60; then note_ok "LSP restarted from its DB"
    else tail -20 "$D/lsp2.log"; note_fail "restarted LSP did not recover"; kill_procs; return; fi
    if waitlog "$D/lsp2.log" "reconnected" 300 "$N"; then note_ok "all $N members reconnected to the restarted LSP"
    else note_fail "only $(grep -ac reconnected "$D/lsp2.log") of $N members reconnected"; fi
    sleep 3
    pay lsp2.log 1 0 1700
    pay lsp2.log 0 1 900
    # restart one member (reconnect from its DB)
    kill -9 "${CPID[1]}"; wait "${CPID[1]}" 2>/dev/null; sleep 1
    local nrec; nrec=$(grep -aFc "client 1 reconnected" "$D/lsp2.log")
    start_client 1
    if waitlog "$D/lsp2.log" "client 1 reconnected" 120 $((nrec + 1)); then note_ok "member 1 restarted and reconnected"
    else note_fail "member 1 did not reconnect after its restart"; fi
    sleep 3
    pay lsp2.log 1 "$last" 2600
    pay lsp2.log "$last" 1 800
    # and the other way round after the restarts, so every member's latest
    # commitment is one signed against the reloaded tree
    ring lsp2.log 2000 -1
    sleep 8
    kill_procs
    check_db_balances
    no_advance_anywhere

    # every member exits alone, one after the other
    EXIT_OK=0
    local i
    for i in $(seq 0 $((N - 1))); do exit_member "$i"; done
    [ "$EXIT_OK" = "$N" ] && note_ok "all $N members exited alone: each commitment confirmed and pays its member exactly its balance" \
        || note_fail "$EXIT_OK of $N members exited with their balance"

    # an LSP whose DB holds a factory it cannot load as the signed tree
    # (here: its static depth lost) must stop, not start a new factory
    cp "$D/lsp.db" "$D/lsp_bad.db"
    sqlite3 "$D/lsp_bad.db" "UPDATE factories SET static_threshold_depth = 0;"
    local bad_args=("${LSP_ARGS[@]}") k rc
    for k in "${!bad_args[@]}"; do
        [ "${bad_args[$k]}" = "$D/lsp.db" ] && bad_args[$k]="$D/lsp_bad.db"
        [ "${bad_args[$k]}" = "--cli" ] && unset 'bad_args[k]'
    done
    timeout 60 "$LSP_BIN" "${bad_args[@]}" > "$D/lsp_bad.log" 2>&1 < /dev/null; rc=$?
    if [ "$rc" = 1 ] && grep -aq "cannot be loaded (see above); refusing to start" "$D/lsp_bad.log" &&
       grep -aq "is not the signed tree" "$D/lsp_bad.log" &&
       ! grep -aq "waiting for $N clients" "$D/lsp_bad.log"; then
        note_ok "an LSP whose factory does not reload as the signed tree stops (rc=1) instead of starting a new one"
    else
        tail -8 "$D/lsp_bad.log" | sed 's/^/         /'
        note_fail "LSP with an unloadable factory: rc=$rc"
    fi
    # the same factory marked closed is history: the LSP starts a new one
    sqlite3 "$D/lsp_bad.db" "UPDATE factories SET state = 'closed';"
    # (it then waits for clients; SIGKILL after 20 s: rc 137)
    timeout -s KILL 20 "$LSP_BIN" "${bad_args[@]}" > "$D/lsp_closed.log" 2>&1 < /dev/null; rc=$?
    if [ "$rc" = 137 ] && grep -aq "closed factory in .* is not loaded" "$D/lsp_closed.log" &&
       grep -aq "waiting for $N clients" "$D/lsp_closed.log"; then
        note_ok "a closed factory that does not reload is history: the LSP starts and waits for a new factory"
    else
        tail -8 "$D/lsp_closed.log" | sed 's/^/         /'
        note_fail "LSP with an unloadable closed factory: rc=$rc"
    fi
}

run_expiry(){
    echo; echo "--- N=$N expiry (the distribution TX pays the members) ---"
    local h; h=$(height)
    create_factory "$TMPD/exp$N" $((PORT + 2 * N + 1)) --cltv-timeout $((h + 400)) \
        --active-blocks 200 --dying-blocks 150 || { kill_procs; return; }
    check_shape
    pay lsp1.log 0 1 4000
    sleep 8
    kill_procs
    local i hex txid0="" same=0 lt
    for i in $(seq 0 $((N - 1))); do
        hex=$(sqlite3 "$D/c$i.db" "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id=0;")
        [ -n "$hex" ] || continue
        [ -z "$txid0" ] && txid0=$(txinfo "$hex" txid)
        [ "$(txinfo "$hex" txid)" = "$txid0" ] && same=$((same + 1))
    done
    [ "$same" = "$N" ] && note_ok "all $N members hold the same signed distribution TX ${txid0:0:16}..." \
        || { note_fail "$same of $N members hold the distribution TX"; return; }
    hex=$(sqlite3 "$D/c0.db" "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id=0;")
    lt=$(txinfo "$hex" locktime)
    if $BCLI sendrawtransaction "$hex" >/dev/null 2>&1; then
        note_fail "distribution TX accepted before its nLockTime $lt"
    else
        note_ok "distribution TX not final before block $lt"
    fi
    h=$(height); [ "$h" -lt "$lt" ] && mine $((lt - h))
    local sent; sent=$($BCLI sendrawtransaction "$hex" 2>&1)
    mine 1
    if [ "$(confs "$txid0")" -ge 1 ]; then note_ok "member 0 published the distribution TX at block $lt; it confirmed"
    else note_fail "distribution TX did not confirm: $sent"; return; fi
    local -a outs; mapfile -t outs < <(txinfo "$hex" outs)
    local funding fee_total low=0
    funding=$(sqlite3 "$D/lsp.db" "SELECT funding_amount FROM factories WHERE id=0;")
    [ "${#outs[@]}" = "$N" ] && note_ok "$N member outputs" || note_fail "${#outs[@]} member outputs for $N members"
    for i in $(seq 0 $((N - 1))); do
        [ "${outs[$i]:-0}" -ge "${INIT[$i]}" ] || low=$((low + 1))
    done
    [ "$low" = 0 ] && note_ok "every member is paid at least its creation balance ($(txinfo "$hex" outsum) of $funding sats to members)" \
        || note_fail "$low member(s) paid less than their creation balance"
}

run_rollover_refused(){
    echo; echo "--- N=$N --test-tier-b-rollover on the default tree (refused) ---"
    D="$TMPD/tierb$N"; LPORT=$((PORT + 2 * N + 300)); mkdir -p "$D"
    "$LSP_BIN" --network regtest --port "$LPORT" --clients "$N" \
        --amount $(( N * 100000 + 300000 )) --fee-rate 1000 --lsp-balance-pct 50 \
        --confirm-timeout 900 --max-conn-rate 100000 --max-handshakes 256 \
        --seckey "$LSP_SECKEY" "${RPC_ARGS[@]}" --wallet "$WALLET" \
        --db "$D/lsp.db" --demo --test-tier-b-rollover > "$D/lsp1.log" 2>&1 &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    waitlog "$D/lsp1.log" "listening" 60 || { note_fail "LSP never listened"; kill_procs; return; }
    local i rc
    for i in $(seq 0 $((N - 1))); do start_client "$i"; sleep 0.1; done
    start_miner
    for _ in $(seq 1 600); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 1; done
    wait "$LSP_PID"; rc=$?
    kill_procs
    if [ "$rc" != 0 ] && grep -aq "TIER B ROLLOVER TEST: REFUSED" "$D/lsp1.log" &&
       grep -aq "refused: this factory has no Decker-Wattenhofer state layer" "$D/lsp1.log" &&
       ! grep -aqE "Tier B ceremony|rolled over to epoch" "$D/lsp1.log"; then
        note_ok "the LSP refused the root rollover with the rotation message and ran no Tier B (rc=$rc)"
    else
        tail -15 "$D/lsp1.log" | sed 's/^/         /'
        note_fail "--test-tier-b-rollover was not refused (rc=$rc)"
    fi
}

for N in $N_LIST; do
    for s in $SCENARIOS; do
        case "$s" in
            lifecycle) run_lifecycle ;;
            expiry)    run_expiry ;;
            rollover_refused) run_rollover_refused ;;
            *) echo "unknown scenario $s"; FAILS=$((FAILS + 1)) ;;
        esac
    done
done

echo
if [ "$FAILS" -eq 0 ]; then
    echo "=== PASS: advanceless default tree (N = $N_LIST): built, paid, restarted, every member exited alone; the distribution TX paid the members ==="
    exit 0
fi
echo "=== FAIL: $FAILS check(s) failed ==="
exit 1
