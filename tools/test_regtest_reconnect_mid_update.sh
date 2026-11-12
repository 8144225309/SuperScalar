#!/usr/bin/env bash
# test_regtest_reconnect_mid_update.sh -- a member that disconnects in the
# middle of a channel update reconnects and the update is finished.
#
# Real daemons on regtest, N = 4 members.  A payment 0 -> 1 reaches the LSP's
# forward to member 1; member 1 is killed (under gdb) just before it sends the
# revocation that completes the exchange, so the LSP's forward is half
# finished.  Member 1 is then restarted and reconnects:
#
#   - the LSP puts the forward back to the state in its database if it does
#     not complete, and replays it (the HTLC amount on the wire is msat);
#   - member 1 takes the HTLC, fulfils it, and the payment settles;
#   - afterwards both sides hold the same commitment number and balances, and
#     payments flow both ways through member 1 again.
#
# The test starts its own bitcoind (private datadir and RPC port, default relay
# policy) and stops it on exit.
#
# Usage: bash tools/test_regtest_reconnect_mid_update.sh [BUILD_DIR]
#   BUILD_DIR    holds superscalar_lsp / superscalar_client (argument,
#                $BUILD_DIR, or ./build)
#   BITCOIND, BITCOIN_CLI   binaries (default: bitcoind / bitcoin-cli in PATH)
#   RPCPORT      RPC port of the private bitcoind (default 18781)
#   PORT         base LSP port (default 30811)
#   WORK_ROOT    parent of the work directory (default ${TMPDIR:-/tmp})
#   KEEP_TMP=1   keep the work directory
#
# Requires sqlite3, python3 and gdb in PATH (the test is skipped without gdb).
#   SCENARIOS    any of "lifecycle expiry rollover_refused" (default: all)
#   BITCOIND, BITCOIN_CLI   binaries (default: bitcoind / bitcoin-cli in PATH)
#   RPCPORT      RPC port of the private bitcoind (default 18781)
#   PORT         base LSP port (default 30811)
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
RPCPORT="${RPCPORT:-18781}"
PORT="${PORT:-30811}"
RU=rpcuser
RP=rpcpass
WALLET=ss_midupd
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

for b in "$LSP_BIN" "$CLIENT_BIN"; do
    [ -x "$b" ] || { echo "FAIL: missing binary $b"; exit 1; }
done
for t in "$BITCOIND" "$BITCOIN_CLI" sqlite3 python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "FAIL: $t not found"; exit 1; }
done

TMPD=$(mktemp -d "${WORK_ROOT:-${TMPDIR:-/tmp}}/ss-midupd.XXXXXX")
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


# ---- scenario --------------------------------------------------------------
N=4

# start_client_gdb <i>: member i under gdb; it dies just before its first
# REVOKE_AND_ACK (message type 0x33) goes out.
start_client_gdb(){
    local i=$1
    stdbuf -oL gdb -q -batch -ex "set pagination off" \
        -ex "break wire_send if (\$rsi & 0xff) == 0x33" \
        -ex run -ex "echo GDB-HIT-RAA\n" -ex kill -ex quit \
        --args "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LPORT" \
        --seckey "$(sk "$i")" --fee-rate 1000 --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUB" --participant-id $((i + 1)) "${RPC_ARGS[@]}" \
        --wallet "$WALLET" --db "$D/c$i.db" --daemon >> "$D/c$i.log" 2>&1 &
    CPID[$i]=$!
    PIDS+=("${CPID[$i]}")
}

command -v gdb >/dev/null 2>&1 || { echo "SKIP: gdb not found"; exit 0; }

h=$(height)
create_factory "$TMPD/mid" $((PORT + 1)) --cltv-timeout $((h + 2900 + 600)) \
    --active-blocks 2500 --dying-blocks 400 || { echo "=== FAIL: no factory ==="; exit 1; }
pay lsp1.log 0 1 5000
pay lsp1.log 1 2 1000
sleep 3

# member 1 restarts under gdb
kill -9 "${CPID[1]}"; wait "${CPID[1]}" 2>/dev/null; sleep 1
nrec=$(grep -aFc "client 1 reconnected" "$D/lsp1.log")
start_client_gdb 1
if waitlog "$D/lsp1.log" "client 1 reconnected" 120 $((nrec + 1)); then note_ok "member 1 reconnected under gdb"
else note_fail "member 1 did not reconnect under gdb"; fi
sleep 2

# the payment: the LSP forwards to member 1, which dies before its revocation
cli "pay 0 1 1500"
for _ in $(seq 1 60); do grep -aq GDB-HIT-RAA "$D/c1.log" && break; sleep 1; done
if grep -aq GDB-HIT-RAA "$D/c1.log"; then note_ok "member 1 died just before its revocation"
else note_fail "member 1 never reached its revocation"; fi
waitlog "$D/lsp1.log" "pay FAILED" 60 || note_fail "the LSP did not give up the half-finished forward"
sleep 2

# member 1 comes back
nrec=$(grep -aFc "client 1 reconnected" "$D/lsp1.log")
start_client 1
if waitlog "$D/lsp1.log" "client 1 reconnected" 120 $((nrec + 1)); then note_ok "member 1 reconnected after the half-finished update"
else tail -8 "$D/lsp1.log" | sed 's/^/         /'; note_fail "member 1 was not taken back"; fi

if waitlog "$D/lsp1.log" "replayed HTLC to client 1 (amount=1500" 60; then
    note_ok "the LSP replayed the forward (1500 sat)"
else
    tail -8 "$D/lsp1.log" | sed 's/^/         /'
    note_fail "the forward was not replayed"
fi
if waitlog "$D/c1.log" "fulfilling HTLC" 60 2; then note_ok "member 1 took the replayed HTLC and fulfilled it"
else tail -6 "$D/c1.log" | sed 's/^/         /'; note_fail "member 1 did not fulfil the replayed HTLC"; fi
sleep 5

# both sides agree, and the channel works both ways
l=$(sqlite3 "$D/lsp.db" "SELECT commitment_number || ':' || remote_amount FROM channels WHERE slot=1;")
c=$(sqlite3 "$D/c1.db" "SELECT commitment_number || ':' || local_amount FROM channels;")
if [ "$l" = "$c" ]; then note_ok "LSP and member 1 hold the same commitment and balance ($l)"
else note_fail "LSP says $l, member 1 says $c"; fi
pay lsp1.log 0 1 1000
pay lsp1.log 1 0 1200
pay lsp1.log 2 1 1100
sleep 3
kill_procs
l=$(sqlite3 "$D/lsp.db" "SELECT commitment_number || ':' || remote_amount FROM channels WHERE slot=1;")
c=$(sqlite3 "$D/c1.db" "SELECT commitment_number || ':' || local_amount FROM channels;")
[ "$l" = "$c" ] && note_ok "after three more payments both sides still agree ($l)" \
    || note_fail "after three more payments: LSP says $l, member 1 says $c"

echo
if [ "$FAILS" -eq 0 ]; then
    echo "=== PASS: a member that died in the middle of an update reconnected, the update was finished, and the channel works ==="
    exit 0
fi
echo "=== FAIL: $FAILS check(s) failed ==="
exit 1
