#!/usr/bin/env bash
# test_regtest_idle_client_exit.sh — a client that has never sent or received a
# payment can still leave its channel alone.
#
# One LSP daemon and four client daemons build a factory on the default leaf
# type and open their channels.  Then every SuperScalar process is killed and
# each client runs --force-close from nothing but its own database: it
# publishes the factory tree down to its leaf and then its own commitment.
#
#   scenario "idle"  : no payment is ever made.  Every client must already hold
#                      a signed commitment 0 when its channel becomes usable.
#                      Client 4 is also killed and restarted before the LSP
#                      disappears: it must reconnect from its database with
#                      that commitment unchanged.
#   scenario "mixed" : client 1 pays client 2 once; clients 3 and 4 stay idle.
#                      The two that transacted exit with their latest
#                      commitment, which requires that the settled payment
#                      left the leaf transaction funding their channels
#                      unchanged.
#   scenario "rotate": client 1 pays client 2, then the factory reaches the
#                      end of its (short) active period and the LSP rotates
#                      it.  Nobody transacts in the new factory.  Every
#                      client must hold a signed commitment 0 for its channel
#                      in the NEW factory, carrying its balance, and exit
#                      with it.
#   scenario "rotate_stopped": the LSP dies during a rotation after the new
#                      tree is signed but before any client has commitment 0
#                      of its new channel (SUPERSCALAR_CRASH_AT checkpoint
#                      rotate_channel_setup).  Every client must report that
#                      the rotation did not complete and exit non-zero, and
#                      refuse to start again.  Its database must hold the
#                      new factory as a pending record with its distribution
#                      transaction, next to the untouched old factory and
#                      commitment, and its --force-close must NOT publish
#                      the new factory's tree.  No exit is attempted.
#   scenario "reconnect": client 4 is restarted right after channel open,
#                      then pays and is paid.  Both payments must succeed and
#                      the client must stay up (commitment 0 took nonce index
#                      0 on both sides; the pools are exchanged afresh on
#                      reconnect).  No exit is attempted in this scenario.
#
# Checked in the exit scenarios, for all four clients:
#   - a signed commitment is in the client database before the kill, and for a
#     client that never transacted it is commitment number 0;
#   - the commitment confirms and spends the client's channel funding output;
#   - output 0 (to_local) equals the client's balance in its own database and
#     the balance the LSP recorded for that channel;
#   - every transaction that spends a factory output is a signed tree node or
#     one of the four commitments, and the factory funding amount equals the
#     unspent outputs plus the fees paid plus anchors consumed by fee bumps.
#
# RELAY FEE.  The test starts its own bitcoind (regtest, private datadir, own
# RPC port) with minrelaytxfee and blockmintxfee lowered to 0.5 sat/vB.  This
# matters: a commitment transaction pays a fixed 154 sat and is about 167 vB,
# which is BELOW the default 1 sat/vB minimum relay fee.  Under default relay
# policy an idle client's commitment is therefore not relayed on its own; it
# can only confirm together with a fee-paying child that spends its anchor.
# Giving the exit path that child (and sizing the tree's fees) is a separate
# change to the tree and commitment fees; it is not part of what this test
# covers, and this test would fail on a node with the default relay floor.
#
# Usage: bash tools/test_regtest_idle_client_exit.sh [BUILD_DIR]
# Env:   SCENARIOS ("idle mixed rotate rotate_stopped reconnect")  RPCPORT (18543)
#        PORT (29961)  KEEP (0)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${1:-$(dirname "$SCRIPT_DIR")/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
SCENARIOS="${SCENARIOS:-idle mixed rotate rotate_stopped reconnect}"
RPCPORT="${RPCPORT:-18543}"
PORT="${PORT:-29961}"
KEEP="${KEEP:-0}"

N=4
AMOUNT=400000
FEE=1000
PAY_AMT=10000
PREIMAGE=$(printf '%02x%062x' 0x70 0)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
WALLET="idle_exit"

for b in "$LSP_BIN" "$CLIENT_BIN"; do [ -x "$b" ] || { echo "FAIL: $b not found"; exit 1; }; done
for t in bitcoind bitcoin-cli sqlite3 python3; do command -v $t >/dev/null || { echo "FAIL: $t not on PATH"; exit 1; }; done

TMP=$(mktemp -d /tmp/ss-idle-exit.XXXXXX)
BTC="$TMP/btc"; mkdir -p "$BTC"
RPC=(--rpcuser rpcuser --rpcpassword rpcpass --rpcport "$RPCPORT")
BCLI=(bitcoin-cli -regtest -datadir="$BTC" -rpcport="$RPCPORT" -rpcuser=rpcuser -rpcpassword=rpcpass)
MINER_PID=""; PIDS=()

green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
stop_miner(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null; MINER_PID=""; }
kill_ss(){ stop_miner; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; PIDS=(); { exec 9>&-; } 2>/dev/null; sleep 2; }
# cli_pay <lsp log> <from> <to> <sats>: payment through the LSP's --cli (0-based client indexes)
cli_pay(){
    local before; before=$(grep -c "CLI: pay succeeded" "$1")
    echo "pay $2 $3 $4" >&9
    for _ in $(seq 1 60); do
        sleep 1
        [ "$(grep -c "CLI: pay succeeded" "$1")" -gt "$before" ] && return 0
    done
    return 1
}
bal_of(){ sqlite3 "file:$1?mode=ro" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null; }
cleanup(){
    kill_ss
    "${BCLI[@]}" stop >/dev/null 2>&1
    for _ in $(seq 1 20); do [ -f "$BTC/regtest/bitcoind.pid" ] || break; sleep 1; done
    if [ "$KEEP" = 1 ]; then echo "logs and databases kept in $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT
mine(){ "${BCLI[@]}" -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }

# ---- private regtest node ----
{ echo regtest=1; echo server=1; echo txindex=1; echo listen=0
  echo rpcuser=rpcuser; echo rpcpassword=rpcpass; echo fallbackfee=0.00001
  echo minrelaytxfee=0.000005; echo blockmintxfee=0.000005
  echo "[regtest]"; echo "rpcport=$RPCPORT"; } > "$BTC/bitcoin.conf"
bitcoind -regtest -datadir="$BTC" -daemon >/dev/null || { echo "FAIL: bitcoind did not start"; exit 1; }
for _ in $(seq 1 60); do "${BCLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
"${BCLI[@]}" getblockcount >/dev/null 2>&1 || { echo "FAIL: bitcoind RPC not reachable on port $RPCPORT"; exit 1; }
"${BCLI[@]}" -named createwallet wallet_name=$WALLET >/dev/null
MINE_ADDR=$("${BCLI[@]}" -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 110

wait_log(){ # pattern file seconds what
    for _ in $(seq 1 "$3"); do
        grep -qE "$1" "$2" 2>/dev/null && return 0
        kill -0 "$LSP_PID" 2>/dev/null || { grep -qE "$1" "$2" 2>/dev/null && return 0; echo "  LSP exited while waiting for $4"; return 1; }
        sleep 1
    done
    echo "  timeout waiting for $4"; return 1
}

run_scenario(){
    local SC=$1 P=$2 D="$TMP/$1"
    mkdir -p "$D"
    echo
    case "$SC" in
        idle)      echo "=== scenario 'idle': LSP + $N clients, no payments ===" ;;
        mixed)     echo "=== scenario 'mixed': LSP + $N clients, client 1 pays client 2, clients 3 and 4 idle ===" ;;
        rotate)    echo "=== scenario 'rotate': LSP + $N clients, one payment, factory rotation, then exit from the new factory ===" ;;
        rotate_stopped) echo "=== scenario 'rotate_stopped': LSP + $N clients, the LSP dies mid-rotation before commitment 0 ===" ;;
        reconnect) echo "=== scenario 'reconnect': LSP + $N clients, client 4 restarted after open, then payments ===" ;;
        *)         echo "unknown scenario '$SC'"; return 1 ;;
    esac
    local H0; H0=$("${BCLI[@]}" getblockcount)
    local ACTIVE=3000
    { [ "$SC" = rotate ] || [ "$SC" = rotate_stopped ]; } && ACTIVE=45
    local LSPARGS=(--network regtest --port "$P" --clients $N --amount $AMOUNT
        --active-blocks $ACTIVE --dying-blocks 300 --cltv-timeout $((H0 + 3500))
        --step-blocks 5 --states-per-layer 2 --fee-rate $FEE --lsp-balance-pct 50
        --confirm-timeout 600 --seckey "$LSP_SECKEY" "${RPC[@]}" --wallet $WALLET
        --db "$D/lsp.db" --daemon)
    [ "$SC" = mixed ] && LSPARGS+=(--payments 1)
    if [ "$SC" = rotate ] || [ "$SC" = reconnect ]; then
        LSPARGS+=(--cli)
        mkfifo "$D/cli.fifo"; exec 9<>"$D/cli.fifo"
        "$LSP_BIN" "${LSPARGS[@]}" > "$D/lsp.log" 2>&1 <&9 &
    elif [ "$SC" = rotate_stopped ]; then
        SUPERSCALAR_CRASH_AT=rotate_channel_setup "$LSP_BIN" "${LSPARGS[@]}" > "$D/lsp.log" 2>&1 </dev/null &
    else
        "$LSP_BIN" "${LSPARGS[@]}" > "$D/lsp.log" 2>&1 </dev/null &
    fi
    LSP_PID=$!; PIDS+=($LSP_PID)
    wait_log "listening" "$D/lsp.log" 60 "LSP to listen" || { tail -20 "$D/lsp.log"; return 1; }

    local i
    declare -a CPID
    start_client(){ # participant id; uses SC, P, D of the running scenario
        local id=$1 SK EXTRA=(--daemon)
        SK=$(printf '%064x' $((id + 1)))
        if [ "$SC" = mixed ]; then
            [ "$id" = 1 ] && EXTRA=(--channels --send "1:$PAY_AMT:$PREIMAGE")
            [ "$id" = 2 ] && EXTRA=(--channels --recv "$PREIMAGE")
        fi
        "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$P" --seckey "$SK" \
            --fee-rate $FEE --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id "$id" \
            "${RPC[@]}" --wallet $WALLET --db "$D/c$id.db" "${EXTRA[@]}" >> "$D/c$id.log" 2>&1 </dev/null &
        CPID[$id]=$!; PIDS+=($!)
    }
    for i in $(seq 1 $N); do start_client "$i"; sleep 0.3; done
    ( while true; do mine 1; sleep 3; done ) & MINER_PID=$!

    wait_log "channels ready" "$D/lsp.log" 400 "channels ready" || { tail -30 "$D/lsp.log"; return 1; }
    if [ "$SC" = mixed ]; then
        wait_log "all 1 payments processed" "$D/lsp.log" 180 "the payment" || { tail -30 "$D/lsp.log"; return 1; }
    fi
    wait_log "entering daemon mode" "$D/lsp.log" 120 "LSP daemon mode" || { tail -30 "$D/lsp.log"; return 1; }
    echo "  channels ready, LSP in daemon mode (height $("${BCLI[@]}" getblockcount))"

    # Every client must hold a signed commitment now, payment or not.
    local have=0 n
    for _ in $(seq 1 20); do
        have=0
        for i in $(seq 1 $N); do
            n=$(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT count(*) FROM signed_commitments;" 2>/dev/null || echo 0)
            [ "${n:-0}" -ge 1 ] && have=$((have + 1))
        done
        [ "$have" -eq $N ] && break
        sleep 1
    done
    for i in $(seq 1 $N); do
        echo "  client $i: $(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT 'commitment_number=' || commitment_number FROM signed_commitments;" 2>/dev/null | head -1 | grep . || echo "NO signed commitment") balance=$(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null)"
    done
    [ "$have" -eq $N ] || red "  only $have of $N clients hold a signed commitment before the LSP disappears"

    # A client restarted before its first payment keeps its commitment 0.
    local restart_ok=1 before after
    if { [ "$SC" = idle ] || [ "$SC" = reconnect ]; } && [ "$have" -eq $N ]; then
        before=$(sqlite3 "file:$D/c4.db?mode=ro" "SELECT commitment_number || ':' || signed_tx_hex FROM signed_commitments;" 2>/dev/null)
        kill -9 "${CPID[4]}" 2>/dev/null; sleep 1
        start_client 4
        for _ in $(seq 1 60); do grep -q "reconnected (channel" "$D/c4.log" 2>/dev/null && break; sleep 1; done
        after=$(sqlite3 "file:$D/c4.db?mode=ro" "SELECT commitment_number || ':' || signed_tx_hex FROM signed_commitments;" 2>/dev/null)
        if ! grep -q "reconnected (channel" "$D/c4.log" 2>/dev/null; then
            red "  CHECK FAIL client 4 did not reconnect after its restart"; tail -5 "$D/c4.log" | sed 's/^/    /'; restart_ok=0
        elif [ -z "$after" ] || [ "$before" != "$after" ]; then
            red "  CHECK FAIL client 4's stored commitment changed or disappeared across its restart"; restart_ok=0
        else
            echo "  ok   client 4 restarted and reconnected from its database; its commitment 0 is unchanged"
        fi
    fi

    if [ "$SC" = reconnect ]; then
        local ok=$restart_ok base b4
        [ "$have" -eq $N ] || ok=0
        base=$(bal_of "$D/c3.db")
        sleep 3
        if cli_pay "$D/lsp.log" 3 0 5000; then echo "  ok   payment of 5000 sat from the restarted client 4 to client 1 succeeded"
        else red "  CHECK FAIL payment from the restarted client 4 did not succeed"; ok=0; fi
        if cli_pay "$D/lsp.log" 0 3 2000; then echo "  ok   payment of 2000 sat from client 1 to the restarted client 4 succeeded"
        else red "  CHECK FAIL payment to the restarted client 4 did not succeed"; ok=0; fi
        sleep 4
        if ! kill -0 "${CPID[4]}" 2>/dev/null; then red "  CHECK FAIL client 4 is no longer running"; ok=0; fi
        if grep -qE "no retrievable committed point|INVALID LSP revocation|verification/aggregation failed|halting daemon loop" "$D/c4.log"; then
            red "  CHECK FAIL client 4 rejected a signature or revocation after its restart:"
            grep -E "no retrievable committed point|INVALID LSP revocation|verification/aggregation failed|halting daemon loop" "$D/c4.log" | head -3 | sed 's/^/    /'
            ok=0
        fi
        b4=$(bal_of "$D/c4.db")
        if [ -n "$base" ] && [ "${b4:-0}" -eq $((base - 3000)) ]; then echo "  ok   client 4 balance $b4 sat = $base - 5000 + 2000"
        else red "  CHECK FAIL client 4 balance ${b4:-none} sat, expected $((base - 3000))"; ok=0; fi
        kill_ss
        [ "$ok" = 1 ]; return $?
    fi

    if [ "$SC" = rotate_stopped ]; then
        local ok=1 rc fop
        [ "$have" -eq $N ] || ok=0
        mine 45
        wait_log "lsp_crash_checkpoint: HIT 'rotate_channel_setup'" "$D/lsp.log" 600 "the LSP to die mid-rotation" || { grep -aE "LSP rotate:|DYING" "$D/lsp.log" | tail -8; return 1; }
        echo "  LSP died at the checkpoint (height $("${BCLI[@]}" getblockcount))"
        for i in $(seq 1 $N); do
            for _ in $(seq 1 60); do kill -0 "${CPID[$i]}" 2>/dev/null || break; sleep 1; done
            if kill -0 "${CPID[$i]}" 2>/dev/null; then red "  CHECK FAIL client $i is still running (it must stop, not reconnect)"; ok=0; continue; fi
            wait "${CPID[$i]}" 2>/dev/null; rc=$?
            if grep -q "ROTATION NOT COMPLETED" "$D/c$i.log" && [ "$rc" -ne 0 ]; then
                echo "  ok   client $i reported the rotation as not completed and exited with status $rc"
            else red "  CHECK FAIL client $i: exit status $rc, 'ROTATION NOT COMPLETED' $(grep -c "ROTATION NOT COMPLETED" "$D/c$i.log") time(s)"; ok=0; fi
        done
        stop_miner
        # a restarted client finds the record and does not connect
        for i in $(seq 1 $N); do
            start_client "$i"
            for _ in $(seq 1 30); do kill -0 "${CPID[$i]}" 2>/dev/null || break; sleep 1; done
            if kill -0 "${CPID[$i]}" 2>/dev/null; then red "  CHECK FAIL client $i started again although its rotation is unfinished"; ok=0; continue; fi
            wait "${CPID[$i]}" 2>/dev/null; rc=$?
            if [ "$rc" -ne 0 ] && [ "$(grep -c "ROTATION NOT COMPLETED" "$D/c$i.log")" -ge 2 ] && ! grep -q "reconnecting from persisted state" "$D/c$i.log"; then
                echo "  ok   client $i refuses to start again (status $rc)"
            else red "  CHECK FAIL client $i restart: status $rc"; tail -3 "$D/c$i.log" | sed 's/^/    /'; ok=0; fi
        done
        for i in $(seq 1 $N); do
            n=$(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT (SELECT count(*) FROM signed_commitments) || ' ' || (SELECT count(*) FROM factories WHERE id = 1) || (SELECT count(*) FROM distribution_txs WHERE factory_id = 1);" 2>/dev/null)
            timeout 180 "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli "${RPC[@]}" \
                --force-close --db "$D/c$i.db" >> "$D/fc_c$i.log" 2>&1 </dev/null
            if [ "$n" = "1 11" ] && grep -q "NOT publishing the factory tree" "$D/fc_c$i.log" && ! grep -q "broadcast node" "$D/fc_c$i.log"; then
                echo "  ok   client $i: old commitment kept, new factory and its distribution TX recorded as pending, force-close left the new tree unpublished"
            else red "  CHECK FAIL client $i: commitments/distribution rows '$n', force-close log: $(grep -E "Force-close:" "$D/fc_c$i.log" | head -2 | tr '\n' ' ')"; ok=0; fi
        done
        mine 2
        fop=$(sqlite3 "file:$D/c1.db?mode=ro" "SELECT funding_txid || ' ' || funding_vout FROM factories WHERE id = 1;" 2>/dev/null)
        if [ -n "$fop" ] && [ -n "$("${BCLI[@]}" gettxout $fop 2>/dev/null)" ]; then echo "  ok   the new factory's funding output ($fop) is still unspent"
        else red "  CHECK FAIL the new factory's funding output ($fop) is spent or unknown"; ok=0; fi
        kill_ss
        [ "$ok" = 1 ]; return $?
    fi

    local PRE_BAL=""
    if [ "$SC" = rotate ]; then
        sleep 3
        if cli_pay "$D/lsp.log" 0 1 5000; then echo "  payment of 5000 sat from client 1 to client 2 settled in the first factory"
        else red "  CHECK FAIL payment before the rotation did not succeed"; return 1; fi
        sleep 3
        for i in $(seq 1 $N); do PRE_BAL="$PRE_BAL $(bal_of "$D/c$i.db")"; done
        echo "  balances before the rotation:$PRE_BAL"
        # run the factory out of its active period; the LSP rotates on its own
        mine 45
        if ! wait_log "LSP rotate: rotation complete" "$D/lsp.log" 600 "the rotation"; then
            red "  CHECK FAIL the rotation did not complete"
            grep -aE "LSP rotate:|rotation" "$D/lsp.log" | tail -8 | sed 's/^/    /'
            for i in $(seq 1 $N); do grep -aE "rotation|ROTATION|REFUSING|initial commitment|opening balances" "$D/c$i.log" | tail -3 | sed "s/^/    c$i: /"; done
            return 1
        fi
        echo "  rotation succeeded (height $("${BCLI[@]}" getblockcount))"
        for _ in $(seq 1 60); do
            have=0
            for i in $(seq 1 $N); do
                grep -q "persisted rotated factory" "$D/c$i.log" 2>/dev/null || continue
                n=$(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT count(*) FROM signed_commitments WHERE commitment_number = 0;" 2>/dev/null || echo 0)
                [ "${n:-0}" -ge 1 ] && have=$((have + 1))
            done
            [ "$have" -eq $N ] && break
            sleep 1
        done
        for i in $(seq 1 $N); do
            echo "  client $i after rotation: $(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT 'commitment_number=' || commitment_number FROM signed_commitments;" 2>/dev/null | head -1 | grep . || echo "NO signed commitment") balance=$(bal_of "$D/c$i.db")"
        done
        [ "$have" -eq $N ] || red "  only $have of $N clients hold a signed commitment 0 for the new factory"
        sleep 5
    fi
    sleep 5

    echo "  killing the LSP and all clients"
    kill_ss

    # Each client exits alone from its database; mine between passes so each
    # tree level matures.
    local pass conf c h
    declare -a CTX
    for i in $(seq 1 $N); do
        h=$(sqlite3 "file:$D/c$i.db?mode=ro" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;" 2>/dev/null)
        CTX[$i]=""
        [ -n "$h" ] && CTX[$i]=$("${BCLI[@]}" decoderawtransaction "$h" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["txid"])' 2>/dev/null)
    done
    for pass in $(seq 1 40); do
        local FC=()
        for i in $(seq 1 $N); do
            timeout 180 "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli "${RPC[@]}" \
                --force-close --db "$D/c$i.db" >> "$D/fc_c$i.log" 2>&1 </dev/null &
            FC+=($!)
        done
        for c in "${FC[@]}"; do wait "$c" 2>/dev/null || true; done
        mine 6
        conf=0
        for i in $(seq 1 $N); do
            [ -n "${CTX[$i]}" ] || continue
            c=$("${BCLI[@]}" getrawtransaction "${CTX[$i]}" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
            [ "${c:-0}" -ge 1 ] && conf=$((conf + 1))
        done
        [ "$conf" -eq $N ] && break
        # nothing more can happen for a client without a commitment once the tree is out
        [ "$have" -lt $N ] && [ "$pass" -ge 15 ] && [ "$conf" -eq "$have" ] && break
    done
    echo "  $conf of $N commitments confirmed after $pass force-close pass(es) (height $("${BCLI[@]}" getblockcount))"
    mine 2

    BCLI_STR="${BCLI[*]}" PRE_BAL="$PRE_BAL" python3 - "$D" "$N" "$SC" "$PAY_AMT" <<'PYEOF'
import sys, os, json, sqlite3, subprocess
D, N, SC, PAY = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
BCLI = os.environ["BCLI_STR"].split()
P2A = "51024e73"
fails = 0
def ok(m): print("  ok   " + m)
def fail(m):
    global fails
    fails += 1
    print("  CHECK FAIL " + m)
def cli(*a, stdin=None):
    r = subprocess.run(BCLI + list(a), input=stdin, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None
def decode(h):
    r = cli("-stdin", "decoderawtransaction", stdin=h)
    return json.loads(r) if r else None
def q(db, sql):
    try:
        c = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=30)
        rows = c.execute(sql).fetchall(); c.close(); return rows
    except Exception:
        return []
def sats(v): return int(round(v * 1e8))

lsp_db = os.path.join(D, "lsp.db")
# the factory the clients are in now, as client 1 recorded it
fac = q(os.path.join(D, "c1.db"), "SELECT funding_txid, funding_vout, funding_amount FROM factories WHERE id = 0")
if not fac:
    print("  CHECK FAIL no factory row in client 1's database"); sys.exit(1)
fund_op, F = (fac[0][0], fac[0][1]), fac[0][2]
lsp_rows = q(lsp_db, "SELECT slot, local_amount, remote_amount, funding_txid, funding_vout, commitment_number FROM channels")
pre_bal = [int(x) for x in os.environ.get("PRE_BAL", "").split()]
movers = {1: -PAY, 2: PAY} if SC == "mixed" else {}

# signed tree, as every client holds it
known = {}
for i in range(1, N + 1):
    for (hx,) in q(os.path.join(D, "c%d.db" % i), "SELECT signed_tx_hex FROM tree_nodes WHERE signed_tx_hex IS NOT NULL AND signed_tx_hex != ''"):
        d = decode(hx)
        if d: known[d["txid"]] = "tree"

commits = {}; total_bal = 0; total_tolocal = 0; idle_bal = set()
for i in range(1, N + 1):
    db = os.path.join(D, "c%d.db" % i)
    role = "idle" if i not in movers else ("sender" if movers[i] < 0 else "receiver")
    ch = q(db, "SELECT local_amount, remote_amount, funding_txid, funding_vout FROM channels LIMIT 1")
    sc = q(db, "SELECT commitment_number, signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1")
    if not ch:
        fail("client %d (%s): no channel row" % (i, role)); continue
    bal = ch[0][0]; total_bal += bal
    if role == "idle": idle_bal.add(bal)
    if not sc:
        fail("client %d (%s): no signed commitment in its database, balance %d sat cannot be claimed" % (i, role, bal)); continue
    cn, d = sc[0][0], decode(sc[0][1])
    if d is None:
        fail("client %d (%s): stored commitment does not decode" % (i, role)); continue
    known[d["txid"]] = "commitment"; commits[i] = d
    if role == "idle" and cn != 0:
        fail("client %d (idle): commitment number %d, expected 0" % (i, cn))
    if role != "idle" and cn == 0:
        fail("client %d (%s): still at commitment 0 after the payment" % (i, role))
    if (d["vin"][0]["txid"], d["vin"][0]["vout"]) != (ch[0][2], ch[0][3]):
        fail("client %d (%s): commitment does not spend its channel funding output" % (i, role))
    raw = cli("getrawtransaction", d["txid"], "1")
    conf = json.loads(raw).get("confirmations", 0) if raw else 0
    if conf < 1:
        fail("client %d (%s): commitment %s not confirmed" % (i, role, d["txid"])); continue
    tl = sats(d["vout"][0]["value"]); total_tolocal += tl
    l = next((r[1:] for r in lsp_rows if r[0] == i - 1 and (r[3], r[4]) == (ch[0][2], ch[0][3])), None)
    if pre_bal and bal != pre_bal[i - 1]:
        fail("client %d: balance %d sat in the new factory, %d sat before the rotation" % (i, bal, pre_bal[i - 1]))
    if tl != bal:
        fail("client %d (%s): to_local %d sat != balance in its database %d sat" % (i, role, tl, bal))
    elif l is None or l[1] != bal:
        fail("client %d (%s): balance %d sat != the LSP's record %s" % (i, role, bal, l[1] if l else None))
    else:
        ok("client %d (%s): commitment %d confirmed (%d conf), to_local %d sat = its balance (client and LSP databases agree)" % (i, role, cn, conf, tl))
if SC == "mixed" and len(idle_bal) == 1:
    base = next(iter(idle_bal))
    for i, delta in movers.items():
        b = q(os.path.join(D, "c%d.db" % i), "SELECT local_amount FROM channels LIMIT 1")
        if b and b[0][0] != base + delta:
            fail("client %d: balance %d sat, expected idle balance %d %+d" % (i, b[0][0], base, delta))
    if not fails: ok("sender is down %d sat and receiver up %d sat against the idle balance %d sat" % (PAY, PAY, base))
if len(commits) == N and total_tolocal == total_bal:
    ok("sum of the %d to_local outputs = sum of client balances = %d sat" % (N, total_bal))
elif len(commits) == N:
    fail("sum of to_local %d sat != sum of client balances %d sat" % (total_tolocal, total_bal))

# walk the chain from the factory funding output
fraw = cli("getrawtransaction", fund_op[0], "1")
if not fraw:
    fail("factory funding transaction not found on chain"); sys.exit(1)
ftx = json.loads(fraw)
if sats(ftx["vout"][fund_op[1]]["value"]) != F:
    fail("funding output on chain %d sat != factory funding_amount %d sat" % (sats(ftx["vout"][fund_op[1]]["value"]), F))
start = json.loads(cli("getblockheader", ftx["blockhash"]))["height"]
tip = int(cli("getblockcount")); chain = {}
for h in range(start, tip + 1):
    for tx in json.loads(cli("getblock", cli("getblockhash", str(h)), "2"))["tx"]:
        if "coinbase" not in tx["vin"][0]: chain[tx["txid"]] = tx
spender = {}
for t, tx in chain.items():
    for vin in tx["vin"]: spender[(vin["txid"], vin["vout"])] = t
desc = set(); ops = {fund_op}; changed = True
while changed:
    changed = False
    for t, tx in chain.items():
        if t in desc: continue
        if any((v["txid"], v["vout"]) in ops for v in tx["vin"]):
            desc.add(t); changed = True
            for o in tx["vout"]: ops.add((t, o["n"]))
def spk(op): return chain[op[0]]["vout"][op[1]]["scriptPubKey"]["hex"] if op[0] in chain else None
foreign = [t for t in desc if t not in known and any(
    (v["txid"], v["vout"]) in ops and v["txid"] in known and spk((v["txid"], v["vout"])) != P2A for v in chain[t]["vin"])]
if foreign: fail("%d on-chain transaction(s) spend a factory output but are neither a signed tree node nor a client commitment: %s" % (len(foreign), foreign[:3]))
else: ok("every transaction spending a factory output is a signed tree node or a client commitment (%d tree, %d commitments on chain)" % (
    sum(1 for t in desc if known.get(t) == "tree"), sum(1 for t in desc if known.get(t) == "commitment")))
fees = unspent = bumped = 0
for t in desc:
    if t not in known: continue
    tx = chain[t]
    inv = sum(F if (v["txid"], v["vout"]) == fund_op else sats(chain[v["txid"]]["vout"][v["vout"]]["value"]) for v in tx["vin"])
    fees += inv - sum(sats(o["value"]) for o in tx["vout"])
    for o in tx["vout"]:
        s = spender.get((t, o["n"]))
        if s is None: unspent += sats(o["value"])
        elif s not in known: bumped += sats(o["value"])
if not desc: fail("the factory funding output was never spent")
elif unspent + fees + bumped == F:
    ok("conservation: funding %d sat = %d unspent + %d fees + %d anchors spent by fee bumps" % (F, unspent, fees, bumped))
else: fail("conservation: funding %d sat != %d unspent + %d fees + %d anchors spent by fee bumps" % (F, unspent, fees, bumped))
sys.exit(1 if fails else 0)
PYEOF
    local rc=$?
    [ "$restart_ok" = 1 ] || rc=1
    if [ $rc -ne 0 ]; then
        for i in $(seq 1 $N); do echo "  --- client $i force-close log (tail) ---"; tail -4 "$D/fc_c$i.log" 2>/dev/null | sed 's/^/  /'; done
    fi
    return $rc
}

RESULT=0; n=0
for SC in $SCENARIOS; do
    if run_scenario "$SC" $((PORT + n)); then green "scenario '$SC': PASS"; else red "scenario '$SC': FAIL"; RESULT=1; fi
    kill_ss
    n=$((n + 1))
done
echo
if [ $RESULT -eq 0 ]; then green "PASS: every client left its channel alone with its full balance ($SCENARIOS)"; else red "FAIL: see CHECK FAIL lines above"; fi
exit $RESULT
