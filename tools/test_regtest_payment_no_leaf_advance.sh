#!/usr/bin/env bash
# test_regtest_payment_no_leaf_advance.sh — a payment must not touch the
# factory leaf that funds the channels it flows through.
#
# Real daemons on regtest: 1 LSP + 2 clients, one client-initiated payment
# (client 0 pays client 1 through the LSP), then a unilateral exit.  A channel
# is funded by output 0 of its leaf transaction and that outpoint is fixed when
# the channel opens, so the leaf must be exactly the same transaction after the
# payment as before it.  If the leaf were re-signed, the transaction that lands
# on chain would no longer carry the output the commitments spend and the
# clients' balances would be stranded.
#
# Two scenarios per invocation:
#
#   lsp_exit      the LSP routes the payment and force-closes the factory
#                 itself; each client then force-closes from its own DB.
#   client_exit   the LSP is killed after the payment; the clients force-close
#                 alone (tree + commitment from their own DBs).  Afterwards a
#                 standalone watchtower runs on the LSP's watch DB and the LSP
#                 is restarted on its DB: neither may treat a leaf as a stale
#                 state or report a balance mismatch.
#
# Checks, in both scenarios:
#   - the payment settled and no leaf-advance ceremony ran (logs);
#   - no PS chain entry beyond chain[0] and no advanced per-leaf DW state in
#     any DB; LSP and client agree on each channel's funding outpoint;
#   - each client's latest commitment confirms, spends that funding outpoint,
#     and pays the client exactly its channel balance.
#
# The leaf type is the LSP's default unless ARITY is set (ARITY=1 runs the
# per-client DW leaf: `--arity 1`).
#
# The test starts its own bitcoind (private datadir and RPC port) and stops it
# on exit.  That node runs with minrelaytxfee/blockmintxfee lowered to
# 500 sat/kvB: a commitment transaction currently pays a fixed 154 sat for
# 167 vB, which is below the default 1000 sat/kvB relay floor.  The floor is
# lowered here only so the exit path can be exercised; it is not something
# this test verifies.
#
# Usage: bash tools/test_regtest_payment_no_leaf_advance.sh [BUILD_DIR]
#   BUILD_DIR   directory holding superscalar_lsp / superscalar_client /
#               superscalar_watchtower (argument, or $BUILD_DIR, or ./build)
#   ARITY       leaf arity passed to the LSP (default: unset = LSP default)
#   RPCPORT     RPC port of the private bitcoind (default 18643)
#   PORT        first LSP listen port (default 29975)
#   KEEP_TMP=1  keep the work directory
#
# Requires bitcoind, bitcoin-cli, sqlite3 and python3 in PATH.
set -uo pipefail

BUILD_DIR="${1:-${BUILD_DIR:-build}}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

ARITY="${ARITY:-}"
RPCPORT="${RPCPORT:-18643}"
PORT="${PORT:-29975}"
AMOUNT="${AMOUNT:-200000}"
FEE="${FEE:-1100}"
PAY_SATS=5000
RU=rpcuser
RP=rpcpass
WALLET=ss_no_leaf_advance
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
PREIMAGE="7000000000000000000000000000000000000000000000000000000000000000"

for b in "$LSP_BIN" "$CLIENT_BIN" "$WT_BIN"; do
    [ -x "$b" ] || { echo "FAIL: missing binary $b"; exit 1; }
done
for t in bitcoind bitcoin-cli sqlite3 python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "FAIL: $t not found in PATH"; exit 1; }
done

TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/ss-no-leaf-advance.XXXXXX")
BTC_DIR="$TMPDIR/bitcoind"
mkdir -p "$BTC_DIR"
BCLI="bitcoin-cli -regtest -datadir=$BTC_DIR -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPCPORT"
RPC_ARGS=(--rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPCPORT")

PIDS=()
MINER_PID=""
FAILS=0
kill_procs(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null
    MINER_PID=""
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
    PIDS=()
    wait 2>/dev/null
}
cleanup(){
    kill_procs
    $BCLI stop >/dev/null 2>&1
    for _ in $(seq 1 20); do $BCLI getblockcount >/dev/null 2>&1 || break; sleep 1; done
    if [ "${KEEP_TMP:-0}" = 1 ] || [ "$FAILS" -gt 0 ]; then
        echo "work directory kept: $TMPDIR"
    else
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

note_ok(){ printf '  \033[32mok\033[0m   %s\n' "$*"; }
note_fail(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
start_miner(){ ( while true; do mine 1; sleep 2; done ) & MINER_PID=$!; disown "$MINER_PID" 2>/dev/null; }
stop_miner(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null; wait "$MINER_PID" 2>/dev/null; MINER_PID=""; }
sk(){ printf "%064x" $(( $1 + 2 )); }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1; }

# txfield <rawhex> <field>: txid | in_txid | in_vout | pays <sats> (vout index paying exactly <sats>, or -1)
txfield(){
    $BCLI decoderawtransaction "$1" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
f = sys.argv[1]
if f == "txid": print(d["txid"])
elif f == "in_txid": print(d["vin"][0]["txid"])
elif f == "in_vout": print(d["vin"][0]["vout"])
elif f == "n_in": print(len(d["vin"]))
elif f == "pays":
    want = int(sys.argv[2])
    hits = [o["n"] for o in d["vout"] if int(round(o["value"] * 1e8)) == want]
    print(hits[0] if hits else -1)
' "${@:2}" 2>/dev/null
}

# --- private regtest node -------------------------------------------------
bitcoind -regtest -datadir="$BTC_DIR" -daemon -server=1 -txindex=1 -listen=0 \
    -rpcuser=$RU -rpcpassword=$RP -rpcport="$RPCPORT" -fallbackfee=0.00001 \
    -minrelaytxfee=0.000005 -blockmintxfee=0.000005 >/dev/null \
    || { echo "FAIL: could not start bitcoind"; exit 1; }
for _ in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockcount >/dev/null 2>&1 || { echo "FAIL: bitcoind RPC not reachable on port $RPCPORT"; exit 1; }
$BCLI -named createwallet wallet_name=$WALLET >/dev/null 2>&1
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 101

ARITY_ARGS=()
[ -n "$ARITY" ] && ARITY_ARGS=(--arity "$ARITY")
echo "=== payment must not advance the leaf (leaf type: ${ARITY:+--arity }${ARITY:-LSP default}) ==="

# no_advance_in_db <db> <label>
no_advance_in_db(){
    local db=$1 label=$2 n ls
    n=$(sqlite3 "$db" "SELECT COUNT(*) FROM ps_leaf_chains WHERE chain_pos >= 1;" 2>/dev/null)
    if [ "${n:-x}" = 0 ]; then note_ok "$label: no PS chain entry beyond chain[0]"
    else note_fail "$label: $n PS chain entr(ies) with chain_pos >= 1"; fi
    ls=$(sqlite3 "$db" "SELECT leaf_states FROM dw_counter_state;" 2>/dev/null | tr -d '0,\n ')
    if [ -z "$ls" ]; then note_ok "$label: per-leaf DW states all at 0"
    else note_fail "$label: per-leaf DW state advanced ($(sqlite3 "$db" 'SELECT leaf_states FROM dw_counter_state;' 2>/dev/null))"; fi
}

# run_scenario <lsp_exit|client_exit> <port>
run_scenario(){
    local MODE=$1 LPORT=$2
    local D="$TMPDIR/$MODE"
    mkdir -p "$D"
    echo
    echo "--- scenario $MODE ---"

    local LSP_ARGS=(--network regtest --port "$LPORT" --lsp-balance-pct 50 --clients 2
        ${ARITY_ARGS[@]+"${ARITY_ARGS[@]}"} --amount "$AMOUNT" --fee-rate "$FEE" --confirm-timeout 600
        --seckey "$LSP_SECKEY" "${RPC_ARGS[@]}" --wallet "$WALLET" --db "$D/lsp.db")
    local LSP_RUN=(--payments 1)
    if [ "$MODE" = lsp_exit ]; then
        LSP_RUN+=(--force-close)
    else
        LSP_ARGS+=(--wt-db "$D/wt.db")
        LSP_RUN+=(--daemon)
    fi

    "$LSP_BIN" "${LSP_ARGS[@]}" "${LSP_RUN[@]}" > "$D/lsp.log" 2>&1 &
    local LSP_PID=$!
    PIDS+=("$LSP_PID")
    for _ in $(seq 1 60); do
        sleep 1
        grep -q "listening" "$D/lsp.log" 2>/dev/null && break
        kill -0 "$LSP_PID" 2>/dev/null || break
    done
    if ! grep -q "listening" "$D/lsp.log" 2>/dev/null; then
        tail -20 "$D/lsp.log"; note_fail "$MODE: LSP never listened"; kill_procs; return
    fi

    local i
    for i in 0 1; do
        local CX=(--channels --recv "$PREIMAGE")
        [ "$i" = 0 ] && CX=(--channels --send "1:$PAY_SATS:$PREIMAGE")
        "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$LPORT" \
            --seckey "$(sk $i)" --fee-rate "$FEE" --lsp-balance-pct 50 \
            --lsp-pubkey "$LSP_PUB" --participant-id $((i + 1)) "${RPC_ARGS[@]}" \
            --wallet "$WALLET" --db "$D/c$i.db" "${CX[@]}" > "$D/c$i.log" 2>&1 &
        PIDS+=($!)
        sleep 0.5
    done
    start_miner

    if [ "$MODE" = lsp_exit ]; then
        for _ in $(seq 1 450); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 2; done
        if kill -0 "$LSP_PID" 2>/dev/null; then
            tail -30 "$D/lsp.log"; note_fail "$MODE: LSP still running after 900s"; kill_procs; return
        fi
        wait "$LSP_PID"; local rc=$?
        if [ "$rc" = 0 ] && grep -q "FORCE CLOSE COMPLETE" "$D/lsp.log"; then
            note_ok "LSP routed the payment and force-closed (rc=0)"
        else
            tail -30 "$D/lsp.log"; note_fail "$MODE: LSP force-close did not complete (rc=$rc)"
        fi
    else
        for _ in $(seq 1 300); do
            grep -q "entering daemon mode" "$D/lsp.log" 2>/dev/null && break
            kill -0 "$LSP_PID" 2>/dev/null || break
            sleep 2
        done
        if ! grep -q "entering daemon mode" "$D/lsp.log" 2>/dev/null; then
            tail -30 "$D/lsp.log"; note_fail "$MODE: LSP never reached daemon mode"; kill_procs; return
        fi
        sleep 8   # let both sides finish persisting the settled payment
    fi
    # Every SuperScalar process goes away; from here on only the DBs matter.
    kill_procs

    # ---- the payment settled, and nothing advanced a leaf ----
    if grep -q "all 1 payments processed" "$D/lsp.log" && grep -q "HTLC fulfilled" "$D/lsp.log"; then
        note_ok "payment settled (client 0 -> client 1, $PAY_SATS sats)"
    else
        note_fail "$MODE: payment did not settle"
    fi
    local ADV_RE="LEAF_ADVANCE_PROPOSE|leaf [0-9]+ advanced|leaf [0-9]+ advance (confirmed|complete)"
    local ADV
    ADV=$(cat "$D/lsp.log" "$D/c0.log" "$D/c1.log" 2>/dev/null | grep -cE "$ADV_RE")
    if [ "$ADV" = 0 ]; then note_ok "no leaf-advance ceremony in LSP or client logs"
    else
        note_fail "$MODE: leaf-advance ceremony ran after the payment ($ADV log lines)"
        cat "$D/lsp.log" "$D/c0.log" "$D/c1.log" | grep -E "$ADV_RE" | head -6 | sed 's/^/         /'
    fi
    no_advance_in_db "$D/lsp.db" "LSP DB"
    no_advance_in_db "$D/c0.db" "client 0 DB"
    no_advance_in_db "$D/c1.db" "client 1 DB"

    # ---- balances and funding outpoints, from the DBs ----
    local -a BAL FTXID FVOUT CHEX CTXID
    for i in 0 1; do
        BAL[$i]=$(sqlite3 "$D/c$i.db" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null)
        FTXID[$i]=$(sqlite3 "$D/c$i.db" "SELECT funding_txid FROM channels LIMIT 1;" 2>/dev/null)
        FVOUT[$i]=$(sqlite3 "$D/c$i.db" "SELECT funding_vout FROM channels LIMIT 1;" 2>/dev/null)
        CHEX[$i]=$(sqlite3 "$D/c$i.db" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;" 2>/dev/null)
        CTXID[$i]=""
        [ -n "${CHEX[$i]}" ] && CTXID[$i]=$(txfield "${CHEX[$i]}" txid)
        local lsp_remote lsp_ftxid
        lsp_remote=$(sqlite3 "$D/lsp.db" "SELECT remote_amount FROM channels WHERE slot=$i;" 2>/dev/null)
        lsp_ftxid=$(sqlite3 "$D/lsp.db" "SELECT funding_txid FROM channels WHERE slot=$i;" 2>/dev/null)
        if [ -n "${BAL[$i]}" ] && [ "${BAL[$i]}" = "$lsp_remote" ]; then
            note_ok "client $i balance ${BAL[$i]} sats (LSP agrees)"
        else
            note_fail "$MODE: client $i balance '${BAL[$i]}' vs LSP's view '$lsp_remote'"
        fi
        if [ -n "${FTXID[$i]}" ] && [ "${FTXID[$i]}" = "$lsp_ftxid" ]; then
            note_ok "client $i channel funding outpoint ${FTXID[$i]:0:16}...:${FVOUT[$i]} (LSP agrees)"
        else
            note_fail "$MODE: client $i funding txid '${FTXID[$i]}' vs LSP's '$lsp_ftxid'"
        fi
        if [ -z "${CTXID[$i]}" ]; then
            note_fail "$MODE: client $i has no signed commitment to broadcast"
        elif [ "$(txfield "${CHEX[$i]}" in_txid)" = "${FTXID[$i]}" ] && \
             [ "$(txfield "${CHEX[$i]}" in_vout)" = "${FVOUT[$i]}" ]; then
            note_ok "client $i latest commitment spends that outpoint"
        else
            note_fail "$MODE: client $i commitment does not spend its funding outpoint"
        fi
    done
    if [ -n "${BAL[0]}" ] && [ -n "${BAL[1]}" ] && [ $(( BAL[1] - BAL[0] )) = $(( 2 * PAY_SATS )) ]; then
        note_ok "balances reflect the payment (client 1 - client 0 = $(( 2 * PAY_SATS )) sats)"
    else
        note_fail "$MODE: balances do not reflect the payment (c0=${BAL[0]} c1=${BAL[1]})"
    fi

    # ---- unilateral exit by each client, from its own DB ----
    for i in 0 1; do
        local pass c="" fc_rc
        for pass in $(seq 1 40); do
            "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli "${RPC_ARGS[@]}" \
                --force-close --db "$D/c$i.db" >> "$D/fc_c$i.log" 2>&1
            fc_rc=$?
            [ "$fc_rc" = 0 ] || note_fail "$MODE: client $i --force-close pass $pass exited $fc_rc"
            mine 6
            [ -n "${CTXID[$i]}" ] && c=$(confs "${CTXID[$i]}")
            [ "${c:-0}" -ge 1 ] && break
        done
        if [ "${c:-0}" -ge 1 ]; then
            note_ok "client $i commitment ${CTXID[$i]:0:16}... confirmed ($pass force-close pass(es))"
        else
            note_fail "$MODE: client $i commitment never confirmed after $pass force-close passes"
            [ -n "${CHEX[$i]}" ] && $BCLI testmempoolaccept "[\"${CHEX[$i]}\"]" 2>&1 | grep -E "allowed|reject-reason" | sed 's/^/         /'
            continue
        fi
        local leaf_conf
        leaf_conf=$(confs "${FTXID[$i]}")
        if [ "${leaf_conf:-0}" -ge 1 ]; then note_ok "client $i leaf ${FTXID[$i]:0:16}... is the transaction on chain"
        else note_fail "$MODE: client $i leaf ${FTXID[$i]} is not on chain"; fi
        local v
        v=$(txfield "${CHEX[$i]}" pays "${BAL[$i]}")
        if [ "${v:--1}" -ge 0 ]; then
            note_ok "client $i to_local = ${BAL[$i]} sats (commitment output $v)"
            CTXID[$i]="${CTXID[$i]}:$v"
        else
            note_fail "$MODE: client $i commitment has no output of ${BAL[$i]} sats"
        fi
    done

    [ "$MODE" = client_exit ] || return

    # ---- nobody treats the leaves as stale afterwards ----
    local WT_ROWS
    WT_ROWS=$(sqlite3 "$D/wt.db" "SELECT COUNT(*) FROM wt_watches;" 2>/dev/null)
    "$WT_BIN" --wt-db "$D/wt.db" --network regtest --poll-interval 2 "${RPC_ARGS[@]}" > "$D/wt.log" 2>&1 &
    local WT_PID=$!
    PIDS+=("$WT_PID")
    for _ in $(seq 1 15); do mine 1; sleep 2; done
    kill -TERM "$WT_PID" 2>/dev/null; sleep 2
    kill_procs
    if ! grep -q "Watching for breaches" "$D/wt.log"; then
        tail -10 "$D/wt.log"; note_fail "$MODE: standalone watchtower did not start"
    elif grep -qE "BREACH|penalty tx\(s\) broadcast|state tx broadcast" "$D/wt.log"; then
        grep -E "BREACH|penalty|broadcast" "$D/wt.log" | head -6 | sed 's/^/         /'
        note_fail "$MODE: standalone watchtower reacted to the clients' exit"
    else
        note_ok "standalone watchtower (${WT_ROWS:-0} watches) saw no breach"
    fi

    "$LSP_BIN" "${LSP_ARGS[@]}" --daemon > "$D/lsp_restart.log" 2>&1 &
    local RL_PID=$!
    PIDS+=("$RL_PID")
    for _ in $(seq 1 20); do mine 1; sleep 3; done
    kill -TERM "$RL_PID" 2>/dev/null; sleep 3
    kill_procs
    if ! grep -q "entering recovery mode" "$D/lsp_restart.log"; then
        tail -15 "$D/lsp_restart.log"; note_fail "$MODE: restarted LSP did not recover its factory"
    elif grep -qE "BREACH|CONSERVATION VIOLATION|penalty tx|restored to chain_len=[1-9]" "$D/lsp_restart.log"; then
        grep -E "BREACH|CONSERVATION VIOLATION|penalty|chain_len" "$D/lsp_restart.log" | head -6 | sed 's/^/         /'
        note_fail "$MODE: restarted LSP reported a stale leaf or a balance mismatch"
    else
        note_ok "restarted LSP: no breach, no balance mismatch, no advanced leaf restored"
    fi
    for i in 0 1; do
        case "${CTXID[$i]}" in
            *:*)
                if [ -n "$($BCLI gettxout "${CTXID[$i]%%:*}" "${CTXID[$i]##*:}" 2>/dev/null)" ]; then
                    note_ok "client $i to_local still unspent after watchtower + LSP restart"
                else
                    note_fail "$MODE: client $i to_local was spent while watchtower / restarted LSP ran"
                fi ;;
        esac
    done
}

run_scenario lsp_exit "$PORT"
run_scenario client_exit $((PORT + 1))

# When the binaries are sanitizer builds, none of them may have reported
# anything (processes that were killed outright report nothing).
SAN_RE="ERROR: (Address|Leak|Thread|Memory)Sanitizer|SUMMARY: [A-Za-z]*Sanitizer|runtime error:"
SAN_LOGS=$(grep -lE "$SAN_RE" "$TMPDIR"/*/*.log 2>/dev/null)
if [ -z "$SAN_LOGS" ]; then
    note_ok "no sanitizer report in any daemon log"
else
    note_fail "sanitizer report in: $(echo $SAN_LOGS)"
    grep -hE "$SAN_RE" $SAN_LOGS | sort | uniq -c | head -8 | sed 's/^/         /'
fi

echo
if [ "$FAILS" -eq 0 ]; then
    printf '\033[32m=== PASS: payment left the leaf untouched; both clients exited with their balances ===\033[0m\n'
    exit 0
fi
printf '\033[31m=== FAIL: %d check(s) failed ===\033[0m\n' "$FAILS"
exit 1
