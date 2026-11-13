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
# Three scenarios per invocation:
#
#   lsp_exit          the LSP routes the payment and force-closes the factory
#                     itself; each client then force-closes from its own DB.
#   client_exit       the LSP is killed after the payment; the clients
#                     force-close alone (tree + commitment from their own
#                     DBs).  Afterwards a standalone watchtower runs on the
#                     LSP's watch DB and the LSP is restarted on its DB:
#                     neither may treat a leaf as a stale state or report a
#                     balance mismatch.
#   advance_refused   after the payment the LSP proposes a leaf advance
#                     (--test-leaf-advance) to clients started WITHOUT
#                     --test-allow-tree-advance.  The client must refuse, the
#                     LSP's attempt must fail, and the clients must still be
#                     able to force-close alone.
#
# Checks, in every scenario:
#   - the payment settled and no leaf advance completed (logs); in the first
#     two scenarios none may even be proposed;
#   - no PS chain entry beyond chain[0] and no advanced DW state in any DB
#     (a query that fails or returns nothing where a row must exist is a
#     failure); each client's persisted tree still holds the leaf its channel
#     is funded by; LSP and client agree on each channel's funding outpoint;
#   - each client's latest commitment confirms and spends that outpoint; its
#     outputs are exactly {client balance, LSP balance less the anchor, the
#     anchor}, and the output paying the client is a taproot script that no
#     other output shares.  (The script itself is derived from per-commitment
#     keys the test cannot recompute, so it is identified by role, not
#     recomputed.)
#   - a payment client that ends on its own (its LSP exited) ends the way a
#     client that lost its LSP does: "disconnected", status 1.  Any other
#     status (a signal, a sanitizer exit code) is a failure.
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
#   RPCPORT     RPC port of the private bitcoind (default 18643 + ARITY)
#   PORT        first LSP listen port; three consecutive ports are used
#               (default 29975 + 10 * ARITY)
#               The defaults differ per ARITY and the work directory is
#               unique per run, so runs for different arities do not collide.
#   KEEP_TMP=1  keep the work directory
#
# Requires bitcoind, bitcoin-cli, sqlite3 and python3 in PATH.
set -uo pipefail

BUILD_DIR="${1:-${BUILD_DIR:-build}}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

ARITY="${ARITY:-}"
case "${ARITY:-0}" in
    ''|*[!0-9]*) echo "FAIL: ARITY must be a number"; exit 1 ;;
esac
RPCPORT="${RPCPORT:-$((18643 + ${ARITY:-0}))}"
PORT="${PORT:-$((29975 + 10 * ${ARITY:-0}))}"
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
CLIENT_PIDS=()
MINER_PID=""
FAILS=0
kill_procs(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null
    MINER_PID=""
    for p in "${PIDS[@]:-}" "${CLIENT_PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
    PIDS=()
    CLIENT_PIDS=()
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

# txfield <rawhex> <field>: txid | in_txid | in_vout |
#   pays <sats>            vout index paying exactly <sats>, or -1
#   shape <local> <remote> "ok" when the outputs are exactly: one paying
#                          <local> to a taproot script no other output uses,
#                          one P2A anchor, and one paying the rest of
#                          <local>+<remote>; otherwise a description
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
elif f == "shape":
    local, remote = int(sys.argv[2]), int(sys.argv[3])
    outs = [(int(round(o["value"] * 1e8)), o["scriptPubKey"]["hex"],
             o["scriptPubKey"].get("type", "")) for o in d["vout"]]
    anchors = [o for o in outs if o[1] == "51024e73"]
    mine = [o for o in outs if o[0] == local and o[1] != "51024e73"]
    problems = []
    if len(outs) != 3: problems.append("%d outputs, expected 3" % len(outs))
    if len(anchors) != 1: problems.append("%d anchor outputs" % len(anchors))
    if len(mine) != 1: problems.append("%d outputs of %d sats" % (len(mine), local))
    if sum(o[0] for o in outs) != local + remote:
        problems.append("outputs sum to %d, balances to %d" % (sum(o[0] for o in outs), local + remote))
    if len(mine) == 1:
        if mine[0][2] != "witness_v1_taproot": problems.append("client output is %s" % mine[0][2])
        if sum(1 for o in outs if o[1] == mine[0][1]) != 1: problems.append("client script is shared")
    print("ok" if not problems else "; ".join(problems))
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

# no_advance_in_db <db> <label> <lsp|client>
# Every query must succeed.  The LSP writes its DW counter row when the
# factory is created, so there it must exist and read epoch 0 with every leaf
# at state 0.  A client writes that row only when it takes part in an advance,
# so there it must be absent or all zero, and the client's persisted tree must
# still contain the leaf transaction its channel is funded by.
no_advance_in_db(){
    local db=$1 label=$2 role=$3 n dw rc
    n=$(sqlite3 "$db" "SELECT COUNT(*) FROM ps_leaf_chains WHERE chain_pos >= 1;" 2>/dev/null); rc=$?
    if [ "$rc" = 0 ] && [ "$n" = 0 ]; then note_ok "$label: no PS chain entry beyond chain[0]"
    else note_fail "$label: PS chain query rc=$rc, entries with chain_pos >= 1: '${n}'"; fi

    dw=$(sqlite3 "$db" "SELECT current_epoch || ':' || leaf_states FROM dw_counter_state;" 2>/dev/null); rc=$?
    if [ "$rc" != 0 ]; then
        note_fail "$label: DW counter query failed (rc=$rc)"
    elif [ -z "$dw" ]; then
        if [ "$role" = lsp ]; then note_fail "$label: no DW counter row"
        else note_ok "$label: no DW counter row (never took part in an advance)"; fi
    elif [ -z "$(printf '%s' "$dw" | tr -d '0,:\n ')" ]; then
        note_ok "$label: DW counter at epoch 0, every leaf at state 0 ($dw)"
    else
        note_fail "$label: DW counter advanced (epoch:leaf_states = $dw)"
    fi

    if [ "$role" = client ]; then
        n=$(sqlite3 "$db" "SELECT COUNT(*) FROM tree_nodes WHERE txid = (SELECT funding_txid FROM channels LIMIT 1);" 2>/dev/null); rc=$?
        if [ "$rc" = 0 ] && [ "${n:-0}" -ge 1 ] 2>/dev/null; then
            note_ok "$label: persisted tree holds the leaf that funds the channel"
        else
            note_fail "$label: persisted tree does not hold the channel's funding leaf (rc=$rc, n='${n}')"
        fi
    fi
}

# run_scenario <lsp_exit|client_exit|advance_refused> <port>
run_scenario(){
    local MODE=$1 LPORT=$2
    local D="$TMPDIR/$MODE"
    mkdir -p "$D"
    echo
    echo "--- scenario $MODE ---"

    # A factory that lives long enough for the payment HTLC to reach the
    # payee with its final CLTV margin to spare: the payee refuses an HTLC
    # that expires within CLIENT_MIN_FINAL_CLTV_DELTA blocks of its tip, and
    # the regtest default lifetime (20 + 10 blocks) leaves no such margin.
    local LSP_ARGS=(--network regtest --port "$LPORT" --lsp-balance-pct 50 --clients 2
        --active-blocks 400
        ${ARITY_ARGS[@]+"${ARITY_ARGS[@]}"} --amount "$AMOUNT" --fee-rate "$FEE" --confirm-timeout 600
        --seckey "$LSP_SECKEY" "${RPC_ARGS[@]}" --wallet "$WALLET" --db "$D/lsp.db")
    local LSP_RUN=(--payments 1)
    case "$MODE" in
        lsp_exit)        LSP_RUN+=(--force-close) ;;
        client_exit)     LSP_ARGS+=(--wt-db "$D/wt.db"); LSP_RUN+=(--daemon) ;;
        advance_refused) LSP_RUN+=(--test-leaf-advance) ;;
    esac

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
        CLIENT_PIDS+=($!)
        sleep 0.5
    done
    start_miner

    if [ "$MODE" != client_exit ]; then
        for _ in $(seq 1 450); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 2; done
        if kill -0 "$LSP_PID" 2>/dev/null; then
            tail -30 "$D/lsp.log"; note_fail "$MODE: LSP still running after 900s"; kill_procs; return
        fi
        wait "$LSP_PID"; local rc=$?
        if [ "$MODE" = lsp_exit ]; then
            if [ "$rc" = 0 ] && grep -q "FORCE CLOSE COMPLETE" "$D/lsp.log"; then
                note_ok "LSP routed the payment and force-closed (rc=0)"
            else
                tail -30 "$D/lsp.log"; note_fail "$MODE: LSP force-close did not complete (rc=$rc)"
            fi
        else
            if grep -q "LEAF_ADVANCE_PROPOSE sent" "$D/lsp.log"; then
                note_ok "LSP proposed a leaf advance after the payment"
            else
                tail -30 "$D/lsp.log"; note_fail "$MODE: LSP never proposed the leaf advance"
            fi
            if cat "$D/c0.log" "$D/c1.log" | grep -q "REFUSING leaf advance"; then
                note_ok "client refused the leaf advance"
            else
                note_fail "$MODE: no client refused the leaf advance"
            fi
            if [ "$rc" != 0 ] && grep -qE "LEAF ADVANCE TEST: .* returned 0" "$D/lsp.log" && \
               ! grep -q "LEAF ADVANCE TEST PASSED" "$D/lsp.log"; then
                note_ok "LSP's advance attempt failed (rc=$rc)"
            else
                tail -30 "$D/lsp.log"; note_fail "$MODE: LSP's advance attempt did not fail (rc=$rc)"
            fi
        fi
        # The LSP is gone, so the payment clients end on their own.
        for i in 0 1; do
            local cpid=${CLIENT_PIDS[$i]} crc
            for _ in $(seq 1 60); do kill -0 "$cpid" 2>/dev/null || break; sleep 1; done
            if kill -0 "$cpid" 2>/dev/null; then
                note_fail "$MODE: payment client $i still running 60s after the LSP exited"
            else
                wait "$cpid"; crc=$?
                if [ "$crc" = 1 ] && grep -q "daemon recv failed (disconnected)" "$D/c$i.log"; then
                    note_ok "payment client $i ended on the LSP's disconnect (status 1)"
                else
                    tail -5 "$D/c$i.log"; note_fail "$MODE: payment client $i exited $crc"
                fi
            fi
        done
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
    # A completed advance in any scenario; a proposed one too unless this
    # scenario is the one where the LSP proposes it on purpose.
    local ADV_RE="leaf [0-9]+ advanced|leaf [0-9]+ advance complete"
    [ "$MODE" = advance_refused ] || ADV_RE="LEAF_ADVANCE_PROPOSE|$ADV_RE"
    local ADV
    ADV=$(cat "$D/lsp.log" "$D/c0.log" "$D/c1.log" 2>/dev/null | grep -cE "$ADV_RE")
    if [ "$ADV" = 0 ]; then note_ok "no leaf advance took place (LSP and client logs)"
    else
        note_fail "$MODE: leaf-advance ceremony ran after the payment ($ADV log lines)"
        cat "$D/lsp.log" "$D/c0.log" "$D/c1.log" | grep -E "$ADV_RE" | head -6 | sed 's/^/         /'
    fi
    no_advance_in_db "$D/lsp.db" "LSP DB" lsp
    no_advance_in_db "$D/c0.db" "client 0 DB" client
    no_advance_in_db "$D/c1.db" "client 1 DB" client

    # ---- balances and funding outpoints, from the DBs ----
    local -a BAL LSPBAL FTXID FVOUT CHEX CTXID
    for i in 0 1; do
        BAL[$i]=$(sqlite3 "$D/c$i.db" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null)
        LSPBAL[$i]=$(sqlite3 "$D/c$i.db" "SELECT remote_amount FROM channels LIMIT 1;" 2>/dev/null)
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
            # 0 = commitment accepted, 2 = path still maturing; anything else
            # (1 = the exit cannot be completed, or a sanitizer exit code) fails
            [ "$fc_rc" = 0 ] || [ "$fc_rc" = 2 ] || note_fail "$MODE: client $i --force-close pass $pass exited $fc_rc"
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
        local v shape
        v=$(txfield "${CHEX[$i]}" pays "${BAL[$i]}")
        shape=$(txfield "${CHEX[$i]}" shape "${BAL[$i]}" "${LSPBAL[$i]:-0}")
        if [ "${v:--1}" -ge 0 ] && [ "$shape" = ok ]; then
            note_ok "client $i to_local = ${BAL[$i]} sats (output $v: own taproot script; the other outputs are the LSP's balance and the anchor)"
            CTXID[$i]="${CTXID[$i]}:$v"
        else
            note_fail "$MODE: client $i commitment outputs are not {client ${BAL[$i]}, LSP, anchor}: ${shape:-no decode}"
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
run_scenario advance_refused $((PORT + 2))

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
    printf '\033[32m=== PASS: payment left the leaf untouched; a proposed advance was refused; both clients exited with their balances ===\033[0m\n'
    exit 0
fi
printf '\033[31m=== FAIL: %d check(s) failed ===\033[0m\n' "$FAILS"
exit 1
