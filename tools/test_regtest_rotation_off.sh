#!/usr/bin/env bash
# test_regtest_rotation_off.sh — factory rotation is off by default.
#
# Usage: tools/test_regtest_rotation_off.sh [BUILD_DIR]     (default: build)
#
# Real daemons on regtest: one LSP (--daemon --cli), two clients, one factory,
# every client online for the whole run, the chain mined one block at a time
# through the factory's DYING window and past its expiry.
#
#   default  LSP WITHOUT --enable-rotation-experimental.  Asserted: at DYING
#            the LSP logs that it is not rotating and starts no rotation (no
#            auto-rotation, no ceremony, no retry); the CLI "rotate" command
#            is refused; a payment between the two clients still succeeds
#            while the factory is DYING; the LSP wallet makes no payment (no
#            close to the LSP wallet, no new factory funded); after expiry,
#            once its nLockTime (the factory CLTV) is reached, the LSP
#            broadcasts the co-signed distribution TX (the one every client
#            holds) and it confirms with an output for every client; both
#            clients are still running at the end.
#
#   member-first  LSP without the flag; client 0's co-signed distribution TX
#            is broadcast and confirmed the moment it becomes valid, before
#            the LSP's next tick.  Asserted: the LSP sees the funding output
#            spent and stops, without retrying or broadcasting.
#
#   opt-in   Same command line plus --enable-rotation-experimental.
#            Asserted: at DYING the LSP starts the automatic rotation.  This
#            shows that the default phase really reached the trigger.
#
# The node is the regtest bitcoind named by REGTEST_CONF (default
# ~/.bitcoin/bitcoin.conf); it must be running, with RPC credentials
# RPCUSER/RPCPASSWORD (default rpcuser/rpcpass) on RPCPORT (default 18443).
# KEEP_LOGS=1 keeps the logs.
set -euo pipefail

BUILD_DIR="$(cd "${1:-build}" && pwd)"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
[ -x "$LSP_BIN" ] && [ -x "$CLIENT_BIN" ] || { echo "FAIL: binaries not found in $BUILD_DIR"; exit 1; }

N_CLIENTS=2
FUNDING_SATS=200000
ACTIVE_BLOCKS=8
DYING_BLOCKS=6
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
RPCUSER="${RPCUSER:-rpcuser}"
RPCPASSWORD="${RPCPASSWORD:-rpcpass}"
# The LSP talks JSON-RPC to the node directly (as in production), so it can
# tell a spent output from an unknown one.
RPCPORT="${RPCPORT:-18443}"

REGTEST_CONF="${REGTEST_CONF:-$HOME/.bitcoin/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
$BCLI getblockcount >/dev/null 2>&1 || { echo "FAIL: regtest node not reachable ($REGTEST_CONF)"; exit 1; }

TMPDIR=$(mktemp -d /tmp/ss-rotation-off.XXXXXX)
MINER_WALLET="ss_rotoff_miner_$$"
PIDS=()
cleanup() {
    set +e
    exec 3>&- 2>/dev/null
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null; done
    if [ "${KEEP_LOGS:-0}" = 1 ]; then
        echo "logs kept in $TMPDIR"
    else
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

FAILED=0
check() {   # check "<description>" <command...>
    local what=$1; shift
    if "$@"; then echo "  ok:   $what"; else echo "  FAIL: $what"; FAILED=1; fi
}
count_in() { grep -a -c -E -- "$1" "$2" 2>/dev/null || true; }
is_zero() { [ "${1:-x}" = 0 ]; }
is_positive() { [ "${1:-0}" -gt 0 ] 2>/dev/null; }
at_least() { [ "${1:-0}" -ge "$2" ] 2>/dev/null; }
show_log_on_failure() {
    [ "$FAILED" = 0 ] && return 0
    echo "--- LSP log (lifecycle / rotation lines) ---"
    grep -a -E "DYING|EXPIRED|rotat|distribution|CLI:|disconnected" "$LSP_LOG" | tail -40
}

$BCLI -named createwallet wallet_name="$MINER_WALLET" load_on_startup=false >/dev/null
MINE_ADDR=$($BCLI -rpcwallet="$MINER_WALLET" -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
mine() { $BCLI generatetoaddress "$1" "$MINE_ADDR" >/dev/null; }

# wallet_sends_since WALLET BLOCKHASH — number of payments the wallet made
# after that block (confirmed or still in the mempool).
wallet_sends_since() {
    $BCLI -rpcwallet="$1" listsinceblock "$2" | python3 -c '
import json, sys
print(len({t["txid"] for t in json.load(sys.stdin)["transactions"] if t["category"] == "send"}))'
}

# start_phase NAME PORT LSP_FLAGS...
start_phase() {
    local name=$1 port=$2; shift 2
    PHASE_DIR="$TMPDIR/$name"; mkdir -p "$PHASE_DIR"
    LSP_LOG="$PHASE_DIR/lsp.log"; LSP_DB="$PHASE_DIR/lsp.db"
    LSP_WALLET="ss_rotoff_lsp_${name//-/_}_$$"

    echo
    echo "=== phase $name: superscalar_lsp $* ==="
    $BCLI -named createwallet wallet_name="$LSP_WALLET" load_on_startup=false >/dev/null
    local fund_addr
    fund_addr=$($BCLI -rpcwallet="$LSP_WALLET" -named getnewaddress address_type=bech32m)
    $BCLI -rpcwallet="$MINER_WALLET" sendtoaddress "$fund_addr" 1.0 >/dev/null
    mine 1

    # The CLI reads stdin; a FIFO held open on fd 3 feeds it.
    rm -f "$PHASE_DIR/cli"; mkfifo "$PHASE_DIR/cli"
    exec 3<>"$PHASE_DIR/cli"
    "$LSP_BIN" --network regtest --port "$port" --clients $N_CLIENTS --arity 2 \
        --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
        --active-blocks $ACTIVE_BLOCKS --dying-blocks $DYING_BLOCKS \
        --step-blocks 1 --states-per-layer 2 --lsp-balance-pct 50 \
        --seckey "$LSP_SECKEY" --rpcuser "$RPCUSER" --rpcpassword "$RPCPASSWORD" \
        --rpcport "$RPCPORT" \
        --wallet "$LSP_WALLET" --db "$LSP_DB" --demo --daemon --cli \
        "$@" < "$PHASE_DIR/cli" > "$LSP_LOG" 2>&1 &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    for _ in $(seq 1 60); do
        grep -a -q "listening on port $port" "$LSP_LOG" 2>/dev/null && break
        kill -0 "$LSP_PID" 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -20 "$LSP_LOG"; exit 1; }
        sleep 1
    done

    CLIENT_PIDS=()
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$port" \
            --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
            --participant-id $((i + 1)) --daemon \
            --rpcuser "$RPCUSER" --rpcpassword "$RPCPASSWORD" --wallet "$MINER_WALLET" \
            --db "$PHASE_DIR/client_$i.db" > "$PHASE_DIR/client_$i.log" 2>&1 &
        CLIENT_PIDS+=("$!"); PIDS+=("$!")
        sleep 0.5
    done
}

# wait_for_lsp_log PATTERN SECONDS — the LSP must log PATTERN, and stay alive
# until it does.
wait_for_lsp_log() {
    for _ in $(seq 1 "$2"); do
        grep -a -q -E -- "$1" "$LSP_LOG" 2>/dev/null && return 0
        kill -0 "$LSP_PID" 2>/dev/null || break
        sleep 1
    done
    grep -a -q -E -- "$1" "$LSP_LOG" 2>/dev/null && return 0
    echo "FAIL: LSP never logged \"$1\""; tail -40 "$LSP_LOG"; exit 1
}

# mine_until PATTERN MAX — one block at a time until the LSP logs PATTERN.
mine_until() {
    for _ in $(seq 1 "$2"); do
        grep -a -q -E -- "$1" "$LSP_LOG" 2>/dev/null && return 0
        mine 1
        sleep 2
    done
    wait_for_lsp_log "$1" 30
}

cli() { echo "$1" >&3; }

stop_phase() {
    show_log_on_failure
    exec 3>&-
    kill "$LSP_PID" "${CLIENT_PIDS[@]}" 2>/dev/null || true
    sleep 2
    kill -9 "$LSP_PID" "${CLIENT_PIDS[@]}" 2>/dev/null || true
    wait "$LSP_PID" "${CLIENT_PIDS[@]}" 2>/dev/null || true
}

# ---------------------------------------------------------------- default
start_phase default 29971
wait_for_lsp_log "daemon loop started" 300
sleep 2
BASE_HASH=$($BCLI getbestblockhash)
echo "  daemon running; height $($BCLI getblockcount)"

mine_until "ladder factory 0 -> DYING" 40
sleep 3
cli "rotate"
wait_for_lsp_log "CLI: rotation is disabled" 30
cli "pay 0 1 1000"
wait_for_lsp_log "CLI: pay (succeeded|FAILED)" 120
echo "  DYING at height $($BCLI getblockcount); CLI answered"

mine_until "ladder factory 0 -> EXPIRED" 40
EXPIRED_HEIGHT=$($BCLI getblockcount)
# The distribution TX can be relayed from its nLockTime (the factory CLTV)
# on; the LSP broadcasts it then.  A few more blocks confirm it.
mine_until "distribution TX broadcast: [0-9a-f]{64}" 60
for _ in $(seq 1 3); do mine 1; sleep 3; done

DIST_TXID=$(grep -a -o -E "distribution TX broadcast: [0-9a-f]{64}" "$LSP_LOG" | head -1 | awk '{print $NF}' || true)
DIST_LOCKTIME=0; DIST_MIN_OUT=0
DIST_CONFS=0; DIST_OUTS=0
if [ -n "$DIST_TXID" ]; then
    # No txindex: find the block that holds it among the last blocks.
    DIST_BLOCK=""
    tip=$($BCLI getblockcount)
    for h in $(seq "$tip" -1 $((tip - 10))); do
        bh=$($BCLI getblockhash "$h")
        if $BCLI getblock "$bh" 1 | grep -q "\"$DIST_TXID\""; then DIST_BLOCK=$bh; break; fi
    done
    if [ -n "$DIST_BLOCK" ]; then
        DIST_JSON=$($BCLI getrawtransaction "$DIST_TXID" true "$DIST_BLOCK" 2>/dev/null || echo '{}')
    else
        DIST_JSON=$($BCLI getrawtransaction "$DIST_TXID" true 2>/dev/null || echo '{}')
    fi
    DIST_CONFS=$(printf '%s' "$DIST_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations",0))')
    # Outputs other than the 240-sat P2A anchor.
    DIST_OUTS=$(printf '%s' "$DIST_JSON" | python3 -c '
import json, sys
t = json.load(sys.stdin)
print(sum(1 for o in t.get("vout", []) if o["scriptPubKey"]["hex"] != "51024e73"))')
    DIST_LOCKTIME=$(printf '%s' "$DIST_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("locktime",0))')
    DIST_MIN_OUT=$(printf '%s' "$DIST_JSON" | python3 -c '
import json, sys
v = [round(o["value"] * 1e8) for o in json.load(sys.stdin).get("vout", [])
     if o["scriptPubKey"]["hex"] != "51024e73"]
print(min(v) if v else 0)')
    echo "  factory EXPIRED at height $EXPIRED_HEIGHT; distribution TX nLockTime $DIST_LOCKTIME"
    echo "  distribution TX $DIST_TXID: $DIST_CONFS confirmation(s), $DIST_OUTS paying output(s)"
    printf '%s' "$DIST_JSON" | python3 -c '
import json, sys
for o in json.load(sys.stdin).get("vout", []):
    print("    vout %d: %d sat  %s" % (o["n"], round(o["value"] * 1e8), o["scriptPubKey"]["hex"][:16]))'
fi

check "the factory reached DYING and EXPIRED"     is_positive "$(count_in 'ladder factory 0 -> EXPIRED' "$LSP_LOG")"
check "at DYING the LSP said it is not rotating"  is_positive "$(count_in 'factory 0 DYING .* not rotating: rotation is disabled' "$LSP_LOG")"
check "no automatic rotation was started"         is_zero "$(count_in 'starting auto-rotation|retrying rotation|partial rotation' "$LSP_LOG")"
check "no rotation ceremony ran"                  is_zero "$(count_in 'LSP rotate:' "$LSP_LOG")"
check "the CLI rotate command was refused"        is_positive "$(count_in 'CLI: rotation is disabled' "$LSP_LOG")"
check "a payment succeeded while DYING"           is_positive "$(count_in 'CLI: pay succeeded' "$LSP_LOG")"
check "the LSP wallet made no payment"            is_zero "$(wallet_sends_since "$LSP_WALLET" "$BASE_HASH")"
check "the distribution TX was broadcast at expiry" [ -n "$DIST_TXID" ]
check "the distribution TX confirmed"             is_positive "$DIST_CONFS"
check "the LSP held the co-signed distribution TX" \
    is_positive "$(count_in 'signed distribution TX stored' "$LSP_LOG")"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    held=$(sqlite3 "$PHASE_DIR/client_$i.db" "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id = 0;" 2>/dev/null || true)
    held_txid=$( [ -n "$held" ] && $BCLI decoderawtransaction "$held" | python3 -c 'import json,sys; print(json.load(sys.stdin)["txid"])' || echo none)
    check "it is the co-signed distribution TX client $i holds" [ "$held_txid" = "$DIST_TXID" ]
done
check "the distribution TX has an output for every client ($DIST_OUTS)" \
    at_least "$DIST_OUTS" $N_CLIENTS
check "every output carries a client's share (smallest $DIST_MIN_OUT sat)" \
    at_least "$DIST_MIN_OUT" $((FUNDING_SATS / (N_CLIENTS + 1)))
check "the LSP logged where the distribution TX stands at EXPIRED" \
    is_positive "$(count_in 'factory 0 EXPIRED .* not rotating: rotation is disabled; the distribution TX is broadcast at its nLockTime' "$LSP_LOG")"
check "the LSP is still running"                  kill -0 "$LSP_PID"
check "client 0 is still running"                 kill -0 "${CLIENT_PIDS[0]}"
check "client 1 is still running"                 kill -0 "${CLIENT_PIDS[1]}"
stop_phase

# ---------------------------------------------------------------- member-first
# A member broadcasts its own copy the moment it becomes valid, before the
# LSP's next tick: the LSP finds the funding output spent and stops trying.
start_phase member-first 29973
wait_for_lsp_log "daemon loop started" 300
mine_until "ladder factory 0 -> EXPIRED" 60
HELD=$(sqlite3 "$PHASE_DIR/client_0.db" "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id = 0;")
LOCKTIME=$($BCLI decoderawtransaction "$HELD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["locktime"])')
while [ "$($BCLI getblockcount)" -lt $((LOCKTIME - 1)) ]; do mine 1; sleep 1; done
# Valid from this block on; broadcast and confirm it within milliseconds, well
# inside the LSP's 5-second tick.
mine 1
MEMBER_TXID=$($BCLI sendrawtransaction "$HELD" 2>&1 || true)
mine 1
echo "  client 0 broadcast its distribution TX at height $(( $($BCLI getblockcount) - 1 )): $MEMBER_TXID"
wait_for_lsp_log "funding output is already spent|distribution TX broadcast" 60
for _ in $(seq 1 4); do mine 1; sleep 3; done
check "client 0's broadcast was accepted"         [ "${#MEMBER_TXID}" = 64 ]
check "the LSP saw the funding spent and stopped" \
    is_positive "$(count_in 'factory 0 funding output is already spent' "$LSP_LOG")"
check "the LSP did not keep retrying"             \
    is_zero "$(count_in 'not accepted at height' "$LSP_LOG")"
check "the LSP did not broadcast it again"        \
    is_zero "$(count_in 'distribution TX broadcast:' "$LSP_LOG")"
check "the member's distribution TX confirmed"    \
    is_positive "$($BCLI gettxout "$MEMBER_TXID" 0 | python3 -c 'import json,sys; print(json.load(sys.stdin)["confirmations"])' 2>/dev/null || echo 0)"
stop_phase

# ---------------------------------------------------------------- opt-in
start_phase opt-in 29972 --enable-rotation-experimental
wait_for_lsp_log "daemon loop started" 300
sleep 2
mine_until "ladder factory 0 -> DYING" 40
wait_for_lsp_log "starting auto-rotation|LSP rotate:" 60
check "the opt-in LSP warned that rotation is enabled" \
    is_positive "$(count_in 'WARNING: --enable-rotation-experimental' "$LSP_LOG")"
check "with the opt-in, the LSP started the automatic rotation at DYING" \
    is_positive "$(count_in 'factory 0 DYING — starting auto-rotation' "$LSP_LOG")"
check "with the opt-in, there is no 'not rotating' line" \
    is_zero "$(count_in 'not rotating: rotation is disabled' "$LSP_LOG")"
stop_phase

echo
if [ "$FAILED" != 0 ]; then
    echo "rotation-off scenario: FAILED"
    exit 1
fi
echo "rotation-off scenario: PASS"
