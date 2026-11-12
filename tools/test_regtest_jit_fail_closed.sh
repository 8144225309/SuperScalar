#!/usr/bin/env bash
# test_regtest_jit_fail_closed.sh — JIT channel opens are off by default.
#
# Usage: tools/test_regtest_jit_fail_closed.sh [BUILD_DIR]     (default: build)
#
# Real daemons on regtest: one LSP, two clients, one factory.  Both clients
# run with --auto-accept-jit, so an offer would be taken if one were made.
#
# The production trigger for a JIT open is "every factory has expired and a
# client is connected".  A daemon whose clients are all online rotates the
# factory before it expires, so the scenario takes one client away: the
# rotation then cannot run, the factory expires, and the other client is
# still connected.
#
#   default    LSP WITHOUT --enable-jit-experimental, driven to that state.
#              Asserted: the LSP wallet's balance is unchanged, none of its
#              coins was spent and it made no payment; the LSP sent no
#              JIT_OFFER; nobody recorded a JIT channel.
#
#   opt-in     Same LSP command line plus --enable-jit-experimental, driven
#              the same way.  Asserted: the trigger fires and the connected
#              client is offered a JIT channel.  This shows that the default
#              phase really reached the trigger.
#
#   test-mode  LSP with --enable-jit-experimental --test-jit (the JIT test
#              mode).  Asserted: it still opens a JIT channel, funded from
#              the LSP wallet and recorded by the LSP and by the client.
#
# The other production trigger is a purchase request (lsps2.buy) from a
# factory client:
#
#   buy        LSP WITHOUT the flag; client 0 sends lsps2.get_info and then
#              lsps2.buy.  Asserted: no terms are advertised, the purchase
#              is answered with a refusal, no JIT_OFFER is sent and no JIT
#              channel is recorded.
#
#   buy-opt-in Same with --enable-jit-experimental.  Asserted: the purchase
#              is accepted and a JIT channel is opened.
#
# The node is the regtest bitcoind named by REGTEST_CONF (default
# ~/.bitcoin/bitcoin.conf); it must be running, with RPC credentials
# RPCUSER/RPCPASSWORD (default rpcuser/rpcpass).  KEEP_LOGS=1 keeps the logs.
set -euo pipefail

BUILD_DIR="$(cd "${1:-build}" && pwd)"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
[ -x "$LSP_BIN" ] && [ -x "$CLIENT_BIN" ] || { echo "FAIL: binaries not found in $BUILD_DIR"; exit 1; }

N_CLIENTS=2
FUNDING_SATS=200000
JIT_AMOUNT=50000
ACTIVE_BLOCKS=8
DYING_BLOCKS=4
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
RPCUSER="${RPCUSER:-rpcuser}"
RPCPASSWORD="${RPCPASSWORD:-rpcpass}"

REGTEST_CONF="${REGTEST_CONF:-$HOME/.bitcoin/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
$BCLI getblockcount >/dev/null 2>&1 || { echo "FAIL: regtest node not reachable ($REGTEST_CONF)"; exit 1; }

TMPDIR=$(mktemp -d /tmp/ss-jit-fail-closed.XXXXXX)
MINER_WALLET="ss_jitfc_miner_$$"
PIDS=()
cleanup() {
    set +e
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
show_log_on_failure() {
    [ "$FAILED" = 0 ] && return 0
    echo "--- LSP log (JIT / lifecycle lines) ---"
    grep -a -E "JIT|EXPIRED|DYING|rotat|disconnected" "$LSP_LOG" | tail -40
}

$BCLI -named createwallet wallet_name="$MINER_WALLET" load_on_startup=false >/dev/null
MINE_ADDR=$($BCLI -rpcwallet="$MINER_WALLET" -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
mine() { $BCLI generatetoaddress "$1" "$MINE_ADDR" >/dev/null; }

# wallet_sats WALLET — everything the wallet owns, in satoshi (confirmed,
# unconfirmed and immature).
wallet_sats() {
    $BCLI -rpcwallet="$1" getbalances | python3 -c '
import json, sys
m = json.load(sys.stdin)["mine"]
print(int(round((m["trusted"] + m["untrusted_pending"] + m["immature"]) * 1e8)))'
}
# wallet_coins WALLET — one "txid:vout" per line for every coin of the wallet.
wallet_coins() {
    $BCLI -rpcwallet="$1" listunspent 0 | python3 -c '
import json, sys
for u in json.load(sys.stdin): print("%s:%d" % (u["txid"], u["vout"]))' | sort
}
# wallet_sends_since WALLET BLOCKHASH — number of payments the wallet made
# after that block (confirmed or still in the mempool).
wallet_sends_since() {
    $BCLI -rpcwallet="$1" listsinceblock "$2" | python3 -c '
import json, sys
print(len({t["txid"] for t in json.load(sys.stdin)["transactions"] if t["category"] == "send"}))'
}
# coins_spent FILE — how many of the coins listed in FILE are no longer unspent.
coins_spent() {
    local n=0 c
    while read -r c; do
        [ -n "$c" ] || continue
        [ -n "$($BCLI gettxout "${c%:*}" "${c#*:}" true)" ] || n=$((n + 1))
    done < "$1"
    echo "$n"
}
jit_rows() { sqlite3 "$1" "SELECT COUNT(*) FROM jit_channels;" 2>/dev/null || echo "?"; }

# start_phase NAME PORT LSP_FLAGS...
# Funds a fresh LSP wallet, starts the LSP with the given extra flags and
# both clients.
start_phase() {
    local name=$1 port=$2; shift 2
    PHASE_DIR="$TMPDIR/$name"; mkdir -p "$PHASE_DIR"
    LSP_LOG="$PHASE_DIR/lsp.log"; LSP_DB="$PHASE_DIR/lsp.db"
    LSP_WALLET="ss_jitfc_lsp_${name//-/_}_$$"
    FAILED_BEFORE=$FAILED

    echo
    echo "=== phase $name: superscalar_lsp $* ==="
    $BCLI -named createwallet wallet_name="$LSP_WALLET" load_on_startup=false >/dev/null
    local fund_addr
    fund_addr=$($BCLI -rpcwallet="$LSP_WALLET" -named getnewaddress address_type=bech32m)
    $BCLI -rpcwallet="$MINER_WALLET" sendtoaddress "$fund_addr" 1.0 >/dev/null
    mine 1

    "$LSP_BIN" --network regtest --port "$port" --clients $N_CLIENTS --arity 2 \
        --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
        --active-blocks $ACTIVE_BLOCKS --dying-blocks $DYING_BLOCKS \
        --step-blocks 1 --states-per-layer 2 --lsp-balance-pct 50 \
        --seckey "$LSP_SECKEY" --rpcuser "$RPCUSER" --rpcpassword "$RPCPASSWORD" \
        --wallet "$LSP_WALLET" --db "$LSP_DB" --jit-amount $JIT_AMOUNT \
        "$@" > "$LSP_LOG" 2>&1 &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    for _ in $(seq 1 60); do
        grep -a -q "listening on port $port" "$LSP_LOG" 2>/dev/null && break
        kill -0 "$LSP_PID" 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -20 "$LSP_LOG"; exit 1; }
        sleep 1
    done

    CLIENT_PIDS=()
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        local extra=()
        if [ "$i" = 0 ] && [ -n "${CLIENT0_FLAG:-}" ]; then extra=("$CLIENT0_FLAG"); fi
        "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$port" \
            --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
            --participant-id $((i + 1)) --daemon --auto-accept-jit ${extra[@]+"${extra[@]}"} \
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

# Factory up and LSP in its daemon loop; then the last client goes away, the
# wallet state is recorded, and the chain is mined past the factory's expiry.
drive_to_expiry_with_one_client_left() {
    wait_for_lsp_log "daemon loop started" 300
    local gone=$((N_CLIENTS - 1))
    kill -9 "${CLIENT_PIDS[$gone]}" 2>/dev/null || true
    wait_for_lsp_log "client $gone disconnected" 60
    sleep 2

    BASE_HASH=$($BCLI getbestblockhash)
    BASE_SATS=$(wallet_sats "$LSP_WALLET")
    wallet_coins "$LSP_WALLET" > "$PHASE_DIR/coins.base"
    echo "  client $gone gone; LSP wallet at baseline: $BASE_SATS sat in $(wc -l < "$PHASE_DIR/coins.base") coin(s), height $($BCLI getblockcount)"

    # One block at a time so the daemon loop sees every state.
    for _ in $(seq 1 60); do
        grep -a -q "EXPIRED" "$LSP_LOG" 2>/dev/null && break
        mine 1
        sleep 2
    done
    # Several more passes of the daemon loop, and confirmations for anything
    # it may have broadcast.
    for _ in $(seq 1 12); do
        mine 1
        sleep 3
    done
    END_SATS=$(wallet_sats "$LSP_WALLET")
    echo "  LSP wallet at end:      $END_SATS sat, height $($BCLI getblockcount)"
}

stop_phase() {
    show_log_on_failure
    kill "$LSP_PID" "${CLIENT_PIDS[@]}" 2>/dev/null || true
    sleep 2
    kill -9 "$LSP_PID" "${CLIENT_PIDS[@]}" 2>/dev/null || true
    wait "$LSP_PID" "${CLIENT_PIDS[@]}" 2>/dev/null || true
}

# ---------------------------------------------------------------- default
start_phase default 29961 --demo --daemon
drive_to_expiry_with_one_client_left
check "the factory reached EXPIRED"              is_positive "$(count_in 'EXPIRED' "$LSP_LOG")"
check "the LSP is still running"                 kill -0 "$LSP_PID"
check "client 0 is still running"                kill -0 "${CLIENT_PIDS[0]}"
check "client 0 is still connected to the LSP"   is_zero "$(count_in 'client 0 (disconnected|offline)' "$LSP_LOG")"
check "LSP wallet balance unchanged ($BASE_SATS -> $END_SATS sat)" [ "$END_SATS" = "$BASE_SATS" ]
check "none of the LSP wallet's coins was spent" is_zero "$(coins_spent "$PHASE_DIR/coins.base")"
check "the LSP wallet made no payment"           is_zero "$(wallet_sends_since "$LSP_WALLET" "$BASE_HASH")"
check "the LSP did not start a JIT open"         is_zero "$(count_in 'opening JIT channel|LSP JIT:' "$LSP_LOG")"
check "client 0 received no JIT_OFFER"           is_zero "$(count_in 'JIT offer received|JIT phase' "$PHASE_DIR/client_0.log")"
check "client 0 recorded no JIT channel"         is_zero "$(jit_rows "$PHASE_DIR/client_0.db")"
check "the LSP recorded no JIT channel"          is_zero "$(jit_rows "$LSP_DB")"
stop_phase

# ---------------------------------------------------------------- opt-in
start_phase opt-in 29962 --demo --daemon --enable-jit-experimental
drive_to_expiry_with_one_client_left
check "the factory reached EXPIRED"              is_positive "$(count_in 'EXPIRED' "$LSP_LOG")"
check "the trigger fired for the connected client" \
    is_positive "$(count_in 'opening JIT channel for client 0 \(factory expired\)' "$LSP_LOG")"
check "client 0 received a JIT_OFFER"            is_positive "$(count_in 'JIT offer received' "$PHASE_DIR/client_0.log")"
check "the LSP wallet paid for a JIT funding transaction" \
    is_positive "$(wallet_sends_since "$LSP_WALLET" "$BASE_HASH")"
stop_phase

# ---------------------------------------------------------------- test-mode
start_phase test-mode 29963 --demo --enable-jit-experimental --test-jit
wait_for_lsp_log "JIT LIFECYCLE TEST: (PASS|FAIL|SKIP)" 600
sleep 2
JIT_TXID=$(sqlite3 "$LSP_DB" "SELECT funding_txid FROM jit_channels LIMIT 1;" 2>/dev/null || true)
JIT_CONFS=$($BCLI -rpcwallet="$LSP_WALLET" gettransaction "${JIT_TXID:-0}" 2>/dev/null \
    | python3 -c 'import json,sys; print(max(0, json.load(sys.stdin)["confirmations"]))' 2>/dev/null || echo 0)
check "JIT test mode passed"                     is_positive "$(count_in 'JIT LIFECYCLE TEST: PASS' "$LSP_LOG")"
check "the LSP recorded a JIT channel"           is_positive "$(jit_rows "$LSP_DB")"
check "client 0 received the JIT_OFFER"          is_positive "$(count_in 'JIT offer received' "$PHASE_DIR/client_0.log")"
check "client 0 has the JIT channel open"        is_positive "$(count_in 'JIT channel [0-9a-f]+ OPEN' "$PHASE_DIR/client_0.log")"
check "the JIT funding transaction ${JIT_TXID:-(none)} was paid by the LSP wallet and confirmed" \
    is_positive "$JIT_CONFS"
stop_phase

# wait_for_client0_log PATTERN SECONDS
wait_for_client0_log() {
    for _ in $(seq 1 "$2"); do
        grep -a -q -E -- "$1" "$PHASE_DIR/client_0.log" 2>/dev/null && return 0
        sleep 1
    done
    echo "FAIL: client 0 never logged \"$1\""; tail -20 "$PHASE_DIR/client_0.log"; FAILED=1
}

# ---------------------------------------------------------------- buy
CLIENT0_FLAG="--test-lsps2-buy"
start_phase buy 29964 --demo --daemon
wait_for_client0_log "LSPS2 BUY: (OK|FAIL)" 300
sleep 2
check "no JIT terms were advertised"             is_positive "$(count_in 'LSPS2 GET_INFO: FAIL' "$PHASE_DIR/client_0.log")"
check "client 0 sent lsps2.buy"                  is_positive "$(count_in 'sent lsps2.buy request' "$PHASE_DIR/client_0.log")"
check "the purchase was answered with a refusal" is_positive "$(count_in 'LSPS2 BUY: FAIL' "$PHASE_DIR/client_0.log")"
check "the LSP did not start a JIT open"         is_zero "$(count_in 'opening JIT channel|LSP JIT:' "$LSP_LOG")"
check "client 0 received no JIT_OFFER"           is_zero "$(count_in 'JIT offer received|JIT phase' "$PHASE_DIR/client_0.log")"
check "client 0 recorded no JIT channel"         is_zero "$(jit_rows "$PHASE_DIR/client_0.db")"
check "the LSP recorded no JIT channel"          is_zero "$(jit_rows "$LSP_DB")"
stop_phase

# ---------------------------------------------------------------- buy-opt-in
start_phase buy-opt-in 29965 --demo --daemon --enable-jit-experimental
wait_for_client0_log "LSPS2 BUY: (OK|FAIL)" 300
sleep 2
check "JIT terms were advertised"                is_positive "$(count_in 'LSPS2 GET_INFO: OK' "$PHASE_DIR/client_0.log")"
check "the purchase was accepted"                is_positive "$(count_in 'LSPS2 BUY: OK' "$PHASE_DIR/client_0.log")"
check "client 0 received a JIT_OFFER"            is_positive "$(count_in 'JIT offer received' "$PHASE_DIR/client_0.log")"
check "the LSP recorded a JIT channel"           is_positive "$(jit_rows "$LSP_DB")"
stop_phase
CLIENT0_FLAG=""

echo
if [ "$FAILED" != 0 ]; then
    echo "JIT fail-closed scenario: FAILED"
    exit 1
fi
echo "JIT fail-closed scenario: PASS"
