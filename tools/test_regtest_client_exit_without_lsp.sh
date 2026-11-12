#!/usr/bin/env bash
# test_regtest_client_exit_without_lsp.sh -- client exits that must work with
# the LSP gone, on a 1 LSP + 4 client regtest factory.
#
# Scenarios (all by default, or name them after BUILD_DIR):
#   expiry      LSP killed right after creation, client daemons left running.
#               Nobody may publish the distribution TX before its nLockTime;
#               once the chain reaches it the daemons publish it, it confirms,
#               it spends the factory funding output, and the daemons exit.
#   forceclose  LSP and daemons killed.  At the nLockTime a client's
#               --force-close publishes the distribution TX and none of the
#               tree (which would make it invalid); a second client's
#               --force-close sees it confirmed and publishes nothing.
#   sweep       LSP --force-close publishes the tree; every client (all four
#               slots) broadcasts its commitment and, after the CSV,
#               --sweep-to-local sweeps its to_local output.  Commitments pay
#               a fixed 154 sat for 167 vB, below the default relay floor, so
#               this scenario restarts the node with a 0.5 sat/vB floor.
#   cltv        The LSP refuses a --cltv-timeout in the past, one inside the
#               factory's lifetime and one a block short of a member's exit,
#               before it funds anything; the earliest allowed one is
#               accepted by the LSP and by every member.
#
# Run inside the regtest sandbox (REGTEST_CONF names a conf whose node this
# script starts if it is not running).  Needs sqlite3.
# Usage: test_regtest_client_exit_without_lsp.sh BUILD_DIR [SCENARIO...]

set -uo pipefail

BUILD_DIR="${1:-build}"
shift || true
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(expiry forceclose cltv sweep)
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

REGTEST_CONF="${REGTEST_CONF:-$HOME/.bitcoin/bitcoin.conf}"
export REGTEST_CONF
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
RPC=(--rpcuser "${RPCUSER:-rpcuser}" --rpcpassword "${RPCPASSWORD:-rpcpass}" --rpcport 18443)
WALLET=ss_client_exit
LSP_SECKEY=0000000000000000000000000000000000000000000000000000000000000001
LSP_PUBKEY=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
NCLI=4

T=$(mktemp -d /tmp/ss-client-exit.XXXXXX)
PIDS=()
FAILS=0
cleanup() {
    set +e
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && stop "$p"; done
    if [ "${KEEP_LOGS:-0}" = 1 ]; then echo "logs kept in $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT

say()  { echo "[$(date +%T) h=$($BCLI getblockcount 2>/dev/null)] $*"; }
fail() { echo "  FAIL: $*"; FAILS=$((FAILS + 1)); }
pass() { echo "  ok: $*"; }
stop() { kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
mine() { $BCLI generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
height() { $BCLI getblockcount; }
client_sk() { printf "%064x" $(( $1 + 2 )); }
wait_grep() { # FILE REGEX SECONDS [mine]
    local i
    for i in $(seq 1 "$3"); do
        grep -qaE "$2" "$1" 2>/dev/null && return 0
        [ "${4:-}" = mine ] && mine 1
        sleep 1
    done
    return 1
}
confs() {
    $BCLI getrawtransaction "$1" true 2>/dev/null |
        python3 -c 'import json,sys;print(json.load(sys.stdin).get("confirmations",0))' 2>/dev/null || echo -1
}
dist_hex()  { sqlite3 "$1" "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id=0;"; }
txid_of()   { $BCLI decoderawtransaction "$1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["txid"])'; }
locktime_of() { $BCLI decoderawtransaction "$1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["locktime"])'; }
funding_of() { sqlite3 "$1" "SELECT funding_txid || ':' || funding_vout FROM factories WHERE id=0;"; }
spender_of() { # TXID VOUT -> txid of the confirmed tx spending it, or empty
    python3 - "$1" "$2" <<'PY'
import json, subprocess, sys
txid, vout = sys.argv[1], int(sys.argv[2])
cli = ["bitcoin-cli", "-regtest", "-conf=" + __import__("os").environ["REGTEST_CONF"]]
tip = int(subprocess.check_output(cli + ["getblockcount"]))
for h in range(tip, max(tip - 400, 0), -1):
    bh = subprocess.check_output(cli + ["getblockhash", str(h)]).decode().strip()
    b = json.loads(subprocess.check_output(cli + ["getblock", bh, "2"]))
    for tx in b["tx"]:
        for vin in tx["vin"]:
            if vin.get("txid") == txid and vin.get("vout") == vout:
                print(tx["txid"]); sys.exit(0)
PY
}

node_up() { # [extra bitcoind args]
    if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
        bitcoind -regtest -conf="$REGTEST_CONF" -daemon "$@" >/dev/null
        for _ in $(seq 1 60); do $BCLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
    fi
    $BCLI -named createwallet wallet_name=$WALLET load_on_startup=false >/dev/null 2>&1 || true
    $BCLI loadwallet $WALLET >/dev/null 2>&1 || true
    MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
    mine 101
    say "node ready ($($BCLI getnetworkinfo | python3 -c 'import json,sys;print("relayfee",json.load(sys.stdin)["relayfee"])'))"
}

# factory_up DIR PORT [LSP args...] -- LSP daemon + 4 client daemons, waits
# until the LSP is in daemon mode and every client saved its channel.
factory_up() {
    local d=$1 port=$2 i
    shift 2
    mkdir -p "$d"
    "$LSP_BIN" --network regtest --port "$port" --clients $NCLI --amount 400000 \
        --lsp-balance-pct 50 --seckey $LSP_SECKEY "${RPC[@]}" --wallet $WALLET \
        --db "$d/lsp.db" --confirm-timeout 900 "$@" > "$d/lsp.log" 2>&1 &
    LSP_PID=$!; PIDS+=("$LSP_PID")
    wait_grep "$d/lsp.log" "listening on port $port" 60 || { fail "LSP did not listen"; return 1; }
    CLIENT_PIDS=()
    for i in $(seq 0 $((NCLI - 1))); do
        local key=(--seckey "$(client_sk "$i")")
        [ -n "${KEYFILES:-}" ] && key=(--keyfile "$d/c$i.key" --passphrase "")
        "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$port" "${key[@]}" \
            --lsp-pubkey $LSP_PUBKEY --participant-id $((i + 1)) "${RPC[@]}" \
            --db "$d/c$i.db" --daemon > "$d/c$i.log" 2>&1 &
        CLIENT_PIDS+=($!); PIDS+=($!)
        sleep 0.5
    done
}
clients_ready() { # DIR
    local i
    for i in $(seq 0 $((NCLI - 1))); do
        wait_grep "$1/c$i.log" "daemon mode active" 300 mine || { fail "client $i not ready"; return 1; }
    done
}
kill_clients() { local p; for p in "${CLIENT_PIDS[@]:-}"; do stop "$p"; done; }

# ---------------------------------------------------------------------------
scenario_expiry() {
    local d=$T/expiry
    say "=== expiry: client daemons publish the distribution TX without the LSP"
    factory_up "$d" 29961 --daemon --active-blocks 20 --dying-blocks 10 || return
    wait_grep "$d/lsp.log" "entering daemon mode" 400 mine || { fail "LSP not in daemon mode"; return; }
    clients_ready "$d" || return
    sleep 2
    stop "$LSP_PID"; say "LSP killed"
    local hex txid lt fund
    hex=$(dist_hex "$d/c0.db"); txid=$(txid_of "$hex"); lt=$(locktime_of "$hex"); fund=$(funding_of "$d/c0.db")
    say "distribution TX $txid nLockTime $lt, funding $fund"
    grep -q "distribution TX $txid stored and verified" "$d/c0.log" &&
        pass "daemon verified the stored distribution TX" ||
        fail "daemon did not report the verified distribution TX"
    while [ "$(height)" -lt $((lt - 1)) ]; do mine 1; sleep 0.3; done
    sleep 15   # several daemon checks at nLockTime - 1
    [ "$(confs "$txid")" = -1 ] && pass "not published at block $(height) < nLockTime $lt" ||
        fail "distribution TX seen before its nLockTime"
    mine 1; say "tip reached nLockTime"
    local i ok=0 by=""
    for _ in $(seq 1 60); do
        by=$(grep -l "broadcast distribution TX $txid" "$d"/c*.log 2>/dev/null | head -1)
        [ -n "$by" ] && break
        sleep 1
    done
    [ -n "$by" ] && pass "$(basename "$by" .log) daemon broadcast the distribution TX at the nLockTime" ||
        fail "no daemon broadcast the distribution TX"
    mine 1
    for i in $(seq 0 $((NCLI - 1))); do
        wait_grep "$d/c$i.log" "distribution TX $txid is confirmed" 60 mine && ok=$((ok + 1))
    done
    [ $ok -eq $NCLI ] && pass "every daemon saw it confirmed" || fail "$ok of $NCLI daemons saw it confirmed"
    [ "$(confs "$txid")" -ge 1 ] && pass "distribution TX confirmed" || fail "distribution TX not confirmed"
    [ "$(spender_of "${fund%:*}" "${fund#*:}")" = "$txid" ] &&
        pass "it spends the factory funding output" || fail "funding not spent by the distribution TX"
    sleep 3
    local alive=0
    for p in "${CLIENT_PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
    [ $alive -eq 0 ] && pass "daemons exited once settled" || fail "$alive daemons still running"
    grep -qa "non-final" "$d"/c*.log && fail "a client sent it before its nLockTime (non-final)" ||
        pass "no client sent it early"
    kill_clients
}

scenario_forceclose() {
    local d=$T/forceclose
    say "=== forceclose: --force-close at expiry publishes the distribution TX, not the tree"
    factory_up "$d" 29962 --daemon --active-blocks 20 --dying-blocks 10 || return
    wait_grep "$d/lsp.log" "entering daemon mode" 400 mine || { fail "LSP not in daemon mode"; return; }
    clients_ready "$d" || return
    sleep 2
    stop "$LSP_PID"; kill_clients; say "LSP and daemons killed"
    local hex txid lt fund
    hex=$(dist_hex "$d/c0.db"); txid=$(txid_of "$hex"); lt=$(locktime_of "$hex"); fund=$(funding_of "$d/c0.db")
    while [ "$(height)" -lt "$lt" ]; do mine 1; done
    say "tip at nLockTime $lt"
    "$CLIENT_BIN" --network regtest "${RPC[@]}" --force-close --db "$d/c0.db" > "$d/fc0.log" 2>&1
    grep -q "broadcast distribution TX $txid" "$d/fc0.log" && pass "client 0 --force-close broadcast it" ||
        fail "client 0 --force-close did not broadcast it"
    grep -q "NOT publishing the factory tree" "$d/fc0.log" && pass "and published no tree" ||
        fail "client 0 --force-close went for the tree"
    # (a tree root sent first can still lose to the higher-fee distribution
    # TX under full RBF; the check is on what this client sent)
    [ "$($BCLI getrawmempool | python3 -c 'import json,sys;print(" ".join(json.load(sys.stdin)))')" = "$txid" ] &&
        pass "mempool holds only the distribution TX" || fail "mempool: $($BCLI getrawmempool | tr -d ' \n')"
    mine 1
    "$CLIENT_BIN" --network regtest "${RPC[@]}" --force-close --db "$d/c1.db" > "$d/fc1.log" 2>&1
    grep -q "distribution TX $txid is confirmed" "$d/fc1.log" && pass "client 1 --force-close sees it confirmed" ||
        fail "client 1 --force-close did not see it confirmed"
    grep -qE "broadcast node [0-9]+ type=" "$d"/fc*.log && fail "a tree node was broadcast" ||
        pass "no tree node broadcast"
    [ "$(spender_of "${fund%:*}" "${fund#*:}")" = "$txid" ] &&
        pass "funding spent by the distribution TX" || fail "funding not spent by the distribution TX"
}

scenario_sweep() {
    local d=$T/sweep
    say "=== sweep: --sweep-to-local for every client slot"
    $BCLI stop >/dev/null 2>&1
    for _ in $(seq 1 60); do $BCLI getblockcount >/dev/null 2>&1 || break; sleep 1; done
    sleep 2
    node_up -minrelaytxfee=0.000005 -blockmintxfee=0.000005 -incrementalrelayfee=0.000005
    KEYFILES=1 factory_up "$d" 29963 --demo --force-close || return
    local i
    for _ in $(seq 1 600); do kill -0 "$LSP_PID" 2>/dev/null || break; mine 1; sleep 1; done
    kill -0 "$LSP_PID" 2>/dev/null && { fail "LSP --force-close did not finish"; stop "$LSP_PID"; }
    sleep 5; kill_clients
    for i in $(seq 0 $((NCLI - 1))); do
        local ct="" pass_n
        ct=$(sqlite3 "$d/c$i.db" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;")
        ct=$(txid_of "$ct")
        for pass_n in $(seq 1 40); do
            "$CLIENT_BIN" --network regtest "${RPC[@]}" --force-close --db "$d/c$i.db" >> "$d/fc$i.log" 2>&1
            mine 6
            [ "$(confs "$ct")" -ge 1 ] && break
        done
        [ "$(confs "$ct")" -ge 1 ] && pass "client $i commitment confirmed" || fail "client $i commitment not confirmed"
    done
    mine 150
    local dest
    dest=$($BCLI -rpcwallet=$WALLET getaddressinfo "$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)" |
           python3 -c 'import json,sys;print(json.load(sys.stdin)["scriptPubKey"])')
    for i in $(seq 0 $((NCLI - 1))); do
        "$CLIENT_BIN" --network regtest "${RPC[@]}" --db "$d/c$i.db" --keyfile "$d/c$i.key" --passphrase "" \
            --sweep-to-local --sweep-dest "$dest" > "$d/sweep$i.log" 2>&1
        local st
        st=$(grep -aoE "to_local swept! txid = [0-9a-f]{64}" "$d/sweep$i.log" | grep -oE "[0-9a-f]{64}")
        if [ -n "$st" ]; then
            mine 1
            [ "$(confs "$st")" -ge 1 ] && pass "client $i (slot $i) swept to_local: $st" ||
                fail "client $i sweep $st did not confirm"
        else
            fail "client $i sweep: $(grep -aE "ERROR|Sweep:" "$d/sweep$i.log" | tail -2 | tr '\n' ' ')"
        fi
    done
}

scenario_cltv() {
    local d=$T/cltv h
    mkdir -p "$d"
    say "=== cltv: the LSP refuses a factory timeout that is not in the future"
    h=$(height)
    local tx0
    tx0=$($BCLI -rpcwallet=$WALLET getwalletinfo | python3 -c 'import json,sys;print(json.load(sys.stdin)["txcount"])')
    # in the past
    factory_up "$d/past" 29964 --cltv-timeout $((h - 10)) || return
    for _ in $(seq 1 60); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$LSP_PID" 2>/dev/null; then fail "LSP accepted --cltv-timeout $((h - 10)) at height $h"; stop "$LSP_PID"
    else
        grep -q "factory CLTV timeout $((h - 10)) is too early" "$d/past/lsp.log" &&
            pass "past --cltv-timeout refused: $(grep -m1 'too early' "$d/past/lsp.log" | cut -c1-120)..." ||
            fail "LSP exited without the refusal: $(tail -2 "$d/past/lsp.log" | tr '\n' ' ')"
    fi
    grep -qE "funded [0-9]+ sats|funding TX broadcast" "$d/past/lsp.log" && fail "LSP funded before refusing" ||
        pass "nothing funded"
    kill_clients
    # inside the lifetime: 300 active + 50 dying, timeout 200 blocks after creation
    h=$(height)
    factory_up "$d/life" 29965 --active-blocks 300 --dying-blocks 50 --cltv-timeout $((h + 103 + 200)) || return
    for _ in $(seq 1 60); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$LSP_PID" 2>/dev/null; then fail "LSP accepted a timeout inside the factory lifetime"; stop "$LSP_PID"
    else
        grep -q "is too early" "$d/life/lsp.log" && pass "timeout inside the lifetime refused" ||
            fail "LSP exited without the refusal: $(tail -2 "$d/life/lsp.log" | tr '\n' ' ')"
    fi
    grep -qE "funded [0-9]+ sats|funding TX broadcast" "$d/life/lsp.log" && fail "LSP funded before refusing" ||
        pass "nothing funded"
    kill_clients
    local tx1
    tx1=$($BCLI -rpcwallet=$WALLET getwalletinfo | python3 -c 'import json,sys;print(json.load(sys.stdin)["txcount"])')
    [ "$tx0" = "$tx1" ] && pass "no wallet transaction" || fail "wallet transactions $tx0 -> $tx1"
    # The floor is judged at the block the factory will be created at (103
    # blocks on: 101, one more ensure_funded may mine, the funding block), and
    # a member's exit from the default shape takes 99 blocks (+6 margin): the
    # earliest timeout is h + 103 + 106.  One block less is refused before
    # anything is funded; the earliest one is accepted by LSP and members.
    h=$(height)
    factory_up "$d/edge" 29966 --cltv-timeout $((h + 103 + 105)) || return
    for _ in $(seq 1 60); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$LSP_PID" 2>/dev/null; then fail "LSP accepted a timeout one block below the floor"; stop "$LSP_PID"
    else
        grep -q "is too early" "$d/edge/lsp.log" && pass "one block below the floor refused" ||
            fail "LSP exited without the refusal: $(tail -2 "$d/edge/lsp.log" | tr '\n' ' ')"
    fi
    grep -qE "funded [0-9]+ sats|funding TX broadcast" "$d/edge/lsp.log" && fail "LSP funded before refusing" ||
        pass "nothing funded"
    kill_clients
    h=$(height)
    factory_up "$d/floor" 29967 --daemon --cltv-timeout $((h + 103 + 106)) || return
    if wait_grep "$d/floor/lsp.log" "entering daemon mode" 400; then  # no mining: members judge by their own tip
        pass "the earliest timeout is accepted by the LSP and every member"
    else
        fail "factory at the floor not created: $(grep -ahE "too early|REFUSING|WARNING" "$d/floor/"*.log | head -2 | tr '\n' ' ')"
    fi
    stop "$LSP_PID"; kill_clients
}

echo "=========== client exits without the LSP (build: $BUILD_DIR) ==========="
node_up
for s in "${SCENARIOS[@]}"; do
    case $s in
        expiry|forceclose|sweep|cltv) "scenario_$s" ;;
        *) echo "unknown scenario $s"; exit 2 ;;
    esac
done
echo
if [ $FAILS -eq 0 ]; then echo "PASS: ${SCENARIOS[*]}"; exit 0; fi
echo "FAIL: $FAILS check(s) failed"
exit 1
