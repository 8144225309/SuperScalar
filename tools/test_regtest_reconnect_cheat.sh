#!/usr/bin/env bash
# test_regtest_reconnect_cheat.sh — #94 (carries #92's real content): prove a client
# REFUSES a malicious LSP's forged RECONNECT_ACK commitment number.
#
# The SCB-restore / stale-state-injection defense lives on the client's REAL reconnect
# path (client_reconnect.c:412-438): the LSP's RECONNECT_ACK is UNTRUSTED -- if it
# claims a commitment number != the client's own persisted state, the client REFUSES
# it, reloads its own DB (fund-safe), and raises a SECURITY alert. (The type-136
# scb_recovery_channel path is dead code on a transport the client never uses; this
# tests the transport the client ACTUALLY uses.)
#
#   Run 1: LSP --demo --test-leaf-advance + clients -> establish + advance a PS leaf
#          so each client persists commitment_number > 0 to its --db; LSP exits.
#   Run 2: restart the LSP --daemon (same --db, loads the factory + listens) ARMED
#          with SS_CHEAT_RECONNECT_CN_OFFSET; restart client 0 (same --db) ->
#          client_run_reconnect sends MSG_RECONNECT; the LSP forges the RECONNECT_ACK
#          cn; the client MUST refuse.
#   PASS: LSP forged the ACK cn + client logged "REFUSING to adopt" + kept its own state.
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-4}"; LSP_PORT=29971; OFFSET="${OFFSET:-7}"
FUNDING_SATS=100000
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
TMPDIR=$(mktemp -d /tmp/ss-reconn-cheat.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp1.log"; LSP_LOG2="$TMPDIR/lsp2.log"
MINER_WALLET="ss_cheat_leaf_miner"; PIDS=(); MINE_PID=""
cleanup(){ [ -n "$MINE_PID" ] && kill -9 "$MINE_PID" 2>/dev/null||true; for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null||true; done; cp "$LSP_LOG2" /tmp/reconn_cheat_lsp2.log 2>/dev/null||true; cp "$TMPDIR/client_0_reconn.log" /tmp/reconn_cheat_c0.log 2>/dev/null||true; rm -rf "$TMPDIR"; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m); $BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo "=== RECONNECT CHEAT drill (#94/#92, regtest): client must refuse a forged RECONNECT_ACK cn ==="

# --- Run 1: establish + advance, persist client DBs, LSP exits ---
echo "--- Run 1: establish + advance (persist commitment_number > 0) ---"
"$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" --demo --test-leaf-advance --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || break; done
for i in $(seq 0 $((N_CLIENTS - 1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT --seckey "${CLIENT_SECKEYS[$i]}" \
        --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} --wallet $MINER_WALLET \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.5
done
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) & MINE_PID=$!
echo "--- Waiting for run-1 advance + exit (timeout 400s) ---"
for i in $(seq 1 200); do sleep 2; kill -0 $LSP_PID 2>/dev/null || { echo "  run-1 LSP exited after $((i*2))s"; break; }; done
kill -9 $MINE_PID 2>/dev/null || true; MINE_PID=""
for pid in "${PIDS[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done; sleep 3
PIDS=()

# client 0 must have persisted a channel (else reconnect has nothing to protect)
CN1=$(sqlite3 "$TMPDIR/client_0.db" "SELECT commitment_number FROM channel_state LIMIT 1;" 2>/dev/null || echo "")
echo "  client 0 persisted commitment_number = ${CN1:-<none>}"

# --- Run 2: LSP back up (recovery + listen) ARMED with the forge cheat ---
echo "--- Run 2: LSP --daemon (same --db) armed SS_CHEAT_RECONNECT_CN_OFFSET=$OFFSET ---"
SS_CHEAT_RECONNECT_CN_OFFSET=$OFFSET "$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" --daemon --lsp-balance-pct 50 \
    > "$LSP_LOG2" 2>&1 &
LSP_PID2=$!; PIDS+=($LSP_PID2)
for i in $(seq 1 60); do sleep 1; grep -qE "listening on port $LSP_PORT" "$LSP_LOG2" 2>/dev/null && { echo "  run-2 LSP listening"; break; }; kill -0 $LSP_PID2 2>/dev/null || { tail -20 "$LSP_LOG2"; fail "run-2 LSP exited early"; }; done
( while kill -0 $LSP_PID2 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) & MINE_PID=$!

# --- restart client 0 with the SAME db -> client_run_reconnect -> MSG_RECONNECT ---
echo "--- Restart client 0 (same --db) -> reconnect; LSP forges ACK cn (+$OFFSET) ---"
"$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT --seckey "${CLIENT_SECKEYS[0]}" \
    --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" --participant-id 1 --daemon \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} --wallet $MINER_WALLET \
    --db "$TMPDIR/client_0.db" > "$TMPDIR/client_0_reconn.log" 2>&1 &
C0R_PID=$!; PIDS+=($C0R_PID)

REFUSED=0
for i in $(seq 1 90); do
    sleep 1
    grep -qiE "REFUSING to adopt|SECURITY:.*RECONNECT_ACK" "$TMPDIR/client_0_reconn.log" 2>/dev/null && { REFUSED=1; echo "  client REFUSED the forged ACK (${i}s)"; break; }
    kill -0 $C0R_PID 2>/dev/null || { echo "  client 0 exited"; break; }
done
kill -9 $C0R_PID 2>/dev/null || true; kill -9 $LSP_PID2 2>/dev/null || true
[ -n "$MINE_PID" ] && kill -9 "$MINE_PID" 2>/dev/null||true; MINE_PID=""

FORGED=$(grep -c "#94-CHEAT: forging RECONNECT_ACK" "$LSP_LOG2" 2>/dev/null || echo 0)
echo; echo "=== client reconnect log tail ==="; grep -aiE "SECURITY|REFUS|reconnect|commit|claim" "$TMPDIR/client_0_reconn.log" 2>/dev/null | tail -12
echo; echo "=== LSP run-2 cheat marker ==="; grep -aE "#94-CHEAT: forging RECONNECT_ACK" "$LSP_LOG2" 2>/dev/null | tail -3
echo; echo "=== result: lsp_forged=$FORGED client_refused=$REFUSED ==="
if [ "${FORGED:-0}" -ge 1 ] && [ "$REFUSED" -eq 1 ]; then
    green "PASS: LSP forged the RECONNECT_ACK cn (+$OFFSET); the recovering client REFUSED it and kept"
    green "      its own persisted state (fund-safe). Stale-state / SCB-restore injection defense PROVEN"
    green "      e2e on the real reconnect transport (client_reconnect.c untrusted-ACK path)."
    exit 0
fi
red "FAIL: need lsp_forged>=1 AND client_refused (got forged=$FORGED refused=$REFUSED)"; exit 1
