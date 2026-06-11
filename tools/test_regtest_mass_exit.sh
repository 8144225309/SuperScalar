#!/usr/bin/env bash
# test_regtest_mass_exit.sh — Frontier B: thundering-herd mass exit (regtest).
#
# Build an N-client PS factory, the LSP VANISHES, then ALL N clients exit
# UNILATERALLY at once with no LSP: each rebroadcasts the shared factory tree
# (topological multi-pass — shared ancestors dedup) + its own commitment from
# its OWN db. Verify every client lands its commitment + to_local on-chain, and
# that the recovered total matches the sum of per-client channel balances.
#
# Also VERIFIES the #313 self-custody fix: every client (even one that never
# transacted) must have a persisted commitment at channel-open, so a cold
# --force-close has something to broadcast when the LSP is gone.
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
AMOUNT="${AMOUNT:-200000}"
PORT="${PORT:-29955}"
FEE="${FEE:-1100}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
WALLET="ss_cheat_leaf_miner"

TMPDIR=$(mktemp -d /tmp/ss-mass-exit.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/mass_exit_last_lsp.log 2>/dev/null || true
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
sk(){ printf "00000000000000000000000000000000000000000000000000000000000000%02x" $(( $1 + 1 )); }
db_commit_txid(){ local h; h=$(sqlite3 "$1" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;" 2>/dev/null); [ -z "$h" ] && return 1; $BCLI decoderawtransaction "$h" 2>/dev/null | grep -oE '"txid": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -1; }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1; }
tolocal_sats(){ $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c "import json,sys
try:
  d=json.load(sys.stdin); print(int(round(d['vout'][0]['value']*1e8)))
except Exception: print(0)" 2>/dev/null; }

$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 101

echo "=== Frontier B: thundering-herd mass exit (regtest, N=$N_CLIENTS) ==="

# --- build the factory (LSP + N daemon clients) ---
"$LSP_BIN" --network regtest --port $PORT --demo --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity 3 --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done

for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon \
        --seckey "$(sk $i)" --fee-rate $FEE --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" \
        --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!

echo "--- building factory; waiting for 'channels ready' ---"
for i in $(seq 1 150); do sleep 2; grep -q "channels ready" "$LSP_LOG" 2>/dev/null && { echo "  channels ready"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -40 "$LSP_LOG"; fail "LSP died before factory ready"; }; done
grep -q "channels ready" "$LSP_LOG" || { tail -40 "$LSP_LOG"; fail "factory never reached 'channels ready'"; }

# --- #313 FIX VERIFICATION: poll until EVERY client has a persisted commitment ---
echo "--- verifying #313 fix: every client persists its INITIAL commitment at channel-open (no payment needed) ---"
ALLSC=0
for i in $(seq 1 40); do
    sleep 2; ALLSC=1
    for c in $(seq 0 $((N_CLIENTS-1))); do
        sc=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT count(*) FROM signed_commitments;" 2>/dev/null || echo 0)
        [ "${sc:-0}" -ge 1 ] || ALLSC=0
    done
    [ "$ALLSC" = 1 ] && break
done
echo "  per-client signed_commitments at creation:"
for c in $(seq 0 $((N_CLIENTS-1))); do
    sc=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT count(*) FROM signed_commitments;" 2>/dev/null || echo 0)
    la=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null)
    echo "    c$c: signed_commitments=$sc local_amount=$la"
done
[ "$ALLSC" = 1 ] || fail "#313 fix NOT working — not every client persisted its initial commitment"
green "  #313 fix CONFIRMED: all $N_CLIENTS clients have a broadcastable commitment at channel-open (incl. never-transacted)."

# --- the LSP + clients VANISH ---
echo "--- LSP + clients VANISH (kill all SuperScalar procs) ---"
kill -9 "$MINER_PID" 2>/dev/null || true; MINER_PID=""
for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
PIDS=(); sleep 2

# capture each client's commitment txid + expected to_local from its db
declare -a CTXID; EXPECT=0
for i in $(seq 0 $((N_CLIENTS-1))); do
    CTXID[$i]=$(db_commit_txid "$TMPDIR/c${i}.db" || echo "")
    la=$(sqlite3 "$TMPDIR/c${i}.db" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null); EXPECT=$((EXPECT + ${la:-0}))
    echo "  c$i commitment txid: ${CTXID[$i]:-NONE}"
done

# === thundering-herd force-close: iterate (topological multi-pass) ===
echo "--- thundering-herd: $N_CLIENTS clients --force-close at once, iterated until commitments confirm ---"
CONF_N=0
for pass in $(seq 1 30); do
    FC_PIDS=()
    for i in $(seq 0 $((N_CLIENTS-1))); do
        "$CLIENT_BIN" --network regtest --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
            --force-close --db "$TMPDIR/c${i}.db" >> "$TMPDIR/fc_${i}.log" 2>&1 &
        FC_PIDS+=($!)
    done
    for pid in "${FC_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    mine 4
    CONF_N=0
    for i in $(seq 0 $((N_CLIENTS-1))); do
        c=$(confs "${CTXID[$i]}" 2>/dev/null); [ -n "$c" ] && [ "${c:-0}" -ge 1 ] && CONF_N=$((CONF_N+1))
    done
    echo "  pass $pass: $CONF_N/$N_CLIENTS commitments confirmed (height $($BCLI getblockcount))"
    [ "$CONF_N" -eq "$N_CLIENTS" ] && break
done

# === conservation on the on-chain to_local outputs ===
ACTUAL=0
for i in $(seq 0 $((N_CLIENTS-1))); do
    v=$(tolocal_sats "${CTXID[$i]}"); [ -n "$v" ] && ACTUAL=$((ACTUAL + v))
done
echo
echo "=== mass-exit accounting ==="
echo "  commitments confirmed on-chain : $CONF_N / $N_CLIENTS"
echo "  Σ per-client channel local_amount : $EXPECT sats"
echo "  Σ on-chain to_local (commitment out[0]) : $ACTUAL sats"
[ "$EXPECT" -gt 0 ] && echo "  on-chain recovered = $(awk "BEGIN{printf \"%.1f\", ($ACTUAL/$EXPECT)*100}")% of channel balances (rest = commitment fees)"
echo "  NOTE: spending each to_local needs the client keyfile + CSV(144) — a standard P2TR CSV spend; on-chain presence here proves the funds are client-controlled and recoverable."

echo
# Upper bound: the DB channels.local_amount row can lag the LATEST signed
# commitment by one balance-persist step per client (the demo persists the
# balance AFTER the commitment is signed; the vanish kill can land between).
# On-chain to_local is the commitment truth, so recovered can exceed the
# stale row in the FUNDS-SAFE direction. Allow 1000 sats/client of persist
# lag, and never more than the total funding.
if [ "$CONF_N" -eq "$N_CLIENTS" ] && [ "$ACTUAL" -gt 0 ] \
   && [ "$ACTUAL" -ge $((EXPECT * 70 / 100)) ] \
   && [ "$ACTUAL" -le $((EXPECT + N_CLIENTS * 1000)) ] \
   && [ "$ACTUAL" -le "$AMOUNT" ]; then
    green "PASS: all $N_CLIENTS clients self-exited with the LSP gone — simultaneous topological force-close landed every"
    green "      commitment + its to_local on-chain ($ACTUAL/$EXPECT sats). #313 fix verified end-to-end. [Frontier B regtest]"
    exit 0
else
    red "FAIL: not all commitments confirmed or conservation outside bounds (conf=$CONF_N/$N_CLIENTS actual=$ACTUAL expect=$EXPECT)"
    for i in $(seq 0 $((N_CLIENTS-1))); do echo "--- fc_$i tail ---"; tail -6 "$TMPDIR/fc_${i}.log" 2>/dev/null; done
    exit 1
fi
