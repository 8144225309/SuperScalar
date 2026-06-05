#!/usr/bin/env bash
# test_regtest_n64_payments.sh — Stage A of the N=64/128 real-sats end-to-end
# validation (#311).
#
# Builds a full N=64 PS factory on REGTEST, opens all 64 channels with the
# clients holding balance (--lsp-balance-pct 50), routes real HTLC payments
# through the factory (--demo --payments N), then cooperatively closes and
# checks conservation.  This is the first time payments are actually moved
# through a full-size factory — every prior N=64 run was --lsp-balance-pct 50
# --force-close, which creates the tree but routes zero sats.
#
# Uses the proven daemon launch pattern from test_testnet4_n64_ps_lifecycle.sh
# (64 client daemons, staggered, with --max-conn-rate / --max-handshakes raised
# and the 600s HELLO_ACK window) so the sequential-accept loop at N=64 works.
#
# Usage: bash tools/test_regtest_n64_payments.sh [BUILD_DIR]
# Env:  N_CLIENTS (default 64)  PAYMENTS (default 8)  AMOUNT (default 3000000)
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

N_CLIENTS="${N_CLIENTS:-64}"
PAYMENTS="${PAYMENTS:-8}"
ARITY="${ARITY:-2,4,8}"
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-1}"
# Funding scales with N so each channel is a realistic ~100k sats and stays
# well above the fixed 5000-sat channel reserve at any client count.
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
FEE_RATE="${FEE_RATE:-1000}"   # sat/kvB; regtest mempool floor is generous
PORT="${PORT:-9941}"
WALLET="ss_n64_pay"
TAG="regtest_n64_payments"
LSP_DB="/tmp/ss_${TAG}.db"
LSP_LOG="/tmp/ss_${TAG}_lsp.log"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[n64-pay]\033[0m %s\n' "$*"; }
die()   { red "FAIL: $*"; cleanup; exit 1; }

cleanup() {
    pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true
    [ -n "${LSP_PID:-}" ] && kill -9 "$LSP_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG"
for n in $(seq 2 $((N_CLIENTS + 1))); do
    HEX=$(printf '%064x' "$n")
    rm -f "/tmp/ss_${TAG}_c${HEX:60:4}.db"* "/tmp/ss_${TAG}_c${HEX:60:4}.log"
done

info "regtest bitcoind reachable?"
$BCLI getblockcount >/dev/null || die "regtest bitcoind not reachable at $REGTEST_CONF"

# --- Fund the LSP wallet ---
info "preparing + funding LSP wallet '$WALLET'"
$BCLI createwallet "$WALLET" 2>/dev/null || $BCLI loadwallet "$WALLET" 2>/dev/null || true
FUND_ADDR=$($BCLI -rpcwallet="$WALLET" getnewaddress)
# Mine 101 to make a coinbase spendable, then top up if balance is thin.
$BCLI generatetoaddress 101 "$FUND_ADDR" >/dev/null
BAL=$($BCLI -rpcwallet="$WALLET" getbalance)
info "LSP wallet balance: $BAL BTC"

echo "=== regtest N=$N_CLIENTS PS payments E2E ==="
echo "  clients=$N_CLIENTS arity=$ARITY static=$STATIC_NEAR_ROOT amount=$AMOUNT payments=$PAYMENTS pct=50"

# --- Launch LSP (route payments, cooperative close; NOT --force-close) ---
nohup "$LSP_BIN" \
    --network regtest --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root "$STATIC_NEAR_ROOT" \
    --amount "$AMOUNT" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
    --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --seckey "$LSP_SECKEY" \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --wallet "$WALLET" --db "$LSP_DB" \
    --demo --payments "$PAYMENTS" \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
info "LSP pid=$LSP_PID, waiting for listen..."

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { tail -30 "$LSP_LOG"; die "LSP died before listening"; }
done
grep -q "listening on port $PORT" "$LSP_LOG" || { tail -30 "$LSP_LOG"; die "LSP never listened"; }

# --- Designate PAYMENTS sender->receiver pairs among the clients ---
# Pair j (0-based): sender = client 2j+1, receiver = client 2j+2, sharing a
# deterministic preimage.  Senders run scripted (--send DEST:AMT:PREIMAGE
# --channels), receivers run scripted (--recv PREIMAGE --channels), and they
# still take part in factory creation.  Everyone else is a passive --daemon.
# Requires 2*PAYMENTS <= N_CLIENTS.
declare -A ROLE   # client idx -> "send:DEST:PRE" | "recv:PRE" | "idle"
# Scripted payment = 1/10 of per-channel funding (10k at 100k/channel).
# Always clears the 5000-sat reserve since the client half-channel is
# ~AMOUNT/N/3 and AMOUNT/N/10 << that minus reserve.
PAY_AMT=$(( (AMOUNT / N_CLIENTS) / 10 ))
[ "$PAY_AMT" -lt 1000 ] && PAY_AMT=1000
for j in $(seq 0 $((PAYMENTS - 1))); do
    S=$((2*j + 1)); R=$((2*j + 2))
    [ "$R" -le "$N_CLIENTS" ] || break
    PRE=$(printf '%02x%062x' $((0x70 + j)) "$j")   # unique 32-byte preimage
    # The LSP routes by 0-based CLIENT INDEX (mgr->entries[dest_client]) =
    # participant-id - 1 (sender participant 1 is the LSP's "client 0").  The
    # receiver is participant R, so its dest index is R-1.  Sending R (the
    # participant-id) routed one client too far -> "recv ADD_HTLC failed".
    ROLE[$S]="send:$((R - 1)):$PRE"
    ROLE[$R]="recv:$PRE"
done

info "launching $N_CLIENTS clients ($PAYMENTS sender/receiver pairs, rest idle)..."
for i in $(seq 1 "$N_CLIENTS"); do
    SK=$(printf '%064x' $((i + 1)))   # 0x02 .. 0x(N+1)
    R="${ROLE[$i]:-idle}"
    COMMON=(--network regtest --host 127.0.0.1 --port "$PORT"
            --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50
            --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i"
            --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443
            --wallet "$WALLET" --db "/tmp/ss_${TAG}_c${SK:60:4}.db")
    case "$R" in
        send:*) DEST="${R#send:}"; DEST="${DEST%%:*}"; PRE="${R##*:}"
                EXTRA=(--channels --send "$DEST:$PAY_AMT:$PRE") ;;
        recv:*) PRE="${R#recv:}"; EXTRA=(--channels --recv "$PRE") ;;
        *)      EXTRA=(--daemon) ;;
    esac
    nohup "$CLIENT_BIN" "${COMMON[@]}" "${EXTRA[@]}" \
        > "/tmp/ss_${TAG}_c${SK:60:4}.log" 2>&1 &
    sleep 0.2
done

# Regtest needs blocks mined to confirm the funding TX + advance the lifecycle.
# Mine periodically in the background while the LSP drives the ceremony.
( for _ in $(seq 1 120); do sleep 5; $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$FUND_ADDR" >/dev/null 2>&1 || true; done ) &
MINER_PID=$!

# --- Wait for the LSP to finish (creation -> payments -> close) ---
info "waiting for ceremony + payments + close (up to ~10 min)..."
DEADLINE=$(( $(date +%s) + 600 ))
RESULT="TIMEOUT"
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if ! kill -0 $LSP_PID 2>/dev/null; then RESULT="LSP_EXITED"; break; fi
    if grep -qE "demo complete|all payments|cooperative close.*complete|close.*broadcast|DEMO COMPLETE" "$LSP_LOG" 2>/dev/null; then
        RESULT="DONE"; break
    fi
    sleep 5
done
kill -9 "$MINER_PID" 2>/dev/null || true

echo "=== result: $RESULT ==="
echo "--- LSP lifecycle evidence ---"
grep -iE "channels ready|forwarded|fulfilled|payment complete|cooperative close|SUCCESS|event loop failed|CLOSE_PROPOSE" "$LSP_LOG" 2>/dev/null | tail -40

# ============================================================================
# Strong end-to-end verification (no shortcuts).  The factory must have:
#   (1) reached the LSP SUCCESS end-state for all N clients,
#   (2) logged NO LSP-side failure,
#   (3) routed the scripted payment(s) to REAL settlement on the LSP AND both
#       client ends (sender back-fulfill + receiver auto-fulfill from the
#       registered preimage),
#   (4) cooperatively closed with the close TX CONFIRMED on-chain,
#   (5) conserved sats (close outputs == funding - fee, fee < 1%),
#   (6) had EVERY client take part in the cooperative close.
# Every check is hard; any miss fails the run.
# ============================================================================
FAILED=0
note_fail() { red   "  CHECK FAIL: $*"; FAILED=1; }
note_ok()   { green "  ok: $*"; }

# (1) LSP definitive success end-state.
if grep -qE "factory created and closed with $N_CLIENTS clients" "$LSP_LOG"; then
    note_ok "LSP SUCCESS end-state (created + closed with $N_CLIENTS clients)"
else
    note_fail "LSP never reached 'factory created and closed with $N_CLIENTS clients'"
fi

# (2) No LSP-side failure anywhere.
if grep -qE "event loop failed|cooperative close failed|failed to send CLOSE_PROPOSE" "$LSP_LOG"; then
    note_fail "LSP logged a failure: $(grep -hoE 'event loop failed|cooperative close failed|failed to send CLOSE_PROPOSE' "$LSP_LOG" | head -1)"
else
    note_ok "no LSP event-loop / close failure"
fi

# (3) Scripted payment REAL settlement — LSP side + both client ends.
#   daemon-loop settlement strings:
#     sender back-fulfill  : "Client N: HTLC M fulfilled"
#     receiver auto-fulfill : "Client N: fulfilling HTLC M with real preimage"
#     receiver arm          : "Client N: RECV armed"
LSP_FWD=$(grep -ciE "HTLC [0-9]+ forwarded" "$LSP_LOG" 2>/dev/null); LSP_FWD=${LSP_FWD:-0}
LSP_FUL=$(grep -ciE "HTLC fulfilled" "$LSP_LOG" 2>/dev/null); LSP_FUL=${LSP_FUL:-0}
RECV_ARMED=$(cat /tmp/ss_${TAG}_c*.log 2>/dev/null | grep -ciE "RECV armed"); RECV_ARMED=${RECV_ARMED:-0}
RECV_SETTLED=$(cat /tmp/ss_${TAG}_c*.log 2>/dev/null | grep -ciE "fulfilling HTLC [0-9]+ with real preimage"); RECV_SETTLED=${RECV_SETTLED:-0}
SENDER_SETTLED=$(cat /tmp/ss_${TAG}_c*.log 2>/dev/null | grep -ciE "HTLC [0-9]+ fulfilled"); SENDER_SETTLED=${SENDER_SETTLED:-0}
info "settlement: LSP fwd=$LSP_FWD ful=$LSP_FUL | client recv-armed=$RECV_ARMED recv-fulfill=$RECV_SETTLED sender-fulfill=$SENDER_SETTLED (PAYMENTS=$PAYMENTS)"
if [ "$LSP_FWD" -ge "$PAYMENTS" ] && [ "$LSP_FUL" -ge "$PAYMENTS" ] \
   && [ "$RECV_ARMED" -ge "$PAYMENTS" ] && [ "$RECV_SETTLED" -ge "$PAYMENTS" ] \
   && [ "$SENDER_SETTLED" -ge "$PAYMENTS" ]; then
    note_ok "scripted payment(s) settled end-to-end (>= $PAYMENTS on every leg)"
else
    note_fail "scripted settlement short of $PAYMENTS on some leg (fwd=$LSP_FWD ful=$LSP_FUL armed=$RECV_ARMED recv=$RECV_SETTLED send=$SENDER_SETTLED)"
fi

# (4)+(5) Cooperative close confirmed on-chain + conservation.
CLOSE_TXID=$(grep -oE "cooperative close confirmed! txid: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | tail -1 | awk '{print $NF}')
if [ -z "$CLOSE_TXID" ]; then
    note_fail "no 'cooperative close confirmed! txid:' in LSP log"
else
    note_ok "cooperative close txid: $CLOSE_TXID"
    CONS=$(python3 - "$CLOSE_TXID" "$REGTEST_CONF" <<'PYEOF'
import sys, json, subprocess
txid, conf = sys.argv[1], sys.argv[2]
def rawtx(t):
    r = subprocess.run(["bitcoin-cli","-regtest","-conf="+conf,"getrawtransaction",t,"1"],
                       capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None
d = rawtx(txid)
if not d:
    print("ERR 0 0 0 0"); sys.exit(0)
confs = d.get("confirmations", 0)
out_sats = round(sum(v["value"] for v in d["vout"]) * 1e8)
fin = d["vin"][0]
f = rawtx(fin["txid"])
fund = round(f["vout"][fin["vout"]]["value"] * 1e8) if f else 0
print(f"{confs} {out_sats} {len(d['vin'])} {len(d['vout'])} {fund}")
PYEOF
)
    set -- $CONS
    C_CONF="${1:-0}"; C_OUT="${2:-0}"; C_NVIN="${3:-0}"; C_NVOUT="${4:-0}"; FUND_VAL="${5:-0}"
    if [ "$C_CONF" = "ERR" ]; then
        note_fail "close txid not on-chain / unqueryable"
    else
        info "close: conf=$C_CONF vin=$C_NVIN vout=$C_NVOUT out_sats=$C_OUT funding_sats=$FUND_VAL"
        if [ "$C_CONF" -ge 1 ] 2>/dev/null; then note_ok "close confirmed ($C_CONF conf)"; else note_fail "close not confirmed on-chain"; fi
        if [ "$FUND_VAL" -gt 0 ] && [ "$C_OUT" -gt 0 ] && [ "$C_OUT" -le "$FUND_VAL" ]; then
            FEE=$((FUND_VAL - C_OUT)); MAXFEE=$((FUND_VAL / 100))
            if [ "$FEE" -le "$MAXFEE" ]; then
                note_ok "conservation holds: outputs=$C_OUT = funding=$FUND_VAL - fee=$FEE (<= 1%)"
            else
                note_fail "fee $FEE > 1% of funding $FUND_VAL (possible sat leak)"
            fi
        else
            note_fail "conservation violated: outputs=$C_OUT funding=$FUND_VAL (need 0 < outputs <= funding)"
        fi
    fi
fi

# (6) Every client took part in the cooperative close.
CLOSE_PARTIES=$(cat /tmp/ss_${TAG}_c*.log 2>/dev/null | grep -ciE "received CLOSE_PROPOSE"); CLOSE_PARTIES=${CLOSE_PARTIES:-0}
info "close participation: $CLOSE_PARTIES / $N_CLIENTS clients received CLOSE_PROPOSE"
if [ "$CLOSE_PARTIES" -ge "$N_CLIENTS" ]; then note_ok "all $N_CLIENTS clients joined the close"; else note_fail "only $CLOSE_PARTIES/$N_CLIENTS clients joined the close"; fi

echo
if [ "$FAILED" -eq 0 ]; then
    green "PASS: N=$N_CLIENTS PS factory — scripted payment settled end-to-end, demo ran, cooperative close confirmed on-chain, sats conserved, all clients closed."
else
    die "one or more end-to-end checks FAILED at N=$N_CLIENTS (see CHECK FAIL lines above)"
fi
