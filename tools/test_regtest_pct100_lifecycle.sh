#!/usr/bin/env bash
# test_regtest_pct100_lifecycle.sh — REALISTIC pct-100 lifecycle on REGTEST.
#
#   ONBOARD : N clients join with ZERO balance (--lsp-balance-pct 100: the LSP
#             holds every leaf's full capacity as inbound liquidity).
#   SEED    : the LSP pays EVERY client once over LN via the new `lsppay` CLI
#             (random PAY_MIN..PAY_MAX sats) -> each client's first sats arrive
#             as a real settled HTLC.  A 0-balance client cannot have a close
#             output, so the seed phase is what makes the (N+1)-output close
#             possible.
#   ECONOMY : MAX_PAYS random client->client payments among the funded clients
#             (random sizes) -> circulation + a real balance spread.  Insufficient-
#             balance failures are EXPECTED capacity behavior and are counted.
#   CLOSE   : CLI `close` -> convergence gate -> single 1-input (N+1)-output
#             cooperative close; assert nout == N+1 + conservation on-chain.
#   MATH    : reconcile EVERY close output as output_i == received_i - sent_i
#             (implied baseline 0 for every client -> the strictest no-skim proof).
#
# Doubles as the N=127 MAX-FINDER: N_CLIENTS=127 MAX_PAYS=300 PAY_GAP=2 finds the
# true payment ceiling (auto-stops on the first conservation violation).
#
# Usage: bash test_regtest_pct100_lifecycle.sh [BUILD_DIR]
# Env: N_CLIENTS(3) MAX_PAYS(6) PAY_MIN(1000) PAY_MAX(6000) PORT(9970)
#      PAY_SETTLE_TRIES(40) PAY_RECOVER(1) PAY_GAP(1) CLOSE_WAIT_SEC(900)
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar-lsppay/build-lsppay}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
MINERW="${MINERW:-ss_cheat_leaf_miner}"

N_CLIENTS="${N_CLIENTS:-3}"
ARITY="${ARITY:-2,4,8}"
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-2}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
PORT="${PORT:-9970}"
MAX_PAYS="${MAX_PAYS:-6}"               # c2c economy payments AFTER the seed
SEED_MIN="${SEED_MIN:-5000}"            # LN seed amounts: big enough that clients can afford economy sends
SEED_MAX="${SEED_MAX:-15000}"
ECON_MIN="${ECON_MIN:-500}"             # economy c2c amounts: small vs seeds so senders usually have the balance
ECON_MAX="${ECON_MAX:-2500}"
PAY_SETTLE_TRIES="${PAY_SETTLE_TRIES:-40}"
PAY_POLL="${PAY_POLL:-0.5}"                # settle poll granularity; lower it for large N
PAY_RECOVER="${PAY_RECOVER:-1}"
PAY_GAP="${PAY_GAP:-1}"
CLOSE_WAIT_SEC="${CLOSE_WAIT_SEC:-900}"

TAG="pct100_$$"
LSP_DB="/tmp/ss_${TAG}.db"
LSP_LOG="/tmp/ss_${TAG}_lsp.log"
FIFO="/tmp/ss_${TAG}.cli"

red(){   printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
info(){  printf '\033[36m[pct100]\033[0m %s\n' "$*"; }
ts(){ date -u +%H:%M:%S; }
die(){ red "FAIL: $*"; exit 1; }

declare -A CPID CDB CSK
LSP_PID=""; MINER_PID=""; CLI_FD_OPEN=0
cleanup(){
    [ "$CLI_FD_OPEN" = 1 ] && { exec 3>&- 2>/dev/null || true; }
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    [ -n "${LSP_PID:-}" ] && kill -9 "$LSP_PID" 2>/dev/null || true
    for i in "${!CPID[@]}"; do kill -9 "${CPID[$i]}" 2>/dev/null || true; done
    pkill -9 -f "superscalar_client --network regtest.*--port $PORT" 2>/dev/null || true
    rm -f "$FIFO" 2>/dev/null || true
    cp "$LSP_LOG" /tmp/pct100_last_lsp.log 2>/dev/null || true
}
trap cleanup EXIT
cli(){ printf '%s\n' "$1" >&3 2>/dev/null || true; }
seed_amt(){ echo $(( SEED_MIN + RANDOM % (SEED_MAX - SEED_MIN + 1) )); }
econ_amt(){ echo $(( ECON_MIN + RANDOM % (ECON_MAX - ECON_MIN + 1) )); }

settle_wait(){  # wait for the "Payment complete" count to increase past $1
    # PAY_POLL is the poll granularity.  It matters at scale: seeding is O(N)
    # serialized payments, so every payment pays the average poll latency plus
    # PAY_RECOVER.  At N=224 the defaults (0.5s poll + 1s recover) spend ~280s of
    # the ~690s seed phase asleep while the protocol itself takes milliseconds.
    # Defaults unchanged; large-N runs should lower both (PAY_POLL=0.1
    # PAY_RECOVER=0.2 cuts the seed roughly 4x).
    local before="$1" now _w
    for _w in $(seq 1 "$PAY_SETTLE_TRIES"); do
        now=$(grep -ac "Payment complete" "$LSP_LOG" 2>/dev/null); now=${now:-0}
        [ "$now" -gt "$before" ] && { sleep "$PAY_RECOVER"; return 0; }
        sleep "$PAY_POLL"
    done
    sleep "$PAY_RECOVER"; return 1
}
lsppay_cli(){ local b; b=$(grep -ac "Payment complete" "$LSP_LOG" 2>/dev/null); cli "lsppay $1 $2"; settle_wait "${b:-0}"; }
pay_cli(){    local b; b=$(grep -ac "Payment complete" "$LSP_LOG" 2>/dev/null); cli "pay $1 $2 $3"; settle_wait "${b:-0}"; }

# ---- preflight ----
[ -x "$LSP_BIN" ] && [ -x "$CLIENT_BIN" ] || die "binaries not found in $BUILD_DIR"
$BCLI getblockcount >/dev/null 2>&1 || die "regtest bitcoind not reachable ($REGTEST_CONF)"
$BCLI -named createwallet wallet_name="$MINERW" load_on_startup=false 2>/dev/null || $BCLI loadwallet "$MINERW" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$MINERW" getnewaddress 2>/dev/null); [ -n "$MINE_ADDR" ] || die "miner wallet unusable"
mine(){ $BCLI -rpcwallet="$MINERW" generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
BAL=$($BCLI -rpcwallet="$MINERW" getbalance 2>/dev/null || echo 0)
awk "BEGIN{exit !($BAL+0>0.01)}" || { mine 110; }   # top up if needed (regtest: fresh coinbase maturity)
rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$FIFO"
rm -f /tmp/ss_${TAG}_c*.log /tmp/ss_${TAG}_c*.db /tmp/ss_${TAG}_c*.db-shm /tmp/ss_${TAG}_c*.db-wal

# ---- keys (keygen's only RPC is offline getdescriptorinfo math) ----
eval "$(python3 "$(dirname "$0")/signet_strong_keygen.py" "$N_CLIENTS" "$TAG")"
[ -n "${LSP_PUBKEY:-}" ] && [ -s "${CLIENT_KEYS_FILE:-/nonexistent}" ] || die "keygen failed"
for i in $(seq 1 "$N_CLIENTS"); do
    CSK[$i]=$(sed -n "${i}p" "$CLIENT_KEYS_FILE"); CDB[$i]="/tmp/ss_${TAG}_c${CSK[$i]:0:8}.db"
done

echo "=== N=$N_CLIENTS REGTEST pct-100 REALISTIC lifecycle: onboard@0 -> LN seed -> economy($MAX_PAYS) -> $((N_CLIENTS+1))-output close + exact accounting ==="

# ---- BIRTH ----
mkfifo "$FIFO"; exec 3<>"$FIFO"; CLI_FD_OPEN=1
nohup "$LSP_BIN" --network regtest --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" --static-near-root "$STATIC_NEAR_ROOT" \
    --amount "$AMOUNT" \
    --active-blocks 500 --dying-blocks 20 --step-blocks 5 --states-per-layer 2 \
    --fee-rate 1000 --lsp-balance-pct 100 --confirm-timeout 600 \
    --max-conn-rate 100000 --max-handshakes 256 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$MINERW" --db "$LSP_DB" \
    --daemon --cli < "$FIFO" >> "$LSP_LOG" 2>&1 &
LSP_PID=$!
for i in $(seq 1 60); do sleep 1; grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break; kill -0 "$LSP_PID" 2>/dev/null || { tail -25 "$LSP_LOG"; die "LSP died before listening"; }; done
grep -q "listening on port $PORT" "$LSP_LOG" || { tail -25 "$LSP_LOG"; die "LSP never listened"; }
info "$(ts) LSP listening; launching $N_CLIENTS zero-balance clients + block miner..."
for i in $(seq 1 "$N_CLIENTS"); do
    nohup "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port "$PORT" \
        --seckey "${CSK[$i]}" --fee-rate 1000 --lsp-balance-pct 100 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i" \
        --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        --wallet "$MINERW" --db "${CDB[$i]}" \
        --daemon >> "/tmp/ss_${TAG}_c${CSK[$i]:0:8}.log" 2>&1 &
    CPID[$i]=$!
    sleep 0.1
done
( while kill -0 "$LSP_PID" 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!

CDEAD=$(( $(date +%s) + 420 )); CREATED=0
while [ "$(date +%s)" -lt "$CDEAD" ]; do
    grep -q "entering daemon mode" "$LSP_LOG" 2>/dev/null && { CREATED=1; break; }
    grep -qE "event loop failed|channel init failed|ceremony failed|FATAL" "$LSP_LOG" 2>/dev/null && { tail -30 "$LSP_LOG"; die "LSP creation failure"; }
    kill -0 "$LSP_PID" 2>/dev/null || { tail -30 "$LSP_LOG"; die "LSP died during creation"; }
    sleep 3
done
[ "$CREATED" = 1 ] || { tail -30 "$LSP_LOG"; die "factory not created in 420s"; }
green "$(ts) FACTORY LIVE — $N_CLIENTS clients onboarded with ZERO balance (pct-100)"

# ---- SEED: every client's first sats arrive over LN ----
info "$(ts) SEED: LSP pays each of the $N_CLIENTS clients over LN (lsppay, random $SEED_MIN..$SEED_MAX sats)..."
for i in $(seq 0 $((N_CLIENTS-1))); do
    lsppay_cli "$i" "$(seed_amt)" || red "$(ts)   seed of client $i did not settle (retry pass follows)"
    sleep "$PAY_GAP"
done
for i in $(seq 0 $((N_CLIENTS-1))); do
    grep -aq "Payment complete: LSP -> client $i (" "$LSP_LOG" 2>/dev/null || { info "$(ts)   retrying client $i"; lsppay_cli "$i" "$(seed_amt)" || true; }
done
SEEDED=$(grep -aoE "Payment complete: LSP -> client [0-9]+ \(" "$LSP_LOG" 2>/dev/null | sort -u | wc -l); SEEDED=${SEEDED:-0}
[ "$SEEDED" -ge "$N_CLIENTS" ] && green "$(ts) SEED complete: $SEEDED/$N_CLIENTS funded over LN" \
                                || red   "$(ts) SEED INCOMPLETE: $SEEDED/$N_CLIENTS (close will have $((SEEDED+1)) outputs)"

# ---- ECONOMY: bounded random c2c circulation (auto-stop on conservation violation) ----
info "$(ts) ECONOMY: up to $MAX_PAYS random client->client payments..."
ECON_OK=0; ECON_FAIL=0
for _k in $(seq 1 "$MAX_PAYS"); do
    if grep -aqE "CONSERVATION VIOLATION|conservation violated" "$LSP_LOG" 2>/dev/null; then
        red "$(ts) conservation violation detected after $ECON_OK settled -> STOP economy (this IS the measured ceiling)"
        break
    fi
    s=$((RANDOM % N_CLIENTS)); d=$((RANDOM % N_CLIENTS)); [ "$s" = "$d" ] && d=$(( (d+1) % N_CLIENTS ))
    if pay_cli "$s" "$d" "$(econ_amt)"; then ECON_OK=$((ECON_OK+1)); else ECON_FAIL=$((ECON_FAIL+1)); fi
    sleep "$PAY_GAP"
done
info "$(ts) economy done: $ECON_OK settled, $ECON_FAIL not settled (insufficient balance / timeout = expected capacity behavior)"

# ---- CLOSE ----
sleep 10
info "$(ts) issuing CLI close -> $((N_CLIENTS+1))-output cooperative payout..."
cli "close"
CLOSE_TXID=""; CDEAD=$(( $(date +%s) + CLOSE_WAIT_SEC ))
while [ "$(date +%s)" -lt "$CDEAD" ]; do
    CLOSE_TXID=$(grep -aoE "cooperative close confirmed! txid: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | tail -1 | awk '{print $NF}')
    [ -n "$CLOSE_TXID" ] && break
    grep -qE "cooperative close failed" "$LSP_LOG" 2>/dev/null && break
    sleep 3
done
[ -n "$CLOSE_TXID" ] || { tail -30 "$LSP_LOG"; die "cooperative close did not confirm in ${CLOSE_WAIT_SEC}s"; }
info "$(ts) close txid: $CLOSE_TXID"

# ---- VERIFY on-chain + EXACT accounting ----
FAILED=0
RES=$($BCLI getrawtransaction "$CLOSE_TXID" true 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
nout = len(d['vout']); nin = len(d['vin'])
out = round(sum(v['value'] for v in d['vout']) * 1e8)
print('nin=%d nout=%d out=%d confs=%d' % (nin, nout, out, d.get('confirmations', 0)))
")
info "close: $RES"
eval "$RES"
[ "${confs:-0}" -ge 1 ] || { red "  CHECK FAIL: not confirmed"; FAILED=1; }
[ "${nin:-0}" -eq 1 ] || { red "  CHECK FAIL: nin=${nin:-?} != 1"; FAILED=1; }
[ "${nout:-0}" -eq $((N_CLIENTS+1)) ] && green "  ok: exactly $((N_CLIENTS+1)) outputs (every onboarded-at-zero client got an LN-earned payout)" \
                                       || { red "  CHECK FAIL: nout=${nout:-?} != $((N_CLIENTS+1))"; FAILED=1; }

info "=== EXACT accounting: output_i == received_i - sent_i (baseline 0) ==="
python3 - "$LSP_LOG" "$N_CLIENTS" <<'PYEOF'
import sys, re
from collections import defaultdict
txt = open(sys.argv[1], errors="replace").read()
n = int(sys.argv[2])
c2c = re.findall(r"Payment complete: client (\d+) -> client (\d+) \((\d+) sats\)", txt)
lsp = re.findall(r"Payment complete: LSP -> client (\d+) \((\d+) sats\)", txt)
net = defaultdict(int)
for s, d, a in c2c: net[int(s)] -= int(a); net[int(d)] += int(a)
for d, a in lsp:    net[int(d)] += int(a)
i = txt.rfind("Close outputs:")
close = {int(k): int(v) for k, v in re.findall(r"Client (\d+):\s+(\d+) sats", txt[i:] if i >= 0 else "")}
print("  LN inbound (seed): %d payments, %d sats;  c2c: %d payments, %d sats moved"
      % (len(lsp), sum(int(a) for _, a in lsp), len(c2c), sum(int(a) for *_, a in c2c)))
bad = 0
for c in range(n):
    o, e = close.get(c), net.get(c, 0)
    tag = "OK " if o == e else "MISMATCH"
    if o != e: bad += 1
    print("  client %3d: output=%-8s expected(recv-sent)=%-8d %s" % (c, o, e, tag))
if bad == 0 and len(close) == n:
    print("  RECONCILE PERFECT: every output equals exactly the client's net LN flow (baseline 0) -> NO SKIM, sat-for-sat")
else:
    print("  RECONCILE FAILED: %d mismatches, %d/%d outputs present" % (bad, len(close), n)); sys.exit(1)
PYEOF
[ $? -eq 0 ] || FAILED=1

if [ "$FAILED" -eq 0 ]; then
    green "PASS: N=$N_CLIENTS pct-100 REALISTIC lifecycle — clients onboarded with ZERO sats, every sat in every"
    green "      close output was delivered over LN, and the $((N_CLIENTS+1))-output close reconciles sat-for-sat ($CLOSE_TXID)"
    exit 0
else
    die "verification gate failed (see CHECK FAIL / RECONCILE above)"
fi
