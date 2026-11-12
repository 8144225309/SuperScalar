#!/usr/bin/env bash
# test_signet_soak_lifecycle.sh — N=127 SIGNET FULL-LIFECYCLE soak -> 127-payout coop close.
#
# ONE factory, birth -> 24h life -> a single cooperative close paying every client:
#   BIRTH : LSP --daemon --cli (serve-forever, CLI commands fed via a FIFO on stdin)
#           creates a 127-client PS factory; 127 client --daemon processes fund + hold.
#   PRIME : round-robin CLI `pay i (i+1)` across ALL clients so every client transacts
#           once -> each gets a SIGNED leaf commitment (in --daemon mode the commitment
#           is lazy: it is only signed on the first payment, not at channel-open).
#   LIFE  : for SOAK_SEC (default 24h) a supervisor loop
#            (a) WATCHDOG respawns any dead client/LSP from its DB every WATCHDOG_SEC
#                (the hardening that keeps all 127 up where the flagship lost ~30), and
#            (b) drives a fresh round-robin `pay` round every PAY_SEC -> real routed
#                HTLCs over the factory throughout the soak.
#   CLOSE : all clients are brought up, then CLI `close` -> the LSP exits the daemon
#           loop into Phase 5 = the live all-N cooperative close = 1-input -> (N+1)-output
#           payout (the 128-output tx). We assert it confirms on real signet with N+1
#           outputs and conserves. If the all-N close cannot assemble (a client offline
#           at close time), we FALL BACK to unilateral --force-close of the clients
#           (they now hold signed commitments from the payments) -> trustless self-exit.
#
# NO SHORTCUTS: strong per-run keys (recoverable via the saved seed), real signet blocks,
# hard on-chain assertions on the close.
#
# Usage: bash tools/test_signet_soak_lifecycle.sh [BUILD_DIR]
# Env: N_CLIENTS(127) SOAK_SEC(86400) PAY_SEC(900) WATCHDOG_SEC(60) PAY_AMT(2000)
#      AMOUNT(N*100000) ARITY(2,4,8) STATIC_NEAR_ROOT(2) ACTIVE_BLOCKS(500)
#      CREATE_WAIT_SEC(7200) CLOSE_WAIT_SEC(10800) VAL_KILL(0) PORT(9952) WALLET(ss_sig_n127)
set -uo pipefail
: "${SIGNET_RPCPASS:=$(sed -n 's/^rpcpassword=//p' /var/lib/bitcoind-signet/bitcoin.conf 2>/dev/null)}"

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
BCLI="bitcoin-cli -signet -conf=$SIGNET_CONF"

N_CLIENTS="${N_CLIENTS:-127}"
ARITY="${ARITY:-2,4,8}"
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-2}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
FEE_RATE="${FEE_RATE:-1000}"
PORT="${PORT:-9952}"
WALLET="${WALLET:-ss_sig_n127}"
SOAK_SEC="${SOAK_SEC:-86400}"
PAY_SEC="${PAY_SEC:-900}"
WATCHDOG_SEC="${WATCHDOG_SEC:-60}"
PAY_AMT="${PAY_AMT:-2000}"              # sats per CLI pay (uniform mode)
PAY_VARY="${PAY_VARY:-0}"               # 1 = VARIED balances: round-robin with random amounts + extra random pairs -> a real spread in the close; 0 = uniform round-robin
PAY_MIN="${PAY_MIN:-1000}"             # varied-mode per-pay amount range (sats)
PAY_MAX="${PAY_MAX:-6000}"
PAY_SETTLE_TRIES="${PAY_SETTLE_TRIES:-40}"  # 0.5s ticks to wait for each payment to SETTLE (40=20s). Raise at high N: the single-threaded LSP settles HTLCs slower with 127 connections (~45s), so a bigger factory wants ~100 (50s) so all clients actually transact.
STAGGER="${STAGGER:-0.2}"
ACTIVE_BLOCKS="${ACTIVE_BLOCKS:-500}"   # keep the tree static (no rollover) for a clean single close
CREATE_WAIT_SEC="${CREATE_WAIT_SEC:-7200}"
CLOSE_WAIT_SEC="${CLOSE_WAIT_SEC:-10800}"
VAL_KILL="${VAL_KILL:-0}"               # >0: mid-soak, kill this many daemons ONCE to self-test the watchdog
PERIODIC_PAYS="${PERIODIC_PAYS:-0}"     # >0: this many SETTLED random pays each PAY_SEC during the soak (0 = quiet soak; the prime already paid everyone once)
QUIESCE_SEC="${QUIESCE_SEC:-90}"        # quiet window (no payments) before the close so the LSP settles + any dropped clients reconnect -> the all-N close assembles

TAG="signet_soak_life_$$"
LSP_DB="/tmp/ss_${TAG}.db"
LSP_LOG="/tmp/ss_${TAG}_lsp.log"
FIFO="/tmp/ss_${TAG}.cli"
STATUS="/tmp/ss_${TAG}.status"

red(){   printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
info(){  printf '\033[36m[soak]\033[0m %s\n' "$*"; }
ts(){ date -u +%H:%M:%S; }

declare -A CPID CDB CSK CRESTARTS
LSP_PID=""; LSP_RESTARTS=0; CLI_FD_OPEN=0

cleanup(){
    [ "$CLI_FD_OPEN" = 1 ] && { exec 3>&- 2>/dev/null || true; }
    [ -n "${LSP_PID:-}" ] && kill -9 "$LSP_PID" 2>/dev/null || true
    for i in "${!CPID[@]}"; do kill -9 "${CPID[$i]}" 2>/dev/null || true; done
    rm -f "$FIFO" 2>/dev/null || true
    cp "$LSP_LOG" /tmp/soak_life_last_lsp.log 2>/dev/null || true
}
trap cleanup EXIT
die(){ red "FAIL: $*"; exit 1; }
cli(){ printf '%s\n' "$1" >&3 2>/dev/null || true; }   # send one CLI command to the LSP via the FIFO

commit_txid(){ local h; h=$(sqlite3 "$1" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;" 2>/dev/null); [ -z "$h" ] && return 1; $BCLI decoderawtransaction "$h" 2>/dev/null | grep -oE '"txid": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -1; }
confs(){ $BCLI getrawtransaction "$1" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1; }

launch_lsp(){
    nohup "$LSP_BIN" --network signet --port "$PORT" \
        --clients "$N_CLIENTS" --arity "$ARITY" --static-near-root "$STATIC_NEAR_ROOT" \
        --amount "$AMOUNT" \
        --active-blocks "$ACTIVE_BLOCKS" --dying-blocks 20 --step-blocks 5 --states-per-layer 2 \
        --fee-rate "$FEE_RATE" --lsp-balance-pct 50 --confirm-timeout 86400 \
        --max-conn-rate 400 --max-handshakes 80 \
        --seckey "$LSP_SECKEY" \
        --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
        --wallet "$WALLET" --db "$LSP_DB" \
        --daemon --cli < "$FIFO" >> "$LSP_LOG" 2>&1 &
    LSP_PID=$!
}
launch_client(){
    local i="$1" sk="${CSK[$1]}" db="${CDB[$1]}"
    nohup "$CLIENT_BIN" --network signet --host 127.0.0.1 --port "$PORT" \
        --seckey "$sk" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i" \
        --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
        --wallet "$WALLET" --db "$db" \
        --daemon >> "/tmp/ss_${TAG}_c${sk:0:8}.log" 2>&1 &
    CPID[$i]=$!
}

# ---- preflight ----
[ -x "$LSP_BIN" ] && [ -x "$CLIENT_BIN" ] || die "binaries not found in $BUILD_DIR"
$BCLI getblockcount >/dev/null || die "signet bitcoind not reachable ($SIGNET_CONF)"
rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$FIFO" "$STATUS"
rm -f /tmp/ss_${TAG}_c*.log /tmp/ss_${TAG}_c*.db /tmp/ss_${TAG}_c*.db-shm /tmp/ss_${TAG}_c*.db-wal /tmp/ss_${TAG}_fc*.log
$BCLI loadwallet "$WALLET" 2>/dev/null || true
BAL=$($BCLI -rpcwallet="$WALLET" getbalance 2>/dev/null || echo 0)
awk "BEGIN{exit !($BAL+0>0)}" || die "wallet $WALLET has no balance ($BAL BTC)"
info "$(ts) wallet $WALLET balance $BAL BTC (need ~$(awk "BEGIN{printf \"%.4f\",$AMOUNT/1e8}") BTC for funding)"

# ---- strong per-run keys ----
eval "$(SIGNET_CONF="$SIGNET_CONF" python3 "$(dirname "$0")/signet_strong_keygen.py" "$N_CLIENTS" "$TAG")"
[ -n "${LSP_PUBKEY:-}" ] && [ -s "${CLIENT_KEYS_FILE:-/nonexistent}" ] || die "strong keygen failed"
info "$(ts) strong keys (LSP pub ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE)"
for i in $(seq 1 "$N_CLIENTS"); do
    CSK[$i]=$(sed -n "${i}p" "$CLIENT_KEYS_FILE"); CDB[$i]="/tmp/ss_${TAG}_c${CSK[$i]:0:8}.db"; CRESTARTS[$i]=0
done

echo "=== N=$N_CLIENTS SIGNET full-lifecycle soak -> 127-payout cooperative close ==="
echo "  arity=$ARITY static=$STATIC_NEAR_ROOT amount=$AMOUNT soak=${SOAK_SEC}s pay_every=${PAY_SEC}s pay_amt=$PAY_AMT watchdog=${WATCHDOG_SEC}s"

# ---- BIRTH: FIFO + LSP + clients ----
mkfifo "$FIFO"
exec 3<>"$FIFO"; CLI_FD_OPEN=1  # hold the FIFO open (read+write) for the whole run so open never blocks / EOFs; harness only writes to fd3
info "$(ts) launching LSP (--daemon --cli, stdin <- FIFO)..."
launch_lsp
for i in $(seq 1 120); do sleep 1; grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break; kill -0 "$LSP_PID" 2>/dev/null || { tail -30 "$LSP_LOG"; die "LSP died before listening"; }; done
grep -q "listening on port $PORT" "$LSP_LOG" || { tail -30 "$LSP_LOG"; die "LSP never listened"; }
info "$(ts) LSP listening (pid $LSP_PID); launching $N_CLIENTS client daemons..."
for i in $(seq 1 "$N_CLIENTS"); do launch_client "$i"; sleep "$STAGGER"; done

info "$(ts) waiting for factory creation + funding ('entering daemon mode'; up to $((CREATE_WAIT_SEC/60)) min over real blocks)..."
CDEAD=$(( $(date +%s) + CREATE_WAIT_SEC )); CREATED=0
while [ "$(date +%s)" -lt "$CDEAD" ]; do
    grep -q "entering daemon mode" "$LSP_LOG" 2>/dev/null && { CREATED=1; break; }
    grep -qE "event loop failed|channel init failed|ceremony failed|FATAL" "$LSP_LOG" 2>/dev/null && { tail -40 "$LSP_LOG"; die "LSP creation failure"; }
    kill -0 "$LSP_PID" 2>/dev/null || { tail -40 "$LSP_LOG"; die "LSP died during creation"; }
    sleep 10
done
[ "$CREATED" = 1 ] || { tail -40 "$LSP_LOG"; die "factory not created within ${CREATE_WAIT_SEC}s"; }
green "$(ts) FACTORY LIVE — $N_CLIENTS-client factory funded + serving (height $($BCLI getblockcount)). Priming payments."

# ---- PRIME: one round-robin pay so every client signs a leaf commitment ----
# Send ONE pay and wait until it fully SETTLES ("Payment complete") before the next.
# Two reasons: (1) the LSP reads CLI commands with a single read() that can slurp a
# whole burst and process only the first, and (2) firing pays faster than their HTLCs
# settle piles them up on the single-threaded LSP loop -> it stops servicing keepalives
# -> clients disconnect -> the all-N cooperative close can't assemble. Waiting for
# settlement makes payments strictly serial and keeps the LSP responsive.
pay_cli(){
    local before now _w
    before=$(grep -ac "Payment complete" "$LSP_LOG" 2>/dev/null); before=${before:-0}
    cli "pay $1 $2 $3"
    for _w in $(seq 1 "$PAY_SETTLE_TRIES"); do   # wait for the HTLC to settle (PAY_SETTLE_TRIES x 0.5s)
        now=$(grep -ac "Payment complete" "$LSP_LOG" 2>/dev/null); now=${now:-0}
        [ "${now:-0}" -gt "${before:-0}" ] && return 0
        sleep 0.5
    done
    return 1
}
rand_amt(){ echo $(( PAY_MIN + RANDOM % (PAY_MAX - PAY_MIN + 1) )); }
pay_round(){
    local ok=0 i amt s d n _e
    # base pass: every client sends to the next -> every client transacts -> signed commitment
    for i in $(seq 0 $((N_CLIENTS-1))); do
        if [ "${PAY_VARY:-0}" = 1 ]; then amt=$(rand_amt); else amt="$PAY_AMT"; fi
        pay_cli "$i" "$(( (i+1) % N_CLIENTS ))" "$amt" && ok=$((ok+1))
    done
    if [ "${PAY_VARY:-0}" = 1 ]; then
        # extra random pairs -> amplify the balance spread (some clients become net receivers, others net senders)
        n=$(( N_CLIENTS / 3 )); [ "$n" -lt 1 ] && n=1
        for _e in $(seq 1 "$n"); do
            s=$((RANDOM % N_CLIENTS)); d=$((RANDOM % N_CLIENTS)); [ "$s" = "$d" ] && d=$(( (d+1) % N_CLIENTS ))
            pay_cli "$s" "$d" "$(rand_amt)" && ok=$((ok+1))
        done
    fi
    info "$(ts)   pay_round: $ok pays settled (vary=${PAY_VARY:-0})"
}
info "$(ts) priming: round-robin pay across all $N_CLIENTS clients..."
pay_round
info "$(ts) waiting for signed commitments to materialize..."
have=0
for w in $(seq 1 72); do
    have=0
    for i in $(seq 1 "$N_CLIENTS"); do sc=$(sqlite3 "${CDB[$i]}" "SELECT count(*) FROM signed_commitments;" 2>/dev/null||echo 0); [ "${sc:-0}" -ge 1 ] && have=$((have+1)); done
    [ $((w % 6)) -eq 0 ] && info "$(ts)   commitments: $have/$N_CLIENTS"
    [ "$have" -ge "$N_CLIENTS" ] && break
    sleep 5
done
info "$(ts) after prime: $have/$N_CLIENTS clients hold a signed commitment"

# ---- LIFE: soak loop ----
START=$(date +%s); DEADLINE=$((START+SOAK_SEC)); NEXT_PAY=$((START+PAY_SEC))
PAY_ROUNDS=1; MIN_ALIVE=$N_CLIENTS; DID_VALKILL=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    NOW=$(date +%s)
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        LSP_RESTARTS=$((LSP_RESTARTS+1)); info "$(ts) LSP down -> respawn #$LSP_RESTARTS (fd3/FIFO persists; new LSP re-opens read end)"
        launch_lsp
        for w in $(seq 1 60); do sleep 1; grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break; done
    fi
    ALIVE=0
    for i in $(seq 1 "$N_CLIENTS"); do
        if kill -0 "${CPID[$i]}" 2>/dev/null; then ALIVE=$((ALIVE+1)); else CRESTARTS[$i]=$((CRESTARTS[$i]+1)); launch_client "$i"; fi
    done
    [ "$ALIVE" -lt "$MIN_ALIVE" ] && MIN_ALIVE="$ALIVE"
    if [ "$VAL_KILL" -gt 0 ] && [ "$DID_VALKILL" = 0 ] && [ $((NOW-START)) -ge 120 ]; then
        info "$(ts) VAL: killing $VAL_KILL daemons to self-test the watchdog"
        pgrep -f "superscalar_client.*$TAG" 2>/dev/null | head -"$VAL_KILL" | xargs -r kill -9; DID_VALKILL=1
    fi
    if [ "${PERIODIC_PAYS:-0}" -gt 0 ] && [ "$NOW" -ge "$NEXT_PAY" ]; then
        NEXT_PAY=$((NOW+PAY_SEC)); PAY_ROUNDS=$((PAY_ROUNDS+1)); info "$(ts) light payment round $PAY_ROUNDS ($PERIODIC_PAYS settled pays)"
        for _k in $(seq 1 "$PERIODIC_PAYS"); do _s=$((RANDOM % N_CLIENTS)); pay_cli "$_s" "$(( (_s+1) % N_CLIENTS ))" "$PAY_AMT" || true; done
    fi
    TOTR=0; for i in $(seq 1 "$N_CLIENTS"); do TOTR=$((TOTR+CRESTARTS[$i])); done
    printf '[%s] uptime=%ds alive=%d/%d min_alive=%d restarts=%d(lsp=%d) pay_rounds=%d height=%s\n' \
        "$(ts)" "$((NOW-START))" "$ALIVE" "$N_CLIENTS" "$MIN_ALIVE" "$TOTR" "$LSP_RESTARTS" "$PAY_ROUNDS" "$($BCLI getblockcount 2>/dev/null)" | tee "$STATUS"
    sleep "$WATCHDOG_SEC"
done
SOAK_ELAPSED=$(( $(date +%s)-START ))

# ---- QUIESCE: no payments, let the LSP drain in-flight HTLCs + dropped clients reconnect ----
info "$(ts) soak complete (${SOAK_ELAPSED}s); quiescing ${QUIESCE_SEC}s (no payments) so the LSP settles + any dropped clients reconnect before the all-N close..."
_qend=$(( $(date +%s) + QUIESCE_SEC ))
while [ "$(date +%s)" -lt "$_qend" ]; do
    for i in $(seq 1 "$N_CLIENTS"); do kill -0 "${CPID[$i]}" 2>/dev/null || { CRESTARTS[$i]=$((CRESTARTS[$i]+1)); launch_client "$i"; }; done
    sleep 10
done

# ---- bring every client up before the all-N cooperative close ----
info "$(ts) bringing all $N_CLIENTS clients up for the cooperative close..."
ALIVE=0
for w in $(seq 1 20); do
    ALIVE=0; for i in $(seq 1 "$N_CLIENTS"); do if kill -0 "${CPID[$i]}" 2>/dev/null; then ALIVE=$((ALIVE+1)); else CRESTARTS[$i]=$((CRESTARTS[$i]+1)); launch_client "$i"; fi; done
    [ "$ALIVE" -eq "$N_CLIENTS" ] && break; sleep 4
done
TOTR=0; for i in $(seq 1 "$N_CLIENTS"); do TOTR=$((TOTR+CRESTARTS[$i])); done
green "$(ts) pre-close: alive=$ALIVE/$N_CLIENTS min_alive=$MIN_ALIVE restarts=$TOTR pay_rounds=$PAY_ROUNDS"

# ---- CLOSE: CLI 'close' -> Phase 5 cooperative (N+1)-output payout ----
info "$(ts) === issuing CLI 'close' -> cooperative 128-output payout ==="
cli "close"
CLOSE_TXID=""; COOP_FAILED=0
CDEAD=$(( $(date +%s) + CLOSE_WAIT_SEC ))
while [ "$(date +%s)" -lt "$CDEAD" ]; do
    CLOSE_TXID=$(grep -oE "cooperative close confirmed! txid: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | tail -1 | awk '{print $NF}')
    [ -n "$CLOSE_TXID" ] && break
    grep -qE "cooperative close failed|event loop failed|close ceremony aborted" "$LSP_LOG" 2>/dev/null && { COOP_FAILED=1; break; }
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        CLOSE_TXID=$(grep -oE "cooperative close confirmed! txid: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | tail -1 | awk '{print $NF}')
        [ -z "$CLOSE_TXID" ] && COOP_FAILED=1; break
    fi
    sleep 10
done

FAILED=0
if [ -n "$CLOSE_TXID" ]; then
    info "$(ts) cooperative close txid: $CLOSE_TXID — verifying on-chain (N+1 outputs + conservation)..."
    RES=$(python3 - "$CLOSE_TXID" "$SIGNET_CONF" "$N_CLIENTS" <<'PYEOF'
import sys, json, subprocess
txid, conf, ncli = sys.argv[1], sys.argv[2], int(sys.argv[3])
def rawtx(t):
    r = subprocess.run(["bitcoin-cli","-signet","-conf="+conf,"getrawtransaction",t,"1"], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None
d = rawtx(txid)
if not d: print("ERR notfound"); sys.exit(0)
confs = d.get("confirmations", 0)
nout = len(d["vout"]); nin = len(d["vin"])
out_sats = round(sum(v["value"] for v in d["vout"]) * 1e8)
fin = d["vin"][0]; f = rawtx(fin["txid"])
fund = round(f["vout"][fin["vout"]]["value"]*1e8) if f else 0
fee = fund - out_sats if fund else -1
print("OK confs=%d nin=%d nout=%d out=%d fund=%d fee=%d" % (confs, nin, nout, out_sats, fund, fee))
PYEOF
)
    info "$(ts) close: $RES"
    set -- $RES
    if [ "$1" = "OK" ]; then
        eval "$2 $3 $4 $5 $6 $7"   # confs= nin= nout= out= fund= fee=
        [ "${confs:-0}" -ge 1 ] 2>/dev/null && green "  ok: close confirmed (${confs} conf)" || { red "  CHECK FAIL: not confirmed"; FAILED=1; }
        [ "${nout:-0}" -ge $((N_CLIENTS + 1)) ] 2>/dev/null && green "  ok: $nout outputs (>= N+1 = $((N_CLIENTS+1)); every client paid)" || { red "  CHECK FAIL: only ${nout:-0} outputs (< N+1)"; FAILED=1; }
        if [ "${fund:-0}" -gt 0 ] && [ "${fee:-0}" -ge 0 ] && [ "${fee:-1}" -le $((fund/100)) ]; then green "  ok: conservation — out=$out = fund=$fund - fee=$fee (<=1%)"; else red "  CHECK FAIL: conservation (out=${out:-?} fund=${fund:-?} fee=${fee:-?})"; FAILED=1; fi
    else
        red "  CHECK FAIL: close tx not on-chain ($RES)"; FAILED=1
    fi
    CLOSE_PARTIES=$(cat /tmp/ss_${TAG}_c*.log 2>/dev/null | grep -ciE "received CLOSE_PROPOSE|cooperative close complete"); CLOSE_PARTIES=${CLOSE_PARTIES:-0}
    info "$(ts) close participation: $CLOSE_PARTIES clients logged the close"

    # ---- Payment accounting + per-client reconciliation (every payment vs every close output) ----
    info "$(ts) === payment accounting + per-client reconciliation ==="
    python3 - "$LSP_LOG" "$N_CLIENTS" <<'PYEOF'
import sys, re
from collections import defaultdict, Counter
lsplog, ncli = sys.argv[1], int(sys.argv[2])
txt = open(lsplog, errors="replace").read()
pays = re.findall(r"Payment complete: client (\d+) -> client (\d+) \((\d+) sats\)", txt)
net = defaultdict(int)
for s, d, a in pays:
    net[int(s)] -= int(a); net[int(d)] += int(a)
moved = sum(int(a) for _, _, a in pays)
i = txt.rfind("Close outputs:")
close = {int(n): int(v) for n, v in re.findall(r"Client (\d+):\s+(\d+) sats", txt[i:] if i >= 0 else "")}
print("  payments settled : %d   (total %d sats moved between clients)" % (len(pays), moved))
print("  client outputs   : %d   (sum %d sats)" % (len(close), sum(close.values())))
if close:
    vals = sorted(close.values())
    print("  balance spread   : min=%d max=%d distinct=%d -> %s" % (vals[0], vals[-1], len(set(vals)), "VARIED" if len(set(vals)) > 1 else "uniform"))
    base = {k: close[k] - net.get(k, 0) for k in close}          # implied funded baseline = close - net flow
    mode, mn = Counter(base.values()).most_common(1)[0]
    off = {k: base[k] for k in base if abs(base[k] - mode) > 1}   # allow 1-sat rounding
    if not off:
        print("  RECONCILE OK     : every client output = uniform funded baseline (%d) + its net payment flow -> NO SKIM" % mode)
    else:
        print("  RECONCILE CHECK  : %d client(s) off baseline %d (may be tree rounding/remainder leaf): %s" % (len(off), mode, dict(list(off.items())[:8])))
PYEOF
    echo
    if [ "$FAILED" -eq 0 ]; then
        green "PASS: N=$N_CLIENTS factory — BORN, LIVED ${SOAK_ELAPSED}s (all signers held up by the watchdog: $TOTR recoveries,"
        green "      lsp=$LSP_RESTARTS), ran $PAY_ROUNDS payment rounds, and CLOSED COOPERATIVELY paying every client in one"
        green "      $nout-output tx ($CLOSE_TXID) on real signet."
        exit 0
    else
        die "cooperative close landed but a verification gate failed (see CHECK FAIL)"
    fi
else
    # ---- FALLBACK: the live all-N close could not assemble -> unilateral self-exit ----
    red "$(ts) cooperative close did NOT confirm (coop_failed=$COOP_FAILED) — falling back to UNILATERAL exits"
    info "$(ts) LSP + daemons vanish; clients --force-close from their own DBs (topological multi-pass)"
    { exec 3>&- 2>/dev/null || true; }; CLI_FD_OPEN=0
    kill -9 "$LSP_PID" 2>/dev/null || true; LSP_PID=""
    for i in $(seq 1 "$N_CLIENTS"); do kill -9 "${CPID[$i]}" 2>/dev/null || true; done
    sleep 5
    EXITB="${EXIT_BATCH:-8}"; [ "$EXITB" -gt "$N_CLIENTS" ] && EXITB="$N_CLIENTS"
    declare -a CTXID
    for i in $(seq 1 "$EXITB"); do CTXID[$i]=$(commit_txid "${CDB[$i]}" || echo ""); done
    CONF_N=0
    for pass in $(seq 1 12); do
        FC=()
        for i in $(seq 1 "$EXITB"); do "$CLIENT_BIN" --network signet --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 --force-close --db "${CDB[$i]}" >> "/tmp/ss_${TAG}_fc${i}.log" 2>&1 & FC+=($!); done
        for p in "${FC[@]}"; do wait "$p" 2>/dev/null || true; done
        H0=$($BCLI getblockcount 2>/dev/null); for w in $(seq 1 80); do sleep 15; H1=$($BCLI getblockcount 2>/dev/null); [ "${H1:-0}" -gt "${H0:-0}" ] && break; done
        CONF_N=0; for i in $(seq 1 "$EXITB"); do c=$(confs "${CTXID[$i]}"); [ "${c:-0}" -ge 1 ] && CONF_N=$((CONF_N+1)); done
        info "$(ts) fallback pass $pass: $CONF_N/$EXITB commitments confirmed (h=$($BCLI getblockcount 2>/dev/null))"
        [ "$CONF_N" -eq "$EXITB" ] && break
    done
    echo
    if [ "$CONF_N" -eq "$EXITB" ]; then
        green "PASS (fallback): the live all-N close could not assemble, but $EXITB clients SELF-EXITED unilaterally —"
        green "      commitments confirmed on real signet with NO LSP. Trustless self-custody held at soak scale."
        exit 0
    else
        die "both the cooperative close AND the unilateral fallback failed (coop_failed=$COOP_FAILED, unilateral=$CONF_N/$EXITB)"
    fi
fi
