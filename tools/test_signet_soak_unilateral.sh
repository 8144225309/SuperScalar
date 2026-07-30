#!/usr/bin/env bash
# test_signet_soak_unilateral.sh — N=127 SIGNET soak: birth -> 24h life -> UNILATERAL-EXIT death.
#
# ONE factory, the whole lifecycle, on real signet:
#   BIRTH : LSP --daemon (serve-forever; NO --demo auto-close; large --active-blocks
#           so the DW tree does NOT rotate within the soak -> a clean, static exit)
#           creates a 127-client PS factory; 127 client --daemon processes fund + hold.
#   LIFE  : for SOAK_SEC (default 24h) a supervisor loop runs two jobs on a wall-clock
#           cadence:
#             WATCHDOG (every WATCHDOG_SEC): respawn ANY dead client/LSP from its own DB
#               (client resumes + reconnects cleanly). This is the hardening that keeps
#               all 127 signers up where the flagship soak lost ~30 to attrition.
#             PAYMENTS (every PAY_SEC): drive a live keysend between nodes via the LSP
#               admin RPC (--rpc-file unix socket) -> a real routed HTLC over the factory.
#   DEATH : the LSP + all daemons VANISH, then a batch of EXIT_BATCH clients each
#           --force-close from its OWN db (topological multi-pass, waiting REAL signet
#           blocks -- no mining). We assert every one lands its commitment + to_local
#           ON-CHAIN and conserves. No LSP, no operator reconstruction: the exhibit that
#           earns "unilateral retrieval demonstrated at the soak's scale."
#
# NO SHORTCUTS: strong per-run keys (recoverable via the saved seed, never weak on
# public signet), real signet blocks, hard on-chain assertions on the exit. Payments
# are best-effort soak-color (reported, never a pass gate); the pass gates are 24h
# liveness + the unilateral exit landing on-chain + conservation.
#
# Usage: bash tools/test_signet_soak_unilateral.sh [BUILD_DIR]
# Env: N_CLIENTS(127) SOAK_SEC(86400) PAY_SEC(900) WATCHDOG_SEC(60) EXIT_BATCH(8)
#      AMOUNT(N*100000) ARITY(2,4,8) STATIC_NEAR_ROOT(2) KEYSEND_MSAT(1000000)
#      CREATE_WAIT_SEC(7200) PORT(9952) WALLET(ss_sig_n127)
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

SOAK_SEC="${SOAK_SEC:-86400}"          # 24h life
PAY_SEC="${PAY_SEC:-900}"              # keysend every 15 min
WATCHDOG_SEC="${WATCHDOG_SEC:-60}"     # respawn check every 60s
EXIT_BATCH="${EXIT_BATCH:-8}"          # clients that unilaterally exit at the end
KEYSEND_MSAT="${KEYSEND_MSAT:-1000000}" # 1000 sat per keysend
STAGGER="${STAGGER:-0.2}"
CREATE_WAIT_SEC="${CREATE_WAIT_SEC:-7200}"  # up to 2h for the 127-party ceremony + funding confs
# active window per DW state; large enough that the tree does NOT roll over within
# the soak (24h ~= 144 signet blocks) so the exit is from a single static epoch.
# If this trips the 2016-block CLTV ceiling at launch, lower it (the LSP rejects at
# startup, before any ceremony -> fast feedback).
ACTIVE_BLOCKS="${ACTIVE_BLOCKS:-500}"

TAG="signet_soak_uni_$$"               # PID-suffixed: a re-run must NOT clobber a prior seed
LSP_DB="/tmp/ss_${TAG}.db"
LSP_LOG="/tmp/ss_${TAG}_lsp.log"
RPC_SOCK="/tmp/ss_${TAG}.rpc"
STATUS="/tmp/ss_${TAG}.status"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[soak]\033[0m %s\n' "$*"; }
ts()    { date -u +%H:%M:%S; }

declare -A CPID CDB CSK CPUB CRESTARTS
LSP_PID=""
LSP_RESTARTS=0

cleanup() {
    [ -n "${LSP_PID:-}" ] && kill -9 "$LSP_PID" 2>/dev/null || true
    for i in "${!CPID[@]}"; do kill -9 "${CPID[$i]}" 2>/dev/null || true; done
    rm -f "$RPC_SOCK" 2>/dev/null || true
    cp "$LSP_LOG" "/tmp/soak_uni_last_lsp.log" 2>/dev/null || true
}
trap cleanup EXIT
die() { red "FAIL: $*"; exit 1; }

# --- JSON-RPC over the LSP unix socket (newline-terminated request) ---
rpc() {
    python3 - "$RPC_SOCK" "$1" <<'PY'
import socket, sys
sock, req = sys.argv[1], sys.argv[2]
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(8); s.connect(sock)
    s.sendall((req + "\n").encode()); print(s.recv(65536).decode(errors="replace").strip())
except Exception as e:
    print('{"rpc_error":"%s"}' % e)
PY
}

# --- on-chain helpers (signet) ---
commit_txid() {  # latest signed commitment txid from a client db
    local h; h=$(sqlite3 "$1" "SELECT signed_tx_hex FROM signed_commitments ORDER BY commitment_number DESC LIMIT 1;" 2>/dev/null)
    [ -z "$h" ] && return 1
    $BCLI decoderawtransaction "$h" 2>/dev/null | grep -oE '"txid": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -1
}
confs()   { $BCLI getrawtransaction "$1" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1; }
tolocal_sats() {
    $BCLI getrawtransaction "$1" true 2>/dev/null | python3 -c "import json,sys
try:
  d=json.load(sys.stdin); print(int(round(d['vout'][0]['value']*1e8)))
except Exception: print(0)" 2>/dev/null
}

launch_lsp() {
    nohup "$LSP_BIN" \
        --network signet --port "$PORT" \
        --clients "$N_CLIENTS" --arity "$ARITY" --static-near-root "$STATIC_NEAR_ROOT" \
        --amount "$AMOUNT" \
        --active-blocks "$ACTIVE_BLOCKS" --dying-blocks 20 --step-blocks 5 --states-per-layer 2 \
        --fee-rate "$FEE_RATE" --lsp-balance-pct 50 --confirm-timeout 86400 \
        --max-conn-rate 400 --max-handshakes 80 \
        --seckey "$LSP_SECKEY" \
        --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
        --wallet "$WALLET" --db "$LSP_DB" --rpc-file "$RPC_SOCK" \
        --daemon >> "$LSP_LOG" 2>&1 &
    LSP_PID=$!
}

launch_client() {  # $1 = 1-based client index
    local i="$1" sk="${CSK[$1]}" db="${CDB[$1]}"
    nohup "$CLIENT_BIN" --network signet --host 127.0.0.1 --port "$PORT" \
        --seckey "$sk" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i" \
        --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
        --wallet "$WALLET" --db "$db" \
        --daemon >> "/tmp/ss_${TAG}_c${sk:0:8}.log" 2>&1 &
    CPID[$i]=$!
}

# ============================================================================
# Preflight
# ============================================================================
[ -x "$LSP_BIN" ] || die "LSP binary not found/executable: $LSP_BIN"
[ -x "$CLIENT_BIN" ] || die "client binary not found: $CLIENT_BIN"
$BCLI getblockcount >/dev/null || die "signet bitcoind not reachable ($SIGNET_CONF)"
rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$RPC_SOCK" "$STATUS"
rm -f /tmp/ss_${TAG}_c*.log /tmp/ss_${TAG}_c*.db /tmp/ss_${TAG}_c*.db-shm /tmp/ss_${TAG}_c*.db-wal /tmp/ss_${TAG}_fc*.log

info "$(ts) loading pre-funded signet wallet '$WALLET'"
$BCLI loadwallet "$WALLET" 2>/dev/null || true
BAL=$($BCLI -rpcwallet="$WALLET" getbalance 2>/dev/null || echo 0)
awk "BEGIN{exit !($BAL+0>0)}" || die "signet wallet '$WALLET' has no spendable balance ($BAL BTC)"
info "$(ts) wallet balance: $BAL BTC  |  need ~$(awk "BEGIN{printf \"%.4f\", $AMOUNT/1e8}") BTC for funding"

# --- Strong per-run keys (never weak on shared signet) ---
eval "$(SIGNET_CONF="$SIGNET_CONF" python3 "$(dirname "$0")/signet_strong_keygen.py" "$N_CLIENTS" "$TAG")"
[ -n "${LSP_PUBKEY:-}" ] && [ -s "${CLIENT_KEYS_FILE:-/nonexistent}" ] || die "strong keygen failed"
info "$(ts) strong keys ready (LSP pub ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE)"

# --- Derive client node pubkeys (keysend destinations), same method as the keygen ---
CLIENT_PUBKEYS_FILE="/tmp/ss_${TAG}_clientpubs.txt"
python3 - "$CLIENT_KEYS_FILE" "$SIGNET_CONF" "$CLIENT_PUBKEYS_FILE" <<'PY'
import sys, subprocess, hashlib, re, json
ckfile, conf, out = sys.argv[1], sys.argv[2], sys.argv[3]
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58c(p):
    d = p + hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4]
    n = int.from_bytes(d, "big"); s = ""
    while n > 0: n, r = divmod(n, 58); s = B58[r] + s
    for b in d:
        if b == 0: s = "1" + s
        else: break
    return s
def wif(h): return b58c(bytes([0xEF]) + bytes.fromhex(h) + bytes([0x01]))
def cli(*a): return subprocess.run(["bitcoin-cli","-signet","-conf="+conf,*a], capture_output=True, text=True).stdout.strip()
with open(ckfile) as f, open(out, "w") as o:
    for line in f:
        sk = line.strip()
        if not sk:
            o.write("\n"); continue
        try:
            d = json.loads(cli("getdescriptorinfo", "pk(%s)" % wif(sk)))["descriptor"]
            m = re.search(r"pk\(([0-9a-fA-F]+)\)", d)
            o.write((m.group(1) if m else "") + "\n")
        except Exception:
            o.write("\n")
PY
[ "$(grep -c . "$CLIENT_PUBKEYS_FILE")" -ge "$N_CLIENTS" ] || die "client pubkey derivation short ($(grep -c . "$CLIENT_PUBKEYS_FILE")/$N_CLIENTS)"
info "$(ts) derived $N_CLIENTS client node pubkeys for keysend"

# load keys + pubkeys into arrays
for i in $(seq 1 "$N_CLIENTS"); do
    CSK[$i]=$(sed -n "${i}p" "$CLIENT_KEYS_FILE")
    CPUB[$i]=$(sed -n "${i}p" "$CLIENT_PUBKEYS_FILE")
    CDB[$i]="/tmp/ss_${TAG}_c${CSK[$i]:0:8}.db"
    CRESTARTS[$i]=0
done

echo "=== N=$N_CLIENTS SIGNET soak (birth -> 24h life -> unilateral exit) ==="
echo "  arity=$ARITY static=$STATIC_NEAR_ROOT amount=$AMOUNT soak=${SOAK_SEC}s pay_every=${PAY_SEC}s watchdog=${WATCHDOG_SEC}s exit_batch=$EXIT_BATCH"

# ============================================================================
# BIRTH — LSP serve-forever + 127 client daemons, wait for the factory to fund
# ============================================================================
info "$(ts) launching LSP (--daemon serve-forever, --rpc-file $RPC_SOCK)..."
launch_lsp
for i in $(seq 1 120); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 "$LSP_PID" 2>/dev/null || { tail -30 "$LSP_LOG"; die "LSP died before listening"; }
done
grep -q "listening on port $PORT" "$LSP_LOG" || { tail -30 "$LSP_LOG"; die "LSP never listened"; }
info "$(ts) LSP listening (pid $LSP_PID); launching $N_CLIENTS client daemons..."

for i in $(seq 1 "$N_CLIENTS"); do launch_client "$i"; sleep "$STAGGER"; done

info "$(ts) waiting for factory creation + funding ('entering daemon mode'; up to $((CREATE_WAIT_SEC/60)) min over real blocks)..."
CDEAD=$(( $(date +%s) + CREATE_WAIT_SEC ))
CREATED=0
while [ "$(date +%s)" -lt "$CDEAD" ]; do
    if grep -q "entering daemon mode" "$LSP_LOG" 2>/dev/null; then CREATED=1; break; fi
    if grep -qE "event loop failed|channel init failed|ceremony failed|FATAL" "$LSP_LOG" 2>/dev/null; then
        tail -40 "$LSP_LOG"; die "LSP reported a creation failure"
    fi
    kill -0 "$LSP_PID" 2>/dev/null || { tail -40 "$LSP_LOG"; die "LSP died during creation"; }
    sleep 10
done
[ "$CREATED" = 1 ] || { tail -40 "$LSP_LOG"; die "factory did not reach daemon mode within ${CREATE_WAIT_SEC}s"; }
FUND_HEIGHT=$($BCLI getblockcount 2>/dev/null)
green "$(ts) FACTORY LIVE — $N_CLIENTS-client factory funded + serving (height $FUND_HEIGHT). Beginning ${SOAK_SEC}s soak."

# confirm every exiting client persisted its INITIAL commitment (self-custody prereq, #313)
for i in $(seq 1 "$EXIT_BATCH"); do
    for w in $(seq 1 30); do
        sc=$(sqlite3 "${CDB[$i]}" "SELECT count(*) FROM signed_commitments;" 2>/dev/null || echo 0)
        [ "${sc:-0}" -ge 1 ] && break; sleep 2
    done
    [ "${sc:-0}" -ge 1 ] || die "exit client c$i has no persisted commitment (cannot self-exit) — #313 regression"
done
info "$(ts) all $EXIT_BATCH exit-batch clients have a broadcastable commitment (self-custody prereq OK)"

# ============================================================================
# LIFE — 24h supervisor loop: watchdog (respawn) + live keysend payments
# ============================================================================
START=$(date +%s); DEADLINE=$((START + SOAK_SEC)); NEXT_PAY=$((START + PAY_SEC))
PAY_OK=0; PAY_TRY=0; MIN_ALIVE=$N_CLIENTS
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    NOW=$(date +%s)

    # WATCHDOG — LSP first (its death drops all clients)
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        LSP_RESTARTS=$((LSP_RESTARTS + 1))
        info "$(ts) LSP down -> respawn #$LSP_RESTARTS (resume from DB)"
        launch_lsp
        for w in $(seq 1 60); do sleep 1; grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break; done
    fi
    # WATCHDOG — clients: respawn any that died (resume + reconnect from DB)
    ALIVE=0
    for i in $(seq 1 "$N_CLIENTS"); do
        if kill -0 "${CPID[$i]}" 2>/dev/null; then
            ALIVE=$((ALIVE + 1))
        else
            CRESTARTS[$i]=$(( CRESTARTS[$i] + 1 )); launch_client "$i"
        fi
    done
    [ "$ALIVE" -lt "$MIN_ALIVE" ] && MIN_ALIVE="$ALIVE"

    # PAYMENTS — drive one live keysend LSP -> random client (best-effort soak color)
    if [ "$NOW" -ge "$NEXT_PAY" ]; then
        NEXT_PAY=$((NOW + PAY_SEC))
        DST=$(( (RANDOM % N_CLIENTS) + 1 )); PUB="${CPUB[$DST]}"
        if [ -n "$PUB" ]; then
            PAY_TRY=$((PAY_TRY + 1))
            RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"keysend\",\"params\":{\"destination\":\"$PUB\",\"amount_msat\":$KEYSEND_MSAT}}")
            if echo "$RES" | grep -q '"payment_hash"'; then
                PAY_OK=$((PAY_OK + 1)); info "$(ts) keysend -> c$DST OK ($PAY_OK/$PAY_TRY)"
            else
                info "$(ts) keysend -> c$DST fail: $(echo "$RES" | head -c 160)"
            fi
        fi
    fi

    TOTR=0; for i in $(seq 1 "$N_CLIENTS"); do TOTR=$((TOTR + CRESTARTS[$i])); done
    H=$($BCLI getblockcount 2>/dev/null)
    printf '[%s] uptime=%ds alive=%d/%d min_alive=%d restarts=%d(lsp=%d) pay=%d/%d height=%s\n' \
        "$(ts)" "$((NOW-START))" "$ALIVE" "$N_CLIENTS" "$MIN_ALIVE" "$TOTR" "$LSP_RESTARTS" "$PAY_OK" "$PAY_TRY" "$H" | tee "$STATUS"
    sleep "$WATCHDOG_SEC"
done
SOAK_ELAPSED=$(( $(date +%s) - START ))
FINAL_ALIVE=0; for i in $(seq 1 "$N_CLIENTS"); do kill -0 "${CPID[$i]}" 2>/dev/null && FINAL_ALIVE=$((FINAL_ALIVE+1)); done
TOTR=0; for i in $(seq 1 "$N_CLIENTS"); do TOTR=$((TOTR + CRESTARTS[$i])); done
green "$(ts) SOAK COMPLETE: elapsed=${SOAK_ELAPSED}s alive=$FINAL_ALIVE/$N_CLIENTS min_alive=$MIN_ALIVE restarts=$TOTR(lsp=$LSP_RESTARTS) payments=$PAY_OK/$PAY_TRY"

# ============================================================================
# DEATH — LSP + all daemons VANISH, then EXIT_BATCH clients self-exit unilaterally
# ============================================================================
info "$(ts) === UNILATERAL EXIT: LSP + daemons VANISH, $EXIT_BATCH clients --force-close from own DB ==="
kill -9 "$LSP_PID" 2>/dev/null || true; LSP_PID=""
for i in $(seq 1 "$N_CLIENTS"); do kill -9 "${CPID[$i]}" 2>/dev/null || true; done
sleep 5

declare -a CTXID; EXPECT=0
for i in $(seq 1 "$EXIT_BATCH"); do
    CTXID[$i]=$(commit_txid "${CDB[$i]}" || echo "")
    la=$(sqlite3 "${CDB[$i]}" "SELECT local_amount FROM channels LIMIT 1;" 2>/dev/null); EXPECT=$((EXPECT + ${la:-0}))
    echo "  c$i commitment=${CTXID[$i]:-NONE} local_amount=${la:-0}"
done

CONF_N=0
for pass in $(seq 1 12); do
    FC=()
    for i in $(seq 1 "$EXIT_BATCH"); do
        "$CLIENT_BIN" --network signet \
            --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
            --force-close --db "${CDB[$i]}" >> "/tmp/ss_${TAG}_fc${i}.log" 2>&1 &
        FC+=($!)
    done
    for p in "${FC[@]}"; do wait "$p" 2>/dev/null || true; done
    # wait for a REAL signet block (no mining) between passes, up to ~20 min
    H0=$($BCLI getblockcount 2>/dev/null)
    for w in $(seq 1 80); do sleep 15; H1=$($BCLI getblockcount 2>/dev/null); [ "${H1:-0}" -gt "${H0:-0}" ] && break; done
    CONF_N=0
    for i in $(seq 1 "$EXIT_BATCH"); do c=$(confs "${CTXID[$i]}"); [ "${c:-0}" -ge 1 ] && CONF_N=$((CONF_N+1)); done
    info "$(ts) pass $pass: $CONF_N/$EXIT_BATCH commitments confirmed (height $($BCLI getblockcount 2>/dev/null))"
    [ "$CONF_N" -eq "$EXIT_BATCH" ] && break
done

ACTUAL=0
for i in $(seq 1 "$EXIT_BATCH"); do v=$(tolocal_sats "${CTXID[$i]}"); ACTUAL=$((ACTUAL + ${v:-0})); done

# ============================================================================
# VERIFY (no shortcuts) — liveness gate + unilateral-exit-on-chain gate + conservation
# ============================================================================
echo
echo "=== SOAK + UNILATERAL-EXIT ACCOUNTING ==="
echo "  soak elapsed              : ${SOAK_ELAPSED}s (target ${SOAK_SEC}s)"
echo "  daemons alive at exit     : $FINAL_ALIVE / $N_CLIENTS   (min during soak: $MIN_ALIVE)"
echo "  total watchdog restarts   : $TOTR (LSP restarts: $LSP_RESTARTS)"
echo "  live keysends settled     : $PAY_OK / $PAY_TRY"
echo "  unilateral commitments on-chain : $CONF_N / $EXIT_BATCH"
echo "  Sigma per-client local_amount    : $EXPECT sats"
echo "  Sigma on-chain to_local          : $ACTUAL sats"
[ "$EXPECT" -gt 0 ] && echo "  recovered (unilateral)    : $(awk "BEGIN{printf \"%.1f\", ($ACTUAL/$EXPECT)*100}")% of exit-batch balances (rest = commitment fees)"
echo "  exit-batch txids:"; for i in $(seq 1 "$EXIT_BATCH"); do echo "    c$i: ${CTXID[$i]:-NONE}"; done
echo "  NOTE: spending each to_local needs the client keyfile + CSV(144) — on-chain presence PROVES client-controlled, LSP-free recovery."
echo "  RECOVERY: seed=$RUN_SEED_FILE  wallet=$WALLET  (sweep exit-batch to_local after CSV + operator-sweep the remaining $((N_CLIENTS-EXIT_BATCH)) for cleanup)"

FAILED=0
# Gate 1: the factory survived the full soak (liveness hardening worked)
if [ "$SOAK_ELAPSED" -ge $((SOAK_SEC * 95 / 100)) ]; then green "  ok: soak ran full duration (${SOAK_ELAPSED}s >= 95% of ${SOAK_SEC}s)"; else red "  CHECK FAIL: soak short (${SOAK_ELAPSED}s)"; FAILED=1; fi
# Gate 2: watchdog kept the fleet up (all 127 alive at exit; every dropout was recovered)
if [ "$FINAL_ALIVE" -eq "$N_CLIENTS" ]; then green "  ok: all $N_CLIENTS signers alive at exit (watchdog recovered $TOTR dropout(s))"; else red "  CHECK FAIL: only $FINAL_ALIVE/$N_CLIENTS alive at exit"; FAILED=1; fi
# Gate 3: THE headline — unilateral exit landed every commitment on-chain, LSP absent
if [ "$CONF_N" -eq "$EXIT_BATCH" ]; then green "  ok: all $EXIT_BATCH clients self-exited unilaterally — commitments confirmed on real signet, NO LSP/operator"; else red "  CHECK FAIL: only $CONF_N/$EXIT_BATCH unilateral commitments confirmed"; FAILED=1; fi
# Gate 4: conservation on the exited balances (to_local landed the funds)
if [ "$EXPECT" -gt 0 ] && [ "$ACTUAL" -ge $((EXPECT * 70 / 100)) ] && [ "$ACTUAL" -le "$EXPECT" ]; then
    green "  ok: conservation — $ACTUAL/$EXPECT sats recovered to client-controlled to_local outputs"
else
    red "  CHECK FAIL: conservation outside bounds (actual=$ACTUAL expect=$EXPECT)"; FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
    green "PASS: N=$N_CLIENTS factory — BORN, LIVED ${SOAK_ELAPSED}s with all signers held up by the watchdog ($TOTR recoveries),"
    green "      routed $PAY_OK live keysends, and DIED by $EXIT_BATCH clients UNILATERALLY EXITING on real signet (no LSP)."
    exit 0
else
    red "FAIL: one or more gates failed (see CHECK FAIL above)"
    for i in $(seq 1 "$EXIT_BATCH"); do echo "--- fc c$i tail ---"; tail -5 "/tmp/ss_${TAG}_fc${i}.log" 2>/dev/null; done
    exit 1
fi
