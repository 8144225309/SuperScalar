#!/usr/bin/env bash
# test_regtest_hashlock_poison_subfactory_e2e.sh — #53 sub-factory hashlock
# L-stock (sales-stock) poison end-to-end on regtest, through the LIVE
# LSP<->client daemon ceremony.  Sub-factory sibling of
# test_regtest_hashlock_poison_e2e.sh (the leaf-advance variant).
#
# Proof that the sub-factory hashlock phases work together over the wire:
#   1. LSP runs --enable-hashlock-poison --cheat-daemon-sub: it builds a
#      hashlock-gated k>=2 PS factory, then advances a SUB-factory chain over
#      the REAL multi-input wire ceremony with running clients.  During the
#      advance:
#        - Phase 0: the sub bumps its per-state counter + re-commits H_new on
#          the sales-stock SPK (each sub state a DISTINCT hash),
#        - Phase 1: the LSP ships H_new in SUBFACTORY_PROPOSE_INTENT; the
#          seedless client mirrors it (builds the same sales-stock SPK),
#        - the prep-before-advance NULL override targets the superseded H_old,
#        - both sides co-sign the Leaf-P sub poison against H_old (script-path,
#          untweaked sub N-of-N agg),
#        - Phase 2: after DONE the LSP reveals secret_old to EVERY sub client;
#          each verifies SHA256(secret)==H_old and PERSISTS the row
#          (l_stock_poison_reveals) with the template + the revealed secret.
#   2. The cheating LSP broadcasts the SUPERSEDED chain[N-1] sub state on-chain
#      (trying to over-claim the sub sales-stock at a revoked state).
#   3. The CLIENT recourse tool (superscalar_lstock_recover) loads the persisted
#      reveal for the SUB node, assembles the Leaf-P poison [agg_sig, secret,
#      script, control block], and we broadcast it.
#   4. ASSERT: the poison CONFIRMS on-chain and redistributes the sales-stock
#      to the sub clients (a real, non-dust output) — the economic outcome.
#   5. ANTI-VACUITY: with the revealed secret removed, the tool REFUSES (exit 5)
#      — no reveal, no recourse (the #53 security property).
#
# Models the client-driven recourse (the secret-less standalone WT cannot
# assemble a hashlock poison alone — see #62).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
REC_BIN="$BUILD_DIR/superscalar_lstock_recover"

N_CLIENTS="${N_CLIENTS:-4}"          # k^2 = 4 for k=2
PS_SUB_ARITY="${PS_SUB_ARITY:-2}"

FUNDING_SATS="${FUNDING_SATS:-400000}"
LSP_PORT=29958                # distinct from leaf hashlock e2e (29957)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000006"
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000008"
    "0000000000000000000000000000000000000000000000000000000000000009"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

# ASan preload only when the binaries are actually ASan-linked.
ASAN_ENV="ASAN_OPTIONS=detect_leaks=0"
if ldd "$LSP_BIN" 2>/dev/null | grep -q libasan; then
    ASAN_ENV="ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8"
fi

TMPDIR=$(mktemp -d /tmp/ss-hashlock-sub-e2e.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
WT_DB="$TMPDIR/wt.db"
MINER_WALLET="ss_cheat_leaf_miner"
CPFP_WALLET="ss_cpfp_race"        # #60: spends ANY client's poison output to CPFP-bump it

PIDS=()
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/hashlock_sub_e2e_last_lsp.log 2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/hashlock_sub_e2e_last_client_${i}.log" 2>/dev/null || true
    done
    $BCLI unloadwallet "$CPFP_WALLET" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== HASHLOCK SUB-FACTORY L-STOCK POISON E2E (regtest, #53) ==="
echo "  build dir : $BUILD_DIR"
echo "  N clients : $N_CLIENTS   k(sub arity): $PS_SUB_ARITY   funding: $FUNDING_SATS sats"
echo "  bitcoind  : $REGTEST_CONF"
echo

# --- bitcoind ---
echo "--- bitcoind regtest check ---"
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, height $($BCLI getblockcount)"

$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready, 101 blocks mined"

# --- #60 CPFP fee-race pre-stage (SS_POISON_CPFP_RACE=1) ---
# The poison is a pre-signed, FIXED-FEE tx: the N-of-N agg-sig binds its outputs,
# so it is NOT RBF-able.  Its ONLY fee-bump is a CPFP child on a client's own
# P2TR(client_key) output (factory.c:3581 "any client can trivially CPFP").  We
# pre-stage a wallet over tr(<each client WIF>) BEFORE the poison broadcasts, so
# it ingests the unconfirmed poison output from the mempool and can spend it.
if [ "${SS_POISON_CPFP_RACE:-0}" = 1 ]; then
    echo "--- #60 pre-staging CPFP wallet ($CPFP_WALLET) over $N_CLIENTS client keys ---"
    $BCLI -named createwallet wallet_name=$CPFP_WALLET blank=true disable_private_keys=false load_on_startup=false 2>&1 | head -1 || true
    $BCLI loadwallet $CPFP_WALLET 2>/dev/null || true
    for sk in "${CLIENT_SECKEYS[@]:0:$N_CLIENTS}"; do
        WIF=$(python3 - "$sk" <<'PY'
import sys, hashlib
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
sk=bytes.fromhex(sys.argv[1]); p=b'\xef'+sk+b'\x01'
chk=hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4]
n=int.from_bytes(p+chk,'big'); s=''
while n>0: n,r=divmod(n,58); s=A[r]+s
print(s)
PY
)
        CK=$($BCLI getdescriptorinfo "tr($WIF)" 2>/dev/null | grep -oE '"checksum": *"[0-9a-z]+"' | grep -oE '[0-9a-z]{8}' | head -1)
        [ -n "$CK" ] && $BCLI -rpcwallet=$CPFP_WALLET importdescriptors "[{\"desc\":\"tr($WIF)#$CK\",\"timestamp\":\"now\",\"internal\":false}]" >/dev/null 2>&1
    done
    echo "  CPFP wallet staged (watching $N_CLIENTS client keys, ready to bump the poison)"
fi

# --- LSP daemon (hashlock poison + sub-factory cheat) ---
echo
echo "--- LSP daemon (--enable-hashlock-poison --cheat-daemon-sub) ---"
env $ASAN_ENV \
"$LSP_BIN" \
    --network regtest \
    --port $LSP_PORT \
    --clients $N_CLIENTS \
    --arity 3 \
    --ps-subfactory-arity $PS_SUB_ARITY \
    --amount $FUNDING_SATS \
    --fee-rate 1000 \
    --confirm-timeout 600 \
    --step-blocks 1 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET \
    --db "$LSP_DB" \
    --wt-db "$WT_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --enable-hashlock-poison \
    --demo --cheat-daemon-sub \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening (PID=$LSP_PID)"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -20 "$LSP_LOG"; exit 1; }
done

# --- Clients ---
echo
echo "--- Starting $N_CLIENTS clients ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    env $ASAN_ENV \
    "$CLIENT_BIN" \
        --network regtest \
        --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i + 1)) \
        --daemon \
        --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET \
        --cli-path "$(which bitcoin-cli)" \
        --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    echo "  client[$i] PID=$!"
    sleep 0.5
done

# --- Background miner ---
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) &
PIDS+=($!)

# --- Wait for CHEAT DAEMON COMPLETE ---
echo
echo "--- Waiting for sub advance + stale broadcast + CHEAT DAEMON COMPLETE (timeout 420s) ---"
READY=0
for i in $(seq 1 210); do
    sleep 2
    grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { READY=1; echo "  CHEAT DAEMON COMPLETE after ${i}*2s"; break; }
    [ $((i % 15)) -eq 0 ] && echo "  ... ${i}*2s elapsed"
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done
[ $READY -eq 1 ] || { echo "FAIL: no CHEAT DAEMON COMPLETE in 420s"; tail -60 "$LSP_LOG"; exit 1; }

# Factory creation has run by now — assert the hashlock feature actually engaged.
grep -q "hashlock-gated L-stock poison ENABLED" "$LSP_LOG" || { echo "FAIL: hashlock poison was NOT enabled"; tail -40 "$LSP_LOG"; exit 1; }
echo "  hashlock poison ENABLED confirmed in LSP log"

# Assert the sub-factory hashlock reveal (Phase 2) actually fired over the wire.
grep -q "revealed sub sales-stock secret for" "$LSP_LOG" || { echo "FAIL: LSP never revealed the sub sales-stock secret (Phase 2 did not fire)"; grep -iE "subfactory|poison|reveal" "$LSP_LOG" | tail -30; exit 1; }
echo "  sub sales-stock secret REVEAL fired in LSP log"

STALE_TXID=$(grep -E "Stale chain\[N-1\] broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
echo "  Stale (superseded) sub chain[N-1] broadcast txid: ${STALE_TXID:-(unknown)}"
[ -n "$STALE_TXID" ] || { echo "FAIL: no stale sub broadcast txid"; tail -30 "$LSP_LOG"; exit 1; }

# Stop clients so their SQLite DBs are flushed before we read them.
echo "  Stopping clients so their persist DBs flush..."
for pid in "${PIDS[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
sleep 3

# --- Find the client that persisted the SUB reveal ---
echo
echo "=== Locating the client-persisted sub reveal (l_stock_poison_reveals) ==="
REVEAL_DB=""; REVEAL_NODE=""; REVEAL_STATE=""
for i in $(seq 0 $((N_CLIENTS - 1))); do
    row=$(sqlite3 "$TMPDIR/client_${i}.db" \
        "SELECT node_idx||' '||state_counter FROM l_stock_poison_reveals WHERE revocation_secret IS NOT NULL ORDER BY node_idx DESC, state_counter ASC LIMIT 1;" 2>/dev/null || true)
    if [ -n "$row" ]; then
        REVEAL_DB="$TMPDIR/client_${i}.db"
        REVEAL_NODE=$(echo "$row" | awk '{print $1}')
        REVEAL_STATE=$(echo "$row" | awk '{print $2}')
        echo "  reveal persisted by client[$i]: node=$REVEAL_NODE state=$REVEAL_STATE db=$REVEAL_DB"
        break
    fi
done
[ -n "$REVEAL_DB" ] || { echo "FAIL: NO client persisted an l_stock_poison_reveals row — the sub reveal wire (Phase 2) did not persist"; exit 1; }

# --- Mine the stale state to maturity, then assemble + broadcast the poison ---
echo
echo "=== CLIENT recourse: assemble hashlock sub poison from persisted reveal ==="
$BCLI generatetoaddress 3 "$MINE_ADDR" >/dev/null 2>&1
POISON_HEX=$("$REC_BIN" --db "$REVEAL_DB" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" 2>/tmp/_recsub.err) || {
    echo "FAIL: superscalar_lstock_recover failed (rc=$?)"; cat /tmp/_recsub.err; exit 1; }
echo "  assembled sub poison (${#POISON_HEX} hex chars)"
POISON_TXID=$($BCLI sendrawtransaction "$POISON_HEX" 2>/tmp/_sendsub.err) || {
    echo "FAIL: sub poison sendrawtransaction REJECTED"; cat /tmp/_sendsub.err
    echo "  (mempool reject means the persisted template/secret did not yield a spend of the stale sales-stock)"; exit 1; }
echo "  SUB POISON broadcast txid: $POISON_TXID"

# === #60 CPFP FEE-RACE (SS_POISON_CPFP_RACE=1) =============================
# Prove the client WINS the L&CSV-fallback race under fee pressure.  The poison
# is pre-signed at a FIXED fee and is NOT RBF-able (the agg-sig binds outputs);
# under congestion its bare fee can be below the floor.  The trustless escape is
# a CPFP child on the client's OWN P2TR output.  We (1) deprioritise the bare
# poison so it cannot be mined alone, (2) CONTROL-prove it stays stuck, (3) the
# client CPFPs via a fat-fee child on its poison output, (4) assert the poison
# CONFIRMS -- well within the 144-block L_STOCK CSV head-start (Leaf-L can't
# mature before then), so the poison beats the LSP's CSV fallback.
if [ "${SS_POISON_CPFP_RACE:-0}" = 1 ]; then
    echo
    echo "=== #60 CPFP FEE-RACE: bump the FIXED-FEE pre-signed poison via a client-output CPFP ==="
    DEPRIO=3000
    $BCLI prioritisetransaction "$POISON_TXID" 0 -$DEPRIO >/dev/null 2>&1
    echo "  poison deprioritised by $DEPRIO sats (bare fixed-fee poison now unmineable)"
    # CONTROL: the bare poison must STAY unconfirmed, else the CPFP proof is vacuous.
    for i in $(seq 1 4); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; done
    c0=$($BCLI getrawtransaction "$POISON_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    { [ -z "$c0" ] || [ "$c0" -eq 0 ]; } || { echo "FAIL(control): poison confirmed despite -$DEPRIO deprioritise ($c0 confs) -- pressure not biting; CPFP proof vacuous"; exit 1; }
    echo "  CONTROL OK: bare poison STUCK unconfirmed under fee pressure (4 blocks, no CPFP)"
    # Locate the poison's client output in the pre-staged CPFP wallet (it ingested
    # the unconfirmed output because tr(client_key) was imported pre-broadcast).
    read CV CA CSPK < <($BCLI -rpcwallet=$CPFP_WALLET listunspent 0 9999999 2>/dev/null | python3 -c "
import sys,json
try: u=[x for x in json.load(sys.stdin) if x['txid']=='$POISON_TXID']
except Exception: u=[]
print(u[0]['vout'], format(u[0]['amount'],'.8f'), u[0]['scriptPubKey']) if u else print('')")
    [ -n "${CV:-}" ] || { echo "FAIL: CPFP wallet did not ingest the poison output (txid=$POISON_TXID)"; $BCLI -rpcwallet=$CPFP_WALLET listunspent 0 2>/dev/null | head -40; exit 1; }
    echo "  poison client output located: vout=$CV amount=$CA BTC"
    # Build a fat-fee CPFP child: absolute 12000-sat fee (>> the $DEPRIO deficit) so the
    # poison+child PACKAGE clears the floor.  Sweep the single explicit input to the miner.
    CA_SATS=$(python3 -c "print(int(round(float('$CA')*1e8)))")
    CHILD_FEE=12000
    [ "$CA_SATS" -gt $((CHILD_FEE + 600)) ] || { echo "FAIL: poison output ${CA_SATS} sats too small to CPFP with a ${CHILD_FEE}-sat fee"; exit 1; }
    OUT_SATS=$((CA_SATS - CHILD_FEE))
    OUT_BTC=$(python3 -c "print(format($OUT_SATS/1e8,'.8f'))")
    CHILD_DEST=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
    RAWCHILD=$($BCLI -named createrawtransaction inputs="[{\"txid\":\"$POISON_TXID\",\"vout\":$CV}]" outputs="[{\"$CHILD_DEST\":$OUT_BTC}]")
    SIGNED=$($BCLI -rpcwallet=$CPFP_WALLET signrawtransactionwithwallet "$RAWCHILD" "[{\"txid\":\"$POISON_TXID\",\"vout\":$CV,\"scriptPubKey\":\"$CSPK\",\"amount\":$CA}]" 2>/tmp/_cpfpsign.err)
    SHEX=$(echo "$SIGNED" | python3 -c "import sys,json
try: d=json.load(sys.stdin); print(d['hex'] if d.get('complete') else '')
except Exception: print('')")
    [ -n "$SHEX" ] || { echo "FAIL: CPFP child sign incomplete"; cat /tmp/_cpfpsign.err 2>/dev/null; echo "$SIGNED"; exit 1; }
    CHILD_TXID=$($BCLI sendrawtransaction "$SHEX" 2>/tmp/_cpfpsend.err) || { echo "FAIL: CPFP child REJECTED"; cat /tmp/_cpfpsend.err; exit 1; }
    echo "  CPFP child broadcast: $CHILD_TXID (absolute fee ${CHILD_FEE} sats >> ${DEPRIO}-sat deficit)"
    # The package (poison+child) must now confirm -- and the poison output stays swept.
    PCONF=0; PBLKS=0
    for i in $(seq 1 8); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; PBLKS=$i; c=$($BCLI getrawtransaction "$POISON_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1); [ -n "$c" ] && [ "$c" -ge 1 ] && { PCONF=$c; break; }; done
    [ "$PCONF" -ge 1 ] || { echo "FAIL: poison did NOT confirm even after CPFP -- #60 race LOST"; exit 1; }
    CC=$($BCLI getrawtransaction "$CHILD_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    echo "  poison CONFIRMED via CPFP after ${PBLKS} block(s) (${PCONF} confs); child confs=${CC:-0}"
    [ "$PBLKS" -lt 144 ] || { echo "FAIL: CPFP confirmation took $PBLKS blocks >= 144-block CSV head-start"; exit 1; }
    echo
    echo "=== PASS: #60 CPFP FEE-RACE -- the pre-signed, NON-RBF-able poison was BUMPED to"
    echo "    confirmation by a client-output CPFP under fee pressure, in ${PBLKS} block(s) <<"
    echo "    the 144-block L_STOCK CSV head-start.  The poison BEATS the LSP's Leaf-L CSV"
    echo "    fallback => Layer-3 (win-the-fee-race) PROVEN for the #53 sub-factory poison."
    exit 0
fi

# --- Confirm + amount ---
echo
echo "=== Verifying sub poison CONFIRMS + redistributes sales-stock ==="
PRAW=""
for n in $(seq 1 10); do
    $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1
    PRAW=$($BCLI getrawtransaction "$POISON_TXID" true 2>/dev/null || true)
    echo "$PRAW" | grep -q '"confirmations"' && break
done
echo "$PRAW" | grep -q '"confirmations"' || { echo "FAIL: sub poison $POISON_TXID never CONFIRMED"; exit 1; }
PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
echo "  sub poison CONFIRMED; largest output ${PSATS:-0} sats"
[ "${PSATS:-0}" -ge 1000 ] || { echo "FAIL: poison output ${PSATS} sats <= dust — not a real sales-stock recapture"; exit 1; }

# --- Anti-vacuity: no revealed secret -> no recourse ---
echo
echo "=== Anti-vacuity: tool must REFUSE when the secret is absent ==="
cp "$REVEAL_DB" "$TMPDIR/novax.db"
sqlite3 "$TMPDIR/novax.db" "UPDATE l_stock_poison_reveals SET revocation_secret=NULL;" 2>/dev/null
set +e
"$REC_BIN" --db "$TMPDIR/novax.db" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" >/dev/null 2>/tmp/_nvsub.err
NRC=$?
set -e
echo "  no-secret recourse exit=$NRC (expect 5)"; cat /tmp/_nvsub.err 2>/dev/null || true
[ "$NRC" = "5" ] || { echo "FAIL: tool did NOT refuse a missing reveal (anti-vacuity broken)"; exit 1; }

echo
echo "=== PASS: hashlock SUB-FACTORY L-stock poison E2E ==="
echo "  multi-input advance->reveal->persist->assemble->broadcast->CONFIRM proven on regtest"
echo "  sub poison $POISON_TXID confirmed, ${PSATS} sats recaptured; no-reveal refused (exit 5)"
exit 0
