#!/usr/bin/env bash
# test_regtest_cheat_daemon_subfactory.sh — end-to-end PS sub-factory cheat
# (regtest) with the STANDALONE watchtower binary doing detection + response.
#
# Daemon-mode companion to test_regtest_k2_subfactory_breach.sh.
# Closes Gap 1: until now we had the in-memory WT defending against
# sub-factory cheats (which a malicious LSP could suppress). This proves
# the standalone WT — an independent process the LSP cannot interfere
# with — picks up the same breach from persisted DB and defends.
#
# Flow:
#   1. LSP runs --cheat-daemon-sub (subfactory advance + cheat broadcast,
#      no internal WT — sets SS_CHEAT_DAEMON_MODE, honored by CL4.F).
#   2. After CHEAT DAEMON COMPLETE marker, standalone WT starts against
#      same DB.
#   3. WT hydrates PS sub-factory chain state (CL4 hydration) AND
#      initial-state defense entry (CL4.E new — sub-factory analog of
#      Task #40 / CL4.D for leaves).
#   4. WT polls blocks, sees the stale chain[N-1] TX, broadcasts
#      response_tx + sub-factory L-stock poison TX.
#
# Pass criterion: WT stdout contains "penalty tx(s) broadcast".

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

N_CLIENTS="${N_CLIENTS:-4}"
PS_SUB_ARITY="${PS_SUB_ARITY:-2}"   # k=2 canonical

FUNDING_SATS="${FUNDING_SATS:-400000}"
LSP_PORT=29957                # distinct from k² test (29949) and cheat-leaf (29950)
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

# Auto-detect ASan build and preload libasan only if needed.
if command -v nm >/dev/null 2>&1 && nm -D "$LSP_BIN" 2>/dev/null | grep -q __asan_init; then
    SS_ASAN_ENV="ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8"
else
    SS_ASAN_ENV=""
fi

TMPDIR=$(mktemp -d /tmp/ss-cheat-daemon-sub.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
WT_LOG="$TMPDIR/wt.log"
WT_DB="$TMPDIR/wt.db"   # trustless WT db (no secrets); armed by the LSP's --wt-db

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    # #178: checkpoint WAL before cp so the saved snapshot has the actual data
    # (kill -9 above bypasses SQLite's clean shutdown, leaving recent writes
    # in the WAL file. Without this checkpoint, the cp captures an empty stub
    # DB and downstream sqlite3 queries on /tmp/cheat_daemon_sub_last_lsp.db
    # see zero tables.)
    sqlite3 "$LSP_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
    cp "$LSP_LOG" /tmp/cheat_daemon_sub_last_lsp.log 2>/dev/null || true
    cp "$WT_LOG"  /tmp/cheat_daemon_sub_last_wt.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/cheat_daemon_sub_last_lsp.db  2>/dev/null || true
    [ -n "${REORG_LOG:-}" ] && cp "$REORG_LOG" /tmp/cheat_daemon_sub_last_reorg.log 2>/dev/null || true
    rm -rf "$TMPDIR"
    echo "  preserved: /tmp/cheat_daemon_sub_last_{lsp,wt}.{log,db}"
}
trap cleanup EXIT

echo "=== PS SUB-FACTORY CHEAT WITH STANDALONE WT (regtest) ==="
echo "  build dir   : $BUILD_DIR"
echo "  N clients   : $N_CLIENTS"
echo "  k (sub arity): $PS_SUB_ARITY (k²=$((PS_SUB_ARITY * PS_SUB_ARITY)) clients per leaf)"
echo "  funding     : $FUNDING_SATS sats"

# --- bitcoind check ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, chain at height $($BCLI getblockcount)"

REORG_LOG="$TMPDIR/reorg.log"
REORG_PID=$(start_reorg_watcher "$REORG_LOG")
PIDS+=($REORG_PID)

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo
echo "--- LSP daemon (--demo --cheat-daemon-sub) ---"
env $SS_ASAN_ENV "$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --ps-subfactory-arity $PS_SUB_ARITY \
    --amount $FUNDING_SATS \
    --step-blocks 1 \
    --max-conn-rate 1000 --max-handshakes 256 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET \
    --db "$LSP_DB" \
    --wt-db "$WT_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --demo --lsp-balance-pct 50 --cheat-daemon-sub \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening (PID=$LSP_PID)"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -20 "$LSP_LOG"; exit 1; }
done

echo
echo "--- Starting $N_CLIENTS clients ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    env $SS_ASAN_ENV "$CLIENT_BIN" \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --host 127.0.0.1 --port $LSP_PORT \
        --network regtest \
        --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i + 1)) \
        --daemon \
        --db "$TMPDIR/client_${i}.db" \
        --cli-path "$(which bitcoin-cli)" \
        --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.4
done

# Background miner
(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

echo
echo "--- Waiting for CHEAT DAEMON COMPLETE marker (timeout 360s) ---"
DAEMON_READY=0
for i in $(seq 1 180); do
    sleep 2
    if grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null; then
        DAEMON_READY=1
        echo "  CHEAT DAEMON COMPLETE marker observed after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        echo "  ... waiting (${i}*2s elapsed)"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done
if [ $DAEMON_READY -eq 0 ]; then
    echo "FAIL: LSP did not reach CHEAT DAEMON COMPLETE in 360s"
    tail -50 "$LSP_LOG"
    exit 1
fi

STALE_TXID=$(grep -E "Stale chain\[N-1\] broadcast" "$LSP_LOG" | head -1 | awk -F': ' '{print $2}')
echo "  Stale chain[N-1] sub-factory txid: ${STALE_TXID:-(unknown)}"

echo
# Stop the cheating LSP gracefully so its wt.db (WAL) is checkpointed before the
# standalone trustless WT reads it. The stale sub-factory state is already on-chain;
# the WT must now defend WITHOUT the LSP (exactly the trustless scenario).
echo "--- stopping cheating LSP so wt.db is flushed for the standalone WT ---"
kill -TERM $LSP_PID 2>/dev/null || true
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited (wt.db checkpointed)"; break; }; sleep 1; done
WT_K1=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=1;" 2>/dev/null || echo 0)
echo "  wt.db sub-factory (kind=1) watches available to the standalone WT: ${WT_K1:-0}"

echo "--- Standalone trustless WT (--wt-db $WT_DB, NO secrets) ---"
"$WT_BIN" \
    --network regtest \
    --wt-db "$WT_DB" \
    --poll-interval 5 \
    --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} \
    --rpcpassword ${RPCPASSWORD:-rpcpass} \
    > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
echo "  WT PID=$WT_PID"

echo
echo "--- Waiting for WT to detect + broadcast penalty TXs (timeout 120s) ---"
WT_FIRED=0
for i in $(seq 1 60); do
    sleep 2
    # Match either the heartbeat-summary "penalty tx(s) broadcast" line
    # OR the inner "L-stock burn tx broadcast: <txid>" success line.
    # The latter is what fires when sub-factory breach is detected and
    # the wire-ceremony poison TX is sent successfully.
    if grep -qE 'penalty tx\(s\) broadcast|L-stock burn tx broadcast: [0-9a-f]{64}' "$WT_LOG" 2>/dev/null; then
        WT_FIRED=1
        echo "  WT fired after ${i}*2s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        ENTRIES=$(grep -cE "heartbeat" "$WT_LOG" 2>/dev/null || echo 0)
        echo "  ... waiting (${i}*2s elapsed, $ENTRIES heartbeats)"
    fi
    kill -0 $WT_PID 2>/dev/null || { echo "  WT died"; break; }
done

echo
echo "=== WT log tail ==="
tail -30 "$WT_LOG"
echo
echo "=== penalty broadcasts ==="
grep -E "penalty tx|response|burn|poison|BREACH" "$WT_LOG" | head -10 || echo "  (none)"

echo
echo "=== reorg events ==="
if [ -s "$REORG_LOG" ]; then cat "$REORG_LOG"; else echo "  (none)"; fi

echo
echo "=== Final result ==="
set +e
if [ "$WT_FIRED" -eq 1 ]; then
    # OUTCOME (not just a broadcast log line): confirm the WT's response/penalty txid ON-CHAIN + assert a real amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT response_txid FROM breach_detections WHERE response_txid IS NOT NULL AND length(response_txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(grep -aoiE "Latest state tx broadcast: *[0-9a-f]{64}|Penalty tx broadcast: *[0-9a-f]{64}|L-stock burn tx broadcast: [0-9a-f]{64}|Sub-factory poison tx broadcast: *[0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { echo "  FAIL: WT fired but no response/penalty txid found (breach_detections + WT log)"; tail -30 "$WT_LOG"; exit 1; }
    echo "  WT response txid: $PEN_TXID — mining to confirm + verify payout"
    PRAW=""; for n in $(seq 1 10); do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 1; PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null); echo "$PRAW" | grep -q '"confirmations"' && break; done
    echo "$PRAW" | grep -q '"confirmations"' || { echo "  FAIL: WT response $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    # G1 #44 PROOF: the poison spends chain[N-1]'s OWN sales-stock output (vin[0].txid == breach),
    # whereas chain[N] spends chain[N-1]'s PARENT. So vin==breach proves the trustless wt_db response
    # is the POISON (valid pre- AND post-confirmation), not the RBF-only chain[N] that orphans (-25)
    # once the breach confirms. Hard-FAIL otherwise — a green here means the poison is in wt_db.
    if [ -n "$STALE_TXID" ]; then
        RVIN=$(echo "$PRAW" | python3 -c 'import json,sys
try:
 d=json.load(sys.stdin); print(d["vin"][0]["txid"])
except Exception: print("")')
        if [ "$RVIN" = "$STALE_TXID" ]; then
            echo "  G1 VERIFIED: WT response spends the breach chain[N-1] ($STALE_TXID) -> it IS the POISON (post-confirmation recourse), not chain[N]"
        else
            echo "  FAIL (G1): WT response spends $RVIN, expected the breach $STALE_TXID -> still chain[N] (RBF-only); poison NOT persisted to wt_db"; exit 1
        fi
    fi
    # Finding-2 fix: a sub-factory penalty REDISTRIBUTES to N per-client P2TR outputs (verified on
    # signet: 3 outputs 55416/44333/33051, no change). Assert the SMALLEST per-client output is
    # above dust — checking only 'largest' would pass even if one client were shorted to dust.
    PINFO=$(echo "$PRAW" | python3 -c 'import json,sys
try:
 d=json.load(sys.stdin); vs=[int(round(v["value"]*1e8)) for v in d["vout"] if v["scriptPubKey"].get("type")=="witness_v1_taproot"]
 print(min(vs) if vs else 0, len(vs), sum(vs))
except Exception: print("0 0 0")')
    PMIN=$(echo "$PINFO" | awk "{print \$1}"); PNUM=$(echo "$PINFO" | awk "{print \$2}"); PTOT=$(echo "$PINFO" | awk "{print \$3}")
    echo "  WT response confirmed on-chain; $PNUM per-client P2TR output(s), smallest ${PMIN:-0} sats, total ${PTOT:-0} sats"
    [ "${PNUM:-0}" -ge 1 ] || { echo "  FAIL: WT response has no P2TR recovery output"; exit 1; }
    [ "${PMIN:-0}" -ge 330 ] || { echo "  FAIL: a per-client output ${PMIN} sats <= dust — redistribution shorted a client"; exit 1; }
    A2=$(pen_recovers_most "$PEN_TXID"); echo "  A-2 recovery ratio: $A2 (OK=outputs>=90% of swept inputs)"
    case "$A2" in LOW*) echo "  FAIL: penalty recovers <90% of swept value ($A2) — value leaked/burned to fee"; exit 1;; esac
    echo "  PASS: standalone WT detected sub-factory breach, broadcast AND CONFIRMED its redistribution ($PEN_TXID; $PNUM clients, min ${PMIN}, total ${PTOT} sats) — outcome verified per-client"
    exit 0
else
    echo "  FAIL: standalone WT did not broadcast penalty TXs"
    tail -50 "$WT_LOG"
    exit 1
fi
