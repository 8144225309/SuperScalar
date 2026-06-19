#!/usr/bin/env bash
# test_regtest_htlc_force_close.sh — FIRE the force-close HTLC sweep on regtest.
#
# --test-htlc-force-close: after the demo, add a pending HTLC on channel 0,
# broadcast the factory tree (leaf on-chain), broadcast the commitment TX (which
# carries the HTLC output), mine to the HTLC CLTV, then broadcast the HTLC
# *timeout* TX — the sweep. PASS = "HTLC FORCE-CLOSE TEST PASSED" (the timeout
# sweep broadcast + confirmed on-chain). Also reports wt.db kind=3 arming.
#
# NB: the test re-signs the commitment with client[0]'s key, so the client
# daemons MUST be launched with the canonical scaffold seckeys (client_fills).
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS=4; PORT=29965; FEE=1100; ARITY=2; AMOUNT=200000
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-htlc-fc.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/htlc_fc_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
# Canonical scaffold seckeys: byte = 0x22 + i*0x11 (must equal client_fills).
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== HTLC force-close sweep (kind=3) on regtest ==="
"$LSP_BIN" --network regtest --port $PORT --demo --test-htlc-force-close --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity $ARITY --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" --wt-db "$WT_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -20 "$LSP_LOG"; fail "LSP died"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon --seckey "$(sk $i)" --fee-rate $FEE \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" \
        --rpcport "$RPORT" --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!

echo "--- waiting for HTLC force-close + timeout-sweep, then LSP exit (~6min) ---"
for i in $(seq 1 200); do
    sleep 2
    grep -q "HTLC FORCE-CLOSE TEST PASSED" "$LSP_LOG" 2>/dev/null && { echo "  PASSED marker seen (${i}*2s)"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited"; break; }
done
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done
kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""

echo
echo "=== evidence ==="
grep -aiE "HTLC FORCE-CLOSE|HTLC timeout|sweep|timeout TX|broadcast|PASSED" "$LSP_LOG" 2>/dev/null | tail -15
K3=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=3;" 2>/dev/null || echo 0)
echo "  wt.db force-close-HTLC (kind=3) watches armed: ${K3:-0}"
echo
set +e
if grep -q "HTLC FORCE-CLOSE TEST PASSED" "$LSP_LOG" 2>/dev/null; then
    # OUTCOME (not just the LSP's self-reported marker): independently confirm the HTLC
    # timeout-sweep on-chain + assert it swept a real amount.
    SWEEP_TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE (source LIKE '%htlc%' OR source LIKE '%sweep%' OR source LIKE '%timeout%' OR source LIKE '%force%') AND result='ok' AND length(txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$SWEEP_TXID" ] && SWEEP_TXID=$(grep -aoiE "HTLC timeout[^0-9a-f]*[0-9a-f]{64}|timeout sweep[^0-9a-f]*[0-9a-f]{64}|HTLC timeout TX broadcast: *[0-9a-f]{64}|Latest state tx broadcast: *[0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$SWEEP_TXID" ] || { red "FAIL: PASSED marker present but no HTLC timeout-sweep txid found (broadcast_log + log)"; tail -25 "$LSP_LOG"; exit 1; }
    echo "  HTLC timeout-sweep txid: $SWEEP_TXID — confirming on-chain"
    SRAW=""; for n in $(seq 1 12); do mine 1; sleep 1; SRAW=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null); echo "$SRAW" | grep -q '"confirmations"' && break; done
    echo "$SRAW" | grep -q '"confirmations"' || { red "FAIL: HTLC sweep $SWEEP_TXID never CONFIRMED on-chain (marker != confirmed)"; exit 1; }
    SV=$(echo "$SRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    SSATS=$(awk "BEGIN{printf \"%d\", ($SV+0)*100000000}")
    echo "  HTLC sweep confirmed on-chain; largest output ${SSATS:-0} sats"
    [ "${SSATS:-0}" -ge 1000 ] || { red "FAIL: HTLC sweep output ${SSATS} sats <= dust — not a real timeout recovery"; exit 1; }
    green "PASS: the force-close HTLC timeout sweep $SWEEP_TXID was broadcast AND independently CONFIRMED on-chain ($SSATS sats)."
    green "      (wt.db kind=3 force-close watches armed: ${K3:-0})"
    exit 0
else
    red "FAIL: HTLC force-close timeout sweep did not complete"; tail -30 "$LSP_LOG"; exit 1
fi
