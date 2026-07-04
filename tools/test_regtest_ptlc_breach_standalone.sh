#!/usr/bin/env bash
# test_regtest_ptlc_breach_standalone.sh — #93: a SECRET-LESS standalone WT sweeps
# a PTLC output from a revoked-commitment breach, using ONLY wt.db, LSP OFFLINE.
#
# Gap closed: channel_build_ptlc_penalty_tx (watchtower.c:1496) is proven via the
# LSP-internal WT (ptlc_breach_chain.sh) + a unit, but the SECRET-LESS standalone
# path -- the wt_db PTLC mirror (watchtower.c:847 pre-builds the signed sweep at
# registration) + hydrate + broadcast -- had no e2e test.
#
# --test-ptlc-breach-chain + SS_CHEAT_DAEMON_MODE=1: the LSP adds a PTLC on ch0,
# broadcasts the tree + the revoked commitment (THE BREACH), confirms it, mirrors
# the PTLC penalty to wt.db at registration, then EXITS (skips the internal
# watchtower_check).  A standalone WT (--wt-db only, LSP OFFLINE) must then detect
# the breach on-chain + hydrate + broadcast the PTLC penalty itself.
#
# PASS: STANDALONE-ARM COMPLETE + wt.db watch persisted + the WT broadcasts a PTLC
# penalty that CONFIRMS on-chain (>= dust) with NO secret.
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; WT_BIN="$BUILD_DIR/superscalar_watchtower"
N_CLIENTS=4; PORT=29963; FEE=1100; ARITY=2; AMOUNT=200000
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-ptlc-std.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_LOG="$TMPDIR/wt.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client|watchtower).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/ptlc_std_lsp.log 2>/dev/null||true; cp "$WT_LOG" /tmp/ptlc_std_wt.log 2>/dev/null||true; cp "$WT_DB" /tmp/ptlc_std_wt.db 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== PTLC BREACH STANDALONE sweep (regtest, #93) ==="
echo "    LSP breaches (revoked commit w/ PTLC) + mirrors wt.db + exits; secret-less WT must sweep the PTLC."
SS_CHEAT_DAEMON_MODE=1 "$LSP_BIN" --network regtest --port $PORT --demo --test-ptlc-breach-chain --lsp-balance-pct 50 \
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

echo "--- waiting for STANDALONE-ARM COMPLETE + LSP exit (~6min) ---"
ARMED=0
for i in $(seq 1 220); do
    sleep 2
    grep -q "PTLC BREACH CHAIN STANDALONE-ARM COMPLETE" "$LSP_LOG" 2>/dev/null && { ARMED=1; echo "  standalone armed (${i}*2s)"; break; }
    grep -qiE "PTLC BREACH CHAIN: .*failed|safety gate not enabled|need at least 1 channel|insufficient local" "$LSP_LOG" 2>/dev/null && { echo "  LSP reported a ptlc-breach error"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited"; break; }
done
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done   # full exit -> wt.db WAL checkpoint
[ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""

BREACH_TXID=$(grep -aoE "\[7\] BREACH broadcast: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
WATCHES=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches;" 2>/dev/null || echo 0)
echo "  breach txid: ${BREACH_TXID:-none}; wt.db watches: ${WATCHES:-0}"
[ "$ARMED" -eq 1 ] || { tail -30 "$LSP_LOG"; fail "standalone-arm never completed"; }
[ "${WATCHES:-0}" -ge 1 ] || fail "no watch in wt.db (arming did not persist the PTLC watch)"

# keep mining so the standalone WT's poll advances + the ptlc_penalty can confirm
( for k in $(seq 1 80); do mine 1; sleep 3; done ) & MINER_PID=$!

echo "--- standalone trustless WT (--wt-db only, LSP OFFLINE) ---"
"$WT_BIN" --network regtest --wt-db "$WT_DB" --poll-interval 5 --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)

echo "--- waiting for WT to broadcast the PTLC penalty (timeout 220s) ---"
WT_FIRED=0; SWEEP_TXID=""
for i in $(seq 1 110); do
    sleep 2
    # the standalone WT may log the PTLC sweep via the ptlc_penalty path OR the
    # uniform hydrate/"Latest state tx broadcast" path -- match broadly.
    SWEEP_TXID=$(grep -aoiE "PTLC penalty[^0-9a-f]*[0-9a-f]{64}|ptlc_penalty[^0-9a-f]*[0-9a-f]{64}|Latest state tx broadcast: [0-9a-f]{64}|penalty tx[^0-9a-f]*[0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    if [ -n "$SWEEP_TXID" ]; then WT_FIRED=1; echo "  WT broadcast a sweep $SWEEP_TXID (${i}*2s)"; break; fi
    kill -0 $WT_PID 2>/dev/null || break
    [ $((i % 15)) -eq 0 ] && echo "  ... ${i}*2s ($(grep -c heartbeat "$WT_LOG" 2>/dev/null||echo 0) heartbeats)"
done

# Rigorous: the standalone WT sweeps BOTH the main penalty and the PTLC penalty; we
# want to confirm a PTLC penalty specifically.  Prefer a wt.db ptlc_penalty row, else
# fall back to any confirmed WT broadcast that spends the breach commit's PTLC output.
PTLC_TXID=$(sqlite3 "$WT_DB" "SELECT txid FROM broadcast_log WHERE source='ptlc_penalty' AND result='ok' AND length(txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null || true)
[ -n "$PTLC_TXID" ] && SWEEP_TXID="$PTLC_TXID"
SWEEP_CONF=0
if [ -n "$SWEEP_TXID" ]; then
    for k in $(seq 1 20); do
        C=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE "\"confirmations\": [0-9]+" | grep -oE "[0-9]+" | head -1)
        [ -n "$C" ] && [ "$C" -ge 1 ] && { SWEEP_CONF=1; echo "  sweep $SWEEP_TXID confirmed on-chain ($C confs)"; break; }
        mine 1; sleep 2
    done
fi

echo; echo "=== WT log tail ==="; tail -30 "$WT_LOG"
echo; echo "=== wt.db broadcast_log ==="; sqlite3 "$WT_DB" "SELECT id,source,result,substr(txid,1,20) FROM broadcast_log ORDER BY id;" 2>/dev/null || true
echo; echo "=== Final result ==="
echo "  armed=$ARMED watches=$WATCHES wt_fired=$WT_FIRED ptlc_penalty_row=${PTLC_TXID:+yes} txid=${SWEEP_TXID:-none} confirmed=$SWEEP_CONF"
SWEEP_SATS=0
if [ "$SWEEP_CONF" -eq 1 ]; then
    SV=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    SWEEP_SATS=$(awk "BEGIN{printf \"%d\", ($SV+0)*100000000}")
    echo "  sweep largest output: ${SWEEP_SATS:-0} sats"
fi
# A confirmed WT broadcast + a ptlc_penalty row in wt.db proves the standalone PTLC sweep.
if [ "$ARMED" -eq 1 ] && [ "${WATCHES:-0}" -ge 1 ] && [ "$WT_FIRED" -eq 1 ] && [ "$SWEEP_CONF" -eq 1 ] && [ "${SWEEP_SATS:-0}" -ge 330 ] && [ -n "$PTLC_TXID" ]; then
    green "PASS: secret-less standalone WT (--wt-db only) swept a PTLC from wt.db on a"
    green "      revoked-commitment breach -- PTLC penalty $SWEEP_TXID broadcast + CONFIRMED"
    green "      on-chain ($SWEEP_SATS sats), LSP OFFLINE. Standalone PTLC-sweep PROVEN trustless."
    exit 0
fi
red "FAIL: need armed + watch>=1 + WT broadcast + a CONFIRMED ptlc_penalty row (>=330 sats)"; exit 1
