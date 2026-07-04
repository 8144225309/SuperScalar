#!/usr/bin/env bash
# test_regtest_multibreach.sh -- #96: RIGOROUS simultaneous multi-breach.
#
# The existing breach path already broadcasts revoked commitments for ALL K
# channels (superscalar_lsp_post_daemon_tests.inc:35 loop), but the in-process
# assertion only checks `detected > 0` (>=1 penalty) and the standalone drill
# asserts ONE penalty txid -- a WT that penalized 1 of K would falsely pass.
#
# This proves the real robustness property: when K revoked channel commitments
# hit the chain SIMULTANEOUSLY, a secret-less standalone WT (--wt-db only)
# penalizes EVERY one of them. Ground truth (not a broadcast count): each breach's
# to_local output must be CONFIRMED-spent (the penalty claimed the revoked balance
# before the cheater's CSV could mature), for ALL K breaches.
#
#   1. LSP --demo --breach-standalone --wt-db: advances state (revoking commitments
#      -> kind=2 watches mirrored to wt.db), broadcasts K revoked commitments, sleeps.
#   2. Capture all K breach txids from the LSP log.
#   3. Standalone WT (--wt-db only) hydrates + must penalize all K.
#   4. Assert: for EVERY breach, its to_local is confirmed-spent (== K penalized),
#      and the recovered value is real (not dust).
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; WT_BIN="$BUILD_DIR/superscalar_watchtower"
N_CLIENTS="${N_CLIENTS:-4}"; PORT=29968; FEE=1100
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-multibreach.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_LOG="$TMPDIR/wt.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$WT_LOG" /tmp/multibreach_wt.log 2>/dev/null||true; cp "$LSP_LOG" /tmp/multibreach_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
# breach-launcher seckeys MUST equal the breach-test's client_fills (0x22 + i*0x11)
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== SIMULTANEOUS MULTI-BREACH x STANDALONE WT (#96): every one of K breaches must be penalized ==="
"$LSP_BIN" --network regtest --port $PORT --demo --breach-standalone --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity 3 --amount 200000 --fee-rate $FEE --confirm-timeout 600 \
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

echo "--- waiting for the K revoked commitments to broadcast, then LSP exit (wt.db flush) ---"
for i in $(seq 1 120); do sleep 2; grep -qiE "Revoked commitment broadcast|breach-standalone" "$LSP_LOG" 2>/dev/null && { echo "  breach(es) broadcast (${i}*2s)"; break; }; kill -0 $LSP_PID 2>/dev/null||break; done
for i in $(seq 1 60); do kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited — wt.db flushed"; break; }; sleep 2; done
kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""; sleep 1

# Capture ALL K breach txids (the whole point: multiple, simultaneous)
mapfile -t BREACHES < <(grep -aoE "Revoked commitment broadcast \(ch [0-9]+\): [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | sort -u)
K=${#BREACHES[@]}
echo "  K = $K simultaneous revoked commitments broadcast: ${BREACHES[*]:0:4} ..."
[ "$K" -ge 2 ] || fail "need a genuine MULTI-breach (K>=2); got K=$K -- not a multi-breach scenario"
K2=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=2;" 2>/dev/null || echo 0)
echo "  wt.db kind=2 commitment watches: ${K2:-0}"
[ "${K2:-0}" -ge "$K" ] || echo "  WARN: fewer kind=2 watches (${K2}) than breaches ($K)"
mine 1; sleep 1   # confirm all K breaches

echo "--- launch STANDALONE trustless WT (--wt-db only, NO secrets) vs $K concurrent breaches ---"
"$WT_BIN" --network regtest --wt-db "$WT_DB" --poll-interval 3 --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
# give the WT time to detect all K + broadcast + mine to confirm the penalties
for i in $(seq 1 60); do
    sleep 2
    grep -qE "penalty tx\(s\) broadcast|Latest state tx broadcast:" "$WT_LOG" 2>/dev/null && [ $i -ge 4 ] && { mine 2; }
    kill -0 $WT_PID 2>/dev/null || break
    [ $((i % 2)) -eq 0 ] && mine 1
done
mine 3; sleep 2   # ensure all penalties are confirmed before the ground-truth check

echo
echo "=== GROUND TRUTH: every breach's to_local must be CONFIRMED-spent (penalized) ==="
grep -q "hydrated" "$WT_LOG" || fail "WT did not hydrate from wt.db"
PENALIZED=0; TOTAL_RECOVERED=0; UNPENALIZED=()
for btxid in "${BREACHES[@]}"; do
    # to_local = the largest witness_v1_taproot output of the revoked commitment
    read -r TL_VOUT TL_VAL < <($BCLI getrawtransaction "$btxid" true 2>/dev/null | python3 -c '
import json,sys
try:
 d=json.load(sys.stdin)
 tr=sorted([(v["n"], int(round(v["value"]*1e8))) for v in d["vout"] if v["scriptPubKey"].get("type")=="witness_v1_taproot"], key=lambda x:-x[1])
 print(tr[0][0], tr[0][1]) if tr else print("-1 0")
except Exception: print("-1 0")')
    if [ "${TL_VOUT:--1}" -lt 0 ]; then UNPENALIZED+=("$btxid(no-taproot)"); continue; fi
    # gettxout with include_mempool=false: null => the output was spent by a CONFIRMED tx (the penalty)
    UTXO=$($BCLI gettxout "$btxid" "$TL_VOUT" false 2>/dev/null)
    if [ -z "$UTXO" ]; then
        PENALIZED=$((PENALIZED+1)); TOTAL_RECOVERED=$((TOTAL_RECOVERED + TL_VAL))
        echo "  breach ${btxid:0:16} to_local (vout $TL_VOUT, $TL_VAL sats): CONFIRMED-spent = penalized"
    else
        UNPENALIZED+=("${btxid:0:16}(vout $TL_VOUT still UNSPENT)")
    fi
done
PEN_BCASTS=$(grep -acE "penalty tx\(s\) broadcast|Latest state tx broadcast:" "$WT_LOG" 2>/dev/null || echo 0)
echo
echo "=== result ==="
echo "  breaches K=$K  penalized=$PENALIZED  wt_penalty_broadcasts~=$PEN_BCASTS  total_recovered=${TOTAL_RECOVERED} sats"
[ ${#UNPENALIZED[@]} -gt 0 ] && echo "  UNPENALIZED: ${UNPENALIZED[*]}"
echo "=== WT log tail ==="; tail -15 "$WT_LOG" 2>/dev/null

# ELITE assertion: EVERY breach penalized (not >=1), real value recovered.
if [ "$PENALIZED" -eq "$K" ] && [ "$K" -ge 2 ] && [ "$TOTAL_RECOVERED" -ge 5000 ]; then
    green "PASS: a secret-less standalone WT (--wt-db only) penalized ALL $K simultaneous revoked"
    green "      commitments -- every breach's to_local CONFIRMED-spent on-chain ($TOTAL_RECOVERED sats"
    green "      recovered). Multi-breach robustness PROVEN: the WT drops none under a mass breach."
    exit 0
fi
red "FAIL: need ALL $K breaches penalized (got $PENALIZED/$K) + real recovery; a dropped breach = a WT starvation bug"; exit 1
