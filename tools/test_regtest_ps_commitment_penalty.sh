#!/usr/bin/env bash
# test_regtest_ps_commitment_penalty.sh — the verification I owe: does a PS
# channel-commitment breach actually get PUNISHED end-to-end, and is the same
# penalty armed in the trustless wt.db?
#
# Uses --breach-test (mode 1): runs the demo (payments revoke commitments ->
# WT_KIND_CHANNEL_COMMITMENT watches mirrored to wt.db), broadcasts the factory
# TREE (so the leaf is on-chain), then broadcasts a REVOKED channel commitment
# (the breach), then the LSP's watchtower detects it and broadcasts the penalty.
#
# PASS = the breach is punished (penalty broadcast) AND the same penalty is
#        armed in wt.db (kind=2) for the trustless standalone WT. That makes the
#        PS channel-commitment penalty path PROVEN (in-process) + trustless-armed.
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS=4; PORT=29962; FEE=1100
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-ps-commit-penalty.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/ps_commit_penalty_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
# breach-test (post_daemon_tests.inc) re-signs the old commitment with client_fills
# = {0x22,0x33,0x44,0x55} (32 bytes each). The launcher MUST hand the clients those
# exact seckeys or the 2-of-2 re-sign uses the wrong client key -> Invalid Schnorr
# (the documented scaffold-seckey trap). byte = 0x22 + i*0x11.
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== PS channel-commitment breach -> penalty (the verification I owe) ==="
"$LSP_BIN" --network regtest --port $PORT --demo --breach-test --lsp-balance-pct 50 \
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

echo "--- demo + tree broadcast + revoked-commitment breach + watchtower penalty (timeout ~6min) ---"
PEN=0
for i in $(seq 1 180); do
    sleep 2
    grep -qE "broadcast [0-9]+ penalty tx|BREACH.*penal|penalty tx.*broadcast|punished" "$LSP_LOG" 2>/dev/null && { PEN=1; echo "  penalty broadcast detected (${i}*2s)"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited"; break; }
done

echo
echo "=== evidence ==="
echo "-- breach markers --"; grep -aiE "BREACH TEST|revoked commit|broadcast.*revoked|node\[.*broadcast" "$LSP_LOG" 2>/dev/null | tail -6
echo "-- penalty markers --"; grep -aiE "penalty tx|punished|broadcast [0-9]+ penalty" "$LSP_LOG" 2>/dev/null | tail -6
K2=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=2;" 2>/dev/null || echo 0)
echo "  wt.db channel-commitment (kind=2) watches armed for the trustless standalone WT: ${K2:-0}"
echo
set +e
if [ "$PEN" = 1 ] && [ "${K2:-0}" -ge 1 ]; then
    # OUTCOME (not just a broadcast log line): confirm the penalty ON-CHAIN + assert the swept amount.
    PEN_TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE (source LIKE '%penalty%' OR source LIKE '%punish%') AND result='ok' AND length(txid)=64 ORDER BY id DESC LIMIT 1;" 2>/dev/null)
    [ -z "$PEN_TXID" ] && PEN_TXID=$(grep -aoiE "penalty tx broadcast: *[0-9a-f]{64}|Latest state tx broadcast: *[0-9a-f]{64}|punished[^0-9a-f]*[0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    [ -n "$PEN_TXID" ] || { red "FAIL: penalty was broadcast but no penalty txid found (broadcast_log + LSP log)"; tail -25 "$LSP_LOG"; exit 1; }
    echo "  penalty txid: $PEN_TXID — mining to confirm + verify payout"
    mine 6
    PRAW=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null)
    echo "$PRAW" | grep -q '"confirmations"' || { red "FAIL: penalty $PEN_TXID never CONFIRMED on-chain (broadcast != confirmed)"; exit 1; }
    PV=$(echo "$PRAW" | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    PSATS=$(awk "BEGIN{printf \"%d\", ($PV+0)*100000000}")
    echo "  penalty confirmed on-chain; largest output ${PSATS:-0} sats"
    [ "${PSATS:-0}" -ge 5000 ] || { red "FAIL: penalty output ${PSATS} sats too small — not a real to_local recovery (dust/zero?)"; exit 1; }
    green "PASS: a PS channel-commitment breach was PUNISHED — penalty $PEN_TXID CONFIRMED on-chain ($PSATS sats),"
    green "      and the same penalty is armed in wt.db ($K2 kind=2 watches). Outcome verified, not just broadcast."
    exit 0
elif [ "$PEN" = 1 ]; then
    red "PARTIAL: penalty fired but wt.db kind=2=$K2 — in-process works, trustless arming unconfirmed"; exit 1
else
    red "FAIL: no penalty broadcast for the PS channel-commitment breach. THIS would be a real bug. Full LSP log tail:"; tail -30 "$LSP_LOG"; exit 1
fi
