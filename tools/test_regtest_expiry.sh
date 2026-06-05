#!/usr/bin/env bash
# test_regtest_expiry.sh — exercise --test-expiry (Multi-Level Timeout Recovery).
#
# After the demo, the LSP broadcasts the factory tree (kickoff_root + state_root
# + chain nodes), mines past the per-level CLTVs, and recovers funds via the
# leaf-level AND mid-level timeout scripts.  This is the cooperative-failure
# recovery path (no breach, no penalty) — the last never-run --test-* flag.
# PASS = "EXPIRY TEST PASSED" (leaf_recovered > 0 && mid_recovered > 0).
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS=4; PORT=29955; FEE=1100; ARITY=2; AMOUNT=200000
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-expiry.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/expiry_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== EXPIRY (multi-level timeout recovery) on regtest ==="
"$LSP_BIN" --network regtest --port $PORT --demo --test-expiry --lsp-balance-pct 50 \
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

echo "--- waiting for EXPIRY TEST result + LSP exit (~6min) ---"
for i in $(seq 1 220); do
    sleep 2
    grep -qE "EXPIRY TEST (PASSED|FAILED)" "$LSP_LOG" 2>/dev/null && { echo "  marker seen (${i}*2s)"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited"; break; }
done
for s in $(seq 1 20); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done
[ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""

echo; echo "=== evidence ==="
grep -aiE "EXPIRY TEST|recover|timeout tx broadcast|leaf_recovered|mid_recovered|PASSED|FAILED" "$LSP_LOG" 2>/dev/null | tail -15
echo
if grep -q "EXPIRY TEST PASSED" "$LSP_LOG" 2>/dev/null; then
    green "PASS: multi-level CLTV timeout recovery (leaf + mid) succeeded."
    exit 0
else
    red "FAIL: expiry timeout recovery did not complete"; tail -30 "$LSP_LOG"; exit 1
fi
