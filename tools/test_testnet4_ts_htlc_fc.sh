#!/usr/bin/env bash

# Self-respawn in own session so systemd-logind cleanup on SSH session end
# doesn't kill us mid-run (lesson from 2026-05-18 dual #112/#189 deaths).
# Skip if already respawned or if running interactively (stdin is a tty).
if [ -z "${_SS_TESTNET4_DETACHED:-}" ] && [ ! -t 0 ]; then
    export _SS_TESTNET4_DETACHED=1
    exec setsid "$0" "$@"
fi

# test_testnet4_ts_htlc_fc.sh — TS-HTLC-FC (#112): force-close with HTLC pending
# on testnet4 using --test-htlc-force-close.
#
# Wall time: 4-12 hours depending on testnet4 block tempo. Uses build-release
# (per #138 — ASan binaries die silently in long RPC polling).

set -euo pipefail

# Diagnostic helpers: forensics bundle on LSP death, periodic /proc snapshots.
# shellcheck source=test_diag_lib.sh
source "$(dirname "$0")/test_diag_lib.sh"

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
# Fee rate in sat/kvB. Default 1000 = 1 sat/vB = testnet4 wallet mintxfee floor.
# Lower (e.g. FEE_RATE=100 = 0.1 sat/vB) when running sat-recovery sweeps
# against a bitcoind that has -mintxfee lowered in bitcoin.conf.
FEE_RATE="${FEE_RATE:-1000}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

NETWORK="testnet4"
RPCUSER="${RPCUSER:-testnet4rpc}"
RPCPASS="${RPCPASS:-$(sed -n 's/^rpcpassword=//p' /var/lib/bitcoind-testnet4/bitcoin.conf 2>/dev/null)}"
RPCPORT="${RPCPORT:-48332}"
WALLET="${WALLET:-superscalar_test}"
PORT="${PORT:-9912}"

N_CLIENTS=4
ARITY=2
AMOUNT="${AMOUNT:-2000000}"

TAG="ts_htlc_fc"
LSP_DB="/tmp/ss_t4_${TAG}.db"
LSP_LOG="/tmp/ss_t4_${TAG}_lsp.log"
DONE="/tmp/ss_t4_${TAG}.done"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$DONE"
for HEX in 2222 3333 4444 5555; do
    rm -f "/tmp/ss_t4_${TAG}_c${HEX}.db"* "/tmp/ss_t4_${TAG}_c${HEX}.log"
done
diag_setup "ss_t4_${TAG}"

echo "=== testnet4 TS-HTLC-FC (#112) ==="
echo "  port    : $PORT"
echo "  wallet  : $WALLET"
echo "  N       : $N_CLIENTS"
echo "  amount  : $AMOUNT sats"
echo "  binary  : build-release (per #138 ASan-stability rule)"

pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true

nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --demo --test-htlc-force-close \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --amount "$AMOUNT" --fee-rate "$FEE_RATE" \
    --confirm-timeout 259200 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
echo "  LSP pid=$LSP_PID"
diag_periodic "$LSP_PID" 60

# Wait for listen
for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP died early"
        tail -20 "$LSP_LOG"
        echo "EXIT=1" > "$DONE"
        exit 1
    fi
done

# 4 clients with repeated-byte seckeys (standard testnet4 launcher scheme)
for N in 1 2 3 4; do
    HEX=$(printf "%02x" $((N * 0x11)))    # 22, 33, 44, 55
    SK=$(printf "%s" "$HEX" | head -c 2)
    SK_FULL=""
    for _ in $(seq 1 32); do SK_FULL="${SK_FULL}${SK}"; done
    nohup "$CLIENT_BIN" \
        --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK_FULL" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$N" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c${SK}${SK}.db" \
        > "/tmp/ss_t4_${TAG}_c${SK}${SK}.log" 2>&1 &
    sleep 0.5
done

echo "  4 clients launched; waiting for LSP to exit..."

# Wait for LSP to finish (captures EXIT without set -e short-circuit;
# runs diag bundle if LSP dies non-zero).
diag_wait_lsp "$LSP_PID" "$LSP_LOG" "ss_t4_${TAG}"
EXIT=$DIAG_EXIT

pkill -f "superscalar_client.*--port $PORT" 2>/dev/null || true
echo "EXIT=$EXIT" > "$DONE"

if [ "$EXIT" -eq 0 ] && grep -q "HTLC FORCE-CLOSE TEST PASSED" "$LSP_LOG"; then
    echo "=== PASS: TS-HTLC-FC (HTLC timeout TX broadcast + confirmed) ==="
    exit 0
else
    echo "=== FAIL: exit=$EXIT, see $LSP_LOG ==="
    tail -30 "$LSP_LOG"
    exit 1
fi
