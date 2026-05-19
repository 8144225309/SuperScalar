#!/usr/bin/env bash

# Self-respawn in own session so systemd-logind cleanup on SSH session end
# doesn't kill us mid-run (lesson from 2026-05-18 dual #112/#189 deaths).
# Skip if already respawned or if running interactively (stdin is a tty).
if [ -z "${_SS_TESTNET4_DETACHED:-}" ] && [ ! -t 0 ]; then
    export _SS_TESTNET4_DETACHED=1
    exec setsid "$0" "$@"
fi

# test_testnet4_ts_ptlc_basic.sh — TS-PTLC-BASIC (#107, SF-W-PTLC Phase 3a)
# on testnet4 using --test-ptlc-basic.
#
# Wall time: ~10-30 minutes on testnet4 (one factory creation cycle + tree
# broadcast confirmation). The PTLC test itself runs in-memory after the
# demo channels are up, so the long pole is the factory confirm wait.
#
# Uses build-release (per #138 — ASan binaries die silently in long RPC
# polling against bitcoind).

set -euo pipefail

# shellcheck source=test_diag_lib.sh
source "$(dirname "$0")/test_diag_lib.sh"

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

NETWORK="testnet4"
RPCUSER="${RPCUSER:-testnet4rpc}"
RPCPASS="${RPCPASS:-testnet4rpcpass123}"
RPCPORT="${RPCPORT:-48332}"
WALLET="${WALLET:-superscalar_test}"
PORT="${PORT:-9913}"

N_CLIENTS=4
ARITY=2
AMOUNT="${AMOUNT:-2000000}"

TAG="ts_ptlc_basic"
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

echo "=== testnet4 TS-PTLC-BASIC (#107, SF-W-PTLC Phase 3a) ==="
echo "  port    : $PORT"
echo "  wallet  : $WALLET"
echo "  N       : $N_CLIENTS"
echo "  amount  : $AMOUNT sats"
echo "  binary  : build-release (per #138 ASan-stability rule)"
echo "  fee-rate: 110 sat/vB (signet-budget memory rule)"

pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true

# --test-ptlc-basic implies --enable-ptlc-unsafe (parser flips the gate).
# --fee-rate 1100 per signet-sat budget memory.
nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --demo --test-ptlc-basic \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --amount "$AMOUNT" --fee-rate 1100 \
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

# 4 clients with repeated-byte seckeys (standard testnet4 launcher scheme).
for N in 1 2 3 4; do
    HEX=$(printf "%02x" $((N * 0x11)))    # 22, 33, 44, 55
    SK=""
    for _ in $(seq 1 32); do SK="${SK}${HEX}"; done
    nohup "$CLIENT_BIN" \
        --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$N" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c${HEX}.db" \
        > "/tmp/ss_t4_${TAG}_c${HEX}.log" 2>&1 &
    sleep 0.5
done

echo "  $N_CLIENTS clients launched; waiting for LSP to exit..."

diag_wait_lsp "$LSP_PID" "$LSP_LOG" "ss_t4_${TAG}"
EXIT=$DIAG_EXIT

pkill -f "superscalar_client.*--port $PORT" 2>/dev/null || true
echo "EXIT=$EXIT" > "$DONE"

if [ "$EXIT" -eq 0 ] && grep -q "PTLC BASIC TEST PASSED" "$LSP_LOG"; then
    echo "=== PASS: TS-PTLC-BASIC ==="
    grep -E "PTLC BASIC|PTLC added|PTLC failed|Commitment TX|safety gate" "$LSP_LOG" | head -20
    exit 0
else
    echo "=== FAIL: exit=$EXIT, see $LSP_LOG ==="
    tail -40 "$LSP_LOG"
    exit 1
fi
