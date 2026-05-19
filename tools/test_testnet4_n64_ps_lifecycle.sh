#!/usr/bin/env bash

# Self-respawn in own session so systemd-logind cleanup on SSH session end
# doesn't kill us mid-run (lesson from 2026-05-18 dual #112/#189 deaths).
# Skip if already respawned or if running interactively (stdin is a tty).
if [ -z "${_SS_TESTNET4_DETACHED:-}" ] && [ ! -t 0 ]; then
    export _SS_TESTNET4_DETACHED=1
    exec setsid "$0" "$@"
fi

# test_testnet4_n64_ps_lifecycle.sh — N=64 PS factory full lifecycle on
# testnet4.
#
# N=64 is the canonical scale-shape from t/1242.  This test:
#   1. Creates a PS factory with 64 clients
#   2. Drives the full ceremony (factory creation + all node signing)
#   3. Validates the factory is funded + tree broadcast
#   4. Force-closes the factory and verifies all tree TXs broadcast
#
# Unit tests cover N=64 at the in-memory level
# (test_factory_ps_subfactory_poison_tx_k2_n4 et al.).  This is the
# real-chain counterpart.  Wall time: 4-12 hours depending on testnet4
# block tempo.
#
# Note: requires the N=64 LSP fix (Issue #3 from PR #161) for the
# HELLO_ACK timeout — already merged on main.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

NETWORK="testnet4"
RPCUSER="${RPCUSER:-testnet4rpc}"
RPCPASS="${RPCPASS:-testnet4rpcpass123}"
RPCPORT="${RPCPORT:-48332}"
WALLET="${WALLET:-superscalar_test}"
PORT="${PORT:-9940}"

N_CLIENTS=64
ARITY="${ARITY:-2,4,8}"  # canonical mixed-arity from docs
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-1}"
AMOUNT="${AMOUNT:-3000000}"  # ~46k sats per party

TAG="ts_n64_ps_lifecycle"
LSP_DB="/tmp/ss_t4_${TAG}.db"
LSP_LOG="/tmp/ss_t4_${TAG}_lsp.log"
DONE="/tmp/ss_t4_${TAG}.done"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$DONE"
for n in $(seq 2 65); do
    HEX=$(printf '%064x' $n)
    rm -f "/tmp/ss_t4_${TAG}_c${HEX:60:4}.db"* "/tmp/ss_t4_${TAG}_c${HEX:60:4}.log"
done

echo "=== testnet4 N=64 PS lifecycle ==="
echo "  port            : $PORT"
echo "  wallet          : $WALLET"
echo "  N_CLIENTS       : $N_CLIENTS"
echo "  ARITY           : $ARITY"
echo "  static-near-root: $STATIC_NEAR_ROOT"
echo "  funding         : $AMOUNT sats"

# Issue #3 fix already on main: client HELLO_ACK timeout extended to 600s.
# At N=64 with sequential accept loop the first client may wait ~60s for
# HELLO_ACK; the 600s window is generous.

# LSP needs --max-conn-rate and --max-handshakes raised for N=64.
nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root "$STATIC_NEAR_ROOT" \
    --amount "$AMOUNT" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate 1000 --lsp-balance-pct 100 \
    --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    --demo --force-close \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
echo "  LSP pid=$LSP_PID"

# Wait for listen
for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -20 "$LSP_LOG"; exit 1; }
done

# Launch 64 clients with sequential seckeys (0x02..0x41).
for i in $(seq 1 $N_CLIENTS); do
    SK=$(printf '%064x' $((i + 1)))  # 0x02 .. 0x41
    nohup "$CLIENT_BIN" \
        --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK" --fee-rate 1000 --lsp-balance-pct 100 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $i \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c${SK:60:4}.db" \
        > "/tmp/ss_t4_${TAG}_c${SK:60:4}.log" 2>&1 &
    sleep 0.2  # stagger to avoid HELLO_ACK pile-up
done

wait $LSP_PID
EXIT=$?
pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true

echo "EXIT=$EXIT" > "$DONE"
echo "=== N=64 PS lifecycle done $(date) exit=$EXIT ===" >> "$DONE"
grep -E "tree.*broadcast|FORCE CLOSE|force close|confirmed" "$LSP_LOG" | tail -20 >> "$DONE"
cat "$DONE"
exit $EXIT
