#!/usr/bin/env bash

# Self-respawn in own session so systemd-logind cleanup on SSH session end
# doesn't kill us mid-run.
if [ -z "${_SS_TESTNET4_DETACHED:-}" ] && [ ! -t 0 ]; then
    export _SS_TESTNET4_DETACHED=1
    exec setsid "$0" "$@"
fi

# test_testnet4_n128_ps_lifecycle.sh — N=128 PS factory full lifecycle on
# testnet4.
#
# N=128 is the next-step scale-shape past the canonical t/1242 N=64.  This
# test:
#   1. Creates a PS factory with 128 clients (1 LSP + 127 daemon clients,
#      arity 2,4,8 mixed with static-near-root=2)
#   2. Drives the full ceremony (factory creation + all node signing)
#   3. Validates the factory is funded + tree broadcast
#   4. Force-closes the factory and verifies all tree TXs broadcast
#
# Unit tests covering N=128 at the in-memory level:
#   - test_factory_build_tree_n128 (254 nodes, depth=6, 7 DW layers)
#   - test_factory_ps_build_n128 (506 nodes, 127 leaves, 8 DW layers,
#     128-way MuSig verified)
#   - test_factory_static_near_root_n128_arity_2_4_8_static_2 (the shape
#     used here)
#   - test_cli_shape_mixed_248_static2_n128_passes (CLI accepts this shape)
#
# All in-memory N=128 work landed via PR #64 (2026-04-18).  This script
# is the real-chain counterpart, intended for the v0.2.0 release validation.
#
# Wall time: 8-24 hours depending on testnet4 block tempo.  Funding draws
# 6.4M sats from $WALLET; ensure adequate balance before launch.
#
# IMPORTANT: do NOT run this concurrently with the N=64 lifecycle
# (test_testnet4_n64_ps_lifecycle.sh) — both use the same wallet and
# would race on UTXO selection.

set -euo pipefail

# shellcheck source=test_diag_lib.sh
source "$(dirname "$0")/test_diag_lib.sh"

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
# Fee rate in sat/kvB. Default 1000 = 1 sat/vB = testnet4 wallet mintxfee floor.
FEE_RATE="${FEE_RATE:-1000}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

NETWORK="testnet4"
RPCUSER="${RPCUSER:-testnet4rpc}"
RPCPASS="${RPCPASS:-testnet4rpcpass123}"
RPCPORT="${RPCPORT:-48332}"
WALLET="${WALLET:-superscalar_test}"
PORT="${PORT:-9941}"  # 9940 is reserved for N=64; use 9941 for N=128

N_CLIENTS=128
ARITY="${ARITY:-2,4,8}"                    # validated by test_cli_shape_mixed_248_static2_n128_passes
STATIC_NEAR_ROOT="${STATIC_NEAR_ROOT:-2}"  # N=128 uses static_near_root=2, NOT 1 (N=64's choice)
AMOUNT="${AMOUNT:-6400000}"                # ~50k sats per party (128 * 50k)

TAG="ts_n128_ps_lifecycle"
LSP_DB="/tmp/ss_t4_${TAG}.db"
LSP_LOG="/tmp/ss_t4_${TAG}_lsp.log"
DONE="/tmp/ss_t4_${TAG}.done"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"

rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$DONE"
for n in $(seq 2 129); do
    HEX=$(printf '%064x' $n)
    rm -f "/tmp/ss_t4_${TAG}_c${HEX:60:4}.db"* "/tmp/ss_t4_${TAG}_c${HEX:60:4}.log"
done
diag_setup "ss_t4_${TAG}"

echo "=== testnet4 N=128 PS lifecycle ==="
echo "  port            : $PORT"
echo "  wallet          : $WALLET"
echo "  N_CLIENTS       : $N_CLIENTS"
echo "  ARITY           : $ARITY"
echo "  static-near-root: $STATIC_NEAR_ROOT"
echo "  funding         : $AMOUNT sats"

# Sanity check: verify wallet balance is sufficient before launching
# 128 clients (otherwise we'd burn ~20 min on connect storm only to
# fail at funding).
BAL_SATS=$(bitcoin-cli -testnet4 -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" \
    -rpcport="$RPCPORT" -rpcwallet="$WALLET" getbalance 2>/dev/null \
    | awk '{printf "%.0f", $1 * 100000000}')
if [ -n "$BAL_SATS" ] && [ "$BAL_SATS" -lt "$AMOUNT" ]; then
    echo "FAIL: wallet $WALLET has $BAL_SATS sats < required $AMOUNT" >&2
    exit 1
fi
echo "  wallet balance  : $BAL_SATS sats (OK)"

# LSP: N=128 needs --max-conn-rate and --max-handshakes doubled from N=64
# (which used 400/80).  Connect storm of 128 clients in ~30s requires
# 800/160 to avoid backpressure.
nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root "$STATIC_NEAR_ROOT" \
    --amount "$AMOUNT" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 100 \
    --confirm-timeout 86400 \
    --max-conn-rate 800 --max-handshakes 160 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    --demo --force-close \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
echo "  LSP pid=$LSP_PID"
diag_periodic "$LSP_PID" 60

# Wait for listen — give N=128 a touch more startup time than N=64.
for i in $(seq 1 90); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -30 "$LSP_LOG"; exit 1; }
done

# Launch 128 clients with sequential seckeys (0x02..0x81).
for i in $(seq 1 $N_CLIENTS); do
    SK=$(printf '%064x' $((i + 1)))  # 0x02 .. 0x81
    nohup "$CLIENT_BIN" \
        --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 100 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $i \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c${SK:60:4}.db" \
        > "/tmp/ss_t4_${TAG}_c${SK:60:4}.log" 2>&1 &
    sleep 0.2  # stagger to avoid HELLO_ACK pile-up
done

diag_wait_lsp "$LSP_PID" "$LSP_LOG" "ss_t4_${TAG}"
EXIT=$DIAG_EXIT
pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true

echo "EXIT=$EXIT" > "$DONE"
echo "=== N=128 PS lifecycle done $(date) exit=$EXIT ===" >> "$DONE"
grep -E "tree.*broadcast|FORCE CLOSE|force close|confirmed" "$LSP_LOG" | tail -30 >> "$DONE"
cat "$DONE"
exit $EXIT
