#!/bin/bash
# SuperScalar Demo: Multi-Party Channel Factory with Live Payments
#
# This demo showcases the SuperScalar protocol — a novel Bitcoin Lightning
# scaling solution that creates N+1-of-N+1 MuSig2 channel factories with
# Decker-Wattenhofer state machines.
#
# What happens:
#   1. LSP creates a 5-of-5 factory (1 LSP + 4 clients), funded on-chain
#   2. 4 payment channels are established inside the factory
#   3. Payments flow between clients via real preimage/hash validation
#   4. Final balances reflect all payments
#   5. Cooperative close settles everything in a single on-chain transaction
#
# Prerequisites:
#   - bitcoind running with -regtest
#   - Build: cd build && cmake .. && make -j$(nproc)
#
# Usage: bash tools/demo.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

PORT=9735

# RPC authentication (optional — falls back to cookie auth)
RPC_ARGS=""
if [ -n "$RPCUSER" ]; then
    RPC_ARGS="-rpcuser=$RPCUSER -rpcpassword=${RPCPASSWORD:-}"
fi

# LSP key (deterministic for demo — secp256k1 generator key)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Client secret keys (deterministic for demo)
CLIENT1_KEY="2222222222222222222222222222222222222222222222222222222222222222"
CLIENT2_KEY="3333333333333333333333333333333333333333333333333333333333333333"
CLIENT3_KEY="4444444444444444444444444444444444444444444444444444444444444444"
CLIENT4_KEY="5555555555555555555555555555555555555555555555555555555555555555"

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kill $LSP_PID 2>/dev/null || true
    kill $C1_PID 2>/dev/null || true
    kill $C2_PID 2>/dev/null || true
    kill $C3_PID 2>/dev/null || true
    kill $C4_PID 2>/dev/null || true
    wait 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT

echo "============================================================"
echo "  SuperScalar: Multi-Party Channel Factory Demo"
echo "  First Implementation of ZmnSCPxj's Design"
echo "============================================================"
echo ""
echo "  Protocol:  N+1-of-N+1 MuSig2 + Decker-Wattenhofer"
echo "  Parties:   1 LSP + 4 clients (5-of-5 factory)"
echo "  Funding:   100,000 sats on-chain"
echo ""

# Check binaries exist
if [ ! -f "$LSP_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
    echo "ERROR: Binaries not found. Build first:"
    echo "  cd build && cmake .. && make -j\$(nproc)"
    exit 1
fi

# Check bitcoind
if ! bitcoin-cli -regtest $RPC_ARGS getblockchaininfo >/dev/null 2>&1; then
    echo "ERROR: bitcoind not running with -regtest"
    exit 1
fi

echo "------------------------------------------------------------"
echo "  Step 1: Factory Creation"
echo "------------------------------------------------------------"
echo ""
echo "  Starting LSP with --demo flag..."
echo "  The LSP will:"
echo "    - Accept 4 client connections"
echo "    - Fund a factory on-chain (100,000 sats)"
echo "    - Create the DW state tree (kickoff + state nodes)"
echo "    - Establish 4 channels inside the factory"
echo "    - Run a scripted payment sequence"
echo "    - Cooperatively close the factory"
echo ""

LSP_RPC=""
if [ -n "$RPCUSER" ]; then
    LSP_RPC="--rpcuser $RPCUSER --rpcpassword ${RPCPASSWORD:-}"
fi
$LSP_BIN --regtest --port $PORT --clients 4 --amount 100000 --seckey $LSP_SECKEY --demo $LSP_RPC &
LSP_PID=$!
sleep 2

echo "  Starting 4 clients in daemon mode..."
$CLIENT_BIN --seckey $CLIENT1_KEY --port $PORT --daemon --lsp-pubkey $LSP_PUBKEY &
C1_PID=$!
sleep 0.5

$CLIENT_BIN --seckey $CLIENT2_KEY --port $PORT --daemon --lsp-pubkey $LSP_PUBKEY &
C2_PID=$!
sleep 0.5

$CLIENT_BIN --seckey $CLIENT3_KEY --port $PORT --daemon --lsp-pubkey $LSP_PUBKEY &
C3_PID=$!
sleep 0.5

$CLIENT_BIN --seckey $CLIENT4_KEY --port $PORT --daemon --lsp-pubkey $LSP_PUBKEY &
C4_PID=$!

echo ""
echo "------------------------------------------------------------"
echo "  Step 2: Waiting for payments and cooperative close..."
echo "------------------------------------------------------------"
echo ""

# Wait for LSP to finish (demo + close)
wait $LSP_PID 2>/dev/null
LSP_EXIT=$?

# Clients exit after close
wait $C1_PID 2>/dev/null || true
wait $C2_PID 2>/dev/null || true
wait $C3_PID 2>/dev/null || true
wait $C4_PID 2>/dev/null || true

echo ""
echo "============================================================"
if [ "$LSP_EXIT" = "0" ]; then
    echo "  DEMO SUCCESS"
    echo ""
    echo "  What happened:"
    echo "    - Factory created: 5-of-5 MuSig2, 100,000 sats"
    echo "    - 4 payments routed through LSP with real preimages"
    echo "    - SHA256(preimage) validated at each hop"
    echo "    - Cooperative close: single on-chain transaction"
    echo ""
    echo "  This is SuperScalar: scalable, trust-minimized,"
    echo "  multi-party channel factories for Bitcoin Lightning."
else
    echo "  DEMO COMPLETE (LSP exit code: $LSP_EXIT)"
fi
echo "============================================================"

# Disarm trap since we already cleaned up
trap - EXIT
