#!/usr/bin/env bash
# setup_regtest.sh — One-time regtest environment setup for SuperScalar testing.
#
# Sets env vars, starts bitcoind, creates wallet, mines initial blocks.
# Source this script (don't execute) to export vars into your shell:
#
#   source tools/setup_regtest.sh
#
# After sourcing, you can run:
#   cd $SUPERSCALAR_BUILD && ./test_superscalar --regtest
#   python3 tools/manual_tests.py all
#   python3 tools/test_orchestrator.py --scenario all

set -euo pipefail

# --- Auto-detect paths ---

# bitcoin-cli: check common locations
if command -v bitcoin-cli &>/dev/null; then
    BTC_CLI="$(command -v bitcoin-cli)"
elif [ -x "$HOME/bin/bitcoin-cli" ]; then
    BTC_CLI="$HOME/bin/bitcoin-cli"
elif [ -x "/usr/local/bin/bitcoin-cli" ]; then
    BTC_CLI="/usr/local/bin/bitcoin-cli"
else
    echo "ERROR: bitcoin-cli not found. Install Bitcoin Core 28.1+ and add to PATH."
    return 1 2>/dev/null || exit 1
fi

# bitcoind: same directory as bitcoin-cli
BTCD="$(dirname "$BTC_CLI")/bitcoind"
if [ ! -x "$BTCD" ]; then
    echo "ERROR: bitcoind not found at $BTCD"
    return 1 2>/dev/null || exit 1
fi

# Build directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -d "$HOME/superscalar-build" ]; then
    BUILD_DIR="$HOME/superscalar-build"
elif [ -d "$PROJECT_DIR/build" ]; then
    BUILD_DIR="$PROJECT_DIR/build"
else
    echo "ERROR: No build directory found. Run: mkdir -p build && cd build && cmake .. && make -j\$(nproc)"
    return 1 2>/dev/null || exit 1
fi

# Bitcoin config (optional)
if [ -f "$HOME/bitcoin-regtest/bitcoin.conf" ]; then
    BTC_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
    CONF_FLAGS="-regtest -conf=$BTC_CONF"
else
    BTC_CONF=""
    CONF_FLAGS="-regtest -rpcuser=rpcuser -rpcpassword=rpcpass"
fi

# --- Export env vars ---

export SUPERSCALAR_BTC="$BTC_CLI"
export SUPERSCALAR_BUILD="$BUILD_DIR"
export SUPERSCALAR_BTCCONF="${BTC_CONF}"
export PATH="$(dirname "$BTC_CLI"):$PATH"

echo "Environment:"
echo "  SUPERSCALAR_BTC=$SUPERSCALAR_BTC"
echo "  SUPERSCALAR_BUILD=$SUPERSCALAR_BUILD"
echo "  SUPERSCALAR_BTCCONF=$SUPERSCALAR_BTCCONF"

# --- Stop any existing regtest ---

$BTC_CLI $CONF_FLAGS stop 2>/dev/null || true
sleep 2

# --- Wipe stale data ---

rm -rf "$HOME/.bitcoin/regtest"
echo "Wiped ~/.bitcoin/regtest"

# --- Start bitcoind ---

$BTCD -daemon -fallbackfee=0.00001 -txindex=1 $CONF_FLAGS
echo "Started bitcoind (regtest)"

# Wait for RPC to be ready
for i in $(seq 1 15); do
    if $BTC_CLI $CONF_FLAGS getblockchaininfo &>/dev/null; then
        break
    fi
    sleep 1
done

if ! $BTC_CLI $CONF_FLAGS getblockchaininfo &>/dev/null; then
    echo "ERROR: bitcoind failed to start after 15 seconds"
    return 1 2>/dev/null || exit 1
fi

# --- Create wallet and mine ---

$BTC_CLI $CONF_FLAGS createwallet superscalar_lsp >/dev/null 2>&1 || true
ADDR=$($BTC_CLI $CONF_FLAGS -rpcwallet=superscalar_lsp getnewaddress "" bech32m)
$BTC_CLI $CONF_FLAGS -rpcwallet=superscalar_lsp generatetoaddress 101 "$ADDR" >/dev/null

echo "Wallet 'superscalar_lsp' funded (101 blocks mined)"
echo ""
echo "Ready. You can now run:"
echo "  cd $BUILD_DIR && ./test_superscalar --regtest"
echo "  python3 tools/manual_tests.py all"
echo "  python3 tools/test_orchestrator.py --scenario all"
