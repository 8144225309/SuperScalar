#!/usr/bin/env bash
# activate_testnet4_ln_bridge.sh — enable the SuperScalar bridge plugin
# on the existing CLN-A testnet4 node and start the bridge daemon, so
# the LSP can route real Lightning payments INTO/OUT OF factory clients.
#
# Prerequisites (already on VPS at <SIGNET_VPS>):
#   - CLN-A running with /var/lib/cln-testnet4/config
#   - The config has the bridge plugin lines commented out
#   - $BUILD_DIR/superscalar_bridge binary exists
#   - bitcoind testnet4 running on RPC port 48332
#
# What this does:
#   1. Uncomment the plugin lines in CLN-A's config
#   2. Restart CLN-A (forces plugin load)
#   3. Start superscalar_bridge in the background
#   4. Print the bridge's listen port for LSP to connect via --bridge-port
#
# The actual BOLT11 test driver is in a separate runner — this script
# just ACTIVATES the testbed.

set -uo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build}"
BRIDGE_BIN="$BUILD_DIR/superscalar_bridge"
CLN_DIR="${CLN_DIR:-/var/lib/cln-testnet4}"
CLN_CONFIG="$CLN_DIR/config"
BRIDGE_PORT="${BRIDGE_PORT:-9737}"
BRIDGE_LOG="${BRIDGE_LOG:-/tmp/superscalar_bridge.log}"
PLUGIN_PATH="/root/SuperScalar/tools/cln_plugin.py"

echo "=== Activate testnet4 LN bridge ==="
echo "  CLN dir       : $CLN_DIR"
echo "  Plugin path   : $PLUGIN_PATH"
echo "  Bridge binary : $BRIDGE_BIN"
echo "  Bridge port   : $BRIDGE_PORT"

if [ ! -x "$BRIDGE_BIN" ]; then
    echo "FAIL: $BRIDGE_BIN missing or not executable; rebuild first"
    exit 1
fi
if [ ! -f "$PLUGIN_PATH" ]; then
    echo "FAIL: $PLUGIN_PATH missing"
    exit 1
fi

# 1. Uncomment plugin lines in CLN config (idempotent).
sed -i 's|^#plugin=/root/SuperScalar/tools/cln_plugin.py|plugin=/root/SuperScalar/tools/cln_plugin.py|' "$CLN_CONFIG"
sed -i 's|^#superscalar-bridge-host=|superscalar-bridge-host=|' "$CLN_CONFIG"
sed -i "s|^#superscalar-bridge-port=9737|superscalar-bridge-port=$BRIDGE_PORT|" "$CLN_CONFIG"
sed -i 's|^#superscalar-lightning-cli=|superscalar-lightning-cli=|' "$CLN_CONFIG"

echo
echo "--- Updated CLN config (plugin lines) ---"
grep -E '^(plugin|superscalar)' "$CLN_CONFIG"

# 2. Restart CLN-A so it picks up the plugin.
echo
echo "--- Restarting CLN-A ---"
PID=$(pgrep -f "lightningd.*$CLN_DIR")
if [ -n "$PID" ]; then
    kill -TERM "$PID"
    for i in $(seq 1 30); do
        sleep 1
        kill -0 "$PID" 2>/dev/null || break
    done
fi
sleep 2
lightningd --lightning-dir="$CLN_DIR" --daemon
sleep 3

if ! lightning-cli --lightning-dir="$CLN_DIR" getinfo >/dev/null 2>&1; then
    echo "FAIL: CLN-A didn't restart cleanly; check $CLN_DIR/cln.log"
    exit 1
fi
echo "  CLN-A running, plugin loaded:"
lightning-cli --lightning-dir="$CLN_DIR" plugin list 2>/dev/null | grep -i superscalar || \
    echo "  WARNING: plugin not in 'plugin list' output yet"

# 3. Start the bridge daemon.
echo
echo "--- Starting superscalar_bridge ---"
pkill -f superscalar_bridge 2>/dev/null || true
sleep 1

nohup "$BRIDGE_BIN" \
    --plugin-port "$BRIDGE_PORT" \
    --network testnet4 \
    --lightning-cli "lightning-cli --lightning-dir=$CLN_DIR" \
    > "$BRIDGE_LOG" 2>&1 &
BRIDGE_PID=$!
sleep 2

if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "FAIL: bridge didn't start; check $BRIDGE_LOG"
    tail -20 "$BRIDGE_LOG"
    exit 1
fi

echo "  Bridge PID=$BRIDGE_PID listening on port $BRIDGE_PORT"
echo "  Bridge log : $BRIDGE_LOG"
echo

echo "=== LN bridge testbed active ==="
echo "Next steps:"
echo "  - Start an LSP with --bridge-port $BRIDGE_PORT to route HTLCs"
echo "  - From a factory client, request BOLT11 invoice via the LSP CLI"
echo "  - Pay the invoice from any LN wallet (phone, Eclair, LND, etc.)"
echo "  - Watch \$BRIDGE_LOG for 'htlc_accepted' → forwarded → factory client"
