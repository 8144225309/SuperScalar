#!/usr/bin/env bash
#
# SuperScalar health check — verifies all components are running.
# Exit 0 = healthy, Exit 1 = unhealthy.
#
set -euo pipefail

PID_DIR="${PID_DIR:-/var/run/superscalar}"
CLI_PATH="${CLI_PATH:-bitcoin-cli}"
NETWORK="${NETWORK:-signet}"
LIGHTNING_CLI="${LIGHTNING_CLI:-lightning-cli}"
OK=0
WARN=0

check() {
    local label="$1"
    local result="$2"
    if [[ "$result" == "ok" ]]; then
        echo "[OK]   $label"
    else
        echo "[FAIL] $label: $result"
        OK=1
    fi
}

warn() {
    local label="$1"
    local result="$2"
    echo "[WARN] $label: $result"
    WARN=1
}

echo "=== SuperScalar Health Check ==="
echo "  Time: $(date -u)"
echo ""

# 1. Check LSP process
if [[ -f "$PID_DIR/lsp.pid" ]]; then
    LSP_PID=$(cat "$PID_DIR/lsp.pid")
    if kill -0 "$LSP_PID" 2>/dev/null; then
        check "LSP process" "ok"
    else
        check "LSP process" "PID $LSP_PID not running"
    fi
else
    check "LSP process" "no PID file"
fi

# 2. Check bridge process
if [[ -f "$PID_DIR/bridge.pid" ]]; then
    BRIDGE_PID=$(cat "$PID_DIR/bridge.pid")
    if kill -0 "$BRIDGE_PID" 2>/dev/null; then
        check "Bridge process" "ok"
    else
        check "Bridge process" "PID $BRIDGE_PID not running"
    fi
else
    check "Bridge process" "no PID file"
fi

# 3. Check bitcoin-cli connectivity
if BLOCK_HEIGHT=$("$CLI_PATH" -"$NETWORK" getblockcount 2>/dev/null); then
    check "Bitcoin node" "ok"
    echo "       Block height: $BLOCK_HEIGHT"
else
    check "Bitcoin node" "bitcoin-cli failed"
fi

# 4. Check CLN plugin
if PLUGIN_LIST=$("$LIGHTNING_CLI" plugin list 2>/dev/null); then
    if echo "$PLUGIN_LIST" | grep -q "cln_plugin"; then
        check "CLN plugin" "ok"
    else
        check "CLN plugin" "not loaded"
    fi
else
    warn "CLN plugin" "lightning-cli unavailable"
fi

# 5. Check CLN node connectivity
if CLN_INFO=$("$LIGHTNING_CLI" getinfo 2>/dev/null); then
    CLN_BLOCKHEIGHT=$(echo "$CLN_INFO" | grep -o '"blockheight":[0-9]*' | grep -o '[0-9]*')
    check "CLN node" "ok"
    echo "       CLN block height: ${CLN_BLOCKHEIGHT:-unknown}"
else
    warn "CLN node" "lightning-cli getinfo failed"
fi

echo ""
if [[ $OK -eq 0 ]]; then
    echo "Status: HEALTHY"
else
    echo "Status: UNHEALTHY"
fi
if [[ $WARN -gt 0 ]]; then
    echo "  ($WARN warnings)"
fi
exit $OK
