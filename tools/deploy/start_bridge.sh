#!/usr/bin/env bash
#
# Start SuperScalar bridge daemon with auto-restart supervisor.
# Connects CLN plugin to LSP.
#
# Flags (or the environment variables in capitals):
#   --lsp-host HOST            LSP_HOST            default 127.0.0.1
#   --lsp-port PORT            LSP_PORT            default 9735
#   --lsp-pubkey HEX           LSP_PUBKEY          required: the LSP prints it at startup
#   --plugin-port PORT         PLUGIN_PORT         default 19736
#   --plugin-bind ADDR         PLUGIN_BIND         default 127.0.0.1 (bridge default)
#   --plugin-secret-file PATH  PLUGIN_SECRET_FILE  default ~/.superscalar/bridge-plugin.secret
#
# The bridge creates the secret file (mode 0600) on first start.  The CLN
# plugin must read the same secret from a file owned by the user lightningd
# runs as; see "Running the plugin as a different user" in
# docs/lsp-operator-guide.md.
#
# The bridge exits with status 78 when its configuration is unusable.  That
# is not retried.
#
set -euo pipefail

LSP_HOST="${LSP_HOST:-127.0.0.1}"
LSP_PORT="${LSP_PORT:-9735}"
PLUGIN_PORT="${PLUGIN_PORT:-19736}"
LSP_PUBKEY="${LSP_PUBKEY:-}"
PLUGIN_BIND="${PLUGIN_BIND:-}"
PLUGIN_SECRET_FILE="${PLUGIN_SECRET_FILE:-}"
LOG_DIR="${LOG_DIR:-/var/log/superscalar}"
PID_DIR="${PID_DIR:-/var/run/superscalar}"
BRIDGE_BINARY="${BRIDGE_BINARY:-superscalar_bridge}"
MAX_BACKOFF=60
BACKOFF=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lsp-host)    LSP_HOST="$2"; shift 2 ;;
        --lsp-port)    LSP_PORT="$2"; shift 2 ;;
        --plugin-port) PLUGIN_PORT="$2"; shift 2 ;;
        --lsp-pubkey)  LSP_PUBKEY="$2"; shift 2 ;;
        --plugin-bind) PLUGIN_BIND="$2"; shift 2 ;;
        --plugin-secret-file) PLUGIN_SECRET_FILE="$2"; shift 2 ;;
        *)             echo "Unknown flag: $1"; exit 1 ;;
    esac
done

mkdir -p "$LOG_DIR" "$PID_DIR"

echo "Starting bridge supervisor"
echo "  LSP: $LSP_HOST:$LSP_PORT"
echo "  Plugin port: ${PLUGIN_BIND:-127.0.0.1}:$PLUGIN_PORT"
echo "  Plugin secret file: ${PLUGIN_SECRET_FILE:-~/.superscalar/bridge-plugin.secret}"
echo "  Log: $LOG_DIR/bridge.log"

echo $$ > "$PID_DIR/bridge.pid"

while true; do
    CMD=("$BRIDGE_BINARY"
        --lsp-host "$LSP_HOST"
        --lsp-port "$LSP_PORT"
        --plugin-port "$PLUGIN_PORT"
    )
    if [[ -n "$LSP_PUBKEY" ]]; then
        CMD+=(--lsp-pubkey "$LSP_PUBKEY")
    fi
    if [[ -n "$PLUGIN_BIND" ]]; then
        CMD+=(--plugin-bind "$PLUGIN_BIND")
    fi
    if [[ -n "$PLUGIN_SECRET_FILE" ]]; then
        CMD+=(--plugin-secret-file "$PLUGIN_SECRET_FILE")
    fi

    echo "[$(date)] Starting bridge: ${CMD[*]}" >> "$LOG_DIR/bridge.log"
    EXIT_CODE=0
    "${CMD[@]}" >> "$LOG_DIR/bridge.log" 2>&1 || EXIT_CODE=$?

    # 78: the bridge cannot run as configured.  Restarting changes nothing.
    if [[ $EXIT_CODE -eq 78 ]]; then
        echo "[$(date)] Bridge refused its configuration (exit 78); not restarting." \
            "See the error above." >> "$LOG_DIR/bridge.log"
        echo "Bridge refused its configuration; see $LOG_DIR/bridge.log" >&2
        exit 78
    fi

    echo "[$(date)] Bridge exited with code $EXIT_CODE, restarting in ${BACKOFF}s..." \
        >> "$LOG_DIR/bridge.log"
    sleep "$BACKOFF"

    # Exponential backoff capped at MAX_BACKOFF, reset on success
    if [[ $EXIT_CODE -eq 0 ]]; then
        BACKOFF=1
    else
        BACKOFF=$((BACKOFF * 2))
        if [[ $BACKOFF -gt $MAX_BACKOFF ]]; then
            BACKOFF=$MAX_BACKOFF
        fi
    fi
done
