#!/usr/bin/env bash
#
# Start SuperScalar bridge daemon with auto-restart supervisor.
# Connects CLN plugin to LSP.
#
set -euo pipefail

LSP_HOST="${LSP_HOST:-127.0.0.1}"
LSP_PORT="${LSP_PORT:-9735}"
PLUGIN_PORT="${PLUGIN_PORT:-19736}"
LSP_PUBKEY="${LSP_PUBKEY:-}"
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
        *)             echo "Unknown flag: $1"; exit 1 ;;
    esac
done

mkdir -p "$LOG_DIR" "$PID_DIR"

echo "Starting bridge supervisor"
echo "  LSP: $LSP_HOST:$LSP_PORT"
echo "  Plugin port: $PLUGIN_PORT"
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

    echo "[$(date)] Starting bridge: ${CMD[*]}" >> "$LOG_DIR/bridge.log"
    "${CMD[@]}" >> "$LOG_DIR/bridge.log" 2>&1
    EXIT_CODE=$?

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
