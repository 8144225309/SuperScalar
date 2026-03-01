#!/usr/bin/env bash
#
# Start SuperScalar client daemon.
#
set -euo pipefail

LSP_HOST="${LSP_HOST:-127.0.0.1}"
LSP_PORT="${LSP_PORT:-9735}"
NETWORK="${NETWORK:-signet}"
LSP_PUBKEY="${LSP_PUBKEY:-}"
KEYFILE="${KEYFILE:-}"
PASSPHRASE="${PASSPHRASE:-}"
CLIENT_BINARY="${CLIENT_BINARY:-superscalar_client}"
LOG_DIR="${LOG_DIR:-/var/log/superscalar}"
PID_DIR="${PID_DIR:-/var/run/superscalar}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)       LSP_HOST="$2"; shift 2 ;;
        --port)       LSP_PORT="$2"; shift 2 ;;
        --network)    NETWORK="$2"; shift 2 ;;
        --lsp-pubkey) LSP_PUBKEY="$2"; shift 2 ;;
        --keyfile)    KEYFILE="$2"; shift 2 ;;
        --passphrase) PASSPHRASE="$2"; shift 2 ;;
        *)            echo "Unknown flag: $1"; exit 1 ;;
    esac
done

mkdir -p "$LOG_DIR" "$PID_DIR"

CMD=("$CLIENT_BINARY"
    --host "$LSP_HOST"
    --port "$LSP_PORT"
    --network "$NETWORK"
    --daemon
)

if [[ -n "$LSP_PUBKEY" ]]; then
    CMD+=(--lsp-pubkey "$LSP_PUBKEY")
fi
if [[ -n "$KEYFILE" ]]; then
    CMD+=(--keyfile "$KEYFILE")
    if [[ -n "$PASSPHRASE" ]]; then
        CMD+=(--passphrase "$PASSPHRASE")
    fi
fi

echo "Starting client: ${CMD[*]}"
echo "  LSP: $LSP_HOST:$LSP_PORT"
echo "  Network: $NETWORK"
echo "  Log: $LOG_DIR/client.log"

"${CMD[@]}" >> "$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
echo "$CLIENT_PID" > "$PID_DIR/client.pid"
echo "Client started (PID $CLIENT_PID)"
