#!/usr/bin/env bash
#
# Start SuperScalar LSP daemon for signet/testnet4 deployment.
# Usage: ./start_lsp.sh [--network signet|testnet4] [--port 9735] [--clients 4]
#
set -euo pipefail

# Defaults
NETWORK="${NETWORK:-signet}"
PORT="${PORT:-9735}"
CLIENTS="${CLIENTS:-4}"
AMOUNT="${AMOUNT:-100000}"
ACTIVE_BLOCKS="${ACTIVE_BLOCKS:-4320}"
DYING_BLOCKS="${DYING_BLOCKS:-432}"
FEE_RATE="${FEE_RATE:-2000}"
DB_PATH="${DB_PATH:-/var/lib/superscalar/lsp.db}"
LOG_DIR="${LOG_DIR:-/var/log/superscalar}"
PID_DIR="${PID_DIR:-/var/run/superscalar}"
LSP_BINARY="${LSP_BINARY:-superscalar_lsp}"
CLI_PATH="${CLI_PATH:-bitcoin-cli}"
RPC_USER="${RPC_USER:-rpcuser}"
RPC_PASS="${RPC_PASS:-rpcpass}"
KEYFILE="${KEYFILE:-}"
PASSPHRASE="${PASSPHRASE:-}"

# Parse overrides from command line
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)   NETWORK="$2"; shift 2 ;;
        --port)      PORT="$2"; shift 2 ;;
        --clients)   CLIENTS="$2"; shift 2 ;;
        --amount)    AMOUNT="$2"; shift 2 ;;
        --fee-rate)  FEE_RATE="$2"; shift 2 ;;
        --db)        DB_PATH="$2"; shift 2 ;;
        --keyfile)   KEYFILE="$2"; shift 2 ;;
        --passphrase) PASSPHRASE="$2"; shift 2 ;;
        *)           echo "Unknown flag: $1"; exit 1 ;;
    esac
done

# Create directories
mkdir -p "$LOG_DIR" "$PID_DIR" "$(dirname "$DB_PATH")"

# Build command
CMD=("$LSP_BINARY"
    --network "$NETWORK"
    --daemon --cli
    --db "$DB_PATH"
    --port "$PORT"
    --clients "$CLIENTS"
    --amount "$AMOUNT"
    --active-blocks "$ACTIVE_BLOCKS"
    --dying-blocks "$DYING_BLOCKS"
    --fee-rate "$FEE_RATE"
    --dynamic-fees
    --auto-rebalance
    --cli-path "$CLI_PATH"
    --rpcuser "$RPC_USER"
    --rpcpassword "$RPC_PASS"
)

if [[ -n "$KEYFILE" ]]; then
    CMD+=(--keyfile "$KEYFILE")
    if [[ -n "$PASSPHRASE" ]]; then
        CMD+=(--passphrase "$PASSPHRASE")
    fi
fi

echo "Starting LSP: ${CMD[*]}"
echo "  Network: $NETWORK"
echo "  Port: $PORT"
echo "  Clients: $CLIENTS"
echo "  DB: $DB_PATH"
echo "  Log: $LOG_DIR/lsp.log"

# Start with logging
"${CMD[@]}" >> "$LOG_DIR/lsp.log" 2>&1 &
LSP_PID=$!
echo "$LSP_PID" > "$PID_DIR/lsp.pid"
echo "LSP started (PID $LSP_PID)"
