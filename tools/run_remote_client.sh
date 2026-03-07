#!/bin/bash
# SuperScalar remote client — connects to a remote LSP over the internet.
#
# Usage:
#   bash tools/run_remote_client.sh --host <LSP_HOST> --port 9735 --network testnet4
#   bash tools/run_remote_client.sh --host <LSP_HOST> --port 9735 --network testnet4 --keyfile client.key
#
# Prerequisites:
#   - superscalar_client binary in ../build/ (or specify --build-dir)
#   - LSP must be running on the remote host with the specified port open
#   - For testnet4: the remote LSP needs funded UTXOs

set -euo pipefail

# Defaults
HOST=""
PORT=9735
NETWORK="testnet4"
KEYFILE=""
BUILD_DIR=""
LSP_PUBKEY=""
EXTRA_ARGS=""
LOG_FILE=""

usage() {
    echo "Usage: $0 --host <IP> [--port PORT] [--network NETWORK] [--keyfile PATH] [--lsp-pubkey HEX]"
    echo ""
    echo "Options:"
    echo "  --host          LSP host IP or hostname (required)"
    echo "  --port          LSP port (default: 9735)"
    echo "  --network       Network: regtest, signet, testnet4 (default: testnet4)"
    echo "  --keyfile       Path to client key file (optional, generates ephemeral if omitted)"
    echo "  --lsp-pubkey    LSP public key hex (optional, for verification)"
    echo "  --build-dir     Path to build directory containing superscalar_client"
    echo "  --log           Log file path (default: /tmp/remote_client.log)"
    echo "  --extra         Extra arguments to pass to superscalar_client"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --network) NETWORK="$2"; shift 2 ;;
        --keyfile) KEYFILE="$2"; shift 2 ;;
        --lsp-pubkey) LSP_PUBKEY="$2"; shift 2 ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --log) LOG_FILE="$2"; shift 2 ;;
        --extra) EXTRA_ARGS="$2"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$HOST" ]]; then
    echo "ERROR: --host is required"
    usage
fi

# Find client binary
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -z "$BUILD_DIR" ]]; then
    BUILD_DIR="$(dirname "$SCRIPT_DIR")/build"
fi
CLIENT_BIN="$BUILD_DIR/superscalar_client"

if [[ ! -x "$CLIENT_BIN" ]]; then
    echo "ERROR: superscalar_client not found at $CLIENT_BIN"
    echo "Build first: cd build && cmake .. && make -j\$(nproc)"
    exit 1
fi

# Set log file
if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="/tmp/remote_client_${NETWORK}_$(date +%Y%m%d_%H%M%S).log"
fi

# Build command
CMD=("$CLIENT_BIN"
    "--host" "$HOST"
    "--port" "$PORT"
    "--network" "$NETWORK"
)

if [[ -n "$KEYFILE" ]]; then
    CMD+=("--keyfile" "$KEYFILE")
fi

if [[ -n "$LSP_PUBKEY" ]]; then
    CMD+=("--lsp-pubkey" "$LSP_PUBKEY")
fi

if [[ -n "$EXTRA_ARGS" ]]; then
    # shellcheck disable=SC2206
    CMD+=($EXTRA_ARGS)
fi

echo "=== SuperScalar Remote Client ==="
echo "Host:    $HOST:$PORT"
echo "Network: $NETWORK"
echo "Keyfile: ${KEYFILE:-<ephemeral>}"
echo "Log:     $LOG_FILE"
echo "Binary:  $CLIENT_BIN"
echo "Command: ${CMD[*]}"
echo "================================="
echo ""
echo "Connecting to LSP at $HOST:$PORT..."
echo ""

# Run client, tee to log
"${CMD[@]}" 2>&1 | tee "$LOG_FILE"
RC=${PIPESTATUS[0]}

echo ""
echo "Client exited with code $RC"
echo "Log saved to $LOG_FILE"
exit $RC
