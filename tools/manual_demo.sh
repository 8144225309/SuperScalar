#!/bin/bash
# tools/manual_demo.sh — SuperScalar Manual Step-by-Step Control
#
# Subcommands:
#   setup          Start bitcoind, create+fund wallet
#   start-lsp      Start LSP daemon (background), save PID
#   start-clients  Start 4 client daemons (background), save PIDs
#   status         Show process + channel state from DB
#   balances       Dump channel balances from SQLite
#   stop           Kill all daemons
#   teardown       Stop bitcoind, clean temp files

set -e

# ---------------------------------------------------------------------------
# Color definitions
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

DEMO_DIR="/tmp/superscalar_demo"
LSP_DB="$DEMO_DIR/lsp.db"
LSP_PID_FILE="$DEMO_DIR/lsp.pid"

PORT=9735
AMOUNT=100000
NETWORK="regtest"
CLI_ARGS="-regtest"

LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

CLIENT_KEYS=(
    "2222222222222222222222222222222222222222222222222222222222222222"
    "3333333333333333333333333333333333333333333333333333333333333333"
    "4444444444444444444444444444444444444444444444444444444444444444"
    "5555555555555555555555555555555555555555555555555555555555555555"
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
ok()   { echo -e "  ${GREEN}+${NC} $1"; }
fail() { echo -e "  ${RED}!${NC} $1"; }
info() { echo -e "  ${CYAN}>${NC} $1"; }

check_binaries() {
    if [ ! -f "$LSP_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
        fail "Binaries not found. Build first: cd build && cmake .. && make -j\$(nproc)"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Subcommand: setup
# ---------------------------------------------------------------------------
cmd_setup() {
    echo -e "${BOLD}Setting up demo environment${NC}"
    mkdir -p "$DEMO_DIR"
    ok "Created $DEMO_DIR"

    # Start bitcoind if needed
    if ! bitcoin-cli $CLI_ARGS getblockchaininfo >/dev/null 2>&1; then
        info "Starting bitcoind $CLI_ARGS..."
        bitcoind $CLI_ARGS -daemon -fallbackfee=0.00001 -txindex=1 2>/dev/null
        echo "1" > "$DEMO_DIR/started_bitcoind"
        sleep 2
        if ! bitcoin-cli $CLI_ARGS getblockchaininfo >/dev/null 2>&1; then
            fail "Could not start bitcoind"
            exit 1
        fi
        ok "bitcoind started"
    else
        ok "bitcoind already running"
    fi

    # Ensure wallet
    if ! bitcoin-cli $CLI_ARGS -rpcwallet=superscalar_lsp getbalance >/dev/null 2>&1; then
        bitcoin-cli $CLI_ARGS createwallet superscalar_lsp >/dev/null 2>&1 || true
        ok "Created wallet 'superscalar_lsp'"
    fi

    # Fund wallet if needed
    BALANCE=$(bitcoin-cli $CLI_ARGS -rpcwallet=superscalar_lsp getbalance 2>/dev/null || echo "0")
    BALANCE_INT=$(printf '%.0f' "$BALANCE" 2>/dev/null || echo "0")
    if [ "$BALANCE_INT" -lt 1 ] 2>/dev/null; then
        info "Funding wallet..."
        ADDR=$(bitcoin-cli $CLI_ARGS -rpcwallet=superscalar_lsp getnewaddress 2>/dev/null)
        bitcoin-cli $CLI_ARGS generatetoaddress 101 "$ADDR" >/dev/null 2>&1
        ok "Mined 101 blocks, wallet funded"
    else
        ok "Wallet already funded (balance: $BALANCE BTC)"
    fi

    ok "Setup complete"
}

# ---------------------------------------------------------------------------
# Subcommand: start-lsp
# ---------------------------------------------------------------------------
cmd_start_lsp() {
    check_binaries
    echo -e "${BOLD}Starting LSP daemon${NC}"

    if [ -f "$LSP_PID_FILE" ] && kill -0 "$(cat "$LSP_PID_FILE")" 2>/dev/null; then
        fail "LSP already running (PID $(cat "$LSP_PID_FILE"))"
        exit 1
    fi

    $LSP_BIN --network $NETWORK --port $PORT --clients 4 --amount $AMOUNT \
        --seckey $LSP_SECKEY --db "$LSP_DB" --daemon &
    LSP_PID=$!
    echo "$LSP_PID" > "$LSP_PID_FILE"
    ok "LSP started (PID $LSP_PID, DB: $LSP_DB)"
    info "Waiting for clients to connect..."
}

# ---------------------------------------------------------------------------
# Subcommand: start-clients
# ---------------------------------------------------------------------------
cmd_start_clients() {
    check_binaries
    echo -e "${BOLD}Starting 4 client daemons${NC}"

    for i in 0 1 2 3; do
        CLIENT_DB="$DEMO_DIR/client_${i}.db"
        CLIENT_PID_FILE="$DEMO_DIR/client_${i}.pid"

        if [ -f "$CLIENT_PID_FILE" ] && kill -0 "$(cat "$CLIENT_PID_FILE")" 2>/dev/null; then
            info "Client $i already running (PID $(cat "$CLIENT_PID_FILE"))"
            continue
        fi

        $CLIENT_BIN --seckey "${CLIENT_KEYS[$i]}" --port $PORT \
            --network $NETWORK --db "$CLIENT_DB" --daemon \
            --lsp-pubkey $LSP_PUBKEY &
        C_PID=$!
        echo "$C_PID" > "$CLIENT_PID_FILE"
        ok "Client $i started (PID $C_PID, DB: $CLIENT_DB)"
        sleep 0.3
    done

    ok "All clients started"
}

# ---------------------------------------------------------------------------
# Subcommand: status
# ---------------------------------------------------------------------------
cmd_status() {
    echo -e "${BOLD}Process Status${NC}"

    # LSP
    if [ -f "$LSP_PID_FILE" ] && kill -0 "$(cat "$LSP_PID_FILE")" 2>/dev/null; then
        ok "LSP: running (PID $(cat "$LSP_PID_FILE"))"
    else
        info "LSP: not running"
    fi

    # Clients
    for i in 0 1 2 3; do
        PID_FILE="$DEMO_DIR/client_${i}.pid"
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            ok "Client $i: running (PID $(cat "$PID_FILE"))"
        else
            info "Client $i: not running"
        fi
    done

    # Channel state from DB
    echo ""
    echo -e "${BOLD}Channel State (from LSP DB)${NC}"
    if [ -f "$LSP_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 -header -column "$LSP_DB" \
            "SELECT channel_id, local_amount, remote_amount, commitment_number FROM channels" 2>/dev/null \
            || info "No channel data yet"
    else
        info "DB not available (need sqlite3 + $LSP_DB)"
    fi
}

# ---------------------------------------------------------------------------
# Subcommand: balances
# ---------------------------------------------------------------------------
cmd_balances() {
    echo -e "${BOLD}Channel Balances${NC}"

    if [ ! -f "$LSP_DB" ]; then
        fail "LSP database not found: $LSP_DB"
        exit 1
    fi

    if ! command -v sqlite3 >/dev/null 2>&1; then
        fail "sqlite3 not installed"
        exit 1
    fi

    echo ""
    echo "  LSP Database ($LSP_DB):"
    sqlite3 -header -column "$LSP_DB" \
        "SELECT channel_id AS ch, local_amount AS local_sats, remote_amount AS remote_sats, commitment_number AS commit_n FROM channels" 2>/dev/null \
        || info "No channels"

    echo ""
    for i in 0 1 2 3; do
        CLIENT_DB="$DEMO_DIR/client_${i}.db"
        if [ -f "$CLIENT_DB" ]; then
            echo "  Client $i Database ($CLIENT_DB):"
            sqlite3 -header -column "$CLIENT_DB" \
                "SELECT channel_id AS ch, local_amount AS local_sats, remote_amount AS remote_sats, commitment_number AS commit_n FROM channels" 2>/dev/null \
                || info "No channels"
            echo ""
        fi
    done
}

# ---------------------------------------------------------------------------
# Subcommand: stop
# ---------------------------------------------------------------------------
cmd_stop() {
    echo -e "${BOLD}Stopping all daemons${NC}"

    # Stop clients first
    for i in 0 1 2 3; do
        PID_FILE="$DEMO_DIR/client_${i}.pid"
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID" 2>/dev/null || true
                ok "Stopped client $i (PID $PID)"
            fi
            rm -f "$PID_FILE"
        fi
    done

    # Stop LSP
    if [ -f "$LSP_PID_FILE" ]; then
        PID=$(cat "$LSP_PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            ok "Stopped LSP (PID $PID)"
        fi
        rm -f "$LSP_PID_FILE"
    fi

    wait 2>/dev/null || true
    ok "All daemons stopped"
}

# ---------------------------------------------------------------------------
# Subcommand: teardown
# ---------------------------------------------------------------------------
cmd_teardown() {
    echo -e "${BOLD}Tearing down demo environment${NC}"

    cmd_stop

    # Stop bitcoind if we started it
    if [ -f "$DEMO_DIR/started_bitcoind" ]; then
        bitcoin-cli $CLI_ARGS stop 2>/dev/null || true
        rm -f "$DEMO_DIR/started_bitcoind"
        ok "Stopped bitcoind"
    fi

    # Clean temp files
    rm -rf "$DEMO_DIR"
    ok "Removed $DEMO_DIR"
    ok "Teardown complete"
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------
if [ $# -eq 0 ]; then
    echo "Usage: bash tools/manual_demo.sh <command>"
    echo ""
    echo "Commands:"
    echo "  setup          Start bitcoind, create+fund wallet"
    echo "  start-lsp      Start LSP daemon (background)"
    echo "  start-clients  Start 4 client daemons (background)"
    echo "  status         Show process + channel state from DB"
    echo "  balances       Dump channel balances from SQLite"
    echo "  stop           Kill all daemons"
    echo "  teardown       Stop bitcoind, clean temp files"
    exit 0
fi

case "$1" in
    setup)         cmd_setup ;;
    start-lsp)     cmd_start_lsp ;;
    start-clients) cmd_start_clients ;;
    status)        cmd_status ;;
    balances)      cmd_balances ;;
    stop)          cmd_stop ;;
    teardown)      cmd_teardown ;;
    *)
        fail "Unknown command: $1"
        echo "Run without arguments for usage."
        exit 1
        ;;
esac
