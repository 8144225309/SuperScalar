#!/bin/bash
# SuperScalar Signet Setup — subcommand-based setup and diagnostics.
#
# Each subcommand: header → explain → do → query → result → next step.
# JSON parsing via python3 (no jq dependency).
#
# Usage: bash tools/signet_setup.sh <subcommand>
#   Run without arguments for help.

set -e

# ==========================================================================
# Configuration — edit these paths for your environment
# ==========================================================================

BTCBIN="${BTCBIN:-$(dirname "$(command -v bitcoin-cli 2>/dev/null || echo /usr/local/bin/bitcoin-cli)")}"
CLNDIR="${CLNDIR:-$(dirname "$(command -v lightningd 2>/dev/null || echo /usr/local/bin/lightningd)")/..}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCBIN="${SCBIN:-$SCRIPT_DIR/../build}"

# Source .env if it exists (credentials, paths)
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    . "$SCRIPT_DIR/.env"
    set +a
fi

DATADIR="${DATADIR:-/tmp/superscalar-signet}"
RPCUSER="${RPCUSER:-superscalar}"
RPCPASS="${RPCPASS:-superscalar123}"
RPCPORT="${RPCPORT:-38332}"

# Derived paths
BTCDATA="$DATADIR/bitcoin"
CLNA_DIR="$DATADIR/cln-a"
CLNB_DIR="$DATADIR/cln-b"
LOGDIR="$DATADIR/logs"
LSPDB="$DATADIR/lsp.db"
CLIENTDB="$DATADIR/client1.db"
CLIENT2DB="$DATADIR/client2.db"
CLIENT3DB="$DATADIR/client3.db"
CLIENT4DB="$DATADIR/client4.db"
SCDIR="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
LD_LIBRARY_PATH_SC="$SCBIN/_deps/secp256k1-zkp-build/src:$SCBIN/_deps/cjson-build"

# ==========================================================================
# Helper commands
# ==========================================================================

btc() {
    "$BTCBIN/bitcoin-cli" -signet -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" "$@"
}

btc_wallet() {
    btc -rpcwallet=superscalar_lsp "$@"
}

cln_a() {
    "$CLNDIR/cli/lightning-cli" --lightning-dir="$CLNA_DIR" "$@"
}

cln_b() {
    "$CLNDIR/cli/lightning-cli" --lightning-dir="$CLNB_DIR" "$@"
}

# JSON field extraction via python3 (no jq dependency)
json_field() {
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$1',''))"
}

json_field_int() {
    python3 -c "import json,sys; d=json.load(sys.stdin); print(int(d.get('$1',0)))"
}

json_array_len() {
    python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('$1',[])))"
}

json_pretty() {
    python3 -c "import json,sys; json.dump(json.load(sys.stdin),sys.stdout,indent=2); print()"
}

# ==========================================================================
# Colored output helpers
# ==========================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

header()   { echo ""; echo -e "${BOLD}${CYAN}=== $* ===${NC}"; echo ""; }
info()     { echo -e "${GREEN}  ✓${NC} $*"; }
warn()     { echo -e "${YELLOW}  ⚠${NC} $*"; }
fail()     { echo -e "${RED}  ✗${NC} $*"; }
step()     { echo -e "${BOLD}  →${NC} $*"; }
detail()   { echo -e "${DIM}    $*${NC}"; }
nextstep() { echo ""; echo -e "${CYAN}  Next:${NC} bash $0 $*"; echo ""; }

# ==========================================================================
# 1. start-bitcoind
# ==========================================================================

cmd_start_bitcoind() {
    header "Start bitcoind (signet)"
    step "Creating data directory and config..."
    mkdir -p "$BTCDATA"
    cat > "$BTCDATA/bitcoin.conf" <<EOF
signet=1
txindex=1
server=1
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
[signet]
rpcport=$RPCPORT
EOF
    detail "Config: $BTCDATA/bitcoin.conf"

    if btc getblockchaininfo &>/dev/null; then
        info "bitcoind is already running"
    else
        step "Starting bitcoind daemon..."
        "$BTCBIN/bitcoind" -signet -datadir="$BTCDATA" -daemon
        step "Waiting for RPC to become available..."
        for i in $(seq 1 30); do
            if btc getblockchaininfo &>/dev/null; then
                info "bitcoind RPC ready"
                break
            fi
            if [ "$i" -eq 30 ]; then
                fail "bitcoind did not start within 30 seconds"
                exit 1
            fi
            sleep 1
        done
    fi

    step "Querying blockchain info..."
    CHAIN=$(btc getblockchaininfo | json_field chain)
    BLOCKS=$(btc getblockchaininfo | json_field_int blocks)
    HEADERS=$(btc getblockchaininfo | json_field_int headers)
    PEERS=$(btc getnetworkinfo | json_field_int connections)

    info "Chain:   $CHAIN"
    info "Blocks:  $BLOCKS / $HEADERS"
    info "Peers:   $PEERS"

    nextstep "sync-status"
}

# ==========================================================================
# 2. sync-status
# ==========================================================================

cmd_sync_status() {
    header "Sync Status"

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running. Start it first."
        nextstep "start-bitcoind"
        exit 1
    fi

    INFO=$(btc getblockchaininfo)
    BLOCKS=$(echo "$INFO" | json_field_int blocks)
    HEADERS=$(echo "$INFO" | json_field_int headers)
    IBD=$(echo "$INFO" | json_field initialblockdownload)
    PROGRESS=$(echo "$INFO" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'{d.get(\"verificationprogress\",0)*100:.2f}%')")
    PEERS=$(btc getnetworkinfo | json_field_int connections)

    info "Blocks:   $BLOCKS"
    info "Headers:  $HEADERS"
    info "Progress: $PROGRESS"
    info "IBD:      $IBD"
    info "Peers:    $PEERS"

    if [ "$IBD" = "True" ] || [ "$IBD" = "true" ]; then
        warn "Still in Initial Block Download. Wait for sync to complete."
        detail "This can take a few minutes for signet."
        echo ""
        step "Run this command again to check progress."
    else
        info "Fully synced!"
        nextstep "create-wallet"
    fi
}

# ==========================================================================
# 3. create-wallet
# ==========================================================================

cmd_create_wallet() {
    header "Create Wallet"

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running."
        nextstep "start-bitcoind"
        exit 1
    fi

    step "Creating/loading wallet 'superscalar_lsp'..."
    btc createwallet "superscalar_lsp" 2>/dev/null || \
        btc loadwallet "superscalar_lsp" 2>/dev/null || true

    step "Generating new address..."
    ADDR=$(btc_wallet getnewaddress "" bech32m)
    BAL=$(btc_wallet getbalance)

    info "Wallet:  superscalar_lsp"
    info "Address: $ADDR"
    info "Balance: $BAL BTC"

    # Check if balance is sufficient (need ~0.001 BTC for channel + fees)
    SUFFICIENT=$(python3 -c "print('yes' if float('$BAL') >= 0.001 else 'no')" 2>/dev/null || echo "no")
    if [ "$SUFFICIENT" = "no" ]; then
        warn "Insufficient balance (need ≥ 0.001 BTC)"
        echo ""
        detail "Fund from signet faucet:"
        detail "  https://signetfaucet.com/"
        detail "  Address: $ADDR"
        echo ""
        step "After funding, run: bash $0 check-balance"
    else
        info "Balance sufficient for channel funding"
        nextstep "check-balance"
    fi
}

# ==========================================================================
# 4. check-balance
# ==========================================================================

cmd_check_balance() {
    header "Check Balance"

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running."
        exit 1
    fi

    # Load wallet if needed
    btc loadwallet "superscalar_lsp" 2>/dev/null || true

    BAL=$(btc_wallet getbalance)
    info "Balance: $BAL BTC"

    step "Listing UTXOs..."
    UTXO_COUNT=$(btc_wallet listunspent | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

    info "UTXOs: $UTXO_COUNT"

    btc_wallet listunspent | python3 -c "
import json, sys
utxos = json.load(sys.stdin)
for u in utxos[:10]:
    print(f'    {u[\"amount\"]:>12.8f} BTC  conf={u.get(\"confirmations\",0):>4}  {u[\"txid\"][:16]}...')
" 2>/dev/null || true

    SUFFICIENT=$(python3 -c "print('yes' if float('$BAL') >= 0.001 else 'no')" 2>/dev/null || echo "no")
    if [ "$SUFFICIENT" = "yes" ]; then
        info "Balance sufficient"
        nextstep "start-cln-b"
    else
        warn "Need ≥ 0.001 BTC. Fund from signet faucet first."
    fi
}

# ==========================================================================
# 5. start-cln-b
# ==========================================================================

cmd_start_cln_b() {
    header "Start CLN Node B (vanilla)"

    mkdir -p "$CLNB_DIR"

    if cln_b getinfo &>/dev/null; then
        info "CLN Node B is already running"
    else
        step "Starting lightningd (port 9737)..."
        "$CLNDIR/lightningd/lightningd" \
            --network=signet \
            --lightning-dir="$CLNB_DIR" \
            --bitcoin-cli="$BTCBIN/bitcoin-cli" \
            --bitcoin-rpcuser="$RPCUSER" \
            --bitcoin-rpcpassword="$RPCPASS" \
            --bitcoin-rpcport="$RPCPORT" \
            --addr=127.0.0.1:9737 \
            --daemon
        sleep 2
    fi

    step "Querying node info..."
    if cln_b getinfo &>/dev/null; then
        NODE_ID=$(cln_b getinfo | json_field id)
        BH=$(cln_b getinfo | json_field_int blockheight)
        info "Node B ID:     ${NODE_ID:0:20}..."
        info "Blockheight:   $BH"
        info "Port:          9737"
    else
        fail "CLN Node B failed to start. Check $CLNB_DIR/log"
        exit 1
    fi

    nextstep "start-cln-a"
}

# ==========================================================================
# 6. start-cln-a
# ==========================================================================

cmd_start_cln_a() {
    header "Start CLN Node A (with SuperScalar plugin)"

    mkdir -p "$CLNA_DIR"

    if cln_a getinfo &>/dev/null; then
        info "CLN Node A is already running"
    else
        step "Starting lightningd (port 9738, SuperScalar plugin)..."
        "$CLNDIR/lightningd/lightningd" \
            --network=signet \
            --lightning-dir="$CLNA_DIR" \
            --bitcoin-cli="$BTCBIN/bitcoin-cli" \
            --bitcoin-rpcuser="$RPCUSER" \
            --bitcoin-rpcpassword="$RPCPASS" \
            --bitcoin-rpcport="$RPCPORT" \
            --addr=127.0.0.1:9738 \
            --plugin="$SCDIR/tools/cln_plugin.py" \
            --superscalar-bridge-host=127.0.0.1 \
            --superscalar-bridge-port=9736 \
            --superscalar-lightning-cli="$CLNDIR/cli/lightning-cli --lightning-dir=$CLNA_DIR" \
            --daemon
        sleep 2
    fi

    step "Querying node info..."
    if cln_a getinfo &>/dev/null; then
        NODE_ID=$(cln_a getinfo | json_field id)
        BH=$(cln_a getinfo | json_field_int blockheight)
        info "Node A ID:     ${NODE_ID:0:20}..."
        info "Blockheight:   $BH"
        info "Port:          9738"
        info "Plugin:        cln_plugin.py"
    else
        fail "CLN Node A failed to start. Check $CLNA_DIR/log"
        exit 1
    fi

    nextstep "open-channel"
}

# ==========================================================================
# 7. open-channel
# ==========================================================================

cmd_open_channel() {
    header "Open Channel (A → B)"

    if ! cln_a getinfo &>/dev/null; then
        fail "CLN Node A is not running."
        nextstep "start-cln-a"
        exit 1
    fi
    if ! cln_b getinfo &>/dev/null; then
        fail "CLN Node B is not running."
        nextstep "start-cln-b"
        exit 1
    fi

    # Fund Node A from bitcoind wallet
    step "Getting Node A funding address..."
    ADDR_A=$(cln_a newaddr | json_field bech32)
    info "Node A address: $ADDR_A"

    step "Sending 0.01 BTC to Node A..."
    btc loadwallet "superscalar_lsp" 2>/dev/null || true
    TXID=$(btc_wallet sendtoaddress "$ADDR_A" 0.01)
    info "Funding txid: ${TXID:0:16}..."

    step "Waiting for confirmation (signet ≈ 10 min)..."
    while true; do
        CONF=$(btc_wallet gettransaction "$TXID" | json_field_int confirmations 2>/dev/null || echo 0)
        if [ "${CONF:-0}" -ge 1 ]; then
            info "Funding confirmed ($CONF confirmations)"
            break
        fi
        detail "Waiting... confirmations=$CONF"
        sleep 30
    done

    # Connect A → B
    step "Connecting Node A to Node B..."
    NODE_B_ID=$(cln_b getinfo | json_field id)
    cln_a connect "$NODE_B_ID@127.0.0.1:9737" 2>/dev/null || true
    info "Connected"

    # Open 500k sat channel
    step "Opening 500,000 sat channel..."
    cln_a fundchannel "$NODE_B_ID" 500000
    info "Channel opening tx broadcast"

    step "Waiting for CHANNELD_NORMAL state..."
    while true; do
        STATE=$(cln_a listpeerchannels | python3 -c "
import json, sys
d = json.load(sys.stdin)
chans = d.get('channels', [])
if chans:
    print(chans[0].get('state', 'UNKNOWN'))
else:
    print('NO_CHANNEL')
" 2>/dev/null || echo "UNKNOWN")
        if [ "$STATE" = "CHANNELD_NORMAL" ]; then
            info "Channel ready! State: $STATE"
            break
        fi
        detail "Current state: $STATE"
        sleep 30
    done

    nextstep "start-bridge"
}

# ==========================================================================
# 8. channel-status
# ==========================================================================

cmd_channel_status() {
    header "CLN Channel Status"

    for label_fn in "Node A:cln_a" "Node B:cln_b"; do
        LABEL="${label_fn%%:*}"
        FN="${label_fn##*:}"

        echo -e "  ${BOLD}$LABEL${NC}"
        if ! $FN getinfo &>/dev/null; then
            fail "$LABEL is not running"
            continue
        fi

        $FN listpeerchannels | python3 -c "
import json, sys
d = json.load(sys.stdin)
chans = d.get('channels', [])
if not chans:
    print('    No channels')
else:
    for ch in chans:
        state = ch.get('state', '?')
        total = ch.get('total_msat', 0)
        local = ch.get('to_us_msat', 0)
        if isinstance(total, str): total = int(total.replace('msat',''))
        if isinstance(local, str): local = int(local.replace('msat',''))
        remote = total - local
        scid = ch.get('short_channel_id', '—')
        peer = ch.get('peer_id', '?')[:16]
        htlcs = len(ch.get('htlcs', []))
        print(f'    State: {state}')
        print(f'    SCID:  {scid}')
        print(f'    Cap:   {total // 1000:,} sat')
        print(f'    Local: {local // 1000:,} sat  Remote: {remote // 1000:,} sat')
        print(f'    HTLCs: {htlcs}')
        print(f'    Peer:  {peer}...')
        print()
" 2>/dev/null || fail "Could not query channels"
    done
}

# ==========================================================================
# 9. start-bridge
# ==========================================================================

cmd_start_bridge() {
    header "Start SuperScalar Bridge"

    mkdir -p "$LOGDIR"

    if pgrep -f "superscalar_bridge" &>/dev/null; then
        info "Bridge is already running"
    else
        step "Starting bridge (LSP port 9735, plugin port 9736)..."
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
            "$SCBIN/superscalar_bridge" \
                --lsp-port 9735 \
                --plugin-port 9736 \
            > "$LOGDIR/bridge.log" 2>&1 &
        BRIDGE_PID=$!
        sleep 1

        if kill -0 "$BRIDGE_PID" 2>/dev/null; then
            info "Bridge started (PID=$BRIDGE_PID)"
            detail "Log: $LOGDIR/bridge.log"
        else
            fail "Bridge failed to start. Check $LOGDIR/bridge.log"
            exit 1
        fi
    fi

    nextstep "start-lsp"
}

# ==========================================================================
# 10. start-lsp
# ==========================================================================

cmd_start_lsp() {
    header "Start SuperScalar LSP"

    mkdir -p "$LOGDIR"

    if pgrep -f "superscalar_lsp" &>/dev/null; then
        info "LSP is already running"
    else
        step "Starting LSP (4 clients, 200k sats, arity-1, signet)..."
        # step-blocks=1 for fast demo, arity-1 for per-client leaves
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
            "$SCBIN/superscalar_lsp" \
                --network signet \
                --cli-path "$BTCBIN/bitcoin-cli" \
                --rpcuser "$RPCUSER" \
                --rpcpassword "$RPCPASS" \
                --port 9735 \
                --clients 4 \
                --amount 200000 \
                --arity 1 \
                --step-blocks 1 \
                --daemon \
                --db "$LSPDB" \
                --keyfile "$DATADIR/lsp.key" \
                --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
            > "$LOGDIR/lsp.log" 2>&1 &
        LSP_PID=$!
        sleep 1

        if kill -0 "$LSP_PID" 2>/dev/null; then
            info "LSP started (PID=$LSP_PID)"
            detail "DB:  $LSPDB"
            detail "Log: $LOGDIR/lsp.log"
        else
            fail "LSP failed to start. Check $LOGDIR/lsp.log"
            exit 1
        fi
    fi

    nextstep "start-client"
}

# ==========================================================================
# 11. start-client
# ==========================================================================

cmd_start_client() {
    header "Start SuperScalar Client"

    mkdir -p "$LOGDIR"

    if pgrep -f "superscalar_client" &>/dev/null; then
        info "Client is already running"
    else
        step "Starting client (daemon mode)..."
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
            "$SCBIN/superscalar_client" \
                --keyfile "$DATADIR/client1.key" \
                --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
                --network signet \
                --port 9735 \
                --daemon \
                --db "$CLIENTDB" \
            > "$LOGDIR/client.log" 2>&1 &
        CLIENT_PID=$!
        sleep 2

        if kill -0 "$CLIENT_PID" 2>/dev/null; then
            info "Client started (PID=$CLIENT_PID)"
            detail "DB:  $CLIENTDB"
            detail "Log: $LOGDIR/client.log"
        else
            fail "Client failed to start. Check $LOGDIR/client.log"
            exit 1
        fi
    fi

    nextstep "status"
}

# ==========================================================================
# 11b. start-client2 (second client for 2-client factory)
# ==========================================================================

cmd_start_client2() {
    header "Start SuperScalar Client 2"

    mkdir -p "$LOGDIR"

    if pgrep -f "superscalar_client.*client2.key" &>/dev/null; then
        info "Client 2 is already running"
    else
        step "Starting client 2 (daemon mode)..."
        LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
            "$SCBIN/superscalar_client" \
                --keyfile "$DATADIR/client2.key" \
                --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
                --network signet \
                --port 9735 \
                --daemon \
                --db "$CLIENT2DB" \
            > "$LOGDIR/client2.log" 2>&1 &
        CLIENT2_PID=$!
        sleep 2

        if kill -0 "$CLIENT2_PID" 2>/dev/null; then
            info "Client 2 started (PID=$CLIENT2_PID)"
            detail "DB:  $CLIENT2DB"
            detail "Log: $LOGDIR/client2.log"
        else
            fail "Client 2 failed to start. Check $LOGDIR/client2.log"
            exit 1
        fi
    fi

    nextstep "status"
}

# ==========================================================================
# Helper: start N clients in background
# ==========================================================================

_start_demo_clients() {
    local NET="$1"        # signet or regtest
    local PORT="$2"
    local LOGPFX="$3"     # log filename prefix
    local EXTRA_ARGS="${4:-}"

    for i in 1 2 3 4; do
        local KEYFILE="$DATADIR/client${i}.key"
        local DBFILE="$DATADIR/client${i}.db"
        local LOGFILE="$LOGDIR/${LOGPFX}_client${i}.log"

        LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
            "$SCBIN/superscalar_client" \
                --keyfile "$KEYFILE" \
                --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
                --network "$NET" \
                --port "$PORT" \
                --db "$DBFILE" \
                $EXTRA_ARGS \
            > "$LOGFILE" 2>&1 &
        eval "CLIENT${i}_PID=$!"
        sleep 0.5
    done
    info "4 clients started"
}

# ==========================================================================
# Demo: cooperative close (LSP + 4 clients, --demo, coop close)
# ==========================================================================

cmd_demo_coop() {
    header "Demo: Factory + Payments + Cooperative Close"

    mkdir -p "$LOGDIR"

    step "Stopping any running SuperScalar processes..."
    pkill -f "superscalar_lsp" 2>/dev/null || true
    pkill -f "superscalar_client" 2>/dev/null || true
    sleep 2

    # Clean DBs for fresh demo
    rm -f "$LSPDB" "$CLIENTDB" "$CLIENT2DB" "$CLIENT3DB" "$CLIENT4DB"

    step "Starting cooperative close demo (4 clients, arity-1)..."
    detail "This will: connect 4 clients → create factory → run payments → cooperative close"
    detail "On signet, factory creation waits for funding tx confirmation (~10 min)."

    # Start LSP in background first (needs to listen before clients connect)
    LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
        "$SCBIN/superscalar_lsp" \
            --network signet \
            --cli-path "$BTCBIN/bitcoin-cli" \
            --rpcuser "$RPCUSER" \
            --rpcpassword "$RPCPASS" \
            --port 9735 \
            --clients 4 \
            --amount 200000 \
            --arity 1 \
            --step-blocks 1 \
            --demo \
            --db "$LSPDB" \
            --keyfile "$DATADIR/lsp.key" \
            --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
        > "$LOGDIR/demo_coop.log" 2>&1 &
    LSP_PID=$!
    sleep 2

    _start_demo_clients signet 9735 demo_coop "--daemon"

    # Wait for LSP to finish
    wait "$LSP_PID"
    LSP_EXIT=$?

    for i in 1 2 3 4; do
        eval "wait \$CLIENT${i}_PID 2>/dev/null || true"
    done

    echo ""
    echo "=== LSP Output ==="
    cat "$LOGDIR/demo_coop.log"

    if [ "$LSP_EXIT" -eq 0 ]; then
        info "Cooperative close demo completed successfully!"
    else
        fail "Demo failed (exit=$LSP_EXIT). Check logs in $LOGDIR/"
    fi
}

# ==========================================================================
# Demo: force close (LSP + 4 clients, --demo --force-close)
# ==========================================================================

cmd_demo_force_close() {
    header "Demo: Factory + Payments + Force Close (Tree Broadcast)"

    mkdir -p "$LOGDIR"

    step "Stopping any running SuperScalar processes..."
    pkill -f "superscalar_lsp" 2>/dev/null || true
    pkill -f "superscalar_client" 2>/dev/null || true
    sleep 2

    # Clean DBs for fresh demo
    rm -f "$LSPDB" "$CLIENTDB" "$CLIENT2DB" "$CLIENT3DB" "$CLIENT4DB"

    step "Starting force-close demo (4 clients, arity-1)..."
    detail "This will: connect 4 clients → create factory → run payments → broadcast tree → wait for confirmations"
    detail "On signet with step-blocks=1, each node needs ~10 min per block of relative timelock."
    detail "Arity-1 tree has 14 nodes with 3 DW layers. Most nSequence values are 0-3 blocks."

    # Start LSP in background first
    LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
        "$SCBIN/superscalar_lsp" \
            --network signet \
            --cli-path "$BTCBIN/bitcoin-cli" \
            --rpcuser "$RPCUSER" \
            --rpcpassword "$RPCPASS" \
            --port 9735 \
            --clients 4 \
            --amount 200000 \
            --arity 1 \
            --step-blocks 1 \
            --demo \
            --force-close \
            --db "$LSPDB" \
            --keyfile "$DATADIR/lsp.key" \
            --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
        > "$LOGDIR/demo_force_close.log" 2>&1 &
    LSP_PID=$!
    sleep 2

    _start_demo_clients signet 9735 demo_fc "--daemon"

    # Wait for LSP to finish
    wait "$LSP_PID"
    LSP_EXIT=$?

    for i in 1 2 3 4; do
        eval "wait \$CLIENT${i}_PID 2>/dev/null || true"
    done

    echo ""
    echo "=== LSP Output ==="
    cat "$LOGDIR/demo_force_close.log"

    if [ "$LSP_EXIT" -eq 0 ]; then
        info "Force-close demo completed successfully!"
        info "All tree nodes confirmed on-chain."
    else
        fail "Demo failed (exit=$LSP_EXIT). Check logs in $LOGDIR/"
    fi
}

# ==========================================================================
# Demo: breach (LSP + 4 clients, --demo --cheat-daemon, regtest only)
# ==========================================================================

cmd_demo_breach() {
    local NET="${2:-regtest}"
    header "Demo: Factory + Payments + Breach → Penalty + CPFP ($NET)"

    mkdir -p "$LOGDIR"

    step "Stopping any running SuperScalar processes..."
    pkill -f "superscalar_lsp" 2>/dev/null || true
    pkill -f "superscalar_client" 2>/dev/null || true
    sleep 2

    # Clean DBs for fresh demo
    rm -f "$LSPDB" "$CLIENTDB" "$CLIENT2DB" "$CLIENT3DB" "$CLIENT4DB"

    step "Starting breach demo (4 clients, arity-1, $NET)..."
    detail "This will: connect 4 clients → create factory → run payments"
    detail "→ LSP broadcasts revoked commitment (--cheat-daemon)"
    detail "→ client watchtowers detect breach → broadcast penalty with P2A anchor"
    detail "→ CPFP child bumps fee → penalty confirms"

    # On signet, breach wait is longer (need real block confirmations)
    local BREACH_WAIT=10
    if [ "$NET" = "signet" ]; then
        BREACH_WAIT=120
    fi

    # Start LSP with --cheat-daemon (broadcasts revoked commitment, then sleeps)
    LD_LIBRARY_PATH="$LD_LIBRARY_PATH_SC" \
        "$SCBIN/superscalar_lsp" \
            --network "$NET" \
            --cli-path "$BTCBIN/bitcoin-cli" \
            --rpcuser "$RPCUSER" \
            --rpcpassword "$RPCPASS" \
            --port 9735 \
            --clients 4 \
            --amount 200000 \
            --arity 1 \
            --step-blocks 1 \
            --demo \
            --cheat-daemon \
            --daemon \
            --db "$LSPDB" \
            --keyfile "$DATADIR/lsp.key" \
            --passphrase "${KEYFILE_PASSPHRASE:-superscalar}" \
        > "$LOGDIR/demo_breach.log" 2>&1 &
    LSP_PID=$!
    sleep 2

    _start_demo_clients "$NET" 9735 demo_breach "--daemon"

    # Wait for LSP to finish (it sleeps ~30s after breach on regtest, longer on signet)
    wait "$LSP_PID"
    LSP_EXIT=$?

    # Give clients time to process watchtower
    step "Waiting for client watchtowers to detect breach (${BREACH_WAIT}s)..."
    sleep "$BREACH_WAIT"

    for i in 1 2 3 4; do
        eval "wait \$CLIENT${i}_PID 2>/dev/null || true"
    done

    echo ""
    echo "=== LSP Output ==="
    cat "$LOGDIR/demo_breach.log"

    # Check client logs for breach detection and penalty
    BREACH_COUNT=0
    PENALTY_COUNT=0
    CPFP_COUNT=0
    for i in 1 2 3 4; do
        LOGFILE="$LOGDIR/demo_breach_client${i}.log"
        if [ -f "$LOGFILE" ]; then
            echo ""
            echo "=== Client $i Output (last 20 lines) ==="
            tail -20 "$LOGFILE"
            if grep -q "BREACH DETECTED" "$LOGFILE"; then
                BREACH_COUNT=$((BREACH_COUNT + 1))
            fi
            if grep -q "Penalty tx" "$LOGFILE"; then
                PENALTY_COUNT=$((PENALTY_COUNT + 1))
            fi
            if grep -q "CPFP child" "$LOGFILE"; then
                CPFP_COUNT=$((CPFP_COUNT + 1))
            fi
        fi
    done

    echo ""
    echo "=== Results ==="
    info "Breach detected by: $BREACH_COUNT/4 clients"
    info "Penalty broadcast by: $PENALTY_COUNT/4 clients"
    info "CPFP child broadcast by: $CPFP_COUNT/4 clients"

    if [ "$BREACH_COUNT" -gt 0 ] && [ "$PENALTY_COUNT" -gt 0 ]; then
        info "Breach demo PASSED — watchtower detected and penalized!"
    else
        fail "Breach demo FAILED — check logs in $LOGDIR/"
    fi
}

# ==========================================================================
# 12. status
# ==========================================================================

cmd_status() {
    header "Full System Status"

    # --- Processes ---
    echo -e "  ${BOLD}Processes${NC}"
    for name_pattern in \
        "bitcoind:bitcoind.*signet" \
        "CLN-A:lightningd.*$CLNA_DIR" \
        "CLN-B:lightningd.*$CLNB_DIR" \
        "Bridge:superscalar_bridge" \
        "LSP:superscalar_lsp" \
        "Client:superscalar_client"; do
        NAME="${name_pattern%%:*}"
        PATTERN="${name_pattern##*:}"
        if pgrep -f "$PATTERN" &>/dev/null; then
            PID=$(pgrep -f "$PATTERN" | head -1)
            info "$NAME: running (PID=$PID)"
        else
            fail "$NAME: stopped"
        fi
    done
    echo ""

    # --- Bitcoin ---
    echo -e "  ${BOLD}Bitcoin Network${NC}"
    if btc getblockchaininfo &>/dev/null; then
        BLOCKS=$(btc getblockchaininfo | json_field_int blocks)
        CHAIN=$(btc getblockchaininfo | json_field chain)
        PEERS=$(btc getnetworkinfo | json_field_int connections)
        btc loadwallet "superscalar_lsp" 2>/dev/null || true
        BAL=$(btc_wallet getbalance 2>/dev/null || echo "?")
        info "Chain: $CHAIN  Height: $BLOCKS  Peers: $PEERS  Balance: $BAL BTC"
    else
        fail "bitcoind not reachable"
    fi
    echo ""

    # --- CLN ---
    echo -e "  ${BOLD}Lightning Network${NC}"
    for label_fn in "Node A:cln_a" "Node B:cln_b"; do
        LABEL="${label_fn%%:*}"
        FN="${label_fn##*:}"
        if $FN getinfo &>/dev/null; then
            NODE_ID=$($FN getinfo | json_field id)
            BH=$($FN getinfo | json_field_int blockheight)
            NCHANS=$($FN listpeerchannels | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('channels',[])))" 2>/dev/null || echo "?")
            info "$LABEL: ${NODE_ID:0:16}... height=$BH channels=$NCHANS"
        else
            fail "$LABEL: not reachable"
        fi
    done
    echo ""

    # --- Databases ---
    echo -e "  ${BOLD}Databases${NC}"
    for label_db in "LSP:$LSPDB" "Client:$CLIENTDB"; do
        LABEL="${label_db%%:*}"
        DBPATH="${label_db##*:}"
        if [ -f "$DBPATH" ]; then
            FCOUNT=$(python3 -c "
import sqlite3, sys
try:
    conn = sqlite3.connect('file:$DBPATH?mode=ro', uri=True)
    f = conn.execute('SELECT COUNT(*) FROM factories').fetchone()[0]
    c = conn.execute('SELECT COUNT(*) FROM channels').fetchone()[0]
    h = conn.execute('SELECT COUNT(*) FROM htlcs').fetchone()[0]
    w = conn.execute('SELECT COUNT(*) FROM old_commitments').fetchone()[0]
    print(f'factories={f} channels={c} htlcs={h} watchtower={w}')
    conn.close()
except Exception as e:
    print(f'error: {e}')
" 2>/dev/null || echo "error reading")
            info "$LABEL DB: $FCOUNT"
        else
            detail "$LABEL DB: not found ($DBPATH)"
        fi
    done
    echo ""
}

# ==========================================================================
# 13. test-payment
# ==========================================================================

cmd_test_payment() {
    header "Test Payment"

    if ! cln_b getinfo &>/dev/null; then
        fail "CLN Node B is not running."
        exit 1
    fi
    if ! cln_a getinfo &>/dev/null; then
        fail "CLN Node A is not running."
        exit 1
    fi

    LABEL="test_$(date +%s)"

    step "Creating invoice on Node B (10,000 msat)..."
    INVOICE=$(cln_b invoice 10000 "$LABEL" "SuperScalar test payment")
    BOLT11=$(echo "$INVOICE" | json_field bolt11)
    HASH=$(echo "$INVOICE" | json_field payment_hash)
    info "Invoice: ${BOLT11:0:30}..."
    info "Hash:    ${HASH:0:16}..."

    step "Paying from Node A..."
    RESULT=$(cln_a pay "$BOLT11" 2>&1) || true
    STATUS=$(echo "$RESULT" | json_field status 2>/dev/null || echo "unknown")

    if [ "$STATUS" = "complete" ]; then
        info "Payment successful!"
        PREIMAGE=$(echo "$RESULT" | json_field payment_preimage)
        detail "Preimage: ${PREIMAGE:0:16}..."
    else
        warn "Payment status: $STATUS"
        detail "$RESULT"
    fi

    step "Verifying invoice status on Node B..."
    INV_STATUS=$(cln_b listinvoices "$LABEL" | python3 -c "
import json, sys
d = json.load(sys.stdin)
invs = d.get('invoices', [])
if invs:
    print(invs[0].get('status', 'unknown'))
else:
    print('not found')
" 2>/dev/null || echo "unknown")
    info "Invoice status: $INV_STATUS"
}

# ==========================================================================
# 14. stop-all
# ==========================================================================

cmd_stop_all() {
    header "Stop All Components"

    # SuperScalar components first (graceful)
    for name_pattern in \
        "Client:superscalar_client" \
        "LSP:superscalar_lsp" \
        "Bridge:superscalar_bridge"; do
        NAME="${name_pattern%%:*}"
        PATTERN="${name_pattern##*:}"
        if pgrep -f "$PATTERN" &>/dev/null; then
            step "Stopping $NAME..."
            pkill -f "$PATTERN" 2>/dev/null || true
            sleep 1
            if pgrep -f "$PATTERN" &>/dev/null; then
                pkill -9 -f "$PATTERN" 2>/dev/null || true
            fi
            info "$NAME stopped"
        else
            detail "$NAME: not running"
        fi
    done

    # CLN nodes
    for label_fn in "CLN-A:cln_a" "CLN-B:cln_b"; do
        LABEL="${label_fn%%:*}"
        FN="${label_fn##*:}"
        if $FN getinfo &>/dev/null; then
            step "Stopping $LABEL..."
            $FN stop 2>/dev/null || true
            sleep 2
            info "$LABEL stopped"
        else
            detail "$LABEL: not running"
        fi
    done

    # bitcoind
    if btc getblockchaininfo &>/dev/null; then
        step "Stopping bitcoind..."
        btc stop 2>/dev/null || true
        sleep 2
        info "bitcoind stopped"
    else
        detail "bitcoind: not running"
    fi

    echo ""
    info "All components stopped."
    detail "Data preserved in $DATADIR"
}

# ==========================================================================
# dump-state — Quick factory/channel/watchtower summary from all DBs
# ==========================================================================

cmd_dump_state() {
    header "Dump State (all DBs)"

    for LABEL_DB in "LSP:$LSPDB" "Client1:$CLIENTDB" "Client2:$CLIENT2DB" "Client3:$CLIENT3DB" "Client4:$CLIENT4DB"; do
        LABEL="${LABEL_DB%%:*}"
        DBPATH="${LABEL_DB##*:}"
        echo -e "  ${BOLD}$LABEL${NC} ($DBPATH)"
        if [ ! -f "$DBPATH" ]; then
            detail "(not found)"
            echo ""
            continue
        fi
        python3 -c "
import sqlite3
db = sqlite3.connect('file:$DBPATH?mode=ro', uri=True)
try:
    f = db.execute('SELECT COUNT(*) FROM factories').fetchone()[0]
    c = db.execute('SELECT COUNT(*) FROM channels').fetchone()[0]
    print(f'    factories={f}  channels={c}', end='')
except: print('    (no factories/channels)', end='')
try:
    h = db.execute('SELECT COUNT(*) FROM htlcs').fetchone()[0]
    print(f'  htlcs={h}', end='')
except: pass
try:
    w = db.execute('SELECT COUNT(*) FROM old_commitments').fetchone()[0]
    print(f'  watchtower={w}', end='')
except: pass
print()
# Channel balances
try:
    for r in db.execute('SELECT id, local_amount, remote_amount, commitment_number FROM channels').fetchall():
        print(f'      ch#{r[0]}: local={r[1]} remote={r[2]} commit={r[3]}')
except: pass
db.close()
" 2>/dev/null || fail "Could not read $LABEL database"
        echo ""
    done
}

# ==========================================================================
# check-stuck — List unconfirmed wallet txs older than 2 blocks
# ==========================================================================

cmd_check_stuck() {
    header "Check Stuck Transactions"

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running."
        exit 1
    fi

    btc loadwallet superscalar_lsp 2>/dev/null || true

    step "Checking for unconfirmed wallet transactions..."
    btc_wallet listtransactions "*" 50 0 true 2>/dev/null | python3 -c "
import json, sys
txs = json.load(sys.stdin)
unconfirmed = [t for t in txs if t.get('confirmations', 0) < 1]
if not unconfirmed:
    print('    No unconfirmed transactions')
else:
    print(f'    {len(unconfirmed)} unconfirmed transaction(s):')
    for t in unconfirmed:
        txid = t.get('txid', '?')
        amount = t.get('amount', 0)
        cat = t.get('category', '?')
        print(f'      {txid[:20]}...  {amount:+.8f} BTC  ({cat})')
" 2>/dev/null || fail "Could not query wallet transactions"

    step "Checking mempool..."
    MEMPOOL_SIZE=$(btc getmempoolinfo | python3 -c "import json,sys; print(json.load(sys.stdin).get('size',0))" 2>/dev/null)
    info "Mempool size: $MEMPOOL_SIZE txs"

    if [ "$MEMPOOL_SIZE" -gt 0 ] 2>/dev/null; then
        detail "Use 'bash tools/signet_diagnose.sh mempool' for full mempool listing"
        detail "Use 'bash tools/signet_diagnose.sh bump <TXID>' for emergency fee bump"
    fi
}

# ==========================================================================
# Help
# ==========================================================================

cmd_help() {
    echo ""
    echo -e "${BOLD}${CYAN}=== SuperScalar Signet Setup ===${NC}"
    echo ""
    echo -e "${BOLD}Startup sequence:${NC}"
    echo "   1.  bash $0 start-bitcoind     Start bitcoind (signet)"
    echo "   2.  bash $0 sync-status        Check sync progress"
    echo "   3.  bash $0 create-wallet      Create wallet + funding address"
    echo "   4.  bash $0 check-balance      Check wallet balance + UTXOs"
    echo "   5.  bash $0 start-cln-b        Start CLN Node B (vanilla)"
    echo "   6.  bash $0 start-cln-a        Start CLN Node A (with plugin)"
    echo "   7.  bash $0 open-channel       Fund + open A→B channel (500k sat)"
    echo "   8.  bash $0 start-bridge       Start SuperScalar bridge"
    echo "   9.  bash $0 start-lsp          Start SuperScalar LSP"
    echo "  10.  bash $0 start-client       Start SuperScalar client 1 (daemon)"
    echo "  11.  bash $0 start-client2      Start SuperScalar client 2 (daemon)"
    echo ""
    echo -e "${BOLD}Demo (standalone, no CLN needed):${NC}"
    echo "       bash $0 demo-coop          Factory + payments + cooperative close"
    echo "       bash $0 demo-force-close   Factory + payments + force close (tree broadcast)"
    echo "       bash $0 demo-breach        Breach + watchtower penalty + CPFP (regtest default)"
    echo "       bash $0 demo-breach-signet Breach + watchtower penalty + CPFP (signet)"
    echo ""
    echo -e "${BOLD}Diagnostics:${NC}"
    echo "       bash $0 status             Full system status dump"
    echo "       bash $0 channel-status     CLN channel details"
    echo "       bash $0 test-payment       Create + pay test invoice"
    echo "       bash $0 dump-state         Quick factory/channel/watchtower summary"
    echo "       bash $0 check-stuck        List unconfirmed txs, flag stuck ones"
    echo ""
    echo -e "${BOLD}Cleanup:${NC}"
    echo "       bash $0 stop-all           Graceful shutdown of everything"
    echo ""
    echo -e "${BOLD}Configuration:${NC}"
    echo "  Edit the config block at the top of this script to match your paths."
    echo "  Data directory: $DATADIR"
    echo ""
}

# ==========================================================================
# Main dispatch
# ==========================================================================

case "${1:-}" in
    start-bitcoind)      cmd_start_bitcoind ;;
    sync-status)         cmd_sync_status ;;
    create-wallet)       cmd_create_wallet ;;
    check-balance)       cmd_check_balance ;;
    start-cln-b)         cmd_start_cln_b ;;
    start-cln-a)         cmd_start_cln_a ;;
    open-channel)        cmd_open_channel ;;
    channel-status)      cmd_channel_status ;;
    start-bridge)        cmd_start_bridge ;;
    start-lsp)           cmd_start_lsp ;;
    start-client)        cmd_start_client ;;
    start-client2)       cmd_start_client2 ;;
    demo-coop)           cmd_demo_coop ;;
    demo-force-close)    cmd_demo_force_close ;;
    demo-breach)         cmd_demo_breach "$@" ;;
    demo-breach-signet)  cmd_demo_breach "$@" signet ;;
    status)              cmd_status ;;
    test-payment)        cmd_test_payment ;;
    dump-state)          cmd_dump_state ;;
    check-stuck)         cmd_check_stuck ;;
    stop-all)            cmd_stop_all ;;
    help|--help|-h)      cmd_help ;;
    *)                   cmd_help ;;
esac
