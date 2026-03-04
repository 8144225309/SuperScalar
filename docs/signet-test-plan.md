# Signet/Testnet Live Testing Plan

Step-by-step instructions for running SuperScalar v0.1.0 on signet with CLN bridge integration, suitable for handing to an AI assistant or following manually.

**Goal:** Run a SuperScalar factory on signet, connect it to Core Lightning via the bridge, and send payments back and forth between normal LN channels and factory channels.

---

## Prerequisites

- **Linux machine** (Ubuntu 22.04+ or Debian 12+). macOS works for SuperScalar but CLN is easiest on Linux.
- **Bitcoin Core 28.1+** — synced on signet
- **Core Lightning (CLN) v24.11+** — built from source or installed via package
- **Python 3.8+** — for the CLN plugin (stdlib only, no pip)
- **Build tools**: `gcc`, `cmake 3.14+`, `libsqlite3-dev`, `libssl-dev`

If any of these are missing, install them first before proceeding.

---

## Phase 0: Environment Setup

### 0.1 Install system dependencies

```bash
sudo apt update
sudo apt install -y build-essential cmake libsqlite3-dev libssl-dev \
  python3 git wget
```

### 0.2 Bitcoin Core (if not already installed)

```bash
wget -q https://bitcoincore.org/bin/bitcoin-core-28.1/bitcoin-28.1-x86_64-linux-gnu.tar.gz
tar xzf bitcoin-28.1-x86_64-linux-gnu.tar.gz
sudo install -m 0755 bitcoin-28.1/bin/bitcoind bitcoin-28.1/bin/bitcoin-cli /usr/local/bin/
```

### 0.3 Core Lightning (if not already installed)

Follow CLN's official install guide: https://github.com/ElementsProject/lightning#installation

On Ubuntu:
```bash
sudo apt install -y autoconf automake build-essential git libtool \
  libsqlite3-dev python3 python3-pip net-tools zlib1g-dev libsodium-dev \
  gettext cargo rustc
git clone https://github.com/ElementsProject/lightning.git
cd lightning
pip3 install --user mako grpcio-tools
./configure
make -j$(nproc)
sudo make install
```

Verify: `lightningd --version` should print a version string.

### 0.4 Build SuperScalar

```bash
git clone https://github.com/8144225309/SuperScalar.git
cd SuperScalar
mkdir -p build && cd build
cmake .. && make -j$(nproc)

# Verify
./superscalar_lsp --version    # Should print: superscalar_lsp 0.1.0
./superscalar_client --version # Should print: superscalar_client 0.1.0
./superscalar_bridge --version # Should print: superscalar_bridge 0.1.0
```

---

## Phase 1: Start Bitcoin Core on Signet

### 1.1 Configure bitcoind

```bash
mkdir -p ~/.bitcoin
cat > ~/.bitcoin/bitcoin.conf << 'EOF'
signet=1
server=1
txindex=1
fallbackfee=0.00001
rpcuser=superscalar
rpcpassword=superscalar123

[signet]
rpcport=38332
EOF
```

### 1.2 Start bitcoind and wait for sync

```bash
bitcoind -signet -daemon
# Wait for sync (signet is small, usually < 30 min from scratch)
bitcoin-cli -signet getblockchaininfo | grep -E "blocks|headers"
```

Wait until `blocks` equals `headers`.

### 1.3 Create and fund a wallet

```bash
bitcoin-cli -signet createwallet "superscalar_test"
ADDR=$(bitcoin-cli -signet -rpcwallet=superscalar_test getnewaddress)
echo "Fund this address from a signet faucet: $ADDR"
```

Get signet coins from https://signetfaucet.com — request at least 0.001 BTC (100,000 sats). Wait for 1 confirmation:

```bash
# Check balance (wait until > 0)
bitcoin-cli -signet -rpcwallet=superscalar_test getbalance
```

---

## Phase 2: Generate Keys

SuperScalar requires real keys on signet (no deterministic defaults).

### 2.1 Generate keyfiles using BIP39 mnemonics

```bash
cd /path/to/SuperScalar/build

# LSP keyfile
./superscalar_lsp --generate-mnemonic --keyfile lsp.key --passphrase "test"
# IMPORTANT: Write down the 24 words printed. This is your LSP recovery seed.

# Client 1 keyfile
./superscalar_client --generate-mnemonic --keyfile client1.key --passphrase "test"
# Write down these 24 words too.

# Client 2 keyfile
./superscalar_client --generate-mnemonic --keyfile client2.key --passphrase "test"
# Write down these 24 words too.
```

Alternatively, generate raw hex keys:
```bash
LSP_KEY=$(openssl rand -hex 32)
CLIENT1_KEY=$(openssl rand -hex 32)
CLIENT2_KEY=$(openssl rand -hex 32)
echo "LSP_KEY=$LSP_KEY"
echo "CLIENT1_KEY=$CLIENT1_KEY"
echo "CLIENT2_KEY=$CLIENT2_KEY"
# Save these somewhere safe.
```

---

## Phase 3: Start SuperScalar Factory on Signet

### 3.1 Start the LSP

Open a terminal (Terminal 1):

```bash
cd /path/to/SuperScalar/build

# Using keyfile:
./superscalar_lsp \
  --network signet \
  --port 9735 \
  --clients 2 \
  --amount 50000 \
  --keyfile lsp.key \
  --passphrase "test" \
  --daemon \
  --db lsp.db \
  --rpcuser superscalar \
  --rpcpassword superscalar123 \
  --wallet superscalar_test \
  --cli \
  --confirm-timeout 7200

# OR using raw hex key:
./superscalar_lsp \
  --network signet \
  --port 9735 \
  --clients 2 \
  --amount 50000 \
  --seckey $LSP_KEY \
  --daemon \
  --db lsp.db \
  --rpcuser superscalar \
  --rpcpassword superscalar123 \
  --wallet superscalar_test \
  --cli \
  --confirm-timeout 7200
```

The LSP will:
1. Check wallet balance
2. Query fee estimate
3. Print "Waiting for 2 clients..."
4. Block until both clients connect

**Key flags explained:**
- `--daemon`: long-lived mode (Ctrl+C for cooperative close)
- `--db lsp.db`: persist state to SQLite (survives crashes)
- `--cli`: enable interactive commands (pay, status, rotate, close)
- `--confirm-timeout 7200`: wait up to 2 hours for on-chain confirmations (signet blocks are ~10 min)
- `--wallet superscalar_test`: use the funded wallet from Phase 1

### 3.2 Start Client 1

Open a new terminal (Terminal 2):

```bash
cd /path/to/SuperScalar/build

./superscalar_client \
  --network signet \
  --keyfile client1.key \
  --passphrase "test" \
  --port 9735 \
  --host 127.0.0.1 \
  --daemon \
  --db client1.db \
  --rpcuser superscalar \
  --rpcpassword superscalar123
```

### 3.3 Start Client 2

Open a new terminal (Terminal 3):

```bash
cd /path/to/SuperScalar/build

./superscalar_client \
  --network signet \
  --keyfile client2.key \
  --passphrase "test" \
  --port 9735 \
  --host 127.0.0.1 \
  --daemon \
  --db client2.db \
  --rpcuser superscalar \
  --rpcpassword superscalar123
```

### 3.4 Wait for factory creation

Once both clients connect, the ceremony runs automatically:

1. **Factory proposal** — LSP proposes tree structure
2. **Nonce exchange** — 2-round MuSig2 nonce collection
3. **Signing** — All parties co-sign the factory tree
4. **Funding** — LSP broadcasts funding tx
5. **Confirmation** — Wait for 1 confirmation (~10 min on signet)
6. **Channel ready** — Channels open, daemon mode active

Watch Terminal 1 (LSP) for progress. You should eventually see:
```
LSP: factory funded: <txid>
LSP: waiting for funding tx confirmation on signet...
LSP: funding confirmed (1 confs)
LSP: channels ready
```

**This step takes ~15-20 minutes** (ceremony + 1 signet block).

---

## Phase 4: CLN Bridge Setup (for LN interop)

### 4.1 Configure and start CLN on signet

```bash
mkdir -p ~/.lightning

lightningd \
  --network=signet \
  --daemon \
  --log-level=debug \
  --log-file=$HOME/.lightning/signet/cln.log \
  --plugin=/path/to/SuperScalar/tools/cln_plugin.py \
  --superscalar-bridge-host=127.0.0.1 \
  --superscalar-bridge-port=9736 \
  --superscalar-lightning-cli=lightning-cli
```

Note: The plugin will warn about bridge connection failure until the bridge daemon starts. This is normal.

### 4.2 Fund the CLN node

```bash
CLN_ADDR=$(lightning-cli --network=signet newaddr | jq -r .bech32)
echo "Fund CLN node: $CLN_ADDR"
bitcoin-cli -signet -rpcwallet=superscalar_test sendtoaddress $CLN_ADDR 0.0005
bitcoin-cli -signet -rpcwallet=superscalar_test sendtoaddress $CLN_ADDR 0.0005
# Wait for confirmation
```

### 4.3 Connect CLN to a public signet peer

To send/receive Lightning payments, your CLN node needs at least one channel with a signet peer. Find signet nodes at https://mempool.space/signet/lightning or use a known signet node.

```bash
# Example: connect to a signet node (replace with actual node info)
lightning-cli --network=signet connect <PUBKEY>@<HOST>:<PORT>

# Open a channel (50k sats)
lightning-cli --network=signet fundchannel <PUBKEY> 50000

# Wait for 3 confirmations (~30 min)
lightning-cli --network=signet listfunds | jq '.channels'
```

### 4.4 Start the bridge daemon

Open a new terminal (Terminal 4):

```bash
cd /path/to/SuperScalar/build

./superscalar_bridge \
  --lsp-host 127.0.0.1 \
  --lsp-port 9735 \
  --plugin-port 9736
```

The bridge will:
1. Connect to the LSP on port 9735 (Noise handshake)
2. Listen on port 9736 for the CLN plugin
3. The plugin (already running inside CLN) will auto-connect

You should see:
```
SuperScalar Bridge Daemon
  LSP: 127.0.0.1:9735
  Plugin port: 9736
```

---

## Phase 5: Test Payments

### 5.1 Internal factory payments (Client ↔ Client via LSP)

From the LSP interactive CLI (Terminal 1), if running with `--cli`:

```
status           # Show channel balances
pay 0 1 1000     # Pay 1000 sats from client 0 to client 1
pay 1 0 500      # Pay 500 sats from client 1 to client 0
status           # Verify balances changed
```

Or from a separate client process:
```bash
./superscalar_client \
  --network signet \
  --seckey $CLIENT1_KEY \
  --port 9735 \
  --host 127.0.0.1 \
  --send 1:1000:$(openssl rand -hex 32)
```

### 5.2 Inbound LN payment (External LN → CLN → Bridge → Factory Client)

This tests the full bridge flow: an external Lightning payment arrives at CLN, gets forwarded through the bridge to a factory client.

**Step 1: Create an invoice from a factory client**

The client must register an invoice via the LSP. From the LSP CLI:
```
invoice 0 10000    # Create invoice for client 0, 10000 msat
```

This will:
1. Client sends MSG_REGISTER_INVOICE to LSP
2. LSP forwards MSG_BRIDGE_REGISTER to bridge
3. Bridge forwards to CLN plugin
4. Plugin creates a CLN invoice with known preimage
5. BOLT11 string is returned

**Step 2: Pay the invoice from an external wallet**

Take the BOLT11 string and pay it from any signet Lightning wallet (e.g., another CLN node, or a signet-capable mobile wallet).

```bash
# From another CLN node:
lightning-cli --network=signet pay <BOLT11_STRING>
```

**Step 3: Verify settlement**

Watch the bridge and LSP logs. You should see:
- Bridge: "htlc_accepted" from plugin
- LSP: HTLC forwarded to client
- Client: HTLC fulfilled with preimage
- Bridge: "htlc_resolve" with preimage back to plugin
- CLN: payment settled

Check balances from LSP CLI: `status`

### 5.3 Outbound LN payment (Factory Client → Bridge → CLN → External LN)

**Step 1: Get a BOLT11 invoice from an external node**

```bash
# On another CLN node:
lightning-cli --network=signet invoice 5000 "test-outbound" "test"
# Copy the bolt11 string
```

**Step 2: Pay from factory via bridge**

From the CLN node connected to the bridge:
```bash
lightning-cli --network=signet superscalar-pay <BOLT11_STRING>
```

This routes: CLN plugin → bridge → LSP → deduct from client channel → bridge → CLN → external.

### 5.4 Keysend payment (spontaneous, no invoice)

If keysend is supported by your CLN peers:

```bash
# Get factory CLN node's pubkey
CLN_PUBKEY=$(lightning-cli --network=signet getinfo | jq -r .id)

# From external node, keysend to factory's CLN:
lightning-cli --network=signet keysend $CLN_PUBKEY 1000
```

The plugin detects the keysend TLV, extracts the preimage, and routes it to the default factory client.

---

## Phase 6: Long-Running Daemon Test

The most valuable testing is leaving everything running for hours or days.

### 6.1 What to monitor

```bash
# LSP status (from CLI)
status

# Bitcoin block height
bitcoin-cli -signet getblockcount

# CLN node status
lightning-cli --network=signet getinfo

# Dashboard (optional — opens browser at :8080)
python3 /path/to/SuperScalar/tools/dashboard.py \
  --lsp-db /path/to/build/lsp.db \
  --client-db /path/to/build/client1.db \
  --btc-cli bitcoin-cli \
  --btc-network signet \
  --btc-rpcuser superscalar \
  --btc-rpcpassword superscalar123
```

### 6.2 Things to test over time

- [ ] **Periodic payments**: Send a payment every ~30 minutes and verify balances
- [ ] **Reconnection**: Kill a client process (`kill -9 <pid>`), wait 30 seconds, restart it. Verify it reconnects and channels resume.
- [ ] **LSP crash recovery**: Kill the LSP (`kill -9 <pid>`), restart with same `--db` and `--keyfile`. Verify clients reconnect.
- [ ] **Bridge resilience**: Kill the bridge, restart it. The CLN plugin should auto-reconnect within 5 seconds.
- [ ] **Block progression**: Monitor as new signet blocks arrive. The factory should track block height correctly.
- [ ] **Fee estimation**: Check LSP logs for fee rate updates from `estimatesmartfee`.
- [ ] **Memory usage**: Run `ps aux | grep superscalar` periodically. Memory should be stable, not growing.
- [ ] **Multiple payment rounds**: Send 10+ payments in sequence. Verify commitment numbers increment and nonce pools don't exhaust.

### 6.3 Checklist for multi-day runs

- [ ] Factory created and funded on signet
- [ ] Both clients connected and channels ready
- [ ] CLN node running with bridge plugin
- [ ] Bridge daemon running and connected
- [ ] At least one LN channel open on CLN (for external payments)
- [ ] Internal payments (client ↔ client) working
- [ ] Inbound LN payments (external → bridge → factory) working
- [ ] Outbound LN payments (factory → bridge → external) working
- [ ] Reconnection tested at least once for each component
- [ ] Running for 24+ hours without crashes or memory leaks
- [ ] Running for 72+ hours without issues (stretch goal)

---

## Phase 7: Cooperative Close

When done testing:

### 7.1 From LSP CLI
```
close
```

Or press **Ctrl+C** on the LSP process.

### 7.2 What happens

1. LSP initiates cooperative close (single on-chain transaction)
2. All parties sign the close tx
3. LSP broadcasts and waits for confirmation (~10 min)
4. Funds returned to wallet
5. All processes exit cleanly

### 7.3 Verify

```bash
# Check that funds returned to wallet
bitcoin-cli -signet -rpcwallet=superscalar_test getbalance

# Should be close to original amount minus on-chain fees
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| LSP says "wallet balance insufficient" | Wallet not funded or wrong `--wallet` name | Fund wallet, check wallet name matches Phase 1 |
| Client says "connection refused" | LSP not running or wrong port | Start LSP first, verify `--port` matches |
| "expected FACTORY_PROPOSE" on client | LSP is still waiting for other clients | Start all clients before timeout |
| Funding tx not confirming | Signet blocks are ~10 min | Increase `--confirm-timeout`, wait longer |
| Bridge "connection refused to LSP" | LSP not running or wrong host/port | Check `--lsp-host` and `--lsp-port` |
| CLN plugin "bridge not connected" | Bridge not running or wrong port | Start bridge, check `--plugin-port` matches `--superscalar-bridge-port` |
| Payment fails with "no route" | CLN has no channels or peer is offline | Open CLN channel, check `lightning-cli listpeers` |
| Client won't reconnect after crash | Wrong `--db` or `--keyfile` | Must use same DB and keyfile as original session |
| "deterministic key only on regtest" | Missing `--seckey` or `--keyfile` on signet | Provide real key via `--seckey` or `--keyfile` |
| Memory growing over time | Possible leak (report as bug) | Note RSS from `ps`, report with logs |

---

## Reporting Results

When reporting test results (bugs or success), include:

1. **Network**: signet or testnet4
2. **SuperScalar version**: `./superscalar_lsp --version`
3. **Bitcoin Core version**: `bitcoind --version`
4. **CLN version**: `lightningd --version` (if using bridge)
5. **OS**: `uname -a`
6. **Duration**: How long the factory ran
7. **What worked**: Which payment types succeeded
8. **What failed**: Error messages, logs, steps to reproduce
9. **DB files**: Attach `lsp.db` and `client*.db` if possible (they contain diagnostic state)

File issues at: https://github.com/8144225309/SuperScalar/issues
