# Deployment & Coordination Guide

How to deploy a SuperScalar factory with real participants across multiple machines. Covers the full coordination flow from "we have an LSP and N users" to "factory is live and payments are flowing."

## Overview

A SuperScalar deployment has three roles:

| Role | Binary | Count | Purpose |
|------|--------|-------|---------|
| **LSP** | `superscalar_lsp` | 1 | Funds the factory, routes payments, manages tree state |
| **Clients** | `superscalar_client` | 1-16 | Hold channels, send/receive payments |
| **Bridge** (optional) | `superscalar_bridge` + CLN | 1 | Connects factory to the Lightning Network |

## Coordination Timeline

```
1. LSP operator prepares:     bitcoind, wallet, keys, config
2. LSP starts:                listening on port, waiting for clients
3. Clients connect:           one by one, each with their own key
4. Ceremony (automatic):      once all clients connect
   a. LSP proposes factory parameters
   b. Nonce exchange (parallel)
   c. Partial signature exchange (parallel)
   d. LSP broadcasts funding tx
   e. Wait for confirmation
5. Channels open:             basepoint exchange, CHANNEL_READY
6. Payments flow:             LSP routes HTLCs between clients
7. Shutdown:                  Ctrl+C on LSP triggers cooperative close
```

Steps 4-5 are fully automatic — no manual intervention needed after clients connect.

## Single-Machine Deployment (Regtest)

For testing on one machine. Everything runs locally.

```bash
# 1. Build
mkdir -p build && cd build && cmake .. && make -j$(nproc) && cd ..

# 2. Automated (one command)
bash tools/run_demo.sh --basic

# 3. Or manual control
bash tools/manual_demo.sh setup
bash tools/manual_demo.sh start-lsp
bash tools/manual_demo.sh start-clients
bash tools/manual_demo.sh status
bash tools/manual_demo.sh balances
bash tools/manual_demo.sh stop
bash tools/manual_demo.sh teardown
```

## Multi-Machine Deployment (Signet)

### LSP Machine

```bash
# 1. Sync bitcoind
bitcoind -signet -daemon -txindex=1 \
  -rpcuser=lsp_user -rpcpassword=lsp_pass

# 2. Fund wallet (faucet or transfer)
bitcoin-cli -signet -rpcuser=lsp_user -rpcpassword=lsp_pass \
  createwallet superscalar_lsp
# Get address, send signet coins to it

# 3. Generate LSP key
LSP_KEY=$(openssl rand -hex 32)
echo "SAVE THIS: $LSP_KEY"

# 4. Start LSP (waiting for 2 clients)
./superscalar_lsp \
  --network signet \
  --port 9735 \
  --clients 2 \
  --amount 50000 \
  --daemon \
  --db lsp.db \
  --rpcuser lsp_user \
  --rpcpassword lsp_pass \
  --wallet superscalar_lsp
```

The LSP is now listening. Share your **IP address** and **port** with clients.

### Client Machine(s)

Each client needs:
- The LSP's IP address and port
- Their own secret key

```bash
# 1. Generate key
MY_KEY=$(openssl rand -hex 32)
echo "SAVE THIS: $MY_KEY"

# 2. Connect (no local bitcoind needed for basic operation)
./superscalar_client \
  --seckey $MY_KEY \
  --host LSP_IP_ADDRESS \
  --port 9735 \
  --network signet \
  --daemon \
  --db client.db
```

For watchtower protection, the client also needs bitcoin-cli access:

```bash
./superscalar_client \
  --seckey $MY_KEY \
  --host LSP_IP_ADDRESS \
  --port 9735 \
  --network signet \
  --daemon \
  --db client.db \
  --cli-path /path/to/bitcoin-cli \
  --rpcuser YOUR_USER \
  --rpcpassword YOUR_PASS
```

### What Clients Need to Know

Share this with your clients:

1. **LSP address**: `IP:PORT` (e.g. `203.0.113.5:9735`)
2. **Network**: signet (must match LSP)
3. **Number of clients**: how many need to connect before the factory starts
4. **Funding amount**: what the factory will hold (informational)

Clients do NOT need:
- Access to the LSP's wallet
- A funded wallet of their own (the LSP funds the factory)
- Any pre-coordination beyond knowing the address

## Tor Deployment

### LSP with Hidden Service

```bash
# Tor must be running with ControlPort enabled
./superscalar_lsp \
  --network signet \
  --port 9735 \
  --clients 2 \
  --amount 50000 \
  --daemon \
  --db lsp.db \
  --tor-control 127.0.0.1:9051 \
  --tor-password YOUR_TOR_PASSWORD \
  --onion
  # ... bitcoin RPC flags ...
```

The LSP will create a Tor hidden service and print its .onion address. Share this with clients.

### Client over Tor

```bash
./superscalar_client \
  --seckey $MY_KEY \
  --host ONION_ADDRESS.onion \
  --port 9735 \
  --tor-proxy 127.0.0.1:9050 \
  --daemon \
  --db client.db
```

### Authenticated (NK Noise)

If the LSP publishes their static pubkey, clients can verify identity:

```bash
# LSP prints their pubkey at startup; share it with clients
# Client connects with pinned pubkey:
./superscalar_client \
  --seckey $MY_KEY \
  --host ONION_ADDRESS.onion \
  --port 9735 \
  --tor-proxy 127.0.0.1:9050 \
  --lsp-pubkey 02abc...def \
  --daemon
```

## Adding the Lightning Bridge

To receive payments from the broader Lightning Network:

### On the LSP Machine

```bash
# 1. Start bridge daemon
./superscalar_bridge \
  --lsp-host 127.0.0.1 \
  --lsp-port 9735 \
  --plugin-port 9736

# 2. Start CLN with the plugin
lightningd \
  --network=signet \
  --plugin=/path/to/tools/cln_plugin.py \
  --superscalar-bridge-port=9736
```

### Payment Flow

```
External payer (any LN node)
  → CLN (htlc_accepted hook)
    → cln_plugin.py
      → superscalar_bridge (port 9736)
        → superscalar_lsp (port 9735)
          → destination client's channel
```

Factory clients can now receive payments from anyone on the Lightning Network.

## Factory Lifecycle

### Normal Operation

1. **ACTIVE**: Factory is live, payments flowing. Duration: `--active-blocks`
2. **DYING**: Approaching CLTV timeout, rotation window. Duration: `--dying-blocks`
3. **EXPIRED**: Must close or funds locked in timeout path

### Rotation (Zero Downtime)

When `--active-blocks` is reached, the LSP automatically:
1. Initiates PTLC key turnover (extracts client keys via adaptor sigs)
2. Closes old factory (LSP can sign alone with extracted keys)
3. Creates new factory with same clients
4. Channels resume in new factory

### Manual Close

Press Ctrl+C on the LSP for cooperative close (single on-chain tx).

### Crash Recovery

If anything crashes:
- **LSP**: Restart with same `--seckey` + `--db`. Loads state from DB.
- **Client**: Restarts automatically in `--daemon` mode (5s retry loop). With `--db`, state survives restarts.
- **Both crash**: LSP recovers from DB on restart, clients reconnect.
- **Everyone disappears**: After CLTV timeout, distribution TX recovers funds.

## Monitoring

### Dashboard (Web)

```bash
python3 tools/dashboard.py \
  --lsp-db lsp.db \
  --btc-cli bitcoin-cli \
  --btc-network signet \
  --btc-rpcuser YOUR_USER \
  --btc-rpcpassword YOUR_PASS
# Open http://localhost:8080
```

### Database Queries

```bash
# Channel balances
sqlite3 -header -column lsp.db \
  "SELECT channel_id, local_amount, remote_amount FROM channels"

# Factory state
sqlite3 -header -column lsp.db \
  "SELECT factory_id, lifecycle_state, funding_amount FROM factories"

# Pending HTLCs
sqlite3 -header -column lsp.db \
  "SELECT channel_id, payment_hash, amount_msat, direction FROM htlcs WHERE resolved=0"
```

## Firewall & Security

### Minimum Ports

| Port | Protocol | Who connects |
|------|----------|-------------|
| 9735 | TCP | Clients + Bridge |
| 9736 | TCP (optional) | CLN plugin |
| 8080 | HTTP (optional) | Dashboard (bind to localhost in production) |

### Recommendations

- Bind dashboard to `127.0.0.1` (not `0.0.0.0`) in production
- Use Tor for client privacy
- Use `--lsp-pubkey` for NK authentication (prevents MITM)
- Use `--keyfile` instead of `--seckey` on the command line (avoids key in process list)
- Set `--accept-timeout` to prevent indefinite blocking on slow clients
- Use `iptables` rate limiting on port 9735 for DoS protection

## Checklist

### Before Launch

- [ ] bitcoind synced and running on target network
- [ ] Wallet funded (factory amount + ~5,000 sats for fees)
- [ ] LSP key generated and backed up
- [ ] `--db` flag set for crash recovery
- [ ] Firewall allows inbound on LSP port
- [ ] Clients have LSP address, port, and network info
- [ ] (Optional) Tor hidden service configured
- [ ] (Optional) Bridge + CLN running for Lightning connectivity

### After Launch

- [ ] All clients connected (check LSP stdout)
- [ ] Factory ceremony completed (funding tx broadcast)
- [ ] Funding tx confirmed (check block explorer or dashboard)
- [ ] Test payment between clients works
- [ ] Dashboard showing correct balances
- [ ] Watchtower scan running (check LSP logs)
