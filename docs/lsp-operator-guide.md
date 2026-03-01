# LSP Operator Guide

How to deploy and run a SuperScalar LSP node. Covers regtest, signet, and testnet.

## Prerequisites

- Built `superscalar_lsp` binary (see main [README](../README.md#build))
- Bitcoin Core 28.1+ (`bitcoind` and `bitcoin-cli`)
- SQLite3 (system package, used for persistence)
- A funded wallet on your target network

## 1. Choose Your Network

| Network | Use case | Block time | Funding |
|---------|----------|------------|---------|
| regtest | Local development and testing | Instant (mine on demand) | Self-mine |
| signet  | Public testing with real timing | ~10 min | [Faucet](https://signetfaucet.com) |
| testnet | Legacy test network | ~10 min | Faucet |
| mainnet | Production (not recommended yet) | ~10 min | Real BTC |

## 2. Start Bitcoin Core

### Regtest (Local)

```bash
bitcoind -regtest -daemon -txindex=1 -fallbackfee=0.00001 \
  -rpcuser=rpcuser -rpcpassword=rpcpass
```

Create and fund a wallet:

```bash
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  createwallet superscalar_lsp

ADDR=$(bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  -rpcwallet=superscalar_lsp getnewaddress)

bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  generatetoaddress 101 "$ADDR"
```

### Signet

```bash
bitcoind -signet -daemon -txindex=1 -fallbackfee=0.00001 \
  -rpcuser=YOUR_USER -rpcpassword=YOUR_PASS
```

Wait for sync, then fund from a faucet. Check balance:

```bash
bitcoin-cli -signet -rpcuser=YOUR_USER -rpcpassword=YOUR_PASS \
  -rpcwallet=YOUR_WALLET getbalance
```

You need at least the factory funding amount plus ~5,000 sats for fees.

## 3. Generate an LSP Key

The LSP needs a persistent 32-byte secret key. This key identifies the LSP and is used for MuSig2 signing and channel operations.

```bash
# Option A: random key (save this!)
LSP_KEY=$(openssl rand -hex 32)
echo "LSP_KEY=$LSP_KEY"

# Option B: encrypted keyfile (prompted for passphrase on each startup)
./superscalar_lsp --keyfile lsp.key --passphrase "your passphrase" ...
```

**Keep your key safe.** If you lose it and have active factories, you'll need to wait for CLTV timeout to recover funds.

## 4. Start the LSP

### Minimal (Regtest)

```bash
./superscalar_lsp \
  --network regtest \
  --port 9735 \
  --clients 4 \
  --amount 100000 \
  --daemon \
  --db lsp.db
```

### Full (Signet)

```bash
./superscalar_lsp \
  --network signet \
  --port 9735 \
  --clients 2 \
  --amount 50000 \
  --daemon \
  --db lsp.db \
  --cli-path /path/to/bitcoin-cli \
  --rpcuser YOUR_USER \
  --rpcpassword YOUR_PASS \
  --wallet YOUR_WALLET \
  --confirm-timeout 7200
```

### What Happens on Startup

1. LSP binds to `--port` and waits for `--clients` connections
2. Once all clients connect, the factory ceremony runs automatically:
   - LSP proposes factory parameters (funding amount, tree shape)
   - All parties exchange MuSig2 nonces (parallel collection)
   - All parties exchange partial signatures
   - LSP broadcasts the funding transaction
   - LSP polls for confirmation (up to `--confirm-timeout` seconds)
3. After confirmation, channels open and daemon loop starts
4. LSP forwards HTLCs between clients, runs watchtower, monitors factory lifecycle

### Shutdown

Press **Ctrl+C**. The LSP will:
1. Cooperatively close the factory (single on-chain transaction)
2. Wait for confirmation
3. Exit cleanly

## 5. Configuration Reference

### Core Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 9735 | Listen port for client connections |
| `--clients` | 4 | Number of clients to accept before starting ceremony |
| `--amount` | 100000 | Factory funding amount in satoshis |
| `--arity` | 2 | Leaf arity: `1` = one client per leaf, `2` = paired leaves |
| `--network` | regtest | Bitcoin network: regtest / signet / testnet / mainnet |
| `--daemon` | off | Long-lived mode (handles reconnections, Ctrl+C for close) |
| `--demo` | off | Run scripted payment sequence then close |
| `--db` | none | SQLite database path (enables crash recovery) |

### Bitcoin RPC

| Flag | Default | Description |
|------|---------|-------------|
| `--cli-path` | bitcoin-cli | Path to bitcoin-cli binary |
| `--rpcuser` | rpcuser | RPC username |
| `--rpcpassword` | rpcpass | RPC password |
| `--datadir` | (default) | Bitcoin datadir path |
| `--rpcport` | (auto) | RPC port override |
| `--wallet` | superscalar_lsp | Wallet name (skips createwallet if set) |

### Economics

| Flag | Default | Description |
|------|---------|-------------|
| `--routing-fee-ppm` | 0 | Routing fee in parts-per-million (0 = free forwarding) |
| `--lsp-balance-pct` | 50 | LSP's share of each channel capacity (0-100) |
| `--placement-mode` | sequential | Client tree placement: `sequential` / `inward` / `outward` |
| `--economic-mode` | lsp-takes-all | Fee model: `lsp-takes-all` / `profit-shared` |
| `--default-profit-bps` | 0 | Default profit share per client (basis points, 0-10000) |

### Timing

| Flag | Default | Description |
|------|---------|-------------|
| `--confirm-timeout` | 3600 (regtest) / 7200 (other) | Max seconds to wait for tx confirmation |
| `--accept-timeout` | 0 (unlimited) | Max seconds to wait for each client to connect |
| `--active-blocks` | 20 (regtest) / 4320 (other) | Factory active period in blocks |
| `--dying-blocks` | 10 (regtest) / 432 (other) | Factory dying period (rotation window) |
| `--fee-rate` | 1000 | Fee rate in sat/kvB |

### Security

| Flag | Default | Description |
|------|---------|-------------|
| `--keyfile` | none | Encrypted keyfile path (alternative to --seckey) |
| `--passphrase` | none | Keyfile decryption passphrase |
| `--tor-proxy` | none | SOCKS5 proxy for Tor (e.g. `127.0.0.1:9050`) |
| `--tor-control` | none | Tor control port for hidden service creation |
| `--onion` | off | Create Tor hidden service on startup |

### JIT Channels

| Flag | Default | Description |
|------|---------|-------------|
| `--no-jit` | off | Disable JIT channel fallback |
| `--jit-amount` | auto | Per-client JIT channel funding amount |

### Placement Modes Explained

- **sequential**: Connection order. Simple, predictable — good default.
- **inward**: High-balance clients near root. Reduces exit costs for clients with the most at stake.
- **outward**: Low-uptime clients at leaves. Reduces operator exposure at the edges of the tree.

### Economic Modes Explained

- **lsp-takes-all**: The LSP keeps 100% of routing fees. Simple, no settlement overhead — a good starting point.
- **profit-shared**: Routing fees are redistributed to clients based on their `profit_share_bps`. Settlement happens periodically via Decker-Wattenhofer state advances. Incentivizes client participation.

### Advanced Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--cli` | off | Interactive CLI in daemon mode (pay/status/rotate/close/help) |
| `--step-blocks` | 10 | DW step blocks (nSequence decrement per state) |
| `--states-per-layer` | 4 | DW states per layer (2-256) |
| `--settlement-interval` | 144 | Blocks between profit settlements |
| `--payments` | 0 | Number of HTLC payments to process |
| `--cltv-timeout` | auto | Factory CLTV timeout (absolute block height; auto: +35 regtest, +1008 non-regtest) |
| `--regtest` | off | Shorthand for `--network regtest` |
| `--i-accept-the-risk` | off | Required for mainnet operation |
| `--help` | — | Show help and exit |

### Testing & Debug Flags

These flags run after the `--demo` payment sequence to test specific protocol features:

| Flag | Default | Description |
|------|---------|-------------|
| `--breach-test` | off | Broadcast revoked commitment, trigger watchtower penalty |
| `--cheat-daemon` | off | Broadcast revoked commitment and sleep (clients detect) |
| `--test-expiry` | off | Mine past CLTV, recover via timeout script path |
| `--test-distrib` | off | Broadcast pre-signed distribution TX (nLockTime fallback) |
| `--test-turnover` | off | PTLC key turnover, close with extracted keys |
| `--test-rotation` | off | Full factory rotation lifecycle |
| `--force-close` | off | Broadcast factory tree on-chain, wait for confirmations |

### Interactive CLI

When `--cli` is enabled in daemon mode, the LSP reads commands from stdin:

| Command | Description |
|---------|-------------|
| `pay <from> <to> <amount>` | Send a payment between factory clients |
| `status` | Print channel balances, factory state, ladder info |
| `rotate` | Trigger manual factory rotation |
| `close` | Initiate cooperative close and shutdown |
| `help` | Show available commands |

## 6. Crash Recovery

If the LSP process crashes (power failure, OOM, etc.):

1. Restart with the **same `--seckey`** (or `--keyfile`) and **same `--db`** path
2. The LSP loads factory state, channel balances, and pending HTLCs from the database
3. Clients detect the disconnect and reconnect automatically (5s retry loop)
4. After reconnection, pending HTLCs are replayed and normal operation resumes

Without `--db`, crash recovery is not possible — you'll need to wait for CLTV timeout.

## 7. Monitoring

### Web Dashboard

```bash
python3 tools/dashboard.py \
  --lsp-db lsp.db \
  --btc-cli bitcoin-cli \
  --btc-network signet \
  --btc-rpcuser YOUR_USER \
  --btc-rpcpassword YOUR_PASS
```

Open http://localhost:8080 for real-time factory, channel, and watchtower status.

### Command-Line Status

```bash
# Check channel balances from DB
sqlite3 -header -column lsp.db \
  "SELECT channel_id, local_amount, remote_amount, commitment_number FROM channels"

# Check factory state
sqlite3 -header -column lsp.db \
  "SELECT factory_id, n_participants, funding_amount, lifecycle_state FROM factories"
```

### JSON Diagnostic Report

```bash
./superscalar_lsp --report /tmp/lsp_report.json ...
```

Writes a JSON file with factory state, channel balances, and pending HTLCs.

## 8. CLN Bridge (Lightning Network Integration)

The CLN bridge connects the SuperScalar factory to the broader Lightning Network. External Lightning nodes pay a CLN invoice; the bridge relays the HTLC into the factory and returns the preimage once the client fulfills. This makes factory clients reachable by any LN wallet without the sender knowing about SuperScalar.

### Prerequisites

- **CLN v24.11+** with `htlc_accepted` hook support
- **Python 3.8+** (for the CLN plugin)
- The built `superscalar_bridge` binary and `tools/cln_plugin.py` plugin

### Architecture

```
External LN Node
      │
      ▼
    CLN ──htlc_accepted──▶ cln_plugin.py
                                │  (JSON over TCP)
                                ▼
                         superscalar_bridge
                                │  (wire protocol over TCP/Noise)
                                ▼
                          superscalar_lsp
                                │  (channel messages)
                                ▼
                         Factory Client
```

The plugin intercepts inbound HTLCs via CLN's `htlc_accepted` hook, forwards them through the bridge daemon to the LSP, and holds the HTLC until the client fulfills with the preimage.

### Startup Order

The three processes must start in this order:

1. **LSP** — listens for bridge and client connections
2. **Bridge daemon** — connects to the LSP, listens for the plugin
3. **CLN with plugin** — connects to the bridge

### Step 1: Start the LSP

```bash
./superscalar_lsp --network regtest --port 9735 --clients 4 --amount 100000 \
  --daemon --db /tmp/lsp.db
```

The LSP automatically accepts bridge connections on its main port.

### Step 2: Start the Bridge Daemon

```bash
./superscalar_bridge \
  --lsp-host 127.0.0.1 \
  --lsp-port 9735 \
  --plugin-port 9736
```

The bridge connects to the LSP and listens on `--plugin-port` for the CLN plugin.

### Step 3: Start CLN with the Plugin

```bash
lightningd --network=regtest \
  --plugin=/path/to/tools/cln_plugin.py \
  --superscalar-bridge-host=127.0.0.1 \
  --superscalar-bridge-port=9736 \
  --superscalar-lightning-cli=lightning-cli
```

### Bridge Daemon Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--lsp-host HOST` | `127.0.0.1` | LSP hostname or IP address |
| `--lsp-port PORT` | `9735` | LSP listening port |
| `--plugin-port PORT` | `9736` | Port the bridge listens on for the CLN plugin |
| `--lsp-pubkey HEX` | *(none)* | LSP static pubkey (33-byte compressed hex) for NK-authenticated Noise handshake |
| `--tor-proxy HOST:PORT` | `127.0.0.1:9050` | SOCKS5 proxy for connecting to the LSP over Tor |

### CLN Plugin Options

| Option | Default | Description |
|--------|---------|-------------|
| `--superscalar-bridge-host` | `127.0.0.1` | Bridge daemon hostname |
| `--superscalar-bridge-port` | `9736` | Bridge daemon port |
| `--superscalar-lightning-cli` | `lightning-cli` | Path to `lightning-cli` binary (used for invoice creation) |

### Invoice Flow

When a factory client wants to receive an external Lightning payment:

1. Client sends `MSG_REGISTER_INVOICE` to the LSP with payment_hash, preimage, and amount
2. LSP registers the invoice in its local registry
3. LSP forwards `MSG_BRIDGE_REGISTER` to the bridge daemon (includes preimage)
4. Bridge forwards the registration to the CLN plugin (JSON over TCP)
5. Plugin calls `lightning-cli invoice` to create a BOLT11 invoice with the matching payment_hash
6. Plugin sends `invoice_bolt11` response back through the bridge
7. Bridge forwards `MSG_INVOICE_BOLT11` to the LSP
8. LSP forwards `MSG_INVOICE_BOLT11` to the client (client can now share the BOLT11 string)
9. External payer pays the BOLT11 invoice; CLN's `htlc_accepted` hook fires
10. Plugin sends the HTLC through the bridge → LSP → client channel
11. Client fulfills with preimage; LSP returns `MSG_BRIDGE_FULFILL_HTLC`; plugin resolves the CLN HTLC

### NK Authentication

For production, pin the LSP's static public key on the bridge to prevent MITM attacks:

```bash
# The LSP prints its pubkey at startup:
# "LSP: clients should use --lsp-pubkey 02abcdef..."

./superscalar_bridge \
  --lsp-host 127.0.0.1 \
  --lsp-port 9735 \
  --plugin-port 9736 \
  --lsp-pubkey 02abcdef...
```

Without `--lsp-pubkey`, the bridge uses an unauthenticated NN Noise handshake and prints a warning.

### Monitoring

**Plugin logs** — CLN logs plugin activity at the `info` level:
```bash
lightning-cli getlog | grep superscalar
```

**Bridge stderr** — the bridge prints connection events and message flow to stderr. Redirect to a file for persistent logging:
```bash
./superscalar_bridge --lsp-host 127.0.0.1 --lsp-port 9735 \
  --plugin-port 9736 2>/var/log/superscalar-bridge.log
```

**Plugin status** — verify the plugin is loaded:
```bash
lightning-cli plugin list | grep cln_plugin
```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| "bridge socketpair failed" | Check file descriptor limits: `ulimit -n 4096` |
| "no --lsp-pubkey, using unauthenticated NN handshake" | Add `--lsp-pubkey` with the LSP's static pubkey for production |
| Plugin not connecting | Verify `--superscalar-bridge-port` matches `--plugin-port` |
| "INVOICE_BOLT11 for unknown hash" | Client must send `MSG_REGISTER_INVOICE` before the external payment arrives |
| Bridge heartbeat timeout | Check network connectivity between bridge and LSP; default timeout is 30 seconds |
| "htlc_accepted hook timeout" | Increase CLN's hook timeout or check bridge ↔ LSP latency |

## 9. Factory Rotation

Factories have a limited lifetime (`--active-blocks` + `--dying-blocks`). Before expiry, the LSP rotates to a new factory:

1. PTLC key turnover extracts client keys via adaptor signatures
2. Old factory is cooperatively closed (LSP can sign alone with extracted keys)
3. New factory is created with the same clients
4. Channels resume in the new factory

This happens automatically in daemon mode when `--active-blocks` is reached. You can also trigger it manually with `--test-rotation` for testing.

## 10. Troubleshooting

| Problem | Fix |
|---------|-----|
| "wallet balance insufficient" | Fund your wallet. On regtest: mine blocks. On signet: use faucet. |
| "cannot connect to bitcoind" | Check `--cli-path`, `--rpcuser`, `--rpcpassword`, `--datadir` |
| "funding tx not confirmed" | Increase `--confirm-timeout`. Signet blocks average ~10 min. |
| Clients can't connect | Check firewall, verify `--port` matches on both sides |
| Crash recovery fails | Must use same `--seckey` and `--db` as original run |
| "too many open files" | Increase ulimit: `ulimit -n 4096` |
