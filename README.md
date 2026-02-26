# SuperScalar

> **Status: Functional Prototype** — builds, passes 308 tests (271 unit + 37 regtest). Signet-ready. Not production-ready.

First implementation of [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) — laddered timeout-tree-structured Decker-Wattenhofer channel factories for Bitcoin.

A Bitcoin channel factory protocol combining:

- **Decker-Wattenhofer invalidation** — alternating kickoff/state layers with decrementing nSequence
- **Timeout-sig-trees** — N-of-N MuSig2 key-path with CLTV timeout script-path fallback
- **Poon-Dryja channels** — standard Lightning channels at leaf outputs with HTLCs
- **LSP + N clients** — the LSP participates in every branch; no consensus changes required

## Quick Start

[Build the project](#build), then:

```bash
bash tools/run_demo.sh --basic
```

Creates a 5-of-5 factory, opens 4 channels, runs payments, and cooperative-closes in ~30 seconds. If `bitcoind` isn't running, the script starts one for you.

## Build

**System prerequisites**: a C compiler (gcc/clang), CMake 3.14+, SQLite3 dev headers, Python 3 (for tooling)

```bash
# Ubuntu / Debian
sudo apt install build-essential cmake libsqlite3-dev python3

# macOS (SQLite3 ships with Xcode; install CMake via Homebrew if needed)
brew install cmake
```

```bash
mkdir -p build && cd build
cmake .. && make -j$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)
```

**Auto-fetched** (CMake FetchContent):
- [secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp) — MuSig2, Schnorr, adaptor signatures
- [cJSON](https://github.com/DaveGamble/cJSON) — JSON parsing

## Tests

271 unit + 37 regtest integration tests (including 10 adversarial/edge-case tests).

See [docs/testing-guide.md](docs/testing-guide.md) for a detailed walkthrough.

```bash
cd build

# Unit tests only (no bitcoind needed)
./test_superscalar --unit

# Integration tests (needs bitcoind -regtest)
bitcoind -regtest -daemon -rpcuser=rpcuser -rpcpassword=rpcpass \
  -fallbackfee=0.00001 -txindex=1
./test_superscalar --regtest
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass stop

# All tests
./test_superscalar --all
```

---

## Demos

All demos require a built project (`build/` directory with binaries) and `bitcoind -regtest`.

### One-Command Demo Runner

The easiest way to see SuperScalar in action:

```bash
bash tools/run_demo.sh --basic       # Factory + payments + cooperative close (~30s)
bash tools/run_demo.sh --breach      # + watchtower detects breach, broadcasts penalty (~60s)
bash tools/run_demo.sh --rotation    # + PTLC turnover + factory ladder rotation (~2min)
bash tools/run_demo.sh --all         # All three scenarios sequentially
```

`run_demo.sh` handles pre-flight checks, auto-starts `bitcoind` if needed, funds the wallet, launches the LSP + 4 clients, and prints colored output.

#### What each demo shows

| Demo | What happens |
|------|-------------|
| `--basic` | Creates a 5-of-5 MuSig2 factory (100k sats), opens 4 channels, runs 4 payments with real preimage validation, cooperative-closes everything in a single on-chain tx |
| `--breach` | Runs `--basic` first, then broadcasts a **revoked** commitment tx. The watchtower detects the breach and broadcasts a penalty tx that sweeps the cheater's funds |
| `--rotation` | Runs `--basic`, then performs PTLC key turnover (adaptor sigs extract every client's key over the wire), closes Factory 0, creates Factory 1, runs payments in the new factory, and closes — demonstrating zero-downtime laddering |

### Manual Demo (Minimal)

```bash
# Terminal: start LSP + auto-fork 4 clients, run demo, close
cd build
bash ../tools/demo.sh
```

### LSP Test Flags

These flags run after the `--demo` payment sequence completes:

```bash
# Watchtower breach test (LSP detects its own revoked commitment)
./superscalar_lsp --port 9735 --demo --breach-test

# Cheat daemon (broadcast revoked commitment, sleep — clients detect breach)
./superscalar_lsp --port 9735 --demo --cheat-daemon

# CLTV timeout recovery (mine past timeout, LSP recovers via script-path)
./superscalar_lsp --port 9735 --demo --test-expiry

# Distribution tx (pre-signed nLockTime tx defaults funds to clients)
./superscalar_lsp --port 9735 --demo --test-distrib

# PTLC key turnover (adaptor sigs, LSP can close alone afterward)
./superscalar_lsp --port 9735 --demo --test-turnover

# Full factory rotation (PTLC wire msgs + new factory + payments)
./superscalar_lsp --port 9735 --demo --test-rotation
```

### Test Orchestrator

Multi-party scenario testing with automatic process management. Stdlib-only Python3.

```bash
python3 tools/test_orchestrator.py --list                        # Show scenarios
python3 tools/test_orchestrator.py --scenario all_watch          # All clients detect breach
python3 tools/test_orchestrator.py --scenario partial_watch --k 2  # 2 of 4 detect
python3 tools/test_orchestrator.py --scenario nobody_home        # No clients, breach undetected
python3 tools/test_orchestrator.py --scenario late_arrival       # Clients restart after breach
python3 tools/test_orchestrator.py --scenario cooperative_close  # Clean shutdown
python3 tools/test_orchestrator.py --scenario timeout_expiry     # LSP reclaims via CLTV
python3 tools/test_orchestrator.py --scenario factory_breach     # Old factory tree broadcast
python3 tools/test_orchestrator.py --scenario all                # Run all scenarios
```

---

## Web Dashboard

A real-time monitoring dashboard for SuperScalar deployments. Stdlib-only Python3 (no pip install needed).

### Launch

```bash
# Demo mode (no databases required — shows synthetic data)
python3 tools/dashboard.py --demo

# With real databases from a running deployment
python3 tools/dashboard.py \
  --lsp-db /path/to/lsp.db \
  --client-db /path/to/client.db \
  --btc-cli bitcoin-cli \
  --btc-network signet \
  --btc-rpcuser superscalar \
  --btc-rpcpassword superscalar123

# Launch alongside the demo runner
bash tools/run_demo.sh --all --dashboard
```

Then open **http://localhost:8080** in your browser.

### Dashboard Tabs

| Tab | What it shows |
|-----|---------------|
| **Overview** | Process status (bitcoind, CLN, bridge, LSP, client), blockchain height, wallet balance, system health |
| **Factory** | Factory state (ACTIVE/DYING/EXPIRED), creation block, participant keys, DW epoch, funding txid |
| **Channels** | Per-channel balances (local/remote), commitment number, HTLC count, state |
| **Protocol** | Factory tree node visualization (kickoff + state nodes), signatures, wire message log |
| **Lightning** | CLN node info, peers, channels, forwarding stats (requires `--cln-a-dir` / `--cln-b-dir`) |
| **Watchtower** | Old commitment tracking, breach detection status, penalty tx history |
| **Events** | Recent 100 wire messages with timestamp, direction, type, peer label, payload summary |

The dashboard auto-refreshes every 5 seconds. Status indicators: green = healthy, yellow = warning, red = error.

### Dashboard Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--port` | 8080 | HTTP server port |
| `--demo` | off | Use synthetic data (no databases needed) |
| `--lsp-db` | — | Path to LSP SQLite database |
| `--client-db` | — | Path to client SQLite database |
| `--btc-cli` | bitcoin-cli | Path to bitcoin-cli |
| `--btc-network` | signet | Bitcoin network |
| `--btc-rpcuser` | — | Bitcoin RPC username |
| `--btc-rpcpassword` | — | Bitcoin RPC password |
| `--cln-cli` | lightning-cli | Path to lightning-cli |
| `--cln-a-dir` | — | CLN Node A data directory |
| `--cln-b-dir` | — | CLN Node B data directory |

---

## Running on Signet

SuperScalar works on signet (and testnet4) with real Bitcoin transactions. This guide walks through a full factory lifecycle: create, pay, close.

### Prerequisites

- A synced `bitcoind` running on signet with a funded wallet
- The built `superscalar_lsp` and `superscalar_client` binaries
- At least ~50,000 sats in the wallet (factory funding + fees)

### 1. Start bitcoind

```bash
bitcoind -signet -daemon -txindex=1 -fallbackfee=0.00001 \
  -rpcuser=YOUR_USER -rpcpassword=YOUR_PASS
```

If your `bitcoind` is in a non-standard location or uses a custom datadir, note the paths — you'll need `--cli-path` and `--datadir` below.

Get signet coins from a faucet (e.g. https://signetfaucet.com) if your wallet is empty.

### 2. Generate keys

The LSP and each client need a unique 32-byte secret key. On signet, deterministic keys are blocked — you must provide real ones.

```bash
# Generate random keys (requires openssl or /dev/urandom)
LSP_KEY=$(openssl rand -hex 32)
CLIENT1_KEY=$(openssl rand -hex 32)
CLIENT2_KEY=$(openssl rand -hex 32)

# Or use encrypted keyfiles (prompted for passphrase)
./superscalar_lsp --keyfile lsp.key --passphrase "your passphrase" ...
```

Save these keys. If the LSP crashes and restarts (with `--db`), it needs the same key to recover channels.

### 3. Start the LSP

```bash
./superscalar_lsp \
  --network signet \
  --port 9735 \
  --clients 2 \
  --amount 50000 \
  --seckey $LSP_KEY \
  --daemon \
  --db lsp.db \
  --cli-path /path/to/bitcoin-cli \
  --rpcuser YOUR_USER \
  --rpcpassword YOUR_PASS \
  --wallet YOUR_WALLET
```

| Flag | Why |
|------|-----|
| `--network signet` | Use signet instead of regtest |
| `--wallet YOUR_WALLET` | Use your existing funded wallet (skips `createwallet`) |
| `--db lsp.db` | Persist factory, channels, HTLCs — survives crashes |
| `--daemon` | Long-lived mode (Ctrl+C for cooperative close) |
| `--amount 50000` | Fund the factory with 50k sats |

Optional flags: `--datadir`, `--rpcport` if your bitcoind uses non-standard paths.

The LSP will:
1. Check wallet balance (fails if insufficient)
2. Query fee estimate from the node
3. Listen for client connections
4. Wait for all clients to connect before proceeding

### 4. Connect clients

In separate terminals (or machines — use `--host` for remote):

```bash
# Client 1
./superscalar_client \
  --network signet \
  --seckey $CLIENT1_KEY \
  --port 9735 \
  --host 127.0.0.1 \
  --daemon \
  --db client1.db \
  --cli-path /path/to/bitcoin-cli \
  --rpcuser YOUR_USER \
  --rpcpassword YOUR_PASS

# Client 2
./superscalar_client \
  --network signet \
  --seckey $CLIENT2_KEY \
  --port 9735 \
  --host 127.0.0.1 \
  --daemon \
  --db client2.db \
  --cli-path /path/to/bitcoin-cli \
  --rpcuser YOUR_USER \
  --rpcpassword YOUR_PASS
```

Once all clients connect, the ceremony runs automatically:

1. **Factory creation**: LSP funds a MuSig2 UTXO, all parties co-sign the tree
2. **Funding confirmation**: LSP broadcasts and waits for 1 confirmation (~10 min on signet)
3. **Channel setup**: Basepoint exchange, channel ready
4. **Daemon mode**: LSP and clients stay online, forwarding HTLCs

### 5. Send payments

From a client using `--send`:

```bash
./superscalar_client \
  --network signet \
  --seckey $CLIENT1_KEY \
  --port 9735 \
  --send 1:1000:$(openssl rand -hex 32)
```

Format: `--send DEST_CLIENT:AMOUNT_SATS:PREIMAGE_HEX`

Or in daemon mode, payments flow through the LSP automatically when triggered via the wire protocol.

### 6. Shutdown

Press **Ctrl+C** on the LSP. It will:
1. Cooperatively close the factory (single on-chain tx)
2. Wait for confirmation
3. Exit cleanly

If the LSP crashes instead, restart with the same `--seckey` and `--db`. It will recover the factory and channels from the database and accept client reconnections.

### Monitoring

```bash
python3 tools/dashboard.py \
  --lsp-db lsp.db \
  --client-db client1.db \
  --btc-cli /path/to/bitcoin-cli \
  --btc-network signet \
  --btc-rpcuser YOUR_USER \
  --btc-rpcpassword YOUR_PASS
```

Open http://localhost:8080 for real-time factory, channel, and payment status.

### Troubleshooting

| Problem | Fix |
|---------|-----|
| "wallet balance insufficient" | Fund your wallet via faucet, or use `--wallet` to point at a funded wallet |
| "cannot connect to bitcoind" | Check `--cli-path`, `--rpcuser`, `--rpcpassword`, `--datadir` match your setup |
| "funding tx not confirmed within timeout" | Signet blocks are ~10 min; increase `--confirm-timeout` if needed |
| Client "expected FACTORY_PROPOSE" | LSP isn't running or wrong `--host`/`--port` |
| LSP crash recovery not working | Must use same `--seckey` and `--db` as the original run |

---

## Standalone Binaries

### superscalar_lsp

```
superscalar_lsp [OPTIONS]
```

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--port` | PORT | 9735 | Listen port |
| `--clients` | N | 4 | Number of clients |
| `--arity` | N | 2 | Leaf arity: 1 (per-client leaves) or 2 (paired leaves) |
| `--amount` | SATS | 100000 | Funding amount |
| `--network` | MODE | regtest | regtest / signet / testnet / mainnet |
| `--daemon` | — | off | Long-lived daemon mode |
| `--demo` | — | off | Run scripted demo sequence |
| `--db` | PATH | — | SQLite persistence |
| `--fee-rate` | N | 1000 | Fee rate (sat/kvB) |
| `--keyfile` | PATH | — | Encrypted keyfile |
| `--passphrase` | PASS | — | Keyfile passphrase |
| `--cli-path` | PATH | bitcoin-cli | Bitcoin CLI binary |
| `--rpcuser` | USER | rpcuser | Bitcoin RPC username |
| `--rpcpassword` | PASS | rpcpass | Bitcoin RPC password |
| `--datadir` | PATH | — | Bitcoin datadir |
| `--rpcport` | PORT | — | Bitcoin RPC port |
| `--wallet` | NAME | superscalar_lsp | Bitcoin wallet (skip createwallet if set) |
| `--confirm-timeout` | SECS | 3600/7200 | Confirmation polling timeout |
| `--report` | PATH | — | Write JSON diagnostic report |
| `--breach-test` | — | off | Broadcast revoked commitment, trigger penalty |
| `--cheat-daemon` | — | off | Broadcast revoked commitment, sleep (clients detect) |
| `--test-expiry` | — | off | Mine past CLTV, recover via timeout script |
| `--test-distrib` | — | off | Broadcast pre-signed distribution tx |
| `--test-turnover` | — | off | PTLC key turnover, close with extracted keys |
| `--test-rotation` | — | off | Full factory rotation lifecycle |
| `--force-close` | — | off | Broadcast factory tree on-chain, wait for confirmations |

### superscalar_client

```
superscalar_client [OPTIONS]
```

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--seckey` | HEX | **required** | 32-byte secret key |
| `--port` | PORT | 9735 | LSP port |
| `--host` | HOST | 127.0.0.1 | LSP host |
| `--daemon` | — | off | Daemon mode (auto-fulfill HTLCs, client watchtower) |
| `--db` | PATH | — | SQLite persistence |
| `--network` | MODE | regtest | Network mode |
| `--fee-rate` | N | 1000 | Fee rate (sat/kvB) |
| `--keyfile` | PATH | — | Encrypted keyfile |
| `--passphrase` | PASS | — | Keyfile passphrase |
| `--cli-path` | PATH | bitcoin-cli | Bitcoin CLI binary |
| `--rpcuser` | USER | rpcuser | Bitcoin RPC username |
| `--rpcpassword` | PASS | rpcpass | Bitcoin RPC password |
| `--datadir` | PATH | — | Bitcoin datadir |
| `--rpcport` | PORT | — | Bitcoin RPC port |
| `--lsp-pubkey` | HEX | — | LSP static pubkey (33-byte compressed hex) for NK authentication |
| `--tor-proxy` | HOST:PORT | — | SOCKS5 proxy for Tor (e.g. `127.0.0.1:9050`) |
| `--auto-accept-jit` | — | off | Auto-accept JIT channel offers |

### superscalar_bridge

```
superscalar_bridge [OPTIONS]
```

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `--lsp-host` | HOST | 127.0.0.1 | LSP host |
| `--lsp-port` | PORT | 9735 | LSP port |
| `--plugin-port` | PORT | 9736 | CLN plugin listen port |
| `--lsp-pubkey` | HEX | — | LSP static pubkey (33-byte compressed hex) for NK authentication |
| `--tor-proxy` | HOST:PORT | — | SOCKS5 proxy for Tor (e.g. `127.0.0.1:9050`) |

---

## Architecture

### Factory Tree (LSP + 4 Clients)

```
                    funding UTXO (5-of-5)
                          |
                   kickoff_root (5-of-5, nSeq=disabled)
                          |
                    state_root (5-of-5, nSeq=DW layer 0)
                    /                    \
         kickoff_left (3-of-3)    kickoff_right (3-of-3)
         {LSP, A, B}              {LSP, C, D}
         nSeq=disabled            nSeq=disabled
              |                        |
        state_left (3-of-3)      state_right (3-of-3)
        nSeq=DW layer 1          nSeq=DW layer 1
        /     |     \            /     |     \
     chan_A  chan_B  L_stock   chan_C  chan_D  L_stock
```

- **6 transactions** in the tree, all pre-signed cooperatively via MuSig2
- **Alternating kickoff/state layers** prevents the cascade problem
- **Leaf outputs**: 2 Poon-Dryja channels + 1 LSP liquidity stock per branch
- **L-stock outputs**: Shachain-based invalidation with burn path for old states

### Decker-Wattenhofer Invalidation

Newer states get shorter relative timelocks, so they always confirm first:

```
State 0 (oldest): nSequence = 432 blocks  <- trapped behind newer states
State 1:          nSequence = 288 blocks
State 2:          nSequence = 144 blocks
State 3 (newest): nSequence = 0 blocks    <- confirms immediately
```

Multi-layer counter works like an odometer: 2 layers x 4 states = 16 epochs.

**Per-leaf advance**: Left and right subtrees can advance independently (only 3 signers needed per leaf instead of all 5). When a leaf exhausts its states, the root layer advances and both leaves reset. A cooperative epoch reset reclaims all states back to zero.

### Timeout-Sig-Trees

```
Output key = TapTweak(internal_key, merkle_root)
  Key path:    MuSig2(subset N-of-N)  — cooperative spend
  Script path: <cltv_timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <LSP_pubkey> OP_CHECKSIG
```

If clients disappear, the LSP can unilaterally recover funds after the timeout.

### Payment Channels

Each leaf channel is a standard Poon-Dryja Lightning channel:

```
Commitment TX:
  Input:  leaf output (2-of-2 MuSig key-path)
  Output 0: to_local  (revocable with per-commitment point)
  Output 1: to_remote (immediate)
  Output 2+: HTLC outputs (offered/received)
```

Revocation via random per-commitment secrets, penalty sweeps on breach, 2-leaf taproot HTLC trees, cooperative close via single key-path spend.

### Wire Protocol

49 message types over TCP with length-prefixed JSON framing:

| Category | Messages |
|----------|----------|
| Handshake | HELLO, HELLO_ACK |
| Factory | PROPOSE, NONCES, PSIGS, READY, FACTORY_PROPOSE |
| Channel | BASEPOINTS, CHANNEL_NONCES, CHANNEL_READY, CLOSE_REQUEST, CLOSE_COMPLETE |
| HTLC | ADD_HTLC, COMMITMENT_SIGNED, REVOKE_AND_ACK, FULFILL_HTLC, FAIL_HTLC |
| Revocation | LSP_REVOKE_AND_ACK |
| Bridge | BRIDGE_HELLO through BRIDGE_PAY_RESULT (8 types) |
| Reconnect | RECONNECT, RECONNECT_ACK |
| Invoice | CREATE_INVOICE, INVOICE_CREATED, REGISTER_INVOICE |
| PTLC | PTLC_PRESIG, PTLC_ADAPTED_SIG, PTLC_COMPLETE |
| Epoch/Leaf | EPOCH_RESET_PROPOSE/PSIG/DONE, LEAF_ADVANCE_PROPOSE/PSIG/DONE |
| JIT | JIT_OFFER, JIT_ACCEPT, JIT_READY, JIT_MIGRATE |

### Connection Topology (with CLN Bridge)

```
CLN (lightningd)
  └── cln_plugin.py (htlc_accepted hook + superscalar-pay RPC)
        └── superscalar_bridge (port 9736 ← plugin, port 9735 → LSP)
              │   ↑ NK-authenticated Noise handshake (--lsp-pubkey)
              │   ↑ Optional Tor/SOCKS5 (--tor-proxy)
              └── superscalar_lsp (port 9735)
                    ├── client 1
                    ├── client 2
                    ├── client 3
                    └── client 4
```

---

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `dw_state` | dw_state.c | nSequence state machine, odometer-style multi-layer counter |
| `musig` | musig.c | MuSig2 key aggregation, 2-round signing, split-round protocol, nonce pools |
| `tx_builder` | tx_builder.c | Raw tx serialization, BIP-341 key-path sighash, witness finalization |
| `tapscript` | tapscript.c | TapLeaf/TapBranch hashing, CLTV timeout scripts, control blocks |
| `factory` | factory.c | Factory tree: build, sign, advance, epoch reset, per-leaf advance, timeout-sig-tree outputs, cooperative close |
| `shachain` | shachain.c | BOLT #3 shachain, compact storage, epoch-to-index mapping |
| `channel` | channel.c | Poon-Dryja channels: commitment txs, revocation, penalty, HTLCs |
| `adaptor` | adaptor.c | MuSig2 adaptor signatures, PTLC key turnover |
| `ladder` | ladder.c | Ladder manager: overlapping factory lifecycle, migration |
| `wire` | wire.c | TCP transport, JSON framing, 49 message types |
| `lsp` | lsp.c | LSP server: factory creation, cooperative close |
| `client` | client.c | Client: factory ceremony, channel ops, rotation |
| `lsp_channels` | lsp_channels.c | HTLC forwarding, event loop, watchtower, multi-factory |
| `persist` | persist.c | SQLite3: 19 tables for full state persistence |
| `bridge` | bridge.c | CLN bridge daemon |
| `fee` | fee.c | Configurable fee estimation |
| `watchtower` | watchtower.c | Breach detection + penalty broadcast (LSP + client-side, factory nodes) |
| `keyfile` | keyfile.c | Encrypted keyfile storage |
| `jit_channel` | jit_channel.c | JIT channel fallback for offline/low-balance clients |
| `noise` | noise.c | Noise protocol encrypted transport (NN + NK patterns) |
| `tor` | tor.c | SOCKS5 proxy client, Tor hidden service creation via control port |
| `crypto_aead` | crypto_aead.c | AEAD encryption primitives |
| `report` | report.c | JSON diagnostic report generation |
| `regtest` | regtest.c | bitcoin-cli subprocess harness |
| `util` | util.c | SHA-256, tagged hashing, hex, byte utilities |

## License

MIT
