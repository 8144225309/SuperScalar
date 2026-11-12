# LSP Operator Guide

For mainnet operations see [mainnet-runbook.md](mainnet-runbook.md).

How to deploy and run a SuperScalar LSP node. Covers regtest, signet, and testnet.

## Prerequisites

- Built `superscalar_lsp` binary (see main [README](../README.md#build))
- Bitcoin Core 29.1+ (`bitcoind` and `bitcoin-cli`; CI runs 30.3), and the
  LSP refuses to start on an older node: factory exits are TRUC (nVersion 3)
  transactions with P2A anchors, relayed through package relay (`submitpackage`)
  when their pre-signed fee is below what the mempool needs; a factory at rate
  0 uses 0-value (ephemeral) anchors (29.0), and 29.1 relays down to 0.1
  sat/vB by default.
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
# Option A: BIP39 mnemonic (recommended — write down the 24 words)
./superscalar_lsp --generate-mnemonic --keyfile lsp.key --passphrase "your passphrase"
# Prints 24 words. Write them down. Key derived via BIP32 m/1039'/0'/0'.

# Option B: restore from existing mnemonic
./superscalar_lsp --from-mnemonic "abandon abandon ... about" \
  --keyfile lsp.key --passphrase "your passphrase"

# Option C: random key (save this!)
LSP_KEY=$(openssl rand -hex 32)
echo "LSP_KEY=$LSP_KEY"

# Option D: encrypted keyfile without mnemonic
./superscalar_lsp --keyfile lsp.key --passphrase "your passphrase" ...
```

**Keep your key safe.** With BIP39, you can recover from the 24 words. Without it, if the keyfile is lost and you have active factories, you'll need to wait for CLTV timeout to recover funds.

**How the keyfile is handled**

- **A keyfile is never overwritten.** `--generate-mnemonic` and `--from-mnemonic` refuse to run if anything already exists at `--keyfile`. A normal start creates a key only when nothing exists at the path.
- **A keyfile that is there but cannot be loaded is an error.** With a wrong or missing `--passphrase`, or a damaged file, the daemon exits and leaves the file untouched; it does not start with a new key. To start over with a new key, move the old file away first.
- **A recovery phrase is checked before use.** `--from-mnemonic` and `--hd-mnemonic` accept 12, 15, 18, 21 or 24 lower-case words from the BIP39 English list with a valid checksum (extra spaces are ignored) and exit with the reason otherwise.
- **Keyfiles are private.** New keyfiles are created with mode `0600`. An existing keyfile that group or others can access is tightened to `0600` at start-up, with a warning, when it is a regular file owned by the user running the daemon, has no other hard links and is not reached through a symbolic link. Otherwise its mode is left alone: a keyfile readable only by its group (for example `root:superscalar 0640`, read by the service user) is used with a warning; a keyfile readable by every user is refused with an error naming the mode. For a mounted secret, set the mount's file mode to `0400` or `0440`.
- **Writing a keyfile needs a writable directory.** The file is written under a temporary name (`<keyfile>.ss-partial.XXXXXX`) in the same directory and then moved into place, so the directory must be writable and a crash never leaves a half-written key. A `--keyfile` path that is a symbolic link can be read but is never written to.

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
| `--arity` | advanceless | Tree shape.  Without `--arity`, `--static-near-root` and `--ps-subfactory-arity` the LSP builds the advanceless tree: every interior level kickoff-only, one member per pseudo-Spilman leaf, zero exit delay (4 clients: `4,3` static 1; 64: `8,8,3` static 2; rule in [factory-arity.md](factory-arity.md)).  Such a factory is extended only by rotation.  Explicit: `3` = Pseudo-Spilman, `1`/`2` = DW, comma list per level (e.g. `3,4,8`). |
| `--static-near-root` | depth of the default tree | Number of near-root tree levels to make kickoff-only (no DW state machine).  With an explicit `--arity` and no `--static-near-root`, 0. |
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
| `--dying-blocks` | 10 (regtest) / 432 (other) | Factory dying period (the rotation window, when rotation is enabled) |
| `--fee-rate` | 1000 | Fee rate in sat/kvB |
| `--tree-fee-rate N` | 100 | The factory's agreed pre-signed rate (sat/kvB), proposed in FACTORY_PROPOSE: every tree tx, the distribution TX and the commitments pay exactly it for their size; 0 = no fee (0-value anchors, every exit tx needs a CPFP child). Never taken from a fee estimate. Clients refuse a rate above their own `--max-tree-fee-rate` (default 10000). A factory with more than 230 clients is refused before funding: its distribution TX would not fit a TRUC transaction |

**Ceremony timeouts on signet/testnet4**: MuSig2 signing ceremonies (factory creation, cooperative close, rotation) use longer message timeouts on non-regtest networks — 120s per message vs 30s on regtest. The cooperative close nonce/psig collection uses 300s per client on signet/testnet4. These are automatic based on `--network`; no flags needed.

### Security

| Flag | Default | Description |
|------|---------|-------------|
| `--keyfile` | none | Encrypted keyfile path (alternative to --seckey; required on mainnet, where `--seckey` is refused). Created if nothing exists at the path; never overwritten. See "How the keyfile is handled" in section 3 |
| `--passphrase` | none | Keyfile decryption passphrase |
| `--encrypt-db` | off (forced on mainnet) | Encrypt secret columns (HD seed, revocation/channel secrets) at rest |
| `--tor-proxy` | none | SOCKS5 proxy for Tor (e.g. `127.0.0.1:9050`) |
| `--tor-control` | none | Tor control port for hidden service creation |
| `--generate-mnemonic` | off | Generate 24-word BIP39 mnemonic, derive keyfile, and exit. Refuses if `--keyfile` already exists |
| `--from-mnemonic` | *(none)* | Derive keyfile from BIP39 mnemonic words (validated first). Refuses if `--keyfile` already exists |
| `--mnemonic-passphrase` | "" | Optional BIP39 passphrase for seed derivation |
| `--max-conn-rate` | 10 | Max inbound connections per minute per IP |
| `--max-handshakes` | 4 | Max concurrent handshakes |
| `--onion` | off | Create Tor hidden service on startup |

### JIT Channels

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-jit-experimental` | off | **Unsafe, testing only.** Allow the LSP to open JIT channels: for every connected client once all factories have expired, and when a factory client sends `lsps2.buy`. Refused on mainnet. |
| `--jit-amount` | auto | Per-client JIT channel funding amount (only used with `--enable-jit-experimental`) |

JIT channels are **disabled by default**. Without `--enable-jit-experimental`
the LSP never offers a JIT channel, never funds one, and answers `lsps2.buy`
and `lsps2.get_info` with a JSON-RPC error. The current JIT channel is an experiment: the LSP
broadcasts the funding transaction before the client has signed anything, so
a client that stops responding leaves the LSP's coins in a 2-of-2 output, and
the channel cannot yet carry payments. Do not enable it with funds you are
not prepared to lose. `--test-jit` implies the flag. JIT channels that were
opened earlier are still loaded at start-up and closed at rotation whether or
not the flag is given.

### Factory Rotation

| Flag | Default | Description |
|------|---------|-------------|
| `--enable-rotation-experimental` | off | **Unsafe, testing only.** Allow factory rotation: automatically when a factory turns DYING (daemon mode), and the CLI `rotate` command. Refused on mainnet. |
| `--async-rotation` | off | Queue rotation requests and wait for offline clients to reconnect. Needs `--enable-rotation-experimental`. |

Factory rotation is **disabled by default**. In its current form the members
hand their factory keys to the LSP, the LSP closes the old factory with every
output, members' balances included, paid to its own wallet, and the new
factory reuses the same keys. Do not enable it with funds you are not prepared
to lose. `--test-rotation` and `--test-partial-rotation` imply the flag.
See [Factory Rotation](#12-factory-rotation) for what happens to a factory
when rotation is off.

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
| `--backup PATH` | — | Create encrypted backup of `--db` and `--keyfile` at PATH and exit (passphrase via `SUPERSCALAR_BACKUP_PASSPHRASE` env) |
| `--restore PATH` | — | Restore `--db` and `--keyfile` from the backup at PATH and exit. Never overwrites: see section 6 |
| `--backup-verify` | — | Verify backup integrity and exit |
| `--fee-bump-after` | 6 | Blocks before first RBF fee bump on funding TX |
| `--fee-bump-max` | 3 | Maximum number of fee bump attempts |
| `--fee-bump-multiplier` | 1.5 | Fee rate multiplier per bump |
| `--version` | — | Print version and exit |
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
| `--test-rotation` | off | Full factory rotation lifecycle (implies `--enable-rotation-experimental`) |
| `--force-close` | off | Broadcast factory tree on-chain, wait for confirmations |

### Interactive CLI

When `--cli` is enabled in daemon mode, the LSP reads commands from stdin:

| Command | Description |
|---------|-------------|
| `pay <from> <to> <amount>` | Send a payment between factory clients |
| `rebalance <from> <to> <amount>` | Rebalance channels within the factory |
| `invoice <client> <amount>` | Create a BOLT11 invoice for a client (requires bridge) |
| `status` | Print channel balances, factory state, ladder info |
| `rotate` | Trigger manual factory rotation (only with `--enable-rotation-experimental`) |
| `close` | Initiate cooperative close and shutdown |
| `help` | Show available commands |

## 6. Backup & Restore

Create encrypted backups of the database and keyfile:

```bash
# Create a backup (reads passphrase from SUPERSCALAR_BACKUP_PASSPHRASE env var)
export SUPERSCALAR_BACKUP_PASSPHRASE="your-secure-passphrase"
./superscalar_lsp --db lsp.db --keyfile lsp.key --backup /path/to/backup.bak

# Verify a backup without restoring
./superscalar_lsp --backup-verify /path/to/backup.bak

# Restore from backup: --db and --keyfile name where the two files are written
./superscalar_lsp --restore /path/to/backup.bak --db lsp.db --keyfile lsp.key
```

Backup format (v2): `[magic][version][iterations][salt][nonce][ciphertext][tag]` using PBKDF2-HMAC-SHA256 key derivation (600,000 iterations) and ChaCha20-Poly1305 AEAD encryption. V1 backups (`SSBK0001`) are auto-detected and can still be decrypted. The passphrase never touches disk. A backup whose stored iteration count is outside 100,000 to 10,000,000 is rejected.

**Restore never overwrites.** `--restore` exits with an error, naming the file in the way, if any of these exists:

- the database (`--db`), or its SQLite sidecar files `<db>-wal`, `<db>-shm` or `<db>-journal`;
- the keyfile (`--keyfile`).

Stop the LSP, move the old database (with its sidecar files) and the old keyfile out of the way, then restore. Both files are written completely before either appears; the keyfile is put in place first, then the database. If the restore fails, neither file is normally left behind. If the process is killed between the two steps, or the keyfile cannot be removed again after a failure (an error names it), the keyfile is left without the database: delete it before running `--restore` again.

**Failed writes are reported.** `--backup` and `--restore` write to a temporary file (`<name>.ss-partial.XXXXXX`) in the destination directory and move it into place only when it is complete on disk. On a full disk or any other write error they print `FAILED` and exit non-zero, and an older backup at the same path is left intact. The destination directory must be writable, and a destination that is a symbolic link is refused.

**Permissions.** Backups, restored databases and restored keyfiles are created with mode `0600`. When a backup is read (`--backup-verify`, `--restore`), and when the keyfile is read for `--backup`, a file that group or others can access is tightened to `0600` with a warning, under the same conditions as for keyfiles (section 3): a regular file owned by the current user, with no other hard links, not reached through a symbolic link. Otherwise its mode is left alone and it is still read, so a backup on read-only media can be restored.

Schedule regular backups in production. Keep backups on a separate machine.

## 7. Crash Recovery

If the LSP process crashes (power failure, OOM, etc.):

1. Restart with the **same `--seckey`** (or `--keyfile`) and **same `--db`** path
2. The LSP loads factory state, channel balances, and pending HTLCs from the database
3. Clients detect the disconnect and reconnect automatically (5s retry loop)
4. After reconnection, pending HTLCs are replayed and normal operation resumes

Without `--db`, crash recovery is not possible — you'll need to wait for CLTV timeout.

## 8. Standalone Watchtower

For defense-in-depth, run `superscalar_watchtower` on a separate machine. It opens a secret-less `wt.db` of pre-signed response transactions (penalty / sweep / poison TXs, **no secrets and no signing keys**) and independently monitors the blockchain:

```bash
./superscalar_watchtower \
  --wt-db /path/to/wt.db \
  --network signet \
  --poll-interval 30 \
  --cli-path /path/to/bitcoin-cli \
  --rpcuser YOUR_USER \
  --rpcpassword YOUR_PASS
```

On mainnet the watchtower, like the LSP and the client, starts only with `--i-accept-the-risk` and refuses `--cheat-*` / `--test-*` flags and `SS_CHEAT*`, `SS_KILL*` and `SUPERSCALAR_CRASH*` environment variables. `--network bitcoin` is another spelling of `--network mainnet` and is treated identically by all three daemons.

The systemd unit in `tools/deploy/superscalar-watchtower.service` passes `$SS_WATCHTOWER_ARGS` from `/etc/superscalar/env`; for a mainnet watchtower set `SS_WATCHTOWER_ARGS=--i-accept-the-risk` there.

The watchtower prints heartbeat messages and broadcasts the relevant pre-signed response automatically if a breach is detected. Because it holds no secrets and no keys, a compromised watchtower cannot construct any new transaction — verifiable with `nm` (see [`watchtower-trustless-schema.md`](watchtower-trustless-schema.md)). To fund CPFP fee-bumping of the anyone-can-spend P2A anchors under fee pressure, pass `--bump-wallet` (a wallet the bumper spends its own UTXOs from; the watchtower still signs nothing of the protocol).

### Watchtower flags

| Flag | Default | Description |
|------|---------|-------------|
| `--wt-db PATH` | **required** | Path to the watchtower response DB (pre-signed penalty/sweep/poison TXs; contains **no secrets**) |
| `--network MODE` | regtest | Bitcoin network: regtest / signet / testnet / testnet4 / mainnet. An unknown name is refused |
| `--i-accept-the-risk` | off | Required for mainnet operation. On mainnet the watchtower also refuses `--cheat-*` / `--test-*` flags and `SS_CHEAT*`, `SS_KILL*`, `SUPERSCALAR_CRASH*` environment variables |
| `--poll-interval N` | 30 | Seconds between block scans |
| `--cli-path PATH` | bitcoin-cli | Path to bitcoin-cli binary |
| `--rpcuser USER` | rpcuser | Bitcoin RPC username |
| `--rpcpassword PASS` | rpcpass | Bitcoin RPC password |
| `--datadir PATH` | (default) | Bitcoin datadir |
| `--rpcport PORT` | (auto) | Bitcoin RPC port override |
| `--bump-wallet NAME` | — | Funded wallet the CPFP fee-bumper draws UTXOs from (to CPFP the P2A anchor; the WT holds no protocol keys) |
| `--max-bump-fee SATS` | 50000 | Cap on the fee of one CPFP child (penalty bumps and every pre-signed exit tx) |
| `--bump-budget-pct N` | — | Percentage of channel value to budget for fee bumps |
| `--version` | — | Show version and exit |
| `--help` | — | Show help and exit |

## 9. Monitoring

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
  "SELECT id, factory_id, slot, local_amount, remote_amount, commitment_number, state FROM channels"

# Check factory state
sqlite3 -header -column lsp.db \
  "SELECT id, n_participants, funding_amount, leaf_arity, state FROM factories"
```

### JSON Diagnostic Report

```bash
./superscalar_lsp --report /tmp/lsp_report.json ...
```

Writes a JSON file with factory state, channel balances, and pending HTLCs.

## 10. CLN Bridge (Lightning Network Integration)

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

The plugin port is bound to `127.0.0.1` unless `--plugin-bind` names another
address. The bridge and the plugin authenticate each other with a shared
secret. On first start the bridge writes a random secret to
`--plugin-secret-file` (default `~/.superscalar/bridge-plugin.secret`, mode
`0600`); the plugin reads the same file. The secret is never sent: each side
sends a random nonce and proves it holds the secret with an HMAC over both
nonces, the plugin checks the bridge first, and neither side acts on a message
from a peer that has not passed. Both sides refuse a secret file that is not a
regular file owned by their own user with no group or other permissions. The
handshake also yields a session key, and every later line in either direction
carries a MAC under it with a running counter, so a process between the two
cannot add, alter, replay or drop a message without ending the connection. The
link is not encrypted (payment hashes, amounts and preimages are readable to
whoever can see the traffic), so keep it on loopback or a trusted network. Only
one plugin connection is served at a time; further connections are closed.

### Step 3: Start CLN with the Plugin

```bash
lightningd --network=regtest \
  --important-plugin=/path/to/tools/cln_plugin.py \
  --superscalar-bridge-host=127.0.0.1 \
  --superscalar-bridge-port=9736 \
  --superscalar-bridge-secret-file=~/.superscalar/bridge-plugin.secret \
  --superscalar-lightning-cli=lightning-cli
```

Load the plugin with `important-plugin=`, never with `plugin=`. With
`plugin=`, `lightningd` keeps running when the plugin stops, and it then
settles HTLCs for unpaid factory invoices by itself (see below).

### Running the plugin as a different user

`lightningd` normally runs under its own account, and both sides insist that
the secret file belongs to the user reading it. Give each side its own copy:

```bash
# The bridge (user superscalar) creates its file on first start:
#   --plugin-secret-file /var/lib/superscalar/bridge-plugin.secret
# Copy it for lightningd (user cln), owner-only:
sudo install -o cln -g cln -m 0600 \
    /var/lib/superscalar/bridge-plugin.secret /var/lib/cln/bridge-plugin.secret
```

and point the plugin at its copy with
`superscalar-bridge-secret-file=/var/lib/cln/bridge-plugin.secret`. Repeat the
copy whenever the bridge's file is recreated. The plugin also needs a writable
`superscalar-bridge-state-file` (default
`~/.superscalar/bridge-plugin.state.json`), where it records outside payments
until the LSP has acknowledged their result. `tools/deploy/start_bridge.sh`
accepts `--plugin-bind` and `--plugin-secret-file` (or `PLUGIN_BIND` and
`PLUGIN_SECRET_FILE`), `tools/deploy/superscalar-bridge.service` sets them, and
`tools/deploy/cln-bridge.conf.example` shows the plugin side.

The bridge exits with status 78 when it cannot run as configured: no
`--lsp-pubkey`, a `--plugin-bind` that is not an IPv4 address, a secret
directory it cannot create, or a secret file it cannot create or will not
accept. The message says which. `start_bridge.sh` and the systemd unit do not
restart it on that status.

### What the plugin keeps on disk

The plugin's state file (`superscalar-bridge-state-file`) holds what must
survive a restart of `lightningd`: outside payments that were requested and
whose result the LSP has not acknowledged, the HTLCs handed to the LSP and not
yet resolved, and the factory invoices already fulfilled (with the preimage
given). It is written atomically, mode `0600`, and records the CLN node id and
the LSP key it belongs to.

The plugin loads it before it does anything else and **stops** if the file
cannot be read or parsed, belongs to another node, or cannot be written. With
`important-plugin=` that stops `lightningd`. Do not delete the file to get
going again without checking it: an open payment in it may still complete on
the node (and would then never be reported to the LSP), and a held HTLC would
be treated as new. A bridge that serves a different LSP than the one recorded
is refused the link.

### What the bridge checks do not cover

Core Lightning holds every factory invoice together with its preimage (that
is how it produces the BOLT11 string). The plugin therefore never lets CLN
handle an HTLC for a factory invoice, deletes CLN's copy once the LSP has
fulfilled it, and keeps fulfilled hashes closed across restarts. That
protection is the plugin's, so it has limits:

- **Plugin not loaded.** If `lightningd` runs without the plugin, CLN settles
  any HTLC for an unpaid factory invoice by itself: the payer is charged and
  the node keeps the money, while the factory client is not paid. This was
  seen on CLN v26.06.9 with the plugin loaded as `plugin=` and stopped.
  `important-plugin=` is therefore required: CLN then stops when the plugin
  does. Do not start `lightningd` without the plugin while factory invoices
  are outstanding.
- **Outside payments are not reachable from the stock client.** The LSP pays
  an outside invoice when a client offers an HTLC that carries the invoice,
  but `superscalar_client` has no command that sends one. The path is
  exercised by tests only.
- **Keysend is refused.** A keysend arriving at the node is failed with
  `incorrect_or_unknown_payment_details`, whether or not it was meant for a
  factory client: nothing delivers a keysend's preimage to a factory client,
  and CLN's own keysend handling would settle it for the node, including one
  whose payment hash an outside payment in flight is using. The node cannot
  receive keysends while the plugin is loaded.
- **An outside payment that fails** is failed back to the client with a full
  commitment exchange. One that is refused before the LSP takes the HTLC (bad
  invoice, deadline too close, bridge down) is answered with a failure marked
  `uncommitted`, and both sides drop the HTLC without a commitment exchange.
  If the client does not complete an exchange the LSP started, the LSP
  closes that client's connection and finishes the exchange when the client
  reconnects.
- **Invoices from the LSP's own invoice code** (payee is the LSP key, which
  is not a node in the Lightning graph) can only be paid by a sender that is
  given a route hint through the Lightning node. Invoices created through the
  plugin are CLN's own and do not have this limit.
- **Self-payment.** A factory client paying another factory client's invoice
  as an outside payment is refused by the LSP (`invoice_is_internal`) and by
  the plugin (invoice issued by, or payable to, this node). Both checks rely
  on the registries of the running LSP and plugin.
- **One use per payment hash.** A hash with an HTLC in flight, or one that was
  paid in either direction, is not accepted for a new invoice or a new inbound
  payment. The LSP's memory of completed hashes is bounded (the last 64
  outside payments, the last 32 inbound fulfils) and is not restored after an
  LSP restart, except for inbound fulfils the bridge has not yet confirmed.
- **Multi-part payments** to a factory invoice are refused part by part; the
  payer has to send the full amount in one HTLC.
- **HTLC replay** after a `lightningd` restart is matched by CLN's own HTLC
  name (`short_channel_id` and `id` in the `htlc_accepted` hook). An HTLC CLN
  does not name cannot be matched: the repeat is refused, and it is not
  offered to the LSP again after a bridge reconnect.
- **A pay result the LSP rejects** (for instance a success whose preimage
  does not match) leaves the client's HTLC held and is logged as an error by
  the LSP and the plugin. Nothing resolves it automatically.
- **An outside payment whose result never arrives** (node or bridge down for
  good) leaves the client's HTLC held; the LSP warns near its expiry, with or
  without a bridge connection, and does not fail it on a timer.
- **An outside payment held by the remote side.** The node's own outgoing
  HTLC must expire well before the client's HTLC does: the LSP keeps back the
  blocks it needs to claim the client's HTLC in the factory (in one run
  `pay` was given `maxdelay=17` for a client HTLC that expired more than 100
  blocks later). If the payee or a hop holds the payment until that earlier
  expiry, CLN closes its channel unilaterally to take the HTLC back on-chain.
  The payment then fails and the client is refunded, long before the
  client's own HTLC would have expired, and the operator bears the cost of a
  channel close.
- **A channel that is closed and forgotten while its incoming HTLC is
  held.** CLN v26.06.9 aborted (`SIGABRT` in `htlc_accepted_hook_final`) when
  a held `htlc_accepted` hook was answered after the HTLC's channel had been
  closed on-chain and CLN had logged `onchaind complete, forgetting peer`.
  Before answering, the plugin asks `listpeerchannels`; if CLN answers and no
  longer lists the channel, the plugin does not answer the hook. A channel
  that is still listed gets its answer in every state, including
  `AWAITING_UNILATERAL` and `ONCHAIN`: while a channel is being closed, the
  answer is how CLN learns the preimage it needs to claim the HTLC. Which
  closing states are safe to answer in has not been established from CLN's
  source for this version; only the forgotten-channel case was observed and
  only that case is guarded. If the withheld answer was a fulfil, the
  factory client has been paid and the incoming payment has not been
  settled. The plugin then keeps the preimage in its state file under
  `unresolved`, logs an error, and reports `htlc_unresolved` to the LSP. The
  LSP logs `the Lightning node could not take the fulfil` with the payment
  hash, the upstream HTLC and the preimage, keeps the fulfil in its database
  and does not treat it as delivered. Recovering the money is up to the
  operator. The check and the answer are two steps; a channel forgotten
  between them is not caught.
- **An inbound HTLC that nears its expiry while the bridge is away** is
  failed back to the client. The Lightning node still holds its HTLC; the
  LSP keeps the failure on record and tells the bridge when it is connected
  again, or when the plugin offers the held HTLC again.
- **Keepalive messages.** The LSP's waits for a client's reply in the bridge
  paths skip keepalive pings and pongs. The waits in the reconnect
  retransmission and in the operator-initiated payment commands do not yet:
  a keepalive arriving there is taken for the awaited reply and the exchange
  is abandoned until the client reconnects.
- **Deadlines.** The check that an HTLC's expiry is far enough past the
  current block height is applied to outside payments only, not yet to
  inbound and factory-internal HTLCs.
- **The plugin link** is authenticated line by line but not encrypted.
- **A bridge restart** loses its table of pending inbound HTLCs and its queue
  for the plugin. The plugin offers its held HTLCs again when it reconnects
  and the LSP repeats unconfirmed fulfils, which covers both; a pay request
  that was only in the bridge's queue is lost, and its client HTLC stays held.

### Known limits of channel updates in this release

The LSP and a client change a channel's state with a short exchange: the
change (an HTLC added, fulfilled or failed), the LSP's commitment signature,
the client's revocation, the LSP's revocation. The following holds for every
such exchange, not only for the bridge:

- **A connection lost in the middle.** When the client reconnects, the LSP
  sends the pending commitment signature again but not the change it belongs
  to (the fulfil or fail itself). A client that never received the change
  cannot verify that signature, and the two sides can fail to converge on
  the same state.
  A commitment that is pending at reconnect is settled only by the client's
  valid revocation: if the client does not send one (it cannot, if it never
  received the change), the LSP keeps the commitment pending, refuses the
  reconnect and closes the connection. Such a client cannot reconnect until
  the operator deals with the channel.
- **Messages that arrive out of turn.** While the LSP is waiting for a
  client's reply, any other message that client sends is dropped, not queued.
  A request sent at that moment is lost and has to be sent again.
- **Signatures before storage.** The LSP sends its commitment signature
  before the new state is durably saved. A crash between the two leaves the
  client with a signature for a state the LSP does not remember.

- **An inbound HTLC failed near its expiry.** The LSP tells the Lightning
  node to fail the incoming HTLC as soon as it has failed the HTLC towards
  the client; it does not first wait for the client's revocation of the
  state that still contained it.
- **A fulfil the Lightning node could not take** stays on the LSP's record
  until the node acknowledges it; nothing else clears it, and it is offered
  to the node again after each LSP start. The LSP drops such records after
  14 days. The plugin's state file keeps the preimage.

What is checked: a revocation whose secret does not match the point the
client committed to is refused, the exchange counts as not done and the
client is disconnected, and an HTLC whose addition the client did not
revoke for is failed and goes no further; the LSP starts no second exchange on a channel while
one is in progress (a result from the Lightning node for that channel waits
its turn); a client can fail only an HTLC it received, and takes back an HTLC
of its own only if the LSP has signed nothing that contains it.

These limits are being addressed by moving every channel update
onto one routine. They are not fixed in this release.

### Live-node checklist

The code relies on the following behaviour of CLN. Items marked `[x]` were
seen to hold on regtest against Core Lightning v26.06.9 (one node with the
plugin, one outside node, two factory clients); the others have not been
exercised against a running node. Check each again on the CLN version you
deploy.

`htlc_accepted` hook
- [x] `htlc.short_channel_id` and `htlc.id` are present and identify the
      incoming HTLC; `htlc.amount_msat` is the amount received and
      `htlc.cltv_expiry` its absolute expiry.
- [x] `onion.payload` is the hop payload as it is in the onion: a BigSize
      length followed by the TLV stream.
- [x] After a restart, `lightningd` calls the hook again for every HTLC that
      was unresolved, with the same `short_channel_id` and `id`.
- [x] An HTLC stays held for as long as the plugin does not answer, including
      across a bridge reconnect, and the answer may come from another thread.
- [x] `{"result": "resolve", "payment_key": ...}` settles the HTLC without the
      invoice being marked paid; `{"result": "fail", "failure_message":
      "2002"}` and `"0017"` are accepted as failure messages.
- [x] `{"result": "fail", "failure_message": "400f" + amount + height}`
      (the answer to a keysend) reaches the sender as
      `incorrect_or_unknown_payment_details`.
- [x] `{"result": "continue"}` for a hash with no invoice forwards or fails
      the HTLC as CLN would without the plugin.
- [x] The hook registration `"before": ["keysend"]` is honoured: the plugin
      sees a keysend before CLN's keysend plugin does.
- [ ] The hook must not be answered once CLN has forgotten the HTLC's
      channel (CLN aborts). `listpeerchannels` lists a channel under
      `short_channel_id` or `alias` for as long as CLN can take the answer,
      and answering with the preimage while the channel is closing lets CLN
      claim the HTLC on-chain.

Invoices
- [x] `invoice` accepts `preimage`, `cltv`, `expiry` and
      `exposeprivatechannels` together, and returns `bolt11`.
- [x] `listinvoices` returns `label`, `payment_hash` and `status` (`unpaid`
      until paid or expired).
- [x] `delinvoice label=... status=unpaid` removes an invoice whose HTLC was
      resolved through the hook.

Outside payments
- [x] `decode` returns `type: "bolt11 invoice"`, `valid`, `payment_hash`,
      `amount_msat`, `payee` and `min_final_cltv_expiry`.
- [x] `pay` accepts `maxfee`, `maxdelay` and `retry_for` together; `maxfee`
      is an absolute amount in millisatoshi and bounds the total fee.
- [x] `lightning-cli pay` prints a notification line starting with `# `
      ahead of the JSON reply on success; `lightning-cli -N none` suppresses
      it. An error is printed as a JSON object with `code` and `message`,
      with exit status 1.
- [ ] `pay` starts no new attempt after `retry_for` seconds, and none after
      it has returned an error; a JSON-RPC error from `pay` means the command
      is over.
- [ ] `pay` for an invoice the node already paid returns the old preimage
      without paying again (the reason the plugin checks `listsendpays`
      first).
- [x] `listpays payment_hash=...` reports `pending` while any part is in
      flight, `failed` only when all parts failed, and `complete` with
      `preimage`.
- [x] `listsendpays payment_hash=...` returns `payments` with `status`.
- [x] `getinfo` returns `id`, and RPC calls work from inside the plugin's
      `init` handling.

Plugin life cycle
- [x] With `important-plugin=`, `lightningd` stops when the plugin exits
      (the plugin exits on an unusable state file).
- [x] The plugin's options are delivered in `init` as declared, and
      `lightning-dir` is in `configuration`.
- [x] `lightning-cli -k` with `--lightning-dir`/`--network` as the plugin
      builds them reaches the node the plugin runs in.

Deployment
- [ ] `tools/deploy/superscalar-bridge.service` starts the bridge before
      `lightningd`, and the copy of the secret file for the `lightningd` user
      is accepted by the plugin.
- [ ] End to end on the network you deploy on: an inbound payment to a
      factory invoice, an outside payment from a factory client, each across
      a restart of `lightningd`, of the bridge and of the LSP while the HTLC
      is in flight.

### Bridge Daemon Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--lsp-host HOST` | `127.0.0.1` | LSP hostname or IP address |
| `--lsp-port PORT` | `9735` | LSP listening port |
| `--plugin-port PORT` | `9736` | Port the bridge listens on for the CLN plugin |
| `--plugin-bind ADDR` | `127.0.0.1` | IPv4 address the plugin port binds to |
| `--plugin-secret-file PATH` | `~/.superscalar/bridge-plugin.secret` | File holding the secret the plugin must present; created (mode `0600`) if missing |
| `--lsp-pubkey HEX` | *(none)* | LSP static pubkey (33-byte compressed hex) for NK-authenticated Noise handshake |
| `--tor-proxy HOST:PORT` | `127.0.0.1:9050` | SOCKS5 proxy for connecting to the LSP over Tor |

### CLN Plugin Options

| Option | Default | Description |
|--------|---------|-------------|
| `--superscalar-bridge-host` | `127.0.0.1` | Bridge daemon hostname |
| `--superscalar-bridge-port` | `9736` | Bridge daemon port |
| `--superscalar-bridge-secret-file` | `~/.superscalar/bridge-plugin.secret` | File with the bridge's shared secret (written by the bridge); regular file, owned by the plugin's user, mode `0600` |
| `--superscalar-bridge-state-file` | `~/.superscalar/bridge-plugin.state.json` | Where the plugin records outside payments until their result is acknowledged |
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
| Bridge logs `plugin connection failed authentication`, or the plugin logs `Peer on the bridge port does not hold the bridge secret` | The plugin's `--superscalar-bridge-secret-file` does not hold the secret in the bridge's `--plugin-secret-file` |
| Plugin logs `Bridge secret ... must be a regular file owned by this user with mode 0600` | Fix the owner and mode of the plugin's copy of the secret file |
| "INVOICE_BOLT11 for unknown hash" | Client must send `MSG_REGISTER_INVOICE` before the external payment arrives |
| Bridge heartbeat timeout | Check network connectivity between bridge and LSP; default timeout is 30 seconds |
| "htlc_accepted hook timeout" | Increase CLN's hook timeout or check bridge ↔ LSP latency |

## 11. JIT operations and rollback

Buy-liquidity, leaf reallocation, and bridge HTLC forwarding can all fail mid-flight (e.g. a client times out during the realloc MuSig ceremony, or a downstream BOLT-11 payment fails). SuperScalar relies on **cut-through** for reconciliation rather than a per-realloc undo hashlock — the on-chain factory is never mutated mid-flight, so failed operations leave the factory at its last fully-signed state and the next legitimate state advance absorbs the gap.

**Operational implication.** An operator does not need to take any recovery action when a JIT operation fails mid-flight — the LSP retries or surfaces the failure to the originating client, and the factory's signed state remains unchanged. Database rollback is automatic via the same transaction boundary as the in-memory state.

The full rollback contract per primitive (realloc, buy-liquidity, bridge HTLC, coop close) is documented at [superscalar.win](https://superscalar.win).

## 12. Factory Rotation

Factories have a limited lifetime (`--active-blocks` + `--dying-blocks`).

**Rotation is off by default.** Without `--enable-rotation-experimental` the
LSP never rotates a factory:

1. When the factory turns DYING the LSP logs
   `factory N DYING — not rotating: rotation is disabled` and carries on.
   Channels stay in service: payments between members keep working.
2. When it turns EXPIRED the LSP logs the block at which the distribution TX
   becomes valid (its nLockTime, the factory CLTV, `--cltv-timeout`).
3. From that block on, the LSP broadcasts the distribution TX that the LSP
   and every member co-signed when the factory was created. It pays every
   member their share. If it is not accepted, it is retried at the next block.
4. Members do not depend on the LSP for this: each holds its own co-signed
   copy of the distribution TX, and can exit unilaterally (`superscalar_client
   --force-close`) at any time.

The CLI `rotate` command answers that rotation is disabled.

**With `--enable-rotation-experimental`** (testing only, refused on mainnet),
the LSP rotates to a new factory when the old one turns DYING:

1. PTLC key turnover extracts client keys via adaptor signatures
2. Old factory is cooperatively closed (LSP can sign alone with extracted keys)
3. New factory is created with the same clients
4. Channels resume in the new factory

This is not safe yet: the close in step 2 pays everything to the LSP wallet,
and the new factory reuses the extracted keys. `--test-rotation` runs the
rotation once after the demo, for testing.

## 13. Troubleshooting

| Problem | Fix |
|---------|-----|
| "wallet balance insufficient" | Fund your wallet. On regtest: mine blocks. On signet: use faucet. |
| "cannot connect to bitcoind" | Check `--cli-path`, `--rpcuser`, `--rpcpassword`, `--datadir` |
| "funding tx not confirmed" | Increase `--confirm-timeout`. Signet blocks average ~10 min. |
| Clients can't connect | Check firewall, verify `--port` matches on both sides |
| Crash recovery fails | Must use same `--seckey` and `--db` as original run |
| "too many open files" | Increase ulimit: `ulimit -n 4096` |
