# Client User Guide

How to connect to a SuperScalar LSP and use your payment channel.

## What You Need

- The `superscalar_client` binary (see main [README](../README.md#build) for build instructions)
- The LSP's IP address (or hostname / .onion) and port
- A 32-byte secret key for your identity
- (Optional) `bitcoin-cli` access for watchtower functionality.  The node must
  be Bitcoin Core 28.0 or later (the client refuses an older one): factory
  exits are TRUC transactions with P2A anchors that need package relay.

## 1. Generate Your Key

Your secret key identifies you to the LSP and is used for signing. Keep it safe.

```bash
# Option A: BIP39 mnemonic (recommended — write down the 24 words)
./superscalar_client --generate-mnemonic --keyfile my.key --passphrase "my passphrase"
# Prints 24 words. Write them down on paper. Your key is derived from these words.

# Option B: restore from existing mnemonic
./superscalar_client --from-mnemonic "abandon abandon ... about" \
  --keyfile my.key --passphrase "my passphrase"

# Option C: random key (save this!)
MY_KEY=$(openssl rand -hex 32)
echo "Save this: $MY_KEY"

# Option D: encrypted keyfile without mnemonic
./superscalar_client --keyfile my.key --passphrase "my passphrase" ...
```

With BIP39, you can recover your key from the 24 words at any time. Without it, if you lose your key, you lose access to your channel balance. The LSP cannot recover it for you — though your funds will eventually be recoverable via the CLTV timeout path.

**How the keyfile is handled**

- **A keyfile is never overwritten.** `--generate-mnemonic` and `--from-mnemonic` refuse to run if anything already exists at `--keyfile`. A normal start creates a key only when nothing exists at the path.
- **A keyfile that is there but cannot be loaded is an error.** With a wrong or missing `--passphrase`, or a damaged file, the daemon exits and leaves the file untouched; it does not start with a new key. To start over with a new key, move the old file away first.
- **A recovery phrase is checked before use.** `--from-mnemonic` and `--hd-mnemonic` accept 12, 15, 18, 21 or 24 lower-case words from the BIP39 English list with a valid checksum (extra spaces are ignored) and exit with the reason otherwise.
- **Keyfiles are private.** New keyfiles are created with mode `0600`. An existing keyfile that group or others can access is tightened to `0600` at start-up, with a warning, when it is a regular file owned by the user running the daemon, has no other hard links and is not reached through a symbolic link. Otherwise its mode is left alone: a keyfile readable only by its group (for example `root:superscalar 0640`, read by the service user) is used with a warning; a keyfile readable by every user is refused with an error naming the mode. For a mounted secret, set the mount's file mode to `0400` or `0440`.
- **Writing a keyfile needs a writable directory.** The file is written under a temporary name (`<keyfile>.ss-partial.XXXXXX`) in the same directory and then moved into place, so the directory must be writable and a crash never leaves a half-written key. A `--keyfile` path that is a symbolic link can be read but is never written to.

## 2. Connect to the LSP

### Basic Connection (Regtest)

```bash
./superscalar_client \
  --seckey $MY_KEY \
  --host 127.0.0.1 \
  --port 9735 \
  --daemon
```

### Full Connection (Signet)

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

### What Happens

1. Client connects to the LSP over TCP
2. If the LSP is waiting for clients (factory not yet created), you join the ceremony:
   - LSP sends factory proposal (funding amount, participants, tree shape)
   - You exchange MuSig2 nonces and partial signatures
   - LSP broadcasts the funding transaction
   - After confirmation, your channel is open
3. If the LSP has an existing factory and you're reconnecting:
   - Client sends MSG_RECONNECT with your pubkey
   - LSP matches you to your channel slot
   - Nonces are re-exchanged
   - Normal operation resumes

### Daemon Mode

With `--daemon`, the client stays running and:
- Auto-fulfills incoming HTLCs (receives payments)
- Runs a watchtower that monitors for LSP cheating
- Automatically reconnects if the connection drops (5s retry loop)
- Handles JIT channel offers (with `--auto-accept-jit`)

Without `--daemon`, the client joins the factory ceremony and exits after channel setup.

## 3. Receiving Payments

In daemon mode, incoming HTLCs are automatically fulfilled. The LSP routes the payment to your channel, you validate the preimage, and the payment completes.

Your channel balance increases on the "remote" side (from the LSP's perspective, your balance is the "remote_amount").

## 4. Checking Your Balance

### From the Database

```bash
sqlite3 -header -column client.db \
  "SELECT id, slot, local_amount, remote_amount, commitment_number, state FROM channels"
```

- `slot` = your client position in the factory (0-indexed)
- `local_amount` = your balance (what you can send)
- `remote_amount` = LSP's balance on your channel (what you can receive)
- `state` = current channel lifecycle state (`open`, `closing`, etc.)

### From the Dashboard

If the LSP operator runs the web dashboard, ask them for the URL. You can also run your own dashboard pointed at your client database:

```bash
python3 tools/dashboard.py --client-db client.db
```

## 5. Security: Your Watchtower

When running with `--daemon` and `--cli-path` (access to bitcoin-cli), the client runs a watchtower that:

- Stores every revoked commitment transaction from the LSP
- Periodically scans the blockchain and mempool for breaches
- If the LSP broadcasts a revoked commitment, your client automatically:
  1. Detects the breach
  2. Constructs a penalty transaction
  3. Broadcasts the penalty (sweeps the cheater's funds to you)

This is the core security guarantee: **you don't need to trust the LSP**. As long as your client is online (or comes online before the CLTV timeout), you can detect and penalize cheating.

### How Long Can You Be Offline?

Your funds are safe as long as you come online before the factory's CLTV timeout expires. Default timeouts:

| Network | Active period | Dying period | Total safety window |
|---------|--------------|--------------|---------------------|
| regtest | 20 blocks | 10 blocks | ~30 blocks |
| signet/testnet/mainnet | 4,320 blocks (~30 days) | 432 blocks (~3 days) | ~33 days |

If you're offline longer than this and the LSP cheats, you may not be able to penalize them. Run your client in daemon mode on a reliable machine for best protection.

## 6. Reconnection

If your connection drops:

1. Client detects the disconnect
2. Sleeps 5 seconds
3. Reconnects and sends MSG_RECONNECT with your pubkey and last commitment number
4. LSP re-identifies your channel slot and re-exchanges nonces
5. Any pending HTLCs are replayed
6. Normal operation resumes

This happens automatically in `--daemon` mode. With `--db`, your channel state survives client restarts too.

## 7. Tor Support

Connect to an LSP running as a Tor hidden service:

```bash
./superscalar_client \
  --seckey $MY_KEY \
  --host ONION_ADDRESS.onion \
  --port 9735 \
  --tor-proxy 127.0.0.1:9050 \
  --daemon
```

Requires a running Tor SOCKS5 proxy (e.g. `tor` daemon or Tor Browser).

### Authenticated Connection

If the LSP publishes their static public key, use it for NK (Noise Known) authentication:

```bash
./superscalar_client \
  --seckey $MY_KEY \
  --host LSP_ADDRESS \
  --port 9735 \
  --lsp-pubkey 02abc...def \
  --daemon
```

This prevents MITM attacks — the client verifies the LSP's identity during the Noise handshake.

## 8. Configuration Reference

| Flag | Default | Description |
|------|---------|-------------|
### Identity + keys

| Flag | Default | Description |
|------|---------|-------------|
| `--seckey HEX` | **required** unless `--keyfile` | Your 32-byte secret key (hex). Refused on mainnet (visible in `ps` and shell history): use `--keyfile` there |
| `--keyfile PATH` | none | Encrypted keyfile path (alternative to `--seckey`). Created if nothing exists at the path; never overwritten. See "How the keyfile is handled" in section 1 |
| `--passphrase PASS` | none | Keyfile passphrase |
| `--generate-mnemonic` | off | Generate 24-word BIP39 mnemonic, derive keyfile, and exit. Refuses if `--keyfile` already exists |
| `--from-mnemonic WORDS` | *(none)* | Derive keyfile from BIP39 mnemonic words (validated first). Refuses if `--keyfile` already exists |
| `--mnemonic-passphrase PASS` | "" | Optional BIP39 passphrase for seed derivation |

### Connection

| Flag | Default | Description |
|------|---------|-------------|
| `--host HOST` | 127.0.0.1 | LSP hostname or IP (supports `.onion`) |
| `--port PORT` | 9735 | LSP port |
| `--lsp DOMAIN` | — | Look up `--host` and `--port` at `http://DOMAIN/.well-known/lsps.json`. The public key served there is fetched over unauthenticated HTTP and is never trusted: `--lsp-pubkey` is still required outside regtest, and the client refuses to connect if the two differ. The lookup is a direct HTTP connection, so `--lsp` is refused together with `--tor-proxy` or `--tor-only`: give `--host` and `--port` instead |
| `--lsp-pubkey HEX` | none | LSP static pubkey for NK authentication (33-byte compressed hex). Required on every network except regtest; the client checks this before it creates a keyfile or connects |
| `--participant-id N` | auto | Explicit client slot ID in the factory (auto-assigned by LSP if omitted) |
| `--network MODE` | regtest | Bitcoin network: regtest / signet / testnet / testnet4 / mainnet |
| `--regtest` | off | Shorthand for `--network regtest` |
| `--tor-proxy HOST:PORT` | none | SOCKS5 proxy for Tor connections (e.g. `127.0.0.1:9050`) |
| `--tor-only` | off | Refuse all non-`.onion` outbound connections (hard privacy mode) |
| `--daemon` | off | Stay running (auto-fulfill, watchtower, reconnect) |
| `--auto-accept-jit` | off | Auto-accept JIT channel offers from LSP |
| `--min-profit-bps N` | 0 | Refuse factory proposal if LSP's profit share for this client < N bps |
| `--i-accept-the-risk` | off | Required for mainnet operation (`--network mainnet` or its other spelling `--network bitcoin`). Mainnet also requires `--db` and refuses `--seckey` and test/cheat flags |

### Persistence + Bitcoin RPC

| Flag | Default | Description |
|------|---------|-------------|
| `--db PATH` | none | SQLite persistence (survives restarts; required for crash recovery) |
| `--cli-path PATH` | bitcoin-cli | Path to bitcoin-cli (needed for watchtower) |
| `--rpcuser USER` | rpcuser | Bitcoin RPC username |
| `--rpcpassword PASS` | rpcpass | Bitcoin RPC password |
| `--datadir PATH` | (default) | Bitcoin datadir |
| `--rpcport PORT` | (auto) | Bitcoin RPC port override |
| `--fee-rate N` | 1000 | Fee rate for penalty / sweep transactions (sat/kvB) |
| `--fee-estimator MODE` | static | `static[:N]`, `api[:URL]` or `blocks`. Its urgent rate is also the CPFP target of exit broadcasts (default there: `estimatesmartfee`) |
| `--wallet NAME` | none | bitcoind wallet that funds CPFP children on exit; without it a bump spends the P2A anchor alone |
| `--max-tree-fee-rate N` | 100000 | Refuse a factory whose tree fee rate (sat/kvB) is above N; must match the LSP's value |
| `--light-client HOST:PORT` | — | Use a BIP-158 P2P compact-block-filter peer instead of a local bitcoind |
| `--light-client-fallback HOST:PORT` | — | Add a fallback BIP-158 peer (can repeat, up to 7 peers total) |

### Payments

| Flag | Default | Description |
|------|---------|-------------|
| `--send DEST:AMOUNT:PREIMAGE_HEX` | — | Send HTLC payment (can repeat) |
| `--recv PREIMAGE_HEX` | — | Receive payment (can repeat) |
| `--pay-offer OFFER` | — | Pay a BOLT 12 offer (requires LSP bridge connection) |
| `--channels` | off | Expect channel phase (when LSP uses `--payments`) |

### Recovery (when the LSP is unreachable)

| Flag | Default | Description |
|------|---------|-------------|
| `--force-close` | off | Broadcast your factory tree on-chain from the local DB (unilateral exit) |
| `--sweep-to-local` | off | After force-close, sweep your `to_local` outputs once CSV maturity hits |
| `--sweep-dest ADDR` | (wallet) | Destination address for swept funds (defaults to your bitcoind wallet) |

### Misc / Diagnostic

| Flag | Default | Description |
|------|---------|-------------|
| `--report PATH` | — | Write diagnostic JSON report to PATH and exit |
| `--version` | — | Print version and exit |
| `--help` | — | Show all flags and exit |

## 9. Troubleshooting

| Problem | Fix |
|---------|-----|
| "expected FACTORY_PROPOSE" | LSP isn't running or wrong `--host`/`--port` |
| Can't reconnect after restart | Use same `--seckey` and `--db` as original connection |
| Balance shows 0 | Channel not yet open (factory ceremony incomplete) or wrong `--db` |
| "connection refused" | LSP not running, wrong port, or firewall blocking |
| ".onion address requires --tor-proxy" | Add `--tor-proxy 127.0.0.1:9050` |
| Watchtower not detecting breaches | Need `--cli-path` with working bitcoin-cli access |
