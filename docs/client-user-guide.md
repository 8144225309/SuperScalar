# Client User Guide

How to connect to a SuperScalar LSP and use your payment channel.

## What You Need

- The `superscalar_client` binary (see main [README](../README.md#build) for build instructions)
- The LSP's IP address (or hostname / .onion) and port
- A 32-byte secret key for your identity
- (Optional) `bitcoin-cli` access for watchtower functionality

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

### Your factory keys

The key above is your **identity** key: it identifies you to the LSP and is never used
to sign a factory. For every factory you join, the client derives a separate **factory
key** from it (and from the LSP's pinned key), records which one in `--db`, and signs
that factory, its channel and its payouts with it. Handing one factory key to the LSP
(as a partial rotation does, after the client's own checks) reveals neither your
identity key nor any other factory key.

- With `--db`, pin the LSP's key with `--lsp-pubkey` (required on signet, testnet and
  mainnet anyway). Without it the client refuses to create a new factory key.
- Keep `--db` backed up. If it is lost but you still have your key or 24 words, the
  client finds the key of a stored factory by trying the first 1000 key indexes.
  Finding your factories from the chain alone is not supported yet.
- A factory created by an older client signs with the identity key itself ("legacy
  factory"); it keeps doing so until it is rotated. Its key is never released to the
  LSP: it moves only in a rotation with every client online.

Each factory key has a state, shown by `--export-factory-keys`:

| State | Meaning |
|-------|---------|
| `reserved` | Sent to the LSP for a factory that is not signed yet |
| `active` | The key of the factory you are in |
| `retired` | A factory you moved out of; the key was not released |
| `released` | Handed to the LSP in a partial rotation; never used again |

After a rotation switch exactly one key is active.

#### Spending your payouts

Your cooperative-close output pays your factory key directly (descriptor
`rawtr(KEY)`), and your distribution-TX output pays the BIP-86 tweaked key (descriptor
`tr(KEY)`). To spend them from a wallet, print the keys:

```bash
./superscalar_client --seckey $MY_KEY --db client.db --network signet --export-factory-keys
```

**This prints private keys.** Anyone who sees the output can spend those payouts. For
each factory key it prints the pubkey, the secret (hex), and both descriptors with
their checksums; import the one you need into Bitcoin Core, for example
`bitcoin-cli importdescriptors '[{"desc":"rawtr(...)#...","timestamp":0}]'` into a
descriptor wallet. A legacy factory is listed with your identity key's descriptors:
**that line is your master key** (the same secret as `--seckey` or your 24 words), so
treat it accordingly. The command writes no key row and never reserves a key index;
opening an older DB may still run the schema migration and tighten the file's
permissions. It prints at most 4096 keys and warns if there are more. The recovery tools `recover_stranded_coop_output` and
`superscalar_factory_residual_sweep` take client secrets: pass the "seckey" printed
here (for a legacy factory, your `--seckey`).

Retired and released keys are listed too. A retired key belongs to a factory you moved
out of; keep it until that factory is resolved. A **released** key was handed to the LSP
in a partial rotation: its value was already paid to you in the replacement factory, so
any old-factory output that still pays this key belongs to the LSP. Do not spend such
outputs — the LSP sweeps its distribution-TX payout. The key is listed only so you can recognise it.

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

### Factory Rotation

Before a factory expires the LSP rotates it into a replacement. The client takes part
only when it runs with:

- `--db`,
- the LSP's key pinned with `--lsp-pubkey`, and
- its own Bitcoin Core RPC connection (`--cli-path`, `--rpcuser`, `--rpcpassword`, ...):
  the client checks the rotation on its own chain view and waits on it to switch.

Without all three it takes no part: it stays in the old factory and leaves through that
factory's exits (its signed tree, your channel commitment, or the distribution TX after
the CLTV). The client always refuses the older key turnover, in which the LSP would
learn your factory key before anything is verified.

- **Every client online and able: close into the new factory.** The client sends a fresh
  factory key, checks the close of the old factory (one output, paying the replacement
  under the fresh keys, your balance carried exactly) and its replacement tree, stores
  them, and only then signs the close with its old key. No key is handed over. Once it
  has signed, it refuses further state changes on the old factory.
- **Some clients offline or not upgraded: partial rotation with verified release.** The
  client holds its signed replacement tree before the LSP funds it. After the funding
  confirms, it checks its own exit path and balance in the replacement, switches, and
  only then releases its old factory key, against an LSP receipt signed over exactly that
  position. Right before the key it settles its old channel: it accepts one final update
  that moves exactly the balance carried into the replacement to the LSP (same channel,
  next commitment, same fee rate, nothing in flight), signs it and revokes its own latest
  old commitment. It accepts the settlement only if its old channel holds no more than
  the balance carried into the replacement (otherwise releasing the key would forfeit
  the remainder), and it checks that against the real old channel, not an assumed value.
  The settled commitment is stored in the old database as its latest state, under the
  channel a force-close from that file reads, before anything is revoked (it pays the
  client nothing; a force-close from that file only costs the fee). If the settlement is
  interrupted after the client accepted it, the next release request is answered with
  the same settled state; nothing more is given. It never does this before those checks pass. Clients that do not move
  keep their full exit in the old factory; one that reconnects later is told by the LSP
  to exit through that factory.

The client switches only when the close (or the replacement's funding) is at the safe
depth on its own chain view, not on the LSP's word: 1 confirmation on regtest, 3 on
signet and testnet, 6 on mainnet.

#### The switch and the `.pre-rotation` file

The client builds the replacement's state in a side DB, `<db>.rotation`. At the switch
it keeps the current DB under a second name, `<db>.pre-rotation` (`<db>.pre-rotation.1`,
`.2`, ... on later rotations), and then renames the side DB to `<db>` in one rename, so
`<db>` always holds a complete DB.

The `.pre-rotation` file holds the old factory's state and its **secret keys**. Keep it,
backed up like `--db`, until the old factory is resolved (its funding output is spent and
that spend is buried, or your exit from it has confirmed). Then archive it or delete it
securely. A client that switched before it released settles its old channel from this
file when the LSP asks for the release again, so do not remove it while a release is
still owed.

After a partial rotation the latest commitment in that file is the settled one, which pays
you nothing (that balance was paid to you in the replacement); the commitments before it
are **revoked**. A copy of that file from before the settlement holds a revoked commitment:
never broadcast it, the LSP holds the revocation and would take that balance as a penalty.
A replacement that never confirms is given up after 1008 blocks (it never confirmed and
is not in the mempool or in any block since you signed): the old channel then accepts
payments again.

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
| `--seckey HEX` | **required** | Your 32-byte secret key (hex) |
| `--keyfile PATH` | none | Encrypted keyfile path (alternative to `--seckey`) |
| `--passphrase PASS` | none | Keyfile passphrase |
| `--generate-mnemonic` | off | Generate 24-word BIP39 mnemonic, derive keyfile, and exit |
| `--from-mnemonic WORDS` | *(none)* | Derive keyfile from BIP39 mnemonic words |
| `--mnemonic-passphrase PASS` | "" | Optional BIP39 passphrase for seed derivation |

### Connection

| Flag | Default | Description |
|------|---------|-------------|
| `--host HOST` | 127.0.0.1 | LSP hostname or IP (supports `.onion`) |
| `--port PORT` | 9735 | LSP port |
| `--lsp HOST:PORT` | — | Shorthand: sets both `--host` and `--port` from a single string |
| `--lsp-pubkey HEX` | none | LSP static pubkey for NK authentication (33-byte compressed hex) |
| `--participant-id N` | auto | Explicit client slot ID in the factory (auto-assigned by LSP if omitted) |
| `--network MODE` | regtest | Bitcoin network: regtest / signet / testnet / testnet4 / mainnet |
| `--regtest` | off | Shorthand for `--network regtest` |
| `--tor-proxy HOST:PORT` | none | SOCKS5 proxy for Tor connections (e.g. `127.0.0.1:9050`) |
| `--tor-only` | off | Refuse all non-`.onion` outbound connections (hard privacy mode) |
| `--daemon` | off | Stay running (auto-fulfill, watchtower, reconnect) |
| `--auto-accept-jit` | off | Auto-accept JIT channel offers from LSP |
| `--min-profit-bps N` | 0 | Refuse factory proposal if LSP's profit share for this client < N bps |
| `--i-accept-the-risk` | off | Required for mainnet operation |

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
| `--export-factory-keys` | off | Print the state, secret and wallet descriptors of every factory key in `--db` (reserved, active, retired, released), then exit (**prints private keys**; see "Spending your payouts") |

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
| "a new factory key needs the LSP's key pinned" | Pass the LSP's key with `--lsp-pubkey` (needed with `--db`) |
| "the LSP put our identity key in our slot: it does not support per-factory keys" | The LSP runs an older version that ignores per-factory keys. Ask the operator to upgrade; the client refuses to sign a factory with its identity key |
| "stored key N does not match this root key" | The `--seckey` / keyfile is not the one this `--db` was created with |
| Balance shows 0 | Channel not yet open (factory ceremony incomplete) or wrong `--db` |
| "connection refused" | LSP not running, wrong port, or firewall blocking |
| ".onion address requires --tor-proxy" | Add `--tor-proxy 127.0.0.1:9050` |
| Watchtower not detecting breaches | Need `--cli-path` with working bitcoin-cli access |
