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
# Generate a random key
MY_KEY=$(openssl rand -hex 32)
echo "Save this: $MY_KEY"

# Or use an encrypted keyfile
./superscalar_client --keyfile my.key --passphrase "my passphrase" ...
```

If you lose your key, you lose access to your channel balance. The LSP cannot recover it for you — though your funds will eventually be recoverable via the CLTV timeout path.

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
  "SELECT channel_id, local_amount, remote_amount, commitment_number FROM channels"
```

- `local_amount` = your balance (what you can send)
- `remote_amount` = LSP's balance on your channel (what you can receive)

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
| `--seckey` | **required** | Your 32-byte secret key (hex) |
| `--host` | 127.0.0.1 | LSP hostname or IP |
| `--port` | 9735 | LSP port |
| `--network` | regtest | Bitcoin network |
| `--daemon` | off | Stay running (auto-fulfill, watchtower, reconnect) |
| `--db` | none | SQLite persistence (survives restarts) |
| `--cli-path` | bitcoin-cli | Path to bitcoin-cli (needed for watchtower) |
| `--rpcuser` | rpcuser | Bitcoin RPC username |
| `--rpcpassword` | rpcpass | Bitcoin RPC password |
| `--datadir` | (default) | Bitcoin datadir |
| `--rpcport` | (auto) | Bitcoin RPC port override |
| `--fee-rate` | 1000 | Fee rate for penalty transactions (sat/kvB) |
| `--keyfile` | none | Encrypted keyfile path |
| `--passphrase` | none | Keyfile passphrase |
| `--lsp-pubkey` | none | LSP static pubkey for NK authentication (33-byte hex) |
| `--tor-proxy` | none | SOCKS5 proxy for Tor connections |
| `--auto-accept-jit` | off | Auto-accept JIT channel offers from LSP |
| `--send` | — | Send payment: `DEST:AMOUNT:PREIMAGE_HEX` (can repeat) |
| `--recv` | — | Receive payment: `PREIMAGE_HEX` (can repeat) |
| `--channels` | off | Expect channel phase (when LSP uses `--payments`) |
| `--report` | — | Write diagnostic JSON report to PATH |

## 9. Troubleshooting

| Problem | Fix |
|---------|-----|
| "expected FACTORY_PROPOSE" | LSP isn't running or wrong `--host`/`--port` |
| Can't reconnect after restart | Use same `--seckey` and `--db` as original connection |
| Balance shows 0 | Channel not yet open (factory ceremony incomplete) or wrong `--db` |
| "connection refused" | LSP not running, wrong port, or firewall blocking |
| ".onion address requires --tor-proxy" | Add `--tor-proxy 127.0.0.1:9050` |
| Watchtower not detecting breaches | Need `--cli-path` with working bitcoin-cli access |
