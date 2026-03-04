# Mainnet Audit — Verified Gaps

Post-v0.1.0 security audit. Each item verified against source code.

**Test baseline:** 392 unit + 43 regtest = 435 total, all passing.

---

## Critical (fund-loss risk)

### 1. No HD Key Derivation

**Status:** Real limitation

Keys are random 32-byte secrets from `/dev/urandom` (`src/keyfile.c:113-145`).
No BIP32/BIP39/BIP86 support. If the keyfile is lost, funds are lost.

The encrypted backup system (`src/backup.c`) bundles the DB + keyfile into a
passphrase-protected archive, which mitigates total loss but does not provide
deterministic seed-phrase recovery.

**Files:** `src/keyfile.c`, `include/superscalar/keyfile.h`

### 2. Weak Passphrase KDF

**Status:** Confirmed

`keyfile.c:26-35` derives the encryption key via HKDF-Extract (single
HMAC-SHA256) + HKDF-Expand. HKDF is designed for high-entropy key material,
not low-entropy passwords. An attacker with a stolen encrypted keyfile could
brute-force common passphrases at ~millions of attempts per second.

Production fix: replace with Argon2id or scrypt for the passphrase-to-key step.

**Files:** `src/keyfile.c:26-35`, `src/noise.c:22-49` (HKDF implementation)

### 3. No Atomic DB Transactions Around State Updates

**Status:** Confirmed

`persist_begin()` and `persist_commit()` exist in `src/persist.c:390-410` but
are **not used** in `src/lsp_channels.c` around the HTLC + balance update
sequence. Example at `lsp_channels.c:710-729`:

```
persist_update_channel_balance(...)   // ← no BEGIN
...
persist_save_htlc(...)                // ← separate statement
```

If the process crashes between these two calls, the database has the new
balance but the HTLC is missing, corrupting recovery state.

Production fix: wrap all related `persist_*` calls in
`persist_begin()`/`persist_commit()` blocks.

**Files:** `src/lsp_channels.c:710-729`, `src/persist.c:390-410`

---

## Serious (operational risk)

### 4. Shell Command Injection Surface

**Status:** Confirmed (low risk in practice)

`regtest_exec()` at `src/regtest.c:130-142` constructs shell commands via
`snprintf` and passes them to `popen()` without sanitizing parameters:

```c
snprintf(cmd, sizeof(cmd), "%s %s %s 2>&1", prefix, method, params);
return run_command(cmd);  // popen()
```

Currently all callers pass internally-generated strings (txids, addresses,
amounts), not user input. However, a malicious bitcoind RPC response containing
shell metacharacters (`;`, `` ` ``, `$()`) in a txid or address field could
inject commands.

Production fix: use `execvp()` with argument array instead of `popen()` with
string interpolation, or sanitize all params against `[^a-zA-Z0-9._-]`.

**Files:** `src/regtest.c:130-142`, `src/regtest.c:37-56` (prefix builder)

---

## Verified Non-Issues

The following items from the initial audit were investigated and found to be
properly handled:

- **Channel commitment storage**: Dynamic arrays (malloc/realloc) with no upper
  bound. Channels grow storage as needed — no fixed limit, no forced rotation.

- **NN handshake fallback**: Intentional design — NK authentication works when
  `--lsp-pubkey` is provided. NN fallback prints explicit stderr warning.
  Clients choose their security posture.

- **Satoshi overflow**: `channel_update()` at `channel.c:1391-1403` has proper
  bounds checks before arithmetic. Coin selection amounts are bounded by
  Bitcoin's 21M BTC supply (~51 bits), well within uint64_t range.

---

## By-Design Tradeoffs (not gaps)

These are architectural choices inherent to SuperScalar, not missing features:

- **No onion routing** — hub-and-spoke by design; cross-factory via CLN bridge
- **No BOLT #7 gossip** — off-chain channels use synthetic SCIDs + route hints
- **JSON wire protocol** — TLV codec ready, migration is incremental
- **BOLT #11 encoding** — correctly delegated to CLN
