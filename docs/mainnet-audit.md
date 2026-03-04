# Mainnet Audit — Verified Gaps

Internal security audit. Each item verified against source code.

**Test baseline:** 415 unit + 43 regtest = 458 total, all passing.

**Status: All 4 gaps identified in the original audit are now fixed.**

---

## Fixed: Critical (fund-loss risk)

### 1. No HD Key Derivation — FIXED

**Original gap:** Keys were random 32-byte secrets from `/dev/urandom`. No BIP32/BIP39
support. If the keyfile was lost, funds were lost.

**Fix:** Full BIP39 mnemonic support (`src/bip39.c`) and BIP32 HD key derivation
(`src/hd_key.c`). Users can generate 12/24-word seed phrases and derive deterministic
keys via `--generate-mnemonic` and `--from-mnemonic` flags. Derivation path:
`m/1039'/0'/0'`. 10 tests including official TREZOR test vectors.

**Files:** `src/bip39.c`, `include/superscalar/bip39.h`, `src/hd_key.c`,
`tools/superscalar_lsp.c`, `tools/superscalar_client.c`

### 2. Weak Passphrase KDF — FIXED

**Original gap:** `keyfile.c` derived encryption keys via HKDF-Extract (single HMAC-SHA256).
Backup files used the same single-pass HKDF. An attacker with a stolen encrypted file
could brute-force passphrases at millions of attempts per second.

**Fix:** Keyfile encryption upgraded to PBKDF2-HMAC-SHA256 with 600,000 iterations
(`src/keyfile.c`). Backup encryption upgraded from HKDF to PBKDF2-HMAC-SHA256 with
600,000 iterations (`src/backup.c`). Backup format v2 (`SSBK0002`) auto-detected
alongside v1 (`SSBK0001`) for backward compatibility.

**Files:** `src/keyfile.c`, `src/backup.c`, `include/superscalar/backup.h`

### 3. No Atomic DB Transactions Around State Updates — FIXED

**Original gap:** `persist_begin()` and `persist_commit()` existed but were not used
around HTLC + balance update sequences in `lsp_channels.c`. A crash between calls
could corrupt recovery state.

**Fix:** All multi-statement persist sequences wrapped in `persist_begin()`/`persist_commit()`
blocks. Verified across `lsp_channels.c`, `lsp_bridge.c`, and `lsp_demo.c`.

**Files:** `src/lsp_channels.c`, `src/lsp_bridge.c`, `src/lsp_demo.c`

---

## Fixed: Serious (operational risk)

### 4. Shell Command Injection Surface — FIXED

**Original gap:** `regtest_exec()` constructed shell commands via `snprintf` and passed
them to `popen()`. A malicious bitcoind RPC response containing shell metacharacters
could inject commands.

**Fix:** On POSIX systems, `popen()` replaced with `fork()/pipe()/execvp()` which
passes arguments directly to the kernel with no shell interpretation. Input sanitizer
retained as defense-in-depth. Non-POSIX fallback to `popen()` with sanitizer.

**Files:** `src/regtest.c`

---

## Additional Hardening (beyond original audit)

These items were not in the original audit but were added as part of mainnet hardening:

### 5. Connection Rate Limiting

Per-IP sliding-window rate limiting with configurable concurrent handshake cap.
Prevents connection flooding DoS attacks against the LSP.

**Files:** `src/rate_limit.c`, `include/superscalar/rate_limit.h`, `src/lsp.c`

### 6. BOLT #2 HTLC Capacity

`MAX_HTLCS` increased from 32 to 483 (BOLT #2 standard). Dynamic array growth from
`DEFAULT_HTLCS_CAP=64` prevents stack overflow. All 13 stack-allocated HTLC arrays
across 5 files converted to heap allocations.

**Files:** `include/superscalar/channel.h`, `src/channel.c`, `src/lsp_channels.c`,
`src/lsp_demo.c`, `src/lsp_bridge.c`, `src/watchtower.c`

### 7. Mainnet Codepath Coverage

Unit tests added for `strcmp(network, "mainnet")` branches in CLI prefix building
and scan depth configuration. These codepaths were previously untested in CI.

**Files:** `tests/test_reconnect.c`

---

## Verified Non-Issues

The following items from the initial audit were investigated and found to be
properly handled:

- **Channel commitment storage**: Dynamic arrays (malloc/realloc) with no upper
  bound. Channels grow storage as needed — no fixed limit, no forced rotation.

- **NN handshake fallback**: Intentional design — NK authentication works when
  `--lsp-pubkey` is provided. NN fallback prints explicit stderr warning.
  Clients choose their security posture.

- **Satoshi overflow**: `channel_update()` at `channel.c` has proper
  bounds checks before arithmetic. Coin selection amounts are bounded by
  Bitcoin's 21M BTC supply (~51 bits), well within uint64_t range.

---

## By-Design Tradeoffs (not gaps)

These are architectural choices inherent to SuperScalar, not missing features:

- **No onion routing** — hub-and-spoke by design; cross-factory via CLN bridge
- **No BOLT #7 gossip** — off-chain channels use synthetic SCIDs + route hints
- **JSON wire protocol** — TLV codec ready, migration is incremental
- **BOLT #11 encoding** — correctly delegated to CLN
