# Changelog

All notable changes to SuperScalar are documented here.

## 0.1.2 — 2026-03-05

### Fixed

- **Cooperative close now works from daemon mode**: The CLI `close` command previously set the shutdown flag which caused Phase 5 to abort instead of running the cooperative close ceremony. The close transaction is now properly built, signed (MuSig2), and broadcast.
- **Client reconnection after crash**: Restarting a client process with `--db` now correctly detects persisted factory state and sends `MSG_RECONNECT` (0x48) instead of `MSG_HELLO` (0x01). Previously, `first_run` was hardcoded to 1 on every process start, causing the LSP to reject the reconnecting client.
- **Consistent 0-indexed client numbering in payment logs**: `lsp_demo.c` payment log now uses 0-indexed client numbers, matching the CLI `pay` command and daemon HTLC logs.
- **Post-reconnect payments work**: Remote per-commitment points are now persisted on every `REVOKE_AND_ACK` and restored during reconnect. Previously, the persist functions existed but were never called, leaving the PCP ring buffer empty after reconnect — the channel couldn't verify commitment signatures, so payments silently failed.
- **CLN plugin BOLT11 invoice creation**: Fixed `fallbacks` argument passed to `lightning-cli invoice` from `"null"` (invalid string) to `"[]"` (empty JSON array). CLN v25+ rejected the malformed argument, resulting in empty BOLT11 strings for bridge-routed payments.

### Test Count

415 unit + 43 regtest = 458 total (unchanged).

---

## 0.1.1 — 2026-03-04

### Security

- **RBF on penalty transactions**: Penalty and HTLC timeout/success transactions now signal BIP125 Replace-By-Fee (`nSequence = 0xFFFFFFFD`) so fee bumps can be broadcast if the initial penalty is stuck in the mempool.
- **Zero-sat output guards**: Penalty and HTLC sweep transactions bail out when the output amount falls below the 546-sat dust limit, preventing invalid transactions.
- **CLTV cap vs factory timeout**: `lsp_validate_cltv_for_forward()` now rejects HTLCs whose `cltv_expiry` meets or exceeds the factory's own timeout — prevents funds from being trapped when the factory expires.
- **Watchtower HTLC timeout auto-sweep**: New `WATCH_FORCE_CLOSE` entry type enables the watchtower to automatically broadcast HTLC timeout transactions once `cltv_expiry` is reached after a force close.
- **Enforce `--db` on mainnet**: LSP and client binaries now refuse to start on mainnet without `--db`, preventing loss of revocation secrets on crash.

### Added

- Linux ARM64 (Raspberry Pi) prebuilt binaries in releases
- Dashboard screenshot in README
- Bitcoin donation address and Support section in README
- Release workflow: manual dispatch via `workflow_dispatch` (re-trigger without recreating release)

### Fixed

- Release workflow: ARM64 builds via QEMU emulation (replaces flaky cross-compile)
- Release workflow: `--clobber` flag for re-run asset replacement
- FUNDING.yml: use HTTPS URL for GitHub Sponsor button rendering

### Test Count

415 unit + 43 regtest = 458 total (unchanged from 0.1.0).

---

## 0.1.0 — 2026-03-04

First tagged release. Ready for signet/testnet collaborative testing.

### Security

- **PBKDF2 backup encryption**: Backup files now use PBKDF2-HMAC-SHA256 with 600,000 iterations instead of single-pass HKDF. V1 backups (`SSBK0001`) are still auto-detected and readable. New backups use v2 format (`SSBK0002`).
- **BIP39 mnemonic support**: Generate 12/24-word seed phrases for deterministic key recovery. `--generate-mnemonic` and `--from-mnemonic` flags on both LSP and client binaries. BIP32 derivation path `m/1039'/0'/0'`.
- **Shell-free subprocess execution**: `popen()` replaced with `fork()/execvp()` on POSIX systems, eliminating shell interpretation of bitcoin-cli arguments. Input sanitizer retained as defense-in-depth.
- **Connection rate limiting**: Per-IP sliding-window rate limiter with configurable concurrent handshake cap (`--max-conn-rate`, `--max-handshakes`).
- **factory_set_funding() bounds check**: Prevents buffer overflow if scriptPubKey exceeds 34-byte buffer.
- **tx_buf OOM safety**: Sticky `oom` flag prevents heap buffer overflow on `realloc()` failure — all write functions bail out instead of writing past the buffer.
- **SQLite PRAGMA error checking**: `persist_open()` now verifies `journal_mode=WAL`, `synchronous=FULL`, and `foreign_keys=ON` all succeed — previously failures were silently discarded.
- **simulate_tree() stack guard**: Bounds check prevents stack overflow in tree simulation.
- **Bidirectional MSG_ERROR**: Client sends error on ceremony failures; LSP checks for MSG_ERROR at all 6 reception points (4 ceremony steps, daemon loop, reconnect).

### Changed

- **MAX_HTLCS raised to 483**: BOLT #2 standard capacity (was 32). Dynamic array growth from initial allocation of 64, with all stack-allocated HTLC arrays across 5 files converted to heap.
- **Mainnet codepath coverage**: Unit tests added for `strcmp(network, "mainnet")` branches in CLI prefix building and scan depth configuration.
- **LeakSanitizer enabled in CI**: Sanitizer build now runs with `detect_leaks=1` (was disabled globally).

### Added

- `include/superscalar/version.h` — version string (`SUPERSCALAR_VERSION`)
- `--version` flag on all 4 binaries (LSP, client, bridge, watchtower)
- `src/bip39.c`, `include/superscalar/bip39.h` — BIP39 mnemonic implementation
- `src/bip39_wordlist.h` — 2048-word English wordlist
- `src/rate_limit.c`, `include/superscalar/rate_limit.h` — connection rate limiting
- `tests/test_bip39.c` — 10 tests including official TREZOR vectors
- `tests/test_rate_limit.c` — 4 tests for rate limiter
- `SECURITY.md` — responsible disclosure policy
- `CHANGELOG.md` — this file

### Test Count

415 unit + 43 regtest = 458 total (was 394 unit + 43 regtest = 437).

---

## Prior Development

SuperScalar was developed as a research prototype implementing ZmnSCPxj's SuperScalar design for Bitcoin Lightning channel factories. Major milestones before changelog tracking:

- Decker-Wattenhofer state machine with multi-layer counter
- MuSig2 distributed signing (2-round N-of-N ceremony, nonce pools)
- Timeout-sig-trees with CLTV script-path fallback
- Poon-Dryja payment channels with HTLCs at leaf outputs
- Noise NK encrypted transport with Tor hidden service support
- SQLite persistence (27 tables) with crash recovery
- CLN bridge for Lightning Network interoperability
- Client + LSP + standalone watchtowers
- PTLC key turnover via adaptor signatures
- Factory ladder rotation (zero-downtime)
- Web dashboard, interactive CLI, JSON diagnostic reports
- 7-job CI: Linux, macOS, sanitizers, cppcheck, regtest, coverage, fuzz
