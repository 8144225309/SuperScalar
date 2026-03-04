# Changelog

All notable changes to SuperScalar are documented here.

## Unreleased

### Security

- **PBKDF2 backup encryption**: Backup files now use PBKDF2-HMAC-SHA256 with 600,000 iterations instead of single-pass HKDF. V1 backups (`SSBK0001`) are still auto-detected and readable. New backups use v2 format (`SSBK0002`).
- **BIP39 mnemonic support**: Generate 12/24-word seed phrases for deterministic key recovery. `--generate-mnemonic` and `--from-mnemonic` flags on both LSP and client binaries. BIP32 derivation path `m/1039'/0'/0'`.
- **Shell-free subprocess execution**: `popen()` replaced with `fork()/execvp()` on POSIX systems, eliminating shell interpretation of bitcoin-cli arguments. Input sanitizer retained as defense-in-depth.
- **Connection rate limiting**: Per-IP sliding-window rate limiter with configurable concurrent handshake cap (`--max-conn-rate`, `--max-handshakes`).

### Changed

- **MAX_HTLCS raised to 483**: BOLT #2 standard capacity (was 32). Dynamic array growth from initial allocation of 64, with all stack-allocated HTLC arrays across 5 files converted to heap.
- **Mainnet codepath coverage**: Unit tests added for `strcmp(network, "mainnet")` branches in CLI prefix building and scan depth configuration.

### Added

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
