# Changelog

All notable changes to SuperScalar are documented here.

## 0.1.2 — 2026-03-05

### Fixed

- **Cooperative close now works from daemon mode**: The CLI `close` command previously set the shutdown flag which caused Phase 5 to abort instead of running the cooperative close ceremony. The close transaction is now properly built, signed (MuSig2), and broadcast.
- **Client reconnection after crash**: Restarting a client process with `--db` now correctly detects persisted factory state and sends `MSG_RECONNECT` (0x48) instead of `MSG_HELLO` (0x01). Previously, `first_run` was hardcoded to 1 on every process start, causing the LSP to reject the reconnecting client.
- **Consistent 0-indexed client numbering in payment logs**: `lsp_demo.c` payment log now uses 0-indexed client numbers, matching the CLI `pay` command and daemon HTLC logs.
- **Post-reconnect payments work**: Both local per-commitment secrets (PCS) and remote per-commitment points (PCPs) are now persisted on every `REVOKE_AND_ACK` and restored during reconnect. Previously, neither persist function was called. After reconnect the client generated new random PCS that didn't match the PCPs the LSP had stored, causing commitment signature verification to fail on both sender and dest sides. Initial PCS (from factory creation) are also persisted.
- **CLN plugin BOLT11 invoice creation**: Switched `lightning-cli invoice` from fragile positional arguments to `-k` keyword mode, skipping the `fallbacks` parameter entirely. Also made `cli_cmd()` LIGHTNING_DIR handling robust across CLN versions (detects known network names instead of unconditionally splitting the path). Plugin logging now uses CLN's JSON-RPC `log` notification so errors appear in CLN's log file instead of being silently lost on stderr.
- **Bridge LSP reconnection**: Bridge now retries up to 12 times with exponential backoff (2s/5s/10s) instead of exiting on first reconnection failure. Previously, if the LSP restarted and wasn't ready within milliseconds, the bridge process would exit.
- **Payment state persistence**: All payment paths — internal CLI (`pay`), bridge inbound (`MSG_BRIDGE_ADD_HTLC`), and bridge outbound (`MSG_BRIDGE_PAY_RESULT`) — now persist channel balance, commitment number, PCS, PCP, and HTLC state after each commitment exchange. Previously, none of the three paths called `persist_update_channel_balance()`, so killing the LSP after any payment caused irreconcilable commitment number mismatches on reconnect (`client=4, lsp=0`). The bridge fulfill path also now waits for `REVOKE_AND_ACK` and processes revocation (watchtower, bidirectional revocation) instead of fire-and-forget.
- **Client daemon reconnect on disconnect**: Client daemon loop now signals disconnect (`return 0`) when `wire_recv` fails, causing `main()` to retry via reconnect. Previously, the disconnect path fell through to the cooperative close ceremony on a dead socket, which blocked or failed, and the client would exit instead of retrying.
- **Client survives factory rotation**: After rotation, the client now disconnects cleanly and reconnects from persisted state instead of continuing in the same daemon loop with replaced factory/channel objects. The rotation persist block also now saves initial PCS and remote PCPs for the new channel, preventing post-rotation reconnect failures. Also fixed a segfault where `watchtower_clear_entries()` freed the channels array but left `channels_cap` non-zero, causing `watchtower_set_channel()` to write through NULL.
- **Regtest test script FIFO reliability**: `regtest_full.sh` now uses a persistent file descriptor (`exec 3>/tmp/lsp_fifo`) instead of `cat /tmp/lsp_fifo | ...`, which broke when each write opened and closed the FIFO causing the LSP to see EOF.
- **Demo payment 4 below dust limit**: The 2-client demo sequence sent 500 sats in payment 4, which is below the 546-sat P2TR dust limit. Bumped to 600. Also fixed two regtest script payments that used 500 sats (post-LSP-crash and post-BIP39-recovery tests).

### Testing

- **Manual flag tests expanded to 25**: Added 10 new tests covering 1-client factory, variable funding amounts (50k/200k/500k), DW configuration (states-per-layer, step-blocks), profit-shared economics, backup/restore cycle, no-JIT mode, all 3 placement modes, BIP39 mnemonic generation, and JSON report validation.
- **Removed redundant test scripts**: Deleted `regtest_extended.sh`, `testnet4_full.sh`, and `verify_onchain.sh` — all genuinely new test coverage integrated into `manual_tests.py`, redundant orchestrator wrappers and duplicate tests eliminated.

### Performance

- **DB write batching**: Per-payment persist calls (PCS, PCP, balance, HTLC) are now batched into a single SQLite transaction per side (sender and dest), reducing fsyncs from ~9 to 3 per internal payment.
- **Bridge buffered reads**: `bridge_read_plugin_line()` now reads 4KB chunks instead of 1 byte at a time, reducing syscalls by ~1000x per JSON message from the CLN plugin.
- **Plugin send/recv lock separation**: CLN plugin uses a dedicated `send_lock` for `sendall()` instead of the shared `lock`, so bridge reads and writes no longer block each other.
- **BRIDGE_MAX_PENDING 32→256**: In-flight inbound HTLCs from CLN raised to match BOLT #2 capacity, removing a hard bottleneck for burst inbound traffic.

### Test Count

415 unit + 43 regtest = 458 automated + 25 manual flag tests + 23 orchestrator scenarios.

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
