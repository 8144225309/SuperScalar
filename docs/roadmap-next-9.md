# Roadmap: Next 9 — Engineering Plan for Production Readiness

Point-in-time snapshot from 2026-02-27 at commit `7b3c064`.

**Current state:** 319 unit + 41 regtest + 20 orchestrator = 380 tests, all green.
CI green on Linux + macOS + sanitizers + cppcheck + regtest integration.

This document covers the next 9 items on the roadmap, each with context,
current state, design decisions, implementation plan, and verification
criteria. Items are ordered by dependency and value.

---

## Table of Contents

1. [Signet Smoke Test](#1-signet-smoke-test)
2. [Fuzz Testing](#2-fuzz-testing)
3. [Coverage Measurement](#3-coverage-measurement)
4. [Bridge End-to-End](#4-bridge-end-to-end)
5. [Property-Based Testing](#5-property-based-testing)
6. [Tor Full Integration](#6-tor-full-integration)
7. [Multi-Hop Routing](#7-multi-hop-routing)
8. [Pre-Built Release Binaries](#8-pre-built-release-binaries)
9. [Signet Long-Running Test](#9-signet-long-running-test)

---

## 1. Signet Smoke Test

### Current State

The codebase has **full signet support** baked into every layer:

- `regtest_t` struct carries `network` field ("regtest", "signet", "testnet", "mainnet")
- LSP auto-adjusts `active_blocks` (4,320 for signet vs 20 for regtest),
  `dying_blocks` (432 vs 10), `confirm_timeout` (7,200s vs 3,600s)
- Orchestrator has signet timing constants (`factory_timeout=900s`,
  `lsp_timeout=1800s`, poll every 15s for natural blocks)
- Mining guard: `regtest_mine_blocks()` returns 0 on non-regtest (prevents
  accidental signet mining)
- Two substantial scripts exist: `tools/signet_setup.sh` (~1,200 lines) and
  `tools/signet_diagnose.sh` (~800 lines)
- `SIGNET_GAPS.md` tracks 11 gaps; all Tier 1 (crash/funds-loss) are closed

### What's Missing

No CI job runs on signet. The `cooperative_close` scenario has never been
verified with real 10-minute block intervals. The orchestrator's
`advance_chain()` polls `getblockcount` on non-regtest but this path is
untested.

### Design

**Approach:** GitHub Actions scheduled workflow (weekly or manual dispatch).
Uses a persistent signet wallet pre-funded via faucet. Runs the
`cooperative_close` scenario with `--network signet`.

**CI job structure:**
```yaml
signet-smoke:
  runs-on: ubuntu-latest
  timeout-minutes: 90
  steps:
    - Build SuperScalar
    - Download + start Bitcoin Core with signet
    - Load pre-funded wallet (encrypted backup in repo secrets)
    - python3 test_orchestrator.py --scenario cooperative_close --network signet
```

**Key decisions:**
- Weekly schedule avoids burning faucet funds (each run costs ~50,000 sats)
- `cooperative_close` is the simplest scenario — factory create, payments,
  close — and exercises the real block-timing path
- Wallet backup encrypted with GitHub repository secret
- 90-minute timeout accommodates 2-3 signet blocks

### Verification

- CI job passes on manual dispatch
- Factory creation confirmed on signet (real txid in explorer)
- Cooperative close confirmed (real txid)
- Orchestrator logs show signet timing (15s polls, not instant mining)

---

## 2. Fuzz Testing [DONE]

### Current State

**Zero fuzz infrastructure.** No harnesses, no AFL/libFuzzer integration, no
fuzz corpus. The only fuzzing-adjacent tests are 4 wire edge-case tests
(oversized frame, truncated header/body, zero-length frame).

### Attack Surface Analysis

The primary attack surface is network-facing wire protocol parsing. All
incoming data flows through:

```
TCP bytes → wire_recv() → length decode → [AEAD decrypt] → cJSON_Parse() → wire_parse_*()
```

**Priority fuzz targets (by attack surface):**

| Priority | Target | File:Line | Why |
|----------|--------|-----------|-----|
| 1 | `wire_recv()` | wire.c:353 | Entry point for all network data |
| 2 | `wire_parse_*()` (30+ functions) | wire.c:720-1517 | JSON → binary decoders |
| 3 | `wire_parse_bundle()` | wire.c:1492 | Generic array parser for nonce/psig |
| 4 | `compute_taproot_sighash()` | tx_builder.c:128 | Hardcoded tx offsets (line 169: `out_start=46`) |
| 5 | `persist_load_factory()` | persist.c:490 | Reconstructs factory from SQLite |
| 6 | `persist_load_channel_state()` | persist.c:672 | Loads balances + commitment |
| 7 | AEAD decrypt | crypto_aead.c | Hand-rolled ChaCha20-Poly1305 |
| 8 | `hex_decode()` | util.c | Foundation of all binary parsing |

### Design

**Framework:** libFuzzer (built into clang). Rationale:
- Zero external dependencies (clang ships with it)
- Integrates with ASan/UBSan (already in CMake)
- Corpus can be seeded from existing test data
- Compatible with OSS-Fuzz for future public fuzzing

**Directory structure:**
```
fuzz/
  fuzz_wire_recv.c        — Target 1: raw frame bytes → wire_recv()
  fuzz_wire_parse_json.c  — Target 2: arbitrary JSON → each wire_parse_*()
  fuzz_tx_sighash.c       — Target 3: raw tx buffer → compute_taproot_sighash()
  fuzz_persist_load.c     — Target 4: malformed SQLite → persist_load_factory()
  fuzz_hex_decode.c       — Target 5: arbitrary strings → hex_decode()
  corpus/                 — Seed inputs from test runs
```

**CMake integration:**
```cmake
option(ENABLE_FUZZING "Build fuzz targets with libFuzzer" OFF)
if(ENABLE_FUZZING)
    # Each fuzz target is a standalone executable
    add_executable(fuzz_wire_recv fuzz/fuzz_wire_recv.c)
    target_link_libraries(fuzz_wire_recv superscalar ...)
    target_compile_options(fuzz_wire_recv PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_wire_recv PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
```

**Harness pattern (fuzz_wire_recv.c):**
```c
#include "superscalar/wire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a socketpair, write fuzz data to one end
    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    write(fds[1], data, size);
    close(fds[1]);

    // Try to parse — should never crash, regardless of input
    wire_msg_t msg = {0};
    wire_recv(fds[0], &msg);
    if (msg.json) cJSON_Delete(msg.json);
    close(fds[0]);
    return 0;
}
```

**CI integration:**
```yaml
fuzz:
  runs-on: ubuntu-latest
  steps:
    - apt install clang
    - cmake -DENABLE_FUZZING=ON -DCMAKE_C_COMPILER=clang
    - make fuzz_wire_recv fuzz_wire_parse_json ...
    - timeout 300 ./fuzz_wire_recv corpus/wire_recv/
    - timeout 300 ./fuzz_wire_parse_json corpus/wire_parse/
```

5-minute fuzz runs on each PR catch regressions. Longer runs (1+ hour) on
weekly schedule.

### Verification

- `cmake -DENABLE_FUZZING=ON && make` builds all fuzz targets
- Each target runs for 60s without crashes
- Any crash found produces a minimized reproducer in `corpus/`
- CI job runs 5-minute fuzz on every PR

---

## 3. Coverage Measurement [DONE]

### Current State

**Zero coverage instrumentation.** No `--coverage` flags, no lcov config, no
CI coverage step. We have 380 tests but no visibility into which code paths
they miss.

### Design

**Tool:** gcov + lcov (standard for C projects, free, works with gcc).

**CMake option:**
```cmake
option(ENABLE_COVERAGE "Enable gcov coverage instrumentation" OFF)
if(ENABLE_COVERAGE)
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
endif()
```

**Workflow:**
```bash
cmake -DENABLE_COVERAGE=ON ..
make -j$(nproc)
./test_superscalar --unit    # generates .gcda files
./test_superscalar --regtest # more .gcda files
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '*/build/_deps/*' '/usr/*' --output-file filtered.info
genhtml filtered.info --output-directory coverage_report/
```

**CI integration:**
```yaml
coverage:
  runs-on: ubuntu-latest
  steps:
    - apt install lcov
    - cmake -DENABLE_COVERAGE=ON
    - make && ctest
    - lcov --capture ...
    - Upload coverage_report/ as artifact
    - Optional: codecov.io or coveralls upload
```

**Coverage targets (realistic baselines):**
- Wire protocol: >90% line coverage (heavily tested)
- Persistence: >85% (many load/save round-trip tests)
- Factory/channel: >80% (complex state machines)
- Tor: >60% (SOCKS5 mock exists but no live daemon tests)
- tx_builder: >70% (serialization covered, sighash partially)

### Verification

- `cmake -DENABLE_COVERAGE=ON && make && ctest` generates coverage data
- `genhtml` produces browsable HTML report
- CI uploads report as artifact on every push
- Coverage numbers match expected baselines (no surprise dead code)

---

## 4. Bridge End-to-End [DONE]

### Current State

The bridge has **strong unit coverage** (18 tests in test_bridge.c) including:
- Message round-trip for all 8 bridge message types
- Invoice registry lookup
- Full inbound and outbound HTLC flows (in-process)
- NK Noise handshake over real TCP (regtest fork test)
- HTLC timeout enforcement
- Complete regtest bridge payment (factory + bridge HTLC + fulfill)

A comprehensive integration test script exists at
`tools/test_bridge_regtest.sh` (479 lines) that:
1. Starts bitcoind regtest
2. Starts 2 CLN nodes with the plugin
3. Opens a CLN channel between them
4. Creates a SuperScalar factory + bridge
5. Registers invoice, sends payment, verifies completion

**What's missing:** This script is not in CI and has never been run
automatically. It requires CLN binaries which are not in the CI environment.

### Design

**Approach:** Docker-based CI job with CLN + Bitcoin Core + SuperScalar.

**Docker image for bridge testing:**
```dockerfile
FROM ubuntu:24.04
# Bitcoin Core 28.1 + CLN latest stable
# Build SuperScalar
# Run test_bridge_regtest.sh
```

**Alternative (lighter):** Add CLN binary download to the CI workflow, similar
to how Bitcoin Core is downloaded for regtest tests. CLN releases provide
pre-built binaries.

**Key test paths to verify:**
1. Inbound: external CLN payment → bridge → LSP → factory client fulfills
2. Outbound: factory client pays bolt11 → bridge → CLN → external node receives
3. Timeout: HTLC expires → fail-back through bridge → CLN resolves
4. Reconnect: bridge disconnects from LSP, reconnects, pending HTLCs resume

### Verification

- `test_bridge_regtest.sh` passes in CI
- Inbound payment confirmed (preimage matches)
- Outbound payment confirmed (CLN node 2 balance increases)
- HTLC timeout test: expired HTLC is failed back correctly
- CI runs this on every PR (or weekly if too slow)

---

## 5. Property-Based Testing [DONE]

### Current State

**Zero property-based testing.** All tests use hand-crafted inputs. The DW
state machine and MuSig2 signing have extensive unit tests but only with
specific, deterministic test vectors.

### Design

**Framework:** Custom C-based random testing (no external dependency).
Rationale: the codebase is pure C with no Python dependencies for core
testing. Adding `hypothesis` would require Python test wrappers. Instead,
use the existing C test framework with random seed generation.

**Properties to test:**

| Property | Domain | Invariant |
|----------|--------|-----------|
| DW state round-trip | Random epoch sequences | `advance(N) → serialize → deserialize → state == original` |
| MuSig2 sign-verify | Random messages × random keys | `sign(msg, keys) → verify(msg, agg_pubkey, sig) == true` |
| Channel balance conservation | Random payment sequences | `local + remote == initial_total` after any sequence of add/fulfill/fail |
| Factory tree construction | Random N (2-16), random amounts | Tree always has exactly `2N-1` nodes, leaf sum equals funding |
| Shachain derivation | Random indices | `derive(seed, i) ⊕ derive(seed, j)` are distinct for `i ≠ j` |
| Persistence round-trip | Random factory params | `save(factory) → load(factory) → compare == identical` |
| Wire hex encode/decode | Random binary data | `hex_encode(data) → hex_decode(hex) == data` |
| Tapscript construction | Random pubkeys | Output script is valid P2TR, controlblock verifies |

**Implementation pattern:**
```c
int test_channel_balance_conservation_property(void) {
    srand(42); // deterministic seed for reproducibility
    for (int trial = 0; trial < 1000; trial++) {
        uint64_t initial = 100000 + (rand() % 900000);
        // ... create channel, random payment sequence
        // ... assert local + remote == initial after every operation
    }
    return 1;
}
```

**Adding to test suite:**
- New file: `tests/test_property.c`
- Register in CMakeLists.txt and test_main.c
- ~8-12 property tests, each running 1000 random trials
- Deterministic seed means failures are reproducible

### Verification

- All property tests pass with seed=42
- Re-running with different seeds (43, 44, ...) also passes
- Any failure prints the exact seed + trial number for reproduction
- Added to `--unit` test suite (increases unit count by ~10)

---

## 6. Tor Full Integration [DONE]

### Current State

The Tor implementation is **architecturally sound** and pattern-matches
Bitcoin Core's approach in several key ways:

**What's already right (matching Bitcoin Core):**

| Bitcoin Core | SuperScalar | Status |
|-------------|-------------|--------|
| `-proxy=HOST:PORT` | `--tor-proxy HOST:PORT` | Implemented |
| DNS leak prevention | SOCKS5 ATYP=3 (domainname, not IP) | Implemented + tested |
| .onion without proxy = refuse | `wire_connect()` hard-fails with warning | Implemented + tested |
| Proxy set = all traffic routed | `wire_connect()` routes everything through SOCKS5 | Implemented |
| Ephemeral v3 hidden service | `--onion` creates ED25519-V3 via ADD_ONION | Implemented |
| Control port auth injection guard | Rejects `"`, `\`, `\r`, `\n` in password | Implemented |

**What's missing (gaps vs Bitcoin Core):**

| Bitcoin Core Feature | SuperScalar Gap | Priority |
|---------------------|-----------------|----------|
| `-onlynet=onion` | No Tor-only mode — can't refuse clearnet | High |
| `-bind=127.0.0.1` | No listen-address restriction with `--onion` | Medium |
| SOCKS5 username/password auth | NO_AUTH only (method 0x00) | Low |
| Tor password from config file | `--tor-password` is in argv (visible in `/proc`) | Medium |
| Stream isolation | No per-connection SOCKS5 credentials | Low |
| `-nolisten` | No way to disable incoming connections | Low |

### Design: Tor Safety Model

**Principle:** Tor is off by default. When enabled, it must be impossible to
accidentally leak identifying information. The user should not need to
understand SOCKS5 internals to be safe.

**New flags:**

| Flag | Effect | Default |
|------|--------|---------|
| `--tor-only` | Refuse all non-.onion outbound connections | Off |
| `--bind ADDRESS` | Restrict listen address (use `127.0.0.1` with `--onion`) | `0.0.0.0` |
| `--tor-password-file PATH` | Read control port password from file instead of argv | None |

**Implementation of `--tor-only`:**
```c
// In wire.c, add a global flag:
static int g_tor_only = 0;

void wire_set_tor_only(int enable) { g_tor_only = enable; }

int wire_connect(const char *host, int port) {
    // ... existing .onion guard ...

    // NEW: refuse non-.onion in tor-only mode
    if (g_tor_only && !is_onion) {
        fprintf(stderr, "wire_connect: --tor-only mode refuses clearnet "
                        "connection to %s:%d\n", h, port);
        return -1;
    }
    // ... rest of existing logic
}
```

**Implementation of `--bind`:**
```c
// In superscalar_lsp.c, pass bind_addr to wire_listen():
// Currently: wire_listen("0.0.0.0", port)
// With --bind: wire_listen(bind_addr, port)
// With --onion and no --bind: auto-set bind_addr = "127.0.0.1"
if (tor_onion && !bind_addr_set) {
    bind_addr = "127.0.0.1";
    fprintf(stderr, "Note: --onion without --bind defaults to 127.0.0.1 "
                    "(use --bind 0.0.0.0 to override)\n");
}
```

**Implementation of `--tor-password-file`:**
```c
// Read first line of file, strip newline, use as tor_password
FILE *f = fopen(tor_password_file, "r");
if (!f) { fprintf(stderr, "Cannot read %s\n", tor_password_file); exit(1); }
fgets(tor_password, sizeof(tor_password), f);
tor_password[strcspn(tor_password, "\r\n")] = 0;
fclose(f);
```

### Testing Plan

**Unit tests (no Tor daemon needed):**
1. `test_tor_only_refuses_clearnet` — set tor-only, try clearnet connect, verify -1
2. `test_tor_only_allows_onion` — set tor-only + proxy, try .onion, verify routes through proxy
3. `test_bind_localhost_only` — `wire_listen("127.0.0.1", port)`, verify external connect refused
4. `test_password_file_read` — write temp file, read via tor_password_file path
5. `test_password_file_missing` — nonexistent file, verify graceful error

**Docker integration test (with real Tor daemon):**
```dockerfile
FROM ubuntu:24.04
RUN apt install tor bitcoind
# Configure Tor with ControlPort 9051, CookieAuthentication 0, HashedControlPassword
# Start Tor, start bitcoind regtest
# Run: superscalar_lsp --onion --tor-proxy 127.0.0.1:9050 --tor-control 127.0.0.1:9051
# Verify: .onion address printed, client connects through Tor
```

**Test scenarios:**
1. LSP creates hidden service, client connects through Tor proxy → factory created
2. `--tor-only` mode: client refuses to connect to clearnet IP
3. `--bind 127.0.0.1` with `--onion`: external connection attempt refused
4. Password file: control port auth works with file-based password

### Verification

- 5 new unit tests pass in `--unit` suite
- Docker integration creates real .onion address
- Client connects through SOCKS5 proxy to .onion
- Factory creation + cooperative close works over Tor
- `--tor-only` correctly refuses clearnet connections

---

## 7. Multi-Hop Routing [DONE — bridge reliability only; full multi-hop deferred]

### Current State

The codebase supports **exactly one external hop** via the CLN bridge:

```
External LN → CLN node → cln_plugin.py → bridge daemon → LSP → factory client
```

And the reverse:

```
Factory client → LSP → bridge → cln_plugin.py → CLN node → External LN
```

Intra-factory routing (client → LSP → client) is fully implemented with
routing fee deduction.

### Architecture

Multi-hop across SuperScalar factories is a **protocol-level feature**, not
just a testing gap. The current design assumes a single LSP with direct
bridge connectivity. True multi-hop would require:

1. **Route finding:** Currently no gossip protocol. The LSP only knows its
   own factory clients. Each factory is a private graph.

2. **Onion routing:** HTLCs carry plaintext `dest_client` or `bolt11`.
   Multi-hop requires onion packet construction (SPHINX) so intermediate
   nodes can't see the final destination.

3. **Cross-LSP forwarding:** No mechanism for one SuperScalar LSP to
   forward to another. Would need an HTLC forwarding protocol between LSPs.

4. **Channel announcements:** Factory channels are private. Multi-hop
   requires route hints or BOLT12 offers with factory routing information.

5. **Invoice encoding:** No BOLT11/BOLT12 invoice generation that encodes
   SuperScalar factory routing hints.

### Design Decision

**The production path does NOT build custom multi-hop.** Instead, the design
(documented in `docs/design-production-roadmap.md`) replaces the custom
channel/routing stack with CLN/LDK/LND:

- **Keep:** Factory tree + MuSig2 + PTLC + DW state machine (core innovation)
- **Replace:** HTLC forwarding, commitment transactions, routing → base node
- **Result:** Multi-hop comes "for free" from the base node's gossip/pathfinding

The bridge architecture is the transitional mechanism. In production, the
SuperScalar protocol becomes a CLN plugin or LDK module that manages factory
lifecycle while delegating routing to the base node.

### What We Build Now

Instead of full multi-hop, we improve the **bridge reliability** to make the
single-hop path production-grade:

1. Bridge reconnection with pending HTLC recovery
2. Bridge heartbeat (detect stale connections)
3. Concurrent HTLC stress test (current max: 32 pending)
4. Bridge metrics (latency, throughput, failure rate)

### Verification

- Bridge reconnection test: kill bridge mid-HTLC, restart, HTLC resolves
- 32 concurrent inbound HTLCs: all complete without deadlock
- Bridge heartbeat: stale connection detected within 30s
- Documented in design doc: multi-hop deferred to base-node integration

---

## 8. Pre-Built Release Binaries

### Current State

**Zero release automation.** No GitHub Releases, no binary packaging, no
version tagging. CI builds on Linux + macOS but discards artifacts.

### Design

**GitHub Actions release workflow** triggered by version tags:

```yaml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            artifact: superscalar-linux-x86_64
          - os: macos-latest
            artifact: superscalar-macos-x86_64
          - os: macos-14     # ARM runner
            artifact: superscalar-macos-arm64
    steps:
      - Build with -DCMAKE_BUILD_TYPE=Release
      - Strip binaries
      - Package: tar.gz with lsp, client, bridge, README
      - Upload artifact

  release:
    needs: build
    steps:
      - Create GitHub Release from tag
      - Attach all platform archives
      - Generate SHA256SUMS file
```

**Version scheme:** Semantic versioning. `v0.1.0` for first tagged release.
Version embedded in binary via cmake define:
```cmake
execute_process(COMMAND git describe --tags --always OUTPUT_VARIABLE GIT_VERSION)
add_compile_definitions(SUPERSCALAR_VERSION="${GIT_VERSION}")
```

**Package contents:**
```
superscalar-v0.1.0-linux-x86_64.tar.gz
├── superscalar_lsp
├── superscalar_client
├── superscalar_bridge
├── tools/demo.sh
├── tools/run_demo.sh
├── README.md
└── LICENSE
```

**Dependencies for end users:**
- Linux: `libsqlite3-0` (runtime only)
- macOS: nothing (SQLite bundled with OS)
- Bitcoin Core 28.x must be installed separately

### Verification

- `git tag v0.1.0 && git push --tags` triggers release workflow
- Three platform archives uploaded to GitHub Releases
- SHA256SUMS matches each archive
- Downloaded binary runs `superscalar_lsp --help` on clean machine
- Binaries are stripped (no debug symbols, <5MB each)

---

## 9. Signet Long-Running Test

### Current State

The signet smoke test (item 1) verifies a single factory lifecycle. A
long-running test would keep a factory alive through multiple rotation
cycles, exercising:
- Real CLTV timeout enforcement (~30-day active window)
- Real block-timing for DYING → rotation transitions
- Factory ladder management (ACTIVE + DYING concurrently)
- JIT channel fallback when factory expires

### Design

**Approach:** Dedicated signet instance running continuously. NOT in CI
(runs for days/weeks). Instead, a monitoring script that:
1. Creates Factory 0 with short `active_blocks` (144 = ~1 day)
2. Monitors block height vs factory CLTV
3. Triggers rotation when DYING threshold reached
4. Verifies Factory 1 created, Factory 0 closed
5. Repeats for 3+ rotation cycles
6. Reports results to dashboard

**Infrastructure:**
- VPS or dedicated machine running bitcoind signet + SuperScalar
- Dashboard (`tools/dashboard.py`) displays factory lifecycle state
- Alert on rotation failure (simple webhook or email)

**Key metrics to track:**
- Time from DYING detection to Factory N+1 creation
- PTLC turnover success rate
- JIT channel trigger count
- Cooperative close success rate per factory
- Total on-chain transaction count per rotation cycle

### Verification

- Factory survives 3+ rotation cycles on signet
- Each rotation creates a new factory and closes the old
- No HTLC timeouts during rotation (clients seamlessly switch)
- Dashboard shows continuous uptime graph
- Total downtime during rotation < 1 block (~10 minutes)

---

## Implementation Priority Matrix

| Item | Effort | Value | Dependencies | Phase |
|------|--------|-------|--------------|-------|
| 1. Signet smoke test | 1 day | High | None | Phase A |
| 2. Fuzz testing | 3 days | Very High | None | Phase A |
| 3. Coverage measurement | 1 day | High | None | Phase A |
| 4. Bridge end-to-end | 3 days | High | CLN binaries | Phase B |
| 5. Property-based testing | 2 days | Medium | None | Phase B |
| 6. Tor full integration | 5 days | Very High | Docker | Phase B |
| 7. Multi-hop routing | N/A | Deferred | Base node integration | Phase C |
| 8. Release binaries | 2 days | High | None | Phase A |
| 9. Signet long-running | Ongoing | Medium | Item 1 | Phase C |

**Phase A (immediate, 1 week):** Items 1, 2, 3, 8 — zero external deps
**Phase B (short-term, 2 weeks):** Items 4, 5, 6 — need CLN/Docker/Tor
**Phase C (long-term):** Items 7, 9 — ongoing or deferred

---

## Tor Safety Design: Pattern-Matching Bitcoin Core

This section documents the privacy and safety model in detail, since Tor
integration is the highest-risk area for user privacy.

### Core Principle: Off By Default, Safe When Enabled

Bitcoin Core's Tor model:
1. Tor is off by default — clearnet connections work normally
2. `-proxy=` routes all traffic through SOCKS5 (Tor or any SOCKS5 proxy)
3. `-onlynet=onion` refuses all non-.onion connections
4. `.onion` addresses always go through proxy (never DNS-resolved locally)
5. `-bind=127.0.0.1` restricts listening to localhost
6. Control port auth from config file (not command line)

SuperScalar's current implementation matches 1-4 exactly. Items 5-6 are the
gaps we close in this roadmap.

### Safety Guarantees (Current)

| Guarantee | How It's Enforced | Test |
|-----------|-------------------|------|
| No DNS leak for .onion | `wire_connect()` hard-fails .onion without proxy | `test_wire_connect_onion_no_proxy` |
| SOCKS5 sends domain, not IP | ATYP=0x03 always used | `test_tor_socks5_mock` validates ATYP byte |
| Proxy routes all traffic | `g_proxy_set` checked before any connect | `wire_connect()` line 222-224 |
| Control port injection blocked | Password chars `"`, `\`, `\r`, `\n` rejected | `tor_create_hidden_service()` line 178-183 |

### Safety Guarantees (Planned)

| Guarantee | How It's Enforced | Test |
|-----------|-------------------|------|
| Tor-only mode | `--tor-only` sets `g_tor_only`; `wire_connect()` refuses clearnet | `test_tor_only_refuses_clearnet` |
| Hidden service binds localhost | `--onion` auto-sets `--bind 127.0.0.1` | `test_bind_localhost_only` |
| Password not in argv | `--tor-password-file` reads from file | `test_password_file_read` |

### What We Explicitly Do NOT Build

- **Stream isolation:** SOCKS5 per-connection auth for Tor circuit isolation.
  Bitcoin Core does this but it's unnecessary for SuperScalar — each process
  makes one long-lived connection, not many short ones.

- **Separate onion proxy:** Bitcoin Core's `-onion=` vs `-proxy=` distinction.
  SuperScalar has one proxy setting that handles both. This is simpler and
  sufficient.

- **`-nolisten`:** Bitcoin Core can disable incoming connections entirely.
  SuperScalar's LSP is a server by design — it must listen. Clients already
  don't listen.

### Deployment Checklist for Tor Users

```bash
# LSP: hidden service + Tor-only
superscalar_lsp \
    --tor-proxy 127.0.0.1:9050 \
    --onion \
    --tor-control 127.0.0.1:9051 \
    --tor-password-file /etc/superscalar/tor_password \
    --tor-only \
    --port 9735 \
    ...

# Client: connect to .onion via Tor
superscalar_client \
    --tor-proxy 127.0.0.1:9050 \
    --host abc123...xyz.onion \
    --port 9735 \
    --lsp-pubkey 02... \
    ...
```

---

## Grant Proposal Talking Points

For reviewers evaluating this project:

1. **380 tests pass** (319 unit + 41 regtest + 20 orchestrator), covering
   factory creation, payments, breach detection, crash recovery, rotation,
   JIT channels, and cooperative close with real Bitcoin transactions.

2. **20 adversarial orchestrator scenarios** test multi-process failure modes
   including LSP crash recovery, client mass departure, PTLC turnover abort,
   and watchtower late detection — all with real Bitcoin Core regtest.

3. **Privacy-safe Tor integration** follows Bitcoin Core's model: off by
   default, DNS leak prevention enforced at the wire layer, SOCKS5 ATYP=3
   (never resolves .onion locally), and .onion connections require explicit
   proxy configuration.

4. **Docker one-command demo** (`docker run superscalar demo`) builds from
   source, starts bitcoind regtest, funds wallet, and runs the full factory
   lifecycle — zero manual setup.

5. **CI on every push:** Linux + macOS + ASan/UBSan + cppcheck static
   analysis + regtest integration with real Bitcoin Core.

6. **Signet-ready:** Full network abstraction, timing constants for real
   block intervals, safety guards against accidental mainnet/signet mining,
   dedicated signet deployment scripts.

7. **Next steps are testing infrastructure** (fuzz, coverage, property
   tests) — not feature work. The protocol is implemented and proven; we're
   hardening for production.
