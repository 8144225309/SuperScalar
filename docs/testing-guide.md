# Testing Guide

How to build, run, and understand the full test suite.

---

## Prerequisites

You need a Linux or macOS machine (or WSL on Windows). Install:

```bash
# Ubuntu / Debian / WSL
sudo apt update
sudo apt install build-essential cmake libsqlite3-dev python3

# macOS
brew install cmake
# (SQLite3 ships with Xcode command line tools)
```

For **regtest integration tests** you also need Bitcoin Core (28.1+):

```bash
# Download from https://bitcoincore.org/en/download/
# Or on Ubuntu:
sudo apt install bitcoind bitcoin-cli

# Verify
bitcoind --version
bitcoin-cli --version
```

---

## Build

```bash
git clone https://github.com/8144225309/SuperScalar.git
cd SuperScalar
mkdir -p build && cd build
cmake .. && make -j$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)
```

CMake auto-fetches two dependencies (secp256k1-zkp and cJSON) so the first
build takes a bit longer. After that, incremental builds are fast.

You should see zero warnings — the project compiles with `-Wall -Wextra -Werror`.

---

## Test Suite Overview

| Category | Count | Needs bitcoind? | What it covers |
|----------|-------|-----------------|----------------|
| Unit tests | 337 | No | Every module in isolation: crypto, state machines, channels, wire protocol, persistence, bridge, Tor SOCKS5, placement, ceremonies, profit settlement, property-based tests |
| Regtest integration | 41 | Yes | Real Bitcoin transactions: factory funding, tree broadcast, payments, cooperative close, bridge payment, NK handshake over TCP, LSP crash recovery, TCP reconnection |
| **Total** | **378** | | |

---

## Running Unit Tests

No bitcoind needed. Just build and run:

```bash
cd build
./test_superscalar --unit
```

Expected output: `Results: 337/337 passed`

These run in ~2 seconds and test every core module: DW state machines,
MuSig2 signing, transaction building, tapscript, factory trees, channels
with HTLCs, penalty construction, wire protocol serialization, SQLite
persistence, watchtower logic, CLN bridge messages, Tor SOCKS5 protocol,
NK-authenticated Noise handshakes, client placement strategies, ceremony
state machines, distributed state advances, and profit settlement.

---

## Running Regtest Tests

Regtest tests create real Bitcoin transactions on a local regtest chain.

### Step 1: Start bitcoind

```bash
bitcoind -regtest -daemon \
  -rpcuser=rpcuser -rpcpassword=rpcpass \
  -fallbackfee=0.00001 -txindex=1
```

Wait a couple seconds for it to start.

### Step 2: Run tests

```bash
cd build
./test_superscalar --regtest
```

Expected output: `Results: 41/41 passed`

### Step 3: Stop bitcoind

```bash
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass stop
```

### Tip: Wipe before re-running

Regtest tests create wallets. If you run them a second time, stale wallets
can cause false failures. Wipe the chain first:

```bash
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass stop
rm -rf ~/.bitcoin/regtest
bitcoind -regtest -daemon \
  -rpcuser=rpcuser -rpcpassword=rpcpass \
  -fallbackfee=0.00001 -txindex=1
sleep 3
./test_superscalar --regtest
```

### Run everything at once

```bash
./test_superscalar --all    # unit + regtest (bitcoind must be running)
```

---

## Unit Test Suites

### Core Crypto

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| DW State Machine | 8 | nSequence odometer: layer init, delay calculation, advance, exhaustion |
| MuSig2 | 4 | Key aggregation, sign/verify, wrong message rejection, taproot signing |
| MuSig2 Split-Round | 6 | Split-round protocol, nonce pools, partial sig verification, 5-of-5 |
| Transaction Builder | 5 | P2TR output scripts, unsigned tx serialization, witness finalization, varint |
| Tapscript | 6 | Leaf hashing, tree tweaking, control blocks, sighash, CLTV timeout scripts |
| Shachain | 2 | Shachain generation, derivation property |
| Adaptor Signatures | 3 | Adaptor round-trip, invalid pre-sig, taproot adaptor |
| PTLC Key Turnover | 3 | PTLC key extraction via adaptor sigs, multi-client turnover |

### Factory

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Factory Tree | 3 | Build tree, sign all nodes, advance state |
| Factory Split-Round | 3 | Step-by-step split-round, pool-based signing, advance with split-round |
| Factory Shachain | 3 | L-output burn path, burn tx construction, advance with shachain |
| Variable-N Tree | 4 | Tree construction for N=3, 7, 9, 16 clients |
| Arity-1 Leaves | 8 | Per-client leaves: build, outputs, sign, advance, independence, coop close |
| Arity-1 Hardening | 6 | CLTV ordering, min funding rejection, input amounts, split-round, persistence |
| Tree Navigation | 6 | Path-to-root, subtree clients, leaf lookup, variable-N, timeout spend |
| Epoch/Leaf | 8 | Counter reset, epoch reset, left/right leaf advance, independence, exhaustion |
| Placement + Economics | 5 | Sequential/inward/outward placement, profile wire round-trip, bps validation |
| Nonce Pool Integration | 3 | Pool-based factory creation, exhaustion handling, participant node counts |
| Subtree-Scoped Signing | 4 | Path session init, path rebuild, path signing, advance+rebuild path |

### Channels

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Channel (Poon-Dryja) | 6 | Key derivation, commitment tx, signing, update, revocation, penalty |
| HTLC | 9 | Offered/received scripts, control blocks, add/fulfill/fail, commitment tx with HTLCs, success/timeout spend, penalty sweep |
| Cooperative Close | 3 | Factory close, close with balances, channel close |
| Channel Operations | 4 | Wire message round-trip, LSP channel init, fee policy, channel framing |

### Wire Protocol & Networking

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Wire Protocol | 7 | Pubkey-only factory, framing, crypto serialization, nonce/psig bundles, close unsigned, distributed signing |
| Wire Hardening | 4 | Oversized frame rejection, CLTV delta, truncated header/body, zero-length frame |
| Wire Hostname + Tor | 5 | Hostname connect, .onion rejection without proxy, proxy arg parsing, SOCKS5 mock |
| CLN Bridge | 11 | Message round-trip, hello handshake, invoice registry, inbound/outbound flow, unknown hash, forward registration, NK pubkey, HTLC timeout |
| Encrypted Transport | 5 | ChaCha20-Poly1305, HMAC-SHA256, Noise handshake, encrypted wire, tamper rejection |

### Persistence & Recovery

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Persistence | 8 | Open/close, channel round-trip, revocation, HTLC save/load/delete, factory, nonce pool, multi-channel |
| Persistence Hardening | 6 | DW counter, departed clients, invoice, HTLC origin, client invoice, counter round-trip |
| Schema Validation | 4 | Version check, future version rejection, factory load validation, channel load validation |
| Persistence Stress | 2 | Crash stress (10 cycles with HTLC mutations), DW state crash recovery |

### Security & Watchtower

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Security Hardening | 5 | Secure zero, plaintext rejection, nonce stability, FD table growth, channel near-exhaustion |
| Watchtower + Fees | 7 | Fee init, penalty tx fee, factory tx fee, null estimator, watch+check, old commitment persistence, raw tx API |
| Client Watchtower | 7 | Init, bidirectional revocation, revoked commitment watch, LSP revoke-and-ack wire, factory node watch, combined entries, HTLC penalty |
| CPFP Anchor | 5 | Penalty anchor, HTLC penalty anchor, pending tracking, fee update, anchor init |
| CPFP Audit | 4 | Sign-complete check, witness offset, retry bump, pending persistence |

### Production Hardening

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Ceremony State Machine | 4 | Parallel client collection, timeout handling, quorum check, state transitions |
| Distributed Advances | 2 | Distributed epoch reset, arity-2 leaf advance (3-signer ceremony) |
| Production Hardening | 3 | Distribution TX P2A anchor, ceremony retry with exclusion, funding reserve check |
| Profit Settlement | 3 | Settlement calculation, trigger conditions, unsettled share on close |

### JIT Channels, Lifecycle, Demos

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| JIT Channel | 19 | Wire round-trips, channel init/find, ID collision, routing, fallback, persistence, migrate lifecycle, state conversion |
| JIT Hardening | 8 | Watchtower registration/revocation/cleanup, persist reload, multiple channels/indices, funding confirmation |
| Factory Lifecycle | 4 | States, queries, distribution tx, distribution tx default |
| Ladder Manager | 4 | Create factories, state transitions, key turnover+close, overlapping |
| Ladder Hardening | 5 | Partial departure, restructure, DW cross-layer delay, full rotation, evict and reuse |
| Partial Close | 7 | Cooperative/uncooperative clients, thresholds, 3of4/2of4 rotation, preserves distribution tx |
| Continuous Ladder | 3 | Evict expired, rotation trigger, context save/restore |
| Demo Polish | 3 | Invoice wire, preimage fulfills, balance reporting |
| Daemon Mode | 4 | Invoice registration, daemon event loop, client auto-fulfill, feature wiring |
| Reconnection | 4 | Wire format, pubkey matching, nonce re-exchange, persist+reload |
| Network Mode | 3 | Regtest init, mode flag, block height |

### Additional Suites

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Cooperative Epoch Reset + Per-Leaf Advance | 8 | Counter reset, epoch reset, left/right leaf advance, independence, exhaustion |
| Basepoint Exchange | 2 | Channel basepoint wire round-trip, multi-client exchange |
| Random Basepoints | 2 | Random basepoint generation, uniqueness |
| LSP Recovery | 1 | Factory + channel reload from DB after crash |
| Rotation Retry with Backoff | 3 | Retry timing, success resets, default config |
| Signet Interop | 3 | Signet network init, fee estimation, confirmation polling |
| Demo Protections | 3 | Safe defaults, error guards, regtest-only flags |
| Factory Rotation | 3 | PTLC turnover, close + recreate, payment in new factory |
| Daemon Feature Wiring | 3 | Watchtower wiring, fee estimator, settlement trigger |
| Security Model Tests | 5 | Threat model validation, access control, key isolation |
| Security Model Gap Tests | 4 | Noise FD overflow, cooperative close timeout, persist atomicity |
| Dust/Reserve Validation | 3 | Dust limit enforcement, reserve checks, edge amounts |
| Watchtower Wiring | 2 | Watchtower registration in factory lifecycle |
| HTLC Timeout Enforcement | 3 | CLTV expiry, timeout path, success vs timeout precedence |
| Encrypted Keyfile | 3 | Encrypt, decrypt, wrong-passphrase rejection |
| Edge Cases + Failure Modes | 10 | Boundary conditions, error paths, malformed input handling |
| Phase 2: Testnet Ready | 13 | End-to-end testnet integration, multi-step scenarios |

---

## Adversarial Tests: What Each One Proves

These 11 tests run as part of `--regtest` and are the most important from a security perspective.

### 1. `test_regtest_dw_exhaustion_close`

**Question:** What happens when the DW state machine runs out of states?

Burns through all 15 DW advances, confirms the 16th is refused, then cooperatively closes. Proves the factory degrades gracefully without losing funds.

### 2. `test_regtest_htlc_timeout_race`

**Question:** If both a preimage reveal and a timeout are possible, who wins?

Creates an HTLC, mines to exact CLTV expiry, broadcasts both success and timeout. The success path must win — allowing timeout would steal funds from the recipient.

### 3. `test_regtest_penalty_with_htlcs`

**Question:** Can the watchtower penalize a breach during an active payment?

Broadcasts a revoked commitment with 3 outputs (to_local + to_remote + HTLC). Watchtower must sweep both to_local AND the HTLC output with separate penalty transactions.

### 4. `test_regtest_multi_htlc_unilateral`

**Question:** Can multiple concurrent HTLCs be resolved independently?

Creates 2 HTLCs, broadcasts commitment, resolves one via preimage and the other via timeout. Proves HTLC outputs are independently spendable.

### 5. `test_regtest_watchtower_late_detection`

**Question:** What if the watchtower missed the breach when it happened?

Broadcasts revoked commitment, mines 3 blocks, THEN runs the watchtower check. Watchtower detects it in the chain and still broadcasts a penalty.

### 6. `test_regtest_ptlc_no_coop_close`

**Question:** What if the LSP extracts all keys and then disappears?

Performs PTLC key turnover, LSP refuses to close cooperatively. After CLTV timeout, the distribution TX confirms. Proves clients get funds back even when the LSP has all keys.

### 7. `test_regtest_all_offline_recovery`

**Question:** What if all clients disappear forever?

Creates factory, all clients are offline. After CLTV timeout, distribution TX recovers all funds with correct per-participant outputs.

### 8. `test_regtest_tree_ordering`

**Question:** Can someone skip tree nodes and broadcast a leaf directly?

Broadcasts all 6 factory tree nodes in correct order, each with proper nSequence delay. All confirm. Proves consensus enforces the tree structure.

### 9. `test_regtest_watchtower_mempool_detection`

**Question:** Can breaches be detected before confirmation?

Broadcasts revoked commitment, runs watchtower before mining. Watchtower detects the breach in the mempool.

### 10. `test_regtest_htlc_wrong_preimage_rejected`

**Question:** Does the HTLC script reject the wrong preimage?

Attempts to spend an HTLC with an incorrect preimage. Bitcoin consensus (`OP_SHA256 OP_EQUALVERIFY`) rejects the spend.

### 11. `test_regtest_funding_double_spend_rejected`

**Question:** Can old factory tree txs be replayed after cooperative close?

Closes factory cooperatively (spending the funding UTXO), then broadcasts old kickoff tx. Bitcoin consensus rejects the double-spend.

---

## Sanitizer Build (Optional)

For catching memory bugs and undefined behavior:

```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
make -j$(nproc)

ASAN_OPTIONS=detect_leaks=0 ./test_superscalar --unit
ASAN_OPTIONS=detect_leaks=0 ./test_superscalar --regtest
```

This enables AddressSanitizer and UndefinedBehaviorSanitizer. Any memory
error or UB will cause an immediate abort with a stack trace.

---

## CI (Continuous Integration)

GitHub Actions runs on every push and pull request:

| Runner | What it builds/tests |
|--------|---------------------|
| Linux (Ubuntu) | Full build + unit tests |
| macOS | Full build + unit tests |
| Linux + Sanitizers | ASan + UBSan build + unit tests |
| Static Analysis | cppcheck (zero warnings enforced) |
| Regtest Integration | Real Bitcoin Core 28.1 + regtest tests |
| Coverage | gcov/lcov instrumented build + HTML report artifact |
| Fuzz Testing | 5 libFuzzer targets, 5 minutes each |

Additionally:
- All platforms compile with `-Wall -Wextra -Werror` — zero warnings is a hard gate

CI config is in `.github/workflows/`. A failing CI check blocks merges.

---

## Writing New Tests

### Unit Test Pattern

Tests live in `tests/test_*.c` and are registered in `tests/test_main.c`.

```c
// In tests/test_yourmodule.c
#include "superscalar/yourmodule.h"
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

int test_your_feature(void) {
    your_struct_t s;
    memset(&s, 0, sizeof(s));

    int result = your_function(&s, 42);

    TEST_ASSERT(result == 1, "should succeed");
    TEST_ASSERT_EQ(s.field, 42, "field set correctly");

    return 1;  // 1 = pass, 0 = fail
}
```

Register in `test_main.c`:

```c
// Add extern declaration near the top
extern int test_your_feature(void);

// Add to run_unit_tests()
printf("\n=== Your Module ===\n");
RUN_TEST(test_your_feature);
```

Add the source file to `CMakeLists.txt`:

```cmake
add_executable(test_superscalar
    ...existing files...
    tests/test_yourmodule.c
)
```

### Regtest Test Pattern

Regtest tests use the `regtest_t` helper struct:

```c
int test_regtest_your_scenario(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) return 0;

    // Fund, build, sign, broadcast, mine, verify
    // ...

    regtest_cleanup(&rt);
    return 1;
}
```

Register in `test_main.c` inside `run_regtest_tests()`.

---

## Running Demos

See [demo-walkthrough.md](demo-walkthrough.md) for a full walkthrough of every demo scenario.

Quick version:

```bash
bash tools/run_demo.sh --basic       # Factory + payments + close (~30s)
bash tools/run_demo.sh --breach      # + watchtower penalty (~60s)
bash tools/run_demo.sh --rotation    # + factory rotation (~2min)
bash tools/run_demo.sh --all         # All scenarios
```

---

## Quick Reference

```bash
# Build
mkdir -p build && cd build && cmake .. && make -j$(nproc)

# Unit tests (no bitcoind)
./test_superscalar --unit

# Regtest tests (needs bitcoind -regtest)
bitcoind -regtest -daemon -rpcuser=rpcuser -rpcpassword=rpcpass \
  -fallbackfee=0.00001 -txindex=1
sleep 3
./test_superscalar --regtest

# Everything
./test_superscalar --all

# Demos
bash tools/run_demo.sh --all

# Stop bitcoind when done
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass stop
```
