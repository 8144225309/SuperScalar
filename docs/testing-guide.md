# SuperScalar Testing Guide

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

For **regtest integration tests** you also need Bitcoin Core (28.x+):

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
| Unit tests | 271 | No | Every module in isolation: crypto, state machines, channels, wire protocol, persistence, bridge, Tor SOCKS5 |
| Regtest integration | 26 | Yes | Real Bitcoin transactions: factory funding, tree broadcast, payments, cooperative close, bridge payment, NK handshake over TCP |
| Adversarial regtest | 11 | Yes | Fund safety under attack: breach penalties, HTLC edge cases, timeout recovery, DW exhaustion, wrong preimage rejection, double-spend rejection |
| **Total** | **308** | | |

---

## Running Unit Tests

No bitcoind needed. Just build and run:

```bash
cd build
./test_superscalar --unit
```

Expected output: `Results: 271/271 passed`

These run in ~2 seconds and test every core module: DW state machines,
MuSig2 signing, transaction building, tapscript, factory trees, channels
with HTLCs, penalty construction, wire protocol serialization, SQLite
persistence, watchtower logic, CLN bridge messages, Tor SOCKS5 protocol,
NK-authenticated Noise handshakes, and more.

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

Expected output: `Results: 37/37 passed`

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

## Adversarial Tests: What Each One Proves

These 11 tests are the most important from a security perspective. They run
as part of `--regtest` (under the "Adversarial & Edge-Case Tests" and
"Security Model Gap Tests" headers). Here's what each one does and why it
matters:

### 1. `test_regtest_dw_exhaustion_close`

**Question:** What happens when the Decker-Wattenhofer state machine runs
out of states?

**What it does:** Creates a factory, burns through all DW states (15 advances
with the default 2-layer x 4-state counter), confirms that the 16th advance
is refused, then cooperatively closes the factory anyway.

**Why it matters:** A factory that can't advance is stuck, but it must not
lose funds. This proves the factory degrades gracefully and cooperative close
still works even when DW is exhausted.

### 2. `test_regtest_htlc_timeout_race`

**Question:** If both a preimage reveal and a timeout happen at the same
block height, who wins?

**What it does:** Creates a channel with an HTLC, mines to the exact CLTV
expiry height, then tries to broadcast both the success tx (with preimage)
and the timeout tx. Only one can spend the HTLC output.

**Why it matters:** This is a protocol correctness edge case. The success
path must win because the payer already released the preimage — allowing
the timeout would steal funds. The test proves the success tx confirms and
the timeout tx is rejected.

### 3. `test_regtest_penalty_with_htlcs`

**Question:** Can the watchtower punish a breach that happened during an
active payment?

**What it does:** Sets up a channel, adds an HTLC (so the commitment has
3 outputs: to_local, to_remote, and HTLC), advances to the next state, then
broadcasts the revoked commitment. The watchtower must build and broadcast
TWO penalty transactions: one sweeping to_local and one sweeping the HTLC.

**Why it matters:** Most breach tests only cover 2-output commitments. In
practice, breaches can happen when HTLCs are in flight. If the watchtower
can't sweep HTLC outputs, the cheater keeps those funds.

### 4. `test_regtest_multi_htlc_unilateral`

**Question:** When a commitment tx with multiple HTLCs is broadcast, can
each HTLC be resolved independently?

**What it does:** Creates a channel with 2 HTLCs (one received, one offered),
broadcasts the commitment tx, resolves HTLC #1 via the preimage success
path, mines past the CLTV timeout, then resolves HTLC #2 via the timeout
path.

**Why it matters:** Real channels carry multiple concurrent payments. This
proves that each HTLC output is independently spendable and the two
resolution paths (success vs timeout) don't interfere with each other.

### 5. `test_regtest_watchtower_late_detection`

**Question:** What if the watchtower wasn't running when the breach happened?

**What it does:** Creates a channel, revokes commitment #0, broadcasts the
revoked commitment, mines 3 blocks so it's fully confirmed — all BEFORE
the watchtower checks. Then the watchtower scans the chain, detects the
breach, and broadcasts a penalty tx.

**Why it matters:** A watchtower that only works if it sees the breach in
real-time is useless. This proves late detection works — the watchtower
can come online hours later and still punish.

### 6. `test_regtest_ptlc_no_coop_close`

**Question:** What if the LSP gets all client keys via PTLC turnover and
then disappears?

**What it does:** Creates a full factory (LSP + 4 clients), performs PTLC
key turnover (the LSP extracts all client private keys via adaptor sigs),
then the LSP refuses to cooperatively close. After mining past the CLTV
timeout, the pre-signed distribution tx is broadcast as a fallback.

**Why it matters:** PTLC turnover is the most trust-sensitive operation in
the protocol. Even after the LSP has every client's key, the nLockTime
fallback guarantees clients get their funds back. No trust required.

### 7. `test_regtest_all_offline_recovery`

**Question:** What if every client disappears and never comes back?

**What it does:** Creates a full factory, then does nothing — all clients
are "offline." After mining past the CLTV timeout, the distribution tx is
broadcast. Verifies that the tx has N+1 outputs (one per participant) and
each output is P2TR to the correct key.

**Why it matters:** The worst-case scenario for a channel factory is total
client abandonment. This proves the LSP can recover its own funds AND that
client funds are preserved (the LSP can't steal them because outputs are
locked to client keys).

### 8. `test_regtest_tree_ordering`

**Question:** Can someone skip intermediate tree nodes and broadcast a leaf
directly?

**What it does:** Builds the full 6-node factory tree, then broadcasts
each node in the correct order (root to leaf), mining between each to
satisfy nSequence. Verifies all 6 transactions confirm in sequence.

**Why it matters:** The factory tree enforces a broadcast order — each
node's input is the previous node's output. Skipping a node is impossible
because the input doesn't exist on-chain. This test verifies consensus
enforces the tree structure.

> **Note:** This test runs last and may print `SKIP: regtest subsidy
> exhausted` if the chain has mined too many blocks (regtest halves every
> 150 blocks). This is normal — the test passes cleanly on a fresh chain.

### 9. `test_regtest_watchtower_mempool_detection`

**Question:** Can the watchtower detect a breach before the tx confirms?

**What it does:** Broadcasts a revoked commitment, then runs the watchtower
check before mining. The watchtower detects the breach in the mempool and
builds a penalty tx.

**Why it matters:** Early detection gives more time to react. A watchtower
that only detects confirmed breaches is one block behind.

### 10. `test_regtest_htlc_wrong_preimage_rejected`

**Question:** Does the script-path HTLC success path reject a wrong preimage?

**What it does:** Creates a channel with an HTLC, then broadcasts the
commitment tx and attempts to spend the HTLC output with an incorrect
preimage. Bitcoin consensus (`OP_SHA256 OP_EQUALVERIFY`) rejects the spend.

**Why it matters:** HTLC security depends on the hash lock. If the wrong
preimage could satisfy the script, anyone could steal in-flight payments.

### 11. `test_regtest_funding_double_spend_rejected`

**Question:** Can a cooperatively-closed factory be attacked by replaying
the old factory tree?

**What it does:** Creates a factory, cooperatively closes it (spending the
funding UTXO), then attempts to broadcast the kickoff transaction from the
old tree. Bitcoin consensus rejects the double-spend.

**Why it matters:** After cooperative close, the factory tree transactions
must be permanently invalid. If they weren't, the LSP or a client could
reopen the old tree and claim funds twice.

---

## Running Demos

The demo scripts are the easiest way to see SuperScalar in action without
reading test code. They start bitcoind, fund a wallet, launch the LSP + 4
clients, and run through scenarios with colored output.

```bash
cd SuperScalar

# Basic: factory + payments + cooperative close (~30 seconds)
bash tools/run_demo.sh --basic

# Breach: + watchtower detects breach, broadcasts penalty (~60 seconds)
bash tools/run_demo.sh --breach

# Rotation: + PTLC turnover + factory ladder rotation (~2 minutes)
bash tools/run_demo.sh --rotation

# All three in sequence
bash tools/run_demo.sh --all
```

The demo runner handles all pre-flight checks and cleanup. If bitcoind
isn't running, it starts one.

---

## Test Orchestrator

The orchestrator (`tools/test_orchestrator.py`) runs multi-process scenarios
where the LSP and clients are separate OS processes communicating over TCP.
This tests the wire protocol, process crash recovery, and multi-party
failure modes.

```bash
# List available scenarios
python3 tools/test_orchestrator.py --list

# Run specific scenarios
python3 tools/test_orchestrator.py --scenario all_watch          # All 4 clients detect breach
python3 tools/test_orchestrator.py --scenario partial_watch --k 2  # 2 of 4 detect
python3 tools/test_orchestrator.py --scenario nobody_home        # No clients, breach undetected
python3 tools/test_orchestrator.py --scenario late_arrival       # Clients restart after breach
python3 tools/test_orchestrator.py --scenario cooperative_close  # Clean shutdown
python3 tools/test_orchestrator.py --scenario timeout_expiry     # LSP reclaims via CLTV
python3 tools/test_orchestrator.py --scenario factory_breach     # Old factory tree broadcast
python3 tools/test_orchestrator.py --scenario all                # Run all scenarios
```

Requirements: a built `build/` directory with `superscalar_lsp` and
`superscalar_client` binaries, plus `bitcoind -regtest` running.

---

## Sanitizer Build (Optional)

For catching memory bugs and undefined behavior:

```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
make -j$(nproc)

# Run with leak detector suppressed (known codebase-wide leaks in test cleanup)
ASAN_OPTIONS=detect_leaks=0 ./test_superscalar --unit
ASAN_OPTIONS=detect_leaks=0 ./test_superscalar --regtest
```

This enables AddressSanitizer and UndefinedBehaviorSanitizer. Any memory
error or UB will cause an immediate abort with a stack trace.

---

## Reading the Test Code

If you want to understand the protocol by reading tests, here's a suggested
order — each test builds on concepts from the previous ones:

### Start here (foundations)

| File | Test | What you learn |
|------|------|---------------|
| `tests/test_dw.c` | `test_dw_advance` | How the DW state machine works (nSequence odometer) |
| `tests/test_musig.c` | `test_musig_sign_verify` | MuSig2 key aggregation and signing |
| `tests/test_tx.c` | `test_build_p2tr_tx` | How transactions are built and signed |
| `tests/test_tapscript.c` | `test_timeout_tapscript` | CLTV timeout script-path construction |

### Then channels

| File | Test | What you learn |
|------|------|---------------|
| `tests/test_channel.c` | `test_build_commitment_tx` | Poon-Dryja commitment structure |
| `tests/test_channel.c` | `test_channel_penalty_tx` | Revocation and penalty sweeps |
| `tests/test_channel.c` | `test_htlc_success_tx` | HTLC resolution via preimage |
| `tests/test_channel.c` | `test_htlc_timeout_tx` | HTLC resolution via timeout |

### Then factory

| File | Test | What you learn |
|------|------|---------------|
| `tests/test_factory.c` | `test_factory_build_tree` | 6-node timeout-sig-tree structure |
| `tests/test_factory.c` | `test_factory_sign_tree` | Cooperative MuSig2 signing of tree |
| `tests/test_factory.c` | `test_factory_advance` | DW state advance within factory |
| `tests/test_factory.c` | `test_factory_coop_close` | Single-tx cooperative close |

### Then bridge + Tor

| File | Test | What you learn |
|------|------|---------------|
| `tests/test_bridge.c` | `test_bridge_msg_round_trip` | Bridge wire message serialization (all 8 MSG_BRIDGE_* types) |
| `tests/test_bridge.c` | `test_lsp_inbound_via_bridge` | Invoice registry, origin tracking, fulfill back-propagation |
| `tests/test_bridge.c` | `test_tor_socks5_mock` | SOCKS5 protocol bytes (greeting, CONNECT, tunnel echo) via mock server |
| `tests/test_bridge.c` | `test_regtest_bridge_nk_handshake` | NK Noise handshake + encrypted messages over real TCP |
| `tests/test_bridge.c` | `test_regtest_bridge_payment` | Full bridge payment: factory → register invoice → HTLC → fulfill → verify |

### Then the adversarial tests

Read these after you understand channels and factories. They're in
`tests/test_channel.c`, `tests/test_factory.c`, `tests/test_ladder.c`,
and `tests/test_regtest.c` — grep for `Adversarial Test` to find them.

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
