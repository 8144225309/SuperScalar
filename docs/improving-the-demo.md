# Improving the Demo Experience

What works today, what's missing, and concrete ideas for making SuperScalar easier to test and demonstrate.

## What Works Today

### Automated Testing
- **378 tests** (337 unit + 41 regtest), all passing
- Unit tests run in ~2 seconds with no external dependencies
- Regtest tests run real Bitcoin transactions against Bitcoin Core
- CI runs on every push: Linux, macOS, sanitizers, static analysis, regtest
- Test orchestrator runs multi-process scenarios (breach, timeout, rotation)

### Demo Tooling
- `run_demo.sh` — one-command demo with 4 scenarios (basic, breach, client-breach, rotation)
- `manual_demo.sh` — step-by-step subcommand tool for manual control
- `demo.sh` — minimal demo script
- `dashboard.py` — web dashboard with demo mode and live mode
- `test_orchestrator.py` — multi-process adversarial scenario runner

### Protocol Features
- Full factory lifecycle: create, pay, advance DW states, rotate, close
- Breach detection + penalty (LSP-side and client-side watchtowers)
- PTLC key turnover via adaptor signatures
- Factory ladder rotation (zero downtime)
- CLN bridge for Lightning Network connectivity
- Persistence and crash recovery
- Encrypted transport (Noise NN + NK)
- Tor hidden service support
- JIT channel fallback
- Client placement optimization (inward/outward)
- Profit-sharing economics

## What's Missing: Demo Gaps

### 1. ~~No Interactive Payment CLI~~ — IMPLEMENTED

> **Update:** The `--cli` flag on `superscalar_lsp` enables an interactive
> stdin-based CLI in daemon mode. Commands: `pay <from> <to> <amount>`,
> `status`, `rotate`, `close`, `help`. This resolves the core gap.

~~**Problem:** Once a factory is running in daemon mode, there's no way to trigger individual payments from the command line.~~

The remaining wish-list items (UNIX socket API, external CLI tool) are
polish on top of the working `--cli` implementation.

### 2. No Real Client-Initiated Payments

**Problem:** All payments are currently initiated by the LSP. A client can't decide "I want to send 1000 sats to client 2" — only the LSP can orchestrate this. The client binary has `--send` but it only works during the factory ceremony, not in daemon mode.

**What would help:**
- Wire message `MSG_PAY_REQUEST` from client to LSP
- LSP receives, validates, and orchestrates the HTLC flow
- Client gets `MSG_PAY_RESULT` back

**Effort:** Medium. The HTLC plumbing exists; this is mostly a new message type and daemon loop handler.

### 3. No Multi-Factory Ladder Demo

**Problem:** The rotation demo (`--test-rotation`) shows one rotation (Factory 0 -> Factory 1). A full ladder demo with 3+ overlapping factories would better showcase the SuperScalar name.

**What would help:**
- `--demo-ladder` flag that creates Factory 0, runs payments, rotates to Factory 1, runs more payments, rotates to Factory 2, closes all
- Show the timeline of factory lifetimes on the dashboard

**Effort:** Low. The ladder code exists and works. This is wiring up a longer scripted sequence.

### 4. No Cross-Bridge Demo Script

**Problem:** The bridge to CLN works in tests, but there's no demo script showing an external Lightning payment arriving at a factory client.

**What would help:**
- `tools/run_bridge_demo.sh` that:
  1. Starts bitcoind (regtest)
  2. Starts 2 CLN nodes (payer and bridge)
  3. Starts the SuperScalar LSP + bridge + clients
  4. Creates a Lightning invoice on a factory client
  5. Pays it from the external CLN node
  6. Shows the factory client's balance increase

**Effort:** High. Requires CLN binaries, channel funding between CLN nodes, and careful orchestration. But it would be the most impressive demo — proving factory clients are reachable from the entire Lightning Network.

### 5. Dashboard Has No Payment Trigger

**Problem:** The dashboard is read-only. You can see balances and state but can't interact.

**What would help:**
- "Send Payment" button on the Channels tab
- Input fields for from/to/amount
- POST endpoint on the dashboard that talks to the LSP

**Effort:** Medium. The dashboard is stdlib-only Python (no frameworks), so adding a POST handler and minimal JS form is doable but not trivial.

### 6. No Balance History / Payment Log

**Problem:** The dashboard shows current balances but not the history of payments. After a demo, you can't see "payment 1: 1000 sats from A to B at block 105."

**What would help:**
- `payment_log` table in SQLite persistence
- Dashboard Events tab showing payment history with amounts, participants, timestamps
- CLI command: `sqlite3 lsp.db "SELECT * FROM payment_log ORDER BY timestamp"`

**Effort:** Low-Medium. The persist module already has an audit_log table. Extending it for payments is straightforward.

### 7. No "Try It Yourself" Sandbox

**Problem:** Testing requires building from source (C compiler, CMake, SQLite headers) which is a barrier for non-developers.

**What would help:**
- Docker image with everything pre-built:
  ```bash
  docker run -it superscalar/demo bash tools/run_demo.sh --all
  ```
- GitHub Codespaces / Gitpod configuration
- Pre-built binaries for common platforms (Linux x86_64 at minimum)

**Effort:** Low for Docker (just a Dockerfile). Medium for pre-built binaries (cross-compilation or CI artifacts).

## Concrete Improvement Ideas (Prioritized)

### Quick Wins (1-2 hours each)

1. **Docker demo image** — Dockerfile with Ubuntu 24.04, build deps, Bitcoin Core, pre-compiled binaries. `docker run` and you're in.

2. **Payment log in SQLite** — Add `persist_log_payment()` calls in the HTLC fulfill path. Display in dashboard Events tab.

3. **Multi-rotation demo** — New `--demo-ladder` flag that runs 3 factory rotations with payments between each. Reuses existing ladder code.

4. **Regtest test script** — `tools/run_tests.sh` that wipes regtest, starts bitcoind, runs all tests, stops bitcoind. One command for contributors.

### Medium Effort (1-2 days each)

5. **Interactive payment CLI** — UNIX domain socket on LSP daemon, simple CLI tool sends commands. Or: stdin-based command parser in the daemon loop's select() timeout path.

6. **Client-initiated payments** — New `MSG_PAY_REQUEST` wire message. Client sends to LSP, LSP orchestrates HTLC.

7. **End-to-end signet demo script** — `tools/signet_demo.sh` that walks through the full signet lifecycle with real timing, progress indicators, and explanatory output.

### High Effort (1+ week)

8. **Cross-bridge demo** — Full script with 2 CLN nodes + bridge + factory. Most impressive demo but complex setup.

9. **Web UI for payments** — Dashboard gets POST endpoints and JS forms for triggering payments, inspecting HTLCs, and controlling factory lifecycle.

10. **Pre-built release binaries** — CI workflow that builds release binaries for Linux/macOS/Windows on tag push. GitHub Releases with download links.

## What We'd Recommend for Contributors

If you want to help improve the demo experience:

1. **Start with the Docker image** — lowest effort, highest impact for accessibility
2. **Then the interactive payment CLI** — makes daemon mode actually useful for demos
3. **Then the bridge demo** — the "wow factor" demo that proves Lightning Network integration

For the test infrastructure:

1. **The test suite is solid** — 378 tests with adversarial scenarios, sanitizer builds, and CI. No urgent gaps.
2. ~~**Fuzz testing**~~ — DONE. 5 libFuzzer harnesses (wire, JSON, sighash, persist, hex) with CI integration.
3. ~~**Property-based testing**~~ — DONE. 10 property tests with deterministic random inputs.
4. ~~**Coverage measurement**~~ — DONE. `cmake -DENABLE_COVERAGE=ON` generates lcov HTML reports.

## Running the Existing Demos

See [demo-walkthrough.md](demo-walkthrough.md) for step-by-step instructions on every current demo scenario.
