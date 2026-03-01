# Demo Walkthrough

Step-by-step instructions for running every SuperScalar demo scenario. Covers automated (one-command) and manual (step-by-step) approaches.

## Prerequisites

1. Build the project:
   ```bash
   mkdir -p build && cd build
   cmake .. && make -j$(nproc)
   cd ..
   ```

2. Have `bitcoind` and `bitcoin-cli` in your PATH (Bitcoin Core 28.1+).

3. All demos below assume you're in the project root directory.

---

## Automated Demos (One Command)

The `run_demo.sh` script handles everything — starts bitcoind if needed, funds the wallet, launches processes, runs the scenario, and cleans up.

### Basic: Factory + Payments + Cooperative Close

```bash
bash tools/run_demo.sh --basic
```

**What you'll see:**
1. Pre-flight checks (binaries, bitcoin-cli)
2. bitcoind starts (if not running), wallet funded
3. LSP starts, 4 clients connect
4. Factory ceremony: PROPOSE -> NONCES -> PSIGS -> READY
5. Funding transaction broadcast and confirmed
6. 4 payments with real SHA256 preimage validation
7. Balance table showing movement
8. Cooperative close (single on-chain tx)
9. Summary: "All demos passed!"

**Duration:** ~30 seconds on regtest.

### Breach: Watchtower Detects Revoked Commitment

```bash
bash tools/run_demo.sh --breach
```

**What you'll see (in addition to basic):**
1. After normal payments, LSP broadcasts a **revoked** commitment transaction
2. Watchtower detects the breach (scans chain every 5 seconds)
3. Penalty transaction broadcast, sweeping cheater's funds
4. Penalty confirmed

**Duration:** ~60 seconds.

### Client Breach: Clients Catch LSP Cheating

```bash
bash tools/run_demo.sh --client-breach
```

**What you'll see:**
1. LSP runs in "cheat daemon" mode — processes payments normally, then cheats
2. Each of the 4 clients independently detects the breach
3. Clients broadcast penalty transactions
4. Log output confirms: "4/4 clients detected the LSP cheat"

**Duration:** ~60 seconds.

### Rotation: Factory Ladder (Factory 0 -> Factory 1)

```bash
bash tools/run_demo.sh --rotation
```

**What you'll see:**
1. Factory 0 created, payments flow
2. PTLC key turnover: adaptor signatures extract client keys
3. Factory 0 closed (LSP signs alone with extracted keys)
4. Factory 1 created as replacement
5. Payments resume in Factory 1
6. Factory 1 cooperatively closed

**Duration:** ~2 minutes.

### All Demos Sequentially

```bash
bash tools/run_demo.sh --all
```

Runs basic, breach, client-breach, and rotation in order. Summary at the end.

### With Dashboard

```bash
bash tools/run_demo.sh --all --dashboard
```

After demos complete, launches the web dashboard at http://localhost:8080 in demo mode.

---

## Manual Demo (Step by Step)

For when you want full control over each step. Uses the `manual_demo.sh` subcommand tool.

### Step 1: Setup Environment

```bash
bash tools/manual_demo.sh setup
```

This:
- Starts bitcoind if not running
- Creates and funds the `superscalar_lsp` wallet
- Creates `/tmp/superscalar_demo/` for databases and PID files

### Step 2: Start the LSP

```bash
bash tools/manual_demo.sh start-lsp
```

The LSP starts in daemon mode with persistence (`/tmp/superscalar_demo/lsp.db`). It waits for 4 client connections.

### Step 3: Start Clients

```bash
bash tools/manual_demo.sh start-clients
```

Starts 4 clients with deterministic keys, each with its own database. Once all 4 connect, the factory ceremony runs automatically.

### Step 4: Check Status

```bash
bash tools/manual_demo.sh status
```

Shows:
- Process status (LSP and each client PID)
- Channel balances from the LSP database

### Step 5: Check Balances

```bash
bash tools/manual_demo.sh balances
```

Shows channel balances from both the LSP and each client's database side by side.

### Step 6: Stop

```bash
bash tools/manual_demo.sh stop
```

Kills all client and LSP processes. The LSP will attempt cooperative close before exiting.

### Step 7: Teardown

```bash
bash tools/manual_demo.sh teardown
```

Stops processes, stops bitcoind (if the setup script started it), and removes temp files.

---

## Fully Manual Demo (Individual Commands)

For maximum control, run each binary directly.

### Terminal 1: Start bitcoind

```bash
bitcoind -regtest -daemon -txindex=1 -fallbackfee=0.00001 \
  -rpcuser=rpcuser -rpcpassword=rpcpass

# Create and fund wallet
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  createwallet superscalar_lsp

ADDR=$(bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  -rpcwallet=superscalar_lsp getnewaddress)

bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  generatetoaddress 101 "$ADDR"
```

### Terminal 2: Start the LSP

```bash
cd build

# Demo mode (auto-runs payments then closes)
./superscalar_lsp --network regtest --port 9735 --clients 4 --amount 100000 --demo

# OR daemon mode (stays running, Ctrl+C to close)
./superscalar_lsp --network regtest --port 9735 --clients 4 --amount 100000 \
  --daemon --db /tmp/lsp.db
```

### Terminals 3-6: Start Clients

```bash
cd build

# Client 1
./superscalar_client --seckey 2222222222222222222222222222222222222222222222222222222222222222 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon

# Client 2
./superscalar_client --seckey 3333333333333333333333333333333333333333333333333333333333333333 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon

# Client 3
./superscalar_client --seckey 4444444444444444444444444444444444444444444444444444444444444444 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon

# Client 4
./superscalar_client --seckey 5555555555555555555555555555555555555555555555555555555555555555 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon
```

Once all 4 clients connect, the factory ceremony starts automatically.

### Watch It Work

In `--demo` mode, the LSP runs 4 payments and cooperatively closes. Output includes balance tables at each step.

In `--daemon` mode, the factory stays open. Payments happen when triggered externally (or via the bridge from CLN).

---

## Test Orchestrator (Multi-Process Scenarios)

For adversarial testing with automatic process management:

```bash
# List all scenarios
python3 tools/test_orchestrator.py --list

# Run a specific scenario
python3 tools/test_orchestrator.py --scenario all_watch          # All clients detect breach
python3 tools/test_orchestrator.py --scenario partial_watch --k 2  # 2 of 4 detect
python3 tools/test_orchestrator.py --scenario nobody_home        # No clients detect
python3 tools/test_orchestrator.py --scenario late_arrival       # Clients restart after breach
python3 tools/test_orchestrator.py --scenario all                # Run everything
```

### Lifecycle Scenarios

```bash
python3 tools/test_orchestrator.py --scenario cooperative_close    # Clean SIGTERM shutdown, close TX confirmed
python3 tools/test_orchestrator.py --scenario timeout_expiry       # All vanish; LSP reclaims via CLTV
python3 tools/test_orchestrator.py --scenario timeout_recovery     # Clients vanish → LSP timeout reclaim
python3 tools/test_orchestrator.py --scenario jit_lifecycle        # Late client triggers JIT channel create + fund + route
python3 tools/test_orchestrator.py --scenario factory_rotation     # DYING trigger → PTLC turnover → new factory
python3 tools/test_orchestrator.py --scenario full_lifecycle       # Factory → payments → watchtower → cooperative close
```

### Failure & Recovery Scenarios

```bash
python3 tools/test_orchestrator.py --scenario factory_breach       # LSP broadcasts old factory tree; clients detect
python3 tools/test_orchestrator.py --scenario ladder_breach        # Breach in DYING factory; ACTIVE factory unaffected
python3 tools/test_orchestrator.py --scenario turnover_abort       # PTLC turnover aborted midway; client reconnects
python3 tools/test_orchestrator.py --scenario lsp_crash_recovery   # LSP SIGKILL + restart; clients reconnect
python3 tools/test_orchestrator.py --scenario client_crash_htlc    # Client crashes during payment; HTLC resolves after restart
python3 tools/test_orchestrator.py --scenario mass_departure_jit   # Mass client departure triggers JIT fallback
python3 tools/test_orchestrator.py --scenario watchtower_late_arrival  # Clients restart after breach, detect before CSV
```

The orchestrator manages process lifecycles, waits for expected outcomes, and reports pass/fail. 17 scenarios total.

---

## Special Test Flags (LSP)

These flags run after the `--demo` payment sequence to demonstrate specific protocol features:

| Flag | What It Tests |
|------|---------------|
| `--breach-test` | LSP broadcasts a revoked commitment, its own watchtower detects and penalizes |
| `--cheat-daemon` | LSP broadcasts a revoked commitment and sleeps — clients must detect it |
| `--test-expiry` | Mines past CLTV timeout, LSP recovers funds via timeout script path |
| `--test-distrib` | Broadcasts the pre-signed distribution TX (nLockTime fallback for clients) |
| `--test-turnover` | PTLC key turnover via adaptor signatures, LSP closes alone afterward |
| `--test-rotation` | Full factory rotation: PTLC turnover + close + new factory + payments |
| `--force-close` | Broadcasts entire factory tree on-chain, waits for all confirmations |

Example:

```bash
# Terminal 1: LSP with breach test
./superscalar_lsp --network regtest --port 9735 --clients 4 --amount 100000 \
  --demo --breach-test

# Terminals 2-5: Clients (same as above)
```

---

## Bridge Integration Demo (CLN + SuperScalar)

This demo shows the full CLN bridge pipeline: a factory client registers an invoice, the bridge creates a BOLT11 via CLN, an external Lightning node pays it, and the payment flows through the bridge into the factory.

### Prerequisites

- Everything from the basic demo prerequisites
- CLN v24.11+ installed (`lightningd`, `lightning-cli`)
- Python 3.8+ (for the CLN plugin)
- Two funded CLN nodes (or use the regtest setup below for a single-node test)

### Terminal 1: bitcoind

```bash
bitcoind -regtest -daemon -txindex=1 -fallbackfee=0.00001 \
  -rpcuser=rpcuser -rpcpassword=rpcpass

# Create and fund wallet
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  createwallet superscalar_lsp

ADDR=$(bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  -rpcwallet=superscalar_lsp getnewaddress)

bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass \
  generatetoaddress 101 "$ADDR"
```

### Terminal 2: LSP (Daemon Mode)

```bash
cd build
./superscalar_lsp --network regtest --port 9735 --clients 4 --amount 100000 \
  --daemon --db /tmp/lsp.db
```

Note the LSP pubkey printed at startup — you'll need it for the bridge.

### Terminals 3-6: Clients

```bash
cd build

# Client 1
./superscalar_client --seckey 2222222222222222222222222222222222222222222222222222222222222222 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon --db /tmp/client0.db

# Client 2
./superscalar_client --seckey 3333333333333333333333333333333333333333333333333333333333333333 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon --db /tmp/client1.db

# Client 3
./superscalar_client --seckey 4444444444444444444444444444444444444444444444444444444444444444 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon --db /tmp/client2.db

# Client 4
./superscalar_client --seckey 5555555555555555555555555555555555555555555555555555555555555555 \
  --host 127.0.0.1 --port 9735 --network regtest --daemon --db /tmp/client3.db
```

Wait for "Factory ceremony complete" in the LSP terminal.

### Terminal 7: Bridge

```bash
cd build
./superscalar_bridge \
  --lsp-host 127.0.0.1 \
  --lsp-port 9735 \
  --plugin-port 9736 \
  --lsp-pubkey <LSP_PUBKEY_FROM_TERMINAL_2>
```

You should see "Bridge: connected to LSP" and "Bridge: listening for plugin on port 9736".

### Terminal 8: CLN with Plugin

```bash
lightningd --network=regtest \
  --lightning-dir=/tmp/cln-superscalar \
  --plugin=/path/to/tools/cln_plugin.py \
  --superscalar-bridge-host=127.0.0.1 \
  --superscalar-bridge-port=9736 \
  --superscalar-lightning-cli=lightning-cli
```

### What to Expect

1. **Client registers invoice** — Client 1 sends `MSG_REGISTER_INVOICE` to the LSP
2. **Bridge forwards** — LSP sends `MSG_BRIDGE_REGISTER` to bridge → plugin
3. **CLN creates BOLT11** — Plugin calls `lightning-cli invoice` and returns the BOLT11 string
4. **Client receives BOLT11** — The BOLT11 flows back: plugin → bridge → LSP → client
5. **External payment** — Another LN node (or `lightning-cli pay`) pays the BOLT11
6. **HTLC flows in** — CLN's `htlc_accepted` fires → plugin → bridge → LSP → client channel
7. **Client fulfills** — Client reveals preimage → LSP → bridge → plugin resolves the CLN HTLC
8. **Payment complete** — Client's channel balance increases by the payment amount

### Verify the Pipeline

```bash
# Check CLN received the payment
lightning-cli listinvoices

# Check factory channel balances
sqlite3 -header -column /tmp/lsp.db \
  "SELECT channel_id, local_amount, remote_amount FROM channels"

# Check bridge is connected
lightning-cli plugin list | grep cln_plugin
```

### Teardown

```bash
# Stop CLN
lightning-cli stop

# Stop bridge (Ctrl+C in terminal 7)

# Stop clients (Ctrl+C in terminals 3-6)

# Stop LSP (Ctrl+C in terminal 2 — triggers cooperative close)

# Stop bitcoind
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass stop

# Clean up temp files
rm -rf /tmp/lsp.db /tmp/client*.db /tmp/cln-superscalar
```

---

## Web Dashboard

### Demo Mode (No Running Processes Needed)

```bash
python3 tools/dashboard.py --demo
# Open http://localhost:8080
```

Shows synthetic data — useful for exploring the dashboard UI without any setup.

### Live Mode (Connected to Running Deployment)

```bash
python3 tools/dashboard.py \
  --lsp-db /tmp/superscalar_demo/lsp.db \
  --client-db /tmp/superscalar_demo/client_0.db \
  --btc-cli bitcoin-cli \
  --btc-network regtest \
  --btc-rpcuser rpcuser \
  --btc-rpcpassword rpcpass
```

### Dashboard Tabs

| Tab | What It Shows |
|-----|---------------|
| Overview | Process status, blockchain height, wallet balance |
| Factory | Factory state (ACTIVE/DYING/EXPIRED), participant keys, DW epoch |
| Channels | Per-channel balances, commitment number, HTLC count |
| Protocol | Factory tree visualization, signatures, wire messages |
| Lightning | CLN node info (if bridge connected) |
| Watchtower | Old commitments being tracked, breach detection status |
| Events | Recent wire messages with timestamps |
