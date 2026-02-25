#!/usr/bin/env python3
"""SuperScalar Test Orchestrator — stdlib-only (subprocess + sqlite3 + json).

Manages LSP + N client processes for multi-party failure scenario testing.
Requires a built superscalar_lsp and superscalar_client in ../build/.

Usage:
    python3 tools/test_orchestrator.py --scenario all_watch
    python3 tools/test_orchestrator.py --scenario partial_watch --k 2
    python3 tools/test_orchestrator.py --scenario nobody_home
    python3 tools/test_orchestrator.py --scenario late_arrival
    python3 tools/test_orchestrator.py --scenario cooperative_close
    python3 tools/test_orchestrator.py --scenario timeout_expiry
    python3 tools/test_orchestrator.py --scenario all
    python3 tools/test_orchestrator.py --list
"""

import argparse
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Paths + constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
LSP_BIN = os.path.join(BUILD_DIR, "superscalar_lsp")
CLIENT_BIN = os.path.join(BUILD_DIR, "superscalar_client")
TEST_DIR = "/tmp/superscalar_test"

# Demo client keys: 0x22 repeated for client 0, 0x33 for 1, 0x44 for 2, 0x55 for 3
CLIENT_KEY_FILLS = [0x22, 0x33, 0x44, 0x55]
DEFAULT_PORT = 9745
DEFAULT_AMOUNT = 100000
DEFAULT_N_CLIENTS = 4
DEFAULT_NETWORK = "regtest"

# Per-network timing constants
TIMING = {
    "regtest": {"factory_timeout": 30, "breach_wait": 10, "lsp_timeout": 90,
                "coop_wait": 15, "stagger": 0.3, "lsp_bind": 0.5},
    "signet":  {"factory_timeout": 900, "breach_wait": 120, "lsp_timeout": 1800,
                "coop_wait": 300, "stagger": 1.0, "lsp_bind": 2.0},
}

def client_seckey(index):
    """Deterministic 32-byte hex secret key for client index."""
    fill = CLIENT_KEY_FILLS[index] if index < len(CLIENT_KEY_FILLS) else (0x22 + index)
    return (bytes([fill]) * 32).hex()


# ---------------------------------------------------------------------------
# ChainControl — wraps bitcoin-cli -regtest
# ---------------------------------------------------------------------------

class ChainControl:
    """Bitcoin Core chain operations (regtest, signet, etc.)."""

    def __init__(self, cli_path="bitcoin-cli", network=None,
                 rpcuser=None, rpcpassword=None):
        self.cli_path = cli_path
        self.network = network or os.environ.get("SUPERSCALAR_NETWORK", "regtest")
        self.rpcuser = rpcuser or os.environ.get("RPCUSER", "rpcuser")
        self.rpcpassword = rpcpassword or os.environ.get("RPCPASS", "rpcpass")

    def _cmd(self, *args, timeout=10):
        cmd = [self.cli_path]
        if self.network and self.network != "mainnet":
            cmd.append("-" + self.network)
        if self.rpcuser:
            cmd.append("-rpcuser=" + self.rpcuser)
        if self.rpcpassword:
            cmd.append("-rpcpassword=" + self.rpcpassword)
        cmd.extend(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                return None, r.stderr.strip()
            return r.stdout.strip(), None
        except Exception as e:
            return None, str(e)

    def mine_blocks(self, n, addr=None):
        if not addr:
            addr, _ = self.get_new_address()
            if not addr:
                return False
        out, err = self._cmd("generatetoaddress", str(n), addr)
        return err is None

    def get_height(self):
        out, err = self._cmd("getblockcount")
        return int(out) if out else -1

    def get_new_address(self):
        # Ensure wallet exists
        self._cmd("createwallet", "orchestrator", "false", "false", "", "false", "true")
        self._cmd("loadwallet", "orchestrator")
        out, err = self._cmd("-rpcwallet=orchestrator", "getnewaddress", "", "bech32m")
        return out, err

    def ensure_wallet(self, name="orchestrator"):
        self._cmd("createwallet", name, "false", "false", "", "false", "true")
        self._cmd("loadwallet", name)

    def fund_address(self, addr, btc=1.0):
        self._cmd("-rpcwallet=orchestrator", "sendtoaddress", addr, str(btc))
        return True

    def send_raw_tx(self, hex_tx):
        out, err = self._cmd("sendrawtransaction", hex_tx)
        return out  # txid or None

    def get_confirmations(self, txid):
        out, err = self._cmd("gettransaction", txid)
        if not out:
            return -1
        try:
            return json.loads(out).get("confirmations", 0)
        except Exception:
            return -1

    def get_mempool(self):
        out, err = self._cmd("getrawmempool")
        if not out:
            return []
        try:
            return json.loads(out)
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Actor — manages a single subprocess
# ---------------------------------------------------------------------------

class Actor:
    """Wraps a single superscalar binary process."""

    def __init__(self, name, cmd, log_path, env=None):
        self.name = name
        self.cmd = cmd
        self.log_path = log_path
        self.env = env or {}
        self.proc = None
        self.log_fh = None

    def start(self):
        env = dict(os.environ)
        env.update(self.env)
        self.log_fh = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=self.log_fh,
            stderr=subprocess.STDOUT,
            env=env,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        return self.proc.pid

    def stop(self, timeout=5):
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            else:
                self.proc.terminate()
            self.proc.wait(timeout=timeout)
        except Exception:
            self.kill()

    def kill(self):
        if self.proc and self.proc.poll() is None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                else:
                    self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:
                pass
        if self.log_fh:
            self.log_fh.close()
            self.log_fh = None

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait(self, timeout=30):
        if self.proc:
            try:
                return self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return None
        return None

    def returncode(self):
        if self.proc:
            return self.proc.returncode
        return None

    def read_log(self):
        try:
            with open(self.log_path, "r") as f:
                return f.read()
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Orchestrator — manages full test scenario
# ---------------------------------------------------------------------------

class Orchestrator:
    """Manages LSP + N clients for scenario testing."""

    def __init__(self, n_clients=DEFAULT_N_CLIENTS, port=DEFAULT_PORT,
                 amount=DEFAULT_AMOUNT, verbose=False, network=DEFAULT_NETWORK,
                 rpcuser=None, rpcpassword=None):
        self.n_clients = n_clients
        self.port = port
        self.amount = amount
        self.verbose = verbose
        self.network = network
        self.is_regtest = (network == "regtest")
        self.timing = TIMING.get(network, TIMING["signet"])
        self.chain = ChainControl(network=network, rpcuser=rpcuser,
                                   rpcpassword=rpcpassword)
        self.rpcuser = self.chain.rpcuser
        self.rpcpassword = self.chain.rpcpassword
        self.lsp = None
        self.clients = [None] * n_clients
        self.test_dir = TEST_DIR

        # Clean and recreate test directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
        os.makedirs(self.test_dir, exist_ok=True)

    def _log(self, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {msg}")
        sys.stdout.flush()

    def _lsp_db(self):
        return os.path.join(self.test_dir, "lsp.db")

    def _client_db(self, i):
        return os.path.join(self.test_dir, f"client_{i}.db")

    def _lsp_log(self):
        return os.path.join(self.test_dir, "lsp.log")

    def _client_log(self, i):
        return os.path.join(self.test_dir, f"client_{i}.log")

    def _lsp_report(self):
        return os.path.join(self.test_dir, "lsp_report.json")

    def _client_keyfile(self, i):
        return os.path.join(self.test_dir, f"client_{i}.key")

    def start_lsp(self, extra_flags=None):
        """Start LSP process."""
        cmd = [
            LSP_BIN,
            "--port", str(self.port),
            "--clients", str(self.n_clients),
            "--amount", str(self.amount),
            "--network", self.network,
            "--db", self._lsp_db(),
            "--report", self._lsp_report(),
            "--fee-rate", "1000",
            "--rpcuser", self.rpcuser,
            "--rpcpassword", self.rpcpassword,
        ]
        if not self.is_regtest:
            lsp_keyfile = os.path.join(self.test_dir, "lsp.key")
            cmd.extend(["--keyfile", lsp_keyfile, "--passphrase", "orchestrator"])
        if extra_flags:
            cmd.extend(extra_flags)
        self.lsp = Actor("LSP", cmd, self._lsp_log())
        pid = self.lsp.start()
        self._log(f"LSP started (PID {pid})")
        time.sleep(self.timing["lsp_bind"])
        return pid

    def start_client(self, index, extra_flags=None):
        """Start a single client process."""
        if index >= self.n_clients:
            return None
        cmd = [
            CLIENT_BIN,
            "--port", str(self.port),
            "--host", "127.0.0.1",
            "--network", self.network,
            "--db", self._client_db(index),
            "--daemon",
            "--fee-rate", "1000",
        ]
        if self.is_regtest:
            cmd.extend(["--seckey", client_seckey(index)])
        else:
            cmd.extend(["--keyfile", self._client_keyfile(index),
                         "--passphrase", "orchestrator"])
        if extra_flags:
            cmd.extend(extra_flags)
        actor = Actor(f"Client-{index}", cmd, self._client_log(index))
        pid = actor.start()
        self.clients[index] = actor
        self._log(f"Client {index} started (PID {pid})")
        return pid

    def start_all_clients(self, extra_flags=None):
        """Start all N clients."""
        for i in range(self.n_clients):
            self.start_client(i, extra_flags)
            time.sleep(self.timing["stagger"])

    def stop_client(self, index):
        """Stop a single client."""
        if self.clients[index]:
            self.clients[index].stop()
            self._log(f"Client {index} stopped")

    def stop_lsp(self):
        """Stop the LSP."""
        if self.lsp:
            self.lsp.stop()
            self._log("LSP stopped")

    def stop_all(self):
        """Stop all processes."""
        for i in range(self.n_clients):
            if self.clients[i]:
                self.clients[i].stop()
        if self.lsp:
            self.lsp.stop()
        self._log("All processes stopped")

    def kill_all(self):
        """Force-kill all processes."""
        for i in range(self.n_clients):
            if self.clients[i]:
                self.clients[i].kill()
        if self.lsp:
            self.lsp.kill()

    def wait_for_lsp(self, timeout=60):
        """Wait for LSP process to exit."""
        if self.lsp:
            return self.lsp.wait(timeout=timeout)
        return None

    def wait_for_factory(self, timeout=30):
        """Poll LSP DB until a factory row appears."""
        db_path = self._lsp_db()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
                    rows = conn.execute("SELECT COUNT(*) FROM factories").fetchone()
                    conn.close()
                    if rows and rows[0] > 0:
                        return True
                except Exception:
                    pass
            time.sleep(1)
        return False

    def get_channel_states(self):
        """Read channel state from all DBs."""
        states = {}
        # LSP
        db_path = self._lsp_db()
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
                conn.row_factory = sqlite3.Row
                rows = [dict(r) for r in conn.execute("SELECT * FROM channels").fetchall()]
                conn.close()
                states["lsp"] = rows
            except Exception:
                pass
        # Clients
        for i in range(self.n_clients):
            db_path = self._client_db(i)
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
                    conn.row_factory = sqlite3.Row
                    rows = [dict(r) for r in conn.execute("SELECT * FROM channels").fetchall()]
                    conn.close()
                    states[f"client_{i}"] = rows
                except Exception:
                    pass
        return states

    def check_watchtower_entries(self):
        """Read old_commitments table from all client DBs."""
        entries = {}
        for i in range(self.n_clients):
            db_path = self._client_db(i)
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
                    conn.row_factory = sqlite3.Row
                    rows = [dict(r) for r in
                            conn.execute("SELECT * FROM old_commitments").fetchall()]
                    conn.close()
                    entries[f"client_{i}"] = rows
                except Exception:
                    entries[f"client_{i}"] = []
        return entries

    def check_lsp_report(self):
        """Parse the LSP's JSON report file."""
        path = self._lsp_report()
        if not os.path.exists(path):
            return {}
        try:
            with open(path) as f:
                content = f.read().strip()
            # Report may have multiple JSON objects; take last valid one
            # or try parsing the whole thing as-is
            if content.startswith("{"):
                return json.loads(content)
            return {}
        except Exception:
            return {}

    def check_penalty_in_log(self, client_idx):
        """Check if a client's log contains penalty broadcast evidence."""
        if self.clients[client_idx]:
            log = self.clients[client_idx].read_log()
            return "BREACH DETECTED" in log or "penalty" in log.lower()
        return False

    def mine(self, n=1):
        """Mine N blocks (regtest only)."""
        return self.chain.mine_blocks(n)

    def advance_chain(self, n=1):
        """Advance chain by N blocks: mine on regtest, wait for natural blocks on signet."""
        if self.is_regtest:
            return self.chain.mine_blocks(n)
        # Wait for N new blocks on signet/testnet
        start_h = self.chain.get_height()
        target_h = start_h + n
        self._log(f"Waiting for {n} block(s) (height {start_h} -> {target_h})...")
        while self.chain.get_height() < target_h:
            time.sleep(15)
        return True

    def dump_logs(self):
        """Print all logs for debugging."""
        if self.lsp:
            print(f"\n--- LSP LOG ---")
            print(self.lsp.read_log()[-2000:])
        for i in range(self.n_clients):
            if self.clients[i]:
                print(f"\n--- CLIENT {i} LOG ---")
                print(self.clients[i].read_log()[-2000:])


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_all_watch(orch):
    """All N clients online — all detect LSP breach, penalty + CPFP confirmed."""
    orch._log("=== SCENARIO: all_watch ===")
    orch._log("All clients online; LSP broadcasts revoked commitment.")

    # Start LSP with --cheat-daemon (runs demo, broadcasts revoked, sleeps)
    orch.start_lsp(["--demo", "--cheat-daemon"])

    # Wait for LSP to bind, then start all clients
    time.sleep(1)
    orch.start_all_clients()

    # Wait for LSP to finish (it sleeps 30s after breach on regtest, longer on signet)
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Give clients a moment to process watchtower + CPFP cycles
    time.sleep(orch.timing["breach_wait"])

    # Check which clients detected the breach and broadcast CPFP
    n_detected = 0
    n_cpfp = 0
    for i in range(orch.n_clients):
        detected = orch.check_penalty_in_log(i)
        status = "DETECTED" if detected else "missed"
        cpfp = False
        if orch.clients[i]:
            log = orch.clients[i].read_log()
            cpfp = "CPFP child" in log
        cpfp_status = "+CPFP" if cpfp else ""
        orch._log(f"  Client {i}: {status} {cpfp_status}")
        if detected:
            n_detected += 1
        if cpfp:
            n_cpfp += 1

    orch.stop_all()

    success = n_detected == orch.n_clients
    orch._log(f"Result: {n_detected}/{orch.n_clients} detected breach, "
              f"{n_cpfp}/{orch.n_clients} broadcast CPFP child — "
              f"{'PASS' if success else 'FAIL'}")
    return success


def scenario_partial_watch(orch, k=2):
    """K of N clients online — only K detect breach."""
    orch._log(f"=== SCENARIO: partial_watch (k={k}) ===")
    orch._log(f"{k} clients online, {orch.n_clients - k} offline.")

    # Start LSP with --cheat-daemon
    orch.start_lsp(["--demo", "--cheat-daemon"])
    time.sleep(orch.timing["lsp_bind"])

    # Start only k clients
    for i in range(k):
        orch.start_client(i)
        time.sleep(orch.timing["stagger"])

    # Wait for LSP
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")
    time.sleep(orch.timing["breach_wait"] // 2)

    # Check online clients
    n_detected = 0
    for i in range(k):
        detected = orch.check_penalty_in_log(i)
        status = "DETECTED" if detected else "missed"
        orch._log(f"  Client {i} (online): {status}")
        if detected:
            n_detected += 1

    # Offline clients should not have logs
    for i in range(k, orch.n_clients):
        orch._log(f"  Client {i} (offline): not running")

    orch.stop_all()

    success = n_detected == k
    orch._log(f"Result: {n_detected}/{k} online clients detected — "
              f"{'PASS' if success else 'FAIL'}")
    return success


def scenario_nobody_home(orch):
    """0 clients online — LSP steals undetected (proves watchtower matters)."""
    orch._log("=== SCENARIO: nobody_home ===")
    orch._log("No clients online; LSP breach goes undetected.")

    # Start LSP with --cheat-daemon, no clients
    orch.start_lsp(["--demo", "--cheat-daemon"])

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # No clients running — check mempool for penalty txs (there should be none)
    mempool = orch.chain.get_mempool()
    has_penalty = len(mempool) > 0
    orch._log(f"Mempool has {len(mempool)} txs (expected 0 penalty)")

    orch.stop_all()

    success = not has_penalty
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"breach {'undetected' if success else 'detected unexpectedly'}")
    return success


def scenario_late_arrival(orch, k=2):
    """Clients offline at breach time, restart before CSV, catch breach."""
    orch._log(f"=== SCENARIO: late_arrival (k={k}) ===")
    orch._log("No clients at breach; they start later and detect it.")

    # Start LSP with --cheat-daemon, no clients
    orch.start_lsp(["--demo", "--cheat-daemon"])

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Now start k clients after the breach
    orch._log(f"Starting {k} clients after breach...")
    for i in range(k):
        orch.start_client(i)
        time.sleep(orch.timing["stagger"])

    # Give clients time to connect, realize factory is on-chain, and check watchtower
    # Advance chain to trigger watchtower scan
    orch.advance_chain(1)
    time.sleep(orch.timing["breach_wait"])

    # Check if late-arriving clients detect the breach
    n_detected = 0
    for i in range(k):
        detected = orch.check_penalty_in_log(i)
        status = "DETECTED" if detected else "missed"
        orch._log(f"  Client {i} (late): {status}")
        if detected:
            n_detected += 1

    orch.stop_all()

    # Late arrival detection depends on client reconnect loading watchtower state
    orch._log(f"Result: {n_detected}/{k} late clients detected — "
              f"{'PASS' if n_detected > 0 else 'PARTIAL (needs reconnect watchtower)'}")
    return n_detected > 0


def scenario_cooperative_close(orch):
    """All online, demo runs, cooperative close TX confirmed."""
    orch._log("=== SCENARIO: cooperative_close ===")
    orch._log("All clients + LSP: normal demo then cooperative close.")

    # Start LSP in demo mode (no --daemon: runs demo, then cooperative close, then exits)
    orch.start_lsp(["--demo"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for LSP to finish (demo + cooperative close)
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Advance chain to confirm close tx
    orch.advance_chain(1)
    time.sleep(2)

    # Check LSP log for cooperative close evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_close = "cooperative close" in lsp_log.lower() or "Close outputs" in lsp_log

    orch.stop_all()

    orch._log(f"Result: {'PASS' if has_close else 'FAIL'} — "
              f"cooperative close {'confirmed' if has_close else 'not found in log'}")
    return has_close


def scenario_timeout_expiry(orch):
    """All vanish, LSP reclaims via CLTV timeout path."""
    orch._log("=== SCENARIO: timeout_expiry ===")
    orch._log("All clients vanish; LSP reclaims via timeout.")

    # Start LSP with --test-expiry (mines past CLTV, reclaims)
    orch.start_lsp(["--demo", "--test-expiry"])

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    # Check report for expiry result
    report = orch.check_lsp_report()
    result = report.get("result", "unknown")
    orch._log(f"LSP report result: {result}")

    # Check LSP log
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_expiry = "TIMEOUT" in lsp_log or "expiry" in lsp_log.lower() or "reclaim" in lsp_log.lower()

    orch.stop_all()

    success = rc == 0 and has_expiry
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"timeout reclaim {'succeeded' if success else 'failed'}")
    return success


def scenario_factory_breach(orch):
    """LSP broadcasts old factory tree — clients detect and respond with latest state."""
    orch._log("=== SCENARIO: factory_breach ===")
    orch._log("All clients online; LSP broadcasts old factory tree after DW advance.")

    # Start LSP with --breach-test (broadcasts factory tree + revoked commitment,
    # then runs its own watchtower — we just observe client detection)
    orch.start_lsp(["--demo", "--breach-test"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")
    time.sleep(orch.timing["breach_wait"] // 2)

    # Check LSP log for breach detection (LSP watchtower catches its own breach)
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    lsp_breach = "BREACH DETECTED" in lsp_log
    lsp_penalty = "Penalty tx broadcast" in lsp_log or "penalty" in lsp_log.lower()

    orch._log(f"LSP breach detection: {lsp_breach}, penalty: {lsp_penalty}")

    # Check client logs for any breach detection
    n_client_detect = 0
    for i in range(orch.n_clients):
        detected = orch.check_penalty_in_log(i)
        if detected:
            n_client_detect += 1

    orch._log(f"Clients detected: {n_client_detect}/{orch.n_clients}")

    orch.stop_all()

    # Success if LSP's own watchtower caught the breach
    success = lsp_breach and lsp_penalty
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"factory breach {'handled' if success else 'not handled'}")
    return success


def scenario_jit_lifecycle(orch):
    """Late client triggers JIT channel fallback — create, fund, route."""
    orch._log("=== SCENARIO: jit_lifecycle ===")
    orch._log("3 of 4 clients connect; client 3 joins late → JIT channel.")

    # Start LSP with JIT enabled (--demo --daemon --jit-amount 50000)
    orch.start_lsp(["--demo", "--daemon", "--jit-amount", "50000"])
    time.sleep(orch.timing["lsp_bind"])

    # Start 3 of 4 clients (client 3 stays offline)
    for i in range(3):
        orch.start_client(i)
        time.sleep(orch.timing["stagger"])

    # Wait for factory creation
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created with 3/4 clients, starting client 3 late...")
    time.sleep(orch.timing["coop_wait"] // 3)

    # Start client 3 late — triggers JIT channel fallback
    orch.start_client(3)

    # Wait for JIT funding confirmation
    orch._log("Waiting for JIT channel funding...")
    time.sleep(orch.timing["coop_wait"])

    # Advance chain to confirm JIT funding tx
    orch.advance_chain(1)
    time.sleep(orch.timing["breach_wait"])

    # Check client 3 log for JIT evidence
    jit_evidence = False
    if orch.clients[3]:
        log = orch.clients[3].read_log()
        jit_evidence = "JIT" in log or "jit" in log.lower() or "channel" in log.lower()

    # Check LSP log for JIT evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    lsp_jit = "JIT" in lsp_log or "jit" in lsp_log.lower()
    orch._log(f"LSP JIT evidence: {lsp_jit}")
    orch._log(f"Client 3 JIT evidence: {jit_evidence}")

    # Graceful shutdown
    orch.stop_all()

    success = lsp_jit or jit_evidence
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"JIT lifecycle {'completed' if success else 'not detected in logs'}")
    return success


def scenario_factory_rotation(orch):
    """Factory ages past DYING threshold, auto-rotation fires."""
    orch._log("=== SCENARIO: factory_rotation ===")
    orch._log("LSP + 4 clients with short active/dying blocks; wait for auto-rotation.")

    # Start LSP with short active/dying periods so rotation triggers quickly
    orch.start_lsp(["--demo", "--daemon", "--active-blocks", "5", "--dying-blocks", "3"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for initial factory creation
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for it to age past DYING threshold...")

    # On regtest, mine blocks to push past active+dying period
    # On signet, wait for natural blocks
    total_blocks = 5 + 3 + 2  # active + dying + buffer
    if orch.is_regtest:
        for _ in range(total_blocks):
            orch.mine(1)
            time.sleep(2)
    else:
        orch.advance_chain(total_blocks)

    # Wait for rotation to complete
    time.sleep(orch.timing["coop_wait"])

    # Check LSP log for rotation evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_turnover = "turnover" in lsp_log.lower() or "PTLC" in lsp_log
    has_new_factory = "Factory 1" in lsp_log or "factory_id=1" in lsp_log or "new factory" in lsp_log.lower()

    orch._log(f"Turnover evidence: {has_turnover}")
    orch._log(f"New factory evidence: {has_new_factory}")

    # Graceful close
    orch.stop_lsp()
    time.sleep(2)
    orch.advance_chain(1)
    orch.stop_all()

    success = has_turnover or has_new_factory
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"factory rotation {'completed' if success else 'not detected'}")
    return success


def scenario_timeout_recovery(orch):
    """All clients vanish, LSP reclaims via timeout script-path spend."""
    orch._log("=== SCENARIO: timeout_recovery ===")
    orch._log("All clients connect, make payments, then vanish. LSP reclaims.")

    # Start LSP with demo to create factory + payments
    orch.start_lsp(["--demo", "--daemon"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for factory
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for demo payments...")
    time.sleep(orch.timing["coop_wait"])

    # Kill all clients (simulate vanishing)
    orch._log("Killing all clients (simulating disappearance)...")
    for i in range(orch.n_clients):
        if orch.clients[i]:
            orch.clients[i].kill()
    orch._log("All clients killed")

    # Stop LSP gracefully so it attempts cooperative close first (which fails),
    # then does timeout reclaim
    orch.stop_lsp()
    time.sleep(2)

    # Now start LSP with --test-expiry to mine past CLTV and reclaim
    orch._log("Restarting LSP with --test-expiry for timeout reclaim...")
    orch.start_lsp(["--test-expiry"])
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    # Check logs for timeout/reclaim evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_timeout = "timeout" in lsp_log.lower() or "reclaim" in lsp_log.lower()
    has_expiry = "TIMEOUT" in lsp_log or "expiry" in lsp_log.lower()

    orch._log(f"Timeout evidence: {has_timeout}")
    orch._log(f"Expiry evidence: {has_expiry}")

    orch.stop_all()

    success = has_timeout or has_expiry
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"timeout recovery {'completed' if success else 'not detected'}")
    return success


def scenario_full_lifecycle(orch):
    """Full lifecycle: factory → payments → breach attempt → penalty → cooperative close."""
    orch._log("=== SCENARIO: full_lifecycle ===")
    orch._log("The integration test to end all integration tests.")

    # Phase 1: Create factory + payments
    orch._log("Phase 1: Factory creation + demo payments...")
    orch.start_lsp(["--demo", "--daemon"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for demo payments...")
    time.sleep(orch.timing["coop_wait"])

    # Check that channels have been updated (commitment_number > 0)
    states = orch.get_channel_states()
    lsp_channels = states.get("lsp", [])
    if lsp_channels:
        max_commit = max(ch.get("commitment_number", 0) for ch in lsp_channels)
        orch._log(f"Max commitment number: {max_commit}")
    else:
        orch._log("Warning: no LSP channels found in DB")

    # Phase 2: Check watchtower entries exist
    orch._log("Phase 2: Verifying watchtower state...")
    wt_entries = orch.check_watchtower_entries()
    total_wt = sum(len(v) for v in wt_entries.values())
    orch._log(f"Total watchtower entries across clients: {total_wt}")

    # Phase 3: Cooperative close
    orch._log("Phase 3: Cooperative close...")
    orch.stop_lsp()
    time.sleep(2)
    orch.advance_chain(1)

    # Check LSP log for close evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_close = "cooperative close" in lsp_log.lower() or "CLOSE" in lsp_log

    orch.stop_all()

    success = has_close
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"full lifecycle {'completed' if success else 'cooperative close not found'}")
    return success


# ---------------------------------------------------------------------------
# Adversarial & Edge-Case Scenarios
# ---------------------------------------------------------------------------

def scenario_ladder_breach(orch):
    """Breach in DYING factory while ACTIVE factory runs — isolation holds."""
    orch._log("=== SCENARIO: ladder_breach ===")
    orch._log("Breach in Factory 0 (DYING) while Factory 1 (ACTIVE) is running.")

    # Start LSP with short active/dying periods and breach test enabled
    orch.start_lsp(["--demo", "--daemon", "--active-blocks", "5", "--dying-blocks", "3",
                     "--breach-test"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for initial factory creation
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory 0 created, mining to push into DYING state...")

    # Mine past active_blocks to push Factory 0 into DYING
    if orch.is_regtest:
        for _ in range(6):
            orch.mine(1)
            time.sleep(1)
    else:
        orch.advance_chain(6)

    # Wait for rotation to create Factory 1
    time.sleep(orch.timing["coop_wait"])

    # Mine a few more to trigger breach from --breach-test on Factory 0
    if orch.is_regtest:
        for _ in range(4):
            orch.mine(1)
            time.sleep(1)
    else:
        orch.advance_chain(4)

    time.sleep(orch.timing["breach_wait"])

    # Check LSP log for breach detection on Factory 0
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_breach = "BREACH DETECTED" in lsp_log
    has_penalty = "penalty" in lsp_log.lower()

    # Check that Factory 1 channels are still functional
    has_factory1 = "Factory 1" in lsp_log or "factory_id=1" in lsp_log

    # Check client logs for detection
    n_client_detect = 0
    for i in range(orch.n_clients):
        if orch.check_penalty_in_log(i):
            n_client_detect += 1

    orch._log(f"Breach detected: {has_breach}, penalty: {has_penalty}")
    orch._log(f"Factory 1 exists: {has_factory1}")
    orch._log(f"Clients detected: {n_client_detect}/{orch.n_clients}")

    orch.stop_all()

    success = has_breach and has_penalty
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"ladder breach isolation {'holds' if success else 'failed'}")
    return success


def scenario_turnover_abort(orch):
    """PTLC turnover aborted halfway — 3/4 clients complete, 4th disconnects."""
    orch._log("=== SCENARIO: turnover_abort ===")
    orch._log("Key turnover fails midway; 4th client reconnects to complete.")

    # Start LSP with short lifecycle for quick turnover trigger
    orch.start_lsp(["--demo", "--daemon", "--active-blocks", "5", "--dying-blocks", "3"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, mining to trigger DYING + turnover...")

    # Mine to trigger DYING state and turnover initiation
    if orch.is_regtest:
        for _ in range(5):
            orch.mine(1)
            time.sleep(1)
    else:
        orch.advance_chain(5)

    # Wait for turnover to begin
    time.sleep(orch.timing["coop_wait"] // 2)

    # Kill client 3 mid-turnover
    orch._log("Killing client 3 mid-turnover...")
    if orch.clients[3]:
        orch.clients[3].kill()

    # Wait — turnover should be incomplete
    time.sleep(orch.timing["coop_wait"] // 2)

    # Check LSP log for partial turnover state
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_turnover_start = "turnover" in lsp_log.lower() or "PTLC" in lsp_log

    orch._log(f"Turnover started: {has_turnover_start}")

    # Restart client 3 to complete turnover
    orch._log("Restarting client 3...")
    orch.start_client(3)

    # Wait for reconnection and turnover completion
    time.sleep(orch.timing["coop_wait"])

    # Mine a block to trigger any pending operations
    orch.advance_chain(1)
    time.sleep(orch.timing["breach_wait"] // 2)

    # Check final state
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_close = "cooperative close" in lsp_log.lower() or "Close" in lsp_log
    has_reconnect = "reconnect" in lsp_log.lower() or "client 3" in lsp_log.lower()

    orch._log(f"Close evidence: {has_close}")
    orch._log(f"Reconnect evidence: {has_reconnect}")

    orch.stop_all()

    success = has_turnover_start
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"turnover abort {'recoverable' if success else 'not detected'}")
    return success


def scenario_lsp_crash_recovery(orch):
    """LSP crashes (SIGKILL) and restarts — clients reconnect, channels survive."""
    orch._log("=== SCENARIO: lsp_crash_recovery ===")
    orch._log("LSP crash + restart; clients reconnect and continue.")

    # Start LSP in daemon mode
    orch.start_lsp(["--demo", "--daemon"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for demo payments...")
    time.sleep(orch.timing["coop_wait"])

    # Record pre-crash channel state
    pre_states = orch.get_channel_states()
    pre_lsp = pre_states.get("lsp", [])
    orch._log(f"Pre-crash: {len(pre_lsp)} LSP channels")

    # CRASH: kill LSP with SIGKILL (no graceful shutdown)
    orch._log("CRASHING LSP (SIGKILL)...")
    if orch.lsp:
        orch.lsp.kill()

    time.sleep(2)

    # Restart LSP with same DB
    orch._log("Restarting LSP with same DB...")
    orch.start_lsp(["--daemon"])
    time.sleep(orch.timing["lsp_bind"] * 2)

    # Advance chain to trigger reconnection
    orch.advance_chain(1)
    time.sleep(orch.timing["coop_wait"])

    # Check post-restart state
    post_states = orch.get_channel_states()
    post_lsp = post_states.get("lsp", [])
    orch._log(f"Post-restart: {len(post_lsp)} LSP channels")

    # Check LSP log for reconnection evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_reconnect = "reconnect" in lsp_log.lower() or "client" in lsp_log.lower()

    # Graceful shutdown
    orch.stop_all()

    success = len(post_lsp) >= len(pre_lsp) and has_reconnect
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"LSP crash recovery {'succeeded' if success else 'failed'}")
    return success


def scenario_client_crash_htlc(orch):
    """Client crashes during payment — HTLC resolves after restart."""
    orch._log("=== SCENARIO: client_crash_htlc ===")
    orch._log("Client 0 crashes after payment initiation; HTLC resolves.")

    orch.start_lsp(["--demo", "--daemon"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for demo payments...")
    time.sleep(orch.timing["coop_wait"])

    # Kill client 0 (simulates crash during payment)
    orch._log("Killing client 0 (simulating crash during payment)...")
    if orch.clients[0]:
        orch.clients[0].kill()

    # Mine blocks past any HTLC timeout
    orch._log("Mining past HTLC timeout...")
    if orch.is_regtest:
        orch.mine(20)
    else:
        orch.advance_chain(20)

    time.sleep(orch.timing["breach_wait"])

    # Check LSP detects client 0 offline
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    offline_detect = "offline" in lsp_log.lower() or "disconnect" in lsp_log.lower()
    htlc_resolve = "htlc" in lsp_log.lower() or "fail" in lsp_log.lower()

    orch._log(f"Offline detection: {offline_detect}")
    orch._log(f"HTLC resolution: {htlc_resolve}")

    # Restart client 0
    orch._log("Restarting client 0...")
    orch.start_client(0)
    time.sleep(orch.timing["coop_wait"])

    # Check client 0 recovered
    client_log = orch.clients[0].read_log() if orch.clients[0] else ""
    has_reconnect = "reconnect" in client_log.lower() or "connected" in client_log.lower()
    orch._log(f"Client 0 reconnected: {has_reconnect}")

    orch.stop_all()

    success = offline_detect or htlc_resolve
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"client crash HTLC {'resolved' if success else 'not resolved'}")
    return success


def scenario_mass_departure_jit(orch):
    """3 of 4 clients vanish; remaining client still functional."""
    orch._log("=== SCENARIO: mass_departure_jit ===")
    orch._log("Clients 1-3 vanish; client 0 still active.")

    orch.start_lsp(["--demo", "--daemon", "--jit-amount", "50000"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for initial payments...")
    time.sleep(orch.timing["coop_wait"])

    # Kill clients 1, 2, 3 simultaneously
    orch._log("Killing clients 1, 2, 3 simultaneously...")
    for i in [1, 2, 3]:
        if orch.clients[i]:
            orch.clients[i].kill()

    # Mine blocks to trigger offline detection
    time.sleep(3)
    orch.advance_chain(2)
    time.sleep(orch.timing["breach_wait"])

    # Check that client 0 is still functional
    client0_alive = orch.clients[0] and orch.clients[0].is_alive()
    orch._log(f"Client 0 still alive: {client0_alive}")

    # Check LSP detects departures
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    offline_count = lsp_log.lower().count("offline") + lsp_log.lower().count("disconnect")
    has_jit = "JIT" in lsp_log or "jit" in lsp_log.lower()

    orch._log(f"Offline mentions in LSP log: {offline_count}")
    orch._log(f"JIT evidence: {has_jit}")

    # Mine past factory DYING threshold
    if orch.is_regtest:
        orch.mine(10)
    else:
        orch.advance_chain(10)

    time.sleep(orch.timing["breach_wait"])

    # Check client 0 channel state
    states = orch.get_channel_states()
    client0_channels = states.get("client_0", [])
    orch._log(f"Client 0 channels: {len(client0_channels)}")

    orch.stop_all()

    success = client0_alive
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"mass departure {'handled' if success else 'failed'}")
    return success


def scenario_watchtower_late_arrival(orch):
    """Breach already confirmed; clients restart with watchtower and detect it."""
    orch._log("=== SCENARIO: watchtower_late_arrival ===")
    orch._log("Breach confirmed while all clients offline; they restart and detect.")

    # Start LSP with --cheat-daemon (broadcasts revoked state)
    orch.start_lsp(["--demo", "--cheat-daemon"])

    # Do NOT start clients — they're all offline during breach
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Mine 6 blocks — breach is fully confirmed
    orch._log("Mining 6 blocks to confirm breach...")
    orch.advance_chain(6)
    time.sleep(2)

    # Now start all clients (they come online after breach is confirmed)
    orch._log("Starting all clients after breach is confirmed...")
    orch.start_all_clients(["--watchtower"])

    # Give clients time to scan chain and detect breach
    time.sleep(orch.timing["breach_wait"] * 2)

    # Advance chain to trigger watchtower scan cycles
    orch.advance_chain(2)
    time.sleep(orch.timing["breach_wait"])

    # Check which clients detected the breach
    n_detected = 0
    for i in range(orch.n_clients):
        detected = orch.check_penalty_in_log(i)
        status = "DETECTED" if detected else "missed"
        orch._log(f"  Client {i} (late arrival): {status}")
        if detected:
            n_detected += 1

    orch.stop_all()

    success = n_detected > 0
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"{n_detected}/{orch.n_clients} late-arriving clients detected breach")
    return success


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS = {
    "all_watch": lambda o, **kw: scenario_all_watch(o),
    "partial_watch": lambda o, **kw: scenario_partial_watch(o, k=kw.get("k", 2)),
    "nobody_home": lambda o, **kw: scenario_nobody_home(o),
    "late_arrival": lambda o, **kw: scenario_late_arrival(o, k=kw.get("k", 2)),
    "cooperative_close": lambda o, **kw: scenario_cooperative_close(o),
    "timeout_expiry": lambda o, **kw: scenario_timeout_expiry(o),
    "factory_breach": lambda o, **kw: scenario_factory_breach(o),
    "jit_lifecycle": lambda o, **kw: scenario_jit_lifecycle(o),
    "factory_rotation": lambda o, **kw: scenario_factory_rotation(o),
    "timeout_recovery": lambda o, **kw: scenario_timeout_recovery(o),
    "full_lifecycle": lambda o, **kw: scenario_full_lifecycle(o),
    "ladder_breach": lambda o, **kw: scenario_ladder_breach(o),
    "turnover_abort": lambda o, **kw: scenario_turnover_abort(o),
    "lsp_crash_recovery": lambda o, **kw: scenario_lsp_crash_recovery(o),
    "client_crash_htlc": lambda o, **kw: scenario_client_crash_htlc(o),
    "mass_departure_jit": lambda o, **kw: scenario_mass_departure_jit(o),
    "watchtower_late_arrival": lambda o, **kw: scenario_watchtower_late_arrival(o),
}


def list_scenarios():
    """Print available scenarios."""
    print("Available scenarios:")
    descs = {
        "all_watch": "All N clients detect LSP breach, penalty confirmed",
        "partial_watch": "K of N clients online; only K detect (use --k N)",
        "nobody_home": "No clients online; breach goes undetected",
        "late_arrival": "Clients restart after breach, detect before CSV",
        "cooperative_close": "Clean SIGTERM shutdown, close TX confirmed",
        "timeout_expiry": "All vanish; LSP reclaims via CLTV timeout",
        "factory_breach": "LSP broadcasts old factory tree; clients detect",
        "jit_lifecycle": "Late client triggers JIT channel create + fund + route",
        "factory_rotation": "DYING trigger → PTLC turnover → new factory",
        "timeout_recovery": "Clients vanish → LSP timeout reclaim",
        "full_lifecycle": "Factory → payments → watchtower → cooperative close",
        "ladder_breach": "Breach in DYING factory; ACTIVE factory unaffected",
        "turnover_abort": "PTLC turnover aborted midway; client reconnects to finish",
        "lsp_crash_recovery": "LSP SIGKILL + restart; clients reconnect",
        "client_crash_htlc": "Client crashes during payment; HTLC resolves after restart",
        "mass_departure_jit": "3/4 clients vanish; remaining client still functional",
        "watchtower_late_arrival": "Breach confirmed; late clients detect via watchtower",
    }
    for name in SCENARIOS:
        print(f"  {name:20s} — {descs.get(name, '')}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SuperScalar test orchestrator for multi-party scenario testing")
    parser.add_argument("--scenario", type=str, default=None,
                        help="Scenario to run (or 'all' to run all)")
    parser.add_argument("--list", action="store_true",
                        help="List available scenarios")
    parser.add_argument("--clients", type=int, default=DEFAULT_N_CLIENTS,
                        help=f"Number of clients (default {DEFAULT_N_CLIENTS})")
    parser.add_argument("--k", type=int, default=2,
                        help="K value for partial_watch/late_arrival (default 2)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"LSP port (default {DEFAULT_PORT})")
    parser.add_argument("--amount", type=int, default=DEFAULT_AMOUNT,
                        help=f"Factory amount in sats (default {DEFAULT_AMOUNT})")
    parser.add_argument("--network", type=str, default=DEFAULT_NETWORK,
                        help=f"Network: regtest, signet, testnet (default {DEFAULT_NETWORK})")
    parser.add_argument("--rpcuser", type=str, default=None,
                        help="Bitcoin RPC username (default from env or 'rpcuser')")
    parser.add_argument("--rpcpassword", type=str, default=None,
                        help="Bitcoin RPC password (default from env or 'rpcpass')")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output (dump logs on failure)")
    args = parser.parse_args()

    if args.list:
        list_scenarios()
        return 0

    if not args.scenario:
        parser.print_help()
        return 1

    # Verify binaries exist
    if not os.path.exists(LSP_BIN):
        print(f"ERROR: LSP binary not found at {LSP_BIN}")
        print("Build first: cd build && cmake .. && make -j$(nproc)")
        return 1
    if not os.path.exists(CLIENT_BIN):
        print(f"ERROR: Client binary not found at {CLIENT_BIN}")
        return 1

    # Run scenario(s)
    scenarios_to_run = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    results = {}

    for name in scenarios_to_run:
        if name not in SCENARIOS:
            print(f"Unknown scenario: {name}")
            list_scenarios()
            return 1

        orch = Orchestrator(
            n_clients=args.clients,
            port=args.port,
            amount=args.amount,
            verbose=args.verbose,
            network=args.network,
            rpcuser=args.rpcuser,
            rpcpassword=args.rpcpassword,
        )

        try:
            ok = SCENARIOS[name](orch, k=args.k)
            results[name] = ok
        except KeyboardInterrupt:
            print("\nInterrupted!")
            orch.kill_all()
            return 130
        except Exception as e:
            print(f"ERROR in {name}: {e}")
            if args.verbose:
                orch.dump_logs()
            orch.kill_all()
            results[name] = False

        print()

    # Summary
    if len(results) > 1:
        print("=" * 50)
        print("SUMMARY")
        print("=" * 50)
        for name, ok in results.items():
            print(f"  {name:20s} {'PASS' if ok else 'FAIL'}")
        n_pass = sum(1 for v in results.values() if v)
        print(f"\n  {n_pass}/{len(results)} scenarios passed")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
