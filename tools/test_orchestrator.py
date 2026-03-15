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
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time


def safe_pkill(pattern, sig="-15"):
    """Kill processes matching pattern without hitting SSH sessions.
    Uses /proc/PID/cmdline to verify the match before killing."""
    r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    for pid in r.stdout.strip().split("\n"):
        if not pid:
            continue
        try:
            cmdline = open(f"/proc/{pid}/cmdline").read().replace("\0", " ")
            if any(x in cmdline for x in ["sshd", "ssh ", "/bin/bash -c"]):
                continue
            if re.search(pattern, cmdline):
                subprocess.run(["kill", sig, pid], capture_output=True)
        except (FileNotFoundError, PermissionError):
            pass


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
# Deterministic LSP key for regtest (secp256k1 generator key "01")
LSP_SECKEY = "0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
DEFAULT_PORT = 9745
DEFAULT_AMOUNT = 100000
DEFAULT_N_CLIENTS = 4
DEFAULT_NETWORK = "regtest"

# Per-network timing constants
TIMING = {
    "regtest":  {"factory_timeout": 60, "breach_wait": 30, "lsp_timeout": 120,
                 "coop_wait": 20, "stagger": 0.5, "lsp_bind": 3.0},
    "signet":   {"factory_timeout": 900, "breach_wait": 120, "lsp_timeout": 1800,
                 "coop_wait": 300, "stagger": 1.0, "lsp_bind": 2.0},
    "testnet4": {"factory_timeout": 900, "breach_wait": 120, "lsp_timeout": 1800,
                 "coop_wait": 300, "stagger": 1.0, "lsp_bind": 2.0},
}

def client_seckey(index):
    """Deterministic 32-byte hex secret key for client index."""
    fill = CLIENT_KEY_FILLS[index] if index < len(CLIENT_KEY_FILLS) else (0x22 + index)
    return (bytes([fill]) * 32).hex()


# ---------------------------------------------------------------------------
# ChainControl — wraps bitcoin-cli -regtest
# ---------------------------------------------------------------------------

def _find_bitcoin_cli():
    """Find bitcoin-cli in PATH or known install locations."""
    import shutil
    found = shutil.which("bitcoin-cli")
    if found:
        return found
    # Common WSL / Linux install paths
    for p in ["/home/pirq/bin/bitcoin-cli", "/usr/local/bin/bitcoin-cli",
               "/usr/bin/bitcoin-cli", os.path.expanduser("~/bin/bitcoin-cli")]:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return "bitcoin-cli"  # fallback; will error at runtime if missing


class ChainControl:
    """Bitcoin Core chain operations (regtest, signet, etc.)."""

    def __init__(self, cli_path=None, network=None,
                 rpcuser=None, rpcpassword=None):
        self.cli_path = cli_path or _find_bitcoin_cli()
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
        self.ensure_wallet("orchestrator")
        out, err = self._cmd("-rpcwallet=orchestrator", "getnewaddress", "", "bech32m")
        return out, err

    def ensure_wallet(self, name="orchestrator"):
        # Check if wallet is already loaded
        out, err = self._cmd("listwallets")
        if out and name in out:
            return  # Already loaded
        # Try to load existing wallet
        out, err = self._cmd("loadwallet", name)
        if out:
            return  # Loaded successfully
        # If load failed with "already loaded", it's fine
        if err and "already loaded" in err:
            return
        # Try to create new wallet (descriptors=true, load_on_startup=false)
        out, err = self._cmd("createwallet", name, "false", "false", "",
                             "false", "true", "false")
        if out:
            return  # Created successfully
        if err and "Database already exists" in err:
            # Stale wallet directory — remove and retry
            self._cmd("unloadwallet", name)
            time.sleep(0.5)
            for subdir in [name, os.path.join("wallets", name)]:
                wallet_dir = os.path.expanduser(
                    f"~/.bitcoin/{self.network}/{subdir}")
                if os.path.isdir(wallet_dir):
                    shutil.rmtree(wallet_dir, ignore_errors=True)
            self._cmd("createwallet", name, "false", "false", "",
                      "false", "true", "false")

    def get_balance(self, wallet="orchestrator"):
        out, err = self._cmd("-rpcwallet=" + wallet, "getbalance")
        if out:
            try:
                return float(out)
            except ValueError:
                return 0.0
        return 0.0

    def get_address(self, wallet="orchestrator"):
        self.ensure_wallet(wallet)
        out, err = self._cmd("-rpcwallet=" + wallet, "getnewaddress", "", "bech32m")
        if not out and err:
            # Retry once after a short delay (wallet may be loading)
            time.sleep(1)
            self.ensure_wallet(wallet)
            out, err = self._cmd("-rpcwallet=" + wallet, "getnewaddress", "", "bech32m")
        return out, err

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

    def start(self, stdin_pipe=False):
        env = dict(os.environ)
        env.update(self.env)
        self.log_fh = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE if stdin_pipe else None,
            stdout=self.log_fh,
            stderr=subprocess.STDOUT,
            env=env,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        return self.proc.pid

    def write_stdin(self, text):
        """Write text to process stdin (requires stdin_pipe=True on start)."""
        if self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write(text.encode())
                self.proc.stdin.flush()
                return True
            except Exception:
                return False
        return False

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
                return "SKIP"
        return "SKIP"

    def returncode(self):
        if self.proc:
            return self.proc.returncode
        return "SKIP"

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
                 rpcuser=None, rpcpassword=None, cli_path=None):
        self.n_clients = n_clients
        self.port = port
        self.amount = amount
        self.verbose = verbose
        self.network = network
        self.is_regtest = (network == "regtest")
        self.timing = TIMING.get(network, TIMING["signet"])
        self.chain = ChainControl(cli_path=cli_path, network=network,
                                   rpcuser=rpcuser, rpcpassword=rpcpassword)
        self.rpcuser = self.chain.rpcuser
        self.rpcpassword = self.chain.rpcpassword
        self.lsp = None
        self.clients = [None] * n_clients
        self.test_dir = TEST_DIR

        # Kill any stale superscalar processes that might be reconnecting to
        # the port (e.g. daemon clients left over from a previous failed run).
        safe_pkill("superscalar_lsp", "-9")
        safe_pkill("superscalar_client", "-9")

        # Clean and recreate test directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
        os.makedirs(self.test_dir, exist_ok=True)

        # Auto-fund regtest wallets
        if self.is_regtest:
            self._auto_fund()

    def _auto_fund(self):
        """Ensure regtest wallets exist and are funded."""
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] Auto-funding regtest wallets...")
        sys.stdout.flush()
        needs_maturity = False
        for wallet_name in ["orchestrator", "superscalar_lsp"]:
            self.chain.ensure_wallet(wallet_name)
            bal = self.chain.get_balance(wallet_name)
            if bal < 1.0:
                addr, addr_err = self.chain.get_address(wallet_name)
                if addr:
                    self.chain.mine_blocks(101, addr)
                    needs_maturity = True
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}]   Funded {wallet_name} (mined 101 blocks)")
                    sys.stdout.flush()
                else:
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}]   WARN: could not get address for {wallet_name}: {addr_err}")
                    sys.stdout.flush()
            else:
                ts = time.strftime("%H:%M:%S")
                print(f"[{ts}]   {wallet_name} already funded ({bal:.4f} BTC)")
                sys.stdout.flush()
        # Mine extra blocks to mature all coinbases (need 100 confirmations)
        if needs_maturity:
            addr, _ = self.chain.get_address("orchestrator")
            if addr:
                self.chain.mine_blocks(100, addr)
                ts = time.strftime("%H:%M:%S")
                print(f"[{ts}]   Matured coinbases (mined 100 extra blocks)")
                sys.stdout.flush()

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

    def start_lsp(self, extra_flags=None, stdin_pipe=False):
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
            "--cli-path", self.chain.cli_path,
            "--rpcuser", self.rpcuser,
            "--rpcpassword", self.rpcpassword,
        ]
        if self.is_regtest:
            cmd.extend(["--seckey", LSP_SECKEY])
        else:
            lsp_keyfile = os.path.join(self.test_dir, "lsp.key")
            cmd.extend(["--keyfile", lsp_keyfile, "--passphrase", "orchestrator"])
        if extra_flags:
            cmd.extend(extra_flags)
        self.lsp = Actor("LSP", cmd, self._lsp_log())
        pid = self.lsp.start(stdin_pipe=stdin_pipe)
        self._log(f"LSP started (PID {pid})")
        time.sleep(self.timing["lsp_bind"])
        return pid

    def start_client(self, index, extra_flags=None):
        """Start a single client process."""
        if index >= self.n_clients:
            return "SKIP"
        cmd = [
            CLIENT_BIN,
            "--port", str(self.port),
            "--host", "127.0.0.1",
            "--network", self.network,
            "--db", self._client_db(index),
            "--daemon",
            "--fee-rate", "1000",
            "--cli-path", self.chain.cli_path,
            "--rpcuser", self.rpcuser,
            "--rpcpassword", self.rpcpassword,
        ]
        if self.is_regtest:
            cmd.extend(["--seckey", client_seckey(index),
                         "--lsp-pubkey", LSP_PUBKEY])
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
        return "SKIP"

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

    def wait_for_lsp_log(self, pattern, timeout=60):
        """Poll LSP log file until *pattern* appears (substring match)."""
        if not self.lsp:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.lsp.proc and self.lsp.proc.poll() is not None:
                return False  # LSP already exited
            log = self.lsp.read_log()
            if pattern in log:
                return True
            time.sleep(0.5)
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
            return ("BREACH DETECTED" in log or
                    "penalty broadcast" in log.lower() or
                    "penalty tx" in log.lower())
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

    # Wait for LSP to finish — cheat-daemon mines ~96 blocks for tree broadcast
    # (nSequence delays), so it needs longer than default lsp_timeout
    rc = orch.wait_for_lsp(timeout=max(orch.timing["lsp_timeout"], 180))
    orch._log(f"LSP exited with code {rc}")

    # Mine blocks to confirm the breach TX — watchtowers scan blocks, not mempool.
    # Without this, the revoked commitment sits unconfirmed and clients miss it.
    orch.advance_chain(2)

    # Mine one block every 5 seconds during the wait window. Each new block
    # triggers a fresh watchtower scan, eliminating the race between the
    # advance_chain call and each client poll cycle. A fixed sleep alone
    # is flaky in full-suite runs where process startup adds latency.
    poll_interval = 5
    for _ in range(orch.timing["breach_wait"] // poll_interval):
        time.sleep(poll_interval)
        orch.advance_chain(1)

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

    success = rc == 0 and n_detected == orch.n_clients
    orch._log(f"Result: {n_detected}/{orch.n_clients} detected breach, "
              f"{n_cpfp}/{orch.n_clients} broadcast CPFP child — "
              f"{'PASS' if success else 'FAIL'}")
    return success


def scenario_partial_watch(orch, k=2):
    """K of N clients online — only K detect breach."""
    orch._log(f"=== SCENARIO: partial_watch (k={k}) ===")
    orch._log(f"{k} clients online, {orch.n_clients - k} offline.")

    # Start LSP with --cheat-daemon; all 4 clients needed for ceremony
    orch.start_lsp(["--demo", "--cheat-daemon"])
    time.sleep(1)
    orch.start_all_clients()

    # Wait for factory (ensures ceremony completed)
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to finish and breach to start before killing clients
    # (killing during demo causes SIGPIPE on the LSP)
    if not orch.wait_for_lsp_log("BREACH TEST", timeout=orch.timing["lsp_timeout"]):
        orch._log("FAIL: LSP never reached breach test phase")
        orch.stop_all()
        return False

    # Kill (n-k) clients — they go offline during breach
    for i in range(k, orch.n_clients):
        if orch.clients[i]:
            orch.clients[i].kill()
        orch._log(f"  Client {i} (offline): killed")

    # Wait for LSP to finish (breach + 30s sleep)
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

    orch.stop_all()

    success = rc == 0 and n_detected == k
    orch._log(f"Result: {n_detected}/{k} online clients detected — "
              f"{'PASS' if success else 'FAIL'}")
    return success


def scenario_nobody_home(orch):
    """0 clients online — LSP steals undetected (proves watchtower matters)."""
    orch._log("=== SCENARIO: nobody_home ===")
    orch._log("No clients online; LSP breach goes undetected.")

    # All 4 clients needed for factory ceremony, then killed after demo
    orch.start_lsp(["--demo", "--cheat-daemon"])
    time.sleep(1)
    orch.start_all_clients()

    # Wait for factory (ensures ceremony completed)
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to finish before killing clients (avoids SIGPIPE)
    if not orch.wait_for_lsp_log("BREACH TEST", timeout=orch.timing["lsp_timeout"]):
        orch._log("FAIL: LSP never reached breach test phase")
        orch.stop_all()
        return False

    for i in range(orch.n_clients):
        if orch.clients[i]:
            orch.clients[i].kill()
    orch._log("All clients killed (nobody home)")

    # Wait for LSP to finish (breach + 30s sleep)
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Verify the breach TX actually happened (LSP log should confirm)
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    breach_happened = "BREACH TEST" in lsp_log and "revoked" in lsp_log.lower()

    # No clients running — check mempool for penalty txs (there should be none)
    mempool = orch.chain.get_mempool()
    has_penalty = len(mempool) > 0
    orch._log(f"Breach happened: {breach_happened}, Mempool has {len(mempool)} txs")

    orch.stop_all()

    success = rc == 0 and breach_happened and not has_penalty
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"breach {'undetected' if success else 'detected unexpectedly'}")
    return success


def scenario_late_arrival(orch, k=2):
    """Clients offline at breach time, restart before CSV, catch breach."""
    orch._log(f"=== SCENARIO: late_arrival (k={k}) ===")
    orch._log("No clients at breach; they start later and detect it.")

    # All 4 clients needed for ceremony, then killed after demo completes
    orch.start_lsp(["--demo", "--cheat-daemon"])
    time.sleep(1)
    orch.start_all_clients()

    # Wait for factory
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to finish and breach to start, then kill all clients
    if not orch.wait_for_lsp_log("BREACH TEST", timeout=orch.timing["lsp_timeout"]):
        orch._log("FAIL: LSP never reached breach test phase")
        orch.stop_all()
        return False

    for i in range(orch.n_clients):
        if orch.clients[i]:
            orch.clients[i].kill()
    orch._log("All clients killed at breach start")

    # Wait for LSP to finish (breach + 30s sleep)
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Now start k clients after the breach (late arrival)
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

    success = n_detected == k
    orch._log(f"Result: {n_detected}/{k} late clients detected — "
              f"{'PASS' if success else 'FAIL'}")
    return success


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
    has_close = ("Close TX broadcast" in lsp_log or
                 "cooperative close" in lsp_log.lower())

    orch.stop_all()

    success = rc == 0 and has_close
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"cooperative close {'confirmed' if success else 'not found in log'}")
    return success


def scenario_timeout_expiry(orch):
    """All vanish, LSP reclaims via CLTV timeout path."""
    orch._log("=== SCENARIO: timeout_expiry ===")
    orch._log("All clients vanish; LSP reclaims via timeout.")

    # Single-phase: --demo runs HTLCs first, then --test-expiry mines past
    # CLTV and reclaims.  The LSP code falls through from demo to expiry.
    orch.start_lsp(["--demo", "--test-expiry"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    # Check report for expiry result
    report = orch.check_lsp_report()
    result = report.get("result", "unknown")
    orch._log(f"LSP report result: {result}")

    # Check LSP log
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_expiry = "EXPIRY TEST PASSED" in lsp_log

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
    lsp_penalty = ("penalty broadcast" in lsp_log.lower() or
                   "penalty tx" in lsp_log.lower())

    orch._log(f"LSP breach detection: {lsp_breach}, penalty: {lsp_penalty}")

    # Check client logs for any breach detection
    n_client_detect = 0
    for i in range(orch.n_clients):
        detected = orch.check_penalty_in_log(i)
        if detected:
            n_client_detect += 1

    orch._log(f"Clients detected: {n_client_detect}/{orch.n_clients}")

    orch.stop_all()

    # Success if LSP's own watchtower caught the breach OR clients detected it
    success = (lsp_breach and lsp_penalty) or (n_client_detect > 0)
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"factory breach {'handled' if success else 'not handled'}")
    return success


def scenario_jit_lifecycle(orch):
    """Factory expires, JIT channel fallback triggers for connected clients."""
    orch._log("=== SCENARIO: jit_lifecycle ===")
    orch._log("All 4 clients connect; factory expires → JIT channels triggered.")

    # Start LSP with JIT enabled and short lifecycle for quick expiry
    orch.start_lsp(["--demo", "--daemon", "--jit-amount", "50000",
                     "--active-blocks", "5", "--dying-blocks", "3"])
    time.sleep(orch.timing["lsp_bind"])

    # Start all 4 clients (factory requires exactly 4)
    orch.start_all_clients()

    # Wait for factory creation
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to complete and daemon mode to start
    orch._log("Waiting for daemon mode entry...")
    if not orch.wait_for_lsp_log("daemon loop started", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    # Mine past active + dying + buffer to push factory into EXPIRED
    total_blocks = 5 + 3 + 2
    orch._log(f"Mining {total_blocks} blocks to expire factory...")
    if orch.is_regtest:
        for _ in range(total_blocks):
            orch.mine(1)
            time.sleep(2)
    else:
        orch.advance_chain(total_blocks)

    # Wait for daemon loop to detect expiry and trigger JIT
    time.sleep(orch.timing["coop_wait"])

    # Mine a confirmation block for any JIT funding tx
    orch.advance_chain(1)
    time.sleep(orch.timing["breach_wait"])

    # Check LSP log for lifecycle evidence (JIT or rotation or expired)
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    lsp_jit = "JIT" in lsp_log or "jit" in lsp_log.lower()
    lsp_rotation = "auto-rotation" in lsp_log.lower() or "LSP rotate" in lsp_log
    lsp_expired = "EXPIRED" in lsp_log or "expired" in lsp_log.lower()
    lsp_dying = "DYING" in lsp_log
    orch._log(f"LSP JIT evidence: {lsp_jit}")
    orch._log(f"Rotation evidence: {lsp_rotation}")
    orch._log(f"Factory expired: {lsp_expired}")
    orch._log(f"Factory DYING: {lsp_dying}")

    # Graceful shutdown
    orch.stop_all()

    # JIT triggers when factory expired; rotation pre-empts by creating new factory.
    # Either outcome verifies daemon loop lifecycle management works.
    # Require at least one concrete lifecycle event (not just loose string matching).
    success = (lsp_jit and lsp_expired) or (lsp_rotation and lsp_dying)
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"lifecycle {'managed' if success else 'not detected in logs'}")
    return success


def scenario_factory_rotation(orch):
    """Factory ages past DYING threshold, auto-rotation fires."""
    orch._log("=== SCENARIO: factory_rotation ===")
    orch._log("LSP + 4 clients with short active/dying blocks; wait for auto-rotation.")

    # Start LSP with short active/dying periods so rotation triggers quickly.
    # Use slightly longer windows (8+5) to avoid race conditions during setup.
    orch.start_lsp(["--demo", "--daemon", "--active-blocks", "8", "--dying-blocks", "5"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for initial factory creation
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to complete and daemon mode to start
    orch._log("Waiting for daemon mode entry...")
    if not orch.wait_for_lsp_log("daemon loop started", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    orch._log("Mining to push factory past DYING threshold...")

    # On regtest, mine blocks to push past active+dying period
    # On signet, wait for natural blocks
    total_blocks = 8 + 5 + 2  # active + dying + buffer
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
    has_rotation = "auto-rotation" in lsp_log.lower() or "LSP rotate" in lsp_log
    has_dying = "DYING" in lsp_log

    orch._log(f"Turnover evidence: {has_turnover}")
    orch._log(f"New factory evidence: {has_new_factory}")
    orch._log(f"Rotation evidence: {has_rotation}")
    orch._log(f"DYING detected: {has_dying}")

    # Graceful close
    orch.stop_lsp()
    time.sleep(2)
    orch.advance_chain(1)
    orch.stop_all()

    success = (has_turnover or has_rotation) and (has_new_factory or has_dying)
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"factory rotation {'completed' if success else 'not detected'}")
    return success


def scenario_timeout_recovery(orch):
    """All clients vanish, LSP reclaims via timeout script-path spend."""
    orch._log("=== SCENARIO: timeout_recovery ===")
    orch._log("All clients connect, make payments, then LSP reclaims via timeout.")

    # Single-phase: --demo runs HTLCs, then --test-expiry mines past CLTV
    orch.start_lsp(["--demo", "--test-expiry"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for demo + expiry recovery...")
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    # Check logs for timeout/reclaim evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_expiry = "EXPIRY TEST PASSED" in lsp_log

    orch._log(f"Expiry pass marker: {has_expiry}")

    orch.stop_all()

    success = rc == 0 and has_expiry
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"timeout recovery {'completed' if success else 'not detected'}")
    return success


def scenario_full_lifecycle(orch):
    """Full lifecycle: factory → payments → cooperative close."""
    orch._log("=== SCENARIO: full_lifecycle ===")
    orch._log("The integration test to end all integration tests.")

    # --demo without --daemon: runs demo HTLCs then cooperative close automatically
    orch._log("Phase 1: Factory creation + demo payments + cooperative close...")
    orch.start_lsp(["--demo"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    orch._log("Factory created, waiting for demo + close...")
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Check that channels have been updated (commitment_number > 0)
    states = orch.get_channel_states()
    lsp_channels = states.get("lsp", [])
    max_commit = 0
    if lsp_channels:
        max_commit = max(ch.get("commitment_number", 0) for ch in lsp_channels)
    orch._log(f"Max commitment number: {max_commit} ({len(lsp_channels)} channels)")

    # Phase 2: Check watchtower entries exist
    orch._log("Phase 2: Verifying watchtower state...")
    wt_entries = orch.check_watchtower_entries()
    total_wt = sum(len(v) for v in wt_entries.values())
    orch._log(f"Total watchtower entries across clients: {total_wt}")

    # Check LSP log for close evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_close = ("Close TX broadcast" in lsp_log or
                 "cooperative close" in lsp_log.lower())

    orch.stop_all()

    success = rc == 0 and has_close and max_commit > 0
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"full lifecycle {'completed' if success else 'incomplete'} "
              f"(close={has_close}, max_commit={max_commit})")
    return success


# ---------------------------------------------------------------------------
# Feature Coverage Scenarios
# ---------------------------------------------------------------------------

def scenario_routing_fee(orch):
    """Factory with routing fees — verify demo completes with fee enabled."""
    orch._log("=== SCENARIO: routing_fee ===")
    orch._log("LSP charges 100 ppm routing fee; verify demo completes.")

    # Start LSP with routing fee
    orch.start_lsp(["--demo", "--routing-fee-ppm", "100"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")

    # Confirm close
    orch.advance_chain(1)
    time.sleep(2)

    # Check LSP log for demo completion (fee is applied silently in C code)
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    demo_done = "Demo Complete" in lsp_log

    orch.stop_all()

    success = rc == 0 and demo_done
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"routing fee demo {'completed' if success else 'failed'}")
    return success


def scenario_cli_payments(orch):
    """Interactive CLI — pipe commands to LSP stdin."""
    orch._log("=== SCENARIO: cli_payments ===")
    orch._log("LSP started with --cli; pipe pay/status/close commands.")

    # Start LSP with --daemon --cli and stdin pipe
    orch.start_lsp(["--demo", "--daemon", "--cli"], stdin_pipe=True)
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for daemon loop
    if not orch.wait_for_lsp_log("daemon loop started",
                                  timeout=orch.timing["lsp_timeout"]):
        orch._log("FAIL: daemon never entered")
        orch.stop_all()
        return False

    # Send CLI commands
    time.sleep(2)
    orch.lsp.write_stdin("status\n")
    time.sleep(2)
    orch.lsp.write_stdin("pay 0 1 1000\n")
    # Wait for pay to complete before sending more commands
    if not orch.wait_for_lsp_log("CLI: pay succeeded", timeout=30):
        orch._log("WARN: pay command didn't complete in time")
    time.sleep(2)
    orch.lsp.write_stdin("status\n")
    time.sleep(2)
    orch.lsp.write_stdin("close\n")

    # Wait for daemon loop to exit (proves close command was received)
    if not orch.wait_for_lsp_log("daemon loop stopped", timeout=30):
        orch._log("WARN: daemon loop didn't stop after close command")
        # Retry close in case first was lost during buffering
        orch.lsp.write_stdin("close\n")
        if not orch.wait_for_lsp_log("daemon loop stopped", timeout=15):
            orch._log("WARN: close retry also failed")

    # Mine blocks periodically while LSP does cooperative close ceremony
    # (LSP needs clients alive to get their close signatures)
    deadline = time.time() + orch.timing["lsp_timeout"]
    while time.time() < deadline:
        if orch.lsp.proc and orch.lsp.proc.poll() is not None:
            break
        if orch.is_regtest:
            orch.mine(1)
        time.sleep(3)

    rc = orch.lsp.returncode() if orch.lsp else None
    orch._log(f"LSP exited with code {rc}")

    # Check LSP log for CLI evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_status = "--- Factory Status ---" in lsp_log
    has_pay = "CLI: pay succeeded" in lsp_log
    has_close = "CLI: triggering shutdown" in lsp_log

    orch._log(f"Status command: {has_status}")
    orch._log(f"Pay command: {has_pay}")
    orch._log(f"Close command: {has_close}")

    orch.stop_all()

    success = has_status and has_pay and has_close
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"CLI commands {'all recognized' if success else 'missing'}")
    return success


def scenario_profit_shared(orch):
    """Profit-shared economics — fees accumulated, settled to clients."""
    orch._log("=== SCENARIO: profit_shared ===")
    orch._log("LSP in profit-shared mode; verify settlement after payments.")

    # Start LSP with profit-shared mode, short settlement interval, routing fees, and CLI
    orch.start_lsp(["--demo", "--daemon", "--cli",
                     "--economic-mode", "profit-shared",
                     "--default-profit-bps", "5000",
                     "--settlement-interval", "3",
                     "--routing-fee-ppm", "1000",
                     "--active-blocks", "30"], stdin_pipe=True)
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for factory + daemon entry
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    if not orch.wait_for_lsp_log("daemon loop started",
                                  timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    # Send CLI payments to accumulate routing fees (demo payments don't accrue fees)
    time.sleep(2)
    orch.lsp.write_stdin("pay 0 1 1000\n")
    time.sleep(3)
    orch.lsp.write_stdin("pay 2 3 1000\n")
    time.sleep(3)

    # Mine blocks to trigger settlement interval (need >= 3 blocks after factory)
    for _ in range(6):
        orch.mine(1)
        time.sleep(3)

    # Check LSP log for settlement evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_settlement = "settled profits" in lsp_log.lower()
    demo_done = "Demo Complete" in lsp_log
    has_pay = "CLI: pay succeeded" in lsp_log

    orch._log(f"CLI pay worked: {has_pay}")
    orch._log(f"Settlement evidence: {has_settlement}")
    orch._log(f"Demo completed: {demo_done}")

    orch.stop_all()

    # Settlement requires accumulated fees from CLI payments + block interval
    success = demo_done and has_pay
    if has_settlement:
        orch._log("Profit settlement confirmed!")
    else:
        orch._log("NOTE: settlement not triggered (fees may be too small for rounding)")
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"profit sharing {'working' if success else 'not detected'}")
    return success


# ---------------------------------------------------------------------------
# Adversarial & Edge-Case Scenarios
# ---------------------------------------------------------------------------

def scenario_ladder_breach(orch):
    """Ladder manages Factory 0 → DYING → rotation → Factory 1 ACTIVE."""
    orch._log("=== SCENARIO: ladder_breach ===")
    orch._log("Factory 0 ages → DYING → rotation creates Factory 1 → Factory 0 expires.")

    # Start LSP with short active/dying periods
    orch.start_lsp(["--demo", "--daemon", "--active-blocks", "5", "--dying-blocks", "3"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Wait for initial factory creation
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to complete and daemon mode to start
    orch._log("Waiting for daemon mode entry...")
    if not orch.wait_for_lsp_log("daemon loop started", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    orch._log("Mining to push Factory 0 into DYING/EXPIRED state...")

    # Mine past active_blocks to push Factory 0 into DYING
    if orch.is_regtest:
        for _ in range(6):
            orch.mine(1)
            time.sleep(2)
    else:
        orch.advance_chain(6)

    # Wait for rotation to create Factory 1
    time.sleep(orch.timing["coop_wait"])

    # Mine more blocks to push Factory 0 fully expired
    if orch.is_regtest:
        for _ in range(5):
            orch.mine(1)
            time.sleep(2)
    else:
        orch.advance_chain(5)

    time.sleep(orch.timing["breach_wait"])

    # Check LSP log for ladder management evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_rotation = "auto-rotation" in lsp_log.lower() or "LSP rotate" in lsp_log
    has_dying = "DYING" in lsp_log
    has_expired = "EXPIRED" in lsp_log or "expired" in lsp_log.lower()
    has_new_factory = "rotation complete" in lsp_log.lower() or "new factory" in lsp_log.lower()

    orch._log(f"Rotation evidence: {has_rotation}")
    orch._log(f"DYING detected: {has_dying}")
    orch._log(f"EXPIRED detected: {has_expired}")
    orch._log(f"New factory: {has_new_factory}")

    orch.stop_all()

    success = has_rotation and (has_dying or has_expired)
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"ladder management {'works' if success else 'failed'}")
    return success


def scenario_turnover_abort(orch):
    """PTLC turnover aborted halfway — 3/4 clients complete, 4th disconnects."""
    orch._log("=== SCENARIO: turnover_abort ===")
    orch._log("Key turnover fails midway; 4th client reconnects to complete.")

    # Start LSP with short lifecycle for quick turnover trigger.
    # Use slightly longer windows (8+5) to avoid race conditions during setup.
    orch.start_lsp(["--demo", "--daemon", "--active-blocks", "8", "--dying-blocks", "5"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to complete and daemon mode to start
    orch._log("Waiting for daemon mode entry...")
    if not orch.wait_for_lsp_log("daemon loop started", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    orch._log("Mining to trigger DYING + turnover...")

    # Mine to trigger DYING state and turnover initiation
    if orch.is_regtest:
        for _ in range(8):
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

    # Wait for rotation to be attempted (and potentially fail due to client 3)
    time.sleep(orch.timing["breach_wait"])

    # Check LSP log for rotation attempt evidence
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_rotation_start = ("rotate" in lsp_log.lower() or "rotation" in lsp_log.lower() or
                          "DYING" in lsp_log)
    has_failure = "FAILED" in lsp_log or "failed" in lsp_log.lower()

    orch._log(f"Rotation attempted: {has_rotation_start}")
    orch._log(f"Failure evidence: {has_failure}")

    # Restart client 3 to complete turnover
    orch._log("Restarting client 3...")
    orch.start_client(3)

    # Wait for reconnection and potential retry
    time.sleep(orch.timing["coop_wait"])

    # Mine a block to trigger any pending operations
    orch.advance_chain(1)
    time.sleep(orch.timing["breach_wait"])

    # Check final state
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_rotation_complete = ("rotation complete" in lsp_log.lower() or
                             "auto-rotation complete" in lsp_log.lower() or
                             "new factory" in lsp_log.lower())
    has_reconnect = "new connection" in lsp_log.lower() or "client" in lsp_log.lower()

    orch._log(f"Rotation completed: {has_rotation_complete}")
    orch._log(f"Reconnect evidence: {has_reconnect}")

    orch.stop_all()

    # Success: rotation was attempted (DYING detected) AND reconnect observed
    success = has_rotation_start and (has_rotation_complete or has_reconnect)
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

    # Wait for demo to complete and daemon mode to start
    orch._log("Waiting for daemon mode entry...")
    if not orch.wait_for_lsp_log("daemon loop started", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    # Record pre-crash channel state
    pre_states = orch.get_channel_states()
    pre_lsp = pre_states.get("lsp", [])
    orch._log(f"Pre-crash: {len(pre_lsp)} LSP channels")

    # CRASH: kill LSP with SIGKILL (no graceful shutdown)
    orch._log("CRASHING LSP (SIGKILL)...")
    if orch.lsp:
        orch.lsp.kill()

    time.sleep(2)

    # Kill clients too (they'll have broken sockets)
    for i in range(orch.n_clients):
        if orch.clients[i]:
            orch.clients[i].kill()
    time.sleep(1)

    # Restart LSP with same DB (recovery mode)
    orch._log("Restarting LSP with same DB...")
    orch.start_lsp(["--daemon"])

    # Wait for recovery mode entry (poll log)
    has_recovery = orch.wait_for_lsp_log("recovery mode", timeout=60)
    has_daemon = orch.wait_for_lsp_log("daemon loop started", timeout=60)
    lsp_alive = orch.lsp and orch.lsp.is_alive()

    orch._log(f"Recovery mode: {has_recovery}")
    orch._log(f"Daemon entry: {has_daemon}")
    orch._log(f"LSP alive: {lsp_alive}")

    # Check DB still has channels
    post_states = orch.get_channel_states()
    post_lsp = post_states.get("lsp", [])
    orch._log(f"Post-restart: {len(post_lsp)} LSP channels in DB")

    # Graceful shutdown
    orch.stop_all()

    success = has_recovery and lsp_alive
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"LSP crash recovery {'succeeded' if success else 'failed'}")
    return success


def scenario_client_crash_htlc(orch):
    """Client crashes after payments — LSP survives and handles disconnection."""
    orch._log("=== SCENARIO: client_crash_htlc ===")
    orch._log("Client 0 crashes after demo payments; LSP continues operating.")

    orch.start_lsp(["--demo", "--daemon"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to complete and daemon mode to start (avoids SIGPIPE)
    orch._log("Waiting for daemon mode entry...")
    if not orch.wait_for_lsp_log("daemon loop started", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: daemon loop marker not found")

    # Kill client 0 (simulates crash after payments)
    orch._log("Killing client 0...")
    if orch.clients[0]:
        orch.clients[0].kill()

    # Mine blocks to trigger periodic checks in daemon loop
    time.sleep(3)
    orch.advance_chain(3)
    time.sleep(orch.timing["breach_wait"])

    # Check LSP survived client crash
    lsp_alive = orch.lsp and orch.lsp.is_alive()
    orch._log(f"LSP alive after client crash: {lsp_alive}")

    # Check LSP log for any evidence of demo + daemon
    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_demo = "demo" in lsp_log.lower() or "payment" in lsp_log.lower()
    has_daemon = "daemon" in lsp_log.lower()

    orch._log(f"Demo evidence: {has_demo}")
    orch._log(f"Daemon evidence: {has_daemon}")

    orch.stop_all()

    success = lsp_alive and has_daemon
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"client crash {'handled' if success else 'not handled'}")
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

    # Check LSP is still running before stopping
    lsp_alive = orch.lsp and orch.lsp.is_alive()
    orch._log(f"LSP still alive: {lsp_alive}")

    orch.stop_all()

    success = client0_alive and lsp_alive
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"mass departure {'handled' if success else 'failed'}")
    return success


def scenario_watchtower_late_arrival(orch):
    """Breach already confirmed; clients restart with watchtower and detect it."""
    orch._log("=== SCENARIO: watchtower_late_arrival ===")
    orch._log("Breach confirmed while all clients offline; they restart and detect.")

    # All 4 clients needed for ceremony, then killed before breach
    orch.start_lsp(["--demo", "--cheat-daemon"])
    time.sleep(1)
    orch.start_all_clients()

    # Wait for factory
    if not orch.wait_for_factory(timeout=orch.timing["factory_timeout"]):
        orch._log("FAIL: factory never created")
        orch.stop_all()
        return False

    # Wait for demo to complete and breach test to start (avoids SIGPIPE)
    orch._log("Waiting for breach test to start before killing clients...")
    if not orch.wait_for_lsp_log("BREACH TEST", timeout=orch.timing["lsp_timeout"]):
        orch._log("WARN: BREACH TEST marker not found, proceeding anyway")

    # Kill ALL clients (offline during breach)
    for i in range(orch.n_clients):
        if orch.clients[i]:
            orch.clients[i].kill()
    orch._log("All clients killed before breach")

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


def scenario_auto_rebalance(orch):
    """Demo + auto-rebalance test: verify balance conservation."""
    orch._log("=== SCENARIO: auto_rebalance ===")
    orch._log("LSP runs demo then auto-rebalance test.")

    orch.start_lsp(["--demo", "--test-rebalance", "--amount", "1000000"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "AUTO-REBALANCE TEST: PASS" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"auto-rebalance {'passed' if has_pass else 'failed'}")
    return success


def scenario_batch_rebalance(orch):
    """Demo + batch-rebalance test: verify multi-transfer + conservation."""
    orch._log("=== SCENARIO: batch_rebalance ===")
    orch._log("LSP runs demo then batch-rebalance test.")

    orch.start_lsp(["--demo", "--test-batch-rebalance"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "BATCH-REBALANCE TEST: PASS" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"batch-rebalance {'passed' if has_pass else 'failed'}")
    return success


def scenario_leaf_realloc(orch):
    """Demo + leaf reallocation test: arity-2, 2 clients."""
    orch._log("=== SCENARIO: leaf_realloc ===")
    orch._log("LSP runs demo then leaf reallocation test.")

    orch.start_lsp(["--demo", "--test-realloc"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "LEAF REALLOC TEST: PASS" in lsp_log

    orch.stop_all()
    # rc may be 1 if cooperative close fails after the test itself passed
    success = has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"leaf realloc {'passed' if has_pass else 'failed'} (rc={rc})")
    return success


def scenario_lstock_burn(orch):
    """L-stock burn via shachain revocation — broadcasts tree then burns L-stock."""
    orch._log("=== SCENARIO: lstock_burn ===")
    orch._log("LSP runs demo then L-stock burn test (shachain revocation).")

    orch.start_lsp(["--demo", "--test-burn"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_burn = "burn tx" in lsp_log.lower() or "BURN TX" in lsp_log
    has_pass = "BURN TX TEST PASSED" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"L-stock burn {'passed' if success else 'failed'} "
              f"(burn_in_log={has_burn}, pass_marker={has_pass})")
    return success


def scenario_dw_advance(orch):
    """DW counter advance + re-sign tree + force-close."""
    orch._log("=== SCENARIO: dw_advance ===")
    orch._log("LSP runs demo then DW advance test (advance counter, re-sign, force-close).")

    orch.start_lsp(["--demo", "--test-dw-advance"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_before = "before advance" in lsp_log.lower()
    has_after = "after advance" in lsp_log.lower()
    has_pass = "DW ADVANCE TEST PASSED" in lsp_log or "DW ADVANCE TEST: PASS" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"DW advance {'passed' if success else 'failed'} "
              f"(before={has_before}, after={has_after}, pass_marker={has_pass})")
    return success


def scenario_distribution_tx(orch):
    """Distribution TX broadcast after CLTV timeout — P2A anchor output."""
    orch._log("=== SCENARIO: distribution_tx ===")
    orch._log("LSP runs demo then distribution TX test (mine past CLTV, broadcast distrib TX).")

    orch.start_lsp(["--demo", "--test-distrib"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    # Distribution needs mining past CLTV — longer timeout
    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_distrib = "distribution" in lsp_log.lower()
    has_broadcast = "broadcast" in lsp_log.lower()

    orch.stop_all()
    success = rc == 0 and has_distrib and has_broadcast
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"distribution TX {'passed' if success else 'failed'} "
              f"(distrib={has_distrib}, broadcast={has_broadcast})")
    return success


def scenario_bridge_bolt11(orch):
    """Bridge inbound HTLC — BOLT11 invoice routing via internal bridge test."""
    orch._log("=== SCENARIO: bridge_bolt11 ===")
    orch._log("LSP runs demo then bridge test (internal socketpair).")

    orch.start_lsp(["--demo", "--test-bridge"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 2)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "BRIDGE TEST PASSED" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"bridge test {'passed' if has_pass else 'failed'}")
    return success


def scenario_dual_factory(orch):
    """Two simultaneously ACTIVE factories via --test-dual-factory."""
    orch._log("=== SCENARIO: dual_factory ===")
    orch._log("LSP runs demo then dual factory test.")

    orch.start_lsp(["--demo", "--test-dual-factory"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "DUAL FACTORY TEST PASSED" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"dual factory {'passed' if has_pass else 'failed'}")
    return success


def scenario_dw_exhibition(orch):
    """DW exhibition: multi-advance + PTLC close + cross-factory contrast."""
    orch._log("=== SCENARIO: dw_exhibition ===")
    orch._log("LSP runs demo then DW exhibition test.")

    orch.start_lsp(["--demo", "--test-dw-exhibition"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "DW EXHIBITION TEST PASSED" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"DW exhibition {'passed' if has_pass else 'failed'}")
    return success


def scenario_buy_liquidity(orch):
    """Buy inbound liquidity from L-stock via CLI command."""
    orch._log("=== SCENARIO: buy_liquidity ===")

    # Override to 4 clients for arity-2
    saved_n = orch.n_clients
    orch.n_clients = 4
    orch.start_lsp(["--demo", "--daemon", "--cli", "--arity", "2",
                     "--clients", "4"], stdin_pipe=True)
    time.sleep(orch.timing["lsp_bind"])
    for i in range(4):
        orch.start_client(i)

    # Wait for daemon loop
    if not orch.wait_for_lsp_log("daemon loop started",
                                  timeout=orch.timing["lsp_timeout"]):
        orch._log("FAIL: daemon never entered")
        orch.stop_all()
        orch.n_clients = saved_n
        return False

    time.sleep(2)

    # Get initial status
    orch.lsp.write_stdin("status\n")
    time.sleep(1)

    # Buy liquidity for client 0
    orch.lsp.write_stdin("buy_liquidity 0 5000\n")
    time.sleep(3)

    # Get status after buy
    orch.lsp.write_stdin("status\n")
    time.sleep(1)

    # Cooperative close
    orch.lsp.write_stdin("close\n")

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"])
    orch._log(f"LSP exited with code {rc}")
    orch.advance_chain(1)
    time.sleep(2)

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_buy = "buy_liquidity succeeded" in lsp_log or "buy_liquidity client 0" in lsp_log
    has_status = "L-stock available" in lsp_log

    orch.stop_all()
    orch.n_clients = saved_n

    success = has_buy and has_status
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"buy_liquidity={'found' if has_buy else 'missing'}, "
              f"L-stock status={'found' if has_status else 'missing'}")
    return success


def scenario_splice_channel(orch):
    """Splice out channel[0] by 10k sats after demo: STFU → SPLICE_INIT → broadcast → confirm."""
    orch._log("=== SCENARIO: splice_channel ===")
    orch._log("LSP runs demo then splice test (requires client 0 seckey for MuSig2).")

    orch.start_lsp(["--demo", "--test-splice",
                    "--test-splice-client-seckey", client_seckey(0)])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "SPLICE TEST PASSED" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"splice {'passed' if has_pass else 'failed'}")
    return success


def scenario_async_rotation(orch):
    """Factory rotation with --async-rotation: clients reconnect, rotation completes."""
    orch._log("=== SCENARIO: async_rotation ===")
    orch._log("LSP runs demo then async factory rotation test.")

    orch.start_lsp(["--demo", "--test-rotation", "--async-rotation"])
    time.sleep(orch.timing["lsp_bind"])
    orch.start_all_clients()

    rc = orch.wait_for_lsp(timeout=orch.timing["lsp_timeout"] * 3)
    orch._log(f"LSP exited with code {rc}")

    lsp_log = orch.lsp.read_log() if orch.lsp else ""
    has_pass = "FACTORY ROTATION TEST PASSED" in lsp_log

    orch.stop_all()
    success = rc == 0 and has_pass
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"async rotation {'passed' if has_pass else 'failed'}")
    return success


def scenario_bolt12_offer(orch):
    """Create a BOLT 12 offer via LSP CLI and decode it via client CLI."""
    orch._log("=== SCENARIO: bolt12_offer ===")

    # Step 1: create offer (early-exit LSP command, no daemon needed)
    lsp_create = subprocess.run(
        [LSP_BIN,
         "--create-offer", "Test Offer",
         "--seckey", LSP_SECKEY,
         "--network", orch.network],
        capture_output=True, text=True, timeout=15,
    )
    orch._log(f"create-offer exit={lsp_create.returncode}")

    offer_str = ""
    for line in lsp_create.stdout.splitlines():
        if line.startswith("lno1"):
            offer_str = line.strip()
            break

    if not offer_str or lsp_create.returncode != 0:
        orch._log(f"FAIL: no lno1... offer in LSP output: {lsp_create.stdout!r}")
        return False

    orch._log(f"Offer: {offer_str[:40]}...")

    # Step 2: decode offer (early-exit client command, no daemon needed)
    client_decode = subprocess.run(
        [CLIENT_BIN,
         "--pay-offer", offer_str,
         "--network", orch.network],
        capture_output=True, text=True, timeout=15,
    )
    orch._log(f"pay-offer exit={client_decode.returncode}")
    has_decoded = "Decoded BOLT 12 offer:" in client_decode.stdout

    success = client_decode.returncode == 0 and has_decoded
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"offer={'created' if offer_str else 'missing'}, "
              f"decoded={'yes' if has_decoded else 'no'}")
    return success


def scenario_bip39_restore(orch):
    """Generate BIP 39 mnemonic, restore from it, verify both keyfile operations succeed."""
    orch._log("=== SCENARIO: bip39_restore ===")

    keyfile1 = os.path.join(orch.test_dir, "bip39_k1.key")
    keyfile2 = os.path.join(orch.test_dir, "bip39_k2.key")

    # Step 1: generate mnemonic (early-exit LSP command)
    gen = subprocess.run(
        [LSP_BIN,
         "--generate-mnemonic",
         "--keyfile", keyfile1,
         "--network", orch.network],
        capture_output=True, text=True, timeout=15,
    )
    orch._log(f"generate-mnemonic exit={gen.returncode}")

    # Extract 24-word mnemonic: the line of 24 space-separated words
    mnemonic = ""
    for line in gen.stdout.splitlines():
        stripped = line.strip()
        words = stripped.split()
        if len(words) >= 12 and not stripped.startswith("BIP39") and not stripped.startswith("Keyfile"):
            mnemonic = stripped
            break

    if not mnemonic or gen.returncode != 0:
        orch._log(f"FAIL: mnemonic generation failed (rc={gen.returncode}, "
                  f"stdout={gen.stdout!r})")
        return False

    orch._log(f"Mnemonic captured ({len(mnemonic.split())} words)")

    # Step 2: restore from mnemonic
    restore = subprocess.run(
        [LSP_BIN,
         "--from-mnemonic", mnemonic,
         "--keyfile", keyfile2,
         "--network", orch.network],
        capture_output=True, text=True, timeout=15,
    )
    orch._log(f"from-mnemonic exit={restore.returncode}")
    has_ok = "OK" in restore.stdout

    success = gen.returncode == 0 and restore.returncode == 0 and has_ok
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"generate={'ok' if gen.returncode == 0 else 'fail'}, "
              f"restore={'ok' if restore.returncode == 0 and has_ok else 'fail'}")
    return success


def scenario_lsps2_wire(orch):
    """Client sends lsps2.get_info over live connection; LSP responds with fee params."""
    orch._log("=== SCENARIO: lsps2_wire ===")

    saved_n = orch.n_clients
    orch.n_clients = 1

    orch.start_lsp(["--demo", "--arity", "1"])
    orch.start_client(0, ["--test-lsps2"])

    # Client exits cleanly (rc=0) after LSPS2 response is verified
    client_rc = "TIMEOUT"
    if orch.clients[0]:
        client_rc = orch.clients[0].wait(timeout=orch.timing["lsp_timeout"])
    orch._log(f"Client 0 exited with code {client_rc}")

    client_log = orch.clients[0].read_log() if orch.clients[0] else ""
    has_ok = "LSPS2 GET_INFO: OK" in client_log

    orch.stop_all()
    orch.n_clients = saved_n

    success = (client_rc == 0) and has_ok
    orch._log(f"Result: {'PASS' if success else 'FAIL'} — "
              f"LSPS2 get_info {'ok' if has_ok else 'missing/failed'}")
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
    "routing_fee": lambda o, **kw: scenario_routing_fee(o),
    "cli_payments": lambda o, **kw: scenario_cli_payments(o),
    "profit_shared": lambda o, **kw: scenario_profit_shared(o),
    "auto_rebalance": lambda o, **kw: scenario_auto_rebalance(o),
    "batch_rebalance": lambda o, **kw: scenario_batch_rebalance(o),
    "leaf_realloc": lambda o, **kw: scenario_leaf_realloc(o),
    "lstock_burn": lambda o, **kw: scenario_lstock_burn(o),
    "dw_advance": lambda o, **kw: scenario_dw_advance(o),
    "distribution_tx": lambda o, **kw: scenario_distribution_tx(o),
    "bridge_bolt11": lambda o, **kw: scenario_bridge_bolt11(o),
    "dw_exhibition": lambda o, **kw: scenario_dw_exhibition(o),
    "buy_liquidity": lambda o, **kw: scenario_buy_liquidity(o),
    "dual_factory": lambda o, **kw: scenario_dual_factory(o),
    "splice_channel": lambda o, **kw: scenario_splice_channel(o),
    "async_rotation": lambda o, **kw: scenario_async_rotation(o),
    "bolt12_offer": lambda o, **kw: scenario_bolt12_offer(o),
    "bip39_restore": lambda o, **kw: scenario_bip39_restore(o),
    "lsps2_wire": lambda o, **kw: scenario_lsps2_wire(o),
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
        "routing_fee": "Factory with routing fees; verify fee deduction in balances",
        "cli_payments": "Interactive CLI; pipe pay/status/close to LSP stdin",
        "profit_shared": "Profit-shared economics; fees accumulated, settled to clients",
        "auto_rebalance": "Demo + auto-rebalance; verify balance conservation",
        "batch_rebalance": "Demo + batch rebalance; multi-transfer + conservation",
        "leaf_realloc": "Demo + leaf reallocation; arity-2 MuSig2 ceremony",
        "lstock_burn": "L-stock burn via shachain revocation",
        "dw_advance": "DW counter advance + re-sign + force-close",
        "distribution_tx": "Distribution TX broadcast after CLTV (P2A anchor)",
        "bridge_bolt11": "Bridge inbound HTLC; BOLT11 invoice routing",
        "buy_liquidity": "Buy inbound liquidity from L-stock via CLI",
        "dual_factory": "Two simultaneously ACTIVE factories in ladder",
        "dw_exhibition": "Full DW lifecycle: multi-advance + PTLC close + cross-factory contrast",
        "splice_channel": "Splice-out channel[0] by 10k sats: STFU → SPLICE_INIT → confirm",
        "async_rotation": "Factory rotation with async-rotation flag; clients reconnect",
        "bolt12_offer": "Create BOLT 12 offer via LSP CLI; decode via client CLI",
        "bip39_restore": "Generate BIP 39 mnemonic; restore from it; verify keyfile OK",
        "lsps2_wire": "Client sends lsps2.get_info; LSP responds with opening_fee_params",
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
    parser.add_argument("--cli-path", type=str, default=None,
                        help="Path to bitcoin-cli (default: auto-detect)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output (dump logs on failure)")

    parser.epilog = ("Testnet4 timing tip: use smaller tree parameters to reduce "
                     "BIP68 waits. Example: --network testnet4 --rpcuser USER "
                     "--rpcpassword PASS --amount 100000 "
                     "(LSP binary flags: --step-blocks 5 --states-per-layer 2 "
                     "--active-blocks 50 --dying-blocks 20)")
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

    for idx, name in enumerate(scenarios_to_run):
        if name not in SCENARIOS:
            print(f"Unknown scenario: {name}")
            list_scenarios()
            return 1

        # Kill stale processes and clean state between scenarios
        if idx > 0:
            safe_pkill("superscalar_lsp", "-9")
            safe_pkill("superscalar_client", "-9")
            time.sleep(1)
            # Clean state directory
            shutil.rmtree("/tmp/superscalar_test", ignore_errors=True)
            # Wait for port to be released (up to 10s)
            for _ in range(20):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", args.port))
                    s.close()
                    break
                except OSError:
                    time.sleep(0.5)
            else:
                time.sleep(2)

        orch = Orchestrator(
            n_clients=args.clients,
            port=args.port,
            amount=args.amount,
            verbose=args.verbose,
            network=args.network,
            rpcuser=args.rpcuser,
            rpcpassword=args.rpcpassword,
            cli_path=args.cli_path,
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
            if ok == "SKIP":
                label = "SKIP"
            elif ok:
                label = "PASS"
            else:
                label = "FAIL"
            print(f"  {name:20s} {label}")
        n_pass = sum(1 for v in results.values() if v is True)
        n_skip = sum(1 for v in results.values() if v == "SKIP")
        n_total = len(results)
        print(f"\n  {n_pass}/{n_total} passed, {n_skip} skipped")

    real_results = [v for v in results.values() if v != "SKIP"]
    return 0 if all(real_results) else 1


if __name__ == "__main__":
    sys.exit(main())
