#!/usr/bin/env python3
"""Multi-arity scenario driver: open factory, pay, (advance), close, with state recording.

Runs on regtest OR signet. Covers arity 1 (2-of-2 DW), arity 2 (3-of-3 DW), and
arity 3 (PS chain). Captures a JSON timeline via state_recorder.StateRecorder at
each phase, including per-step LSP admin-RPC view, sqlite snapshots from LSP and
each client, and bitcoind's chain view.

Scenario steps:
    1. start LSP + N clients
    2. wait for factory ready    [snapshot: factory_ready]
    3. run K payments (LSP CLI "pay a b amount")
       snapshot after each payment: paid_<k>
    4. if PS or DW: trigger advance via --test-ps-advance / --test-dw-advance
       snapshot: after_advance
    5. cooperative close        [snapshot: coop_closed]

Intentional limitations:
    - Assumes binaries already built at ../build/superscalar_{lsp,client}.
    - Uses deterministic seckeys for clients (reproducible across runs).
    - On signet, expects the system bitcoind + RPC creds in env vars.

Usage:
    python3 tools/multi_arity_scenario.py --network regtest --arity 2 --clients 4 \
        --payments 3 --run-dir /tmp/ss-test --label arity2-coop
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

from state_recorder import StateRecorder, admin_rpc_call, bitcoin_cli  # noqa: E402


# --------------------------------------------------------------------------- #
# Config                                                                        #
# --------------------------------------------------------------------------- #

# Deterministic client seckeys — 32-byte hex, predictable for repro
CLIENT_SECKEYS = [
    f"{i:064x}" for i in range(0x10, 0x10 + 64)
]


def bitcoin_cli_args(network: str) -> list:
    """Return the bitcoin-cli argv prefix for the given network."""
    # Use env overrides if present; sensible defaults for VPS system bitcoind
    cli = os.environ.get("BITCOIN_CLI", "bitcoin-cli")
    if network == "signet":
        return [
            cli,
            "-signet",
            "-rpcuser=" + os.environ.get("SIGNET_RPCUSER", "signetrpc"),
            "-rpcpassword=" + os.environ.get("SIGNET_RPCPASS", "signetrpcpass123"),
            "-rpcport=" + os.environ.get("SIGNET_RPCPORT", "38332"),
        ]
    if network == "regtest":
        port = os.environ.get("REGTEST_RPCPORT", "18443")
        user = os.environ.get("REGTEST_RPCUSER", "rpcuser")
        passwd = os.environ.get("REGTEST_RPCPASS", "rpcpass")
        # Caller is expected to have set -regtest=1 bitcoind configured with these creds
        return [
            cli,
            "-regtest",
            f"-rpcuser={user}",
            f"-rpcpassword={passwd}",
            f"-rpcport={port}",
        ]
    raise ValueError(f"unknown network {network}")


# --------------------------------------------------------------------------- #
# Process orchestration                                                         #
# --------------------------------------------------------------------------- #

class ProcGroup:
    """Manage subprocess lifecycle for LSP + clients, with stdin control for the LSP."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.procs: list = []
        self.lsp_proc: subprocess.Popen = None
        self.lsp_stdin_fifo: Path = None

    def launch(self, name: str, argv: list, stdin=None, fifo=False, env=None) -> subprocess.Popen:
        logf = open(self.run_dir / f"{name}.log", "wb")
        if fifo:
            fifo_path = self.run_dir / f"{name}.stdin.fifo"
            if fifo_path.exists():
                fifo_path.unlink()
            os.mkfifo(str(fifo_path))
            # Open for reading+writing ensures open() doesn't block
            stdin_fd = os.open(str(fifo_path), os.O_RDWR)
            proc = subprocess.Popen(
                argv, stdin=stdin_fd, stdout=logf, stderr=subprocess.STDOUT, env=env)
            os.close(stdin_fd)
            if name == "lsp":
                self.lsp_stdin_fifo = fifo_path
        else:
            proc = subprocess.Popen(
                argv, stdin=stdin or subprocess.DEVNULL,
                stdout=logf, stderr=subprocess.STDOUT, env=env)
        self.procs.append((name, proc, logf))
        if name == "lsp":
            self.lsp_proc = proc
        return proc

    def lsp_cli(self, line: str) -> None:
        """Send a line to LSP stdin via the FIFO."""
        if self.lsp_stdin_fifo is None:
            raise RuntimeError("LSP not launched with fifo=True")
        with open(self.lsp_stdin_fifo, "w") as f:
            f.write(line + "\n")
            f.flush()

    def shutdown_all(self, grace_s: float = 5.0) -> None:
        # Try graceful SIGINT first
        for name, p, _ in self.procs:
            if p.poll() is None:
                try:
                    p.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
        deadline = time.time() + grace_s
        for name, p, _ in self.procs:
            remaining = max(0.1, deadline - time.time())
            try:
                p.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=2.0)
        for name, p, lf in self.procs:
            try:
                lf.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Scenario                                                                     #
# --------------------------------------------------------------------------- #

def wait_for_factory_ready(rec: StateRecorder, socket_path: str,
                            n_clients: int, timeout_s: float = 180.0) -> bool:
    """Poll the LSP via listchannels until all N channels are active."""
    deadline = time.time() + timeout_s
    last_state = None
    while time.time() < deadline:
        r = admin_rpc_call(socket_path, "listchannels")
        chans = r.get("result") or []
        if isinstance(chans, list) and len(chans) >= n_clients:
            active = sum(1 for c in chans if c.get("state") == "active")
            state = (len(chans), active)
            if state != last_state:
                print(f"  factory progress: {active}/{len(chans)} active", flush=True)
                last_state = state
            if active == n_clients:
                return True
        time.sleep(2.0)
    return False


def run_scenario(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    # Per-run artifacts
    lsp_db = run_dir / "lsp.db"
    lsp_socket = run_dir / "lsp.sock"
    client_dbs = [run_dir / f"client{i+1}.db" for i in range(args.clients)]
    timeline = run_dir / "timeline.jsonl"

    # Clean any stale state
    for p in [lsp_db, lsp_socket] + client_dbs:
        if p.exists():
            p.unlink()
    for p in run_dir.glob("*.log"):
        p.unlink()
    for p in run_dir.glob("*.fifo"):
        p.unlink()

    btc_cli = bitcoin_cli_args(args.network)

    # -- Launch LSP -----------------------------------------------------------
    lsp_bin = str(REPO / "build" / "superscalar_lsp")
    client_bin = str(REPO / "build" / "superscalar_client")
    if not os.path.exists(lsp_bin) or not os.path.exists(client_bin):
        print(f"ERROR: binaries missing — build with: (cd {REPO} && make)", file=sys.stderr)
        return 2

    pg = ProcGroup(run_dir)

    lsp_argv = [
        lsp_bin,
        "--network", args.network,
        "--port", str(args.port),
        "--clients", str(args.clients),
        "--amount", str(args.amount),
        "--arity", str(args.arity),
        "--daemon",
        "--cli",  # enable stdin CLI for pay/status/rotate/close
        "--db", str(lsp_db),
        "--rpc-file", str(lsp_socket),
        "--step-blocks", str(args.step_blocks),
        "--rpcuser", btc_cli[2].split("=", 1)[1] if "=" in btc_cli[2] else "",
        "--rpcpassword", btc_cli[3].split("=", 1)[1] if "=" in btc_cli[3] else "",
        "--rpcport", btc_cli[4].split("=", 1)[1] if "=" in btc_cli[4] else "",
        "--cli-path", btc_cli[0],
    ]
    if args.states_per_layer:
        lsp_argv += ["--states-per-layer", str(args.states_per_layer)]
    if args.no_jit:
        lsp_argv.append("--no-jit")

    # Advance / force-close flags are set LATER via CLI, not at LSP start,
    # so we can record state between payments and the advance.

    print(f"launching LSP: {' '.join(lsp_argv)}", flush=True)
    pg.launch("lsp", lsp_argv, fifo=True)

    # Wait for LSP admin socket to appear
    for _ in range(30):
        if lsp_socket.exists():
            break
        time.sleep(0.5)
    else:
        print("ERROR: LSP admin socket never appeared", file=sys.stderr)
        pg.shutdown_all()
        return 3

    # -- Launch clients -------------------------------------------------------
    for i in range(args.clients):
        cargv = [
            client_bin,
            "--seckey", CLIENT_SECKEYS[i],
            "--network", args.network,
            "--port", str(args.port),
            "--daemon",
            "--db", str(client_dbs[i]),
            "--rpcuser", btc_cli[2].split("=", 1)[1] if "=" in btc_cli[2] else "",
            "--rpcpassword", btc_cli[3].split("=", 1)[1] if "=" in btc_cli[3] else "",
            "--rpcport", btc_cli[4].split("=", 1)[1] if "=" in btc_cli[4] else "",
            "--cli-path", btc_cli[0],
        ]
        pg.launch(f"client{i+1}", cargv)
        time.sleep(0.3)

    # -- Recorder -------------------------------------------------------------
    rec = StateRecorder(
        timeline_path=str(timeline),
        lsp_socket=str(lsp_socket),
        lsp_db=str(lsp_db),
        client_dbs=[str(p) for p in client_dbs],
        btc_cli=btc_cli,
    )
    rec.snapshot("launched")

    # -- Wait for factory ready -----------------------------------------------
    ok = wait_for_factory_ready(rec, str(lsp_socket), args.clients,
                                timeout_s=args.factory_timeout)
    rec.snapshot("factory_ready" if ok else "factory_timeout")
    if not ok:
        print("ERROR: factory did not become ready in time", file=sys.stderr)
        pg.shutdown_all()
        return 4

    # -- Payments -------------------------------------------------------------
    for k in range(args.payments):
        a = k % args.clients
        b = (k + 1) % args.clients
        amount = args.pay_amount
        print(f"  pay {a} -> {b}: {amount} sats", flush=True)
        pg.lsp_cli(f"pay {a} {b} {amount}")
        # Polling the log for success is brittle; give the LSP time to settle
        time.sleep(3.0)
        rec.snapshot(f"paid_{k+1}")

    # -- Advance --------------------------------------------------------------
    # For arity 3 (PS) or 2/1 (DW), trigger an advance via the LSP CLI.
    # Current LSP CLI doesn't expose an advance command directly (uses flags at start),
    # so we skip advance here and instead cover advance via dedicated scenarios elsewhere.
    # TODO: If/when the LSP CLI gains "advance" / "ps_advance", call it here.

    # -- Close ----------------------------------------------------------------
    pg.lsp_cli("close")
    time.sleep(3.0)
    rec.snapshot("coop_close_requested")

    # Wait for LSP to exit on its own
    for _ in range(60):
        if pg.lsp_proc.poll() is not None:
            break
        time.sleep(1.0)

    rec.snapshot("final")

    # Summary
    summary = rec.summarize()
    print()
    print(summary)
    print()

    pg.shutdown_all()
    return 0 if pg.lsp_proc.returncode in (0, None) else 1


# --------------------------------------------------------------------------- #
# Main                                                                          #
# --------------------------------------------------------------------------- #

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Multi-arity scenario driver")
    p.add_argument("--network", default="regtest", choices=["regtest", "signet"])
    p.add_argument("--arity", type=int, default=1, choices=[1, 2, 3])
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--amount", type=int, default=200_000,
                   help="Total factory funding in sats")
    p.add_argument("--payments", type=int, default=3)
    p.add_argument("--pay-amount", type=int, default=1000)
    p.add_argument("--port", type=int, default=9935)
    p.add_argument("--step-blocks", type=int, default=1)
    p.add_argument("--states-per-layer", type=int, default=0,
                   help="0 = use LSP default")
    p.add_argument("--no-jit", action="store_true")
    p.add_argument("--run-dir", required=True, help="Directory for logs/db/timeline")
    p.add_argument("--label", default="run")
    p.add_argument("--factory-timeout", type=float, default=600.0)
    return p


if __name__ == "__main__":
    args = build_argparser().parse_args()
    sys.exit(run_scenario(args))
