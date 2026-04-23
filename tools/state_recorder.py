#!/usr/bin/env python3
"""State recorder for SuperScalar test scenarios.

Captures three views at every step of a test:
  1. LSP view     — admin RPC 2.0 Unix socket (requires --rpc-file on LSP)
  2. Persistence  — SQLite snapshots of factories, channels, tree_nodes, ps_leaf_chains
  3. Chain view   — bitcoin-cli getblockcount, mempool, funding-txid status

Each call to snapshot(label) appends one JSON object to the timeline file.

Usage (library):
    rec = StateRecorder(
        timeline_path="/tmp/run.timeline.jsonl",
        lsp_socket="/tmp/lsp.sock",
        lsp_db="/tmp/lsp.db",
        client_dbs=["/tmp/c1.db", ...],
        btc_cli=["bitcoin-cli", "-signet", "-rpcuser=...", ...],
    )
    rec.snapshot("factory_ready")
    ...
    rec.snapshot("after_payment_1")

Design choices:
  - JSONL output: each line is one self-describing snapshot; appendable during crashes.
  - Tolerant to missing pieces: if LSP socket isn't up yet, socket_error is recorded
    rather than raising, so a post-crash investigation still gets partial data.
  - Read-only: never mutates state. Safe to call from parallel harnesses.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Admin RPC client                                                              #
# --------------------------------------------------------------------------- #

def admin_rpc_call(socket_path: str, method: str, params=None, timeout_s: float = 5.0) -> dict:
    """Send a JSON-RPC 2.0 request over the LSP's Unix socket.

    Returns the decoded JSON response. On error (socket absent, LSP down, etc.)
    returns {"error": <str>} so callers can keep recording without raising.
    """
    req = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        req["params"] = params
    payload = json.dumps(req).encode() + b"\n"

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect(socket_path)
        s.sendall(payload)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        if not buf:
            return {"error": "empty response"}
        return json.loads(buf.decode())
    except (FileNotFoundError, ConnectionRefusedError) as e:
        return {"error": f"socket unavailable: {e}"}
    except socket.timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------------- #
# SQLite snapshot helpers                                                      #
# --------------------------------------------------------------------------- #

def _rows_as_dicts(conn: sqlite3.Connection, sql: str, params=()) -> list:
    try:
        cur = conn.execute(sql, params)
    except sqlite3.Error as e:
        return [{"_error": str(e)}]
    cols = [d[0] for d in cur.description] if cur.description else []
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def snapshot_db(path: str) -> dict:
    """Snapshot the relevant tables from a SuperScalar sqlite db.

    Opens read-only. If the db file is missing, returns {"absent": True}.
    """
    if not os.path.exists(path):
        return {"absent": True}
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as e:
        return {"error": str(e)}

    out = {"path": path}
    out["factories"] = _rows_as_dicts(conn, "SELECT * FROM factories")
    out["channels"] = _rows_as_dicts(conn, "SELECT * FROM channels")
    # tree_nodes can be large; keep key fields
    out["tree_nodes"] = _rows_as_dicts(
        conn,
        "SELECT factory_id, node_index, type, parent_index, parent_vout, "
        "dw_layer_index, n_outputs, output_amounts, nsequence, input_amount, "
        "txid, is_built, is_signed FROM tree_nodes ORDER BY factory_id, node_index")
    out["ps_leaf_chains"] = _rows_as_dicts(
        conn,
        "SELECT factory_id, leaf_node_idx, chain_pos, txid, chan_amount_sats "
        "FROM ps_leaf_chains ORDER BY factory_id, leaf_node_idx, chain_pos")
    out["htlcs"] = _rows_as_dicts(
        conn,
        "SELECT id, channel_id, htlc_id, direction, amount, payment_hash, "
        "cltv_expiry, state FROM htlcs")
    out["broadcast_log"] = _rows_as_dicts(
        conn,
        "SELECT id, txid, source FROM broadcast_log ORDER BY id DESC LIMIT 32")

    conn.close()
    return out


# --------------------------------------------------------------------------- #
# Bitcoin chain snapshot                                                        #
# --------------------------------------------------------------------------- #

def bitcoin_cli(cmd_prefix: list, args: list, timeout_s: float = 15.0) -> dict:
    """Run bitcoin-cli with the given argv; parse JSON if possible."""
    try:
        r = subprocess.run(
            cmd_prefix + args,
            capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except FileNotFoundError as e:
        return {"error": f"cli not found: {e}"}
    if r.returncode != 0:
        return {"error": r.stderr.strip() or f"exit {r.returncode}"}
    out = r.stdout.strip()
    if not out:
        return {"result": None}
    try:
        return {"result": json.loads(out)}
    except json.JSONDecodeError:
        return {"result": out}


def snapshot_chain(cmd_prefix: list, funding_txids: list) -> dict:
    """Snapshot height, mempool size, and confirmation count for known txids."""
    out: dict = {}
    r = bitcoin_cli(cmd_prefix, ["getblockcount"])
    out["height"] = r.get("result")
    r = bitcoin_cli(cmd_prefix, ["getrawmempool"])
    mp = r.get("result") or []
    out["mempool_size"] = len(mp) if isinstance(mp, list) else None
    out["mempool_txids"] = mp if isinstance(mp, list) else None
    tx_status = {}
    for txid in funding_txids:
        if not txid or len(txid) != 64:
            continue
        r = bitcoin_cli(cmd_prefix, ["getrawtransaction", txid, "true"])
        res = r.get("result")
        if isinstance(res, dict):
            tx_status[txid] = {
                "confirmations": res.get("confirmations", 0),
                "blockhash": res.get("blockhash"),
                "in_mempool": txid in mp if isinstance(mp, list) else None,
            }
        else:
            tx_status[txid] = {"error": r.get("error", "not found")}
    out["txs"] = tx_status
    return out


# --------------------------------------------------------------------------- #
# Recorder                                                                      #
# --------------------------------------------------------------------------- #

@dataclass
class StateRecorder:
    timeline_path: str
    lsp_socket: Optional[str] = None
    lsp_db: Optional[str] = None
    client_dbs: list = field(default_factory=list)
    btc_cli: list = field(default_factory=list)  # e.g. ["bitcoin-cli", "-signet", ...]
    truncate: bool = True  # set False to append to an existing timeline

    def __post_init__(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.timeline_path)), exist_ok=True)
        if self.truncate:
            open(self.timeline_path, "w").close()
            self.step_counter = 0
        else:
            # Continue numbering from existing file
            self.step_counter = 0
            try:
                with open(self.timeline_path) as f:
                    self.step_counter = sum(1 for _ in f)
            except FileNotFoundError:
                pass

    def _lsp_snapshot(self) -> dict:
        if not self.lsp_socket:
            return {"disabled": True}
        out = {}
        for method in ("getinfo", "listchannels", "listfactories",
                       "listfunds", "listinvoices", "listpayments", "getbalance"):
            r = admin_rpc_call(self.lsp_socket, method)
            # Flatten — drop the jsonrpc envelope, keep result or error
            if "result" in r:
                out[method] = r["result"]
            elif "error" in r:
                out[method] = {"_error": r["error"]}
            else:
                out[method] = r
        return out

    def _collect_funding_txids(self, db_snapshots: dict) -> list:
        txids = set()
        for snap in db_snapshots.values():
            if not isinstance(snap, dict):
                continue
            for f in snap.get("factories", []) or []:
                txid = f.get("funding_txid")
                if isinstance(txid, str) and len(txid) == 64:
                    txids.add(txid)
            for c in snap.get("channels", []) or []:
                txid = c.get("funding_txid")
                if isinstance(txid, str) and len(txid) == 64:
                    txids.add(txid)
            for p in snap.get("ps_leaf_chains", []) or []:
                txid = p.get("txid")
                if isinstance(txid, str) and len(txid) == 64:
                    txids.add(txid)
        return list(txids)

    def snapshot(self, label: str, extra: Optional[dict] = None) -> dict:
        """Capture a full state snapshot and append to the timeline."""
        self.step_counter += 1
        ts = time.time()

        dbs = {"lsp": snapshot_db(self.lsp_db) if self.lsp_db else {"disabled": True}}
        for i, path in enumerate(self.client_dbs):
            dbs[f"client{i+1}"] = snapshot_db(path)

        funding_txids = self._collect_funding_txids(dbs)

        chain = snapshot_chain(self.btc_cli, funding_txids) if self.btc_cli else {"disabled": True}
        lsp = self._lsp_snapshot()

        rec = {
            "step": self.step_counter,
            "label": label,
            "ts": ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
            "chain": chain,
            "lsp": lsp,
            "db": dbs,
        }
        if extra:
            rec["extra"] = extra

        with open(self.timeline_path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        return rec

    # ------------------------------------------------------------------ #
    # Summarization helpers (called at end of run to produce human output) #
    # ------------------------------------------------------------------ #

    def read_timeline(self) -> list:
        out = []
        with open(self.timeline_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out

    def summarize(self) -> str:
        """Return a human-readable per-step summary of the timeline."""
        recs = self.read_timeline()
        lines = [f"Timeline: {self.timeline_path}  ({len(recs)} steps)"]
        for r in recs:
            chan = r.get("lsp", {}).get("listchannels") or []
            if isinstance(chan, list):
                balances = ",".join(
                    f"{c.get('local_msat','?')}/{c.get('remote_msat','?')}"
                    for c in chan)
            else:
                balances = str(chan)[:40]
            facs = r.get("lsp", {}).get("listfactories") or []
            height = r.get("chain", {}).get("height", "?")
            mp_size = r.get("chain", {}).get("mempool_size", "?")

            # Count PS leaves & their chain positions
            ps_desc = ""
            for name, snap in r.get("db", {}).items():
                if isinstance(snap, dict):
                    ps = snap.get("ps_leaf_chains") or []
                    if ps:
                        ps_desc = f" ps[{name}]={len(ps)}"
                        break

            lines.append(
                f"  step {r['step']:2d} [{r['label']:<30s}] h={height} mp={mp_size} "
                f"facs={len(facs) if isinstance(facs, list) else '?'} "
                f"bal={balances}{ps_desc}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI                                                                           #
# --------------------------------------------------------------------------- #

def _main():
    import argparse
    p = argparse.ArgumentParser(description="SuperScalar state recorder")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("snapshot", help="Write one snapshot to the timeline")
    s.add_argument("--timeline", required=True)
    s.add_argument("--label", required=True)
    s.add_argument("--lsp-socket", default=None)
    s.add_argument("--lsp-db", default=None)
    s.add_argument("--client-db", action="append", default=[])
    s.add_argument("--btc-cli", default="bitcoin-cli",
                   help="Path to bitcoin-cli; pass args with --btc-arg")
    s.add_argument("--btc-arg", action="append", default=[])

    s2 = sub.add_parser("summarize", help="Human-readable timeline summary")
    s2.add_argument("--timeline", required=True)

    args = p.parse_args()

    if args.cmd == "snapshot":
        rec = StateRecorder(
            timeline_path=args.timeline,
            lsp_socket=args.lsp_socket,
            lsp_db=args.lsp_db,
            client_dbs=args.client_db,
            btc_cli=[args.btc_cli] + args.btc_arg,
            truncate=False,
        )
        r = rec.snapshot(args.label)
        print(json.dumps({"step": r["step"], "label": r["label"]}))
    elif args.cmd == "summarize":
        rec = StateRecorder(timeline_path=args.timeline, truncate=False)
        print(rec.summarize())


if __name__ == "__main__":
    _main()
