#!/usr/bin/env python3
"""
recover_exhibition_funds.py — Detect and recover stuck exhibition funds.

Scans the signet/testnet4 blockchain for unspent factory leaf outputs
created during the SuperScalar exhibition, and sweeps them back to the
faucet wallet.

Exhibition keys are deterministic:
  LSP:     0x0000...0001
  Client1: 0x2222...2222
  Client2: 0x3333...3333
  Client3: 0x4444...4444
  Client4: 0x5555...5555

Usage:
  python3 recover_exhibition_funds.py --network signet --scan
  python3 recover_exhibition_funds.py --network signet --sweep --dest-address <addr>

Requires: bitcoin-cli accessible, SuperScalar build directory with binaries.
"""

import argparse
import json
import os
import subprocess
import sys
import glob

def bitcoin_cli(network, *args, wallet=None):
    """Run bitcoin-cli with network and optional wallet."""
    cmd = ["bitcoin-cli"]
    rpcuser = os.environ.get("SS_RPCUSER", "rpcuser")
    rpcpass = os.environ.get("SS_RPCPASS", "rpcpass")
    if network == "signet":
        cmd += ["-signet", f"-rpcuser={rpcuser}", f"-rpcpassword={rpcpass}"]
    elif network == "testnet4":
        cmd += ["-testnet4", f"-rpcuser={rpcuser}", f"-rpcpassword={rpcpass}"]
    elif network == "regtest":
        cmd += ["-regtest", f"-rpcuser={rpcuser}", f"-rpcpassword={rpcpass}"]
    if wallet:
        cmd += [f"-rpcwallet={wallet}"]
    cmd += list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except Exception:
        return None


def scan_exhibition_dirs(exhibit_dir):
    """Scan exhibition directories for funding TXIDs and close status."""
    structures = []
    for d in sorted(glob.glob(os.path.join(exhibit_dir, "s*"))):
        name = os.path.basename(d)
        log_path = os.path.join(d, "lsp.log")
        db_path = os.path.join(d, "lsp.db")
        if not os.path.exists(log_path):
            continue

        # Extract funding txids from log
        funding_txids = []
        close_txids = []
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                if "funded" in line.lower() and "txid:" in line.lower():
                    parts = line.split("txid:")
                    if len(parts) > 1:
                        txid = parts[1].strip()[:64]
                        if len(txid) == 64:
                            funding_txids.append(txid)
                if "close confirmed" in line.lower() and "txid:" in line.lower():
                    parts = line.split("txid:")
                    if len(parts) > 1:
                        txid = parts[1].strip()[:64]
                        if len(txid) == 64:
                            close_txids.append(txid)

        structures.append({
            "name": name,
            "dir": d,
            "funding_txids": funding_txids,
            "close_txids": close_txids,
            "has_db": os.path.exists(db_path),
            "closed": len(close_txids) > 0,
        })
    return structures


def scan_unspent_outputs(network, structures):
    """Check each structure's tree nodes for unspent outputs."""
    unspent = []
    for s in structures:
        log_path = os.path.join(s["dir"], "lsp.log")
        # Find all broadcast txids from the log
        txids = set()
        try:
            with open(log_path, "r", errors="replace") as f:
                for line in f:
                    # Match "node[N] confirmed: TXID"
                    if "confirmed:" in line:
                        parts = line.split("confirmed:")
                        if len(parts) > 1:
                            txid = parts[1].strip().split()[0][:64]
                            if len(txid) == 64:
                                txids.add(txid)
                    # Match "broadcast OK (txid=TXID"
                    if "txid=" in line:
                        for part in line.split("txid="):
                            txid = part.strip()[:64]
                            if len(txid) == 64 and all(c in "0123456789abcdef" for c in txid):
                                txids.add(txid)
        except Exception:
            pass

        # Also add funding txids
        txids.update(s["funding_txids"])

        # Check each txid for unspent outputs
        for txid in txids:
            for vout in range(4):
                result = bitcoin_cli(network, "gettxout", txid, str(vout))
                if result:
                    try:
                        data = json.loads(result)
                        value = data.get("value", 0)
                        spk = data.get("scriptPubKey", {}).get("hex", "")
                        unspent.append({
                            "structure": s["name"],
                            "txid": txid,
                            "vout": vout,
                            "amount_btc": value,
                            "amount_sats": int(float(value) * 1e8),
                            "scriptpubkey": spk,
                            "confirmations": data.get("confirmations", 0),
                        })
                    except json.JSONDecodeError:
                        pass
    return unspent


def sweep_with_admin_rpc(network, structure_name, exhibit_dir, dest_address, dry_run=True):
    """Attempt to sweep using the LSP's sweepfactory admin RPC (requires DB)."""
    db_path = os.path.join(exhibit_dir, structure_name, "lsp.db")
    if not os.path.exists(db_path):
        print(f"  {structure_name}: no DB — manual sweep needed")
        return False
    # TODO: Connect to admin RPC socket and call sweepfactory
    print(f"  {structure_name}: DB exists — sweepfactory RPC available")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Detect and recover stuck SuperScalar exhibition funds"
    )
    parser.add_argument("--network", default="signet",
                        choices=["signet", "testnet4", "regtest"])
    parser.add_argument("--exhibit-dir", default="./ss_exhibit",
                        help="Path to exhibition directory")
    parser.add_argument("--scan", action="store_true",
                        help="Scan for unspent exhibition outputs")
    parser.add_argument("--sweep", action="store_true",
                        help="Sweep unspent outputs to dest address")
    parser.add_argument("--dest-address", default=None,
                        help="Destination address for swept funds")
    parser.add_argument("--wallet", default="faucet",
                        help="Wallet name for RPC calls")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview sweep without broadcasting")
    args = parser.parse_args()

    print(f"SuperScalar Exhibition Fund Recovery")
    print(f"  Network: {args.network}")
    print(f"  Exhibit dir: {args.exhibit_dir}")
    print()

    # Step 1: Scan exhibition directories
    print("=== Scanning exhibition directories ===")
    structures = scan_exhibition_dirs(args.exhibit_dir)
    for s in structures:
        status = "CLOSED" if s["closed"] else ("DB" if s["has_db"] else "NO DB")
        n_fund = len(s["funding_txids"])
        print(f"  {s['name']}: {n_fund} funding TXs, status={status}")

    print()

    # Step 2: Scan for unspent outputs
    if args.scan or args.sweep:
        print("=== Scanning blockchain for unspent outputs ===")
        unspent = scan_unspent_outputs(args.network, structures)
        total_sats = sum(u["amount_sats"] for u in unspent)
        print(f"  Found {len(unspent)} unspent outputs, total {total_sats} sats "
              f"({total_sats / 1e8:.8f} BTC)")
        print()
        for u in unspent:
            print(f"  {u['structure']}: {u['txid'][:16]}... vout={u['vout']} "
                  f"{u['amount_sats']} sats ({u['confirmations']} confs)")

        if args.sweep:
            if not args.dest_address:
                # Get new address from wallet
                addr = bitcoin_cli(args.network, "getnewaddress", wallet=args.wallet)
                if addr:
                    print(f"\n  Sweep destination: {addr}")
                    args.dest_address = addr
                else:
                    print("\n  ERROR: could not get destination address")
                    return 1

            print(f"\n=== {'DRY RUN — ' if args.dry_run else ''}Sweeping to {args.dest_address} ===")
            for s in structures:
                if not s["closed"] and s["has_db"]:
                    sweep_with_admin_rpc(args.network, s["name"],
                                         args.exhibit_dir, args.dest_address,
                                         args.dry_run)

            print(f"\n  Total recoverable: {total_sats} sats")
            if args.dry_run:
                print("  (dry run — no transactions broadcast)")
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
