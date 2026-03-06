#!/usr/bin/env python3
"""SuperScalar on-chain TX tree inspector.

Reads TXIDs from an LSP report JSON (or --txid-file with a list of TXIDs)
and produces a markdown report showing the full TX tree structure.

Usage:
    python3 tools/inspect_factory.py --report /tmp/superscalar_test/lsp_report.json
    python3 tools/inspect_factory.py --txid-file exhibition_txids.json --network testnet4
    python3 tools/inspect_factory.py --txid <single_txid> --network regtest
"""

import argparse
import json
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Bitcoin RPC helper
# ---------------------------------------------------------------------------

class BitcoinRPC:
    def __init__(self, cli_path="bitcoin-cli", network="regtest",
                 rpcuser=None, rpcpassword=None, rpcport=None):
        self.cli_path = cli_path
        self.network = network
        self.rpcuser = rpcuser
        self.rpcpassword = rpcpassword
        self.rpcport = rpcport

    def _cmd(self, *args, timeout=30):
        cmd = [self.cli_path]
        if self.network and self.network != "mainnet":
            cmd.append("-" + self.network)
        if self.rpcuser:
            cmd.append("-rpcuser=" + self.rpcuser)
        if self.rpcpassword:
            cmd.append("-rpcpassword=" + self.rpcpassword)
        if self.rpcport:
            cmd.append("-rpcport=" + str(self.rpcport))
        cmd.extend(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                return None, r.stderr.strip()
            return r.stdout.strip(), None
        except Exception as e:
            return None, str(e)

    def getrawtx(self, txid):
        """Get decoded raw transaction (requires txindex=1)."""
        out, err = self._cmd("getrawtransaction", txid, "true")
        if out:
            return json.loads(out)
        return None

    def getblock(self, blockhash):
        out, err = self._cmd("getblock", blockhash)
        if out:
            return json.loads(out)
        return None

    def getblockcount(self):
        out, err = self._cmd("getblockcount")
        if out:
            return int(out)
        return None


# ---------------------------------------------------------------------------
# TX classification
# ---------------------------------------------------------------------------

def classify_tx_from_report(node):
    """Classify a TX node from the LSP report JSON."""
    return node.get("type", "unknown")


def interpret_nsequence(nseq):
    """Interpret nSequence for BIP68 relative timelock."""
    if nseq == 0xFFFFFFFF:
        return "final (no RBF, no relative lock)"
    if nseq == 0xFFFFFFFE:
        return "no RBF, nLockTime enabled"
    # BIP68: bit 31 = disable flag
    if nseq & (1 << 31):
        return "0x{:08x} (BIP68 disabled)".format(nseq)
    # BIP68: bit 22 = type flag (0=blocks, 1=time)
    if nseq & (1 << 22):
        # Time-based: value * 512 seconds
        val = nseq & 0xFFFF
        secs = val * 512
        return "{} units = {}s (~{}m) time-lock".format(val, secs, secs // 60)
    else:
        # Block-based
        val = nseq & 0xFFFF
        return "{} blocks relative lock".format(val)


def interpret_nlocktime(nlt):
    """Interpret nLockTime."""
    if nlt == 0:
        return "0 (immediate)"
    if nlt < 500000000:
        return "block {}".format(nlt)
    else:
        return "timestamp {} ({})".format(nlt, time.strftime("%Y-%m-%d %H:%M", time.gmtime(nlt)))


def classify_output_type(spk_hex):
    """Classify script pubkey type."""
    if not spk_hex:
        return "unknown"
    if spk_hex.startswith("5120") and len(spk_hex) == 68:
        return "P2TR (Taproot)"
    if spk_hex.startswith("0020") and len(spk_hex) == 68:
        return "P2WSH"
    if spk_hex.startswith("0014") and len(spk_hex) == 44:
        return "P2WPKH"
    if spk_hex.startswith("6a"):
        return "OP_RETURN"
    # SegWit v1 anchor: OP_1 OP_PUSH2
    if spk_hex.startswith("5102"):
        return "P2A (pay-to-anchor)"
    return "script({}...)".format(spk_hex[:16])


def classify_witness(witness):
    """Classify witness spend type."""
    if not witness:
        return "no witness"
    n = len(witness)
    if n == 1 and len(witness[0]) == 128:
        return "key-path (Schnorr sig)"
    if n >= 2:
        # Check for script-path: last element is control block (33+ bytes starting with 0xc0/0xc1)
        last = witness[-1]
        if len(last) >= 66 and last[:2] in ("c0", "c1"):
            return "script-path ({} args + script + control)".format(n - 2)
    if n == 2 and len(witness[0]) == 128:
        return "key-path (sig + sighash)"
    return "witness ({} elements)".format(n)


# ---------------------------------------------------------------------------
# Report generation from LSP report JSON
# ---------------------------------------------------------------------------

def report_from_lsp_json(report_data, rpc=None):
    """Generate markdown report from an LSP report JSON."""
    lines = []
    lines.append("# SuperScalar Factory TX Tree Report")
    lines.append("")

    # Header info
    n_clients = report_data.get("n_clients", "?")
    funding_sats = report_data.get("funding_sats", "?")
    lines.append("- **Participants:** 1 LSP + {} clients".format(n_clients))
    lines.append("- **Funding amount:** {} sats".format(funding_sats))

    participants = report_data.get("participants", {})
    lsp_pub = participants.get("lsp", "?")
    lines.append("- **LSP pubkey:** `{}...`".format(lsp_pub[:16]))
    lines.append("")

    # Funding TX
    funding = report_data.get("funding", {})
    if funding:
        lines.append("## Funding TX")
        lines.append("- **TXID:** `{}`".format(funding.get("txid", "?")))
        lines.append("- **Vout:** {}".format(funding.get("vout", "?")))
        lines.append("- **Amount:** {} sats".format(funding.get("amount_sats", "?")))
        spk = funding.get("script_pubkey", "")
        lines.append("- **Output type:** {}".format(classify_output_type(spk)))
        lines.append("")

    # Factory nodes
    factory = report_data.get("factory", {})
    nodes = factory.get("nodes", [])
    if nodes:
        lines.append("## Factory TX Tree")
        lines.append("")
        lines.append("- **Total nodes:** {}".format(factory.get("n_nodes", len(nodes))))
        lines.append("- **Step blocks:** {}".format(factory.get("step_blocks", "?")))
        lines.append("- **Fee per TX:** {} sats".format(factory.get("fee_per_tx", "?")))
        lines.append("")
        lines.append("| # | Type | TXID | nSequence | Signers | Input | Outputs |")
        lines.append("|---|------|------|-----------|---------|-------|---------|")

        for node in nodes:
            idx = node.get("index", "?")
            ntype = node.get("type", "?")
            txid = node.get("txid", "?")
            txid_short = txid[:12] + "..." if len(str(txid)) > 12 else txid
            nseq = node.get("nsequence", 0)
            nseq_str = interpret_nsequence(nseq)
            n_signers = node.get("n_signers", "?")
            input_amt = node.get("input_amount", "?")
            outputs = node.get("outputs", [])
            n_out = len(outputs)
            out_total = sum(o.get("amount_sats", 0) for o in outputs)

            lines.append(
                "| {} | {} | `{}` | {} | {} | {} | {} ({} sats) |".format(
                    idx, ntype, txid_short, nseq_str,
                    n_signers, input_amt, n_out, out_total))

        lines.append("")

        # Detailed per-node breakdown
        lines.append("### Node Details")
        lines.append("")
        for node in nodes:
            idx = node.get("index", "?")
            ntype = node.get("type", "?")
            txid = node.get("txid", "?")
            lines.append("#### Node {}: {}".format(idx, ntype))
            lines.append("- **TXID:** `{}`".format(txid))

            parent = node.get("parent_index", -1)
            if parent >= 0:
                pvout = node.get("parent_vout", 0)
                lines.append("- **Spends:** node {} vout {}".format(parent, pvout))

            nseq = node.get("nsequence", 0)
            lines.append("- **nSequence:** 0x{:08X} ({})".format(nseq, interpret_nsequence(nseq)))

            dw_layer = node.get("dw_layer_index", -1)
            if dw_layer >= 0:
                lines.append("- **DW layer:** {}".format(dw_layer))

            lines.append("- **Signers:** {} (indices: {})".format(
                node.get("n_signers", "?"), node.get("signer_indices", [])))

            has_tap = node.get("has_taptree", False)
            lines.append("- **Taproot tree:** {}".format("yes" if has_tap else "key-path only"))

            agg = node.get("agg_pubkey", "")
            if agg:
                lines.append("- **Aggregate pubkey:** `{}...`".format(agg[:24]))

            outputs = node.get("outputs", [])
            if outputs:
                lines.append("- **Outputs ({}):**".format(len(outputs)))
                for i, o in enumerate(outputs):
                    amt = o.get("amount_sats", 0)
                    spk = o.get("script_pubkey", "")
                    otype = classify_output_type(spk)
                    lines.append("  - vout {}: {} sats -- {}".format(i, amt, otype))

            # If we have RPC access, fetch on-chain data
            if rpc and txid and txid != "?":
                tx_data = rpc.getrawtx(txid)
                if tx_data:
                    conf = tx_data.get("confirmations", 0)
                    bh = tx_data.get("blockhash", "")
                    vsize = tx_data.get("vsize", "?")
                    weight = tx_data.get("weight", "?")
                    lines.append("- **On-chain:** {} confirmations, vsize={}, weight={}".format(
                        conf, vsize, weight))
                    if bh:
                        block = rpc.getblock(bh)
                        if block:
                            lines.append("- **Block:** height {}".format(block.get("height", "?")))

                    # Witness analysis for each input
                    vin = tx_data.get("vin", [])
                    for vi, inp in enumerate(vin):
                        wit = inp.get("txinwitness", [])
                        if wit:
                            lines.append("- **Input {} witness:** {}".format(
                                vi, classify_witness(wit)))

            lines.append("")

    # Extra TXs (close, penalty, burn, distribution) from report
    for key in ["close_tx", "penalty_txs", "burn_tx", "distribution_tx",
                "expiry_txs", "htlc_timeout_txs"]:
        val = report_data.get(key)
        if val:
            lines.append("## {}".format(key.replace("_", " ").title()))
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        txid = item.get("txid", "?")
                        lines.append("- `{}`".format(txid))
                    else:
                        lines.append("- `{}`".format(item))
            elif isinstance(val, dict):
                txid = val.get("txid", "?")
                lines.append("- `{}`".format(txid))
            else:
                lines.append("- `{}`".format(val))
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report generation from raw TXIDs
# ---------------------------------------------------------------------------

def report_from_txids(txids, rpc, labels=None):
    """Generate markdown report from a list of TXIDs fetched on-chain."""
    lines = []
    lines.append("# SuperScalar On-Chain TX Report")
    lines.append("")
    lines.append("- **TXIDs inspected:** {}".format(len(txids)))
    lines.append("- **Network:** {}".format(rpc.network))
    lines.append("")
    lines.append("| # | Label | TXID | Confirms | vsize | Fee | Outputs |")
    lines.append("|---|-------|------|----------|-------|-----|---------|")

    details = []
    for i, txid in enumerate(txids):
        label = (labels[i] if labels and i < len(labels)
                 else "tx_{}".format(i))
        tx = rpc.getrawtx(txid)
        if not tx:
            lines.append("| {} | {} | `{}...` | NOT FOUND | - | - | - |".format(
                i, label, txid[:12]))
            continue

        conf = tx.get("confirmations", 0)
        vsize = tx.get("vsize", "?")
        fee_btc = tx.get("fee")
        fee_str = "{} sat".format(int(fee_btc * 1e8)) if fee_btc else "?"
        vout = tx.get("vout", [])
        n_out = len(vout)
        out_total = sum(int(round(o.get("value", 0) * 1e8)) for o in vout)

        lines.append(
            "| {} | {} | `{}...` | {} | {} | {} | {} ({} sat) |".format(
                i, label, txid[:12], conf, vsize, fee_str, n_out, out_total))
        details.append((i, label, txid, tx))

    lines.append("")

    # Detailed breakdown
    for i, label, txid, tx in details:
        lines.append("## TX {}: {}".format(i, label))
        lines.append("- **TXID:** `{}`".format(txid))

        conf = tx.get("confirmations", 0)
        bh = tx.get("blockhash", "")
        lines.append("- **Confirmations:** {}".format(conf))

        if bh:
            block = rpc.getblock(bh)
            if block:
                lines.append("- **Block height:** {}".format(block.get("height", "?")))

        vsize = tx.get("vsize", "?")
        weight = tx.get("weight", "?")
        lines.append("- **Size:** vsize={}, weight={}".format(vsize, weight))

        nlt = tx.get("locktime", 0)
        lines.append("- **nLockTime:** {}".format(interpret_nlocktime(nlt)))

        # Inputs
        vin = tx.get("vin", [])
        lines.append("- **Inputs ({}):**".format(len(vin)))
        for vi, inp in enumerate(vin):
            prev_txid = inp.get("txid", "coinbase")
            prev_vout = inp.get("vout", 0)
            seq = inp.get("sequence", 0xFFFFFFFF)
            wit = inp.get("txinwitness", [])
            lines.append("  - vin {}: `{}...`:{} nSeq={}".format(
                vi, prev_txid[:12], prev_vout, interpret_nsequence(seq)))
            if wit:
                lines.append("    witness: {}".format(classify_witness(wit)))

        # Outputs
        vout = tx.get("vout", [])
        lines.append("- **Outputs ({}):**".format(len(vout)))
        for o in vout:
            n = o.get("n", 0)
            val_sat = int(round(o.get("value", 0) * 1e8))
            spk = o.get("scriptPubKey", {})
            spk_hex = spk.get("hex", "")
            spk_type = spk.get("type", "")
            addr = spk.get("address", "")
            otype = classify_output_type(spk_hex)
            addr_str = " `{}`".format(addr) if addr else ""
            lines.append("  - vout {}: {} sats -- {} ({}){}".format(
                n, val_sat, otype, spk_type, addr_str))

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SuperScalar on-chain TX tree inspector")
    parser.add_argument("--report", type=str,
                        help="Path to LSP report JSON file")
    parser.add_argument("--txid-file", type=str,
                        help="Path to JSON file with list of TXIDs")
    parser.add_argument("--txid", type=str,
                        help="Single TXID to inspect")
    parser.add_argument("--network", type=str, default="regtest",
                        help="Network (regtest, signet, testnet4)")
    parser.add_argument("--rpcuser", type=str, default=None)
    parser.add_argument("--rpcpassword", type=str, default=None)
    parser.add_argument("--rpcport", type=int, default=None)
    parser.add_argument("--bitcoin-cli", type=str, default="bitcoin-cli")
    parser.add_argument("--on-chain", action="store_true",
                        help="Also fetch on-chain data for report TXs")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output file (default: stdout)")
    args = parser.parse_args()

    rpc = None
    if args.on_chain or args.txid or args.txid_file:
        rpc = BitcoinRPC(
            cli_path=args.bitcoin_cli,
            network=args.network,
            rpcuser=args.rpcuser,
            rpcpassword=args.rpcpassword,
            rpcport=args.rpcport,
        )

    md = ""

    if args.report:
        with open(args.report) as f:
            data = json.load(f)
        md = report_from_lsp_json(data, rpc=rpc if args.on_chain else None)

    elif args.txid_file:
        with open(args.txid_file) as f:
            txid_data = json.load(f)
        # Support both flat list and labeled dict
        if isinstance(txid_data, list):
            txids = txid_data
            labels = None
        elif isinstance(txid_data, dict):
            # {"label": "txid", ...} or {"txids": [...], "labels": [...]}
            if "txids" in txid_data:
                txids = txid_data["txids"]
                labels = txid_data.get("labels")
            else:
                labels = list(txid_data.keys())
                txids = list(txid_data.values())
        else:
            print("ERROR: txid-file must be a JSON list or object", file=sys.stderr)
            return 1
        md = report_from_txids(txids, rpc, labels)

    elif args.txid:
        md = report_from_txids([args.txid], rpc, [args.txid[:12]])

    else:
        parser.print_help()
        return 1

    if args.output:
        with open(args.output, "w") as f:
            f.write(md + "\n")
        print("Report written to {}".format(args.output))
    else:
        print(md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
