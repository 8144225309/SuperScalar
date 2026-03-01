#!/usr/bin/env python3
"""
SuperScalar CLN Plugin

Bridges Core Lightning to the SuperScalar bridge daemon via TCP.
Handles:
  - htlc_accepted hook: selectively forwards factory HTLCs to bridge
  - invoice_registered from bridge: creates CLN invoice with known preimage
  - superscalar-pay RPC: convenience wrapper for lightning-cli pay
  - pay_request from bridge: calls lightning-cli pay for outbound LN payments

Non-factory HTLCs pass through to CLN's normal handling, so traditional
Lightning channels continue to work unaffected.

Usage:
  lightningd --plugin=/path/to/cln_plugin.py \
             --superscalar-bridge-host=127.0.0.1 \
             --superscalar-bridge-port=9736 \
             --superscalar-lightning-cli=lightning-cli
"""

import hashlib
import json
import socket
import subprocess
import sys
import threading
import time

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 9736
LIGHTNING_CLI = "lightning-cli"
LIGHTNING_DIR = None   # set from CLN init, passed to lightning-cli
KEYSEND_DEFAULT_CLIENT = 0  # default dest_client for keysend payments
bridge_sock = None
# Keyed by payment_hash (hex string) — immune to htlc_id counter desync
pending_htlcs = {}   # payment_hash -> rpc_id for resolving
pending_pays = {}    # request_id -> rpc_id for superscalar-pay responses
registered_invoices = set()   # payment_hash hex strings for factory clients
lock = threading.Lock()
cln_lock = threading.Lock()  # serializes writes to CLN stdout

# Keysend TLV type used by CLN/LND for spontaneous payments (BOLT TLV)
KEYSEND_TLV_TYPE = "5482373484"


def cli_cmd(*args):
    """Build a lightning-cli command with proper --lightning-dir and --network.
    CLN v25 sets lightning-dir to the network-specific subdir (e.g., .../cln/regtest),
    but lightning-cli --lightning-dir expects the parent dir and appends its own
    network subdir.  Split the path so both sides agree."""
    cmd = [LIGHTNING_CLI]
    if LIGHTNING_DIR:
        import os
        parent = os.path.dirname(LIGHTNING_DIR)
        network = os.path.basename(LIGHTNING_DIR)
        cmd.extend(["--lightning-dir", parent, "--network", network])
    cmd.extend(args)
    return cmd


def log(msg):
    """Write to CLN's log via stderr."""
    sys.stderr.write(f"superscalar: {msg}\n")
    sys.stderr.flush()


def send_to_cln(response):
    """Send JSON-RPC response to CLN (thread-safe).
    CLN v25+ uses \\n\\n as message delimiter."""
    with cln_lock:
        sys.stdout.write(json.dumps(response) + "\n\n")
        sys.stdout.flush()


def send_to_bridge(msg):
    """Send newline-delimited JSON to bridge (thread-safe)."""
    global bridge_sock
    with lock:
        sock = bridge_sock
    if sock is None:
        return False
    try:
        data = json.dumps(msg) + "\n"
        with lock:
            sock.sendall(data.encode())
        return True
    except Exception as e:
        log(f"send_to_bridge error: {e}")
        return False


def connect_bridge():
    """Connect to the SuperScalar bridge daemon."""
    global bridge_sock
    try:
        sock = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT))
        with lock:
            bridge_sock = sock
        log(f"Connected to bridge at {BRIDGE_HOST}:{BRIDGE_PORT}")
        return True
    except Exception as e:
        log(f"Failed to connect to bridge: {e}")
        return False


def bridge_reader():
    """Read responses from bridge and resolve pending HTLCs/pays.
    Reconnects automatically on disconnect."""
    global bridge_sock
    while True:
        buf = b""
        while True:
            try:
                with lock:
                    sock = bridge_sock
                if sock is None:
                    break
                data = sock.recv(4096)
                if not data:
                    log("Bridge connection closed")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    msg = json.loads(line)
                    handle_bridge_msg(msg)
            except Exception as e:
                log(f"bridge_reader error: {e}")
                break

        # Connection lost — attempt reconnect
        with lock:
            bridge_sock = None
        log("Bridge disconnected, will retry in 5s...")
        time.sleep(5)
        while not connect_bridge():
            log("Bridge reconnect failed, retrying in 5s...")
            time.sleep(5)
        # Clean up orphaned HTLCs from the old connection — send "continue"
        # so CLN retries or resolves them via its own invoice DB
        with lock:
            orphans = dict(pending_htlcs)
            pending_htlcs.clear()
        for ph, rid in orphans.items():
            log(f"Orphaned HTLC {ph[:16]}... — returning continue")
            send_to_cln({
                "jsonrpc": "2.0",
                "id": rid,
                "result": {"result": "continue"}
            })
        log("Bridge reconnected")


def handle_bridge_msg(msg):
    """Handle a message from the bridge."""
    method = msg.get("method", "")

    if method == "htlc_resolve":
        payment_hash = msg.get("payment_hash", "")
        result = msg.get("result")
        log(f"htlc_resolve: hash={payment_hash[:16]}... result={result}")
        with lock:
            rpc_id = pending_htlcs.pop(payment_hash, None)
            # Clean up resolved invoice from registry
            registered_invoices.discard(payment_hash)

        if rpc_id is None:
            log(f"No pending HTLC for hash {payment_hash[:16]}...")
            return

        if result == "fulfill":
            preimage = msg.get("preimage", "")
            send_to_cln({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "result": "resolve",
                    "payment_key": preimage
                }
            })
        else:
            reason = msg.get("reason", "unknown")
            # If bridge rejects with unknown_payment_hash, let CLN handle it
            if reason == "unknown_payment_hash":
                send_to_cln({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"result": "continue"}
                })
            else:
                # CLN v25+ requires failure_message for hook fail.
                # 2002 = TEMPORARY_NODE_FAILURE (BOLT #4 wire format).
                send_to_cln({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "result": "fail",
                        "failure_message": "2002"
                    }
                })

    elif method == "invoice_registered":
        # Bridge forwarded a registered invoice — create CLN invoice with
        # the known preimage so external LN nodes can pay it
        payment_hash = msg.get("payment_hash", "")
        preimage_hex = msg.get("preimage", "")
        amount_msat = int(msg.get("amount_msat", 0))
        t = threading.Thread(
            target=_create_cln_invoice,
            args=(payment_hash, preimage_hex, amount_msat),
            daemon=True
        )
        t.start()

    elif method == "pay_request":
        bolt11 = msg.get("bolt11", "")
        request_id = msg.get("request_id", 0)
        log(f"Pay request: {bolt11[:30]}... (id={request_id})")
        # Run lightning-cli pay in a background thread to avoid blocking
        t = threading.Thread(target=_do_pay, args=(bolt11, request_id), daemon=True)
        t.start()

    elif method == "pay_result":
        # Response from bridge for a superscalar-pay RPC call
        request_id = msg.get("request_id", 0)
        success = msg.get("success", False)
        preimage = msg.get("preimage", "00" * 32)
        with lock:
            rpc_id = pending_pays.pop(request_id, None)
        if rpc_id is not None:
            if success:
                send_to_cln({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"status": "complete", "payment_preimage": preimage}
                })
            else:
                send_to_cln({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"status": "failed"}
                })
        else:
            log(f"No pending pay for request_id {request_id}")


def _create_cln_invoice(payment_hash, preimage_hex, amount_msat):
    """Create a CLN invoice with a known preimage and send BOLT11 back to bridge."""
    label = f"superscalar-{payment_hash[:16]}-{int(time.time())}"
    try:
        cmd = cli_cmd(
            "invoice",
            str(amount_msat),
            label,
            "SuperScalar factory payment",
            "3600",    # expiry seconds
            "null",    # fallbacks
            preimage_hex
        )
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            inv_result = json.loads(result.stdout)
            bolt11 = inv_result.get("bolt11", "")
            with lock:
                registered_invoices.add(payment_hash)
            log(f"Created CLN invoice for {payment_hash[:16]}...")
            # Send BOLT11 back to bridge for forwarding to client
            send_to_bridge({
                "method": "invoice_bolt11",
                "payment_hash": payment_hash,
                "bolt11": bolt11
            })
        else:
            log(f"CLN invoice creation failed: {result.stderr[:200]}")
            # Notify bridge of failure so client doesn't wait forever
            send_to_bridge({
                "method": "invoice_bolt11",
                "payment_hash": payment_hash,
                "bolt11": ""
            })
    except Exception as e:
        log(f"CLN invoice exception: {e}")
        send_to_bridge({
            "method": "invoice_bolt11",
            "payment_hash": payment_hash,
            "bolt11": ""
        })


def _do_pay(bolt11, request_id):
    """Execute lightning-cli pay in a subprocess and report result to bridge."""
    try:
        result = subprocess.run(
            cli_cmd("pay", bolt11),
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            pay_result = json.loads(result.stdout)
            preimage = pay_result.get("payment_preimage", "00" * 32)
            send_to_bridge({
                "method": "pay_result",
                "request_id": request_id,
                "success": True,
                "preimage": preimage
            })
            log(f"Pay succeeded: {preimage[:16]}...")
        else:
            log(f"Pay failed: {result.stderr[:100]}")
            send_to_bridge({
                "method": "pay_result",
                "request_id": request_id,
                "success": False,
                "preimage": "00" * 32
            })
    except Exception as e:
        log(f"Pay exception: {e}")
        send_to_bridge({
            "method": "pay_result",
            "request_id": request_id,
            "success": False,
            "preimage": "00" * 32
        })


def _extract_keysend_preimage(params):
    """Check if the HTLC contains a keysend TLV (type 5482373484).
    Returns the preimage hex string if found and valid, None otherwise."""
    onion = params.get("onion", {})
    payload = onion.get("payload", "")
    # CLN provides the payload as a hex-encoded TLV stream; but the
    # individual TLVs are typically pre-parsed in onion.type and
    # onion.short_channel_id etc.  The keysend preimage is in the
    # per-hop payload's TLV.  CLN exposes it in onion.payload as raw
    # hex, or sometimes in a "tlvs" field depending on version.

    # Method 1: CLN v24+ may include parsed TLVs
    tlvs = onion.get("tlvs", {})
    if KEYSEND_TLV_TYPE in tlvs:
        return tlvs[KEYSEND_TLV_TYPE]

    # Method 2: Some CLN versions put keysend preimage in onion payload
    # as raw hex TLV stream — parse manually
    if payload and len(payload) > 64:
        try:
            raw = bytes.fromhex(payload)
            offset = 0
            while offset < len(raw):
                # TLV: varint type, varint length, value
                tlv_type, offset = _read_varint(raw, offset)
                tlv_len, offset = _read_varint(raw, offset)
                if offset + tlv_len > len(raw):
                    break
                if str(tlv_type) == KEYSEND_TLV_TYPE and tlv_len == 32:
                    return raw[offset:offset + tlv_len].hex()
                offset += tlv_len
        except Exception:
            pass

    return None


def _read_varint(data, offset):
    """Read a BigSize varint from data at offset. Returns (value, new_offset)."""
    if offset >= len(data):
        raise ValueError("varint: no data")
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        return int.from_bytes(data[offset+1:offset+3], 'big'), offset + 3
    elif first == 0xfe:
        return int.from_bytes(data[offset+1:offset+5], 'big'), offset + 5
    else:
        return int.from_bytes(data[offset+1:offset+9], 'big'), offset + 9


def handle_htlc_accepted(rpc_id, params):
    """Handle the htlc_accepted hook from CLN.
    Forwards HTLCs for registered factory invoices to the bridge.
    Detects keysend TLV and routes spontaneous payments to factory clients.
    All other HTLCs are passed through to CLN's normal handling."""
    htlc = params.get("htlc", {})
    payment_hash = htlc.get("payment_hash", "")
    # CLN may send amount_msat as int or string "Nmsat" depending on version
    raw_amt = htlc.get("amount_msat", 0)
    amount_msat = int(str(raw_amt).replace("msat", ""))
    cltv_expiry = htlc.get("cltv_expiry", 0)

    # Check if this HTLC is for a registered factory invoice
    with lock:
        is_ours = payment_hash in registered_invoices
        n_registered = len(registered_invoices)

    # Check for keysend TLV if not a registered invoice
    keysend_preimage = None
    if not is_ours:
        keysend_preimage = _extract_keysend_preimage(params)
        if keysend_preimage:
            # Verify SHA256(preimage) == payment_hash
            preimage_bytes = bytes.fromhex(keysend_preimage)
            expected_hash = hashlib.sha256(preimage_bytes).hexdigest()
            if expected_hash != payment_hash:
                log(f"Keysend preimage mismatch: SHA256(preimage)={expected_hash[:16]}... "
                    f"!= hash={payment_hash[:16]}...")
                keysend_preimage = None

    log(f"htlc_accepted: hash={payment_hash[:16]}... amt={amount_msat} "
        f"cltv={cltv_expiry} ours={is_ours} keysend={keysend_preimage is not None} "
        f"(registry={n_registered})")

    if not is_ours and not keysend_preimage:
        # Not a factory payment and not keysend — let CLN handle it normally
        send_to_cln({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"result": "continue"}
        })
        return

    # Register pending HTLC keyed by payment_hash (no counter desync risk)
    with lock:
        if payment_hash in pending_htlcs:
            # Duplicate HTLC for same hash (MPP or retry) — let CLN handle
            log(f"Duplicate HTLC for {payment_hash[:16]}..., passing to CLN")
            send_to_cln({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"result": "continue"}
            })
            return
        pending_htlcs[payment_hash] = rpc_id

    # Build bridge message
    bridge_msg = {
        "method": "htlc_accepted",
        "payment_hash": payment_hash,
        "amount_msat": amount_msat,
        "cltv_expiry": cltv_expiry
    }
    if keysend_preimage:
        bridge_msg["keysend"] = True
        bridge_msg["preimage"] = keysend_preimage
        bridge_msg["dest_client"] = KEYSEND_DEFAULT_CLIENT

    log(f"Forwarding HTLC {payment_hash[:16]}... to bridge"
        f"{' (keysend)' if keysend_preimage else ''}")
    ok = send_to_bridge(bridge_msg)

    if not ok:
        log(f"Bridge send failed for HTLC {payment_hash[:16]}...")
        # Bridge not connected — let CLN handle it (maybe CLN has the invoice)
        with lock:
            pending_htlcs.pop(payment_hash, None)
        send_to_cln({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"result": "continue"}
        })


def read_requests():
    """Read JSON-RPC requests from CLN stdin.
    CLN v25+ uses \\n\\n as message delimiter; messages may span lines."""
    buf = ""
    for line in sys.stdin:
        if line.strip() == "":
            # Empty line = message boundary
            if buf.strip():
                yield json.loads(buf)
                buf = ""
        else:
            buf += line
    # Handle any remaining buffer at EOF
    if buf.strip():
        yield json.loads(buf)


def main():
    global BRIDGE_HOST, BRIDGE_PORT, LIGHTNING_CLI, LIGHTNING_DIR

    # CLN plugin main loop: read JSON-RPC requests
    for request in read_requests():
        method = request.get("method", "")

        if method == "getmanifest":
            send_to_cln({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "dynamic": True,
                    "options": [
                        {
                            "name": "superscalar-bridge-host",
                            "type": "string",
                            "default": "127.0.0.1",
                            "description": "SuperScalar bridge host"
                        },
                        {
                            "name": "superscalar-bridge-port",
                            "type": "int",
                            "default": 9736,
                            "description": "SuperScalar bridge port"
                        },
                        {
                            "name": "superscalar-lightning-cli",
                            "type": "string",
                            "default": "lightning-cli",
                            "description": "Path to lightning-cli binary"
                        }
                    ],
                    "rpcmethods": [
                        {
                            "name": "superscalar-pay",
                            "usage": "bolt11",
                            "description": "Pay via SuperScalar bridge"
                        }
                    ],
                    "hooks": [
                        {"name": "htlc_accepted", "before": ["keysend"]}
                    ],
                    "subscriptions": []
                }
            })

        elif method == "init":
            config = request.get("params", {}).get("options", {})
            BRIDGE_HOST = config.get("superscalar-bridge-host", BRIDGE_HOST)
            BRIDGE_PORT = int(config.get("superscalar-bridge-port", BRIDGE_PORT))
            LIGHTNING_CLI = config.get("superscalar-lightning-cli", LIGHTNING_CLI)

            # Capture lightning-dir from CLN's configuration so we can
            # pass it to lightning-cli subprocess calls
            cln_config = request.get("params", {}).get("configuration", {})
            LIGHTNING_DIR = cln_config.get("lightning-dir")

            connected = connect_bridge()
            # Always start bridge_reader — it reconnects on disconnect
            t = threading.Thread(target=bridge_reader, daemon=True)
            t.start()

            send_to_cln({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {}
            })
            log(f"Plugin initialized (bridge={'connected' if connected else 'disconnected'}, "
                f"cli={LIGHTNING_CLI}, dir={LIGHTNING_DIR})")

        elif method == "htlc_accepted":
            handle_htlc_accepted(request["id"], request.get("params", {}))

        elif method == "superscalar-pay":
            bolt11 = request.get("params", [""])[0] if request.get("params") else ""
            log(f"superscalar-pay: {bolt11[:30]}...")
            rpc_id = request["id"]
            # Pay directly via lightning-cli (reuses existing _do_pay path)
            def _pay_and_respond(bolt11_str, rpc_id_val):
                try:
                    result = subprocess.run(
                        cli_cmd("pay", bolt11_str),
                        capture_output=True, text=True, timeout=600
                    )
                    if result.returncode == 0:
                        pay_result = json.loads(result.stdout)
                        preimage = pay_result.get("payment_preimage", "00" * 32)
                        send_to_cln({
                            "jsonrpc": "2.0",
                            "id": rpc_id_val,
                            "result": {"status": "complete", "payment_preimage": preimage}
                        })
                    else:
                        log(f"superscalar-pay failed: {result.stderr[:100]}")
                        send_to_cln({
                            "jsonrpc": "2.0",
                            "id": rpc_id_val,
                            "result": {"status": "failed"}
                        })
                except Exception as e:
                    log(f"superscalar-pay exception: {e}")
                    send_to_cln({
                        "jsonrpc": "2.0",
                        "id": rpc_id_val,
                        "result": {"status": "failed"}
                    })
            t = threading.Thread(target=_pay_and_respond,
                                 args=(bolt11, rpc_id), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
