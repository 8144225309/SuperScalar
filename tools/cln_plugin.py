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

import json
import socket
import subprocess
import sys
import threading
import time

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 9736
LIGHTNING_CLI = "lightning-cli"
bridge_sock = None
pending_htlcs = {}   # htlc_id -> rpc_id for resolving
pending_pays = {}    # request_id -> rpc_id for superscalar-pay responses
registered_invoices = set()   # payment_hash hex strings for factory clients
next_request_id = 1
next_htlc_id = 1
lock = threading.Lock()


def log(msg):
    """Write to CLN's log via stderr."""
    sys.stderr.write(f"superscalar: {msg}\n")
    sys.stderr.flush()


def send_to_cln(response):
    """Send JSON-RPC response to CLN."""
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def send_to_bridge(msg):
    """Send newline-delimited JSON to bridge."""
    global bridge_sock
    if bridge_sock is None:
        return False
    try:
        data = json.dumps(msg) + "\n"
        bridge_sock.sendall(data.encode())
        return True
    except Exception as e:
        log(f"send_to_bridge error: {e}")
        return False


def connect_bridge():
    """Connect to the SuperScalar bridge daemon."""
    global bridge_sock
    try:
        bridge_sock = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT))
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
                if bridge_sock is None:
                    break
                data = bridge_sock.recv(4096)
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
        bridge_sock = None
        log("Bridge disconnected, will retry in 5s...")
        time.sleep(5)
        while not connect_bridge():
            log("Bridge reconnect failed, retrying in 5s...")
            time.sleep(5)
        log("Bridge reconnected")


def handle_bridge_msg(msg):
    """Handle a message from the bridge."""
    method = msg.get("method", "")

    if method == "htlc_resolve":
        htlc_id = msg.get("htlc_id")
        result = msg.get("result")
        with lock:
            rpc_id = pending_htlcs.pop(htlc_id, None)

        if rpc_id is None:
            log(f"No pending HTLC for id {htlc_id}")
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
                send_to_cln({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "result": "fail",
                        "failure_message": reason
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
        cmd = [
            LIGHTNING_CLI, "invoice",
            str(amount_msat),
            label,
            "SuperScalar factory payment",
            "3600",    # expiry seconds
            "null",    # fallbacks
            preimage_hex
        ]
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
    except Exception as e:
        log(f"CLN invoice exception: {e}")


def _do_pay(bolt11, request_id):
    """Execute lightning-cli pay in a subprocess and report result to bridge."""
    try:
        result = subprocess.run(
            [LIGHTNING_CLI, "pay", bolt11],
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


def handle_htlc_accepted(rpc_id, params):
    """Handle the htlc_accepted hook from CLN.
    Only forwards HTLCs for registered factory invoices to the bridge.
    All other HTLCs are passed through to CLN's normal handling."""
    htlc = params.get("htlc", {})
    payment_hash = htlc.get("payment_hash", "")
    amount_msat = int(htlc.get("amount_msat", "0msat").replace("msat", ""))
    cltv_expiry = htlc.get("cltv_expiry", 0)

    # Check if this HTLC is for a registered factory invoice
    with lock:
        is_ours = payment_hash in registered_invoices

    if not is_ours:
        # Not a factory payment — let CLN handle it normally
        send_to_cln({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"result": "continue"}
        })
        return

    # Assign local htlc_id (monotonic to avoid collisions after pops)
    global next_htlc_id
    with lock:
        htlc_id = next_htlc_id
        next_htlc_id += 1
        pending_htlcs[htlc_id] = rpc_id

    ok = send_to_bridge({
        "method": "htlc_accepted",
        "payment_hash": payment_hash,
        "amount_msat": amount_msat,
        "cltv_expiry": cltv_expiry,
        "htlc_id": htlc_id
    })

    if not ok:
        # Bridge not connected — let CLN handle it (maybe CLN has the invoice)
        with lock:
            pending_htlcs.pop(htlc_id, None)
        send_to_cln({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"result": "continue"}
        })


def main():
    global BRIDGE_HOST, BRIDGE_PORT, LIGHTNING_CLI, next_request_id

    # CLN plugin initialization: read getmanifest
    for line in sys.stdin:
        request = json.loads(line)
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
                f"cli={LIGHTNING_CLI})")

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
                        [LIGHTNING_CLI, "pay", bolt11_str],
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
