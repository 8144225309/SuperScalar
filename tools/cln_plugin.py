#!/usr/bin/env python3
"""
SuperScalar CLN Plugin

Bridges Core Lightning to the SuperScalar bridge daemon via TCP.
Handles:
  - htlc_accepted hook: selectively forwards factory HTLCs to bridge
  - invoice_registered from bridge: creates CLN invoice with known preimage
  - superscalar-pay RPC: convenience wrapper for lightning-cli pay
  - pay_request from bridge: pays an outside invoice with lightning-cli pay,
    after checking it against the payment hash and spend cap the bridge sent

Non-factory HTLCs pass through to CLN's normal handling, so traditional
Lightning channels continue to work unaffected.

CLN holds every factory invoice together with its preimage, so if the hook
answered "continue" for an HTLC paying one, CLN would settle the invoice
itself and the factory client would never be paid.  HTLCs for factory
invoices are therefore only ever resolved (on the LSP's word) or failed.

The bridge and this plugin share a secret, which the bridge writes to a file
(mode 0600) when it first starts.  The secret never crosses the link: each
side sends a random nonce and proves knowledge of the secret with an HMAC
over both nonces.  The plugin checks the bridge's proof first and takes no
message from a peer that has not given it.

Usage:
  lightningd --plugin=/path/to/cln_plugin.py \
             --superscalar-bridge-host=127.0.0.1 \
             --superscalar-bridge-port=9736 \
             --superscalar-bridge-secret-file=~/.superscalar/bridge-plugin.secret \
             --superscalar-lightning-cli=lightning-cli
"""

import hashlib
import hmac
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 9736
# File holding the secret the bridge expects (written by superscalar_bridge)
BRIDGE_SECRET_FILE = "~/.superscalar/bridge-plugin.secret"
LIGHTNING_CLI = "lightning-cli"
LIGHTNING_DIR = None   # set from CLN init, passed to lightning-cli
KEYSEND_DEFAULT_CLIENT = 0  # default dest_client for keysend (overridable via plugin option)
ROUTE_HINT = None  # "node_id/scid/fee_base/fee_ppm/cltv_delta" for factory channels
bridge_sock = None
# Keyed by payment_hash (hex string) — immune to htlc_id counter desync
# payment_hash -> {"rpc_id": hook request to answer,
#                  "factory_invoice": True if CLN holds this hash's invoice,
#                  "upstream": CLN's own name for the HTLC ("" if unknown)}
pending_htlcs = {}
pending_pays = {}    # request_id -> rpc_id for superscalar-pay responses
registered_invoices = set()   # payment_hash hex strings for factory clients
# True once registered_invoices has been rebuilt from CLN's invoice list.
# Until then an unlisted hash may still be a factory invoice.
registry_recovered = False
lock = threading.Lock()
send_lock = threading.Lock()  # serializes sendall to bridge socket
cln_lock = threading.Lock()  # serializes writes to CLN stdout

# Keysend TLV type used by CLN/LND for spontaneous payments (BOLT TLV)
KEYSEND_TLV_TYPE = "5482373484"

# min_final_cltv_expiry for factory invoices.  Must exceed LSP's
# FACTORY_CLTV_DELTA (40) so the HTLC arriving at the LSP still has
# enough blocks of margin before the timeout check fires.
FACTORY_INVOICE_CLTV = 80

# Outbound pays.  CLN's `pay` stops starting new attempts after
# PAY_RETRY_FOR seconds; parts already in flight can still settle later.
PAY_RETRY_FOR = 60
PAY_CLI_TIMEOUT = 600      # how long to wait for `pay` itself to return
PAY_POLL_INTERVAL = 10     # seconds between listpays polls while unresolved
PAY_SETTLE_GRACE = 30      # slack added to PAY_RETRY_FOR before trusting "failed"


_KNOWN_NETWORKS = {"bitcoin", "testnet", "signet", "regtest", "testnet4", "liquidv1"}

def cli_cmd(*args):
    """Build a lightning-cli command with proper --lightning-dir and --network.
    CLN v25 sets lightning-dir to the network-specific subdir (e.g., .../cln/regtest),
    but lightning-cli --lightning-dir expects the parent dir and appends its own
    network subdir.  Split the path so both sides agree."""
    cmd = LIGHTNING_CLI.split()
    if LIGHTNING_DIR:
        tail = os.path.basename(LIGHTNING_DIR)
        if tail in _KNOWN_NETWORKS:
            # CLN v25+: lightning-dir includes network subdir — split it
            cmd.extend(["--lightning-dir", os.path.dirname(LIGHTNING_DIR),
                         "--network", tail])
        else:
            # Older CLN or custom dir — pass as-is
            cmd.extend(["--lightning-dir", LIGHTNING_DIR])
    cmd.extend(args)
    return cmd


class ClnRpcError(Exception):
    """CLN answered an RPC call with an error."""
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def cln_rpc(method, params=None, timeout=60):
    """Call a CLN RPC method through lightning-cli with keyword parameters.
    Returns the decoded result.  Raises ClnRpcError if CLN reports an error
    and subprocess.TimeoutExpired if lightning-cli does not return in time."""
    args = ["-k", method]
    for key, value in (params or {}).items():
        args.append(f"{key}={value}")
    result = subprocess.run(cli_cmd(*args), capture_output=True, text=True,
                            timeout=timeout)
    if result.returncode != 0:
        code = None
        message = (result.stdout or result.stderr or "").strip()[:300]
        try:
            err = json.loads(result.stdout)
            code = err.get("code")
            message = err.get("message", message)
        except (ValueError, AttributeError):
            pass
        raise ClnRpcError(message, code)
    return json.loads(result.stdout)


def _msat(value):
    """Parse a CLN millisatoshi amount (int, or "123msat" in older releases).
    Returns None if there is no usable amount."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value).replace("msat", ""))
    except ValueError:
        return None


def _is_hash(value):
    """True for a 32-byte value in hex."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


_can_log_to_cln = False

def log(msg):
    """Write to CLN's log via JSON-RPC notification (after init) or stderr."""
    if _can_log_to_cln:
        # CLN captures 'log' notifications and shows them in its log file
        try:
            send_to_cln({
                "jsonrpc": "2.0",
                "method": "log",
                "params": {"level": "info", "message": f"superscalar: {msg}"}
            })
            return
        except Exception:
            pass
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
        with send_lock:
            sock.sendall(data.encode())
        return True
    except Exception as e:
        log(f"send_to_bridge error: {e}")
        return False


def read_bridge_secret():
    """Read the shared secret (64 hex characters) from BRIDGE_SECRET_FILE.

    The file must be a regular file owned by the user this plugin runs as,
    with no access for group or others; anything else could have been
    written or read by someone else.  Returns None if it cannot be used."""
    path = os.path.expanduser(BRIDGE_SECRET_FILE)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        log(f"Cannot read bridge secret {path}: {e}")
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() \
                or st.st_mode & 0o077:
            log(f"Bridge secret {path} must be a regular file owned by this "
                f"user with mode 0600")
            return None
        secret = os.read(fd, 256).decode("ascii", "replace").strip()
    except OSError as e:
        log(f"Cannot read bridge secret {path}: {e}")
        return None
    finally:
        os.close(fd)
    if not _is_hash(secret):
        log(f"Bridge secret {path} is not 64 hex characters")
        return None
    return secret


AUTH_LABEL = b"superscalar-bridge-plugin-auth-v1/"
AUTH_TIMEOUT = 10   # seconds the bridge has for each handshake step


def auth_proof(secret, role, plugin_nonce, bridge_nonce):
    """What one side sends to show it knows the secret: HMAC-SHA256 keyed
    with the secret over the side's role and both nonces (hex)."""
    return hmac.new(bytes.fromhex(secret),
                    AUTH_LABEL + role + b"/" + plugin_nonce + bridge_nonce,
                    hashlib.sha256).hexdigest()


def _recv_line(sock, limit=1024):
    """Read one newline-terminated line, a byte at a time so nothing past
    it is consumed.  Returns None if the peer closes or sends too much."""
    line = b""
    while len(line) < limit:
        c = sock.recv(1)
        if not c:
            return None
        if c == b"\n":
            return line
        line += c
    return None


def authenticate_bridge(sock, secret):
    """Run the handshake on a fresh connection.  Returns True only if the
    peer proved it holds the secret; our own proof is sent after that and
    the secret itself is never sent."""
    plugin_nonce = os.urandom(32)
    sock.sendall((json.dumps({"method": "auth_hello",
                              "nonce": plugin_nonce.hex()}) + "\n").encode())
    try:
        challenge = json.loads(_recv_line(sock) or b"null")
    except ValueError:
        challenge = None
    if not isinstance(challenge, dict) \
            or challenge.get("method") != "auth_challenge" \
            or not _is_hash(challenge.get("nonce")) \
            or not _is_hash(challenge.get("proof")):
        log("Bridge did not answer the handshake")
        return False
    bridge_nonce = bytes.fromhex(challenge["nonce"])
    expected = auth_proof(secret, b"bridge", plugin_nonce, bridge_nonce)
    if not hmac.compare_digest(expected, challenge["proof"].lower()):
        log("Peer on the bridge port does not hold the bridge secret")
        return False

    sock.sendall((json.dumps({
        "method": "auth_response",
        "proof": auth_proof(secret, b"plugin", plugin_nonce, bridge_nonce)
    }) + "\n").encode())
    try:
        accepted = json.loads(_recv_line(sock) or b"null")
    except ValueError:
        accepted = None
    if not isinstance(accepted, dict) or accepted.get("method") != "auth_ok":
        log("Bridge did not accept our proof")
        return False
    return True


# BOLT #4 failure codes for the htlc_accepted hook (hex, no data)
FAIL_TEMPORARY_NODE = "2002"   # temporary_node_failure
FAIL_MPP_TIMEOUT = "0017"      # mpp_timeout: give up on this payment set


def hook_continue(rpc_id):
    """Let CLN handle the HTLC itself.  Never for a factory invoice: CLN has
    its preimage and would settle it without the factory client being paid."""
    send_to_cln({"jsonrpc": "2.0", "id": rpc_id,
                 "result": {"result": "continue"}})


def hook_fail(rpc_id, failure_message=FAIL_TEMPORARY_NODE):
    """Fail the HTLC back to its sender.
    CLN v25+ requires failure_message for hook fail."""
    send_to_cln({"jsonrpc": "2.0", "id": rpc_id,
                 "result": {"result": "fail",
                            "failure_message": failure_message}})


def recover_registered_invoices():
    """Rebuild registered_invoices from CLN's invoice list (the set is lost
    when the plugin restarts; the invoices are not).  Returns True once the
    list has been read."""
    global registry_recovered
    try:
        invs = cln_rpc("listinvoices", timeout=10).get("invoices", [])
    except Exception as e:
        log(f"Invoice recovery failed: {type(e).__name__}: {e}")
        return False
    recovered = 0
    with lock:
        for inv in invs:
            if inv.get("status") == "unpaid" and \
               inv.get("label", "").startswith("superscalar-"):
                ph = inv.get("payment_hash", "")
                if ph and ph not in registered_invoices:
                    registered_invoices.add(ph)
                    recovered += 1
        registry_recovered = True
    if recovered:
        log(f"Recovered {recovered} unpaid factory invoices from CLN DB")
    return True


def connect_bridge():
    """Connect to the SuperScalar bridge daemon and authenticate it.

    The secret is read afresh on every attempt (the bridge may have been
    started, and the file created, after this plugin).  The connection only
    becomes the bridge link, from which messages are read and acted on,
    once the peer has proven that it holds the secret."""
    global bridge_sock
    secret = read_bridge_secret()
    if secret is None:
        return False
    sock = None
    try:
        sock = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT),
                                        timeout=AUTH_TIMEOUT)
        if not authenticate_bridge(sock, secret):
            sock.close()
            return False
        sock.settimeout(None)
        with lock:
            bridge_sock = sock
        log(f"Connected to bridge at {BRIDGE_HOST}:{BRIDGE_PORT}")
        return True
    except Exception as e:
        log(f"Failed to connect to bridge: {e}")
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
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
        # HTLCs handed to the bridge over the old connection stay held.  The
        # LSP may already have offered them to its client, so neither
        # answer is safe from here: "continue" would let CLN settle the
        # invoice whether or not the client is paid, and "fail" would refund
        # the sender of an HTLC the client may still claim.  The LSP's
        # verdict arrives as htlc_resolve, keyed by payment hash, over
        # whichever connection is up.
        with lock:
            held = len(pending_htlcs)
        if held:
            log(f"Bridge reconnected; {held} HTLC(s) still awaiting the LSP")
        else:
            log("Bridge reconnected")


def handle_bridge_msg(msg):
    """Handle a message from the bridge."""
    method = msg.get("method", "")

    if method == "htlc_resolve":
        payment_hash = msg.get("payment_hash", "")
        result = msg.get("result")
        log(f"htlc_resolve: hash={payment_hash[:16]}... result={result}")
        with lock:
            held = pending_htlcs.pop(payment_hash, None)
            # The invoice stays registered until it is paid: after a failed
            # attempt the next HTLC for it must come back here, not fall
            # through to CLN.
            if held is not None and result == "fulfill":
                registered_invoices.discard(payment_hash)

        if held is None:
            log(f"No pending HTLC for hash {payment_hash[:16]}...")
            return
        rpc_id = held["rpc_id"]

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
            # The LSP does not know this hash.  If it is not one of our
            # invoices either (a forward, or keysend) the HTLC is CLN's
            # business.  If CLN holds the invoice, "continue" would have CLN
            # settle it with nobody paying the factory client: fail it.
            if reason == "unknown_payment_hash" and not held["factory_invoice"]:
                hook_continue(rpc_id)
            else:
                hook_fail(rpc_id)

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
        payment_hash = msg.get("payment_hash")
        max_total_msat = msg.get("max_total_msat")
        max_delay = msg.get("max_delay")
        log(f"Pay request: {bolt11[:30]}... (id={request_id})")
        # Run lightning-cli pay in a background thread to avoid blocking
        t = threading.Thread(
            target=_do_pay,
            args=(bolt11, request_id, payment_hash, max_total_msat, max_delay),
            daemon=True
        )
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
    """Create a CLN invoice with a known preimage and send BOLT11 back to bridge.
    If ROUTE_HINT is set, includes it so external nodes can route via the LSP."""
    label = f"superscalar-{payment_hash[:16]}-{int(time.time())}"
    try:
        cmd = cli_cmd(
            "-k", "invoice",
            f"amount_msat={amount_msat}",
            f"label={label}",
            "description=SuperScalar factory payment",
            "expiry=3600",
            f"preimage={preimage_hex}",
            f"cltv={FACTORY_INVOICE_CLTV}"
        )
        if ROUTE_HINT:
            cmd.append(f"exposeprivatechannels={ROUTE_HINT}")
        log(f"invoice cmd: {' '.join(cmd)}")
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
            log(f"CLN invoice creation failed (rc={result.returncode}): "
                f"stderr={result.stderr[:200]} stdout={result.stdout[:200]}")
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


def check_pay_request(decoded, payment_hash, max_total_msat, max_delay):
    """Check a decoded invoice against what the bridge authorised.

    The bridge names the payment hash the invoice must carry, the most this
    node may spend on it (routing fees included) and the longest the payment
    may stay locked up, in blocks.  All are checked here against CLN's own
    decoding of the invoice, so a request that does not match its invoice is
    never paid.

    Returns (invoice_amount_msat, None) if the invoice may be paid, or
    (None, reason) if it must be refused."""
    if not _is_hash(payment_hash):
        return None, "request carries no payment hash"
    if (isinstance(max_total_msat, bool) or not isinstance(max_total_msat, int)
            or max_total_msat <= 0):
        return None, "request carries no spend cap"
    if (isinstance(max_delay, bool) or not isinstance(max_delay, int)
            or max_delay <= 0):
        return None, "request carries no delay bound"
    if not isinstance(decoded, dict) or decoded.get("valid") is not True \
            or decoded.get("type") != "bolt11 invoice":
        return None, "not a valid bolt11 invoice"
    if str(decoded.get("payment_hash", "")).lower() != payment_hash.lower():
        return None, "invoice payment hash differs from the requested one"
    amount_msat = _msat(decoded.get("amount_msat"))
    if amount_msat is None or amount_msat <= 0:
        return None, "invoice states no amount"
    if amount_msat > max_total_msat:
        return None, (f"invoice amount {amount_msat} msat exceeds the cap of "
                      f"{max_total_msat} msat")
    final_cltv = decoded.get("min_final_cltv_expiry")
    if isinstance(final_cltv, int) and not isinstance(final_cltv, bool) \
            and final_cltv > max_delay:
        return None, (f"invoice needs {final_cltv} final-hop blocks, more than "
                      f"the {max_delay} allowed")
    return amount_msat, None


def _preimage_matches(preimage, payment_hash):
    """True if preimage (hex) hashes to payment_hash (hex)."""
    if not _is_hash(preimage) or not _is_hash(payment_hash):
        return False
    return hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == payment_hash.lower()


def _send_pay_result(request_id, success, preimage=None):
    send_to_bridge({
        "method": "pay_result",
        "request_id": request_id,
        "success": bool(success),
        "preimage": preimage if success else "00" * 32
    })


def _pay_state(payment_hash):
    """Ask CLN what has become of the payment for payment_hash.

    Returns (state, preimage):
      "complete"  it was paid; preimage is the proof
      "pending"   at least one attempt is still in flight
      "failed"    attempts were made and every one of them has failed
      "none"      CLN knows of no attempt for this hash
      "unknown"   CLN could not be asked, or gave an answer we cannot read"""
    try:
        pays = cln_rpc("listpays", {"payment_hash": payment_hash},
                       timeout=30).get("pays", [])
    except Exception as e:
        log(f"listpays failed: {type(e).__name__}: {e}")
        return "unknown", None
    if not isinstance(pays, list):
        return "unknown", None
    statuses = set()
    for p in pays:
        status = p.get("status") if isinstance(p, dict) else None
        if status == "complete":
            preimage = p.get("preimage", p.get("payment_preimage", ""))
            if _preimage_matches(preimage, payment_hash):
                return "complete", preimage
        statuses.add(status)
    if not statuses:
        return "none", None
    if statuses == {"failed"}:
        return "failed", None
    if "pending" in statuses:
        return "pending", None
    return "unknown", None


def _do_pay(bolt11, request_id, payment_hash, max_total_msat, max_delay):
    """Pay an outside invoice on the bridge's request and report the result.

    The invoice is paid only if CLN decodes it to the requested payment hash
    and to an amount within max_total_msat; the rest of the cap is the most
    CLN may add in routing fees (pay's maxfee), and max_delay bounds how long
    the route may lock the payment up (pay's maxdelay).

    The LSP refunds its client when told the payment failed, so failure is
    reported only once CLN can no longer complete it.  A `pay` that times
    out, errors or returns "pending" may leave attempts in flight; the
    payment is then followed with listpays until it has completed or every
    attempt has failed, and the bridge hears nothing in the meantime."""
    log(f"Pay start: request_id={request_id}, bolt11_len={len(bolt11)}, "
        f"bolt11_prefix={bolt11[:20]}...")
    try:
        decoded = cln_rpc("decode", {"string": bolt11}, timeout=30)
    except Exception as e:
        log(f"Pay refused: cannot decode invoice: {type(e).__name__}: {e}")
        _send_pay_result(request_id, False)
        return
    amount_msat, why = check_pay_request(decoded, payment_hash, max_total_msat,
                                         max_delay)
    if why:
        log(f"Pay refused for request_id={request_id}: {why}")
        _send_pay_result(request_id, False)
        return

    # From here on CLN may have HTLCs out for this hash.
    started = time.monotonic()
    pay_ended = False   # True once CLN itself said the pay command is over
    try:
        pay_result = cln_rpc(
            "pay",
            {"bolt11": bolt11,
             "maxfee": max_total_msat - amount_msat,
             "maxdelay": max_delay,
             "retry_for": PAY_RETRY_FOR},
            timeout=PAY_CLI_TIMEOUT
        )
        status = pay_result.get("status", "?")
        preimage = pay_result.get("payment_preimage", "")
        log(f"Pay returned: status={status}, preimage_prefix={preimage[:16]}")
        if status == "complete" and _preimage_matches(preimage, payment_hash):
            _send_pay_result(request_id, True, preimage)
            log(f"Pay succeeded: {preimage[:16]}...")
            return
        pay_ended = status == "failed"
    except ClnRpcError as e:
        # A JSON-RPC error is CLN's own verdict that the command is over
        # (it will start no further attempts).  Anything else, such as
        # lightning-cli losing its connection, says nothing about the pay.
        pay_ended = e.code is not None
        log(f"Pay error for request_id={request_id}: code={e.code} {e}")
    except subprocess.TimeoutExpired:
        log(f"Pay still running after {PAY_CLI_TIMEOUT}s for "
            f"request_id={request_id}")
    except Exception as e:
        log(f"Pay exception for request_id={request_id}: "
            f"{type(e).__name__}: {e}")

    # Not complete.  Follow the payment until CLN has settled it either way.
    polls = 0
    while True:
        state, preimage = _pay_state(payment_hash)
        if state == "complete":
            _send_pay_result(request_id, True, preimage)
            log(f"Pay succeeded after follow-up: {preimage[:16]}...")
            return
        # "failed"/"none" only count once no new attempt can start: either
        # CLN ended the command, or its retry window is long past.
        no_new_attempts = pay_ended or \
            time.monotonic() - started >= PAY_RETRY_FOR + PAY_SETTLE_GRACE
        if state in ("failed", "none") and no_new_attempts:
            log(f"Pay failed for request_id={request_id} (listpays: {state})")
            _send_pay_result(request_id, False)
            return
        if polls % 30 == 0:
            log(f"Pay unresolved for request_id={request_id} "
                f"(listpays: {state}); holding")
        polls += 1
        time.sleep(PAY_POLL_INTERVAL)


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


def upstream_id(htlc):
    """CLN's own name for an incoming HTLC: "<short_channel_id>:<id>".

    CLN calls the hook again for every HTLC still unresolved when it
    restarts.  The name is the same then, which is how the LSP tells the
    same HTLC offered again from a second HTLC for the same payment hash.
    Returns "" if CLN does not report both parts."""
    scid = htlc.get("short_channel_id")
    hid = htlc.get("id")
    if scid is None or hid is None or isinstance(hid, bool):
        return ""
    return f"{scid}:{hid}"


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
    upstream = upstream_id(htlc)

    # The invoice list could not be read yet, so the registry below may be
    # missing factory invoices.  Try again now.
    if not registry_recovered:
        recover_registered_invoices()

    # Check if this HTLC is for a registered factory invoice
    with lock:
        is_ours = payment_hash in registered_invoices
        n_registered = len(registered_invoices)
        registry_known = registry_recovered

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

    # Check if this is a forwarding HTLC (has short_channel_id in onion).
    # If CLN-A is forwarding to an unknown next-hop, it's likely destined
    # for the SuperScalar LSP via the bridge.  Forward it.
    onion = params.get("onion", {})
    is_forward = "short_channel_id" in onion

    log(f"htlc_accepted: hash={payment_hash[:16]}... amt={amount_msat} "
        f"cltv={cltv_expiry} ours={is_ours} keysend={keysend_preimage is not None} "
        f"forward={is_forward} (registry={n_registered})")

    if not is_ours and not keysend_preimage and not is_forward:
        if not registry_known:
            # A payment to this node for a hash we cannot classify: CLN's
            # invoice list is unreadable, so this may be a factory invoice
            # that CLN would settle itself.  Fail it; the sender can retry.
            log(f"Cannot tell whether {payment_hash[:16]}... is a factory "
                f"invoice — failing")
            hook_fail(rpc_id)
            return
        # Not a factory payment, not keysend, not a forward — an invoice of
        # this node's own.  Let CLN handle it; no factory client is involved.
        hook_continue(rpc_id)
        return

    # amount_msat is what this HTLC actually delivers to the node.  That is
    # the amount the LSP is told, also for a forward: the onion's forward
    # amount is whatever the sender wrote and was never received.

    # Register pending HTLC keyed by payment_hash (no counter desync risk)
    with lock:
        held = pending_htlcs.get(payment_hash)
        # The same HTLC offered again takes over the entry (the answer has
        # to go to the latest hook call) and is offered to the LSP again,
        # which attaches it to what it already has.
        again = held is not None and upstream != "" and \
            held.get("upstream") == upstream
        duplicate = held is not None and not again
        if not duplicate:
            pending_htlcs[payment_hash] = {"rpc_id": rpc_id,
                                           "factory_invoice": is_ours,
                                           "upstream": upstream}
    if duplicate:
        # A second HTLC for a hash that is already with the LSP: a further
        # part of a split payment, or a repeat.  The LSP takes an invoice
        # in one HTLC.  For a factory invoice CLN must not get to settle
        # this one from its own copy of the preimage, so fail it; anything
        # else is CLN's to handle.
        if is_ours:
            log(f"Duplicate HTLC for factory invoice {payment_hash[:16]}..., failing")
            hook_fail(rpc_id, FAIL_MPP_TIMEOUT)
        else:
            log(f"Duplicate HTLC for {payment_hash[:16]}..., passing to CLN")
            hook_continue(rpc_id)
        return

    # Build bridge message
    bridge_msg = {
        "method": "htlc_accepted",
        "payment_hash": payment_hash,
        "amount_msat": amount_msat,
        "cltv_expiry": cltv_expiry,
        "upstream_id": upstream
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
        with lock:
            pending_htlcs.pop(payment_hash, None)
        if is_ours:
            # The LSP cannot be reached, so the factory client cannot be
            # paid; CLN must not settle the invoice in its place.  A
            # temporary failure lets the sender retry later.
            hook_fail(rpc_id)
        else:
            # Not an invoice of ours — let CLN handle it
            hook_continue(rpc_id)


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
    global BRIDGE_HOST, BRIDGE_PORT, BRIDGE_SECRET_FILE, LIGHTNING_CLI, LIGHTNING_DIR, KEYSEND_DEFAULT_CLIENT, ROUTE_HINT

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
                            "name": "superscalar-bridge-secret-file",
                            "type": "string",
                            "default": "~/.superscalar/bridge-plugin.secret",
                            "description": "File with the secret the SuperScalar bridge expects"
                        },
                        {
                            "name": "superscalar-lightning-cli",
                            "type": "string",
                            "default": "lightning-cli",
                            "description": "Path to lightning-cli binary"
                        },
                        {
                            "name": "superscalar-keysend-client",
                            "type": "int",
                            "default": 0,
                            "description": "Default factory client index for keysend payments"
                        },
                        {
                            "name": "superscalar-route-hint",
                            "type": "string",
                            "default": "",
                            "description": "Route hint SCID for factory channel invoices (exposeprivatechannels)"
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
            BRIDGE_SECRET_FILE = config.get("superscalar-bridge-secret-file",
                                            BRIDGE_SECRET_FILE)
            LIGHTNING_CLI = config.get("superscalar-lightning-cli", LIGHTNING_CLI)
            KEYSEND_DEFAULT_CLIENT = int(config.get("superscalar-keysend-client",
                                                      KEYSEND_DEFAULT_CLIENT))
            rh = config.get("superscalar-route-hint", "")
            ROUTE_HINT = rh if rh else None

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

            global _can_log_to_cln
            _can_log_to_cln = True

            # Re-populate registered_invoices from CLN's invoice DB.
            # On plugin restart (CLN restart), the in-memory set is empty
            # but CLN still has the invoices with "superscalar-" labels.
            # If this fails it is retried when the next HTLC arrives.
            recover_registered_invoices()

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
