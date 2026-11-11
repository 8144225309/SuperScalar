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
message from a peer that has not given it.  Every line after that carries a
MAC under a session key derived from the secret and both nonces, with a
per-direction counter, so nothing between the two can add, change, replay
or drop a message unnoticed.

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
import struct
import subprocess
import sys
import tempfile
import threading
import time

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 9736
# File holding the secret the bridge expects (written by superscalar_bridge)
BRIDGE_SECRET_FILE = "~/.superscalar/bridge-plugin.secret"
# Where this plugin keeps what must survive its own restart: the outside
# payments it was asked to make and has not yet seen acknowledged.
BRIDGE_STATE_FILE = "~/.superscalar/bridge-plugin.state.json"
LIGHTNING_CLI = "lightning-cli"
LIGHTNING_DIR = None   # set from CLN init, passed to lightning-cli
KEYSEND_DEFAULT_CLIENT = 0  # default dest_client for keysend (overridable via plugin option)
ROUTE_HINT = None  # "node_id/scid/fee_base/fee_ppm/cltv_delta" for factory channels
bridge_sock = None
# Session of the current bridge connection, set with bridge_sock:
# {"key": bytes, "tx": lines sent, "rx": lines received}
bridge_session = None
# Keyed by payment_hash (hex string) — immune to htlc_id counter desync
# payment_hash -> {"rpc_id": hook request to answer,
#                  "factory_invoice": True if CLN holds this hash's invoice,
#                  "upstream": CLN's own name for the HTLC ("" if unknown)}
pending_htlcs = {}
pending_pays = {}    # request_id -> rpc_id for superscalar-pay responses
registered_invoices = set()   # payment_hash hex strings for factory clients
# Factory invoices the LSP has fulfilled through this plugin, oldest first:
# payment_hash -> {"preimage": hex, "upstream": CLN's name of the HTLC that
# paid it}.  CLN still holds such an invoice as unpaid, with its preimage: a
# later HTLC for the hash must never be left to CLN.  If CLN offers the very
# HTLC that paid it again (it lost our answer in a restart), it gets the
# same answer.  Kept in BRIDGE_STATE_FILE; the CLN invoice itself is deleted
# as well when possible.
settled_invoices = {}
# HTLCs handed to the LSP and not yet resolved, by CLN's name for them:
# upstream -> {"payment_hash": hex, "factory_invoice": bool}.  Kept in
# BRIDGE_STATE_FILE.  When CLN restarts it offers each of them again; the
# client may hold it by then, so it is held here until the LSP says how it
# ended, whatever the state of the bridge link or of the invoice.
forwarded_htlcs = {}
SETTLED_MAX = 20000
invoice_labels = {}  # payment_hash -> CLN label of the factory invoice
NODE_ID = None       # this CLN node's id (from getinfo), once known
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

# How long CLN keeps a factory invoice payable.  An HTLC that pays it can be
# held for as long as its timelock allows, so the invoice has to outlive
# the hour a payer gets to start paying by that hold time (taken as twice
# the final CLTV delta at ten minutes a block).
FACTORY_INVOICE_PAY_WINDOW = 3600
FACTORY_INVOICE_EXPIRY = FACTORY_INVOICE_PAY_WINDOW + 2 * FACTORY_INVOICE_CLTV * 600

# Outbound pays.  CLN's `pay` stops starting new attempts after
# PAY_RETRY_FOR seconds; parts already in flight can still settle later.
PAY_RETRY_FOR = 60
PAY_CLI_TIMEOUT = 600      # how long to wait for `pay` itself to return
PAY_POLL_INTERVAL = 10     # seconds between listpays polls while unresolved
PAY_SETTLE_GRACE = 30      # slack added to PAY_RETRY_FOR before trusting "failed"
RESULT_RETRY_INTERVAL = 15 # seconds between repeats of an unacknowledged result

# Outside payments requested by the bridge, until the LSP acknowledges their
# result: request_id -> {"payment_hash": hex, "started": unix time,
#                        "result": None | {"success": bool, "preimage": hex}}
# Kept in BRIDGE_STATE_FILE so that a restart neither forgets a payment that
# is still in flight nor loses a result that was not delivered.
open_pays = {}
pays_lock = threading.RLock()

# The state file belongs to one CLN node working for one LSP.  Request ids,
# HTLC names and payment hashes mean nothing to another pair, so a file
# from elsewhere is refused rather than acted on.
state_lock = threading.RLock()   # one save at a time
STATE_NODE_ID = None    # the CLN node the state belongs to
STATE_LSP_KEY = None    # the LSP's key as the bridge reports it ("" if the
                        # bridge runs without one); None until first seen


class StateFileError(Exception):
    """The state file exists but cannot be used."""


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


def session_key(secret, plugin_nonce, bridge_nonce):
    """The key both ends derive for the lines after the handshake."""
    return hmac.new(bytes.fromhex(secret),
                    b"superscalar-bridge-plugin-session-v1/" +
                    plugin_nonce + bridge_nonce, hashlib.sha256).digest()


def line_mac(key, direction, seq, line):
    """MAC of one line (bytes): direction is b"p2b" or b"b2p", seq the number
    of lines sent before it in that direction."""
    return hmac.new(key, direction + struct.pack(">Q", seq) + line,
                    hashlib.sha256).hexdigest()


def seal_line(session, msg):
    """One message as it goes to the bridge: "<mac> <json>\\n"."""
    line = json.dumps(msg).encode()
    mac = line_mac(session["key"], b"p2b", session["tx"], line)
    session["tx"] += 1
    return mac.encode() + b" " + line + b"\n"


def open_line(session, raw):
    """Check one line from the bridge (bytes, without the newline) and
    return its message.  Raises ValueError if it does not carry the MAC for
    the next counter value: it was altered, injected, replayed, or
    something before it is missing."""
    mac, sep, line = raw.partition(b" ")
    expected = line_mac(session["key"], b"b2p", session["rx"], line)
    if not sep or not hmac.compare_digest(expected.encode(), mac.lower()):
        raise ValueError("bridge line failed authentication")
    session["rx"] += 1
    return json.loads(line)


def send_to_bridge(msg):
    """Send one authenticated message to the bridge (thread-safe)."""
    with lock:
        sock = bridge_sock
        session = bridge_session
    if sock is None or session is None:
        return False
    try:
        with send_lock:
            sock.sendall(seal_line(session, msg))
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


def _recv_line(sock, deadline, limit=1024):
    """Read one newline-terminated line, a byte at a time so nothing past
    it is consumed.  `deadline` (time.monotonic()) bounds the whole line,
    however slowly the bytes come.  Returns None if the peer closes, sends
    too much or runs out of time."""
    line = b""
    while len(line) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            c = sock.recv(1)
        except socket.timeout:
            return None
        if not c:
            return None
        if c == b"\n":
            return line
        line += c
    return None


def authenticate_bridge(sock, secret):
    """Run the handshake on a fresh connection.

    Returns the session for the connection if the peer proved that it
    holds the secret, else None.  Our own proof is sent only after the
    peer's checked out, the secret itself is never sent, and the whole
    exchange has AUTH_TIMEOUT seconds."""
    deadline = time.monotonic() + AUTH_TIMEOUT
    plugin_nonce = os.urandom(32)
    sock.sendall((json.dumps({"method": "auth_hello",
                              "nonce": plugin_nonce.hex()}) + "\n").encode())
    try:
        challenge = json.loads(_recv_line(sock, deadline) or b"null")
    except ValueError:
        challenge = None
    if not isinstance(challenge, dict) \
            or challenge.get("method") != "auth_challenge" \
            or not _is_hash(challenge.get("nonce")) \
            or not _is_hash(challenge.get("proof")):
        log("Bridge did not answer the handshake")
        return None
    bridge_nonce = bytes.fromhex(challenge["nonce"])
    expected = auth_proof(secret, b"bridge", plugin_nonce, bridge_nonce)
    if not hmac.compare_digest(expected, challenge["proof"].lower()):
        log("Peer on the bridge port does not hold the bridge secret")
        return None

    sock.sendall((json.dumps({
        "method": "auth_response",
        "proof": auth_proof(secret, b"plugin", plugin_nonce, bridge_nonce)
    }) + "\n").encode())

    # The answer is the first line of the session: it has to carry the MAC
    # only the holder of the secret can make for these nonces.  A peer that
    # merely passed the handshake along cannot.
    session = {"key": session_key(secret, plugin_nonce, bridge_nonce),
               "tx": 0, "rx": 0}
    try:
        accepted = open_line(session, _recv_line(sock, deadline) or b"")
    except ValueError:
        accepted = None
    if not isinstance(accepted, dict) or accepted.get("method") != "auth_ok":
        log("Bridge did not accept our proof")
        return None
    if not check_lsp_identity(accepted.get("lsp_pubkey", "")):
        return None
    return session


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


def _mark_settled(payment_hash, preimage, upstream):
    """The LSP fulfilled this factory invoice: remember it for good, with
    the answer given and which HTLC it was given for."""
    with lock:
        settled_invoices[payment_hash] = {"preimage": preimage,
                                          "upstream": upstream}
        while len(settled_invoices) > SETTLED_MAX:
            del settled_invoices[next(iter(settled_invoices))]
    save_state()


def _note_forwarded(upstream, payment_hash, factory_invoice):
    """An HTLC CLN names is about to go to the LSP: remember that across a
    restart."""
    if not upstream:
        return
    with lock:
        forwarded_htlcs[upstream] = {"payment_hash": payment_hash,
                                     "factory_invoice": bool(factory_invoice)}
    save_state()


def _forget_forwarded(upstream):
    """The HTLC was answered: nothing to hold for any more."""
    if not upstream:
        return
    with lock:
        known = forwarded_htlcs.pop(upstream, None) is not None
    if known:
        save_state()


def _drop_cln_invoice(payment_hash):
    """Delete CLN's copy of a fulfilled factory invoice, so that CLN cannot
    settle a later HTLC for it from its own preimage even when this plugin
    is not running."""
    with lock:
        label = invoice_labels.pop(payment_hash, None)
    if not label:
        return
    try:
        cln_rpc("delinvoice", {"label": label, "status": "unpaid"}, timeout=30)
    except Exception as e:
        log(f"Could not delete fulfilled invoice {label}: "
            f"{type(e).__name__}: {e}")


def own_node_id():
    """This node's id, or None while CLN cannot be asked."""
    global NODE_ID
    if NODE_ID is None:
        try:
            node = cln_rpc("getinfo", timeout=10).get("id")
            if isinstance(node, str) and node:
                NODE_ID = node.lower()
        except Exception as e:
            log(f"getinfo failed: {type(e).__name__}: {e}")
    return NODE_ID


def own_invoice_reason(decoded, payment_hash):
    """Why an invoice must not be paid as an outside payment because it is
    one of ours, or None.  Paying an invoice of this very node would send
    the money out and straight back in, with CLN settling it from its own
    copy of the preimage."""
    with lock:
        ours = payment_hash in registered_invoices or \
            payment_hash in settled_invoices
    if ours:
        return "invoice was issued by this node for a factory client"
    node = own_node_id()
    if node and str(decoded.get("payee", "")).lower() == node:
        return "invoice is payable to this node itself"
    return None


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
                if ph:
                    invoice_labels[ph] = inv.get("label", "")
                # Already fulfilled by the LSP: it stays closed.
                if ph and ph not in settled_invoices and \
                        ph not in registered_invoices:
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
    global bridge_sock, bridge_session
    secret = read_bridge_secret()
    if secret is None:
        return False
    sock = None
    try:
        sock = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT),
                                        timeout=AUTH_TIMEOUT)
        session = authenticate_bridge(sock, secret)
        if session is None:
            sock.close()
            return False
        sock.settimeout(None)
        with lock:
            bridge_sock = sock
            bridge_session = session
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
    global bridge_sock, bridge_session
    while True:
        buf = b""
        sock = None
        while True:
            try:
                with lock:
                    sock = bridge_sock
                    session = bridge_session
                if sock is None or session is None:
                    break
                data = sock.recv(4096)
                if not data:
                    log("Bridge connection closed")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    # A line that is not authentic ends the connection
                    handle_bridge_msg(open_line(session, line))
            except Exception as e:
                log(f"bridge_reader error: {e}")
                break

        # Connection lost — attempt reconnect
        with lock:
            bridge_sock = None
            bridge_session = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
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
        # Results the LSP has not acknowledged go out again, and so do the
        # HTLCs we hold: whatever was said over the old connection may not
        # have arrived.
        resend_pay_results()
        reannounce_held_htlcs()


def handle_bridge_msg(msg):
    """Handle a message from the bridge."""
    method = msg.get("method", "")

    if method == "htlc_resolve":
        payment_hash = msg.get("payment_hash", "")
        result = msg.get("result")
        log(f"htlc_resolve: hash={payment_hash[:16]}... result={result}")
        # A fulfil is only a fulfil with the preimage of this hash.  CLN
        # would reject anything else and fail the HTLC, which the client
        # may already have been paid for: keep holding instead.
        if result == "fulfill" and \
                not _preimage_matches(msg.get("preimage", ""), payment_hash):
            log(f"ERROR: fulfil for {payment_hash[:16]}... carries a preimage "
                f"that does not hash to it; HTLC stays held")
            return
        with lock:
            held = pending_htlcs.pop(payment_hash, None)
            # The invoice stays registered until it is paid: after a failed
            # attempt the next HTLC for it must come back here, not fall
            # through to CLN.
            if held is not None and result == "fulfill":
                registered_invoices.discard(payment_hash)
                settle = held["factory_invoice"]
            else:
                settle = False

        if held is None:
            log(f"No pending HTLC for hash {payment_hash[:16]}...")
            # A fulfil repeated for an HTLC we already resolved: say so, or
            # the LSP keeps repeating it.
            with lock:
                done = payment_hash in settled_invoices
            if result == "fulfill" and done:
                send_to_bridge({"method": "htlc_resolved",
                                "payment_hash": payment_hash})
            return
        rpc_id = held["rpc_id"]

        if result == "fulfill":
            preimage = msg.get("preimage", "")
            # Closed for good before CLN is answered: no later HTLC for this
            # hash is ever passed on to CLN, which still has the invoice.
            if settle:
                _mark_settled(payment_hash, preimage, held.get("upstream", ""))
            send_to_cln({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "result": "resolve",
                    "payment_key": preimage
                }
            })
            # Tell the LSP the node has the preimage; until then it keeps
            # the fulfil and repeats it.
            send_to_bridge({"method": "htlc_resolved",
                            "payment_hash": payment_hash})
            _forget_forwarded(held.get("upstream", ""))
            if settle:
                _spawn(_drop_cln_invoice, payment_hash)
        else:
            _forget_forwarded(held.get("upstream", ""))
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
        # No invoice for a hash this node is paying, or has paid, on the
        # outside: CLN would hold the preimage of its own outgoing payment.
        with pays_lock:
            paying = any(
                rec.get("payment_hash") == payment_hash and
                not (rec.get("result") and not rec["result"].get("success"))
                for rec in open_pays.values())
        if paying:
            log(f"No invoice for {payment_hash[:16]}...: an outside payment "
                f"for this hash is open")
            send_to_bridge({"method": "invoice_bolt11",
                            "payment_hash": payment_hash, "bolt11": ""})
            return
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

    elif method == "pay_result_ack":
        _pay_acknowledged(msg.get("request_id"), msg.get("status", "applied"),
                          str(msg.get("reason", "")))

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
            f"expiry={FACTORY_INVOICE_EXPIRY}",
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
                invoice_labels[payment_hash] = label
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


def save_state():
    """Write the plugin's state to BRIDGE_STATE_FILE.

    One save at a time; each writes a temporary file of its own (mode
    0600), syncs it, renames it over the state file and syncs the
    directory, so that the file on disk is always one complete state."""
    path = os.path.expanduser(BRIDGE_STATE_FILE)
    directory = os.path.dirname(path) or "."
    with state_lock:
        with pays_lock:
            pays = {str(k): dict(v) for k, v in open_pays.items()}
        with lock:
            settled = dict(settled_invoices)
            forwarded = dict(forwarded_htlcs)
        data = json.dumps({"version": 1, "node_id": STATE_NODE_ID,
                           "lsp_key": STATE_LSP_KEY, "pays": pays,
                           "settled": settled, "forwarded": forwarded})
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".bridge-plugin.state.",
                                       dir=directory)
            with os.fdopen(fd, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            tmp = None
            dfd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return True
        except OSError as e:
            log(f"ERROR: cannot save plugin state to {path}: {e}")
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return False


def load_state(node_id=None):
    """Read the plugin's state back from BRIDGE_STATE_FILE.

    A missing file is a fresh start.  A file that cannot be read, is not
    what save_state writes, or was written for another CLN node raises
    StateFileError: it may describe payments in flight and held HTLCs, and
    carrying on as if there were none could pay twice or drop an HTLC.
    Returns how many outside payments were restored."""
    global STATE_NODE_ID, STATE_LSP_KEY
    path = os.path.expanduser(BRIDGE_STATE_FILE)
    try:
        with open(path, "r") as f:
            text = f.read()
    except FileNotFoundError:
        STATE_NODE_ID = node_id
        return 0
    except OSError as e:
        raise StateFileError(f"cannot read {path}: {e}")
    try:
        state = json.loads(text)
    except ValueError as e:
        raise StateFileError(f"{path} is not valid JSON ({e})")
    if not isinstance(state, dict):
        raise StateFileError(f"{path} does not hold a state object")
    pays = state.get("pays", {})
    settled = state.get("settled", {})
    forwarded = state.get("forwarded", {})
    if not all(isinstance(part, dict) for part in (pays, settled, forwarded)):
        raise StateFileError(f"{path} has a malformed section")
    file_node = state.get("node_id")
    if node_id and file_node and file_node != node_id:
        raise StateFileError(
            f"{path} belongs to node {file_node}, this node is {node_id}")
    parsed = {}
    for key, rec in pays.items():
        try:
            request_id = int(key)
        except ValueError:
            raise StateFileError(f"{path} has a malformed payment id {key!r}")
        if not isinstance(rec, dict):
            raise StateFileError(f"{path} has a malformed payment {key}")
        parsed[request_id] = {
            "payment_hash": rec.get("payment_hash", ""),
            "started": rec.get("started"),
            "launched": bool(rec.get("launched")),
            "result": rec.get("result"),
        }
        if rec.get("rejected"):
            parsed[request_id]["rejected"] = rec["rejected"]

    with state_lock:
        STATE_NODE_ID = node_id or file_node
        STATE_LSP_KEY = state.get("lsp_key")
    with lock:
        for ph, rec in settled.items():
            if _is_hash(ph) and isinstance(rec, dict):
                settled_invoices[ph] = {"preimage": rec.get("preimage", ""),
                                        "upstream": rec.get("upstream", "")}
        for up, rec in forwarded.items():
            if up and isinstance(rec, dict) and _is_hash(rec.get("payment_hash")):
                forwarded_htlcs[up] = {
                    "payment_hash": rec["payment_hash"],
                    "factory_invoice": bool(rec.get("factory_invoice"))}
    with pays_lock:
        open_pays.update(parsed)
    return len(parsed)


def init_state(attempts=10):
    """Find out which node this is and load its state, before anything else
    runs.  Stops the plugin if either cannot be done: without its state it
    could pay an invoice twice or mishandle an HTLC it was holding."""
    node_id = None
    for attempt in range(attempts):
        node_id = own_node_id()
        if node_id:
            break
        time.sleep(1)
    try:
        if not node_id:
            raise StateFileError("cannot ask CLN for this node's id (getinfo)")
        return load_state(node_id)
    except StateFileError as e:
        message = (f"FATAL: {e}. The SuperScalar plugin is not starting. Its "
                   f"state file records outside payments in flight and HTLCs "
                   f"held for the LSP; move it away only after checking that "
                   f"none are open.")
        log(message)
        sys.stderr.write(f"superscalar: {message}\n")
        sys.stderr.flush()
        sys.exit(1)


def check_lsp_identity(lsp_key):
    """The bridge says which LSP it serves.  The first answer is recorded
    with the state; a different one later means the state belongs to
    another LSP, and the link is refused."""
    global STATE_LSP_KEY
    if not isinstance(lsp_key, str):
        lsp_key = ""
    with state_lock:
        if STATE_LSP_KEY is None:
            STATE_LSP_KEY = lsp_key
            first = True
        elif STATE_LSP_KEY == lsp_key:
            return True
        else:
            log(f"ERROR: the bridge serves LSP {lsp_key or '(no key)'} but "
                f"this plugin's state belongs to LSP "
                f"{STATE_LSP_KEY or '(no key)'}; refusing the link")
            return False
    if first:
        save_state()
    return True


def _open_pay(request_id, payment_hash):
    """Note that a payment was requested.  Returns False if this request id
    is already known (the request is a repeat and must not be paid again)."""
    with pays_lock:
        if request_id in open_pays:
            return False
        open_pays[request_id] = {"payment_hash": payment_hash,
                                 "started": None, "launched": False,
                                 "result": None}
    save_state()
    return True


def _mark_pay_launched(request_id):
    """`pay` is about to be called: from this moment CLN may make attempts,
    and its retry window is counted from here.  Returns the time recorded."""
    now = time.time()
    with pays_lock:
        rec = open_pays.get(request_id)
        if rec is not None:
            rec["started"] = now
            rec["launched"] = True
    save_state()
    return now


def _send_pay_result(request_id, success, preimage=None):
    """Record the final outcome of a payment and tell the bridge.

    The result stays recorded, and is repeated by resend_pay_results(),
    until the LSP acknowledges it: a result sent while the link is down, or
    just before a restart, is not lost."""
    result = {"success": bool(success),
              "preimage": preimage if success else "00" * 32}
    with pays_lock:
        rec = open_pays.setdefault(
            request_id, {"payment_hash": "", "started": time.time()})
        rec["result"] = result
    save_state()
    send_to_bridge({"method": "pay_result", "request_id": request_id, **result})


def resend_pay_results():
    """Send every recorded result that has not been answered yet."""
    with pays_lock:
        waiting = [(rid, dict(rec["result"]))
                   for rid, rec in open_pays.items()
                   if rec.get("result") and not rec.get("rejected")]
    for request_id, result in waiting:
        send_to_bridge({"method": "pay_result", "request_id": request_id,
                        **result})
    return len(waiting)


def _pay_acknowledged(request_id, status="applied", reason=""):
    """The LSP answered the result for this request.

    applied: nothing left to remember.  An ack for a payment that has no
    result yet is not believed: the payment may still be in flight, and its
    record is what lets a restart find out how it ended.

    rejected: the LSP could not use the result (for instance a preimage it
    does not accept).  Repeating it changes nothing, so it is not sent
    again; the record is kept, marked, for the operator."""
    with pays_lock:
        rec = open_pays.get(request_id)
        if rec is None:
            return
        if not rec.get("result"):
            log(f"WARNING: LSP acknowledged request_id={request_id}, which "
                f"has no result yet; keeping it")
            return
        if status == "rejected":
            already = rec.get("rejected")
            rec["rejected"] = reason or "rejected"
        else:
            del open_pays[request_id]
    if status == "rejected":
        if not already:
            log(f"ERROR: the LSP REJECTED the result of outside payment "
                f"request_id={request_id} (success="
                f"{rec['result'].get('success')}): {reason or 'no reason'}. "
                f"It will not be sent again. Operator action needed.")
    save_state()


def result_retrier():
    """Repeat unacknowledged results for as long as the plugin runs."""
    while True:
        time.sleep(RESULT_RETRY_INTERVAL)
        try:
            resend_pay_results()
        except Exception as e:
            log(f"resend_pay_results error: {e}")


def _spawn(target, *args):
    threading.Thread(target=target, args=args, daemon=True).start()


def recover_open_pays():
    """After a restart: pick the payments that were open back up.

    One that already has its result only needs delivering.  One without
    was in flight (or about to start) when the plugin stopped; CLN is asked
    what became of it, and it is followed until CLN has settled it."""
    # No start time means `pay` was not known to have been launched; the
    # window is then counted from now, which can only be later.
    with pays_lock:
        restored = len(open_pays)
        unresolved = [(rid, rec["payment_hash"], rec.get("started") or time.time())
                      for rid, rec in open_pays.items() if not rec.get("result")]
    for request_id, payment_hash, started in unresolved:
        if not _is_hash(payment_hash):
            # It was refused before anything was sent; only the answer is
            # missing.
            _send_pay_result(request_id, False)
            continue
        log(f"Resuming outside payment request_id={request_id}")
        _spawn(_follow_pay, request_id, payment_hash, started, False)
    return restored


def _hash_in_use(payment_hash, request_id):
    """Why a new payment for payment_hash must not be started, or None.

    CLN answers `pay` for an invoice it already paid with the old preimage
    and pays nothing; the LSP would charge its client for that a second
    time.  The same goes for a hash another request is still paying."""
    with pays_lock:
        for rid, rec in open_pays.items():
            if rid != request_id and rec.get("payment_hash") == payment_hash \
                    and not (rec.get("result") and
                             not rec["result"].get("success")):
                return f"request {rid} is already paying this hash"
    try:
        sent = cln_rpc("listsendpays", {"payment_hash": payment_hash},
                       timeout=30).get("payments", [])
    except Exception as e:
        return f"cannot check earlier payments: {type(e).__name__}: {e}"
    for p in sent if isinstance(sent, list) else []:
        status = p.get("status") if isinstance(p, dict) else None
        if status in ("complete", "pending"):
            return f"the node already has a {status} payment for this hash"
    return None


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
    if isinstance(request_id, bool) or not isinstance(request_id, int):
        log("Pay request without a usable request id ignored")
        return
    if not _open_pay(request_id, payment_hash if _is_hash(payment_hash) else ""):
        # A repeat of a request we already have: never pay twice.  If its
        # result is known it is on its way again.
        log(f"Pay request_id={request_id} is already known; not paying again")
        resend_pay_results()
        return
    try:
        decoded = cln_rpc("decode", {"string": bolt11}, timeout=30)
    except Exception as e:
        log(f"Pay refused: cannot decode invoice: {type(e).__name__}: {e}")
        _send_pay_result(request_id, False)
        return
    amount_msat, why = check_pay_request(decoded, payment_hash, max_total_msat,
                                         max_delay)
    if not why:
        why = own_invoice_reason(decoded, payment_hash)
    if not why:
        why = _hash_in_use(payment_hash, request_id)
    if why:
        log(f"Pay refused for request_id={request_id}: {why}")
        _send_pay_result(request_id, False)
        return

    # From here on CLN may have HTLCs out for this hash.
    started = _mark_pay_launched(request_id)
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

    _follow_pay(request_id, payment_hash, started, pay_ended)


def _follow_pay(request_id, payment_hash, started, pay_ended):
    """Follow a payment that is not known to be complete until CLN has
    settled it either way, then report.  `started` is when it was requested
    (unix time); `pay_ended` says CLN itself declared the pay command over."""
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
            time.time() - started >= PAY_RETRY_FOR + PAY_SETTLE_GRACE
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


def reannounce_held_htlcs():
    """Offer the HTLCs we hold to the LSP again (after a reconnect).

    The LSP recognises each by CLN's name for it: one it already has is
    re-attached, one it has fulfilled gets its fulfil again.  An HTLC CLN
    did not name is left out: the LSP could not tell it from a second HTLC
    and would refuse it."""
    with lock:
        held = [dict(e["msg"]) for e in pending_htlcs.values()
                if e.get("upstream") and e.get("msg")]
    for msg in held:
        send_to_bridge(msg)
    return len(held)


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

    with lock:
        stored = settled_invoices.get(payment_hash)
        replayed = forwarded_htlcs.get(upstream) if upstream else None

    # The HTLC that paid a fulfilled invoice, offered again: CLN lost our
    # answer in a restart.  The client has been paid; give the same answer.
    if upstream and isinstance(stored, dict) and \
            stored.get("upstream") == upstream and \
            _preimage_matches(stored.get("preimage", ""), payment_hash):
        log(f"HTLC {upstream} for fulfilled invoice {payment_hash[:16]}... "
            f"offered again — resolving as before")
        send_to_cln({"jsonrpc": "2.0", "id": rpc_id,
                     "result": {"result": "resolve",
                                "payment_key": stored["preimage"]}})
        send_to_bridge({"method": "htlc_resolved",
                        "payment_hash": payment_hash})
        return

    # An HTLC we handed to the LSP before a restart, offered again.  The
    # client may hold it, so only the LSP can say how it ends: hold it and
    # offer it to the LSP again (now, or once the bridge is back).  Whether
    # the invoice is still listed, still unpaid or even readable does not
    # matter here, and neither "fail" nor "continue" is safe.
    if replayed and replayed.get("payment_hash") == payment_hash:
        bridge_msg = {"method": "htlc_accepted", "payment_hash": payment_hash,
                      "amount_msat": amount_msat, "cltv_expiry": cltv_expiry,
                      "upstream_id": upstream}
        with lock:
            pending_htlcs[payment_hash] = {
                "rpc_id": rpc_id,
                "factory_invoice": replayed.get("factory_invoice", False),
                "upstream": upstream, "msg": dict(bridge_msg)}
        log(f"HTLC {upstream} for {payment_hash[:16]}... offered again after "
            f"a restart — held for the LSP")
        send_to_bridge(bridge_msg)
        return

    # The invoice list could not be read yet, so the registry below may be
    # missing factory invoices.  Try again now.
    if not registry_recovered:
        recover_registered_invoices()

    # Check if this HTLC is for a registered factory invoice
    with lock:
        is_ours = payment_hash in registered_invoices
        was_settled = payment_hash in settled_invoices
        n_registered = len(registered_invoices)
        registry_known = registry_recovered

    if was_settled:
        # A factory invoice that was already paid and fulfilled.  CLN may
        # still hold it as unpaid; "continue" would let CLN take a second
        # payment that no factory client receives.
        log(f"HTLC for already fulfilled invoice {payment_hash[:16]}... — failing")
        hook_fail(rpc_id)
        return

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
    with lock:
        if payment_hash in pending_htlcs:
            pending_htlcs[payment_hash]["msg"] = dict(bridge_msg)
    _note_forwarded(upstream, payment_hash, is_ours)

    log(f"Forwarding HTLC {payment_hash[:16]}... to bridge"
        f"{' (keysend)' if keysend_preimage else ''}")
    ok = send_to_bridge(bridge_msg)

    if not ok:
        log(f"Bridge send failed for HTLC {payment_hash[:16]}...")
        with lock:
            pending_htlcs.pop(payment_hash, None)
        _forget_forwarded(upstream)
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
    global BRIDGE_HOST, BRIDGE_PORT, BRIDGE_SECRET_FILE, BRIDGE_STATE_FILE, LIGHTNING_CLI, LIGHTNING_DIR, KEYSEND_DEFAULT_CLIENT, ROUTE_HINT

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
                            "name": "superscalar-bridge-state-file",
                            "type": "string",
                            "default": "~/.superscalar/bridge-plugin.state.json",
                            "description": "Where the plugin keeps outside payments that are not yet settled with the LSP"
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
            BRIDGE_STATE_FILE = config.get("superscalar-bridge-state-file",
                                           BRIDGE_STATE_FILE)
            LIGHTNING_CLI = config.get("superscalar-lightning-cli", LIGHTNING_CLI)
            KEYSEND_DEFAULT_CLIENT = int(config.get("superscalar-keysend-client",
                                                      KEYSEND_DEFAULT_CLIENT))
            rh = config.get("superscalar-route-hint", "")
            ROUTE_HINT = rh if rh else None

            # Capture lightning-dir from CLN's configuration so we can
            # pass it to lightning-cli subprocess calls
            cln_config = request.get("params", {}).get("configuration", {})
            LIGHTNING_DIR = cln_config.get("lightning-dir")

            # State first: which node this is, the outside payments that
            # were open and the HTLCs that were held.  Nothing talks to the
            # bridge and no thread runs before it is loaded.
            init_state()

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

            # Outside payments that were open when the plugin last stopped:
            # deliver their results, or find out what became of them.
            recover_open_pays()
            resend_pay_results()
            threading.Thread(target=result_retrier, daemon=True).start()

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
