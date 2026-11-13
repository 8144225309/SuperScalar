#!/usr/bin/env python3
"""On-chain invariant checker for SuperScalar regtest drills (stdlib only).

Run it after a drill, against the drill's node and the factory's databases
(the LSP's and the members').  It reads the chain, never changes it, and
checks four invariants:

  conservation  From every factory funding outpoint, the spend graph is
                followed down to its terminal outputs.  Every sat of the
                funding (plus any outside input a graph transaction adds) is
                a terminal output or a fee, every fee is within
                --max-feerate, and no output of a transaction the databases
                did not sign beforehand pays a script nobody is known to own
                (a participant key, a wallet given with --wallet, a P2A
                anchor, a script of a transaction stored in a database, or
                --allow-spk).
  balances      Each member's on-chain outcome is what its database says:
                its own latest commitment pays it exactly its balance
                (to_local) and the LSP its balance (to_remote, less the
                240 sat P2A anchor it funds); the LSP's commitment pays the
                member its balance; the distribution TX pays it at least its
                channel capacity and pays nobody but the members.  A
                commitment that confirmed must be the latest one the member
                holds, and the LSP's and member's databases must agree on
                the channel's balances at the same commitment number.
  revocation    No revoked commitment (one whose per-commitment secret the
                other side's database holds) is confirmed with its to_local
                output unspent or swept by the CSV path: the penalty (the
                revocation key) must have taken it.  The databases' own
                breach records (old_commitments) are checked the same way.
  exit          Every member that has not exited can still exit from its
                database alone: its latest commitment and every ancestor of
                it up to an unspent confirmed output are stored in the
                member's database, none of them conflicts with a confirmed
                transaction, and the first unconfirmed one is accepted by
                the node (testmempoolaccept), except for relay fee and
                timelock refusals that time or a CPFP child resolve.  Every
                key-path signature on the path is verified here (BIP341
                sighash, BIP340), since the node refuses on fee before it
                checks scripts, and the later transactions must spend the
                previous one's outputs.  If the commitment path is
                broken, a distribution TX whose input is still unspent
                counts as the exit.

Output: one JSON document on stdout (or --json FILE): every check's status,
its violations and the per-party ledger.  Exit 0 when nothing is violated,
1 on a violation, 2 on a usage or RPC error.

Usage:
  check_chain.py --conf REGTEST_CONF --db-dir DIR [--wallet NAME ...]
  check_chain.py --rpcport 18443 --rpcuser U --rpcpassword P \\
                 --lsp-db lsp.db --member-db c0.db --member-db c1.db
"""
import argparse
import base64
import decimal
import hashlib
import http.client
import json
import os
import re
import sqlite3
import sys

ANCHOR_SPK = "51024e73"
ANCHOR_VALUE = 240
DUST = 546
DEFAULT_CSV = 144

# ---------------------------------------------------------------- secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def pt_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def pt_mul(k, pt=G):
    r = None
    k %= N
    while k:
        if k & 1:
            r = pt_add(r, pt)
        pt = pt_add(pt, pt)
        k >>= 1
    return r


def ser33(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def lift_x(x):
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        raise ValueError("not on curve")
    return (x, y if y % 2 == 0 else P - y)


def parse33(b):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("bad compressed point")
    x, y = lift_x(int.from_bytes(b[1:], "big"))
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


def sha256(b):
    return hashlib.sha256(b).digest()


def tagged(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def xonly(pt):
    return pt[0].to_bytes(32, "big")


def taproot_spk(internal_pt, merkle=None):
    """P2TR scriptPubKey hex for an internal key (either parity) and a
    merkle root (None: key path only)."""
    p = lift_x(internal_pt[0])
    t = int.from_bytes(tagged("TapTweak", xonly(p) + (merkle or b"")), "big")
    return "5120" + xonly(pt_add(p, pt_mul(t))).hex()


def leaf_hash(script):
    return tagged("TapLeaf", b"\xc0" + bytes([len(script)]) + script)


def branch(a, b):
    return tagged("TapBranch", a + b if a <= b else b + a)


def scriptnum_push(v):
    if v == 0:
        return b"\x00"
    if v <= 16:
        return bytes([0x50 + v])
    out = []
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes([len(out)]) + bytes(out)


def csv_leaf(delay, xonly32):
    """<delay> OP_CSV OP_DROP <key> OP_CHECKSIG (tapscript_build_csv_delay)."""
    return scriptnum_push(delay) + b"\xb2\x75\x20" + xonly32 + b"\xac"


def _ser_bytes(b):
    n = len(b)
    pre = bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little")
    return pre + b


def taproot_keypath_valid(tx, idx, prevouts):
    """BIP341/340: is input idx of tx (parsed) a valid key-path spend of
    prevouts[idx]?  prevouts: [(value, spk hex)] for every input.  None
    when the input is not a key-path spend of a P2TR output."""
    wit = tx["vin"][idx][3]
    spk = prevouts[idx][1]
    if len(wit) != 1 or not spk.startswith("5120") or len(spk) != 68:
        return None
    sig = bytes.fromhex(wit[0])
    if len(sig) == 65:
        ht = sig[64]
        if ht == 0:
            return False
        sig = sig[:64]
    elif len(sig) == 64:
        ht = 0
    else:
        return False
    if ht not in (0, 1):
        return None  # other sighash types: not checked here
    ins = tx["vin"]
    msg = bytes([0, ht]) + tx["version"].to_bytes(4, "little") + tx["locktime"].to_bytes(4, "little")
    msg += sha256(b"".join(bytes.fromhex(t)[::-1] + v.to_bytes(4, "little") for t, v, _, _ in ins))
    msg += sha256(b"".join(p[0].to_bytes(8, "little") for p in prevouts))
    msg += sha256(b"".join(_ser_bytes(bytes.fromhex(p[1])) for p in prevouts))
    msg += sha256(b"".join(s.to_bytes(4, "little") for _, _, s, _ in ins))
    msg += sha256(b"".join(v.to_bytes(8, "little") + _ser_bytes(bytes.fromhex(s)) for v, s in tx["vout"]))
    msg += b"\x00" + idx.to_bytes(4, "little")
    m = tagged("TapSighash", msg)
    try:
        pk = lift_x(int(spk[4:], 16))
    except ValueError:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + bytes.fromhex(spk[4:]) + m), "big") % N
    R = pt_add(pt_mul(s), pt_mul(N - e, pk))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def derive_pub(basepoint, pcp):
    """basepoint + SHA256(pcp || basepoint) * G (channel_derive_pubkey)."""
    return pt_add(basepoint, pt_mul(int.from_bytes(sha256(ser33(pcp) + ser33(basepoint)), "big")))


def derive_revocation(rev_bp, pcp):
    """rev_bp * SHA256(rev_bp || pcp) + pcp * SHA256(pcp || rev_bp)."""
    rb, pc = ser33(rev_bp), ser33(pcp)
    return pt_add(pt_mul(int.from_bytes(sha256(rb + pc), "big"), rev_bp),
                  pt_mul(int.from_bytes(sha256(pc + rb), "big"), pcp))


def hexkey(v):
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("ascii", "replace") if len(v) != 32 else v.hex()
    if not isinstance(v, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return None
    k = int(v, 16)
    return k if 0 < k < N else None


def point_of(v):
    if isinstance(v, (bytes, bytearray)):
        v = v.decode("ascii", "replace") if len(v) != 33 else v.hex()
    try:
        return parse33(bytes.fromhex(v))
    except (ValueError, TypeError):
        return None


# ------------------------------------------------------------- transactions
def parse_tx(hexstr):
    """Serialized transaction -> txid, vin [(txid, vout, seq, witness)],
    vout [(value, spk hex)], vsize."""
    b = bytes.fromhex(hexstr)
    pos = [0]

    def take(n):
        if pos[0] + n > len(b):
            raise ValueError("truncated transaction")
        r = b[pos[0]:pos[0] + n]
        pos[0] += n
        return r

    def varint():
        x = take(1)[0]
        if x < 0xFD:
            return x
        return int.from_bytes(take({0xFD: 2, 0xFE: 4, 0xFF: 8}[x]), "little")

    version = take(4)
    segwit = len(b) > 6 and b[4] == 0 and b[5] == 1
    if segwit:
        take(2)
    start = pos[0]
    n_in = varint()
    if n_in == 0 or n_in > 10000:
        raise ValueError("no inputs")
    vin = []
    for _ in range(n_in):
        txid = take(32)[::-1].hex()
        vout = int.from_bytes(take(4), "little")
        take(varint())
        vin.append([txid, vout, int.from_bytes(take(4), "little"), []])
    n_out = varint()
    if n_out > 10000:
        raise ValueError("too many outputs")
    vout = []
    for _ in range(n_out):
        value = int.from_bytes(take(8), "little")
        vout.append((value, take(varint()).hex()))
    body_end = pos[0]
    if segwit:
        for i in vin:
            i[3] = [take(varint()).hex() for _ in range(varint())]
    locktime = take(4)
    if pos[0] != len(b):
        raise ValueError("trailing bytes")
    base = len(version) + (body_end - start) + 4
    weight = base * 3 + len(b)
    txid = sha256(sha256(version + b[start:body_end] + locktime))[::-1].hex()
    return {"txid": txid, "version": int.from_bytes(version, "little"),
            "locktime": int.from_bytes(locktime, "little"),
            "vin": [tuple(i) for i in vin], "vout": vout,
            "vsize": (weight + 3) // 4, "hex": hexstr}


# ---------------------------------------------------------------------- RPC
class RpcError(Exception):
    pass


class Rpc:
    def __init__(self, host, port, user, password, timeout=120):
        self.host, self.port, self.timeout = host, port, timeout
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        self.n = 0

    def _post(self, path, payload):
        c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            c.request("POST", path, json.dumps(payload),
                      {"Authorization": self.auth, "Content-Type": "application/json"})
            r = c.getresponse()
            data = r.read()
        except OSError as e:
            raise RpcError("cannot reach the node at %s:%d: %s" % (self.host, self.port, e))
        finally:
            c.close()
        if r.status == 401:
            raise RpcError("RPC authentication failed")
        try:
            return json.loads(data, parse_float=decimal.Decimal)
        except ValueError:
            raise RpcError("bad RPC reply (HTTP %d): %r" % (r.status, data[:200]))

    def call(self, method, *params, wallet=None):
        self.n += 1
        r = self._post("/wallet/" + wallet if wallet else "/",
                       {"jsonrpc": "1.0", "id": self.n, "method": method, "params": list(params)})
        if r.get("error"):
            raise RpcError("%s: %s" % (method, r["error"].get("message")))
        return r["result"]

    def batch(self, calls, wallet=None):
        """[(method, params)] -> [(result, error message or None)]."""
        out = []
        for i in range(0, len(calls), 200):
            chunk = calls[i:i + 200]
            req = [{"jsonrpc": "1.0", "id": j, "method": m, "params": list(p)}
                   for j, (m, p) in enumerate(chunk)]
            res = self._post("/wallet/" + wallet if wallet else "/", req)
            if not isinstance(res, list):
                raise RpcError("batch call refused: %s" % res)
            res = sorted(res, key=lambda x: x["id"])
            out += [(x.get("result"), (x.get("error") or {}).get("message")) for x in res]
        return out


def sats(v):
    return int((decimal.Decimal(v) * 100000000).to_integral_value())


def read_conf(path):
    conf, section = {}, ""
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("["):
                section = line.strip("[]")
                continue
            if "=" in line and section in ("", "regtest"):
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    return conf


# -------------------------------------------------------------------- chain
class Chain:
    """Every transaction from --from-height to the tip (and the mempool),
    with its prevouts, and an outpoint -> spender index.  No -txindex is
    needed."""

    def __init__(self, rpc, from_height):
        self.rpc = rpc
        self.tip = rpc.call("getblockcount")
        self.txs = {}
        self.spender = {}
        hs = list(range(max(from_height, 0), self.tip + 1))
        hashes = [r for r, _ in rpc.batch([("getblockhash", [h]) for h in hs])]
        for i in range(0, len(hashes), 25):
            for blk, err in rpc.batch([("getblock", [h, 3]) for h in hashes[i:i + 25]]):
                if err:
                    raise RpcError("getblock: %s" % err)
                for tx in blk["tx"]:
                    self._add(tx, blk["height"])
        mp = rpc.call("getrawmempool")
        if mp:
            res = rpc.batch([("getrawtransaction", [t, True]) for t in mp])
            pending = [tx for tx, err in res if not err and tx]
            for _ in range(len(pending) + 1):  # parents before children
                left = []
                for tx in pending:
                    if all(("coinbase" in v) or (v["txid"], v["vout"]) in self._outs
                           or v["txid"] not in mp for v in tx["vin"]):
                        self._add(tx, None)
                    else:
                        left.append(tx)
                if not left or len(left) == len(pending):
                    for tx in left:
                        self._add(tx, None)
                    break
                pending = left

    @property
    def _outs(self):
        return self.__dict__.setdefault("_outcache", {})

    def _add(self, tx, height):
        vin = []
        for v in tx["vin"]:
            if "coinbase" in v:
                continue
            pv = v.get("prevout")
            val = spk = None
            if pv:
                val, spk = sats(pv["value"]), pv["scriptPubKey"]["hex"]
            elif (v["txid"], v["vout"]) in self._outs:
                val, spk = self._outs[(v["txid"], v["vout"])]
            vin.append({"txid": v["txid"], "vout": v["vout"], "value": val, "spk": spk,
                        "witness": v.get("txinwitness", []), "sequence": v["sequence"]})
            self.spender[(v["txid"], v["vout"])] = (tx["txid"], height)
        vout = [(sats(o["value"]), o["scriptPubKey"]["hex"]) for o in tx["vout"]]
        for i, o in enumerate(vout):
            self._outs[(tx["txid"], i)] = o
        self.txs[tx["txid"]] = {"txid": tx["txid"], "height": height, "vin": vin,
                                "vout": vout, "vsize": tx["vsize"], "hex": tx.get("hex"),
                                "coinbase": any("coinbase" in v for v in tx["vin"])}

    def confirmed(self, txid):
        t = self.txs.get(txid)
        return t is not None and t["height"] is not None

    def output(self, txid, vout):
        return self._outs.get((txid, vout))

    def fee(self, tx):
        if tx["coinbase"] or any(v["value"] is None for v in tx["vin"]):
            return None
        return sum(v["value"] for v in tx["vin"]) - sum(o[0] for o in tx["vout"])


# ---------------------------------------------------------------- databases
def _txt(v):
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.decode("ascii")
        except UnicodeDecodeError:
            return v.hex()
    return v


class Db:
    def __init__(self, path, role, name):
        self.path, self.role, self.name = path, role, name
        self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        self.tables = {r[0] for r in self.rows("SELECT name FROM sqlite_master WHERE type='table'")}
        self._stored = None

    def rows(self, sql, args=()):
        try:
            return list(self.con.execute(sql, args))
        except sqlite3.Error:
            return []

    def cols(self, table):
        return [r[1] for r in self.rows("PRAGMA table_info(%s)" % table)]

    def dicts(self, table, where=""):
        if table not in self.tables:
            return []
        c = self.cols(table)
        return [dict(zip(c, r)) for r in self.rows("SELECT * FROM %s %s" % (table, where))]

    def stored_txs(self):
        """Every transaction this database holds, in any *_hex column:
        txid -> parsed tx with 'where' (table.column)."""
        if self._stored is None:
            self._stored = {}
            for t in sorted(self.tables):
                for c in self.cols(t):
                    if not c.endswith("hex"):
                        continue
                    for (v,) in self.rows("SELECT %s FROM %s WHERE %s IS NOT NULL" % (c, t, c)):
                        v = _txt(v)
                        if not isinstance(v, str) or len(v) < 120 or len(v) % 2:
                            continue
                        try:
                            tx = parse_tx(v)
                        except (ValueError, KeyError):
                            continue
                        tx["where"] = "%s.%s" % (t, c)
                        self._stored.setdefault(tx["txid"], tx)
        return self._stored


# ------------------------------------------------------------------ checker
class Checker:
    def __init__(self, rpc, chain, lsp, members, wallets, allow, max_feerate):
        self.rpc, self.chain = rpc, chain
        self.lsp, self.members = lsp, members
        self.dbs = ([lsp] if lsp else []) + members
        self.wallets, self.allow, self.max_feerate = wallets, set(allow), max_feerate
        self.violations, self.warnings = [], []
        self.report = {}
        self.stored = {}
        for db in self.dbs:
            for txid, tx in db.stored_txs().items():
                self.stored.setdefault(txid, dict(tx, db=db.name))
        self.owner = {}
        self._cp_cache = {}
        self._participants()
        self._commitment_labels()
        self._wallet_cache = {}

    def violate(self, check, msg, **kw):
        self.violations.append(dict({"check": check, "msg": msg}, **kw))

    def warn(self, check, msg, **kw):
        self.warnings.append(dict({"check": check, "msg": msg}, **kw))

    # -- who owns a script
    def _participants(self):
        for db in self.dbs:
            for r in db.dicts("factory_participants"):
                pt = point_of(r["pubkey"])
                if not pt:
                    continue
                spk = taproot_spk(pt)
                who = "lsp" if r["slot"] == 0 else "member:%d" % r["slot"]
                self.owner.setdefault(spk, who)
        for s in self.allow:
            self.owner.setdefault(s, "allowed")

    def _commitment_labels(self):
        """The to_remote output of every commitment of a channel whose
        output is spent on chain belongs to one party alone (key path)."""
        for db in self.dbs:
            for ch in self.channel_rows(db):
                op = (ch["funding_txid"], int(ch["funding_vout"]))
                if op not in self.chain.spender:
                    continue
                slot = int(ch.get("slot") or 0) + 1
                me = "lsp" if db.role == "lsp" else "member:%d" % slot
                them = "member:%d" % slot if db.role == "lsp" else "lsp"
                for c in self.counterparty_commitments(db, int(ch.get("id") or 0)):
                    self.owner.setdefault(c["to_remote"], me)
                    for tl in c["to_local"]:   # delayed, revocable by `me`
                        self.owner.setdefault(tl, them + " (to_local)")
                if db.role == "member":
                    mi = self.member_info(db)
                    if mi and mi[1] and len(mi[1]["vout"]) > 1:
                        self.owner.setdefault(mi[1]["vout"][1][1], them)

    def wallet_owner(self, spks):
        need = [s for s in spks if s not in self._wallet_cache]
        if need and self.wallets:
            addrs = self.rpc.batch([("decodescript", [s]) for s in need])
            amap = {}
            for s, (r, err) in zip(need, addrs):
                a = (r or {}).get("address") or ((r or {}).get("segwit") or {}).get("address")
                self._wallet_cache[s] = None
                if a:
                    amap[s] = a
            for w in self.wallets:
                todo = [s for s in amap if self._wallet_cache.get(s) is None]
                if not todo:
                    break
                res = self.rpc.batch([("getaddressinfo", [amap[s]]) for s in todo], wallet=w)
                for s, (r, err) in zip(todo, res):
                    if r and (r.get("ismine") or r.get("iswatchonly")):
                        self._wallet_cache[s] = "wallet:" + w
        for s in need:
            self._wallet_cache.setdefault(s, None)
        return {s: self._wallet_cache.get(s) for s in spks}

    def classify(self, spk):
        if spk == ANCHOR_SPK:
            return "anchor"
        if spk.startswith("6a"):
            return "burn"
        if spk in self.owner:
            return self.owner[spk]
        return self._wallet_cache.get(spk)

    # -- factories
    def roots(self):
        out = {}
        for db in self.dbs:
            for f in db.dicts("factories"):
                if not f.get("funding_txid"):
                    continue
                key = (f["funding_txid"], int(f["funding_vout"] or 0))
                out.setdefault(key, {"factory_id": f["id"], "amount": f.get("funding_amount"),
                                     "dbs": []})["dbs"].append(db.name)
        return out

    # ---------------------------------------------------------- conservation
    def check_conservation(self):
        res = []
        for (txid, vout), info in sorted(self.roots().items()):
            ftx = self.chain.txs.get(txid)
            entry = {"funding": "%s:%d" % (txid, vout), "factory_id": info["factory_id"],
                     "dbs": info["dbs"]}
            res.append(entry)
            if not ftx or not self.chain.confirmed(txid):
                entry["status"] = "unfunded"
                self.warn("conservation", "factory funding %s:%d is not confirmed" % (txid, vout))
                continue
            if vout >= len(ftx["vout"]):
                self.violate("conservation", "funding outpoint %s:%d does not exist" % (txid, vout))
                continue
            fval = ftx["vout"][vout][0]
            entry["funding_value"] = fval
            if info["amount"] is not None and int(info["amount"]) != fval:
                self.violate("conservation", "factory %s funding output holds %d sat, the DB says %d"
                             % (info["factory_id"], fval, int(info["amount"])))
            graph, terminals, followed = {}, [], set()
            stack = [(txid, vout)]
            while stack:
                op = stack.pop()
                if op in followed:
                    continue
                followed.add(op)
                val, spk = self.chain.output(*op)
                sp = self.chain.spender.get(op)
                who = self.classify(spk)
                if who is None:
                    who = self.wallet_owner([spk])[spk]
                term = {"outpoint": "%s:%d" % op, "value": val, "owner": who,
                        "spent_by": sp[0] if sp else None}
                if who is not None and op != (txid, vout):
                    terminals.append(term)
                    continue
                if sp:
                    stx = self.chain.txs[sp[0]]
                    if sp[0] not in graph:
                        graph[sp[0]] = stx
                        for i in range(len(stx["vout"])):
                            stack.append((sp[0], i))
                    continue
                parent = op[0]
                if parent in self.stored or op == (txid, vout):
                    term["owner"] = "unspent protocol output"
                    terminals.append(term)
                else:
                    term["owner"] = "UNKNOWN"
                    terminals.append(term)
            # outputs of runtime-built txs must pay a known script
            ext_in, fees = 0, 0
            reached = followed
            for gid, g in graph.items():
                fee = self.chain.fee(g)
                fees += fee or 0
                for v in g["vin"]:
                    if (v["txid"], v["vout"]) not in reached:
                        ext_in += v["value"] or 0
                rate = (fee or 0) / g["vsize"]
                if fee is None or fee < 0:
                    self.violate("conservation", "graph tx %s: fee unknown or negative" % gid)
                elif rate > self.max_feerate:
                    self.violate("conservation", "graph tx %s pays %d sat (%.1f sat/vB), more than %s sat/vB"
                                 % (gid, fee, rate, self.max_feerate), txid=gid)
                if gid not in self.stored:
                    for i, (val, spk) in enumerate(g["vout"]):
                        w = self.classify(spk) or self.wallet_owner([spk])[spk]
                        if w is None and (gid, i) not in self.chain.spender:
                            self.violate("conservation", "tx %s (not signed in any DB) output %d pays "
                                         "%d sat to a script nobody is known to own: %s"
                                         % (gid, i, val, spk), txid=gid)
            for t in terminals:
                if t["owner"] == "UNKNOWN":
                    self.violate("conservation", "output %s (%d sat) is unspent and pays a script "
                                 "no party is known to own" % (t["outpoint"], t["value"]))
            total_out = sum(t["value"] for t in terminals)
            if fval + ext_in != total_out + fees:
                self.violate("conservation", "funding %d + outside inputs %d != terminal outputs %d "
                             "+ fees %d" % (fval, ext_in, total_out, fees))
            by_owner = {}
            for t in terminals:
                o = t["owner"] if t["owner"] != "unspent protocol output" else "pending"
                by_owner[o] = by_owner.get(o, 0) + t["value"]
            entry.update({"status": "ok", "graph_txs": len(graph), "fees": fees,
                          "outside_inputs": ext_in, "terminal_by_owner": by_owner,
                          "terminals": terminals})
        self.report["conservation"] = res

    # ------------------------------------------------------- commitment math
    def counterparty_commitments(self, db, chan_id):
        """The counterparty's commitments of channel chan_id as this DB can
        derive them: per commitment number, its to_local scripts (with and
        without the revocation leaf, for each CSV delay), its to_remote
        script (this side's payment key), and whether this DB holds the
        counterparty's revocation secret for it."""
        key = (db.path, chan_id)
        if key not in self._cp_cache:
            self._cp_cache[key] = self._counterparty_commitments(db, chan_id)
        return self._cp_cache[key]

    def _counterparty_commitments(self, db, chan_id):
        bps = db.dicts("channel_basepoints", "WHERE channel_id=%d" % chan_id)
        if not bps:
            bps = db.dicts("channel_basepoints")
            if len(bps) != 1:
                return []
        b = bps[0]
        psec, rsec = hexkey(b["local_payment_secret"]), hexkey(b["local_revocation_secret"])
        rdel = point_of(b["remote_delayed_bp"])
        if not (psec and rsec and rdel):
            return []
        my_rev, my_pay = pt_mul(rsec), pt_mul(psec)
        pcps = db.rows("SELECT commit_num, point FROM remote_pcps WHERE channel_id=?", (chan_id,))
        if not pcps:
            pcps = db.rows("SELECT commit_num, point FROM remote_pcps")
        secrets = {}
        for cn, s in db.rows("SELECT commit_num, secret FROM revocation_secrets WHERE channel_id=?",
                             (chan_id,)) or db.rows("SELECT commit_num, secret FROM revocation_secrets"):
            k = hexkey(_txt(s))
            if k:
                secrets[ser33(pt_mul(k))] = cn
        delays = {DEFAULT_CSV}
        for r in db.dicts("channels"):
            if r.get("to_self_delay"):
                delays.add(int(r["to_self_delay"]))
        out = []
        for cn, p in pcps:
            pcp = point_of(_txt(p))
            if not pcp:
                continue
            rev = derive_revocation(my_rev, pcp)
            dk = xonly(lift_x(derive_pub(rdel, pcp)[0]))
            to_local = []
            for d in sorted(delays):
                lf = csv_leaf(d, dk)
                to_local.append(taproot_spk(rev, leaf_hash(lf)))
                rl = b"\x20" + xonly(lift_x(rev[0])) + b"\xac"
                to_local.append(taproot_spk(rev, branch(leaf_hash(lf), leaf_hash(rl))))
            out.append({"cn": cn, "to_local": to_local,
                        "to_remote": taproot_spk(derive_pub(my_pay, pcp)),
                        "revoked": ser33(pcp) in secrets})
        return out

    @staticmethod
    def is_csv_sweep(witness):
        """A script-path spend whose leaf script starts with <n> OP_CSV."""
        if len(witness) < 2:
            return False
        w = list(witness)
        if w and w[-1].startswith("50"):  # annex
            w = w[:-1]
        if len(w) < 2:
            return False
        script = bytes.fromhex(w[-2])
        n = script[0]
        off = 1 if (n == 0 or 0x51 <= n <= 0x60) else 1 + n
        return off < len(script) and script[off] == 0xB2

    # ------------------------------------------------------------ channels
    def channel_rows(self, db):
        return [r for r in db.dicts("channels") if r.get("funding_txid")]

    def member_info(self, db):
        """(channel row, latest signed commitment tx or None, slot)."""
        chans = self.channel_rows(db)
        if not chans:
            return None
        ch = chans[0]
        sc = db.dicts("signed_commitments")
        latest = None
        if sc:
            row = max(sc, key=lambda r: r["commitment_number"])
            try:
                latest = parse_tx(_txt(row["signed_tx_hex"]))
                latest["cn"] = row["commitment_number"]
            except ValueError:
                latest = None
        return ch, latest

    def lsp_channel_for(self, op):
        if not self.lsp:
            return None
        for r in self.channel_rows(self.lsp):
            if (r["funding_txid"], int(r["funding_vout"])) == op:
                return r
        return None

    # ------------------------------------------------------------ balances
    def check_balances(self):
        out = {}
        for db in self.members:
            mi = self.member_info(db)
            rec = {}
            out[db.name] = rec
            if not mi:
                rec["status"] = "no channel"
                continue
            ch, latest = mi
            op = (ch["funding_txid"], int(ch["funding_vout"]))
            local, remote = int(ch["local_amount"]), int(ch["remote_amount"])
            rec.update({"channel": "%s:%d" % op, "db_local": local, "db_remote": remote,
                        "db_commitment": ch.get("commitment_number"),
                        "capacity": ch.get("funding_amount")})
            lch = self.lsp_channel_for(op)
            if lch is not None:
                rec["lsp_db"] = {"local": lch["local_amount"], "remote": lch["remote_amount"],
                                 "commitment": lch.get("commitment_number")}
                if (lch.get("commitment_number") == ch.get("commitment_number") and
                        (int(lch["remote_amount"]), int(lch["local_amount"])) != (local, remote)):
                    self.violate("balances", "%s: the member's DB says %d/%d, the LSP's DB %d/%d "
                                 "(member/LSP) at commitment %s" % (db.name, local, remote,
                                 lch["remote_amount"], lch["local_amount"], ch.get("commitment_number")),
                                 member=db.name)
            sp = self.chain.spender.get(op)
            dist = self._dist(db)
            if sp:
                ctx = self.chain.txs[sp[0]]
                rec["exit"] = "channel output spent by %s" % sp[0]
                self._check_commitment_outcome(db, ch, latest, ctx, rec)
            elif dist and self.chain.confirmed(dist["txid"]):
                rec["exit"] = "distribution TX %s" % dist["txid"]
                self._check_dist_outcome(db, ch, dist, rec)
            elif self._payout_exit(db) and self._payout_exit(db)[0] == "confirmed":
                rec["exit"] = "end-date payout %s" % self._payout_exit(db)[1]
            else:
                f = self._factory_spender(db)
                if f and f not in self.stored:
                    rec["exit"] = "factory funding spent by %s (not signed in any DB)" % f
                    self.warn("balances", "%s: factory funding spent by %s, a transaction no DB "
                              "holds; its payout is not checked" % (db.name, f))
                else:
                    rec["exit"] = None
        self.report["balances"] = out

    def _payouts(self, db):
        out = []
        if "factory_payouts" not in db.tables:
            return out
        for r in db.dicts("factory_payouts"):
            try:
                out.append(parse_tx(_txt(r["signed_tx_hex"])))
            except ValueError:
                continue
        return out

    def _payout_exit(self, db):
        """('confirmed', txid) when one of the member's end-date payouts is
        on chain, ('open', txid) when one spends an on-chain unspent output,
        else None."""
        alt = None
        for t in self._payouts(db):
            if self.chain.confirmed(t["txid"]):
                return ("confirmed", t["txid"])
            fin = t["vin"][0]
            if (self.chain.output(fin[0], fin[1]) and self.chain.confirmed(fin[0]) and
                    not self.chain.spender.get((fin[0], fin[1]))):
                alt = ("open", "%s (nLockTime %d)" % (t["txid"], t["locktime"]))
        return alt

    def _dist(self, db):
        for r in db.dicts("distribution_txs"):
            try:
                return parse_tx(_txt(r["signed_tx_hex"]))
            except ValueError:
                continue
        return None

    def _factory_spender(self, db):
        for f in db.dicts("factories"):
            if f.get("funding_txid"):
                sp = self.chain.spender.get((f["funding_txid"], int(f["funding_vout"] or 0)))
                if sp:
                    return sp[0]
        return None

    def _my_slot(self, db, ch):
        parts = db.dicts("factory_participants")
        if ch.get("slot") is not None and any(p["slot"] == int(ch["slot"]) + 1 for p in parts):
            return int(ch["slot"]) + 1
        return None

    def _expected_pair(self, mine, theirs, theirs_funds_anchor, has_anchor):
        """Outputs (mine, theirs) of a commitment where `theirs` is the
        to_remote side: the anchor comes out of to_remote when it can,
        else out of to_local (channel_build_commitment_tx_impl)."""
        if not has_anchor:
            return mine, theirs
        if theirs_funds_anchor:
            return mine, theirs - ANCHOR_VALUE
        return mine - ANCHOR_VALUE, theirs

    def _check_commitment_outcome(self, db, ch, latest, ctx, rec):
        local, remote = int(ch["local_amount"]), int(ch["remote_amount"])
        has_anchor = any(o[1] == ANCHOR_SPK for o in ctx["vout"])
        if latest and ctx["txid"] == latest["txid"]:
            rec["commitment"] = {"txid": ctx["txid"], "kind": "member's own", "cn": latest["cn"]}
            if ch.get("commitment_number") is not None and latest["cn"] != ch["commitment_number"]:
                self.violate("balances", "%s: confirmed commitment %d is not the channel's current "
                             "commitment %s" % (db.name, latest["cn"], ch["commitment_number"]),
                             member=db.name)
            exp_l, exp_r = self._expected_pair(local, remote, remote > ANCHOR_VALUE + DUST, has_anchor)
            got_l, got_r = ctx["vout"][0][0], ctx["vout"][1][0] if len(ctx["vout"]) > 1 else 0
            rec["to_local"], rec["to_remote"] = got_l, got_r
            if (got_l, got_r) != (exp_l, exp_r):
                self.violate("balances", "%s: its commitment %s pays to_local %d / to_remote %d, "
                             "its DB balance %d/%d means %d/%d" % (db.name, ctx["txid"], got_l, got_r,
                             local, remote, exp_l, exp_r), member=db.name)
            self._follow_sweep(db, ctx, 0, got_l, rec)
            return
        cid = int(ch.get("id") or 0)
        for c in self.counterparty_commitments(db, cid):
            if any(o[1] == c["to_remote"] for o in ctx["vout"]):
                rec["commitment"] = {"txid": ctx["txid"], "kind": "LSP's", "cn": c["cn"],
                                     "revoked": c["revoked"]}
                if c["revoked"]:
                    return  # the revocation check covers it
                got = next(o[0] for o in ctx["vout"] if o[1] == c["to_remote"])
                # the funder (the LSP) funds the anchor from its to_local,
                # never from the member's output
                exp = local
                rec["to_remote"] = got
                if got != exp:
                    self.violate("balances", "%s: the LSP's commitment %s pays the member %d, its DB "
                                 "balance %d means %d" % (db.name, ctx["txid"], got, local, exp),
                                 member=db.name)
                return
        rv = self._revoked_own_commitment(ch, ctx)
        if rv:
            self._revoked_outcome(db, ctx, rv, rec)
            return
        # the member's own end-date payout of the channel output: it pays the
        # member the whole output less fee and anchor, at least its balance
        for t in self._payouts(db):
            if t["txid"] == ctx["txid"]:
                paid = sum(o[0] for o in ctx["vout"] if o[1] != ANCHOR_SPK)
                rec["commitment"] = {"txid": ctx["txid"], "kind": "end-date payout"}
                rec["to_member"] = paid
                if paid < local:
                    self.violate("balances", "%s: its end-date payout %s pays %d, below its "
                                 "balance %d" % (db.name, ctx["txid"], paid, local), member=db.name)
                return
        self.violate("balances", "%s: its channel output is spent by %s, which is neither its latest "
                     "commitment nor one of the LSP's it can recognise" % (db.name, ctx["txid"]),
                     member=db.name)

    def _revoked_own_commitment(self, ch, ctx):
        """The member's own commitment that spends its channel output, if it is
        an old one the other side holds the revocation secret of.  The member's
        DB keeps only its latest commitment; the other side's DB derives all of
        them (counterparty_commitments), so the match is made there."""
        op = (ch["funding_txid"], int(ch["funding_vout"]))
        lch = self.lsp_channel_for(op)
        if lch is None:
            return None
        for c in self.counterparty_commitments(self.lsp, int(lch.get("id") or 0)):
            idx = [i for i, o in enumerate(ctx["vout"]) if o[1] in c["to_local"]]
            if c["revoked"] and idx and any(o[1] == c["to_remote"] for o in ctx["vout"]):
                return {"cn": c["cn"], "to_local_vout": idx[0]}
        return None

    def _revoked_outcome(self, db, ctx, rv, rec):
        """A revoked commitment of the member is on chain: the expected outcome
        is that its to_local is taken by a confirmed penalty, and the balance
        comes from the penalty.  Whether the penalty is there and is not a CSV
        sweep is the revocation check's verdict; here the outcome is recorded."""
        vout = rv["to_local_vout"]
        rec["commitment"] = {"txid": ctx["txid"], "kind": "member's own, revoked",
                             "cn": rv["cn"], "revoked": True}
        sp = self.chain.spender.get((ctx["txid"], vout))
        if sp and sp[1] is not None and self.chain.confirmed(sp[0]):
            pen = self.chain.txs[sp[0]]
            rec["final"] = {"penalty": sp[0],
                            "received": sum(o[0] for o in pen["vout"] if o[1] != ANCHOR_SPK)}
        else:
            rec["final"] = {"penalty": None}

    def _follow_sweep(self, db, ctx, vout, value, rec):
        sp = self.chain.spender.get((ctx["txid"], vout))
        if not sp:
            rec["final"] = {"unspent": value}
            return
        s = self.chain.txs[sp[0]]
        fee = self.chain.fee(s)
        rec["final"] = {"sweep": sp[0], "fee": fee,
                        "received": sum(o[0] for o in s["vout"]) if len(s["vin"]) == 1 else None}
        if fee is not None and fee / s["vsize"] > self.max_feerate:
            self.violate("balances", "%s: sweep %s pays %d sat fee (%.1f sat/vB)" %
                         (db.name, sp[0], fee, fee / s["vsize"]), member=db.name)

    def _check_dist_outcome(self, db, ch, dist, rec):
        tx = self.chain.txs[dist["txid"]]
        slot = self._my_slot(db, ch)
        member_spks = {}
        for p in db.dicts("factory_participants"):
            pt = point_of(p["pubkey"])
            if pt and p["slot"] != 0:
                member_spks[taproot_spk(pt)] = p["slot"]
        cap = int(ch.get("funding_amount") or 0)
        mine = [o[0] for o in tx["vout"] if member_spks.get(o[1]) == slot]
        rec["dist_payout"] = mine[0] if mine else None
        if slot is None or not mine:
            self.violate("balances", "%s: the distribution TX %s has no output to its key" %
                         (db.name, dist["txid"]), member=db.name)
        elif mine[0] < cap:
            self.violate("balances", "%s: the distribution TX pays it %d, less than its channel "
                         "capacity %d" % (db.name, mine[0], cap), member=db.name)
        others = [(i, o) for i, o in enumerate(tx["vout"])
                  if o[1] != ANCHOR_SPK and o[1] not in member_spks]
        if others:
            self.violate("balances", "the distribution TX %s pays %d output(s) to non-members: %s" %
                         (dist["txid"], len(others), others), member=db.name)

    # ---------------------------------------------------------- revocation
    def check_revocation(self):
        found = []
        # (1) breach records the DBs keep
        for db in self.dbs:
            for r in db.dicts("old_commitments"):
                if not self.chain.confirmed(r["txid"]):
                    continue
                found.append(self._penalised(db, r["txid"], int(r["to_local_vout"]),
                                             "old_commitments cn %s" % r["commit_num"]))
        # (2) any confirmed spend of a channel output that is a revoked commitment
        seen = {f["txid"] for f in found}
        for db in self.dbs:
            for ch in self.channel_rows(db):
                op = (ch["funding_txid"], int(ch["funding_vout"]))
                sp = self.chain.spender.get(op)
                if not sp or sp[0] in seen or not self.chain.confirmed(sp[0]):
                    continue
                ctx = self.chain.txs[sp[0]]
                for c in self.counterparty_commitments(db, int(ch.get("id") or 0)):
                    idx = [i for i, o in enumerate(ctx["vout"]) if o[1] in c["to_local"]]
                    if c["revoked"] and idx and any(o[1] == c["to_remote"] for o in ctx["vout"]):
                        found.append(self._penalised(db, sp[0], idx[0],
                                                     "revoked commitment cn %s" % c["cn"]))
                        seen.add(sp[0])
                        break
        self.report["revocation"] = found

    def _penalised(self, db, txid, vout, what):
        sp = self.chain.spender.get((txid, vout))
        rec = {"txid": txid, "to_local_vout": vout, "db": db.name, "what": what}
        if not sp or sp[1] is None:
            rec["penalty"] = None
            self.violate("revocation", "%s: revoked commitment %s (%s) is confirmed and its to_local "
                         "output is not taken by a confirmed penalty" % (db.name, txid, what), txid=txid)
            return rec
        s = self.chain.txs[sp[0]]
        w = next(v["witness"] for v in s["vin"] if (v["txid"], v["vout"]) == (txid, vout))
        rec["penalty"] = sp[0]
        if self.is_csv_sweep(w):
            self.violate("revocation", "%s: revoked commitment %s (%s): its to_local was swept by the "
                         "CSV path (%s), not by the penalty" % (db.name, txid, what, sp[0]), txid=txid)
        return rec

    # ---------------------------------------------------------------- exit
    def check_exit(self):
        out = {}
        for db in self.members:
            mi = self.member_info(db)
            rec = {}
            out[db.name] = rec
            if not mi:
                rec["status"] = "no channel"
                funded = [f for f in db.dicts("factories") if f.get("funding_txid")
                          and self.chain.confirmed(f["funding_txid"])]
                lsp_knows = self.lsp and any(
                    self.chain.confirmed(f["funding_txid"]) for f in self.lsp.dicts("factories")
                    if f.get("funding_txid"))
                if funded or (lsp_knows and not db.dicts("factories")):
                    rec["status"] = "STUCK"
                    self.violate("exit", "%s holds no channel although its factory is funded"
                                 % db.name, member=db.name)
                continue
            ch, latest = mi
            op = (ch["funding_txid"], int(ch["funding_vout"]))
            dist = self._dist(db)
            if self.chain.spender.get(op):
                rec["status"] = "exited (channel output spent)"
                continue
            if dist and self.chain.confirmed(dist["txid"]):
                rec["status"] = "exited (distribution TX)"
                continue
            pe = self._payout_exit(db)
            if pe and pe[0] == "confirmed":
                rec["status"] = "exited (end-date payout %s)" % pe[1]
                continue
            fs = self._factory_spender(db)
            if fs and fs not in self.stored:
                rec["status"] = "exited (factory closed by %s)" % fs
                continue
            problems = []
            if latest is None:
                problems.append("no signed commitment in its DB")
            else:
                path, why = self._path(db, latest)
                if why:
                    problems.append(why)
                else:
                    rec["path"] = [t["txid"] for t in path]
                    why = self._broadcastable(path)
                    if why:
                        problems.append(why)
            if not problems:
                rec["status"] = "can exit with its commitment"
                continue
            alt = None
            if dist:
                fin = dist["vin"][0]
                if (self.chain.output(fin[0], fin[1]) and self.chain.confirmed(fin[0]) and
                        not self.chain.spender.get((fin[0], fin[1]))):
                    alt = "distribution TX %s (nLockTime %d)" % (dist["txid"], dist["locktime"])
            if not alt and pe:
                alt = "end-date payout %s" % pe[1]
            if alt:
                rec["status"] = "can exit with the %s" % alt
                rec["commitment_path"] = problems
                self.warn("exit", "%s: commitment path unusable (%s); the distribution TX remains"
                          % (db.name, "; ".join(problems)), member=db.name)
            else:
                rec["status"] = "STUCK"
                rec["problems"] = problems
                self.violate("exit", "%s cannot exit from its DB: %s" % (db.name, "; ".join(problems)),
                             member=db.name)
        self.report["exit"] = out

    def _path(self, db, commit):
        """Ancestors of commit (root first) that are not confirmed, from the
        member's DB; or (None, reason)."""
        stored = db.stored_txs()
        path, cur = [commit], commit
        for _ in range(64):
            nxt = None
            for (ptxid, pvout, _, _) in cur["vin"]:
                if self.chain.confirmed(ptxid):
                    if not self.chain.output(ptxid, pvout):
                        return None, "%s spends %s:%d, which does not exist" % (cur["txid"], ptxid, pvout)
                    sp = self.chain.spender.get((ptxid, pvout))
                    if sp and sp[0] != cur["txid"]:
                        return None, ("%s spends %s:%d, already spent on chain by %s" %
                                      (cur["txid"], ptxid, pvout, sp[0]))
                    continue
                if ptxid in stored:
                    t = stored[ptxid]
                    if pvout >= len(t["vout"]):
                        return None, "%s spends %s:%d, past its outputs" % (cur["txid"], ptxid, pvout)
                    nxt = t
                    continue
                return None, ("%s spends %s:%d, neither confirmed nor in the member's DB" %
                              (cur["txid"], ptxid, pvout))
            if nxt is None:
                return path, None
            path.insert(0, nxt)
            cur = nxt
        return None, "ancestor chain longer than 64"

    TOLERATED = re.compile(r"min relay fee not met|mempool min fee not met|non-final|"
                           r"non-BIP68-final|already|insufficient fee|txn-mempool-conflict|"
                           r"TRUC|v3|package|too-long-mempool-chain|ephemeral", re.I)

    def _broadcastable(self, path):
        first = path[0]
        if self.chain.txs.get(first["txid"]):
            return None
        # signatures first: the node refuses a tx on its fee before it
        # verifies its scripts, so a bad signature hides behind a fee refusal
        made = {t["txid"]: t for t in path}
        for t in path:
            prevouts = []
            for (p, v, _, _) in t["vin"]:
                o = made[p]["vout"][v] if p in made else self.chain.output(p, v)
                prevouts.append(o)
            if any(o is None for o in prevouts):
                continue
            for i in range(len(t["vin"])):
                if taproot_keypath_valid(t, i, prevouts) is False:
                    return "%s (%s) input %d carries an invalid signature" % (
                        t["txid"], t.get("where", "?"), i)
        res = self.rpc.call("testmempoolaccept", [first["hex"]])[0]
        if not res.get("allowed") and not self.TOLERATED.search(res.get("reject-reason", "")):
            return "the node refuses %s (%s): %s" % (first["txid"], first.get("where", "commitment"),
                                                     res.get("reject-reason"))
        for prev, t in zip(path, path[1:]):
            ins = [(p, v) for (p, v, _, _) in t["vin"] if p == prev["txid"]]
            if not ins:
                return "%s does not spend %s" % (t["txid"], prev["txid"])
            if any(not w for (_, _, _, w) in t["vin"]):
                return "%s has an unsigned input" % t["txid"]
            fee = sum(prev["vout"][v][0] for _, v in ins) - sum(o[0] for o in t["vout"])
            if len(ins) == len(t["vin"]) and fee < 0:
                return "%s spends more than it receives" % t["txid"]
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--conf", help="bitcoin.conf with rpcuser/rpcpassword/rpcport")
    ap.add_argument("--rpchost", default="127.0.0.1")
    ap.add_argument("--rpcport", type=int)
    ap.add_argument("--rpcuser")
    ap.add_argument("--rpcpassword")
    ap.add_argument("--lsp-db")
    ap.add_argument("--member-db", action="append", default=[])
    ap.add_argument("--db-dir", help="a drill directory: lsp.db and c*.db in it")
    ap.add_argument("--wallet", action="append", default=[],
                    help="a node wallet whose addresses count as owned (sweeps, CPFP change)")
    ap.add_argument("--allow-spk", action="append", default=[])
    ap.add_argument("--from-height", type=int, default=0)
    ap.add_argument("--max-feerate", type=float, default=50.0, help="sat/vB (default 50)")
    ap.add_argument("--checks", default="conservation,balances,revocation,exit")
    ap.add_argument("--json", help="write the JSON report here too")
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    a = ap.parse_args()

    conf = read_conf(a.conf) if a.conf else {}
    port = a.rpcport or int(conf.get("rpcport", 18443))
    user = a.rpcuser or conf.get("rpcuser")
    pw = a.rpcpassword or conf.get("rpcpassword")
    if not user:
        print("check_chain: no RPC credentials (--conf or --rpcuser/--rpcpassword)", file=sys.stderr)
        return 2
    lsp_path, mem = a.lsp_db, list(a.member_db)
    if a.db_dir:
        if not lsp_path and os.path.exists(os.path.join(a.db_dir, "lsp.db")):
            lsp_path = os.path.join(a.db_dir, "lsp.db")
        mem += sorted((os.path.join(a.db_dir, f) for f in os.listdir(a.db_dir)
                       if re.fullmatch(r"c\d+\.db", f)),
                      key=lambda p: int(re.search(r"(\d+)\.db$", p).group(1)))
    if not lsp_path and not mem:
        print("check_chain: no databases given", file=sys.stderr)
        return 2
    try:
        lsp = Db(lsp_path, "lsp", "lsp") if lsp_path else None
        members = [Db(p, "member", os.path.basename(p)[:-3]) for p in mem]
    except sqlite3.Error as e:
        print("check_chain: cannot open a database: %s" % e, file=sys.stderr)
        return 2
    rpc = Rpc(a.rpchost, port, user, pw)
    try:
        chain = Chain(rpc, a.from_height)
        ck = Checker(rpc, chain, lsp, members, a.wallet, a.allow_spk, a.max_feerate)
        checks = [c.strip() for c in a.checks.split(",") if c.strip()]
        for c in checks:
            if c not in ("conservation", "balances", "revocation", "exit"):
                print("check_chain: unknown check %s" % c, file=sys.stderr)
                return 2
            getattr(ck, "check_" + c)()
    except RpcError as e:
        print("check_chain: %s" % e, file=sys.stderr)
        return 2
    status = {c: ("fail" if any(v["check"] == c for v in ck.violations) else "pass") for c in checks}
    doc = {"tool": "check_chain", "tip": chain.tip, "dbs": [d.path for d in ck.dbs],
           "status": status, "result": "FAIL" if ck.violations else "PASS",
           "violations": ck.violations, "warnings": ck.warnings, "report": ck.report}
    text = json.dumps(doc, indent=1, default=str)
    if a.json:
        with open(a.json, "w") as f:
            f.write(text + "\n")
    if not a.quiet:
        print(text)
    print("INVARIANTS: %s (%s)%s" % (doc["result"], ", ".join("%s %s" % kv for kv in status.items()),
          "".join("\n  VIOLATION [%s] %s" % (v["check"], v["msg"]) for v in ck.violations)),
          file=sys.stderr)
    return 1 if ck.violations else 0


if __name__ == "__main__":
    sys.exit(main())
