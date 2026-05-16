#!/usr/bin/env python3
"""SuperScalar Web Dashboard — stdlib-only (http.server + sqlite3 + subprocess).

Tabbed read-only dashboard for SuperScalar signet deployments.
Usage:
    python3 tools/dashboard.py --demo --port 8080
    python3 tools/dashboard.py --port 8080 --lsp-db ... --client-db ... --btc-cli ... --cln-cli ...
"""

import argparse, json, os, random, sqlite3, subprocess, sys, time
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------------------------------------------------------------------------
# Config + helpers
# ---------------------------------------------------------------------------

class Config:
    def __init__(self, a):
        self.port = a.port; self.demo = getattr(a,'demo',False)
        self.lsp_db = a.lsp_db; self.client_db = a.client_db
        self.btc_cli = a.btc_cli; self.btc_network = a.btc_network
        self.btc_rpcuser = a.btc_rpcuser; self.btc_rpcpassword = a.btc_rpcpassword
        # P3: allow pointing bitcoin-cli at a non-default daemon (custom
        # datadir / shifted RPC port).  Without these, the helper silently
        # hits whatever bitcoind is on the network's default port with
        # ~/.bitcoin/bitcoin.conf credentials, which on a shared box can
        # be a completely different chain.
        self.btc_datadir = getattr(a, 'btc_datadir', None)
        self.btc_rpcport = getattr(a, 'btc_rpcport', None)
        # Defense-Status #13 wallet UTXO tile: name of the LSP's bitcoind
        # wallet so listunspent can be scoped to it.  Leave None to fall
        # back to the default wallet (or skip the tile entirely).
        self.lsp_wallet = getattr(a, 'lsp_wallet', None)
        self.cln_cli = a.cln_cli; self.cln_a_dir = a.cln_a_dir; self.cln_b_dir = a.cln_b_dir

def run_cmd(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout.strip(), True) if r.returncode == 0 else (r.stderr.strip(), False)
    except Exception as e:
        return str(e), False

def btc_cmd(cfg, *a):
    cmd = [cfg.btc_cli]
    if cfg.btc_datadir: cmd.append("-datadir=" + cfg.btc_datadir)
    if cfg.btc_network and cfg.btc_network != "mainnet": cmd.append("-" + cfg.btc_network)
    if cfg.btc_rpcport: cmd.append("-rpcport=" + str(cfg.btc_rpcport))
    if cfg.btc_rpcuser: cmd.append("-rpcuser=" + cfg.btc_rpcuser)
    if cfg.btc_rpcpassword: cmd.append("-rpcpassword=" + cfg.btc_rpcpassword)
    cmd.extend(a); return run_cmd(cmd)

def cln_cmd(cfg, d, *a):
    return run_cmd([cfg.cln_cli, "--lightning-dir=" + d] + list(a))

def pgrep_check(p):
    _, ok = run_cmd(["pgrep", "-f", p]); return ok

def query_db(path, sql, params=()):
    if not path or not os.path.exists(path): return None, "not found"
    try:
        c = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=2)
        c.row_factory = sqlite3.Row
        rows = [dict(r) for r in c.execute(sql, params).fetchall()]; c.close()
        return rows, None
    except Exception as e:
        return None, str(e)

# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------

def collect_processes(cfg):
    p = {}
    for n, pat in [("bitcoind","bitcoind.*-"+(cfg.btc_network or "signet")),
        ("cln_a","lightningd.*"+(cfg.cln_a_dir or "/cln-a")),
        ("cln_b","lightningd.*"+(cfg.cln_b_dir or "/cln-b")),
        ("bridge","superscalar_bridge"),("lsp","superscalar_lsp"),("client","superscalar_client")]:
        p[n] = pgrep_check(pat)
    if not p["bitcoind"] and cfg.btc_cli: _, p["bitcoind"] = btc_cmd(cfg, "getblockchaininfo")[1:][:1] or [False]
    return p

# --- P3: on-chain TX enrichment cache ---
# Single in-process cache shared across requests so multiple browser tabs
# don't multiply RPC load.  Key = txid (display order).  Value =
# {confirmations, vsize, in_mempool, last_check, never_seen}.
# Re-check TTLs:
#   - confs >= 6   : 5 min (catch reorgs cheaply)
#   - confs <  6   : 30 sec (mempool / shallow churns)
#   - never_seen   : 30 sec (might land any moment)
_tx_cache = {}
def _tx_should_refresh(entry, now):
    if not entry: return True
    age = now - entry.get("last_check", 0)
    if entry.get("never_seen"): return age >= 30
    confs = entry.get("confirmations", 0) or 0
    return age >= (300 if confs >= 6 else 30)

def collect_tx_enrichment(cfg, txids):
    """Look up txid metadata via bitcoin-cli getrawtransaction with caching.
    Returns {txid: {confirmations, vsize, in_mempool, last_check}}.
    Caller passes a deduped txid set; we only RPC for entries past their
    TTL.  See header comment for the TTL policy."""
    if not cfg.btc_cli: return {}
    now = time.time()
    out = {}
    for txid in txids:
        if not txid or len(txid) != 64: continue
        cached = _tx_cache.get(txid)
        if not _tx_should_refresh(cached, now):
            out[txid] = cached
            continue
        # RPC.  -verbose=1 returns JSON with confirmations + vsize.
        raw, ok = btc_cmd(cfg, "getrawtransaction", txid, "1")
        entry = {"last_check": now}
        if ok:
            try:
                obj = json.loads(raw)
                entry["confirmations"] = int(obj.get("confirmations", 0) or 0)
                entry["vsize"] = int(obj.get("vsize", 0) or 0)
                entry["in_mempool"] = (entry["confirmations"] == 0)
                entry["never_seen"] = False
            except Exception:
                entry["never_seen"] = True
                entry["confirmations"] = 0
                entry["in_mempool"] = False
                entry["vsize"] = 0
        else:
            # bitcoin-cli says "No such mempool or blockchain transaction"
            # → TX never broadcast (or evicted).  Keep last_check so we
            # don't hammer; treat as never_seen for the empty-state UI.
            entry["never_seen"] = True
            entry["confirmations"] = 0
            entry["in_mempool"] = False
            entry["vsize"] = 0
        _tx_cache[txid] = entry
        out[txid] = entry
    return out

def _extract_txids(databases):
    """Collect every txid that might be worth enriching across both DBs."""
    txids = set()
    # Defensive iterator: skip any row that isn't a dict (handles edge
    # cases where the LSP DB is in a half-initialized state during
    # startup races — saw 'str' rows leak in when persist_open errored
    # partway through, which crashed _extract_txids and 500'd the API).
    def each(rows, key, skip_q=False):
        for r in (rows or []):
            if not isinstance(r, dict): continue
            v = r.get(key)
            if v and (not skip_q or v != "?"):
                txids.add(v)
    for db in databases.values():
        if not isinstance(db, dict): continue
        each(db.get("factories"),               "funding_txid")
        each(db.get("tree_nodes"),              "txid")
        each(db.get("ps_leaf_chains"),          "txid")
        each(db.get("ps_subfactory_chains"),    "txid")
        each(db.get("ps_initial_signed_states"),"txid")
        each(db.get("jit_channels"),            "funding_txid")
        each(db.get("broadcast_log"),           "txid", skip_q=True)
        each(db.get("watchtower_pending"),      "txid")
        each(db.get("old_commitments"),         "txid")
        each(db.get("pending_sweeps"),          "source_txid")
        each(db.get("pending_sweeps"),          "sweep_txid")
    return txids

def collect_bitcoin(cfg):
    d = {"available": False}
    if not cfg.btc_cli: return d
    for rpc, handler in [
        ("getblockchaininfo", lambda o: d.update(available=True, chain=o.get("chain","?"),
            blocks=o.get("blocks",0), headers=o.get("headers",0),
            ibd=o.get("initialblockdownload",False), verification=o.get("verificationprogress",0))),
        ("getnetworkinfo", lambda o: d.update(peers=o.get("connections",0))),
        ("getmempoolinfo", lambda o: d.update(mempool_size=o.get("size",0)))]:
        out, ok = btc_cmd(cfg, rpc)
        if ok:
            try: handler(json.loads(out))
            except: pass
    out, ok = btc_cmd(cfg, "-rpcwallet=superscalar_lsp", "getbalance")
    if ok:
        try: d["balance"] = float(out)
        except: pass
    return d

def collect_wallet_utxos(cfg):
    """Defense-Status #13 source: query the LSP wallet's UTXOs via
    bitcoin-cli listunspent so the dashboard can compare available
    pre-split outputs against the worst-case mass-CPFP need."""
    out = {"available": False, "configured": bool(cfg.lsp_wallet),
        "wallet": cfg.lsp_wallet or None}
    if not cfg.btc_cli: return out
    args = ["listunspent"]
    if cfg.lsp_wallet:
        raw, ok = btc_cmd(cfg, "-rpcwallet=" + cfg.lsp_wallet, *args)
    else:
        # Fall back to default wallet (may fail on multi-wallet setups
        # where bitcoind requires explicit -rpcwallet=NAME).
        raw, ok = btc_cmd(cfg, *args)
    if not ok:
        out["error"] = "listunspent failed"
        return out
    try:
        utxos = json.loads(raw)
        amounts = [int(round(float(u.get("amount", 0)) * 1e8)) for u in utxos]
        out.update({"available": True,
            "count": len(utxos),
            "total_sats": sum(amounts),
            "min_sats": min(amounts) if amounts else 0,
            "max_sats": max(amounts) if amounts else 0})
    except Exception as e:
        out["error"] = str(e)
    return out

def collect_databases(cfg):
    data = {"lsp": {}, "client": {}}
    for label, path in [("lsp", cfg.lsp_db), ("client", cfg.client_db)]:
        if not path or not os.path.exists(str(path)):
            data[label]["error"] = "not configured"; continue
        for key, sql in [
            ("factories", "SELECT * FROM factories ORDER BY id DESC LIMIT 5"),
            ("participants", "SELECT * FROM factory_participants ORDER BY factory_id, slot"),
            ("channels", "SELECT * FROM channels ORDER BY id"),
            ("htlcs", "SELECT * FROM htlcs ORDER BY id DESC LIMIT 50"),
        ]:
            rows, err = query_db(path, sql)
            # Always assign a list on error (matches the pattern used by
            # every other collector query below).  Earlier this was
            # `{"error": err}` which left downstream iterators (e.g.,
            # _extract_txids) walking a dict's keys as if they were rows —
            # crashed the entire /api/status response when client.db
            # lacked an LSP-only table like `factories` or `participants`.
            data[label][key] = rows if not err else []
        for key, sql in [
            ("watchtower_count", "SELECT COUNT(*) as c FROM old_commitments"),
            ("revocation_count", "SELECT COUNT(*) as c FROM revocation_secrets"),
        ]:
            rows, err = query_db(path, sql)
            data[label][key] = rows[0]["c"] if (not err and rows) else 0
        rows, err = query_db(path,
            "SELECT channel_id, commit_num, txid, to_local_amount, to_local_vout "
            "FROM old_commitments ORDER BY channel_id, commit_num DESC LIMIT 30")
        data[label]["old_commitments"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT channel_id, COUNT(*) as cnt FROM revocation_secrets GROUP BY channel_id")
        data[label]["revocations_by_channel"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT channel_id, side, next_index FROM nonce_pools ORDER BY channel_id, side")
        data[label]["nonce_pools"] = rows if not err else []
        # Phase 22: new tables
        rows, err = query_db(path,
            "SELECT * FROM tree_nodes ORDER BY factory_id, node_index")
        data[label]["tree_nodes"] = rows if not err else []
        # Wire-messages query: filter out PING/PONG heartbeats and raise the
        # limit.  Without this, an LSP that's been alive a few minutes fills
        # the entire "latest 100" window with PING/PONG (the LSP emits one
        # of each per ~5s heartbeat).  Result: the Ceremonies reconstructed
        # view goes blank because FACTORY_PROPOSE / NONCE_BUNDLE / etc.
        # have fallen off the window, and the Protocol Log shows nothing
        # but heartbeat noise.  Filtering at query time keeps the operationally
        # interesting messages visible.  200-row limit gives headroom for
        # multi-factory deployments without bloating the API payload.
        rows, err = query_db(path,
            "SELECT * FROM wire_messages "
            "WHERE msg_name NOT IN ('PING','PONG') "
            "ORDER BY id DESC LIMIT 200")
        data[label]["wire_messages"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT * FROM ladder_factories ORDER BY factory_id")
        data[label]["ladder_factories"] = rows if not err else []
        # Phase 23: persistence hardening tables
        rows, err = query_db(path,
            "SELECT * FROM dw_counter_state ORDER BY factory_id")
        data[label]["dw_counter_state"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT * FROM departed_clients ORDER BY factory_id, client_idx")
        data[label]["departed_clients"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT * FROM invoice_registry ORDER BY id DESC LIMIT 50")
        data[label]["invoice_registry"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT * FROM htlc_origins ORDER BY id DESC LIMIT 50")
        data[label]["htlc_origins"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT * FROM client_invoices ORDER BY id DESC LIMIT 50")
        data[label]["client_invoices"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT * FROM id_counters ORDER BY name")
        data[label]["id_counters"] = rows if not err else []
        # JIT Channels (Gap #2 hardening)
        rows, err = query_db(path,
            "SELECT jit_channel_id, client_idx, state, funding_txid, "
            "funding_vout, funding_amount, local_amount, remote_amount, "
            "commitment_number, created_at, target_factory_id "
            "FROM jit_channels ORDER BY jit_channel_id")
        data[label]["jit_channels"] = rows if not err else []
        # Broadcast log — TX broadcast history for operators.
        # LIMIT 200: a 16-client force-close broadcasts ~62 tree TXes plus
        # funding + close + sweeps, which the prior LIMIT 50 truncated on
        # the funding-end (so the Events derivation lost the "Factory funded"
        # bookend).  200 matches the wire_messages limit used elsewhere.
        rows, err = query_db(path,
            "SELECT id, txid, source, result, broadcast_time "
            "FROM broadcast_log ORDER BY id DESC LIMIT 200")
        data[label]["broadcast_log"] = rows if not err else []
        # Reorg events (schema v29) — tip regressions detected by the daemon
        # loop / standalone watchtower.  Feeds the Events narrative.
        rows, err = query_db(path,
            "SELECT id, timestamp, old_tip, new_tip, n_entries_reset "
            "FROM reorg_events ORDER BY id DESC LIMIT 50")
        data[label]["reorg_events"] = rows if not err else []
        # Breach detections (schema v29) — counterparty broadcast a revoked
        # commit; watchtower responded (or is about to).  Feeds Events.
        rows, err = query_db(path,
            "SELECT id, timestamp, channel_id, expected_commit_num, "
            "txid_seen, height_seen, response_txid "
            "FROM breach_detections ORDER BY id DESC LIMIT 50")
        data[label]["breach_detections"] = rows if not err else []
        # Signing progress — per-signer nonce/sig collection status
        rows, err = query_db(path,
            "SELECT factory_id, node_index, signer_slot, has_nonce, "
            "has_partial_sig, updated_at "
            "FROM signing_progress ORDER BY factory_id, node_index, signer_slot")
        data[label]["signing_progress"] = rows if not err else []
        # Watchtower pending — penalty TXs in-flight
        rows, err = query_db(path,
            "SELECT txid, anchor_vout, anchor_amount, cycles_in_mempool, bump_count "
            "FROM watchtower_pending ORDER BY bump_count DESC")
        data[label]["watchtower_pending"] = rows if not err else []
        # Old commitment HTLCs — HTLCs attached to old (revoked) commitments.
        # Schema uses htlc_vout/htlc_amount and integer direction (0=offered,
        # 1=received per htlc_direction_t).  Alias to match the live htlcs
        # row shape (htlc_index, amount, string direction) so rPayments and
        # the per-channel rollup can consume both lists uniformly without
        # special-casing the historical table.
        rows, err = query_db(path,
            "SELECT channel_id, commit_num, htlc_vout AS htlc_index, "
            "CASE direction WHEN 0 THEN 'offered' ELSE 'received' END AS direction, "
            "htlc_amount AS amount, payment_hash, cltv_expiry "
            "FROM old_commitment_htlcs ORDER BY channel_id, commit_num DESC LIMIT 50")
        data[label]["old_commitment_htlcs"] = rows if not err else []
        # PR #181 Phase A consumer: count old_commitments rows with persisted
        # penalty TX bytes vs total rows.  Column was added in schema v25
        # (old_commitments.signed_penalty_tx_hex).  If column is missing
        # (pre-#181 LSP), the first query errors and we fall back to
        # total-only — persisted reads 0 which surfaces as "not yet
        # persisted" in the UI.
        rows, err = query_db(path,
            "SELECT COUNT(*) AS total, "
            "COUNT(CASE WHEN signed_penalty_tx_hex IS NOT NULL "
            "  AND length(signed_penalty_tx_hex) > 0 THEN 1 END) AS persisted "
            "FROM old_commitments")
        if err:
            rows, err = query_db(path,
                "SELECT COUNT(*) AS total, 0 AS persisted FROM old_commitments")
        data[label]["old_commitments_coverage"] = (rows[0] if rows else
            {"total": 0, "persisted": 0})
        # PR #181 Phase B consumer: signing_rounds journal summary.  Table
        # was added in schema v26.  Empty (table missing) on pre-#181 LSPs
        # — graceful: row stays as the defaults, UI shows the
        # journal-not-yet-available copy.
        rows, err = query_db(path,
            "SELECT COUNT(*) AS total, "
            "COUNT(CASE WHEN result = 'success' THEN 1 END) AS success, "
            "COUNT(CASE WHEN result = 'timeout' THEN 1 END) AS timeout, "
            "COUNT(CASE WHEN result = 'aborted_crash' THEN 1 END) AS crashed, "
            "COUNT(CASE WHEN completed_at IS NULL THEN 1 END) AS in_flight, "
            "COUNT(DISTINCT ceremony_type) AS types "
            "FROM signing_rounds")
        data[label]["signing_rounds_summary"] = (rows[0] if rows and not err
            else {"total": 0, "success": 0, "timeout": 0, "crashed": 0,
                  "in_flight": 0, "types": 0})
        # Recent signing rounds for the Overview ledger.  Same graceful
        # fallback as the summary.
        rows, err = query_db(path,
            "SELECT id, factory_id, node_idx, ceremony_type, epoch, "
            "started_at, completed_at, n_participants, "
            "nonces_collected, partial_sigs_collected, "
            "result, result_txid, error_detail "
            "FROM signing_rounds ORDER BY started_at DESC LIMIT 20")
        data[label]["signing_rounds_recent"] = rows if not err else []
        # Factory revocation secrets — per-epoch flat revocation
        rows, err = query_db(path,
            "SELECT factory_id, COUNT(*) as cnt "
            "FROM factory_revocation_secrets GROUP BY factory_id")
        data[label]["factory_revocations_by_factory"] = rows if not err else []
        # PS leaf chains (schema v20+): canonical pseudo-Spilman leaf state
        # chains.  Each row is chain[N] for a given (factory_id, leaf_node_idx),
        # with chan_amount_sats decreasing as the LSP sells liquidity into the
        # leaf and poison_tx_hex (v22+) carrying the per-position wire-signed
        # poison TX for the trustless watchtower defense.
        # F2: include epoch column (v24+).  COALESCE handles older DBs where
        # ALTER TABLE may have failed silently and rows lack the field.
        rows, err = query_db(path,
            "SELECT factory_id, leaf_node_idx, chain_pos, txid, "
            "chan_amount_sats, "
            "COALESCE(epoch, 0) AS epoch, "
            "CASE WHEN poison_tx_hex IS NOT NULL AND length(poison_tx_hex)>0 "
            "  THEN 1 ELSE 0 END AS has_poison "
            "FROM ps_leaf_chains "
            "ORDER BY factory_id, leaf_node_idx, chain_pos")
        data[label]["ps_leaf_chains"] = rows if not err else []
        # PS sub-factory chains (schema v21+): k² wide-leaves shape.  Each row
        # carries sales_stock_amount_sats + channel_amounts_csv for the
        # per-sub-factory chain.  Empty when --ps-subfactory-arity=1.
        rows, err = query_db(path,
            "SELECT factory_id, sub_node_idx, chain_pos, txid, "
            "sales_stock_amount_sats, channel_amounts_csv, "
            "COALESCE(epoch, 0) AS epoch, "
            "CASE WHEN poison_tx_hex IS NOT NULL AND length(poison_tx_hex)>0 "
            "  THEN 1 ELSE 0 END AS has_poison "
            "FROM ps_subfactory_chains "
            "ORDER BY factory_id, sub_node_idx, chain_pos")
        data[label]["ps_subfactory_chains"] = rows if not err else []
        # PS chain[0] initial signed states (schema v23+): the chain origin TX
        # for each PS leaf / sub-factory.  Empty rows here when other PS
        # tables are populated indicates the v0.1.15 force-close-fails-with-25
        # bug pattern.
        rows, err = query_db(path,
            "SELECT factory_id, node_idx, txid, "
            "COALESCE(epoch, 0) AS epoch "
            "FROM ps_initial_signed_states "
            "ORDER BY factory_id, node_idx")
        data[label]["ps_initial_signed_states"] = rows if not err else []
        # Client-side PS double-spend defense (schema v20+): one row per
        # (factory_id, parent_txid, parent_vout) the client has co-signed.
        # Aggregate per leaf to keep the dashboard payload small.
        rows, err = query_db(path,
            "SELECT factory_id, leaf_node_idx, COUNT(*) as cnt "
            "FROM client_ps_signed_inputs "
            "GROUP BY factory_id, leaf_node_idx")
        data[label]["ps_signed_inputs_by_leaf"] = rows if not err else []
        # TX preparedness audit feeds — one query per signed-bytes-bearing
        # table so the TX Inventory tab can build a unified "is the defense
        # set ready" view across factory tree, channel commitments,
        # distribution TXs and pending sweeps.
        rows, err = query_db(path,
            "SELECT channel_id, commitment_number, "
            "CASE WHEN signed_tx_hex IS NOT NULL AND length(signed_tx_hex)>0 "
            "  THEN 1 ELSE 0 END AS has_bytes "
            "FROM signed_commitments ORDER BY channel_id")
        data[label]["signed_commitments"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT factory_id, "
            "CASE WHEN signed_tx_hex IS NOT NULL AND length(signed_tx_hex)>0 "
            "  THEN 1 ELSE 0 END AS has_bytes "
            "FROM distribution_txs ORDER BY factory_id")
        data[label]["distribution_txs"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT id, sweep_type, state, source_txid, source_vout, "
            "amount_sats, channel_id, factory_id, sweep_txid, csv_delay, "
            "confirmed_height "
            "FROM pending_sweeps ORDER BY id DESC LIMIT 30")
        data[label]["pending_sweeps"] = rows if not err else []
        # The factories table only carries funding_txid (no bytes); the
        # bytes live in the bitcoind wallet.  Treat "txid present" as the
        # readiness signal for the funding category.
        rows, err = query_db(path,
            "SELECT id, funding_amount, "
            "CASE WHEN funding_txid IS NOT NULL AND length(funding_txid)>0 "
            "  THEN 1 ELSE 0 END AS has_funding_bytes "
            "FROM factories ORDER BY id")
        data[label]["factory_funding_bytes"] = rows if not err else []
        rows, err = query_db(path,
            "SELECT factory_id, node_index, "
            "CASE WHEN signed_tx_hex IS NOT NULL AND length(signed_tx_hex)>0 "
            "  THEN 1 ELSE 0 END AS has_bytes "
            "FROM tree_nodes ORDER BY factory_id, node_index")
        data[label]["tree_nodes_bytes"] = rows if not err else []
        # P1: count PS leaf + sub-factory nodes so we can derive correct
        # chain[0] "expected" denominators.  Persisted schema doesn't carry
        # is_ps_leaf as a direct column; identify via nsequence (PS leaves
        # have nsequence = 0xFFFFFFFE = BIP-68 disabled) and via type
        # column ("ps_subfactory" persisted from NODE_PS_SUBFACTORY).
        rows, err = query_db(path,
            "SELECT factory_id, "
            "SUM(CASE WHEN nsequence = 4294967294 AND type='state' "
            "         THEN 1 ELSE 0 END) AS ps_leaf_count, "
            "SUM(CASE WHEN type LIKE '%subfactory%' "
            "         THEN 1 ELSE 0 END) AS subfactory_count "
            "FROM tree_nodes GROUP BY factory_id")
        data[label]["ps_node_counts"] = rows if not err else []
        # P1: how many channels have had at least one commit exchange?
        # signed_commitments only stores rows once commitment_number > 0;
        # at commit 0 (just opened, no payments) there's nothing to sign.
        rows, err = query_db(path,
            "SELECT factory_id, "
            "SUM(CASE WHEN commitment_number > 0 THEN 1 ELSE 0 END) "
            "  AS channels_with_commits "
            "FROM channels GROUP BY factory_id")
        data[label]["channels_committed"] = rows if not err else []
    return data

def collect_cln(cfg):
    data = {"a": {"available": False}, "b": {"available": False}}
    for label, ldir in [("a", cfg.cln_a_dir), ("b", cfg.cln_b_dir)]:
        if not cfg.cln_cli or not ldir: continue
        for rpc, handler in [
            ("getinfo", lambda o, d=data[label]: d.update(available=True, id=o.get("id","?"),
                alias=o.get("alias",""), blockheight=o.get("blockheight",0),
                num_peers=o.get("num_peers",0), num_channels=o.get("num_active_channels",0),
                version=o.get("version","?"), color=o.get("color","?"),
                fees_collected_msat=o.get("fees_collected_msat",0))),
            ("listpeers", lambda o, d=data[label]: d.update(peers=[{
                "id": p.get("id","?"), "connected": p.get("connected",False),
                "netaddr": p.get("netaddr",[]), "features": p.get("features",""),
            } for p in o.get("peers",[])])),
            ("listpeerchannels", lambda o, d=data[label]: d.update(channels=[{
                "state": c.get("state","?"), "total_msat": c.get("total_msat",0),
                "to_us_msat": c.get("to_us_msat",0), "peer_id": c.get("peer_id","?"),
                "short_channel_id": c.get("short_channel_id","?"),
                "funding_txid": c.get("funding_txid","?"),
                "fee_base_msat": c.get("fee_base_msat",0),
                "fee_proportional_millionths": c.get("fee_proportional_millionths",0),
                "htlcs": c.get("htlcs",[]),
                "to_self_delay": c.get("to_self_delay",0),
                "dust_limit_msat": c.get("dust_limit_msat",0),
                "max_htlc_value_in_flight_msat": c.get("max_htlc_value_in_flight_msat",0),
                "their_reserve_msat": c.get("their_reserve_msat",0),
                "our_reserve_msat": c.get("our_reserve_msat",0),
                "spendable_msat": c.get("spendable_msat",0),
                "receivable_msat": c.get("receivable_msat",0),
            } for c in o.get("channels",[])])),
            ("listforwards", lambda o, d=data[label]: d.update(
                forwards=o.get("forwards",[])[-20:])),
            ("listinvoices", lambda o, d=data[label]: d.update(
                invoices=[{"label":i.get("label",""),"status":i.get("status",""),
                    "amount_msat":i.get("amount_msat",0),"paid_at":i.get("paid_at"),
                    "payment_hash":i.get("payment_hash",""),
                    "bolt11":i.get("bolt11","")[:40]+"..." if i.get("bolt11") else "",
                } for i in o.get("invoices",[])[-20:]])),
        ]:
            out, ok = cln_cmd(cfg, ldir, rpc)
            if ok:
                try: handler(json.loads(out))
                except: pass
    return data

def collect_factory_config(cfg):
    """Parse the LSP process cmdline to extract deployment knobs.
    Returns the live --arity, --ps-subfactory-arity and the rest of the
    economic/lifecycle flags so the Factory tab has an anchor for
    'what shape am I actually looking at'."""
    out = {"available": False}
    try:
        r = subprocess.run(["pgrep", "-f", "superscalar_lsp"],
                           capture_output=True, text=True, timeout=2)
        if r.returncode != 0: return out
        for pid in r.stdout.strip().split("\n"):
            if not pid.strip(): continue
            try:
                with open("/proc/" + pid + "/cmdline", "rb") as f:
                    argv = f.read().decode("utf-8", "replace").split("\x00")
            except (FileNotFoundError, PermissionError, OSError):
                continue
            argv = [a for a in argv if a]
            if cfg.lsp_db and cfg.lsp_db not in argv: continue
            def flag_val(name, default=None):
                if name in argv:
                    i = argv.index(name)
                    if i + 1 < len(argv) and not argv[i+1].startswith("--"):
                        return argv[i+1]
                return default
            def flag_present(name): return name in argv
            out.update({
                "available": True, "pid": int(pid),
                "arity": flag_val("--arity", "3"),
                "ps_subfactory_arity": flag_val("--ps-subfactory-arity", "1"),
                "clients": flag_val("--clients"),
                "amount": flag_val("--amount"),
                "network": flag_val("--network", "regtest" if flag_present("--regtest") else None),
                "port": flag_val("--port"),
                "lsp_balance_pct": flag_val("--lsp-balance-pct", "100"),
                "placement_mode": flag_val("--placement-mode", "sequential"),
                "economic_mode": flag_val("--economic-mode", "lsp-takes-all"),
                "routing_fee_ppm": flag_val("--routing-fee-ppm", "0"),
                "default_profit_bps": flag_val("--default-profit-bps", "0"),
                "active_blocks": flag_val("--active-blocks"),
                "dying_blocks": flag_val("--dying-blocks"),
                "step_blocks": flag_val("--step-blocks", "10"),
                "states_per_layer": flag_val("--states-per-layer", "4"),
                "fee_rate": flag_val("--fee-rate", "1000"),
                "fee_bump_after": flag_val("--fee-bump-after", "6"),
                "fee_bump_max": flag_val("--fee-bump-max", "3"),
                "settlement_interval": flag_val("--settlement-interval", "144"),
                "daemon": flag_present("--daemon"),
                "demo": flag_present("--demo"),
                "cli": flag_present("--cli"),
                "no_jit": flag_present("--no-jit"),
                "onion": flag_present("--onion"),
                "tor_only": flag_present("--tor-only"),
                "i_accept_risk": flag_present("--i-accept-the-risk"),
            })
            return out
    except Exception as e:
        out["error"] = str(e)
    return out

def derive_events(db):
    """Synthesize the narrative Events feed from real lsp.db rows.

    The Events section in rProtocol consumes D.events with shape
    {time:"HH:MM:SS", msg:"..."}.  Without this function, only the
    synthetic --demo collector populates events; production runs render
    an empty section that auto-hides, leaving operators without the
    narrative layer that summarizes broadcast_log / signing_rounds /
    reorg_events / breach_detections.

    Sources are bounded by their own LIMIT clauses in collect_databases,
    so the merged feed is capped at the union.  Ascending order matches
    the renderer's .slice().reverse() (newest at top)."""
    if not db or "lsp" not in db: return []
    lsp = db.get("lsp") or {}
    events = []
    def _push(ts, msg):
        try:
            t = int(ts)
            tstr = time.strftime("%H:%M:%S", time.localtime(t)) if t > 0 else "??:??:??"
        except (ValueError, TypeError):
            t = 0; tstr = "??:??:??"
        events.append({"time": tstr, "msg": msg, "_ts": t})

    # Two-pass over broadcast_log: tree_node_* rows collapse into one summary
    # event ("Force-close: N/M tree nodes confirmed").  Without collapsing, a
    # 16-client force-close produces ~62 tree-node events that crowd out
    # factory_funding / cooperative_close from the 50-event cap.
    tree_total = 0; tree_ok = 0; tree_fail = 0
    tree_first_ts = 0; tree_last_ts = 0
    for row in (lsp.get("broadcast_log") or []):
        if not isinstance(row, dict): continue
        source = row.get("source", "") or ""
        if not source.startswith("tree_node_"): continue
        tree_total += 1
        if (row.get("result") or "ok") == "ok":
            tree_ok += 1
        else:
            tree_fail += 1
        ts = int(row.get("broadcast_time", 0) or 0)
        if ts > 0:
            if tree_first_ts == 0 or ts < tree_first_ts: tree_first_ts = ts
            if ts > tree_last_ts: tree_last_ts = ts
    if tree_total > 0:
        msg = f"Force-close: {tree_ok}/{tree_total} tree nodes confirmed"
        if tree_fail > 0: msg += f" ({tree_fail} failed)"
        _push(tree_last_ts or tree_first_ts, msg)

    for row in (lsp.get("broadcast_log") or []):
        if not isinstance(row, dict): continue
        source = row.get("source", "") or ""
        if source.startswith("tree_node_"): continue  # collapsed above
        txid = (row.get("txid", "") or "")[:16]
        result = row.get("result", "ok") or "ok"
        ts = row.get("broadcast_time", 0)
        tag = "" if result == "ok" else f" [{result}]"
        if source == "factory_funding":
            _push(ts, f"Factory funded ({txid}…){tag}")
        elif source == "cooperative_close":
            _push(ts, f"Cooperative close confirmed ({txid}…){tag}")
        elif source.startswith("penalty"):
            _push(ts, f"Penalty TX broadcast ({txid}…){tag}")
        elif source.startswith("breach_revoked"):
            _push(ts, f"Breach attempt: {source} ({txid}…){tag}")
        elif source.startswith("htlc_"):
            _push(ts, f"HTLC TX: {source} ({txid}…){tag}")
        elif source == "reorg_detected":
            pass  # surfaced via reorg_events with richer detail
        elif source:
            _push(ts, f"Broadcast: {source} ({txid}…){tag}")

    for row in (lsp.get("signing_rounds_recent") or []):
        if not isinstance(row, dict): continue
        ctype = row.get("ceremony_type", "?") or "?"
        result = row.get("result", "") or ""
        n_part = row.get("n_participants", 0)
        started = row.get("started_at", 0) or 0
        completed = row.get("completed_at", started) or started
        try:
            duration = max(0, int(completed) - int(started))
        except (ValueError, TypeError):
            duration = 0
        if result == "success":
            _push(completed, f"{ctype}: {n_part} signers, {duration}s")
        else:
            tag = result.upper() if result else "ABORTED"
            _push(completed or started, f"{ctype} {tag}: {n_part} signers")

    for row in (lsp.get("reorg_events") or []):
        if not isinstance(row, dict): continue
        ts = row.get("timestamp", 0)
        old_tip = row.get("old_tip", 0) or 0
        new_tip = row.get("new_tip", 0) or 0
        depth = abs(old_tip - new_tip)
        n_reset = row.get("n_entries_reset", 0)
        _push(ts, f"Reorg: tip {old_tip}→{new_tip} (depth {depth}), {n_reset} entries reset")

    for row in (lsp.get("breach_detections") or []):
        if not isinstance(row, dict): continue
        ts = row.get("timestamp", 0)
        cid = row.get("channel_id", "?")
        commit = row.get("expected_commit_num", "?")
        resp = (row.get("response_txid", "") or "")
        resp_str = f"penalty {resp[:16]}…" if resp else "pending"
        _push(ts, f"Breach detected on channel {cid} (commit {commit}); {resp_str}")

    # State-mismatch detector: surface a warning event when factories.state
    # claims "active" but broadcast_log shows terminal-close activity
    # (cooperative_close, tree_node_*, force_close_*).  Today the LSP-side
    # state machine doesn't bump factories.state on close, so an operator
    # reading the Factory tab sees stale "active" with no indication that
    # the factory has been swept on-chain.  This emits a single forensic
    # event so the mismatch is visible until the LSP fixes the column.
    facs = lsp.get("factories") or []
    bl = lsp.get("broadcast_log") or []
    has_terminal = any(
        (r.get("source") or "").startswith(("cooperative_close", "tree_node_",
                                              "force_close", "penalty"))
        and (r.get("result") or "ok") == "ok"
        for r in bl if isinstance(r, dict)
    )
    if facs and has_terminal:
        active_facs = [f for f in facs if isinstance(f, dict)
                       and (f.get("state") or "").lower() == "active"]
        for f in active_facs:
            ts = max((int(r.get("broadcast_time", 0) or 0) for r in bl
                      if isinstance(r, dict)), default=0)
            _push(ts, f"⚠ Factory {f.get('id', '?')} state=active but on-chain close detected (LSP state-machine gap)")

    events.sort(key=lambda e: e.get("_ts", 0))
    for e in events: e.pop("_ts", None)
    return events[-50:]

def _db_freshness(cfg):
    """Sample mtime + ISO timestamp of lsp.db and client.db so the UI can
    detect a stale browser fetch (operator looks at the page after a wipe
    + restart, sees old data, doesn't realize the tab cached an earlier
    /api/status response).  Times are unix seconds; renderer can compute
    'now - api_ts' to flag staleness."""
    out = {"api_ts": int(time.time()),
           "api_time": time.strftime("%H:%M:%S")}
    for label, path in (("lsp_db_mtime", cfg.lsp_db),
                         ("client_db_mtime", cfg.client_db)):
        try:
            if path and os.path.exists(str(path)):
                out[label] = int(os.path.getmtime(str(path)))
            else:
                out[label] = 0
        except OSError:
            out[label] = 0
    return out

def collect_all(cfg):
    if cfg.demo: return collect_demo()
    db = collect_databases(cfg)
    return {"timestamp": time.strftime("%H:%M:%S"),
        "freshness": _db_freshness(cfg),
        "processes": collect_processes(cfg), "bitcoin": collect_bitcoin(cfg),
        "databases": db, "cln": collect_cln(cfg),
        "factory_config": collect_factory_config(cfg),
        "wallet_utxos": collect_wallet_utxos(cfg),
        "tx_enrichment": collect_tx_enrichment(cfg, _extract_txids(db)),
        "events": derive_events(db)}

# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------

_dc = [0]; _de = []
def _rh(n): return ''.join(random.choice('0123456789abcdef') for _ in range(n))
def _ev(m): _de.append({"time":time.strftime("%H:%M:%S"),"msg":m}); _de[:] = _de[-25:]

def collect_demo():
    t=time.time(); h=234567+int(t/60)%100; _dc[0]+=1; c=_dc[0]
    if c%3==0: _ev(f"CH{random.randint(0,3)} HTLC#{c} fulfilled {random.choice([1000,2500,5000])} sats")
    if c%5==0: _ev(f"Commitment signed: CH{random.randint(0,3)} commit #{random.randint(2,12)}")
    if c%7==0: _ev(f"Revocation received: CH{random.randint(0,3)} secret #{random.randint(1,10)}")
    if c%11==0: _ev(f"Watchtower stored old commitment for CH{random.randint(0,3)}")
    if c%13==0: _ev(f"Nonce pool replenished: CH{random.randint(0,3)} +16 nonces")
    if c%17==0: _ev(f"Bridge: inbound HTLC from CLN, hash={_rh(8)}...")
    if c%19==0: _ev(f"Forward: {random.randint(100,5000)} msat via {_rh(8)}...")
    if c%23==0: _ev(f"PTLC presig sent to Client {random.randint(1,4)}")
    if c%29==0: _ev(f"PTLC adapted sig received, key extracted for Client {random.randint(1,4)}")
    ft=_rh(64); cb=h-500; ct=cb+1008; db_=cb+4320; spl=4; nl=2; te=spl**nl; ce=7
    parts=[{"factory_id":0,"slot":i,"pubkey":("02"if i%2==0 else"03")+_rh(64)} for i in range(5)]
    node_a_id = "02a1b2c3d4e5f678" + _rh(48)
    node_b_id = "03f9e8d7c6b5a493" + _rh(48)
    _DEMO_DATA = {
        "timestamp": time.strftime("%H:%M:%S"), "demo": True,
        "processes": {k:True for k in ["bitcoind","cln_a","cln_b","bridge","lsp","client"]},
        "bitcoin": {"available":True,"chain":"signet","blocks":h,"headers":h,"ibd":False,
            "verification":1.0,"peers":8,"balance":0.04923145,"mempool_size":3},
        "databases": {
            "lsp": {
                "factories": [{"id":0,"n_participants":5,"funding_txid":ft,"funding_vout":0,
                    "funding_amount":200000,"step_blocks":144,"states_per_layer":spl,
                    "cltv_timeout":ct,"fee_per_tx":354,"state":"active","created_at":int(t)-3600}],
                "participants": parts,
                "channels": [
                    {"id":0,"factory_id":0,"slot":0,"local_amount":24500,"remote_amount":24500,"funding_amount":50000,"commitment_number":3,"funding_txid":_rh(64),"funding_vout":0,"state":"open"},
                    {"id":1,"factory_id":0,"slot":1,"local_amount":26000,"remote_amount":23000,"funding_amount":50000,"commitment_number":7,"funding_txid":_rh(64),"funding_vout":1,"state":"open"},
                    {"id":2,"factory_id":0,"slot":2,"local_amount":18200,"remote_amount":30800,"funding_amount":50000,"commitment_number":2,"funding_txid":_rh(64),"funding_vout":2,"state":"open"},
                    {"id":3,"factory_id":0,"slot":3,"local_amount":31300,"remote_amount":17700,"funding_amount":50000,"commitment_number":5,"funding_txid":_rh(64),"funding_vout":3,"state":"open"},
                ],
                "htlcs": [
                    {"id":1,"channel_id":1,"htlc_id":5,"direction":"offered","amount":1000,"payment_hash":_rh(64),"payment_preimage":_rh(64),"cltv_expiry":h+40,"state":"fulfilled"},
                    {"id":2,"channel_id":0,"htlc_id":3,"direction":"received","amount":2500,"payment_hash":_rh(64),"payment_preimage":_rh(64),"cltv_expiry":h+35,"state":"fulfilled"},
                    {"id":3,"channel_id":2,"htlc_id":1,"direction":"offered","amount":5000,"payment_hash":_rh(64),"payment_preimage":None,"cltv_expiry":h+144,"state":"active"},
                    {"id":4,"channel_id":3,"htlc_id":2,"direction":"received","amount":800,"payment_hash":_rh(64),"payment_preimage":None,"cltv_expiry":h+72,"state":"active"},
                ],
                "watchtower_count":12,"revocation_count":17,
                "revocations_by_channel":[{"channel_id":i,"cnt":[3,7,2,5][i]} for i in range(4)],
                "nonce_pools":[{"channel_id":i//2,"side":["local","remote"][i%2],"next_index":[6,5,14,13,4,3,10,9][i]} for i in range(8)],
                "old_commitments":[{"channel_id":i,"commit_num":j,"txid":_rh(64),"to_local_amount":20000+i*2000+j*500,"to_local_vout":0} for i in range(4) for j in range(3 if i!=2 else 1)],
                "tree_nodes":[
                    {"factory_id":0,"node_index":0,"type":"kickoff","parent_index":-1,"parent_vout":0,"dw_layer_index":-1,"n_signers":5,"signer_indices":"0,1,2,3,4","n_outputs":1,"output_amounts":"199646","nsequence":4294967295,"input_amount":200000,"txid":_rh(64),"is_built":1,"is_signed":1,"spending_spk":"5120"+_rh(64)},
                    {"factory_id":0,"node_index":1,"type":"state","parent_index":0,"parent_vout":0,"dw_layer_index":0,"n_signers":5,"signer_indices":"0,1,2,3,4","n_outputs":2,"output_amounts":"99646,99646","nsequence":10,"input_amount":199646,"txid":_rh(64),"is_built":1,"is_signed":1,"spending_spk":"5120"+_rh(64)},
                    {"factory_id":0,"node_index":2,"type":"kickoff","parent_index":1,"parent_vout":0,"dw_layer_index":-1,"n_signers":3,"signer_indices":"0,1,2","n_outputs":1,"output_amounts":"99292","nsequence":4294967295,"input_amount":99646,"txid":_rh(64),"is_built":1,"is_signed":1,"spending_spk":"5120"+_rh(64)},
                    {"factory_id":0,"node_index":3,"type":"kickoff","parent_index":1,"parent_vout":1,"dw_layer_index":-1,"n_signers":3,"signer_indices":"0,3,4","n_outputs":1,"output_amounts":"99292","nsequence":4294967295,"input_amount":99646,"txid":_rh(64),"is_built":1,"is_signed":1,"spending_spk":"5120"+_rh(64)},
                    {"factory_id":0,"node_index":4,"type":"state","parent_index":2,"parent_vout":0,"dw_layer_index":1,"n_signers":3,"signer_indices":"0,1,2","n_outputs":2,"output_amounts":"49292,49646","nsequence":40,"input_amount":99292,"txid":_rh(64),"is_built":1,"is_signed":1,"spending_spk":"5120"+_rh(64)},
                    {"factory_id":0,"node_index":5,"type":"state","parent_index":3,"parent_vout":0,"dw_layer_index":1,"n_signers":3,"signer_indices":"0,3,4","n_outputs":2,"output_amounts":"49292,49646","nsequence":40,"input_amount":99292,"txid":_rh(64),"is_built":1,"is_signed":1,"spending_spk":"5120"+_rh(64)},
                ],
                "wire_messages":[
                    {"id":i+1,"timestamp":int(t)-300+i*10,"direction":"recv" if i%2==0 else "sent",
                     "msg_type":[0x01,0x02,0x10,0x11,0x12,0x13,0x14,0x30,0x31,0x32,0x33,0x34,0x32,0x33,0x31,0x32,0x33,0x34,0x32,0x33,0x38,0x40,0x41,0x42,0x43,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0xFF][i%33],
                     "msg_name":["HELLO","HELLO_ACK","FACTORY_PROPOSE","NONCE_BUNDLE","ALL_NONCES","PSIG_BUNDLE","FACTORY_READY","CHANNEL_READY","UPDATE_ADD_HTLC","COMMITMENT_SIGNED","REVOKE_AND_ACK","UPDATE_FULFILL_HTLC","COMMITMENT_SIGNED","REVOKE_AND_ACK","UPDATE_ADD_HTLC","COMMITMENT_SIGNED","REVOKE_AND_ACK","UPDATE_FULFILL_HTLC","COMMITMENT_SIGNED","REVOKE_AND_ACK","REGISTER_INVOICE","BRIDGE_HELLO","BRIDGE_HELLO_ACK","BRIDGE_ADD_HTLC","BRIDGE_FULFILL_HTLC","RECONNECT","RECONNECT_ACK","CREATE_INVOICE","INVOICE_CREATED","PTLC_PRESIG","PTLC_ADAPTED_SIG","PTLC_COMPLETE","ERROR"][i%33],
                     "peer":["client_0","client_0","client_0","client_1","client_2","client_3","client_0","client_1","client_2","client_3","client_0","client_1","client_2","client_3","bridge","client_0"][i%16],
                     "payload_summary":'{"example":"data_'+str(i)+'"}'}
                    for i in range(25)
                ],
                "ladder_factories":[
                    {"factory_id":0,"state":"active","is_funded":1,"is_initialized":1,"n_departed":0,"created_block":cb,"active_blocks":4320,"dying_blocks":432,"updated_at":int(t)-60},
                    {"factory_id":1,"state":"dying","is_funded":1,"is_initialized":1,"n_departed":2,"created_block":cb-4000,"active_blocks":4320,"dying_blocks":432,"updated_at":int(t)-30},
                ],
                # Phase 23
                "dw_counter_state":[{"factory_id":0,"current_epoch":7,"n_layers":2,"layer_states":"3,1"}],
                "departed_clients":[
                    {"factory_id":1,"client_idx":2,"extracted_key":_rh(64),"departed_at":int(t)-1800},
                    {"factory_id":1,"client_idx":3,"extracted_key":_rh(64),"departed_at":int(t)-900},
                ],
                "invoice_registry":[
                    {"id":1,"payment_hash":_rh(64),"dest_client":0,"amount_msat":10000,"bridge_htlc_id":0,"active":1,"created_at":int(t)-600},
                    {"id":2,"payment_hash":_rh(64),"dest_client":2,"amount_msat":25000,"bridge_htlc_id":5,"active":1,"created_at":int(t)-300},
                    {"id":3,"payment_hash":_rh(64),"dest_client":1,"amount_msat":5000,"bridge_htlc_id":0,"active":0,"created_at":int(t)-1200},
                ],
                "htlc_origins":[
                    {"id":1,"payment_hash":_rh(64),"bridge_htlc_id":5,"request_id":0,"sender_idx":0,"sender_htlc_id":0,"active":1,"created_at":int(t)-300},
                    {"id":2,"payment_hash":_rh(64),"bridge_htlc_id":0,"request_id":3,"sender_idx":1,"sender_htlc_id":2,"active":0,"created_at":int(t)-600},
                ],
                "client_invoices":[
                    {"id":1,"payment_hash":_rh(64),"preimage":_rh(64),"amount_msat":10000,"active":1,"created_at":int(t)-500},
                    {"id":2,"payment_hash":_rh(64),"preimage":_rh(64),"amount_msat":5000,"active":0,"created_at":int(t)-1000},
                ],
                "id_counters":[
                    {"name":"next_request_id","value":4},
                    {"name":"next_htlc_id","value":12},
                ],
                "broadcast_log":[
                    {"id":1,"txid":_rh(64),"source":"factory_funding","result":"success","broadcast_time":int(t)-3600},
                    {"id":2,"txid":_rh(64),"source":"penalty_tx","result":"success","broadcast_time":int(t)-1800},
                    {"id":3,"txid":_rh(64),"source":"state_update","result":"mempool_conflict","broadcast_time":int(t)-300},
                ],
                "signing_progress":[
                    {"factory_id":0,"node_index":0,"signer_slot":i,"has_nonce":1,"has_partial_sig":1,"updated_at":int(t)-60}
                    for i in range(5)
                ]+[
                    {"factory_id":0,"node_index":1,"signer_slot":i,"has_nonce":1,"has_partial_sig":int(i<3),"updated_at":int(t)-30}
                    for i in range(5)
                ],
                "watchtower_pending":[
                    {"txid":_rh(64),"anchor_vout":0,"anchor_amount":330,"cycles_in_mempool":2,"bump_count":1},
                ],
                "old_commitment_htlcs":[
                    {"channel_id":1,"commit_num":5,"htlc_index":0,"direction":"offered","amount":1000,"payment_hash":_rh(64),"cltv_expiry":h+40},
                    {"channel_id":1,"commit_num":5,"htlc_index":1,"direction":"received","amount":2500,"payment_hash":_rh(64),"cltv_expiry":h+35},
                ],
                "factory_revocations_by_factory":[{"factory_id":0,"cnt":6}],
            },
            "client": {
                "factories":[{"id":0,"n_participants":5,"funding_txid":ft,"funding_vout":0,"funding_amount":200000,"step_blocks":144,"states_per_layer":spl,"cltv_timeout":ct,"fee_per_tx":354,"state":"active","created_at":int(t)-3600}],
                "participants":[parts[0],parts[1]],
                "channels":[{"id":0,"factory_id":0,"slot":0,"local_amount":24500,"remote_amount":24500,"funding_amount":50000,"commitment_number":3,"funding_txid":_rh(64),"funding_vout":0,"state":"open"}],
                "htlcs":[],"watchtower_count":3,"revocation_count":3,
                "revocations_by_channel":[{"channel_id":0,"cnt":3}],
                "nonce_pools":[{"channel_id":0,"side":"local","next_index":6},{"channel_id":0,"side":"remote","next_index":5}],
                "old_commitments":[{"channel_id":0,"commit_num":i,"txid":_rh(64),"to_local_amount":24500,"to_local_vout":0} for i in range(3)],
                "tree_nodes":[],"wire_messages":[],"ladder_factories":[],
                "dw_counter_state":[],"departed_clients":[],"invoice_registry":[],
                "htlc_origins":[],"client_invoices":[
                    {"id":1,"payment_hash":_rh(64),"preimage":_rh(64),"amount_msat":10000,"active":1,"created_at":int(t)-500},
                ],"id_counters":[],
                "broadcast_log":[],"signing_progress":[],"watchtower_pending":[],
                "old_commitment_htlcs":[],"factory_revocations_by_factory":[],
            },
        },
        "cln": {
            "a": {
                "available":True,"id":node_a_id,"alias":"SUPERSCALAR-A","blockheight":h,
                "num_peers":2,"num_channels":1,"version":"v24.11","color":"02a1b2",
                "fees_collected_msat":12500,
                "peers":[
                    {"id":node_b_id,"connected":True,"netaddr":["127.0.0.1:9737"],"features":""},
                    {"id":"04"+_rh(64),"connected":True,"netaddr":["44.55.66.77:9735"],"features":""},
                ],
                "channels":[{
                    "state":"CHANNELD_NORMAL","total_msat":500000000,"to_us_msat":400000000,
                    "peer_id":node_b_id,"short_channel_id":f"{h-100}x1x0","funding_txid":_rh(64),
                    "fee_base_msat":1000,"fee_proportional_millionths":100,"htlcs":[],
                    "to_self_delay":144,"dust_limit_msat":546000,
                    "max_htlc_value_in_flight_msat":495000000,
                    "their_reserve_msat":5000000,"our_reserve_msat":5000000,
                    "spendable_msat":390000000,"receivable_msat":95000000,
                }],
                "forwards":[
                    {"in_channel":f"{h-100}x1x0","out_channel":"factory","in_msat":1100,"out_msat":1000,"fee_msat":100,"status":"settled","received_time":t-300},
                    {"in_channel":"factory","out_channel":f"{h-100}x1x0","in_msat":2600,"out_msat":2500,"fee_msat":100,"status":"settled","received_time":t-120},
                    {"in_channel":f"{h-100}x1x0","out_channel":"factory","in_msat":5100,"out_msat":5000,"fee_msat":100,"status":"offered","received_time":t-10},
                ],
                "invoices":[
                    {"label":"test_1","status":"paid","amount_msat":10000,"paid_at":int(t)-600,"payment_hash":_rh(64),"bolt11":"lnsb10u1pj"+_rh(30)+"..."},
                    {"label":"test_2","status":"paid","amount_msat":25000,"paid_at":int(t)-180,"payment_hash":_rh(64),"bolt11":"lnsb250u1pj"+_rh(29)+"..."},
                    {"label":"test_3","status":"unpaid","amount_msat":50000,"paid_at":None,"payment_hash":_rh(64),"bolt11":"lnsb500u1pj"+_rh(29)+"..."},
                ],
            },
            "b": {
                "available":True,"id":node_b_id,"alias":"SUPERSCALAR-B","blockheight":h,
                "num_peers":1,"num_channels":1,"version":"v24.11","color":"03f9e8",
                "fees_collected_msat":5000,
                "peers":[
                    {"id":node_a_id,"connected":True,"netaddr":["127.0.0.1:9738"],"features":""},
                ],
                "channels":[{
                    "state":"CHANNELD_NORMAL","total_msat":500000000,"to_us_msat":100000000,
                    "peer_id":node_a_id,"short_channel_id":f"{h-100}x1x0","funding_txid":_rh(64),
                    "fee_base_msat":1000,"fee_proportional_millionths":100,"htlcs":[],
                    "to_self_delay":144,"dust_limit_msat":546000,
                    "max_htlc_value_in_flight_msat":495000000,
                    "their_reserve_msat":5000000,"our_reserve_msat":5000000,
                    "spendable_msat":90000000,"receivable_msat":390000000,
                }],
                "forwards":[],"invoices":[
                    {"label":"recv_1","status":"paid","amount_msat":1000,"paid_at":int(t)-300,"payment_hash":_rh(64),"bolt11":"lnsb1u1pj"+_rh(31)+"..."},
                ],
            },
        },
        "factory_protocol": {
            "phases":["PROPOSE","NONCES","PSIGS","READY"],"current_phase_idx":3,
            "nonces_collected":5,"nonces_needed":5,"psigs_collected":5,"psigs_needed":5,
            "tree_nodes":7,"signed_nodes":7,
        },
        "dw_state": {
            "n_layers":nl,"states_per_layer":spl,"total_epochs":te,"current_epoch":ce,
            "layers":[{"index":0,"current_state":ce%spl,"max_states":spl,"step_blocks":144},
                      {"index":1,"current_state":ce//spl,"max_states":spl,"step_blocks":144*spl}],
            "created_block":cb,"cltv_timeout":ct,"dying_block":db_,"current_block":h,
        },
        "bridge":{"lsp_connected":True,"plugin_connected":True,"pending_inbound":1,"next_htlc_id":42,"next_request_id":17},
        "events": list(_de),
        # Phase 1 #8: synthetic data for the new panels added since the
        # original collect_demo() was written.  Without these, --demo mode
        # would render empty Factory Config / PS Leaf Chains / TX
        # Inventory / Outcomes panels.
        "factory_config": {
            "available": True, "pid": 12345,
            "arity": "3", "ps_subfactory_arity": "2",
            "clients": "4", "amount": "200000",
            "network": "regtest", "port": "29735",
            "lsp_balance_pct": "100",
            "placement_mode": "sequential",
            "economic_mode": "lsp-takes-all",
            "routing_fee_ppm": "0",
            "default_profit_bps": "0",
            "active_blocks": "20", "dying_blocks": "10",
            "step_blocks": "10", "states_per_layer": "4",
            "fee_rate": "1000",
            "fee_bump_after": "6", "fee_bump_max": "3",
            "settlement_interval": "144",
            "daemon": True, "demo": True, "cli": False,
            "no_jit": False, "onion": False, "tor_only": False,
            "i_accept_risk": False,
        },
        "tx_enrichment": {
            ft: {"confirmations": 12, "vsize": 165, "in_mempool": False, "never_seen": False, "last_check": int(t)},
        },
    }
    # Inject the PS-era + TX-inventory tables into the demo lsp/client
    # views so the new panels render against representative data.
    _d_lsp = _DEMO_DATA["databases"]["lsp"]
    _d_cl = _DEMO_DATA["databases"]["client"]
    _d_lsp["ps_leaf_chains"] = [
        {"factory_id":0, "leaf_node_idx":4, "chain_pos":1, "txid":_rh(64), "chan_amount_sats":13000, "has_poison":1},
        {"factory_id":0, "leaf_node_idx":4, "chain_pos":2, "txid":_rh(64), "chan_amount_sats":15000, "has_poison":1},
    ]
    _d_lsp["ps_subfactory_chains"] = [
        {"factory_id":0, "sub_node_idx":2, "chain_pos":1, "txid":_rh(64),
         "sales_stock_amount_sats":11911, "channel_amounts_csv":"32111,22111", "has_poison":1},
    ]
    _d_lsp["ps_initial_signed_states"] = [
        {"factory_id":0, "node_idx":i, "txid":_rh(64)} for i in [4,5,6]
    ]
    _d_lsp["ps_signed_inputs_by_leaf"] = [
        {"factory_id":0, "leaf_node_idx":4, "cnt":2},
    ]
    _d_lsp["signed_commitments"] = []
    _d_lsp["distribution_txs"] = []
    _d_lsp["pending_sweeps"] = []
    _d_lsp["factory_funding_bytes"] = [{"id":0, "funding_amount":200000, "has_funding_bytes":1}]
    _d_lsp["tree_nodes_bytes"] = [
        {"factory_id":0, "node_index":i, "has_bytes":1} for i in range(7)
    ]
    _d_lsp["ps_node_counts"] = [
        {"factory_id":0, "ps_leaf_count":1, "subfactory_count":2},
    ]
    _d_lsp["channels_committed"] = [
        {"factory_id":0, "channels_with_commits":4},
    ]
    _d_cl["distribution_txs"] = [
        {"factory_id":0, "has_bytes":1},
    ]
    _d_cl["signed_commitments"] = [
        {"channel_id":0, "commitment_number":3, "has_bytes":1},
    ]
    return _DEMO_DATA

# ---------------------------------------------------------------------------
# HTML Template (tabbed)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SuperScalar Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:'Cascadia Code','Fira Code','JetBrains Mono','Consolas',monospace;font-size:13px;padding:0;line-height:1.5}
.wrap{max-width:1300px;margin:0 auto;padding:12px 16px}
a{color:#58a6ff;text-decoration:none}
.hdr{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #30363d;padding-bottom:10px;margin-bottom:0}
.hdr h1{font-size:18px;color:#58a6ff;font-weight:600}
.hdr .sub{font-size:10px;color:#484f58;margin-left:6px;font-weight:400}
.hdr .tm{color:#8b949e;display:flex;align-items:center;gap:8px;font-size:12px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%}
.dot.g{background:#3fb950;box-shadow:0 0 6px #3fb95088}
.dot.r{background:#f85149;box-shadow:0 0 6px #f8514988}
.dot.y{background:#d29922;box-shadow:0 0 6px #d2992288}
.demo{background:#1a1040;border:1px solid #6e40c9;border-radius:6px;padding:5px 16px;margin:8px 0;color:#d2a8ff;font-size:11px;text-align:center}
/* Tabs */
.tabs{display:flex;flex-wrap:wrap;gap:2px;border-bottom:2px solid #21262d;margin:10px 0 12px 0}
.tab{padding:7px 16px;cursor:pointer;color:#8b949e;font-size:12px;font-weight:600;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap;transition:color .15s}
.tab:hover{color:#c9d1d9}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.tab .badge-count{background:#30363d;color:#8b949e;padding:0 6px;border-radius:10px;font-size:10px;margin-left:4px}
.tab.active .badge-count{background:#0c2d6b;color:#58a6ff}
.tp{display:none}.tp.show{display:block}
/* Cards */
.s{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin-bottom:10px}
.st{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;display:flex;justify-content:space-between}
.st .c{color:#58a6ff}
.kv{display:flex;flex-wrap:wrap;gap:6px 18px}
.ki{display:flex;align-items:center;gap:5px}
.ki .k{color:#484f58;font-size:11px}.ki .v{color:#c9d1d9;font-weight:600}
.b{display:inline-block;padding:1px 8px;border-radius:12px;font-size:11px;font-weight:600}
.b.ok{background:#238636;color:#3fb950}.b.dn{background:#490202;color:#f85149}
.b.w{background:#3d2e00;color:#d29922}.b.i{background:#0c2d6b;color:#58a6ff}
.b.done{background:#1a4023;color:#56d364}
table{width:100%;border-collapse:collapse;margin-top:4px}
th{color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;text-align:left;padding:5px 8px;border-bottom:1px solid #30363d;font-weight:600}
td{padding:4px 8px;border-bottom:1px solid #21262d;font-size:12px}
tr:hover td{background:#1c2128}
.r{text-align:right;font-variant-numeric:tabular-nums}
.h{color:#79c0ff;font-size:11px;word-break:break-all}
.pk{color:#d2a8ff;font-size:10px;word-break:break-all}
.er{color:#f85149;font-style:italic}
.mu{color:#484f58;font-style:italic}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:900px){.g2{grid-template-columns:1fr}}
.pt{background:#21262d;border-radius:3px;height:6px;overflow:hidden}
.pf{height:100%;border-radius:3px;transition:width .5s}
.pf.pg{background:#3fb950}.pf.po{background:#f0883e}.pf.pb{background:#58a6ff}
.b4{display:flex;height:4px;border-radius:2px;overflow:hidden;margin-top:2px}
.b4 .l{background:#3fb950}.b4 .rm{background:#f0883e}
.pr{display:flex;gap:4px;align-items:center;margin:6px 0}
.ps{padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600}
.ps.done{background:#238636;color:#3fb950}.ps.pend{background:#21262d;color:#484f58}
.pa{color:#30363d;font-size:10px}
.lr{display:flex;gap:2px;margin:2px 0;align-items:center}
.lc{width:18px;height:18px;border-radius:2px;display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:700}
.lc.u{background:#238636;color:#3fb950}.lc.cu{background:#0c2d6b;color:#58a6ff;border:1px solid #58a6ff}.lc.av{background:#21262d;color:#484f58}
.ll{color:#484f58;font-size:10px;width:55px}
.el{max-height:200px;overflow-y:auto}
.ew{display:flex;gap:10px;padding:1px 0;font-size:11px}
.et{color:#484f58;flex-shrink:0}.em{color:#8b949e}
.conn{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:4px}
.conn.on{background:#3fb950}.conn.off{background:#f85149}
</style></head><body>
<div class="wrap">
<div class="hdr">
 <h1>SuperScalar Dashboard<span class="sub">DW Factories + Timeout-Sig-Trees + Laddering</span></h1>
 <div class="tm"><span id="stale" title="data staleness: server payload age" style="display:none;background:#bb800922;color:#d29922;border:1px solid #bb800966;padding:1px 6px;border-radius:3px;font-size:10px;margin-right:6px">—</span><span id="poison" title="trustless poison-TX coverage across PS chain entries" style="display:none">—</span><button id="exp" onclick="exportSnapshot()" title="download current dashboard state as JSON for incident sharing" style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:3px 10px;border-radius:4px;font-size:11px;cursor:pointer;margin-right:4px">⇩ snapshot</button><span id="ts">--:--:--</span><span id="dot" class="dot r"></span></div>
</div>
<div id="dm" class="demo" style="display:none">DEMO MODE — simulated data for UI preview</div>
<div class="tabs" id="tabs">
 <div class="tab active" data-t="overview">Overview</div>
 <div class="tab" data-t="factory">Factory</div>
 <div class="tab" data-t="channels">Channels & HTLCs</div>
 <div class="tab" data-t="payments">Payments</div>
 <div class="tab" data-t="protocol">Protocol Log</div>
 <div class="tab" data-t="ceremonies">Ceremonies</div>
 <div class="tab" data-t="lightning">Lightning Network</div>
 <div class="tab" data-t="watchtower">Watchtower</div>
 <div class="tab" data-t="defense">Defense Status</div>
 <div class="tab" data-t="txinv">TX Inventory</div>
 <div class="tab" data-t="outcomes">Outcomes</div>
</div>
<div id="content"></div>
</div>

<script>
const R=5000;let curTab='overview';
// Polish PR: module-scope state for cross-render filter/UI persistence.
//   pf*    — Protocol-log filter inputs (item 1)
//   facSel — Per-factory isolation selector (item 4)
//   _D     — Last full API payload, exposed for the export button (item 5)
//   _hist  — Rolling-window samples for the sparklines (item 2)
let pfMsg='', pfDir='all', pfPeer='';
let facSel='all';
let _D=null;
let _hist={sigStates:[],wtEntries:[],htlcCount:[],fwdActive:[]};
const _HIST_MAX=60; // ~5 minutes at the 5s refresh tick
document.getElementById('tabs').addEventListener('click',e=>{
    const t=e.target.closest('.tab'); if(!t)return;
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
    t.classList.add('active'); curTab=t.dataset.t;
    document.querySelectorAll('.tp').forEach(x=>x.classList.toggle('show',x.id==='t-'+curTab));
});
// Polish item 1 helper: filter wire-message rows in-place (no re-render needed
// — preserves keyboard focus on the input).  Reads current values from the
// DOM, mirrors them back into pf* so the next auto-refresh restores them.
function applyProtoFilter(){
 const me=document.getElementById('pf-msg'), de=document.getElementById('pf-dir'), pe=document.getElementById('pf-peer');
 if(me)pfMsg=me.value; if(de)pfDir=de.value; if(pe)pfPeer=pe.value;
 const rows=document.querySelectorAll('#proto-rows tr[data-msg]');
 const mU=pfMsg.toUpperCase(), pL=pfPeer.toLowerCase();
 let shown=0;
 rows.forEach(r=>{
  const name=(r.dataset.msg||'').toUpperCase();
  const dir=r.dataset.dir||'';
  const peer=(r.dataset.peer||'').toLowerCase();
  const hide=(pfMsg && !name.includes(mU)) ||
             (pfDir!=='all' && dir!==pfDir) ||
             (pfPeer && !peer.includes(pL));
  r.style.display=hide?'none':'';
  if(!hide)shown++;
 });
 const cnt=document.getElementById('proto-cnt');
 if(cnt)cnt.textContent=rows.length===shown?`${rows.length}`:`${shown} of ${rows.length}`;
}
// Polish item 5 helper: download the current API payload as JSON for
// incident response — operator pastes it to another operator or attaches it
// to a ticket.  Uses the cached _D rather than re-fetching so the snapshot
// matches what's currently on screen.
function exportSnapshot(){
 if(!_D){alert('no data yet');return;}
 const ts=new Date().toISOString().replace(/[:.]/g,'-');
 const blob=new Blob([JSON.stringify(_D,null,2)],{type:'application/json'});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a'); a.href=url; a.download=`superscalar-snapshot-${ts}.json`;
 document.body.appendChild(a); a.click(); a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
// Polish item 2 helper: render a tiny inline sparkline from a numeric array.
// Pure SVG, no library — values normalized to the series' own min/max.
function spark(vals,w,hgt,col){
 if(!vals||vals.length<2)return '';
 w=w||80; hgt=hgt||18; col=col||'#58a6ff';
 const mn=Math.min.apply(null,vals), mx=Math.max.apply(null,vals);
 const range=mx-mn||1;
 const pts=vals.map((v,i)=>{
  const x=(i/(vals.length-1))*w;
  const y=hgt-((v-mn)/range)*(hgt-2)-1;
  return `${x.toFixed(1)},${y.toFixed(1)}`;
 }).join(' ');
 return `<svg width="${w}" height="${hgt}" style="vertical-align:middle"><polyline fill="none" stroke="${col}" stroke-width="1.2" points="${pts}"/></svg>`;
}
// Polish item 2: feed the rolling history buffers from a fresh payload.
function pushHistory(D){
 const lsp=(D.databases||{}).lsp||{};
 const tn=lsp.tree_nodes||[];
 const sigStates=tn.filter(n=>n.is_signed).length;
 const wtEntries=lsp.watchtower_count||0;
 const htlcCount=(lsp.htlcs||[]).length;
 const fwdActive=(lsp.htlc_origins||[]).filter(o=>o.active).length;
 const push=(k,v)=>{_hist[k].push(v); if(_hist[k].length>_HIST_MAX)_hist[k].shift();};
 push('sigStates',sigStates); push('wtEntries',wtEntries);
 push('htlcCount',htlcCount); push('fwdActive',fwdActive);
}

// Helpers
const bg=(ok,y,n)=>ok?`<span class="b ok">${y||'OK'}</span>`:`<span class="b dn">${n||'DOWN'}</span>`;
function sb(s){const l=(s||'').toLowerCase();
 if(l==='open'||l==='active'||l==='channeld_normal')return`<span class="b ok">${s}</span>`;
 if(l==='fulfilled'||l==='complete'||l==='settled'||l==='paid')return`<span class="b done">${s}</span>`;
 if(l==='closed'||l==='failed'||l==='expired')return`<span class="b dn">${s}</span>`;
 if(l==='dying'||l==='offered'||l==='unpaid')return`<span class="b w">${s}</span>`;
 return`<span class="b i">${s||'?'}</span>`;}
const fs=v=>v==null?'\u2014':Number(v).toLocaleString()+' sat';
const fm=v=>{if(v==null)return'\u2014';let n=Number(v);if(typeof v==='string'&&v.endsWith('msat'))n=parseInt(v);return Math.floor(n/1000).toLocaleString()+' sat';};
const th=h=>{if(!h||h==='?'||h==='null'||h==='None')return'\u2014';return h.length>22?h.slice(0,10)+'\u2026'+h.slice(-10):h;};
const ts=h=>{if(!h||h==='?')return'\u2014';return h.length>16?h.slice(0,8)+'\u2026':h;};
const bar=(l,r)=>{const t=l+r;if(!t)return'';const p=Math.round(l/t*100);return`<div class="b4"><div class="l" style="width:${p}%"></div><div class="rm" style="width:${100-p}%"></div></div>`;};
const ta=ts=>{
 // Defensive: LSP currently inserts the literal string '%s' into some
 // created_at columns (printf placeholder never substituted \u2014 invoice
 // registry hit by this).  Number('%s') is NaN; arithmetic propagates;
 // result was rendered as "NaNd".  Coerce + NaN-check first so the
 // dashboard degrades to "\u2014" instead of "NaNd".
 const t=Number(ts);
 if(!t||!Number.isFinite(t))return'\u2014';
 const d=Math.floor(Date.now()/1000)-t;
 if(d<60)return d+'s';if(d<3600)return Math.floor(d/60)+'m';
 if(d<86400)return Math.floor(d/3600)+'h';return Math.floor(d/86400)+'d';
};
const prog=(p,c)=>`<div class="pt"><div class="pf ${c||'pg'}" style="width:${Math.min(100,Math.max(0,p))}%"></div></div>`;

// === TAB: Overview ===
function rOverview(D){
 const p=D.processes||{},bt=D.bitcoin||{},db=D.databases||{},lsp=db.lsp||{},cln=D.cln||{};
 let h='';
 // Processes
 h+=`<div class="s"><div class="st">System</div><div class="kv">`;
 for(const[k,l]of Object.entries({bitcoind:'bitcoind',cln_a:'CLN-A',cln_b:'CLN-B',bridge:'Bridge',lsp:'LSP',client:'Client'}))
  h+=`<div class="ki"><span class="k">${l}</span>${bg(p[k])}</div>`;
 h+=`</div></div>`;
 // Bitcoin
 h+=`<div class="s"><div class="st">Bitcoin Network</div>`;
 if(!bt.available)h+=`<p class="mu">Unavailable</p>`;
 else{h+=`<div class="kv">`;
  h+=`<div class="ki"><span class="k">Height</span><span class="v">${Number(bt.blocks||0).toLocaleString()}</span></div>`;
  h+=`<div class="ki"><span class="k">Chain</span><span class="v">${bt.chain||'?'}</span></div>`;
  if(bt.balance!==undefined)h+=`<div class="ki"><span class="k">Balance</span><span class="v">${bt.balance} BTC</span></div>`;
  h+=`<div class="ki"><span class="k">Peers</span><span class="v">${bt.peers||0}</span></div>`;
  if(bt.mempool_size!==undefined)h+=`<div class="ki"><span class="k">Mempool</span><span class="v">${bt.mempool_size} tx</span></div>`;
  if(bt.ibd)h+=`<div class="ki"><span class="b w">Syncing</span><span class="v">${(bt.verification*100).toFixed(1)}%</span></div>`;
  h+=`</div>`;}
 h+=`</div>`;
 // Polish item 2: Trends panel.  Rolling-window in-memory sparklines for a
 // few operationally-interesting counts.  Each series is appended once per
 // render() tick (~5s), capped at _HIST_MAX samples (~5 minutes).  Pure
 // SVG, no library — useful for spotting growth or shrinkage at a glance.
 const tr=_hist;
 if((tr.sigStates||[]).length>1){
  const cell=(label,arr,col,fmt)=>{
   const cur=arr[arr.length-1]||0, prev=arr[0]||0, delta=cur-prev;
   const dCls=delta>0?'b ok':delta<0?'b dn':'b i';
   const dStr=delta>0?`+${delta}`:`${delta}`;
   return `<div class="ki" style="min-width:130px"><span class="k">${label}</span><span class="v">${(fmt||String)(cur)} ${spark(arr,80,18,col)} <span class="${dCls}" style="font-size:9px;margin-left:2px">${dStr}</span></span></div>`;
  };
  h+=`<div class="s"><div class="st"><span>Trends</span><span class="c">last ${tr.sigStates.length} ticks (~${Math.round(tr.sigStates.length*5/60)} min)</span></div>`;
  h+=`<div class="kv">`;
  h+=cell('Signed tree states', tr.sigStates, '#3fb950');
  h+=cell('Watchtower entries', tr.wtEntries, '#58a6ff');
  h+=cell('HTLCs in flight',    tr.htlcCount, '#f0883e');
  h+=cell('Active forwards',    tr.fwdActive, '#d29922');
  h+=`</div></div>`;
 }
 // Factory summary
 const facs=lsp.factories||[];
 h+=`<div class="s"><div class="st"><span>Factory Summary</span><span class="c">${facs.length}</span></div>`;
 if(!facs.length)h+=`<p class="mu">No factories</p>`;
 else for(const f of facs){
  h+=`<div class="kv"><div class="ki"><span class="k">ID</span><span class="v">#${f.id}</span></div><div class="ki"><span class="k">Parties</span><span class="v">${f.n_participants}</span></div><div class="ki"><span class="k">Funding</span><span class="v">${fs(f.funding_amount)}</span></div><div class="ki"><span class="k">State</span>${sb(f.state)}</div><div class="ki"><span class="k">Age</span><span class="v">${ta(f.created_at)}</span></div></div>`;}
 h+=`</div>`;
 // Ladder lifecycle
 const lad=lsp.ladder_factories||[];
 if(lad.length){h+=`<div class="s"><div class="st"><span>Ladder Lifecycle</span><span class="c">${lad.length} factories</span></div>`;
  h+=`<table><tr><th>Factory</th><th>State</th><th>Funded</th><th>Init</th><th>Departed</th><th>Created</th><th>Active blks</th><th>Dying blks</th><th>Lifecycle</th><th>Updated</th></tr>`;
  for(const lf of lad){
   const bh=bt.blocks||0;const total=lf.active_blocks+lf.dying_blocks;
   let elapsed=0;if(lf.state==='active')elapsed=Math.min(bh-lf.created_block,lf.active_blocks);
   else if(lf.state==='dying')elapsed=lf.active_blocks+Math.min(bh-(lf.created_block+lf.active_blocks),lf.dying_blocks);
   else elapsed=total;
   const pct=total>0?Math.min(100,elapsed/total*100):100;
   const pc=lf.state==='expired'?'po':lf.state==='dying'?'po':'pg';
   h+=`<tr><td>#${lf.factory_id}</td><td>${sb(lf.state)}</td><td>${lf.is_funded?'\u2705':'\u274C'}</td><td>${lf.is_initialized?'\u2705':'\u274C'}</td><td>${lf.n_departed||0}</td><td>${lf.created_block||'\u2014'}</td><td class="r">${lf.active_blocks||'\u2014'}</td><td class="r">${lf.dying_blocks||'\u2014'}</td><td style="min-width:100px">${prog(pct,pc)}</td><td>${ta(lf.updated_at)}</td></tr>`;}
  h+=`</table></div>`;}
 // DW Counter State (Phase 23)
 const dwc=lsp.dw_counter_state||[];
 if(dwc.length){h+=`<div class="s"><div class="st"><span>DW Counter State</span><span class="c">${dwc.length}</span></div>`;
  h+=`<div class="kv">`;
  for(const d of dwc)h+=`<div class="ki"><span class="k">Factory #${d.factory_id}</span><span class="v">epoch=${d.current_epoch} layers=${d.n_layers} states=[${d.layer_states}]</span></div>`;
  h+=`</div></div>`;}
 // ID Counters (Phase 23)
 const idc=lsp.id_counters||[];
 if(idc.length){h+=`<div class="s"><div class="st"><span>ID Counters</span><span class="c">${idc.length}</span></div>`;
  h+=`<div class="kv">`;
  for(const c of idc)h+=`<div class="ki"><span class="k">${c.name}</span><span class="v">${c.value}</span></div>`;
  h+=`</div></div>`;}
 // PR #181 Phase B consumer: signing_rounds journal summary.  Renders
 // when the table exists (schema v26+); silent against pre-#181 LSPs
 // where total=0 from the graceful-fallback collector.
 const srs=lsp.signing_rounds_summary||{};
 const srRecent=lsp.signing_rounds_recent||[];
 if((srs.total||0)>0){
  h+=`<div class="s"><div class="st"><span>Signing Rounds Journal</span><span class="c">${srs.total} ceremonies across ${srs.types} type(s)</span></div>`;
  h+=`<div class="kv" style="margin-bottom:8px">`;
  h+=`<div class="ki"><span class="k">Success</span><span class="b ok">${srs.success||0}</span></div>`;
  if(srs.in_flight)h+=`<div class="ki"><span class="k">In flight</span><span class="b w">${srs.in_flight}</span></div>`;
  if(srs.timeout)h+=`<div class="ki"><span class="k">Timeout</span><span class="b w">${srs.timeout}</span></div>`;
  if(srs.crashed)h+=`<div class="ki"><span class="k">Crashed</span><span class="b dn">${srs.crashed}</span></div>`;
  h+=`</div>`;
  if(srRecent.length){
   h+=`<table><tr><th>ID</th><th>Type</th><th>Factory</th><th>Node</th><th class="r">Epoch</th><th class="r">Parts</th><th class="r">Nonces</th><th class="r">PSigs</th><th>Started</th><th>Duration</th><th>Result</th></tr>`;
   for(const r of srRecent){
    const dur=(r.completed_at&&r.started_at)?(r.completed_at-r.started_at)+'s':(r.completed_at?'—':'in flight');
    let resCls='b w', resText=r.result||'pending';
    if(r.result==='success')resCls='b ok';
    else if(r.result==='timeout')resCls='b w';
    else if(r.result==='aborted_crash')resCls='b dn';
    else if(!r.result)resCls='b i';
    const err=r.error_detail?` <span class="mu" title="${(r.error_detail||'').replace(/"/g,'&quot;')}">⚠</span>`:'';
    h+=`<tr><td>${r.id}</td><td>${r.ceremony_type||'?'}</td><td>#${r.factory_id??'—'}</td><td>${r.node_idx??'—'}</td><td class="r">${r.epoch??'—'}</td><td class="r">${r.n_participants??'—'}</td><td class="r">${r.nonces_collected??'—'}</td><td class="r">${r.partial_sigs_collected??'—'}</td><td>${ta(r.started_at)} ago</td><td>${dur}</td><td><span class="${resCls}">${resText}</span>${err}</td></tr>`;
   }
   h+=`</table>`;
  }
  h+=`</div>`;
 }
 // Channels summary
 const chs=lsp.channels||[];
 h+=`<div class="s"><div class="st"><span>Channels</span><span class="c">${chs.length}</span></div>`;
 if(!chs.length)h+=`<p class="mu">No channels</p>`;
 else{h+=`<table><tr><th>CH</th><th>Slot</th><th class="r">Local</th><th class="r">Remote</th><th style="min-width:60px">Bal</th><th class="r">Commits</th><th>State</th></tr>`;
  for(const c of chs){const l=c.local_amount||0,r=c.remote_amount||0;
   h+=`<tr><td>${c.id}</td><td>${c.slot??'\u2014'}</td><td class="r">${fs(l)}</td><td class="r">${fs(r)}</td><td>${bar(l,r)}</td><td class="r">${c.commitment_number??'?'}</td><td>${sb(c.state)}</td></tr>`;}
  h+=`</table>`;}
 h+=`</div>`;
 // JIT Channels summary
 const jits=lsp.jit_channels||[];
 h+=`<div class="s"><div class="st"><span>JIT Channels</span><span class="c">${jits.length}</span></div>`;
 if(!jits.length)h+=`<p class="mu">No active JIT channels</p>`;
 else{h+=`<table><tr><th>JIT ID</th><th>Client</th><th>State</th><th>Funding TXID</th><th class="r">Amount</th><th class="r">Local</th><th class="r">Remote</th><th>Created</th></tr>`;
  for(const j of jits){
   h+=`<tr><td>0x${(j.jit_channel_id||0).toString(16)}</td><td>${j.client_idx}</td><td>${sb(j.state)}</td><td class="h">${th(j.funding_txid)}</td><td class="r">${fs(j.funding_amount)}</td><td class="r">${fs(j.local_amount)}</td><td class="r">${fs(j.remote_amount)}</td><td>${ta(j.created_at)}</td></tr>`;}
  h+=`</table>`;}
 h+=`</div>`;
 // CLN summary
 h+=`<div class="g2">`;
 for(const[k,lb]of[['a','CLN Node A'],['b','CLN Node B']]){
  const n=cln[k]||{}; h+=`<div class="s"><div class="st">${lb}</div>`;
  if(!n.available)h+=`<p class="mu">Unavailable</p>`;
  else{h+=`<div class="kv"><div class="ki"><span class="k">ID</span><span class="v h">${th(n.id)}</span></div><div class="ki"><span class="k">Peers</span><span class="v">${n.num_peers||0}</span></div><div class="ki"><span class="k">Channels</span><span class="v">${n.num_channels||0}</span></div></div>`;}
  h+=`</div>`;}
 h+=`</div>`;
 return h;
}

// === Factory Configuration card (live LSP cmdline) ===
function rConfig(D){
 const c=D.factory_config||{};
 if(!c.available)return '';
 // Decode arity to a human-readable leaf-mechanism label
 const a=String(c.arity||'?');
 let shape;
 if(a==='3')shape='PS canonical';
 else if(a==='2')shape='DW arity-2 (legacy)';
 else if(a==='1')shape='DW arity-1 (legacy)';
 else if(a.indexOf(',')>=0)shape=`mixed [${a}]`;
 else shape=`arity ${a}`;
 const subk=String(c.ps_subfactory_arity||'1');
 const wideLabel=subk==='1'?'no wide leaves':`k² wide leaves (k=${subk})`;
 const shapeColor=a==='3'?'#3fb950':(a==='1'||a==='2')?'#d29922':'#58a6ff';
 let h=`<div class="s"><div class="st"><span>Factory Configuration</span><span class="c">live cmdline (pid ${c.pid||'?'})</span></div>`;
 // Headline row: the two knobs that change the protocol shape
 h+=`<div class="kv" style="margin-bottom:8px">`;
 h+=`<div class="ki"><span class="k">Leaf shape</span><span class="v" style="color:${shapeColor};font-weight:700">${shape}</span></div>`;
 h+=`<div class="ki"><span class="k">Sub-factory arity</span><span class="v">${wideLabel}</span></div>`;
 h+=`<div class="ki"><span class="k">Clients</span><span class="v">${c.clients||'—'}</span></div>`;
 h+=`<div class="ki"><span class="k">Funding</span><span class="v">${fs(c.amount)}</span></div>`;
 h+=`<div class="ki"><span class="k">Network</span><span class="v">${c.network||'—'}</span></div>`;
 h+=`<div class="ki"><span class="k">Port</span><span class="v">${c.port||'—'}</span></div>`;
 h+=`</div>`;
 // Economics row
 h+=`<div class="kv" style="margin-bottom:8px">`;
 h+=`<div class="ki"><span class="k">LSP balance %</span><span class="v">${c.lsp_balance_pct||'?'}</span></div>`;
 h+=`<div class="ki"><span class="k">Placement</span><span class="v">${c.placement_mode||'?'}</span></div>`;
 h+=`<div class="ki"><span class="k">Economic mode</span><span class="v">${c.economic_mode||'?'}</span></div>`;
 h+=`<div class="ki"><span class="k">Routing fee</span><span class="v">${c.routing_fee_ppm||'0'} ppm</span></div>`;
 h+=`<div class="ki"><span class="k">Default profit</span><span class="v">${c.default_profit_bps||'0'} bps</span></div>`;
 h+=`<div class="ki"><span class="k">Settlement</span><span class="v">every ${c.settlement_interval||'?'} blk</span></div>`;
 h+=`</div>`;
 // Lifecycle + fees row
 h+=`<div class="kv">`;
 h+=`<div class="ki"><span class="k">Active blocks</span><span class="v">${c.active_blocks||'—'}</span></div>`;
 h+=`<div class="ki"><span class="k">Dying blocks</span><span class="v">${c.dying_blocks||'—'}</span></div>`;
 h+=`<div class="ki"><span class="k">DW step blocks</span><span class="v">${c.step_blocks||'?'}</span></div>`;
 h+=`<div class="ki"><span class="k">States/layer</span><span class="v">${c.states_per_layer||'?'}</span></div>`;
 h+=`<div class="ki"><span class="k">Fee rate</span><span class="v">${c.fee_rate||'?'} sat/kvB</span></div>`;
 h+=`<div class="ki"><span class="k">Fee bump</span><span class="v">after ${c.fee_bump_after||'?'}, max ${c.fee_bump_max||'?'}</span></div>`;
 h+=`</div>`;
 // Mode/flag badges
 const flags=[];
 if(c.daemon)flags.push(['daemon','b i']);
 if(c.demo)flags.push(['demo','b i']);
 if(c.cli)flags.push(['cli','b i']);
 if(c.no_jit)flags.push(['no-jit','b w']);
 if(c.onion)flags.push(['tor onion','b i']);
 if(c.tor_only)flags.push(['tor-only','b i']);
 if(c.i_accept_risk)flags.push(['mainnet-risk','b dn']);
 if(flags.length){
  h+=`<div style="margin-top:8px">`;
  for(const[t,cls]of flags)h+=`<span class="${cls}" style="margin-right:4px">${t}</span>`;
  h+=`</div>`;
 }
 h+=`</div>`;
 return h;
}

// === PS Leaf Chains panel (canonical pseudo-Spilman state mechanism) ===
function rPsChains(D){
 const db=D.databases||{},lsp=db.lsp||{};
 // Polish item 4: honor the rFactory per-factory isolation selector by
 // filtering every PS-related collection on factory_id when facSel != 'all'.
 const fOK=r=>facSel==='all'||String(r.factory_id)===facSel;
 const chains=(lsp.ps_leaf_chains||[]).filter(fOK);
 const initial=(lsp.ps_initial_signed_states||[]).filter(fOK);
 const sigInputs=(lsp.ps_signed_inputs_by_leaf||[]).filter(fOK);
 const subChains=(lsp.ps_subfactory_chains||[]).filter(fOK);
 const tn=(lsp.tree_nodes||[]).filter(fOK);
 // Tree nodes that look like PS leaves: state nodes with nSequence = 0xFFFFFFFE
 const psLeafNodes=tn.filter(n=>n.type==='state'&&n.nsequence===4294967294);
 // Nothing to show if both no chains and no PS leaves in the tree
 if(!chains.length&&!initial.length&&!subChains.length&&!psLeafNodes.length)return '';
 // Group leaf chain rows by (factory_id, leaf_node_idx)
 const byLeaf={};
 for(const r of chains){
  const k=`${r.factory_id}_${r.leaf_node_idx}`;
  if(!byLeaf[k])byLeaf[k]={factory_id:r.factory_id,leaf_node_idx:r.leaf_node_idx,entries:[]};
  byLeaf[k].entries.push(r);
 }
 // chain[0] / sig-defense lookups
 const initMap={};for(const r of initial)initMap[`${r.factory_id}_${r.node_idx}`]=r;
 const sigMap={};for(const r of sigInputs)sigMap[`${r.factory_id}_${r.leaf_node_idx}`]=r.cnt;
 const leafKeys=Object.keys(byLeaf).sort();
 let h=`<div class="s"><div class="st"><span>PS Leaf Chains</span><span class="c">${leafKeys.length||psLeafNodes.length} leaves</span></div>`;
 // Trustless coverage headline: poison-TX presence across all PS chain entries
 let totalPos=0,totalCovered=0;
 for(const r of chains){totalPos++;if(r.has_poison)totalCovered++;}
 for(const r of subChains){totalPos++;if(r.has_poison)totalCovered++;}
 if(totalPos>0){
  const pct=Math.round(100*totalCovered/totalPos);
  const cls=pct===100?'b ok':pct>=80?'b i':'b w';
  h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">Trustless poison-TX coverage</span><span class="${cls}">${totalCovered}/${totalPos} positions (${pct}%)</span></div></div>`;
 }
 // Empty-but-PS-leaves-exist banner (catches the v0.1.15 persistence gap)
 if(!leafKeys.length&&psLeafNodes.length){
  h+=`<p class="mu">No PS chain advances yet. ${psLeafNodes.length} PS leaf state nodes exist in the tree — they'll start populating <code>ps_leaf_chains</code> when leaf advances fire.</p>`;
  if(!initial.length){
   h+=`<p class="mu" style="color:#d29922">⚠ ${psLeafNodes.length} PS leaves but no rows in <code>ps_initial_signed_states</code>. This is the v0.1.15 force-close-fails-with-25 pattern — chain[0] bytes not persisted on advance.</p>`;
  }
  h+=`</div>`;return h;
 }
 // Per-leaf summary table
 // Build a factory_id -> fee_per_tx lookup so force-close cost
 // projection can be expressed in absolute sats.  chain_len + 1 because
 // chain[0] (initial) must also be broadcast for chain[N] to be valid.
 const facMap={};for(const fr of (lsp.factories||[]))facMap[fr.id]=fr;
 if(leafKeys.length){
  h+=`<table><tr><th>Factory</th><th>Leaf</th><th class="r">Epoch</th><th class="r">Chain len</th><th>chain[0] persisted</th><th class="r">Latest amt</th><th class="r">Poison coverage</th><th class="r">Defense rows</th><th class="r">Force-close cost</th><th>Latest TXID</th></tr>`;
  for(const k of leafKeys){
   const e=byLeaf[k];
   e.entries.sort((a,b)=>a.chain_pos-b.chain_pos);
   // F2: filter to CURRENT epoch only.  After a Tier B rollover the table
   // can contain entries from prior epochs which are no longer broadcastable
   // (their parent UTXO was replaced by the re-signed root) — counting them
   // inflates the force-close cost.  Pre-F2 DBs have epoch=0 everywhere
   // (no rollover concept), so max-epoch = 0 = no filtering.
   const curEpoch=Math.max(0,...e.entries.map(x=>x.epoch||0));
   const curEntries=e.entries.filter(x=>(x.epoch||0)===curEpoch);
   const latest=curEntries.length?curEntries[curEntries.length-1]:e.entries[e.entries.length-1];
   const init=initMap[`${e.factory_id}_${e.leaf_node_idx}`];
   const cov=curEntries.filter(x=>x.has_poison).length;
   const pct=curEntries.length?Math.round(100*cov/curEntries.length):0;
   const cls=pct===100?'b ok':pct>=80?'b i':'b w';
   const sig=sigMap[`${e.factory_id}_${e.leaf_node_idx}`]||0;
   const fac=facMap[e.factory_id]||{};
   // Force-close cost projection: each chain entry needs its own on-chain
   // broadcast.  chain[0] + chain[1..N] = curEntries.length+1 total TXs;
   // fee_per_tx is the LSP's budgeted endogenous fee at factory creation.
   // Real cost can be higher under CPFP fee-bumps; this is the baseline
   // operator commitment for the CURRENT epoch.
   const fcTxCount=curEntries.length+(init?1:0);
   const fcCost=fcTxCount*(fac.fee_per_tx||0);
   const epochBadge=curEpoch>0?` <span class="mu">(${e.entries.length-curEntries.length} historical)</span>`:'';
   h+=`<tr><td>#${e.factory_id}</td><td>node ${e.leaf_node_idx}</td><td class="r">${curEpoch}${epochBadge}</td><td class="r">${curEntries.length}</td><td>${init?'<span class="b ok">yes</span>':'<span class="b dn">missing</span>'}</td><td class="r">${fs(latest.chan_amount_sats)}</td><td class="r"><span class="${cls}">${cov}/${curEntries.length} (${pct}%)</span></td><td class="r">${sig}</td><td class="r" title="${fcTxCount} TXs × ${fac.fee_per_tx||0} sat budgeted fee/TX, current epoch only">${fs(fcCost)}</td><td class="h">${th(latest.txid)} ${txBadge(D,latest.txid,'reserve')}</td></tr>`;  }
  h+=`</table>`;
 }
 // Per-leaf chain detail (one mini-table per leaf showing chain[0..N])
 for(const k of leafKeys){
  const e=byLeaf[k];
  e.entries.sort((a,b)=>a.chain_pos-b.chain_pos);
  const init=initMap[`${e.factory_id}_${e.leaf_node_idx}`];
  h+=`<div style="margin-top:12px"><div class="st" style="margin-bottom:4px"><span>Leaf node ${e.leaf_node_idx} (factory #${e.factory_id}) progression</span><span class="c">${e.entries.length} advances</span></div>`;
  h+=`<table><tr><th>chain_pos</th><th class="r">channel amount</th><th>poison TX</th><th>TXID</th></tr>`;
  if(init)h+=`<tr><td>0 (initial)</td><td class="r">—</td><td><span class="b ok">persisted</span></td><td class="h">${th(init.txid)} ${txBadge(D,init.txid,'reserve')}</td></tr>`;
  else h+=`<tr><td>0 (initial)</td><td class="r">—</td><td><span class="b dn">missing</span></td><td class="mu">no row in ps_initial_signed_states</td></tr>`;
  for(const ent of e.entries){
   h+=`<tr><td>${ent.chain_pos}</td><td class="r">${fs(ent.chan_amount_sats)}</td><td>${ent.has_poison?'<span class="b ok">signed</span>':'<span class="b dn">unsigned</span>'}</td><td class="h">${th(ent.txid)} ${txBadge(D,ent.txid,'reserve')}</td></tr>`;
  }
  h+=`</table></div>`;
 }
 // PS sub-factory chains (k² wide leaves)
 if(subChains.length){
  const bySub={};
  for(const r of subChains){
   const k=`${r.factory_id}_${r.sub_node_idx}`;
   if(!bySub[k])bySub[k]={factory_id:r.factory_id,sub_node_idx:r.sub_node_idx,entries:[]};
   bySub[k].entries.push(r);
  }
  const subKeys=Object.keys(bySub).sort();
  h+=`<div style="margin-top:14px;border-top:1px solid #30363d;padding-top:10px">`;
  h+=`<div class="st"><span>PS Sub-Factory Chains (k² wide leaves)</span><span class="c">${subKeys.length} sub-factories</span></div>`;
  h+=`<table><tr><th>Factory</th><th>Sub</th><th class="r">Epoch</th><th class="r">Chain len</th><th class="r">Sales-stock (latest)</th><th>Channel amounts (latest)</th><th class="r">Poison coverage</th><th class="r">Force-close cost</th><th>Latest TXID</th></tr>`;
  for(const k of subKeys){
   const e=bySub[k];
   e.entries.sort((a,b)=>a.chain_pos-b.chain_pos);
   // F2: filter to current epoch (matches leaf-level treatment above).
   const curEpoch=Math.max(0,...e.entries.map(x=>x.epoch||0));
   const curEntries=e.entries.filter(x=>(x.epoch||0)===curEpoch);
   const latest=curEntries.length?curEntries[curEntries.length-1]:e.entries[e.entries.length-1];
   const cov=curEntries.filter(x=>x.has_poison).length;
   const pct=curEntries.length?Math.round(100*cov/curEntries.length):0;
   const cls=pct===100?'b ok':pct>=80?'b i':'b w';
   const fac=facMap[e.factory_id]||{};
   const fcTxCount=curEntries.length+1;  // chain[0] + chain[1..N]
   const fcCost=fcTxCount*(fac.fee_per_tx||0);
   const epochBadge=curEpoch>0?` <span class="mu">(${e.entries.length-curEntries.length} historical)</span>`:'';
   h+=`<tr><td>#${e.factory_id}</td><td>node ${e.sub_node_idx}</td><td class="r">${curEpoch}${epochBadge}</td><td class="r">${curEntries.length}</td><td class="r">${fs(latest.sales_stock_amount_sats)}</td><td style="font-size:11px">${latest.channel_amounts_csv||'—'}</td><td class="r"><span class="${cls}">${cov}/${curEntries.length} (${pct}%)</span></td><td class="r" title="${fcTxCount} TXs × ${fac.fee_per_tx||0} sat budgeted fee/TX, current epoch only">${fs(fcCost)}</td><td class="h">${th(latest.txid)} ${txBadge(D,latest.txid,'reserve')}</td></tr>`;  }
  h+=`</table></div>`;
 }
 h+=`</div>`;
 return h;
}

// === TAB: Factory ===
function rFactory(D){
 const db=D.databases||{},lsp=db.lsp||{},facs=lsp.factories||[],parts=lsp.participants||[];
 let h=rConfig(D);
 // Polish item 4: per-factory isolation selector.  When the deployment has
 // multiple factories, today the Factory tab renders all of them stacked.
 // This selector lets the operator narrow the view to one at a time
 // without changing any data — just hides the others.  Filter is applied
 // downstream by checking facSel.  rPsChains() reads facSel from
 // module-scope too.  Default 'all' preserves prior behavior.
 const facsAll=facs;
 const facsView=(facSel==='all')?facs:facs.filter(f=>String(f.id)===facSel);
 if(facsAll.length>1){
  h+=`<div class="s" style="background:#0c2d6b22;border-color:#58a6ff44"><div class="st"><span>Factory isolation</span><span class="c">${facsAll.length} factories on this LSP</span></div>`;
  h+=`<div style="display:flex;gap:8px;align-items:center;font-size:11px;margin-top:4px">`;
  h+=`<span class="mu">view:</span>`;
  h+=`<select id="fac-sel" onchange="facSel=this.value;refresh()" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:4px 8px;border-radius:4px;font-family:inherit;font-size:11px">`;
  h+=`<option value="all"${facSel==='all'?' selected':''}>all factories (${facsAll.length})</option>`;
  for(const f of facsAll)h+=`<option value="${f.id}"${facSel===String(f.id)?' selected':''}>Factory #${f.id} (${f.n_participants||'?'} parties)</option>`;
  h+=`</select>`;
  if(facSel!=='all')h+=`<span class="mu">showing only Factory #${facSel} — tree, PS chains, participants all filtered</span>`;
  h+=`</div></div>`;
 }
 // P4: Factory detail — when multiple factories exist, render each in a
 // visually-separated section.  Most data already groups by factory_id
 // (tree_nodes, ps_*_chains, etc.); this just gives the operator a clear
 // header anchor per factory.
 if(facsAll.length>1 && facSel==='all'){
  h+=`<div class="s" style="background:#0c2d6b22;border-color:#58a6ff44"><div class="st"><span>Multi-factory deployment</span><span class="c">${facsAll.length} factories on this LSP</span></div>`;
  h+=`<p class="mu" style="font-size:11px">Each factory below has its own tree, PS chains, and lifecycle.  Scroll for per-factory detail, or pick one from the isolation selector above.</p></div>`;
 }
 h+=`<div class="s"><div class="st"><span>Factory (N+1-of-N+1 MuSig2 UTXO)</span><span class="c">${facsView.length}${facSel!=='all'?` of ${facsAll.length}`:''}</span></div>`;
 for(const f of facsView){
  if(facsView.length>1)h+=`<div style="border-top:2px solid #30363d;margin:8px 0 4px;padding-top:6px;font-weight:600;color:#58a6ff">Factory #${f.id}</div>`;
  h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">ID</span><span class="v">#${f.id}</span></div><div class="ki"><span class="k">Parties</span><span class="v">${f.n_participants} (N+1-of-N+1 MuSig2)</span></div><div class="ki"><span class="k">Funding</span><span class="v">${fs(f.funding_amount)}</span></div><div class="ki"><span class="k">State</span>${sb(f.state)}</div><div class="ki"><span class="k">Created</span><span class="v">${ta(f.created_at)} ago</span></div></div>`;
  h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">TXID</span><span class="v h">${th(f.funding_txid)}</span></div><div class="ki"><span class="k">vout</span><span class="v">${f.funding_vout??'\u2014'}</span></div><div class="ki"><span class="k">step_blocks</span><span class="v">${f.step_blocks??'\u2014'}</span></div><div class="ki"><span class="k">states/layer</span><span class="v">${f.states_per_layer??'\u2014'}</span></div><div class="ki"><span class="k">cltv_timeout</span><span class="v">${f.cltv_timeout??'\u2014'} blk</span></div><div class="ki"><span class="k">fee/tx</span><span class="v">${f.fee_per_tx!=null?f.fee_per_tx+' sat':'\u2014'}</span></div></div>`;
  // Participants
  const fp=parts.filter(p=>p.factory_id===f.id);
  if(fp.length){const roles=['LSP','Client 1','Client 2','Client 3','Client 4'];
   h+=`<table><tr><th>Slot</th><th>Role</th><th>Public Key (secp256k1)</th></tr>`;
   for(const p of fp)h+=`<tr><td>${p.slot}</td><td>${roles[p.slot]||'Client '+(p.slot)}</td><td class="pk">${p.pubkey}</td></tr>`;
   h+=`</table>`;}
 }
 if(!facsView.length)h+=`<p class="mu">${facsAll.length?`Factory #${facSel} not found in current data`:'No factories'}</p>`;
 h+=`</div>`;
 // Departed Clients (Phase 23) — filtered by selector
 const dep=(lsp.departed_clients||[]).filter(d=>facSel==='all'||String(d.factory_id)===facSel);
 if(dep.length){h+=`<div class="s"><div class="st"><span>Departed Clients</span><span class="c">${dep.length}</span></div>`;
  h+=`<table><tr><th>Factory</th><th>Client Idx</th><th>Extracted Key</th><th>Departed</th></tr>`;
  for(const d of dep)h+=`<tr><td>#${d.factory_id}</td><td>${d.client_idx}</td><td class="h">${th(d.extracted_key)}</td><td>${ta(d.departed_at)}</td></tr>`;
  h+=`</table></div>`;}
 // Tree nodes visualization — filter to selected factory if isolation is active
 const tn=(lsp.tree_nodes||[]).filter(n=>facSel==='all'||String(n.factory_id)===facSel);
 if(tn.length){h+=`<div class="s"><div class="st"><span>Timeout-Sig-Tree Nodes</span><span class="c">${tn.length}${facSel!=='all'?` (Factory #${facSel} only)`:''}</span></div>`;
  // Group by factory
  const byF={};tn.forEach(n=>{if(!byF[n.factory_id])byF[n.factory_id]=[];byF[n.factory_id].push(n);});
  for(const[fid,nodes]of Object.entries(byF)){
   h+=`<div style="margin-bottom:8px;font-size:11px;color:#8b949e">Factory #${fid}</div>`;
   // ASCII tree
   const nm=n=>{const sc=n.is_signed?'color:#3fb950':'color:#484f58';const tp=n.type==='kickoff'?'K':'S';return`<span style="${sc};font-weight:700">[${tp}${n.node_index}]</span>`;};
   const nd=n=>{const sc=n.is_signed?'border-color:#3fb950':'border-color:#484f58';return`<div style="display:inline-block;border:1px solid #30363d;${sc};border-radius:4px;padding:4px 8px;margin:2px;font-size:11px;min-width:140px;vertical-align:top"><div style="font-weight:700;margin-bottom:2px">${nm(n)} ${n.type}</div><div class="kv" style="gap:2px 10px"><div class="ki"><span class="k">signers</span><span class="v" style="font-size:10px">[${n.signer_indices}]</span></div><div class="ki"><span class="k">amt</span><span class="v" style="font-size:10px">${n.output_amounts}</span></div><div class="ki"><span class="k">seq</span><span class="v" style="font-size:10px">${n.nsequence===4294967295?'final':n.nsequence}</span></div><div class="ki"><span class="k">txid</span><span class="v h" style="font-size:9px">${th(n.txid)}</span></div></div>${n.is_signed?'<span class="b ok" style="margin-top:3px;display:inline-block">signed</span>':'<span class="b dn" style="margin-top:3px;display:inline-block">unsigned</span>'}</div>`;};
   // Build tree layout by BFS layers — works for any depth (arity-1: 14 nodes, arity-2: 6 nodes)
   h+=`<div style="text-align:center;overflow-x:auto;padding:8px">`;
   let curLayer=nodes.filter(n=>n.parent_index===-1||n.parent_index===null);
   while(curLayer.length){
    h+=`<div style="display:flex;justify-content:center;flex-wrap:wrap;gap:4px">${curLayer.map(n=>nd(n)).join('')}</div>`;
    const curIdx=new Set(curLayer.map(n=>n.node_index));
    const nextLayer=nodes.filter(n=>curIdx.has(n.parent_index));
    if(nextLayer.length)h+=`<div style="color:#30363d;font-size:14px">${'\u2502'.repeat(Math.min(nextLayer.length,curLayer.length))}</div>`;
    curLayer=nextLayer;
   }
   h+=`</div>`;
  }
  // Detail table \u2014 Phase 1: include on-chain status badge from P3 enrichment
  h+=`<table style="margin-top:8px"><tr><th>#</th><th>Type</th><th>Parent</th><th>Layer</th><th>Signers</th><th class="r">Input</th><th>Outputs</th><th>nSeq</th><th>TXID</th><th>On-chain</th><th>Status</th></tr>`;
  for(const n of tn){h+=`<tr><td>${n.node_index}</td><td>${n.type}</td><td>${n.parent_index>=0?n.parent_index:'\u2014'}</td><td>${n.dw_layer_index>=0?n.dw_layer_index:'\u2014'}</td><td>[${n.signer_indices}] (${n.n_signers})</td><td class="r">${fs(n.input_amount)}</td><td>${n.output_amounts}</td><td>${n.nsequence===4294967295?'final':n.nsequence}</td><td class="h">${th(n.txid)}</td><td>${txBadge(D,n.txid,'reserve')}</td><td>${n.is_signed?'<span class="b ok">signed</span>':'<span class="b dn">unsigned</span>'}</td></tr>`;}
  h+=`</table>`;
  h+=`</div>`;}
 // Signing Progress (MuSig2 nonce/sig collection).  D2: the table is a
 // crash-recovery SNAPSHOT — rows are written during an in-progress
 // ceremony and cleared on success.  Empty = no ceremony in flight = OK.
 const sp=lsp.signing_progress||[];
 if(!sp.length){
  h+=`<div class="s"><div class="st"><span>Signing Progress (MuSig2)</span><span class="c">no ceremony in flight</span></div>`;
  h+=`<p class="mu">Empty by design — <code>signing_progress</code> is a crash-recovery snapshot. Rows appear during an in-progress nonce/psig round and are cleared by <code>persist_clear_signing_progress</code> on ceremony success. Empty means the last ceremony completed cleanly.</p>`;
  h+=`</div>`;
 } else if(sp.length){h+=`<div class="s"><div class="st"><span>Signing Progress (MuSig2)</span><span class="c">${sp.length} entries — ceremony in flight</span></div>`;
  // Group by factory_id + node_index
  const byNode={};sp.forEach(s=>{const k=s.factory_id+'_'+s.node_index;if(!byNode[k])byNode[k]=[];byNode[k].push(s);});
  h+=`<table><tr><th>Factory</th><th>Node</th><th>Slot</th><th>Nonce</th><th>Partial Sig</th><th>Updated</th></tr>`;
  for(const s of sp){
   h+=`<tr><td>#${s.factory_id}</td><td>${s.node_index}</td><td>${s.signer_slot}</td><td>${s.has_nonce?'<span class="b ok">yes</span>':'<span class="b dn">no</span>'}</td><td>${s.has_partial_sig?'<span class="b ok">yes</span>':'<span class="b dn">no</span>'}</td><td>${ta(s.updated_at)}</td></tr>`;}
  h+=`</table>`;
  // Summary per node: X/N nonces, Y/N sigs
  for(const[k,entries]of Object.entries(byNode)){const nn=entries.filter(e=>e.has_nonce).length,ns=entries.filter(e=>e.has_partial_sig).length,tot=entries.length;
   h+=`<div class="kv" style="margin-top:4px"><div class="ki"><span class="k">Node ${entries[0].node_index}</span><span class="v">nonces ${nn}/${tot}</span></div><div class="ki"><span class="k">sigs</span><span class="v">${ns}/${tot}</span></div><div style="flex:1">${prog(ns/tot*100,ns===tot?'pg':'po')}</div></div>`;}
  h+=`</div>`;}
 // Protocol + DW
 // F3b: in real mode, build a dw_state-shaped object from the live
 // lsp.dw_counter_state + factory row + bitcoin tip so the existing
 // DW state widget (which was originally written for demo mode) can
 // render against real factory data.  Demo mode populates D.dw_state
 // directly; real mode populates lsp.dw_counter_state via the
 // collect_databases query.  Fall back to demo shape when present
 // (so demo mode keeps rendering unchanged).
 const proto=D.factory_protocol;
 let dw=D.dw_state;
 if(!dw){
  const dwc=(lsp.dw_counter_state||[])[0];
  const fac0=(lsp.factories||[])[0];
  const lf0=(lsp.ladder_factories||[]).find(r=>r.factory_id===(fac0&&fac0.id))||{};
  if(dwc&&fac0){
   const spl=fac0.states_per_layer||0;
   const nl=dwc.n_layers||0;
   const layerStates=(dwc.layer_states||'').split(',').map(s=>parseInt(s,10)||0);
   const layers=[];
   for(let i=0;i<nl;i++){
    layers.push({
     index:i,
     current_state:layerStates[i]||0,
     max_states:spl,
     // step_blocks per layer = base × states_per_layer^layer_index
     step_blocks:(fac0.step_blocks||0)*Math.pow(spl||1,i),
    });
   }
   const cb=lf0.created_block||0;
   const ab=lf0.active_blocks||0;
   const db_=cb+ab;
   dw={
    n_layers:nl,
    states_per_layer:spl,
    total_epochs:Math.pow(spl||1,nl),
    current_epoch:dwc.current_epoch||0,
    layers:layers,
    created_block:cb,
    cltv_timeout:fac0.cltv_timeout||db_,
    dying_block:db_,
    current_block:(D.bitcoin&&D.bitcoin.blocks)||cb,
   };
  }
 }
 if(proto||dw){h+=`<div class="g2">`;
  if(proto){h+=`<div class="s"><div class="st">Creation Protocol (4 rounds)</div><div class="pr">`;
   for(let i=0;i<proto.phases.length;i++){if(i)h+=`<span class="pa">\u25B6</span>`;
    h+=`<span class="ps ${i<=proto.current_phase_idx?'done':'pend'}">${proto.phases[i]}</span>`;}
   h+=`</div><div class="kv" style="margin-top:6px"><div class="ki"><span class="k">Nonces</span><span class="v">${proto.nonces_collected}/${proto.nonces_needed}</span></div><div class="ki"><span class="k">Partial sigs</span><span class="v">${proto.psigs_collected}/${proto.psigs_needed}</span></div><div class="ki"><span class="k">Tree nodes</span><span class="v">${proto.signed_nodes}/${proto.tree_nodes} signed</span></div></div></div>`;}
  if(dw){const bh=D.bitcoin?.blocks||0,total=dw.dying_block-dw.created_block,el=bh-dw.created_block,pct=Math.min(100,Math.max(0,el/total*100)),bl=dw.dying_block-bh;
   h+=`<div class="s"><div class="st">Decker-Wattenhofer State</div>`;
   h+=`<div class="kv" style="margin-bottom:6px"><div class="ki"><span class="k">Created</span><span class="v">blk ${dw.created_block.toLocaleString()}</span></div><div class="ki"><span class="k">CLTV</span><span class="v">blk ${dw.cltv_timeout.toLocaleString()}</span></div><div class="ki"><span class="k">Dying</span><span class="v">blk ${dw.dying_block.toLocaleString()}</span></div><div class="ki"><span class="k">Left</span><span class="v">${bl.toLocaleString()} blk</span></div></div>`;
   h+=`<div style="margin-bottom:8px"><span class="k" style="font-size:10px">Lifetime</span>${prog(pct,pct>80?'po':'pg')}</div>`;
   h+=`<div class="kv" style="margin-bottom:6px"><div class="ki"><span class="k">Layers</span><span class="v">${dw.n_layers}</span></div><div class="ki"><span class="k">States/layer</span><span class="v">${dw.states_per_layer}</span></div><div class="ki"><span class="k">Epochs</span><span class="v">${dw.current_epoch}/${dw.total_epochs-1}</span></div></div>`;
   if(dw.layers)for(const ly of dw.layers){h+=`<div class="lr"><span class="ll">L${ly.index} (${ly.step_blocks}b)</span>`;
    for(let s=0;s<ly.max_states;s++){const c=s<ly.current_state?'u':s===ly.current_state?'cu':'av';h+=`<div class="lc ${c}">${s}</div>`;}h+=`</div>`;}
   h+=`</div>`;}
  h+=`</div>`;}
 // PS leaf chain panel (canonical pseudo-Spilman; populated on leaf advance)
 h+=rPsChains(D);
 return h;
}

// === TAB: Channels & HTLCs ===
function rChannels(D){
 const db=D.databases||{},lsp=db.lsp||{},chs=lsp.channels||[],htlcs=lsp.htlcs||[];
 const revMap={};(lsp.revocations_by_channel||[]).forEach(r=>revMap[r.channel_id]=r.cnt);
 const nMap={};(lsp.nonce_pools||[]).forEach(n=>{if(!nMap[n.channel_id])nMap[n.channel_id]={};nMap[n.channel_id][n.side]=n.next_index;});
 let h='';
 h+=`<div class="s"><div class="st"><span>Channels (LSP \u2194 Clients)</span><span class="c">${chs.length}</span></div>`;
 if(!chs.length)h+=`<p class="mu">No channels</p>`;
 else{h+=`<table><tr><th>CH</th><th>Slot</th><th class="r">Local</th><th class="r">Remote</th><th class="r">Cap</th><th style="min-width:70px">Balance</th><th class="r">Commits</th><th class="r">Revoked</th><th>Nonces (L/R)</th><th>State</th></tr>`;
  for(const c of chs){const l=c.local_amount||0,rm=c.remote_amount||0,np=nMap[c.id]||{};
   h+=`<tr><td>${c.id}</td><td>${c.slot??'\u2014'}</td><td class="r">${fs(l)}</td><td class="r">${fs(rm)}</td><td class="r">${fs(c.funding_amount)}</td><td>${bar(l,rm)}</td><td class="r">${c.commitment_number??'?'}</td><td class="r">${revMap[c.id]??0}</td><td>${np.local??'?'} / ${np.remote??'?'}</td><td>${sb(c.state)}</td></tr>`;}
  h+=`</table>`;}
 h+=`</div>`;
 // JIT Channels detail
 const jits=lsp.jit_channels||[];
 h+=`<div class="s"><div class="st"><span>JIT Channels (Standalone 2-of-2)</span><span class="c">${jits.length}</span></div>`;
 if(!jits.length)h+=`<p class="mu">No JIT channels</p>`;
 else{h+=`<table><tr><th>JIT ID</th><th>Client</th><th>State</th><th>Funding TXID</th><th class="r">Amount</th><th class="r">Local</th><th class="r">Remote</th><th style="min-width:60px">Balance</th><th class="r">Commits</th><th>Target</th><th>Created</th></tr>`;
  for(const j of jits){const jl=j.local_amount||0,jr=j.remote_amount||0;
   h+=`<tr><td>0x${(j.jit_channel_id||0).toString(16)}</td><td>${j.client_idx}</td><td>${sb(j.state)}</td><td class="h">${th(j.funding_txid)}</td><td class="r">${fs(j.funding_amount)}</td><td class="r">${fs(jl)}</td><td class="r">${fs(jr)}</td><td>${bar(jl,jr)}</td><td class="r">${j.commitment_number??'?'}</td><td>${j.target_factory_id||'\u2014'}</td><td>${ta(j.created_at)}</td></tr>`;}
  h+=`</table>`;}
 h+=`</div>`;
 // HTLCs
 h+=`<div class="s"><div class="st"><span>HTLCs</span><span class="c">${htlcs.length}</span></div>`;
 if(!htlcs.length)h+=`<p class="mu">No HTLCs</p>`;
 else{h+=`<table><tr><th>ID</th><th>CH</th><th>#</th><th>Dir</th><th class="r">Amount</th><th>State</th><th class="r">CLTV</th><th>Payment Hash</th><th>Preimage</th></tr>`;
  for(const x of htlcs){const dc=x.direction==='offered'?'color:#f0883e':'color:#3fb950';
   h+=`<tr><td>${x.id??'\u2014'}</td><td>${x.channel_id}</td><td>${x.htlc_id??'\u2014'}</td><td style="${dc}">${x.direction||'?'}</td><td class="r">${fs(x.amount)}</td><td>${sb(x.state)}</td><td class="r">${x.cltv_expiry??'\u2014'}</td><td class="h">${th(x.payment_hash)}</td><td class="h">${x.payment_preimage?ts(x.payment_preimage):'\u2014'}</td></tr>`;}
  h+=`</table>`;}
 h+=`</div>`;
 // Invoice Registry (Phase 23)
 const invReg=lsp.invoice_registry||[];
 if(invReg.length){h+=`<div class="s"><div class="st"><span>Invoice Registry</span><span class="c">${invReg.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th>Dest</th><th class="r">Amount (msat)</th><th>Bridge HTLC</th><th>Active</th><th>Payment Hash</th><th>Created</th></tr>`;
  for(const iv of invReg)h+=`<tr><td>${iv.id}</td><td>Client ${iv.dest_client}</td><td class="r">${iv.amount_msat?.toLocaleString()??'\u2014'}</td><td>${iv.bridge_htlc_id||'\u2014'}</td><td>${iv.active?'\u2705':'\u274C'}</td><td class="h">${th(iv.payment_hash)}</td><td>${ta(iv.created_at)}</td></tr>`;
  h+=`</table></div>`;}
 // HTLC Origins (Phase 23)
 const htlcOrig=lsp.htlc_origins||[];
 if(htlcOrig.length){h+=`<div class="s"><div class="st"><span>HTLC Origins</span><span class="c">${htlcOrig.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th>Bridge HTLC</th><th>Request</th><th>Sender</th><th>Sender HTLC</th><th>Active</th><th>Payment Hash</th></tr>`;
  for(const o of htlcOrig)h+=`<tr><td>${o.id}</td><td>${o.bridge_htlc_id||'\u2014'}</td><td>${o.request_id||'\u2014'}</td><td>${o.sender_idx}</td><td>${o.sender_htlc_id||'\u2014'}</td><td>${o.active?'\u2705':'\u274C'}</td><td class="h">${th(o.payment_hash)}</td></tr>`;
  h+=`</table></div>`;}
 return h;
}

// === TAB: Payments ===
// Reconstructs payment-level activity from HTLC tables: groups by payment_hash
// to detect MPP (multi-part), surfaces forwarding through htlc_origins, and
// rolls up per-channel volume/success.  No server-side schema changes —
// reads tables already queried by collect_databases.
function rPayments(D){
 const db=D.databases||{},lsp=db.lsp||{},cl=db.client||{};
 const htlcs=lsp.htlcs||[];
 const oldHtlcs=lsp.old_commitment_htlcs||[];
 const origins=lsp.htlc_origins||[];
 const invoices=lsp.invoice_registry||[];
 const clInvoices=cl.client_invoices||[];
 const chans=lsp.channels||[];
 // Group HTLCs (live + historical) by payment_hash
 const byHash={};
 const noteHash=(ph)=>{if(!byHash[ph])byHash[ph]={hash:ph,htlcs:[],historical:[],origins:[],invoices:[]};return byHash[ph];};
 for(const x of htlcs){if(x.payment_hash)noteHash(x.payment_hash).htlcs.push(x);}
 for(const x of oldHtlcs){if(x.payment_hash)noteHash(x.payment_hash).historical.push(x);}
 for(const o of origins){if(o.payment_hash)noteHash(o.payment_hash).origins.push(o);}
 for(const iv of invoices){if(iv.payment_hash)noteHash(iv.payment_hash).invoices.push(iv);}
 const payments=Object.values(byHash);
 const allHtlcs=htlcs.concat(oldHtlcs);
 // Empty state
 if(!payments.length && !allHtlcs.length){
  let h='';
  h+=`<div class="s"><div class="st"><span>Payments</span><span class="c">no HTLC traffic yet</span></div>`;
  h+=`<p class="mu">No HTLCs have flowed through this LSP yet.  Drive payments via the cheat-engine campaign (<code>superscalar_client --send DEST:AMT:PREIMAGE</code>) or restart the LSP with <code>--demo</code> to populate.  Once HTLCs are present this tab groups them by <code>payment_hash</code> to surface MPP splits, forwarding, and per-channel rollups.</p>`;
  h+=`</div>`;
  return h;
 }
 // Aggregate counts
 const stateCounts={};
 for(const x of allHtlcs)stateCounts[x.state||'unknown']=(stateCounts[x.state||'unknown']||0)+1;
 const totalAmt=allHtlcs.reduce((a,x)=>a+(x.amount||0),0);
 const succN=(stateCounts.fulfilled||0);
 const failN=(stateCounts.failed||0);
 const activeN=(stateCounts.active||0)+(stateCounts.offered||0)+(stateCounts.received||0)+(stateCounts.pending||0);
 // Per-channel rollup
 const byChan={};
 for(const x of allHtlcs){
  const cid=x.channel_id;if(cid==null)continue;
  if(!byChan[cid])byChan[cid]={cid,sent:0,recv:0,vol_out:0,vol_in:0,succ:0,fail:0,total:0};
  const r=byChan[cid];r.total++;
  if(x.direction==='offered'){r.sent++;r.vol_out+=(x.amount||0);}
  else if(x.direction==='received'){r.recv++;r.vol_in+=(x.amount||0);}
  if(x.state==='fulfilled')r.succ++;
  if(x.state==='failed')r.fail++;
 }
 let h='';
 // Summary card
 h+=`<div class="s"><div class="st"><span>Payment Activity</span><span class="c">${payments.length} unique payment(s), ${allHtlcs.length} HTLC(s) tracked</span></div>`;
 h+=`<div class="kv">`;
 h+=`<div class="ki"><span class="k">Total HTLCs</span><span class="v">${allHtlcs.length}</span></div>`;
 h+=`<div class="ki"><span class="k">Unique payments</span><span class="v">${payments.length}</span></div>`;
 h+=`<div class="ki"><span class="k">Volume routed</span><span class="v">${fs(totalAmt)}</span></div>`;
 if(activeN)h+=`<div class="ki"><span class="k">In-flight</span><span class="b w">${activeN}</span></div>`;
 if(succN)h+=`<div class="ki"><span class="k">Fulfilled</span><span class="b ok">${succN}</span></div>`;
 if(failN)h+=`<div class="ki"><span class="k">Failed</span><span class="b dn">${failN}</span></div>`;
 h+=`<div class="ki"><span class="k">Open invoices</span><span class="v">${invoices.filter(i=>i.active).length}</span></div>`;
 h+=`<div class="ki"><span class="k">Bridge forwards</span><span class="v">${origins.length}</span></div>`;
 h+=`</div></div>`;
 // Per-channel breakdown
 if(Object.keys(byChan).length){
  h+=`<div class="s"><div class="st"><span>Per-Channel Activity</span></div>`;
  h+=`<table><tr><th>CH</th><th class="r">HTLCs</th><th class="r">Sent</th><th class="r">Recv</th><th class="r">Vol out</th><th class="r">Vol in</th><th class="r">Success</th></tr>`;
  const cks=Object.keys(byChan).sort((a,b)=>parseInt(a)-parseInt(b));
  for(const k of cks){const c=byChan[k];
   const rate=c.total?Math.round(100*c.succ/c.total):0;
   const cls=rate>=95?'b ok':rate>=80?'b i':rate>0?'b w':'b';
   h+=`<tr><td>${c.cid}</td><td class="r">${c.total}</td><td class="r">${c.sent}</td><td class="r">${c.recv}</td><td class="r">${fs(c.vol_out)}</td><td class="r">${fs(c.vol_in)}</td><td class="r"><span class="${cls}" style="font-size:9px">${c.succ}/${c.total} (${rate}%)</span></td></tr>`;
  }
  h+=`</table></div>`;
 }
 // Per-payment table (MPP-aware)
 if(payments.length){
  // Sort: in-flight first, then by HTLC count (MPP) descending
  const stateOrder={offered:0,received:0,active:0,pending:0,fulfilled:1,failed:2};
  payments.sort((a,b)=>{
   const al=a.htlcs.concat(a.historical),bl=b.htlcs.concat(b.historical);
   const ast=(al[0]||{}).state||'',bst=(bl[0]||{}).state||'';
   const ao=stateOrder[ast]??3,bo=stateOrder[bst]??3;
   if(ao!==bo)return ao-bo;
   return bl.length-al.length;
  });
  h+=`<div class="s"><div class="st"><span>Payments</span><span class="c">${payments.length}, sorted in-flight first</span></div>`;
  h+=`<table><tr><th>Payment Hash</th><th class="r">HTLCs</th><th class="r">Amount</th><th>Direction</th><th>Origin</th><th>State</th><th class="r">CLTV</th></tr>`;
  for(const p of payments.slice(0,50)){
   const all=p.htlcs.concat(p.historical);
   const amt=all.reduce((a,x)=>a+(x.amount||0),0);
   const states=new Set(all.map(x=>x.state).filter(x=>x));
   const dirs=new Set(all.map(x=>x.direction).filter(x=>x));
   const cltvs=all.map(x=>x.cltv_expiry).filter(x=>x);
   const mppBadge=all.length>1?`<span class="b i" style="font-size:9px" title="multi-part payment">${all.length} parts</span>`:`${all.length}`;
   let origin='—';
   if(p.invoices.length)origin=`<span title="LSP-issued invoice">invoice (inbound)</span>`;
   else if(p.origins.length)origin=`<span title="forwarded via htlc_origins">bridge forward</span>`;
   else if(dirs.has('offered')&&!dirs.has('received'))origin='outbound (LSP-paid)';
   else if(dirs.has('received')&&!dirs.has('offered'))origin='inbound';
   const dir=dirs.size===1?Array.from(dirs)[0]:dirs.size>1?'mixed':'—';
   let stateText,stateCls;
   if(states.size===0){stateText='—';stateCls='b';}
   else if(states.size===1){stateText=Array.from(states)[0];stateCls=stateText==='fulfilled'?'b ok':stateText==='failed'?'b dn':'b w';}
   else{stateText=`${states.size} states`;stateCls='b w';}
   h+=`<tr><td class="h">${th(p.hash)}</td><td class="r">${mppBadge}</td><td class="r">${fs(amt)}</td><td>${dir}</td><td>${origin}</td><td><span class="${stateCls}" style="font-size:9px">${stateText}</span></td><td class="r">${cltvs.length?Math.max.apply(null,cltvs):'—'}</td></tr>`;
  }
  if(payments.length>50)h+=`<tr><td colspan="7" class="mu">… and ${payments.length-50} more</td></tr>`;
  h+=`</table></div>`;
 }
 // LSP forwarding stats
 if(origins.length){
  const active=origins.filter(o=>o.active).length;
  const done=origins.length-active;
  const fwdPayments=payments.filter(p=>p.origins.length>0);
  let fwdVol=0;
  for(const p of fwdPayments)fwdVol+=p.htlcs.concat(p.historical).reduce((a,x)=>a+(x.amount||0),0);
  h+=`<div class="s"><div class="st"><span>LSP Forwarding</span><span class="c">${origins.length} bridge record(s)</span></div>`;
  h+=`<div class="kv">`;
  h+=`<div class="ki"><span class="k">Active forwards</span><span class="b w">${active}</span></div>`;
  h+=`<div class="ki"><span class="k">Completed</span><span class="b ok">${done}</span></div>`;
  h+=`<div class="ki"><span class="k">Unique fwd payments</span><span class="v">${fwdPayments.length}</span></div>`;
  h+=`<div class="ki"><span class="k">Volume forwarded</span><span class="v">${fs(fwdVol)}</span></div>`;
  h+=`</div></div>`;
 }
 // Client-side invoice ledger (when available)
 if(clInvoices.length){
  const paid=clInvoices.filter(i=>i.state==='paid').length;
  const open=clInvoices.length-paid;
  h+=`<div class="s"><div class="st"><span>Client Invoice Ledger</span><span class="c">${clInvoices.length} invoice(s)</span></div>`;
  h+=`<div class="kv">`;
  h+=`<div class="ki"><span class="k">Open</span><span class="b w">${open}</span></div>`;
  h+=`<div class="ki"><span class="k">Paid</span><span class="b ok">${paid}</span></div>`;
  h+=`</div></div>`;
 }
 return h;
}

// === TAB: Protocol Log ===
function rProtocol(D){
 const db=D.databases||{},lsp=db.lsp||{},msgs=lsp.wire_messages||[];
 let h='';
 // Events section (formerly the standalone Events tab — merged here so the
 // operator log is in one place).  Auto-hides when D.events is empty (the
 // typical production case where only --demo populates the synthetic
 // event stream).  Wire-level firehose continues below; this is the
 // narrative summary layer.
 const ev=D.events||[];
 if(ev.length){
  h+=`<div class="s"><div class="st"><span>Events</span><span class="c">${ev.length} recent</span></div>`;
  h+=`<div class="el">`;
  for(const e of ev.slice().reverse()){
   h+=`<div class="ew"><span class="et">${e.time}</span><span class="em">${e.msg}</span></div>`;
  }
  h+=`</div>`;
  h+=`<p class="mu" style="font-size:10px;margin-top:4px">Narrative summaries.  See raw wire messages below for the protocol-level view.</p>`;
  h+=`</div>`;
 }
 const catColor=(name)=>{
  const n=(name||'').toUpperCase();
  if(n.startsWith('CHANNEL')||n.startsWith('UPDATE')||n.startsWith('COMMITMENT')||n.startsWith('REVOKE'))return'color:#3fb950';
  if(n.startsWith('FACTORY')||n.startsWith('NONCE')||n.startsWith('PSIG')||n.startsWith('ALL_NONCES'))return'color:#58a6ff';
  if(n.startsWith('BRIDGE'))return'color:#f0883e';
  if(n.startsWith('CLOSE'))return'color:#d2a8ff';
  if(n.startsWith('HELLO')||n.startsWith('RECONNECT'))return'color:#79c0ff';
  if(n.startsWith('INVOICE')||n.startsWith('CREATE_INVOICE')||n.startsWith('REGISTER'))return'color:#d29922';
  if(n.startsWith('PTLC'))return'color:#e6db74';
  if(n==='ERROR')return'color:#f85149';
  return'color:#8b949e';
 };
 h+=`<div class="s"><div class="st"><span>Wire Messages</span><span class="c" id="proto-cnt">${msgs.length}</span></div>`;
 // Polish item 1: filter inputs that toggle row visibility in-place (no
 // re-render \u2014 preserves keyboard focus across the 5s auto-refresh).
 const inp='background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:4px 8px;border-radius:4px;font-family:inherit;font-size:11px';
 h+=`<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap;font-size:11px">`;
 h+=`<span class="mu">filter:</span>`;
 h+=`<input id="pf-msg" type="text" placeholder="msg name (e.g. NONCE)" value="${(pfMsg||'').replace(/"/g,'&quot;')}" style="${inp};width:200px" oninput="applyProtoFilter()">`;
 h+=`<select id="pf-dir" style="${inp}" onchange="applyProtoFilter()">`;
 for(const opt of [['all','any direction'],['sent','sent only'],['received','received only']]){
  h+=`<option value="${opt[0]}"${pfDir===opt[0]?' selected':''}>${opt[1]}</option>`;
 }
 h+=`</select>`;
 h+=`<input id="pf-peer" type="text" placeholder="peer" value="${(pfPeer||'').replace(/"/g,'&quot;')}" style="${inp};width:120px" oninput="applyProtoFilter()">`;
 if(pfMsg||pfDir!=='all'||pfPeer){
  h+=`<button onclick="pfMsg='';pfDir='all';pfPeer='';document.getElementById('pf-msg').value='';document.getElementById('pf-dir').value='all';document.getElementById('pf-peer').value='';applyProtoFilter()" style="${inp};cursor:pointer">clear</button>`;
 }
 h+=`</div>`;
 if(!msgs.length)h+=`<p class="mu">No wire messages logged yet. Messages appear when LSP/client communicate with --db enabled.</p>`;
 else{h+=`<table><thead><tr><th>Time</th><th>Dir</th><th>Type</th><th>Peer</th><th>Payload</th></tr></thead><tbody id="proto-rows">`;
  for(const m of msgs){
   const arrow=m.direction==='sent'?'\u2192':'\u2190';
   const dirC=m.direction==='sent'?'color:#f0883e':'color:#3fb950';
   const ts2=m.timestamp?new Date(m.timestamp*1000).toLocaleTimeString():'\u2014';
   const pay=(m.payload_summary||'').length>80?(m.payload_summary.slice(0,80)+'\u2026'):m.payload_summary||'';
   const peerAttr=(m.peer||'').replace(/"/g,'&quot;');
   const nameAttr=(m.msg_name||'').replace(/"/g,'&quot;');
   h+=`<tr data-msg="${nameAttr}" data-dir="${m.direction||''}" data-peer="${peerAttr}"><td style="white-space:nowrap">${ts2}</td><td style="${dirC};font-weight:600">${arrow} ${m.direction||'?'}</td><td style="${catColor(m.msg_name)};font-weight:600">${m.msg_name||'0x'+((m.msg_type||0).toString(16))}</td><td>${m.peer||'\u2014'}</td><td class="h" style="font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${(m.payload_summary||'').replace(/"/g,'&quot;')}">${pay}</td></tr>`;}
  h+=`</tbody></table>`;}
 h+=`</div>`;
 return h;
}

// === TAB: Lightning Network ===
function rLightning(D){
 const cln=D.cln||{},br=D.bridge;
 let h='';
 for(const[key,label]of[['a','CLN Node A (SuperScalar plugin)'],['b','CLN Node B (vanilla)']]) {
  const n=cln[key]||{}; h+=`<div class="s"><div class="st">${label}</div>`;
  if(!n.available){h+=`<p class="mu">Unavailable</p></div>`;continue;}
  h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">ID</span><span class="v h">${n.id||'?'}</span></div><div class="ki"><span class="k">Alias</span><span class="v">${n.alias||'\u2014'}</span></div><div class="ki"><span class="k">Version</span><span class="v">${n.version||'?'}</span></div><div class="ki"><span class="k">Height</span><span class="v">${n.blockheight||'?'}</span></div><div class="ki"><span class="k">Fees collected</span><span class="v">${fm(n.fees_collected_msat)}</span></div></div>`;
  // Peers
  const peers=n.peers||[];
  h+=`<div class="st" style="margin-top:8px"><span>Peers</span><span class="c">${peers.length}</span></div>`;
  if(peers.length){h+=`<table><tr><th></th><th>Peer ID</th><th>Address</th></tr>`;
   for(const p of peers){h+=`<tr><td><span class="conn ${p.connected?'on':'off'}"></span></td><td class="h">${p.id}</td><td>${(p.netaddr||[]).join(', ')||'\u2014'}</td></tr>`;}
   h+=`</table>`;}
  // Channels detail
  const chs=n.channels||[];
  h+=`<div class="st" style="margin-top:8px"><span>Channels</span><span class="c">${chs.length}</span></div>`;
  if(chs.length){h+=`<table><tr><th>State</th><th>SCID</th><th class="r">Capacity</th><th class="r">Local</th><th class="r">Remote</th><th>Bal</th><th class="r">Spendable</th><th class="r">Receivable</th><th class="r">Fee</th><th>CSV</th></tr>`;
   for(const c of chs){const t=typeof c.total_msat==='string'?parseInt(c.total_msat):(c.total_msat||0);const l=typeof c.to_us_msat==='string'?parseInt(c.to_us_msat):(c.to_us_msat||0);
    h+=`<tr><td>${sb(c.state)}</td><td>${c.short_channel_id||'\u2014'}</td><td class="r">${fm(c.total_msat)}</td><td class="r">${fm(c.to_us_msat)}</td><td class="r">${fm(t-l)}</td><td style="min-width:50px">${bar(l,t-l)}</td><td class="r">${fm(c.spendable_msat)}</td><td class="r">${fm(c.receivable_msat)}</td><td class="r">${c.fee_base_msat||0}+${c.fee_proportional_millionths||0}ppm</td><td>${c.to_self_delay||'\u2014'}</td></tr>`;}
   h+=`</table>`;}
  // Forwards
  const fws=n.forwards||[];
  if(fws.length){h+=`<div class="st" style="margin-top:8px"><span>Recent Forwards</span><span class="c">${fws.length}</span></div>`;
   h+=`<table><tr><th>In</th><th>Out</th><th class="r">In amt</th><th class="r">Out amt</th><th class="r">Fee</th><th>Status</th></tr>`;
   for(const f of fws.slice().reverse())h+=`<tr><td>${f.in_channel||'?'}</td><td>${f.out_channel||'?'}</td><td class="r">${fm(f.in_msat)}</td><td class="r">${fm(f.out_msat)}</td><td class="r">${fm(f.fee_msat)}</td><td>${sb(f.status)}</td></tr>`;
   h+=`</table>`;}
  // Invoices
  const invs=n.invoices||[];
  if(invs.length){h+=`<div class="st" style="margin-top:8px"><span>Invoices</span><span class="c">${invs.length}</span></div>`;
   h+=`<table><tr><th>Label</th><th>Status</th><th class="r">Amount</th><th>Paid</th><th>Hash</th></tr>`;
   for(const i of invs.slice().reverse())h+=`<tr><td>${i.label}</td><td>${sb(i.status)}</td><td class="r">${fm(i.amount_msat)}</td><td>${i.paid_at?ta(i.paid_at)+' ago':'\u2014'}</td><td class="h">${ts(i.payment_hash)}</td></tr>`;
   h+=`</table>`;}
  h+=`</div>`;
 }
 // Bridge
 h+=`<div class="s"><div class="st">Bridge (CLN \u2194 SuperScalar)</div>`;
 if(!br)h+=`<p class="mu">No bridge data</p>`;
 else h+=`<div class="kv"><div class="ki"><span class="k">LSP</span>${bg(br.lsp_connected,'Connected','Disconnected')}</div><div class="ki"><span class="k">CLN Plugin</span>${bg(br.plugin_connected,'Connected','Disconnected')}</div><div class="ki"><span class="k">Pending inbound</span><span class="v">${br.pending_inbound} HTLCs</span></div><div class="ki"><span class="k">Next HTLC ID</span><span class="v">${br.next_htlc_id}</span></div><div class="ki"><span class="k">Next req ID</span><span class="v">${br.next_request_id}</span></div></div>`;
 h+=`</div>`;
 return h;
}

// === TAB: Watchtower ===
function rWatchtower(D){
 const db=D.databases||{},lsp=db.lsp||{},cl=db.client||{};
 let h='';
 h+=`<div class="s"><div class="st">Watchtower + Revocations</div>`;
 h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">LSP watched</span><span class="v">${lsp.watchtower_count||0} commitments</span></div><div class="ki"><span class="k">Client watched</span><span class="v">${cl.watchtower_count||0} commitments</span></div><div class="ki"><span class="k">LSP revocations</span><span class="v">${lsp.revocation_count||0}</span></div><div class="ki"><span class="k">Client revocations</span><span class="v">${cl.revocation_count||0}</span></div>`;
 const byC={};(lsp.old_commitments||[]).forEach(o=>{byC[o.channel_id]=(byC[o.channel_id]||0)+1;});
 for(const[ch,cnt]of Object.entries(byC))h+=`<div class="ki"><span class="k">CH${ch}</span><span class="v">${cnt} old</span></div>`;
 h+=`</div>`;
 // Revocations per channel
 const rv=lsp.revocations_by_channel||[];
 if(rv.length){h+=`<div class="st">Revocations by Channel</div><table><tr><th>CH</th><th class="r">Revoked commits</th><th>Penalty capacity</th></tr>`;
  for(const r of rv)h+=`<tr><td>${r.channel_id}</td><td class="r">${r.cnt}</td><td>${prog(Math.min(100,r.cnt*10),'pb')}</td></tr>`;
  h+=`</table>`;}
 // Old commitments table
 const oc=lsp.old_commitments||[];
 if(oc.length){h+=`<div class="st" style="margin-top:8px"><span>Old Commitments (breach detection)</span><span class="c">${oc.length}</span></div>`;
  h+=`<table><tr><th>CH</th><th>Commit#</th><th>TXID</th><th>On-chain</th><th>Vout</th><th class="r">To-Local</th></tr>`;
  for(const o of oc.slice(0,15)){const jitBadge=o.channel_id>=4?' <span class="b i">JIT</span>':'';
   h+=`<tr><td>${o.channel_id}${jitBadge}</td><td>${o.commit_num}</td><td class="h">${th(o.txid)}</td><td>${txBadge(D,o.txid)}</td><td>${o.to_local_vout??'\u2014'}</td><td class="r">${fs(o.to_local_amount)}</td></tr>`;}
  if(oc.length>15)h+=`<tr><td colspan="6" class="mu">\u2026 and ${oc.length-15} more</td></tr>`;
  h+=`</table>`;}
 // Old commitment HTLCs (breach penalty HTLCs)
 const och=lsp.old_commitment_htlcs||[];
 if(och.length){h+=`<div class="st" style="margin-top:8px"><span>Old Commitment HTLCs (breach penalty)</span><span class="c">${och.length}</span></div>`;
  h+=`<table><tr><th>CH</th><th>Commit#</th><th>HTLC#</th><th>Dir</th><th class="r">Amount</th><th>Hash</th><th class="r">CLTV</th></tr>`;
  for(const x of och){const dc=x.direction==='offered'?'color:#f0883e':'color:#3fb950';
   h+=`<tr><td>${x.channel_id}</td><td>${x.commit_num}</td><td>${x.htlc_index}</td><td style="${dc}">${x.direction||'?'}</td><td class="r">${fs(x.amount)}</td><td class="h">${th(x.payment_hash)}</td><td class="r">${x.cltv_expiry??'\u2014'}</td></tr>`;}
  h+=`</table>`;}
 // Factory revocation secrets count
 const frs=lsp.factory_revocations_by_factory||[];
 if(frs.length){h+=`<div class="st" style="margin-top:8px"><span>Factory Revocation Secrets</span></div>`;
  h+=`<div class="kv">`;
  for(const r of frs)h+=`<div class="ki"><span class="k">Factory #${r.factory_id}</span><span class="v">${r.cnt} epochs revoked</span></div>`;
  h+=`</div>`;}
 // Watchtower pending penalty TXs
 const wp=lsp.watchtower_pending||[];
 if(wp.length){h+=`<div class="st" style="margin-top:8px"><span>Watchtower Pending Penalties</span><span class="c">${wp.length}</span></div>`;
  h+=`<table><tr><th>TXID</th><th>On-chain</th><th class="r">Anchor Vout</th><th class="r">Anchor Amount</th><th class="r">Mempool Cycles</th><th class="r">Fee Bumps</th></tr>`;
  for(const w of wp)h+=`<tr><td class="h">${th(w.txid)}</td><td>${txBadge(D,w.txid)}</td><td class="r">${w.anchor_vout}</td><td class="r">${fs(w.anchor_amount)}</td><td class="r">${w.cycles_in_mempool}</td><td class="r">${w.bump_count}</td></tr>`;
  h+=`</table>`;}
 // Breach detections (schema v29 PR #189): rows the watchtower wrote when
 // it observed a stale commitment broadcast and responded with penalty TX.
 // Authoritative breach-response record — distinct from old_commitments
 // (the catalog of "would-be-cheats" we have penalty bytes for).
 const bd=lsp.breach_detections||[];
 if(bd.length){h+=`<div class="st" style="margin-top:8px"><span>Detected Breaches</span><span class="c">${bd.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th>CH</th><th>Commit#</th><th>Stale TXID</th><th>Height</th><th>Response</th><th>When</th></tr>`;
  for(const r of bd){
   const resp=r.response_txid?`<span class="b ok" style="font-size:9px" title="penalty broadcast: ${r.response_txid}">penalty broadcast</span>`:`<span class="b w" style="font-size:9px">pending</span>`;
   h+=`<tr><td>${r.id}</td><td>${r.channel_id}</td><td>${r.expected_commit_num}</td><td class="h">${th(r.txid_seen)}</td><td class="r">${r.height_seen}</td><td>${resp}</td><td>${ta(r.timestamp)}</td></tr>`;
  }
  h+=`</table>`;}
 // Reorg events (schema v29 PR #189): chain reorg detections + entries-reset
 // counts.  Useful for forensic correlation when an operator asks "did a
 // reorg invalidate any of the state we're watching?"
 const reorgs=lsp.reorg_events||[];
 if(reorgs.length){h+=`<div class="st" style="margin-top:8px"><span>Reorg Events</span><span class="c">${reorgs.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th class="r">Old tip</th><th class="r">New tip</th><th class="r">Depth</th><th class="r">Entries reset</th><th>When</th></tr>`;
  for(const r of reorgs){
   const depth=Math.abs((r.old_tip||0)-(r.new_tip||0));
   const dcls=depth>=6?'b dn':depth>=2?'b w':'b i';
   h+=`<tr><td>${r.id}</td><td class="r">${r.old_tip}</td><td class="r">${r.new_tip}</td><td class="r"><span class="${dcls}" style="font-size:9px">${depth}</span></td><td class="r">${r.n_entries_reset}</td><td>${ta(r.timestamp)}</td></tr>`;
  }
  h+=`</table>`;}
 h+=`</div>`;
 // Broadcast log (separate card)
 const bl=lsp.broadcast_log||[];
 if(bl.length){h+=`<div class="s"><div class="st"><span>Broadcast Log</span><span class="c">${bl.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th>TXID</th><th>On-chain</th><th>Source</th><th>Result</th><th>Time</th></tr>`;
  for(const b of bl){const rc=b.result==='success'||b.result==='ok'?'b ok':'b dn';
   h+=`<tr><td>${b.id}</td><td class="h">${th(b.txid)}</td><td>${txBadge(D,b.txid)}</td><td>${b.source||'\u2014'}</td><td><span class="${rc}">${b.result||'?'}</span></td><td>${ta(b.broadcast_time)}</td></tr>`;}
  h+=`</table></div>`;}
 return h;
}

// === TAB: TX Inventory (preparedness ledger) ===
// Renders every signed-bytes-bearing pre-signed TX the LSP holds, grouped
// by category, plus a top-level "defense readiness" headline.  Surfaces
// the operationally-dangerous gaps (penalty TXs, burn TXs, HTLC resolution
// TXs) that aren't in the schema today.
// P3: render a small confirmation badge for a given txid.  Uses
// tx_enrichment cache populated server-side.  Unknown → grey "—".
// P1: 'expected' parameter — distinguishes TXs we *expect* to broadcast
// (funding, jit, broadcast_log entries, watchtower-pending penalty bumps —
// "not on chain" = real warning) from TXs that are pre-signed *defense*
// kept in reserve (factory tree, PS chains, poison TXs — "not on chain"
// is the normal happy-path state, so render neutral instead of red).
// Default 'broadcast' preserves the original red-when-missing semantics
// for callers that haven't migrated.
function txBadge(D, txid, expected){
 if(!txid||txid==='?'||txid==='—')return '';
 const e=(D.tx_enrichment||{})[txid];
 expected = expected || 'broadcast';
 if(!e)return `<span class="b" style="background:#21262d;color:#484f58;font-size:9px">unchecked</span>`;
 if(e.never_seen){
  if(expected==='reserve'){
   return `<span class="b i" style="font-size:9px" title="signed and persisted on disk; not broadcast (held in reserve for unilateral exit)">signed, in reserve</span>`;
  }
  return `<span class="b dn" style="font-size:9px">not on chain</span>`;
 }
 if(e.in_mempool)return `<span class="b w" style="font-size:9px">mempool</span>`;
 const c=e.confirmations||0;
 const cls=c>=6?'b ok':c>=1?'b i':'b w';
 return `<span class="${cls}" style="font-size:9px">${c} conf${e.vsize?` · ${e.vsize}vB`:''}</span>`;
}

function rTxInventory(D){
 const db=D.databases||{},lsp=db.lsp||{};
 const facs=lsp.factories||[];
 const cl=db.client||{};
 const tn=lsp.tree_nodes_bytes||[];
 const fundBytes=lsp.factory_funding_bytes||[];
 const psChain=lsp.ps_leaf_chains||[];
 const psSub=lsp.ps_subfactory_chains||[];
 const psInit=lsp.ps_initial_signed_states||[];
 // D1: distribution_txs and signed_commitments are persisted CLIENT-side by
 // design (the inverted-timelock recovery TX must reach clients so they can
 // broadcast at CLTV timeout without LSP cooperation; commitment sigs are
 // each side's own).  Merge LSP + client views — in practice the client.db
 // is where the rows actually live.
 const sigCom=[...(lsp.signed_commitments||[]),...(cl.signed_commitments||[])];
 const distTx=[...(lsp.distribution_txs||[]),...(cl.distribution_txs||[])];
 const jits=lsp.jit_channels||[];
 const wtPending=lsp.watchtower_pending||[];
 const pendSweeps=lsp.pending_sweeps||[];
 const chans=lsp.channels||[];

 // Aggregate counts: expected vs actual signed (P1: corrected math)
 const fundingSigned=fundBytes.filter(r=>r.has_funding_bytes).length;
 const fundingExpected=facs.length;
 const treeSigned=tn.filter(r=>r.has_bytes).length;
 const treeExpected=tn.length;
 const psChainSigned=psChain.length;
 const psSubSigned=psSub.length;
 const psInitSigned=psInit.length;
 // P1: chain[0] expected = count of PS leaf nodes + sub-factory nodes
 // (one chain[0] origin per node), derived from tree_nodes structure.
 const psNodeCounts=lsp.ps_node_counts||[];
 const psInitExpected=psNodeCounts.reduce((a,r)=>a+(r.ps_leaf_count||0)+(r.subfactory_count||0),0);
 const psPoisonExpected=psChain.length+psSub.length;
 const psPoisonHave=psChain.filter(r=>r.has_poison).length+psSub.filter(r=>r.has_poison).length;
 const comSigned=sigCom.filter(r=>r.has_bytes).length;
 // P1: channel commits expected = channels with commitment_number > 0,
 // i.e. channels that have actually exchanged state.  commit-0 just-opened
 // channels have nothing to sign yet, so they shouldn't count as missing.
 const chansCommitted=lsp.channels_committed||[];
 const comExpected=chansCommitted.reduce((a,r)=>a+(r.channels_with_commits||0),0);
 const distSigned=distTx.filter(r=>r.has_bytes).length;
 const distExpected=facs.length;
 const jitSigned=jits.length;
 const totalSigned=fundingSigned+treeSigned+psChainSigned+psInitSigned+psSubSigned+psPoisonHave+comSigned+distSigned+jitSigned;
 const totalExpected=fundingExpected+treeExpected+psChainSigned+psInitExpected+psSubSigned+psPoisonExpected+comExpected+distExpected+jitSigned;
 const readiness=totalExpected?Math.round(100*totalSigned/totalExpected):0;
 const readyCls=readiness===100?'b ok':readiness>=80?'b i':'b w';

 let h='';
 // Defense readiness headline
 h+=`<div class="s"><div class="st"><span>Defense Readiness</span><span class="c">unilateral-exit preparedness ledger</span></div>`;
 h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">Signed &amp; persisted</span><span class="${readyCls}" style="font-size:14px;padding:2px 12px">${totalSigned}/${totalExpected} (${readiness}%)</span></div></div>`;
 h+=`<p class="mu" style="margin-top:4px;font-size:11px">Counts pre-signed TXs the LSP has on disk vs the count expected for full unilateral-exit defense.  100% = every counterparty / watchtower / client can broadcast their copy of the exit/penalty/recovery chain without any further signing round.</p>`;
 h+=`</div>`;

 // Category breakdown table
 h+=`<div class="s"><div class="st"><span>By Category</span></div>`;
 h+=`<table><tr><th>Category</th><th>Stored in</th><th class="r">Signed</th><th class="r">Expected</th><th>Coverage</th><th>Who broadcasts</th></tr>`;
 const cat=(name,table,signed,expected,who,note)=>{
  const pct=expected?Math.round(100*signed/expected):0;
  const cls=expected===0?'b i':pct===100?'b ok':pct>=80?'b i':pct>0?'b w':'b dn';
  const label=expected===0?'n/a':`${signed}/${expected} (${pct}%)`;
  const noteHtml=note?` <span class="mu" style="font-size:9px" title="${note}">ⓘ</span>`:'';
  h+=`<tr><td>${name}${noteHtml}</td><td><code>${table}</code></td><td class="r">${signed}</td><td class="r">${expected}</td><td><span class="${cls}">${label}</span></td><td>${who}</td></tr>`;
 };
 cat('Funding TX',           'factories.funding_tx_hex',          fundingSigned, fundingExpected, 'LSP');
 cat('Factory tree TXs',     'tree_nodes.signed_tx_hex',          treeSigned,    treeExpected,    'LSP or client');
 cat('PS chain[0] (initial)','ps_initial_signed_states.signed_tx_hex', psInitSigned, psInitExpected, 'LSP or client');
 cat('PS leaf chain[1..N]',  'ps_leaf_chains.signed_tx_hex',      psChainSigned, psChainSigned,   'LSP or client');
 cat('PS sub-factory chain', 'ps_subfactory_chains.signed_tx_hex',psSubSigned,   psSubSigned,     'LSP or client');
 cat('Poison TXs (trustless)','ps_*_chains.poison_tx_hex',         psPoisonHave,  psPoisonExpected,'Watchtower');
 // Channel commitments: signed_commitments is PRIMARY KEY (channel_id) on
 // the client side, so each client's DB holds exactly one row (the latest
 // signed commit for THAT client's channel).  The dashboard reads a single
 // --client-db, so it can only see one client's row out of N — not a
 // signing failure, just a single-client view.  Multi-client.db aggregation
 // would close the gap (separate PR).
 cat('Channel commitments',  'signed_commitments (client-side)',  comSigned,     comExpected,     'Side holder', `Per-client schema (PRIMARY KEY channel_id) — dashboard reads one --client-db, so this shows 1-of-N until multi-POV PR lands. Not a signing failure.`);
 cat('Distribution TX (recovery)','distribution_txs (client-side)', distSigned,   distExpected,    'ANY client at CLTV timeout');
 cat('JIT channel funding',  'jit_channels.funding_tx_hex',       jitSigned,     jitSigned,       'LSP');
 h+=`</table></div>`;

 // Schema gaps (TX types that exist in protocol but have no persistent home)
 // PR #181 closed the penalty-TX gap (schema v25: old_commitments
 // .signed_penalty_tx_hex).  The row below reads live coverage from the
 // new column when present and degrades to "in memory only" against
 // pre-#181 LSPs (column missing → persisted reads 0).
 const ocov=lsp.old_commitments_coverage||{total:0,persisted:0};
 const ocPersist=ocov.persisted||0, ocTot=ocov.total||0;
 let penRow;
 if(ocTot===0){
  penRow=`<tr><td>Penalty TXs (revocation breach response)</td><td><span class="b i">n/a yet</span></td><td>No revoked commitments to defend against in the current data.  Once revocations arrive, the LSP persists penalty bytes to <code>old_commitments.signed_penalty_tx_hex</code> (schema v25).</td></tr>`;
 } else if(ocPersist===0){
  penRow=`<tr><td>Penalty TXs (revocation breach response)</td><td><span class="b w">in memory only (${ocTot} entries)</span></td><td>Pre-#181 LSP build: <code>old_commitments.signed_penalty_tx_hex</code> column missing.  After upgrade, broadcast bytes survive LSP restart instead of needing reconstruction.</td></tr>`;
 } else if(ocPersist===ocTot){
  penRow=`<tr><td>Penalty TXs (revocation breach response)</td><td><span class="b ok">persisted ✓ (${ocPersist}/${ocTot})</span></td><td>Schema v25 active: every revoked commitment has its signed penalty TX bytes on disk.  Survives LSP restart without rebuild from secrets.</td></tr>`;
 } else {
  const pct=Math.round(100*ocPersist/ocTot);
  penRow=`<tr><td>Penalty TXs (revocation breach response)</td><td><span class="b w">partial: ${ocPersist}/${ocTot} (${pct}%)</span></td><td>Some entries persisted, ${ocTot-ocPersist} still in memory only — likely a mix of pre-upgrade entries and new ones.  Will normalize as old entries age out / get re-registered.</td></tr>`;
 }
 h+=`<div class="s"><div class="st"><span>Schema gaps — pre-signed TXs that are not persisted anywhere</span><span class="c">operational risk</span></div>`;
 h+=`<table><tr><th>TX type</th><th>Status</th><th>Risk</th></tr>`;
 h+=penRow;
 h+=`<tr><td>HTLC sweep TXs (per-output penalty)</td><td><span class="b i">lazy-built per-cycle</span></td><td>Different lifecycle from the commitment penalty above — built per watchtower cycle inside <code>watchtower_check()</code>, not pre-built at registration.  Persistence would require moving the build to registration time first (LSP-side refactor, intentionally deferred per PR #181).</td></tr>`;
 h+=`<tr><td>L-stock burn TXs (OP_RETURN destruction)</td><td><span class="b i">constructed on-demand</span></td><td>Rebuilt from <code>factory_revocation_secrets</code> + <code>old_commitments</code> on need — works but no preparedness check available</td></tr>`;
 h+=`<tr><td>HTLC success/timeout resolution TXs</td><td><span class="b i">constructed on-demand</span></td><td>Rebuilt from <code>htlcs</code> + commitment data — same as burn</td></tr>`;
 h+=`<tr><td>Cooperative close TX</td><td><span class="b i">negotiated at close time</span></td><td>Expected — single TX, both sides online</td></tr>`;
 h+=`<tr><td>CPFP children</td><td><span class="b i">dynamic</span></td><td>Generated by watchtower budget sweeper at broadcast time</td></tr>`;
 h+=`</table></div>`;

 // Detail: pending sweeps in flight
 if(pendSweeps.length){
  h+=`<div class="s"><div class="st"><span>Pending sweeps in flight</span><span class="c">${pendSweeps.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th>Type</th><th>State</th><th>Source TXID:vout</th><th class="r">Amount</th><th>CH/Factory</th><th class="r">CSV</th><th>Sweep TXID</th></tr>`;
  for(const s of pendSweeps){
   h+=`<tr><td>${s.id}</td><td>${s.sweep_type||'?'}</td><td>${s.state}</td><td class="h">${th(s.source_txid)}:${s.source_vout}</td><td class="r">${fs(s.amount_sats)}</td><td>ch ${s.channel_id}/f ${s.factory_id}</td><td class="r">${s.csv_delay}</td><td class="h">${s.sweep_txid?th(s.sweep_txid):'—'}</td></tr>`;
  }
  h+=`</table></div>`;
 }

 // Watchtower pending detail (penalty TXs in flight)
 if(wtPending.length){
  h+=`<div class="s"><div class="st"><span>Watchtower penalties in flight</span><span class="c">${wtPending.length}</span></div>`;
  h+=`<table><tr><th>TXID</th><th class="r">Anchor vout</th><th class="r">Anchor amount</th><th class="r">Penalty value</th><th class="r">Mempool cycles</th><th class="r">Fee bumps</th></tr>`;
  for(const w of wtPending){
   h+=`<tr><td class="h">${th(w.txid)}</td><td class="r">${w.anchor_vout}</td><td class="r">${fs(w.anchor_amount)}</td><td class="r">${fs(w.penalty_value||0)}</td><td class="r">${w.cycles_in_mempool}</td><td class="r">${w.bump_count}</td></tr>`;
  }
  h+=`</table></div>`;
 }

 return h;
}

// === TAB: Outcomes (13-scenarios map) ===
// Groups broadcast_log entries by source, plus cross-references readiness
// signals (signed-but-not-broadcast TXs) so operators can see at a glance
// which SuperScalar scenarios have fired this session, which are ready to
// fire, and which haven't been exercised.  Sources of truth:
//   - broadcast_log.source : free-form label written at broadcast time
//                            (factory_funding, tree_node_N, response,
//                             burn, poison, penalty, htlc, ptlc, cpfp,
//                             jit_*, rotation_*, ...).
//   - presence of signed bytes in their respective tables = "ready" tile.
function rOutcomes(D){
 const db=D.databases||{},lsp=db.lsp||{},cl=db.client||{};
 const log=lsp.broadcast_log||[];
 // Build a map of source → entries
 const bySrc={};
 for(const r of log){
  const s=(r.source||'unknown').toLowerCase();
  if(!bySrc[s])bySrc[s]=[];
  bySrc[s].push(r);
 }
 // Scenario definitions.  Each tile checks (a) broadcast_log entries
 // matching one or more source prefixes, and (b) optionally a "ready"
 // count from a persisted-bytes signal.
 const matchAny=(prefixes)=>{
  const out=[];
  for(const k of Object.keys(bySrc))
   for(const p of prefixes)
    if(k===p||k.indexOf(p)===0){out.push(...bySrc[k]);break;}
  return out;
 };
 const psChain=lsp.ps_leaf_chains||[];
 const psSub=lsp.ps_subfactory_chains||[];
 const distTx=(lsp.distribution_txs||[]).concat(cl.distribution_txs||[]);
 const jits=lsp.jit_channels||[];
 const facs=lsp.factories||[];
 const lad=lsp.ladder_factories||[];
 const wtPending=lsp.watchtower_pending||[];

 // P2: tile applicability per current deployment shape.  PS leaf advance
 // is k=1-only (in k≥2 sub-factories carry the chains); PS sub-factory
 // advance is k≥2-only.  DW-specific scenarios (per-leaf DW advance,
 // L-stock burn) are arity-1/-2 legacy.  Tiles that don't apply show
 // as 'n/a (different arity)' instead of generic 'not fired' so
 // operators don't read greyness as "something is broken."
 const fc=D.factory_config||{};
 const arityStr=String(fc.arity||'?');
 const subArity=parseInt(fc.ps_subfactory_arity)||1;
 const isPSCanon=arityStr==='3';
 const isDWLegacy=arityStr==='1'||arityStr==='2';
 const isWide=isPSCanon && subArity>=2;
 const isNarrow=isPSCanon && subArity===1;

 const SCEN=[
  {name:'Factory creation', icon:'🏭', sources:['factory_funding'],
   readySignal:facs.length>0?facs.length+' factory(ies)':'',
   blurb:'Funding TX broadcast that seats the factory MuSig2 UTXO on-chain.'},
  {name:'PS leaf advance', icon:'🌿', sources:['ps_advance_leaf','ps_advance_node','ps_advance_pass','ps_advance_fail','ps_leaf'],
   readySignal:psChain.length?psChain.length+' chain entries persisted':'',
   applicable:isPSCanon&&isNarrow,
   notApplicableNote:isWide?'k≥2 deployment uses sub-factory advances instead':isDWLegacy?'DW legacy deployment (arity 1/2) — leaves use decrementing nSequence, not PS chains':'',
   blurb:'lsp_leaf_chain_advance: extends a PS leaf chain[N]→chain[N+1] when liquidity is sold.  --test-ps-advance writes broadcast_log rows with source=ps_advance_{node_N,leaf_N_chain0,pass,fail}.'},
  {name:'PS sub-factory advance', icon:'🌳', sources:['ps_subfactory','sub_factory_advance','subfactory_advance'],
   readySignal:psSub.length?psSub.length+' sub-factory chain entries':'',
   applicable:isWide,
   notApplicableNote:isNarrow?'k=1 deployment uses leaf advances instead (no sub-factories present)':isDWLegacy?'DW legacy deployment (arity 1/2) — no PS chains':'',
   blurb:'lsp_subfactory_chain_advance: extends a k² sub-factory chain (wide leaves).'},
  {name:'DW force-close (tree broadcast)', icon:'⚡', sources:['tree_node_','tree_ok','tree_fail'],
   readySignal:'',
   blurb:'Broadcast of the factory tree from kickoff_root to leaves — full unilateral exit.'},
  {name:'Per-leaf advance (DW)', icon:'🎯', sources:['leaf_advance'],
   readySignal:'',
   applicable:isDWLegacy,
   notApplicableNote:isPSCanon?'PS canonical (arity 3) — leaves use PS chain advance, not DW state':'',
   blurb:'3-of-3 partial advance of one leaf without rolling the root state.'},
  {name:'L-stock burn', icon:'🔥', sources:['burn','l_stock_burn'],
   readySignal:'',
   applicable:isDWLegacy,
   notApplicableNote:isPSCanon?'PS canonical — uses poison TX (tile below) instead of shachain burn':'',
   blurb:'Burn TX broadcast: OP_RETURN destroys L-stock when LSP publishes old state (deterrence).'},
  {name:'Trustless poison redistribute', icon:'🛡', sources:['poison'],
   readySignal:(psChain.filter(r=>r.has_poison).length+psSub.filter(r=>r.has_poison).length)+' poison TXs signed',
   blurb:'Pre-signed poison TX redistributes L-stock / sales-stock to clients on cheat.'},
  {name:'Breach + penalty', icon:'⚔', sources:['penalty','response'],
   readySignal:wtPending.length?wtPending.length+' penalties in flight':'',
   blurb:'Watchtower detects revoked commitment broadcast, broadcasts penalty sweep.'},
  {name:'HTLC force-close', icon:'🪝', sources:['htlc','ptlc'],
   readySignal:'',
   blurb:'HTLC success/timeout TX broadcast when channel force-closes with live HTLCs.'},
  {name:'CLTV timeout distribution', icon:'⏱', sources:['distribution'],
   readySignal:distTx.filter(r=>r.has_bytes).length?distTx.filter(r=>r.has_bytes).length+' distribution TX(s) signed (client-side)':'',
   blurb:'nLockTime\'d recovery TX returns funds to clients at factory CLTV timeout.'},
  {name:'Cooperative close', icon:'🤝', sources:['coop_close','cooperative_close'],
   readySignal:'',
   blurb:'Single negotiated on-chain TX dissolving the factory cooperatively.'},
  {name:'JIT channel', icon:'⚡', sources:['jit_funding','jit_close','jit_'],
   readySignal:jits.length?jits.length+' JIT channels':'',
   blurb:'LSP opens a standalone 2-of-2 channel from its own UTXO when leaf liquidity unavailable.'},
  {name:'Factory rotation', icon:'🔁', sources:['rotation_','rotation'],
   readySignal:lad.length>1?lad.length+' ladder factories':'',
   blurb:'PTLC key turnover + dying-period migration to a fresh factory.'},
  {name:'CPFP fee bump', icon:'⛽', sources:['cpfp'],
   readySignal:'',
   blurb:'CPFP child broadcast to fee-bump a stuck parent (penalty/HTLC/state TX).'},
 ];

 let h='';
 h+=`<div class="s"><div class="st"><span>Scenario Map</span><span class="c">${SCEN.length} SuperScalar structures</span></div>`;
 h+=`<p class="mu" style="font-size:11px;margin-bottom:10px">Each tile is one of the SuperScalar structures from the README, sourced from <code>broadcast_log.source</code> plus presence-of-signed-bytes signals.  Green = fired | Blue = ready (signed bytes persisted, nothing broadcast yet) | Grey = neither | Dimmed = not applicable to this deployment's leaf shape.</p>`;
 // Tile grid
 h+=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px">`;
 for(const sc of SCEN){
  // P2: skip-or-not-applicable check.  If sc.applicable is defined and
  // false, render a 'n/a' tile (dimmer than 'not fired') with the
  // deployment-shape reason in the body.
  const isNA = sc.applicable !== undefined && !sc.applicable;
  const fired=matchAny(sc.sources);
  let state, badge, lastTx='';
  if(isNA){
   state='na'; badge=`<span class="b" style="background:#0d1117;color:#484f58;border:1px solid #21262d">n/a for this deployment</span>`;
   if(sc.notApplicableNote)lastTx=`<div class="mu" style="font-size:10px;margin-top:4px;font-style:italic">${sc.notApplicableNote}</div>`;
  } else if(fired.length>0){
   state='fired'; badge=`<span class="b ok">fired ${fired.length}×</span>`;
   const latest=fired.reduce((a,b)=>(a.broadcast_time||0)>(b.broadcast_time||0)?a:b);
   lastTx=`<div class="kv" style="margin-top:4px;gap:2px 8px"><div class="ki"><span class="k">last</span><span class="v h" style="font-size:10px">${th(latest.txid)}</span></div><div class="ki"><span class="k">at</span><span class="v" style="font-size:10px">${ta(latest.broadcast_time)} ago</span></div></div>`;
  } else if(sc.readySignal){
   state='ready'; badge=`<span class="b i">ready</span>`;
   lastTx=`<div class="mu" style="font-size:10px;margin-top:4px">${sc.readySignal}</div>`;
  } else {
   state='inactive'; badge=`<span class="b" style="background:#21262d;color:#484f58">not fired</span>`;
  }
  const borderColor=state==='fired'?'#3fb950':state==='ready'?'#58a6ff':state==='na'?'#21262d':'#30363d';
  const tileOpacity=state==='na'?'0.55':'1';
  h+=`<div style="border:1px solid ${borderColor};border-radius:6px;padding:8px 10px;background:#0d1117;opacity:${tileOpacity}">`;
  h+=`<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:6px">`;
  h+=`<div><span style="font-size:14px;margin-right:4px">${sc.icon}</span><span style="font-weight:600;font-size:12px">${sc.name}</span></div>`;
  h+=`<div>${badge}</div>`;
  h+=`</div>`;
  h+=`<div class="mu" style="font-size:10px;margin-top:4px">${sc.blurb}</div>`;
  h+=lastTx;
  h+=`</div>`;
 }
 h+=`</div></div>`;
 // Recent broadcasts table (raw broadcast_log) + on-chain badges
 if(log.length){
  h+=`<div class="s"><div class="st"><span>Recent broadcasts</span><span class="c">${log.length}</span></div>`;
  h+=`<table><tr><th>ID</th><th>Source</th><th>Result</th><th>TXID</th><th>On-chain status</th><th>When</th></tr>`;
  for(const r of log){
   const rc=r.result==='ok'?'b ok':r.result==='failed'?'b dn':'b i';
   h+=`<tr><td>${r.id}</td><td><code>${r.source||'?'}</code></td><td><span class="${rc}">${r.result||'?'}</span></td><td class="h">${th(r.txid)}</td><td>${txBadge(D,r.txid)}</td><td>${ta(r.broadcast_time)} ago</td></tr>`;
  }
  h+=`</table></div>`;
 }
 return h;
}

// === TAB: Defense Status (per-failure-mode trustless model coverage) ===
// Renders a tile per documented failure mode in the SuperScalar trustless
// model.  Each tile shows the defense mechanism, current coverage from
// observable DB state, and the risk if the defense itself fails.  Phase 1
// covers 6 tiles with clean DB data sources (see
// DEFENSE_STATUS_PANEL_DESIGN.md in the local working area).
function rDefenseStatus(D){
 const db=D.databases||{},lsp=db.lsp||{},cl=db.client||{};
 const tn=lsp.tree_nodes||[];
 const psChain=lsp.ps_leaf_chains||[];
 const psSub=lsp.ps_subfactory_chains||[];
 const psInit=lsp.ps_initial_signed_states||[];
 const psSigInputs=lsp.ps_signed_inputs_by_leaf||[];
 const sigProg=lsp.signing_progress||[];
 const distCl=cl.distribution_txs||[];
 const psNodeCounts=lsp.ps_node_counts||[];
 const clFacs=cl.factories||[];

 // Terminal-state detection: render a banner above the tiles when the
 // factory has been closed on-chain.  The live-monitoring tiles below
 // are still rendered so operators can see the forensic state, but the
 // banner makes it clear the underlying factory is no longer active.
 // Trigger: any of cooperative_close / tree_node_* / penalty / breach
 // appears in broadcast_log with result=ok.  (factories.state can't be
 // trusted today — LSP doesn't bump it; see PR #219 mismatch warning.)
 const bl=lsp.broadcast_log||[];
 let terminalKind='';
 for(const r of bl){
  const s=(r.source||'');
  if((r.result||'ok')!=='ok') continue;
  if(s==='cooperative_close'){terminalKind='cooperative close'; break;}
  if(s.startsWith('tree_node_')){terminalKind=terminalKind||'force-close';}
  if(s.startsWith('penalty')){terminalKind=terminalKind||'penalty (breach response)';}
  if(s.startsWith('breach_revoked')){terminalKind=terminalKind||'breach attempt';}
 }
 let terminalBanner='';
 if(terminalKind){
  terminalBanner=`<div class="s" style="border-color:#8b949e44;background:#21262d22;margin-bottom:8px"><div class="st"><span style="color:#8b949e">⏷ Factory in terminal state: ${terminalKind}</span><span class="c">live-monitor tiles below are historical</span></div><p class="mu" style="font-size:11px;margin:4px 0">Tiles reflect the protocol's defense readiness at the moment of close; they will not change further.  See Payments / Protocol Log / Channels tabs for forensic detail.</p></div>`;
 }

 const tiles=[];

 // #1 — LSP disappears → pre-signed factory tree
 {
  const treeSigned=tn.filter(n=>n.is_signed).length;
  const treeTotal=tn.length;
  let color,status;
  if(treeTotal===0){color='grey'; status='no factory active';}
  else if(treeSigned===treeTotal){color='green'; status=`${treeSigned}/${treeTotal} nodes signed (100%)`;}
  else{color='red'; status=`${treeSigned}/${treeTotal} nodes signed — ${treeTotal-treeSigned} unsigned`;}
  tiles.push({n:'#1',icon:'🚪',name:'LSP disappears',
   defense:'Pre-signed factory tree — any client broadcasts the path',
   status,color,source:'tree_nodes.is_signed',
   risk:'Clients trapped; no unilateral exit possible'});
 }

 // #4 — Old PS chain published → pre-signed poison TX
 {
  const psTot=psChain.length+psSub.length;
  const psHave=psChain.filter(r=>r.has_poison).length+psSub.filter(r=>r.has_poison).length;
  const pct=psTot?Math.round(100*psHave/psTot):0;
  let color,status;
  if(psTot===0){color='grey'; status='no PS chain entries yet (no advances driven)';}
  else if(psHave===psTot){color='green'; status=`${psHave}/${psTot} positions with signed poison TX (100%)`;}
  else if(pct>=80){color='yellow'; status=`${psHave}/${psTot} (${pct}%) — partial coverage`;}
  else{color='red'; status=`${psHave}/${psTot} (${pct}%) — poison TX missing`;}
  tiles.push({n:'#4',icon:'🛡',name:'Old PS chain published',
   defense:'Pre-signed poison TX redistributes L-stock/sales-stock to clients',
   status,color,source:'ps_*_chains.poison_tx_hex',
   risk:'LSP keeps stolen liquidity; watchtower cannot intervene'});
 }

 // #5 — CLTV timeout / LSP gone → distribution TX (client-side)
 {
  const distFromClient=distCl.filter(r=>r.has_bytes).length;
  const expected=Math.max(clFacs.length,1);
  let color,status;
  if(distFromClient>=expected){color='green'; status=`${distFromClient} distribution TX(s) signed and stored on client`;}
  else if(distFromClient>0){color='yellow'; status=`${distFromClient}/${expected} factories covered`;}
  else if(expected>0&&clFacs.length>0){color='red'; status=`0/${expected} — client has NO recovery TX`;}
  else{color='grey'; status='no client DB / no factories the client is in';}
  tiles.push({n:'#5',icon:'⏱',name:'CLTV timeout / LSP gone',
   defense:'Distribution TX — any client broadcasts at timeout (inverted-timelock)',
   status,color,source:'distribution_txs (client.db)',
   risk:'Funds unrecoverable at CLTV without LSP cooperation'});
 }

 // #7 — LSP crash mid-ceremony → signing_progress snapshot
 {
  let color,status;
  if(sigProg.length===0){
   color='green'; status='no ceremony in flight (snapshot empty = healthy)';
  } else {
   const now=Math.floor(Date.now()/1000);
   const freshest=Math.max(...sigProg.map(s=>s.updated_at||0));
   const ageS=now-freshest;
   if(ageS<300){color='green'; status=`${sigProg.length} entries — ceremony in flight (fresh, ${ageS}s ago)`;}
   else{color='yellow'; status=`${sigProg.length} entries stale (${Math.floor(ageS/60)}min) — possible stuck ceremony`;}
  }
  tiles.push({n:'#7',icon:'⚙',name:'LSP crash mid-ceremony',
   defense:'signing_progress snapshot allows resume; cleared on success',
   status,color,source:'signing_progress',
   risk:'Stuck ceremony or wasted nonce — usually recoverable on restart'});
 }

 // #14 — Double-spend on PS leaf advance → client_ps_signed_inputs
 {
  const sigInputsTot=psSigInputs.reduce((a,r)=>a+(r.cnt||0),0);
  let color,status;
  if(sigInputsTot===0){
   color='grey'; status='no PS advances signed yet (defense table empty — OK pre-advance)';
  } else {
   color='green'; status=`${sigInputsTot} inputs guarded, 0 conflicts detected`;
  }
  tiles.push({n:'#14',icon:'🚫',name:'Double-spend on PS leaf advance',
   defense:'client_ps_signed_inputs records each parent; refuses conflicting sign',
   status,color,source:'client_ps_signed_inputs',
   risk:'LSP signs two TXs for same parent UTXO → wallet inconsistency'});
 }

 // #15 — PS chain[0] persistence (the F1 issue lives here)
 {
  const psNodes=psNodeCounts.reduce((a,r)=>a+(r.ps_leaf_count||0)+(r.subfactory_count||0),0);
  const persisted=psInit.length;
  let color,status;
  if(psNodes===0){
   color='grey'; status='no PS nodes (legacy DW-only deployment)';
  } else if(persisted>=psNodes){
   color='green'; status=`${persisted}/${psNodes} PS nodes have chain[0] persisted ✓`;
  } else {
   color='red'; status=`${persisted}/${psNodes} persisted — v0.1.15 risk: ${psNodes-persisted} missing`;
  }
  tiles.push({n:'#15',icon:'🧬',name:'PS chain[0] bytes lost on restart',
   defense:'ps_initial_signed_states persists chain[0] per PS leaf/sub-factory',
   status,color,source:'ps_initial_signed_states',
   risk:'Force-close fails with -25 bad-txns-inputs-missingorspent indefinitely'});
 }

 // #8 — Fee-spike CPFP defense (Phase 2 partial)
 // watchtower_pending tracks each broadcast penalty/sweep TX along with
 // its current cycles_in_mempool and bump_count.  A pending sweep that
 // has been sitting in the mempool for many cycles without ever being
 // bumped is the signature of a deadline-aware bump loop that's not
 // executing — exactly the case where a fee-spike could let an old
 // state win the DW race.
 {
  const wp=lsp.watchtower_pending||[];
  let color,status;
  if(wp.length===0){
   color='grey'; status='no pending sweeps (nothing to fee-bump right now)';
  } else {
   const stuck=wp.filter(w=>(w.cycles_in_mempool||0)>6 && (w.bump_count||0)===0);
   if(stuck.length===0){
    color='green';
    const bumped=wp.filter(w=>(w.bump_count||0)>0).length;
    status=`${wp.length} pending sweep(s), all progressing (${bumped} bumped)`;
   } else {
    color='red';
    status=`${stuck.length}/${wp.length} sweep(s) stuck >6 cycles with NO fee bump`;
   }
  }
  tiles.push({n:'#8',icon:'⛽',name:'Fee-spike CPFP defense',
   defense:'P2A + CPFP child + deadline-aware budget sweeper re-bumps per block',
   status,color,source:'watchtower_pending (cycles_in_mempool, bump_count)',
   risk:'Stuck TX loses DW race; old state confirms; cheater succeeds'});
 }

 // #13 — LSP wallet UTXO budget for mass-CPFP (Phase 2 partial)
 // The defense against fee spikes during a mass force-close is for the
 // LSP wallet to hold many small pre-split UTXOs so each in-flight
 // factory can attach a CPFP child without contention.  When the wallet
 // is consolidated into one large UTXO, only one CPFP child can be
 // attached at a time and the rest of the closes stall.  Approach A
 // (this implementation): server queries `bitcoin-cli listunspent` and
 // the tile compares the result to the worst-case need.
 {
  const wu=D.wallet_utxos||{};
  const facCount=(lsp.factories||[]).filter(f=>f.state!=='closed').length;
  // Worst-case: one CPFP child per active factory + 1 buffer slot.
  // If we have no observed factories yet, default to 1 so the tile
  // still has a non-zero target instead of dividing by zero.
  const worstCase=Math.max(facCount,1);
  let color,status;
  if(!wu.available){
   color='grey';
   status=wu.configured ? `listunspent failed for wallet "${wu.wallet}" (locked or missing?)` : 'no --lsp-wallet configured (cannot query)';
  } else {
   const count=wu.count||0;
   const margin=worstCase>0?count/worstCase:0;
   if(margin>=2){
    color='green';
    status=`${count} UTXO(s) ≥ 2× worst-case need (${worstCase} active factor${worstCase===1?'y':'ies'})`;
   } else if(margin>=1){
    color='yellow';
    status=`${count} UTXO(s) vs. need ${worstCase} — at margin, consider pre-splitting`;
   } else {
    color='red';
    status=`${count} UTXO(s) < ${worstCase} worst-case CPFP slots needed`;
   }
  }
  tiles.push({n:'#13',icon:'💰',name:'LSP wallet UTXO budget',
   defense:'Pre-split wallet UTXOs allow one CPFP child per in-flight close',
   status,color,source:'bitcoin-cli listunspent',
   risk:'Mass force-close exhausts CPFP slots; later TXs stall, lose DW race'});
 }

 // #2 — Channel breach (counterparty publishes revoked commitment).
 // Defense is the pre-signed penalty TX.  PR #181 added persistence for
 // the bytes (old_commitments.signed_penalty_tx_hex, schema v25); PR
 // #182 added the collector.  This tile lights up when both have
 // landed; until then it shows grey ("data source pending").
 {
  const ocov=lsp.old_commitments_coverage||{};
  const tot=ocov.total||0, per=ocov.persisted||0;
  let color, status;
  if(ocov.total===undefined){
   color='grey';
   status='data source pending (waiting on dashboard collector — PR #182)';
  } else if(tot===0){
   color='grey';
   status='no revoked commitments to defend against yet';
  } else if(per===tot){
   color='green';
   status=`${per}/${tot} entries with signed penalty TX bytes on disk`;
  } else if(per===0){
   color='yellow';
   status=`${tot} revoked commitment(s) — penalty bytes in memory only (pre-PR #181 LSP build)`;
  } else {
   const pct=Math.round(100*per/tot);
   color='yellow';
   status=`${per}/${tot} (${pct}%) persisted — ${tot-per} still in memory`;
  }
  tiles.push({n:'#2',icon:'⚔',name:'Channel breach (revoked commit)',
   defense:'Pre-signed penalty TX sweeps both outputs using revocation secret',
   status,color,source:'old_commitments.signed_penalty_tx_hex',
   risk:'Cheater wins disputed balance if LSP restarts before broadcast'});
 }

 // ---- Aggregate header ----
 const greenCount=tiles.filter(t=>t.color==='green').length;
 const yellowCount=tiles.filter(t=>t.color==='yellow').length;
 const redCount=tiles.filter(t=>t.color==='red').length;
 const greyCount=tiles.filter(t=>t.color==='grey').length;
 const counted=greenCount+yellowCount+redCount;
 const pct=counted?Math.round(100*greenCount/counted):0;
 const aggCls=redCount>0?'b dn':yellowCount>0?'b w':counted>0?'b ok':'b i';

 let h='';
 h+=terminalBanner;
 h+=`<div class="s"><div class="st"><span>Defense Posture</span><span class="c">per-failure-mode coverage</span></div>`;
 h+=`<div class="kv" style="margin-bottom:8px">`;
 h+=`<div class="ki"><span class="k">Healthy</span><span class="${aggCls}" style="font-size:14px;padding:2px 12px">${greenCount}/${counted}${counted?` (${pct}%)`:''}</span></div>`;
 if(yellowCount)h+=`<div class="ki"><span class="k">Partial</span><span class="b w">${yellowCount}</span></div>`;
 if(redCount)h+=`<div class="ki"><span class="k">Missing</span><span class="b dn">${redCount}</span></div>`;
 if(greyCount)h+=`<div class="ki"><span class="k">N/A</span><span class="b i">${greyCount}</span></div>`;
 h+=`</div>`;
 h+=`<p class="mu" style="font-size:11px;margin-top:4px">Each tile maps to one documented failure mode in the SuperScalar trustless model.  Green = defense fully in place.  Yellow = partial / open problem.  Red = defense missing.  Grey = not applicable to this deployment shape.</p>`;
 h+=`</div>`;

 // ---- Tile grid ----
 h+=`<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:8px">`;
 for(const t of tiles){
  const borderColor=t.color==='green'?'#3fb950':t.color==='yellow'?'#d29922':t.color==='red'?'#f85149':'#30363d';
  const statusCls=t.color==='green'?'b ok':t.color==='yellow'?'b w':t.color==='red'?'b dn':'b i';
  h+=`<div style="border:1px solid ${borderColor};border-radius:6px;padding:10px 12px;background:#0d1117">`;
  h+=`<div><span style="font-size:14px;margin-right:4px">${t.icon}</span><span style="font-weight:600;font-size:12px">${t.n} ${t.name}</span></div>`;
  h+=`<div style="font-size:11px;color:#8b949e;margin:4px 0">${t.defense}</div>`;
  h+=`<div style="margin:6px 0"><span class="${statusCls}" style="font-size:11px">${t.status}</span></div>`;
  h+=`<div style="font-size:10px;color:#484f58;margin-top:6px"><code>${t.source}</code></div>`;
  h+=`<div class="mu" style="font-size:10px;margin-top:4px;border-top:1px solid #21262d;padding-top:4px">If defense fails: ${t.risk}</div>`;
  h+=`</div>`;
 }
 h+=`</div>`;

 // ---- Failure-mode taxonomy reference ----
 // Operators see numbered tiles (#1, #4, #5, ...) and reasonably wonder
 // "what about #2, #3, #6 — are those also defended?  forgotten?  not
 // surfaced for a reason?"  This expandable section documents every
 // failure mode in the 15-mode SuperScalar trustless taxonomy, marking
 // which are surfaced as tiles above and explaining the rationale for
 // each one that isn't.
 const surfaced=new Set(tiles.map(t=>t.n));
 const taxonomy=[
  {n:'#1', name:'LSP disappears',                              status:'tile above'},
  {n:'#2', name:'Channel breach (revoked commit)',             status:'tile above'},
  {n:'#3', name:'Old DW state published (legacy)',             status:'skipped — n/a on canonical PS (arity=3) deployments; tile would always show grey'},
  {n:'#4', name:'Old PS chain state published',                status:'tile above'},
  {n:'#5', name:'CLTV timeout, LSP gone',                      status:'tile above'},
  {n:'#6', name:'HTLC times out / preimage not received',      status:'skipped — built on-demand, no preparedness check available'},
  {n:'#7', name:'LSP crash mid-ceremony',                      status:'tile above'},
  {n:'#8', name:'Mempool fee spike during force-close',        status:'tile above'},
  {n:'#9', name:'Reorg invalidates penalty confirmation',      status:'skipped — needs deeper bitcoind enrichment; informational only'},
  {n:'#10',name:'Concurrent ceremonies / state-update race',   status:'skipped — JIT is both defense and normal mechanism; no clean signal'},
  {n:'#11',name:'Client disappears mid-assisted-exit',         status:'skipped — known open protocol problem; no defense available to verify'},
  {n:'#12',name:'Miner collusion on DW challenge',             status:'skipped — theoretical risk with low practical likelihood'},
  {n:'#13',name:'Mass-close exhausts LSP CPFP UTXOs',          status:'tile above'},
  {n:'#14',name:'Double-spend on PS leaf advance',             status:'tile above'},
  {n:'#15',name:'PS chain[0] bytes lost on restart',           status:'tile above'},
 ];
 h+=`<details style="margin-top:12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px 12px">`;
 h+=`<summary style="cursor:pointer;font-size:11px;color:#58a6ff">Full 15-mode taxonomy reference — what's surfaced, what isn't, and why</summary>`;
 h+=`<p class="mu" style="font-size:11px;margin:6px 0">The SuperScalar trustless model documents 15 failure modes.  This panel surfaces ${tiles.length} as live tiles.  The rest are either not applicable to the current deployment shape, informational-only (no observable defense state), or known open problems.</p>`;
 h+=`<table style="font-size:11px"><tr><th>#</th><th>Failure mode</th><th>Coverage</th></tr>`;
 for(const t of taxonomy){
  const shown=surfaced.has(t.n);
  const badge=shown?'<span class="b ok" style="font-size:9px">surfaced</span>':'<span class="b i" style="font-size:9px">not surfaced</span>';
  h+=`<tr><td>${t.n}</td><td>${t.name}</td><td>${badge} <span class="mu">${t.status}</span></td></tr>`;
 }
 h+=`</table>`;
 h+=`</details>`;

 return h;
}

// === TAB: Ceremonies (signing rounds journal, reconstructed from wire_messages) ===
// The LSP doesn't currently persist a signing_rounds journal (only the
// signing_progress snapshot which is cleared on success).  But the
// wire_messages protocol log contains every signing-round message and
// can be reconstructed into per-ceremony entries client-side.  Phase 1
// of C3.
//
// Each ceremony spans a known sequence of wire-message types between a
// canonical start and end marker.  Messages are clustered into
// ceremonies by (a) ceremony-type membership and (b) time-proximity, so
// multi-client broadcasts of the same message (e.g. 4× FACTORY_PROPOSE
// sent to each client at the same timestamp) collapse into one ceremony
// entry.
function rCeremonies(D){
 const db=D.databases||{},lsp=db.lsp||{};
 // PR #182 collector exposes the new signing_rounds journal (schema v26
 // from PR #181).  When available, render it as the primary source for
 // ceremony types the LSP team has actually hooked.  The wire_messages
 // reconstruction below stays as the universal fallback — only Tier B
 // is hooked in #181 today, so reconstruction still handles factory
 // creation, leaf advance, sub-factory advance, and leaf realloc until
 // the LSP team's 4 follow-up hooks land.
 const srs=lsp.signing_rounds_summary||{};
 const srRecent=lsp.signing_rounds_recent||[];
 const srAvail=(srs.total||0)>0;
 let h='';
 if(srAvail){
  h+=`<div class="s" style="border-color:#3fb95044;background:#0c2d6b18"><div class="st"><span>Direct Journal (signing_rounds)</span><span class="c">${srs.total} ceremon${srs.total===1?'y':'ies'} × ${srs.types} type(s)</span></div>`;
  h+=`<p class="mu" style="font-size:11px;margin:4px 0">Authoritative source for hooked ceremony types: PR #181 added the <code>signing_rounds</code> table (schema v26) plus per-participant timing + result.  Tier B is hooked today; the other 4 ceremony types still come from the wire_messages reconstruction below until LSP team lands their follow-up hooks.</p>`;
  h+=`<div class="kv" style="margin-bottom:8px">`;
  h+=`<div class="ki"><span class="k">Success</span><span class="b ok">${srs.success||0}</span></div>`;
  if(srs.in_flight)h+=`<div class="ki"><span class="k">In flight</span><span class="b w">${srs.in_flight}</span></div>`;
  if(srs.timeout)h+=`<div class="ki"><span class="k">Timeout</span><span class="b w">${srs.timeout}</span></div>`;
  if(srs.crashed)h+=`<div class="ki"><span class="k">Crashed (LSP died mid-round)</span><span class="b dn">${srs.crashed}</span></div>`;
  h+=`</div>`;
  if(srRecent.length){
   h+=`<table><tr><th>ID</th><th>Type</th><th>Factory</th><th>Node</th><th class="r">Epoch</th><th class="r">Parts</th><th class="r">Nonces</th><th class="r">PSigs</th><th>Started</th><th>Duration</th><th>Result TXID</th><th>Result</th></tr>`;
   for(const r of srRecent){
    const dur=(r.completed_at&&r.started_at)?(r.completed_at-r.started_at)+'s':(r.completed_at?'—':'in flight');
    let resCls='b w', resText=r.result||'pending';
    if(r.result==='success')resCls='b ok';
    else if(r.result==='timeout')resCls='b w';
    else if(r.result==='aborted_crash')resCls='b dn';
    else if(!r.result)resCls='b i';
    const err=r.error_detail?` <span class="mu" title="${(r.error_detail||'').replace(/"/g,'&quot;')}">⚠</span>`:'';
    h+=`<tr><td>${r.id}</td><td>${r.ceremony_type||'?'}</td><td>#${r.factory_id??'—'}</td><td>${r.node_idx??'—'}</td><td class="r">${r.epoch??'—'}</td><td class="r">${r.n_participants??'—'}</td><td class="r">${r.nonces_collected??'—'}</td><td class="r">${r.partial_sigs_collected??'—'}</td><td>${ta(r.started_at)} ago</td><td>${dur}</td><td class="h">${th(r.result_txid)} ${r.result_txid?txBadge(D,r.result_txid):''}</td><td><span class="${resCls}">${resText}</span>${err}</td></tr>`;
   }
   h+=`</table>`;
  }
  h+=`</div>`;
 }
 const wm=(lsp.wire_messages||[]).slice().sort((a,b)=>(a.timestamp||0)-(b.timestamp||0)||(a.id||0)-(b.id||0));
 // Map: msg_name -> {type, role: 'start' | 'mid' | 'end'}
 const MAP={
  // Factory creation: FACTORY_PROPOSE → NONCE_BUNDLE → ALL_NONCES → PSIG_BUNDLE → FACTORY_READY
  FACTORY_PROPOSE: {type:'Factory creation',     role:'start',icon:'🏭'},
  NONCE_BUNDLE:    {type:'Factory creation',     role:'mid'  ,icon:'🏭'},
  ALL_NONCES:      {type:'Factory creation',     role:'mid'  ,icon:'🏭'},
  PSIG_BUNDLE:     {type:'Factory creation',     role:'mid'  ,icon:'🏭'},
  FACTORY_READY:   {type:'Factory creation',     role:'end'  ,icon:'🏭'},
  // Sub-factory chain advance
  SUBFACTORY_PROPOSE:    {type:'Sub-factory advance', role:'start',icon:'🌳'},
  SUBFACTORY_NONCE:      {type:'Sub-factory advance', role:'mid'  ,icon:'🌳'},
  SUBFACTORY_ALL_NONCES: {type:'Sub-factory advance', role:'mid'  ,icon:'🌳'},
  SUBFACTORY_PSIG:       {type:'Sub-factory advance', role:'mid'  ,icon:'🌳'},
  SUBFACTORY_DONE:       {type:'Sub-factory advance', role:'end'  ,icon:'🌳'},
  // Per-leaf advance (PS or DW)
  LEAF_ADVANCE_PROPOSE: {type:'Leaf advance',        role:'start',icon:'🌿'},
  LEAF_ADVANCE_PSIG:    {type:'Leaf advance',        role:'mid'  ,icon:'🌿'},
  LEAF_ADVANCE_DONE:    {type:'Leaf advance',        role:'end'  ,icon:'🌿'},
  // Tier B rollover (root-driven path signing)
  PATH_NONCE_BUNDLE: {type:'Tier B rollover',        role:'start',icon:'🔁'},
  PATH_ALL_NONCES:   {type:'Tier B rollover',        role:'mid'  ,icon:'🔁'},
  PATH_PSIG_BUNDLE:  {type:'Tier B rollover',        role:'mid'  ,icon:'🔁'},
  PATH_SIGN_DONE:    {type:'Tier B rollover',        role:'end'  ,icon:'🔁'},
  // Channel setup (basepoint exchange + initial commit)
  CHANNEL_BASEPOINTS: {type:'Channel setup',         role:'start',icon:'🔗'},
  CHANNEL_NONCES:     {type:'Channel setup',         role:'mid'  ,icon:'🔗'},
  CHANNEL_READY:      {type:'Channel setup',         role:'end'  ,icon:'🔗'},
  // PTLC key turnover (assisted exit, factory rotation)
  PTLC_PRESIG:       {type:'PTLC key turnover',      role:'start',icon:'🔑'},
  PTLC_ADAPTED_SIG:  {type:'PTLC key turnover',      role:'mid'  ,icon:'🔑'},
  PTLC_COMPLETE:     {type:'PTLC key turnover',      role:'end'  ,icon:'🔑'},
 };
 // Group messages into ceremonies.  Algorithm:
 //   - Walk chronologically.
 //   - For each message known to MAP, either start a new ceremony or
 //     extend the current one if the type matches and the time gap is
 //     small (< 60s — ceremonies don't typically span minutes).
 //   - When a new ceremony of a different type starts, close the current
 //     one (with whatever end-marker it saw, or mark in-progress).
 const MAX_GAP_SEC=60;
 const ceremonies=[];
 let cur=null;
 const closeCur=()=>{if(cur){ceremonies.push(cur); cur=null;}};
 for(const m of wm){
  const cls=MAP[m.msg_name];
  if(!cls)continue; // skip PING/PONG/etc.
  if(cur && (cur.type!==cls.type || (m.timestamp-cur.last_ts)>MAX_GAP_SEC)){
   closeCur();
  }
  if(!cur){
   cur={
    type:cls.type, icon:cls.icon,
    first_ts:m.timestamp, last_ts:m.timestamp,
    peers:new Set(), msg_names:new Set(),
    msg_count:0, saw_end:false,
    first_msg:m.msg_name, last_msg:m.msg_name,
    first_id:m.id, last_id:m.id,
   };
  }
  cur.last_ts=m.timestamp;
  cur.last_msg=m.msg_name;
  cur.last_id=m.id;
  cur.peers.add(m.peer||'?');
  cur.msg_names.add(m.msg_name);
  cur.msg_count++;
  if(cls.role==='end')cur.saw_end=true;
 }
 closeCur();

 // Sort newest first
 ceremonies.reverse();

 // Aggregates
 const total=ceremonies.length;
 const complete=ceremonies.filter(c=>c.saw_end).length;
 const inProgress=total-complete;
 const ceremonyTypes={};
 for(const c of ceremonies){ceremonyTypes[c.type]=(ceremonyTypes[c.type]||0)+1;}

 h+=`<div class="s"><div class="st"><span>Signing Rounds — Reconstructed Journal</span><span class="c">${srAvail?'fallback for unhooked ceremony types':'reconstructed from wire_messages'}</span></div>`;
 h+=`<p class="mu" style="font-size:11px;margin-bottom:8px">Reconstructed from <code>wire_messages</code> by grouping consecutive signing-related messages within ${MAX_GAP_SEC}s windows.  ${srAvail?'PR #181 added a direct <code>signing_rounds</code> table — Tier B ceremonies are now shown above from that authoritative source.  The 4 other ceremony types (factory_creation, leaf_advance, sub_factory_advance, leaf_realloc) continue to use this reconstructed view until the LSP team hooks them.':'Will move to a direct query when the LSP team hooks more ceremony types into the <code>signing_rounds</code> journal (schema v26 from PR #181).'}</p>`;
 if(total===0){
  h+=`<p class="mu">No ceremonies detected. <code>wire_messages</code> may be empty or only contain non-signing traffic (PING/PONG, HELLO, etc.).</p>`;
  h+=`</div>`;
  return h;
 }
 // Summary row
 h+=`<div class="kv" style="margin-bottom:8px">`;
 h+=`<div class="ki"><span class="k">Total ceremonies</span><span class="v">${total}</span></div>`;
 h+=`<div class="ki"><span class="k">Completed</span><span class="b ok">${complete}</span></div>`;
 if(inProgress>0)h+=`<div class="ki"><span class="k">In progress / no end marker</span><span class="b w">${inProgress}</span></div>`;
 for(const[t,c]of Object.entries(ceremonyTypes))h+=`<div class="ki"><span class="k">${t}</span><span class="v">${c}</span></div>`;
 h+=`</div>`;
 h+=`</div>`;

 // Detail table
 h+=`<div class="s"><div class="st"><span>Ceremony detail</span><span class="c">${total} entries (newest first)</span></div>`;
 h+=`<table><tr><th>#</th><th>Type</th><th>Started</th><th class="r">Duration</th><th class="r">Peers</th><th class="r">Messages</th><th>Pattern</th><th>Outcome</th></tr>`;
 for(let i=0;i<ceremonies.length;i++){
  const c=ceremonies[i];
  const duration=c.last_ts-c.first_ts;
  const durStr=duration<1?'< 1s':duration<60?`${duration}s`:`${Math.floor(duration/60)}m${duration%60}s`;
  const outcomeCls=c.saw_end?'b ok':'b w';
  const outcomeText=c.saw_end?'success':'no end marker';
  const peerList=Array.from(c.peers).filter(p=>p!=='unknown'&&p!=='?').join(', ')||Array.from(c.peers).join(', ');
  const pattern=`${c.first_msg} → … → ${c.last_msg}`;
  h+=`<tr><td>${total-i}</td><td><span style="font-size:14px;margin-right:4px">${c.icon}</span>${c.type}</td><td>${ta(c.first_ts)} ago</td><td class="r">${durStr}</td><td class="r" title="${peerList}">${c.peers.size}</td><td class="r">${c.msg_count}</td><td style="font-size:10px"><code>${pattern}</code></td><td><span class="${outcomeCls}">${outcomeText}</span></td></tr>`;
 }
 h+=`</table>`;
 h+=`<p class="mu" style="font-size:10px;margin-top:6px">Duration is <code>last_ts - first_ts</code> across the ceremony's messages.  Peer count is distinct peers seen; multi-client broadcasts (e.g. one <code>FACTORY_PROPOSE</code> per client) are collapsed.  "no end marker" means the ceremony's canonical terminal message (e.g. <code>FACTORY_READY</code>) was not seen — could be in-flight, aborted, or pruned from the message log.</p>`;
 h+=`</div>`;
 return h;
}

// === Main render ===
function render(D){
 _D=D;             // expose latest payload for exportSnapshot()
 pushHistory(D);   // feed sparkline buffers
 document.getElementById('ts').textContent=D.timestamp||'--:--:--';
 // Staleness badge: flag when the browser is showing a payload older than
 // 30s (auto-refresh is 5s, so 30s means the tab is detached / fetching is
 // failing) OR when the lsp.db has been written to more recently than the
 // payload was generated (race: payload built mid-write).  Operators saw
 // this when wiping + restarting a test — old data lingers in the tab.
 const fresh=D.freshness||{};
 const stale=document.getElementById('stale');
 if(fresh.api_ts){
  const age=Math.floor(Date.now()/1000)-fresh.api_ts;
  if(age>=30){
   stale.textContent='⚠ payload '+age+'s old';
   stale.style.display='inline-block';
  } else if(fresh.lsp_db_mtime && fresh.lsp_db_mtime>fresh.api_ts+2){
   stale.textContent='⚠ lsp.db newer than payload';
   stale.style.display='inline-block';
  } else {
   stale.style.display='none';
  }
 }
 const dot=document.getElementById('dot');
 const au=D.processes&&Object.values(D.processes).every(v=>v);
 const su=D.processes&&Object.values(D.processes).some(v=>v);
 dot.className='dot '+(au?'g':su?'y':'r');
 document.getElementById('dm').style.display=D.demo?'block':'none';
 // Global poison-TX coverage indicator (trustless-model dial)
 const lsp=(D.databases||{}).lsp||{};
 const pchains=lsp.ps_leaf_chains||[],psubs=lsp.ps_subfactory_chains||[];
 let pTot=0,pCov=0;
 for(const r of pchains){pTot++;if(r.has_poison)pCov++;}
 for(const r of psubs){pTot++;if(r.has_poison)pCov++;}
 const poisonEl=document.getElementById('poison');
 if(pTot>0){
  const pct=Math.round(100*pCov/pTot);
  const cls=pct===100?'b ok':pct>=80?'b i':'b w';
  poisonEl.style.display='inline-block';
  poisonEl.innerHTML=`<span class="${cls}" title="poison-TX coverage across PS chain entries">🛡 poison ${pCov}/${pTot} (${pct}%)</span>`;
 } else { poisonEl.style.display='none'; }
 // Phase 1: hide the Lightning Network tab when no CLN is wired.  The
 // operator dashboard's job is the LSP + factories; end-user payment
 // UX lives in the wallet, not here.  Tab stays hidden if both CLN A
 // and CLN B are unavailable.  Auto-flips back to Overview if the
 // hidden tab was currently selected.
 const cln=D.cln||{};
 const cnlAny=(cln.a&&cln.a.available)||(cln.b&&cln.b.available);
 const lnTab=document.querySelector('.tab[data-t="lightning"]');
 if(lnTab){
  lnTab.style.display=cnlAny?'':'none';
  if(!cnlAny&&curTab==='lightning'){
   curTab='overview';
   document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.t==='overview'));
  }
 }
 // Update tab counts
 const tabCounts={channels:(lsp.channels||[]).length+(lsp.htlcs||[]).length,
  lightning:((D.cln||{}).a||{}).num_peers||0+((D.cln||{}).b||{}).num_peers||0,
  watchtower:(lsp.watchtower_count||0)+(lsp.revocation_count||0)};
 // Events tab was merged into Protocol Log — redirect stale curTab so
 // operators with persisted tab state from a prior session don't see a
 // blank page (the 'events' tab markup no longer exists).
 if(curTab==='events'){
  curTab='protocol';
  document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.t==='protocol'));
 }
 // Render all tabs (hidden, shown via CSS)
 let h='';
 h+=`<div class="tp ${curTab==='overview'?'show':''}" id="t-overview">${rOverview(D)}</div>`;
 h+=`<div class="tp ${curTab==='factory'?'show':''}" id="t-factory">${rFactory(D)}</div>`;
 h+=`<div class="tp ${curTab==='channels'?'show':''}" id="t-channels">${rChannels(D)}</div>`;
 h+=`<div class="tp ${curTab==='payments'?'show':''}" id="t-payments">${rPayments(D)}</div>`;
 h+=`<div class="tp ${curTab==='protocol'?'show':''}" id="t-protocol">${rProtocol(D)}</div>`;
 h+=`<div class="tp ${curTab==='ceremonies'?'show':''}" id="t-ceremonies">${rCeremonies(D)}</div>`;
 h+=`<div class="tp ${curTab==='lightning'?'show':''}" id="t-lightning">${rLightning(D)}</div>`;
 h+=`<div class="tp ${curTab==='watchtower'?'show':''}" id="t-watchtower">${rWatchtower(D)}</div>`;
 h+=`<div class="tp ${curTab==='defense'?'show':''}" id="t-defense">${rDefenseStatus(D)}</div>`;
 h+=`<div class="tp ${curTab==='txinv'?'show':''}" id="t-txinv">${rTxInventory(D)}</div>`;
 h+=`<div class="tp ${curTab==='outcomes'?'show':''}" id="t-outcomes">${rOutcomes(D)}</div>`;
 document.getElementById('content').innerHTML=h;
 // Polish item 1 re-application: rProtocol just rebuilt the rows, so re-apply
 // the saved filter values so the user's filter persists across the 5s
 // auto-refresh without them having to retype.
 if(curTab==='protocol')applyProtoFilter();
}
async function refresh(){try{const r=await fetch('/api/status');if(r.ok)render(await r.json());}catch(e){}}
refresh();setInterval(refresh,R);
</script></body></html>"""

# ---------------------------------------------------------------------------
# HTTP Handler + Main
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    cfg = None
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/":
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif self.path == "/api/status":
            d = collect_all(self.cfg)
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-cache"); self.end_headers()
            self.wfile.write(json.dumps(d, default=str).encode("utf-8"))
        else: self.send_error(404)

def main():
    p = argparse.ArgumentParser(description="SuperScalar Web Dashboard")
    p.add_argument("--port",type=int,default=8080); p.add_argument("--demo",action="store_true")
    p.add_argument("--lsp-db",default=None); p.add_argument("--client-db",default=None)
    p.add_argument("--btc-cli",default="bitcoin-cli"); p.add_argument("--btc-network",default="signet")
    p.add_argument("--btc-rpcuser",default=None); p.add_argument("--btc-rpcpassword",default=None)
    p.add_argument("--btc-datadir",default=None,help="bitcoind datadir (for non-default deployments)")
    p.add_argument("--btc-rpcport",default=None,help="bitcoind RPC port (for non-default deployments)")
    p.add_argument("--lsp-wallet",default=None,help="LSP bitcoind wallet name (enables Defense Status #13 wallet-UTXO tile)")
    p.add_argument("--cln-cli",default="lightning-cli")
    p.add_argument("--cln-a-dir",default=None); p.add_argument("--cln-b-dir",default=None)
    a = p.parse_args(); cfg = Config(a); Handler.cfg = cfg
    s = HTTPServer(("0.0.0.0",cfg.port), Handler)
    print(f"SuperScalar Dashboard: http://localhost:{cfg.port}")
    print("Press Ctrl+C to stop")
    try: s.serve_forever()
    except KeyboardInterrupt: print("\nDone"); s.server_close()

if __name__ == "__main__": main()
