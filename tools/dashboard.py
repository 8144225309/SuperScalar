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
        self.cln_cli = a.cln_cli; self.cln_a_dir = a.cln_a_dir; self.cln_b_dir = a.cln_b_dir

def run_cmd(args, timeout=5):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return (r.stdout.strip(), True) if r.returncode == 0 else (r.stderr.strip(), False)
    except Exception as e:
        return str(e), False

def btc_cmd(cfg, *a):
    cmd = [cfg.btc_cli]
    if cfg.btc_network and cfg.btc_network != "mainnet": cmd.append("-" + cfg.btc_network)
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
            data[label][key] = rows if not err else {"error": err}
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
        rows, err = query_db(path,
            "SELECT * FROM wire_messages ORDER BY id DESC LIMIT 100")
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

def collect_all(cfg):
    if cfg.demo: return collect_demo()
    return {"timestamp": time.strftime("%H:%M:%S"),
        "processes": collect_processes(cfg), "bitcoin": collect_bitcoin(cfg),
        "databases": collect_databases(cfg), "cln": collect_cln(cfg)}

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
    return {
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
    }

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
.tabs{display:flex;gap:2px;border-bottom:2px solid #21262d;margin:10px 0 12px 0;overflow-x:auto}
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
 <div class="tm"><span id="ts">--:--:--</span><span id="dot" class="dot r"></span></div>
</div>
<div id="dm" class="demo" style="display:none">DEMO MODE — simulated data for UI preview</div>
<div class="tabs" id="tabs">
 <div class="tab active" data-t="overview">Overview</div>
 <div class="tab" data-t="factory">Factory</div>
 <div class="tab" data-t="channels">Channels & HTLCs</div>
 <div class="tab" data-t="protocol">Protocol Log</div>
 <div class="tab" data-t="lightning">Lightning Network</div>
 <div class="tab" data-t="watchtower">Watchtower</div>
 <div class="tab" data-t="events">Events</div>
</div>
<div id="content"></div>
</div>

<script>
const R=5000;let curTab='overview';
document.getElementById('tabs').addEventListener('click',e=>{
    const t=e.target.closest('.tab'); if(!t)return;
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
    t.classList.add('active'); curTab=t.dataset.t;
    document.querySelectorAll('.tp').forEach(x=>x.classList.toggle('show',x.id==='t-'+curTab));
});

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
const ta=ts=>{if(!ts)return'\u2014';const d=Math.floor(Date.now()/1000)-ts;if(d<60)return d+'s';if(d<3600)return Math.floor(d/60)+'m';if(d<86400)return Math.floor(d/3600)+'h';return Math.floor(d/86400)+'d';};
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

// === TAB: Factory ===
function rFactory(D){
 const db=D.databases||{},lsp=db.lsp||{},facs=lsp.factories||[],parts=lsp.participants||[];
 let h='';
 // Factory detail
 h+=`<div class="s"><div class="st"><span>Factory (N+1-of-N+1 MuSig2 UTXO)</span><span class="c">${facs.length}</span></div>`;
 for(const f of facs){
  h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">ID</span><span class="v">#${f.id}</span></div><div class="ki"><span class="k">Parties</span><span class="v">${f.n_participants} (N+1-of-N+1 MuSig2)</span></div><div class="ki"><span class="k">Funding</span><span class="v">${fs(f.funding_amount)}</span></div><div class="ki"><span class="k">State</span>${sb(f.state)}</div><div class="ki"><span class="k">Created</span><span class="v">${ta(f.created_at)} ago</span></div></div>`;
  h+=`<div class="kv" style="margin-bottom:8px"><div class="ki"><span class="k">TXID</span><span class="v h">${th(f.funding_txid)}</span></div><div class="ki"><span class="k">vout</span><span class="v">${f.funding_vout??'\u2014'}</span></div><div class="ki"><span class="k">step_blocks</span><span class="v">${f.step_blocks??'\u2014'}</span></div><div class="ki"><span class="k">states/layer</span><span class="v">${f.states_per_layer??'\u2014'}</span></div><div class="ki"><span class="k">cltv_timeout</span><span class="v">${f.cltv_timeout??'\u2014'} blk</span></div><div class="ki"><span class="k">fee/tx</span><span class="v">${f.fee_per_tx!=null?f.fee_per_tx+' sat':'\u2014'}</span></div></div>`;
  // Participants
  const fp=parts.filter(p=>p.factory_id===f.id);
  if(fp.length){const roles=['LSP','Client 1','Client 2','Client 3','Client 4'];
   h+=`<table><tr><th>Slot</th><th>Role</th><th>Public Key (secp256k1)</th></tr>`;
   for(const p of fp)h+=`<tr><td>${p.slot}</td><td>${roles[p.slot]||'Client '+(p.slot)}</td><td class="pk">${p.pubkey}</td></tr>`;
   h+=`</table>`;}
 }
 if(!facs.length)h+=`<p class="mu">No factories</p>`;
 h+=`</div>`;
 // Departed Clients (Phase 23)
 const dep=lsp.departed_clients||[];
 if(dep.length){h+=`<div class="s"><div class="st"><span>Departed Clients</span><span class="c">${dep.length}</span></div>`;
  h+=`<table><tr><th>Factory</th><th>Client Idx</th><th>Extracted Key</th><th>Departed</th></tr>`;
  for(const d of dep)h+=`<tr><td>#${d.factory_id}</td><td>${d.client_idx}</td><td class="h">${th(d.extracted_key)}</td><td>${ta(d.departed_at)}</td></tr>`;
  h+=`</table></div>`;}
 // Tree nodes visualization
 const tn=lsp.tree_nodes||[];
 if(tn.length){h+=`<div class="s"><div class="st"><span>Timeout-Sig-Tree Nodes</span><span class="c">${tn.length}</span></div>`;
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
  // Detail table
  h+=`<table style="margin-top:8px"><tr><th>#</th><th>Type</th><th>Parent</th><th>Layer</th><th>Signers</th><th class="r">Input</th><th>Outputs</th><th>nSeq</th><th>TXID</th><th>Status</th></tr>`;
  for(const n of tn){h+=`<tr><td>${n.node_index}</td><td>${n.type}</td><td>${n.parent_index>=0?n.parent_index:'\u2014'}</td><td>${n.dw_layer_index>=0?n.dw_layer_index:'\u2014'}</td><td>[${n.signer_indices}] (${n.n_signers})</td><td class="r">${fs(n.input_amount)}</td><td>${n.output_amounts}</td><td>${n.nsequence===4294967295?'final':n.nsequence}</td><td class="h">${th(n.txid)}</td><td>${n.is_signed?'<span class="b ok">signed</span>':'<span class="b dn">unsigned</span>'}</td></tr>`;}
  h+=`</table>`;
  h+=`</div>`;}
 // Protocol + DW
 const proto=D.factory_protocol,dw=D.dw_state;
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

// === TAB: Protocol Log ===
function rProtocol(D){
 const db=D.databases||{},lsp=db.lsp||{},msgs=lsp.wire_messages||[];
 let h='';
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
 h+=`<div class="s"><div class="st"><span>Wire Messages (recent)</span><span class="c">${msgs.length}</span></div>`;
 if(!msgs.length)h+=`<p class="mu">No wire messages logged yet. Messages appear when LSP/client communicate with --db enabled.</p>`;
 else{h+=`<table><tr><th>Time</th><th>Dir</th><th>Type</th><th>Peer</th><th>Payload</th></tr>`;
  for(const m of msgs){
   const arrow=m.direction==='sent'?'\u2192':'\u2190';
   const dirC=m.direction==='sent'?'color:#f0883e':'color:#3fb950';
   const ts2=m.timestamp?new Date(m.timestamp*1000).toLocaleTimeString():'\u2014';
   const pay=(m.payload_summary||'').length>80?(m.payload_summary.slice(0,80)+'\u2026'):m.payload_summary||'';
   h+=`<tr><td style="white-space:nowrap">${ts2}</td><td style="${dirC};font-weight:600">${arrow} ${m.direction||'?'}</td><td style="${catColor(m.msg_name)};font-weight:600">${m.msg_name||'0x'+((m.msg_type||0).toString(16))}</td><td>${m.peer||'\u2014'}</td><td class="h" style="font-size:10px;max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${(m.payload_summary||'').replace(/"/g,'&quot;')}">${pay}</td></tr>`;}
  h+=`</table>`;}
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
  h+=`<table><tr><th>CH</th><th>Commit#</th><th>TXID</th><th>Vout</th><th class="r">To-Local</th></tr>`;
  for(const o of oc.slice(0,15)){const jitBadge=o.channel_id>=4?' <span class="b i">JIT</span>':'';
   h+=`<tr><td>${o.channel_id}${jitBadge}</td><td>${o.commit_num}</td><td class="h">${th(o.txid)}</td><td>${o.to_local_vout??'\u2014'}</td><td class="r">${fs(o.to_local_amount)}</td></tr>`;}
  if(oc.length>15)h+=`<tr><td colspan="5" class="mu">\u2026 and ${oc.length-15} more</td></tr>`;
  h+=`</table>`;}
 h+=`</div>`;
 return h;
}

// === TAB: Events ===
function rEvents(D){
 const ev=D.events||[];
 let h=`<div class="s"><div class="st"><span>Event Log</span><span class="c">${ev.length}</span></div>`;
 if(!ev.length)h+=`<p class="mu">No events yet. Events appear as the system operates.</p>`;
 else{h+=`<div class="el">`;for(const e of ev.slice().reverse())h+=`<div class="ew"><span class="et">${e.time}</span><span class="em">${e.msg}</span></div>`;h+=`</div>`;}
 h+=`</div>`;
 return h;
}

// === Main render ===
function render(D){
 document.getElementById('ts').textContent=D.timestamp||'--:--:--';
 const dot=document.getElementById('dot');
 const au=D.processes&&Object.values(D.processes).every(v=>v);
 const su=D.processes&&Object.values(D.processes).some(v=>v);
 dot.className='dot '+(au?'g':su?'y':'r');
 document.getElementById('dm').style.display=D.demo?'block':'none';
 // Update tab counts
 const lsp=(D.databases||{}).lsp||{};
 const tabCounts={channels:(lsp.channels||[]).length+(lsp.htlcs||[]).length,
  lightning:((D.cln||{}).a||{}).num_peers||0+((D.cln||{}).b||{}).num_peers||0,
  watchtower:(lsp.watchtower_count||0)+(lsp.revocation_count||0),
  events:(D.events||[]).length};
 // Render all tabs (hidden, shown via CSS)
 let h='';
 h+=`<div class="tp ${curTab==='overview'?'show':''}" id="t-overview">${rOverview(D)}</div>`;
 h+=`<div class="tp ${curTab==='factory'?'show':''}" id="t-factory">${rFactory(D)}</div>`;
 h+=`<div class="tp ${curTab==='channels'?'show':''}" id="t-channels">${rChannels(D)}</div>`;
 h+=`<div class="tp ${curTab==='protocol'?'show':''}" id="t-protocol">${rProtocol(D)}</div>`;
 h+=`<div class="tp ${curTab==='lightning'?'show':''}" id="t-lightning">${rLightning(D)}</div>`;
 h+=`<div class="tp ${curTab==='watchtower'?'show':''}" id="t-watchtower">${rWatchtower(D)}</div>`;
 h+=`<div class="tp ${curTab==='events'?'show':''}" id="t-events">${rEvents(D)}</div>`;
 document.getElementById('content').innerHTML=h;
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
    p.add_argument("--cln-cli",default="lightning-cli")
    p.add_argument("--cln-a-dir",default=None); p.add_argument("--cln-b-dir",default=None)
    a = p.parse_args(); cfg = Config(a); Handler.cfg = cfg
    s = HTTPServer(("0.0.0.0",cfg.port), Handler)
    print(f"SuperScalar Dashboard: http://localhost:{cfg.port}")
    print("Press Ctrl+C to stop")
    try: s.serve_forever()
    except KeyboardInterrupt: print("\nDone"); s.server_close()

if __name__ == "__main__": main()
