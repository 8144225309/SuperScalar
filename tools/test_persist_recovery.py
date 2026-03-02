#!/usr/bin/env python3
"""Test persistence recovery: kill LSP mid-operation, restart from DB."""

import subprocess, time, os, sys, signal, json

btc = "/home/pirq/bin/bitcoin-cli"
conf = ["-regtest", "-conf=/home/pirq/bitcoin-regtest/bitcoin.conf"]
build = "/home/pirq/superscalar-build"
LSP = f"{build}/superscalar_lsp"
CLIENT = f"{build}/superscalar_client"

LSP_SECKEY = "0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CLIENT_KEYS = ["22" * 32, "33" * 32, "44" * 32, "55" * 32]
WALLET = "persist_test"
DB_PATH = "/tmp/persist_lsp.db"

def rpc(*args, wallet=None):
    cmd = [btc] + conf
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip()

def wait_for_in_file(path, keyword, timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(path) as f:
                if keyword in f.read():
                    return True
        except:
            pass
        time.sleep(2)
    return False

def read_log(path="/tmp/persist_lsp.log"):
    try:
        with open(path) as f:
            return f.read()
    except:
        return ""

# Fresh regtest
subprocess.run([btc] + conf + ["stop"], capture_output=True)
time.sleep(2)
subprocess.run(["rm", "-rf", os.path.expanduser("~/.bitcoin/regtest")])
subprocess.Popen([os.path.expanduser("~/bin/bitcoind"), "-regtest",
                   "-conf=" + os.path.expanduser("~/bitcoin-regtest/bitcoin.conf"), "-daemon"])
time.sleep(3)
rpc("createwallet", WALLET)
addr = rpc("getnewaddress", "", "bech32m", wallet=WALLET)
rpc("generatetoaddress", "201", addr, wallet=WALLET)
time.sleep(1)
print("Regtest ready, height:", rpc("getblockcount"))

env = dict(os.environ)
env["PATH"] = "/home/pirq/bin:" + env.get("PATH", "")

# Clean old files
for f in [DB_PATH, "/tmp/persist_lsp.log", "/tmp/persist_report.json"]:
    try: os.unlink(f)
    except: pass
for i in range(4):
    for f in [f"/tmp/persist_client_{i}.db", f"/tmp/persist_client_{i}.log"]:
        try: os.unlink(f)
        except: pass

print("\n=== PHASE 1: Start LSP + clients, create factory, enter daemon mode ===")

lsp_log = open("/tmp/persist_lsp.log", "w")
lsp_cmd = [LSP, "--seckey", LSP_SECKEY, "--amount", "100000", "--clients", "4",
           "--wallet", WALLET, "--port", "9746", "--network", "regtest",
           "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass", "--fee-rate", "1000",
           "--db", DB_PATH, "--report", "/tmp/persist_report.json",
           "--daemon", "--cli"]
lsp = subprocess.Popen(lsp_cmd, stdin=subprocess.PIPE, stdout=lsp_log,
                        stderr=subprocess.STDOUT, env=env)
time.sleep(2)

clients = []
for i in range(4):
    cmd = [CLIENT, "--seckey", CLIENT_KEYS[i], "--port", "9746", "--host", "127.0.0.1",
           "--network", "regtest", "--db", f"/tmp/persist_client_{i}.db", "--fee-rate", "1000",
           "--lsp-pubkey", LSP_PUBKEY, "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass",
           "--daemon"]
    clog = open(f"/tmp/persist_client_{i}.log", "w")
    c = subprocess.Popen(cmd, stdout=clog, stderr=subprocess.STDOUT, env=env)
    clients.append((c, clog))
    time.sleep(0.5)

# Mine blocks for funding
for _ in range(5):
    rpc("generatetoaddress", "1", addr, wallet=WALLET)
    time.sleep(2)

print("Waiting for daemon loop...")
if not wait_for_in_file("/tmp/persist_lsp.log", "daemon loop started"):
    print("FATAL: daemon never started")
    lsp.terminate()
    for c, cl in clients:
        c.terminate()
        cl.close()
    sys.exit(1)

time.sleep(2)

# Make a payment via CLI
print("Sending payment: pay 0 1 1000")
lsp.stdin.write(b"pay 0 1 1000\n")
lsp.stdin.flush()
time.sleep(10)

# Check status
lsp.stdin.write(b"status\n")
lsp.stdin.flush()
time.sleep(2)

log1 = read_log()
pay_ok = "pay succeeded" in log1
print(f"  Payment succeeded: {pay_ok}")

# Check DB contents before kill
db_check = subprocess.run(["sqlite3", DB_PATH,
    "SELECT COUNT(*) FROM old_commitments; SELECT COUNT(*) FROM invoices;"],
    capture_output=True, text=True)
print(f"  DB state before kill: {db_check.stdout.strip()}")

print("\n=== PHASE 2: KILL LSP (SIGKILL - simulate crash) ===")
lsp.kill()
lsp.wait()
lsp_log.close()
print(f"  LSP killed (pid={lsp.pid})")

# Kill clients too
for c, clog in clients:
    c.kill()
    c.wait()
    clog.close()
print("  Clients killed")

time.sleep(2)

# Check DB contents after kill (should persist)
db_check = subprocess.run(["sqlite3", DB_PATH,
    "SELECT COUNT(*) FROM old_commitments; SELECT COUNT(*) FROM invoices; SELECT COUNT(*) FROM factory;"],
    capture_output=True, text=True)
print(f"  DB state after kill: {db_check.stdout.strip()}")

# Also check HTLC state
htlc_check = subprocess.run(["sqlite3", DB_PATH,
    "SELECT COUNT(*) FROM htlcs;"],
    capture_output=True, text=True)
print(f"  HTLCs in DB: {htlc_check.stdout.strip()}")

print("\n=== PHASE 3: Restart LSP from DB (recovery) ===")

# Restart LSP — it should detect the DB and recover
lsp_log2 = open("/tmp/persist_lsp2.log", "w")
lsp2_cmd = [LSP, "--seckey", LSP_SECKEY, "--amount", "100000", "--clients", "4",
            "--wallet", WALLET, "--port", "9746", "--network", "regtest",
            "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass", "--fee-rate", "1000",
            "--db", DB_PATH, "--report", "/tmp/persist_report2.json",
            "--daemon", "--cli"]
lsp2 = subprocess.Popen(lsp2_cmd, stdin=subprocess.PIPE, stdout=lsp_log2,
                         stderr=subprocess.STDOUT, env=env)
time.sleep(3)

# Start clients again
clients2 = []
for i in range(4):
    cmd = [CLIENT, "--seckey", CLIENT_KEYS[i], "--port", "9746", "--host", "127.0.0.1",
           "--network", "regtest", "--db", f"/tmp/persist_client_{i}.db", "--fee-rate", "1000",
           "--lsp-pubkey", LSP_PUBKEY, "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass",
           "--daemon"]
    clog = open(f"/tmp/persist_client_{i}.log", "a")
    c = subprocess.Popen(cmd, stdout=clog, stderr=subprocess.STDOUT, env=env)
    clients2.append((c, clog))
    time.sleep(0.5)

# Mine blocks to help reconnection
for _ in range(3):
    rpc("generatetoaddress", "1", addr, wallet=WALLET)
    time.sleep(2)

# Wait for recovery
print("Waiting for recovery...")
time.sleep(10)

log2 = ""
try:
    with open("/tmp/persist_lsp2.log") as f:
        log2 = f.read()
except:
    pass

# Check recovery indicators
has_recovery = "recovery" in log2.lower() or "loaded" in log2.lower() or "restored" in log2.lower()
has_factory = "factory" in log2.lower()
has_channels = "channel" in log2.lower()
has_daemon = "daemon" in log2.lower()

print(f"  Recovery detected: {has_recovery}")
print(f"  Factory info: {has_factory}")
print(f"  Channel info: {has_channels}")
print(f"  Daemon re-entered: {has_daemon}")

# Print key recovery lines
print("\n  Recovery log lines:")
for line in log2.split("\n"):
    ll = line.lower()
    if any(kw in ll for kw in ["recover", "loaded", "restored", "persist", "factory",
                                 "daemon", "channel", "error", "failed"]):
        print(f"    {line.strip()}")

# Try sending a command to verify recovered LSP is operational
lsp2.stdin.write(b"status\n")
lsp2.stdin.flush()
time.sleep(3)

try:
    with open("/tmp/persist_lsp2.log") as f:
        log2_updated = f.read()
except:
    log2_updated = ""

# Look for status output
has_status = "Channels:" in log2_updated
print(f"\n  Post-recovery status command: {'works' if has_status else 'no response'}")
if has_status:
    for line in log2_updated.split("\n"):
        if "Channel " in line and "local=" in line:
            print(f"    {line.strip()}")

# Cleanup
lsp2.stdin.write(b"close\n")
lsp2.stdin.flush()
try:
    lsp2.wait(timeout=20)
except:
    lsp2.terminate()
    lsp2.wait(timeout=10)
lsp_log2.close()

for c, clog in clients2:
    c.terminate()
    clog.close()

print(f"\n  LSP2 exit code: {lsp2.returncode}")

# Final verdict
results = {
    "payment_before_kill": pay_ok,
    "db_survives_kill": "old_commitments" not in db_check.stderr,
    "recovery_detected": has_recovery,
    "post_recovery_status": has_status,
}

print("\n" + "=" * 50)
print("PERSISTENCE RECOVERY SUMMARY")
print("=" * 50)
passed = sum(1 for v in results.values() if v)
total = len(results)
for name, ok in results.items():
    print(f"  {name:30s} {'PASS' if ok else 'FAIL'}")
print(f"\n  {passed}/{total} passed")
