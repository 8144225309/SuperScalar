#!/usr/bin/env python3
"""Test daemon CLI commands: help, status, pay, rebalance, invoice, close.
Uses a simple approach: pipe commands via stdin with delays, log to file."""

import subprocess, time, os, sys, threading

# Auto-detect paths: env vars → PATH lookup
btc = os.environ.get('SUPERSCALAR_BTC', 'bitcoin-cli')
_btcconf = os.environ.get('SUPERSCALAR_BTCCONF')
if _btcconf:
    conf = ["-regtest", f"-conf={_btcconf}"]
else:
    conf = ["-regtest"]
build = os.environ.get('SUPERSCALAR_BUILD', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'build'))
LSP = f"{build}/superscalar_lsp"
CLIENT = f"{build}/superscalar_client"

LSP_SECKEY = "0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CLIENT_KEYS = ["22" * 32, "33" * 32, "44" * 32, "55" * 32]
WALLET = "cli_test"

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

# Fresh regtest
subprocess.run([btc] + conf + ["stop"], capture_output=True)
time.sleep(2)
subprocess.run(["rm", "-rf", os.path.expanduser("~/.bitcoin/regtest")])
btcd = os.path.join(os.path.dirname(btc), "bitcoind") if "/" in btc else "bitcoind"
btcd_cmd = [btcd, "-daemon", "-regtest", "-fallbackfee=0.00001"]
if _btcconf:
    btcd_cmd.append(f"-conf={_btcconf}")
subprocess.Popen(btcd_cmd)
time.sleep(3)
rpc("createwallet", WALLET)
addr = rpc("getnewaddress", "", "bech32m", wallet=WALLET)
rpc("generatetoaddress", "201", addr, wallet=WALLET)
time.sleep(1)
print("Regtest ready")

# Clean up
subprocess.run(["pkill", "-f", "superscalar_lsp.*--network regtest"], capture_output=True)
subprocess.run(["pkill", "-f", "superscalar_client.*--network regtest"], capture_output=True)
time.sleep(1)
for f in ["/tmp/cli_lsp.db", "/tmp/cli_report.json", "/tmp/cli_lsp.log"]:
    try: os.unlink(f)
    except: pass
for i in range(4):
    for f in [f"/tmp/cli_client_{i}.db", f"/tmp/cli_client_{i}.log"]:
        try: os.unlink(f)
        except: pass

env = dict(os.environ)
env["PATH"] = os.path.dirname(btc) + ":" + env.get("PATH", "")

# Start LSP in daemon+cli mode, stdout to log file
lsp_log = open("/tmp/cli_lsp.log", "w")
lsp_cmd = [LSP, "--seckey", LSP_SECKEY, "--amount", "100000", "--clients", "4",
           "--wallet", WALLET, "--port", "9745", "--network", "regtest",
           "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass", "--fee-rate", "1000",
           "--db", "/tmp/cli_lsp.db", "--report", "/tmp/cli_report.json",
           "--daemon", "--cli"]
lsp = subprocess.Popen(lsp_cmd, stdin=subprocess.PIPE, stdout=lsp_log,
                        stderr=subprocess.STDOUT, env=env)
time.sleep(2)

# Start 4 clients
clients = []
for i in range(4):
    cmd = [CLIENT, "--seckey", CLIENT_KEYS[i], "--port", "9745", "--host", "127.0.0.1",
           "--network", "regtest", "--db", f"/tmp/cli_client_{i}.db", "--fee-rate", "1000",
           "--lsp-pubkey", LSP_PUBKEY, "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass",
           "--daemon"]
    clog = open(f"/tmp/cli_client_{i}.log", "w")
    c = subprocess.Popen(cmd, stdout=clog, stderr=subprocess.STDOUT, env=env)
    clients.append((c, clog))
    time.sleep(0.5)

# Mine blocks in background while waiting for factory
def mine_blocks():
    for _ in range(10):
        rpc("generatetoaddress", "1", addr, wallet=WALLET)
        time.sleep(2)

miner = threading.Thread(target=mine_blocks, daemon=True)
miner.start()

print("Waiting for daemon loop...")
if not wait_for_in_file("/tmp/cli_lsp.log", "daemon loop started"):
    print("FATAL: daemon never started")
    lsp.terminate()
    for c, cl in clients:
        c.terminate()
        cl.close()
    sys.exit(1)

time.sleep(3)
print("Daemon loop started, sending CLI commands...")

def send_cmd(cmd_str):
    lsp.stdin.write((cmd_str + "\n").encode())
    lsp.stdin.flush()

def get_log():
    lsp_log.flush()
    with open("/tmp/cli_lsp.log") as f:
        return f.read()

results = {}

# Test 1: help
print("\n=== CLI TEST: help ===")
send_cmd("help")
time.sleep(2)
log = get_log()
results["help"] = "Commands:" in log and "pay <from>" in log
print(f"  RESULT: {'PASS' if results['help'] else 'FAIL'}")

# Test 2: status
print("\n=== CLI TEST: status ===")
send_cmd("status")
time.sleep(2)
log = get_log()
results["status"] = "Channels: 4" in log and "Factory state:" in log
print(f"  RESULT: {'PASS' if results['status'] else 'FAIL'}")

# Test 3: pay (valid, must be above dust limit 546 sats)
print("\n=== CLI TEST: pay 0 1 1000 ===")
log_before = len(get_log())
send_cmd("pay 0 1 1000")
time.sleep(10)
log = get_log()
new_output = log[log_before:]
results["pay"] = "succeeded" in new_output
print(f"  New output: {repr(new_output[:200])}")
print(f"  RESULT: {'PASS' if results['pay'] else 'FAIL'}")

# Test 4: pay (self - error)
print("\n=== CLI TEST: pay 0 0 1000 ===")
log_before = len(get_log())
send_cmd("pay 0 0 1000")
time.sleep(2)
log = get_log()
new_output = log[log_before:]
results["pay_self"] = "cannot" in new_output.lower()
print(f"  New output: {repr(new_output[:200])}")
print(f"  RESULT: {'PASS' if results['pay_self'] else 'FAIL'}")

# Test 5: pay (bad index)
print("\n=== CLI TEST: pay 99 0 1000 ===")
log_before = len(get_log())
send_cmd("pay 99 0 1000")
time.sleep(2)
log = get_log()
new_output = log[log_before:]
results["pay_badidx"] = "invalid" in new_output.lower()
print(f"  New output: {repr(new_output[:200])}")
print(f"  RESULT: {'PASS' if results['pay_badidx'] else 'FAIL'}")

# Test 6: rebalance (must be above dust limit 546 sats)
print("\n=== CLI TEST: rebalance 1 2 1000 ===")
log_before = len(get_log())
send_cmd("rebalance 1 2 1000")
time.sleep(10)
log = get_log()
new_output = log[log_before:]
results["rebalance"] = "succeeded" in new_output
print(f"  New output: {repr(new_output[:200])}")
print(f"  RESULT: {'PASS' if results['rebalance'] else 'FAIL'}")

# Test 7: invoice (no bridge)
print("\n=== CLI TEST: invoice 0 100000 ===")
log_before = len(get_log())
send_cmd("invoice 0 100000")
time.sleep(2)
log = get_log()
new_output = log[log_before:]
results["invoice_nobridge"] = "no bridge" in new_output.lower()
print(f"  New output: {repr(new_output[:200])}")
print(f"  RESULT: {'PASS' if results['invoice_nobridge'] else 'FAIL'}")

# Test 8: unknown command
print("\n=== CLI TEST: foobar ===")
log_before = len(get_log())
send_cmd("foobar")
time.sleep(2)
log = get_log()
new_output = log[log_before:]
results["unknown"] = "unknown" in new_output.lower()
print(f"  New output: {repr(new_output[:200])}")
print(f"  RESULT: {'PASS' if results['unknown'] else 'FAIL'}")

# Test 9: status (post-pay balances changed)
print("\n=== CLI TEST: status (post-pay) ===")
log_before = len(get_log())
send_cmd("status")
time.sleep(2)
log = get_log()
new_output = log[log_before:]
results["status_post"] = "Channels: 4" in new_output
# Print the status block
for line in new_output.strip().split("\n"):
    print(f"  {line}")
print(f"  RESULT: {'PASS' if results['status_post'] else 'FAIL'}")

# Test 10: close
print("\n=== CLI TEST: close ===")
send_cmd("close")
try:
    lsp.wait(timeout=30)
except:
    lsp.terminate()
    lsp.wait(timeout=10)
log = get_log()
results["close"] = "triggering shutdown" in log.lower() or "cooperative close" in log.lower()
print(f"  LSP exit code: {lsp.returncode}")
print(f"  RESULT: {'PASS' if results['close'] else 'FAIL'}")

# Cleanup
lsp_log.close()
for c, clog in clients:
    c.terminate()
    clog.close()
time.sleep(1)

# Print final log tail for debugging
print("\n--- LSP Log (last 30 lines) ---")
with open("/tmp/cli_lsp.log") as f:
    lines = f.readlines()
    for line in lines[-30:]:
        print(f"  {line.rstrip()}")

print("\n" + "=" * 50)
print("CLI COMMAND SUMMARY")
print("=" * 50)
passed = sum(1 for v in results.values() if v)
total = len(results)
for name, ok in results.items():
    print(f"  {name:20s} {'PASS' if ok else 'FAIL'}")
print(f"\n  {passed}/{total} passed")
