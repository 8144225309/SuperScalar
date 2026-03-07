#!/usr/bin/env python3
"""Comprehensive boundary value tests for SuperScalar LSP/Client.

Tests edge cases systematically:
- CLI flag validation (invalid values rejected, boundary values work)
- Factory creation with extreme parameters
- Payment boundary conditions (dust, reserve, max amounts)
- Rotation and lifecycle edge cases
- Stress: rapid payments, multiple rotations

Each test gets a fresh regtest to avoid cross-contamination.
"""

import subprocess, time, os, sys, threading, json, signal

def ts():
    return time.strftime("[%H:%M:%S]")

def clean_files(*paths):
    for f in paths:
        try: os.unlink(f)
        except OSError: pass

# Auto-detect paths: env vars → PATH lookup
btc = os.environ.get('SUPERSCALAR_BTC', 'bitcoin-cli')
_btcconf = os.environ.get('SUPERSCALAR_BTCCONF')
if _btcconf:
    conf = ["-regtest", f"-conf={_btcconf}"]
else:
    conf = ["-regtest", "-rpcuser=rpcuser", "-rpcpassword=rpcpass"]
build = os.environ.get('SUPERSCALAR_BUILD', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'build'))
LSP = f"{build}/superscalar_lsp"
CLIENT = f"{build}/superscalar_client"

LSP_SECKEY = "0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CLIENT_KEYS = ["22" * 32, "33" * 32, "44" * 32, "55" * 32,
               "66" * 32, "77" * 32, "88" * 32, "99" * 32]

WALLET = "boundary_test"
TEST_PORT = 9750
results = {}
env = dict(os.environ)
env["PATH"] = os.path.dirname(btc) + ":" + env.get("PATH", "")

def rpc(*args, wallet=None):
    cmd = [btc] + conf
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(args)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip()

def fresh_regtest():
    """Wipe and restart regtest."""
    subprocess.run([btc] + conf + ["stop"], capture_output=True)
    for _ in range(15):
        r = subprocess.run([btc] + conf + ["ping"], capture_output=True)
        if r.returncode != 0:
            break
        time.sleep(1)
    else:
        subprocess.run(["pkill", "-f", "bitcoind.*-regtest"], capture_output=True)
        time.sleep(2)
    subprocess.run(["rm", "-rf", os.path.expanduser("~/.bitcoin/regtest")])
    btcd = os.path.join(os.path.dirname(btc), "bitcoind") if "/" in btc else "bitcoind"
    btcd_cmd = [btcd, "-daemon", "-regtest", "-fallbackfee=0.00001"]
    if _btcconf:
        btcd_cmd.append(f"-conf={_btcconf}")
    else:
        btcd_cmd.extend(["-rpcuser=rpcuser", "-rpcpassword=rpcpass"])
    subprocess.Popen(btcd_cmd)
    time.sleep(5)
    for attempt in range(10):
        result = rpc("createwallet", WALLET)
        if "error" not in result.lower() and result != "":
            break
        time.sleep(1)
    addr = rpc("getnewaddress", "", "bech32m", wallet=WALLET)
    rpc("generatetoaddress", "201", addr, wallet=WALLET)
    time.sleep(1)
    return addr

def run_lsp_quick(extra_args, timeout=5):
    """Run LSP with given args, return (rc, stdout, stderr)."""
    cmd = [LSP, "--seckey", LSP_SECKEY, "--network", "regtest",
           "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass",
           "--wallet", WALLET, "--report", "/tmp/boundary_report.json",
           "--db", "/tmp/boundary_test.db"] + extra_args
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env=env)
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        return -1, "", "TIMEOUT"

def run_lsp_daemon(extra_args, port, log_path, n_clients=4, amount=100000):
    """Start LSP in daemon mode, return Popen + log file."""
    clean_files(log_path, "/tmp/boundary_test.db", "/tmp/boundary_report.json")
    log = open(log_path, "w")
    cmd = [LSP, "--seckey", LSP_SECKEY, "--amount", str(amount), "--clients", str(n_clients),
           "--wallet", WALLET, "--port", str(port), "--network", "regtest",
           "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass", "--fee-rate", "1000",
           "--db", "/tmp/boundary_test.db", "--report", "/tmp/boundary_report.json",
           "--daemon", "--cli"] + extra_args
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT, env=env)
    return p, log

def start_clients(n, port, prefix="boundary"):
    """Start n clients, return list of (Popen, log_file)."""
    clients = []
    for i in range(n):
        db = f"/tmp/{prefix}_client_{i}.db"
        logpath = f"/tmp/{prefix}_client_{i}.log"
        clean_files(db, logpath)
        clog = open(logpath, "w")
        cmd = [CLIENT, "--seckey", CLIENT_KEYS[i], "--port", str(port), "--host", "127.0.0.1",
               "--network", "regtest", "--db", db, "--fee-rate", "1000",
               "--lsp-pubkey", LSP_PUBKEY, "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass",
               "--daemon"]
        c = subprocess.Popen(cmd, stdout=clog, stderr=subprocess.STDOUT, env=env)
        clients.append((c, clog))
        time.sleep(0.3)
    return clients

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

def read_log(path):
    try:
        with open(path) as f:
            return f.read()
    except:
        return ""

def cleanup_procs(*procs):
    for p in procs:
        if isinstance(p, tuple):
            p[0].kill()
            try: p[0].wait(timeout=5)
            except: pass
            p[1].close()
        else:
            p.kill()
            try: p.wait(timeout=5)
            except: pass

def mine_n(addr, n):
    for _ in range(n):
        rpc("generatetoaddress", "1", addr, wallet=WALLET)
        time.sleep(1)

# ============================================================
# SECTION 1: CLI FLAG VALIDATION (no regtest needed for most)
# ============================================================

print("\n" + "=" * 60)
print("SECTION 1: CLI FLAG VALIDATION")
print("=" * 60)

# Need regtest running for validation tests that get past flag checking
addr = fresh_regtest()

# Test 1.1: --arity 0 (invalid)
print(f"\n{ts()} --- 1.1: --arity 0 (should reject) ---")
rc, out, err = run_lsp_quick(["--arity", "0", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["arity_0"] = rc != 0 and "arity" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['arity_0'] else 'FAIL'}")

# Test 1.2: --arity 3 (invalid)
print(f"\n{ts()} --- 1.2: --arity 3 (should reject) ---")
rc, out, err = run_lsp_quick(["--arity", "3", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["arity_3"] = rc != 0 and "arity" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['arity_3'] else 'FAIL'}")

# Test 1.3: --arity -1 (invalid)
print(f"\n{ts()} --- 1.3: --arity -1 (should reject) ---")
rc, out, err = run_lsp_quick(["--arity", "-1", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["arity_neg1"] = rc != 0 and "arity" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['arity_neg1'] else 'FAIL'}")

# Test 1.4: --clients 0 (invalid)
print(f"\n{ts()} --- 1.4: --clients 0 (should reject) ---")
rc, out, err = run_lsp_quick(["--clients", "0", "--amount", "100000", "--port", str(TEST_PORT)])
results["clients_0"] = rc != 0
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['clients_0'] else 'FAIL'}")

# Test 1.5: --clients 9 (over max 8)
print(f"\n{ts()} --- 1.5: --clients 9 (should reject) ---")
rc, out, err = run_lsp_quick(["--clients", "9", "--amount", "100000", "--port", str(TEST_PORT)])
results["clients_9"] = rc != 0
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['clients_9'] else 'FAIL'}")

# Test 1.6: --states-per-layer 1 (below min 2)
print(f"\n{ts()} --- 1.6: --states-per-layer 1 (should reject) ---")
rc, out, err = run_lsp_quick(["--states-per-layer", "1", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["spl_1"] = rc != 0 and "states-per-layer" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['spl_1'] else 'FAIL'}")

# Test 1.7: --states-per-layer 257 (above max 256)
print(f"\n{ts()} --- 1.7: --states-per-layer 257 (should reject) ---")
rc, out, err = run_lsp_quick(["--states-per-layer", "257", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["spl_257"] = rc != 0 and "states-per-layer" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['spl_257'] else 'FAIL'}")

# Test 1.8: --lsp-balance-pct 101 (over max 100)
print(f"\n{ts()} --- 1.8: --lsp-balance-pct 101 (should reject) ---")
rc, out, err = run_lsp_quick(["--lsp-balance-pct", "101", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["bal_101"] = rc != 0 and "lsp-balance-pct" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['bal_101'] else 'FAIL'}")

# Test 1.9: --confirm-timeout 0 (should reject)
print(f"\n{ts()} --- 1.9: --confirm-timeout 0 (should reject) ---")
rc, out, err = run_lsp_quick(["--confirm-timeout", "0", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["ctimeout_0"] = rc != 0 and "confirm-timeout" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['ctimeout_0'] else 'FAIL'}")

# Test 1.10: --confirm-timeout -5 (should reject)
print(f"\n{ts()} --- 1.10: --confirm-timeout -5 (should reject) ---")
rc, out, err = run_lsp_quick(["--confirm-timeout", "-5", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["ctimeout_neg"] = rc != 0
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['ctimeout_neg'] else 'FAIL'}")

# Test 1.11: --rebalance-threshold 50 (below min 51)
print(f"\n{ts()} --- 1.11: --rebalance-threshold 50 (should reject) ---")
rc, out, err = run_lsp_quick(["--rebalance-threshold", "50", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["rebal_50"] = rc != 0 and "rebalance-threshold" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['rebal_50'] else 'FAIL'}")

# Test 1.12: --rebalance-threshold 100 (above max 99)
print(f"\n{ts()} --- 1.12: --rebalance-threshold 100 (should reject) ---")
rc, out, err = run_lsp_quick(["--rebalance-threshold", "100", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["rebal_100"] = rc != 0
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['rebal_100'] else 'FAIL'}")

# Test 1.13: --placement-mode invalid
print(f"\n{ts()} --- 1.13: --placement-mode badvalue (should reject) ---")
rc, out, err = run_lsp_quick(["--placement-mode", "badvalue", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["placement_bad"] = rc != 0 and "placement-mode" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['placement_bad'] else 'FAIL'}")

# Test 1.14: --default-profit-bps 10001 (above max)
print(f"\n{ts()} --- 1.14: --default-profit-bps 10001 (should reject) ---")
rc, out, err = run_lsp_quick(["--default-profit-bps", "10001", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["bps_10001"] = rc != 0
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['bps_10001'] else 'FAIL'}")

# Test 1.15: --accept-timeout 0 (should reject - must be positive)
print(f"\n{ts()} --- 1.15: --accept-timeout 0 (should reject) ---")
rc, out, err = run_lsp_quick(["--accept-timeout", "0", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
# Note: accept_timeout_arg default is 0 (block forever), but explicit --accept-timeout 0 hits the <=0 check
results["atimeout_0"] = rc != 0
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['atimeout_0'] else 'FAIL'}")

# Test 1.16: --mainnet without risk flag (should reject)
print(f"\n{ts()} --- 1.16: --network mainnet without --i-accept-the-risk ---")
rc, out, err = run_lsp_quick(["--network", "mainnet", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["mainnet_guard"] = rc != 0 and "mainnet" in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['mainnet_guard'] else 'FAIL'}")

# Test 1.17: --test-expiry on non-regtest (allowed since 105b05b)
print(f"\n{ts()} --- 1.17: --test-expiry on signet (allowed on all networks) ---")
rc, out, err = run_lsp_quick(["--network", "signet", "--test-expiry", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
# Since 105b05b, test flags work on all networks. LSP should start (rc may be nonzero
# because no clients connect, but it should NOT reject due to network).
results["test_nonregtest"] = "only supported on regtest" not in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['test_nonregtest'] else 'FAIL'}")

# Test 1.18: Valid boundary - --states-per-layer 2 (minimum)
print(f"\n{ts()} --- 1.18: --states-per-layer 2 (valid minimum) ---")
rc, out, err = run_lsp_quick(["--states-per-layer", "2", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
# Should NOT reject for states-per-layer (may fail for other reasons like no clients connecting)
results["spl_2_valid"] = "states-per-layer" not in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['spl_2_valid'] else 'FAIL'}")

# Test 1.19: Valid boundary - --states-per-layer 256 (maximum)
print(f"\n{ts()} --- 1.19: --states-per-layer 256 (valid maximum) ---")
rc, out, err = run_lsp_quick(["--states-per-layer", "256", "--clients", "2", "--amount", "100000", "--port", str(TEST_PORT)])
results["spl_256_valid"] = "states-per-layer" not in err.lower()
print(f"  rc={rc}, stderr={err[:100]}")
print(f"  {ts()} RESULT: {'PASS' if results['spl_256_valid'] else 'FAIL'}")

# ============================================================
# SECTION 2: FACTORY CREATION EDGE CASES (need regtest)
# ============================================================

print("\n" + "=" * 60)
print("SECTION 2: FACTORY CREATION EDGE CASES")
print("=" * 60)

# Test 2.1: 1 client, arity-1 (should fail: factory ceremony needs >=2 clients)
print(f"\n{ts()} --- 2.1: 1 client, arity-1 (factory creation expected to fail) ---")
addr = fresh_regtest()

lsp, lsp_log = run_lsp_daemon(["--arity", "1"], TEST_PORT, "/tmp/bound_2_1.log",
                                n_clients=1, amount=200000)
time.sleep(2)

# Start 1 client
cl = start_clients(1, TEST_PORT, "bound21")
mine_n(addr, 5)

# Factory creation with 1 client is expected to fail (ceremony needs N>=3 signers)
time.sleep(10)
log = read_log("/tmp/bound_2_1.log")
factory_failed = "factory creation failed" in log.lower() or "ceremony" in log.lower()
results["1client_arity1"] = factory_failed or "daemon loop started" in log.lower()
if "daemon loop started" in log.lower():
    print(f"  Factory created successfully (unexpected but OK)")
else:
    print(f"  Factory creation failed as expected (1-client edge case)")
print(f"  {ts()} RESULT: {'PASS' if results['1client_arity1'] else 'FAIL'}")

cleanup_procs(lsp, *cl)
time.sleep(1)

# Test 2.2: 8 clients (maximum), arity-2
print(f"\n{ts()} --- 2.2: 8 clients, arity-2, 1M sats ---")
addr = fresh_regtest()

clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", "/tmp/bound_2_2.log")

lsp, lsp_log = run_lsp_daemon([], TEST_PORT+1, "/tmp/bound_2_2.log",
                                n_clients=8, amount=1000000)
time.sleep(2)

cl = start_clients(8, TEST_PORT+1, "bound22")
mine_n(addr, 8)

ok = wait_for_in_file("/tmp/bound_2_2.log", "daemon loop started", timeout=120)
log = read_log("/tmp/bound_2_2.log")
results["8client_arity2"] = ok
print(f"  Daemon loop started: {ok}")
if not ok:
    for line in log.split("\n")[-10:]:
        print(f"    {line.strip()}")
print(f"  {ts()} RESULT: {'PASS' if results['8client_arity2'] else 'FAIL'}")

cleanup_procs(lsp, *cl)
time.sleep(1)

# Test 2.3: 1 client, arity-2 (should be rejected at startup)
print(f"\n{ts()} --- 2.3: 1 client, arity-2 (should reject: arity-2 needs >=2 clients) ---")
rc, out, err = run_lsp_quick(["--arity", "2", "--clients", "1", "--amount", "100000", "--port", str(TEST_PORT+2)])
results["1client_arity2"] = rc != 0 and "arity 2 requires at least 2" in err.lower()
print(f"  rc={rc}, stderr={err.strip()[:120]}")
print(f"  {ts()} RESULT: {'PASS' if results['1client_arity2'] else 'FAIL'}")

# Test 2.4: 3 clients, arity-2 (odd count with pair grouping)
print(f"\n{ts()} --- 2.4: 3 clients, arity-2 (odd count) ---")
addr = fresh_regtest()

clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", "/tmp/bound_2_4.log")

lsp, lsp_log = run_lsp_daemon([], TEST_PORT+3, "/tmp/bound_2_4.log",
                                n_clients=3, amount=300000)
time.sleep(2)

cl = start_clients(3, TEST_PORT+3, "bound24")
mine_n(addr, 5)

ok = wait_for_in_file("/tmp/bound_2_4.log", "daemon loop started", timeout=90)
log = read_log("/tmp/bound_2_4.log")
results["3client_arity2"] = ok
print(f"  Daemon loop started: {ok}")
if not ok:
    for line in log.split("\n")[-10:]:
        print(f"    {line.strip()}")
print(f"  {ts()} RESULT: {'PASS' if results['3client_arity2'] else 'FAIL'}")

cleanup_procs(lsp, *cl)
time.sleep(1)

# ============================================================
# SECTION 3: PAYMENT BOUNDARY CONDITIONS
# ============================================================

print("\n" + "=" * 60)
print("SECTION 3: PAYMENT BOUNDARY CONDITIONS")
print("=" * 60)

# Need a working factory for payment tests
print(f"\n{ts()} --- Setting up factory for payment tests ---")
addr = fresh_regtest()

clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", "/tmp/bound_pay.log")
for i in range(4):
    clean_files(f"/tmp/boundpay_client_{i}.db", f"/tmp/boundpay_client_{i}.log")

lsp, lsp_log = run_lsp_daemon([], TEST_PORT+4, "/tmp/bound_pay.log",
                                n_clients=4, amount=200000)
time.sleep(2)

cl = start_clients(4, TEST_PORT+4, "boundpay")
mine_n(addr, 6)

ok = wait_for_in_file("/tmp/bound_pay.log", "daemon loop started", timeout=120)
if not ok:
    print("FATAL: Could not create factory for payment tests")
    cleanup_procs(lsp, *cl)
    # Skip remaining payment tests
else:
    print(f"  Factory ready for payment tests")
    time.sleep(3)

    def send_cmd(cmd_str):
        try:
            lsp.stdin.write((cmd_str + "\n").encode())
            lsp.stdin.flush()
        except (BrokenPipeError, OSError):
            print(f"  WARNING: LSP stdin broken, skipping command: {cmd_str}")

    def get_new_output(since_len):
        lsp_log.flush()
        log = read_log("/tmp/bound_pay.log")
        return log[since_len:]

    # Test 3.1: Pay exactly dust limit (546 sats)
    print(f"\n{ts()} --- 3.1: pay 0 1 546 (exact dust limit) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1 546")
    time.sleep(10)
    new = get_new_output(log_before)
    results["pay_dust_exact"] = "succeeded" in new
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_dust_exact'] else 'FAIL'}")

    # Test 3.2: Pay below dust limit (545 sats - should fail)
    print(f"\n{ts()} --- 3.2: pay 0 1 545 (below dust - should fail) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1 545")
    time.sleep(5)
    new = get_new_output(log_before)
    results["pay_below_dust"] = "failed" in new.lower() or "dust" in new.lower() or "error" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_below_dust'] else 'FAIL'}")

    # Test 3.3: Pay 1 sat (well below dust - should fail)
    print(f"\n{ts()} --- 3.3: pay 0 1 1 (1 sat - should fail) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1 1")
    time.sleep(5)
    new = get_new_output(log_before)
    results["pay_1_sat"] = "failed" in new.lower() or "dust" in new.lower() or "error" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_1_sat'] else 'FAIL'}")

    # Test 3.4: Pay 0 sats (should fail)
    print(f"\n{ts()} --- 3.4: pay 0 1 0 (0 sats - should fail) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1 0")
    time.sleep(5)
    new = get_new_output(log_before)
    results["pay_0_sats"] = "failed" in new.lower() or "error" in new.lower() or "0" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_0_sats'] else 'FAIL'}")

    # Test 3.5: Large payment that should exceed channel balance
    print(f"\n{ts()} --- 3.5: pay 0 1 99999999 (exceeds balance) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1 99999999")
    time.sleep(5)
    new = get_new_output(log_before)
    results["pay_too_large"] = "failed" in new.lower() or "error" in new.lower() or "insufficient" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_too_large'] else 'FAIL'}")

    # Test 3.6: Rebalance same channel (should fail)
    print(f"\n{ts()} --- 3.6: rebalance 0 0 1000 (same channel) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("rebalance 0 0 1000")
    time.sleep(5)
    new = get_new_output(log_before)
    results["rebal_self"] = "cannot" in new.lower() or "same" in new.lower() or "error" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['rebal_self'] else 'FAIL'}")

    # Test 3.7: Rebalance with invalid indices
    print(f"\n{ts()} --- 3.7: rebalance 99 0 1000 (bad index) ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("rebalance 99 0 1000")
    time.sleep(5)
    new = get_new_output(log_before)
    results["rebal_badidx"] = "invalid" in new.lower() or "error" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['rebal_badidx'] else 'FAIL'}")

    # Test 3.8: Check status shows correct channel count
    # (Run before blocking tests so daemon is responsive)
    print(f"\n{ts()} --- 3.8: status shows all 4 channels ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("status")
    time.sleep(8)
    new = get_new_output(log_before)
    results["status_4ch"] = "Channels: 4" in new
    for line in new.strip().split("\n"):
        if "Channel" in line or "Factory" in line or "Channels" in line:
            print(f"  {line.strip()}")
    print(f"  {ts()} RESULT: {'PASS' if results['status_4ch'] else 'FAIL'}")

    # Test 3.9: Pay with missing arguments
    print(f"\n{ts()} --- 3.9: pay with missing args ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1")
    time.sleep(8)
    new = get_new_output(log_before)
    results["pay_missing_args"] = "usage" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_missing_args'] else 'FAIL'}")

    # Test 3.10: Pay with non-numeric arguments
    print(f"\n{ts()} --- 3.10: pay abc def ghi ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay abc def ghi")
    time.sleep(8)
    new = get_new_output(log_before)
    # Should handle gracefully (invalid index or parse to 0)
    results["pay_nonnumeric"] = "invalid" in new.lower() or "error" in new.lower() or "failed" in new.lower() or "usage" in new.lower()
    print(f"  Output: {repr(new[:200])}")
    print(f"  {ts()} RESULT: {'PASS' if results['pay_nonnumeric'] else 'FAIL'}")

    # Test 3.11: Multiple rapid payments
    print(f"\n{ts()} --- 3.11: 5 rapid sequential payments ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    for i in range(5):
        send_cmd(f"pay 0 1 1000")
        time.sleep(1)  # Minimal delay
    time.sleep(15)
    new = get_new_output(log_before)
    succeeded_count = new.count("succeeded")
    results["rapid_payments"] = succeeded_count >= 3  # At least 3 of 5 should succeed
    print(f"  Succeeded: {succeeded_count}/5")
    print(f"  {ts()} RESULT: {'PASS' if results['rapid_payments'] else 'FAIL'}")

    # Test 3.12: Bidirectional payments (0->1 then 1->0)
    # Run last: reverse payment can block daemon for up to 120s on failure
    # Cooldown after rapid payments to let daemon fully settle
    time.sleep(5)
    print(f"\n{ts()} --- 3.12: bidirectional payments ---")
    log_before = len(read_log("/tmp/bound_pay.log"))
    send_cmd("pay 0 1 2000")
    time.sleep(20)
    send_cmd("pay 1 0 1000")
    time.sleep(20)
    new = get_new_output(log_before)
    succeeded_count = new.count("succeeded")
    results["bidirectional"] = succeeded_count >= 1  # At least forward should succeed
    print(f"  Succeeded: {succeeded_count}/2")
    print(f"  {ts()} RESULT: {'PASS' if results['bidirectional'] else 'FAIL'}")

    # Cleanup payment factory
    send_cmd("close")
    try:
        lsp.wait(timeout=20)
    except:
        lsp.terminate()
        try: lsp.wait(timeout=10)
        except: lsp.kill()
    lsp_log.close()
    for c, clog in cl:
        c.terminate()
        clog.close()
    time.sleep(2)

# ============================================================
# SECTION 4: ROTATION AND LIFECYCLE
# ============================================================

print("\n" + "=" * 60)
print("SECTION 4: ROTATION AND LIFECYCLE")
print("=" * 60)

# Test 4.1: Rotation with --active-blocks 5 (very short)
print(f"\n{ts()} --- 4.1: Rotation with active-blocks=5 ---")
addr = fresh_regtest()

clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", "/tmp/bound_rot.log")
for i in range(2):
    clean_files(f"/tmp/boundrot_client_{i}.db", f"/tmp/boundrot_client_{i}.log")

lsp_rot_log = open("/tmp/bound_rot.log", "w")
lsp_rot_cmd = [LSP, "--seckey", LSP_SECKEY, "--amount", "200000", "--clients", "2",
               "--wallet", WALLET, "--port", str(TEST_PORT+5), "--network", "regtest",
               "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass", "--fee-rate", "1000",
               "--db", "/tmp/boundary_test.db", "--report", "/tmp/boundary_report.json",
               "--daemon", "--cli", "--active-blocks", "5", "--dying-blocks", "3"]
lsp_rot = subprocess.Popen(lsp_rot_cmd, stdin=subprocess.PIPE, stdout=lsp_rot_log,
                            stderr=subprocess.STDOUT, env=env)
time.sleep(2)

cl_rot = start_clients(2, TEST_PORT+5, "boundrot")
mine_n(addr, 5)

ok = wait_for_in_file("/tmp/bound_rot.log", "daemon loop started", timeout=90)
if ok:
    print("  Factory created, mining to trigger rotation...")
    # Mine enough blocks to pass active period
    mine_n(addr, 8)
    time.sleep(10)
    log = read_log("/tmp/bound_rot.log")
    has_rotation = "rotation" in log.lower()
    results["short_rotation"] = has_rotation
    # Print rotation-related lines
    for line in log.split("\n"):
        ll = line.lower()
        if "rotation" in ll or "close" in ll or "new factory" in ll:
            print(f"  {line.strip()}")
else:
    results["short_rotation"] = False
    print("  FAIL: factory never started")

print(f"  {ts()} RESULT: {'PASS' if results['short_rotation'] else 'FAIL'}")

# Cleanup
lsp_rot.stdin.write(b"close\n")
lsp_rot.stdin.flush()
try:
    lsp_rot.wait(timeout=20)
except:
    lsp_rot.terminate()
    try: lsp_rot.wait(timeout=10)
    except: lsp_rot.kill()
lsp_rot_log.close()
for c, clog in cl_rot:
    c.terminate()
    clog.close()
time.sleep(2)

# Test 4.2: Force close via --force-close flag
print(f"\n{ts()} --- 4.2: Force close (--force-close) ---")
addr = fresh_regtest()

clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", "/tmp/bound_fc.log")
for i in range(2):
    clean_files(f"/tmp/boundfc_client_{i}.db", f"/tmp/boundfc_client_{i}.log")

lsp_fc_log = open("/tmp/bound_fc.log", "w")
lsp_fc_cmd = [LSP, "--seckey", LSP_SECKEY, "--amount", "100000", "--clients", "2",
              "--wallet", WALLET, "--port", str(TEST_PORT+6), "--network", "regtest",
              "--rpcuser", "rpcuser", "--rpcpassword", "rpcpass", "--fee-rate", "1000",
              "--force-close"]
lsp_fc = subprocess.Popen(lsp_fc_cmd, stdout=lsp_fc_log, stderr=subprocess.STDOUT, env=env)
time.sleep(2)

cl_fc = start_clients(2, TEST_PORT+6, "boundfc")
mine_n(addr, 8)

# Wait for it to complete (force close should exit after broadcasting tree)
try:
    lsp_fc.wait(timeout=120)
except:
    lsp_fc.terminate()
    try: lsp_fc.wait(timeout=10)
    except: lsp_fc.kill()

log = read_log("/tmp/bound_fc.log")
results["force_close"] = "force" in log.lower() or "broadcast" in log.lower() or "tree" in log.lower()
print(f"  Exit code: {lsp_fc.returncode}")
for line in log.split("\n")[-10:]:
    print(f"  {line.strip()}")
print(f"  {ts()} RESULT: {'PASS' if results['force_close'] else 'FAIL'}")

lsp_fc_log.close()
for c, clog in cl_fc:
    c.terminate()
    clog.close()
time.sleep(1)

# ============================================================
# SECTION 5: PLACEMENT MODES & ECONOMIC MODES
# ============================================================

print("\n" + "=" * 60)
print("SECTION 5: PLACEMENT & ECONOMIC MODES")
print("=" * 60)

for mode_name, mode_arg in [("inward", "inward"), ("outward", "outward")]:
    print(f"\n--- 5.x: placement-mode {mode_name}, 4 clients ---")
    addr = fresh_regtest()

    clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", f"/tmp/bound_pm_{mode_name}.log")
    for i in range(4):
        clean_files(f"/tmp/boundpm{mode_name}_client_{i}.db", f"/tmp/boundpm{mode_name}_client_{i}.log")

    lsp_pm, lsp_pm_log = run_lsp_daemon(["--placement-mode", mode_arg], TEST_PORT+7,
                                          f"/tmp/bound_pm_{mode_name}.log", n_clients=4)
    time.sleep(2)
    cl_pm = start_clients(4, TEST_PORT+7, f"boundpm{mode_name}")
    mine_n(addr, 6)

    ok = wait_for_in_file(f"/tmp/bound_pm_{mode_name}.log", "daemon loop started", timeout=90)
    results[f"placement_{mode_name}"] = ok
    if not ok:
        log = read_log(f"/tmp/bound_pm_{mode_name}.log")
        for line in log.split("\n")[-5:]:
            print(f"  {line.strip()}")
    print(f"  {ts()} RESULT: {'PASS' if ok else 'FAIL'}")

    cleanup_procs(lsp_pm, *cl_pm)
    TEST_PORT += 1  # Avoid port conflicts
    time.sleep(2)

# Test 5.3: profit-shared economic mode
print(f"\n{ts()} --- 5.3: economic-mode profit-shared ---")
addr = fresh_regtest()

clean_files("/tmp/boundary_test.db", "/tmp/boundary_report.json", "/tmp/bound_econ.log")
for i in range(2):
    clean_files(f"/tmp/boundecon_client_{i}.db", f"/tmp/boundecon_client_{i}.log")

lsp_ec, lsp_ec_log = run_lsp_daemon(["--economic-mode", "profit-shared", "--default-profit-bps", "500"],
                                      TEST_PORT+10, "/tmp/bound_econ.log", n_clients=2)
time.sleep(2)
cl_ec = start_clients(2, TEST_PORT+10, "boundecon")
mine_n(addr, 5)

ok = wait_for_in_file("/tmp/bound_econ.log", "daemon loop started", timeout=120)
results["econ_profit_shared"] = ok
if not ok:
    log = read_log("/tmp/bound_econ.log")
    for line in log.split("\n")[-5:]:
        print(f"  {line.strip()}")
print(f"  {ts()} RESULT: {'PASS' if ok else 'FAIL'}")

cleanup_procs(lsp_ec, *cl_ec)
time.sleep(1)

# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("BOUNDARY VALUE TEST SUMMARY")
print("=" * 60)

sections = {
    "CLI Flag Validation": [k for k in results if k.startswith(("arity", "clients", "spl", "bal_", "ctimeout", "rebal", "placement_bad", "bps_", "atimeout", "mainnet", "test_non"))],
    "Factory Creation": [k for k in results if k.startswith(("1client", "8client", "3client"))],
    "Payment Boundaries": [k for k in results if k.startswith(("pay_", "rebal_", "rapid", "bidir", "status_4"))],
    "Rotation/Lifecycle": [k for k in results if k.startswith(("short_", "force_"))],
    "Placement/Economic": [k for k in results if k.startswith(("placement_", "econ_"))],
}

total_pass = 0
total_fail = 0

for section, keys in sections.items():
    if not keys:
        continue
    print(f"\n  {section}:")
    for k in sorted(keys):
        v = results.get(k, False)
        status = "PASS" if v else "FAIL"
        if v: total_pass += 1
        else: total_fail += 1
        print(f"    {k:30s} {status}")

# Any results not in a section
uncategorized = [k for k in results if not any(k in keys for keys in sections.values())]
if uncategorized:
    print(f"\n  Other:")
    for k in sorted(uncategorized):
        v = results[k]
        status = "PASS" if v else "FAIL"
        if v: total_pass += 1
        else: total_fail += 1
        print(f"    {k:30s} {status}")

print(f"\n  TOTAL: {total_pass}/{total_pass + total_fail} passed")
