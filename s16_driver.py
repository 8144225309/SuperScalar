#!/usr/bin/env python3
import subprocess, time, sys

LSP_CMD = [
    "/root/SuperScalar/build/superscalar_lsp",
    "--network", "signet", "--port", "9816",
    "--demo", "--daemon", "--cli",
    "--active-blocks", "50", "--dying-blocks", "20",
    "--step-blocks", "5", "--states-per-layer", "2",
    "--seckey", "0000000000000000000000000000000000000000000000000000000000000001",
    "--fee-rate", "110", "--wallet", "faucet",
    "--rpcuser", "signetrpc", "--rpcpassword", "signetrpcpass123",
    "--db", "/root/ss_signet_exhibit/s16/lsp.db",
    "--report", "/root/ss_signet_exhibit/s16/report.json",
]
LOG = "/root/ss_signet_exhibit/s16/lsp.log"
NL = bytes([10])

log_f = open(LOG, "w")
proc = subprocess.Popen(LSP_CMD, stdin=subprocess.PIPE, stdout=log_f, stderr=subprocess.STDOUT)
print(f"LSP PID: {proc.pid}", flush=True)

while True:
    time.sleep(5)
    if proc.poll() is not None:
        print(f"LSP exited early: {proc.returncode}", flush=True)
        sys.exit(1)
    content = open(LOG).read()
    if "entering daemon mode" in content:
        break

print("Daemon mode detected, waiting for 4 client reconnections...", flush=True)
# Wait until all 4 clients are connected and ready
for _ in range(120):  # up to 10 min
    time.sleep(5)
    content = open(LOG).read()
    reconnects = content.count("reconnected (commitment=")
    if reconnects >= 4:
        break
print(f"Clients ready ({reconnects} reconnections found), waiting 15s...", flush=True)
time.sleep(15)

print("Sending reset command...", flush=True)
proc.stdin.write(b"reset" + NL)
proc.stdin.flush()
time.sleep(10)

content = open(LOG).read()
if "epoch reset complete" in content:
    print("EPOCH RESET: PASS", flush=True)
elif "epoch reset FAILED" in content:
    print("EPOCH RESET: FAILED (check client logs for debug output)", flush=True)
else:
    print("EPOCH RESET: unknown result", flush=True)

print("Sending close command...", flush=True)
proc.stdin.write(b"close" + NL)
proc.stdin.flush()

rc = proc.wait(timeout=600)
print(f"LSP exit: {rc}", flush=True)
