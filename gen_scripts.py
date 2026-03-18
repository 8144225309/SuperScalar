#!/usr/bin/env python3
import os

CLIENTS = [
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "5555555555555555555555555555555555555555555555555555555555555555",
]
LSP_SK = "0000000000000000000000000000000000000000000000000000000000000001"
LSP_PK = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

structures = [
    (1,  9801, "--demo"),
    (12, 9812, "--demo --test-rotation"),
    (11, 9811, "--demo --test-dual-factory"),
    (2,  9802, "--demo --force-close"),
    (3,  9803, "--demo --test-dw-advance"),
    (5,  9805, "--demo --test-leaf-advance"),
    (4,  9804, "--demo --test-dw-exhibition"),
    (7,  9807, "--demo --breach-test"),
    (6,  9806, "--demo --test-burn"),
    (8,  9808, "--demo --test-expiry"),
    (9,  9809, "--demo --test-distrib"),
    (10, 9810, "--demo --test-bridge"),
    (13, 9813, "--demo --test-htlc-force-close"),
]

for sn, port, extra_flags in structures:
    sdir = "/tmp/ss_exhibit_v2/s" + str(sn)
    L = []
    L.append("#!/bin/bash")
    L.append("cd /root/SuperScalar")
    L.append("bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass unloadwallet orchestrator 2>/dev/null || true")
    L.append("bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass unloadwallet superscalar_lsp 2>/dev/null || true")
    L.append("rm -rf " + sdir + " && mkdir -p " + sdir)
    L.append(
        "build/superscalar_lsp --network regtest --port " + str(port) + " " + extra_flags +
        " --active-blocks 50 --dying-blocks 20 --step-blocks 5 --states-per-layer 2" +
        " --seckey " + LSP_SK +
        " --fee-rate 1000 --wallet default --db " + sdir + "/lsp.db" +
        " --rpcuser rpcuser --rpcpassword rpcpass" +
        " --report " + sdir + "/report.json" +
        " > " + sdir + "/lsp.log 2>&1 &"
    )
    L.append("LSP_PID=$!")
    lsp_wait = 6 if sn in (7, 8) else 3
    client_gap = 2 if sn in (7, 8) else 1
    L.append("sleep " + str(lsp_wait))
    for sk in CLIENTS:
        short = sk[:4]
        L.append(
            "build/superscalar_client --network regtest --host 127.0.0.1 --port " + str(port) +
            " --daemon --seckey " + sk +
            " --fee-rate 1000 --db " + sdir + "/c" + short + ".db" +
            " --lsp-pubkey " + LSP_PK +
            " --rpcuser rpcuser --rpcpassword rpcpass" +
            " > " + sdir + "/c" + short + ".log 2>&1 &"
        )
        L.append("sleep " + str(client_gap))
    L.append("wait $LSP_PID")
    L.append("EXIT_CODE=$?")
    L.append('echo "S' + str(sn) + ' exit: $EXIT_CODE"')
    # kill clients
    L.append("ps aux | grep superscalar_client | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null || true")
    L.append(
        "if [ -f " + sdir + "/report.json ] && [ -s " + sdir + "/report.json ]; then"
        + ' echo "S' + str(sn) + ': PASS (report exists)"'
        + '; else echo "S' + str(sn) + ': FAIL (no report)"; fi'
    )
    L.append("grep -i 'pass' " + sdir + "/lsp.log | tail -3 || true")
    L.append("tail -5 " + sdir + "/lsp.log")
    fname = "/root/SuperScalar/run_s" + str(sn) + ".sh"
    with open(fname, "w") as f:
        f.write("\n".join(L) + "\n")
    os.chmod(fname, 0o755)
    print("Written " + fname)

print("All done.")
