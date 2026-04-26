# Signet PS at N=8 — Manual Test Procedure

## Why this is a manual procedure

Phase 3 item #3 of the v0.1.14 audit (`docs/v0114-audit-phase3.md`) requires
running a full PS factory lifecycle on **real signet** at N=8 with chain
advances and per-party accounting. Signet block times average ~10 minutes,
so a full lifecycle (factory funding → tree broadcast → chain advances →
sweeps → accounting verification) takes **4-8 hours of real wall clock**.

This doesn't fit in any agent or CI session. So instead of a one-shot
automated test, we ship the infrastructure (`tools/signet_setup.sh` now
accepts `N_CLIENTS` and `ARITY` env vars) plus this procedure for a
human operator to drive the full campaign at their pace.

## Prerequisites

- VPS at `root@68.168.216.243` reachable via SSH
- bitcoind signet running with at least 1M sats in the `superscalar_lsp`
  wallet (verify: `bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf -rpcwallet=superscalar_lsp getbalance`)
- Latest SuperScalar build on VPS at `/root/SuperScalar/build/`

## Procedure

### 1. Sync VPS to latest main + rebuild

```
ssh root@68.168.216.243 "cd /root/SuperScalar && git fetch origin && git checkout main && git pull && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc) 2>&1 | tail -10"
```

Confirm `superscalar_lsp` and `superscalar_client` binaries built.

### 2. Verify signet bitcoind is healthy

```
ssh root@68.168.216.243 "bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf getblockchaininfo | head -5"
ssh root@68.168.216.243 "bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf -rpcwallet=superscalar_lsp getbalance"
```

Need ≥0.01 BTC (1M sats) in the LSP wallet to fund a PS factory at N=8.

### 3. Start the lifecycle

The patched `signet_setup.sh` accepts `N_CLIENTS` and `ARITY` env vars:

```
ssh root@68.168.216.243 "cd /root/SuperScalar && N_CLIENTS=8 ARITY=3 bash tools/signet_setup.sh demo_coop 2>&1 | tee /tmp/signet_ps_n8_run.log"
```

`ARITY=3` selects the Pseudo-Spilman leaf type. `N_CLIENTS=8` opens 8
client channels (one per leaf, since PS has 1 client per leaf).

This runs in the foreground and prints progress. Expected timeline:

| Phase | ~Wall clock |
|---|---|
| LSP startup + funding TX broadcast | <1 min |
| Funding TX confirmed (1 signet block) | ~10 min |
| Factory tree built + signed in-process | <1 min |
| Tree broadcast (each level needs confirms) | ~30-60 min |
| Payments routed across leaves | ~10-20 min |
| Cooperative close TX broadcast + confirmed | ~10 min |
| **TOTAL** | **~1-2 hours** for coop close path |

For the **force-close** path (closer to phase 3 item #3's goal — exercises
chain advances + sweeps), substitute `demo_force_close`:

```
ssh root@68.168.216.243 "cd /root/SuperScalar && N_CLIENTS=8 ARITY=3 bash tools/signet_setup.sh demo_force_close 2>&1 | tee /tmp/signet_ps_n8_fc.log"
```

This adds:
- Each leaf's CSV-delayed force-close sweep — adds ~10 min × N leaves
- **TOTAL: ~3-5 hours** for force-close path

### 4. Verify on-chain conservation

After the close TX confirms, get the close txid from the log:

```
grep -i "close" /tmp/signet_ps_n8_run.log | tail -5
```

Then verify on-chain:

```
ssh root@68.168.216.243 "bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf getrawtransaction <CLOSE_TXID> true | jq '.vout[] | {value: .value, addr: .scriptPubKey.address}'"
```

Sum `value` fields and confirm they total `funding_amount - close_fee`.

### 5. Per-party verification

Each client's keyfile lives at `/var/lib/superscalar/client${i}.key`. The
client wallets receive their close outputs at deterministic P2TR addresses.

```
ssh root@68.168.216.243 "for i in 1 2 3 4 5 6 7 8; do
    addr=$(./build/superscalar_client --keyfile /var/lib/superscalar/client${i}.key \
              --passphrase superscalar --network signet --print-address)
    bal=$(bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf \
              scantxoutset start \"[\\\"addr($addr)\\\"]\" | jq '.total_amount')
    echo \"client$i: $addr balance=$bal BTC\"
done"
```

(Adjust the `--print-address` invocation to whatever the client CLI exposes
for printing its P2TR receive address.)

### 6. Cleanup

```
ssh root@68.168.216.243 "pkill -f superscalar_lsp; pkill -f superscalar_client; sleep 2"
```

The signet wallet retains the swept sats — they can be reused for the next
campaign or sent back to the faucet.

## Smoke test — what's been validated automatically

Phase 3 item #3 ships the infrastructure (this doc + the `signet_setup.sh`
parameterization) but does NOT run the full lifecycle. The bounded smoke
test that DID run validates:

- `signet_setup.sh` accepts `N_CLIENTS=8 ARITY=3` env vars without parse error
- LSP daemon starts under those params, listens on port 9735, ready for clients
- The first signet RPC call (`getbalance`) succeeds (signet chain reachable)

Anything beyond that — actual factory funding, tree broadcast, payment
routing, close, sweep, and per-party accounting — is the **manual
campaign documented above**.

## When this campaign should be run

- Before the v0.1.14 release tag is cut
- After any PR that touches `src/factory.c` PS code paths or
  `src/lsp.c` / `src/client.c` wire-protocol code
- Periodically (monthly?) as a regression check against signet network
  evolution

## Outputs to save

- `/tmp/signet_ps_n8_run.log` (or `_fc.log`) — full LSP+client output
- The close txid + bitcoind raw-TX dump
- A summary of per-party deltas vs expected

Append the summary to `docs/v0114-audit-phase3.md`'s execution log under
Item #3 with the run date + outcome.
