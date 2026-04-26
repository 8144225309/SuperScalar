# Signet Manual Test Procedure — Canonical Mixed-Arity Shapes

## Why this is a manual procedure

Phase 3 item #3 of the v0.1.14 audit (`docs/v0114-audit-phase3.md`) requires
running a full PS factory lifecycle on **real signet** with chain advances
and per-party accounting. Phase 5 of the mixed-arity initiative
(PRs #102-#106) extends this to the canonical mixed-arity + static-near-root
shapes that produce the design-target ewt budgets.

Signet block times average ~10 minutes, so a full lifecycle (factory funding
→ tree broadcast → chain advances → sweeps → accounting verification) takes
**4-8 hours of real wall clock** for an N=8 PS shape and longer for larger N
or deeper trees. This doesn't fit in any agent or CI session, so instead of a
one-shot automated test we ship the infrastructure (`tools/signet_setup.sh`
now accepts `N_CLIENTS`, `ARITY`, and `STATIC_NEAR_ROOT` env vars) plus this
procedure for a human operator to drive the campaign at their pace.

## Smoke-test status

Pre-campaign smoke tests have validated the infrastructure end-to-end up
to the broadcast threshold (without burning multi-hour wall-clock):

- `signet_setup.sh` parses cleanly with all canonical env-var combinations
  (`N_CLIENTS=8 ARITY=3,4 STATIC_NEAR_ROOT=1`, `N_CLIENTS=64 ARITY=2,4,8 STATIC_NEAR_ROOT=1`,
  `N_CLIENTS=128 ARITY=2,4,8 STATIC_NEAR_ROOT=2`)
- `superscalar_lsp` binary recognizes `--arity 3,4` and `--static-near-root 1`
  on `--network signet`
- Signet bitcoind reachable at `/var/lib/bitcoind-signet`; `superscalar_lsp`
  wallet has ≥1M sats (verify before launch)
- `bitcoin-cli ... -rpcwallet=superscalar_lsp loadwallet superscalar_lsp`
  may need to be run if the wallet shows as unloaded

The full lifecycle is the operator's call to launch when a multi-hour
window is available.

## Prerequisites

- VPS at `root@68.168.216.243` reachable via SSH
- bitcoind signet running with at least 1M sats in the `superscalar_lsp`
  wallet (verify: `bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf -rpcwallet=superscalar_lsp getbalance`)
- Latest SuperScalar build on VPS at `/root/SuperScalar/build/`

## Canonical shapes

The shapes below are the recommended Phase 5 deployments. All ewt numbers
come from `factory_compute_ewt_for_shape()` with `states_per_layer=4`. The
`signet ewt (sb=1)` column is the worst-path block budget the operator will
actually wait for during the live signet run, where every CSV block costs
one signet block (~10 min). The `mainnet ewt (sb=144)` column is what the
same shape would cost on production and is the value the BOLT-2016 ceiling
check enforces at LSP startup.

| Shape | tree depth | DW layers | mainnet ewt | signet ewt (sb=1) | use case |
|---|---|---|---|---|---|
| `N_CLIENTS=8 ARITY=3 STATIC_NEAR_ROOT=0`   | 3 | 4 | 1296 | 9 | small-N PS baseline (existing audit campaign) |
| `N_CLIENTS=8 ARITY=3,4 STATIC_NEAR_ROOT=1` | 1 | 1 | 432  | 3 | mid-size mixed-arity (smallest live signet test) |
| `N_CLIENTS=64 ARITY=2,4,8 STATIC_NEAR_ROOT=1` | 2 | 2 | 864  | 6 | scale-shape canonical (depth halved vs uniform) |
| `N_CLIENTS=128 ARITY=2,4,8 STATIC_NEAR_ROOT=2` | 3 | 2 | 864 | 6 | maximum-scale canonical (the design target) |

> **Note:** `N_CLIENTS=64 ARITY=3` (uniform PS at scale) computes to mainnet
> ewt=2592 blocks, which **exceeds the BOLT-2016 ceiling** (2016 blocks).
> The LSP will refuse to start with that shape on mainnet. The 64- and 128-
> client deployments above use mixed-arity precisely because uniform PS
> stacks too much CSV.

### Wall-clock estimates

Each signet block is ~10 minutes. The dominant chain-time cost is:
- Funding TX confirmation: ~10 min (1 block)
- Tree broadcast: depth × ~10 min × (states_per_layer-1) for non-static layers
- Per-leaf force-close sweep: 1 block per CSV step the leaf has accumulated

Rough expected wall-clock for the full lifecycle (funding → tree broadcast
→ payments → force-close → all leaves swept):

| Shape | Lifecycle wall-clock |
|---|---|
| `N=8 ARITY=3`                              | ~3-5 hours (force-close path, 8 leaves to sweep) |
| `N=8 ARITY=3,4 STATIC_NEAR_ROOT=1`         | ~2-3 hours (depth=1, only 1 DW layer of CSV) |
| `N=64 ARITY=2,4,8 STATIC_NEAR_ROOT=1`      | ~6-10 hours (depth=2, 64 leaves to sweep) |
| `N=128 ARITY=2,4,8 STATIC_NEAR_ROOT=2`     | ~10-16 hours (depth=3, 128 leaves to sweep, but only 2 DW layers thanks to static-near-root) |

Use a `tmux` / `screen` session on the VPS for runs longer than ~2h.

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

Need ≥0.01 BTC (1M sats) in the LSP wallet to fund a PS factory at N=8;
larger N needs proportionally more (the LSP funds `--amount 200000` per the
script defaults; multiply by N as a worst-case envelope).

### 3. Pick a shape and start the lifecycle

The patched `signet_setup.sh` accepts `N_CLIENTS`, `ARITY`, and the new
`STATIC_NEAR_ROOT` env var (Phase 5 of the mixed-arity plan). Pick one
of the canonical shapes from the table above and invoke `demo-coop` (for
the cooperative-close lifecycle) or `demo-force-close` (closer to phase 3
item #3's goal — exercises chain advances + sweeps).

#### 3a. N=8 uniform PS (original Phase 3 #3 baseline)

```
ssh root@68.168.216.243 "cd /root/SuperScalar && N_CLIENTS=8 ARITY=3 bash tools/signet_setup.sh demo-coop 2>&1 | tee /tmp/signet_n8_ps_coop.log"
```

#### 3b. N=8 mixed-arity (Phase 5 mid-size canonical)

```
ssh root@68.168.216.243 "cd /root/SuperScalar && N_CLIENTS=8 ARITY=3,4 STATIC_NEAR_ROOT=1 bash tools/signet_setup.sh demo-force-close 2>&1 | tee /tmp/signet_n8_mixed_fc.log"
```

#### 3c. N=64 mixed-arity (scale-shape canonical)

```
ssh root@68.168.216.243 "cd /root/SuperScalar && N_CLIENTS=64 ARITY=2,4,8 STATIC_NEAR_ROOT=1 bash tools/signet_setup.sh demo-force-close 2>&1 | tee /tmp/signet_n64_canonical_fc.log"
```

#### 3d. N=128 mixed-arity (maximum-scale canonical, the design target)

```
ssh root@68.168.216.243 "cd /root/SuperScalar && N_CLIENTS=128 ARITY=2,4,8 STATIC_NEAR_ROOT=2 bash tools/signet_setup.sh demo-force-close 2>&1 | tee /tmp/signet_n128_canonical_fc.log"
```

The LSP prints `"shape ewt = N blocks (BOLT 2016 ceiling = 2016)"` at startup
so the operator can verify the chosen shape was accepted. Then it streams
progress for the rest of the lifecycle.

### 4. Verify on-chain conservation

After the close TX confirms, get the close txid from the log:

```
grep -i "close\|FORCE CLOSE COMPLETE\|tree_node_0" /tmp/signet_n8_mixed_fc.log | tail -20
```

Then verify on-chain:

```
ssh root@68.168.216.243 "bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf getrawtransaction <CLOSE_OR_ROOT_TXID> true | jq '.vout[] | {value: .value, addr: .scriptPubKey.address}'"
```

Sum `value` fields and confirm they total `funding_amount - close_fee`.

### 5. Per-party verification

Each client's keyfile lives at `/var/lib/superscalar/client${i}.key`. The
client wallets receive their close outputs at deterministic P2TR addresses.

```
ssh root@68.168.216.243 "for i in \$(seq 1 \$N_CLIENTS); do
    addr=\$(./build/superscalar_client --keyfile /var/lib/superscalar/client\${i}.key \
              --passphrase superscalar --network signet --print-address)
    bal=\$(bitcoin-cli -signet -conf=/var/lib/bitcoind-signet/bitcoin.conf \
              scantxoutset start \"[\\\"addr(\$addr)\\\"]\" | jq '.total_amount')
    echo \"client\$i: \$addr balance=\$bal BTC\"
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

Phase 5 (this PR) ships the infrastructure (this doc, the `signet_setup.sh`
parameterization, and multi-process N-way verification on regtest) but does
NOT run the full signet lifecycle. The bounded smoke test that DID run
validates:

- `signet_setup.sh` accepts `N_CLIENTS`, `ARITY`, and `STATIC_NEAR_ROOT`
  env vars without parse error
- `lsp_static_args` helper emits the `--static-near-root N` LSP flag only
  when `STATIC_NEAR_ROOT > 0`
- LSP daemon starts under those params, listens on port 9735, ready for
  clients
- Multi-process MuSig at N=8 with mixed arity passes end-to-end on
  **regtest** (`tools/test_multiprocess_musig_n8.sh` with `MIXED_ARITY=1`)

Anything beyond that — actual signet factory funding, tree broadcast,
payment routing, close, sweep, and per-party accounting — is the
**manual campaign documented above**.

## When this campaign should be run

- Before the v0.1.14 release tag is cut (currently suspended; see
  `feedback_no_0114_release` in user memory)
- After any PR that touches `src/factory.c` (tree shape / DW counter),
  `src/lsp_channels.c` / `src/client.c` (close path), or
  `tools/superscalar_lsp.c` (CLI shape validation)
- Periodically (monthly?) as a regression check against signet network
  evolution and node software updates

## Outputs to save

- `/tmp/signet_<shape>_<lifecycle>.log` — full LSP+client output
- The close txid + bitcoind raw-TX dump
- A summary of per-party deltas vs expected

Append the summary to `docs/v0114-audit-phase3.md`'s execution log under
Item #3 with the run date + outcome and the shape parameters used.
