# Testnet4 Quickstart

Run all 11 SuperScalar on-chain structures on Bitcoin testnet4.

---

## Prerequisites

1. **Build SuperScalar:**
   ```bash
   mkdir -p build && cd build
   cmake .. && make -j$(nproc)
   cd ..
   ```

2. **Bitcoin Core 28.1+** synced on testnet4:
   ```bash
   bitcoind -testnet4 -daemon -txindex=1
   # Wait for sync to complete
   bitcoin-cli -testnet4 getblockchaininfo | grep blocks
   ```

3. **Funded wallet** — at least 1M sats for running all structures. Get testnet4 coins from a faucet or mine them.

4. **Core Lightning** (optional, structure 4 only):
   - CLN-A with the SuperScalar bridge plugin
   - CLN-B as a vanilla peer
   - Funded channel between them (~500k sats)

---

## Quick Run

```bash
# Run all 11 structures sequentially
bash tools/exhibition_testnet4.sh --all

# Run a single structure
bash tools/exhibition_testnet4.sh --structure 1   # Cooperative close

# Run structures 2,3,7 in parallel (saves calendar time)
bash tools/exhibition_testnet4.sh --parallel 2,3,7
```

### Environment Variables

Override defaults by exporting before running:

```bash
export SS_RPCUSER=myrpcuser
export SS_RPCPASS=myrpcpassword
export SS_RPCPORT=48332
export SS_CLN_A_DIR=/path/to/cln-a
export SS_CLN_B_DIR=/path/to/cln-b
```

---

## Recommended Flags

Testnet4 blocks arrive every ~10 minutes. Use these to minimize BIP68 wait times:

```
--step-blocks 5         # 5 blocks per DW layer (vs 30 default = 50 min vs 5 hours)
--states-per-layer 2    # Fewer states = fewer layers = fewer waits
--active-blocks 50      # Factory lifetime ~8 hours
--dying-blocks 20       # Migration window ~3 hours
```

These are already the defaults in `exhibition_testnet4.sh`.

For long-running daemon tests (rotation, multi-hour), add:
```
--heartbeat-interval 300   # Print status every 5 minutes
```

---

## Time Estimates

With `--step-blocks 5 --states-per-layer 2` at ~10 min/block:

| # | Structure | Blocks | Estimate |
|---|-----------|--------|----------|
| 1 | Cooperative close | ~6 | ~1 hour |
| 2 | Full DW tree (force close) | ~30 | ~5 hours |
| 3 | L-stock burn | ~35 | ~6 hours |
| 4 | BOLT11 bridge payment | ~6 | ~1 hour |
| 5 | Factory rotation | ~12 | ~2 hours |
| 6 | DW advance + force close | ~40 | ~7 hours |
| 7 | Breach + penalty | ~35 | ~6 hours |
| 8 | CLTV timeout recovery | ~50 | ~8 hours |
| 9 | Remote client (MuSig2 over internet) | ~6 | ~1 hour |
| 10 | Distribution TX (P2A anchor) | ~50 | ~8 hours |
| 11 | JIT channel (late arrival) | ~6 | ~1 hour |

**Total:** ~2-3 days if run sequentially. Parallelize structures 2+3+7 and 8+10 to finish in ~1.5 days.

---

## What Each Structure Proves

| # | Structure | On-chain Artifact |
|---|-----------|-------------------|
| 1 | Cooperative close | Single close TX spending funding output (key-path Taproot) |
| 2 | Full DW tree | Complete kickoff + state node chain with BIP68 nSequence timelocks |
| 3 | L-stock burn | Shachain-preimage reveal burning old state commitment |
| 4 | BOLT11 bridge | HTLC routed: CLN-B -> CLN-A -> bridge -> factory client |
| 5 | Rotation | Old factory close + new factory fund in one atomic flow |
| 6 | DW advance | Re-signed tree with decremented nSequence values |
| 7 | Breach + penalty | Penalty TX claiming breacher's funds via revocation key |
| 8 | CLTV timeout | Timeout TX reclaiming funds after absolute timelock expiry |
| 9 | Remote client | MuSig2 signing ceremony over TCP/Noise across the internet |
| 10 | Distribution TX | P2A-anchored distribution splitting factory output to clients |
| 11 | JIT channel | Separate funding+close TX pair for late-arriving client |

---

## Inspecting Results

After running, inspect the on-chain TX tree:

```bash
# View the exhibition report
cat /tmp/exhibition_testnet4/exhibition_summary.md

# Inspect a specific structure's TXIDs
python3 tools/inspect_factory.py \
  --txid-file /tmp/exhibition_testnet4/exhibition_txids.json \
  --network testnet4 \
  --rpcuser $SS_RPCUSER --rpcpassword $SS_RPCPASS
```

The inspector classifies each TX (funding, kickoff, state, leaf, close, burn, penalty, distribution), shows witness types, nSequence/nLockTime interpretation, and fee analysis.

---

## Troubleshooting

**"Waiting for confirmation" hangs for hours:**
Normal on testnet4. Each BIP68 layer requires `--step-blocks` real blocks (~50 min with default 5). The progress logging shows current height and time estimate.

**"min relay fee not met":**
Your `--fee-rate` is too low. Increase it: `--fee-rate 2000` (2 sat/vB).

**TX stuck in mempool >1 hour:**
A warning will be printed with the TXID. Use `bitcoin-cli -testnet4 bumpfee <txid>` to CPFP bump it.

**Client disconnects during long wait:**
The daemon auto-reconnects clients. If a MuSig2 ceremony was in progress, the operation will be retried on reconnection.

**"estimatesmartfee" returns -1:**
Fresh testnet4 nodes have no fee data. Use explicit `--fee-rate 1000` until the node has seen enough blocks.
