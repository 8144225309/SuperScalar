# Signet PS k² Sub-Factory Lifecycle — Operator Procedure

**Status:** v0.1.15 PR-E.  The first end-to-end k² PS sub-factory
campaign on real signet, exercising the wire-ceremony poison TX
(PR #138), persistence (PR #141), and breach detection (PR #142) all
the way to on-chain confirmation.

**Wall-clock estimate:** 2-4 hours per campaign (signet block timing
dominates; wire ceremony itself is ~5 min).

**Why signet:** real network with real block timing, but no real money
at stake.  The first deployment of the canonical k² shape outside of
regtest unit/regtest tests.

---

## Prerequisites

1. VPS access — see `~/.claude/projects/C--pirq-soup/memory/reference_vps.md`.
2. Signet bitcoind synced and running (`bitcoin-cli -signet getblockchaininfo`).
3. LSP wallet ≥ 1M sats.  Check via:
   ```
   bitcoin-cli -signet -rpcwallet=superscalar_lsp getbalance
   ```
   If insufficient, top up via signet faucet
   (https://signetfaucet.com/) to the LSP's funding address.
4. Latest `main` branch built:
   ```
   cd ~/SuperScalar
   git pull
   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
   cmake --build build --parallel
   ```

---

## 10-step procedure

### 1. Pre-flight check

```bash
cd ~/SuperScalar
bitcoin-cli -signet getblockchaininfo | jq '.headers, .blocks'
# Headers should equal blocks (chain fully synced).

bash tools/signet_setup.sh status
# Confirm bitcoind running, LSP/Client/Bridge stopped.
```

### 2. Launch the campaign in tmux

The campaign takes 2-4 hours; running in tmux survives SSH
disconnections.

```bash
tmux new -s k2-campaign
cd ~/SuperScalar
bash tools/signet_k2_campaign.sh
# Detach with Ctrl-b d; reattach later with `tmux attach -t k2-campaign`.
```

The script prints a transcript to `/tmp/ss-k2-signet-campaign-<unix>/transcript.log`
and writes a structured summary to `summary.json` in the same dir.

### 3. Verify the off-chain ceremony

The script's first phase invokes `signet_setup.sh demo-k2-subfactory`
with `FORCE_CLOSE=1`.  Look for these markers in the transcript (or
in `<campaign-dir>/lsp.log`):

- `LSP: sub-factory 0.0 wire-ceremony poison TX signed (... bytes ...)`
  — Confirms the multi-process MuSig2 poison ceremony succeeded
  (closes Gap A SECURITY GAP).
- `LSP: sub-factory 0.0 chain extended to len 1 (client[0]+=10000 sats)`
  — Confirms the chain advance + balance shift.
- `ps_subfactory_chains rows: 1` — Confirms PR-B persistence wrote
  the new chain entry (poison_tx_hex column populated).

### 4. Watch tree-tx broadcast

After the ceremony, the LSP daemon broadcasts every signed tree TX
via `sendrawtransaction`.  Look for `tree TXs broadcast: N` in the
transcript.  N depends on the shape (root + interior + leaf nodes);
for k=2 N=4 expect ~7-9.

### 5. Wait for confirmations

The script polls bitcoind every 30 seconds until every tree TX
has ≥1 confirmation.  Signet block time is ~30-60 min, so confirming
N=7 transactions can take 2-3 hours wall-clock.  Progress prints
every 10 minutes.

If the confirmation timeout (`TREE_CONFIRM_TIMEOUT`, default 4h)
expires before all confirmed, the script exits with `fail` and the
summary records `n_confirmed` < `n_tree_tx` — re-run after fee bump
or wait for next signet faucet window.

### 6. Per-output enumeration

After all tree TXs confirm, the script iterates each tree TX with
`getrawtransaction TXID 1` and sums every vout's value.  Reports:

- `total outputs across all N tree TXs` (count)
- `aggregate output value` (sats)
- `funding_sats` (target, 400000 by default)

### 7. Conservation assertion

The script asserts `0 < Σ outputs ≤ funding_sats`.  The delta
`funding_sats - Σ outputs` is the cumulative miner fee + dust margin
across the tree (typically 1k-3k sats).  Negative or zero output sums
indicate a serious accounting bug — STOP and investigate.

### 8. Pass / fail report

The script writes `<campaign-dir>/summary.json`:

```json
{
  "result": "pass",
  "n_clients": 4,
  "arity": 3,
  "ps_subfactory_arity": 2,
  "funding_sats": 400000,
  "n_tree_tx": 7,
  "n_confirmed": 7,
  "total_outputs": 14,
  "total_output_sats": 397842,
  "fee_delta_sats": 2158,
  "elapsed_sec": 9842,
  "campaign_dir": "/tmp/ss-k2-signet-campaign-1730000000"
}
```

Operator: copy this JSON to the v0.1.15 release notes / signet
artifact tracking.

### 9. Archive artifacts

The campaign directory contains:
- `transcript.log` — full stdout/stderr of the campaign run
- `summary.json` — structured pass/fail report
- `lsp.log` — LSP daemon log copy (contains the wire-ceremony trace)
- `lsp.db` — LSP SQLite snapshot (contains broadcast_log + ps_subfactory_chains)

Mirror to long-term storage:
```bash
tar czf ~/signet-campaigns/k2-$(date +%Y%m%d-%H%M%S).tar.gz \
        /tmp/ss-k2-signet-campaign-*/
```

### 10. Stop SuperScalar processes

Cleanup (does NOT touch bitcoind / CLN — see
`~/.claude/projects/C--pirq-soup/memory/feedback_never_wipe_campaign_state.md`):

```bash
pkill -f superscalar_lsp || true
pkill -f superscalar_client || true
```

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `cannot find LSP DB` | `signet_setup.sh` setup never ran | Verify `~/SuperScalar/bin/superscalar_lsp` exists; run `bash tools/signet_setup.sh status` |
| `no tree-tx broadcasts in LSP DB` | LSP exited before broadcasting | Check `lsp.log` for crash; rebuild from latest main |
| `n_confirmed < n_tree_tx` | Slow signet blocks or fee market | Re-run; signet sometimes goes 1+ hr between blocks; consider RBF if needed |
| `aggregate output value` near zero | bitcoind getrawtransaction fails (no txindex) | Add `txindex=1` to bitcoin.conf, restart bitcoind, wait for reindex |
| Conservation check FAIL | Real accounting bug | STOP — preserve all artifacts, file an issue with the campaign-dir contents |

---

## What this proves (and what it doesn't)

**Proves:**
- The full k² PS sub-factory shape works on a live network.
- The wire-ceremony poison TX from PRs #136-#138 produces a valid TX.
- PR-B persistence stores the poison TX bytes (visible in `lsp.db`).
- Conservation holds: every input sat ends up either in an output or
  a miner fee.

**Doesn't prove (out of scope for PR-E):**
- Per-client P2TR sweeps complete on the watching client side.  That's
  client-side scantxoutset + sweep-tx broadcast, which the campaign
  doesn't run (LSP-only).
- Tier B rotation poison TX is wire-signed (deferred to PR-D in the
  next focused session).
- Multiple campaigns survive an LSP restart between them.  PR-B's
  persistence covers the data layer; the operator can verify by killing
  the LSP between phases 4 and 5 and confirming the script recovers.
