# Design proposal: multi-transaction cooperative close (large-factory payout)

Status: **proposal / feature request** (research done, not implemented).
Motivated by the signer-scaling work (256-signer factory proven; see
`tools/test_musig_scale.c`, `tools/test_musig_session_scale.c`).

## 1. Problem

The cooperative close spends the **single** factory funding UTXO to one output
per funded client, in **one transaction** (`lsp_channels_build_close_outputs`,
`src/lsp_channels.c`). This is inherent: a UTXO is spent by exactly one tx, and
the builder enforces `sum(outputs) + fee == funding_amount`.

Two facts bound how large that one tx gets:

- **Empty channels cost nothing.** `build_close_outputs` folds every sub-dust
  balance (`< 546` sats, including never-funded 0-balance channels) into the LSP
  output and emits no output for it (`lsp_channels.c:6156-6162`). So tx size
  tracks **funded** channels, not signer count. Signing cost tracks *all*
  signers (one 64-byte aggregate — proven to scale to 2048); output count tracks
  *funded* clients only. The two are decoupled.
- **Standardness caps the output count.** `MAX_STANDARD_TX_WEIGHT` = 400,000 wu
  (~100 KB). One P2TR output ≈ 43 bytes ≈ 172 wu, so the ceiling is roughly
  **~2,300 funded outputs (~99 KB)** before a node refuses to relay the close.

So: a factory with 10,000 signers but only ~500 funded clients closes fine in
one ~22 KB tx. A factory with **> ~2,300 funded clients** cannot cooperatively
close in a single standard transaction. That is the gap this proposal addresses.

Non-goal: this does **not** reduce the signer count of any single signature.
All N signers still co-sign the funding spend (one aggregate). Multi-tx solves
the **output-count / tx-size** limit, not a signing limit.

## 2. Proposed construction — a presigned cooperative payout tree

Stage the payout through intermediate outputs instead of paying every client
directly from the funding UTXO:

```
funding UTXO (N-of-N MuSig2)
      │  split-tx  (N-of-N signed; K intermediate outputs)
      ▼
   ┌──────────┬──────────┬─── … ──┐
  int_0      int_1      int_2     int_{K-1}     (each a bucket sub-aggregate)
   │ payout_0 │ payout_1 │         │ payout_{K-1}
   ▼          ▼          ▼         ▼
 bucket_0    bucket_1   …        bucket_{K-1}   (≤ ~2,300 client outputs each)
```

- **split-tx**: spends the funding UTXO to `K` intermediate outputs. One tx,
  `K` outputs (tiny). Signed by the full **N-of-N** (one aggregate — the part
  we've proven scales).
- **payout_i**: spends `int_i` to that bucket's clients (≤ ~2,300 outputs).
  Signed by the parties controlling `int_i`.

Depth-2 handles `K × 2,300` clients (e.g. `K=5` → ~11,500). Deeper/wider trees
scale further; fanout vs depth is a fee/latency tradeoff.

This is the same **presigned-transaction-tree** primitive the factory already
uses for the Decker-Wattenhofer tree and unilateral exit — reused as a
**cooperative, CSV-free, freshly-signed** shallow tree at close time.

## 3. The requester's mechanism — validated, with corrections

The feature was proposed as: *"the LSP controls the MuSig2 side; have everyone
sign the multiple output txs first, then the split; the split UTXO stays
unsigned/unsubmitted until all payout txs are signed; then bundle them so
everyone is paid and everyone stays trustless."*

That is **essentially correct** and matches the standard construction. Precise
version:

- ✅ **Sign children before the parent is broadcast.** The security invariant of
  any presigned tree: collect **every** signature (split **and** all payouts)
  *before broadcasting anything*. Once the split is on-chain, each intermediate
  must already have a valid, presigned payout — otherwise funds can be stranded
  or held hostage.
- ✅ **You can presign the payouts before the split is signed** — and this is the
  subtle part the proposal got right. A payout's input is `split_txid:i`, and
  under SegWit the **txid excludes the witness**, so `split_txid` is fixed the
  moment the split's inputs/outputs are chosen, *before* the split is signed.
  So "sign payouts first, split last" is valid.
- ✅ **Trustless is achievable without new opcodes.** Make each `int_i` a
  **bucket sub-aggregate MuSig2** (its clients + LSP) and presign `payout_i`
  with that sub-aggregate. Nobody can redirect a bucket's funds.
- ⚠️ **Correction — the split still needs *all* N signers.** The split spends the
  funding (the full N-of-N), so every signer co-signs it (one aggregate). Multi-
  tx does not shrink that; it only shrinks per-tx output count. (Fine — the
  aggregate is one 64-byte sig, proven to 2048 signers.)
- ⚠️ **"tx bundle" = package relay, with limits.** Bitcoin Core `submitpackage`
  relays a parent+children package, but current limits are ~25 txs / 101 KvB per
  package. So either (a) buckets fit one package, or (b) broadcast the split,
  wait for confirmation, then broadcast payouts (each spends a now-confirmed
  intermediate). Sequential is simplest and needs no package support.

## 4. Alternative: CTV (BIP-119)

If `OP_CHECKTEMPLATEVERIFY` were available, each `int_i` could **commit** to its
exact `payout_i` template, so no presigning of payouts is needed — anyone can
broadcast the committed child. Cleaner and less interactive, but CTV is not on
mainnet and not on standard signet, so the **presigned-MuSig-tree above is the
build-today path**; CTV is a future simplification.

## 5. Relationship to existing code

- The unilateral **force-close already is** a presigned multi-tx walk of the DW
  tree (topological multi-pass, CSV-gated). The machinery (nodes, per-node
  keyaggs, presigned spends) exists.
- This proposal adds a **cooperative** shallow tree used only at close: fresh
  sub-aggregate keys for buckets, no CSV (cooperative), one extra signing round
  per tree level. It should reuse `factory_node_t` keyagg plumbing and the
  MuSig session path (`musig_session_*`).
- `lsp_channels_build_close_outputs` would gain a bucketed variant that emits the
  split + per-bucket payout templates; Phase 5 of the LSP close would run the
  multi-level ceremony and the staged/packaged broadcast.

## 6. Open questions (for review before implementation)

1. **Bucketing policy** — by client index? by balance? fixed K vs adaptive to
   funded-count? Dust handling at the *intermediate* level (an intermediate must
   itself be ≥ dust and cover its payout's fee).
2. **Intermediate key structure** — bucket = (its clients + LSP) MuSig2? Who is
   in each sub-aggregate, and how are those keys derived/verified so the tree is
   verifiable by each client (a client must confirm its payout is correctly
   presigned before contributing to the split).
3. **Fee accounting across the tree** — split outputs must fund payout fees;
   K+1 txs cost more total fee than one; how to distribute the fee fairly.
4. **Fee-bumping** — presigned txs can't be RBF'd; needs CPFP/anchors. This
   inherits the fee-race / pinning concerns already tracked for the single-tx
   close (see the fee-race/pinning/1p1c design work). Anchor outputs per tree tx?
5. **Broadcast strategy** — package relay (bounded K per package) vs sequential
   (split confirms first). Reorg behavior of the tree.
6. **Interaction with unilateral exit** — if the cooperative close stalls after
   the split confirms, each intermediate must still be unilaterally spendable by
   its bucket (the presigned payout is that path). Verify no new hostage vector.
7. **Verification burden on clients** — each client must verify the whole
   split + its bucket's payout before signing the split. Keep this O(bucket),
   not O(N), so scaling holds.

## 7. Feasibility verdict

**Feasible, and the requester's design is sound** — it is a standard presigned
tx-tree, buildable today with MuSig2 sub-aggregates (no new consensus features),
reusing machinery the factory already has for unilateral exit. It is, however, a
**real feature** (bucketing, intermediate keys, multi-level ceremony, staged
broadcast, fee accounting), **not** a small change.

**Recommendation:** keep it **out of the signer-scaling PR** (which stays
single-tx and validates the ceiling: a ~99 KB / ~2,300-output close that lands
on signet, plus a ~430 KB oversized close that our code builds and signet
rejects — pinning the exact limit). Track this multi-tx cooperative close as its
own feature, scheduled after the scaling harness lands.
