# Pseudo-Spilman k² sub-factories

## Background

ZmnSCPxj's t/1242 SuperScalar spec describes PS leaves as containing
**k² clients distributed across k pseudo-Spilman sub-factories**, with
**k clients per sub-factory** and the LSP holding "sales stock" inside
each sub-factory that can be dynamically chained into new client
channels.

Quote from t/1242 (post #16 / canonical spec):

> *"For arity of `k`, leaves would have `k²` clients and `k`
> pseudo-Spilman channel factories with `k` clients each."*

> *"The advantages... is that the pseudo-Spilman factory does not
> require an additional decrementing-`nSequence` layer."*

The **rationale** is reducing total nSequence delay: more clients per
leaf → fewer DW layers needed for a target client count → lower CSV
budget → tighter `final_cltv_delta` for incoming HTLCs.

Worked example for k=2:
```
PS leaf (4 clients = k²)
├── sub-factory 1 ─ chain[0]: A&L channel + B&L channel + (A,B,L) sales-stock
└── sub-factory 2 ─ chain[0]: C&L channel + D&L channel + (C,D,L) sales-stock
```

Each sub-factory's sales-stock can be chained: when client A wants more
inbound liquidity, the LSP chains a new (A&L, B&L, sales-stock) state
where A&L gains capacity from sales-stock.

## Pre-PR state (as of `a34c29f`)

- PS leaves are **1-client-per-leaf** (`n_signers=2`, `n_outputs=2` =
  channel + L-stock).  Set by `setup_ps_leaf_outputs` in `src/factory.c`.
- Chain advance in `factory_advance_leaf_unsigned` (PS branch, line ~1912)
  flips `n_outputs` from 2 to 1 and decreases the channel amount by
  `fee_per_tx`.  No sub-factories.
- `compute_leaf_count(n, FACTORY_ARITY_PS)` returns `n` (one leaf per
  client).  `compute_tree_depth` likewise.
- `factory_client_to_leaf` for PS maps client `i` directly to leaf `i`,
  vout 0.
- No `subfactory_t` / `nested_factory_t` infrastructure exists.

## Target post-spec state

Each PS leaf with `k² > 1` will:

- Have `k+1` outputs: `k` sub-factory entry-points + 1 L-stock
- Spawn `k` **NODE_PS_SUBFACTORY** child nodes, one per sub-factory
- Each sub-factory has `k+2` signers (LSP + k clients) and produces a
  chain[0] TX with `k+1` outputs: `k` per-client channels + 1
  sales-stock output
- Sub-factory chain extension (the "buy liquidity from sales-stock" op)
  spends the sub-factory's prior chain TX → new chain TX with adjusted
  channel amounts (one channel grew, sales-stock shrunk), same shape

`compute_leaf_count(n, FACTORY_ARITY_PS, k=K)` becomes `ceil(n / K²)`.
`compute_tree_depth` shortens correspondingly.  At k=2 with N=64
clients: 64 / 4 = 16 leaves → depth 4 vs the current 64 leaves →
depth 6.  Lowers nSequence budget by exactly the count zmn names as
the rationale.

## Phased delivery

This is a multi-day architectural piece.  Splitting into discrete,
mergeable phases:

### Phase 1 — Foundation (this PR)

**Scope:**
- New CLI/factory config: `factory_set_ps_subfactory_arity(f, k)`.
  Default `k=1` preserves current 1-client-per-leaf behavior.
- New node type: `NODE_PS_SUBFACTORY`.
- New struct fields on `factory_node_t`:
  - `int n_subfactories` (k for PS leaves with k>1, else 0)
  - `int subfactory_node_indices[FACTORY_MAX_SUBFACTORIES]` (entries point into `f->nodes[]`)
- Tree builder: when `k > 1`, `setup_ps_leaf_outputs` becomes
  `setup_ps_leaf_with_subfactories`:
  - Leaf has `k+1` outputs (k sub-factory entry SPKs + L-stock).
  - For each sub-factory, append a `NODE_PS_SUBFACTORY` to `f->nodes[]`
    with `parent_index = leaf, parent_vout = i`, `n_signers = k+1`
    (LSP + k clients in this sub-factory), `n_outputs = k+1` (k
    channels + sales-stock), keyagg = MuSig(LSP, those k clients).
- `compute_leaf_count` / `compute_tree_depth` / `simulate_tree`
  generalize for `k > 1`: leaf count = `ceil(n / k²)`, depth scales
  accordingly.
- `factory_client_to_leaf`: for PS with k>1, maps client `i` to
  `(leaf = i / k², subfactory = (i % k²) / k, channel_in_sub = i % k)`,
  returns `(node_idx, vout)` of the sub-factory's channel output.
- `factory_sign_all` requires no changes — it iterates all
  `f->n_nodes` so the new sub-factory nodes get signed automatically.
- Unit test `test_factory_ps_k2_build` at k=2, N=4:
  - Expect: 1 leaf node, 2 sub-factory nodes, all signed.
  - Verify each sub-factory has 2 client signers + LSP, 3 outputs.
  - Verify the leaf's outputs[0..1] SPKs match sub-factory entry keyaggs.

**Out of scope** (deferred to Phase 2+):
- Sub-factory chain extension ceremony (the dynamic "sell from
  sales-stock" op).
- Sub-factory state advance over the wire (multi-party MuSig with
  sub-factory's k+1 signers — a smaller cousin of Tier B).
- Watchtower per-sub-factory state poison TX.
- On-chain regtest force-close + sweep at k=2.

### Phase 2 — Sub-factory chain extension

Implement `lsp_subfactory_chain_advance(mgr, lsp, leaf_idx, sub_idx,
client_idx_in_sub, amount_to_buy)` that drives a multi-party ceremony
to chain a new sub-factory state with adjusted channel amounts.

This mirrors Tier B's bundled MuSig but scoped to one sub-factory's
signers (LSP + k clients).  New wire messages
`MSG_SUBFACTORY_PROPOSE / NONCE_BUNDLE / ALL_NONCES / PSIG_BUNDLE /
DONE` (or possibly reuse `MSG_PATH_*` infrastructure with a
sub-factory scope tag).

### Phase 3 — On-chain force-close + sweep at k=2

Regtest test: build k=2 N=4 factory, broadcast leaf + sub-factory
chain[0] TXs, each client sweeps their channel output with their own
seckey (similar to existing PS sweep tests).  Conservation + per-party
deltas verified via `econ_helpers`.

### Phase 4 — Persist + watchtower

Store sub-factory state in the persist DB (new table or extension of
existing tree_nodes).  Register sub-factory state TXs with watchtower
for breach detection.  Per-sub-factory poison TX on stale-state
broadcast.

### Phase 5 — Mixed config + signet

CLI `--ps-subfactory-arity 2` flag, deployment script using k=2 + N=16
(4 leaves of 4 clients each = 16 clients with depth 2 vs depth 4 today).
Signet end-to-end campaign.

## Why this PR is foundation-only

Honest scoping after research: each phase is genuinely a non-trivial
day's work.  Phase 1 alone touches:

- New struct field + node type
- Tree builder conditionals
- 4 helper functions (compute_leaf_count, compute_tree_depth,
  simulate_tree, factory_client_to_leaf) that all need k² support
- New unit test at k=2

That's a coherent "foundation lands" PR.  Phase 2 (chain extension) is
itself a new wire ceremony similar to Tier B's complexity and deserves
its own focused review.  Phase 3 (on-chain test) requires Phase 2 to
exist before the test can do anything useful.

Shipping the foundation first lets reviewers evaluate the data
structures + tree shape against the t/1242 spec before the dynamic
extension ceremony commits to a particular protocol direction.

## Cross-references

- `docs/pseudo-spilman.md` — the existing 1-client-per-leaf design
- `docs/factory-arity.md` — mixed-arity tree shapes
- `docs/rotation-ceremony.md` — Tier B ceremony (template for Phase 2)
- t/1242 thread on Delving Bitcoin
- `.claude/CANONICAL_DESIGN_GAPS.md` Gap E followup (task #181)
