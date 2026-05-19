# Shape 3a — N=8 ARITY=3 (uniform PS baseline)

Smallest pure-PS shape from `docs/signet-ps-n8-procedure.md` §3a.
8 clients, each their own PS leaf, no sub-factory, no static-near-root.

## Why this matters
The baseline PS leaf shape — proves the canonical `--arity 3` leaf path
works on real chain. If 3e (sub-factory) breaks but 3a passes, the
delta is the sub-factory ceremony specifically.

## Topology
```
root  (8 children, arity-3 split → 3 mid nodes → 8 PS leaves)
  ├── PS leaf 0  (LSP + client 1, 2 outputs: channel + L-stock)
  ├── ...
  └── PS leaf 7
```
- 8 PS leaves (one client each)
- Tree depth: 3 (uniform PS at N=8 builds depth-3)
- DW layers after PS subtraction: 3 → ewt = 3 × per_layer (signet) or 1296 mainnet blocks
- Funding: 1M sats per client × 8 = 8M sats per factory

## Variants
- **V1 lifecycle** — coop close path; sweeps via PS leaf channel outputs
- **V2 force-close** — broadcasts factory root → all 8 leaves → per-client sweeps

## Pool assignment
- V1 → ss_pool_2
- V2 → ss_pool_3
