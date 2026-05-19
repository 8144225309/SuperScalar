# Shape 3b — N=8 ARITY=3,4 STATIC_NEAR_ROOT=1

Mid-size mixed-arity shape from `docs/signet-ps-n8-procedure.md` §3b. Adds
two features over 3a: mixed-arity interior fan-out (PS leaves + arity-4 mid),
and static-near-root depth 1 (top layer is kickoff-only, no DW counter).

## Why this matters
First on-chain validation of:
- TRUE N-way mixed-arity fan-out (Phase 2 merge, PR #104)
- Static-near-root (Phase 3 merge, PR #105) — zero CSV contribution from the static layer

## Topology
```
root (STATIC, kickoff-only, nsequence=0xFFFFFFFE)
 └─ arity-4 mid node (4 outputs)
      ├─ PS leaf 0  (LSP + client 1, 2 outputs)
      ├─ PS leaf 1  (LSP + client 2, 2 outputs)
      ├─ PS leaf 2  (LSP + client 3, 2 outputs)
      └─ (arity-3 split below → 8 leaves total)
```

- Tree depth: 2 (root static + 1 DW mid + PS leaves)
- DW layers after PS subtraction and static depth: 1 → ewt = 1 × per_layer (signet) or 432 mainnet blocks

## Variants
- **V1 lifecycle** — coop close path; static root spends directly into mid outputs
- **V2 force-close** — broadcasts static root → mid → 8 leaves → sweeps

## Pool assignment
- V1 → ss_pool_4
- V2 → ss_pool_5
