# Shape 3f — N=64 ARITY=2,4 PS_SUBFACTORY_ARITY=2 STATIC_NEAR_ROOT=1

**The integration test.** Every PS-SuperScalar feature simultaneously: scale,
mixed-arity interior, static-near-root, k² sub-factory. If 3f PASSES, every
constituent feature is exercised on real chain in combination.

## Why this matters
The most-ambitious shape: validates that the features don't interfere with each
other under load. Bugs that hide at smaller shapes (lock ordering, ceremony
sequencing, scheduler fairness) tend to surface here.

## Topology (16 leaves × 4 clients = 64)
```
root (STATIC, kickoff-only, arity 2)
 ├── mid 0 (DW, arity 4) → 4 PS leaves
 │   ├── leaf 0 (4 clients via 2 sub-factories of 2 clients)
 │   ├── leaf 1 (4 clients via 2 sub-factories of 2 clients)
 │   ├── leaf 2 (4 clients via 2 sub-factories of 2 clients)
 │   └── leaf 3 (4 clients via 2 sub-factories of 2 clients)
 └── mid 1 (DW, arity 4) → 4 PS leaves
     └── ... (4 more leaves, 16 clients) [continues for total 8 leaves under each mid]
     Actually 16 leaves required for k²=4 × 16 = 64 clients.
     LSP CLI validator (factory_compute_ewt_for_shape) resolves the
     exact tree shape from --arity 2,4 + N_CLIENTS=64 + PS_SUBFACTORY_ARITY=2.
```
- Tree depth: 2 (static root + 1 DW mid + PS leaves)
- DW layers after PS subtraction + static depth: 1 → ewt = 1 × per_layer (~432 mainnet)
- Multi-input MuSig active when V4 chains advance any sub-factory (SF-A merge)

## Variants
- **V1 lifecycle** — coop close at scale
- **V2 force-close** — broadcasts root + all mids + 16 leaves + 32 sub-factory chain[0] TXs + 64 client sweeps
- **V3 chain-advance** — PS state advances across multiple leaves
- **V4 sub-factory advance** — chain-extend one sub-factory; rest stable
- **V5 breach + WT** — LSP cheats one sub-factory's stale state → WT broadcasts response TX
- **V6 mid-flight restart** — kill LSP mid-ceremony; restart → recover (gated on #245 SF-CRASH-INJECT)

## Wall-clock estimate
8-12 hours per variant. V2 is longest (32 sub-factory broadcasts + 64 sweeps × testnet4 confirms).

## Pool assignment
TBD — 3f variants run last, so will reuse pools after their earlier variant's
sweep-back completes. Per shape × variant matrix in README.

## RAM estimate
LSP ~250 MB + 64 clients × 35 MB + WT ~5 MB ≈ **2.5 GB**.
Single-shape; do NOT parallel with another N≥32 test.
