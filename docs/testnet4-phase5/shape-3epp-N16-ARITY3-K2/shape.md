# Shape 3e+ — N=16 ARITY=3 PS_SUBFACTORY_ARITY=2

k² sub-factory ceremony at moderate scale. Same sub-factory primitives as 3e
but stresses the ceremony with 4 leaves × k=2 sub-factories per leaf × 2 clients
per sub-factory = 16 clients in 4 leaves with 8 total sub-factories.

## Why this matters
Catches scale-bugs that hide at N=4 (3e) but show before N=64 (3f). Specifically:
- 8 concurrent sub-factory ceremonies during initial sign
- v21 `ps_subfactory_chains` writes from 8 distinct nodes
- Watchtower registers 8 separate stale-state targets

## Topology
```
root → arity-3 fan-out (4 PS leaves):
  ├── leaf 0  (4 clients via 2 sub-factories of 2 clients each)
  ├── leaf 1  (4 clients via 2 sub-factories of 2 clients each)
  ├── leaf 2  (4 clients via 2 sub-factories of 2 clients each)
  └── leaf 3  (4 clients via 2 sub-factories of 2 clients each)
```
Total: 4 leaves × 4 clients = 16. Each leaf has 2 sub-factories (k=2). 8 sub-factories total.

## Variants
- **V2 force-close** — broadcasts root + 4 leaves + 8 sub-factory chain[0] TXs + 16 client sweeps
- **V3 chain-advance** — N PS state advances per leaf (PS TX chaining at leaf level)
- **V4 sub-factory advance** — `lsp_subfactory_chain_advance` on one sub-factory; the other 7 remain stable

## Pool assignment
- V2 → ss_pool_9
- V3 → ss_pool_10
- V4 → ss_pool_1 (post-sweep-back, reuses after 3e V1)
