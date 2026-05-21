# Shape 3e — N=4 ARITY=3 PS_SUBFACTORY_ARITY=2

The **k² PS sub-factory canonical** from t/1242 post #16. Smallest shape that
exercises the dedicated sub-factory ceremony, the v21 `ps_subfactory_chains`
persistence schema, and the watchtower's sub-factory registration path.

## Why this matters
This is the first real-chain validation of the **k² sub-factory ceremony**
(MSG_SUBFACTORY_* wire opcodes, not Tier B reuse). Until this shape PASSES
on testnet4, the sub-factory feature is regtest-only.

## Topology
```
1 PS leaf (4 clients = k²)
├── sub-factory 1 (LSP + clients 0,1)  chain[0]: ch0 + ch1 + sales-stock
└── sub-factory 2 (LSP + clients 2,3)  chain[0]: ch2 + ch3 + sales-stock
```
- N=4 clients total
- Leaf arity 3 (PS)
- PS_SUBFACTORY_ARITY=2 → each leaf hosts k=2 sub-factories of k=2 clients each
- Tree depth: 1 (just the root + 1 leaf)
- ewt: pure-PS, no DW layers → 0 CSV blocks for the leaf
- Funding: 1M sats per client × 4 = 4M sats per factory

## Variants
- **V1 lifecycle** — open k² shape → coop close → sweep. Proves k² ceremony works for initial sign.
- **V2 force-close** — open → force-close → leaf TX + 2 sub-factory chain[0] TX broadcast → per-client sweeps. Proves force-close traversal of sub-factory output paths.
- **V3 chain-advance** — open → repeated PS leaf advances → close. Proves PS TX chaining at the leaf level (orthogonal to sub-factory).
- **V4 sub-factory advance** — open → `lsp_subfactory_chain_advance` for one client (buy from sales-stock) → close. Proves the `MSG_SUBFACTORY_*` ceremony end-to-end, chain[1] persistence, and watchtower registration of chain[0] as stale.

## Expected log markers
- `shape ewt = N blocks (BOLT 2016 ceiling = 2016)` — startup CLI validator accepted shape
- `factory: k²=4 PS sub-factory shape, k=2, 2 sub-factories per leaf`
- `sub-factory N built: 3 outputs (2 channels + sales-stock), 3 signers`
- `MSG_SUBFACTORY_PROPOSE → MSG_SUBFACTORY_NONCE → ALL_NONCES → PSIG → DONE` round-trip
- `persist: ps_subfactory_chain entry leaf=0 sub=N chain_len=1`
- `watchtower: registered subfactory node N chain[0]`

## Pool assignment
- V1 → ss_pool_1
- V2 → ss_pool_6
- V3 → ss_pool_7
- V4 → ss_pool_8

## Wall-clock estimate
3-5 hours per variant on testnet4 (block-bound for funding confirm + tree confirm).
