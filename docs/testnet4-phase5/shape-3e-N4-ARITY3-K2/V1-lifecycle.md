# Shape 3e V1 — k² sub-factory lifecycle (cooperative close)

## What this proves
First real-chain execution of the k² PS sub-factory shape from t/1242. Validates:
- Factory creation builds 1 leaf with k=2 sub-factories, each with k+1=3 signers and k+1=3 outputs
- Initial MuSig signs each sub-factory node's outputs alongside the parent leaf
- v21 `ps_subfactory_chains` chain[0] row is written for each sub-factory
- Watchtower registers chain[0] of each sub-factory as the stale state to defend
- Cooperative close path traverses sub-factory outputs cleanly

## Configuration
- Command:    `WALLET=ss_pool_1 TAG=phase5_3e_V1 VARIANT=V1 bash docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh`
- Pool:       `ss_pool_1` (10000000 sats funded; see ledger)
- Binary:     `/root/SuperScalar/build-release/`  commit=`<sha>`  built=`<date>`
- Started:    `<UTC>`
- Completed:  `<UTC>`
- Duration:   `<wall>`
- Outcome:    `<PASS | FAIL — reason>`

## On-chain evidence
| Event | Block | TXID | Notes |
|---|---|---|---|
| Funding TX (factory init) | | | from ss_pool_1 |
| Factory root broadcast (leaf TX) | | | k²=4 shape, 3 outputs (2 sub-factory entries + L-stock) |
| Sub-factory 1 chain[0] | | | LSP + clients 1,2; 3 outputs (ch1 + ch2 + sales-stock) |
| Sub-factory 2 chain[0] | | | LSP + clients 3,4; 3 outputs (ch3 + ch4 + sales-stock) |
| Cooperative close TX | | | sweeps all 4 client channels |

## Log assertions
- `shape ewt = 0 blocks (BOLT 2016 ceiling = 2016)` — pure-PS, no DW layers
- `k²=4 PS sub-factory shape, k=2`
- `sub-factory 0 built: 3 outputs, 3 signers`
- `sub-factory 1 built: 3 outputs, 3 signers`
- `persist: ps_subfactory_chain entry leaf=0 sub=0 chain_len=1`
- `persist: ps_subfactory_chain entry leaf=0 sub=1 chain_len=1`
- `watchtower: registered subfactory node 0`
- `watchtower: registered subfactory node 1`

## Conservation
- Funding into factory: `<X>` sats
- Sweeps sum (4 clients × close output): `<Y>` sats
- Total fees (funding + leaf TX + 2 sub-factory chain[0] + close): `<Z>` sats
- Conservation:  `X == Y + Z` ✓ | ✗

## Sweep-back
- `ss_pool_1 → superscalar_test`  txid=`<hex>`  block=`<N>`  swept=`<sats>`

## Failure notes (if FAIL)
- <root cause analysis>
- <next-step task created>
