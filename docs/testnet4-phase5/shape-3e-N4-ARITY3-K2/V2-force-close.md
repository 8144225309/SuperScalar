# Shape 3e V2 — k² sub-factory force-close

## What this proves
Force-close traversal of a k² sub-factory shape. Validates:
- LSP broadcasts factory root (leaf TX)
- LSP broadcasts both sub-factory chain[0] TXs
- Each client sweeps its own channel output cleanly from its sub-factory's outputs
- The sales-stock output in each sub-factory is correctly attributed to the LSP

## Configuration
- Command:    `WALLET=ss_pool_6 TAG=phase5_3e_V2 VARIANT=V2 bash docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh`
- Pool:       `ss_pool_6`
- Binary:     `/root/SuperScalar/build-release/`  commit=`<sha>`
- Started:    `<UTC>`   Completed: `<UTC>`   Duration: `<wall>`
- Outcome:    `<PASS | FAIL>`

## On-chain evidence
| Event | Block | TXID | Notes |
|---|---|---|---|
| Funding TX | | | |
| Factory root (force-close) | | | |
| Sub-factory 1 chain[0] broadcast | | | |
| Sub-factory 2 chain[0] broadcast | | | |
| Client 1 sweep | | | from sub-factory 1 |
| Client 2 sweep | | | from sub-factory 1 |
| Client 3 sweep | | | from sub-factory 2 |
| Client 4 sweep | | | from sub-factory 2 |
| LSP sales-stock sweep 1 | | | |
| LSP sales-stock sweep 2 | | | |

## Log assertions
- `FORCE CLOSE`
- Each sub-factory's chain[0] broadcast
- All 4 client sweeps confirmed

## Conservation
- Funding: `<X>`   Sweeps sum: `<Y>`   Fees: `<Z>`   `X == Y + Z` ✓|✗

## Sweep-back
- `ss_pool_6 → superscalar_test`  txid=`<hex>`  swept=`<sats>`
