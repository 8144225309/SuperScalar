# Shape 3e V4 — Sub-factory chain advance (buy from sales-stock)

## What this proves
**The headline t/1242 feature.** `lsp_subfactory_chain_advance` drives the
MSG_SUBFACTORY_* ceremony to chain a new sub-factory state where one client's
channel grows by `delta_sats` taken from sales-stock. Validates:
- MSG_SUBFACTORY_PROPOSE → NONCE → ALL_NONCES → PSIG → DONE wire round-trip
  with only the sub-factory's k+1 signers (LSP + 2 clients)
- Multi-input MuSig path (SF-A merge) when chain_len ≥ 1
- v21 `ps_subfactory_chains` row inserted for chain[1]
- Watchtower upgrades its registered stale state from chain[0] → chain[1]
- Non-cohort clients (clients 3,4 in the OTHER sub-factory) are NOT involved

## Configuration
- Command:    `WALLET=ss_pool_8 TAG=phase5_3e_V4 VARIANT=V4 bash docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh`
- Pool:       `ss_pool_8`
- Outcome:    `<PASS | FAIL>`

## On-chain evidence
| Event | Block | TXID | Notes |
|---|---|---|---|
| Funding TX | | | |
| Factory root (leaf TX) | | | |
| Sub-factory 1 chain[0] | | | initial state |
| Sub-factory 1 chain[1] | | | post-advance: ch1 grew by delta, sales-stock shrunk |
| Sub-factory 2 chain[0] | | | unchanged across the advance |
| Cooperative close | | | |

## Log assertions
- `MSG_SUBFACTORY_PROPOSE sent to 2 clients` (only sub-factory 1's cohort)
- `MSG_SUBFACTORY_DONE: chain extended sub=0 to chain_len=2`
- `persist: ps_subfactory_chain entry leaf=0 sub=0 chain_len=2`
- `watchtower: re-registered subfactory node 0 chain[1]`
- Clients 3 and 4 logs: NO `MSG_SUBFACTORY_*` traffic (non-cohort)

## Conservation
After advance: `chain[0].ch1_amount + chain[0].sales_stock == chain[1].ch1_amount + chain[1].sales_stock` (modulo per-advance fee).

`X (funding) == Y (sweeps post-advance) + Z (fees)` ✓|✗

## Sweep-back
- `ss_pool_8 → superscalar_test`  txid=`<hex>`  swept=`<sats>`
