# Shape 3e V3 — PS leaf chain-advance

## What this proves
PS TX chaining at the leaf level under the k² sub-factory shape. Validates:
- N PS state advances on the parent leaf
- Each advance is a new TX spending the prior chain TX's channel output
- `client_ps_signed_inputs` double-spend defense fires correctly
- Sub-factory state remains stable across leaf advances

## Configuration
- Command:    `WALLET=ss_pool_7 TAG=phase5_3e_V3 VARIANT=V3 bash docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh`
- Pool:       `ss_pool_7`
- Outcome:    `<PASS | FAIL>`

## On-chain evidence
| Event | Block | TXID |
|---|---|---|
| Funding TX | | |
| Leaf TX chain[0] (PS root) | | |
| Leaf TX chain[1..N] | | (one row per advance) |
| Cooperative close | | |

## Log assertions
- `ps_chain_len=N` (after N advances)
- `persist_save_ps_signed_input` recorded per advance
- No `client_ps_signed_inputs.*conflict` (double-spend defense did not refuse)
- Sub-factory chain entries unchanged across leaf advances

## Conservation
`X == Y + Z` ✓|✗

## Sweep-back
- `ss_pool_7 → superscalar_test`  txid=`<hex>`  swept=`<sats>`
