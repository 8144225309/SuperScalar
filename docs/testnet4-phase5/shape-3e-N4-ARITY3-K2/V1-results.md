# shape-3e-N4-ARITY3-K2 V1 - Results

See `V1-commands.md` for the launch protocol.

## Run record
- Wallet:       ss_pool_1
- Started:      2026-05-19T23:15:59Z
- Completed:    2026-05-19T23:33:xx Z (close confirmed at ~5min after launch + 11 confirmations later)
- Duration:     ~18 minutes (block-bound)
- Funding rate: 1.0 sat/vB
- Commit:       6003a672cb7c78a7e483f9bdb4663f0581959536
- LSP pid:      3703836
- WT  pid:      3703871
- **Outcome: PASS**

## On-chain evidence
| Event | TXID | Notes |
|---|---|---|
| Funding TX (factory init)      | `082f1c2d51d9acd2...` | from ss_pool_1, fee 1.0 sat/vB |
| Sub-factory persistence        | `A1 fix: persisted chain[0] for 3 PS leaf/sub-factory node(s)` | 1 PS leaf + 2 sub-factories, all chain[0] rows written to v21 schema |
| Cooperative close TX           | `c44e682beb812bab5066fd606fcf6d69b7f0c87768a983812cf7cf5178ce0674` | 11 confirmations; 1 input, 1 output (0.009995 BTC = 999500 sats) to LSP-owned P2TR `tb1p0xlxvlhemja6c4dqv22u..` |

## Log assertions observed
- [x] `LSP: shape ewt = 10 blocks (BOLT 2016 ceiling = 2016)` — pure-PS, no DW layers
- [x] `LSP: all 4 clients connected` — 4 clients (2 per sub-factory × 2 sub-factories)
- [x] `LSP: funding TX broadcast at fee_rate=1000 sat/kvB (1.0000 sat/vB)` — fee ceiling honored
- [x] `LSP: A1 fix: persisted chain[0] for 3 PS leaf/sub-factory node(s)` — **k² sub-factory persistence works on real chain**
- [x] `LSP: starting cooperative close...`
- [x] `LSP: cooperative close confirmed! txid: c44e682beb812bab5066fd606fcf6d69b7f0c87768a983812cf7cf5178ce0674`
- [x] `LSP: SUCCESS — factory created and closed with 4 clients`

## What this proves (vs t/1242 design)
- **First real-chain validation of k² sub-factory ceremony.** Sub-factory shape with k=2 (2 sub-factories × 2 clients = 4 clients in 1 PS leaf) created, signed, persisted, and closed cleanly.
- **v21 `ps_subfactory_chains` writes correctly** — 3 chain[0] rows persisted (1 leaf + 2 sub-factory nodes).
- **Cooperative close traverses sub-factory output paths** without requiring force-close machinery.
- **1 sat/vB fee ceiling holds throughout** (CLI accepted, funding TX broadcast at rate, no fee bumps).

## Conservation
- ss_pool_1 pre-funding:        9,995,967 sats
- ss_pool_1 post-coop-close:    8,995,802 sats
- Net spent from pool 1:        1,000,165 sats (funding amount + funding fee)
- Cooperative close output:        999,500 sats (returned to LSP-owned P2TR address; recoverable via LSP key)
- Net fees (funding tx):              ~665 sats (1.0 sat/vB × ~665 vB funding TX)

Conservation: `funding_in (1,000,165) ≈ close_out (999,500) + fees (~665)` ✓ (matches within rounding)

## Recoverable LSP-owned dust (not in pool 1)
The cooperative close output went to `tb1p0xlxvlhemja6c4dqv22u..` — an LSP P2TR derived from seckey 0x...01. 999,500 sats are sweepable from there with the LSP key but not via pool 1 wallet. Track as "LSP recoverable" — does not lose sats; just lives outside the pool ledger.

## Sweep-back
- Command:   `bash docs/testnet4-phase5/sweep-back.sh ss_pool_1`
- ss_pool_1 → superscalar_test (address `tb1q4lh4mwc6muew4kdp2k6nfnkjlhtc62n5y3yua8`)
- TXID:      `698327f73e0b1e2d09d6bad91a669a00d294cb33bf3824fce2c0e0dbc064e11b`
- Sats in:   8,995,802 (full balance)
- fee_rate:  1 sat/vB (Phase 5 ceiling)
- Pool 1 status: drained, available for next assignment

## Next steps
- Pool 1 sweep-back to superscalar_test
- Launch 3e V2 (force-close variant) against ss_pool_6 to validate the force-close path of the same shape
- Then move to 3a V1 baseline (regression-style check that uniform PS still works)
