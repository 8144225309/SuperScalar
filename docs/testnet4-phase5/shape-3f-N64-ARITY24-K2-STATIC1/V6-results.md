# shape-3f-N64-ARITY24-K2-STATIC1 V6 - Results

See `V6-commands.md` for the launch protocol. Filled in as the run progresses.

## Run record
- Wallet:    ss_pool_7
- Started:   `<UTC>`
- Completed: `<UTC>`
- Duration:  `<wall>`
- Funding rate: 1.0 sat/vB
- **Outcome: pending**

## On-chain evidence
| Event | Block | TXID | Notes |
|---|---|---|---|
| Funding TX                     | TBD | TBD | from ss_pool_7 |
| Factory root / leaf broadcasts | TBD | TBD | |
| Sub-factory chain[N] TXs       | TBD | TBD | (k2 shapes only) |
| Force-close commits            | TBD | TBD | (V2/V5/V6 only) |
| Per-client sweeps              | TBD | TBD | |
| Sales-stock sweeps             | TBD | TBD | (k2 shapes only) |
| WT response TX                 | TBD | TBD | (V5 only) |

## Log assertions observed
- [ ] `persist_scan_in_flight_ceremonies`
- [ ] `RESUME from PENDING_SIGS`

## Conservation
- Funding in:   TBD sats
- Sweeps out:   TBD sats
- Fees total:   TBD sats (all at <=1 sat/vB)
- Conservation: `X == Y + Z`  [ ]

## Sweep-back
- ss_pool_7 -> superscalar_test
- TXID:    TBD
- Block:   TBD
- Sats:    TBD in / TBD fee at 1 sat/vB

## Failure / observation notes
(empty)
