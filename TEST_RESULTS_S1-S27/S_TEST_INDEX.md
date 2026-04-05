# SuperScalar Exhibition Tests (S1-S29)

Complete on-chain exhibition test suite. Each S-test produces unique
on-chain artifacts demonstrating a distinct SuperScalar capability.

## Active Tests

| S# | Name | Flag | Unique On-Chain Structure |
|----|------|------|--------------------------|
| S1 | Cooperative close | `--demo` | Key-path spend of factory UTXO (single TX) |
| S2 | Force close | `--force-close` | Full DW tree broadcast (all 6 nodes, script-path spends with nSequence) |
| S3 | DW advance | `--test-dw-advance` | Re-signed tree with decreased nSequence values on-chain |
| S4 | DW exhibition | `--test-dw-exhibition` | 3-phase: nSequence countdown to 0 + PTLC-assisted close + cross-factory contrast |
| S5 | Per-leaf advance | `--test-leaf-advance` | Left leaf nSequence decreased, right leaf unchanged (per-leaf independence) |
| S6 | L-stock burn | `--test-burn` | Tree with revoked L-stock via shachain |
| S7 | Breach + penalty | `--breach-test` | Revoked commitment TX + watchtower penalty TX |
| S8 | CLTV timeout recovery | `--test-expiry` | Multi-level timeout script-path spends (kickoff → state → leaf) |
| S9 | Distribution TX | `--test-distrib` | nLockTime-guarded distribution TX after CLTV expiry |
| S10 | BOLT11 bridge | `--test-bridge` | CLN bridge HTLC fulfillment via factory channel |
| S11 | Dual factory | `--test-dual-factory` | Two independent factory trees broadcast (2 funding UTXOs, 12 nodes) |
| S12 | Factory rotation | `--test-rotation` | PTLC key turnover → cooperative close F0 → new factory F1 |
| S13 | HTLC force-close | `--test-htlc-force-close` | Force-close with pending HTLC + CSV delay + HTLC timeout TX sweep |
| S14 | Real LN payment inbound | Manual (CLN-B → CLN-A → bridge → factory) | External BOLT11 payment settled through factory channel |
| S15 | Splice TX | `--test-splice` | Splice-out resizes factory UTXO while channels live |
| ~~S16~~ | ~~Epoch reset~~ | ~~removed~~ | ~~Removed 2026-03-25: DW security vulnerability~~ |
| S17 | JIT channel lifecycle | `--test-jit` | Standalone 2-of-2 JIT channel funding TX on-chain |
| S18 | Leaf realloc | `--test-realloc` | Rebalanced leaf outputs between two clients sharing a leaf |
| S19 | LSPS2 JIT buy | `--test-lsps2` | Standards-compliant lsps2.buy flow triggering JIT channel |
| S20 | 3-factory ladder | `--test-dual-factory` variant | Three concurrent factory trees (ACTIVE/DYING/EXPIRED lifecycle) |
| S21 | BOLT12 offer | `--test-bolt12` | Offer encode/decode + invoice_request signing |
| S22 | Buy liquidity | `--test-buy-liquidity` | Inbound capacity purchase from L-stock reserve |
| S23 | BIP39 mnemonic | `--test-bip39` | Factory lifecycle with HD-derived LSP key |
| S24 | Large factory | `--test-large-factory` | 8+ client factory with deeper DW tree |
| S25 | Outbound payment | Manual (factory → bridge → CLN) | Factory client pays external Lightning invoice |
| S26 | Standalone watchtower | Separate binary | Independent watchtower monitors and detects breaches |
| **S27** | **Partial rotation** | `--test-partial-rotation` | **3/4 cooperative factory (smaller MuSig2 set) + old factory distribution TX** |
| **S28** | **Multi-HTLC force-close** | `--test-multi-htlc-force-close` | **4 concurrent HTLC timeout TXs with staggered CSV/CLTV on leaf outputs** |
| **S29** | **Mixed arity factory** | `--demo --arity 1,1,2` | **Variable-depth tree: different branching at each level** |

## New Tests Detail

### S27 — Partial Rotation (1 client offline)
**Status:** IMPLEMENTED, passed regtest 2026-04-05

Demonstrates the most common real-world failure: client's phone dies.
- Phase A: PTLC key turnover for 3 of 4 clients (skip offline)
- Phase B: Disconnect offline client, build distribution TX for old factory
- Phase C: Create new factory with 3 cooperative clients
- Phase E: Mine to old factory CLTV, broadcast distribution TX

On-chain artifacts:
1. New factory funding TX (4-of-4 MuSig2: LSP + 3 clients)
2. Old factory distribution TX (5-of-5 nLockTime spend)

### S28 — Multi-HTLC Force-Close
**Status:** TO BUILD

Force-close with HTLCs pending on all 4 channels simultaneously.
S13 only tests 1 HTLC; production will have concurrent HTLCs.

On-chain artifacts:
1. Factory tree broadcast (6 nodes)
2. 4 HTLC timeout TXs (one per channel, each with its own CSV + CLTV)

### S29 — Mixed Arity Factory
**Status:** TO BUILD (flag exists: `--arity 1,1,2`)

Factory with variable arity at different tree levels. Produces
a genuinely different tree shape — some levels branch binary,
others are single-child. Tests the `factory_set_level_arity()` path.

On-chain artifacts:
1. Asymmetric factory tree (different node counts per subtree)
2. Cooperative close of mixed-arity tree

## Removed Tests

| S# | Name | Reason |
|----|------|--------|
| S16 | Epoch reset | Removed 2026-03-25 — DW architectural vulnerability |
