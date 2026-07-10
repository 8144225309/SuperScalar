# SuperScalar v0.2.0 — signet exhibition manifest (FINAL)

Every transaction below is on **real signet**, built by **v0.2.0**. View any txid at
`https://mempool.space/signet/tx/<txid>`. Full flat record: `docs/all-signet-txids.tsv`.

This is the on-chain evidence package for the Delving Bitcoin post. It is deliberately
**honest**: where a run hit a real-world limit (client attrition at N=127, a lost recovery
seed, signet congestion), that is recorded as a finding rather than hidden.

## The exhibits

### 1. Force-close + P2A anchors + CPFP (mass/unilateral exit)
Keyless P2A anchors present and spendable for fee-bumping a stuck exit.
| txid | role | height |
|---|---|---|
| `c7ad28fa…` | factory funding (250k) | 312264 |
| `ecac2791…` | anchored force-close (P2A `51024e73`) | 312266 |
| `4648fc2e…` | CPFP child spending a P2A anchor | 312267 |

### 2. B-legible — N=8 arity-2 PS-k=2 force-close cascade (5 P2A nodes)
Teaching-shaped legible exit; every force-close node carries a P2A anchor.
`2d054df3…` funding (312339) → 5 cascade nodes `2b10e8d1`/`1d96af3a`/`cba7274f`/`b2f95397`/`b2c97bbe` (312340–346).

### 3. 1-client exit — literal single client, anchors at 1 sat/vB
`978f62f6…` funding (312366) → `1fbc8f2f…` / `a28bb6f7…` force-close (P2A confirmed at ≥1 sat/vB, 312367/369).

### 4. Cheat → revealed-secret poison → redistribution
LSP broadcasts a stale sub-state (theft); client recourse assembles the revealed-secret poison and redistributes the sales-stock.
`e82035f2…` **LSP cheat** (312269) → `d2ae19cf…` **poison recourse**, 2-way redistribution 21,085 sats (312272).

### 5. On-chain ladder rollover (whole-tree epoch refresh)
`d766282…` old-epoch close (312379) → `09762ddd…` new-epoch funding (312385). Factory rotated in place to a new epoch.

### 6. 127-client flagship (design maximum) — real Lightning payments
LSP + 127 clients behind one P2TR UTXO, no free sats; real inbound payments routed from a vanilla (non-bLIP-56) CLN node through the bridge.
| txid | role | height |
|---|---|---|
| `143471b5…` | **127-client factory funding**, then **99 real routed payments** over a ~24 h soak | 312349 |

### 7. 128-of-128 MuSig aggregate spend of the factory funding (flagship close)
`0ca6b929…` (312535) — **one 162-byte transaction, a single Schnorr signature aggregating all 128 participant keys**, spending the design-max factory funding output. On-chain this is the shape of a cooperative close; it also recovered the 15M. MuSig2 at N=128 on real chain.

### 8. Clean cooperative close at legible N (via rotation)
`c116878…` (312543) — the N=8 factory reached DYING, the LSP ran rotation **Phase A PTLC key-turnover (8/8 clients cooperated)** then **Phase B cooperative close**. The clean coop-close ceremony, all clients cooperating.

### 9. Timelock (144-block CSV) — proven from confirmation heights
The B-legible cascade (base 312339 → maturity 312483) and the 1-client commitment `a28bb6f7` (base 312369, 2×149,560 sats CSV-locked, unspent through the window, unlocked h312510) demonstrate the 144-block delta on-chain — verifiable by anyone, no live sweep required.

## Honest findings (worth telling, not hiding)
- **127-client *cooperative* close failed.** The 24 h soak lost 30 of 127 client daemons to attrition (one modest VPS). A coop-close is N-of-N — needs every participant — so it correctly fell back to force-close. The **designed liveness behavior**, and a real data point on the cost of very large factories. The 15M was instead recovered via the 128-key aggregate spend (#7).
- **distribution-at-expiry is the *fallback*, not the default.** When clients cooperate, a dying factory **rotates / coop-closes** (the better outcome, #8). Pure expiry-distribution only fires when rotation can't happen (clients gone); it's the documented safety-net (`lsp_channels.c:7182` + regtest), and the LSP correctly prefers rotation.
- **N=8 B-legible recovery seed was overwritten** by a harness tag collision → **1,197,800 signet sats stranded** (unrecoverable; signet-replenishable). Lesson saved: unique per-run tags.
- **signet was congested** (mining minimal blocks) during teardown — low-fee txs confirmed slowly. Cooperative timing is *relative*, so this is harmless; fee/timing only matters on adversarial recourse races (mainnet-track #52/#56/#97).

## Teardown — all funds home
Bridge channel closed (`2c6e7442…`) + both node wallets swept (`bb2dcc94…`, `c1a28a9f…`). Every **factory-funding-root** residual recovered with the (patched, 128-participant) residual-sweep tool: A2 15M (`0ca6b929`), LadderTest 600k (`f7b936d8`), first-stalled-dist 2M (`1bb788d2`). All consolidated to `ss_sig_n127` (~2.39 BTC). The only un-recovered dust is the feewave channel-level leaf (`ecac2791:1`, 124,559 sats — the tool sweeps funding roots, not channel outputs) and the stranded N=8 seed (above) — both signet, immaterial. Recovery daemon restarted.
