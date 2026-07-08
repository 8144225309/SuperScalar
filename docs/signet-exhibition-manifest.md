# SuperScalar signet exhibition — txid manifest

All transactions are on **real signet**, built by **v0.2.0** (`main` @ `3c75c39`), at
**0.1 sat/vB**. View any txid at `https://mempool.space/signet/tx/<txid>`.

Status: **B (force-close) and C (cheat→poison) complete + PASS.** A's realistic factory
lifecycle (LSP-side liquidity, no free sats) is on-chain; A's real-payment bridge layer
hit an inbound integration bug (documented below) and is deferred.

## Exhibition B — force-close cascade + P2A anchors + CPFP (PASS)
Mass-exit / unilateral self-exit; keyless P2A anchors present + spendable for fee-bumping.

| txid | role | height | vsize |
|---|---|---|---|
| `c7ad28faecc4a754eb5e9f2bffd2430129d69b9c200c41a654ea56ebb1b09fac` | factory funding (250k) | 312264 | 154 |
| `bee9cbf5c44ef951b521832a703c1ed34432878d080e0848534130b7aa9fa84a` | anchored force-close (P2A `51024e73`) | 312265 | 124 |
| `ecac2791a686e821c5ecb60560cbe8c62ebaca4bb99174c9f9caebcc7d3a6ab7` | anchored force-close #2 (P2A) — PROOF 1 | 312266 | 167 |
| `4648fc2e7c122f227109eac285d804fa6d374832a7fabfb6e20359a7ae12d700` | CPFP child spending a P2A anchor — PROOF 2 | 312267 | 153 |

## Exhibition C — cheat → revealed-secret poison → redistribution (PASS)
LSP broadcasts a stale sub-state (theft); client recourse assembles the revealed-secret
poison and redistributes the sales-stock to clients (punishment).

| txid | role | height | vsize |
|---|---|---|---|
| `ae4e99a0601fd9db4fc26ee02ae928d1793ee770fbadd5741f5de25391705b4a` | sub-factory funding (200k) | 312266 | 154 |
| `97ee1aa1e37f17dc3a315b63fab2aa78556d086cb0f624b0cfa6c932c8d09e49` | tree node 0 | 312267 | 124 |
| `577d7e32da5a6b82c83ebbead50fbef0294a9d74154780203473b609ba53eaf0` | tree node 1 | 312268 | 197 |
| `e82035f2b724c0c16225fada682af20684a91bc04aa62f59718a1a2e3c4a53a2` | **LSP cheat**: stale/superseded sub chain[N-1] | 312269 | 197 |
| `d2ae19cf39547b7eb69930ef8ad92e3d7f51e683b02cd8643a74d45640d4a4f0` | **poison recourse**: 2-way redistribution, 21085 sats (smallest 10542) | 312272 | 198 |

## Flagship A — realistic factory lifecycle (LSP-side liquidity, no free sats)
No `--lsp-balance-pct`, no `--demo`: LSP holds all capacity, clients start at 0. Funding +
cooperative close both at 0.1 sat/vB. (Real client payments require the bridge — see notes.)

| txid | role | height | vsize |
|---|---|---|---|
| `56c0b669305ba14e648be4355a9f8cca542cc46bc187c738376e184b16ae56fa` | factory funding (fresh-node run) | 312259 | 165 |
| `88d40da71587f60fc4393ebd239196f08384cdfcf56119885f3e005595290f06` | cooperative close | 312261 | 111 |
| `2cc23def19a5cfcba5311a1709edc2ac84d6bdffbf2afa5342419d470fa9d512` | factory funding (bridge-debug run 0c) | 312321 | 154 |
| `9b12f83aa44512bd5bdc0a16bd4bcbcc241a3ba1089bfad67c6d438ef68c1622` | cooperative close (run 0c) | mempool | 111 |

## Bridge infrastructure (fresh non-bLIP56 CLN nodes for A's real-payment layer)

| txid | role | height | vsize |
|---|---|---|---|
| `ab54835768a4a6aac3b4a748d91de39b0ead425ec13472b21ea0436a5e7bcddc` | vanilla node funding (8M) `ss_sig_n127`→`cln-exhib-v` | 312256 | 130 |
| `02a0ffda2de68becc2dfa6ae664d438d4ea41c6f63f95c9fee3b7d91c163fd93` | 7M sat announced channel `cln-exhib-v`→`cln-exhib-p` | 312257 | 165 |

## Validation (old-infra Stage 0, before the fresh bridge nodes)

| txid | role | height | vsize |
|---|---|---|---|
| `69a85e4fae23823078d879a0241fe662059791cd75d9c6a549c2ff555f776252` | factory funding | 312254 | 165 |
| `877800c08f3ddf51a30cac22b99d1072adbbb2e18379ceeadae41253a9288f8c` | cooperative close | 312255 | 111 |

## Notes
- **A bridge inbound (deferred):** the vanilla→plugin channel + routing are proven (plain
  and cltv=80 invoices pay `complete`); the SS invoice fails in the
  `cln_plugin.py htlc_accepted → bridge → LSP → client` forward. Factory lifecycle above
  is A's on-chain footprint; the real-payment layer needs a dedicated full-stack debug.
- **Recovery seeds** (strong keys): B `/tmp/ss_signet_seed_feewave.txt`, C
  `/tmp/ss_signet_seed_hashsub.txt`, A/0b/0c stage seeds. B's force-close outputs are
  CSV(144)-gated (~24 h) before sweep; C's poison per-client P2TR outputs are sweepable now.
