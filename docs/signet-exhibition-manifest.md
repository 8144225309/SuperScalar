# SuperScalar signet exhibition — txid manifest

All transactions are on **real signet**, built by **v0.2.0** (`main` @ `3c75c39`), at
**0.1 sat/vB**. View any txid at `https://mempool.space/signet/tx/<txid>`.

Status: **B (force-close) and C (cheat→poison) complete + PASS.** A (127-client flagship)
is **running with real payments** — the earlier inbound "bug" turned out to be a harness
stdout-pollution bug (fixed; real inbound proven end-to-end in Stage 0d, `in ok` ×3). A is
soaking 24 h then cooperatively closes; its real-payment + close txids append here as they land.
A second legible force-close (N=8, arity-2, PS-k=2) is running in parallel for the measured-exit numbers.

## Exhibition B — force-close cascade + P2A anchors + CPFP (PASS)
Mass-exit / unilateral self-exit; keyless P2A anchors present + spendable for fee-bumping.

| txid | role | height | vsize |
|---|---|---|---|
| `c7ad28faecc4a754eb5e9f2bffd2430129d69b9c200c41a654ea56ebb1b09fac` | factory funding (250k) | 312264 | 154 |
| `bee9cbf5c44ef951b521832a703c1ed34432878d080e0848534130b7aa9fa84a` | anchored force-close (P2A `51024e73`) | 312265 | 124 |
| `ecac2791a686e821c5ecb60560cbe8c62ebaca4bb99174c9f9caebcc7d3a6ab7` | anchored force-close #2 (P2A) — PROOF 1 | 312266 | 167 |
| `4648fc2e7c122f227109eac285d804fa6d374832a7fabfb6e20359a7ae12d700` | CPFP child spending a P2A anchor — PROOF 2 | 312267 | 153 |

## Exhibition B-legible — N=8 arity-2 PS-k=2 mid-schedule force-close cascade (PASS)
The teaching-shaped legible exit: full cascade (kickoff → state → PS-leaf → close), **every force-close node carrying a P2A anchor**. Base force-close height **312339**; the CSV(144)-gated leaf/commitment sweep can only confirm at/after **height 312483** — the confirmation-height delta (144 blocks) is the on-chain proof of the timelock (sweep captured on a later pass).

| txid | role | height | vsize | P2A |
|---|---|---|---|---|
| `2d054df38cecbec834c5c1ac3640faa7f981f86bf75700262c0717c0724b1839` | factory funding | 312339 | 269 | — |
| `2b10e8d168c1f5af7963284116f832a2526f8b8415a9d4ca83a671ee9ff49961` | force-close cascade node | 312340 | 124 | P2A |
| `1d96af3add57e8507a92b56215eea004c29a4783545c40948fbaa92e1fcd77ed` | force-close cascade node | 312342 | 167 | P2A |
| `cba7274f26b6c88b08af84b9dfe71933da8e5d563404aa9520339e0992e68b05` | force-close cascade node | 312343 | 124 | P2A |
| `b2f953974b6f20438cd29e57d7f4da926f7ca3452034ad3e877afbd6d884dba7` | force-close cascade node | 312345 | 167 | P2A |
| `b2c97bbeb9f02bbecbed09c40ba6d4e65b8918b32e8d95baee3afb251ce342ed` | force-close cascade node | 312346 | 124 | P2A |

## 1-client exit — literal single-client force-close at 1 sat/vB, anchors ON (PASS)
A single client force-closing its own small factory, run at **1 sat/vB** so the commitment-level P2A anchor is enabled (`channel.c:933` gate: anchor when `fee_rate ≥ 1000 sat/kvB`). Backs the post's "a client forcing its way out of a small factory, measured." Base force-close height **312366**; CSV(144) sweep matures at **height 312510** (144-block delta = on-chain timelock proof; sweep captured on a later pass). **2 of 3 cascade txs carry P2A at 1 sat/vB** — confirms anchors re-enable at ≥1 sat/vB with no extra flag.

| txid | role | height | vsize | P2A |
|---|---|---|---|---|
| `978f62f662eb1c8180f7c617b4e7ef6a1d30eaf8fb3fb281cc21550a03fdd053` | factory funding | 312366 | 154 | — |
| `1fbc8f2f7b1fcf470a239c6c8f0f88ef6ab5794c226eb554e17b67b023be1ee4` | force-close cascade node | 312367 | 124 | P2A |
| `a28bb6f7de7949fe0aaacdbc561f09970592e4b35c3585c4f41d0f7f3b56a223` | force-close / commitment node | 312369 | 167 | P2A |

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
cooperative close both at 0.1 sat/vB.

**A2 — the 127-client flagship (design maximum), running now:** LSP + 127 clients, 15M sat, no free sats. Real inbound payments flow from the vanilla (non-bLIP56) node through the bridge into factory clients (8+ `in ok` in the soak so far; the moves are Lightning HTLCs that settle off-chain, so A2's on-chain footprint is the funding + the eventual coop close). Now in a 24 h soak with periodic real activity, then a cooperative close.

| txid | role | height | vsize |
|---|---|---|---|
| `143471b5d1ddc0eee3ea54d74ed17081f24d48f429bb826723c8b0897e55c0e6` | **127-client factory funding** (real payments; soaking → coop close pending) | 312349 | — |

Earlier smaller runs (preliminary lifecycle validation):

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
- **A bridge inbound (RESOLVED):** the earlier failure was a harness bug — `get_bolt11`
  printed log text to stdout, which was captured into the bolt11 string (`Invalid bolt11:
  Bad bech32 string`); fixed by routing logs to stderr. Real inbound is now proven
  end-to-end (Stage 0d: `in ok` ×3, plus real outbound + client-to-client + close). The
  127-client flagship runs on this path.
- **Recovery seeds** (strong keys): B `/tmp/ss_signet_seed_feewave.txt`, C
  `/tmp/ss_signet_seed_hashsub.txt`, A/0b/0c stage seeds. B's force-close outputs are
  CSV(144)-gated (~24 h) before sweep; C's poison per-client P2TR outputs are sweepable now.
