# Trustless-model completion plan

Living tracker for closing out every remaining gap in SuperScalar's trustless
self-custody model. Created 2026-06-22 after the #53 sub-factory hashlock poison
landed + was proven on regtest + real signet. Branch: `trustless-completion`.

## Verdict (2026-06-22)

The **breach-recourse** trust model — a client / standalone watchtower recovers
funds WITHOUT trusting the LSP — is **PROVEN for the main paths** (factory,
sub-factory, channel-commitment, PTLC) on regtest AND real signet. This session
closed the last KNOWN *theft* vector (co-signed-poison, "Scenario B") at the
sub-factory level (#53, PR #390). **There is no known "the LSP can steal" gap.**

The frontier has moved from *theft prevention* to: recourse **winning the
fee-race**, **operational** self-custody, **coverage** completeness, **harness
rigor**, and the **external audit**.

## The 5-layer model

| Layer | Question | Status |
|---|---|---|
| 1 Detect | Standalone WT sees the breach? | PROVEN (regtest + signet) |
| 2 Respond | Builds + broadcasts recourse? | PROVEN — factory/sub/commitment/PTLC penalties + #53 hashlock poison fire, confirm, redistribute |
| 3 **Win** | Recourse confirms BEFORE the attacker's tx, under fee pressure? | **PROVEN for single-breach** (P2a WT-CPFP + P2b client-CPFP poison); mass-exit herd still open (P3) |
| 4 Afford | Client with all funds in-factory can pay the exit/bump fee? | OPEN (P7 / #63) |
| 5 Operate | Who runs the WT; secret backup; migration? | OPEN (P7 / #62,#64) |

## Execution plan (one piece at a time, each committed + validated)

Order chosen for value + de-risking: a fast warm-up that closes tonight's loop,
then the Layer-3 frontier, then coverage, rigor, liveness, ops, audit-prep.

- **P1 — Adversarial agg-sig drill (validate this session's D1/D2 hardening).**
  DoD: a regtest test where the LSP ships a CORRUPTED poison agg-sig in
  SUBFACTORY_DONE (env-gated cheat); the client's verify-before-trust REJECTS it
  and does NOT persist a worthless reveal row; assert the loud abort. "Prove the
  negative" on the N-party agg-sig verify. STATUS: **DONE + PROVEN** (regtest green:
  LSP shipped corrupt sig, 2 clients D2-rejected, 0 worthless rows).
- **P2 — Layer 3: recourse WINS the fee-race (#60).** DoD: a regtest harness where
  after a breach the recourse must confirm despite a competing low-fee mempool /
  the LSP's L&CSV fallback; prove it confirms (fee-bumping via #52 if needed).
  Recourse that fires but loses the race isn't trustless. STATUS: **DONE + PROVEN**
  (both halves green on regtest):
  - P2a (WT-driven): `SS_HIFEE_BUMP=1` commitment breach — the standalone WT's
    deadline CPFP escalator bumped a deprioritised penalty (feerates 5501->11399)
    to CONFIRM at 69 blocks. Covers factory/sub/commitment penalties.
  - P2b (client-driven #53 poison): `SS_POISON_CPFP_RACE=1` in the sub-factory e2e.
    The poison is pre-signed/fixed-fee (agg-sig binds outputs => NOT RBF-able); its
    only bump is CPFP on a client's own `tr(client_key)` poison output. Deprioritise
    -3000 (control: bare poison STUCK), client CPFP child (12000-sat fee) -> poison
    CONFIRMED in 1 block, << the 144-block Leaf-L CSV head-start (Leaf-L is a genuine
    relative timelock, factory.c:240/268, so it can't even be broadcast first). The
    poison provably beats the LSP's CSV fallback.
- **P3 — Mass-exit thundering herd (#56).** DoD: N clients exit at the shared
  factory CLTV simultaneously; prove no client is stranded by the fee-race, or
  document + implement the mitigation. STATUS: **in progress** (baseline GREEN +
  finding + fix underway).
  - Baseline GREEN: `test_regtest_mass_exit.sh` N=4 on this branch -- LSP vanishes,
    all 4 clients self-exit (topological root->leaf over ~17 CSV-maturation passes),
    100%+ conservation. The #313 mechanism works.
  - Block space is NOT the herd bottleneck: the whole unwind is ~127 commitments +
    ~127 sweeps + ~tree-nodes ~= 57 kvB even at N=127 -> fits in 1-2 blocks (shared
    tree dedups). The real risk is GENERAL fee pressure vs the pre-signed fixed fee.
  - **FINDING (real):** the mass-exit cascade has NO unilateral CPFP path for a
    force-closing client. Tree txs are nVersion=2 + no anchor (factory.c:2224);
    the commitment is v3/TRUC but had NO anchor (channel.c, to_local CSV-locked);
    the CPFP-able distribution-TX backstop (P2A anchor, factory.c:4083) is NOT
    persisted in the daemon `--demo` flow (empirically distribution_txs=0). Mean-
    while the LSP's cltv_timeout claim is live-signed (freely bumpable). So a client
    exiting near cltv_timeout under sustained high fees could lose the race.
  - **DECISION (user, 2026-06-23): add commitment + tree anchors** (the gold-standard
    per-client unilateral CPFP).
  - **Increment 1 = commitment P2A anchor — CODED + VALIDATED** (commit c755d13). Made
    it a negotiated per-channel feature `use_cpfp_anchor` (option_anchors style): keyless
    P2A appended last, 240 sats moved out of to_remote (fee + to_local + the count-bounded
    WT parsers unchanged), deterministic across co-signers; default OFF (legacy/unit
    channels unchanged), set ON at all 4 production channel_init sites (client/lsp/jit/
    db-restore). Validation ALL GREEN: **unit 1511/1511** (incl. a new differential test
    proving the anchor is gated, P2A-shaped, to_remote-funded); **breach/penalty regtest**
    -- a standalone WT confirms a penalty (11843 sats swept) against an ANCHORED revoked
    commitment (anchor transparent to the penalty path); **mass-exit N=4** -- all clients
    self-exit, conservation now EXACTLY 100.0% (46992/46992; anchor deducts from to_remote
    so to_local == channel balance precisely). Increment 1 is production-safe + DONE.
    Remaining for full rigor: a CPFP-the-commitment e2e proof (deprioritise a force-closed
    commitment, bump via its P2A anchor + a funded input, confirm) -- analogous to P2b.
  - **Increment 2 = tree anchors** -- branch `trustless-tree-anchors` (off trustless-completion).
    INVESTIGATED; deferred to a careful dedicated effort because it is a major,
    safety-critical change to core factory accounting:
    * Mechanism (per node): each node builder does `output_total = input_amount -
      f->fee_per_tx` then splits among children (factory.c:449 leaf, :1062/:1123 internal,
      :1213 sub-factory). A tree anchor = reserve 240 MORE from output_total (carved from
      the subtree, NOT the fee, since fee_per_tx may be < 240) + append a P2A output last.
      Gate on a factory-level flag (deterministic across LSP+clients), default off for
      unit/legacy.
    * COUPLING RISK (why it's hard): the LEAF node's outputs (setup_leaf_outputs) ARE the
      channel funding amounts -- carving 240 there changes the channel fundings, which the
      channel COMMITMENTS are signed against (ch->funding_amount must track it). And the
      v3 commitment can't CPFP-pull a v2 leaf-node ancestor (TRUC all-v3-ancestors rule),
      so the leaf-node tx genuinely needs its OWN anchor. So increment 2 ripples through:
      4+ node builders, the channel-funding coupling, conservation (must add Sigma anchors),
      the recovery/WT tree parsers, the factory unit tests, and the full lifecycle.
    * GUARDRAIL: the mass-exit conservation assert (must stay 100%) catches leaf-level
      mis-allocation; re-validate factory unit + breach + mass-exit + lifecycle after.
    * Recommended order: (1) factory-level `use_tree_anchor` flag + internal-node anchors
      (root/intermediate, low coupling) first, validate; (2) then the leaf-node anchor with
      the channel-funding coupling, validate conservation; (3) consider v3 for tree txs
      (anti-pinning) as a follow-up. Do NOT rush -- a conservation bug mis-allocates funds.
  - **2026-06-24 — IMPLEMENTED (commits e4303b8 leaf + 09fb5c4 internal), VALIDATION PENDING.**
    Coupling fear was UNFOUNDED: lsp_channels.c:221 reads funding_amount = the leaf node's
    channel output, so per-channel conservation (lsp_channels.c:7831) auto-tracks any node-
    output change. Uniform carve: every builder does `output_total -= FACTORY_ANCHOR_COST(f)`
    + `factory_append_tree_anchor()` (P2A last), so output sum = input-fee is unchanged.
    Done: factory.h flag; the helper+macro; all 3 leaf builders (setup_leaf/single/ps); all 3
    internal builders (static kickoff, regular kickoff, state-with-children); the 4 production
    setters (lsp.c, client.c x2, persist.c) -- default OFF for unit/legacy, ON in production
    (deterministic across LSP+clients). FACTORY_MAX_OUTPUTS=16 has headroom; append helper
    skips if full. NOT YET anchored: PS-subfactory builders (setup_ps_leaf_with_subfactories,
    the k^2 shape) -- follow-up (basic factory / mass-exit / signet don't use them).
    REGTEST VALIDATION (2026-06-25): **ALL GREEN.** Build rc=0 (stage-2 compiles); **unit
    1511/1511** (one fallout fixed: test_persist_factory_round_trip must build with
    use_tree_anchor=1 since persist_load_factory rebuilds anchored on the client-reconnect
    path -- commit e67948f); **mass-exit N=4** all clients self-exit with the fully-anchored
    tree, conservation 104.3% (the fund-safety guardrail -- the uniform carve preserves
    conservation as predicted). So the tree anchors are PROVEN correct on regtest; combined
    with PR #391's commitment anchor, every force-close cascade tx is now CPFP-able.
    SIGNET (2026-06-25): **PASSED end-to-end** (tools/test_signet_tree_anchor_feewave.sh,
    commit 75a4282). Built a small anchored factory on REAL signet (strong keys, 250k sats,
    fee 110), force-closed; **PROOF 1**: 2 on-chain force-close txs (68f0a4f6, ffab493f)
    each carry the keyless P2A output (51024e73), conf=1 -- anchors PRESENT + relay-standard
    on a real public chain; **PROOF 2**: CPFP-spent a P2A anchor (child 27b7cbb7 accepted by
    the signet network) -- anchor SPENDABLE for fee-bumping. Signet has no congestion to
    contend (winning a contested race is the regtest P2a/P2b/mass-exit proof). NOTE: must
    pause ss-recover-signet during signet runs (its per-block ss_recover_scav rescan holds
    cs_main and starves ALL bitcoind RPC incl. getrpcinfo -- the runner stops it, waits for
    the in-flight rescan to drain, then restarts it after). RECOVERY: strong-key seed at
    /tmp/ss_signet_seed_feewave.txt; ~250k sats of force-close outputs (to_local/L-stock) are
    CSV(144)-gated -- sweepable after maturation via the seed (scantxoutset + re-derive).
  - **#56 / P3 fee-wave defense: COMPLETE** -- commitment anchor (PR #391) + tree anchors
    (this branch), proven on regtest (unit + mass-exit conservation) AND real signet
    (presence + spendability). Every force-close cascade tx is CPFP-able. Open a PR.
- **P4 — Remaining wt_db recourse paths (#55, R6). DONE + CONFIRMED (2026-06-25).**
  Research conclusion (then empirically confirmed, per the kind-3 lesson "trust the
  test over the grep"): NO real gap remained. (1) **kind=3 force-close CLTV**: standalone
  test green — secret-less WT swept the HTLC-timeout from wt.db alone, sweep confirmed
  on-chain (819 sats). (2) **JIT**: by design the defense is DETECTION via the factory-leaf
  watch (JIT doesn't mutate the leaf, so there's no distinct response to broadcast) —
  test_regtest_cheat_jit.sh green: cheat fired -> WT registered the OLD leaf -> FACTORY
  BREACH detected (breach_detections row). (3) **L-stock burn kind0**: the standalone WT
  fires the burn on a factory-node breach (watchtower.c:1083), and the modern recourse is
  the wt_db-persisted POISON (standalone-proven via #53) -- the burn is legacy/single-process.
  The factory-node response + poison are already standalone-matrix-proven. INFRA NOTE: the
  JIT test first failed on regtest faucet-exhaustion (height>~4500 -> ~0-sat coinbases);
  fixed by pre-funding ss_cheat_jit_miner from the accumulated ss_cheat_leaf_miner (9348 BTC)
  -- applies to any fresh-miner-wallet test at high regtest height.
- **P5 — Harness rigor Tier 2/3/4 (#35).** DoD: audit the back-catalog breach
  tests; upgrade machinery-asserts ("penalty broadcast") to economic-outcome
  asserts (real txid -> confirm -> amount/net-delta). Are our trustless PROOFS
  rigorous? STATUS: pending.
- **P6 — Liveness / escalation (#48-51, #54).** DoD: bounded-retry -> proactive
  exit on a stalled advance (not blind-until-expiry); ABORT_ADVANCE advisory +
  local timeout; intent-to-exit NOTICE. Safety holds via the DW/CLTV override;
  this is graceful degradation. STATUS: pending.
- **P7 — Operational self-custody (#62,#63,#64).** DoD: fee-reserve /
  deposit-insurance so a fully-in-factory client can pay to exit; WT operational
  model doc; secret backup/restore + construction migration. Part design, part
  code. STATUS: pending.
- **P8 — External audit (#328).** CANNOT be closed here (funding-gated, the
  mainnet long pole). Keep the audit-prep package current as the layers close.
  STATUS: external/blocked.

## Progress log

- 2026-06-22: plan created. Baseline = #53 sub-factory hashlock proven (regtest +
  signet) + recovered; no known theft gap. Starting P1.
- 2026-06-22: **P1 CODED** (awaiting validation) — `SS_CHEAT_BAD_POISON_AGGSIG` env
  cheat (lsp_channels.c, regtest-only via superscalar_cheat_allowed; #9 gate refuses
  SS_CHEAT* on mainnet) corrupts the agg-sig shipped in SUBFACTORY_DONE;
  `tools/test_regtest_hashlock_aggsig_reject.sh` asserts the client D2-rejects + persists
  no worthless reveal row. Committed locally.
- 2026-06-22: **BLOCKED on local network outage** — GitHub HTTPS + VPS SSH both timing
  out from this machine (`curl https://github.com` -> 000; ssh port 22 -> banner-exchange
  abort). Can't push or build/test on the VPS until connectivity returns. All work is
  committed locally on `trustless-completion`.
- 2026-06-22: **P2 design note** (read-only investigation while blocked): the standalone
  WT already carries a deadline-driven CPFP fee-bump escalator (watchtower.c +
  htlc_fee_bump.h: `watchtower_build_cpfp_tx`, per-pending `fee_bump` = {start_block,
  deadline_block, budget_sat, start_feerate, last_feerate}, `max_bump_fee_sat` ceiling).
  So P2's harness = register a recourse/penalty at a LOW start feerate, apply fee pressure
  (competing low-fee mempool or a manual high-feerate floor), and prove the escalator bumps
  the package to CONFIRM before the CSV/CLTV `deadline_block`. The mechanism exists (#52);
  P2 proves it WINS the contested race. Resume here when the network is back.
- 2026-06-22: network restored (fail2ban ban aged out). **P1 VALIDATED GREEN** on regtest
  (LSP shipped corrupt agg-sig; 2 clients D2-rejected; 0 worthless reveal rows). P1 closed.
  Starting **P2** (Layer-3 fee-race).
- 2026-06-23: **P2a (WT-driven fee-bump) VALIDATED GREEN** on regtest. The #52 BUMP PROOF
  (`SS_HIFEE_BUMP=1 test_regtest_trustless_commitment_breach.sh`): a standalone WT hydrated
  24 commitment watches, the penalty was deprioritised -3000 sats (bare tx unmineable), and
  the WT's deadline-driven CPFP escalator ramped feerates 5501->6898->9071->11399 until the
  penalty CONFIRMED (69 blocks). WT-driven Layer-3 (factory/sub/commitment penalties) PROVEN.
  (Infra note: the VPS regtest bitcoind was simply down — the commitment harness assumes it
  is up; my hashlock harnesses start it. Runner now ensures bitcoind up before the test.)
- 2026-06-23: **P2b (client-driven poison fee-race) CODED**. Key architectural finding: the
  #53 poison is CLIENT-driven (the secret-less WT can't assemble it) and is a PRE-SIGNED,
  FIXED-FEE tx -- the N-of-N agg-sig binds its outputs, so it is **NOT RBF-able**. Its only
  fee-bump is **CPFP on a client's own P2TR output** (every poison output is `tr(client_key)`,
  factory.c:3555-3585 -- Zmn: "any client can trivially CPFP the poisoning transaction"). The
  first-line defense is the **144-block L_STOCK CSV head-start** (the LSP's Leaf-L fallback
  can't mature before then). New gated branch `SS_POISON_CPFP_RACE=1` in the sub-factory e2e:
  deprioritise the bare poison (control-prove it stuck), then the client CPFPs via a fat-fee
  child on its poison output and the poison CONFIRMS << 144 blocks. Awaiting validation.
- 2026-06-23: **P2b VALIDATED GREEN** on regtest (commit 3a12ae7). Poison broadcast, -3000
  deprioritise => control proved the bare poison STUCK; client output located by address-match
  (vout=0, 21,667 sats); client CPFP child (12000-sat fee) => poison CONFIRMED in 1 block
  (<< 144-block head-start). signrawtransactionwithwallet signed the taproot key-path cleanly.
  Two bugs found+fixed en route: (1) set -euo pipefail tripped on the no-match `getrawtransaction
  | grep '"confirmations"'` in the EXPECTED-unconfirmed control state (added `|| true`); (2) the
  descriptor checksum was extracted with `grep -oE '[0-9a-z]{8}'`, which matched the literal word
  "checksum" -> tr(WIF)#checksum rejected -> empty wallet (now parses the JSON `checksum` field).
  **P2 (Layer-3 fee-race) is DONE + PROVEN for single-breach.** Tasks #60 + #68 closed.
  NEXT: P3 (mass-exit thundering herd, #56) -- the OTHER fee-race: N clients contending for
  block space at the SHARED factory CLTV deadline simultaneously.
