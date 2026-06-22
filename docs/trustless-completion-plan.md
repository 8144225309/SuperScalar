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
| 3 **Win** | Recourse confirms BEFORE the attacker's tx, under fee pressure? | **FRONTIER** — fee-bump exists (#52), contested race UNPROVEN (P2/P3) |
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
  Recourse that fires but loses the race isn't trustless. STATUS: pending.
- **P3 — Mass-exit thundering herd (#56).** DoD: N clients exit at the shared
  factory CLTV simultaneously; prove no client is stranded by the fee-race, or
  document + implement the mitigation. STATUS: pending.
- **P4 — Remaining wt_db recourse paths (#55, R6).** DoD: e2e the L-stock burn
  kind0 + JIT-channel recourse via the standalone (secret-less) WT — arm in wt_db
  + fire + confirm. (kind=3 force-close already corrected as NOT a gap.) STATUS: pending.
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
