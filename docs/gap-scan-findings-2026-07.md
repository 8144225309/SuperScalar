# Gap-scan audit findings — 2026-07 (pre-v0.2.0-tag)

A four-lens adversarial audit (fund-safety, watchtower completeness, mainnet-safety,
recent-PR correctness) of `main`. Every finding below was **verified against the code**
by the orchestrator, not taken on an agent's word. Headline: **no direct-theft,
key-leak, or fund-theft gap.** One HIGH *robustness* gap + one real bug were found and
**fixed**; the rest are MED/LOW deterrent-gaps and design boundaries, recorded here.

## FIXED (this pass)

- **HIGH — client never verified the LSP factory tree signatures.** `client_apply_factory_ready`
  set `is_signed=1` with no check; `factory_verify_all` (secret-free) was never called
  client-side. A buggy/malicious LSP could ship an invalid tree → client uses the channel,
  then can't self-exit (force-close rejected on-chain) = **frozen funds** (freeze/ransom, not
  theft — N-of-N frozen for the LSP too). **Fix:** client now calls `factory_verify_all` and
  refuses on failure (client.c). Validated: passes on 319 valid factories, regression 19/19,
  INVALID marker absent → no false-positive.
- **BUG — L-stock advance siblings not anchor-aware.** `update_l_stock_for_leaf` (factory.c:2488)
  and `update_l_stock_outputs` (:435) wrote the L-stock SPK into `outputs[n_outputs-1]` = the
  P2A anchor when `use_tree_anchor` is on (same #98 off-by-one). Corrupted the CPFP anchor +
  froze the L-stock hashlock on advance. **Fix:** anchor-aware index in both.
- **G3 (MED) — `local_pcs` per-commitment secrets plaintext at rest.** A channel-security
  secret mis-grouped with the v0.3 payment-privacy deferral. **Fix:** sealed (writer/reader +
  SECRET_COLS, auto-migrates).
- **G1/G2/G5 (LOW) — mainnet guard gaps.** Broadened the LSP env-refusal to `SUPERSCALAR_CRASH`
  prefix (catches `_ALLOW`); mirrored the env-refusal in the client (was args-only); added an
  unknown-`--network` allowlist (an unrecognized network defaulted to the mainnet RPC port
  while exact-`"mainnet"` guards did not fire).

## DOCUMENTED (deterrent-gaps / design boundaries — pre-mainnet, not tag-blocking)

- **MED — Tier-B rollover L-stock poison-arming is dead code.** In
  `lsp_run_state_advance_stateless` (lsp_channels.c), `affected[]` skips `is_signed` nodes
  (:2111), so `had_old = (an->is_signed && ...)` (:2195) is **always false** → the
  epoch-boundary superseded state gets no freshly-armed L-stock poison; the wt_db watch is
  inert. **Not principal loss** — client channel funds are PD-penalty-covered independently;
  this only affects the *deterrent* (burn/redistribute the LSP's own L-stock) for the
  epoch-boundary state, and the DW timelock override still applies. Distinct from the
  leaf-advance poison, which IS armed + proven firing (#37, on-chain). **Fix spec (traced
  end-to-end):** the bug is deeper than the `had_old` gate — the entire per-affected-node
  snapshot at lsp_channels.c:2223-2243 reads the ALREADY-REBUILT node (txid @2225, L-stock
  amount @2233, chain amount/SPK @2237-2243), because `factory_advance_*` calls
  `update_l_stock_outputs` (rewrites the L-stock SPK) then `build_all_unsigned_txs`
  (overwrites `node->txid`, factory.c:569) BEFORE the caller `lsp_run_state_advance_stateless`
  runs. So a valid poison spending the OLD L-stock output cannot be assembled from what's
  left. Fix = have factory.c snapshot each node's old {txid, L-stock vout+amount+SPK, chain
  amount+SPK} into `prev_epoch_*` fields BEFORE `update_l_stock_outputs`/`build_all_unsigned_txs`
  overwrite them, at ALL FOUR advance paths (factory.c:2546/2593/2617/2699), then have the
  ceremony read `prev_epoch_*` (mirrors how the leaf path snapshots pre-advance at
  lsp_channels.c:1382-1418); add a fail-closed abort like the leaf advance (lsp_channels.c:1840).
  A careful core-rollover restructure (high blast radius, 4 paths) needing a NEW Tier-B-boundary
  poison regression (the existing rollover test exercises the leaf poison, not the epoch
  boundary). Deferred as a focused follow-up rather than rushed — deterrent-only, not fund-safety.
- **MED — leaf L-stock poison not mirrored to wt.db — LEAF-ADVANCE FIXED + PROVEN (branch gapscan-meds).**
  `lsp_channels.c:1924` (leaf-advance) mirrored only `signed_tx` (chain[N]), not the co-signed
  poison. Unlike the sub-factory (chain[N] orphans `-25`, so the poison *replaces* it `:4199`),
  the leaf's chain[N] is a VALID post-confirmation response that re-asserts client balances
  (≥90%), so the poison is a *secondary deterrent* spending a DIFFERENT vout of `old_leaf_txid`.
  **Fix (proven):** register the poison as a SECOND wt_db factory-node watch on the same parent
  (leaf node carries `poison_signed_tx`/`poison_is_signed`/`poison_txid`, factory.h:177-182);
  `wt_watches` has an AUTOINCREMENT PK and the hydrating WT fires every row sharing a parent, so
  both broadcast. VALIDATED e2e: `test_regtest_cheat_daemon_leaf.sh` asserts the secret-less
  standalone WT confirms BOTH chain[N] AND the poison (2 responses from wt.db alone). CAVEAT: the
  cheat tests read BUILD_DIR from `$1` (default ASan `build/`) — validate with `build-release`
  as `$1` or rebuild `build/`, else you test a stale binary (feedback_cheat_test_build_dir).
  **Realloc variant (:3366) REVERTED — code-ready follow-up:** identical pattern, but no suite
  test has BOTH `--wt-db` AND a prepared realloc poison (cheat_realloc has the poison, no
  `--wt-db`; watchtower_trustless has `--wt-db`, no realloc poison), so it can't be e2e-validated
  now. Follow-up: add `--wt-db` + standalone WT to cheat_realloc, then re-apply the 2nd-watch mirror.
- **LOW — WT completeness nuances.** (F4) force-close kind=3 is armed reactively (on a peer's
  BOLT ERROR), so a *pre-suppressed* LSP leaves no kind=3 row — pre-emptive arming would close
  it. (F5) `fee_bump_*` metadata is inert in every wt_db row; the WT only CPFPs if the
  pre-signed response happens to carry a P2A anchor (baked at registration), so a penalty
  signed in a low-fee window can't be bumped later (relates to #52). (F6) the HTLC-sweep mirror
  is nested under `wt->db` presence while to_local/PTLC mirrors are not — inconsistent coupling,
  never hit in production (always both DBs).
- **LOW — client-side.** Client's own watchtower handles only revoked channel commitments (no
  reactive factory/sub-factory WT — offline clients lean on the LSP-populated wt.db or
  `--force-close`; canonical model is "each client runs its own WT", `pre-mainnet-design-decisions.md`).
  Client revoked-commitment watch is armed with `NULL` PTLCs (superscalar_client.c:827) — main
  penalty sweeps to_local, but a PTLC output on that commitment wouldn't be swept by the
  client's WT. Client does not re-persist `tree_nodes` after intra-factory advances (a crash
  recovers the last-rotation tree, not principal-affecting).

## Verified-solid (no gap)
Poon-Dryja channel-penalty recourse is client-secret-complete, persisted, and enforced by a
client-controlled watchtower the LSP cannot suppress. Cheat gate is fail-safe (only `"regtest"`
enables; all 11 theft-cheats inert on mainnet). All custody secrets sealed; `--seckey` refused
on mainnet; no MuSig secnonce persisted. Standalone WT is genuinely secret-less. Reconnect
untrusted-claim refusal, revocation-secret handling, and poison/distribution verify-before-trust
are fail-closed.
