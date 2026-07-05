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
  leaf-advance poison, which IS armed + proven firing (#37, on-chain). **Fix approach**
  (`docs/cl4-rollover-remediation-plan.md`): snapshot each affected node's old signed_tx +
  txid BEFORE `build_all_unsigned_txs` (factory.c:569) overwrites them, and add a fail-closed
  abort mirroring the in-epoch leaf advance (lsp_channels.c:1840). Non-trivial restructure;
  do with a targeted Tier-B-boundary regression.
- **MED — leaf/factory-node L-stock poison not mirrored to wt.db.** `lsp_channels.c:1924/2715/3366`
  mirror only `signed_tx` (chain[N]) as the factory-node response, not the co-signed poison
  (contrast sub-factory, which stores the poison). A standalone WT re-asserts client channel
  balances (chain[N], ≥90% value proven) but does not fire the leaf L-stock poison — that leg
  is client-driven by design (`superscalar_lstock_recover`, #62) or in-memory-WT only. **Fix
  approach:** mirror the co-signed leaf poison into wt_db as the response (symmetry with
  sub-factory) so the "run your own WT" story covers the L-stock leg.
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
