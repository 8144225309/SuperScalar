# Trustless Watchtower Model — Research & Analysis Findings

Five independent read-only analyses (2026-06-20). Synthesis + reprioritization.

## What is sound
- **Secret-less split is real.** `wt.db` holds zero secrets (verifiable `nm -D --defined-only superscalar_watchtower | grep persist_load_` → empty). Tables `wt_watches`/`wt_responses` store only public bytes (parent outpoint/value/spk/csv + fully-signed response hex). `watchtower_hydrate_from_wt_db` (watchtower.c:1961) rebuilds in-memory entries with no keys. (`docs/watchtower-trustless-schema.md`, `persist_wt.c:18-68`.)
- **Commitment penalty (kind 2)** spends the breach's OWN to_local/HTLC outputs → no orphan risk; CSV-deadline CPFP fee-bump handles the confirmation window (watchtower.c:1177-1266,1517-1610). Fail-closed if penalty bytes absent.
- **DW timelock model** is a correct decrementing scheme: `dw_delay_for_state = step*(max_states-1-state_index)` (dw_state.c:11); newer state = smaller relative timelock; kickoff has fixed `0xFFFFFFFF` (no CSV) and is the epoch-invariant output competing states race to spend (factory.c:1417-1438).

## CORRECTION — CL4 rollover was MISDIAGNOSED (#37)
- The WT response model is NOT broken. Tier-B Step 10 (lsp_channels.c:2565-2589) registers **each affected node** with its own `{old txid → new tx}`; `affected[]` on a root rollover **includes the root NODE_STATE** (node index 1, not 0 — node 0 is the root kickoff). So the WT already holds `{old root-state → new root-state}`.
- validate20's "Latest state tx broadcast failed" is because the **test** mines the old tree to confirmation (`broadcast_factory_tree_any_network` mines THROUGH timelocks, superscalar_lsp.c:811-868). Once the old root-state confirms, the kickoff output is spent → new root-state can't double-spend.
- **Fix is TEST-ONLY**: give the DW window. Drop plan Phases 1-2 (protocol changes unnecessary).
- **Deeper question (verify):** the clean timelock win happens only in `[new_csv, old_csv)` after the kickoff confirms. A purely reactive WT that waits to *see* the stale state reacts at `old_csv` (both txs final → fee race). The clean win needs acting on the **kickoff/window-start**. Confirm whether the WT watches the kickoff, or the honest client's escalation (#19-23) broadcasts the new state proactively, or this is a real reactive-timing gap.

## REAL GAPS surfaced (trustless wt_db persistence)
### G1 — CRITICAL: sub-factory breach unremediable for the STANDALONE trustless WT
- `wt_db` sub-factory row stores `response = chain[N]` and **NO poison TX** (lsp_channels.c:3958; adapter lsp_wt.c:82 has no poison param/column). Hydration loads it as `WATCH_FACTORY_NODE` poison=NULL (watchtower.c:1948) → broadcasts `chain[N]`, which the in-process handler itself documents as structurally invalid after `chain[N-1]` confirms (`-25 bad-txns-inputs-missingorspent`, watchtower.c:1076-1138). In-process path uses the poison (works); trustless path can't.
- **TENSION TO RESOLVE:** memory says "sub-factory PROVEN standalone-WT" (signet #38 subfactory PASS). Either that proof used the in-process WT (not true wt_db-only hydration), or the poison reaches wt_db by a path the analysis missed. **Verify before acting:** does the sub-factory standalone test launch a separate WT process that hydrates ONLY from wt_db, and does the poison actually fire from there?

### G2 — MEDIUM: HTLC/PTLC sweeps absent from wt_db
- Revoked-commitment HTLC sweep + PTLC bytes persist only to `lsp.db` (watchtower.c:714,803-820), not mirrored to `wt_db`. Standalone WT penalizes `to_local` but leaks in-flight HTLC/PTLC value. (In-process / same-`wt->db` WT is fine — init reloads them.)

### G3 — HIGH (in-process too): sub-factory poison degradation
- If poison signing degrades during the ceremony (signer non-cooperation, lsp_channels.c:2569/3941), `burn_tx`=NULL → handler logs "Gap A SECURITY GAP" and does nothing (watchtower.c:1133-1138). Sub-factory has no `response_tx` fallback by design → detect-but-cannot-remediate even in-process.

### Minor
- wt_db rows never superseded (`persist_wt_supersede_watch` has 0 callsites) → unbounded growth (operational), but means a standalone WT does ladder ALL historical states (so the in-process "only-latest-revoked rehydrate" gap, lsp_channels.c:7653, is covered for the standalone path — except sub-factory, nullified by G1).
- kind 3 force-close: latent orphan (no conf check on commit txid before timeout sweep) but dead in production (`ch==NULL` gate, watchtower.c:1410).

## Reprioritization
1. **Verify G1** (sub-factory standalone wt_db-only) — resolve the tension with the "proven" claim. If real, it's higher severity than the rollover.
2. **Rollover (#37):** downgrade to a TEST-window fix + verify the reactive-timing question.
3. **G2/G3** scoped fixes (mirror HTLC/PTLC + poison to wt_db; add a degraded-poison alarm).
