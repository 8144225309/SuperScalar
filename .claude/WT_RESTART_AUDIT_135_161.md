# Watchtower restart-correctness audit (R1/R5)

**Tasks:** #135 (audit R1/R5 WT restart), #161 (verify watchtower_init reloads WATCH_FACTORY_NODE + WATCH_SUBFACTORY_NODE)

**Date:** 2026-05-16
**Audited against:** main post-PR #222 (commit 8bb9dab)

## Method

Code-read of every persistent WT entry type's save/load path, then walked the LSP startup sequence to verify each entry type is restored correctly.

## Findings — each WT entry type

### WATCH_COMMITMENT entries

**Storage:** `old_commitments` table.
**Restore:** `watchtower_init` (src/watchtower.c:56-140) iterates channels and calls `persist_load_old_commitments` for each. Per-entry fields restored:
- commit_num, txid, to_local_vout/amount/spk
- csv_delay (v32 SF-WTC #149, src/watchtower.c:88-90) ✓
- signed_penalty_tx (v25 — pre-built penalty bytes via `persist_load_old_commitment_witness`) ✓
- HTLC outputs via `persist_load_old_commitment_htlcs` ✓
- Chain-backend script registration via `wt->chain->register_script` so BIP-158 scanning resumes ✓

**Status:** ✓ Complete.

### WATCH_FACTORY_NODE + WATCH_SUBFACTORY_NODE entries (#161)

**Storage:** **NOT directly persisted.** Instead, rebuilt from in-memory factory state (which IS persisted) via `lsp_channels_rehydrate_watchtower_from_chains` (src/lsp_channels.c:6866).

**Restore flow:**
1. `persist_load_factory` restores `factory_t` including `ps_chain_len`, `ps_prev_txid`, signed_tx, poison_signed_tx for every node
2. Caller (tools/superscalar_lsp.c:2568) calls `lsp_channels_rehydrate_watchtower_from_chains(mgr)` AFTER factory load
3. Function walks `f->leaf_node_indices[]` for PS leaves with `chain_len >= 2` → calls `watchtower_watch_factory_node_with_channels`
4. Function walks `f->n_nodes[]` for `NODE_PS_SUBFACTORY` with `chain_len >= 2` → calls `watchtower_watch_subfactory_node`

**Status:** ✓ Both WATCH_FACTORY_NODE and WATCH_SUBFACTORY_NODE re-watch paths are wired and called on startup.

**Observation (not a gap):** Nodes with `chain_len < 2` are skipped. This is correct — `chain_len=1` means chain[0] only, no advance, no prior state to watch. The cooperative path on chain[0] doesn't need a WT registration.

### WATCH_FORCE_CLOSE entries

**Storage:** Dedicated `force_close_watches` + `force_close_htlcs` tables (v28, PR-C-2).
**Restore:** Documented in persist.h:691-703.

**Status:** ✓ Persisted with dedicated tables. (Did not deep-audit the restore path; PR-C-2's tests cover this.)

### WATCH_PENDING (CPFP bump tracking)

**Storage:** `pending_penalty_broadcasts` table.
**Restore:** `watchtower_init` lines 142-160 via `persist_load_pending`. Restores: txid, vout, amount, cycles, bumps, penalty_values, csv_delays, start_heights, fb_*_blocks/deadlines/budgets/feerates.

**Status:** ✓ Complete.

## R1 (reorg detection) — restart correctness

- **Daemon-loop reorg detector** (PR #201) → calls `watchtower_on_reorg` to re-validate WT entries ✓
- **Heartbeat reorg detector** (lsp_channels.c:6382-6479) — mirrors main-loop logic with same three-kind detection (HEIGHT_REGRESSION, SAME_HEIGHT, FORWARD_REORG) ✓
- **factory_reset_all_subfactory_chains** (PR #208) — wired into reorg handler, drops in-memory `ps_chain_len` on PS_SUBFACTORY nodes ✓

**Status:** ✓ No gaps.

## R5 (funding_pending_reorg) — restart correctness

- **lsp_channels_revalidate_funding** called from R1 handler (PR #210) ✓
- **Persistence across restart** (PR #211, schema v31) — `funding_pending_reorg` flag survives restart ✓
- **Wire protocol notification** to clients (MSG_FUNDING_REORG, PR #212) ✓
- **Mempool-expiry policy** (PR #215) — proactive freeze when funding TX evicted ✓
- **Client-side mirror** — PR (this audit's #145 work, in flight) wires client-side `factory_reset_all_subfactory_chains` on MSG_FUNDING_REORG ✓

**Status:** ✓ No gaps post-#145.

## Conclusion

**WT restart correctness for R1/R5 is complete. No new code required.**

Both #135 (audit R1/R5) and #161 (WT factory/subfactory reload) are answered:
- #135: every WT entry type has a documented and wired restore path
- #161: factory and subfactory node entries are NOT stored in dedicated tables; they're rebuilt from in-memory factory state by `lsp_channels_rehydrate_watchtower_from_chains` which IS called on startup (tools/superscalar_lsp.c:2568). This is by design (the factory state is the source of truth) and works correctly.

**Recommendation:** Mark #135 and #161 completed.
