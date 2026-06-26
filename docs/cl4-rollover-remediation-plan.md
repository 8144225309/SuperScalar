# CL4-Rollover Remediation — Self-Executable Plan

**Owner:** me (no hand-offs). **Branch:** `test/harness-rigor-remediation` (push from LOCAL Windows; VPS has no git creds).
**State at start:** detection PROVEN (`FACTORY BREACH on node 3`, validate20 @ 381a763). Remediation (WT override) fails: `Latest state tx broadcast failed`.

## Goal (the OUTCOME to assert — not just machinery)
A Tier-B **root rollover** stake-theft is fully defeated end-to-end on regtest:
1. WT **detects** the revoked old-epoch tree (done).
2. WT **remediates** by broadcasting the **new-epoch root `NODE_STATE`** (the kickoff-spender). It double-spends the root kickoff output (already on-chain from the cheat) with the **smaller DW timelock**, wins the race, and invalidates the entire old tree.
3. Test asserts the **economic outcome**: the WT's new-state tx **confirms**, the old leaf is **invalidated** (never confirms / its output unspent by the attacker), funds end up under the new epoch. No existence-masquerade.

## Topology (confirmed)
- DW nodes are `NODE_KICKOFF`→`NODE_STATE` pairs (`factory.h:100`). Root counter rollover advances the **root** `NODE_STATE`.
- Kickoff output is fixed across epochs; competing `NODE_STATE`s double-spend it; **smaller relative timelock wins**.
- Breach is observed at the leaf (`node 3`), but the **override competitor is the new-epoch root `NODE_STATE`**, not the leaf. The current response (`e->response_tx = an->signed_tx` = new leaf, `watchtower.c:1001`) spends a not-yet-on-chain parent → orphan → fail.

---

## Phase 0 — Empirically pin the topology (de-risk before coding)
Add a one-shot debug print (guarded by `getenv("SS_CL4_TOPO")`) in the cheat (`superscalar_lsp_pre_daemon_tests.inc`, right after the rollover) dumping, for every node: index, `type`, `parent_index`, `parent_vout`, `nsequence` (relative timelock), `dw_layer_index`, txid first8, is_signed. Run the rollover test once with `SS_CL4_TOPO=1`.
**Outputs to capture:** which node index is the **root `NODE_STATE`** (parent = root `NODE_KICKOFF`), its nsequence vs the leaf's, and the old vs new root-state txids. This confirms the competitor node + that old root-state timelock > new root-state timelock.
**Exit criteria:** I can name the exact node index whose new-epoch tx the WT must broadcast.

## Phase 1 — WT response model (`src/watchtower.c`)
- Extend `watchtower_entry_t` (and `watchtower_watch_factory_node[_with_channels]`, `watchtower.c:1756/1792`) to carry an **ordered response path** (array of `{bytes,len}`) instead of a single `response_tx`. Keep `response_tx` as path[0] for back-compat; add `response_path[]`/`n_response_path`.
- In the `WATCH_FACTORY_NODE` handler (`watchtower.c:993–1066`): broadcast the path **in order** (root-state first, then any intermediates, then the leaf), stop+count success on the first that lands the competing state node; treat the override as successful when the **root-state competitor** confirms (that alone kills the old tree). `penalties_broadcast++` only on the competitor landing.
- Trustless persistence: mirror the path into `wt_db` (extend `lsp_wt_register_factory_node_watch` / schema with a small `response_path` blob, or N rows). Keep `persist_log_broadcast` markers (`factory_response`).

## Phase 2 — Registration of the competitor (`src/lsp_channels.c`)
- In Tier-B Step 10 (`lsp_channels.c:~2585`), for a **root rollover** (trigger_leaf == -1), build the response **path** = [new root `NODE_STATE` tx, …intermediates…, new leaf tx] for each affected leaf, and pass it to the extended `watchtower_watch_factory_node_with_channels`. Reuse `parent_index` walking from the leaf up to the root state to assemble the path.
- Leave the per-leaf *advance* path (non-rollover) unchanged (leaf-only response is correct there — same parent stays on-chain).

## Phase 3 — Test gives the DW window (`tools/superscalar_lsp_pre_daemon_tests.inc`, cheat block)
- Today the cheat broadcasts the old tree via `broadcast_factory_tree_any_network` which **mines through** the timelocks → old root-state confirms → no window. Change the cheat to:
  1. Broadcast the old tree **up to and including the root kickoff** (confirm the kickoff), then submit the **old root-state** to the **mempool only** (do NOT mine past its relative timelock).
  2. Call `watchtower_check` — the WT broadcasts the **new root-state** (smaller timelock).
  3. Mine the minimum blocks for the **new** root-state's timelock; assert the **new** root-state confirms and the **old** root-state is evicted/never confirms.
- If `broadcast_factory_tree_any_network` can't stop before the final timelock, broadcast the path manually with `regtest_send_raw_tx` and control mining.

## Phase 4 — Test asserts the economic OUTCOME (`tools/test_regtest_cheat_daemon_rollover.sh`)
- Replace the detect-only pass with: (a) `FACTORY BREACH` detected; (b) the WT's **new root-state txid** CONFIRMED on-chain (`getrawtransaction … confirmations≥1`); (c) the **old leaf txid is NOT confirmed** (attacker’s stale state defeated); (d) optional: funds at the new-epoch output ≥ expected. Hard-FAIL otherwise. Source `pen_recovers_most`/floor helpers as elsewhere.

## Build / run (VPS, isolated)
- Push from local → on VPS reuse worktree: `git -C /root/SuperScalar-rigor reset --hard origin/test/harness-rigor-remediation` → `cmake --build /root/SuperScalar-rigor/build-rigor -j6` (incremental, only LSP/WT recompile) → run `test_regtest_cheat_daemon_rollover.sh` with `BUILD_DIR=…/build-rigor`. Detached `systemd-run --unit=ss-rvNN --collect`; poll one long-lived SSH (no bursts → fail2ban). Node-guard restarts `bitcoind-jaynet` if down.

## GREEN criteria
- `test_regtest_cheat_daemon_rollover.sh` rc=0 with: breach detected + **new root-state confirmed** + **old leaf not confirmed**. Then run the full `run_rigor_matrix.sh` to confirm no regressions (expect 17 PASS / multistate SKIP).

## Risks / rollback
- Schema change to `wt_db` → bump persist schema_version + migration (pattern: existing v36/v37). If the trustless-WT path proves large, land the **in-process** path-response first (makes the test GREEN + closes the live-LSP gap), then the `wt_db` mirror as an immediate fast-follow — but do NOT mark #37 done until the standalone trustless WT also overrides.
- If the DW window can't be cleanly created in the harness, fall back to a unit-level test that drives the WT override directly with crafted timelocks (still asserts the competitor confirms / old dies).
- Each step is independently committable; revert is per-file. Keep the cheat behind `SS_CHEAT_ROLLOVER` so production paths are untouched.

## Definition of done for #37
Standalone trustless WT (separate process, no factory access) detects a Tier-B root-rollover breach AND its pre-stored new-root-state response confirms on-chain, defeating the old tree, asserted by amount/confirmation — on regtest, then signet. Update memory `project_test_harness_rigor` + close #37.
