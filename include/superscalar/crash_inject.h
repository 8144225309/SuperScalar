#ifndef SUPERSCALAR_CRASH_INJECT_H
#define SUPERSCALAR_CRASH_INJECT_H

/* Crash-injection helper for ceremony-state restart drills.
 *
 * Gate C of the dashboard-team handoff
 * (C:/pirq/dashboard-upgrade/LSP_TEAM_HANDOFF_CEREMONY_CRASH_INJECTION.md).
 *
 * The library sprinkles lsp_crash_checkpoint("<name>") at ceremony state
 * boundaries.  Production code never sets SUPERSCALAR_CRASH_AT, so the
 * helper is a no-op (one getenv + one strcmp per checkpoint, microseconds).
 * Test scaffolds set SUPERSCALAR_CRASH_AT=<name> in the LSP env to trigger a
 * deterministic abort right after the named state lands in persist — driving
 * mid-ceremony crash-recovery tests against fixed cut points instead of
 * timing-based kills.
 *
 * Names defined today (see src/lsp.c lsp_run_factory_creation):
 *   "pending_nonces"     — after persist_save_ceremony(PENDING_NONCES)
 *   "nonces_aggregated"  — after persist_update_ceremony_state(NONCES_AGGREGATED)
 *   "pending_sigs"       — after persist_update_ceremony_state(PENDING_SIGS)
 *   "finalize_partial"   — before persist_update_ceremony_state(FINALIZED)
 *                          (catches the N-1-SIGNED dual-sig-trap path)
 *
 * The same naming convention extends to ROTATE / FORCE_OUT once those
 * ceremonies wire their own persist transitions (Gaps A + B of #245).  No
 * conditional logic, no flag persistence — pure env check + abort.
 */
void lsp_crash_checkpoint(const char *name);

/* SF-CRASH-INJECT-WIRE #245 Half B: install a runtime crash-checkpoint
   target.  NULL or "" clears it.  The runtime target is checked BEFORE
   the SUPERSCALAR_CRASH_AT env var so wire-driven tests (MSG_FORCE_OUT)
   can override compile-time settings.
   THREAD UNSAFE -- for single-process test harness only. */
void lsp_crash_set_target(const char *name);

/* #9 cheat-gate: defense-BYPASS cheats (e.g. SS_CHEAT_DUST_RACE, which strands
   counterparty HTLCs to absorb them at force-close) must NEVER fire on a real
   network. The binary calls superscalar_set_cheat_gate(is_regtest) at startup;
   library cheat sites call superscalar_cheat_allowed() IN ADDITION to their
   env-var check, so a directly-set SS_CHEAT_* env var is inert unless the node
   runs on regtest. Default (gate never set) is 0 = NOT allowed (fail-safe).
   Detection-only cheats (broadcast-revoked-state, self-harming) are handled
   separately by refusing the cheat/test scaffolding flags on mainnet at
   arg-parse. */
void superscalar_set_cheat_gate(int is_regtest);
int  superscalar_cheat_allowed(void);

#endif /* SUPERSCALAR_CRASH_INJECT_H */
