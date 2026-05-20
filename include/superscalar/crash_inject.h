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

#endif /* SUPERSCALAR_CRASH_INJECT_H */
