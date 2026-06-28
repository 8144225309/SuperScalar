# P6 — Bounded fresh-nonce retry for MuSig2 signing ceremonies (#48)

Living design doc for the trustless-completion P6 liveness item. Branch:
`feat/bounded-fresh-nonce-retry`. Created 2026-06-28.

## Goal / DoD

When a MuSig2 signing ceremony fails — a partial signature fails to verify, the
aggregate Schnorr signature is invalid, or a counterparty's nonce/psig is
rejected — the ceremony should **retry with a FRESH nonce a bounded number of
times** before aborting, instead of aborting on the first failure or blocking
until a timeout/expiry. On exhaustion it escalates via the existing P6 policy
(proactive exit, `CEREMONY_ABORT_RETRY_LIMIT_REACHED`, intent-to-exit NOTICE),
never "blind until expiry". Safety always holds via the DW/CLTV override; this is
graceful **liveness** degradation, not a safety mechanism.

## Security precondition — the gate (VERIFIED)

Bounded retry is only safe if each attempt uses a genuinely **fresh** nonce.
Reusing a secnonce across two different challenges leaks the secret key
(Schnorr/MuSig2: two `s_i = k_i + e·a_i·x_i` with the same `k_i`, different `e`,
solve for `x_i`). The codebase satisfies this:

- All nonces draw fresh OS randomness per call via `fill_random()` →
  `/dev/urandom` (`src/musig.c:9-15`), feeding the BIP-327 `session_id` (`rand`)
  input in **every** nonce-gen entry point: `musig_sign_all_local`,
  `musig_nonce_pool_generate` (also fresh `extra_input`), and
  `musig_generate_nonce`. There is **no deterministic nonce derivation anywhere**.
- A secnonce is **single-use**: `secp256k1_musig_partial_sign` zeroes it. So a
  retry cannot re-sign with a held secnonce — it MUST restart from nonce
  generation, which by construction yields a new, non-repeating nonce.
- Secnonces are **per-attempt, stack-resident, never persisted** (stateless-signer
  model). Re-entering an orchestrator on retry automatically gets a brand-new
  secnonce; there is no cache to invalidate.

**Conclusion: re-running a ceremony from nonce generation is nonce-reuse-safe.**
The only resource concern is the two *pool*-based paths (channel commitment;
stateless factory-creation client) — a retry consumes a pool slot, so retries
must handle `musig_nonce_pool_next == 0` (pool exhaustion) by regenerating.

## Architecture findings (from the ceremony map)

1. Most ceremonies aggregate partial sigs **without** per-signer verification, then
   verify the **final aggregate** Schnorr sig. Exceptions: `channel.c` verifies the
   peer's partial sig; and — critically — **networked factory-creation and
   cooperative-close verify NOTHING at ceremony time** (a bad psig surfaces only at
   broadcast). `factory_verify_all` (`factory.c:2107`) exists but is called only
   from tests/tools, never `src/`.
2. Therefore bounded retry on factory-creation and coop-close **requires first
   adding a ceremony-time detection point** (aggregate verify). This is also an
   independent robustness win: fail fast + fall back cleanly rather than ship a
   dud tx.
3. Reusable scaffolding already present (unused in prod): `ceremony_prepare_retry()`
   (`ceremony.c:79`); the proven all-local retry loop
   (`tools/superscalar_lsp_pre_daemon_tests.inc:437`); and the rotation
   attempt-counter + backoff (`lsp_rotation.c:33-68`).

## Retry policy

- `SS_NONCE_RETRY_MAX` attempts (default 3) per ceremony, then abort+escalate.
- Each attempt: full nonce-gen → exchange → psig → aggregate → **verify** round.
- Detection = verify the aggregate Schnorr sig (or per-signer where already done).
- Transient fault (corruption, flaky peer that recovers) → retry succeeds.
  Persistent fault (a signer that keeps sending bad psigs / stays absent) → the
  bound is reached and we escalate; retry never masks a real fault.
- N-of-N ceremonies (factory root/intermediate nodes): one bad/absent signer is
  fatal — retries give transient-recovery chances, then proactive-exit. Quorum
  ceremonies (coop-close): retry, and on the final attempt the existing
  quorum/timeout exclusion (`ceremony_prepare_retry`) drops the faulty signer.

## Per-ceremony plan (phases; each = a tested, reviewable increment)

- **Phase A — reusable primitive + all-local path.** Lift the proven inc:437
  loop into `factory_sign_all_with_retry()` (library) and call it at every
  `factory_sign_all` site. Unit test: a verify-fail-then-retry-succeeds via fault
  injection. Lowest risk.
- **Phase B — detection.** Add ceremony-time aggregate verify to networked
  factory-creation (`factory_verify_all` after `factory_sessions_complete`,
  `lsp.c`) and coop-close (final-sig verify after aggregate, `lsp.c:~1174`). No
  retry yet; abort-on-fail as today. Standalone verify-before-broadcast win.
- **Phase C — coop-close bounded retry.** Wrap `lsp_run_cooperative_close`
  (`lsp.c:890-1206`) in the bounded loop; reuse `ceremony_prepare_retry` on the
  existing `close_*_cer` ceremony objects; re-run PROPOSE→NONCE→PSIG; escalate on
  exhaustion. Highest production liveness value (avoids a needless force-close).
- **Phase D — factory-creation bounded retry.** Wrap
  `lsp_run_factory_creation_stateless`; loop back to client-nonce request on
  verify-fail; `ceremony_prepare_retry`; escalate on exhaustion.
- **Phase E — leaf / sub-factory / rollover.** These already return "retry next
  tick" and are re-invoked by the daemon loop; add a **bounded attempt counter at
  the daemon call site** (mirroring `lsp_rotation_should_retry`) with proactive
  exit on exhaustion, plus an inner nonce-regen retry where cheap.

## Testing

- Unit: fault-injected verify-fail → retry → success (Phase A; and a unit-level
  ceremony harness where feasible).
- Regtest: the networked ceremonies (B–E) under a transient-fault cheat
  (`SS_CHEAT_*`, regtest-only, refused on mainnet per the cheat-guard) that
  corrupts one psig on attempt 1 only → assert the ceremony RETRIES and
  SUCCEEDS, and that a persistent corruption hits the bound and escalates
  (asserts `CEREMONY_ABORT_RETRY_LIMIT_REACHED` + proactive exit, not blind wait).
- No nonce-reuse: assert (in the retry harness) that each attempt's pubnonce
  differs from the prior attempt's.

## Open items / follow-ups

- Pool exhaustion handling on retry for the two pool paths.
- Mainnet guard on any new fault-injection cheat (reuse `superscalar_cheat_allowed`).
- Self-reviewed; flag for the external audit (P8).
