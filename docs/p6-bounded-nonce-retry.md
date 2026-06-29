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

## Status + C/D two-sided-retry protocol design (2026-06-28)

PROGRESS:
- Phase A (all-local sign retry): DONE, green (#407).
- Phase B (ceremony-time detection, factory-creation + coop-close): DONE, green
  (both regtest jobs pass -> the new verifies do not false-fail a valid ceremony).
- P6 DoD core was ALREADY MET pre-#48: the rotation/rollover "stalled advance"
  does bounded-retry -> proactive-exit (lsp_channels.c:7240-7305 -
  lsp_rotation_should_retry up to 3x, then distribution-TX exit +
  CEREMONY_ABORT_RETRY_LIMIT_REACHED + "ensure your watchtower is live" NOTICE).
- User chose "go all the way" -> implement the C/D two-sided retry below.

C/D TWO-SIDED RETRY PROTOCOL (no new wire message; the retry signal is a re-sent
CLOSE_PROPOSE / re-sent factory nonce-request -- the client distinguishes it from
CLOSE_DONE/FACTORY_READY):
- LSP coop-close (lsp_run_cooperative_close): wrap session-init -> LSP nonce ->
  CLOSE_PROPOSE -> collect CLOSE_NONCE -> ALL_NONCES -> finalize -> LSP psig ->
  collect CLOSE_PSIG -> aggregate -> verify in a `for (attempt < SS_NONCE_RETRY_MAX)`
  loop. The close OUTPUTS + sighash are built once (unchanged across attempts);
  only nonces/psigs are fresh. On verify/aggregate fail: ceremony_prepare_retry on
  close_nonce_cer/close_psig_cer, re-init the musig session + fresh LSP nonce, loop
  (re-send CLOSE_PROPOSE). On success: break -> CLOSE_DONE. On exhaustion:
  close_fail + the CEREMONY_ABORT_RETRY_LIMIT_REACHED NOTICE (mirror rotation).
- Client (client_do_close_ceremony): wrap NONCE->PSIG->wait in a loop; after
  sending CLOSE_PSIG, branch on the next msg -- CLOSE_DONE -> success;
  CLOSE_PROPOSE (same outputs) -> retry with a fresh nonce; CEREMONY_ABORT ->
  fail. Bounded by the same max so a wedged peer can't loop forever.
- D (factory-creation): analogous -- LSP re-runs the client nonce-request on a
  factory_verify_all fail; client re-enters the nonce/psig round.
- Fault injection (regtest-only via superscalar_cheat_allowed; refused on mainnet
  per the cheat-guard): SS_CHEAT_CLOSE_BAD_PSIG / SS_CHEAT_CREATE_BAD_PSIG -> a
  client emits a corrupt psig on attempt 1 only (transient) or every attempt
  (persistent).
- Tests (before/after each step): normal ceremony stays green (no regression --
  Phase B's passing regtest is the guard) + transient -> retry -> success +
  persistent -> bounded abort + proactive-exit NOTICE + a pubnonce-differs check.
RISK: this restructures the working close/creation ceremonies. Mitigation: keep
the OUTPUTS/sighash build outside the loop (only re-randomise nonces); run the
normal-path regtest before and after every commit.

## Phase C + D RESULTS (2026-06-29) -- DONE + PROVEN on regtest

**Phase C (coop-close)** -- two-sided protocol as designed. The LSP returns a
distinct "retryable" code (no abort, no client disconnect) on a ceremony-time
verify-fail; the daemon caller loops it bounded; `client_do_close_ceremony`
recurses on a re-sent CLOSE_PROPOSE. Cheat-proof `tools/test_regtest_close_retry.sh`:
=1 (transient) -> close RETRIES + the full lifecycle SUCCEEDS; =2 (persistent) ->
close BOUNDS + aborts -> clients fall back to force-close. CLOSE_RETRY_TEST PASS.

**Phase D (factory-creation)** -- implemented as a BUILD-ONCE INTERNAL LOOP, NOT
the "caller re-invokes" sketch above. Rationale discovered during impl: the LSP
re-invoke path rebuilds the whole tree (`factory_init_from_pubkeys` memsets f) and
re-sends FACTORY_PROPOSE, and the old `fail_pre`'s `factory_free` is what silently
broke the pre-existing 3x creation retry (config lost + clients disconnected). The
clean design: build the tree + FACTORY_PROPOSE ONCE, then loop ONLY the signing
rounds in `lsp_run_factory_creation_stateless` -- `factory_sessions_init`
(re-callable; inline session structs; leak-free) -> PROPOSE_INTENT -> client
pubnonces -> LSP nonces / LSP_RESPONSE -> client psigs -> `factory_sessions_complete`
-> `factory_verify_all`. On verify-fail: re-init sessions + re-send PROPOSE_INTENT
(NO abort, NO factory_free), up to SS_NONCE_RETRY_MAX, then `fail_pre`. Every
per-round buffer (all_pn / lsp_* / client_*) is freed before the verify point, so
the retry path is leak-free. The client mirrors it: build once, then a bounded loop
calling `client_factory_creation_stateless_signing` with a new `intent_already_recvd`
param so a retry (which already consumed the re-sent PROPOSE_INTENT to detect it)
does not double-recv; on FACTORY_READY it applies + breaks, so the shared legacy
FACTORY_READY recv is skipped for the stateless path. Cheat-proof
`tools/test_regtest_create_retry.sh`: =1 (transient) -> creation RETRIES (2x) +
lifecycle SUCCEEDS; =2 (persistent) -> creation BOUNDS + aborts before broadcast
(nothing committed on-chain -> fallback is re-create). CREATE_RETRY_TEST PASS.

**Test-design finding (flaky cheat, fixed 6dbb82b):** the creation cheat must
corrupt EXACTLY ONE client. If every client XORs the low bit of its OWN node-0
partial, the per-signer +-1 deltas can sum to zero in the MuSig2 aggregate
(`s_agg = sum of partials`) ~37% of runs -> a VALID aggregate -> no failure to
detect -> flaky no-op. A single bad partial cannot cancel; gated to my_index==1.

**Regression (no-cutting-corners):** `client_factory_creation_stateless_signing`
is shared with the rotation re-entry path (client.c, `rot_stateless`), which passes
`intent_already_recvd=0` -> byte-identical to pre-#48 behavior (the new retry loop
lives only in the initial-creation caller). Confirmed e2e by
`test_regtest_rotation_restart_resume.sh` + a clean `test_regtest_n64_payments.sh`
+ the unit suite, all green on the integrated branch.

## Open items / follow-ups

- Pool exhaustion handling on retry for the two pool paths.
- Mainnet guard on any new fault-injection cheat (reuse `superscalar_cheat_allowed`).
- Self-reviewed; flag for the external audit (P8).
