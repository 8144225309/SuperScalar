# Revocation Verification Standard

**Status:** design → implementation (branch `fix/revocation-verify-standard`)
**Class:** fund-safety correctness (BOLT-2 conformance)
**Origin:** present since the repo root commit `a1b5e0f` (2026-05-16) — an original design gap, not a regression.

## 1. The principle

> Every piece of counterparty-supplied secret material that gates fund safety MUST
> be cryptographically verified, at a single choke point, against durable state,
> BEFORE it is trusted or stored. Unverifiable material is rejected and the channel
> is treated as breached. "Don't trust — verify" is an enforced invariant, not a
> per-call-site convention.

## 2. The problem this fixes

Counterparty **revocation secrets** (per-commitment secrets revealed in `revoke_and_ack`)
are accepted and stored through several paths with inconsistent verification:

| Path | Today |
|---|---|
| `lsp_channels.c` payment handlers (961/1240/5355) | verify, but **fail OPEN** when the committed PCP isn't in the 2-slot window |
| `htlc_commit.c` BOLT-2 handler (153/665) | **no verification** — stores `peer_pcs` straight off the wire |
| `client.c` LSP-revoke handler (`0x50`) | **no verification** (the user's side of trustlessness) |

A wrong/garbage secret that is stored arms the watchtower's penalty with a bad key
(`channel_build_penalty_tx` is built from the stored secret; nothing re-verifies it at
breach time). Result: when the counterparty later broadcasts that revoked state, the
penalty TX is invalid → **the breach is unpunishable → the honest party loses the
clawback.** This breaks the trustless guarantee in BOTH directions; the client side is
the more important half because the user is exposed to the LSP.

## 3. What the spec requires

- **BOLT-2** (`revoke_and_ack`): the receiver MUST check the `per_commitment_secret`
  generates the expected `per_commitment_point`; on mismatch the channel SHOULD/MAY
  fail. There is no "accept on trust."
- **BOLT-3**: received per-commitment secrets are stored compactly in a **shachain**
  (O(log N)), inserted in order with a built-in consistency check.

SuperScalar uses `shachain_from_seed` only to GENERATE its own secrets; received
secrets go into a fixed 512-entry flat array + a lossy 2-slot remote-PCP window, with
verification bolted onto some call sites and absent from others.

## 4. Root cause

Verification lives at *call sites* and depends on *lossy in-memory state* (the 2-slot
PCP window evicts old commitments). When the committed point isn't in the window, the
code cannot verify, and chose to ACCEPT rather than REJECT. The durable `remote_pcps`
table exists but (a) is written at revoke time, not commitment creation, and (b) is
never consulted by the verifier.

## 5. The design

Move verification to the **storage choke point**, back it with **durable** state, make
it **fail-closed**, and make it **symmetric**.

1. **One shared verifier.** Promote `verify_revocation_secret` out of `lsp_channels.c`
   (static) into `channel.c` as public `channel_verify_revocation_secret(ch, cn, secret)`,
   used by LSP and client alike.
2. **Durable committed-PCP.** Persist the remote PCP at **commitment creation**, and have
   `channel_get_remote_pcp` fall back to `persist_load_remote_pcp(ch->persist_db, …)` when
   the in-memory window misses. The committed point is then always retrievable for the
   life of a revocable commitment.
3. **Verify at the choke point.** `channel_receive_revocation[_flat]` verifies internally
   and returns failure if the secret can't be verified — so NO path (htlc_commit, lsp
   handlers, client, bridge) can store an unverified secret. Callers must handle failure.
4. **Fail closed.** On mismatch or genuinely-missing committed point, reject and fail the
   channel (BOLT-2). Never store-on-trust.
5. **Symmetric.** Because the choke point is shared `channel.c`, both the LSP verifying the
   client and the client verifying the LSP are covered by the same code.
6. **Completeness guard.** A test asserts the verifier is the only way secrets enter
   storage (no direct flat-array writes bypass it), so the standard cannot silently
   regress.
7. **(Optional, deferred) BOLT-3 shachain receiver storage** to replace the 512-flat-array
   with compact, uncapped, self-consistent storage. Separable from the correctness fix.

### Safety: detect-then-enforce
Because this is payment-hot and some paths verify nothing today, flipping straight to
strict could surface a latent ordering bug and halt payments. Within this PR we prove
correctness with tests rather than a production soak: legitimate flows (incl.
restart-then-revoke) verify and pass; injected garbage secrets are rejected in both
directions; the penalty/breach matrix stays green. A loud log remains on the
(now-should-be-unreachable) reject path as a tripwire.

## 6. Phases

- **Phase 1 — Durable shared verifier (no enforcement change).** Move verifier to
  `channel.c`; persist committed PCP at creation; `get_remote_pcp` consults the DB.
  Unit tests for verify match/mismatch + durable lookup. Build green.
- **Phase 2 — Centralize + fail-closed.** Verification moves INTO
  `channel_receive_revocation[_flat]`; callers fail-close on failure; accept-on-trust →
  reject. Unit tests for reject-on-mismatch/missing.
- **Phase 3 — Symmetric + integration.** Confirm/route the client path through the
  verifying choke point. Regtest drills: payment happy path, restart-then-revoke,
  cheating-client garbage secret rejected, cheating-LSP garbage rejected client-side;
  penalty/breach matrix green.
- **Phase 4 — (optional) shachain receiver storage.** Deferrable follow-up.
- **Phase 5 — PR.** This doc + tests + completeness guard; open PR vs `main`.

## 7. Before / after (plain terms)

**Before:** the other side says "here's the secret that retires our old state," and we
mostly take their word for it — and in some paths don't check at all. A bogus secret gets
filed away; if they later cheat by publishing that old state, our punishment is built from
the bogus secret and bounces — they keep money they shouldn't.

**After:** every revocation secret — us checking the client, the client checking us — is
mathematically verified against the exact state it claims to retire, using a record
written durably to disk. If it doesn't verify, we refuse it and treat the channel as
breached. A valid punishment can always be built; neither side can cheat the other.

## 8. All three actors must verify at every step

The shared verifier (`channel_verify_revocation_secret` in `channel.c`) + the choke point
(`channel_receive_revocation_flat`) give **all three actors the capability** to verify.
Status of each, as of this branch:

| Step | LSP | Client (user) | Watchtower |
|---|---|---|---|
| Counterparty commitment signature | ✅ | ✅ `channel_verify_and_aggregate_commitment_sig` | n/a (pre-signed) |
| **Counterparty revocation secret** | ✅ Phase 2, fail-closed | ✅ `client_handle_lsp_revoke_and_ack` — verifies `0x50` fail-closed + tracks the LSP's next PCP; on a detected forgery applies the **escalation policy** (§9) | ✅ transitive — only ever reads secrets verified at store time; hydrate uses pre-signed penalty TXs, never raw secrets |
| Funding on-chain | gated | warn + hard-gated on prod (#197) | (uses pre-signed) |
| Ceremony / MuSig | ✅ | ✅ (participates) | n/a |

**LSP — done.** Verifies client revocations at the choke point, fail-closed (Phases 1–2,
tested green).

**Watchtower — covered (transitive), no change needed.** Post-Phase-2 every secret in
`received_revocations` was verified when stored; the standalone WT hydrate path
(`wt_hydrate_row_cb`) loads pre-signed penalty TXs, so it never trusts a raw, unverified
secret. (A belt-and-suspenders verify-on-ingest is a possible hardening, not a gap.)

**Client — closed.** `client_handle_lsp_revoke_and_ack` now verifies the LSP's `0x50`
fail-closed (`secret*G == committed PCP`), stores the secret only on success, and tracks the
LSP's *next* per-commitment point so the chain stays verifiable past cn 0/1. Wired into the
production daemon loop (`client_recv_lsp_revocation`) and the legacy bare-`--channels`
consume. Proven live: an honest LSP's revocations are accepted (0 false-rejects across a
routed-payment drill); a cheating LSP that forges every `0x50` is refused 24/24 fail-closed
with no watchtower armed from a forgery (see `doc/adversarial-verification-matrix.md`). The
client can now itself detect an LSP breach attempt at the revocation step — and respond to
it per the policy in §9.

### Client implementation plan (focused next piece)
1. Add `client_handle_lsp_revoke_and_ack(ch, ctx, msg)` mirroring the LSP handler:
   parse → `channel_verify_revocation_secret(ch, cn-1, secret)` → on fail, reject + fail the
   channel (BOLT-2) → `channel_receive_revocation` (store) → set the LSP's next per-commitment
   point from the message (enabling ongoing tracking; the message already carries it — the
   client currently throws it away).
2. **Map the client's real payment commitment flow first.** `client_handle_commitment_signed`
   is only called on reconnect (`client_reconnect.c:327`); the normal path is LSP-driven and
   multi-loop, and `0x50` is intentionally skipped in the setup/ceremony loops. The handler
   must be wired into the actual payment exchange, not the setup loops — this needs the client
   message architecture mapped before touching it (delicate; mis-wiring risks breaking
   payments).
3. Tests: client rejects a garbage LSP revocation (fail-closed) and retains/verifies a correct
   one across many commitments; existing client/reconnect suites stay green.
4. Design note: the client retaining LSP revocations enables self-detection; whether it
   self-penalizes or hands secrets to its watchtower is a separate (existing) concern.

## 9. Detection → Response: the escalation policy (`--on-lsp-forgery`)

Verification (§5–§8) tells the client *that* the LSP forged a revocation. It does **not**
by itself decide what to do next. Detection is necessary but not sufficient: a client that
cannot obtain a *valid* LSP revocation is holding an **un-penalizable old LSP state** — if
the LSP later broadcasts that revoked state, the client cannot build a valid penalty and is
exposed (the receiver of a payment is most exposed, having gained balance). So continuing to
build new states the client cannot protect is the riskiest choice.

The client exposes a selectable response, applied at the detection point
(`client_recv_lsp_revocation` → on a fail-closed verify), via `--on-lsp-forgery MODE`:

| Mode | Behaviour on a detected forged `0x50` | When to use |
|---|---|---|
| `continue` | Refuse the bad secret, arm no watchtower from it, **keep the session** (legacy). | Testing / maximum tolerance; leaves the exposure open. |
| `halt` (**default**) | Refuse + **stop accepting further commitments** + CRITICAL alert + do not reconnect to the proven-cheating LSP. No on-chain action. | Default: stops the exposure without surprise on-chain spends; operator decides whether to close. |
| `close` | `halt` + **force-close on the last fully-verified state** (reuses the #313 self-custody `factory_recovery_run` from the persisted DB + broadcasts the last signed commitment). | Maximum fund-safety; accepts the on-chain cost. |

In **every** mode the forged secret is refused and no watchtower is armed from it — the modes
differ only in what happens *after* detection. The default is `halt`, **not** the legacy
`continue`: it only ever triggers on a genuinely detected forgery (an honest LSP's
revocations verify — proven by 0 false-rejects on the happy-path drill), so honest operation
is unaffected while the exposure is closed by default.

**Wiring.** `lsp_forgery_response_t` enum + `client_parse_forgery_response` (`src/client.c`,
unit-tested by `test_lsp_forgery_response_parse`); `daemon_cb_data_t` carries the policy +
`lsp_forgery_detected` + `force_close_requested`; the daemon loop breaks on detection (both
the `--daemon` and scripted `--send`/`--recv` paths); `client_force_close_from_db` performs
the `close`-mode recovery after the loop.

**PS-leaf-type nuance.** Pseudo-Spilman (PS) leaves are **CLTV-gated**, not revocation-gated,
so a forged LSP revocation is *less* severe on a PS leaf (funds are protected by the timeout,
not by the ability to penalize) than on a revocation-gated leaf. The policy is applied
**uniformly** today; a per-leaf-type response (e.g. tolerate on PS, force-close on
revocation-gated) is a possible future refinement, not a current gap.

**Live evidence (regtest, N=4 daemon payment harness; `ON_LSP_FORGERY` selects the mode):**

| Drill | Config | Observed |
|---|---|---|
| happy-path control | no cheat, default (`halt`) | **PASS** — payments settle e2e, cooperative close confirmed on-chain, sats conserved; **0** forgery refusals, **0** halts (an honest LSP never trips the policy — the default is safe) |
| `continue` | cheat + `continue` | **24/24** forged `0x50` refused fail-closed; session continues; payments still settle (legacy behaviour, exposure left open) |
| `halt` (default) | cheat + `halt` | clients refuse the forgery, log `CRITICAL`, and **halt the daemon loop (4/4 clients)** without reconnecting — no further commitments accepted, no on-chain action |
| `close` | cheat + `close` | clients refuse + **force-close on the last verified state (4/4 clients)** via the #313 self-custody `factory_recovery_run` — `CLOSE policy force-close: factory 0 (state=active): broadcast 3 TXs (run=1)` |

The refusal counts differ by design: `continue` processes all 24 forged revocations (it never stops), while `halt`/`close` stop at the first detection (≈1 per client) — both refuse every forgery they see, fail-closed, before acting.

### 9.1 Refinements

- **Config-file** — `on-lsp-forgery` (and `on-lsp-forgery-ps`) are honoured in the
  JSON `--config` file; CLI overrides config.
- **Poisoned-LSP marker** — on a `halt`/`close` detection the client writes a
  sentinel (`<db>.lsp_poisoned`) and, on a later start, **refuses to reconnect** to
  the proven-cheating LSP. `--force-close` still works (it is handled before the
  connect path); deleting the marker re-enables connecting. (File sentinel — no
  schema change.)
- **Per-leaf-type response (`--on-lsp-forgery-ps`)** — PS leaves are CLTV-gated, so a
  forged revocation *may* be less severe than on a revocation-gated leaf. The client
  **detects + reports** the leaf type in the alert and lets an operator set a
  *separate* PS-leaf policy. **It defaults to "inherit" (uniform) and never
  auto-downgrades** — PS leaf *chaining* does not by itself prove the channel-level
  revocation is non-load-bearing. **Open security-model question:** confirm whether a
  PS leaf's channel commitments still depend on revocation before recommending a more
  lenient PS policy; until then the safe default is to respond uniformly (over-respond
  rather than under-respond).
- **Surgical close** — already per-client: `close` runs `factory_recovery_run` for the
  client's *own* factory + broadcasts only the client's *own* signed commitment. The
  shared tree nodes (root/intermediates) are architecturally required to reach any
  leaf; a client never publishes another client's leaf commitment. So the close is as
  surgical as the factory construction allows.
