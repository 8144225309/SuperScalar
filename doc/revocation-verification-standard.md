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
