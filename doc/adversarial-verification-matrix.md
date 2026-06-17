# Adversarial Verification Matrix

**Branch:** `fix/adversarial-verification` (stacked on the revocation-verification PR).
**Principle:** a fail-closed fund-safety check is only *proven* by feeding it a
valid-LOOKING but WRONG input and watching it reject. These negative tests are the
auditor-grade evidence that user / LSP / watchtower reject realistic forgeries
everywhere, and they are regression tripwires if a check is ever weakened to
fail-open.

## The matrix (forgery → expected rejection → proof)

| Verifier | "Looks real but isn't" | Expect | Proven by |
|---|---|---|---|
| MuSig keyagg substitution | [A,B] sig verified under substituted keyagg[A,C] | reject | `test_adversarial_keyagg_substitution` ✅ |
| Final aggregate sig tamper | any single flipped byte | reject | `test_adversarial_final_sig_tamper` ✅ |
| Message binding | valid sig vs a different message | reject | `test_adversarial_wrong_message_binding` ✅ |
| Preimage (fulfill) | 32B preimage, `SHA256≠hash` | reject | `test_channel.c` (wrong preimage) ✅ |
| HTLC CLTV range | expiry ≤ delta | reject | `test_channels.c` ✅ |
| Nonce reuse | second draw of a consumed nonce | refused | `test_musig.c` (pool exhaustion) ✅ |
| Partial-sig tamper | flipped byte in a partial sig | reject | `test_musig.c` ✅ |
| Peer auth wrong key | NK handshake with wrong pinned pubkey | handshake fails | `test_channels.c` (`test_noise_nk_wrong_pubkey`) ✅ |
| Revocation secret | valid scalar, ≠ committed PCP | reject, not stored | `test_persist.c` (`failclosed` + `client_verifies_lsp_revocation`) ✅ |
| Client rejects bad LSP `0x50` | valid-looking but wrong LSP revocation | refuse, no WT-arm | `test_persist.c` (`test_client_verifies_lsp_revocation`) ✅ |
| Cheat gate | `SS_CHEAT_*` set, network≠regtest | inert | `test_persist.c` (`test_cheat_gate`) ✅ |
| **WT false-positive** | revoked commitment NOT on-chain | no penalty (non-vacuous: WT did query chain) | `test_client_watchtower.c` (`test_adversarial_wt_no_false_penalty`) ✅ |
| **Reconnect stale-claim** | LSP `RECONNECT_ACK` claims a different commitment number | keep own DB state + loud SECURITY alert | code `client_reconnect.c` + reconnect suite green; dedicated drill ⏳ |
| Item-1 live (routed payment) | cheating LSP forges every `0x50` mid-payment (`SS_CHEAT_LSP_BAD_REVOCATION`) | client refuses all, no WT-arm | **live regtest drill ✅** — N=4 daemon payment harness: LSP forged 24 revocations → clients refused **24/24** fail-closed (two ways: point-mismatch, then "no retrievable committed point" once the PCP chain breaks); happy-path control = **0** false-rejects + full settlement |

## Phases
- **Phase 1 — unit forgery suite** (`tests/test_adversarial_verify.c`): keyagg
  substitution, final-sig tamper, message binding. ✅ green (3/3).
- **Phase 2 — WT false-positive** (chain-backend mock): the watchtower broadcasts a
  penalty ONLY when its registered revoked commitment is actually on-chain; proven
  non-vacuous (it queries the chain, finds the commitment absent, refuses). ✅ (4/4).
- **Phase 3 — reconnect stale-claim alert**: the client never adopts the LSP's
  `RECONNECT_ACK` commitment claim; keeps its own persisted state (fund-safe) and
  raises a SECURITY alert (AHEAD = forged/stale injection, BEHIND = replay). ✅
  (reconnect 13/13).
- **Phase 4 — item-1 routed-payment drill** ✅: overcome by building an
  integration tree that stacks the #380 routed-payment harness + #381 revocation
  verification + #382 adversarial work (`integration/security-e2e`), then running
  the daemon `--send`/`--recv` payment harness (`test_regtest_n64_payments.sh`) on
  regtest at N=4 with two configs:
    - **happy-path control** (no cheat): payments settle end-to-end, cooperative
      close confirmed on-chain, sats conserved to the sat, LSP wt.db armed (24
      kind=2 watches), standalone secret-less WT hydrated all 24, and **0**
      client revocation rejections — legit `0x50`s VERIFY and are accepted.
    - **adversarial** (`SS_CHEAT_LSP_BAD_REVOCATION=1`, regtest-gated): the LSP
      forged all 24 revocations (`LSP-CHEAT-BADREV` ×24); every client refused
      every one (`INVALID LSP revocation secret` / `refusing (penalty NOT armed)`
      ×24) fail-closed and armed no watchtower from a forgery.
  Production path = `client_recv_lsp_revocation` → `client_handle_lsp_revoke_and_ack`
  (the harness clients run the daemon loop even under `--send`/`--recv`). The
  legacy bare-`--channels` consume (`scripted_consume_lsp_revoke`) was also
  hardened to verify (defense-in-depth; it previously stored blindly).
- **Phase 4 follow-up — detect → ESCALATE** ⏳ (open hardening): the client
  correctly DETECTS + REFUSES a cheating LSP's forged revocation, but currently
  CONTINUES the session (payments still settle). A client that cannot obtain a
  valid LSP revocation holds an un-penalizable old LSP state; the fund-safe
  response is to halt + cooperatively/force-close on the last fully-verified
  state rather than keep building states it cannot protect. Detection is wired;
  response is the next layer. Tracked.
- **Phase 5 — PTLC adaptor pre-sig + HTLC provenance** ⏳: PTLC (off-by-default)
  already verifies the turnover binding (#196); a cryptographic adaptor-pre-sig
  verify needs an adaptor-verify primitive. Client receiver-side HTLC invoice
  provenance is defense-in-depth (fulfill already requires the preimage). Tracked.

## Release gate + audit
`tests/test_adversarial_verify.c` runs in the unit suite. The matrix is cited in the
external audit package as the evidence that every fund-safety verifier has a
negative test that proves it fail-closes.
