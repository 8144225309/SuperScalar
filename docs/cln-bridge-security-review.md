# CLN-bridge security review — signoff (task #330 / #5)

Scope: the `superscalar_bridge` daemon (`tools/superscalar_bridge.c`, `src/bridge.c`)
and the LSP-side bridge handling (`src/lsp_bridge.c`).  The bridge relays
BOLT-2 HTLCs between an external CLN node and the SuperScalar LSP over a Noise
transport.

Reviewed 2026-06-27 against the current code (post #9/#54 merges).

## Finding 1 — bridge↔LSP transport was not secure-by-default — FIXED

**Was:** without `--lsp-pubkey`, `src/bridge.c:62-68` silently fell back to the
**unauthenticated NN** Noise handshake (MITM-exposed) with only a `WARNING`.
The runbook says the bridge MUST use `--lsp-pubkey`, but it was not enforced —
a misconfigured production bridge would run unauthenticated.

**Fix (this PR):** `superscalar_bridge` now **refuses to start without
`--lsp-pubkey`** (authenticated NK) unless the operator explicitly passes the
new `--insecure-no-auth` flag (testing only).  Mirrors the secure-by-default
mainnet guards (#327a refuse-cmdline-seckey, #9 refuse-cheat-flags).  A CI step
(`CLN-bridge secure-by-default`) asserts the refusal + message.

## Finding 2 — LSP does not authenticate the bridge — SCOPED (low severity)

**Observation:** `src/lsp_bridge.c:581` (`MSG_BRIDGE_HELLO`) replies `HELLO_ACK`
without pinning/verifying the bridge's identity.  The LSP's responder handshake
is NK (it authenticates the LSP *to* the bridge, not the bridge to the LSP) or
NN, and `BRIDGE_HELLO` carries a cleartext (post-Noise) `bridge_pubkey` that is
not proof-of-possession.  So any peer that completes the handshake can claim to
be the bridge and submit `MSG_BRIDGE_ADD_HTLC`.

**Severity: low**, bounded by existing mitigations:
- the bridge port is normally **localhost-only** (bridge runs on the LSP host;
  the runbook firewall section keeps it off the public interface);
- **#10** already validates every bridge-relayed HTLC's provenance
  (payment_hash / cltv / funding-depth), so a rogue bridge cannot forge
  arbitrary HTLCs — it can only relay what passes provenance checks.

**Proper fix (follow-on, not this PR):** mutual auth = Noise **KK** (the bridge's
static key authenticated *in* the handshake) + an LSP-side `--bridge-pubkey`
pin that rejects unknown bridges.  This is a transport-protocol change worth
doing for defense-in-depth, but it is not a standalone theft vector given the
localhost + #10 mitigations.  Tracked as a follow-on.

## Finding 3 — bridge-relayed HTLC input validation — REVIEWED, no new gap

`src/lsp_bridge.c:104+` (`MSG_BRIDGE_ADD_HTLC`) already rejects malformed /
unauthorized HTLCs along many paths (`MSG_BRIDGE_FAIL_HTLC` at 138/148/159/169/
188/218/309), and **#10** added payment_hash/cltv provenance + LSP funding-depth
checks.  No new validation gap found in this review.

## Signoff

Finding 1 (the only one that left the production bridge unauthenticated by
default) is **closed**.  Finding 2 is a **low-severity defense-in-depth
follow-on** (mutual KK auth) with the rogue-bridge vector already bounded by
localhost + #10.  Finding 3 is **already covered** by #10.  The bridge is signed
off for v0.2.0 with Finding 2 documented as a tracked follow-on.
