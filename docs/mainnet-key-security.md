# Mainnet key-handling architecture

**Status:** Planned. Tracked as umbrella task **#242**.
**Date:** 2026-05-19
**Owner:** SuperScalar core
**Audience:** internal team; external Bitcoin/LN reviewer when #152 audit is commissioned.

---

## 1. Problem

SuperScalar is a library + plugin that integrates with the user's existing Lightning Network node (CLN initially; lnd/eclair/LDK later). Users will bring their own LN node, which already manages a master seed and per-channel keys via its own HSM daemon. SuperScalar must:

1. Receive only what it needs from the user's node, via a well-defined plugin interface.
2. Never duplicate, derive, or otherwise touch the user's master seed material.
3. Persist library state (channel metadata, signed TXs, counterparty revocation receipts) in a way that fits into the user's existing backup workflow.
4. Avoid every key-handling anti-pattern an experienced Bitcoin/LN cryptographer would flag.

The objective is to make SuperScalar's mainnet posture indistinguishable in security profile from CLN itself for the same tier of operators — so that a user who already trusts CLN with their funds can extend that trust to SuperScalar without additional risk surface.

---

## 2. Layered architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                  User's LN node (CLN today; lnd/eclair later)      │
│                                                                    │
│   hsmd (isolated process)                                          │
│   ├── holds hsm_secret = master seed (one file, mode 600)          │
│   ├── BIP32-derives every key on demand                            │
│   └── signs TXs / proves possession of keys                        │
│                                                                    │
│   lightningd / hsmd peer plumbing                                  │
│   ├── tracks vanilla LN channel state                              │
│   └── exposes hooks (db_write, custom-msg, RPC) to plugins         │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │
                  plugin protocol (RPC, never raw seed)
                                   │
┌──────────────────────────────────┴─────────────────────────────────┐
│        SuperScalar plugin (lives inside the user's LN node)        │
│                                                                    │
│   ├── owns the SuperScalar-specific DB                             │
│   ├── translates wire protocol <-> library API                     │
│   ├── ASKS the user's hsmd for HD-derived keys + signatures        │
│   ├── INJECTS results into the SuperScalar library                 │
│   └── PARTICIPATES in the node's backup hooks                      │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │
                  library API (in-process calls)
                                   │
┌──────────────────────────────────┴─────────────────────────────────┐
│         SuperScalar library (this repo)                            │
│                                                                    │
│   ├── stateful crypto-ceremony engine                              │
│   ├── orchestrates MuSig2 factory + sub-factory + leaf ceremonies  │
│   ├── persists state required to operate (see §4)                  │
│   └── never holds the operator's master seed                       │
└────────────────────────────────────────────────────────────────────┘
```

**Principle:** the library is a ceremony engine, not a keystore. The plugin is the bridge between the user's node and the library. The user's node is the sole owner of seed material.

---

## 3. Reference baseline — CLN's hobbyist-tier security model

The bar we are matching is what every CLN-based LN routing node ships with today:

| Feature | Effect |
|---|---|
| `hsmd` process isolation | Raw seed never leaves a dedicated daemon. |
| `hsm_secret` master seed | One BIP32 master; mnemonic backup recovers everything. |
| Default file ACLs (mode 600) | Filesystem-level protection from non-root users. |
| `db_write` hooks for backups | Backup plugins replicate state via a standard interface. |
| Optional `hsm-password` | At-rest encryption of `hsm_secret` (operator choice). |
| PSBT-based signing flow | Validation surface — hsmd inspects what it's asked to sign. |

We are not trying to exceed this for v0.x mainnet. Higher tiers (HSM hardware, VLS policy enforcement, hsmd-mediated MuSig2) are tracked as v1.x work but not gate-blocking.

---

## 4. SuperScalar DB content — what is persisted and why

### Persisted (required for correctness)

- Channel metadata: amounts, CLTVs, indices, peer ids.
- Counterparty pubkeys (funding, basepoints, per-commitment points).
- Counterparty revocation secrets received at each state update (required to broadcast penalty on breach).
- Signed commitment TXs (raw hex, both sides).
- Signed sweep TXs (post-CSV recovery).
- Signed penalty TXs (pre-signed; the watchtower broadcasts on breach).
- Distribution TX hex (multi-channel coordination).
- Per-commitment shachain (compressed encoding of our revocation secrets sent to counterparty).
- Counterparty pubnonces during in-flight ceremonies.
- Our partial sigs (post-aggregation).

### Not persisted (security)

- The operator's master seed (`hsm_secret`) — lives in the user's node, never enters the library.
- MuSig2 secnonces — RAM-only; crash mid-ceremony triggers a clean restart.
- Any per-signing one-time material between sign() and broadcast.

### HD-derived per channel (recoverable from seed)

- Per-factory funding seckey (LSP side of MuSig keyagg).
- Per-channel basepoint secrets (revocation, payment, delayed payment, htlc).

### Per-channel ephemeral, regenerated on use

- MuSig2 secnonces for active ceremonies (held in RAM only).
- Per-commitment delayed payment derivations (standard LN technique).

---

## 5. Plugin contract — what the library asks the plugin to provide

The library exposes a small set of callbacks that the plugin implements. The plugin is the only component that talks to the user's node. The library never touches the node's hsmd directly.

The callbacks fall into four categories:

1. **Key derivation** — given a channel/factory index, return HD-derived basepoint or funding secrets. The plugin implementation calls into the user's hsmd.
2. **Signing requests** — given a message hash + signing role, return a signature. The plugin implementation routes to hsmd or signs locally with HD-derived material.
3. **Nonce generation** — given a ceremony context, return a MuSig2 secnonce/pubnonce pair derived deterministically per BIP-327.
4. **Backup hook subscription** — register a callback that fires on every library DB write. The plugin implementation forwards to the node's existing backup pipeline.

The exact RPC schema for these callbacks (message format, error codes, versioning) is part of the planned work — see §7.

The standalone `superscalar_lsp` / `superscalar_client` binaries are test/dev tools. They are not a supported production deployment mode. Production runs through the plugin.

---

## 6. Why each architectural decision

### HD-derived basepoints (not random)

Random per-channel basepoints make the library's DB the sole keeper of those keys. CLN does not ship that way — every CLN channel's basepoints are HD-derived so a mnemonic backup is sufficient. Matching that gives operators the recovery story they already understand.

### RAM-only MuSig2 secnonces

BIP-327 mandates single-use secnonces. Persisting them creates a key-recovery attack surface (an attacker who restores a backup + replays a partial sig with the same secnonce can extract the full seckey). RAM-only is the bulletproof posture. Crash mid-ceremony costs one ceremony restart, never funds.

### Deterministic nonce derivation (BIP-327 §3.1)

Deterministic derivation of secnonces from (seckey, message, aggregate pubkey, ceremony context) eliminates the entire class of "bad RNG" vulnerabilities. Pure-random secnonces are accepted by the spec but fragile; deterministic is the recommended path and reviewers expect it.

### No raw secrets to the watchtower

The watchtower is supposed to be a limited-trust component. Even if it is fully compromised, the attacker should only be able to broadcast already-signed penalty TXs, not steal funds. The library's DB schema today holds revocation secrets in columns the watchtower can read; that needs refactoring so the watchtower's view is pubkey + ciphertext blob only.

### Plugin DB hooks into the node's backup pipeline

Operators have existing backup tooling for CLN. If the plugin DB lives outside that pipeline, the operator's normal workflow misses SuperScalar state — disk failure equals lost state even with normal CLN discipline. Wiring into `db_write` (or storing in a custom lightningd-managed table) makes the operator workflow cover everything.

### External cryptographer audit

We cannot review our own crypto. A reviewer who has seen ten Lightning implementations will spot issues we will not. Non-negotiable for handling real funds.

---

## 7. Planned work

### Phase A — security research and design refinement

This phase produces the artifacts a Bitcoin/LN reviewer expects to see before code review begins. The current doc is a starting point; the items below extend it to a complete RFC.

| Workstream | Output |
|---|---|
| **Threat model** | Enumerate adversaries (passive disk reader, OS root, compromised plugin, malicious counterparty, malicious watchtower, compromised bitcoind RPC). For each, list invariants we preserve and recovery paths. |
| **Adversary research** | Survey known LN attack classes (channel jamming, fee griefing, breach replay, nonce reuse, splice race conditions) and document how our design defends or accepts each. |
| **Prior art comparison** | Document how SuperScalar's key handling relates to CLN hsmd, lnd channeldb, eclair, LDK Signer trait, VLS, eltoo / BIP-118. Adopt where applicable; explain where we diverge. |
| **BIP32 derivation spec** | Define exact derivation paths including network, protocol-version, factory-index, channel-index, role. Include domain separation across mainnet/testnet/regtest. Publish in BIP-style format. |
| **Plugin RPC schema** | Define the wire format (likely JSON-RPC over AF_UNIX or similar) for the four callback families in §5, with versioning, replay protection, and explicit error codes. |
| **MuSig2 deterministic nonce spec** | Spell out BIP-327 §3.1 inputs as used in SuperScalar's multi-input ceremonies. Verify the aggregate context is included correctly. |
| **Watchtower trust model** | Document the WT's exact threat model, what it sees, what it cannot do, and the schema refactor that enforces "no raw secrets readable by WT process." |
| **DB content & encryption** | Per-column classification (persist / never-persist / HD-derive / ephemeral). Consider at-rest column encryption for sensitive fields, deriving the column-encryption-key from `hsm_secret`. |
| **Compatibility & migration** | Define the migration path for any existing channels created under the test scaffolding (random keys) to the production HD-derived scheme. |
| **Operator runbook** | Document operator-side responsibilities (LUKS, `hsm-password`, backup discipline, recovery from disaster). |

### Phase B — implementation (after Phase A artifacts exist)

| Task | Description |
|---|---|
| **#234** SF-HD-BASEPOINTS | Add the key-derivation plugin callback to the library API. Plugin implementation (in the external CLN-fork repo) calls hsmd for derivations. |
| **#236** SF-NONCE-RAM-ONLY | Remove secnonce columns from the `nonce_pools` table. Keep secnonces RAM-only. Restart-resets-ceremony test. |
| **#237** SF-MUSIG-DETERMINISTIC-NONCE | Verify the current implementation against the Phase A BIP-327 spec; fix if it diverges. |
| **#239** SF-WT-NO-SECRETS | Schema refactor per the Phase A watchtower trust model. |
| **#241** SF-CLN-BACKUP-HOOKS | Add the backup-subscription plugin callback. Plugin implementation hooks into lightningd's `db_write` chain (or stores SuperScalar state in custom lightningd tables). |

### Phase C — external review

| Task | Description |
|---|---|
| **#152** SF-AUDIT | Commission a Bitcoin/LN cryptographer. Provide the Phase A artifacts + Phase B code. Address findings before mainnet launch. |

### Phase D — v1.x hardening (post-launch)

| Task | Description |
|---|---|
| **#214** SF-HSM-KEY-ROTATION | Full hsmd-mediated MuSig2 signing. Requires CLN-core patches. |
| **#238** SF-VLS-COMPAT | Validating Lightning Signer integration / policy engine. |
| **#240** SF-SIGN-AUDIT-TRAIL | Structured signing log for forensics and compliance. |
| **#235** SF-DB-CONTINUOUS-BACKUP | Timer-driven snapshots beyond pre-rotation. |

---

## 8. Acceptance criteria

The mainnet key-security gate (#242) closes when all of the following are true:

1. All Phase A artifacts exist, reviewed internally, no major open architectural questions.
2. #234, #236, #237, #239, #241 are all merged.
3. #152 external audit report is received and any critical / high findings are addressed.

Post-gate state: SuperScalar's key handling matches CLN's hobbyist-tier baseline. Mnemonic-phrase backup of the user's node + backup of the SuperScalar DB (via #241) is sufficient for full recovery. Watchtower compromise yields no key material. Operators take the same hardware/OS hardening responsibilities they already take for vanilla CLN.

---

## 9. Operator responsibilities (documented in mainnet runbook, not enforced by code)

- Back up `hsm_secret` offline (paper, metal, HSM, Shamir-shared).
- Encrypt the disk holding lightning-dir (LUKS recommended).
- Use CLN's `hsm-password` for at-rest seed encryption above hobbyist tier.
- Restrict OS user accounts; do not run lightning as root if avoidable.
- Run at least one independent watchtower.
- Subscribe plugin DB to the node's existing backup workflow (automatic via #241).

---

## 10. Anti-goals

SuperScalar's mainnet key handling is explicitly NOT trying to:

- Build a custom HSM appliance.
- Replace the user's LN node hsmd.
- Invent a new key-derivation scheme (BIP32 is the standard).
- Require a hardware key for hobbyist-tier users.
- Match institutional-grade custody systems on the initial release.

It IS trying to:

- Match CLN's hobbyist-tier security model exactly.
- Give operators a recovery story they already understand.
- Pass an experienced Bitcoin/LN cryptographer review at that tier.
- Leave the door open for higher-tier hardening (#214 / #238 / #240) without architectural change.

---

## 11. Tracking

- Umbrella task: **#242** SF-MAINNET-KEY-SECURITY
- Phase A research workstreams: tracked internally; sub-tasks opened once doc is reviewed
- Phase B implementation tasks: **#234, #236, #237, #239, #241**
- Phase C external review: **#152**
- Phase D v1.x hardening: **#214, #238, #240, #235**

Every PR closing a Phase B item should link this doc and the umbrella task.
