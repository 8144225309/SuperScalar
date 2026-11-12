# PTLC internal end-to-end: HTLC→PTLC parity + build plan

Status: **2026-07-14**, verified against the shipped tree. Tracking issue: **#192**.
PTLC machinery is built and watchtower-defended but **dormant** — no production path originates a PTLC, so all factory payments are HTLCs today. This doc is the proof-positive denominator (what creates an HTLC → what must reach PTLC parity) plus the build plan. Every anchor is verified against code, not docs.

> The exhaustive per-function matrix (≈85 HTLC-surface functions × 14 modules vs 24 PTLC) is maintained by the PTLC team in `knowledge-base/ptlc/htlc-parity-matrix.md`. This doc is the code-repo-resident summary + the load-bearing findings.

---

## A. Complete HTLC origination inventory — 6 classes, provably closed

Every `htlc_t` that enters memory comes from exactly these, and nothing else in the tree can mint one:

| Class | Sites | Parity plan |
|---|---|---|
| **1. Protocol origination** (`channel_add_htlc`) | `client.c:375/:504`, `htlc_commit.c:455/:493/:591`, `lsp_channels.c:900/:1162/:5638/:6280`, `lsp_bridge.c:214`, `lsp_demo.c ×3` | P1 (selector) |
| **2. Engine forward** | `ln_dispatch.c:921` (`htlc_commit_add_and_sign`, one level above `channel_add_htlc` — makes A→LSP→B forwarding work) | P1 |
| **3. Raw BOLT-2 public sender** | `payment.c:129-147` (byte-packed `update_add_htlc` to external peers, incl. MPP `shard_msat` loop) | **EXCLUDED** — public network is HTLC-only until network PTLCs exist |
| **4. Restart resurrection** | `lsp_init_from_db.c:237`, `client_reconnect.c:246`, `lsp_channels.c:5834` (reconnect rollback), watchtower loads | P3 (see gap below) |
| **5. Watchtower shims** | `watchtower.c:393-434` (penalty-build save/rebuild) | **parity already exists** (wired penalty path) — no action |
| **6. Test code** | `test_persist.c`, pre-daemon `.inc`, unit tests | test parity |

Notable newly-catalogued sites: `lsp_channels.c:5638` (reconnect replay), `:6280` (settlement HTLC — needs a PTLC-variant-or-carve-out decision), `ln_dispatch.c:921`, `payment.c:145`.

---

## B. ⚠️ P2 is a leaf REDESIGN, not builder-wiring (highest-risk finding)

The PTLC "success" tapleaf is **HTLC hashlock scaffolding, not a point-lock.** `tapscript.c:429` (`tapscript_build_htlc_offered_success`, reused for PTLC at `channel.c:888-891`) emits the literal BOLT-3 hashlock:

```
OP_SIZE 0x20 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <key> OP_CHECKSIG
```

The PTLC path serializes the payment point's x-only bytes into the `<hash>` slot (`channel.c:880-886`), so the leaf demands a 32-byte preimage whose SHA256 equals those bytes — which by definition does not exist. And `channel_build_ptlc_success_tx` (`channel.c:2778`) assembles its witness as `<sig> <script> <control_block>` with **no preimage/secret item pushed.** **The on-chain PTLC success path is therefore unspendable as built.**

P2 is not "call the two orphan builders." It is:
1. redesign the success leaf as a **true point-lock** — key-path / `CHECKSIG`-only against the aggregate point; completing the adaptor signature *is* the reveal; `adaptor_extract_secret` (`adaptor.c:28`) recovers the scalar on-chain;
2. rebuild the witness assembly to match;
3. update the commitment-output builder `channel.c:888-901`.

`channel_build_ptlc_timeout_tx` / `_penalty_tx` are fine (CLTV / revocation). Only the **success** leaf is the redesign. This is a crypto-design task, above the ~200 LOC estimate, and the critical-path risk the whole effort sits on.

---

## C. 🐛 Restart-resurrection gap (fund-state bug)

`persist_load_ptlcs` (`persist.c:6500`) and `persist_load_old_commitment_ptlcs` (`persist.c:3804`) exist but have **zero production callers** — only `test_persist.c` / pre-daemon tests. The HTLC twins *are* called in production (`lsp_init_from_db.c:237` writes straight into `channel.htlcs[n_htlcs++]`; `client_reconnect.c:246`; `lsp_channels.c:5834` reconnect rollback). Consequence: **an in-flight PTLC survives in the DB but vanishes from channel state on restart/reconnect.** P3 must mirror all resurrection callsites, not merely persist the adaptor scalar — otherwise it's a silent fund-state bug if origination ships before restart is tested.

---

## D. Wire-envelope gaps (P1 net-new)

Only `0x4C PTLC_PRESIG / 0x4D ADAPTED_SIG / 0x4E COMPLETE` exist (`wire.h:59-61`). Missing:
- **`MSG_PTLC_ADD`** carrying (amount, payment_point) inbound.
- **PTLC fail message** (`fail_and_sign` exists; no wire builder).

---

## E. Build plan (P0-P6)

Mirrors issue #192. ~1,200-1,500 LOC incl. tests (revised up from the ~800-1000 core-path estimate after this scan). v0.3 research track — **not a v0.2.0 blocker** (v0.2.0 ships HTLC-only).

- **P0 — Selector + hygiene.** `htlc | ptlc | auto` per-payment/per-factory selector (default `htlc`); retire the legacy `ptlc_safety_set_enabled` gate; threat-model refresh; docs reconcile (comments landed in PR #445).
- **P1 — Originate + settle (~300).** Wire `ptlc_commit_add_and_sign` at the origination callsites (`client.c:375/:504`, `lsp_channels.c:900/:1162`, `ln_dispatch.c:921`) behind the selector; real receive at `ptlc_commit.c:224`; new `MSG_PTLC_ADD` + PTLC-fail wire messages; intra-factory point-locked invoice (`S = s·G`, settle reveals `s`). **Design invariant:** adaptor signatures for pending received PTLCs *before* `commitment_signed`.
- **P2 — Success-leaf redesign (SAFETY-CRITICAL, critical-path).** Section B. Gates P1 exposure on any real-value factory.
- **P3 — Persistence/restart + nonce rule (~100+).** Resurrection mirror (Section C); extend no-secret-nonce-at-rest to adaptor sessions (abort-and-retry, never resume; mirror the stateless pool `channel.c:1541/:1616`); persist the adaptor scalar. Scope fork: point-lock 2-of-2 (client+LSP) vs N-of-N keyagg.
- **P4 — Adversarial + fault matrix (~250).** PTLC cheat-driver rows; conservation-freeze case (`lsp_channels.c:6459`); crash injection per ceremony phase + reorg; fuzz `0x4C-4E`; pending-PTLC-at-rotation/expiry policy (rotation precedent: `lsp_rotation.c:150-166` already fails HTLCs pre-rotate → `channel_fail_ptlc`; only factory-expiry needs a decision).
- **P5 — Enable + evidence.** Soak `--ptlc` mode on the #443 harness (bounded knobs — PTLC ceremonies are heavier, expect *tens* of clean payments/factory at N=127); signet exhibits mirroring the HTLC close `589c763b`.
- **P6 — Payment surface + spec (v0.3).** Invoice/BOLT-12 surface; MPP with per-part scalars; A→LSP→B as two terminated single-hop PTLCs (LSP re-originates — no privacy from the hub); spec section → bLIP.

---

## F. Infra + coordination

**No new infrastructure** — the MuSig2 adaptor API ships in the linked secp256k1-**zkp**; regtest/fuzz/soak rigs are reused; `ptlcs` / `old_commitment_ptlcs` tables exist. The factory is its own PTLC test infrastructure.

Two coordination flags (timing, not infra):
- **Pin secp256k1-zkp** — adaptor support is zkp-only (upstream removed it from the MuSig2 merge); note the maintenance exposure in the P3 audit.
- **Sequence P5 around the VPS credential/IP rotation** so a signet soak isn't stranded mid-run.

Posture: HTLC and PTLC are peer payment kinds, both always compiled in; selection is per-payment (default HTLC). Never originate a real PTLC on a real-value factory until P2 lands.
