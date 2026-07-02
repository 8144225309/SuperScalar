# SuperScalar v0.2.0 Release Notes

*v0.2.0 — 2026-07-02*

v0.2.0 is the largest SuperScalar release to date. It bundles a new canonical leaf shape (Pseudo-Spilman k² sub-factories), a top-to-bottom MuSig2 redesign, PTLC infrastructure, reorg-correctness pre-flight, crash-injection scaffolding, an adversarial cheat-engine campaign, a trustless standalone watchtower, and — since the rc1 candidate — at-rest secret encryption, revealed-secret poison recourse, and CLN-bridge interop with unmodified Lightning nodes proven at the factory design max on public signet.

**Read [Mainnet readiness](#not-yet-for-mainnet) before deploying real funds.** v0.2.0 is feature-complete and proven end-to-end on regtest and public signet; it is **not** yet cleared for mainnet — a third-party security audit and a small set of pre-mainnet hardening items are still open.

This document is the operator-facing summary. See `CHANGELOG.md` for the full per-PR log. Bare `#N` references in that log are internal task IDs, not GitHub PR numbers.

---

## Since v0.2.0-rc1

Work landed after the rc1 candidate (2026-05-31), verified on the current release commit:

- **At-rest secret encryption** — the LSP's HD seed and, subsequently, the remaining at-rest secret columns are sealed with an app-level field-encryption scheme (LND/Core model, no new dependency). `--encrypt-db` wiring plus a mainnet refusal of cmdline `--seckey`. Closes the plaintext-seed steal-all-funds hole for the LSP.
- **Revealed-secret (revocation-style) L-stock poison (#53)** — closes the co-signed-poison theft class at the leaf *and* sub-factory level; proven on regtest and real signet (poison broadcast + multi-party redistribution confirmed on-chain).
- **CLN-bridge interop** — an unmodified, non-bLIP-56 Core Lightning node pays into and out of a SuperScalar factory channel through the bridge. Proven both directions on regtest and real signet, and **at the factory design max (127 clients) on public signet** — inbound to a shallow and a deep-index client, outbound back out, with on-chain funding + cooperative close and net economics reconciled to the sat.
- **Scale correctness at 127 clients** — full lifecycle (creation → client-to-client payments → cooperative close → sat-exact conservation) and async factory rotation both re-proven at the design max. Along the way: the readiness tracker's >64-client undefined shift was removed (derive from per-entry state), `--async-rotation` was fixed to actually gate on readiness rather than fire on a retry tick, and the LSP CLI now rejects `--clients` above 127 (the 128-signer MuSig cap) with a clear message instead of a deep signing failure.

## Headline: Pseudo-Spilman k² sub-factories

The marquee feature of v0.2.0 is the **canonical PS leaf shape from [zmn t/1242](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242)**: instead of one client per leaf, each PS leaf now hosts **k² clients distributed across k pseudo-Spilman sub-factories, with k clients per sub-factory**. The LSP holds "sales stock" inside each sub-factory that can be dynamically chained into new client channels.

For arity k=2 (entry-level production shape):
- 4 clients per leaf vs 1 in pre-PS
- Tree depth drops by ~log₂(4) per leaf compaction
- Lower CSV budget → tighter `final_cltv_delta` for incoming HTLCs
- Sales-stock chain extension lets the LSP refill client liquidity without a full leaf re-sign

Implementation landed in 13 staged PRs (Phase 1 foundation → Phase 5 signet campaign), plus the multi-input MuSig ceremony for sub-factory chain advance, force-close persistence, watchtower coverage, on-chain force-close at k=2, per-client channel sweep, and reorg invariants. At k≥3, multi-input keyagg threading is per-input-aware (no more "Invalid Schnorr" at scale).

This is what made the N=64 PS lifecycle on signet + testnet4 not just possible but *practical*.

Reference docs: `docs/ps-subfactories.md`, `docs/pseudo-spilman.md`, `docs/factory-arity.md`.

---

## Major systems

### MuSig2 stateless signer (BIP-327) — default-on

Removed LSP-side secnonce persistence across network waits, per BIP-327 + Bitcoin Core PR #29675 wallet-team guidance. Closes a class of cross-ceremony nonce-reuse attacks that prior pool-based persistence couldn't fully prevent under reorgs and ceremony aborts.

- Phase 0: design audit answering §8 open questions
- Phase 1a: `MSG_CEREMONY_ABORT` opcode + `--musig-stateless` flag (feature-gated, no behavior change)
- Phase 1b: wire opcodes for reversed per-leaf advance flow (greenfield)
- Phase 1c: wire reversed per-leaf advance flow behind feature flag
- Phase 1d: poison TX support in stateless per-leaf advance
- Phase 1e: stateless coverage for sub-factory chain advance, Tier B, factory creation
- Phase 2: stateless flipped to default-on (`SS_MUSIG_LEGACY=1` opt-out)
- Phase 3: legacy `musig_nonce_pool_*` API deleted, `nonce_pools` SQLite schema dropped permanently
- Watchtower registration + poison-TX persist wired into each stateless ceremony
- Unit test asserts the `nonce_pools` table no longer exists (strongest possible invariant — no future refactor can accidentally re-persist secnonces)

### Mixed-arity + static-near-root (canonical SuperScalar shape)

The factory builder now implements zmn's full canonical SuperScalar design: TRUE N-way interior branching with optional static-near-root variant for depth reduction.

- Phase 1: `FACTORY_MAX_OUTPUTS` 8 → 16
- Phase 2: TRUE N-way interior + N-way leaves (arity-N leaf = N+1 outputs)
- Phase 3: `--static-near-root N` makes N shallowest tree levels kickoff-only (no DW counter)
- Phase 4: CLI hardening + BOLT-2016 ceiling check (rejects shapes whose worst-path EWT exceeds 2016 blocks)
- Phase 5: multi-process MuSig coordination at N=8 mixed-arity verified on regtest
- N=128 with `--arity 2,4,8 --static-near-root 2`: EWT = 864 blocks (vs binary baseline 3456)
- `FACTORY_MAX_SIGNERS` 128 → 256 (fixes N=128 LSP stack canary crash)
- `FACTORY_MAX_LEAVES` 64 → 128

### Tier B (multi-leaf state-advance ceremony)

The wire-ceremony equivalent of per-leaf realloc, for when the root DW counter rolls over and every leaf needs re-signing:

- Full implementation with reserved wire IDs `MSG_PATH_NONCE_BUNDLE` / `ALL_NONCES` / `PSIG_BUNDLE` / `SIGN_DONE` (0x60–0x63)
- Block-driven root rollover semantics (proper, supersedes earlier rc=-1 trigger)
- Client loops `factory_tick_root` until rollover
- PS leaves re-signed on root rollover + epoch-aware persistence
- Tree-broadcast skips unsigned nodes
- PS sub-factory chain state reset on DW epoch rollover
- Lifted `FACTORY_ARITY_2` restriction on `lsp_realloc_leaf` + `buy_liquidity`
- Rotation log assertion that the poison TX is fully signed (no unsigned-stub fallback)
- Pre-rotation SQLite snapshot hook (`--backup-dir`)

### PTLC (Point-Time-Locked Contracts) — enabled by default

PTLC is on by default in v0.2.0. Disable with `--disable-ptlc` if you want HTLC-only channels.

- Watchtower PTLC breach-defense feed (chain-level breach → sweep)
- PTLC turnover ceremony journaled to `signing_rounds`
- Hard guard against blind-sign seckey extraction in the PTLC pre-sign path
- PTLC commit-tx direction fix
- PTLCs persisted on every channel-add path
- 5 new regtest scripts: basic / breach / restart / chain / breach-chain
- End-to-end PTLC breach test under real chain conditions

### Wire-ceremony poison TX — all 4 paths

Multi-process LSPs now produce a fully-signed L-stock / sales-stock poison TX via a second MuSig2 round bundled with every state advance. Prior to this work, the watchtower received an unsigned stub poison TX on multi-process deployments:

- Canonical L-stock SPK + per-client poison TX per zmn t/1242
- Sub-factory advance path
- Leaf advance path (DW + PS leaves)
- `lsp_realloc_leaf` Tier B per-leaf rotation
- Tier B root-rotation poison wire ceremony (LSP + client sides)
- Poison TX persist + rehydrate across LSP restart (schema v22)
- Realloc WT-register fix — registers pre-realloc leaf as stale-watch target (surfaced by the cheat-realloc test)

### Trustless watchtower (default + only mode)

The standalone `superscalar_watchtower` binary now opens **only** a separate `wt.db` containing pre-signed response TXs and no secrets. The LSP pre-signs every penalty/sweep/response TX at the moment the relevant secret is in memory and stashes the bytes in wt.db. A compromised WT process cannot construct any new transaction.

Verifiable in one command:
```
nm -D --defined-only superscalar_watchtower \
  | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
```
Expected output: empty.

Four watch kinds covered:

| Watch kind | Trigger | Pre-signed response |
|---|---|---|
| `WT_KIND_FACTORY_NODE` | Stale factory-node state broadcast | Latest state TX + L-stock poison |
| `WT_KIND_SUBFACTORY_NODE` | Stale sub-factory chain TX broadcast | Latest chain TX + sales-stock poison |
| `WT_KIND_CHANNEL_COMMITMENT` | Revoked commitment broadcast | Penalty TX |
| `WT_KIND_FORCE_CLOSE_HTLC` | Honest force-close confirmed (per HTLC) | HTLC timeout sweep TX |

Link surgery: secret-reader functions moved into `superscalar_secrets` static library which the LSP/client/tests/bridge link but the WT binary does not.

### Reorg correctness — R1–R6 mainnet pre-flight

- R1: detect same-height + forward reorgs (LSP daemon loop + heartbeat)
- R2: wait loops use stable-confirmation helper
- R3: per-network safe confirmation depth
- R4: 3-kind adversarial reorg regression test against standalone WT
- R5: `funding_pending_reorg` channel state (schema v31), `MSG_FUNDING_REORG` wire, client-side `ps_chain_len` reset, proactive mempool-expiry freeze
- R6: standalone WT detects forward reorgs
- Schema v29 forensic tables: `reorg_events`, `breach_detections`
- Watchtower restart correctness audited end-to-end
- CPFP child-broadcast / anchor mismatch fix (byte-inspection authoritative)
- Sub-factory chain reset on reorg + height-aware reset
- Client-side `ps_chain_len` reset on `MSG_FUNDING_REORG`

### Crash recovery + injection

- `SUPERSCALAR_CRASH_AT` checkpoint framework
- Crash-injection wired at all stateless ceremony phases (PROPOSE / NONCE_BUNDLE / ALL_NONCES / PSIG_BUNDLE / DONE)
- `MSG_FORCE_OUT` + `MSG_ROTATE` wire ops for crash-drill matrix
- Half A: journal SENT-phase participants at every ceremony PROPOSE
- Half C1: crash_checkpoint at all stateless ceremony phases
- Half C2: 20/20 crash-drill matrix tests pass on regtest (incl. production factory rotation, #332)
- ROTATE ceremony persistence + 4 checkpoints in `lsp_channels_rotate_factory`
- LSP loadwallet auto-recovery hook
- LSP self-rebroadcasts after mempool eviction
- BIP-68 audit fix for remaining broadcast paths

### Cheat-engine adversarial campaign (CL1–CL7)

Seven new cheat drivers exercising worst-case adversary behavior end-to-end:

- CL2: `--cheat-realloc` — adversarial pre-realloc-state broadcast
- CL3-K: `--cheat-state K` + multistate daemon scaffold
- CL4: `--cheat-daemon-rollover` — adversarial during Tier B rollover
- CL4-multistate: dashboard multistate cheat tests
- CL5: `--cheat-jit` — adversarial against JIT channel creation
- CL6: `--cheat-lstock-buy` — adversarial against buy-liquidity path
- CL7: `--cheat-backup-restore` — adversarial against SCB restore
- `--cheat-dust-race` — adversarial against force-close HTLC-dust-bump race
- `--cheat-client` net-delta assertion (cheat detection)
- `superscalar_watchtower --inspect-wt-db` for forensic inspection
- Per-cheat regtest script with breach-detection assertions

### Schema migrations (v22 → v39)

Each migration is additive (ALTER TABLE ADD COLUMN or CREATE TABLE IF NOT EXISTS), version-gated, idempotent. `PERSIST_SCHEMA_VERSION` is 39; the persisted version lives in the `schema_version` table (not `PRAGMA user_version`).

- v22: poison TX persist + rehydrate
- v26: `signing_rounds` ceremony forensics journal
- v27: fee-bump escalation persist
- v28: force-close watch persist + subfactory reload
- v29: `reorg_events` + `breach_detections`
- v30: `old_commitment_ptlcs` schema groundwork
- v33: `ps_subfactory_chains.confirmed_height` + `reorg_stale`
- v34: ceremony tables for multi-party coordination (`ceremonies`, `ceremony_participants`, `revocation_releases`)
- v35: per-output HTLC sweep TX persistence
- v36: HTLC resolution TX + L-stock burn TX + agg hard guard
- v37: at-rest HD-seed sealing (encrypted secret storage)
- v38–v39: remaining at-rest secret columns sealed (revocation / channel secrets)
- wt.db schema v2: `watch_kind` discriminant column

### Observability + dashboard

- Native Prometheus exporter (LSP-side metrics endpoint)
- Watchtower penalty TX persist + signing_rounds journal
- Per-signer instrumentation in `signing_rounds`
- 12 dashboard tabs incl. Live Monitor, Defense Status, Payments (HTLC + PTLC), Ceremonies, TX Inventory, Outcomes, Old Commitments, per-POV scoping, multi-client switcher
- Defense Status panel (15-mode failure taxonomy, penalty bytes tile, wallet UTXO + CPFP tiles)
- Outcomes tiles for cheat-* scenarios
- Freshness banner (WAL-aware)
- Production-mode Events derivation
- Tree-node event spam collapsed
- Old Commitments reserve badge
- Factory Config card + PS Leaf Chains panel

### BIP-157/158 lite client

- End-to-end + adversarial regtest scripts
- BIP-158 sync headers: seed locator with genesis hash on initial sync
- P2P tip-lag + reconnect storm fix
- Light-client-mode LSP can verify blocks without a full-node RPC backend

---

## Build, packaging, CI

- Multi-platform binaries auto-built on release: Linux x86_64, Linux ARM64, macOS
- `SHA256SUMS` attached to every GitHub release
- `superscalar_secrets` CMake static library bundles the secret-bearing TUs (`persist_secrets.c`, `watchtower_autosettle.c`, `lsp_init_from_db.c`, `client_reconnect.c`) — LSP/client/tests/bridge link it, WT binary does not
- Bitcoin Core-style release process documented in `docs/release-process.md`
- testnet4 fee floor enforcement (0.1 sat/vB minimum across all runner scripts)
- `setsid` wrap for testnet4 long-runners to avoid systemd-logind SIGTERM on SSH session end
- Sanitizer regtest job (ASan + TSan) catches leaks in wire-ceremony paths
- 17-script regtest serial sweep on every pre-tag main

## Operator tooling

- New `docs/mainnet-runbook.md` (full operator runbook)
- New `docs/release-process.md` (release maintainer checklist)
- New `docs/watchtower-trustless-schema.md` (trust-model design)
- New `docs/deployment-coordination.md` (multi-party deployment)
- New `docs/poison-tx.md` (poison TX semantics)
- Setsid-wrapped runner scripts for testnet4 long-runners
- Stderr separation + core dumps + predeath snapshot in testnet4 runners
- `build-release` defaults for long-runners (avoid ASan instability)
- Sat recovery sweep tooling (`recover_exhibition_funds.py`)

---

## Breaking changes

### Watchtower CLI: `--db` removed

```
Error: --db is no longer a valid flag for the standalone watchtower.
       v0.2.0 ships trustless mode as the only mode.  Use --wt-db PATH instead.
```

`--inspect-db` also removed. Use `sqlite3 wt.db` directly.

### LSP: `--wt-db` required on mainnet

```
Error: mainnet requires --wt-db for the trustless watchtower.
       v0.2.0 removed the legacy --db-only watchtower mode.
```

### v0.1.x → v0.2.0 migration

1. On the LSP: add `--wt-db /path/to/wt.db` (any path adjacent to `lsp.db`). Restart.
2. On the WT: replace `--db /path/to/lsp.db` with `--wt-db /path/to/wt.db`. Restart.
3. `lsp.db` stays — the LSP still uses it for channel state, ceremonies, etc. Only the WT process stops touching it.

No schema migration required on `lsp.db`.

---

## Validation

End-to-end PASS on three independent chains:

- **regtest**: 19/19 acceptance scripts in the serial sweep
- **signet**: full N=64 PS lifecycle (21 tree-nodes confirmed at 0.1 sat/vB)
- **testnet4**: full N=64 PS lifecycle (21 tree-nodes confirmed under live testnet4 attack conditions)

Plus the per-feature regtest suites (PTLC × 5, cheat-engine × 7, crash-drill × 16, sub-factory × 4, watchtower trustless × 3).

---

## Not yet for mainnet

v0.2.0 is feature-complete and proven end-to-end on regtest and public signet, including at the 127-client design max. It is deliberately **not** marked mainnet-ready. Before real funds, the following are open:

- **Third-party security audit** — not started; this is the dominant gate.
- **CLN-bridge authentication** — the bridge's pubkey "pin" is not mutual authentication over the current Noise NK handshake; a peer that knows the (public) bridge key could inject bridge HTLCs. Run the bridge on a trusted/firewalled interface until Noise KK mutual auth lands.
- **Reference-client at-rest encryption** — the LSP seals its secrets at rest; the reference *client* does not yet, so its HD seed is on disk in the clear. Use `--keyfile` and protect the client data directory.
- **Post-rotation accounting** — a conservation-checker/init mismatch can freeze new HTLCs on channels immediately after a factory rotation (funds are safe; payments pause until restart). Fix in progress.
- **Operational model** — watchtower + CPFP-bumper funding/ownership, client fee-reserve for self-exit, and construction migration/backup-restore are still being specified.

Deploy on signet/testnet only until these close.

## Verifying your install

```
$ nm -D --defined-only $(which superscalar_watchtower) \
    | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
```

Expected output: **empty**. Any line in the output is a regression — file an issue.

Smoke-test on regtest:
```
$ bash tools/test_regtest_watchtower_trustless.sh
```
