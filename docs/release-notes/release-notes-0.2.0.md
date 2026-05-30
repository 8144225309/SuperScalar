# SuperScalar v0.2.0 Release Notes

SuperScalar v0.2.0 is the "release client" — the first version that maintainers and operators should treat as a credible mainnet candidate.  The defining change is the trustless watchtower: the standalone `superscalar_watchtower` binary literally cannot read revocation secrets, even if compromised.

This document is the operator-facing summary.  See `CHANGELOG.md` for the per-commit log and `docs/watchtower-trustless-schema.md` for the trust-model design.

---

## Headline: trustless watchtower is now the only mode

Pre-v0.2.0, the standalone watchtower opened `lsp.db` read-only and read revocation secrets from it to construct penalty transactions at breach detection time.  A compromised WT process meant compromised channel secrets.

v0.2.0 inverts the model:

- The LSP pre-signs every penalty / sweep / response TX at the moment the relevant secret is in memory, and stashes the bytes in a separate `wt.db` (the "trustless watchtower DB") with no secrets.
- The standalone WT opens **only** `wt.db`.  Its CLI no longer accepts `--db`.  Its binary no longer contains the secret-reader functions.  Verifiable in one command:

  ```
  $ nm -D --defined-only superscalar_watchtower \
      | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
  (empty)
  ```

- Trust model summary: *the watchtower can broadcast pre-signed responses but cannot construct any new transactions and cannot recover any key material, even with full filesystem access to lsp.db*.

All 4 watch kinds are covered:

| Watch kind | Trigger | Pre-signed response |
|---|---|---|
| `WT_KIND_FACTORY_NODE` | Stale factory-node state broadcast | Latest state TX + L-stock poison |
| `WT_KIND_SUBFACTORY_NODE` | Stale sub-factory chain TX broadcast | Latest chain TX + sales-stock poison |
| `WT_KIND_CHANNEL_COMMITMENT` | Revoked commitment broadcast | Penalty TX |
| `WT_KIND_FORCE_CLOSE_HTLC` | Honest force-close confirmed (per HTLC) | HTLC timeout sweep TX |

The wt.db schema is single-table (`wt_watches`) with a `watch_kind` discriminant column.  Migration from a Phase 1a wt.db to v2 happens in place on open.

---

## Breaking changes

### Watchtower CLI: `--db` removed

The standalone watchtower no longer accepts `--db PATH`.  Passing it errors with:

```
Error: --db is no longer a valid flag for the standalone watchtower.
       v0.2.0 ships trustless mode as the only mode.  Use --wt-db PATH instead.
```

`--inspect-db` is also removed.  Use `sqlite3` directly on `wt.db` for inspection; the schema is documented at `docs/watchtower-trustless-schema.md`.

### LSP: `--wt-db` required on mainnet

If you launch `superscalar_lsp --network mainnet`, you must also pass `--wt-db PATH`.  Without it, the LSP cannot populate the trustless watchtower binary, so any mainnet deployment would have zero breach response capability.  Hard error:

```
Error: mainnet requires --wt-db for the trustless watchtower.
       v0.2.0 removed the legacy --db-only watchtower mode; the LSP
       must populate wt.db so a standalone trustless WT can broadcast
       penalty TXs on breach without ever opening lsp.db.
```

### v0.1.x → v0.2.0 migration

For an existing v0.1.x deployment:

1. **On the LSP**, add `--wt-db /path/to/wt.db` to the launch command.  Pick any path adjacent to your `lsp.db`.  Restart the LSP.  It will create `wt.db` on first run and start populating it on every revocation / state advance / force-close.
2. **On the WT**, replace `--db /path/to/lsp.db` with `--wt-db /path/to/wt.db` (the file the LSP just created).  Restart the WT.
3. `lsp.db` stays where it is — the LSP still uses it for everything else (channel state, ceremonies, etc.).  Only the WT process stops touching it.

There is no schema migration on lsp.db.  The watchtower-specific tables (`old_commitments*`, etc.) are no longer consumed by the standalone WT but remain written by the LSP for the in-process watchtower path and for future tooling.

---

## What's new (engineer-facing)

### `wt.db` schema v2

`include/superscalar/persist_wt.h` declares the `wt_watch_kind_t` enum and the public API.  The schema in `src/persist_wt.c` adds a single `watch_kind` column to `wt_watches` (default 0 for backward compat with Phase 1a data).  In-place v1→v2 migration is run on open.

### LSP-side adapters

`include/superscalar/lsp_wt.h` exposes 4 helpers, one per kind:

- `lsp_wt_register_factory_node_watch` (existing)
- `lsp_wt_register_subfactory_node_watch` (new)
- `lsp_wt_register_commitment_watch` (new)
- `lsp_wt_register_force_close_watch` (new)

Each hex-encodes the signed response TX and calls `persist_wt_register_watch` with the matching `watch_kind`.

### Wired callsites

All production paths that previously registered with the legacy in-memory watchtower now also write to wt.db:

- Leaf advance, Tier B advance, leaf realloc (Phase 1b — pre-existing)
- Sub-factory chain advance, single + multi-input (new in this release)
- 7 channel-revocation sites (lsp_channels.c × 5 + lsp_bridge.c × 2) — wired via a single-edit inside `watchtower_watch_revoked_commitment` since the penalty TX was already pre-built there (#208 A3.1b)
- Force-close HTLC sweep at ln_dispatch.c, with per-HTLC sweep TX build via `channel_build_htlc_timeout_tx`

### WT-side hydration

`watchtower_hydrate_from_wt_db` walks all 4 watch kinds via `persist_wt_list_watches_by_kind`, logs per-kind counters at startup.

### Link surgery

5 secret-reader functions moved out of `src/persist.c` into `src/persist_secrets.c`.  The auto-settle helper moved out of `src/watchtower.c` into `src/watchtower_autosettle.c` (called via function-pointer registered by the LSP).  Two LSP-specific helpers (`lsp_channels_init_from_db`, `client_run_reconnect`) moved out of their original TUs into `src/lsp_init_from_db.c` and `src/client_reconnect.c` to break transitive symbol pulls from the WT binary's link set.  All 4 new TUs go into a new CMake static library `superscalar_secrets` which the LSP/client/tests link but the WT binary does not.

### Latent bug fixes (along the way)

- `superscalar_watchtower.c`: 3 NULL-deref sites in trustless mode (`persist_close(&db)` and `persist_log_broadcast(&db, ...)` on uninitialized `db`; unconditional `printf(... db_path)`) — all guarded.

---

## What stayed the same

- Channel protocol (BOLT-1/2/4/9/11/12) — no wire changes for clients.
- Sub-factory ceremony semantics — unchanged.
- MuSig2 stateless signer (introduced in 0.1.x late updates) — unchanged.
- `superscalar_client` binary — unchanged from operator perspective.

---

## What's coming in v0.3

- `lsp.db` cleanup: drop the watchtower-only tables (`old_commitments*`, etc.) since the standalone WT no longer needs them.  Schema migration with operator notice.
- Further library split: separate `libsuperscalar_lsp_only` and `libsuperscalar_client_only` from the shared core to reduce binary surface for each tool.

---

## Verification on your own deployment

After upgrading to v0.2.0, verify the trustless guarantee on your binary:

```
$ nm -D --defined-only $(which superscalar_watchtower) \
    | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
```

Expected output: **empty**.  Any line in the output is a regression — file an issue.

Smoke-test the trustless WT against a real chain (regtest):

```
$ bash tools/test_regtest_watchtower_trustless.sh
```

Should print 6 PASS checks (A-E plus Phase 4 invariants).
