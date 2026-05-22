# MuSig2 Stateless-Signer Redesign — Phase 0 Audit

**Date:** 2026-05-22
**Tracker:** task #270 (Phase 0 of #261 master)
**Gates:** Phase 1 implementation (#271)
**Per:** `.claude/MUSIG_NONCE_REDESIGN_MEMO.md` (wallet-team handoff, 2026-05-22)

This audit answers the 8 open questions in §8 of the memo against the current codebase. Implementation recommendations are deliberately omitted — they live in #271.

---

## TL;DR

**The persistence risk surface is smaller than the memo's threat model suggests, but the architectural fix is still required.**

- The `nonce_pools` SQLite table is **dead code** in production — only test code reads/writes it. Scenarios 1, 2, 3 from memo §2.4 are NOT exploitable today through the persistence layer.
- The **real problem** is the wire-protocol shape: all four LSP-side multi-party ceremonies (factory create, per-leaf advance, Tier B state advance, sub-factory advance) put the **LSP first** — LSP generates its nonce, ships it in `*_PROPOSE`, then waits for client responses. The LSP secnonce lives on the stack across one (sometimes more) `recv` waits.
- Option G (stateless signer) requires reversing this: client → LSP pubnonce first, then LSP runs NonceGen+NonceAgg+Sign atomically in one message.
- Phase 3 (drop the `nonce_pools` table) is zero-risk because nothing reads from it in production.

---

## 1. All callsites of `secp256k1_musig_nonce_gen` in LSP code

The raw library symbol is only called from **`src/musig.c`** (3 sites). All other callers go through one of two wrappers — `musig_generate_nonce` (single-shot) or `musig_nonce_pool_generate` (pre-generated pool).

```
src/musig.c:75    inside musig_sign_all_local()           — demo / single-process only
src/musig.c:198   inside musig_nonce_pool_generate()      — pool pre-gen (under scrutiny)
src/musig.c:409   inside musig_generate_nonce()           — single-shot wrapper
```

**LSP callsites of the pool wrapper** `musig_nonce_pool_generate`:

```
src/lsp.c:508             factory creation ceremony — pool of (lsp_node_count + 1)
src/lsp_channels.c:2230   lsp_run_state_advance() (Tier B) — pool sized lsp_node_count
src/lsp_channels.c:2316   same, separate poison-TX pool
```

**LSP callsites of the single-shot wrapper** `musig_generate_nonce`:

```
src/lsp.c:1193                       cooperative close (LSP nonce across CLOSE_NONCE round-trip)
src/lsp_channels.c:1682+1691         lsp_advance_leaf() — state + poison nonces, held across PROPOSE→PSIG
src/lsp_channels.c:3104+3113         lsp_realloc_leaf() — state + poison, held across PROPOSE→NONCE→ALL_NONCES→PSIG
src/lsp_channels.c:3714+3730         lsp_subfactory_chain_advance() multi-input — n_inputs+1 nonces
src/lsp_channels.c:4109+4118         lsp_subfactory_chain_advance() single-input — same wait pattern
```

Out of scope (single-process all-local signing, not production paths): `factory.c:1962`, `factory.c:2158`, `adaptor.c:75`.

---

## 2. Reads/writes from the `nonce_pools` SQLite table

**Critical finding:** the table exists in the schema but **no production code calls either helper**. Both `persist_save_nonce_pool` and `persist_load_nonce_pool` are dead-API; only `tests/test_persist.c` exercises them.

Schema:
```
src/persist.c:92  CREATE TABLE IF NOT EXISTS nonce_pools (
                    channel_id INTEGER NOT NULL,
                    side TEXT NOT NULL,
                    pool_data BLOB,
                    next_index INTEGER DEFAULT 0,
                    PRIMARY KEY (channel_id, side));
```

Helpers:
```
src/persist.c:2888  persist_save_nonce_pool() — INSERT OR REPLACE
src/persist.c:2916  persist_load_nonce_pool() — SELECT pool_data, next_index
```

Production callers: **none.** Test callers: `tests/test_persist.c:940` (save), `:946` (load).

The in-memory pool struct `musig_nonce_pool_t` (`include/superscalar/musig.h:61`) IS used in production for in-memory pre-gen but never serialized. References:

```
include/superscalar/channel.h:136     embedded in channel_t (Lightning channel commitments)
src/lsp.c:504                         factory create
src/lsp_channels.c:2226               state advance
src/lsp_channels.c:2300               state advance poison
src/channel.c:1382/1434/1509          per-channel commitment pool
```

**Implication:** Scenarios 1, 2, 3 from memo §2.4 are not currently exploitable. The risk surface is (a) the API existing as a latent footgun, and (b) the in-memory secnonces living across `recv` waits in process memory (§3 + §6 below).

---

## 3. Current exact wire-message ordering for round 2

### (a) Per-leaf advance — `lsp_advance_leaf` in `src/lsp_channels.c:1547`–`1983`

Three messages: `PROPOSE → PSIG → DONE`.

```
Step 3 (:1682)  LSP generates lsp_secnonce                                [HELD ACROSS WAIT]
Step 4 (:1720)  wire_send MSG_LEAF_ADVANCE_PROPOSE {lsp_pubnonce, [lsp_poison_pubnonce]}
Step 5 (:1732)  recv MSG_LEAF_ADVANCE_PSIG {client_pubnonce, client_psig, [client_poison_*]}
Step 7 (:1815)  musig_create_partial_sig(&lsp_secnonce, ...)              ← library zeroes here
Step 9 (:1878)  factory_session_complete_node (final aggregation)
Step 10(:1979)  wire_send MSG_LEAF_ADVANCE_DONE
```

**Already a 3-message round (not the 4-message old pattern).** The single `MSG_LEAF_ADVANCE_PSIG` carries client pubnonce AND psig together — right shape. But the **LSP goes first** (Step 4 before Step 5), so the LSP secnonce lives on stack across the `recv` wait.

### (b) Tier B state advance — `lsp_run_state_advance` in `src/lsp_channels.c:2075`–~2950

Five messages: `PROPOSE → PATH_NONCE_BUNDLE (×N clients) → PATH_ALL_NONCES → PATH_PSIG_BUNDLE (×N clients) → PATH_SIGN_DONE`.

```
Step 2   (:2230)  musig_nonce_pool_generate(&lsp_pool, lsp_node_count, ...)   [POOL HELD]
Step 2.5 (:2316)  musig_nonce_pool_generate(&lsp_poison_pool, ...)            [POOL HELD]
Step 3   (:2368)  wire_send MSG_STATE_ADVANCE_PROPOSE {new_epoch, lsp_nonce_bundle[]}   ← LSP nonces FIRST
Step 4   (:2398)  for each client: recv MSG_PATH_NONCE_BUNDLE
Step 5   (:2534)  wire_send MSG_PATH_ALL_NONCES (aggregate) to all clients
Step 6   (:2548)  factory_session_finalize_node (all nodes)
Step 7   (:2581)  musig_create_partial_sig per node (LSP pool secnonces consumed)
       … collect PATH_PSIG_BUNDLE per client …
       wire_send MSG_PATH_SIGN_DONE
```

**Largest blast radius:** LSP holds the entire pool (one secnonce per affected node, often dozens) across multiple `recv` waits.

### (c) Sub-factory chain advance — `lsp_subfactory_chain_advance` in `src/lsp_channels.c:3519`

Five messages: `PROPOSE → NONCE (×k) → ALL_NONCES → PSIG (×k) → DONE`.

```
Step 3 (:3714 multi-input)   musig_generate_nonce × n_inputs LSP + 1 poison    [HELD]
Step 3 (:4109 single-input)  musig_generate_nonce × 1 LSP + 1 poison           [HELD]
Step 4 (~:3760/4140)         wire_send MSG_SUBFACTORY_PROPOSE {lsp_pubnonce[s]}    ← LSP first
Step 5 (~:3770/4180)         for each client: recv MSG_SUBFACTORY_NONCE
Step 6                       wire_send MSG_SUBFACTORY_ALL_NONCES
Step 7                       musig_create_partial_sig (LSP secnonces consumed)
Step 9                       for each client: recv MSG_SUBFACTORY_PSIG
Step 10                      factory_session_complete + MSG_SUBFACTORY_DONE
```

Same shape: LSP first; secnonces held across two round-trips.

### Summary

None of the three ceremonies use the original 4-step Bitcoin-Core-style `MSG_AGGNONCE` pattern. Aggregation already happens client-side (every signer receives ALL pubnonces and aggregates locally). The dangerous step is **the LSP going first**, which forces secnonce lifetime to span at least one `recv` wait. Option G reverses the order: client → LSP pubnonce first, LSP runs NonceGen+Sign atomically and responds with `{lsp_pubnonce, lsp_psig}` in one message.

---

## 4. Persist-then-wire-send invariant for the pool counter

**There is no current persistence of `next_unused` in production.** The pool helpers operate purely on the in-memory `musig_nonce_pool_t`. The only counter increment is at `src/musig.c:228` (`pool->next_unused++` after copying the pubnonce out). The SQLite helpers are dead code (§2).

Scenario 1 from memo §2.4 is **not exploitable in the factory / Tier B / sub-factory pools today** because the pool dies with the process. Equivalent crash window also doesn't apply to the `channel.c` in-memory pool:

```
src/channel.c:1374  channel_init_nonce_pool() — fresh pool, count ≤ MUSIG_NONCE_POOL_MAX (256)
src/channel.c:1434  channel_create_commitment_partial_sig() — pool_next + sign + next_unused++ same fn
src/channel.c:1509  channel_verify_and_aggregate_commitment_sig() — same on verify path
```

`persist_save_channel` (`src/persist.c:2396`) persists `id, factory_id, slot, local/remote_amount, funding_amount, commitment_number, funding_txid, funding_vout, state, to_self_delay, fee_rate, use_revocation_leaf, funding_pending_reorg` — **no pool fields**. Per-channel pool is in-memory-only and re-generated fresh on `lsp_channels_init_from_db`.

**The pre-mainnet risk is the API surface itself.** Any future caller of `persist_save_nonce_pool` would immediately re-introduce Scenario 1.

---

## 5. Code paths that pull a secnonce outside the official pool API

**No red-flag direct calls were found in `src/*.c` outside `musig.c`.** Every production call to `secp256k1_musig_nonce_gen` is inside `src/musig.c` (lines 75, 198, 409). External code goes through `musig_generate_nonce` or `musig_nonce_pool_*`.

The only direct test caller is `tests/test_property.c:297` (property/fuzz local test, intentional).

The single-shot wrapper `musig_generate_nonce` is called from many LSP / client / factory sites (see §1) — all legitimate per-ceremony nonce generation, none escape the secnonce into persistence today. But every LSP call holding `lsp_secnonce` across a wire `recv` is a stack-resident copy with multi-millisecond-to-multi-second lifetime. These are the redesign targets.

---

## 6. Sub-factory / Tier B ceremony shapes where LSP cannot wait for client pubnonces first

**Tier B (`lsp_run_state_advance`, `lsp_channels.c:2075`):** LSP **goes first**. At `:2230` it builds the full pool, at `:2368` it ships the LSP nonce bundle in `MSG_STATE_ADVANCE_PROPOSE`. Only afterward (`:2421`+) does it `recv MSG_PATH_NONCE_BUNDLE` from each client. **Structurally backwards from Option G.** Largest blast radius — one ceremony involves nonces for every affected node (potentially every PS leaf in the tree on a root-driven rotation).

**Sub-factory chain advance (`lsp_subfactory_chain_advance`, `lsp_channels.c:3519`):** LSP also first. Multi-input branch generates `n_inputs` secnonces at `:3714`, ships in PROPOSE, then waits for client NONCEs at `~:3770`. Single-input branch same pattern at `:4109` / `~:4140`. Per #142 SF-A multi-input fork: number of LSP secnonces grows with `n_inputs` (k+1 for k-client sub-factories on second-and-later advances).

**Per-leaf advance (`lsp_advance_leaf`, `lsp_channels.c:1547`):** LSP first (`:1682` gen, `:1720` send PROPOSE). 1-on-1, so the order inversion is structurally simplest — memo §3.1 happy-path.

**Cooperative close (`lsp.c:1193`):** N-of-N. Same shape, LSP nonce before `MSG_CLOSE_PROPOSE`.

**Factory creation (`lsp.c:504`):** LSP pre-generates pool BEFORE clients connect; LSP nonces bundled with FACTORY_PROPOSE; clients respond with NONCE_BUNDLE. Same forward order.

**All four LSP-side multi-party ceremonies put the LSP first.** None match the stateless-signer pattern today.

---

## 7. Wallet-client side

**External — wallet team task #275 owns.** The `superscalar-wallet` repo is not in this codebase.

Note that this repo's bundled `src/client.c` (test/regtest client) does use `musig_nonce_pool_t`:

```
src/client.c:1727  pool gen on factory creation
src/client.c:1761  pool_next at signing
```

Plus `musig_generate_nonce` callsites at `client.c:615, 987, 1039, 2708, 2717, 3003, 3018, 3240, 3248, 3575, 3584, 3877, 3916`. The bundled `client.c` is the test client; the production wallet is the separate repo.

---

## 8. Per-process ceremony throughput baseline

**No existing musig benchmark in this repo.** `fuzz/` contains `fuzz_aead_decrypt.c`, `fuzz_hex_decode.c`, `fuzz_noise_handshake.c`, `fuzz_persist_load.c`, `fuzz_tx_sighash.c`, `fuzz_wire_parse_json.c`, `fuzz_wire_recv.c` — none touch MuSig2 directly. `oss-fuzz/` has the harness configuration but no nonce-specific target.

**Suggested location:** `tests/bench_musig_ceremony.c` paralleling `tests/test_musig.c`, or a new `bench/` directory.

**Minimum measurements:**
- `musig_generate_nonce` calls/sec/core
- Full per-leaf-advance ceremony rate at N=2
- Full Tier B at N=8 / 64 / 128
- Full sub-factory advance at typical k

Compare current pool-pre-gen path against inline-with-sign Option G path once both exist. Per memo §8 question 6: "should not be a problem but worth measuring" before flipping the Phase-2 default.

---

## Other findings (adjacent to §1–§8)

- **No active wire support for `MSG_CEREMONY_ABORT`** (memo §5.2). `grep MSG_CEREMONY_ABORT` returns no hits. `wire.h` uses single-byte IDs; the highest in use is `MSG_SUBFACTORY_DONE 0x77` plus `0x78`+ for funding-reorg msgs. The new ID can be a free single-byte slot.
- **Per-leaf advance ALREADY uses the 3-message shape** — only architectural change needed there is **reversing who goes first**, not adding/removing messages.
- **The `nonce_pools` table is effectively unused.** Phase 3 of the memo's migration plan can drop it with zero production-data risk — retire API and table together.
- **Two functions reset the pool counter without persistence:** `musig_nonce_pool_generate` (`src/musig.c:213`) and `channel_init_nonce_pool` (`src/channel.c:1374`). Both run at full pool re-generation time, in-memory only. **If anyone ever adds `persist_save_nonce_pool` here, the persist-before-wire-send invariant becomes a load-bearing concern instantly.**
- **C3 signing-round journaling** (`persist_save_signing_round_*` at `lsp_channels.c:2079, 2152, 2429, 2613, 3580, …`) records public state per ceremony (round_id, signer_slot, "verified"/etc.) — this is the existing scaffolding for the "what may be persisted" list in memo §3.2.

---

## Phase 1 priorities derived from this audit

(Not implementation — sequencing only. Implementation lives in #271.)

1. **Add MSG_CEREMONY_ABORT opcode + handler** (memo §5.2). Greenfield work, no existing path to deconflict.
2. **Reverse per-leaf advance** (memo §3.1). Smallest blast radius, already 3-message shape; only the order changes.
3. **Reverse Tier B + sub-factory advance** (memo §3.4). Largest blast radius; needs care because LSP currently pre-aggregates per-node nonce bundles before sending — the new flow waits for all client pubnonces first, generates LSP nonces atomically per node, signs, responds.
4. **Reverse cooperative close + factory creation** for completeness.
5. **Feature-gate** all the above behind `--musig-stateless` (default off in Phase 1).
6. **Phase 3 retirement** is independent and trivial — drop the `nonce_pools` table + the dead API together. Can be sequenced any time after Phase 1 lands.
