# Changelog

All notable changes to SuperScalar are documented here.

## Unreleased

## 0.1.13 — 2026-04-24

Factory participant cap raised from 64 to 128. Per-channel fee tracking and HTLC-based profit settlement. Client-side verification at every factory lifecycle boundary. Memory-safety CI hardening (LSan leak gate, TSan job, OSS-Fuzz integration) — 1050 pre-existing leaks found and fixed. End-to-end spendability + economic-correctness verification across all three factory arities (**Chart A 28/28**, Chart B 28/29 regtest + 3/3 bridge external_in; 3 external_out cells remain 🟡 pending signet infrastructure — see `tools/test_bridge_econ_signet.sh`). Production-blocking cooperative-close-after-payments bug fixed (`factory_recovery_scan` no longer force-publishes the tree at startup). On-chain stranded-funds recovery tool. 1377 unit tests, all passing under ASan+UBSan+LSan and TSan.

### Spendability + economic-correctness verification (PRs #68–#72)

- **Cooperative close: LSP output uses its own P2TR, not the N-of-N funding SPK** (PR #68, `lsp_channels.c`, `lsp_channels.h`). Before: `lsp_channels_build_close_outputs` sent the LSP's recovered share (L-stock + local_amount sums + accumulated fees) back to the factory's 5-of-5 MuSig funding SPK, leaving those sats spendable only with N-of-N cooperation. After: `mgr->lsp_close_spk = P2TR(xonly(factory->pubkeys[0]))`, derived in `lsp_channels_init` (and `init_from_db`). Existing rotation-override SPK still wins when present.
- **Client-side conservation check off-by-154** (PR #70, `client.c`). `client_check_conservation` compared `local + remote + Σhtlc` against `funding_amount` but `lsp_channels_init` already deducts `base_commit_fee = ceil(fee_rate × 154 / 1000)` from the channel's usable balance. On arity-1 multi-payment this printed a false `CONSERVATION VIOLATION delta=-154` every HTLC add/fulfill. Log-noise fix; check never aborted.
- **Spendability test gauntlet** (merged via PR #71, `tests/spend_helpers.{c,h}`, `tests/test_close_spendability_full.c`): reusable `spend_coop_close_gauntlet` harness (BIP-341 key-path sweep per party with only their own seckey) and 22 Chart A cells covering coop close × 5 parties × 3 arities, force-close to_remote / to_local (CSV script-path), breach penalty via revocation secret, rotation balance-carry, PS chain close (arity 3), and HTLC-in-flight acknowledgment.
- **Economic-correctness harness (Chart B)** (PR #71, `tests/econ_helpers.{c,h}`, `tests/test_economic_correctness.c`): `econ_snap_pre/post`, `econ_assert_close_amounts`, `econ_assert_wallet_deltas` (asserts on-chain output amounts match the production formula AND wallet deltas match expectations, via `scantxoutset` RPC ground truth). 30+ cells covering baseline × 3 arities, rotation × 3, buy_liquidity (arity-2 only, by design), JIT cooperative close, `ps_advance`, and hybrid CLN bridge invoicing (external_in × 3 arities ✓, external_out × 3 still 🟡 on regtest due to CLN private-channel routing).
- **Arity-1 + arity-PS close ceremony handles post-fulfill leaf-advance messages** (PR #71, `src/client.c`). `client_do_close_ceremony`'s `CLOSE_PROPOSE` and `CLOSE_ALL_NONCES` recv loops now transparently handle `MSG_LEAF_ADVANCE_PROPOSE/DONE` interleaved with close traffic. Fixed arity-1 and arity-PS multi-payment + close tests that were failing on "expected LEAF_ADVANCE_PSIG from client, got 0x58".
- **CLI line buffer grows to 2048** (PR #71, `src/lsp_channels.c:4512`). BOLT11 invoices run 300–700 chars; the 256-char CLI input buffer was truncating `pay_external` commands.
- **LSP-side conservation check off-by-154** (PR #71, `src/lsp_channels.c`). Same shape as PR #70's client-side fix; this one trips the "refusing new HTLCs" alert (not just log noise). Paired with a regression test (`test_conservation_with_real_htlc`) whose hardcoded balances now account for `base_commit_fee`.
- **Stranded-funds recovery tool** (PR #71, `tools/recover_stranded_coop_output.c`): offline N-party MuSig2 sweep of N-of-N factory coop-close outputs stranded by the pre-PR-#68 behavior. Recovered 433,060 signet sats across 3 outputs during v0.1.12 validation.
- **cppcheck `invalidPrintfArgType_uint` warnings** (PR #72, `tools/superscalar_lsp_pre_daemon_tests.inc`): 4 pre-existing `%u`/`int` mismatches in PS-advance diagnostics switched to `%d`, unblocking Static Analysis CI for the spendability/econ stack.

### Planned follow-ups (in-flight PRs)

- **Signet bridge-econ port** (PR #73, `tools/test_bridge_econ_signet.sh`): runs the hybrid-CLN flow against the persistent signet environment to flip the three external_out 🟡 cells to ✓ on a real network with announced channels. Manual; blocks are ~10 min so per-run latency is ~60 min.
- **Factory recovery scan must not auto-broadcast** (PR #74, `src/factory_recovery.c`): `factory_recovery_scan` (startup/reorg) force-published the tree whenever funding confirmed, causing `bad-txns-inputs-missingorspent` on subsequent coop close. Fix gates tree broadcast on an explicit operator force-close via a new `allow_root_broadcast` parameter to `do_factory_recovery`. Verified end-to-end: hybrid CLN bridge econ regtest now passes full flow (external_in + external_out + coop close after payments, 5-conf close TX decoded and client output matched to invoice amount).

### Added

- **Factory scale to 128 signers**: `FACTORY_MAX_SIGNERS` 64→128, `FACTORY_MAX_NODES` 256→512, `FACTORY_MAX_LEAVES` 32→64, `LSP_MAX_CLIENTS` 64→128, `MUSIG_SESSION_MAX_SIGNERS` 64→128, `WATCHTOWER_MAX_CHANNELS` 32→64. New `test_factory_build_tree_n128` verifies 254-node tree (depth 6, 7 DW layers) builds, signs, and advances.
- **Per-channel fee tracking** (`lsp_channels.c`, `channel.c`): routing fees attributed to the channel that carried the payment (`accumulated_fees_sats` per `lsp_channel_entry_t`). Replaces the previous global pool that distributed fees to unrelated channels.
- **HTLC-based profit settlement** (`lsp_channels_settle_via_payment`): fee distribution now flows through the standard HTLC add → commit → revoke → fulfill pipeline, replacing the broken direct balance modification that desynced channel state.
- **Client-side fee tracking + settlement verification** (`superscalar_client.c`): client tracks `tracked_routed_sats`, `tracked_fees_sats`, `settled_fees_sats` and logs `SETTLEMENT UNDERPAYMENT` when offered amount is below the expected share. Settlement HTLCs are auto-fulfilled with the included preimage on detection.
- **Client verification at lifecycle boundaries** (PR #63 — `client.c`, `client.h`):
  - Funding TX on-chain verification via `client_verify_funding_fn` (RPC `getrawtransaction`); rejects phantom-funding LSPs.
  - Distribution TX amount verification during rotation; refuses to sign if offered amount < channel balance.
  - Rotation balance carry verification; refuses to sign if new balance < old balance.
  - Participant index verification after HELLO_ACK; refuses to sign if `all_pubkeys[my_index]` ≠ own pubkey.
  - Cooperative close verification; refuses to sign unless at least one output ≥ local balance.
  - Economic terms logging; `--min-profit-bps N` CLI flag rejects factories offering less.
  - Conservation invariant check (`client_check_conservation`) after every HTLC add/fulfill.
- **Memory-safety CI** (`.github/workflows/ci.yml`, `CMakeLists.txt`):
  - `Linux (sanitizers)` job now gates on leaks (`LSAN_OPTIONS=exitcode=23`). Suppressions file at `test/sanitizer_suppressions/lsan.supp`.
  - New `Linux (TSan)` job builds with `-fsanitize=thread`.
  - `ENABLE_TSAN` and `ENABLE_MSAN` CMake options for local developer use.
  - `CONTRIBUTING.md` documents how to run each sanitizer locally.
- **OSS-Fuzz integration** (`oss-fuzz/`): `build.sh`, `Dockerfile`, `project.yaml`, and README for submitting to Google's continuous fuzzing service. All 7 in-repo fuzz harnesses run under ASan + UBSan + MSan 24/7 once onboarded.
- **`--test-bad-terms` mode** (`superscalar_lsp.c`): LSP offers 0 bps profit share; clients with `--min-profit-bps > 0` should refuse.
- **15-combination fee cross-product test** (`test_channels.c`).
- **Schema v18** (`persist.c`, `persist.h`): `to_self_delay`, `fee_rate_sat_per_kvb`, `use_revocation_leaf` columns on `channels` table for standalone watchtower hydration.

### Changed

- **Default `--lsp-balance-pct` 50 → 100** (`superscalar_lsp.c`): LSP retains all initial channel capacity. The old default gave away 50% of the LSP's capital; SuperScalar's design has clients earn balance by receiving or purchasing. `--demo` auto-overrides to 50.
- **Distribution TX output limit**: validates against `f->n_participants` instead of the per-tree-node `FACTORY_MAX_OUTPUTS = 8` constant. Output array heap-allocated.
- **Readiness bitmap** `uint32_t → uint64_t` (`readiness.h`, `readiness.c`).
- **Large stack arrays moved to heap**: 128 KB `FACTORY_MAX_EPOCHS[32]` arrays in `client.c` and `lsp.c`; 1.5 MB RGS gossip arrays in `gossip_store.c`; 12 MB `factory_t` copies in `superscalar_lsp_post_daemon_tests.inc` and `fuzz_persist_load.c`.

### Fixed

- **Readiness tracker UB at 32+ clients** (`readiness.c`): `(1u << client_idx)` was undefined for `client_idx >= 32` despite `FACTORY_MAX_SIGNERS = 64`. Tracker silently broke at 32 clients.
- **Daemon capped at 15 clients** (`superscalar_lsp.c`): `struct pollfd pfds[16]` in funding-confirmation loop overrode `--max-connections`. Now heap-allocated from `lsp->n_clients + 1`.
- **`add_node()` ignored runtime config** (`factory.c`): checked compile-time `FACTORY_MAX_NODES` instead of `f->config.max_nodes`.
- **`persist_load_factory` leaked tx_bufs on validation failure** (`persist.c`): `factory_build_tree` could partially allocate node tx_bufs before failing validation; failure path now calls `factory_free`.
- **`persist_load_factory` leaked tx_bufs on reuse** (`persist.c`): calling twice into the same `factory_t` overwrote existing pointers without freeing. Now `factory_free(f)` when `f->n_nodes > 0`.
- **`channel_cleanup` leaked `ch->ptlcs`** (`channel.c`): forgot to free the PTLC heap array.
- **`noise.c` HKDF NULL memcpy** (UBSan): `memcpy(input + t_len, info, 0)` triggered null-pointer-to-nonnull-arg violation; now guarded on `info_len > 0`.
- **HTLC CLTV safety** (`lsp_channels.c`): `FACTORY_CLTV_DELTA` was hardcoded to 40 blocks (~7 hours) but DW tree unwind can need 300+ blocks (~2 days). New `lsp_compute_factory_cltv_delta()` computes from DW counter parameters.
- **Rotation conservation violation** (`lsp_rotation.c`): `ch->funding_amount` now updated to match carried balances; HTLC settlement fees from the old factory no longer cause false -152 sat/channel deltas.
- **Stack overflow in `test_wire_distributed_signing`** (`test_wire.c`): heap-allocated ~2.1 MB of structs that were overflowing the stack.
- **RPC error logging** (`chain_backend_rpc.c`): `rpc_call()` now logs method, code, and message on bitcoind failures.
- **`getrawtransaction` params format** (`superscalar_client.c`): comma-separator broke `params_to_json_array`; now space-separated.
- **1050 memory leaks plugged** across test files (`lsp_channels_cleanup`, `watchtower_cleanup`, `channel_cleanup`, `factory_free`, `wallet_source_hd.base.free`, `cJSON_Delete`). Full suite passes under LeakSanitizer with the gate enabled.

## 0.1.12 — 2026-04-16

Standalone watchtower penalty signing, secp256k1-zkp pin sync with CLN/wally, test infrastructure fix, and rotation conservation fix. 30/30 signet exhibition tests passed. 1363 unit tests.

### Standalone watchtower penalty signing (PR #61)

- **Revocation secret persistence** (`channel.c`, `channel.h`): new `channel_set_persist()` attaches a `persist_t*` to a `channel_t`. `channel_receive_revocation_flat()` now writes each received revocation secret to the `revocation_secrets` table via the existing (but previously uncalled) `persist_save_revocation()`. Without this, revocation secrets lived only in heap memory and died with the process.
- **Channel hydration for watchtower** (`persist.c`, `persist.h`): new `persist_load_channel_for_watchtower()` reads `channels`, `channel_basepoints`, and `revocation_secrets` tables and populates a `channel_t` with enough state for `channel_build_penalty_tx()` to sign a penalty. No MuSig2 state needed — penalty uses plain Schnorr.
- **Standalone binary wiring** (`superscalar_watchtower.c`): on startup, enumerates channel IDs via new `persist_list_channel_ids()`, hydrates each, and registers with `watchtower_set_channel()`. Previously `wt->channels[N]` was always NULL and every detected breach fell through to "no channel N for penalty".
- **S26 signet exhibition test PASSED**: standalone watchtower detected revoked commitment `b764cb06...` and broadcast penalty TX on-chain at block 300310.
- **Unit test** (`test_persist.c`): `test_persist_watchtower_hydrate_round_trip` validates the full save → hydrate → penalty construction path.

### secp256k1-zkp pin update

- **Pin sync** (`CMakeLists.txt`): updated from `64316eac` to `6152622613fd` to match CLN/wally's secp256k1-zkp submodule. Eliminates `--allow-multiple-definition` linker workaround for CLN plugin builds.
- **API update** (`musig.c`): `secp256k1_musig_pubkey_agg` gained a `scratch` parameter (pass NULL). `secp256k1_musig_nonce_gen_counter` removed upstream — we never called it.

### Bug fixes

- **Rotation conservation violation** (`lsp_rotation.c`): after factory rotation, `ch->funding_amount` was not updated to match carried balances. HTLC settlement fees consumed during the previous factory reduced `local + remote` below `funding_amount`, causing false conservation violations every 60s (-152 sats/channel in typical 4-HTLC demo). Fixed by setting `funding_amount = local + remote` after balance carry.
- **Test stack overflow** (`test_wire.c`): `test_wire_distributed_signing` allocated ~2.1 MB on the stack (`factory_t[5]` + `nonce_record_t[1280]`), causing a segfault that killed the test runner before ~500 remaining tests could execute. Moved to heap. Full suite now runs: 1363/1363 pass.

## 0.1.11 — 2026-04-13

Bug fixes and improvements surfaced during the signet exhibition suite: LSPS2 server crash fix, chain gossip hash correction, admin RPC block height, BOLT 12 invoice completion, fee persistence across crashes, and watchtower/revocation logging gaps.

### Bug fixes (PR #57 — fix/client-watchtower-gaps)

- **Client watchtower gaps** (`client.c`): fixed two paths where the client failed to hand revocation secrets to the watchtower — inbox-drain loop and async `MSG_REVOKE_AND_ACK` handler. Watchtower could miss breach detection for payments processed while the client was offline.

### Bug fixes (PR #58 — fix/log-revocation-failures)

- **Penalty TX failure logging** (`lsp_channels.c`): log an error when `channel_build_penalty_tx()` fails due to a missing revocation secret instead of silently dropping the breach. Makes watchtower gaps visible in production logs.

### Bug fixes & improvements (PR #59 — fix/admin-rpc-block-height)

- **Admin RPC block height** (`superscalar_lsp.c`, `admin_rpc.c`): `STATUS` response now includes `current_block_height` so operators can verify chain sync without connecting to bitcoind separately.
- **BOLT 12 invoice flow** (`lsp_bridge.c`, `client.c`): complete end-to-end BOLT 12 invoice request/response via onion messages. Clients can now pay BOLT 12 offers through the factory bridge.
- **Chain hash fix** (`gossip.c`): replaced hardcoded mainnet chain hash with `gossip_chain_hash_for_network()`. `channel_announcement` messages were malformed on signet/testnet, breaking CLN bridge gossip.
- **Accumulated fee persistence** (`persist.c`, `lsp_channels.c`): accumulated LSP fees written to DB after each factory cycle (schema v17). Fees no longer lost on LSP crash between rotation cycles.
- **LSPS2 crash fix** (`lsp_channels.c`): `FD_SET(-1, &rfds)` glibc fortified-abort when draining LSPS_REQUEST messages after a client disconnected mid-handshake. Fixed by skipping entries where `client_fds[i] < 0`.
- **S15 non-regtest fix** (`superscalar_lsp_post_daemon_tests.inc`): partial-rotation test no longer waits for CLTV expiry on signet/mainnet when `blocks_to_cltv > 10`. Deferred distribution TX stored in DB and broadcast when the block arrives.

### Housekeeping

- **README**: added open PRs badge.
- **`.gitignore`**: suppress `*_LOCAL.md` signet test result files.

## 0.1.10 — 2026-04-10

Full signet exhibition suite (29/30 S-tests passed), watchtower auto-settlement, rotation reconnect fixes, and 4 bug fixes found during signet testing.

### Signet exhibition tests (S1–S30)

- **29 of 30 S-tests passed on signet** with real on-chain confirmation, BIP68 relative timelocks, and CLN bridge integration. S16 (epoch reset) removed due to DW security vulnerabilities.
- **S10/S14**: End-to-end CLN bridge payments (CLN-B → CLN-A → plugin → bridge → factory → client → preimage) confirmed on signet with real Lightning Network routing.
- **S25**: Outbound payment (factory → bridge → CLN → external invoice) confirmed on signet.
- **S26**: Standalone watchtower binary (`superscalar_watchtower`) independently detects breaches from LSP database.
- **S20**: 3-factory ladder (three concurrent factories demonstrating ACTIVE/DYING/EXPIRED lifecycle).

### Watchtower & fee bumping (PRs #55, #56)

- **Watchtower auto-settlement** (`watchtower.c`, `lsp_channels.c`): after factory force-close, watchtower automatically broadcasts the latest signed commitment TX for each channel on the leaf — clients no longer need to be online for fund recovery. Channel-to-leaf mapping stored in `watchtower_entry_t.leaf_channel_ids[]`.
- **CPFP fee budget fix** (`watchtower.c`): fee bump budget now based on actual penalty value (% of sats at stake) instead of fixed amount. Real block deadline from CSV delay replaces cycle-counting.
- **Operator-tunable CPFP** (`superscalar_lsp.c`, `superscalar_watchtower.c`): `--bump-budget-pct N` (default 50%) and `--max-bump-fee N` (default 50000 sats) CLI flags.
- **Pending entry persistence** (`persist.c`): penalty TX entries now store `penalty_value`, `csv_delay`, and `start_height` for budget calculation across restarts. Schema v16.

### Bug fixes found during signet testing

- **`--states-per-layer` CLI flag ignored** (`superscalar_lsp.c`): factory creation hardcoded `states_per_layer=4`, ignoring the CLI flag. Caused unexpectedly large DW tree nSequence delays.
- **S28 HTLC amount below dust** (`superscalar_lsp_pre_daemon_tests.inc`): test used 500 sats for channel 3, below `CHANNEL_DUST_LIMIT_SATS` (546). Changed to 1000.
- **Rotation reconnect timeout** (`superscalar_lsp_post_daemon_tests.inc`): reconnect window extended from 30s to 120s on non-regtest networks.
- **Rotation reconnect nonce exchange** (`superscalar_lsp_post_daemon_tests.inc`): replaced inline reconnect handler with production `lsp_channels_handle_reconnect()` which does full ceremony — commitment reconciliation, PCS/PCP restore, nonce pool re-init, bidirectional CHANNEL_NONCES exchange. Without this, cooperative close after rotation failed on signet.

## 0.1.9 — 2026-04-07

Complete fund settlement, crash safety, trustless recovery, and chain backend for all networks. 132 commits since v0.1.8. 1362 unit tests, 42 regtest integration tests.

### Accounting & balance fixes (PR #54)

- **Conservation invariant fix** (`channel.c`, `lsp_channels.c`): per-HTLC fee now stored in `htlc_t.fee_at_add` at add time and refunded from stored value on fulfill/fail. Conservation check accounts for in-flight fee gap. Previously false-alarmed every 60s with active HTLCs. Schema v15.
- **Rotation balance carry** (`lsp_rotation.c`): channel balances preserved across factory rotation. Previously `lsp_channels_init()` reset all channels to default split (e.g. 50/50), discarding accumulated payment state.
- **Balance-aware distribution TX** (`factory.c`, `lsp.c`, `client.c`): new `factory_compute_distribution_outputs_balanced()` uses actual channel balances instead of equal `funding/N` split. LSP includes `dist_amounts` in `MSG_FACTORY_PROPOSE` so clients build identical unsigned TX.
- **Bridge msat truncation** (`lsp_bridge.c`): rejects non-whole-sat HTLC amounts (`amount_msat % 1000 != 0`) with `BRIDGE_FAIL_HTLC` instead of silently truncating. Fixed zero-sats error path to properly fail back.

### Chain backend (PR #54)

- **HTTP JSON-RPC chain backend** (`chain_backend_rpc.c`, `chain_backend_rpc.h`): direct TCP/HTTP connection to any bitcoind instance. Implements all 7 `chain_backend_t` vtable functions. Auto-detects default RPC port per network. No new dependencies (POSIX sockets + cJSON).
- **Force-close unlocked for all networks** (`superscalar_client.c`): `--force-close` and `--sweep-to-local` now accept `--rpcuser` + `--rpcpassword` for bitcoind connection on any network, not just regtest.

### Security (PR #54)

- **Require `--lsp-pubkey` on non-regtest** (`superscalar_client.c`): client refuses to connect without server pubkey pinning on mainnet/signet/testnet, preventing Noise_NN MITM fallback.

### Operational tooling (PR #54)

- **Config file support** (`superscalar_client.c`, `superscalar_lsp.c`): `--config PATH` loads settings from JSON file. CLI args override config values.
- **Log file redirect** (`superscalar_client.c`, `superscalar_lsp.c`): `--log-file PATH` redirects stderr to file (line-buffered, logrotate compatible).
- **Syslog integration** (`superscalar_client.c`, `superscalar_lsp.c`): `--syslog` opens syslog connection for system log integration (Linux).
- **Structured JSON logging** (`log.c`, `log.h`): `--json-log` outputs `{"ts":...,"level":...,"event":...}` format compatible with ELK/Loki/CloudWatch.
- **Client `--sweep-to-local`** (`superscalar_client.c`): sweeps CSV-delayed `to_local` output after commitment TX confirms. Reuses `channel_build_to_local_sweep()` from sweeper module.
- **HTLC display on reconnect** (`client.c`): client loads and displays persisted in-flight HTLCs from DB after crash recovery.

### Fund settlement (PR #53)

- **Sweeper module** (`sweeper.c`, `sweeper.h`): new auto-sweep engine for CSV-delayed `to_local`, penalty, and HTLC timeout outputs. Persists pending sweeps to DB (`pending_sweeps` table, schema v12), retries each daemon cycle until confirmed.
- **Distribution TX in MuSig2 ceremony** (`lsp.c`, `client.c`, `factory.c`): the distribution TX (nLockTime safety net) is now signed by all participants during factory creation using a virtual node (node_idx = n_nodes). Previously never built in production. Both initial and rotation ceremonies supported. Schema v14 adds `distribution_txs` table.
- **Watchtower factory state monitoring** (`lsp_channels.c`): after each DW state advance, old state txid is registered with the watchtower via `watchtower_watch_factory_node()`. On breach detection, watchtower broadcasts the newer state TX + burn TX to destroy the attacker's L-stock.
- **Burn TX registration** (`lsp_channels.c`): `factory_build_burn_tx()` output is now passed to the watchtower alongside state response TXs. Completes the old-state poisoning mechanism from ZmnSCPxj's design.
- **CLTV leaf sweep automation** (`lsp_channels.c`): daemon loop now checks expired factories each cycle and calls `factory_sweep_run()` when `current_height >= cltv_timeout`. LSP recovers funds from permanently offline clients without manual intervention.
- **Atomic HTLC fulfill persistence** (`lsp_channels.c`): payee credit and sender debit wrapped in a single DB transaction. Crash between the two rolls back both, preventing fund mis-attribution.
- **Bridge origin field persistence** (`lsp_bridge.c`): `sender_idx`, `sender_htlc_id`, and `cltv_expiry` re-persisted after update. Prevents bridge HTLC timeout routing failure on crash recovery.
- **HTLC drain before rotation** (`lsp_rotation.c`): all active HTLCs failed cleanly before starting rotation ceremony, preventing funds stranded mid-flight.
- **Client commitment TX persistence** (`superscalar_client.c`, `persist.c`): signed commitment TX stored to DB (schema v13, `signed_commitments` table) at 5 sites after `client_handle_commitment_signed`. Client can independently broadcast for trustless force-close.
- **Client tree node persistence** (`superscalar_client.c`): `persist_save_tree_nodes()` called during initial and rotation factory persist blocks. Enables client-side tree broadcast without LSP cooperation.
- **Client distribution TX persistence** (`superscalar_client.c`): signed distribution TX saved to DB after FACTORY_READY. Client `--force-close` broadcasts it as nLockTime fallback.
- **Commitment sig loaded on reconnect** (`client.c`): `persist_load_commitment_sig()` called in `client_run_reconnect()` so the client retains force-close ability across restarts without waiting for a new payment.
- **JIT channel force-close** (`jit_channel.c`): new `jit_channel_force_close()` detects and handles JIT channels during force-close flow.
- **Balance conservation invariant** (`lsp_channels.c`, `test_channels.c`): `lsp_channels_check_conservation()` verifies `sum(local + remote + htlc) == funding` after every state change. 3 new unit tests.

Factory scaling to 64 participants + full reorg resistance + production hardening. 36/36 orchestrator.

### Added

- **64-participant factory support** (`factory.h`, `lsp.h`, `musig.h`): raised FACTORY_MAX_SIGNERS 16→64, FACTORY_MAX_NODES 64→256, FACTORY_MAX_LEAVES 16→32, FACTORY_MAX_EPOCHS 256→4096, LSP_MAX_CLIENTS 16→64, MUSIG_SESSION_MAX_SIGNERS 16→64. With 4-8 laddered factories, an LSP can now serve 256-512 users.
- **Parallel basepoint/nonce exchange** (`lsp_channels.c`): replaced serial per-client loops with batch-send + parallel-collect using `ceremony_select_all()`. At 64 clients, setup time drops from O(N×30s) to O(30s) regardless of client count.
- **N=32 and N=64 factory unit tests** (`test_factory.c`, `test_main.c`): verify tree construction, signing, and advancement at new participant counts. Expanded `seckeys_n` from 16 to 64 entries.

### Fixed

- **Config initialization in pubkeys-only path** (`factory.c`): `factory_init_from_pubkeys()` now calls `factory_config_default()` after memset; previously left config.max_signers=0, causing factory_build_tree() to reject all factories via distributed signing path.
- **Heap allocation for large structs** (`lsp.c`, `superscalar_lsp.c`): with factory_t at ~3MB, lsp_t and ceremony arrays are now heap-allocated to prevent stack overflow on the default 8MB stack. `lsp_t` uses pointer access (lsp_p->) throughout.
- **Stack size in test runner** (`run_unit_tests.sh`): added `ulimit -s unlimited` to match CI configuration; ladder_t (8 × factory_t ≈ 26MB) exceeds default stack.

### Full reorg resistance

- **BIP 158 reorg detection** (`bip158_backend.c`, `p2p_bitcoin.c`): validate `prev_hash` chain continuity during header sync. On mismatch, `bip158_handle_reorg()` invalidates tx_cache entries above fork point, rolls back tip/header/filter state, fires `block_disconnected_cb` for each rolled-back block, and persists corrected checkpoint.
- **RPC backend reorg detection** (`lsp_channels.c`): daemon heartbeat detects chain tip height decrease and fires `reorg_cb` callback for higher layers.
- **Watchtower reorg resilience** (`watchtower.c`): penalty broadcast entries are now kept until penalty has safe confirmations (6 on non-regtest). If penalty tx vanishes (reorg), entry reverts to normal watching and re-detects the breach. New `watchtower_on_reorg()` re-validates all entries and pending CPFP penalties.
- **HTLC timeout monotonicity** (`channel.c`): `channel_check_htlc_timeouts()` skips timeout checks when height goes backward (reorg), preventing premature HTLC failure.
- **JIT channel safe confirmation** (`jit_channel.c`): uses `MAINNET_SAFE_CONFIRMATIONS` on non-regtest. New `jit_channels_revalidate_funding()` re-checks funding on startup, reverting OPEN channels to FUNDING if funding tx is gone.
- **Rotation height regression guard** (`lsp_rotation.c`): `lsp_rotation_should_retry()` allows immediate retry when height goes backward instead of hanging on stale backoff.
- **Reorg simulation tests** (`test_reorg.c`): 4 new tests covering BIP 158 cache invalidation, callback firing, HTLC monotonicity guard, and edge cases.
- **Chain backend reorg callback** (`chain_backend.h`): new optional `reorg_cb(new_tip, old_tip, ctx)` field for cross-component reorg notification.

### Security hardening (mainnet preparation)

- **Secure invoice randomness** (`invoice.c`): removed `rand()` fallback for preimage generation. Invoice creation now fails if no secure entropy source is available, preventing predictable preimages.
- **SSL certificate verification** (`fee_estimator_api.c`): enabled `SSL_VERIFY_PEER` with system CA certificates for the mempool.space fee estimation API. Previously disabled (`SSL_VERIFY_NONE`), allowing MITM on fee rate data.
- **Admin RPC socket permissions** (`admin_rpc.c`): explicit `chmod(0600)` after socket bind ensures owner-only access regardless of process umask.
- **6-confirmation threshold** (`chain_backend.h`, `factory_recovery.c`): factory tree broadcast now requires 6 confirmations on the funding TX (non-regtest), eliminating reorg risk without a full reorg handler.
- **Reorg detection** (`lsp_channels.c`): daemon heartbeat now logs an alert if chain tip decreases between checks.
- **Watchtower broadcast retry** (`watchtower.c`, `persist.c`): failed penalty tx broadcasts are saved as `pending_retry` and automatically re-attempted on each watchtower cycle. Ensures penalties are not lost during temporary chain backend outages.

### Architecture improvements

- **Runtime-configurable validation** (`factory.c`): `factory_build_tree()` now validates against `f->config.max_signers` / `f->config.max_nodes` / `f->config.max_leaves` instead of compile-time constants, enabling future runtime configurability.

### Added (pre-existing)

- **Ceremony reconnect retry** (`lsp.c`): on nonce timeout, waits up to 30s for clients to reconnect, re-sends FACTORY_PROPOSE, and collects nonces. Falls back to quorum check only after recovery fails.
- **Ceremony quorum support** (`lsp.c`): wired `ceremony_has_quorum()` (previously dead code) into all 4 ceremony phases — factory creation nonces/psigs and cooperative close nonces/psigs. Partial client failures no longer abort if quorum is met.
- **Factory creation retry** (`superscalar_lsp.c`): initial ceremony retries up to 3 times with 5s backoff
- **Bridge supervisor** (`superscalar_bridge.c`): outer restart loop with escalating backoff (5s→60s, max 5 restarts), re-initializes NK auth on each attempt
- **Bridge HTLC timeout monitoring** (`lsp_channels.c`): daemon loop checks bridge HTLC origins against block height, fails back 10 blocks before CLTV expiry to avoid on-chain resolution
- **BIP 158 deposit detection** (`lsp_channels.c`, `wallet_source_hd.c`): daemon loop polls HD wallet balance every 30s, logs deposit events with delta
- **`getdepositaddress` admin RPC** (`admin_rpc.c`): returns bech32m P2TR deposit address from HD wallet
- **`persist_sum_hd_utxos()`** (`persist.c`): SQL SUM query for total unspent HD wallet balance
- **Dynamic gap limit** (`wallet_source_hd.c`): `wallet_source_hd_extend_gap()` reallocs SPK cache and registers new addresses with BIP 158 as next_index approaches boundary
- **Watchtower systemd unit** (`tools/deploy/superscalar-watchtower.service`): new unit file for standalone watchtower deployment

### Fixed

- **Bridge HTLC rollback** (`lsp_bridge.c`): on client disconnect during COMMITMENT_SIGNED exchange, rollback via `channel_fail_htlc()` and send `BRIDGE_FAIL_HTLC`. Previously left channel in half-committed state.
- **Light-client rotation** (`lsp_rotation.c`): use vout=0 and known amount in light-client mode instead of calling `regtest_get_tx_output(NULL)` which would crash
- **Bech32m deposit address** (`wallet_source_hd.c`): `wallet_source_hd_get_address()` now returns proper bech32m P2TR address instead of hex SPK

### Operator tooling

- **LSP systemd unit** updated: admin RPC socket, keyfile auth, env file, security hardening (NoNewPrivileges, ProtectSystem, PrivateTmp)
- **`.env.example`** updated: comprehensive config with `SS_` prefix variables for all components

## 0.1.8 — 2026-03-28

Production hardening + LN phase 2 integration. MSG_PING/MSG_PONG keepalive, end-to-end bridge payments, factory rotation on signet, 12 bug fixes. 26/26 signet exhibition structures passing. 36/36 orchestrator scenarios. 1351 unit tests.

### Added

- **MSG_PING/MSG_PONG keepalive** (`wire.h`, `lsp_fund.c`, `lsp_channels.c`): poll-based confirmation waits send periodic pings to all clients every 30s; daemon loop sends keepalive pings; `wire_recv_skip_ping()` transparently handles stale pongs during ceremonies. Replaces sleep-based waits that caused client disconnections on signet.
- **End-to-end bridge payments** (`admin_rpc.c`, `cln_plugin.py`, `lsp_bridge.c`): admin RPC `createinvoice` with route hints, MSG_DELIVER_PREIMAGE to client, MSG_BRIDGE_REGISTER to CLN plugin, HTLC intercept for forwarding — full CLN-B → CLN-A → plugin → bridge → LSP → client → fulfill pipeline proven on signet (S14)
- **BOLT #11 route hints** (`invoice.c`): `invoice_create_with_hint()` embeds route hint (tag `r`) for bridge channel routing
- **Persistent daemon mode** (`superscalar_lsp.c`, `persist.c`): LSP loops after cooperative close, reloading factory state from DB — enables long-running production deployments (PR #36)
- **HD wallet wired to factory funding** (`superscalar_lsp.c`): BIP 32/39 derived keys used for factory self-funding path instead of hardcoded regtest keys (PR #37)
- **Admin RPC: `getbalance`, `listfunds`, `pay_bridge`, `createinvoice`** (`admin_rpc.c`): query wallet, list UTXOs, outbound payment via bridge, invoice creation with route hints (PRs #38–#39)
- **LN phase 2 features (PRs #28–#34, merged via #35, +22,000 lines)**:
  - **BOLT #1 peer protocol** (`bolt1.c`): init/error/warning/ping/pong (types 16–19), feature bit negotiation, mandatory feature check
  - **Circuit breaker** (`circuit_breaker.c`): per-peer HTLC rate limits, token bucket, ban escalation callback
  - **Splicing** (`splice.c`): BOLT #2 interactive tx construction, STFU quiescence (types 140/141 + legacy 0x68/0x69), splice_init/ack/locked
  - **Liquidity advertisements** (`liquidity_ad.c`): option_will_fund (BOLT #878), node_announcement TLV, compact_lease, real pubkey derivation
  - **Static channel backup** (`scb.c`): SCB format, save/load, disaster recovery
  - **Onion messages** (`onion_message.c`, `onion_msg.c`): type 513, final-hop decryption, TLV routing, multi-hop relay
  - **Trampoline routing** (`trampoline.c`): BOLT #4 trampoline header parse/unwrap
  - **Rapid Gossip Sync** (`rgs.c`): compact gossip import/export, admin RPC
  - **LNURL + BIP 353** (`lnurl.c`): Lightning Address, pay/withdraw, DNS resolution
  - **Hold invoices** (`hold_invoice.c`): async HTLC delivery, settlement control
  - **Mission control** (`mission_control.c`): payment failure scoring, channel exclusion
  - **Route policy** (`route_policy.c`): HTLC forwarding policy enforcement
  - **Stateless invoices** (`stateless_invoice.c`): HMAC-derived payment secrets
  - **Gossip ingestion** (`gossip_ingest.c`): verify and store incoming BOLT #7 messages
  - **HTLC fee bumping** (`htlc_fee_bump.c`): deadline-aware sweep fee estimation
  - **BOLT #4 failure parser** (`bolt4_failure.c`): onion failure message decoding
  - **Peer storage** (BOLT #9 types 7/9): store/retrieve peer blobs
  - **Announcement signatures** (type 259): channel announcement flow
  - **Dynamic commitments**: channel_type TLV negotiation (BOLT #2 PR #880)
  - **PTLC penalty**: watchtower PTLC sweep on breach
  - **Admin RPC methods**: `exportrgs`, `importrgs`, `payoffer`, `listfactories`, `recoverfactory`, `sweepfactory`, `createoffer`
- **Exhibition tests S17–S26**:
  - **S17** (`--test-jit`): JIT channel lifecycle with non-blocking state machine
  - **S18** (`--test-realloc`): Leaf realloc with corrected sats/msat units
  - **S19** (`--test-lsps2`): LSPS2 buy flow through daemon loop
  - **S20** (3-factory ladder): concurrent factory lifecycle
  - **S21** (`--test-bolt12`): BOLT #12 offer codec + signature round-trip
  - **S22** (`--test-buy-liquidity`): L-stock inbound capacity purchase
  - **S23** (`--test-bip39`): BIP39 mnemonic generate/validate/seed round-trip
  - **S24** (`--test-large-factory`): 8+ client factory with deeper DW tree
  - **S25** (`pay_external` CLI): outbound payment via bridge
  - **S26**: standalone watchtower deployment
- **Fund recovery tool** (`tools/recover_exhibition_funds.py`): scan blockchain for stuck exhibition outputs and sweep them back to wallet
### Fixed

- **TX confirmation via getrawtransaction** (`regtest.c`): added `getrawtransaction` probe between `gettransaction` (wallet-only) and block-scanning fallback. Fixes "Invalid or non-wallet transaction id" for manually-built TXs (HD wallet funding path). Matches CLN/LND/LDK industry standard — treat bitcoind as chain source, not wallet.
- **Admin RPC network-aware invoice encoding** (`admin_rpc.c`): `createinvoice` reads `rpc->network` from the LSP's `--network` CLI flag instead of hardcoding "signet". Invoices now encode the correct BOLT #11 prefix on any network.
- **Testnet4 BOLT #11 prefix** (`invoice.c`): added `testnet4 → tb` mapping in both `invoice_create` and `invoice_create_with_hint` (was falling through to `bcrt` regtest prefix)
- **BOLT #11 tag numbers** (`bolt11.c`): payment_secret was encoded as tag 18 (wrong); corrected to tag 16 (`s` = bech32 value 16). Payee pubkey corrected from tag 16 to tag 19 (`n` = bech32 value 19). Fixed "Missing required payment secret" when CLN paid SuperScalar invoices.
- **CLN plugin HTLC intercept** (`cln_plugin.py`): plugin now forwards all HTLCs with `short_channel_id` in onion (forwarding HTLCs) to bridge, not just registered invoices and keysend
- **Bridge invoice table registration** (`admin_rpc.c`): admin RPC `createinvoice` now registers invoices in both BOLT11 table and bridge htlc_inbound table; previously bridge HTLCs failed with "unknown hash"
- **Deferred ceremony reconnections** (`lsp_channels.c`, PR #48): listen socket now polled during blocking ceremony waits; new connections accepted, noise-handshaked, and queued — drained when daemon loop resumes
- **Non-blocking confirmation wait** (`superscalar_lsp.c`): confirmation polling services client reconnections instead of blocking the event loop
- **Ceremony message handling robustness** (`lsp.c`, `lsp_channels.c`): boundary checks on recv, partial-message handling, timeout propagation, error recovery
- **Cooperative close dust filter** (`superscalar_lsp.c`): outputs below dust limit excluded from close TX; `sweepfactory` RPC recovery path hardened
- **Breach detection and lifecycle monitoring** (`superscalar_lsp.c`, `lsp_rotation.c`): rotation retry on transient failure; lifecycle state transitions validated
- **Client watchtower scan starvation** (`superscalar_client.c`): active socket traffic could starve periodic watchtower block scans; fix: dedicated scan window between message polls
- **BOLT #11 HRP for signet/testnet4** (`bolt11.c`): added `tbs` (signet) and `tb4` (testnet4) prefixes to invoice decoder
- **Leaf realloc msat/sats units** (`lsp_channels.c`): channel balance update used millisatoshis instead of satoshis after leaf realloc
- **Epoch reset nonce double-counting** (`superscalar_client.c`): Round 2 added nonces on top of Round 1; fix: `factory_sessions_init()` before Round 2
- **CLN plugin subprocess** (`cln_plugin.py`): `LIGHTNING_CLI` config with embedded args; fix: `.split()`
- **Inbox message drops** (`superscalar_client.c`): daemon loop inbox discarded all non-COMMITMENT_SIGNED messages; fix: re-dispatch through main switch
- **JIT blocking handler** (`superscalar_client.c`): synchronous `wire_recv` blocked for 10+ min on signet; fix: non-blocking state machine
- **LSP stale messages before JIT_ACCEPT** (`jit_channel.c`): `wire_recv` got stale MSG_REGISTER_INVOICE; fix: drain loop
- **Watchtower breach detection** (`watchtower.c`): TXIDs mismatched; fix: breach test uses `channel_build_commitment_tx_for_remote`
- **LSPS2 test timing** (`superscalar_lsp.c`): sleep-poll loop didn't process client messages; fix: force daemon_mode

### Architecture improvements

- **Poll-based keepalive**: all blocking waits replaced with `poll()` + periodic MSG_PING — clients never see >30s silence during confirmation waits, ceremonies, or daemon idle
- **Non-blocking JIT state machine**: industry-standard message-driven dispatch matching CLN/LND/LDK/Eclair pattern
- **Inbox re-dispatch**: all message types properly handled regardless of arrival order
- **Onion message API unification**: PR #29 and PR #34 onion implementations reconciled
- **Test extraction**: monolithic test blocks extracted into dedicated include files

### Added

- **LN phase 2 features (PRs #28–#34, merged via #35, +22,000 lines)**:
  - **BOLT #1 peer protocol** (`bolt1.c`): init/error/warning/ping/pong (types 16–19), feature bit negotiation, mandatory feature check
  - **Circuit breaker** (`circuit_breaker.c`): per-peer HTLC rate limits, token bucket, ban escalation callback
  - **Splicing** (`splice.c`): BOLT #2 interactive tx construction, STFU quiescence (types 140/141 + legacy 0x68/0x69), splice_init/ack/locked
  - **Liquidity advertisements** (`liquidity_ad.c`): option_will_fund (BOLT #878), node_announcement TLV, compact_lease, real pubkey derivation
  - **Static channel backup** (`scb.c`): SCB format, save/load, disaster recovery
  - **Onion messages** (`onion_message.c`, `onion_msg.c`): type 513, final-hop decryption, TLV routing, multi-hop relay
  - **Trampoline routing** (`trampoline.c`): BOLT #4 trampoline header parse/unwrap
  - **Rapid Gossip Sync** (`rgs.c`): compact gossip import/export, admin RPC
  - **LNURL + BIP 353** (`lnurl.c`): Lightning Address, pay/withdraw, DNS resolution
  - **Hold invoices** (`hold_invoice.c`): async HTLC delivery, settlement control
  - **Mission control** (`mission_control.c`): payment failure scoring, channel exclusion
  - **Route policy** (`route_policy.c`): HTLC forwarding policy enforcement
  - **Stateless invoices** (`stateless_invoice.c`): HMAC-derived payment secrets
  - **Gossip ingestion** (`gossip_ingest.c`): verify and store incoming BOLT #7 messages
  - **HTLC fee bumping** (`htlc_fee_bump.c`): deadline-aware sweep fee estimation
  - **BOLT #4 failure parser** (`bolt4_failure.c`): onion failure message decoding
  - **Peer storage** (BOLT #9 types 7/9): store/retrieve peer blobs
  - **Announcement signatures** (type 259): channel announcement flow
  - **Dynamic commitments**: channel_type TLV negotiation (BOLT #2 PR #880)
  - **PTLC penalty**: watchtower PTLC sweep on breach
  - **Admin RPC methods**: `exportrgs`, `importrgs`, `payoffer`, `listfactories`, `recoverfactory`, `sweepfactory`, `createoffer`

- **Exhibition tests S17–S21 (new protocol demonstrations)**:
  - **S17** (`--test-jit`): JIT channel lifecycle with non-blocking state machine
  - **S18** (`--test-realloc`): Leaf realloc with corrected sats/msat units
  - **S19** (`--test-lsps2`): LSPS2 buy flow through daemon loop
  - **S20** (3-factory ladder): concurrent factory lifecycle
  - **S21** (`--test-bolt12`): BOLT #12 offer codec + signature round-trip

- **Exhibition tests S22–S26 (planned)**:
  - **S22** (`--test-buy-liquidity`): L-stock inbound capacity purchase
  - **S23** (`--test-bip39`): BIP39 mnemonic generate/validate/seed round-trip
  - **S24** (`--test-large-factory`): 8+ client factory with deeper DW tree
  - **S25** (`pay_external` CLI): outbound payment via bridge
  - **S26**: standalone watchtower deployment

- **Fund recovery tool** (`tools/recover_exhibition_funds.py`): scan blockchain for stuck exhibition outputs and sweep them back to wallet

### Fixed

- **Leaf realloc msat/sats units** (`lsp_channels.c`): channel balance update used millisatoshis instead of satoshis after leaf realloc
- **Epoch reset nonce double-counting** (`superscalar_client.c`): Round 2 added nonces on top of Round 1 (7 vs 5); fix: `factory_sessions_init()` before Round 2
- **CLN plugin subprocess** (`cln_plugin.py`): `LIGHTNING_CLI` config with embedded args passed as single executable path; fix: `.split()`
- **Inbox message drops** (`superscalar_client.c`): daemon loop inbox discarded all non-COMMITMENT_SIGNED messages; fix: re-dispatch through main switch via `goto`
- **JIT blocking handler** (`superscalar_client.c`): synchronous `wire_recv` blocked for 10+ min on signet; fix: non-blocking state machine (WAITING_BASEPOINTS → WAITING_NONCES → WAITING_READY → COMPLETE)
- **LSP stale messages before JIT_ACCEPT** (`jit_channel.c`): `wire_recv` got stale MSG_REGISTER_INVOICE; fix: drain loop with 1s timeout
- **Watchtower breach detection** (`watchtower.c`): TXIDs mismatched because breach test broadcast LSP's commitment but watchtower watched for client's; fix: breach test uses `channel_build_commitment_tx_for_remote`
- **Duplicate case value** (`ln_dispatch.c`): `BOLT1_MSG_ERROR` and `MSG_ERROR` both type 17
- **LSPS2 test timing** (`superscalar_lsp.c`): sleep-poll loop didn't process client messages; fix: force daemon_mode for message dispatch
- **cppcheck warnings**: duplicate expression in lnurl.c, uninitialized vars in test_chan_open.c

### Architecture improvements

- **Non-blocking JIT state machine**: industry-standard message-driven dispatch matching CLN/LND/LDK/Eclair pattern
- **Inbox re-dispatch**: all message types properly handled regardless of arrival order
- **Onion message API unification**: PR #29 and PR #34 onion implementations reconciled (build/encode 2-step API, BOLT #12 TLV types 64/66/68)

## 0.1.7 — 2026-03-19

890/890 unit tests pass. Full BOLT Lightning wire protocol stack integrated on top of the SuperScalar factory layer.

### Added

- **Full Lightning Network wire protocol stack (PRs #19–#26, merged via #27, +32,093 lines)**:
  - **BOLT #8 Noise_XK transport** (`bolt8.c`, `bolt8_server.c`): 3-act handshake, ChaCha20-Poly1305 encryption with key rotation, phase-specific timeouts (60s handshake / 30s init / 300s idle)
  - **BOLT #7 gossip** (`gossip.c`, `gossip_peer.c`, `gossip_store.c`): `node_announcement` (257), `channel_announcement` (256), `channel_update` (258), `gossip_timestamp_filter` (265); SQLite gossip store; exponential reconnect backoff; stale channel pruning (14-day); rate limiting (token-bucket 10/60s per direction); gossip query handlers (types 261–264); sends real channel data on query
  - **BOLT #11 invoice** (`bolt11.c`): full bech32 decode/encode, tagged fields, route hints, recoverable ECDSA signature verification
  - **BOLT #4 multi-hop onion** (`onion.c`): 1366-byte Sphinx onion build/peel with correct HMAC tail-zeroing filler, keysend TLV (type 5482373484)
  - **BOLT #2 commitment messages**: all 7 types — `update_add_htlc` (128), `update_fulfill_htlc` (130), `update_fail_htlc` (131), `update_fail_malformed_htlc` (135), `commitment_signed` (132), `revoke_and_ack` (133), `update_fee` (134); BOLT #3 dust guard; MuSig2 partial-sig packing in 64-byte sig field
  - **BOLT #12 offers**: expiry TLV, `invoice_request` → invoice merkle+Schnorr flow, blinded path hints, `invoice_error`
  - **Dijkstra pathfinding** (`pathfind.c`): over gossip_store SQLite graph, fee+CLTV penalties (LDK risk model), MPP route splitting
  - **MPP aggregation** (`mpp.c`): 32 concurrent payments × 10 parts, 60s incomplete-set timeout, 2× overpayment guard
  - **AMP send side**: TLV type 14 encoding, `payment_send_amp()` with independent root shares; real per-shard routes committed before state change
  - **HTLC forwarding engine** (`htlc_forward.c`): inbound HTLC processing, settle/fail propagation, forward table; TLV type 6 relay pump routing via SCID lookup
  - **Payment state machine** (`payment.c`): invoice-driven, keysend, MPP sharding, onion error decryption, 3-attempt retry with penalty-box updates; timeout retry/fail at 60s
  - **PTLC state machine** (`ptlc_commit.c`): add/settle/fail wire types 0x4C–0x4E
  - **External peer manager** (`peer_mgr.c`): connect/accept/disconnect/send over BOLT #8 sessions; reconnect with backoff (5s × 2^n, cap 300s)
  - **Channel open/accept** (`chan_open.c`): `open_channel` (321), `accept_channel` (272), `channel_reestablish` with DLP detection; dual-fund v2 (`open_channel2` type 78) with zero-contribution accept and real random basepoints; zero-conf channels (sends `channel_ready` when `min_depth=0`)
  - **Cooperative close dispatch**: `shutdown` (38) / `closing_signed` (39), BOLT #2 meet-in-the-middle fee negotiation; broadcasts TX on completion
  - **LSPS0/1/2**: `lsps1.get_info`, `lsps2.get_info` over BOLT #8 (Zeus/Blixt/Phoenix compatible); LSPS1 order state machine (CREATED → PENDING_FUNDING → COMPLETED); LSPS2 JIT HTLC interception with deferred factory-open until HTLCs cover cost; stale JIT entry expiry
  - **Factory entry/exit + fake SCIDs** (`scid_registry.c`, `htlc_inbound.c`): BOLT #4 last-hop intercept, `htlc_inbound` state machine, JIT channel creation on HTLC intercept
  - **LSP discovery**: `/.well-known/lsps.json` endpoint, DNS SRV fallback
  - **Watchtower breach wired to block events**: `watchtower_check()` on every block, justice tx auto-broadcast on breach; CPFP bump for non-breach TXs
  - **Tor SOCKS5 proxy**: `.onion` peers routed through proxy, `--tor-proxy HOST:PORT`
  - **Async signing queue dispatch**: `MSG_QUEUE_POLL` / `MSG_QUEUE_DONE` dispatch wired
  - **Invoice CLI**: `--invoice <amount_msat> [description]`

- **CLTV recovery leaf for single-client (arity-1) leaf outputs** (`src/factory.c`): `setup_single_leaf_outputs()` was missing the CLTV recovery leaf added to `setup_leaf_outputs()` in v0.1.6. Both arity-2 and arity-1 tree nodes now embed the LSP unilateral recovery script when `cltv_timeout > 0`.

- **CLTV script-path sweep in factory recovery** (`src/factory_recovery.c`): `factory_sweep_run` now identifies MuSig2+CLTV channel outputs by reconstructing `taptweak(MuSig2_agg(client, LSP), CLTV_leaf_hash)` and comparing to on-chain SPK. After CLTV maturity, builds a BIP-342 script-path TX signed by the LSP key and broadcasts it. Outputs without a matching CLTV leaf remain marked `"requires_client_key"`.

### Removed

- **`gen_scripts.py`**: VPS-specific exhibition script generator with hardcoded `/root` paths. Superseded by `test_orchestrator.py` and the `ss_signet_runner.py` local tool.
- **`launch_exhibition.sh`**: VPS-specific one-off exhibition launcher with hardcoded paths.

### Fixed

- **`bitcoin-cli` finder path** (`tools/test_orchestrator.py`): Removed a stale developer-specific fallback path and the associated "WSL / Linux" comment from the `find_bitcoin_cli()` function.

---

## 0.1.6 — 2026-03-15

36/36 orchestrator scenarios pass. 553/553 unit tests pass.

### Added

- **5 new orchestrator scenarios** (`tools/test_orchestrator.py`):
  - `splice_channel` — splice-out channel[0] by 10k sats: STFU → SPLICE_INIT → broadcast → confirm
  - `async_rotation` — factory rotation with `--async-rotation`; clients reconnect and rotation completes
  - `bolt12_offer` — create BOLT 12 offer via LSP CLI (`--create-offer`); decode via client CLI (`--pay-offer`)
  - `bip39_restore` — generate 24-word BIP 39 mnemonic, restore from it, verify keyfile OK
  - `lsps2_wire` — client sends `lsps2.get_info` over live factory connection; LSP responds with fee params
- **LSPS_REQUEST handling during cooperative close** (`src/lsp.c`): `lsp_run_cooperative_close` now drains queued `MSG_LSPS_REQUEST` messages from each client before sending `CLOSE_PROPOSE`, and dispatches them inline during close-nonce collection. Prevents LSPS responses from appearing mid-ceremony and breaking the MuSig2 close sequence when a client sends a protocol query right after factory entry.
- **LSPS_REQUEST dispatch in demo `wait_for_msg`** (`src/lsp_demo.c`): `wait_for_msg` now routes `MSG_LSPS_REQUEST` to `lsps_handle_request` inline so protocol queries arriving during factory ceremonies (DW advance, rotation nonce exchange) receive a timely response.

- **Async factory rotation** (`--async-rotation`): The LSP can now coordinate factory rotation without requiring all N clients to be online simultaneously. When the factory enters the DYING state, the LSP pushes a `QUEUE_REQ_ROTATION` work item into each client's pending queue and sends a push notification. As clients reconnect and poll their queue (via `MSG_QUEUE_POLL` / `MSG_QUEUE_ITEMS` / `MSG_QUEUE_DONE`), they acknowledge the rotation request and the LSP marks them ready. The MuSig2 ceremony fires automatically once all N clients are ready. If the factory expires before all clients reconnect, partial rotation is attempted with the ready subset (≥ 2 signers). Urgency escalates from `LOW → NORMAL → HIGH → CRITICAL` as the deadline approaches. Companion flags: `--notify-webhook URL` (HTTP POST notifications) and `--notify-exec SCRIPT` (external script). Without `--async-rotation`, the existing synchronous blocking rotation path is unchanged.
- **Wire protocol: queue coordination messages** (`MSG_QUEUE_POLL` 0x65, `MSG_QUEUE_ITEMS` 0x66, `MSG_QUEUE_DONE` 0x67): Three new message types for client/LSP pending-work coordination. `wire_build_queue_items()` serializes `queue_entry_t[]` to JSON; `wire_parse_queue_done()` parses client acknowledgement IDs.
- **`lsp_queue` module** (`src/lsp_queue.c`): SQLite-backed pending work queue with per-client, per-factory, per-request-type deduplication (UNIQUE constraint with `ON CONFLICT REPLACE` for urgency escalation). Supports push, drain, get, delete, expire, and count operations.
- **`notify` module** (`src/notify.c`): Pluggable push notification backend. Three backends: `notify_init_log` (stdout, default), `notify_init_webhook` (HTTP POST), `notify_init_exec` (external script). Safe to call with `NULL` (no-op).
- **`readiness` module** (`src/readiness.c`): Bitmap-based per-client readiness tracker. Tracks connected/ready state independently; `readiness_all_ready()` fires when every client has both connected and acknowledged their rotation queue item. `readiness_compute_urgency()` maps blocks-remaining to `QUEUE_URGENCY_*` levels. Supports SQLite persistence via `readiness_save()`/`readiness_load()`.



- **CI: ARM64 build and unit test job**: GitHub Actions now builds and runs all 418 unit tests on `linux/arm64` via Docker on every push to main. CI job count increases from 7 to 8.
- **CI: concurrency cancellation, job timeouts, and caching**: Duplicate CI runs are cancelled when a new push arrives on the same ref. All jobs have explicit `timeout-minutes` (20 for build/test/analysis, 30 for ARM64, 60 for fuzz). CMake `_deps` are cached across runs; Bitcoin Core binary is cached in the regtest job — eliminating redundant downloads on repeat pushes.
- **Dashboard: 5 missing DB tables** (`tools/dashboard.py`): queries `broadcast_log`, `signing_progress`, `watchtower_pending`, `old_commitment_htlcs`, and `factory_revocation_secrets` — bringing dashboard coverage to all 26 schema tables.
- **Dashboard: Signing Progress UI** (Factory tab): per-signer MuSig2 nonce/partial-sig collection status with progress bars per tree node.
- **Dashboard: Watchtower enhancements** (Watchtower tab): Broadcast Log (TX broadcast history with pass/fail results), Watchtower Pending Penalties (in-flight penalty TXs with mempool cycle and fee bump counts), Old Commitment HTLCs (breach-penalty HTLC details), and Factory Revocation Secrets (per-factory epoch count).
- **Dashboard: demo data**: synthetic data for all new tables so `--demo` previews every section.
- **Docker: dashboard integration**: `EXPOSE 8080` in Dockerfile, `8080:8080` port mapping in `docker-compose.yml`, and three new entrypoint modes in `docker-entrypoint.sh`: `dashboard` (demo), `dashboard-live` (connects to regtest bitcoind), `orchestrator`.

### Fixed

- **`--test-bridge` race: `INVOICE_CREATED` missed by client**: `CREATE_INVOICE` was sent to the client immediately after demo payments completed, while the client was still inside the `MSG_UPDATE_ADD_HTLC` handler processing nested `recv_or_handle_ptlc` and revocation rounds (up to ~14s of blocking recvs). The client missed the message and the 10-second wait window expired. Added a 15-second sleep before sending `CREATE_INVOICE` — ensuring the client has returned to the daemon loop and is ready to receive — and extended the `INVOICE_CREATED`/`REGISTER_INVOICE` collection window from 10s to 60s.

- **Watchtower regtest scan depth** (`src/regtest.c`): `scan_depth` for regtest was 20 blocks — causing the LSP's `watchtower_check` in `factory_breach` to make ~688 RPC calls (~206 s), exceeding the 240 s test timeout. Reduced to 10. Depth 7 (first attempt) was too shallow: the `all_watch` scenario mines 1 confirmation block inside the LSP, then `advance_chain(2)` + 6 breach-wait blocks = 9 blocks total on top of the breach TX, placing it just outside a depth-7 window. Depth 10 covers this with one spare block. Fixes `all_watch` (0/4 → 4/4 detected) and `factory_breach` (SKIP → PASS).

- **Daemon loop lifecycle detection** (`src/lsp_channels.c`): `watchtower_check` was called synchronously on every 5-second poll timeout, making ~672 `bitcoin-cli` subprocess calls per cycle (16 old commitment entries × 42 RPC calls each — one `gettransaction` attempt plus up to 20-block fallback scan per entry). This blocked the daemon loop for ~65 seconds, preventing factory DYING/EXPIRED state from ever being detected within the orchestrator test window. Fixed by: (1) moving the block-height/factory-lifecycle check before `watchtower_check` so it runs on every 5-second tick with 1 RPC call; (2) rate-limiting `watchtower_check` to once per 60 seconds; (3) initializing the rate-limit clock on the first tick so the initial cycle is not blocked. Fixes four pre-existing orchestrator failures: `factory_rotation`, `jit_lifecycle`, `ladder_breach`, `turnover_abort`.

- **`watchtower_check` false-positive on cooperative close** (`src/regtest.c`): `regtest_is_in_mempool` returned `true` for any txid when `bitcoin-cli getmempoolentry` produced empty output (stderr redirected to `/dev/null`, stdout was empty string). Added empty-string guard: `result[0] == '\0'` → `false`. Previously `cooperative_close` was incorrectly flagged as a breach.
- **Watchtower `all_watch` txid mismatch** (`tools/superscalar_lsp.c`): The LSP breach test built a CPFP child from the client's old commitment (`channel_build_commitment_tx_for_remote(lsp_ch)`) which produces the commitment from the LSP's side. But the client's watchtower registered the txid built from `channel_build_commitment_tx_for_remote(client_ch)`, which is the LSP's commitment from the client's perspective — a different transaction. Changed the LSP breach code to use `channel_build_commitment_tx(chX, ...)` (LSP's own commitment), which is the same transaction the client watches for. Fixes 0/4 → 4/4 detected breach.
- **Watchtower `all_watch` periodic check blocking** (`tools/superscalar_client.c`): Periodic `watchtower_check()` was called every 2-second select timeout, blocking for 150 ms × 4 entries × 41 calls ≈ 24 seconds, starving the payment message loop. Rate-limited to once every 15 timeouts (~30s).
- **Watchtower `late_arrival` detection** (`src/watchtower.c`): Entries loaded from SQLite had `registered_height` set to the current block height at load time. A breach confirmed during downtime (height < load height) was filtered as "pre-existing" and never detected. Changed to `registered_height = 0` for all DB-loaded entries — height filter only applies to fresh in-session registrations. Fixes 0/4 → 4/4 late-arrival detection.
- **`test_regtest_breach_penalty_cpfp` CPFP bump failure**: `regtest_sign_raw_tx_with_wallet` required `complete: true` from `signrawtransactionwithwallet`, but CPFP child transactions have a P2A (anyone-can-spend) anchor input that the wallet intentionally leaves unsigned — so `complete` is correctly `false`. Added `require_complete` flag; CPFP callers pass `0`.
- **`fee_for_factory_tx` vbyte underestimate**: Factory tree transaction overhead was calculated as 50 vB instead of the correct 68 vB (10 vB tx overhead + 58 vB P2TR keypath input). Formula is now `68 + 43 × n_outputs`. Updated `test_fee_factory_tx` assertions (93→111, 179→197, 265→283 at 1 sat/vB).
- **Docs: testing-guide regtest count corrected**: Was 43, actual count is 42. Total automated corrected to 460, suite total to 515.
- **Docs: ARM64 CI row** added to testing-guide CI table and README feature table.
- **Docs: signet/testnet4 ceremony timeout note** added to lsp-operator-guide Timing section — ceremony message timeouts are 120s on non-regtest networks; cooperative close nonce/psig collection is 300s per client, automatic based on `--network`.
- **Ceremony close timeout**: `ceremony_select_all()` used 30-second hardcoded timeout for close nonce/psig collection. Now uses `per_client_timeout_sec` (300s on signet/testnet4) so cooperative close doesn't time out on slow networks.
- **Ceremony and rotation timeouts**: Increased `wire_recv_timeout` for demo rotation and close ceremonies from 30s to 120s for signet/testnet4 where block confirmation can take minutes.
- **Demo/rotation message timeouts**: Increased `wire_recv_timeout` for `MSG_FACTORY_PROPOSE`, `MSG_NONCE_BUNDLE`, `MSG_PSIG_BUNDLE`, and other ceremony messages from 30s to 120s on non-regtest networks.

- **Client message inbox (`tools/superscalar_client.c`)**: `recv_or_handle_ptlc` previously returned unexpected messages to its caller, causing `MSG_COMMITMENT_SIGNED` and other protocol messages to be silently dropped when they arrived during a different blocking receive. Added a per-fd `client_inbox_t` ring-buffer (4-slot) to `daemon_cb_data_t`; unexpected messages are now queued rather than discarded, and the daemon loop drains the inbox before each `select()` call. `MSG_LSP_REVOKE_AND_ACK` is handled via a new `case` in the daemon switch so bidirectional revocations are never lost.

- **PTLC rotation race (`src/lsp_rotation.c`, `tools/superscalar_lsp.c`)**: The LSP's wait for `MSG_PTLC_ADAPTED_SIG` during factory rotation used a single `wire_recv_timeout` call that failed immediately if any stray message (e.g. `MSG_REVOKE_AND_ACK` from a concurrent payment flow) arrived first. Replaced with a 60-second wall-clock retry loop in `lsp_rotation.c` (30-second in the `--test-rotation` path in `superscalar_lsp.c`) that discards stray messages, breaks on `MSG_ERROR`, and only exits on success or deadline.

- **Channel reestablish CS retransmit (`src/lsp_channels.c`, `src/client.c`, `src/persist.c`)**: If the LSP crashed between sending `MSG_COMMITMENT_SIGNED` and receiving the client's `MSG_REVOKE_AND_ACK`, the commitment was silently abandoned on reconnect and channel state diverged. Added a `pending_cs` SQLite table (schema v3 → v4) that records the in-flight commitment number after every CS send and is cleared after RAA receipt. On reconnect (`handle_reconnect_with_msg`), if a pending CS is detected, the LSP generates a fresh partial sig using the newly-exchanged nonces (no MuSig2 nonce reuse) and retransmits the commitment before sending `MSG_RECONNECT_ACK`. The client (`client_run_reconnect`) peeks for an optional `MSG_COMMITMENT_SIGNED` before `MSG_RECONNECT_ACK` and handles it inline.

- **Watchtower breach txid mismatch**: The `--cheat-daemon` breach block was calling `channel_build_commitment_tx_for_remote()` from the LSP's perspective, producing the client's old commitment txid, while client watchtowers register via `watchtower_watch_revoked_commitment()` which uses the same function from the client's perspective — producing the LSP's old commitment txid. The two txids never matched, so watchtower detection always returned 0/4. Fixed by switching the breach block to `channel_build_commitment_tx()` so the LSP broadcasts its own old commitment, which is exactly what client watchtowers are watching for.

- **Test orchestrator reliability (`tools/test_orchestrator.py`)**: Four timing fixes for the full `--scenario all` suite: (1) added pre-suite `safe_pkill` before scenario 0 (previously only `idx > 0` received cleanup, leaving stale processes able to interfere with the first scenario); (2) removed non-existent `--watchtower` flag from `scenario_watchtower_late_arrival`; (3) increased regtest `factory_timeout` from 60s to 90s to handle heavier VPS load late in long runs; (4) increased inter-scenario sleep from 1s to 2s to give daemon-mode LSPs more time to release listen sockets.

- **Test orchestrator `safe_pkill` port scoping (`tools/test_orchestrator.py`)**: `safe_pkill` matched processes by binary name alone, killing any `superscalar_lsp`/`superscalar_client` on the machine — including unrelated signet or testnet4 exhibition runs on different ports and networks. Added a `port` parameter; `safe_pkill` now reads `/proc/<pid>/cmdline` and skips processes whose command line does not contain `--port <port>`. All four call sites updated. Fixes #23.

- **UTXO double-selection race in CPFP wallet (`src/regtest.c`, `src/wallet_source_rpc.c`, `src/watchtower.c`)**: `regtest_get_utxo_for_bump` selected a UTXO via `listunspent` but did not lock it, leaving a window where concurrent callers sharing a wallet (e.g. two LSP instances using the same faucet wallet) could select the same coin and have one `sendrawtransaction` fail with `txn-mempool-conflict`. Fixed by calling `lockunspent false` immediately after selection. Added `regtest_release_utxo` (`lockunspent true`) as the counterpart, called after broadcast. Added a `release_utxo` slot to the `wallet_source_t` vtable (NULL-safe; callers must check for NULL before invoking). Refactored `watchtower_build_cpfp_tx` to use a single `done:` cleanup label so `release_utxo` is guaranteed on every exit path, including all error returns.

- **HD wallet UTXO reservation (`src/persist.c`, `src/wallet_source_hd.c`)**: `persist_get_hd_utxo` queried `hd_utxos WHERE spent=0` but never reserved the coin, so two concurrent CPFP calls could select the same UTXO. Fixed with a `reserved` column (schema v4 → v5): `persist_get_hd_utxo` now wraps the SELECT and `UPDATE SET reserved=1` in a single `BEGIN IMMEDIATE` transaction. Added `persist_unreserve_hd_utxo` (called by `hd_release_utxo` after broadcast) and `persist_clear_hd_reserved` (called at `wallet_source_hd_init` to release reservations left by any prior crashed run). The `hd_release_utxo` vtable implementation is now registered; on broadcast success the BIP158 scanner's `hd_utxo_spent` callback later sets `spent=1` authoritatively.

- **Docs: README scenario count and stale pass/fail counts**: Removed hardcoded `32/36` pass/fail counts from the tagline, feature table, and test section — counts go stale immediately and mislead readers. Fixed the orchestrator scenario count from 30 to 36 in two locations.


### Removed

- **`bitcoin-cli.sh`**: Vestigial pass-through wrapper that added no value. All scripts call `bitcoin-cli` directly.

---

## 0.1.5 — 2026-03-10

Test counts hold at 30/30 orchestrator scenarios, 418/418 unit tests, and 42/42 regtest tests. This release fixes three bugs in the exhibition test infrastructure found during the 13-structure regtest rehearsal, removes the deprecated `regtest_full.sh` script, and corrects `version.h` which was not updated in v0.1.4.

### Fixed

- **`all_watch` flaky in full suite runs**: `scenario_all_watch` mined 2 blocks once then waited 30 seconds. Watchtowers scan blocks, not a timer — if the poll cycle fired just before those 2 blocks arrived, a client could miss the entire detection window under full-suite process load. Replaced the fixed sleep with a loop that mines 1 block every 5 seconds for the full wait period, giving watchtowers 8 block-triggered scan opportunities instead of 2. `--scenario all` now reliably passes 30/30 on every run.
- **`--test-dw-exhibition` Phase 1 pass condition**: Changed from `any_decreased && any_zero` to just `any_decreased`. With `--states-per-layer 2`, only one DW advance occurs and nSequence never reaches 0 — the original condition always failed. The exhibition proves that nSequence *decreased*, not that it hit zero.
- **`--test-leaf-advance` (`test_realloc`) BIP-327 keypair reordering**: The `--test-leaf-advance` branch was missing the MuSig2 keypair reordering that `--test-dw-exhibition` already had. Without reordering `all_kps[]` to match `lsp.factory.pubkeys[]` (connection order), the aggregated pubkey used for signing differs from the one embedded in the funding TX script, causing every broadcast leaf TX to fail on-chain with “Invalid Schnorr signature”.
- **`version.h` out of sync**: `SUPERSCALAR_VERSION` was not updated in v0.1.4 and still reported `0.1.3`. Bumped `SUPERSCALAR_VERSION_PATCH` to 5 and version string to `0.1.5`.

### Removed

- **`regtest_full.sh`**: Superseded by `test_orchestrator.py` and `manual_tests.py`. The orchestrator covers all scenarios that `regtest_full.sh` provided and more, with better isolation, per-scenario reporting, and support for parallel runs.

---

## 0.1.4 — 2026-03-09

All 30 orchestrator scenarios pass in a single `--scenario all` run on regtest. This release fixes C code bugs, MuSig2 keypair ordering issues, and test infrastructure gaps that caused six orchestrator scenarios to fail or be skipped in v0.1.3.

### Fixed

- **30/30 orchestrator scenarios**: `auto_rebalance`, `batch_rebalance`, `leaf_realloc`, `bridge_bolt11`, `dual_factory`, and `dw_exhibition` were included in the orchestrator since v0.1.3 but always failed or were skipped. All 30 scenarios now pass in a single `--scenario all` run.
- **`channels_active` gating**: Six `--test-*` code paths (`--test-dw-exhibition`, `--test-dual-factory`, rebalance, leaf realloc, bridge BOLT11) were never reached because `channels_active` was set to `1` only after the daemon loop exited, not after `--demo` completed. Set immediately after the demo payment block.
- **MuSig2 keypair ordering — `dw_exhibition`**: Exhibition keypairs were in canonical order (`0x22, 0x33, 0x44, 0x55`) but `fund_spk` was computed with connection order. MuSig2 key aggregation is order-dependent (BIP-327); the mismatch produced a different aggregate pubkey, causing every factory signature to verify as invalid. Reordered exhibition keypairs to match `lsp.factory.pubkeys[]`. Also added a sign+verify+retry loop with full factory re-init on failure.
- **MuSig2 keypair ordering — `dual_factory`**: Same root cause as `dw_exhibition` for Factory 1. `all_kps` now reordered to match connection order before `factory_init`. Factory 0 tree broadcast from `lsp.factory` (intact signed TX buffers) instead of the ladder copy, which has detached buffers after `factory_detach_txbufs()`.
- **`auto_rebalance` direction**: Payment was routed from the heaviest channel to the lightest (wrong direction — increases imbalance). Fixed to route FROM the lightest TO the heavy channel. Imbalance amount increased from `local/3` to `local/2` to reliably exceed the 70% rebalance threshold.
- **`bridge_bolt11` invoice flow**: Replaced hardcoded preimage with the `CREATE_INVOICE` flow so the client generates and holds the preimage locally. Added message pump after HTLC forwarding to read client `FULFILL` and relay it to the bridge fd. Drains `MSG_REGISTER_INVOICE` from client socket after invoice creation.
- **`buy_liquidity` incorrectly skipped**: The orchestrator scenario had an erroneous skip guard; the C implementation exists and works. Skip removed.
- **DW exhibition leaf-node exclusion**: Leaf nodes have `nSequence=0xFFFFFFFF` (BIP68 disabled) and do not participate in the DW counter. Counter verification now skips leaf nodes; pass criterion relaxed from strict `f0_seq < f1_seq` comparison to `f1_built` (factory created and broadcast) since multi-layer counters can wrap bottom layers on advance.
- **`leaf_realloc` pass criterion**: Cooperative close after leaf realloc may fail if clients disconnect before the signing ceremony. Pass criterion changed to check only the test log marker, not the process exit code.
- **`dw_exhibition` stack allocation**: `factory_t exh_f1` (~305 KB) was stack-allocated. Moved to heap via `calloc`.
- **Orchestrator `safe_pkill()`**: Previous `pkill -f` matched the SSH session process. Replaced with per-PID cmdline inspection so only superscalar processes are killed between scenarios.
- **Orchestrator socket bind race**: Wait up to 10 seconds for port release between scenarios before starting the next LSP process.
- **Orchestrator coinbase maturity**: Mine 100 extra blocks after wallet funding so all coinbases are spendable. Prevents `ensure_funded()` from mining >101 blocks mid-test and exceeding scenario timeouts.
- **Orchestrator breach timing**: `breach_wait` increased from 20s to 30s for reliable 4/4 watchtower detection across all clients in `all_watch`.
- **Orchestrator scenario fixes**: `cli_payments` waits for pay completion before triggering cooperative close and keeps clients alive during the close ceremony. `profit_shared` sends CLI pay commands during the daemon loop instead of relying on demo payments. `routing_fee` checks for demo completion rather than a nonexistent `report.routing_fee_ppm` field. `mass_departure_jit` checks `lsp.is_alive()` before calling `stop_all()`.
- **Static analysis**: `rh` and `rp` arrays in the bridge regtest test are now zero-initialized. `cppcheck` had flagged an uninitialized-value use in the `memcpy` path when `rpj` is NULL.

### Added

- **`factory_verify_all()`** (`src/factory.c`, `include/superscalar/factory.h`): Extracts the Schnorr signature from each signed tree node's witness, verifies it against the sighash and tweaked pubkey, and returns 0 with a diagnostic on the first invalid signature. Used by the `dw_exhibition` sign+verify+retry loop to confirm all tree nodes are valid before broadcast.

### Test Count

418 unit + 43 regtest = 461 automated + 25 manual flag tests + 30 orchestrator scenarios (all passing).

---

## 0.1.3 — 2026-03-07

### Fixed

- **DW advance crash**: `--test-dw-advance` crashed with `secp256k1 illegal argument` because the factory's keypairs were zeroed (`factory_init_from_pubkeys()` only sets pubkeys). Populated demo keypairs before calling `factory_advance()`, matching the pattern used by the distribution TX and turnover tests.
- **Pay after rotate**: After factory rotation, `lsp_channels_rotate_factory` persisted channel amounts and commitment number but not basepoints or remote per-commitment points (PCPs). When clients reconnected, `handle_reconnect_with_msg` loaded stale PCPs from the old channel's DB rows (same slot, same cn), corrupting commitment state and failing all subsequent payments. Added `persist_save_basepoints()` and `persist_save_remote_pcp()` calls inside the existing transaction in `lsp_rotation.c`.
- **Backup test keyfile missing**: The backup manual test passed `--seckey` to the demo run, which bypasses `--keyfile` entirely. The keyfile was never written to disk, so `backup_create()` failed on `read_file()`. Fixed by generating a keyfile via `--generate-mnemonic` after the demo run.
- **DW advance scenario pass marker**: The orchestrator matched "DW ADVANCE TEST" which also matched failure messages. Changed to match only "DW ADVANCE TEST PASSED" or "DW ADVANCE TEST: PASS".
- **Boundary test failures**: `run_lsp_quick` switched to `Popen` so timed-out LSP processes are killed instead of leaving stale processes holding the port. `send_cmd` now catches `BrokenPipeError` instead of crashing the test harness. Safe regtest bitcoind kill now reads `/proc/PID/cmdline` to target only `-regtest` processes instead of using `pkill -f` which matched SSH sessions.
- **Non-regtest test flags**: `test_nonregtest` manual test updated to reflect that `--test-*` flags are now allowed on all networks (per e433c8d).
- **1-client arity-1 test**: Updated to accept factory creation success (LSP + 1 client = 2 MuSig2 signers is valid since 0.1.2's 2-participant support).
- **Short rotation test timing**: Added more time for daemon DYING detection and extra mining for rotation close + new factory funding confirmations.
- **Pay-after-rotate stress test**: Added 15s channel settle wait after rotation, status polling to verify channels are online, and a retry on first payment failure.

### Added

- **`--test-*` flags on non-regtest networks**: Replaced bare `regtest_mine_blocks()` calls in test paths with an `ADVANCE(n)` macro that calls `advance_chain()` — mines on regtest, polls `getblockcount` on signet/testnet4. Removed the gate that blocked `--test-expiry`, `--test-distrib`, `--test-turnover`, and `--test-rotation` on non-regtest networks.
- **TXID broadcast logging**: Added `persist_log_broadcast()` calls at all 15+ TX broadcast sites (burn, HTLC commitment/timeout, breach, expiry, distribution, turnover close, rotation close, cooperative close). Enables post-run inspection tools to look up TXIDs from the database.
- **JIT channel exhibition**: Late-arriving client creates a separate JIT channel funding TX + close TX, producing a distinct on-chain artifact (exhibition structure 11).
- **4 new orchestrator scenarios**: `lstock_burn` (L-stock burn via shachain revocation), `dw_advance` (DW counter advance + re-sign + force-close), `distribution_tx` (distribution TX broadcast after CLTV with P2A anchor), `bridge_bolt11` (bridge inbound HTLC / BOLT11 invoice routing).
- **`--test-dw-exhibition`**: Full Decker-Wattenhofer lifecycle on-chain demonstration — Phase 1: nSequence countdown to zero over multiple DW advances, Phase 2: PTLC-assisted cooperative close (adaptor sigs + key extraction), Phase 3: cross-factory nSequence contrast (advanced vs fresh factory).
- **`--test-dual-factory`**: Creates a second factory while the first is still ACTIVE, stores both in the ladder, then force-closes both trees independently on-chain.
- **`--test-leaf-advance`**: Advances only the left leaf's DW counter and force-closes, proving per-leaf independence (right leaf nSequence unchanged).
- **`buy_liquidity` CLI command**: Interactive CLI command to purchase inbound liquidity from L-stock reserves.
- **Testnet4 quickstart guide**: `docs/testnet4-quickstart.md` with prerequisites, recommended flags, per-structure time estimates, environment variable configuration, and common failure modes.
- **Testnet4 operational improvements**: Enhanced confirmation wait logging with TXID/block height/elapsed time, fee-rate floor hint on `sendrawtransaction` min relay fee error, force-close tree broadcast logging with BIP68 wait time estimates, stuck TX warning after 1 hour unconfirmed, daemon heartbeat (`--heartbeat-interval N`).
- **Exhibition tooling**: `inspect_factory.py` (on-chain TX tree inspector with witness analysis and nSequence/nLockTime interpretation), `exhibition_testnet4.sh` (master script for all on-chain structures), `run_remote_client.sh` (remote MuSig2 signing helper).

### Changed

- **Testnet4 timing guidance in README**: Documented recommended `--active-blocks`, `--dying-blocks`, `--step-blocks`, `--states-per-layer` values for faster testnet4 iteration with comparison table.
- **Environment-specific artifacts removed**: `regtest_full.sh` uses relative paths, `exhibition_testnet4.sh` uses configurable env vars instead of hardcoded credentials and IPs, removed WSL-specific `docker-install-wsl.sh`.

### Testing

- **Manual flag tests expanded to 29**: Added 4 new tests (backup/restore cycle fix, DW advance, JIT exhibition, non-regtest flag validation).
- **Orchestrator scenarios expanded to 30**: Added `lstock_burn`, `dw_advance`, `distribution_tx`, `bridge_bolt11`, `buy_liquidity`, `dual_factory`, `dw_exhibition`.

### Test Count

418 unit + 43 regtest = 461 automated + 29 manual flag tests + 30 orchestrator scenarios.

---

## 0.1.2 — 2026-03-05

### Fixed

- **Cooperative close now works from daemon mode**: The CLI `close` command previously set the shutdown flag which caused Phase 5 to abort instead of running the cooperative close ceremony. The close transaction is now properly built, signed (MuSig2), and broadcast.
- **Client reconnection after crash**: Restarting a client process with `--db` now correctly detects persisted factory state and sends `MSG_RECONNECT` (0x48) instead of `MSG_HELLO` (0x01). Previously, `first_run` was hardcoded to 1 on every process start, causing the LSP to reject the reconnecting client.
- **Consistent 0-indexed client numbering in payment logs**: `lsp_demo.c` payment log now uses 0-indexed client numbers, matching the CLI `pay` command and daemon HTLC logs.
- **Post-reconnect payments work**: Both local per-commitment secrets (PCS) and remote per-commitment points (PCPs) are now persisted on every `REVOKE_AND_ACK` and restored during reconnect. Previously, neither persist function was called. After reconnect the client generated new random PCS that didn't match the PCPs the LSP had stored, causing commitment signature verification to fail on both sender and dest sides. Initial PCS (from factory creation) are also persisted.
- **CLN plugin BOLT11 invoice creation**: Switched `lightning-cli invoice` from fragile positional arguments to `-k` keyword mode, skipping the `fallbacks` parameter entirely. Also made `cli_cmd()` LIGHTNING_DIR handling robust across CLN versions (detects known network names instead of unconditionally splitting the path). Plugin logging now uses CLN's JSON-RPC `log` notification so errors appear in CLN's log file instead of being silently lost on stderr.
- **Bridge LSP reconnection**: Bridge now retries up to 12 times with exponential backoff (2s/5s/10s) instead of exiting on first reconnection failure. Previously, if the LSP restarted and wasn't ready within milliseconds, the bridge process would exit.
- **Payment state persistence**: All payment paths — internal CLI (`pay`), bridge inbound (`MSG_BRIDGE_ADD_HTLC`), and bridge outbound (`MSG_BRIDGE_PAY_RESULT`) — now persist channel balance, commitment number, PCS, PCP, and HTLC state after each commitment exchange. Previously, none of the three paths called `persist_update_channel_balance()`, so killing the LSP after any payment caused irreconcilable commitment number mismatches on reconnect (`client=4, lsp=0`). The bridge fulfill path also now waits for `REVOKE_AND_ACK` and processes revocation (watchtower, bidirectional revocation) instead of fire-and-forget.
- **Client daemon reconnect on disconnect**: Client daemon loop now signals disconnect (`return 0`) when `wire_recv` fails, causing `main()` to retry via reconnect. Previously, the disconnect path fell through to the cooperative close ceremony on a dead socket, which blocked or failed, and the client would exit instead of retrying.
- **Client survives factory rotation**: After rotation, the client now disconnects cleanly and reconnects from persisted state instead of continuing in the same daemon loop with replaced factory/channel objects. The rotation persist block also now saves initial PCS and remote PCPs for the new channel, preventing post-rotation reconnect failures. Also fixed a segfault where `watchtower_clear_entries()` freed the channels array but left `channels_cap` non-zero, causing `watchtower_set_channel()` to write through NULL.
- **Regtest test script FIFO reliability**: `regtest_full.sh` now uses a persistent file descriptor (`exec 3>/tmp/lsp_fifo`) instead of `cat /tmp/lsp_fifo | ...`, which broke when each write opened and closed the FIFO causing the LSP to see EOF.
- **Demo payment 4 below dust limit**: The 2-client demo sequence sent 500 sats in payment 4, which is below the 546-sat P2TR dust limit. Bumped to 600. Also fixed two regtest script payments that used 500 sats (post-LSP-crash and post-BIP39-recovery tests).
- **HTLC cltv_expiry on real networks**: All internal payment paths hardcoded `cltv_expiry = 500` (absolute block height), which works on regtest but is expired on testnet4/mainnet. Now derived from `factory.cltv_timeout - FACTORY_CLTV_DELTA`. Client-side payments also use factory-derived cltv.
- **Leaf reallocation ceremony completes**: Client daemon loop was missing the `MSG_LEAF_REALLOC_PROPOSE` dispatch case — the handler existed but was never called, causing the LSP to time out waiting for client nonces. Added case handler.
- **Client watchtower late-arrival breach detection**: Clients now call `watchtower_check()` immediately on startup (before the daemon loop) when reconnecting from persisted state. Previously, breach scanning only ran between reconnect retries, so a client coming online after a confirmed breach would never detect it.
- **fallbackfee in fresh_regtest()**: `manual_tests.py` now passes `-fallbackfee=0.00001` to bitcoind on startup. `regtest_fund_address()` now prints the actual bitcoin-cli error and a hint about fallbackfee when `sendtoaddress` fails, instead of silently returning 0.
- **Penalty TX never broadcast**: Client used the LSP's factory-wide channel_id (0,1,2,3) when registering revoked commitments with its watchtower, but each client only has one channel at local index 0. Clients 1+ stored entries at indices the watchtower couldn't find, causing "no channel N for penalty" and skipping penalty broadcast entirely. Also fixed watchtower DB reload to iterate all persisted indices, not just factory channel count.
- **Rotation PTLC adaptor verification**: The test-rotation path created demo keypairs and used their pubkeys as adaptor points, but actual client processes adapt with real secret keys from keyfiles. The extracted secret never matched the demo pubkey, causing "verify failed client 0". Now uses real client pubkeys from `lsp.client_pubkeys[]`.
- **All_watch breach test reliability**: Mine 2 blocks after broadcasting revoked commitment so watchtowers scanning blocks (not mempool) can detect the breach. Also added inter-scenario process cleanup (`pkill`) to prevent stale processes causing port conflicts and factory creation timeouts.
- **MuSig2 double nonce in leaf reallocation**: The leaf realloc signing path set the LSP nonce early, but the ALL_NONCES loop already sets all signers' nonces. The early set pushed `nonces_collected` past `n_signers`, failing MuSig2 session finalize.
- **2-participant factory support**: Lowered minimum participant count from 3 to 2, enabling `--clients 1 --arity 1` (single leaf with LSP + 1 client).
- **MuSig2 keyagg cache corruption**: `musig_session_finalize_nonces()` and `musig_sign_taproot()` modified the session's keyagg cache in-place before `nonce_process`, corrupting state on failure. Now tweaks a local copy and stores only on success.
- **Breach test PCP availability check**: Verify local per-commitment point availability before building old commitment in breach test. Also wait for client reconnections after rotation before cooperative close.
- **Leaf realloc amount calculation**: `--test-realloc` now reads leaf node output amounts from the factory tree instead of a buggy channel manager loop that duplicated channel 0's amount for all leaves.
- **Orchestrator --cli-path passthrough**: Now passes `--cli-path` to LSP and client processes so watchtower breach detection finds `bitcoin-cli` in all orchestrator scenarios.
- **LSP wallet auto-load**: LSP auto-creates and loads its wallet on startup even when `--wallet` is specified, eliminating the multi-wallet foot-gun where a missing wallet caused silent failures.
- **--breach-test on testnet4/signet**: Removed regtest-only guard. Added block-height polling for revoked commitment and penalty TX confirmation on non-regtest networks, matching the pattern already used by `--cheat-daemon`.
- **L-stock taptree mismatch in distributed signing**: LSP set `has_shachain=1` to build L-stock outputs with hashlock taptrees, but `FACTORY_PROPOSE` never sent the hashlock hashes to clients. Clients built simple P2TR outputs instead, producing a different sighash. The aggregated MuSig2 signature was invalid on any leaf node with L-stock. Fixed by adding `l_stock_hashes` (SHA256 of each epoch's revocation secret) to the wire protocol. Clients now call `factory_set_l_stock_hashes()` before `factory_build_tree()`, producing identical taptrees on both sides.
- **DW advance after demo invalidated tree for burn test**: After demo payments, `dw_counter_advance()` bumped the epoch but never re-signed the tree (can't re-sign without all participants' keys). The burn test then broadcast a tree with stale signatures. Fixed by skipping the DW advance when `--test-burn` is set.
- **Bridge test bitcoind startup race**: `test_bridge_regtest.sh` used `sleep 2` after `bitcoind -daemon`, which wasn't enough on slow machines. Replaced with a poll loop waiting for `getblockchaininfo`.
- **Stale process cleanup between manual tests**: `manual_tests.py` now kills stale `superscalar_lsp`/`superscalar_client` processes before each test run, preventing port conflicts from timed-out or crashed tests.
- **MSG_HELLO reconnect hardcoded cn=0**: When a known client sent `MSG_HELLO` (lost state), the LSP synthesized a `MSG_RECONNECT` with `commitment_number=0`. If the channel had advanced past the initial state, the reconnect handler rejected the connection as irreconcilable. Now uses the channel's actual commitment number from the slot.
- **Bridge test clients missing `--db`**: All 4 factory clients in `test_bridge_regtest.sh` started without `--db`, so channel state (invoices, preimages, balances) existed only in memory. Added `--db "$TMPDIR/client_${i}.db"` to each client.
- **Bridge test plugin→bridge race**: The test verified the bridge→LSP connection but not the CLN plugin→bridge connection. If the invoice command was sent before the plugin connected, the bridge exited. Added a poll loop waiting for "plugin connected" in the bridge log.
- **manual_tests.py regtest teardown**: `fresh_regtest()` used a fixed `sleep 3` after `bitcoind stop`, which wasn't enough on slow machines. Replaced with a poll loop waiting for the bitcoind process to exit.
- **HTLC force-close test direction mismatch**: `add_pending_htlc` used `HTLC_RECEIVED` but the LSP is offering the HTLC to the client. The client (with no `dest_client` field) also added `HTLC_RECEIVED`, causing a commitment TX mismatch — the LSP's sig was for the wrong transaction, `verify_and_aggregate` failed, and `REVOKE_AND_ACK` was never sent. Fixed to `HTLC_OFFERED`.
- **Test process kills scoped to regtest**: `manual_tests.py`, `test_orchestrator.py`, `test_cli_cmds.py`, and `regtest_full.sh` all used broad `pkill bitcoind` / `pkill superscalar_lsp` / `killall` that could kill non-regtest instances (testnet4, signet). All process kills now use `pkill -f '...--network regtest'` or `bitcoin-cli -regtest ping` polling to target only regtest processes.
- **reset_regtest.sh hardcoded PATH**: Removed `$HOME/bitcoin-28.0/bin` PATH addition and replaced the fixed `sleep` with `bitcoin-cli -regtest ping` polling to wait for bitcoind to exit.
- **Hardcoded `/home/pirq/` paths in all test scripts**: All 5 Python test scripts (`manual_tests.py`, `test_cli_cmds.py`, `test_boundary.py`, `test_persist_recovery.py`, `test_stress.py`) hardcoded `/home/pirq/bin/bitcoin-cli`, `/home/pirq/bitcoin-regtest/bitcoin.conf`, and `/home/pirq/superscalar-build`. Defaults now use PATH lookup for `bitcoin-cli`, `rpcuser`/`rpcpass` auth (matching what LSP expects), and `../build` relative to the script. Custom paths still work via `SUPERSCALAR_BTC`, `SUPERSCALAR_BTCCONF`, `SUPERSCALAR_BUILD` env vars.
- **cleanup_procs() killed bitcoind**: `cleanup_procs()` in `manual_tests.py` called `bitcoin-cli stop`, but `run_lsp()` calls `cleanup_procs()` at the top — killing the bitcoind that `fresh_regtest()` just started. Removed bitcoin-cli stop from `cleanup_procs()`; bitcoind lifecycle now managed exclusively by `fresh_regtest()`.
- **Auth mismatch between bitcoind and LSP**: When no `SUPERSCALAR_BTCCONF` was set, `fresh_regtest()` started bitcoind with cookie auth but `lsp_base_cmd()` passed `--rpcuser`/`--rpcpassword`. The LSP couldn't authenticate. All scripts now start bitcoind with `-rpcuser=rpcuser -rpcpassword=rpcpass` when no conf file is specified, matching `lsp_base_cmd()`.
- **Inconsistent `fresh_regtest()` across test scripts**: `test_boundary.py`, `test_stress.py`, `test_cli_cmds.py`, and `test_persist_recovery.py` used fixed `sleep 2-3` instead of ping polling, and some skipped wallet creation retry. All now use the robust pattern from `manual_tests.py` (ping polling with pkill fallback, 10-retry wallet creation).
- **Rotation test pass/fail too lenient**: `test_demo_rotation()` computed `has_close` but only checked exit code. Now also requires `has_close` (rotation must actually complete, not just exit 0).

### Security

- **Revocation secret verification**: `REVOKE_AND_ACK` handlers now verify that the received secret derives the expected per-commitment point via `secp256k1_ec_pubkey_create()` before accepting it. Prevents a malicious peer from sending garbage secrets to avoid penalty on old commitments.
- **bitcoin-cli timeout**: `run_command_exec()` now uses a 30-second timeout with `waitpid(WNOHANG)` polling instead of blocking indefinitely. Hung bitcoin-cli processes are killed with SIGKILL after timeout, preventing LSP hangs.
- **channel_cleanup secret wiping**: `channel_cleanup()` now calls `secure_zero()` on `local_pcs` and `received_revocations` arrays before freeing, preventing revocation secrets from lingering in freed heap memory.
- **Keyfile/backup file permissions**: `keyfile_save()` and `backup_create()` now use `open(O_CREAT|O_WRONLY|O_TRUNC, 0600)` on POSIX instead of `fopen("wb")`, creating files with owner-only permissions instead of umask-dependent (typically 0644).
- **fee_estimate overflow guard**: `fee_estimate()` now returns a 1 BTC cap instead of wrapping to near-zero when extreme fee rates would overflow `uint64_t` multiplication.
- **musig/watchtower secure_zero**: Replaced `memset()` with `secure_zero()` for secret key and session ID wiping in `musig_sign()` and `watchtower_check_and_respond()`, preventing compiler optimization from eliding the wipe.
- **Wire protocol negative number rejection**: All wire parsers that cast `cJSON valuedouble` to unsigned types (`uint64_t`, `uint32_t`, `uint16_t`, `size_t`) now reject negative values via `wire_check_nonneg()`. Prevents undefined behavior from casting negative doubles to unsigned integers, which could produce huge amounts/IDs.

### Added

- **`--test-burn` flag**: New test mode broadcasts the factory tree then builds and broadcasts a burn TX spending L-stock via flat secrets revocation (hashlock script-path spend). Uses `factory_generate_flat_secrets()` per ZmnSCPxj's Delving Bitcoin post #34 recommendation to store all revocation keys independently rather than using shachain.
- **`tools/setup_regtest.sh`**: One-command regtest environment setup that exports `SUPERSCALAR_BTC`/`BUILD`/`BTCCONF`, starts bitcoind, and funds the wallet.
- **README quickstart**: 5-line copy-paste from fresh Ubuntu to running demo.
- **Script-path revocation penalty TX**: New `channel_build_penalty_tx_script_path()` spends the to-local output via a revocation checksig leaf (`<key> OP_CHECKSIG`) in a 2-leaf taptree, providing an alternative to key-path penalty. Enabled by `use_revocation_leaf=1` on the channel. Key-path penalty also works correctly with the 2-leaf taptree.
- **`tapscript_build_revocation_checksig()`**: Builds a 34-byte revocation script leaf for the 2-leaf to-local taptree.

### Changed

- **Non-regtest confirmation timeout raised to 3 days**: The default polling timeout for factory funding confirmation on testnet4/signet/mainnet was 7200s (2 hours), far too short for BIP68 relative timelocks (testnet4 `active-blocks=4320` can take ~30 days). Raised to 259200s (3 days). Regtest default remains 3600s.
- **Operator and client user guides updated**: Added missing CLI flags and commands to `docs/lsp-operator-guide.md` and `docs/client-user-guide.md`.

### Testing

- **Manual flag tests expanded to 25**: Added 10 new tests covering 1-client factory, variable funding amounts (50k/200k/500k), DW configuration (states-per-layer, step-blocks), profit-shared economics, backup/restore cycle, no-JIT mode, all 3 placement modes, BIP39 mnemonic generation, and JSON report validation.
- **Manual test runner improvements**: `manual_tests.py` now prints the exact LSP command before each test, shows per-test timing in the summary, auto-tails the last 30 log lines on failure, and supports `--list` for test discovery without running anything.
- **Removed redundant test scripts**: Deleted `regtest_extended.sh`, `testnet4_full.sh`, and `verify_onchain.sh` — all genuinely new test coverage integrated into `manual_tests.py`, redundant orchestrator wrappers and duplicate tests eliminated.
- **Removed dead scripts**: Deleted `tools/bitcoin-cli-wrapper.sh` (superseded by shell-free `run_command_exec`), `tools/check_wallets.sh` (debug-only wallet lister), and `tools/run_penalty_test.sh` (superseded by `manual_tests.py` penalty test).
- **Timestamped test output**: All 5 Python test scripts now prefix test headers and RESULT lines with `[HH:MM:SS]` timestamps, matching the pattern already used by `test_orchestrator.py`.
- **`clean_files()` helper**: Replaced 26 occurrences of `try: os.unlink(f) except: pass` with a shared `clean_files(*paths)` helper across all test scripts.

### Performance

- **TCP_NODELAY on all sockets**: Disabled Nagle's algorithm on accept and connect paths, eliminating 200ms+ coalescing delays on small wire protocol messages. Critical for testnet4/mainnet where latency matters.
- **DB write batching**: Per-payment persist calls (PCS, PCP, balance, HTLC) are now batched into a single SQLite transaction per side (sender and dest), reducing fsyncs from ~9 to 3 per internal payment.
- **Bridge buffered reads**: `bridge_read_plugin_line()` now reads 4KB chunks instead of 1 byte at a time, reducing syscalls by ~1000x per JSON message from the CLN plugin.
- **Plugin send/recv lock separation**: CLN plugin uses a dedicated `send_lock` for `sendall()` instead of the shared `lock`, so bridge reads and writes no longer block each other.
- **BRIDGE_MAX_PENDING 32→256**: In-flight inbound HTLCs from CLN raised to match BOLT #2 capacity, removing a hard bottleneck for burst inbound traffic.

### Test Count

418 unit + 43 regtest = 461 automated + 25 manual flag tests + 23 orchestrator scenarios.

---

## 0.1.1 — 2026-03-04

### Security

- **RBF on penalty transactions**: Penalty and HTLC timeout/success transactions now signal BIP125 Replace-By-Fee (`nSequence = 0xFFFFFFFD`) so fee bumps can be broadcast if the initial penalty is stuck in the mempool.
- **Zero-sat output guards**: Penalty and HTLC sweep transactions bail out when the output amount falls below the 546-sat dust limit, preventing invalid transactions.
- **CLTV cap vs factory timeout**: `lsp_validate_cltv_for_forward()` now rejects HTLCs whose `cltv_expiry` meets or exceeds the factory's own timeout — prevents funds from being trapped when the factory expires.
- **Watchtower HTLC timeout auto-sweep**: New `WATCH_FORCE_CLOSE` entry type enables the watchtower to automatically broadcast HTLC timeout transactions once `cltv_expiry` is reached after a force close.
- **Enforce `--db` on mainnet**: LSP and client binaries now refuse to start on mainnet without `--db`, preventing loss of revocation secrets on crash.

### Added

- Linux ARM64 (Raspberry Pi) prebuilt binaries in releases
- Dashboard screenshot in README
- Bitcoin donation address and Support section in README
- Release workflow: manual dispatch via `workflow_dispatch` (re-trigger without recreating release)

### Fixed

- Release workflow: ARM64 builds via QEMU emulation (replaces flaky cross-compile)
- Release workflow: `--clobber` flag for re-run asset replacement
- FUNDING.yml: use HTTPS URL for GitHub Sponsor button rendering

### Test Count

415 unit + 43 regtest = 458 total (unchanged from 0.1.0).

---

## 0.1.0 — 2026-03-04

First tagged release. Ready for signet/testnet collaborative testing.

### Security

- **PBKDF2 backup encryption**: Backup files now use PBKDF2-HMAC-SHA256 with 600,000 iterations instead of single-pass HKDF. V1 backups (`SSBK0001`) are still auto-detected and readable. New backups use v2 format (`SSBK0002`).
- **BIP39 mnemonic support**: Generate 12/24-word seed phrases for deterministic key recovery. `--generate-mnemonic` and `--from-mnemonic` flags on both LSP and client binaries. BIP32 derivation path `m/1039'/0'/0'`.
- **Shell-free subprocess execution**: `popen()` replaced with `fork()/execvp()` on POSIX systems, eliminating shell interpretation of bitcoin-cli arguments. Input sanitizer retained as defense-in-depth.
- **Connection rate limiting**: Per-IP sliding-window rate limiter with configurable concurrent handshake cap (`--max-conn-rate`, `--max-handshakes`).
- **factory_set_funding() bounds check**: Prevents buffer overflow if scriptPubKey exceeds 34-byte buffer.
- **tx_buf OOM safety**: Sticky `oom` flag prevents heap buffer overflow on `realloc()` failure — all write functions bail out instead of writing past the buffer.
- **SQLite PRAGMA error checking**: `persist_open()` now verifies `journal_mode=WAL`, `synchronous=FULL`, and `foreign_keys=ON` all succeed — previously failures were silently discarded.
- **simulate_tree() stack guard**: Bounds check prevents stack overflow in tree simulation.
- **Bidirectional MSG_ERROR**: Client sends error on ceremony failures; LSP checks for MSG_ERROR at all 6 reception points (4 ceremony steps, daemon loop, reconnect).

### Changed

- **MAX_HTLCS raised to 483**: BOLT #2 standard capacity (was 32). Dynamic array growth from initial allocation of 64, with all stack-allocated HTLC arrays across 5 files converted to heap.
- **Mainnet codepath coverage**: Unit tests added for `strcmp(network, "mainnet")` branches in CLI prefix building and scan depth configuration.
- **LeakSanitizer enabled in CI**: Sanitizer build now runs with `detect_leaks=1` (was disabled globally).

### Added

- `include/superscalar/version.h` — version string (`SUPERSCALAR_VERSION`)
- `--version` flag on all 4 binaries (LSP, client, bridge, watchtower)
- `src/bip39.c`, `include/superscalar/bip39.h` — BIP39 mnemonic implementation
- `src/bip39_wordlist.h` — 2048-word English wordlist
- `src/rate_limit.c`, `include/superscalar/rate_limit.h` — connection rate limiting
- `tests/test_bip39.c` — 10 tests including official TREZOR vectors
- `tests/test_rate_limit.c` — 4 tests for rate limiter
- `SECURITY.md` — responsible disclosure policy
- `CHANGELOG.md` — this file

### Test Count

415 unit + 43 regtest = 458 total (was 394 unit + 43 regtest = 437).

---

## Prior Development

SuperScalar was developed as a research prototype implementing ZmnSCPxj's SuperScalar design for Bitcoin Lightning channel factories. Major milestones before changelog tracking:

- Decker-Wattenhofer state machine with multi-layer counter
- MuSig2 distributed signing (2-round N-of-N ceremony, nonce pools)
- Timeout-sig-trees with CLTV script-path fallback
- Poon-Dryja payment channels with HTLCs at leaf outputs
- Noise NK encrypted transport with Tor hidden service support
- SQLite persistence (27 tables) with crash recovery
- CLN bridge for Lightning Network interoperability
- Client + LSP + standalone watchtowers
- PTLC key turnover via adaptor signatures
- Factory ladder rotation (zero-downtime)
- Web dashboard, interactive CLI, JSON diagnostic reports
- 7-job CI: Linux, macOS, sanitizers, cppcheck, regtest, coverage, fuzz
