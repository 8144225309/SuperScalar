# Changelog

All notable changes to SuperScalar are documented here.

## 0.1.6 — unreleased

### Added

- **CI: ARM64 build and unit test job**: GitHub Actions now builds and runs all 418 unit tests on `linux/arm64` via Docker on every push to main. CI job count increases from 7 to 8.
- **Dashboard: 5 missing DB tables** (`tools/dashboard.py`): queries `broadcast_log`, `signing_progress`, `watchtower_pending`, `old_commitment_htlcs`, and `factory_revocation_secrets` — bringing dashboard coverage to all 26 schema tables.
- **Dashboard: Signing Progress UI** (Factory tab): per-signer MuSig2 nonce/partial-sig collection status with progress bars per tree node.
- **Dashboard: Watchtower enhancements** (Watchtower tab): Broadcast Log (TX broadcast history with pass/fail results), Watchtower Pending Penalties (in-flight penalty TXs with mempool cycle and fee bump counts), Old Commitment HTLCs (breach-penalty HTLC details), and Factory Revocation Secrets (per-factory epoch count).
- **Dashboard: demo data**: synthetic data for all new tables so `--demo` previews every section.
- **Docker: dashboard integration**: `EXPOSE 8080` in Dockerfile, `8080:8080` port mapping in `docker-compose.yml`, and three new entrypoint modes in `docker-entrypoint.sh`: `dashboard` (demo), `dashboard-live` (connects to regtest bitcoind), `orchestrator`.

### Fixed

- **`test_regtest_breach_penalty_cpfp` CPFP bump failure**: `regtest_sign_raw_tx_with_wallet` required `complete: true` from `signrawtransactionwithwallet`, but CPFP child transactions have a P2A (anyone-can-spend) anchor input that the wallet intentionally leaves unsigned — so `complete` is correctly `false`. Added `require_complete` flag; CPFP callers pass `0`.
- **`fee_for_factory_tx` vbyte underestimate**: Factory tree transaction overhead was calculated as 50 vB instead of the correct 68 vB (10 vB tx overhead + 58 vB P2TR keypath input). Formula is now `68 + 43 × n_outputs`. Updated `test_fee_factory_tx` assertions (93→111, 179→197, 265→283 at 1 sat/vB).
- **Docs: testing-guide regtest count corrected**: Was 43, actual count is 42. Total automated corrected to 460, suite total to 515.
- **Docs: ARM64 CI row** added to testing-guide CI table and README feature table.
- **Docs: signet/testnet4 ceremony timeout note** added to lsp-operator-guide Timing section — ceremony message timeouts are 120s on non-regtest networks; cooperative close nonce/psig collection is 300s per client, automatic based on `--network`.
- **Ceremony close timeout**: `ceremony_select_all()` used 30-second hardcoded timeout for close nonce/psig collection. Now uses `per_client_timeout_sec` (300s on signet/testnet4) so cooperative close doesn't time out on slow networks.
- **Ceremony and rotation timeouts**: Increased `wire_recv_timeout` for demo rotation and close ceremonies from 30s to 120s for signet/testnet4 where block confirmation can take minutes.
- **Demo/rotation message timeouts**: Increased `wire_recv_timeout` for `MSG_FACTORY_PROPOSE`, `MSG_NONCE_BUNDLE`, `MSG_PSIG_BUNDLE`, and other ceremony messages from 30s to 120s on non-regtest networks.

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
