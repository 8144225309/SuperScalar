# Cheat-engine follow-up gaps

Tracking the items deferred from PR #159 (Cheat-engine validation: wire-ceremony poison TX + standalone WT). All items here build on the closures already in PR #159 — Gap 1 (standalone WT sub-factory), Gap 2 (isolated CL7 client cheat), Gap 4 (late-arriving WT), and Gap 6 (reorg watcher with real evidence).

---

## Gap 3 — fee race against cheat broadcast

**Threat**: malicious LSP CPFPs its stale broadcast at high fee, hoping to win the confirmation race against the WT's response_tx.

**Why this is bounded at the economic level**: the wire-ceremony L-stock poison TX spends a *different output* than the response_tx. Specifically:
- Cheat broadcast confirms → its outputs (channel vout + L-stock vout) appear on chain.
- WT response_tx spends the *channel vout* — restores the latest signed leaf state. If it loses the fee race against a CPFP of the cheat's *channel-vout* descendants, the response can't propagate; the LSP "wins" the latest state.
- WT poison TX spends the *L-stock vout* — redirects the LSP's reserve to clients per-channel. This output is independent of the channel vout, so the LSP can't CPFP the poison's parent without giving up its own funds. The economic disincentive (L-stock → clients) holds regardless of the response_tx race outcome.

**What's missing for validation**: a CPFP-bumping test harness. To exercise it we'd need:
1. An LSP flag like `--cheat-cpfp-bump SATS` that broadcasts a child TX spending the cheat's channel-vout at high fee.
2. A WT response_tx fee-bumping path (currently the response is broadcast at a baked-in fee).
3. Test verification that the poison TX confirms regardless of who wins the channel-vout race.

**Status**: deferred. The protocol design is correct; the missing piece is exercising it under adversarial fee conditions. Estimated half-day of implementation work for the flag + test harness.

---

## Gap 5 — HTLC-layer cheats (channel-state cheating)

**Threat**: malicious LSP broadcasts a stale CHANNEL commitment (different layer than factory state). Lightning HTLC adds/settles + commitment updates happen INSIDE the channel output, BELOW the factory layer we exercise in PR #159.

**Why this is out of scope for the cheat-engine PR**: PR #159 exercises factory-state cheats (leaf advance, sub-factory chain advance, Tier-B rollover). HTLC-level cheats require a working CLN integration + the wallet layer to fully drive HTLC state transitions. That stack is "wallet doesn't work end-to-end yet" per project status.

**Status**: separate PR pending wallet-layer maturity. Not blocked on cheat-engine work.

---

## Gap 7 — long-running soak

**Threat**: not a real attack vector — a stability check. The WT registers an entry per persisted ps_leaf_chains row. Over hundreds of advances, does the WT's memory stay bounded? Does the per-block scan stay fast?

**Test**: `tools/test_regtest_soak_advances.sh` drives `--advance-count 50` then cheats from the oldest state. Validates:
- 50 ps_leaf_chains rows persist correctly
- LSP completes the chain (no timeout / OOM)
- WT defense still fires at the end

**Status**: runner ships in this follow-up PR. Default ADVANCE_COUNT=50 (configurable up to FACTORY_MAX_NODES limits). Production deployments would want N >> 50 over a longer wall clock.

---

## Item 2 carryover — WT response_tx `-22 TX decode failed` (sub-factory case)

**Symptom**: in `cheat_daemon_subfactory` runs, the WT broadcasts the L-stock burn TX successfully but the response_tx broadcast fails with bitcoind `-22 TX decode failed. Make sure the tx has at least one input.`

**What we know**:
- `signed_tx_hex` in `ps_subfactory_chains` decodes fine via `bitcoin-cli decoderawtransaction` when read out via sqlite3 directly.
- WT hex dump shows bytes start with `02000000000103…` — version 2, SegWit marker `00`, flag `01`, then input count `03` = 3 inputs.
- bitcoind v30 says "no inputs" — strongly suggests SegWit witness section is malformed somewhere after the input/output sections, causing bitcoind to fall back to non-SegWit parsing (which sees `00` after version as input count = 0, hence "no inputs").
- The L-stock burn TX (different code path) broadcasts cleanly. So the economic defense is unaffected.

**Why this doesn't undermine the trustless story**: the wire-ceremony L-stock poison TX is the headline economic disincentive — it redirects LSP funds to clients on cheat detection. response_tx is a secondary recovery mechanism (restores latest channel state automatically). When response_tx broadcast fails, clients can still recover manually using the burn TX confirmation + their persisted channel state.

**Status**: real bug, but defense holds. Tracked as the primary code item in this follow-up PR.

**Diagnostic tooling staged for next attempt**:
- `add_hex_dump.py` (in local Windows dev tree) — adds a `fopen("/tmp/wt_response_hex.txt", "w")` write in `src/watchtower.c` right before the broadcast, so we can capture the full hex bytes from a live run without WAL/cleanup races. Run again with the dump in place, then `bitcoin-cli decoderawtransaction` against the captured bytes to confirm exactly where the SegWit decode fails.

---

## Branch + PR notes

This follow-up PR sits on top of `feature/cl1-cheat-leaf` (PR #159 HEAD). When PR #159 lands, rebase onto main and re-target.

Strict ordering: do NOT merge this PR before #159, since the CL4.E + CL4.F infrastructure it builds on lives in #159.
