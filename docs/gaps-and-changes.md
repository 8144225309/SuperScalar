# SuperScalar: Verified Gaps & Changes Roadmap

Cross-referenced against repo state as of 2026-03-02 (commit 15341af).
Items verified by reading actual source — claims from external AI review
that turned out to be wrong (already implemented) are excluded.

---

## Priority 1: Security / Correctness Bugs — ALL FIXED

### 1A. ~~Watchtower never triggers burn tx~~ — FIXED (commit 20a44ec)
- Watchtower now stores pre-built burn tx alongside response tx and
  broadcasts both on breach. `watchtower_watch_factory_node()` accepts
  burn_tx/burn_tx_len parameters; cleanup frees the allocation.

### 1B. ~~Tapscript >2 leaves silently zeros output~~ — FIXED (commit 20a44ec)
- `tapscript_merkle_root()` return type changed from void to int.
  Returns 0 on error (n_leaves == 0). Implements recursive balanced
  binary tree for N > 2 leaves (BIP-341 compliant).

### 1C. ~~Invoice registry never cleaned~~ — FIXED (commit 20a44ec)
- `lsp_channels_register_invoice()` and `lsp_channels_track_bridge_origin()`
  now scan for inactive slots before appending. In-memory invoice
  deactivation added in the fulfill path (was only deactivated in DB).

### 1D. ~~Hashlock burn script not consensus-enforced~~ — DOCUMENTED (commit 20a44ec)
- Accepted risk: Bitcoin Script cannot inspect tx outputs. Burn-to-OP_RETURN
  enforced by `factory_build_burn_tx()` construction. Preimage only exposed
  during breach response (narrow window). Consensus-enforced burn would
  require covenant opcodes (OP_CTV). Comment added to `tapscript_build_hashlock()`.

---

## Priority 2: Protocol Correctness

### 2A. ~~Epoch reset uses local signing~~ — FIXED (commit 15341af)
- Full 2-round distributed MuSig2 ceremony implemented:
  `lsp_epoch_reset_distributed()` orchestrates nonce collection (round 1)
  and partial signature collection (round 2) from all clients. Client
  handler processes both rounds with persistent secnonces between rounds.
  Wire protocol updated with `round` field in EPOCH_RESET_PROPOSE.
  Also fixed pre-existing key mismatch in epoch reset wire builders.

### 2B. Reconnect commitment mismatch tolerated silently — FIXED
- **Files**: `src/lsp_channels.c`, `src/client.c`
- **Problem**: On reconnect, if client's commitment_number != LSP's, it logged
  a warning and proceeded. Comment: "Proceed anyway for PoC."
- **Fix**: Proper commitment reconciliation implemented:
  - LSP ahead by 1: rolls back to last persisted DB state
  - Client ahead by 1: accepts client's cn, reloads from DB
  - Diff > 1 or no persistence: irreconcilable, closes connection
  - Per-operation persistence added (Phase 1): `persist_update_channel_balance()`
    after each successful REVOKE_AND_ACK in add/fulfill HTLC paths
  - Client-side verification in `client_run_reconnect()`: compares ack_commit
    with local cn, reloads from DB on mismatch

### 2C. No HTLC replay on reconnect — FIXED
- **Files**: `src/lsp_channels.c`
- **Problem**: HTLCs were retained in memory but not replayed to the peer
  after reconnection. Comment said "no replay needed" but BOLT #2 requires
  retransmitting uncommitted updates.
- **Fix**: `replay_pending_htlcs()` function added. After RECONNECT_ACK,
  scans all channels for ACTIVE RECEIVED HTLCs whose invoice destination
  matches the reconnected client. For each unforwarded HTLC, re-does the
  full forward: channel_add_htlc → ADD_HTLC → COMMITMENT_SIGNED →
  wait for REVOKE_AND_ACK → persist. Skips HTLCs already present on dest.

---

## Priority 3: Production Hardening (PoC Shortcuts)

### 3A. Hand-rolled ChaCha20-Poly1305
- **Files**: `src/crypto_aead.c` (self-identified TECHNICAL DEBT comment)
- **Problem**: Custom AEAD implementation. Comment already says "replace with
  libsodium crypto_aead_chacha20poly1305_ietf_* or OpenSSL EVP_AEAD."
- **Fix**: Link libsodium or use OpenSSL EVP, drop crypto_aead.c.
- **Effort**: Low

### 3B. Static capacity limits
- **Files**: `include/superscalar/lsp.h` (LSP_MAX_CLIENTS=8),
  `include/superscalar/channel.h` (MAX_HTLCS=16),
  `include/superscalar/lsp_channels.h` (MAX_INVOICE_REGISTRY=64)
- **Problem**: Compile-time constants limit scale.
- **Fix**: Dynamic allocation or at least increase the caps.
- **Effort**: Low-moderate (dynamic alloc touches many array accesses)

### 3C. JIT migration is naive balance addition
- **Files**: `src/jit_channel.c` (lines 491-498)
- **Problem**: `jit_channel_migrate()` does direct balance addition in
  memory. Comment: "For PoC, we adjust balances directly." Not a real splice.
- **Fix**: Implement proper splice-in transaction for JIT-to-factory
  migration.
- **Effort**: Significant (splice is complex)

### 3D. Fee estimation defaults to static 1000 sat/kvB
- **Files**: `src/fee.c` (lines 9-46)
- **Problem**: `use_estimatesmartfee` defaults to 0. Dynamic estimation via
  bitcoin-cli RPC exists but is opt-in. Floor clamped at 1000 sat/kvB.
- **Fix**: Enable dynamic estimation by default when bitcoind is available.
  Add mempool-based estimation as fallback.
- **Effort**: Low

---

## Priority 4: Design Enhancements

### 4A. Variable arity per tree level
- **Files**: `src/factory.c` — `build_subtree()`, `factory_set_arity()`
- **Problem**: Arity is uniform (all ARITY_1 or all ARITY_2). ZmnSCPxj's
  design recommends "low arity near leaves, increase a few levels away"
  for reduced tree depth and locktime accumulation.
- **Fix**: Add per-level arity array or arity function. Modify
  `build_subtree()` to use level-dependent arity.
- **Effort**: Moderate

### 4B. Gossip protocol support
- **Files**: None (zero matches for gossip/channel_announcement)
- **Problem**: Factory channels are invisible to LN routing. No
  channel_announcement, node_announcement, or channel_update messages.
- **Fix**: Generate and propagate gossip messages for factory channels so
  they're routable on the broader LN.
- **Effort**: Major (needs BOLT #7 implementation + CLN plugin integration)

### 4C. DW revocation (Poon-Dryja punishment in DW layers)
- **Problem**: DW state defense is race-to-confirm only. Adding a punishment
  branch would upgrade deterrent from "both lose" to "cheater loses all."
- **Caveat**: ZmnSCPxj chose NOT to include this in SuperScalar. Burn tx +
  inverted timeout defaults already make fraud irrational. This is
  incremental, not critical.
- **Fix**: New tapscript punishment leaf in state node taptrees, shachain
  for DW-layer revocation, watchtower penalty tx construction.
- **Effort**: Significant

---

## Priority 5: Future Protocol (Not Actionable Now)

These require Bitcoin consensus changes or are entirely new protocol designs.
Track but don't implement.

| Item | Dependency |
|------|-----------|
| Tunable-Penalty Protocol (John Law) | Could replace DW entirely; major redesign |
| MultiPTLC for payment availability | ZmnSCPxj proposal; new protocol feature |
| Optimistic locking for concurrency | ZmnSCPxj proposal; new protocol feature |
| LSP feerate futures | ZmnSCPxj proposal; no protocol change needed |
| Fee-Dependent Timelocks | Requires soft fork |
| OP_CTV non-interactive factory creation | BIP-119 (not activated) |
| LN-Symmetry / APO replacing DW | BIP-118 (not activated) |
| OP_CHECKSEPARATESIG + Actuaries | Two soft forks |
| Cross-Input Signature Aggregation | CISA soft fork |

---

## Items From External Review That Were WRONG

Verified as already implemented — do NOT add these:

| Claim | Reality |
|-------|---------|
| "Cooperative close outputs go to same address" | Per-client P2TR close addresses derived from client factory pubkeys (commit 15e8669) |
| "No graceful ceremony degradation" | `ceremony_t` has quorum, per-client timeouts, retry logic |
| "Private Key Handover not implemented" | `ladder_record_key_turnover()` works, called from `lsp_rotation.c` |
| "PTLC adaptor sigs not implemented" | Full implementation in `adaptor.c` + `lsp_rotation.c` |
| "Automated factory migration not implemented" | `lsp_channels_rotate_factory()` in `lsp_rotation.c` does full A/B/C |
| "Multi-LSP MultiChannel" | Separate construction, not applicable to single-LSP SuperScalar |
| "Asymmetric Kickoff" | Designed for multi-LSP quorum; degenerates in single-LSP |
| "One-to-Many Channel Mapping" | Only meaningful with multiple LSPs |
