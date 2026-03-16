# Plan: SuperScalar LN Integration — PR #17

## Context

SuperScalar currently operates as an isolated LSP: clients connect via the native Noise
protocol, and the CLN bridge handles all interaction with the broader Lightning Network.
This PR makes SuperScalar a first-class participant in the LN ecosystem — connectable,
discoverable, and eventually independent of the CLN bridge.

**Builds upon PR #16** (`superscalar-hardening-v2` branch).
New branch: `superscalar-ln-gossip`.

## Architectural principle

The factory structure (DW tree, MuSig2, epoch resets) stays **internal to the LSP**.
The rest of the Lightning Network never sees factory leaves — there are no on-chain UTXOs
for them and no benefit to advertising them. To the outside world, a SuperScalar LSP is
a normal well-connected Lightning routing node. The factory is an implementation detail.

```
External LN peers / wallets
        ↕  BOLT #8 (Noise_XK) + BOLT #7 gossip
SuperScalar LSP  ← "just a Lightning node" to the outside
        ↕  native Noise protocol  |  BOLT #8 + LSPS2 shim
   Factory clients (full benefits) | Third-party wallets (plain channel)
```

---

## Phase 1 — BOLT #8 Transport + BOLT #1 Feature Negotiation

### Problem
SuperScalar cannot be connected to by any standard LN peer or LSPS-compatible wallet.
All connections require the native Noise NN/NK protocol. Zeus, Blixt, Phoenix cannot
connect at all.

### Design

**BOLT #8 = Noise_XK_secp256k1_ChaChaPoly_SHA256**

Three-act handshake (166 bytes total):
- Act 1 (initiator → responder): 50 bytes. Ephemeral pubkey + ChaChaPoly tag.
- Act 2 (responder → initiator): 50 bytes. Ephemeral pubkey + ChaChaPoly tag.
- Act 3 (initiator → responder): 66 bytes. Encrypted static pubkey + two tags.

Three DH operations (vs two in current NK):
- `ee`: ephemeral × ephemeral
- `es`: initiator_ephemeral × responder_static (same as current NK)
- `se`: responder_ephemeral × initiator_static  ← NEW vs NK

Differences from current `noise.c`:
- Prologue: empty (vs "superscalar-v1")
- Nonce encoding: big-endian (vs little-endian)
- Key rotation: after every 1000 encryptions/decryptions (not currently done)
- Act sizes fixed to spec byte counts

Post-handshake: **BOLT #1 init message** (type 16):
- Fields: globalfeatures (deprecated, empty), localfeatures (TLV)
- Feature bits advertised:
  - Bit 729 (odd): LSPS0 support
  - Bit 759 (odd): SuperScalar-native support (custom, signals native protocol available)
- Followed by custom message dispatch:
  - Type 37913 (0x9451): LSPS0 request → `lsps_handle_request()`
  - Type 37899 (0x9449): LSPS0 response (outbound only)
  - Type 0x51–0x57: SuperScalar native messages (forward to existing wire handler)

### Files

| File | Change |
|------|--------|
| `src/bolt8.c` | NEW — Noise_XK handshake (acts 1/2/3), key rotation, message framing |
| `include/superscalar/bolt8.h` | NEW — public API |
| `src/bolt8_server.c` | NEW — TCP accept loop, BOLT #1 init, message dispatch |
| `include/superscalar/bolt8_server.h` | NEW — server API |
| `tools/superscalar_lsp.c` | Add `--bolt8-port PORT` flag (default 9735 if set) |
| `tests/test_bolt8.c` | NEW — BOLT #8 spec test vectors, BOLT #1 feature negotiation |
| `CMakeLists.txt` | Add bolt8.c, bolt8_server.c, test_bolt8.c |

### Key reused functions

- `secp256k1_ecdh()` — already in noise.c
- `aead_encrypt()` / `aead_decrypt()` — already in crypto_aead.c
- `hkdf_extract()` / `hkdf_expand()` / `hmac_sha256()` — already in noise.c
- `wire_listen()` / `wire_accept()` — already in wire.c
- `lsps_handle_request()` — already in lsps.c

### New tests
- `test_bolt8_handshake_vectors` — BOLT #8 spec test vectors (act1/2/3 byte-exact)
- `test_bolt8_key_rotation` — verify sk/rk rotate correctly at message 1000
- `test_bolt8_init_features` — BOLT #1 init exchange, feature bit 729 + 759 present
- `test_bolt8_lsps_dispatch` — LSPS0 request (type 37913) routed to lsps_handle_request

### Test delta: +4

---

## Phase 2 — LSP Discovery Infrastructure

### Problem
Clients must manually specify `--host IP --port 9735 --lsp-pubkey HEX`. There is no way
to find a SuperScalar LSP by name or to let clients auto-discover available LSPs.

### Design

**`/.well-known/lsps.json` HTTP endpoint** served by `superscalar_lsp`:

```json
{
  "pubkey": "02abc...def",
  "host": "lsp.example.com",
  "port": 9735,
  "bolt8_port": 9735,
  "native_port": 9736,
  "network": "bitcoin",
  "lsps": ["lsps0", "lsps1", "lsps2"],
  "superscalar": true,
  "fee_ppm": 1000,
  "min_channel_sats": 100000,
  "max_channel_sats": 10000000,
  "version": "0.1.7"
}
```

**`--well-known-port PORT`** flag: starts a minimal HTTP server on PORT (e.g. 80 or 8080)
that responds to `GET /.well-known/lsps.json`. TLS termination handled by operator's
reverse proxy (nginx/caddy in front).

**`--lsp DOMAIN`** flag in `superscalar_client`: bootstrap from domain. Client does:
1. HTTPS GET `https://DOMAIN/.well-known/lsps.json`
2. Parses pubkey + host + port
3. Connects via native Noise NK (if `superscalar: true`) or BOLT #8 (fallback)
4. Caches result in DB for reconnections

**Feature bit in BOLT #1**: `bolt8_server.c` advertises bit 729 (LSPS) and bit 759
(SuperScalar) in every init message. Third-party wallets see the LSPS bits and know
to use LSPS0/1/2. SuperScalar-aware clients see bit 759 and switch to native protocol.

### Files

| File | Change |
|------|--------|
| `src/lsp_wellknown.c` | NEW — minimal HTTP server for /.well-known/lsps.json |
| `include/superscalar/lsp_wellknown.h` | NEW |
| `tools/superscalar_lsp.c` | Add `--well-known-port PORT` flag |
| `tools/superscalar_client.c` | Add `--lsp DOMAIN` flag; HTTPS bootstrap |
| `src/persist.c` | Persist cached LSP endpoint in DB (avoid re-bootstrap) |
| `tests/test_lsp_discovery.c` | NEW — HTTP response format, client bootstrap flow |
| `CMakeLists.txt` | Add lsp_wellknown.c, test_lsp_discovery.c |

### New tests
- `test_wellknown_json_format` — JSON response has required fields
- `test_client_bootstrap_from_domain` — mock HTTPS response → client connects correctly
- `test_feature_bit_advertisement` — BOLT #1 init contains bits 729 and 759

### Test delta: +3

---

## Phase 3 — BOLT #7 Gossip (Node Visibility)

### Problem
SuperScalar LSPs are invisible to the Lightning routing graph. Wallets that discover
LSPs by scanning gossip (the standard method) cannot find SuperScalar nodes.

### Design

**Minimum viable gossip** — we do NOT need to relay all gossip to other nodes.
We need to:
1. **Send node_announcement** (type 257) so we appear in the graph
2. **Send channel_announcement** (type 256) for our external LN channels so
   node_announcement is accepted (LN requires at least one channel_announcement first)
3. **Send channel_update** (type 258) with our routing policy
4. **Receive gossip** from seed peers and store it for routing decisions
5. **Send gossip_timestamp_filter** (type 265) to request gossip since last sync

**Key constraint**: node_announcement is rejected without a prior channel_announcement.
For the CLN-bridge deployment: use CLN's existing channels. For standalone: open one
"bootstrap" channel to a well-connected node.

**Gossip peers**: connect to 3-5 known LN nodes at startup (DNS seed: `nodes.lightning.directory`,
`soa.nodes.lightning.directory`, ACINQ/Bitrefill nodes as fallback).

**Gossip store**: SQLite tables:
- `gossip_nodes`: pubkey, alias, addresses, features, last_seen
- `gossip_channels`: scid, node1_pubkey, node2_pubkey, capacity, last_update
- `gossip_channel_updates`: scid, direction, fee_base, fee_ppm, cltv_delta, timestamp

**node_announcement fields** (type 257):
```
signature(64) features(varint+bytes) timestamp(4) node_id(33)
rgb_color(3) alias(32) addresses(varint+list)
```
Sign with node's static secp256k1 key.

**channel_announcement fields** (type 256):
```
node_sig_1(64) node_sig_2(64) bitcoin_sig_1(64) bitcoin_sig_2(64)
features(varint+bytes) chain_hash(32) short_channel_id(8)
node_id_1(33) node_id_2(33) bitcoin_key_1(33) bitcoin_key_2(33)
```
Requires both channel endpoints to sign + Bitcoin keys to sign.
For CLN-bridge deployment: use CLN's real channel SCID + CLN signs on behalf.

### Files

| File | Change |
|------|--------|
| `src/gossip.c` | NEW — message construction/parsing, peer loop, gossip store ops |
| `include/superscalar/gossip.h` | NEW — public API |
| `src/gossip_store.c` | NEW — SQLite gossip store (nodes/channels/updates tables) |
| `include/superscalar/gossip_store.h` | NEW |
| `src/persist.c` | Add gossip schema tables (schema v4 migration) |
| `tools/superscalar_lsp.c` | Add `--gossip-peers` flag, gossip thread startup |
| `tests/test_gossip.c` | NEW — message construction, signing, store ops |
| `CMakeLists.txt` | Add gossip.c, gossip_store.c, test_gossip.c |

### New tests
- `test_node_announcement_sign_verify` — construct + sign node_announcement, verify sig
- `test_channel_announcement_fields` — correct field ordering per BOLT #7
- `test_channel_update_construction` — routing policy fields
- `test_gossip_store_roundtrip` — store and retrieve node/channel entries
- `test_gossip_timestamp_filter` — construct filter message with correct chain_hash

### Test delta: +5

---

## Phase 4 — Factory Entry/Exit (CLN Bridge Optional)

### Problem
Inbound LN payments to factory clients require the CLN bridge. If CLN is down,
clients can't receive. The bridge also requires LSP operators to run two daemons
with separate liquidity pools.

### Design

**Fake SCID registry**: each factory leaf gets a short_channel_id (SCID) assigned at
leaf creation. The SCID encodes block_height=factory_id, tx_index=leaf_idx, vout=0.
These SCIDs appear in BOLT #11 invoice route hints.

Format (8 bytes, big-endian):
```
bits 63-40: block_height (24 bits) = factory internal ID
bits 39-16: tx_index (24 bits)     = leaf index
bits 15-0:  output_index (16 bits) = 0
```

**BOLT #4 last-hop onion decryption** — when a payment arrives with our node as
final hop:
1. Receive `update_add_htlc` on an inbound LN channel
2. Decrypt innermost onion layer using node static key + ephemeral key ECDH
3. Extract TLV fields: `amt_to_forward`, `outgoing_cltv_value`, `payment_secret`
4. Look up `payment_secret` → factory leaf → SCID mapping
5. Forward HTLC into factory leaf via existing `channel_add_htlc()`
6. When factory client fulfills: send `update_fulfill_htlc` back on LN channel

**HTLC state machine** (new, thin layer):
- `htlc_inbound_t`: pending inbound LN HTLCs awaiting factory fulfillment
- Timeout handling: if factory doesn't fulfill within CLTV window, fail upstream
- Persistence: `htlc_inbound` table in SQLite

The CLN bridge remains available as fallback (`--clnbridge` flag). Phase 4 makes
it optional for operators who want a single-binary deployment.

### Files

| File | Change |
|------|--------|
| `src/onion_last_hop.c` | NEW — BOLT #4 final-hop ECDH + TLV decryption |
| `include/superscalar/onion_last_hop.h` | NEW |
| `src/scid_registry.c` | NEW — factory leaf ↔ SCID mapping, route hint generation |
| `include/superscalar/scid_registry.h` | NEW |
| `src/htlc_inbound.c` | NEW — inbound HTLC state machine, timeout, fulfill/fail |
| `include/superscalar/htlc_inbound.h` | NEW |
| `src/persist.c` | Add scid_registry + htlc_inbound tables (schema v5 migration) |
| `tools/superscalar_lsp.c` | Wire up inbound HTLC handler, `--clnbridge` flag for fallback |
| `tests/test_onion_last_hop.c` | NEW — BOLT #4 final-hop spec test vectors |
| `tests/test_scid_registry.c` | NEW — SCID encode/decode, factory leaf mapping |
| `CMakeLists.txt` | Add new source files and test files |

### New tests
- `test_onion_last_hop_decrypt` — BOLT #4 test vector for final-hop decryption
- `test_scid_encode_decode` — factory_id + leaf_idx → SCID → back
- `test_scid_route_hint_format` — BOLT #11 route hint construction with fake SCID
- `test_htlc_inbound_fulfill_path` — receive HTLC → factory fulfill → upstream fulfill
- `test_htlc_inbound_timeout` — CLTV expiry → upstream fail

### Test delta: +5

---

## Phase 5 — Full Gossip Participation (Future / Out of Scope for PR #17)

**NOT built in this PR.** Requires:
- Full Sphinx onion construction (500+ lines)
- Gossip relay to other peers (become a relay node)
- Channel graph for pathfinding (100s MB on mainnet)
- This is effectively building a routing node — separate product decision

Revisit in 12-18 months when there is operational data on whether CLN dependency
is causing real pain and whether routing revenue justifies the scope.

---

## Branch and commit strategy

```
superscalar-hardening-v2  (PR #16)
    └── superscalar-ln-gossip   ← PR #17
          commit 1: feat: Phase 1 — BOLT #8 transport + BOLT #1 feature negotiation
          commit 2: feat: Phase 2 — LSP discovery (/.well-known + --lsp DOMAIN)
          commit 3: feat: Phase 3 — BOLT #7 gossip (node visibility)
          commit 4: feat: Phase 4 — factory entry/exit (BOLT #4 last-hop + fake SCIDs)
```

PR #17 title: `"LN integration: BOLT #8 transport + gossip visibility + factory entry/exit"`

---

## Starting test count

556 unit + 42 regtest = 598 total.
Target after all phases: ≥ 615 (556 + 17 new unit tests + 42 regtest unchanged).

---

## Key reference implementations

| Component | CLN reference | LND reference |
|-----------|---------------|---------------|
| BOLT #8 Noise_XK | `connectd/handshake.c` | `brontide/noise.go` |
| BOLT #1 init | `connectd/peer_exchange_initmsg.c` | `lnpeer/peer.go` |
| node_announcement | `gossipd/gossip_wire.c` | `discovery/gossiper.go` |
| channel_announcement | `gossipd/routing.c` | `discovery/manager.go` |
| Last-hop onion | `channeld/full_channel.c` | `htlcswitch/hop/payload.go` |
| Fake SCID | ACINQ Phoenix (pay-to-open) | `routing/route/vertex.go` |

---

## What this PR does NOT do

- Does not remove the CLN bridge (Phase 4 makes it optional, not gone)
- Does not implement full Sphinx onion routing (Phase 5, future)
- Does not implement gossip relay (full routing node capability, Phase 5)
- Does not change the factory protocol or channel structure
- Does not affect existing unit or regtest tests
