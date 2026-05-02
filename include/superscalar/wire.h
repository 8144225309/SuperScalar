#ifndef SUPERSCALAR_WIRE_H
#define SUPERSCALAR_WIRE_H

#include "types.h"
#include "factory.h"
#include "lsp_queue.h"
#include <stdint.h>
#include <stddef.h>
#include <cJSON.h>

/* --- Message types --- */
#define MSG_HELLO              0x01
#define MSG_DELIVER_PREIMAGE   0x72  /* LSP → Client: preimage for admin-created invoice */
#define MSG_PING               0x70  /* Keepalive: either side sends */
#define MSG_PONG               0x71  /* Keepalive response */
#define MSG_HELLO_ACK          0x02
#define MSG_FACTORY_PROPOSE    0x10
#define MSG_NONCE_BUNDLE       0x11
#define MSG_ALL_NONCES         0x12
#define MSG_PSIG_BUNDLE        0x13
#define MSG_FACTORY_READY      0x14
#define MSG_CLOSE_PROPOSE      0x20
#define MSG_CLOSE_NONCE        0x21
#define MSG_CLOSE_ALL_NONCES   0x22
#define MSG_CLOSE_PSIG         0x23
#define MSG_CLOSE_DONE         0x24
/* Channel operation messages (Phase 10) */
#define MSG_CHANNEL_READY      0x30
#define MSG_UPDATE_ADD_HTLC    0x31
#define MSG_COMMITMENT_SIGNED  0x32
#define MSG_REVOKE_AND_ACK     0x33
#define MSG_UPDATE_FULFILL_HTLC 0x34
#define MSG_UPDATE_FAIL_HTLC   0x35
#define MSG_CLOSE_REQUEST      0x36
#define MSG_CHANNEL_NONCES     0x37   /* batch of pubnonces for channel signing */
#define MSG_REGISTER_INVOICE   0x38   /* Client → LSP: register payment hash for inbound */
#define MSG_INVOICE_BOLT11     0x39   /* LSP → Client: BOLT11 string from CLN */

/* Bridge messages (Phase 14) */
#define MSG_BRIDGE_HELLO        0x40  /* Bridge → LSP: identify as bridge */
#define MSG_BRIDGE_HELLO_ACK    0x41  /* LSP → Bridge: acknowledge */
#define MSG_BRIDGE_ADD_HTLC     0x42  /* Bridge → LSP: inbound from LN */
#define MSG_BRIDGE_FULFILL_HTLC 0x43  /* LSP → Bridge: preimage back */
#define MSG_BRIDGE_FAIL_HTLC    0x44  /* LSP → Bridge: fail inbound */
#define MSG_BRIDGE_SEND_PAY     0x45  /* LSP → Bridge: outbound via CLN */
#define MSG_BRIDGE_PAY_RESULT   0x46  /* Bridge → LSP: sendpay result */
#define MSG_BRIDGE_REGISTER     0x47  /* LSP → Bridge: register invoice */

/* Reconnection messages (Phase 16) */
#define MSG_RECONNECT           0x48  /* Client → LSP: reconnect with pubkey */
#define MSG_RECONNECT_ACK       0x49  /* LSP → Client: reconnect acknowledged */

/* Invoice messages (Phase 17) */
#define MSG_CREATE_INVOICE      0x4A  /* LSP → Client: please create invoice */
#define MSG_INVOICE_CREATED     0x4B  /* Client → LSP: here's the payment_hash */

/* PTLC key turnover messages (Tier 3) */
#define MSG_PTLC_PRESIG         0x4C  /* LSP → Client: adaptor pre-signature */
#define MSG_PTLC_ADAPTED_SIG    0x4D  /* Client → LSP: adapted signature */
#define MSG_PTLC_COMPLETE       0x4E  /* LSP → Client: turnover acknowledged */

/* Bidirectional revocation (Client Watchtower) */
#define MSG_LSP_REVOKE_AND_ACK  0x50  /* LSP → Client: LSP's own revocation */

/* Basepoint exchange (Gap #1) */
#define MSG_CHANNEL_BASEPOINTS  0x4F  /* Both: exchange channel basepoint pubkeys */

/* JIT Channel Fallback (Gap #2) */
#define MSG_JIT_OFFER           0x51  /* LSP -> Client: offer JIT channel */
#define MSG_JIT_ACCEPT          0x52  /* Client -> LSP: accept JIT channel */
#define MSG_JIT_READY           0x53  /* LSP -> Client: JIT channel funded + ready */
#define MSG_JIT_MIGRATE         0x54  /* LSP -> Client: migrate JIT to factory */

/* Per-Leaf Advance */
#define MSG_LEAF_ADVANCE_PROPOSE 0x58 /* LSP -> Subtree clients: advance leaf */
#define MSG_LEAF_ADVANCE_PSIG    0x59 /* Client -> LSP: partial sig for leaf node */
#define MSG_LEAF_ADVANCE_DONE    0x5A /* LSP -> Subtree clients: leaf advance complete */

/* SCID assignment for route hints (4B) */
#define MSG_SCID_ASSIGN         0x5B  /* LSP → Client: SCID + routing params */

/* Leaf-Level Fund Reallocation (3-signer cooperative redistribution) */
#define MSG_LEAF_REALLOC_PROPOSE    0x5C  /* LSP → Clients: propose new amounts + LSP nonce */
#define MSG_LEAF_REALLOC_NONCE      0x5D  /* Client → LSP: client pubnonce */
#define MSG_LEAF_REALLOC_ALL_NONCES 0x5E  /* LSP → Clients: all 3 pubnonces */
#define MSG_LEAF_REALLOC_PSIG       0x5F  /* Client → LSP: partial sig */
#define MSG_LEAF_REALLOC_DONE       0x64  /* LSP → Clients: reallocation complete */

/* Path-scoped signing — used by the Tier B state-advance ceremony when
   the DW counter rolls over and a path through the tree (or the whole
   tree, in the worst case) needs to be re-signed.  The single-process
   equivalent is factory_advance() (Tier A, PR #112).  Wire ceremony
   driver is lsp_run_state_advance() in src/lsp.c. */
#define MSG_STATE_ADVANCE_PROPOSE 0x55 /* LSP -> Clients: advance to new epoch */
#define MSG_PATH_NONCE_BUNDLE   0x60  /* Client -> LSP: nonces for path nodes */
#define MSG_PATH_ALL_NONCES     0x61  /* LSP -> Clients: aggregated path nonces */
#define MSG_PATH_PSIG_BUNDLE    0x62  /* Client -> LSP: partial sigs for path */
#define MSG_PATH_SIGN_DONE      0x63  /* LSP -> Clients: path signing complete */

/* LSPS0/1/2 standard protocol (Phase E) */
#define MSG_LSPS_REQUEST   0x65  /* client → LSP: JSON-RPC request  */
#define MSG_LSPS_RESPONSE  0x66  /* LSP → client: JSON-RPC response */
#define MSG_LSPS_NOTIFY    0x67  /* LSP → client: async notification */

/* Splicing (Phase G — BOLT 2 draft) */
#define MSG_STFU           0x68  /* quiescence request */
#define MSG_STFU_ACK       0x69  /* quiescence acknowledge */
#define MSG_SPLICE_INIT    0x6A  /* initiator: new funding amount + spk */
#define MSG_SPLICE_ACK     0x6B  /* acceptor: agrees + optional contribution */
#define MSG_SPLICE_LOCKED  0x6C  /* both: new funding tx confirmed */

/* Async signing: pending work queue
 * NOTE: 0x65–0x6C are reserved for LSPS/splice above. */
#define MSG_QUEUE_POLL          0x6D  /* Client → LSP: poll for pending work items */
#define MSG_QUEUE_ITEMS         0x6E  /* LSP → Client: pending work items response */
#define MSG_QUEUE_DONE          0x6F  /* Client → LSP: acknowledge processed item IDs */

/* PS k² sub-factory chain extension ceremony (Gap E followup Phase 2b,
   t/1242 k² PS).  Drives the multi-party MuSig signing of a new
   sub-factory state when the LSP "sells liquidity from sales-stock".
   N-of-N over (LSP + k clients in this sub-factory).  Same shape as
   MSG_LEAF_REALLOC_* but scoped to one sub-factory's signers and
   carrying the (leaf_side, sub_idx, channel_idx, delta_sats) tuple
   in the propose. */
#define MSG_SUBFACTORY_PROPOSE      0x73  /* LSP → sub clients: propose chain extension */
#define MSG_SUBFACTORY_NONCE        0x74  /* Client → LSP: client pubnonce */
#define MSG_SUBFACTORY_ALL_NONCES   0x75  /* LSP → sub clients: all pubnonces */
#define MSG_SUBFACTORY_PSIG         0x76  /* Client → LSP: client partial sig */
#define MSG_SUBFACTORY_DONE         0x77  /* LSP → sub clients: chain extension complete */

#define MSG_ERROR              0xFF

/* --- Protocol limits --- */
#define WIRE_MAX_FRAME_SIZE     (16 * 1024 * 1024) /* 16 MB; needed for ALL_NONCES at N=64+ */
#define WIRE_DEFAULT_TIMEOUT_SEC 120

/* --- Wire frame: [uint32 len][uint8 type][JSON payload] --- */

typedef struct {
    uint8_t  msg_type;
    cJSON   *json;      /* caller must cJSON_Delete after use */
} wire_msg_t;

/* --- TCP transport --- */

int wire_listen(const char *host, int port);
int wire_accept(int listen_fd);
int wire_connect(const char *host, int port);
void wire_close(int fd);
int wire_set_timeout(int fd, int timeout_sec);

/* SOCKS5 proxy support (for Tor .onion addresses) */

/* Set global SOCKS5 proxy. When set, wire_connect() routes through it.
   .onion addresses always require a proxy; clearnet uses proxy if set. */
void wire_set_proxy(const char *host, int port);

/* Get current proxy config. Returns 1 if proxy is set. */
int wire_get_proxy(char *host_out, size_t host_len, int *port_out);

/* Tor-only mode: refuse all clearnet (non-.onion) connections.
   Requires a SOCKS5 proxy to be set via wire_set_proxy(). */
void wire_set_tor_only(int enable);
int wire_get_tor_only(void);

/* Connect via SOCKS5 proxy (used internally by wire_connect when proxy set). */
int wire_connect_via_proxy(const char *host, int port,
                           const char *proxy_host, int proxy_port);

/* Direct TCP connect (bypasses proxy). Used internally by tor.c to
   connect to the SOCKS5 proxy itself. */
int wire_connect_direct_internal(const char *host, int port);

/* --- Framing --- */

/* Send: writes [4-byte big-endian length][1-byte type][JSON bytes]. Returns 1 on success. */
int wire_send(int fd, uint8_t msg_type, cJSON *json);

/* Recv: reads one frame. Caller must cJSON_Delete(msg->json). Returns 1 on success, 0 on EOF/error. */
int wire_recv(int fd, wire_msg_t *msg);

/* Recv with per-call timeout: sets SO_RCVTIMEO to timeout_sec before recv,
   restores WIRE_DEFAULT_TIMEOUT_SEC after. Use timeout_sec=0 for infinite wait. */
int wire_recv_timeout(int fd, wire_msg_t *msg, int timeout_sec);

/* Recv, transparently handling MSG_PING/MSG_PONG keepalives.
   Loops until a non-keepalive message is received or the recv fails.
   Use in ceremony code where stale PONG messages may arrive. */
int wire_recv_skip_ping(int fd, wire_msg_t *msg);

/* --- Crypto JSON helpers --- */

/* Encode binary as hex string and add to JSON object */
void wire_json_add_hex(cJSON *obj, const char *key, const unsigned char *data, size_t len);

/* Decode hex string from JSON object into binary. Returns decoded length or 0 on error. */
int wire_json_get_hex(const cJSON *obj, const char *key, unsigned char *out, size_t max_len);

/* --- Nonce/Psig bundle entry --- */
typedef struct {
    uint32_t node_idx;
    uint32_t signer_slot;
    unsigned char data[66];  /* 66 for pubnonce, 32 for psig */
    size_t data_len;
} wire_bundle_entry_t;

/* --- Message builders --- */

/* Client → LSP: HELLO {pubkey} */
cJSON *wire_build_hello(const secp256k1_context *ctx, const secp256k1_pubkey *pubkey);

/* Optional: append `"slot_hint": N` to a HELLO json. N = 1..n_clients (LSP slot
   the client wants placed at). N = 0 means no hint. LSP may use this to enforce
   a deterministic keyagg order across restarts. */
void wire_hello_set_slot_hint(cJSON *hello, int slot_hint);

/* LSP → Client: HELLO_ACK {lsp_pubkey, participant_index, all_pubkeys[]} */
cJSON *wire_build_hello_ack(const secp256k1_context *ctx,
                            const secp256k1_pubkey *lsp_pubkey,
                            uint32_t participant_index,
                            const secp256k1_pubkey *all_pubkeys, size_t n);

/* LSP → Client: FACTORY_PROPOSE {funding_txid, funding_vout, funding_amount,
                                   step_blocks, states_per_layer, cltv_timeout, fee_per_tx} */
cJSON *wire_build_factory_propose(const factory_t *f);

/* Client → LSP: NONCE_BUNDLE {entries: [{node_idx, slot, pubnonce_hex}...]} */
cJSON *wire_build_nonce_bundle(const wire_bundle_entry_t *entries, size_t n);

/* LSP → Client: ALL_NONCES {nonces: [{node_idx, slot, pubnonce_hex}...]} */
cJSON *wire_build_all_nonces(const wire_bundle_entry_t *entries, size_t n);

/* Client → LSP: PSIG_BUNDLE {entries: [{node_idx, slot, psig_hex}...]} */
cJSON *wire_build_psig_bundle(const wire_bundle_entry_t *entries, size_t n);

/* LSP → Client: FACTORY_READY {signed_txs: [{node_idx, tx_hex}...]} */
cJSON *wire_build_factory_ready(const factory_t *f);

/* LSP → Client: CLOSE_PROPOSE {outputs: [{amount, spk_hex}...], current_height} */
cJSON *wire_build_close_propose(const tx_output_t *outputs, size_t n,
                                uint32_t current_height);

/* Client → LSP: CLOSE_NONCE {pubnonce_hex} */
cJSON *wire_build_close_nonce(const unsigned char *pubnonce66);

/* LSP → Client: CLOSE_ALL_NONCES {nonces: [pubnonce_hex...]} */
cJSON *wire_build_close_all_nonces(const unsigned char pubnonces[][66], size_t n);

/* Client → LSP: CLOSE_PSIG {psig_hex} */
cJSON *wire_build_close_psig(const unsigned char *psig32);

/* LSP → Client: CLOSE_DONE {tx_hex} */
cJSON *wire_build_close_done(const unsigned char *tx_data, size_t tx_len);

/* MSG_ERROR {message} */
cJSON *wire_build_error(const char *message);

/* --- Channel operation message builders (Phase 10) --- */

/* LSP → Client: CHANNEL_READY {channel_id, balance_local_msat, balance_remote_msat} */
cJSON *wire_build_channel_ready(uint32_t channel_id,
                                 uint64_t balance_local_msat,
                                 uint64_t balance_remote_msat);

/* Either → LSP: UPDATE_ADD_HTLC {htlc_id, amount_msat, payment_hash, cltv_expiry} */
cJSON *wire_build_update_add_htlc(uint64_t htlc_id, uint64_t amount_msat,
                                    const unsigned char *payment_hash32,
                                    uint32_t cltv_expiry);

/* Both: COMMITMENT_SIGNED {channel_id, commitment_number, partial_sig, nonce_index} */
cJSON *wire_build_commitment_signed(uint32_t channel_id,
                                      uint64_t commitment_number,
                                      const unsigned char *partial_sig32,
                                      uint32_t nonce_index);

/* Both: REVOKE_AND_ACK {channel_id, revocation_secret, next_per_commitment_point} */
cJSON *wire_build_revoke_and_ack(uint32_t channel_id,
                                   const unsigned char *revocation_secret32,
                                   const secp256k1_context *ctx,
                                   const secp256k1_pubkey *next_per_commitment_point);

/* Either → LSP: UPDATE_FULFILL_HTLC {htlc_id, preimage} */
cJSON *wire_build_update_fulfill_htlc(uint64_t htlc_id,
                                        const unsigned char *preimage32);

/* Either → LSP: UPDATE_FAIL_HTLC {htlc_id, reason} */
cJSON *wire_build_update_fail_htlc(uint64_t htlc_id, const char *reason);

/* Client → LSP: CLOSE_REQUEST {} */
cJSON *wire_build_close_request(void);

/* Both: CHANNEL_NONCES {channel_id, pubnonces: ["hex"...]} */
cJSON *wire_build_channel_nonces(uint32_t channel_id,
                                   const unsigned char pubnonces[][66],
                                   size_t count);

/* --- Channel operation message parsers (Phase 10) --- */

int wire_parse_channel_ready(const cJSON *json, uint32_t *channel_id,
                              uint64_t *balance_local_msat,
                              uint64_t *balance_remote_msat);

int wire_parse_update_add_htlc(const cJSON *json, uint64_t *htlc_id,
                                 uint64_t *amount_msat,
                                 unsigned char *payment_hash32,
                                 uint32_t *cltv_expiry);

int wire_parse_commitment_signed(const cJSON *json, uint32_t *channel_id,
                                   uint64_t *commitment_number,
                                   unsigned char *partial_sig32,
                                   uint32_t *nonce_index);

int wire_parse_revoke_and_ack(const cJSON *json, uint32_t *channel_id,
                                unsigned char *revocation_secret32,
                                unsigned char *next_point33);

int wire_parse_update_fulfill_htlc(const cJSON *json, uint64_t *htlc_id,
                                     unsigned char *preimage32);

int wire_parse_update_fail_htlc(const cJSON *json, uint64_t *htlc_id,
                                  char *reason, size_t reason_len);

int wire_parse_channel_nonces(const cJSON *json, uint32_t *channel_id,
                                unsigned char pubnonces_out[][66],
                                size_t max_nonces, size_t *count_out);

/* Client → LSP: REGISTER_INVOICE {payment_hash, preimage, amount_msat, dest_client} */
cJSON *wire_build_register_invoice(const unsigned char *payment_hash32,
                                     const unsigned char *preimage32,
                                     uint64_t amount_msat, size_t dest_client);

int wire_parse_register_invoice(const cJSON *json,
                                  unsigned char *payment_hash32,
                                  unsigned char *preimage32,
                                  uint64_t *amount_msat, size_t *dest_client);

/* --- Bridge message builders (Phase 14) --- */

/* Bridge → LSP: BRIDGE_HELLO {} */
cJSON *wire_build_bridge_hello(void);

/* LSP → Bridge: BRIDGE_HELLO_ACK {} */
cJSON *wire_build_bridge_hello_ack(void);

/* Bridge → LSP: BRIDGE_ADD_HTLC {payment_hash, amount_msat, cltv_expiry, htlc_id,
   [keysend], [dest_client], [preimage]} — keysend fields optional (backward-compat) */
cJSON *wire_build_bridge_add_htlc(const unsigned char *payment_hash32,
                                    uint64_t amount_msat, uint32_t cltv_expiry,
                                    uint64_t htlc_id);

/* Keysend variant: includes preimage + dest_client for spontaneous payments */
cJSON *wire_build_bridge_add_htlc_keysend(const unsigned char *payment_hash32,
                                            uint64_t amount_msat, uint32_t cltv_expiry,
                                            uint64_t htlc_id,
                                            const unsigned char *preimage32,
                                            size_t dest_client);

/* LSP → Bridge: BRIDGE_FULFILL_HTLC {payment_hash, preimage, htlc_id} */
cJSON *wire_build_bridge_fulfill_htlc(const unsigned char *payment_hash32,
                                        const unsigned char *preimage32,
                                        uint64_t htlc_id);

/* LSP → Bridge: BRIDGE_FAIL_HTLC {payment_hash, reason, htlc_id} */
cJSON *wire_build_bridge_fail_htlc(const unsigned char *payment_hash32,
                                     const char *reason, uint64_t htlc_id);

/* LSP → Bridge: BRIDGE_SEND_PAY {bolt11, payment_hash, request_id} */
cJSON *wire_build_bridge_send_pay(const char *bolt11,
                                    const unsigned char *payment_hash32,
                                    uint64_t request_id);

/* Bridge → LSP: BRIDGE_PAY_RESULT {request_id, success, preimage} */
cJSON *wire_build_bridge_pay_result(uint64_t request_id, int success,
                                      const unsigned char *preimage32);

/* LSP → Bridge: BRIDGE_REGISTER {payment_hash, preimage, amount_msat, dest_client} */
cJSON *wire_build_bridge_register(const unsigned char *payment_hash32,
                                    const unsigned char *preimage32,
                                    uint64_t amount_msat, size_t dest_client);

/* --- Bridge message parsers (Phase 14) --- */

int wire_parse_bridge_add_htlc(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 uint64_t *amount_msat, uint32_t *cltv_expiry,
                                 uint64_t *htlc_id);

/* Extended parser: also extracts optional keysend fields.
   *is_keysend_out=1 if keysend present, preimage32/dest_client_out filled.
   *is_keysend_out=0 if absent (backward-compatible). */
int wire_parse_bridge_add_htlc_keysend(const cJSON *json,
                                         unsigned char *payment_hash32,
                                         uint64_t *amount_msat, uint32_t *cltv_expiry,
                                         uint64_t *htlc_id,
                                         int *is_keysend_out,
                                         unsigned char *preimage32,
                                         size_t *dest_client_out);

int wire_parse_bridge_fulfill_htlc(const cJSON *json,
                                     unsigned char *payment_hash32,
                                     unsigned char *preimage32,
                                     uint64_t *htlc_id);

int wire_parse_bridge_fail_htlc(const cJSON *json,
                                  unsigned char *payment_hash32,
                                  char *reason, size_t reason_len,
                                  uint64_t *htlc_id);

int wire_parse_bridge_send_pay(const cJSON *json,
                                 char *bolt11, size_t bolt11_len,
                                 unsigned char *payment_hash32,
                                 uint64_t *request_id);

int wire_parse_bridge_pay_result(const cJSON *json,
                                   uint64_t *request_id, int *success,
                                   unsigned char *preimage32);

int wire_parse_bridge_register(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 unsigned char *preimage32,
                                 uint64_t *amount_msat, size_t *dest_client);

/* LSP → Client: INVOICE_BOLT11 {payment_hash, bolt11} */
cJSON *wire_build_invoice_bolt11(const unsigned char *payment_hash32,
                                   const char *bolt11);

int wire_parse_invoice_bolt11(const cJSON *json,
                                unsigned char *payment_hash32,
                                char *bolt11, size_t bolt11_len);

/* --- Reconnection messages (Phase 16) --- */

/* Client → LSP: RECONNECT {pubkey, commitment_number} */
cJSON *wire_build_reconnect(const secp256k1_context *ctx,
                              const secp256k1_pubkey *pubkey,
                              uint64_t commitment_number);

int wire_parse_reconnect(const cJSON *json, const secp256k1_context *ctx,
                           secp256k1_pubkey *pubkey_out,
                           uint64_t *commitment_number_out);

/* LSP → Client: RECONNECT_ACK {channel_id, local_amount_msat, remote_amount_msat, commitment_number} */
cJSON *wire_build_reconnect_ack(uint32_t channel_id,
                                  uint64_t local_amount_msat,
                                  uint64_t remote_amount_msat,
                                  uint64_t commitment_number);

int wire_parse_reconnect_ack(const cJSON *json, uint32_t *channel_id,
                                uint64_t *local_amount_msat,
                                uint64_t *remote_amount_msat,
                                uint64_t *commitment_number);

/* --- Invoice messages (Phase 17) --- */

/* LSP → Client: CREATE_INVOICE {amount_msat} */
cJSON *wire_build_create_invoice(uint64_t amount_msat);

int wire_parse_create_invoice(const cJSON *json, uint64_t *amount_msat);

/* Client → LSP: INVOICE_CREATED {payment_hash, amount_msat} */
cJSON *wire_build_invoice_created(const unsigned char *payment_hash32,
                                    uint64_t amount_msat);

int wire_parse_invoice_created(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 uint64_t *amount_msat);

/* --- PTLC key turnover messages (Tier 3) --- */

/* LSP → Client: PTLC_PRESIG {presig, nonce_parity, turnover_msg} */
cJSON *wire_build_ptlc_presig(const unsigned char *presig64,
                               int nonce_parity,
                               const unsigned char *turnover_msg32);

int wire_parse_ptlc_presig(const cJSON *json, unsigned char *presig64,
                            int *nonce_parity, unsigned char *turnover_msg32);

/* Client → LSP: PTLC_ADAPTED_SIG {adapted_sig} */
cJSON *wire_build_ptlc_adapted_sig(const unsigned char *adapted_sig64);

int wire_parse_ptlc_adapted_sig(const cJSON *json, unsigned char *adapted_sig64);

/* LSP → Client: PTLC_COMPLETE {} */
cJSON *wire_build_ptlc_complete(void);

/* --- Basepoint exchange (Gap #1) --- */

/* Both: CHANNEL_BASEPOINTS {channel_id, payment_basepoint, delayed_payment_basepoint,
   revocation_basepoint, htlc_basepoint, first_per_commitment_point} */
cJSON *wire_build_channel_basepoints(
    uint32_t channel_id,
    const secp256k1_context *ctx,
    const secp256k1_pubkey *payment_basepoint,
    const secp256k1_pubkey *delayed_payment_basepoint,
    const secp256k1_pubkey *revocation_basepoint,
    const secp256k1_pubkey *htlc_basepoint,
    const secp256k1_pubkey *first_per_commitment_point,
    const secp256k1_pubkey *second_per_commitment_point);

int wire_parse_channel_basepoints(
    const cJSON *json,
    uint32_t *channel_id_out,
    const secp256k1_context *ctx,
    secp256k1_pubkey *payment_bp_out,
    secp256k1_pubkey *delayed_bp_out,
    secp256k1_pubkey *revocation_bp_out,
    secp256k1_pubkey *htlc_bp_out,
    secp256k1_pubkey *first_pcp_out,
    secp256k1_pubkey *second_pcp_out);

/* --- JIT Channel messages (Gap #2) --- */

/* LSP -> Client: JIT_OFFER {client_idx, funding_amount, reason, lsp_pubkey} */
cJSON *wire_build_jit_offer(size_t client_idx, uint64_t funding_amount,
                              const char *reason,
                              const secp256k1_context *ctx,
                              const secp256k1_pubkey *lsp_pubkey);

int wire_parse_jit_offer(const cJSON *json, const secp256k1_context *ctx,
                           size_t *client_idx, uint64_t *funding_amount,
                           char *reason, size_t reason_len,
                           secp256k1_pubkey *lsp_pubkey);

/* Client -> LSP: JIT_ACCEPT {client_idx, client_pubkey} */
cJSON *wire_build_jit_accept(size_t client_idx,
                               const secp256k1_context *ctx,
                               const secp256k1_pubkey *client_pubkey);

int wire_parse_jit_accept(const cJSON *json, const secp256k1_context *ctx,
                            size_t *client_idx,
                            secp256k1_pubkey *client_pubkey);

/* LSP -> Client: JIT_READY {jit_channel_id, funding_txid, vout, amount,
                              local_amount, remote_amount} */
cJSON *wire_build_jit_ready(uint32_t jit_channel_id,
                              const char *funding_txid_hex,
                              uint32_t vout, uint64_t amount,
                              uint64_t local_amount, uint64_t remote_amount);

int wire_parse_jit_ready(const cJSON *json, uint32_t *jit_channel_id,
                           char *funding_txid_hex, size_t hex_len,
                           uint32_t *vout, uint64_t *amount,
                           uint64_t *local_amount, uint64_t *remote_amount);

/* LSP -> Client: JIT_MIGRATE {jit_channel_id, target_factory_id,
                                local_balance, remote_balance} */
cJSON *wire_build_jit_migrate(uint32_t jit_channel_id,
                                uint32_t target_factory_id,
                                uint64_t local_balance, uint64_t remote_balance);

int wire_parse_jit_migrate(const cJSON *json, uint32_t *jit_channel_id,
                             uint32_t *target_factory_id,
                             uint64_t *local_balance, uint64_t *remote_balance);

/* --- Per-Leaf Advance message builders (Upgrade 2) --- */

/* LSP -> Client: LEAF_ADVANCE_PROPOSE {leaf_side, pubnonce, [poison_pubnonce]}.
   poison_pubnonce is OPTIONAL on the wire — when present it accompanies
   the state pubnonce so the client can run two MuSig2 ceremonies in
   lockstep (closes Wire-Ceremony Gap A for leaf advance: poison TX
   defense in multi-process LSPs).  Pass `poison_pubnonce66 = NULL` to
   either build or parse to skip the second nonce.  Parse return value:
   0 = failure, 1 = state only, 2 = state + poison both parsed. */
cJSON *wire_build_leaf_advance_propose(int leaf_side,
                                        const unsigned char *state_pubnonce66,
                                        const unsigned char *poison_pubnonce66);

int wire_parse_leaf_advance_propose(const cJSON *json, int *leaf_side,
                                      unsigned char *state_pubnonce66,
                                      unsigned char *poison_pubnonce66);

/* Client -> LSP: LEAF_ADVANCE_PSIG {pubnonce, partial_sig,
                                       [poison_pubnonce, poison_partial_sig]}.
   Same dual-sig semantics as PROPOSE — second pair is the client's
   MuSig2 nonce + partial sig over the OLD state's poison TX sighash. */
cJSON *wire_build_leaf_advance_psig(const unsigned char *state_pubnonce66,
                                      const unsigned char *state_partial_sig32,
                                      const unsigned char *poison_pubnonce66,
                                      const unsigned char *poison_partial_sig32);

int wire_parse_leaf_advance_psig(const cJSON *json,
                                    unsigned char *state_pubnonce66,
                                    unsigned char *state_partial_sig32,
                                    unsigned char *poison_pubnonce66,
                                    unsigned char *poison_partial_sig32);

/* LSP -> All: LEAF_ADVANCE_DONE {leaf_side} */
cJSON *wire_build_leaf_advance_done(int leaf_side);

int wire_parse_leaf_advance_done(const cJSON *json, int *leaf_side);

/* --- Tier B: state-advance ceremony (root rollover, MSG_PATH_*) ---

   When factory_advance_leaf_unsigned() returns -1, the leaf's per-leaf
   DW counter exhausted, the root layer advanced, and every non-PS,
   non-static-only node's nSequence changed.  All such nodes need to be
   re-signed via N-of-N MuSig.  This ceremony bundles per-node nonces
   and partial sigs across the wire so we get O(1) round trips instead
   of O(n_nodes).  See docs/rotation-ceremony.md.

   The bundle messages MSG_PATH_NONCE_BUNDLE/ALL_NONCES/PSIG_BUNDLE
   reuse the existing wire_build_nonce_bundle/all_nonces/psig_bundle
   JSON shape and wire_parse_bundle parser — they're dispatched by
   message ID, not JSON shape. */

/* LSP → Clients: STATE_ADVANCE_PROPOSE {epoch, trigger_leaf, lsp_nonces[]}
   lsp_nonces is the LSP's own per-node pubnonce contributions, bundled
   over every node in the tree where the LSP is a signer. */
cJSON *wire_build_state_advance_propose(uint32_t epoch, int trigger_leaf,
                                          const wire_bundle_entry_t *lsp_nonces,
                                          size_t n_lsp_nonces);

int wire_parse_state_advance_propose(const cJSON *json, uint32_t *epoch_out,
                                       int *trigger_leaf_out,
                                       wire_bundle_entry_t *lsp_nonces_out,
                                       size_t max_nonces, size_t *n_out);

/* LSP → Clients: PATH_SIGN_DONE {epoch} */
cJSON *wire_build_path_sign_done(uint32_t epoch);

int wire_parse_path_sign_done(const cJSON *json, uint32_t *epoch_out);

/* --- Leaf-Level Fund Reallocation message builders (Upgrade 3) --- */

/* LSP → Clients: LEAF_REALLOC_PROPOSE {leaf_side, amounts[], pubnonce} */
cJSON *wire_build_leaf_realloc_propose(int leaf_side,
                                        const uint64_t *amounts, size_t n_amounts,
                                        const unsigned char *pubnonce66);

int wire_parse_leaf_realloc_propose(const cJSON *json, int *leaf_side,
                                      uint64_t *amounts, size_t max_amounts,
                                      size_t *n_amounts_out,
                                      unsigned char *pubnonce66);

/* Client → LSP: LEAF_REALLOC_NONCE {pubnonce} */
cJSON *wire_build_leaf_realloc_nonce(const unsigned char *pubnonce66);

int wire_parse_leaf_realloc_nonce(const cJSON *json, unsigned char *pubnonce66);

/* LSP → Clients: LEAF_REALLOC_ALL_NONCES {pubnonces[3]} */
cJSON *wire_build_leaf_realloc_all_nonces(const unsigned char pubnonces[][66],
                                            size_t n_signers);

int wire_parse_leaf_realloc_all_nonces(const cJSON *json,
                                         unsigned char pubnonces_out[][66],
                                         size_t max_signers, size_t *n_out);

/* Client → LSP: LEAF_REALLOC_PSIG {partial_sig} */
cJSON *wire_build_leaf_realloc_psig(const unsigned char *partial_sig32);

int wire_parse_leaf_realloc_psig(const cJSON *json, unsigned char *partial_sig32);

/* LSP → Clients: LEAF_REALLOC_DONE {leaf_side, amounts[]} */
cJSON *wire_build_leaf_realloc_done(int leaf_side,
                                      const uint64_t *amounts, size_t n_amounts);

int wire_parse_leaf_realloc_done(const cJSON *json, int *leaf_side,
                                   uint64_t *amounts, size_t max_amounts,
                                   size_t *n_amounts_out);

/* --- PS k² Sub-factory Chain Extension (Gap E followup Phase 2b) ---

   Wire ceremony for the canonical "buy liquidity from sales-stock" op
   (factory_subfactory_chain_advance_unsigned).  N-of-N MuSig over
   (LSP + k clients in the target sub-factory). */

/* LSP → sub clients: SUBFACTORY_PROPOSE
     {leaf_side, sub_idx, channel_idx, delta_sats, lsp_pubnonce} */
cJSON *wire_build_subfactory_propose(int leaf_side, int sub_idx,
                                       int channel_idx, uint64_t delta_sats,
                                       const unsigned char *lsp_pubnonce66);

int wire_parse_subfactory_propose(const cJSON *json,
                                    int *leaf_side, int *sub_idx,
                                    int *channel_idx, uint64_t *delta_sats,
                                    unsigned char *lsp_pubnonce66);

/* Client → LSP: SUBFACTORY_NONCE {pubnonce, [poison_pubnonce]}.
   Both fields carry 66-byte MuSig2 pubnonces.  poison_pubnonce is
   OPTIONAL on the wire (legacy clients omit it); when present it
   accompanies the state pubnonce for the same signer in the same
   message — this lets the LSP run two split-round MuSig2 ceremonies
   in lockstep (closes Wire-Ceremony Gap A: poison TX in multi-process).
   Pass `poison_pubnonce66 = NULL` to either build or parse to skip the
   second nonce.  Parse return value: 0 = failure, 1 = state only,
   2 = state + poison both parsed. */
cJSON *wire_build_subfactory_nonce(const unsigned char *state_pubnonce66,
                                     const unsigned char *poison_pubnonce66);
int wire_parse_subfactory_nonce(const cJSON *json,
                                  unsigned char *state_pubnonce66,
                                  unsigned char *poison_pubnonce66);

/* LSP → sub clients: SUBFACTORY_ALL_NONCES {pubnonces[], [poison_pubnonces[]]}.
   Same dual-nonce semantics as SUBFACTORY_NONCE.  Pass
   `poison_pubnonces = NULL` (build) or `poison_pubnonces_out = NULL`
   (parse) to skip the second array. */
cJSON *wire_build_subfactory_all_nonces(const unsigned char pubnonces[][66],
                                          const unsigned char poison_pubnonces[][66],
                                          size_t n_signers);
int wire_parse_subfactory_all_nonces(const cJSON *json,
                                       unsigned char pubnonces_out[][66],
                                       unsigned char poison_pubnonces_out[][66],
                                       size_t max_signers, size_t *n_out);

/* Client → LSP: SUBFACTORY_PSIG {partial_sig, [poison_partial_sig]}.
   Same dual-sig semantics — second sig is the client's MuSig2 partial
   sig over the OLD state's poison TX sighash.  Optional. */
cJSON *wire_build_subfactory_psig(const unsigned char *state_psig32,
                                    const unsigned char *poison_psig32);
int wire_parse_subfactory_psig(const cJSON *json,
                                 unsigned char *state_psig32,
                                 unsigned char *poison_psig32);

/* LSP → sub clients: SUBFACTORY_DONE {leaf_side, sub_idx, chain_len} */
cJSON *wire_build_subfactory_done(int leaf_side, int sub_idx, uint32_t chain_len);
int wire_parse_subfactory_done(const cJSON *json,
                                 int *leaf_side, int *sub_idx,
                                 uint32_t *chain_len);

/* --- SCID assignment for route hints (4B) --- */

/* LSP → Client: SCID_ASSIGN {channel_id, scid, fee_base_msat, fee_ppm, cltv_delta} */
cJSON *wire_build_scid_assign(uint32_t channel_id, uint64_t scid,
                               uint32_t fee_base_msat, uint32_t fee_ppm,
                               uint16_t cltv_delta);

int wire_parse_scid_assign(const cJSON *json, uint32_t *channel_id,
                             uint64_t *scid, uint32_t *fee_base_msat,
                             uint32_t *fee_ppm, uint16_t *cltv_delta);

/* --- Bundle parsing --- */

/* Parse a nonce or psig bundle array from JSON. Returns count, fills entries[]. */
size_t wire_parse_bundle(const cJSON *array, wire_bundle_entry_t *entries,
                         size_t max_entries, size_t expected_data_len);

/* --- Splice message builders/parsers (Phase G) --- */

/* Initiator → Acceptor: SPLICE_INIT {channel_id, new_funding_amount, new_funding_spk_hex} */
cJSON *wire_build_splice_init(uint32_t channel_id,
                               uint64_t new_funding_amount,
                               const unsigned char *new_funding_spk,
                               size_t new_funding_spk_len);

int wire_parse_splice_init(const cJSON *json,
                            uint32_t *channel_id_out,
                            uint64_t *new_funding_amount_out,
                            unsigned char *new_funding_spk_out,
                            size_t *new_funding_spk_len_out,
                            size_t max_spk_len);

/* Acceptor → Initiator: SPLICE_ACK {channel_id, acceptor_contribution} */
cJSON *wire_build_splice_ack(uint32_t channel_id, uint64_t acceptor_contribution);

int wire_parse_splice_ack(const cJSON *json,
                           uint32_t *channel_id_out,
                           uint64_t *acceptor_contribution_out);

/* Both: SPLICE_LOCKED {channel_id, new_funding_txid_hex, new_funding_vout} */
cJSON *wire_build_splice_locked(uint32_t channel_id,
                                  const unsigned char *new_funding_txid32,
                                  uint32_t new_funding_vout);

int wire_parse_splice_locked(const cJSON *json,
                               uint32_t *channel_id_out,
                               unsigned char *new_funding_txid32_out,
                               uint32_t *new_funding_vout_out);

/* --- Encrypted transport (Phase 19) --- */

/* Perform noise handshake as initiator and register encryption for fd.
   Call after wire_connect(), before any wire_send/wire_recv.
   Returns 1 on success, 0 on failure. */
int wire_noise_handshake_initiator(int fd, secp256k1_context *ctx);

/* Perform noise handshake as responder and register encryption for fd.
   Call after wire_accept(), before any wire_send/wire_recv.
   Returns 1 on success, 0 on failure. */
int wire_noise_handshake_responder(int fd, secp256k1_context *ctx);

/* NK (server-authenticated) variants.
   Initiator pins server's static pubkey; responder uses its static secret.
   Returns 1 on success, 0 on failure (wrong server key = failure). */
int wire_noise_handshake_nk_initiator(int fd, secp256k1_context *ctx,
                                        const secp256k1_pubkey *server_pubkey);
int wire_noise_handshake_nk_responder(int fd, secp256k1_context *ctx,
                                        const unsigned char *static_seckey32);

/* --- Wire message logging (Phase 22) --- */

/* Log callback: direction 0=sent, 1=recv */
typedef void (*wire_log_callback_t)(int direction, uint8_t msg_type,
                                     const cJSON *json, const char *peer_label,
                                     void *userdata);
void wire_set_log_callback(wire_log_callback_t cb, void *userdata);

/* Human-readable name for a message type constant */
const char *wire_msg_type_name(uint8_t type);

/* Associate a peer label (e.g. "client_0", "bridge") with a file descriptor */
void wire_set_peer_label(int fd, const char *label);

/* --- Async signing: queue messages --- */

/* LSP → Client: QUEUE_ITEMS {items:[{id,request_type,urgency,factory_id,payload},...]}
   entries: array of queue_entry_t; count: number of entries (0 = empty list) */
cJSON *wire_build_queue_items(const queue_entry_t *entries, size_t count);

/* Client → LSP: QUEUE_DONE {ids:[N,...]}
   Parses acknowledged item IDs. Returns 1 on success. */
int wire_parse_queue_done(const cJSON *json,
                           uint64_t *ids_out, size_t max_ids,
                           size_t *count_out);

#endif /* SUPERSCALAR_WIRE_H */
