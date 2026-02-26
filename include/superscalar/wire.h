#ifndef SUPERSCALAR_WIRE_H
#define SUPERSCALAR_WIRE_H

#include "types.h"
#include "factory.h"
#include <stdint.h>
#include <stddef.h>
#include <cJSON.h>

/* --- Message types --- */
#define MSG_HELLO              0x01
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

/* Cooperative Epoch Reset */
#define MSG_EPOCH_RESET_PROPOSE 0x55  /* LSP -> All: propose epoch reset + nonces */
#define MSG_EPOCH_RESET_PSIG    0x56  /* Client -> LSP: partial sigs for reset */
#define MSG_EPOCH_RESET_DONE    0x57  /* LSP -> All: reset complete, new signed txs */

/* Per-Leaf Advance */
#define MSG_LEAF_ADVANCE_PROPOSE 0x58 /* LSP -> Subtree clients: advance leaf */
#define MSG_LEAF_ADVANCE_PSIG    0x59 /* Client -> LSP: partial sig for leaf node */
#define MSG_LEAF_ADVANCE_DONE    0x5A /* LSP -> Subtree clients: leaf advance complete */

#define MSG_ERROR              0xFF

/* --- Protocol limits --- */
#define WIRE_MAX_FRAME_SIZE     (65536)         /* 64 KB */
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

/* LSP → Client: CLOSE_PROPOSE {outputs: [{amount, spk_hex}...]} */
cJSON *wire_build_close_propose(const tx_output_t *outputs, size_t n);

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

/* Client → LSP: REGISTER_INVOICE {payment_hash, amount_msat, dest_client} */
cJSON *wire_build_register_invoice(const unsigned char *payment_hash32,
                                     uint64_t amount_msat, size_t dest_client);

int wire_parse_register_invoice(const cJSON *json,
                                  unsigned char *payment_hash32,
                                  uint64_t *amount_msat, size_t *dest_client);

/* --- Bridge message builders (Phase 14) --- */

/* Bridge → LSP: BRIDGE_HELLO {} */
cJSON *wire_build_bridge_hello(void);

/* LSP → Bridge: BRIDGE_HELLO_ACK {} */
cJSON *wire_build_bridge_hello_ack(void);

/* Bridge → LSP: BRIDGE_ADD_HTLC {payment_hash, amount_msat, cltv_expiry, htlc_id} */
cJSON *wire_build_bridge_add_htlc(const unsigned char *payment_hash32,
                                    uint64_t amount_msat, uint32_t cltv_expiry,
                                    uint64_t htlc_id);

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

/* LSP → Bridge: BRIDGE_REGISTER {payment_hash, amount_msat, dest_client} */
cJSON *wire_build_bridge_register(const unsigned char *payment_hash32,
                                    uint64_t amount_msat, size_t dest_client);

/* --- Bridge message parsers (Phase 14) --- */

int wire_parse_bridge_add_htlc(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 uint64_t *amount_msat, uint32_t *cltv_expiry,
                                 uint64_t *htlc_id);

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
                                 uint64_t *amount_msat, size_t *dest_client);

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

/* LSP -> Client: LEAF_ADVANCE_PROPOSE {leaf_side, pubnonce} */
cJSON *wire_build_leaf_advance_propose(int leaf_side,
                                        const unsigned char *pubnonce66);

int wire_parse_leaf_advance_propose(const cJSON *json, int *leaf_side,
                                      unsigned char *pubnonce66);

/* Client -> LSP: LEAF_ADVANCE_PSIG {pubnonce, partial_sig} */
cJSON *wire_build_leaf_advance_psig(const unsigned char *pubnonce66,
                                      const unsigned char *partial_sig32);

int wire_parse_leaf_advance_psig(const cJSON *json,
                                    unsigned char *pubnonce66,
                                    unsigned char *partial_sig32);

/* LSP -> All: LEAF_ADVANCE_DONE {leaf_side} */
cJSON *wire_build_leaf_advance_done(int leaf_side);

int wire_parse_leaf_advance_done(const cJSON *json, int *leaf_side);

/* --- Bundle parsing --- */

/* Parse a nonce or psig bundle array from JSON. Returns count, fills entries[]. */
size_t wire_parse_bundle(const cJSON *array, wire_bundle_entry_t *entries,
                         size_t max_entries, size_t expected_data_len);

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

#endif /* SUPERSCALAR_WIRE_H */
