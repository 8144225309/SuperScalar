/*
 * htlc_commit.h — BOLT #2 binary HTLC commitment round-trip for external peers
 *
 * This module is the missing wire layer between the channel state machine
 * (channel.c, which has all the logic) and the peer transport layer
 * (peer_mgr.c, which handles BOLT #8 framing). It encodes/decodes BOLT #2
 * binary messages and drives the commitment update state machine.
 *
 * Commitment update sequence (BOLT #2 §2.4):
 *   Sender:   update_add_htlc → commitment_signed
 *   Receiver: revoke_and_ack → commitment_signed
 *   Sender:   revoke_and_ack
 *
 * Signature format (SuperScalar MuSig2 extension):
 *   The 64-byte sig field in commitment_signed carries:
 *     [0..31]  partial_sig32  (our partial Schnorr contribution)
 *     [32..35] nonce_index    (big-endian uint32, identifies which nonce was used)
 *     [36..63] zeros          (reserved)
 *   On receive: bytes [0..31] = peer's partial_sig32,
 *               bytes [32..35] = peer's nonce_index.
 *   After aggregation, channel_verify_and_aggregate_commitment_sig produces
 *   the full 64-byte Schnorr signature.
 *
 * Reference: CLN channeld/channeld.c, LDK lightning/src/ln/channel.rs,
 *            LND lnwallet/channel.go, BOLT #2 spec §2.4.
 */

#ifndef SUPERSCALAR_HTLC_COMMIT_H
#define SUPERSCALAR_HTLC_COMMIT_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "channel.h"
#include "peer_mgr.h"
#include "onion_last_hop.h"   /* ONION_PACKET_SIZE */

/* ---- BOLT #2 wire type numbers ---- */
#define BOLT2_UPDATE_ADD_HTLC             128   /* 0x0080 */
#define BOLT2_UPDATE_FULFILL_HTLC         130   /* 0x0082 */
#define BOLT2_UPDATE_FAIL_HTLC            131   /* 0x0083 */
#define BOLT2_COMMITMENT_SIGNED           132   /* 0x0084 */
#define BOLT2_REVOKE_AND_ACK              133   /* 0x0085 */
#define BOLT2_UPDATE_FAIL_MALFORMED_HTLC  135   /* 0x0087 */
#define BOLT2_UPDATE_FEE                  134   /* 0x0086 */
#define BOLT2_SHUTDOWN                     38   /* 0x0026 */
#define BOLT2_CLOSING_SIGNED               39   /* 0x0027 */

/* Maximum wire message size (update_add_htlc is the largest: 1452 bytes) */
#define BOLT2_MAX_MSG_SIZE  1500

/* update_fee feerate bounds (sat/kw) */
#define BOLT2_UPDATE_FEE_FLOOR    25     /* minimum (0.1 sat/vB = 100 sat/kvB / 4) */
#define BOLT2_UPDATE_FEE_CEILING  100000 /* maximum (prevents griefing) */

/*
 * ---- Low-level message builders ----
 * Each function encodes a BOLT #2 message and sends it via peer_mgr_send.
 * Returns 1 on success, 0 on failure.
 */

/* Send update_add_htlc (type 128). Total: 1452 bytes. */
int htlc_commit_send_add(peer_mgr_t *mgr, int peer_idx,
                          const unsigned char channel_id[32],
                          uint64_t htlc_id,
                          uint64_t amount_msat,
                          const unsigned char payment_hash[32],
                          uint32_t cltv_expiry,
                          const unsigned char onion[ONION_PACKET_SIZE]);

/* Send commitment_signed (type 132). */
int htlc_commit_send_commitment_signed(peer_mgr_t *mgr, int peer_idx,
                                        const unsigned char channel_id[32],
                                        const unsigned char sig64[64],
                                        const unsigned char (*htlc_sigs)[64],
                                        uint16_t n_htlc_sigs);

/* Send revoke_and_ack (type 133). Total: 99 bytes. */
int htlc_commit_send_revoke_and_ack(peer_mgr_t *mgr, int peer_idx,
                                     const unsigned char channel_id[32],
                                     const unsigned char per_commitment_secret[32],
                                     const unsigned char next_per_commitment_point[33]);

/* Send update_fulfill_htlc (type 130). Total: 74 bytes. */
int htlc_commit_send_fulfill(peer_mgr_t *mgr, int peer_idx,
                               const unsigned char channel_id[32],
                               uint64_t htlc_id,
                               const unsigned char preimage[32]);

/* Send update_fail_htlc (type 131). */
int htlc_commit_send_fail(peer_mgr_t *mgr, int peer_idx,
                            const unsigned char channel_id[32],
                            uint64_t htlc_id,
                            const unsigned char *reason, uint16_t reason_len);

/* Send update_fail_malformed_htlc (type 135). Total: 76 bytes. */
int htlc_commit_send_fail_malformed(peer_mgr_t *mgr, int peer_idx,
                                     const unsigned char channel_id[32],
                                     uint64_t htlc_id,
                                     const unsigned char sha256_of_onion[32],
                                     uint16_t failure_code);

/* Send update_fee (type 134). Total: 38 bytes.
   Returns 0 if feerate_per_kw is outside valid bounds. */
int htlc_commit_send_update_fee(peer_mgr_t *mgr, int peer_idx,
                                  const unsigned char channel_id[32],
                                  uint32_t feerate_per_kw);

/* Process an inbound update_fee (already BOLT #8 decrypted).
   Validates bounds; on success updates ch->fee_rate_sat_per_kvb.
   Returns 1 if accepted, 0 if rejected. */
int htlc_commit_recv_update_fee(channel_t *ch,
                                  const unsigned char *msg, size_t msg_len,
                                  uint32_t feerate_floor,
                                  uint32_t feerate_ceiling);

/*
 * ---- High-level commitment round-trips ----
 */

/* Outbound HTLC add + full commitment round-trip.
   htlc_id_out receives the assigned HTLC ID.
   Returns 1 on success, 0 on failure. */
int htlc_commit_add_and_sign(peer_mgr_t *mgr, int peer_idx,
                               channel_t *ch,
                               secp256k1_context *ctx,
                               const unsigned char channel_id[32],
                               uint64_t amount_msat,
                               const unsigned char payment_hash[32],
                               uint32_t cltv_expiry,
                               const unsigned char onion[ONION_PACKET_SIZE],
                               uint64_t *htlc_id_out);

/* Inbound HTLC received + full commitment round-trip. Returns 1 on success. */
int htlc_commit_recv_and_sign(peer_mgr_t *mgr, int peer_idx,
                                channel_t *ch,
                                secp256k1_context *ctx,
                                const unsigned char channel_id[32],
                                uint64_t htlc_id,
                                uint64_t amount_msat,
                                const unsigned char payment_hash[32],
                                uint32_t cltv_expiry,
                                const unsigned char onion[ONION_PACKET_SIZE]);

/* Fulfill an inbound HTLC + commitment round-trip. Returns 1 on success. */
int htlc_commit_fulfill(peer_mgr_t *mgr, int peer_idx,
                         channel_t *ch,
                         secp256k1_context *ctx,
                         const unsigned char channel_id[32],
                         uint64_t htlc_id,
                         const unsigned char preimage[32]);

/* Fail an inbound HTLC + commitment round-trip. Returns 1 on success. */
int htlc_commit_fail(peer_mgr_t *mgr, int peer_idx,
                      channel_t *ch,
                      secp256k1_context *ctx,
                      const unsigned char channel_id[32],
                      uint64_t htlc_id,
                      const unsigned char *reason, uint16_t reason_len);

/*
 * ---- Message dispatcher ----
 *
 * Parse one plaintext BOLT #2 message (already BOLT #8 decrypted).
 * msg includes the 2-byte type prefix.
 *
 * Dispatches to: channel_add_htlc, channel_fulfill_htlc, channel_fail_htlc,
 * channel_verify_and_aggregate_commitment_sig + send revoke_and_ack,
 * channel_receive_revocation_flat + update remote PCP, update_fee.
 *
 * Returns the message type on success (e.g. BOLT2_UPDATE_ADD_HTLC = 128),
 *         or -1 on error or unknown type.
 */
int htlc_commit_dispatch(peer_mgr_t *mgr, int peer_idx,
                          channel_t *ch,
                          secp256k1_context *ctx,
                          const unsigned char channel_id[32],
                          const unsigned char *msg, size_t msg_len);

/* Dynamic commitment upgrade TLV for commitment_signed extension */
size_t commitment_signed_encode_channel_type_tlv(
    unsigned char *buf, size_t buf_cap, uint32_t channel_type_bits);
int commitment_signed_decode_channel_type_tlv(
    const unsigned char *tlv_data, size_t tlv_len,
    uint32_t *channel_type_bits_out);

#endif /* SUPERSCALAR_HTLC_COMMIT_H */
