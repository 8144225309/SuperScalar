/*
 * htlc_commit.c — BOLT #2 binary HTLC commitment wire protocol for external peers
 *
 * Bridges channel.c (state machine) and peer_mgr.c (BOLT #8 transport).
 * Encodes/decodes BOLT #2 messages and drives the commitment update flow.
 *
 * Commitment update sequence (BOLT #2 §2.4):
 *   Sender:   update_add_htlc → commitment_signed
 *   Receiver: revoke_and_ack → commitment_signed
 *   Sender:   revoke_and_ack
 *
 * MuSig2 partial sig packing in commitment_signed sig64:
 *   [0..31]  partial_sig32  — our partial Schnorr contribution
 *   [32..35] nonce_index    — big-endian uint32
 *   [36..63] zeros          — reserved
 */

#include "superscalar/htlc_commit.h"
#include "superscalar/channel.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Serialisation helpers (big-endian)                                  */
/* ------------------------------------------------------------------ */

static void put_u16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}
static void put_u32(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >>  8); b[3] = (unsigned char)(v);
}
static void put_u64(unsigned char *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) b[7 - i] = (unsigned char)(v >> (i * 8));
}
static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t get_u32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}
static uint64_t get_u64(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* ------------------------------------------------------------------ */
/* MuSig2 partial-sig packing                                          */
/* ------------------------------------------------------------------ */

/*
 * Pack a 32-byte partial sig + nonce_index into the 64-byte sig field
 * used in commitment_signed:
 *   [0..31]  partial_sig32
 *   [32..35] nonce_index (big-endian uint32)
 *   [36..63] zeros
 */
static void pack_commit_sig(const unsigned char partial32[32], uint32_t nonce_idx,
                              unsigned char sig64[64]) {
    memcpy(sig64, partial32, 32);
    put_u32(sig64 + 32, nonce_idx);
    memset(sig64 + 36, 0, 28);
}

/*
 * Unpack a received commitment_signed sig64 into partial sig + nonce_index.
 */
static void unpack_commit_sig(const unsigned char sig64[64],
                               unsigned char partial32[32],
                               uint32_t *nonce_idx_out) {
    memcpy(partial32, sig64, 32);
    *nonce_idx_out = get_u32(sig64 + 32);
}

/* ------------------------------------------------------------------ */
/* Internal round-trip helpers                                         */
/* ------------------------------------------------------------------ */

/*
 * Create our partial sig for the remote commitment tx and send it
 * as commitment_signed to the peer.
 */
static int send_commitment_signed_for_remote(peer_mgr_t *mgr, int peer_idx,
                                              channel_t *ch,
                                              secp256k1_context *ctx,
                                              const unsigned char channel_id[32]) {
    (void)ctx;
    unsigned char partial32[32];
    uint32_t nonce_idx;
    if (!channel_create_commitment_partial_sig(ch, partial32, &nonce_idx)) return 0;

    unsigned char sig64[64];
    pack_commit_sig(partial32, nonce_idx, sig64);

    return htlc_commit_send_commitment_signed(mgr, peer_idx, channel_id,
                                              sig64, NULL, 0);
}

/*
 * Reveal our per-commitment secret for the old commitment and advertise
 * our per-commitment point for the next one, then send revoke_and_ack.
 * Requires ch->commitment_number >= 1.
 */
static int send_revoke_and_ack_internal(peer_mgr_t *mgr, int peer_idx,
                                         channel_t *ch,
                                         secp256k1_context *ctx,
                                         const unsigned char channel_id[32]) {
    if (ch->commitment_number == 0) return 0;

    /* Reveal PCS for the commitment we are revoking */
    unsigned char pcs[32];
    if (!channel_get_per_commitment_secret(ch, ch->commitment_number - 1, pcs))
        return 0;

    /* Advertise PCP for the next commitment we will create */
    secp256k1_pubkey next_pcp;
    if (!channel_get_per_commitment_point(ch, ch->commitment_number + 1, &next_pcp))
        return 0;

    unsigned char next_pcp_bytes[33];
    size_t pcp_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, next_pcp_bytes, &pcp_len, &next_pcp,
                                   SECP256K1_EC_COMPRESSED);

    return htlc_commit_send_revoke_and_ack(mgr, peer_idx, channel_id,
                                            pcs, next_pcp_bytes);
}

/*
 * Receive a revoke_and_ack from the peer, store their revocation secret,
 * and update the remote per-commitment point.
 */
static int recv_revoke_and_ack(peer_mgr_t *mgr, int peer_idx,
                                 channel_t *ch, secp256k1_context *ctx,
                                 const unsigned char channel_id[32]) {
    unsigned char buf[BOLT2_MAX_MSG_SIZE];
    size_t msg_len = 0;
    if (!peer_mgr_recv(mgr, peer_idx, buf, &msg_len, sizeof(buf))) return 0;

    /* revoke_and_ack: type(2) + channel_id(32) + pcs(32) + next_pcp(33) = 99 bytes */
    if (msg_len < 99) return 0;
    if (get_u16(buf) != BOLT2_REVOKE_AND_ACK) return 0;

    const unsigned char *peer_pcs      = buf + 34; /* after type(2) + channel_id(32) */
    const unsigned char *next_pcp_wire = buf + 66; /* after + pcs(32) */

    if (ch->commitment_number > 0)
        channel_receive_revocation_flat(ch, ch->commitment_number - 1, peer_pcs);

    secp256k1_pubkey next_pcp;
    if (!secp256k1_ec_pubkey_parse(ctx, &next_pcp, next_pcp_wire, 33)) return 0;
    channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);

    (void)channel_id;
    return 1;
}

/*
 * Receive a commitment_signed from the peer, extract their partial sig,
 * and aggregate it with ours to produce the full Schnorr sig.
 */
static int recv_commitment_signed(peer_mgr_t *mgr, int peer_idx,
                                    channel_t *ch, secp256k1_context *ctx,
                                    const unsigned char channel_id[32]) {
    unsigned char buf[BOLT2_MAX_MSG_SIZE];
    size_t msg_len = 0;
    if (!peer_mgr_recv(mgr, peer_idx, buf, &msg_len, sizeof(buf))) return 0;

    /* commitment_signed: type(2) + channel_id(32) + sig(64) + num_htlcs(2) = 100 min */
    if (msg_len < 100) return 0;
    if (get_u16(buf) != BOLT2_COMMITMENT_SIGNED) return 0;

    const unsigned char *sig64 = buf + 34; /* after type(2) + channel_id(32) */
    unsigned char peer_partial[32];
    uint32_t peer_nonce_idx;
    unpack_commit_sig(sig64, peer_partial, &peer_nonce_idx);

    unsigned char full_sig[64];
    if (!channel_verify_and_aggregate_commitment_sig(ch, peer_partial,
                                                      peer_nonce_idx, full_sig))
        return 0;

    (void)ctx;
    (void)channel_id;
    return 1;
}

/* ================================================================== */
/* Low-level message builders / senders                               */
/* ================================================================== */

int htlc_commit_send_add(peer_mgr_t *mgr, int peer_idx,
                          const unsigned char channel_id[32],
                          uint64_t htlc_id,
                          uint64_t amount_msat,
                          const unsigned char payment_hash[32],
                          uint32_t cltv_expiry,
                          const unsigned char onion[ONION_PACKET_SIZE]) {
    /*
     * update_add_htlc wire layout (1452 bytes):
     *   type(2) + channel_id(32) + htlc_id(8) + amount_msat(8) +
     *   payment_hash(32) + cltv_expiry(4) + onion_routing_packet(1366)
     */
    unsigned char buf[1452];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_UPDATE_ADD_HTLC);   pos += 2;
    memcpy(buf + pos, channel_id, 32);            pos += 32;
    put_u64(buf + pos, htlc_id);                  pos += 8;
    put_u64(buf + pos, amount_msat);              pos += 8;
    memcpy(buf + pos, payment_hash, 32);          pos += 32;
    put_u32(buf + pos, cltv_expiry);              pos += 4;
    memcpy(buf + pos, onion, ONION_PACKET_SIZE);  pos += ONION_PACKET_SIZE;
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_send_commitment_signed(peer_mgr_t *mgr, int peer_idx,
                                        const unsigned char channel_id[32],
                                        const unsigned char sig64[64],
                                        const unsigned char (*htlc_sigs)[64],
                                        uint16_t n_htlc_sigs) {
    /*
     * commitment_signed wire layout:
     *   type(2) + channel_id(32) + sig(64) + num_htlcs(2) + htlc_sigs(n*64)
     */
    size_t total = 100 + (size_t)n_htlc_sigs * 64;
    if (total > BOLT2_MAX_MSG_SIZE) return 0;

    unsigned char buf[BOLT2_MAX_MSG_SIZE];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_COMMITMENT_SIGNED); pos += 2;
    memcpy(buf + pos, channel_id, 32);           pos += 32;
    memcpy(buf + pos, sig64, 64);                pos += 64;
    put_u16(buf + pos, n_htlc_sigs);             pos += 2;
    for (uint16_t i = 0; i < n_htlc_sigs; i++) {
        memcpy(buf + pos, htlc_sigs[i], 64);     pos += 64;
    }
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_send_revoke_and_ack(peer_mgr_t *mgr, int peer_idx,
                                     const unsigned char channel_id[32],
                                     const unsigned char per_commitment_secret[32],
                                     const unsigned char next_per_commitment_point[33]) {
    /*
     * revoke_and_ack wire layout (99 bytes):
     *   type(2) + channel_id(32) + per_commitment_secret(32) +
     *   next_per_commitment_point(33)
     */
    unsigned char buf[99];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_REVOKE_AND_ACK);             pos += 2;
    memcpy(buf + pos, channel_id, 32);                     pos += 32;
    memcpy(buf + pos, per_commitment_secret, 32);          pos += 32;
    memcpy(buf + pos, next_per_commitment_point, 33);      pos += 33;
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_send_fulfill(peer_mgr_t *mgr, int peer_idx,
                               const unsigned char channel_id[32],
                               uint64_t htlc_id,
                               const unsigned char preimage[32]) {
    /*
     * update_fulfill_htlc wire layout (74 bytes):
     *   type(2) + channel_id(32) + htlc_id(8) + payment_preimage(32)
     */
    unsigned char buf[74];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_UPDATE_FULFILL_HTLC); pos += 2;
    memcpy(buf + pos, channel_id, 32);              pos += 32;
    put_u64(buf + pos, htlc_id);                    pos += 8;
    memcpy(buf + pos, preimage, 32);                pos += 32;
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_send_fail(peer_mgr_t *mgr, int peer_idx,
                            const unsigned char channel_id[32],
                            uint64_t htlc_id,
                            const unsigned char *reason, uint16_t reason_len) {
    /*
     * update_fail_htlc wire layout:
     *   type(2) + channel_id(32) + htlc_id(8) + len(2) + reason(len)
     */
    size_t total = 44 + (size_t)reason_len;
    if (total > BOLT2_MAX_MSG_SIZE) return 0;

    unsigned char buf[BOLT2_MAX_MSG_SIZE];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_UPDATE_FAIL_HTLC); pos += 2;
    memcpy(buf + pos, channel_id, 32);           pos += 32;
    put_u64(buf + pos, htlc_id);                 pos += 8;
    put_u16(buf + pos, reason_len);              pos += 2;
    if (reason && reason_len > 0) {
        memcpy(buf + pos, reason, reason_len);   pos += reason_len;
    }
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_send_fail_malformed(peer_mgr_t *mgr, int peer_idx,
                                     const unsigned char channel_id[32],
                                     uint64_t htlc_id,
                                     const unsigned char sha256_of_onion[32],
                                     uint16_t failure_code) {
    /*
     * update_fail_malformed_htlc wire layout (76 bytes):
     *   type(2) + channel_id(32) + htlc_id(8) + sha256_of_onion(32) +
     *   failure_code(2)
     */
    unsigned char buf[76];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_UPDATE_FAIL_MALFORMED_HTLC); pos += 2;
    memcpy(buf + pos, channel_id, 32);                     pos += 32;
    put_u64(buf + pos, htlc_id);                           pos += 8;
    memcpy(buf + pos, sha256_of_onion, 32);                pos += 32;
    put_u16(buf + pos, failure_code);                      pos += 2;
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_send_update_fee(peer_mgr_t *mgr, int peer_idx,
                                  const unsigned char channel_id[32],
                                  uint32_t feerate_per_kw) {
    if (feerate_per_kw < BOLT2_UPDATE_FEE_FLOOR ||
        feerate_per_kw > BOLT2_UPDATE_FEE_CEILING) return 0;

    /*
     * update_fee wire layout (38 bytes):
     *   type(2) + channel_id(32) + feerate_per_kw(4)
     */
    unsigned char buf[38];
    size_t pos = 0;
    put_u16(buf + pos, BOLT2_UPDATE_FEE); pos += 2;
    memcpy(buf + pos, channel_id, 32);    pos += 32;
    put_u32(buf + pos, feerate_per_kw);   pos += 4;
    return peer_mgr_send(mgr, peer_idx, buf, pos);
}

int htlc_commit_recv_update_fee(channel_t *ch,
                                  const unsigned char *msg, size_t msg_len,
                                  uint32_t feerate_floor,
                                  uint32_t feerate_ceiling) {
    /* type(2) + channel_id(32) + feerate_per_kw(4) = 38 bytes minimum */
    if (!ch || !msg || msg_len < 38) return 0;
    if (get_u16(msg) != BOLT2_UPDATE_FEE) return 0;

    uint32_t feerate = get_u32(msg + 34); /* after type(2) + channel_id(32) */
    if (feerate < feerate_floor || feerate > feerate_ceiling) return 0;

    ch->fee_rate_sat_per_kvb = (uint64_t)feerate;
    return 1;
}

/* ================================================================== */
/* High-level commitment round-trips                                   */
/* ================================================================== */

int htlc_commit_add_and_sign(peer_mgr_t *mgr, int peer_idx,
                               channel_t *ch,
                               secp256k1_context *ctx,
                               const unsigned char channel_id[32],
                               uint64_t amount_msat,
                               const unsigned char payment_hash[32],
                               uint32_t cltv_expiry,
                               const unsigned char onion[ONION_PACKET_SIZE],
                               uint64_t *htlc_id_out) {
    uint64_t htlc_id = 0;

    /* 1. Register outbound HTLC (amount_msat → sats, ch->commitment_number++) */
    if (!channel_add_htlc(ch, HTLC_OFFERED, amount_msat / 1000,
                           payment_hash, cltv_expiry, &htlc_id)) return 0;
    if (htlc_id_out) *htlc_id_out = htlc_id;

    /* 2. Send update_add_htlc */
    if (!htlc_commit_send_add(mgr, peer_idx, channel_id, htlc_id,
                               amount_msat, payment_hash, cltv_expiry, onion))
        return 0;

    /* 3+4. Partial-sign their new commitment tx, send commitment_signed */
    if (!send_commitment_signed_for_remote(mgr, peer_idx, ch, ctx, channel_id))
        return 0;

    /* 5. Receive their revoke_and_ack (revokes their old commitment) */
    if (!recv_revoke_and_ack(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    /* 6+7. Receive their commitment_signed and aggregate the full sig for ours */
    if (!recv_commitment_signed(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    /* 8. Send our revoke_and_ack (revoke old, advertise next PCP) */
    if (!send_revoke_and_ack_internal(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    return 1;
}

int htlc_commit_recv_and_sign(peer_mgr_t *mgr, int peer_idx,
                                channel_t *ch,
                                secp256k1_context *ctx,
                                const unsigned char channel_id[32],
                                uint64_t htlc_id,
                                uint64_t amount_msat,
                                const unsigned char payment_hash[32],
                                uint32_t cltv_expiry,
                                const unsigned char onion[ONION_PACKET_SIZE]) {
    (void)onion; /* forwarding is handled by htlc_forward.c */

    /* 1. Register inbound HTLC (ch->commitment_number++) */
    uint64_t internal_id;
    if (!channel_add_htlc(ch, HTLC_RECEIVED, amount_msat / 1000,
                           payment_hash, cltv_expiry, &internal_id)) return 0;

    /* Map internal id → peer's htlc_id so later fail/fulfill can look it up */
    if (ch->n_htlcs > 0)
        ch->htlcs[ch->n_htlcs - 1].id = htlc_id;

    /* 2. Partial-sign their new commitment tx, send commitment_signed */
    if (!send_commitment_signed_for_remote(mgr, peer_idx, ch, ctx, channel_id))
        return 0;

    /* 3. Receive their revoke_and_ack */
    if (!recv_revoke_and_ack(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    /* 4. Receive their commitment_signed */
    if (!recv_commitment_signed(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    /* 5. Send our revoke_and_ack */
    if (!send_revoke_and_ack_internal(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    return 1;
}

int htlc_commit_fulfill(peer_mgr_t *mgr, int peer_idx,
                         channel_t *ch,
                         secp256k1_context *ctx,
                         const unsigned char channel_id[32],
                         uint64_t htlc_id,
                         const unsigned char preimage[32]) {
    /* 1. Update local state (credits recipient, ch->commitment_number++) */
    if (!channel_fulfill_htlc(ch, htlc_id, preimage)) return 0;

    /* 2. Send update_fulfill_htlc (htlc_id is peer's original HTLC ID) */
    if (!htlc_commit_send_fulfill(mgr, peer_idx, channel_id, htlc_id, preimage))
        return 0;

    /* 3-6. Commitment round-trip */
    if (!send_commitment_signed_for_remote(mgr, peer_idx, ch, ctx, channel_id))
        return 0;
    if (!recv_revoke_and_ack(mgr, peer_idx, ch, ctx, channel_id)) return 0;
    if (!recv_commitment_signed(mgr, peer_idx, ch, ctx, channel_id)) return 0;
    if (!send_revoke_and_ack_internal(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    return 1;
}

int htlc_commit_fail(peer_mgr_t *mgr, int peer_idx,
                      channel_t *ch,
                      secp256k1_context *ctx,
                      const unsigned char channel_id[32],
                      uint64_t htlc_id,
                      const unsigned char *reason, uint16_t reason_len) {
    /* 1. Update local state (ch->commitment_number++) */
    if (!channel_fail_htlc(ch, htlc_id)) return 0;

    /* 2. Send update_fail_htlc */
    if (!htlc_commit_send_fail(mgr, peer_idx, channel_id, htlc_id,
                                reason, reason_len)) return 0;

    /* 3-6. Commitment round-trip */
    if (!send_commitment_signed_for_remote(mgr, peer_idx, ch, ctx, channel_id))
        return 0;
    if (!recv_revoke_and_ack(mgr, peer_idx, ch, ctx, channel_id)) return 0;
    if (!recv_commitment_signed(mgr, peer_idx, ch, ctx, channel_id)) return 0;
    if (!send_revoke_and_ack_internal(mgr, peer_idx, ch, ctx, channel_id)) return 0;

    return 1;
}

/* ================================================================== */
/* Message dispatcher                                                  */
/* ================================================================== */

int htlc_commit_dispatch(peer_mgr_t *mgr, int peer_idx,
                          channel_t *ch,
                          secp256k1_context *ctx,
                          const unsigned char channel_id[32],
                          const unsigned char *msg, size_t msg_len) {
    if (!msg || msg_len < 2) return -1;

    int type = (int)get_u16(msg);
    const unsigned char *payload     = msg + 2;
    size_t               payload_len = msg_len - 2;

    switch (type) {

    case BOLT2_UPDATE_ADD_HTLC: {
        /*
         * payload: channel_id(32) + htlc_id(8) + amount_msat(8) +
         *          payment_hash(32) + cltv_expiry(4) + onion(1366) = 1450
         */
        if (payload_len < 1450) return -1;
        uint64_t remote_htlc_id = get_u64(payload + 32);
        uint64_t amount_msat    = get_u64(payload + 40);
        const unsigned char *hash = payload + 48;
        uint32_t cltv           = get_u32(payload + 80);

        uint64_t local_id;
        if (!channel_add_htlc(ch, HTLC_RECEIVED, amount_msat / 1000,
                               hash, cltv, &local_id)) return -1;

        /*
         * Override our auto-assigned id with the peer's htlc_id so that
         * subsequent update_fail/fulfill messages (which carry the peer's ID)
         * can be looked up correctly via channel_fail_htlc / channel_fulfill_htlc.
         */
        if (ch->n_htlcs > 0)
            ch->htlcs[ch->n_htlcs - 1].id = remote_htlc_id;

        return type;
    }

    case BOLT2_UPDATE_FULFILL_HTLC: {
        /*
         * payload: channel_id(32) + htlc_id(8) + payment_preimage(32) = 72
         * htlc_id refers to an HTLC we OFFERED (our internal id matches).
         */
        if (payload_len < 72) return -1;
        uint64_t htlc_id              = get_u64(payload + 32);
        const unsigned char *preimage = payload + 40;
        if (!channel_fulfill_htlc(ch, htlc_id, preimage)) return -1;
        return type;
    }

    case BOLT2_UPDATE_FAIL_HTLC: {
        /*
         * payload: channel_id(32) + htlc_id(8) + len(2) + reason(len)
         * htlc_id refers to an HTLC we OFFERED (our internal id matches).
         */
        if (payload_len < 42) return -1;
        uint64_t htlc_id = get_u64(payload + 32);
        if (!channel_fail_htlc(ch, htlc_id)) return -1;
        return type;
    }

    case BOLT2_UPDATE_FAIL_MALFORMED_HTLC: {
        /*
         * payload: channel_id(32) + htlc_id(8) + sha256(32) + failure_code(2) = 74
         * htlc_id refers to an HTLC we OFFERED.
         */
        if (payload_len < 74) return -1;
        uint64_t htlc_id = get_u64(payload + 32);
        if (!channel_fail_htlc(ch, htlc_id)) return -1;
        return type;
    }

    case BOLT2_COMMITMENT_SIGNED: {
        /*
         * payload: channel_id(32) + sig(64) + num_htlcs(2) >= 98
         * Aggregate peer's partial sig → full Schnorr sig for our commitment.
         * Then complete this side of the round-trip by sending revoke_and_ack.
         */
        if (payload_len < 98) return -1;
        const unsigned char *sig64 = payload + 32;
        unsigned char peer_partial[32];
        uint32_t peer_nonce_idx;
        unpack_commit_sig(sig64, peer_partial, &peer_nonce_idx);

        unsigned char full_sig[64];
        if (!channel_verify_and_aggregate_commitment_sig(ch, peer_partial,
                                                          peer_nonce_idx,
                                                          full_sig)) return -1;

        /* Send revoke_and_ack to complete our side of the round-trip */
        if (!send_revoke_and_ack_internal(mgr, peer_idx, ch, ctx, channel_id))
            return -1;
        return type;
    }

    case BOLT2_REVOKE_AND_ACK: {
        /*
         * payload: channel_id(32) + per_commitment_secret(32) +
         *          next_per_commitment_point(33) = 97
         */
        if (payload_len < 97) return -1;
        const unsigned char *peer_pcs      = payload + 32;
        const unsigned char *next_pcp_wire = payload + 64;

        if (ch->commitment_number > 0)
            channel_receive_revocation_flat(ch, ch->commitment_number - 1,
                                             peer_pcs);

        secp256k1_pubkey next_pcp;
        if (!secp256k1_ec_pubkey_parse(ctx, &next_pcp, next_pcp_wire, 33))
            return -1;
        channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);
        return type;
    }

    case BOLT2_UPDATE_FEE: {
        /*
         * payload: channel_id(32) + feerate_per_kw(4) = 36
         */
        if (payload_len < 36) return -1;
        uint32_t feerate = get_u32(payload + 32);
        if (feerate < BOLT2_UPDATE_FEE_FLOOR || feerate > BOLT2_UPDATE_FEE_CEILING)
            return -1;
        ch->fee_rate_sat_per_kvb = (uint64_t)feerate;
        return type;
    }

    default:
        return -1;
    }
}
