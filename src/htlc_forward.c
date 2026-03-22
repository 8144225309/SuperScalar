/*
 * htlc_forward.c — HTLC forwarding engine
 *
 * Decrypts inbound onion layers and routes HTLCs to the correct next hop
 * or to the MPP aggregation table for final-hop delivery.
 *
 * Reference: LDK ChannelManager, CLN channeld/channeld.c
 */

#include "superscalar/htlc_forward.h"
#include "superscalar/onion.h"
#include "superscalar/onion_last_hop.h"
#include "superscalar/noise.h"    /* hmac_sha256 */
#include <string.h>
#include <openssl/evp.h>

void htlc_forward_init(htlc_forward_table_t *fwd) {
    if (!fwd) return;
    memset(fwd, 0, sizeof(*fwd));
}

int htlc_forward_process(htlc_forward_table_t *fwd,
                          mpp_table_t *mpp,
                          const unsigned char our_privkey[32],
                          secp256k1_context *ctx,
                          const unsigned char onion[ONION_PACKET_SIZE],
                          uint64_t in_htlc_id, uint64_t in_chan_id,
                          uint64_t amount_msat, uint32_t cltv,
                          htlc_forward_entry_t *out) {
    if (!fwd || !our_privkey || !ctx || !onion || !out) return FORWARD_FAIL;
    if (fwd->count >= FORWARD_TABLE_MAX) return FORWARD_FAIL;

    /* Peel one onion layer */
    unsigned char next_onion[ONION_PACKET_SIZE];
    onion_hop_payload_t payload;
    int is_final = 0;

    if (!onion_peel(our_privkey, ctx, onion, next_onion, &payload, &is_final))
        return FORWARD_FAIL;

    /* Derive shared secret for this hop (for error re-encryption) */
    unsigned char ss[32];
    const unsigned char *eph_pub33 = onion + 1;
    if (!onion_ecdh_shared_secret(ctx, our_privkey, eph_pub33, ss))
        return FORWARD_FAIL;

    if (is_final) {
        /* Final hop: feed into MPP table */
        if (mpp && payload.has_payment_data) {
            mpp_add_part(mpp, payload.payment_secret,
                         in_htlc_id, amount_msat,
                         payload.total_msat, cltv);
        }

        /* Record in forward table as settled immediately */
        htlc_forward_entry_t *e = &fwd->entries[fwd->count++];
        memset(e, 0, sizeof(*e));
        e->in_htlc_id    = in_htlc_id;
        e->in_chan_id     = in_chan_id;
        e->out_htlc_id   = 0;
        e->out_chan_id    = 0;
        e->in_amount_msat = amount_msat;
        e->out_amount_msat = amount_msat;
        e->in_cltv       = cltv;
        e->state         = FORWARD_STATE_SETTLED;
        memcpy(e->onion_shared_secret, ss, 32);
        if (payload.has_payment_data) {
            memcpy(e->payment_secret,  payload.payment_secret, 32);
            e->has_payment_secret = 1;
        }
        if (payload.has_amt)
            memcpy(out, e, sizeof(*e));
        return FORWARD_FINAL;
    }

    /* Relay hop: find outgoing SCID from the payload (TLV type 6) */
    /* The short_channel_id is not in onion_hop_payload_t (final-hop only),
     * we need to parse it from the raw decrypted payload.
     * Since onion_peel calls onion_parse_tlv_payload which only parses types
     * 2, 4, 8, we need the scid from type 6. We re-read the plain hops data. */

    /* Trampoline detection: if type 0x0c is present, this node is a trampoline.
       Extract the real destination and set up for re-routing. */
    if (payload.has_trampoline) {
        /* Parse trampoline payload for destination info */
        onion_hop_payload_t tp;
        if (onion_parse_tlv_payload(payload.trampoline_payload,
                                     payload.trampoline_payload_len, &tp)) {
            /* Override relay parameters with trampoline destination */
            if (tp.has_amt) payload.amt_to_forward = tp.amt_to_forward;
            if (tp.has_cltv) payload.outgoing_cltv_value = tp.outgoing_cltv_value;
        }
    }

    /* For relay, we have the outgoing amount from payload.amt_to_forward */
    if (!payload.has_amt || !payload.has_cltv) return FORWARD_FAIL;

    htlc_forward_entry_t *e = &fwd->entries[fwd->count++];
    memset(e, 0, sizeof(*e));
    e->in_htlc_id     = in_htlc_id;
    e->in_chan_id      = in_chan_id;
    e->out_htlc_id    = 0;  /* set when add_htlc succeeds */
    e->out_chan_id     = 0;  /* derived from scid */
    e->in_amount_msat  = amount_msat;
    e->out_amount_msat = payload.amt_to_forward;
    e->in_cltv         = cltv;
    e->out_cltv        = payload.outgoing_cltv_value;
    e->state           = FORWARD_STATE_PENDING_OUT;
    memcpy(e->onion_shared_secret, ss, 32);
    /* Phase N: store peeled onion for relay pump */
    memcpy(e->next_onion, next_onion, ONION_PACKET_SIZE);
    /* Phase N: set next_hop_scid from TLV type 6 if present */
    if (payload.has_scid)
        e->next_hop_scid = payload.short_channel_id;

    if (out) memcpy(out, e, sizeof(*e));
    return FORWARD_RELAY;
}

void htlc_forward_settle(htlc_forward_table_t *fwd,
                          uint64_t out_htlc_id, uint64_t out_chan_id,
                          const unsigned char preimage[32]) {
    if (!fwd || !preimage) return;
    for (int i = 0; i < fwd->count; i++) {
        htlc_forward_entry_t *e = &fwd->entries[i];
        if (e->out_htlc_id == out_htlc_id &&
            e->out_chan_id  == out_chan_id &&
            e->state == FORWARD_STATE_INFLIGHT) {
            e->state = FORWARD_STATE_SETTLED;
            /* Preimage is propagated back; caller sends update_fulfill_htlc
               on the inbound channel using e->in_htlc_id, e->in_chan_id */
            (void)preimage; /* caller handles actual channel update */
            return;
        }
    }
}

void htlc_forward_fail(htlc_forward_table_t *fwd,
                        uint64_t out_htlc_id, uint64_t out_chan_id,
                        const unsigned char *onion_error, size_t err_len,
                        unsigned char out_error[256]) {
    if (!fwd) return;
    for (int i = 0; i < fwd->count; i++) {
        htlc_forward_entry_t *e = &fwd->entries[i];
        if (e->out_htlc_id == out_htlc_id &&
            e->out_chan_id  == out_chan_id &&
            e->state == FORWARD_STATE_INFLIGHT) {
            e->state = FORWARD_STATE_FAILED;

            /* Re-encrypt error onion with ammag for this hop's shared secret */
            if (out_error) {
                memset(out_error, 0, 256);
                if (onion_error && err_len > 0) {
                    size_t copy_len = err_len < 256 ? err_len : 256;
                    memcpy(out_error, onion_error, copy_len);
                }

                /* XOR with ChaCha20(ammag, ss) */
                unsigned char ammag[32];
                hmac_sha256(ammag,
                            (const unsigned char *)"ammag", 5,
                            e->onion_shared_secret, 32);
                /* Apply ammag stream */
                EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
                if (evp) {
                    static const unsigned char zero_iv[16] = {0};
                    unsigned char stream[256];
                    unsigned char zeros[256] = {0};
                    int outlen = 0;
                    if (EVP_EncryptInit_ex(evp, EVP_chacha20(), NULL, ammag, zero_iv) == 1 &&
                        EVP_EncryptUpdate(evp, stream, &outlen, zeros, 256) == 1) {
                        for (int k = 0; k < 256; k++)
                            out_error[k] ^= stream[k];
                    }
                    EVP_CIPHER_CTX_free(evp);
                }
            }
            return;
        }
    }
}
