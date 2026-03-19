/*
 * gossip_ingest.c — Verify and store incoming BOLT #7 gossip messages
 *
 * Reference: BOLT #7 §gossip-messages
 */

#include "superscalar/gossip_ingest.h"
#include "superscalar/gossip.h"
#include "superscalar/sha256.h"
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------
 * Wire helpers
 * --------------------------------------------------------------------- */

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | (uint32_t)p[3];
}

static uint64_t rd64(const unsigned char *p)
{
    return ((uint64_t)rd32(p) << 32) | rd32(p + 4);
}

/* -----------------------------------------------------------------------
 * Signature verification helper (Schnorr, same as gossip.c pattern)
 *
 * BOLT #7 signed data = SHA256(SHA256(type(2) || data_after_sig))
 *   where data_after_sig = msg[66..] (msg[2..65] is the 64-byte sig)
 * --------------------------------------------------------------------- */
static int verify_schnorr(secp256k1_context *ctx,
                           const unsigned char sig64[64],
                           const unsigned char pubkey33[33],
                           const unsigned char *msg, size_t msg_len)
{
    if (!ctx || msg_len < 66) return 0;

    /* signable data: type(2) || msg[66..] */
    size_t data_len = 2 + (msg_len - 66);
    unsigned char *data = (unsigned char *)malloc(data_len);
    if (!data) return 0;
    memcpy(data, msg, 2);
    memcpy(data + 2, msg + 66, msg_len - 66);

    unsigned char hash[32];
    sha256_double(data, data_len, hash);
    free(data);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey33, 33)) return 0;

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xpk, NULL, &pk)) return 0;

    return secp256k1_schnorrsig_verify(ctx, sig64, hash, 32, &xpk);
}

/* -----------------------------------------------------------------------
 * Rate limiting
 * --------------------------------------------------------------------- */
static int rate_check(gossip_ingest_t *gi, const unsigned char *key, int klen,
                       uint32_t now)
{
    /* Look for existing entry */
    for (int i = 0; i < gi->rate_count; i++) {
        if (gi->rate[i].key_len == (uint8_t)klen &&
            memcmp(gi->rate[i].key, key, (size_t)klen) == 0)
        {
            if (now - gi->rate[i].last_seen < GOSSIP_INGEST_MIN_INTERVAL)
                return 0; /* rate limited */
            gi->rate[i].last_seen = now;
            return 1;
        }
    }
    /* New entry — add (evict oldest if table full) */
    int slot = gi->rate_count;
    if (gi->rate_count < GOSSIP_INGEST_RATE_MAX) {
        gi->rate_count++;
    } else {
        /* Evict entry with smallest last_seen */
        uint32_t oldest = gi->rate[0].last_seen;
        slot = 0;
        for (int i = 1; i < gi->rate_count; i++) {
            if (gi->rate[i].last_seen < oldest) {
                oldest = gi->rate[i].last_seen;
                slot = i;
            }
        }
    }
    memcpy(gi->rate[slot].key, key, (size_t)klen);
    gi->rate[slot].key_len   = (uint8_t)klen;
    gi->rate[slot].last_seen = now;
    return 1; /* admitted */
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

void gossip_ingest_init(gossip_ingest_t *gi,
                        secp256k1_context *ctx,
                        gossip_store_t    *gs)
{
    if (!gi) return;
    memset(gi, 0, sizeof(*gi));
    gi->ctx = ctx;
    gi->gs  = gs;
}

/* -----------------------------------------------------------------------
 * channel_announcement (type 256)
 *
 * Wire layout (after type(2)):
 *   node_sig_1(64) node_sig_2(64) bitcoin_sig_1(64) bitcoin_sig_2(64)
 *   flen(2) features(flen)
 *   chain_hash(32) short_channel_id(8) node_id_1(33) node_id_2(33)
 *   bitcoin_key_1(33) bitcoin_key_2(33)
 *
 * => node_sig_1 at msg[2], node_sig_2 at msg[66]
 *    bitcoin_sig_1 at msg[130], bitcoin_sig_2 at msg[194]
 *    flen at msg[258]
 *    features at msg[260..260+flen-1]
 *    chain_hash at msg[260+flen]
 *    scid at msg[260+flen+32]
 *    node_id_1 at msg[260+flen+40]
 *    node_id_2 at msg[260+flen+73]
 *    bitcoin_key_1 at msg[260+flen+106]
 *    bitcoin_key_2 at msg[260+flen+139]
 *
 * Min length without features: 2+4*64+2+0+32+8+4*33 = 2+256+2+32+8+132 = 432
 * --------------------------------------------------------------------- */
int gossip_ingest_channel_announcement(gossip_ingest_t     *gi,
                                        const unsigned char *msg,
                                        size_t               msg_len,
                                        uint32_t             now_unix)
{
    if (!gi) return GOSSIP_INGEST_MALFORMED;

    /* minimum: type(2) + 4*sig(64) + flen(2) + chain(32) + scid(8) + 4*key(33) */
    if (msg_len < 432) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    /* flen at offset 258 */
    uint16_t flen = rd16(msg + 258);
    size_t min_needed = 432 + flen;
    if (msg_len < min_needed) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    size_t base = (size_t)(260 + flen);   /* offset of chain_hash */
    /* chain_hash + scid + node_id_1 + node_id_2 + bitcoin_key_1 + bitcoin_key_2 */
    if (msg_len < base + 32 + 8 + 33 + 33 + 33 + 33) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    uint64_t scid = rd64(msg + base + 32);
    const unsigned char *node_id_1    = msg + base + 40;
    const unsigned char *node_id_2    = msg + base + 73;

    /* Rate limit on scid */
    unsigned char rate_key[8];
    memcpy(rate_key, msg + base + 32, 8);
    if (!rate_check(gi, rate_key, 8, now_unix)) {
        gi->n_rejected_rate++;
        return GOSSIP_INGEST_RATE_LIMITED;
    }

    /* Signature verification */
    if (gi->ctx) {
        if (!gossip_validate_channel_announcement(gi->ctx, msg, msg_len)) {
            gi->n_rejected_sig++;
            return GOSSIP_INGEST_BAD_SIG;
        }
    }

    /* Store */
    if (gi->gs) {
        gossip_store_upsert_channel(gi->gs, scid, node_id_1, node_id_2,
                                    0, now_unix);
    }

    gi->n_channel_ann++;
    return gi->ctx ? GOSSIP_INGEST_OK : GOSSIP_INGEST_NO_VERIFY;
}

/* -----------------------------------------------------------------------
 * node_announcement (type 257)
 *
 * Wire layout (after type(2)):
 *   sig(64) flen(2) features(flen) timestamp(4) node_id(33)
 *   rgb(3) alias(32) addrlen(2) [addrs...]
 *
 * node_id at msg[2+64+2+flen+4] = msg[72+flen]
 * Min length (no features, no addrs): 2+64+2+0+4+33+3+32+2 = 142
 * --------------------------------------------------------------------- */
int gossip_ingest_node_announcement(gossip_ingest_t     *gi,
                                     const unsigned char *msg,
                                     size_t               msg_len,
                                     uint32_t             now_unix)
{
    if (!gi) return GOSSIP_INGEST_MALFORMED;

    /* Minimum: type(2)+sig(64)+flen(2)+features(0)+timestamp(4)+node_id(33)
     *          +rgb(3)+alias(32)+addrlen(2) = 142 */
    if (msg_len < 142) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    uint16_t flen = rd16(msg + 66);  /* flen at offset 2+64 = 66 */
    if (msg_len < (size_t)(142 + flen)) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    /* node_id at offset 2+64+2+flen+4 = 72+flen */
    size_t nid_off = (size_t)(72 + flen);
    if (msg_len < nid_off + 33) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    const unsigned char *node_id = msg + nid_off;

    /* Rate limit on node_id */
    if (!rate_check(gi, node_id, 33, now_unix)) {
        gi->n_rejected_rate++;
        return GOSSIP_INGEST_RATE_LIMITED;
    }

    /* Signature verification: sig at msg[2], signed by node_id */
    if (gi->ctx) {
        if (!gossip_verify_node_announcement(gi->ctx, msg, msg_len)) {
            gi->n_rejected_sig++;
            return GOSSIP_INGEST_BAD_SIG;
        }
    }

    /* Extract alias (32 bytes at nid_off+33+3) */
    char alias[33] = {0};
    if (msg_len >= nid_off + 33 + 3 + 32) {
        memcpy(alias, msg + nid_off + 33 + 3, 32);
        alias[32] = '\0';
    }

    /* Store */
    if (gi->gs) {
        gossip_store_upsert_node(gi->gs, node_id, alias, "", now_unix);
    }

    gi->n_node_ann++;
    return gi->ctx ? GOSSIP_INGEST_OK : GOSSIP_INGEST_NO_VERIFY;
}

/* -----------------------------------------------------------------------
 * channel_update (type 258)
 *
 * Wire layout (after type(2)):
 *   sig(64) chain_hash(32) short_channel_id(8) timestamp(4)
 *   message_flags(1) channel_flags(1) cltv_expiry_delta(2)
 *   htlc_minimum_msat(8) fee_base_msat(4) fee_proportional_millionths(4)
 *   [htlc_maximum_msat(8)]  -- if message_flags bit 0 set
 *
 * Offsets from msg[0]:
 *   sig        at  2
 *   chain_hash at 66
 *   scid       at 98
 *   timestamp  at 106
 *   msg_flags  at 110
 *   chan_flags at 111
 *   cltv       at 112
 *   htlc_min   at 114
 *   fee_base   at 122
 *   fee_ppm    at 126
 *   htlc_max   at 130 (optional)
 *
 * Min length (without htlc_max): 2+64+32+8+4+1+1+2+8+4+4 = 130
 * --------------------------------------------------------------------- */
int gossip_ingest_channel_update(gossip_ingest_t     *gi,
                                  const unsigned char *msg,
                                  size_t               msg_len,
                                  uint32_t             now_unix)
{
    if (!gi) return GOSSIP_INGEST_MALFORMED;

    if (msg_len < 130) {
        gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    uint64_t scid        = rd64(msg + 98);
    uint8_t  chan_flags  = msg[111];
    int      direction   = (int)(chan_flags & 0x01);
    uint16_t cltv        = (uint16_t)(((uint16_t)msg[112] << 8) | msg[113]);
    uint32_t fee_base    = rd32(msg + 122);
    uint32_t fee_ppm     = rd32(msg + 126);

    /* Rate limit: key = scid(8) + direction(1) */
    unsigned char rate_key[9];
    memcpy(rate_key, msg + 98, 8);
    rate_key[8] = (unsigned char)direction;
    if (!rate_check(gi, rate_key, 9, now_unix)) {
        gi->n_rejected_rate++;
        return GOSSIP_INGEST_RATE_LIMITED;
    }

    /* Look up channel to get signer pubkey */
    unsigned char node1[33] = {0}, node2[33] = {0};
    int have_signer = 0;
    if (gi->gs) {
        uint64_t cap; uint32_t lu;
        if (gossip_store_get_channel(gi->gs, scid, node1, node2, &cap, &lu)) {
            have_signer = 1;
        }
    }

    if (!have_signer && gi->gs) {
        /* Channel unknown — orphan update */
        gi->n_rejected_orphan++;
        return GOSSIP_INGEST_ORPHAN;
    }

    /* Signature verification */
    if (gi->ctx && have_signer) {
        const unsigned char *signer = (direction == 0) ? node1 : node2;
        const unsigned char *sig64  = msg + 2;
        if (!verify_schnorr(gi->ctx, sig64, signer, msg, msg_len)) {
            gi->n_rejected_sig++;
            return GOSSIP_INGEST_BAD_SIG;
        }
    }

    /* Store */
    if (gi->gs) {
        gossip_store_upsert_channel_update(gi->gs, scid, direction,
                                           fee_base, fee_ppm,
                                           cltv, now_unix);
    }

    gi->n_chan_update++;
    return (gi->ctx && have_signer) ? GOSSIP_INGEST_OK : GOSSIP_INGEST_NO_VERIFY;
}

/* -----------------------------------------------------------------------
 * gossip_timestamp_filter (type 265)
 *
 * Wire layout (after type(2)):
 *   chain_hash(32) first_timestamp(4) timestamp_range(4)
 * Total: 2+32+4+4 = 42 bytes
 * --------------------------------------------------------------------- */
int gossip_ingest_timestamp_filter(gossip_ingest_t     *gi,
                                    const unsigned char *msg,
                                    size_t               msg_len,
                                    unsigned char        chain_hash_out[32],
                                    uint32_t            *first_ts_out,
                                    uint32_t            *range_out)
{
    (void)gi;
    if (msg_len < 42) return GOSSIP_INGEST_MALFORMED;
    if (chain_hash_out) memcpy(chain_hash_out, msg + 2, 32);
    if (first_ts_out)   *first_ts_out = rd32(msg + 34);
    if (range_out)       *range_out   = rd32(msg + 38);
    return GOSSIP_INGEST_OK;
}

/* -----------------------------------------------------------------------
 * Dispatcher
 * --------------------------------------------------------------------- */
int gossip_ingest_message(gossip_ingest_t      *gi,
                          const unsigned char  *msg,
                          size_t                msg_len,
                          uint32_t              now_unix)
{
    if (!gi || !msg || msg_len < 2) {
        if (gi) gi->n_rejected_malformed++;
        return GOSSIP_INGEST_MALFORMED;
    }

    uint16_t t = rd16(msg);
    switch (t) {
    case 256:
        return gossip_ingest_channel_announcement(gi, msg, msg_len, now_unix);
    case 257:
        return gossip_ingest_node_announcement(gi, msg, msg_len, now_unix);
    case 258:
        return gossip_ingest_channel_update(gi, msg, msg_len, now_unix);
    case 265: {
        unsigned char ch[32]; uint32_t ft = 0, rng = 0;
        return gossip_ingest_timestamp_filter(gi, msg, msg_len, ch, &ft, &rng);
    }
    default:
        return GOSSIP_INGEST_UNKNOWN_TYPE;
    }
}

/* -----------------------------------------------------------------------
 * Result string
 * --------------------------------------------------------------------- */
const char *gossip_ingest_result_str(int result)
{
    switch (result) {
    case GOSSIP_INGEST_OK:           return "ok";
    case GOSSIP_INGEST_BAD_SIG:      return "bad_signature";
    case GOSSIP_INGEST_RATE_LIMITED: return "rate_limited";
    case GOSSIP_INGEST_ORPHAN:       return "orphan_update";
    case GOSSIP_INGEST_MALFORMED:    return "malformed";
    case GOSSIP_INGEST_UNKNOWN_TYPE: return "unknown_type";
    case GOSSIP_INGEST_NO_VERIFY:    return "no_verify";
    default:                          return "unknown";
    }
}
