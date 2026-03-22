/*
 * liquidity_ad.c — Liquidity Advertisements (option_will_fund, BOLT #878 draft).
 *
 * Reference: CLN lightningd/liquidity_ads.c, BOLT PR #878
 */

#include "superscalar/liquidity_ad.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>

static void put_u32_be(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24);
    b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >>  8);
    b[3] = (unsigned char)(v);
}
static void put_u64_be(unsigned char *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) b[7-i] = (unsigned char)(v >> (i*8));
}
static uint32_t get_u32_be(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}
static uint64_t get_u64_be(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

uint32_t liquidity_ad_compact(const liquidity_ad_t *ad)
{
    if (!ad) return 0;
    unsigned char b[4];
    b[0] = (unsigned char)(ad->lease_fee_base_sat > 255 ? 255 : ad->lease_fee_base_sat);
    b[1] = (unsigned char)(ad->lease_fee_proportional_basis > 255
                           ? 255 : ad->lease_fee_proportional_basis);
    b[2] = (unsigned char)((ad->channel_fee_max_base_msat >> 8) > 255
                           ? 255 : (ad->channel_fee_max_base_msat >> 8));
    b[3] = (unsigned char)(ad->channel_fee_max_proportional_thousandths > 255
                           ? 255 : ad->channel_fee_max_proportional_thousandths);
    return get_u32_be(b);
}

size_t liquidity_ad_build_tlv(const liquidity_ad_t *ad,
                               unsigned char *buf, size_t buf_cap)
{
    /* type(1) + len(1) + 5*uint32(20) = 22 bytes */
    if (!ad || !buf || buf_cap < 22) return 0;
    buf[0] = (unsigned char)LIQAD_NODE_ANN_TLV_TYPE;
    buf[1] = (unsigned char)LIQAD_NODE_ANN_TLV_LEN;
    put_u32_be(buf +  2, ad->lease_fee_base_sat);
    put_u32_be(buf +  6, ad->lease_fee_proportional_basis);
    put_u32_be(buf + 10, ad->channel_fee_max_base_msat);
    put_u32_be(buf + 14, ad->channel_fee_max_proportional_thousandths);
    put_u32_be(buf + 18, ad->funding_weight);
    return 22;
}

int liquidity_ad_parse_tlv(const unsigned char *tlv, size_t len,
                             liquidity_ad_t *ad_out)
{
    if (!tlv || len < 22 || !ad_out) return 0;
    if (tlv[0] != (unsigned char)LIQAD_NODE_ANN_TLV_TYPE) return 0;
    if (tlv[1] != (unsigned char)LIQAD_NODE_ANN_TLV_LEN) return 0;
    ad_out->lease_fee_base_sat                      = get_u32_be(tlv +  2);
    ad_out->lease_fee_proportional_basis            = get_u32_be(tlv +  6);
    ad_out->channel_fee_max_base_msat               = get_u32_be(tlv + 10);
    ad_out->channel_fee_max_proportional_thousandths= get_u32_be(tlv + 14);
    ad_out->funding_weight                          = get_u32_be(tlv + 18);
    return 1;
}

size_t liquidity_ad_build_lease_request(uint64_t requested_sats,
                                         uint32_t compact_lease,
                                         unsigned char *buf, size_t buf_cap)
{
    /* type(1) + len(1) + requested_sats(8) + compact_lease(4) = 14 bytes */
    if (!buf || buf_cap < 14) return 0;
    buf[0] = (unsigned char)LIQAD_OPEN_CHAN_TLV_TYPE;
    buf[1] = (unsigned char)LIQAD_OPEN_CHAN_TLV_LEN;
    put_u64_be(buf + 2, requested_sats);
    put_u32_be(buf + 10, compact_lease);
    return 14;
}

int liquidity_ad_parse_lease_request(const unsigned char *buf, size_t len,
                                      uint64_t *sats_out,
                                      uint32_t *compact_lease_out)
{
    if (!buf || len < 14) return 0;
    if (buf[0] != (unsigned char)LIQAD_OPEN_CHAN_TLV_TYPE) return 0;
    if (buf[1] != (unsigned char)LIQAD_OPEN_CHAN_TLV_LEN) return 0;
    if (sats_out)         *sats_out         = get_u64_be(buf + 2);
    if (compact_lease_out)*compact_lease_out = get_u32_be(buf + 10);
    return 1;
}

uint64_t liquidity_ad_fee(const liquidity_ad_t *ad,
                           uint64_t requested_sats,
                           uint32_t feerate_perkw)
{
    if (!ad) return 0;
    uint64_t fee = (uint64_t)ad->lease_fee_base_sat;
    /* proportional: requested_sats * basis / 10000 */
    fee += (requested_sats * (uint64_t)ad->lease_fee_proportional_basis) / 10000ULL;
    /* weight fee: funding_weight * feerate_perkw / 1000 */
    fee += ((uint64_t)ad->funding_weight * (uint64_t)feerate_perkw) / 1000ULL;
    return fee;
}

size_t liquidity_ad_build_node_announcement(
    unsigned char *out, size_t out_cap,
    secp256k1_context *ctx,
    const unsigned char node_priv32[32],
    uint32_t timestamp,
    const unsigned char rgb[3],
    const char *alias_utf8,
    const liquidity_ad_t *ad)
{
    /*
     * node_announcement (type 257):
     *   type(2) + sig(64) + flen(2) + features(var) + timestamp(4)
     *   + node_id(33) + rgb(3) + alias(32) + addrlen(2) + addrs
     *   + will_fund TLV(22)
     *
     * We build a minimal node_announcement without addresses (addrlen=0)
     * and append the will_fund TLV.
     */
    if (!out || !node_priv32 || !ctx) return 0;

    /* Minimal fixed size: 2+64+2+0+4+33+3+32+2+0 = 142 bytes, plus TLV=22 */
    size_t base = 2 + 64 + 2 + 4 + 33 + 3 + 32 + 2;
    size_t tlv_size = ad ? 22 : 0;
    size_t total = base + tlv_size;
    if (out_cap < total) return 0;

    size_t off = 0;

    /* type = 257 (GOSSIP_MSG_NODE_ANNOUNCEMENT) */
    out[off++] = 0x01; out[off++] = 0x01;

    /* signature: 64 zero bytes (caller should sign after) */
    memset(out + off, 0, 64); off += 64;

    /* features: flen=0 (no features) */
    out[off++] = 0x00; out[off++] = 0x00;

    /* timestamp */
    out[off++] = (unsigned char)(timestamp >> 24);
    out[off++] = (unsigned char)(timestamp >> 16);
    out[off++] = (unsigned char)(timestamp >>  8);
    out[off++] = (unsigned char)(timestamp);

    /* node_id: 33-byte compressed pubkey derived from private key (BOLT #7) */
    {
        secp256k1_pubkey pub;
        if (!secp256k1_ec_pubkey_create(ctx, &pub, node_priv32)) return 0;
        size_t pub_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, out + off, &pub_len, &pub,
                                      SECP256K1_EC_COMPRESSED);
    }
    off += 33;

    /* rgb_color: 3 bytes */
    if (rgb) { memcpy(out + off, rgb, 3); }
    else { memset(out + off, 0, 3); }
    off += 3;

    /* alias: 32 bytes */
    if (alias_utf8) {
        size_t al = 0;
        while (al < 32 && alias_utf8[al]) { out[off + al] = (unsigned char)alias_utf8[al]; al++; }
        while (al < 32) { out[off + al] = 0; al++; }
    } else {
        memset(out + off, 0, 32);
    }
    off += 32;

    /* addresses: addrlen=0, no addresses */
    out[off++] = 0x00; out[off++] = 0x00;

    /* will_fund TLV appended after addresses */
    if (ad) {
        size_t tlv_written = liquidity_ad_build_tlv(ad, out + off, out_cap - off);
        if (!tlv_written) return 0;
        off += tlv_written;
    }

    return off;
}
