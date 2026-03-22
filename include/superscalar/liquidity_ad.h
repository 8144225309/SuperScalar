#ifndef SUPERSCALAR_LIQUIDITY_AD_H
#define SUPERSCALAR_LIQUIDITY_AD_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

/*
 * Liquidity Advertisements (option_will_fund, BOLT #878 draft).
 *
 * Allows LSP nodes to advertise willingness to lease channel liquidity
 * via gossip (node_announcement TLV) and dual-fund open_channel2.
 *
 * Reference: CLN liquidity_ads.h/c, BOLT PR #878, Bitcoin Optech
 *
 * Terms broadcast in node_announcement TLV type 9:
 *   lease_fee_base_sat                    (4 bytes BE)
 *   lease_fee_proportional_basis          (4 bytes BE, per 10000)
 *   channel_fee_max_base_msat             (4 bytes BE)
 *   channel_fee_max_proportional_thousandths (4 bytes BE)
 *   funding_weight                        (4 bytes BE)
 *   = 20 bytes total
 *
 * compact_lease: 4-byte summary packed as:
 *   [0] fee_base_byte      = min(lease_fee_base_sat, 255)
 *   [1] fee_prop_byte      = min(lease_fee_proportional_basis, 255)
 *   [2] chan_fee_base_byte  = min(channel_fee_max_base_msat >> 8, 255)
 *   [3] chan_fee_prop_byte  = min(channel_fee_max_proportional_thousandths, 255)
 */

#define LIQAD_FEATURE_BIT        250  /* option_will_fund (even bit = required) */
#define LIQAD_NODE_ANN_TLV_TYPE    9  /* TLV type in node_announcement */
#define LIQAD_NODE_ANN_TLV_LEN    20  /* 5 x uint32 */
#define LIQAD_OPEN_CHAN_TLV_TYPE  100  /* TLV type in open_channel2: lease request */
#define LIQAD_OPEN_CHAN_TLV_LEN   12  /* requested_sats(8) + compact_lease(4) */

typedef struct {
    uint32_t lease_fee_base_sat;              /* flat fee in satoshis */
    uint32_t lease_fee_proportional_basis;    /* fee per 10000 sats of liquidity */
    uint32_t channel_fee_max_base_msat;       /* max routing base fee (HTLC cap) */
    uint32_t channel_fee_max_proportional_thousandths; /* max prop fee cap */
    uint32_t funding_weight;                  /* weight contribution charged to lessee */
} liquidity_ad_t;

/*
 * Encode liquidity_ad_t to a 4-byte compact_lease summary.
 * Lossy but sufficient for peer matching validation.
 */
uint32_t liquidity_ad_compact(const liquidity_ad_t *ad);

/*
 * Build the 22-byte TLV (type(1)+len(1)+data(20)) for node_announcement.
 * Returns bytes written (22), or 0 on error.
 */
size_t liquidity_ad_build_tlv(const liquidity_ad_t *ad,
                               unsigned char *buf, size_t buf_cap);

/*
 * Parse a 22-byte will_fund TLV into ad_out.
 * Returns 1 on success.
 */
int liquidity_ad_parse_tlv(const unsigned char *tlv, size_t len,
                             liquidity_ad_t *ad_out);

/*
 * Build a lease_request TLV for open_channel2.
 * type(1)+len(1)+requested_sats(8 BE)+compact_lease(4 BE) = 14 bytes.
 * Returns bytes written, or 0 on error.
 */
size_t liquidity_ad_build_lease_request(uint64_t requested_sats,
                                         uint32_t compact_lease,
                                         unsigned char *buf, size_t buf_cap);

/*
 * Parse a lease_request TLV from open_channel2.
 * Returns 1 on success.
 */
int liquidity_ad_parse_lease_request(const unsigned char *buf, size_t len,
                                      uint64_t *sats_out,
                                      uint32_t *compact_lease_out);

/*
 * Calculate the total lease fee for the requested satoshis.
 * fee = lease_fee_base_sat + (requested_sats * lease_fee_proportional_basis / 10000)
 *       + (funding_weight * feerate_perkw / 1000)
 * Returns fee in satoshis.
 */
uint64_t liquidity_ad_fee(const liquidity_ad_t *ad,
                           uint64_t requested_sats,
                           uint32_t feerate_perkw);

/*
 * Build a full node_announcement that includes a will_fund TLV at the end.
 * Extends gossip_build_node_announcement() with liquidity ad terms appended
 * as a TLV record after the standard address section.
 *
 * Returns bytes written, or 0 on error. Fills unsigned 64-byte Schnorr sig.
 */
size_t liquidity_ad_build_node_announcement(
    unsigned char *out, size_t out_cap,
    secp256k1_context *ctx,
    const unsigned char node_priv32[32],
    uint32_t timestamp,
    const unsigned char rgb[3],
    const char *alias_utf8,
    const liquidity_ad_t *ad);

#endif /* SUPERSCALAR_LIQUIDITY_AD_H */
