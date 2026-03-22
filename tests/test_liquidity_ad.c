/*
 * test_liquidity_ad.c — Tests for liquidity advertisements (option_will_fund).
 *
 * PR #31: Liquidity Advertisements
 * Reference: CLN liquidity_ads.c, BOLT PR #878
 */

#include "superscalar/liquidity_ad.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* LA1: liquidity_ad_build_tlv + parse round-trip */
int test_liqad_tlv_roundtrip(void)
{
    liquidity_ad_t ad = {
        .lease_fee_base_sat = 1000,
        .lease_fee_proportional_basis = 50,
        .channel_fee_max_base_msat = 2000000,
        .channel_fee_max_proportional_thousandths = 100,
        .funding_weight = 700
    };
    unsigned char buf[32];
    size_t len = liquidity_ad_build_tlv(&ad, buf, sizeof(buf));
    ASSERT(len == 22, "TLV is 22 bytes");
    ASSERT(buf[0] == LIQAD_NODE_ANN_TLV_TYPE, "correct TLV type");
    ASSERT(buf[1] == LIQAD_NODE_ANN_TLV_LEN, "correct TLV len");

    liquidity_ad_t ad2;
    memset(&ad2, 0, sizeof(ad2));
    ASSERT(liquidity_ad_parse_tlv(buf, len, &ad2), "parse succeeds");
    ASSERT(ad2.lease_fee_base_sat == 1000, "base_sat matches");
    ASSERT(ad2.lease_fee_proportional_basis == 50, "prop_basis matches");
    ASSERT(ad2.channel_fee_max_base_msat == 2000000, "chan_fee_max_base matches");
    ASSERT(ad2.channel_fee_max_proportional_thousandths == 100, "chan_fee_prop matches");
    ASSERT(ad2.funding_weight == 700, "funding_weight matches");
    return 1;
}

/* LA2: compact_lease encoding is deterministic and consistent */
int test_liqad_compact_deterministic(void)
{
    liquidity_ad_t ad = {
        .lease_fee_base_sat = 100,
        .lease_fee_proportional_basis = 20,
        .channel_fee_max_base_msat = 5120,
        .channel_fee_max_proportional_thousandths = 10,
        .funding_weight = 500
    };
    uint32_t c1 = liquidity_ad_compact(&ad);
    uint32_t c2 = liquidity_ad_compact(&ad);
    ASSERT(c1 == c2, "compact is deterministic");
    ASSERT(c1 != 0, "compact is non-zero for valid ad");

    /* Check byte packing: byte0 = lease_fee_base_sat (clamped 100) */
    unsigned char b0 = (unsigned char)(c1 >> 24);
    ASSERT(b0 == 100, "byte0 encodes lease_fee_base_sat=100");

    /* byte1 = prop_basis (clamped 20) */
    unsigned char b1 = (unsigned char)(c1 >> 16);
    ASSERT(b1 == 20, "byte1 encodes lease_fee_proportional_basis=20");
    return 1;
}

/* LA3: liquidity_ad_fee calculation */
int test_liqad_fee_calc(void)
{
    liquidity_ad_t ad = {
        .lease_fee_base_sat = 1000,
        .lease_fee_proportional_basis = 100,  /* 1% */
        .channel_fee_max_base_msat = 0,
        .channel_fee_max_proportional_thousandths = 0,
        .funding_weight = 500
    };
    /* requested=1000000 sats, feerate=2000 perkw */
    /* fee = 1000 + 1000000*100/10000 + 500*2000/1000 */
    /* fee = 1000 + 10000 + 1000 = 12000 */
    uint64_t fee = liquidity_ad_fee(&ad, 1000000, 2000);
    ASSERT(fee == 12000, "fee = base + proportional + weight = 12000");
    return 1;
}

/* LA4: lease_request build/parse round-trip */
int test_liqad_lease_request_roundtrip(void)
{
    liquidity_ad_t ad = {
        .lease_fee_base_sat = 50,
        .lease_fee_proportional_basis = 10,
        .channel_fee_max_base_msat = 1000,
        .channel_fee_max_proportional_thousandths = 5,
        .funding_weight = 400
    };
    uint32_t compact = liquidity_ad_compact(&ad);
    uint64_t requested = 2000000;  /* 2M sats */

    unsigned char buf[32];
    size_t len = liquidity_ad_build_lease_request(requested, compact, buf, sizeof(buf));
    ASSERT(len == 14, "lease_request is 14 bytes");
    ASSERT(buf[0] == LIQAD_OPEN_CHAN_TLV_TYPE, "correct TLV type");
    ASSERT(buf[1] == LIQAD_OPEN_CHAN_TLV_LEN, "correct TLV len");

    uint64_t sats_out = 0;
    uint32_t compact_out = 0;
    ASSERT(liquidity_ad_parse_lease_request(buf, len, &sats_out, &compact_out),
           "parse succeeds");
    ASSERT(sats_out == requested, "requested_sats matches");
    ASSERT(compact_out == compact, "compact_lease matches");
    return 1;
}

/* LA5: parse truncated TLV returns 0 */
int test_liqad_parse_truncated(void)
{
    unsigned char buf[32];
    memset(buf, 0, sizeof(buf));
    buf[0] = LIQAD_NODE_ANN_TLV_TYPE;
    buf[1] = LIQAD_NODE_ANN_TLV_LEN;
    liquidity_ad_t ad;
    ASSERT(!liquidity_ad_parse_tlv(buf, 10, &ad), "truncated TLV rejected");
    ASSERT(!liquidity_ad_parse_tlv(NULL, 22, &ad), "NULL TLV rejected");
    ASSERT(!liquidity_ad_parse_lease_request(buf, 5, NULL, NULL), "short req rejected");
    return 1;
}

/* LA6: wrong TLV type rejected */
int test_liqad_wrong_type(void)
{
    unsigned char buf[32];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x42;  /* wrong type */
    buf[1] = LIQAD_NODE_ANN_TLV_LEN;
    liquidity_ad_t ad;
    ASSERT(!liquidity_ad_parse_tlv(buf, 22, &ad), "wrong TLV type rejected");
    return 1;
}

/* LA7: fee with zero feerate */
int test_liqad_fee_zero_rate(void)
{
    liquidity_ad_t ad = {
        .lease_fee_base_sat = 500,
        .lease_fee_proportional_basis = 10,
        .channel_fee_max_base_msat = 0,
        .channel_fee_max_proportional_thousandths = 0,
        .funding_weight = 1000
    };
    /* fee = 500 + 100000*10/10000 + 1000*0/1000 = 500 + 100 + 0 = 600 */
    uint64_t fee = liquidity_ad_fee(&ad, 100000, 0);
    ASSERT(fee == 600, "fee with zero feerate = base + proportional");
    return 1;
}

/* LA8: NULL ad -> compact returns 0 */
int test_liqad_null_ad(void)
{
    ASSERT(liquidity_ad_compact(NULL) == 0, "NULL ad compact=0");
    ASSERT(liquidity_ad_fee(NULL, 1000000, 2000) == 0, "NULL ad fee=0");
    unsigned char buf[32];
    ASSERT(liquidity_ad_build_tlv(NULL, buf, sizeof(buf)) == 0, "NULL ad tlv=0");
    ASSERT(liquidity_ad_build_lease_request(1000, 0, NULL, sizeof(buf)) == 0,
           "NULL buf lease_request=0");
    return 1;
}

/* LA9: node_announcement with will_fund TLV */
int test_liqad_node_announcement(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "LA9: secp ctx");
    liquidity_ad_t ad = {
        .lease_fee_base_sat = 200,
        .lease_fee_proportional_basis = 30,
        .channel_fee_max_base_msat = 500000,
        .channel_fee_max_proportional_thousandths = 15,
        .funding_weight = 600
    };
    unsigned char node_priv[32]; memset(node_priv, 0x11, 32);
    unsigned char rgb[3] = {0xFF, 0x88, 0x00};

    unsigned char buf[256];
    size_t len = liquidity_ad_build_node_announcement(buf, sizeof(buf),
                                                       ctx, node_priv, 1700000000,
                                                       rgb, "SuperScalar-LSP", &ad);
    ASSERT(len > 0, "node_announcement with will_fund built");
    /* type should be 257 = 0x0101 */
    ASSERT(buf[0] == 0x01 && buf[1] == 0x01, "msg type is 257");
    /* Last 22 bytes should be the TLV */
    ASSERT(len >= 22, "length >= 22 for TLV");
    ASSERT(buf[len - 22] == LIQAD_NODE_ANN_TLV_TYPE, "TLV appended at end");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* LA10: build without ad (NULL) works as regular node_announcement */
int test_liqad_node_announcement_no_ad(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "LA10: secp ctx");
    unsigned char node_priv[32]; memset(node_priv, 0x22, 32);
    unsigned char buf[256];
    size_t len_with = liquidity_ad_build_node_announcement(buf, sizeof(buf),
                                                            ctx, node_priv, 100,
                                                            NULL, NULL, NULL);
    ASSERT(len_with > 0, "node_announcement without ad built");
    /* With ad should be 22 bytes longer */
    liquidity_ad_t ad = { .lease_fee_base_sat = 1, .funding_weight = 1 };
    size_t len_with_ad = liquidity_ad_build_node_announcement(buf, sizeof(buf),
                                                               ctx, node_priv, 100,
                                                               NULL, NULL, &ad);
    ASSERT(len_with_ad == len_with + 22, "ad adds exactly 22 bytes");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* PR #61: Liquidity Ad node_id pubkey tests                          */
/* ================================================================== */

/* LA_NID1: node_id in announcement is a valid compressed pubkey (0x02/0x03) */
int test_liqad_nodeid_is_compressed_pubkey(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "LA_NID1: secp ctx");
    unsigned char priv[32]; memset(priv, 0x33, 32);
    unsigned char buf[256];
    size_t len = liquidity_ad_build_node_announcement(buf, sizeof(buf),
                                                       ctx, priv, 0,
                                                       NULL, NULL, NULL);
    ASSERT(len > 0, "LA_NID1: built");
    /* node_id is at offset 2+64+2+4 = 72 */
    unsigned char prefix = buf[72];
    ASSERT(prefix == 0x02 || prefix == 0x03, "LA_NID1: node_id prefix is 0x02 or 0x03");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* LA_NID2: node_id is NOT the private key bytes (regression: old placeholder was priv||0x02) */
int test_liqad_nodeid_not_privkey(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "LA_NID2: secp ctx");
    unsigned char priv[32]; memset(priv, 0x44, 32);
    unsigned char buf[256];
    size_t len = liquidity_ad_build_node_announcement(buf, sizeof(buf),
                                                       ctx, priv, 0,
                                                       NULL, NULL, NULL);
    ASSERT(len > 0, "LA_NID2: built");
    /* node_id starts at offset 72; first 32 bytes must NOT be the private key */
    ASSERT(memcmp(buf + 72, priv, 32) != 0,
           "LA_NID2: node_id does not contain raw private key bytes");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* LA_NID3: two different privkeys produce different node_ids */
int test_liqad_nodeid_unique_per_key(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "LA_NID3: secp ctx");
    unsigned char priv_a[32]; memset(priv_a, 0x55, 32);
    unsigned char priv_b[32]; memset(priv_b, 0x66, 32);
    unsigned char buf_a[256], buf_b[256];

    liquidity_ad_build_node_announcement(buf_a, sizeof(buf_a), ctx, priv_a, 0, NULL, NULL, NULL);
    liquidity_ad_build_node_announcement(buf_b, sizeof(buf_b), ctx, priv_b, 0, NULL, NULL, NULL);

    /* node_id at offset 72, 33 bytes */
    ASSERT(memcmp(buf_a + 72, buf_b + 72, 33) != 0,
           "LA_NID3: different privkeys → different node_ids");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* LA_NID4: same privkey → same node_id (deterministic) */
int test_liqad_nodeid_deterministic(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "LA_NID4: secp ctx");
    unsigned char priv[32]; memset(priv, 0x77, 32);
    unsigned char buf1[256], buf2[256];

    liquidity_ad_build_node_announcement(buf1, sizeof(buf1), ctx, priv, 1000, NULL, NULL, NULL);
    liquidity_ad_build_node_announcement(buf2, sizeof(buf2), ctx, priv, 2000, NULL, NULL, NULL);

    /* Different timestamps but same key → same node_id */
    ASSERT(memcmp(buf1 + 72, buf2 + 72, 33) == 0,
           "LA_NID4: same key → same node_id regardless of timestamp");
    secp256k1_context_destroy(ctx);
    return 1;
}
