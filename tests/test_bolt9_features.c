/*
 * test_bolt9_features.c — BOLT #9 feature bit negotiation smoke tests
 *
 * BF1:  BOLT1_OUR_FEATURES includes payment_secret bit
 * BF2:  BOLT1_OUR_FEATURES includes gossip_queries bit
 * BF3:  BOLT1_OUR_FEATURES includes basic_mpp bit
 * BF4:  BOLT1_OUR_FEATURES includes static_remote_key bit
 * BF5:  BOLT1_OUR_FEATURES includes data_loss_protect bit
 * BF6:  bolt1_has_feature() returns 1 for a set bit
 * BF7:  bolt1_has_feature() returns 0 for an unset bit
 * BF8:  bolt1_check_mandatory_features() passes for known-only peer features
 * BF9:  bolt1_check_mandatory_features() fails on unknown even (mandatory) bit
 * BF10: bolt1_build_init() + bolt1_parse_init() round-trip preserves features
 * BF11: bolt1_build_init(0) round-trip → local_features == 0
 * BF12: payment_secret even bit (14) from peer → check_mandatory_features fails
 */

#include "superscalar/bolt1.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ================================================================== */
/* BF1 — BOLT1_OUR_FEATURES has payment_secret bit (15)              */
/* ================================================================== */
int test_bf1_our_features_payment_secret(void)
{
    ASSERT(bolt1_has_feature(BOLT1_OUR_FEATURES, BOLT9_PAYMENT_SECRET),
           "BF1: payment_secret bit set in BOLT1_OUR_FEATURES");
    return 1;
}

/* ================================================================== */
/* BF2 — BOLT1_OUR_FEATURES has gossip_queries bit (7)               */
/* ================================================================== */
int test_bf2_our_features_gossip_queries(void)
{
    ASSERT(bolt1_has_feature(BOLT1_OUR_FEATURES, BOLT9_GOSSIP_QUERIES),
           "BF2: gossip_queries bit set in BOLT1_OUR_FEATURES");
    return 1;
}

/* ================================================================== */
/* BF3 — BOLT1_OUR_FEATURES has basic_mpp bit (17)                   */
/* ================================================================== */
int test_bf3_our_features_basic_mpp(void)
{
    ASSERT(bolt1_has_feature(BOLT1_OUR_FEATURES, BOLT9_BASIC_MPP),
           "BF3: basic_mpp bit set in BOLT1_OUR_FEATURES");
    return 1;
}

/* ================================================================== */
/* BF4 — BOLT1_OUR_FEATURES has static_remote_key bit (13)           */
/* ================================================================== */
int test_bf4_our_features_static_remote_key(void)
{
    ASSERT(bolt1_has_feature(BOLT1_OUR_FEATURES, BOLT9_STATIC_REMOTE_KEY),
           "BF4: static_remote_key bit set in BOLT1_OUR_FEATURES");
    return 1;
}

/* ================================================================== */
/* BF5 — BOLT1_OUR_FEATURES has data_loss_protect bit (1)            */
/* ================================================================== */
int test_bf5_our_features_data_loss_protect(void)
{
    ASSERT(bolt1_has_feature(BOLT1_OUR_FEATURES, BOLT9_DATA_LOSS_PROTECT),
           "BF5: data_loss_protect bit set in BOLT1_OUR_FEATURES");
    return 1;
}

/* ================================================================== */
/* BF6 — bolt1_has_feature returns 1 for a set bit                   */
/* ================================================================== */
int test_bf6_has_feature_set(void)
{
    uint64_t feats = UINT64_C(1) << 7; /* bit 7 = gossip_queries */
    ASSERT(bolt1_has_feature(feats, 7) == 1, "BF6: bit 7 is set");
    ASSERT(bolt1_has_feature(feats, 0) == 0, "BF6: bit 0 not set");
    return 1;
}

/* ================================================================== */
/* BF7 — bolt1_has_feature returns 0 for an unset bit                */
/* ================================================================== */
int test_bf7_has_feature_unset(void)
{
    uint64_t feats = 0;
    ASSERT(bolt1_has_feature(feats, BOLT9_PAYMENT_SECRET) == 0,
           "BF7: payment_secret not set in zero features");
    ASSERT(bolt1_has_feature(feats, 63) == 0, "BF7: high bit not set");
    /* Out-of-range → 0 */
    ASSERT(bolt1_has_feature(feats, -1) == 0, "BF7: negative bit → 0");
    ASSERT(bolt1_has_feature(feats, 64) == 0, "BF7: bit 64 → 0");
    return 1;
}

/* ================================================================== */
/* BF8 — check_mandatory_features passes for all-known peer features  */
/* ================================================================== */
int test_bf8_mandatory_check_pass(void)
{
    /* Peer advertises exactly our feature set — all known, no unknown even bits */
    ASSERT(bolt1_check_mandatory_features(BOLT1_OUR_FEATURES, BOLT1_OUR_FEATURES) == 1,
           "BF8: our own features pass mandatory check");

    /* Peer advertises subset of our features */
    uint64_t subset = (UINT64_C(1) << BOLT9_PAYMENT_SECRET);
    ASSERT(bolt1_check_mandatory_features(subset, BOLT1_OUR_FEATURES) == 1,
           "BF8: subset of our features passes");

    /* Peer with no features */
    ASSERT(bolt1_check_mandatory_features(0, BOLT1_OUR_FEATURES) == 1,
           "BF8: zero peer features passes");
    return 1;
}

/* ================================================================== */
/* BF9 — check_mandatory_features fails on unknown even bit           */
/* ================================================================== */
int test_bf9_mandatory_check_fail_unknown_even(void)
{
    /* Bit 20 is even and not in BOLT1_OUR_FEATURES — unknown mandatory */
    uint64_t peer_with_unknown = BOLT1_OUR_FEATURES | (UINT64_C(1) << 20);
    ASSERT(bolt1_check_mandatory_features(peer_with_unknown, BOLT1_OUR_FEATURES) == 0,
           "BF9: unknown even bit 20 fails mandatory check");

    /* Bit 22 (even, not in our features) */
    uint64_t peer_bit22 = UINT64_C(1) << 22;
    ASSERT(bolt1_check_mandatory_features(peer_bit22, BOLT1_OUR_FEATURES) == 0,
           "BF9: unknown even bit 22 fails");

    /* Odd unknown bits are OPTIONAL — should not fail */
    uint64_t peer_odd = BOLT1_OUR_FEATURES | (UINT64_C(1) << 21); /* bit 21 = odd */
    ASSERT(bolt1_check_mandatory_features(peer_odd, BOLT1_OUR_FEATURES) == 1,
           "BF9: unknown odd bit 21 does not fail (optional)");
    return 1;
}

/* ================================================================== */
/* BF10 — bolt1_build_init + bolt1_parse_init round-trip             */
/* ================================================================== */
int test_bf10_init_roundtrip(void)
{
    unsigned char buf[64];
    size_t len = bolt1_build_init(BOLT1_OUR_FEATURES, buf, sizeof(buf));
    ASSERT(len > 4, "BF10: build_init produced bytes");

    bolt1_init_t parsed;
    ASSERT(bolt1_parse_init(buf, len, &parsed) == 1, "BF10: parse_init succeeds");

    /* The local_features field must carry all our advertised bits */
    uint64_t combined = parsed.local_features | parsed.global_features;
    for (int bit = 0; bit < 64; bit++) {
        if ((BOLT1_OUR_FEATURES >> bit) & 1) {
            ASSERT((combined >> bit) & 1,
                   "BF10: every BOLT1_OUR_FEATURES bit present after round-trip");
        }
    }
    return 1;
}

/* ================================================================== */
/* BF11 — bolt1_build_init(0) → local_features == 0 after parse      */
/* ================================================================== */
int test_bf11_init_zero_features(void)
{
    unsigned char buf[64];
    size_t len = bolt1_build_init(0, buf, sizeof(buf));
    ASSERT(len >= 4, "BF11: build_init(0) produced bytes");

    bolt1_init_t parsed;
    ASSERT(bolt1_parse_init(buf, len, &parsed) == 1, "BF11: parse_init");
    ASSERT(parsed.local_features == 0 && parsed.global_features == 0,
           "BF11: zero features after round-trip");
    return 1;
}

/* ================================================================== */
/* BF12 — peer with payment_secret as even (bit 14) fails mandatory   */
/* ================================================================== */
int test_bf12_mandatory_check_even_payment_secret(void)
{
    /* Bit 14 is even — "payment_secret required". We know odd bit 15
     * (BOLT9_PAYMENT_SECRET) but not even bit 14. */
    uint64_t peer_even_ps = UINT64_C(1) << 14; /* even = mandatory */
    ASSERT(bolt1_check_mandatory_features(peer_even_ps, BOLT1_OUR_FEATURES) == 0,
           "BF12: even payment_secret bit 14 fails mandatory check");

    /* Bit 15 (odd = optional) from peer → should pass */
    uint64_t peer_odd_ps = UINT64_C(1) << 15;
    ASSERT(bolt1_check_mandatory_features(peer_odd_ps, BOLT1_OUR_FEATURES) == 1,
           "BF12: odd payment_secret bit 15 passes (optional)");
    return 1;
}
