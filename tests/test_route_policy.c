/*
 * test_route_policy.c — Tests for per-channel HTLC forwarding policy
 *
 * PR #42: Route Policy Enforcement (BOLT #7 channel_update)
 */

#include "superscalar/route_policy.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void make_policy(route_policy_t *p,
                        uint64_t scid, int dir,
                        uint32_t base, uint32_t ppm, uint16_t cltv,
                        uint64_t htlc_min, uint64_t htlc_max)
{
    memset(p, 0, sizeof(*p));
    p->scid = scid;
    p->direction = dir;
    p->fee_base_msat = base;
    p->fee_ppm = ppm;
    p->cltv_expiry_delta = cltv;
    p->htlc_minimum_msat = htlc_min;
    p->htlc_maximum_msat = htlc_max;
    p->disabled = 0;
}

/* RP1: POLICY_OK when fee is sufficient */
int test_route_policy_fee_ok(void)
{
    route_policy_t p;
    make_policy(&p, 1000, 0, 1000, 100, 40, 1000, 0);
    /* fee_required = 1000 + ceil(100000 * 100 / 1000000) = 1000 + 10 = 1010 */
    /* in_amount = out_amount + 1100 (more than enough) */
    int r = route_policy_check(&p, 101100, 100000, 1040, 1000, 0);
    ASSERT(r == POLICY_OK, "fee sufficient → OK");
    return 1;
}

/* RP2: POLICY_FEE_INSUFFICIENT when fee too low */
int test_route_policy_fee_insufficient(void)
{
    route_policy_t p;
    make_policy(&p, 1001, 0, 1000, 1000, 40, 0, 0);
    /* fee_required = 1000 + 100000*1000/1000000 = 1000 + 100 = 1100 */
    /* in_amount = out_amount + 50 (too little) */
    int r = route_policy_check(&p, 100050, 100000, 1040, 1000, 0);
    ASSERT(r == POLICY_FEE_INSUFFICIENT, "insufficient fee");
    return 1;
}

/* RP3: POLICY_HTLC_TOO_SMALL when below htlc_minimum_msat */
int test_route_policy_htlc_too_small(void)
{
    route_policy_t p;
    make_policy(&p, 1002, 0, 0, 0, 40, 10000, 0); /* min = 10000 msat */
    int r = route_policy_check(&p, 5000, 5000, 1040, 1000, 0);
    ASSERT(r == POLICY_HTLC_TOO_SMALL, "below minimum msat");
    return 1;
}

/* RP4: POLICY_HTLC_TOO_LARGE when above htlc_maximum_msat */
int test_route_policy_htlc_too_large(void)
{
    route_policy_t p;
    make_policy(&p, 1003, 0, 0, 0, 40, 0, 1000000); /* max = 1000000 msat = 1 sat */
    int r = route_policy_check(&p, 2000001, 2000000, 1040, 1000, 0);
    ASSERT(r == POLICY_HTLC_TOO_LARGE, "above maximum msat");
    return 1;
}

/* RP5: POLICY_CHANNEL_DISABLED when disabled=1 */
int test_route_policy_disabled(void)
{
    route_policy_t p;
    make_policy(&p, 1004, 0, 0, 0, 40, 0, 0);
    p.disabled = 1;
    int r = route_policy_check(&p, 100100, 100000, 1040, 1000, 0);
    ASSERT(r == POLICY_CHANNEL_DISABLED, "disabled channel");
    return 1;
}

/* RP6: POLICY_CLTV_TOO_SMALL when delta insufficient */
int test_route_policy_cltv_too_small(void)
{
    route_policy_t p;
    make_policy(&p, 1005, 0, 0, 0, 40, 0, 0); /* requires delta ≥ 40 */
    /* in_cltv=1030, out_cltv=1000: delta=30, below required 40 */
    int r = route_policy_check(&p, 100000, 100000, 1030, 1000, 0);
    ASSERT(r == POLICY_CLTV_TOO_SMALL, "cltv delta too small");
    return 1;
}

/* RP7: POLICY_EXPIRY_TOO_SOON when out_cltv too close to chain tip */
int test_route_policy_expiry_too_soon(void)
{
    route_policy_t p;
    make_policy(&p, 1006, 0, 0, 0, 40, 0, 0);
    /* chain_height=1000, out_cltv=1010: only 10 blocks away, less than POLICY_MIN_FINAL_CLTV_DELTA=18 */
    /* in_cltv = out_cltv + 40 to pass cltv delta check */
    int r = route_policy_check(&p, 100000, 100000, 1050, 1010, 1000);
    ASSERT(r == POLICY_EXPIRY_TOO_SOON, "expiry too soon");
    return 1;
}

/* RP8: compute_fee accuracy */
int test_route_policy_compute_fee(void)
{
    route_policy_t p;
    make_policy(&p, 1007, 0, 1000, 100, 40, 0, 0);
    /* fee = 1000 + ceil(100000 * 100 / 1000000) = 1000 + 10 = 1010 */
    uint64_t fee = route_policy_compute_fee(&p, 100000);
    ASSERT(fee == 1010, "fee = 1010 msat");

    /* fee_ppm=1 on 1 msat → ceil = 1 (not 0) */
    make_policy(&p, 1007, 0, 0, 1, 40, 0, 0);
    fee = route_policy_compute_fee(&p, 1);
    ASSERT(fee == 1, "ppm=1 on 1 msat rounds up to 1");

    /* fee_ppm=0 */
    make_policy(&p, 1007, 0, 500, 0, 40, 0, 0);
    fee = route_policy_compute_fee(&p, 1000000);
    ASSERT(fee == 500, "fee_ppm=0 → base only");
    return 1;
}

/* RP9: channel_update wire roundtrip */
int test_route_policy_channel_update_roundtrip(void)
{
    route_policy_t p, q;
    make_policy(&p, 0x0001020304050607ULL, 1, 2000, 500, 144, 1000, 16000000);
    p.last_update = 1700000000;

    unsigned char sig[64]; memset(sig, 0xAB, 64);
    unsigned char chain[32]; memset(chain, 0x00, 32);
    chain[31] = 0x01; /* fake chain hash */

    unsigned char buf[256];
    size_t len = route_policy_build_channel_update(&p, sig, chain, p.last_update,
                                                    buf, sizeof(buf));
    ASSERT(len > 0, "build ok");
    ASSERT(buf[0] == 0x01 && buf[1] == 0x02, "type = 258");

    ASSERT(route_policy_parse_channel_update(buf, len, &q), "parse ok");
    ASSERT(q.scid == p.scid, "scid preserved");
    ASSERT(q.direction == p.direction, "direction preserved");
    ASSERT(q.fee_base_msat == p.fee_base_msat, "fee_base preserved");
    ASSERT(q.fee_ppm == p.fee_ppm, "fee_ppm preserved");
    ASSERT(q.cltv_expiry_delta == p.cltv_expiry_delta, "cltv_delta preserved");
    ASSERT(q.htlc_minimum_msat == p.htlc_minimum_msat, "htlc_min preserved");
    ASSERT(q.htlc_maximum_msat == p.htlc_maximum_msat, "htlc_max preserved");
    ASSERT(q.disabled == p.disabled, "disabled preserved");
    return 1;
}

/* RP10: channel_update without htlc_max */
int test_route_policy_channel_update_no_max(void)
{
    route_policy_t p, q;
    make_policy(&p, 42, 0, 1000, 100, 40, 0, 0); /* htlc_max = 0 = unset */
    p.last_update = 100;

    unsigned char sig[64]; memset(sig, 0, 64);
    unsigned char chain[32]; memset(chain, 0, 32);
    unsigned char buf[256];
    size_t len = route_policy_build_channel_update(&p, sig, chain, 100,
                                                    buf, sizeof(buf));
    ASSERT(len > 0, "build ok");
    ASSERT(route_policy_parse_channel_update(buf, len, &q), "parse ok");
    ASSERT(q.htlc_maximum_msat == 0, "no htlc_max");
    return 1;
}

/* RP11: policy table upsert + find */
int test_route_policy_table_upsert_find(void)
{
    route_policy_table_t tbl; memset(&tbl, 0, sizeof(tbl));
    route_policy_t p;
    make_policy(&p, 5000, 0, 1000, 100, 40, 0, 0);
    p.last_update = 100;

    route_policy_upsert(&tbl, &p);
    ASSERT(tbl.count == 1, "one entry");

    const route_policy_t *found = route_policy_find(&tbl, 5000, 0);
    ASSERT(found != NULL, "found");
    ASSERT(found->fee_base_msat == 1000, "fee_base correct");

    /* Update */
    p.fee_base_msat = 2000; p.last_update = 200;
    route_policy_upsert(&tbl, &p);
    ASSERT(tbl.count == 1, "still one entry after update");
    found = route_policy_find(&tbl, 5000, 0);
    ASSERT(found->fee_base_msat == 2000, "fee_base updated");

    /* Separate direction */
    p.direction = 1; p.fee_base_msat = 500;
    route_policy_upsert(&tbl, &p);
    ASSERT(tbl.count == 2, "two entries for different directions");
    ASSERT(route_policy_find(&tbl, 5000, 0)->fee_base_msat == 2000, "dir0 unchanged");
    ASSERT(route_policy_find(&tbl, 5000, 1)->fee_base_msat == 500, "dir1 found");
    return 1;
}

/* RP12: route_policy_set_disabled */
int test_route_policy_set_disabled(void)
{
    route_policy_table_t tbl; memset(&tbl, 0, sizeof(tbl));
    route_policy_t p;
    make_policy(&p, 6000, 0, 0, 0, 40, 0, 0);
    p.last_update = 1;
    route_policy_upsert(&tbl, &p);

    ASSERT(!route_policy_find(&tbl, 6000, 0)->disabled, "not disabled initially");
    ASSERT(route_policy_set_disabled(&tbl, 6000, 0, 1) == 1, "set_disabled returns 1");
    ASSERT(route_policy_find(&tbl, 6000, 0)->disabled == 1, "now disabled");

    /* Unknown channel → 0 */
    ASSERT(route_policy_set_disabled(&tbl, 9999, 0, 1) == 0, "unknown → 0");
    return 1;
}

/* RP13: NULL safety */
int test_route_policy_null_safety(void)
{
    /* Should not crash */
    route_policy_check(NULL, 100, 100, 1040, 1000, 0);
    route_policy_compute_fee(NULL, 100000);
    route_policy_build_channel_update(NULL, NULL, NULL, 0, NULL, 0);
    route_policy_parse_channel_update(NULL, 0, NULL);
    route_policy_upsert(NULL, NULL);
    route_policy_find(NULL, 0, 0);
    route_policy_set_disabled(NULL, 0, 0, 1);
    return 1;
}

/* RP14: Parse rejects wrong type */
int test_route_policy_parse_wrong_type(void)
{
    unsigned char buf[200]; memset(buf, 0, sizeof(buf));
    buf[0] = 0x01; buf[1] = 0x01; /* type = 257, not 258 */
    route_policy_t q;
    ASSERT(!route_policy_parse_channel_update(buf, sizeof(buf), &q),
           "wrong type rejected");
    return 1;
}
