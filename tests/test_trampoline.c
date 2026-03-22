/*
 * test_trampoline.c — Tests for trampoline routing (Phoenix/BOLT #4 PR #716).
 *
 * PR #37: Trampoline routing for Phoenix wallet interoperability
 */

#include "superscalar/trampoline.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void make_pubkey(unsigned char pk[33], unsigned char seed)
{
    pk[0] = 0x02;  /* compressed pubkey prefix */
    memset(pk + 1, seed, 32);
}

/* TR1: trampoline_build_hop_payload encodes correctly */
int test_trampoline_build_hop_payload(void)
{
    trampoline_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    make_pubkey(hop.pubkey, 0x11);
    hop.amt_msat    = 100000;
    hop.cltv_expiry = 600;

    unsigned char buf[256];
    size_t len = trampoline_build_hop_payload(&hop, buf, sizeof(buf));
    ASSERT(len > 0, "build ok");
    /* type 2 (amt) should appear */
    ASSERT(buf[0] == 2, "first TLV type=2 (amt)");
    return 1;
}

/* TR2: trampoline_build_hop_payload + trampoline_parse_hop_payload round-trip */
int test_trampoline_hop_payload_roundtrip(void)
{
    trampoline_hop_t hop_in, hop_out;
    memset(&hop_in, 0, sizeof(hop_in));
    make_pubkey(hop_in.pubkey, 0x22);
    hop_in.amt_msat    = 50000;
    hop_in.cltv_expiry = 720;

    unsigned char buf[256];
    size_t len = trampoline_build_hop_payload(&hop_in, buf, sizeof(buf));
    ASSERT(len > 0, "build ok");

    ASSERT(trampoline_parse_hop_payload(buf, len, &hop_out), "parse ok");
    ASSERT(hop_out.amt_msat == 50000, "amt preserved");
    ASSERT(hop_out.cltv_expiry == 720, "cltv preserved");
    ASSERT(memcmp(hop_out.pubkey, hop_in.pubkey, 33) == 0, "pubkey preserved");
    return 1;
}

/* TR3: trampoline_estimate_fees uses 0.1% min 100 msat */
int test_trampoline_fee_estimate(void)
{
    trampoline_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    make_pubkey(hop.pubkey, 0x33);

    /* 1,000,000 msat → 0.1% = 1000 msat fee */
    ASSERT(trampoline_estimate_fees(&hop, 1000000), "estimate ok");
    ASSERT(hop.fee_msat == 1000, "fee=1000 for 1000000 msat");
    ASSERT(hop.amt_msat == 1001000, "amt = dest + fee");
    ASSERT(hop.cltv_expiry == 288, "default cltv=288");

    /* Small amount → minimum 100 msat fee */
    memset(&hop, 0, sizeof(hop));
    make_pubkey(hop.pubkey, 0x44);
    ASSERT(trampoline_estimate_fees(&hop, 50000), "estimate small ok");
    ASSERT(hop.fee_msat >= 100, "min fee = 100 msat");
    return 1;
}

/* TR4: trampoline_path_total_fees sums hop fees */
int test_trampoline_path_fees(void)
{
    trampoline_path_t path;
    memset(&path, 0, sizeof(path));
    path.n_hops = 2;
    path.hops[0].fee_msat = 500;
    path.hops[1].fee_msat = 300;

    uint64_t total = trampoline_path_total_fees(&path);
    ASSERT(total == 800, "total fees = 800");
    ASSERT(trampoline_path_total_fees(NULL) == 0, "NULL path = 0 fees");
    return 1;
}

/* TR5: trampoline_build_single_hop_path builds correct path */
int test_trampoline_single_hop_path(void)
{
    unsigned char trampoline_pk[33], dest_pk[33];
    make_pubkey(trampoline_pk, 0x55);
    make_pubkey(dest_pk, 0x66);

    trampoline_path_t path;
    ASSERT(trampoline_build_single_hop_path(&path, trampoline_pk, dest_pk,
                                             100000, 144), "build path ok");
    ASSERT(path.n_hops == 1, "one hop");
    ASSERT(memcmp(path.hops[0].pubkey, trampoline_pk, 33) == 0,
           "hop pubkey = trampoline");
    ASSERT(memcmp(path.dest_pubkey, dest_pk, 33) == 0, "dest pubkey set");
    ASSERT(path.dest_amt_msat == 100000, "dest amount preserved");
    ASSERT(path.hops[0].amt_msat > 100000, "hop amount includes fees");
    return 1;
}

/* TR6: trampoline_build_invoice_hint encodes 51 bytes */
int test_trampoline_invoice_hint_build(void)
{
    trampoline_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    make_pubkey(hop.pubkey, 0x77);
    hop.fee_msat    = 100;
    hop.cltv_expiry = 288;

    unsigned char buf[64];
    size_t len = trampoline_build_invoice_hint(&hop, buf, sizeof(buf));
    ASSERT(len == 51, "hint = 51 bytes");
    ASSERT(memcmp(buf, hop.pubkey, 33) == 0, "pubkey first");
    /* SCID at offset 33 should be zero */
    unsigned char zeros[8] = {0};
    ASSERT(memcmp(buf + 33, zeros, 8) == 0, "scid=0");
    /* cltv_expiry_delta at offset 49: 288 = 0x0120 */
    ASSERT(buf[49] == 0x01 && buf[50] == 0x20, "cltv=288");
    return 1;
}

/* TR7: trampoline_parse_invoice_hint round-trip */
int test_trampoline_invoice_hint_roundtrip(void)
{
    trampoline_hop_t hop_in, hop_out;
    memset(&hop_in, 0, sizeof(hop_in));
    make_pubkey(hop_in.pubkey, 0x88);
    hop_in.fee_msat    = 100;
    hop_in.cltv_expiry = 288;

    unsigned char buf[64];
    size_t len = trampoline_build_invoice_hint(&hop_in, buf, sizeof(buf));
    ASSERT(len == 51, "build ok");

    int r = trampoline_parse_invoice_hint(buf, len, &hop_out);
    ASSERT(r == 1, "parse returns 1 (trampoline hint)");
    ASSERT(memcmp(hop_out.pubkey, hop_in.pubkey, 33) == 0, "pubkey preserved");
    ASSERT(hop_out.cltv_expiry == 288, "cltv preserved");
    return 1;
}

/* TR8: non-trampoline hint (low CLTV) returns 0 */
int test_trampoline_hint_not_trampoline(void)
{
    unsigned char buf[51];
    memset(buf, 0, sizeof(buf));
    /* cltv_expiry_delta = 6 (normal channel) */
    buf[49] = 0; buf[50] = 6;

    trampoline_hop_t hop;
    int r = trampoline_parse_invoice_hint(buf, 51, &hop);
    ASSERT(r == 0, "low-cltv hint not trampoline");
    return 1;
}

/* TR9: NULL / buffer too small safety */
int test_trampoline_null_safety(void)
{
    unsigned char buf[256];
    trampoline_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    make_pubkey(hop.pubkey, 0x99);
    hop.amt_msat = 1000; hop.cltv_expiry = 100;

    ASSERT(!trampoline_build_hop_payload(NULL, buf, sizeof(buf)),
           "NULL hop rejected");
    ASSERT(!trampoline_build_hop_payload(&hop, NULL, sizeof(buf)),
           "NULL buf rejected");
    ASSERT(!trampoline_build_hop_payload(&hop, buf, 3),
           "tiny buf rejected");
    ASSERT(!trampoline_parse_hop_payload(NULL, 10, &hop), "NULL buf rejected");
    ASSERT(!trampoline_estimate_fees(&hop, 0), "zero amount rejected");
    ASSERT(!trampoline_estimate_fees(NULL, 1000), "NULL hop rejected");

    trampoline_path_t path;
    ASSERT(!trampoline_build_single_hop_path(NULL, hop.pubkey, hop.pubkey,
                                              1000, 100), "NULL path rejected");
    ASSERT(!trampoline_build_single_hop_path(&path, NULL, hop.pubkey,
                                              1000, 100), "NULL trampoline pk rejected");
    ASSERT(!trampoline_build_single_hop_path(&path, hop.pubkey, NULL,
                                              1000, 100), "NULL dest pk rejected");
    ASSERT(!trampoline_build_single_hop_path(&path, hop.pubkey, hop.pubkey,
                                              0, 100), "zero amount rejected");
    return 1;
}

/* TR10: bigsize encoding handles various values */
int test_trampoline_bigsize_encoding(void)
{
    /* Indirect test via hop payload with large amounts */
    trampoline_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    make_pubkey(hop.pubkey, 0xAA);
    hop.amt_msat    = 21000000000000ULL;  /* 21M BTC in msat */
    hop.cltv_expiry = 65536;              /* u32, > 0xffff */

    unsigned char buf[256];
    size_t len = trampoline_build_hop_payload(&hop, buf, sizeof(buf));
    ASSERT(len > 0, "large values encoded");

    trampoline_hop_t parsed;
    ASSERT(trampoline_parse_hop_payload(buf, len, &parsed), "parse large values ok");
    ASSERT(parsed.amt_msat == 21000000000000ULL, "large amt preserved");
    ASSERT(parsed.cltv_expiry == 65536, "large cltv preserved");
    return 1;
}
