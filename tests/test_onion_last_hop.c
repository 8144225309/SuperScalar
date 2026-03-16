/*
 * test_onion_last_hop.c — Unit tests for BOLT #4 final-hop onion decryption
 *                         and inbound HTLC state machine
 */

#include "superscalar/onion_last_hop.h"
#include "superscalar/htlc_inbound.h"
#include "superscalar/persist.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/*
 * Helper: build a minimal valid single-hop onion packet for a known node key.
 *
 * Constructs:
 *   version=0 || ephemeral_pub(33) || encrypted_hops_data(1300) || hmac_zeroed(32)
 *
 * The TLV payload encodes:
 *   type=2 (amt_to_forward=50000 msat)
 *   type=4 (outgoing_cltv=800000)
 *   type=8 (payment_data: secret=0xAA..AA, total=50000 msat)
 *
 * Returns 1 on success.
 */
static int build_test_onion(secp256k1_context *ctx,
                              const unsigned char node_priv32[32],
                              unsigned char onion_out[ONION_PACKET_SIZE],
                              onion_hop_payload_t *expected_out) {
    /* Generate ephemeral keypair */
    unsigned char eph_priv[32];
    memset(eph_priv, 0x55, 32);

    secp256k1_pubkey eph_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &eph_pub, eph_priv)) return 0;

    unsigned char eph_pub33[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, eph_pub33, &pub_len, &eph_pub,
                                   SECP256K1_EC_COMPRESSED);

    /* Compute shared secret: ECDH(eph_priv, node_pub) */
    secp256k1_pubkey node_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &node_pub, node_priv32)) return 0;
    unsigned char node_pub33[33];
    pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, node_pub33, &pub_len, &node_pub,
                                   SECP256K1_EC_COMPRESSED);

    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, node_priv32, eph_pub33, ss)) return 0;

    /* Derive rho */
    unsigned char rho[32];
    onion_generate_rho(ss, rho);

    /* Build TLV payload:
       type=2, len=8, value=50000 (u64 BE)
       type=4, len=4, value=800000 (u32 BE)
       type=8, len=40, value=secret(32)||total_msat(8)
    */
    unsigned char payment_secret[32];
    memset(payment_secret, 0xAA, 32);
    uint64_t amt = 50000;
    uint32_t cltv = 800000;
    uint64_t total = 50000;

    unsigned char tlv[64];
    size_t tlv_len = 0;
    /* type=2 */
    tlv[tlv_len++] = 2;
    tlv[tlv_len++] = 8;
    for (int i = 7; i >= 0; i--) tlv[tlv_len++] = (unsigned char)(amt >> (i*8));
    /* type=4 */
    tlv[tlv_len++] = 4;
    tlv[tlv_len++] = 4;
    tlv[tlv_len++] = (unsigned char)(cltv >> 24);
    tlv[tlv_len++] = (unsigned char)(cltv >> 16);
    tlv[tlv_len++] = (unsigned char)(cltv >>  8);
    tlv[tlv_len++] = (unsigned char)(cltv);
    /* type=8 */
    tlv[tlv_len++] = 8;
    tlv[tlv_len++] = 40;
    memcpy(tlv + tlv_len, payment_secret, 32); tlv_len += 32;
    for (int i = 7; i >= 0; i--) tlv[tlv_len++] = (unsigned char)(total >> (i*8));

    /* Build plaintext hops_data: BigSize(tlv_len) || tlv || HMAC(32 zeros) || zeros... */
    unsigned char plain[ONION_HOPS_DATA_SIZE];
    memset(plain, 0, sizeof(plain));
    size_t off = 0;
    plain[off++] = (unsigned char)tlv_len; /* BigSize: tlv_len < 0xFD so 1 byte */
    memcpy(plain + off, tlv, tlv_len); off += tlv_len;
    /* HMAC zeroed (already zero from memset) */

    /* Encrypt hops_data by XORing with rho stream */
    unsigned char encrypted[ONION_HOPS_DATA_SIZE];
    if (!onion_xor_stream(plain, ONION_HOPS_DATA_SIZE, rho, encrypted)) return 0;

    /* Build onion packet */
    onion_out[0] = 0x00; /* version */
    memcpy(onion_out + 1, eph_pub33, 33);
    memcpy(onion_out + 34, encrypted, ONION_HOPS_DATA_SIZE);
    memset(onion_out + 34 + ONION_HOPS_DATA_SIZE, 0, 32); /* hmac zeros */

    /* Set expected output */
    memset(expected_out, 0, sizeof(*expected_out));
    expected_out->amt_to_forward      = amt;
    expected_out->outgoing_cltv_value = cltv;
    memcpy(expected_out->payment_secret, payment_secret, 32);
    expected_out->total_msat           = total;
    expected_out->has_amt             = 1;
    expected_out->has_cltv            = 1;
    expected_out->has_payment_data    = 1;

    return 1;
}

/* Test O1: last-hop onion decrypt self-consistent round-trip */
int test_onion_last_hop_decrypt(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char node_priv[32];
    memset(node_priv, 0x33, 32);

    unsigned char onion[ONION_PACKET_SIZE];
    onion_hop_payload_t expected;
    ASSERT(build_test_onion(ctx, node_priv, onion, &expected), "build test onion");

    onion_hop_payload_t got;
    ASSERT(onion_last_hop_decrypt(ctx, node_priv, onion, &got), "decrypt succeeds");

    ASSERT(got.amt_to_forward == expected.amt_to_forward, "amt_to_forward matches");
    ASSERT(got.outgoing_cltv_value == expected.outgoing_cltv_value, "cltv matches");
    ASSERT(got.has_payment_data, "payment_data present");
    ASSERT(memcmp(got.payment_secret, expected.payment_secret, 32) == 0,
           "payment_secret matches");
    ASSERT(got.total_msat == expected.total_msat, "total_msat matches");

    /* Wrong private key must fail to produce correct payload */
    unsigned char wrong_priv[32];
    memset(wrong_priv, 0x44, 32);
    onion_hop_payload_t bad;
    int bad_ok = onion_last_hop_decrypt(ctx, wrong_priv, onion, &bad);
    /* Either returns 0 (parse error) or returns 1 but with wrong values */
    if (bad_ok) {
        ASSERT(bad.amt_to_forward != expected.amt_to_forward ||
               bad.outgoing_cltv_value != expected.outgoing_cltv_value,
               "wrong key produces wrong values");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test O2: TLV parser handles missing optional fields */
int test_onion_tlv_parse_partial(void)
{
    /* Only type=2 and type=4, no payment_data */
    unsigned char tlv[16];
    size_t off = 0;
    /* type=2, len=8, value=12345 */
    tlv[off++] = 2; tlv[off++] = 8;
    uint64_t v = 12345;
    for (int i = 7; i >= 0; i--) tlv[off++] = (unsigned char)(v >> (i*8));
    /* type=4, len=4, value=700000 */
    tlv[off++] = 4; tlv[off++] = 4;
    uint32_t c = 700000;
    tlv[off++] = (unsigned char)(c >> 24);
    tlv[off++] = (unsigned char)(c >> 16);
    tlv[off++] = (unsigned char)(c >>  8);
    tlv[off++] = (unsigned char)(c);

    onion_hop_payload_t out;
    ASSERT(onion_parse_tlv_payload(tlv, off, &out), "parse with amt+cltv only");
    ASSERT(out.amt_to_forward == 12345, "amt_to_forward");
    ASSERT(out.outgoing_cltv_value == 700000, "outgoing_cltv");
    ASSERT(!out.has_payment_data, "no payment_data");

    /* Only type=2: should fail (no cltv) */
    onion_hop_payload_t out2;
    ASSERT(!onion_parse_tlv_payload(tlv, 10, &out2),
           "only amt without cltv should fail");

    return 1;
}

/* Test O3: htlc_inbound fulfill path */
int test_htlc_inbound_fulfill_path(void)
{
    htlc_inbound_table_t tbl;
    htlc_inbound_init(&tbl);

    unsigned char ph[32], ps[32], pre[32];
    memset(ph,  0xCC, 32);
    memset(ps,  0xDD, 32);
    memset(pre, 0xEE, 32);

    uint64_t scid = 0x000001000003000ULL;
    ASSERT(htlc_inbound_add(&tbl, 1, 50000, ph, ps, 800000, scid),
           "add htlc");
    ASSERT(tbl.count == 1, "count == 1");
    ASSERT(tbl.entries[0].state == HTLC_INBOUND_PENDING, "state PENDING");

    /* Look up by payment secret */
    htlc_inbound_t *found = htlc_inbound_find_by_secret(&tbl, ps);
    ASSERT(found != NULL, "find_by_secret found");
    ASSERT(found->htlc_id == 1, "correct htlc_id");
    ASSERT(found->scid == scid, "correct scid");

    /* Fulfill */
    ASSERT(htlc_inbound_fulfill(&tbl, ph, pre), "fulfill returns 1");
    ASSERT(tbl.entries[0].state == HTLC_INBOUND_FULFILLED, "state FULFILLED");
    ASSERT(memcmp(tbl.entries[0].preimage, pre, 32) == 0, "preimage stored");

    /* Already fulfilled: find_by_secret returns NULL */
    ASSERT(htlc_inbound_find_by_secret(&tbl, ps) == NULL,
           "fulfilled htlc not found by secret");

    /* Duplicate htlc_id rejected */
    ASSERT(!htlc_inbound_add(&tbl, 1, 50000, ph, ps, 800000, scid),
           "duplicate htlc_id rejected");

    return 1;
}

/* Test O4: htlc_inbound timeout */
int test_htlc_inbound_timeout(void)
{
    htlc_inbound_table_t tbl;
    htlc_inbound_init(&tbl);

    unsigned char ph1[32], ps1[32];
    unsigned char ph2[32], ps2[32];
    memset(ph1, 0x01, 32); memset(ps1, 0x02, 32);
    memset(ph2, 0x03, 32); memset(ps2, 0x04, 32);

    /* HTLC 1: expires at height 700 */
    ASSERT(htlc_inbound_add(&tbl, 1, 1000, ph1, ps1, 700, 0), "add htlc1");
    /* HTLC 2: expires at height 800 */
    ASSERT(htlc_inbound_add(&tbl, 2, 2000, ph2, ps2, 800, 0), "add htlc2");

    /* At height 699: no timeouts */
    ASSERT(htlc_inbound_check_timeouts(&tbl, 699) == 0, "no timeouts at 699");
    ASSERT(tbl.entries[0].state == HTLC_INBOUND_PENDING, "htlc1 still pending");

    /* At height 700: htlc1 times out */
    ASSERT(htlc_inbound_check_timeouts(&tbl, 700) == 1, "one timeout at 700");
    ASSERT(tbl.entries[0].state == HTLC_INBOUND_FAILED, "htlc1 failed");
    ASSERT(tbl.entries[1].state == HTLC_INBOUND_PENDING, "htlc2 still pending");

    /* At height 800: htlc2 times out */
    ASSERT(htlc_inbound_check_timeouts(&tbl, 800) == 1, "one timeout at 800");
    ASSERT(tbl.entries[1].state == HTLC_INBOUND_FAILED, "htlc2 failed");

    /* explicit fail */
    htlc_inbound_table_t tbl2;
    htlc_inbound_init(&tbl2);
    unsigned char ph3[32], ps3[32];
    memset(ph3, 0x11, 32); memset(ps3, 0x22, 32);
    ASSERT(htlc_inbound_add(&tbl2, 10, 5000, ph3, ps3, 900000, 0), "add htlc");
    ASSERT(htlc_inbound_fail(&tbl2, 10), "explicit fail returns 1");
    ASSERT(tbl2.entries[0].state == HTLC_INBOUND_FAILED, "state FAILED");
    ASSERT(!htlc_inbound_fail(&tbl2, 10), "re-fail returns 0 (already failed)");

    return 1;
}

/* Test O5: htlc_inbound persist round-trip (schema v6) */
int test_htlc_inbound_persist_roundtrip(void)
{
    persist_t p;
    ASSERT(persist_open(&p, ":memory:"), "open DB");
    ASSERT(PERSIST_SCHEMA_VERSION >= 6, "schema version >= 6");

    /* Build and save a pending HTLC */
    htlc_inbound_t h;
    memset(&h, 0, sizeof(h));
    h.htlc_id    = 42;
    h.amount_msat = 100000;
    memset(h.payment_hash,   0xAA, 32);
    memset(h.payment_secret, 0xBB, 32);
    h.cltv_expiry = 800000;
    h.scid        = 0x000001000003000ULL;
    h.state       = HTLC_INBOUND_PENDING;

    ASSERT(persist_save_htlc_inbound(&p, &h), "save pending HTLC");

    /* Load pending HTLCs back */
    htlc_inbound_table_t tbl;
    htlc_inbound_init(&tbl);
    int n = persist_load_htlc_inbound_pending(&p, &tbl);
    ASSERT(n == 1, "one pending HTLC loaded");
    ASSERT(tbl.entries[0].htlc_id == 42, "htlc_id");
    ASSERT(tbl.entries[0].amount_msat == 100000, "amount_msat");
    ASSERT(memcmp(tbl.entries[0].payment_hash, h.payment_hash, 32) == 0, "payment_hash");
    ASSERT(memcmp(tbl.entries[0].payment_secret, h.payment_secret, 32) == 0, "payment_secret");
    ASSERT(tbl.entries[0].cltv_expiry == 800000, "cltv_expiry");
    ASSERT(tbl.entries[0].scid == h.scid, "scid");

    /* Fulfill: update state + preimage */
    unsigned char preimage[32];
    memset(preimage, 0xCC, 32);
    ASSERT(persist_update_htlc_inbound(&p, 42, HTLC_INBOUND_FULFILLED, preimage),
           "update to fulfilled");

    /* Reload: fulfilled HTLC should NOT appear in pending load */
    htlc_inbound_table_t tbl2;
    htlc_inbound_init(&tbl2);
    n = persist_load_htlc_inbound_pending(&p, &tbl2);
    ASSERT(n == 0, "no pending HTLCs after fulfill");

    /* Failed HTLC also not in pending load */
    htlc_inbound_t h2;
    memset(&h2, 0, sizeof(h2));
    h2.htlc_id = 99;
    h2.state   = HTLC_INBOUND_PENDING;
    memset(h2.payment_hash,   0x11, 32);
    memset(h2.payment_secret, 0x22, 32);
    ASSERT(persist_save_htlc_inbound(&p, &h2), "save second HTLC");
    ASSERT(persist_update_htlc_inbound(&p, 99, HTLC_INBOUND_FAILED, NULL), "fail HTLC");
    htlc_inbound_table_t tbl3;
    htlc_inbound_init(&tbl3);
    n = persist_load_htlc_inbound_pending(&p, &tbl3);
    ASSERT(n == 0, "failed HTLC not in pending");

    persist_close(&p);
    return 1;
}
