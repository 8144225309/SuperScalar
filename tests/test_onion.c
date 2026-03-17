/*
 * test_onion.c — Unit tests for BOLT #4 multi-hop onion construction
 */

#include "superscalar/onion.h"
#include "superscalar/onion_last_hop.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void make_privkey(unsigned char priv[32], int seed) {
    memset(priv, 0, 32);
    priv[0] = 0x01;
    priv[1] = (unsigned char)seed;
    priv[31] = (unsigned char)(seed >> 8);
    /* Ensure non-zero */
    if (priv[0] == 0) priv[0] = 1;
}

/* ---- Test O1: single-hop onion build and peel ---- */
int test_onion_single_hop(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char dest_priv[32], dest_pub[33];
    make_privkey(dest_priv, 1);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, dest_priv), "pub");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, dest_pub, &pub_len, &pub, SECP256K1_EC_COMPRESSED);

    unsigned char payment_secret[32];
    memset(payment_secret, 0xCC, 32);

    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, dest_pub, 33);
    hop.amount_msat = 50000;
    hop.cltv_expiry = 800000;
    hop.is_final    = 1;
    memcpy(hop.payment_secret, payment_secret, 32);
    hop.total_msat  = 50000;

    unsigned char session_key[32];
    memset(session_key, 0x55, 32);

    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt), "build single-hop onion");
    ASSERT(onion_pkt[0] == 0x00, "version byte is 0");

    /* Peel the onion as the destination */
    unsigned char next_onion[ONION_PACKET_SIZE];
    onion_hop_payload_t payload;
    int is_final = 0;
    ASSERT(onion_peel(dest_priv, ctx, onion_pkt, next_onion, &payload, &is_final),
           "peel single-hop onion");
    ASSERT(is_final, "recognized as final hop");
    ASSERT(payload.has_amt, "has amt_to_forward");
    ASSERT(payload.amt_to_forward == 50000, "amount matches");
    ASSERT(payload.has_cltv, "has cltv");
    ASSERT(payload.has_payment_data, "has payment_data");
    ASSERT(memcmp(payload.payment_secret, payment_secret, 32) == 0,
           "payment_secret matches");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test O2: two-hop onion, peel at first then final hop ---- */
int test_onion_two_hops(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char hop1_priv[32], hop1_pub[33];
    unsigned char hop2_priv[32], hop2_pub[33];
    make_privkey(hop1_priv, 1);
    make_privkey(hop2_priv, 2);

    secp256k1_pubkey p1, p2;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &p1, hop1_priv), "p1");
    ASSERT(secp256k1_ec_pubkey_create(ctx, &p2, hop2_priv), "p2");
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, hop1_pub, &l, &p1, SECP256K1_EC_COMPRESSED);
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, hop2_pub, &l, &p2, SECP256K1_EC_COMPRESSED);

    unsigned char payment_secret[32];
    memset(payment_secret, 0xAA, 32);

    onion_hop_t hops[2];
    memset(hops, 0, sizeof(hops));

    /* Hop 1 (relay) */
    memcpy(hops[0].pubkey, hop1_pub, 33);
    hops[0].amount_msat      = 51000; /* includes fee */
    hops[0].cltv_expiry      = 800040;
    hops[0].short_channel_id = 12345;
    hops[0].is_final         = 0;

    /* Hop 2 (final) */
    memcpy(hops[1].pubkey, hop2_pub, 33);
    hops[1].amount_msat = 50000;
    hops[1].cltv_expiry = 800000;
    hops[1].is_final    = 1;
    memcpy(hops[1].payment_secret, payment_secret, 32);
    hops[1].total_msat  = 50000;

    unsigned char session_key[32];
    memset(session_key, 0x77, 32);

    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(hops, 2, session_key, ctx, onion_pkt),
           "build two-hop onion");

    /* Peel at hop 1 */
    unsigned char onion2[ONION_PACKET_SIZE];
    onion_hop_payload_t payload1;
    int is_final1 = 0;
    ASSERT(onion_peel(hop1_priv, ctx, onion_pkt, onion2, &payload1, &is_final1),
           "peel at hop 1");
    ASSERT(!is_final1, "hop 1 is relay");
    ASSERT(payload1.has_amt, "hop1 has amount");
    ASSERT(payload1.amt_to_forward == 51000, "hop1 amount");

    /* Peel at hop 2 */
    unsigned char onion3[ONION_PACKET_SIZE];
    onion_hop_payload_t payload2;
    int is_final2 = 0;
    ASSERT(onion_peel(hop2_priv, ctx, onion2, onion3, &payload2, &is_final2),
           "peel at hop 2");
    ASSERT(is_final2, "hop 2 is final");
    ASSERT(payload2.amt_to_forward == 50000, "final hop amount");
    ASSERT(memcmp(payload2.payment_secret, payment_secret, 32) == 0,
           "payment_secret at final");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test O3: keysend onion ---- */
int test_onion_keysend(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char dest_priv[32], dest_pub[33];
    make_privkey(dest_priv, 5);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, dest_priv), "pub");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, dest_pub, &pub_len, &pub, SECP256K1_EC_COMPRESSED);

    unsigned char preimage[32];
    memset(preimage, 0x11, 32);

    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, dest_pub, 33);
    hop.amount_msat   = 10000;
    hop.cltv_expiry   = 700000;
    hop.is_final      = 1;
    hop.has_keysend   = 1;
    memcpy(hop.keysend_preimage, preimage, 32);
    hop.total_msat    = 10000;

    unsigned char session_key[32];
    memset(session_key, 0x99, 32);

    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt),
           "build keysend onion");

    /* Verify it parses correctly */
    unsigned char next_onion[ONION_PACKET_SIZE];
    onion_hop_payload_t payload;
    int is_final = 0;
    ASSERT(onion_peel(dest_priv, ctx, onion_pkt, next_onion, &payload, &is_final),
           "peel keysend onion");
    ASSERT(is_final, "keysend is final");
    ASSERT(payload.amt_to_forward == 10000, "keysend amount");

    secp256k1_context_destroy(ctx);
    return 1;
}
