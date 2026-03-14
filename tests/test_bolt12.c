#include "superscalar/bolt12.h"
#include "superscalar/blinded_path.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Test F1: offer encode/decode round-trip */
int test_offer_encode_decode(void)
{
    offer_t o;
    memset(&o, 0, sizeof(o));
    memset(o.node_id, 0x02, 33);
    o.node_id[0] = 0x02;
    o.amount_msat = 10000;
    o.has_amount = 1;
    strcpy(o.description, "Test offer");

    char encoded[512];
    ASSERT(offer_encode(&o, encoded, sizeof(encoded)), "encode should succeed");
    ASSERT(strncmp(encoded, "lno1", 4) == 0, "should start with lno1");

    offer_t decoded;
    ASSERT(offer_decode(encoded, &decoded), "decode should succeed");
    ASSERT(memcmp(decoded.node_id, o.node_id, 33) == 0, "node_id matches");
    ASSERT(decoded.amount_msat == o.amount_msat, "amount_msat matches");
    ASSERT(strcmp(decoded.description, o.description) == 0, "description matches");

    return 1;
}

/* Test F2: invoice_request sign then verify */
int test_invoice_request_sign_verify(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char seckey[32];
    memset(seckey, 0x11, 32);

    /* Get the corresponding pubkey */
    secp256k1_keypair kp;
    ASSERT(secp256k1_keypair_create(ctx, &kp, seckey), "keypair");
    secp256k1_pubkey pub;
    ASSERT(secp256k1_keypair_pub(ctx, &pub, &kp), "pubkey");
    unsigned char pub33[33];
    size_t pub33_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33_len, &pub, SECP256K1_EC_COMPRESSED);

    invoice_request_t req;
    memset(&req, 0, sizeof(req));
    memset(req.offer_id, 0xAB, 32);
    req.amount_msat = 5000000;
    memcpy(req.payer_key, pub33, 33);

    ASSERT(invoice_request_sign(&req, ctx, seckey), "sign should succeed");
    ASSERT(invoice_request_verify(&req, ctx), "verify should succeed");

    /* Tamper with amount — verify should fail */
    req.amount_msat = 9999999;
    ASSERT(!invoice_request_verify(&req, ctx), "tampered request should fail verify");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test F3: invoice sign then verify */
int test_invoice_sign_verify(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char node_seckey[32];
    memset(node_seckey, 0x22, 32);

    /* Get node_id (pubkey) */
    secp256k1_keypair kp;
    ASSERT(secp256k1_keypair_create(ctx, &kp, node_seckey), "keypair");
    secp256k1_pubkey pub;
    ASSERT(secp256k1_keypair_pub(ctx, &pub, &kp), "pubkey");
    unsigned char node_id33[33];
    size_t sz = 33;
    secp256k1_ec_pubkey_serialize(ctx, node_id33, &sz, &pub, SECP256K1_EC_COMPRESSED);

    invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    memset(inv.payment_hash, 0xCC, 32);
    memset(inv.offer_id, 0xDD, 32);
    inv.amount_msat = 7777777;

    ASSERT(invoice_sign(&inv, ctx, node_seckey), "sign invoice");
    ASSERT(invoice_verify(&inv, ctx, node_id33), "verify invoice");

    /* Tamper — verify should fail */
    inv.amount_msat = 1;
    ASSERT(!invoice_verify(&inv, ctx, node_id33), "tampered invoice fails verify");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test F4: blinded path with 2 hops */
int test_blinded_path_onion(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char intro_seckey[32];
    memset(intro_seckey, 0x33, 32);

    /* 2 hop pubkeys (33 bytes each) */
    unsigned char hops[2][33];
    memset(hops[0], 0x02, 33); hops[0][0] = 0x02;
    memset(hops[1], 0x03, 33); hops[1][0] = 0x03;

    blinded_path_t path;
    ASSERT(blinded_path_build(&path, ctx, (const unsigned char (*)[33])hops, 2, intro_seckey),
           "blinded_path_build should succeed");
    ASSERT(path.n_hops == 2, "2 hops");
    ASSERT(path.hops[0].blinded_node_id[0] == 0x02, "hop[0] node_id matches");
    ASSERT(path.hops[1].blinded_node_id[0] == 0x03, "hop[1] node_id matches");

    /* Unblind first hop → get hop[1] pubkey */
    unsigned char next33[33];
    ASSERT(blinded_path_unblind_first_hop(&path, ctx, intro_seckey, next33),
           "unblind_first_hop should succeed");
    ASSERT(memcmp(next33, hops[1], 33) == 0, "unblinded next hop matches hop[1]");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test F5: offer with no amount (variable-amount offer) */
int test_offer_no_amount(void)
{
    offer_t o;
    memset(&o, 0, sizeof(o));
    memset(o.node_id, 0x03, 33);
    o.node_id[0] = 0x03;
    o.amount_msat = 0;
    o.has_amount = 0;
    strcpy(o.description, "Variable amount offer");

    char encoded[512];
    ASSERT(offer_encode(&o, encoded, sizeof(encoded)), "encode");

    offer_t decoded;
    ASSERT(offer_decode(encoded, &decoded), "decode");
    ASSERT(decoded.amount_msat == 0, "amount_msat == 0 for variable offer");
    ASSERT(strcmp(decoded.description, o.description) == 0, "description matches");

    return 1;
}
