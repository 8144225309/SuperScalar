/*
 * test_bolt12_full.c — Full BOLT #12 test suite (Phase 5 additions)
 *
 * Tests: offer expiry, invoice_from_request, invoice_error, blinded paths.
 */

#include "superscalar/bolt12.h"
#include "superscalar/bech32m.h"
#include "superscalar/blinded_path.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Test F12-1: offer encode/decode with expiry ---- */
int test_bolt12_offer_expiry(void)
{
    offer_t o;
    memset(&o, 0, sizeof(o));
    memset(o.node_id, 0x02, 33);
    o.amount_msat = 10000;
    o.has_amount  = 1;
    strcpy(o.description, "Expiring offer");
    o.absolute_expiry = (uint64_t)time(NULL) + 3600;
    o.has_expiry = 1;

    /* offer_is_expired before expiry */
    ASSERT(!offer_is_expired(&o, (uint64_t)time(NULL) - 1),
           "not expired before time");

    /* offer_is_expired at/after expiry */
    ASSERT(offer_is_expired(&o, o.absolute_expiry),
           "expired at exact time");
    ASSERT(offer_is_expired(&o, o.absolute_expiry + 1),
           "expired after time");

    /* Offer with no expiry never expires */
    offer_t o2;
    memset(&o2, 0, sizeof(o2));
    o2.has_expiry = 0;
    ASSERT(!offer_is_expired(&o2, UINT64_MAX), "no-expiry offer never expires");

    return 1;
}

/* ---- Test F12-2: invoice_from_request ---- */
int test_bolt12_invoice_from_request(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_seckey[32];
    memset(node_seckey, 0x55, 32);

    /* Build request */
    invoice_request_t req;
    memset(&req, 0, sizeof(req));
    memset(req.offer_id, 0xAA, 32);
    req.amount_msat = 100000;
    memset(req.payer_key, 0x02, 33);

    unsigned char payment_hash[32], payment_secret[32];
    memset(payment_hash,   0x11, 32);
    memset(payment_secret, 0x22, 32);

    invoice_t inv;
    ASSERT(invoice_from_request(&req, ctx, node_seckey,
                                  payment_hash, payment_secret, &inv),
           "invoice_from_request succeeds");
    ASSERT(memcmp(inv.payment_hash, payment_hash, 32) == 0, "payment_hash");
    ASSERT(memcmp(inv.payment_secret, payment_secret, 32) == 0, "payment_secret");
    ASSERT(inv.amount_msat == 100000, "amount_msat");
    ASSERT(memcmp(inv.offer_id, req.offer_id, 32) == 0, "offer_id");

    /* Verify the signature */
    secp256k1_pubkey node_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &node_pub, node_seckey), "pub");
    unsigned char node_id33[33];
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, node_id33, &l, &node_pub, SECP256K1_EC_COMPRESSED);
    ASSERT(invoice_verify(&inv, ctx, node_id33), "invoice signature verifies");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test F12-3: invoice_error_build ---- */
int test_bolt12_invoice_error(void)
{
    const char *reason = "amount too low";
    unsigned char req_tlv[16];
    memset(req_tlv, 0x42, 16);

    invoice_error_t err;
    ASSERT(invoice_error_build(req_tlv, sizeof(req_tlv), reason, 12, &err),
           "error build succeeds");
    ASSERT(strcmp(err.error, reason) == 0, "error message matches");
    ASSERT(err.erroneous_field == 12, "erroneous_field matches");
    ASSERT(err.invoice_request_len == 16, "request TLV copied");
    ASSERT(memcmp(err.invoice_request, req_tlv, 16) == 0, "request data matches");

    /* Null inputs */
    ASSERT(!invoice_error_build(NULL, 0, NULL, 0, NULL), "null out → fail");

    return 1;
}

/* ---- Test F12-4: invoice_request sign + verify ---- */
int test_bolt12_full_sign_verify(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char seckey[32];
    memset(seckey, 0x33, 32);

    secp256k1_keypair kp;
    ASSERT(secp256k1_keypair_create(ctx, &kp, seckey), "kp");
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    unsigned char pub33[33];
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub33, &l, &pub, SECP256K1_EC_COMPRESSED);

    invoice_request_t req;
    memset(&req, 0, sizeof(req));
    memset(req.offer_id, 0xDE, 32);
    req.amount_msat = 77777;
    memcpy(req.payer_key, pub33, 33);

    ASSERT(invoice_request_sign(&req, ctx, seckey), "sign succeeds");
    ASSERT(invoice_request_verify(&req, ctx), "verify succeeds");

    /* Tamper → fail */
    req.amount_msat = 88888;
    ASSERT(!invoice_request_verify(&req, ctx), "tampered verify fails");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test F12-5: offer encode/decode round-trip (existing) ---- */
int test_bolt12_offer_encode_decode(void)
{
    offer_t o;
    memset(&o, 0, sizeof(o));
    memset(o.node_id, 0x02, 33);
    o.amount_msat = 5000;
    o.has_amount  = 1;
    strcpy(o.description, "Full spec offer");

    char encoded[512];
    ASSERT(offer_encode(&o, encoded, sizeof(encoded)), "encode");
    ASSERT(strncmp(encoded, "lno1", 4) == 0, "lno1 prefix");

    offer_t dec;
    ASSERT(offer_decode(encoded, &dec), "decode");
    ASSERT(dec.amount_msat == o.amount_msat, "amount");
    ASSERT(strcmp(dec.description, o.description) == 0, "description");
    return 1;
}

/* ---- Test BF1: blinded path build → unblind first hop → recovers next_node_id ---- */
int test_bolt12_blinded_path_aead(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    /* Ephemeral key e (used by sender to build path) */
    unsigned char e[32];
    memset(e, 0x42, 32);

    /* Hop 0 private key (introduction node's own key) */
    unsigned char hop0_priv[32];
    memset(hop0_priv, 0x11, 32);

    /* Hop 1 private key */
    unsigned char hop1_priv[32];
    memset(hop1_priv, 0x22, 32);

    /* Derive public keys */
    unsigned char hop0_pub[33], hop1_pub[33];
    secp256k1_pubkey pub0, pub1;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub0, hop0_priv), "pub0");
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub1, hop1_priv), "pub1");
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, hop0_pub, &l, &pub0, SECP256K1_EC_COMPRESSED);
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, hop1_pub, &l, &pub1, SECP256K1_EC_COMPRESSED);

    /* Build blinded path: node_pubkeys = [hop0_pub, hop1_pub], intro_seckey = e */
    unsigned char node_pubkeys[2][33];
    memcpy(node_pubkeys[0], hop0_pub, 33);
    memcpy(node_pubkeys[1], hop1_pub, 33);

    blinded_path_t path;
    ASSERT(blinded_path_build(&path, ctx, node_pubkeys, 2, e), "build");
    ASSERT(path.n_hops == 2, "n_hops");

    /* Unblind first hop with hop0's private key → should recover hop1_pub */
    unsigned char next_node[33];
    ASSERT(blinded_path_unblind_first_hop(&path, ctx, hop0_priv, next_node),
           "unblind succeeds");
    ASSERT(memcmp(next_node, hop1_pub, 33) == 0, "recovered next_node_id == hop1_pub");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test BF2: BOLT #12 merkle root — non-empty stream ---- */
int test_bolt12_merkle_root_nonempty(void)
{
    /* Two known byte streams → different roots */
    unsigned char stream_a[64];
    memset(stream_a, 0xAA, 64);
    unsigned char stream_b[64];
    memset(stream_b, 0xBB, 64);

    unsigned char root_a[32], root_b[32];
    bolt12_merkle_root(stream_a, 64, root_a);
    bolt12_merkle_root(stream_b, 64, root_b);

    ASSERT(memcmp(root_a, root_b, 32) != 0, "different streams → different roots");

    /* Same stream → same root (deterministic) */
    unsigned char root_a2[32];
    bolt12_merkle_root(stream_a, 64, root_a2);
    ASSERT(memcmp(root_a, root_a2, 32) == 0, "same stream → same root");

    return 1;
}

/* ---- Test BF3: merkle root over empty stream is well-defined ---- */
int test_bolt12_merkle_root_empty(void)
{
    unsigned char root1[32], root2[32];
    bolt12_merkle_root(NULL, 0, root1);
    bolt12_merkle_root((const unsigned char *)"", 0, root2);
    ASSERT(memcmp(root1, root2, 32) == 0, "NULL and zero-len give same root");
    return 1;
}

/* ---- Test BF4: invoice_sign → invoice_verify with merkle-based sighash ---- */
int test_bolt12_sign_verify_merkle(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char seckey[32];
    memset(seckey, 0x77, 32);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, seckey), "pub");
    unsigned char node_id33[33];
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, node_id33, &l, &pub, SECP256K1_EC_COMPRESSED);

    invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    memset(inv.payment_hash, 0x11, 32);
    memset(inv.offer_id,     0x22, 32);
    inv.amount_msat = 99000;

    ASSERT(invoice_sign(&inv, ctx, seckey),             "sign");
    ASSERT(invoice_verify(&inv, ctx, node_id33),        "verify");

    /* Tamper with amount → verify fails */
    inv.amount_msat = 1;
    ASSERT(!invoice_verify(&inv, ctx, node_id33),       "tampered verify fails");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test BF5: invoice_error_encode → invoice_error_decode roundtrip ---- */
int test_bolt12_invoice_error_wire(void)
{
    const char *reason = "invalid payment hash";
    unsigned char req_tlv[32];
    memset(req_tlv, 0x55, 32);

    invoice_error_t err;
    ASSERT(invoice_error_build(req_tlv, 32, reason, 7, &err), "build");

    unsigned char buf[512];
    size_t len = invoice_error_encode(&err, buf, sizeof(buf));
    ASSERT(len > 4, "encoded to wire");
    ASSERT(buf[0] == 0x80 && buf[1] == 0x02, "outer type 0x8002");

    invoice_error_t dec;
    ASSERT(invoice_error_decode(buf, len, &dec), "decode");
    ASSERT(strcmp(dec.error, reason) == 0,        "error message matches");
    ASSERT(dec.erroneous_field == 7,               "erroneous_field matches");
    ASSERT(dec.invoice_request_len == 32,          "request TLV length");
    ASSERT(memcmp(dec.invoice_request, req_tlv, 32) == 0, "request TLV data");

    /* Wrong outer type → decode fails */
    buf[1] = 0x01;
    ASSERT(!invoice_error_decode(buf, len, &dec), "wrong outer type rejected");

    return 1;
}
