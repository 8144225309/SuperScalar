/*
 * test_bolt12_full.c — Full BOLT #12 test suite (Phase 5 additions)
 *
 * Tests: offer expiry, invoice_from_request, invoice_error, blinded paths.
 */

#include "superscalar/bolt12.h"
#include "superscalar/ln_dispatch.h"
#include "superscalar/htlc_forward.h"
#include "superscalar/mpp.h"
#include "superscalar/invoice.h"
#include "superscalar/bech32m.h"
#include "superscalar/blinded_path.h"
#include "superscalar/sha256.h"
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

/* ---- Test BF2: BOLT #12 merkle root — non-empty TLV stream ---- */
int test_bolt12_merkle_root_nonempty(void)
{
    /* Two valid single-field TLV records: [type:2][len:2][value:4]
     * Same type and length, different values -> different leaves -> different roots */
    unsigned char stream_a[8] = {0x00, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};
    unsigned char stream_b[8] = {0x00, 0x01, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44};

    unsigned char root_a[32], root_b[32];
    bolt12_merkle_root(stream_a, 8, root_a);
    bolt12_merkle_root(stream_b, 8, root_b);

    ASSERT(memcmp(root_a, root_b, 32) != 0, "different TLV values produce different roots");

    /* Same stream -> same root (deterministic) */
    unsigned char root_a2[32];
    bolt12_merkle_root(stream_a, 8, root_a2);
    ASSERT(memcmp(root_a, root_a2, 32) == 0, "same stream -> same root");

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

/* ================================================================== */
/* BM1 — empty stream produces deterministic root                      */
/* ================================================================== */
int test_bolt12_merkle_empty_deterministic(void)
{
    unsigned char root1[32], root2[32];
    bolt12_merkle_root(NULL, 0, root1);
    bolt12_merkle_root((const unsigned char *)"", 0, root2);
    ASSERT(memcmp(root1, root2, 32) == 0, "NULL and zero-len give same root");

    /* Root is non-zero (SHA256 of tag, not all-zeros) */
    unsigned char zero[32] = {0};
    ASSERT(memcmp(root1, zero, 32) != 0, "empty root is non-zero");
    return 1;
}

/* ================================================================== */
/* BM2 — single TLV field produces correct leaf                        */
/* ================================================================== */
int test_bolt12_merkle_single_field(void)
{
    /* [type=0x0001][len=0x0004][value=0xAABBCCDD] = 8 bytes */
    unsigned char field[8] = {0x00, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};
    unsigned char root[32];
    bolt12_merkle_root(field, 8, root);

    /* Manually compute expected: SHA256(tag_leaf || field) */
    unsigned char tag_leaf[32];
    sha256((const unsigned char *)"LnLeaf", 6, tag_leaf);
    unsigned char buf[32 + 8];
    memcpy(buf, tag_leaf, 32);
    memcpy(buf + 32, field, 8);
    unsigned char expected[32];
    sha256(buf, 40, expected);

    ASSERT(memcmp(root, expected, 32) == 0, "single-field root matches manual SHA256");
    return 1;
}

/* ================================================================== */
/* BM3 — two TLV fields produce correct branch                         */
/* ================================================================== */
int test_bolt12_merkle_two_fields(void)
{
    /* field0: [type=0x0001][len=4][0xAABBCCDD] */
    unsigned char f0[8] = {0x00, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};
    /* field1: [type=0x0002][len=4][0x11223344] */
    unsigned char f1[8] = {0x00, 0x02, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44};
    unsigned char stream[16];
    memcpy(stream,     f0, 8);
    memcpy(stream + 8, f1, 8);

    unsigned char root[32];
    bolt12_merkle_root(stream, 16, root);

    /* Manually compute: SHA256(tag_branch || leaf0 || leaf1) */
    unsigned char tag_leaf[32], tag_branch[32];
    sha256((const unsigned char *)"LnLeaf",   6, tag_leaf);
    sha256((const unsigned char *)"LnBranch", 8, tag_branch);

    unsigned char buf[32 + 8], leaf0[32], leaf1[32];
    memcpy(buf, tag_leaf, 32); memcpy(buf + 32, f0, 8);
    sha256(buf, 40, leaf0);
    memcpy(buf, tag_leaf, 32); memcpy(buf + 32, f1, 8);
    sha256(buf, 40, leaf1);

    unsigned char bbuf[32 + 64], expected[32];
    memcpy(bbuf, tag_branch, 32);
    memcpy(bbuf + 32,      leaf0, 32);
    memcpy(bbuf + 32 + 32, leaf1, 32);
    sha256(bbuf, 96, expected);

    ASSERT(memcmp(root, expected, 32) == 0, "two-field root matches manual SHA256");
    return 1;
}

/* ================================================================== */
/* BM4 — three TLV fields (odd count): last leaf duplicated            */
/* ================================================================== */
int test_bolt12_merkle_three_fields_odd(void)
{
    unsigned char f0[8] = {0x00, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};
    unsigned char f1[8] = {0x00, 0x02, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44};
    unsigned char f2[8] = {0x00, 0x03, 0x00, 0x04, 0x55, 0x66, 0x77, 0x88};
    unsigned char stream[24];
    memcpy(stream,      f0, 8);
    memcpy(stream + 8,  f1, 8);
    memcpy(stream + 16, f2, 8);

    unsigned char root[32];
    bolt12_merkle_root(stream, 24, root);

    /* Manually compute:
     * l0 = SHA256(tag_leaf||f0), l1 = SHA256(tag_leaf||f1), l2 = SHA256(tag_leaf||f2)
     * b01 = SHA256(tag_branch||l0||l1)
     * b22 = SHA256(tag_branch||l2||l2)  <- duplicate last
     * root = SHA256(tag_branch||b01||b22) */
    unsigned char tag_leaf[32], tag_branch[32];
    sha256((const unsigned char *)"LnLeaf",   6, tag_leaf);
    sha256((const unsigned char *)"LnBranch", 8, tag_branch);

    unsigned char lbuf[40], l0[32], l1[32], l2[32];
    memcpy(lbuf, tag_leaf, 32); memcpy(lbuf + 32, f0, 8); sha256(lbuf, 40, l0);
    memcpy(lbuf, tag_leaf, 32); memcpy(lbuf + 32, f1, 8); sha256(lbuf, 40, l1);
    memcpy(lbuf, tag_leaf, 32); memcpy(lbuf + 32, f2, 8); sha256(lbuf, 40, l2);

    unsigned char bbuf[96], b01[32], b22[32], expected[32];
    memcpy(bbuf, tag_branch, 32); memcpy(bbuf+32, l0, 32); memcpy(bbuf+64, l1, 32);
    sha256(bbuf, 96, b01);
    memcpy(bbuf, tag_branch, 32); memcpy(bbuf+32, l2, 32); memcpy(bbuf+64, l2, 32);
    sha256(bbuf, 96, b22);
    memcpy(bbuf, tag_branch, 32); memcpy(bbuf+32, b01, 32); memcpy(bbuf+64, b22, 32);
    sha256(bbuf, 96, expected);

    ASSERT(memcmp(root, expected, 32) == 0, "three-field root with odd-count duplicate matches");
    return 1;
}

/* ================================================================== */
/* BM5 — same TLV stream produces different root than old 64-byte      */
/*       chunk approach (regression: new impl is spec-correct)         */
/* ================================================================== */
int test_bolt12_merkle_regression_vs_old_chunking(void)
{
    /* A valid single 8-byte TLV record */
    unsigned char stream[8] = {0x00, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};

    unsigned char new_root[32];
    bolt12_merkle_root(stream, 8, new_root);

    /* Compute what the OLD 64-byte chunk approach would have produced:
     * leaf = SHA256(tag_leaf || 8_bytes)  [old: same for <=64 byte chunk]
     * Actually for a single 8-byte chunk the old approach gives:
     * leaf = SHA256(SHA256("LnLeaf") || stream[0..7])
     * For the new approach: same! Because the entire 8-byte TLV IS the field.
     * So for a single valid TLV that fits in 64 bytes, the result is the same.
     *
     * The difference emerges when we have a stream that splits across chunk boundaries
     * differently than TLV field boundaries. Test with 2 fields totaling < 64 bytes
     * where old approach makes 1 leaf but new approach makes 2 leaves. */

    /* Two 8-byte fields = 16 bytes total. Old: 1 chunk (16 bytes). New: 2 leaves. */
    unsigned char f0[8] = {0x00, 0x01, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44};
    unsigned char f1[8] = {0x00, 0x02, 0x00, 0x04, 0x55, 0x66, 0x77, 0x88};
    unsigned char stream2[16];
    memcpy(stream2,     f0, 8);
    memcpy(stream2 + 8, f1, 8);

    unsigned char new_root2[32];
    bolt12_merkle_root(stream2, 16, new_root2);

    /* Simulate old approach (single 16-byte chunk): leaf = SHA256(tag_leaf || 16 bytes) */
    unsigned char tag_leaf[32];
    sha256((const unsigned char *)"LnLeaf", 6, tag_leaf);
    unsigned char old_buf[32 + 16];
    memcpy(old_buf, tag_leaf, 32);
    memcpy(old_buf + 32, stream2, 16);
    unsigned char old_root[32];
    sha256(old_buf, 48, old_root);

    ASSERT(memcmp(new_root2, old_root, 32) != 0,
           "TLV-field-boundary approach differs from old 64-byte chunking");
    return 1;
}

/* ================================================================== */
/* BM6 — zero-value TLV field (vlen=0) is a valid leaf                */
/* ================================================================== */
int test_bolt12_merkle_zero_value_field(void)
{
    /* [type=0x0001][len=0x0000] = 4 bytes, valid TLV with empty value */
    unsigned char field[4] = {0x00, 0x01, 0x00, 0x00};
    unsigned char root[32];
    bolt12_merkle_root(field, 4, root);

    /* Manually: leaf = SHA256(tag_leaf || 4_bytes) */
    unsigned char tag_leaf[32];
    sha256((const unsigned char *)"LnLeaf", 6, tag_leaf);
    unsigned char buf[36];
    memcpy(buf, tag_leaf, 32);
    memcpy(buf + 32, field, 4);
    unsigned char expected[32];
    sha256(buf, 36, expected);

    ASSERT(memcmp(root, expected, 32) == 0, "zero-value TLV produces correct leaf");

    /* Must differ from empty stream root */
    unsigned char empty_root[32];
    bolt12_merkle_root(NULL, 0, empty_root);
    ASSERT(memcmp(root, empty_root, 32) != 0, "zero-value field != empty stream");
    return 1;
}

/* ================================================================== */
/* BM7 — truncated TLV field falls back to empty-stream behavior      */
/* ================================================================== */
int test_bolt12_merkle_truncated_field(void)
{
    /* [type=0x0001][len=0x0010] but only 2 bytes of value (truncated) */
    unsigned char partial[8] = {0x00, 0x01, 0x00, 0x10, 0xAA, 0xBB, 0x00, 0x00};
    /* len=0x0010=16 but we only have 4 bytes of the field (8-4=4 value bytes) */

    unsigned char root[32];
    bolt12_merkle_root(partial, 8, root);  /* 8 bytes total, field needs 4+16=20 */

    /* No valid field parsed -> falls back to empty stream root */
    unsigned char empty_root[32];
    bolt12_merkle_root(NULL, 0, empty_root);
    ASSERT(memcmp(root, empty_root, 32) == 0,
           "truncated TLV -> fallback to empty stream root");
    return 1;
}

/* ================================================================== */
/* IS1 — invoice sign → verify roundtrip (regression with merkle)     */
/* ================================================================== */
int test_invoice_sign_verify_regression(void)
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
    memset(inv.offer_id, 0x22, 32);
    memset(inv.payment_secret, 0x33, 32);
    inv.amount_msat = 99000;

    /* Sign with merkle-based approach */
    ASSERT(invoice_sign(&inv, ctx, seckey), "sign");
    /* Verify with same merkle-based approach */
    ASSERT(invoice_verify(&inv, ctx, node_id33), "verify after sign");

    /* Wrong key must not verify */
    unsigned char bad_id[33];
    memset(bad_id, 0x02, 33);
    ASSERT(!invoice_verify(&inv, ctx, bad_id), "wrong key fails verify");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* IS2 — tampered amount_msat causes verify to fail                    */
/* ================================================================== */
int test_invoice_sign_tampered_amount(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char seckey[32];
    memset(seckey, 0x55, 32);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, seckey), "pub");
    unsigned char node_id33[33];
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, node_id33, &l, &pub, SECP256K1_EC_COMPRESSED);

    invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    memset(inv.payment_hash, 0x11, 32);
    memset(inv.offer_id, 0x22, 32);
    inv.amount_msat = 50000;

    ASSERT(invoice_sign(&inv, ctx, seckey), "sign");
    ASSERT(invoice_verify(&inv, ctx, node_id33), "verify before tamper");

    inv.amount_msat = 99999;  /* tamper */
    ASSERT(!invoice_verify(&inv, ctx, node_id33), "verify fails after tamper");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* IS3 — two invoices with different fields produce different sigs     */
/* ================================================================== */
int test_invoice_sign_different_invoices(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char seckey[32];
    memset(seckey, 0x66, 32);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, seckey), "pub");
    unsigned char node_id33[33];
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, node_id33, &l, &pub, SECP256K1_EC_COMPRESSED);

    invoice_t inv1, inv2;
    memset(&inv1, 0, sizeof(inv1));
    memset(&inv2, 0, sizeof(inv2));
    memset(inv1.payment_hash, 0x11, 32);
    memset(inv2.payment_hash, 0x22, 32);  /* different payment_hash */
    inv1.amount_msat = 1000;
    inv2.amount_msat = 1000;

    ASSERT(invoice_sign(&inv1, ctx, seckey), "sign inv1");
    ASSERT(invoice_sign(&inv2, ctx, seckey), "sign inv2");

    /* Signatures must differ (different payment_hash -> different merkle root) */
    ASSERT(memcmp(inv1.node_sig, inv2.node_sig, 64) != 0,
           "different invoices produce different signatures");

    /* Cross-verify must fail */
    memcpy(inv1.node_sig, inv2.node_sig, 64);  /* swap sig */
    ASSERT(!invoice_verify(&inv1, ctx, node_id33), "cross-verify fails");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* IS4 — new merkle-based sig differs from old flat-72-byte sig        */
/* ================================================================== */
int test_invoice_sign_differs_from_old_approach(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char seckey[32];
    memset(seckey, 0x44, 32);

    invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    memset(inv.payment_hash, 0x11, 32);
    memset(inv.offer_id, 0x22, 32);
    memset(inv.payment_secret, 0x33, 32);
    inv.amount_msat = 50000;

    ASSERT(invoice_sign(&inv, ctx, seckey), "sign with new merkle approach");

    /* Manually compute the OLD flat-72-byte sighash:
     * msg = payment_hash(32) || offer_id(32) || amount_msat(8 LE)
     * sighash = SHA256("BOLT12Signature" || msg) */
    unsigned char old_msg[72];
    memcpy(old_msg, inv.payment_hash, 32);
    memcpy(old_msg + 32, inv.offer_id, 32);
    uint64_t amt = inv.amount_msat;
    for (int i = 0; i < 8; i++) { old_msg[64+i] = (unsigned char)(amt & 0xff); amt >>= 8; }
    unsigned char old_sighash[32];
    sha256_tagged("BOLT12Signature", old_msg, 72, old_sighash);

    secp256k1_keypair kp;
    ASSERT(secp256k1_keypair_create(ctx, &kp, seckey), "kp");
    unsigned char aux[32] = {0};
    unsigned char old_sig[64];
    ASSERT(secp256k1_schnorrsig_sign32(ctx, old_sig, old_sighash, &kp, aux), "old sign");

    /* New signature must differ from old flat approach */
    ASSERT(memcmp(inv.node_sig, old_sig, 64) != 0,
           "new merkle-based sig differs from old flat-72-byte sig");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* IW1 — invoice_request_decode round-trip                            */
/* ================================================================== */
int test_invoice_request_decode_roundtrip(void)
{
    /* Manually encode a minimal invoice_request TLV:
     * type 88 (payer_key, 33B) + type 240 (sig, 64B) */
    unsigned char tlv[200];
    size_t pos = 0;

    /* type 88: payer_key (33B) */
    tlv[pos++] = 0x00; tlv[pos++] = 0x58; /* type 88 */
    tlv[pos++] = 0x00; tlv[pos++] = 0x21; /* len 33 */
    tlv[pos++] = 0x02; /* compressed pubkey prefix */
    memset(tlv + pos, 0xAB, 32); pos += 32;

    /* type 240: sig (64B) */
    tlv[pos++] = 0x00; tlv[pos++] = 0xF0; /* type 240 */
    tlv[pos++] = 0x00; tlv[pos++] = 0x40; /* len 64 */
    memset(tlv + pos, 0xCD, 64); pos += 64;

    invoice_request_t req;
    int r = invoice_request_decode(tlv, pos, &req);
    ASSERT(r == 1, "decode returns 1");
    ASSERT(req.payer_key[0] == 0x02, "payer_key prefix correct");
    ASSERT(req.sig[0] == 0xCD, "sig correct");
    return 1;
}

/* ================================================================== */
/* IW2 — truncated TLV → decode returns 0, no crash                   */
/* ================================================================== */
int test_invoice_request_decode_truncated(void)
{
    unsigned char tlv[5];
    memset(tlv, 0x00, sizeof(tlv));
    invoice_request_t req;
    int r = invoice_request_decode(tlv, 3, &req); /* too short for any field */
    ASSERT(r == 0, "truncated → returns 0");

    r = invoice_request_decode(NULL, 0, &req);
    ASSERT(r == 0, "NULL → returns 0");
    return 1;
}

/* ================================================================== */
/* IW3 — invoice_encode produces parseable TLV                        */
/* ================================================================== */
int test_invoice_encode_parseable(void)
{
    invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    memset(inv.payment_hash,   0x11, 32);
    memset(inv.payment_secret, 0x22, 32);
    memset(inv.offer_id,       0x33, 32);
    memset(inv.node_sig,       0x44, 64);
    inv.amount_msat = 50000;

    unsigned char buf[512];
    size_t n = invoice_encode(&inv, buf, sizeof(buf));
    ASSERT(n > 4, "encode produces bytes");

    /* Outer type must be 0x8000 */
    ASSERT(buf[0] == 0x80 && buf[1] == 0x00, "outer type 0x8000");

    /* Parse inner: find type 2 (payment_hash) */
    uint16_t body_len = ((uint16_t)buf[2] << 8) | buf[3];
    ASSERT((size_t)(4 + body_len) <= n, "body length in bounds");

    const unsigned char *body = buf + 4;
    size_t pos = 0;
    int found_hash = 0;
    while (pos + 4 <= body_len) {
        uint16_t t = ((uint16_t)body[pos] << 8) | body[pos + 1];
        uint16_t l = ((uint16_t)body[pos + 2] << 8) | body[pos + 3];
        pos += 4;
        if (t == 2 && l == 32) { found_hash = 1; break; }
        pos += l;
    }
    ASSERT(found_hash, "payment_hash field present");
    return 1;
}

/* ================================================================== */
/* IW4 — ln_dispatch MSG_INVOICE_REQUEST (0x8001): no crash           */
/* ================================================================== */
int test_ln_dispatch_invoice_request(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd; htlc_forward_init(&fwd);
    mpp_table_t mpp; mpp_init(&mpp);

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.ctx = ctx;
    d.fwd = &fwd;
    d.mpp = &mpp;
    memset(d.our_privkey, 0x11, 32);
    d.pmgr = NULL; /* no peer manager — send guarded by peer_idx >= 0 */

    /* Build a minimal MSG_INVOICE_REQUEST (0x8001) with short payload */
    unsigned char msg[16];
    msg[0] = 0x80; msg[1] = 0x01; /* type 0x8001 */
    memset(msg + 2, 0, 14);       /* minimal payload — decode will fail */

    /* With invalid payload, dispatch sends invoice_error but must not crash */
    int rc = ln_dispatch_process_msg(&d, -1, msg, sizeof(msg));
    ASSERT(rc == (int)0x8001 || rc == 0, "invoice_request returns type or 0");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* IW5 — ln_dispatch type 135 (malformed HTLC): htlc_forward_fail     */
/* ================================================================== */
int test_ln_dispatch_malformed_htlc(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd; htlc_forward_init(&fwd);
    mpp_table_t mpp; mpp_init(&mpp);

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.ctx = ctx; d.fwd = &fwd; d.mpp = &mpp;
    memset(d.our_privkey, 0x11, 32);

    /* update_fail_malformed_htlc: type(2) + channel_id(32) + htlc_id(8) + sha256(32) + code(2) = 76 */
    unsigned char msg[76];
    msg[0] = 0x00; msg[1] = 135; /* type 135 */
    memset(msg + 2, 0, 74);

    int rc = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(rc == 135, "malformed HTLC returns type 135");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* IW6 — bad invoice_request TLV → invoice_error reply, no crash      */
/* ================================================================== */
int test_ln_dispatch_invoice_request_bad_sig(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd; htlc_forward_init(&fwd);
    mpp_table_t mpp; mpp_init(&mpp);

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.ctx = ctx; d.fwd = &fwd; d.mpp = &mpp;
    memset(d.our_privkey, 0x11, 32);
    d.pmgr = NULL;

    /* Build MSG_INVOICE_REQUEST with payer_key + sig (invalid sig) */
    unsigned char msg[200];
    msg[0] = 0x80; msg[1] = 0x01;
    size_t pos = 2;
    msg[pos++] = 0x00; msg[pos++] = 0x58; msg[pos++] = 0x00; msg[pos++] = 0x21;
    msg[pos++] = 0x02; memset(msg + pos, 0xAB, 32); pos += 32;
    msg[pos++] = 0x00; msg[pos++] = 0xF0; msg[pos++] = 0x00; msg[pos++] = 0x40;
    memset(msg + pos, 0x00, 64); pos += 64; /* invalid sig */

    int rc = ln_dispatch_process_msg(&d, -1, msg, pos);
    /* With invalid sig, verify fails → invoice_error sent (guarded by pmgr=NULL), no crash */
    ASSERT(rc == (int)0x8001 || rc == 0, "bad sig: returns type or 0, no crash");

    secp256k1_context_destroy(ctx);
    return 1;
}
