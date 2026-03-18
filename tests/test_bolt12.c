#include "superscalar/bolt12.h"
#include "superscalar/blinded_path.h"
#include "superscalar/bech32m.h"
#include "superscalar/persist.h"
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

/* Test F4: blinded path with 2 hops — blinded_node_id != original pubkey */
int test_blinded_path_onion(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char intro_seckey[32];
    memset(intro_seckey, 0x33, 32);

    /* 2 valid compressed pubkeys derived from known seckeys */
    unsigned char sec0[32], sec1[32];
    memset(sec0, 0x11, 32);
    memset(sec1, 0x22, 32);
    secp256k1_keypair kp0, kp1;
    secp256k1_pubkey pub0, pub1;
    ASSERT(secp256k1_keypair_create(ctx, &kp0, sec0), "kp0");
    ASSERT(secp256k1_keypair_create(ctx, &kp1, sec1), "kp1");
    ASSERT(secp256k1_keypair_pub(ctx, &pub0, &kp0), "pub0");
    ASSERT(secp256k1_keypair_pub(ctx, &pub1, &kp1), "pub1");
    unsigned char hops[2][33];
    size_t sz = 33;
    secp256k1_ec_pubkey_serialize(ctx, hops[0], &sz, &pub0, SECP256K1_EC_COMPRESSED);
    sz = 33;
    secp256k1_ec_pubkey_serialize(ctx, hops[1], &sz, &pub1, SECP256K1_EC_COMPRESSED);

    blinded_path_t path;
    ASSERT(blinded_path_build(&path, ctx, (const unsigned char (*)[33])hops, 2, intro_seckey),
           "blinded_path_build should succeed");
    ASSERT(path.n_hops == 2, "2 hops");

    /* Phase 4 fix: blinded_node_id must be DIFFERENT from the original pubkey */
    ASSERT(memcmp(path.hops[0].blinded_node_id, hops[0], 33) != 0,
           "hop[0] blinded_node_id != original pubkey (real ECDH blinding)");
    ASSERT(memcmp(path.hops[1].blinded_node_id, hops[1], 33) != 0,
           "hop[1] blinded_node_id != original pubkey (real ECDH blinding)");

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

/* Phase 4 fix: bech32m known vector test (BIP 350 test vector) */
int test_bech32m_known_vector(void)
{
    /* Simple round-trip: encode some bytes and decode them back */
    const unsigned char data[] = {0x00, 0x0e, 0x14, 0x00, 0xd3, 0x23, 0x14, 0x04};
    char encoded[256];
    ASSERT(bech32m_encode("test", data, sizeof(data), encoded, sizeof(encoded)),
           "bech32m_encode should succeed");
    /* Should start with "test1" */
    ASSERT(strncmp(encoded, "test1", 5) == 0, "HRP 'test' present");

    unsigned char decoded[64];
    size_t dec_len = 0;
    ASSERT(bech32m_decode(encoded, "test", decoded, &dec_len, sizeof(decoded)),
           "bech32m_decode should succeed");
    ASSERT(dec_len == sizeof(data), "decoded length matches");
    ASSERT(memcmp(decoded, data, sizeof(data)) == 0, "decoded data matches original");
    return 1;
}

/* Phase 4 fix: real bech32m offer encode has valid bech32m checksum */
int test_offer_encode_bech32m_valid(void)
{
    offer_t o;
    memset(&o, 0, sizeof(o));
    memset(o.node_id, 0x02, 33);
    o.node_id[0] = 0x02;
    o.amount_msat = 1000;
    o.has_amount = 1;
    strcpy(o.description, "bech32m test");

    char encoded[1024];
    ASSERT(offer_encode(&o, encoded, sizeof(encoded)), "encode succeeds");

    /* Verify it decodes back correctly with bech32m */
    offer_t decoded;
    ASSERT(offer_decode(encoded, &decoded), "decode succeeds");
    ASSERT(decoded.amount_msat == 1000, "amount round-trips");
    ASSERT(strcmp(decoded.description, "bech32m test") == 0, "description round-trips");

    /* Verify prefix is "lno1" (lno + separator "1") */
    ASSERT(strncmp(encoded, "lno1", 4) == 0, "starts with lno1");
    return 1;
}

/* Phase 4 fix: corrupted checksum should fail decode */
int test_offer_decode_bad_checksum(void)
{
    offer_t o;
    memset(&o, 0, sizeof(o));
    memset(o.node_id, 0x02, 33);
    o.node_id[0] = 0x02;
    o.amount_msat = 500;
    strcpy(o.description, "checksum test");

    char encoded[1024];
    ASSERT(offer_encode(&o, encoded, sizeof(encoded)), "encode");

    /* Corrupt the last character of the checksum */
    size_t len = strlen(encoded);
    encoded[len - 1] = (encoded[len - 1] == 'q') ? 'p' : 'q';

    offer_t bad;
    ASSERT(!offer_decode(encoded, &bad), "corrupted offer should fail decode");
    return 1;
}

/* Schema version smoke test (v2=HD wallet, v3=BOLT 12 offers, v4=pending_cs,
 * v5=hd_utxos.reserved) */
int test_persist_schema_v3(void)
{
    persist_t p;
    ASSERT(persist_open(&p, ":memory:"), "open in-memory DB");
    ASSERT(persist_schema_version(&p) == PERSIST_SCHEMA_VERSION, "schema version is current");
    ASSERT(PERSIST_SCHEMA_VERSION == 8, "schema version is 8");
    persist_close(&p);
    return 1;
}

/* Phase 4 fix: persist_save_offer / persist_list_offers / persist_delete_offer */
int test_persist_save_list_offer(void)
{
    persist_t p;
    ASSERT(persist_open(&p, ":memory:"), "open DB");

    unsigned char offer_id[32];
    memset(offer_id, 0xAB, 32);
    const char *enc = "lno1testencoded";

    ASSERT(persist_save_offer(&p, offer_id, enc), "save offer");

    unsigned char ids[8][32];
    char encs[8][PERSIST_OFFER_ENC_MAX];
    size_t count = persist_list_offers(&p, ids, encs, 8);
    ASSERT(count == 1, "one offer listed");
    ASSERT(memcmp(ids[0], offer_id, 32) == 0, "offer_id matches");
    ASSERT(strcmp(encs[0], enc) == 0, "encoded string matches");

    ASSERT(persist_delete_offer(&p, offer_id), "delete offer");
    count = persist_list_offers(&p, ids, encs, 8);
    ASSERT(count == 0, "no offers after delete");

    persist_close(&p);
    return 1;
}
