/*
 * test_bolt11.c — Unit tests for BOLT #11 invoice decode/encode
 */

#include "superscalar/bolt11.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
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

/* ---- Test B1: decode known good invoice ---- */
int test_bolt11_decode_known(void)
{
    /* Minimal lnbcrt invoice (regtest, any amount, known payment_hash) */
    /* This is a synthetically-constructed invoice for unit testing */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    /* Build an invoice and then decode it to verify round-trip */
    unsigned char node_priv[32];
    memset(node_priv, 0x42, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 50000;
    inv.has_amount  = 1;
    inv.timestamp   = (uint32_t)time(NULL);
    inv.expiry      = 3600;
    memset(inv.payment_hash,   0xAB, 32);
    memset(inv.payment_secret, 0xCD, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "Test invoice");

    /* Encode */
    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "encode should succeed");
    ASSERT(strncmp(encoded, "lnbcrt", 6) == 0, "should start with lnbcrt");

    /* Decode */
    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "decode should succeed");
    ASSERT(strcmp(dec.network, "bcrt") == 0, "network matches");
    ASSERT(dec.amount_msat == 50000, "amount matches");
    ASSERT(dec.has_amount, "has_amount flag");
    ASSERT(memcmp(dec.payment_hash, inv.payment_hash, 32) == 0, "payment_hash matches");
    ASSERT(dec.has_payment_secret, "has_payment_secret flag");
    ASSERT(memcmp(dec.payment_secret, inv.payment_secret, 32) == 0,
           "payment_secret matches");
    ASSERT(strcmp(dec.description, "Test invoice") == 0, "description matches");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test B2: zero-amount invoice ---- */
int test_bolt11_no_amount(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32];
    memset(node_priv, 0x33, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bs"); /* signet */
    inv.has_amount  = 0;
    inv.amount_msat = 0;
    inv.timestamp   = 1700000000;
    inv.expiry      = 7200;
    memset(inv.payment_hash,   0x11, 32);
    memset(inv.payment_secret, 0x22, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "Any amount");

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "encode no-amount");
    ASSERT(strncmp(encoded, "lnbs1", 5) == 0, "signet prefix");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "decode no-amount");
    ASSERT(!dec.has_amount || dec.amount_msat == 0, "no amount in decoded");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test B3: route hints round-trip ---- */
int test_bolt11_route_hints(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32];
    memset(node_priv, 0x77, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bc");
    inv.amount_msat = 1000000; /* 1 sat */
    inv.has_amount  = 1;
    inv.timestamp   = 1700000000;
    memset(inv.payment_hash,   0xCC, 32);
    memset(inv.payment_secret, 0xDD, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "With hint");

    /* Add one route hint with one hop */
    inv.n_hints = 1;
    inv.hints[0].n_hops = 1;
    memset(inv.hints[0].hops[0].pubkey, 0x02, 33);
    inv.hints[0].hops[0].short_channel_id = 0x0001000000000001ULL;
    inv.hints[0].hops[0].fee_base_msat    = 1000;
    inv.hints[0].hops[0].fee_ppm          = 100;
    inv.hints[0].hops[0].cltv_expiry_delta = 40;

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "encode with hint");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "decode with hint");
    ASSERT(dec.n_hints >= 1, "has route hint");
    ASSERT(dec.hints[0].n_hops >= 1, "hint has hops");
    ASSERT(dec.hints[0].hops[0].fee_base_msat == 1000, "fee_base matches");
    ASSERT(dec.hints[0].hops[0].fee_ppm == 100, "fee_ppm matches");
    ASSERT(dec.hints[0].hops[0].cltv_expiry_delta == 40, "cltv_delta matches");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test B4: invalid invoice rejected ---- */
int test_bolt11_invalid_rejected(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    bolt11_invoice_t dec;

    /* Totally invalid string */
    ASSERT(!bolt11_decode(ctx, "notaninvoice", &dec), "invalid string rejected");

    /* Too short */
    ASSERT(!bolt11_decode(ctx, "lnbc1", &dec), "too short rejected");

    /* Truncated */
    ASSERT(!bolt11_decode(ctx, "lnbc10m1pvjluezpp5", &dec), "truncated rejected");

    secp256k1_context_destroy(ctx);
    return 1;
}


/* ================================================================== */
/* M1 — metadata round-trip encode/decode                             */
/* ================================================================== */
int test_bolt11_metadata_roundtrip(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x42, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 1000000;
    inv.has_amount  = 1;
    inv.timestamp   = 1700000000;
    memset(inv.payment_hash,   0xAA, 32);
    memset(inv.payment_secret, 0xBB, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "metadata test");

    /* Set metadata */
    inv.metadata[0] = 0x01; inv.metadata[1] = 0x02;
    inv.metadata[2] = 0x03; inv.metadata[3] = 0x04;
    inv.metadata_len = 4;
    inv.has_metadata = 1;

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M1: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M1: decode");
    ASSERT(dec.has_metadata,           "M1: has_metadata=1");
    ASSERT(dec.metadata_len == 4,      "M1: metadata_len=4");
    ASSERT(dec.metadata[0] == 0x01,    "M1: metadata[0]");
    ASSERT(dec.metadata[3] == 0x04,    "M1: metadata[3]");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* M2 — no metadata: has_metadata=0, no crash                        */
/* ================================================================== */
int test_bolt11_no_metadata(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x55, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 500; inv.has_amount = 1;
    inv.timestamp = 1700000001;
    memset(inv.payment_hash,   0xCC, 32);
    memset(inv.payment_secret, 0xDD, 32);
    inv.has_payment_secret = 1;
    inv.has_metadata = 0; /* no metadata */
    strcpy(inv.description, "no meta");

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M2: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M2: decode");
    ASSERT(!dec.has_metadata, "M2: has_metadata=0");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* M3 — metadata_len truncated to 64 on decode                       */
/* ================================================================== */
int test_bolt11_metadata_truncated(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x66, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 1000; inv.has_amount = 1;
    inv.timestamp = 1700000002;
    memset(inv.payment_hash,   0xEE, 32);
    memset(inv.payment_secret, 0xFF, 32);
    inv.has_payment_secret = 1;
    /* 64 bytes metadata (max) */
    memset(inv.metadata, 0x11, 64);
    inv.metadata_len = 64;
    inv.has_metadata = 1;
    strcpy(inv.description, "max meta");

    char encoded[4096];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M3: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M3: decode");
    ASSERT(dec.has_metadata,      "M3: has_metadata");
    ASSERT(dec.metadata_len <= 64, "M3: truncated to 64");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* M4 — full round-trip with all fields including metadata            */
/* ================================================================== */
int test_bolt11_full_roundtrip_with_metadata(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x77, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bc");
    inv.amount_msat = 2000000; inv.has_amount = 1;
    inv.timestamp = 1700000003;
    memset(inv.payment_hash,   0x12, 32);
    memset(inv.payment_secret, 0x34, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "full roundtrip");
    inv.expiry = 7200;
    inv.min_final_cltv_expiry = 40;
    /* metadata */
    inv.metadata[0] = 0xDE; inv.metadata[1] = 0xAD;
    inv.metadata[2] = 0xBE; inv.metadata[3] = 0xEF;
    inv.metadata_len = 4; inv.has_metadata = 1;

    char encoded[4096];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M4: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M4: decode");
    ASSERT(dec.amount_msat == 2000000,       "M4: amount");
    ASSERT(dec.has_payment_secret,           "M4: has_payment_secret");
    ASSERT(dec.has_metadata,                 "M4: has_metadata");
    ASSERT(dec.metadata[0] == 0xDE,          "M4: metadata[0]");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Published BOLT #11 example invoices decode to their stated values ---- */
int test_bolt11_spec_vectors(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    static const unsigned char spec_hash[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,0x08,0x09,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x01,0x02 };

    /* "Please send $3 for a cup of coffee to the same peer, within one
       minute": 2500 micro-BTC, expiry 60 seconds. */
    bolt11_invoice_t dec;
    memset(&dec, 0, sizeof(dec));
    ASSERT(bolt11_decode(ctx,
        "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
        "zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxat"
        "syp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh"
        "8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh",
        &dec), "coffee invoice decodes");
    ASSERT(strcmp(dec.network, "bc") == 0, "coffee: mainnet");
    ASSERT(dec.has_amount, "coffee: has amount");
    ASSERT(dec.amount_msat == 250000000ULL, "coffee: 2500u = 250,000,000 msat");
    ASSERT(dec.timestamp == 1496314658, "coffee: timestamp");
    ASSERT(dec.expiry == 60, "coffee: x field is the expiry");
    ASSERT(dec.min_final_cltv_expiry == 18, "coffee: default min_final_cltv");
    ASSERT(memcmp(dec.payment_hash, spec_hash, 32) == 0, "coffee: payment hash");

    /* "Please make a donation of any amount": no amount, default expiry. */
    memset(&dec, 0, sizeof(dec));
    ASSERT(bolt11_decode(ctx,
        "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs"
        "pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5s"
        "xxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ue"
        "h7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt"
        "8r2t7mlcwspyetp5h2tztugp9lfyql",
        &dec), "donation invoice decodes");
    ASSERT(!dec.has_amount && dec.amount_msat == 0, "donation: no amount");
    ASSERT(dec.expiry == 3600, "donation: default expiry");
    ASSERT(memcmp(dec.payment_hash, spec_hash, 32) == 0, "donation: payment hash");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Amount units, expiry and min_final_cltv survive encode/decode ---- */
int test_bolt11_amount_units_and_fields(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char node_priv[32]; memset(node_priv, 0x51, 32);

    static const struct { uint64_t msat; const char *prefix; } cases[] = {
        { 250000000ULL, "lnbc2500u1" },   /* 250,000 sat */
        { 100000000ULL, "lnbc1m1"    },   /* 0.001 BTC   */
        { 4000000ULL,   "lnbc40u1"   },   /* 4,000 sat   */
        { 1000ULL,      "lnbc10n1"   },   /* 1 sat       */
        { 1ULL,         "lnbc10p1"   },   /* 1 msat      */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bolt11_invoice_t inv;
        memset(&inv, 0, sizeof(inv));
        strcpy(inv.network, "bc");
        inv.amount_msat = cases[i].msat; inv.has_amount = 1;
        inv.timestamp = 1700000100;
        memset(inv.payment_hash, 0x21, 32);
        memset(inv.payment_secret, 0x22, 32);
        inv.has_payment_secret = 1;
        strcpy(inv.description, "units");
        inv.expiry = 900;
        inv.min_final_cltv_expiry = 144;

        char enc[2048];
        ASSERT(bolt11_encode(&inv, node_priv, ctx, enc, sizeof(enc)), "encode");
        ASSERT(strncmp(enc, cases[i].prefix, strlen(cases[i].prefix)) == 0,
               "amount written in BOLT #11 units");

        bolt11_invoice_t dec;
        memset(&dec, 0, sizeof(dec));
        ASSERT(bolt11_decode(ctx, enc, &dec), "decode");
        ASSERT(dec.has_amount && dec.amount_msat == cases[i].msat,
               "amount round-trips");
        ASSERT(dec.expiry == 900, "expiry round-trips");
        ASSERT(dec.min_final_cltv_expiry == 144, "min_final_cltv round-trips");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}
