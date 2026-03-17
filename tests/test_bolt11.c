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
