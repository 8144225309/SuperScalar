/*
 * test_invoice.c — Unit tests for the invoice creation and receivability module
 *
 * IV1: invoice_create → bolt11_decode roundtrip (payment_hash matches)
 * IV2: invoice_claim  returns correct preimage for matching hash+amount
 * IV3: invoice_claim  returns 0 for under-payment (amount < invoice amount)
 * IV4: second invoice_claim returns 0 after first claim (no double-redeem)
 * IV5: expired invoice rejected by claim
 * IV6: invoice_settle marks invoice as settled
 * IV7: invoice_create fills table → INVOICE_TABLE_MAX limit enforced
 */

#include "superscalar/invoice.h"
#include "superscalar/stateless_invoice.h"
#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
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

static secp256k1_context *g_ctx = NULL;
static unsigned char g_privkey[32];

static void iv_setup(void)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                          SECP256K1_CONTEXT_VERIFY);
        memset(g_privkey, 0x55, 32);
    }
}

/* ================================================================== */
/* IV1 — invoice_create → bolt11_decode roundtrip                     */
/* ================================================================== */
int test_invoice_create_decode(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           50000, "Test invoice", 3600, bech32, sizeof(bech32)),
           "invoice_create succeeds");
    ASSERT(strncmp(bech32, "lnbcrt", 6) == 0, "regtest prefix lnbcrt");

    /* Decode and verify payment_hash matches */
    bolt11_invoice_t decoded;
    ASSERT(bolt11_decode(g_ctx, bech32, &decoded), "bolt11_decode succeeds");
    ASSERT(decoded.amount_msat == 50000, "amount_msat matches");

    /* The table entry's payment_hash must match decoded payment_hash */
    int found = 0;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (!tbl.entries[i].active) continue;
        if (memcmp(tbl.entries[i].payment_hash, decoded.payment_hash, 32) == 0) {
            found = 1;
            /* Verify preimage hashes to payment_hash */
            unsigned char h[32];
            sha256(tbl.entries[i].preimage, 32, h);
            ASSERT(memcmp(h, decoded.payment_hash, 32) == 0,
                   "preimage hashes to payment_hash");
            break;
        }
    }
    ASSERT(found, "table entry found for decoded payment_hash");

    return 1;
}

/* ================================================================== */
/* IV2 — invoice_claim returns correct preimage for matching payment  */
/* ================================================================== */
int test_invoice_claim_success(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           100000, "Pay me", 3600, bech32, sizeof(bech32)),
           "create");

    /* Find the entry to get the payment_hash */
    bolt11_invoice_entry_t *entry = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { entry = &tbl.entries[i]; break; }
    }
    ASSERT(entry != NULL, "entry exists");

    unsigned char preimage[32];
    ASSERT(invoice_claim(&tbl, entry->payment_hash, 100000, preimage),
           "claim succeeds");

    /* Verify preimage hashes to payment_hash */
    unsigned char h[32];
    sha256(preimage, 32, h);
    ASSERT(memcmp(h, entry->payment_hash, 32) == 0, "preimage is correct");

    return 1;
}

/* ================================================================== */
/* IV3 — invoice_claim returns 0 for under-payment                    */
/* ================================================================== */
int test_invoice_claim_underpay(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           100000, "Underpay test", 3600, bech32, sizeof(bech32)),
           "create");

    bolt11_invoice_entry_t *entry = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { entry = &tbl.entries[i]; break; }
    }
    ASSERT(entry != NULL, "entry exists");

    unsigned char preimage[32];
    /* Pay only 99999 msat (1 less than required) */
    ASSERT(!invoice_claim(&tbl, entry->payment_hash, 99999, preimage),
           "underpayment rejected");
    ASSERT(!entry->settled, "invoice not settled after rejection");

    return 1;
}

/* ================================================================== */
/* IV4 — second claim returns 0 (no double-redeem)                    */
/* ================================================================== */
int test_invoice_claim_double(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           5000, "Double claim test", 3600, bech32, sizeof(bech32)),
           "create");

    bolt11_invoice_entry_t *entry = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { entry = &tbl.entries[i]; break; }
    }
    ASSERT(entry != NULL, "entry");

    unsigned char preimage[32];
    ASSERT(invoice_claim(&tbl, entry->payment_hash, 5000, preimage),
           "first claim succeeds");
    ASSERT(!invoice_claim(&tbl, entry->payment_hash, 5000, preimage),
           "second claim rejected");

    return 1;
}

/* ================================================================== */
/* IV5 — expired invoice rejected by claim                            */
/* ================================================================== */
int test_invoice_claim_expired(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           1000, "Expires fast", 1 /* 1 second expiry */,
                           bech32, sizeof(bech32)),
           "create");

    bolt11_invoice_entry_t *entry = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { entry = &tbl.entries[i]; break; }
    }
    ASSERT(entry != NULL, "entry");

    /* Force expiry by backdating created_at by 2 seconds */
    entry->created_at -= 2;

    unsigned char preimage[32];
    ASSERT(!invoice_claim(&tbl, entry->payment_hash, 1000, preimage),
           "expired invoice rejected");

    return 1;
}

/* ================================================================== */
/* IV6 — invoice_settle marks settled without claim                   */
/* ================================================================== */
int test_invoice_settle(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           2000, "Settle test", 3600, bech32, sizeof(bech32)),
           "create");

    bolt11_invoice_entry_t *entry = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { entry = &tbl.entries[i]; break; }
    }
    ASSERT(entry != NULL, "entry");
    ASSERT(!entry->settled, "not settled before settle");

    invoice_settle(&tbl, entry->payment_hash);
    ASSERT(entry->settled, "settled after invoice_settle");

    unsigned char preimage[32];
    ASSERT(!invoice_claim(&tbl, entry->payment_hash, 2000, preimage),
           "claim after settle rejected");

    return 1;
}

/* ================================================================== */
/* IV7 — any-amount invoice accepts any positive amount               */
/* ================================================================== */
int test_invoice_any_amount(void)
{
    iv_setup();

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    /* amount_msat = 0 → any-amount invoice */
    ASSERT(invoice_create(&tbl, g_ctx, g_privkey, "regtest",
                           0, "Any amount", 3600, bech32, sizeof(bech32)),
           "create any-amount");

    bolt11_invoice_entry_t *entry = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { entry = &tbl.entries[i]; break; }
    }
    ASSERT(entry != NULL, "entry");
    ASSERT(entry->amount_msat == 0, "amount_msat is 0");

    unsigned char preimage[32];
    /* Any non-zero amount should be accepted */
    ASSERT(invoice_claim(&tbl, entry->payment_hash, 1, preimage),
           "any-amount invoice accepts 1 msat");

    return 1;
}


/* ================================================================== */
/* SI_W1 — invoice_create: payment_secret == derived HMAC secret     */
/* ================================================================== */
int test_stateless_invoice_secret_derived(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x42, 32);

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, ctx, node_priv, "regtest",
                           5000, "SI_W1 test", 3600, bech32, sizeof(bech32)),
           "SI_W1: create");

    bolt11_invoice_entry_t *e = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { e = &tbl.entries[i]; break; }
    }
    ASSERT(e != NULL, "SI_W1: entry exists");

    /* Verify payment_secret == HMAC(node_priv, payment_hash) */
    unsigned char expected[32];
    stateless_invoice_derive_secret(node_priv, e->payment_hash, expected);
    ASSERT(memcmp(e->payment_secret, expected, 32) == 0,
           "SI_W1: payment_secret is HMAC-derived");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* SI_W2 — two different payment_hashes → different secrets          */
/* ================================================================== */
int test_stateless_invoice_secrets_differ(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x77, 32);

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char b1[1024], b2[1024];
    ASSERT(invoice_create(&tbl, ctx, node_priv, "regtest",
                           1000, "inv1", 3600, b1, sizeof(b1)), "create 1");
    ASSERT(invoice_create(&tbl, ctx, node_priv, "regtest",
                           2000, "inv2", 3600, b2, sizeof(b2)), "create 2");

    bolt11_invoice_entry_t *e1 = NULL, *e2 = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) {
            if (!e1) e1 = &tbl.entries[i];
            else if (!e2) { e2 = &tbl.entries[i]; break; }
        }
    }
    ASSERT(e1 && e2, "SI_W2: two entries");
    /* Different preimages → different payment_hashes → different secrets */
    ASSERT(memcmp(e1->payment_secret, e2->payment_secret, 32) != 0,
           "SI_W2: secrets differ");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* SI_W3 — same node_key + payment_hash → deterministic secret       */
/* ================================================================== */
int test_stateless_invoice_secret_deterministic(void)
{
    unsigned char node_priv[32]; memset(node_priv, 0x55, 32);
    unsigned char phash[32];     memset(phash,     0xAB, 32);

    unsigned char s1[32], s2[32];
    stateless_invoice_derive_secret(node_priv, phash, s1);
    stateless_invoice_derive_secret(node_priv, phash, s2);

    ASSERT(memcmp(s1, s2, 32) == 0, "SI_W3: deterministic");
    return 1;
}

/* ================================================================== */
/* SI_W4 — correct presented secret → verify returns 1               */
/* ================================================================== */
int test_stateless_invoice_verify_correct(void)
{
    unsigned char node_priv[32]; memset(node_priv, 0x33, 32);
    unsigned char phash[32];     memset(phash,     0xCC, 32);

    unsigned char secret[32];
    stateless_invoice_derive_secret(node_priv, phash, secret);

    int ok = stateless_invoice_verify_secret(node_priv, phash, secret);
    ASSERT(ok == 1, "SI_W4: correct secret verifies");
    return 1;
}

/* ================================================================== */
/* SI_W5 — wrong presented secret → verify returns 0, no crash       */
/* ================================================================== */
int test_stateless_invoice_verify_wrong(void)
{
    unsigned char node_priv[32]; memset(node_priv, 0x44, 32);
    unsigned char phash[32];     memset(phash,     0xDD, 32);

    unsigned char wrong[32]; memset(wrong, 0xFF, 32);
    int ok = stateless_invoice_verify_secret(node_priv, phash, wrong);
    ASSERT(ok == 0, "SI_W5: wrong secret rejected");
    return 1;
}

/* ================================================================== */
/* SL2_1 — invoice_create Level 2: has_stateless_preimage + nonce set */
/* ================================================================== */
int test_sl2_invoice_has_nonce(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x11, 32);

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, ctx, node_priv, "regtest",
                           10000, "SL2_1", 3600, bech32, sizeof(bech32)),
           "SL2_1: create");

    bolt11_invoice_entry_t *e = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { e = &tbl.entries[i]; break; }
    }
    ASSERT(e != NULL, "SL2_1: entry exists");
    ASSERT(e->has_stateless_preimage == 1, "SL2_1: has_stateless_preimage set");

    /* Nonce must be non-zero */
    unsigned char zero[32]; memset(zero, 0, 32);
    ASSERT(memcmp(e->stateless_nonce, zero, 32) != 0, "SL2_1: nonce non-zero");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* SL2_2 — nonce embedded in bolt11 metadata (type 27)               */
/* ================================================================== */
int test_sl2_nonce_in_metadata(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x22, 32);

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, ctx, node_priv, "regtest",
                           20000, "SL2_2", 3600, bech32, sizeof(bech32)),
           "SL2_2: create");

    bolt11_invoice_entry_t *e = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { e = &tbl.entries[i]; break; }
    }
    ASSERT(e != NULL, "SL2_2: entry");

    /* Decode and check metadata */
    bolt11_invoice_t decoded;
    ASSERT(bolt11_decode(ctx, bech32, &decoded), "SL2_2: decode");
    ASSERT(decoded.has_metadata, "SL2_2: has_metadata set in decoded invoice");
    ASSERT(decoded.metadata_len == 32, "SL2_2: metadata_len == 32");
    ASSERT(memcmp(decoded.metadata, e->stateless_nonce, 32) == 0,
           "SL2_2: decoded metadata matches stored nonce");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* SL2_3 — stateless_invoice_from_nonce: preimage hashes to hash     */
/* ================================================================== */
int test_sl2_from_nonce_check_preimage(void)
{
    unsigned char node_priv[32]; memset(node_priv, 0x33, 32);
    unsigned char nonce[32];     memset(nonce,     0xAA, 32);

    unsigned char phash[32], preimage[32], secret[32];
    ASSERT(stateless_invoice_from_nonce(node_priv, nonce, phash, preimage, secret),
           "SL2_3: from_nonce succeeds");

    ASSERT(stateless_invoice_check_preimage(phash, preimage),
           "SL2_3: preimage hashes to payment_hash");

    return 1;
}

/* ================================================================== */
/* SL2_4 — stateless_invoice_claim: correct secret → preimage OK     */
/* ================================================================== */
int test_sl2_claim_correct_secret(void)
{
    unsigned char node_priv[32]; memset(node_priv, 0x44, 32);
    unsigned char nonce[32];     memset(nonce,     0xBB, 32);

    unsigned char phash[32], preimage_expected[32], secret[32];
    ASSERT(stateless_invoice_from_nonce(node_priv, nonce, phash,
                                         preimage_expected, secret),
           "SL2_4: from_nonce");

    unsigned char preimage_out[32];
    ASSERT(stateless_invoice_claim(node_priv, nonce, phash, secret, preimage_out),
           "SL2_4: claim with correct secret");
    ASSERT(memcmp(preimage_out, preimage_expected, 32) == 0,
           "SL2_4: claimed preimage matches expected");
    ASSERT(stateless_invoice_check_preimage(phash, preimage_out),
           "SL2_4: claimed preimage hashes to payment_hash");

    return 1;
}

/* ================================================================== */
/* SL2_5 — stateless_invoice_claim: wrong secret → returns 0         */
/* ================================================================== */
int test_sl2_claim_wrong_secret(void)
{
    unsigned char node_priv[32]; memset(node_priv, 0x55, 32);
    unsigned char nonce[32];     memset(nonce,     0xCC, 32);

    unsigned char phash[32], preimage[32], secret[32];
    ASSERT(stateless_invoice_from_nonce(node_priv, nonce, phash, preimage, secret),
           "SL2_5: from_nonce");

    unsigned char wrong_secret[32]; memset(wrong_secret, 0xFF, 32);
    unsigned char preimage_out[32];
    ASSERT(!stateless_invoice_claim(node_priv, nonce, phash,
                                     wrong_secret, preimage_out),
           "SL2_5: wrong secret rejected");

    return 1;
}

/* ================================================================== */
/* SL2_6 — end-to-end: invoice_create Level2 → stateless_invoice_claim */
/* ================================================================== */
int test_sl2_end_to_end(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x66, 32);

    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    char bech32[1024];
    ASSERT(invoice_create(&tbl, ctx, node_priv, "regtest",
                           30000, "SL2_6", 3600, bech32, sizeof(bech32)),
           "SL2_6: create");

    bolt11_invoice_entry_t *e = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (tbl.entries[i].active) { e = &tbl.entries[i]; break; }
    }
    ASSERT(e != NULL, "SL2_6: entry");
    ASSERT(e->has_stateless_preimage, "SL2_6: Level 2 flag set");

    /* Simulate payer: use nonce + correct payment_secret to claim */
    unsigned char preimage_out[32];
    ASSERT(stateless_invoice_claim(node_priv, e->stateless_nonce,
                                    e->payment_hash, e->payment_secret,
                                    preimage_out),
           "SL2_6: stateless_invoice_claim succeeds");

    /* Verify preimage hashes to payment_hash */
    ASSERT(stateless_invoice_check_preimage(e->payment_hash, preimage_out),
           "SL2_6: preimage valid");

    secp256k1_context_destroy(ctx);
    return 1;
}
