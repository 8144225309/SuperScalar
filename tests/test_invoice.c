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
