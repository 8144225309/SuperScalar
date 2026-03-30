/*
 * invoice.c — BOLT #11 inbound payment invoice management
 *
 * Generates payment_hash/secret pairs, tracks pending invoices,
 * and redeems them when the final HTLC arrives.
 *
 * Reference: CLN lightningd/invoices.c, LND invoices/invoiceregistry.go
 */

#include "superscalar/invoice.h"
#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include "superscalar/stateless_invoice.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef __linux__
#include <sys/random.h>
#endif

/* ---- Portable random bytes ---- */
static void invoice_rand_bytes(unsigned char *buf, size_t len)
{
#ifdef __linux__
    ssize_t got = getrandom(buf, len, 0);
    if (got == (ssize_t)len) return;
#endif
    /* Fallback: use C stdlib rand (test-only quality, not for production) */
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(rand() & 0xFF);
}

void invoice_init(bolt11_invoice_table_t *tbl)
{
    if (!tbl) return;
    memset(tbl, 0, sizeof(*tbl));
}

int invoice_create(bolt11_invoice_table_t *tbl,
                   secp256k1_context *ctx,
                   const unsigned char node_privkey[32],
                   const char *network,
                   uint64_t amount_msat,
                   const char *description,
                   uint32_t expiry_secs,
                   char *bech32_out, size_t out_cap)
{
    if (!tbl || !ctx || !node_privkey || !network || !bech32_out) return 0;
    if (tbl->count >= INVOICE_TABLE_MAX) return 0;

    /* Find a free slot */
    int slot = -1;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        if (!tbl->entries[i].active) { slot = i; break; }
    }
    if (slot < 0) return 0;

    bolt11_invoice_entry_t *e = &tbl->entries[slot];
    memset(e, 0, sizeof(*e));

    /* Level 2 stateless: generate nonce, derive preimage + secret deterministically.
     * Nonce is embedded in invoice metadata (BOLT #11 type 27) so the receiver
     * can re-derive the preimage on demand without storing it. */
    if (!stateless_invoice_gen_nonce(e->stateless_nonce)) {
        /* /dev/urandom unavailable — fallback to rand() (test-only quality) */
        invoice_rand_bytes(e->stateless_nonce, 32);
    }
    if (!stateless_invoice_from_nonce(node_privkey, e->stateless_nonce,
                                      e->payment_hash, e->preimage,
                                      e->payment_secret)) {
        return 0;
    }
    e->has_stateless_secret   = 1;
    e->has_stateless_preimage = 1;

    e->amount_msat = amount_msat;
    e->created_at  = (uint32_t)time(NULL);
    e->expiry      = expiry_secs > 0 ? expiry_secs : 3600;
    e->settled     = 0;
    e->active      = 1;

    if (description) {
        strncpy(e->description, description, sizeof(e->description) - 1);
        e->description[sizeof(e->description) - 1] = '\0';
    }

    /* Build and encode the BOLT #11 invoice */
    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));

    /* Network prefix */
    const char *pfx = "bcrt";  /* default regtest */
    if (strcmp(network, "mainnet") == 0) pfx = "bc";
    else if (strcmp(network, "testnet") == 0) pfx = "tb";
    else if (strcmp(network, "signet") == 0)  pfx = "tbs";
    else if (strcmp(network, "testnet4") == 0) pfx = "tb";
    strncpy(inv.network, pfx, sizeof(inv.network) - 1);

    inv.amount_msat = amount_msat;
    inv.has_amount  = (amount_msat > 0);
    inv.timestamp   = e->created_at;
    inv.expiry      = e->expiry;
    inv.min_final_cltv_expiry = 18;
    memcpy(inv.payment_hash,   e->payment_hash,   32);
    memcpy(inv.payment_secret, e->payment_secret, 32);
    inv.has_payment_secret = 1;

    /* Level 2: embed nonce in BOLT #11 metadata (tagged field type 27) */
    memcpy(inv.metadata, e->stateless_nonce, 32);
    inv.metadata_len = 32;
    inv.has_metadata = 1;

    if (description) {
        strncpy(inv.description, description,
                sizeof(inv.description) - 1);
    }

    /* Mandatory BOLT #11 v1.1 features */
    inv.features = (1 << BOLT11_FEATURE_PAYMENT_SECRET);

    if (!bolt11_encode(&inv, node_privkey, ctx, bech32_out, out_cap)) {
        e->active = 0;
        return 0;
    }

    tbl->count++;
    return 1;
}

int invoice_create_with_hint(bolt11_invoice_table_t *tbl,
                              secp256k1_context *ctx,
                              const unsigned char node_privkey[32],
                              const char *network,
                              uint64_t amount_msat,
                              const char *description,
                              uint32_t expiry_secs,
                              const unsigned char *hint_pubkey,
                              uint64_t hint_scid,
                              uint32_t hint_fee_base,
                              uint32_t hint_fee_ppm,
                              uint16_t hint_cltv_delta,
                              char *bech32_out, size_t out_cap)
{
    /* Create the base invoice first (without hint) into a temp buffer */
    char tmp[512];
    if (!invoice_create(tbl, ctx, node_privkey, network, amount_msat,
                        description, expiry_secs, tmp, sizeof(tmp)))
        return 0;

    /* If no hint requested, just copy and return */
    if (!hint_pubkey) {
        strncpy(bech32_out, tmp, out_cap - 1);
        bech32_out[out_cap - 1] = '\0';
        return 1;
    }

    /* Undo: decrement count since invoice_create already incremented it.
       We'll re-encode with the hint and the count stays correct. */
    tbl->count--;

    /* Find the entry that was just created (last active slot) */
    bolt11_invoice_entry_t *e2 = NULL;
    for (int i = INVOICE_TABLE_MAX - 1; i >= 0; i--) {
        if (tbl->entries[i].active) { e2 = &tbl->entries[i]; break; }
    }
    if (!e2) return 0;

    /* Build invoice struct directly with hint included */
    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    const char *pfx2 = "bcrt";
    if (strcmp(network, "mainnet") == 0) pfx2 = "bc";
    else if (strcmp(network, "testnet") == 0) pfx2 = "tb";
    else if (strcmp(network, "signet") == 0) pfx2 = "tbs";
    else if (strcmp(network, "testnet4") == 0) pfx2 = "tb";
    strncpy(inv.network, pfx2, sizeof(inv.network) - 1);
    inv.amount_msat = amount_msat;
    inv.has_amount = (amount_msat > 0);
    inv.timestamp = e2->created_at;
    inv.expiry = e2->expiry;
    inv.min_final_cltv_expiry = 18;
    memcpy(inv.payment_hash, e2->payment_hash, 32);
    memcpy(inv.payment_secret, e2->payment_secret, 32);
    inv.has_payment_secret = 1;
    memcpy(inv.metadata, e2->stateless_nonce, 32);
    inv.metadata_len = 32;
    inv.has_metadata = 1;
    if (description)
        strncpy(inv.description, description, sizeof(inv.description) - 1);
    inv.features = (1 << BOLT11_FEATURE_PAYMENT_SECRET);

    /* Add route hint */
    bolt11_route_hint_t *h = &inv.hints[0];
    memcpy(h->hops[0].pubkey, hint_pubkey, 33);
    h->hops[0].short_channel_id = hint_scid;
    h->hops[0].fee_base_msat = hint_fee_base;
    h->hops[0].fee_ppm = hint_fee_ppm;
    h->hops[0].cltv_expiry_delta = hint_cltv_delta;
    h->n_hops = 1;
    inv.n_hints = 1;

    if (!bolt11_encode(&inv, node_privkey, ctx, bech32_out, out_cap)) {
        e2->active = 0;
        return 0;
    }
    tbl->count++;
    return 1;
}

int invoice_claim(bolt11_invoice_table_t *tbl,
                  const unsigned char payment_hash[32],
                  uint64_t amount_msat,
                  unsigned char preimage_out[32])
{
    if (!tbl || !payment_hash || !preimage_out) return 0;

    uint32_t now = (uint32_t)time(NULL);

    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        bolt11_invoice_entry_t *e = &tbl->entries[i];
        if (!e->active) continue;
        if (memcmp(e->payment_hash, payment_hash, 32) != 0) continue;

        /* Already settled → reject double-claim */
        if (e->settled) return 0;

        /* Expired → reject */
        if (now >= e->created_at + e->expiry) return 0;

        /* Underpayment → reject (unless any-amount invoice) */
        if (e->amount_msat > 0 && amount_msat < e->amount_msat) return 0;

        /* Success */
        memcpy(preimage_out, e->preimage, 32);
        e->settled = 1;
        return 1;
    }

    return 0;  /* not found */
}

void invoice_settle(bolt11_invoice_table_t *tbl, const unsigned char payment_hash[32])
{
    if (!tbl || !payment_hash) return;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        bolt11_invoice_entry_t *e = &tbl->entries[i];
        if (!e->active) continue;
        if (memcmp(e->payment_hash, payment_hash, 32) == 0) {
            e->settled = 1;
            return;
        }
    }
}
