/* Bridge/invoice support extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/htlc_inbound.h"
#include "superscalar/persist.h"
#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include "superscalar/readiness.h"
#include "superscalar/network.h"
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd) {
    mgr->bridge_fd = bridge_fd;
}

const char *lsp_channels_network(const lsp_channel_mgr_t *mgr) {
    if (!mgr) return NULL;
    if (mgr->network[0]) return mgr->network;
    if (mgr->watchtower && mgr->watchtower->rt &&
        mgr->watchtower->rt->network[0])
        return mgr->watchtower->rt->network;
    return NULL;
}

uint32_t lsp_channels_chain_height(const lsp_channel_mgr_t *mgr) {
    if (!mgr) return 0;
    if (mgr->chain_be) {
        chain_backend_t *be = (chain_backend_t *)mgr->chain_be;
        int h = be->get_block_height ? be->get_block_height(be) : -1;
        if (h > 0) return (uint32_t)h;
    }
    if (mgr->watchtower && mgr->watchtower->rt) {
        int h = regtest_get_block_height(mgr->watchtower->rt);
        if (h > 0) return (uint32_t)h;
    }
    return 0;
}

/* --- Outbound invoice checks --- */

const char *lsp_bridge_pay_check_str(bridge_pay_check_t r) {
    switch (r) {
    case BRIDGE_PAY_OK:                 return "ok";
    case BRIDGE_PAY_BAD_INVOICE:        return "invalid_invoice";
    case BRIDGE_PAY_WRONG_NETWORK:      return "invoice_wrong_network";
    case BRIDGE_PAY_HASH_MISMATCH:      return "invoice_payment_hash_mismatch";
    case BRIDGE_PAY_NO_AMOUNT:          return "invoice_without_amount";
    case BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC: return "invoice_amount_exceeds_htlc";
    case BRIDGE_PAY_EXPIRED:            return "invoice_expired";
    case BRIDGE_PAY_NO_CHAIN_HEIGHT:    return "chain_height_unavailable";
    case BRIDGE_PAY_CLTV_OUT_OF_BOUNDS: return "cltv_expiry_out_of_bounds";
    }
    return "invalid_invoice";
}

int lsp_bridge_invoice_network_ok(const char *network, const char *invoice_hrp) {
    /* "bitcoin" and "mainnet" name the same chain */
    network = network_canonical(network);
    if (!network || !invoice_hrp) return 0;
    if (network_is_mainnet(network))
        return strcmp(invoice_hrp, "bc") == 0;
    if (strcmp(network, "testnet") == 0 || strcmp(network, "testnet4") == 0)
        return strcmp(invoice_hrp, "tb") == 0;
    if (strcmp(network, "signet") == 0)
        return strcmp(invoice_hrp, "tbs") == 0;
    if (strcmp(network, "regtest") == 0)
        return strcmp(invoice_hrp, "bcrt") == 0;
    return 0;
}

uint64_t lsp_bridge_outbound_budget_msat(uint64_t htlc_amount_sats,
                                           uint64_t routing_fee_ppm) {
    if (htlc_amount_sats > UINT64_MAX / 1000) return 0;
    if (routing_fee_ppm >= 1000000) return 0;
    uint64_t amount_msat = htlc_amount_sats * 1000;
    /* ceil(amount_msat * ppm / 10^6) without overflowing 64 bits */
    uint64_t fee_msat = (amount_msat / 1000000) * routing_fee_ppm +
        ((amount_msat % 1000000) * routing_fee_ppm + 999999) / 1000000;
    if (fee_msat >= amount_msat) return 0;
    return amount_msat - fee_msat;
}

bridge_pay_check_t lsp_bridge_check_outbound_invoice(
    secp256k1_context *ctx, const char *bolt11,
    const unsigned char *htlc_payment_hash32, uint64_t htlc_amount_sats,
    uint64_t routing_fee_ppm, const char *network, uint64_t now,
    uint64_t *invoice_msat_out, uint64_t *budget_msat_out,
    uint32_t *min_final_cltv_out) {
    if (!ctx || !bolt11 || !htlc_payment_hash32)
        return BRIDGE_PAY_BAD_INVOICE;

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    if (!bolt11_decode(ctx, bolt11, &inv))
        return BRIDGE_PAY_BAD_INVOICE;

    if (!lsp_bridge_invoice_network_ok(network, inv.network))
        return BRIDGE_PAY_WRONG_NETWORK;

    /* The client's HTLC only pays the LSP back if the outside payment
       releases the preimage of this exact hash. */
    if (memcmp(inv.payment_hash, htlc_payment_hash32, 32) != 0)
        return BRIDGE_PAY_HASH_MISMATCH;

    /* An amountless invoice lets the payer choose the amount, so there is
       nothing to bound the spend with. */
    if (!inv.has_amount || inv.amount_msat == 0)
        return BRIDGE_PAY_NO_AMOUNT;

    uint64_t budget = lsp_bridge_outbound_budget_msat(htlc_amount_sats,
                                                        routing_fee_ppm);
    if (inv.amount_msat > budget)
        return BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC;

    if (now >= (uint64_t)inv.timestamp + (uint64_t)inv.expiry)
        return BRIDGE_PAY_EXPIRED;

    if (invoice_msat_out) *invoice_msat_out = inv.amount_msat;
    if (budget_msat_out) *budget_msat_out = budget;
    if (min_final_cltv_out)
        *min_final_cltv_out = inv.min_final_cltv_expiry > 0
            ? (uint32_t)inv.min_final_cltv_expiry : 0;
    return BRIDGE_PAY_OK;
}

bridge_pay_check_t lsp_bridge_outbound_max_delay(uint32_t htlc_cltv_expiry,
                                                  uint32_t current_height,
                                                  uint32_t min_final_cltv,
                                                  uint32_t forward_margin,
                                                  uint32_t factory_cltv_timeout,
                                                  uint32_t *max_delay_out) {
    /* Without the tip there is nothing to measure the expiry against. */
    if (current_height == 0)
        return BRIDGE_PAY_NO_CHAIN_HEIGHT;
    if (forward_margin == 0) forward_margin = FACTORY_CLTV_DELTA_DEFAULT;

    /* Earliest height the final hop may demand; it must still leave the
       forwarding margin before the client's HTLC expires. */
    uint64_t final_hop = (uint64_t)current_height + min_final_cltv;
    if (final_hop > UINT32_MAX)
        return BRIDGE_PAY_CLTV_OUT_OF_BOUNDS;
    uint32_t settle_by;   /* htlc_cltv_expiry - forward_margin */
    if (!lsp_validate_cltv_for_forward(htlc_cltv_expiry, &settle_by,
                                        factory_cltv_timeout, forward_margin,
                                        (uint32_t)final_hop))
        return BRIDGE_PAY_CLTV_OUT_OF_BOUNDS;

    if (max_delay_out) *max_delay_out = settle_by - current_height;
    return BRIDGE_PAY_OK;
}

/* Routing-fee allowance for operator-initiated pays: 0.5% of the invoice,
   at least 5 sat (Core Lightning's own `pay` defaults). */
#define OPERATOR_PAY_FEE_PPM        5000
#define OPERATOR_PAY_FEE_FLOOR_MSAT 5000

int lsp_channels_operator_pay(lsp_channel_mgr_t *mgr, const char *bolt11,
                               uint64_t *request_id_out, const char **err_out) {
    const char *err = NULL;
    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    if (!mgr || !bolt11)
        err = "missing invoice";
    else if (mgr->bridge_fd < 0)
        err = "bridge not connected";
    else if (!bolt11_decode(mgr->ctx, bolt11, &inv))
        err = "invalid_invoice";
    else if (!lsp_bridge_invoice_network_ok(lsp_channels_network(mgr),
                                             inv.network))
        err = "invoice_wrong_network";
    else if (!inv.has_amount || inv.amount_msat == 0)
        err = "invoice_without_amount";
    else if ((uint64_t)time(NULL) >=
             (uint64_t)inv.timestamp + (uint64_t)inv.expiry)
        err = "invoice_expired";
    if (err) {
        if (err_out) *err_out = err;
        return 0;
    }

    uint64_t fee_allow = inv.amount_msat / 1000000 * OPERATOR_PAY_FEE_PPM +
        (inv.amount_msat % 1000000) * OPERATOR_PAY_FEE_PPM / 1000000;
    if (fee_allow < OPERATOR_PAY_FEE_FLOOR_MSAT)
        fee_allow = OPERATOR_PAY_FEE_FLOOR_MSAT;

    uint64_t request_id = mgr->next_request_id++;
    cJSON *pay = wire_build_bridge_send_pay(bolt11, inv.payment_hash,
                                              request_id,
                                              inv.amount_msat + fee_allow,
                                              LSP_BRIDGE_OPERATOR_MAX_DELAY);
    int ok = pay && wire_send(mgr->bridge_fd, MSG_BRIDGE_SEND_PAY, pay);
    if (pay) cJSON_Delete(pay);
    if (mgr->persist)
        persist_save_counter((persist_t *)mgr->persist,
                              "next_request_id", mgr->next_request_id);
    if (!ok) {
        if (err_out) *err_out = "bridge send failed";
        return 0;
    }
    if (request_id_out) *request_id_out = request_id;
    return 1;
}

int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    const unsigned char *preimage32,
                                    size_t dest_client, uint64_t amount_msat) {
    if (dest_client >= mgr->n_channels) return 0;
    /* One use per payment hash: not while an HTLC for it is in flight, and
       not after a payment for it went through in either direction. */
    if (lsp_channels_hash_spent_or_busy(mgr, payment_hash32)) return 0;

    /* Reuse an inactive slot first */
    invoice_entry_t *inv = NULL;
    for (size_t i = 0; i < mgr->n_invoices; i++) {
        if (!mgr->invoices[i].active) {
            inv = &mgr->invoices[i];
            break;
        }
    }
    /* Fall back to appending if no inactive slot */
    if (!inv) {
        if (mgr->n_invoices >= mgr->invoices_cap) return 0;
        inv = &mgr->invoices[mgr->n_invoices++];
    }
    memcpy(inv->payment_hash, payment_hash32, 32);
    memcpy(inv->preimage, preimage32, 32);
    inv->dest_client = dest_client;
    inv->amount_msat = amount_msat;
    inv->bridge_htlc_id = 0;
    inv->active = 1;

    if (mgr->persist)
        persist_save_invoice((persist_t *)mgr->persist, payment_hash32,
                              dest_client, amount_msat);
    return 1;
}

int lsp_channels_lookup_invoice(lsp_channel_mgr_t *mgr,
                                  const unsigned char *payment_hash32,
                                  size_t *dest_client_out) {
    for (size_t i = 0; i < mgr->n_invoices; i++) {
        if (!mgr->invoices[i].active) continue;
        if (memcmp(mgr->invoices[i].payment_hash, payment_hash32, 32) == 0) {
            *dest_client_out = mgr->invoices[i].dest_client;
            return 1;
        }
    }
    return 0;
}

int lsp_channels_invoice_amount(lsp_channel_mgr_t *mgr,
                                 const unsigned char *payment_hash32,
                                 uint64_t *amount_msat_out) {
    for (size_t i = 0; i < mgr->n_invoices; i++) {
        if (!mgr->invoices[i].active) continue;
        if (memcmp(mgr->invoices[i].payment_hash, payment_hash32, 32) == 0) {
            if (amount_msat_out) *amount_msat_out = mgr->invoices[i].amount_msat;
            return 1;
        }
    }
    return 0;
}

int lsp_channels_bridge_htlc_pending(const lsp_channel_mgr_t *mgr,
                                      const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        const htlc_origin_t *o = &mgr->htlc_origins[i];
        if (o->active && o->bridge_htlc_id > 0 &&
            memcmp(o->payment_hash, payment_hash32, 32) == 0)
            return 1;
    }
    return 0;
}

/* Fulfils older than this are no longer worth repeating: the upstream HTLC
   has long expired. */
#define BRIDGE_FULFIL_MAX_AGE_SECS (14 * 24 * 3600)

/* The ring entry for a new fulfil: one whose fulfil was confirmed, if any;
   otherwise the oldest. */
static bridge_fulfilled_t *fulfilled_slot(lsp_channel_mgr_t *mgr) {
    for (size_t k = 0; k < LSP_BRIDGE_FULFILLED_MAX; k++) {
        size_t i = (mgr->bridge_fulfilled_next + k) % LSP_BRIDGE_FULFILLED_MAX;
        if (i < mgr->n_bridge_fulfilled && mgr->bridge_fulfilled[i].undelivered)
            continue;
        mgr->bridge_fulfilled_next = (i + 1) % LSP_BRIDGE_FULFILLED_MAX;
        if (i >= mgr->n_bridge_fulfilled) mgr->n_bridge_fulfilled = i + 1;
        return &mgr->bridge_fulfilled[i];
    }
    fprintf(stderr, "LSP: WARNING — %d unconfirmed bridge fulfils, the oldest "
            "is no longer repeated from memory\n", LSP_BRIDGE_FULFILLED_MAX);
    bridge_fulfilled_t *f = &mgr->bridge_fulfilled[mgr->bridge_fulfilled_next];
    mgr->bridge_fulfilled_next =
        (mgr->bridge_fulfilled_next + 1) % LSP_BRIDGE_FULFILLED_MAX;
    return f;
}

uint64_t lsp_channels_settle_bridge_origin(lsp_channel_mgr_t *mgr,
                                             const unsigned char *payment_hash32,
                                             const unsigned char *preimage32) {
    htlc_origin_t *o = lsp_channels_find_origin(mgr, payment_hash32, 0);
    if (o) {
        bridge_fulfilled_t *f = fulfilled_slot(mgr);
        memset(f, 0, sizeof(*f));
        memcpy(f->payment_hash, payment_hash32, 32);
        memcpy(f->preimage, preimage32, 32);
        memcpy(f->upstream_id, o->upstream_id, sizeof(f->upstream_id));
        f->bridge_htlc_id = o->bridge_htlc_id;
        f->undelivered = 1;
        if (mgr->persist) {
            persist_bridge_fulfil_t row;
            memset(&row, 0, sizeof(row));
            memcpy(row.payment_hash, payment_hash32, 32);
            memcpy(row.preimage, preimage32, 32);
            snprintf(row.upstream_id, sizeof(row.upstream_id), "%s", f->upstream_id);
            row.bridge_htlc_id = f->bridge_htlc_id;
            persist_save_bridge_fulfil((persist_t *)mgr->persist, &row);
        }
    }
    return lsp_channels_get_bridge_origin(mgr, payment_hash32);
}

size_t lsp_channels_flush_bridge_fulfils(lsp_channel_mgr_t *mgr) {
    if (mgr->bridge_fd < 0) return 0;
    size_t sent = 0;
    for (size_t i = 0; i < mgr->n_bridge_fulfilled; i++) {
        const bridge_fulfilled_t *f = &mgr->bridge_fulfilled[i];
        if (!f->undelivered || f->unresolved) continue;
        cJSON *again = wire_build_bridge_fulfill_htlc(f->payment_hash, f->preimage,
                                                       f->bridge_htlc_id);
        wire_send(mgr->bridge_fd, MSG_BRIDGE_FULFILL_HTLC, again);
        cJSON_Delete(again);
        sent++;
    }
    if (sent)
        printf("LSP: repeated %zu unconfirmed fulfil(s) to the bridge\n", sent);
    return sent;
}

size_t lsp_channels_load_bridge_fulfils(lsp_channel_mgr_t *mgr) {
    if (!mgr->persist) return 0;
    persist_bridge_fulfil_t rows[LSP_BRIDGE_FULFILLED_MAX];
    size_t n = persist_load_bridge_fulfils((persist_t *)mgr->persist, rows,
                                            LSP_BRIDGE_FULFILLED_MAX,
                                            BRIDGE_FULFIL_MAX_AGE_SECS);
    for (size_t i = 0; i < n; i++) {
        bridge_fulfilled_t *f = fulfilled_slot(mgr);
        memset(f, 0, sizeof(*f));
        memcpy(f->payment_hash, rows[i].payment_hash, 32);
        memcpy(f->preimage, rows[i].preimage, 32);
        snprintf(f->upstream_id, sizeof(f->upstream_id), "%s", rows[i].upstream_id);
        f->bridge_htlc_id = rows[i].bridge_htlc_id;
        f->undelivered = 1;
    }
    if (n)
        printf("LSP: loaded %zu unconfirmed bridge fulfil(s) from DB\n", n);
    return n;
}

static void bridge_fulfil_confirmed(lsp_channel_mgr_t *mgr,
                                     const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_bridge_fulfilled; i++) {
        bridge_fulfilled_t *f = &mgr->bridge_fulfilled[i];
        if (memcmp(f->payment_hash, payment_hash32, 32) == 0)
            f->undelivered = 0;
    }
    if (mgr->persist)
        persist_delete_bridge_fulfil((persist_t *)mgr->persist, payment_hash32);
}

/* The Lightning node could not take the preimage for its HTLC (it no longer
   has the HTLC to resolve).  The client was paid inside the factory, the
   node was not paid upstream.  The fulfil stays recorded, in the database
   too, for the operator; it is not repeated again until the next start. */
static void bridge_fulfil_unresolved(lsp_channel_mgr_t *mgr,
                                      const unsigned char *payment_hash32,
                                      const char *reason) {
    char hash_hex[65], pre_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);
    for (size_t i = 0; i < mgr->n_bridge_fulfilled; i++) {
        bridge_fulfilled_t *f = &mgr->bridge_fulfilled[i];
        if (memcmp(f->payment_hash, payment_hash32, 32) != 0) continue;
        hex_encode(f->preimage, 32, pre_hex);
        if (!f->unresolved)
            fprintf(stderr, "LSP: ERROR — the Lightning node could not take "
                    "the fulfil of %s (upstream HTLC %s, reason: %s).  The "
                    "client has been paid; the incoming payment is NOT "
                    "settled.  Operator action needed: preimage %s\n",
                    hash_hex, f->upstream_id[0] ? f->upstream_id : "unknown",
                    reason, pre_hex);
        f->unresolved = 1;
        memset(pre_hex, 0, sizeof(pre_hex));
        return;
    }
    fprintf(stderr, "LSP: ERROR — the Lightning node reports an unresolved "
            "fulfil for %s (reason: %s), which is not on record here\n",
            hash_hex, reason);
}

size_t lsp_channels_flush_bridge_fails(lsp_channel_mgr_t *mgr) {
    if (mgr->bridge_fd < 0) return 0;
    size_t sent = 0;
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        htlc_origin_t *o = &mgr->htlc_origins[i];
        if (!o->active || !o->fail_pending || o->bridge_htlc_id == 0) continue;
        cJSON *fail = wire_build_bridge_fail_htlc(o->payment_hash,
            "htlc_timeout", o->bridge_htlc_id);
        int ok = wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
        cJSON_Delete(fail);
        if (!ok) break;
        lsp_channels_origin_close(mgr, o);
        o->fail_pending = 0;
        sent++;
    }
    if (sent)
        printf("LSP: told the bridge of %zu inbound HTLC(s) failed while it "
               "was away\n", sent);
    return sent;
}

/* The inbound origin in flight for this hash, or NULL. */
static htlc_origin_t *inbound_origin(lsp_channel_mgr_t *mgr,
                                      const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        htlc_origin_t *o = &mgr->htlc_origins[i];
        if (o->active && o->bridge_htlc_id > 0 &&
            memcmp(o->payment_hash, payment_hash32, 32) == 0)
            return o;
    }
    return NULL;
}

/* 1 if an HTLC offered by the bridge is the one `o` already stands for.
   With both identities known they must be equal.  An origin restored from
   the database has none; it is recognised by the HTLC the client was
   offered for it, which carries the same amount and expiry. */
static int same_upstream_htlc(lsp_channel_mgr_t *mgr, htlc_origin_t *o,
                               const char *upstream_id, uint64_t amount_msat,
                               uint32_t cltv_expiry) {
    if (!upstream_id[0]) return 0;
    if (o->upstream_id[0])
        return strcmp(o->upstream_id, upstream_id) == 0;
    if (o->sender_idx >= mgr->n_channels) return 0;
    const channel_t *ch = &mgr->entries[o->sender_idx].channel;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        const htlc_t *h = &ch->htlcs[i];
        if (h->id == o->sender_htlc_id && h->direction == HTLC_OFFERED &&
            h->state == HTLC_STATE_ACTIVE &&
            memcmp(h->payment_hash, o->payment_hash, 32) == 0)
            return h->amount_sats == amount_msat / 1000 &&
                   amount_msat % 1000 == 0 && h->cltv_expiry == cltv_expiry;
    }
    return 0;
}

int lsp_channels_hash_in_flight(const lsp_channel_mgr_t *mgr,
                                 const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++)
        if (mgr->htlc_origins[i].active &&
            memcmp(mgr->htlc_origins[i].payment_hash, payment_hash32, 32) == 0)
            return 1;
    return 0;
}

void lsp_channels_note_outbound_paid(lsp_channel_mgr_t *mgr,
                                      const unsigned char *payment_hash32) {
    memcpy(mgr->outbound_paid[mgr->outbound_paid_next], payment_hash32, 32);
    mgr->outbound_paid_next =
        (mgr->outbound_paid_next + 1) % LSP_OUTBOUND_PAID_MAX;
    if (mgr->n_outbound_paid < LSP_OUTBOUND_PAID_MAX)
        mgr->n_outbound_paid++;
}

int lsp_channels_outbound_was_paid(const lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_outbound_paid; i++)
        if (memcmp(mgr->outbound_paid[i], payment_hash32, 32) == 0)
            return 1;
    return 0;
}

int lsp_channels_origin_slot_free(const lsp_channel_mgr_t *mgr) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++)
        if (!mgr->htlc_origins[i].active) return 1;
    return mgr->n_htlc_origins < mgr->htlc_origins_cap;
}

htlc_origin_t *lsp_channels_track_outbound_pay(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t request_id,
                                        size_t sender_idx,
                                        uint64_t sender_htlc_id,
                                        uint32_t cltv_expiry) {
    htlc_origin_t *origin =
        lsp_channels_track_bridge_origin(mgr, payment_hash32, 0);
    if (!origin) return NULL;
    origin->request_id = request_id;
    origin->sender_idx = sender_idx;
    origin->sender_htlc_id = sender_htlc_id;
    origin->cltv_expiry = cltv_expiry;
    return origin;
}

htlc_origin_t *lsp_channels_track_bridge_origin(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t bridge_htlc_id) {
    /* Reuse an inactive slot first */
    htlc_origin_t *origin = NULL;
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        if (!mgr->htlc_origins[i].active) {
            origin = &mgr->htlc_origins[i];
            break;
        }
    }
    if (!origin) {
        if (mgr->n_htlc_origins >= mgr->htlc_origins_cap) return NULL;
        origin = &mgr->htlc_origins[mgr->n_htlc_origins++];
    }
    memset(origin, 0, sizeof(*origin));
    memcpy(origin->payment_hash, payment_hash32, 32);
    origin->bridge_htlc_id = bridge_htlc_id;
    origin->active = 1;
    return origin;
}

htlc_origin_t *lsp_channels_find_origin(lsp_channel_mgr_t *mgr,
                                         const unsigned char *payment_hash32,
                                         int outbound) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        htlc_origin_t *o = &mgr->htlc_origins[i];
        if (!o->active) continue;
        if ((o->bridge_htlc_id == 0) != (outbound != 0)) continue;
        if (memcmp(o->payment_hash, payment_hash32, 32) == 0)
            return o;
    }
    return NULL;
}

void lsp_channels_origin_save(lsp_channel_mgr_t *mgr, htlc_origin_t *origin) {
    if (!mgr->persist || !origin) return;
    persist_t *db = (persist_t *)mgr->persist;
    if (origin->db_id == 0)
        origin->db_id = persist_insert_htlc_origin(db, origin->payment_hash,
            origin->bridge_htlc_id, origin->request_id,
            origin->sender_idx, origin->sender_htlc_id);
    else
        persist_update_htlc_origin(db, origin->db_id,
            origin->bridge_htlc_id, origin->request_id,
            origin->sender_idx, origin->sender_htlc_id);
    if (origin->db_id != 0)
        persist_save_htlc_origin_detail(db, origin->db_id, origin->cltv_expiry,
                                         origin->upstream_id, origin->fail_pending);
}

size_t lsp_channels_restore_origins(lsp_channel_mgr_t *mgr) {
    if (!mgr->persist || !mgr->htlc_origins) return 0;
    persist_t *db = (persist_t *)mgr->persist;
    static unsigned char hashes[MAX_HTLC_ORIGINS][32];
    static uint64_t bridge_ids[MAX_HTLC_ORIGINS], request_ids[MAX_HTLC_ORIGINS];
    static size_t senders[MAX_HTLC_ORIGINS];
    static uint64_t htlc_ids[MAX_HTLC_ORIGINS];
    static int64_t row_ids[MAX_HTLC_ORIGINS];
    size_t n = persist_load_htlc_origins_ids(db, hashes, bridge_ids, request_ids,
                                              senders, htlc_ids, row_ids,
                                              MAX_HTLC_ORIGINS);
    size_t restored = 0;
    for (size_t i = 0; i < n; i++) {
        if (mgr->n_htlc_origins >= mgr->htlc_origins_cap) break;
        htlc_origin_t *o = &mgr->htlc_origins[mgr->n_htlc_origins++];
        memset(o, 0, sizeof(*o));
        memcpy(o->payment_hash, hashes[i], 32);
        o->bridge_htlc_id = bridge_ids[i];
        o->request_id = request_ids[i];
        o->sender_idx = senders[i];
        o->sender_htlc_id = htlc_ids[i];
        o->db_id = row_ids[i];
        o->active = 1;
        persist_load_htlc_origin_detail(db, o->db_id, &o->cltv_expiry,
                                         o->upstream_id, sizeof(o->upstream_id),
                                         &o->fail_pending);
        restored++;
    }
    return restored;
}

void lsp_channels_origin_close(lsp_channel_mgr_t *mgr, htlc_origin_t *origin) {
    if (!origin) return;
    origin->active = 0;
    if (mgr->persist && origin->db_id != 0)
        persist_deactivate_htlc_origin_id((persist_t *)mgr->persist,
                                           origin->db_id);
}

int lsp_channels_hash_spent_or_busy(const lsp_channel_mgr_t *mgr,
                                     const unsigned char *payment_hash32) {
    if (lsp_channels_hash_in_flight(mgr, payment_hash32) ||
        lsp_channels_outbound_was_paid(mgr, payment_hash32))
        return 1;
    for (size_t i = 0; i < mgr->n_bridge_fulfilled; i++)
        if (memcmp(mgr->bridge_fulfilled[i].payment_hash, payment_hash32, 32) == 0)
            return 1;
    return 0;
}

/* Inbound only: an outside payment a client requested for the same hash is
   a different origin and is not touched. */
uint64_t lsp_channels_get_bridge_origin(lsp_channel_mgr_t *mgr,
                                          const unsigned char *payment_hash32) {
    htlc_origin_t *o = lsp_channels_find_origin(mgr, payment_hash32, 0);
    if (!o) return 0;
    uint64_t id = o->bridge_htlc_id;
    lsp_channels_origin_close(mgr, o);
    return id;
}

int lsp_channels_recv_client_reply(int fd, wire_msg_t *msg, uint8_t expected,
                                    int timeout_sec) {
    struct timeval t_start, t_now;
    gettimeofday(&t_start, NULL);
    for (;;) {
        gettimeofday(&t_now, NULL);
        int remain = timeout_sec - (int)(t_now.tv_sec - t_start.tv_sec);
        memset(msg, 0, sizeof(*msg));
        if (remain <= 0 || fd < 0) return 0;
        if (!wire_recv_timeout(fd, msg, remain)) {
            if (msg->json) { cJSON_Delete(msg->json); msg->json = NULL; }
            return 0;
        }
        if (msg->msg_type == expected) return 1;
        if (msg->msg_type == MSG_PING) {
            cJSON *pong = cJSON_CreateObject();
            wire_send(fd, MSG_PONG, pong);
            cJSON_Delete(pong);
        } else if (msg->msg_type != MSG_PONG) {
            fprintf(stderr, "LSP: dropping msg 0x%02x while waiting for 0x%02x\n",
                    msg->msg_type, expected);
        }
        if (msg->json) { cJSON_Delete(msg->json); msg->json = NULL; }
    }
}

int lsp_channels_peer_revoked(const channel_t *ch) {
    if (!ch || ch->commitment_number == 0) return 0;
    uint64_t old_cn = ch->commitment_number - 1;
    return ch->received_revocation_valid != NULL &&
           old_cn < ch->revocations_cap &&
           ch->received_revocation_valid[old_cn];
}

void lsp_channels_abort_unrevoked_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                        size_t client_idx, channel_t *ch,
                                        uint64_t htlc_id) {
    fprintf(stderr, "LSP: ERROR — client %zu did not revoke its previous "
            "commitment for HTLC %llu; the HTLC is failed and the payment "
            "goes no further\n", client_idx, (unsigned long long)htlc_id);
    channel_fail_htlc(ch, htlc_id);
    if (lsp && lsp->client_fds && client_idx < mgr->n_channels &&
        lsp->client_fds[client_idx] >= 0) {
        wire_close(lsp->client_fds[client_idx]);
        lsp->client_fds[client_idx] = -1;
        if (mgr->readiness)
            readiness_clear((readiness_tracker_t *)mgr->readiness,
                            (uint32_t)client_idx);
    }
}

void lsp_channels_handle_bridge_msg_during_wait(lsp_channel_mgr_t *mgr,
                                                 lsp_t *lsp,
                                                 int waiting_client_fd,
                                                 const wire_msg_t *msg) {
    size_t busy = mgr->n_channels;
    for (size_t i = 0; lsp && lsp->client_fds && waiting_client_fd >= 0 &&
                       i < mgr->n_channels; i++)
        if (lsp->client_fds[i] == waiting_client_fd) { busy = i; break; }
    int was_busy = busy < mgr->n_channels
        ? mgr->entries[busy].exchange_in_progress : 0;
    if (busy < mgr->n_channels)
        mgr->entries[busy].exchange_in_progress = 1;
    lsp_channels_handle_bridge_msg(mgr, lsp, msg);
    if (busy < mgr->n_channels)
        mgr->entries[busy].exchange_in_progress = was_busy;
}

/* Put a bridge message aside until its channel is free again. */
static int defer_bridge_msg(lsp_channel_mgr_t *mgr, const wire_msg_t *msg,
                             size_t client_idx) {
    if (mgr->n_bridge_deferred >= LSP_BRIDGE_DEFERRED_MAX) {
        fprintf(stderr, "LSP: ERROR — bridge message 0x%02x for busy client "
                "%zu dropped: too many waiting\n", msg->msg_type, client_idx);
        return 0;
    }
    cJSON *copy = cJSON_Duplicate(msg->json, 1);
    if (!copy) return 0;
    mgr->bridge_deferred[mgr->n_bridge_deferred].msg_type = msg->msg_type;
    mgr->bridge_deferred[mgr->n_bridge_deferred].json = copy;
    mgr->n_bridge_deferred++;
    printf("LSP: bridge message 0x%02x waits for the exchange in progress "
           "with client %zu\n", msg->msg_type, client_idx);
    return 1;
}

size_t lsp_channels_run_deferred_bridge_msgs(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (mgr->n_bridge_deferred == 0) return 0;
    for (size_t i = 0; i < mgr->n_channels; i++)
        if (mgr->entries[i].exchange_in_progress) return 0;

    wire_msg_t waiting[LSP_BRIDGE_DEFERRED_MAX];
    size_t n = mgr->n_bridge_deferred;
    for (size_t i = 0; i < n; i++) {
        waiting[i].msg_type = mgr->bridge_deferred[i].msg_type;
        waiting[i].json = (cJSON *)mgr->bridge_deferred[i].json;
        mgr->bridge_deferred[i].json = NULL;
    }
    mgr->n_bridge_deferred = 0;
    for (size_t i = 0; i < n; i++) {
        lsp_channels_handle_bridge_msg(mgr, lsp, &waiting[i]);
        cJSON_Delete(waiting[i].json);
    }
    return n;
}

int lsp_channels_commit_htlc_update(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                     size_t client_idx,
                                     uint64_t old_local, uint64_t old_remote,
                                     const htlc_t *old_htlcs, size_t old_n_htlcs,
                                     int missing_is_fatal) {
    channel_t *ch = &mgr->entries[client_idx].channel;
    int fd = (lsp && lsp->client_fds) ? lsp->client_fds[client_idx] : -1;
    int done = 0;

    /* Remembered until the client has revoked, so that a reconnect sends
       this commitment (again). */
    if (mgr->persist)
        persist_save_pending_cs((persist_t *)mgr->persist,
            mgr->entries[client_idx].channel_id, ch->commitment_number);

    unsigned char psig[32];
    uint32_t nonce_idx;
    if (fd >= 0 && channel_create_commitment_partial_sig(ch, psig, &nonce_idx)) {
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[client_idx].channel_id,
            ch->commitment_number, psig, nonce_idx);
        int sent = wire_send(fd, MSG_COMMITMENT_SIGNED, cs);
        cJSON_Delete(cs);

        wire_msg_t ack_msg;
        memset(&ack_msg, 0, sizeof(ack_msg));
        /* A revocation that does not verify, or a revoked commitment that
           cannot be watched, fails the channel (no watch, no LSP
           revocation). */
        uint64_t old_cn;
        if (sent &&
            lsp_channels_recv_client_reply(fd, &ack_msg, MSG_REVOKE_AND_ACK, 30) &&
            lsp_channels_accept_raa(mgr, lsp, client_idx, ch,
                (uint32_t)client_idx, ack_msg.json, old_local, old_remote,
                old_htlcs, old_n_htlcs, ch->ptlcs, ch->n_ptlcs, &old_cn, NULL)) {
            lsp_send_revocation(mgr, lsp, client_idx, old_cn);
            if (mgr->persist)
                persist_save_pending_cs((persist_t *)mgr->persist,
                    mgr->entries[client_idx].channel_id, 0);
            done = 1;
        }
        if (ack_msg.json) cJSON_Delete(ack_msg.json);
    }

    if (!done && missing_is_fatal) {
        /* The client has the preimage and may keep the commitment this
           update replaced: the channel fails (and is disconnected). */
        lsp_channels_fail_channel(mgr, lsp, client_idx, ch, fd >= 0,
            "no revoke_and_ack after a fulfil");
    } else if (!done) {
        fprintf(stderr, "LSP: ERROR — commitment exchange with client %zu did "
                "not complete (commitment %llu); dropping its connection until "
                "it reconnects\n", client_idx,
                (unsigned long long)ch->commitment_number);
        if (fd >= 0 && lsp->client_fds[client_idx] == fd) {
            wire_close(fd);
            lsp->client_fds[client_idx] = -1;
        }
        if (mgr->readiness)
            readiness_clear((readiness_tracker_t *)mgr->readiness,
                            (uint32_t)client_idx);
    }
    return done;
}

/* Fail an HTLC that is in a client's commitment: the amount goes back, the
   client is told, the commitment exchange follows and the result is written
   to the database.  Returns 1 if the HTLC was there to fail. */
static int fail_committed_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                size_t client_idx, uint64_t htlc_id,
                                const char *reason) {
    channel_t *ch = &mgr->entries[client_idx].channel;
    uint64_t old_local = ch->local_amount;
    uint64_t old_remote = ch->remote_amount;
    size_t old_n_htlcs = ch->n_htlcs;
    htlc_t *old_htlcs = old_n_htlcs > 0 ? malloc(old_n_htlcs * sizeof(htlc_t)) : NULL;
    if (old_htlcs) memcpy(old_htlcs, ch->htlcs, old_n_htlcs * sizeof(htlc_t));
    else old_n_htlcs = 0;

    if (!channel_fail_htlc(ch, htlc_id)) {
        free(old_htlcs);
        return 0;
    }
    if (lsp && lsp->client_fds && lsp->client_fds[client_idx] >= 0) {
        cJSON *fail = wire_build_update_fail_htlc(htlc_id, reason);
        wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FAIL_HTLC, fail);
        cJSON_Delete(fail);
    }
    lsp_channels_commit_htlc_update(mgr, lsp, client_idx, old_local, old_remote,
                                     old_htlcs, old_n_htlcs, 0);
    free(old_htlcs);

    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        int own_txn = !persist_in_transaction(db);
        if (own_txn) persist_begin(db);
        persist_update_channel_balance(db, (uint32_t)client_idx,
            ch->local_amount, ch->remote_amount, ch->commitment_number);
        persist_delete_htlc(db, (uint32_t)client_idx, htlc_id);
        unsigned char pcs[32];
        if (channel_get_local_pcs(ch, ch->commitment_number, pcs))
            persist_save_local_pcs(db, (uint32_t)client_idx,
                ch->commitment_number, pcs);
        if (channel_get_local_pcs(ch, ch->commitment_number + 1, pcs))
            persist_save_local_pcs(db, (uint32_t)client_idx,
                ch->commitment_number + 1, pcs);
        memset(pcs, 0, 32);
        if (own_txn) persist_commit(db);
    }
    return 1;
}

void lsp_channels_fail_outbound_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      htlc_origin_t *origin, size_t client_idx,
                                      uint64_t htlc_id, const char *reason) {
    if (client_idx < mgr->n_channels)
        fail_committed_htlc(mgr, lsp, client_idx, htlc_id, reason);
    lsp_channels_origin_close(mgr, origin);
}

/* An inbound bridge HTLC could not be handed to the client after all: take
   it off the client's channel, close its origin and tell the bridge, so
   that the plugin fails the upstream HTLC and nothing stays reserved. */
static void inbound_rollback(lsp_channel_mgr_t *mgr, channel_t *dest_ch,
                              uint64_t dest_htlc_id, htlc_origin_t *origin,
                              const unsigned char *payment_hash,
                              uint64_t bridge_htlc_id, const char *reason) {
    channel_fail_htlc(dest_ch, dest_htlc_id);
    lsp_channels_origin_close(mgr, origin);
    cJSON *fail = wire_build_bridge_fail_htlc(payment_hash, reason, bridge_htlc_id);
    wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
    cJSON_Delete(fail);
}

int lsp_channels_handle_bridge_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                     const wire_msg_t *msg) {
    if (!mgr || !lsp || !msg) return 0;

    switch (msg->msg_type) {
    case MSG_BRIDGE_ADD_HTLC: {
        /* Inbound payment from LN via bridge */
        unsigned char payment_hash[32];
        uint64_t amount_msat, htlc_id;
        uint32_t cltv_expiry;
        int is_keysend = 0;
        unsigned char ks_preimage[32];
        size_t ks_dest = 0;
        if (!wire_parse_bridge_add_htlc_keysend(msg->json, payment_hash,
                                                  &amount_msat, &cltv_expiry, &htlc_id,
                                                  &is_keysend, ks_preimage, &ks_dest)) {
            fprintf(stderr, "LSP: bridge ADD_HTLC parse failed\n");
            return 0;
        }
        printf("LSP: bridge ADD_HTLC received (%llu msat, cltv=%u, htlc_id=%llu%s)\n",
               (unsigned long long)amount_msat, cltv_expiry,
               (unsigned long long)htlc_id,
               is_keysend ? ", keysend" : "");

        char upstream_id[BRIDGE_UPSTREAM_ID_MAX] = "";
        {
            cJSON *up = cJSON_GetObjectItem(msg->json, "upstream_id");
            if (up && cJSON_IsString(up) &&
                strlen(up->valuestring) < sizeof(upstream_id))
                strcpy(upstream_id, up->valuestring);
        }

        /* The Lightning node offers an HTLC again when it comes back from a
           restart with the HTLC still unresolved.  That is not a second
           payment: the client already has it (or has already fulfilled
           it), so attach the new offer to what is there. */
        {
            htlc_origin_t *prev = inbound_origin(mgr, payment_hash);
            if (prev && prev->fail_pending &&
                same_upstream_htlc(mgr, prev, upstream_id, amount_msat,
                                   cltv_expiry)) {
                /* Already failed towards the client while the bridge was
                   away: this is where the node gets the verdict */
                cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                    "htlc_timeout", htlc_id);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                cJSON_Delete(fail);
                lsp_channels_origin_close(mgr, prev);
                printf("LSP: bridge HTLC offered again after it timed out, "
                       "failed back\n");
                return 1;
            }
            if (prev && same_upstream_htlc(mgr, prev, upstream_id, amount_msat,
                                           cltv_expiry)) {
                prev->bridge_htlc_id = htlc_id;
                memcpy(prev->upstream_id, upstream_id, sizeof(prev->upstream_id));
                lsp_channels_origin_save(mgr, prev);
                printf("LSP: bridge HTLC offered again, still in flight "
                       "(htlc_id now %llu)\n", (unsigned long long)htlc_id);
                return 1;
            }
            for (size_t i = 0; !prev && upstream_id[0] &&
                               i < mgr->n_bridge_fulfilled; i++) {
                bridge_fulfilled_t *f = &mgr->bridge_fulfilled[i];
                if (memcmp(f->payment_hash, payment_hash, 32) != 0 ||
                    strcmp(f->upstream_id, upstream_id) != 0)
                    continue;
                f->bridge_htlc_id = htlc_id;
                cJSON *again = wire_build_bridge_fulfill_htlc(payment_hash,
                                                               f->preimage, htlc_id);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_FULFILL_HTLC, again);
                cJSON_Delete(again);
                printf("LSP: bridge HTLC offered again after it was "
                       "fulfilled, fulfil repeated\n");
                return 1;
            }
        }

        /* A hash a client is paying, or has paid, on the outside is not
           also accepted as an inbound payment (invoice or keysend): the two
           would be settled by the same preimage. */
        if (lsp_channels_find_origin(mgr, payment_hash, 1) ||
            lsp_channels_outbound_was_paid(mgr, payment_hash)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "payment_hash_in_use", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC rejected — hash is in use by an "
                   "outside payment\n");
            return 1;
        }

        /* Look up invoice to find dest_client */
        size_t dest_idx;
        if (!lsp_channels_lookup_invoice(mgr, payment_hash, &dest_idx)) {
            if (is_keysend) {
                /* Keysend: register ephemeral invoice with sender's preimage */
                if (ks_dest >= mgr->n_channels) {
                    fprintf(stderr, "LSP: keysend dest_client %zu out of range "
                            "(max %zu), defaulting to 0\n",
                            ks_dest, mgr->n_channels - 1);
                    ks_dest = 0;
                }
                if (!lsp_channels_register_invoice(mgr, payment_hash,
                        ks_preimage, ks_dest, amount_msat)) {
                    cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                        "keysend_register_failed", htlc_id);
                    wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                    cJSON_Delete(fail);
                    return 1;
                }
                dest_idx = ks_dest;
                printf("LSP: keysend registered for client %zu\n", dest_idx);
            } else {
                /* Unknown payment hash — fail back to bridge */
                cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                    "unknown_payment_hash", htlc_id);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                cJSON_Delete(fail);
                printf("LSP: bridge HTLC unknown hash, failing back\n");
                return 1;
            }
        }

        /* The invoice amount must arrive in this one HTLC.  The client is
           offered exactly what came in and releases the preimage for it, so
           an HTLC below the invoice amount would settle the invoice for
           less than it asks.  Parts of a multi-part payment are not
           collected: each is below the invoice amount and is refused here,
           before anything is offered to the client. */
        uint64_t invoice_msat = 0;
        if (lsp_channels_invoice_amount(mgr, payment_hash, &invoice_msat) &&
            amount_msat < invoice_msat) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "amount_below_invoice", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC rejected — %llu msat is below the "
                   "invoice amount of %llu msat\n",
                   (unsigned long long)amount_msat,
                   (unsigned long long)invoice_msat);
            return 1;
        }

        /* One HTLC per invoice at a time: a second one for the same hash
           would be a further part or a repeat of a payment still in
           flight. */
        if (lsp_channels_bridge_htlc_pending(mgr, payment_hash)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "duplicate_payment_hash", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC rejected — payment already in flight "
                   "for this hash\n");
            return 1;
        }

        /* Reject sub-satoshi fractions: on-chain amounts are whole sats */
        if (amount_msat % 1000 != 0) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "fractional_msat_unsupported", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC rejected — fractional msat (%llu)\n",
                   (unsigned long long)amount_msat);
            return 1;
        }
        uint64_t amount_sats = amount_msat / 1000;
        if (amount_sats == 0) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "amount_too_small", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC zero sats (%llu msat)\n",
                   (unsigned long long)amount_msat);
            return 1;
        }

        /* CLTV bound: reject HTLCs that expire at/past the factory timeout
           or below the DW safety delta.  A misconfigured bridge could request
           expiry past the channel's CSV horizon, trapping funds.  Mirror the
           client-side forwarding policy at src/lsp_channels.c:1389.
           Closes Finding C of LSP_TEAM_BRIDGE_AUDIT_2026-05-19.md. */
        uint32_t factory_delta = lsp_compute_factory_cltv_delta(&lsp->factory);
        uint32_t fwd_cltv_expiry;
        if (!lsp_validate_cltv_for_forward(cltv_expiry, &fwd_cltv_expiry,
                                            lsp->factory.cltv_timeout,
                                            factory_delta, 0)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "cltv_expiry_out_of_bounds", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            fprintf(stderr, "LSP: bridge HTLC cltv_expiry=%u rejected "
                    "(delta=%u, factory_timeout=%u)\n",
                    cltv_expiry, factory_delta, lsp->factory.cltv_timeout);
            return 1;
        }

        /* Without an origin the fulfil could never find its way back to
           the bridge: refuse before anything is offered to the client. */
        if (!lsp_channels_origin_slot_free(mgr)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "too_many_pending_payments", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            fprintf(stderr, "LSP: bridge HTLC rejected — origin table full\n");
            return 1;
        }

        channel_t *dest_ch = &mgr->entries[dest_idx].channel;

        /* Not while another exchange with this client is in progress */
        if (mgr->entries[dest_idx].exchange_in_progress) {
            if (!defer_bridge_msg(mgr, msg, dest_idx)) {
                cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                    "client_busy", htlc_id);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                cJSON_Delete(fail);
            }
            return 1;
        }

        /* Capture amounts and HTLC state before add_htlc changes them (for watchtower) */
        uint64_t old_dest_local = dest_ch->local_amount;
        uint64_t old_dest_remote = dest_ch->remote_amount;
        size_t old_dest_n_htlcs = dest_ch->n_htlcs;
        htlc_t *old_dest_htlcs = old_dest_n_htlcs > 0
            ? malloc(old_dest_n_htlcs * sizeof(htlc_t)) : NULL;
        if (old_dest_n_htlcs > 0 && !old_dest_htlcs) return 0;
        if (old_dest_n_htlcs > 0)
            memcpy(old_dest_htlcs, dest_ch->htlcs, old_dest_n_htlcs * sizeof(htlc_t));

        /* Add HTLC to destination's channel (offered from LSP).
           cltv_expiry is checked above against the factory horizon
           but passed raw here so LSP and client both sign the commitment with the
           same cltv (delta-subtracting LSP-side only would diverge sighashes
           and break partial_sig_verify — caught by #310 CI regtest_bridge tests). */
        uint64_t dest_htlc_id;
        if (!channel_add_htlc(dest_ch, HTLC_OFFERED, amount_sats,
                               payment_hash, cltv_expiry, &dest_htlc_id)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "insufficient_funds", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC add failed (client %zu, %llu sats, "
                   "local=%llu remote=%llu)\n",
                   dest_idx, (unsigned long long)amount_sats,
                   (unsigned long long)dest_ch->local_amount,
                   (unsigned long long)dest_ch->remote_amount);
            free(old_dest_htlcs);
            return 1;
        }

        /* Record in htlc_inbound table (unified inbound HTLC tracking) */
        {
            static const unsigned char zero_secret[32] = {0};
            htlc_inbound_add(&mgr->htlc_inbound, htlc_id, amount_msat,
                             payment_hash, zero_secret, cltv_expiry, 0);
            if (mgr->persist) {
                htlc_inbound_t hi;
                memset(&hi, 0, sizeof(hi));
                hi.htlc_id      = htlc_id;
                hi.amount_msat  = amount_msat;
                memcpy(hi.payment_hash, payment_hash, 32);
                hi.cltv_expiry  = cltv_expiry;
                persist_save_htlc_inbound((persist_t *)mgr->persist, &hi);
            }
        }

        /* Track bridge origin for back-propagation (with cltv for timeout),
           in the entry the tracker filled. */
        htlc_origin_t *org = lsp_channels_track_bridge_origin(mgr, payment_hash,
                                                               htlc_id);
        if (org) {
            org->cltv_expiry = cltv_expiry;
            org->sender_idx = dest_idx;
            org->sender_htlc_id = dest_htlc_id;
            memcpy(org->upstream_id, upstream_id, sizeof(org->upstream_id));
            lsp_channels_origin_save(mgr, org);
        }

        /* Forward ADD_HTLC to destination client */
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            free(old_dest_htlcs);
            inbound_rollback(mgr, dest_ch, dest_htlc_id, org, payment_hash,
                             htlc_id, "client_unreachable");
            return 1;
        }
        cJSON_Delete(fwd);

        /* Send COMMITMENT_SIGNED to dest */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx)) {
                free(old_dest_htlcs);
                inbound_rollback(mgr, dest_ch, dest_htlc_id, org, payment_hash,
                                 htlc_id, "commitment_failed");
                return 1;
            }
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[dest_idx].channel_id,
                dest_ch->commitment_number, psig32, nonce_idx);
            if (!wire_send(lsp->client_fds[dest_idx], MSG_COMMITMENT_SIGNED, cs)) {
                cJSON_Delete(cs);
                free(old_dest_htlcs);
                inbound_rollback(mgr, dest_ch, dest_htlc_id, org, payment_hash,
                                 htlc_id, "client_unreachable");
                return 1;
            }
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from dest */
        {
            wire_msg_t ack_msg;
            if (!wire_recv_skip_ping(lsp->client_fds[dest_idx], &ack_msg) ||
                ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
                /* Client disconnected or sent unexpected message.
                   Rollback: fail the HTLC we just added so the channel
                   state is consistent and bridge can retry later. */
                fprintf(stderr, "LSP: bridge HTLC rollback — client %zu disconnected during commit\n",
                        dest_idx);
                inbound_rollback(mgr, dest_ch, dest_htlc_id, org, payment_hash,
                                 htlc_id, "client_disconnected");
                if (ack_msg.json) cJSON_Delete(ack_msg.json);
                free(old_dest_htlcs);
                return 1;  /* handled (not a fatal error) */
            }
            /* Fail-closed: if the revocation does not verify, or the commitment
               it revokes cannot be watched, the channel is failed and this
               update goes no further (no watch, no LSP revocation). */
            uint64_t old_cn;
            if (!lsp_channels_accept_raa(mgr, lsp, dest_idx, dest_ch,
                    (uint32_t)dest_idx, ack_msg.json,
                    old_dest_local, old_dest_remote,
                    old_dest_htlcs, old_dest_n_htlcs,
                    dest_ch->ptlcs, dest_ch->n_ptlcs, &old_cn, NULL)) {
                cJSON_Delete(ack_msg.json);
                free(old_dest_htlcs);
                return 0;
            }
            lsp_send_revocation(mgr, lsp, dest_idx, old_cn);
            cJSON_Delete(ack_msg.json);
        }
        free(old_dest_htlcs);

        /* Persist dest channel balance + HTLC + PCS/PCP after commitment exchange */
        if (mgr->persist) {
            persist_t *db = (persist_t *)mgr->persist;
            int own_txn = !persist_in_transaction(db);
            if (own_txn) persist_begin(db);

            persist_update_channel_balance(db,
                (uint32_t)dest_idx,
                dest_ch->local_amount, dest_ch->remote_amount,
                dest_ch->commitment_number);

            htlc_t persist_htlc;
            memset(&persist_htlc, 0, sizeof(persist_htlc));
            persist_htlc.id = dest_htlc_id;
            persist_htlc.direction = HTLC_OFFERED;
            persist_htlc.state = HTLC_STATE_ACTIVE;
            persist_htlc.amount_sats = amount_sats;
            memcpy(persist_htlc.payment_hash, payment_hash, 32);
            persist_htlc.cltv_expiry = cltv_expiry;
            persist_save_htlc(db, (uint32_t)dest_idx, &persist_htlc);

            /* Save remote PCP received in REVOKE_AND_ACK */
            {
                unsigned char ser[33];
                size_t slen = 33;
                secp256k1_pubkey saved_pcp;
                if (channel_get_remote_pcp(dest_ch,
                        dest_ch->commitment_number + 1, &saved_pcp) &&
                    secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &slen,
                        &saved_pcp, SECP256K1_EC_COMPRESSED))
                    persist_save_remote_pcp(db, (uint32_t)dest_idx,
                        dest_ch->commitment_number + 1, ser);
            }

            /* Save LSP's local PCS for crash recovery */
            unsigned char pcs[32];
            if (channel_get_local_pcs(dest_ch, dest_ch->commitment_number, pcs))
                persist_save_local_pcs(db, (uint32_t)dest_idx,
                    dest_ch->commitment_number, pcs);
            if (channel_get_local_pcs(dest_ch, dest_ch->commitment_number + 1, pcs))
                persist_save_local_pcs(db, (uint32_t)dest_idx,
                    dest_ch->commitment_number + 1, pcs);
            memset(pcs, 0, 32);

            if (own_txn) persist_commit(db);
        }

        printf("LSP: bridge HTLC forwarded to client %zu (%llu sats)\n",
               dest_idx, (unsigned long long)amount_sats);
        return 1;
    }

    case MSG_BRIDGE_PAY_RESULT: {
        /* Outbound pay result from bridge */
        uint64_t request_id;
        int success;
        unsigned char preimage[32];
        memset(preimage, 0, sizeof(preimage));
        if (!wire_parse_bridge_pay_result(msg->json, &request_id, &success,
                                            preimage))
            return 0;

        printf("LSP: bridge pay result: request_id=%llu success=%d\n",
               (unsigned long long)request_id, success);
        const char *rejected = NULL;   /* why the result could not be used */

        /* Find the originating HTLC by request_id (outbound origins only:
           request ids start at 1 and inbound origins carry none) */
        for (size_t i = 0; request_id != 0 && i < mgr->n_htlc_origins; i++) {
            if (!mgr->htlc_origins[i].active) continue;
            if (mgr->htlc_origins[i].bridge_htlc_id != 0) continue;
            if (mgr->htlc_origins[i].request_id != request_id) continue;

            size_t client_idx = mgr->htlc_origins[i].sender_idx;
            uint64_t htlc_id_val = mgr->htlc_origins[i].sender_htlc_id;

            if (client_idx >= mgr->n_channels) {
                fprintf(stderr, "LSP: ERROR — bridge pay result %llu rejected: "
                        "origin names client %zu, which does not exist\n",
                        (unsigned long long)request_id, client_idx);
                lsp_channels_origin_close(mgr, &mgr->htlc_origins[i]);
                rejected = "no_channel";
                break;
            }
            channel_t *ch = &mgr->entries[client_idx].channel;

            /* The LSP is in the middle of another exchange with this client
               (this message was read while waiting for its reply).  Applying
               the result now would start a second exchange on the channel
               and take the reply meant for the first.  It is applied, and
               acknowledged, once the channel is free. */
            if (mgr->entries[client_idx].exchange_in_progress) {
                if (defer_bridge_msg(mgr, msg, client_idx))
                    return 1;
                /* could not be kept: unacknowledged, the plugin repeats it */
                return 0;
            }

            /* A success is only a success with the preimage of the hash the
               client's HTLC is locked to.  Anything else settles nothing:
               the HTLC stays held and the origin open.  The node says the
               payment went through but cannot prove it, so neither
               claiming nor refunding the client is safe here. */
            if (success) {
                unsigned char check[32];
                sha256(preimage, 32, check);
                if (memcmp(check, mgr->htlc_origins[i].payment_hash, 32) != 0) {
                    fprintf(stderr, "LSP: ERROR — bridge pay result %llu rejected: "
                            "preimage does not match the payment hash.  HTLC "
                            "%llu of client %zu stays held; operator action "
                            "needed\n",
                            (unsigned long long)request_id,
                            (unsigned long long)htlc_id_val, client_idx);
                    rejected = "preimage_mismatch";
                    break;
                }
            }

            if (success) {
                /* Capture pre-fulfill state for watchtower */
                uint64_t old_local = ch->local_amount;
                uint64_t old_remote = ch->remote_amount;
                size_t old_n_htlcs = ch->n_htlcs;
                htlc_t *old_htlcs = old_n_htlcs > 0
                    ? malloc(old_n_htlcs * sizeof(htlc_t)) : NULL;
                if (old_n_htlcs > 0 && old_htlcs)
                    memcpy(old_htlcs, ch->htlcs, old_n_htlcs * sizeof(htlc_t));

                /* The client may withhold its revoke_and_ack and broadcast
                   the commitment still holding this HTLC once it sees the
                   preimage: be ready to claim it on chain first.  If the
                   claim cannot be armed, the preimage is not revealed and
                   the result is left unacknowledged, so the plugin repeats
                   it and arming is tried again. */
                if (!lsp_channels_watch_commitment(mgr, client_idx) ||
                    lsp_channels_register_htlc_claim(mgr, client_idx,
                                                     htlc_id_val,
                                                     preimage) < 0) {
                    fprintf(stderr, "LSP: CRITICAL: no on-chain claim for "
                            "HTLC %llu of client %zu: its preimage is not "
                            "revealed yet\n",
                            (unsigned long long)htlc_id_val, client_idx);
                    free(old_htlcs);
                    return 0;
                }
                /* A failed channel gets no preimage: the HTLC is claimed on
                   chain from whichever commitment the client broadcasts. */
                if (ch->revocation_failed) {
                    fprintf(stderr, "LSP: client %zu channel failed: preimage "
                            "of HTLC %llu not revealed to it, claimed on chain "
                            "if it broadcasts\n", client_idx,
                            (unsigned long long)htlc_id_val);
                    free(old_htlcs);
                    rejected = "channel_failed";
                    break;
                }

                /* Fulfill the HTLC on the client's channel; the client is
                   told nothing unless that worked */
                if (!channel_fulfill_htlc(ch, htlc_id_val, preimage)) {
                    fprintf(stderr, "LSP: ERROR — bridge pay result %llu rejected: "
                            "no HTLC %llu to fulfil on client %zu\n",
                            (unsigned long long)request_id,
                            (unsigned long long)htlc_id_val, client_idx);
                    free(old_htlcs);
                    lsp_channels_origin_close(mgr, &mgr->htlc_origins[i]);
                    rejected = "no_htlc";
                    break;
                }
                mgr->htlc_origins[i].active = 0;
                lsp_channels_note_outbound_paid(mgr,
                    mgr->htlc_origins[i].payment_hash);

                cJSON *ful = wire_build_update_fulfill_htlc(htlc_id_val, preimage);
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FULFILL_HTLC, ful);
                cJSON_Delete(ful);

                /* The commitment exchange for the fulfil.  If the client does
                   not complete it, its connection is dropped; the fulfil
                   itself stands (the preimage is known and the channel
                   state has moved). */
                lsp_channels_commit_htlc_update(mgr, lsp, client_idx,
                                                 old_local, old_remote,
                                                 old_htlcs, old_n_htlcs, 1);
                free(old_htlcs);

                /* Persist balance + commitment_number + PCS/PCP + origin deactivation
                   atomically (all in one transaction) */
                if (mgr->persist) {
                    persist_t *db = (persist_t *)mgr->persist;
                    int own_txn = !persist_in_transaction(db);
                    if (own_txn) persist_begin(db);

                    persist_update_channel_balance(db,
                        (uint32_t)client_idx,
                        ch->local_amount, ch->remote_amount,
                        ch->commitment_number);
                    persist_delete_htlc(db, (uint32_t)client_idx, htlc_id_val);

                    unsigned char pcs[32];
                    if (channel_get_local_pcs(ch, ch->commitment_number, pcs))
                        persist_save_local_pcs(db, (uint32_t)client_idx,
                            ch->commitment_number, pcs);
                    if (channel_get_local_pcs(ch, ch->commitment_number + 1, pcs))
                        persist_save_local_pcs(db, (uint32_t)client_idx,
                            ch->commitment_number + 1, pcs);
                    memset(pcs, 0, 32);

                    persist_deactivate_htlc_origin_id(db,
                        mgr->htlc_origins[i].db_id);

                    if (own_txn) persist_commit(db);
                }

                printf("LSP: bridge pay fulfilled for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id_val);
            } else {
                /* Fail the HTLC: amount back to the client, client told,
                   commitment exchanged, as for a fulfil */
                if (!fail_committed_htlc(mgr, lsp, client_idx, htlc_id_val,
                                          "bridge_pay_failed")) {
                    fprintf(stderr, "LSP: ERROR — bridge pay result %llu rejected: "
                            "no HTLC %llu to fail on client %zu\n",
                            (unsigned long long)request_id,
                            (unsigned long long)htlc_id_val, client_idx);
                    lsp_channels_origin_close(mgr, &mgr->htlc_origins[i]);
                    rejected = "no_htlc";
                    break;
                }
                lsp_channels_origin_close(mgr, &mgr->htlc_origins[i]);

                printf("LSP: bridge pay failed for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id_val);
            }
            break;
        }

        /* Every result gets its answer, so the plugin stops repeating it:
           applied (or nothing left to apply it to), or rejected with the
           reason. */
        if (mgr->bridge_fd >= 0) {
            cJSON *ack = wire_build_bridge_pay_result_ack(request_id, rejected);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_PAY_RESULT_ACK, ack);
            cJSON_Delete(ack);
        }
        return 1;
    }

    case MSG_INVOICE_BOLT11: {
        /* BOLT11 invoice created by CLN plugin — forward to dest client */
        unsigned char payment_hash[32];
        char bolt11[2048];
        if (!wire_parse_invoice_bolt11(msg->json, payment_hash, bolt11,
                                         sizeof(bolt11)))
            return 0;

        /* Look up dest_client via invoice registry */
        size_t dest_idx;
        if (!lsp_channels_lookup_invoice(mgr, payment_hash, &dest_idx)) {
            fprintf(stderr, "LSP: INVOICE_BOLT11 for unknown hash\n");
            return 0;
        }

        /* Forward to client */
        cJSON *fwd = wire_build_invoice_bolt11(payment_hash, bolt11);
        int ok = wire_send(lsp->client_fds[dest_idx], MSG_INVOICE_BOLT11, fwd);
        cJSON_Delete(fwd);
        printf("LSP: forwarded BOLT11 to client %zu\n", dest_idx);
        return ok;
    }

    case MSG_BRIDGE_HELLO:
        /* Bridge heartbeat ping — send ACK back, and take the occasion to
           repeat fulfils it has not confirmed */
        {
            cJSON *ack = wire_build_bridge_hello_ack();
            wire_send(mgr->bridge_fd, MSG_BRIDGE_HELLO_ACK, ack);
            cJSON_Delete(ack);
        }
        lsp_channels_flush_bridge_fulfils(mgr);
        lsp_channels_flush_bridge_fails(mgr);
        lsp_channels_run_deferred_bridge_msgs(mgr, lsp);
        return 1;

    case MSG_BRIDGE_FULFILL_UNRESOLVED: {
        unsigned char payment_hash[32];
        char why[96];
        if (!wire_parse_bridge_fulfill_unresolved(msg->json, payment_hash,
                                                    why, sizeof(why)))
            return 0;
        bridge_fulfil_unresolved(mgr, payment_hash, why);
        return 1;
    }

    case MSG_BRIDGE_FULFILL_ACK: {
        unsigned char payment_hash[32];
        if (!wire_parse_bridge_fulfill_ack(msg->json, payment_hash))
            return 0;
        bridge_fulfil_confirmed(mgr, payment_hash);
        return 1;
    }

    default:
        fprintf(stderr, "LSP: unexpected bridge msg 0x%02x\n", msg->msg_type);
        return 0;
    }
}

void lsp_channels_check_bridge_htlc_timeouts(lsp_channel_mgr_t *mgr,
                                               lsp_t *lsp,
                                               uint32_t current_height) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        htlc_origin_t *origin = &mgr->htlc_origins[i];
        if (!origin->active) continue;
        if (origin->cltv_expiry == 0) continue;

        /* Outbound: the client's HTLC pays for an outside payment whose
           outcome only the Lightning node knows.  It is settled by that
           node's result and by nothing else: failing it here on a timer
           would refund a client whose payment may have gone through.  The
           route was limited so that the outside payment is decided before
           this point, and the plugin repeats the result until it is
           acknowledged, so an origin still open here means the node or the
           bridge is unreachable.  Say so once and keep holding. */
        if (origin->bridge_htlc_id == 0) {
            if (origin->request_id != 0 && !origin->expiry_warned &&
                current_height + FACTORY_CLTV_DELTA_DEFAULT >= origin->cltv_expiry) {
                fprintf(stderr, "LSP: WARNING — outside payment %llu still "
                        "unresolved at height %u, client HTLC expires at %u; "
                        "holding it until the Lightning node reports the "
                        "outcome\n",
                        (unsigned long long)origin->request_id,
                        current_height, origin->cltv_expiry);
                origin->expiry_warned = 1;
            }
            continue;
        }

        /* Fail back if current height is within FACTORY_CLTV_DELTA_DEFAULT of expiry */
        if (current_height + FACTORY_CLTV_DELTA_DEFAULT >= origin->cltv_expiry) {
            if (!origin->fail_pending) {
                printf("LSP: bridge HTLC timeout — height %u approaching expiry %u\n",
                       current_height, origin->cltv_expiry);

                /* Fail HTLC on destination channel to free balance */
                size_t dest_idx = origin->sender_idx;
                uint64_t dest_htlc_id = origin->sender_htlc_id;
                if (dest_idx < mgr->n_channels) {
                    fail_committed_htlc(mgr, lsp, dest_idx, dest_htlc_id,
                                        "htlc_timeout");
                }
                /* The Lightning node holds its HTLC until it hears the
                   verdict.  The origin stays open until the bridge has been
                   told (now, or when it is back), and the pending failure
                   is written to the database with it, so that a restart in
                   between does not lose it. */
                origin->fail_pending = 1;
                lsp_channels_origin_save(mgr, origin);
            }
            if (mgr->bridge_fd >= 0) {
                cJSON *fail = wire_build_bridge_fail_htlc(origin->payment_hash,
                    "htlc_timeout", origin->bridge_htlc_id);
                int ok = wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                cJSON_Delete(fail);
                if (ok) {
                    origin->fail_pending = 0;
                    lsp_channels_origin_close(mgr, origin);
                }
            }
        }
    }
}

int lsp_channels_htlc_awaits_outside_pay(const lsp_channel_mgr_t *mgr,
                                          size_t client_idx, uint64_t htlc_id) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        const htlc_origin_t *o = &mgr->htlc_origins[i];
        if (o->active && o->bridge_htlc_id == 0 && o->request_id != 0 &&
            o->sender_idx == client_idx && o->sender_htlc_id == htlc_id)
            return 1;
    }
    return 0;
}

void lsp_channels_expire_htlcs(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                uint32_t height) {
    (void)lsp;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        channel_t *ch = &mgr->entries[c].channel;
        /* Monotonicity guard: a height that went backward (reorg) must not
           fail anything early. */
        if (height < ch->last_htlc_check_height) continue;
        ch->last_htlc_check_height = height;

        /* Collect first: failing an HTLC rearranges the array. */
        uint64_t expired[MAX_HTLCS];
        size_t n_expired = 0;
        for (size_t h = 0; h < ch->n_htlcs && n_expired < MAX_HTLCS; h++) {
            const htlc_t *htlc = &ch->htlcs[h];
            if (htlc->state != HTLC_STATE_ACTIVE || htlc->cltv_expiry == 0 ||
                height < htlc->cltv_expiry)
                continue;
            if (htlc->direction == HTLC_RECEIVED &&
                lsp_channels_htlc_awaits_outside_pay(mgr, c, htlc->id))
                continue;
            expired[n_expired++] = htlc->id;
        }
        if (n_expired == 0) continue;

        persist_t *db = (persist_t *)mgr->persist;
        int own_txn = db && !persist_in_transaction(db);
        if (own_txn) persist_begin(db);
        int n_failed = 0;
        for (size_t k = 0; k < n_expired; k++) {
            if (!channel_fail_htlc(ch, expired[k])) continue;
            n_failed++;
            if (db) persist_delete_htlc(db, (uint32_t)c, expired[k]);
        }
        if (own_txn) persist_commit(db);
        if (n_failed > 0)
            printf("LSP: auto-failed %d expired HTLCs on channel %zu "
                   "(height=%u)\n", n_failed, c, height);
    }

    /* Inbound bridge HTLCs approaching their deadline are failed back to
       avoid on-chain resolution (10 blocks before expiry). */
    if (!mgr->htlc_origins || mgr->bridge_fd < 0) return;
    for (size_t oi = 0; oi < mgr->n_htlc_origins; oi++) {
        htlc_origin_t *orig = &mgr->htlc_origins[oi];
        if (!orig->active || orig->cltv_expiry == 0) continue;
        if (orig->bridge_htlc_id == 0) continue;   /* outbound: never by timer */
        if (height + 10 < orig->cltv_expiry) continue;

        fprintf(stderr, "LSP: bridge HTLC timeout — failing back "
                "htlc_id=%llu (height=%u, cltv=%u)\n",
                (unsigned long long)orig->bridge_htlc_id, height,
                orig->cltv_expiry);
        cJSON *fail = wire_build_bridge_fail_htlc(orig->payment_hash,
            "cltv_expiry_too_soon", orig->bridge_htlc_id);
        wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
        cJSON_Delete(fail);
        /* Also fail the HTLC offered to the client for it, if still active */
        if (orig->sender_idx < mgr->n_channels)
            channel_fail_htlc(&mgr->entries[orig->sender_idx].channel,
                              orig->sender_htlc_id);
        lsp_channels_origin_close(mgr, orig);
    }
}
