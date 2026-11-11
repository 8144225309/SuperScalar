/* Bridge/invoice support extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/htlc_inbound.h"
#include "superscalar/persist.h"
#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    if (!network || !invoice_hrp) return 0;
    if (strcmp(network, "mainnet") == 0 || strcmp(network, "bitcoin") == 0)
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

    if (mgr->persist)
        persist_save_htlc_origin((persist_t *)mgr->persist, payment_hash32,
                                  bridge_htlc_id, 0, 0, 0);
    return origin;
}

uint64_t lsp_channels_get_bridge_origin(lsp_channel_mgr_t *mgr,
                                          const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        if (!mgr->htlc_origins[i].active) continue;
        if (memcmp(mgr->htlc_origins[i].payment_hash, payment_hash32, 32) == 0) {
            mgr->htlc_origins[i].active = 0;
            if (mgr->persist)
                persist_deactivate_htlc_origin((persist_t *)mgr->persist,
                                                payment_hash32);
            return mgr->htlc_origins[i].bridge_htlc_id;
        }
    }
    return 0;
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

        channel_t *dest_ch = &mgr->entries[dest_idx].channel;

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

        /* Track bridge origin for back-propagation (with cltv for timeout) */
        lsp_channels_track_bridge_origin(mgr, payment_hash, htlc_id);
        /* Store cltv_expiry and dest info for timeout cleanup.
           Look up by payment_hash since slot reuse may place it anywhere. */
        for (size_t oi = 0; oi < mgr->n_htlc_origins; oi++) {
            htlc_origin_t *org = &mgr->htlc_origins[oi];
            if (org->active && memcmp(org->payment_hash, payment_hash, 32) == 0) {
                org->cltv_expiry = cltv_expiry;
                org->sender_idx = dest_idx;
                org->sender_htlc_id = dest_htlc_id;
                /* Re-persist with updated sender/cltv fields so timeout
                   routing works after crash (the initial persist only
                   stored bridge_htlc_id with zeroed sender fields) */
                if (mgr->persist)
                    persist_save_htlc_origin((persist_t *)mgr->persist,
                        payment_hash, htlc_id, 0,
                        dest_idx, dest_htlc_id);
                break;
            }
        }

        /* Forward ADD_HTLC to destination client */
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            free(old_dest_htlcs);
            return 0;
        }
        cJSON_Delete(fwd);

        /* Send COMMITMENT_SIGNED to dest */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx)) {
                free(old_dest_htlcs);
                return 0;
            }
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[dest_idx].channel_id,
                dest_ch->commitment_number, psig32, nonce_idx);
            if (!wire_send(lsp->client_fds[dest_idx], MSG_COMMITMENT_SIGNED, cs)) {
                cJSON_Delete(cs);
                free(old_dest_htlcs);
                return 0;
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
                channel_fail_htlc(dest_ch, dest_htlc_id);
                /* Notify bridge of failure */
                cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                    "client_disconnected", htlc_id);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                cJSON_Delete(fail);
                if (ack_msg.json) cJSON_Delete(ack_msg.json);
                free(old_dest_htlcs);
                return 1;  /* handled (not a fatal error) */
            }
            uint32_t ack_chan_id;
            unsigned char rev_secret[32], next_point[33];
            if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                            rev_secret, next_point)) {
                uint64_t old_cn = dest_ch->commitment_number - 1;
                channel_receive_revocation(dest_ch, old_cn, rev_secret);
                /* SF-W-PTLC #171: inline PTLC snapshot for revocation registration.
                   No-op today (n_ptlcs == 0 at all current callsites); defensive
                   for when CLN-bLIP56 (#172) wires real PTLC flow through here. */
                size_t old_dest_n_ptlcs = dest_ch->n_ptlcs;
                ptlc_t *old_dest_ptlcs = NULL;
                if (old_dest_n_ptlcs > 0) {
                    old_dest_ptlcs = malloc(old_dest_n_ptlcs * sizeof(ptlc_t));
                    if (old_dest_ptlcs)
                        memcpy(old_dest_ptlcs, dest_ch->ptlcs,
                               old_dest_n_ptlcs * sizeof(ptlc_t));
                }
                watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                    (uint32_t)dest_idx, old_cn,
                    old_dest_local, old_dest_remote,
                    old_dest_htlcs, old_dest_n_htlcs,
                    /* SF-W-PTLC #171: thread PTLC snapshot */ old_dest_ptlcs, old_dest_n_ptlcs);
                free(old_dest_ptlcs);
                secp256k1_pubkey next_pcp;
                if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                    channel_set_remote_pcp(dest_ch, dest_ch->commitment_number + 1, &next_pcp);
                /* Bidirectional: send LSP's own revocation to dest */
                lsp_send_revocation(mgr, lsp, dest_idx, old_cn);
            }
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

        /* Find the originating HTLC by request_id (outbound origins only:
           request ids start at 1 and inbound origins carry none) */
        for (size_t i = 0; request_id != 0 && i < mgr->n_htlc_origins; i++) {
            if (!mgr->htlc_origins[i].active) continue;
            if (mgr->htlc_origins[i].bridge_htlc_id != 0) continue;
            if (mgr->htlc_origins[i].request_id != request_id) continue;

            size_t client_idx = mgr->htlc_origins[i].sender_idx;
            uint64_t htlc_id_val = mgr->htlc_origins[i].sender_htlc_id;

            if (client_idx >= mgr->n_channels) break;
            channel_t *ch = &mgr->entries[client_idx].channel;

            /* A success is only a success with the preimage of the hash the
               client's HTLC is locked to.  Anything else settles nothing:
               the HTLC stays as it is and the origin stays open for the
               real result. */
            if (success) {
                unsigned char check[32];
                sha256(preimage, 32, check);
                if (memcmp(check, mgr->htlc_origins[i].payment_hash, 32) != 0) {
                    fprintf(stderr, "LSP: bridge pay result %llu ignored — "
                            "preimage does not match the payment hash\n",
                            (unsigned long long)request_id);
                    return 1;
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

                /* Fulfill the HTLC on the client's channel; the client is
                   told nothing unless that worked */
                if (!channel_fulfill_htlc(ch, htlc_id_val, preimage)) {
                    fprintf(stderr, "LSP: bridge pay result %llu ignored — "
                            "no HTLC %llu to fulfil on client %zu\n",
                            (unsigned long long)request_id,
                            (unsigned long long)htlc_id_val, client_idx);
                    free(old_htlcs);
                    return 1;
                }
                mgr->htlc_origins[i].active = 0;
                lsp_channels_note_outbound_paid(mgr,
                    mgr->htlc_origins[i].payment_hash);

                cJSON *ful = wire_build_update_fulfill_htlc(htlc_id_val, preimage);
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FULFILL_HTLC, ful);
                cJSON_Delete(ful);

                /* Sign commitment */
                unsigned char psig[32];
                uint32_t nonce_idx;
                if (channel_create_commitment_partial_sig(ch, psig, &nonce_idx)) {
                    cJSON *cs = wire_build_commitment_signed(
                        mgr->entries[client_idx].channel_id,
                        ch->commitment_number, psig, nonce_idx);
                    wire_send(lsp->client_fds[client_idx], MSG_COMMITMENT_SIGNED, cs);
                    cJSON_Delete(cs);
                }

                /* Wait for REVOKE_AND_ACK from client */
                {
                    wire_msg_t ack_msg;
                    if (wire_recv_timeout(lsp->client_fds[client_idx], &ack_msg, 30) &&
                        ack_msg.msg_type == MSG_REVOKE_AND_ACK) {
                        uint32_t ack_chan_id;
                        unsigned char rev_secret[32], next_point[33];
                        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                                        rev_secret, next_point)) {
                            uint64_t old_cn = ch->commitment_number - 1;
                            channel_receive_revocation(ch, old_cn, rev_secret);
                            /* SF-W-PTLC #171: inline PTLC snapshot for revocation registration.
                               No-op today (n_ptlcs == 0 at all current callsites); defensive
                               for when CLN-bLIP56 (#172) wires real PTLC flow through here. */
                            size_t old_n_ptlcs = ch->n_ptlcs;
                            ptlc_t *old_ptlcs = NULL;
                            if (old_n_ptlcs > 0) {
                                old_ptlcs = malloc(old_n_ptlcs * sizeof(ptlc_t));
                                if (old_ptlcs)
                                    memcpy(old_ptlcs, ch->ptlcs,
                                           old_n_ptlcs * sizeof(ptlc_t));
                            }
                            watchtower_watch_revoked_commitment(mgr->watchtower, ch,
                                (uint32_t)client_idx, old_cn,
                                old_local, old_remote,
                                old_htlcs, old_n_htlcs,
                                /* SF-W-PTLC #171: thread PTLC snapshot */ old_ptlcs, old_n_ptlcs);
                            free(old_ptlcs);
                            secp256k1_pubkey next_pcp;
                            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp,
                                                            next_point, 33))
                                channel_set_remote_pcp(ch,
                                    ch->commitment_number + 1, &next_pcp);
                            lsp_send_revocation(mgr, lsp, client_idx, old_cn);
                        }
                        cJSON_Delete(ack_msg.json);
                    } else {
                        if (ack_msg.json) cJSON_Delete(ack_msg.json);
                        fprintf(stderr, "LSP: bridge pay fulfill — "
                                "no REVOKE_AND_ACK from client %zu\n", client_idx);
                    }
                }
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

                    persist_deactivate_htlc_origin(db,
                        mgr->htlc_origins[i].payment_hash);

                    if (own_txn) persist_commit(db);
                }

                printf("LSP: bridge pay fulfilled for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id_val);
            } else {
                /* Fail the HTLC */
                if (!channel_fail_htlc(ch, htlc_id_val)) {
                    fprintf(stderr, "LSP: bridge pay result %llu ignored — "
                            "no HTLC %llu to fail on client %zu\n",
                            (unsigned long long)request_id,
                            (unsigned long long)htlc_id_val, client_idx);
                    return 1;
                }
                mgr->htlc_origins[i].active = 0;
                cJSON *fail = wire_build_update_fail_htlc(htlc_id_val, "bridge_pay_failed");
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FAIL_HTLC, fail);
                cJSON_Delete(fail);

                /* Persist balance + delete HTLC atomically */
                if (mgr->persist) {
                    persist_t *db = (persist_t *)mgr->persist;
                    int own_txn = !persist_in_transaction(db);
                    if (own_txn) persist_begin(db);

                    persist_update_channel_balance(db,
                        (uint32_t)client_idx,
                        ch->local_amount, ch->remote_amount,
                        ch->commitment_number);
                    persist_delete_htlc(db, (uint32_t)client_idx, htlc_id_val);
                    persist_deactivate_htlc_origin(db,
                        mgr->htlc_origins[i].payment_hash);

                    if (own_txn) persist_commit(db);
                }

                printf("LSP: bridge pay failed for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id_val);
            }
            break;
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
        /* Bridge heartbeat ping — send ACK back, no-op otherwise */
        {
            cJSON *ack = wire_build_bridge_hello_ack();
            wire_send(mgr->bridge_fd, MSG_BRIDGE_HELLO_ACK, ack);
            cJSON_Delete(ack);
        }
        return 1;

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
        if (origin->bridge_htlc_id == 0) continue;
        if (origin->cltv_expiry == 0) continue;

        /* Fail back if current height is within FACTORY_CLTV_DELTA_DEFAULT of expiry */
        if (current_height + FACTORY_CLTV_DELTA_DEFAULT >= origin->cltv_expiry) {
            printf("LSP: bridge HTLC timeout — height %u approaching expiry %u\n",
                   current_height, origin->cltv_expiry);

            /* Fail HTLC on destination channel to free balance */
            size_t dest_idx = origin->sender_idx;
            uint64_t dest_htlc_id = origin->sender_htlc_id;
            if (dest_idx < mgr->n_channels) {
                channel_t *ch = &mgr->entries[dest_idx].channel;
                channel_fail_htlc(ch, dest_htlc_id);
                if (mgr->persist)
                    persist_delete_htlc((persist_t *)mgr->persist,
                                        (uint32_t)dest_idx, dest_htlc_id);
                if (lsp && lsp->client_fds[dest_idx] >= 0) {
                    cJSON *cf = wire_build_update_fail_htlc(dest_htlc_id,
                        "htlc_timeout");
                    wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_FAIL_HTLC, cf);
                    cJSON_Delete(cf);
                }
            }

            /* Send BRIDGE_FAIL_HTLC to bridge if connected */
            if (mgr->bridge_fd >= 0) {
                cJSON *fail = wire_build_bridge_fail_htlc(origin->payment_hash,
                    "htlc_timeout", origin->bridge_htlc_id);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                cJSON_Delete(fail);
            }

            origin->active = 0;
            if (mgr->persist)
                persist_deactivate_htlc_origin((persist_t *)mgr->persist,
                                                origin->payment_hash);
        }
    }
}
