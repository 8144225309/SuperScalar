/* Bridge/invoice support extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/persist.h"
#include <stdio.h>
#include <string.h>

void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd) {
    mgr->bridge_fd = bridge_fd;
}

int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    const unsigned char *preimage32,
                                    size_t dest_client, uint64_t amount_msat) {
    if (mgr->n_invoices >= MAX_INVOICE_REGISTRY) return 0;
    if (dest_client >= mgr->n_channels) return 0;

    invoice_entry_t *inv = &mgr->invoices[mgr->n_invoices++];
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

void lsp_channels_track_bridge_origin(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t bridge_htlc_id) {
    if (mgr->n_htlc_origins >= MAX_HTLC_ORIGINS) return;
    htlc_origin_t *origin = &mgr->htlc_origins[mgr->n_htlc_origins++];
    memcpy(origin->payment_hash, payment_hash32, 32);
    origin->bridge_htlc_id = bridge_htlc_id;
    origin->cltv_expiry = 0;
    origin->active = 1;

    if (mgr->persist)
        persist_save_htlc_origin((persist_t *)mgr->persist, payment_hash32,
                                  bridge_htlc_id, 0, 0, 0);
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
        if (!wire_parse_bridge_add_htlc(msg->json, payment_hash,
                                          &amount_msat, &cltv_expiry, &htlc_id))
            return 0;

        /* Look up invoice to find dest_client */
        size_t dest_idx;
        if (!lsp_channels_lookup_invoice(mgr, payment_hash, &dest_idx)) {
            /* Unknown payment hash — fail back to bridge */
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "unknown_payment_hash", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC unknown hash, failing back\n");
            return 1;
        }

        uint64_t amount_sats = amount_msat / 1000;
        if (amount_sats == 0) return 0;

        channel_t *dest_ch = &mgr->entries[dest_idx].channel;

        /* Capture amounts and HTLC state before add_htlc changes them (for watchtower) */
        uint64_t old_dest_local = dest_ch->local_amount;
        uint64_t old_dest_remote = dest_ch->remote_amount;
        size_t old_dest_n_htlcs = dest_ch->n_htlcs;
        htlc_t old_dest_htlcs[MAX_HTLCS];
        if (old_dest_n_htlcs > 0)
            memcpy(old_dest_htlcs, dest_ch->htlcs, old_dest_n_htlcs * sizeof(htlc_t));

        /* Add HTLC to destination's channel (offered from LSP) */
        uint64_t dest_htlc_id;
        if (!channel_add_htlc(dest_ch, HTLC_OFFERED, amount_sats,
                               payment_hash, cltv_expiry, &dest_htlc_id)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "insufficient_funds", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            return 1;
        }

        /* Track bridge origin for back-propagation (with cltv for timeout) */
        lsp_channels_track_bridge_origin(mgr, payment_hash, htlc_id);
        /* Store cltv_expiry and dest info for timeout cleanup */
        if (mgr->n_htlc_origins > 0) {
            htlc_origin_t *org = &mgr->htlc_origins[mgr->n_htlc_origins - 1];
            org->cltv_expiry = cltv_expiry;
            org->sender_idx = dest_idx;
            org->sender_htlc_id = dest_htlc_id;
        }

        /* Forward ADD_HTLC to destination client */
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            return 0;
        }
        cJSON_Delete(fwd);

        /* Send COMMITMENT_SIGNED to dest */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx))
                return 0;
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[dest_idx].channel_id,
                dest_ch->commitment_number, psig32, nonce_idx);
            if (!wire_send(lsp->client_fds[dest_idx], MSG_COMMITMENT_SIGNED, cs)) {
                cJSON_Delete(cs);
                return 0;
            }
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from dest */
        {
            wire_msg_t ack_msg;
            if (!wire_recv(lsp->client_fds[dest_idx], &ack_msg) ||
                ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
                if (ack_msg.json) cJSON_Delete(ack_msg.json);
                return 0;
            }
            uint32_t ack_chan_id;
            unsigned char rev_secret[32], next_point[33];
            if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                            rev_secret, next_point)) {
                uint64_t old_cn = dest_ch->commitment_number - 1;
                channel_receive_revocation(dest_ch, old_cn, rev_secret);
                watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                    (uint32_t)dest_idx, old_cn,
                    old_dest_local, old_dest_remote,
                    old_dest_htlcs, old_dest_n_htlcs);
                secp256k1_pubkey next_pcp;
                if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                    channel_set_remote_pcp(dest_ch, dest_ch->commitment_number + 1, &next_pcp);
                /* Bidirectional: send LSP's own revocation to dest */
                lsp_send_revocation(mgr, lsp, dest_idx, old_cn);
            }
            cJSON_Delete(ack_msg.json);
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
        if (!wire_parse_bridge_pay_result(msg->json, &request_id, &success,
                                            preimage))
            return 0;

        printf("LSP: bridge pay result: request_id=%llu success=%d\n",
               (unsigned long long)request_id, success);

        /* Find the originating HTLC by request_id */
        for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
            if (!mgr->htlc_origins[i].active) continue;
            if (mgr->htlc_origins[i].request_id != request_id) continue;

            size_t client_idx = mgr->htlc_origins[i].sender_idx;
            uint64_t htlc_id_val = mgr->htlc_origins[i].sender_htlc_id;
            mgr->htlc_origins[i].active = 0;

            if (client_idx >= mgr->n_channels) break;
            channel_t *ch = &mgr->entries[client_idx].channel;

            if (success) {
                /* Fulfill the HTLC on the client's channel */
                channel_fulfill_htlc(ch, htlc_id_val, preimage);

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

                printf("LSP: bridge pay fulfilled for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id_val);
            } else {
                /* Fail the HTLC */
                channel_fail_htlc(ch, htlc_id_val);
                /* Delete failed HTLC from persistence */
                if (mgr->persist)
                    persist_delete_htlc((persist_t *)mgr->persist,
                                          (uint32_t)client_idx, htlc_id_val);
                cJSON *fail = wire_build_update_fail_htlc(htlc_id_val, "bridge_pay_failed");
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FAIL_HTLC, fail);
                cJSON_Delete(fail);

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

        /* Fail back if current height is within FACTORY_CLTV_DELTA of expiry */
        if (current_height + FACTORY_CLTV_DELTA >= origin->cltv_expiry) {
            printf("LSP: bridge HTLC timeout — height %u approaching expiry %u\n",
                   current_height, origin->cltv_expiry);

            /* Fail HTLC on destination channel to free balance */
            size_t dest_idx = origin->sender_idx;
            uint64_t dest_htlc_id = origin->sender_htlc_id;
            if (dest_idx < mgr->n_channels) {
                channel_t *ch = &mgr->entries[dest_idx].channel;
                channel_fail_htlc(ch, dest_htlc_id);
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
