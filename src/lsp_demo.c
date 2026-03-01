/* Demo mode + payment initiation extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/persist.h"
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

void lsp_channels_print_balances(const lsp_channel_mgr_t *mgr) {
    if (!mgr) return;
    printf("\n  Channel | Client | Local (sats) | Remote (sats)\n");
    printf("  --------+--------+--------------+--------------\n");
    for (size_t c = 0; c < mgr->n_channels; c++) {
        const channel_t *ch = &mgr->entries[c].channel;
        printf("    %zu     |   %zu    |  %10llu  |  %10llu\n",
               c, c + 1,
               (unsigned long long)ch->local_amount,
               (unsigned long long)ch->remote_amount);
    }
    printf("\n");
}

/* Wait for a specific message type from a client fd, processing
   MSG_REGISTER_INVOICE messages that may arrive before the expected one.
   Returns 1 on success with msg filled, 0 on error. */
static int wait_for_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                          int fd, uint8_t expected_type, wire_msg_t *msg,
                          int timeout_sec) {
    (void)lsp;
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        gettimeofday(&now, NULL);
        int elapsed = (int)(now.tv_sec - start.tv_sec);
        int remaining = timeout_sec - elapsed;
        if (remaining <= 0) return 0;

        struct timeval tv = { .tv_sec = remaining, .tv_usec = 0 };
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) return 0;

        if (!wire_recv(fd, msg)) return 0;

        if (msg->msg_type == expected_type)
            return 1;

        /* Handle MSG_REGISTER_INVOICE that arrives before INVOICE_CREATED */
        if (msg->msg_type == MSG_REGISTER_INVOICE) {
            unsigned char ph[32], pre[32];
            uint64_t am;
            size_t dc;
            if (wire_parse_register_invoice(msg->json, ph, pre, &am, &dc))
                lsp_channels_register_invoice(mgr, ph, pre, dc, am);
            cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;
        }

        /* Unexpected message — skip */
        fprintf(stderr, "LSP demo: expected 0x%02x, got 0x%02x (skipping)\n",
                expected_type, msg->msg_type);
        cJSON_Delete(msg->json);
        msg->json = NULL;
    }
}

int lsp_channels_initiate_payment(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                    size_t from_client, size_t to_client,
                                    uint64_t amount_sats) {
    if (!mgr || !lsp) return 0;
    if (from_client >= mgr->n_channels || to_client >= mgr->n_channels) return 0;
    if (from_client == to_client) return 0;

    uint64_t amount_msat = amount_sats * 1000;

    /* 1. Send MSG_CREATE_INVOICE to receiving client */
    {
        cJSON *inv_req = wire_build_create_invoice(amount_msat);
        if (!wire_send(lsp->client_fds[to_client], MSG_CREATE_INVOICE, inv_req)) {
            cJSON_Delete(inv_req);
            fprintf(stderr, "LSP demo: send CREATE_INVOICE failed\n");
            return 0;
        }
        cJSON_Delete(inv_req);
    }

    /* 2. Wait for MSG_INVOICE_CREATED from receiver */
    unsigned char payment_hash[32];
    {
        wire_msg_t inv_resp;
        if (!wait_for_msg(mgr, lsp, lsp->client_fds[to_client],
                            MSG_INVOICE_CREATED, &inv_resp, 10)) {
            fprintf(stderr, "LSP demo: timeout waiting for INVOICE_CREATED\n");
            return 0;
        }
        uint64_t resp_amount;
        if (!wire_parse_invoice_created(inv_resp.json, payment_hash, &resp_amount)) {
            cJSON_Delete(inv_resp.json);
            fprintf(stderr, "LSP demo: bad INVOICE_CREATED\n");
            return 0;
        }
        cJSON_Delete(inv_resp.json);
    }

    /* 3. Drain any pending MSG_REGISTER_INVOICE from receiver */
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsp->client_fds[to_client], &rfds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 }; /* 200ms */
        while (select(lsp->client_fds[to_client] + 1, &rfds, NULL, NULL, &tv) > 0) {
            wire_msg_t drain_msg;
            if (!wire_recv(lsp->client_fds[to_client], &drain_msg)) break;
            if (drain_msg.msg_type == MSG_REGISTER_INVOICE) {
                unsigned char ph[32], pre[32];
                uint64_t am;
                size_t dc;
                if (wire_parse_register_invoice(drain_msg.json, ph, pre, &am, &dc))
                    lsp_channels_register_invoice(mgr, ph, pre, dc, am);
            }
            cJSON_Delete(drain_msg.json);
            FD_ZERO(&rfds);
            FD_SET(lsp->client_fds[to_client], &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
        }
    }

    /* 4. Add HTLC on sender's channel (HTLC_RECEIVED from LSP perspective) */
    channel_t *sender_ch = &mgr->entries[from_client].channel;

    /* Capture amounts and HTLC state before add_htlc changes them (for watchtower) */
    uint64_t old_sender_local = sender_ch->local_amount;
    uint64_t old_sender_remote = sender_ch->remote_amount;
    size_t old_sender_n_htlcs = sender_ch->n_htlcs;
    htlc_t old_sender_htlcs[MAX_HTLCS];
    if (old_sender_n_htlcs > 0)
        memcpy(old_sender_htlcs, sender_ch->htlcs, old_sender_n_htlcs * sizeof(htlc_t));

    uint64_t sender_htlc_id;
    if (!channel_add_htlc(sender_ch, HTLC_RECEIVED, amount_sats,
                           payment_hash, 500, &sender_htlc_id)) {
        fprintf(stderr, "LSP demo: add_htlc on sender failed\n");
        return 0;
    }

    /* 5. Send ADD_HTLC + COMMITMENT_SIGNED to sender */
    {
        cJSON *add = wire_build_update_add_htlc(sender_htlc_id, amount_msat,
                                                   payment_hash, 500);
        /* Add dest_client field so sender knows where it's going */
        cJSON_AddNumberToObject(add, "dest_client", (double)to_client);
        if (!wire_send(lsp->client_fds[from_client], MSG_UPDATE_ADD_HTLC, add)) {
            cJSON_Delete(add);
            return 0;
        }
        cJSON_Delete(add);
    }
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx))
            return 0;
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[from_client].channel_id,
            sender_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[from_client], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* 6. Wait for REVOKE_AND_ACK from sender */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[from_client], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP demo: expected REVOKE_AND_ACK from sender\n");
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = sender_ch->commitment_number - 1;
            channel_receive_revocation(sender_ch, old_cn, rev_secret);
            watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                (uint32_t)from_client, old_cn,
                old_sender_local, old_sender_remote,
                old_sender_htlcs, old_sender_n_htlcs);
            secp256k1_pubkey next_pcp;
            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                channel_set_remote_pcp(sender_ch, sender_ch->commitment_number + 1, &next_pcp);
            /* Bidirectional: send LSP's own revocation to sender */
            lsp_send_revocation(mgr, lsp, from_client, old_cn);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* 7. Forward HTLC to destination client */
    channel_t *dest_ch = &mgr->entries[to_client].channel;

    /* Capture amounts and HTLC state before add_htlc changes them (for watchtower) */
    uint64_t old_dest_local = dest_ch->local_amount;
    uint64_t old_dest_remote = dest_ch->remote_amount;
    size_t old_dest_n_htlcs = dest_ch->n_htlcs;
    htlc_t old_dest_htlcs[MAX_HTLCS];
    if (old_dest_n_htlcs > 0)
        memcpy(old_dest_htlcs, dest_ch->htlcs, old_dest_n_htlcs * sizeof(htlc_t));

    uint64_t dest_htlc_id;
    if (!channel_add_htlc(dest_ch, HTLC_OFFERED, amount_sats,
                           payment_hash, 500, &dest_htlc_id)) {
        fprintf(stderr, "LSP demo: forward add_htlc failed\n");
        return 0;
    }

    {
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, 500);
        if (!wire_send(lsp->client_fds[to_client], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            return 0;
        }
        cJSON_Delete(fwd);
    }
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx))
            return 0;
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[to_client].channel_id,
            dest_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[to_client], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* 8. Wait for REVOKE_AND_ACK from dest */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[to_client], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP demo: expected REVOKE_AND_ACK from dest\n");
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = dest_ch->commitment_number - 1;
            channel_receive_revocation(dest_ch, old_cn, rev_secret);
            watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                (uint32_t)to_client, old_cn,
                old_dest_local, old_dest_remote,
                old_dest_htlcs, old_dest_n_htlcs);
            secp256k1_pubkey next_pcp;
            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                channel_set_remote_pcp(dest_ch, dest_ch->commitment_number + 1, &next_pcp);
            /* Bidirectional: send LSP's own revocation to dest */
            lsp_send_revocation(mgr, lsp, to_client, old_cn);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* 9. Wait for FULFILL_HTLC from dest (client fulfills with real preimage) */
    {
        wire_msg_t ful_msg;
        if (!wire_recv(lsp->client_fds[to_client], &ful_msg) ||
            ful_msg.msg_type != MSG_UPDATE_FULFILL_HTLC) {
            if (ful_msg.json) cJSON_Delete(ful_msg.json);
            fprintf(stderr, "LSP demo: expected FULFILL from dest\n");
            return 0;
        }
        uint64_t ful_htlc_id;
        unsigned char preimage[32];
        if (!wire_parse_update_fulfill_htlc(ful_msg.json, &ful_htlc_id, preimage)) {
            cJSON_Delete(ful_msg.json);
            return 0;
        }
        cJSON_Delete(ful_msg.json);

        /* Capture amounts and HTLC state before fulfill changes them (for watchtower) */
        uint64_t old_dest_ful_local = dest_ch->local_amount;
        uint64_t old_dest_ful_remote = dest_ch->remote_amount;
        size_t old_dest_ful_n_htlcs = dest_ch->n_htlcs;
        htlc_t old_dest_ful_htlcs[MAX_HTLCS];
        if (old_dest_ful_n_htlcs > 0)
            memcpy(old_dest_ful_htlcs, dest_ch->htlcs, old_dest_ful_n_htlcs * sizeof(htlc_t));

        /* Fulfill on dest channel */
        channel_fulfill_htlc(dest_ch, ful_htlc_id, preimage);

        /* Send COMMITMENT_SIGNED to dest */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx))
                return 0;
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[to_client].channel_id,
                dest_ch->commitment_number, psig32, nonce_idx);
            wire_send(lsp->client_fds[to_client], MSG_COMMITMENT_SIGNED, cs);
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from dest */
        {
            wire_msg_t ack;
            if (wire_recv(lsp->client_fds[to_client], &ack) &&
                ack.msg_type == MSG_REVOKE_AND_ACK) {
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = dest_ch->commitment_number - 1;
                    channel_receive_revocation(dest_ch, old_cn, rev_secret);
                    watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                        (uint32_t)to_client, old_cn,
                        old_dest_ful_local, old_dest_ful_remote,
                        old_dest_ful_htlcs, old_dest_ful_n_htlcs);
                    secp256k1_pubkey next_pcp;
                    if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                        channel_set_remote_pcp(dest_ch, dest_ch->commitment_number + 1, &next_pcp);
                    /* Bidirectional: send LSP's own revocation to dest */
                    lsp_send_revocation(mgr, lsp, to_client, old_cn);
                }
            }
            if (ack.json) cJSON_Delete(ack.json);
        }

        /* 10. Back-propagate fulfill to sender */
        uint64_t old_sender_ful_local = sender_ch->local_amount;
        uint64_t old_sender_ful_remote = sender_ch->remote_amount;
        size_t old_sender_ful_n_htlcs = sender_ch->n_htlcs;
        htlc_t old_sender_ful_htlcs[MAX_HTLCS];
        if (old_sender_ful_n_htlcs > 0)
            memcpy(old_sender_ful_htlcs, sender_ch->htlcs, old_sender_ful_n_htlcs * sizeof(htlc_t));
        channel_fulfill_htlc(sender_ch, sender_htlc_id, preimage);

        cJSON *ful_fwd = wire_build_update_fulfill_htlc(sender_htlc_id, preimage);
        wire_send(lsp->client_fds[from_client], MSG_UPDATE_FULFILL_HTLC, ful_fwd);
        cJSON_Delete(ful_fwd);

        /* Send COMMITMENT_SIGNED to sender */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx))
                return 0;
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[from_client].channel_id,
                sender_ch->commitment_number, psig32, nonce_idx);
            wire_send(lsp->client_fds[from_client], MSG_COMMITMENT_SIGNED, cs);
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from sender */
        {
            wire_msg_t ack;
            if (wire_recv(lsp->client_fds[from_client], &ack) &&
                ack.msg_type == MSG_REVOKE_AND_ACK) {
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = sender_ch->commitment_number - 1;
                    channel_receive_revocation(sender_ch, old_cn, rev_secret);
                    watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                        (uint32_t)from_client, old_cn,
                        old_sender_ful_local, old_sender_ful_remote,
                        old_sender_ful_htlcs, old_sender_ful_n_htlcs);
                    secp256k1_pubkey next_pcp;
                    if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                        channel_set_remote_pcp(sender_ch, sender_ch->commitment_number + 1, &next_pcp);
                    /* Bidirectional: send LSP's own revocation to sender */
                    lsp_send_revocation(mgr, lsp, from_client, old_cn);
                }
            }
            if (ack.json) cJSON_Delete(ack.json);
        }
    }

    printf("  Payment complete: client %zu -> client %zu (%llu sats)\n",
           from_client + 1, to_client + 1, (unsigned long long)amount_sats);
    return 1;
}

int lsp_channels_create_external_invoice(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                          size_t client_idx, uint64_t amount_msat) {
    if (!mgr || !lsp) return 0;
    if (client_idx >= mgr->n_channels) return 0;

    /* 1. Send MSG_CREATE_INVOICE to target client */
    {
        cJSON *inv_req = wire_build_create_invoice(amount_msat);
        if (!wire_send(lsp->client_fds[client_idx], MSG_CREATE_INVOICE, inv_req)) {
            cJSON_Delete(inv_req);
            fprintf(stderr, "LSP: send CREATE_INVOICE failed\n");
            return 0;
        }
        cJSON_Delete(inv_req);
    }

    /* 2. Wait for MSG_INVOICE_CREATED from client */
    unsigned char payment_hash[32];
    {
        wire_msg_t inv_resp;
        if (!wait_for_msg(mgr, lsp, lsp->client_fds[client_idx],
                            MSG_INVOICE_CREATED, &inv_resp, 10)) {
            fprintf(stderr, "LSP: timeout waiting for INVOICE_CREATED\n");
            return 0;
        }
        uint64_t resp_amount;
        if (!wire_parse_invoice_created(inv_resp.json, payment_hash, &resp_amount)) {
            cJSON_Delete(inv_resp.json);
            fprintf(stderr, "LSP: bad INVOICE_CREATED\n");
            return 0;
        }
        cJSON_Delete(inv_resp.json);
    }

    /* 3. Drain any pending MSG_REGISTER_INVOICE from client */
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsp->client_fds[client_idx], &rfds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
        while (select(lsp->client_fds[client_idx] + 1, &rfds, NULL, NULL, &tv) > 0) {
            wire_msg_t drain_msg;
            if (!wire_recv(lsp->client_fds[client_idx], &drain_msg)) break;
            if (drain_msg.msg_type == MSG_REGISTER_INVOICE) {
                unsigned char ph[32], pre[32];
                uint64_t am;
                size_t dc;
                if (wire_parse_register_invoice(drain_msg.json, ph, pre, &am, &dc))
                    lsp_channels_register_invoice(mgr, ph, pre, dc, am);
            }
            cJSON_Delete(drain_msg.json);
            FD_ZERO(&rfds);
            FD_SET(lsp->client_fds[client_idx], &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
        }
    }

    /* 4. Forward the just-registered invoice to bridge */
    if (mgr->bridge_fd >= 0) {
        /* Find the invoice entry to get preimage and amount */
        for (size_t i = 0; i < mgr->n_invoices; i++) {
            if (!mgr->invoices[i].active) continue;
            if (memcmp(mgr->invoices[i].payment_hash, payment_hash, 32) == 0) {
                cJSON *reg = wire_build_bridge_register(
                    payment_hash, mgr->invoices[i].preimage,
                    mgr->invoices[i].amount_msat, mgr->invoices[i].dest_client);
                wire_send(mgr->bridge_fd, MSG_BRIDGE_REGISTER, reg);
                cJSON_Delete(reg);
                printf("LSP: forwarded external invoice to bridge (client %zu, %llu msat)\n",
                       client_idx, (unsigned long long)amount_msat);
                return 1;
            }
        }
        fprintf(stderr, "LSP: invoice registered but not found for bridge forward\n");
        return 0;
    }

    fprintf(stderr, "LSP: no bridge connected for external invoice\n");
    return 0;
}

int lsp_channels_batch_rebalance(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   const rebalance_entry_t *entries, size_t n_entries) {
    if (!mgr || !lsp || !entries || n_entries == 0) return 0;

    printf("--- Batch rebalance: %zu transfers ---\n", n_entries);
    int successes = 0;
    for (size_t i = 0; i < n_entries; i++) {
        printf("  [%zu/%zu] client %zu -> client %zu (%llu sats): ",
               i + 1, n_entries, entries[i].from, entries[i].to,
               (unsigned long long)entries[i].amount_sats);
        fflush(stdout);
        if (lsp_channels_initiate_payment(mgr, lsp, entries[i].from,
                entries[i].to, entries[i].amount_sats)) {
            printf("OK\n");
            successes++;
        } else {
            printf("FAILED\n");
        }
    }
    printf("--- Batch rebalance complete: %d/%zu succeeded ---\n",
           successes, n_entries);
    return successes;
}

int lsp_channels_auto_rebalance(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;
    int rebalanced = 0;
    uint16_t threshold = mgr->rebalance_threshold_pct;
    if (threshold == 0 || threshold > 99) threshold = 80; /* default 80% */

    for (size_t c = 0; c < mgr->n_channels; c++) {
        channel_t *ch = &mgr->entries[c].channel;
        uint64_t total = ch->local_amount + ch->remote_amount;
        if (total == 0) continue;

        /* Check if channel is imbalanced (exceeds threshold on one side) */
        uint64_t pct_local = (ch->local_amount * 100) / total;
        if (pct_local > threshold) {
            /* LSP-heavy: move balance to a light channel */
            uint64_t excess = ch->local_amount - (total / 2);
            /* Find lightest LSP-side channel to receive */
            size_t lightest = c;
            uint64_t lightest_local = UINT64_MAX;
            for (size_t j = 0; j < mgr->n_channels; j++) {
                if (j == c) continue;
                uint64_t jl = mgr->entries[j].channel.local_amount;
                if (jl < lightest_local) {
                    lightest_local = jl;
                    lightest = j;
                }
            }
            if (lightest != c && excess > 0) {
                printf("Auto-rebalance: client %zu -> client %zu (%llu sats)\n",
                       c, lightest, (unsigned long long)excess);
                if (lsp_channels_initiate_payment(mgr, lsp, c, lightest, excess))
                    rebalanced++;
            }
        }
    }
    return rebalanced;
}

int lsp_channels_run_demo_sequence(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    printf("\n");
    printf("======================================================\n");
    printf("  SuperScalar Factory Demo - Payment Sequence\n");
    printf("======================================================\n");
    printf("\n");

    printf("Factory created with %zu channels (1 LSP + %zu clients)\n",
           mgr->n_channels, mgr->n_channels);
    printf("Initial balances:\n");
    lsp_channels_print_balances(mgr);

    if (mgr->n_channels >= 4) {
        /* 4-client demo: cross-payment circuit */
        printf("--- Payment 1: Client 1 -> Client 2 (1,000 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 0, 1, 1000)) {
            fprintf(stderr, "LSP demo: payment 1 failed\n");
            return 0;
        }
        lsp_channels_print_balances(mgr);

        printf("--- Payment 2: Client 3 -> Client 1 (1,500 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 2, 0, 1500)) {
            fprintf(stderr, "LSP demo: payment 2 failed\n");
            return 0;
        }
        lsp_channels_print_balances(mgr);

        printf("--- Payment 3: Client 4 -> Client 3 (2,000 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 3, 2, 2000)) {
            fprintf(stderr, "LSP demo: payment 3 failed\n");
            return 0;
        }
        lsp_channels_print_balances(mgr);

        printf("--- Payment 4: Client 2 -> Client 4 (1,000 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 1, 3, 1000)) {
            fprintf(stderr, "LSP demo: payment 4 failed\n");
            return 0;
        }
    } else if (mgr->n_channels >= 2) {
        /* 2-client demo: back-and-forth payments */
        printf("--- Payment 1: Client 1 -> Client 2 (1,000 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 0, 1, 1000)) {
            fprintf(stderr, "LSP demo: payment 1 failed\n");
            return 0;
        }
        lsp_channels_print_balances(mgr);

        printf("--- Payment 2: Client 2 -> Client 1 (1,500 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 1, 0, 1500)) {
            fprintf(stderr, "LSP demo: payment 2 failed\n");
            return 0;
        }
        lsp_channels_print_balances(mgr);

        printf("--- Payment 3: Client 1 -> Client 2 (2,000 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 0, 1, 2000)) {
            fprintf(stderr, "LSP demo: payment 3 failed\n");
            return 0;
        }
        lsp_channels_print_balances(mgr);

        printf("--- Payment 4: Client 2 -> Client 1 (500 sats) ---\n");
        if (!lsp_channels_initiate_payment(mgr, lsp, 1, 0, 500)) {
            fprintf(stderr, "LSP demo: payment 4 failed\n");
            return 0;
        }
    } else if (mgr->n_channels == 1) {
        printf("Only 1 channel — no inter-client payments possible.\n");
    }

    printf("\n");
    printf("======================================================\n");
    printf("  Demo Complete - Final Balances\n");
    printf("======================================================\n");
    lsp_channels_print_balances(mgr);

    return 1;
}
