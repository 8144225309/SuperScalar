#include "superscalar/lsp_channels.h"
#include "superscalar/jit_channel.h"
#include "superscalar/fee.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/ladder.h"
#include "superscalar/regtest.h"
#include "superscalar/adaptor.h"
#include "superscalar/musig.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);

/* watch_revoked_commitment moved to watchtower.c as watchtower_watch_revoked_commitment() */

/* Send the LSP's own revocation secret to a client after each commitment update.
   This enables bidirectional revocation so clients can detect LSP breaches.
   old_cn: the commitment number whose secret is being revealed. */
static void lsp_send_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t client_idx, uint64_t old_cn) {
    if (!mgr || !lsp || client_idx >= mgr->n_channels) return;

    channel_t *ch = &mgr->entries[client_idx].channel;

    /* Get LSP's old per-commitment secret (local PCS) */
    unsigned char lsp_rev_secret[32];
    if (!channel_get_revocation_secret(ch, old_cn, lsp_rev_secret))
        return;

    /* Get LSP's next per-commitment point */
    secp256k1_pubkey next_pcp;
    if (!channel_get_per_commitment_point(ch, ch->commitment_number + 1, &next_pcp)) {
        memset(lsp_rev_secret, 0, 32);
        return;
    }

    /* Build and send using same format as REVOKE_AND_ACK but with LSP type */
    cJSON *j = wire_build_revoke_and_ack(
        mgr->entries[client_idx].channel_id,
        lsp_rev_secret, mgr->ctx, &next_pcp);
    wire_send(lsp->client_fds[client_idx], MSG_LSP_REVOKE_AND_ACK, j);
    cJSON_Delete(j);

    memset(lsp_rev_secret, 0, 32);
}

/*
 * Factory tree layout (5 participants: LSP=0, A=1, B=2, C=3, D=4):
 *   node[0] = kickoff_root (5-of-5)
 *   node[1] = state_root   (5-of-5)
 *   node[2] = kickoff_left (3-of-3: LSP,A,B)
 *   node[3] = kickoff_right(3-of-3: LSP,C,D)
 *   node[4] = state_left   (3-of-3) -> outputs: [chan_A, chan_B, L_stock]
 *   node[5] = state_right  (3-of-3) -> outputs: [chan_C, chan_D, L_stock]
 *
 * Channel mapping:
 *   client 0 (A): node[4].txid, vout=0
 *   client 1 (B): node[4].txid, vout=1
 *   client 2 (C): node[5].txid, vout=0
 *   client 3 (D): node[5].txid, vout=1
 */

/* Map client index (0-based) to factory state node and vout.
   Uses factory's leaf_node_indices[] for arity-agnostic lookup. */
static void client_to_leaf(size_t client_idx, const factory_t *factory,
                            size_t *node_idx_out, uint32_t *vout_out) {
    if (factory->leaf_arity == FACTORY_ARITY_1) {
        /* Arity-1: each client has its own leaf node, channel at vout 0 */
        *node_idx_out = (client_idx < (size_t)factory->n_leaf_nodes)
            ? factory->leaf_node_indices[client_idx] : 0;
        *vout_out = 0;
    } else {
        /* Arity-2: 2 clients share a leaf node */
        if (client_idx < 2) {
            *node_idx_out = factory->leaf_node_indices[0];
            *vout_out = (uint32_t)client_idx;
        } else {
            *node_idx_out = factory->leaf_node_indices[1];
            *vout_out = (uint32_t)(client_idx - 2);
        }
    }
}

int lsp_channels_init(lsp_channel_mgr_t *mgr,
                       secp256k1_context *ctx,
                       const factory_t *factory,
                       const unsigned char *lsp_seckey32,
                       size_t n_clients) {
    if (!mgr || !ctx || !factory || !lsp_seckey32) return 0;
    if (n_clients == 0 || n_clients > LSP_MAX_CLIENTS) return 0;

    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx = ctx;
    mgr->n_channels = n_clients;
    mgr->bridge_fd = -1;
    mgr->n_invoices = 0;
    mgr->n_htlc_origins = 0;
    mgr->next_request_id = 1;
    mgr->leaf_arity = factory->leaf_arity;

    for (size_t c = 0; c < n_clients; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];
        entry->channel_id = (uint32_t)c;
        entry->ready = 0;
        entry->last_message_time = time(NULL);
        entry->offline_detected = 0;

        /* Find leaf output for this client */
        size_t node_idx;
        uint32_t vout;
        client_to_leaf(c, factory, &node_idx, &vout);

        const factory_node_t *state_node = &factory->nodes[node_idx];
        if (vout >= state_node->n_outputs) return 0;

        /* Funding info from the leaf output */
        const unsigned char *funding_txid = state_node->txid;  /* internal byte order */
        uint64_t funding_amount = state_node->outputs[vout].amount_sats;
        const unsigned char *funding_spk = state_node->outputs[vout].script_pubkey;
        size_t funding_spk_len = state_node->outputs[vout].script_pubkey_len;

        /* LSP pubkey (participant 0) */
        secp256k1_pubkey lsp_pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &lsp_pubkey, lsp_seckey32))
            return 0;

        /* Client pubkey (participant c+1) */
        const secp256k1_pubkey *client_pubkey = &factory->pubkeys[c + 1];

        /* Commitment tx fee: base 154 vB (dynamic with HTLCs via fee module). */
        fee_estimator_t _fe;
        fee_init(&_fe, 1000);
        uint64_t commit_fee = fee_for_commitment_tx(&_fe, 0);
        uint64_t usable = funding_amount > commit_fee ? funding_amount - commit_fee : 0;
        uint64_t local_amount = usable / 2;
        uint64_t remote_amount = usable - local_amount;

        /* Initialize channel: LSP = local, client = remote */
        if (!channel_init(&entry->channel, ctx,
                           lsp_seckey32,
                           &lsp_pubkey,
                           client_pubkey,
                           funding_txid, vout,
                           funding_amount,
                           funding_spk, funding_spk_len,
                           local_amount, remote_amount,
                           CHANNEL_DEFAULT_CSV_DELAY))
            return 0;
        entry->channel.funder_is_local = 1;  /* LSP is funder and local */

        /* Generate random basepoint secrets */
        if (!channel_generate_random_basepoints(&entry->channel)) {
            fprintf(stderr, "LSP: random basepoint generation failed for channel %zu\n", c);
            return 0;
        }

        /* Remote basepoints are left zeroed here.
           They will be populated by lsp_channels_exchange_basepoints()
           which exchanges MSG_CHANNEL_BASEPOINTS with each client. */

        /* Initialize nonce pool for commitment signing (Phase 12) */
        if (!channel_init_nonce_pool(&entry->channel, MUSIG_NONCE_POOL_MAX))
            return 0;
    }

    return 1;
}

int lsp_channels_init_from_db(lsp_channel_mgr_t *mgr,
                               secp256k1_context *ctx,
                               const factory_t *factory,
                               const unsigned char *lsp_seckey32,
                               size_t n_clients,
                               void *db) {
    persist_t *pdb = (persist_t *)db;
    if (!mgr || !ctx || !factory || !lsp_seckey32 || !pdb) return 0;
    if (n_clients == 0 || n_clients > LSP_MAX_CLIENTS) return 0;

    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx = ctx;
    mgr->n_channels = n_clients;
    mgr->bridge_fd = -1;
    mgr->n_invoices = 0;
    mgr->n_htlc_origins = 0;
    mgr->next_request_id = 1;
    mgr->leaf_arity = factory->leaf_arity;

    for (size_t c = 0; c < n_clients; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];
        entry->channel_id = (uint32_t)c;
        entry->ready = 0;
        entry->last_message_time = time(NULL);
        entry->offline_detected = 0;

        /* Find leaf output for this client */
        size_t node_idx;
        uint32_t vout;
        client_to_leaf(c, factory, &node_idx, &vout);

        const factory_node_t *state_node = &factory->nodes[node_idx];
        if (vout >= state_node->n_outputs) return 0;

        /* Funding info from the leaf output */
        const unsigned char *funding_txid = state_node->txid;
        uint64_t funding_amount = state_node->outputs[vout].amount_sats;
        const unsigned char *funding_spk = state_node->outputs[vout].script_pubkey;
        size_t funding_spk_len = state_node->outputs[vout].script_pubkey_len;

        /* LSP pubkey (participant 0) */
        secp256k1_pubkey lsp_pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &lsp_pubkey, lsp_seckey32))
            return 0;

        /* Client pubkey (participant c+1) */
        const secp256k1_pubkey *client_pubkey = &factory->pubkeys[c + 1];

        /* Commitment tx fee */
        fee_estimator_t _fe;
        fee_init(&_fe, 1000);
        uint64_t commit_fee = fee_for_commitment_tx(&_fe, 0);
        uint64_t usable = funding_amount > commit_fee ? funding_amount - commit_fee : 0;
        uint64_t local_amount = usable / 2;
        uint64_t remote_amount = usable - local_amount;

        /* Initialize channel: LSP = local, client = remote */
        if (!channel_init(&entry->channel, ctx,
                           lsp_seckey32,
                           &lsp_pubkey,
                           client_pubkey,
                           funding_txid, vout,
                           funding_amount,
                           funding_spk, funding_spk_len,
                           local_amount, remote_amount,
                           CHANNEL_DEFAULT_CSV_DELAY))
            return 0;
        entry->channel.funder_is_local = 1;

        /* Load basepoints from DB instead of generating random ones */
        unsigned char local_secrets[4][32];
        unsigned char remote_bps[4][33];
        if (!persist_load_basepoints(pdb, (uint32_t)c, local_secrets, remote_bps)) {
            fprintf(stderr, "LSP recovery: failed to load basepoints for channel %zu\n", c);
            return 0;
        }

        /* Set local basepoints from loaded secrets */
        channel_set_local_basepoints(&entry->channel,
                                       local_secrets[0],
                                       local_secrets[1],
                                       local_secrets[2]);
        channel_set_local_htlc_basepoint(&entry->channel, local_secrets[3]);

        /* Set remote basepoints from loaded pubkeys */
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        if (!secp256k1_ec_pubkey_parse(ctx, &rpay, remote_bps[0], 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &rdelay, remote_bps[1], 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &rrevoc, remote_bps[2], 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &rhtlc, remote_bps[3], 33)) {
            fprintf(stderr, "LSP recovery: failed to parse remote basepoints for channel %zu\n", c);
            return 0;
        }
        channel_set_remote_basepoints(&entry->channel, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(&entry->channel, &rhtlc);

        /* Load channel state (balances, commitment_number) from DB */
        uint64_t loaded_local, loaded_remote, loaded_cn;
        if (!persist_load_channel_state(pdb, (uint32_t)c,
                                          &loaded_local, &loaded_remote, &loaded_cn)) {
            fprintf(stderr, "LSP recovery: failed to load channel state for channel %zu\n", c);
            return 0;
        }
        entry->channel.local_amount = loaded_local;
        entry->channel.remote_amount = loaded_remote;
        entry->channel.commitment_number = loaded_cn;

        /* Load active HTLCs from DB (GAP-4b) */
        {
            htlc_t loaded_htlcs[MAX_HTLCS];
            size_t n_loaded = persist_load_htlcs(pdb, (uint32_t)c,
                                                    loaded_htlcs, MAX_HTLCS);
            for (size_t h = 0; h < n_loaded; h++) {
                if (loaded_htlcs[h].state != HTLC_STATE_ACTIVE) continue;
                if (entry->channel.n_htlcs >= MAX_HTLCS) break;
                entry->channel.htlcs[entry->channel.n_htlcs++] = loaded_htlcs[h];
            }
            if (n_loaded > 0)
                printf("LSP recovery: loaded %zu HTLCs for channel %zu\n",
                       n_loaded, c);
        }

        /* Initialize nonce pool (fresh nonces — reconnect re-exchanges) */
        if (!channel_init_nonce_pool(&entry->channel, MUSIG_NONCE_POOL_MAX))
            return 0;

        entry->ready = 1;  /* channels are already operational */
    }

    return 1;
}

int lsp_channels_exchange_basepoints(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    for (size_t c = 0; c < mgr->n_channels; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];
        channel_t *ch = &entry->channel;

        /* Compute LSP's first_per_commitment_point (cn=0) and second (cn=1) */
        secp256k1_pubkey lsp_first_pcp, lsp_second_pcp;
        if (!channel_get_per_commitment_point(ch, 0, &lsp_first_pcp) ||
            !channel_get_per_commitment_point(ch, 1, &lsp_second_pcp)) {
            fprintf(stderr, "LSP: failed to get per_commitment_points for channel %zu\n", c);
            return 0;
        }

        /* Send LSP's basepoints to client */
        cJSON *bp_msg = wire_build_channel_basepoints(
            entry->channel_id, mgr->ctx,
            &ch->local_payment_basepoint,
            &ch->local_delayed_payment_basepoint,
            &ch->local_revocation_basepoint,
            &ch->local_htlc_basepoint,
            &lsp_first_pcp, &lsp_second_pcp);
        if (!wire_send(lsp->client_fds[c], MSG_CHANNEL_BASEPOINTS, bp_msg)) {
            fprintf(stderr, "LSP: failed to send CHANNEL_BASEPOINTS to client %zu\n", c);
            cJSON_Delete(bp_msg);
            return 0;
        }
        cJSON_Delete(bp_msg);

        /* Receive client's basepoints */
        wire_msg_t bp_resp;
        if (!wire_recv(lsp->client_fds[c], &bp_resp) ||
            bp_resp.msg_type != MSG_CHANNEL_BASEPOINTS) {
            fprintf(stderr, "LSP: expected CHANNEL_BASEPOINTS from client %zu, got 0x%02x\n",
                    c, bp_resp.msg_type);
            if (bp_resp.json) cJSON_Delete(bp_resp.json);
            return 0;
        }

        uint32_t resp_ch_id;
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc, rfirst_pcp, rsecond_pcp;
        if (!wire_parse_channel_basepoints(bp_resp.json, &resp_ch_id, mgr->ctx,
                                             &rpay, &rdelay, &rrevoc, &rhtlc,
                                             &rfirst_pcp, &rsecond_pcp)) {
            fprintf(stderr, "LSP: failed to parse client %zu basepoints\n", c);
            cJSON_Delete(bp_resp.json);
            return 0;
        }
        cJSON_Delete(bp_resp.json);

        /* Set remote basepoints from wire */
        channel_set_remote_basepoints(ch, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(ch, &rhtlc);

        /* Store remote's first and second per-commitment points */
        channel_set_remote_pcp(ch, 0, &rfirst_pcp);
        channel_set_remote_pcp(ch, 1, &rsecond_pcp);

        printf("LSP: basepoint exchange complete for channel %zu\n", c);
    }

    return 1;
}

int lsp_channels_send_ready(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    for (size_t c = 0; c < mgr->n_channels; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];

        /* Send CHANNEL_READY */
        cJSON *msg = wire_build_channel_ready(
            entry->channel_id,
            entry->channel.local_amount * 1000,   /* sats → msat */
            entry->channel.remote_amount * 1000);
        if (!wire_send(lsp->client_fds[c], MSG_CHANNEL_READY, msg)) {
            fprintf(stderr, "LSP: failed to send CHANNEL_READY to client %zu\n", c);
            cJSON_Delete(msg);
            return 0;
        }
        cJSON_Delete(msg);

        /* Phase 12: Send nonce pool pubnonces to client */
        {
            channel_t *ch = &entry->channel;
            size_t nonce_count = ch->local_nonce_pool.count;
            unsigned char (*pubnonces_ser)[66] =
                (unsigned char (*)[66])calloc(nonce_count, 66);
            if (!pubnonces_ser) return 0;

            for (size_t i = 0; i < nonce_count; i++) {
                musig_pubnonce_serialize(mgr->ctx,
                    pubnonces_ser[i], &ch->local_nonce_pool.nonces[i].pubnonce);
            }

            cJSON *nonce_msg = wire_build_channel_nonces(
                entry->channel_id, (const unsigned char (*)[66])pubnonces_ser,
                nonce_count);
            if (!wire_send(lsp->client_fds[c], MSG_CHANNEL_NONCES, nonce_msg)) {
                fprintf(stderr, "LSP: failed to send CHANNEL_NONCES to client %zu\n", c);
                cJSON_Delete(nonce_msg);
                free(pubnonces_ser);
                return 0;
            }
            cJSON_Delete(nonce_msg);
            free(pubnonces_ser);
        }

        /* Wait for client's nonces */
        {
            wire_msg_t nonce_resp;
            if (!wire_recv(lsp->client_fds[c], &nonce_resp) ||
                nonce_resp.msg_type != MSG_CHANNEL_NONCES) {
                fprintf(stderr, "LSP: expected CHANNEL_NONCES from client %zu\n", c);
                if (nonce_resp.json) cJSON_Delete(nonce_resp.json);
                return 0;
            }

            uint32_t resp_ch_id;
            unsigned char client_nonces[MUSIG_NONCE_POOL_MAX][66];
            size_t client_nonce_count;
            if (!wire_parse_channel_nonces(nonce_resp.json, &resp_ch_id,
                                             client_nonces, MUSIG_NONCE_POOL_MAX,
                                             &client_nonce_count)) {
                fprintf(stderr, "LSP: failed to parse client nonces\n");
                cJSON_Delete(nonce_resp.json);
                return 0;
            }
            cJSON_Delete(nonce_resp.json);

            channel_set_remote_pubnonces(&entry->channel,
                (const unsigned char (*)[66])client_nonces, client_nonce_count);
        }

        entry->ready = 1;
    }
    return 1;
}

/* --- HTLC handling --- */

/* Handle ADD_HTLC from a client: add to sender's channel, forward to recipient. */
static int handle_add_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                             size_t sender_idx, const cJSON *json) {
    uint64_t htlc_id, amount_msat;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;

    if (!wire_parse_update_add_htlc(json, &htlc_id, &amount_msat,
                                      payment_hash, &cltv_expiry))
        return 0;

    uint64_t amount_sats = amount_msat / 1000;
    if (amount_sats == 0) return 0;

    channel_t *sender_ch = &mgr->entries[sender_idx].channel;

    /* Capture amounts and HTLC state before add_htlc changes them (for watchtower) */
    uint64_t old_sender_local = sender_ch->local_amount;
    uint64_t old_sender_remote = sender_ch->remote_amount;
    size_t old_sender_n_htlcs = sender_ch->n_htlcs;
    htlc_t old_sender_htlcs[MAX_HTLCS];
    if (old_sender_n_htlcs > 0)
        memcpy(old_sender_htlcs, sender_ch->htlcs, old_sender_n_htlcs * sizeof(htlc_t));

    /* Add HTLC to sender's channel (offered from client = received by LSP) */
    uint64_t new_htlc_id;
    if (!channel_add_htlc(sender_ch, HTLC_RECEIVED, amount_sats,
                           payment_hash, cltv_expiry, &new_htlc_id)) {
        fprintf(stderr, "LSP: add_htlc failed for client %zu (insufficient funds?)\n",
                sender_idx);
        /* Send fail back */
        cJSON *fail = wire_build_update_fail_htlc(htlc_id, "insufficient funds");
        wire_send(lsp->client_fds[sender_idx], MSG_UPDATE_FAIL_HTLC, fail);
        cJSON_Delete(fail);
        return 1;  /* not a protocol error, just a payment failure */
    }

    /* Send COMMITMENT_SIGNED to sender (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for sender %zu\n", sender_idx);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[sender_idx].channel_id,
            sender_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[sender_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* Wait for REVOKE_AND_ACK from sender */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[sender_idx], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP: expected REVOKE_AND_ACK from sender %zu\n", sender_idx);
            return 0;
        }
        /* Parse and store revocation secret */
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = sender_ch->commitment_number - 1;
            channel_receive_revocation(sender_ch, old_cn, rev_secret);
            watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                (uint32_t)sender_idx, old_cn,
                old_sender_local, old_sender_remote,
                old_sender_htlcs, old_sender_n_htlcs);
            /* Store next per-commitment point from peer */
            secp256k1_pubkey next_pcp;
            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                channel_set_remote_pcp(sender_ch, sender_ch->commitment_number + 1, &next_pcp);
            /* Bidirectional: send LSP's own revocation to sender */
            lsp_send_revocation(mgr, lsp, sender_idx, old_cn);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* Find destination: check dest_client field, then bolt11 for bridge routing */
    cJSON *dest_item = cJSON_GetObjectItem(json, "dest_client");
    cJSON *bolt11_item = cJSON_GetObjectItem(json, "bolt11");

    /* If bolt11 present and bridge connected, route outbound via bridge */
    if ((!dest_item || !cJSON_IsNumber(dest_item)) &&
        bolt11_item && cJSON_IsString(bolt11_item) && mgr->bridge_fd >= 0) {
        uint64_t request_id = mgr->next_request_id++;
        cJSON *pay = wire_build_bridge_send_pay(bolt11_item->valuestring,
                                                  payment_hash, request_id);
        int ok = wire_send(mgr->bridge_fd, MSG_BRIDGE_SEND_PAY, pay);
        cJSON_Delete(pay);
        if (!ok) return 0;

        /* Track origin for when PAY_RESULT comes back */
        lsp_channels_track_bridge_origin(mgr, payment_hash, 0);
        /* Store request_id + sender info for back-propagation */
        if (mgr->n_htlc_origins > 0) {
            htlc_origin_t *origin = &mgr->htlc_origins[mgr->n_htlc_origins - 1];
            origin->request_id = request_id;
            origin->sender_idx = sender_idx;
            origin->sender_htlc_id = new_htlc_id;
            /* Persist full origin with all fields */
            if (mgr->persist)
                persist_save_htlc_origin((persist_t *)mgr->persist,
                    payment_hash, 0, request_id, sender_idx, new_htlc_id);
        }
        if (mgr->persist)
            persist_save_counter((persist_t *)mgr->persist,
                                  "next_request_id", mgr->next_request_id);
        printf("LSP: HTLC from client %zu routed to bridge (bolt11)\n", sender_idx);
        return 1;
    }

    if (!dest_item || !cJSON_IsNumber(dest_item)) {
        fprintf(stderr, "LSP: ADD_HTLC missing dest_client\n");
        return 0;
    }
    size_t dest_idx = (size_t)dest_item->valuedouble;
    if (dest_idx >= mgr->n_channels || dest_idx == sender_idx) {
        fprintf(stderr, "LSP: invalid dest_client %zu\n", dest_idx);
        return 0;
    }

    /* Smart channel dispatch: prefer factory channel, fall back to JIT */
    channel_t *dest_ch;
    uint32_t dest_chan_id;
    int dest_is_jit = 0;

    if (mgr->entries[dest_idx].ready) {
        dest_ch = &mgr->entries[dest_idx].channel;
        dest_chan_id = mgr->entries[dest_idx].channel_id;
    } else {
        jit_channel_t *jit = jit_channel_find(mgr, dest_idx);
        if (jit && jit->state == JIT_STATE_OPEN) {
            dest_ch = &jit->channel;
            dest_chan_id = jit->jit_channel_id;
            dest_is_jit = 1;
        } else {
            fprintf(stderr, "LSP: no channel for client %zu\n", dest_idx);
            return 0;
        }
    }

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
        fprintf(stderr, "LSP: forward add_htlc failed to client %zu\n", dest_idx);
        return 0;
    }

    /* Forward ADD_HTLC to destination */
    {
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            return 0;
        }
        cJSON_Delete(fwd);
    }

    /* Send COMMITMENT_SIGNED to dest (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for dest %zu\n", dest_idx);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            dest_chan_id,
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
            fprintf(stderr, "LSP: expected REVOKE_AND_ACK from dest %zu\n", dest_idx);
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = dest_ch->commitment_number - 1;
            channel_receive_revocation(dest_ch, old_cn, rev_secret);
            uint32_t wt_chan_id = dest_is_jit ?
                (uint32_t)(mgr->n_channels + dest_idx) : (uint32_t)dest_idx;
            watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                wt_chan_id, old_cn,
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

    /* Persist in-flight HTLC for replay on reconnect (GAP-4b) */
    if (mgr->persist) {
        htlc_t persist_htlc;
        memset(&persist_htlc, 0, sizeof(persist_htlc));
        persist_htlc.id = dest_htlc_id;
        persist_htlc.direction = HTLC_OFFERED;
        persist_htlc.state = HTLC_STATE_ACTIVE;
        persist_htlc.amount_sats = amount_sats;
        memcpy(persist_htlc.payment_hash, payment_hash, 32);
        persist_htlc.cltv_expiry = cltv_expiry;
        persist_save_htlc((persist_t *)mgr->persist,
                            (uint32_t)dest_idx, &persist_htlc);
    }

    printf("LSP: HTLC %llu forwarded: client %zu -> client %zu (%llu sats)\n",
           (unsigned long long)new_htlc_id, sender_idx, dest_idx,
           (unsigned long long)amount_sats);
    return 1;
}

/* --- Per-leaf DW advance (arity-1 split-round signing) --- */

/* Advance one leaf's DW counter, do split-round signing with the affected
   client, and notify all clients. Only operates in arity-1 mode.
   leaf_side: 0..n_leaf_nodes-1 (same as client index for arity-1).
   Returns 1 on success, 0 on failure or skip. */
static int lsp_advance_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp, int leaf_side) {
    factory_t *f = &lsp->factory;

    /* Only advance for arity-1 (each leaf = 1 client, 2-of-2 signing) */
    if (f->leaf_arity != FACTORY_ARITY_1) return 1;
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    /* Step 1: Advance DW counter + rebuild unsigned tx */
    int rc = factory_advance_leaf_unsigned(f, leaf_side);
    if (rc == 0) {
        fprintf(stderr, "LSP: leaf %d DW fully exhausted\n", leaf_side);
        return 0;
    }
    if (rc == -1) {
        /* Root advanced + full rebuild needed — too complex for per-leaf flow.
           This is rare and should trigger an epoch reset instead. */
        printf("LSP: leaf %d exhausted, root advanced — skipping per-leaf signing\n",
               leaf_side);
        return 1;
    }

    size_t node_idx = f->leaf_node_indices[leaf_side];
    uint32_t client_participant = (uint32_t)(leaf_side + 1);

    /* Step 2: Init signing session for the leaf node */
    if (!factory_session_init_node(f, node_idx)) {
        fprintf(stderr, "LSP: session init failed for leaf node %zu\n", node_idx);
        return 0;
    }

    /* Step 3: Generate LSP's nonce (participant 0) */
    int lsp_slot = factory_find_signer_slot(f, node_idx, 0);
    if (lsp_slot < 0) {
        fprintf(stderr, "LSP: LSP not signer on leaf node %zu\n", node_idx);
        return 0;
    }

    unsigned char lsp_seckey[32];
    secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair);

    secp256k1_musig_secnonce lsp_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                               lsp_seckey, &lsp->lsp_pubkey,
                               &f->nodes[node_idx].keyagg.cache)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP: nonce gen failed for leaf advance\n");
        return 0;
    }

    if (!factory_session_set_nonce(f, node_idx, (size_t)lsp_slot, &lsp_pubnonce)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Step 4: Send LEAF_ADVANCE_PROPOSE to the affected client */
    unsigned char lsp_pubnonce_ser[66];
    musig_pubnonce_serialize(lsp->ctx, lsp_pubnonce_ser, &lsp_pubnonce);
    cJSON *propose = wire_build_leaf_advance_propose(leaf_side, lsp_pubnonce_ser);
    if (!wire_send(lsp->client_fds[leaf_side], MSG_LEAF_ADVANCE_PROPOSE, propose)) {
        cJSON_Delete(propose);
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(propose);

    /* Step 5: Wait for LEAF_ADVANCE_PSIG from client */
    wire_msg_t psig_msg;
    if (!wire_recv(lsp->client_fds[leaf_side], &psig_msg) ||
        psig_msg.msg_type != MSG_LEAF_ADVANCE_PSIG) {
        fprintf(stderr, "LSP: expected LEAF_ADVANCE_PSIG from client %d, got 0x%02x\n",
                leaf_side, psig_msg.msg_type);
        if (psig_msg.json) cJSON_Delete(psig_msg.json);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    unsigned char client_pubnonce_ser[66], client_psig_ser[32];
    if (!wire_parse_leaf_advance_psig(psig_msg.json,
                                        client_pubnonce_ser, client_psig_ser)) {
        fprintf(stderr, "LSP: failed to parse LEAF_ADVANCE_PSIG\n");
        cJSON_Delete(psig_msg.json);
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(psig_msg.json);

    /* Step 6: Set client's nonce + finalize */
    int client_slot = factory_find_signer_slot(f, node_idx, client_participant);
    if (client_slot < 0) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    secp256k1_musig_pubnonce client_pubnonce;
    if (!musig_pubnonce_parse(lsp->ctx, &client_pubnonce, client_pubnonce_ser)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    if (!factory_session_set_nonce(f, node_idx, (size_t)client_slot, &client_pubnonce)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    if (!factory_session_finalize_node(f, node_idx)) {
        fprintf(stderr, "LSP: session finalize failed for leaf node %zu\n", node_idx);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Step 7: Create LSP's partial sig */
    secp256k1_keypair lsp_kp;
    secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey);
    memset(lsp_seckey, 0, 32);

    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce, &lsp_kp,
                                    &f->nodes[node_idx].signing_session)) {
        fprintf(stderr, "LSP: partial sig failed for leaf advance\n");
        return 0;
    }

    if (!factory_session_set_partial_sig(f, node_idx, (size_t)lsp_slot, &lsp_psig))
        return 0;

    /* Track LSP signing progress */
    if (mgr->persist)
        persist_save_signing_progress((persist_t *)mgr->persist, 0,
                                       (uint32_t)node_idx, (uint32_t)lsp_slot, 1, 1);

    /* Step 8: Set client's partial sig */
    secp256k1_musig_partial_sig client_psig;
    if (!musig_partial_sig_parse(lsp->ctx, &client_psig, client_psig_ser))
        return 0;

    if (!factory_session_set_partial_sig(f, node_idx, (size_t)client_slot, &client_psig))
        return 0;

    /* Track client signing progress */
    if (mgr->persist)
        persist_save_signing_progress((persist_t *)mgr->persist, 0,
                                       (uint32_t)node_idx, (uint32_t)client_slot, 1, 1);

    /* Step 9: Aggregate + finalize */
    if (!factory_session_complete_node(f, node_idx)) {
        fprintf(stderr, "LSP: session complete failed for leaf node %zu\n", node_idx);
        return 0;
    }

    /* Clear signing progress after successful aggregation */
    if (mgr->persist)
        persist_clear_signing_progress((persist_t *)mgr->persist, 0);

    /* Step 10: Send LEAF_ADVANCE_DONE to all clients */
    cJSON *done = wire_build_leaf_advance_done(leaf_side);
    for (size_t i = 0; i < lsp->n_clients; i++) {
        wire_send(lsp->client_fds[i], MSG_LEAF_ADVANCE_DONE, done);
    }
    cJSON_Delete(done);

    /* Step 11: Persist per-leaf DW state */
    if (mgr->persist) {
        uint32_t leaf_states[8];
        for (int i = 0; i < f->n_leaf_nodes; i++)
            leaf_states[i] = f->leaf_layers[i].current_state;
        uint32_t layer_states[DW_MAX_LAYERS];
        for (uint32_t i = 0; i < f->counter.n_layers; i++)
            layer_states[i] = f->counter.layers[i].config.max_states;
        persist_save_dw_counter_with_leaves(
            (persist_t *)mgr->persist, 0, f->counter.current_epoch,
            f->counter.n_layers, layer_states,
            f->per_leaf_enabled, leaf_states, f->n_leaf_nodes);
    }

    printf("LSP: leaf %d advanced (node %zu), DW state %u\n",
           leaf_side, node_idx, f->leaf_layers[leaf_side].current_state);
    return 1;
}

/* Handle FULFILL_HTLC from a client (the payee reveals the preimage). */
static int handle_fulfill_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                 size_t client_idx, const cJSON *json) {
    uint64_t htlc_id;
    unsigned char preimage[32];

    if (!wire_parse_update_fulfill_htlc(json, &htlc_id, preimage))
        return 0;

    channel_t *ch = &mgr->entries[client_idx].channel;

    /* Capture amounts and HTLC state before fulfill changes them (for watchtower) */
    uint64_t old_ch_local = ch->local_amount;
    uint64_t old_ch_remote = ch->remote_amount;
    size_t old_ch_n_htlcs = ch->n_htlcs;
    htlc_t old_ch_htlcs[MAX_HTLCS];
    if (old_ch_n_htlcs > 0)
        memcpy(old_ch_htlcs, ch->htlcs, old_ch_n_htlcs * sizeof(htlc_t));

    /* Fulfill the HTLC on this channel (LSP offered → client fulfills) */
    if (!channel_fulfill_htlc(ch, htlc_id, preimage)) {
        fprintf(stderr, "LSP: fulfill_htlc failed for client %zu htlc %llu\n",
                client_idx, (unsigned long long)htlc_id);
        return 0;
    }

    /* Send COMMITMENT_SIGNED to this client (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for client %zu\n", client_idx);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[client_idx].channel_id,
            ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[client_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* Wait for REVOKE_AND_ACK */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[client_idx], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = ch->commitment_number - 1;
            channel_receive_revocation(ch, old_cn, rev_secret);
            watchtower_watch_revoked_commitment(mgr->watchtower, ch,
                (uint32_t)client_idx, old_cn,
                old_ch_local, old_ch_remote,
                old_ch_htlcs, old_ch_n_htlcs);
            secp256k1_pubkey next_pcp;
            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);
            /* Bidirectional: send LSP's own revocation to this client */
            lsp_send_revocation(mgr, lsp, client_idx, old_cn);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* Now back-propagate: find the sender's channel that has a matching HTLC.
       We search all other channels for a received HTLC with the same payment_hash. */
    unsigned char payment_hash[32];
    /* Compute hash from preimage */
    sha256(preimage, 32, payment_hash);

    /* Deactivate fulfilled invoice in persistence */
    if (mgr->persist)
        persist_deactivate_invoice((persist_t *)mgr->persist, payment_hash);

    /* Delete settled HTLC from persistence (GAP-4b) */
    if (mgr->persist)
        persist_delete_htlc((persist_t *)mgr->persist,
                              (uint32_t)client_idx, htlc_id);

    /* Check if this HTLC originated from the bridge */
    uint64_t bridge_htlc_id = lsp_channels_get_bridge_origin(mgr, payment_hash);
    if (bridge_htlc_id > 0 && mgr->bridge_fd >= 0) {
        /* Back-propagate to bridge instead of intra-factory */
        cJSON *fulfill = wire_build_bridge_fulfill_htlc(payment_hash, preimage,
                                                          bridge_htlc_id);
        wire_send(mgr->bridge_fd, MSG_BRIDGE_FULFILL_HTLC, fulfill);
        cJSON_Delete(fulfill);
        printf("LSP: HTLC fulfilled via bridge (htlc_id=%llu)\n",
               (unsigned long long)bridge_htlc_id);
        return 1;
    }

    int sender_found = -1;
    for (size_t s = 0; s < mgr->n_channels; s++) {
        if (s == client_idx) continue;
        channel_t *sender_ch = &mgr->entries[s].channel;

        /* Find matching received HTLC (from sender's perspective, LSP received it) */
        for (size_t h = 0; h < sender_ch->n_htlcs; h++) {
            htlc_t *htlc = &sender_ch->htlcs[h];
            if (htlc->state != HTLC_STATE_ACTIVE) continue;
            if (htlc->direction != HTLC_RECEIVED) continue;
            if (memcmp(htlc->payment_hash, payment_hash, 32) != 0) continue;

            /* Found it — fulfill on sender's channel */
            uint64_t old_sender_local = sender_ch->local_amount;
            uint64_t old_sender_remote = sender_ch->remote_amount;
            size_t old_sender_n_htlcs = sender_ch->n_htlcs;
            htlc_t old_sender_htlcs[MAX_HTLCS];
            if (old_sender_n_htlcs > 0)
                memcpy(old_sender_htlcs, sender_ch->htlcs, old_sender_n_htlcs * sizeof(htlc_t));
            if (!channel_fulfill_htlc(sender_ch, htlc->id, preimage)) {
                fprintf(stderr, "LSP: back-fulfill failed\n");
                continue;
            }

            /* Send FULFILL_HTLC to sender */
            cJSON *fwd = wire_build_update_fulfill_htlc(htlc->id, preimage);
            wire_send(lsp->client_fds[s], MSG_UPDATE_FULFILL_HTLC, fwd);
            cJSON_Delete(fwd);

            /* Send COMMITMENT_SIGNED (real partial sig) */
            {
                unsigned char psig32[32];
                uint32_t nonce_idx;
                if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx)) {
                    fprintf(stderr, "LSP: create partial sig failed for back-propagation to %zu\n", s);
                    continue;
                }
                cJSON *cs = wire_build_commitment_signed(
                    mgr->entries[s].channel_id,
                    sender_ch->commitment_number, psig32, nonce_idx);
                wire_send(lsp->client_fds[s], MSG_COMMITMENT_SIGNED, cs);
                cJSON_Delete(cs);
            }

            /* Wait for REVOKE_AND_ACK */
            wire_msg_t ack_msg;
            if (wire_recv(lsp->client_fds[s], &ack_msg) &&
                ack_msg.msg_type == MSG_REVOKE_AND_ACK) {
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = sender_ch->commitment_number - 1;
                    channel_receive_revocation(sender_ch, old_cn, rev_secret);
                    watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                        (uint32_t)s, old_cn,
                        old_sender_local, old_sender_remote,
                        old_sender_htlcs, old_sender_n_htlcs);
                    secp256k1_pubkey next_pcp;
                    if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                        channel_set_remote_pcp(sender_ch, sender_ch->commitment_number + 1, &next_pcp);
                    /* Bidirectional: send LSP's own revocation to sender */
                    lsp_send_revocation(mgr, lsp, s, old_cn);
                }
            }
            if (ack_msg.json) cJSON_Delete(ack_msg.json);

            printf("LSP: HTLC fulfilled: client %zu -> client %zu (%llu sats)\n",
                   s, client_idx, (unsigned long long)htlc->amount_sats);
            sender_found = (int)s;
            break;
        }
    }

    /* Per-leaf DW advance: after payment settles, advance both affected leaves.
       This is the arity-1 killer feature — only the involved clients' leaves
       need to be re-signed, not the entire tree. */
    if (lsp->factory.leaf_arity == FACTORY_ARITY_1) {
        /* Advance payee's leaf */
        lsp_advance_leaf(mgr, lsp, (int)client_idx);
        /* Advance sender's leaf (if found via intra-factory routing) */
        if (sender_found >= 0 && sender_found != (int)client_idx)
            lsp_advance_leaf(mgr, lsp, sender_found);
    }

    return 1;
}

int lsp_channels_handle_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                              size_t client_idx, const wire_msg_t *msg) {
    if (!mgr || !lsp || !msg || client_idx >= mgr->n_channels) return 0;

    /* Update activity tracking (Step 1: offline detection) */
    mgr->entries[client_idx].last_message_time = time(NULL);
    mgr->entries[client_idx].offline_detected = 0;

    switch (msg->msg_type) {
    case MSG_UPDATE_ADD_HTLC:
        return handle_add_htlc(mgr, lsp, client_idx, msg->json);

    case MSG_UPDATE_FULFILL_HTLC:
        return handle_fulfill_htlc(mgr, lsp, client_idx, msg->json);

    case MSG_UPDATE_FAIL_HTLC: {
        uint64_t htlc_id;
        char reason[256];
        if (!wire_parse_update_fail_htlc(msg->json, &htlc_id, reason, sizeof(reason)))
            return 0;
        channel_t *ch = &mgr->entries[client_idx].channel;
        channel_fail_htlc(ch, htlc_id);
        printf("LSP: HTLC %llu failed by client %zu: %s\n",
               (unsigned long long)htlc_id, client_idx, reason);
        return 1;
    }

    case MSG_REGISTER_INVOICE: {
        unsigned char payment_hash[32];
        uint64_t amount_msat;
        size_t dest_client;
        if (!wire_parse_register_invoice(msg->json, payment_hash,
                                           &amount_msat, &dest_client))
            return 0;
        if (!lsp_channels_register_invoice(mgr, payment_hash,
                                             dest_client, amount_msat)) {
            fprintf(stderr, "LSP: register_invoice failed\n");
            return 0;
        }
        /* Also forward to bridge if connected */
        if (mgr->bridge_fd >= 0) {
            cJSON *reg = wire_build_bridge_register(payment_hash, amount_msat,
                                                      dest_client);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_REGISTER, reg);
            cJSON_Delete(reg);
        }
        printf("LSP: registered invoice for client %zu (%llu msat)\n",
               dest_client, (unsigned long long)amount_msat);
        return 1;
    }

    case MSG_CLOSE_REQUEST:
        printf("LSP: client %zu requested close\n", client_idx);
        return 1;  /* handled by caller */

    case MSG_EPOCH_RESET_PSIG:
        /* Client sent partial sigs for epoch reset — collect and aggregate.
           In the PoC, epoch reset is done locally with factory_reset_epoch().
           This handler acknowledges receipt for future distributed mode. */
        printf("LSP: received EPOCH_RESET_PSIG from client %zu\n", client_idx);
        return 1;

    case MSG_LEAF_ADVANCE_PSIG:
        /* Client sent partial sig for leaf advance.
           In the PoC, leaf advance is done locally with factory_advance_leaf().
           This handler acknowledges receipt for future distributed mode. */
        printf("LSP: received LEAF_ADVANCE_PSIG from client %zu\n", client_idx);
        return 1;

    default:
        fprintf(stderr, "LSP: unexpected msg 0x%02x from client %zu\n",
                msg->msg_type, client_idx);
        return 0;
    }
}

/* --- Bridge support functions (Phase 14) --- */

void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd) {
    mgr->bridge_fd = bridge_fd;
}

int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    size_t dest_client, uint64_t amount_msat) {
    if (mgr->n_invoices >= MAX_INVOICE_REGISTRY) return 0;
    if (dest_client >= mgr->n_channels) return 0;

    invoice_entry_t *inv = &mgr->invoices[mgr->n_invoices++];
    memcpy(inv->payment_hash, payment_hash32, 32);
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

        /* Track bridge origin for back-propagation */
        lsp_channels_track_bridge_origin(mgr, payment_hash, htlc_id);

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
            uint64_t htlc_id = mgr->htlc_origins[i].sender_htlc_id;
            mgr->htlc_origins[i].active = 0;

            if (client_idx >= mgr->n_channels) break;
            channel_t *ch = &mgr->entries[client_idx].channel;

            if (success) {
                /* Fulfill the HTLC on the client's channel */
                channel_fulfill_htlc(ch, htlc_id, preimage);

                cJSON *ful = wire_build_update_fulfill_htlc(htlc_id, preimage);
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
                       client_idx, (unsigned long long)htlc_id);
            } else {
                /* Fail the HTLC */
                channel_fail_htlc(ch, htlc_id);
                cJSON *fail = wire_build_update_fail_htlc(htlc_id, "bridge_pay_failed");
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FAIL_HTLC, fail);
                cJSON_Delete(fail);

                printf("LSP: bridge pay failed for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id);
            }
            break;
        }
        return 1;
    }

    default:
        fprintf(stderr, "LSP: unexpected bridge msg 0x%02x\n", msg->msg_type);
        return 0;
    }
}

/* --- Reconnection (Phase 16) --- */

/* Core reconnect handler that takes an already-read MSG_RECONNECT message. */
static int handle_reconnect_with_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       int new_fd, const wire_msg_t *msg) {
    if (!mgr || !lsp || new_fd < 0 || !msg) return 0;

    /* 2. Parse pubkey + commitment_number */
    secp256k1_pubkey client_pk;
    uint64_t commitment_number;
    if (!wire_parse_reconnect(msg->json, mgr->ctx, &client_pk, &commitment_number)) {
        fprintf(stderr, "LSP reconnect: failed to parse MSG_RECONNECT\n");
        wire_close(new_fd);
        return 0;
    }

    /* 3. Match pubkey against lsp->client_pubkeys[] to find client index */
    int found = -1;
    unsigned char client_ser[33], cmp_ser[33];
    size_t len1 = 33, len2 = 33;
    secp256k1_ec_pubkey_serialize(mgr->ctx, client_ser, &len1, &client_pk,
                                   SECP256K1_EC_COMPRESSED);
    for (size_t c = 0; c < lsp->n_clients; c++) {
        len2 = 33;
        secp256k1_ec_pubkey_serialize(mgr->ctx, cmp_ser, &len2,
                                       &lsp->client_pubkeys[c],
                                       SECP256K1_EC_COMPRESSED);
        if (memcmp(client_ser, cmp_ser, 33) == 0) {
            found = (int)c;
            break;
        }
    }

    if (found < 0) {
        fprintf(stderr, "LSP reconnect: unknown pubkey\n");
        wire_close(new_fd);
        return 0;
    }
    size_t c = (size_t)found;

    /* 4. Verify commitment_number matches */
    channel_t *ch = &mgr->entries[c].channel;
    if (commitment_number != ch->commitment_number) {
        fprintf(stderr, "LSP reconnect: commitment_number mismatch "
                "(client=%llu, lsp=%llu) for slot %zu\n",
                (unsigned long long)commitment_number,
                (unsigned long long)ch->commitment_number, c);
        /* Proceed anyway for PoC — the ACK will tell client the LSP's state */
    }

    /* 5. Close old client_fds[c] if still open */
    if (lsp->client_fds[c] >= 0) {
        wire_close(lsp->client_fds[c]);
    }

    /* 6. Set new fd */
    lsp->client_fds[c] = new_fd;

    /* Reset offline detection on reconnect */
    mgr->entries[c].last_message_time = time(NULL);
    mgr->entries[c].offline_detected = 0;

    /* 7. Re-init nonce pool */
    if (!channel_init_nonce_pool(ch, MUSIG_NONCE_POOL_MAX)) {
        fprintf(stderr, "LSP reconnect: nonce pool init failed for slot %zu\n", c);
        return 0;
    }

    /* 8. Exchange CHANNEL_NONCES (send LSP's, recv client's) */
    {
        size_t nonce_count = ch->local_nonce_pool.count;
        unsigned char (*pubnonces_ser)[66] =
            (unsigned char (*)[66])calloc(nonce_count, 66);
        if (!pubnonces_ser) return 0;

        for (size_t i = 0; i < nonce_count; i++) {
            musig_pubnonce_serialize(mgr->ctx,
                pubnonces_ser[i], &ch->local_nonce_pool.nonces[i].pubnonce);
        }

        cJSON *nonce_msg = wire_build_channel_nonces(
            mgr->entries[c].channel_id, (const unsigned char (*)[66])pubnonces_ser,
            nonce_count);
        if (!wire_send(new_fd, MSG_CHANNEL_NONCES, nonce_msg)) {
            fprintf(stderr, "LSP reconnect: send CHANNEL_NONCES failed\n");
            cJSON_Delete(nonce_msg);
            free(pubnonces_ser);
            return 0;
        }
        cJSON_Delete(nonce_msg);
        free(pubnonces_ser);
    }

    /* Recv client's nonces */
    {
        wire_msg_t nonce_resp;
        if (!wire_recv(new_fd, &nonce_resp) ||
            nonce_resp.msg_type != MSG_CHANNEL_NONCES) {
            fprintf(stderr, "LSP reconnect: expected CHANNEL_NONCES from client\n");
            if (nonce_resp.json) cJSON_Delete(nonce_resp.json);
            return 0;
        }

        uint32_t resp_ch_id;
        unsigned char client_nonces[MUSIG_NONCE_POOL_MAX][66];
        size_t client_nonce_count;
        if (!wire_parse_channel_nonces(nonce_resp.json, &resp_ch_id,
                                         client_nonces, MUSIG_NONCE_POOL_MAX,
                                         &client_nonce_count)) {
            fprintf(stderr, "LSP reconnect: failed to parse client nonces\n");
            cJSON_Delete(nonce_resp.json);
            return 0;
        }
        cJSON_Delete(nonce_resp.json);

        channel_set_remote_pubnonces(ch,
            (const unsigned char (*)[66])client_nonces, client_nonce_count);
    }

    /* 9. Send MSG_RECONNECT_ACK */
    {
        cJSON *ack = wire_build_reconnect_ack(
            mgr->entries[c].channel_id,
            ch->local_amount * 1000,   /* sats → msat */
            ch->remote_amount * 1000,
            ch->commitment_number);
        if (!wire_send(new_fd, MSG_RECONNECT_ACK, ack)) {
            fprintf(stderr, "LSP reconnect: send RECONNECT_ACK failed\n");
            cJSON_Delete(ack);
            return 0;
        }
        cJSON_Delete(ack);
    }

    /* Replay in-flight HTLCs from persistence (GAP-4b) */
    if (mgr->persist) {
        htlc_t pending[MAX_HTLCS];
        size_t n_pending = persist_load_htlcs((persist_t *)mgr->persist,
                                                (uint32_t)c, pending, MAX_HTLCS);
        for (size_t h = 0; h < n_pending; h++) {
            if (pending[h].state != HTLC_STATE_ACTIVE) continue;
            cJSON *add = wire_build_update_add_htlc(
                pending[h].id,
                pending[h].amount_sats * 1000,  /* sats → msat */
                pending[h].payment_hash,
                pending[h].cltv_expiry);
            if (wire_send(new_fd, MSG_UPDATE_ADD_HTLC, add))
                printf("LSP reconnect: replayed HTLC %llu to client %zu\n",
                       (unsigned long long)pending[h].id, c);
            cJSON_Delete(add);
        }
    }

    printf("LSP: client %zu reconnected (commitment=%llu)\n",
           c, (unsigned long long)ch->commitment_number);
    return 1;
}

int lsp_channels_handle_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, int new_fd) {
    if (!mgr || !lsp || new_fd < 0) return 0;

    /* Read MSG_RECONNECT */
    wire_msg_t msg;
    if (!wire_recv(new_fd, &msg) || msg.msg_type != MSG_RECONNECT) {
        fprintf(stderr, "LSP reconnect: expected MSG_RECONNECT, got 0x%02x\n",
                msg.msg_type);
        if (msg.json) cJSON_Delete(msg.json);
        wire_close(new_fd);
        return 0;
    }

    int ret = handle_reconnect_with_msg(mgr, lsp, new_fd, &msg);
    cJSON_Delete(msg.json);
    return ret;
}

lsp_channel_entry_t *lsp_channels_get(lsp_channel_mgr_t *mgr, size_t client_idx) {
    if (!mgr || client_idx >= mgr->n_channels) return NULL;
    return &mgr->entries[client_idx];
}

size_t lsp_channels_build_close_outputs(const lsp_channel_mgr_t *mgr,
                                         const factory_t *factory,
                                         tx_output_t *outputs,
                                         uint64_t close_fee) {
    if (!mgr || !factory || !outputs) return 0;

    /* Output 0: LSP gets factory_funding - sum(client_remotes) - close_fee.
       In a cooperative close that bypasses the tree, the LSP recovers the
       tree transaction fees (funding_amount - sum_of_leaf_outputs). */
    uint64_t client_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++)
        client_total += mgr->entries[c].channel.remote_amount;

    if (factory->funding_amount_sats < client_total + close_fee) return 0;
    uint64_t lsp_total = factory->funding_amount_sats - client_total - close_fee;

    outputs[0].amount_sats = lsp_total;
    memcpy(outputs[0].script_pubkey, factory->funding_spk, factory->funding_spk_len);
    outputs[0].script_pubkey_len = factory->funding_spk_len;

    /* Outputs 1..N: each client gets their remote_amount */
    for (size_t c = 0; c < mgr->n_channels; c++) {
        outputs[c + 1].amount_sats = mgr->entries[c].channel.remote_amount;
        memcpy(outputs[c + 1].script_pubkey, factory->funding_spk, factory->funding_spk_len);
        outputs[c + 1].script_pubkey_len = factory->funding_spk_len;
    }

    /* Invariant: sum of outputs + close_fee == funding_amount */
    uint64_t sum = close_fee;
    for (size_t i = 0; i < mgr->n_channels + 1; i++)
        sum += outputs[i].amount_sats;
    if (sum != factory->funding_amount_sats) {
        fprintf(stderr, "lsp_channels_build_close_outputs: balance invariant failed "
                "(%llu vs %llu)\n", (unsigned long long)sum,
                (unsigned long long)factory->funding_amount_sats);
        return 0;
    }

    return mgr->n_channels + 1;
}

int lsp_channels_run_event_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t expected_msgs) {
    if (!mgr || !lsp) return 0;

    size_t handled = 0;
    while (handled < expected_msgs) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            int cfd = lsp->client_fds[c];
            FD_SET(cfd, &rfds);
            if (cfd > max_fd) max_fd = cfd;
        }

        /* Include bridge fd in select if connected */
        if (mgr->bridge_fd >= 0) {
            FD_SET(mgr->bridge_fd, &rfds);
            if (mgr->bridge_fd > max_fd) max_fd = mgr->bridge_fd;
        }

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) {
            fprintf(stderr, "LSP event loop: select timeout/error (handled %zu/%zu)\n",
                    handled, expected_msgs);
            return 0;
        }

        /* Handle bridge messages */
        if (mgr->bridge_fd >= 0 && FD_ISSET(mgr->bridge_fd, &rfds)) {
            wire_msg_t msg;
            if (!wire_recv(mgr->bridge_fd, &msg)) {
                fprintf(stderr, "LSP event loop: bridge recv failed\n");
                mgr->bridge_fd = -1;  /* bridge disconnected */
            } else {
                if (!lsp_channels_handle_bridge_msg(mgr, lsp, &msg)) {
                    fprintf(stderr, "LSP event loop: bridge handle failed 0x%02x\n",
                            msg.msg_type);
                }
                cJSON_Delete(msg.json);
                handled++;
            }
        }

        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (!FD_ISSET(lsp->client_fds[c], &rfds)) continue;

            wire_msg_t msg;
            if (!wire_recv(lsp->client_fds[c], &msg)) {
                fprintf(stderr, "LSP event loop: recv failed from client %zu\n", c);
                return 0;
            }

            if (!lsp_channels_handle_msg(mgr, lsp, c, &msg)) {
                fprintf(stderr, "LSP event loop: handle_msg failed for client %zu "
                        "msg 0x%02x\n", c, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }
            cJSON_Delete(msg.json);
            handled++;
        }
    }

    return 1;
}

/* --- Continuous Ladder Rotation (Gap #3) --- */

int lsp_channels_rotate_factory(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp || !mgr->ladder) return 0;

    ladder_t *lad = (ladder_t *)mgr->ladder;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    if (!fe) return 0;

    /* Find the DYING factory to rotate from */
    ladder_factory_t *dying = ladder_get_dying(lad);
    if (!dying) {
        fprintf(stderr, "LSP rotate: no DYING factory found\n");
        return 0;
    }
    uint32_t dying_id = dying->factory_id;
    printf("LSP rotate: starting rotation for factory %u\n", dying_id);

    /* Build combined keypair/pubkey arrays for adaptor protocol */
    size_t n_total = 1 + lsp->n_clients;
    secp256k1_keypair rot_kps[FACTORY_MAX_SIGNERS];
    secp256k1_pubkey rot_pks[FACTORY_MAX_SIGNERS];

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(mgr->ctx, &lsp_kp, mgr->rot_lsp_seckey))
        return 0;
    rot_kps[0] = lsp_kp;
    secp256k1_keypair_pub(mgr->ctx, &rot_pks[0], &lsp_kp);
    for (size_t i = 0; i < lsp->n_clients; i++) {
        rot_pks[i + 1] = lsp->client_pubkeys[i];
        /* We don't have client secret keys — only their pubkeys.
           Build dummy keypairs for the keyagg; actual signing uses
           the adaptor protocol (presig + adapt over wire). */
        rot_kps[i + 1] = lsp_kp;  /* placeholder — not used for signing */
    }

    musig_keyagg_t rot_ka;
    musig_aggregate_keys(mgr->ctx, &rot_ka, rot_pks, n_total);

    unsigned char turnover_msg[32];
    extern void sha256_tagged(const char *, const unsigned char *, size_t,
                               unsigned char *);
    sha256_tagged("turnover", (const unsigned char *)"turnover", 8, turnover_msg);

    /* --- Phase A: PTLC key turnover over wire --- */
    printf("LSP rotate: Phase A — PTLC key turnover\n");
    for (size_t ci = 0; ci < lsp->n_clients; ci++) {
        if (lsp->client_fds[ci] < 0) {
            printf("LSP rotate: client %zu offline, skipping turnover\n", ci);
            continue;
        }

        uint32_t pidx = (uint32_t)(ci + 1);
        secp256k1_pubkey client_pk = rot_pks[pidx];

        unsigned char presig[64];
        int nonce_parity;
        musig_keyagg_t ka_copy = rot_ka;
        if (!adaptor_create_turnover_presig(mgr->ctx, presig, &nonce_parity,
                                              turnover_msg, rot_kps, n_total,
                                              &ka_copy, NULL, &client_pk)) {
            fprintf(stderr, "LSP rotate: presig failed client %zu\n", ci);
            return 0;
        }

        /* Send PTLC_PRESIG to client */
        cJSON *pm = wire_build_ptlc_presig(presig, nonce_parity, turnover_msg);
        if (!wire_send(lsp->client_fds[ci], MSG_PTLC_PRESIG, pm)) {
            cJSON_Delete(pm);
            fprintf(stderr, "LSP rotate: send presig failed client %zu\n", ci);
            return 0;
        }
        cJSON_Delete(pm);

        /* Wait for PTLC_ADAPTED_SIG (30s timeout) */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsp->client_fds[ci], &rfds);
        struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
        int ret = select(lsp->client_fds[ci] + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) {
            fprintf(stderr, "LSP rotate: timeout waiting for adapted_sig from client %zu\n", ci);
            return 0;
        }

        wire_msg_t resp;
        if (!wire_recv(lsp->client_fds[ci], &resp) ||
            resp.msg_type != MSG_PTLC_ADAPTED_SIG) {
            if (resp.json) cJSON_Delete(resp.json);
            fprintf(stderr, "LSP rotate: no adapted_sig from client %zu\n", ci);
            return 0;
        }

        unsigned char adapted_sig[64];
        if (!wire_parse_ptlc_adapted_sig(resp.json, adapted_sig)) {
            cJSON_Delete(resp.json);
            fprintf(stderr, "LSP rotate: parse adapted_sig failed client %zu\n", ci);
            return 0;
        }
        cJSON_Delete(resp.json);

        /* Extract client's secret key */
        unsigned char extracted[32];
        if (!adaptor_extract_secret(mgr->ctx, extracted, adapted_sig, presig,
                                      nonce_parity)) {
            fprintf(stderr, "LSP rotate: extract failed client %zu\n", ci);
            return 0;
        }
        if (!adaptor_verify_extracted_key(mgr->ctx, extracted, &client_pk)) {
            fprintf(stderr, "LSP rotate: verify failed client %zu\n", ci);
            return 0;
        }

        ladder_record_key_turnover(lad, dying_id, pidx, extracted);
        if (mgr->persist)
            persist_save_departed_client((persist_t *)mgr->persist,
                                          dying_id, pidx, extracted);

        /* Send PTLC_COMPLETE */
        cJSON *cm = wire_build_ptlc_complete();
        wire_send(lsp->client_fds[ci], MSG_PTLC_COMPLETE, cm);
        cJSON_Delete(cm);

        printf("LSP rotate: client %zu key extracted via wire PTLC\n", ci + 1);
    }

    /* Check if all online clients departed */
    if (!ladder_can_close(lad, dying_id)) {
        fprintf(stderr, "LSP rotate: not all clients departed, cannot close factory %u\n",
                dying_id);
        return 0;
    }

    /* --- Phase B: Cooperative close of dying factory --- */
    printf("LSP rotate: Phase B — cooperative close of factory %u\n", dying_id);

    tx_output_t rot_outputs[FACTORY_MAX_SIGNERS];
    uint64_t close_fee = fee_estimate(fe, 200);
    if (close_fee == 0) {
        /* Floor: 1 sat/vB for 200 vB close tx */
        close_fee = 200;
        fprintf(stderr, "LSP rotate: WARNING: fee estimation returned 0, "
                "using 1 sat/vB floor (%llu sats)\n",
                (unsigned long long)close_fee);
    }
    size_t n_close = lsp_channels_build_close_outputs(mgr, &lsp->factory,
                                                        rot_outputs, close_fee);
    if (n_close == 0) {
        /* Fallback: equal split */
        uint64_t per = (lsp->factory.funding_amount_sats - close_fee) / n_total;
        for (size_t ti = 0; ti < n_total; ti++) {
            rot_outputs[ti].amount_sats = per;
            memcpy(rot_outputs[ti].script_pubkey, mgr->rot_fund_spk, 34);
            rot_outputs[ti].script_pubkey_len = 34;
        }
        rot_outputs[n_total - 1].amount_sats =
            lsp->factory.funding_amount_sats - close_fee - per * (n_total - 1);
        n_close = n_total;
    }

    tx_buf_t rot_close_tx;
    tx_buf_init(&rot_close_tx, 512);
    if (!ladder_build_close(lad, dying_id, &rot_close_tx, rot_outputs, n_close)) {
        fprintf(stderr, "LSP rotate: ladder_build_close failed\n");
        tx_buf_free(&rot_close_tx);
        return 0;
    }

    extern void hex_encode(const unsigned char *, size_t, char *);
    extern int hex_decode(const char *, unsigned char *, size_t);
    extern void reverse_bytes(unsigned char *, size_t);

    char *rc_hex = malloc(rot_close_tx.len * 2 + 1);
    hex_encode(rot_close_tx.data, rot_close_tx.len, rc_hex);
    char rc_txid[65];
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
    if (!rt) {
        free(rc_hex);
        tx_buf_free(&rot_close_tx);
        fprintf(stderr, "LSP rotate: no regtest connection\n");
        return 0;
    }
    int rc_sent = regtest_send_raw_tx(rt, rc_hex, rc_txid);
    if (mgr->persist) {
        persist_log_broadcast((persist_t *)mgr->persist,
                              rc_sent ? rc_txid : "?", "rotation_close",
                              rc_hex, rc_sent ? "ok" : "failed");
    }
    free(rc_hex);
    tx_buf_free(&rot_close_tx);

    if (!rc_sent) {
        fprintf(stderr, "LSP rotate: close TX broadcast failed\n");
        return 0;
    }

    if (mgr->rot_is_regtest) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
    } else {
        printf("LSP rotate: waiting for close TX confirmation...\n");
        int conf = regtest_wait_for_confirmation(rt, rc_txid, 7200);
        if (conf < 1) {
            fprintf(stderr, "LSP rotate: close TX not confirmed\n");
            return 0;
        }
    }
    printf("LSP rotate: factory %u closed: %s\n", dying_id, rc_txid);

    /* --- Phase C: Create new factory --- */
    printf("LSP rotate: Phase C — creating new factory\n");

    /* Fund new factory */
    if (mgr->rot_is_regtest) {
        /* Ensure wallet has funds */
        double bal = regtest_get_balance(rt);
        if (bal < 0.01) {
            regtest_mine_blocks(rt, 10, mgr->rot_mine_addr);
        }
    } else {
        double bal = regtest_get_balance(rt);
        double needed = (double)mgr->rot_funding_sats / 100000000.0;
        if (bal < needed) {
            fprintf(stderr, "LSP rotate: insufficient balance %.8f (need %.8f)\n",
                    bal, needed);
            return 0;
        }
    }

    double funding_btc = (double)mgr->rot_funding_sats / 100000000.0;
    char fund_txid_hex[65];
    if (!regtest_fund_address(rt, mgr->rot_fund_addr, funding_btc, fund_txid_hex)) {
        fprintf(stderr, "LSP rotate: fund new factory failed\n");
        return 0;
    }
    if (mgr->rot_is_regtest) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
    } else {
        printf("LSP rotate: waiting for funding confirmation...\n");
        if (regtest_wait_for_confirmation(rt, fund_txid_hex, 7200) < 1) {
            fprintf(stderr, "LSP rotate: funding not confirmed\n");
            return 0;
        }
    }

    unsigned char fund_txid[32];
    hex_decode(fund_txid_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);

    uint64_t fund_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t fund_vout = 0;
    for (uint32_t v = 0; v < 4; v++) {
        regtest_get_tx_output(rt, fund_txid_hex, v,
                              &fund_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == mgr->rot_fund_spk_len &&
            memcmp(actual_spk, mgr->rot_fund_spk, mgr->rot_fund_spk_len) == 0) {
            fund_vout = v;
            break;
        }
    }
    if (fund_amount == 0) {
        fprintf(stderr, "LSP rotate: could not find funding output\n");
        return 0;
    }
    printf("LSP rotate: funded %llu sats, txid: %s, vout=%u\n",
           (unsigned long long)fund_amount, fund_txid_hex, fund_vout);

    /* Free old factory, but preserve arity for new factory */
    factory_arity_t saved_arity = (factory_arity_t)mgr->rot_leaf_arity;
    factory_free(&lsp->factory);
    /* Restore arity on the zeroed struct so lsp_run_factory_creation's
       saved_arity = f->leaf_arity picks it up correctly. */
    lsp->factory.leaf_arity = saved_arity;

    /* Compute cltv_timeout for new factory */
    uint32_t new_cltv = 0;
    {
        int cur_h = regtest_get_block_height(rt);
        if (cur_h > 0) {
            int offset = mgr->rot_is_regtest ? 35 : 1008;
            new_cltv = (uint32_t)cur_h + offset;
        }
    }

    /* Run factory creation ceremony (sends FACTORY_PROPOSE to clients) */
    if (!lsp_run_factory_creation(lsp,
                                   fund_txid, fund_vout,
                                   fund_amount,
                                   mgr->rot_fund_spk, mgr->rot_fund_spk_len,
                                   mgr->rot_step_blocks,
                                   mgr->rot_states_per_layer, new_cltv)) {
        fprintf(stderr, "LSP rotate: new factory creation failed\n");
        return 0;
    }

    /* Set lifecycle for new factory */
    {
        int cur_h = regtest_get_block_height(rt);
        if (cur_h > 0)
            factory_set_lifecycle(&lsp->factory, (uint32_t)cur_h,
                                  lad->active_blocks, lad->dying_blocks);
    }
    lsp->factory.fee = fe;

    /* Evict expired factories if at max capacity */
    if (lad->n_factories >= LADDER_MAX_FACTORIES)
        ladder_evict_expired(lad);

    /* Store new factory in next ladder slot */
    if (lad->n_factories < LADDER_MAX_FACTORIES) {
        ladder_factory_t *lf_new = &lad->factories[lad->n_factories];
        memset(lf_new, 0, sizeof(*lf_new));
        lf_new->factory = lsp->factory;
        lf_new->factory_id = lad->next_factory_id++;
        lf_new->is_initialized = 1;
        lf_new->is_funded = 1;
        lf_new->cached_state = FACTORY_ACTIVE;
        tx_buf_init(&lf_new->distribution_tx, 256);
        lad->n_factories++;
    } else {
        fprintf(stderr, "LSP rotate: no ladder slots available\n");
        return 0;
    }

    /* Persist new factory (transactional) */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        if (!persist_begin(db)) {
            fprintf(stderr, "LSP rotate: persist_begin failed\n");
            return 0;
        }
        if (!persist_save_factory(db, &lsp->factory, mgr->ctx, 0) ||
            !persist_save_tree_nodes(db, &lsp->factory, 0)) {
            fprintf(stderr, "LSP rotate: factory persist failed, rolling back\n");
            persist_rollback(db);
            return 0;
        } else {
            persist_commit(db);
        }
    }

    /* --- Phase D: Reinitialize channels --- */
    printf("LSP rotate: Phase D — reinitializing channels\n");

    /* Save rotation + infrastructure state before lsp_channels_init memset */
    int saved_bridge_fd = mgr->bridge_fd;
    watchtower_t *saved_wt = mgr->watchtower;
    void *saved_persist = mgr->persist;
    void *saved_ladder = mgr->ladder;
    /* JIT channel state preserved across reinit */
    void *saved_jit = mgr->jit_channels;
    size_t saved_n_jit = mgr->n_jit_channels;
    int saved_jit_enabled = mgr->jit_enabled;
    uint64_t saved_jit_funding = mgr->jit_funding_sats;
    unsigned char saved_seckey[32];
    memcpy(saved_seckey, mgr->rot_lsp_seckey, 32);
    void *saved_fee_est = mgr->rot_fee_est;
    unsigned char saved_fund_spk[34];
    memcpy(saved_fund_spk, mgr->rot_fund_spk, 34);
    size_t saved_fund_spk_len = mgr->rot_fund_spk_len;
    char saved_fund_addr[128];
    memcpy(saved_fund_addr, mgr->rot_fund_addr, 128);
    char saved_mine_addr[128];
    memcpy(saved_mine_addr, mgr->rot_mine_addr, 128);
    uint16_t saved_step_blocks = mgr->rot_step_blocks;
    uint32_t saved_spl = mgr->rot_states_per_layer;
    int saved_leaf_arity = mgr->rot_leaf_arity;
    int saved_is_regtest = mgr->rot_is_regtest;
    uint64_t saved_funding_sats = mgr->rot_funding_sats;
    int saved_auto_rotate = mgr->rot_auto_rotate;
    uint32_t saved_attempted_mask = mgr->rot_attempted_mask;

    if (!lsp_channels_init(mgr, mgr->ctx, &lsp->factory,
                            saved_seckey, lsp->n_clients)) {
        fprintf(stderr, "LSP rotate: channel reinit failed\n");
        memset(saved_seckey, 0, 32);
        return 0;
    }

    /* Restore saved state */
    mgr->bridge_fd = saved_bridge_fd;
    mgr->watchtower = saved_wt;
    mgr->persist = saved_persist;
    mgr->ladder = saved_ladder;
    memcpy(mgr->rot_lsp_seckey, saved_seckey, 32);
    memset(saved_seckey, 0, 32);
    mgr->rot_fee_est = saved_fee_est;
    memcpy(mgr->rot_fund_spk, saved_fund_spk, 34);
    mgr->rot_fund_spk_len = saved_fund_spk_len;
    memcpy(mgr->rot_fund_addr, saved_fund_addr, 128);
    memcpy(mgr->rot_mine_addr, saved_mine_addr, 128);
    mgr->rot_step_blocks = saved_step_blocks;
    mgr->rot_states_per_layer = saved_spl;
    mgr->rot_leaf_arity = saved_leaf_arity;
    mgr->rot_is_regtest = saved_is_regtest;
    mgr->rot_funding_sats = saved_funding_sats;
    mgr->rot_auto_rotate = saved_auto_rotate;
    mgr->rot_attempted_mask = saved_attempted_mask;
    mgr->jit_channels = saved_jit;
    mgr->n_jit_channels = saved_n_jit;
    mgr->jit_enabled = saved_jit_enabled;
    mgr->jit_funding_sats = saved_jit_funding;

    if (!lsp_channels_exchange_basepoints(mgr, lsp)) {
        fprintf(stderr, "LSP rotate: basepoint exchange failed\n");
        return 0;
    }

    /* Set fee rate on all new channels */
    uint64_t fee_rate = fe->fee_rate_sat_per_kvb;
    for (size_t c = 0; c < mgr->n_channels; c++)
        mgr->entries[c].channel.fee_rate_sat_per_kvb = fee_rate;

    if (!lsp_channels_send_ready(mgr, lsp)) {
        fprintf(stderr, "LSP rotate: send_ready failed\n");
        return 0;
    }

    /* Update watchtower channel pointers */
    if (mgr->watchtower) {
        for (size_t c = 0; c < mgr->n_channels; c++)
            watchtower_set_channel(mgr->watchtower, c,
                                    &mgr->entries[c].channel);
    }

    /* Persist new channel state (transactional) */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        if (!persist_begin(db)) {
            fprintf(stderr, "LSP rotate: persist_begin failed for channels\n");
            return 0;
        }
        int ch_ok = 1;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (!persist_save_channel(db, &mgr->entries[c].channel, 0, (uint32_t)c)) {
                ch_ok = 0;
                break;
            }
        }
        if (ch_ok) {
            persist_commit(db);
        } else {
            fprintf(stderr, "LSP rotate: channel persist failed, rolling back\n");
            persist_rollback(db);
            return 0;
        }
    }

    /* Migrate any active JIT channels into the new factory */
    for (size_t c = 0; c < mgr->n_channels; c++) {
        if (jit_channel_is_active(mgr, c)) {
            printf("LSP rotate: migrating JIT channel for client %zu\n", c);
            jit_channel_migrate(mgr, lsp, c, 0);
        }
    }

    printf("LSP rotate: rotation complete — new factory active with %zu channels\n",
           mgr->n_channels);
    return 1;
}

int lsp_channels_run_daemon_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   volatile sig_atomic_t *shutdown_flag) {
    if (!mgr || !lsp || !shutdown_flag) return 0;

    printf("LSP: daemon loop started (Ctrl+C to stop)\n");

    while (!(*shutdown_flag)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            int cfd = lsp->client_fds[c];
            if (cfd < 0) continue;  /* skip disconnected clients */
            FD_SET(cfd, &rfds);
            if (cfd > max_fd) max_fd = cfd;
        }

        /* Include bridge fd in select if connected */
        if (mgr->bridge_fd >= 0) {
            FD_SET(mgr->bridge_fd, &rfds);
            if (mgr->bridge_fd > max_fd) max_fd = mgr->bridge_fd;
        }

        /* Include listen_fd for reconnections (Phase 16) */
        if (lsp->listen_fd >= 0) {
            FD_SET(lsp->listen_fd, &rfds);
            if (lsp->listen_fd > max_fd) max_fd = lsp->listen_fd;
        }

        if (max_fd < 0) {
            /* No fds to watch — all clients disconnected, no listen socket */
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            select(0, NULL, NULL, NULL, &tv);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            /* EINTR from signal — check shutdown flag */
            continue;
        }
        if (ret == 0) {
            /* Timeout — run watchtower check if available */
            if (mgr->watchtower)
                watchtower_check(mgr->watchtower);
            /* Check HTLC timeouts if we have a chain connection */
            if (mgr->watchtower && mgr->watchtower->rt) {
                int height = regtest_get_block_height(mgr->watchtower->rt);
                if (height > 0) {
                    for (size_t c = 0; c < mgr->n_channels; c++) {
                        channel_t *ch = &mgr->entries[c].channel;
                        int n_failed = channel_check_htlc_timeouts(ch, (uint32_t)height);
                        if (n_failed > 0) {
                            printf("LSP: auto-failed %d expired HTLCs on channel %zu "
                                   "(height=%d)\n", n_failed, c, height);
                        }
                    }
                    /* Factory lifecycle monitoring */
                    factory_state_t fstate = factory_get_state(
                        &lsp->factory, (uint32_t)height);
                    if (fstate == FACTORY_DYING)
                        printf("LSP: factory DYING (%u blocks to expiry)\n",
                               factory_blocks_until_expired(&lsp->factory,
                                                            (uint32_t)height));
                    else if (fstate == FACTORY_EXPIRED)
                        printf("LSP: factory EXPIRED at height %d\n", height);

                    /* Ladder state tracking (Tier 2 → Tier 3: multi-factory) */
                    if (mgr->ladder) {
                        ladder_t *lad = (ladder_t *)mgr->ladder;
                        /* Save old states */
                        factory_state_t old_states[LADDER_MAX_FACTORIES];
                        for (size_t fi = 0; fi < lad->n_factories; fi++)
                            old_states[fi] = lad->factories[fi].cached_state;

                        ladder_advance_block(lad, (uint32_t)height);

                        for (size_t fi = 0; fi < lad->n_factories; fi++) {
                            ladder_factory_t *lf = &lad->factories[fi];
                            if (lf->cached_state != old_states[fi]) {
                                const char *st_names[] = {
                                    "ACTIVE", "DYING", "EXPIRED" };
                                int si = (int)lf->cached_state;
                                const char *st_str = (si >= 0 && si <= 2) ?
                                    st_names[si] : "UNKNOWN";
                                printf("LSP: ladder factory %zu -> %s at height %d\n",
                                       fi, st_str, height);
                                if (mgr->persist) {
                                    const char *ps[] = {
                                        "active", "dying", "expired" };
                                    persist_save_ladder_factory(
                                        (persist_t *)mgr->persist,
                                        (uint32_t)lf->factory_id,
                                        (si >= 0 && si <= 2) ? ps[si] : "unknown",
                                        lf->is_funded,
                                        lf->is_initialized,
                                        lf->n_departed,
                                        lf->factory.created_block,
                                        lf->factory.active_blocks,
                                        lf->factory.dying_blocks);
                                }
                                /* Auto-broadcast distribution TX on EXPIRED */
                                if (lf->cached_state == FACTORY_EXPIRED &&
                                    lf->distribution_tx.len > 0 &&
                                    mgr->watchtower && mgr->watchtower->rt) {
                                    char *dhex = malloc(lf->distribution_tx.len * 2 + 1);
                                    if (dhex) {
                                        extern void hex_encode(const unsigned char *,
                                                               size_t, char *);
                                        hex_encode(lf->distribution_tx.data,
                                                   lf->distribution_tx.len, dhex);
                                        char dtxid[65];
                                        if (regtest_send_raw_tx(mgr->watchtower->rt,
                                                                 dhex, dtxid))
                                            printf("LSP: distribution TX broadcast: %s\n",
                                                   dtxid);
                                        free(dhex);
                                    }
                                }

                                /* Auto-rotate when a factory enters DYING */
                                if (mgr->rot_auto_rotate &&
                                    lf->cached_state == FACTORY_DYING &&
                                    old_states[fi] == FACTORY_ACTIVE &&
                                    !(mgr->rot_attempted_mask & (1u << lf->factory_id))) {
                                    printf("LSP: factory %u DYING — starting auto-rotation\n",
                                           lf->factory_id);
                                    mgr->rot_attempted_mask |= (1u << lf->factory_id);
                                    int ok = lsp_channels_rotate_factory(mgr, lsp);
                                    if (ok)
                                        printf("LSP: auto-rotation complete — new factory active\n");
                                    else
                                        fprintf(stderr, "LSP: auto-rotation FAILED for factory %u\n",
                                                lf->factory_id);
                                }
                            }
                        }
                    }
                }
            }

            /* Check if DW counter is near exhaustion — trigger epoch reset */
            if (!dw_counter_is_exhausted(&lsp->factory.counter)) {
                uint32_t epoch = dw_counter_epoch(&lsp->factory.counter);
                uint32_t total = lsp->factory.counter.total_states;
                if (total > 0 && epoch >= (total * 3) / 4) {
                    printf("LSP: DW counter at %u/%u (>75%%) — epoch reset needed\n",
                           epoch, total);
                    /* In distributed mode, this would orchestrate a 3-round
                       signing ceremony via MSG_EPOCH_RESET_PROPOSE/PSIG/DONE.
                       For local signing (PoC), call factory_reset_epoch directly. */
                    if (factory_reset_epoch(&lsp->factory))
                        printf("LSP: epoch reset complete — counter back to 0\n");
                    else
                        fprintf(stderr, "LSP: epoch reset FAILED\n");
                }
            }

            /* Offline detection: mark clients with no message for 120s */
            {
                time_t now = time(NULL);
                for (size_t c = 0; c < mgr->n_channels; c++) {
                    if (lsp->client_fds[c] < 0) continue;
                    if (mgr->entries[c].offline_detected) continue;
                    if (now - mgr->entries[c].last_message_time >=
                        JIT_OFFLINE_TIMEOUT_SEC) {
                        fprintf(stderr, "LSP: client %zu offline (no message for %ds)\n",
                                c, JIT_OFFLINE_TIMEOUT_SEC);
                        wire_close(lsp->client_fds[c]);
                        lsp->client_fds[c] = -1;
                        mgr->entries[c].offline_detected = 1;
                    }
                }
            }

            /* JIT channel trigger: factory expired + client online + no JIT */
            if (mgr->jit_enabled) {
                int all_expired = 1;
                if (mgr->ladder) {
                    ladder_t *lad = (ladder_t *)mgr->ladder;
                    for (size_t fi = 0; fi < lad->n_factories; fi++) {
                        if (lad->factories[fi].cached_state != FACTORY_EXPIRED) {
                            all_expired = 0;
                            break;
                        }
                    }
                    if (lad->n_factories == 0)
                        all_expired = 0; /* no factories at all != expired */
                } else {
                    /* Single-factory mode: check main factory */
                    if (mgr->watchtower && mgr->watchtower->rt) {
                        int h = regtest_get_block_height(mgr->watchtower->rt);
                        factory_state_t fs = factory_get_state(&lsp->factory, (uint32_t)h);
                        all_expired = (fs == FACTORY_EXPIRED) ? 1 : 0;
                    } else {
                        all_expired = 0;
                    }
                }

                if (all_expired) {
                    for (size_t c = 0; c < mgr->n_channels; c++) {
                        if (lsp->client_fds[c] >= 0 &&
                            !jit_channel_is_active(mgr, c)) {
                            uint64_t jit_amt = mgr->jit_funding_sats;
                            if (jit_amt == 0)
                                jit_amt = mgr->rot_funding_sats / mgr->n_channels;
                            if (jit_amt > 0) {
                                printf("LSP: opening JIT channel for client %zu "
                                       "(factory expired)\n", c);
                                jit_channel_create(mgr, lsp, c, jit_amt,
                                                    "factory_expired");
                            }
                        }
                    }
                }
            }

            /* Check JIT funding confirmation (FUNDING → OPEN) */
            jit_channels_check_funding(mgr);

            continue;
        }

        /* Handle new connections on listen_fd (bridge or client reconnect) */
        if (lsp->listen_fd >= 0 && FD_ISSET(lsp->listen_fd, &rfds)) {
            int new_fd = wire_accept(lsp->listen_fd);
            if (new_fd >= 0) {
                /* Noise handshake */
                if (!wire_noise_handshake_responder(new_fd, mgr->ctx)) {
                    wire_close(new_fd);
                } else {
                    /* Peek at first message to distinguish bridge vs client */
                    wire_msg_t peek;
                    if (wire_recv(new_fd, &peek)) {
                        if (peek.msg_type == MSG_BRIDGE_HELLO) {
                            /* Bridge connection */
                            cJSON_Delete(peek.json);
                            cJSON *ack = wire_build_bridge_hello_ack();
                            wire_send(new_fd, MSG_BRIDGE_HELLO_ACK, ack);
                            cJSON_Delete(ack);
                            lsp->bridge_fd = new_fd;
                            mgr->bridge_fd = new_fd;
                            printf("LSP: bridge connected in daemon loop (fd=%d)\n", new_fd);
                        } else if (peek.msg_type == MSG_RECONNECT) {
                            /* Client reconnect — use pre-read message */
                            int ret = handle_reconnect_with_msg(mgr, lsp, new_fd, &peek);
                            cJSON_Delete(peek.json);
                            if (!ret) {
                                fprintf(stderr, "LSP daemon: reconnect handshake failed\n");
                            }
                        } else {
                            fprintf(stderr, "LSP daemon: unexpected msg 0x%02x from new connection\n",
                                    peek.msg_type);
                            cJSON_Delete(peek.json);
                            wire_close(new_fd);
                        }
                    } else {
                        wire_close(new_fd);
                    }
                }
            }
        }

        /* Handle bridge messages */
        if (mgr->bridge_fd >= 0 && FD_ISSET(mgr->bridge_fd, &rfds)) {
            wire_msg_t msg;
            if (!wire_recv(mgr->bridge_fd, &msg)) {
                fprintf(stderr, "LSP daemon: bridge disconnected\n");
                mgr->bridge_fd = -1;
            } else {
                if (!lsp_channels_handle_bridge_msg(mgr, lsp, &msg)) {
                    fprintf(stderr, "LSP daemon: bridge handle failed 0x%02x\n",
                            msg.msg_type);
                }
                cJSON_Delete(msg.json);
            }
        }

        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (lsp->client_fds[c] < 0) continue;
            if (!FD_ISSET(lsp->client_fds[c], &rfds)) continue;

            wire_msg_t msg;
            if (!wire_recv(lsp->client_fds[c], &msg)) {
                fprintf(stderr, "LSP daemon: client %zu disconnected\n", c);
                wire_close(lsp->client_fds[c]);
                lsp->client_fds[c] = -1;
                continue;
            }

            if (!lsp_channels_handle_msg(mgr, lsp, c, &msg)) {
                fprintf(stderr, "LSP daemon: handle_msg failed for client %zu "
                        "msg 0x%02x\n", c, msg.msg_type);
            }
            cJSON_Delete(msg.json);
        }
    }

    printf("LSP: daemon loop stopped (shutdown requested)\n");
    return 1;
}

/* --- Demo mode (Phase 17) --- */

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
            unsigned char ph[32];
            uint64_t am;
            size_t dc;
            if (wire_parse_register_invoice(msg->json, ph, &am, &dc))
                lsp_channels_register_invoice(mgr, ph, dc, am);
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
                unsigned char ph[32];
                uint64_t am;
                size_t dc;
                if (wire_parse_register_invoice(drain_msg.json, ph, &am, &dc))
                    lsp_channels_register_invoice(mgr, ph, dc, am);
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
