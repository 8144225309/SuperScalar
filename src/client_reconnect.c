/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248) — client reconnect/recovery.
 *
 * Extracted from src/client.c so the trustless watchtower binary's link
 * set does NOT transitively pull in persist_load_basepoints +
 * persist_load_commitment_sig via client_run_reconnect.  This TU is part
 * of the superscalar_secrets static library; superscalar_watchtower does
 * not link it.
 *
 * The client binary calls this function via the prototype in
 * include/superscalar/client.h (unchanged).
 */

#include "superscalar/client.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/peer_mgr.h"
#include "superscalar/wire.h"
#include "superscalar/regtest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248): shared state in src/client.c. */
extern factory_t *g_client_active_factory;
extern secp256k1_pubkey g_client_nk_server_pubkey;
extern int g_client_nk_server_pubkey_set;
#define g_nk_server_pubkey     g_client_nk_server_pubkey
#define g_nk_server_pubkey_set g_client_nk_server_pubkey_set

int client_run_reconnect(secp256k1_context *ctx,
                           const secp256k1_keypair *keypair,
                           const char *host, int port,
                           persist_t *db,
                           client_channel_cb_t channel_cb,
                           void *user_data) {
    if (!ctx || !keypair || !db) return 0;

    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    /* 1. Load factory from DB (heap — factory_t is ~3MB) */
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    if (!persist_load_factory(db, 0, factory, ctx)) {
        fprintf(stderr, "Client reconnect: failed to load factory from DB\n");
        free(factory);
        return 0;
    }
    /* SF-followup #145: register active factory for MSG_FUNDING_REORG reset
       (mirror of LSP-side #208). */
    g_client_active_factory = factory;

    /* 2. Determine my_index by matching pubkey against factory->pubkeys[] */
    uint32_t my_index = 0;
    {
        unsigned char my_ser[33], cmp_ser[33];
        size_t len1 = 33, len2 = 33;
        secp256k1_ec_pubkey_serialize(ctx, my_ser, &len1, &my_pubkey,
                                       SECP256K1_EC_COMPRESSED);
        for (size_t i = 0; i < factory->n_participants; i++) {
            len2 = 33;
            secp256k1_ec_pubkey_serialize(ctx, cmp_ser, &len2,
                                           &factory->pubkeys[i],
                                           SECP256K1_EC_COMPRESSED);
            if (memcmp(my_ser, cmp_ser, 33) == 0) {
                my_index = (uint32_t)i;
                break;
            }
        }
        if (my_index == 0) {
            fprintf(stderr, "Client reconnect: pubkey not found in factory\n");
            factory_free(factory);
            free(factory);
            return 0;
        }
    }

    size_t n_participants = factory->n_participants;

    /* 3. Connect to LSP */
    int fd = wire_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "Client reconnect: connect failed\n");
        factory_free(factory);
        free(factory);
        return 0;
    }
    wire_set_peer_label(fd, "lsp");

    /* Encrypted transport handshake (NK if server pubkey pinned) */
    int reconn_hs_ok;
    if (g_nk_server_pubkey_set)
        reconn_hs_ok = wire_noise_handshake_nk_initiator(fd, ctx, &g_nk_server_pubkey);
    else
        reconn_hs_ok = wire_noise_handshake_initiator(fd, ctx);
    if (!reconn_hs_ok) {
        fprintf(stderr, "Client reconnect: noise handshake failed\n");
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }

    /* 4. Load persisted channel state to get commitment_number */
    uint32_t client_idx = my_index - 1;  /* 0-based client index */
    uint64_t local_amount = 0, remote_amount = 0, commitment_number = 0;
    persist_load_channel_state(db, client_idx, &local_amount, &remote_amount,
                                 &commitment_number);

    /* 5. Send MSG_RECONNECT */
    {
        cJSON *reconn = wire_build_reconnect(ctx, &my_pubkey, commitment_number);
        if (!wire_send(fd, MSG_RECONNECT, reconn)) {
            fprintf(stderr, "Client reconnect: send MSG_RECONNECT failed\n");
            cJSON_Delete(reconn);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(reconn);
    }

    /* 6. Load basepoints from persistence */
    unsigned char local_secs[4][32];
    unsigned char remote_bps[4][33];
    if (!persist_load_basepoints(db, client_idx, local_secs, remote_bps)) {
        fprintf(stderr, "Client reconnect: no basepoints in DB for channel %u\n", client_idx);
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }

    secp256k1_pubkey reconn_lsp_pay_bp, reconn_lsp_delay_bp, reconn_lsp_revoc_bp, reconn_lsp_htlc_bp;
    if (!secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_pay_bp, remote_bps[0], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_delay_bp, remote_bps[1], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_revoc_bp, remote_bps[2], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_htlc_bp, remote_bps[3], 33)) {
        fprintf(stderr, "Client reconnect: failed to parse remote basepoints\n");
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }

    channel_t channel;
    if (!client_init_channel(&channel, ctx, factory, keypair, my_index,
                              &reconn_lsp_pay_bp, &reconn_lsp_delay_bp,
                              &reconn_lsp_revoc_bp, &reconn_lsp_htlc_bp,
                              local_secs[0], local_secs[1], local_secs[2], local_secs[3], NULL)) {
        fprintf(stderr, "Client reconnect: channel init failed\n");
        memset(local_secs, 0, sizeof(local_secs));
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }
    memset(local_secs, 0, sizeof(local_secs));

    /* 7. Overwrite channel state with persisted values */
    if (local_amount > 0 || remote_amount > 0) {
        channel.local_amount = local_amount;
        channel.remote_amount = remote_amount;
        channel.commitment_number = commitment_number;

        /* Restore local per-commitment secrets from DB.  These MUST match
           the per-commitment points the LSP has stored as our remote PCPs,
           otherwise commitment signature verification fails post-reconnect. */
        if (db) {
            size_t pcs_max = (size_t)(commitment_number + 2);
            unsigned char (*pcs_arr)[32] = calloc(pcs_max, 32);
            if (pcs_arr) {
                size_t pcs_loaded = 0;
                persist_load_local_pcs(db, 0, pcs_arr, pcs_max, &pcs_loaded);
                for (uint64_t cn = 0; cn < pcs_max; cn++) {
                    /* Check if entry was loaded (non-zero) */
                    int nonzero = 0;
                    for (int j = 0; j < 32; j++)
                        if (pcs_arr[cn][j]) { nonzero = 1; break; }
                    if (nonzero)
                        channel_set_local_pcs(&channel, cn, pcs_arr[cn]);
                }
                memset(pcs_arr, 0, pcs_max * 32);
                free(pcs_arr);
            }
        }

        /* Display any persisted in-flight HTLCs for user visibility */
        if (db) {
            htlc_t loaded_htlcs[16];
            size_t n_loaded = persist_load_htlcs(db, client_idx,
                                                   loaded_htlcs, 16);
            if (n_loaded > 0) {
                printf("Client reconnect: %zu persisted HTLC(s) from DB:\n",
                       n_loaded);
                for (size_t hi = 0; hi < n_loaded; hi++) {
                    printf("  HTLC #%llu: %llu sats (%s, %s)\n",
                           (unsigned long long)loaded_htlcs[hi].id,
                           (unsigned long long)loaded_htlcs[hi].amount_sats,
                           loaded_htlcs[hi].direction == HTLC_OFFERED
                               ? "offered" : "received",
                           loaded_htlcs[hi].state == HTLC_STATE_ACTIVE
                               ? "active"
                               : loaded_htlcs[hi].state == HTLC_STATE_FULFILLED
                                   ? "fulfilled" : "failed");
                }
            }
        }

        /* Generate random PCS only for commitment numbers not restored from DB */
        for (uint64_t cn = channel.n_local_pcs; cn <= commitment_number + 1; cn++)
            channel_generate_local_pcs(&channel, cn);

        /* Restore remote per-commitment points from DB so the channel
           can verify commitment signatures after reconnect. */
        if (db) {
            unsigned char pcp_ser[33];
            secp256k1_pubkey pcp;
            if (persist_load_remote_pcp(db, 0, commitment_number, pcp_ser) &&
                secp256k1_ec_pubkey_parse(ctx, &pcp, pcp_ser, 33))
                channel_set_remote_pcp(&channel, commitment_number, &pcp);
            if (persist_load_remote_pcp(db, 0, commitment_number + 1, pcp_ser) &&
                secp256k1_ec_pubkey_parse(ctx, &pcp, pcp_ser, 33))
                channel_set_remote_pcp(&channel, commitment_number + 1, &pcp);
        }
    }

    /* 7b. Restore latest commitment TX signature for force-close capability */
    if (db) {
        uint64_t sig_cn = 0;
        unsigned char sig64[64];
        if (persist_load_commitment_sig(db, client_idx, &sig_cn, sig64,
                                         NULL, NULL, 0) &&
            sig_cn == commitment_number) {
            memcpy(channel.latest_commitment_sig, sig64, 64);
            channel.has_latest_commitment_sig = 1;
        }
        memset(sig64, 0, 64);
    }

    /* 8. Nonce exchange — LSP sends CHANNEL_NONCES before RECONNECT_ACK */
    /* Receive LSP's pubnonces */
    {
        wire_msg_t msg;
        if (!wire_recv(fd, &msg) || msg.msg_type != MSG_CHANNEL_NONCES) {
            fprintf(stderr, "Client reconnect: expected CHANNEL_NONCES from LSP\n");
            if (msg.json) cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }

        uint32_t nonce_ch_id;
        unsigned char lsp_nonces[MUSIG_NONCE_POOL_MAX][66];
        size_t lsp_nonce_count;
        if (!wire_parse_channel_nonces(msg.json, &nonce_ch_id,
                                         lsp_nonces, MUSIG_NONCE_POOL_MAX,
                                         &lsp_nonce_count)) {
            fprintf(stderr, "Client reconnect: failed to parse LSP nonces\n");
            cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(msg.json);

        /* Init client nonce pool */
        if (!channel_init_nonce_pool(&channel, lsp_nonce_count)) {
            fprintf(stderr, "Client reconnect: nonce pool init failed\n");
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }

        /* Send client's pubnonces */
        size_t my_nonce_count = channel.local_nonce_pool.count;
        unsigned char (*my_pubnonces_ser)[66] =
            (unsigned char (*)[66])calloc(my_nonce_count, 66);
        if (!my_pubnonces_ser) {
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        for (size_t i = 0; i < my_nonce_count; i++) {
            musig_pubnonce_serialize(ctx,
                my_pubnonces_ser[i],
                &channel.local_nonce_pool.nonces[i].pubnonce);
        }

        cJSON *nonce_reply = wire_build_channel_nonces(
            client_idx,
            (const unsigned char (*)[66])my_pubnonces_ser,
            my_nonce_count);
        if (!wire_send(fd, MSG_CHANNEL_NONCES, nonce_reply)) {
            fprintf(stderr, "Client reconnect: send CHANNEL_NONCES failed\n");
            cJSON_Delete(nonce_reply);
            free(my_pubnonces_ser);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(nonce_reply);
        free(my_pubnonces_ser);

        /* Store LSP's pubnonces */
        channel_set_remote_pubnonces(&channel,
            (const unsigned char (*)[66])lsp_nonces, lsp_nonce_count);
    }

    printf("Client %u: nonce re-exchange complete (%zu nonces)\n",
           my_index, channel.remote_nonce_count);

    /* 9. Recv MSG_RECONNECT_ACK (sent by LSP after nonce exchange).
       Fix 5: LSP may send a pending COMMITMENT_SIGNED before RECONNECT_ACK
       if a CS was in-flight when the client disconnected. Handle it inline. */
    {
        wire_msg_t msg;
        if (!wire_recv(fd, &msg)) {
            fprintf(stderr, "Client reconnect: recv failed expecting RECONNECT_ACK\n");
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
            /* LSP retransmitting a pending CS -- handle it before RECONNECT_ACK */
            client_handle_commitment_signed(fd, &channel, ctx, &msg);
            cJSON_Delete(msg.json);
            /* Now read the actual RECONNECT_ACK */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client reconnect: recv failed after CS retransmit\n");
                wire_close(fd);
                factory_free(factory); free(factory);
                return 0;
            }
        }
        if (msg.msg_type != MSG_RECONNECT_ACK) {
            fprintf(stderr, "Client reconnect: expected RECONNECT_ACK, got 0x%02x\n",
                    msg.msg_type);
            if (msg.json) cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }

        uint32_t ack_channel_id;
        uint64_t ack_local, ack_remote, ack_commit;
        if (!wire_parse_reconnect_ack(msg.json, &ack_channel_id,
                                        &ack_local, &ack_remote, &ack_commit)) {
            fprintf(stderr, "Client reconnect: failed to parse RECONNECT_ACK\n");
            cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(msg.json);

        /* Verify commitment_number matches (Gap 2B: client-side).
           Revocation-verify Phase 3: the LSP's RECONNECT_ACK is UNTRUSTED. If it
           claims a different commitment number than our own, we must NOT adopt
           the LSP's claim — keep our own persisted state (fund-safe) and raise a
           LOUD security alert. A claim AHEAD of our state is a possible forged/
           stale-state injection (trying to induce us to sign/broadcast a state we
           never reached, cf. #256); a claim BEHIND is a possible replay. Either
           way the defense is the same: trust our DB, never the peer's word. */
        if (ack_commit != channel.commitment_number) {
            fprintf(stderr, "Client %u: SECURITY: LSP RECONNECT_ACK commitment "
                    "claim (%llu) != our state (%llu) — REFUSING to adopt the "
                    "LSP's claim; keeping our own persisted state%s\n",
                    my_index, (unsigned long long)ack_commit,
                    (unsigned long long)channel.commitment_number,
                    (ack_commit > channel.commitment_number)
                        ? " [LSP claims AHEAD of us — possible forged/stale-state injection]"
                        : " [LSP claims BEHIND us — possible replay]");
            if (db) {
                uint64_t db_l, db_r, db_cn;
                if (persist_load_channel_state(db, my_index - 1,
                        &db_l, &db_r, &db_cn)) {
                    channel.local_amount = db_l;
                    channel.remote_amount = db_r;
                    channel.commitment_number = db_cn;
                }
            }
        }

        printf("Client %u: reconnected (channel=%u, commit=%llu)\n",
               my_index, ack_channel_id,
               (unsigned long long)ack_commit);
    }

    /* 10. Call channel callback */
    int cb_ret = 0;
    if (channel_cb) {
        cb_ret = channel_cb(fd, &channel, my_index, ctx, keypair,
                              factory, n_participants, user_data);
    }

    if (cb_ret == 2) {
        /* Callback handled close */
        factory_free(factory); free(factory);
        wire_close(fd);
        return 1;
    }
    if (cb_ret == 1) {
        /* Run close ceremony */
        int close_ok = client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                                  factory, n_participants,
                                                  NULL, 0, &channel);
        factory_free(factory); free(factory);
        wire_close(fd);
        return close_ok;
    }

    /* cb_ret == 0: error or disconnect */
    factory_free(factory); free(factory);
    wire_close(fd);
    return 0;
}
