#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/channel.h"
#include "superscalar/factory.h"
#include "superscalar/report.h"
#include "superscalar/persist.h"
#include "superscalar/keyfile.h"
#include "superscalar/adaptor.h"
#include "superscalar/regtest.h"
#include "superscalar/watchtower.h"
#include "superscalar/fee.h"
#include "superscalar/jit_channel.h"
#include "superscalar/musig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include "cJSON.h"

static volatile sig_atomic_t g_shutdown = 0;

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void sha256(const unsigned char *, size_t, unsigned char *);

#define MAX_ACTIONS 16

typedef enum { ACTION_SEND, ACTION_RECV } action_type_t;

typedef struct {
    action_type_t type;
    uint32_t dest_client;
    uint64_t amount_sats;
    unsigned char preimage[32];
    unsigned char payment_hash[32];
} scripted_action_t;

typedef struct {
    scripted_action_t *actions;
    size_t n_actions;
    size_t current;
} multi_payment_data_t;

/* Channel callback replicating multi_payment_client_cb from test harness */
static int standalone_channel_cb(int fd, channel_t *ch, uint32_t my_index,
                                   secp256k1_context *ctx,
                                   const secp256k1_keypair *keypair,
                                   factory_t *factory,
                                   size_t n_participants,
                                   void *user_data) {
    (void)keypair; (void)factory; (void)n_participants;
    multi_payment_data_t *data = (multi_payment_data_t *)user_data;

    for (size_t i = 0; i < data->n_actions; i++) {
        scripted_action_t *act = &data->actions[i];

        if (act->type == ACTION_SEND) {
            printf("Client %u: SEND %llu sats to client %u\n",
                   my_index, (unsigned long long)act->amount_sats, act->dest_client);

            if (!client_send_payment(fd, ch, act->amount_sats, act->payment_hash,
                                       500, act->dest_client)) {
                fprintf(stderr, "Client %u: send_payment failed\n", my_index);
                return 0;
            }

            /* Wait for COMMITMENT_SIGNED (acknowledging HTLC) */
            wire_msg_t msg;
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv failed after send\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected COMMIT_SIGNED, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Wait for FULFILL_HTLC */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                /* Update local channel state to match LSP */
                uint64_t fulfill_htlc_id;
                unsigned char fulfill_preimage[32];
                if (wire_parse_update_fulfill_htlc(msg.json, &fulfill_htlc_id,
                                                     fulfill_preimage)) {
                    channel_fulfill_htlc(ch, fulfill_htlc_id, fulfill_preimage);
                }
                printf("Client %u: payment fulfilled!\n", my_index);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected FULFILL, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Handle COMMITMENT_SIGNED for the fulfill */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit after fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            printf("Client %u: payment sent: %llu sats to client %u\n",
                   my_index, (unsigned long long)act->amount_sats, act->dest_client);

        } else { /* ACTION_RECV */
            printf("Client %u: RECV (waiting for ADD_HTLC)\n", my_index);

            /* Wait for ADD_HTLC from LSP */
            wire_msg_t msg;
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv ADD_HTLC failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                client_handle_add_htlc(ch, &msg);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected ADD_HTLC, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Handle COMMITMENT_SIGNED */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            /* Find active received HTLC and fulfill it */
            uint64_t htlc_id = 0;
            int found = 0;
            for (size_t h = 0; h < ch->n_htlcs; h++) {
                if (ch->htlcs[h].state == HTLC_STATE_ACTIVE &&
                    ch->htlcs[h].direction == HTLC_RECEIVED) {
                    htlc_id = ch->htlcs[h].id;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "Client %u: no active received HTLC to fulfill\n", my_index);
                return 0;
            }

            printf("Client %u: fulfilling HTLC %llu\n", my_index,
                   (unsigned long long)htlc_id);
            client_fulfill_payment(fd, ch, htlc_id, act->preimage);

            /* Handle COMMITMENT_SIGNED for the fulfill */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit after fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            printf("Client %u: payment received\n", my_index);
        }
    }

    return 1;
}

/* Client-side invoice store for real preimage validation (Phase 17) */
#define MAX_CLIENT_INVOICES 32

typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    uint64_t amount_msat;
    int active;
} client_invoice_t;

/* Data passed through daemon callback's user_data */
typedef struct {
    persist_t *db;
    int saved_initial;  /* 1 after first save of factory+channel */
    client_invoice_t invoices[MAX_CLIENT_INVOICES];
    size_t n_invoices;
    watchtower_t *wt;
    fee_estimator_t *fee;
    regtest_t *rt;
    jit_channel_t *jit_ch;  /* JIT channel, or NULL */
    int auto_accept_jit;    /* 1 = auto-accept JIT offers */
} daemon_cb_data_t;

/* Receive and process LSP's own revocation (bidirectional revocation).
   Call after each client_handle_commitment_signed in daemon mode.
   old_local/old_remote are the channel amounts at the OLD commitment being
   revoked (before the state-advancing add/fulfill that preceded this). */
static void client_recv_lsp_revocation(int fd, channel_t *ch, daemon_cb_data_t *cbd,
                                         secp256k1_context *ctx,
                                         uint64_t old_local, uint64_t old_remote,
                                         const htlc_t *old_htlcs, size_t old_n_htlcs) {
    wire_msg_t rev_msg;
    if (!wire_recv(fd, &rev_msg))
        return;
    if (rev_msg.msg_type != MSG_LSP_REVOKE_AND_ACK) {
        /* Not a revocation — might be an error or unexpected msg; silently skip */
        cJSON_Delete(rev_msg.json);
        return;
    }
    uint32_t rev_chan_id;
    unsigned char lsp_rev_secret[32], lsp_next_point[33];
    if (wire_parse_revoke_and_ack(rev_msg.json, &rev_chan_id,
                                    lsp_rev_secret, lsp_next_point)) {
        uint64_t old_cn = ch->commitment_number - 1;
        channel_receive_revocation(ch, old_cn, lsp_rev_secret);

        /* Register with client watchtower using the OLD commitment's amounts */
        if (cbd && cbd->wt) {
            watchtower_watch_revoked_commitment(cbd->wt, ch,
                rev_chan_id, old_cn,
                old_local, old_remote,
                old_htlcs, old_n_htlcs);
        }

        /* Store LSP's next per-commitment point */
        secp256k1_pubkey next_pcp;
        if (secp256k1_ec_pubkey_parse(ctx, &next_pcp, lsp_next_point, 33))
            channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);

        memset(lsp_rev_secret, 0, 32);
    }
    cJSON_Delete(rev_msg.json);
}

/* Daemon mode callback: select() loop handling incoming HTLCs and close */
static int daemon_channel_cb(int fd, channel_t *ch, uint32_t my_index,
                               secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               factory_t *factory,
                               size_t n_participants,
                               void *user_data) {
    daemon_cb_data_t *cbd = (daemon_cb_data_t *)user_data;

    /* Save factory + channel + basepoints on first entry (Phase 16 persistence) */
    if (cbd && cbd->db && !cbd->saved_initial) {
        if (persist_begin(cbd->db)) {
            uint32_t client_idx = my_index - 1;
            if (persist_save_factory(cbd->db, factory, ctx, 0) &&
                persist_save_channel(cbd->db, ch, 0, client_idx) &&
                persist_save_basepoints(cbd->db, client_idx, ch)) {
                persist_commit(cbd->db);
                cbd->saved_initial = 1;
                printf("Client %u: persisted factory + channel + basepoints to DB\n", my_index);
            } else {
                fprintf(stderr, "Client %u: initial persist failed, rolling back\n", my_index);
                persist_rollback(cbd->db);
            }
        } else {
            fprintf(stderr, "Client %u: persist_begin failed for initial save\n", my_index);
        }
    }

    /* Wire channel into client watchtower */
    if (cbd && cbd->wt) {
        watchtower_set_channel(cbd->wt, 0, ch);

        /* Register factory STATE nodes with watchtower (first entry only).
           After a factory_advance(), old state txids should be re-registered
           with the new (latest) signed txs as responses. For now, we register
           current state nodes so the infrastructure is wired. */
        if (!cbd->saved_initial && factory) {
            for (size_t ni = 0; ni < factory->n_nodes; ni++) {
                factory_node_t *fn = &factory->nodes[ni];
                if (fn->type == NODE_STATE && fn->is_signed &&
                    fn->signed_tx.len > 0) {
                    /* No old txid to watch yet (first epoch) — store current
                       state for future advance-based watches. */
                }
            }
        }
    }

    secp256k1_pubkey my_pubkey;
    if (!secp256k1_keypair_pub(ctx, &my_pubkey, keypair)) {
        fprintf(stderr, "Client %u: keypair_pub failed\n", my_index);
        return 0;
    }

    printf("Client %u: daemon mode active (Ctrl+C to stop)\n", my_index);

    /* Log factory lifecycle once (Tier 2) */
    if (factory && factory->active_blocks > 0) {
        printf("Client %u: factory lifecycle: active %u blocks, dying %u blocks\n",
               my_index, factory->active_blocks, factory->dying_blocks);
    }

    while (!g_shutdown) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) continue;  /* EINTR */
        if (ret == 0) {
            /* Periodic watchtower check on timeout */
            if (cbd && cbd->wt)
                watchtower_check(cbd->wt);
            continue;
        }

        wire_msg_t msg;
        if (!wire_recv(fd, &msg)) {
            fprintf(stderr, "Client %u: daemon recv failed (disconnected)\n", my_index);
            break;
        }

        switch (msg.msg_type) {
        case MSG_UPDATE_ADD_HTLC: {
            /* Save pre-add state (this is the OLD commitment being revoked) */
            uint64_t pre_add_local = ch->local_amount;
            uint64_t pre_add_remote = ch->remote_amount;
            htlc_t pre_add_htlcs[MAX_HTLCS];
            size_t pre_add_n_htlcs = ch->n_htlcs;
            if (pre_add_n_htlcs > 0)
                memcpy(pre_add_htlcs, ch->htlcs, pre_add_n_htlcs * sizeof(htlc_t));

            client_handle_add_htlc(ch, &msg);
            cJSON_Delete(msg.json);

            /* Wait for COMMITMENT_SIGNED */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
                /* Receive LSP's own revocation (bidirectional) */
                client_recv_lsp_revocation(fd, ch, cbd, ctx,
                    pre_add_local, pre_add_remote,
                    pre_add_n_htlcs > 0 ? pre_add_htlcs : NULL, pre_add_n_htlcs);
            } else {
                cJSON_Delete(msg.json);
            }

            /* Persist balance after commitment update */
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }

            /* Fulfill: find the most recent active received HTLC and look up preimage */
            {
                uint64_t htlc_id = 0;
                unsigned char htlc_hash[32];
                int found = 0;
                for (size_t h = 0; h < ch->n_htlcs; h++) {
                    if (ch->htlcs[h].state == HTLC_STATE_ACTIVE &&
                        ch->htlcs[h].direction == HTLC_RECEIVED) {
                        htlc_id = ch->htlcs[h].id;
                        memcpy(htlc_hash, ch->htlcs[h].payment_hash, 32);
                        found = 1;
                    }
                }
                if (found) {
                    /* Look up preimage from local invoice store */
                    unsigned char preimage[32];
                    int have_preimage = 0;
                    if (cbd) {
                        for (size_t inv = 0; inv < cbd->n_invoices; inv++) {
                            if (cbd->invoices[inv].active &&
                                memcmp(cbd->invoices[inv].payment_hash, htlc_hash, 32) == 0) {
                                memcpy(preimage, cbd->invoices[inv].preimage, 32);
                                cbd->invoices[inv].active = 0;
                                /* Deactivate in persistence (Phase 23) */
                                if (cbd->db)
                                    persist_deactivate_client_invoice(cbd->db, htlc_hash);
                                have_preimage = 1;
                                break;
                            }
                        }
                    }
                    if (!have_preimage) {
                        fprintf(stderr, "Client %u: no preimage for HTLC %llu, failing\n",
                                my_index, (unsigned long long)htlc_id);
                        break;
                    }
                    printf("Client %u: fulfilling HTLC %llu with real preimage\n",
                           my_index, (unsigned long long)htlc_id);

                    /* Save pre-fulfill state (old commitment being revoked) */
                    uint64_t pre_ful_local = ch->local_amount;
                    uint64_t pre_ful_remote = ch->remote_amount;
                    htlc_t pre_ful_htlcs[MAX_HTLCS];
                    size_t pre_ful_n_htlcs = ch->n_htlcs;
                    if (pre_ful_n_htlcs > 0)
                        memcpy(pre_ful_htlcs, ch->htlcs, pre_ful_n_htlcs * sizeof(htlc_t));

                    client_fulfill_payment(fd, ch, htlc_id, preimage);

                    /* Handle COMMITMENT_SIGNED for the fulfill */
                    if (wire_recv(fd, &msg) && msg.msg_type == MSG_COMMITMENT_SIGNED) {
                        client_handle_commitment_signed(fd, ch, ctx, &msg);
                        if (msg.json) cJSON_Delete(msg.json);
                        /* Receive LSP's own revocation (bidirectional) */
                        client_recv_lsp_revocation(fd, ch, cbd, ctx,
                            pre_ful_local, pre_ful_remote,
                            pre_ful_n_htlcs > 0 ? pre_ful_htlcs : NULL, pre_ful_n_htlcs);
                    } else {
                        if (msg.json) cJSON_Delete(msg.json);
                    }

                    /* Persist balance after fulfill */
                    if (cbd && cbd->db) {
                        persist_update_channel_balance(cbd->db, my_index - 1,
                            ch->local_amount, ch->remote_amount, ch->commitment_number);
                    }
                }
            }
            break;
        }

        case MSG_COMMITMENT_SIGNED:
            client_handle_commitment_signed(fd, ch, ctx, &msg);
            cJSON_Delete(msg.json);
            /* Receive LSP's own revocation (bidirectional).
               No add/fulfill preceded this, so current state = old commitment state. */
            client_recv_lsp_revocation(fd, ch, cbd, ctx,
                ch->local_amount, ch->remote_amount,
                ch->n_htlcs > 0 ? ch->htlcs : NULL, ch->n_htlcs);
            /* Persist balance after commitment update */
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }
            break;

        case MSG_UPDATE_FULFILL_HTLC: {
            /* Parse and apply the HTLC fulfill to update channel state */
            uint64_t ful_htlc_id;
            unsigned char ful_preimage[32];

            /* Save pre-fulfill state (old commitment being revoked) */
            uint64_t pre_ful2_local = ch->local_amount;
            uint64_t pre_ful2_remote = ch->remote_amount;
            htlc_t pre_ful2_htlcs[MAX_HTLCS];
            size_t pre_ful2_n_htlcs = ch->n_htlcs;
            if (pre_ful2_n_htlcs > 0)
                memcpy(pre_ful2_htlcs, ch->htlcs, pre_ful2_n_htlcs * sizeof(htlc_t));

            if (wire_parse_update_fulfill_htlc(msg.json, &ful_htlc_id, ful_preimage)) {
                channel_fulfill_htlc(ch, ful_htlc_id, ful_preimage);
                printf("Client %u: HTLC %llu fulfilled\n",
                       my_index, (unsigned long long)ful_htlc_id);
            } else {
                fprintf(stderr, "Client %u: bad FULFILL_HTLC\n", my_index);
            }
            cJSON_Delete(msg.json);
            /* Handle follow-up COMMITMENT_SIGNED */
            if (wire_recv(fd, &msg) && msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                if (msg.json) cJSON_Delete(msg.json);
                /* Receive LSP's own revocation (bidirectional) */
                client_recv_lsp_revocation(fd, ch, cbd, ctx,
                    pre_ful2_local, pre_ful2_remote,
                    pre_ful2_n_htlcs > 0 ? pre_ful2_htlcs : NULL, pre_ful2_n_htlcs);
            } else {
                if (msg.json) cJSON_Delete(msg.json);
            }
            /* Persist balance after fulfill */
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }
            break;
        }

        case MSG_CLOSE_PROPOSE:
            printf("Client %u: received CLOSE_PROPOSE in daemon mode\n", my_index);
            client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                      factory, n_participants, &msg);
            cJSON_Delete(msg.json);
            return 2;  /* close already handled */

        case MSG_CREATE_INVOICE: {
            /* LSP asks us to create an invoice (Phase 17) */
            uint64_t inv_amount_msat;
            if (!wire_parse_create_invoice(msg.json, &inv_amount_msat)) {
                fprintf(stderr, "Client %u: bad CREATE_INVOICE\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            if (cbd && cbd->n_invoices < MAX_CLIENT_INVOICES) {
                client_invoice_t *inv = &cbd->invoices[cbd->n_invoices];

                /* Generate random preimage from /dev/urandom */
                FILE *urand = fopen("/dev/urandom", "rb");
                if (urand) {
                    if (fread(inv->preimage, 1, 32, urand) != 32)
                        memset(inv->preimage, 0x42, 32); /* fallback */
                    fclose(urand);
                } else {
                    /* Deterministic fallback: derive from index */
                    memset(inv->preimage, 0x42, 32);
                    inv->preimage[0] = (unsigned char)cbd->n_invoices;
                    inv->preimage[1] = (unsigned char)my_index;
                }

                /* Compute payment_hash = SHA256(preimage) */
                sha256(inv->preimage, 32, inv->payment_hash);
                inv->amount_msat = inv_amount_msat;
                inv->active = 1;
                cbd->n_invoices++;

                /* Persist client invoice (Phase 23) */
                if (cbd->db)
                    persist_save_client_invoice(cbd->db, inv->payment_hash,
                                                inv->preimage, inv_amount_msat);

                printf("Client %u: created invoice for %llu msat\n",
                       my_index, (unsigned long long)inv_amount_msat);

                /* Send MSG_INVOICE_CREATED back to LSP */
                cJSON *reply = wire_build_invoice_created(inv->payment_hash,
                                                            inv_amount_msat);
                wire_send(fd, MSG_INVOICE_CREATED, reply);
                cJSON_Delete(reply);

                /* Also register with LSP so it knows to route to us */
                uint32_t client_idx = my_index - 1;
                cJSON *reg = wire_build_register_invoice(inv->payment_hash,
                                                           inv_amount_msat,
                                                           (size_t)client_idx);
                wire_send(fd, MSG_REGISTER_INVOICE, reg);
                cJSON_Delete(reg);
            }
            break;
        }

        case MSG_PTLC_PRESIG: {
            /* LSP sends adaptor pre-signature for PTLC key turnover */
            unsigned char presig[64], turnover_msg[32];
            int nonce_parity;
            if (!wire_parse_ptlc_presig(msg.json, presig, &nonce_parity, turnover_msg)) {
                fprintf(stderr, "Client %u: bad PTLC_PRESIG\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            /* Adapt with our secret key */
            unsigned char my_seckey[32];
            if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
                fprintf(stderr, "Client %u: keypair_sec failed\n", my_index);
                break;
            }
            unsigned char adapted_sig[64];
            if (!adaptor_adapt(ctx, adapted_sig, presig, my_seckey, nonce_parity)) {
                fprintf(stderr, "Client %u: adaptor_adapt failed\n", my_index);
                memset(my_seckey, 0, 32);
                break;
            }
            memset(my_seckey, 0, 32);

            /* Send adapted signature back */
            cJSON *reply = wire_build_ptlc_adapted_sig(adapted_sig);
            wire_send(fd, MSG_PTLC_ADAPTED_SIG, reply);
            cJSON_Delete(reply);

            /* Receive PTLC_COMPLETE acknowledgement */
            wire_msg_t complete_msg;
            if (wire_recv(fd, &complete_msg)) {
                if (complete_msg.msg_type == MSG_PTLC_COMPLETE)
                    printf("Client %u: PTLC departure complete\n", my_index);
                cJSON_Delete(complete_msg.json);
            }
            break;
        }

        case MSG_JIT_OFFER: {
            /* LSP offers a JIT channel */
            size_t jit_cidx;
            uint64_t jit_amount;
            char jit_reason[64];
            secp256k1_pubkey jit_lsp_pk;
            if (!wire_parse_jit_offer(msg.json, ctx, &jit_cidx, &jit_amount,
                                        jit_reason, sizeof(jit_reason), &jit_lsp_pk)) {
                fprintf(stderr, "Client %u: bad JIT_OFFER\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            printf("Client %u: JIT offer received (%llu sats, reason: %s)\n",
                   my_index, (unsigned long long)jit_amount, jit_reason);

            /* Gate JIT acceptance behind flag */
            if (!cbd->auto_accept_jit) {
                printf("Client %u: rejecting JIT offer "
                       "(use --auto-accept-jit to enable)\n", my_index);
                break;
            }

            /* Auto-accept */
            secp256k1_pubkey my_pk;
            if (!secp256k1_keypair_pub(ctx, &my_pk, keypair)) {
                fprintf(stderr, "Client %u: keypair_pub failed\n", my_index);
                break;
            }
            cJSON *accept = wire_build_jit_accept(jit_cidx, ctx, &my_pk);
            wire_send(fd, MSG_JIT_ACCEPT, accept);
            cJSON_Delete(accept);

            /* Wait for basepoints exchange */
            wire_msg_t bp_msg;
            if (!wire_recv(fd, &bp_msg) ||
                bp_msg.msg_type != MSG_CHANNEL_BASEPOINTS) {
                if (bp_msg.json) cJSON_Delete(bp_msg.json);
                fprintf(stderr, "Client %u: expected CHANNEL_BASEPOINTS for JIT\n", my_index);
                break;
            }

            /* Allocate JIT channel if not yet present */
            if (!cbd->jit_ch) {
                cbd->jit_ch = calloc(1, sizeof(jit_channel_t));
                if (!cbd->jit_ch) {
                    cJSON_Delete(bp_msg.json);
                    break;
                }
            }
            jit_channel_t *jit = cbd->jit_ch;

            /* Parse LSP's basepoints */
            uint32_t bp_ch_id;
            secp256k1_pubkey pay_bp, delay_bp, revoc_bp, htlc_bp, first_pcp, second_pcp;
            if (!wire_parse_channel_basepoints(bp_msg.json, &bp_ch_id, ctx,
                                                 &pay_bp, &delay_bp, &revoc_bp, &htlc_bp,
                                                 &first_pcp, &second_pcp)) {
                cJSON_Delete(bp_msg.json);
                break;
            }
            cJSON_Delete(bp_msg.json);

            jit->jit_channel_id = bp_ch_id;
            jit->client_idx = jit_cidx;

            /* For the client, "local" = client, "remote" = LSP.
               We'll init the channel_t when we get JIT_READY with funding info.
               For now, store the LSP's basepoints temporarily. */

            /* Send client's basepoints back */
            {
                /* We need a temporary channel_t context to generate basepoints.
                   Use a stack-local secp ctx. */
                channel_t *jch = &jit->channel;
                jch->ctx = ctx;

                /* Generate client basepoints */
                channel_generate_random_basepoints(jch);

                secp256k1_pubkey c_first_pcp, c_second_pcp;
                /* Generate per-commitment secrets */
                channel_generate_local_pcs(jch, 0);
                channel_generate_local_pcs(jch, 1);
                channel_get_per_commitment_point(jch, 0, &c_first_pcp);
                channel_get_per_commitment_point(jch, 1, &c_second_pcp);

                cJSON *client_bp = wire_build_channel_basepoints(
                    bp_ch_id, ctx,
                    &jch->local_payment_basepoint,
                    &jch->local_delayed_payment_basepoint,
                    &jch->local_revocation_basepoint,
                    &jch->local_htlc_basepoint,
                    &c_first_pcp, &c_second_pcp);
                wire_send(fd, MSG_CHANNEL_BASEPOINTS, client_bp);
                cJSON_Delete(client_bp);

                /* Store LSP's basepoints as remote */
                channel_set_remote_basepoints(jch, &pay_bp, &delay_bp, &revoc_bp);
                channel_set_remote_htlc_basepoint(jch, &htlc_bp);
                channel_set_remote_pcp(jch, 0, &first_pcp);
                channel_set_remote_pcp(jch, 1, &second_pcp);
            }

            /* Exchange nonces */
            {
                wire_msg_t nm;
                if (!wire_recv(fd, &nm) || nm.msg_type != MSG_CHANNEL_NONCES) {
                    if (nm.json) cJSON_Delete(nm.json);
                    break;
                }
                uint32_t nm_ch_id;
                unsigned char lsp_nonces[MUSIG_NONCE_POOL_MAX][66];
                size_t lsp_nc;
                wire_parse_channel_nonces(nm.json, &nm_ch_id, lsp_nonces,
                                            MUSIG_NONCE_POOL_MAX, &lsp_nc);
                cJSON_Delete(nm.json);

                /* Init nonce pool and send client's nonces */
                channel_init_nonce_pool(&jit->channel, MUSIG_NONCE_POOL_MAX);
                channel_set_remote_pubnonces(&jit->channel,
                    (const unsigned char (*)[66])lsp_nonces, lsp_nc);

                size_t nc = jit->channel.local_nonce_pool.count;
                unsigned char (*pn_ser)[66] = calloc(nc, 66);
                if (pn_ser) {
                    for (size_t i = 0; i < nc; i++)
                        musig_pubnonce_serialize(ctx, pn_ser[i],
                            &jit->channel.local_nonce_pool.nonces[i].pubnonce);
                    cJSON *cnm = wire_build_channel_nonces(bp_ch_id,
                        (const unsigned char (*)[66])pn_ser, nc);
                    wire_send(fd, MSG_CHANNEL_NONCES, cnm);
                    cJSON_Delete(cnm);
                    free(pn_ser);
                }
            }

            /* Wait for JIT_READY */
            {
                wire_msg_t ready_msg;
                if (!wire_recv(fd, &ready_msg) ||
                    ready_msg.msg_type != MSG_JIT_READY) {
                    if (ready_msg.json) cJSON_Delete(ready_msg.json);
                    fprintf(stderr, "Client %u: expected JIT_READY\n", my_index);
                    break;
                }

                uint32_t jit_ch_id;
                char fund_txid_hex[65];
                uint32_t fund_vout;
                uint64_t fund_amount, local_amt, remote_amt;
                if (!wire_parse_jit_ready(ready_msg.json, &jit_ch_id,
                                            fund_txid_hex, sizeof(fund_txid_hex),
                                            &fund_vout, &fund_amount,
                                            &local_amt, &remote_amt)) {
                    cJSON_Delete(ready_msg.json);
                    break;
                }
                cJSON_Delete(ready_msg.json);

                /* Finalize JIT channel init — for client, swap local/remote
                   since LSP's local is client's remote */
                jit->jit_channel_id = jit_ch_id;
                memcpy(jit->funding_txid_hex, fund_txid_hex, 64);
                jit->funding_txid_hex[64] = '\0';
                jit->funding_amount = fund_amount;
                jit->funding_vout = fund_vout;
                jit->funding_confirmed = 1;

                /* Set balances: from client perspective, local_amt is LSP's local
                   (= our remote), remote_amt is LSP's remote (= our local) */
                jit->channel.local_amount = remote_amt;
                jit->channel.remote_amount = local_amt;
                jit->channel.funding_amount = fund_amount;
                jit->channel.funder_is_local = 0;

                jit->state = JIT_STATE_OPEN;

                /* Register JIT channel with client watchtower */
                if (cbd && cbd->wt)
                    watchtower_set_channel(cbd->wt, 0, &jit->channel);

                /* Persist JIT channel */
                if (cbd && cbd->db) {
                    if (persist_begin(cbd->db)) {
                        if (persist_save_jit_channel(cbd->db, jit) &&
                            persist_save_basepoints(cbd->db, jit->jit_channel_id,
                                                      &jit->channel)) {
                            persist_commit(cbd->db);
                        } else {
                            fprintf(stderr, "Client %u: JIT persist failed, rolling back\n", my_index);
                            persist_rollback(cbd->db);
                        }
                    } else {
                        fprintf(stderr, "Client %u: persist_begin failed for JIT channel\n", my_index);
                    }
                }

                printf("Client %u: JIT channel %08x open (%llu sats)\n",
                       my_index, jit_ch_id, (unsigned long long)fund_amount);
            }
            break;
        }

        case MSG_JIT_MIGRATE: {
            /* LSP requests migration of JIT channel to factory */
            uint32_t mig_jit_id, mig_factory_id;
            uint64_t mig_local, mig_remote;
            if (!wire_parse_jit_migrate(msg.json, &mig_jit_id, &mig_factory_id,
                                          &mig_local, &mig_remote)) {
                fprintf(stderr, "Client %u: bad JIT_MIGRATE\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            printf("Client %u: JIT channel %08x migrating to factory %u\n",
                   my_index, mig_jit_id, mig_factory_id);

            if (cbd->jit_ch && cbd->jit_ch->jit_channel_id == mig_jit_id) {
                cbd->jit_ch->state = JIT_STATE_CLOSED;
                /* Remove watchtower entries for JIT channel */
                if (cbd->wt)
                    watchtower_remove_channel(cbd->wt, 0);
                /* Remove from persistence */
                if (cbd->db)
                    persist_delete_jit_channel(cbd->db, mig_jit_id);
                printf("Client %u: JIT channel closed (migrated)\n", my_index);
            }
            break;
        }

        case MSG_FACTORY_PROPOSE: {
            /* LSP initiates factory rotation — create new factory */
            printf("Client %u: received FACTORY_PROPOSE (rotation)\n", my_index);

            /* Save pubkeys from current factory */
            secp256k1_pubkey saved_pubkeys[FACTORY_MAX_SIGNERS];
            for (size_t pi = 0; pi < n_participants; pi++)
                saved_pubkeys[pi] = factory->pubkeys[pi];

            /* Free old factory */
            factory_free(factory);

            /* Run rotation ceremony */
            if (!client_do_factory_rotation(fd, ctx, keypair, my_index,
                                             n_participants, saved_pubkeys,
                                             factory, ch, &msg)) {
                fprintf(stderr, "Client %u: factory rotation failed\n", my_index);
                cJSON_Delete(msg.json);
                return 0;
            }
            cJSON_Delete(msg.json);

            /* Re-register watchtower channel pointer after rotation */
            if (cbd && cbd->wt)
                watchtower_set_channel(cbd->wt, 0, ch);

            /* Persist new factory + channel if DB available */
            if (cbd && cbd->db) {
                if (persist_begin(cbd->db)) {
                    if (persist_save_factory(cbd->db, factory, ctx, 0) &&
                        persist_save_channel(cbd->db, ch, 0, my_index - 1)) {
                        persist_commit(cbd->db);
                        printf("Client %u: persisted rotated factory + channel\n", my_index);
                    } else {
                        fprintf(stderr, "Client %u: rotation persist failed, rolling back\n", my_index);
                        persist_rollback(cbd->db);
                    }
                } else {
                    fprintf(stderr, "Client %u: persist_begin failed for rotation\n", my_index);
                }
            }
            break;
        }

        case MSG_EPOCH_RESET_PROPOSE:
            /* LSP proposes epoch reset — reset local counter + rebuild.
               In distributed mode, client would generate partial sigs and send
               MSG_EPOCH_RESET_PSIG. For PoC, just reset locally. */
            printf("Client %u: received EPOCH_RESET_PROPOSE\n", my_index);
            dw_counter_reset(&factory->counter);
            printf("Client %u: epoch reset to 0\n", my_index);
            cJSON_Delete(msg.json);
            break;

        case MSG_EPOCH_RESET_DONE:
            /* LSP confirms epoch reset complete with new signed txs. */
            printf("Client %u: epoch reset confirmed by LSP\n", my_index);
            cJSON_Delete(msg.json);
            break;

        case MSG_LEAF_ADVANCE_PROPOSE: {
            /* LSP proposes leaf advance — do split-round signing.
               1. Parse leaf_side + LSP's pubnonce
               2. Advance DW + rebuild locally
               3. Init session, set LSP nonce, generate client nonce
               4. Finalize nonces (both known), create partial sig
               5. Send MSG_LEAF_ADVANCE_PSIG with pubnonce + partial sig */
            int leaf_side;
            unsigned char lsp_pubnonce_ser[66];
            if (!wire_parse_leaf_advance_propose(msg.json, &leaf_side,
                                                    lsp_pubnonce_ser)) {
                fprintf(stderr, "Client %u: bad LEAF_ADVANCE_PROPOSE\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);
            printf("Client %u: LEAF_ADVANCE_PROPOSE for leaf %d\n",
                   my_index, leaf_side);

            /* Advance DW + rebuild unsigned tx locally */
            int arc = factory_advance_leaf_unsigned(factory, leaf_side);
            if (arc <= 0) {
                fprintf(stderr, "Client %u: leaf advance failed (rc=%d)\n",
                        my_index, arc);
                break;
            }

            size_t node_idx = factory->leaf_node_indices[leaf_side];

            /* Init signing session for the leaf node */
            if (!factory_session_init_node(factory, node_idx)) {
                fprintf(stderr, "Client %u: session init failed\n", my_index);
                break;
            }

            /* Set LSP's pubnonce (slot for participant 0) */
            int lsp_slot = factory_find_signer_slot(factory, node_idx, 0);
            if (lsp_slot < 0) break;

            secp256k1_musig_pubnonce lsp_pubnonce;
            if (!musig_pubnonce_parse(ctx, &lsp_pubnonce, lsp_pubnonce_ser))
                break;

            if (!factory_session_set_nonce(factory, node_idx,
                                             (size_t)lsp_slot, &lsp_pubnonce))
                break;

            /* Generate client's nonce */
            int my_slot = factory_find_signer_slot(factory, node_idx, my_index);
            if (my_slot < 0) break;

            unsigned char my_seckey[32];
            if (!secp256k1_keypair_sec(ctx, my_seckey, keypair))
                break;
            secp256k1_pubkey my_pk;
            if (!secp256k1_keypair_pub(ctx, &my_pk, keypair)) {
                memset(my_seckey, 0, 32);
                break;
            }

            secp256k1_musig_secnonce my_secnonce;
            secp256k1_musig_pubnonce my_pubnonce;
            if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                                        my_seckey, &my_pk,
                                        &factory->nodes[node_idx].keyagg.cache)) {
                memset(my_seckey, 0, 32);
                break;
            }

            if (!factory_session_set_nonce(factory, node_idx,
                                             (size_t)my_slot, &my_pubnonce)) {
                memset(my_seckey, 0, 32);
                break;
            }

            /* Both nonces set — finalize (compute sighash + aggregate nonces) */
            if (!factory_session_finalize_node(factory, node_idx)) {
                memset(my_seckey, 0, 32);
                break;
            }

            /* Create client's partial sig */
            secp256k1_musig_partial_sig my_psig;
            secp256k1_keypair my_kp;
            if (!secp256k1_keypair_create(ctx, &my_kp, my_seckey)) {
                memset(my_seckey, 0, 32);
                break;
            }
            memset(my_seckey, 0, 32);

            if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, &my_kp,
                                            &factory->nodes[node_idx].signing_session))
                break;

            /* Send MSG_LEAF_ADVANCE_PSIG: pubnonce + partial sig */
            unsigned char my_pubnonce_ser[66], my_psig_ser[32];
            musig_pubnonce_serialize(ctx, my_pubnonce_ser, &my_pubnonce);
            musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);

            cJSON *psig_json = wire_build_leaf_advance_psig(
                my_pubnonce_ser, my_psig_ser);
            wire_send(fd, MSG_LEAF_ADVANCE_PSIG, psig_json);
            cJSON_Delete(psig_json);

            printf("Client %u: sent LEAF_ADVANCE_PSIG for leaf %d (node %zu)\n",
                   my_index, leaf_side, node_idx);

            /* Persist per-leaf DW state */
            if (cbd && cbd->db) {
                uint32_t leaf_states[8];
                for (int li = 0; li < factory->n_leaf_nodes; li++)
                    leaf_states[li] = factory->leaf_layers[li].current_state;
                uint32_t layer_states[DW_MAX_LAYERS];
                for (uint32_t li = 0; li < factory->counter.n_layers; li++)
                    layer_states[li] = factory->counter.layers[li].config.max_states;
                persist_save_dw_counter_with_leaves(
                    cbd->db, 0, factory->counter.current_epoch,
                    factory->counter.n_layers, layer_states,
                    factory->per_leaf_enabled, leaf_states,
                    factory->n_leaf_nodes);
            }
            break;
        }

        case MSG_LEAF_ADVANCE_DONE: {
            /* LSP confirms leaf advance — the signed tx is now finalized.
               Client's factory already has the correct unsigned tx from PROPOSE. */
            int leaf_side;
            if (wire_parse_leaf_advance_done(msg.json, &leaf_side))
                printf("Client %u: leaf %d advance confirmed by LSP\n",
                       my_index, leaf_side);
            cJSON_Delete(msg.json);
            break;
        }

        default:
            fprintf(stderr, "Client %u: daemon got unexpected msg 0x%02x\n",
                    my_index, msg.msg_type);
            cJSON_Delete(msg.json);
            break;
        }
    }

    return 1;  /* normal return — caller handles close */
}

/* Wire message log callback (Phase 22) */
static void client_wire_log_cb(int dir, uint8_t type, const cJSON *json,
                                 const char *peer_label, void *ud) {
    persist_log_wire_message((persist_t *)ud, dir, type, peer_label, json);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --seckey HEX --port PORT [--host HOST] [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --seckey HEX                      Client secret key (32-byte hex, required)\n"
        "  --port PORT                       LSP port (default 9735)\n"
        "  --host HOST                       LSP host (default 127.0.0.1)\n"
        "  --send DEST:AMOUNT:PREIMAGE_HEX   Send payment (can repeat)\n"
        "  --recv PREIMAGE_HEX               Receive payment (can repeat)\n"
        "  --channels                        Expect channel phase (for when LSP uses --payments)\n"
        "  --daemon                          Run as long-lived daemon (auto-fulfill HTLCs)\n"
        "  --fee-rate N                      Fee rate in sat/kvB (default 1000 = 1 sat/vB)\n"
        "  --report PATH                     Write diagnostic JSON report to PATH\n"
        "  --db PATH                         SQLite database for persistence (default: none)\n"
        "  --network MODE                    Network: regtest, signet, testnet, mainnet (default: regtest)\n"
        "  --regtest                         Shorthand for --network regtest\n"
        "  --keyfile PATH                    Load/save secret key from encrypted file\n"
        "  --passphrase PASS                 Passphrase for keyfile (default: empty)\n"
        "  --cli-path PATH                   Path to bitcoin-cli binary (default: bitcoin-cli)\n"
        "  --rpcuser USER                    Bitcoin RPC username (default: rpcuser)\n"
        "  --rpcpassword PASS                Bitcoin RPC password (default: rpcpass)\n"
        "  --datadir PATH                    Bitcoin datadir (default: bitcoind default)\n"
        "  --rpcport PORT                    Bitcoin RPC port (default: network default)\n"
        "  --auto-accept-jit                 Auto-accept JIT channel offers (default: off)\n"
        "  --help                            Show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    /* Ignore SIGPIPE — write() to dead LSP socket returns EPIPE instead of killing us */
    signal(SIGPIPE, SIG_IGN);

    const char *seckey_hex = NULL;
    int port = 9735;
    const char *host = "127.0.0.1";
    int expect_channels = 0;
    int daemon_mode = 0;
    const char *report_path = NULL;
    const char *db_path = NULL;
    const char *keyfile_path = NULL;
    const char *passphrase = "";
    const char *network = "regtest";
    const char *cli_path = "bitcoin-cli";
    const char *rpcuser = "rpcuser";
    const char *rpcpassword = "rpcpass";
    const char *datadir = NULL;
    int rpcport = 0;
    int fee_rate = 1000;
    int auto_accept_jit = 0;

    scripted_action_t actions[MAX_ACTIONS];
    size_t n_actions = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seckey") == 0 && i + 1 < argc)
            seckey_hex = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "--channels") == 0)
            expect_channels = 1;
        else if (strcmp(argv[i], "--daemon") == 0)
            daemon_mode = 1;
        else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc)
            report_path = argv[++i];
        else if (strcmp(argv[i], "--fee-rate") == 0 && i + 1 < argc)
            fee_rate = atoi(argv[++i]);
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_path = argv[++i];
        else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            network = argv[++i];
        else if (strcmp(argv[i], "--regtest") == 0)
            network = "regtest";
        else if (strcmp(argv[i], "--cli-path") == 0 && i + 1 < argc)
            cli_path = argv[++i];
        else if (strcmp(argv[i], "--rpcuser") == 0 && i + 1 < argc)
            rpcuser = argv[++i];
        else if (strcmp(argv[i], "--rpcpassword") == 0 && i + 1 < argc)
            rpcpassword = argv[++i];
        else if (strcmp(argv[i], "--datadir") == 0 && i + 1 < argc)
            datadir = argv[++i];
        else if (strcmp(argv[i], "--rpcport") == 0 && i + 1 < argc)
            rpcport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--keyfile") == 0 && i + 1 < argc)
            keyfile_path = argv[++i];
        else if (strcmp(argv[i], "--passphrase") == 0 && i + 1 < argc)
            passphrase = argv[++i];
        else if (strcmp(argv[i], "--send") == 0 && i + 1 < argc) {
            if (n_actions >= MAX_ACTIONS) {
                fprintf(stderr, "Too many actions (max %d)\n", MAX_ACTIONS);
                return 1;
            }
            /* Parse DEST:AMOUNT:PREIMAGE_HEX */
            const char *arg = argv[++i];
            char *copy = strdup(arg);
            char *p1 = strchr(copy, ':');
            if (!p1) { fprintf(stderr, "Bad --send format: %s\n", arg); free(copy); return 1; }
            *p1++ = '\0';
            char *p2 = strchr(p1, ':');
            if (!p2) { fprintf(stderr, "Bad --send format: %s\n", arg); free(copy); return 1; }
            *p2++ = '\0';

            scripted_action_t *act = &actions[n_actions++];
            act->type = ACTION_SEND;
            act->dest_client = (uint32_t)atoi(copy);
            act->amount_sats = (uint64_t)strtoull(p1, NULL, 10);
            if (hex_decode(p2, act->preimage, 32) != 32) {
                fprintf(stderr, "Bad preimage hex in --send: %s\n", p2);
                free(copy);
                return 1;
            }
            sha256(act->preimage, 32, act->payment_hash);
            free(copy);

        } else if (strcmp(argv[i], "--recv") == 0 && i + 1 < argc) {
            if (n_actions >= MAX_ACTIONS) {
                fprintf(stderr, "Too many actions (max %d)\n", MAX_ACTIONS);
                return 1;
            }
            const char *arg = argv[++i];
            scripted_action_t *act = &actions[n_actions++];
            act->type = ACTION_RECV;
            act->dest_client = 0;
            act->amount_sats = 0;
            if (hex_decode(arg, act->preimage, 32) != 32) {
                fprintf(stderr, "Bad preimage hex in --recv: %s\n", arg);
                return 1;
            }
            sha256(act->preimage, 32, act->payment_hash);

        } else if (strcmp(argv[i], "--auto-accept-jit") == 0) {
            auto_accept_jit = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    unsigned char seckey[32];
    int key_loaded = 0;

    if (seckey_hex) {
        if (hex_decode(seckey_hex, seckey, 32) != 32) {
            fprintf(stderr, "Invalid seckey hex\n");
            return 1;
        }
        key_loaded = 1;
    } else if (keyfile_path) {
        secp256k1_context *tmp_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (keyfile_load(keyfile_path, seckey, passphrase)) {
            printf("Client: loaded key from %s\n", keyfile_path);
            key_loaded = 1;
        } else {
            printf("Client: generating new key and saving to %s\n", keyfile_path);
            if (keyfile_generate(keyfile_path, seckey, passphrase, tmp_ctx)) {
                key_loaded = 1;
            } else {
                fprintf(stderr, "Error: failed to generate keyfile\n");
                secp256k1_context_destroy(tmp_ctx);
                return 1;
            }
        }
        secp256k1_context_destroy(tmp_ctx);
    }

    if (!key_loaded) {
        usage(argv[0]);
        return 1;
    }

    /* Initialize diagnostic report */
    report_t rpt;
    if (!report_init(&rpt, report_path)) {
        fprintf(stderr, "Error: cannot open report file: %s\n", report_path);
        return 1;
    }
    report_add_string(&rpt, "role", "client");
    report_add_string(&rpt, "host", host);
    report_add_uint(&rpt, "port", (uint64_t)port);
    report_add_uint(&rpt, "n_actions", n_actions);
    report_add_bool(&rpt, "expect_channels", expect_channels);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) {
        fprintf(stderr, "Invalid secret key\n");
        memset(seckey, 0, 32);
        report_close(&rpt);
        return 1;
    }

    /* Report: client pubkey */
    {
        secp256k1_pubkey pk;
        int ok_pk = secp256k1_keypair_pub(ctx, &pk, &kp);
        if (ok_pk)
            report_add_pubkey(&rpt, "pubkey", ctx, &pk);
    }
    memset(seckey, 0, 32);

    /* Report: scripted actions */
    if (n_actions > 0) {
        report_begin_array(&rpt, "actions");
        for (size_t i = 0; i < n_actions; i++) {
            report_begin_section(&rpt, NULL);
            report_add_string(&rpt, "type",
                              actions[i].type == ACTION_SEND ? "send" : "recv");
            if (actions[i].type == ACTION_SEND) {
                report_add_uint(&rpt, "dest_client", actions[i].dest_client);
                report_add_uint(&rpt, "amount_sats", actions[i].amount_sats);
            }
            report_add_hex(&rpt, "payment_hash", actions[i].payment_hash, 32);
            report_end_section(&rpt);
        }
        report_end_array(&rpt);
    }
    report_flush(&rpt);

    /* Initialize persistence (optional) */
    persist_t db;
    int use_db = 0;
    if (db_path) {
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "Error: cannot open database: %s\n", db_path);
            secp256k1_context_destroy(ctx);
            report_close(&rpt);
            return 1;
        }
        use_db = 1;
        printf("Client: persistence enabled (%s)\n", db_path);

        /* Wire message logging (Phase 22) */
        wire_set_log_callback(client_wire_log_cb, &db);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Initialize regtest + watchtower for client-side breach detection */
    regtest_t rt;
    int rt_ok = regtest_init_full(&rt, network, cli_path, rpcuser, rpcpassword,
                                  datadir, rpcport);
    if (!rt_ok)
        fprintf(stderr, "Client: regtest init failed (watchtower disabled)\n");

    static watchtower_t client_wt;
    fee_estimator_t client_fee;
    fee_init(&client_fee, fee_rate);
    watchtower_init(&client_wt, 1, rt_ok ? &rt : NULL, &client_fee,
                      use_db ? &db : NULL);

    int ok;
    if (daemon_mode) {
        daemon_cb_data_t cbd;
        memset(&cbd, 0, sizeof(cbd));
        cbd.db = use_db ? &db : NULL;
        cbd.wt = &client_wt;
        cbd.fee = &client_fee;
        cbd.rt = rt_ok ? &rt : NULL;
        cbd.auto_accept_jit = auto_accept_jit;

        /* Load persisted client invoices (Phase 23) */
        if (use_db) {
            unsigned char ci_hashes[MAX_CLIENT_INVOICES][32];
            unsigned char ci_preimages[MAX_CLIENT_INVOICES][32];
            uint64_t ci_amounts[MAX_CLIENT_INVOICES];
            size_t n_ci = persist_load_client_invoices(&db,
                ci_hashes, ci_preimages, ci_amounts, MAX_CLIENT_INVOICES);
            for (size_t i = 0; i < n_ci && cbd.n_invoices < MAX_CLIENT_INVOICES; i++) {
                client_invoice_t *inv = &cbd.invoices[cbd.n_invoices++];
                memcpy(inv->payment_hash, ci_hashes[i], 32);
                memcpy(inv->preimage, ci_preimages[i], 32);
                inv->amount_msat = ci_amounts[i];
                inv->active = 1;
            }
            if (n_ci > 0)
                printf("Client: loaded %zu invoices from DB\n", n_ci);

            /* Load active JIT channel from DB */
            {
                jit_channel_t jit_loaded[JIT_MAX_CHANNELS];
                size_t jit_count = 0;
                persist_load_jit_channels(&db, jit_loaded, JIT_MAX_CHANNELS,
                                            &jit_count);
                for (size_t ji = 0; ji < jit_count; ji++) {
                    if (jit_loaded[ji].state == JIT_STATE_OPEN) {
                        cbd.jit_ch = calloc(1, sizeof(jit_channel_t));
                        if (cbd.jit_ch) {
                            memcpy(cbd.jit_ch, &jit_loaded[ji],
                                   sizeof(jit_channel_t));
                            cbd.jit_ch->channel.ctx = ctx;
                            /* Reload basepoints from DB */
                            unsigned char ls[4][32], rb[4][33];
                            if (persist_load_basepoints(&db,
                                    jit_loaded[ji].jit_channel_id, ls, rb)) {
                                memcpy(cbd.jit_ch->channel.local_payment_basepoint_secret, ls[0], 32);
                                memcpy(cbd.jit_ch->channel.local_delayed_payment_basepoint_secret, ls[1], 32);
                                memcpy(cbd.jit_ch->channel.local_revocation_basepoint_secret, ls[2], 32);
                                memcpy(cbd.jit_ch->channel.local_htlc_basepoint_secret, ls[3], 32);
                                int bp_ok = 1;
                                bp_ok &= secp256k1_ec_pubkey_create(ctx, &cbd.jit_ch->channel.local_payment_basepoint, ls[0]);
                                bp_ok &= secp256k1_ec_pubkey_create(ctx, &cbd.jit_ch->channel.local_delayed_payment_basepoint, ls[1]);
                                bp_ok &= secp256k1_ec_pubkey_create(ctx, &cbd.jit_ch->channel.local_revocation_basepoint, ls[2]);
                                bp_ok &= secp256k1_ec_pubkey_create(ctx, &cbd.jit_ch->channel.local_htlc_basepoint, ls[3]);
                                bp_ok &= secp256k1_ec_pubkey_parse(ctx, &cbd.jit_ch->channel.remote_payment_basepoint, rb[0], 33);
                                bp_ok &= secp256k1_ec_pubkey_parse(ctx, &cbd.jit_ch->channel.remote_delayed_payment_basepoint, rb[1], 33);
                                bp_ok &= secp256k1_ec_pubkey_parse(ctx, &cbd.jit_ch->channel.remote_revocation_basepoint, rb[2], 33);
                                bp_ok &= secp256k1_ec_pubkey_parse(ctx, &cbd.jit_ch->channel.remote_htlc_basepoint, rb[3], 33);
                                if (!bp_ok) {
                                    fprintf(stderr, "Client: failed to restore JIT basepoints\n");
                                    free(cbd.jit_ch);
                                    cbd.jit_ch = NULL;
                                }
                            }
                            if (cbd.jit_ch) {
                                /* Register with watchtower */
                                if (cbd.wt)
                                    watchtower_set_channel(cbd.wt, 0,
                                        &cbd.jit_ch->channel);
                                printf("Client: loaded JIT channel %08x from DB\n",
                                       cbd.jit_ch->jit_channel_id);
                            }
                        }
                        break;  /* Only one JIT per client */
                    }
                }
            }
        }

        int first_run = 1;

        while (!g_shutdown) {
            if (first_run || !use_db) {
                ok = client_run_with_channels(ctx, &kp, host, port,
                                                daemon_channel_cb, &cbd);
                /* Only switch to reconnect mode once factory is persisted */
                if (ok || cbd.saved_initial)
                    first_run = 0;
            } else {
                printf("Client: reconnecting from persisted state...\n");
                cbd.saved_initial = 1;  /* already saved on first run */
                ok = client_run_reconnect(ctx, &kp, host, port, &db,
                                            daemon_channel_cb, &cbd);
            }
            if (g_shutdown) break;
            if (!ok) {
                fprintf(stderr, "Client: disconnected, retrying in 5s...\n");
                /* Run watchtower check between reconnect attempts so we can
                   detect on-chain breaches even when the LSP is unreachable. */
                if (cbd.wt)
                    watchtower_check(cbd.wt);
                sleep(5);
            } else {
                break;  /* clean exit */
            }
        }
    } else if (n_actions > 0 || expect_channels) {
        multi_payment_data_t data = { actions, n_actions, 0 };
        ok = client_run_with_channels(ctx, &kp, host, port, standalone_channel_cb, &data);
    } else {
        ok = client_run_ceremony(ctx, &kp, host, port);
    }

    report_add_string(&rpt, "result", ok ? "success" : "failure");
    report_close(&rpt);

    if (use_db)
        persist_close(&db);
    secp256k1_context_destroy(ctx);
    return ok ? 0 : 1;
}
