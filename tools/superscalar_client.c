#include "superscalar/version.h"
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
#include "superscalar/tor.h"
#include "superscalar/bip39.h"
#include "superscalar/hd_key.h"
#include "superscalar/bip158_backend.h"
#include "superscalar/wallet_source_hd.h"
#include "superscalar/splice.h"
#include "superscalar/lsp_wellknown.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include "cJSON.h"

static volatile sig_atomic_t g_shutdown = 0;

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

/* BIP 158 light client backend (global so it outlives main's stack frame) */
static bip158_backend_t g_bip158_client;

/* HD wallet — used when --light-client is active without a bitcoind wallet */
static wallet_source_hd_t *g_hd_wallet_client = NULL;

static int attach_hd_wallet_client(watchtower_t *wt, persist_t *db_ptr,
                                     secp256k1_context *ctx, const char *network,
                                     const char *hd_mnemonic,
                                     const char *hd_passphrase,
                                     uint32_t lookahead)
{
    if (!wt || !ctx) return 0;

    unsigned char seed[64];
    size_t seed_len = 64;

    /* 1. If seed exists in DB AND no hd_mnemonic override: load and use */
    if (!hd_mnemonic && db_ptr &&
        persist_load_hd_seed(db_ptr, seed, &seed_len, sizeof(seed)) && seed_len >= 16) {
        printf("Client: HD wallet: loaded existing seed (%zu bytes)\n", seed_len);
    } else if (hd_mnemonic) {
        /* 2. Derive seed from provided mnemonic */
        if (!bip39_mnemonic_to_seed(hd_mnemonic, hd_passphrase ? hd_passphrase : "", seed)) {
            fprintf(stderr, "Client: HD wallet: bip39_mnemonic_to_seed failed\n");
            memset(seed, 0, sizeof(seed));
            return 0;
        }
        seed_len = 64;
        printf("Client: HD wallet: derived seed from provided mnemonic\n");
    } else {
        /* 3. First run: generate a BIP 39 24-word phrase */
        char mnemonic_buf[300];
        if (!bip39_generate(24, mnemonic_buf, sizeof(mnemonic_buf))) {
            fprintf(stderr, "Client: HD wallet: bip39_generate failed\n");
            return 0;
        }
        printf("=== WRITE THIS DOWN: YOUR 24-WORD RECOVERY PHRASE ===\n%s\n"
               "=== KEEP THIS SAFE — LOSING IT MEANS LOSING FUNDS ===\n",
               mnemonic_buf);
        if (!bip39_mnemonic_to_seed(mnemonic_buf, hd_passphrase ? hd_passphrase : "", seed)) {
            fprintf(stderr, "Client: HD wallet: bip39_mnemonic_to_seed failed\n");
            memset(seed, 0, sizeof(seed));
            return 0;
        }
        seed_len = 64;
    }

    /* Save seed and lookahead to DB */
    if (db_ptr) {
        persist_save_hd_seed(db_ptr, seed, seed_len);
        persist_save_hd_lookahead(db_ptr, lookahead);
    }

    g_hd_wallet_client = (wallet_source_hd_t *)calloc(1, sizeof(wallet_source_hd_t));
    if (!g_hd_wallet_client) {
        memset(seed, 0, sizeof(seed));
        return 0;
    }

    if (!wallet_source_hd_init(g_hd_wallet_client, seed, 64,
                                ctx, db_ptr, &g_bip158_client, network, lookahead)) {
        fprintf(stderr, "Client: HD wallet: init failed\n");
        free(g_hd_wallet_client);
        g_hd_wallet_client = NULL;
        memset(seed, 0, sizeof(seed));
        return 0;
    }
    memset(seed, 0, sizeof(seed));

    char spk_hex[69];
    if (wallet_source_hd_get_address(g_hd_wallet_client, 0, spk_hex, sizeof(spk_hex)))
        printf("Client: HD wallet address[0] SPK: %s\n"
               "Client: HD wallet ready (%u addresses pre-derived)\n",
               spk_hex, g_hd_wallet_client->n_spks);

    watchtower_set_wallet(wt, &g_hd_wallet_client->base);
    return 1;
}

/*
 * Initialise the BIP 158 backend, connect to the peer, restore checkpoint,
 * then plug the backend into the watchtower as its chain backend.
 * Returns 1 on success, 0 on failure.
 */
static int attach_light_client_client(watchtower_t *wt, persist_t *db_ptr,
                                       const char *host_port,
                                       const char *network,
                                       const char **fallbacks, int n_fallbacks)
{
    char host[256];
    int  port = 0;
    if (!bip158_parse_host_port(host_port, host, sizeof(host), &port)) {
        fprintf(stderr, "Client: --light-client: bad HOST:PORT '%s'\n", host_port);
        return 0;
    }

    if (!bip158_backend_init(&g_bip158_client, network)) {
        fprintf(stderr, "Client: bip158_backend_init failed\n");
        return 0;
    }

    if (db_ptr) {
        bip158_backend_set_db(&g_bip158_client, db_ptr);
        int restored = bip158_backend_restore_checkpoint(&g_bip158_client);
        if (restored)
            printf("Client: BIP 158 checkpoint restored (tip_height=%d)\n",
                   g_bip158_client.tip_height);
    }

    for (int i = 0; i < n_fallbacks; i++) {
        char fb_host[256];
        int  fb_port = 0;
        if (bip158_parse_host_port(fallbacks[i], fb_host, sizeof(fb_host), &fb_port))
            bip158_backend_add_peer(&g_bip158_client, fb_host, fb_port);
        else
            fprintf(stderr, "Client: --light-client-fallback: bad HOST:PORT '%s' (ignored)\n",
                    fallbacks[i]);
    }

    printf("Client: connecting BIP 157/158 peer %s:%d ...\n", host, port);
    if (!bip158_backend_connect_p2p(&g_bip158_client, host, port)) {
        fprintf(stderr, "Client: primary peer %s:%d failed; trying fallbacks...\n", host, port);
        if (g_bip158_client.n_peers == 0) {
            snprintf(g_bip158_client.peer_hosts[0],
                     sizeof(g_bip158_client.peer_hosts[0]), "%s", host);
            g_bip158_client.peer_ports[0] = port;
            g_bip158_client.n_peers = 1;
        }
        if (!bip158_backend_reconnect(&g_bip158_client)) {
            fprintf(stderr, "Client: --light-client: all peers failed\n");
            bip158_backend_free(&g_bip158_client);
            return 0;
        }
    }
    printf("Client: BIP 158 P2P peer connected (version %u, height %d)\n",
           g_bip158_client.peers[g_bip158_client.current_peer].peer_version,
           g_bip158_client.peers[g_bip158_client.current_peer].peer_start_height);

    watchtower_set_chain_backend(wt, &g_bip158_client.base);
    return 1;
}

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void hex_encode(const unsigned char *data, size_t len, char *out);
#include "superscalar/sha256.h"
#include "superscalar/bolt12.h"
#include "superscalar/bech32m.h"

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
    (void)keypair; (void)n_participants;
    multi_payment_data_t *data = (multi_payment_data_t *)user_data;

    /* Derive HTLC cltv from factory timeout (must expire before factory) */
    uint32_t htlc_cltv = factory->cltv_timeout > 40
                        ? factory->cltv_timeout - 40 : 500;

    for (size_t i = 0; i < data->n_actions; i++) {
        scripted_action_t *act = &data->actions[i];

        if (act->type == ACTION_SEND) {
            printf("Client %u: SEND %llu sats to client %u\n",
                   my_index, (unsigned long long)act->amount_sats, act->dest_client);

            if (!client_send_payment(fd, ch, act->amount_sats, act->payment_hash,
                                       htlc_cltv, act->dest_client)) {
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

/* Per-fd message inbox: queues messages that arrive out-of-order while
   recv_or_handle_ptlc is blocking for a specific message type.
   Prevents unexpected messages from being silently lost. */
#define CLIENT_INBOX_SIZE 4

typedef struct {
    wire_msg_t msgs[CLIENT_INBOX_SIZE];
    int head, tail, count;
} client_inbox_t;

static void client_inbox_push(client_inbox_t *ib, const wire_msg_t *m)
{
    if (ib->count >= CLIENT_INBOX_SIZE) {
        /* Inbox full — drop oldest to make room */
        if (ib->msgs[ib->head].json)
            cJSON_Delete(ib->msgs[ib->head].json);
        ib->head = (ib->head + 1) % CLIENT_INBOX_SIZE;
        ib->count--;
    }
    ib->msgs[ib->tail] = *m;
    ib->tail = (ib->tail + 1) % CLIENT_INBOX_SIZE;
    ib->count++;
}

static int client_inbox_pop(client_inbox_t *ib, wire_msg_t *out)
{
    if (ib->count == 0) return 0;
    *out = ib->msgs[ib->head];
    ib->head = (ib->head + 1) % CLIENT_INBOX_SIZE;
    ib->count--;
    return 1;
}


/* JIT channel state machine (non-blocking) */
typedef enum {
    JIT_PHASE_NONE = 0,
    JIT_PHASE_WAITING_BASEPOINTS,
    JIT_PHASE_WAITING_NONCES,
    JIT_PHASE_WAITING_READY,
    JIT_PHASE_COMPLETE
} jit_phase_t;

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
    client_inbox_t inbox;   /* out-of-order messages from recv_or_handle_ptlc */
    int test_lsps2;         /* 1 = send lsps2.get_info after factory setup */
    int test_lsps2_done;    /* 1 = LSPS2 get_info response verified */
    int test_lsps2_buy;     /* 1 = also send lsps2.buy after get_info */
    int test_lsps2_buy_done;/* 1 = LSPS2 buy response verified */
    int test_splice;        /* 1 = exit cleanly after first SPLICE_LOCKED */
    jit_phase_t jit_phase;
    size_t jit_offer_cidx;        /* client index from the offer */
    uint64_t jit_offer_amount;     /* funding amount from the offer */
} daemon_cb_data_t;

/* Handle a PTLC_PRESIG message inline (when received during a blocking wait
   for another message type like COMMITMENT_SIGNED).  This prevents the rotation
   PTLC from being silently discarded when it arrives mid-HTLC-flow. */
static void handle_ptlc_presig_inline(int fd, wire_msg_t *msg,
                                       secp256k1_context *ctx,
                                       const secp256k1_keypair *keypair,
                                       uint32_t my_index) {
    unsigned char presig[64], turnover_msg[32];
    int nonce_parity;
    if (!wire_parse_ptlc_presig(msg->json, presig, &nonce_parity, turnover_msg)) {
        fprintf(stderr, "Client %u: bad inline PTLC_PRESIG\n", my_index);
        return;
    }
    unsigned char my_seckey[32];
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair))
        return;
    unsigned char adapted_sig[64];
    if (!adaptor_adapt(ctx, adapted_sig, presig, my_seckey, nonce_parity)) {
        memset(my_seckey, 0, 32);
        return;
    }
    memset(my_seckey, 0, 32);
    cJSON *reply = wire_build_ptlc_adapted_sig(adapted_sig);
    wire_send(fd, MSG_PTLC_ADAPTED_SIG, reply);
    cJSON_Delete(reply);
    printf("Client %u: handled PTLC_PRESIG inline (mid-HTLC flow)\n", my_index);
}

/* Receive a specific message type, handling PTLC_PRESIG inline if it arrives
   instead.  Returns 1 if expected message received, 0 on timeout/error. */
static int recv_or_handle_ptlc(int fd, wire_msg_t *msg, int timeout_sec,
                                uint8_t expected_type,
                                secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                uint32_t my_index,
                                client_inbox_t *inbox) {
    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        int elapsed = (int)(now.tv_sec - start.tv_sec);
        int remaining = timeout_sec - elapsed;
        if (remaining <= 0)
            return 0;
        if (!wire_recv_timeout(fd, msg, remaining))
            return 0;
        if (msg->msg_type == expected_type)
            return 1;
        if (msg->msg_type == MSG_PTLC_PRESIG) {
            handle_ptlc_presig_inline(fd, msg, ctx, keypair, my_index);
            cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;  /* Retry for the expected message */
        }
        /* Unexpected non-PTLC message: queue to inbox so the daemon loop
           can process it, rather than silently discarding it. */
        if (msg->msg_type == MSG_ERROR)
            return 0;  /* propagate abort */
        if (inbox) {
            client_inbox_push(inbox, msg);
            msg->json = NULL;  /* inbox owns the json now */
        } else {
            cJSON_Delete(msg->json);
            msg->json = NULL;
        }
        continue;  /* keep waiting for expected_type */
    }
}

/* Receive and process LSP's own revocation (bidirectional revocation).
   Call after each client_handle_commitment_signed in daemon mode.
   old_local/old_remote are the channel amounts at the OLD commitment being
   revoked (before the state-advancing add/fulfill that preceded this). */
static void client_recv_lsp_revocation(int fd, channel_t *ch, daemon_cb_data_t *cbd,
                                         secp256k1_context *ctx,
                                         uint64_t old_local, uint64_t old_remote,
                                         const htlc_t *old_htlcs, size_t old_n_htlcs,
                                         const secp256k1_keypair *keypair,
                                         uint32_t my_index) {
    wire_msg_t rev_msg;
    if (!recv_or_handle_ptlc(fd, &rev_msg, 15, MSG_LSP_REVOKE_AND_ACK,
                              ctx, keypair, my_index, cbd ? &cbd->inbox : NULL))
        return;
    if (rev_msg.msg_type != MSG_LSP_REVOKE_AND_ACK) {
        /* Not a revocation — unexpected msg; silently skip */
        cJSON_Delete(rev_msg.json);
        return;
    }
    uint32_t rev_chan_id;
    unsigned char lsp_rev_secret[32], lsp_next_point[33];
    if (wire_parse_revoke_and_ack(rev_msg.json, &rev_chan_id,
                                    lsp_rev_secret, lsp_next_point)) {
        uint64_t old_cn = ch->commitment_number - 1;
        channel_receive_revocation(ch, old_cn, lsp_rev_secret);

        /* Register with client watchtower using the OLD commitment's amounts.
           Use local channel index 0 (not the LSP's factory-wide rev_chan_id)
           because the client watchtower has only one channel at index 0. */
        if (cbd && cbd->wt) {
            watchtower_watch_revoked_commitment(cbd->wt, ch,
                0, old_cn,
                old_local, old_remote,
                old_htlcs, old_n_htlcs);
        }

        /* Store LSP's next per-commitment point */
        secp256k1_pubkey next_pcp;
        if (secp256k1_ec_pubkey_parse(ctx, &next_pcp, lsp_next_point, 33)) {
            channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);
            /* Persist both current and next remote PCPs for crash recovery */
            if (cbd && cbd->db) {
                unsigned char ser[33];
                size_t slen = 33;
                secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &next_pcp,
                                               SECP256K1_EC_COMPRESSED);
                persist_save_remote_pcp(cbd->db, 0,
                    ch->commitment_number + 1, ser);
                /* Also persist the current PCP (may have just been set) */
                secp256k1_pubkey cur_pcp;
                if (channel_get_remote_pcp(ch, ch->commitment_number, &cur_pcp)) {
                    slen = 33;
                    secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &cur_pcp,
                                                   SECP256K1_EC_COMPRESSED);
                    persist_save_remote_pcp(cbd->db, 0,
                        ch->commitment_number, ser);
                }
            }
        }

        /* Persist our own local PCS so they survive crash/reconnect.
           Without this, reconnect generates new random PCS that don't
           match the PCPs the LSP has stored, breaking sig verification. */
        if (cbd && cbd->db) {
            unsigned char pcs[32];
            if (channel_get_local_pcs(ch, ch->commitment_number, pcs))
                persist_save_local_pcs(cbd->db, 0,
                    ch->commitment_number, pcs);
            if (channel_get_local_pcs(ch, ch->commitment_number + 1, pcs))
                persist_save_local_pcs(cbd->db, 0,
                    ch->commitment_number + 1, pcs);
            memset(pcs, 0, 32);
        }

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
                /* Save initial local PCS so they survive crash before first payment */
                for (uint64_t cn = 0; cn < ch->n_local_pcs; cn++) {
                    unsigned char pcs[32];
                    if (channel_get_local_pcs(ch, cn, pcs)) {
                        persist_save_local_pcs(cbd->db, 0, cn, pcs);
                        memset(pcs, 0, 32);
                    }
                }
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


    /* Clear any stale inbox messages from a previous connection.
       The same daemon_cb_data_t is reused across reconnects, so
       messages queued during the previous session would otherwise
       be replayed with the new connection's channel state. */
    {
        wire_msg_t stale_imsg;
        while (client_inbox_pop(&cbd->inbox, &stale_imsg))
            cJSON_Delete(stale_imsg.json);
    }

    printf("Client %u: daemon mode active (Ctrl+C to stop)\n", my_index);

    /* Log factory lifecycle once (Tier 2) */
    if (factory && factory->active_blocks > 0) {
        printf("Client %u: factory lifecycle: active %u blocks, dying %u blocks\n",
               my_index, factory->active_blocks, factory->dying_blocks);
    }

    /* Watchtower check runs on a time-gated basis (every ~10s) inside the
       select() loop below, regardless of whether select() timed out or
       returned socket activity.  See the static last_wt variable there. */

    /* --test-lsps2: send lsps2.get_info immediately on factory entry */
    if (cbd && cbd->test_lsps2 && !cbd->test_lsps2_done) {
        cJSON *req = cJSON_CreateObject();
        if (req) {
            cJSON_AddStringToObject(req, "jsonrpc", "2.0");
            cJSON_AddNumberToObject(req, "id", 1);
            cJSON_AddStringToObject(req, "method", "lsps2.get_info");
            cJSON_AddNullToObject(req, "params");
            wire_send(fd, MSG_LSPS_REQUEST, req);
            cJSON_Delete(req);
            printf("Client %u: sent lsps2.get_info request\n", my_index);
        }
    }

    while (!g_shutdown) {
        wire_msg_t msg;

        /* Drain messages queued by recv_or_handle_ptlc before blocking.
           MSG_COMMITMENT_SIGNED is handled inline (needs immediate revocation
           exchange).  ALL other message types are re-dispatched through the
           main daemon switch via goto so nothing is silently dropped. */
        {
            wire_msg_t imsg;
            while (client_inbox_pop(&cbd->inbox, &imsg)) {
                if (imsg.msg_type == MSG_COMMITMENT_SIGNED) {
                    client_handle_commitment_signed(fd, ch, ctx, &imsg);
                    cJSON_Delete(imsg.json);
                    if (cbd && cbd->db)
                        persist_update_channel_balance(cbd->db, my_index - 1,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number);
                } else {
                    /* Re-dispatch through main switch instead of discarding */
                    msg = imsg;
                    goto handle_message;
                }
            }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) continue;  /* EINTR */

        /* Periodic watchtower check — runs every ~10s regardless of select()
           result.  Previous code only ran on timeout (ret==0), so active
           sockets could starve the watchtower indefinitely. */
        {
            static time_t last_wt = 0;
            time_t tnow = time(NULL);
            if (last_wt == 0) last_wt = tnow;
            if (cbd && cbd->wt && (tnow - last_wt) >= 10) {
                last_wt = tnow;
                watchtower_check(cbd->wt);
            }
        }

        if (ret == 0) continue;  /* no socket data — loop back */

        if (!wire_recv(fd, &msg)) {
            fprintf(stderr, "Client %u: daemon recv failed (disconnected)\n", my_index);
            return 0;  /* signal disconnect — main() will retry */
        }

handle_message:
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

            /* Wait for COMMITMENT_SIGNED (5s timeout), handling PTLC_PRESIG
               inline to prevent rotation messages from being discarded */
            if (!recv_or_handle_ptlc(fd, &msg, 5, MSG_COMMITMENT_SIGNED,
                                      ctx, keypair, my_index, &cbd->inbox)) {
                fprintf(stderr, "Client %u: timeout waiting for commit after ADD\n", my_index);
                break;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                if (!client_handle_commitment_signed(fd, ch, ctx, &msg)) {
                    fprintf(stderr, "Client %u: commitment_signed handling failed "
                            "(cn=%llu, local=%llu, remote=%llu, htlcs=%zu)\n",
                            my_index,
                            (unsigned long long)ch->commitment_number,
                            (unsigned long long)ch->local_amount,
                            (unsigned long long)ch->remote_amount,
                            ch->n_htlcs);
                    cJSON_Delete(msg.json);
                    break;
                }
                cJSON_Delete(msg.json);
                /* Receive LSP's own revocation (bidirectional) */
                client_recv_lsp_revocation(fd, ch, cbd, ctx,
                    pre_add_local, pre_add_remote,
                    pre_add_n_htlcs > 0 ? pre_add_htlcs : NULL, pre_add_n_htlcs,
                    keypair, my_index);
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

                    /* Handle COMMITMENT_SIGNED for the fulfill (5s timeout),
                       handling PTLC_PRESIG inline to prevent rotation loss */
                    if (recv_or_handle_ptlc(fd, &msg, 5, MSG_COMMITMENT_SIGNED,
                                             ctx, keypair, my_index, &cbd->inbox) &&
                        msg.msg_type == MSG_COMMITMENT_SIGNED) {
                        client_handle_commitment_signed(fd, ch, ctx, &msg);
                        if (msg.json) cJSON_Delete(msg.json);
                        /* Receive LSP's own revocation (bidirectional) */
                        client_recv_lsp_revocation(fd, ch, cbd, ctx,
                            pre_ful_local, pre_ful_remote,
                            pre_ful_n_htlcs > 0 ? pre_ful_htlcs : NULL, pre_ful_n_htlcs,
                            keypair, my_index);
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
                ch->n_htlcs > 0 ? ch->htlcs : NULL, ch->n_htlcs,
                keypair, my_index);
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
            /* Handle follow-up COMMITMENT_SIGNED (5s timeout),
               handling PTLC_PRESIG inline to prevent rotation loss */
            if (recv_or_handle_ptlc(fd, &msg, 5, MSG_COMMITMENT_SIGNED,
                                     ctx, keypair, my_index, &cbd->inbox) &&
                msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                if (msg.json) cJSON_Delete(msg.json);
                /* Receive LSP's own revocation (bidirectional) */
                client_recv_lsp_revocation(fd, ch, cbd, ctx,
                    pre_ful2_local, pre_ful2_remote,
                    pre_ful2_n_htlcs > 0 ? pre_ful2_htlcs : NULL, pre_ful2_n_htlcs,
                    keypair, my_index);
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

        case MSG_LSP_REVOKE_AND_ACK: {
            /* LSP's own revocation, arriving naturally in the daemon loop.
               This happens when a queued CS was processed from the inbox:
               client_handle_commitment_signed sent RAA, LSP responded with this. */
            uint32_t lra_chan_id;
            unsigned char lra_rev_secret[32], lra_next_point[33];
            if (wire_parse_revoke_and_ack(msg.json, &lra_chan_id,
                                            lra_rev_secret, lra_next_point)) {
                if (ch->commitment_number > 0)
                    channel_receive_revocation(ch, ch->commitment_number - 1,
                                               lra_rev_secret);
                /* Persist new remote PCP */
                if (cbd && cbd->db) {
                    secp256k1_pubkey lra_pcp;
                    if (secp256k1_ec_pubkey_parse(ctx, &lra_pcp, lra_next_point, 33)) {
                        unsigned char lra_ser[33];
                        size_t lra_slen = 33;
                        secp256k1_ec_pubkey_serialize(ctx, lra_ser, &lra_slen,
                                                       &lra_pcp, SECP256K1_EC_COMPRESSED);
                        persist_save_remote_pcp(cbd->db, 0,
                            ch->commitment_number, lra_ser);
                    }
                }
            }
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_CLOSE_PROPOSE:
            printf("Client %u: received CLOSE_PROPOSE in daemon mode\n", my_index);
            client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                      factory, n_participants, &msg, 0);
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
                                                           inv->preimage,
                                                           inv_amount_msat,
                                                           (size_t)client_idx);
                wire_send(fd, MSG_REGISTER_INVOICE, reg);
                cJSON_Delete(reg);
            }
            break;
        }

        case MSG_INVOICE_BOLT11: {
            /* LSP forwarded a BOLT11 invoice string from CLN */
            unsigned char bolt11_hash[32];
            char bolt11_str[2048];
            if (!wire_parse_invoice_bolt11(msg.json, bolt11_hash,
                                             bolt11_str, sizeof(bolt11_str))) {
                fprintf(stderr, "Client %u: bad INVOICE_BOLT11\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            printf("Client %u: BOLT11 invoice ready:\n%s\n",
                   my_index, bolt11_str);
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

            /* Receive PTLC_COMPLETE acknowledgement (5s timeout) */
            wire_msg_t complete_msg;
            if (wire_recv_timeout(fd, &complete_msg, 5)) {
                if (complete_msg.msg_type == MSG_PTLC_COMPLETE)
                    printf("Client %u: PTLC departure complete\n", my_index);
                cJSON_Delete(complete_msg.json);
            }
            break;
        }

        case MSG_PING: {
            /* Keepalive ping from LSP: respond with pong */
            cJSON *pong = cJSON_CreateObject();
            wire_send(fd, MSG_PONG, pong);
            cJSON_Delete(pong);
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_PONG:
            /* Keepalive response: discard */
            cJSON_Delete(msg.json);
            break;

        case MSG_DELIVER_PREIMAGE: {
            /* LSP delivers preimage for an admin-created invoice.
               Store it so we can fulfill the HTLC when it arrives. */
            unsigned char dp_hash[32], dp_preimage[32];
            if (msg.json &&
                wire_json_get_hex(msg.json, "payment_hash", dp_hash, 32) == 32 &&
                wire_json_get_hex(msg.json, "preimage", dp_preimage, 32) == 32) {
                if (cbd && cbd->n_invoices < MAX_CLIENT_INVOICES) {
                    client_invoice_t *inv = &cbd->invoices[cbd->n_invoices];
                    memcpy(inv->payment_hash, dp_hash, 32);
                    memcpy(inv->preimage, dp_preimage, 32);
                    cJSON *amt = cJSON_GetObjectItem(msg.json, "amount_msat");
                    inv->amount_msat = amt ? (uint64_t)amt->valuedouble : 0;
                    inv->active = 1;
                    cbd->n_invoices++;
                    printf("Client %u: stored preimage for admin invoice\n", my_index);
                }
            }
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_JIT_OFFER: {
            /* LSP offers a JIT channel — non-blocking state machine */
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

            /* Save offer context and transition to non-blocking wait */
            cbd->jit_offer_cidx = jit_cidx;
            cbd->jit_offer_amount = jit_amount;
            cbd->jit_phase = JIT_PHASE_WAITING_BASEPOINTS;
            printf("Client %u: JIT phase -> WAITING_BASEPOINTS\n", my_index);
            break;
        }

        case MSG_CHANNEL_BASEPOINTS: {
            /* JIT basepoints exchange (non-blocking) */
            if (cbd->jit_phase != JIT_PHASE_WAITING_BASEPOINTS) {
                fprintf(stderr, "Client %u: unexpected CHANNEL_BASEPOINTS "
                        "(jit_phase=%d)\n", my_index, cbd->jit_phase);
                cJSON_Delete(msg.json);
                break;
            }

            /* Allocate JIT channel if not yet present */
            if (!cbd->jit_ch) {
                cbd->jit_ch = calloc(1, sizeof(jit_channel_t));
                if (!cbd->jit_ch) {
                    fprintf(stderr, "Client %u: JIT channel alloc failed\n", my_index);
                    cbd->jit_phase = JIT_PHASE_NONE;
                    cJSON_Delete(msg.json);
                    break;
                }
            }
            jit_channel_t *jit_bp = cbd->jit_ch;

            /* Parse LSP's basepoints */
            uint32_t bp_ch_id;
            secp256k1_pubkey pay_bp, delay_bp, revoc_bp, htlc_bp, first_pcp, second_pcp;
            if (!wire_parse_channel_basepoints(msg.json, &bp_ch_id, ctx,
                                                 &pay_bp, &delay_bp, &revoc_bp, &htlc_bp,
                                                 &first_pcp, &second_pcp)) {
                fprintf(stderr, "Client %u: bad JIT CHANNEL_BASEPOINTS\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            jit_bp->jit_channel_id = bp_ch_id;
            jit_bp->client_idx = cbd->jit_offer_cidx;

            /* Send client's basepoints back */
            {
                channel_t *jch = &jit_bp->channel;
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

            cbd->jit_phase = JIT_PHASE_WAITING_NONCES;
            printf("Client %u: JIT phase -> WAITING_NONCES\n", my_index);
            break;
        }

        case MSG_CHANNEL_NONCES: {
            /* JIT nonce exchange (non-blocking) */
            if (cbd->jit_phase != JIT_PHASE_WAITING_NONCES) {
                fprintf(stderr, "Client %u: unexpected CHANNEL_NONCES "
                        "(jit_phase=%d)\n", my_index, cbd->jit_phase);
                cJSON_Delete(msg.json);
                break;
            }

            jit_channel_t *jit_nc = cbd->jit_ch;
            uint32_t nm_ch_id;
            unsigned char lsp_nonces[MUSIG_NONCE_POOL_MAX][66];
            size_t lsp_nc;
            wire_parse_channel_nonces(msg.json, &nm_ch_id, lsp_nonces,
                                        MUSIG_NONCE_POOL_MAX, &lsp_nc);
            cJSON_Delete(msg.json);

            /* Init nonce pool and send client's nonces */
            channel_init_nonce_pool(&jit_nc->channel, MUSIG_NONCE_POOL_MAX);
            channel_set_remote_pubnonces(&jit_nc->channel,
                (const unsigned char (*)[66])lsp_nonces, lsp_nc);

            size_t nc = jit_nc->channel.local_nonce_pool.count;
            unsigned char (*pn_ser)[66] = calloc(nc, 66);
            if (pn_ser) {
                for (size_t i = 0; i < nc; i++)
                    musig_pubnonce_serialize(ctx, pn_ser[i],
                        &jit_nc->channel.local_nonce_pool.nonces[i].pubnonce);
                cJSON *cnm = wire_build_channel_nonces(jit_nc->jit_channel_id,
                    (const unsigned char (*)[66])pn_ser, nc);
                wire_send(fd, MSG_CHANNEL_NONCES, cnm);
                cJSON_Delete(cnm);
                free(pn_ser);
            }

            cbd->jit_phase = JIT_PHASE_WAITING_READY;
            printf("Client %u: JIT phase -> WAITING_READY\n", my_index);
            break;
        }

        case MSG_JIT_READY: {
            /* JIT channel funded and ready (non-blocking) */
            if (cbd->jit_phase != JIT_PHASE_WAITING_READY) {
                fprintf(stderr, "Client %u: unexpected JIT_READY "
                        "(jit_phase=%d)\n", my_index, cbd->jit_phase);
                cJSON_Delete(msg.json);
                break;
            }

            jit_channel_t *jit_rd = cbd->jit_ch;
            uint32_t jit_ch_id;
            char fund_txid_hex[65];
            uint32_t fund_vout;
            uint64_t fund_amount, local_amt, remote_amt;
            if (!wire_parse_jit_ready(msg.json, &jit_ch_id,
                                        fund_txid_hex, sizeof(fund_txid_hex),
                                        &fund_vout, &fund_amount,
                                        &local_amt, &remote_amt)) {
                fprintf(stderr, "Client %u: bad JIT_READY\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            /* Finalize JIT channel init — for client, swap local/remote
               since LSP's local is client's remote */
            jit_rd->jit_channel_id = jit_ch_id;
            memcpy(jit_rd->funding_txid_hex, fund_txid_hex, 64);
            jit_rd->funding_txid_hex[64] = '\0';
            jit_rd->funding_amount = fund_amount;
            jit_rd->funding_vout = fund_vout;
            jit_rd->funding_confirmed = 1;

            /* Set balances: from client perspective, local_amt is LSP's local
               (= our remote), remote_amt is LSP's remote (= our local) */
            jit_rd->channel.local_amount = remote_amt;
            jit_rd->channel.remote_amount = local_amt;
            jit_rd->channel.funding_amount = fund_amount;
            jit_rd->channel.funder_is_local = 0;

            jit_rd->state = JIT_STATE_OPEN;

            /* Register JIT channel with client watchtower */
            if (cbd && cbd->wt)
                watchtower_set_channel(cbd->wt, 0, &jit_rd->channel);

            /* Persist JIT channel */
            if (cbd && cbd->db) {
                if (persist_begin(cbd->db)) {
                    if (persist_save_jit_channel(cbd->db, jit_rd) &&
                        persist_save_basepoints(cbd->db, jit_rd->jit_channel_id,
                                                  &jit_rd->channel)) {
                        persist_commit(cbd->db);
                    } else {
                        fprintf(stderr, "Client %u: JIT persist failed, rolling back\n", my_index);
                        persist_rollback(cbd->db);
                    }
                } else {
                    fprintf(stderr, "Client %u: persist_begin failed for JIT channel\n", my_index);
                }
            }

            cbd->jit_phase = JIT_PHASE_COMPLETE;
            printf("Client %u: JIT channel %08x OPEN (%llu sats)\n",
                   my_index, jit_ch_id, (unsigned long long)fund_amount);
            printf("Client %u: JIT phase -> COMPLETE\n", my_index);
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

            /* Clear old watchtower entries — the old factory is closed.
               Don't call watchtower_set_channel after clear: clear_entries
               frees the channels array (via watchtower_cleanup), so
               set_channel would write through a NULL pointer.
               The reconnect path will re-register the channel. */
            if (cbd && cbd->wt)
                watchtower_clear_entries(cbd->wt);

            /* Persist new factory + channel if DB available */
            if (cbd && cbd->db) {
                if (persist_begin(cbd->db)) {
                    uint32_t rot_client_idx = my_index - 1;
                    if (persist_save_factory(cbd->db, factory, ctx, 0) &&
                        persist_save_channel(cbd->db, ch, 0, rot_client_idx) &&
                        persist_save_basepoints(cbd->db, rot_client_idx, ch)) {
                        /* Save initial PCS for the new rotated channel so they
                           survive crash before first payment on the new factory */
                        for (uint64_t cn = 0; cn < ch->n_local_pcs; cn++) {
                            unsigned char pcs[32];
                            if (channel_get_local_pcs(ch, cn, pcs)) {
                                persist_save_local_pcs(cbd->db, 0, cn, pcs);
                                memset(pcs, 0, 32);
                            }
                        }
                        /* Save remote PCPs (LSP's per-commitment points) */
                        for (uint64_t cn = 0; cn <= ch->commitment_number + 1; cn++) {
                            secp256k1_pubkey pcp;
                            if (channel_get_remote_pcp(ch, cn, &pcp)) {
                                unsigned char ser[33];
                                size_t slen = 33;
                                if (secp256k1_ec_pubkey_serialize(ctx, ser, &slen,
                                        &pcp, SECP256K1_EC_COMPRESSED))
                                    persist_save_remote_pcp(cbd->db, 0, cn, ser);
                            }
                        }
                        persist_commit(cbd->db);
                        printf("Client %u: persisted rotated factory + channel + basepoints + PCS\n", my_index);
                    } else {
                        fprintf(stderr, "Client %u: rotation persist failed, rolling back\n", my_index);
                        persist_rollback(cbd->db);
                    }
                } else {
                    fprintf(stderr, "Client %u: persist_begin failed for rotation\n", my_index);
                }
            }

            /* Disconnect and let main() reconnect from DB with the new
               factory.  Continuing in the same daemon loop after replacing
               factory + channel in-place causes subtle state corruption
               (Bug 11).  The reconnect path loads cleanly from DB. */
            printf("Client %u: rotation complete, reconnecting with new factory\n", my_index);
            return 0;
        }

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

        case MSG_LEAF_REALLOC_PROPOSE: {
            /* LSP proposes leaf reallocation — run the full ceremony
               (nonce exchange + partial sig exchange + done confirmation). */
            wire_msg_t propose_msg = { .msg_type = msg.msg_type, .json = msg.json };
            if (!client_handle_leaf_realloc(fd, ctx, keypair, factory,
                                              my_index, &propose_msg)) {
                fprintf(stderr, "Client %u: leaf realloc failed\n", my_index);
            }
            cJSON_Delete(msg.json);
            break;
        }

        /* -------------------------------------------------------------------
         * Splice protocol — LSP-initiated quiescence and funding replacement
         * ----------------------------------------------------------------- */

        case MSG_STFU: {
            /* LSP is requesting quiescence prior to splice.
               Mark channel quiescent and echo STFU_ACK (reusing splice_ack
               JSON with acceptor_contribution=0 — same format as lsp_channels.c). */
            const cJSON *cid_f = cJSON_GetObjectItemCaseSensitive(msg.json, "channel_id");
            uint32_t stfu_ch_id = (cid_f && cJSON_IsNumber(cid_f))
                                      ? (uint32_t)cid_f->valuedouble : 0;
            ch->channel_quiescent = 1;
            cJSON *ack = wire_build_splice_ack(stfu_ch_id, 0);
            if (ack) { wire_send(fd, MSG_STFU_ACK, ack); cJSON_Delete(ack); }
            printf("Client %u: STFU from LSP (ch %u), sent STFU_ACK\n",
                   my_index, stfu_ch_id);
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_SPLICE_INIT: {
            /* LSP is proposing a splice (amount + new funding SPK).
               Respond with SPLICE_ACK, no extra contribution from client. */
            uint32_t sp_ch_id = 0;
            uint64_t sp_new_amount = 0;
            unsigned char sp_new_spk[34];
            size_t sp_spk_len = 0;
            if (wire_parse_splice_init(msg.json, &sp_ch_id, &sp_new_amount,
                                        sp_new_spk, &sp_spk_len, sizeof(sp_new_spk))) {
                ch->channel_quiescent = 1;
                cJSON *ack = wire_build_splice_ack(sp_ch_id, 0);
                if (ack) { wire_send(fd, MSG_SPLICE_ACK, ack); cJSON_Delete(ack); }
                printf("Client %u: SPLICE_INIT from LSP: new_funding=%llu sats, sent SPLICE_ACK\n",
                       my_index, (unsigned long long)sp_new_amount);
            } else {
                fprintf(stderr, "Client %u: invalid SPLICE_INIT\n", my_index);
            }
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_SPLICE_LOCKED: {
            /* LSP confirms splice tx confirmed on-chain.
               Apply channel update and echo SPLICE_LOCKED. */
            uint32_t sl_ch_id = 0;
            unsigned char sl_new_txid[32];
            uint32_t sl_new_vout = 0;
            if (wire_parse_splice_locked(msg.json, &sl_ch_id,
                                          sl_new_txid, &sl_new_vout)) {
                channel_apply_splice_update(ch, sl_new_txid, sl_new_vout,
                                             ch->funding_amount);
                cJSON *locked = wire_build_splice_locked(sl_ch_id, sl_new_txid, sl_new_vout);
                if (locked) { wire_send(fd, MSG_SPLICE_LOCKED, locked); cJSON_Delete(locked); }

                unsigned char disp_txid[32];
                memcpy(disp_txid, sl_new_txid, 32);
                /* txid display: reverse to RPC byte order */
                for (int _i = 0; _i < 16; _i++) {
                    unsigned char _t = disp_txid[_i];
                    disp_txid[_i] = disp_txid[31 - _i];
                    disp_txid[31 - _i] = _t;
                }
                char disp_hex[65]; hex_encode(disp_txid, 32, disp_hex);
                printf("Client %u: splice complete! new txid=%s vout=%u\n",
                       my_index, disp_hex, sl_new_vout);
                if (cbd && cbd->test_splice) {
                    cJSON_Delete(msg.json);
                    return 2;  /* splice test done — exit daemon loop cleanly */
                }
            } else {
                fprintf(stderr, "Client %u: invalid SPLICE_LOCKED\n", my_index);
            }
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_LSPS_RESPONSE: {
            cJSON *result = msg.json
                ? cJSON_GetObjectItem(msg.json, "result") : NULL;

            /* Phase 1: lsps2.get_info response */
            if (cbd && cbd->test_lsps2 && !cbd->test_lsps2_done) {
                int ok = (result != NULL &&
                          cJSON_GetObjectItem(result, "min_fee_msat") != NULL);
                printf("LSPS2 GET_INFO: %s\n", ok ? "OK" : "FAIL");
                fflush(stdout);
                cbd->test_lsps2_done = 1;

                /* get_info-only test: exit cleanly now — no need for close ceremony */
                if (!cbd->test_lsps2_buy) {
                    cJSON_Delete(msg.json);
                    return 2;
                }

                /* If buy test requested, send lsps2.buy using returned fee params */
                if (ok && cbd->test_lsps2_buy && !cbd->test_lsps2_buy_done) {
                    cJSON *buy_req = cJSON_CreateObject();
                    if (buy_req) {
                        cJSON_AddStringToObject(buy_req, "jsonrpc", "2.0");
                        cJSON_AddNumberToObject(buy_req, "id", 2);
                        cJSON_AddStringToObject(buy_req, "method", "lsps2.buy");
                        cJSON *params = cJSON_CreateObject();
                        if (params) {
                            /* opening_fee_params: forward the params object from get_info */
                            cJSON *fee_params = cJSON_CreateObject();
                            cJSON *min_fee = cJSON_GetObjectItem(result, "min_fee_msat");
                            if (fee_params && min_fee)
                                cJSON_AddNumberToObject(fee_params, "min_fee_msat",
                                                        min_fee->valuedouble);
                            cJSON_AddItemToObject(params, "opening_fee_params", fee_params);
                            cJSON_AddNumberToObject(params, "payment_size_msat", 100000.0);
                            cJSON_AddItemToObject(buy_req, "params", params);
                        }
                        wire_send(fd, MSG_LSPS_REQUEST, buy_req);
                        cJSON_Delete(buy_req);
                        printf("Client %u: sent lsps2.buy request\n", my_index);
                        fflush(stdout);
                    }
                }
                cJSON_Delete(msg.json);
                break;
            }

            /* Phase 2: lsps2.buy response — verify jit_channel_scid */
            if (cbd && cbd->test_lsps2_buy && !cbd->test_lsps2_buy_done) {
                int ok = 0;
                if (result) {
                    cJSON *scid_j = cJSON_GetObjectItem(result, "jit_channel_scid");
                    if (scid_j && cJSON_IsString(scid_j) && scid_j->valuestring) {
                        /* scid format: NxNxN */
                        unsigned int a, b, c;
                        ok = (sscanf(scid_j->valuestring, "%ux%ux%u", &a, &b, &c) == 3);
                    }
                }
                printf("LSPS2 BUY: %s\n", ok ? "OK" : "FAIL");
                fflush(stdout);
                cbd->test_lsps2_buy_done = 1;
                cJSON_Delete(msg.json);
                return 2;  /* all LSPS2 test objectives done; skip close ceremony */
            }

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
        "  --fee-rate N                      Fee rate in sat/kvB (default 1000 = 1 sat/vB, min 100 = 0.1 sat/vB)\n"
        "  --report PATH                     Write diagnostic JSON report to PATH\n"
        "  --db PATH                         SQLite database for persistence (default: none)\n"
        "  --network MODE                    Network: regtest, signet, testnet, testnet4, mainnet (default: regtest)\n"
        "  --regtest                         Shorthand for --network regtest\n"
        "  --keyfile PATH                    Load/save secret key from encrypted file\n"
        "  --passphrase PASS                 Passphrase for keyfile (default: empty)\n"
        "  --cli-path PATH                   Path to bitcoin-cli binary (default: bitcoin-cli)\n"
        "  --rpcuser USER                    Bitcoin RPC username (default: rpcuser)\n"
        "  --rpcpassword PASS                Bitcoin RPC password (default: rpcpass)\n"
        "  --datadir PATH                    Bitcoin datadir (default: bitcoind default)\n"
        "  --rpcport PORT                    Bitcoin RPC port (default: network default)\n"
        "  --light-client HOST:PORT          Use BIP 157/158 P2P compact block filters for chain\n"
        "                                    scanning. bitcoind not required when set.\n"
        "  --light-client-fallback HOST:PORT Add a fallback peer (up to 7 total).\n"
        "  --auto-accept-jit                 Auto-accept JIT channel offers (default: off)\n"
        "  --lsp-pubkey HEX                  LSP static pubkey (33-byte hex) for NK authentication\n"
        "  --tor-proxy HOST:PORT             SOCKS5 proxy for Tor (default: 127.0.0.1:9050)\n"
        "  --generate-mnemonic               Generate 24-word BIP39 mnemonic, derive key, save to --keyfile, then exit\n"
        "  --from-mnemonic WORDS             Restore key from BIP39 mnemonic, save to --keyfile, then exit\n"
        "  --mnemonic-passphrase P           BIP39 passphrase for seed derivation (default: empty)\n"
        "  --i-accept-the-risk               Allow mainnet operation (PROTOTYPE — funds at risk!)\n"
        "  --version                         Show version and exit\n"
        "  --help                            Show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    /* Line-buffered stdout so logs are visible even if process is killed */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

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
    const char *lsp_pubkey_hex = NULL;
    const char *lsp_domain = NULL;      /* --lsp DOMAIN: bootstrap from well-known */
    const char *tor_proxy_arg = NULL;
    int tor_only = 0;
    int accept_risk = 0;
    int generate_mnemonic = 0;
    const char *from_mnemonic = NULL;
    const char *mnemonic_passphrase = "";
    const char *hd_mnemonic = NULL;
    const char *hd_passphrase = "";
    uint32_t hd_lookahead = HD_WALLET_LOOKAHEAD;
    const char *light_client_arg = NULL;
    const char *fee_estimator_arg = NULL;
    const char *lc_fallbacks[BIP158_MAX_PEERS - 1];
    memset(lc_fallbacks, 0, sizeof(lc_fallbacks));
    int n_lc_fallbacks = 0;
    const char *pay_offer_str = NULL;  /* --pay-offer BECH32M_OFFER */
    int test_lsps2 = 0;               /* --test-lsps2: send lsps2.get_info, verify response */
    int test_lsps2_buy = 0;           /* --test-lsps2-buy: also send lsps2.buy, verify scid */
    int test_splice = 0;              /* --test-splice: exit cleanly after SPLICE_LOCKED */

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
        else if (strcmp(argv[i], "--fee-estimator") == 0 && i + 1 < argc)
            fee_estimator_arg = argv[++i];
        else if (strcmp(argv[i], "--light-client") == 0 && i + 1 < argc)
            light_client_arg = argv[++i];
        else if (strcmp(argv[i], "--light-client-fallback") == 0 && i + 1 < argc) {
            if (n_lc_fallbacks < (int)(sizeof(lc_fallbacks)/sizeof(lc_fallbacks[0])))
                lc_fallbacks[n_lc_fallbacks++] = argv[++i];
            else { fprintf(stderr, "Warning: too many --light-client-fallback peers (max %d)\n",
                           (int)(sizeof(lc_fallbacks)/sizeof(lc_fallbacks[0]))); i++; }
        }
        else if (strcmp(argv[i], "--hd-mnemonic") == 0 && i + 1 < argc)
            hd_mnemonic = argv[++i];
        else if (strcmp(argv[i], "--hd-passphrase") == 0 && i + 1 < argc)
            hd_passphrase = argv[++i];
        else if (strcmp(argv[i], "--hd-lookahead") == 0 && i + 1 < argc)
            hd_lookahead = (uint32_t)atoi(argv[++i]);
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
        } else if (strcmp(argv[i], "--test-lsps2") == 0) {
            test_lsps2 = 1;
        } else if (strcmp(argv[i], "--test-lsps2-buy") == 0) {
            test_lsps2 = 1;        /* implies get_info first */
            test_lsps2_buy = 1;
            auto_accept_jit = 1;   /* lsps2.buy triggers JIT offer; must accept */
        } else if (strcmp(argv[i], "--test-splice") == 0) {
            test_splice = 1;
        } else if (strcmp(argv[i], "--lsp-pubkey") == 0 && i + 1 < argc) {
            lsp_pubkey_hex = argv[++i];
        } else if (strcmp(argv[i], "--lsp") == 0 && i + 1 < argc) {
            lsp_domain = argv[++i];
        } else if (strcmp(argv[i], "--tor-proxy") == 0 && i + 1 < argc) {
            tor_proxy_arg = argv[++i];
        } else if (strcmp(argv[i], "--tor-only") == 0) {
            tor_only = 1;
        } else if (strcmp(argv[i], "--generate-mnemonic") == 0) {
            generate_mnemonic = 1;
        } else if (strcmp(argv[i], "--from-mnemonic") == 0 && i + 1 < argc) {
            from_mnemonic = argv[++i];
        } else if (strcmp(argv[i], "--mnemonic-passphrase") == 0 && i + 1 < argc) {
            mnemonic_passphrase = argv[++i];
        } else if (strcmp(argv[i], "--i-accept-the-risk") == 0) {
            accept_risk = 1;
        } else if (strcmp(argv[i], "--pay-offer") == 0 && i + 1 < argc) {
            pay_offer_str = argv[++i];
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("superscalar_client %s\n", SUPERSCALAR_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    /* --- Validate fee rate floor --- */
    if ((uint64_t)fee_rate < FEE_FLOOR_SAT_PER_KVB) {
        fprintf(stderr, "ERROR: --fee-rate %d is below minimum %d sat/kvB (0.1 sat/vB)\n",
                fee_rate, FEE_FLOOR_SAT_PER_KVB);
        return 1;
    }
    if (fee_rate < 1000) {
        fprintf(stderr, "WARNING: fee rate %d sat/kvB (%.1f sat/vB) is below Bitcoin Core "
                "default minrelaytxfee (1 sat/vB).\n"
                "  Anchor outputs disabled at sub-1-sat/vB rates.\n",
                fee_rate, (double)fee_rate / 1000.0);
    }

    /* --- BOLT 12 Offer payment (early exit / decode + display) --- */
    if (pay_offer_str) {
        offer_t offer;
        if (!offer_decode(pay_offer_str, &offer)) {
            fprintf(stderr, "Error: failed to decode offer: %s\n", pay_offer_str);
            return 1;
        }
        printf("Decoded BOLT 12 offer:\n");
        /* Print node_id as hex */
        printf("  node_id: ");
        for (int k = 0; k < 33; k++) printf("%02x", offer.node_id[k]);
        printf("\n");
        printf("  amount_msat: %llu%s\n",
               (unsigned long long)offer.amount_msat,
               offer.has_amount ? "" : " (any)");
        printf("  description: %s\n", offer.description);
        printf("(Payment flow via channel not yet implemented)\n");
        return 0;
    }

    /* --- BIP39 Mnemonic (early exit) --- */
    if (generate_mnemonic || from_mnemonic) {
        if (!keyfile_path) {
            fprintf(stderr, "Error: --keyfile required for mnemonic operations\n");
            return 1;
        }
        unsigned char seed[64];
        if (generate_mnemonic) {
            char mnemonic[1024];
            if (!bip39_generate(24, mnemonic, sizeof(mnemonic))) {
                fprintf(stderr, "Error: failed to generate mnemonic\n");
                return 1;
            }
            printf("BIP39 Mnemonic (WRITE THIS DOWN!):\n\n  %s\n\n", mnemonic);
            if (!bip39_mnemonic_to_seed(mnemonic, mnemonic_passphrase, seed)) {
                fprintf(stderr, "Error: failed to derive seed\n");
                secure_zero(mnemonic, sizeof(mnemonic));
                return 1;
            }
            secure_zero(mnemonic, sizeof(mnemonic));
        } else {
            if (!bip39_validate(from_mnemonic)) {
                fprintf(stderr, "Error: invalid mnemonic (bad word or checksum)\n");
                return 1;
            }
            if (!bip39_mnemonic_to_seed(from_mnemonic, mnemonic_passphrase, seed)) {
                fprintf(stderr, "Error: failed to derive seed from mnemonic\n");
                return 1;
            }
        }
        unsigned char seckey[32];
        int ok = keyfile_generate_from_seed(keyfile_path, seckey, passphrase,
                                             seed, 64, NULL);
        secure_zero(seed, sizeof(seed));
        secure_zero(seckey, sizeof(seckey));
        printf("Keyfile %s: %s\n", keyfile_path, ok ? "OK" : "FAILED");
        return ok ? 0 : 1;
    }

    /* Mainnet safety guard: refuse unless explicitly acknowledged */
    if (strcmp(network, "mainnet") == 0 && !accept_risk) {
        fprintf(stderr,
            "Error: mainnet operation refused.\n"
            "SuperScalar is a PROTOTYPE. Running on mainnet risks loss of funds.\n"
            "If you understand this risk, pass --i-accept-the-risk\n");
        return 1;
    }

    /* Mainnet requires --db for revocation secret persistence */
    if (strcmp(network, "mainnet") == 0 && !db_path) {
        fprintf(stderr,
            "Error: mainnet requires --db for persistent state.\n"
            "Without a database, revocation secrets are lost on crash\n"
            "and breach penalties cannot be constructed.\n");
        return 1;
    }

    /* Tor SOCKS5 proxy setup */
    if (tor_proxy_arg) {
        char proxy_host[256];
        int proxy_port;
        if (!tor_parse_proxy_arg(tor_proxy_arg, proxy_host, sizeof(proxy_host),
                                  &proxy_port)) {
            fprintf(stderr, "Error: invalid --tor-proxy format (use HOST:PORT)\n");
            return 1;
        }
        wire_set_proxy(proxy_host, proxy_port);
        printf("Client: Tor SOCKS5 proxy set to %s:%d\n", proxy_host, proxy_port);
    }

    /* --tor-only mode */
    if (tor_only) {
        if (!tor_proxy_arg) {
            fprintf(stderr, "Error: --tor-only requires --tor-proxy\n");
            return 1;
        }
        wire_set_tor_only(1);
        printf("Client: Tor-only mode enabled (clearnet connections refused)\n");
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

    /* Bootstrap from well-known endpoint: overrides --host, --port, --lsp-pubkey */
    static char wk_host_buf[256];
    static char wk_pubkey_buf[128];
    if (lsp_domain) {
        uint16_t wk_port = 0;
        printf("Client: fetching /.well-known/lsps.json from %s ...\n",
               lsp_domain);
        if (!lsp_wellknown_fetch_http(lsp_domain,
                                      wk_host_buf, sizeof(wk_host_buf),
                                      &wk_port, wk_pubkey_buf,
                                      sizeof(wk_pubkey_buf))) {
            fprintf(stderr, "Client: failed to fetch well-known from %s\n",
                    lsp_domain);
            memset(seckey, 0, 32);
            report_close(&rpt);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        host = wk_host_buf;
        port = (int)wk_port;
        if (!lsp_pubkey_hex)
            lsp_pubkey_hex = wk_pubkey_buf;
        printf("Client: bootstrapped from %s -> %s:%d pubkey %s\n",
               lsp_domain, wk_host_buf, wk_port, wk_pubkey_buf);
    }

    /* NK authentication: pin LSP static pubkey if provided */
    if (lsp_pubkey_hex) {
        unsigned char pk_buf[33];
        if (hex_decode(lsp_pubkey_hex, pk_buf, 33) != 33) {
            fprintf(stderr, "Error: --lsp-pubkey must be 33-byte compressed pubkey hex\n");
            memset(seckey, 0, 32);
            report_close(&rpt);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        secp256k1_pubkey lsp_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &lsp_pk, pk_buf, 33)) {
            fprintf(stderr, "Error: invalid --lsp-pubkey\n");
            memset(seckey, 0, 32);
            report_close(&rpt);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        client_set_lsp_pubkey(&lsp_pk);
        printf("Client: NK authentication enabled (pinned LSP pubkey)\n");
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
        fprintf(stderr, "Client: regtest init failed (watchtower/RPC disabled)\n");

    /* Fee estimator — honour --fee-estimator if provided */
    static watchtower_t client_wt;
    static fee_estimator_static_t  client_fee_static;
    static fee_estimator_blocks_t  client_fee_blocks;
    static fee_estimator_api_t     client_fee_api;
    fee_estimator_t *client_fee_ptr;

    const char *fe_mode = fee_estimator_arg;
    if (!fe_mode) fe_mode = light_client_arg ? "blocks" : "static";

    if (strcmp(fe_mode, "blocks") == 0) {
        fee_estimator_blocks_init(&client_fee_blocks);
        client_fee_ptr = &client_fee_blocks.base;
    } else if (strcmp(fe_mode, "api") == 0) {
        fee_estimator_api_init(&client_fee_api, NULL, NULL, NULL);
        client_fee_ptr = &client_fee_api.base;
    } else if (strncmp(fe_mode, "api:", 4) == 0) {
        fee_estimator_api_init(&client_fee_api, fe_mode + 4, NULL, NULL);
        client_fee_ptr = &client_fee_api.base;
    } else {
        /* static or static:N */
        uint64_t r = (uint64_t)fee_rate;
        if (strncmp(fe_mode, "static:", 7) == 0)
            r = (uint64_t)strtoull(fe_mode + 7, NULL, 10) * 1000;
        fee_estimator_static_init(&client_fee_static, r);
        client_fee_ptr = &client_fee_static.base;
    }

    watchtower_init(&client_wt, 1, rt_ok ? &rt : NULL, client_fee_ptr,
                      use_db ? &db : NULL);

    /* Attach BIP 158 light client as chain backend (overrides regtest backend) */
    if (light_client_arg) {
        attach_light_client_client(&client_wt, use_db ? &db : NULL,
                                   light_client_arg, network,
                                   lc_fallbacks, n_lc_fallbacks);
        /* Wire blocks estimator into backend for per-block samples */
        if (strcmp(fe_mode, "blocks") == 0)
            bip158_backend_set_fee_estimator(&g_bip158_client, client_fee_ptr);
        /* Auto-attach HD wallet when running without bitcoind */
        if (!rt_ok)
            attach_hd_wallet_client(&client_wt, use_db ? &db : NULL, ctx, network,
                                    hd_mnemonic, hd_passphrase, hd_lookahead);
    }

    int ok;
    if (daemon_mode) {
        daemon_cb_data_t cbd;
        memset(&cbd, 0, sizeof(cbd));
        cbd.db = use_db ? &db : NULL;
        cbd.wt = &client_wt;
        cbd.fee = client_fee_ptr;
        cbd.rt = rt_ok ? &rt : NULL;
        cbd.auto_accept_jit = auto_accept_jit;
        cbd.test_lsps2     = test_lsps2;
        cbd.test_lsps2_buy = test_lsps2_buy;
        cbd.test_splice    = test_splice;

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

        /* If the DB already has a persisted factory from a previous run,
           skip the fresh HELLO handshake and go straight to reconnect. */
        int first_run = (use_db && persist_has_factory(&db, 0)) ? 0 : 1;

        /* Scan for breaches that may have occurred while we were offline.
           watchtower_init() loaded old commitments from DB — check if any
           are now confirmed on-chain (late-arrival breach detection). */
        if (!first_run && cbd.wt)
            watchtower_check(cbd.wt);

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
