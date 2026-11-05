#include "superscalar/version.h"
#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/channel.h"
#include "superscalar/factory.h"
#include "superscalar/report.h"
#include "superscalar/crash_inject.h"   /* #9 superscalar_set_cheat_gate() */
#include "superscalar/persist.h"
#include "superscalar/keyfile.h"
#include "superscalar/network.h"
#include "superscalar/adaptor.h"
#include "superscalar/regtest.h"
#include "superscalar/watchtower.h"
#include "superscalar/sweeper.h"
#include "superscalar/chain_backend_rpc.h"
#include "superscalar/fee.h"
#include "superscalar/cpfp.h"
#include "superscalar/jit_channel.h"
#include "superscalar/musig.h"
#include "superscalar/tor.h"
#include "superscalar/log.h"
#ifdef __linux__
#include <syslog.h>
#endif
#include "superscalar/bip39.h"
#include "superscalar/hd_key.h"
#include "superscalar/bip158_backend.h"
#include "superscalar/wallet_source_hd.h"
#include "superscalar/wallet_source.h"
#include "superscalar/splice.h"
#include "superscalar/lsp_wellknown.h"
#include "superscalar/factory_recovery.h"
#include "superscalar/client_dist.h"
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

/* --wallet: bitcoind wallet that funds CPFP children on exit.  Without it a
   pre-signed tx that needs a bump gets an anchor-only child. */
static const char *g_client_wallet_name = NULL;
static wallet_source_rpc_t g_client_cpfp_wallet;
static regtest_t g_client_cpfp_rt;

/* --fee-estimator and --fee-rate, read by the exit paths' CPFP target. */
static const char *g_client_fee_mode = NULL;
static uint64_t g_client_fee_rate = 1000;
static fee_estimator_rpc_t g_client_exit_fee_rpc;
static fee_estimator_static_t g_client_exit_fee_static;
static fee_estimator_api_t g_client_exit_fee_api;

/* Estimator whose urgent rate is the CPFP target of every pre-signed exit
   broadcast: --fee-estimator static[:N] or api[:URL] as given, otherwise
   bitcoind's estimatesmartfee (the blocks estimator has no samples on these
   paths).  NULL without bitcoind RPC. */
static fee_estimator_t *client_exit_fee_estimator(regtest_t *rt, const char **mode_out) {
    const char *m = g_client_fee_mode;
    if (m && strncmp(m, "static", 6) == 0) {
        uint64_t r = g_client_fee_rate;
        if (strncmp(m, "static:", 7) == 0) r = strtoull(m + 7, NULL, 10) * 1000;
        fee_estimator_static_init(&g_client_exit_fee_static, r);
        *mode_out = m;
        return &g_client_exit_fee_static.base;
    }
    if (m && strncmp(m, "api", 3) == 0) {
        fee_estimator_api_init(&g_client_exit_fee_api, m[3] == ':' ? m + 4 : NULL,
                               NULL, NULL);
        *mode_out = m;
        return &g_client_exit_fee_api.base;
    }
    if (!rt) { *mode_out = "none"; return NULL; }
    fee_estimator_rpc_init(&g_client_exit_fee_rpc, rt);
    *mode_out = "estimatesmartfee";
    return &g_client_exit_fee_rpc.base;
}

/* Route this process's pre-signed broadcasts through the CPFP path, on a copy
   of rt bound to --wallet (the caller's rt keeps its own wallet setting).  A
   pre-signed tx goes alone only when it pays the mempool minimum and the
   urgent fee estimate; otherwise it is packaged (or re-bumped) with a child. */
static int client_setup_cpfp(const regtest_t *rt) {
    wallet_source_t *w = NULL;
    fee_estimator_t *urgent = NULL;
    const char *mode = "none";
    if (rt && !cpfp_check_node_version((regtest_t *)rt)) return 0;
    if (rt) {
        g_client_cpfp_rt = *rt;
        if (g_client_wallet_name) {
            memset(g_client_cpfp_rt.wallet, 0, sizeof(g_client_cpfp_rt.wallet));
            strncpy(g_client_cpfp_rt.wallet, g_client_wallet_name,
                    sizeof(g_client_cpfp_rt.wallet) - 1);
            wallet_source_rpc_init(&g_client_cpfp_wallet, &g_client_cpfp_rt);
            w = &g_client_cpfp_wallet.base;
        }
        urgent = client_exit_fee_estimator(&g_client_cpfp_rt, &mode);
    }
    cpfp_set_default(rt ? &g_client_cpfp_rt : NULL, w, urgent, 0);
    /* the exit's deadline is the factory timeout, far ahead: no urgent rate */
    cpfp_set_default_target(FEE_TARGET_NORMAL);
    printf("Client: pre-signed broadcasts via %s (CPFP child funding: %s, "
           "target: 6-block estimate from %s)\n",
           rt ? "bitcoind RPC, package relay" : "chain backend",
           w ? g_client_wallet_name : "anchor only", mode);
    return 1;
}

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
            fprintf(stderr, "Client: HD wallet: invalid recovery phrase: %s\n",
                    bip39_status_str(bip39_check(hd_mnemonic)));
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

/* --- Funding output lookup over RPC ---
 * Chain source for client_check_factory_funding(): reports what bitcoind
 * knows about the output; the library decides.  ctx is a regtest_t* (same
 * RPC backend used for force-close and sweep). */
static int verify_funding_rpc(const unsigned char *txid32, uint32_t vout,
                                client_funding_output_t *out, void *ctx) {
    regtest_t *rt = (regtest_t *)ctx;
    if (!rt || !out) return 0;

    /* Convert internal-order txid to display hex */
    unsigned char disp[32];
    memcpy(disp, txid32, 32);
    extern void reverse_bytes(unsigned char *, size_t);
    reverse_bytes(disp, 32);
    char txid_hex[65];
    extern void hex_encode(const unsigned char *, size_t, char *);
    hex_encode(disp, 32, txid_hex);

    int confs = regtest_get_confirmations(rt, txid_hex);
    if (confs < 0) {
        fprintf(stderr, "verify_funding: TX %s not found on-chain\n", txid_hex);
        return 0;
    }
    /* regtest_get_tx_output tries getrawtransaction, then gettransaction
       (wallet-aware, no -txindex needed), then block-scan. */
    unsigned char spk[256];
    size_t spk_len = 0;
    uint64_t sats = 0;
    if (!regtest_get_tx_output(rt, txid_hex, vout, &sats, spk, &spk_len) ||
        spk_len > sizeof(out->spk)) {
        fprintf(stderr, "verify_funding: cannot query output %s:%u\n", txid_hex, vout);
        return 0;
    }
    out->amount_sats = sats;
    memcpy(out->spk, spk, spk_len);
    out->spk_len = spk_len;
    out->confirmations = confs;
    out->unspent = regtest_outpoint_unspent(rt, txid_hex, vout);
    return 1;
}

/* Regtest scaffolds may run without --rpcuser; there is then nothing to look
   the funding output up with, and the client says so and proceeds without
   the check.  Never reached on any other network. */
static void allow_unverified_funding_regtest(void) {
    fprintf(stderr, "Client: REGTEST without --rpcuser — funding outputs are NOT "
            "verified; THIS IS UNSAFE ON ANY PRODUCTION NETWORK.\n");
    client_set_allow_unverified_funding(1);
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

/* After client_handle_commitment_signed sends OUR revoke, the LSP replies with
   its OWN MSG_LSP_REVOKE_AND_ACK (0x50) to complete the bidirectional revocation
   (BOLT-2).  The scripted --send/--recv flows must consume + apply it after EVERY
   commitment, exactly like the daemon's client_recv_lsp_revocation — otherwise the
   stray 0x50 desyncs the next recv (sender "expected FULFILL", receiver a leftover
   commitment at close, and the LSP's handle_fulfill_htlc times out waiting for the
   REVOKE and returns 0 → "event loop failed").  Deterministic: the LSP sends
   exactly one revoke per commitment, so a single blocking recv is correct. */
static int scripted_consume_lsp_revoke(int fd, channel_t *ch, secp256k1_context *ctx) {
    wire_msg_t m;
    if (!wire_recv(fd, &m)) return 1;   /* nothing arrived to apply */
    int ok = 1;
    if (m.msg_type == MSG_LSP_REVOKE_AND_ACK && m.json) {
        /* Revocation-verification standard: the scripted --send/--recv flows must
           VERIFY the LSP's revocation exactly like the daemon path
           (client_recv_lsp_revocation) — not blindly store it. Route through the
           shared, tested, fail-closed handler: it checks secret*G == the LSP's
           committed point, stores ONLY on success, and tracks the next PCP (which
           this path previously discarded, so subsequent revokes were unverifiable). */
        if (!client_handle_lsp_revoke_and_ack(ch, ctx, &m)) {
            fprintf(stderr, "Client: SECURITY: LSP revocation FAILED verification "
                    "(commitment %llu) — refusing, NOT stored (no WT-arm)\n",
                    (unsigned long long)(ch->commitment_number ? ch->commitment_number - 1 : 0));
            ok = 0;
        }
    }
    if (m.json) cJSON_Delete(m.json);
    return ok;
}

/* Channel callback replicating multi_payment_client_cb from test harness */
static int standalone_channel_cb(int fd, channel_t *ch, uint32_t my_index,
                                   secp256k1_context *ctx,
                                   const secp256k1_keypair *keypair,
                                   factory_t *factory,
                                   size_t n_participants,
                                   void *user_data) {
    (void)keypair; (void)n_participants;
    multi_payment_data_t *data = (multi_payment_data_t *)user_data;

    /* A cooperative close of this factory was signed and may still be
       completed by the LSP: no payment is started or accepted any more.
       Returning hands over to the close ceremony, the only thing left that
       this client takes part in. */
    if (client_close_signed_for_factory(factory)) {
        fprintf(stderr, "Client %u: a cooperative close of this factory was "
                "signed earlier; the channel is frozen and no payment is "
                "run. Only a close or a unilateral exit (--force-close) can "
                "follow.\n", my_index);
        return 1;
    }

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
                scripted_consume_lsp_revoke(fd, ch, ctx);  /* LSP bidirectional revoke (verified) */
            } else {
                fprintf(stderr, "Client %u: expected COMMIT_SIGNED, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Wait for FULFILL_HTLC (the LSP's revoke was already drained above). */
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
                scripted_consume_lsp_revoke(fd, ch, ctx);  /* LSP bidirectional revoke (verified) */
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
                scripted_consume_lsp_revoke(fd, ch, ctx);  /* LSP bidirectional revoke (verified) */
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
                scripted_consume_lsp_revoke(fd, ch, ctx);  /* LSP bidirectional revoke (verified) */
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
    /* Deferred watchtower state for inbox-drain CS → async LSP revocation */
    uint64_t pending_wt_local;
    uint64_t pending_wt_remote;
    htlc_t pending_wt_htlcs[MAX_HTLCS];
    size_t pending_wt_n_htlcs;
    int pending_wt_valid;  /* 1 = pending old state needs watchtower registration */
    /* Client-side fee tracking for settlement verification.
       Tracks routing volume so the client can independently compute
       its expected profit share and detect under-settlement. */
    uint64_t tracked_routed_sats;   /* total sats routed (sent HTLCs) */
    uint64_t tracked_fees_sats;     /* estimated fees earned on this channel */
    uint64_t settled_fees_sats;     /* total share already received */
    uint64_t routing_fee_ppm;       /* fee rate from factory terms */
    uint16_t profit_share_bps;      /* client's share from factory terms */
    /* Scripted test payments (--send/--recv) routed through this same daemon
       loop instead of the old parallel standalone_channel_cb, which desynced on
       every message type it didn't hand-roll (LSP_REVOKE_AND_ACK,
       CREATE_INVOICE, CLOSE_PROPOSE). */
    scripted_action_t *scripted_actions;
    size_t  n_scripted_actions;
    int     scripted_initiated;     /* 1 after sends fired + recvs registered */
    /* Item-1 escalation: response policy + detection state (--on-lsp-forgery). */
    int     lsp_forgery_response;   /* lsp_forgery_response_t; default HALT */
    int     lsp_forgery_response_ps;/* per-leaf-type override for PS leaves; -1 = inherit (#21) */
    int     lsp_leaf_is_ps;         /* 1 if this factory uses PS (CLTV-gated) leaves (#21) */
    int     lsp_forgery_detected;   /* 1 once a forged LSP revocation is refused */
    int     force_close_requested;  /* 1 = CLOSE policy wants a force-close after the loop */
    int     wt_register_failed;     /* 1 once a revoked LSP commitment could not be watched */
    const char *poison_db_path;     /* db path for the poisoned-LSP sentinel file (#20) */
    /* Cooperative closes this client has signed for the current factory.
       Once client_close_state_frozen() says so the factory is frozen: the loop
       acts on nothing but a close proposal. */
    client_close_state_t close_state;
    /* 1 = a close ceremony ended without completing (see
       daemon_close_outcome): the process must not report success. */
    int     close_not_completed;
    /* 1 = a rotation stopped after the new factory was written to the
       database but before its channel and commitment 0 were: the database
       no longer matches a usable channel, so the client must not reconnect
       from it or report success. */
    int     rotation_not_completed;
    /* On-chain HTLC-success claims (we are payee). */
    sweeper_t *htlc_sweeper;
} daemon_cb_data_t;

/* Keep running the HTLC claims while any is pending: once the preimage is
   out, the HTLC is ours only if the claim confirms. */
static void client_wait_htlc_claims(sweeper_t *sw) {
    size_t n = client_run_htlc_claims(sw);
    if (n > 0)
        printf("Client: %zu HTLC claim(s) pending on chain; staying up until "
               "they settle\n", n);
    while (n > 0 && !g_shutdown) {
        sleep(10);
        n = client_run_htlc_claims(sw);
    }
}

/* SF-PTLC-TURNOVER-AUTH #196: rotation-context state for the PTLC turnover
   handler. The MSG_PTLC_PRESIG handler used to adapt the client identity
   seckey onto any LSP-supplied presig blindly, letting a malicious LSP
   extract the seckey via secp256k1_musig_extract_adaptor (scalar
   subtraction). We now require a precursor MSG_ROTATION_BEGIN carrying
   (dying_factory_txid, new_factory_nonce, rotation_epoch); the client
   recomputes the expected turnover_msg via wire_compute_turnover_msg()
   and refuses any presig whose turnover_msg does not match. The context
   is one-shot: cleared after a presig is consumed (success OR refusal)
   so a stale ROTATION_BEGIN cannot authorize a later presig. */
typedef struct {
    int           expecting;
    unsigned char dying_factory_txid[32];
    unsigned char new_factory_nonce[32];
    uint64_t      rotation_epoch;
    unsigned char expected_turnover_msg[32];
} client_rotation_ctx_t;

static client_rotation_ctx_t g_rotation_ctx;
static void rotation_ctx_clear(void);

static void rotation_ctx_set(const unsigned char *dying_txid,
                              const unsigned char *new_nonce,
                              uint64_t epoch) {
    if (!client_rotation_allowed()) {
        fprintf(stderr, "Client: REFUSING ROTATION_BEGIN — factory rotation is not "
                "enabled (--enable-rotation-experimental); the key turnover that "
                "follows will be refused\n");
        rotation_ctx_clear();
        return;
    }
    memcpy(g_rotation_ctx.dying_factory_txid, dying_txid, 32);
    memcpy(g_rotation_ctx.new_factory_nonce,  new_nonce,  32);
    g_rotation_ctx.rotation_epoch = epoch;
    wire_compute_turnover_msg(dying_txid, new_nonce, epoch,
                                g_rotation_ctx.expected_turnover_msg);
    g_rotation_ctx.expecting = 1;
}

static void rotation_ctx_clear(void) {
    memset(&g_rotation_ctx, 0, sizeof(g_rotation_ctx));
}

/* Returns 1 iff presig turnover_msg matches expected; 0 otherwise. */
static int rotation_ctx_check_presig(const unsigned char *received_turnover_msg) {
    if (!g_rotation_ctx.expecting) return 0;
    if (memcmp(received_turnover_msg,
               g_rotation_ctx.expected_turnover_msg, 32) != 0) return 0;
    return 1;
}

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
    /* SF-PTLC-TURNOVER-AUTH #196: refuse if no matching ROTATION_BEGIN. */
    if (!rotation_ctx_check_presig(turnover_msg)) {
        fprintf(stderr, "Client %u: REJECTED inline PTLC_PRESIG (no matching ROTATION_BEGIN; adversarial LSP suspected, #196)\n", my_index);
        rotation_ctx_clear();
        return;
    }
    rotation_ctx_clear();
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
        if (msg->msg_type == MSG_ROTATION_BEGIN) {
            /* SF-PTLC-TURNOVER-AUTH #196: record rotation context inline
               so an inline PTLC_PRESIG (mid-HTLC-flow) can validate. */
            unsigned char dt[32], nn[32];
            uint64_t ep = 0;
            if (wire_parse_rotation_begin(msg->json, dt, nn, &ep)) {
                rotation_ctx_set(dt, nn, ep);
                printf("Client %u: ROTATION_BEGIN accepted inline (epoch=%llu)\n",
                       my_index, (unsigned long long)ep);
            } else {
                fprintf(stderr, "Client %u: bad inline ROTATION_BEGIN\n", my_index);
            }
            cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;
        }
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

/* Persist the latest commitment TX signature to DB.
   Call after each client_handle_commitment_signed so the client can
   broadcast the commitment TX independently for trustless force-close. */
static int client_persist_commitment_sig(channel_t *ch, daemon_cb_data_t *cbd) {
    if (!cbd || !cbd->db) return 0;
    return client_persist_latest_commitment(cbd->db, 0, ch);
}

/* Receive and process LSP's own revocation (bidirectional revocation).
   Call after each client_handle_commitment_signed in daemon mode.
   old_local/old_remote are the channel amounts at the OLD commitment being
   revoked (before the state-advancing add/fulfill that preceded this). */
static void client_mark_lsp_poisoned(const char *db_path, const char *reason);  /* #20 fwd-decl */

/* Item-1 escalation: the LSP answered with a revocation that failed
   verification.  The bad secret was refused and no watchtower was armed from
   it; apply the configured response so the client does not keep building
   states it cannot protect against a proven-cheating LSP. */
static void client_on_lsp_revocation_forgery(daemon_cb_data_t *cbd,
                                             uint32_t my_index) {
    if (!cbd) return;
    cbd->lsp_forgery_detected = 1;
    /* #21 per-leaf-type: a PS (CLTV-gated) leaf MAY warrant a different
       response than a revocation-gated leaf. We default to UNIFORM (the PS
       override is "inherit" unless the operator explicitly set
       --on-lsp-forgery-ps) and NEVER auto-downgrade: PS leaf *chaining*
       does not by itself prove the channel-level revocation is non-load-
       bearing (open security-model question — see revocation doc §9). The
       leaf type is reported so the operator/auditor sees the severity. */
    int mode = cbd->lsp_forgery_response;
    if (cbd->lsp_leaf_is_ps && cbd->lsp_forgery_response_ps >= 0)
        mode = cbd->lsp_forgery_response_ps;
    fprintf(stderr, "Client %u: forgery on a %s leaf\n", my_index,
            cbd->lsp_leaf_is_ps ? "PS/CLTV-gated" : "revocation-gated");
    switch (mode) {
    case LSP_FORGERY_HALT:
        fprintf(stderr, "Client %u: CRITICAL: LSP revocation forgery — HALT "
                "policy: refusing all further commitments. Operator should "
                "force-close (--force-close) on the last verified state.\n",
                my_index);
        client_mark_lsp_poisoned(cbd->poison_db_path, "lsp revocation forgery (halt)");
        break;
    case LSP_FORGERY_CLOSE:
        fprintf(stderr, "Client %u: CRITICAL: LSP revocation forgery — CLOSE "
                "policy: force-closing on the last verified state.\n", my_index);
        cbd->force_close_requested = 1;
        client_mark_lsp_poisoned(cbd->poison_db_path, "lsp revocation forgery (close)");
        break;
    case LSP_FORGERY_CONTINUE:
    default:
        break;  /* legacy: refuse + no-arm, keep the session */
    }
    /* Collapse to the effective decision so the daemon-loop / reconnect
       break (which reads lsp_forgery_response) honours the PS override. */
    cbd->lsp_forgery_response = mode;
}

/* A verified LSP revocation could not be registered with the client
   watchtower (out of memory, or the DB write failed), so that revoked LSP
   commitment is not protected by this process.  Stop accepting commitments:
   each would add another state we cannot protect.  The watch's DB row is
   written before the in-memory insert, so a restart re-arms it when only the
   in-memory side failed. */
static void client_on_unwatched_revocation(daemon_cb_data_t *cbd,
                                           uint32_t my_index) {
    fprintf(stderr, "Client %u: CRITICAL: a revoked LSP commitment could not be "
            "registered with the watchtower; halting (restart to re-arm it "
            "from the DB)\n", my_index);
    if (cbd) cbd->wt_register_failed = 1;
}

/* Persist the LSP's per-commitment points (the handler set the next one in
   memory) and the client's own PCS, for crash recovery. */
static void client_persist_lsp_points(daemon_cb_data_t *cbd, channel_t *ch,
                                      secp256k1_context *ctx) {
    if (!cbd || !cbd->db || ch->commitment_number == 0) return;
    unsigned char ser[33];
    size_t slen;
    secp256k1_pubkey pcp;
    if (channel_get_remote_pcp(ch, ch->commitment_number + 1, &pcp)) {
        slen = 33;
        secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &pcp,
                                       SECP256K1_EC_COMPRESSED);
        persist_save_remote_pcp(cbd->db, 0, ch->commitment_number + 1, ser);
    }
    if (channel_get_remote_pcp(ch, ch->commitment_number, &pcp)) {
        slen = 33;
        secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &pcp,
                                       SECP256K1_EC_COMPRESSED);
        persist_save_remote_pcp(cbd->db, 0, ch->commitment_number, ser);
    }
    unsigned char pcs[32];
    if (channel_get_local_pcs(ch, ch->commitment_number, pcs))
        persist_save_local_pcs(cbd->db, 0, ch->commitment_number, pcs);
    if (channel_get_local_pcs(ch, ch->commitment_number + 1, pcs))
        persist_save_local_pcs(cbd->db, 0, ch->commitment_number + 1, pcs);
    memset(pcs, 0, 32);
}

/* Apply an LSP revocation through the shared library helper and act on the
   outcome.  Used by both daemon paths that receive MSG_LSP_REVOKE_AND_ACK. */
static void client_apply_lsp_revocation(channel_t *ch, daemon_cb_data_t *cbd,
                                        secp256k1_context *ctx,
                                        const wire_msg_t *msg,
                                        uint64_t old_local, uint64_t old_remote,
                                        const htlc_t *old_htlcs, size_t old_n_htlcs,
                                        uint32_t my_index) {
    /* Revocation-verification standard (client side): verify + retain the
       LSP's revocation and arm the client watchtower for the LSP commitment
       it revokes.  Fail-closed: a secret that does not match the LSP's
       committed point is never stored and never arms the watchtower (it
       would build a penalty that can't spend). */
    int rv = client_accept_lsp_revocation(ch, ctx, msg, cbd ? cbd->wt : NULL,
                                          old_local, old_remote,
                                          old_htlcs, old_n_htlcs);
    if (rv == CLIENT_LSP_REV_REJECTED) {
        fprintf(stderr, "Client %u: LSP revocation FAILED verification "
                "— refusing (penalty NOT armed)\n", my_index);
        client_on_lsp_revocation_forgery(cbd, my_index);
        return;
    }
    if (rv == CLIENT_LSP_REV_UNWATCHED)
        client_on_unwatched_revocation(cbd, my_index);
    client_persist_lsp_points(cbd, ch, ctx);
}

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
    client_apply_lsp_revocation(ch, cbd, ctx, &rev_msg, old_local, old_remote,
                                old_htlcs, old_n_htlcs, my_index);
    cJSON_Delete(rev_msg.json);
}

/* A rotation ended with the new factory recorded as pending but without a
   saved channel and commitment 0 for it.  Say what is and is not recoverable
   and make the process stop instead of reconnecting. */
static void rotation_pending_notice(persist_t *db) {
    char old_txid[65] = {0}, new_txid[65] = {0};
    uint32_t old_vout = 0, new_vout = 0, new_cltv = 0;
    persist_load_factory_outpoint(db, 0, old_txid, &old_vout, NULL);
    persist_load_factory_outpoint(db, CLIENT_ROTATION_PENDING_FACTORY_ID,
                                  new_txid, &new_vout, &new_cltv);
    fprintf(stderr,
            "  A rotation was started and did not finish.  The database holds\n"
            "    the factory being left   %s:%u  with this client's channel and commitment,\n"
            "    the factory being entered %s:%u  with its signed tree and distribution\n"
            "    transaction, and no commitment for a channel in it.\n"
            "  --force-close picks the exit that still exists: while the first funding\n"
            "  output is unspent it publishes that factory's tree and the commitment;\n"
            "  once something else has spent it, it publishes nothing of the new tree and\n"
            "  offers the new factory's distribution transaction (nLockTime %u).  Until then the\n"
            "  funds in the new factory move only with the LSP's cooperation.\n"
            "  The client does not connect while this record exists.\n",
            old_txid, old_vout, new_txid, new_vout, new_cltv);
}

static void rotation_stopped(daemon_cb_data_t *cbd, uint32_t my_index,
                              const factory_t *factory, const char *why) {
    (void)factory;
    fprintf(stderr, "Client %u: ROTATION NOT COMPLETED: %s.\n", my_index, why);
    if (cbd && cbd->db) rotation_pending_notice(cbd->db);
    if (cbd) cbd->rotation_not_completed = 1;
}

/* Daemon mode callback: select() loop handling incoming HTLCs and close */
/* A close ceremony ended without completing.  Record why, so that main()
   does not report a clean exit, and tell the operator what is left to do.
   Nothing is broadcast from here: a unilateral exit is the operator's call. */
static void daemon_close_outcome(daemon_cb_data_t *cbd, uint32_t my_index) {
    cbd->close_not_completed = 1;
    if (cbd->close_state.refused) {
        fprintf(stderr,
            "Client %u: COOPERATIVE CLOSE REFUSED. This client did not sign "
            "what the LSP proposed (reason above); its channel is unchanged. "
            "Unless the LSP proposes an acceptable close after a restart, "
            "the factory needs a unilateral exit: run this client with "
            "--force-close and the same --db to broadcast it.\n", my_index);
    } else if (cbd->close_state.signed_close) {
        fprintf(stderr,
            "Client %u: COOPERATIVE CLOSE NOT COMPLETED after this client "
            "signed it. The LSP may still broadcast that close (it pays this "
            "client %llu sats), so the channel is frozen. Restart to let the "
            "LSP propose the close again, or run with --force-close and the "
            "same --db to exit unilaterally.\n", my_index,
            (unsigned long long)cbd->close_state.paid_sats);
    } else if (cbd->close_state.record_error) {
        fprintf(stderr,
            "Client %u: COOPERATIVE CLOSE NOT COMPLETED. This client's record "
            "of signed closes cannot be read from its database, so it signed "
            "nothing and treats the channel as frozen. Repair the database "
            "and restart, or run with --force-close and the same --db to "
            "exit unilaterally.\n", my_index);
    } else {
        fprintf(stderr,
            "Client %u: COOPERATIVE CLOSE NOT COMPLETED. The ceremony failed "
            "before this client signed anything (reason above). The factory "
            "is still open and the channel is unchanged and still usable: "
            "restart this client to carry on or to let the LSP propose the "
            "close again.\n", my_index);
    }
}

/* This client's own chain tip height, 0 if no chain backend can tell. */
static uint32_t client_tool_chain_tip(void *ctx) {
    watchtower_t *wt = (watchtower_t *)ctx;
    if (!wt || !wt->chain || !wt->chain->get_block_height) return 0;
    int h = wt->chain->get_block_height(wt->chain);
    return h > 0 ? (uint32_t)h : 0;
}

/* The factory's distribution TX: broadcast by this client once it is due
   and the factory is still open.  Checked from the daemon loop and from the
   reconnect loop, so it does not depend on the LSP being reachable. */
static client_dist_watch_t g_dist_watch;

/* The distribution TX goes out through the CPFP path, like every pre-signed
   transaction of this client: alone when it pays the node's floor, else as a
   package with a child on its anchor. */
static int client_dist_send_cpfp(chain_backend_t *chain, const char *tx_hex,
                                  char *txid_out) {
    return cpfp_send_default(chain, tx_hex, txid_out) != CPFP_FAILED;
}

static client_dist_status_t client_dist_tick(persist_t *db, watchtower_t *wt,
                                             secp256k1_context *ctx) {
    if (!db || !wt || !wt->chain) return CLIENT_DIST_NONE;
    return client_dist_watch(&g_dist_watch, db, ctx, wt->chain, client_dist_send_cpfp,
                             10, stdout);
}

static void client_keep_funding_leaf(persist_t *db, const factory_t *factory,
                                     const channel_t *ch, uint32_t my_index);

static int daemon_channel_cb(int fd, channel_t *ch, uint32_t my_index,
                               secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               factory_t *factory,
                               size_t n_participants,
                               void *user_data) {
    daemon_cb_data_t *cbd = (daemon_cb_data_t *)user_data;

    if (cbd && cbd->htlc_sweeper) {
        /* Claims are keyed by the channel row (client index) so they can be
           rebuilt from the DB without this session. */
        client_set_htlc_live_channel(ch);
        client_set_htlc_sweeper(cbd->htlc_sweeper,
                                my_index > 0 ? my_index - 1 : 0);
    }

    /* #21: record whether this factory uses PS (CLTV-gated) leaves, for the
       per-leaf-type forgery response. Factory-level signal (any PS leaf present);
       cheap + idempotent. */
    if (cbd && factory) {
        for (size_t ni = 0; ni < factory->n_nodes; ni++)
            if (factory->nodes[ni].is_ps_leaf) { cbd->lsp_leaf_is_ps = 1; break; }
    }

    /* Save factory + channel + basepoints on first entry (Phase 16 persistence) */
    if (cbd && cbd->db && !cbd->saved_initial) {
        if (persist_begin(cbd->db)) {
            uint32_t client_idx = my_index - 1;
            /* Attach persistence so revocation secrets received later land in
               the revocation_secrets table (needed for standalone watchtower). */
            channel_set_persist(ch, cbd->db, client_idx);
            /* The signed commitment 0 received at channel open goes into the
               same transaction as the factory and channel rows: a channel is
               never on disk without a broadcastable commitment for it. */
            if (persist_save_factory(cbd->db, factory, ctx, 0) &&
                persist_save_channel(cbd->db, ch, 0, client_idx) &&
                persist_save_basepoints(cbd->db, client_idx, ch) &&
                persist_save_tree_nodes(cbd->db, factory, 0) &&
                client_persist_commitment_sig(ch, cbd)) {
                /* Save the verified signed distribution TX */
                if (factory->dist_tx_ready == 2 && factory->dist_unsigned_tx.len > 0) {
                    persist_save_distribution_tx(cbd->db, 0,
                        factory->dist_unsigned_tx.data,
                        factory->dist_unsigned_tx.len);
                }
                /* Save initial local PCS so they survive crash before first payment */
                for (uint64_t cn = 0; cn < ch->n_local_pcs; cn++) {
                    unsigned char pcs[32];
                    if (channel_get_local_pcs(ch, cn, pcs)) {
                        persist_save_local_pcs(cbd->db, 0, cn, pcs);
                        memset(pcs, 0, 32);
                    }
                }
                /* The LSP's per-commitment points for commitments 0 and 1,
                   received with its basepoints: a client that restarts
                   before its first payment needs them to verify the LSP's
                   revocation of commitment 0. */
                for (uint64_t cn = 0; cn <= 1; cn++) {
                    secp256k1_pubkey pcp;
                    unsigned char ser[33];
                    size_t slen = 33;
                    if (channel_get_remote_pcp(ch, cn, &pcp) &&
                        secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &pcp,
                                                      SECP256K1_EC_COMPRESSED))
                        persist_save_remote_pcp(cbd->db, 0, cn, ser);
                }
                if (!persist_commit(cbd->db)) {
                    fprintf(stderr, "Client %u: initial persist commit failed\n", my_index);
                    return 0;
                }
                cbd->saved_initial = 1;
                /* Extract fee terms for client-side settlement verification */
                if (factory && my_index >= 1 && my_index < FACTORY_MAX_SIGNERS) {
                    cbd->profit_share_bps = factory->profiles[my_index].profit_share_bps;
                    /* routing_fee_ppm was captured from SCID_ASSIGN */
                    extern uint32_t g_routing_fee_ppm;  /* defined in client.c */
                    cbd->routing_fee_ppm = g_routing_fee_ppm;
                }
                printf("Client %u: persisted factory + channel + basepoints"
                       " + initial commitment to DB\n", my_index);
            } else {
                /* Without a durable commitment the channel must not be used. */
                fprintf(stderr, "Client %u: initial persist failed, rolling back\n", my_index);
                persist_rollback(cbd->db);
                return 0;
            }
        } else {
            fprintf(stderr, "Client %u: persist_begin failed for initial save\n", my_index);
            return 0;
        }
    }

    /* Wire channel into client watchtower */
    if (cbd && cbd->wt) {
        /* watchtower_set_channel dropped in #208 A3.1b — penalty bytes
           are pre-built at revocation receive time. */

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

    /* Load what this client has already signed for this factory.  The same
       cbd is reused across reconnects and rotations, so this runs on every
       entry, against the factory now in use. */
    client_close_state_init(&cbd->close_state, cbd->db, factory);
    if (client_close_state_frozen(&cbd->close_state, factory)) {
        if (cbd->close_state.signed_close)
            fprintf(stderr, "Client %u: a cooperative close of this factory "
                    "was signed earlier (paying this client %llu sats) and "
                    "may still be completed by the LSP. The channel is "
                    "frozen: only a close paying at least that much will be "
                    "signed. Use --force-close to exit unilaterally.\n",
                    my_index,
                    (unsigned long long)cbd->close_state.paid_sats);
        else
            fprintf(stderr, "Client %u: this client's record of signed "
                    "closes CANNOT BE READ from its database, so it cannot "
                    "rule out that a close of this factory was signed. The "
                    "channel is treated as frozen until the record can be "
                    "read: no payment or state change is processed and no "
                    "close is signed. Repair the database, or use "
                    "--force-close to exit unilaterally.\n", my_index);
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

    /* Scripted test-payment kickoff (--send/--recv routed through this loop).
       Receivers register their preimage so the loop's auto-fulfill path settles
       the incoming HTLC from the invoice store; senders emit the initial
       ADD_HTLC and the loop reactively drives COMMITMENT_SIGNED + bidirectional
       revocation + FULFILL.  Fired once, here, immediately after CHANNEL_READY
       (the LSP --demo loop is already "waiting for payments" by this point —
       same timing the old standalone_channel_cb used successfully). */
    if (cbd && cbd->scripted_actions && !cbd->scripted_initiated &&
        !client_close_state_frozen(&cbd->close_state, factory)) {
        uint32_t sc_htlc_cltv = factory && factory->cltv_timeout > 40
                                ? factory->cltv_timeout - 40 : 500;
        for (size_t si = 0; si < cbd->n_scripted_actions; si++) {
            scripted_action_t *act = &cbd->scripted_actions[si];
            if (act->type == ACTION_RECV) {
                if (cbd->n_invoices < MAX_CLIENT_INVOICES) {
                    client_invoice_t *inv = &cbd->invoices[cbd->n_invoices++];
                    memcpy(inv->preimage, act->preimage, 32);
                    memcpy(inv->payment_hash, act->payment_hash, 32);
                    inv->amount_msat = act->amount_sats * 1000;
                    inv->active = 1;
                    if (cbd->db)
                        persist_save_client_invoice(cbd->db, inv->payment_hash,
                                                    inv->preimage, inv->amount_msat);
                    printf("Client %u: RECV armed (auto-fulfill preimage registered)\n",
                           my_index);
                }
            } else { /* ACTION_SEND */
                printf("Client %u: SEND %llu sats to client %u\n",
                       my_index, (unsigned long long)act->amount_sats,
                       act->dest_client);
                if (!client_send_payment(fd, ch, act->amount_sats,
                                          act->payment_hash, sc_htlc_cltv,
                                          act->dest_client))
                    fprintf(stderr, "Client %u: scripted send_payment failed\n",
                            my_index);
            }
        }
        cbd->scripted_initiated = 1;
    }

    while (!g_shutdown) {
        wire_msg_t msg;

        /* Item-1 escalation: if a forged LSP revocation was detected and the policy
           is HALT or CLOSE, stop here — refuse to accept any further commitment from
           a proven-cheating LSP. The bad secret was already refused at detection;
           this exits the message loop before the next commitment cycle. The actual
           force-close (CLOSE policy) runs after the loop, from the persisted state. */
        if (cbd && cbd->lsp_forgery_detected &&
            cbd->lsp_forgery_response != LSP_FORGERY_CONTINUE) {
            fprintf(stderr, "Client %u: halting daemon loop (LSP revocation forgery, "
                    "policy=%s)\n", my_index,
                    cbd->lsp_forgery_response == LSP_FORGERY_CLOSE ? "close" : "halt");
            break;
        }
        if (cbd && cbd->wt_register_failed) {
            fprintf(stderr, "Client %u: halting daemon loop (a revoked LSP "
                    "commitment could not be watched)\n", my_index);
            break;
        }

        /* Drain messages queued by recv_or_handle_ptlc before blocking.
           MSG_COMMITMENT_SIGNED is handled inline (needs immediate revocation
           exchange).  ALL other message types are re-dispatched through the
           main daemon switch via goto so nothing is silently dropped. */
        {
            wire_msg_t imsg;
            while (client_inbox_pop(&cbd->inbox, &imsg)) {
                if (imsg.msg_type == MSG_COMMITMENT_SIGNED &&
                    !client_close_state_frozen(&cbd->close_state, factory)) {
                    /* Save old state for deferred watchtower registration.
                       LSP revocation arrives later as MSG_LSP_REVOKE_AND_ACK. */
                    if (cbd->wt) {
                        cbd->pending_wt_local = ch->local_amount;
                        cbd->pending_wt_remote = ch->remote_amount;
                        cbd->pending_wt_n_htlcs = ch->n_htlcs;
                        if (ch->n_htlcs > 0)
                            memcpy(cbd->pending_wt_htlcs, ch->htlcs,
                                   ch->n_htlcs * sizeof(htlc_t));
                        cbd->pending_wt_valid = 1;
                    }
                    client_handle_commitment_signed(fd, ch, ctx, &imsg);
                    client_persist_commitment_sig(ch, cbd);
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

        if (ret == 0) {
            /* No socket data — run watchtower during idle time only.
               watchtower_check() spawns many bitcoin-cli subprocesses and
               can block for 10-60s on signet.  Running it BEFORE message
               dispatch caused CREATE_INVOICE timeouts (S14). */
            static time_t last_wt = 0;
            time_t tnow = time(NULL);
            if (last_wt == 0) last_wt = tnow;
            if (cbd && cbd->wt && (tnow - last_wt) >= 10) {
                last_wt = tnow;
                watchtower_check(cbd->wt);
                if (cbd->htlc_sweeper)
                    client_run_htlc_claims(cbd->htlc_sweeper);
            }
            if (cbd && cbd->db)
                client_dist_tick(cbd->db, cbd->wt, ctx);
            /* Periodic fee settlement verification: compare expected share
               (from tracked routing volume) to actual balance increase. */
            static time_t last_fee_check = 0;
            if (cbd && cbd->tracked_fees_sats > 0 && cbd->profit_share_bps > 0
                && (tnow - last_fee_check) >= 60) {
                last_fee_check = tnow;
                uint64_t expected = (cbd->tracked_fees_sats * cbd->profit_share_bps) / 10000;
                uint64_t received = cbd->settled_fees_sats;
                uint64_t owed = expected > received ? expected - received : 0;
                if (owed > 0) {
                    printf("Client %u: fee audit — routed %llu sats, "
                           "est. fees %llu, expected share %llu, "
                           "received %llu, owed %llu\n",
                           my_index,
                           (unsigned long long)cbd->tracked_routed_sats,
                           (unsigned long long)cbd->tracked_fees_sats,
                           (unsigned long long)expected,
                           (unsigned long long)received,
                           (unsigned long long)owed);
                }
            }
            continue;
        }

        if (!wire_recv(fd, &msg)) {
            fprintf(stderr, "Client %u: daemon recv failed (disconnected)\n", my_index);
            return 0;  /* signal disconnect — main() will retry */
        }

handle_message:
        /* A cooperative close of this factory was signed and may still be
           completed by the LSP, or the record that would say so cannot be
           read.  Nothing that changes the channel or the factory tree is
           acted on any more: only a close proposal (which the ceremony
           accepts if it pays at least as much, and does not sign while the
           record is unreadable), keepalives and the LSP's own revocations,
           which only add to what this client can prove.  Everything else is
           dropped unanswered.  The record is read again here while it is
           unreadable, so an error that passes lifts the freeze. */
        if (!client_close_frozen_allows_msg(msg.msg_type) &&
            client_close_state_frozen(&cbd->close_state, factory)) {
            if (cbd->close_state.signed_close)
                fprintf(stderr, "Client %u: ignoring message 0x%02x — a "
                        "cooperative close of this factory was already "
                        "signed; only a close or a unilateral exit "
                        "(--force-close) can follow\n", my_index,
                        msg.msg_type);
            else
                fprintf(stderr, "Client %u: ignoring message 0x%02x — this "
                        "client's record of signed closes cannot be read, "
                        "so the channel is treated as frozen\n", my_index,
                        msg.msg_type);
            if (msg.json) cJSON_Delete(msg.json);
            continue;
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

            /* Check if this is a settlement HTLC from the LSP */
            {
                cJSON *is_sett = cJSON_GetObjectItem(msg.json, "is_settlement");
                if (is_sett && cJSON_IsTrue(is_sett) && cbd) {
                    cJSON *sett_amt = cJSON_GetObjectItem(msg.json, "amount_msat");
                    cJSON *sett_fees = cJSON_GetObjectItem(msg.json, "accumulated_fees");
                    cJSON *sett_bps = cJSON_GetObjectItem(msg.json, "share_bps");
                    uint64_t offered_sats = sett_amt ? (uint64_t)(sett_amt->valuedouble / 1000) : 0;
                    uint64_t claimed_fees = sett_fees ? (uint64_t)sett_fees->valuedouble : 0;
                    uint16_t claimed_bps = sett_bps ? (uint16_t)sett_bps->valuedouble : 0;

                    /* Verify: offered amount == (claimed_fees * claimed_bps) / 10000 */
                    uint64_t expected = (claimed_fees * claimed_bps) / 10000;
                    if (offered_sats < expected) {
                        printf("Client %u: SETTLEMENT UNDERPAYMENT — offered %llu, "
                               "expected %llu (fees=%llu, bps=%u)\n",
                               my_index,
                               (unsigned long long)offered_sats,
                               (unsigned long long)expected,
                               (unsigned long long)claimed_fees, claimed_bps);
                    } else {
                        printf("Client %u: settlement received — %llu sats "
                               "(fees=%llu, bps=%u)\n",
                               my_index,
                               (unsigned long long)offered_sats,
                               (unsigned long long)claimed_fees, claimed_bps);
                    }
                    /* Cross-check against our own tracked fees */
                    if (cbd->tracked_fees_sats > 0) {
                        uint64_t our_expected = (cbd->tracked_fees_sats * cbd->profit_share_bps) / 10000;
                        if (offered_sats < our_expected && our_expected > 0) {
                            fprintf(stderr, "Client %u: WARNING — settlement %llu < "
                                    "independently tracked expected %llu\n",
                                    my_index,
                                    (unsigned long long)offered_sats,
                                    (unsigned long long)our_expected);
                        }
                    }
                    cbd->settled_fees_sats += offered_sats;
                    cbd->tracked_fees_sats = 0;  /* reset for next period */
                }
            }

            /* Extract settlement preimage for auto-fulfill after commitment */
            unsigned char sett_preimage[32];
            int is_settlement_htlc = 0;
            uint64_t sett_htlc_id = 0;
            {
                cJSON *is_sett2 = cJSON_GetObjectItem(msg.json, "is_settlement");
                cJSON *sett_pre = cJSON_GetObjectItem(msg.json, "settlement_preimage");
                cJSON *sett_id = cJSON_GetObjectItem(msg.json, "htlc_id");
                if (is_sett2 && cJSON_IsTrue(is_sett2) && sett_pre && cJSON_IsString(sett_pre)) {
                    if (hex_decode(sett_pre->valuestring, sett_preimage, 32) == 32) {
                        is_settlement_htlc = 1;
                        sett_htlc_id = sett_id ? (uint64_t)sett_id->valuedouble : 0;
                    }
                }
            }

            /* Track routing volume for fee verification.
               If this HTLC has dest_client (we're the sender), the LSP
               deducted a routing fee. Track so we can verify settlement. */
            {
                cJSON *amt_j = cJSON_GetObjectItem(msg.json, "amount_msat");
                cJSON *dest_j = cJSON_GetObjectItem(msg.json, "dest_client");
                if (dest_j && amt_j && cJSON_IsNumber(amt_j) && cbd) {
                    uint64_t htlc_msat = (uint64_t)amt_j->valuedouble;
                    uint64_t htlc_sats = htlc_msat / 1000;
                    cbd->tracked_routed_sats += htlc_sats;
                    if (cbd->routing_fee_ppm > 0) {
                        uint64_t fee_msat = (htlc_msat * cbd->routing_fee_ppm
                                              + 999999) / 1000000;
                        cbd->tracked_fees_sats += (fee_msat + 999) / 1000;
                    }
                }
            }
            /* ADV Phase 5a (defense-in-depth): for a RECEIVED payment HTLC (not a
               settlement, not us-as-sender), the payment_hash should match an
               invoice WE issued — otherwise we hold the preimage for nothing and
               cannot claim it (it simply times back to the LSP; no fund risk to
               us). Warn for observability; no refusal. */
            {
                cJSON *dest_j = cJSON_GetObjectItem(msg.json, "dest_client");
                cJSON *hash_j = cJSON_GetObjectItem(msg.json, "payment_hash");
                if (!dest_j && !is_settlement_htlc && hash_j && cJSON_IsString(hash_j) && cbd) {
                    unsigned char hh[32];
                    if (hex_decode(hash_j->valuestring, hh, 32) == 32) {
                        int known = 0;
                        for (size_t inv = 0; inv < cbd->n_invoices; inv++) {
                            if (cbd->invoices[inv].active &&
                                memcmp(cbd->invoices[inv].payment_hash, hh, 32) == 0) {
                                known = 1; break;
                            }
                        }
                        if (!known) {
                            fprintf(stderr, "Client %u: WARNING — received add_htlc "
                                    "payment_hash matches no invoice we issued; cannot "
                                    "claim it (will time back to the LSP)\n", my_index);
                        }
                    }
                }
            }
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
                client_persist_commitment_sig(ch, cbd);
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

            /* Auto-fulfill settlement HTLCs — preimage was included in the message */
            if (is_settlement_htlc) {
                printf("Client %u: auto-fulfilling settlement HTLC %llu\n",
                       my_index, (unsigned long long)sett_htlc_id);
                /* Save pre-fulfill state for watchtower */
                uint64_t pre_ful_local = ch->local_amount;
                uint64_t pre_ful_remote = ch->remote_amount;

                client_fulfill_payment(fd, ch, sett_htlc_id, sett_preimage);

                /* Handle COMMITMENT_SIGNED for the fulfill */
                if (recv_or_handle_ptlc(fd, &msg, 5, MSG_COMMITMENT_SIGNED,
                                         ctx, keypair, my_index, &cbd->inbox) &&
                    msg.msg_type == MSG_COMMITMENT_SIGNED) {
                    client_handle_commitment_signed(fd, ch, ctx, &msg);
                    client_persist_commitment_sig(ch, cbd);
                    cJSON_Delete(msg.json);
                    client_recv_lsp_revocation(fd, ch, cbd, ctx,
                        pre_ful_local, pre_ful_remote, NULL, 0,
                        keypair, my_index);
                } else {
                    if (msg.json) cJSON_Delete(msg.json);
                }
                if (cbd && cbd->db)
                    persist_update_channel_balance(cbd->db, my_index - 1,
                        ch->local_amount, ch->remote_amount, ch->commitment_number);
                memset(sett_preimage, 0, 32);
                break;
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
                        client_persist_commitment_sig(ch, cbd);
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
            client_persist_commitment_sig(ch, cbd);
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
                client_persist_commitment_sig(ch, cbd);
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

        case MSG_UPDATE_FAIL_HTLC: {
            /* The LSP gives an HTLC back.  One it never took is simply
               dropped.  One that was committed is failed and the commitment
               exchange follows, exactly as after a fulfil. */
            uint64_t pre_fail_local = ch->local_amount;
            uint64_t pre_fail_remote = ch->remote_amount;
            htlc_t pre_fail_htlcs[MAX_HTLCS];
            size_t pre_fail_n_htlcs = ch->n_htlcs;
            if (pre_fail_n_htlcs > 0)
                memcpy(pre_fail_htlcs, ch->htlcs, pre_fail_n_htlcs * sizeof(htlc_t));

            int fail_committed = 0;
            uint64_t fail_htlc_id = 0;
            int fail_ok = client_handle_fail_htlc(ch, &msg, &fail_committed,
                                                   &fail_htlc_id);
            cJSON_Delete(msg.json);
            if (fail_ok && fail_committed) {
                if (recv_or_handle_ptlc(fd, &msg, 5, MSG_COMMITMENT_SIGNED,
                                         ctx, keypair, my_index, &cbd->inbox) &&
                    msg.msg_type == MSG_COMMITMENT_SIGNED) {
                    client_handle_commitment_signed(fd, ch, ctx, &msg);
                    client_persist_commitment_sig(ch, cbd);
                    if (msg.json) cJSON_Delete(msg.json);
                    client_recv_lsp_revocation(fd, ch, cbd, ctx,
                        pre_fail_local, pre_fail_remote,
                        pre_fail_n_htlcs > 0 ? pre_fail_htlcs : NULL, pre_fail_n_htlcs,
                        keypair, my_index);
                } else {
                    if (msg.json) cJSON_Delete(msg.json);
                }
            }
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }
            break;
        }

        case MSG_LSP_REVOKE_AND_ACK: {
            /* LSP's own revocation, arriving naturally in the daemon loop.
               This happens when a queued CS was processed from the inbox:
               client_handle_commitment_signed sent RAA, LSP responded with this.
               Same fail-closed handling as client_recv_lsp_revocation (this
               path used to store the secret unchecked and arm the watchtower
               regardless). */
            int pend = cbd && cbd->pending_wt_valid;
            client_apply_lsp_revocation(ch, cbd, ctx, &msg,
                pend ? cbd->pending_wt_local : ch->local_amount,
                pend ? cbd->pending_wt_remote : ch->remote_amount,
                (pend && cbd->pending_wt_n_htlcs > 0) ? cbd->pending_wt_htlcs : NULL,
                pend ? cbd->pending_wt_n_htlcs : 0,
                my_index);
            if (cbd) cbd->pending_wt_valid = 0;
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_CLOSE_PROPOSE: {
            printf("Client %u: received CLOSE_PROPOSE in daemon mode\n", my_index);
            int close_ok = client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                      factory, n_participants, &msg,
                                      client_chain_tip(), ch,
                                      &cbd->close_state, 0);
            cJSON_Delete(msg.json);
            if (!close_ok && cbd->close_state.unverifiable &&
                !client_close_state_frozen(&cbd->close_state, factory)) {
                /* The client could not check the proposal (no chain tip).
                   It signed and recorded nothing, now or earlier, and told
                   the LSP to try again, so this is neither a close nor a
                   refusal: keep serving the channel.  If a close of this
                   factory is on record from before, or the record cannot be
                   read, the channel is frozen and this is a close that did
                   not complete, handled below. */
                fprintf(stderr,
                    "Client %u: cooperative close NOT signed: this client "
                    "could not verify the proposal (reason above) and asked "
                    "the LSP to try again. The channel is unchanged and still "
                    "usable; staying connected.\n", my_index);
                break;
            }
            if (!close_ok)
                daemon_close_outcome(cbd, my_index);
            return 2;  /* close already handled */
        }

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

        case MSG_ROTATION_BEGIN: {
            /* SF-PTLC-TURNOVER-AUTH #196: rotation context precursor.
               Records (dying_factory_txid, new_factory_nonce, rotation_epoch)
               so the next MSG_PTLC_PRESIG can be validated against it. */
            unsigned char dying_txid[32], new_nonce[32];
            uint64_t epoch = 0;
            if (!wire_parse_rotation_begin(msg.json, dying_txid, new_nonce, &epoch)) {
                fprintf(stderr, "Client %u: bad ROTATION_BEGIN\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);
            rotation_ctx_set(dying_txid, new_nonce, epoch);
            printf("Client %u: ROTATION_BEGIN accepted (epoch=%llu, dying_txid=%02x%02x%02x..)\n",
                   my_index, (unsigned long long)epoch,
                   dying_txid[0], dying_txid[1], dying_txid[2]);
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

            /* SF-PTLC-TURNOVER-AUTH #196: refuse if no matching ROTATION_BEGIN. */
            if (!rotation_ctx_check_presig(turnover_msg)) {
                fprintf(stderr, "Client %u: REJECTED PTLC_PRESIG (no matching ROTATION_BEGIN; adversarial LSP suspected, #196)\n", my_index);
                rotation_ctx_clear();
                break;
            }
            rotation_ctx_clear();

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
                /* Tell the LSP, so it does not wait out its timeout. */
                cJSON *reject = wire_build_jit_reject(jit_cidx, "not accepted");
                wire_send(fd, MSG_JIT_REJECT, reject);
                cJSON_Delete(reject);
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

            /* JIT channel watchtower registration: dropped in #208 A3.2.
               Penalty bytes pre-built at revocation receive time. */

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
            char mig_close_txid[65];
            if (!wire_parse_jit_migrate(msg.json, &mig_jit_id, &mig_factory_id,
                                          &mig_local, &mig_remote,
                                          mig_close_txid)) {
                fprintf(stderr, "Client %u: bad JIT_MIGRATE\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            printf("Client %u: JIT channel %08x migrating to factory %u\n",
                   my_index, mig_jit_id, mig_factory_id);

            if (cbd->jit_ch &&
                jit_client_handle_migrate(cbd->jit_ch, mig_jit_id,
                                           mig_close_txid, cbd->wt, cbd->db))
                printf("Client %u: JIT channel closed (migrated)\n", my_index);
            else
                printf("Client %u: JIT channel record kept "
                       "(close not seen confirmed)\n", my_index);
            break;
        }

        case MSG_FACTORY_PROPOSE: {
            /* LSP initiates factory rotation — create new factory */
            printf("Client %u: received FACTORY_PROPOSE (rotation)\n", my_index);

            /* Save pubkeys from current factory */
            secp256k1_pubkey saved_pubkeys[FACTORY_MAX_SIGNERS] = {0};
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
                if (client_rotation_new_factory_saved())
                    rotation_stopped(cbd, my_index, factory,
                                     "the channel in the new factory was not opened");
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
                        persist_save_basepoints(cbd->db, rot_client_idx, ch) &&
                        persist_save_tree_nodes(cbd->db, factory, 0) &&
                        client_persist_commitment_sig(ch, cbd) &&
                        persist_delete_factory_record(cbd->db,
                            CLIENT_ROTATION_PENDING_FACTORY_ID)) {
                        int rot_ok = 1;
                        /* Save the verified signed distribution TX */
                        if (factory->dist_tx_ready == 2 && factory->dist_unsigned_tx.len > 0)
                            rot_ok = persist_save_distribution_tx(cbd->db, 0,
                                factory->dist_unsigned_tx.data,
                                factory->dist_unsigned_tx.len);
                        /* Save initial PCS for the new rotated channel so they
                           survive crash before first payment on the new factory */
                        for (uint64_t cn = 0; rot_ok && cn < ch->n_local_pcs; cn++) {
                            unsigned char pcs[32];
                            if (channel_get_local_pcs(ch, cn, pcs)) {
                                rot_ok = persist_save_local_pcs(cbd->db, 0, cn, pcs);
                                memset(pcs, 0, 32);
                            }
                        }
                        /* Save remote PCPs (LSP's per-commitment points) */
                        for (uint64_t cn = 0; rot_ok && cn <= ch->commitment_number + 1; cn++) {
                            secp256k1_pubkey pcp;
                            unsigned char ser[33];
                            size_t slen = 33;
                            rot_ok = channel_get_remote_pcp(ch, cn, &pcp) &&
                                     secp256k1_ec_pubkey_serialize(ctx, ser, &slen,
                                         &pcp, SECP256K1_EC_COMPRESSED) &&
                                     persist_save_remote_pcp(cbd->db, 0, cn, ser);
                        }
                        if (!rot_ok) {
                            persist_rollback(cbd->db);
                            rotation_stopped(cbd, my_index, factory,
                                             "the new channel and its commitment could not be saved");
                            return 0;
                        }
                        if (!persist_commit(cbd->db)) {
                            rotation_stopped(cbd, my_index, factory,
                                             "the new channel and its commitment could not be saved");
                            return 0;
                        }
                        printf("Client %u: persisted rotated factory + channel + basepoints + PCS\n", my_index);
                    } else {
                        persist_rollback(cbd->db);
                        rotation_stopped(cbd, my_index, factory,
                                         "the new channel and its commitment could not be saved");
                        return 0;
                    }
                } else {
                    rotation_stopped(cbd, my_index, factory,
                                     "the new channel and its commitment could not be saved");
                    return 0;
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
            /* The advance replaces the leaf in the tree, but this channel and
               its commitments stay on the current leaf's output: keep that
               transaction so a unilateral exit can still publish it. */
            if (cbd && cbd->db)
                client_keep_funding_leaf(cbd->db, factory, ch, my_index);
            /* CL1.G: delegate to client_handle_leaf_advance in src/client.c
               which includes the wire-ceremony poison TX MuSig round and the
               cl7_cheat_tx adversarial-client cheat hook. Was: inline state-only
               handler that explicitly passed NULL for poison data (TODO admitted
               the leaf WT registration gap). Now matches REALLOC + STATE_ADVANCE
               pattern. */
            wire_msg_t propose_msg = { .msg_type = msg.msg_type, .json = msg.json };
            if (!client_handle_leaf_advance(fd, ctx, keypair, factory,
                                              my_index, &propose_msg)) {
                fprintf(stderr, "Client %u: leaf advance failed\n", my_index);
            } else if (cbd && cbd->db &&
                       !persist_save_tree_nodes(cbd->db, factory, 0)) {
                /* The ceremony completed (it ends with the LSP's DONE), so
                   the tree in memory is the advanced one this client signed:
                   persist it so a crash recovers the current leaf state. */
                fprintf(stderr, "Client %u: WARN — tree_nodes re-persist after "
                        "leaf advance failed\n", my_index);
            }
            cJSON_Delete(msg.json);
            break;
        }


        case MSG_LEAF_ADVANCE_DONE: {
            /* LSP confirms leaf advance — the signed tx is now finalized.
               Client's factory already has the correct unsigned tx from PROPOSE. */
            int leaf_side;
            if (wire_parse_leaf_advance_done(msg.json, &leaf_side)) {
                /* A DONE seen here is the LSP's broadcast for a leaf whose
                   ceremony this client took no part in (another client's
                   leaf, or one it refused).  Nothing was accepted, so
                   nothing is persisted; an advance this client signed is
                   persisted where its ceremony completes, above. */
                printf("Client %u: LSP reports leaf %d advanced\n",
                       my_index, leaf_side);
            }
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_LEAF_REALLOC_PROPOSE: {
            /* LSP proposes a leaf reallocation.  The client refuses every
               one (see client_handle_leaf_realloc): it answers with an error
               and its leaf and channel are unchanged, so the loop goes on. */
            wire_msg_t propose_msg = { .msg_type = msg.msg_type, .json = msg.json };
            client_handle_leaf_realloc(fd, ctx, keypair, factory,
                                        my_index, &propose_msg);
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_STATE_ADV_PROPOSE_INTENT:  /* stateless Tier B (#333): client_handle_state_advance dispatches by opcode */
        case MSG_STATE_ADVANCE_PROPOSE: {
            /* Tier B (Gap B + F): LSP detected per-leaf DW counter rollover
               and is driving the whole-tree re-sign ceremony.  Delegate to
               the canonical handler in src/client.c; it bundles per-node
               nonces and partial sigs across MSG_PATH_*. */
            wire_msg_t propose_msg = { .msg_type = msg.msg_type, .json = msg.json };
            if (!client_handle_state_advance(fd, ctx, keypair, factory,
                                              my_index, &propose_msg)) {
                fprintf(stderr, "Client %u: state advance failed\n", my_index);
            }
            cJSON_Delete(msg.json);
            break;
        }

        case MSG_SUBFACTORY_PROPOSE_INTENT:  /* stateless sub-factory (#271/#142): client_handle_subfactory_advance dispatches by opcode */
        case MSG_SUBFACTORY_PROPOSE: {
            /* Phase 2c (Gap E followup): LSP "selling sales-stock" to a
               client.  Delegate to client_handle_subfactory_advance;
               handles MSG_SUBFACTORY_NONCE → ALL_NONCES → PSIG → DONE
               internally for one sub-factory's k+1 signers (LSP + k
               clients in this sub-factory). */
            wire_msg_t propose_msg = { .msg_type = msg.msg_type, .json = msg.json };
            if (!client_handle_subfactory_advance(fd, ctx, keypair, factory,
                                                    my_index, &propose_msg)) {
                fprintf(stderr, "Client %u: sub-factory advance failed\n", my_index);
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

                /* If buy test requested, send lsps2.buy using the returned fee
                   params (none if get_info was refused: the purchase must
                   then be refused as well, which the test observes). */
                if (cbd->test_lsps2_buy && !cbd->test_lsps2_buy_done) {
                    cJSON *buy_req = cJSON_CreateObject();
                    if (buy_req) {
                        cJSON_AddStringToObject(buy_req, "jsonrpc", "2.0");
                        cJSON_AddNumberToObject(buy_req, "id", 2);
                        cJSON_AddStringToObject(buy_req, "method", "lsps2.buy");
                        cJSON *params = cJSON_CreateObject();
                        if (params) {
                            /* opening_fee_params: forward the params object from get_info */
                            cJSON *fee_params = cJSON_CreateObject();
                            cJSON *min_fee = result
                                ? cJSON_GetObjectItem(result, "min_fee_msat") : NULL;
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
            /* Async / unsolicited LSP notifications (MSG_FUNDING_REORG,
               MSG_CEREMONY_ABORT) can arrive here in daemon mode.  Route them
               through the shared handler so we mirror the freeze state / log the
               advisory instead of treating them as "unexpected", desyncing, and
               livelocking on reconnect (the inbound-bridge-payment bug). */
            if (client_handle_async_msg(&msg)) {
                cJSON_Delete(msg.json);
                break;
            }
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
        "  --fee-estimator MODE              static[:N sat/vB] | api[:URL] | blocks (default: static at\n"
        "                                      --fee-rate).  Its urgent rate is also the CPFP target of\n"
        "                                      exit broadcasts (default there: estimatesmartfee)\n"
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
        "  --min-profit-bps N                Refuse factory if profit share < N bps (default: 0 = accept any)\n"
        "  --expect-capacity SATS            Refuse factory unless this member's channel is exactly SATS\n"
        "  --min-capacity SATS               Refuse factory if this member's channel is below SATS\n"
        "  --max-lsp-balance-pct N           Refuse factory if the LSP opens with more than N%% of a channel\n"
        "  --lsp-pubkey HEX                  LSP static pubkey (33-byte hex) for NK authentication\n"
        "  --lsp DOMAIN                      Look up the LSP host and port at http://DOMAIN/.well-known/lsps.json.\n"
        "                                    The key served there is not trusted: --lsp-pubkey is still required\n"
        "                                    (outside regtest) and must match it.  The lookup is a direct HTTP\n"
        "                                    connection: refused together with --tor-proxy / --tor-only.\n"
        "  --tor-proxy HOST:PORT             SOCKS5 proxy for Tor (default: 127.0.0.1:9050)\n"
        "  --generate-mnemonic               Generate 24-word BIP39 mnemonic, derive key, save to --keyfile, then exit\n"
        "  --from-mnemonic WORDS             Restore key from BIP39 mnemonic, save to --keyfile, then exit\n"
        "  --mnemonic-passphrase P           BIP39 passphrase for seed derivation (default: empty)\n"
        "  --force-close                     Unilateral exit from --db without the LSP: publish the tree path\n"
        "                                    to this client's leaf, then its commitment. One pass per run;\n"
        "                                    exit status 0 = commitment accepted, 2 = run again after the next\n"
        "                                    block, 3 = refused for a reason waiting will not cure (needs the\n"
        "                                    operator), 1 = the exit cannot be completed from this DB, or\n"
        "                                    it needs a fee-paying child and has no wallet coin (--wallet)\n"
        "  --wallet NAME                     bitcoind wallet that funds CPFP children on exit\n"
        "                                      (default: none; a bump spends the P2A anchor alone; an exit\n"
        "                                      that needs a fee-paying child and has no coin exits 1)\n"
        "  --max-tree-fee-rate N             Refuse a factory whose pre-signed rate exceeds N sat/kvB\n"
        "                                      (default 10000 = 10 sat/vB; 0 = no ceiling)\n"        "  --on-lsp-forgery MODE             Response to a detected forged LSP revocation:\n"
        "                                      continue = refuse secret only (legacy)\n"
        "                                      halt     = refuse + stop session + alert (default)\n"
        "                                      close    = refuse + force-close on last verified state\n"
        "  --on-lsp-forgery-ps MODE          Override the above for PS (CLTV-gated) leaves\n"
        "                                      (default: inherit --on-lsp-forgery; no auto-downgrade)\n"
        "  --sweep-to-local                  Sweep to_local output after CSV maturity\n"
        "  --funding-confs N                 Confirmations a factory's funding output needs before the\n"
        "                                    client accepts the factory (default: regtest 1, signet,\n"
        "                                    testnet and testnet4 3, mainnet 6; the LSP's default too)\n"
        "  --enable-rotation-experimental    UNSAFE, testing only: take part in factory rotation\n"
        "                                    (refused on mainnet). Off by default: the client refuses\n"
        "                                    the key turnover and rotation proposals.\n"
        "  --test-allow-tree-advance         Harness only (refused on mainnet): co-sign leaf, state and\n"
        "                                    sub-factory advances, which are otherwise refused because\n"
        "                                    they do not move the channel onto the new tree\n"
        "  --sweep-dest HEX                  Destination xonly pubkey (64 hex) or P2TR SPK (68 hex)\n"
        "  --config PATH                     Load settings from JSON config file (CLI overrides)\n"
        "  --i-accept-the-risk               Allow mainnet operation (PROTOTYPE — funds at risk!)\n"
        "  --version                         Show version and exit\n"
        "  --help                            Show this help\n",
        prog);
}

/* Result of one unilateral-exit pass. Also the --force-close exit status. */
#define CLIENT_EXIT_PUBLISHED   0   /* the commitment is in the mempool or a block */
#define CLIENT_EXIT_FAILED      1   /* the exit cannot be completed from this DB */
#define CLIENT_EXIT_IN_PROGRESS 2   /* run again after the next block */
#define CLIENT_EXIT_STUCK       3   /* refused for a reason waiting will not
                                       cure: needs the operator */

/* The channel's latest signed commitment TX, whatever its size (caller frees). */
static unsigned char *exit_load_commitment(persist_t *db, size_t *len_out,
                                           uint64_t *cn_out) {
    size_t len = 0, got = 0;
    if (!persist_load_commitment_sig(db, 0, cn_out, NULL, NULL, &len, 0) || len == 0)
        return NULL;
    unsigned char *buf = malloc(len);
    if (!buf) return NULL;
    if (!persist_load_commitment_sig(db, 0, cn_out, NULL, buf, &got, len) ||
        got != len) {
        free(buf);
        return NULL;
    }
    *len_out = len;
    return buf;
}

/* Keep the signed leaf transaction that funds ch, in client_funding_leaf, so
   it survives an advance that replaces it in tree_nodes. */
static void client_keep_funding_leaf(persist_t *db, const factory_t *factory,
                                     const channel_t *ch, uint32_t my_index) {
    if (!db || !factory || !ch || my_index < 1) return;
    size_t node_idx;
    uint32_t vout;
    if (!factory_client_to_leaf(factory, (size_t)(my_index - 1), &node_idx, &vout))
        return;
    const factory_node_t *node = &factory->nodes[node_idx];
    if (!node->is_signed || node->signed_tx.len == 0) return;
    if (memcmp(node->txid, ch->funding_txid, 32) != 0) return;
    char txid_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(txid_hex + 2 * i, 3, "%02x", node->txid[31 - i]);
    if (persist_save_funding_leaf(db, 0, (uint32_t)node_idx, txid_hex,
                                  node->signed_tx.data, node->signed_tx.len))
        printf("Client %u: kept leaf %.16s... (node %zu) that funds this "
               "channel\n", my_index, txid_hex, node_idx);
    else
        fprintf(stderr, "Client %u: ERROR: could not keep leaf %.16s... that "
                "funds this channel; a unilateral exit after the advance "
                "will fail\n", my_index, txid_hex);
}

/* Broadcast the stored distribution TX of factory_id (the nLockTime
   fallback), through the CPFP path; says when it is not yet final. */
static void client_send_distribution_tx(persist_t *db, chain_backend_t *chain,
                                        uint32_t factory_id) {
    size_t dist_len = 0;
    unsigned char *dist_tx = NULL;
    if (persist_load_distribution_tx(db, factory_id, NULL, &dist_len, 0) &&
        dist_len > 0 && (dist_tx = malloc(dist_len)) != NULL) {
        size_t got = 0;
        char *tx_hex = malloc(dist_len * 2 + 1);
        if (tx_hex &&
            persist_load_distribution_tx(db, factory_id, dist_tx, &got, dist_len) &&
            got == dist_len) {
            hex_encode(dist_tx, dist_len, tx_hex);
            char dist_txid[65];
            uint32_t lock = dist_len < 4 ? 0 :
                            ((uint32_t)dist_tx[dist_len - 4] |
                             ((uint32_t)dist_tx[dist_len - 3] << 8) |
                             ((uint32_t)dist_tx[dist_len - 2] << 16) |
                             ((uint32_t)dist_tx[dist_len - 1] << 24));
            int height = chain->get_block_height ? chain->get_block_height(chain) : -1;
            if (height >= 0 && (uint32_t)height < lock)
                printf("Force-close: distribution TX not yet mature "
                       "(nLockTime %u, height %d)\n", lock, height);
            else if (cpfp_send_default(chain, tx_hex, dist_txid) != CPFP_FAILED)
                printf("Force-close: distribution TX broadcast: %s\n",
                       dist_txid);
            else
                printf("Force-close: distribution TX not accepted\n");
        }
        free(tx_hex);
        free(dist_tx);
    } else {
        printf("Force-close: no distribution TX in DB\n");
    }
}

/* One pass of this client's unilateral exit from its own DB.  Once the
   factory's distribution TX is due (its nLockTime reached, the funding output
   known unspent) or already published, it is the exit: the tree would spend
   the funding output and make it invalid, so nothing of the tree is
   published and the pass returns CLIENT_EXIT_PUBLISHED when the TX is in the
   mempool or a block, CLIENT_EXIT_STUCK when the node refuses it.  Otherwise
   it publishes the tree transactions on the path from the factory root to
   this client's leaf, then the client's signed commitment. Tree levels
   mature one relative timelock at a time, so the caller repeats the pass
   after new blocks until it returns CLIENT_EXIT_PUBLISHED: the commitment
   has been accepted, which a node only does once the whole path below it is
   in the mempool or a block. */
static int client_exit_pass(persist_t *db, chain_backend_t *chain) {
    extern void hex_encode(const unsigned char *, size_t, char *);
    int state;
    cpfp_need_clear();

    client_dist_status_t dist_status = CLIENT_DIST_NONE;
    if (client_dist_force_close(db, chain, client_dist_send_cpfp, stdout, &dist_status)) {
        /* Below the node's floor the distribution TX goes in only as a
           package with a fee-paying child: without a coin for it no further
           pass helps. */
        if (cpfp_need_seen() != CPFP_NEED_NONE) {
            fprintf(stderr, "Force-close: ERROR: the distribution TX needs a "
                    "fee-paying child: %s\n", cpfp_need_text(cpfp_need_seen()));
            return CLIENT_EXIT_FAILED;
        }
        return dist_status == CLIENT_DIST_REFUSED ? CLIENT_EXIT_STUCK
                                                  : CLIENT_EXIT_PUBLISHED;
    }

    /* The exit path ends at the tree node that funds this client's channel.
       A DB that does not name it gets the whole tree published instead. */
    char leaf_txid[65] = {0};
    int have_leaf = (factory_recovery_client_leaf(db, 0, leaf_txid) == 1);
    if (!have_leaf)
        printf("Force-close: DB does not name this client's channel funding "
               "output; publishing the whole factory tree\n");

    char fr_status[512] = {0};
    factory_recovery_result_t fr;
    int ran = factory_recovery_run(db, chain, 0, have_leaf ? leaf_txid : NULL,
                                   &fr, fr_status, sizeof(fr_status));
    printf("Force-close: %s (run=%d)\n", fr_status, ran);
    if (!ran) {
        fprintf(stderr, "Force-close: ERROR: the exit path cannot be "
                "published: %s\n", fr_status);
        state = CLIENT_EXIT_FAILED;
    } else if (!fr.published) {
        printf("Force-close: exit path not fully published: %d of %d "
               "transactions out, node %d is next (%d waiting for a parent "
               "confirmation or a timelock, %d rejected)\n",
               fr.n_confirmed + fr.n_in_mempool, fr.n_target,
               fr.first_unpublished, fr.n_waiting, fr.n_rejected);
        if (fr.n_rejected) {
            fprintf(stderr, "Force-close: STUCK: exit-path node %d: %s\n",
                    fr.reject_node, fr.reject_why);
            state = CLIENT_EXIT_STUCK;
        } else {
            state = CLIENT_EXIT_IN_PROGRESS;
        }
    } else {
        state = CLIENT_EXIT_PUBLISHED;
    }

    /* The signed commitment TX spends the leaf: it pays this client's balance.
       It is offered on every pass, whatever this node can still see of the
       tree: once a node accepts it, its leaf and everything above are out. */
    size_t commit_len = 0;
    uint64_t sig_cn = 0;
    unsigned char *commit_tx = exit_load_commitment(db, &commit_len, &sig_cn);
    factory_recovery_tx_info_t ci;
    if (!commit_tx || !factory_recovery_tx_info(commit_tx, commit_len, &ci)) {
        printf("Force-close: no signed commitment TX in DB\n");
        fprintf(stderr, "Force-close: ERROR: without a signed commitment "
                "this DB cannot claim the channel balance\n");
        state = CLIENT_EXIT_FAILED;
    } else {
        char *tx_hex = malloc(commit_len * 2 + 1);
        char sent_txid[65] = {0};
        int commit_out = 0;
        const char *stuck_why = NULL;
        if (tx_hex) {
            hex_encode(commit_tx, commit_len, tx_hex);
            /* through the CPFP path: alone when it pays the node's floor,
               else as a package with a child on its anchor.  With HTLC/PTLC
               outputs the exit races their deadlines: urgent rate. */
            cpfp_tx_info_t cti;
            fee_target_t ctarget = cpfp_parse_tx(commit_tx, commit_len, &cti)
                                   ? cpfp_commitment_exit_target(&cti)
                                   : FEE_TARGET_URGENT;
            cpfp_set_default_target(ctarget);
            if (ctarget == FEE_TARGET_URGENT)
                printf("Force-close: commitment carries HTLC/PTLC outputs: "
                       "urgent fee target\n");
            int csent = cpfp_send_default(chain, tx_hex, sent_txid) != CPFP_FAILED;
            cpfp_set_default_target(FEE_TARGET_NORMAL);
            if (csent) {
                printf("Force-close: commitment TX broadcast: %s (cn=%llu)\n",
                       sent_txid, (unsigned long long)sig_cn);
                commit_out = 1;
            } else if (chain->get_confirmations(chain, ci.txid) >= 0) {
                commit_out = 1;
            } else if (chain->is_outpoint_unspent) {
                /* A backend without a transaction index stops seeing a
                   transaction some blocks after it confirmed; an unspent
                   output of it is still in the UTXO set. */
                for (size_t v = 0; v < ci.n_outputs && !commit_out; v++)
                    if (chain->is_outpoint_unspent(chain, ci.txid,
                                                   (uint32_t)v) == 1)
                        commit_out = 1;
                if (!commit_out &&
                    chain->get_confirmations(chain, ci.prev_txid) >= 1) {
                    int in = chain->is_outpoint_unspent(chain, ci.prev_txid,
                                                        ci.prev_vout);
                    int height = chain->get_block_height(chain);
                    int locked = ci.locktime > 0 && ci.locktime < 500000000u &&
                                 height >= 0 && (uint32_t)height < ci.locktime;
                    if (in == 0)
                        stuck_why = "the leaf output it spends is already "
                                    "spent by another transaction (or this "
                                    "commitment and every output of it are "
                                    "already spent)";
                    else if (in == 1 && !locked)
                        stuck_why = "it was refused although the leaf output "
                                    "it spends is unspent and confirmed (fee "
                                    "below the node's floor, or policy)";
                }
            }
            if (commit_out && !sent_txid[0])
                printf("Force-close: commitment TX already published: %s "
                       "(cn=%llu)\n", ci.txid, (unsigned long long)sig_cn);
            else if (!commit_out)
                printf("Force-close: commitment TX broadcast failed "
                       "(may need tree to confirm first)\n");
            free(tx_hex);
        }
        if (commit_out) {
            state = CLIENT_EXIT_PUBLISHED;
        } else if (stuck_why) {
            fprintf(stderr, "Force-close: STUCK: commitment %s: %s\n",
                    ci.txid, stuck_why);
            if (state != CLIENT_EXIT_FAILED) state = CLIENT_EXIT_STUCK;
        } else if (state == CLIENT_EXIT_PUBLISHED) {
            state = CLIENT_EXIT_IN_PROGRESS;
        }
    }
    free(commit_tx);
    /* A pre-signed tx the node takes only with a fee-paying child, and no
       child could be funded: no further pass helps, the operator must give
       the exit an on-chain coin (--wallet) or a package-relay backend. */
    if (cpfp_need_seen() != CPFP_NEED_NONE) {
        fprintf(stderr, "Force-close: ERROR: a pre-signed transaction needs a "
                "fee-paying child: %s\n", cpfp_need_text(cpfp_need_seen()));
        state = CLIENT_EXIT_FAILED;
    }
    return state;
}

/* Item-1 CLOSE policy: force-close on the last fully-verified state, reusing the
   #313 self-custody recovery path from the client's persisted DB. Called after the
   daemon loop exits on a detected LSP revocation forgery. Returns 1 if a recovery
   run was executed, 0 if it could not (no DB / no chain backend). */
static int client_force_close_from_db(const char *db_path, const char *network,
                                      const char *cli_path, const char *rpcuser,
                                      const char *rpcpassword, const char *datadir,
                                      int rpcport) {
    if (!db_path) {
        fprintf(stderr, "Client: CLOSE policy needs --db to force-close; cannot proceed\n");
        return 0;
    }
    persist_t db;
    if (!persist_open(&db, db_path)) {
        fprintf(stderr, "Client: CLOSE policy: cannot open DB %s\n", db_path);
        return 0;
    }
    chain_backend_t chain;
    int have_chain = 0;
    regtest_t rt;
    int have_rt = 0;
    if (strcmp(network, "regtest") == 0) {
        if (regtest_init_full(&rt, "regtest", cli_path, rpcuser, rpcpassword, datadir, rpcport)) {
            extern void chain_backend_regtest_init(chain_backend_t *, regtest_t *);
            chain_backend_regtest_init(&chain, &rt);
            have_chain = 1;
            have_rt = 1;
        }
    } else if (rpcuser && rpcpassword) {
        if (chain_backend_rpc_init(&chain, "127.0.0.1", rpcport, rpcuser,
                                    rpcpassword, NULL, network))
            have_chain = 1;
        have_rt = regtest_init_full(&rt, network, cli_path, rpcuser, rpcpassword,
                                    datadir, rpcport);
    }
    if (!client_setup_cpfp(have_rt ? &rt : NULL)) {
        persist_close(&db);
        return 0;
    }
    if (!have_chain) {
        fprintf(stderr, "Client: CLOSE policy: no chain backend (need regtest or "
                "--rpcuser/--rpcpassword) — cannot force-close\n");
        persist_close(&db);
        return 0;
    }
    cpfp_need_clear();
    uint32_t plan_dist = 0;
    if (client_force_close_plan(&db, &chain, &plan_dist, stderr) != 1) {
        persist_close(&db);
        return 0;
    }
    int state = client_exit_pass(&db, &chain);
    if (state == CLIENT_EXIT_FAILED)
        fprintf(stderr, "Client: CLOSE policy force-close FAILED: the exit "
                "cannot be completed from %s (see above)\n", db_path);
    else if (state == CLIENT_EXIT_IN_PROGRESS)
        fprintf(stderr, "Client: CLOSE policy force-close started; run "
                "--force-close --db %s after each new block until it reports "
                "COMPLETE\n", db_path);
    else if (state == CLIENT_EXIT_STUCK)
        fprintf(stderr, "Client: CLOSE policy force-close STUCK: part of the "
                "exit was refused for a reason waiting will not cure (see "
                "above)\n");
    else
        fprintf(stderr, "Client: CLOSE policy force-close: exit path and "
                "commitment published\n");
    persist_close(&db);
    return 1;
}

/* #20 poisoned-LSP marker: persist that THIS node's LSP was caught forging a
   revocation, so a later restart does not silently reconnect to a proven-cheating
   LSP. File sentinel next to the DB (no schema change); checked at startup. */
static void client_mark_lsp_poisoned(const char *db_path, const char *reason) {
    if (!db_path) return;
    char path[1100];
    snprintf(path, sizeof path, "%s.lsp_poisoned", db_path);
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%s\n", reason ? reason : "lsp revocation forgery"); fclose(f); }
}
static int client_lsp_is_poisoned(const char *db_path) {
    if (!db_path) return 0;
    char path[1100];
    snprintf(path, sizeof path, "%s.lsp_poisoned", db_path);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return 1; }
    return 0;
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
    int lsp_forgery_mode = LSP_FORGERY_HALT;  /* --on-lsp-forgery: item-1 escalation policy */
    int lsp_forgery_mode_ps = -1;             /* --on-lsp-forgery-ps: PS-leaf override; -1=inherit (#21) */
    const char *lc_fallbacks[BIP158_MAX_PEERS - 1];
    memset(lc_fallbacks, 0, sizeof(lc_fallbacks));
    int n_lc_fallbacks = 0;
    const char *pay_offer_str = NULL;  /* --pay-offer BECH32M_OFFER */
    int enable_rotation_experimental = 0; /* --enable-rotation-experimental */
    int funding_confs_arg = 0;            /* --funding-confs, 0 = network default */
    int test_lsps2 = 0;               /* --test-lsps2: send lsps2.get_info, verify response */
    int test_lsps2_buy = 0;           /* --test-lsps2-buy: also send lsps2.buy, verify scid */
    int test_splice = 0;              /* --test-splice: exit cleanly after SPLICE_LOCKED */
    int force_close = 0;              /* --force-close: broadcast factory tree from DB */
    uint64_t expect_capacity = 0, min_capacity = 0;   /* --expect-capacity / --min-capacity */
    const char *log_file_path = NULL; /* --log-file PATH */
    int use_syslog = 0;               /* --syslog */
    int use_json_log = 0;              /* --json-log */
    int sweep_to_local = 0;           /* --sweep-to-local: sweep to_local after CSV */
    const char *sweep_dest_addr = NULL; /* --sweep-dest: destination address for sweep */

    scripted_action_t actions[MAX_ACTIONS];
    size_t n_actions = 0;

    /* Load config file if --config provided (first pass) */
    /* SF-W-PTLC #174: PTLCs default-on; operator opts out with --disable-ptlc. */
    {
        extern void ptlc_safety_set_enabled(int);
        ptlc_safety_set_enabled(1);
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            FILE *cf = fopen(argv[i + 1], "r");
            if (!cf) { fprintf(stderr, "ERROR: cannot open config: %s\n", argv[i + 1]); return 1; }
            fseek(cf, 0, SEEK_END);
            long cfsz = ftell(cf);
            fseek(cf, 0, SEEK_SET);
            char *cfdata = malloc((size_t)cfsz + 1);
            if (cfdata) {
                size_t cfrd = fread(cfdata, 1, (size_t)cfsz, cf);
                cfdata[cfrd] = '\0';
                cJSON *cfg = cJSON_Parse(cfdata);
                free(cfdata);
                if (cfg) {
                    cJSON *v;
                    if ((v = cJSON_GetObjectItem(cfg, "host")) && cJSON_IsString(v)) host = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "port")) && cJSON_IsNumber(v)) port = (int)v->valuedouble;
                    if ((v = cJSON_GetObjectItem(cfg, "network")) && cJSON_IsString(v)) network = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "keyfile")) && cJSON_IsString(v)) keyfile_path = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "db")) && cJSON_IsString(v)) db_path = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "passphrase")) && cJSON_IsString(v)) passphrase = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "lsp-pubkey")) && cJSON_IsString(v)) lsp_pubkey_hex = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "rpcuser")) && cJSON_IsString(v)) rpcuser = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "rpcpassword")) && cJSON_IsString(v)) rpcpassword = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "rpcport")) && cJSON_IsNumber(v)) rpcport = (int)v->valuedouble;
                    if ((v = cJSON_GetObjectItem(cfg, "on-lsp-forgery")) && cJSON_IsString(v)) {
                        int m = client_parse_forgery_response(v->valuestring);
                        if (m >= 0) lsp_forgery_mode = m;
                        else fprintf(stderr, "WARNING: config on-lsp-forgery invalid: %s\n", v->valuestring);
                    }
                    if ((v = cJSON_GetObjectItem(cfg, "on-lsp-forgery-ps")) && cJSON_IsString(v)) {
                        int m = client_parse_forgery_response(v->valuestring);
                        if (m >= 0) lsp_forgery_mode_ps = m;
                        else fprintf(stderr, "WARNING: config on-lsp-forgery-ps invalid: %s\n", v->valuestring);
                    }
                    printf("Loaded config from %s\n", argv[i + 1]);
                    cJSON_Delete(cfg);
                } else {
                    fprintf(stderr, "WARNING: failed to parse config JSON: %s\n", argv[i + 1]);
                }
            }
            fclose(cf);
            break;
        }
    }

    /* Parse CLI arguments (override config file) */
    /* SF-W-PTLC #174: PTLCs default-on; operator opts out with --disable-ptlc. */
    {
        extern void ptlc_safety_set_enabled(int);
        ptlc_safety_set_enabled(1);
    }

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
        else if (strcmp(argv[i], "--enable-ptlc-unsafe") == 0) {
            /* SF-W-PTLC #174: kept as a no-op alias for back-compat. */
            extern void ptlc_safety_set_enabled(int);
            ptlc_safety_set_enabled(1);
            printf("Client: --enable-ptlc-unsafe is now a no-op alias (PTLCs default-on)\n");
        }
        else if (strcmp(argv[i], "--musig-stateless") == 0) {
            /* #271 Phase 1a: opt into BIP-327 stateless-signer wire flow.
               Client-side counterpart. Currently registers only. */
            setenv("SS_MUSIG_STATELESS", "1", 1);
        }
        else if (strcmp(argv[i], "--disable-ptlc") == 0) {
            extern void ptlc_safety_set_enabled(int);
            ptlc_safety_set_enabled(0);
            printf("Client: PTLC channel ops disabled (--disable-ptlc)\n");
        }
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
        else if (strcmp(argv[i], "--wallet") == 0 && i + 1 < argc)
            g_client_wallet_name = argv[++i];
        else if (strcmp(argv[i], "--max-tree-fee-rate") == 0 && i + 1 < argc)
            client_set_max_tree_fee_rate((uint64_t)strtoull(argv[++i], NULL, 10));
        else if (strcmp(argv[i], "--cheat-client") == 0 && i + 1 < argc) {
            /* CL7: adversarial client cheat. SIDE = 0 (left) or 1 (right).
               Sets env var read by client_handle_leaf_advance. */
            setenv("SS_CHEAT_CLIENT_SIDE", argv[++i], 1);
        }
        else if (strcmp(argv[i], "--fee-estimator") == 0 && i + 1 < argc)
            fee_estimator_arg = argv[++i];
        else if (strcmp(argv[i], "--on-lsp-forgery") == 0 && i + 1 < argc) {
            int m = client_parse_forgery_response(argv[++i]);
            if (m < 0) {
                fprintf(stderr, "Error: --on-lsp-forgery must be continue|halt|close\n");
                return 1;
            }
            lsp_forgery_mode = m;
        }
        else if (strcmp(argv[i], "--on-lsp-forgery-ps") == 0 && i + 1 < argc) {
            int m = client_parse_forgery_response(argv[++i]);
            if (m < 0) {
                fprintf(stderr, "Error: --on-lsp-forgery-ps must be continue|halt|close\n");
                return 1;
            }
            lsp_forgery_mode_ps = m;
        }
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
        } else if (strcmp(argv[i], "--min-profit-bps") == 0 && i + 1 < argc) {
            client_set_min_profit_bps((uint16_t)atoi(argv[++i]));
        } else if (strcmp(argv[i], "--expect-capacity") == 0 && i + 1 < argc) {
            expect_capacity = (uint64_t)strtoull(argv[++i], NULL, 10);
            client_set_capacity_terms(expect_capacity, min_capacity);
        } else if (strcmp(argv[i], "--max-lsp-balance-pct") == 0 && i + 1 < argc) {
            client_set_max_lsp_balance_pct((uint16_t)atoi(argv[++i]));
        } else if (strcmp(argv[i], "--min-capacity") == 0 && i + 1 < argc) {
            min_capacity = (uint64_t)strtoull(argv[++i], NULL, 10);
            client_set_capacity_terms(expect_capacity, min_capacity);
        } else if (strcmp(argv[i], "--participant-id") == 0 && i + 1 < argc) {
            client_set_slot_hint(atoi(argv[++i]));
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
        } else if (strcmp(argv[i], "--enable-rotation-experimental") == 0) {
            enable_rotation_experimental = 1;
        } else if (strcmp(argv[i], "--funding-confs") == 0 && i + 1 < argc) {
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 1000) {
                fprintf(stderr, "Error: --funding-confs needs a number from 1 to 1000\n");
                return 1;
            }
            funding_confs_arg = (int)v;
        } else if (strcmp(argv[i], "--test-allow-tree-advance") == 0) {
            /* Harness only (the --test- prefix is refused on mainnet):
               co-sign leaf, state and sub-factory advances, which the client
               otherwise refuses because they do not re-anchor its channel. */
            client_set_allow_tree_advance(1);
        } else if (strcmp(argv[i], "--force-close") == 0) {
            force_close = 1;
        } else if (strcmp(argv[i], "--sweep-to-local") == 0) {
            sweep_to_local = 1;
        } else if (strcmp(argv[i], "--sweep-dest") == 0 && i + 1 < argc) {
            sweep_dest_addr = argv[++i];
        } else if (strcmp(argv[i], "--i-accept-the-risk") == 0) {
            accept_risk = 1;
        } else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            log_file_path = argv[++i];
        } else if (strcmp(argv[i], "--syslog") == 0) {
            use_syslog = 1;
        } else if (strcmp(argv[i], "--json-log") == 0) {
            use_json_log = 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            i++;  /* already parsed in first pass */
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

    /* Redirect logs if requested */
    if (log_file_path) {
        if (!freopen(log_file_path, "a", stderr)) {
            printf("ERROR: cannot open log file: %s\n", log_file_path);
            return 1;
        }
        setvbuf(stderr, NULL, _IOLBF, 0);
    }
    if (use_syslog) {
#ifdef __linux__
        openlog("superscalar_client", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
    }
    if (use_json_log)
        ss_log_set_json(1);

    /* Canonicalise the chain name once ("bitcoin" is mainnet), so that every
       check below and in the library sees one spelling.  An unrecognised name
       is refused: it would otherwise select the mainnet RPC port by default
       while none of the mainnet gates fire. */
    {
        const char *canonical = network_canonical(network);
        if (!canonical) {
            fprintf(stderr, "Error: unknown --network '%s' (expected regtest|testnet|"
                    "testnet4|signet|mainnet).\n", network);
            return 1;
        }
        network = canonical;
    }
    /* A recovery phrase with a typo would derive a different, empty wallet
       without any error: refuse it before anything is derived from it. */
    if (hd_mnemonic) {
        bip39_status_t mn_status = bip39_check(hd_mnemonic);
        if (mn_status != BIP39_OK) {
            fprintf(stderr, "Error: invalid --hd-mnemonic: %s\n",
                    bip39_status_str(mn_status));
            return 1;
        }
    }
    /* Defense-bypass cheats are inert unless this is regtest. */
    superscalar_set_cheat_gate(strcmp(network, "regtest") == 0);
    /* Mainnet refuses test/cheat scaffolding in the arguments and in the
       environment (see network.h). */
    {
        extern char **environ;
        char gate_err[512];
        if (!network_gate_no_test_scaffolding(network, argc, argv, environ,
                                              gate_err, sizeof(gate_err))) {
            fputs(gate_err, stderr);
            return 1;
        }
    }

    g_client_fee_mode = fee_estimator_arg;
    g_client_fee_rate = fee_rate > 0 ? (uint64_t)fee_rate : 1000;

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

    /* --- Client force-close (early exit — no LSP needed) --- */
    if (force_close) {
        if (!db_path) {
            fprintf(stderr, "ERROR: --force-close requires --db PATH\n");
            return 1;
        }
        persist_t db;
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "ERROR: failed to open database: %s\n", db_path);
            return 1;
        }

        /* Load tree nodes and broadcast the factory tree */
        printf("=== CLIENT FORCE-CLOSE ===\n");
        printf("Loading factory tree from %s...\n", db_path);

        chain_backend_t chain;
        int have_chain = 0;
        int have_rt = 0;
        regtest_t rt;
        if (strcmp(network, "regtest") == 0) {
            if (!regtest_init_full(&rt, "regtest", cli_path, rpcuser, rpcpassword, datadir, rpcport)) {
                fprintf(stderr, "ERROR: regtest init failed\n");
                persist_close(&db);
                return 1;
            }
            have_rt = 1;
            extern void chain_backend_regtest_init(chain_backend_t *, regtest_t *);
            chain_backend_regtest_init(&chain, &rt);
            /* CL7: expose rt to client_handle_leaf_advance for cheat broadcast */
            { extern void client_set_chain_rt(regtest_t *); client_set_chain_rt(&rt); }
            have_chain = 1;
        } else if (rpcuser && rpcpassword) {
            /* Direct HTTP JSON-RPC to bitcoind (any network) */
            const char *rpchost_fc = "127.0.0.1";
            if (chain_backend_rpc_init(&chain, rpchost_fc,
                                        rpcport, rpcuser, rpcpassword,
                                        NULL, network)) {
                have_chain = 1;
                have_rt = regtest_init_full(&rt, network, cli_path, rpcuser,
                                            rpcpassword, datadir, rpcport);
            } else {
                fprintf(stderr, "ERROR: chain backend RPC init failed\n");
                persist_close(&db);
                return 1;
            }
        }

        if (!have_chain) {
            fprintf(stderr, "ERROR: --force-close requires either regtest or "
                    "--rpcuser + --rpcpassword for bitcoind connection\n");
            persist_close(&db);
            return 1;
        }
        if (!client_setup_cpfp(have_rt ? &rt : NULL)) {
            persist_close(&db);
            return 1;
        }
        cpfp_need_clear();

        /* Publishing the tree spends the factory funding output, after which
           the distribution transaction can never confirm.  Without a signed
           commitment for a channel in it the client could not claim its
           channel output either, so in that case the tree is left alone and
           only a distribution transaction is offered. */
        uint32_t dist_factory = 0;
        int plan = client_force_close_plan(&db, &chain, &dist_factory, stdout);
        if (plan < 0) {
            persist_close(&db);
            printf("=== CLIENT FORCE-CLOSE: nothing published ===\n");
            return 1;
        }
        if (plan == 0) {
            /* Broadcast distribution TX as nLockTime fallback */
            client_send_distribution_tx(&db, &chain, dist_factory);
            persist_close(&db);
            printf("=== CLIENT FORCE-CLOSE: no tree published ===\n");
            return 0;
        }

        /* EXPLICIT operator force-close: publish this client's exit path
           root-down, then its commitment. factory_recovery_scan() is the
           passive startup/reorg scan that never broadcasts. Call repeatedly
           (caller mines between passes) so each tree level matures its CSV;
           the root spends the funding directly, so no distribution TX is
           required. */
        int exit_state = client_exit_pass(&db, &chain);

        /* HTLC claims armed before their preimages went out, run from the
           DB alone: one cycle per run, as the tree and the commitment
           confirm between runs. */
        {
            secp256k1_context *cl_ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            sweeper_t cl_sw;
            if (cl_ctx && sweeper_init(&cl_sw, cl_ctx, NULL, NULL, 0, &chain,
                                       &db, NULL)) {
                /* Claims on our other commitments stay until the one just
                   broadcast is buried final (a reorg can still swap it). */
                client_htlc_claims_attach(&cl_sw, &db, cl_ctx);
                size_t n_claims = client_run_htlc_claims(&cl_sw);
                if (n_claims > 0) {
                    printf("Force-close: %zu HTLC claim(s) pending: run "
                           "--force-close again, or keep the client running, "
                           "until they settle\n", n_claims);
                    if (exit_state == CLIENT_EXIT_PUBLISHED)
                        exit_state = CLIENT_EXIT_IN_PROGRESS;
                }
                client_htlc_claims_attach(NULL, NULL, NULL);
                sweeper_cleanup(&cl_sw);
            }
            if (cl_ctx) secp256k1_context_destroy(cl_ctx);
        }

        persist_close(&db);
        if (exit_state == CLIENT_EXIT_FAILED) {
            printf("=== CLIENT FORCE-CLOSE FAILED ===\n");
            return CLIENT_EXIT_FAILED;
        }
        if (exit_state == CLIENT_EXIT_STUCK) {
            printf("=== CLIENT FORCE-CLOSE STUCK: needs the operator (see the "
                   "STUCK line) ===\n");
            return CLIENT_EXIT_STUCK;
        }
        if (exit_state == CLIENT_EXIT_IN_PROGRESS) {
            printf("=== CLIENT FORCE-CLOSE IN PROGRESS: run --force-close again "
                   "after the next block ===\n");
            return CLIENT_EXIT_IN_PROGRESS;
        }
        printf("=== CLIENT FORCE-CLOSE COMPLETE ===\n");
        return 0;
    }

    /* --- Sweep to_local output after CSV maturity (early exit) --- */
    if (sweep_to_local) {
        if (!db_path) {
            fprintf(stderr, "ERROR: --sweep-to-local requires --db PATH\n");
            return 1;
        }
        if (!sweep_dest_addr) {
            fprintf(stderr, "ERROR: --sweep-to-local requires --sweep-dest ADDRESS\n");
            return 1;
        }
        persist_t db;
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "ERROR: failed to open database: %s\n", db_path);
            return 1;
        }

        printf("=== CLIENT SWEEP TO-LOCAL ===\n");

        /* Initialize chain backend */
        chain_backend_t chain;
        int have_chain = 0;
        regtest_t rt;
        if (strcmp(network, "regtest") == 0) {
            if (!regtest_init_full(&rt, "regtest", cli_path, rpcuser, rpcpassword, datadir, rpcport)) {
                fprintf(stderr, "ERROR: regtest init failed\n");
                persist_close(&db);
                return 1;
            }
            extern void chain_backend_regtest_init(chain_backend_t *, regtest_t *);
            chain_backend_regtest_init(&chain, &rt);
            /* CL7: expose rt to client_handle_leaf_advance for cheat broadcast */
            { extern void client_set_chain_rt(regtest_t *); client_set_chain_rt(&rt); }
            have_chain = 1;
        } else if (rpcuser && rpcpassword) {
            const char *rpchost_sw = "127.0.0.1";
            if (chain_backend_rpc_init(&chain, rpchost_sw,
                                        rpcport, rpcuser, rpcpassword,
                                        NULL, network)) {
                have_chain = 1;
            }
        }
        if (!have_chain) {
            fprintf(stderr, "ERROR: --sweep-to-local requires either regtest or "
                    "--rpcuser + --rpcpassword\n");
            persist_close(&db);
            return 1;
        }

        /* Load commitment sig to get the signed commitment TX */
        size_t commit_tx_len = 0;
        uint64_t sig_cn = 0;
        unsigned char *commit_tx_data =
            exit_load_commitment(&db, &commit_tx_len, &sig_cn);
        if (!commit_tx_data) {
            fprintf(stderr, "ERROR: no signed commitment TX in DB\n");
            persist_close(&db);
            return 1;
        }
        free(commit_tx_data);
        printf("Sweep: loaded commitment TX (cn=%llu, %zu bytes)\n",
               (unsigned long long)sig_cn, commit_tx_len);

        /* Load factory (needed for funding info) */
        secp256k1_context *sweep_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        factory_t *sweep_factory = calloc(1, sizeof(factory_t));
        if (!sweep_factory || !persist_load_factory(&db, 0, sweep_factory, sweep_ctx)) {
            fprintf(stderr, "ERROR: failed to load factory from DB\n");
            free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }

        /* Load keyfile to get keypair */
        unsigned char sweep_seckey[32];
        if (!keyfile_path) {
            fprintf(stderr, "ERROR: --sweep-to-local requires --keyfile\n");
            factory_free(sweep_factory); free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }
        if (!keyfile_load(keyfile_path, sweep_seckey, passphrase)) {
            fprintf(stderr, "ERROR: failed to load keyfile\n");
            factory_free(sweep_factory); free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }
        secp256k1_keypair sweep_kp;
        secp256k1_keypair_create(sweep_ctx, &sweep_kp, sweep_seckey);
        memset(sweep_seckey, 0, 32);

        /* This client's index in the factory, found from its own key as the
           reconnect path does; its channel row and basepoints are stored
           under slot index - 1. */
        uint32_t sweep_my_index = 0;
        {
            secp256k1_pubkey my_pub;
            unsigned char mine[33], other[33];
            size_t mine_len = 33;
            if (secp256k1_keypair_pub(sweep_ctx, &my_pub, &sweep_kp) &&
                secp256k1_ec_pubkey_serialize(sweep_ctx, mine, &mine_len, &my_pub,
                                              SECP256K1_EC_COMPRESSED)) {
                for (size_t k = 1; k < sweep_factory->n_participants; k++) {
                    size_t other_len = 33;
                    if (secp256k1_ec_pubkey_serialize(sweep_ctx, other, &other_len,
                                                      &sweep_factory->pubkeys[k],
                                                      SECP256K1_EC_COMPRESSED) &&
                        memcmp(mine, other, 33) == 0) {
                        sweep_my_index = (uint32_t)k;
                        break;
                    }
                }
            }
        }
        uint64_t local_amt = 0, remote_amt = 0;
        uint64_t cn = 0;
        unsigned char local_secs[4][32] = {{0}};
        unsigned char remote_bps_raw[4][33] = {{0}};
        secp256k1_pubkey r_pay = {{0}}, r_delay = {{0}}, r_revoc = {{0}}, r_htlc = {{0}};
        const char *sweep_err = NULL;
        if (sweep_my_index == 0)
            sweep_err = "the keyfile's key is not a client of the factory in this DB";
        else if (!persist_load_channel_state(&db, sweep_my_index - 1, &local_amt,
                                             &remote_amt, &cn))
            sweep_err = "no channel state in DB";
        else if (!persist_load_basepoints(&db, sweep_my_index - 1, local_secs,
                                          remote_bps_raw))
            sweep_err = "no basepoints in DB";
        else if (!secp256k1_ec_pubkey_parse(sweep_ctx, &r_pay, remote_bps_raw[0], 33) ||
                 !secp256k1_ec_pubkey_parse(sweep_ctx, &r_delay, remote_bps_raw[1], 33) ||
                 !secp256k1_ec_pubkey_parse(sweep_ctx, &r_revoc, remote_bps_raw[2], 33) ||
                 !secp256k1_ec_pubkey_parse(sweep_ctx, &r_htlc, remote_bps_raw[3], 33))
            sweep_err = "failed to parse remote basepoints";
        if (sweep_err) {
            fprintf(stderr, "ERROR: %s\n", sweep_err);
            memset(local_secs, 0, sizeof(local_secs));
            factory_free(sweep_factory); free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }
        printf("Sweep: client %u (channel slot %u)\n", sweep_my_index,
               sweep_my_index - 1);

        /* Initialize channel using the same path as reconnect */
        channel_t sweep_ch;
        if (!client_init_channel(&sweep_ch, sweep_ctx, sweep_factory, &sweep_kp,
                                  sweep_my_index,
                                  &r_pay, &r_delay, &r_revoc, &r_htlc,
                                  local_secs[0], local_secs[1], local_secs[2], local_secs[3],
                                  NULL)) {
            fprintf(stderr, "ERROR: channel init failed\n");
            memset(local_secs, 0, sizeof(local_secs));
            factory_free(sweep_factory); free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }
        memset(local_secs, 0, sizeof(local_secs));

        /* Restore channel state */
        sweep_ch.local_amount = local_amt;
        sweep_ch.remote_amount = remote_amt;
        sweep_ch.commitment_number = cn;

        /* Restore per-commitment secrets */
        {
            size_t pcs_max = (size_t)(cn + 2);
            unsigned char (*pcs_arr)[32] = calloc(pcs_max, 32);
            if (pcs_arr) {
                size_t pcs_loaded = 0;
                persist_load_local_pcs(&db, 0, pcs_arr, pcs_max, &pcs_loaded);
                for (uint64_t c = 0; c < pcs_max; c++) {
                    int nonzero = 0;
                    for (int j = 0; j < 32; j++)
                        if (pcs_arr[c][j]) { nonzero = 1; break; }
                    if (nonzero)
                        channel_set_local_pcs(&sweep_ch, c, pcs_arr[c]);
                }
                free(pcs_arr);
            }
        }

        /* Build commitment TX to get txid and to_local amount */
        tx_buf_t commit_utx;
        unsigned char commit_txid[32];
        tx_buf_init(&commit_utx, 256);
        if (!channel_build_commitment_tx(&sweep_ch, &commit_utx, commit_txid)) {
            fprintf(stderr, "ERROR: failed to rebuild commitment TX\n");
            tx_buf_free(&commit_utx);
            channel_cleanup(&sweep_ch);
            factory_free(sweep_factory); free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }
        tx_buf_free(&commit_utx);

        uint64_t to_local_amount = sweep_ch.local_amount;
        uint32_t to_local_vout = 0; /* to_local is always output[0] */

        /* Check commitment TX confirmation */
        {
            extern void hex_encode(const unsigned char *, size_t, char *);
            char txid_hex[65];
            unsigned char display_txid[32];
            for (int k = 0; k < 32; k++) display_txid[k] = commit_txid[31 - k];
            hex_encode(display_txid, 32, txid_hex);
            printf("Sweep: commitment txid = %s\n", txid_hex);
            printf("Sweep: to_local amount = %llu sats (vout %u)\n",
                   (unsigned long long)to_local_amount, to_local_vout);

            int confs = chain.get_confirmations(&chain, txid_hex);
            if (confs <= 0) {
                printf("Sweep: commitment TX not confirmed yet. "
                       "Run --force-close first.\n");
                channel_cleanup(&sweep_ch);
                factory_free(sweep_factory); free(sweep_factory);
                secp256k1_context_destroy(sweep_ctx);
                persist_close(&db);
                return 1;
            }

            uint32_t csv_delay = CHANNEL_DEFAULT_CSV_DELAY;
            printf("Sweep: commitment TX has %d confirmations "
                   "(need %u for CSV)\n", confs, csv_delay);
            if ((uint32_t)confs < csv_delay) {
                printf("Sweep: CSV not mature yet — %u blocks remaining\n",
                       csv_delay - (uint32_t)confs);
                channel_cleanup(&sweep_ch);
                factory_free(sweep_factory); free(sweep_factory);
                secp256k1_context_destroy(sweep_ctx);
                persist_close(&db);
                return 1;
            }
        }

        /* Build destination SPK from --sweep-dest.
           Accepts either a 34-byte hex scriptPubKey (5120<32-byte-xonly>)
           or a 32-byte hex xonly pubkey (auto-wraps as P2TR). */
        unsigned char dest_spk[34];
        size_t dest_spk_len = 0;
        {
            extern int hex_decode(const char *, unsigned char *, size_t);
            size_t addr_len = strlen(sweep_dest_addr);
            if (addr_len == 68) {
                /* 34-byte hex SPK */
                if (hex_decode(sweep_dest_addr, dest_spk, 34) != 34) {
                    fprintf(stderr, "ERROR: invalid 34-byte hex scriptPubKey\n");
                    channel_cleanup(&sweep_ch);
                    factory_free(sweep_factory); free(sweep_factory);
                    secp256k1_context_destroy(sweep_ctx);
                    persist_close(&db);
                    return 1;
                }
                dest_spk_len = 34;
            } else if (addr_len == 64) {
                /* 32-byte xonly pubkey → wrap as P2TR */
                dest_spk[0] = 0x51; /* OP_1 */
                dest_spk[1] = 0x20; /* push 32 bytes */
                if (hex_decode(sweep_dest_addr, dest_spk + 2, 32) != 32) {
                    fprintf(stderr, "ERROR: invalid 32-byte hex xonly pubkey\n");
                    channel_cleanup(&sweep_ch);
                    factory_free(sweep_factory); free(sweep_factory);
                    secp256k1_context_destroy(sweep_ctx);
                    persist_close(&db);
                    return 1;
                }
                dest_spk_len = 34;
            } else {
                fprintf(stderr, "ERROR: --sweep-dest expects 64-char xonly pubkey hex "
                        "or 68-char P2TR scriptPubKey hex\n");
                channel_cleanup(&sweep_ch);
                factory_free(sweep_factory); free(sweep_factory);
                secp256k1_context_destroy(sweep_ctx);
                persist_close(&db);
                return 1;
            }
        }

        /* Build sweep TX.  It is signed now, by this client alone: its fee
           follows --fee-rate, not the factory's pre-signed rate the
           commitment above was rebuilt at (which may be 0). */
        channel_set_fee_rate(&sweep_ch, fee_rate > 0 ? (uint64_t)fee_rate : 1000);
        tx_buf_t sweep_tx;
        tx_buf_init(&sweep_tx, 256);
        if (!channel_build_to_local_sweep(&sweep_ch, &sweep_tx,
                                            commit_txid, to_local_vout,
                                            to_local_amount,
                                            dest_spk, dest_spk_len)) {
            fprintf(stderr, "ERROR: failed to build sweep TX "
                    "(amount too small for fees?)\n");
            tx_buf_free(&sweep_tx);
            channel_cleanup(&sweep_ch);
            factory_free(sweep_factory); free(sweep_factory);
            secp256k1_context_destroy(sweep_ctx);
            persist_close(&db);
            return 1;
        }

        /* Broadcast sweep TX */
        {
            extern void hex_encode(const unsigned char *, size_t, char *);
            char *sweep_hex = malloc(sweep_tx.len * 2 + 1);
            if (sweep_hex) {
                hex_encode(sweep_tx.data, sweep_tx.len, sweep_hex);
                char sweep_txid[65];
                if (chain.send_raw_tx(&chain, sweep_hex, sweep_txid))
                    printf("Sweep: to_local swept! txid = %s\n", sweep_txid);
                else
                    fprintf(stderr, "ERROR: sweep TX broadcast failed\n");
                free(sweep_hex);
            }
        }

        tx_buf_free(&sweep_tx);
        channel_cleanup(&sweep_ch);
        factory_free(sweep_factory); free(sweep_factory);
        secp256k1_context_destroy(sweep_ctx);
        persist_close(&db);
        printf("=== CLIENT SWEEP COMPLETE ===\n");
        return 0;
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
        if (keyfile_exists(keyfile_path)) {
            fprintf(stderr,
                "Error: keyfile %s already exists; refusing to overwrite it.\n"
                "  Move the file away first, or choose another --keyfile path.\n",
                keyfile_path);
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
            bip39_status_t mn_status = bip39_check(from_mnemonic);
            if (mn_status != BIP39_OK) {
                fprintf(stderr, "Error: invalid --from-mnemonic: %s\n",
                        bip39_status_str(mn_status));
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

    /* Mainnet start-up gates (see network.h): explicit risk acknowledgement,
       no secret key on the command line, no test/cheat scaffolding, and a
       database for persistent state. */
    {
        extern char **environ;
        char gate_err[512];
        network_startup_t startup = {
            .role = NETWORK_ROLE_CLIENT,
            .network = network,
            .accept_risk = accept_risk,
            .seckey_on_cmdline = seckey_hex != NULL,
            .have_db = db_path != NULL,
            .enable_rotation_experimental = enable_rotation_experimental,
            .argc = argc,
            .argv = argv,
            .envp = environ,
        };
        if (!network_startup_gates(&startup, gate_err, sizeof(gate_err))) {
            fputs(gate_err, stderr);
            return 1;
        }
    }
    client_set_allow_rotation(enable_rotation_experimental);
    if (enable_rotation_experimental)
        fprintf(stderr, "WARNING: --enable-rotation-experimental: factory rotation is "
                "enabled. This is unsafe and for testing only.\n");

    /* SF-FUND-VERIFY-REFUSE #197: production networks require a chain
       backend so the client can verify the funding TX on-chain before
       signing the factory tree.  An adversarial LSP could otherwise claim
       a larger funding_amount than actually exists.  Audit 2026-05-17
       recommended refusing at startup rather than warning. */
    if (strcmp(network, "regtest") != 0 && !(rpcuser && rpcpassword)) {
        fprintf(stderr,
            "Error: network=%s requires --rpcuser/--rpcpassword (or --light-client)\n"
            "       so the client can verify the funding TX on-chain.\n"
            "       Without it, an adversarial LSP could claim a larger\n"
            "       funding_amount than actually exists; see audit 2026-05-17.\n",
            network);
        return 1;
    }

    /* Every network except regtest needs the LSP's key pinned with
       --lsp-pubkey.  Checked here, before a keyfile or anything else is
       created; the endpoint resolution below enforces the same rule. */
    if (strcmp(network, "regtest") != 0 && !lsp_pubkey_hex) {
        fprintf(stderr, "ERROR: --lsp-pubkey required on non-regtest networks "
                "(prevents MITM attacks)\n");
        return 1;
    }

    /* The well-known lookup is a direct HTTP connection.  With Tor in use it
       would reveal this host to the LSP's domain, so the two are not combined. */
    if (lsp_domain && (tor_proxy_arg || tor_only)) {
        fprintf(stderr,
            "Error: --lsp DOMAIN cannot be used with --tor-proxy / --tor-only.\n"
            "  The lookup of /.well-known/lsps.json is a direct clearnet HTTP\n"
            "  connection and would bypass Tor. Give the LSP's address with\n"
            "  --host and --port (and its key with --lsp-pubkey) instead.\n");
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
        /* A new key is only ever created when no file exists at the path. */
        keyfile_open_result_t kf_res =
            keyfile_load_or_generate(keyfile_path, seckey, passphrase, tmp_ctx);
        secp256k1_context_destroy(tmp_ctx);
        switch (kf_res) {
        case KEYFILE_OPEN_LOADED:
            printf("Client: loaded key from %s\n", keyfile_path);
            break;
        case KEYFILE_OPEN_GENERATED:
            printf("Client: generated new key and saved it to %s\n", keyfile_path);
            break;
        case KEYFILE_OPEN_LOAD_FAILED:
            fprintf(stderr,
                "Error: keyfile %s exists but could not be loaded\n"
                "  (wrong --passphrase, or the file is corrupt or unreadable).\n"
                "  The file has not been modified. To create a new key instead,\n"
                "  move the file away first.\n", keyfile_path);
            return 1;
        case KEYFILE_OPEN_INSECURE_MODE:
            fprintf(stderr, "Error: refusing to start with keyfile %s: its permissions\n"
                "  let every user read it (details above).\n", keyfile_path);
            return 1;
        default:
            fprintf(stderr, "Error: failed to generate keyfile %s\n", keyfile_path);
            return 1;
        }
        key_loaded = 1;
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

    /* Where to connect, and which key authenticates the LSP.  With --lsp the
       well-known endpoint supplies the host and port.  Its response travels
       over plain HTTP, so the public key in it is not proof of anything and
       never becomes the pinned key: only --lsp-pubkey does, and every network
       except regtest requires it. */
    static lsp_endpoint_t lsp_endpoint;
    {
        if (lsp_domain)
            printf("Client: fetching /.well-known/lsps.json from %s ...\n",
                   lsp_domain);
        lsp_endpoint_status_t ep_status = lsp_wellknown_resolve_endpoint(
            lsp_domain, 80, host, port, lsp_pubkey_hex,
            strcmp(network, "regtest") != 0, &lsp_endpoint);

        if (lsp_domain && ep_status != LSP_ENDPOINT_FETCH_FAILED) {
            printf("Client: bootstrapped from %s -> %s:%d\n",
                   lsp_domain, lsp_endpoint.host, lsp_endpoint.port);
            if (lsp_endpoint.pinned_pubkey_hex)
                printf("Client: advertised LSP pubkey matches --lsp-pubkey\n");
            else if (ep_status != LSP_ENDPOINT_PIN_MISMATCH)
                printf("Client: %s advertises LSP pubkey %s\n"
                       "Client: that key was fetched over unauthenticated HTTP and is NOT trusted.\n"
                       "Client: confirm it with the LSP operator out of band, then pass it\n"
                       "Client: with --lsp-pubkey.\n",
                       lsp_domain, lsp_endpoint.advertised_pubkey_hex);
        }

        switch (ep_status) {
        case LSP_ENDPOINT_OK:
            break;
        case LSP_ENDPOINT_FETCH_FAILED:
            fprintf(stderr, "Client: failed to fetch well-known from %s\n",
                    lsp_domain);
            break;
        case LSP_ENDPOINT_PIN_MISMATCH:
            fprintf(stderr,
                "Error: --lsp-pubkey does not match the key advertised by %s.\n"
                "  --lsp-pubkey: %s\n"
                "  advertised:   %s\n"
                "  Either the LSP has changed its key (confirm the new key with the\n"
                "  operator out of band) or the response did not come from your LSP.\n",
                lsp_domain, lsp_pubkey_hex, lsp_endpoint.advertised_pubkey_hex);
            break;
        case LSP_ENDPOINT_PIN_REQUIRED:
            fprintf(stderr, "ERROR: --lsp-pubkey required on non-regtest networks "
                    "(prevents MITM attacks)\n");
            break;
        }
        if (ep_status != LSP_ENDPOINT_OK) {
            memset(seckey, 0, 32);
            report_close(&rpt);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        host = lsp_endpoint.host;
        port = lsp_endpoint.port;
        lsp_pubkey_hex = lsp_endpoint.pinned_pubkey_hex;
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

        /* PS double-spend defense: client_handle_leaf_advance will
           consult client_ps_signed_inputs and refuse to sign a second
           TX spending the same parent UTXO. ZmnSCPxj §PS wide leaves. */
        client_set_persist(&db);

        if (persist_has_factory(&db, CLIENT_ROTATION_PENDING_FACTORY_ID)) {
            fprintf(stderr, "Client: ROTATION NOT COMPLETED (recorded in %s).\n", db_path);
            rotation_pending_notice(&db);
            persist_close(&db);
            return 1;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Initialize regtest + watchtower for client-side breach detection */
    regtest_t rt;
    int rt_ok = regtest_init_full(&rt, network, cli_path, rpcuser, rpcpassword,
                                  datadir, rpcport);
    if (rt_ok && !client_setup_cpfp(&rt)) return 1;
    if (!rt_ok)
        fprintf(stderr, "Client: regtest init failed (watchtower/RPC disabled)\n");
    /* CL7.B: expose rt to client_handle_leaf_advance so --cheat-client can
       broadcast the stale leaf state during the wire ceremony. The force-close
       and sweep-to-local paths already set this; daemon-mode was missing it,
       which made the CL7 hook silently no-op. */
    if (rt_ok) {
        extern void client_set_chain_rt(regtest_t *);
        client_set_chain_rt(&rt);
    }

    /* Fee estimator — honour --fee-estimator if provided */
    static watchtower_t client_wt;
    static sweeper_t client_sweeper;
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
    /* The close ceremony bounds a proposal's nLockTime by this client's own
       chain tip, read from whatever chain backend the watchtower ends up
       with (bitcoind RPC, or the light client attached below). */
    client_set_chain_tip_source(client_tool_chain_tip, &client_wt);

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

    /* #20 poisoned-LSP marker: if a prior session caught this LSP forging a
       revocation, refuse to reconnect. (--force-close is handled earlier, so the
       operator can still recover; deleting the marker re-enables connecting.) */
    if (db_path && client_lsp_is_poisoned(db_path)) {
        fprintf(stderr, "Client: REFUSING to connect — this LSP was previously caught "
                "forging a revocation (marker %s.lsp_poisoned). Force-close with "
                "--force-close, then delete the marker to re-enable.\n", db_path);
        return 1;
    }

    int ok;
    if (daemon_mode) {
        daemon_cb_data_t cbd;
        memset(&cbd, 0, sizeof(cbd));
        cbd.db = use_db ? &db : NULL;
        cbd.wt = &client_wt;
        if (client_wt.chain &&
            sweeper_init(&client_sweeper, ctx, NULL, NULL, 0, client_wt.chain,
                         use_db ? &db : NULL, client_fee_ptr)) {
            client_htlc_claims_attach(&client_sweeper, use_db ? &db : NULL,
                                      ctx);
            cbd.htlc_sweeper = &client_sweeper;
        }
        cbd.fee = client_fee_ptr;
        cbd.rt = rt_ok ? &rt : NULL;
        cbd.lsp_forgery_response = lsp_forgery_mode;
        cbd.lsp_forgery_response_ps = lsp_forgery_mode_ps;
        cbd.poison_db_path = db_path;
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
                                /* watchtower_set_channel dropped in #208 A3.2 —
                                   penalty bytes are pre-built at revocation
                                   receive time. */
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

        /* Initialize RPC backend for funding TX verification (if credentials available) */
        regtest_t verify_rt;
        (void)verify_rt; /* used only when RPC credentials are available */
        client_verify_funding_fn vfn = NULL;
        void *vctx = NULL;
        if (rpcuser && rpcpassword && strcmp(network, "regtest") != 0) {
            if (regtest_init_full(&verify_rt, network, NULL,
                                   rpcuser, rpcpassword, NULL, rpcport)) {
                /* verify_rt initialized */
                vfn = verify_funding_rpc;
                vctx = &verify_rt;
            }
        } else if (strcmp(network, "regtest") == 0 && rpcuser && rpcpassword) {
            if (regtest_init_full(&verify_rt, "regtest", NULL,
                                   rpcuser, rpcpassword, NULL, rpcport)) {
                /* verify_rt initialized */
                vfn = verify_funding_rpc;
                vctx = &verify_rt;
            }
        }
        /* Without a chain source the library refuses every factory.  The
           only exception is regtest without --rpcuser (harness). */
        if (!rpcuser && strcmp(network, "regtest") == 0)
            allow_unverified_funding_regtest();
        else if (!vfn)
            fprintf(stderr, "Client: RPC connection unavailable — funding outputs cannot "
                    "be verified, so every factory will be refused\n");
        client_set_funding_min_confs(network_funding_confs(network, funding_confs_arg));

        /* A rotation after a reconnect checks the new funding output with
           the same verifier as the first factory. */
        client_set_funding_verifier(vfn, vctx);

        while (!g_shutdown) {
            if (first_run || !use_db) {
                ok = client_run_with_channels(ctx, &kp, host, port,
                                                daemon_channel_cb, &cbd,
                                                vfn, vctx);
                /* Only switch to reconnect mode once factory is persisted */
                if (ok || cbd.saved_initial)
                    first_run = 0;
            } else {
                printf("Client: reconnecting from persisted state...\n");
                cbd.saved_initial = 1;  /* already saved on first run */
                ok = client_run_reconnect(ctx, &kp, host, port, &db,
                                            daemon_channel_cb, &cbd);
            }
            /* The session's channel is gone: claims are built from the DB
               until the next session. */
            client_set_htlc_live_channel(NULL);
            client_set_htlc_sweeper(NULL, 0);
            if (g_shutdown) break;
            if (ok == CLIENT_RECONNECT_REFUSED) {
                /* The stored factory is not the signed tree.  Waiting and
                   loading it again changes nothing: stop, non-zero. */
                fprintf(stderr, "Client: the stored factory cannot be loaded "
                        "(reason above); stopping, not retrying\n");
                ok = 0;
                break;
            }
            if (cbd.rotation_not_completed) {
                ok = 0;
                break;
            }
            if (cbd.lsp_forgery_detected &&
                cbd.lsp_forgery_response != LSP_FORGERY_CONTINUE) {
                fprintf(stderr, "Client: LSP revocation forgery — not reconnecting "
                        "to a proven-cheating LSP\n");
                break;
            }
            if (cbd.wt_register_failed) {
                fprintf(stderr, "Client: not reconnecting: a revoked LSP "
                        "commitment could not be watched (restart to re-arm)\n");
                break;
            }
            if (!ok) {
                fprintf(stderr, "Client: disconnected, retrying in 1s...\n");
                /* Run watchtower check between reconnect attempts so we can
                   detect on-chain breaches even when the LSP is unreachable. */
                if (cbd.wt)
                    watchtower_check(cbd.wt);
                /* The factory's end date pays the members without the LSP.
                   Once its TX is buried to the close depth and nothing is
                   left to watch, the daemon stops; otherwise it keeps
                   running the watchtower. */
                if (use_db &&
                    client_dist_tick(&db, cbd.wt, ctx) == CLIENT_DIST_CONFIRMED) {
                    chain_backend_t *cb = cbd.wt ? cbd.wt->chain : NULL;
                    size_t watched = cbd.wt ? cbd.wt->n_entries + cbd.wt->n_pending : 0;
                    if (client_dist_may_exit(g_dist_watch.confs,
                                             chain_close_confs(cb, cb && cb->is_regtest),
                                             cbd.jit_ch != NULL, watched)) {
                        printf("Client: the factory is settled by its distribution "
                               "TX (%d confirmations); nothing left to watch, "
                               "exiting\n", g_dist_watch.confs);
                        ok = 1;
                        break;
                    }
                    static int keep_reported = 0;
                    if (!keep_reported) {
                        keep_reported = 1;
                        printf("Client: the factory is settled by its distribution "
                               "TX; still running: %d confirmations (close depth %d), %zu "
                               "watched commitment(s)/penalty(ies), JIT channel %s\n",
                               g_dist_watch.confs,
                               chain_close_confs(cb, cb && cb->is_regtest), watched,
                               cbd.jit_ch ? "open" : "none");
                    }
                }
                /* Same for HTLC claims, which must not wait for the LSP. */
                if (cbd.htlc_sweeper) {
                    static time_t last_claims = 0;
                    time_t tn = time(NULL);
                    if (tn - last_claims >= 10) {
                        last_claims = tn;
                        client_run_htlc_claims(cbd.htlc_sweeper);
                    }
                }
                sleep(1);
            } else {
                break;  /* clean exit */
            }
        }
        client_dist_watch_free(&g_dist_watch);
        if (cbd.force_close_requested)
            client_force_close_from_db(db_path, network, cli_path,
                                       rpcuser, rpcpassword, datadir, rpcport);
        client_wait_htlc_claims(cbd.htlc_sweeper);
        /* A close that did not complete is not a clean exit. */
        if (cbd.close_not_completed || cbd.rotation_not_completed)
            ok = 0;
    } else if (n_actions > 0 || expect_channels) {
        /* Funding verification (if RPC available) — shared by both sub-paths. */
        regtest_t sa_verify_rt;
        client_verify_funding_fn sa_vfn = NULL;
        void *sa_vctx = NULL;
        if (rpcuser && rpcpassword) {
            if (regtest_init_full(&sa_verify_rt, network, NULL,
                                   rpcuser, rpcpassword, NULL, rpcport)) {
                sa_vfn = verify_funding_rpc;
                sa_vctx = &sa_verify_rt;
            }
        }
        if (!rpcuser && strcmp(network, "regtest") == 0)
            allow_unverified_funding_regtest();
        else if (!sa_vfn)
            fprintf(stderr, "Client: RPC connection unavailable — funding outputs cannot "
                    "be verified, so every factory will be refused\n");
        client_set_funding_min_confs(network_funding_confs(network, funding_confs_arg));

        if (n_actions > 0) {
            /* Scripted --send/--recv now run through the SAME proven daemon
               message loop as production (daemon_channel_cb), driven by
               cbd.scripted_actions.  The loop auto-fulfills received HTLCs from
               the invoice store, settles sent HTLCs with full bidirectional
               revocation, answers the demo's external-invoice step
               (CREATE_INVOICE), and runs the cooperative close — exiting cleanly
               (return 2) on CLOSE_PROPOSE.  This replaces standalone_channel_cb,
               a parallel re-implementation that desynced on every message type
               it didn't hand-roll (LSP_REVOKE_AND_ACK / CREATE_INVOICE /
               CLOSE_PROPOSE). */
            daemon_cb_data_t cbd;
            memset(&cbd, 0, sizeof(cbd));
            cbd.db  = use_db ? &db : NULL;
            cbd.wt  = &client_wt;
            if (client_wt.chain &&
                sweeper_init(&client_sweeper, ctx, NULL, NULL, 0,
                             client_wt.chain, use_db ? &db : NULL,
                             client_fee_ptr)) {
                client_htlc_claims_attach(&client_sweeper,
                                          use_db ? &db : NULL, ctx);
                cbd.htlc_sweeper = &client_sweeper;
            }
            cbd.fee = client_fee_ptr;
            cbd.rt  = rt_ok ? &rt : NULL;
            cbd.lsp_forgery_response = lsp_forgery_mode;
            cbd.lsp_forgery_response_ps = lsp_forgery_mode_ps;
            cbd.poison_db_path = db_path;
            cbd.scripted_actions   = actions;
            cbd.n_scripted_actions = n_actions;
            ok = client_run_with_channels(ctx, &kp, host, port,
                                          daemon_channel_cb, &cbd,
                                          sa_vfn, sa_vctx);
            client_set_htlc_live_channel(NULL);
            client_set_htlc_sweeper(NULL, 0);
            if (cbd.force_close_requested)
                client_force_close_from_db(db_path, network, cli_path,
                                           rpcuser, rpcpassword, datadir, rpcport);
            client_wait_htlc_claims(cbd.htlc_sweeper);
            if (cbd.close_not_completed)
                ok = 0;
        } else {
            /* Bare --channels (no scripted payment): unchanged legacy path. */
            multi_payment_data_t data = { actions, n_actions, 0 };
            ok = client_run_with_channels(ctx, &kp, host, port,
                                          standalone_channel_cb, &data,
                                          sa_vfn, sa_vctx);
        }
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
