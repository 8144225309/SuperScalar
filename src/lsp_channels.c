#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/ceremony.h"
#include "superscalar/chain_backend.h"
#include "superscalar/factory_recovery.h"
#include "superscalar/sweeper.h"
#include "superscalar/jit_channel.h"
#include "superscalar/lsps.h"
#include "superscalar/splice.h"
#include "superscalar/fee.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/ladder.h"
#include "superscalar/regtest.h"
#include "superscalar/adaptor.h"
#include "superscalar/musig.h"
#include "superscalar/lsp_queue.h"
#include "superscalar/readiness.h"
#include "superscalar/notify.h"
#include "superscalar/admin_rpc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <poll.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#include "superscalar/sha256.h"
#include "superscalar/wallet_source.h"
#include "superscalar/wallet_source_hd.h"

/* watch_revoked_commitment moved to watchtower.c as watchtower_watch_revoked_commitment() */

/* Verify that a revocation secret matches the per-commitment point stored for
   the given commitment number.  Returns 1 if valid (or if no stored PCP to
   check against), 0 if the secret is demonstrably wrong. */
static int verify_revocation_secret(const secp256k1_context *ctx,
                                     const channel_t *ch,
                                     uint64_t commitment_num,
                                     const unsigned char *secret32) {
    secp256k1_pubkey derived;
    if (!secp256k1_ec_pubkey_create(ctx, &derived, secret32))
        return 0;  /* not a valid scalar */

    secp256k1_pubkey stored;
    if (!channel_get_remote_pcp(ch, commitment_num, &stored))
        return 1;  /* no PCP stored — can't verify, accept on trust */

    unsigned char d_ser[33], s_ser[33];
    size_t dlen = 33, slen = 33;
    secp256k1_ec_pubkey_serialize(ctx, d_ser, &dlen, &derived,
                                   SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, s_ser, &slen, &stored,
                                   SECP256K1_EC_COMPRESSED);
    return memcmp(d_ser, s_ser, 33) == 0;
}

/* Send the LSP's own revocation secret to a client after each commitment update.
   This enables bidirectional revocation so clients can detect LSP breaches.
   old_cn: the commitment number whose secret is being revealed. */
void lsp_send_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
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
        secure_zero(lsp_rev_secret, 32);
        return;
    }

    /* Build and send using same format as REVOKE_AND_ACK but with LSP type */
    cJSON *j = wire_build_revoke_and_ack(
        mgr->entries[client_idx].channel_id,
        lsp_rev_secret, mgr->ctx, &next_pcp);
    wire_send(lsp->client_fds[client_idx], MSG_LSP_REVOKE_AND_ACK, j);
    cJSON_Delete(j);

    secure_zero(lsp_rev_secret, 32);
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
        size_t leaf_idx = client_idx / 2;
        *node_idx_out = (leaf_idx < (size_t)factory->n_leaf_nodes)
            ? factory->leaf_node_indices[leaf_idx] : 0;
        *vout_out = (uint32_t)(client_idx % 2);
    }
}

int lsp_channels_init(lsp_channel_mgr_t *mgr,
                       secp256k1_context *ctx,
                       const factory_t *factory,
                       const unsigned char *lsp_seckey32,
                       size_t n_clients) {
    if (!mgr || !ctx || !factory || !lsp_seckey32) return 0;
    if (n_clients == 0) return 0;

    /* Preserve fee policy set before init (caller may configure these) */
    uint64_t saved_fee_ppm = mgr->routing_fee_ppm;
    uint16_t saved_bal_pct = mgr->lsp_balance_pct;
    void *saved_fee = mgr->fee;
    memset(mgr, 0, sizeof(*mgr));
    mgr->routing_fee_ppm = saved_fee_ppm;
    mgr->lsp_balance_pct = saved_bal_pct;
    mgr->fee = saved_fee;
    mgr->ctx = ctx;
    mgr->n_channels = n_clients;
    mgr->bridge_fd = -1;
    mgr->n_invoices = 0;
    mgr->n_htlc_origins = 0;

    /* Allocate dynamic arrays */
    mgr->entries = calloc(n_clients, sizeof(lsp_channel_entry_t));
    mgr->invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr->htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    if (!mgr->entries || !mgr->invoices || !mgr->htlc_origins) {
        free(mgr->entries); free(mgr->invoices); free(mgr->htlc_origins);
        memset(mgr, 0, sizeof(*mgr));
        return 0;
    }
    mgr->entries_cap = n_clients;
    mgr->invoices_cap = MAX_INVOICE_REGISTRY;
    mgr->htlc_origins_cap = MAX_HTLC_ORIGINS;
    mgr->next_request_id = 1;
    mgr->leaf_arity = factory->leaf_arity;
    htlc_inbound_init(&mgr->htlc_inbound);

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

        /* Derive per-client close address: P2TR from client's factory pubkey */
        secp256k1_xonly_pubkey client_xonly;
        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &client_xonly, NULL, client_pubkey)) {
            build_p2tr_script_pubkey(entry->close_spk, &client_xonly);
            entry->close_spk_len = 34;
        }

        /* Commitment tx fee: use manager's fee estimator if available */
        fee_estimator_static_t _fe_default;
        fee_estimator_t *_fe = (fee_estimator_t *)mgr->fee;
        if (!_fe) { fee_estimator_static_init(&_fe_default, 1000); _fe = &_fe_default.base; }
        uint64_t commit_fee = fee_for_commitment_tx(_fe, 0);
        uint64_t usable = funding_amount > commit_fee ? funding_amount - commit_fee : 0;
        /* Balance split: lsp_balance_pct controls LSP share (default 50 = fair) */
        uint16_t pct = mgr->lsp_balance_pct;
        if (pct == 0) pct = 50;  /* 0 means "use default" */
        if (pct > 100) pct = 100;
        uint64_t local_amount = (usable * pct) / 100;
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
        /* Attach persistence so revocation secrets land in revocation_secrets
           and a standalone watchtower can hydrate this channel. */
        channel_set_persist(&entry->channel, mgr->persist, (uint32_t)c);
        /* Do NOT override fee_rate from estimatesmartfee: client always uses the
           default 1000 sat/kvB from channel_init, so both sides must agree. */

        /* Fix keyagg: factory leaf outputs always use [client, lsp] key ordering.
           channel_init's SPK-match heuristic fails for CLTV-taptree outputs
           (cltv_timeout > 0), falling back to [local, remote] = [lsp, client].
           Override to match the factory's actual ordering. */
        {
            secp256k1_pubkey ch_pks[2] = { *client_pubkey, lsp_pubkey };
            if (!musig_aggregate_keys(ctx, &entry->channel.funding_keyagg, ch_pks, 2))
                return 0;
            entry->channel.local_funding_signer_idx = 1;  /* LSP at index 1 */
        }
        /* Set CLTV taptree merkle root so MuSig2 session uses correct tweak */
        if (factory->cltv_timeout > 0)
            channel_set_cltv_merkle_root(&entry->channel, factory->cltv_timeout, &lsp_pubkey);

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
    if (n_clients == 0) return 0;

    /* Preserve fields set before init (caller may configure these) */
    uint64_t saved_fee_ppm = mgr->routing_fee_ppm;
    uint16_t saved_bal_pct = mgr->lsp_balance_pct;
    void *saved_fee2 = mgr->fee;
    economic_mode_t saved_econ = mgr->economic_mode;
    uint16_t saved_profit_bps = mgr->default_profit_bps;
    uint32_t saved_settle_interval = mgr->settlement_interval_blocks;
    memset(mgr, 0, sizeof(*mgr));
    mgr->routing_fee_ppm = saved_fee_ppm;
    mgr->lsp_balance_pct = saved_bal_pct;
    mgr->fee = saved_fee2;
    mgr->economic_mode = saved_econ;
    mgr->default_profit_bps = saved_profit_bps;
    mgr->settlement_interval_blocks = saved_settle_interval;
    mgr->ctx = ctx;
    mgr->n_channels = n_clients;
    mgr->bridge_fd = -1;
    mgr->n_invoices = 0;
    mgr->n_htlc_origins = 0;

    /* Allocate dynamic arrays */
    mgr->entries = calloc(n_clients, sizeof(lsp_channel_entry_t));
    mgr->invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr->htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    if (!mgr->entries || !mgr->invoices || !mgr->htlc_origins) {
        free(mgr->entries); free(mgr->invoices); free(mgr->htlc_origins);
        memset(mgr, 0, sizeof(*mgr));
        return 0;
    }
    mgr->entries_cap = n_clients;
    mgr->invoices_cap = MAX_INVOICE_REGISTRY;
    mgr->htlc_origins_cap = MAX_HTLC_ORIGINS;
    mgr->next_request_id = 1;
    mgr->leaf_arity = factory->leaf_arity;
    htlc_inbound_init(&mgr->htlc_inbound);

    /* Restore accumulated fees from DB (crash recovery) */
    persist_load_fee_settlement(pdb, 0,
        &mgr->accumulated_fees_sats, &mgr->last_settlement_block);

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

        /* Derive per-client close address: P2TR from client's factory pubkey */
        secp256k1_xonly_pubkey client_xonly2;
        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &client_xonly2, NULL, client_pubkey)) {
            build_p2tr_script_pubkey(entry->close_spk, &client_xonly2);
            entry->close_spk_len = 34;
        }

        /* Commitment tx fee: use manager's fee estimator if available */
        fee_estimator_static_t _fe_default2;
        fee_estimator_t *_fe2 = (fee_estimator_t *)mgr->fee;
        if (!_fe2) { fee_estimator_static_init(&_fe_default2, 1000); _fe2 = &_fe_default2.base; }
        uint64_t commit_fee = fee_for_commitment_tx(_fe2, 0);
        uint64_t usable = funding_amount > commit_fee ? funding_amount - commit_fee : 0;
        uint16_t pct2 = mgr->lsp_balance_pct;
        if (pct2 == 0) pct2 = 50;
        if (pct2 > 100) pct2 = 100;
        uint64_t local_amount = (usable * pct2) / 100;
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
        /* Attach persistence (see lsp_channels_init for rationale). */
        channel_set_persist(&entry->channel, mgr->persist, (uint32_t)c);
        /* Do NOT override fee_rate from estimatesmartfee: client always uses the
           default 1000 sat/kvB from channel_init, so both sides must agree. */

        /* Fix keyagg: factory leaf outputs always use [client, lsp] key ordering */
        {
            secp256k1_pubkey ch_pks2[2] = { *client_pubkey, lsp_pubkey };
            if (!musig_aggregate_keys(ctx, &entry->channel.funding_keyagg, ch_pks2, 2))
                return 0;
            entry->channel.local_funding_signer_idx = 1;  /* LSP at index 1 */
        }
        if (factory->cltv_timeout > 0)
            channel_set_cltv_merkle_root(&entry->channel, factory->cltv_timeout, &lsp_pubkey);

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
        memset(local_secrets, 0, sizeof(local_secrets));

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

        /* Load active HTLCs from DB */
        {
            htlc_t *loaded_htlcs = malloc(MAX_HTLCS * sizeof(htlc_t));
            if (!loaded_htlcs) return 0;
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
            free(loaded_htlcs);
        }

        /* Initialize nonce pool (fresh nonces — reconnect re-exchanges) */
        if (!channel_init_nonce_pool(&entry->channel, MUSIG_NONCE_POOL_MAX))
            return 0;

        entry->ready = 1;  /* channels are already operational */
    }

    return 1;
}

/* Receive from client_fd with timeout, servicing bridge heartbeats while waiting.
   Replaces wire_recv_timeout() to prevent bridge starvation during HTLC processing. */

/* Accept a connection on the listen socket and queue it for deferred processing.
   Callable from any wait loop (confirmation waits, ceremony waits, etc.).
   Returns 1 if a connection was queued, 0 otherwise. */

/* Forward declarations for daemon_loop_once */
static int handle_reconnect_with_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp, int fd, const wire_msg_t *msg);
int lsp_accept_and_queue_connection(void *mgr_ptr, void *lsp_ptr);

/* Single iteration: drain queue, poll for 1 second, return. */
int lsp_channels_run_daemon_loop_once(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       volatile int *shutdown_flag)
{
    /* Set shutdown after one iteration */
    volatile int one_shot = 0;
    (void)shutdown_flag;

    /* Accept any pending connections */
    lsp_accept_and_queue_connection(mgr, lsp);

    /* Drain reconnect queue - this is the code from the daemon loop top */
    while (mgr->n_pending_reconnects > 0) {
        mgr->n_pending_reconnects--;
        size_t qi = mgr->n_pending_reconnects;
        if (!mgr->pending_reconnects[qi].valid) continue;
        int qfd = mgr->pending_reconnects[qi].fd;
        uint8_t qtype = mgr->pending_reconnects[qi].msg_type;
        cJSON *qjson = (cJSON *)mgr->pending_reconnects[qi].json;
        mgr->pending_reconnects[qi].valid = 0;
        mgr->pending_reconnects[qi].json = NULL;
        wire_set_timeout(qfd, WIRE_DEFAULT_TIMEOUT_SEC);
        if (qtype == MSG_RECONNECT) {
            wire_msg_t qmsg = { .msg_type = qtype, .json = qjson };
            handle_reconnect_with_msg(mgr, lsp, qfd, &qmsg);
            if (qjson) cJSON_Delete(qjson);
        } else if (qtype == MSG_HELLO) {
            unsigned char pk_buf[33];
            secp256k1_pubkey pk;
            if (qjson && wire_json_get_hex(qjson, "pubkey", pk_buf, 33) == 33 &&
                secp256k1_ec_pubkey_parse(mgr->ctx, &pk, pk_buf, 33)) {
                int slot = -1;
                for (size_t s = 0; s < lsp->n_clients; s++) {
                    unsigned char s1[33], s2[33];
                    size_t l1 = 33, l2 = 33;
                    if (secp256k1_ec_pubkey_serialize(mgr->ctx, s1, &l1,
                            &lsp->client_pubkeys[s], SECP256K1_EC_COMPRESSED) &&
                        secp256k1_ec_pubkey_serialize(mgr->ctx, s2, &l2,
                            &pk, SECP256K1_EC_COMPRESSED) &&
                        memcmp(s1, s2, 33) == 0) { slot = (int)s; break; }
                }
                if (slot >= 0) {
                    cJSON_Delete(qjson);
                    uint64_t cn = mgr->entries[slot].channel.commitment_number;
                    qjson = wire_build_reconnect(mgr->ctx, &pk, cn);
                    wire_msg_t qmsg = { .msg_type = MSG_RECONNECT, .json = qjson };
                    handle_reconnect_with_msg(mgr, lsp, qfd, &qmsg);
                    cJSON_Delete(qjson);
                } else {
                    if (qjson) cJSON_Delete(qjson);
                    wire_close(qfd);
                }
            } else {
                if (qjson) cJSON_Delete(qjson);
                wire_close(qfd);
            }
        } else {
            if (qjson) cJSON_Delete(qjson);
            wire_close(qfd);
        }
    }
    (void)one_shot;
    return 1;
}

int lsp_accept_and_queue_connection(void *mgr_ptr, void *lsp_ptr)
{
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    lsp_t *lsp = (lsp_t *)lsp_ptr;
    if (!mgr || !lsp || lsp->listen_fd < 0) return 0;
    if (mgr->n_pending_reconnects >= PENDING_RECONNECT_MAX) return 0;

    /* Non-blocking check: is there a connection waiting? */
    struct pollfd pfd = { .fd = lsp->listen_fd, .events = POLLIN };
    int ret = poll(&pfd, 1, 0);  /* instant poll, no wait */
    if (ret <= 0 || !(pfd.revents & POLLIN)) return 0;

    int new_fd = wire_accept(lsp->listen_fd);
    if (new_fd < 0) return 0;

    wire_set_timeout(new_fd, 5);
    int hs_ok;
    if (lsp->use_nk)
        hs_ok = wire_noise_handshake_nk_responder(new_fd, mgr->ctx, lsp->nk_seckey);
    else
        hs_ok = wire_noise_handshake_responder(new_fd, mgr->ctx);

    if (!hs_ok) { wire_close(new_fd); return 0; }

    wire_msg_t peek;
    if (!wire_recv_timeout(new_fd, &peek, 5)) { wire_close(new_fd); return 0; }

    size_t qi = mgr->n_pending_reconnects++;
    mgr->pending_reconnects[qi].fd = new_fd;
    mgr->pending_reconnects[qi].msg_type = peek.msg_type;
    mgr->pending_reconnects[qi].json = peek.json;
    mgr->pending_reconnects[qi].valid = 1;
    return 1;
}

static int recv_timeout_service_bridge(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       int client_fd, wire_msg_t *msg,
                                       int timeout_sec) {
    /* Zero msg so callers can safely check msg->json on failure */
    memset(msg, 0, sizeof(*msg));
    static int servicing = 0;   /* recursion guard (single-threaded) */
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {
        struct pollfd pfds[4];
        int nfds = 0;
        int client_slot, bridge_slot = -1, listen_slot = -1;

        pfds[nfds].fd = client_fd;
        pfds[nfds].events = POLLIN;
        client_slot = nfds++;

        if (mgr->bridge_fd >= 0 && !servicing) {
            bridge_slot = nfds;
            pfds[nfds].fd = mgr->bridge_fd;
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        /* Poll listen socket during ceremonies so clients can connect.
           Connections are accepted, handshaked, and QUEUED (not processed)
           to avoid modifying state that the active ceremony depends on. */
        if (lsp && lsp->listen_fd >= 0 && !servicing &&
            mgr->n_channels > 0) {
            listen_slot = nfds;
            pfds[nfds].fd = lsp->listen_fd;
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        gettimeofday(&now, NULL);
        int elapsed = (int)(now.tv_sec - start.tv_sec);
        int remaining = timeout_sec - elapsed;
        if (remaining <= 0) return 0;

        int ret = poll(pfds, (nfds_t)nfds, remaining * 1000);
        if (ret <= 0) {
            if (ret < 0) continue;  /* EINTR */
            return 0;               /* timeout */
        }

        /* Service bridge if ready */
        if (bridge_slot >= 0 && (pfds[bridge_slot].revents & POLLIN)) {
            wire_msg_t bmsg;
            if (!wire_recv(mgr->bridge_fd, &bmsg)) {
                fprintf(stderr, "LSP: bridge disconnected during ceremony\n");
                mgr->bridge_fd = -1;
            } else {
                servicing = 1;
                lsp_channels_handle_bridge_msg(mgr, lsp, &bmsg);
                servicing = 0;
                cJSON_Delete(bmsg.json);
            }
        }

        /* Accept + handshake + queue new connections (no state modification) */
        if (listen_slot >= 0 && (pfds[listen_slot].revents & POLLIN)) {
            int new_fd = wire_accept(lsp->listen_fd);
            if (new_fd >= 0 &&
                mgr->n_pending_reconnects < PENDING_RECONNECT_MAX) {
                /* Set short timeout for handshake so it doesn't stall */
                wire_set_timeout(new_fd, 5);
                int hs_ok;
                if (lsp->use_nk)
                    hs_ok = wire_noise_handshake_nk_responder(
                                new_fd, mgr->ctx, lsp->nk_seckey);
                else
                    hs_ok = wire_noise_handshake_responder(new_fd, mgr->ctx);

                if (hs_ok) {
                    wire_msg_t peek;
                    if (wire_recv_timeout(new_fd, &peek, 5)) {
                        /* Queue for deferred processing */
                        size_t qi = mgr->n_pending_reconnects++;
                        mgr->pending_reconnects[qi].fd = new_fd;
                        mgr->pending_reconnects[qi].msg_type = peek.msg_type;
                        mgr->pending_reconnects[qi].json = peek.json;
                        mgr->pending_reconnects[qi].valid = 1;
                        /* Don't cJSON_Delete — ownership transferred to queue */
                    } else {
                        wire_close(new_fd);
                    }
                } else {
                    wire_close(new_fd);
                }
            } else if (new_fd >= 0) {
                wire_close(new_fd);  /* queue full */
            }
        }

        /* Target client fd ready — read and return */
        if (pfds[client_slot].revents & POLLIN)
            return wire_recv(client_fd, msg);
    }
}

/* Receive an expected message type, draining stray benign messages.
   Loops with a wall-clock timeout, dispatching REGISTER_INVOICE,
   CLOSE_REQUEST, LSPS_REQUEST, and QUEUE_POLL to their handlers
   instead of failing the ceremony.  Pattern from lsp_rotation.c:168-184. */
static int recv_expected_drain_stray(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      int client_fd, wire_msg_t *msg,
                                      uint8_t expected_type,
                                      int timeout_sec, size_t client_idx) {
    struct timeval t_start, t_now;
    gettimeofday(&t_start, NULL);
    while (1) {
        gettimeofday(&t_now, NULL);
        int elapsed = (int)(t_now.tv_sec - t_start.tv_sec);
        int remain = timeout_sec - elapsed;
        if (remain <= 0) return 0;
        memset(msg, 0, sizeof(*msg));
        if (!recv_timeout_service_bridge(mgr, lsp, client_fd, msg, remain))
            return 0;
        if (msg->msg_type == expected_type)
            return 1;
        if (msg->msg_type == MSG_ERROR)
            return 0;
        /* Benign stray: dispatch and retry */
        if (msg->msg_type == MSG_REGISTER_INVOICE ||
            msg->msg_type == MSG_CLOSE_REQUEST ||
            msg->msg_type == MSG_LSPS_REQUEST ||
            msg->msg_type == MSG_QUEUE_POLL ||
            msg->msg_type == MSG_QUEUE_DONE ||
            msg->msg_type == MSG_PONG) {
            lsp_channels_handle_msg(mgr, lsp, client_idx, msg);
            if (msg->json) { cJSON_Delete(msg->json); msg->json = NULL; }
            continue;
        }
        /* Unknown stray — log and retry */
        fprintf(stderr, "LSP: ceremony: discarding stray msg 0x%02x from client %zu\n",
                msg->msg_type, client_idx);
        if (msg->json) { cJSON_Delete(msg->json); msg->json = NULL; }
    }
}

void lsp_channels_cleanup(lsp_channel_mgr_t *mgr) {
    if (!mgr) return;
    if (mgr->entries) {
        for (size_t i = 0; i < mgr->n_channels; i++)
            channel_cleanup(&mgr->entries[i].channel);
    }
    free(mgr->entries);
    free(mgr->invoices);
    free(mgr->htlc_origins);
    mgr->entries = NULL;
    mgr->invoices = NULL;
    mgr->htlc_origins = NULL;
    mgr->n_channels = 0;
    mgr->n_invoices = 0;
    mgr->n_htlc_origins = 0;
}

int lsp_channels_exchange_basepoints(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    /* Phase 1: batch-send basepoints to ALL clients */
    for (size_t c = 0; c < mgr->n_channels; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];
        channel_t *ch = &entry->channel;

        secp256k1_pubkey lsp_first_pcp, lsp_second_pcp;
        if (!channel_get_per_commitment_point(ch, 0, &lsp_first_pcp) ||
            !channel_get_per_commitment_point(ch, 1, &lsp_second_pcp)) {
            fprintf(stderr, "LSP: failed to get per_commitment_points for channel %zu\n", c);
            return 0;
        }

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
    }

    /* Phase 2: parallel-collect basepoint replies from all clients */
    int *bp_fds = (int *)calloc(mgr->n_channels, sizeof(int));
    int *bp_ready = (int *)calloc(mgr->n_channels, sizeof(int));
    if (!bp_fds || !bp_ready) { free(bp_fds); free(bp_ready); return 0; }

    for (size_t c = 0; c < mgr->n_channels; c++)
        bp_fds[c] = lsp->client_fds[c];

    size_t bp_received = 0;
    while (bp_received < mgr->n_channels) {
        int n_ready = ceremony_select_all(bp_fds, mgr->n_channels, 30, bp_ready);
        if (n_ready <= 0) {
            fprintf(stderr, "LSP: timeout waiting for basepoint replies (%zu/%zu received)\n",
                    bp_received, mgr->n_channels);
            free(bp_fds); free(bp_ready);
            return 0;
        }
        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (!bp_ready[c]) continue;

            wire_msg_t bp_resp;
            if (!wire_recv_skip_ping(lsp->client_fds[c], &bp_resp) ||
                bp_resp.msg_type != MSG_CHANNEL_BASEPOINTS) {
                fprintf(stderr, "LSP: expected CHANNEL_BASEPOINTS from client %zu, got 0x%02x\n",
                        c, bp_resp.msg_type);
                if (bp_resp.json) cJSON_Delete(bp_resp.json);
                free(bp_fds); free(bp_ready);
                return 0;
            }

            uint32_t resp_ch_id;
            secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc, rfirst_pcp, rsecond_pcp;
            if (!wire_parse_channel_basepoints(bp_resp.json, &resp_ch_id, mgr->ctx,
                                                 &rpay, &rdelay, &rrevoc, &rhtlc,
                                                 &rfirst_pcp, &rsecond_pcp)) {
                fprintf(stderr, "LSP: failed to parse client %zu basepoints\n", c);
                cJSON_Delete(bp_resp.json);
                free(bp_fds); free(bp_ready);
                return 0;
            }
            cJSON_Delete(bp_resp.json);

            channel_t *ch = &mgr->entries[c].channel;
            channel_set_remote_basepoints(ch, &rpay, &rdelay, &rrevoc);
            channel_set_remote_htlc_basepoint(ch, &rhtlc);
            channel_set_remote_pcp(ch, 0, &rfirst_pcp);
            channel_set_remote_pcp(ch, 1, &rsecond_pcp);

            bp_fds[c] = -1;  /* mark as received */
            bp_received++;
            printf("LSP: basepoint exchange complete for channel %zu\n", c);
        }
    }
    free(bp_fds);
    free(bp_ready);

    return 1;
}

int lsp_channels_send_ready(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    /* Phase 1: batch-send CHANNEL_READY + SCID + nonces to ALL clients */
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

        /* 4B: Send SCID assignment for route hints */
        {
            int leaf_pos = -1;
            for (int li = 0; li < lsp->factory.n_leaf_nodes; li++) {
                size_t ni = lsp->factory.leaf_node_indices[li];
                const factory_node_t *nd = &lsp->factory.nodes[ni];
                for (size_t s = 0; s < nd->n_signers; s++) {
                    if (nd->signer_indices[s] == (uint32_t)(c + 1)) {
                        leaf_pos = li;
                        break;
                    }
                }
                if (leaf_pos >= 0) break;
            }
            if (leaf_pos < 0) leaf_pos = (int)c;
            uint64_t scid = factory_derive_scid(&lsp->factory, leaf_pos, 0);
            cJSON *scid_msg = wire_build_scid_assign(
                entry->channel_id, scid,
                0,                                  /* fee_base_msat */
                (uint32_t)mgr->routing_fee_ppm,     /* fee_ppm */
                40);                                 /* cltv_delta */
            wire_send(lsp->client_fds[c], MSG_SCID_ASSIGN, scid_msg);
            cJSON_Delete(scid_msg);
        }

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
    }

    /* Phase 2: parallel-collect nonce replies from all clients */
    int *nonce_fds = (int *)calloc(mgr->n_channels, sizeof(int));
    int *nonce_ready = (int *)calloc(mgr->n_channels, sizeof(int));
    if (!nonce_fds || !nonce_ready) { free(nonce_fds); free(nonce_ready); return 0; }

    for (size_t c = 0; c < mgr->n_channels; c++)
        nonce_fds[c] = lsp->client_fds[c];

    size_t nonces_received = 0;
    while (nonces_received < mgr->n_channels) {
        int n_ready = ceremony_select_all(nonce_fds, mgr->n_channels, 30, nonce_ready);
        if (n_ready <= 0) {
            fprintf(stderr, "LSP: timeout waiting for nonce replies (%zu/%zu received)\n",
                    nonces_received, mgr->n_channels);
            free(nonce_fds); free(nonce_ready);
            return 0;
        }
        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (!nonce_ready[c]) continue;

            wire_msg_t nonce_resp;
            if (!wire_recv_skip_ping(lsp->client_fds[c], &nonce_resp) ||
                nonce_resp.msg_type != MSG_CHANNEL_NONCES) {
                fprintf(stderr, "LSP: expected CHANNEL_NONCES from client %zu, got 0x%02x\n",
                        c, nonce_resp.msg_type);
                if (nonce_resp.json) cJSON_Delete(nonce_resp.json);
                free(nonce_fds); free(nonce_ready);
                return 0;
            }

            uint32_t resp_ch_id;
            unsigned char client_nonces[MUSIG_NONCE_POOL_MAX][66];
            size_t client_nonce_count;
            if (!wire_parse_channel_nonces(nonce_resp.json, &resp_ch_id,
                                             client_nonces, MUSIG_NONCE_POOL_MAX,
                                             &client_nonce_count)) {
                fprintf(stderr, "LSP: failed to parse client %zu nonces\n", c);
                cJSON_Delete(nonce_resp.json);
                free(nonce_fds); free(nonce_ready);
                return 0;
            }
            cJSON_Delete(nonce_resp.json);

            channel_set_remote_pubnonces(&mgr->entries[c].channel,
                (const unsigned char (*)[66])client_nonces, client_nonce_count);

            nonce_fds[c] = -1;  /* mark as received */
            nonces_received++;
            mgr->entries[c].ready = 1;
        }
    }
    free(nonce_fds);
    free(nonce_ready);

    return 1;
}

/* --- CLTV validation --- */

int lsp_validate_cltv_for_forward(uint32_t cltv_expiry, uint32_t *fwd_cltv_out,
                                   uint32_t factory_cltv_timeout) {
    if (cltv_expiry <= FACTORY_CLTV_DELTA)
        return 0;
    /* Reject HTLCs that expire at or past factory timeout — funds would be trapped */
    if (factory_cltv_timeout > 0 && cltv_expiry >= factory_cltv_timeout)
        return 0;
    if (fwd_cltv_out)
        *fwd_cltv_out = cltv_expiry - FACTORY_CLTV_DELTA;
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
    htlc_t *old_sender_htlcs = old_sender_n_htlcs > 0
        ? malloc(old_sender_n_htlcs * sizeof(htlc_t)) : NULL;
    if (old_sender_n_htlcs > 0 && !old_sender_htlcs) return 0;
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
        free(old_sender_htlcs);
        return 1;  /* not a protocol error, just a payment failure */
    }

    /* Send COMMITMENT_SIGNED to sender (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for sender %zu\n", sender_idx);
            free(old_sender_htlcs);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[sender_idx].channel_id,
            sender_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[sender_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            free(old_sender_htlcs);
            return 0;
        }
        cJSON_Delete(cs);
        /* Fix 5: flag pending CS so reconnect can retransmit if RAA lost */
        if (mgr->persist)
            persist_save_pending_cs((persist_t *)mgr->persist,
                mgr->entries[sender_idx].channel_id,
                sender_ch->commitment_number);
    }

    int sender_batch = 0;

    /* Wait for REVOKE_AND_ACK from sender */
    {
        wire_msg_t ack_msg;
        if (!recv_expected_drain_stray(mgr, lsp, lsp->client_fds[sender_idx],
                                        &ack_msg, MSG_REVOKE_AND_ACK, 30, sender_idx)) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP: expected REVOKE_AND_ACK from sender %zu\n", sender_idx);
            free(old_sender_htlcs);
            return 0;
        }
        /* Parse and verify revocation secret */
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = sender_ch->commitment_number - 1;
            if (!verify_revocation_secret(mgr->ctx, sender_ch, old_cn, rev_secret)) {
                fprintf(stderr, "LSP: INVALID revocation secret from sender %zu "
                        "(commitment %lu) — rejecting\n",
                        sender_idx, (unsigned long)old_cn);
                secure_zero(rev_secret, 32);
                cJSON_Delete(ack_msg.json);
                free(old_sender_htlcs);
                return 0;
            }
            channel_receive_revocation(sender_ch, old_cn, rev_secret);
            watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                (uint32_t)sender_idx, old_cn,
                old_sender_local, old_sender_remote,
                old_sender_htlcs, old_sender_n_htlcs);
            /* Store next per-commitment point from peer */
            secp256k1_pubkey next_pcp;
            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33)) {
                channel_set_remote_pcp(sender_ch, sender_ch->commitment_number + 1, &next_pcp);
                /* Begin batch for sender-side persists (PCS/PCP + balance + HTLC) */
                if (mgr->persist && !persist_in_transaction((persist_t *)mgr->persist)) {
                    persist_begin((persist_t *)mgr->persist);
                    sender_batch = 1;
                }
                /* Persist remote PCPs for crash recovery */
                if (mgr->persist) {
                    unsigned char ser[33];
                    size_t slen = 33;
                    secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &slen, &next_pcp,
                                                   SECP256K1_EC_COMPRESSED);
                    persist_save_remote_pcp((persist_t *)mgr->persist,
                        (uint32_t)sender_idx,
                        sender_ch->commitment_number + 1, ser);
                }
                /* Persist LSP's own local PCS for sender channel */
                unsigned char pcs[32];
                if (channel_get_local_pcs(sender_ch, sender_ch->commitment_number, pcs))
                    persist_save_local_pcs((persist_t *)mgr->persist,
                        (uint32_t)sender_idx, sender_ch->commitment_number, pcs);
                if (channel_get_local_pcs(sender_ch, sender_ch->commitment_number + 1, pcs))
                    persist_save_local_pcs((persist_t *)mgr->persist,
                        (uint32_t)sender_idx, sender_ch->commitment_number + 1, pcs);
                memset(pcs, 0, 32);
            }
            /* Bidirectional: send LSP's own revocation to sender */
            lsp_send_revocation(mgr, lsp, sender_idx, old_cn);
        }
        cJSON_Delete(ack_msg.json);
    }
    free(old_sender_htlcs);

    /* Persist sender channel balance + HTLC atomically (crash-state protection) */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        int own_txn = !persist_in_transaction(db);
        if (own_txn) persist_begin(db);

        persist_update_channel_balance(db,
            (uint32_t)sender_idx,
            sender_ch->local_amount, sender_ch->remote_amount,
            sender_ch->commitment_number);

        htlc_t sender_persist;
        memset(&sender_persist, 0, sizeof(sender_persist));
        sender_persist.id = new_htlc_id;
        sender_persist.direction = HTLC_RECEIVED;
        sender_persist.state = HTLC_STATE_ACTIVE;
        sender_persist.amount_sats = amount_sats;
        memcpy(sender_persist.payment_hash, payment_hash, 32);
        sender_persist.cltv_expiry = cltv_expiry;
        persist_save_htlc(db, (uint32_t)sender_idx, &sender_persist);

        if (own_txn) persist_commit(db);
    }
    /* Commit sender batch (PCS/PCP + balance + HTLC in one fsync) */
    if (sender_batch)
        persist_commit((persist_t *)mgr->persist);

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
            /* Persist origin + counter atomically */
            if (mgr->persist) {
                persist_t *db = (persist_t *)mgr->persist;
                int own_txn = !persist_in_transaction(db);
                if (own_txn) persist_begin(db);
                persist_save_htlc_origin(db,
                    payment_hash, 0, request_id, sender_idx, new_htlc_id);
                persist_save_counter(db,
                                      "next_request_id", mgr->next_request_id);
                if (own_txn) persist_commit(db);
            }
        } else if (mgr->persist) {
            persist_save_counter((persist_t *)mgr->persist,
                                  "next_request_id", mgr->next_request_id);
        }
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
    htlc_t *old_dest_htlcs = old_dest_n_htlcs > 0
        ? malloc(old_dest_n_htlcs * sizeof(htlc_t)) : NULL;
    if (old_dest_n_htlcs > 0 && !old_dest_htlcs) return 0;
    if (old_dest_n_htlcs > 0)
        memcpy(old_dest_htlcs, dest_ch->htlcs, old_dest_n_htlcs * sizeof(htlc_t));

    /* Apply routing fee (LSP retains the difference in its channel balance) */
    uint64_t fwd_amount_sats = amount_sats;
    uint64_t fwd_amount_msat = amount_msat;
    if (mgr->routing_fee_ppm > 0) {
        uint64_t fee_msat = (amount_msat * mgr->routing_fee_ppm + 999999) / 1000000;
        if (fee_msat >= amount_msat) {
            fprintf(stderr, "LSP: routing fee exceeds payment amount\n");
            free(old_dest_htlcs);
            return 0;
        }
        fwd_amount_msat = amount_msat - fee_msat;
        fwd_amount_sats = fwd_amount_msat / 1000;
        if (fwd_amount_sats == 0) { free(old_dest_htlcs); return 0; }
        /* Track accumulated fees for profit settlement */
        uint64_t fee_sats = (fee_msat + 999) / 1000;
        mgr->accumulated_fees_sats += fee_sats;
        if (mgr->persist)
            persist_save_fee_settlement((persist_t *)mgr->persist, 0,
                mgr->accumulated_fees_sats, mgr->last_settlement_block);
    }

    /* CLTV delta enforcement: subtract safety margin for factory close.
       Also reject HTLCs that expire at or past the factory timeout. */
    uint32_t fwd_cltv_expiry;
    if (!lsp_validate_cltv_for_forward(cltv_expiry, &fwd_cltv_expiry,
                                        lsp->factory.cltv_timeout)) {
        fprintf(stderr, "LSP: cltv_expiry %u rejected (delta %d, factory timeout %u)\n",
                cltv_expiry, FACTORY_CLTV_DELTA, lsp->factory.cltv_timeout);
        free(old_dest_htlcs);
        return 0;
    }

    /* Add HTLC to destination's channel (offered from LSP) */
    uint64_t dest_htlc_id;
    if (!channel_add_htlc(dest_ch, HTLC_OFFERED, fwd_amount_sats,
                           payment_hash, fwd_cltv_expiry, &dest_htlc_id)) {
        fprintf(stderr, "LSP: forward add_htlc failed to client %zu\n", dest_idx);
        free(old_dest_htlcs);
        return 0;
    }

    /* Persist in-flight HTLC BEFORE commitment exchange.
       If we crash after CS but before persist, the HTLC is in committed
       state but not tracked. Persisting first avoids that window. */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        htlc_t persist_htlc;
        memset(&persist_htlc, 0, sizeof(persist_htlc));
        persist_htlc.id = dest_htlc_id;
        persist_htlc.direction = HTLC_OFFERED;
        persist_htlc.state = HTLC_STATE_ACTIVE;
        persist_htlc.amount_sats = fwd_amount_sats;
        memcpy(persist_htlc.payment_hash, payment_hash, 32);
        persist_htlc.cltv_expiry = fwd_cltv_expiry;
        persist_save_htlc(db, (uint32_t)dest_idx, &persist_htlc);
    }

    /* Forward ADD_HTLC to destination */
    {
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, fwd_amount_msat,
                                                   payment_hash, fwd_cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            free(old_dest_htlcs);
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
            free(old_dest_htlcs);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            dest_chan_id,
            dest_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            free(old_dest_htlcs);
            return 0;
        }
        cJSON_Delete(cs);
        /* Fix 5: flag pending CS so reconnect can retransmit if RAA lost */
        if (mgr->persist)
            persist_save_pending_cs((persist_t *)mgr->persist,
                dest_chan_id, dest_ch->commitment_number);
    }

    int dest_batch = 0;

    /* Wait for REVOKE_AND_ACK from dest */
    {
        wire_msg_t ack_msg;
        if (!recv_expected_drain_stray(mgr, lsp, lsp->client_fds[dest_idx],
                                        &ack_msg, MSG_REVOKE_AND_ACK, 30, dest_idx)) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP: expected REVOKE_AND_ACK from dest %zu\n", dest_idx);
            free(old_dest_htlcs);
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = dest_ch->commitment_number - 1;
            if (!verify_revocation_secret(mgr->ctx, dest_ch, old_cn, rev_secret)) {
                fprintf(stderr, "LSP: INVALID revocation secret from dest %zu "
                        "(commitment %lu) — rejecting\n",
                        dest_idx, (unsigned long)old_cn);
                secure_zero(rev_secret, 32);
                cJSON_Delete(ack_msg.json);
                free(old_dest_htlcs);
                return 0;
            }
            channel_receive_revocation(dest_ch, old_cn, rev_secret);
            uint32_t wt_chan_id = dest_is_jit ?
                (uint32_t)(mgr->n_channels + dest_idx) : (uint32_t)dest_idx;
            watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                wt_chan_id, old_cn,
                old_dest_local, old_dest_remote,
                old_dest_htlcs, old_dest_n_htlcs);
            secp256k1_pubkey next_pcp;
            if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33)) {
                channel_set_remote_pcp(dest_ch, dest_ch->commitment_number + 1, &next_pcp);
                /* Begin batch for dest-side persists (PCS/PCP + balance) */
                if (mgr->persist && !persist_in_transaction((persist_t *)mgr->persist)) {
                    persist_begin((persist_t *)mgr->persist);
                    dest_batch = 1;
                }
                if (mgr->persist) {
                    unsigned char ser[33];
                    size_t slen = 33;
                    secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &slen, &next_pcp,
                                                   SECP256K1_EC_COMPRESSED);
                    persist_save_remote_pcp((persist_t *)mgr->persist,
                        (uint32_t)dest_idx,
                        dest_ch->commitment_number + 1, ser);
                }
                /* Persist LSP's own local PCS for dest channel */
                unsigned char pcs[32];
                if (channel_get_local_pcs(dest_ch, dest_ch->commitment_number, pcs))
                    persist_save_local_pcs((persist_t *)mgr->persist,
                        (uint32_t)dest_idx, dest_ch->commitment_number, pcs);
                if (channel_get_local_pcs(dest_ch, dest_ch->commitment_number + 1, pcs))
                    persist_save_local_pcs((persist_t *)mgr->persist,
                        (uint32_t)dest_idx, dest_ch->commitment_number + 1, pcs);
                memset(pcs, 0, 32);
            }
            /* Bidirectional: send LSP's own revocation to dest */
            lsp_send_revocation(mgr, lsp, dest_idx, old_cn);
        }
        cJSON_Delete(ack_msg.json);
    }
    free(old_dest_htlcs);

    /* Persist dest channel balance after successful revocation */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        int own_txn = !persist_in_transaction(db);
        if (own_txn) persist_begin(db);
        persist_update_channel_balance(db,
            (uint32_t)dest_idx,
            dest_ch->local_amount, dest_ch->remote_amount,
            dest_ch->commitment_number);
        if (own_txn) persist_commit(db);
    }
    /* Commit dest batch (PCS/PCP + balance in one fsync) */
    if (dest_batch)
        persist_commit((persist_t *)mgr->persist);

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

    /* Capture old state txid BEFORE advancing (for watchtower).
       If old state is later published on-chain, the watchtower responds
       with the new state tx and burns the L-stock output. */
    size_t pre_node_idx = f->leaf_node_indices[leaf_side];
    unsigned char old_leaf_txid[32];
    int had_old_signed = (f->nodes[pre_node_idx].is_signed &&
                          f->nodes[pre_node_idx].signed_tx.len > 0);
    if (had_old_signed)
        memcpy(old_leaf_txid, f->nodes[pre_node_idx].txid, 32);

    /* Step 1: Advance DW counter + rebuild unsigned tx */
    int rc = factory_advance_leaf_unsigned(f, leaf_side);
    if (rc == 0) {
        fprintf(stderr, "LSP: leaf %d DW fully exhausted\n", leaf_side);
        return 0;
    }
    if (rc == -1) {
        /* Root advanced + full rebuild needed — too complex for per-leaf flow.
           This is rare and should trigger a factory rotation instead. */
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
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair))
        return 0;

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
    if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[leaf_side], &psig_msg, 30) ||
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
    if (!secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }
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

    /* Register old leaf state with watchtower for breach detection.
       If the old state is broadcast, the watchtower responds with the
       new (latest) signed state tx and burns the old L-stock output. */
    if (had_old_signed && mgr->watchtower) {
        factory_node_t *leaf_node = &f->nodes[node_idx];

        /* Build burn TX for old state's L-stock output */
        tx_buf_t burn_tx;
        tx_buf_init(&burn_tx, 256);
        uint32_t old_epoch = f->counter.current_epoch > 0
                           ? f->counter.current_epoch - 1 : 0;
        size_t l_vout = leaf_node->n_outputs - 1;
        int burn_ok = factory_build_burn_tx(f, &burn_tx,
            old_leaf_txid, (uint32_t)l_vout,
            leaf_node->outputs[l_vout].amount_sats, old_epoch);

        /* Collect channel indices that live on this leaf node */
        uint32_t leaf_ch_ids[FACTORY_MAX_SIGNERS];
        size_t n_leaf_ch = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            size_t c_node; uint32_t c_vout;
            client_to_leaf(c, f, &c_node, &c_vout);
            if (c_node == node_idx)
                leaf_ch_ids[n_leaf_ch++] = (uint32_t)c;
        }
        watchtower_watch_factory_node_with_channels(mgr->watchtower,
            (uint32_t)node_idx, old_leaf_txid,
            leaf_node->signed_tx.data, leaf_node->signed_tx.len,
            burn_ok ? burn_tx.data : NULL,
            burn_ok ? burn_tx.len : 0,
            leaf_ch_ids, n_leaf_ch);
        tx_buf_free(&burn_tx);
    }

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

/* Cooperatively redistribute output amounts on an arity-2 leaf (3-of-3).
   LSP proposes new amounts; both clients agree via 2-round MuSig2 ceremony. */
int lsp_realloc_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                      int leaf_side, const uint64_t *amounts, size_t n_amounts) {
    factory_t *f = &lsp->factory;

    /* Only for arity-2 (each leaf = 2 clients, 3-of-3 signing) */
    if (f->leaf_arity != FACTORY_ARITY_2) {
        fprintf(stderr, "LSP realloc: only supported for arity-2 leaves\n");
        return 0;
    }
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    size_t node_idx = f->leaf_node_indices[leaf_side];
    factory_node_t *node = &f->nodes[node_idx];

    if (node->n_signers != 3) {
        fprintf(stderr, "LSP realloc: leaf node %zu has %zu signers, expected 3\n",
                node_idx, node->n_signers);
        return 0;
    }

    /* Get both client participant indices */
    uint32_t clients[2];
    size_t n_clients = factory_get_subtree_clients(f, (int)node_idx, clients, 2);
    if (n_clients != 2) {
        fprintf(stderr, "LSP realloc: expected 2 clients on leaf, got %zu\n", n_clients);
        return 0;
    }

    /* Step 1: Advance DW counter + rebuild unsigned tx */
    int rc = factory_advance_leaf_unsigned(f, leaf_side);
    if (rc == 0) {
        fprintf(stderr, "LSP realloc: leaf %d DW fully exhausted\n", leaf_side);
        return 0;
    }
    if (rc == -1) {
        printf("LSP realloc: leaf %d exhausted, root advanced — skipping realloc\n",
               leaf_side);
        return 1;
    }

    /* Step 2: Set new amounts */
    if (!factory_set_leaf_amounts(f, leaf_side, amounts, n_amounts)) {
        fprintf(stderr, "LSP realloc: set_leaf_amounts failed (bad amounts?)\n");
        return 0;
    }

    /* Step 3: Init signing session for the leaf node */
    if (!factory_session_init_node(f, node_idx)) {
        fprintf(stderr, "LSP realloc: session init failed for node %zu\n", node_idx);
        return 0;
    }

    /* Step 4: Generate LSP's nonce (participant 0) */
    int lsp_slot = factory_find_signer_slot(f, node_idx, 0);
    if (lsp_slot < 0) {
        fprintf(stderr, "LSP realloc: LSP not signer on node %zu\n", node_idx);
        return 0;
    }

    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair))
        return 0;

    secp256k1_musig_secnonce lsp_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                               lsp_seckey, &lsp->lsp_pubkey,
                               &node->keyagg.cache)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP realloc: nonce gen failed\n");
        return 0;
    }

    if (!factory_session_set_nonce(f, node_idx, (size_t)lsp_slot, &lsp_pubnonce)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Step 5: Send REALLOC_PROPOSE to both clients */
    unsigned char lsp_pubnonce_ser[66];
    musig_pubnonce_serialize(lsp->ctx, lsp_pubnonce_ser, &lsp_pubnonce);
    cJSON *propose = wire_build_leaf_realloc_propose(leaf_side, amounts, n_amounts,
                                                      lsp_pubnonce_ser);
    for (int ci = 0; ci < 2; ci++) {
        /* client_fds indexed by client_idx - 1 (participant_idx 1-based) */
        size_t fd_idx = (size_t)(clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_LEAF_REALLOC_PROPOSE, propose)) {
            cJSON_Delete(propose);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
    }
    cJSON_Delete(propose);

    /* Step 6: Recv REALLOC_NONCE from both clients, set their nonces */
    unsigned char all_pubnonces[3][66];
    memcpy(all_pubnonces[lsp_slot], lsp_pubnonce_ser, 66);

    for (int ci = 0; ci < 2; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        wire_msg_t nonce_msg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx], &nonce_msg, 30) ||
            nonce_msg.msg_type != MSG_LEAF_REALLOC_NONCE) {
            fprintf(stderr, "LSP realloc: expected REALLOC_NONCE from client %u, got 0x%02x\n",
                    clients[ci], nonce_msg.msg_type);
            if (nonce_msg.json) cJSON_Delete(nonce_msg.json);
            memset(lsp_seckey, 0, 32);
            return 0;
        }

        unsigned char client_pn_ser[66];
        if (!wire_parse_leaf_realloc_nonce(nonce_msg.json, client_pn_ser)) {
            fprintf(stderr, "LSP realloc: failed to parse REALLOC_NONCE\n");
            cJSON_Delete(nonce_msg.json);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        cJSON_Delete(nonce_msg.json);

        int client_slot = factory_find_signer_slot(f, node_idx, clients[ci]);
        if (client_slot < 0) {
            memset(lsp_seckey, 0, 32);
            return 0;
        }

        secp256k1_musig_pubnonce client_pubnonce;
        if (!musig_pubnonce_parse(lsp->ctx, &client_pubnonce, client_pn_ser)) {
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        if (!factory_session_set_nonce(f, node_idx, (size_t)client_slot, &client_pubnonce)) {
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        memcpy(all_pubnonces[client_slot], client_pn_ser, 66);
    }

    /* Step 7: Send REALLOC_ALL_NONCES to both clients */
    cJSON *all_nonces = wire_build_leaf_realloc_all_nonces(
        (const unsigned char (*)[66])all_pubnonces, node->n_signers);
    for (int ci = 0; ci < 2; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_LEAF_REALLOC_ALL_NONCES, all_nonces)) {
            cJSON_Delete(all_nonces);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
    }
    cJSON_Delete(all_nonces);

    /* Step 8: Finalize nonces */
    if (!factory_session_finalize_node(f, node_idx)) {
        fprintf(stderr, "LSP realloc: session finalize failed for node %zu\n", node_idx);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Step 9: Create LSP's partial sig */
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce, &lsp_kp,
                                    &node->signing_session)) {
        fprintf(stderr, "LSP realloc: partial sig failed\n");
        return 0;
    }
    if (!factory_session_set_partial_sig(f, node_idx, (size_t)lsp_slot, &lsp_psig))
        return 0;

    /* Step 10: Recv REALLOC_PSIG from both clients */
    for (int ci = 0; ci < 2; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        wire_msg_t psig_msg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx], &psig_msg, 30) ||
            psig_msg.msg_type != MSG_LEAF_REALLOC_PSIG) {
            fprintf(stderr, "LSP realloc: expected REALLOC_PSIG from client %u, got 0x%02x\n",
                    clients[ci], psig_msg.msg_type);
            if (psig_msg.json) cJSON_Delete(psig_msg.json);
            return 0;
        }

        unsigned char client_psig_ser[32];
        if (!wire_parse_leaf_realloc_psig(psig_msg.json, client_psig_ser)) {
            fprintf(stderr, "LSP realloc: failed to parse REALLOC_PSIG\n");
            cJSON_Delete(psig_msg.json);
            return 0;
        }
        cJSON_Delete(psig_msg.json);

        int client_slot = factory_find_signer_slot(f, node_idx, clients[ci]);
        if (client_slot < 0) return 0;

        secp256k1_musig_partial_sig client_psig;
        if (!musig_partial_sig_parse(lsp->ctx, &client_psig, client_psig_ser))
            return 0;
        if (!factory_session_set_partial_sig(f, node_idx, (size_t)client_slot, &client_psig))
            return 0;
    }

    /* Step 11: Aggregate + finalize */
    if (!factory_session_complete_node(f, node_idx)) {
        fprintf(stderr, "LSP realloc: session complete failed for node %zu\n", node_idx);
        return 0;
    }

    /* Step 12: Update channel amounts in lsp_channel_entry_t */
    for (int ci = 0; ci < 2; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        if (fd_idx < mgr->n_channels) {
            lsp_channel_entry_t *entry = &mgr->entries[fd_idx];
            /* The leaf outputs map to: output 0 = channel A, output 1 = channel B,
               output 2 = L-stock.  Update funding amount based on this client's output. */
            entry->channel.funding_amount = amounts[ci];  /* sats, matching channel_init */
            /* Recalculate using lsp_balance_pct (matching channel init logic) */
            uint16_t pct = mgr->lsp_balance_pct;
            if (pct == 0) pct = 50;
            if (pct > 100) pct = 100;
            fee_estimator_static_t _fe_realloc;
            fee_estimator_t *_fe_ra = mgr->fee ? (fee_estimator_t *)mgr->fee : NULL;
            if (!_fe_ra) { fee_estimator_static_init(&_fe_realloc, 1000); _fe_ra = &_fe_realloc.base; }
            uint64_t commit_fee_ra = fee_for_commitment_tx(_fe_ra, 0);
            uint64_t usable_ra = amounts[ci] > commit_fee_ra ? amounts[ci] - commit_fee_ra : 0;
            entry->channel.local_amount = (usable_ra * pct) / 100;
            entry->channel.remote_amount = usable_ra - entry->channel.local_amount;
        }
    }

    /* Step 13: Send REALLOC_DONE to both clients */
    cJSON *done = wire_build_leaf_realloc_done(leaf_side, amounts, n_amounts);
    for (size_t i = 0; i < lsp->n_clients; i++)
        wire_send(lsp->client_fds[i], MSG_LEAF_REALLOC_DONE, done);
    cJSON_Delete(done);

    /* Step 14: Persist per-leaf DW state */
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

    printf("LSP: leaf %d realloc complete (node %zu), amounts=[", leaf_side, node_idx);
    for (size_t i = 0; i < n_amounts; i++)
        printf("%s%lu", i ? "," : "", (unsigned long)amounts[i]);
    printf("]\n");

    return 1;
}

/* Buy inbound liquidity from L-stock for a client (arity-2 only).
   Moves amount_sats from L-stock (output 2) to client's channel output,
   then adjusts channel balance so purchased sats become LSP local_amount
   (= client's inbound capacity). Returns 1 on success. */
int lsp_channels_buy_liquidity(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                size_t client_idx, uint64_t amount_sats) {
    if (!mgr || !lsp) return 0;
    factory_t *f = &lsp->factory;
    if (f->leaf_arity != FACTORY_ARITY_2) {
        fprintf(stderr, "buy_liquidity: only supported for arity-2\n");
        return 0;
    }
    if (client_idx >= mgr->n_channels || amount_sats == 0) {
        fprintf(stderr, "buy_liquidity: invalid client %zu or amount 0\n", client_idx);
        return 0;
    }

    /* Map client to leaf */
    size_t node_idx;
    uint32_t vout;
    client_to_leaf(client_idx, f, &node_idx, &vout);
    factory_node_t *ln = &f->nodes[node_idx];
    if (ln->n_outputs < 3) {
        fprintf(stderr, "buy_liquidity: leaf has %zu outputs, need 3\n", ln->n_outputs);
        return 0;
    }

    /* Validate L-stock has enough (keep >= 546 dust) */
    uint64_t lstock = ln->outputs[2].amount_sats;
    if (lstock < 546 + amount_sats) {
        fprintf(stderr, "buy_liquidity: amount %llu exceeds L-stock %llu (dust limit)\n",
                (unsigned long long)amount_sats, (unsigned long long)lstock);
        return 0;
    }

    /* Build new amounts: add to client's output, subtract from L-stock */
    int leaf_side = (int)(client_idx / 2);
    uint64_t new_amounts[3];
    for (size_t k = 0; k < 3; k++)
        new_amounts[k] = ln->outputs[k].amount_sats;
    new_amounts[vout] += amount_sats;
    new_amounts[2] -= amount_sats;

    /* Perform the reallocation (DW advance + MuSig2 re-sign) */
    if (!lsp_realloc_leaf(mgr, lsp, leaf_side, new_amounts, 3)) {
        fprintf(stderr, "buy_liquidity: realloc failed\n");
        return 0;
    }

    /* Override balance split: purchased sats go to LSP local_amount
       (= client's inbound capacity) */
    size_t fd_idx = client_idx;
    if (fd_idx < mgr->n_channels) {
        lsp_channel_entry_t *entry = &mgr->entries[fd_idx];
        uint64_t add_msat = amount_sats * 1000;
        entry->channel.local_amount += add_msat;
        if (entry->channel.remote_amount >= add_msat)
            entry->channel.remote_amount -= add_msat;
        else
            entry->channel.remote_amount = 0;
    }

    printf("LSP: buy_liquidity client %zu: +%llu sats inbound from L-stock\n",
           client_idx, (unsigned long long)amount_sats);
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
    htlc_t *old_ch_htlcs = old_ch_n_htlcs > 0
        ? malloc(old_ch_n_htlcs * sizeof(htlc_t)) : NULL;
    if (old_ch_n_htlcs > 0 && !old_ch_htlcs) return 0;
    if (old_ch_n_htlcs > 0)
        memcpy(old_ch_htlcs, ch->htlcs, old_ch_n_htlcs * sizeof(htlc_t));

    /* Fulfill the HTLC on this channel (LSP offered → client fulfills) */
    if (!channel_fulfill_htlc(ch, htlc_id, preimage)) {
        fprintf(stderr, "LSP: fulfill_htlc failed for client %zu htlc %llu\n",
                client_idx, (unsigned long long)htlc_id);
        free(old_ch_htlcs);
        return 0;
    }

    /* Send COMMITMENT_SIGNED to this client (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for client %zu\n", client_idx);
            free(old_ch_htlcs);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[client_idx].channel_id,
            ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[client_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            free(old_ch_htlcs);
            return 0;
        }
        cJSON_Delete(cs);
        /* Fix 5: flag pending CS so reconnect can retransmit if RAA lost */
        if (mgr->persist)
            persist_save_pending_cs((persist_t *)mgr->persist,
                mgr->entries[client_idx].channel_id,
                ch->commitment_number);
    }

    /* Wait for REVOKE_AND_ACK */
    {
        wire_msg_t ack_msg;
        if (!recv_expected_drain_stray(mgr, lsp, lsp->client_fds[client_idx],
                                        &ack_msg, MSG_REVOKE_AND_ACK, 30, client_idx)) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            free(old_ch_htlcs);
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
    free(old_ch_htlcs);

    /* Now back-propagate: find the sender's channel that has a matching HTLC.
       We search all other channels for a received HTLC with the same payment_hash. */
    unsigned char payment_hash[32];
    /* Compute hash from preimage */
    sha256(preimage, 32, payment_hash);

    /* Deactivate fulfilled invoice in memory (enables slot reuse) */
    for (size_t iv = 0; iv < mgr->n_invoices; iv++) {
        if (mgr->invoices[iv].active &&
            memcmp(mgr->invoices[iv].payment_hash, payment_hash, 32) == 0) {
            mgr->invoices[iv].active = 0;
            break;
        }
    }

    /* Persist payee balance + deactivate invoice + delete HTLC.
       Begin a transaction that stays open until the sender side is also
       persisted (or bridge propagation completes), so the two balance
       updates are atomic.  If the LSP crashes between payee credit and
       sender debit, the DB rolls back both. */
    int fulfill_txn_started = 0;
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        if (!persist_in_transaction(db)) {
            persist_begin(db);
            fulfill_txn_started = 1;
        }

        persist_update_channel_balance(db,
            (uint32_t)client_idx,
            ch->local_amount, ch->remote_amount,
            ch->commitment_number);
        persist_deactivate_invoice(db, payment_hash);
        persist_delete_htlc(db, (uint32_t)client_idx, htlc_id);
        /* Transaction stays open — committed after sender persist below */
    }

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
        /* Commit the payee persist transaction (bridge = no sender debit) */
        if (fulfill_txn_started && mgr->persist)
            persist_commit((persist_t *)mgr->persist);
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
            htlc_t *old_sender_htlcs = old_sender_n_htlcs > 0
                ? malloc(old_sender_n_htlcs * sizeof(htlc_t)) : NULL;
            if (old_sender_n_htlcs > 0 && !old_sender_htlcs) continue;
            if (old_sender_n_htlcs > 0)
                memcpy(old_sender_htlcs, sender_ch->htlcs, old_sender_n_htlcs * sizeof(htlc_t));
            if (!channel_fulfill_htlc(sender_ch, htlc->id, preimage)) {
                fprintf(stderr, "LSP: back-fulfill failed\n");
                free(old_sender_htlcs);
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
                    free(old_sender_htlcs);
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
            if (recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[s], &ack_msg, 30) &&
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
            free(old_sender_htlcs);

            /* Persist sender balance + delete HTLC (inside the transaction
               started at payee persist above — both sides commit atomically) */
            if (mgr->persist) {
                persist_t *db = (persist_t *)mgr->persist;
                persist_update_channel_balance(db,
                    (uint32_t)s,
                    sender_ch->local_amount, sender_ch->remote_amount,
                    sender_ch->commitment_number);
                persist_delete_htlc(db, (uint32_t)s, htlc->id);
                /* Commit the atomic payee+sender transaction */
                if (fulfill_txn_started)
                    persist_commit(db);
                fulfill_txn_started = 0;
            }

            printf("LSP: HTLC fulfilled: client %zu -> client %zu (%llu sats)\n",
                   s, client_idx, (unsigned long long)htlc->amount_sats);
            sender_found = (int)s;
            break;
        }
    }

    /* Commit if transaction still open (no sender found — shouldn't happen
       for intra-factory payments, but defensive) */
    if (fulfill_txn_started && mgr->persist)
        persist_commit((persist_t *)mgr->persist);

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
        /* Delete failed HTLC from persistence */
        if (mgr->persist)
            persist_delete_htlc((persist_t *)mgr->persist,
                                  (uint32_t)client_idx, htlc_id);
        printf("LSP: HTLC %llu failed by client %zu: %s\n",
               (unsigned long long)htlc_id, client_idx, reason);
        return 1;
    }

    case MSG_REGISTER_INVOICE: {
        unsigned char payment_hash[32];
        unsigned char preimage[32];
        uint64_t amount_msat;
        size_t dest_client;
        if (!wire_parse_register_invoice(msg->json, payment_hash, preimage,
                                           &amount_msat, &dest_client))
            return 0;
        if (!lsp_channels_register_invoice(mgr, payment_hash, preimage,
                                             dest_client, amount_msat)) {
            fprintf(stderr, "LSP: register_invoice failed\n");
            return 0;
        }
        /* Also forward to bridge if connected */
        if (mgr->bridge_fd >= 0) {
            cJSON *reg = wire_build_bridge_register(payment_hash, preimage,
                                                      amount_msat, dest_client);
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

    case MSG_LEAF_ADVANCE_PSIG:
        /* Stale PSIG outside of active ceremony — discard. Active ceremony
           (lsp_advance_leaf) uses recv_timeout_service_bridge() to read
           responses directly from the affected client. */
        printf("LSP: discarding stale LEAF_ADVANCE_PSIG from client %zu\n", client_idx);
        return 1;

    case MSG_LEAF_REALLOC_NONCE:
    case MSG_LEAF_REALLOC_PSIG:
        /* Stale realloc message outside of active ceremony — discard. */
        printf("LSP: discarding stale LEAF_REALLOC msg 0x%02x from client %zu\n",
               msg->msg_type, client_idx);
        return 1;

    case MSG_INVOICE_CREATED:
        /* Stale response from a timed-out payment request — discard silently */
        return 1;

    case MSG_REVOKE_AND_ACK:
        /* Stale revocation from a timed-out commitment exchange — discard silently.
           The commitment state was already rolled back by the timeout handler. */
        return 1;

    case MSG_COMMITMENT_SIGNED:
        /* Stale commitment_signed — discard silently */
        return 1;

    case MSG_PTLC_ADAPTED_SIG:
        /* Late adapted_sig from a rotation Phase A that already timed out.
           The rotation code reads these via wire_recv_timeout with a 15s
           deadline per client; if the client responds after the deadline,
           the message sits in the fd buffer until the daemon loop picks
           it up here. Safe to discard. */
        printf("LSP: discarding stale PTLC_ADAPTED_SIG from client %zu\n",
               client_idx);
        return 1;

    case MSG_PONG:
        /* Keepalive response — daemon sends PING every 30s, clients reply PONG.
           These can arrive at any time during the event/daemon loop. */
        return 1;

    case MSG_STFU: {
        /* Quiescence request from client: acknowledge with STFU_ACK */
        lsp_channel_entry_t *entry = &mgr->entries[client_idx];
        entry->channel.channel_quiescent = 1;
        cJSON *ack = wire_build_splice_ack(entry->channel_id, 0);
        int fd = (lsp && client_idx < lsp->n_clients)
                     ? lsp->client_fds[client_idx] : -1;
        if (ack && fd >= 0)
            wire_send(fd, MSG_STFU_ACK, ack);
        cJSON_Delete(ack);
        printf("LSP: client %zu sent STFU, channel %u quiescent\n",
               client_idx, entry->channel_id);
        return 1;
    }

    case MSG_SPLICE_INIT: {
        /* Initiator sent splice proposal: parse and send SPLICE_ACK */
        uint32_t channel_id = 0;
        uint64_t new_funding_amount = 0;
        unsigned char new_spk[34];
        size_t new_spk_len = 0;
        if (!wire_parse_splice_init(msg->json, &channel_id,
                                      &new_funding_amount,
                                      new_spk, &new_spk_len, sizeof(new_spk))) {
            fprintf(stderr, "LSP: invalid SPLICE_INIT from client %zu\n", client_idx);
            return 0;
        }
        /* Mark channel quiescent for splice */
        mgr->entries[client_idx].channel.channel_quiescent = 1;
        /* Send SPLICE_ACK with no additional contribution */
        cJSON *ack = wire_build_splice_ack(channel_id, 0);
        int fd = (lsp && client_idx < lsp->n_clients)
                     ? lsp->client_fds[client_idx] : -1;
        if (ack && fd >= 0)
            wire_send(fd, MSG_SPLICE_ACK, ack);
        cJSON_Delete(ack);
        printf("LSP: SPLICE_INIT from client %zu: new_funding=%llu\n",
               client_idx, (unsigned long long)new_funding_amount);
        return 1;
    }

    case MSG_SPLICE_LOCKED: {
        /* Both sides confirmed: apply splice update */
        uint32_t channel_id = 0;
        unsigned char new_txid[32];
        uint32_t new_vout = 0;
        if (!wire_parse_splice_locked(msg->json, &channel_id,
                                        new_txid, &new_vout)) {
            fprintf(stderr, "LSP: invalid SPLICE_LOCKED from client %zu\n", client_idx);
            return 0;
        }
        channel_t *ch = &mgr->entries[client_idx].channel;
        /* amount stays the same unless we tracked it — use existing funding amount */
        channel_apply_splice_update(ch, new_txid, new_vout, ch->funding_amount);
        printf("LSP: SPLICE_LOCKED applied for client %zu, channel %u\n",
               client_idx, channel_id);
        return 1;
    }

    case MSG_LSPS_REQUEST: {
        lsps_ctx_t lsps_ctx = {
            .mgr        = mgr,
            .lsp        = lsp,
            .client_idx = client_idx,
        };
        int fd = (lsp && client_idx < lsp->n_clients)
                     ? lsp->client_fds[client_idx] : -1;
        return lsps_handle_request(&lsps_ctx, fd, msg->json);
    }

    case MSG_ERROR: {
        cJSON *m = msg->json ? cJSON_GetObjectItem(msg->json, "message") : NULL;
        fprintf(stderr, "LSP: client %zu sent error: %s\n",
                client_idx,
                (m && cJSON_IsString(m)) ? m->valuestring : "(unknown)");
        return 0;  /* close the connection */
    }

    case MSG_QUEUE_POLL: {
        /* Client is polling for pending work items. Drain the queue and reply. */
        persist_t *db = (persist_t *)mgr->persist;
        queue_entry_t entries[16];
        size_t n = 0;
        if (db)
            n = queue_drain(db, (uint32_t)client_idx, entries, 16);
        cJSON *items_json = wire_build_queue_items(entries, n);
        if (!wire_send(lsp->client_fds[client_idx], MSG_QUEUE_ITEMS, items_json)) {
            cJSON_Delete(items_json);
            return 0;
        }
        cJSON_Delete(items_json);
        return 1;
    }

    case MSG_QUEUE_DONE: {
        /* Client has processed a set of queue items; delete them from the queue
           and, if any were QUEUE_REQ_ROTATION, mark this client as ready. */
        uint64_t ids[64];
        size_t count = 0;
        if (!wire_parse_queue_done(msg->json, ids, 64, &count))
            return 0;

        persist_t *db = (persist_t *)mgr->persist;
        int has_rotation_ack = 0;
        for (size_t i = 0; i < count; i++) {
            if (db) {
                queue_entry_t entry;
                if (queue_get(db, ids[i], &entry) &&
                    entry.request_type == QUEUE_REQ_ROTATION)
                    has_rotation_ack = 1;
                queue_delete(db, ids[i]);
            }
        }

        if (has_rotation_ack && mgr->readiness) {
            readiness_tracker_t *rt = (readiness_tracker_t *)mgr->readiness;
            readiness_set_ready(rt, (uint32_t)client_idx, QUEUE_REQ_ROTATION);
            printf("LSP: client %zu acknowledged rotation — %zu/%zu ready\n",
                   client_idx,
                   (size_t)readiness_count_ready(rt),
                   rt->n_clients);
        }
        return 1;
    }

    default:
        fprintf(stderr, "LSP: unexpected msg 0x%02x from client %zu\n",
                msg->msg_type, client_idx);
        return 0;
    }
}

/* Bridge/invoice functions moved to lsp_bridge.c */

/* --- Reconnection (Phase 16) --- */

/* Replay pending HTLC forwards to a reconnected client (Gap 2C).
   Scans all channels for ACTIVE RECEIVED HTLCs whose invoice destination
   matches the reconnected client. For each unforwarded HTLC, re-does the
   forward: channel_add_htlc → ADD_HTLC → COMMITMENT_SIGNED →
   wait for REVOKE_AND_ACK → persist. */
static void replay_pending_htlcs(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t reconnected_idx) {
    if (!mgr || !lsp) return;

    /* Skip replay if factory is expired — forwarding HTLCs is pointless
       when the factory can no longer advance DW state. */
    if (lsp->factory.n_nodes == 0) return;
    {
        int h = mgr->watchtower && mgr->watchtower->rt ?
                regtest_get_block_height(mgr->watchtower->rt) : 0;
        if (h > 0 && factory_get_state(&lsp->factory, (uint32_t)h) == FACTORY_EXPIRED)
            return;
    }

    for (size_t src = 0; src < mgr->n_channels; src++) {
        if (src == reconnected_idx) continue;
        channel_t *src_ch = &mgr->entries[src].channel;

        for (size_t h = 0; h < src_ch->n_htlcs; h++) {
            htlc_t *htlc = &src_ch->htlcs[h];
            if (htlc->state != HTLC_STATE_ACTIVE) continue;
            if (htlc->direction != HTLC_RECEIVED) continue;

            /* Check if this HTLC is destined for the reconnected client */
            size_t dest_client;
            if (!lsp_channels_lookup_invoice(mgr, htlc->payment_hash, &dest_client))
                continue;
            if (dest_client != reconnected_idx) continue;

            /* Check if HTLC is already on the dest channel (already forwarded) */
            channel_t *dest_ch = &mgr->entries[reconnected_idx].channel;
            int already_forwarded = 0;
            for (size_t dh = 0; dh < dest_ch->n_htlcs; dh++) {
                if (dest_ch->htlcs[dh].state == HTLC_STATE_ACTIVE &&
                    memcmp(dest_ch->htlcs[dh].payment_hash, htlc->payment_hash, 32) == 0) {
                    already_forwarded = 1;
                    break;
                }
            }
            if (already_forwarded) continue;

            /* Forward this HTLC to the reconnected client */
            uint64_t old_dest_local = dest_ch->local_amount;
            uint64_t old_dest_remote = dest_ch->remote_amount;
            size_t old_dest_n_htlcs = dest_ch->n_htlcs;
            htlc_t *old_dest_htlcs = old_dest_n_htlcs > 0
                ? malloc(old_dest_n_htlcs * sizeof(htlc_t)) : NULL;
            if (old_dest_n_htlcs > 0 && !old_dest_htlcs) continue;
            if (old_dest_n_htlcs > 0)
                memcpy(old_dest_htlcs, dest_ch->htlcs, old_dest_n_htlcs * sizeof(htlc_t));

            uint64_t dest_htlc_id;
            if (!channel_add_htlc(dest_ch, HTLC_OFFERED,
                                    htlc->amount_sats, htlc->payment_hash,
                                    htlc->cltv_expiry, &dest_htlc_id)) {
                fprintf(stderr, "LSP: HTLC replay add failed for client %zu\n",
                        reconnected_idx);
                free(old_dest_htlcs);
                continue;
            }

            /* Persist the forwarded HTLC */
            if (mgr->persist) {
                persist_t *db = (persist_t *)mgr->persist;
                htlc_t persist_htlc;
                memset(&persist_htlc, 0, sizeof(persist_htlc));
                persist_htlc.id = dest_htlc_id;
                persist_htlc.direction = HTLC_OFFERED;
                persist_htlc.state = HTLC_STATE_ACTIVE;
                persist_htlc.amount_sats = htlc->amount_sats;
                memcpy(persist_htlc.payment_hash, htlc->payment_hash, 32);
                persist_htlc.cltv_expiry = htlc->cltv_expiry;
                persist_save_htlc(db, (uint32_t)reconnected_idx, &persist_htlc);
            }

            /* Send ADD_HTLC to dest */
            cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, htlc->amount_sats,
                                                       htlc->payment_hash, htlc->cltv_expiry);
            if (!wire_send(lsp->client_fds[reconnected_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
                cJSON_Delete(fwd);
                free(old_dest_htlcs);
                continue;
            }
            cJSON_Delete(fwd);

            /* Send COMMITMENT_SIGNED (real partial sig) */
            {
                unsigned char psig32[32];
                uint32_t nonce_idx;
                if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx)) {
                    fprintf(stderr, "LSP: replay partial sig failed for client %zu\n",
                            reconnected_idx);
                    free(old_dest_htlcs);
                    continue;
                }
                cJSON *cs = wire_build_commitment_signed(
                    mgr->entries[reconnected_idx].channel_id,
                    dest_ch->commitment_number, psig32, nonce_idx);
                if (!wire_send(lsp->client_fds[reconnected_idx], MSG_COMMITMENT_SIGNED, cs)) {
                    cJSON_Delete(cs);
                    free(old_dest_htlcs);
                    continue;
                }
                cJSON_Delete(cs);
            }

            /* Wait for REVOKE_AND_ACK from dest */
            {
                wire_msg_t ack_msg;
                if (!recv_expected_drain_stray(mgr, lsp,
                        lsp->client_fds[reconnected_idx], &ack_msg,
                        MSG_REVOKE_AND_ACK, 30, reconnected_idx)) {
                    if (ack_msg.json) cJSON_Delete(ack_msg.json);
                    fprintf(stderr, "LSP: replay REVOKE_AND_ACK timeout for client %zu\n",
                            reconnected_idx);
                    free(old_dest_htlcs);
                    continue;
                }
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = dest_ch->commitment_number - 1;
                    if (!verify_revocation_secret(mgr->ctx, dest_ch, old_cn, rev_secret)) {
                        fprintf(stderr, "LSP: INVALID revocation secret from reconnected "
                                "client %zu (commitment %lu)\n",
                                reconnected_idx, (unsigned long)old_cn);
                        secure_zero(rev_secret, 32);
                        cJSON_Delete(ack_msg.json);
                        free(old_dest_htlcs);
                        continue;
                    }
                    channel_receive_revocation(dest_ch, old_cn, rev_secret);
                    watchtower_watch_revoked_commitment(mgr->watchtower, dest_ch,
                        (uint32_t)reconnected_idx, old_cn,
                        old_dest_local, old_dest_remote,
                        old_dest_htlcs, old_dest_n_htlcs);
                    secp256k1_pubkey next_pcp;
                    if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                        channel_set_remote_pcp(dest_ch, dest_ch->commitment_number + 1, &next_pcp);
                    lsp_send_revocation(mgr, lsp, reconnected_idx, old_cn);
                }
                cJSON_Delete(ack_msg.json);
            }

            /* Persist dest channel balance after replay (Gap 2B) */
            if (mgr->persist)
                persist_update_channel_balance((persist_t *)mgr->persist,
                    (uint32_t)reconnected_idx,
                    dest_ch->local_amount, dest_ch->remote_amount,
                    dest_ch->commitment_number);

            printf("LSP: replayed HTLC to client %zu (amount=%llu, htlc_id=%llu)\n",
                   reconnected_idx, (unsigned long long)htlc->amount_sats,
                   (unsigned long long)dest_htlc_id);
            free(old_dest_htlcs);
        }
    }
}

/* Find client slot by pubkey. Returns index or -1 if not found. */
static int find_client_slot_by_pubkey(const lsp_t *lsp,
                                       const secp256k1_context *ctx,
                                       const secp256k1_pubkey *pk) {
    unsigned char pk_ser[33], cmp_ser[33];
    size_t len1 = 33, len2 = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pk_ser, &len1, pk,
                                        SECP256K1_EC_COMPRESSED))
        return -1;
    for (size_t c = 0; c < lsp->n_clients; c++) {
        len2 = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, cmp_ser, &len2,
                                            &lsp->client_pubkeys[c],
                                            SECP256K1_EC_COMPRESSED))
            continue;
        if (memcmp(pk_ser, cmp_ser, 33) == 0)
            return (int)c;
    }
    return -1;
}

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
    if (!secp256k1_ec_pubkey_serialize(mgr->ctx, client_ser, &len1, &client_pk,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    for (size_t c = 0; c < lsp->n_clients; c++) {
        len2 = 33;
        if (!secp256k1_ec_pubkey_serialize(mgr->ctx, cmp_ser, &len2,
                                            &lsp->client_pubkeys[c],
                                            SECP256K1_EC_COMPRESSED))
            return 0;
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

    /* 4. Verify commitment_number matches (Gap 2B: proper reconciliation) */
    channel_t *ch = &mgr->entries[c].channel;
    if (commitment_number != ch->commitment_number) {
        int64_t diff = (int64_t)ch->commitment_number - (int64_t)commitment_number;

        if (diff == 1 && mgr->persist) {
            /* LSP is 1 ahead: last operation wasn't confirmed by client.
               Roll back to last committed state from persistence. */
            uint64_t db_local, db_remote, db_cn;
            if (persist_load_channel_state((persist_t *)mgr->persist,
                    (uint32_t)c, &db_local, &db_remote, &db_cn)) {
                ch->local_amount = db_local;
                ch->remote_amount = db_remote;
                ch->commitment_number = db_cn;
                ch->n_htlcs = persist_load_htlcs((persist_t *)mgr->persist,
                    (uint32_t)c, ch->htlcs, MAX_HTLCS);
                printf("LSP: rolled back channel %zu to committed state "
                       "(cn=%llu)\n", c, (unsigned long long)db_cn);
            } else {
                fprintf(stderr, "LSP: rollback failed — no DB state for %zu\n", c);
                wire_close(new_fd);
                return 0;
            }
        } else if (diff == -1 && mgr->persist) {
            /* Client is 1 ahead: LSP crashed after client committed but
               before LSP persisted. Accept client's commitment_number. */
            ch->commitment_number = commitment_number;
            uint64_t db_local, db_remote, db_cn;
            if (persist_load_channel_state((persist_t *)mgr->persist,
                    (uint32_t)c, &db_local, &db_remote, &db_cn)) {
                ch->local_amount = db_local;
                ch->remote_amount = db_remote;
                ch->n_htlcs = persist_load_htlcs((persist_t *)mgr->persist,
                    (uint32_t)c, ch->htlcs, MAX_HTLCS);
            }
            printf("LSP: accepted client %zu commitment_number %llu "
                   "(LSP was behind)\n", c, (unsigned long long)commitment_number);
        } else {
            /* Large mismatch or no persistence: irreconcilable */
            fprintf(stderr, "LSP reconnect: irreconcilable commitment mismatch "
                    "(client=%llu, lsp=%llu, diff=%lld) for slot %zu — "
                    "closing connection\n",
                    (unsigned long long)commitment_number,
                    (unsigned long long)ch->commitment_number,
                    (long long)diff, c);
            wire_close(new_fd);
            return 0;
        }
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

    /* 6b. Restore remote per-commitment points from DB */
    if (mgr->persist) {
        unsigned char pcp_ser[33];
        secp256k1_pubkey pcp;
        if (persist_load_remote_pcp((persist_t *)mgr->persist, (uint32_t)c,
                ch->commitment_number, pcp_ser) &&
            secp256k1_ec_pubkey_parse(mgr->ctx, &pcp, pcp_ser, 33))
            channel_set_remote_pcp(ch, ch->commitment_number, &pcp);
        if (persist_load_remote_pcp((persist_t *)mgr->persist, (uint32_t)c,
                ch->commitment_number + 1, pcp_ser) &&
            secp256k1_ec_pubkey_parse(mgr->ctx, &pcp, pcp_ser, 33))
            channel_set_remote_pcp(ch, ch->commitment_number + 1, &pcp);
    }

    /* 6c. Restore LSP's own local PCS from DB */
    if (mgr->persist) {
        size_t pcs_max = (size_t)(ch->commitment_number + 2);
        unsigned char (*pcs_arr)[32] = calloc(pcs_max, 32);
        if (pcs_arr) {
            size_t pcs_loaded = 0;
            persist_load_local_pcs((persist_t *)mgr->persist, (uint32_t)c,
                                    pcs_arr, pcs_max, &pcs_loaded);
            for (uint64_t cn = 0; cn < pcs_max; cn++) {
                int nonzero = 0;
                for (int j = 0; j < 32; j++)
                    if (pcs_arr[cn][j]) { nonzero = 1; break; }
                if (nonzero)
                    channel_set_local_pcs(ch, cn, pcs_arr[cn]);
            }
            memset(pcs_arr, 0, pcs_max * 32);
            free(pcs_arr);
        }
        /* Generate PCS for any missing commitment numbers */
        for (uint64_t cn = ch->n_local_pcs; cn <= ch->commitment_number + 1; cn++)
            channel_generate_local_pcs(ch, cn);
    }

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
        if (!wire_recv_timeout(new_fd, &nonce_resp, 30)) {
            fprintf(stderr, "LSP reconnect: expected CHANNEL_NONCES from client\n");
            if (nonce_resp.json) cJSON_Delete(nonce_resp.json);
            return 0;
        }
        if (nonce_resp.msg_type == MSG_ERROR) {
            cJSON *m = nonce_resp.json ? cJSON_GetObjectItem(nonce_resp.json, "message") : NULL;
            fprintf(stderr, "LSP reconnect: client sent error: %s\n",
                    (m && cJSON_IsString(m)) ? m->valuestring : "(unknown)");
            cJSON_Delete(nonce_resp.json);
            return 0;
        }
        if (nonce_resp.msg_type != MSG_CHANNEL_NONCES) {
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

    /* Fix 5: CS retransmit — if a COMMITMENT_SIGNED was pending when the client
       disconnected, retransmit it now using fresh nonces from the exchange above.
       This is NOT a replay: channel_create_commitment_partial_sig generates a
       new psig with the new nonces (MuSig2 nonce reuse avoided). */
    if (mgr->persist) {
        persist_t *pcs_db = (persist_t *)mgr->persist;
        uint64_t pending_cn = 0;
        if (persist_load_pending_cs(pcs_db, mgr->entries[c].channel_id, &pending_cn) &&
            pending_cn == ch->commitment_number) {
            unsigned char pcs_psig32[32];
            uint32_t pcs_nonce_idx;
            if (channel_create_commitment_partial_sig(ch, pcs_psig32, &pcs_nonce_idx)) {
                cJSON *pcs_cs = wire_build_commitment_signed(
                    mgr->entries[c].channel_id,
                    ch->commitment_number, pcs_psig32, pcs_nonce_idx);
                if (wire_send(new_fd, MSG_COMMITMENT_SIGNED, pcs_cs)) {
                    fprintf(stderr, "LSP reconnect: retransmitted pending CS "
                            "(cn=%llu) to client %zu\n",
                            (unsigned long long)ch->commitment_number, c);
                    /* Wait for RAA before RECONNECT_ACK */
                    wire_msg_t pcs_raa;
                    if (wire_recv_timeout(new_fd, &pcs_raa, 30) &&
                        pcs_raa.msg_type == MSG_REVOKE_AND_ACK) {
                        uint32_t pcs_ack_id;
                        unsigned char pcs_rev[32], pcs_np[33];
                        if (wire_parse_revoke_and_ack(pcs_raa.json, &pcs_ack_id,
                                                        pcs_rev, pcs_np)) {
                            uint64_t old_pcn = ch->commitment_number - 1;
                            channel_receive_revocation(ch, old_pcn, pcs_rev);
                        }
                        cJSON_Delete(pcs_raa.json);
                        persist_save_pending_cs(pcs_db,
                            mgr->entries[c].channel_id, 0); /* clear */
                    } else {
                        if (pcs_raa.json) cJSON_Delete(pcs_raa.json);
                        fprintf(stderr, "LSP reconnect: RAA timeout after CS retransmit "
                                "(client %zu) — clearing stale pending_cs\n", c);
                        /* Clear pending_cs to prevent infinite retransmit on
                           every future reconnect.  The client already processed
                           the CS on the first attempt. */
                        persist_save_pending_cs(pcs_db,
                            mgr->entries[c].channel_id, 0);
                    }
                }
                cJSON_Delete(pcs_cs);
            }
        }
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

    /* Replay any pending HTLC forwards to this client (Gap 2C) */
    replay_pending_htlcs(mgr, lsp, c);

    if (mgr->readiness)
        readiness_set_connected((readiness_tracker_t *)mgr->readiness,
                                (uint32_t)c, 1);

    printf("LSP: client %zu reconnected (commitment=%llu)\n",
           c, (unsigned long long)ch->commitment_number);
    return 1;
}

int lsp_channels_handle_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, int new_fd) {
    if (!mgr || !lsp || new_fd < 0) return 0;

    /* Read MSG_RECONNECT */
    wire_msg_t msg;
    if (!wire_recv_timeout(new_fd, &msg, 30) || msg.msg_type != MSG_RECONNECT) {
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
                                         uint64_t close_fee,
                                         const unsigned char *close_spk,
                                         size_t close_spk_len) {
    if (!mgr || !factory || !outputs) return 0;

    /* Use override SPK if provided, otherwise fall back to factory funding SPK */
    const unsigned char *spk = close_spk ? close_spk : factory->funding_spk;
    size_t spk_len = close_spk ? close_spk_len : factory->funding_spk_len;

    /* Output 0: LSP gets factory_funding - sum(client_remotes) - close_fee.
       In a cooperative close that bypasses the tree, the LSP recovers the
       tree transaction fees (funding_amount - sum_of_leaf_outputs). */
    uint64_t client_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++)
        client_total += mgr->entries[c].channel.remote_amount;

    if (factory->funding_amount_sats < client_total + close_fee) return 0;
    uint64_t lsp_total = factory->funding_amount_sats - client_total - close_fee;

    outputs[0].amount_sats = lsp_total;
    memcpy(outputs[0].script_pubkey, spk, spk_len);
    outputs[0].script_pubkey_len = spk_len;

    /* Outputs 1..N: each client gets their remote_amount.
       When close_spk override is active, all outputs use it (rotation/recycling).
       Otherwise, each client output uses their per-client close address.
       Skip dust outputs (< 546 sats) — fold them back into the LSP output. */
    size_t n_outs = 1;  /* output 0 = LSP */
    uint64_t dust_reclaimed = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        uint64_t amt = mgr->entries[c].channel.remote_amount;
        if (amt < 546) {
            dust_reclaimed += amt;
            continue;
        }
        outputs[n_outs].amount_sats = amt;
        if (!close_spk && mgr->entries[c].close_spk_len > 0) {
            memcpy(outputs[n_outs].script_pubkey, mgr->entries[c].close_spk,
                   mgr->entries[c].close_spk_len);
            outputs[n_outs].script_pubkey_len = mgr->entries[c].close_spk_len;
        } else {
            memcpy(outputs[n_outs].script_pubkey, spk, spk_len);
            outputs[n_outs].script_pubkey_len = spk_len;
        }
        n_outs++;
    }
    outputs[0].amount_sats += dust_reclaimed;

    /* Invariant: sum of outputs + close_fee == funding_amount */
    uint64_t sum = close_fee;
    for (size_t i = 0; i < n_outs; i++)
        sum += outputs[i].amount_sats;
    if (sum != factory->funding_amount_sats) {
        fprintf(stderr, "lsp_channels_build_close_outputs: balance invariant failed "
                "(%llu vs %llu)\n", (unsigned long long)sum,
                (unsigned long long)factory->funding_amount_sats);
        return 0;
    }

    return n_outs;
}

int lsp_channels_settle_profits(lsp_channel_mgr_t *mgr, const factory_t *factory) {
    if (!mgr || !factory) return 0;
    if (mgr->economic_mode != ECON_PROFIT_SHARED) return 0;
    if (mgr->accumulated_fees_sats == 0) return 0;

    int settled = 0;
    for (size_t i = 0; i < mgr->n_channels; i++) {
        /* Client participant index = i + 1 (0 = LSP) */
        uint32_t pidx = (uint32_t)(i + 1);
        if (pidx >= factory->n_participants) continue;

        uint16_t bps = factory->profiles[pidx].profit_share_bps;
        if (bps == 0) continue;

        uint64_t share = (mgr->accumulated_fees_sats * bps) / 10000;
        if (share == 0) continue;

        /* Shift balance from LSP-local to client-remote */
        channel_t *ch = &mgr->entries[i].channel;
        if (ch->local_amount >= share) {
            ch->local_amount -= share;
            ch->remote_amount += share;
            settled++;
        }
    }

    if (settled > 0)
        mgr->accumulated_fees_sats = 0;

    return settled;
}

uint64_t lsp_channels_unsettled_share(const lsp_channel_mgr_t *mgr,
                                       const factory_t *factory,
                                       size_t client_idx) {
    if (!mgr || !factory) return 0;
    if (mgr->economic_mode != ECON_PROFIT_SHARED) return 0;
    if (mgr->accumulated_fees_sats == 0) return 0;

    uint32_t pidx = (uint32_t)(client_idx + 1);
    if (pidx >= factory->n_participants) return 0;

    uint16_t bps = factory->profiles[pidx].profit_share_bps;
    return (mgr->accumulated_fees_sats * bps) / 10000;
}

int lsp_channels_run_event_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t expected_msgs) {
    if (!mgr || !lsp) return 0;

    size_t handled = 0;

    /* Allocate pollfd array: clients + optional bridge */
    size_t max_pfds = mgr->n_channels + 1;
    struct pollfd *pfds = (struct pollfd *)calloc(max_pfds, sizeof(struct pollfd));
    if (!pfds) return 0;

    while (handled < expected_msgs) {
        int nfds = 0;

        for (size_t c = 0; c < mgr->n_channels; c++) {
            pfds[nfds].fd = lsp->client_fds[c];
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        int bridge_slot = -1;
        if (mgr->bridge_fd >= 0) {
            pfds[nfds].fd = mgr->bridge_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            bridge_slot = nfds++;
        }

        int ret = poll(pfds, (nfds_t)nfds, 30000);
        if (ret <= 0) {
            fprintf(stderr, "LSP event loop: poll timeout/error (handled %zu/%zu)\n",
                    handled, expected_msgs);
            free(pfds);
            return 0;
        }

        /* Handle bridge messages */
        if (bridge_slot >= 0 && (pfds[bridge_slot].revents & POLLIN)) {
            wire_msg_t msg;
            if (!wire_recv(mgr->bridge_fd, &msg)) {
                fprintf(stderr, "LSP event loop: bridge recv failed\n");
                mgr->bridge_fd = -1;
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
            if (!(pfds[c].revents & POLLIN)) continue;

            wire_msg_t msg;
            if (!wire_recv(lsp->client_fds[c], &msg)) {
                fprintf(stderr, "LSP event loop: recv failed from client %zu\n", c);
                free(pfds);
                return 0;
            }

            if (!lsp_channels_handle_msg(mgr, lsp, c, &msg)) {
                fprintf(stderr, "LSP event loop: handle_msg failed for client %zu "
                        "msg 0x%02x\n", c, msg.msg_type);
                cJSON_Delete(msg.json);
                free(pfds);
                return 0;
            }
            cJSON_Delete(msg.json);
            handled++;
        }
    }

    free(pfds);
    return 1;
}

/* Factory rotation moved to lsp_rotation.c */

int lsp_channels_handle_cli_line(lsp_channel_mgr_t *mgr, void *lsp_ptr,
                                  const char *line,
                                  volatile sig_atomic_t *shutdown_flag) {
    lsp_t *lsp = (lsp_t *)lsp_ptr;
    size_t len = strlen(line);

    if (strncmp(line, "pay ", 4) == 0 || strncmp(line, "rebalance ", 10) == 0) {
        int is_rebalance = (line[0] == 'r');
        const char *args = line + (is_rebalance ? 10 : 4);
        const char *cmd_name = is_rebalance ? "rebalance" : "pay";
        unsigned int from, to;
        unsigned long long amt;
        if (sscanf(args, "%u %u %llu", &from, &to, &amt) == 3) {
            if (from >= mgr->n_channels || to >= mgr->n_channels) {
                printf("CLI: invalid client index (max %zu)\n",
                       mgr->n_channels - 1);
            } else if (from == to) {
                printf("CLI: cannot %s self\n", cmd_name);
            } else {
                printf("CLI: %s %u \xe2\x86\x92 %u (%llu sats)\n", cmd_name, from, to, amt);
                fflush(stdout);
                if (lsp_channels_initiate_payment(mgr, lsp,
                        (size_t)from, (size_t)to, (uint64_t)amt))
                    printf("CLI: %s succeeded\n", cmd_name);
                else
                    printf("CLI: %s FAILED\n", cmd_name);
            }
        } else {
            printf("CLI: usage: %s <from> <to> <amount>\n", cmd_name);
        }
        fflush(stdout);
    } else if (strcmp(line, "status") == 0) {
        printf("--- Factory Status ---\n");
        printf("  Channels: %zu\n", mgr->n_channels);
        for (size_t c = 0; c < mgr->n_channels; c++) {
            channel_t *ch = &mgr->entries[c].channel;
            printf("  Channel %zu: local=%llu remote=%llu cn=%llu fd=%d%s\n",
                   c,
                   (unsigned long long)ch->local_amount,
                   (unsigned long long)ch->remote_amount,
                   (unsigned long long)ch->commitment_number,
                   lsp->client_fds[c],
                   mgr->entries[c].offline_detected ? " [offline]" : "");
        }
        if (mgr->watchtower && mgr->watchtower->rt) {
            int h = regtest_get_block_height(mgr->watchtower->rt);
            factory_state_t fs = factory_get_state(&lsp->factory, (uint32_t)h);
            const char *fs_names[] = {"ACTIVE","DYING","EXPIRED"};
            int fsi = (int)fs;
            printf("  Factory state: %s (height=%d)\n",
                   (fsi >= 0 && fsi <= 2) ? fs_names[fsi] : "?", h);
            printf("  DW epoch: states_per_layer=%u, step_blocks=%u\n",
                   lsp->factory.states_per_layer, lsp->factory.step_blocks);
        }
        /* Per-leaf DW state */
        {
            factory_t *f = &lsp->factory;
            for (int li = 0; li < f->n_leaf_nodes; li++) {
                size_t ni = f->leaf_node_indices[li];
                printf("  Leaf %d: nSeq=0x%X", li, f->nodes[ni].nsequence);
                if (f->per_leaf_enabled)
                    printf(" state=%u", f->leaf_layers[li].current_state);
                factory_node_t *ln = &f->nodes[ni];
                printf(" outputs=[");
                for (size_t k = 0; k < ln->n_outputs; k++)
                    printf("%s%llu", k ? "," : "",
                           (unsigned long long)ln->outputs[k].amount_sats);
                printf("]\n");
            }
            if (f->leaf_arity == FACTORY_ARITY_2) {
                uint64_t total_lstock = 0;
                for (int li = 0; li < f->n_leaf_nodes; li++) {
                    size_t ni = f->leaf_node_indices[li];
                    factory_node_t *ln = &f->nodes[ni];
                    if (ln->n_outputs >= 3)
                        total_lstock += ln->outputs[ln->n_outputs - 1].amount_sats;
                }
                printf("  L-stock available: %llu sats\n",
                       (unsigned long long)total_lstock);
            }
        }
        /* Bridge connection status */
        printf("  Bridge: %s\n", mgr->bridge_fd >= 0 ? "connected" : "disconnected");
        /* Invoice registry */
        {
            size_t active_inv = 0;
            for (size_t i = 0; i < mgr->n_invoices; i++)
                if (mgr->invoices[i].active) active_inv++;
            printf("  Registered invoices: %zu active / %zu total\n",
                   active_inv, mgr->n_invoices);
        }
        /* Active HTLCs across channels */
        {
            size_t total_htlcs = 0;
            for (size_t c = 0; c < mgr->n_channels; c++)
                total_htlcs += mgr->entries[c].channel.n_htlcs;
            printf("  Active HTLCs: %zu\n", total_htlcs);
        }
        /* Bridge HTLC origins */
        {
            size_t active_origins = 0;
            for (size_t i = 0; i < mgr->n_htlc_origins; i++)
                if (mgr->htlc_origins[i].active) active_origins++;
            if (active_origins > 0)
                printf("  Bridge HTLC origins: %zu pending\n", active_origins);
        }
        if (mgr->ladder) {
            ladder_t *lad = (ladder_t *)mgr->ladder;
            printf("  Ladder factories: %zu\n", lad->n_factories);
        }
        /* JIT channels */
        if (mgr->jit_enabled && mgr->n_jit_channels > 0)
            printf("  JIT channels: %zu\n", mgr->n_jit_channels);
        printf("---\n");
        fflush(stdout);
    } else if (strcmp(line, "rotate") == 0) {
        printf("CLI: forcing rotation\n");
        fflush(stdout);
        if (lsp_channels_rotate_factory(mgr, lsp))
            printf("CLI: rotation succeeded\n");
        else {
            printf("CLI: rotation FAILED\n");
            fflush(stdout);
            fflush(stderr);
        }
        /* Reset offline timers after rotation attempt */
        {
            time_t tnow = time(NULL);
            for (size_t rc = 0; rc < mgr->n_channels; rc++) {
                mgr->entries[rc].last_message_time = tnow;
                mgr->entries[rc].offline_detected = 0;
            }
        }
    } else if (strcmp(line, "close") == 0) {
        printf("CLI: triggering shutdown (cooperative close)\n");
        fflush(stdout);
        *((volatile sig_atomic_t *)shutdown_flag) = 1;
    } else if (strncmp(line, "invoice ", 8) == 0) {
        unsigned int client;
        unsigned long long amt;
        if (sscanf(line + 8, "%u %llu", &client, &amt) == 2) {
            if (client >= mgr->n_channels) {
                printf("CLI: invalid client index (max %zu)\n",
                       mgr->n_channels - 1);
            } else if (mgr->bridge_fd < 0) {
                printf("CLI: no bridge connected\n");
            } else {
                printf("CLI: creating external invoice for client %u (%llu msat)\n",
                       client, amt);
                fflush(stdout);
                if (lsp_channels_create_external_invoice(mgr, lsp,
                        (size_t)client, (uint64_t)amt))
                    printf("CLI: external invoice created\n");
                else
                    printf("CLI: external invoice FAILED\n");
            }
        } else {
            printf("CLI: usage: invoice <client> <amount_msat>\n");
        }
    } else if (strcmp(line, "help") == 0) {
        printf("Commands:\n");
        printf("  pay <from> <to> <amount>     Send payment between clients\n");
        printf("  rebalance <from> <to> <amt>  Rebalance: move sats between clients\n");
        printf("  invoice <client> <msat>      Create external invoice for LN receive\n");
        printf("  status                       Show factory/channel/bridge state\n");
        printf("  rotate                       Force factory rotation\n");
        printf("  close                        Cooperative close and shutdown\n");
        printf("  buy_liquidity <client> <sats> Buy inbound liquidity from L-stock\n");
        printf("  pay_external <client> <bolt11> Pay external LN invoice via bridge\n");
        printf("  help                         Show this help\n");
    } else if (strncmp(line, "buy_liquidity ", 14) == 0) {
        unsigned int client;
        unsigned long long amt;
        if (sscanf(line + 14, "%u %llu", &client, &amt) == 2) {
            if (client >= mgr->n_channels) {
                printf("CLI: invalid client index (max %zu)\n",
                       mgr->n_channels - 1);
            } else if (amt == 0) {
                printf("CLI: amount must be > 0\n");
            } else {
                printf("CLI: buying %llu sats inbound for client %u\n", amt, client);
                fflush(stdout);
                if (lsp_channels_buy_liquidity(mgr, lsp, (size_t)client, (uint64_t)amt))
                    printf("CLI: buy_liquidity succeeded\n");
                else
                    printf("CLI: buy_liquidity FAILED\n");
            }
        } else {
            printf("CLI: usage: buy_liquidity <client> <amount_sats>\n");
        }
    } else if (strncmp(line, "pay_external ", 13) == 0) {
        /* pay_external <from_client> <bolt11> — outbound payment via bridge */
        unsigned int from;
        char bolt11[2048];
        if (sscanf(line + 13, "%u %2047s", &from, bolt11) == 2) {
            if (from >= mgr->n_channels) {
                printf("CLI: invalid client index (max %zu)\n",
                       mgr->n_channels - 1);
            } else if (mgr->bridge_fd < 0) {
                printf("CLI: no bridge connected (need --clnbridge)\n");
            } else {
                printf("CLI: paying external invoice from client %u...\n", from);
                fflush(stdout);
                /* Send bolt11 to bridge for outbound payment */
                uint64_t request_id = mgr->next_request_id++;
                unsigned char dummy_hash[32] = {0};
                cJSON *pay_msg = wire_build_bridge_send_pay(bolt11,
                                                             dummy_hash, request_id);
                if (wire_send(mgr->bridge_fd, MSG_BRIDGE_SEND_PAY, pay_msg))
                    printf("CLI: pay_external sent to bridge (request %llu)\n",
                           (unsigned long long)request_id);
                else
                    printf("CLI: pay_external bridge send FAILED\n");
                cJSON_Delete(pay_msg);
            }
        } else {
            printf("CLI: usage: pay_external <from_client> <bolt11_invoice>\n");
        }
    } else if (len > 0) {
        printf("CLI: unknown command '%s' (type 'help')\n", line);
        fflush(stdout);
        return 0;
    }
    fflush(stdout);
    return 1;
}

int lsp_channels_run_daemon_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   volatile sig_atomic_t *shutdown_flag) {
    if (!mgr || !lsp || !shutdown_flag) return 0;

    printf("LSP: daemon loop started (Ctrl+C to stop)\n");
    if (mgr->heartbeat_interval > 0)
        printf("LSP: heartbeat every %ds\n", mgr->heartbeat_interval);
    fflush(stdout);
    mgr->daemon_start_time = time(NULL);
    mgr->last_heartbeat = mgr->daemon_start_time;

    /* Initialize profit settlement baseline height */
    if (mgr->last_settlement_block == 0 &&
        mgr->watchtower && mgr->watchtower->rt) {
        int h = regtest_get_block_height(mgr->watchtower->rt);
        if (h > 0)
            mgr->last_settlement_block = (uint32_t)h;
    }

    /* Startup recovery: reconcile DB tree nodes with on-chain reality */
    {
        persist_t       *p_rec     = (persist_t *)mgr->persist;
        chain_backend_t *chain_rec = mgr->watchtower ? mgr->watchtower->chain : NULL;
        factory_recovery_scan(p_rec, chain_rec);
    }

    /* Pre-allocate poll arrays (clients + bridge + listen + stdin + admin_rpc) */
    int max_pfds = (int)mgr->n_channels + 4;
    struct pollfd *pfds = calloc(max_pfds, sizeof(struct pollfd));
    int *client_slots = calloc(mgr->n_channels, sizeof(int));
    if (!pfds || !client_slots) {
        free(pfds);
        free(client_slots);
        return 0;
    }

    while (!(*shutdown_flag)) {
        /* Drain any connections queued during ceremonies */
        while (mgr->n_pending_reconnects > 0) {
            mgr->n_pending_reconnects--;
            size_t qi = mgr->n_pending_reconnects;
            if (!mgr->pending_reconnects[qi].valid) continue;
            int qfd = mgr->pending_reconnects[qi].fd;
            uint8_t qtype = mgr->pending_reconnects[qi].msg_type;
            cJSON *qjson = (cJSON *)mgr->pending_reconnects[qi].json;
            mgr->pending_reconnects[qi].valid = 0;
            mgr->pending_reconnects[qi].json = NULL;

            /* Restore normal socket timeout for reconnect processing */
            wire_set_timeout(qfd, WIRE_DEFAULT_TIMEOUT_SEC);

            if (qtype == MSG_RECONNECT) {
                wire_msg_t qmsg = { .msg_type = qtype, .json = qjson };
                int ret = handle_reconnect_with_msg(mgr, lsp, qfd, &qmsg);
                if (!ret)
                    fprintf(stderr, "LSP: deferred reconnect failed\n");
                if (qjson) cJSON_Delete(qjson);
            } else if (qtype == MSG_BRIDGE_HELLO) {
                if (qjson) cJSON_Delete(qjson);
                cJSON *ack = wire_build_bridge_hello_ack();
                wire_send(qfd, MSG_BRIDGE_HELLO_ACK, ack);
                cJSON_Delete(ack);
                if (lsp->bridge_fd >= 0) wire_close(lsp->bridge_fd);
                lsp->bridge_fd = qfd;
                mgr->bridge_fd = qfd;
                printf("LSP: bridge connected (deferred, fd=%d)\n", qfd);
            } else if (qtype == MSG_HELLO) {
                /* HELLO from known client — try reconnect */
                unsigned char pk_buf[33];
                secp256k1_pubkey pk;
                if (qjson &&
                    wire_json_get_hex(qjson, "pubkey", pk_buf, 33) == 33 &&
                    secp256k1_ec_pubkey_parse(mgr->ctx, &pk, pk_buf, 33)) {
                    int slot = -1;
                    for (size_t s = 0; s < lsp->n_clients; s++) {
                        unsigned char s1[33], s2[33];
                        size_t l1 = 33, l2 = 33;
                        if (secp256k1_ec_pubkey_serialize(mgr->ctx, s1, &l1,
                                &lsp->client_pubkeys[s], SECP256K1_EC_COMPRESSED) &&
                            secp256k1_ec_pubkey_serialize(mgr->ctx, s2, &l2,
                                &pk, SECP256K1_EC_COMPRESSED) &&
                            memcmp(s1, s2, 33) == 0) {
                            slot = (int)s;
                            break;
                        }
                    }
                    if (slot >= 0) {
                        cJSON_Delete(qjson);
                        uint64_t cn = mgr->entries[slot].channel.commitment_number;
                        qjson = wire_build_reconnect(mgr->ctx, &pk, cn);
                        wire_msg_t qmsg = { .msg_type = MSG_RECONNECT, .json = qjson };
                        handle_reconnect_with_msg(mgr, lsp, qfd, &qmsg);
                        cJSON_Delete(qjson);
                    } else {
                        if (qjson) cJSON_Delete(qjson);
                        wire_close(qfd);
                    }
                } else {
                    if (qjson) cJSON_Delete(qjson);
                    wire_close(qfd);
                }
            } else {
                if (qjson) cJSON_Delete(qjson);
                wire_close(qfd);
            }
        }

        int nfds = 0;
        int listen_slot = -1, stdin_slot = -1, bridge_slot = -1, admin_rpc_slot = -1;
        for (size_t ci = 0; ci < mgr->n_channels; ci++)
            client_slots[ci] = -1;

        for (size_t c = 0; c < mgr->n_channels; c++) {
            int cfd = lsp->client_fds[c];
            if (cfd < 0) continue;  /* skip disconnected clients */
            client_slots[c] = nfds;
            pfds[nfds] = (struct pollfd){ .fd = cfd, .events = POLLIN };
            nfds++;
        }

        /* Include bridge fd if connected */
        if (mgr->bridge_fd >= 0) {
            bridge_slot = nfds;
            pfds[nfds] = (struct pollfd){ .fd = mgr->bridge_fd, .events = POLLIN };
            nfds++;
        }

        /* Include listen_fd for reconnections (Phase 16) */
        if (lsp->listen_fd >= 0) {
            listen_slot = nfds;
            pfds[nfds] = (struct pollfd){ .fd = lsp->listen_fd, .events = POLLIN };
            nfds++;
        }

        /* Include stdin for interactive CLI */
        if (mgr->cli_enabled) {
            stdin_slot = nfds;
            pfds[nfds] = (struct pollfd){ .fd = STDIN_FILENO, .events = POLLIN };
            nfds++;
        }

        /* Include admin RPC listen socket */
        {
            admin_rpc_t *arpc = (admin_rpc_t *)mgr->admin_rpc;
            if (arpc && arpc->listen_fd >= 0) {
                admin_rpc_slot = nfds;
                pfds[nfds] = (struct pollfd){ .fd = arpc->listen_fd, .events = POLLIN };
                nfds++;
            }
        }

        if (nfds == 0) {
            /* No fds to watch — all clients disconnected, no listen socket */
            poll(NULL, 0, 5000);
            continue;
        }

        int ret = poll(pfds, (nfds_t)nfds, 5000);
        if (ret < 0) {
            /* EINTR from signal — check shutdown flag */
            continue;
        }

        /* ---- Periodic checks: run on every iteration, throttled to ~5s ----
           poll() may never return 0 (timeout) if client reconnections or
           listen-socket events keep firing.  Time-gate the height-dependent
           checks so they still run reliably. */
        {
            static time_t last_periodic = 0;
            time_t tnow = time(NULL);
            if (last_periodic == 0) last_periodic = tnow;

            /* Send keepalive pings every 30s to prevent client recv timeout */
            {
                static time_t last_daemon_ping = 0;
                if (!last_daemon_ping) last_daemon_ping = tnow;
                if (tnow - last_daemon_ping >= 30) {
                    cJSON *ping = cJSON_CreateObject();
                    for (size_t pi = 0; pi < mgr->n_channels; pi++) {
                        if (lsp->client_fds[pi] >= 0)
                            wire_send(lsp->client_fds[pi], MSG_PING, ping);
                    }
                    cJSON_Delete(ping);
                    last_daemon_ping = tnow;
                }
            }

            if (tnow - last_periodic >= 5) {
                last_periodic = tnow;

                /* Check HD wallet balance for incoming deposits (every 30s) */
                {
                    static time_t last_deposit_check = 0;
                    if (!last_deposit_check) last_deposit_check = tnow;
                    if (tnow - last_deposit_check >= 30 && mgr->wallet_src) {
                        wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
                        if (ws->type == WALLET_SOURCE_HD) {
                            wallet_source_hd_t *hd = (wallet_source_hd_t *)ws;
                            uint64_t bal = wallet_source_hd_get_balance(hd);
                            if (bal != mgr->available_balance_sats) {
                                if (bal > mgr->available_balance_sats)
                                    printf("LSP: deposit detected — wallet balance: %llu sats (+%llu)\n",
                                           (unsigned long long)bal,
                                           (unsigned long long)(bal - mgr->available_balance_sats));
                                mgr->available_balance_sats = bal;
                            }
                            /* Extend gap limit if needed */
                            wallet_source_hd_extend_gap(hd);
                        }
                        last_deposit_check = tnow;
                    }
                }

                /* Periodic fee refresh */
                if (mgr->fee) {
                    fee_estimator_t *fe = (fee_estimator_t *)mgr->fee;
                    if (fe->update)
                        fe->update(fe);
                }

                /* Check block height / factory lifecycle (fast: 1 RPC call).
                   watchtower_check is deferred to once per 60s (below). */
                if (mgr->watchtower && mgr->watchtower->rt) {
                    int height = regtest_get_block_height(mgr->watchtower->rt);
                /* Reorg detection: height decreased since last check */
                {
                    static int32_t daemon_last_height = 0;
                    if (daemon_last_height > 0 && height > 0 &&
                        height < daemon_last_height) {
                        fprintf(stderr, "LSP: REORG detected — height %d → %d "
                                "(depth %d)\n", daemon_last_height, height,
                                daemon_last_height - height);
                        /* Re-validate watchtower entries */
                        watchtower_on_reorg(mgr->watchtower, height,
                                           daemon_last_height);
                        /* Immediate watchtower check to re-detect breaches */
                        watchtower_check(mgr->watchtower);
                        /* Re-run factory recovery to re-broadcast lost TXs */
                        if (mgr->persist) {
                            chain_backend_t *chain_rec = mgr->watchtower->chain;
                            factory_recovery_scan((persist_t *)mgr->persist,
                                                  chain_rec);
                        }
                    }
                    if (height > 0) daemon_last_height = height;
                }
                if (height > 0) {
                    for (size_t c = 0; c < mgr->n_channels; c++) {
                        channel_t *ch = &mgr->entries[c].channel;
                        int n_failed = channel_check_htlc_timeouts(ch, (uint32_t)height);
                        if (n_failed > 0) {
                            printf("LSP: auto-failed %d expired HTLCs on channel %zu "
                                   "(height=%d)\n", n_failed, c, height);
                            /* Delete failed HTLCs from persistence (atomic batch) */
                            if (mgr->persist) {
                                persist_t *db = (persist_t *)mgr->persist;
                                int own_txn = !persist_in_transaction(db);
                                if (own_txn) persist_begin(db);
                                for (size_t h = 0; h < ch->n_htlcs; h++) {
                                    if (ch->htlcs[h].state == HTLC_STATE_FAILED)
                                        persist_delete_htlc(db,
                                                            (uint32_t)c, ch->htlcs[h].id);
                                }
                                if (own_txn) persist_commit(db);
                            }
                        }
                    }

                    /* Bridge HTLC timeout check: fail back bridge HTLCs approaching
                       their CLTV deadline to avoid on-chain resolution.
                       Safety margin: fail 10 blocks before expiry. */
                    if (mgr->htlc_origins && mgr->bridge_fd >= 0) {
                        for (size_t oi = 0; oi < mgr->n_htlc_origins; oi++) {
                            htlc_origin_t *orig = &mgr->htlc_origins[oi];
                            if (!orig->active || orig->cltv_expiry == 0) continue;
                            if ((uint32_t)height + 10 >= orig->cltv_expiry) {
                                fprintf(stderr, "LSP: bridge HTLC timeout — failing back "
                                        "htlc_id=%llu (height=%d, cltv=%u)\n",
                                        (unsigned long long)orig->bridge_htlc_id,
                                        height, orig->cltv_expiry);
                                unsigned char zero_hash[32] = {0};
                                cJSON *fail = wire_build_bridge_fail_htlc(
                                    zero_hash, "cltv_expiry_too_soon",
                                    orig->bridge_htlc_id);
                                wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
                                cJSON_Delete(fail);
                                /* Also fail the channel-side HTLC if still active */
                                for (size_t c = 0; c < mgr->n_channels; c++) {
                                    channel_t *ch = &mgr->entries[c].channel;
                                    for (size_t h = 0; h < ch->n_htlcs; h++) {
                                        if (ch->htlcs[h].state == HTLC_STATE_ACTIVE &&
                                            memcmp(ch->htlcs[h].payment_hash,
                                                   orig->payment_hash, 32) == 0) {
                                            channel_fail_htlc(ch, ch->htlcs[h].id);
                                            break;
                                        }
                                    }
                                }
                                orig->active = 0;
                            }
                        }
                    }

                    /* Profit settlement check */
                    if (mgr->economic_mode == ECON_PROFIT_SHARED &&
                        mgr->accumulated_fees_sats > 0 &&
                        mgr->settlement_interval_blocks > 0 &&
                        (uint32_t)height - mgr->last_settlement_block >=
                            mgr->settlement_interval_blocks) {
                        int settled = lsp_channels_settle_profits(
                            mgr, &lsp->factory);
                        if (settled > 0) {
                            mgr->last_settlement_block = (uint32_t)height;
                            if (mgr->persist)
                                persist_save_fee_settlement(
                                    (persist_t *)mgr->persist, 0,
                                    mgr->accumulated_fees_sats,
                                    mgr->last_settlement_block);
                            printf("LSP: settled profits to %d channels "
                                   "(height=%d)\n", settled, height);
                            fflush(stdout);
                        }
                    }
                    /* Factory lifecycle monitoring */
                    factory_state_t fstate = factory_get_state(
                        &lsp->factory, (uint32_t)height);
                    if (fstate == FACTORY_DYING) {
                        printf("LSP: factory DYING (%u blocks to expiry)\n",
                               factory_blocks_until_expired(&lsp->factory,
                                                            (uint32_t)height));
                        fflush(stdout);
                    } else if (fstate == FACTORY_EXPIRED) {
                        printf("LSP: factory EXPIRED at height %d\n", height);
                        fflush(stdout);
                    }

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
                                fflush(stdout);
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
                                        lf->factory.dying_blocks,
                                        lf->partial_rotation_done);
                                }
                                /* Auto-broadcast distribution TX on EXPIRED */
                                if (lf->cached_state == FACTORY_EXPIRED &&
                                    lf->distribution_tx.len > 0 &&
                                    mgr->chain_be) {
                                    chain_backend_t *_cb = (chain_backend_t *)mgr->chain_be;
                                    char *dhex = malloc(lf->distribution_tx.len * 2 + 1);
                                    if (dhex) {
                                        extern void hex_encode(const unsigned char *,
                                                               size_t, char *);
                                        hex_encode(lf->distribution_tx.data,
                                                   lf->distribution_tx.len, dhex);
                                        char dtxid[65];
                                        if (_cb->send_raw_tx(_cb, dhex, dtxid))
                                            printf("LSP: distribution TX broadcast: %s\n",
                                                   dtxid);
                                        free(dhex);
                                    }
                                }

                                /* Async rotation: handle EXPIRED with partial ready set.
                                   DYING → EXPIRED means the window closed; rotate
                                   with whoever showed up (n_ready >= 2). */
                                if (lf->cached_state == FACTORY_EXPIRED &&
                                    old_states[fi] == FACTORY_DYING &&
                                    mgr->readiness) {
                                    readiness_tracker_t *rt =
                                        (readiness_tracker_t *)mgr->readiness;
                                    size_t n_ready = (size_t)readiness_count_ready(rt);
                                    if (n_ready >= 2 && n_ready < rt->n_clients) {
                                        printf("LSP: factory %u EXPIRED — partial rotation "
                                               "with %zu/%zu ready clients\n",
                                               lf->factory_id, n_ready, rt->n_clients);
                                        fflush(stdout);
                                        lsp_channels_rotate_factory(mgr, lsp);
                                    } else if (n_ready < 2) {
                                        printf("LSP: factory %u EXPIRED — only %zu client(s) ready,"
                                               " cannot partial-rotate (need >= 2)\n",
                                               lf->factory_id, n_ready);
                                    }
                                    readiness_reset(rt);
                                }

                                /* Auto-rotate when factory enters DYING
                                   (or jumps directly to EXPIRED, skipping DYING
                                    — can happen if blocks mine faster than poll) */
                                if (mgr->rot_auto_rotate &&
                                    (lf->cached_state == FACTORY_DYING ||
                                     lf->cached_state == FACTORY_EXPIRED)) {
                                    /* First attempt: ACTIVE → DYING transition */
                                    if (old_states[fi] == FACTORY_ACTIVE &&
                                        !(mgr->rot_attempted_mask & (1u << (lf->factory_id & 31)))) {
                                        printf("LSP: factory %u DYING — starting auto-rotation\n",
                                               lf->factory_id);
                                        fflush(stdout);
                                        mgr->rot_attempted_mask |= (1u << (lf->factory_id & 31));
                                        /* Reset retry state — prevent aliasing from old factory */
                                        uint32_t ridx = lf->factory_id % 8;
                                        mgr->rot_retry_count[ridx] = 0;
                                        mgr->rot_last_attempt_block[ridx] = 0;

                                        if (mgr->readiness) {
                                            /* Async path: queue rotation request for all clients,
                                               mark already-connected ones, fire fast-path if all
                                               are already present. */
                                            readiness_tracker_t *rt =
                                                (readiness_tracker_t *)mgr->readiness;
                                            readiness_init(rt, lf->factory_id,
                                                           lsp->n_clients,
                                                           (persist_t *)mgr->persist);
                                            persist_t *db = (persist_t *)mgr->persist;
                                            notify_t *nfy = (notify_t *)mgr->notify;
                                            for (size_t ci = 0; ci < lsp->n_clients; ci++) {
                                                if (lsp->client_fds[ci] >= 0)
                                                    readiness_set_connected(rt, (uint32_t)ci, 1);
                                                if (db)
                                                    queue_push(db, (uint32_t)ci,
                                                               lf->factory_id,
                                                               QUEUE_REQ_ROTATION,
                                                               QUEUE_URGENCY_NORMAL,
                                                               0,
                                                               "{\"reason\":\"factory_dying\"}");
                                                notify_send(nfy, (uint32_t)ci,
                                                            NOTIFY_ROTATION_NEEDED,
                                                            QUEUE_URGENCY_NORMAL, NULL);
                                            }
                                            /* Fast path: fire immediately if all already here */
                                            lsp_check_rotation_readiness(mgr, lsp);
                                        } else {
                                            /* Legacy synchronous path */
                                            int ok = lsp_channels_rotate_factory(mgr, lsp);
                                            /* Reset offline timers — rotation involves client
                                               communication that doesn't go through the
                                               daemon loop's message handler */
                                            {
                                                time_t tnow = time(NULL);
                                                for (size_t rc = 0; rc < mgr->n_channels; rc++) {
                                                    mgr->entries[rc].last_message_time = tnow;
                                                    mgr->entries[rc].offline_detected = 0;
                                                }
                                            }
                                            if (ok) {
                                                printf("LSP: auto-rotation complete — new factory active\n");
                                                fflush(stdout);
                                                lsp_rotation_record_success(mgr, lf->factory_id);
                                            } else {
                                                fprintf(stderr, "LSP: auto-rotation FAILED for factory %u\n",
                                                        lf->factory_id);
                                                lsp_rotation_record_failure(mgr, lf->factory_id,
                                                                            (uint32_t)height);
                                            }
                                        }
                                    }
                                }
                            }

                            /* Retry rotation with exponential backoff — runs on
                               every poll tick while factory is DYING/EXPIRED,
                               even without a state transition (the initial
                               trigger above fires only on ACTIVE→DYING). */
                            if (mgr->rot_auto_rotate &&
                                (lf->cached_state == FACTORY_DYING ||
                                 lf->cached_state == FACTORY_EXPIRED)) {
                                int retry_act = lsp_rotation_should_retry(
                                    mgr, lf->factory_id, (uint32_t)height);
                                if (retry_act == 1) {
                                    uint32_t ridx = lf->factory_id % 8;
                                    uint32_t attempt = mgr->rot_retry_count[ridx] + 1;
                                    uint32_t mret = mgr->rot_max_retries > 0
                                                    ? mgr->rot_max_retries : 3;
                                    printf("LSP: retrying rotation for factory %u "
                                           "(attempt %u/%u)\n",
                                           lf->factory_id, attempt, mret);
                                    fflush(stdout);
                                    int ok = lsp_channels_rotate_factory(mgr, lsp);
                                    {
                                        time_t tnow = time(NULL);
                                        for (size_t rc = 0; rc < mgr->n_channels; rc++) {
                                            mgr->entries[rc].last_message_time = tnow;
                                            mgr->entries[rc].offline_detected = 0;
                                        }
                                    }
                                    if (ok) {
                                        printf("LSP: retry rotation complete\n");
                                        fflush(stdout);
                                        lsp_rotation_record_success(mgr, lf->factory_id);
                                    } else {
                                        lsp_rotation_record_failure(mgr, lf->factory_id,
                                                                    (uint32_t)height);
                                        fprintf(stderr, "LSP: retry rotation FAILED "
                                                "(attempt %u)\n", attempt);
                                    }
                                } else if (retry_act == -1) {
                                    /* Max retries exhausted — distribution TX fallback */
                                    uint32_t mret = mgr->rot_max_retries > 0
                                                    ? mgr->rot_max_retries : 3;
                                    printf("LSP: rotation failed %u times for factory %u"
                                           " — broadcasting distribution TX\n",
                                           mret, lf->factory_id);
                                    fflush(stdout);
                                    if (lf->distribution_tx.len > 0 &&
                                        mgr->chain_be) {
                                        chain_backend_t *_cb =
                                            (chain_backend_t *)mgr->chain_be;
                                        char *dhex = malloc(
                                            lf->distribution_tx.len * 2 + 1);
                                        if (dhex) {
                                            extern void hex_encode(
                                                const unsigned char *, size_t,
                                                char *);
                                            hex_encode(lf->distribution_tx.data,
                                                       lf->distribution_tx.len,
                                                       dhex);
                                            char dtxid[65];
                                            if (_cb->send_raw_tx(_cb, dhex, dtxid))
                                                printf("LSP: fallback distribution "
                                                       "TX: %s\n", dtxid);
                                            else
                                                fprintf(stderr, "LSP: fallback "
                                                        "dist TX broadcast failed\n");
                                            free(dhex);
                                        }
                                    }
                                    /* Sentinel: past max → no further action */
                                    uint32_t ridx = lf->factory_id % 8;
                                    mgr->rot_retry_count[ridx] = (uint8_t)(mret + 1);
                                }
                            }
                        }
                    }
                }
            }

            /* Watchtower breach check — rate-limited to once per 60s because
               it makes O(n_entries × scan_depth) RPC calls and would otherwise
               block the daemon loop for tens of seconds every 5-second timeout.
               Initialize last_wt_check on first entry (0 sentinel) so the first
               real check is delayed by a full 60-second cycle. */
            {
                static time_t last_wt_check = 0;
                time_t tnow = time(NULL);
                if (last_wt_check == 0)
                    last_wt_check = tnow;   /* arm the clock; skip this tick */
                else if (mgr->watchtower && (tnow - last_wt_check) >= 60) {
                    last_wt_check = tnow;
                    watchtower_check(mgr->watchtower);
                    /* Balance conservation check */
                    if (!lsp_channels_check_conservation(mgr))
                        fprintf(stderr, "LSP: ALERT — balance conservation "
                                "violated, refusing new HTLCs\n");
                    /* Detect commitment TXs on-chain and register sweeps */
                    if (mgr->sweeper)
                        lsp_channels_detect_commitment_sweeps(mgr);
                    /* Run sweeper on same cycle */
                    if (mgr->sweeper)
                        sweeper_check((sweeper_t *)mgr->sweeper);
                    /* Auto-sweep CLTV-timelocked leaf outputs from expired factories.
                       factory_sweep_run exists but was CLI-only — run it periodically. */
                    if (mgr->persist && mgr->chain_be && mgr->ladder) {
                        ladder_t *_lad = (ladder_t *)mgr->ladder;
                        chain_backend_t *_cb = (chain_backend_t *)mgr->chain_be;
                        uint32_t _h = _cb->get_block_height(_cb);
                        for (size_t fi = 0; fi < _lad->n_factories; fi++) {
                            ladder_factory_t *_lf = &_lad->factories[fi];
                            if (_lf->cached_state == FACTORY_EXPIRED &&
                                _lf->factory.cltv_timeout > 0 &&
                                _h >= _lf->factory.cltv_timeout &&
                                mgr->rot_fund_spk_len > 0) {
                                cJSON *res = factory_sweep_run(
                                    (persist_t *)mgr->persist, _cb,
                                    mgr->ctx, mgr->rot_lsp_seckey,
                                    _lf->factory_id,
                                    mgr->rot_fund_spk, mgr->rot_fund_spk_len,
                                    500, 0);
                                if (res) cJSON_Delete(res);
                            }
                        }
                    }
                }
            }

            /* Check if DW counter is near exhaustion — trigger factory rotation */
            if (!dw_counter_is_exhausted(&lsp->factory.counter)) {
                uint32_t epoch = dw_counter_epoch(&lsp->factory.counter);
                uint32_t total = lsp->factory.counter.total_states;
                if (total > 0 && epoch >= (total * 3) / 4) {
                    printf("LSP: DW counter at %u/%u (>75%%) — rotation needed\n",
                           epoch, total);
                    if (mgr->rot_auto_rotate) {
                        lsp_channels_rotate_factory(mgr, lsp);
                    }
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
                                fflush(stdout);
                                jit_channel_create(mgr, lsp, c, jit_amt,
                                                    "factory_expired");
                            }
                        }
                    }
                }
            }

            /* Check JIT funding confirmation (FUNDING → OPEN) */
            jit_channels_check_funding(mgr);

            /* Auto-rebalance: rate-limited to once per 100 blocks */
            if (mgr->auto_rebalance && mgr->watchtower && mgr->watchtower->rt) {
                int rh = regtest_get_block_height(mgr->watchtower->rt);
                if (rh > 0 && (uint32_t)rh - mgr->last_rebalance_block >= 100) {
                    int n_rb = lsp_channels_auto_rebalance(mgr, lsp);
                    if (n_rb > 0) {
                        printf("LSP: auto-rebalanced %d channels (height=%d)\n",
                               n_rb, rh);
                        fflush(stdout);
                    }
                    mgr->last_rebalance_block = (uint32_t)rh;
                }
            }

            /* Check bridge HTLC timeouts */
            if (mgr->bridge_fd >= 0 && mgr->watchtower && mgr->watchtower->rt) {
                int bh = regtest_get_block_height(mgr->watchtower->rt);
                if (bh > 0)
                    lsp_channels_check_bridge_htlc_timeouts(mgr, lsp, (uint32_t)bh);
            }

            /* Async rotation: fire ceremony if all clients ready;
               escalate urgency for missing clients when factory is DYING. */
            if (mgr->readiness && mgr->ladder && mgr->watchtower && mgr->watchtower->rt) {
                readiness_tracker_t *rt = (readiness_tracker_t *)mgr->readiness;
                ladder_t *lad = (ladder_t *)mgr->ladder;
                ladder_factory_t *lf = ladder_get_by_id(lad, rt->factory_id);
                if (lf && lf->cached_state == FACTORY_DYING) {
                    /* Try to fire ceremony */
                    if (lsp_check_rotation_readiness(mgr, lsp)) {
                        /* Ceremony fired — skip escalation */
                    } else {
                        /* Escalate urgency for missing clients */
                        int bh = regtest_get_block_height(mgr->watchtower->rt);
                        if (bh > 0) {
                            uint32_t blocks_left = factory_blocks_until_expired(
                                &lf->factory, (uint32_t)bh);
                            int urgency = readiness_compute_urgency(
                                blocks_left, lf->factory.dying_blocks);
                            uint32_t missing[FACTORY_MAX_SIGNERS];
                            size_t n_missing = readiness_get_missing(
                                rt, missing, FACTORY_MAX_SIGNERS);
                            persist_t *db = (persist_t *)mgr->persist;
                            notify_t *nfy = (notify_t *)mgr->notify;
                            for (size_t mi = 0; mi < n_missing; mi++) {
                                if (db)
                                    queue_push(db, missing[mi], rt->factory_id,
                                               QUEUE_REQ_ROTATION, urgency, 0, NULL);
                                notify_send(nfy, missing[mi],
                                            NOTIFY_ROTATION_NEEDED, urgency, NULL);
                            }
                        }
                    }
                }
            }

            /* Heartbeat: periodic daemon status line */
            if (mgr->heartbeat_interval > 0) {
                time_t now = time(NULL);
                if (now - mgr->last_heartbeat >= mgr->heartbeat_interval) {
                    mgr->last_heartbeat = now;
                    int uptime_s = (int)(now - mgr->daemon_start_time);
                    int online = 0;
                    for (size_t c = 0; c < mgr->n_channels; c++)
                        if (lsp->client_fds[c] >= 0) online++;
                    int hb_height = 0;
                    const char *fstate_str = "?";
                    if (mgr->watchtower && mgr->watchtower->rt) {
                        hb_height = regtest_get_block_height(mgr->watchtower->rt);
                        /* Reorg detection: tip decreased since last check */
                        if (mgr->last_known_height > 0 && hb_height > 0 &&
                            hb_height < mgr->last_known_height) {
                            int depth = mgr->last_known_height - hb_height;
                            fprintf(stderr,
                                "ALERT: chain reorg detected (tip %d → %d, depth %d)\n",
                                mgr->last_known_height, hb_height, depth);
                            /* Fire chain backend reorg callback if set */
                            chain_backend_t *cbe = (chain_backend_t *)mgr->chain_be;
                            if (cbe && cbe->reorg_cb)
                                cbe->reorg_cb(hb_height, mgr->last_known_height,
                                              cbe->reorg_cb_ctx);
                        }
                        if (hb_height > mgr->last_known_height)
                            mgr->last_known_height = hb_height;
                        factory_state_t fs = factory_get_state(
                            &lsp->factory, (uint32_t)hb_height);
                        fstate_str = (fs == FACTORY_ACTIVE) ? "ACTIVE" :
                                     (fs == FACTORY_DYING)  ? "DYING"  :
                                                              "EXPIRED";
                    }
                    printf("[heartbeat] height=%d, factory=%s, "
                           "clients=%d/%zu online, uptime=%dh%02dm%02ds\n",
                           hb_height, fstate_str, online, mgr->n_channels,
                           uptime_s / 3600, (uptime_s / 60) % 60, uptime_s % 60);
                    fflush(stdout);
                }
            }

            } /* if (tnow - last_periodic >= 5) */
        } /* periodic checks block */

        if (ret == 0) continue;

        /* Handle new connections on listen_fd (bridge or client reconnect) */
        if (listen_slot >= 0 && (pfds[listen_slot].revents & POLLIN)) {
            int new_fd = wire_accept(lsp->listen_fd);
            if (new_fd >= 0) {
                /* Noise handshake (NK if LSP has static key set) */
                int reconn_hs;
                if (lsp->use_nk)
                    reconn_hs = wire_noise_handshake_nk_responder(new_fd, mgr->ctx, lsp->nk_seckey);
                else
                    reconn_hs = wire_noise_handshake_responder(new_fd, mgr->ctx);
                if (!reconn_hs) {
                    wire_close(new_fd);
                } else {
                    /* Peek at first message to distinguish bridge vs client */
                    wire_msg_t peek;
                    if (wire_recv_timeout(new_fd, &peek, 30)) {
                        if (peek.msg_type == MSG_BRIDGE_HELLO) {
                            /* Bridge connection */
                            cJSON_Delete(peek.json);
                            cJSON *ack = wire_build_bridge_hello_ack();
                            wire_send(new_fd, MSG_BRIDGE_HELLO_ACK, ack);
                            cJSON_Delete(ack);
                            if (lsp->bridge_fd >= 0)
                                wire_close(lsp->bridge_fd);
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
                        } else if (peek.msg_type == MSG_HELLO) {
                            /* Client reconnecting without state — check if known pubkey */
                            unsigned char pk_buf[33];
                            secp256k1_pubkey pk;
                            if (wire_json_get_hex(peek.json, "pubkey", pk_buf, 33) == 33 &&
                                secp256k1_ec_pubkey_parse(mgr->ctx, &pk, pk_buf, 33)) {
                                int slot = find_client_slot_by_pubkey(lsp, mgr->ctx, &pk);
                                if (slot >= 0) {
                                    fprintf(stderr, "LSP daemon: MSG_HELLO from known client %d "
                                            "(lost state?), attempting reconnect\n", slot);
                                    cJSON_Delete(peek.json);
                                    uint64_t cn = mgr->entries[slot].channel.commitment_number;
                                    peek.json = wire_build_reconnect(mgr->ctx, &pk, cn);
                                    peek.msg_type = MSG_RECONNECT;
                                    int ret = handle_reconnect_with_msg(mgr, lsp, new_fd, &peek);
                                    cJSON_Delete(peek.json);
                                    if (!ret) {
                                        fprintf(stderr, "LSP daemon: HELLO->reconnect failed for "
                                                "slot %d (state mismatch — client needs --db)\n", slot);
                                    }
                                } else {
                                    cJSON_Delete(peek.json);
                                    wire_close(new_fd);
                                }
                            } else {
                                cJSON_Delete(peek.json);
                                wire_close(new_fd);
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

        /* Handle stdin CLI commands */
        if (stdin_slot >= 0 && (pfds[stdin_slot].revents & POLLIN)) {
            char line[256];
            /* Use read() instead of fgets() — fgets permanently marks
               stdio EOF on FIFOs even when new writers connect later. */
            ssize_t nr = read(STDIN_FILENO, line, sizeof(line) - 1);
            if (nr <= 0) {
                /* EOF or error — disable CLI to prevent spin loop */
                mgr->cli_enabled = 0;
            } else {
                line[nr] = '\0';
                /* Strip trailing newline */
                size_t len = strlen(line);
                while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                    line[--len] = '\0';

                lsp_channels_handle_cli_line(mgr, lsp, line, shutdown_flag);
            }
        }

        /* Handle admin RPC request */
        if (admin_rpc_slot >= 0 && (pfds[admin_rpc_slot].revents & POLLIN))
            admin_rpc_service((admin_rpc_t *)mgr->admin_rpc);

        /* Handle bridge messages */
        if (bridge_slot >= 0 && (pfds[bridge_slot].revents & POLLIN)) {
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
            if (client_slots[c] < 0) continue;
            if (!(pfds[client_slots[c]].revents & POLLIN)) continue;

            wire_msg_t msg;
            if (!wire_recv(lsp->client_fds[c], &msg)) {
                fprintf(stderr, "LSP daemon: client %zu disconnected\n", c);
                wire_close(lsp->client_fds[c]);
                lsp->client_fds[c] = -1;
                if (mgr->readiness)
                    readiness_clear((readiness_tracker_t *)mgr->readiness,
                                    (uint32_t)c);
                continue;
            }

            if (!lsp_channels_handle_msg(mgr, lsp, c, &msg)) {
                fprintf(stderr, "LSP daemon: handle_msg failed for client %zu "
                        "msg 0x%02x\n", c, msg.msg_type);
            }
            cJSON_Delete(msg.json);
        }
    }

    free(pfds);
    free(client_slots);
    printf("LSP: daemon loop stopped (shutdown requested)\n");
    return 1;
}

/* Demo mode + payment initiation moved to lsp_demo.c */

/* ------------------------------------------------------------------ */
/* Auto-sweep outputs after force-close                                 */
/* ------------------------------------------------------------------ */

/*
 * Detect commitment TXs on-chain and register to_local outputs with the
 * sweeper for CSV-delayed sweep.
 *
 * After a force-close, the client broadcasts their commitment TX (they hold
 * the fully-signed MuSig2 version). The LSP detects the commitment TX on
 * chain and sweeps the to_local output after the CSV delay.
 *
 * Called from the daemon loop alongside watchtower_check().
 */
int lsp_channels_detect_commitment_sweeps(lsp_channel_mgr_t *mgr)
{
    extern void hex_encode(const unsigned char *, size_t, char *);
    extern void reverse_bytes(unsigned char *, size_t);

    if (!mgr || !mgr->watchtower || !mgr->sweeper) return 0;

    chain_backend_t *chain = mgr->watchtower->chain;
    sweeper_t *sw = (sweeper_t *)mgr->sweeper;
    if (!chain) return 0;

    int n_registered = 0;

    for (size_t c = 0; c < mgr->n_channels; c++) {
        channel_t *ch = &mgr->entries[c].channel;
        if (ch->funding_amount == 0) continue;

        /* Build the expected commitment TX to get its txid */
        tx_buf_t unsigned_tx;
        tx_buf_init(&unsigned_tx, 512);
        unsigned char commit_txid[32];
        if (!channel_build_commitment_tx(ch, &unsigned_tx, commit_txid)) {
            tx_buf_free(&unsigned_tx);
            continue;
        }
        tx_buf_free(&unsigned_tx);

        /* Check if this commitment TX is on-chain */
        unsigned char display_txid[32];
        memcpy(display_txid, commit_txid, 32);
        reverse_bytes(display_txid, 32);
        char txid_hex[65];
        hex_encode(display_txid, 32, txid_hex);

        int confs = chain->get_confirmations(chain, txid_hex);
        if (confs < 1) continue;  /* Not confirmed yet */

        /* Check if we already registered a sweep for this output */
        int already = 0;
        for (size_t s = 0; s < sw->n_entries; s++) {
            if (memcmp(sw->entries[s].source_txid, commit_txid, 32) == 0 &&
                sw->entries[s].type == SWEEP_TO_LOCAL) {
                already = 1;
                break;
            }
        }
        if (already) continue;

        /* Register to_local output (vout 0) for CSV-delayed sweep.
           The to_local output has a CSV delay of to_self_delay blocks. */
        if (ch->local_amount >= CHANNEL_DUST_LIMIT_SATS) {
            sweeper_add(sw, SWEEP_TO_LOCAL,
                        commit_txid, 0, ch->local_amount,
                        ch->to_self_delay,
                        (uint32_t)c, 0, ch->commitment_number);
            printf("LSP sweeper: channel %zu — commitment confirmed, "
                   "registered to_local sweep (%llu sats, CSV %u)\n",
                   c, (unsigned long long)ch->local_amount,
                   ch->to_self_delay);
            fflush(stdout);
            n_registered++;
        }
    }

    return n_registered;
}

/* ------------------------------------------------------------------ */
/* Balance conservation invariant                                       */
/* ------------------------------------------------------------------ */

int lsp_channels_check_conservation(const lsp_channel_mgr_t *mgr)
{
    if (!mgr) return 1;
    int ok = 1;

    for (size_t c = 0; c < mgr->n_channels; c++) {
        const channel_t *ch = &mgr->entries[c].channel;
        if (ch->funding_amount == 0) continue;

        uint64_t sum = ch->local_amount + ch->remote_amount;
        for (size_t h = 0; h < ch->n_htlcs; h++) {
            if (ch->htlcs[h].state == HTLC_STATE_ACTIVE) {
                sum += ch->htlcs[h].amount_sats;
                sum += ch->htlcs[h].fee_at_add;
            }
        }
        for (size_t p = 0; p < ch->n_ptlcs; p++) {
            if (ch->ptlcs[p].state == PTLC_STATE_ACTIVE)
                sum += ch->ptlcs[p].amount_sats;
        }

        if (sum != ch->funding_amount) {
            fprintf(stderr, "CONSERVATION VIOLATION: channel %zu — "
                    "local=%llu remote=%llu htlc_sum=%llu total=%llu "
                    "funding=%llu (delta=%lld)\n",
                    c,
                    (unsigned long long)ch->local_amount,
                    (unsigned long long)ch->remote_amount,
                    (unsigned long long)(sum - ch->local_amount - ch->remote_amount),
                    (unsigned long long)sum,
                    (unsigned long long)ch->funding_amount,
                    (long long)(sum - ch->funding_amount));
            ok = 0;
        }
    }

    return ok;
}

