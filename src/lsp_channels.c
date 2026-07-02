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
#include "superscalar/lsp_wt.h"
#include "superscalar/factory.h"
#include "superscalar/ladder.h"
#include "superscalar/regtest.h"
#include "superscalar/adaptor.h"
#include "superscalar/musig.h"
#include "superscalar/lsp_queue.h"
#include "superscalar/readiness.h"
#include "superscalar/notify.h"
#include "superscalar/admin_rpc.h"
#include "superscalar/crash_inject.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <poll.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>

#include "superscalar/sha256.h"
#include "superscalar/tapscript.h"
#include "superscalar/wallet_source.h"
#include "superscalar/wallet_source_hd.h"

/* watch_revoked_commitment moved to watchtower.c as watchtower_watch_revoked_commitment() */

/* SF-CH #154: 2-party funding keyagg discovery is now centralized in
   channel.c as channel_discover_funding_keyagg (shared with client.c).
   The LSP caller passes its own pubkey as "my", the client's as "peer";
   the returned my_signer_idx indicates LSP's position in the keyagg. */

/* Revocation-secret verification now lives in channel.c as the shared
   channel_verify_revocation_secret() (used by both LSP and client) — see
   doc/revocation-verification-standard.md. */

/* Detect single-process mode: returns 1 only when f->keypairs[i] holds a
   real seckey for every signer in `node` (LSP + every non-LSP signer).
   In multi-process mode the LSP only owns its own keypair (slot 0); the
   client keypairs are zero-filled and `factory_sign_l_stock_poison_tx`
   would crash inside libsecp256k1 with "illegal argument".

   This guard exists because the L-stock poison TX builder is a
   single-process primitive — it requires every leaf signer's seckey
   locally.  Multi-process LSPs must fall back to NULL poison_tx
   (graceful degradation) until the wire-ceremony equivalent that
   gathers per-client partial sigs over MuSig2 lands.  This is a
   SECURITY GAP for multi-process deployments — the watchtower can
   detect breaches but cannot redistribute L-stock to clients. */
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

    /* ADV Phase 4 (adversarial item-1): a CHEATING LSP that hands the client a
       valid-LOOKING but WRONG revocation secret, to prove the client's
       fail-closed verifier rejects a forged 0x50 in a LIVE routed payment and
       refuses to arm its watchtower from it. Defense-bypass class -> regtest-
       gated: a directly-set env var is inert on signet/testnet/mainnet (gate
       default 0). Marker: LSP-CHEAT-BADREV. */
    {
        const char *badrev = getenv("SS_CHEAT_LSP_BAD_REVOCATION");
        if (badrev && badrev[0] && badrev[0] != '0' && superscalar_cheat_allowed()) {
            fprintf(stderr, "LSP-CHEAT-BADREV: corrupting revocation secret for "
                    "client %zu (commitment %llu) — client MUST reject + refuse "
                    "WT-arm\n", client_idx, (unsigned long long)old_cn);
            lsp_rev_secret[0] ^= 0xff;   /* secret*G now != the committed PCP */
        }
    }

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
   Thin wrapper around the canonical factory_client_to_leaf helper —
   keeps the LSP and client side in sync (divergence here was the
   PR #117 bug class).  On lookup failure (out-of-range client_idx, or
   not present in any mixed-arity leaf), returns (node_idx=0,
   vout=UINT32_MAX) so callers' n_outputs bounds check rejects the
   entry instead of accessing a wrong leaf. */
/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248): de-static'd so the
 * lsp_channels_init_from_db extraction in src/lsp_init_from_db.c can
 * call it.  Internal helper — not in lsp_channels.h. */
void client_to_leaf(size_t client_idx, const factory_t *factory,
                            size_t *node_idx_out, uint32_t *vout_out) {
    if (!factory_client_to_leaf(factory, client_idx, node_idx_out, vout_out)) {
        *node_idx_out = 0;
        *vout_out = UINT32_MAX;
    }
}

int lsp_channels_init(lsp_channel_mgr_t *mgr,
                       secp256k1_context *ctx,
                       const factory_t *factory,
                       const unsigned char *lsp_seckey32,
                       size_t n_clients) {
    if (!mgr || !ctx || !factory || !lsp_seckey32) return 0;
    if (n_clients == 0) return 0;

    /* Preserve fields set before init (caller may configure these).
       mgr->persist MUST survive the memset so channel_set_persist() below
       can attach the live DB to each channel — without it, every
       channel-level persist (revocation_secrets, old_commitment_htlcs)
       silently no-ops, and lsp_run_state_advance's Step 11 (DW counter
       persist) and Step 11.5 (F1 chain[0] re-persist) skip the if guard.
       Caller (tools/superscalar_lsp.c:3591) sets mgr->persist before
       this call; PR-DASH-PERSIST (#196) added that ordering but didn't
       extend the memset preservation set. */
    uint64_t saved_fee_ppm = mgr->routing_fee_ppm;
    uint16_t saved_bal_pct = mgr->lsp_balance_pct;
    void *saved_fee = mgr->fee;
    void *saved_persist = mgr->persist;
    memset(mgr, 0, sizeof(*mgr));
    mgr->routing_fee_ppm = saved_fee_ppm;
    mgr->lsp_balance_pct = saved_bal_pct;
    mgr->fee = saved_fee;
    mgr->persist = saved_persist;
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

    /* Derive LSP cooperative-close SPK: P2TR of the LSP's own factory pubkey.
       Symmetric with per-client close_spk below. This lets the LSP alone
       spend its recovered share (L-stock + sum(local_amounts) + accumulated
       fees) with just its own seckey, instead of locking those sats in the
       N-of-N factory funding SPK. */
    if (factory->n_participants > 0) {
        secp256k1_xonly_pubkey lsp_xonly_for_close;
        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly_for_close, NULL,
                                                &factory->pubkeys[0])) {
            build_p2tr_script_pubkey(mgr->lsp_close_spk, &lsp_xonly_for_close);
            mgr->lsp_close_spk_len = 34;
        }
    }

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

        /* Commitment tx fee: pinned at the channel's stored fee_rate (1000
           sat/kvB; channel_init at src/channel.c:282). Using the live fee
           estimator here would diverge from the client's symmetric
           client_check_conservation (which reads ch->fee_rate_sat_per_kvb=1000
           and computes base_commit_fee=154) -- concretely, a 2562 sat/kvB live
           rate produced a constant -241 sat conservation gap on testnet4 that
           crashed PS_ADVANCE quorums (3e V3 / V3b, task #262). Real fee
           bumping at broadcast time happens via CPFP on the factory tree, not
           via this initial accounting deduction. */
        fee_estimator_static_t _fe_default;
        fee_estimator_static_init(&_fe_default, 1000);
        fee_estimator_t *_fe = &_fe_default.base;
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
        entry->channel.use_cpfp_anchor = 1;  /* #56: P2A CPFP anchor (matches client side) */
        /* Attach persistence so revocation secrets land in revocation_secrets
           and a standalone watchtower can hydrate this channel. */
        channel_set_persist(&entry->channel, mgr->persist, (uint32_t)c);
        /* fee_rate stays at channel_init default (1000); commit_fee above is
           pinned to the same rate to maintain the conservation invariant. */

        /* SF-CH #154: factory leaf outputs use DIFFERENT keyagg orderings
           depending on leaf type (setup_leaf_outputs / setup_single_leaf_outputs
           / setup_nway_leaf_outputs use [client, LSP]; setup_ps_leaf_outputs
           uses [LSP, client] via build_subtree's signer set).  Hardcoding one
           order breaks the other family — PS-leaf channels (arity != 2) failed
           on-chain Schnorr verify because the LSP-side 2-party keyagg didn't
           match the factory's actual aggregate.  Auto-discover by reproducing
           the factory's P2TR construction and comparing to funding_spk. */
        {
            musig_keyagg_t ka;
            uint32_t signer_idx;
            unsigned char merkle[32];
            int has_merkle = 0;
            if (!channel_discover_funding_keyagg(
                    ctx, &lsp_pubkey, client_pubkey, &lsp_pubkey,
                    factory->cltv_timeout, state_node->cltv_timeout,
                    funding_spk, funding_spk_len,
                    &ka, &signer_idx, merkle, &has_merkle)) {
                fprintf(stderr,
                        "LSP: channel %zu funding_keyagg discovery failed — "
                        "no combination of ordering [client,LSP]/[LSP,client] "
                        "and cltv (factory=%u, node=%u) produces the on-chain "
                        "funding_spk. Cannot proceed: on-chain spends would "
                        "fail Schnorr verify.\n",
                        c, factory->cltv_timeout, state_node->cltv_timeout);
                return 0;
            }
            entry->channel.funding_keyagg = ka;
            entry->channel.local_funding_signer_idx = signer_idx;
            if (has_merkle) {
                memcpy(entry->channel.chan_merkle_root, merkle, 32);
                entry->channel.has_chan_merkle_root = 1;
            } else {
                entry->channel.has_chan_merkle_root = 0;
            }
        }

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

uint32_t lsp_compute_factory_cltv_delta(const void *factory_ptr) {
    const factory_t *f = (const factory_t *)factory_ptr;
    if (!f || f->counter.n_layers == 0)
        return FACTORY_CLTV_DELTA_DEFAULT;

    uint32_t total = 0;
    for (uint32_t i = 0; i < f->counter.n_layers; i++) {
        uint16_t step = f->counter.layers[i].config.step_blocks;
        uint32_t states = f->counter.layers[i].config.max_states;
        if (states > 1)
            total += (uint32_t)step * (states - 1);
        total += 6;  /* confirmation buffer per layer */
    }
    total += 36;  /* flat safety margin ~6 hours */
    return total > 0 ? total : FACTORY_CLTV_DELTA_DEFAULT;
}

int lsp_validate_cltv_for_forward(uint32_t cltv_expiry, uint32_t *fwd_cltv_out,
                                   uint32_t factory_cltv_timeout,
                                   uint32_t cltv_delta) {
    if (cltv_delta == 0) cltv_delta = FACTORY_CLTV_DELTA_DEFAULT;
    if (cltv_expiry <= cltv_delta)
        return 0;
    /* Reject HTLCs that expire at or past factory timeout — funds would be trapped */
    if (factory_cltv_timeout > 0 && cltv_expiry >= factory_cltv_timeout)
        return 0;
    if (fwd_cltv_out)
        *fwd_cltv_out = cltv_expiry - cltv_delta;
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
    /* SF-W-PTLC: capture PTLC state alongside HTLC so the watchtower can
       sweep PTLC outputs on breach. No-op when n_ptlcs == 0 (current
       SuperScalar wire-protocol channels); defensive for future
       channel-level PTLC ops. */
    size_t old_sender_n_ptlcs = sender_ch->n_ptlcs;
    ptlc_t *old_sender_ptlcs = old_sender_n_ptlcs > 0
        ? malloc(old_sender_n_ptlcs * sizeof(ptlc_t)) : NULL;
    if (old_sender_n_ptlcs > 0 && !old_sender_ptlcs) {
        free(old_sender_htlcs);
        return 0;
    }
    if (old_sender_n_ptlcs > 0)
        memcpy(old_sender_ptlcs, sender_ch->ptlcs, old_sender_n_ptlcs * sizeof(ptlc_t));

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
        free(old_sender_ptlcs);
        return 1;  /* not a protocol error, just a payment failure */
    }

    /* Send COMMITMENT_SIGNED to sender (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for sender %zu\n", sender_idx);
            free(old_sender_htlcs);
            free(old_sender_ptlcs);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[sender_idx].channel_id,
            sender_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[sender_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            free(old_sender_htlcs);
            free(old_sender_ptlcs);
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
            free(old_sender_ptlcs);
            return 0;
        }
        /* Parse and verify revocation secret */
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = sender_ch->commitment_number - 1;
            if (!channel_verify_revocation_secret(sender_ch, old_cn, rev_secret)) {
                fprintf(stderr, "LSP: INVALID revocation secret from sender %zu "
                        "(commitment %lu) — rejecting\n",
                        sender_idx, (unsigned long)old_cn);
                secure_zero(rev_secret, 32);
                cJSON_Delete(ack_msg.json);
                free(old_sender_htlcs);
                free(old_sender_ptlcs);
                return 0;
            }
            channel_receive_revocation(sender_ch, old_cn, rev_secret);
            watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                (uint32_t)sender_idx, old_cn,
                old_sender_local, old_sender_remote,
                old_sender_htlcs, old_sender_n_htlcs,
                old_sender_ptlcs, old_sender_n_ptlcs);
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
    free(old_sender_ptlcs);

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
        /* Track accumulated fees — per-channel AND global.
           Per-channel: used for proportional profit settlement (the client
           whose channel routed the payment gets the share, not all clients).
           Global: kept for backward compat + persistence. */
        uint64_t fee_sats = (fee_msat + 999) / 1000;
        mgr->accumulated_fees_sats += fee_sats;
        mgr->entries[sender_idx].accumulated_fees_sats += fee_sats;
        if (mgr->persist)
            persist_save_fee_settlement((persist_t *)mgr->persist, 0,
                mgr->accumulated_fees_sats, mgr->last_settlement_block);
    }

    /* CLTV delta enforcement: subtract safety margin for factory close.
       Also reject HTLCs that expire at or past the factory timeout.
       The delta is computed from the DW tree depth — enough time to
       unwind the full tree and claim HTLC outputs on-chain. */
    uint32_t factory_delta = lsp_compute_factory_cltv_delta(&lsp->factory);
    uint32_t fwd_cltv_expiry;
    if (!lsp_validate_cltv_for_forward(cltv_expiry, &fwd_cltv_expiry,
                                        lsp->factory.cltv_timeout,
                                        factory_delta)) {
        fprintf(stderr, "LSP: cltv_expiry %u rejected (delta %u, factory timeout %u)\n",
                cltv_expiry, factory_delta, lsp->factory.cltv_timeout);
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
            if (!channel_verify_revocation_secret(dest_ch, old_cn, rev_secret)) {
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
                wt_chan_id, old_cn,
                old_dest_local, old_dest_remote,
                old_dest_htlcs, old_dest_n_htlcs,
                /* SF-W-PTLC #171: thread PTLC snapshot */ old_dest_ptlcs, old_dest_n_ptlcs);
            free(old_dest_ptlcs);
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


/* --- Phase 1c: MuSig2 stateless-signer per-leaf advance ---

   Reversed-order flow per the MuSig2 nonce-redesign memo.  The
   LSP MUST NOT hold a secnonce across any wire recv-wait -- invariant
   that motivates the whole redesign.

   Wire round-trip (gated by SS_MUSIG_STATELESS):
     LSP   -> Client : MSG_LEAF_ADVANCE_PROPOSE   {leaf_side}   (no nonce)
     Client -> LSP   : MSG_LEAF_ADVANCE_CLIENT_PUBNONCE {client_pubnonce}
     LSP   -> Client : MSG_LEAF_ADVANCE_LSP_RESPONSE {lsp_pubnonce, lsp_psig}
                       ^-- LSP atomically: gen nonce, set both nonces,
                           finalize, create_partial_sig (zeroes secnonce),
                           reply.  No suspension between gen and zero.
     Client -> LSP   : MSG_LEAF_ADVANCE_FINAL {final_sig64}
                       ^-- client locally aggregates psigs into the
                           64-byte Schnorr sig and ships it for the LSP
                           to attach to the unsigned tx.

   Scope (Phase 1c MVP):
     - STATE TX only.  Poison TX is NOT signed in the new flow -- the
       atomic generate+sign here would require a second independent
       secnonce, doubling the surface.  TODO(Phase 1d/2): re-introduce
       poison TX via a second MSG_LEAF_ADVANCE_LSP_RESPONSE round or a
       parallel atomic sub-ceremony.
     - Watchtower registration is skipped here too (legacy path keeps
       it).  TODO(Phase 2): re-enable once we decide whether to register
       with a NULL poison TX or run the legacy poison sub-ceremony.
     - Other ceremonies (Tier B, sub-factory, factory creation) defer
       to later phases per the audit's blast-radius ordering.

   When SS_MUSIG_STATELESS is unset the caller takes the legacy path
   instead and this function is unreachable. */
static int lsp_advance_leaf_stateless(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                        int leaf_side) {
    factory_t *f = &lsp->factory;

    if (f->leaf_arity != FACTORY_ARITY_1 && f->leaf_arity != FACTORY_ARITY_PS) return 1;
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    /* PS k>=2: same refusal as legacy path (see lsp_advance_leaf header). */
    if (f->leaf_arity == FACTORY_ARITY_PS && f->ps_subfactory_arity >= 2) {
        fprintf(stderr,
                "lsp_advance_leaf_stateless: refused -- k=%u sub-factory PS has "
                "no leaf-level dynamic operation.\n",
                f->ps_subfactory_arity);
        return 0;
    }

    int64_t c3_round_id = -1;
    if (mgr->persist) {
        persist_save_signing_round_start((persist_t *)mgr->persist,
                                           /* factory_id */ 0,
                                           (uint32_t)f->leaf_node_indices[leaf_side],
                                           "leaf_advance_stateless",
                                           f->counter.current_epoch,
                                           (uint32_t)f->n_participants,
                                           &c3_round_id);
    }

    /* Phase 1d.2: snapshot OLD leaf state BEFORE the advance mutates it. */
    size_t pre_node_idx = f->leaf_node_indices[leaf_side];
    unsigned char old_leaf_txid[32];
    int had_old_signed = (f->nodes[pre_node_idx].is_signed &&
                          f->nodes[pre_node_idx].signed_tx.len > 0);
    if (had_old_signed)
        memcpy(old_leaf_txid, f->nodes[pre_node_idx].txid, 32);
    int old_n_outputs = f->nodes[pre_node_idx].n_outputs;
    /* #53 x P3 interaction: when use_tree_anchor is on, factory_append_tree_anchor
       appends a P2A anchor (ANCHOR_OUTPUT_AMOUNT, SPK 0x51024e73) as the LAST output
       of every node — so the L-stock is the SECOND-to-last output, not outputs[n-1].
       Detect the anchor (flag + SPK) and target the real L-stock; otherwise the poison
       gate below reads the 240-sat anchor and never fires (poison_required=0), so the
       advance degrades + never reveals the recourse secret (caught by the leaf e2e). */
    int old_anchor_outs = (old_n_outputs >= 2 &&
        f->nodes[pre_node_idx].outputs[old_n_outputs - 1].script_pubkey_len == P2A_SPK_LEN &&
        memcmp(f->nodes[pre_node_idx].outputs[old_n_outputs - 1].script_pubkey,
               P2A_SPK, P2A_SPK_LEN) == 0) ? 1 : 0;
    int old_l_vout = old_n_outputs - 1 - old_anchor_outs;
    uint64_t old_l_amount = (old_l_vout >= 0 && (old_n_outputs - old_anchor_outs) >= 2)
                            ? f->nodes[pre_node_idx].outputs[old_l_vout].amount_sats
                            : 0;
    /* SF-WT-TRUSTLESS Phase 1b.4 (#248): also snapshot the OLD chain
     * output (vout=0)'s value + scriptpubkey + the nsequence-encoded
     * CSV.  These feed wt_db.wt_watches so the WT can match the
     * specific spend on-chain and the response_tx's BIP-68 timelock
     * is properly registered.  Snapshot before factory_advance_leaf
     * mutates outputs[]. */
    uint64_t old_chain_amount = (old_n_outputs >= 1)
                                ? f->nodes[pre_node_idx].outputs[0].amount_sats
                                : 0;
    unsigned char old_chain_spk[34];
    size_t old_chain_spk_len = 0;
    if (old_n_outputs >= 1) {
        old_chain_spk_len = f->nodes[pre_node_idx].outputs[0].script_pubkey_len;
        if (old_chain_spk_len > sizeof(old_chain_spk))
            old_chain_spk_len = sizeof(old_chain_spk);
        memcpy(old_chain_spk,
               f->nodes[pre_node_idx].outputs[0].script_pubkey,
               old_chain_spk_len);
    }
    /* BIP-68 nsequence: low 16 bits hold the CSV value when bit 22 is
     * 0 (block-based units, the SuperScalar default).  Phase 1b.4
     * uses just the low 16 bits — if a future deploy uses
     * time-based units, this widens to 22 bits with bit-31 type-flag
     * inspection. */
    uint32_t old_csv_delay = (uint32_t)(f->nodes[pre_node_idx].nsequence & 0xFFFFu);

    /* #53-B3b Phase 1: capture the OLD state's L-stock hash BEFORE the advance bumps
       the per-leaf counter + rebuilds the SPK to H_new — so the poison co-signed below
       targets the SUPERSEDED state's output (H_old), via override_hash32.  No-op unless
       hashlock poison is enabled. */
    unsigned char old_l_stock_hash[32];
    int have_old_l_hash = (f->use_hashlock_poison &&
                           f->nodes[pre_node_idx].has_l_stock_hash);
    if (have_old_l_hash)
        memcpy(old_l_stock_hash, f->nodes[pre_node_idx].l_stock_hash, 32);

    /* Step 1: advance leaf state to rebuild the unsigned TX. */
    int rc = factory_advance_leaf_unsigned(f, leaf_side);
    if (rc == 0) {
        fprintf(stderr, "LSP-stateless: leaf %d advance exhausted\n", leaf_side);
        return 0;
    }
    if (rc == -1) {
        /* Root rollover triggers Tier B -- defer to legacy until that
           ceremony is reversed (Phase 2). */
        printf("LSP-stateless: leaf %d exhausted, root advanced -- "
               "falling back to legacy Tier B state-advance ceremony\n",
               leaf_side);
        return lsp_run_state_advance(mgr, lsp, leaf_side);
    }

    size_t node_idx = f->leaf_node_indices[leaf_side];
    uint32_t client_participant = (uint32_t)(leaf_side + 1);

    /* Phase 1d.2: prep poison TX deterministically (both sides match). */
    const uint64_t LEAF_POISON_FEE_SATS = 1000;
    int leaf_poison_prepared = 0;
    /* #53 Phase 5: economic requirement — the old state has a protectable,
       non-dust L-stock output.  Captured independently of the operational prep
       conditions (watchtower presence / the SS_CHEAT_OMIT_POISON test hook) so
       the fail-closed guard below fires whenever a required poison was not
       co-signed, but never when no poison was ever needed (dust / no old state). */
    int poison_required = (had_old_signed && old_n_outputs >= 2 &&
        old_l_amount > LEAF_POISON_FEE_SATS +
                       (uint64_t)(f->nodes[pre_node_idx].n_signers - 1) * 330u);
    /* #53 Phase 5 test hook: SS_CHEAT_OMIT_POISON forces the LSP to skip poison
       prep so it co-signs the new state but NOT the Leaf-P poison — exercising
       the client's fail-closed "no revoke without recourse" abort.  Env-gated
       test path only (same pattern as SS_CHEAT_DAEMON_MODE). */
    if (mgr->watchtower && poison_required &&
        /* #9: the OMIT_POISON test hook (skip poison registration) only honoured
           when cheats are allowed (regtest); on mainnet poison ALWAYS registers. */
        !(superscalar_cheat_allowed() && getenv("SS_CHEAT_OMIT_POISON"))) {
        if (factory_session_prepare_poison_tx_leaf(
                f, pre_node_idx,
                old_leaf_txid, (uint32_t)old_l_vout,
                old_l_amount, LEAF_POISON_FEE_SATS,
                /* #53-B3b Phase 1: target the SUPERSEDED state's output (H_old captured
                   before the advance); NULL = legacy key-path when hashlock is off. */
                have_old_l_hash ? old_l_stock_hash : NULL)) {
            leaf_poison_prepared = 1;
        }
    }

    /* Step 2: ship PROPOSE with NO nonce -- client goes first. */
    /* SF-CRASH-INJECT-WIRE #245 Half A: journal this stateless leaf advance
       as a STATE_UPDATE ceremony.  Salt epoch with leaf_side + chain
       position so multiple advances per DW epoch do not collide. */
    unsigned char cer_id[8] = {0};
    int cer_persisted = 0;
    if (mgr->persist) {
        uint64_t epoch_salt = ((uint64_t)f->counter.current_epoch << 16)
                              | ((uint64_t)leaf_side << 8)
                              | (uint64_t)(f->nodes[node_idx].ps_chain_len & 0xff);
        lsp_ceremony_derive_id(lsp->factory.funding_txid,
                                PERSIST_CEREMONY_TYPE_STATE_UPDATE,
                                epoch_salt, cer_id);
        if (persist_save_ceremony((persist_t *)mgr->persist, cer_id,
                                   lsp->factory.funding_txid,
                                   PERSIST_CEREMONY_TYPE_STATE_UPDATE,
                                   NULL, 0, f->cltv_timeout))
            cer_persisted = 1;
    }
    cJSON *propose = wire_build_leaf_advance_propose(leaf_side, NULL, NULL);
    /* #53-B3b Phase 1: ship the advancing leaf's NEW-state L-stock hash (H_new, rebuilt
       by the advance @ factory_advance_leaf_unsigned) so the seedless client builds the
       IDENTICAL new leaf-state SPK — else the MuSig co-sign of the new state mismatches.
       Optional field; absent when hashlock poison is off (backward compatible). */
    if (f->use_hashlock_poison && f->nodes[node_idx].has_l_stock_hash)
        wire_json_add_hex(propose, "l_stock_hash", f->nodes[node_idx].l_stock_hash, 32);
    if (!wire_send(lsp->client_fds[leaf_side], MSG_LEAF_ADVANCE_PROPOSE, propose)) {
        cJSON_Delete(propose);
        fprintf(stderr, "LSP-stateless: send PROPOSE failed\n");
        return 0;
    }
    cJSON_Delete(propose);
    if (cer_persisted) {
        unsigned char pk33[33];
        lsp_ceremony_get_client_pubkey33(lsp, (size_t)leaf_side, pk33);
        (void)persist_save_participant_phase((persist_t *)mgr->persist, cer_id,
            pk33, PERSIST_CEREMONY_PHASE_SENT, NULL, NULL, 0, 0);
    }
    printf("LSP: LEAF_ADVANCE_PROPOSE sent for leaf %d\n", leaf_side);
    fflush(stdout);

    lsp_crash_checkpoint("leaf_advance_propose");

    /* Step 3: wait for client_pubnonce. */
    wire_msg_t cpn_msg;
    int rrc = recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[leaf_side],
                                             &cpn_msg, WIRE_CEREMONY_RECV_TIMEOUT_SEC);
    if (!rrc || cpn_msg.msg_type != MSG_LEAF_ADVANCE_CLIENT_PUBNONCE) {
        const char *why = !rrc ? "recv timeout / peer EOF" : "wrong message type";
        fprintf(stderr,
                "LSP-stateless: expected CLIENT_PUBNONCE from client %d, got 0x%02x (%s)\n",
                leaf_side, cpn_msg.msg_type, why);
        if (cpn_msg.json) cJSON_Delete(cpn_msg.json);
        return 0;
    }
    unsigned char client_pubnonce_ser[66];
    unsigned char client_poison_pubnonce_ser[66];
    int prc = wire_parse_leaf_advance_client_pubnonce(cpn_msg.json,
                                                         client_pubnonce_ser,
                                                         leaf_poison_prepared
                                                           ? client_poison_pubnonce_ser
                                                           : NULL);
    cJSON_Delete(cpn_msg.json);
    if (!prc) {
        fprintf(stderr, "LSP-stateless: parse CLIENT_PUBNONCE failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared && prc < 2) {
        fprintf(stderr, "LSP-stateless: client omitted poison pubnonce -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }

    lsp_crash_checkpoint("leaf_advance_nonced");

    /* Step 4: init both sessions (state always; poison if prepped). */
    if (!factory_session_init_node(f, node_idx)) {
        fprintf(stderr, "LSP-stateless: state session init failed for node %zu\n", node_idx);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared &&
        !factory_session_init_node_poison(f, node_idx)) {
        fprintf(stderr, "LSP-stateless: poison session init failed -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }

    /* Step 5: set client's pubnonce into the session. */
    int client_slot = factory_find_signer_slot(f, node_idx, client_participant);
    int lsp_slot = factory_find_signer_slot(f, node_idx, 0);
    if (client_slot < 0 || lsp_slot < 0) {
        fprintf(stderr, "LSP-stateless: signer slot lookup failed (client=%d, lsp=%d)\n",
                client_slot, lsp_slot);
        return 0;
    }
    secp256k1_musig_pubnonce client_pubnonce;
    if (!musig_pubnonce_parse(lsp->ctx, &client_pubnonce, client_pubnonce_ser)) {
        fprintf(stderr, "LSP-stateless: parse client pubnonce failed\n");
        return 0;
    }
    if (!factory_session_set_nonce(f, node_idx, (size_t)client_slot, &client_pubnonce)) {
        fprintf(stderr, "LSP-stateless: set client nonce failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared) {
        secp256k1_musig_pubnonce client_poison_pn;
        if (!musig_pubnonce_parse(lsp->ctx, &client_poison_pn, client_poison_pubnonce_ser) ||
            !factory_session_set_nonce_poison(f, node_idx, (size_t)client_slot, &client_poison_pn)) {
            fprintf(stderr, "LSP-stateless: client poison nonce parse/set failed -- degrading\n");
            factory_session_reset_poison(f, node_idx);
            leaf_poison_prepared = 0;
        }
    }

    /* Step 6 (THE CRITICAL ATOMIC BLOCK):
       Generate LSP secnonce + pubnonce, install it, finalize the session,
       create the partial sig (which zeroes our secnonce), and serialize
       the response.  No wire recv between nonce gen and zeroing. */
    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) {
        fprintf(stderr, "LSP-stateless: keypair_sec failed\n");
        return 0;
    }
    secp256k1_musig_secnonce lsp_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                                lsp_seckey, &lsp->lsp_pubkey,
                                &f->nodes[node_idx].keyagg.cache)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP-stateless: LSP nonce gen failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    secp256k1_musig_secnonce lsp_poison_secnonce;
    secp256k1_musig_pubnonce lsp_poison_pubnonce;
    if (leaf_poison_prepared &&
        !musig_generate_nonce(lsp->ctx, &lsp_poison_secnonce, &lsp_poison_pubnonce,
                                lsp_seckey, &lsp->lsp_pubkey,
                                &f->nodes[node_idx].keyagg.cache)) {
        fprintf(stderr, "LSP-stateless: poison nonce gen failed -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }
    if (!factory_session_set_nonce(f, node_idx, (size_t)lsp_slot, &lsp_pubnonce)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP-stateless: set LSP nonce failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared &&
        !factory_session_set_nonce_poison(f, node_idx, (size_t)lsp_slot,
                                            &lsp_poison_pubnonce)) {
        fprintf(stderr, "LSP-stateless: set LSP poison nonce failed -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }
    if (!factory_session_finalize_node(f, node_idx)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP-stateless: finalize_node failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared &&
        !factory_session_finalize_node_poison(f, node_idx)) {
        fprintf(stderr, "LSP-stateless: poison finalize failed -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP-stateless: keypair_create failed\n");
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce, &lsp_kp,
                                    &f->nodes[node_idx].signing_session)) {
        fprintf(stderr, "LSP-stateless: create_partial_sig failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    secp256k1_musig_partial_sig lsp_poison_psig;
    if (leaf_poison_prepared &&
        !musig_create_partial_sig(lsp->ctx, &lsp_poison_psig,
                                    &lsp_poison_secnonce, &lsp_kp,
                                    &f->nodes[node_idx].poison_signing_session)) {
        fprintf(stderr, "LSP-stateless: poison partial_sig failed -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }
    /* lsp_secnonce + lsp_poison_secnonce have been zeroed by musig_create_partial_sig.
       INVARIANT: from this point on we no longer hold any LSP secnonce of any kind.
       The wire recv that follows is safe. */

    unsigned char lsp_pubnonce_ser[66], lsp_psig_ser[32];
    musig_pubnonce_serialize(lsp->ctx, lsp_pubnonce_ser, &lsp_pubnonce);
    musig_partial_sig_serialize(lsp->ctx, lsp_psig_ser, &lsp_psig);

    /* Also stash our psig into the session so we can verify the final
       aggregated sig matches (and for future Phase-2 re-aggregation). */
    if (!factory_session_set_partial_sig(f, node_idx, (size_t)lsp_slot, &lsp_psig)) {
        fprintf(stderr, "LSP-stateless: set LSP partial_sig failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared &&
        !factory_session_set_partial_sig_poison(f, node_idx, (size_t)lsp_slot,
                                                 &lsp_poison_psig)) {
        fprintf(stderr, "LSP-stateless: set LSP poison partial_sig failed -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }

    /* Step 7: ship LSP_RESPONSE with optional poison fields. */
    unsigned char lsp_poison_pubnonce_ser[66], lsp_poison_psig_ser[32];
    if (leaf_poison_prepared) {
        musig_pubnonce_serialize(lsp->ctx, lsp_poison_pubnonce_ser, &lsp_poison_pubnonce);
        musig_partial_sig_serialize(lsp->ctx, lsp_poison_psig_ser, &lsp_poison_psig);
    }
    cJSON *response = wire_build_leaf_advance_lsp_response(
        lsp_pubnonce_ser, lsp_psig_ser,
        leaf_poison_prepared ? lsp_poison_pubnonce_ser : NULL,
        leaf_poison_prepared ? lsp_poison_psig_ser : NULL);
    if (!wire_send(lsp->client_fds[leaf_side], MSG_LEAF_ADVANCE_LSP_RESPONSE, response)) {
        cJSON_Delete(response);
        fprintf(stderr, "LSP-stateless: send LSP_RESPONSE failed\n");
        return 0;
    }
    cJSON_Delete(response);

    /* Step 8: wait for FINAL with the 64-byte aggregated sig. */
    wire_msg_t fin_msg;
    int frc = recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[leaf_side],
                                             &fin_msg, WIRE_CEREMONY_RECV_TIMEOUT_SEC);
    if (!frc || fin_msg.msg_type != MSG_LEAF_ADVANCE_FINAL) {
        const char *why = !frc ? "recv timeout / peer EOF" : "wrong message type";
        fprintf(stderr,
                "LSP-stateless: expected FINAL from client %d, got 0x%02x (%s)\n",
                leaf_side, fin_msg.msg_type, why);
        if (fin_msg.json) cJSON_Delete(fin_msg.json);
        return 0;
    }
    unsigned char final_sig[64];
    unsigned char final_poison_sig[64];
    int frc2 = wire_parse_leaf_advance_final(fin_msg.json, final_sig,
                                                leaf_poison_prepared ? final_poison_sig : NULL);
    cJSON_Delete(fin_msg.json);
    if (!frc2) {
        fprintf(stderr, "LSP-stateless: parse FINAL failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (leaf_poison_prepared && frc2 < 2) {
        fprintf(stderr, "LSP-stateless: client omitted final_poison_sig -- degrading\n");
        factory_session_reset_poison(f, node_idx);
        leaf_poison_prepared = 0;
    }

    lsp_crash_checkpoint("leaf_advance_signed");

    /* Step 9: verify the final sig against the session's keyagg+sighash
       and (on success) attach it as the node's signed_tx.  The session's
       cache is the tweaked keyagg (factory_session_finalize_node applied
       the taproot xonly tweak), so musig_pubkey_get returns the output
       (tweaked) aggregated pubkey.  Convert to xonly for schnorrsig_verify. */
    factory_node_t *node = &f->nodes[node_idx];
    secp256k1_pubkey output_pk;
    if (!secp256k1_musig_pubkey_get(lsp->ctx, &output_pk,
                                       &node->signing_session.cache)) {
        fprintf(stderr, "LSP-stateless: pubkey_get from cache failed\n");
        return 0;
    }
    secp256k1_xonly_pubkey output_xpub;
    if (!secp256k1_xonly_pubkey_from_pubkey(lsp->ctx, &output_xpub, NULL,
                                              &output_pk)) {
        fprintf(stderr, "LSP-stateless: xonly_from_pubkey failed\n");
        return 0;
    }
    if (!secp256k1_schnorrsig_verify(lsp->ctx, final_sig,
                                       node->signing_session.msg32, 32,
                                       &output_xpub)) {
        fprintf(stderr, "LSP-stateless: schnorr verify of FINAL sig failed\n");
        return 0;
    }
    if (!finalize_signed_tx(&node->signed_tx,
                              node->unsigned_tx.data, node->unsigned_tx.len,
                              final_sig)) {
        fprintf(stderr, "LSP-stateless: finalize_signed_tx failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    node->is_signed = 1;

    /* Phase 1d.2: verify + finalize poison signed_tx. */
    if (leaf_poison_prepared) {
        secp256k1_pubkey poison_output_pk;
        secp256k1_xonly_pubkey poison_output_xpub;
        /* The verify works for BOTH paths: the session cache is the tweaked output
           key for key-path poison, or the RAW agg key after the untweaked finalize
           for script-path (#53-B3a), so musig_pubkey_get returns the correct key. */
        int poison_verified =
            secp256k1_musig_pubkey_get(lsp->ctx, &poison_output_pk,
                                         &node->poison_signing_session.cache) &&
            secp256k1_xonly_pubkey_from_pubkey(lsp->ctx, &poison_output_xpub, NULL,
                                                 &poison_output_pk) &&
            secp256k1_schnorrsig_verify(lsp->ctx, final_poison_sig,
                                          node->poison_signing_session.msg32, 32,
                                          &poison_output_xpub);
        if (poison_verified && node->poison_is_scriptpath) {
            /* #53-B3b.2b: script-path (Leaf-P) poison — the broadcastable witness
               needs the revealed secret as the preimage, unavailable at ceremony
               time.  Store the aggregated Leaf-P sig; factory_assemble_poison_with_secret
               builds the full witness once the secret is revealed (#53-B3b). */
            memcpy(node->poison_agg_sig, final_poison_sig, 64);
            node->poison_has_agg_sig = 1;
            node->poison_is_signed = 1;
            printf("LSP-stateless: script-path poison agg sig stored (L-stock %llu sats)\n",
                   (unsigned long long)old_l_amount);
        } else if (poison_verified && !node->has_l_stock_hash &&
            /* #53-B2: a key-path poison must NEVER be finalized for a hashlock
               leaf (it would spend the L-stock without revealing the secret).
               poison_is_scriptpath is already set from has_l_stock_hash at prep,
               so this is the inconsistent-state backstop: degrade, don't sign. */
            finalize_signed_tx(&node->poison_signed_tx,
                                node->poison_unsigned_tx.data,
                                node->poison_unsigned_tx.len,
                                final_poison_sig)) {
            node->poison_is_signed = 1;
            printf("LSP-stateless: poison TX signed (%zu bytes, L-stock %llu sats)\n",
                   node->poison_signed_tx.len,
                   (unsigned long long)old_l_amount);
        } else {
            fprintf(stderr, "LSP-stateless: poison sig verify/finalize failed -- degrading\n");
            factory_session_reset_poison(f, node_idx);
            leaf_poison_prepared = 0;
        }
    }

    /* #53 Phase 5 (B4): when hashlock poison is ON, an advance that did NOT
       co-sign the Leaf-P poison for the superseded state must NOT be finalized
       (registered / persisted / DONE-broadcast).  Proceeding would revoke the
       old state with NO recourse against a later LSP cheat (latent Scenario
       A/B) — exactly what #53 closes.  Fail-closed: abort and stay on the old,
       still-recourse-able state.  The new state is signed in memory only at this
       point (not yet persisted / DONE), so returning 0 discards it cleanly.
       This subsumes every degrade-and-continue site above (any of them leaves
       leaf_poison_prepared == 0) plus the case where prep never ran.  Legacy
       (flag off) keeps the prior degrade-and-continue behavior unchanged. */
    if (f->use_hashlock_poison && poison_required && !leaf_poison_prepared) {
        fprintf(stderr, "LSP-stateless: hashlock ON + L-stock poison REQUIRED but "
                        "NOT co-signed -- ABORTING advance (would leave the client "
                        "without recourse)\n");
        /* Finding 2: the new state's signed_tx was finalized in memory
           (is_signed=1) just above, but is NOT persisted / DONE-broadcast yet.
           Clear it so a later factory-tree broadcast cannot ship this
           incomplete-advance state; persist still holds the old state. */
        node->is_signed = 0;
        tx_buf_reset(&node->signed_tx);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }

    /* Phase 1d.2: poison TX ceremony DONE.  Same atomic-signer flow as
       state TX, with optional poison fields in CLIENT_PUBNONCE,
       LSP_RESPONSE, and FINAL.  lsp_poison_secnonce zeroed by
       musig_create_partial_sig before any wire recv. */

    /* Phase 1d.3 (#271): register old leaf state + wire-ceremony poison TX
       with the watchtower for breach detection, mirroring the legacy path's
       Step 9 block.  The stateless ceremony is always multi-process, so the
       poison TX is the wire-signed one (no single-process burn_tx fallback).
       poison_snapshot survives factory_session_reset_poison for Step 11
       persist (reset frees node->poison_signed_tx). */
    unsigned char *poison_snapshot = NULL;
    size_t poison_snapshot_len = 0;
    if (had_old_signed && mgr->watchtower) {
        int have_poison_wire = (leaf_poison_prepared &&
                                node->poison_is_signed &&
                                node->poison_signed_tx.len > 0);
        const unsigned char *poison_data = NULL;
        size_t poison_len = 0;
        if (have_poison_wire) {
            poison_data = node->poison_signed_tx.data;
            poison_len  = node->poison_signed_tx.len;
            printf("LSP-stateless: leaf %d wire-ceremony L-stock poison TX "
                   "registered (%zu bytes, L-stock %llu sats -> %zu clients)\n",
                   leaf_side, poison_len,
                   (unsigned long long)old_l_amount,
                   node->n_signers - 1);
        } else if (old_n_outputs >= 2) {
            fprintf(stderr,
                    "LSP-stateless: registering watchtower without poison TX "
                    "(poison_prepared=%d, poison_is_signed=%d) -- DEGRADED, "
                    "breach cannot redistribute L-stock\n",
                    leaf_poison_prepared, node->poison_is_signed);
        }

        /* Collect channel indices that live on this leaf node. */
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
            node->signed_tx.data, node->signed_tx.len,
            poison_data, poison_len,
            leaf_ch_ids, n_leaf_ch);

        /* SF-WT-TRUSTLESS Phase 1b.3+1b.4 (#248): mirror the registration
         * into wt_db when --wt-db is enabled.  The in-memory watchtower
         * above remains canonical; wt_db is a parallel write that the
         * Phase 2 WT-side switchover will consume.
         *
         * All fields now correctly derived (Phase 1b.4):
         *   factory_id        = node_idx
         *   parent_txid32     = old_leaf_txid
         *   parent_vout       = 0 (chain output convention; the leaf TX's
         *                       vout=0 is the channel/chain output that
         *                       the response_tx spends)
         *   parent_value_sat  = old_chain_amount (snapshotted pre-advance)
         *   parent_spk        = old_chain_spk (snapshotted pre-advance)
         *   csv_delay         = old_csv_delay (BIP-68 low-16-bit decode)
         *   signed_response_tx = node->signed_tx
         *   response_txid32   = node->txid
         *
         * fee_bump_budget/deadline are 0 — fee-bump policy is not yet
         * exposed to leaf advance; will land if/when CPFP bumping is
         * wired for leaf-advance responses (separate scope). */
        if (lsp && lsp->wt_db && had_old_signed && old_chain_spk_len > 0) {
            int64_t watch_id = lsp_wt_register_factory_node_watch(
                lsp->wt_db,
                (uint32_t)node_idx,
                old_leaf_txid,
                /* parent_vout      */ 0,
                /* parent_value_sat */ old_chain_amount,
                old_chain_spk, old_chain_spk_len,
                /* csv_delay        */ old_csv_delay,
                node->signed_tx.data, node->signed_tx.len,
                node->txid,
                /* fee_bump_budget  */ 0,
                /* fee_bump_dline   */ 0);
            if (watch_id > 0) {
                printf("LSP-WT-TRUSTLESS: registered leaf-advance watch_id=%lld "
                       "for node %d (parent=%llu sats, csv=%u)\n",
                       (long long)watch_id, (int)node_idx,
                       (unsigned long long)old_chain_amount,
                       (unsigned)old_csv_delay);
            } else {
                fprintf(stderr,
                        "LSP-WT-TRUSTLESS: WARN — wt_db register failed for "
                        "leaf-advance node %d\n", (int)node_idx);
            }
        }

        /* Snapshot poison bytes for Step 11 persist before reset frees them. */
        if (poison_data && poison_len > 0) {
            poison_snapshot = malloc(poison_len);
            if (poison_snapshot) {
                memcpy(poison_snapshot, poison_data, poison_len);
                poison_snapshot_len = poison_len;
            }
        }
        factory_session_reset_poison(f, node_idx);
    }

    /* Step 10: notify everyone leaf advance done. */
    cJSON *done = wire_build_leaf_advance_done(leaf_side);
    for (size_t i = 0; i < lsp->n_clients; i++) {
        wire_send(lsp->client_fds[i], MSG_LEAF_ADVANCE_DONE, done);
    }
    cJSON_Delete(done);

    /* #53-B3b Phase 2: reveal the SUPERSEDED state's L-stock revocation secret to the
       advancing leaf's client (targeted, not broadcast).  The client verifies it +
       persists it so it (or its WT) can spend the Leaf-P poison if we later broadcast
       that stale state — closing Scenario B in the live protocol.  Gated on hashlock +
       a poison having been co-signed; the secret is re-derived from the seed (the poison
       session was already reset above). */
    if (f->use_hashlock_poison && leaf_poison_prepared && have_old_l_hash) {
        uint32_t old_counter = (f->nodes[node_idx].l_stock_state_counter > 0)
                               ? f->nodes[node_idx].l_stock_state_counter - 1u : 0u;
        unsigned char reveal_secret[1][32];
        if (factory_derive_l_stock_secret(f, &f->nodes[node_idx], old_counter,
                                          reveal_secret[0])) {
            uint32_t rn = (uint32_t)node_idx;
            cJSON *rev = wire_build_lstock_reveal(&rn, &old_counter, reveal_secret, 1);
            if (rev) {
                wire_send(lsp->client_fds[leaf_side], MSG_LSTOCK_REVEAL, rev);
                cJSON_Delete(rev);
                printf("LSP-stateless: revealed L-stock secret for node %d state %u\n",
                       (int)node_idx, old_counter);
            }
            memset(reveal_secret, 0, sizeof(reveal_secret));
        }
    }

    lsp_crash_checkpoint("leaf_advance_finalize_partial");

    /* Step 11: persist leaf state (same shape as legacy path). */
    if (mgr->persist) {
        if (node->is_ps_leaf) {
            extern void reverse_bytes(unsigned char *, size_t);
            unsigned char txid_display[32];
            memcpy(txid_display, node->txid, 32);
            reverse_bytes(txid_display, 32);
            persist_save_ps_chain_entry(
                (persist_t *)mgr->persist, 0,
                (uint32_t)node_idx,
                node->ps_chain_len - 1,
                f->counter.current_epoch,
                txid_display,
                node->signed_tx.data, node->signed_tx.len,
                node->outputs[0].amount_sats,
                /* poison_tx */ poison_snapshot, poison_snapshot_len);
        } else {
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
    }

    if (node->is_ps_leaf)
        printf("LSP-stateless: PS leaf %d advanced (node %zu), chain_len %d\n",
               leaf_side, node_idx, node->ps_chain_len);
    else
        printf("LSP-stateless: DW leaf %d advanced (node %zu), DW state %u\n",
               leaf_side, node_idx, f->leaf_layers[leaf_side].current_state);

    if (mgr->persist && c3_round_id > 0) {
        persist_save_signing_round_done((persist_t *)mgr->persist, c3_round_id,
                                          (uint32_t)f->n_participants,
                                          (uint32_t)f->n_participants,
                                          "success", NULL, NULL);
    }
    free(poison_snapshot);
    return 1;
}

/* --- Per-leaf advance (arity-1 DW and arity-PS chained-TX, split-round signing) --- */

/* Advance one leaf, do split-round 2-of-2 signing with the affected client,
   and notify all clients. Supports FACTORY_ARITY_1 (DW) and FACTORY_ARITY_PS.
   leaf_side: 0..n_leaf_nodes-1 (same as client index for these arities).
   Returns 1 on success, 0 on failure or skip. */
static int lsp_advance_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp, int leaf_side) {
    return lsp_advance_leaf_stateless(mgr, lsp, leaf_side);
}

/* Tier B state-advance ceremony driver (Gap B + F).

   Triggered when factory_advance_leaf_unsigned() returns -1 — the
   triggering leaf's per-leaf DW counter exhausted, the root layer
   advanced, and every non-PS-leaf node's nSequence (or input-txid via
   parent rebuild) changed.  build_all_unsigned_txs() has already
   rebuilt every node->unsigned_tx; we now need to drive an N-of-N
   MuSig signing ceremony bundled across all such nodes.

   Wire round structure (see docs/rotation-ceremony.md):
     LSP   → all clients: STATE_ADVANCE_PROPOSE (epoch, trigger_leaf, lsp_nonces[])
     Client → LSP:        PATH_NONCE_BUNDLE (client's nonces for nodes it signs)
     LSP   → all clients: PATH_ALL_NONCES (every signer's nonce per node)
     Client → LSP:        PATH_PSIG_BUNDLE (client's partial sigs)
     LSP   → all clients: PATH_SIGN_DONE (epoch confirms)

   Returns 1 on success, 0 on any failure (clients dropped, timeouts,
   crypto failures).  On failure the factory_t is left in a state where
   unsigned TXs are rebuilt but signed_tx is unset for affected nodes;
   the LSP can retry by calling lsp_run_state_advance() again.  The
   on-chain factory is unaffected — old signed TXs remain stored
   (overlap window) and the watchtower still has the old burn TXs. */
/* Phase 1e.2.b scaffolding: stub for the reversed-flow stateless Tier B
   state advance ceremony.  Dispatched from the public function when
   SS_MUSIG_STATELESS=1 is set.  Currently returns -1 for all cases
   (caller falls through to legacy lsp_run_state_advance) — Phase 1e.2.c
   will fill in the actual multi-leaf MuSig ceremony using the wire codec
   added in Phase 1e.2.a (#328).

   Wire flow (per Phase 1e.2.a opcodes):
     LSP   -> Client:  MSG_STATE_ADV_PROPOSE_INTENT (0x81)
     Client -> LSP:    MSG_STATE_ADV_CLIENT_PATH_NONCES (0x82)
     LSP atomic:       gen lsp_secnonces + set nonces + finalize + create_partial_sigs
                        (lsp_secnonces zeroed before next send)
     LSP   -> Client:  MSG_STATE_ADV_LSP_RESPONSE (0x83) per-leaf data
     Client -> LSP:    MSG_STATE_ADV_CLIENT_FINAL_PSIGS (0x84)
     LSP:              aggregate + factory_session_complete_node per leaf
     LSP   -> Client:  MSG_PATH_SIGN_DONE (existing terminal opcode)

   Returns: 1 on success, 0 on failure, -1 if the stateless function cannot
   handle this case (caller falls through to legacy). */
static int lsp_run_state_advance_stateless(lsp_channel_mgr_t *mgr,
                                             lsp_t *lsp,
                                             int trigger_leaf_side) {
    if (!mgr || !lsp) return 0;
    factory_t *f = &lsp->factory;

    /* Phase 1e.2.e (Tier B poison wiring): the watchtower is configured in
       production.  Instead of refusing, we run the per-DW-leaf L-stock poison
       ceremony in lockstep with the state ceremony (mirror of leaf-advance
       #330, applied per affected leaf).  Each poison step is gated on
       poison_prepared[k]; a degraded leaf simply registers without poison. */

    /* Step 1: Build affected[] (same logic as legacy at line ~2725). */
    size_t affected[FACTORY_MAX_NODES];
    size_t n_affected = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *n = &f->nodes[i];
        if (n->is_ps_leaf && trigger_leaf_side != -1) continue;
        if (!n->is_built) continue;
        if (n->is_signed) continue;
        affected[n_affected++] = i;
    }
    if (n_affected == 0) {
        /* Nothing to do.  Send DONE for completeness. */
        cJSON *done = wire_build_path_sign_done((uint32_t)f->counter.current_epoch);
        for (size_t i = 0; i < lsp->n_clients; i++)
            wire_send(lsp->client_fds[i], MSG_PATH_SIGN_DONE, done);
        cJSON_Delete(done);
        return 1;
    }

    /* C3 Tier 2 (PR-C-4): journal this stateless Tier B ceremony.
       Mirrors the legacy lsp_run_state_advance round_start.
       Participant-level rows (signing_round_participants) are added
       by the recv loops below.  row_id<=0 disables journal calls. */
    int64_t c3_round_id = -1;
    if (mgr->persist) {
        persist_save_signing_round_start((persist_t *)mgr->persist,
                                           /* factory_id = */ 0,
                                           /* node_idx = */ 0,
                                           "tier_b_rollover",
                                           f->counter.current_epoch,
                                           (uint32_t)f->n_participants,
                                           &c3_round_id);
    }

    /* SF-BACKUP-PRE-ROTATION #213: snapshot the LSP DB to backup_dir
       (if configured) before any state mutation.  Failure to snapshot
       warns but does NOT abort the rotation — operator decides.
       Mirrors the legacy lsp_run_state_advance hook that the stateless
       redesign #271/#330 didn't carry over. */
    if (lsp->backup_dir && mgr->persist) {
        char snap_path[512];
        time_t now = time(NULL);
        snprintf(snap_path, sizeof(snap_path),
                 "%s/lsp_pre_rotation_%u_%ld.db",
                 lsp->backup_dir,
                 (unsigned)f->counter.current_epoch,
                 (long)now);
        if (!persist_take_snapshot((persist_t *)mgr->persist, snap_path,
                                    "pre_rotation")) {
            fprintf(stderr, "WARN: pre-rotation snapshot failed; "
                            "continuing rotation anyway\n");
        }
    }

    /* MVP refusal: multi-input on any affected node. */
    for (size_t k = 0; k < n_affected; k++) {
        if (factory_node_uses_multi_input(f, affected[k])) {
            fprintf(stderr,
                "LSP-stateless Tier B: affected node %zu uses multi-input -- "
                "falling back to legacy\n", affected[k]);
            return -1;
        }
    }

    /* Step 1.5 (Tier B poison): capture each affected DW leaf's OLD signed
       state + prepare its L-stock poison TX (mirror of leaf-advance #330).
       PS leaves carry no L-stock poison (it lives in their sub-factory chain).
       Per-affected-node arrays indexed by affected[] order (k). */
    const uint64_t TIERB_POISON_FEE_SATS = 1000;
    int poison_prepared[FACTORY_MAX_NODES];
    unsigned char poison_old_txid[FACTORY_MAX_NODES][32];
    uint64_t poison_old_l_amount[FACTORY_MAX_NODES];
    int poison_client_slot[FACTORY_MAX_NODES];
    unsigned char lsp_poison_pubnonces_per_node[FACTORY_MAX_NODES][66];
    unsigned char lsp_poison_psigs_per_node[FACTORY_MAX_NODES][32];
    /* SF-WT-TRUSTLESS Phase 1b.5 (#248): per-affected-node snapshot of
     * the OLD chain output (vout=0) value + SPK + BIP-68 CSV.  Indexed
     * by affected[] order (k), mirrors the per-k poison_* arrays. */
    int wt_had_old[FACTORY_MAX_NODES];
    uint64_t wt_old_chain_amount[FACTORY_MAX_NODES];
    unsigned char wt_old_chain_spk[FACTORY_MAX_NODES][34];
    size_t wt_old_chain_spk_len[FACTORY_MAX_NODES];
    uint32_t wt_old_csv_delay[FACTORY_MAX_NODES];
    for (size_t k = 0; k < n_affected; k++) {
        poison_prepared[k] = 0;
        poison_client_slot[k] = -1;
        poison_old_l_amount[k] = 0;
        memset(poison_old_txid[k], 0, 32);
        memset(lsp_poison_pubnonces_per_node[k], 0, 66);
        memset(lsp_poison_psigs_per_node[k], 0, 32);
        factory_node_t *an = &f->nodes[affected[k]];
        int had_old = (an->is_signed && an->signed_tx.len > 0);
        int old_no = an->n_outputs;
        if (had_old) memcpy(poison_old_txid[k], an->txid, 32);
        poison_old_l_amount[k] = (old_no >= 2)
            ? an->outputs[old_no - 1].amount_sats : 0;
        /* Phase 1b.5: chain output (vout=0) snapshot for wt_db. */
        wt_had_old[k] = had_old;
        wt_old_chain_amount[k] = (old_no >= 1) ? an->outputs[0].amount_sats : 0;
        wt_old_chain_spk_len[k] = (old_no >= 1) ? an->outputs[0].script_pubkey_len : 0;
        if (wt_old_chain_spk_len[k] > 34) wt_old_chain_spk_len[k] = 34;
        if (old_no >= 1)
            memcpy(wt_old_chain_spk[k],
                   an->outputs[0].script_pubkey,
                   wt_old_chain_spk_len[k]);
        wt_old_csv_delay[k] = (uint32_t)(an->nsequence & 0xFFFFu);
        if (mgr->watchtower && !an->is_ps_leaf && had_old && old_no >= 2 &&
            poison_old_l_amount[k] > TIERB_POISON_FEE_SATS +
                (uint64_t)(an->n_signers - 1) * 330u) {
            if (factory_session_prepare_poison_tx_leaf(
                    f, affected[k], poison_old_txid[k], (uint32_t)(old_no - 1),
                    poison_old_l_amount[k], TIERB_POISON_FEE_SATS,
                    NULL /* #53-B3b: capture per-node H_old when daemon hashlock on */)) {
                poison_prepared[k] = 1;  /* init_node_poison after state init */
            }
        }
    }

    /* Step 2: Init MuSig session for each affected node (state + poison). */
    for (size_t k = 0; k < n_affected; k++) {
        if (!factory_session_init_node(f, affected[k])) {
            fprintf(stderr,
                "LSP-stateless Tier B: init_node[%zu] failed\n", affected[k]);
            return 0;
        }
        if (poison_prepared[k] &&
            !factory_session_init_node_poison(f, affected[k])) {
            fprintf(stderr,
                "LSP-stateless Tier B: init_node_poison[%zu] -- degrading leaf\n",
                affected[k]);
            factory_session_reset_poison(f, affected[k]);
            poison_prepared[k] = 0;
        }
    }

    /* Step 3: Send PROPOSE_INTENT to all clients (no nonces). */
    /* SF-CRASH-INJECT-WIRE #245 Half A: journal Tier B as a ROTATE ceremony. */
    unsigned char cer_id[8] = {0};
    int cer_persisted = 0;
    if (mgr->persist) {
        lsp_ceremony_derive_id(lsp->factory.funding_txid,
                                PERSIST_CEREMONY_TYPE_ROTATE,
                                f->counter.current_epoch, cer_id);
        if (persist_save_ceremony((persist_t *)mgr->persist, cer_id,
                                   lsp->factory.funding_txid,
                                   PERSIST_CEREMONY_TYPE_ROTATE,
                                   NULL, 0, f->cltv_timeout))
            cer_persisted = 1;
    }
    cJSON *propose = wire_build_state_adv_propose_intent(
        (uint32_t)f->counter.current_epoch, (uint32_t)n_affected,
        trigger_leaf_side);
    for (size_t c = 0; c < lsp->n_clients; c++) {
        if (!wire_send(lsp->client_fds[c], MSG_STATE_ADV_PROPOSE_INTENT, propose)) {
            cJSON_Delete(propose);
            fprintf(stderr,
                "LSP-stateless Tier B: send PROPOSE_INTENT[%zu] failed\n", c);
            return 0;
        }
    }
    cJSON_Delete(propose);
    if (cer_persisted) {
        for (size_t c = 0; c < lsp->n_clients; c++) {
            unsigned char pk33[33];
            lsp_ceremony_get_client_pubkey33(lsp, c, pk33);
            (void)persist_save_participant_phase((persist_t *)mgr->persist, cer_id,
                pk33, PERSIST_CEREMONY_PHASE_SENT, NULL, NULL, 0, 0);
        }
    }
    printf("LSP: STATE_ADV_PROPOSE_INTENT sent to %zu clients (Tier B)\n", lsp->n_clients);
    fflush(stdout);

    lsp_crash_checkpoint("state_advance_propose");

    /* Step 4: Collect CLIENT_PATH_NONCES from each client.
       Each client sends pubnonces for the affected nodes they're a signer on.
       Wire format is per-leaf array (66 bytes each) indexed by affected[] order.
       Client must produce nonces only for affected nodes where they sign;
       non-participating slots get all-zero buffers (skip those). */
    unsigned char client_pubnonces_per_node[FACTORY_MAX_NODES][66];
    int client_slot_per_node[FACTORY_MAX_NODES];
    (void)client_slot_per_node; /* recorded for future audit; unused in MVP */
    for (size_t k = 0; k < n_affected; k++) client_slot_per_node[k] = -1;

    for (size_t c = 0; c < lsp->n_clients; c++) {
        wire_msg_t nmsg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[c], &nmsg,
                                          WIRE_CEREMONY_BUNDLE_TIMEOUT_SEC) ||
            nmsg.msg_type != MSG_STATE_ADV_CLIENT_PATH_NONCES) {
            fprintf(stderr,
                "LSP-stateless Tier B: expected CLIENT_PATH_NONCES from client %zu, "
                "got 0x%02x\n", c, nmsg.msg_type);
            if (nmsg.json) cJSON_Delete(nmsg.json);
            return 0;
        }
        unsigned char this_client_pn[FACTORY_MAX_NODES][66];
        unsigned char this_client_poison_pn[FACTORY_MAX_NODES][66];
        memset(this_client_poison_pn, 0, sizeof(this_client_poison_pn));
        if (!wire_parse_state_adv_client_path_nonces(nmsg.json,
                                                       (unsigned char *)this_client_pn,
                                                       (uint32_t)n_affected,
                                                       (unsigned char *)this_client_poison_pn)) {
            cJSON_Delete(nmsg.json);
            fprintf(stderr,
                "LSP-stateless Tier B: parse CLIENT_PATH_NONCES from client %zu failed\n",
                c);
            return 0;
        }
        cJSON_Delete(nmsg.json);
        /* C3 Tier 2 (PR-C-4): client c's nonce bundle arrived.
           Clients are slots 1..n_clients (LSP is slot 0). */
        if (mgr->persist && c3_round_id > 0) {
            persist_save_signing_round_participant_nonce(
                (persist_t *)mgr->persist, c3_round_id,
                /* signer_slot = */ (uint32_t)(c + 1));
        }

        /* Distribute: for each affected node, if this client is a signer,
           record their pubnonce + slot.  An all-zero pubnonce indicates
           "I'm not a signer on this leaf" -- skip. */
        for (size_t k = 0; k < n_affected; k++) {
            int slot = factory_find_signer_slot(f, affected[k], (uint32_t)(c + 1));
            if (slot < 0) continue;  /* this client doesn't sign this node */
            /* Skip if all zeros (client signaled no nonce for this leaf) */
            int all_zero = 1;
            for (size_t b = 0; b < 66; b++) {
                if (this_client_pn[k][b] != 0) { all_zero = 0; break; }
            }
            if (all_zero) continue;
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(lsp->ctx, &pn, this_client_pn[k]) ||
                !factory_session_set_nonce(f, affected[k], (size_t)slot, &pn)) {
                fprintf(stderr,
                    "LSP-stateless Tier B: parse/set client[%zu] nonce for node %zu failed\n",
                    c, affected[k]);
                return 0;
            }
            memcpy(client_pubnonces_per_node[k], this_client_pn[k], 66);
            client_slot_per_node[k] = slot;

            /* Poison: if this leaf has a prepared poison TX and the client
               sent a (non-zero) poison nonce, set it on the poison session. */
            if (poison_prepared[k]) {
                int pz = 1;
                for (size_t b = 0; b < 66; b++)
                    if (this_client_poison_pn[k][b]) { pz = 0; break; }
                if (pz) {
                    fprintf(stderr,
                        "LSP-stateless Tier B: client %zu sent no poison nonce "
                        "for node %zu -- degrading leaf poison\n", c, affected[k]);
                    factory_session_reset_poison(f, affected[k]);
                    poison_prepared[k] = 0;
                } else {
                    secp256k1_musig_pubnonce ppn;
                    if (!musig_pubnonce_parse(lsp->ctx, &ppn, this_client_poison_pn[k]) ||
                        !factory_session_set_nonce_poison(f, affected[k], (size_t)slot, &ppn)) {
                        fprintf(stderr,
                            "LSP-stateless Tier B: set client poison nonce node %zu "
                            "-- degrading\n", affected[k]);
                        factory_session_reset_poison(f, affected[k]);
                        poison_prepared[k] = 0;
                    } else {
                        poison_client_slot[k] = slot;
                    }
                }
            }
        }
    }

    lsp_crash_checkpoint("state_advance_nonced");

    /* Step 5: ATOMIC -- gen LSP nonces, set+finalize, create_partial_sig per leaf.
       Uses musig_nonce_pool_generate (same as legacy line 2790) but ONLY now,
       after all client nonces have arrived.  No LSP secnonces held across recv. */
    size_t lsp_node_count = 0;
    for (size_t k = 0; k < n_affected; k++) {
        if (factory_find_signer_slot(f, affected[k], 0) >= 0)
            lsp_node_count++;
    }
    if (lsp_node_count == 0) {
        fprintf(stderr, "LSP-stateless Tier B: LSP not a signer on any affected\n");
        return 0;
    }

    musig_nonce_pool_t lsp_pool;
    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) return 0;
    if (!musig_nonce_pool_generate(lsp->ctx, &lsp_pool, lsp_node_count,
                                    lsp_seckey, &lsp->lsp_pubkey, NULL)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP-stateless Tier B: nonce pool gen failed\n");
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    int lsp_slot_per_node[FACTORY_MAX_NODES];
    (void)lsp_slot_per_node; /* recorded for future audit; unused in MVP */
    unsigned char lsp_pubnonces_per_node[FACTORY_MAX_NODES][66];
    unsigned char lsp_psigs_per_node[FACTORY_MAX_NODES][32];
    for (size_t k = 0; k < n_affected; k++) {
        lsp_slot_per_node[k] = -1;
        memset(lsp_pubnonces_per_node[k], 0, 66);
        memset(lsp_psigs_per_node[k], 0, 32);
    }

    secp256k1_keypair lsp_kp = lsp->lsp_keypair;
    for (size_t k = 0; k < n_affected; k++) {
        int slot = factory_find_signer_slot(f, affected[k], 0);
        if (slot < 0) continue;
        secp256k1_musig_secnonce *sec;
        secp256k1_musig_pubnonce pub;
        if (!musig_nonce_pool_next(&lsp_pool, &sec, &pub)) {
            fprintf(stderr,
                "LSP-stateless Tier B: pool exhausted at node %zu\n", affected[k]);
            return 0;
        }
        lsp_slot_per_node[k] = slot;
        musig_pubnonce_serialize(lsp->ctx, lsp_pubnonces_per_node[k], &pub);
        if (!factory_session_set_nonce(f, affected[k], (size_t)slot, &pub)) {
            fprintf(stderr,
                "LSP-stateless Tier B: set LSP nonce for %zu failed\n", affected[k]);
            return 0;
        }
        if (!factory_session_finalize_node(f, affected[k])) {
            fprintf(stderr,
                "LSP-stateless Tier B: finalize_node[%zu] failed\n", affected[k]);
            return 0;
        }
        secp256k1_musig_partial_sig psig;
        if (!musig_create_partial_sig(lsp->ctx, &psig, sec, &lsp_kp,
                                        &f->nodes[affected[k]].signing_session)) {
            fprintf(stderr,
                "LSP-stateless Tier B: create_partial_sig[%zu] failed\n",
                affected[k]);
            return 0;
        }
        /* sec zeroed by musig_create_partial_sig */
        musig_partial_sig_serialize(lsp->ctx, lsp_psigs_per_node[k], &psig);
        if (!factory_session_set_partial_sig(f, affected[k], (size_t)slot, &psig)) {
            fprintf(stderr,
                "LSP-stateless Tier B: set LSP psig[%zu] failed\n", affected[k]);
            return 0;
        }

        /* Poison (lockstep): LSP poison nonce -> set -> finalize -> partial sig.
           lsp_poison_secnonce is a loop local, zeroed by create_partial_sig in
           this same iteration -- no poison secnonce held across the wire recv
           that follows (same stateless invariant as the state nonce). */
        if (poison_prepared[k]) {
            secp256k1_musig_secnonce lsp_poison_secnonce;
            secp256k1_musig_pubnonce lsp_poison_pubnonce;
            secp256k1_musig_partial_sig lsp_poison_psig;
            unsigned char lsp_psk[32];
            /* musig_generate_nonce takes (seckey32, pubkey, keyagg.cache); the
               state lsp_seckey was already zeroed after the pool gen, so derive
               a fresh local seckey and zero it right after. */
            int pz_ok =
                secp256k1_keypair_sec(lsp->ctx, lsp_psk, &lsp->lsp_keypair) &&
                musig_generate_nonce(lsp->ctx, &lsp_poison_secnonce, &lsp_poison_pubnonce,
                                       lsp_psk, &lsp->lsp_pubkey,
                                       &f->nodes[affected[k]].keyagg.cache) &&
                factory_session_set_nonce_poison(f, affected[k], (size_t)slot,
                                                   &lsp_poison_pubnonce) &&
                factory_session_finalize_node_poison(f, affected[k]) &&
                musig_create_partial_sig(lsp->ctx, &lsp_poison_psig,
                                           &lsp_poison_secnonce, &lsp_kp,
                                           &f->nodes[affected[k]].poison_signing_session) &&
                factory_session_set_partial_sig_poison(f, affected[k], (size_t)slot,
                                                         &lsp_poison_psig);
            memset(lsp_psk, 0, 32);
            /* Zero the poison secnonce on any path: create_partial_sig already
               zeroed it on success; on early-chain failure this clears the
               generated-but-unconsumed secnonce so none lingers across the recv. */
            memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
            if (!pz_ok) {
                fprintf(stderr,
                    "LSP-stateless Tier B: LSP poison sign[%zu] -- degrading leaf\n",
                    affected[k]);
                factory_session_reset_poison(f, affected[k]);
                poison_prepared[k] = 0;
            } else {
                musig_pubnonce_serialize(lsp->ctx, lsp_poison_pubnonces_per_node[k],
                                          &lsp_poison_pubnonce);
                musig_partial_sig_serialize(lsp->ctx, lsp_poison_psigs_per_node[k],
                                             &lsp_poison_psig);
            }
        }
    }
    /* C3 Tier 2 (PR-C-4): LSP completed both its nonce and psig
       contributions across all affected nodes (slot 0). */
    if (mgr->persist && c3_round_id > 0) {
        persist_save_signing_round_participant_nonce(
            (persist_t *)mgr->persist, c3_round_id, /* signer_slot = */ 0);
        persist_save_signing_round_participant_psig(
            (persist_t *)mgr->persist, c3_round_id,
            /* signer_slot = */ 0, "verified");
    }

    /* INVARIANT: every LSP secnonce in lsp_pool has been pulled and zeroed
       by musig_create_partial_sig.  No LSP secnonce in scope for the recv
       that follows. */

    /* Step 7: Send LSP_RESPONSE with per-node pubnonces + psigs to all clients.
       Gap A: also forward EVERY signer's pubnonce per node (from the session,
       which holds all collected nonces) so each client can build the aggnonce
       for multi-signer nodes (root/intermediates), not just 2-of-2 leaves. */
    size_t total_nonce_slots = 0;
    for (size_t k = 0; k < n_affected; k++)
        total_nonce_slots += f->nodes[affected[k]].n_signers;
    unsigned char *all_pn_flat = calloc(total_nonce_slots ? total_nonce_slots : 1, 66);
    if (!all_pn_flat) {
        fprintf(stderr, "LSP-stateless Tier B: alloc all_pn_flat failed\n");
        return 0;
    }
    {
        size_t base = 0;
        for (size_t k = 0; k < n_affected; k++) {
            factory_node_t *an = &f->nodes[affected[k]];
            for (size_t s = 0; s < an->n_signers; s++)
                musig_pubnonce_serialize(lsp->ctx, all_pn_flat + (base + s) * 66,
                                         &an->signing_session.pubnonces[s]);
            base += an->n_signers;
        }
    }
    cJSON *response = wire_build_state_adv_lsp_response(
        (const unsigned char *)lsp_pubnonces_per_node,
        (const unsigned char *)lsp_psigs_per_node,
        (uint32_t)n_affected,
        (const unsigned char *)lsp_poison_pubnonces_per_node,
        (const unsigned char *)lsp_poison_psigs_per_node,
        all_pn_flat, (uint32_t)(total_nonce_slots * 66));
    free(all_pn_flat); all_pn_flat = NULL;
    for (size_t c = 0; c < lsp->n_clients; c++) {
        if (!wire_send(lsp->client_fds[c], MSG_STATE_ADV_LSP_RESPONSE, response)) {
            cJSON_Delete(response);
            fprintf(stderr,
                "LSP-stateless Tier B: send LSP_RESPONSE[%zu] failed\n", c);
            return 0;
        }
    }
    cJSON_Delete(response);

    /* Step 8: Collect CLIENT_FINAL_PSIGS from each client. */
    for (size_t c = 0; c < lsp->n_clients; c++) {
        wire_msg_t pmsg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[c], &pmsg,
                                          WIRE_CEREMONY_BUNDLE_TIMEOUT_SEC) ||
            pmsg.msg_type != MSG_STATE_ADV_CLIENT_FINAL_PSIGS) {
            fprintf(stderr,
                "LSP-stateless Tier B: expected CLIENT_FINAL_PSIGS from client %zu, "
                "got 0x%02x\n", c, pmsg.msg_type);
            if (pmsg.json) cJSON_Delete(pmsg.json);
            return 0;
        }
        unsigned char this_client_psigs[FACTORY_MAX_NODES][32];
        unsigned char this_client_poison_psigs[FACTORY_MAX_NODES][32];
        memset(this_client_poison_psigs, 0, sizeof(this_client_poison_psigs));
        if (!wire_parse_state_adv_client_final_psigs(pmsg.json,
                                                       (unsigned char *)this_client_psigs,
                                                       (uint32_t)n_affected,
                                                       (unsigned char *)this_client_poison_psigs)) {
            cJSON_Delete(pmsg.json);
            fprintf(stderr,
                "LSP-stateless Tier B: parse CLIENT_FINAL_PSIGS[%zu] failed\n", c);
            return 0;
        }
        cJSON_Delete(pmsg.json);
        /* C3 Tier 2 (PR-C-4): client c's psig bundle parsed + accepted. */
        if (mgr->persist && c3_round_id > 0) {
            persist_save_signing_round_participant_psig(
                (persist_t *)mgr->persist, c3_round_id,
                (uint32_t)(c + 1), "verified");
        }
        for (size_t k = 0; k < n_affected; k++) {
            int slot = factory_find_signer_slot(f, affected[k], (uint32_t)(c + 1));
            if (slot < 0) continue;
            /* Skip if all zeros (client signaled no psig for this leaf) */
            int all_zero = 1;
            for (size_t b = 0; b < 32; b++) {
                if (this_client_psigs[k][b] != 0) { all_zero = 0; break; }
            }
            if (all_zero) continue;
            secp256k1_musig_partial_sig psig;
            if (!musig_partial_sig_parse(lsp->ctx, &psig, this_client_psigs[k]) ||
                !factory_session_set_partial_sig(f, affected[k], (size_t)slot, &psig)) {
                fprintf(stderr,
                    "LSP-stateless Tier B: set client[%zu] psig for %zu failed\n",
                    c, affected[k]);
                return 0;
            }
            /* Poison: set this client's poison partial sig if this leaf still
               has poison active and the client signed for it. */
            if (poison_prepared[k] && (int)slot == poison_client_slot[k]) {
                secp256k1_musig_partial_sig ppsig;
                if (!musig_partial_sig_parse(lsp->ctx, &ppsig, this_client_poison_psigs[k]) ||
                    !factory_session_set_partial_sig_poison(f, affected[k],
                                                              (size_t)slot, &ppsig)) {
                    fprintf(stderr,
                        "LSP-stateless Tier B: set client poison psig node %zu "
                        "-- degrading\n", affected[k]);
                    factory_session_reset_poison(f, affected[k]);
                    poison_prepared[k] = 0;
                }
            }
        }
    }

    lsp_crash_checkpoint("state_advance_signed");

    /* Step 9b (poison): complete the poison session for each leaf that still
       has poison active -> attaches node->poison_signed_tx. */
    for (size_t k = 0; k < n_affected; k++) {
        if (poison_prepared[k] &&
            !factory_session_complete_node_poison(f, affected[k])) {
            fprintf(stderr,
                "LSP-stateless Tier B: complete_node_poison[%zu] -- degrading\n",
                affected[k]);
            factory_session_reset_poison(f, affected[k]);
            poison_prepared[k] = 0;
        }
    }

    /* Step 9: Complete each affected node (aggregate psigs + attach signed_tx). */
    for (size_t k = 0; k < n_affected; k++) {
        if (!factory_session_complete_node(f, affected[k])) {
            fprintf(stderr,
                "LSP-stateless Tier B: complete_node[%zu] failed\n", affected[k]);
            return 0;
        }
    }

    /* Step 9c (Gap B): broadcast the full per-node signer-PSIG matrix so each
       client can locally complete multi-signer nodes (it only holds its own +
       the LSP's psig).  node->partial_sigs[] holds every psig after Step 8. */
    {
        size_t total_psig_slots = 0;
        for (size_t k = 0; k < n_affected; k++)
            total_psig_slots += f->nodes[affected[k]].n_signers;
        unsigned char *all_psig_flat = calloc(total_psig_slots ? total_psig_slots : 1, 32);
        if (!all_psig_flat) {
            fprintf(stderr, "LSP-stateless Tier B: alloc all_psig_flat failed\n");
            return 0;
        }
        size_t base = 0;
        for (size_t k = 0; k < n_affected; k++) {
            factory_node_t *an = &f->nodes[affected[k]];
            for (size_t s = 0; s < an->n_signers; s++)
                musig_partial_sig_serialize(lsp->ctx, all_psig_flat + (base + s) * 32,
                                            &an->partial_sigs[s]);
            base += an->n_signers;
        }
        cJSON *apm = wire_build_state_adv_all_psigs(all_psig_flat,
                                                    (uint32_t)(total_psig_slots * 32));
        free(all_psig_flat);
        if (!apm) {
            fprintf(stderr, "LSP-stateless Tier B: build ALL_PSIGS failed\n");
            return 0;
        }
        for (size_t c = 0; c < lsp->n_clients; c++) {
            if (!wire_send(lsp->client_fds[c], MSG_STATE_ADV_ALL_PSIGS, apm)) {
                cJSON_Delete(apm);
                fprintf(stderr, "LSP-stateless Tier B: send ALL_PSIGS[%zu] failed\n", c);
                return 0;
            }
        }
        cJSON_Delete(apm);
    }

    /* Step 10 (Tier B poison): register each affected leaf's new state +
       wire-signed L-stock poison TX with the watchtower (mirror of legacy
       Step 10 / leaf-advance #330).  poison_signed_tx is NULL for leaves that
       degraded or were never poison-eligible (PS leaves / no old L-stock). */
    if (mgr->watchtower) {
        for (size_t k = 0; k < n_affected; k++) {
            factory_node_t *an = &f->nodes[affected[k]];
            const unsigned char *poison_data = NULL;
            size_t poison_len = 0;
            if (poison_prepared[k] && an->poison_is_signed &&
                an->poison_signed_tx.len > 0) {
                poison_data = an->poison_signed_tx.data;
                poison_len  = an->poison_signed_tx.len;
                printf("LSP-stateless Tier B: node %zu poison TX signed "
                       "(%zu bytes, L-stock %llu sats)\n", affected[k], poison_len,
                       (unsigned long long)poison_old_l_amount[k]);
            }
            uint32_t leaf_ch_ids[FACTORY_MAX_SIGNERS];
            size_t n_leaf_ch = 0;
            for (size_t cc = 0; cc < mgr->n_channels; cc++) {
                size_t c_node; uint32_t c_vout;
                client_to_leaf(cc, f, &c_node, &c_vout);
                if (c_node == affected[k])
                    leaf_ch_ids[n_leaf_ch++] = (uint32_t)cc;
            }
            watchtower_watch_factory_node_with_channels(mgr->watchtower,
                (uint32_t)affected[k], poison_old_txid[k],
                an->signed_tx.data, an->signed_tx.len,
                poison_data, poison_len,
                leaf_ch_ids, n_leaf_ch);

            /* SF-WT-TRUSTLESS Phase 1b.5: parallel wt_db register for
             * Tier B state advance.  Same pattern as leaf-advance
             * (Phase 1b.3+1b.4); uses the per-k snapshot captured before
             * factory_advance mutated the OLD chain output. */
            if (lsp && lsp->wt_db && wt_had_old[k] && wt_old_chain_spk_len[k] > 0) {
                int64_t watch_id = lsp_wt_register_factory_node_watch(
                    lsp->wt_db,
                    (uint32_t)affected[k],
                    poison_old_txid[k],
                    /* parent_vout      */ 0,
                    /* parent_value_sat */ wt_old_chain_amount[k],
                    wt_old_chain_spk[k], wt_old_chain_spk_len[k],
                    /* csv_delay        */ wt_old_csv_delay[k],
                    an->signed_tx.data, an->signed_tx.len,
                    an->txid,
                    /* fee_bump_budget  */ 0,
                    /* fee_bump_dline   */ 0);
                if (watch_id > 0) {
                    printf("LSP-WT-TRUSTLESS: registered tier-B watch_id=%lld "
                           "for node %zu (parent=%llu sats, csv=%u)\n",
                           (long long)watch_id, affected[k],
                           (unsigned long long)wt_old_chain_amount[k],
                           (unsigned)wt_old_csv_delay[k]);
                } else {
                    fprintf(stderr,
                            "LSP-WT-TRUSTLESS: WARN — wt_db register failed for "
                            "tier-B node %zu\n", affected[k]);
                }
            }

            if (poison_prepared[k])
                factory_session_reset_poison(f, affected[k]);
        }
    }

    lsp_crash_checkpoint("state_advance_finalize_partial");

    /* Step 11.5 (F1): persist new-epoch chain[0] for every PS leaf + sub-factory
       node, mirroring the legacy lsp_run_state_advance.  Only fires on
       root-driven Tier B (the only path that re-signs PS leaves).  Without this
       the DB keeps the OLD epoch chain[0] and force-close after rollover cannot
       reconstruct the new signed state ("persisted bytes differ"). */
    if (trigger_leaf_side == -1 && mgr->persist) {
        int saved = lsp_persist_ps_chain0_all(mgr->persist, f);
        if (saved > 0)
            printf("LSP: Tier B F1: persisted new-epoch chain[0] for %d PS node(s)\n",
                   saved);
    }

    /* C3 Tier 2 (PR-C-4): mark stateless Tier B ceremony complete. */
    if (mgr->persist && c3_round_id > 0) {
        persist_save_signing_round_done((persist_t *)mgr->persist,
                                          c3_round_id,
                                          (uint32_t)n_affected,
                                          (uint32_t)n_affected,
                                          "success",
                                          NULL,
                                          NULL);
    }

    /* Step 10: Broadcast DONE (existing opcode). */
    cJSON *done = wire_build_path_sign_done((uint32_t)f->counter.current_epoch);
    for (size_t c = 0; c < lsp->n_clients; c++)
        wire_send(lsp->client_fds[c], MSG_PATH_SIGN_DONE, done);
    cJSON_Delete(done);

    printf("LSP-stateless Tier B: state advance complete for %zu affected nodes\n",
           n_affected);

    /* CL5: --kill-after-state-advance clean exit for restart-harness tests.
       Mirrors the legacy lsp_run_state_advance hook so the stateless path
       honours the same test contract (clean rc=0 right after the first
       state-advance ceremony completes). */
    if (superscalar_cheat_allowed() && getenv("SS_KILL_AFTER_STATE_ADVANCE")) {  /* #9: gated */
        printf("CL5: SS_KILL_AFTER_STATE_ADVANCE set — clean exit after ceremony\n");
        fflush(stdout);
        exit(0);
    }
    return 1;
}

int lsp_run_state_advance(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                            int trigger_leaf_side) {
    return lsp_run_state_advance_stateless(mgr, lsp, trigger_leaf_side);
}

/* F1: Persist chain[0] for every PS leaf and PS sub-factory node.

   Called from:
   - tools/superscalar_lsp.c after factory creation (initial chain[0] save).
   - lsp_run_state_advance after a root-driven Tier B (new-epoch chain[0]).

   is_ps_leaf is set on both single-PS-leaf nodes (k=1) and PS sub-factory
   nodes (k>=2, see factory.c:1138), so a single flag check covers both.

   The save is idempotent (INSERT OR REPLACE) so callers can save uncondi-
   tionally; for root-driven Tier B the new row simply replaces the old
   epoch's row, since both are keyed by (factory_id, node_idx).

   Returns the number of rows persisted. */
int lsp_persist_ps_chain0_all(void *persist, factory_t *f) {
    if (!persist || !f) return 0;
    if (f->leaf_arity != FACTORY_ARITY_PS) return 0;
    extern void reverse_bytes(unsigned char *, size_t);
    persist_t *p = (persist_t *)persist;
    int saved = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *n = &f->nodes[i];
        if (!n->is_ps_leaf) continue;
        if (!n->is_signed || n->signed_tx.len == 0) continue;
        unsigned char txid_display[32];
        memcpy(txid_display, n->txid, 32);
        reverse_bytes(txid_display, 32);
        if (persist_save_ps_initial_signed_state(
                p, /* factory_id = */ 0, (uint32_t)i,
                f->counter.current_epoch,
                txid_display,
                n->signed_tx.data, n->signed_tx.len)) {
            saved++;
        }
    }
    return saved;
}

/* R5 (mainnet pre-flight): revalidate each factory channel's funding UTXO
   against the active chain.  Sets ch->funding_pending_reorg = 1 when the
   funding TX is no longer findable (reorged out); clears the flag back to
   0 when a confirmed observation returns.  Mirrors jit_channels_revalidate
   _funding() (src/jit_channel.c:752) for the factory-channel case.

   Returns the number of channels whose flag state changed (toggled either
   direction).  Caller may persist or notify clients on a non-zero return.

   Intended call sites (separate PRs will wire these up):
     1. Daemon startup recovery (one-shot scan, like jit_channels_*)
     2. R1's reorg handler in lsp_run_state_advance (defense after watchtower_on_reorg)
     3. Periodic heartbeat (cheap defense)
*/
int lsp_channels_revalidate_funding(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !mgr->watchtower || !mgr->watchtower->rt) return 0;
    extern void hex_encode(const unsigned char *, size_t, char *);
    extern void reverse_bytes(unsigned char *, size_t);
    int changed = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        channel_t *ch = &mgr->entries[c].channel;
        /* Compute display-order hex txid for the chain query. */
        unsigned char disp[32];
        memcpy(disp, ch->funding_txid, 32);
        reverse_bytes(disp, 32);
        char txid_hex[65];
        hex_encode(disp, 32, txid_hex);
        txid_hex[64] = '\0';
        int conf = regtest_get_confirmations(mgr->watchtower->rt, txid_hex);
        int new_state = -1;
        /* R5 #128: proactive mempool-expiry freeze.  If the TX is in
           mempool but unconfirmed (conf == 0) AND it has been there
           longer than the network-specific threshold, treat it as
           effectively reorged-out.  Pairs with the reactive `conf < 0`
           freeze below — together they catch "evicted already" and
           "about to be evicted". */
        int mempool_age_freeze = 0;
        if (conf == 0) {
            int age = regtest_get_mempool_entry_seconds_ago(
                mgr->watchtower->rt, txid_hex);
            int threshold = regtest_network_mempool_freeze_seconds(
                mgr->watchtower->rt);
            if (age >= threshold)
                mempool_age_freeze = 1;
        }
        if ((conf < 0 || mempool_age_freeze) && !ch->funding_pending_reorg) {
            fprintf(stderr,
                "LSP revalidate: channel %zu funding %.16s... %s — "
                "FREEZING (funding_pending_reorg=1)\n",
                c, txid_hex,
                mempool_age_freeze ? "stale in mempool past timeout"
                                   : "not on chain");
            ch->funding_pending_reorg = 1;
            changed++;
            new_state = 1;
            /* v31: persist the toggle so a restart mid-reorg reloads frozen. */
            if (mgr->persist)
                persist_update_channel_funding_reorg(
                    (persist_t *)mgr->persist, (uint32_t)c, 1);
        } else if (conf >= 1 && ch->funding_pending_reorg) {
            fprintf(stderr,
                "LSP revalidate: channel %zu funding %.16s... back on chain "
                "(%d confs) — UNFREEZING (funding_pending_reorg=0)\n",
                c, txid_hex, conf);
            ch->funding_pending_reorg = 0;
            changed++;
            new_state = 0;
            if (mgr->persist)
                persist_update_channel_funding_reorg(
                    (persist_t *)mgr->persist, (uint32_t)c, 0);
        }
        /* R5 wire: notify the client so it mirrors the freeze state.
           Best-effort: client may be offline; the LSP-side flag is still
           authoritative.  A reconnect can resync via the next revalidate
           cycle if this message was missed. */
        if (new_state >= 0 && lsp && lsp->client_fds &&
            c < lsp->n_clients && lsp->client_fds[c] >= 0) {
            cJSON *j = cJSON_CreateObject();
            if (j) {
                cJSON_AddNumberToObject(j, "frozen", new_state);
                cJSON_AddStringToObject(j, "funding_txid", txid_hex);
                wire_send(lsp->client_fds[c], MSG_FUNDING_REORG, j);
                cJSON_Delete(j);
            }
        }
    }
    return changed;
}

/* Cooperatively redistribute output amounts on an arity-2 leaf (3-of-3).
   LSP proposes new amounts; both clients agree via 2-round MuSig2 ceremony. */
int lsp_realloc_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                      int leaf_side, const uint64_t *amounts, size_t n_amounts) {
    factory_t *f = &lsp->factory;

    /* Generalized to N-of-N MuSig.  Works for any leaf arity where the
       leaf node has at least one client signer + the LSP (so n_signers
       >= 2).  Pre-PR-#123 this was gated to FACTORY_ARITY_2 (3-of-3);
       lifting that gate was Gap C-followup from the canonical-design
       audit.  PS leaves (n_signers=2, n_outputs=2 = 1 channel + L-stock
       OR 1 channel without L-stock post-advance) and arity-1 leaves
       (n_signers=2, n_outputs=2 = 1 channel + L-stock) are now
       supported in addition to arity-2 (n_signers=3, n_outputs=3). */
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    size_t node_idx = f->leaf_node_indices[leaf_side];
    factory_node_t *node = &f->nodes[node_idx];

    /* C3 (Tier 1): journal the ceremony.  Error returns leave the row in
       flight for the startup sweep to mark aborted_crash. */
    int64_t c3_round_id = -1;
    if (mgr->persist) {
        persist_save_signing_round_start((persist_t *)mgr->persist,
                                           /* factory_id */ 0,
                                           (uint32_t)node_idx,
                                           "leaf_realloc",
                                           f->counter.current_epoch,
                                           (uint32_t)node->n_signers,
                                           &c3_round_id);
    }
    (void)c3_round_id;  /* finalized at success return below */

    if (node->n_signers < 2) {
        fprintf(stderr, "LSP realloc: leaf node %zu has %zu signers, need >= 2\n",
                node_idx, node->n_signers);
        return 0;
    }

    /* Get all client participant indices on this leaf (may be 1..N-1). */
    uint32_t clients[FACTORY_MAX_SIGNERS];
    size_t n_clients = factory_get_subtree_clients(f, (int)node_idx, clients,
                                                     FACTORY_MAX_SIGNERS);
    if (n_clients != node->n_signers - 1) {
        fprintf(stderr, "LSP realloc: leaf %zu has %zu signers but %zu clients found\n",
                node_idx, node->n_signers, n_clients);
        return 0;
    }

    /* Snapshot OLD leaf state BEFORE the realloc — needed to deterministically
       prep the wire-ceremony poison TX (closes Wire-Ceremony Gap A for Tier B
       rotation). */
    unsigned char realloc_old_leaf_txid[32];
    memcpy(realloc_old_leaf_txid, node->txid, 32);
    int realloc_old_n_outputs = node->n_outputs;
    uint64_t realloc_old_l_amount = (realloc_old_n_outputs >= 2)
        ? node->outputs[realloc_old_n_outputs - 1].amount_sats : 0;
    int realloc_had_signed = (node->is_signed && node->signed_tx.len > 0);
    /* SF-WT-TRUSTLESS Phase 1b.5b (#248): snapshot OLD chain output for
     * wt_db register at the bottom of this function.  Same pattern as
     * leaf advance (Phase 1b.4) and Tier B (Phase 1b.5a). */
    uint64_t realloc_old_chain_amount = (realloc_old_n_outputs >= 1)
        ? node->outputs[0].amount_sats : 0;
    unsigned char realloc_old_chain_spk[34] = {0};
    size_t realloc_old_chain_spk_len = (realloc_old_n_outputs >= 1)
        ? node->outputs[0].script_pubkey_len : 0;
    if (realloc_old_chain_spk_len > sizeof(realloc_old_chain_spk))
        realloc_old_chain_spk_len = sizeof(realloc_old_chain_spk);
    if (realloc_old_n_outputs >= 1)
        memcpy(realloc_old_chain_spk,
               node->outputs[0].script_pubkey,
               realloc_old_chain_spk_len);
    uint32_t realloc_old_csv_delay = (uint32_t)(node->nsequence & 0xFFFFu);

    const uint64_t REALLOC_POISON_FEE_SATS = 1000;
    int realloc_poison_prepared = 0;
    if (mgr->watchtower && realloc_had_signed && realloc_old_n_outputs >= 2 &&
        realloc_old_l_amount > REALLOC_POISON_FEE_SATS +
                               (uint64_t)(node->n_signers - 1) * 330u) {
        if (factory_session_prepare_poison_tx_leaf(
                f, node_idx,
                realloc_old_leaf_txid, (uint32_t)(realloc_old_n_outputs - 1),
                realloc_old_l_amount, REALLOC_POISON_FEE_SATS,
                /* #53-B3b: this path prepares BEFORE the advance, so the node's
                   current hash IS H_old — NULL is already correct here. */
                NULL)) {
            realloc_poison_prepared = 1;
        }
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

    /* Step 3: Init BOTH signing sessions (state + poison if prepared). */
    if (!factory_session_init_node(f, node_idx)) {
        fprintf(stderr, "LSP realloc: state session init failed for node %zu\n", node_idx);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !factory_session_init_node_poison(f, node_idx)) {
        fprintf(stderr, "LSP realloc: poison session init failed — degrading\n");
        factory_session_reset_poison(f, node_idx);
        realloc_poison_prepared = 0;
    }

    /* Step 4: Generate LSP's nonces (state + poison — MUST be distinct) */
    int lsp_slot = factory_find_signer_slot(f, node_idx, 0);
    if (lsp_slot < 0) {
        fprintf(stderr, "LSP realloc: LSP not signer on node %zu\n", node_idx);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }

    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) {
        factory_session_reset_poison(f, node_idx);
        return 0;
    }

    secp256k1_musig_secnonce lsp_secnonce, lsp_poison_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce, lsp_poison_pubnonce;
    if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                               lsp_seckey, &lsp->lsp_pubkey,
                               &node->keyagg.cache)) {
        memset(lsp_seckey, 0, 32);
        factory_session_reset_poison(f, node_idx);
        fprintf(stderr, "LSP realloc: state nonce gen failed\n");
        return 0;
    }
    if (realloc_poison_prepared &&
        !musig_generate_nonce(lsp->ctx, &lsp_poison_secnonce, &lsp_poison_pubnonce,
                                lsp_seckey, &lsp->lsp_pubkey,
                                &node->keyagg.cache)) {
        fprintf(stderr, "LSP realloc: poison nonce gen failed — degrading\n");
        factory_session_reset_poison(f, node_idx);
        realloc_poison_prepared = 0;
    }

    if (!factory_session_set_nonce(f, node_idx, (size_t)lsp_slot, &lsp_pubnonce)) {
        memset(lsp_seckey, 0, 32);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !factory_session_set_nonce_poison(f, node_idx, (size_t)lsp_slot,
                                            &lsp_poison_pubnonce)) {
        fprintf(stderr, "LSP realloc: set LSP poison nonce failed — degrading\n");
        factory_session_reset_poison(f, node_idx);
        realloc_poison_prepared = 0;
    }

    /* Step 5: Send REALLOC_PROPOSE (state + optional poison nonce). */
    unsigned char lsp_pubnonce_ser[66], lsp_poison_pn_ser[66];
    musig_pubnonce_serialize(lsp->ctx, lsp_pubnonce_ser, &lsp_pubnonce);
    if (realloc_poison_prepared)
        musig_pubnonce_serialize(lsp->ctx, lsp_poison_pn_ser, &lsp_poison_pubnonce);
    cJSON *propose = wire_build_leaf_realloc_propose(
        leaf_side, amounts, n_amounts, lsp_pubnonce_ser,
        realloc_poison_prepared ? lsp_poison_pn_ser : NULL);
    for (size_t ci = 0; ci < n_clients; ci++) {
        /* client_fds indexed by client_idx - 1 (participant_idx 1-based) */
        size_t fd_idx = (size_t)(clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_LEAF_REALLOC_PROPOSE, propose)) {
            cJSON_Delete(propose);
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
    }
    cJSON_Delete(propose);

    /* Step 6: Recv REALLOC_NONCE from each client, set their nonces (state + poison). */
    unsigned char all_pubnonces[FACTORY_MAX_SIGNERS][66];
    unsigned char all_poison_pubnonces[FACTORY_MAX_SIGNERS][66];
    memcpy(all_pubnonces[lsp_slot], lsp_pubnonce_ser, 66);
    if (realloc_poison_prepared)
        memcpy(all_poison_pubnonces[lsp_slot], lsp_poison_pn_ser, 66);

    for (size_t ci = 0; ci < n_clients; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        wire_msg_t nonce_msg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx], &nonce_msg,
                                          WIRE_CEREMONY_RECV_TIMEOUT_SEC) ||
            nonce_msg.msg_type != MSG_LEAF_REALLOC_NONCE) {
            fprintf(stderr, "LSP realloc: expected REALLOC_NONCE from client %u, got 0x%02x (recv timeout/peer EOF or wrong type)\n",
                    clients[ci], nonce_msg.msg_type);
            if (nonce_msg.json) cJSON_Delete(nonce_msg.json);
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }

        unsigned char client_pn_ser[66], client_poison_pn_ser[66];
        int n_parse_rc = wire_parse_leaf_realloc_nonce(
            nonce_msg.json, client_pn_ser,
            realloc_poison_prepared ? client_poison_pn_ser : NULL);
        cJSON_Delete(nonce_msg.json);
        if (n_parse_rc == 0) {
            fprintf(stderr, "LSP realloc: failed to parse REALLOC_NONCE\n");
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
        if (realloc_poison_prepared && n_parse_rc < 2) {
            fprintf(stderr, "LSP realloc: client %u omitted poison nonce — degrading\n",
                    clients[ci]);
            factory_session_reset_poison(f, node_idx);
            realloc_poison_prepared = 0;
        }

        int client_slot = factory_find_signer_slot(f, node_idx, clients[ci]);
        if (client_slot < 0) {
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }

        secp256k1_musig_pubnonce client_pubnonce;
        if (!musig_pubnonce_parse(lsp->ctx, &client_pubnonce, client_pn_ser)) {
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
        if (!factory_session_set_nonce(f, node_idx, (size_t)client_slot, &client_pubnonce)) {
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
        memcpy(all_pubnonces[client_slot], client_pn_ser, 66);

        if (realloc_poison_prepared) {
            secp256k1_musig_pubnonce client_poison_pn;
            if (!musig_pubnonce_parse(lsp->ctx, &client_poison_pn, client_poison_pn_ser) ||
                !factory_session_set_nonce_poison(f, node_idx, (size_t)client_slot,
                                                    &client_poison_pn)) {
                fprintf(stderr, "LSP realloc: parse/set client %u poison nonce failed — degrading\n",
                        clients[ci]);
                factory_session_reset_poison(f, node_idx);
                realloc_poison_prepared = 0;
            } else {
                memcpy(all_poison_pubnonces[client_slot], client_poison_pn_ser, 66);
            }
        }
    }

    /* Step 7: Send REALLOC_ALL_NONCES (state + optional poison). */
    cJSON *all_nonces = wire_build_leaf_realloc_all_nonces(
        (const unsigned char (*)[66])all_pubnonces,
        realloc_poison_prepared ? (const unsigned char (*)[66])all_poison_pubnonces : NULL,
        node->n_signers);
    for (size_t ci = 0; ci < n_clients; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_LEAF_REALLOC_ALL_NONCES, all_nonces)) {
            cJSON_Delete(all_nonces);
            memset(lsp_seckey, 0, 32);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
    }
    cJSON_Delete(all_nonces);

    /* Step 8: Finalize both sessions. */
    if (!factory_session_finalize_node(f, node_idx)) {
        fprintf(stderr, "LSP realloc: state session finalize failed for node %zu\n", node_idx);
        memset(lsp_seckey, 0, 32);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !factory_session_finalize_node_poison(f, node_idx)) {
        fprintf(stderr, "LSP realloc: poison finalize failed — degrading\n");
        factory_session_reset_poison(f, node_idx);
        realloc_poison_prepared = 0;
    }

    /* Step 9: Create LSP's partial sigs (state + poison if prepared). */
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    secp256k1_musig_partial_sig lsp_psig, lsp_poison_psig;
    if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce, &lsp_kp,
                                    &node->signing_session)) {
        fprintf(stderr, "LSP realloc: state partial sig failed\n");
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (!factory_session_set_partial_sig(f, node_idx, (size_t)lsp_slot, &lsp_psig)) {
        factory_session_reset_poison(f, node_idx);
        return 0;
    }
    if (realloc_poison_prepared) {
        if (!musig_create_partial_sig(lsp->ctx, &lsp_poison_psig, &lsp_poison_secnonce, &lsp_kp,
                                        &node->poison_signing_session) ||
            !factory_session_set_partial_sig_poison(f, node_idx, (size_t)lsp_slot,
                                                     &lsp_poison_psig)) {
            fprintf(stderr, "LSP realloc: poison psig create/set failed — degrading\n");
            factory_session_reset_poison(f, node_idx);
            realloc_poison_prepared = 0;
        }
    }

    /* Step 10: Recv REALLOC_PSIG from each client (state + poison). */
    for (size_t ci = 0; ci < n_clients; ci++) {
        size_t fd_idx = (size_t)(clients[ci] - 1);
        wire_msg_t psig_msg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx], &psig_msg,
                                          WIRE_CEREMONY_RECV_TIMEOUT_SEC) ||
            psig_msg.msg_type != MSG_LEAF_REALLOC_PSIG) {
            fprintf(stderr, "LSP realloc: expected REALLOC_PSIG from client %u, got 0x%02x (recv timeout/peer EOF or wrong type)\n",
                    clients[ci], psig_msg.msg_type);
            if (psig_msg.json) cJSON_Delete(psig_msg.json);
            factory_session_reset_poison(f, node_idx);
            return 0;
        }

        unsigned char client_psig_ser[32], client_poison_psig_ser[32];
        int p_parse_rc = wire_parse_leaf_realloc_psig(
            psig_msg.json, client_psig_ser,
            realloc_poison_prepared ? client_poison_psig_ser : NULL);
        cJSON_Delete(psig_msg.json);
        if (p_parse_rc == 0) {
            fprintf(stderr, "LSP realloc: failed to parse REALLOC_PSIG\n");
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
        if (realloc_poison_prepared && p_parse_rc < 2) {
            fprintf(stderr, "LSP realloc: client %u omitted poison psig — degrading\n",
                    clients[ci]);
            factory_session_reset_poison(f, node_idx);
            realloc_poison_prepared = 0;
        }

        int client_slot = factory_find_signer_slot(f, node_idx, clients[ci]);
        if (client_slot < 0) {
            factory_session_reset_poison(f, node_idx);
            return 0;
        }

        secp256k1_musig_partial_sig client_psig;
        if (!musig_partial_sig_parse(lsp->ctx, &client_psig, client_psig_ser)) {
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
        if (!factory_session_set_partial_sig(f, node_idx, (size_t)client_slot, &client_psig)) {
            factory_session_reset_poison(f, node_idx);
            return 0;
        }
        if (realloc_poison_prepared) {
            secp256k1_musig_partial_sig client_poison_psig;
            if (!musig_partial_sig_parse(lsp->ctx, &client_poison_psig, client_poison_psig_ser) ||
                !factory_session_set_partial_sig_poison(f, node_idx, (size_t)client_slot,
                                                         &client_poison_psig)) {
                fprintf(stderr, "LSP realloc: parse/set client %u poison psig failed — degrading\n",
                        clients[ci]);
                factory_session_reset_poison(f, node_idx);
                realloc_poison_prepared = 0;
            }
        }
    }

    /* Step 11: Aggregate + finalize both signed TXs. */
    if (realloc_poison_prepared &&
        !factory_session_complete_node_poison(f, node_idx)) {
        fprintf(stderr, "LSP realloc: poison complete failed — degrading\n");
        factory_session_reset_poison(f, node_idx);
        realloc_poison_prepared = 0;
    }
    if (!factory_session_complete_node(f, node_idx)) {
        fprintf(stderr, "LSP realloc: state session complete failed for node %zu\n", node_idx);
        factory_session_reset_poison(f, node_idx);
        return 0;
    }

    /* Step 11b: register the OLD (pre-realloc) leaf state with the
       watchtower as a stale-broadcast target.  Without this, a malicious
       LSP can force-close + broadcast the pre-realloc leaf TX and the WT
       has no entry to match the on-chain spend against.  Mirror the
       leaf-advance pattern at line ~2785 — registers (OLD txid → NEW
       signed_tx as response + poison TX).  Surfaced by SF-WT-REALLOC-DETECT-GAP
       (#258), reproduced end-to-end by tools/test_regtest_cheat_realloc.sh. */
    if (mgr->watchtower && realloc_had_signed && node->is_signed &&
        node->signed_tx.len > 0) {
        uint32_t leaf_ch_ids[FACTORY_MAX_SIGNERS];
        size_t n_leaf_ch = 0;
        for (size_t cc = 0; cc < mgr->n_channels; cc++) {
            size_t c_node;
            uint32_t c_vout;
            if (!factory_client_to_leaf(f, cc, &c_node, &c_vout)) continue;
            if (c_node == node_idx)
                leaf_ch_ids[n_leaf_ch++] = (uint32_t)cc;
        }
        const unsigned char *poison_data = NULL;
        size_t poison_len = 0;
        if (realloc_poison_prepared &&
            node->poison_is_signed && node->poison_signed_tx.len > 0) {
            poison_data = node->poison_signed_tx.data;
            poison_len = node->poison_signed_tx.len;
        }
        watchtower_watch_factory_node_with_channels(mgr->watchtower,
            (uint32_t)node_idx, realloc_old_leaf_txid,
            node->signed_tx.data, node->signed_tx.len,
            poison_data, poison_len,
            leaf_ch_ids, n_leaf_ch);
        printf("LSP realloc: watchtower registered OLD leaf %zu txid as stale "
               "(response_tx=%zub, poison=%s, %zu channels)\n",
               node_idx, (size_t)node->signed_tx.len,
               poison_data ? "yes" : "no", n_leaf_ch);

        /* SF-WT-TRUSTLESS Phase 1b.5b: parallel wt_db register for
         * leaf realloc.  Uses snapshot taken before realloc mutated
         * outputs[]. */
        if (lsp && lsp->wt_db && realloc_had_signed && realloc_old_chain_spk_len > 0) {
            int64_t watch_id = lsp_wt_register_factory_node_watch(
                lsp->wt_db,
                (uint32_t)node_idx,
                realloc_old_leaf_txid,
                /* parent_vout      */ 0,
                /* parent_value_sat */ realloc_old_chain_amount,
                realloc_old_chain_spk, realloc_old_chain_spk_len,
                /* csv_delay        */ realloc_old_csv_delay,
                node->signed_tx.data, node->signed_tx.len,
                node->txid,
                /* fee_bump_budget  */ 0,
                /* fee_bump_dline   */ 0);
            if (watch_id > 0) {
                printf("LSP-WT-TRUSTLESS: registered realloc watch_id=%lld "
                       "for node %zu (parent=%llu sats, csv=%u)\n",
                       (long long)watch_id, node_idx,
                       (unsigned long long)realloc_old_chain_amount,
                       (unsigned)realloc_old_csv_delay);
            } else {
                fprintf(stderr,
                        "LSP-WT-TRUSTLESS: WARN — wt_db register failed for "
                        "realloc node %zu\n", node_idx);
            }
        }
    }

    /* Step 12: Update channel amounts in lsp_channel_entry_t.

       Generic mapping: each client owns the leaf output at the vout
       returned by client_to_leaf().  L-stock (if present) is at the
       last vout.  We update each client's funding_amount from the new
       outputs[client_vout].  This is correct for any leaf arity:
         - arity-1: 1 client at vout 0, L-stock at vout 1
         - arity-2: 2 clients at vouts 0/1, L-stock at vout 2
         - arity-N: N clients at vouts 0..N-1, L-stock at vout N
         - PS leaves: 1 client at vout 0, L-stock at vout 1 (pre-advance)
                       or 1 client at vout 0 only (post-advance). */
    for (size_t ci = 0; ci < n_clients; ci++) {
        size_t client_idx_zero = (size_t)(clients[ci] - 1);
        if (client_idx_zero >= mgr->n_channels) continue;

        size_t client_node;
        uint32_t client_vout;
        if (!factory_client_to_leaf(f, client_idx_zero, &client_node, &client_vout)) continue;
        if (client_vout >= n_amounts) continue;
        uint64_t client_amt = amounts[client_vout];

        lsp_channel_entry_t *entry = &mgr->entries[client_idx_zero];
        entry->channel.funding_amount = client_amt;  /* sats, matching channel_init */
        /* Recalculate using lsp_balance_pct (matching channel init logic) */
        uint16_t pct = mgr->lsp_balance_pct;
        if (pct == 0) pct = 50;
        if (pct > 100) pct = 100;
        fee_estimator_static_t _fe_realloc;
        fee_estimator_t *_fe_ra = mgr->fee ? (fee_estimator_t *)mgr->fee : NULL;
        if (!_fe_ra) { fee_estimator_static_init(&_fe_realloc, 1000); _fe_ra = &_fe_realloc.base; }
        uint64_t commit_fee_ra = fee_for_commitment_tx(_fe_ra, 0);
        uint64_t usable_ra = client_amt > commit_fee_ra ? client_amt - commit_fee_ra : 0;
        entry->channel.local_amount = (usable_ra * pct) / 100;
        entry->channel.remote_amount = usable_ra - entry->channel.local_amount;
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

    /* SF-C #143: refresh channel funding state for every channel whose
       funding output lives on this reallocated leaf.  After the realloc,
       node->txid is the new state TX and node->outputs[i].amount_sats
       reflects the new allocation.  Without this, commitment signatures
       built from entry->channel.funding_* would still point at the
       pre-realloc state, breaking on-chain spend on the rare paths that
       reach broadcast (cheat-leaf, lstock-buy followups). */
    {
        int n_refreshed = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            size_t c_node;
            uint32_t c_vout;
            if (!factory_client_to_leaf(f, c, &c_node, &c_vout)) continue;
            if (c_node != node_idx) continue;
            if (c_vout >= node->n_outputs) continue;
            channel_t *ch = &mgr->entries[c].channel;
            channel_update_funding(ch,
                                    node->txid,
                                    c_vout,
                                    node->outputs[c_vout].amount_sats,
                                    node->outputs[c_vout].script_pubkey,
                                    node->outputs[c_vout].script_pubkey_len);
            n_refreshed++;
        }
        if (n_refreshed > 0)
            printf("LSP: refreshed funding state on %d channel(s) after "
                   "leaf %d realloc\n", n_refreshed, leaf_side);
    }

    /* C3 (Tier 1): journal success. */
    if (mgr->persist && c3_round_id > 0) {
        persist_save_signing_round_done((persist_t *)mgr->persist, c3_round_id,
                                          (uint32_t)node->n_signers,
                                          (uint32_t)node->n_signers,
                                          "success", NULL, NULL);
    }
    return 1;
}

/* Sub-factory chain extension ceremony driver (Gap E followup Phase 2b,
   t/1242 k² PS).  Drives the multi-party MuSig signing of a new
   sub-factory state when the LSP "sells liquidity from sales-stock":
   one client's channel grows by delta_sats, sales-stock shrinks by
   delta_sats + fee, all other channels unchanged.  N-of-N MuSig over
   the sub-factory's signers (LSP + k clients in this sub-factory only).

   Mirrors lsp_realloc_leaf's round structure but scoped to one
   sub-factory's signers, and uses the new MSG_SUBFACTORY_* messages.

   Returns 1 on success (chain extended, all participants confirmed
   via DONE), 0 on any failure (validation, ceremony timeout, crypto). */
/* Phase 1e.1.b: stateless single-input sub-factory chain advance variant.
   Dispatched from the public function when SS_MUSIG_STATELESS=1 AND the
   target node is single-input (factory_node_uses_multi_input returns 0).
   Multi-input + poison + WT registration deferred to Phase 1e.1.c. */
/* Phase 1e.1.e: MULTI-INPUT stateless sub-factory chain advance.
   Mirrors lsp_subfactory_chain_advance_stateless (single-input) but loops
   per input.  Called from the single-input function once the unsigned tx,
   session, sub_clients[] and slots have been resolved -- but we re-derive
   everything needed here from (f, sub_node_i, sub) so this stays a clean
   self-contained block.

   STATELESS INVARIANT: LSP per-input secnonces are generated in Step 5 AFTER
   the Step-4 recv of every client's pubnonces, and each lsp_secnonces[i] is
   zeroed by musig_create_partial_sig (Step 5) before the Step-7 recv. */
static int lsp_subfactory_chain_advance_stateless_multi(
        lsp_channel_mgr_t *mgr, lsp_t *lsp, factory_t *f,
        size_t sub_node_i, factory_node_t *sub,
        const uint32_t *sub_clients, size_t n_clients_in_sub,
        int leaf_side, int sub_idx_in_leaf, int channel_idx_in_sub,
        uint64_t delta_sats) {
    /* SF-MULTI-DISPATCH: n_inputs is the number of outputs on chain[N] that
       chain[N+1] will spend.  Use sub->n_outputs (the PRE-advance count of
       outputs on the current chain head) -- this is what advance_unsigned
       will assign to sub->ps_n_prev_outputs.  Reading sub->ps_n_prev_outputs
       here would be stale on the first advance (it's only populated by a
       prior advance_unsigned call, of which there has been none). */
    size_t n_inputs = sub->n_outputs;
    if (n_inputs < 1) {
        fprintf(stderr, "LSP-stateless subfactory MULTI: n_inputs=%zu invalid\n",
                n_inputs);
        return 0;
    }

    /* Step 1.5 (poison prep): snapshot the soon-to-be-stale chain[N-1] state
       BEFORE advance_unsigned mutates sub->txid / sub->outputs[], then build
       the single-input L-stock poison TX (the poison side-channel is always
       single-input even when the state advance is multi-input, mirroring the
       legacy multi path).  Poison only when the watchtower is configured. */
    const uint64_t POISON_FEE_SATS = 1000;
    int poison_prepared = 0;
    unsigned char wt_old_chain_txid[32];
    memcpy(wt_old_chain_txid, sub->txid, 32);
    size_t wt_old_n_chans = (sub->n_outputs > 0) ? sub->n_outputs - 1 : 0;
    if (wt_old_n_chans > 16) wt_old_n_chans = 16;
    uint64_t wt_old_chan_amounts[16] = {0};
    for (size_t ci = 0; ci < wt_old_n_chans; ci++)
        wt_old_chan_amounts[ci] = sub->outputs[ci].amount_sats;
    uint64_t wt_old_sstock_amount = (sub->n_outputs > 0)
        ? sub->outputs[sub->n_outputs - 1].amount_sats : 0;
    /* SF-WT-TRUSTLESS Phase 2c: also snapshot parent vout/value/spk/csv for
       trustless wt_db register (mirrors Tier B pattern at line 2299+).
       wt_db carries parent_vout=0 by convention; legacy WT detection is
       txid-based so vout is informational here.  outputs[0] is the first
       channel output of the chain TX. */
    uint64_t wt_old_chain_amount = (sub->n_outputs > 0)
        ? sub->outputs[0].amount_sats : 0;
    size_t wt_old_chain_spk_len = (sub->n_outputs > 0)
        ? sub->outputs[0].script_pubkey_len : 0;
    if (wt_old_chain_spk_len > 34) wt_old_chain_spk_len = 34;
    unsigned char wt_old_chain_spk[34] = {0};
    if (sub->n_outputs > 0 && wt_old_chain_spk_len > 0)
        memcpy(wt_old_chain_spk, sub->outputs[0].script_pubkey,
               wt_old_chain_spk_len);
    uint32_t wt_old_csv_delay = (uint32_t)(sub->nsequence & 0xFFFFu);
    /* #53 Phase 3: economic poison requirement, DECOUPLED from the watchtower/
       operational prep gate — the OLD sub state has a protectable, non-dust
       sales-stock.  The fail-closed guard below (before DONE) fires whenever a
       required poison was not co-signed, but never when no poison was ever needed. */
    int poison_required = (wt_old_sstock_amount > POISON_FEE_SATS +
                           (uint64_t)wt_old_n_chans * 330u);
    if (mgr->watchtower && poison_required) {
        if (factory_session_prepare_poison_tx_subfactory(
                f, sub_node_i, wt_old_chain_txid, (uint32_t)wt_old_n_chans,
                wt_old_sstock_amount, POISON_FEE_SATS,
                NULL /* prep-before-advance: sub->l_stock_hash is still H_old here,
                        so NULL override naturally targets the superseded state */)) {
            poison_prepared = 1;
        } else {
            fprintf(stderr, "LSP-stateless subfactory MULTI: poison TX prep "
                    "failed -- NULL poison_tx\n");
        }
    }

    /* Step 1: rebuild unsigned_tx (deterministic; clients do the same). */
    if (!factory_subfactory_chain_advance_unsigned(f, leaf_side,
                                                    sub_idx_in_leaf,
                                                    channel_idx_in_sub,
                                                    delta_sats)) {
        fprintf(stderr, "LSP-stateless subfactory MULTI: advance_unsigned failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }

    /* Step 2: init one state session per input + (when prepared) poison. */
    for (size_t i = 0; i < n_inputs; i++) {
        if (!factory_session_init_node_input(f, sub_node_i, i)) {
            fprintf(stderr, "LSP-stateless subfactory MULTI: init input %zu failed\n", i);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
    }
    if (poison_prepared &&
        !factory_session_init_node_poison(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless subfactory MULTI: poison init failed -- "
                "degrading\n");
        factory_session_reset_poison(f, sub_node_i);
        poison_prepared = 0;
    }

    int lsp_slot = factory_find_signer_slot(f, sub_node_i, 0);
    if (lsp_slot < 0) return 0;

    /* Step 3: PROPOSE_INTENT (n_inputs, NO LSP nonce). */
    /* SF-CRASH-INJECT-WIRE #245 Half A: journal sub-factory multi-input advance. */
    unsigned char cer_id[8] = {0};
    int cer_persisted = 0;
    if (mgr->persist) {
        uint64_t epoch_salt = (((uint64_t)f->counter.current_epoch << 24)
                              | ((uint64_t)sub_node_i << 8)
                              | ((uint64_t)sub->ps_chain_len & 0xff))
                              | 0x80000000ull;  /* multi-input bit */
        lsp_ceremony_derive_id(lsp->factory.funding_txid,
                                PERSIST_CEREMONY_TYPE_STATE_UPDATE,
                                epoch_salt, cer_id);
        if (persist_save_ceremony((persist_t *)mgr->persist, cer_id,
                                   lsp->factory.funding_txid,
                                   PERSIST_CEREMONY_TYPE_STATE_UPDATE,
                                   NULL, 0, f->cltv_timeout))
            cer_persisted = 1;
    }
    cJSON *propose = wire_build_subfactory_propose_intent(
        (uint32_t)sub_node_i, (uint32_t)n_inputs,
        leaf_side, sub_idx_in_leaf, channel_idx_in_sub, delta_sats);
    /* #53 sub-factory hashlock: ship the sub's NEW-state H (set by Phase 0 of the
       advance above) so the seedless client mirrors it via factory_set_node_l_stock_hash
       and builds the IDENTICAL sales-stock SPK before its own sub-advance. Absent when
       hashlock poison off -> client no-ops. Mirrors the leaf path (lsp_channels.c ~1497). */
    if (f->use_hashlock_poison && sub->has_l_stock_hash)
        wire_json_add_hex(propose, "l_stock_hash", sub->l_stock_hash, 32);
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_SUBFACTORY_PROPOSE_INTENT, propose)) {
            cJSON_Delete(propose);
            fprintf(stderr, "LSP-stateless MULTI: send PROPOSE_INTENT failed for client %u\n",
                    sub_clients[ci]);
            return 0;
        }
    }
    cJSON_Delete(propose);
    if (cer_persisted) {
        for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
            size_t pk_idx = (size_t)(sub_clients[ci] - 1);
            unsigned char pk33[33];
            lsp_ceremony_get_client_pubkey33(lsp, pk_idx, pk33);
            (void)persist_save_participant_phase((persist_t *)mgr->persist, cer_id,
                pk33, PERSIST_CEREMONY_PHASE_SENT, NULL, NULL, 0, 0);
        }
    }
    printf("LSP: SUBFACTORY_PROPOSE_INTENT sent to %zu clients (MULTI sub_node %zu n_inputs=%zu)\n",
           n_clients_in_sub, sub_node_i, n_inputs);
    fflush(stdout);

    lsp_crash_checkpoint("subfactory_multi_propose");

    /* all_pn_per_input[(signer_slot * n_inputs + input_idx) * 66] -- same
       layout as the legacy multi-input path so the matrix forwarded to
       clients in LSP_RESPONSE is indexed identically on both sides. */
    unsigned char *all_pn_per_input = calloc(sub->n_signers * n_inputs, 66);
    if (!all_pn_per_input) { factory_session_reset_poison(f, sub_node_i); return 0; }
    /* Poison side-channel is single-input: one poison nonce per signer. */
    unsigned char all_poison_pn[FACTORY_MAX_SIGNERS][66];
    memset(all_poison_pn, 0, sizeof(all_poison_pn));

    /* Step 4: collect each client's n_inputs pubnonces (+ 1 poison nonce). */
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        wire_msg_t nmsg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx],
                                            &nmsg, WIRE_CEREMONY_RECV_TIMEOUT_SEC) ||
            nmsg.msg_type != MSG_SUBFACTORY_CLIENT_PUBNONCES) {
            fprintf(stderr,
                    "LSP-stateless MULTI: expected CLIENT_PUBNONCES from client %u, got 0x%02x\n",
                    sub_clients[ci], nmsg.msg_type);
            if (nmsg.json) cJSON_Delete(nmsg.json);
            free(all_pn_per_input);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
        unsigned char *client_pn_buf = calloc(n_inputs, 66);
        if (!client_pn_buf) {
            cJSON_Delete(nmsg.json); free(all_pn_per_input);
            factory_session_reset_poison(f, sub_node_i); return 0;
        }
        unsigned char client_poison_pn[66];
        int parse_rc = wire_parse_subfactory_client_pubnonces(
            nmsg.json, client_pn_buf, (uint32_t)n_inputs,
            poison_prepared ? client_poison_pn : NULL);
        if (parse_rc == 0) {
            cJSON_Delete(nmsg.json);
            free(client_pn_buf); free(all_pn_per_input);
            factory_session_reset_poison(f, sub_node_i);
            fprintf(stderr, "LSP-stateless MULTI: parse CLIENT_PUBNONCES failed\n");
            return 0;
        }
        cJSON_Delete(nmsg.json);
        if (poison_prepared && parse_rc < 2) {
            fprintf(stderr, "LSP-stateless MULTI: client %u omitted poison nonce "
                    "-- degrading\n", sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        }
        int client_slot = factory_find_signer_slot(f, sub_node_i, sub_clients[ci]);
        if (client_slot < 0) {
            free(client_pn_buf); free(all_pn_per_input);
            factory_session_reset_poison(f, sub_node_i); return 0;
        }
        for (size_t i = 0; i < n_inputs; i++)
            memcpy(all_pn_per_input + ((size_t)client_slot * n_inputs + i) * 66,
                   client_pn_buf + i * 66, 66);
        if (poison_prepared)
            memcpy(all_poison_pn[client_slot], client_poison_pn, 66);
        free(client_pn_buf);
    }

    lsp_crash_checkpoint("subfactory_multi_nonced");

    /* Step 5 (THE CRITICAL ATOMIC BLOCK): per input -- gen LSP secnonce, set
       all signers' input-i nonces, finalize input-i, create LSP psig (zeros
       secnonce[i]), set LSP psig.  No wire_recv anywhere in this block. */
    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) {
        free(all_pn_per_input);
        return 0;
    }
    secp256k1_musig_secnonce *lsp_secnonces =
        calloc(n_inputs, sizeof(secp256k1_musig_secnonce));
    unsigned char (*lsp_pn_ser)[66] = calloc(n_inputs, sizeof(unsigned char[66]));
    unsigned char (*lsp_psig_ser)[32] = calloc(n_inputs, sizeof(unsigned char[32]));
    if (!lsp_secnonces || !lsp_pn_ser || !lsp_psig_ser) {
        memset(lsp_seckey, 0, 32);
        free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
        free(all_pn_per_input);
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }

    /* Build the LSP keypair once for the per-input + poison psig calls. */
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
        free(all_pn_per_input);
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }

    for (size_t i = 0; i < n_inputs; i++) {
        /* SF-MULTI-KEYAGG (#283): nonce against per-input keyagg cache
           (channel inputs: 2-of-2; sales-stock: N-of-N). */
        secp256k1_musig_pubnonce lsp_pubnonce_i;
        if (!musig_generate_nonce(lsp->ctx, &lsp_secnonces[i], &lsp_pubnonce_i,
                                   lsp_seckey, &lsp->lsp_pubkey,
                                   &sub->input_keyaggs[i].cache)) {
            fprintf(stderr, "LSP-stateless MULTI: nonce gen input %zu failed\n", i);
            memset(lsp_seckey, 0, 32);
            free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
            free(all_pn_per_input);
            return 0;
        }
        musig_pubnonce_serialize(lsp->ctx, lsp_pn_ser[i], &lsp_pubnonce_i);
        memcpy(all_pn_per_input + ((size_t)lsp_slot * n_inputs + i) * 66,
               lsp_pn_ser[i], 66);

        /* SF-MULTI-KEYAGG (#283): set nonce for every signer that ACTUALLY
           signs input i, mapping node-level slot s -> participant ->
           per-input slot.  Skip slots where the participant doesn't sign
           this input — wire matrix carries zero placeholders there. */
        for (size_t s = 0; s < sub->n_signers; s++) {
            uint32_t participant = sub->signer_indices[s];
            int per_input_slot = factory_session_get_input_signer_slot(
                f, sub_node_i, i, participant);
            if (per_input_slot < 0) continue;
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(lsp->ctx, &pn,
                    all_pn_per_input + (s * n_inputs + i) * 66) ||
                !factory_session_set_nonce_input(f, sub_node_i, i,
                                                  (size_t)per_input_slot, &pn)) {
                fprintf(stderr,
                        "LSP-stateless MULTI: set_nonce_input(participant=%u "
                        "input=%zu per_input_slot=%d) failed\n",
                        participant, i, per_input_slot);
                memset(lsp_seckey, 0, 32);
                free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
                free(all_pn_per_input);
                return 0;
            }
        }

        if (!factory_session_finalize_node_input(f, sub_node_i, i)) {
            fprintf(stderr, "LSP-stateless MULTI: finalize input %zu failed\n", i);
            memset(lsp_seckey, 0, 32);
            free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
            free(all_pn_per_input);
            return 0;
        }

        /* SF-MULTI-KEYAGG (#283): LSP's per-input slot for this input. */
        int lsp_slot_i = factory_session_get_input_signer_slot(
            f, sub_node_i, i, 0);
        if (lsp_slot_i < 0) {
            fprintf(stderr,
                    "LSP-stateless MULTI: LSP not in signer set of input %zu "
                    "(impossible)\n", i);
            memset(lsp_seckey, 0, 32);
            free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
            free(all_pn_per_input);
            return 0;
        }
        secp256k1_musig_partial_sig lsp_psig_i;
        if (!musig_create_partial_sig(lsp->ctx, &lsp_psig_i,
                &lsp_secnonces[i], &lsp_kp,
                &sub->input_signing_sessions[i])) {
            fprintf(stderr, "LSP-stateless MULTI: create_partial_sig input %zu failed\n", i);
            memset(lsp_seckey, 0, 32);
            free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
            free(all_pn_per_input);
            return 0;
        }
        /* lsp_secnonces[i] zeroed by musig_create_partial_sig.  INVARIANT:
           no LSP secnonce for input i is held across the recv that follows. */
        if (!factory_session_set_partial_sig_input(f, sub_node_i, i,
                                                    (size_t)lsp_slot_i, &lsp_psig_i)) {
            fprintf(stderr, "LSP-stateless MULTI: set_partial_sig_input %zu "
                    "(lsp_slot=%d) failed\n", i, lsp_slot_i);
            memset(lsp_seckey, 0, 32);
            free(lsp_secnonces); free(lsp_pn_ser); free(lsp_psig_ser);
            free(all_pn_per_input);
            return 0;
        }
        musig_partial_sig_serialize(lsp->ctx, lsp_psig_ser[i], &lsp_psig_i);
    }

    /* Poison (same atomic region, lsp_seckey still live, no wire_recv): gen the
       LSP poison secnonce, set every signer's poison nonce, finalize, create
       the LSP poison partial sig (which zeros lsp_poison_secnonce).  The poison
       secnonce never survives to the Step-7 recv. */
    unsigned char lsp_poison_pn_ser[66] = {0};
    unsigned char lsp_poison_psig_ser[32] = {0};
    if (poison_prepared) {
        secp256k1_musig_secnonce lsp_poison_secnonce;
        secp256k1_musig_pubnonce lsp_poison_pubnonce;
        if (!musig_generate_nonce(lsp->ctx, &lsp_poison_secnonce,
                                   &lsp_poison_pubnonce, lsp_seckey,
                                   &lsp->lsp_pubkey, &sub->keyagg.cache)) {
            fprintf(stderr, "LSP-stateless MULTI: poison nonce gen failed -- "
                    "degrading\n");
            memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        } else {
            musig_pubnonce_serialize(lsp->ctx, lsp_poison_pn_ser, &lsp_poison_pubnonce);
            memcpy(all_poison_pn[lsp_slot], lsp_poison_pn_ser, 66);
            int pz_ok = 1;
            for (size_t s = 0; s < sub->n_signers && pz_ok; s++) {
                secp256k1_musig_pubnonce ppn;
                if (!musig_pubnonce_parse(lsp->ctx, &ppn, all_poison_pn[s]) ||
                    !factory_session_set_nonce_poison(f, sub_node_i, s, &ppn))
                    pz_ok = 0;
            }
            secp256k1_musig_partial_sig lsp_poison_psig;
            pz_ok = pz_ok &&
                factory_session_finalize_node_poison(f, sub_node_i) &&
                musig_create_partial_sig(lsp->ctx, &lsp_poison_psig,
                                           &lsp_poison_secnonce, &lsp_kp,
                                           &sub->poison_signing_session) &&
                factory_session_set_partial_sig_poison(f, sub_node_i,
                                                         (size_t)lsp_slot, &lsp_poison_psig);
            /* Zero the poison secnonce on every path before the recv that follows. */
            memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
            if (!pz_ok) {
                fprintf(stderr, "LSP-stateless MULTI: LSP poison sign failed -- "
                        "degrading\n");
                factory_session_reset_poison(f, sub_node_i);
                poison_prepared = 0;
            } else {
                musig_partial_sig_serialize(lsp->ctx, lsp_poison_psig_ser, &lsp_poison_psig);
            }
        }
    }

    memset(lsp_seckey, 0, 32);
    free(lsp_secnonces);  /* all entries already zeroed by create_partial_sig */

    /* Build flat per-input LSP arrays for the wire response. */
    unsigned char *lsp_pn_flat = calloc(n_inputs, 66);
    unsigned char *lsp_psig_flat = calloc(n_inputs, 32);
    if (!lsp_pn_flat || !lsp_psig_flat) {
        free(lsp_pn_flat); free(lsp_psig_flat);
        free(lsp_pn_ser); free(lsp_psig_ser);
        free(all_pn_per_input);
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    for (size_t i = 0; i < n_inputs; i++) {
        memcpy(lsp_pn_flat + i * 66, lsp_pn_ser[i], 66);
        memcpy(lsp_psig_flat + i * 32, lsp_psig_ser[i], 32);
    }
    free(lsp_pn_ser); free(lsp_psig_ser);

    /* Step 6: LSP_RESPONSE -- per-input LSP nonces + psigs, plus the full
       signer x input matrix (all_pn_per_input) as the all-signer blob so each
       client can set every co-signer's per-input nonce and finalize.  Carries
       the single-input LSP poison nonce + psig when poison is still active. */
    cJSON *response = wire_build_subfactory_lsp_response(
        lsp_pn_flat, lsp_psig_flat, (uint32_t)n_inputs,
        all_pn_per_input,
        (uint32_t)(sub->n_signers * n_inputs * 66),
        poison_prepared ? (const unsigned char *)all_poison_pn : NULL,
        poison_prepared ? (uint32_t)(sub->n_signers * 66) : 0,
        poison_prepared ? lsp_poison_psig_ser : NULL);
    free(lsp_pn_flat); free(lsp_psig_flat);
    free(all_pn_per_input);
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_SUBFACTORY_LSP_RESPONSE, response)) {
            cJSON_Delete(response);
            fprintf(stderr, "LSP-stateless MULTI: send LSP_RESPONSE failed for client %u\n",
                    sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
    }
    cJSON_Delete(response);

    /* Step 7: collect each client's n_inputs final psigs. */
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        wire_msg_t pmsg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx],
                                            &pmsg, WIRE_CEREMONY_RECV_TIMEOUT_SEC) ||
            pmsg.msg_type != MSG_SUBFACTORY_CLIENT_FINAL_PSIGS) {
            fprintf(stderr,
                    "LSP-stateless MULTI: expected CLIENT_FINAL_PSIGS from client %u, got 0x%02x\n",
                    sub_clients[ci], pmsg.msg_type);
            if (pmsg.json) cJSON_Delete(pmsg.json);
            return 0;
        }
        unsigned char *client_psig_buf = calloc(n_inputs, 32);
        if (!client_psig_buf) {
            cJSON_Delete(pmsg.json);
            factory_session_reset_poison(f, sub_node_i); return 0;
        }
        unsigned char client_poison_psig_ser[32];
        int parse_rc = wire_parse_subfactory_client_final_psigs(
            pmsg.json, client_psig_buf, (uint32_t)n_inputs,
            poison_prepared ? client_poison_psig_ser : NULL);
        if (parse_rc == 0) {
            cJSON_Delete(pmsg.json);
            free(client_psig_buf);
            factory_session_reset_poison(f, sub_node_i);
            fprintf(stderr, "LSP-stateless MULTI: parse CLIENT_FINAL_PSIGS failed\n");
            return 0;
        }
        cJSON_Delete(pmsg.json);
        if (poison_prepared && parse_rc < 2) {
            fprintf(stderr, "LSP-stateless MULTI: client %u omitted poison psig "
                    "-- degrading\n", sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        }
        /* SF-MULTI-KEYAGG (#283): client_slot is the NODE-level slot used only
           for the poison side-channel (N-of-N).  Per-input psig assignment
           remaps via factory_session_get_input_signer_slot and skips inputs
           the client does not sign. */
        int client_slot = factory_find_signer_slot(f, sub_node_i, sub_clients[ci]);
        if (client_slot < 0) {
            free(client_psig_buf);
            factory_session_reset_poison(f, sub_node_i); return 0;
        }
        for (size_t i = 0; i < n_inputs; i++) {
            int per_input_slot = factory_session_get_input_signer_slot(
                f, sub_node_i, i, sub_clients[ci]);
            if (per_input_slot < 0) {
                /* Client does not sign this input — wire carries a 32-byte
                   zero psig placeholder (or, pre-Phase-3, garbage). */
                continue;
            }
            secp256k1_musig_partial_sig client_psig_i;
            if (!musig_partial_sig_parse(lsp->ctx, &client_psig_i,
                                          client_psig_buf + i * 32) ||
                !factory_session_set_partial_sig_input(f, sub_node_i, i,
                                                        (size_t)per_input_slot,
                                                        &client_psig_i)) {
                fprintf(stderr, "LSP-stateless MULTI: set client psig "
                        "(client %u input %zu per_input_slot=%d) failed\n",
                        sub_clients[ci], i, per_input_slot);
                free(client_psig_buf);
                factory_session_reset_poison(f, sub_node_i);
                return 0;
            }
        }
        free(client_psig_buf);
        if (poison_prepared) {
            secp256k1_musig_partial_sig client_poison_psig;
            if (!musig_partial_sig_parse(lsp->ctx, &client_poison_psig, client_poison_psig_ser) ||
                !factory_session_set_partial_sig_poison(f, sub_node_i,
                                                          (size_t)client_slot, &client_poison_psig)) {
                fprintf(stderr, "LSP-stateless MULTI: set client poison psig "
                        "(client %u) failed -- degrading\n", sub_clients[ci]);
                factory_session_reset_poison(f, sub_node_i);
                poison_prepared = 0;
            }
        }
    }

    lsp_crash_checkpoint("subfactory_multi_signed");

    /* Step 8: aggregate + assemble the k+1-witness signed TX + complete poison. */
    if (!factory_session_assemble_signed_tx_multi(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless MULTI: assemble_signed_tx_multi failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    if (poison_prepared &&
        !factory_session_complete_node_poison(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless MULTI: poison complete failed -- degrading\n");
        factory_session_reset_poison(f, sub_node_i);
        poison_prepared = 0;
    }

    /* #53 verify-the-aggregate: before trusting (and shipping to clients) the poison
       agg-sig, the LSP verifies it against the untweaked sub agg key + poison sighash --
       catching a bad co-signer partial that aggregated into a worthless sig (BIP-327
       identifiable-abort spirit; mirrors the leaf LSP verify at ~1782).  On failure
       degrade -> the fail-closed guard below aborts (no revoke without VALID recourse). */
    if (poison_prepared && sub->poison_is_scriptpath) {
        secp256k1_pubkey ppk; secp256k1_xonly_pubkey pxpk;
        if (!(secp256k1_musig_pubkey_get(lsp->ctx, &ppk, &sub->poison_signing_session.cache) &&
              secp256k1_xonly_pubkey_from_pubkey(lsp->ctx, &pxpk, NULL, &ppk) &&
              secp256k1_schnorrsig_verify(lsp->ctx, sub->poison_agg_sig,
                                          sub->poison_signing_session.msg32, 32, &pxpk))) {
            fprintf(stderr, "LSP-stateless MULTI: sub poison agg-sig FAILED self-verify "
                            "(bad co-signer partial?) -- degrading\n");
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        }
    }

    /* #53 Phase 3 fail-closed: hashlock ON + a sales-stock poison was economically
       REQUIRED but NOT co-signed -> ABORT before DONE.  Advancing would revoke the old
       sub state with no recourse (Scenario B at the sub level).  The new state is
       assembled in memory only (not persisted / DONE-sent yet), so resetting it here
       keeps BOTH sides on the old, still-recourse-able state.  Subsumes every
       degrade-and-continue site above (any leaves poison_prepared==0) plus the case
       where prep never ran.  Mirrors the leaf guard (lsp_channels.c ~1821); legacy
       (flag off) keeps the prior degrade-and-continue behavior unchanged. */
    if (f->use_hashlock_poison && poison_required && !poison_prepared) {
        fprintf(stderr, "LSP-stateless MULTI: hashlock ON + sales-stock poison REQUIRED "
                        "but NOT co-signed -- ABORTING sub-advance (no revoke without "
                        "recourse)\n");
        sub->is_signed = 0;
        tx_buf_reset(&sub->signed_tx);
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }

    /* Step 9: DONE to each client.  #53: when the poison was co-signed, attach the
       AGGREGATED poison Schnorr sig so each sub client can persist a complete recourse
       template (it cannot aggregate the N-party poison locally, unlike the 2-party
       leaf).  The secret follows in the reveal below. */
    cJSON *done = wire_build_subfactory_done(leaf_side, sub_idx_in_leaf, sub->ps_chain_len);
    if (f->use_hashlock_poison && poison_prepared && sub->poison_is_scriptpath &&
        sub->poison_has_agg_sig) {
        unsigned char aggsig_to_send[64];
        memcpy(aggsig_to_send, sub->poison_agg_sig, 64);
        /* P1 adversarial drill: a MALICIOUS LSP ships a CORRUPTED agg-sig so the client
           would persist a worthless poison (neutering its recourse).  The client's
           verify-before-trust (client.c ~3221) MUST reject it.  Env-gated + regtest-only
           (superscalar_cheat_allowed); the #9 mainnet gate refuses any SS_CHEAT* env, so
           this is unreachable on mainnet.  The LSP's own poison_agg_sig stays intact. */
        if (superscalar_cheat_allowed() && getenv("SS_CHEAT_BAD_POISON_AGGSIG")) {
            aggsig_to_send[0] ^= 0xff;
            fprintf(stderr, "SS_CHEAT_BAD_POISON_AGGSIG: shipping a CORRUPTED poison agg-sig "
                            "to sub clients (expect client verify to reject)\n");
        }
        wire_subfactory_done_set_poison_aggsig(done, aggsig_to_send);
    }
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        wire_send(lsp->client_fds[fd_idx], MSG_SUBFACTORY_DONE, done);
    }
    cJSON_Delete(done);

    /* #53 Phase 2: reveal the SUPERSEDED sub state's sales-stock revocation secret to
       EVERY sub client (targeted, not broadcast).  Each client verifies + persists it
       so it (or its standalone WT) can spend the Leaf-P sub poison if the LSP later
       broadcasts that stale sub state -- closing Scenario B at the sub level in the live
       protocol.  Gated on hashlock + a poison having been co-signed; the secret is
       re-derived from the seed, keyed by the sub node's agg xonly + the OLD state
       counter (which Phase 0 bumped during this advance, so current-1 = superseded). */
    if (f->use_hashlock_poison && poison_prepared && sub->has_l_stock_hash) {
        uint32_t old_counter = (sub->l_stock_state_counter > 0)
                               ? sub->l_stock_state_counter - 1u : 0u;
        unsigned char reveal_secret[1][32];
        if (factory_derive_l_stock_secret(f, sub, old_counter, reveal_secret[0])) {
            uint32_t rn = (uint32_t)sub_node_i;
            cJSON *rev = wire_build_lstock_reveal(&rn, &old_counter, reveal_secret, 1);
            if (rev) {
                for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
                    size_t fd_idx = (size_t)(sub_clients[ci] - 1);
                    wire_send(lsp->client_fds[fd_idx], MSG_LSTOCK_REVEAL, rev);
                }
                cJSON_Delete(rev);
                printf("LSP-stateless MULTI: revealed sub sales-stock secret for "
                       "node %zu state %u to %zu clients\n",
                       sub_node_i, old_counter, n_clients_in_sub);
            }
            memset(reveal_secret, 0, sizeof(reveal_secret));
        }
    }

    lsp_crash_checkpoint("subfactory_multi_finalize_partial");

    /* Step 10 (persist): record the chain row, mirroring the single-input
       path's Step 10.  Without this an LSP restart loses the multi-input
       advance and the e2e row-count assertion fails. */
    if (mgr->persist) {
        extern void reverse_bytes(unsigned char *, size_t);
        unsigned char txid_display[32];
        memcpy(txid_display, sub->txid, 32);
        reverse_bytes(txid_display, 32);
        size_t sstock_vout = sub->n_outputs - 1;
        uint64_t chan_amounts[16] = {0};
        int n_chans = (int)sstock_vout;
        if (n_chans > 16) n_chans = 16;
        for (int ci = 0; ci < n_chans; ci++)
            chan_amounts[ci] = sub->outputs[ci].amount_sats;
        const unsigned char *poison_bytes = NULL;
        size_t poison_bytes_len = 0;
        if (poison_prepared && sub->poison_is_signed && sub->poison_signed_tx.len > 0) {
            poison_bytes     = sub->poison_signed_tx.data;
            poison_bytes_len = sub->poison_signed_tx.len;
        }
        persist_save_subfactory_chain_entry(
            (persist_t *)mgr->persist, /* factory_id = */ 0,
            (uint32_t)sub_node_i,
            sub->ps_chain_len - 1,
            f->counter.current_epoch,
            txid_display,
            sub->signed_tx.data, sub->signed_tx.len,
            sub->outputs[sstock_vout].amount_sats,
            chan_amounts, n_chans,
            poison_bytes, poison_bytes_len);
    }

    /* Step 10b (poison + WT registration): register the now-stale chain[N-1]
       + wire-co-signed L-stock poison TX with the watchtower, as legacy does. */
    if (mgr->watchtower && sub->ps_chain_len >= 1) {
        int have_poison = (poison_prepared && sub->poison_is_signed &&
                           sub->poison_signed_tx.len > 0);
        if (have_poison)
            printf("LSP-stateless: sub-factory MULTI %d.%d wire-ceremony poison TX "
                   "signed (%zu bytes, sales-stock %llu sats -> %zu clients)\n",
                   leaf_side, sub_idx_in_leaf, sub->poison_signed_tx.len,
                   (unsigned long long)wt_old_sstock_amount, wt_old_n_chans);
        else
            fprintf(stderr, "LSP-stateless subfactory MULTI advance: registering "
                    "watchtower without poison TX -- DEGRADED\n");
        watchtower_watch_subfactory_node(mgr->watchtower,
            (uint32_t)sub_node_i,
            wt_old_chain_txid,
            sub->signed_tx.data, sub->signed_tx.len,
            have_poison ? sub->poison_signed_tx.data : NULL,
            have_poison ? sub->poison_signed_tx.len  : 0,
            wt_old_chan_amounts, wt_old_n_chans,
            wt_old_sstock_amount);

        /* SF-WT-TRUSTLESS Phase 2c: parallel wt_db register for sub-factory
         * chain advance (MULTI-input).  Mirrors the Tier B pattern at
         * lsp_channels.c:2823.  Trustless WT consumes this row instead of
         * needing lsp.db access. */
        if (lsp && lsp->wt_db && wt_old_chain_spk_len > 0) {
            int64_t watch_id = lsp_wt_register_subfactory_node_watch(
                lsp->wt_db,
                (uint32_t)sub_node_i,
                wt_old_chain_txid,
                /* parent_vout      */ 0,
                /* parent_value_sat */ wt_old_chain_amount,
                wt_old_chain_spk, wt_old_chain_spk_len,
                /* csv_delay        */ wt_old_csv_delay,
                /* G1 #44: store the POISON as the trustless wt_db response when
                   available — it spends chain[N-1]'s OWN sales-stock output, so it
                   remediates a CONFIRMED sub-factory breach (chain[N] in wt_db only
                   worked via pre-confirmation RBF and orphaned -25 once the breach
                   confirmed, with no fallback). Falls back to chain[N] if degraded. */
                (sub->poison_is_signed && sub->poison_signed_tx.len > 0)
                    ? sub->poison_signed_tx.data : sub->signed_tx.data,
                (sub->poison_is_signed && sub->poison_signed_tx.len > 0)
                    ? sub->poison_signed_tx.len  : sub->signed_tx.len,
                (sub->poison_is_signed && sub->poison_signed_tx.len > 0)
                    ? sub->poison_txid : sub->txid,
                /* fee_bump_budget  */ 0,
                /* fee_bump_dline   */ 0);
            if (watch_id > 0) {
                printf("LSP-WT-TRUSTLESS: registered sub-factory MULTI "
                       "watch_id=%lld for sub-node %zu (parent=%llu sats, "
                       "csv=%u, %zu chans, sstock=%llu)\n",
                       (long long)watch_id, sub_node_i,
                       (unsigned long long)wt_old_chain_amount,
                       (unsigned)wt_old_csv_delay,
                       wt_old_n_chans,
                       (unsigned long long)wt_old_sstock_amount);
            } else {
                fprintf(stderr,
                        "LSP-WT-TRUSTLESS: WARN — wt_db register failed for "
                        "sub-factory MULTI node %zu\n", sub_node_i);
            }
        }

        factory_session_reset_poison(f, sub_node_i);
    }

    printf("LSP-stateless subfactory MULTI-INPUT advance (n_inputs=%zu) DONE\n", n_inputs);
    printf("LSP-stateless subfactory chain advance: leaf %d sub %d chan %d delta %llu sats DONE\n",
           leaf_side, sub_idx_in_leaf, channel_idx_in_sub,
           (unsigned long long)delta_sats);
    return 1;
}

static int lsp_subfactory_chain_advance_stateless(lsp_channel_mgr_t *mgr,
                                                    lsp_t *lsp,
                                                    int leaf_side,
                                                    int sub_idx_in_leaf,
                                                    int channel_idx_in_sub,
                                                    uint64_t delta_sats) {
    if (!mgr || !lsp) return 0;
    factory_t *f = &lsp->factory;
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;
    if (sub_idx_in_leaf < 0) return 0;
    size_t leaf_node_i = (size_t)f->leaf_node_indices[leaf_side];
    if (leaf_node_i >= f->n_nodes) return 0;
    factory_node_t *leaf = &f->nodes[leaf_node_i];
    if ((size_t)sub_idx_in_leaf >= leaf->n_outputs) return 0;
    /* Compute sub_node index — same as legacy.  Sub-factory PS leaves have
       k sub-nodes after the leaf, one per output other than L-stock. */
    /* We assume the same layout helper used by the public function.  Look up
       sub_node_i via factory_node_indices for the leaf's child outputs. */
    size_t sub_node_i = leaf_node_i + 1 + (size_t)sub_idx_in_leaf;
    if (sub_node_i >= f->n_nodes) return 0;
    factory_node_t *sub = &f->nodes[sub_node_i];

    /* Phase 1e.1.d: k>=2 multi-client now supported -- LSP_RESPONSE (0x7F)
       forwards the full per-signer nonce array (all_pubnonces) so each client
       can build the aggnonce and finalize.  Mirror of Tier B Gap A. */

    /* Sub-factory clients (one client per output != L-stock + LSP).
       Build sub_clients[] -- same shape as legacy. */
    uint32_t sub_clients[FACTORY_MAX_SIGNERS];
    size_t n_clients_in_sub = 0;
    for (size_t s = 1; s < sub->n_signers; s++) {
        sub_clients[n_clients_in_sub++] = sub->signer_indices[s];
    }
    if (n_clients_in_sub == 0) {
        fprintf(stderr, "LSP-stateless subfactory advance: no clients in sub\n");
        return 0;
    }

    /* Phase 1e.1.e: MULTI-INPUT now runs through the STATELESS path too.
       The single-input flow below is unchanged; multi-input gets its own
       fully-looped block that mirrors the validated single-input ordering
       per input.  The whole point is the same BIP-327 invariant: the LSP
       generates its per-input secnonces ONLY after collecting every client's
       pubnonces, and each lsp_secnonces[i] is consumed/zeroed by
       musig_create_partial_sig before the next wire_recv.

       SF-MULTI-DISPATCH: predict whether the chain[N+1] state we're about
       to build is multi-input.  factory_node_uses_multi_input checks
       ps_n_prev_outputs > 1, but that field is populated INSIDE
       factory_subfactory_chain_advance_unsigned (called below), so at this
       point it's still 0 for the first advance.  Predicate equivalent at
       this point: PS sub-factory with k>=2 (n_outputs > 1) ALWAYS produces
       a multi-input chain[N+1] -- rebuild_node_tx spends all n_outputs of
       chain[N] as inputs.  The legacy path dispatches AFTER advance_unsigned
       so it uses the post-state predicate; we must dispatch BEFORE because
       _stateless_multi calls advance_unsigned itself. */
    if (sub->is_ps_leaf && sub->type == NODE_PS_SUBFACTORY &&
        sub->n_outputs > 1) {
        return lsp_subfactory_chain_advance_stateless_multi(
            mgr, lsp, f, sub_node_i, sub, sub_clients, n_clients_in_sub,
            leaf_side, sub_idx_in_leaf, channel_idx_in_sub, delta_sats);
    }

    /* #53 fail-closed: the hashlock sales-stock poison (per-state H, reveal, fail-closed
       guard) is wired ONLY in the multi-input ceremony above.  Any real sub-factory
       (k>=1 channels -> n_outputs > 1) dispatches there; this single-input tail is only
       reachable for a degenerate 0-channel sub (whose channel advance fails the bounds
       check anyway).  Refuse rather than run a single-input advance that would revoke the
       old sub state with no hashlock recourse.  Non-hashlock subs keep the legacy flow. */
    if (f->use_hashlock_poison && sub->has_l_stock_hash) {
        fprintf(stderr, "LSP-stateless subfactory advance: hashlock poison ON but reached "
                        "the single-input path (n_outputs=%zu) -- REFUSING (hashlock sub "
                        "poison is multi-input only)\n", sub->n_outputs);
        return 0;
    }

    /* Step 1.5 (poison prep): snapshot the soon-to-be-stale chain[N-1] state
       (txid + per-channel amounts + sales-stock) BEFORE advance_unsigned
       mutates sub->txid / sub->outputs[], then build the unsigned L-stock
       poison TX (mirror of legacy lsp_subfactory_chain_advance Step "poison
       TX prep" + Tier B 1eda8aa).  Clients run the same prepare from their
       own OLD snapshot so both sides reach a byte-identical sighash.  Poison
       only when the watchtower is configured (LSP-only gate). */
    const uint64_t POISON_FEE_SATS = 1000;
    int poison_prepared = 0;
    unsigned char wt_old_chain_txid[32];
    memcpy(wt_old_chain_txid, sub->txid, 32);
    size_t wt_old_n_chans = (sub->n_outputs > 0) ? sub->n_outputs - 1 : 0;
    if (wt_old_n_chans > 16) wt_old_n_chans = 16;
    uint64_t wt_old_chan_amounts[16] = {0};
    for (size_t ci = 0; ci < wt_old_n_chans; ci++)
        wt_old_chan_amounts[ci] = sub->outputs[ci].amount_sats;
    uint64_t wt_old_sstock_amount = (sub->n_outputs > 0)
        ? sub->outputs[sub->n_outputs - 1].amount_sats : 0;
    /* SF-WT-TRUSTLESS Phase 2c: also snapshot parent vout/value/spk/csv for
       trustless wt_db register (mirrors Tier B pattern at line 2299+ and
       the multi-input branch above).  outputs[0] is the first channel
       output of the chain TX; parent_vout=0 by convention. */
    uint64_t wt_old_chain_amount = (sub->n_outputs > 0)
        ? sub->outputs[0].amount_sats : 0;
    size_t wt_old_chain_spk_len = (sub->n_outputs > 0)
        ? sub->outputs[0].script_pubkey_len : 0;
    if (wt_old_chain_spk_len > 34) wt_old_chain_spk_len = 34;
    unsigned char wt_old_chain_spk[34] = {0};
    if (sub->n_outputs > 0 && wt_old_chain_spk_len > 0)
        memcpy(wt_old_chain_spk, sub->outputs[0].script_pubkey,
               wt_old_chain_spk_len);
    uint32_t wt_old_csv_delay = (uint32_t)(sub->nsequence & 0xFFFFu);
    if (mgr->watchtower &&
        wt_old_sstock_amount > POISON_FEE_SATS + (uint64_t)wt_old_n_chans * 330u) {
        if (factory_session_prepare_poison_tx_subfactory(
                f, sub_node_i, wt_old_chain_txid, (uint32_t)wt_old_n_chans,
                wt_old_sstock_amount, POISON_FEE_SATS,
                NULL /* #53-B3b: capture sub H_old when daemon hashlock on */)) {
            poison_prepared = 1;  /* init_node_poison after state init */
        } else {
            fprintf(stderr,
                    "LSP-stateless subfactory advance: poison TX prep failed "
                    "(sstock=%llu sats, n_chans=%zu) -- NULL poison_tx\n",
                    (unsigned long long)wt_old_sstock_amount, wt_old_n_chans);
        }
    }

    /* Step 1: factory_subfactory_chain_advance_unsigned — rebuild unsigned_tx. */
    if (!factory_subfactory_chain_advance_unsigned(f, leaf_side,
                                                    sub_idx_in_leaf,
                                                    channel_idx_in_sub,
                                                    delta_sats)) {
        fprintf(stderr, "LSP-stateless subfactory advance: advance_unsigned failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }

    /* Step 2: init state session + (when prepared) poison session. */
    if (!factory_session_init_node(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless subfactory advance: session init failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    if (poison_prepared &&
        !factory_session_init_node_poison(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless subfactory advance: poison session init "
                "failed -- degrading\n");
        factory_session_reset_poison(f, sub_node_i);
        poison_prepared = 0;
    }

    /* Step 3: send PROPOSE_INTENT to each sub-client (NO LSP nonce). */
    /* SF-CRASH-INJECT-WIRE #245 Half A: journal sub-factory advance. */
    unsigned char cer_id[8] = {0};
    int cer_persisted = 0;
    if (mgr->persist) {
        uint64_t epoch_salt = ((uint64_t)f->counter.current_epoch << 24)
                              | ((uint64_t)sub_node_i << 8)
                              | ((uint64_t)sub->ps_chain_len & 0xff);
        lsp_ceremony_derive_id(lsp->factory.funding_txid,
                                PERSIST_CEREMONY_TYPE_STATE_UPDATE,
                                epoch_salt, cer_id);
        if (persist_save_ceremony((persist_t *)mgr->persist, cer_id,
                                   lsp->factory.funding_txid,
                                   PERSIST_CEREMONY_TYPE_STATE_UPDATE,
                                   NULL, 0, f->cltv_timeout))
            cer_persisted = 1;
    }
    cJSON *propose = wire_build_subfactory_propose_intent((uint32_t)sub_node_i, 1, leaf_side, sub_idx_in_leaf, channel_idx_in_sub, delta_sats);
    /* #53 sub-factory hashlock: ship the sub's NEW-state H (Phase 0 of the advance
       above) so the seedless client mirrors it before its own sub-advance. No-op when
       hashlock poison off. Mirrors the leaf path + the multi-input branch above. */
    if (f->use_hashlock_poison && sub->has_l_stock_hash)
        wire_json_add_hex(propose, "l_stock_hash", sub->l_stock_hash, 32);
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_SUBFACTORY_PROPOSE_INTENT, propose)) {
            cJSON_Delete(propose);
            fprintf(stderr, "LSP-stateless: send PROPOSE_INTENT failed for client %u\n",
                    sub_clients[ci]);
            return 0;
        }
    }
    cJSON_Delete(propose);
    if (cer_persisted) {
        for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
            size_t pk_idx = (size_t)(sub_clients[ci] - 1);
            unsigned char pk33[33];
            lsp_ceremony_get_client_pubkey33(lsp, pk_idx, pk33);
            (void)persist_save_participant_phase((persist_t *)mgr->persist, cer_id,
                pk33, PERSIST_CEREMONY_PHASE_SENT, NULL, NULL, 0, 0);
        }
    }
    printf("LSP: SUBFACTORY_PROPOSE_INTENT sent to %zu clients (sub_node %zu)\n",
           n_clients_in_sub, sub_node_i);
    fflush(stdout);

    lsp_crash_checkpoint("subfactory_propose");

    /* Step 4: collect CLIENT_PUBNONCES from each client (state + poison). */
    unsigned char all_pubnonces[FACTORY_MAX_SIGNERS][66];
    unsigned char all_poison_pubnonces[FACTORY_MAX_SIGNERS][66];
    memset(all_poison_pubnonces, 0, sizeof(all_poison_pubnonces));
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        wire_msg_t nmsg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx],
                                            &nmsg, WIRE_CEREMONY_RECV_TIMEOUT_SEC) ||
            nmsg.msg_type != MSG_SUBFACTORY_CLIENT_PUBNONCES) {
            fprintf(stderr,
                    "LSP-stateless: expected CLIENT_PUBNONCES from client %u, got 0x%02x\n",
                    sub_clients[ci], nmsg.msg_type);
            if (nmsg.json) cJSON_Delete(nmsg.json);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
        unsigned char client_pn_buf[66], client_poison_pn[66];
        int parse_rc = wire_parse_subfactory_client_pubnonces(
            nmsg.json, client_pn_buf, 1,
            poison_prepared ? client_poison_pn : NULL);
        if (parse_rc == 0) {
            cJSON_Delete(nmsg.json);
            fprintf(stderr, "LSP-stateless: parse CLIENT_PUBNONCES failed\n");
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
        cJSON_Delete(nmsg.json);
        if (poison_prepared && parse_rc < 2) {
            fprintf(stderr, "LSP-stateless: client %u omitted poison nonce -- "
                    "degrading to NULL poison_tx\n", sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        }
        int client_slot = factory_find_signer_slot(f, sub_node_i, sub_clients[ci]);
        if (client_slot < 0) { factory_session_reset_poison(f, sub_node_i); return 0; }
        memcpy(all_pubnonces[client_slot], client_pn_buf, 66);
        if (poison_prepared)
            memcpy(all_poison_pubnonces[client_slot], client_poison_pn, 66);
    }

    lsp_crash_checkpoint("subfactory_nonced");

    /* Step 5 (THE CRITICAL ATOMIC BLOCK): gen LSP secnonce, set all nonces,
       finalize_node, create_partial_sig (zeros secnonce), serialize. */
    int lsp_slot = factory_find_signer_slot(f, sub_node_i, 0);
    if (lsp_slot < 0) return 0;

    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) return 0;

    secp256k1_musig_secnonce lsp_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                                lsp_seckey, &lsp->lsp_pubkey,
                                &sub->keyagg.cache)) {
        memset(lsp_seckey, 0, 32);
        fprintf(stderr, "LSP-stateless subfactory: nonce gen failed\n");
        return 0;
    }

    unsigned char lsp_pubnonce_ser[66];
    musig_pubnonce_serialize(lsp->ctx, lsp_pubnonce_ser, &lsp_pubnonce);
    memcpy(all_pubnonces[lsp_slot], lsp_pubnonce_ser, 66);

    /* Poison (same atomic block): generate the LSP poison secnonce HERE, after
       the Step-4 recv, alongside the state secnonce.  It is a loop-local
       zeroed by musig_create_partial_sig below before the Step-7 recv -- the
       stateless invariant holds for the poison secnonce exactly as for state. */
    secp256k1_musig_secnonce lsp_poison_secnonce;
    secp256k1_musig_pubnonce lsp_poison_pubnonce;
    unsigned char lsp_poison_pn_ser[66] = {0};
    if (poison_prepared) {
        if (!musig_generate_nonce(lsp->ctx, &lsp_poison_secnonce,
                                   &lsp_poison_pubnonce, lsp_seckey,
                                   &lsp->lsp_pubkey, &sub->keyagg.cache)) {
            fprintf(stderr, "LSP-stateless subfactory: poison nonce gen failed "
                    "-- degrading\n");
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        } else {
            musig_pubnonce_serialize(lsp->ctx, lsp_poison_pn_ser, &lsp_poison_pubnonce);
            memcpy(all_poison_pubnonces[lsp_slot], lsp_poison_pn_ser, 66);
        }
    }

    /* Set every signer's nonce on the state session. */
    for (size_t s = 0; s < sub->n_signers; s++) {
        secp256k1_musig_pubnonce pn;
        if (!musig_pubnonce_parse(lsp->ctx, &pn, all_pubnonces[s]) ||
            !factory_session_set_nonce(f, sub_node_i, s, &pn)) {
            memset(lsp_seckey, 0, 32);
            memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
            fprintf(stderr, "LSP-stateless subfactory: set_nonce[%zu] failed\n", s);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
    }
    /* Set every signer's nonce on the poison session (degrade on failure). */
    if (poison_prepared) {
        for (size_t s = 0; s < sub->n_signers; s++) {
            secp256k1_musig_pubnonce ppn;
            if (!musig_pubnonce_parse(lsp->ctx, &ppn, all_poison_pubnonces[s]) ||
                !factory_session_set_nonce_poison(f, sub_node_i, s, &ppn)) {
                fprintf(stderr, "LSP-stateless subfactory: poison set_nonce[%zu] "
                        "failed -- degrading\n", s);
                factory_session_reset_poison(f, sub_node_i);
                poison_prepared = 0;
                break;
            }
        }
    }

    if (!factory_session_finalize_node(f, sub_node_i)) {
        memset(lsp_seckey, 0, 32);
        memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
        fprintf(stderr, "LSP-stateless subfactory: finalize_node failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    if (poison_prepared &&
        !factory_session_finalize_node_poison(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless subfactory: poison finalize failed -- "
                "degrading\n");
        factory_session_reset_poison(f, sub_node_i);
        poison_prepared = 0;
    }

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(lsp->ctx, &lsp_kp, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce, &lsp_kp,
                                    &sub->signing_session)) {
        memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
        fprintf(stderr, "LSP-stateless subfactory: create_partial_sig failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    /* lsp_secnonce zeroed by musig_create_partial_sig.
       INVARIANT: no LSP state secnonce held across the wire recv that follows. */

    unsigned char lsp_psig_ser[32];
    musig_partial_sig_serialize(lsp->ctx, lsp_psig_ser, &lsp_psig);

    if (!factory_session_set_partial_sig(f, sub_node_i, (size_t)lsp_slot, &lsp_psig)) {
        memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }

    /* Poison: create the LSP poison partial sig (zeros lsp_poison_secnonce) in
       the SAME atomic block -- no wire_recv between gen and zero. */
    unsigned char lsp_poison_psig_ser[32] = {0};
    if (poison_prepared) {
        secp256k1_musig_partial_sig lsp_poison_psig;
        int pz_ok =
            musig_create_partial_sig(lsp->ctx, &lsp_poison_psig,
                                       &lsp_poison_secnonce, &lsp_kp,
                                       &sub->poison_signing_session) &&
            factory_session_set_partial_sig_poison(f, sub_node_i,
                                                     (size_t)lsp_slot, &lsp_poison_psig);
        /* Zero on every path: create_partial_sig zeroed it on success; on
           failure clear the generated-but-unconsumed secnonce so none lingers
           across the Step-7 recv. */
        memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
        if (!pz_ok) {
            fprintf(stderr, "LSP-stateless subfactory: LSP poison psig failed -- "
                    "degrading\n");
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        } else {
            musig_partial_sig_serialize(lsp->ctx, lsp_poison_psig_ser, &lsp_poison_psig);
        }
    } else {
        memset(&lsp_poison_secnonce, 0, sizeof(lsp_poison_secnonce));
    }

    /* Step 6: send LSP_RESPONSE to each client (per-client copy so each can
       individually finalize_node + sign).  Single-input -> 1 element each.
       Carries the LSP poison pubnonce + psig when poison is still active. */
    cJSON *response = wire_build_subfactory_lsp_response(lsp_pubnonce_ser,
                                                          lsp_psig_ser, 1,
                                                          (const unsigned char *)all_pubnonces,
                                                          (uint32_t)(sub->n_signers * 66),
                                                          poison_prepared ? (const unsigned char *)all_poison_pubnonces : NULL,
                                                          poison_prepared ? (uint32_t)(sub->n_signers * 66) : 0,
                                                          poison_prepared ? lsp_poison_psig_ser : NULL);
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        if (!wire_send(lsp->client_fds[fd_idx], MSG_SUBFACTORY_LSP_RESPONSE, response)) {
            cJSON_Delete(response);
            fprintf(stderr, "LSP-stateless: send LSP_RESPONSE failed for client %u\n",
                    sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
    }
    cJSON_Delete(response);

    /* Step 7: collect CLIENT_FINAL_PSIGS from each client (state + poison). */
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        wire_msg_t pmsg;
        if (!recv_timeout_service_bridge(mgr, lsp, lsp->client_fds[fd_idx],
                                            &pmsg, WIRE_CEREMONY_RECV_TIMEOUT_SEC) ||
            pmsg.msg_type != MSG_SUBFACTORY_CLIENT_FINAL_PSIGS) {
            fprintf(stderr,
                    "LSP-stateless: expected CLIENT_FINAL_PSIGS from client %u, got 0x%02x\n",
                    sub_clients[ci], pmsg.msg_type);
            if (pmsg.json) cJSON_Delete(pmsg.json);
            return 0;
        }
        unsigned char client_psig_buf[32], client_poison_psig_ser[32];
        int parse_rc = wire_parse_subfactory_client_final_psigs(
            pmsg.json, client_psig_buf, 1,
            poison_prepared ? client_poison_psig_ser : NULL);
        if (parse_rc == 0) {
            cJSON_Delete(pmsg.json);
            fprintf(stderr, "LSP-stateless: parse CLIENT_FINAL_PSIGS failed\n");
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
        cJSON_Delete(pmsg.json);
        if (poison_prepared && parse_rc < 2) {
            fprintf(stderr, "LSP-stateless: client %u omitted poison psig -- "
                    "degrading\n", sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            poison_prepared = 0;
        }
        int client_slot = factory_find_signer_slot(f, sub_node_i, sub_clients[ci]);
        if (client_slot < 0) { factory_session_reset_poison(f, sub_node_i); return 0; }
        secp256k1_musig_partial_sig client_psig;
        if (!musig_partial_sig_parse(lsp->ctx, &client_psig, client_psig_buf) ||
            !factory_session_set_partial_sig(f, sub_node_i, (size_t)client_slot, &client_psig)) {
            fprintf(stderr, "LSP-stateless: set client psig failed for %u\n", sub_clients[ci]);
            factory_session_reset_poison(f, sub_node_i);
            return 0;
        }
        if (poison_prepared) {
            secp256k1_musig_partial_sig client_poison_psig;
            if (!musig_partial_sig_parse(lsp->ctx, &client_poison_psig, client_poison_psig_ser) ||
                !factory_session_set_partial_sig_poison(f, sub_node_i,
                                                          (size_t)client_slot, &client_poison_psig)) {
                fprintf(stderr, "LSP-stateless: set client poison psig failed for %u "
                        "-- degrading\n", sub_clients[ci]);
                factory_session_reset_poison(f, sub_node_i);
                poison_prepared = 0;
            }
        }
    }

    lsp_crash_checkpoint("subfactory_signed");

    /* Step 8: aggregate + complete_node (attaches witness to signed_tx) + poison. */
    if (!factory_session_complete_node(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless subfactory: complete_node failed\n");
        factory_session_reset_poison(f, sub_node_i);
        return 0;
    }
    if (poison_prepared &&
        !factory_session_complete_node_poison(f, sub_node_i)) {
        fprintf(stderr, "LSP-stateless subfactory: poison complete failed -- "
                "degrading\n");
        factory_session_reset_poison(f, sub_node_i);
        poison_prepared = 0;
    }

    /* Step 9: send DONE to each client. */
    cJSON *done = wire_build_subfactory_done(leaf_side, sub_idx_in_leaf, sub->ps_chain_len);
    for (size_t ci = 0; ci < n_clients_in_sub; ci++) {
        size_t fd_idx = (size_t)(sub_clients[ci] - 1);
        wire_send(lsp->client_fds[fd_idx], MSG_SUBFACTORY_DONE, done);
    }
    cJSON_Delete(done);

    lsp_crash_checkpoint("subfactory_finalize_partial");

    /* Step 10 (persist): save the sub-factory chain entry to ps_subfactory_chains,
       mirroring the legacy path (Step 10 below).  Without this the stateless
       advance signs chain[N] but never persists the row, so an LSP restart loses
       it (and the e2e row-count assertion fails).  Stateless MVP runs no poison
       ceremony, so pass NULL/0 for the poison TX bytes. */
    if (mgr->persist) {
        extern void reverse_bytes(unsigned char *, size_t);
        unsigned char txid_display[32];
        memcpy(txid_display, sub->txid, 32);
        reverse_bytes(txid_display, 32);
        size_t sstock_vout = sub->n_outputs - 1;
        uint64_t chan_amounts[16] = {0};
        int n_chans = (int)sstock_vout;
        if (n_chans > 16) n_chans = 16;
        for (int ci = 0; ci < n_chans; ci++)
            chan_amounts[ci] = sub->outputs[ci].amount_sats;
        const unsigned char *poison_bytes = NULL;
        size_t poison_bytes_len = 0;
        if (poison_prepared && sub->poison_is_signed && sub->poison_signed_tx.len > 0) {
            poison_bytes     = sub->poison_signed_tx.data;
            poison_bytes_len = sub->poison_signed_tx.len;
        }
        persist_save_subfactory_chain_entry(
            (persist_t *)mgr->persist, /* factory_id = */ 0,
            (uint32_t)sub_node_i,
            sub->ps_chain_len - 1,
            f->counter.current_epoch,
            txid_display,
            sub->signed_tx.data, sub->signed_tx.len,
            sub->outputs[sstock_vout].amount_sats,
            chan_amounts, n_chans,
            poison_bytes, poison_bytes_len);
    }

    /* Step 10b (poison + WT registration): register the now-stale chain[N-1]
       with the watchtower along with the wire-co-signed L-stock poison TX,
       exactly as the legacy lsp_subfactory_chain_advance does.  poison_tx is
       NULL when poison degraded -- response_tx broadcast still works, but the
       breach cannot redistribute the sales-stock. */
    if (mgr->watchtower && sub->ps_chain_len >= 1) {
        int have_poison = (poison_prepared && sub->poison_is_signed &&
                           sub->poison_signed_tx.len > 0);
        if (have_poison)
            printf("LSP-stateless: sub-factory %d.%d wire-ceremony poison TX signed "
                   "(%zu bytes, sales-stock %llu sats -> %zu clients)\n",
                   leaf_side, sub_idx_in_leaf, sub->poison_signed_tx.len,
                   (unsigned long long)wt_old_sstock_amount, wt_old_n_chans);
        else
            fprintf(stderr,
                    "LSP-stateless subfactory advance: registering watchtower "
                    "without poison TX (poison_prepared=%d, poison_is_signed=%d) "
                    "-- DEGRADED, breach cannot redistribute sales-stock\n",
                    poison_prepared, sub->poison_is_signed);

        watchtower_watch_subfactory_node(mgr->watchtower,
            (uint32_t)sub_node_i,
            wt_old_chain_txid,
            sub->signed_tx.data, sub->signed_tx.len,
            have_poison ? sub->poison_signed_tx.data : NULL,
            have_poison ? sub->poison_signed_tx.len  : 0,
            wt_old_chan_amounts, wt_old_n_chans,
            wt_old_sstock_amount);

        /* SF-WT-TRUSTLESS Phase 2c: parallel wt_db register for sub-factory
         * chain advance (SINGLE-input).  Mirrors the multi-input branch above
         * and the Tier B pattern at lsp_channels.c:2823. */
        if (lsp && lsp->wt_db && wt_old_chain_spk_len > 0) {
            int64_t watch_id = lsp_wt_register_subfactory_node_watch(
                lsp->wt_db,
                (uint32_t)sub_node_i,
                wt_old_chain_txid,
                /* parent_vout      */ 0,
                /* parent_value_sat */ wt_old_chain_amount,
                wt_old_chain_spk, wt_old_chain_spk_len,
                /* csv_delay        */ wt_old_csv_delay,
                /* G1 #44: store the POISON as the trustless wt_db response when
                   available — it spends chain[N-1]'s OWN sales-stock output, so it
                   remediates a CONFIRMED sub-factory breach (chain[N] in wt_db only
                   worked via pre-confirmation RBF and orphaned -25 once the breach
                   confirmed, with no fallback). Falls back to chain[N] if degraded. */
                (sub->poison_is_signed && sub->poison_signed_tx.len > 0)
                    ? sub->poison_signed_tx.data : sub->signed_tx.data,
                (sub->poison_is_signed && sub->poison_signed_tx.len > 0)
                    ? sub->poison_signed_tx.len  : sub->signed_tx.len,
                (sub->poison_is_signed && sub->poison_signed_tx.len > 0)
                    ? sub->poison_txid : sub->txid,
                /* fee_bump_budget  */ 0,
                /* fee_bump_dline   */ 0);
            if (watch_id > 0) {
                printf("LSP-WT-TRUSTLESS: registered sub-factory SINGLE "
                       "watch_id=%lld for sub-node %zu (parent=%llu sats, "
                       "csv=%u, %zu chans, sstock=%llu)\n",
                       (long long)watch_id, sub_node_i,
                       (unsigned long long)wt_old_chain_amount,
                       (unsigned)wt_old_csv_delay,
                       wt_old_n_chans,
                       (unsigned long long)wt_old_sstock_amount);
            } else {
                fprintf(stderr,
                        "LSP-WT-TRUSTLESS: WARN — wt_db register failed for "
                        "sub-factory SINGLE node %zu\n", sub_node_i);
            }
        }

        /* Watchtower copied the bytes; safe to free the poison-session state. */
        factory_session_reset_poison(f, sub_node_i);
    }

    printf("LSP-stateless subfactory chain advance: leaf %d sub %d chan %d delta %llu sats DONE\n",
           leaf_side, sub_idx_in_leaf, channel_idx_in_sub,
           (unsigned long long)delta_sats);
    return 1;
}

int lsp_subfactory_chain_advance(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   int leaf_side, int sub_idx_in_leaf,
                                   int channel_idx_in_sub,
                                   uint64_t delta_sats) {
    return lsp_subfactory_chain_advance_stateless(mgr, lsp, leaf_side, sub_idx_in_leaf, channel_idx_in_sub, delta_sats);
}

/* Buy inbound liquidity from L-stock for a client.
   Moves amount_sats from the L-stock output (last vout on the leaf) to
   the client's channel output, then adjusts channel balance so purchased
   sats become LSP local_amount (= client's inbound capacity).

   Generalized in PR #123 (Gap C-followup) to work for any leaf arity
   that has an L-stock output (i.e., n_outputs >= 2 — at least 1 channel
   + L-stock).  PS leaves post-advance (n_outputs == 1, no L-stock) are
   correctly rejected. */
int lsp_channels_buy_liquidity(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                size_t client_idx, uint64_t amount_sats) {
    if (!mgr || !lsp) return 0;
    factory_t *f = &lsp->factory;
    if (client_idx >= mgr->n_channels || amount_sats == 0) {
        fprintf(stderr, "buy_liquidity: invalid client %zu or amount 0\n", client_idx);
        return 0;
    }

    /* Map client to leaf */
    size_t node_idx;
    uint32_t vout;
    client_to_leaf(client_idx, f, &node_idx, &vout);
    factory_node_t *ln = &f->nodes[node_idx];
    if (ln->n_outputs < 2) {
        fprintf(stderr, "buy_liquidity: leaf %zu has %zu outputs, need >= 2 (channels + L-stock)\n",
                node_idx, ln->n_outputs);
        return 0;
    }

    /* L-stock is the LAST output on the leaf (canonical layout for both
       uniform-arity and mixed-arity factories). */
    size_t lstock_vout = ln->n_outputs - 1;
    if (vout == lstock_vout) {
        fprintf(stderr, "buy_liquidity: client %zu maps to L-stock vout, not a channel\n", client_idx);
        return 0;
    }

    /* Validate L-stock has enough (keep >= 546 dust) */
    uint64_t lstock = ln->outputs[lstock_vout].amount_sats;
    if (lstock < 546 + amount_sats) {
        fprintf(stderr, "buy_liquidity: amount %llu exceeds L-stock %llu (dust limit)\n",
                (unsigned long long)amount_sats, (unsigned long long)lstock);
        return 0;
    }

    /* Find which leaf_side this client's leaf is at.  We need this for
       lsp_realloc_leaf which takes leaf_side (index into
       f->leaf_node_indices[]), not raw node_idx. */
    int leaf_side = -1;
    for (int i = 0; i < f->n_leaf_nodes; i++) {
        if (f->leaf_node_indices[i] == node_idx) { leaf_side = i; break; }
    }
    if (leaf_side < 0) {
        fprintf(stderr, "buy_liquidity: node %zu not found in leaf_node_indices\n", node_idx);
        return 0;
    }

    /* Build new amounts: add to client's output, subtract from L-stock */
    uint64_t new_amounts[FACTORY_MAX_OUTPUTS];
    for (size_t k = 0; k < ln->n_outputs; k++)
        new_amounts[k] = ln->outputs[k].amount_sats;
    new_amounts[vout] += amount_sats;
    new_amounts[lstock_vout] -= amount_sats;

    /* Perform the reallocation (DW advance + MuSig2 re-sign) */
    if (!lsp_realloc_leaf(mgr, lsp, leaf_side, new_amounts, ln->n_outputs)) {
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
            /* SF-W-PTLC #171: inline PTLC snapshot for revocation registration.
               No-op today (n_ptlcs == 0 at all current callsites); defensive
               for when CLN-bLIP56 (#172) wires real PTLC flow through here. */
            size_t old_ch_n_ptlcs = ch->n_ptlcs;
            ptlc_t *old_ch_ptlcs = NULL;
            if (old_ch_n_ptlcs > 0) {
                old_ch_ptlcs = malloc(old_ch_n_ptlcs * sizeof(ptlc_t));
                if (old_ch_ptlcs)
                    memcpy(old_ch_ptlcs, ch->ptlcs,
                           old_ch_n_ptlcs * sizeof(ptlc_t));
            }
            watchtower_watch_revoked_commitment(mgr->watchtower, ch,
                (uint32_t)client_idx, old_cn,
                old_ch_local, old_ch_remote,
                old_ch_htlcs, old_ch_n_htlcs,
                /* SF-W-PTLC #171: thread PTLC snapshot */ old_ch_ptlcs, old_ch_n_ptlcs);
            free(old_ch_ptlcs);
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
                    /* SF-W-PTLC #171: inline PTLC snapshot for revocation registration.
                       No-op today (n_ptlcs == 0 at all current callsites); defensive
                       for when CLN-bLIP56 (#172) wires real PTLC flow through here. */
                    size_t old_sender_n_ptlcs = sender_ch->n_ptlcs;
                    ptlc_t *old_sender_ptlcs = NULL;
                    if (old_sender_n_ptlcs > 0) {
                        old_sender_ptlcs = malloc(old_sender_n_ptlcs * sizeof(ptlc_t));
                        if (old_sender_ptlcs)
                            memcpy(old_sender_ptlcs, sender_ch->ptlcs,
                                   old_sender_n_ptlcs * sizeof(ptlc_t));
                    }
                    watchtower_watch_revoked_commitment(mgr->watchtower, sender_ch,
                        (uint32_t)s, old_cn,
                        old_sender_local, old_sender_remote,
                        old_sender_htlcs, old_sender_n_htlcs,
                        /* SF-W-PTLC #171: thread PTLC snapshot */ old_sender_ptlcs, old_sender_n_ptlcs);
                    free(old_sender_ptlcs);
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

    /* Per-leaf advance: after payment settles, advance both affected leaves.
       Arity-1 (DW) and Arity-PS both use per-leaf 2-of-2 signing, so only
       the involved clients' leaves need to be re-signed, not the entire tree. */
    if (lsp->factory.leaf_arity == FACTORY_ARITY_1 ||
        lsp->factory.leaf_arity == FACTORY_ARITY_PS) {
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

    case MSG_LSTOCK_REVEAL_REQUEST: {
        /* #59 Phase 2c: a client recovering from a crash in the reveal window
           re-requests the L-stock secrets it never received.  Re-derive each from
           the seed and reply with MSG_LSTOCK_REVEAL.  SECURITY: only reveal states
           STRICTLY BEFORE the node's current L-stock counter — a superseded state.
           Never reveal the current/future state's secret, or the client could
           poison a legitimate (non-revoked) state of the LSP. */
        if (!lsp->factory.use_hashlock_poison) return 1;
        uint32_t req_n[128], req_s[128]; size_t req_cnt = 0;
        if (!wire_parse_lstock_reveal_request(msg->json, req_n, req_s, 128, &req_cnt))
            return 0;
        uint32_t out_n[128], out_s[128];
        unsigned char out_sec[128][32];
        size_t out_cnt = 0;
        for (size_t i = 0; i < req_cnt && out_cnt < 128; i++) {
            uint32_t nidx = req_n[i];
            if (nidx >= lsp->factory.n_nodes) continue;
            factory_node_t *nd = &lsp->factory.nodes[nidx];
            if (req_s[i] >= nd->l_stock_state_counter) continue;  /* not superseded -> refuse */
            if (factory_derive_l_stock_secret(&lsp->factory, nd, req_s[i],
                                              out_sec[out_cnt])) {
                out_n[out_cnt] = nidx;
                out_s[out_cnt] = req_s[i];
                out_cnt++;
            }
        }
        if (out_cnt > 0) {
            cJSON *rev = wire_build_lstock_reveal(out_n, out_s, out_sec, out_cnt);
            if (rev) {
                wire_send(lsp->client_fds[client_idx], MSG_LSTOCK_REVEAL, rev);
                cJSON_Delete(rev);
            }
            memset(out_sec, 0, sizeof(out_sec));
            printf("LSP: re-revealed %zu L-stock secret(s) to client %zu (crash recovery)\n",
                   out_cnt, client_idx);
        }
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

    /* === BOLT-2 SPLICE — STUB IMPLEMENTATION (#198 SF-SPLICE-FULL) ===
       The MSG_SPLICE_* handlers here are a wire-codec stub only:
         - LSP always responds with acceptor_contribution = 0 (never contributes).
         - LSP does NOT participate in building the splice TX (no interactive-tx
           messages: MSG_TX_ADD_INPUT/OUTPUT/COMPLETE/SIGNATURES are absent).
         - LSP does NOT sign the splice TX (no MuSig ceremony for splice).
         - SPLICE_LOCKED updates funding_txid/vout but keeps the OLD
           funding_amount.
       SuperScalar's own lifecycle doesn't need splice — internal rebalancing
       uses leaf realloc, sub-factory chain advance, DW rotation, JIT channels,
       and cooperative close.  These handlers exist for future BOLT-2 wire
       compatibility with external Lightning peers (e.g. CLN via #172
       CLN-bLIP56).  A real production splice between SuperScalar and an
       external LN peer requires the full implementation tracked in #198. */
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

    case MSG_FORCE_OUT: {
        /* SF-CRASH-INJECT-WIRE #245 Half B: install runtime crash target. */
        if (!getenv("SUPERSCALAR_CRASH_ALLOW")) {
            fprintf(stderr,
                "LSP: MSG_FORCE_OUT received but SUPERSCALAR_CRASH_ALLOW not set -- dropping\n");
            return 1;
        }
        char name[64] = {0};
        if (!wire_parse_force_out(msg->json, name)) {
            fprintf(stderr, "LSP: MSG_FORCE_OUT parse failed\n");
            return 1;
        }
        lsp_crash_set_target(name);
        fprintf(stderr,
            "LSP: MSG_FORCE_OUT runtime crash target installed: \"%s\"\n",
            name[0] ? name : "<immediate>");
        fflush(stderr);
        if (!name[0]) {
            /* Empty name = abort immediately at this call site. */
            lsp_crash_checkpoint("");
        }
        return 1;
    }

    case MSG_ROTATE: {
        /* SF-CRASH-INJECT-WIRE #245 Half B: trigger in-process rotation. */
        if (!getenv("SUPERSCALAR_CRASH_ALLOW")) {
            fprintf(stderr,
                "LSP: MSG_ROTATE received but SUPERSCALAR_CRASH_ALLOW not set -- dropping\n");
            return 1;
        }
        uint8_t mode = 0;
        wire_parse_rotate(msg->json, &mode);
        fprintf(stderr, "LSP: MSG_ROTATE triggering rotation (mode=%u)\n",
                (unsigned)mode);
        fflush(stderr);
        (void)lsp_channels_rotate_factory(mgr, lsp);
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
                    if (!channel_verify_revocation_secret(dest_ch, old_cn, rev_secret)) {
                        fprintf(stderr, "LSP: INVALID revocation secret from reconnected "
                                "client %zu (commitment %lu)\n",
                                reconnected_idx, (unsigned long)old_cn);
                        secure_zero(rev_secret, 32);
                        cJSON_Delete(ack_msg.json);
                        free(old_dest_htlcs);
                        continue;
                    }
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
                        (uint32_t)reconnected_idx, old_cn,
                        old_dest_local, old_dest_remote,
                        old_dest_htlcs, old_dest_n_htlcs,
                        /* SF-W-PTLC #171: thread PTLC snapshot */ old_dest_ptlcs, old_dest_n_ptlcs);
                    free(old_dest_ptlcs);
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

    /* Clients: rotation override SPK wins; otherwise per-client close_spk;
       otherwise fall back to factory funding SPK (legacy path). */
    const unsigned char *spk = close_spk ? close_spk : factory->funding_spk;
    size_t spk_len = close_spk ? close_spk_len : factory->funding_spk_len;

    /* LSP (output 0): rotation override wins (recycles funds into the new
       factory's SPK); otherwise use mgr->lsp_close_spk (P2TR of the LSP's own
       factory pubkey — LSP-alone spendable); otherwise fall back to factory
       funding SPK (legacy path kept for tests that don't populate
       lsp_close_spk). This keeps the LSP's recovered share unilaterally
       spendable by the LSP with its own seckey, instead of locking it back
       in the N-of-N funding MuSig. */
    const unsigned char *lsp_spk;
    size_t lsp_spk_len;
    if (close_spk) {
        lsp_spk = close_spk;
        lsp_spk_len = close_spk_len;
    } else if (mgr->lsp_close_spk_len > 0) {
        lsp_spk = mgr->lsp_close_spk;
        lsp_spk_len = mgr->lsp_close_spk_len;
    } else {
        lsp_spk = factory->funding_spk;
        lsp_spk_len = factory->funding_spk_len;
    }

    /* Output 0: LSP gets factory_funding - sum(client_remotes) - close_fee.
       In a cooperative close that bypasses the tree, the LSP recovers the
       tree transaction fees (funding_amount - sum_of_leaf_outputs). */
    uint64_t client_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++)
        client_total += mgr->entries[c].channel.remote_amount;

    if (factory->funding_amount_sats < client_total + close_fee) return 0;
    uint64_t lsp_total = factory->funding_amount_sats - client_total - close_fee;

    outputs[0].amount_sats = lsp_total;
    memcpy(outputs[0].script_pubkey, lsp_spk, lsp_spk_len);
    outputs[0].script_pubkey_len = lsp_spk_len;

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
        /* Per-channel settlement: each client gets their share of the fees
           earned on THEIR channel, not a share of the global pool. */
        uint64_t ch_fees = mgr->entries[i].accumulated_fees_sats;
        if (ch_fees == 0) continue;

        uint32_t pidx = (uint32_t)(i + 1);
        if (pidx >= factory->n_participants) continue;

        uint16_t bps = factory->profiles[pidx].profit_share_bps;
        if (bps == 0) continue;

        uint64_t share = (ch_fees * bps) / 10000;
        if (share == 0) continue;

        /* Shift balance from LSP-local to client-remote */
        channel_t *ch = &mgr->entries[i].channel;
        if (ch->local_amount >= share) {
            ch->local_amount -= share;
            ch->remote_amount += share;
            mgr->entries[i].accumulated_fees_sats = 0;
            settled++;
        }
    }

    if (settled > 0)
        mgr->accumulated_fees_sats = 0;

    return settled;
}

int lsp_channels_settle_via_payment(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      const factory_t *factory) {
    if (!mgr || !lsp || !factory) return 0;
    if (mgr->economic_mode != ECON_PROFIT_SHARED) return 0;
    if (mgr->accumulated_fees_sats == 0) return 0;

    extern void hex_encode(const unsigned char *, size_t, char *);

    int settled = 0;
    for (size_t i = 0; i < mgr->n_channels; i++) {
        uint64_t ch_fees = mgr->entries[i].accumulated_fees_sats;
        if (ch_fees == 0) continue;

        uint32_t pidx = (uint32_t)(i + 1);
        if (pidx >= factory->n_participants) continue;
        if (lsp->client_fds[i] < 0) continue;  /* client offline */

        uint16_t bps = factory->profiles[pidx].profit_share_bps;
        if (bps == 0) continue;

        uint64_t share = (ch_fees * bps) / 10000;
        if (share < CHANNEL_DUST_LIMIT_SATS) continue;  /* below dust */

        /* Cheat test: offer half the correct amount */
        if (mgr->test_bad_settlement && share > 1)
            share /= 2;

        channel_t *ch = &mgr->entries[i].channel;
        if (ch->local_amount < share) continue;  /* insufficient balance */

        /* Generate deterministic settlement preimage + hash */
        unsigned char preimage[32], payment_hash[32];
        {
            unsigned char seed[40];
            memcpy(seed, "settlement", 10);
            seed[10] = (unsigned char)(i & 0xFF);
            seed[11] = (unsigned char)((i >> 8) & 0xFF);
            /* Use commitment number as nonce to avoid reuse */
            uint64_t cn = ch->commitment_number;
            for (int b = 0; b < 8; b++) seed[12 + b] = (unsigned char)(cn >> (b * 8));
            memset(seed + 20, 0, 20);
            sha256(seed, 40, preimage);
            sha256(preimage, 32, payment_hash);
        }

        /* CLTV for settlement HTLC */
        uint32_t htlc_cltv = factory->cltv_timeout > FACTORY_CLTV_DELTA_DEFAULT
                            ? factory->cltv_timeout - FACTORY_CLTV_DELTA_DEFAULT
                            : 500;

        /* Add HTLC (OFFERED from LSP to client) */
        uint64_t htlc_id;
        if (!channel_add_htlc(ch, HTLC_OFFERED, share, payment_hash,
                               htlc_cltv, &htlc_id))
            continue;

        /* Send UPDATE_ADD_HTLC with settlement tag + preimage */
        cJSON *add = wire_build_update_add_htlc(htlc_id, share * 1000,
                                                  payment_hash, htlc_cltv);
        cJSON_AddBoolToObject(add, "is_settlement", 1);
        wire_json_add_hex(add, "settlement_preimage", preimage, 32);
        cJSON_AddNumberToObject(add, "accumulated_fees", (double)ch_fees);
        cJSON_AddNumberToObject(add, "share_bps", (double)bps);
        if (!wire_send(lsp->client_fds[i], MSG_UPDATE_ADD_HTLC, add)) {
            cJSON_Delete(add);
            /* Rollback: fail the HTLC we just added */
            channel_fail_htlc(ch, htlc_id);
            continue;
        }
        cJSON_Delete(add);

        /* Send COMMITMENT_SIGNED */
        unsigned char psig[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(ch, psig, &nonce_idx)) {
            channel_fail_htlc(ch, htlc_id);
            continue;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[i].channel_id, ch->commitment_number, psig, nonce_idx);
        if (!wire_send(lsp->client_fds[i], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            continue;
        }
        cJSON_Delete(cs);

        /* Wait for REVOKE_AND_ACK from client (5s timeout) */
        wire_msg_t ack;
        if (!wire_recv_timeout(lsp->client_fds[i], &ack, 5) ||
            ack.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack.json) cJSON_Delete(ack.json);
            continue;
        }
        /* Process revocation */
        {
            uint32_t ack_ch_id;
            unsigned char rev_secret[32], next_point[33];
            if (wire_parse_revoke_and_ack(ack.json, &ack_ch_id,
                                            rev_secret, next_point)) {
                uint64_t old_cn = ch->commitment_number - 1;
                channel_receive_revocation(ch, old_cn, rev_secret);
                secp256k1_pubkey next_pcp;
                if (secp256k1_ec_pubkey_parse(mgr->ctx, &next_pcp, next_point, 33))
                    channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);
            }
            cJSON_Delete(ack.json);
        }

        /* Send LSP's own revocation */
        {
            unsigned char lsp_rev[32];
            if (ch->commitment_number > 0)
                channel_get_revocation_secret(ch, ch->commitment_number - 1, lsp_rev);
            else
                memset(lsp_rev, 0, 32);
            secp256k1_pubkey lsp_next_pcp;
            channel_get_per_commitment_point(ch, ch->commitment_number + 1, &lsp_next_pcp);
            cJSON *rev = wire_build_revoke_and_ack(
                mgr->entries[i].channel_id, lsp_rev, mgr->ctx, &lsp_next_pcp);
            wire_send(lsp->client_fds[i], MSG_REVOKE_AND_ACK, rev);
            cJSON_Delete(rev);
            memset(lsp_rev, 0, 32);
        }

        /* The client will auto-fulfill this HTLC with the preimage we sent.
           Wait for FULFILL_HTLC + COMMITMENT_SIGNED from client. */
        wire_msg_t fulfill_msg;
        if (!wire_recv_timeout(lsp->client_fds[i], &fulfill_msg, 10) ||
            fulfill_msg.msg_type != MSG_UPDATE_FULFILL_HTLC) {
            if (fulfill_msg.json) cJSON_Delete(fulfill_msg.json);
            continue;
        }
        /* Process fulfill */
        {
            uint64_t ful_htlc_id;
            unsigned char ful_preimage[32];
            if (wire_parse_update_fulfill_htlc(fulfill_msg.json,
                                                &ful_htlc_id, ful_preimage))
                channel_fulfill_htlc(ch, ful_htlc_id, ful_preimage);
            cJSON_Delete(fulfill_msg.json);
        }

        /* Receive client's COMMITMENT_SIGNED for the fulfill */
        wire_msg_t client_cs;
        if (wire_recv_timeout(lsp->client_fds[i], &client_cs, 5) &&
            client_cs.msg_type == MSG_COMMITMENT_SIGNED) {
            unsigned char client_psig[32];
            uint32_t client_ni;
            uint64_t client_cn;
            if (wire_parse_commitment_signed(client_cs.json, NULL,
                                              &client_cn, client_psig, &client_ni)) {
                unsigned char full_sig[64];
                channel_verify_and_aggregate_commitment_sig(
                    ch, client_psig, client_ni, full_sig);
            }
            cJSON_Delete(client_cs.json);

            /* Send revocation for the fulfilled state */
            unsigned char lsp_rev2[32];
            if (ch->commitment_number > 0)
                channel_get_revocation_secret(ch, ch->commitment_number - 1, lsp_rev2);
            else
                memset(lsp_rev2, 0, 32);
            secp256k1_pubkey lsp_next2;
            channel_get_per_commitment_point(ch, ch->commitment_number + 1, &lsp_next2);
            cJSON *rev2 = wire_build_revoke_and_ack(
                mgr->entries[i].channel_id, lsp_rev2, mgr->ctx, &lsp_next2);
            wire_send(lsp->client_fds[i], MSG_REVOKE_AND_ACK, rev2);
            cJSON_Delete(rev2);
            memset(lsp_rev2, 0, 32);
        } else {
            if (client_cs.json) cJSON_Delete(client_cs.json);
        }

        mgr->entries[i].accumulated_fees_sats = 0;
        settled++;
        printf("LSP: settled %llu sats to client %zu (fees=%llu, bps=%u)\n",
               (unsigned long long)share, i,
               (unsigned long long)ch_fees, bps);
        memset(preimage, 0, 32);
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
    if (client_idx >= mgr->n_channels) return 0;

    uint64_t ch_fees = mgr->entries[client_idx].accumulated_fees_sats;
    if (ch_fees == 0) return 0;

    uint32_t pidx = (uint32_t)(client_idx + 1);
    if (pidx >= factory->n_participants) return 0;

    uint16_t bps = factory->profiles[pidx].profit_share_bps;
    return (ch_fees * bps) / 10000;
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
                /* Finding A: enforce bridge pubkey pin BEFORE freeing the JSON. */
                if (!lsp_validate_bridge_pin(lsp, qjson)) {
                    if (qjson) cJSON_Delete(qjson);
                    wire_close(qfd);
                    continue;
                }
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

                /* Profit settlement via chain_be (works without watchtower). */
                if (mgr->economic_mode == ECON_PROFIT_SHARED &&
                    mgr->accumulated_fees_sats > 0 &&
                    mgr->settlement_interval_blocks > 0 &&
                    mgr->chain_be) {
                    chain_backend_t *_scb = (chain_backend_t *)mgr->chain_be;
                    uint32_t sheight = _scb->get_block_height(_scb);
                    if (sheight > 0 &&
                        sheight - mgr->last_settlement_block >=
                            mgr->settlement_interval_blocks) {
                        int settled = lsp_channels_settle_via_payment(
                            mgr, lsp, &lsp->factory);
                        if (settled > 0) {
                            mgr->last_settlement_block = sheight;
                            if (mgr->persist)
                                persist_save_fee_settlement(
                                    (persist_t *)mgr->persist, 0,
                                    mgr->accumulated_fees_sats,
                                    mgr->last_settlement_block);
                            printf("LSP: settled profits to %d channels "
                                   "(height=%u)\n", settled, sheight);
                            fflush(stdout);
                        }
                    }
                }

                /* Check block height / factory lifecycle (fast: 1 RPC call).
                   watchtower_check is deferred to once per 60s (below). */
                if (mgr->watchtower && mgr->watchtower->rt) {
                    int height = regtest_get_block_height(mgr->watchtower->rt);
                /* Reorg detection (R1): catches three kinds of reorg the daemon
                   must react to.  Tracking just height — the prior implementation
                   — missed (2) and (3), which are the common cases when a
                   competing chain wins.
                     1. HEIGHT_REGRESSION: tip went backward.
                     2. SAME_HEIGHT:       tip stayed at last height but hash changed.
                     3. FORWARD_REORG:     tip advanced but the block we knew at
                                           last_height is no longer canonical —
                                           a fork beneath our last tip became active. */
                {
                    static int32_t daemon_last_height = 0;
                    static char    daemon_last_tip_hash[65] = {0};
                    char cur_tip_hash[65] = {0};
                    regtest_get_best_block_hash(mgr->watchtower->rt, cur_tip_hash);

                    int reorg_kind = 0;
                    const char *reorg_kind_str = "";
                    if (daemon_last_height > 0 && height > 0 &&
                        height < daemon_last_height) {
                        reorg_kind = 1;
                        reorg_kind_str = "HEIGHT_REGRESSION";
                    } else if (daemon_last_height > 0 && height == daemon_last_height &&
                               daemon_last_tip_hash[0] && cur_tip_hash[0] &&
                               strcmp(cur_tip_hash, daemon_last_tip_hash) != 0) {
                        reorg_kind = 2;
                        reorg_kind_str = "SAME_HEIGHT";
                    } else if (daemon_last_height > 0 && height > daemon_last_height &&
                               daemon_last_tip_hash[0]) {
                        char prev_hash_now[65] = {0};
                        if (regtest_get_block_hash(mgr->watchtower->rt,
                                                    daemon_last_height,
                                                    prev_hash_now,
                                                    sizeof(prev_hash_now)) &&
                            prev_hash_now[0] &&
                            strcmp(prev_hash_now, daemon_last_tip_hash) != 0) {
                            reorg_kind = 3;
                            reorg_kind_str = "FORWARD_REORG";
                        }
                    }

                    if (reorg_kind) {
                        int depth_proxy = (reorg_kind == 1)
                            ? (daemon_last_height - height) : 0;
                        fprintf(stderr, "LSP: REORG detected (%s) — "
                                "height %d → %d (depth %d) hash %.16s → %.16s\n",
                                reorg_kind_str, daemon_last_height, height,
                                depth_proxy,
                                daemon_last_tip_hash[0] ? daemon_last_tip_hash : "?",
                                cur_tip_hash[0] ? cur_tip_hash : "?");
                        /* CL6: persist reorg event for test evidence */
                        if (mgr->persist) {
                            char det[256];
                            snprintf(det, sizeof(det),
                                     "%s height_%d->%d hash_%.16s->%.16s",
                                     reorg_kind_str,
                                     daemon_last_height, height,
                                     daemon_last_tip_hash[0] ? daemon_last_tip_hash : "?",
                                     cur_tip_hash[0] ? cur_tip_hash : "?");
                            persist_log_broadcast((persist_t *)mgr->persist,
                                                   "", "reorg_detected",
                                                   det, "ok");
                        }
                        /* Re-validate watchtower entries */
                        watchtower_on_reorg(mgr->watchtower, height,
                                           daemon_last_height);
                        /* Drop in-memory sub-factory chain advance state.
                           A reorg of chain[N-1] would invalidate chain[N]'s
                           prev-output reference; resetting forces force-close
                           to fall back to chain[0] (v23/PR #144 path), which
                           spends the factory leaf output directly. DB rows
                           in ps_subfactory_chains are preserved for forensics. */
                        {
                            int n_sub_reset =
                                factory_reset_all_subfactory_chains(&lsp->factory);
                            if (n_sub_reset > 0)
                                fprintf(stderr,
                                    "LSP reorg: reset chain advance state for "
                                    "%d sub-factory(s); force-close falls back "
                                    "to chain[0]\n", n_sub_reset);
                        }
                        /* R5 (mainnet pre-flight): revalidate each factory
                           channel's funding UTXO.  Sets funding_pending_reorg
                           on channels whose funding TX is no longer on chain;
                           channel.c gates add_htlc/build_commitment behind
                           that flag so a reorged-out funding TX cannot ship
                           an HTLC that has no on-chain backing. */
                        int frz = lsp_channels_revalidate_funding(mgr, lsp);
                        if (frz)
                            fprintf(stderr, "LSP: reorg revalidate flipped "
                                    "funding_pending_reorg on %d channel(s)\n",
                                    frz);
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
                    if (cur_tip_hash[0]) memcpy(daemon_last_tip_hash, cur_tip_hash, 65);
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

                    /* Profit settlement: handled above via chain_be (works
                       without watchtower). Removed from watchtower block. */
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
                                                if (lsp->client_fds[ci] >= 0) {
                                                    readiness_set_connected(rt, (uint32_t)ci, 1);
                                                    /* A live client takes part in the rotation
                                                       ceremony over its open connection; the
                                                       QUEUE_DONE ack exists for clients that must
                                                       RECONNECT to learn about the rotation.
                                                       Counting online clients as ready makes the
                                                       fast path below real: an all-online fleet
                                                       fires immediately, a partial fleet waits
                                                       for reconnect acks. */
                                                    readiness_set_ready(rt, (uint32_t)ci,
                                                                        QUEUE_REQ_ROTATION);
                                                }
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
                                            /* Fast path: fire immediately if all already here.
                                               Record success when it fires — otherwise the
                                               retry machinery keeps ticking against the old
                                               factory id: spurious FAILED attempts ("no
                                               DYING/EXPIRED factory found") and, after
                                               max_retries of them, the distribution-TX
                                               fallback for a factory that already rotated. */
                                            if (lsp_check_rotation_readiness(mgr, lsp))
                                                lsp_rotation_record_success(mgr,
                                                                            lf->factory_id);
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
                                if (retry_act == 1 && mgr->readiness &&
                                    lf->cached_state == FACTORY_DYING) {
                                    /* Async mode, factory still DYING: the retry tick
                                       goes through the readiness gate instead of firing
                                       the synchronous ceremony directly — the direct
                                       call here used to bypass the gate entirely,
                                       rotating before absent clients had reconnected
                                       and acknowledged (the whole point of
                                       --async-rotation).  should_retry() has no side
                                       effects, so ungated ticks simply poll the gate.
                                       Once the factory reaches EXPIRED the branches
                                       below take over unchanged (partial rotation with
                                       n_ready >= 2, direct attempts, and finally the
                                       distribution-TX fallback) — waiting is only
                                       correct while there is still time to wait. */
                                    readiness_tracker_t *rrt =
                                        (readiness_tracker_t *)mgr->readiness;
                                    printf("LSP: rotation retry tick — async gate %zu/%zu "
                                           "ready for factory %u\n",
                                           readiness_count_ready(rrt), rrt->n_clients,
                                           lf->factory_id);
                                    fflush(stdout);
                                    if (lsp_check_rotation_readiness(mgr, lsp)) {
                                        time_t tnow = time(NULL);
                                        for (size_t rc = 0; rc < mgr->n_channels; rc++) {
                                            mgr->entries[rc].last_message_time = tnow;
                                            mgr->entries[rc].offline_detected = 0;
                                        }
                                        lsp_rotation_record_success(mgr, lf->factory_id);
                                    }
                                } else if (retry_act == 1) {
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
                                    /* #49/#51: notify all clients (best-effort) that
                                       the rotation ceremony is aborted (retry limit)
                                       and the LSP is proactively exiting via the
                                       distribution TX before the factory CLTV.  The
                                       clients' own persisted state + watchtower
                                       protect their funds; this lets them stop
                                       waiting and confirm their WT is live.  An
                                       offline client simply won't receive it. */
                                    {
                                        unsigned char _cer_id[8] = {0};
                                        _cer_id[0] = (unsigned char)(lf->factory_id & 0xff);
                                        _cer_id[1] = (unsigned char)((lf->factory_id >> 8) & 0xff);
                                        _cer_id[2] = (unsigned char)((lf->factory_id >> 16) & 0xff);
                                        _cer_id[3] = (unsigned char)((lf->factory_id >> 24) & 0xff);
                                        char _atext[200];
                                        snprintf(_atext, sizeof(_atext),
                                            "rotation retry limit (%u) reached at height %u; "
                                            "LSP broadcasting distribution TX (proactive exit) "
                                            "-- ensure your watchtower is live",
                                            mret, (unsigned)height);
                                        cJSON *_ab = wire_build_ceremony_abort(_cer_id,
                                            CEREMONY_ABORT_RETRY_LIMIT_REACHED, _atext);
                                        if (_ab) {
                                            for (size_t _aci = 0; _aci < lsp->n_clients; _aci++)
                                                wire_send(lsp->client_fds[_aci],
                                                          MSG_CEREMONY_ABORT, _ab);
                                            cJSON_Delete(_ab);
                                        }
                                    }
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
                        /* Reorg detection (R1): same three-kind scheme as the
                           main loop's check above — height-regress, same-height,
                           and forward-reorg.  Uses mgr->last_known_tip_hash to
                           catch the latter two (mainnet pre-flight). */
                        char hb_cur_hash[65] = {0};
                        regtest_get_best_block_hash(mgr->watchtower->rt, hb_cur_hash);

                        int hb_reorg_kind = 0;
                        const char *hb_reorg_str = "";
                        if (mgr->last_known_height > 0 && hb_height > 0 &&
                            hb_height < mgr->last_known_height) {
                            hb_reorg_kind = 1;
                            hb_reorg_str = "HEIGHT_REGRESSION";
                        } else if (mgr->last_known_height > 0 &&
                                   hb_height == mgr->last_known_height &&
                                   mgr->last_known_tip_hash[0] && hb_cur_hash[0] &&
                                   strcmp(hb_cur_hash, mgr->last_known_tip_hash) != 0) {
                            hb_reorg_kind = 2;
                            hb_reorg_str = "SAME_HEIGHT";
                        } else if (mgr->last_known_height > 0 &&
                                   hb_height > mgr->last_known_height &&
                                   mgr->last_known_tip_hash[0]) {
                            char hb_prev_now[65] = {0};
                            if (regtest_get_block_hash(mgr->watchtower->rt,
                                                        mgr->last_known_height,
                                                        hb_prev_now,
                                                        sizeof(hb_prev_now)) &&
                                hb_prev_now[0] &&
                                strcmp(hb_prev_now, mgr->last_known_tip_hash) != 0) {
                                hb_reorg_kind = 3;
                                hb_reorg_str = "FORWARD_REORG";
                            }
                        }

                        if (hb_reorg_kind) {
                            int depth_proxy = (hb_reorg_kind == 1)
                                ? (mgr->last_known_height - hb_height) : 0;
                            fprintf(stderr,
                                "ALERT: chain reorg detected (%s) tip %d → %d "
                                "(depth %d) hash %.16s → %.16s\n",
                                hb_reorg_str, mgr->last_known_height, hb_height,
                                depth_proxy,
                                mgr->last_known_tip_hash[0] ? mgr->last_known_tip_hash : "?",
                                hb_cur_hash[0] ? hb_cur_hash : "?");
                            /* CL6: persist reorg event for test evidence */
                            if (mgr->persist) {
                                char det[256];
                                snprintf(det, sizeof(det),
                                         "%s height_%d->%d hash_%.16s->%.16s",
                                         hb_reorg_str,
                                         mgr->last_known_height, hb_height,
                                         mgr->last_known_tip_hash[0] ? mgr->last_known_tip_hash : "?",
                                         hb_cur_hash[0] ? hb_cur_hash : "?");
                                persist_log_broadcast((persist_t *)mgr->persist,
                                                       "", "reorg_detected",
                                                       det, "ok");
                            }
                            /* Fire chain backend reorg callback if set */
                            chain_backend_t *cbe = (chain_backend_t *)mgr->chain_be;
                            if (cbe && cbe->reorg_cb)
                                cbe->reorg_cb(hb_height, mgr->last_known_height,
                                              cbe->reorg_cb_ctx);
                            /* R5: revalidate factory channels' funding UTXOs. */
                            int hb_frz = lsp_channels_revalidate_funding(mgr, lsp);
                            if (hb_frz)
                                fprintf(stderr, "LSP: heartbeat revalidate "
                                        "flipped funding_pending_reorg on %d "
                                        "channel(s)\n", hb_frz);
                        }
                        if (hb_height > mgr->last_known_height)
                            mgr->last_known_height = hb_height;
                        if (hb_cur_hash[0])
                            memcpy(mgr->last_known_tip_hash, hb_cur_hash, 65);
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
                    /* SF-WAL #157: passive checkpoint so the dashboard reader
                       sees committed writes within heartbeat granularity. */
                    if (mgr->persist)
                        persist_wal_checkpoint((persist_t *)mgr->persist);
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
                            /* Finding A: enforce bridge pubkey pin BEFORE freeing the JSON. */
                            if (!lsp_validate_bridge_pin(lsp, peek.json)) {
                                cJSON_Delete(peek.json);
                                wire_close(new_fd);
                                continue;
                            }
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
            /* 2048 is enough for any CLI command including a BOLT11
               invoice (typically 300-700 chars) passed to pay_external.
               Was 256, which silently truncated long invoices and caused
               the tail of the BOLT11 to be re-read as a bogus next
               command ('CLI: unknown command'). */
            char line[2048];
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

        /* Match lsp_channels_init: base commit_fee (154 vB × fee_rate)
           was deducted from usable balance at init time, so the invariant
           compares against (funding − base_commit_fee), not funding. See
           fee_for_commitment_tx(fe, 0) in src/fee.c and the symmetric fix
           in client_check_conservation (src/client.c). */
        uint64_t base_commit_fee =
            (ch->fee_rate_sat_per_kvb * 154 + 999) / 1000;
        uint64_t expected = ch->funding_amount > base_commit_fee
                            ? ch->funding_amount - base_commit_fee : 0;

        if (sum != expected) {
            fprintf(stderr, "CONSERVATION VIOLATION: channel %zu — "
                    "local=%llu remote=%llu htlc_sum=%llu total=%llu "
                    "expected=%llu funding=%llu base_commit_fee=%llu "
                    "(delta=%lld)\n",
                    c,
                    (unsigned long long)ch->local_amount,
                    (unsigned long long)ch->remote_amount,
                    (unsigned long long)(sum - ch->local_amount - ch->remote_amount),
                    (unsigned long long)sum,
                    (unsigned long long)expected,
                    (unsigned long long)ch->funding_amount,
                    (unsigned long long)base_commit_fee,
                    (long long)(sum - expected));
            ok = 0;
        }
    }

    return ok;
}


/* Public wrapper: advance one PS leaf via the production wire ceremony. */
int lsp_channels_advance_ps_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp, int leaf_side) {
    return lsp_advance_leaf(mgr, lsp, leaf_side);
}

/* Tick the factory's root counter forward (PS Tier B production trigger).
   For PS factories, leaf advances are chain extension and don't drive root
   state — root must be ticked by an external time/block source.  When the
   root counter rolls over, drives the Tier B ceremony to re-sign every
   non-PS-leaf node for the new epoch.

   Caller wires this into a block-driven polling loop (e.g., every
   step_blocks blocks, or based on observed block height progression).

   Returns:
     1 = ceremony completed (epoch advanced + non-PS-leaf nodes re-signed),
     0 = nothing to do (no rollover this tick),
    -1 = ceremony failed (caller may retry next tick). */
int lsp_factory_tick_root(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;
    factory_t *f = &lsp->factory;
    int rc = factory_tick_root(f);
    if (rc != -1) {
        return 0;
    }
    printf("LSP: root counter rolled over to epoch %u — running Tier B ceremony\n",
           f->counter.current_epoch);
    /* trigger_leaf = -1 signals to client_handle_state_advance that this is
       a root-driven rollover (no specific leaf was advanced). */
    int sa_rc = lsp_run_state_advance(mgr, lsp, -1);
    if (sa_rc) {
        printf("LSP: Tier B ceremony complete for epoch %u\n",
               f->counter.current_epoch);
        return 1;
    }
    fprintf(stderr, "LSP: Tier B ceremony failed for epoch %u\n",
            f->counter.current_epoch);
    return -1;
}

/* PR-B (v22): post-recovery watchtower rehydration.

   For every PS leaf with chain_len >= 2, look up chain[N-1].txid (the
   stale-state-to-watch-for) from the persist layer and re-register
   (chain[N-1].txid → response=chain[N], poison=poison[N]) with the
   watchtower.  Same for every PS sub-factory chain.

   We only register the LATEST advance (chain[N-1] → chain[N]) — not all
   prior advances.  The earlier stale entries from before the LSP restart
   were watched in the live LSP, but those watchtower entries were
   in-memory only (the watchtower never persisted WATCH_FACTORY_NODE /
   WATCH_SUBFACTORY_NODE entries — only WATCH_COMMITMENT does, in
   watchtower_init).  Recovering the full history would require either
   walking every chain entry and chaining responses, or migrating the
   watchtower to persist its watch table.  The latter is a separate
   concern; the former leaves us with M-watch-entries-per-chain
   redundancy.  For PR-B's scope we restore the just-stale entry's
   coverage, which is the most-likely cheat target (a malicious LSP
   broadcasting the immediately-superseded chain state). */
int lsp_channels_rehydrate_watchtower_from_chains(lsp_channel_mgr_t *mgr) {
    if (!mgr || !mgr->watchtower || !mgr->persist) return 0;

    factory_t *f = NULL;
    /* mgr->ladder may not be set in unit-test contexts; fall through to
       the ladder factory[0] only when present.  The recovery branch
       in superscalar_lsp.c sets mgr->ladder = &rec_lad after this
       helper would be called, so we instead key off the lsp_t * the
       caller passes in via mgr->ladder once it's set.  In practice the
       recovery code calls this BEFORE mgr->ladder = &rec_lad, when the
       in-memory factory still lives at lsp_rp->factory — accessible via
       mgr->factory_for_recovery if set, else not callable.

       Simpler: take the factory pointer from mgr->ladder if available,
       otherwise expect the caller to have set mgr->factory_for_recovery
       to lsp_rp->factory before calling.  For now we use ladder. */
    if (mgr->ladder) {
        ladder_t *lad = (ladder_t *)mgr->ladder;
        if (lad->n_factories > 0) f = &lad->factories[0].factory;
    }
    if (!f) {
        fprintf(stderr, "rehydrate_watchtower: no factory available\n");
        return 0;
    }

    persist_t *pdb = (persist_t *)mgr->persist;
    int n_registered = 0;

    /* Walk every PS leaf node.  For each that has chain_len >= 2,
       look up the previous chain entry's txid as the "old" state. */
    for (int li = 0; li < f->n_leaf_nodes; li++) {
        size_t node_idx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[node_idx];
        if (!leaf->is_ps_leaf) continue;
        if (leaf->ps_chain_len < 2) continue;
        if (!leaf->is_signed || leaf->signed_tx.len == 0) continue;

        /* leaf->ps_prev_txid is set by persist_load_factory to the
           previous chain entry's txid (internal byte order) — exactly
           what watchtower wants for old_txid32. */

        /* Collect channel ids on this leaf. */
        uint32_t leaf_ch_ids[FACTORY_MAX_SIGNERS];
        size_t n_leaf_ch = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            size_t c_node; uint32_t c_vout;
            client_to_leaf(c, f, &c_node, &c_vout);
            if (c_node == node_idx)
                leaf_ch_ids[n_leaf_ch++] = (uint32_t)c;
        }

        const unsigned char *poison_data = NULL;
        size_t poison_len = 0;
        if (leaf->poison_is_signed && leaf->poison_signed_tx.len > 0) {
            poison_data = leaf->poison_signed_tx.data;
            poison_len  = leaf->poison_signed_tx.len;
        }

        watchtower_watch_factory_node_with_channels(mgr->watchtower,
            (uint32_t)node_idx, leaf->ps_prev_txid,
            leaf->signed_tx.data, leaf->signed_tx.len,
            poison_data, poison_len,
            leaf_ch_ids, n_leaf_ch);
        n_registered++;
        printf("LSP recovery: re-watched PS leaf %d (node %zu) "
               "chain_pos=%d (poison_tx=%s, %zu channels)\n",
               li, node_idx, leaf->ps_chain_len - 1,
               poison_data ? "yes" : "no", n_leaf_ch);

        /* SF-WT-TRUSTLESS Phase 1b.5c (#248): intentionally NO parallel
         * wt_db register here.  wt_db is a durable on-disk store — its
         * rows survive process restart, so there's nothing to
         * "re-register" the way the in-memory watchtower needs.  If a
         * future deployment needs to rebuild wt_db from lsp.db (e.g.
         * wt_db file lost/corrupt), a separate one-shot migration tool
         * `persist_v36_derive_wt_from_lsp(lsp_db, wt_db)` (see
         * docs/watchtower-trustless-schema.md §Migration) handles that
         * — not the restart path. */

        (void)pdb; /* persist_load_subfactory_chain uses sales-stock /
                      channel amounts directly from the in-memory
                      sub-factory state (already restored by
                      persist_load_factory) — no extra DB round-trip. */
    }

    /* Walk every sub-factory.  Same shape: chain_len >= 2 → register
       (sub->ps_prev_txid → response=sub->signed_tx, poison=sub->poison_signed_tx). */
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *sub = &f->nodes[i];
        if (sub->type != NODE_PS_SUBFACTORY) continue;
        if (sub->ps_chain_len < 2) continue;
        if (!sub->is_signed || sub->signed_tx.len == 0) continue;

        size_t sstock_vout = (sub->n_outputs > 0) ? sub->n_outputs - 1 : 0;
        uint64_t sstock_amount = sub->outputs[sstock_vout].amount_sats;
        uint64_t chan_amounts[16] = {0};
        size_t n_chans = sstock_vout;
        if (n_chans > 16) n_chans = 16;
        for (size_t ci = 0; ci < n_chans; ci++)
            chan_amounts[ci] = sub->outputs[ci].amount_sats;

        const unsigned char *poison_data = NULL;
        size_t poison_len = 0;
        if (sub->poison_is_signed && sub->poison_signed_tx.len > 0) {
            poison_data = sub->poison_signed_tx.data;
            poison_len  = sub->poison_signed_tx.len;
        }

        watchtower_watch_subfactory_node(mgr->watchtower,
            (uint32_t)i, sub->ps_prev_txid,
            sub->signed_tx.data, sub->signed_tx.len,
            poison_data, poison_len,
            chan_amounts, n_chans, sstock_amount);
        n_registered++;
        printf("LSP recovery: re-watched sub-factory node %zu "
               "chain_pos=%d (poison_tx=%s, %zu channels, sstock=%llu)\n",
               i, sub->ps_chain_len - 1,
               poison_data ? "yes" : "no", n_chans,
               (unsigned long long)sstock_amount);
    }

    if (n_registered > 0)
        printf("LSP recovery: rehydrated %d watchtower entries from "
               "persisted PS chains\n", n_registered);
    return 1;
}
