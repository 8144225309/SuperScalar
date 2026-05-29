#include "superscalar/lsp.h"
#include "superscalar/ceremony.h"
#include "superscalar/lsps.h"
#include "superscalar/persist.h"
#include "superscalar/sha256.h"
#include "superscalar/crash_inject.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* === Task #205: ceremony persistence helpers =============================== *
 *
 * Wire the SF-CEREMONY-HELPERS API (PR #259) into the factory_init propose
 * path so crashes leave a forensic trail (one ceremony row + N participant
 * rows per attempt). Persist is observability, not gating — every helper
 * failure is logged but never aborts the ceremony.  The crash-recovery
 * scaffold (tools/test_regtest_crash_at_every_phase.sh, PR #262) drives the
 * test that asserts these rows exist post-SIGKILL.
 *
 * Ceremony-id derivation: sha256(factory_instance_id || ceremony_type ||
 * be64(epoch))[:8].  Deterministic so retries of the same epoch boundary
 * map to the same row (idempotent re-PROPOSE after partial failure does not
 * produce duplicate ceremony rows). The factory_instance_id is the 32-byte
 * funding TXID (internal byte order) — the only stable 32-byte identifier
 * available at initial creation, agreed with wallet team §3 (the
 * autoincrement factory_id is not stable across LSP restarts before
 * persist_save_factory completes).
 * =========================================================================== */

void lsp_ceremony_derive_id(const unsigned char *fid32,
                              uint8_t ceremony_type,
                              uint64_t epoch,
                              unsigned char out_cid8[8]) {
    unsigned char buf[32 + 1 + 8];
    memcpy(buf, fid32, 32);
    buf[32] = ceremony_type;
    /* big-endian epoch so the hash domain matches wire/RPC representations */
    for (int i = 0; i < 8; i++)
        buf[33 + i] = (unsigned char)((epoch >> (56 - 8 * i)) & 0xff);
    unsigned char digest[32];
    sha256(buf, sizeof(buf), digest);
    memcpy(out_cid8, digest, 8);
}

void lsp_ceremony_get_client_pubkey33(const lsp_t *lsp, size_t client_idx,
                                       unsigned char out33[33]) {
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(lsp->ctx, out33, &len,
                                   &lsp->client_pubkeys[client_idx],
                                   SECP256K1_EC_COMPRESSED);
}

/* Log MSG_ERROR from a client during ceremony. Returns 1 if msg was error. */
static int check_client_error(const wire_msg_t *msg, size_t client_idx) {
    if (msg->msg_type == MSG_ERROR) {
        cJSON *m = msg->json ? cJSON_GetObjectItem(msg->json, "message") : NULL;
        fprintf(stderr, "LSP: client %zu sent error: %s\n",
                client_idx,
                (m && cJSON_IsString(m)) ? m->valuestring : "(unknown)");
        return 1;
    }
    return 0;
}

int lsp_init(lsp_t *lsp, secp256k1_context *ctx,
             const secp256k1_keypair *keypair, int port,
             size_t expected_clients) {
    memset(lsp, 0, sizeof(*lsp));
    lsp->ctx = ctx;
    lsp->lsp_keypair = *keypair;
    if (!secp256k1_keypair_pub(ctx, &lsp->lsp_pubkey, keypair))
        return 0;
    lsp->port = port;
    lsp->expected_clients = expected_clients;

    size_t cap = expected_clients < LSP_MAX_CLIENTS ? LSP_MAX_CLIENTS : expected_clients;
    lsp->client_fds = malloc(cap * sizeof(int));
    lsp->client_pubkeys = calloc(cap, sizeof(secp256k1_pubkey));
    if (!lsp->client_fds || !lsp->client_pubkeys) {
        free(lsp->client_fds); free(lsp->client_pubkeys);
        memset(lsp, 0, sizeof(*lsp));
        return 0;
    }
    lsp->clients_cap = cap;
    lsp->max_connections = (int)cap;
    lsp->listen_fd = -1;
    lsp->bridge_fd = -1;

    for (size_t i = 0; i < cap; i++)
        lsp->client_fds[i] = -1;

    /* Initialize rate limiter with defaults (10/min, 4 concurrent handshakes) */
    rate_limiter_init(&lsp->rate_limiter, 10, 60, 4);
    return 1;
}

int lsp_accept_clients(lsp_t *lsp) {
    if ((int)lsp->expected_clients > lsp->max_connections) {
        fprintf(stderr, "ERROR: --clients %d exceeds --max-connections %d\n",
                (int)lsp->expected_clients, lsp->max_connections);
        return 0;
    }

    if (lsp->listen_fd < 0) {
        lsp->listen_fd = wire_listen(NULL, lsp->port);
        if (lsp->listen_fd < 0) {
            fprintf(stderr, "LSP: listen failed on port %d\n", lsp->port);
            return 0;
        }
    }

    lsp->n_clients = 0;
    int hello_slot_hints[FACTORY_MAX_SIGNERS];
    for (size_t k = 0; k < FACTORY_MAX_SIGNERS; k++) hello_slot_hints[k] = 0;

    for (size_t i = 0; i < lsp->expected_clients; i++) {
        /* Timeout: wait for incoming connection with select() */
        if (lsp->accept_timeout_sec > 0) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(lsp->listen_fd, &rfds);
            struct timeval tv;
            tv.tv_sec = lsp->accept_timeout_sec;
            tv.tv_usec = 0;
            int sel = select(lsp->listen_fd + 1, &rfds, NULL, NULL, &tv);
            if (sel <= 0) {
                fprintf(stderr, "LSP: accept timeout waiting for client %zu (%ds)\n",
                        i, lsp->accept_timeout_sec);
                goto accept_fail;
            }
        }

        int fd = wire_accept(lsp->listen_fd);
        if (fd < 0) {
            fprintf(stderr, "LSP: accept failed for client %zu\n", i);
            goto accept_fail;
        }

        /* Rate limiting: check per-IP connection rate */
        {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            char ip_str[INET_ADDRSTRLEN] = "unknown";
            if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) == 0)
                inet_ntop(AF_INET, &peer.sin_addr, ip_str, sizeof(ip_str));

            if (!rate_limiter_allow(&lsp->rate_limiter, ip_str)) {
                fprintf(stderr, "LSP: rate limited connection from %s\n", ip_str);
                wire_close(fd);
                i--;  /* retry this slot */
                continue;
            }
        }

        /* Handshake cap check */
        if (!rate_limiter_handshake_start(&lsp->rate_limiter)) {
            fprintf(stderr, "LSP: too many concurrent handshakes, rejecting\n");
            wire_close(fd);
            i--;  /* retry this slot */
            continue;
        }

        /* Encrypted transport handshake (NK if configured, NN fallback) */
        int hs_ok;
        if (lsp->use_nk)
            hs_ok = wire_noise_handshake_nk_responder(fd, lsp->ctx, lsp->nk_seckey);
        else
            hs_ok = wire_noise_handshake_responder(fd, lsp->ctx);
        if (!hs_ok) {
            fprintf(stderr, "LSP: noise handshake failed for client %zu -- dropping, retrying slot\n", i);
            rate_limiter_handshake_end(&lsp->rate_limiter);
            wire_close(fd);
            i--; continue;
        }
        rate_limiter_handshake_end(&lsp->rate_limiter);

        /* Receive HELLO */
        wire_msg_t msg;
        if (!wire_recv(fd, &msg) || msg.msg_type != MSG_HELLO) {
            fprintf(stderr, "LSP: expected HELLO from client %zu -- dropping, retrying slot\n", i);
            wire_close(fd);
            if (msg.json) cJSON_Delete(msg.json);
            i--; continue;
        }

        /* Parse client pubkey */
        cJSON *pk_item = cJSON_GetObjectItem(msg.json, "pubkey");
        if (!pk_item || !cJSON_IsString(pk_item)) {
            fprintf(stderr, "LSP: bad pubkey in HELLO from client %zu -- dropping, retrying slot\n", i);
            cJSON_Delete(msg.json);
            wire_close(fd);
            i--; continue;
        }

        unsigned char pk_buf[33];
        if (hex_decode(pk_item->valuestring, pk_buf, 33) != 33 ||
            !secp256k1_ec_pubkey_parse(lsp->ctx, &lsp->client_pubkeys[i], pk_buf, 33)) {
            fprintf(stderr, "LSP: invalid pubkey from client %zu -- dropping, retrying slot\n", i);
            cJSON_Delete(msg.json);
            wire_close(fd);
            i--; continue;
        }

        /* Optional slot_hint for deterministic keyagg ordering */
        cJSON *sh_item = cJSON_GetObjectItem(msg.json, "slot_hint");
        if (sh_item && cJSON_IsNumber(sh_item))
            hello_slot_hints[i] = (int)sh_item->valuedouble;

        cJSON_Delete(msg.json);

        lsp->client_fds[i] = fd;
        lsp->n_clients = i + 1;
    }

    /* If every client sent a valid slot_hint forming a permutation of
       1..n_clients, reorder client_pubkeys/client_fds to match. This makes
       the funding-address keyagg deterministic across restarts.

       If require_slot_hints is set (production deployments), refuse to
       proceed without a valid permutation — operator forgot to pass
       --participant-id to clients. This avoids the silent fund-loss
       Campaign #3 hit: connect-order-dependent funding addresses get
       stranded on every restart. */
    {
        int all_hinted = 1;
        int seen[FACTORY_MAX_SIGNERS] = {0};
        for (size_t i = 0; i < lsp->n_clients; i++) {
            int s = hello_slot_hints[i];
            if (s < 1 || (size_t)s > lsp->n_clients || seen[s]) { all_hinted = 0; break; }
            seen[s] = 1;
        }
        if (lsp->require_slot_hints && !all_hinted) {
            fprintf(stderr, "LSP: ERROR — require_slot_hints is set but not all "
                    "clients supplied a valid slot_hint forming a permutation "
                    "of 1..%zu. Funding-address derivation would be "
                    "non-deterministic across restarts (fund-loss risk). "
                    "Each client must launch with --participant-id N "
                    "(unique value 1..%zu).\n",
                    lsp->n_clients, lsp->n_clients);
            goto accept_fail;
        }
        if (all_hinted && lsp->n_clients > 0) {
            for (size_t target = 0; target < lsp->n_clients; target++) {
                if ((size_t)hello_slot_hints[target] - 1 == target) continue;
                for (size_t j = target + 1; j < lsp->n_clients; j++) {
                    if ((size_t)hello_slot_hints[j] - 1 == target) {
                        secp256k1_pubkey tpk = lsp->client_pubkeys[target];
                        int tfd = lsp->client_fds[target];
                        int th = hello_slot_hints[target];
                        lsp->client_pubkeys[target] = lsp->client_pubkeys[j];
                        lsp->client_fds[target] = lsp->client_fds[j];
                        hello_slot_hints[target] = hello_slot_hints[j];
                        lsp->client_pubkeys[j] = tpk;
                        lsp->client_fds[j] = tfd;
                        hello_slot_hints[j] = th;
                        break;
                    }
                }
            }
            fprintf(stderr, "LSP: deterministic ordering applied via slot_hints\n");
        }
    }

    /* Build all_pubkeys array: [LSP, client0, client1, ...] */
    size_t n_total = 1 + lsp->n_clients;
    secp256k1_pubkey all_pubkeys[FACTORY_MAX_SIGNERS];
    all_pubkeys[0] = lsp->lsp_pubkey;
    for (size_t i = 0; i < lsp->n_clients; i++)
        all_pubkeys[i + 1] = lsp->client_pubkeys[i];

    /* Send HELLO_ACK to each client */
    for (size_t i = 0; i < lsp->n_clients; i++) {
        uint32_t participant_index = (uint32_t)(i + 1);  /* 0=LSP */
        cJSON *ack = wire_build_hello_ack(lsp->ctx, &lsp->lsp_pubkey,
                                          participant_index, all_pubkeys, n_total);
        if (!wire_send(lsp->client_fds[i], MSG_HELLO_ACK, ack)) {
            fprintf(stderr, "LSP: failed to send HELLO_ACK to client %zu\n", i);
            cJSON_Delete(ack);
            return 0;
        }
        cJSON_Delete(ack);
    }

    return 1;

accept_fail:
    for (size_t j = 0; j < lsp->n_clients; j++) {
        if (lsp->client_fds[j] >= 0) {
            wire_close(lsp->client_fds[j]);
            lsp->client_fds[j] = -1;
        }
    }
    lsp->n_clients = 0;
    return 0;
}

/* Phase 1e.3.b scaffolding: stub for the reversed-flow stateless factory
   creation ceremony.  Currently returns -1 for all cases (caller falls
   through to legacy lsp_run_factory_creation).  Phase 1e.3.c will fill in
   the actual multi-node MuSig ceremony using the wire codec from Phase
   1e.3.a.

   Wire flow (per Phase 1e.3.a opcodes 0x85-0x88):
     LSP   -> Client: MSG_FACTORY_PROPOSE_INTENT (no nonces)
     Client -> LSP:   MSG_FACTORY_CLIENT_PUBNONCES (per-node pubnonces)
     LSP atomic:      gen lsp_secnonces + set + finalize + create_partial_sigs
                       (lsp_secnonces zeroed by musig_create_partial_sig)
     LSP   -> Client: MSG_FACTORY_LSP_RESPONSE (per-node lsp pubnonces + psigs)
     Client -> LSP:   MSG_FACTORY_CLIENT_FINAL_PSIGS (per-node client psigs)
     LSP:             aggregate per node + send MSG_FACTORY_READY (existing terminal)

   Returns 1 on success, 0 on failure, -1 if stateless can't handle (caller
   falls through to legacy). */
/* Phase 1e.3.c (#271): stateless reversed-flow factory creation ceremony.

   Signs every node in f->nodes[0..n_nodes) (root N-of-N, intermediates,
   2-of-2 / k+1 leaves), each with its own signer set + session.  The LSP
   NEVER holds a secret nonce across a network wait: per node it generates
   its secnonce ONLY after receiving every client's per-node pubnonce, and
   musig_create_partial_sig zeroes that secnonce before the next wire_recv.

   Setup (tree build / send FACTORY_PROPOSE / sessions_init) and completion
   (sessions_complete / FACTORY_READY) mirror legacy lsp_run_factory_creation
   so the post-signing behaviour is identical.  Only the middle nonce/psig
   EXCHANGE is reversed.

   Wire flow (opcodes 0x85-0x88):
     LSP    -> Client:  MSG_FACTORY_PROPOSE        (tree shape; clients build)
     LSP    -> Client:  MSG_FACTORY_PROPOSE_INTENT (n_nodes; begin reversed)
     Client -> LSP:     MSG_FACTORY_CLIENT_PUBNONCES   (per-node pubnonces)
     LSP atomic:        per node { gen lsp secnonce; set ALL signers' nonces;
                          finalize_node; create lsp psig (zeroes secnonce);
                          set lsp psig }
     LSP    -> Client:  MSG_FACTORY_LSP_RESPONSE   (per-node lsp pn+psig +
                          full signer x node nonce matrix)
     Client -> LSP:     MSG_FACTORY_CLIENT_FINAL_PSIGS (per-node client psigs)
     LSP:               complete every node + FACTORY_READY

   Returns 1 on success, 0 on failure, -1 to decline (caller falls back to
   legacy). */
int lsp_run_factory_creation_stateless(lsp_t *lsp,
        const unsigned char *funding_txid, uint32_t funding_vout,
        uint64_t funding_amount,
        const unsigned char *funding_spk, size_t funding_spk_len,
        uint16_t step_blocks, uint32_t states_per_layer,
        uint32_t cltv_timeout) {
    if (!lsp) return -1;
    factory_t *f = &lsp->factory;

    /* SF-CEREMONY-HELPERS #199 / wallet-team v34 API: journal this
       stateless factory creation in the ceremonies table.  Mirrors the
       legacy lsp_run_factory_creation minimum (ceremony_id derivation
       + persist_save_ceremony at entry; participant_phase(SIGNED) per
       client + state transition to FINALIZED at the success return).
       cer_persisted gate so failure-to-persist is non-fatal (continues
       the ceremony, just no journal). */
    unsigned char cer_id[8] = {0};
    int cer_persisted = 0;
    if (lsp->db) {
        lsp_ceremony_derive_id(funding_txid,
                                PERSIST_CEREMONY_TYPE_INITIAL,
                                (uint64_t)lsp->factory.counter.current_epoch,
                                cer_id);
        if (!persist_save_ceremony(lsp->db, cer_id, funding_txid,
                                    PERSIST_CEREMONY_TYPE_INITIAL,
                                    /*parent_ceremony_id8_or_null*/ NULL,
                                    /*started_at_block*/ 0,
                                    /*deadline_block*/ cltv_timeout)) {
            fprintf(stderr, "LSP-stateless: persist_save_ceremony failed (continuing)\n");
        } else {
            cer_persisted = 1;
        }
    }

    /* ---- Setup: identical to legacy lsp_run_factory_creation ---- */
    size_t n_total = 1 + lsp->n_clients;
    secp256k1_pubkey all_pubkeys[FACTORY_MAX_SIGNERS];
    all_pubkeys[0] = lsp->lsp_pubkey;
    for (size_t i = 0; i < lsp->n_clients; i++)
        all_pubkeys[i + 1] = lsp->client_pubkeys[i];

    factory_arity_t saved_arity = f->leaf_arity;
    size_t saved_n_level_arity = f->n_level_arity;
    uint8_t saved_level_arity[FACTORY_MAX_LEVELS];
    if (saved_n_level_arity > 0)
        memcpy(saved_level_arity, f->level_arity,
               saved_n_level_arity * sizeof(uint8_t));
    uint32_t saved_static_threshold = f->static_threshold_depth;
    uint32_t saved_ps_subfactory_arity = f->ps_subfactory_arity;
    uint64_t saved_fee_per_tx = f->fee_per_tx;
    placement_mode_t saved_placement = f->placement_mode;
    economic_mode_t saved_econ = f->economic_mode;
    participant_profile_t saved_profiles[FACTORY_MAX_SIGNERS];
    memcpy(saved_profiles, f->profiles, sizeof(saved_profiles));
    int saved_has_shachain = f->has_shachain;
    int saved_use_flat = f->use_flat_secrets;
    size_t saved_n_secrets = f->n_revocation_secrets;
    unsigned char (*saved_secrets)[32] = (unsigned char (*)[32])calloc(FACTORY_MAX_EPOCHS, 32);
    unsigned char saved_shachain_seed[32];
    if (saved_use_flat && saved_secrets)
        memcpy(saved_secrets, f->revocation_secrets, saved_n_secrets * 32);
    else if (!saved_use_flat)
        memcpy(saved_shachain_seed, f->shachain_seed, 32);
    factory_init_from_pubkeys(f, lsp->ctx, all_pubkeys, n_total,
                              step_blocks, states_per_layer);
    if (saved_n_level_arity > 0) {
        factory_set_level_arity(f, saved_level_arity, saved_n_level_arity);
    } else if (saved_arity == FACTORY_ARITY_1) {
        factory_set_arity(f, FACTORY_ARITY_1);
    } else if (saved_arity == FACTORY_ARITY_PS) {
        factory_set_arity(f, FACTORY_ARITY_PS);
    }
    if (saved_static_threshold > 0)
        factory_set_static_near_root(f, saved_static_threshold);
    if (saved_ps_subfactory_arity > 1)
        factory_set_ps_subfactory_arity(f, saved_ps_subfactory_arity);
    if (saved_fee_per_tx > 200)
        f->fee_per_tx = saved_fee_per_tx;
    f->cltv_timeout = cltv_timeout;
    f->placement_mode = saved_placement;
    f->economic_mode = saved_econ;
    memcpy(f->profiles, saved_profiles, sizeof(saved_profiles));
    if (saved_has_shachain) {
        if (saved_use_flat && saved_secrets)
            factory_set_flat_secrets(f, saved_secrets, saved_n_secrets);
        else if (!saved_use_flat)
            factory_set_shachain_seed(f, saved_shachain_seed);
    }
    free(saved_secrets);
    factory_set_funding(f, funding_txid, funding_vout, funding_amount,
                        funding_spk, funding_spk_len);

    if (!factory_build_tree(f)) {
        fprintf(stderr, "LSP-stateless factory creation: factory_build_tree failed\n");
        return 0;
    }

    /* Send FACTORY_PROPOSE to all clients (tree shape) */
    cJSON *propose = wire_build_factory_propose(f);
    if (lsp->dist_client_amounts && lsp->dist_n_client_amounts > 0) {
        cJSON *da = cJSON_CreateArray();
        for (size_t i = 0; i < lsp->dist_n_client_amounts; i++)
            cJSON_AddItemToArray(da, cJSON_CreateNumber((double)lsp->dist_client_amounts[i]));
        cJSON_AddItemToObject(propose, "dist_amounts", da);
    }
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (!wire_send(lsp->client_fds[i], MSG_FACTORY_PROPOSE, propose)) {
            fprintf(stderr, "LSP-stateless: send FACTORY_PROPOSE to client %zu failed\n", i);
            cJSON_Delete(propose);
            return 0;
        }
    }
    /* SF-CRASH-INJECT-WIRE #245 Half A: mark all clients SENT at the PROPOSE
       send-point so a crash here leaves the participant rows visible. */
    if (cer_persisted) {
        for (size_t i = 0; i < lsp->n_clients; i++) {
            unsigned char pk33[33];
            lsp_ceremony_get_client_pubkey33(lsp, i, pk33);
            (void)persist_save_participant_phase(lsp->db, cer_id, pk33,
                PERSIST_CEREMONY_PHASE_SENT, NULL, NULL, 0, 0);
        }
    }
    printf("LSP: FACTORY_PROPOSE sent to %zu clients\n", lsp->n_clients);
    fflush(stdout);
    cJSON_Delete(propose);

    if (!factory_sessions_init(f)) {
        fprintf(stderr, "LSP-stateless: factory_sessions_init failed\n");
        return 0;
    }

    /* Build unsigned distribution TX so the unsigned dist TX is attached to f
       (legacy rotation re-signs it later).  Stateless MVP does NOT co-sign the
       dist TX during creation -- matches the validated sub-factory / state-
       advance stateless ceremonies which carry no dist TX.  FACTORY_READY
       therefore omits distribution_tx_hex. */
    {
        tx_output_t dist_outputs[FACTORY_MAX_SIGNERS + 1];
        size_t n_dist = factory_compute_distribution_outputs_balanced(f,
            dist_outputs, FACTORY_MAX_SIGNERS + 1, 500,
            lsp->dist_client_amounts, lsp->dist_n_client_amounts);
        if (n_dist > 0 && f->cltv_timeout > 0)
            (void)factory_build_distribution_tx_unsigned(
                f, dist_outputs, n_dist, f->cltv_timeout);
    }

    /* ---- Reversed stateless signing exchange ---- */

    /* Step A: PROPOSE_INTENT(n_nodes) to all clients (begin reversed flow). */
    {
        cJSON *intent = wire_build_factory_propose_intent((uint32_t)f->n_nodes);
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_FACTORY_PROPOSE_INTENT, intent)) {
                fprintf(stderr, "LSP-stateless: send PROPOSE_INTENT to client %zu failed\n", i);
                cJSON_Delete(intent);
                goto fail_pre;
            }
        }
        cJSON_Delete(intent);
    }

    /* all_pn[(node_idx * FACTORY_MAX_SIGNERS + signer_slot) * 66] -- full
       signer x node nonce matrix.  Filled from client pubnonces (Step B) and
       LSP pubnonces (Step C), forwarded to clients in LSP_RESPONSE so each
       client can set every co-signer's per-node nonce and finalize. */
    size_t mtx_stride = (size_t)FACTORY_MAX_SIGNERS * 66;
    unsigned char *all_pn = calloc(f->n_nodes, mtx_stride);
    if (!all_pn) goto fail_pre;

    /* Step B: collect each client's per-node pubnonces (only for nodes the
       client signs; other node slots stay zero in that client's array). */
    for (size_t c = 0; c < lsp->n_clients; c++) {
        uint32_t my_part = (uint32_t)(c + 1);
        wire_msg_t nmsg;
        if (!wire_recv_skip_ping(lsp->client_fds[c], &nmsg) ||
            nmsg.msg_type != MSG_FACTORY_CLIENT_PUBNONCES) {
            if (nmsg.json && !check_client_error(&nmsg, c))
                fprintf(stderr, "LSP-stateless: expected CLIENT_PUBNONCES from client %zu, got 0x%02x\n",
                        c, nmsg.msg_type);
            if (nmsg.json) cJSON_Delete(nmsg.json);
            free(all_pn);
            goto fail_pre;
        }
        unsigned char *client_pn = calloc(f->n_nodes, 66);
        if (!client_pn) { cJSON_Delete(nmsg.json); free(all_pn); goto fail_pre; }
        if (!wire_parse_factory_client_pubnonces(nmsg.json, client_pn,
                                                  (uint32_t)f->n_nodes)) {
            cJSON_Delete(nmsg.json);
            free(client_pn); free(all_pn);
            fprintf(stderr, "LSP-stateless: parse CLIENT_PUBNONCES (client %zu) failed\n", c);
            goto fail_pre;
        }
        cJSON_Delete(nmsg.json);
        for (size_t nidx = 0; nidx < f->n_nodes; nidx++) {
            int slot = factory_find_signer_slot(f, nidx, my_part);
            if (slot < 0) continue;  /* this client does not sign this node */
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(lsp->ctx, &pn, client_pn + nidx * 66)) {
                fprintf(stderr, "LSP-stateless: bad client pubnonce (client %zu node %zu)\n", c, nidx);
                free(client_pn); free(all_pn);
                goto fail_pre;
            }
            if (!factory_session_set_nonce(f, nidx, (size_t)slot, &pn)) {
                fprintf(stderr, "LSP-stateless: set client nonce node %zu slot %d failed\n", nidx, slot);
                free(client_pn); free(all_pn);
                goto fail_pre;
            }
            memcpy(all_pn + (nidx * (size_t)FACTORY_MAX_SIGNERS + (size_t)slot) * 66,
                   client_pn + nidx * 66, 66);
        }
        free(client_pn);
    }

    /* Step C (CRITICAL ATOMIC BLOCK -- no wire_recv inside): per node, gen the
       LSP secnonce, set the LSP slot nonce (clients' already set in Step B),
       finalize the node, create the LSP partial sig (which zeroes the
       secnonce), set it.  STATELESS INVARIANT: every LSP secnonce is generated
       only AFTER Step B's recv of all client pubnonces, and each is zeroed by
       musig_create_partial_sig before Step E's recv. */
    {
        unsigned char lsp_seckey[32];
        if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) { free(all_pn); goto fail_pre; }
        unsigned char *lsp_pn_per_node = calloc(f->n_nodes, 66);
        unsigned char *lsp_psig_per_node = calloc(f->n_nodes, 32);
        if (!lsp_pn_per_node || !lsp_psig_per_node) {
            memset(lsp_seckey, 0, 32);
            free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
            goto fail_pre;
        }
        for (size_t nidx = 0; nidx < f->n_nodes; nidx++) {
            int slot = factory_find_signer_slot(f, nidx, 0);
            if (slot < 0) continue;  /* LSP signs every node, but guard. */
            secp256k1_musig_secnonce lsp_secnonce;
            secp256k1_musig_pubnonce lsp_pubnonce;
            if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                                       lsp_seckey, &lsp->lsp_pubkey,
                                       &f->nodes[nidx].keyagg.cache)) {
                fprintf(stderr, "LSP-stateless: nonce gen node %zu failed\n", nidx);
                memset(lsp_seckey, 0, 32);
                free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
                goto fail_pre;
            }
            musig_pubnonce_serialize(lsp->ctx, lsp_pn_per_node + nidx * 66, &lsp_pubnonce);
            memcpy(all_pn + (nidx * (size_t)FACTORY_MAX_SIGNERS + (size_t)slot) * 66,
                   lsp_pn_per_node + nidx * 66, 66);
            if (!factory_session_set_nonce(f, nidx, (size_t)slot, &lsp_pubnonce)) {
                fprintf(stderr, "LSP-stateless: set LSP nonce node %zu failed\n", nidx);
                memset(lsp_seckey, 0, 32);
                free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
                goto fail_pre;
            }
            if (!factory_session_finalize_node(f, nidx)) {
                fprintf(stderr, "LSP-stateless: finalize_node %zu failed\n", nidx);
                memset(lsp_seckey, 0, 32);
                free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
                goto fail_pre;
            }
            secp256k1_musig_partial_sig lsp_psig;
            if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce,
                                           &lsp->lsp_keypair,
                                           &f->nodes[nidx].signing_session)) {
                fprintf(stderr, "LSP-stateless: create_partial_sig node %zu failed\n", nidx);
                memset(lsp_seckey, 0, 32);
                free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
                goto fail_pre;
            }
            /* lsp_secnonce zeroed by musig_create_partial_sig. INVARIANT holds. */
            if (!factory_session_set_partial_sig(f, nidx, (size_t)slot, &lsp_psig)) {
                fprintf(stderr, "LSP-stateless: set LSP psig node %zu failed\n", nidx);
                memset(lsp_seckey, 0, 32);
                free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
                goto fail_pre;
            }
            musig_partial_sig_serialize(lsp->ctx, lsp_psig_per_node + nidx * 32, &lsp_psig);
        }
        memset(lsp_seckey, 0, 32);

        /* Step D: LSP_RESPONSE -- per-node LSP nonces + psigs + full matrix. */
        cJSON *response = wire_build_factory_lsp_response(
            lsp_pn_per_node, lsp_psig_per_node, (uint32_t)f->n_nodes,
            all_pn, (uint32_t)(f->n_nodes * mtx_stride));
        free(lsp_pn_per_node); free(lsp_psig_per_node);
        if (!response) { free(all_pn); goto fail_pre; }
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_FACTORY_LSP_RESPONSE, response)) {
                fprintf(stderr, "LSP-stateless: send LSP_RESPONSE to client %zu failed\n", i);
                cJSON_Delete(response);
                free(all_pn);
                goto fail_pre;
            }
        }
        cJSON_Delete(response);
        free(all_pn);
    }

    /* Step E: collect each client's per-node final psigs. */
    for (size_t c = 0; c < lsp->n_clients; c++) {
        uint32_t my_part = (uint32_t)(c + 1);
        wire_msg_t pmsg;
        if (!wire_recv_skip_ping(lsp->client_fds[c], &pmsg) ||
            pmsg.msg_type != MSG_FACTORY_CLIENT_FINAL_PSIGS) {
            if (pmsg.json && !check_client_error(&pmsg, c))
                fprintf(stderr, "LSP-stateless: expected CLIENT_FINAL_PSIGS from client %zu, got 0x%02x\n",
                        c, pmsg.msg_type);
            if (pmsg.json) cJSON_Delete(pmsg.json);
            goto fail_pre;
        }
        unsigned char *client_psig = calloc(f->n_nodes, 32);
        if (!client_psig) { cJSON_Delete(pmsg.json); goto fail_pre; }
        if (!wire_parse_factory_client_final_psigs(pmsg.json, client_psig,
                                                    (uint32_t)f->n_nodes)) {
            cJSON_Delete(pmsg.json);
            free(client_psig);
            fprintf(stderr, "LSP-stateless: parse CLIENT_FINAL_PSIGS (client %zu) failed\n", c);
            goto fail_pre;
        }
        cJSON_Delete(pmsg.json);
        for (size_t nidx = 0; nidx < f->n_nodes; nidx++) {
            int slot = factory_find_signer_slot(f, nidx, my_part);
            if (slot < 0) continue;
            secp256k1_musig_partial_sig psig;
            if (!musig_partial_sig_parse(lsp->ctx, &psig, client_psig + nidx * 32) ||
                !factory_session_set_partial_sig(f, nidx, (size_t)slot, &psig)) {
                fprintf(stderr, "LSP-stateless: set client psig node %zu slot %d failed\n", nidx, slot);
                free(client_psig);
                goto fail_pre;
            }
        }
        free(client_psig);
    }

    /* ---- Completion: identical to legacy lsp_run_factory_creation ---- */
    if (!factory_sessions_complete(f)) {
        fprintf(stderr, "LSP-stateless: factory_sessions_complete failed\n");
        goto fail_pre;
    }

    {
        cJSON *ready = wire_build_factory_ready(f);
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_FACTORY_READY, ready)) {
                fprintf(stderr, "LSP-stateless: send FACTORY_READY to client %zu failed\n", i);
                cJSON_Delete(ready);
                goto fail_pre;
            }
        }
        cJSON_Delete(ready);
    }

    /* SF-CEREMONY-HELPERS #199: complete the ceremony journal.  Per-
       client participant rows at SIGNED phase, then state transition
       to FINALIZED (the persist_update_ceremony_state hard guard
       requires every participant row at SIGNED — see persist.c:6836). */
    if (cer_persisted) {
        for (size_t i = 0; i < lsp->n_clients; i++) {
            unsigned char pk33[33];
            size_t pk33_len = 33;
            if (!secp256k1_ec_pubkey_serialize(lsp->ctx, pk33, &pk33_len,
                                                 &lsp->client_pubkeys[i],
                                                 SECP256K1_EC_COMPRESSED)) {
                fprintf(stderr, "LSP-stateless: serialize client %zu pubkey failed (continuing)\n", i);
                continue;
            }
            if (!persist_save_participant_phase(lsp->db, cer_id, pk33,
                                                 PERSIST_CEREMONY_PHASE_SIGNED,
                                                 NULL, NULL, 0, 0)) {
                fprintf(stderr, "LSP-stateless: persist_save_participant_phase(SIGNED) client %zu failed (continuing)\n", i);
            }
        }
        if (!persist_update_ceremony_state(lsp->db, cer_id,
                                            PERSIST_CEREMONY_STATE_FINALIZED)) {
            fprintf(stderr, "LSP-stateless: persist_update_ceremony_state(FINALIZED) failed (continuing)\n");
        }
    }

    printf("LSP-stateless factory creation: %u nodes signed\n", (unsigned)f->n_nodes);
    return 1;

fail_pre:
    lsp_abort_ceremony(lsp, "stateless factory creation failed");
    factory_free(&lsp->factory);
    return 0;
}

int lsp_run_factory_creation(lsp_t *lsp,
                              const unsigned char *funding_txid, uint32_t funding_vout,
                              uint64_t funding_amount,
                              const unsigned char *funding_spk, size_t funding_spk_len,
                              uint16_t step_blocks, uint32_t states_per_layer,
                              uint32_t cltv_timeout) {
    return lsp_run_factory_creation_stateless(lsp, funding_txid, funding_vout, funding_amount, funding_spk, funding_spk_len, step_blocks, states_per_layer, cltv_timeout);
}

int lsp_run_cooperative_close(lsp_t *lsp,
                               tx_buf_t *close_tx_out,
                               const tx_output_t *outputs, size_t n_outputs,
                               uint32_t current_height) {
    factory_t *f = &lsp->factory;
    size_t n_total = 1 + lsp->n_clients;
    int clients_notified = 0;  /* set after CLOSE_PROPOSE sent */

    /* Build unsigned close tx + sighash */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char sighash[32];

    if (!factory_build_cooperative_close_unsigned(f, &unsigned_tx, sighash,
                                                   outputs, n_outputs,
                                                   current_height)) {
        fprintf(stderr, "LSP: build close unsigned failed\n");
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Set up MuSig session for close (single 5-of-5 on funding output) */
    musig_keyagg_t keyagg = f->nodes[0].keyagg;  /* same aggregate key */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, n_total);

    /* Generate LSP's nonce */
    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    secp256k1_musig_secnonce lsp_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_generate_nonce(lsp->ctx, &lsp_secnonce, &lsp_pubnonce,
                               lsp_seckey, &lsp->lsp_pubkey, &keyagg.cache)) {
        memset(lsp_seckey, 0, 32);
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    musig_session_set_pubnonce(&session, 0, &lsp_pubnonce);

    /* Drain any LSPS_REQUEST messages queued before close started.
       A client may send lsps2.get_info immediately on factory entry; if we
       don't respond before CLOSE_PROPOSE the client will receive LSPS_RESPONSE
       mid-ceremony and mistake it for CLOSE_ALL_NONCES. */
    for (size_t di = 0; di < lsp->n_clients; di++) {
        if (lsp->client_fds[di] < 0) continue; /* skip clients that disconnected in daemon mode */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsp->client_fds[di], &rfds);
        struct timeval dtv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100 ms */
        if (select(lsp->client_fds[di] + 1, &rfds, NULL, NULL, &dtv) > 0) {
            wire_msg_t drain_msg;
            if (wire_recv_timeout(lsp->client_fds[di], &drain_msg, 1) &&
                drain_msg.msg_type == MSG_LSPS_REQUEST) {
                lsps_ctx_t lsps_ctx = { .mgr = NULL, .lsp = lsp, .client_idx = di };
                lsps_handle_request(&lsps_ctx, lsp->client_fds[di], drain_msg.json);
            }
            if (drain_msg.json) cJSON_Delete(drain_msg.json);
        }
    }

    /* Send CLOSE_PROPOSE */
    cJSON *propose = wire_build_close_propose(outputs, n_outputs, current_height);
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (!wire_send(lsp->client_fds[i], MSG_CLOSE_PROPOSE, propose)) {
            fprintf(stderr, "LSP: failed to send CLOSE_PROPOSE\n");
            cJSON_Delete(propose);
            goto close_fail;
        }
    }
    cJSON_Delete(propose);
    clients_notified = 1;

    /* Collect CLOSE_NONCE from all clients */
    unsigned char all_pubnonces[FACTORY_MAX_SIGNERS][66];
    musig_pubnonce_serialize(lsp->ctx, all_pubnonces[0], &lsp_pubnonce);

    {
        ceremony_t close_nonce_cer;
        ceremony_init(&close_nonce_cer, lsp->n_clients, 300, (int)lsp->n_clients);
        size_t close_nonces_received = 0;

        while (close_nonces_received < lsp->n_clients) {
            int wait_fds[LSP_MAX_CLIENTS];
            for (size_t i = 0; i < lsp->n_clients; i++) {
                wait_fds[i] = (close_nonce_cer.clients[i] == CLIENT_WAITING)
                              ? lsp->client_fds[i] : -1;
            }

            int ready[LSP_MAX_CLIENTS];
            int n_ready = ceremony_select_all(wait_fds, lsp->n_clients, close_nonce_cer.per_client_timeout_sec, ready);
            if (n_ready <= 0) {
                for (size_t i = 0; i < lsp->n_clients; i++) {
                    if (close_nonce_cer.clients[i] == CLIENT_WAITING) {
                        fprintf(stderr, "LSP: timeout waiting for CLOSE_NONCE from client %zu\n", i);
                        close_nonce_cer.clients[i] = CLIENT_TIMED_OUT;
                    }
                }
                break;
            }

            for (size_t c = 0; c < lsp->n_clients; c++) {
                if (!ready[c]) continue;

                wire_msg_t msg;
                if (!wire_recv_skip_ping(lsp->client_fds[c], &msg)) {
                    fprintf(stderr, "LSP: timeout/disconnect waiting for CLOSE_NONCE from client %zu\n", c);
                    close_nonce_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }
                /* Dispatch LSPS_REQUEST that arrives before close started.
                   Client may send lsps2.get_info right after factory entry,
                   and the request sits in the kernel buffer until we read it. */
                if (msg.msg_type == MSG_LSPS_REQUEST) {
                    lsps_ctx_t lsps_ctx = { .mgr = NULL, .lsp = lsp, .client_idx = c };
                    lsps_handle_request(&lsps_ctx, lsp->client_fds[c], msg.json);
                    cJSON_Delete(msg.json);
                    /* Re-mark client as waiting so we read CLOSE_NONCE next */
                    continue;
                }
                if (msg.msg_type != MSG_CLOSE_NONCE) {
                    if (!check_client_error(&msg, c))
                        fprintf(stderr, "LSP: expected CLOSE_NONCE from client %zu\n", c);
                    if (msg.json) cJSON_Delete(msg.json);
                    close_nonce_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }

                unsigned char nonce_buf[66];
                if (wire_json_get_hex(msg.json, "pubnonce", nonce_buf, 66) != 66) {
                    fprintf(stderr, "LSP: bad close nonce from client %zu\n", c);
                    cJSON_Delete(msg.json);
                    close_nonce_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }
                cJSON_Delete(msg.json);

                memcpy(all_pubnonces[c + 1], nonce_buf, 66);

                secp256k1_musig_pubnonce pn;
                if (!musig_pubnonce_parse(lsp->ctx, &pn, nonce_buf)) {
                    close_nonce_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }
                musig_session_set_pubnonce(&session, c + 1, &pn);
                close_nonce_cer.clients[c] = CLIENT_NONCE_RECEIVED;
                close_nonces_received++;
            }
        }

        if (close_nonces_received < lsp->n_clients) {
            if (ceremony_has_quorum(&close_nonce_cer)) {
                fprintf(stderr, "LSP: %zu/%zu clients sent close nonces (quorum met)\n",
                        close_nonces_received, lsp->n_clients);
            } else {
                fprintf(stderr, "LSP: only %zu/%zu clients sent close nonces (quorum requires %d)\n",
                        close_nonces_received, lsp->n_clients, close_nonce_cer.min_clients);
                goto close_fail;
            }
        }
    }

    /* Send CLOSE_ALL_NONCES */
    {
        cJSON *all_msg = wire_build_close_all_nonces(
            (const unsigned char (*)[66])all_pubnonces, n_total);
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_CLOSE_ALL_NONCES, all_msg)) {
                fprintf(stderr, "LSP: failed to send CLOSE_ALL_NONCES\n");
                cJSON_Delete(all_msg);
                goto close_fail;
            }
        }
        cJSON_Delete(all_msg);
    }

    /* Finalize session */
    if (!musig_session_finalize_nonces(lsp->ctx, &session, sighash, NULL, NULL)) {
        fprintf(stderr, "LSP: close session finalize failed\n");
        goto close_fail;
    }

    /* Generate LSP's partial sig */
    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_create_partial_sig(lsp->ctx, &lsp_psig, &lsp_secnonce,
                                   &lsp->lsp_keypair, &session)) {
        fprintf(stderr, "LSP: close partial sig failed\n");
        goto close_fail;
    }

    secp256k1_musig_partial_sig all_psigs[FACTORY_MAX_SIGNERS];
    all_psigs[0] = lsp_psig;

    /* Collect CLOSE_PSIG from all clients (parallel select) */
    {
        ceremony_t close_psig_cer;
        ceremony_init(&close_psig_cer, lsp->n_clients, 300, (int)lsp->n_clients);
        size_t close_psigs_received = 0;

        while (close_psigs_received < lsp->n_clients) {
            int wait_fds[LSP_MAX_CLIENTS];
            for (size_t i = 0; i < lsp->n_clients; i++) {
                wait_fds[i] = (close_psig_cer.clients[i] == CLIENT_WAITING)
                              ? lsp->client_fds[i] : -1;
            }

            int ready[LSP_MAX_CLIENTS];
            int n_ready = ceremony_select_all(wait_fds, lsp->n_clients, close_psig_cer.per_client_timeout_sec, ready);
            if (n_ready <= 0) {
                for (size_t i = 0; i < lsp->n_clients; i++) {
                    if (close_psig_cer.clients[i] == CLIENT_WAITING) {
                        fprintf(stderr, "LSP: timeout waiting for CLOSE_PSIG from client %zu\n", i);
                        close_psig_cer.clients[i] = CLIENT_TIMED_OUT;
                    }
                }
                break;
            }

            for (size_t c = 0; c < lsp->n_clients; c++) {
                if (!ready[c]) continue;

                wire_msg_t msg;
                if (!wire_recv_skip_ping(lsp->client_fds[c], &msg)) {
                    close_psig_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }
                /* Drain stray benign messages before CLOSE_PSIG */
                if (msg.msg_type == MSG_LSPS_REQUEST) {
                    lsps_ctx_t lsps_ctx = { .mgr = NULL, .lsp = lsp, .client_idx = c };
                    lsps_handle_request(&lsps_ctx, lsp->client_fds[c], msg.json);
                    cJSON_Delete(msg.json);
                    ready[c] = 1;  /* retry this client */
                    continue;
                }
                if (msg.msg_type == MSG_REGISTER_INVOICE) {
                    cJSON_Delete(msg.json);
                    ready[c] = 1;  /* retry this client */
                    continue;
                }
                if (msg.msg_type != MSG_CLOSE_PSIG) {
                    if (msg.json && !check_client_error(&msg, c))
                        fprintf(stderr, "LSP: expected CLOSE_PSIG from client %zu\n", c);
                    if (msg.json) cJSON_Delete(msg.json);
                    close_psig_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }

                unsigned char psig_buf[32];
                if (wire_json_get_hex(msg.json, "psig", psig_buf, 32) != 32) {
                    fprintf(stderr, "LSP: bad close psig from client %zu\n", c);
                    cJSON_Delete(msg.json);
                    close_psig_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }
                cJSON_Delete(msg.json);

                if (!musig_partial_sig_parse(lsp->ctx, &all_psigs[c + 1], psig_buf)) {
                    close_psig_cer.clients[c] = CLIENT_ERROR;
                    continue;
                }
                close_psig_cer.clients[c] = CLIENT_PSIG_RECEIVED;
                close_psigs_received++;
            }
        }

        if (close_psigs_received < lsp->n_clients) {
            if (ceremony_has_quorum(&close_psig_cer)) {
                fprintf(stderr, "LSP: %zu/%zu clients sent close psigs (quorum met)\n",
                        close_psigs_received, lsp->n_clients);
            } else {
                fprintf(stderr, "LSP: only %zu/%zu clients sent close psigs (quorum requires %d)\n",
                        close_psigs_received, lsp->n_clients, close_psig_cer.min_clients);
                goto close_fail;
            }
        }
    }

    /* Aggregate */
    unsigned char sig64[64];
    if (!musig_aggregate_partial_sigs(lsp->ctx, sig64, &session, all_psigs, n_total)) {
        fprintf(stderr, "LSP: close sig aggregation failed\n");
        goto close_fail;
    }

    /* Finalize signed close tx */
    if (!finalize_signed_tx(close_tx_out, unsigned_tx.data, unsigned_tx.len, sig64)) {
        fprintf(stderr, "LSP: close finalize_signed_tx failed\n");
        goto close_fail;
    }

    /* Send CLOSE_DONE to all clients */
    {
        cJSON *done = wire_build_close_done(close_tx_out->data, close_tx_out->len);
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_CLOSE_DONE, done)) {
                fprintf(stderr, "LSP: failed to send CLOSE_DONE\n");
                cJSON_Delete(done);
                goto close_fail;
            }
        }
        cJSON_Delete(done);
    }

    tx_buf_free(&unsigned_tx);
    return 1;

close_fail:
    if (clients_notified)
        lsp_abort_ceremony(lsp, "cooperative close failed");
    tx_buf_free(&unsigned_tx);
    return 0;
}

int lsp_accept_bridge(lsp_t *lsp) {
    if (lsp->listen_fd < 0) {
        lsp->listen_fd = wire_listen(NULL, lsp->port);
        if (lsp->listen_fd < 0) {
            fprintf(stderr, "LSP: listen failed on port %d for bridge\n", lsp->port);
            return 0;
        }
    }

    int fd = wire_accept(lsp->listen_fd);
    if (fd < 0) {
        fprintf(stderr, "LSP: accept failed for bridge\n");
        return 0;
    }

    /* Encrypted transport handshake */
    int bridge_hs_ok;
    if (lsp->use_nk)
        bridge_hs_ok = wire_noise_handshake_nk_responder(fd, lsp->ctx, lsp->nk_seckey);
    else
        bridge_hs_ok = wire_noise_handshake_responder(fd, lsp->ctx);
    if (!bridge_hs_ok) {
        fprintf(stderr, "LSP: noise handshake failed for bridge\n");
        wire_close(fd);
        return 0;
    }

    /* Expect BRIDGE_HELLO */
    wire_msg_t msg;
    if (!wire_recv(fd, &msg) || msg.msg_type != MSG_BRIDGE_HELLO) {
        fprintf(stderr, "LSP: expected BRIDGE_HELLO, got 0x%02x\n", msg.msg_type);
        if (msg.json) cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
    }
    cJSON_Delete(msg.json);

    /* Finding A: enforce bridge pubkey pin before ACK. */
    if (!lsp_validate_bridge_pin(lsp, msg.json)) {
        if (msg.json) cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
    }

        /* Send BRIDGE_HELLO_ACK */
    cJSON *ack = wire_build_bridge_hello_ack();
    if (!wire_send(fd, MSG_BRIDGE_HELLO_ACK, ack)) {
        fprintf(stderr, "LSP: failed to send BRIDGE_HELLO_ACK\n");
        cJSON_Delete(ack);
        wire_close(fd);
        return 0;
    }
    cJSON_Delete(ack);

    lsp->bridge_fd = fd;
    printf("LSP: bridge connected (fd=%d)\n", fd);
    return 1;
}

void lsp_abort_ceremony(lsp_t *lsp, const char *reason) {
    cJSON *err = wire_build_error(reason ? reason : "ceremony aborted");
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] >= 0)
            wire_send(lsp->client_fds[i], MSG_ERROR, err);
    }
    cJSON_Delete(err);
}

void lsp_cleanup(lsp_t *lsp) {
    if (lsp->client_fds) {
        for (size_t i = 0; i < lsp->clients_cap; i++) {
            if (lsp->client_fds[i] >= 0)
                wire_close(lsp->client_fds[i]);
        }
    }
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    lsp->client_fds = NULL;
    lsp->client_pubkeys = NULL;
    if (lsp->bridge_fd >= 0) {
        wire_close(lsp->bridge_fd);
        lsp->bridge_fd = -1;
    }
    if (lsp->listen_fd >= 0) {
        wire_close(lsp->listen_fd);
        lsp->listen_fd = -1;
    }
    factory_free(&lsp->factory);
}

void lsp_set_expected_bridge_pubkey(lsp_t *lsp, const secp256k1_pubkey *pk) {
    if (!lsp || !pk) return;
    memcpy(&lsp->expected_bridge_pubkey, pk, sizeof(secp256k1_pubkey));
    lsp->has_expected_bridge_pubkey = 1;
}

int lsp_validate_bridge_pin(lsp_t *lsp, cJSON *hello_json) {
    if (!lsp || !lsp->has_expected_bridge_pubkey) return 1;
    secp256k1_pubkey got_pk;
    int has_pk = 0;
    wire_parse_bridge_hello(hello_json, &got_pk, &has_pk);
    if (!has_pk) {
        fprintf(stderr, "LSP: rejecting BRIDGE_HELLO -- bridge_pubkey missing "
                        "(Finding A pin set, expected advertise required)\n");
        return 0;
    }
    if (memcmp(&got_pk, &lsp->expected_bridge_pubkey,
                sizeof(secp256k1_pubkey)) != 0) {
        fprintf(stderr, "LSP: rejecting BRIDGE_HELLO -- bridge_pubkey mismatch "
                        "(Finding A pin set, advertised pubkey does not match)\n");
        return 0;
    }
    return 1;
}

