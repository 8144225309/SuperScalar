#include "superscalar/lsp.h"
#include "superscalar/ceremony.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

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
    lsp->max_connections = LSP_MAX_CLIENTS;
    lsp->listen_fd = -1;
    lsp->bridge_fd = -1;

    for (size_t i = 0; i < LSP_MAX_CLIENTS; i++)
        lsp->client_fds[i] = -1;
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

        /* Encrypted transport handshake (NK if configured, NN fallback) */
        int hs_ok;
        if (lsp->use_nk)
            hs_ok = wire_noise_handshake_nk_responder(fd, lsp->ctx, lsp->nk_seckey);
        else
            hs_ok = wire_noise_handshake_responder(fd, lsp->ctx);
        if (!hs_ok) {
            fprintf(stderr, "LSP: noise handshake failed for client %zu\n", i);
            wire_close(fd);
            goto accept_fail;
        }

        /* Receive HELLO */
        wire_msg_t msg;
        if (!wire_recv(fd, &msg) || msg.msg_type != MSG_HELLO) {
            fprintf(stderr, "LSP: expected HELLO from client %zu\n", i);
            wire_close(fd);
            if (msg.json) cJSON_Delete(msg.json);
            goto accept_fail;
        }

        /* Parse client pubkey */
        cJSON *pk_item = cJSON_GetObjectItem(msg.json, "pubkey");
        if (!pk_item || !cJSON_IsString(pk_item)) {
            fprintf(stderr, "LSP: bad pubkey in HELLO from client %zu\n", i);
            cJSON_Delete(msg.json);
            wire_close(fd);
            goto accept_fail;
        }

        unsigned char pk_buf[33];
        if (hex_decode(pk_item->valuestring, pk_buf, 33) != 33 ||
            !secp256k1_ec_pubkey_parse(lsp->ctx, &lsp->client_pubkeys[i], pk_buf, 33)) {
            fprintf(stderr, "LSP: invalid pubkey from client %zu\n", i);
            cJSON_Delete(msg.json);
            wire_close(fd);
            goto accept_fail;
        }
        cJSON_Delete(msg.json);

        lsp->client_fds[i] = fd;
        lsp->n_clients = i + 1;
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

int lsp_run_factory_creation(lsp_t *lsp,
                              const unsigned char *funding_txid, uint32_t funding_vout,
                              uint64_t funding_amount,
                              const unsigned char *funding_spk, size_t funding_spk_len,
                              uint16_t step_blocks, uint32_t states_per_layer,
                              uint32_t cltv_timeout) {
    size_t n_total = 1 + lsp->n_clients;

    /* Build all_pubkeys: LSP=0, clients=1..N */
    secp256k1_pubkey all_pubkeys[FACTORY_MAX_SIGNERS];
    all_pubkeys[0] = lsp->lsp_pubkey;
    for (size_t i = 0; i < lsp->n_clients; i++)
        all_pubkeys[i + 1] = lsp->client_pubkeys[i];

    /* LSP has its own keypair, but we need to use the split-round API.
       Initialize from pubkeys, then we'll use factory_sessions_* */
    factory_t *f = &lsp->factory;
    factory_arity_t saved_arity = f->leaf_arity;
    placement_mode_t saved_placement = f->placement_mode;
    economic_mode_t saved_econ = f->economic_mode;
    participant_profile_t saved_profiles[FACTORY_MAX_SIGNERS];
    memcpy(saved_profiles, f->profiles, sizeof(saved_profiles));
    factory_init_from_pubkeys(f, lsp->ctx, all_pubkeys, n_total,
                              step_blocks, states_per_layer);
    if (saved_arity == FACTORY_ARITY_1)
        factory_set_arity(f, FACTORY_ARITY_1);
    f->cltv_timeout = cltv_timeout;  /* set BEFORE build_tree for staggered taptrees */
    f->placement_mode = saved_placement;
    f->economic_mode = saved_econ;
    memcpy(f->profiles, saved_profiles, sizeof(saved_profiles));
    factory_set_funding(f, funding_txid, funding_vout, funding_amount,
                        funding_spk, funding_spk_len);

    if (!factory_build_tree(f)) {
        fprintf(stderr, "LSP: factory_build_tree failed\n");
        return 0;
    }

    /* Send FACTORY_PROPOSE to all clients */
    cJSON *propose = wire_build_factory_propose(f);
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (!wire_send(lsp->client_fds[i], MSG_FACTORY_PROPOSE, propose)) {
            fprintf(stderr, "LSP: failed to send FACTORY_PROPOSE to client %zu\n", i);
            cJSON_Delete(propose);
            return 0;
        }
    }
    cJSON_Delete(propose);

    /* Initialize signing sessions */
    if (!factory_sessions_init(f)) {
        fprintf(stderr, "LSP: factory_sessions_init failed\n");
        return 0;
    }

    /* Generate LSP's own nonces via pool (participant index 0) */
    size_t lsp_node_count = factory_count_nodes_for_participant(f, 0);

    /* Pre-generate nonce pool for LSP */
    musig_nonce_pool_t lsp_pool;
    unsigned char lsp_seckey[32];
    if (!secp256k1_keypair_sec(lsp->ctx, lsp_seckey, &lsp->lsp_keypair))
        return 0;
    if (!musig_nonce_pool_generate(lsp->ctx, &lsp_pool, lsp_node_count,
                                    lsp_seckey, &lsp->lsp_pubkey, NULL)) {
        fprintf(stderr, "LSP: nonce pool generation failed\n");
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    memset(lsp_seckey, 0, 32);

    /* Keep track of secnonce pointers drawn from pool for later partial sig */
    secp256k1_musig_secnonce *lsp_secnonce_ptrs[FACTORY_MAX_NODES];
    size_t lsp_secnonce_count = 0;

    /* Total entries for ALL_NONCES: all (node, signer) pairs across all participants */
    size_t total_slots = 0;
    for (size_t i = 0; i < f->n_nodes; i++)
        total_slots += f->nodes[i].n_signers;

    wire_bundle_entry_t *all_nonce_entries =
        (wire_bundle_entry_t *)calloc(total_slots, sizeof(wire_bundle_entry_t));
    if (!all_nonce_entries) return 0;
    size_t all_nonce_count = 0;

    /* Draw LSP's nonces from pool */
    for (size_t i = 0; i < f->n_nodes; i++) {
        int slot = factory_find_signer_slot(f, i, 0);
        if (slot < 0) continue;

        secp256k1_musig_secnonce *sec;
        secp256k1_musig_pubnonce pub;
        if (!musig_nonce_pool_next(&lsp_pool, &sec, &pub)) {
            fprintf(stderr, "LSP: nonce pool exhausted at node %zu\n", i);
            goto fail;
        }
        lsp_secnonce_ptrs[lsp_secnonce_count++] = sec;

        if (!factory_session_set_nonce(f, i, (size_t)slot, &pub)) {
            fprintf(stderr, "LSP: set nonce failed node %zu slot %d\n", i, slot);
            goto fail;
        }

        /* Add to all_nonce_entries */
        unsigned char nonce_ser[66];
        musig_pubnonce_serialize(lsp->ctx, nonce_ser, &pub);
        all_nonce_entries[all_nonce_count].node_idx = (uint32_t)i;
        all_nonce_entries[all_nonce_count].signer_slot = (uint32_t)slot;
        memcpy(all_nonce_entries[all_nonce_count].data, nonce_ser, 66);
        all_nonce_entries[all_nonce_count].data_len = 66;
        all_nonce_count++;
    }

    /* Collect NONCE_BUNDLEs from all clients (parallel select) */
    {
        ceremony_t ceremony;
        ceremony_init(&ceremony, lsp->n_clients, 30, (int)lsp->n_clients);
        ceremony.state = CEREMONY_COLLECTING_NONCES;
        size_t nonces_received = 0;

        while (nonces_received < lsp->n_clients) {
            /* Build fd list of clients still waiting */
            int wait_fds[LSP_MAX_CLIENTS];
            for (size_t i = 0; i < lsp->n_clients; i++) {
                wait_fds[i] = (ceremony.clients[i] == CLIENT_WAITING)
                              ? lsp->client_fds[i] : -1;
            }

            int ready[LSP_MAX_CLIENTS];
            int n_ready = ceremony_select_all(wait_fds, lsp->n_clients,
                                              ceremony.per_client_timeout_sec, ready);
            if (n_ready <= 0) {
                /* Timeout: mark remaining as timed out */
                for (size_t i = 0; i < lsp->n_clients; i++) {
                    if (ceremony.clients[i] == CLIENT_WAITING) {
                        ceremony.clients[i] = CLIENT_TIMED_OUT;
                        fprintf(stderr, "LSP: timeout waiting for NONCE_BUNDLE from client %zu\n", i);
                    }
                }
                break;
            }

            for (size_t c = 0; c < lsp->n_clients; c++) {
                if (!ready[c]) continue;

                wire_msg_t msg;
                if (!wire_recv(lsp->client_fds[c], &msg) || msg.msg_type != MSG_NONCE_BUNDLE) {
                    fprintf(stderr, "LSP: expected NONCE_BUNDLE from client %zu, got 0x%02x\n",
                            c, msg.msg_type);
                    if (msg.json) cJSON_Delete(msg.json);
                    ceremony.clients[c] = CLIENT_ERROR;
                    continue;
                }

                cJSON *entries_arr = cJSON_GetObjectItem(msg.json, "entries");
                if (!entries_arr || !cJSON_IsArray(entries_arr)) {
                    fprintf(stderr, "LSP: missing entries in NONCE_BUNDLE from client %zu\n", c);
                    cJSON_Delete(msg.json);
                    ceremony.clients[c] = CLIENT_ERROR;
                    continue;
                }
                wire_bundle_entry_t client_entries[FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS];
                size_t n_entries = wire_parse_bundle(entries_arr, client_entries,
                                                     FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS, 66);

                int client_ok = 1;
                for (size_t e = 0; e < n_entries; e++) {
                    secp256k1_musig_pubnonce pubnonce;
                    if (!musig_pubnonce_parse(lsp->ctx, &pubnonce, client_entries[e].data)) {
                        fprintf(stderr, "LSP: bad pubnonce from client %zu\n", c);
                        client_ok = 0;
                        break;
                    }
                    if (!factory_session_set_nonce(f, client_entries[e].node_idx,
                                                    client_entries[e].signer_slot, &pubnonce)) {
                        fprintf(stderr, "LSP: set_nonce failed node %u slot %u\n",
                                client_entries[e].node_idx, client_entries[e].signer_slot);
                        client_ok = 0;
                        break;
                    }
                    all_nonce_entries[all_nonce_count] = client_entries[e];
                    all_nonce_count++;
                }
                cJSON_Delete(msg.json);

                if (client_ok) {
                    ceremony.clients[c] = CLIENT_NONCE_RECEIVED;
                    nonces_received++;
                } else {
                    ceremony.clients[c] = CLIENT_ERROR;
                }
            }
        }

        /* For now, require all clients (no graceful degradation yet) */
        if (nonces_received < lsp->n_clients) {
            fprintf(stderr, "LSP: only %zu/%zu clients sent nonces\n",
                    nonces_received, lsp->n_clients);
            goto fail;
        }
    }

    /* Send ALL_NONCES to all clients */
    {
        cJSON *all_msg = wire_build_all_nonces(all_nonce_entries, all_nonce_count);
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_ALL_NONCES, all_msg)) {
                fprintf(stderr, "LSP: failed to send ALL_NONCES to client %zu\n", i);
                cJSON_Delete(all_msg);
                goto fail;
            }
        }
        cJSON_Delete(all_msg);
    }

    /* Finalize nonces */
    if (!factory_sessions_finalize(f)) {
        fprintf(stderr, "LSP: factory_sessions_finalize failed\n");
        goto fail;
    }

    /* Generate LSP's partial sigs using pool-drawn secnonces */
    {
        size_t psig_nonce_idx = 0;
        for (size_t i = 0; i < f->n_nodes; i++) {
            int slot = factory_find_signer_slot(f, i, 0);
            if (slot < 0) continue;

            secp256k1_musig_partial_sig psig;
            if (!musig_create_partial_sig(lsp->ctx, &psig,
                                           lsp_secnonce_ptrs[psig_nonce_idx],
                                           &lsp->lsp_keypair,
                                           &f->nodes[i].signing_session)) {
                fprintf(stderr, "LSP: partial sig failed node %zu\n", i);
                goto fail;
            }
            if (!factory_session_set_partial_sig(f, i, (size_t)slot, &psig)) {
                fprintf(stderr, "LSP: set partial sig failed node %zu\n", i);
                goto fail;
            }
            psig_nonce_idx++;
        }
    }

    /* Collect PSIG_BUNDLEs from all clients (parallel select) */
    {
        ceremony_t psig_ceremony;
        ceremony_init(&psig_ceremony, lsp->n_clients, 30, (int)lsp->n_clients);
        psig_ceremony.state = CEREMONY_COLLECTING_PSIGS;
        size_t psigs_received = 0;

        while (psigs_received < lsp->n_clients) {
            int wait_fds[LSP_MAX_CLIENTS];
            for (size_t i = 0; i < lsp->n_clients; i++) {
                wait_fds[i] = (psig_ceremony.clients[i] == CLIENT_WAITING)
                              ? lsp->client_fds[i] : -1;
            }

            int ready[LSP_MAX_CLIENTS];
            int n_ready = ceremony_select_all(wait_fds, lsp->n_clients,
                                              psig_ceremony.per_client_timeout_sec, ready);
            if (n_ready <= 0) {
                for (size_t i = 0; i < lsp->n_clients; i++) {
                    if (psig_ceremony.clients[i] == CLIENT_WAITING) {
                        psig_ceremony.clients[i] = CLIENT_TIMED_OUT;
                        fprintf(stderr, "LSP: timeout waiting for PSIG_BUNDLE from client %zu\n", i);
                    }
                }
                break;
            }

            for (size_t c = 0; c < lsp->n_clients; c++) {
                if (!ready[c]) continue;

                wire_msg_t msg;
                if (!wire_recv(lsp->client_fds[c], &msg) || msg.msg_type != MSG_PSIG_BUNDLE) {
                    fprintf(stderr, "LSP: expected PSIG_BUNDLE from client %zu\n", c);
                    if (msg.json) cJSON_Delete(msg.json);
                    psig_ceremony.clients[c] = CLIENT_ERROR;
                    continue;
                }

                cJSON *entries_arr = cJSON_GetObjectItem(msg.json, "entries");
                if (!entries_arr || !cJSON_IsArray(entries_arr)) {
                    fprintf(stderr, "LSP: missing entries in PSIG_BUNDLE from client %zu\n", c);
                    cJSON_Delete(msg.json);
                    psig_ceremony.clients[c] = CLIENT_ERROR;
                    continue;
                }
                wire_bundle_entry_t client_entries[FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS];
                size_t n_entries = wire_parse_bundle(entries_arr, client_entries,
                                                     FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS, 32);

                int client_ok = 1;
                for (size_t e = 0; e < n_entries; e++) {
                    secp256k1_musig_partial_sig psig;
                    if (!musig_partial_sig_parse(lsp->ctx, &psig, client_entries[e].data)) {
                        fprintf(stderr, "LSP: bad psig from client %zu\n", c);
                        client_ok = 0;
                        break;
                    }
                    if (!factory_session_set_partial_sig(f, client_entries[e].node_idx,
                                                          client_entries[e].signer_slot, &psig)) {
                        fprintf(stderr, "LSP: set psig failed node %u slot %u\n",
                                client_entries[e].node_idx, client_entries[e].signer_slot);
                        client_ok = 0;
                        break;
                    }
                }
                cJSON_Delete(msg.json);

                if (client_ok) {
                    psig_ceremony.clients[c] = CLIENT_PSIG_RECEIVED;
                    psigs_received++;
                } else {
                    psig_ceremony.clients[c] = CLIENT_ERROR;
                }
            }
        }

        if (psigs_received < lsp->n_clients) {
            fprintf(stderr, "LSP: only %zu/%zu clients sent psigs\n",
                    psigs_received, lsp->n_clients);
            goto fail;
        }
    }

    /* Complete signing */
    if (!factory_sessions_complete(f)) {
        fprintf(stderr, "LSP: factory_sessions_complete failed\n");
        goto fail;
    }

    /* Send FACTORY_READY to all clients */
    {
        cJSON *ready = wire_build_factory_ready(f);
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (!wire_send(lsp->client_fds[i], MSG_FACTORY_READY, ready)) {
                fprintf(stderr, "LSP: failed to send FACTORY_READY to client %zu\n", i);
                cJSON_Delete(ready);
                goto fail;
            }
        }
        cJSON_Delete(ready);
    }

    free(all_nonce_entries);
    return 1;

fail:
    lsp_abort_ceremony(lsp, "factory creation failed");
    free(all_nonce_entries);
    return 0;
}

int lsp_run_cooperative_close(lsp_t *lsp,
                               tx_buf_t *close_tx_out,
                               const tx_output_t *outputs, size_t n_outputs) {
    factory_t *f = &lsp->factory;
    size_t n_total = 1 + lsp->n_clients;
    int clients_notified = 0;  /* set after CLOSE_PROPOSE sent */

    /* Build unsigned close tx + sighash */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char sighash[32];

    if (!factory_build_cooperative_close_unsigned(f, &unsigned_tx, sighash,
                                                   outputs, n_outputs)) {
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

    /* Send CLOSE_PROPOSE */
    cJSON *propose = wire_build_close_propose(outputs, n_outputs);
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
        ceremony_init(&close_nonce_cer, lsp->n_clients, 30, (int)lsp->n_clients);
        size_t close_nonces_received = 0;

        while (close_nonces_received < lsp->n_clients) {
            int wait_fds[LSP_MAX_CLIENTS];
            for (size_t i = 0; i < lsp->n_clients; i++) {
                wait_fds[i] = (close_nonce_cer.clients[i] == CLIENT_WAITING)
                              ? lsp->client_fds[i] : -1;
            }

            int ready[LSP_MAX_CLIENTS];
            int n_ready = ceremony_select_all(wait_fds, lsp->n_clients, 30, ready);
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
                if (!wire_recv_timeout(lsp->client_fds[c], &msg, 30) || msg.msg_type != MSG_CLOSE_NONCE) {
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
            fprintf(stderr, "LSP: only %zu/%zu clients sent close nonces\n",
                    close_nonces_received, lsp->n_clients);
            goto close_fail;
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
        ceremony_init(&close_psig_cer, lsp->n_clients, 30, (int)lsp->n_clients);
        size_t close_psigs_received = 0;

        while (close_psigs_received < lsp->n_clients) {
            int wait_fds[LSP_MAX_CLIENTS];
            for (size_t i = 0; i < lsp->n_clients; i++) {
                wait_fds[i] = (close_psig_cer.clients[i] == CLIENT_WAITING)
                              ? lsp->client_fds[i] : -1;
            }

            int ready[LSP_MAX_CLIENTS];
            int n_ready = ceremony_select_all(wait_fds, lsp->n_clients, 30, ready);
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
                if (!wire_recv_timeout(lsp->client_fds[c], &msg, 30) || msg.msg_type != MSG_CLOSE_PSIG) {
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
            fprintf(stderr, "LSP: only %zu/%zu clients sent close psigs\n",
                    close_psigs_received, lsp->n_clients);
            goto close_fail;
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
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] >= 0)
            wire_close(lsp->client_fds[i]);
        lsp->client_fds[i] = -1;
    }
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
