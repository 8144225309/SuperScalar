/* Factory rotation extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
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
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);
extern void hex_encode(const unsigned char *, size_t, char *);
extern int hex_decode(const char *, unsigned char *, size_t);
extern void reverse_bytes(unsigned char *, size_t);

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
    fflush(stdout);

    /* Build combined keypair/pubkey arrays for adaptor protocol */
    size_t n_total = 1 + lsp->n_clients;
    secp256k1_keypair rot_kps[FACTORY_MAX_SIGNERS];
    secp256k1_pubkey rot_pks[FACTORY_MAX_SIGNERS];

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(mgr->ctx, &lsp_kp, mgr->rot_lsp_seckey))
        return 0;
    rot_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(mgr->ctx, &rot_pks[0], &lsp_kp))
        return 0;
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
    /* Close TX: 1 P2TR key-path input (~68 vB overhead) + n_total P2TR outputs (~43 vB each) */
    size_t close_vsize = 68 + 43 * n_total;
    uint64_t close_fee = fee_estimate(fe, close_vsize);
    if (close_fee == 0) {
        /* Floor: 1 sat/vB */
        close_fee = close_vsize;
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
        secure_zero(saved_seckey, 32);
        return 0;
    }

    /* Restore saved state */
    mgr->bridge_fd = saved_bridge_fd;
    mgr->watchtower = saved_wt;
    mgr->persist = saved_persist;
    mgr->ladder = saved_ladder;
    memcpy(mgr->rot_lsp_seckey, saved_seckey, 32);
    secure_zero(saved_seckey, 32);
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
