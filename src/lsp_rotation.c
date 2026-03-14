/* Factory rotation extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/wire.h"
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
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "superscalar/sha256.h"
extern void hex_encode(const unsigned char *, size_t, char *);
extern int hex_decode(const char *, unsigned char *, size_t);
extern void reverse_bytes(unsigned char *, size_t);

/* --- Rotation retry helpers --- */

int lsp_rotation_should_retry(const lsp_channel_mgr_t *mgr,
                              uint32_t factory_id, uint32_t cur_height) {
    if (!(mgr->rot_attempted_mask & (1u << (factory_id & 31))))
        return 0;  /* never attempted */
    uint32_t idx = factory_id % 8;
    uint32_t retries = mgr->rot_retry_count[idx];
    uint32_t max_ret = mgr->rot_max_retries > 0 ? mgr->rot_max_retries : 3;
    if (retries > max_ret)
        return 0;   /* fallback already done */
    if (retries >= max_ret)
        return -1;  /* exhausted — time for fallback */
    /* Exponential backoff: base * 2^retries blocks (clamped to prevent overflow) */
    uint32_t base = mgr->rot_retry_base_delay > 0 ? mgr->rot_retry_base_delay : 10;
    uint32_t shift = retries < 30 ? retries : 30;
    uint32_t delay = base * (1u << shift);
    if (cur_height >= mgr->rot_last_attempt_block[idx] + delay)
        return 1;   /* enough blocks elapsed — retry now */
    return 0;        /* waiting for backoff */
}

void lsp_rotation_record_failure(lsp_channel_mgr_t *mgr,
                                 uint32_t factory_id, uint32_t cur_height) {
    uint32_t idx = factory_id % 8;
    mgr->rot_retry_count[idx]++;
    mgr->rot_last_attempt_block[idx] = cur_height;
}

void lsp_rotation_record_success(lsp_channel_mgr_t *mgr, uint32_t factory_id) {
    uint32_t idx = factory_id % 8;
    mgr->rot_retry_count[idx] = 0;
    mgr->rot_last_attempt_block[idx] = 0;
    /* Clear attempted mask so retry logic won't fire for this factory */
    mgr->rot_attempted_mask &= ~(1u << (factory_id & 31));
}

/* --- Factory rotation --- */

int lsp_channels_rotate_factory(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp || !mgr->ladder) return 0;

    ladder_t *lad = (ladder_t *)mgr->ladder;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    if (!fe) return 0;

    /* Find the DYING (or EXPIRED) factory to rotate from.
       Factory may skip DYING if blocks mine faster than the daemon polls. */
    ladder_factory_t *dying = ladder_get_dying(lad);
    if (!dying) {
        /* Fallback: look for the first EXPIRED factory that hasn't been rotated */
        for (size_t i = 0; i < lad->n_factories; i++) {
            if (lad->factories[i].cached_state == FACTORY_EXPIRED &&
                lad->factories[i].is_initialized &&
                !lad->factories[i].partial_rotation_done) {
                dying = &lad->factories[i];
                break;
            }
        }
    }
    if (!dying) {
        fprintf(stderr, "LSP rotate: no DYING/EXPIRED factory found\n");
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
    size_t turnover_ok = 0, turnover_fail = 0;
    for (size_t ci = 0; ci < lsp->n_clients; ci++) {
        if (lsp->client_fds[ci] < 0) {
            printf("LSP rotate: client %zu offline, skipping turnover\n", ci);
            turnover_fail++;
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
            fprintf(stderr, "LSP rotate: presig failed client %zu, skipping\n", ci);
            turnover_fail++;
            continue;
        }

        /* Send PTLC_PRESIG to client */
        cJSON *pm = wire_build_ptlc_presig(presig, nonce_parity, turnover_msg);
        if (!wire_send(lsp->client_fds[ci], MSG_PTLC_PRESIG, pm)) {
            cJSON_Delete(pm);
            fprintf(stderr, "LSP rotate: send presig failed client %zu, skipping\n", ci);
            wire_close(lsp->client_fds[ci]);
            lsp->client_fds[ci] = -1;
            turnover_fail++;
            continue;
        }
        cJSON_Delete(pm);

        /* Wait for PTLC_ADAPTED_SIG (15s timeout per client) */
        wire_msg_t resp;
        memset(&resp, 0, sizeof(resp));
        if (!wire_recv_timeout(lsp->client_fds[ci], &resp, 60) ||
            resp.msg_type != MSG_PTLC_ADAPTED_SIG) {
            if (resp.json) cJSON_Delete(resp.json);
            fprintf(stderr, "LSP rotate: no adapted_sig from client %zu, skipping\n", ci);
            turnover_fail++;
            continue;
        }

        unsigned char adapted_sig[64];
        if (!wire_parse_ptlc_adapted_sig(resp.json, adapted_sig)) {
            cJSON_Delete(resp.json);
            fprintf(stderr, "LSP rotate: parse adapted_sig failed client %zu, skipping\n", ci);
            turnover_fail++;
            continue;
        }
        cJSON_Delete(resp.json);

        /* Extract client's secret key */
        unsigned char extracted[32];
        if (!adaptor_extract_secret(mgr->ctx, extracted, adapted_sig, presig,
                                      nonce_parity)) {
            fprintf(stderr, "LSP rotate: extract failed client %zu, skipping\n", ci);
            turnover_fail++;
            continue;
        }
        if (!adaptor_verify_extracted_key(mgr->ctx, extracted, &client_pk)) {
            fprintf(stderr, "LSP rotate: verify failed client %zu, skipping\n", ci);
            turnover_fail++;
            continue;
        }

        ladder_record_key_turnover(lad, dying_id, pidx, extracted);
        if (mgr->persist)
            persist_save_departed_client((persist_t *)mgr->persist,
                                          dying_id, pidx, extracted);

        /* Send PTLC_COMPLETE */
        cJSON *cm = wire_build_ptlc_complete();
        wire_send(lsp->client_fds[ci], MSG_PTLC_COMPLETE, cm);
        cJSON_Delete(cm);

        turnover_ok++;
        printf("LSP rotate: client %zu key extracted via wire PTLC\n", ci + 1);
    }
    printf("LSP rotate: Phase A complete — %zu/%zu clients cooperated (%zu failed)\n",
           turnover_ok, lsp->n_clients, turnover_fail);

    /* Probe client sockets: detect fds that are still positive but the
       remote end has closed (e.g., client disconnected after MSG_ERROR from
       a prior failed rotation).  Without this, subsequent checks would see
       stale fds as "online" and proceed with an irreversible close TX. */
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] < 0) continue;
        char probe;
        int rc = recv(lsp->client_fds[i], &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rc == 0) {
            /* EOF: remote end closed */
            printf("LSP rotate: client %zu socket closed (stale fd), marking offline\n", i);
            wire_close(lsp->client_fds[i]);
            lsp->client_fds[i] = -1;
        }
        /* rc > 0: data waiting (client still alive)
           rc < 0 && errno == EAGAIN/EWOULDBLOCK: no data but socket open (alive) */
    }

    /* Phase A.5: Close active JIT channels using extracted keys */
    if (mgr->jit_channels) {
        ladder_factory_t *dying_lf = ladder_get_by_id(lad, dying_id);
        regtest_t *jit_rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
        if (jit_rt) {
            for (size_t c = 0; c < mgr->n_channels; c++) {
                if (!jit_channel_is_active(mgr, c)) continue;
                size_t pidx = c + 1; /* participant index: 0=LSP, 1..N=clients */
                if (!dying_lf || !dying_lf->client_departed[pidx]) {
                    fprintf(stderr, "LSP rotate: client %zu JIT active but "
                            "key not extracted\n", c);
                    continue;
                }
                if (jit_channel_cooperative_close(mgr, c,
                        dying_lf->extracted_keys[pidx], jit_rt)) {
                    printf("LSP rotate: closed JIT channel for client %zu\n", c);
                } else {
                    fprintf(stderr, "LSP rotate: WARNING: could not close JIT "
                            "for client %zu (key mismatch or broadcast failure)\n",
                            c);
                }
            }
        }
    }

    /* Check if all online clients departed (full close) or partial.
       Even if all keys are extracted, only do full close when ALL clients
       are currently online — the close TX is irreversible, and the new
       factory ceremony requires every participant. */
    int full_close = ladder_can_close(lad, dying_id);
    int partial = 0;
    if (full_close) {
        size_t n_online = 0;
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (lsp->client_fds[i] >= 0)
                n_online++;
        }
        if (n_online < lsp->n_clients) {
            printf("LSP rotate: all keys extracted but only %zu/%zu online — "
                   "downgrading to partial rotation\n", n_online, lsp->n_clients);
            full_close = 0;
            partial = 1;
        }
    }
    if (!full_close && !partial) {
        partial = ladder_can_partial_close(lad, dying_id);
        if (!partial) {
            fprintf(stderr, "LSP rotate: < 2 clients departed, cannot rotate\n");
            return 0;
        }
        printf("LSP rotate: partial — %zu/%zu clients cooperative\n",
               dying->n_departed, dying->factory.n_participants - 1);
    }

    /* --- Phase B: Cooperative close OR partial retirement --- */
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
    if (!rt) {
        fprintf(stderr, "LSP rotate: no regtest connection\n");
        return 0;
    }

    if (full_close) {
        /* Full cooperative close of dying factory */
        printf("LSP rotate: Phase B — cooperative close of factory %u\n", dying_id);

        /* Get a wallet-controlled address for close outputs (UTXO recycling) */
        char wallet_addr[128];
        unsigned char wallet_spk[64];
        size_t wallet_spk_len = 0;
        const unsigned char *close_spk = NULL;
        size_t close_spk_len = 0;

        if (regtest_get_new_address(rt, wallet_addr, sizeof(wallet_addr)) &&
            regtest_get_address_scriptpubkey(rt, wallet_addr, wallet_spk, &wallet_spk_len)) {
            close_spk = wallet_spk;
            close_spk_len = wallet_spk_len;
            printf("LSP rotate: close outputs to wallet address %s\n", wallet_addr);
        } else {
            fprintf(stderr, "LSP rotate: WARNING: wallet address fetch failed, "
                    "using factory funding SPK (funds may strand)\n");
        }

        tx_output_t rot_outputs[FACTORY_MAX_SIGNERS];
        size_t close_vsize = 68 + 43 * n_total;
        uint64_t close_fee = fee_estimate(fe, close_vsize);
        if (close_fee == 0) {
            close_fee = (close_vsize * FEE_FLOOR_SAT_PER_KVB + 999) / 1000;
            if (close_fee == 0) close_fee = 1;
            fprintf(stderr, "LSP rotate: WARNING: fee estimation returned 0, "
                    "using %.1f sat/vB floor (%llu sats)\n",
                    (double)FEE_FLOOR_SAT_PER_KVB / 1000.0,
                    (unsigned long long)close_fee);
        }
        size_t n_close = lsp_channels_build_close_outputs(mgr, &lsp->factory,
                                                            rot_outputs, close_fee,
                                                            close_spk, close_spk_len);
        if (n_close == 0) {
            const unsigned char *fb_spk = close_spk ? close_spk : mgr->rot_fund_spk;
            size_t fb_spk_len = close_spk ? close_spk_len : 34;
            uint64_t per = (lsp->factory.funding_amount_sats - close_fee) / n_total;
            for (size_t ti = 0; ti < n_total; ti++) {
                rot_outputs[ti].amount_sats = per;
                memcpy(rot_outputs[ti].script_pubkey, fb_spk, fb_spk_len);
                rot_outputs[ti].script_pubkey_len = fb_spk_len;
            }
            rot_outputs[n_total - 1].amount_sats =
                lsp->factory.funding_amount_sats - close_fee - per * (n_total - 1);
            n_close = n_total;
        }

        tx_buf_t rot_close_tx;
        tx_buf_init(&rot_close_tx, 512);
        if (!ladder_build_close(lad, dying_id, &rot_close_tx, rot_outputs, n_close,
                                  rt ? (uint32_t)regtest_get_block_height(rt) : 0)) {
            fprintf(stderr, "LSP rotate: ladder_build_close failed\n");
            tx_buf_free(&rot_close_tx);
            return 0;
        }

        char *rc_hex = malloc(rot_close_tx.len * 2 + 1);
        if (!rc_hex) {
            fprintf(stderr, "LSP rotate: malloc failed for close TX hex\n");
            tx_buf_free(&rot_close_tx);
            return 0;
        }
        hex_encode(rot_close_tx.data, rot_close_tx.len, rc_hex);
        char rc_txid[65];
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
            int rot_timeout = mgr->confirm_timeout_secs > 0 ?
                              mgr->confirm_timeout_secs : 7200;
            printf("LSP rotate: waiting for close TX confirmation...\n");
            int confirmed = 0;
            for (int attempt = 0; attempt < 2; attempt++) {
                if (regtest_wait_for_confirmation(rt, rc_txid, rot_timeout) >= 1) {
                    confirmed = 1;
                    break;
                }
                if (regtest_is_in_mempool(rt, rc_txid)) {
                    fprintf(stderr, "LSP rotate: close TX still in mempool, "
                            "extending wait (attempt %d)\n", attempt + 1);
                    continue;
                }
                fprintf(stderr, "LSP rotate: close TX %s dropped from mempool\n",
                        rc_txid);
                break;
            }
            if (!confirmed) {
                fprintf(stderr, "LSP rotate: close TX not confirmed after retries\n");
                return 0;
            }
        }
        printf("LSP rotate: factory %u closed: %s\n", dying_id, rc_txid);
        /* Mark as rotated so CLI "rotate" won't try to rotate it again */
        dying->partial_rotation_done = 1;
    } else {
        /* Partial rotation: skip cooperative close, old factory expires naturally.
           The distribution TX (nLockTime) protects all participants. */
        printf("LSP rotate: Phase B — partial retirement of factory %u "
               "(distribution TX on expiry)\n", dying_id);
        dying->partial_rotation_done = 1;
        if (mgr->persist) {
            const char *st = "dying";
            persist_save_ladder_factory((persist_t *)mgr->persist,
                dying_id, st, dying->is_funded, dying->is_initialized,
                dying->n_departed, dying->factory.created_block,
                dying->factory.active_blocks, dying->factory.dying_blocks,
                dying->partial_rotation_done);
        }
    }

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
        int rot_timeout = mgr->confirm_timeout_secs > 0 ?
                          mgr->confirm_timeout_secs : 7200;
        printf("LSP rotate: waiting for funding confirmation...\n");
        int confirmed = 0;
        for (int attempt = 0; attempt < 2; attempt++) {
            if (regtest_wait_for_confirmation(rt, fund_txid_hex, rot_timeout) >= 1) {
                confirmed = 1;
                break;
            }
            if (regtest_is_in_mempool(rt, fund_txid_hex)) {
                fprintf(stderr, "LSP rotate: funding TX still in mempool, "
                        "extending wait (attempt %d)\n", attempt + 1);
                continue;
            }
            fprintf(stderr, "LSP rotate: funding TX %s dropped from mempool\n",
                    fund_txid_hex);
            break;
        }
        if (!confirmed) {
            fprintf(stderr, "LSP rotate: funding not confirmed after retries\n");
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

    /* For partial rotation: remap client arrays to cooperative subset */
    int saved_client_fds[LSP_MAX_CLIENTS];
    secp256k1_pubkey saved_client_pks[LSP_MAX_CLIENTS];
    size_t n_coop = 0;

    memset(saved_client_fds, -1, sizeof(saved_client_fds));
    memset(saved_client_pks, 0, sizeof(saved_client_pks));

    if (partial) {
        memcpy(saved_client_fds, lsp->client_fds, sizeof(saved_client_fds));
        memcpy(saved_client_pks, lsp->client_pubkeys, sizeof(saved_client_pks));

        uint32_t coop[FACTORY_MAX_SIGNERS];
        n_coop = ladder_get_cooperative_clients(lad, dying_id,
                                                 coop, FACTORY_MAX_SIGNERS);

        /* Remap to contiguous indices, skipping clients whose fd went stale */
        size_t n_online = 0;
        for (size_t i = 0; i < n_coop; i++) {
            int fd = saved_client_fds[coop[i] - 1];
            if (fd >= 0) {
                lsp->client_fds[n_online] = fd;
                lsp->client_pubkeys[n_online] = saved_client_pks[coop[i] - 1];
                n_online++;
            } else {
                printf("LSP rotate: cooperative client %u went offline, skipping\n",
                       coop[i]);
            }
        }
        if (n_online < 2) {
            fprintf(stderr, "LSP rotate: only %zu online clients, need >= 2\n",
                    n_online);
            /* Restore original client arrays */
            memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
            memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
            lsp->n_clients = (size_t)mgr->n_channels;
            return 0;
        }
        lsp->n_clients = n_online;
        printf("LSP rotate: remapped %zu/%zu cooperative clients for new factory\n",
               n_online, n_coop);
    } else {
        /* Full close: verify all clients still online */
        size_t n_online = 0;
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (lsp->client_fds[i] >= 0)
                n_online++;
        }
        if (n_online < lsp->n_clients) {
            printf("LSP rotate: %zu/%zu clients online for full close\n",
                   n_online, lsp->n_clients);
        }
    }

    /* Verify ALL participating clients are still connected before committing
       to new factory.  Factory creation sends FACTORY_PROPOSE to every client;
       if any is offline the ceremony fails AFTER we've already freed the old
       factory, leaving the daemon in a broken state. */
    {
        size_t online = 0;
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (lsp->client_fds[i] >= 0)
                online++;
        }
        if (online < lsp->n_clients) {
            fprintf(stderr, "LSP rotate: only %zu/%zu clients online before "
                    "factory creation, aborting (factory preserved)\n",
                    online, lsp->n_clients);
            if (partial) {
                memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
                memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
                lsp->n_clients = (size_t)mgr->n_channels;
            }
            return 0;
        }
    }

    /* Free old factory, preserve arity for new factory.
       Ladder entries use detached copies (factory_detach_txbufs) so they
       don't share heap data — no risk of double-free from ladder. */
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
        /* Factory is already freed — restore client arrays so daemon
           can still service existing connections without crashing. */
        if (partial) {
            memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
            memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
            lsp->n_clients = (size_t)mgr->n_channels;
        }
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
        factory_detach_txbufs(&lf_new->factory);
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

    /* Close fds for uncooperative clients (partial rotation only) */
    if (partial) {
        uint32_t uncoop[FACTORY_MAX_SIGNERS];
        size_t n_uncoop = ladder_get_uncooperative_clients(lad, dying_id,
                                                            uncoop, FACTORY_MAX_SIGNERS);
        for (size_t i = 0; i < n_uncoop; i++) {
            int fd = saved_client_fds[uncoop[i] - 1];
            if (fd >= 0) wire_close(fd);
        }
        printf("LSP rotate: closed %zu uncooperative client connections\n", n_uncoop);
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
    uint8_t  saved_retry_count[8];
    uint32_t saved_last_attempt_block[8];
    uint32_t saved_max_retries = mgr->rot_max_retries;
    uint32_t saved_retry_base_delay = mgr->rot_retry_base_delay;
    memcpy(saved_retry_count, mgr->rot_retry_count, sizeof(saved_retry_count));
    memcpy(saved_last_attempt_block, mgr->rot_last_attempt_block,
           sizeof(saved_last_attempt_block));
    int saved_cli_enabled = mgr->cli_enabled;
    int saved_confirm_timeout = mgr->confirm_timeout_secs;

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
    memcpy(mgr->rot_retry_count, saved_retry_count, sizeof(saved_retry_count));
    memcpy(mgr->rot_last_attempt_block, saved_last_attempt_block,
           sizeof(saved_last_attempt_block));
    mgr->rot_max_retries = saved_max_retries;
    mgr->rot_retry_base_delay = saved_retry_base_delay;
    mgr->jit_channels = saved_jit;
    mgr->n_jit_channels = saved_n_jit;
    mgr->jit_enabled = saved_jit_enabled;
    mgr->jit_funding_sats = saved_jit_funding;
    mgr->cli_enabled = saved_cli_enabled;
    mgr->confirm_timeout_secs = saved_confirm_timeout;

    if (!lsp_channels_exchange_basepoints(mgr, lsp)) {
        fprintf(stderr, "LSP rotate: basepoint exchange failed\n");
        return 0;
    }

    /* Set fee rate on all new channels */
    uint64_t fee_rate = fe->get_rate(fe, FEE_TARGET_NORMAL);
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
            channel_t *ch = &mgr->entries[c].channel;
            if (!persist_save_channel(db, ch, 0, (uint32_t)c) ||
                !persist_save_basepoints(db, (uint32_t)c, ch)) {
                ch_ok = 0;
                break;
            }
            /* Persist remote PCPs (cn=0,1) so reconnect doesn't load
               stale values from the old channel at the same slot. */
            unsigned char pcp_ser[33];
            size_t pcp_len = 33;
            secp256k1_pubkey pcp;
            if (channel_get_remote_pcp(ch, 0, &pcp) &&
                secp256k1_ec_pubkey_serialize(mgr->ctx, pcp_ser, &pcp_len,
                    &pcp, SECP256K1_EC_COMPRESSED))
                persist_save_remote_pcp(db, (uint32_t)c, 0, pcp_ser);
            pcp_len = 33;
            if (channel_get_remote_pcp(ch, 1, &pcp) &&
                secp256k1_ec_pubkey_serialize(mgr->ctx, pcp_ser, &pcp_len,
                    &pcp, SECP256K1_EC_COMPRESSED))
                persist_save_remote_pcp(db, (uint32_t)c, 1, pcp_ser);
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
