#include "superscalar/jit_channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp.h"
#include "superscalar/wire.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/fee.h"
#include "superscalar/persist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

const char *jit_state_to_str(jit_state_t state) {
    switch (state) {
    case JIT_STATE_NONE:      return "none";
    case JIT_STATE_FUNDING:   return "funding";
    case JIT_STATE_OPEN:      return "open";
    case JIT_STATE_MIGRATING: return "migrating";
    case JIT_STATE_CLOSED:    return "closed";
    default:                  return "unknown";
    }
}

jit_state_t jit_state_from_str(const char *str) {
    if (!str) return JIT_STATE_NONE;
    if (strcmp(str, "funding") == 0)   return JIT_STATE_FUNDING;
    if (strcmp(str, "open") == 0)      return JIT_STATE_OPEN;
    if (strcmp(str, "migrating") == 0) return JIT_STATE_MIGRATING;
    if (strcmp(str, "closed") == 0)    return JIT_STATE_CLOSED;
    return JIT_STATE_NONE;
}

int jit_channels_init(void *mgr_ptr) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    if (!mgr) return 0;

    if (!mgr->jit_channels) {
        mgr->jit_channels = calloc(JIT_MAX_CHANNELS, sizeof(jit_channel_t));
        if (!mgr->jit_channels) return 0;
    } else {
        memset(mgr->jit_channels, 0, JIT_MAX_CHANNELS * sizeof(jit_channel_t));
    }
    mgr->n_jit_channels = 0;
    mgr->jit_enabled = 1;
    return 1;
}

jit_channel_t *jit_channel_find(void *mgr_ptr, size_t client_idx) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    if (!mgr || !mgr->jit_channels) return NULL;
    jit_channel_t *jits = (jit_channel_t *)mgr->jit_channels;
    for (size_t i = 0; i < mgr->n_jit_channels; i++) {
        if (jits[i].client_idx == client_idx &&
            jits[i].state != JIT_STATE_NONE &&
            jits[i].state != JIT_STATE_CLOSED)
            return &jits[i];
    }
    return NULL;
}

int jit_channel_is_active(void *mgr_ptr, size_t client_idx) {
    jit_channel_t *jit = jit_channel_find(mgr_ptr, client_idx);
    return (jit && jit->state == JIT_STATE_OPEN) ? 1 : 0;
}

channel_t *jit_get_effective_channel(void *mgr_ptr, size_t client_idx,
                                      uint32_t *channel_id_out) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    if (!mgr) return NULL;

    /* Prefer factory channel when ready */
    if (client_idx < mgr->n_channels && mgr->entries[client_idx].ready) {
        if (channel_id_out)
            *channel_id_out = mgr->entries[client_idx].channel_id;
        return &mgr->entries[client_idx].channel;
    }

    /* Fall back to JIT channel */
    jit_channel_t *jit = jit_channel_find(mgr_ptr, client_idx);
    if (jit && jit->state == JIT_STATE_OPEN) {
        if (channel_id_out)
            *channel_id_out = jit->jit_channel_id;
        return &jit->channel;
    }

    return NULL;
}

int jit_channel_create(void *mgr_ptr, void *lsp_ptr,
                        size_t client_idx, uint64_t funding_amount,
                        const char *reason) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    lsp_t *lsp = (lsp_t *)lsp_ptr;
    if (!mgr || !lsp || !mgr->jit_channels) return 0;
    if (client_idx >= mgr->n_channels) return 0;
    if (lsp->client_fds[client_idx] < 0) return 0;
    if (mgr->n_jit_channels >= JIT_MAX_CHANNELS) return 0;

    /* Already have an active JIT channel for this client? */
    if (jit_channel_is_active(mgr, client_idx)) return 1;

    jit_channel_t *jits = (jit_channel_t *)mgr->jit_channels;
    jit_channel_t *jit = &jits[mgr->n_jit_channels];
    memset(jit, 0, sizeof(*jit));
    jit->client_idx = client_idx;
    jit->jit_channel_id = JIT_CHANNEL_ID_BASE | (uint32_t)client_idx;
    jit->funding_amount = funding_amount;
    jit->created_at = time(NULL);
    jit->state = JIT_STATE_FUNDING;

    /* Get LSP pubkey */
    secp256k1_pubkey lsp_pubkey;
    /* Use the LSP's rotation secret key if available */
    unsigned char lsp_seckey[32];
    int have_seckey = 0;
    if (memcmp(mgr->rot_lsp_seckey, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
               "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32) != 0) {
        memcpy(lsp_seckey, mgr->rot_lsp_seckey, 32);
        have_seckey = 1;
    } else {
        /* Fallback: use channel's local funding secret */
        memcpy(lsp_seckey, mgr->entries[0].channel.local_funding_secret, 32);
        have_seckey = 1;
    }
    if (!have_seckey || !secp256k1_ec_pubkey_create(mgr->ctx, &lsp_pubkey, lsp_seckey)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Send MSG_JIT_OFFER */
    cJSON *offer = wire_build_jit_offer(client_idx, funding_amount, reason,
                                          mgr->ctx, &lsp_pubkey);
    if (!wire_send(lsp->client_fds[client_idx], MSG_JIT_OFFER, offer)) {
        cJSON_Delete(offer);
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(offer);

    /* Wait for MSG_JIT_ACCEPT (30s timeout) */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(lsp->client_fds[client_idx], &rfds);
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    int ret = select(lsp->client_fds[client_idx] + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) {
        fprintf(stderr, "LSP JIT: timeout waiting for JIT_ACCEPT from client %zu\n",
                client_idx);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    wire_msg_t accept_msg;
    if (!wire_recv(lsp->client_fds[client_idx], &accept_msg) ||
        accept_msg.msg_type != MSG_JIT_ACCEPT) {
        if (accept_msg.json) cJSON_Delete(accept_msg.json);
        fprintf(stderr, "LSP JIT: expected JIT_ACCEPT, got 0x%02x\n",
                accept_msg.msg_type);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    size_t parsed_cidx;
    secp256k1_pubkey client_pubkey;
    if (!wire_parse_jit_accept(accept_msg.json, mgr->ctx, &parsed_cidx,
                                 &client_pubkey)) {
        cJSON_Delete(accept_msg.json);
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(accept_msg.json);

    /* Fund the JIT channel on-chain */
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
    if (!rt) {
        fprintf(stderr, "LSP JIT: no regtest connection for funding\n");
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Build 2-of-2 MuSig2 funding key */
    secp256k1_pubkey funding_pks[2] = { lsp_pubkey, client_pubkey };
    musig_keyagg_t jit_ka;
    musig_aggregate_keys(mgr->ctx, &jit_ka, funding_pks, 2);

    /* Build P2TR funding SPK from aggregated key */
    unsigned char agg_ser[32];
    secp256k1_pubkey agg_pk;
    secp256k1_xonly_pubkey agg_xonly;
    if (!secp256k1_musig_pubkey_get(mgr->ctx, &agg_pk, &jit_ka.cache))
        return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(mgr->ctx, &agg_xonly, NULL, &agg_pk))
        return 0;
    if (!secp256k1_xonly_pubkey_serialize(mgr->ctx, agg_ser, &agg_xonly))
        return 0;

    unsigned char funding_spk[34];
    funding_spk[0] = 0x51;  /* OP_1 */
    funding_spk[1] = 0x20;  /* push 32 */
    memcpy(funding_spk + 2, agg_ser, 32);
    size_t funding_spk_len = 34;

    /* Use the same funding address derivation as the main factory */
    char funding_addr[128];
    if (mgr->rot_fund_addr[0]) {
        snprintf(funding_addr, sizeof(funding_addr), "%s", mgr->rot_fund_addr);
    } else {
        /* Can't derive address without bitcoin-cli, use raw funding */
        fprintf(stderr, "LSP JIT: no funding address configured\n");
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    double funding_btc = (double)funding_amount / 100000000.0;
    char fund_txid_hex[65];
    if (!regtest_fund_address(rt, funding_addr, funding_btc, fund_txid_hex)) {
        fprintf(stderr, "LSP JIT: funding failed\n");
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Confirm funding */
    if (mgr->rot_is_regtest) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
    } else {
        int jit_timeout = mgr->confirm_timeout_secs > 0 ?
                          mgr->confirm_timeout_secs : 7200;
        int confirmed = 0;
        for (int attempt = 0; attempt < 2; attempt++) {
            if (regtest_wait_for_confirmation(rt, fund_txid_hex, jit_timeout) >= 1) {
                confirmed = 1;
                break;
            }
            /* Check if tx is still in mempool — if so, keep waiting */
            if (regtest_is_in_mempool(rt, fund_txid_hex)) {
                fprintf(stderr, "LSP JIT: funding still in mempool, "
                        "extending wait (attempt %d)\n", attempt + 1);
                continue;
            }
            /* Tx dropped from mempool — cannot recover here */
            fprintf(stderr, "LSP JIT: funding tx %s dropped from mempool\n",
                    fund_txid_hex);
            break;
        }
        if (!confirmed) {
            fprintf(stderr, "LSP JIT: funding not confirmed after retries\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
    }

    /* Get funding output details */
    unsigned char fund_txid[32];
    hex_decode(fund_txid_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);

    uint64_t actual_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t fund_vout = 0;
    for (uint32_t v = 0; v < 4; v++) {
        regtest_get_tx_output(rt, fund_txid_hex, v,
                              &actual_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == funding_spk_len &&
            memcmp(actual_spk, funding_spk, funding_spk_len) == 0) {
            fund_vout = v;
            break;
        }
    }
    if (actual_amount == 0) {
        /* Fallback: use vout 0 and trust the amount */
        fund_vout = 0;
        actual_amount = funding_amount;
    }

    strncpy(jit->funding_txid_hex, fund_txid_hex, 64);
    jit->funding_txid_hex[64] = '\0';
    jit->funding_vout = fund_vout;
    jit->funding_amount = actual_amount;
    jit->funding_confirmed = 1;

    /* Persist the raw funding tx hex for crash recovery */
    jit->funding_tx_hex[0] = '\0';
    regtest_get_raw_tx(rt, fund_txid_hex,
                       jit->funding_tx_hex, sizeof(jit->funding_tx_hex));
    /* Log the broadcast */
    if (mgr->persist) {
        persist_log_broadcast((persist_t *)mgr->persist, fund_txid_hex,
                              "jit_funding", jit->funding_tx_hex, "ok");
    }

    /* Get current block height */
    int cur_h = regtest_get_block_height(rt);
    jit->created_block = (cur_h > 0) ? (uint32_t)cur_h : 0;

    /* Initialize channel_t for the JIT channel */
    fee_estimator_t jit_fe;
    fee_init(&jit_fe, 1000);
    uint64_t commit_fee = fee_for_commitment_tx(&jit_fe, 0);
    uint64_t usable = actual_amount > commit_fee ? actual_amount - commit_fee : 0;
    uint64_t local_amount = usable / 2;
    uint64_t remote_amount = usable - local_amount;

    if (!channel_init(&jit->channel, mgr->ctx,
                       lsp_seckey, &lsp_pubkey, &client_pubkey,
                       fund_txid, fund_vout, actual_amount,
                       funding_spk, funding_spk_len,
                       local_amount, remote_amount,
                       CHANNEL_DEFAULT_CSV_DELAY)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    jit->channel.funder_is_local = 1;

    /* Generate random basepoints */
    if (!channel_generate_random_basepoints(&jit->channel)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Exchange basepoints */
    {
        secp256k1_pubkey first_pcp, second_pcp;
        channel_get_per_commitment_point(&jit->channel, 0, &first_pcp);
        channel_get_per_commitment_point(&jit->channel, 1, &second_pcp);

        cJSON *bp = wire_build_channel_basepoints(
            jit->jit_channel_id, mgr->ctx,
            &jit->channel.local_payment_basepoint,
            &jit->channel.local_delayed_payment_basepoint,
            &jit->channel.local_revocation_basepoint,
            &jit->channel.local_htlc_basepoint,
            &first_pcp, &second_pcp);
        if (!wire_send(lsp->client_fds[client_idx], MSG_CHANNEL_BASEPOINTS, bp)) {
            cJSON_Delete(bp);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        cJSON_Delete(bp);
    }

    /* Receive client's basepoints */
    {
        wire_msg_t bp_msg;
        if (!wire_recv(lsp->client_fds[client_idx], &bp_msg) ||
            bp_msg.msg_type != MSG_CHANNEL_BASEPOINTS) {
            if (bp_msg.json) cJSON_Delete(bp_msg.json);
            memset(lsp_seckey, 0, 32);
            return 0;
        }

        uint32_t bp_ch_id;
        secp256k1_pubkey pay_bp, delay_bp, revoc_bp, htlc_bp, first_pcp, second_pcp;
        if (!wire_parse_channel_basepoints(bp_msg.json, &bp_ch_id, mgr->ctx,
                                             &pay_bp, &delay_bp, &revoc_bp, &htlc_bp,
                                             &first_pcp, &second_pcp)) {
            cJSON_Delete(bp_msg.json);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        cJSON_Delete(bp_msg.json);

        channel_set_remote_basepoints(&jit->channel, &pay_bp, &delay_bp, &revoc_bp);
        channel_set_remote_htlc_basepoint(&jit->channel, &htlc_bp);
        channel_set_remote_pcp(&jit->channel, 0, &first_pcp);
        channel_set_remote_pcp(&jit->channel, 1, &second_pcp);
    }

    /* Initialize nonce pool */
    if (!channel_init_nonce_pool(&jit->channel, MUSIG_NONCE_POOL_MAX)) {
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Exchange nonces */
    {
        size_t nc = jit->channel.local_nonce_pool.count;
        unsigned char (*pn_ser)[66] = calloc(nc, 66);
        if (!pn_ser) { memset(lsp_seckey, 0, 32); return 0; }

        for (size_t i = 0; i < nc; i++)
            musig_pubnonce_serialize(mgr->ctx, pn_ser[i],
                                      &jit->channel.local_nonce_pool.nonces[i].pubnonce);

        cJSON *nm = wire_build_channel_nonces(jit->jit_channel_id,
                                                (const unsigned char (*)[66])pn_ser, nc);
        int ok = wire_send(lsp->client_fds[client_idx], MSG_CHANNEL_NONCES, nm);
        cJSON_Delete(nm);
        free(pn_ser);
        if (!ok) { memset(lsp_seckey, 0, 32); return 0; }
    }

    /* Receive client nonces */
    {
        wire_msg_t nm;
        if (!wire_recv(lsp->client_fds[client_idx], &nm) ||
            nm.msg_type != MSG_CHANNEL_NONCES) {
            if (nm.json) cJSON_Delete(nm.json);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        uint32_t nm_ch_id;
        unsigned char client_nonces[MUSIG_NONCE_POOL_MAX][66];
        size_t cnt;
        if (!wire_parse_channel_nonces(nm.json, &nm_ch_id, client_nonces,
                                         MUSIG_NONCE_POOL_MAX, &cnt)) {
            cJSON_Delete(nm.json);
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        cJSON_Delete(nm.json);
        channel_set_remote_pubnonces(&jit->channel,
                                       (const unsigned char (*)[66])client_nonces, cnt);
    }

    /* Send MSG_JIT_READY */
    cJSON *ready = wire_build_jit_ready(jit->jit_channel_id,
                                          fund_txid_hex, fund_vout,
                                          actual_amount,
                                          local_amount, remote_amount);
    wire_send(lsp->client_fds[client_idx], MSG_JIT_READY, ready);
    cJSON_Delete(ready);

    jit->state = JIT_STATE_OPEN;
    mgr->n_jit_channels++;

    /* Register JIT channel with watchtower */
    if (mgr->watchtower) {
        size_t wt_idx = mgr->n_channels + client_idx;
        watchtower_set_channel(mgr->watchtower, wt_idx, &jit->channel);
    }

    /* Persist (transactional) */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        if (!persist_begin(db)) {
            fprintf(stderr, "LSP JIT: persist_begin failed\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        if (!persist_save_jit_channel(db, jit) ||
            !persist_save_basepoints(db, jit->jit_channel_id, &jit->channel)) {
            fprintf(stderr, "LSP JIT: persist failed, rolling back\n");
            persist_rollback(db);
            memset(lsp_seckey, 0, 32);
            return 0;
        } else {
            persist_commit(db);
        }
    }

    memset(lsp_seckey, 0, 32);
    printf("LSP JIT: channel %08x open for client %zu (%llu sats)\n",
           jit->jit_channel_id, client_idx,
           (unsigned long long)actual_amount);
    return 1;
}

int jit_channel_migrate(void *mgr_ptr, void *lsp_ptr,
                         size_t client_idx, uint32_t target_factory_id) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    lsp_t *lsp = (lsp_t *)lsp_ptr;
    if (!mgr) return 0;

    jit_channel_t *jit = jit_channel_find(mgr, client_idx);
    if (!jit || jit->state != JIT_STATE_OPEN) return 0;

    jit->state = JIT_STATE_MIGRATING;
    jit->target_factory_id = target_factory_id;

    /* Send MSG_JIT_MIGRATE to client (skip if no lsp/fd) */
    if (lsp) {
        cJSON *mig = wire_build_jit_migrate(jit->jit_channel_id,
                                               target_factory_id,
                                               jit->channel.local_amount,
                                               jit->channel.remote_amount);
        if (lsp->client_fds[client_idx] >= 0)
            wire_send(lsp->client_fds[client_idx], MSG_JIT_MIGRATE, mig);
        cJSON_Delete(mig);
    }

    /* Account for JIT balance in the new factory channel */
    if (client_idx < mgr->n_channels && mgr->entries[client_idx].ready) {
        channel_t *factory_ch = &mgr->entries[client_idx].channel;
        /* The remote_amount in JIT (client's money) should be reflected
           in the factory channel. For PoC, we adjust balances directly. */
        factory_ch->local_amount += jit->channel.local_amount;
        factory_ch->remote_amount += jit->channel.remote_amount;
    }

    /* Close the JIT channel */
    jit->state = JIT_STATE_CLOSED;

    /* Remove watchtower entries for this JIT channel */
    if (mgr->watchtower) {
        size_t wt_idx = mgr->n_channels + client_idx;
        watchtower_remove_channel(mgr->watchtower, (uint32_t)wt_idx);
        mgr->watchtower->channels[wt_idx] = NULL;
    }

    /* Remove from persistence */
    if (mgr->persist)
        persist_delete_jit_channel((persist_t *)mgr->persist, jit->jit_channel_id);

    printf("LSP JIT: channel %08x migrated to factory %u "
           "(local=%llu, remote=%llu)\n",
           jit->jit_channel_id, target_factory_id,
           (unsigned long long)jit->channel.local_amount,
           (unsigned long long)jit->channel.remote_amount);
    return 1;
}

int jit_channels_check_funding(void *mgr_ptr) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    if (!mgr || !mgr->jit_channels) return 0;
    if (!mgr->watchtower || !mgr->watchtower->rt) return 0;

    jit_channel_t *jits = (jit_channel_t *)mgr->jit_channels;
    int transitions = 0;

    for (size_t i = 0; i < mgr->n_jit_channels; i++) {
        if (jits[i].state != JIT_STATE_FUNDING) continue;
        if (jits[i].funding_txid_hex[0] == '\0') continue;

        int conf = regtest_get_confirmations(mgr->watchtower->rt,
                                               jits[i].funding_txid_hex);
        if (conf >= 1) {
            jits[i].state = JIT_STATE_OPEN;
            jits[i].funding_confirmed = 1;
            printf("LSP JIT: channel %08x funding confirmed (%d conf)\n",
                   jits[i].jit_channel_id, conf);

            /* Register with watchtower */
            if (mgr->watchtower) {
                size_t wt_idx = mgr->n_channels + jits[i].client_idx;
                watchtower_set_channel(mgr->watchtower, wt_idx, &jits[i].channel);
            }

            /* Persist state change */
            if (mgr->persist)
                persist_update_jit_state((persist_t *)mgr->persist,
                                           jits[i].jit_channel_id, "open");
            transitions++;
        }
    }
    return transitions;
}

void jit_channels_cleanup(void *mgr_ptr) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    if (!mgr) return;
    if (mgr->jit_channels) {
        free(mgr->jit_channels);
        mgr->jit_channels = NULL;
    }
    mgr->n_jit_channels = 0;
}
