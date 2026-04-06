#include "superscalar/jit_channel.h"
#include "superscalar/chain_backend.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp.h"
#include "superscalar/wire.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/lsp_fund.h"
#include "superscalar/chain_backend.h"
#include "superscalar/fee.h"
#include "superscalar/persist.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
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

    if (!mgr->jit_channels_cap) mgr->jit_channels_cap = JIT_MAX_CHANNELS;
    if (!mgr->jit_channels) {
        mgr->jit_channels = calloc(mgr->jit_channels_cap, sizeof(jit_channel_t));
        if (!mgr->jit_channels) return 0;
    } else {
        memset(mgr->jit_channels, 0, mgr->jit_channels_cap * sizeof(jit_channel_t));
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
    if (mgr->n_jit_channels >= mgr->jit_channels_cap) return 0;

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

    /* Wait for MSG_JIT_ACCEPT — drain any stale messages (e.g. REGISTER_INVOICE
       from demo phase) that arrive before the accept.  30s total timeout. */
    wire_msg_t accept_msg;
    int got_accept = 0;
    for (int attempt = 0; attempt < 30; attempt++) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsp->client_fds[client_idx], &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(lsp->client_fds[client_idx] + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) continue;  /* 1s timeout, retry */
        if (!wire_recv(lsp->client_fds[client_idx], &accept_msg)) {
            fprintf(stderr, "LSP JIT: wire_recv failed waiting for JIT_ACCEPT\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        if (accept_msg.msg_type == MSG_JIT_ACCEPT) {
            got_accept = 1;
            break;
        }
        /* Discard stale message and keep waiting */
        fprintf(stderr, "LSP JIT: discarding stale msg 0x%02x while waiting for JIT_ACCEPT\n",
                accept_msg.msg_type);
        cJSON_Delete(accept_msg.json);
    }
    if (!got_accept) {
        fprintf(stderr, "LSP JIT: timeout waiting for JIT_ACCEPT from client %zu\n",
                client_idx);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    size_t parsed_cidx;
    secp256k1_pubkey client_pubkey;
    if (!wire_parse_jit_accept(accept_msg.json, mgr->ctx, &parsed_cidx,
                                 &client_pubkey)) {
        fprintf(stderr, "LSP JIT: wire_parse_jit_accept failed\n");
        cJSON_Delete(accept_msg.json);
        memset(lsp_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(accept_msg.json);

    /* Fund the JIT channel on-chain */
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
    chain_backend_t *chain_be = (chain_backend_t *)mgr->chain_be;
    wallet_source_t *wallet_src = (wallet_source_t *)mgr->wallet_src;
    if (!rt && !chain_be) {
        fprintf(stderr, "LSP JIT: no chain connection for funding\n");
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    /* Build 2-of-2 MuSig2 funding key */
    secp256k1_pubkey funding_pks[2] = { lsp_pubkey, client_pubkey };
    musig_keyagg_t jit_ka;
    musig_aggregate_keys(mgr->ctx, &jit_ka, funding_pks, 2);

    /* Serialize the internal (untweaked) aggregate key */
    unsigned char agg_ser[32];
    secp256k1_pubkey agg_pk;
    secp256k1_xonly_pubkey agg_xonly;
    if (!secp256k1_musig_pubkey_get(mgr->ctx, &agg_pk, &jit_ka.cache))
        { fprintf(stderr, "LSP JIT: musig_pubkey_get failed\n"); memset(lsp_seckey, 0, 32); return 0; }
    if (!secp256k1_xonly_pubkey_from_pubkey(mgr->ctx, &agg_xonly, NULL, &agg_pk))
        { fprintf(stderr, "LSP JIT: xonly_from_pubkey failed\n"); memset(lsp_seckey, 0, 32); return 0; }
    if (!secp256k1_xonly_pubkey_serialize(mgr->ctx, agg_ser, &agg_xonly))
        { fprintf(stderr, "LSP JIT: xonly_serialize failed\n"); memset(lsp_seckey, 0, 32); return 0; }

    /* TapTweak (key-path-only, no script tree) */
    unsigned char tweak[32];
    sha256_tagged("TapTweak", agg_ser, 32, tweak);

    musig_keyagg_t jit_ka_tweak = jit_ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(mgr->ctx, &tweaked_pk,
                                                  &jit_ka_tweak.cache, tweak))
        { fprintf(stderr, "LSP JIT: tweak_add failed\n"); memset(lsp_seckey, 0, 32); return 0; }
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(mgr->ctx, &tweaked_xonly, NULL, &tweaked_pk))
        { fprintf(stderr, "LSP JIT: tweaked xonly failed\n"); memset(lsp_seckey, 0, 32); return 0; }

    /* Build correct P2TR funding SPK from tweaked key */
    unsigned char funding_spk[34];
    build_p2tr_script_pubkey(funding_spk, &tweaked_xonly);
    size_t funding_spk_len = 34;

    char fund_txid_hex[65];
    if (rt) {
        /* Full-node mode: Core wallet funds via sendtoaddress */
        unsigned char tweaked_ser[32];
        if (!secp256k1_xonly_pubkey_serialize(mgr->ctx, tweaked_ser, &tweaked_xonly))
            { memset(lsp_seckey, 0, 32); return 0; }
        char funding_addr[128];
        if (!regtest_derive_p2tr_address(rt, tweaked_ser, funding_addr, sizeof(funding_addr))) {
            fprintf(stderr, "LSP JIT: failed to derive JIT funding address\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        double funding_btc = (double)funding_amount / 100000000.0;
        if (!regtest_fund_address(rt, funding_addr, funding_btc, fund_txid_hex)) {
            fprintf(stderr, "LSP JIT: funding failed\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
    } else {
        /* Light-client mode: HD wallet builds and signs funding tx */
        if (!wallet_src) {
            fprintf(stderr, "LSP JIT: no wallet for light-client funding\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
        if (!lsp_fund_spk(wallet_src, chain_be,
                          funding_spk, funding_spk_len,
                          funding_amount, 0, fund_txid_hex)) {
            fprintf(stderr, "LSP JIT: light-client funding failed\n");
            memset(lsp_seckey, 0, 32);
            return 0;
        }
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
        fprintf(stderr, "LSP JIT: funding output SPK mismatch in tx %s\n",
                fund_txid_hex);
        memset(lsp_seckey, 0, 32);
        return 0;
    }

    memcpy(jit->funding_txid_hex, fund_txid_hex, 64);
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
    fee_estimator_static_t jit_fe_default;
    fee_estimator_t *jit_fe = (fee_estimator_t *)mgr->fee;
    if (!jit_fe) { fee_estimator_static_init(&jit_fe_default, 1000); jit_fe = &jit_fe_default.base; }
    uint64_t commit_fee = fee_for_commitment_tx(jit_fe, 0);
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
    if (jit_fe) channel_set_fee_rate(&jit->channel, jit_fe->get_rate(jit_fe, FEE_TARGET_NORMAL));

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

int jit_channel_cooperative_close(void *mgr_ptr, size_t client_idx,
                                   const unsigned char *extracted_client_key,
                                   void *chain_be_ptr) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    chain_backend_t *chain_be = (chain_backend_t *)chain_be_ptr;
    if (!mgr || !extracted_client_key || !chain_be) return 0;
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;

    jit_channel_t *jit = jit_channel_find(mgr, client_idx);
    if (!jit || jit->state != JIT_STATE_OPEN) return 0;

    /* Verify extracted key matches jit->channel.remote_funding_pubkey */
    secp256k1_pubkey extracted_pk;
    if (!secp256k1_ec_pubkey_create(mgr->ctx, &extracted_pk, extracted_client_key)) {
        fprintf(stderr, "LSP JIT close: invalid extracted key for client %zu\n",
                client_idx);
        return 0;
    }
    unsigned char ser_extracted[33], ser_remote[33];
    size_t l1 = 33, l2 = 33;
    secp256k1_ec_pubkey_serialize(mgr->ctx, ser_extracted, &l1, &extracted_pk,
                                    SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(mgr->ctx, ser_remote, &l2,
                                    &jit->channel.remote_funding_pubkey,
                                    SECP256K1_EC_COMPRESSED);
    if (memcmp(ser_extracted, ser_remote, 33) != 0) {
        fprintf(stderr, "LSP JIT close: key mismatch for client %zu "
                "(extracted != JIT remote funding key)\n", client_idx);
        return 0;
    }

    /* Build remote keypair from extracted secret */
    secp256k1_keypair remote_kp;
    if (!secp256k1_keypair_create(mgr->ctx, &remote_kp, extracted_client_key)) {
        fprintf(stderr, "LSP JIT close: keypair_create failed for client %zu\n",
                client_idx);
        return 0;
    }

    /* Get fresh wallet address/SPK for close output */
    unsigned char close_spk[64];
    size_t close_spk_len = 0;
    if (rt) {
        char close_addr[128];
        if (!regtest_get_new_address(rt, close_addr, sizeof(close_addr)) ||
            !regtest_get_address_scriptpubkey(rt, close_addr, close_spk, &close_spk_len)) {
            fprintf(stderr, "LSP JIT close: failed to get wallet address for client %zu\n",
                    client_idx);
            return 0;
        }
    } else {
        wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
        if (!ws || !ws->get_change_spk(ws, close_spk, &close_spk_len)) {
            fprintf(stderr, "LSP JIT close: failed to get HD wallet SPK for client %zu\n",
                    client_idx);
            return 0;
        }
    }

    /* Calculate fee: 1-in-1-out P2TR close ~111 vbytes */
    uint64_t total = jit->funding_amount;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->fee;
    uint64_t close_fee = fe ? fee_estimate(fe, 111) : 200;
    if (close_fee == 0) close_fee = 200;
    if (close_fee > total / 2) close_fee = total / 2;

    /* Build single close output: total - fee to LSP wallet */
    tx_output_t output;
    output.amount_sats = total - close_fee;
    memcpy(output.script_pubkey, close_spk, close_spk_len);
    output.script_pubkey_len = close_spk_len;

    /* Build cooperative close tx */
    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 256);
    if (!channel_build_cooperative_close_tx(&jit->channel, &close_tx, NULL,
                                              &remote_kp, &output, 1)) {
        fprintf(stderr, "LSP JIT close: build close tx failed for client %zu\n",
                client_idx);
        tx_buf_free(&close_tx);
        return 0;
    }

    /* Broadcast */
    char *close_hex = malloc(close_tx.len * 2 + 1);
    if (!close_hex) { tx_buf_free(&close_tx); return 0; }
    hex_encode(close_tx.data, close_tx.len, close_hex);
    char close_txid[65];
    int sent = chain_be->send_raw_tx(chain_be, close_hex, close_txid);
    if (mgr->persist) {
        persist_log_broadcast((persist_t *)mgr->persist,
                              sent ? close_txid : "?", "jit_cooperative_close",
                              close_hex, sent ? "ok" : "failed");
    }
    free(close_hex);
    tx_buf_free(&close_tx);

    if (!sent) {
        fprintf(stderr, "LSP JIT close: broadcast failed for client %zu\n",
                client_idx);
        return 0;
    }

    /* Confirm */
    if (mgr->rot_is_regtest) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
    } else {
        int timeout = mgr->confirm_timeout_secs > 0 ?
                      mgr->confirm_timeout_secs : 7200;
        int confirmed = lsp_wait_for_confirmation(chain_be, close_txid, timeout,
                                                    chain_close_confs(chain_be, chain_be->is_regtest));
        if (!confirmed) {
            fprintf(stderr, "LSP JIT close: confirmation timeout for client %zu\n",
                    client_idx);
            return 0;
        }
    }

    /* Re-verify close TX still has safe confirmations before removing
       watchtower entries. This guards against a reorg between the wait
       returning and the removal happening. */
    if (!mgr->rot_is_regtest) {
        int recheck = chain_be->get_confirmations(chain_be, close_txid);
        if (recheck < chain_close_confs(chain_be, chain_be->is_regtest)) {
            fprintf(stderr, "LSP JIT close: close TX lost confirmations "
                    "(was safe, now %d) — keeping watchtower entries\n", recheck);
            return 0;
        }
    }

    /* Update state */
    jit->state = JIT_STATE_CLOSED;

    /* Cleanup watchtower — safe because close TX has >= 6 confirmations */
    if (mgr->watchtower) {
        size_t wt_idx = mgr->n_channels + client_idx;
        watchtower_remove_channel(mgr->watchtower, (uint32_t)wt_idx);
        mgr->watchtower->channels[wt_idx] = NULL;
    }

    /* Persist */
    if (mgr->persist) {
        persist_delete_jit_channel((persist_t *)mgr->persist, jit->jit_channel_id);
        persist_log_broadcast((persist_t *)mgr->persist, close_txid,
                              "jit_close_confirmed", "", "ok");
    }

    printf("LSP JIT close: channel %08x for client %zu closed: %s\n",
           jit->jit_channel_id, client_idx, close_txid);
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

    /* JIT funds recovered via on-chain cooperative close (Phase A.5).
       New factory funding draws from wallet which now includes JIT sats. */

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
        int is_rt = (strcmp(mgr->watchtower->rt->network, "regtest") == 0);
        int safe_conf = chain_funding_confs(mgr->watchtower->chain, is_rt);
        if (conf >= safe_conf) {
            jits[i].state = JIT_STATE_OPEN;
            jits[i].funding_confirmed = 1;
            printf("LSP JIT: channel %08x funding confirmed (%d conf)\n",
                   jits[i].jit_channel_id, conf);

            /* Register with watchtower (guaranteed non-NULL by guard at function entry) */
            size_t wt_idx = mgr->n_channels + jits[i].client_idx;
            watchtower_set_channel(mgr->watchtower, wt_idx, &jits[i].channel);

            /* Persist state change */
            if (mgr->persist)
                persist_update_jit_state((persist_t *)mgr->persist,
                                           jits[i].jit_channel_id, "open");
            transitions++;
        }
    }
    return transitions;
}

int jit_channels_revalidate_funding(void *mgr_ptr) {
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    if (!mgr || !mgr->jit_channels || !mgr->watchtower || !mgr->watchtower->rt)
        return 0;

    jit_channel_t *jits = (jit_channel_t *)mgr->jit_channels;
    int reverted = 0;
    for (size_t i = 0; i < mgr->n_jit_channels; i++) {
        if (jits[i].state != JIT_STATE_OPEN) continue;
        if (jits[i].funding_txid_hex[0] == '\0') continue;

        int conf = regtest_get_confirmations(mgr->watchtower->rt,
                                               jits[i].funding_txid_hex);
        if (conf < 0) {
            fprintf(stderr, "JIT revalidation: channel %08x funding tx gone, "
                    "reverting to FUNDING state\n", jits[i].jit_channel_id);
            jits[i].state = JIT_STATE_FUNDING;
            jits[i].funding_confirmed = 0;
            if (mgr->persist)
                persist_update_jit_state((persist_t *)mgr->persist,
                                           jits[i].jit_channel_id, "funding");
            reverted++;
        }
    }
    return reverted;
}

int jit_channel_force_close(void *mgr_ptr, size_t client_idx,
                            void *chain_be_ptr)
{
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)mgr_ptr;
    chain_backend_t *chain_be = (chain_backend_t *)chain_be_ptr;
    if (!mgr || !chain_be) return 0;

    jit_channel_t *jit = jit_channel_find(mgr, client_idx);
    if (!jit || jit->state != JIT_STATE_OPEN) return 0;

    /* JIT channels use MuSig2 2-of-2 funding. The LSP cannot build a
       fully-signed commitment TX without the client's partial signature.
       In normal operation, the client holds the pre-signed commitment TX.

       Force-close for JIT channels requires one of:
       a) The client broadcasts their commitment TX (client-initiated)
       b) PTLC key turnover reveals the client key (during rotation)
       c) Factory distribution TX settles the JIT UTXO (timeout)

       This function handles the LSP-side detection and monitoring.
       If the funding TX output is already spent (someone broadcast a
       commitment), we track it for sweep. */

    channel_t *ch = &jit->channel;

    /* Check if the funding output has been spent (commitment broadcast) */
    char fund_hex[65];
    {
        unsigned char disp[32];
        extern void hex_encode(const unsigned char *, size_t, char *);
        extern void reverse_bytes(unsigned char *, size_t);
        memcpy(disp, ch->funding_txid, 32);
        reverse_bytes(disp, 32);
        hex_encode(disp, 32, fund_hex);
    }

    int fund_confs = chain_be->get_confirmations(chain_be, fund_hex);
    if (fund_confs < 0) {
        /* Funding TX not found — JIT never confirmed, nothing to close */
        printf("LSP JIT force-close: client %zu — funding not on-chain, "
               "marking closed\n", client_idx);
        jit->state = JIT_STATE_CLOSED;
        if (mgr->persist)
            persist_update_jit_state((persist_t *)mgr->persist,
                                     jit->jit_channel_id, "closed");
        return 1;
    }

    /* Funding is on-chain. Check if commitment TX is already broadcast. */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 512);
    unsigned char commit_txid[32];
    if (!channel_build_commitment_tx(ch, &unsigned_tx, commit_txid)) {
        tx_buf_free(&unsigned_tx);
        fprintf(stderr, "LSP JIT force-close: client %zu — can't build "
                "commitment TX\n", client_idx);
        return 0;
    }
    tx_buf_free(&unsigned_tx);

    unsigned char disp[32];
    memcpy(disp, commit_txid, 32);
    extern void reverse_bytes(unsigned char *, size_t);
    extern void hex_encode(const unsigned char *, size_t, char *);
    reverse_bytes(disp, 32);
    char ctxid_hex[65];
    hex_encode(disp, 32, ctxid_hex);

    int commit_confs = chain_be->get_confirmations(chain_be, ctxid_hex);
    if (commit_confs >= 0) {
        printf("LSP JIT force-close: client %zu — commitment already on-chain "
               "(%d confs)\n", client_idx, commit_confs);
        jit->state = JIT_STATE_CLOSED;
        if (mgr->persist)
            persist_update_jit_state((persist_t *)mgr->persist,
                                     jit->jit_channel_id, "closed");
        return 1;
    }

    /* Commitment not broadcast yet. Log for operator. The client must
       broadcast their pre-signed commitment TX, or the LSP needs the
       client key (obtained during rotation PTLC turnover). */
    printf("LSP JIT force-close: client %zu — cannot unilaterally close "
           "(need client's commitment TX or extracted key)\n", client_idx);
    return 0;
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
