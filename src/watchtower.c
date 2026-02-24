#include "superscalar/watchtower.h"
#include "superscalar/persist.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

int watchtower_init(watchtower_t *wt, size_t n_channels,
                      regtest_t *rt, fee_estimator_t *fee, persist_t *db) {
    if (!wt) return 0;
    memset(wt, 0, sizeof(*wt));
    wt->n_channels = n_channels < WATCHTOWER_MAX_CHANNELS ? n_channels : WATCHTOWER_MAX_CHANNELS;
    wt->rt = rt;
    wt->fee = fee;
    wt->db = db;

    /* P2A anchor: static anyone-can-spend SPK — no keys needed */
    memcpy(wt->anchor_spk, P2A_SPK, P2A_SPK_LEN);
    wt->anchor_spk_len = P2A_SPK_LEN;

    /* Load old commitments from DB if available */
    if (db && db->db) {
        for (size_t c = 0; c < wt->n_channels; c++) {
            uint64_t commit_nums[WATCHTOWER_MAX_WATCH];
            unsigned char txids[WATCHTOWER_MAX_WATCH][32];
            uint32_t vouts[WATCHTOWER_MAX_WATCH];
            uint64_t amounts[WATCHTOWER_MAX_WATCH];
            unsigned char spks[WATCHTOWER_MAX_WATCH][34];
            size_t spk_lens[WATCHTOWER_MAX_WATCH];

            size_t loaded = persist_load_old_commitments(
                db, (uint32_t)c, commit_nums, txids, vouts, amounts,
                spks, spk_lens, WATCHTOWER_MAX_WATCH - wt->n_entries);

            for (size_t i = 0; i < loaded && wt->n_entries < WATCHTOWER_MAX_WATCH; i++) {
                watchtower_entry_t *e = &wt->entries[wt->n_entries++];
                e->type = WATCH_COMMITMENT;
                e->channel_id = (uint32_t)c;
                e->commit_num = commit_nums[i];
                memcpy(e->txid, txids[i], 32);
                e->to_local_vout = vouts[i];
                e->to_local_amount = amounts[i];
                memcpy(e->to_local_spk, spks[i], spk_lens[i]);
                e->to_local_spk_len = spk_lens[i];
                e->n_htlc_outputs = 0;
                e->response_tx = NULL;
                e->response_tx_len = 0;

                /* Load persisted HTLC output data for this commitment */
                if (db && db->db) {
                    e->n_htlc_outputs = persist_load_old_commitment_htlcs(
                        db, (uint32_t)c, commit_nums[i],
                        e->htlc_outputs, MAX_HTLCS);
                }
            }
        }

        /* Load pending penalty entries for CPFP bump tracking */
        char pending_txids[WATCHTOWER_MAX_PENDING][65];
        uint32_t pending_vouts[WATCHTOWER_MAX_PENDING];
        uint64_t pending_amounts[WATCHTOWER_MAX_PENDING];
        int pending_cycles[WATCHTOWER_MAX_PENDING];
        int pending_bumps[WATCHTOWER_MAX_PENDING];
        size_t n_loaded = persist_load_pending(db, pending_txids,
            pending_vouts, pending_amounts, pending_cycles, pending_bumps,
            WATCHTOWER_MAX_PENDING);
        for (size_t i = 0; i < n_loaded && wt->n_pending < WATCHTOWER_MAX_PENDING; i++) {
            watchtower_pending_t *p = &wt->pending[wt->n_pending++];
            strncpy(p->txid, pending_txids[i], 64);
            p->txid[64] = '\0';
            p->anchor_vout = pending_vouts[i];
            p->anchor_amount = pending_amounts[i];
            p->cycles_in_mempool = pending_cycles[i];
            p->bump_count = pending_bumps[i];
            p->cycles_since_bump = 0;
        }
    }

    return 1;
}

void watchtower_set_channel(watchtower_t *wt, size_t idx, channel_t *ch) {
    if (!wt || idx >= WATCHTOWER_MAX_CHANNELS) return;
    wt->channels[idx] = ch;
    if (idx >= wt->n_channels)
        wt->n_channels = idx + 1;
}

int watchtower_watch(watchtower_t *wt, uint32_t channel_id,
                       uint64_t commit_num, const unsigned char *txid32,
                       uint32_t to_local_vout, uint64_t to_local_amount,
                       const unsigned char *to_local_spk, size_t spk_len) {
    if (!wt || !txid32 || !to_local_spk) return 0;
    if (wt->n_entries >= WATCHTOWER_MAX_WATCH) return 0;
    if (spk_len > 34) return 0;

    watchtower_entry_t *e = &wt->entries[wt->n_entries++];
    e->type = WATCH_COMMITMENT;
    e->channel_id = channel_id;
    e->commit_num = commit_num;
    memcpy(e->txid, txid32, 32);
    e->to_local_vout = to_local_vout;
    e->to_local_amount = to_local_amount;
    memcpy(e->to_local_spk, to_local_spk, spk_len);
    e->to_local_spk_len = spk_len;
    e->n_htlc_outputs = 0;
    e->response_tx = NULL;
    e->response_tx_len = 0;

    /* Persist if DB available */
    if (wt->db && wt->db->db) {
        persist_save_old_commitment(wt->db, channel_id, commit_num,
                                      txid32, to_local_vout, to_local_amount,
                                      to_local_spk, spk_len);
    }

    return 1;
}

void watchtower_watch_revoked_commitment(watchtower_t *wt, channel_t *ch,
                                           uint32_t channel_id,
                                           uint64_t old_commit_num,
                                           uint64_t old_local, uint64_t old_remote,
                                           const htlc_t *old_htlcs, size_t old_n_htlcs) {
    if (!wt)
        return;

    /* Save current state (including HTLC state — the old commitment may have
     * had different active HTLCs than the current channel state) */
    uint64_t saved_num = ch->commitment_number;
    uint64_t saved_local = ch->local_amount;
    uint64_t saved_remote = ch->remote_amount;
    size_t saved_n_htlcs = ch->n_htlcs;
    htlc_t saved_htlcs[MAX_HTLCS];
    if (saved_n_htlcs > 0)
        memcpy(saved_htlcs, ch->htlcs, saved_n_htlcs * sizeof(htlc_t));

    /* Temporarily set to old state, restoring the HTLC state that was active
     * at the time of the old commitment. This ensures the rebuilt commitment tx
     * includes HTLC outputs and produces the correct txid. */
    ch->commitment_number = old_commit_num;
    ch->local_amount = old_local;
    ch->remote_amount = old_remote;
    if (old_htlcs && old_n_htlcs > 0) {
        ch->n_htlcs = old_n_htlcs;
        memcpy(ch->htlcs, old_htlcs, old_n_htlcs * sizeof(htlc_t));
    } else {
        ch->n_htlcs = 0;
    }

    /* Count active HTLCs for output parsing */
    size_t n_active_htlcs = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE)
            n_active_htlcs++;
    }

    /* Ensure old remote PCP is available: derive from stored revocation secret */
    {
        unsigned char old_rev_secret[32];
        if (channel_get_received_revocation(ch, old_commit_num, old_rev_secret)) {
            secp256k1_pubkey old_pcp;
            if (secp256k1_ec_pubkey_create(ch->ctx, &old_pcp, old_rev_secret)) {
                channel_set_remote_pcp(ch, old_commit_num, &old_pcp);
            }
            memset(old_rev_secret, 0, 32);
        }
    }

    tx_buf_t old_tx;
    tx_buf_init(&old_tx, 512);
    unsigned char old_txid[32];
    int ok = channel_build_commitment_tx_for_remote(ch, &old_tx, old_txid);

    /* Restore state */
    ch->commitment_number = saved_num;
    ch->local_amount = saved_local;
    ch->remote_amount = saved_remote;
    ch->n_htlcs = saved_n_htlcs;
    if (saved_n_htlcs > 0)
        memcpy(ch->htlcs, saved_htlcs, saved_n_htlcs * sizeof(htlc_t));

    if (!ok) {
        tx_buf_free(&old_tx);
        return;
    }

    /* Parse outputs from the unsigned raw tx.
     * Layout (no segwit marker/flag):
     *   4 version + 1 vincount +
     *   (32 prevhash + 4 vout + 1 scriptlen + 0 script + 4 sequence) = 41 vin bytes
     *   + 1 voutcount = 47 bytes offset to first output
     *   Each output: 8 amount (LE) + 1 spk_len + spk_len bytes */
    if (old_tx.len > 60) {
        size_t ofs = 4 + 1 + 41 + 1;  /* 47: offset to first output */

        /* Output 0: to_local */
        if (ofs + 8 + 1 + 34 <= old_tx.len) {
            uint8_t spk_len = old_tx.data[ofs + 8];
            if (spk_len == 34) {
                unsigned char to_local_spk[34];
                memcpy(to_local_spk, &old_tx.data[ofs + 9], 34);
                /* Remote commitment's to_local = peer's balance = old_remote */
                watchtower_watch(wt, channel_id, old_commit_num,
                                   old_txid, 0, old_remote,
                                   to_local_spk, 34);
            }
        }

        /* If we have active HTLCs, parse their outputs (vout 2+) and store
         * in the watchtower entry we just created */
        if (n_active_htlcs > 0 && wt->n_entries > 0) {
            watchtower_entry_t *entry = &wt->entries[wt->n_entries - 1];
            entry->n_htlc_outputs = 0;

            /* Skip output 0 and output 1 to reach HTLC outputs */
            size_t out_ofs = ofs;
            for (uint32_t v = 0; v < 2; v++) {
                if (out_ofs + 9 > old_tx.len) break;
                uint8_t slen = old_tx.data[out_ofs + 8];
                out_ofs += 8 + 1 + slen;
            }

            /* Parse HTLC outputs (vout 2, 3, ...) */
            size_t htlc_active_idx = 0;
            for (size_t i = 0; i < old_n_htlcs && htlc_active_idx < n_active_htlcs; i++) {
                if (old_htlcs[i].state != HTLC_STATE_ACTIVE)
                    continue;

                if (out_ofs + 8 + 1 > old_tx.len) break;
                uint64_t amount = 0;
                for (int b = 0; b < 8; b++)
                    amount |= ((uint64_t)old_tx.data[out_ofs + b]) << (b * 8);
                uint8_t slen = old_tx.data[out_ofs + 8];
                if (slen != 34 || out_ofs + 9 + slen > old_tx.len) {
                    out_ofs += 8 + 1 + slen;
                    htlc_active_idx++;
                    continue;
                }

                watchtower_htlc_t *wh = &entry->htlc_outputs[entry->n_htlc_outputs];
                wh->htlc_vout = (uint32_t)(2 + htlc_active_idx);
                wh->htlc_amount = amount;
                memcpy(wh->htlc_spk, &old_tx.data[out_ofs + 9], 34);
                wh->direction = old_htlcs[i].direction;
                memcpy(wh->payment_hash, old_htlcs[i].payment_hash, 32);
                wh->cltv_expiry = old_htlcs[i].cltv_expiry;
                entry->n_htlc_outputs++;

                out_ofs += 8 + 1 + slen;
                htlc_active_idx++;
            }

            /* Persist HTLC outputs if DB available (transactional) */
            if (wt->db && wt->db->db && entry->n_htlc_outputs > 0) {
                if (!persist_begin(wt->db)) {
                    fprintf(stderr, "watchtower: persist_begin failed, skipping HTLC persist\n");
                } else {
                    int htlc_ok = 1;
                    for (size_t h = 0; h < entry->n_htlc_outputs; h++) {
                        if (!persist_save_old_commitment_htlc(wt->db, channel_id,
                                old_commit_num, &entry->htlc_outputs[h])) {
                            htlc_ok = 0;
                            break;
                        }
                    }
                    if (htlc_ok)
                        persist_commit(wt->db);
                    else
                        persist_rollback(wt->db);
                }
            }
        }
    }

    tx_buf_free(&old_tx);
}

int watchtower_check(watchtower_t *wt) {
    if (!wt || !wt->rt) return 0;

    int penalties_broadcast = 0;

    for (size_t i = 0; i < wt->n_entries; ) {
        watchtower_entry_t *e = &wt->entries[i];

        /* Convert txid to display-order hex */
        unsigned char display_txid[32];
        memcpy(display_txid, e->txid, 32);
        reverse_bytes(display_txid, 32);
        char txid_hex[65];
        hex_encode(display_txid, 32, txid_hex);

        /* Check if old commitment is on chain or in mempool */
        int conf = regtest_get_confirmations(wt->rt, txid_hex);
        int in_mempool = regtest_is_in_mempool(wt->rt, txid_hex);

        if (conf < 0 && !in_mempool) {
            i++;  /* not found, keep watching */
            continue;
        }

        if (e->type == WATCH_FACTORY_NODE) {
            printf("FACTORY BREACH on node %u (txid: %s)!\n",
                   e->channel_id, txid_hex);

            /* Broadcast the pre-built latest state tx as response */
            if (e->response_tx && e->response_tx_len > 0) {
                char *resp_hex = (char *)malloc(e->response_tx_len * 2 + 1);
                if (resp_hex) {
                    hex_encode(e->response_tx, e->response_tx_len, resp_hex);
                    char resp_txid[65];
                    if (regtest_send_raw_tx(wt->rt, resp_hex, resp_txid)) {
                        printf("  Latest state tx broadcast: %s\n", resp_txid);
                        penalties_broadcast++;
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, resp_txid,
                                                  "factory_response", resp_hex, "ok");
                    } else {
                        fprintf(stderr, "  Latest state tx broadcast failed\n");
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, "?",
                                                  "factory_response", resp_hex, "failed");
                    }
                    free(resp_hex);
                }
            }

            /* Free response_tx and remove entry */
            free(e->response_tx);
            e->response_tx = NULL;
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            wt->n_entries--;
            continue;
        }

        /* WATCH_COMMITMENT: build and broadcast penalty tx */
        printf("BREACH DETECTED on channel %u, commitment %llu (txid: %s)!\n",
               e->channel_id, (unsigned long long)e->commit_num, txid_hex);

        /* If in mempool but not confirmed, mine a block (regtest only) */
        if (in_mempool && conf < 0 && strcmp(wt->rt->network, "regtest") == 0) {
            char mine_addr[128];
            if (regtest_get_new_address(wt->rt, mine_addr, sizeof(mine_addr)))
                regtest_mine_blocks(wt->rt, 1, mine_addr);
        }

        /* Find corresponding channel */
        channel_t *ch = NULL;
        if (e->channel_id < WATCHTOWER_MAX_CHANNELS)
            ch = wt->channels[e->channel_id];

        if (!ch) {
            fprintf(stderr, "Watchtower: no channel %u for penalty\n", e->channel_id);
            i++;
            continue;
        }

        tx_buf_t penalty_tx;
        tx_buf_init(&penalty_tx, 512);

        if (!channel_build_penalty_tx(ch, &penalty_tx,
                                        e->txid, e->to_local_vout,
                                        e->to_local_amount,
                                        e->to_local_spk, e->to_local_spk_len,
                                        e->commit_num,
                                        wt->anchor_spk, wt->anchor_spk_len)) {
            fprintf(stderr, "Watchtower: build penalty tx failed for channel %u\n",
                    e->channel_id);
            tx_buf_free(&penalty_tx);
            i++;
            continue;
        }

        /* Broadcast penalty tx */
        char *penalty_hex = (char *)malloc(penalty_tx.len * 2 + 1);
        char penalty_txid[65] = {0};
        int penalty_sent = 0;
        if (penalty_hex) {
            hex_encode(penalty_tx.data, penalty_tx.len, penalty_hex);
            if (regtest_send_raw_tx(wt->rt, penalty_hex, penalty_txid)) {
                printf("  Penalty tx broadcast: %s\n", penalty_txid);
                penalties_broadcast++;
                penalty_sent = 1;
                if (wt->db && wt->db->db)
                    persist_log_broadcast(wt->db, penalty_txid, "penalty",
                                          penalty_hex, "ok");
            } else {
                fprintf(stderr, "  Penalty tx broadcast failed\n");
                if (wt->db && wt->db->db)
                    persist_log_broadcast(wt->db, "?", "penalty",
                                          penalty_hex, "failed");
            }
            free(penalty_hex);
        }
        tx_buf_free(&penalty_tx);

        /* Track in pending for CPFP bump if anchor is active.
           NOTE: anchor_vout=1 must match channel_build_penalty_tx output order. */
        if (penalty_sent && wt->anchor_spk_len == P2A_SPK_LEN &&
            wt->n_pending < WATCHTOWER_MAX_PENDING) {
            watchtower_pending_t *p = &wt->pending[wt->n_pending++];
            strncpy(p->txid, penalty_txid, 64);
            p->txid[64] = '\0';
            p->anchor_vout = 1;
            p->anchor_amount = WATCHTOWER_ANCHOR_AMOUNT;
            p->cycles_in_mempool = 0;
            p->bump_count = 0;
            p->cycles_since_bump = 0;
            if (wt->db && wt->db->db) {
                persist_save_pending(wt->db, p->txid, p->anchor_vout,
                                       p->anchor_amount, 0, 0);
            }
        }

        /* Sweep HTLC outputs via penalty txs */
        for (size_t h = 0; h < e->n_htlc_outputs; h++) {
            /* Temporarily set ch->htlcs[0] to stored HTLC metadata */
            size_t saved_n = ch->n_htlcs;
            htlc_t saved_h0;
            if (saved_n > 0)
                saved_h0 = ch->htlcs[0];
            ch->n_htlcs = 1;
            memset(&ch->htlcs[0], 0, sizeof(htlc_t));
            ch->htlcs[0].direction = e->htlc_outputs[h].direction;
            memcpy(ch->htlcs[0].payment_hash, e->htlc_outputs[h].payment_hash, 32);
            ch->htlcs[0].cltv_expiry = e->htlc_outputs[h].cltv_expiry;
            ch->htlcs[0].state = HTLC_STATE_ACTIVE;

            tx_buf_t htlc_penalty;
            tx_buf_init(&htlc_penalty, 512);
            if (channel_build_htlc_penalty_tx(ch, &htlc_penalty,
                    e->txid, e->htlc_outputs[h].htlc_vout,
                    e->htlc_outputs[h].htlc_amount,
                    e->htlc_outputs[h].htlc_spk, 34,
                    e->commit_num, 0,
                    wt->anchor_spk, wt->anchor_spk_len)) {
                char *htlc_hex = (char *)malloc(htlc_penalty.len * 2 + 1);
                if (htlc_hex) {
                    hex_encode(htlc_penalty.data, htlc_penalty.len, htlc_hex);
                    char htlc_txid[65];
                    if (regtest_send_raw_tx(wt->rt, htlc_hex, htlc_txid)) {
                        printf("  HTLC penalty tx (vout %u) broadcast: %s\n",
                               e->htlc_outputs[h].htlc_vout, htlc_txid);
                        penalties_broadcast++;
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, htlc_txid,
                                                  "htlc_penalty", htlc_hex, "ok");
                    } else {
                        fprintf(stderr, "  HTLC penalty tx (vout %u) broadcast failed\n",
                                e->htlc_outputs[h].htlc_vout);
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, "?",
                                                  "htlc_penalty", htlc_hex, "failed");
                    }
                    free(htlc_hex);
                }
            }
            tx_buf_free(&htlc_penalty);

            ch->n_htlcs = saved_n;
            if (saved_n > 0)
                ch->htlcs[0] = saved_h0;
        }

        /* Remove this entry (swap with last) */
        wt->entries[i] = wt->entries[wt->n_entries - 1];
        wt->n_entries--;
        /* Don't increment i — check the swapped entry */
    }

    /* CPFP bump loop: check pending penalty txs and bump if stuck */
    for (size_t i = 0; i < wt->n_pending; ) {
        watchtower_pending_t *p = &wt->pending[i];
        int conf = regtest_get_confirmations(wt->rt, p->txid);
        if (conf > 0) {
            /* Confirmed — remove from pending (swap with last) */
            if (wt->db && wt->db->db)
                persist_delete_pending(wt->db, p->txid);
            wt->pending[i] = wt->pending[wt->n_pending - 1];
            wt->n_pending--;
            continue;
        }
        p->cycles_in_mempool++;
        /* Bump if: stuck >= 2 cycles, under 3 bump attempts,
           and enough cycles since last bump (first bump at cycle 2,
           subsequent bumps every 6 cycles = ~30 seconds) */
        if (p->cycles_in_mempool >= 2 && p->bump_count < 3 &&
            (p->bump_count == 0 || p->cycles_since_bump >= 6)) {
            /* Stuck in mempool — attempt CPFP bump */
            tx_buf_t cpfp;
            tx_buf_init(&cpfp, 512);
            if (watchtower_build_cpfp_tx(wt, &cpfp, p->txid,
                                           p->anchor_vout, p->anchor_amount)) {
                char *cpfp_hex = (char *)malloc(cpfp.len * 2 + 1);
                if (cpfp_hex) {
                    hex_encode(cpfp.data, cpfp.len, cpfp_hex);
                    char cpfp_txid[65];
                    if (regtest_send_raw_tx(wt->rt, cpfp_hex, cpfp_txid)) {
                        printf("  CPFP child broadcast (attempt %d): %s\n",
                               p->bump_count + 1, cpfp_txid);
                        p->bump_count++;
                        p->cycles_since_bump = 0;
                        if (wt->db && wt->db->db) {
                            persist_save_pending(wt->db, p->txid,
                                p->anchor_vout, p->anchor_amount,
                                p->cycles_in_mempool, p->bump_count);
                            persist_log_broadcast(wt->db, cpfp_txid,
                                                  "cpfp", cpfp_hex, "ok");
                        }
                    } else {
                        fprintf(stderr, "  CPFP child broadcast failed\n");
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, "?",
                                                  "cpfp", cpfp_hex, "failed");
                    }
                    free(cpfp_hex);
                }
            }
            tx_buf_free(&cpfp);
        }
        p->cycles_since_bump++;
        i++;
    }

    return penalties_broadcast;
}

/* --- CPFP child transaction builder (P2A anchor — no signing needed) --- */

int watchtower_build_cpfp_tx(watchtower_t *wt,
                               tx_buf_t *cpfp_tx_out,
                               const char *parent_txid,
                               uint32_t anchor_vout,
                               uint64_t anchor_amount) {
    if (!wt || !wt->rt || !cpfp_tx_out || !parent_txid) return 0;
    if (wt->anchor_spk_len != P2A_SPK_LEN) return 0;

    /* Get a wallet UTXO to fund the CPFP child */
    char wallet_txid_hex[65];
    uint32_t wallet_vout;
    uint64_t wallet_amount;
    unsigned char wallet_spk[64];
    size_t wallet_spk_len = 0;

    uint64_t cpfp_fee = wt->fee ? fee_for_cpfp_child(wt->fee) : 200;
    uint64_t min_amount = cpfp_fee + 1000;  /* fee + dust margin */

    if (!regtest_get_utxo_for_bump(wt->rt, min_amount,
                                     wallet_txid_hex, &wallet_vout,
                                     &wallet_amount,
                                     wallet_spk, &wallet_spk_len)) {
        fprintf(stderr, "CPFP: no suitable wallet UTXO for bump\n");
        return 0;
    }

    /* Decode txid hex strings to internal byte order */
    unsigned char anchor_txid[32], wallet_txid[32];
    if (hex_decode(parent_txid, anchor_txid, 32) != 32)
        return 0;
    reverse_bytes(anchor_txid, 32);
    if (hex_decode(wallet_txid_hex, wallet_txid, 32) != 32)
        return 0;
    reverse_bytes(wallet_txid, 32);

    /* Change output: wallet amount + anchor amount - fee, sent to a new wallet address */
    uint64_t total_in = wallet_amount + anchor_amount;
    uint64_t change_amount = total_in > cpfp_fee ? total_in - cpfp_fee : 0;
    if (change_amount == 0) return 0;

    /* Get change address SPK from wallet */
    char change_addr[128];
    if (!regtest_get_new_address(wt->rt, change_addr, sizeof(change_addr)))
        return 0;

    /* Use getaddressinfo to get the scriptPubKey */
    char addr_params[256];
    snprintf(addr_params, sizeof(addr_params), "\"%s\"", change_addr);
    char *addr_info = regtest_exec(wt->rt, "getaddressinfo", addr_params);
    if (!addr_info) return 0;

    unsigned char change_spk[64];
    size_t change_spk_len = 0;
    {
        cJSON *json = cJSON_Parse(addr_info);
        free(addr_info);
        if (!json) return 0;
        cJSON *spk_hex = cJSON_GetObjectItem(json, "scriptPubKey");
        if (!spk_hex || !cJSON_IsString(spk_hex)) {
            cJSON_Delete(json);
            return 0;
        }
        int decoded = hex_decode(spk_hex->valuestring, change_spk, sizeof(change_spk));
        if (decoded > 0) change_spk_len = (size_t)decoded;
        cJSON_Delete(json);
    }
    if (change_spk_len == 0) return 0;

    /* Build unsigned 2-input, 1-output tx (non-segwit serialization) */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    tx_buf_write_u32_le(&unsigned_tx, 2);           /* nVersion */
    tx_buf_write_varint(&unsigned_tx, 2);            /* 2 inputs */
    /* Input 0: P2A anchor output from penalty tx (anyone-can-spend) */
    tx_buf_write_bytes(&unsigned_tx, anchor_txid, 32);
    tx_buf_write_u32_le(&unsigned_tx, anchor_vout);
    tx_buf_write_varint(&unsigned_tx, 0);            /* empty scriptSig */
    tx_buf_write_u32_le(&unsigned_tx, 0xFFFFFFFE);
    /* Input 1: wallet UTXO */
    tx_buf_write_bytes(&unsigned_tx, wallet_txid, 32);
    tx_buf_write_u32_le(&unsigned_tx, wallet_vout);
    tx_buf_write_varint(&unsigned_tx, 0);            /* empty scriptSig */
    tx_buf_write_u32_le(&unsigned_tx, 0xFFFFFFFE);
    /* Output 0: change */
    tx_buf_write_varint(&unsigned_tx, 1);
    tx_buf_write_u64_le(&unsigned_tx, change_amount);
    tx_buf_write_varint(&unsigned_tx, change_spk_len);
    tx_buf_write_bytes(&unsigned_tx, change_spk, change_spk_len);
    /* nLockTime */
    tx_buf_write_u32_le(&unsigned_tx, 0);

    /* Hex-encode the unsigned tx for signrawtransactionwithwallet.
       Input 0 (P2A anchor) is anyone-can-spend — empty witness is valid.
       The wallet only needs to sign input 1. */
    char *unsigned_hex = (char *)malloc(unsigned_tx.len * 2 + 1);
    if (!unsigned_hex) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    hex_encode(unsigned_tx.data, unsigned_tx.len, unsigned_hex);

    /* Build prevtxs JSON for the P2A anchor input so the wallet knows
       to leave it unsigned (it only signs its own input 1). */
    char anchor_spk_hex[16];
    hex_encode(wt->anchor_spk, wt->anchor_spk_len, anchor_spk_hex);
    char prevtxs[512];
    snprintf(prevtxs, sizeof(prevtxs),
        "[{\"txid\":\"%s\",\"vout\":%u,\"scriptPubKey\":\"%s\",\"amount\":%.8f}]",
        parent_txid, anchor_vout, anchor_spk_hex,
        (double)anchor_amount / 100000000.0);

    char *signed_hex = regtest_sign_raw_tx_with_wallet(wt->rt, unsigned_hex, prevtxs);
    free(unsigned_hex);
    tx_buf_free(&unsigned_tx);

    if (!signed_hex) return 0;

    /* Decode the signed tx binary. The wallet signed input 1 and left
       input 0 (P2A) with empty witness (0x00), which is valid for
       anyone-can-spend. No witness splicing needed. */
    size_t signed_hex_len = strlen(signed_hex);
    size_t signed_bin_len = signed_hex_len / 2;
    unsigned char *signed_bin = (unsigned char *)malloc(signed_bin_len);
    if (!signed_bin) {
        free(signed_hex);
        return 0;
    }
    hex_decode(signed_hex, signed_bin, signed_bin_len);
    free(signed_hex);

    tx_buf_reset(cpfp_tx_out);
    tx_buf_write_bytes(cpfp_tx_out, signed_bin, signed_bin_len);
    free(signed_bin);

    return 1;
}

int watchtower_watch_factory_node(watchtower_t *wt, uint32_t node_idx,
                                    const unsigned char *old_txid32,
                                    const unsigned char *response_tx,
                                    size_t response_tx_len) {
    if (!wt || !old_txid32 || !response_tx || response_tx_len == 0) return 0;
    if (wt->n_entries >= WATCHTOWER_MAX_WATCH) return 0;

    watchtower_entry_t *e = &wt->entries[wt->n_entries++];
    memset(e, 0, sizeof(*e));
    e->type = WATCH_FACTORY_NODE;
    e->channel_id = node_idx;
    e->commit_num = 0;
    memcpy(e->txid, old_txid32, 32);

    e->response_tx = (unsigned char *)malloc(response_tx_len);
    if (!e->response_tx) {
        wt->n_entries--;
        return 0;
    }
    memcpy(e->response_tx, response_tx, response_tx_len);
    e->response_tx_len = response_tx_len;

    return 1;
}

void watchtower_cleanup(watchtower_t *wt) {
    if (!wt) return;
    for (size_t i = 0; i < wt->n_entries; i++) {
        if (wt->entries[i].type == WATCH_FACTORY_NODE && wt->entries[i].response_tx) {
            free(wt->entries[i].response_tx);
            wt->entries[i].response_tx = NULL;
        }
    }
}

void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id) {
    if (!wt) return;

    for (size_t i = 0; i < wt->n_entries; ) {
        if (wt->entries[i].channel_id == channel_id) {
            if (wt->entries[i].type == WATCH_FACTORY_NODE &&
                wt->entries[i].response_tx) {
                free(wt->entries[i].response_tx);
            }
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            wt->n_entries--;
        } else {
            i++;
        }
    }
}
