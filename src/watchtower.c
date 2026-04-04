#include "superscalar/watchtower.h"
#include "superscalar/ptlc_commit.h"
#include "superscalar/htlc_fee_bump.h"
#include "superscalar/wallet_source.h"
#include "superscalar/types.h"
#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include "cJSON.h"

extern void chain_backend_regtest_init(chain_backend_t *backend, regtest_t *rt);
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

    /* Allocate dynamic arrays */
    size_t ch_cap = n_channels < WATCHTOWER_MAX_CHANNELS ? WATCHTOWER_MAX_CHANNELS : n_channels;
    wt->entries = calloc(WATCHTOWER_MAX_WATCH, sizeof(watchtower_entry_t));
    wt->channels = calloc(ch_cap, sizeof(channel_t *));
    wt->pending = calloc(WATCHTOWER_MAX_PENDING, sizeof(watchtower_pending_t));
    if (!wt->entries || !wt->channels || !wt->pending) {
        free(wt->entries); free(wt->channels); free(wt->pending);
        memset(wt, 0, sizeof(*wt));
        return 0;
    }
    wt->entries_cap = WATCHTOWER_MAX_WATCH;
    wt->channels_cap = ch_cap;
    wt->pending_cap = WATCHTOWER_MAX_PENDING;
    wt->n_channels = n_channels < ch_cap ? n_channels : ch_cap;
    wt->rt = rt;
    wt->fee = fee;
    wt->db = db;

    /* Wrap regtest_t as the default chain backend when provided. */
    if (rt) {
        chain_backend_regtest_init(&wt->_chain_regtest_wrapper, rt);
        wt->chain = &wt->_chain_regtest_wrapper;
        wallet_source_rpc_init(&wt->_wallet_rpc_default, rt);
        wt->wallet = &wt->_wallet_rpc_default.base;
    }

    /* P2A anchor: static anyone-can-spend SPK — no keys needed */
    memcpy(wt->anchor_spk, P2A_SPK, P2A_SPK_LEN);
    wt->anchor_spk_len = P2A_SPK_LEN;

    /* Load old commitments from DB if available.
       Loop up to channels_cap (not n_channels) so we also reload entries
       for JIT channels which are stored at indices >= n_channels. */
    if (db && db->db) {
        for (size_t c = 0; c < wt->channels_cap; c++) {
            uint64_t commit_nums[WATCHTOWER_MAX_WATCH];
            unsigned char txids[WATCHTOWER_MAX_WATCH][32];
            uint32_t vouts[WATCHTOWER_MAX_WATCH];
            uint64_t amounts[WATCHTOWER_MAX_WATCH];
            unsigned char spks[WATCHTOWER_MAX_WATCH][34];
            size_t spk_lens[WATCHTOWER_MAX_WATCH];

            size_t loaded = persist_load_old_commitments(
                db, (uint32_t)c, commit_nums, txids, vouts, amounts,
                spks, spk_lens, wt->entries_cap - wt->n_entries);

            for (size_t i = 0; i < loaded && wt->n_entries < wt->entries_cap; i++) {
                watchtower_entry_t *e = &wt->entries[wt->n_entries++];
                e->type = WATCH_COMMITMENT;
                e->channel_id = (uint32_t)c;
                e->commit_num = commit_nums[i];
                memcpy(e->txid, txids[i], 32);
                /* DB-loaded entries: registered_height = 0 so that late-arrival
                   breach detection works (breach confirmed during downtime).
                   Fresh entries set registered_height in watchtower_watch(). */
                e->registered_height = 0;
                e->to_local_vout = vouts[i];
                e->to_local_amount = amounts[i];
                memcpy(e->to_local_spk, spks[i], spk_lens[i]);
                e->to_local_spk_len = spk_lens[i];

                /* Re-register the watched script with the chain backend so
                   BIP 158 scanning resumes correctly after a process restart. */
                if (wt->chain && wt->chain->register_script && spk_lens[i] > 0)
                    wt->chain->register_script(wt->chain,
                                               e->to_local_spk, e->to_local_spk_len);

                e->n_htlc_outputs = 0;
                e->response_tx = NULL;
                e->response_tx_len = 0;

                /* Load persisted HTLC output data for this commitment */
                if (db && db->db) {
                    watchtower_htlc_t *tmp_htlcs = malloc(MAX_HTLCS * sizeof(watchtower_htlc_t));
                    if (!tmp_htlcs) return 0;
                    size_t n_loaded_htlcs = persist_load_old_commitment_htlcs(
                        db, (uint32_t)c, commit_nums[i],
                        tmp_htlcs, MAX_HTLCS);
                    if (n_loaded_htlcs > 0) {
                        e->htlc_outputs = calloc(n_loaded_htlcs, sizeof(watchtower_htlc_t));
                        if (e->htlc_outputs) {
                            memcpy(e->htlc_outputs, tmp_htlcs,
                                   n_loaded_htlcs * sizeof(watchtower_htlc_t));
                            e->n_htlc_outputs = n_loaded_htlcs;
                            e->htlc_outputs_cap = n_loaded_htlcs;
                        }
                    }
                    free(tmp_htlcs);
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
        for (size_t i = 0; i < n_loaded && wt->n_pending < wt->pending_cap; i++) {
            watchtower_pending_t *p = &wt->pending[wt->n_pending++];
            memcpy(p->txid, pending_txids[i], 64);
            p->txid[64] = '\0';
            p->anchor_vout = pending_vouts[i];
            p->anchor_amount = pending_amounts[i];
            p->cycles_in_mempool = pending_cycles[i];
            memset(&p->fee_bump, 0, sizeof(p->fee_bump));
            p->fee_bump.last_bump_block = (uint32_t)pending_bumps[i];
        }
    }

    return 1;
}

void watchtower_set_channel(watchtower_t *wt, size_t idx, channel_t *ch) {
    if (!wt || idx >= wt->channels_cap) return;
    wt->channels[idx] = ch;
    if (idx >= wt->n_channels)
        wt->n_channels = idx + 1;
}

int watchtower_watch(watchtower_t *wt, uint32_t channel_id,
                       uint64_t commit_num, const unsigned char *txid32,
                       uint32_t to_local_vout, uint64_t to_local_amount,
                       const unsigned char *to_local_spk, size_t spk_len) {
    if (!wt || !txid32 || !to_local_spk) return 0;
    if (wt->n_entries >= wt->entries_cap) return 0;
    if (spk_len > 34) return 0;

    watchtower_entry_t *e = &wt->entries[wt->n_entries++];
    e->type = WATCH_COMMITMENT;
    e->channel_id = channel_id;
    e->commit_num = commit_num;
    memcpy(e->txid, txid32, 32);
    /* Record current height so watchtower_check can reject pre-existing on-chain txids */
    e->registered_height = (wt->chain && wt->chain->get_block_height)
                           ? wt->chain->get_block_height(wt->chain) : 0;
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

    /* Register script with chain backend (no-op for TXID-polling backend) */
    if (wt->chain && wt->chain->register_script)
        wt->chain->register_script(wt->chain, to_local_spk, spk_len);

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
    htlc_t *saved_htlcs = saved_n_htlcs > 0
        ? malloc(saved_n_htlcs * sizeof(htlc_t)) : NULL;
    if (saved_n_htlcs > 0 && !saved_htlcs) return;
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
            secure_zero(old_rev_secret, 32);
        }
    }

    tx_buf_t old_tx;
    tx_buf_init(&old_tx, 512);
    unsigned char old_txid[32];
    /* Build the REMOTE's old commitment TX — this is what the remote party
       (the potential cheater) would broadcast.  The watchtower has the
       revocation secrets needed to punish via the penalty TX. */
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
        free(saved_htlcs);
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
            entry->htlc_outputs = calloc(n_active_htlcs, sizeof(watchtower_htlc_t));
            entry->htlc_outputs_cap = entry->htlc_outputs ? n_active_htlcs : 0;
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

                /* Register HTLC script with chain backend */
                if (wt->chain && wt->chain->register_script)
                    wt->chain->register_script(wt->chain, wh->htlc_spk, 34);

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
    free(saved_htlcs);
}

void watchtower_set_chain_backend(watchtower_t *wt, chain_backend_t *backend)
{
    if (wt)
        wt->chain = backend;
}

void watchtower_set_wallet(watchtower_t *wt, wallet_source_t *wallet)
{
    if (wt)
        wt->wallet = wallet;
}

int watchtower_check(watchtower_t *wt) {
    if (!wt || !wt->chain) return 0;

    /* Retry any previously failed penalty broadcasts */
    if (wt->db && wt->db->db)
        persist_retry_pending_broadcasts(wt->db, wt->chain);

    int penalties_broadcast = 0;

    /* Pre-compute display-order hex for every entry once */
    char (*txid_hexes)[65] = calloc(wt->n_entries + 1, 65);
    int  *batch_confs      = calloc(wt->n_entries + 1, sizeof(int));
    if (!txid_hexes || !batch_confs) {
        free(txid_hexes);
        free(batch_confs);
        return 0;
    }
    for (size_t j = 0; j < wt->n_entries; j++) {
        unsigned char disp[32];
        memcpy(disp, wt->entries[j].txid, 32);
        reverse_bytes(disp, 32);
        hex_encode(disp, 32, txid_hexes[j]);
        batch_confs[j] = -1;
    }

    /* Batch confirmation lookup: O(scan_depth) RPCs regardless of n_entries.
       Falls back to per-entry calls if the backend doesn't implement the slot
       (e.g. the BIP 158 backend). */
    if (wt->chain->get_confirmations_batch) {
        /* Build a flat pointer array — char (*)[65] cannot be cast to char **
           because the stride is different (65 bytes vs sizeof(char*) bytes). */
        const char **ptrs = malloc(wt->n_entries * sizeof(const char *));
        if (ptrs) {
            for (size_t j = 0; j < wt->n_entries; j++)
                ptrs[j] = txid_hexes[j];
            wt->chain->get_confirmations_batch(wt->chain,
                ptrs, wt->n_entries, batch_confs);
            free(ptrs);
        }
    } else {
        for (size_t j = 0; j < wt->n_entries; j++)
            batch_confs[j] = wt->chain->get_confirmations(wt->chain,
                                                           txid_hexes[j]);
    }

    for (size_t i = 0; i < wt->n_entries; ) {
        watchtower_entry_t *e = &wt->entries[i];

        /* Reorg resistance: if penalty was already broadcast, check its confirmation.
           Only remove when penalty is safely confirmed. If penalty vanished (reorg),
           reset and re-detect the breach on this cycle. */
        if (e->penalty_broadcast && e->penalty_txid[0]) {
            int pconf = wt->chain->get_confirmations(wt->chain, e->penalty_txid);
            int is_rt = (wt->rt && strcmp(wt->rt->network, "regtest") == 0);
            int safe = chain_safe_confs(wt->chain, is_rt);
            if (pconf >= safe) {
                /* Penalty safely confirmed — remove entry */
                free(e->htlc_outputs); free(e->ptlc_outputs);
                free(e->response_tx); free(e->burn_tx);
                wt->entries[i] = wt->entries[wt->n_entries - 1];
                wt->n_entries--;
                continue;  /* re-check swapped entry at index i */
            }
            if (pconf < 0 && !wt->chain->is_in_mempool(wt->chain, e->penalty_txid)) {
                /* Penalty tx vanished (reorg) — reset and re-detect */
                fprintf(stderr, "Watchtower: penalty %s vanished (reorg?), re-watching\n",
                        e->penalty_txid);
                e->penalty_broadcast = 0;
                e->penalty_txid[0] = '\0';
                /* Fall through to normal breach detection below */
            } else {
                i++;  /* penalty still in mempool or partially confirmed, wait */
                continue;
            }
        }

        const char *txid_hex = txid_hexes[i];

        /* Check if old commitment is on chain or in mempool */
        int conf = batch_confs[i];
        int in_mempool = wt->chain->is_in_mempool(wt->chain, txid_hex);

        if (conf < 0 && !in_mempool) {
            i++;  /* not found, keep watching */
            continue;
        }

        /* Reject false positives: if the tx was confirmed BEFORE we registered
           this entry, it predates the current factory and is not a breach of
           our channel.  This prevents deterministic-key regtest runs from
           triggering on old commitments left on-chain by previous scenarios. */
        if (conf >= 0 && e->registered_height > 0) {
            int cur_height = (wt->chain->get_block_height)
                             ? wt->chain->get_block_height(wt->chain) : 0;
            int tx_height = cur_height - conf + 1;  /* block the tx was mined in */
            if (tx_height < e->registered_height) {
                i++;  /* predates our factory -- skip */
                continue;
            }
        }

        if (e->type == WATCH_FACTORY_NODE) {
            printf("FACTORY BREACH on node %u (txid: %s)!\n",
                   e->channel_id, txid_hex);
            fflush(stdout);

            char factory_resp_txid[65] = {0};  /* saved for reorg tracking */

            /* Broadcast the pre-built latest state tx as response */
            if (e->response_tx && e->response_tx_len > 0) {
                char *resp_hex = (char *)malloc(e->response_tx_len * 2 + 1);
                if (resp_hex) {
                    hex_encode(e->response_tx, e->response_tx_len, resp_hex);
                    char resp_txid[65];
                    if (wt->chain->send_raw_tx(wt->chain, resp_hex, resp_txid)) {
                        printf("  Latest state tx broadcast: %s\n", resp_txid);
                        memcpy(factory_resp_txid, resp_txid, 64);
                        factory_resp_txid[64] = '\0';
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

            /* Also broadcast burn tx to destroy L-stock */
            if (e->burn_tx && e->burn_tx_len > 0) {
                char *burn_hex = (char *)malloc(e->burn_tx_len * 2 + 1);
                if (burn_hex) {
                    hex_encode(e->burn_tx, e->burn_tx_len, burn_hex);
                    char burn_txid[65];
                    if (wt->chain->send_raw_tx(wt->chain, burn_hex, burn_txid)) {
                        printf("  L-stock burn tx broadcast: %s\n", burn_txid);
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, burn_txid,
                                                  "factory_burn", burn_hex, "ok");
                    } else {
                        fprintf(stderr, "  L-stock burn tx broadcast failed\n");
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, "?",
                                                  "factory_burn", burn_hex, "failed");
                    }
                    free(burn_hex);
                }
            }

            /* Mark as penalty-broadcast (keep entry for reorg resistance) */
            e->penalty_broadcast = 1;
            memcpy(e->penalty_txid, factory_resp_txid, 65);
            i++;
            continue;
        }

        /* WATCH_COMMITMENT: build and broadcast penalty tx */
        printf("BREACH DETECTED on channel %u, commitment %llu (txid: %s)!\n",
               e->channel_id, (unsigned long long)e->commit_num, txid_hex);
        fflush(stdout);

        /* If in mempool but not confirmed, mine a block (regtest only) */
        if (in_mempool && conf < 0 &&
            wt->rt && strcmp(wt->rt->network, "regtest") == 0) {
            char mine_addr[128];
            if (regtest_get_new_address(wt->rt, mine_addr, sizeof(mine_addr)))
                regtest_mine_blocks(wt->rt, 1, mine_addr);
        }

        /* Find corresponding channel */
        channel_t *ch = NULL;
        if (e->channel_id < wt->channels_cap)
            ch = wt->channels[e->channel_id];

        if (!ch) {
            fprintf(stderr, "Watchtower: no channel %u for penalty\n", e->channel_id);
            i++;
            continue;
        }

        tx_buf_t penalty_tx;
        tx_buf_init(&penalty_tx, 512);

        int use_anchor = fee_should_use_anchor(wt->fee);
        if (!channel_build_penalty_tx(ch, &penalty_tx,
                                        e->txid, e->to_local_vout,
                                        e->to_local_amount,
                                        e->to_local_spk, e->to_local_spk_len,
                                        e->commit_num,
                                        use_anchor ? wt->anchor_spk : NULL,
                                        use_anchor ? wt->anchor_spk_len : 0)) {
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
            if (wt->chain->send_raw_tx(wt->chain, penalty_hex, penalty_txid)) {
                printf("  Penalty tx broadcast: %s\n", penalty_txid);
                fflush(stdout);
                penalties_broadcast++;
                penalty_sent = 1;
                if (wt->db && wt->db->db)
                    persist_log_broadcast(wt->db, penalty_txid, "penalty",
                                          penalty_hex, "ok");
            } else {
                fprintf(stderr, "  Penalty tx broadcast failed — queued for retry\n");
                if (wt->db && wt->db->db)
                    persist_log_broadcast(wt->db, "?", "penalty",
                                          penalty_hex, "pending_retry");
            }
            free(penalty_hex);
        }
        tx_buf_free(&penalty_tx);

        /* Track in pending for CPFP bump if anchor is active.
           NOTE: anchor_vout=1 must match channel_build_penalty_tx output order.
           Skip CPFP tracking at sub-1-sat/vB — no anchor output was created. */
        if (penalty_sent && use_anchor &&
            wt->anchor_spk_len == P2A_SPK_LEN &&
            wt->n_pending < wt->pending_cap) {
            watchtower_pending_t *p = &wt->pending[wt->n_pending++];
            memcpy(p->txid, penalty_txid, 64);
            p->txid[64] = '\0';
            p->anchor_vout = 1;
            p->anchor_amount = WATCHTOWER_ANCHOR_AMOUNT;
            p->cycles_in_mempool = 0;
            memset(&p->fee_bump, 0, sizeof(p->fee_bump));
            if (wt->db && wt->db->db) {
                persist_save_pending(wt->db, p->txid, p->anchor_vout,
                                       p->anchor_amount, 0, 0);
            }
        }

        /* Sweep HTLC outputs via penalty txs */
        for (size_t h = 0; h < e->n_htlc_outputs; h++) {
            /* Skip already-swept outputs (amount set to 0 after broadcast) */
            if (e->htlc_outputs[h].htlc_amount == 0) continue;
            /* Temporarily set ch->htlcs[0] to stored HTLC metadata */
            size_t saved_n = ch->n_htlcs;
            htlc_t saved_h0 = {0};
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
                    use_anchor ? wt->anchor_spk : NULL,
                    use_anchor ? wt->anchor_spk_len : 0)) {
                char *htlc_hex = (char *)malloc(htlc_penalty.len * 2 + 1);
                if (htlc_hex) {
                    hex_encode(htlc_penalty.data, htlc_penalty.len, htlc_hex);
                    char htlc_txid[65];
                    if (wt->chain->send_raw_tx(wt->chain, htlc_hex, htlc_txid)) {
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

        /* Sweep PTLC outputs via penalty txs (mirrors HTLC sweep above) */
        for (size_t p = 0; p < e->n_ptlc_outputs; p++) {
            /* Temporarily set ch->ptlcs[0] to stored PTLC metadata */
            size_t saved_np = ch->n_ptlcs;
            ptlc_t saved_p0 = {0};
            if (saved_np > 0 && ch->ptlcs)
                saved_p0 = ch->ptlcs[0];
            if (!ch->ptlcs) {
                ch->ptlcs = (ptlc_t *)calloc(1, sizeof(ptlc_t));
                ch->ptlcs_cap = 1;
            }
            ch->n_ptlcs = 1;
            memset(&ch->ptlcs[0], 0, sizeof(ptlc_t));
            ch->ptlcs[0].direction = (ptlc_direction_t)e->ptlc_outputs[p].direction;
            ch->ptlcs[0].cltv_expiry = e->ptlc_outputs[p].cltv_expiry;
            ch->ptlcs[0].state = PTLC_STATE_ACTIVE;
            /* Use payment_hash as serialized payment_point for tapscript */
            secp256k1_ec_pubkey_parse(ch->ctx, &ch->ptlcs[0].payment_point,
                                       e->ptlc_outputs[p].payment_hash, 33);

            tx_buf_t ptlc_penalty;
            tx_buf_init(&ptlc_penalty, 512);
            if (channel_build_ptlc_penalty_tx(ch, &ptlc_penalty,
                    e->txid, e->ptlc_outputs[p].htlc_vout,
                    e->ptlc_outputs[p].htlc_amount,
                    e->ptlc_outputs[p].htlc_spk, 34,
                    e->commit_num, 0,
                    use_anchor ? wt->anchor_spk : NULL,
                    use_anchor ? wt->anchor_spk_len : 0)) {
                char *ptlc_hex = (char *)malloc(ptlc_penalty.len * 2 + 1);
                if (ptlc_hex) {
                    hex_encode(ptlc_penalty.data, ptlc_penalty.len, ptlc_hex);
                    char ptlc_txid[65];
                    if (wt->chain->send_raw_tx(wt->chain, ptlc_hex, ptlc_txid)) {
                        printf("  PTLC penalty tx (vout %u) broadcast: %s\n",
                               e->ptlc_outputs[p].htlc_vout, ptlc_txid);
                        penalties_broadcast++;
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, ptlc_txid,
                                                  "ptlc_penalty", ptlc_hex, "ok");
                    }
                    free(ptlc_hex);
                }
            }
            tx_buf_free(&ptlc_penalty);

            ch->n_ptlcs = saved_np;
            if (saved_np > 0 && ch->ptlcs)
                ch->ptlcs[0] = saved_p0;
        }

        /* Mark as penalty-broadcast (keep entry for reorg resistance) */
        e->penalty_broadcast = 1;
        if (penalty_sent)
            memcpy(e->penalty_txid, penalty_txid, 65);
        else
            e->penalty_txid[0] = '\0';
        i++;
    }

    /* Force-close HTLC timeout sweep: check if any expired HTLCs can be swept */
    int current_height = wt->chain->get_block_height(wt->chain);
    if (current_height > 0) {
        for (size_t i = 0; i < wt->n_entries; i++) {
            watchtower_entry_t *e = &wt->entries[i];
            if (e->type != WATCH_FORCE_CLOSE || e->n_htlc_outputs == 0)
                continue;

            channel_t *ch = NULL;
            if (e->channel_id < wt->channels_cap)
                ch = wt->channels[e->channel_id];
            if (!ch) continue;

            for (size_t h = 0; h < e->n_htlc_outputs; h++) {
                watchtower_htlc_t *htlc = &e->htlc_outputs[h];

                /* Already swept and confirmed — skip */
                if (htlc->htlc_amount == 0 && htlc->sweep_txid[0] == '\0')
                    continue;

                /* Sweep was broadcast — check if confirmed */
                if (htlc->sweep_txid[0] != '\0') {
                    int sweep_conf = wt->chain->get_confirmations(
                                         wt->chain, htlc->sweep_txid);
                    int sweep_rt = (wt->rt && strcmp(wt->rt->network, "regtest") == 0);
                    int sweep_safe = chain_safe_confs(wt->chain, sweep_rt);
                    if (sweep_conf >= sweep_safe) {
                        /* Safely confirmed — mark as fully swept */
                        htlc->htlc_amount = 0;
                        htlc->sweep_txid[0] = '\0';
                    } else if (sweep_conf < 0 &&
                               !wt->chain->is_in_mempool(wt->chain, htlc->sweep_txid)) {
                        /* Sweep TX vanished (reorg) — reset for re-broadcast */
                        fprintf(stderr, "  HTLC sweep %s reorged out, will re-broadcast\n",
                                htlc->sweep_txid);
                        htlc->sweep_txid[0] = '\0';
                        /* fall through to re-broadcast below */
                    } else {
                        /* Still in mempool or partially confirmed — wait */
                        continue;
                    }
                }

                /* If amount is zero, this HTLC is done */
                if (htlc->htlc_amount == 0) continue;

                /* CLTV not yet expired — skip */
                if ((uint32_t)current_height < htlc->cltv_expiry)
                    continue;

                /* CLTV expired — build and broadcast timeout tx */
                size_t saved_n = ch->n_htlcs;
                htlc_t saved_h0 = {0};
                if (saved_n > 0) saved_h0 = ch->htlcs[0];
                ch->n_htlcs = 1;
                memset(&ch->htlcs[0], 0, sizeof(htlc_t));
                ch->htlcs[0].direction = htlc->direction;
                memcpy(ch->htlcs[0].payment_hash, htlc->payment_hash, 32);
                ch->htlcs[0].cltv_expiry = htlc->cltv_expiry;
                ch->htlcs[0].amount_sats = htlc->htlc_amount;
                ch->htlcs[0].state = HTLC_STATE_ACTIVE;

                tx_buf_t timeout_tx;
                tx_buf_init(&timeout_tx, 512);
                if (channel_build_htlc_timeout_tx(ch, &timeout_tx,
                        e->txid, htlc->htlc_vout, htlc->htlc_amount,
                        htlc->htlc_spk, 34, 0)) {
                    char *tx_hex = (char *)malloc(timeout_tx.len * 2 + 1);
                    if (tx_hex) {
                        hex_encode(timeout_tx.data, timeout_tx.len, tx_hex);
                        char txid[65];
                        if (wt->chain->send_raw_tx(wt->chain, tx_hex, txid)) {
                            printf("  HTLC timeout sweep (vout %u, cltv %u): %s\n",
                                   htlc->htlc_vout, htlc->cltv_expiry, txid);
                            penalties_broadcast++;
                            /* Track the sweep txid for confirmation monitoring */
                            memcpy(htlc->sweep_txid, txid, 65);
                            /* Register for CPFP monitoring */
                            watchtower_add_pending_tx(wt, txid, 1,
                                                      WATCHTOWER_ANCHOR_AMOUNT);
                            if (wt->db && wt->db->db)
                                persist_log_broadcast(wt->db, txid,
                                                      "htlc_timeout", tx_hex, "ok");
                        }
                        free(tx_hex);
                    }
                }
                tx_buf_free(&timeout_tx);

                ch->n_htlcs = saved_n;
                if (saved_n > 0) ch->htlcs[0] = saved_h0;
            }

            /* If all HTLCs fully swept (amount=0 and no pending sweep), remove entry */
            size_t unswept = 0;
            for (size_t hh = 0; hh < e->n_htlc_outputs; hh++)
                if (e->htlc_outputs[hh].htlc_amount > 0 ||
                    e->htlc_outputs[hh].sweep_txid[0] != '\0')
                    unswept++;
            if (unswept == 0) {
                free(e->htlc_outputs);
                e->htlc_outputs = NULL;
                wt->entries[i] = wt->entries[wt->n_entries - 1];
                wt->n_entries--;
                i--;  /* recheck swapped entry */
            }
        }
    }

    /* CPFP bump loop: check pending penalty txs and bump if stuck */
    for (size_t i = 0; i < wt->n_pending; ) {
        watchtower_pending_t *p = &wt->pending[i];
        int conf = wt->chain->get_confirmations(wt->chain, p->txid);
        if (conf > 0) {
            /* Confirmed — remove from pending (swap with last) */
            if (wt->db && wt->db->db)
                persist_delete_pending(wt->db, p->txid);
            wt->pending[i] = wt->pending[wt->n_pending - 1];
            wt->n_pending--;
            continue;
        }
        p->cycles_in_mempool++;
        /* Initialize fee_bump schedule on first encounter */
        if (p->fee_bump.start_block == 0) {
            uint32_t cur = (uint32_t)p->cycles_in_mempool; /* approx block proxy */
            uint64_t start_fr = wt->fee ? (uint64_t)wt->fee->get_rate(wt->fee, FEE_TARGET_NORMAL) : 1000;
            if (start_fr < HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB)
                start_fr = HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB;
            htlc_fee_bump_init(&p->fee_bump, cur, cur + 144,
                               p->anchor_amount,
                               HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT,
                               200, start_fr);
        }
        /* Use deadline-aware fee scheduler */
        uint32_t cur_block = (uint32_t)p->cycles_in_mempool;
        if (htlc_fee_bump_should_bump(&p->fee_bump, cur_block)) {
            uint64_t fr = htlc_fee_bump_calc_feerate(&p->fee_bump, cur_block);
            tx_buf_t cpfp;
            tx_buf_init(&cpfp, 512);
            if (watchtower_build_cpfp_tx(wt, &cpfp, p->txid,
                                           p->anchor_vout, p->anchor_amount)) {
                char *cpfp_hex = (char *)malloc(cpfp.len * 2 + 1);
                if (cpfp_hex) {
                    hex_encode(cpfp.data, cpfp.len, cpfp_hex);
                    char cpfp_txid[65];
                    if (wt->chain->send_raw_tx(wt->chain, cpfp_hex, cpfp_txid)) {
                        htlc_fee_bump_record_broadcast(&p->fee_bump, cur_block, fr);
                        printf("  CPFP child broadcast (feerate %llu): %s\n",
                               (unsigned long long)fr, cpfp_txid);
                        if (wt->db && wt->db->db) {
                            persist_save_pending(wt->db, p->txid,
                                p->anchor_vout, p->anchor_amount,
                                p->cycles_in_mempool,
                                (int)p->fee_bump.last_bump_block);
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
        i++;
    }

    free(txid_hexes);
    free(batch_confs);
    return penalties_broadcast;
}

/* --- CPFP child transaction builder (P2A anchor — no signing needed) --- */

int watchtower_build_cpfp_tx(watchtower_t *wt,
                               tx_buf_t *cpfp_tx_out,
                               const char *parent_txid,
                               uint32_t anchor_vout,
                               uint64_t anchor_amount) {
    if (!wt || !cpfp_tx_out || !parent_txid) return 0;
    if (wt->anchor_spk_len != P2A_SPK_LEN) return 0;
    if (!wt->wallet) {
        fprintf(stderr, "CPFP: disabled (no wallet source attached)\n");
        return 0;
    }

    /* Declare all locals upfront so goto done: is safe on every exit path */
    char wallet_txid_hex[65];
    uint32_t wallet_vout = 0;
    uint64_t wallet_amount = 0;
    unsigned char wallet_spk[64];
    size_t wallet_spk_len = 0;
    unsigned char anchor_txid[32], wallet_txid[32];
    unsigned char change_spk[64];
    size_t change_spk_len = 0;
    uint64_t total_in, change_amount;
    size_t signed_len;
    tx_buf_t unsigned_tx = {0};   /* tx_buf_free(NULL data) is safe */
    unsigned char *signed_buf = NULL;
    int result = 0;

    uint64_t cpfp_fee = wt->fee ? fee_for_cpfp_child(wt->fee) : 200;
    uint64_t min_amount = cpfp_fee + 1000;  /* fee + dust margin */

    if (!wt->wallet->get_utxo(wt->wallet, min_amount,
                               wallet_txid_hex, &wallet_vout,
                               &wallet_amount, wallet_spk, &wallet_spk_len)) {
        fprintf(stderr, "CPFP: no suitable wallet UTXO for bump\n");
        return 0;  /* UTXO not locked — plain return */
    }

    /* UTXO is now locked; all subsequent exits must go through done: */

    /* Decode txid hex strings to internal byte order */
    if (hex_decode(parent_txid, anchor_txid, 32) != 32) goto done;
    reverse_bytes(anchor_txid, 32);
    if (hex_decode(wallet_txid_hex, wallet_txid, 32) != 32) goto done;
    reverse_bytes(wallet_txid, 32);

    /* Change output: wallet amount + anchor amount - fee */
    total_in = wallet_amount + anchor_amount;
    change_amount = total_in > cpfp_fee ? total_in - cpfp_fee : 0;
    if (change_amount == 0) goto done;

    /* Get change scriptPubKey from wallet */
    if (!wt->wallet->get_change_spk(wt->wallet, change_spk, &change_spk_len))
        goto done;
    if (change_spk_len == 0) goto done;

    /* Build unsigned 2-input, 1-output tx (non-segwit serialization) */
    tx_buf_init(&unsigned_tx, 256);
    tx_buf_write_u32_le(&unsigned_tx, 3);           /* nVersion=3 (TRUC): penalty tx is V3, so this
                                                       child can also be V3; enables package relay */
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

    /* Sign input 1 (wallet UTXO) via the wallet_source vtable.
       Input 0 (P2A anchor) is anyone-can-spend — no signature needed. */
    signed_len = unsigned_tx.len + 512; /* room for witness data */
    signed_buf = (unsigned char *)malloc(signed_len);
    if (!signed_buf) goto done;
    memcpy(signed_buf, unsigned_tx.data, unsigned_tx.len);
    signed_len = unsigned_tx.len;
    tx_buf_free(&unsigned_tx);  /* done with unsigned form; safe to re-free at done: */

    if (!wt->wallet->sign_input(wt->wallet, signed_buf, &signed_len,
                                 1 /* input_idx */,
                                 wallet_spk, wallet_spk_len,
                                 wallet_amount))
        goto done;

    tx_buf_reset(cpfp_tx_out);
    tx_buf_write_bytes(cpfp_tx_out, signed_buf, signed_len);
    result = 1;

done:
    free(signed_buf);
    tx_buf_free(&unsigned_tx);  /* no-op if already freed or never init'd */
    if (wt->wallet->release_utxo)
        wt->wallet->release_utxo(wt->wallet, wallet_txid_hex, wallet_vout);
    return result;
}

/* Phase L: register any broadcast tx for CPFP monitoring */
int watchtower_add_pending_tx(watchtower_t *wt,
                               const char *txid_hex,
                               uint32_t anchor_vout,
                               uint64_t anchor_amount)
{
    if (!wt || !txid_hex) return 0;
    if (wt->n_pending >= wt->pending_cap) return 0;

    watchtower_pending_t *p = &wt->pending[wt->n_pending++];
    strncpy(p->txid, txid_hex, 64);
    p->txid[64] = '\0';
    p->anchor_vout       = anchor_vout;
    p->anchor_amount     = anchor_amount;
    p->cycles_in_mempool = 0;
    memset(&p->fee_bump, 0, sizeof(p->fee_bump));

    if (wt->db && wt->db->db)
        persist_save_pending(wt->db, p->txid, p->anchor_vout,
                               p->anchor_amount, 0, 0);
    return 1;
}

int watchtower_watch_factory_node(watchtower_t *wt, uint32_t node_idx,
                                    const unsigned char *old_txid32,
                                    const unsigned char *response_tx,
                                    size_t response_tx_len,
                                    const unsigned char *burn_tx,
                                    size_t burn_tx_len) {
    if (!wt || !old_txid32 || !response_tx || response_tx_len == 0) return 0;
    if (wt->n_entries >= wt->entries_cap) return 0;

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

    /* Store pre-built burn tx for L-stock destruction (optional) */
    if (burn_tx && burn_tx_len > 0) {
        e->burn_tx = (unsigned char *)malloc(burn_tx_len);
        if (e->burn_tx) {
            memcpy(e->burn_tx, burn_tx, burn_tx_len);
            e->burn_tx_len = burn_tx_len;
        }
    }

    return 1;
}

void watchtower_cleanup(watchtower_t *wt) {
    if (!wt) return;
    for (size_t i = 0; i < wt->n_entries; i++) {
        free(wt->entries[i].htlc_outputs);
        wt->entries[i].htlc_outputs = NULL;
        if (wt->entries[i].type == WATCH_FACTORY_NODE) {
            free(wt->entries[i].response_tx);
            wt->entries[i].response_tx = NULL;
            free(wt->entries[i].burn_tx);
            wt->entries[i].burn_tx = NULL;
        }
    }
    free(wt->entries);
    free(wt->channels);
    free(wt->pending);
    wt->entries = NULL;
    wt->channels = NULL;
    wt->pending = NULL;
    wt->n_entries = 0;
    wt->n_pending = 0;
}

int watchtower_watch_force_close(watchtower_t *wt, uint32_t channel_id,
                                  const unsigned char *commitment_txid,
                                  const watchtower_htlc_t *htlcs, size_t n_htlcs) {
    if (!wt || !commitment_txid || n_htlcs == 0) return 0;

    /* Grow entries if needed */
    if (wt->n_entries >= wt->entries_cap) {
        size_t new_cap = wt->entries_cap ? wt->entries_cap * 2 : 16;
        watchtower_entry_t *tmp = realloc(wt->entries,
                                            new_cap * sizeof(watchtower_entry_t));
        if (!tmp) return 0;
        wt->entries = tmp;
        wt->entries_cap = new_cap;
    }

    watchtower_entry_t *e = &wt->entries[wt->n_entries];
    memset(e, 0, sizeof(*e));
    e->type = WATCH_FORCE_CLOSE;
    e->channel_id = channel_id;
    memcpy(e->txid, commitment_txid, 32);

    /* Copy HTLC outputs */
    e->htlc_outputs = malloc(n_htlcs * sizeof(watchtower_htlc_t));
    if (!e->htlc_outputs) return 0;
    memcpy(e->htlc_outputs, htlcs, n_htlcs * sizeof(watchtower_htlc_t));
    e->n_htlc_outputs = n_htlcs;
    e->htlc_outputs_cap = n_htlcs;

    wt->n_entries++;

    /* Register HTLC scripts with chain backend */
    if (wt->chain && wt->chain->register_script)
        for (size_t i = 0; i < n_htlcs; i++)
            wt->chain->register_script(wt->chain, htlcs[i].htlc_spk, 34);
    return 1;
}

/* Unregister all scripts belonging to an entry from the chain backend. */
static void entry_unregister_scripts(watchtower_t *wt, watchtower_entry_t *e)
{
    if (!wt->chain || !wt->chain->unregister_script) return;
    if (e->to_local_spk_len > 0)
        wt->chain->unregister_script(wt->chain, e->to_local_spk,
                                      e->to_local_spk_len);
    for (size_t h = 0; h < e->n_htlc_outputs; h++)
        wt->chain->unregister_script(wt->chain, e->htlc_outputs[h].htlc_spk,
                                      34);
}

void watchtower_clear_entries(watchtower_t *wt) {
    if (!wt) return;
    /* Free per-entry heap data (HTLC outputs, response/burn txs) but
       preserve the channels and pending arrays — they outlive entries. */
    for (size_t i = 0; i < wt->n_entries; i++) {
        entry_unregister_scripts(wt, &wt->entries[i]);
        free(wt->entries[i].htlc_outputs);
        wt->entries[i].htlc_outputs = NULL;
        if (wt->entries[i].type == WATCH_FACTORY_NODE) {
            free(wt->entries[i].response_tx);
            wt->entries[i].response_tx = NULL;
            free(wt->entries[i].burn_tx);
            wt->entries[i].burn_tx = NULL;
        }
    }
    wt->n_entries = 0;
}

void watchtower_on_reorg(watchtower_t *wt, int new_tip, int old_tip) {
    if (!wt || !wt->chain) return;
    fprintf(stderr, "Watchtower: reorg detected (%d → %d), re-validating %zu entries\n",
            old_tip, new_tip, wt->n_entries);

    /* Reset penalty_broadcast for entries whose penalty tx vanished */
    for (size_t i = 0; i < wt->n_entries; i++) {
        watchtower_entry_t *e = &wt->entries[i];
        if (!e->penalty_broadcast || !e->penalty_txid[0])
            continue;
        int conf = wt->chain->get_confirmations(wt->chain, e->penalty_txid);
        if (conf < 0 && !wt->chain->is_in_mempool(wt->chain, e->penalty_txid)) {
            fprintf(stderr, "  Entry ch=%u cn=%llu: penalty %s reorged out, re-watching\n",
                    e->channel_id, (unsigned long long)e->commit_num,
                    e->penalty_txid);
            e->penalty_broadcast = 0;
            e->penalty_txid[0] = '\0';
        }
    }

    /* Re-validate pending CPFP entries */
    for (size_t i = 0; i < wt->n_pending; i++) {
        int conf = wt->chain->get_confirmations(wt->chain, wt->pending[i].txid);
        if (conf < 0 && !wt->chain->is_in_mempool(wt->chain, wt->pending[i].txid)) {
            fprintf(stderr, "  Pending penalty %s reorged out\n", wt->pending[i].txid);
            /* Reset cycle counter — will be retried from broadcast_log */
            wt->pending[i].cycles_in_mempool = 0;
        }
    }

    /* Mark stale entries in database so they survive restarts */
    if (wt->db && wt->db->db)
        persist_mark_reorg_stale(wt->db, new_tip);
}

void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id) {
    if (!wt) return;

    for (size_t i = 0; i < wt->n_entries; ) {
        if (wt->entries[i].channel_id == channel_id) {
            entry_unregister_scripts(wt, &wt->entries[i]);
            free(wt->entries[i].htlc_outputs);
            if (wt->entries[i].type == WATCH_FACTORY_NODE) {
                free(wt->entries[i].response_tx);
                free(wt->entries[i].burn_tx);
            }
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            /* NULL the source entry's pointers after swap */
            wt->entries[wt->n_entries - 1].htlc_outputs = NULL;
            wt->entries[wt->n_entries - 1].response_tx = NULL;
            wt->entries[wt->n_entries - 1].burn_tx = NULL;
            wt->n_entries--;
        } else {
            i++;
        }
    }
}
