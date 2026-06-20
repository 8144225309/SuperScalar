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
extern void sha256_double(const unsigned char *data, size_t len, unsigned char *out32);

/* Authoritative check: does this serialised penalty TX contain a P2A anchor
 * at vout 1?  The build-time `use_anchor` decision (fee_should_use_anchor at
 * registration) can differ from the broadcast-time re-evaluation if the fee
 * estimator's URGENT rate crossed the 1 sat/vB threshold in between.  When
 * that happens we'd otherwise track CPFP against an output that doesn't
 * exist, and bitcoind rejects the child with bad-txns-inputs-missingorspent.
 * This helper inspects the bytes directly so the two decisions can't drift.
 *
 * Penalty TX format assumed (channel_build_penalty_tx, V3/TRUC, segwit):
 *   [4 version][1 marker=0x00][1 flag=0x01]
 *   [varint n_in (always 1 for penalty)]
 *   [32 prev_txid][4 prev_vout][1 script_len=0][4 sequence]
 *   [varint n_out]
 *   for each out: [8 value][1 spk_len][spk_len spk]
 *   [witness ...]
 *   [4 locktime]
 * Returns true iff n_out>=2 AND output 1's scriptPubKey equals P2A_SPK. */
static bool penalty_tx_has_p2a_anchor(const unsigned char *tx, size_t len)
{
    if (!tx || len < 10) return false;
    size_t off = 6;  /* skip version + marker + flag */
    /* n_inputs: penalty always emits 1 input, so this single byte is enough */
    if (tx[off++] != 1) return false;
    off += 32 + 4;                  /* prev_txid + prev_vout */
    if (off >= len) return false;
    unsigned int in_script_len = tx[off++];
    if (in_script_len != 0) return false;  /* segwit empty scriptSig */
    off += 4;                       /* sequence */
    if (off >= len) return false;
    unsigned int n_out = tx[off++];
    if (n_out < 2) return false;
    /* Skip output 0: 8 value + spk_len + spk */
    if (off + 8 + 1 > len) return false;
    off += 8;
    unsigned int spk0_len = tx[off++];
    if (off + spk0_len > len) return false;
    off += spk0_len;
    /* Output 1: must be the P2A anchor */
    if (off + 8 + 1 + P2A_SPK_LEN > len) return false;
    off += 8;
    unsigned int spk1_len = tx[off++];
    if (spk1_len != P2A_SPK_LEN) return false;
    return memcmp(&tx[off], P2A_SPK, P2A_SPK_LEN) == 0;
}

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
    wt->bump_budget_pct = HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT; /* 50% default */
    wt->max_bump_fee_sat = 50000; /* 50k sats absolute ceiling default */

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
            uint32_t csv_delays[WATCHTOWER_MAX_WATCH];

            size_t loaded = persist_load_old_commitments(
                db, (uint32_t)c, commit_nums, txids, vouts, amounts,
                spks, spk_lens, csv_delays,
                wt->entries_cap - wt->n_entries);

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
                /* v32 (SF-WTC #149): hydrate csv_delay so oracular CPFP can
                   read it after restart without live channel state. */
                e->csv_delay = csv_delays[i];

                /* Re-register the watched script with the chain backend so
                   BIP 158 scanning resumes correctly after a process restart. */
                if (wt->chain && wt->chain->register_script && spk_lens[i] > 0)
                    wt->chain->register_script(wt->chain,
                                               e->to_local_spk, e->to_local_spk_len);

                e->n_htlc_outputs = 0;
                e->response_tx = NULL;
                e->response_tx_len = 0;
                e->signed_penalty_tx = NULL;
                e->signed_penalty_tx_len = 0;

                /* v25 restart-defense load: pull the pre-built penalty TX
                   bytes if they were persisted.  Without this, the oracular
                   fast-path skips broadcast post-restart and the channel goes
                   undefended.  rc=0 (row exists, column empty) is the legacy
                   fallback path — leaves signed_penalty_tx NULL and channel_t
                   re-attaches later via watchtower_set_channel. */
                if (db && db->db) {
                    unsigned char *bytes = NULL;
                    size_t blen = 0;
                    if (persist_load_old_commitment_witness(db, (uint32_t)c,
                            commit_nums[i], &bytes, &blen) == 1
                        && bytes && blen > 0) {
                        e->signed_penalty_tx = bytes;
                        e->signed_penalty_tx_len = blen;
                    }
                }

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
        uint64_t pending_penalty_values[WATCHTOWER_MAX_PENDING];
        uint32_t pending_csv_delays[WATCHTOWER_MAX_PENDING];
        uint32_t pending_start_heights[WATCHTOWER_MAX_PENDING];
        uint32_t pending_fb_start_blocks[WATCHTOWER_MAX_PENDING];
        uint32_t pending_fb_deadlines[WATCHTOWER_MAX_PENDING];
        uint64_t pending_fb_budgets[WATCHTOWER_MAX_PENDING];
        uint64_t pending_fb_start_feerates[WATCHTOWER_MAX_PENDING];
        size_t n_loaded = persist_load_pending(db, pending_txids,
            pending_vouts, pending_amounts, pending_cycles, pending_bumps,
            pending_penalty_values, pending_csv_delays, pending_start_heights,
            pending_fb_start_blocks, pending_fb_deadlines,
            pending_fb_budgets, pending_fb_start_feerates,
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
            /* v27: resume escalation schedule.  tx_vsize is constant
               WATCHTOWER_CPFP_CHILD_VSIZE (not persisted); pre-v27 rows
               load as zeros and re-initialize at next bump check. */
            p->fee_bump.start_block    = pending_fb_start_blocks[i];
            p->fee_bump.deadline_block = pending_fb_deadlines[i];
            p->fee_bump.budget_sat     = pending_fb_budgets[i];
            p->fee_bump.start_feerate  = pending_fb_start_feerates[i];
            p->fee_bump.tx_vsize       = WATCHTOWER_CPFP_CHILD_VSIZE;
            p->fee_bump.last_feerate   = 0;  /* re-derived from RBF state */
            p->penalty_value = pending_penalty_values[i];
            p->csv_delay = pending_csv_delays[i];
            p->start_height = pending_start_heights[i];
        }

        /* v28 (PR-C-2): Load force-close watches.  Reconstruct
           WATCH_FORCE_CLOSE entries directly into wt->entries (they have no
           re-build-from-state recovery path like factory_node has). */
        #define WT_FC_MAX_WATCHES 64
        #define WT_FC_MAX_HTLCS_TOTAL 256
        uint32_t fc_channels[WT_FC_MAX_WATCHES];
        unsigned char fc_txids[WT_FC_MAX_WATCHES][32];
        watchtower_htlc_t fc_htlcs[WT_FC_MAX_HTLCS_TOTAL];
        size_t fc_n_per[WT_FC_MAX_WATCHES];
        size_t n_fc = persist_load_force_close_watches(db,
            fc_channels, fc_txids, fc_htlcs, fc_n_per,
            WT_FC_MAX_WATCHES, WT_FC_MAX_HTLCS_TOTAL);

        size_t htlc_cursor = 0;
        for (size_t w = 0; w < n_fc && wt->n_entries < wt->entries_cap; w++) {
            watchtower_entry_t *e = &wt->entries[wt->n_entries++];
            memset(e, 0, sizeof(*e));
            e->type = WATCH_FORCE_CLOSE;
            e->channel_id = fc_channels[w];
            memcpy(e->txid, fc_txids[w], 32);
            e->registered_height = 0;  /* late-arrival mode after restart */

            if (fc_n_per[w] > 0) {
                e->htlc_outputs = calloc(fc_n_per[w], sizeof(watchtower_htlc_t));
                if (e->htlc_outputs) {
                    memcpy(e->htlc_outputs, &fc_htlcs[htlc_cursor],
                           fc_n_per[w] * sizeof(watchtower_htlc_t));
                    e->n_htlc_outputs   = fc_n_per[w];
                    e->htlc_outputs_cap = fc_n_per[w];

                    /* Re-register HTLC scripts on the chain backend so BIP 158
                       scanning picks up timeouts post-restart. */
                    if (wt->chain && wt->chain->register_script) {
                        for (size_t h = 0; h < fc_n_per[w]; h++)
                            wt->chain->register_script(wt->chain,
                                                       e->htlc_outputs[h].htlc_spk, 34);
                    }
                }
            }
            htlc_cursor += fc_n_per[w];
        }
    }

    return 1;
}

/* watchtower_set_channel removed in #208 A3.2 — see oracular API. */

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
    /* v32 (SF-WTC): unset by default; populated post-watch by callers that
       have live channel access (watchtower_watch_revoked_commitment etc.),
       or hydrated from DB at restart by persist_load_watchtower_entries. */
    e->csv_delay = 0;
    e->n_htlc_outputs = 0;
    e->response_tx = NULL;
    e->response_tx_len = 0;
    /* Oracular bytes start NULL — set by watchtower_watch_oracular wrapper. */
    e->signed_penalty_tx = NULL;
    e->signed_penalty_tx_len = 0;

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

int watchtower_watch_oracular(watchtower_t *wt, uint32_t channel_id,
                                uint64_t commit_num,
                                const unsigned char *txid32,
                                uint32_t to_local_vout,
                                uint64_t to_local_amount,
                                const unsigned char *to_local_spk,
                                size_t spk_len,
                                const unsigned char *signed_penalty_tx,
                                size_t signed_penalty_tx_len) {
    /* Register the entry via the legacy path so persist + script
       registration stay identical, then attach pre-signed bytes onto
       the just-added entry.  Falls back to legacy lazy-build path
       transparently when caller passes NULL bytes. */
    if (!watchtower_watch(wt, channel_id, commit_num, txid32,
                            to_local_vout, to_local_amount,
                            to_local_spk, spk_len))
        return 0;
    if (signed_penalty_tx && signed_penalty_tx_len > 0) {
        watchtower_entry_t *e = &wt->entries[wt->n_entries - 1];
        unsigned char *copy = malloc(signed_penalty_tx_len);
        if (!copy) return 0;
        memcpy(copy, signed_penalty_tx, signed_penalty_tx_len);
        /* Defensive: free any stray pointer (shouldn't exist on a fresh
           entry just allocated by watchtower_watch, but the swap-with-last
           deletion pattern means we cannot universally trust slot zero-ness
           without a memset). */
        free(e->signed_penalty_tx);
        e->signed_penalty_tx = copy;
        e->signed_penalty_tx_len = signed_penalty_tx_len;
        /* v25: persist the pre-built bytes so they survive LSP restart.
           Without this, the restart loader can't reattach the bytes, the
           oracular fast-path skips broadcast, and the channel goes
           undefended. */
        if (wt->db && wt->db->db)
            persist_save_old_commitment_witness(wt->db, channel_id, commit_num,
                                                  signed_penalty_tx,
                                                  signed_penalty_tx_len);
    }
    return 1;
}

void watchtower_watch_revoked_commitment(watchtower_t *wt, channel_t *ch,
                                           uint32_t channel_id,
                                           uint64_t old_commit_num,
                                           uint64_t old_local, uint64_t old_remote,
                                           const htlc_t *old_htlcs, size_t old_n_htlcs,
                                           const ptlc_t *old_ptlcs, size_t old_n_ptlcs) {
    if (!wt)
        return;

    /* Save current state (HTLC + PTLC — the old commitment may have had
     * different active HTLCs/PTLCs than the current channel state) */
    uint64_t saved_num = ch->commitment_number;
    uint64_t saved_local = ch->local_amount;
    uint64_t saved_remote = ch->remote_amount;
    size_t saved_n_htlcs = ch->n_htlcs;
    htlc_t *saved_htlcs = saved_n_htlcs > 0
        ? malloc(saved_n_htlcs * sizeof(htlc_t)) : NULL;
    if (saved_n_htlcs > 0 && !saved_htlcs) return;
    if (saved_n_htlcs > 0)
        memcpy(saved_htlcs, ch->htlcs, saved_n_htlcs * sizeof(htlc_t));
    /* SF-W-PTLC: also save PTLC state */
    size_t saved_n_ptlcs = ch->n_ptlcs;
    ptlc_t *saved_ptlcs = saved_n_ptlcs > 0
        ? malloc(saved_n_ptlcs * sizeof(ptlc_t)) : NULL;
    if (saved_n_ptlcs > 0 && !saved_ptlcs) {
        free(saved_htlcs);
        return;
    }
    if (saved_n_ptlcs > 0)
        memcpy(saved_ptlcs, ch->ptlcs, saved_n_ptlcs * sizeof(ptlc_t));

    /* Temporarily set to old state, restoring the HTLC + PTLC state that was
     * active at the time of the old commitment. This ensures the rebuilt
     * commitment tx includes HTLC + PTLC outputs and produces the correct txid. */
    ch->commitment_number = old_commit_num;
    ch->local_amount = old_local;
    ch->remote_amount = old_remote;
    if (old_htlcs && old_n_htlcs > 0) {
        ch->n_htlcs = old_n_htlcs;
        memcpy(ch->htlcs, old_htlcs, old_n_htlcs * sizeof(htlc_t));
    } else {
        ch->n_htlcs = 0;
    }
    /* SF-W-PTLC: install old PTLCs so commitment-TX rebuild includes them */
    if (old_ptlcs && old_n_ptlcs > 0) {
        if (ch->ptlcs_cap < old_n_ptlcs) {
            ptlc_t *new_arr = realloc(ch->ptlcs, old_n_ptlcs * sizeof(ptlc_t));
            if (new_arr) {
                ch->ptlcs = new_arr;
                ch->ptlcs_cap = old_n_ptlcs;
            }
        }
        if (ch->ptlcs && ch->ptlcs_cap >= old_n_ptlcs) {
            ch->n_ptlcs = old_n_ptlcs;
            memcpy(ch->ptlcs, old_ptlcs, old_n_ptlcs * sizeof(ptlc_t));
        } else {
            ch->n_ptlcs = 0;  /* alloc failed — degrade gracefully */
        }
    } else {
        ch->n_ptlcs = 0;
    }

    /* Count active HTLCs + PTLCs for output parsing */
    size_t n_active_htlcs = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE)
            n_active_htlcs++;
    }
    size_t n_active_ptlcs = 0;
    for (size_t i = 0; i < ch->n_ptlcs; i++) {
        if (ch->ptlcs[i].state == PTLC_STATE_ACTIVE &&
            ch->ptlcs[i].amount_sats >= 546 /* dust */)
            n_active_ptlcs++;
    }

    /* #206 fix: NO eager remote-PCP install.  channel_get_remote_pcp's
     * fallback handles derive-from-rev-secret when the slot is missing.
     * Eagerly overwriting a still-present slot was a regression — the slot
     * holds the REAL remote PCP from state exchange, and "rev_secret * G"
     * produces the LOCAL party's pubkey in unit-test scenarios (where the
     * test self-revokes), not the remote's.  In production, rev_secret and
     * slot pcp are guaranteed equal by protocol invariant, so removing this
     * block is safe. */

    tx_buf_t old_tx;
    tx_buf_init(&old_tx, 512);
    unsigned char old_txid[32];
    /* Build the REMOTE's old commitment TX — this is what the remote party
       (the potential cheater) would broadcast.  The watchtower has the
       revocation secrets needed to punish via the penalty TX. */
    int ok = channel_build_commitment_tx_for_remote(ch, &old_tx, old_txid);

    /* Restore state (HTLCs + PTLCs) */
    ch->commitment_number = saved_num;
    ch->local_amount = saved_local;
    ch->remote_amount = saved_remote;
    ch->n_htlcs = saved_n_htlcs;
    if (saved_n_htlcs > 0)
        memcpy(ch->htlcs, saved_htlcs, saved_n_htlcs * sizeof(htlc_t));
    /* SF-W-PTLC: restore PTLC state */
    if (saved_n_ptlcs > 0 && saved_ptlcs && ch->ptlcs && ch->ptlcs_cap >= saved_n_ptlcs) {
        ch->n_ptlcs = saved_n_ptlcs;
        memcpy(ch->ptlcs, saved_ptlcs, saved_n_ptlcs * sizeof(ptlc_t));
    } else {
        ch->n_ptlcs = 0;
    }

    if (!ok) {
        tx_buf_free(&old_tx);
        free(saved_htlcs);
        free(saved_ptlcs);
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

                /* v32 SF-WTC #149: stamp csv_delay on the entry just registered
                   (in-memory + DB) so the oracular CPFP path can drive escalation
                   without needing live channel access at bump time. */
                if (wt->n_entries > 0) {
                    wt->entries[wt->n_entries - 1].csv_delay = ch->to_self_delay;
                    if (wt->db && wt->db->db)
                        persist_save_old_commitment_csv_delay(
                            wt->db, channel_id, old_commit_num, ch->to_self_delay);
                }

                /* #208 A3.1b — pre-build the penalty TX bytes at registration
                   time and attach to the entry we just created.  After this
                   land, watchtower_check goes through the oracular fast-path
                   (no channel_t deref) for every revoked-commitment entry.
                   channel_build_penalty_tx is commit-state-independent (it
                   looks up ch->received_revocations[old_commit_num] for the
                   per-commitment secret), so it's safe to call after the
                   channel state has been restored. */
                if (wt->n_entries > 0) {
                    watchtower_entry_t *just_added =
                        &wt->entries[wt->n_entries - 1];
                    int use_anchor = fee_should_use_anchor(wt->fee);
                    tx_buf_t penalty;
                    tx_buf_init(&penalty, 512);
                    if (channel_build_penalty_tx(ch, &penalty,
                            old_txid, 0, old_remote, to_local_spk, 34,
                            old_commit_num,
                            use_anchor ? wt->anchor_spk : NULL,
                            use_anchor ? wt->anchor_spk_len : 0)) {
                        unsigned char *copy = malloc(penalty.len);
                        if (copy) {
                            memcpy(copy, penalty.data, penalty.len);
                            free(just_added->signed_penalty_tx);
                            just_added->signed_penalty_tx = copy;
                            just_added->signed_penalty_tx_len = penalty.len;
                            /* v25: persist so LSP restart can reattach.  Without
                               this, oracular fast-path post-restart sees NULL
                               and skips broadcast. */
                            if (wt->db && wt->db->db)
                                persist_save_old_commitment_witness(
                                    wt->db, channel_id, old_commit_num,
                                    penalty.data, penalty.len);

                            /* SF-WT-TRUSTLESS Phase 2c (#248): mirror penalty
                               into wt_db for trustless WT consumption.  The
                               penalty was just built using channel secrets;
                               wt_db never sees the secrets, only the signed
                               bytes that the WT broadcasts on breach. */
                            if (wt->wt_db && wt->wt_db->db) {
                                /* response_txid = wtxid of the signed penalty
                                   (sha256d of full bytes).  Not the canonical
                                   non-witness txid; wt_db uses it for
                                   observability + indexing only, not for
                                   chain matching (chain matching keys off
                                   parent_txid). */
                                unsigned char resp_txid[32];
                                sha256_double(penalty.data, penalty.len,
                                              resp_txid);
                                /* hex-encode the bytes for storage. */
                                size_t hex_buf_len = penalty.len * 2 + 1;
                                char *hex = (char *)malloc(hex_buf_len);
                                if (hex) {
                                    hex_encode(penalty.data, penalty.len, hex);
                                    int64_t wid = persist_wt_register_watch(
                                        wt->wt_db,
                                        WT_KIND_CHANNEL_COMMITMENT,
                                        channel_id,
                                        old_txid,
                                        /* parent_vout      */ 0,
                                        /* parent_value_sat */ old_remote,
                                        to_local_spk,
                                        /* parent_spk_len   */ 34,
                                        /* csv_delay        */ ch->to_self_delay,
                                        hex,
                                        resp_txid,
                                        /* fee_bump_budget  */ 0,
                                        /* fee_bump_dline   */ 0);
                                    free(hex);
                                    if (wid > 0) {
                                        fprintf(stderr,
                                            "LSP-WT-TRUSTLESS: registered "
                                            "commitment watch_id=%lld for "
                                            "channel %u (commit_num=%llu, "
                                            "to_local=%llu sats)\n",
                                            (long long)wid, channel_id,
                                            (unsigned long long)old_commit_num,
                                            (unsigned long long)old_remote);
                                    } else {
                                        fprintf(stderr,
                                            "LSP-WT-TRUSTLESS: WARN — wt_db "
                                            "commitment register failed for "
                                            "channel %u (commit_num=%llu)\n",
                                            channel_id,
                                            (unsigned long long)old_commit_num);
                                    }
                                }
                            }
                        }
                    }
                    tx_buf_free(&penalty);
                }
            }
        }

        /* SF-W-PTLC: out_ofs lives at outer scope so the PTLC parsing block
           below can pick up where HTLC parsing left off (PTLC outputs follow
           HTLC outputs in the commitment TX layout). */
        size_t out_ofs = ofs;

        /* If we have active HTLCs, parse their outputs (vout 2+) and store
         * in the watchtower entry we just created */
        if (n_active_htlcs > 0 && wt->n_entries > 0) {
            watchtower_entry_t *entry = &wt->entries[wt->n_entries - 1];
            entry->htlc_outputs = calloc(n_active_htlcs, sizeof(watchtower_htlc_t));
            entry->htlc_outputs_cap = entry->htlc_outputs ? n_active_htlcs : 0;
            entry->n_htlc_outputs = 0;

            /* Skip output 0 and output 1 to reach HTLC outputs */
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

            /* v35 (#207): pre-build the signed HTLC sweep TX bytes at
               registration time and persist them, mirroring the v25 pattern
               for the to_local penalty TX above.  Closes the restart-loses-
               HTLC-defense gap: after an LSP crash, watchtower_check no
               longer needs live channel_t state to broadcast HTLC sweeps —
               the bytes are durably on disk.  Also enables standalone-WT
               operation (run superscalar_watchtower against the same DB).

               channel_build_htlc_penalty_tx requires ch->htlcs[0] to carry
               the HTLC metadata (direction, payment_hash, cltv_expiry) —
               same shim watchtower_check uses on the lazy-build path. */
            if (wt->db && wt->db->db && entry->n_htlc_outputs > 0 && ch) {
                int use_anchor_h = fee_should_use_anchor(wt->fee);

                /* Save + restore ch->htlcs[0] across the per-output build loop. */
                size_t wt_saved_n = ch->n_htlcs;
                htlc_t wt_saved_h0 = {0};
                if (wt_saved_n > 0)
                    wt_saved_h0 = ch->htlcs[0];

                for (size_t h = 0; h < entry->n_htlc_outputs; h++) {
                    watchtower_htlc_t *wh_h = &entry->htlc_outputs[h];

                    /* Shim ch->htlcs[0] like the watchtower_check sweep loop. */
                    ch->n_htlcs = 1;
                    memset(&ch->htlcs[0], 0, sizeof(htlc_t));
                    ch->htlcs[0].direction = wh_h->direction;
                    memcpy(ch->htlcs[0].payment_hash, wh_h->payment_hash, 32);
                    ch->htlcs[0].cltv_expiry = wh_h->cltv_expiry;
                    ch->htlcs[0].state = HTLC_STATE_ACTIVE;

                    tx_buf_t sweep;
                    tx_buf_init(&sweep, 512);
                    if (channel_build_htlc_penalty_tx(ch, &sweep,
                            old_txid, wh_h->htlc_vout, wh_h->htlc_amount,
                            wh_h->htlc_spk, 34, old_commit_num, 0,
                            use_anchor_h ? wt->anchor_spk : NULL,
                            use_anchor_h ? wt->anchor_spk_len : 0)) {
                        persist_save_old_commitment_htlc_sweep(
                            wt->db, channel_id, old_commit_num,
                            wh_h->htlc_vout, sweep.data, sweep.len);
                        /* G2 #45: mirror the HTLC penalty sweep into wt_db so a
                           SECRET-LESS standalone WT also sweeps in-flight HTLCs on
                           a commitment breach (without this it penalizes to_local
                           but leaks HTLC value).  Keyed on the breach commit txid;
                           same pattern + sha256_double(resp) txid as the to_local
                           mirror above. */
                        if (wt->wt_db && wt->wt_db->db) {
                            unsigned char h_resp_txid[32];
                            sha256_double(sweep.data, sweep.len, h_resp_txid);
                            char *h_hex = (char *)malloc(sweep.len * 2 + 1);
                            if (h_hex) {
                                hex_encode(sweep.data, sweep.len, h_hex);
                                int64_t hwid = persist_wt_register_watch(
                                    wt->wt_db, WT_KIND_CHANNEL_COMMITMENT,
                                    channel_id, old_txid,
                                    wh_h->htlc_vout, wh_h->htlc_amount,
                                    wh_h->htlc_spk, 34,
                                    ch->to_self_delay,
                                    h_hex, h_resp_txid, 0, 0);
                                free(h_hex);
                                if (hwid <= 0)
                                    fprintf(stderr, "LSP-WT-TRUSTLESS: WARN — wt_db "
                                        "HTLC-sweep register failed (ch %u vout %u)\n",
                                        channel_id, wh_h->htlc_vout);
                            }
                        }
                    } else {
                        fprintf(stderr,
                                "watchtower: failed to build HTLC sweep TX "
                                "(vout %u) at registration time — restart "
                                "defense will fall back to lazy build\n",
                                wh_h->htlc_vout);
                    }
                    tx_buf_free(&sweep);
                }

                /* Restore ch->htlcs[0] / ch->n_htlcs. */
                ch->n_htlcs = wt_saved_n;
                if (wt_saved_n > 0)
                    ch->htlcs[0] = wt_saved_h0;
            }
        }

        /* SF-W-PTLC: parse PTLC outputs (vouts after HTLC outputs).  Without
           this feed, watchtower_check's PTLC sweep loop is unreachable and a
           breach with PTLCs in flight leaks PTLC value.  Mirror of the HTLC
           block above; uses old_ptlcs (passed in) and walks outputs starting
           where the HTLC parse left off (out_ofs). */
        if (n_active_ptlcs > 0 && wt->n_entries > 0 && old_ptlcs) {
            watchtower_entry_t *entry = &wt->entries[wt->n_entries - 1];
            entry->ptlc_outputs = calloc(n_active_ptlcs, sizeof(watchtower_htlc_t));
            entry->n_ptlc_outputs = 0;

            /* If there were no HTLC outputs, out_ofs is still at the first
               output; advance past to_local + to_remote.  If HTLCs existed,
               the HTLC parse already advanced out_ofs to the post-HTLC
               position. */
            if (n_active_htlcs == 0) {
                for (uint32_t v = 0; v < 2; v++) {
                    if (out_ofs + 9 > old_tx.len) break;
                    uint8_t slen = old_tx.data[out_ofs + 8];
                    out_ofs += 8 + 1 + slen;
                }
            }

            size_t ptlc_active_idx = 0;
            if (entry->ptlc_outputs)
            for (size_t i = 0; i < old_n_ptlcs && ptlc_active_idx < n_active_ptlcs; i++) {
                if (old_ptlcs[i].state != PTLC_STATE_ACTIVE) continue;
                if (old_ptlcs[i].amount_sats < 546 /* dust */) continue;

                if (out_ofs + 8 + 1 > old_tx.len) break;
                uint64_t amount = 0;
                for (int b = 0; b < 8; b++)
                    amount |= ((uint64_t)old_tx.data[out_ofs + b]) << (b * 8);
                uint8_t slen = old_tx.data[out_ofs + 8];
                if (slen != 34 || out_ofs + 9 + slen > old_tx.len) {
                    out_ofs += 8 + 1 + slen;
                    ptlc_active_idx++;
                    continue;
                }

                watchtower_htlc_t *wp = &entry->ptlc_outputs[entry->n_ptlc_outputs];
                wp->htlc_vout = (uint32_t)(2 + n_active_htlcs + ptlc_active_idx);
                wp->htlc_amount = amount;
                memcpy(wp->htlc_spk, &old_tx.data[out_ofs + 9], 34);
                wp->direction = (htlc_direction_t)old_ptlcs[i].direction;
                /* Store xonly form of payment_point in payment_hash[32].
                   The persist + sweep code already treats this field as
                   the xonly serialization for PTLC entries. */
                {
                    secp256k1_xonly_pubkey pp_xonly;
                    if (secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &pp_xonly,
                            NULL, &old_ptlcs[i].payment_point)) {
                        secp256k1_xonly_pubkey_serialize(ch->ctx,
                            wp->payment_hash, &pp_xonly);
                    } else {
                        memset(wp->payment_hash, 0, 32);
                    }
                }
                wp->cltv_expiry = old_ptlcs[i].cltv_expiry;
                entry->n_ptlc_outputs++;

                /* Register PTLC script with chain backend */
                if (wt->chain && wt->chain->register_script)
                    wt->chain->register_script(wt->chain, wp->htlc_spk, 34);

                out_ofs += 8 + 1 + slen;
                ptlc_active_idx++;
            }

            /* Persist PTLC outputs (transactional) */
            if (wt->db && wt->db->db && entry->n_ptlc_outputs > 0) {
                if (!persist_begin(wt->db)) {
                    fprintf(stderr, "watchtower: persist_begin failed, skipping PTLC persist\n");
                } else {
                    int ptlc_ok = 1;
                    for (size_t p = 0; p < entry->n_ptlc_outputs; p++) {
                        if (!persist_save_old_commitment_ptlc(wt->db, channel_id,
                                old_commit_num, &entry->ptlc_outputs[p])) {
                            ptlc_ok = 0;
                            break;
                        }
                    }
                    if (ptlc_ok)
                        persist_commit(wt->db);
                    else
                        persist_rollback(wt->db);
                }
            }
        }
    }

    tx_buf_free(&old_tx);
    free(saved_htlcs);
    free(saved_ptlcs);
}

void watchtower_watch_revoked_commitment_oracular(watchtower_t *wt, channel_t *ch,
                                                    uint32_t channel_id,
                                                    uint64_t old_commit_num,
                                                    uint64_t old_local,
                                                    uint64_t old_remote,
                                                    const htlc_t *old_htlcs,
                                                    size_t old_n_htlcs,
                                                    const ptlc_t *old_ptlcs,
                                                    size_t old_n_ptlcs,
                                                    const unsigned char *signed_penalty_tx,
                                                    size_t signed_penalty_tx_len) {
    /* Run the existing registration so persist + script registration +
       HTLC + PTLC parsing all stay identical.  Then attach pre-signed
       penalty TX bytes to the new entry (the LAST one, since the legacy
       call always pushes to wt->n_entries - 1 if successful).

       If signed_penalty_tx is NULL we degrade to legacy lazy-build
       behaviour transparently — same call shape as the non-oracular
       form. */
    size_t n_before = wt->n_entries;
    watchtower_watch_revoked_commitment(wt, ch, channel_id, old_commit_num,
                                          old_local, old_remote,
                                          old_htlcs, old_n_htlcs,
                                          old_ptlcs, old_n_ptlcs);
    if (!signed_penalty_tx || signed_penalty_tx_len == 0) return;
    if (wt->n_entries == n_before) return;  /* legacy registration failed */

    watchtower_entry_t *e = &wt->entries[wt->n_entries - 1];
    unsigned char *copy = malloc(signed_penalty_tx_len);
    if (!copy) return;
    memcpy(copy, signed_penalty_tx, signed_penalty_tx_len);
    free(e->signed_penalty_tx);
    e->signed_penalty_tx = copy;
    e->signed_penalty_tx_len = signed_penalty_tx_len;
    /* v25: persist so LSP restart can reattach.  See companion calls in
       watchtower_watch_oracular and watchtower_watch_revoked_commitment. */
    if (wt->db && wt->db->db)
        persist_save_old_commitment_witness(wt->db, channel_id, old_commit_num,
                                              signed_penalty_tx,
                                              signed_penalty_tx_len);
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
            int safe = chain_penalty_confs(wt->chain, is_rt);
            if (pconf >= safe) {
                /* Penalty safely confirmed — remove entry */
                free(e->htlc_outputs); free(e->ptlc_outputs);
                free(e->response_tx); free(e->burn_tx);
                /* Oracular bytes (#208 A3.1) — free before swap-with-last */
                free(e->signed_penalty_tx);
                e->signed_penalty_tx = NULL;
                e->signed_penalty_tx_len = 0;
                wt->entries[i] = wt->entries[wt->n_entries - 1];
                /* NULL the swap source so swap_dst's free above doesn't
                   double-free the moved pointers when the slot is later
                   reused via wt->n_entries++ */
                wt->entries[wt->n_entries - 1].signed_penalty_tx = NULL;
                wt->entries[wt->n_entries - 1].signed_penalty_tx_len = 0;
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

            /* #52: enqueue the factory-node response for CPFP fee-bump monitoring.
               Hydrated wt_db entries all flatten to WATCH_FACTORY_NODE, and this
               handler previously never enqueued — so a standalone WT broadcast its
               response ONCE at the registration feerate and could never bump it,
               losing the race under fee pressure (proven via SS_HIFEE_GAP). The
               default RPC wallet (watchtower.c:95) + the existing deadline-aware
               escalator (watchtower_build_cpfp_tx) do the rest. Mirrors the
               WATCH_COMMITMENT enqueue; only when the response carries a P2A anchor. */
            if (factory_resp_txid[0] &&
                penalty_tx_has_p2a_anchor(e->response_tx, e->response_tx_len) &&
                wt->anchor_spk_len == P2A_SPK_LEN &&
                wt->n_pending < wt->pending_cap) {
                uint32_t fn_cur_h = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
                watchtower_pending_t *fp = &wt->pending[wt->n_pending++];
                memcpy(fp->txid, factory_resp_txid, 64); fp->txid[64] = '\0';
                fp->anchor_vout = 1;
                fp->anchor_amount = WATCHTOWER_ANCHOR_AMOUNT;
                fp->penalty_value = (e->sub_sales_stock_amount > 0)
                                    ? e->sub_sales_stock_amount
                                    : e->to_local_amount;
                fp->csv_delay = (e->csv_delay > 0) ? e->csv_delay : CHANNEL_DEFAULT_CSV_DELAY;
                fp->start_height = fn_cur_h;
                fp->cycles_in_mempool = 0;
                memset(&fp->fee_bump, 0, sizeof(fp->fee_bump));
                if (wt->db && wt->db->db)
                    persist_save_pending(wt->db, fp->txid, fp->anchor_vout,
                                          fp->anchor_amount, 0, 0, fp->penalty_value,
                                          fp->csv_delay, fp->start_height, 0, 0, 0, 0);
                printf("  factory-node response %s enqueued for CPFP fee-bump (deadline csv=%u)\n",
                       factory_resp_txid, fp->csv_delay);
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

            /* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248): auto-settle moved to
             * src/watchtower_autosettle.c (linked into superscalar_secrets
             * lib — LSP/client/tests/bridge only).  The trustless WT binary
             * does not link autosettle and leaves wt->autosettle_fn NULL,
             * so this is a no-op there. */
            if (wt->autosettle_fn) wt->autosettle_fn(wt, e);

            /* Mark as penalty-broadcast (keep entry for reorg resistance) */
            e->penalty_broadcast = 1;
            memcpy(e->penalty_txid, factory_resp_txid, 65);

            /* v29 (PR-C-6): observability — record this breach detection.
               Only fired when we *actually broadcast* a response TX
               (not just when we saw the stale state). */
            if (wt->db && wt->db->db) {
                int height = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
                persist_log_breach_detection(wt->db, e->channel_id,
                    e->commit_num, e->txid, height, factory_resp_txid);
            }

            i++;
            continue;
        }

        if (e->type == WATCH_SUBFACTORY_NODE) {
            /* PS sub-factory chain breach (k² shape).
               Stale chain[N-1] confirmed.  The recourse mechanism is the
               poison TX (Gap A): it spends chain[N-1].sales_stock_vout and
               distributes the sales-stock pro-rata to each non-LSP signer.

               Historical note: an earlier version of this handler ALSO
               broadcast `response_tx` (the latest chain[N]) for symmetry
               with WATCH_FACTORY_NODE.  But response_tx and poison_tx
               compete for the same chain[N-1].sales_stock UTXO — only one
               can win.  After chain[N-1] confirms, response_tx
               (chain[N]) is structurally invalid: its parent input is
               consumed by chain[N-1]'s confirmation and bitcoind correctly
               rejects with -25 bad-txns-inputs-missingorspent.  Poison
               TX is the actual recourse; response_tx broadcast was always
               a no-op when bitcoind validation actually ran (regtest tests
               passed because they exited before broadcast was attempted).

               This cleanup removes the dead response_tx broadcast.  The
               watchtower entry's response_tx field is still populated by
               watchtower_watch_subfactory_node for compatibility with the
               WATCH_FACTORY_NODE shape, but is no longer broadcast here.

               Unlike WATCH_FACTORY_NODE we do NOT auto-settle channels —
               sub-factory clients live inside the sub-factory chain TX,
               not as separately registered channels in wt->channels[].
               Their per-channel claims are encoded in the poison TX
               outputs, not in independent commitment TXs. */
            printf("SUB-FACTORY BREACH on node %u (txid: %s, %zu channels, "
                   "sales-stock %llu sats)!\n",
                   e->channel_id, txid_hex, e->n_sub_channels,
                   (unsigned long long)e->sub_sales_stock_amount);
            fflush(stdout);

            char sub_resp_txid[65] = {0};

            if (e->burn_tx && e->burn_tx_len > 0) {
                char *poison_hex = (char *)malloc(e->burn_tx_len * 2 + 1);
                if (poison_hex) {
                    hex_encode(e->burn_tx, e->burn_tx_len, poison_hex);
                    char poison_txid[65];
                    if (wt->chain->send_raw_tx(wt->chain, poison_hex, poison_txid)) {
                        printf("  Sub-factory poison tx broadcast: %s\n", poison_txid);
                        memcpy(sub_resp_txid, poison_txid, 64);
                        sub_resp_txid[64] = '\0';
                        penalties_broadcast++;
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, poison_txid,
                                                  "subfactory_poison", poison_hex, "ok");
                        /* v29 (PR-C-6 / #176): observability — record sub-factory
                           breach detection.  Mirrors WATCH_FACTORY_NODE call at L932. */
                        if (wt->db && wt->db->db) {
                            int sub_h = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
                            persist_log_breach_detection(wt->db, e->channel_id,
                                e->commit_num, e->txid, sub_h, poison_txid);
                        }
                    } else {
                        fprintf(stderr, "  Sub-factory poison tx broadcast failed\n");
                        if (wt->db && wt->db->db)
                            persist_log_broadcast(wt->db, "?",
                                                  "subfactory_poison", poison_hex, "failed");
                    }
                    free(poison_hex);
                }
            } else {
                fprintf(stderr,
                        "  Sub-factory breach detected but no poison TX "
                        "available — degraded path (Gap A SECURITY GAP).  "
                        "Stale sales-stock cannot be redistributed.\n");
            }

            e->penalty_broadcast = 1;
            memcpy(e->penalty_txid, sub_resp_txid, 65);
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

        /* Oracular path (#208 A3.2 — only path now): broadcast the
           pre-signed bytes attached to the entry at registration time.
           Fail-closed if missing — the legacy lazy-build via
           wt->channels[] was removed in A3.2 along with the field. */
        tx_buf_t penalty_tx;
        tx_buf_init(&penalty_tx, 512);
        int use_anchor = fee_should_use_anchor(wt->fee);

        if (!e->signed_penalty_tx || e->signed_penalty_tx_len == 0) {
            fprintf(stderr,
                    "Watchtower: entry %u has no signed_penalty_tx — skipping "
                    "(register via watchtower_watch_oracular or "
                    "watchtower_watch_revoked_commitment to attach bytes)\n",
                    e->channel_id);
            tx_buf_free(&penalty_tx);
            i++;
            continue;
        }
        tx_buf_write_bytes(&penalty_tx, e->signed_penalty_tx,
                            e->signed_penalty_tx_len);
        if (penalty_tx.oom) {
            fprintf(stderr,
                    "Watchtower: copy penalty bytes failed (OOM)\n");
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
                /* v29 (PR-C-6 / #175): observability — record HTLC-commitment
                   breach detection.  Mirrors WATCH_FACTORY_NODE call at L932. */
                if (wt->db && wt->db->db) {
                    int com_h = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
                    persist_log_breach_detection(wt->db, e->channel_id,
                        e->commit_num, e->txid, com_h, penalty_txid);
                }
            } else {
                fprintf(stderr, "  Penalty tx broadcast failed — queued for retry\n");
                if (wt->db && wt->db->db)
                    persist_log_broadcast(wt->db, "?", "penalty",
                                          penalty_hex, "pending_retry");
            }
            free(penalty_hex);
        }
        tx_buf_free(&penalty_tx);

        /* Look up the live channel pointer for the secondary CPFP/HTLC/PTLC
           sweep loops below.  In production this is always NULL (channels[]
           is unpopulated after #208 A3.1b dropped watchtower_set_channel),
           so all `if (ch)` branches short-circuit.  A3.3 will pre-build
           these secondary TX bytes at revocation time and remove the
           channels[] field entirely. */
        channel_t *ch = NULL;
        if (e->channel_id < wt->channels_cap)
            ch = wt->channels[e->channel_id];

        /* Track in pending for CPFP bump if anchor is active.
           Use authoritative byte-inspection of the pre-built penalty TX
           (penalty_tx_has_p2a_anchor) rather than re-deriving use_anchor —
           the build-time and broadcast-time fee_should_use_anchor() can
           disagree when the URGENT fee rate crosses 1 sat/vB in between,
           which produces ghost-anchor pending entries whose CPFP child
           bitcoind rejects with bad-txns-inputs-missingorspent.
           SF-WTC #149: dropped `ch &&` gate.  csv_delay now sourced from
           e->csv_delay (persisted at watch-registration), falling back to
           live ch->to_self_delay for legacy entries pre v32, and to the
           hard default if neither is available. */
        uint32_t cur_height = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
        bool penalty_actually_has_anchor =
            penalty_tx_has_p2a_anchor(e->signed_penalty_tx,
                                        e->signed_penalty_tx_len);
        if (penalty_sent && penalty_actually_has_anchor &&
            wt->anchor_spk_len == P2A_SPK_LEN &&
            wt->n_pending < wt->pending_cap) {
            watchtower_pending_t *p = &wt->pending[wt->n_pending++];
            memcpy(p->txid, penalty_txid, 64);
            p->txid[64] = '\0';
            p->anchor_vout = 1;
            p->anchor_amount = WATCHTOWER_ANCHOR_AMOUNT;
            p->penalty_value = e->to_local_amount;
            p->csv_delay = (e->csv_delay > 0) ? e->csv_delay
                          : (ch ? ch->to_self_delay : CHANNEL_DEFAULT_CSV_DELAY);
            p->start_height = cur_height;
            p->cycles_in_mempool = 0;
            memset(&p->fee_bump, 0, sizeof(p->fee_bump));
            if (wt->db && wt->db->db) {
                /* fee_bump is freshly memset above — escalation schedule
                   not yet initialised; persist zeros so a restart-then-
                   first-bump path still calls htlc_fee_bump_init normally. */
                persist_save_pending(wt->db, p->txid, p->anchor_vout,
                                       p->anchor_amount, 0, 0,
                                       p->penalty_value, p->csv_delay, p->start_height,
                                       0, 0, 0, 0);
            }
        }

        /* Sweep HTLC outputs via penalty txs.  Skip on the oracular path
           (ch == NULL) — A3.1b will add an HTLC-penalty oracular variant
           that pre-builds these TXs at revocation time and stores them
           in e->htlc_outputs[].sweep_txid alongside the main penalty. */
        if (!ch) {
            i++;
            continue;
        }
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
            /* SF-W-PTLC fix: payment_hash[32] holds the xonly form of the
               PTLC payment_point.  Prepend the even-parity byte (0x02) to
               build a 33-byte compressed pubkey for secp256k1_ec_pubkey_parse;
               consumer (channel_build_ptlc_penalty_tx) only uses the xonly
               form via secp256k1_xonly_pubkey_from_pubkey, so parity is
               immaterial for the script-merkle reconstruction.  Pre-fix
               this read 33 bytes from a 32-byte field (heap OOB). */
            {
                unsigned char pp33[33];
                pp33[0] = 0x02;
                memcpy(pp33 + 1, e->ptlc_outputs[p].payment_hash, 32);
                secp256k1_ec_pubkey_parse(ch->ctx, &ch->ptlcs[0].payment_point,
                                           pp33, 33);
            }

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
                    int sweep_safe = chain_sweep_confs(wt->chain, sweep_rt);
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
                /* #248 leak fix: matching ptlc_outputs free. */
                free(e->ptlc_outputs);
                e->ptlc_outputs = NULL;
                /* Oracular bytes (#208 A3.1) — free before swap-with-last */
                free(e->signed_penalty_tx);
                e->signed_penalty_tx = NULL;
                e->signed_penalty_tx_len = 0;
                wt->entries[i] = wt->entries[wt->n_entries - 1];
                wt->entries[wt->n_entries - 1].signed_penalty_tx = NULL;
                wt->entries[wt->n_entries - 1].signed_penalty_tx_len = 0;
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
            uint32_t cur_height = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
            if (p->start_height == 0) p->start_height = cur_height;
            uint32_t csv = p->csv_delay > 0 ? p->csv_delay : CHANNEL_DEFAULT_CSV_DELAY;
            uint32_t deadline = p->start_height + csv;
            if (deadline <= cur_height + HTLC_FEE_BUMP_URGENT_BLOCKS)
                deadline = cur_height + HTLC_FEE_BUMP_URGENT_BLOCKS + 1;

            uint64_t start_fr = wt->fee ? (uint64_t)wt->fee->get_rate(wt->fee, FEE_TARGET_NORMAL) : 1000;
            if (start_fr < HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB)
                start_fr = HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB;

            uint64_t budget_basis = p->penalty_value > 0 ? p->penalty_value : p->anchor_amount;
            int budget_pct = wt->bump_budget_pct > 0 ? wt->bump_budget_pct : HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT;

            htlc_fee_bump_init(&p->fee_bump, cur_height, deadline,
                               budget_basis, budget_pct,
                               WATCHTOWER_CPFP_CHILD_VSIZE, start_fr);

            if (wt->max_bump_fee_sat > 0 && p->fee_bump.budget_sat > wt->max_bump_fee_sat)
                p->fee_bump.budget_sat = wt->max_bump_fee_sat;
        }
        uint32_t cur_block = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
        if (htlc_fee_bump_should_bump(&p->fee_bump, cur_block)) {
            /* Pre-flight: bitcoind rejects CPFP with
             * bad-txns-inputs-missingorspent when the parent is no longer
             * in mempool — RBF replacement, mempool eviction, or never
             * propagated. Skip the build+broadcast effort in that case
             * and emit a meaningful skip line rather than a confusing
             * "broadcast failed". If parent confirmed in the gap since
             * the conf check at loop top, the next cycle removes the entry. */
            bool parent_in_mempool = !wt->chain->is_in_mempool ||
                wt->chain->is_in_mempool(wt->chain, p->txid);
            if (!parent_in_mempool) {
                fprintf(stderr,
                    "  CPFP skipped: parent %s not in mempool (cycles=%d)\n",
                    p->txid, p->cycles_in_mempool);
            } else {
                uint64_t fr = htlc_fee_bump_calc_feerate(&p->fee_bump, cur_block);
                tx_buf_t cpfp;
                tx_buf_init(&cpfp, 512);
                if (watchtower_build_cpfp_tx(wt, &cpfp, p->txid,
                                               p->anchor_vout, p->anchor_amount, fr)) {
                    char *cpfp_hex = (char *)malloc(cpfp.len * 2 + 1);
                    if (cpfp_hex) {
                        hex_encode(cpfp.data, cpfp.len, cpfp_hex);
                        char cpfp_txid[65];
                        if (wt->chain->send_raw_tx(wt->chain, cpfp_hex, cpfp_txid)) {
                            htlc_fee_bump_record_broadcast(&p->fee_bump, cur_block, fr);
                            printf("  CPFP child broadcast (feerate %llu): %s\n",
                                   (unsigned long long)fr, cpfp_txid);
                            if (wt->db && wt->db->db) {
                                /* v27: persist the escalation schedule so a
                                   mid-bump restart resumes instead of rebasing. */
                                persist_save_pending(wt->db, p->txid,
                                    p->anchor_vout, p->anchor_amount,
                                    p->cycles_in_mempool,
                                    (int)p->fee_bump.last_bump_block,
                                    p->penalty_value, p->csv_delay, p->start_height,
                                    p->fee_bump.start_block,
                                    p->fee_bump.deadline_block,
                                    p->fee_bump.budget_sat,
                                    p->fee_bump.start_feerate);
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
                               uint64_t anchor_amount,
                               uint64_t target_feerate_kvb) {
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

    uint64_t cpfp_fee = target_feerate_kvb > 0
        ? (target_feerate_kvb * WATCHTOWER_CPFP_CHILD_VSIZE + 999) / 1000
        : (wt->fee ? fee_for_cpfp_child(wt->fee) : 200);
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

    uint32_t cur_height = wt->chain ? wt->chain->get_block_height(wt->chain) : 0;
    watchtower_pending_t *p = &wt->pending[wt->n_pending++];
    strncpy(p->txid, txid_hex, 64);
    p->txid[64] = '\0';
    p->anchor_vout       = anchor_vout;
    p->anchor_amount     = anchor_amount;
    p->penalty_value     = 0;
    p->csv_delay         = CHANNEL_DEFAULT_CSV_DELAY;
    p->start_height      = cur_height;
    p->cycles_in_mempool = 0;
    memset(&p->fee_bump, 0, sizeof(p->fee_bump));

    if (wt->db && wt->db->db)
        persist_save_pending(wt->db, p->txid, p->anchor_vout,
                               p->anchor_amount, 0, 0,
                               p->penalty_value, p->csv_delay, p->start_height,
                               0, 0, 0, 0);
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

int watchtower_watch_factory_node_with_channels(watchtower_t *wt,
    uint32_t node_idx, const unsigned char *old_txid32,
    const unsigned char *response_tx, size_t response_tx_len,
    const unsigned char *burn_tx, size_t burn_tx_len,
    const uint32_t *channel_ids, size_t n_channels)
{
    if (!watchtower_watch_factory_node(wt, node_idx, old_txid32,
                                        response_tx, response_tx_len,
                                        burn_tx, burn_tx_len))
        return 0;

    /* Attach channel indices to the just-added entry */
    if (channel_ids && n_channels > 0) {
        watchtower_entry_t *e = &wt->entries[wt->n_entries - 1];
        e->leaf_channel_ids = (uint32_t *)malloc(n_channels * sizeof(uint32_t));
        if (e->leaf_channel_ids) {
            memcpy(e->leaf_channel_ids, channel_ids, n_channels * sizeof(uint32_t));
            e->n_leaf_channels = n_channels;
        }
    }
    return 1;
}

int watchtower_watch_subfactory_node(watchtower_t *wt,
    uint32_t sub_node_idx,
    const unsigned char *old_chain_txid32,
    const unsigned char *response_tx, size_t response_tx_len,
    const unsigned char *poison_tx, size_t poison_tx_len,
    const uint64_t *channel_amounts, size_t n_channels,
    uint64_t sales_stock_amount)
{
    if (!wt || !old_chain_txid32 || !response_tx || response_tx_len == 0) return 0;
    if (wt->n_entries >= wt->entries_cap) return 0;

    watchtower_entry_t *e = &wt->entries[wt->n_entries];
    memset(e, 0, sizeof(*e));
    e->type = WATCH_SUBFACTORY_NODE;
    e->channel_id = sub_node_idx;
    e->commit_num = 0;
    memcpy(e->txid, old_chain_txid32, 32);

    e->response_tx = (unsigned char *)malloc(response_tx_len);
    if (!e->response_tx) return 0;
    memcpy(e->response_tx, response_tx, response_tx_len);
    e->response_tx_len = response_tx_len;

    /* Poison TX: distributes stale sales-stock to clients on breach.
       Optional during early integration; the actual poison-TX builder
       lands in a follow-up PR.  Reuses the burn_tx[] storage in the
       entry (same shape — pre-built TX to broadcast on breach). */
    if (poison_tx && poison_tx_len > 0) {
        e->burn_tx = (unsigned char *)malloc(poison_tx_len);
        if (!e->burn_tx) {
            free(e->response_tx);
            e->response_tx = NULL;
            return 0;
        }
        memcpy(e->burn_tx, poison_tx, poison_tx_len);
        e->burn_tx_len = poison_tx_len;
    }

    /* Per-channel amounts at chain[N-1] — needed by analytics + by the
       poison TX builder once wired.  Copied so caller's buffer is free
       to be reused. */
    if (channel_amounts && n_channels > 0) {
        e->sub_channel_amounts = (uint64_t *)malloc(n_channels * sizeof(uint64_t));
        if (!e->sub_channel_amounts) {
            free(e->response_tx);  e->response_tx = NULL;
            free(e->burn_tx);       e->burn_tx = NULL;
            return 0;
        }
        memcpy(e->sub_channel_amounts, channel_amounts,
               n_channels * sizeof(uint64_t));
        e->n_sub_channels = n_channels;
    }
    e->sub_sales_stock_amount = sales_stock_amount;

    wt->n_entries++;
    return 1;
}

/* SF-WT-TRUSTLESS Phase 2 (#248): hydrate from wt_db. */
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

/* SF-WT-TRUSTLESS Phase 2c hydration helper.
 *
 * Trustless watch model: the WT broadcasts the row's response_tx when
 * the row's parent_txid is observed spent.  This is mechanically the
 * SAME action for every watch kind (factory, sub-factory, channel
 * commitment breach, force-close HTLC sweep) — only the LSP-side
 * bookkeeping kind differs.  At hydration we use the WATCH_FACTORY_NODE
 * in-memory shape uniformly, because its broadcast path (chain-observed
 * parent → broadcast pre-built response_tx) is the trustless contract.
 *
 * The kind discriminant is consumed by the LSP and by observability
 * dashboards via wt_db queries — the WT process itself doesn't act on
 * it.  Per-kind counters logged at the end aid operator audits.
 *
 * In legacy --db mode (Phase 1) hydration of channel commitment and
 * force-close watches goes through src/watchtower.c's revoked-commit
 * and force-close entry points which require lsp.db secrets.  Phase 2c
 * removes that requirement for the standalone WT binary.
 */
typedef struct {
    watchtower_t *wt;
    int n_loaded;
    int n_skipped;
} wt_hydrate_ctx_t;

static int wt_hydrate_row_cb(uint32_t factory_id,
                              const unsigned char parent_txid32[32],
                              uint32_t parent_vout,
                              uint64_t parent_value_sat,
                              const unsigned char *parent_spk,
                              size_t parent_spk_len,
                              uint32_t csv_delay,
                              const char *response_tx_hex,
                              const unsigned char response_txid32[32],
                              uint64_t fee_bump_budget_sat,
                              uint32_t fee_bump_deadline_height,
                              void *user) {
    (void)parent_vout; (void)parent_value_sat;
    (void)parent_spk;  (void)parent_spk_len; (void)csv_delay;
    (void)response_txid32;
    (void)fee_bump_budget_sat; (void)fee_bump_deadline_height;
    wt_hydrate_ctx_t *ctx = (wt_hydrate_ctx_t *)user;

    int hex_len = (int)strlen(response_tx_hex);
    if (hex_len <= 0 || (hex_len % 2) != 0) {
        fprintf(stderr,
                "watchtower_hydrate_from_wt_db: skip row factory_id=%u: "
                "response_tx_hex len=%d not valid hex\n",
                factory_id, hex_len);
        ctx->n_skipped++;
        return 1;
    }
    size_t resp_len = (size_t)hex_len / 2;
    unsigned char *resp = malloc(resp_len);
    if (!resp) {
        fprintf(stderr,
                "watchtower_hydrate_from_wt_db: OOM allocating %zu bytes\n",
                resp_len);
        ctx->n_skipped++;
        return 1;
    }
    if (hex_decode(response_tx_hex, resp, resp_len) != (int)resp_len) {
        fprintf(stderr,
                "watchtower_hydrate_from_wt_db: hex_decode failed for "
                "factory_id=%u\n", factory_id);
        free(resp);
        ctx->n_skipped++;
        return 1;
    }

    unsigned char parent_txid[32];
    memcpy(parent_txid, parent_txid32, 32);
    if (watchtower_watch_factory_node(ctx->wt, factory_id, parent_txid,
                                        resp, resp_len, NULL, 0)) {
        ctx->n_loaded++;
    } else {
        fprintf(stderr,
                "watchtower_hydrate_from_wt_db: watch_factory_node failed "
                "for factory_id=%u\n", factory_id);
        ctx->n_skipped++;
    }
    free(resp);
    return 1;
}

int watchtower_hydrate_from_wt_db(watchtower_t *wt, persist_wt_t *pwt) {
    if (!wt || !pwt || !pwt->db) return -1;

    wt_hydrate_ctx_t ctx = { .wt = wt, .n_loaded = 0, .n_skipped = 0 };

    static const struct { wt_watch_kind_t kind; const char *label; } kinds[] = {
        { WT_KIND_FACTORY_NODE,       "factory"       },
        { WT_KIND_SUBFACTORY_NODE,    "subfactory"    },
        { WT_KIND_CHANNEL_COMMITMENT, "commitment"    },
        { WT_KIND_FORCE_CLOSE_HTLC,   "force_close"   },
    };
    int per_kind[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(kinds)/sizeof(kinds[0]); i++) {
        int before = ctx.n_loaded;
        int visited = persist_wt_list_watches_by_kind(pwt, kinds[i].kind,
                                                       wt_hydrate_row_cb, &ctx);
        if (visited < 0) {
            fprintf(stderr,
                    "watchtower_hydrate_from_wt_db: list_by_kind(%s) failed\n",
                    kinds[i].label);
            return -1;
        }
        per_kind[i] = ctx.n_loaded - before;
    }

    printf("WT-TRUSTLESS: hydrated %d watches from wt_db (%d skipped) "
           "[factory=%d subfactory=%d commitment=%d force_close=%d]\n",
           ctx.n_loaded, ctx.n_skipped,
           per_kind[0], per_kind[1], per_kind[2], per_kind[3]);
    return ctx.n_loaded;
}

void watchtower_set_wt_db(watchtower_t *wt, persist_wt_t *wt_db) {
    if (!wt) return;
    wt->wt_db = wt_db;
}

void watchtower_register_autosettle(watchtower_t *wt,
    int (*fn)(struct watchtower_s *wt, watchtower_entry_t *entry)) {
    if (!wt) return;
    wt->autosettle_fn = fn;
}

void watchtower_cleanup(watchtower_t *wt) {
    if (!wt) return;
    for (size_t i = 0; i < wt->n_entries; i++) {
        free(wt->entries[i].leaf_channel_ids);
        free(wt->entries[i].htlc_outputs);
        wt->entries[i].htlc_outputs = NULL;
        /* #248 leak fix: ptlc_outputs allocated by
           watchtower_watch_revoked_commitment SF-W-PTLC block. */
        free(wt->entries[i].ptlc_outputs);
        wt->entries[i].ptlc_outputs = NULL;
        if (wt->entries[i].type == WATCH_FACTORY_NODE ||
            wt->entries[i].type == WATCH_SUBFACTORY_NODE) {
            free(wt->entries[i].response_tx);
            wt->entries[i].response_tx = NULL;
            free(wt->entries[i].burn_tx);
            wt->entries[i].burn_tx = NULL;
        }
        if (wt->entries[i].type == WATCH_SUBFACTORY_NODE) {
            free(wt->entries[i].sub_channel_amounts);
            wt->entries[i].sub_channel_amounts = NULL;
        }
        /* Oracular path bytes (#208 A3.1) — free on any entry type */
        free(wt->entries[i].signed_penalty_tx);
        wt->entries[i].signed_penalty_tx = NULL;
        wt->entries[i].signed_penalty_tx_len = 0;
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
    /* SF-W #148: n_htlcs == 0 is VALID — register the channel for FC
       observability even when there are no HTLCs to sweep (closing a clean
       channel with no in-flight HTLCs).  Previously this case was rejected
       and the BOLT-1 ERROR handler ended up with no watchtower coverage.
       htlcs may be NULL when n_htlcs is 0. */
    if (!wt || !commitment_txid) return 0;
    if (n_htlcs > 0 && !htlcs) return 0;

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

    /* Copy HTLC outputs (skip allocation if n_htlcs == 0). */
    if (n_htlcs > 0) {
        e->htlc_outputs = malloc(n_htlcs * sizeof(watchtower_htlc_t));
        if (!e->htlc_outputs) return 0;
        memcpy(e->htlc_outputs, htlcs, n_htlcs * sizeof(watchtower_htlc_t));
        e->n_htlc_outputs = n_htlcs;
        e->htlc_outputs_cap = n_htlcs;
    } else {
        e->htlc_outputs = NULL;
        e->n_htlc_outputs = 0;
        e->htlc_outputs_cap = 0;
    }

    wt->n_entries++;

    /* Register HTLC scripts with chain backend */
    if (n_htlcs > 0 && wt->chain && wt->chain->register_script)
        for (size_t i = 0; i < n_htlcs; i++)
            wt->chain->register_script(wt->chain, htlcs[i].htlc_spk, 34);

    /* v28 (PR-C-2): persist so the entry survives LSP restart.  Unlike
       commitment / factory_node / subfactory_node entries, force-close
       watches have no rebuild-from-state recovery path. */
    if (wt->db && wt->db->db) {
        int64_t row_id = -1;
        persist_save_force_close(wt->db, channel_id, commitment_txid,
                                   (const struct watchtower_htlc *)htlcs,
                                   n_htlcs, &row_id);
    }
    return 1;
}

int watchtower_build_force_close_htlcs(const channel_t *ch,
                                         unsigned char *commit_txid_out32,
                                         watchtower_htlc_t *htlcs_out,
                                         size_t htlcs_max,
                                         size_t *n_htlcs_out) {
    if (!ch || !commit_txid_out32 || !n_htlcs_out) return 0;
    *n_htlcs_out = 0;

    /* Build the remote-view commit TX.  On BOLT-1 ERROR force-close, the
       peer broadcasts THEIR latest commit (BOLT-2 §2.3.1).  From LSP's
       perspective that's channel_build_commitment_tx_for_remote.  The
       builder also flips HTLC directions in the temp copy of ch->htlcs[]
       (channel.c:906-911) and rebuilds the tapscripts in the swapped
       role.  We KEEP the LSP-side direction in our entry to match the
       breach path's convention (watchtower.c:479 / .c:975). */
    tx_buf_t commit;
    memset(&commit, 0, sizeof(commit));
    tx_buf_init(&commit, 512);
    if (!channel_build_commitment_tx_for_remote(ch, &commit, commit_txid_out32)) {
        tx_buf_free(&commit);
        return 0;
    }

    /* Parse commit TX bytes:
       [nVersion 4][varint n_in=1][input 41][varint n_out][outputs][nLockTime 4]
       Input: [prev_txid 32][prev_vout 4][scriptSig_len varint=0][nSequence 4]
       Output: [amount 8][varint spk_len][spk] */
    if (commit.len < 4 + 1 + 41 + 1 + 4) {
        tx_buf_free(&commit);
        return 0;
    }
    size_t ofs = 4;             /* skip nVersion */
    if (commit.data[ofs] != 1) { /* n_inputs varint — commit always 1 */
        tx_buf_free(&commit);
        return 0;
    }
    ofs += 1 + 41;              /* skip n_inputs + 1 input */
    if (ofs >= commit.len) {
        tx_buf_free(&commit);
        return 0;
    }
    uint8_t n_outputs = commit.data[ofs];
    ofs += 1;

    /* Skip vout 0 (to_local) and vout 1 (to_remote) — both 34-byte P2TR. */
    for (int v = 0; v < 2 && v < (int)n_outputs; v++) {
        if (ofs + 9 > commit.len) {
            tx_buf_free(&commit);
            return 0;
        }
        uint8_t slen = commit.data[ofs + 8];
        ofs += 8 + 1 + slen;
    }

    /* Iterate HTLC vouts (2..n_outputs-1) in parallel with ch->htlcs[]
       active+non-dust entries.  channel_build_commitment_tx_impl iterates
       ch->htlcs[] in array order — that's the order we replay here. */
    size_t htlc_idx = 0;
    size_t n_out = 0;
    for (size_t v = 2; v < (size_t)n_outputs && n_out < htlcs_max; v++) {
        /* Advance past inactive/dust HTLCs. */
        while (htlc_idx < ch->n_htlcs &&
               (ch->htlcs[htlc_idx].state != HTLC_STATE_ACTIVE ||
                ch->htlcs[htlc_idx].amount_sats < CHANNEL_DUST_LIMIT_SATS))
            htlc_idx++;
        if (htlc_idx >= ch->n_htlcs) break;

        if (ofs + 9 > commit.len) break;
        uint64_t amount = 0;
        for (int b = 0; b < 8; b++)
            amount |= ((uint64_t)commit.data[ofs + b]) << (b * 8);
        uint8_t slen = commit.data[ofs + 8];
        if (slen != 34 || ofs + 9 + 34 > commit.len) {
            ofs += 8 + 1 + slen;
            htlc_idx++;
            continue;
        }

        watchtower_htlc_t *wh = &htlcs_out[n_out];
        memset(wh, 0, sizeof(*wh));
        wh->htlc_vout = (uint32_t)v;
        wh->htlc_amount = amount;
        memcpy(wh->htlc_spk, &commit.data[ofs + 9], 34);
        /* LSP-side direction (matches breach-path convention). */
        wh->direction = ch->htlcs[htlc_idx].direction;
        memcpy(wh->payment_hash, ch->htlcs[htlc_idx].payment_hash, 32);
        wh->cltv_expiry = ch->htlcs[htlc_idx].cltv_expiry;
        n_out++;

        ofs += 8 + 1 + 34;
        htlc_idx++;
    }

    tx_buf_free(&commit);
    *n_htlcs_out = n_out;
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
        /* #248 leak fix: ptlc_outputs counterpart. */
        free(wt->entries[i].ptlc_outputs);
        wt->entries[i].ptlc_outputs = NULL;
        if (wt->entries[i].type == WATCH_FACTORY_NODE ||
            wt->entries[i].type == WATCH_SUBFACTORY_NODE) {
            free(wt->entries[i].response_tx);
            wt->entries[i].response_tx = NULL;
            free(wt->entries[i].burn_tx);
            wt->entries[i].burn_tx = NULL;
        }
        if (wt->entries[i].type == WATCH_SUBFACTORY_NODE) {
            free(wt->entries[i].sub_channel_amounts);
            wt->entries[i].sub_channel_amounts = NULL;
        }
        /* Oracular bytes (#208 A3.1) — free on any entry type */
        free(wt->entries[i].signed_penalty_tx);
        wt->entries[i].signed_penalty_tx = NULL;
        wt->entries[i].signed_penalty_tx_len = 0;
    }
    wt->n_entries = 0;
}

void watchtower_on_reorg(watchtower_t *wt, int new_tip, int old_tip) {
    if (!wt || !wt->chain) return;
    fprintf(stderr, "Watchtower: reorg detected (%d → %d), re-validating %zu entries\n",
            old_tip, new_tip, wt->n_entries);

    int n_reset = 0;
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
            n_reset++;
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

    /* v29 (PR-C-6): observability — record this reorg event for forensics. */
    if (wt->db && wt->db->db)
        persist_log_reorg_event(wt->db, new_tip, old_tip, n_reset);
}

void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id) {
    if (!wt) return;

    for (size_t i = 0; i < wt->n_entries; ) {
        if (wt->entries[i].channel_id == channel_id) {
            entry_unregister_scripts(wt, &wt->entries[i]);
            free(wt->entries[i].htlc_outputs);
            /* #248 leak fix: ptlc_outputs counterpart. */
            free(wt->entries[i].ptlc_outputs);
            wt->entries[i].ptlc_outputs = NULL;
            if (wt->entries[i].type == WATCH_FACTORY_NODE) {
                free(wt->entries[i].response_tx);
                free(wt->entries[i].burn_tx);
            }
            /* Oracular bytes (#208 A3.1) — free on any entry type */
            free(wt->entries[i].signed_penalty_tx);
            wt->entries[i].signed_penalty_tx = NULL;
            wt->entries[i].signed_penalty_tx_len = 0;
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            /* NULL the source entry's pointers after swap */
            wt->entries[wt->n_entries - 1].htlc_outputs = NULL;
            wt->entries[wt->n_entries - 1].response_tx = NULL;
            wt->entries[wt->n_entries - 1].burn_tx = NULL;
            wt->entries[wt->n_entries - 1].signed_penalty_tx = NULL;
            wt->entries[wt->n_entries - 1].signed_penalty_tx_len = 0;
            wt->n_entries--;
        } else {
            i++;
        }
    }
}
