/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248) — LSP channel init from DB.
 *
 * Extracted from src/lsp_channels.c so the trustless watchtower binary's
 * link set does NOT transitively pull in persist_load_basepoints via
 * lsp_channels_init_from_db.  This TU is part of the superscalar_secrets
 * static library; superscalar_watchtower does not link it.
 *
 * Tests and the LSP binary call this function via the prototype in
 * include/superscalar/lsp_channels.h (unchanged).
 */

#include "superscalar/lsp_channels.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/fee.h"
#include "superscalar/fee_estimator.h"
#include "superscalar/htlc_inbound.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* client_to_leaf is now non-static in src/lsp_channels.c (per PR-E.2).
   Internal helper — not in the public header. */
extern void client_to_leaf(size_t client_idx, const factory_t *factory,
                            size_t *node_idx_out, uint32_t *vout_out);

int lsp_channels_init_from_db(lsp_channel_mgr_t *mgr,
                               secp256k1_context *ctx,
                               const factory_t *factory,
                               const unsigned char *lsp_seckey32,
                               size_t n_clients,
                               void *db) {
    persist_t *pdb = (persist_t *)db;
    if (!mgr || !ctx || !factory || !lsp_seckey32 || !pdb) return 0;
    if (n_clients == 0) return 0;

    /* Preserve fields set before init (caller may configure these).
       Mirror of lsp_channels_init — see comment there for why mgr->persist
       must survive the memset. */
    uint64_t saved_fee_ppm = mgr->routing_fee_ppm;
    uint16_t saved_bal_pct = mgr->lsp_balance_pct;
    void *saved_fee2 = mgr->fee;
    void *saved_persist = mgr->persist;
    economic_mode_t saved_econ = mgr->economic_mode;
    uint16_t saved_profit_bps = mgr->default_profit_bps;
    uint32_t saved_settle_interval = mgr->settlement_interval_blocks;
    memset(mgr, 0, sizeof(*mgr));
    mgr->routing_fee_ppm = saved_fee_ppm;
    mgr->lsp_balance_pct = saved_bal_pct;
    mgr->fee = saved_fee2;
    mgr->persist = saved_persist;
    mgr->economic_mode = saved_econ;
    mgr->default_profit_bps = saved_profit_bps;
    mgr->settlement_interval_blocks = saved_settle_interval;
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

    /* Derive LSP cooperative-close SPK (see init() for rationale). */
    if (factory->n_participants > 0) {
        secp256k1_xonly_pubkey lsp_xonly_for_close;
        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly_for_close, NULL,
                                                &factory->pubkeys[0])) {
            build_p2tr_script_pubkey(mgr->lsp_close_spk, &lsp_xonly_for_close);
            mgr->lsp_close_spk_len = 34;
        }
    }

    /* Restore accumulated fees from DB (crash recovery) */
    persist_load_fee_settlement(pdb, 0,
        &mgr->accumulated_fees_sats, &mgr->last_settlement_block);

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
        const unsigned char *funding_txid = state_node->txid;
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
        secp256k1_xonly_pubkey client_xonly2;
        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &client_xonly2, NULL, client_pubkey)) {
            build_p2tr_script_pubkey(entry->close_spk, &client_xonly2);
            entry->close_spk_len = 34;
        }

        /* Commitment tx fee: pinned at 1000 sat/kvB to match channel_init
           (src/channel.c:282) and client_check_conservation (src/client.c).
           See sister site in lsp_channels_init for full rationale. */
        fee_estimator_static_t _fe_default2;
        fee_estimator_static_init(&_fe_default2, 1000);
        fee_estimator_t *_fe2 = &_fe_default2.base;
        uint64_t commit_fee = fee_for_commitment_tx(_fe2, 0);
        uint64_t usable = funding_amount > commit_fee ? funding_amount - commit_fee : 0;
        uint16_t pct2 = mgr->lsp_balance_pct;
        if (pct2 == 0) pct2 = 50;
        if (pct2 > 100) pct2 = 100;
        uint64_t local_amount = (usable * pct2) / 100;
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
        entry->channel.funder_is_local = 1;
        entry->channel.use_cpfp_anchor = 1;  /* #56: P2A CPFP anchor (matches client; restore parity) */
        /* Attach persistence (see lsp_channels_init for rationale). */
        channel_set_persist(&entry->channel, mgr->persist, (uint32_t)c);
        /* fee_rate stays at channel_init default (1000); commit_fee above is
           pinned to the same rate to maintain the conservation invariant. */

        /* SF-CH #154: auto-discover funding keyagg ordering (see comment in
           lsp_channels_init for full rationale). */
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
                        "LSP recovery: channel %zu funding_keyagg discovery "
                        "failed (factory_cltv=%u, node_cltv=%u). Refusing "
                        "to load — on-chain spends would fail Schnorr verify.\n",
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

        /* Load basepoints from DB instead of generating random ones */
        unsigned char local_secrets[4][32];
        unsigned char remote_bps[4][33];
        if (!persist_load_basepoints(pdb, (uint32_t)c, local_secrets, remote_bps)) {
            fprintf(stderr, "LSP recovery: failed to load basepoints for channel %zu\n", c);
            return 0;
        }

        /* Set local basepoints from loaded secrets */
        channel_set_local_basepoints(&entry->channel,
                                       local_secrets[0],
                                       local_secrets[1],
                                       local_secrets[2]);
        channel_set_local_htlc_basepoint(&entry->channel, local_secrets[3]);
        memset(local_secrets, 0, sizeof(local_secrets));

        /* Set remote basepoints from loaded pubkeys */
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        if (!secp256k1_ec_pubkey_parse(ctx, &rpay, remote_bps[0], 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &rdelay, remote_bps[1], 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &rrevoc, remote_bps[2], 33) ||
            !secp256k1_ec_pubkey_parse(ctx, &rhtlc, remote_bps[3], 33)) {
            fprintf(stderr, "LSP recovery: failed to parse remote basepoints for channel %zu\n", c);
            return 0;
        }
        channel_set_remote_basepoints(&entry->channel, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(&entry->channel, &rhtlc);

        /* Load channel state (balances, commitment_number) from DB */
        uint64_t loaded_local, loaded_remote, loaded_cn;
        if (!persist_load_channel_state(pdb, (uint32_t)c,
                                          &loaded_local, &loaded_remote, &loaded_cn)) {
            fprintf(stderr, "LSP recovery: failed to load channel state for channel %zu\n", c);
            return 0;
        }
        entry->channel.local_amount = loaded_local;
        entry->channel.remote_amount = loaded_remote;
        entry->channel.commitment_number = loaded_cn;

        /* Load active HTLCs from DB */
        {
            htlc_t *loaded_htlcs = malloc(MAX_HTLCS * sizeof(htlc_t));
            if (!loaded_htlcs) return 0;
            size_t n_loaded = persist_load_htlcs(pdb, (uint32_t)c,
                                                    loaded_htlcs, MAX_HTLCS);
            for (size_t h = 0; h < n_loaded; h++) {
                if (loaded_htlcs[h].state != HTLC_STATE_ACTIVE) continue;
                if (entry->channel.n_htlcs >= MAX_HTLCS) break;
                entry->channel.htlcs[entry->channel.n_htlcs++] = loaded_htlcs[h];
            }
            if (n_loaded > 0)
                printf("LSP recovery: loaded %zu HTLCs for channel %zu\n",
                       n_loaded, c);
            free(loaded_htlcs);
        }

        /* Initialize nonce pool (fresh nonces — reconnect re-exchanges) */
        if (!channel_init_nonce_pool(&entry->channel, MUSIG_NONCE_POOL_MAX))
            return 0;

        entry->ready = 1;  /* channels are already operational */
    }

    return 1;
}

/* A mover's old channel of a partial rotation (see lsp_channels.h), from
   its retired rows. */
extern int hex_decode(const char *, unsigned char *, size_t);
extern void reverse_bytes(unsigned char *, size_t);

int lsp_rotation_part_load_old_channel(lsp_channel_mgr_t *mgr, size_t c, channel_t *ch) {
    if (!mgr || !ch || !mgr->persist || !mgr->part_rel.valid || c >= mgr->part_rel.m)
        return 0;
    persist_t *db = (persist_t *)mgr->persist;
    persist_part_release_t rel;
    if (!lsp_rotation_part_release_row(mgr, c, &rel) || !rel.leaf_txid[0]) return 0;
    uint32_t cid = lsp_rotation_part_old_channel_id(mgr, c);
    secp256k1_pubkey lpk, cpk;
    unsigned char ltx[32];
    uint64_t la = 0, ra = 0, cn = 0;
    if (!secp256k1_ec_pubkey_create(mgr->ctx, &lpk, mgr->rot_lsp_seckey) ||
        !secp256k1_ec_pubkey_parse(mgr->ctx, &cpk, mgr->part_rel.old_pk[c], 33) ||
        hex_decode(rel.leaf_txid, ltx, 32) != 32 ||
        !persist_load_channel_state(db, cid, &la, &ra, &cn))
        return 0;
    reverse_bytes(ltx, 32);
    memset(ch, 0, sizeof(*ch));
    if (!channel_init(ch, mgr->ctx, mgr->rot_lsp_seckey, &lpk, &cpk, ltx, rel.leaf_vout,
                      rel.leaf_amount, rel.leaf_spk, 34, la, ra, CHANNEL_DEFAULT_CSV_DELAY))
        return 0;
    ch->funder_is_local = 1;
    ch->use_cpfp_anchor = 1;
    ch->commitment_number = cn;
    int ok = 1;
    {
        musig_keyagg_t ka;
        uint32_t si = 0;
        unsigned char mr[32];
        int hm = 0;
        ok = channel_discover_funding_keyagg(mgr->ctx, &lpk, &cpk, &lpk, mgr->part_rel.old_cltv,
                                             rel.leaf_cltv, rel.leaf_spk, 34, &ka, &si, mr, &hm);
        if (ok) {
            ch->funding_keyagg = ka;
            ch->local_funding_signer_idx = si;
            ch->has_chan_merkle_root = hm;
            if (hm) memcpy(ch->chan_merkle_root, mr, 32);
        }
    }
    unsigned char ls[4][32], rb[4][33];
    ok = ok && persist_load_basepoints(db, cid, ls, rb);
    if (ok) {
        secp256k1_pubkey p0, p1, p2, p3;
        channel_set_local_basepoints(ch, ls[0], ls[1], ls[2]);
        channel_set_local_htlc_basepoint(ch, ls[3]);
        ok = secp256k1_ec_pubkey_parse(mgr->ctx, &p0, rb[0], 33) &&
             secp256k1_ec_pubkey_parse(mgr->ctx, &p1, rb[1], 33) &&
             secp256k1_ec_pubkey_parse(mgr->ctx, &p2, rb[2], 33) &&
             secp256k1_ec_pubkey_parse(mgr->ctx, &p3, rb[3], 33);
        if (ok) {
            channel_set_remote_basepoints(ch, &p0, &p1, &p2);
            channel_set_remote_htlc_basepoint(ch, &p3);
        }
    }
    secure_zero(ls, sizeof(ls));
    if (ok) {
        htlc_t *hs = calloc(MAX_HTLCS, sizeof(htlc_t));
        size_t nh = hs ? persist_load_htlcs(db, cid, hs, MAX_HTLCS) : 0;
        for (size_t h = 0; h < nh && ch->n_htlcs < MAX_HTLCS; h++)
            if (hs[h].state == HTLC_STATE_ACTIVE) ch->htlcs[ch->n_htlcs++] = hs[h];
        free(hs);
        ok = hs != NULL;
    }
    /* The client's points around its latest commitment (the settlement signs
       the next one; its revocation is of the latest, or of the one before
       when the settled state is answered again). */
    for (uint64_t k = cn ? cn - 1 : 0; ok && k <= cn + 1; k++) {
        unsigned char ser[33];
        secp256k1_pubkey pcp;
        if (persist_load_remote_pcp(db, cid, k, ser) &&
            secp256k1_ec_pubkey_parse(mgr->ctx, &pcp, ser, 33))
            channel_set_remote_pcp(ch, k, &pcp);
    }
    if (ok) {
        size_t pmax = (size_t)cn + 2, got = 0;
        unsigned char (*pcs)[32] = calloc(pmax, 32);
        if (pcs && persist_load_local_pcs(db, cid, pcs, pmax, &got))
            for (uint64_t k = 0; k < pmax; k++) {
                int nz = 0;
                for (int b = 0; b < 32 && !nz; b++) nz = pcs[k][b] != 0;
                if (nz) channel_set_local_pcs(ch, k, pcs[k]);
            }
        if (pcs) { secure_zero(pcs, pmax * 32); free(pcs); }
        channel_set_persist(ch, db, cid);
    }
    if (!ok) channel_cleanup(ch);
    return ok;
}
