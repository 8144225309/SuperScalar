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

    /* Each restored channel writes received revocations and remote PCPs
       back to the DB it was restored from (channel_set_persist below), so
       mgr->persist is set to pdb here rather than trusted from the caller:
       the LSP restart path used to assign it only after this call, which
       left every restored channel with no DB.  A different handle is
       refused. */
    if (mgr->persist && mgr->persist != pdb) {
        fprintf(stderr, "LSP recovery: mgr->persist is not the DB being "
                "restored from; refusing\n");
        return 0;
    }

    /* Preserve fields set before init (caller may configure these).
       Mirror of lsp_channels_init. */
    uint64_t saved_fee_ppm = mgr->routing_fee_ppm;
    uint16_t saved_bal_pct = mgr->lsp_balance_pct;
    void *saved_fee2 = mgr->fee;
    economic_mode_t saved_econ = mgr->economic_mode;
    uint16_t saved_profit_bps = mgr->default_profit_bps;
    uint32_t saved_settle_interval = mgr->settlement_interval_blocks;
    memset(mgr, 0, sizeof(*mgr));
    mgr->routing_fee_ppm = saved_fee_ppm;
    mgr->lsp_balance_pct = saved_bal_pct;
    mgr->fee = saved_fee2;
    mgr->persist = pdb;
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
        if (vout >= state_node->n_outputs) goto fail;

        /* Funding info from the leaf output */
        const unsigned char *funding_txid = state_node->txid;
        uint64_t funding_amount = state_node->outputs[vout].amount_sats;
        const unsigned char *funding_spk = state_node->outputs[vout].script_pubkey;
        size_t funding_spk_len = state_node->outputs[vout].script_pubkey_len;

        /* LSP pubkey (participant 0) */
        secp256k1_pubkey lsp_pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &lsp_pubkey, lsp_seckey32))
            goto fail;

        /* Client pubkey (participant c+1) */
        const secp256k1_pubkey *client_pubkey = &factory->pubkeys[c + 1];

        /* Derive per-client close address: P2TR from client's factory pubkey */
        secp256k1_xonly_pubkey client_xonly2;
        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &client_xonly2, NULL, client_pubkey)) {
            build_p2tr_script_pubkey(entry->close_spk, &client_xonly2);
            entry->close_spk_len = 34;
        }

        /* Commitment tx fee at the factory's agreed rate (see the sister
           site in lsp_channels_init). */
        uint64_t commit_fee = fee_commitment_tx_at(factory->tree_fee_rate, 0);
        if (commit_fee == FEE_INVALID) {
            fprintf(stderr, "lsp_channels_init_from_db: commitment fee not computable\n");
            return 0;
        }
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
            goto fail;
        entry->channel.funder_is_local = 1;
        entry->channel.use_cpfp_anchor = 1;  /* #56: P2A CPFP anchor (matches client; restore parity) */
        /* Attach persistence (see lsp_channels_init for rationale). */
        channel_set_persist(&entry->channel, mgr->persist, (uint32_t)c);
        channel_set_commit_fee_rate(&entry->channel, factory->tree_fee_rate);

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
                goto fail;
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
            memset(local_secrets, 0, sizeof(local_secrets));
            goto fail;
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
            goto fail;
        }
        channel_set_remote_basepoints(&entry->channel, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(&entry->channel, &rhtlc);

        /* Load channel state (balances, commitment_number) from DB */
        uint64_t loaded_local, loaded_remote, loaded_cn;
        if (!persist_load_channel_state(pdb, (uint32_t)c,
                                          &loaded_local, &loaded_remote, &loaded_cn)) {
            fprintf(stderr, "LSP recovery: failed to load channel state for channel %zu\n", c);
            goto fail;
        }
        entry->channel.local_amount = loaded_local;
        entry->channel.remote_amount = loaded_remote;
        entry->channel.commitment_number = loaded_cn;

        /* v31: a funding freeze persisted before the restart stays in force
           until lsp_channels_revalidate_funding() re-checks it; the daemon
           loop does that on its first block (lsp_channels_funding_recheck_due),
           which also clears freezes whose funding TX is confirmed. */
        {
            int frozen = 0;
            if (persist_load_channel_funding_reorg(pdb, (uint32_t)c, &frozen))
                entry->channel.funding_pending_reorg = frozen;
        }

        /* Load active HTLCs from DB */
        {
            /* channel_init allocated DEFAULT_HTLCS_CAP entries; the loader
               grows the array to what the DB holds and refuses more than a
               channel can hold. */
            int n_loaded = persist_load_channel_htlcs(pdb, (uint32_t)c,
                                                      &entry->channel);
            if (n_loaded < 0) {
                fprintf(stderr, "LSP recovery: cannot restore HTLCs for "
                        "channel %zu\n", c);
                goto fail;
            }
            if (n_loaded > 0)
                printf("LSP recovery: loaded %d HTLCs for channel %zu\n",
                       n_loaded, c);
        }

        /* Initialize nonce pool (fresh nonces — reconnect re-exchanges) */
        if (!channel_init_nonce_pool(&entry->channel, MUSIG_NONCE_POOL_MAX))
            goto fail;

        entry->ready = 1;  /* channels are already operational */
    }

    return 1;

fail:
    /* Free what was allocated above, so a failed restore leaves mgr empty
       (entries NULL, n_channels 0) instead of leaking it. */
    lsp_channels_cleanup(mgr);
    return 0;
}
