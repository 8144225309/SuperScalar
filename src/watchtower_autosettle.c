/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248) — auto-settle helper.
 *
 * Extracted from src/watchtower.c so that the standalone trustless
 * watchtower binary (superscalar_watchtower) does NOT need to link
 * persist_load_commitment_sig.  The auto-settle path is an LSP-side
 * feature: after a factory-node state TX confirms, the in-process WT
 * broadcasts each channel's pre-signed commitment TX from lsp.db so
 * HTLC-bearing channels settle without requiring the client to be
 * online.  This depends on lsp.db access, which is exactly what the
 * trustless WT binary refuses to have.
 *
 * Linked into the superscalar_secrets static library together with
 * src/persist_secrets.c.  LSP/client/tests/bridge link
 * superscalar_secrets.  superscalar_watchtower does not, so the
 * symbol persist_load_commitment_sig (called below) does not appear
 * in the trustless WT binary either.
 *
 * Wiring: superscalar_lsp.c calls watchtower_register_autosettle after
 * watchtower_init to install this function on each watchtower_t.
 */

#include "superscalar/watchtower.h"
#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

int watchtower_autosettle_leaf_channels(struct watchtower_s *wt,
                                          watchtower_entry_t *e) {
    if (!wt || !e) return 0;
    if (!e->leaf_channel_ids || e->n_leaf_channels == 0) return 0;
    if (!wt->db || !wt->db->db) return 0;
    if (!wt->chain || !wt->chain->send_raw_tx) return 0;

    int n_settled = 0;
    for (size_t lc = 0; lc < e->n_leaf_channels; lc++) {
        uint32_t ch_idx = e->leaf_channel_ids[lc];
        unsigned char commit_tx[4096];
        size_t commit_tx_len = 0;
        uint64_t commit_cn = 0;
        if (persist_load_commitment_sig(wt->db, ch_idx,
                &commit_cn, NULL, commit_tx, &commit_tx_len,
                sizeof(commit_tx)) &&
            commit_tx_len > 0) {
            char *ctx_hex = (char *)malloc(commit_tx_len * 2 + 1);
            if (ctx_hex) {
                hex_encode(commit_tx, commit_tx_len, ctx_hex);
                char ctx_txid[65];
                if (wt->chain->send_raw_tx(wt->chain, ctx_hex, ctx_txid)) {
                    printf("  Auto-settle channel %u (cn=%llu): %s\n",
                           ch_idx, (unsigned long long)commit_cn,
                           ctx_txid);
                    n_settled++;
                } else {
                    printf("  Auto-settle channel %u: broadcast failed "
                           "(leaf may need more confirmations)\n",
                           ch_idx);
                }
                free(ctx_hex);
            }
        }
    }
    return n_settled;
}
