/* #248 SF-WT-TRUSTLESS — LSP-side wt_db adapters.
 * See include/superscalar/lsp_wt.h for the contract. */

#include "superscalar/lsp_wt.h"
#include <stdlib.h>

/* hex_encode lives in src/util.c (same as factory_recovery, sweeper,
 * etc. use it). Declared extern to keep this TU dep-light. */
extern void hex_encode(const unsigned char *data, size_t len, char *out);

/* Shared internal: hex-encode a signed-tx blob and call
   persist_wt_register_watch with the given watch_kind.  All adapters
   below funnel through this so the kind discriminant is the only
   variable. */
static int64_t lsp_wt_register_generic(persist_wt_t *pwt,
                                         wt_watch_kind_t kind,
                                         uint32_t factory_id,
                                         const unsigned char parent_txid32[32],
                                         uint32_t parent_vout,
                                         uint64_t parent_value_sat,
                                         const unsigned char *parent_spk,
                                         size_t parent_spk_len,
                                         uint32_t csv_delay,
                                         const unsigned char *signed_response_tx,
                                         size_t signed_response_tx_len,
                                         const unsigned char response_txid32[32],
                                         uint64_t fee_bump_budget_sat,
                                         uint32_t fee_bump_deadline_height) {
    /* NULL wt_db is a no-op — callers gate on lsp->wt_db being non-NULL
     * at their callsite, but we also accept NULL here for defense in
     * depth (no error log; just nothing to do). */
    if (!pwt) return -1;
    if (!parent_txid32 || !signed_response_tx || signed_response_tx_len == 0)
        return -1;
    if (!parent_spk || parent_spk_len == 0) return -1;
    if (!response_txid32) return -1;

    /* hex_encode writes 2*len chars + a trailing NUL. */
    size_t hex_buf_len = signed_response_tx_len * 2 + 1;
    char *hex = (char *)malloc(hex_buf_len);
    if (!hex) return -1;
    hex_encode(signed_response_tx, signed_response_tx_len, hex);

    int64_t watch_id = persist_wt_register_watch(pwt,
                                                  kind,
                                                  factory_id,
                                                  parent_txid32,
                                                  parent_vout,
                                                  parent_value_sat,
                                                  parent_spk, parent_spk_len,
                                                  csv_delay,
                                                  hex,
                                                  response_txid32,
                                                  fee_bump_budget_sat,
                                                  fee_bump_deadline_height);
    free(hex);
    return watch_id;
}

int64_t lsp_wt_register_factory_node_watch(persist_wt_t *pwt,
                                            uint32_t factory_id,
                                            const unsigned char parent_txid32[32],
                                            uint32_t parent_vout,
                                            uint64_t parent_value_sat,
                                            const unsigned char *parent_spk,
                                            size_t parent_spk_len,
                                            uint32_t csv_delay,
                                            const unsigned char *signed_response_tx,
                                            size_t signed_response_tx_len,
                                            const unsigned char response_txid32[32],
                                            uint64_t fee_bump_budget_sat,
                                            uint32_t fee_bump_deadline_height) {
    return lsp_wt_register_generic(pwt, WT_KIND_FACTORY_NODE,
                                    factory_id, parent_txid32,
                                    parent_vout, parent_value_sat,
                                    parent_spk, parent_spk_len, csv_delay,
                                    signed_response_tx, signed_response_tx_len,
                                    response_txid32,
                                    fee_bump_budget_sat, fee_bump_deadline_height);
}

int64_t lsp_wt_register_subfactory_node_watch(persist_wt_t *pwt,
                                                uint32_t sub_factory_id,
                                                const unsigned char parent_txid32[32],
                                                uint32_t parent_vout,
                                                uint64_t parent_value_sat,
                                                const unsigned char *parent_spk,
                                                size_t parent_spk_len,
                                                uint32_t csv_delay,
                                                const unsigned char *signed_response_tx,
                                                size_t signed_response_tx_len,
                                                const unsigned char response_txid32[32],
                                                uint64_t fee_bump_budget_sat,
                                                uint32_t fee_bump_deadline_height) {
    return lsp_wt_register_generic(pwt, WT_KIND_SUBFACTORY_NODE,
                                    sub_factory_id, parent_txid32,
                                    parent_vout, parent_value_sat,
                                    parent_spk, parent_spk_len, csv_delay,
                                    signed_response_tx, signed_response_tx_len,
                                    response_txid32,
                                    fee_bump_budget_sat, fee_bump_deadline_height);
}

int64_t lsp_wt_register_commitment_watch(persist_wt_t *pwt,
                                          uint32_t channel_id,
                                          const unsigned char commit_txid32[32],
                                          uint32_t to_local_vout,
                                          uint64_t to_local_amount,
                                          const unsigned char *to_local_spk,
                                          size_t to_local_spk_len,
                                          uint32_t csv_delay,
                                          const unsigned char *signed_penalty_tx,
                                          size_t signed_penalty_tx_len,
                                          const unsigned char penalty_txid32[32]) {
    /* Commitment watches don't carry fee-bump escalation today; pass 0/0.
       The penalty TX itself is built at the agreed feerate; CPFP escalation
       is post-broadcast and lives in the WT-side fee_bump path. */
    return lsp_wt_register_generic(pwt, WT_KIND_CHANNEL_COMMITMENT,
                                    channel_id, commit_txid32,
                                    to_local_vout, to_local_amount,
                                    to_local_spk, to_local_spk_len, csv_delay,
                                    signed_penalty_tx, signed_penalty_tx_len,
                                    penalty_txid32,
                                    /* fee_bump_budget */ 0,
                                    /* fee_bump_deadline */ 0);
}

int64_t lsp_wt_register_force_close_watch(persist_wt_t *pwt,
                                            uint32_t channel_id,
                                            const unsigned char commit_txid32[32],
                                            uint32_t htlc_vout,
                                            uint64_t htlc_amount,
                                            const unsigned char *htlc_spk,
                                            size_t htlc_spk_len,
                                            uint32_t csv_delay,
                                            const unsigned char *signed_sweep_tx,
                                            size_t signed_sweep_tx_len,
                                            const unsigned char sweep_txid32[32]) {
    /* Force-close HTLC sweep watches don't carry fee-bump today; pass 0/0. */
    return lsp_wt_register_generic(pwt, WT_KIND_FORCE_CLOSE_HTLC,
                                    channel_id, commit_txid32,
                                    htlc_vout, htlc_amount,
                                    htlc_spk, htlc_spk_len, csv_delay,
                                    signed_sweep_tx, signed_sweep_tx_len,
                                    sweep_txid32,
                                    /* fee_bump_budget */ 0,
                                    /* fee_bump_deadline */ 0);
}
