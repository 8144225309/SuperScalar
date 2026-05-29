/* #248 SF-WT-TRUSTLESS Phase 1b.2 — LSP-side wt_db adapter.
 * See include/superscalar/lsp_wt.h for the contract. */

#include "superscalar/lsp_wt.h"
#include <stdlib.h>

/* hex_encode lives in src/util.c (same as factory_recovery, sweeper,
 * etc. use it). Declared extern to keep this TU dep-light. */
extern void hex_encode(const unsigned char *data, size_t len, char *out);

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
