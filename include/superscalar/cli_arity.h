#ifndef SUPERSCALAR_CLI_ARITY_H
#define SUPERSCALAR_CLI_ARITY_H

/* CLI helpers for --arity / --static-near-root parsing + BOLT 2016 ceiling
   validation.  Phase 4 of mixed-arity implementation plan: factor parsing
   out of tools/superscalar_lsp.c so it can be unit-tested directly.

   Error reporting: helpers return 1 on success, 0 on failure.  Failure
   writes a clear message into the caller-provided err_buf (always
   NUL-terminated when err_buf_len > 0). */

#include <stddef.h>
#include <stdint.h>
#include "factory.h"  /* FACTORY_MAX_LEVELS, factory_arity_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Parse an --arity spec string.
   Single value: "3"          -> n_arities=1, leaf_arity=3
   Comma list:   "2,4,8"      -> n_arities=3, leaf_arity=8
   Each value MUST be in [1, 15].  16+ is rejected because
   FACTORY_MAX_OUTPUTS=16 and arity-A leaves need A+1 outputs (A channels +
   L-stock).  Arity 0 is rejected.  Empty list is rejected.

   On success: arities_out[0..n_arities_out-1] is the parsed sequence,
               *leaf_arity_out is the LAST entry (legacy compatibility).
               When the input is a single value, n_arities_out is set to 1
               but the caller may treat it as "uniform" — i.e. only pass
               it to factory_set_level_arity if you want true mixed mode;
               otherwise call factory_set_arity(*leaf_arity_out).
   On failure: writes a clear message to err_buf, returns 0. */
int cli_parse_arity_spec(const char *spec,
                          uint8_t *arities_out, size_t arities_cap,
                          size_t *n_arities_out,
                          int *leaf_arity_out,
                          char *err_buf, size_t err_buf_len);

/* Parse the --static-near-root N argument.
   N must be in [0, FACTORY_MAX_LEVELS).  0 disables.
   On success: *value_out = N, returns 1.
   On failure: writes a clear message to err_buf, returns 0. */
int cli_parse_static_near_root(const char *spec,
                                uint32_t *value_out,
                                char *err_buf, size_t err_buf_len);

/* Validate that the chosen shape will not exceed BOLT's 2016-block
   final_cltv_expiry ceiling on the given chain configuration.

   Computes ewt via factory_compute_ewt_for_shape() with the actual
   step_blocks/states_per_layer the operator is using.  Rejects shapes
   whose ewt exceeds 2016 blocks with a clear error pointing the
   operator at docs/factory-arity.md.

   Inputs match the same conventions as factory_compute_ewt_for_shape().
   On success: *ewt_out (if non-NULL) gets the computed ewt, returns 1.
   On failure: writes a clear error to err_buf (and *ewt_out if non-NULL)
   and returns 0. */
int cli_validate_shape_for_bolt2016(
    const uint8_t *level_arities, size_t n_level_arity,
    factory_arity_t leaf_arity,
    size_t n_clients,
    uint32_t static_threshold,
    uint16_t step_blocks,
    uint32_t states_per_layer,
    uint32_t *ewt_out,
    char *err_buf, size_t err_buf_len);

/* BOLT-2016 ceiling constant (HTLC final_cltv_expiry max). */
#define CLI_ARITY_BOLT2016_CEILING 2016u

/* Mainnet safety floor for the DW timeout-tree step (--step-blocks).  Below
   this the CLTV/CSV ladder margin against reorgs / fee-races is too thin for
   mainnet.  144 blocks (~1 day) is the canonical SuperScalar mainnet figure. */
#define CLI_ARITY_MAINNET_MIN_STEP_BLOCKS 144u

/* Reject a --step-blocks value below the mainnet floor.  Applies only to
   network "mainnet"/"bitcoin"; all other chains (signet/testnet4/regtest)
   always pass so fast tests keep working.  Returns 1 on success (writes
   nothing); on rejection writes a clear error to err_buf and returns 0. */
int cli_validate_mainnet_step_floor(const char *network, uint16_t step_blocks,
                                    char *err_buf, size_t err_buf_len);

/* Factory expiry floor (LSP).  From cltv_timeout on the distribution TX is
   valid and the LSP's timeout paths in the tree are open, so it must not
   come before the end of the factory's own lifetime: a factory created at
   block `height` is EXPIRED from height + active_blocks + dying_blocks on.
   Returns 1 if cltv_timeout is at or after that block; otherwise writes an
   error to err_buf and returns 0. */
int cli_validate_factory_cltv(uint32_t cltv_timeout, uint32_t height,
                              uint32_t active_blocks, uint32_t dying_blocks,
                              char *err_buf, size_t err_buf_len);

/* Factory expiry floor as a client can check a proposal, which does not
   carry the lifetime: cltv_timeout must lie beyond the client's chain tip
   by more than the longest delay of one DW layer at the factory's first
   state, step_blocks * (states_per_layer - 1).  A factory failing it has
   its distribution TX and timeout paths valid before even one layer of the
   tree could confirm.  tip == 0 (unknown) is not judged and passes. */
int cli_validate_proposed_cltv(uint32_t cltv_timeout, uint32_t tip,
                               uint16_t step_blocks, uint32_t states_per_layer,
                               char *err_buf, size_t err_buf_len);

#ifdef __cplusplus
}
#endif

#endif  /* SUPERSCALAR_CLI_ARITY_H */
