/* Phase 4 of mixed-arity implementation plan: unit tests for CLI parsing
   and BOLT-2016 ceiling validation.  Exercises cli_parse_arity_spec(),
   cli_parse_static_near_root(), and cli_validate_shape_for_bolt2016()
   directly so the CLI accepts the right shapes and rejects the wrong
   ones with clear error strings.

   Strict severity: each negative test asserts on a specific substring
   in the error message so help text and validator stay in sync. */

#include "superscalar/cli_arity.h"
#include "superscalar/factory.h"
#include "superscalar/dw_state.h"
#include <stdio.h>
#include <string.h>

#define T_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define T_ASSERT_SUBSTR(haystack, needle) do { \
    if (strstr((haystack), (needle)) == NULL) { \
        printf("  FAIL: %s (line %d): expected substring '%s' in '%s'\n", \
               __func__, __LINE__, (needle), (haystack)); \
        return 0; \
    } \
} while(0)

/* ---- cli_parse_arity_spec ---- */

int test_cli_arity_uniform_3_parses(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    int ok = cli_parse_arity_spec("3", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(ok, "uniform --arity 3 must parse");
    T_ASSERT(n == 1, "uniform parses to n=1");
    T_ASSERT(arities[0] == 3, "first entry is 3");
    T_ASSERT(leaf == 3, "leaf is 3");
    return 1;
}

int test_cli_arity_mixed_248_parses(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    int ok = cli_parse_arity_spec("2,4,8", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(ok, "--arity 2,4,8 must parse");
    T_ASSERT(n == 3, "mixed parses to n=3");
    T_ASSERT(arities[0] == 2 && arities[1] == 4 && arities[2] == 8,
             "level_arity == [2,4,8]");
    T_ASSERT(leaf == 8, "leaf is last entry (8)");
    return 1;
}

int test_cli_arity_rejects_16(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    int ok = cli_parse_arity_spec("16", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(!ok, "--arity 16 must be rejected");
    T_ASSERT_SUBSTR(err, "1-15");
    T_ASSERT_SUBSTR(err, "FACTORY_MAX_OUTPUTS");
    return 1;
}

int test_cli_arity_rejects_zero(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    int ok = cli_parse_arity_spec("0", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(!ok, "--arity 0 must be rejected");
    T_ASSERT_SUBSTR(err, "1-15");
    return 1;
}

int test_cli_arity_rejects_negative(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    /* "-2" begins with '-' which fails the digit check. */
    int ok = cli_parse_arity_spec("-2", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(!ok, "--arity -2 must be rejected");
    T_ASSERT_SUBSTR(err, "not a positive integer");
    return 1;
}

int test_cli_arity_rejects_non_numeric(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    int ok = cli_parse_arity_spec("abc", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(!ok, "--arity abc must be rejected");
    T_ASSERT_SUBSTR(err, "not a positive integer");
    return 1;
}

int test_cli_arity_rejects_mixed_with_oversize_entry(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    /* 2,4,16 — last entry is out of range. */
    int ok = cli_parse_arity_spec("2,4,16", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(!ok, "--arity 2,4,16 must be rejected (16 out of range)");
    T_ASSERT_SUBSTR(err, "1-15");
    return 1;
}

int test_cli_arity_rejects_empty(void) {
    uint8_t arities[FACTORY_MAX_LEVELS];
    size_t n = 0;
    int leaf = 0;
    char err[256] = {0};
    int ok = cli_parse_arity_spec("", arities, FACTORY_MAX_LEVELS,
                                   &n, &leaf, err, sizeof(err));
    T_ASSERT(!ok, "empty --arity must be rejected");
    T_ASSERT_SUBSTR(err, "requires a value");
    return 1;
}

/* ---- cli_parse_static_near_root ---- */

int test_cli_static_near_root_parses_1(void) {
    uint32_t v = 99;
    char err[256] = {0};
    int ok = cli_parse_static_near_root("1", &v, err, sizeof(err));
    T_ASSERT(ok, "--static-near-root 1 must parse");
    T_ASSERT(v == 1, "value is 1");
    return 1;
}

int test_cli_static_near_root_parses_zero_disabled(void) {
    uint32_t v = 99;
    char err[256] = {0};
    int ok = cli_parse_static_near_root("0", &v, err, sizeof(err));
    T_ASSERT(ok, "--static-near-root 0 must parse");
    T_ASSERT(v == 0, "value is 0 (disabled)");
    return 1;
}

int test_cli_static_near_root_rejects_negative(void) {
    uint32_t v = 99;
    char err[256] = {0};
    int ok = cli_parse_static_near_root("-1", &v, err, sizeof(err));
    T_ASSERT(!ok, "--static-near-root -1 must be rejected");
    return 1;
}

int test_cli_static_near_root_rejects_too_large(void) {
    uint32_t v = 99;
    char err[256] = {0};
    /* FACTORY_MAX_LEVELS == 8, so 8 must be rejected. */
    int ok = cli_parse_static_near_root("8", &v, err, sizeof(err));
    T_ASSERT(!ok, "--static-near-root 8 must be rejected (>= FACTORY_MAX_LEVELS)");
    T_ASSERT_SUBSTR(err, "[0, 8)");
    return 1;
}

/* ---- cli_validate_shape_for_bolt2016 ---- */

int test_cli_shape_uniform_ps_8_passes(void) {
    /* N=8 uniform PS, mainnet defaults: 3 layers (depth 3) - one PS leaf
       layer = 2 layers * 144 * 3 = 864 blocks, well under 2016. */
    char err[512] = {0};
    uint32_t ewt = 0;
    int ok = cli_validate_shape_for_bolt2016(NULL, 0, FACTORY_ARITY_PS,
                                              8, 0, 144, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(ok, "N=8 uniform PS must pass BOLT-2016");
    T_ASSERT(ewt <= 2016, "ewt must be <= 2016 blocks");
    return 1;
}

int test_cli_shape_binary_n128_rejected(void) {
    /* N=128 uniform DW arity-2: depth 7, 7 DW layers * 144 * 3 = 3024.
       But DW_MAX_LAYERS = 8, capped to 8. Either way exceeds 2016. */
    char err[512] = {0};
    uint32_t ewt = 0;
    factory_arity_t fa = FACTORY_ARITY_2;
    int ok = cli_validate_shape_for_bolt2016(NULL, 0, fa,
                                              128, 0, 144, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(!ok, "N=128 uniform arity-2 must be rejected");
    T_ASSERT(ewt > 2016, "ewt must exceed 2016 blocks");
    T_ASSERT_SUBSTR(err, "exceeds BOLT 2016");
    T_ASSERT_SUBSTR(err, "factory-arity.md");
    return 1;
}

int test_cli_shape_arity_2_4_n64_passes(void) {
    /* --arity 2,4 with N=64 (last entry 4 repeats deeper):
       depth 0 (a=2): 64 -> {32,32}
       depth 1 (a=4): 32 not leaf -> {8,8,8,8}
       depth 2 (a=4): 8 not leaf -> {2,2,2,2}
       depth 3 (a=4): 2 IS leaf (2 <= 4)
       max_depth = 3, n_layers = 4, ewt = 4 * 432 = 1728 — under 2016. */
    uint8_t arities[] = { 2, 4 };
    char err[512] = {0};
    uint32_t ewt = 0;
    int ok = cli_validate_shape_for_bolt2016(arities, 2, FACTORY_ARITY_2,
                                              64, 0, 144, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(ok, "--arity 2,4 N=64 should pass (ewt=1728)");
    T_ASSERT(ewt == 1728, "ewt is 4 layers * 432 = 1728 blocks");
    return 1;
}

int test_cli_shape_uniform_arity2_n64_rejected(void) {
    /* Uniform arity-2 N=64: depth 6 (binary), 6 layers * 432 = 2592 blocks.
       Exceeds BOLT 2016 — the canonical reason to use mixed arity. */
    char err[512] = {0};
    uint32_t ewt = 0;
    int ok = cli_validate_shape_for_bolt2016(NULL, 0, FACTORY_ARITY_2,
                                              64, 0, 144, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(!ok, "uniform arity-2 N=64 must be rejected");
    T_ASSERT(ewt > 2016, "ewt > 2016 (was %u)");
    T_ASSERT_SUBSTR(err, "exceeds BOLT 2016");
    T_ASSERT_SUBSTR(err, "factory-arity.md");
    return 1;
}

int test_cli_shape_mixed_248_n64_passes(void) {
    /* --arity 2,4,8 N=64: depth 3, 3 DW layers * 432 = 1296. Under. */
    uint8_t arities[] = { 2, 4, 8 };
    char err[512] = {0};
    uint32_t ewt = 0;
    int ok = cli_validate_shape_for_bolt2016(arities, 3, FACTORY_ARITY_2,
                                              64, 0, 144, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(ok, "--arity 2,4,8 N=64 must pass BOLT-2016");
    T_ASSERT(ewt <= 2016, "ewt must be <= 2016");
    return 1;
}

int test_cli_shape_mixed_248_static2_n128_passes(void) {
    /* The canonical 128-client design target: --arity 2,4,8
       --static-near-root 2 N=128. depth 3, n_dw_layers = 3-2+1 = 2 ->
       wait: 3 - 2 + 1 = 2 layers... actually 432 * 2 = 864 (one layer
       removed by static count), but the design target says 432.
       Let's check what we actually compute. */
    uint8_t arities[] = { 2, 4, 8 };
    char err[512] = {0};
    uint32_t ewt = 0;
    int ok = cli_validate_shape_for_bolt2016(arities, 3, FACTORY_ARITY_2,
                                              128, 2, 144, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(ok, "--arity 2,4,8 --static-near-root 2 N=128 must pass");
    T_ASSERT(ewt <= 2016, "ewt under BOLT 2016");
    /* Per dw_n_layers_for(depth=3, threshold=2) = 3 - 2 + 1 = 2.
       2 layers * 432 = 864 blocks. (DW arity-2 leaves; no PS subtraction.) */
    T_ASSERT(ewt == 864, "ewt should be 864 blocks (2 DW layers)");
    return 1;
}

int test_cli_shape_regtest_step10_always_passes(void) {
    /* Regtest step_blocks=10 means even uniform binary at N=128 (~ 8
       capped layers * 30 = 240) is well under 2016. */
    char err[512] = {0};
    uint32_t ewt = 0;
    int ok = cli_validate_shape_for_bolt2016(NULL, 0, FACTORY_ARITY_2,
                                              128, 0, 10, 4,
                                              &ewt, err, sizeof(err));
    T_ASSERT(ok, "regtest step_blocks=10 keeps budget non-binding");
    return 1;
}

/* ---- cli_validate_mainnet_step_floor ---- */

int test_cli_step_floor_mainnet_rejects_small(void) {
    char err[512] = {0};
    int ok = cli_validate_mainnet_step_floor("mainnet", 5, err, sizeof(err));
    T_ASSERT(!ok, "mainnet --step-blocks 5 must be rejected");
    T_ASSERT_SUBSTR(err, "below the mainnet safety floor");
    T_ASSERT_SUBSTR(err, "144");
    return 1;
}

int test_cli_step_floor_mainnet_accepts_144(void) {
    char err[512] = {0};
    int ok = cli_validate_mainnet_step_floor("mainnet", 144, err, sizeof(err));
    T_ASSERT(ok, "mainnet --step-blocks 144 must pass the floor");
    return 1;
}

int test_cli_step_floor_bitcoin_alias_rejects_small(void) {
    char err[512] = {0};
    int ok = cli_validate_mainnet_step_floor("bitcoin", 10, err, sizeof(err));
    T_ASSERT(!ok, "network 'bitcoin' alias must also enforce the floor");
    T_ASSERT_SUBSTR(err, "mainnet safety floor");
    return 1;
}

int test_cli_step_floor_regtest_allows_small(void) {
    char err[512] = {0};
    int ok = cli_validate_mainnet_step_floor("regtest", 5, err, sizeof(err));
    T_ASSERT(ok, "regtest --step-blocks 5 must pass (non-mainnet unaffected)");
    return 1;
}

int test_cli_step_floor_signet_allows_small(void) {
    char err[512] = {0};
    int ok = cli_validate_mainnet_step_floor("signet", 1, err, sizeof(err));
    T_ASSERT(ok, "signet --step-blocks 1 must pass (non-mainnet unaffected)");
    return 1;
}

/* End-of-file public test list (referenced from test_main.c) */

/* ---- factory CLTV timeout floors ---- */

int test_cli_factory_cltv_floor(void) {
    char err[512] = {0};
    /* 4 clients, PS leaves, step 10, 4 states: ewt 60 (two DW layers of
       30), depth bound 3 -> 9 transactions and 30 blocks of staggering */
    uint32_t exit4 = cli_factory_exit_blocks(NULL, 0, FACTORY_ARITY_PS, 4, 0, 10, 4);
    T_ASSERT(exit4 == 99, "exit blocks of the default regtest shape");
    T_ASSERT(cli_factory_exit_blocks(NULL, 0, FACTORY_ARITY_PS, 64, 0, 10, 4) > exit4,
             "a deeper tree needs more");
    T_ASSERT(cli_factory_exit_blocks(NULL, 0, FACTORY_ARITY_PS, 4, 0, 1, 2) < exit4,
             "short DW delays need less");
    /* created at 209, 60 active + 20 dying: EXPIRED from 289; exit 99+6 */
    T_ASSERT(cli_validate_factory_cltv(209 + 106, 209, 60, 20, exit4, err, sizeof(err)),
             "a timeout past the lifetime and the exit is accepted");
    T_ASSERT(!cli_validate_factory_cltv(209 + 105, 209, 60, 20, exit4, err, sizeof(err)),
             "a timeout within a member exit is refused");
    T_ASSERT_SUBSTR(err, "--cltv-timeout 315 or later");
    T_ASSERT(cli_validate_factory_cltv(289, 209, 60, 20, 10, err, sizeof(err)),
             "a timeout at the EXPIRED block is accepted when the exit fits");
    T_ASSERT(!cli_validate_factory_cltv(288, 209, 60, 20, 10, err, sizeof(err)),
             "a timeout inside the lifetime is refused");
    T_ASSERT_SUBSTR(err, "expires at block 289");
    /* the trace case: 162 while the chain is at 211 */
    T_ASSERT(!cli_validate_factory_cltv(162, 211, 20, 10, exit4, err, sizeof(err)),
             "a timeout in the past is refused");
    /* the automatic offset satisfies both rules */
    uint32_t off = cli_factory_auto_cltv_offset(35, exit4);
    T_ASSERT(off == 112, "regtest auto offset raised to the exit and tip skew");
    T_ASSERT(cli_validate_factory_cltv(211 + off, 211, 20, 10, exit4, err, sizeof(err)),
             "regtest auto accepted");
    T_ASSERT(cli_factory_auto_cltv_offset(4320 + 432 + 10, exit4) == 4762,
             "mainnet lifetime dominates");
    T_ASSERT(!cli_validate_factory_cltv(100, 0xFFFFFFF0u, 0xFFFFFFF0u, 5, 0, err, sizeof(err)),
             "no wrap-around");
    return 1;
}

int test_cli_proposed_cltv_floor(void) {
    char err[512] = {0};
    uint32_t exit4 = cli_factory_exit_blocks(NULL, 0, FACTORY_ARITY_PS, 4, 0, 10, 4);
    T_ASSERT(cli_validate_proposed_cltv(211 + 106, 211, exit4, err, sizeof(err)),
             "the LSP auto timeout is accepted");
    T_ASSERT(!cli_validate_proposed_cltv(211 + 105, 211, exit4, err, sizeof(err)),
             "a timeout within the exit plus margin is refused");
    T_ASSERT_SUBSTR(err, "not safely in the future");
    T_ASSERT(!cli_validate_proposed_cltv(211 + 35, 211, exit4, err, sizeof(err)),
             "the old regtest +35 is refused for this shape");
    T_ASSERT(!cli_validate_proposed_cltv(162, 211, exit4, err, sizeof(err)),
             "a timeout in the past is refused");
    T_ASSERT(cli_validate_proposed_cltv(5, 0, exit4, err, sizeof(err)),
             "unknown tip is not judged");
    return 1;
}
