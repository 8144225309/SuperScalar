#include "superscalar/dw_state.h"
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

int test_dw_layer_init(void) {
    dw_layer_t layer;
    dw_layer_init(&layer, 144, 4);

    TEST_ASSERT_EQ(layer.config.step_blocks, 144, "step_blocks should be 144");
    TEST_ASSERT_EQ(layer.config.max_states, 4, "max_states should be 4");
    TEST_ASSERT_EQ(layer.current_state, 0, "current_state should start at 0");

    return 1;
}

int test_dw_delay_for_state(void) {
    dw_layer_config_t cfg = { .step_blocks = 144, .max_states = 4 };

    /* step=144, max_states=4:
     *   state 0 (oldest): 144 * 3 = 432
     *   state 1:          144 * 2 = 288
     *   state 2:          144 * 1 = 144
     *   state 3 (newest): 144 * 0 = 0   (confirms immediately) */
    TEST_ASSERT_EQ(dw_delay_for_state(&cfg, 0), 432, "state 0 delay");
    TEST_ASSERT_EQ(dw_delay_for_state(&cfg, 1), 288, "state 1 delay");
    TEST_ASSERT_EQ(dw_delay_for_state(&cfg, 2), 144, "state 2 delay");
    TEST_ASSERT_EQ(dw_delay_for_state(&cfg, 3), 0, "state 3 delay");

    for (uint32_t i = 1; i < 4; i++) {
        TEST_ASSERT(dw_delay_for_state(&cfg, i) < dw_delay_for_state(&cfg, i - 1),
                     "delays must be strictly decreasing");
    }

    return 1;
}

int test_dw_nsequence_for_state(void) {
    dw_layer_config_t cfg = { .step_blocks = 144, .max_states = 4 };

    /* BIP-68 block-based: nSequence = delay, bits 31 and 22 clear */
    TEST_ASSERT_EQ(dw_nsequence_for_state(&cfg, 0), 432, "state 0 nsequence");
    TEST_ASSERT_EQ(dw_nsequence_for_state(&cfg, 3), 0, "state 3 nsequence");

    for (uint32_t i = 0; i < 4; i++) {
        uint32_t seq = dw_nsequence_for_state(&cfg, i);
        TEST_ASSERT((seq & (1u << 31)) == 0, "bit 31 must be 0 for BIP-68");
        TEST_ASSERT((seq & (1u << 22)) == 0, "bit 22 must be 0 for block-based");
        TEST_ASSERT((seq & 0xffff) == seq, "must fit in 16 bits");
    }

    return 1;
}

int test_dw_advance(void) {
    dw_layer_t layer;
    dw_layer_init(&layer, 144, 4);

    TEST_ASSERT_EQ(layer.current_state, 0, "initial state");

    TEST_ASSERT(dw_advance(&layer), "advance 0->1 should succeed");
    TEST_ASSERT_EQ(layer.current_state, 1, "state after first advance");

    TEST_ASSERT(dw_advance(&layer), "advance 1->2 should succeed");
    TEST_ASSERT_EQ(layer.current_state, 2, "state after second advance");

    TEST_ASSERT(dw_advance(&layer), "advance 2->3 should succeed");
    TEST_ASSERT_EQ(layer.current_state, 3, "state after third advance");

    TEST_ASSERT(!dw_advance(&layer), "advance past max should fail");
    TEST_ASSERT_EQ(layer.current_state, 3, "state should not change past max");

    return 1;
}

int test_dw_exhaustion(void) {
    dw_layer_t layer;
    dw_layer_init(&layer, 144, 4);

    TEST_ASSERT(!dw_is_exhausted(&layer), "not exhausted at start");

    for (int i = 0; i < 3; i++)
        dw_advance(&layer);

    TEST_ASSERT(dw_is_exhausted(&layer), "exhausted after 3 advances");
    TEST_ASSERT_EQ(layer.current_state, 3, "at max state");

    dw_layer_t single;
    dw_layer_init(&single, 144, 1);
    TEST_ASSERT(dw_is_exhausted(&single), "single-state layer is immediately exhausted");

    return 1;
}

int test_dw_counter_init(void) {
    dw_counter_t ctr;
    dw_counter_init(&ctr, 3, 144, 4);

    TEST_ASSERT_EQ(ctr.n_layers, 3, "n_layers");
    TEST_ASSERT_EQ(ctr.total_states, 64, "4^3 = 64 total states");
    TEST_ASSERT_EQ(ctr.current_epoch, 0, "initial epoch");

    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQ(ctr.layers[i].config.step_blocks, 144, "layer step_blocks");
        TEST_ASSERT_EQ(ctr.layers[i].config.max_states, 4, "layer max_states");
        TEST_ASSERT_EQ(ctr.layers[i].current_state, 0, "layer initial state");
    }

    return 1;
}

int test_dw_counter_advance(void) {
    dw_counter_t ctr;
    dw_counter_init(&ctr, 3, 144, 4);

    /* innermost layer goes 0->1 */
    TEST_ASSERT(dw_counter_advance(&ctr), "first advance");
    TEST_ASSERT_EQ(ctr.current_epoch, 1, "epoch after first advance");
    TEST_ASSERT_EQ(ctr.layers[2].current_state, 1, "innermost layer state");
    TEST_ASSERT_EQ(ctr.layers[1].current_state, 0, "middle layer unchanged");
    TEST_ASSERT_EQ(ctr.layers[0].current_state, 0, "outer layer unchanged");

    /* two more: innermost hits 3 (exhausted) */
    TEST_ASSERT(dw_counter_advance(&ctr), "advance 2");
    TEST_ASSERT(dw_counter_advance(&ctr), "advance 3");
    TEST_ASSERT_EQ(ctr.layers[2].current_state, 3, "innermost at max");

    /* odometer rollover: innermost resets, middle ticks */
    TEST_ASSERT(dw_counter_advance(&ctr), "odometer rollover");
    TEST_ASSERT_EQ(ctr.current_epoch, 4, "epoch after rollover");
    TEST_ASSERT_EQ(ctr.layers[2].current_state, 0, "innermost reset");
    TEST_ASSERT_EQ(ctr.layers[1].current_state, 1, "middle advanced");
    TEST_ASSERT_EQ(ctr.layers[0].current_state, 0, "outer unchanged");

    return 1;
}

int test_dw_counter_full_cycle(void) {
    dw_counter_t ctr;
    dw_counter_init(&ctr, 3, 144, 4);

    int count = 0;
    while (dw_counter_advance(&ctr))
        count++;

    TEST_ASSERT_EQ(count, 63, "should make exactly 63 transitions");
    TEST_ASSERT(dw_counter_is_exhausted(&ctr), "counter should be exhausted");
    TEST_ASSERT_EQ(ctr.current_epoch, 63, "final epoch");

    for (uint32_t i = 0; i < 3; i++)
        TEST_ASSERT_EQ(ctr.layers[i].current_state, 3, "all layers at max");

    TEST_ASSERT(!dw_counter_advance(&ctr), "cannot advance past end");

    return 1;
}

/* ---- Edge case: single-layer single-state (min config) ---- */

int test_dw_counter_single_state(void) {
    dw_counter_t ctr;
    dw_counter_init(&ctr, 1, 144, 1);

    /* With max_states=1, counter starts exhausted (state 0 is the only state) */
    TEST_ASSERT(dw_counter_is_exhausted(&ctr), "single-state is immediately exhausted");
    TEST_ASSERT(!dw_counter_advance(&ctr), "cannot advance single-state");
    TEST_ASSERT_EQ(ctr.current_epoch, 0, "epoch stays at 0");

    return 1;
}

/* ---- Edge case: DW delay invariants ---- */

int test_dw_delay_invariants(void) {
    /* DW invariant: within any single layer, newer state = strictly lower delay.
       Newest state (max-1) has zero delay. Oldest state (0) has max delay. */
    dw_counter_t ctr;
    dw_counter_init(&ctr, 3, 10, 4);

    /* Per-layer: state N+1 always has strictly lower delay than state N */
    for (uint32_t layer = 0; layer < ctr.n_layers; layer++) {
        for (uint32_t s = 0; s + 1 < ctr.layers[layer].config.max_states; s++) {
            uint16_t d0 = dw_delay_for_state(&ctr.layers[layer].config, s);
            uint16_t d1 = dw_delay_for_state(&ctr.layers[layer].config, s + 1);
            TEST_ASSERT(d1 < d0, "newer state must have strictly lower delay");
        }
    }

    /* Newest state (max_states-1) has zero delay at every layer */
    for (uint32_t layer = 0; layer < ctr.n_layers; layer++) {
        uint32_t max_s = ctr.layers[layer].config.max_states - 1;
        uint16_t d = dw_delay_for_state(&ctr.layers[layer].config, max_s);
        TEST_ASSERT_EQ(d, 0, "newest state delay is zero");
    }

    /* Oldest state (0) has max delay = step * (max_states-1) */
    uint16_t d0 = dw_delay_for_state(&ctr.layers[0].config, 0);
    TEST_ASSERT_EQ(d0, 10 * 3, "oldest state delay = step * (max-1)");

    return 1;
}
