#ifndef SUPERSCALAR_DW_STATE_H
#define SUPERSCALAR_DW_STATE_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Decker-Wattenhofer invalidation layer.
 * Newer states get lower nSequence delays (decrementing).
 * Newest state confirms first, invalidating all older ones.
 *
 * BIP-68 encoding: bit 31=0, bit 22=0, bits 15:0 = block count.
 */

typedef struct {
    uint16_t step_blocks;   /* blocks per step (e.g. 144) */
    uint32_t max_states;
} dw_layer_config_t;

typedef struct {
    dw_layer_config_t config;
    uint32_t current_state; /* 0 = oldest, max_states-1 = newest */
} dw_layer_t;

void     dw_layer_init(dw_layer_t *layer, uint16_t step_blocks, uint32_t max_states);
uint16_t dw_delay_for_state(const dw_layer_config_t *cfg, uint32_t state_index);
uint32_t dw_nsequence_for_state(const dw_layer_config_t *cfg, uint32_t state_index);
bool     dw_advance(dw_layer_t *layer);
bool     dw_is_exhausted(const dw_layer_t *layer);
uint32_t dw_current_nsequence(const dw_layer_t *layer);

/*
 * Multi-layer DW counter. Odometer-style:
 * innermost layer ticks fastest, rolls over into the next.
 * N layers of K states = K^N total states.
 */

#define DW_MAX_LAYERS 8

typedef struct {
    dw_layer_t layers[DW_MAX_LAYERS];
    uint32_t n_layers;
    uint32_t total_states;
    uint32_t current_epoch;
} dw_counter_t;

void     dw_counter_init(dw_counter_t *ctr, uint32_t n_layers,
                          uint16_t step_blocks, uint32_t states_per_layer);
bool     dw_counter_advance(dw_counter_t *ctr);
bool     dw_counter_is_exhausted(const dw_counter_t *ctr);
uint32_t dw_counter_epoch(const dw_counter_t *ctr);

/* Reset all layers and epoch to 0, reclaiming all N^2 states. */
void     dw_counter_reset(dw_counter_t *ctr);

#endif /* SUPERSCALAR_DW_STATE_H */
