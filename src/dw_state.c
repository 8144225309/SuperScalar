#include "superscalar/dw_state.h"

void dw_layer_init(dw_layer_t *layer, uint16_t step_blocks, uint32_t max_states) {
    layer->config.step_blocks = step_blocks;
    layer->config.max_states = max_states;
    layer->current_state = 0;
}

uint16_t dw_delay_for_state(const dw_layer_config_t *cfg, uint32_t state_index) {
    /* delay = step * (max_states - 1 - index), so newest state has delay=0 */
    return cfg->step_blocks * (cfg->max_states - 1 - state_index);
}

uint32_t dw_nsequence_for_state(const dw_layer_config_t *cfg, uint32_t state_index) {
    /* BIP-68 block-based: just the delay value (bits 31,22 = 0) */
    return (uint32_t)dw_delay_for_state(cfg, state_index);
}

bool dw_advance(dw_layer_t *layer) {
    if (layer->current_state >= layer->config.max_states - 1)
        return false;
    layer->current_state++;
    return true;
}

bool dw_is_exhausted(const dw_layer_t *layer) {
    return layer->current_state >= layer->config.max_states - 1;
}

uint32_t dw_current_nsequence(const dw_layer_t *layer) {
    return dw_nsequence_for_state(&layer->config, layer->current_state);
}

/* --- Multi-layer counter --- */

void dw_counter_init(dw_counter_t *ctr, uint32_t n_layers,
                      uint16_t step_blocks, uint32_t states_per_layer) {
    ctr->n_layers = n_layers;
    ctr->current_epoch = 0;

    ctr->total_states = 1;
    for (uint32_t i = 0; i < n_layers; i++)
        ctr->total_states *= states_per_layer;

    for (uint32_t i = 0; i < n_layers; i++)
        dw_layer_init(&ctr->layers[i], step_blocks, states_per_layer);
}

bool dw_counter_advance(dw_counter_t *ctr) {
    if (ctr->current_epoch >= ctr->total_states - 1)
        return false;

    /* Odometer: try innermost first, reset and carry on overflow */
    for (int i = (int)ctr->n_layers - 1; i >= 0; i--) {
        if (dw_advance(&ctr->layers[i])) {
            for (uint32_t j = (uint32_t)i + 1; j < ctr->n_layers; j++)
                ctr->layers[j].current_state = 0;
            ctr->current_epoch++;
            return true;
        }
    }

    return false;
}

bool dw_counter_is_exhausted(const dw_counter_t *ctr) {
    return ctr->current_epoch >= ctr->total_states - 1;
}

uint32_t dw_counter_epoch(const dw_counter_t *ctr) {
    return ctr->current_epoch;
}

void dw_counter_reset(dw_counter_t *ctr) {
    for (uint32_t i = 0; i < ctr->n_layers; i++)
        ctr->layers[i].current_state = 0;
    ctr->current_epoch = 0;
}
