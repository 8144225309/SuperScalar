#include "superscalar/fee_estimator.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* Map fee_target_t to the confirmations argument for estimatesmartfee */
static int target_to_blocks(fee_target_t target)
{
    switch (target) {
        case FEE_TARGET_URGENT:  return 2;
        case FEE_TARGET_NORMAL:  return 6;
        case FEE_TARGET_ECONOMY: return 144;
        case FEE_TARGET_MINIMUM: return 1008;
        default:                 return 6;
    }
}

static int rpc_idx(fee_target_t target)
{
    switch (target) {
        case FEE_TARGET_URGENT:  return FEE_RPC_IDX_URGENT;
        case FEE_TARGET_NORMAL:  return FEE_RPC_IDX_NORMAL;
        case FEE_TARGET_ECONOMY: return FEE_RPC_IDX_ECONOMY;
        case FEE_TARGET_MINIMUM: return FEE_RPC_IDX_MINIMUM;
        default:                 return FEE_RPC_IDX_NORMAL;
    }
}

static uint64_t query_estimatesmartfee(regtest_t *rt, int target_blocks)
{
    char params[32];
    snprintf(params, sizeof(params), "%d", target_blocks);
    char *result = regtest_exec(rt, "estimatesmartfee", params);
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return 0;

    cJSON *feerate = cJSON_GetObjectItem(json, "feerate");
    uint64_t sat_per_kvb = 0;
    if (feerate && cJSON_IsNumber(feerate) && feerate->valuedouble > 0) {
        sat_per_kvb = (uint64_t)(feerate->valuedouble * 100000000.0 + 0.5);
        if (sat_per_kvb < FEE_FLOOR_SAT_PER_KVB) sat_per_kvb = FEE_FLOOR_SAT_PER_KVB;
    }
    cJSON_Delete(json);
    return sat_per_kvb;
}

static uint64_t rpc_get_rate(fee_estimator_t *self, fee_target_t target)
{
    fee_estimator_rpc_t *fe = (fee_estimator_rpc_t *)self;
    if (!fe->rt) return 0;

    int idx = rpc_idx(target);
    uint64_t now = (uint64_t)time(NULL);

    /* Refresh this target if cache is stale (> 60 seconds) */
    if (fe->cached[idx] == 0 || now - fe->last_updated >= 60) {
        uint64_t rate = query_estimatesmartfee(
            (regtest_t *)fe->rt, target_to_blocks(target));
        if (rate > 0) {
            fe->cached[idx] = rate;
            fe->last_updated = now;
        }
    }
    return fe->cached[idx];
}

static void rpc_update(fee_estimator_t *self)
{
    fee_estimator_rpc_t *fe = (fee_estimator_rpc_t *)self;
    if (!fe->rt) return;

    uint64_t now = (uint64_t)time(NULL);
    if (now - fe->last_updated < 60) return;  /* still fresh */

    /* Refresh all four targets */
    static const fee_target_t targets[] = {
        FEE_TARGET_URGENT, FEE_TARGET_NORMAL,
        FEE_TARGET_ECONOMY, FEE_TARGET_MINIMUM
    };
    for (int i = 0; i < 4; i++) {
        uint64_t rate = query_estimatesmartfee(
            (regtest_t *)fe->rt, target_to_blocks(targets[i]));
        if (rate > 0)
            fe->cached[rpc_idx(targets[i])] = rate;
    }
    fe->last_updated = now;
}

void fee_estimator_rpc_init(fee_estimator_rpc_t *fe, void *rt)
{
    if (!fe) return;
    memset(fe, 0, sizeof(*fe));
    fe->base.get_rate = rpc_get_rate;
    fe->base.update   = rpc_update;
    fe->base.free     = NULL;
    fe->rt            = rt;
}
