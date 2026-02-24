#include "superscalar/fee.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb) {
    if (!fe) return;
    memset(fe, 0, sizeof(*fe));
    fe->fee_rate_sat_per_kvb = default_rate_sat_per_kvb;
    fe->use_estimatesmartfee = 0;
}

int fee_update_from_node(fee_estimator_t *fe, void *rt_ptr, int target_blocks) {
    if (!fe || !rt_ptr || target_blocks < 1) return 0;
    regtest_t *rt = (regtest_t *)rt_ptr;

    char params[32];
    snprintf(params, sizeof(params), "%d", target_blocks);
    char *result = regtest_exec(rt, "estimatesmartfee", params);
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return 0;

    /* estimatesmartfee returns {"feerate": BTC_per_kvB, "blocks": N}
       or {"errors": [...]} if insufficient data */
    cJSON *feerate = cJSON_GetObjectItem(json, "feerate");
    if (!feerate || !cJSON_IsNumber(feerate) || feerate->valuedouble <= 0) {
        cJSON_Delete(json);
        return 0;
    }

    /* Convert BTC/kvB to sat/kvB: multiply by 100,000,000 */
    uint64_t sat_per_kvb = (uint64_t)(feerate->valuedouble * 100000000.0 + 0.5);

    /* Clamp to minimum 1000 sat/kvB (1 sat/vB) */
    if (sat_per_kvb < 1000) sat_per_kvb = 1000;

    fe->fee_rate_sat_per_kvb = sat_per_kvb;
    cJSON_Delete(json);
    return 1;
}

uint64_t fee_estimate(const fee_estimator_t *fe, size_t vsize_bytes) {
    if (!fe || fe->fee_rate_sat_per_kvb == 0) return 0;
    /* Round up: (rate * vsize + 999) / 1000 */
    return (fe->fee_rate_sat_per_kvb * vsize_bytes + 999) / 1000;
}

uint64_t fee_for_penalty_tx(const fee_estimator_t *fe) {
    /* Penalty tx: 1 Schnorr key-path input, 2 outputs (sweep P2TR + P2A anchor) ~165 vB */
    return fee_estimate(fe, 165);
}

uint64_t fee_for_cpfp_child(const fee_estimator_t *fe) {
    /* CPFP child: P2A anchor input (empty witness) + wallet input, 1 output ~200 vB */
    return fee_estimate(fe, 200);
}

uint64_t fee_for_htlc_tx(const fee_estimator_t *fe) {
    /* HTLC resolution tx: script-path spend ~180 vB */
    return fee_estimate(fe, 180);
}

uint64_t fee_for_commitment_tx(const fee_estimator_t *fe, size_t n_htlcs) {
    /* Commitment tx: 1 key-path input + 2 base P2TR outputs = 154 vB.
       Each active HTLC adds one P2TR output = 43 vB. */
    size_t vsize = 154 + 43 * n_htlcs;
    return fee_estimate(fe, vsize);
}

uint64_t fee_for_factory_tx(const fee_estimator_t *fe, size_t n_outputs) {
    /* Factory tree tx: ~50 vB overhead + ~43 vB per P2TR output */
    size_t vsize = 50 + 43 * n_outputs;
    return fee_estimate(fe, vsize);
}
