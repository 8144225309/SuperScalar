#include "superscalar/fee_estimator.h"
#include <string.h>

static uint64_t static_get_rate(fee_estimator_t *self, fee_target_t target)
{
    (void)target;
    fee_estimator_static_t *fe = (fee_estimator_static_t *)self;
    return fe->sat_per_kvb;
}

void fee_estimator_static_init(fee_estimator_static_t *fe, uint64_t sat_per_kvb)
{
    if (!fe) return;
    memset(fe, 0, sizeof(*fe));
    fe->base.get_rate = static_get_rate;
    fe->base.update   = NULL;
    fe->base.free     = NULL;
    fe->sat_per_kvb   = sat_per_kvb;
}

/* -----------------------------------------------------------------------
 * fee_est_t implementation
 * --------------------------------------------------------------------- */
#include <time.h>

void fee_est_init(fee_est_t *fe, fee_estimator_t *backend)
{
    if (!fe) return;
    fe->backend               = backend;
    fe->fallback_rate_sat_kvb = 1000;
    fe->cached_rate_sat_kvb   = 0;
    fe->last_update_ts        = 0;
}

void fee_est_set_fallback(fee_est_t *fe, uint32_t feerate_sat_kvb)
{
    if (!fe) return;
    fe->fallback_rate_sat_kvb = feerate_sat_kvb;
}

uint32_t fee_est_get_feerate(fee_est_t *fe)
{
    if (!fe) return 1000;

    uint64_t now = (uint64_t)time(NULL);
    /* Return cached value if it was set within the last 60 seconds */
    if (fe->cached_rate_sat_kvb > 0 &&
        fe->last_update_ts > 0 &&
        now - fe->last_update_ts < 60) {
        return fe->cached_rate_sat_kvb;
    }
    return fe->fallback_rate_sat_kvb;
}

void fee_est_set_cached(fee_est_t *fe, uint32_t feerate_sat_kvb)
{
    if (!fe) return;
    fe->cached_rate_sat_kvb = feerate_sat_kvb;
    fe->last_update_ts      = (uint64_t)time(NULL);
}

void fee_est_invalidate(fee_est_t *fe)
{
    if (!fe) return;
    fe->last_update_ts = 0;
}
