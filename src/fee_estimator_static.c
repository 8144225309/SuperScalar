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
