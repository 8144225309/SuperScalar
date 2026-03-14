#include "superscalar/fee.h"
#include "superscalar/fee_estimator.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * Backwards-compatibility shims
 * --------------------------------------------------------------------- */

void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb)
{
    /* The pointer MUST actually point to a fee_estimator_static_t.
       Deprecated — callers should use fee_estimator_static_init() directly. */
    fee_estimator_static_init((fee_estimator_static_t *)fe,
                               default_rate_sat_per_kvb);
}

int fee_update_from_node(fee_estimator_t *fe, void *rt, int target_blocks)
{
    (void)rt; (void)target_blocks;
    if (!fe) return 0;
    /* Deprecated: call the vtable update slot if available */
    if (fe->update) {
        fe->update(fe);
        return 1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Fee helpers — route through the vtable
 * --------------------------------------------------------------------- */

/* Overflow-safe fee computation: rate * vsize / 1000, rounded up.
   Returns 0 if rate is 0 (estimator unavailable). */
static uint64_t compute_fee(uint64_t sat_per_kvb, size_t vsize_bytes)
{
    if (sat_per_kvb == 0) return 0;
    /* Cap at 1 BTC to prevent overflow at extreme fee rates */
    if (sat_per_kvb > (uint64_t)100000000 / (vsize_bytes + 1))
        return 100000000ULL;
    return (sat_per_kvb * vsize_bytes + 999) / 1000;
}

uint64_t fee_estimate(fee_estimator_t *fe, size_t vsize_bytes)
{
    if (!fe || !fe->get_rate) return 0;
    return compute_fee(fe->get_rate(fe, FEE_TARGET_NORMAL), vsize_bytes);
}

uint64_t fee_for_penalty_tx(fee_estimator_t *fe)
{
    /* Penalty tx: ~165 vB — needs URGENT (next 1-2 blocks) */
    if (!fe || !fe->get_rate) return 0;
    return compute_fee(fe->get_rate(fe, FEE_TARGET_URGENT), 165);
}

uint64_t fee_for_htlc_tx(fee_estimator_t *fe)
{
    /* HTLC resolution tx: ~180 vB — needs URGENT */
    if (!fe || !fe->get_rate) return 0;
    return compute_fee(fe->get_rate(fe, FEE_TARGET_URGENT), 180);
}

uint64_t fee_for_cpfp_child(fee_estimator_t *fe)
{
    /* CPFP child: P2A anchor input + wallet input, 1 output ~264 vB — URGENT */
    if (!fe || !fe->get_rate) return 0;
    return compute_fee(fe->get_rate(fe, FEE_TARGET_URGENT), 264);
}

uint64_t fee_for_commitment_tx(fee_estimator_t *fe, size_t n_htlcs)
{
    /* Commitment tx: 154 vB base + 43 vB per active HTLC — NORMAL */
    if (!fe || !fe->get_rate) return 0;
    size_t vsize = 154 + 43 * n_htlcs;
    return compute_fee(fe->get_rate(fe, FEE_TARGET_NORMAL), vsize);
}

uint64_t fee_for_factory_tx(fee_estimator_t *fe, size_t n_outputs)
{
    /* Factory tree tx: 68 vB overhead + 43 vB per P2TR output — NORMAL */
    if (!fe || !fe->get_rate) return 0;
    size_t vsize = 68 + 43 * n_outputs;
    return compute_fee(fe->get_rate(fe, FEE_TARGET_NORMAL), vsize);
}
