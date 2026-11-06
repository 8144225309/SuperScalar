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

/* ceil(rate * vsize / 1000).  Returns 0 if rate is 0 (estimator unavailable)
   and FEE_INVALID when the fee would exceed FEE_MAX_SATS: the product is
   bounded before it is formed, so it never overflows. */
static uint64_t compute_fee(uint64_t sat_per_kvb, size_t vsize_bytes)
{
    if (sat_per_kvb == 0) return 0;
    if (vsize_bytes > 0 &&
        sat_per_kvb > (FEE_MAX_SATS * 1000) / (uint64_t)vsize_bytes)
        return FEE_INVALID;
    uint64_t fee = (sat_per_kvb * (uint64_t)vsize_bytes + 999) / 1000;
    return fee > FEE_MAX_SATS ? FEE_INVALID : fee;
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

uint64_t fee_for_factory_tx(fee_estimator_t *fe, size_t n_p2tr_outputs,
                            int with_anchor)
{
    if (!fe || !fe->get_rate) return 0;
    size_t vsize = fee_keypath_tx_vsize(1, n_p2tr_outputs, with_anchor ? 1 : 0);
    return fee_presigned(fe->get_rate(fe, FEE_TARGET_NORMAL), vsize);
}

static size_t varint_len(size_t n)
{
    return n < 0xfd ? 1 : n <= 0xffff ? 3 : 5;
}

size_t fee_tx_vsize(size_t n_inputs, size_t n_outputs, size_t outputs_bytes,
                    size_t witness_bytes)
{
    /* version + vin count + inputs (outpoint, empty scriptSig, sequence)
       + vout count + outputs + locktime */
    size_t base = 4 + varint_len(n_inputs) + 41 * n_inputs +
                  varint_len(n_outputs) + outputs_bytes + 4;
    size_t weight = 4 * base;
    if (witness_bytes > 0)
        weight += 2 + witness_bytes;   /* marker + flag */
    return (weight + 3) / 4;
}

size_t fee_keypath_tx_vsize(size_t n_inputs, size_t n_p2tr, size_t n_p2a)
{
    return fee_tx_vsize(n_inputs, n_p2tr + n_p2a,
                        FEE_P2TR_OUTPUT_BYTES * n_p2tr + FEE_P2A_OUTPUT_BYTES * n_p2a,
                        FEE_KEYPATH_WITNESS_BYTES * n_inputs);
}

uint64_t fee_at_rate(uint64_t sat_per_kvb, size_t vsize)
{
    return compute_fee(sat_per_kvb, vsize);
}

uint64_t fee_presigned(uint64_t sat_per_kvb, size_t vsize)
{
    if (sat_per_kvb < FEE_PRESIGNED_FLOOR_SAT_PER_KVB)
        sat_per_kvb = FEE_PRESIGNED_FLOOR_SAT_PER_KVB;
    return compute_fee(sat_per_kvb, vsize);
}

int fee_should_use_anchor(fee_estimator_t *fe)
{
    /* At sub-1-sat/vB rates the 240-sat P2A anchor costs more than the
       entire TX fee, making CPFP uneconomical.  Skip anchors below
       1000 sat/kvB and rely on the low base rate for relay. */
    if (!fe || !fe->get_rate) return 1;  /* default: include anchor */
    return fe->get_rate(fe, FEE_TARGET_URGENT) >= 1000;
}
