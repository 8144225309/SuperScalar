#ifndef SUPERSCALAR_FEE_H
#define SUPERSCALAR_FEE_H

#include <stdint.h>
#include <stddef.h>
#include "superscalar/fee_estimator.h"

struct regtest_t;  /* forward declaration */

/* -----------------------------------------------------------------------
 * Backwards-compatibility shims (deprecated — use fee_estimator_*.h APIs)
 *
 * fee_init: callers MUST pass a pointer to a fee_estimator_static_t that
 * is cast to fee_estimator_t *.  e.g.:
 *   fee_estimator_static_t fe;
 *   fee_init((fee_estimator_t *)&fe, 1000);
 * --------------------------------------------------------------------- */
void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb);

/* Deprecated: calls fe->update() if set; ignored for static estimators. */
int fee_update_from_node(fee_estimator_t *fe, void *rt, int target_blocks);

/* -----------------------------------------------------------------------
 * Fee helpers — call through the vtable
 * --------------------------------------------------------------------- */

/* General-purpose: fee for a transaction of given virtual size (NORMAL rate). */
uint64_t fee_estimate(fee_estimator_t *fe, size_t vsize_bytes);

/* Penalty tx is ~165 vB — uses URGENT rate (next 1-2 blocks). */
uint64_t fee_for_penalty_tx(fee_estimator_t *fe);

/* HTLC resolution tx is ~180 vB — uses URGENT rate. */
uint64_t fee_for_htlc_tx(fee_estimator_t *fe);

/* CPFP child tx is ~264 vB (2-in keypath, 1-out P2TR) — uses URGENT rate. */
uint64_t fee_for_cpfp_child(fee_estimator_t *fe);

/* Commitment tx is 154 vB base + 43 vB per active HTLC — uses NORMAL rate. */
uint64_t fee_for_commitment_tx(fee_estimator_t *fe, size_t n_htlcs);

/* Factory tree tx (variable) — uses NORMAL rate. */
uint64_t fee_for_factory_tx(fee_estimator_t *fe, size_t n_outputs);

#endif /* SUPERSCALAR_FEE_H */
