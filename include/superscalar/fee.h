#ifndef SUPERSCALAR_FEE_H
#define SUPERSCALAR_FEE_H

#include <stdint.h>
#include <stddef.h>

struct regtest_t;  /* forward declaration */

typedef struct {
    uint64_t fee_rate_sat_per_kvb;  /* sat/kilo-vbyte (matches Core's units) */
    int use_estimatesmartfee;        /* if 1, try bitcoin-cli estimatesmartfee */
    uint64_t last_updated;           /* epoch seconds of last successful update */
} fee_estimator_t;

/* Initialize with a default fee rate.  Accepts any rate >= FEE_FLOOR_SAT_PER_KVB. */
void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb);

/* Query bitcoind estimatesmartfee for target_blocks confirmation.
   Updates fee_rate_sat_per_kvb if RPC succeeds; keeps current rate on failure.
   Returns 1 if updated, 0 if RPC failed (rate unchanged). */
int fee_update_from_node(fee_estimator_t *fe, void *rt, int target_blocks);

/* Estimate fee for a tx of given virtual size. Returns fee in sats. */
uint64_t fee_estimate(const fee_estimator_t *fe, size_t vsize_bytes);

/* Convenience: penalty tx is ~165 vB (1-in, 2-out: sweep + anchor, keypath schnorr). */
uint64_t fee_for_penalty_tx(const fee_estimator_t *fe);

/* Convenience: HTLC resolution tx is ~180 vB. */
uint64_t fee_for_htlc_tx(const fee_estimator_t *fe);

/* Convenience: CPFP child tx is ~264 vB (2-in keypath, 1-out P2TR). */
uint64_t fee_for_cpfp_child(const fee_estimator_t *fe);

/* Convenience: commitment tx is 154 vB base + 43 vB per active HTLC output. */
uint64_t fee_for_commitment_tx(const fee_estimator_t *fe, size_t n_htlcs);

/* Convenience: factory tree tx (variable). */
uint64_t fee_for_factory_tx(const fee_estimator_t *fe, size_t n_outputs);

/* Returns 1 if anchors should be included at this fee rate, 0 if not.
   At sub-1-sat/vB rates, CPFP anchors cost more than the TX fee itself,
   creating perverse incentives.  Skip them below 1000 sat/kvB. */
int fee_should_use_anchor(const fee_estimator_t *fe);

/* Minimum fee floor: 100 sat/kvB = 0.1 sat/vB.
   Below this, Bitcoin Core won't relay even with lowered minrelaytxfee. */
#define FEE_FLOOR_SAT_PER_KVB  100

#endif /* SUPERSCALAR_FEE_H */
