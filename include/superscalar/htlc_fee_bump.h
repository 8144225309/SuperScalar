#ifndef SUPERSCALAR_HTLC_FEE_BUMP_H
#define SUPERSCALAR_HTLC_FEE_BUMP_H

/*
 * htlc_fee_bump.h — Deadline-aware fee bumping for HTLC sweep transactions
 *
 * Implements the fee scheduling logic that LND calls "sweeper fee function":
 *   - Linear interpolation from start_feerate to budget-limited max feerate
 *     over the window [start_block, deadline_block]
 *   - Budget allocation: configurable fraction of HTLC value (LND default 50%)
 *   - RBF scheduling: bump when feerate would increase by ≥25% or when urgent
 *   - Urgency detection: deadline within HTLC_FEE_BUMP_URGENT_BLOCKS blocks
 *
 * Fee function (LND-compatible):
 *   start_feerate  — sat/kvB at start_block
 *   max_feerate    = budget_sat * 1000 / tx_vsize  — sat/kvB at deadline_block
 *   feerate(h)     = start_feerate
 *                    + (h - start_block) * (max_feerate - start_feerate)
 *                      / (deadline_block - start_block)
 *   Clamped to [start_feerate, max_feerate].
 *
 * Reference:
 *   LND: sweep/sweeper.go, sweep/fee_function.go (LinearFeeFunction)
 *   LND: lnwallet/channel.go (sweeper budget allocation, 50% HTLC default)
 *   BOLT #2: §force close, §HTLC timeout/success, §minimum CLTV delta (18)
 */

#include <stdint.h>

/* Blocks from deadline at which we enter the urgent window (bump every block) */
#define HTLC_FEE_BUMP_URGENT_BLOCKS    6

/* Minimum fee increase required to attempt RBF (25% over last broadcast rate) */
#define HTLC_FEE_BUMP_RBF_PCT          25

/* Absolute floor fee rate: 250 sat/kvB = 0.25 sat/vB */
#define HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB  250

/* Default budget fraction: 50% of HTLC value (LND default) */
#define HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT  50

typedef struct {
    uint32_t start_block;      /* block when we first want to broadcast */
    uint32_t deadline_block;   /* CLTV expiry — absolute block height */
    uint64_t budget_sat;       /* maximum total fee we will spend */
    uint32_t tx_vsize;         /* virtual size of the sweep tx in vBytes */
    uint64_t start_feerate;    /* initial fee rate (sat/kvB) */
    uint64_t last_feerate;     /* fee rate of last broadcast (0 = never broadcast) */
    uint32_t last_bump_block;  /* block at which we last broadcast/bumped */
    int      confirmed;        /* 1 if the sweep tx confirmed on-chain */
    uint32_t confirm_block;    /* block at which it confirmed */
} htlc_fee_bump_t;

/*
 * Initialise a fee bump schedule.
 *
 * start_block:    block at which we will first broadcast (typically current height)
 * deadline_block: CLTV expiry block (must be > start_block)
 * htlc_value_sat: outgoing HTLC value in satoshis
 * budget_pct:     fraction of htlc_value_sat to allocate as budget (1–100)
 * tx_vsize:       virtual size of the transaction in vBytes (e.g. 180 for HTLC-timeout)
 * start_feerate:  initial fee rate in sat/kvB (must be ≥ HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB)
 *
 * Returns 1 on success, 0 on invalid parameters.
 */
int htlc_fee_bump_init(htlc_fee_bump_t *fb,
                        uint32_t start_block,
                        uint32_t deadline_block,
                        uint64_t htlc_value_sat,
                        int      budget_pct,
                        uint32_t tx_vsize,
                        uint64_t start_feerate);

/*
 * Compute the scheduled fee rate for the given block height.
 *
 * Uses the linear fee function: start_feerate → max_feerate over the
 * window [start_block, deadline_block].  Clamped to [start_feerate, max_feerate].
 * Returns HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB if fb is NULL or uninitialised.
 */
uint64_t htlc_fee_bump_calc_feerate(const htlc_fee_bump_t *fb,
                                     uint32_t current_block);

/*
 * Return the budget-limited maximum fee rate (sat/kvB).
 *
 *   max_feerate = (budget_sat * 1000) / tx_vsize
 */
uint64_t htlc_fee_bump_max_feerate(const htlc_fee_bump_t *fb);

/*
 * Returns 1 if we should broadcast or replace-by-fee right now.
 *
 * Bumps when:
 *   - Never broadcast before (last_feerate == 0)
 *   - In the urgent window (deadline within HTLC_FEE_BUMP_URGENT_BLOCKS)
 *   - Scheduled feerate has risen ≥ HTLC_FEE_BUMP_RBF_PCT% above last_feerate
 * Returns 0 if already confirmed or deadline has passed.
 */
int htlc_fee_bump_should_bump(const htlc_fee_bump_t *fb,
                               uint32_t current_block);

/*
 * Record a successful broadcast or RBF replacement at the given block.
 * Updates last_feerate and last_bump_block.
 */
void htlc_fee_bump_record_broadcast(htlc_fee_bump_t *fb,
                                     uint32_t block,
                                     uint64_t feerate_used);

/*
 * Mark the sweep transaction as confirmed at the given block height.
 */
void htlc_fee_bump_record_confirm(htlc_fee_bump_t *fb,
                                   uint32_t block);

/*
 * Returns 1 if the sweep transaction has been confirmed.
 */
int htlc_fee_bump_is_confirmed(const htlc_fee_bump_t *fb);

/*
 * Returns 1 if we are within HTLC_FEE_BUMP_URGENT_BLOCKS of the deadline.
 * Returns 0 if confirmed or past deadline.
 */
int htlc_fee_bump_is_urgent(const htlc_fee_bump_t *fb,
                              uint32_t current_block);

/*
 * Returns blocks remaining until the deadline (0 if at or past deadline).
 */
uint32_t htlc_fee_bump_blocks_remaining(const htlc_fee_bump_t *fb,
                                         uint32_t current_block);

/*
 * Returns 1 if the deadline has passed (current_block >= deadline_block)
 * and the tx has not confirmed.
 */
int htlc_fee_bump_is_expired(const htlc_fee_bump_t *fb,
                               uint32_t current_block);

/*
 * Compute the absolute fee in satoshis for a given fee rate and vsize.
 *   fee_sat = feerate_sat_per_kvb * tx_vsize / 1000
 * Minimum 1 sat.
 */
uint64_t htlc_fee_bump_fee_sat(uint64_t feerate_sat_per_kvb, uint32_t tx_vsize);

#endif /* SUPERSCALAR_HTLC_FEE_BUMP_H */
