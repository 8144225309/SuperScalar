#ifndef SUPERSCALAR_MISSION_CONTROL_H
#define SUPERSCALAR_MISSION_CONTROL_H

/*
 * mission_control.h — Payment failure channel scoring
 *
 * Tracks per-channel-direction failure history and applies time-decayed
 * penalties to channels that have recently caused payment failures.
 * Pathfinder uses these penalties to exclude recently-failed hops during
 * payment retry.
 *
 * Design follows LDK's MissionControl / ProbabilisticScorer:
 *   - Channel pairs scored by (scid, direction)
 *   - Failure records include the amount that failed
 *   - Penalty decays exponentially over MC_DECAY_SECS (1 hour)
 *   - Success resets the failure score for that direction
 *   - Amount-awareness: penalty only applies if amount >= min_fail_msat
 *
 * Reference:
 *   LDK: lightning/src/routing/scoring.rs (ProbabilisticScorer)
 *   CLN: plugins/askrene/flow.c (channel capacity penalties)
 *   LND: routing/mc_store.go (MissionControl)
 */

#include <stdint.h>
#include <stddef.h>

#define MC_MAX_ENTRIES      256   /* max tracked channel-direction pairs */
#define MC_DECAY_SECS      3600u  /* 1-hour penalty half-life (LDK default) */
#define MC_BASE_PENALTY    1000u  /* base msat penalty at t=0 (proportional decay) */
#define MC_MAX_PENALTY  1000000u  /* cap at 1000 sat (prevent runaway exclusion) */

typedef struct {
    uint64_t scid;              /* short channel ID */
    int      direction;         /* 0 or 1 */
    uint64_t min_fail_msat;     /* smallest amount that was seen to fail */
    uint32_t fail_time;         /* Unix timestamp of last failure */
    uint32_t success_time;      /* Unix timestamp of last success (0 if none) */
    int      fail_count;        /* number of consecutive failures */
} mc_entry_t;

typedef struct {
    mc_entry_t entries[MC_MAX_ENTRIES];
    int        count;
} mc_table_t;

/* Initialise an empty mission-control table. */
void mc_init(mc_table_t *mc);

/*
 * Record a payment failure on (scid, direction) for amount_msat.
 * Increments fail_count; sets fail_time = now_unix; updates min_fail_msat.
 * If the table is full, evicts the oldest failure entry.
 */
void mc_record_failure(mc_table_t *mc, uint64_t scid, int direction,
                       uint64_t amount_msat, uint32_t now_unix);

/*
 * Record a successful payment through (scid, direction) for amount_msat.
 * Resets fail_count to 0 and updates success_time.
 */
void mc_record_success(mc_table_t *mc, uint64_t scid, int direction,
                       uint64_t amount_msat, uint32_t now_unix);

/*
 * Returns 1 if the channel pair should be avoided for routing amount_msat:
 *   - A failure was recorded within MC_DECAY_SECS
 *   - AND amount_msat >= the recorded min_fail_msat
 *   - AND no success after the last failure
 *
 * Returns 0 if the channel is considered usable.
 */
int mc_is_penalized(const mc_table_t *mc, uint64_t scid, int direction,
                    uint64_t amount_msat, uint32_t now_unix);

/*
 * Returns the penalty in msat to add to the channel's routing cost.
 * Penalty decays linearly from MC_BASE_PENALTY at fail_time to 0 at
 * fail_time + MC_DECAY_SECS.  Returns 0 for unknown or expired channels.
 * Only applies if amount_msat >= min_fail_msat.
 */
uint64_t mc_get_penalty_msat(const mc_table_t *mc, uint64_t scid, int direction,
                              uint64_t amount_msat, uint32_t now_unix);

/*
 * Remove all entries where the failure is older than MC_DECAY_SECS
 * AND there has been no subsequent success.
 * Returns count of entries removed.
 */
int mc_prune_stale(mc_table_t *mc, uint32_t now_unix);

/*
 * Find an entry by (scid, direction). Returns pointer or NULL.
 * Const accessor — does not modify the table.
 */
const mc_entry_t *mc_find(const mc_table_t *mc, uint64_t scid, int direction);

#endif /* SUPERSCALAR_MISSION_CONTROL_H */
