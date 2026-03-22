#ifndef SUPERSCALAR_PATHFIND_EXCLUDE_H
#define SUPERSCALAR_PATHFIND_EXCLUDE_H

/*
 * pathfind_exclude.h — Channel exclusion list for payment routing retry
 *
 * Maintains a short-lived set of channels to skip during route computation.
 * Used by the payment retry loop: when a payment fails, the failing channel
 * is added to the exclusion list so the next pathfind attempt avoids it.
 *
 * Integration with mission_control:
 *   pathfind_exclude_from_mc() populates the exclusion list from all
 *   currently-penalised entries in a mission_control table, enabling the
 *   router to avoid channels that historically fail for the payment amount.
 *
 * Reference:
 *   LDK: lightning/src/routing/router.rs PaymentParameters::previously_failed_channels
 *   CLN: plugins/askrene/askrene.c (exclude_list)
 *   LND: routing/pathfind.go RestrictParams.FailedEdges
 */

#include <stdint.h>
#include <stddef.h>
#include "mission_control.h"

/* Maximum exclusion entries.  Payment retries rarely need more than ~32. */
#define PATHFIND_EXCLUDE_MAX  64

/*
 * A single channel-direction exclusion.
 *
 * direction:  0 = forward (node1→node2)
 *             1 = reverse (node2→node1)
 *            -1 = both directions (e.g. channel fully disabled)
 */
typedef struct {
    uint64_t scid;
    int      direction;
} pathfind_exclude_entry_t;

typedef struct {
    pathfind_exclude_entry_t entries[PATHFIND_EXCLUDE_MAX];
    int count;
} pathfind_exclude_t;

/* Initialise an empty exclusion list. */
void pathfind_exclude_init(pathfind_exclude_t *ex);

/*
 * Add a channel-direction pair to the exclusion list.
 * If the same (scid, direction) is already present, does nothing.
 * If the list is full, the entry with the lowest scid is evicted.
 * Returns 1 on success, 0 on error.
 */
int pathfind_exclude_add(pathfind_exclude_t *ex, uint64_t scid, int direction);

/*
 * Remove a specific (scid, direction) pair from the exclusion list.
 * direction == -1 removes all entries for that scid.
 * Returns 1 if something was removed, 0 if not found.
 */
int pathfind_exclude_remove(pathfind_exclude_t *ex, uint64_t scid, int direction);

/*
 * Check whether a given (scid, direction) is currently excluded.
 * Returns 1 if the hop is excluded (should not be used for routing).
 *
 * A hop is excluded if:
 *   - an exact match (scid, direction) exists, OR
 *   - an entry (scid, -1) exists (both directions excluded).
 */
int pathfind_exclude_is_excluded(const pathfind_exclude_t *ex,
                                  uint64_t scid, int direction);

/*
 * Remove all entries from the exclusion list.
 */
void pathfind_exclude_clear(pathfind_exclude_t *ex);

/*
 * Populate the exclusion list from a mission_control table.
 *
 * For each mc_table entry that is currently penalised for amount_msat
 * (mc_is_penalized(mc, scid, direction, amount_msat, now) returns non-zero),
 * adds (scid, direction) to the exclusion list.
 *
 * Does NOT clear the existing exclusion list first; caller should call
 * pathfind_exclude_clear() before this if a clean repopulation is desired.
 *
 * Returns the number of new entries added.
 */
int pathfind_exclude_from_mc(pathfind_exclude_t *ex,
                               mc_table_t         *mc,
                               uint64_t            amount_msat,
                               uint32_t            now_unix);

/*
 * Return the number of entries currently in the exclusion list.
 */
int pathfind_exclude_count(const pathfind_exclude_t *ex);

#endif /* SUPERSCALAR_PATHFIND_EXCLUDE_H */
