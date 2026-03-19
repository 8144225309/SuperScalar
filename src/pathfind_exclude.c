/*
 * pathfind_exclude.c — Channel exclusion list for payment routing retry
 */

#include "superscalar/pathfind_exclude.h"
#include <string.h>

void pathfind_exclude_init(pathfind_exclude_t *ex)
{
    if (!ex) return;
    memset(ex, 0, sizeof(*ex));
}

int pathfind_exclude_add(pathfind_exclude_t *ex, uint64_t scid, int direction)
{
    if (!ex) return 0;

    /* Check for duplicate */
    for (int i = 0; i < ex->count; i++) {
        if (ex->entries[i].scid == scid &&
            ex->entries[i].direction == direction)
            return 1; /* already present */
    }

    if (ex->count < PATHFIND_EXCLUDE_MAX) {
        ex->entries[ex->count].scid      = scid;
        ex->entries[ex->count].direction = direction;
        ex->count++;
        return 1;
    }

    /* Table full — evict entry with lowest scid */
    int victim = 0;
    for (int i = 1; i < ex->count; i++) {
        if (ex->entries[i].scid < ex->entries[victim].scid)
            victim = i;
    }
    ex->entries[victim].scid      = scid;
    ex->entries[victim].direction = direction;
    return 1;
}

int pathfind_exclude_remove(pathfind_exclude_t *ex, uint64_t scid, int direction)
{
    if (!ex) return 0;
    int removed = 0;
    int i = 0;
    while (i < ex->count) {
        int match = (ex->entries[i].scid == scid) &&
                    (direction == -1 || ex->entries[i].direction == direction);
        if (match) {
            /* Shift remaining entries left */
            for (int j = i; j < ex->count - 1; j++)
                ex->entries[j] = ex->entries[j + 1];
            ex->count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

int pathfind_exclude_is_excluded(const pathfind_exclude_t *ex,
                                  uint64_t scid, int direction)
{
    if (!ex) return 0;
    for (int i = 0; i < ex->count; i++) {
        if (ex->entries[i].scid != scid) continue;
        /* Match if direction == -1 (both) OR exact direction match */
        if (ex->entries[i].direction == -1 ||
            ex->entries[i].direction == direction)
            return 1;
    }
    return 0;
}

void pathfind_exclude_clear(pathfind_exclude_t *ex)
{
    if (!ex) return;
    ex->count = 0;
}

int pathfind_exclude_from_mc(pathfind_exclude_t *ex,
                               mc_table_t         *mc,
                               uint64_t            amount_msat,
                               uint32_t            now_unix)
{
    if (!ex || !mc) return 0;
    int added = 0;
    for (int i = 0; i < mc->count; i++) {
        const mc_entry_t *e = &mc->entries[i];
        if (mc_is_penalized(mc, e->scid, e->direction, amount_msat, now_unix)) {
            if (pathfind_exclude_add(ex, e->scid, e->direction))
                added++;
        }
    }
    return added;
}

int pathfind_exclude_count(const pathfind_exclude_t *ex)
{
    if (!ex) return 0;
    return ex->count;
}
