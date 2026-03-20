/*
 * mission_control.c — Payment failure channel scoring (LDK-style)
 *
 * Reference: LDK lightning/src/routing/scoring.rs, LND routing/mc_store.go
 */

#include "superscalar/mission_control.h"
#include <string.h>
#include <stdint.h>

/* ---- Internal helpers ---- */

static mc_entry_t *find_entry(mc_table_t *mc, uint64_t scid, int direction)
{
    for (int i = 0; i < mc->count; i++) {
        if (mc->entries[i].scid == scid &&
            mc->entries[i].direction == direction)
            return &mc->entries[i];
    }
    return NULL;
}

/* Evict oldest failure (lowest fail_time) to make room */
static void evict_oldest(mc_table_t *mc)
{
    if (mc->count == 0) return;
    int oldest = 0;
    for (int i = 1; i < mc->count; i++) {
        if (mc->entries[i].fail_time < mc->entries[oldest].fail_time)
            oldest = i;
    }
    /* Shift remaining entries down */
    for (int i = oldest; i < mc->count - 1; i++)
        mc->entries[i] = mc->entries[i + 1];
    mc->count--;
}

/* ---- Public API ---- */

void mc_init(mc_table_t *mc)
{
    if (!mc) return;
    memset(mc, 0, sizeof(*mc));
}

void mc_record_failure(mc_table_t *mc, uint64_t scid, int direction,
                       uint64_t amount_msat, uint32_t now_unix)
{
    if (!mc) return;
    mc_entry_t *e = find_entry(mc, scid, direction);
    if (!e) {
        if (mc->count >= MC_MAX_ENTRIES)
            evict_oldest(mc);
        e = &mc->entries[mc->count++];
        memset(e, 0, sizeof(*e));
        e->scid      = scid;
        e->direction = direction;
    }
    e->fail_time    = now_unix;
    e->fail_count  += 1;
    /* Track the minimum failing amount */
    if (e->min_fail_msat == 0 || amount_msat < e->min_fail_msat)
        e->min_fail_msat = amount_msat;
}

void mc_record_success(mc_table_t *mc, uint64_t scid, int direction,
                       uint64_t amount_msat, uint32_t now_unix)
{
    if (!mc) return;
    mc_entry_t *e = find_entry(mc, scid, direction);
    if (!e) {
        /* No prior failure entry: create one to track success */
        if (mc->count >= MC_MAX_ENTRIES) return;
        e = &mc->entries[mc->count++];
        memset(e, 0, sizeof(*e));
        e->scid      = scid;
        e->direction = direction;
    }
    (void)amount_msat;
    e->success_time = now_unix;
    e->fail_count   = 0;
    /* Reset min_fail_msat so future failures start fresh */
    e->min_fail_msat = 0;
}

int mc_is_penalized(const mc_table_t *mc, uint64_t scid, int direction,
                    uint64_t amount_msat, uint32_t now_unix)
{
    if (!mc) return 0;
    const mc_entry_t *e = mc_find(mc, scid, direction);
    if (!e) return 0;
    if (e->fail_count == 0) return 0;
    /* No failure within decay window */
    if (now_unix >= e->fail_time &&
        (now_unix - e->fail_time) >= MC_DECAY_SECS) return 0;
    /* Success after last failure clears penalty */
    if (e->success_time > e->fail_time) return 0;
    /* Only penalize if amount is >= the failed amount */
    if (amount_msat < e->min_fail_msat) return 0;
    return 1;
}

uint64_t mc_get_penalty_msat(const mc_table_t *mc, uint64_t scid, int direction,
                              uint64_t amount_msat, uint32_t now_unix)
{
    if (!mc) return 0;
    const mc_entry_t *e = mc_find(mc, scid, direction);
    if (!e || e->fail_count == 0) return 0;
    if (e->success_time > e->fail_time) return 0;
    if (now_unix < e->fail_time) return 0;

    uint32_t age = now_unix - e->fail_time;
    if (age >= MC_DECAY_SECS) return 0;
    if (amount_msat < e->min_fail_msat) return 0;

    /* Linear decay: penalty = BASE * (1 - age/DECAY) * fail_count_factor */
    uint64_t base = (uint64_t)MC_BASE_PENALTY * e->fail_count;
    if (base > MC_MAX_PENALTY) base = MC_MAX_PENALTY;

    /* Remaining fraction: (DECAY - age) / DECAY */
    uint64_t penalty = base * (MC_DECAY_SECS - age) / MC_DECAY_SECS;
    return penalty;
}

int mc_prune_stale(mc_table_t *mc, uint32_t now_unix)
{
    if (!mc) return 0;
    int removed = 0;
    int i = 0;
    while (i < mc->count) {
        mc_entry_t *e = &mc->entries[i];
        int expired = (now_unix >= e->fail_time) &&
                      ((now_unix - e->fail_time) >= MC_DECAY_SECS);
        /* Prune if: expired AND no success after failure (or no success ever) */
        if (expired && (e->success_time <= e->fail_time)) {
            for (int j = i; j < mc->count - 1; j++)
                mc->entries[j] = mc->entries[j + 1];
            mc->count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

const mc_entry_t *mc_find(const mc_table_t *mc, uint64_t scid, int direction)
{
    if (!mc) return NULL;
    for (int i = 0; i < mc->count; i++) {
        if (mc->entries[i].scid == scid &&
            mc->entries[i].direction == direction)
            return &mc->entries[i];
    }
    return NULL;
}
