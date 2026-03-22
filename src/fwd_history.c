/*
 * fwd_history.c — HTLC forwarding history and channel statistics
 *
 * Reference: CLN forwarding.c, LND routing/payment_lifecycle.go
 */

#include "superscalar/fwd_history.h"
#include <string.h>
#include <stdint.h>

void fwd_history_init(fwd_history_t *h)
{
    if (!h) return;
    memset(h, 0, sizeof(*h));
}

void fwd_history_add(fwd_history_t *h,
                     uint64_t scid_in, uint64_t scid_out,
                     uint64_t in_amount_msat, uint64_t out_amount_msat,
                     uint32_t resolved_at,
                     const unsigned char payment_hash[32],
                     fwd_status_t status)
{
    if (!h) return;

    fwd_history_entry_t *e = &h->entries[h->head];
    e->scid_in        = scid_in;
    e->scid_out       = scid_out;
    e->in_amount_msat = in_amount_msat;
    e->out_amount_msat= out_amount_msat;
    e->fee_msat       = (in_amount_msat > out_amount_msat)
                        ? (in_amount_msat - out_amount_msat) : 0;
    e->resolved_at    = resolved_at;
    e->status         = status;
    if (payment_hash)
        memcpy(e->payment_hash, payment_hash, 32);
    else
        memset(e->payment_hash, 0, 32);

    h->head = (h->head + 1) % FWD_HISTORY_MAX;
    if (h->count < FWD_HISTORY_MAX) h->count++;

    if (status == FWD_STATUS_SETTLED) h->total_settled++;
    else if (status == FWD_STATUS_FAILED) h->total_failed++;
}

static int in_range(uint32_t t, uint32_t since, uint32_t until) {
    if (since > 0 && t < since) return 0;
    if (until > 0 && t > until) return 0;
    return 1;
}

uint64_t fwd_history_fee_total(const fwd_history_t *h,
                                uint32_t since, uint32_t until)
{
    if (!h) return 0;
    uint64_t total = 0;
    for (int i = 0; i < h->count; i++) {
        const fwd_history_entry_t *e = &h->entries[i];
        if (e->status != FWD_STATUS_SETTLED) continue;
        if (!in_range(e->resolved_at, since, until)) continue;
        total += e->fee_msat;
    }
    return total;
}

uint64_t fwd_history_volume(const fwd_history_t *h,
                              uint64_t scid_out,
                              uint32_t since, uint32_t until)
{
    if (!h) return 0;
    uint64_t total = 0;
    for (int i = 0; i < h->count; i++) {
        const fwd_history_entry_t *e = &h->entries[i];
        if (e->status != FWD_STATUS_SETTLED) continue;
        if (scid_out != 0 && e->scid_out != scid_out) continue;
        if (!in_range(e->resolved_at, since, until)) continue;
        total += e->out_amount_msat;
    }
    return total;
}

int fwd_history_count(const fwd_history_t *h,
                       uint64_t scid_in,
                       uint32_t since, uint32_t until)
{
    if (!h) return 0;
    int cnt = 0;
    for (int i = 0; i < h->count; i++) {
        const fwd_history_entry_t *e = &h->entries[i];
        if (e->status != FWD_STATUS_SETTLED) continue;
        if (scid_in != 0 && e->scid_in != scid_in) continue;
        if (!in_range(e->resolved_at, since, until)) continue;
        cnt++;
    }
    return cnt;
}

uint64_t fwd_history_avg_fee(const fwd_history_t *h,
                              uint32_t since, uint32_t until)
{
    if (!h) return 0;
    uint64_t total_fee = 0;
    int cnt = 0;
    for (int i = 0; i < h->count; i++) {
        const fwd_history_entry_t *e = &h->entries[i];
        if (e->status != FWD_STATUS_SETTLED) continue;
        if (!in_range(e->resolved_at, since, until)) continue;
        total_fee += e->fee_msat;
        cnt++;
    }
    return (cnt > 0) ? (total_fee / cnt) : 0;
}

uint64_t fwd_history_top_channel(const fwd_history_t *h,
                                  uint32_t since, uint32_t until,
                                  uint64_t *scid_in_out,
                                  uint64_t *scid_out_out)
{
    if (!h || !scid_in_out || !scid_out_out) return 0;
    *scid_in_out = 0;
    *scid_out_out = 0;

    /* Find all unique (scid_in, scid_out) pairs and their total fees */
    struct { uint64_t in, out, fee; } pairs[64];
    int n_pairs = 0;

    for (int i = 0; i < h->count; i++) {
        const fwd_history_entry_t *e = &h->entries[i];
        if (e->status != FWD_STATUS_SETTLED) continue;
        if (!in_range(e->resolved_at, since, until)) continue;

        /* Find existing pair */
        int found = 0;
        for (int j = 0; j < n_pairs; j++) {
            if (pairs[j].in == e->scid_in && pairs[j].out == e->scid_out) {
                pairs[j].fee += e->fee_msat;
                found = 1;
                break;
            }
        }
        if (!found && n_pairs < 64) {
            pairs[n_pairs].in  = e->scid_in;
            pairs[n_pairs].out = e->scid_out;
            pairs[n_pairs].fee = e->fee_msat;
            n_pairs++;
        }
    }

    uint64_t best = 0;
    for (int i = 0; i < n_pairs; i++) {
        if (pairs[i].fee > best) {
            best = pairs[i].fee;
            *scid_in_out  = pairs[i].in;
            *scid_out_out = pairs[i].out;
        }
    }
    return best;
}

int fwd_history_prune(fwd_history_t *h, uint32_t cutoff_unix)
{
    if (!h) return 0;
    int removed = 0;
    int i = 0;
    while (i < h->count) {
        fwd_history_entry_t *e = &h->entries[i];
        if (e->resolved_at < cutoff_unix && e->resolved_at > 0) {
            /* Shift entries down — simple linear remove for correctness */
            for (int j = i; j < h->count - 1; j++)
                h->entries[j] = h->entries[j + 1];
            h->count--;
            /* Also move head back */
            h->head = (h->head > 0) ? h->head - 1 : 0;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}
