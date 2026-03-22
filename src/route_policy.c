/*
 * route_policy.c — Per-channel HTLC forwarding policy enforcement
 *
 * Reference: BOLT #7 §channel_update, BOLT #4 §forwarding-htlcs
 */

#include "superscalar/route_policy.h"
#include <string.h>
#include <stdint.h>

/* ---- Wire helpers ---- */

static void put_u16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8); b[1] = (unsigned char)v;
}
static void put_u32(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >> 8);  b[3] = (unsigned char)v;
}
static void put_u64(unsigned char *b, uint64_t v) {
    put_u32(b, (uint32_t)(v >> 32));
    put_u32(b + 4, (uint32_t)v);
}

static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t get_u32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | b[3];
}
static uint64_t get_u64(const unsigned char *b) {
    return ((uint64_t)get_u32(b) << 32) | get_u32(b + 4);
}

/* ---- Fee computation ---- */

uint64_t route_policy_compute_fee(const route_policy_t *policy,
                                   uint64_t out_amount_msat)
{
    if (!policy) return 0;
    /* fee = base + ceil(out_amount * ppm / 1_000_000) */
    uint64_t prop = ((__uint128_t)out_amount_msat * policy->fee_ppm + 999999) / 1000000;
    return (uint64_t)policy->fee_base_msat + prop;
}

/* ---- Policy check ---- */

int route_policy_check(const route_policy_t *policy,
                       uint64_t in_amount_msat,
                       uint64_t out_amount_msat,
                       uint32_t in_cltv,
                       uint32_t out_cltv,
                       uint32_t chain_height)
{
    if (!policy) return POLICY_FEE_INSUFFICIENT; /* safe default */

    if (out_amount_msat == 0) return POLICY_AMOUNT_ZERO;

    if (policy->disabled) return POLICY_CHANNEL_DISABLED;

    /* HTLC minimum */
    if (policy->htlc_minimum_msat > 0 &&
        out_amount_msat < policy->htlc_minimum_msat)
        return POLICY_HTLC_TOO_SMALL;

    /* HTLC maximum */
    if (policy->htlc_maximum_msat > 0 &&
        out_amount_msat > policy->htlc_maximum_msat)
        return POLICY_HTLC_TOO_LARGE;

    /* Fee check: in_amount must cover out_amount + required fee */
    uint64_t required_fee = route_policy_compute_fee(policy, out_amount_msat);
    if (in_amount_msat < out_amount_msat + required_fee)
        return POLICY_FEE_INSUFFICIENT;

    /* CLTV delta: in_cltv - out_cltv must be >= cltv_expiry_delta */
    if (in_cltv < out_cltv) return POLICY_CLTV_TOO_SMALL;
    uint32_t cltv_diff = in_cltv - out_cltv;
    if (cltv_diff < policy->cltv_expiry_delta) return POLICY_CLTV_TOO_SMALL;

    /* Expiry too soon: out_cltv must be far enough from chain tip */
    if (chain_height > 0 && out_cltv <= chain_height + POLICY_MIN_FINAL_CLTV_DELTA)
        return POLICY_EXPIRY_TOO_SOON;

    return POLICY_OK;
}

/* ---- Wire encode ---- */

/*
 * channel_update (type 258) layout:
 *   type(2) + sig(64) + chain_hash(32) + scid(8) + timestamp(4)
 *   + message_flags(1) + channel_flags(1) + cltv_expiry_delta(2)
 *   + htlc_minimum_msat(8) + fee_base_msat(4) + fee_ppm(4)
 *   [+ htlc_maximum_msat(8)]  ← if message_flags bit 0 set
 */
size_t route_policy_build_channel_update(const route_policy_t *policy,
                                          const unsigned char sig[64],
                                          const unsigned char chain_hash[32],
                                          uint32_t timestamp,
                                          unsigned char *buf, size_t buf_cap)
{
    if (!policy || !sig || !chain_hash || !buf) return 0;

    int has_htlc_max = (policy->htlc_maximum_msat > 0);
    size_t total = 2 + 64 + 32 + 8 + 4 + 1 + 1 + 2 + 8 + 4 + 4;
    if (has_htlc_max) total += 8;
    if (buf_cap < total) return 0;

    size_t p = 0;
    put_u16(buf + p, 258); p += 2;             /* type */
    memcpy(buf + p, sig, 64); p += 64;          /* sig */
    memcpy(buf + p, chain_hash, 32); p += 32;   /* chain_hash */
    put_u64(buf + p, (uint64_t)policy->scid); p += 8; /* scid */
    put_u32(buf + p, timestamp); p += 4;        /* timestamp */

    /* message_flags: bit 0 = htlc_maximum_msat present */
    buf[p++] = (unsigned char)(has_htlc_max ? POLICY_FLAG_HTLC_MAX_SET : 0);

    /* channel_flags: bit 0 = direction, bit 1 = disabled */
    uint8_t chan_flags = (uint8_t)(policy->direction & 1);
    if (policy->disabled) chan_flags |= 0x02;
    buf[p++] = chan_flags;

    put_u16(buf + p, policy->cltv_expiry_delta); p += 2;
    put_u64(buf + p, policy->htlc_minimum_msat); p += 8;
    put_u32(buf + p, policy->fee_base_msat); p += 4;
    put_u32(buf + p, policy->fee_ppm); p += 4;

    if (has_htlc_max) {
        put_u64(buf + p, policy->htlc_maximum_msat); p += 8;
    }
    return p;
}

/* ---- Wire decode ---- */

int route_policy_parse_channel_update(const unsigned char *msg, size_t msg_len,
                                       route_policy_t *out)
{
    if (!msg || !out) return 0;
    /* Minimum size: type(2)+sig(64)+chain(32)+scid(8)+ts(4)+mflags(1)+cflags(1)
     *               +cltv(2)+htlc_min(8)+fee_base(4)+fee_ppm(4) = 130 */
    if (msg_len < 130) return 0;

    uint16_t type = get_u16(msg);
    if (type != 258) return 0;

    size_t p = 2;
    /* Skip sig(64) */
    p += 64;
    /* Skip chain_hash(32) */
    p += 32;

    out->scid = get_u64(msg + p); p += 8;
    out->last_update = get_u32(msg + p); p += 4;

    uint8_t msg_flags  = msg[p++];
    uint8_t chan_flags = msg[p++];

    out->direction = (chan_flags & 1);
    out->disabled  = (chan_flags & 0x02) ? 1 : 0;

    out->cltv_expiry_delta  = get_u16(msg + p); p += 2;
    out->htlc_minimum_msat  = get_u64(msg + p); p += 8;
    out->fee_base_msat      = get_u32(msg + p); p += 4;
    out->fee_ppm            = get_u32(msg + p); p += 4;

    /* Optional htlc_maximum_msat */
    if ((msg_flags & POLICY_FLAG_HTLC_MAX_SET) && p + 8 <= msg_len) {
        out->htlc_maximum_msat = get_u64(msg + p); p += 8;
    } else {
        out->htlc_maximum_msat = 0;
    }

    return 1;
}

/* ---- Policy table ---- */

static int find_idx(route_policy_table_t *tbl, uint64_t scid, int direction)
{
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].scid == scid &&
            tbl->entries[i].direction == direction)
            return i;
    }
    return -1;
}

/* Evict oldest (lowest last_update) */
static void evict_oldest_policy(route_policy_table_t *tbl)
{
    if (tbl->count == 0) return;
    int oldest = 0;
    for (int i = 1; i < tbl->count; i++) {
        if (tbl->entries[i].last_update < tbl->entries[oldest].last_update)
            oldest = i;
    }
    for (int i = oldest; i < tbl->count - 1; i++)
        tbl->entries[i] = tbl->entries[i + 1];
    tbl->count--;
}

void route_policy_upsert(route_policy_table_t *tbl, const route_policy_t *policy)
{
    if (!tbl || !policy) return;
    int idx = find_idx(tbl, policy->scid, policy->direction);
    if (idx >= 0) {
        tbl->entries[idx] = *policy;
        return;
    }
    if (tbl->count >= POLICY_TABLE_MAX)
        evict_oldest_policy(tbl);
    tbl->entries[tbl->count++] = *policy;
}

const route_policy_t *route_policy_find(const route_policy_table_t *tbl,
                                         uint64_t scid, int direction)
{
    if (!tbl) return NULL;
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].scid == scid &&
            tbl->entries[i].direction == direction)
            return &tbl->entries[i];
    }
    return NULL;
}

int route_policy_set_disabled(route_policy_table_t *tbl,
                               uint64_t scid, int direction, int disabled)
{
    if (!tbl) return 0;
    int idx = find_idx(tbl, scid, direction);
    if (idx < 0) return 0;
    tbl->entries[idx].disabled = disabled;
    return 1;
}
