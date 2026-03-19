/*
 * rgs.c — Rapid Gossip Sync compact gossip format.
 *
 * Reference: LDK lightning/src/routing/gossip.rs (RapidGossipSync),
 *            lightning-rapid-gossip-sync crate
 */

#include "superscalar/rgs.h"
#include <string.h>
#include <stdint.h>

/* ---- BE reader helpers ---- */

static uint16_t r16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t r32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | b[3];
}
static uint64_t r64(const unsigned char *b) {
    return ((uint64_t)r32(b) << 32) | r32(b + 4);
}
static uint32_t r24(const unsigned char *b) {
    return ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
}

/* ---- BE writer helpers ---- */
static void w16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8); b[1] = (unsigned char)v;
}
static void w32(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >> 8);  b[3] = (unsigned char)v;
}
static void w64(unsigned char *b, uint64_t v) {
    w32(b, (uint32_t)(v >> 32)); w32(b + 4, (uint32_t)v);
}
static void w24(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 16); b[1] = (unsigned char)(v >> 8);
    b[2] = (unsigned char)v;
}

/* ---- Parse ---- */

int rgs_parse(const unsigned char *blob, size_t blob_len,
               rgs_snapshot_t *snap,
               rgs_node_id_t *node_buf, uint32_t node_cap,
               rgs_channel_t *chan_buf, uint32_t chan_cap)
{
    if (!blob || !snap || blob_len < (size_t)(RGS_MAGIC_LEN + 4)) return 0;

    /* Check magic */
    if (memcmp(blob, RGS_MAGIC, RGS_MAGIC_LEN) != 0) return 0;

    size_t p = RGS_MAGIC_LEN;

    /* last_sync_timestamp (4 bytes) */
    if (p + 4 > blob_len) return 0;
    snap->last_sync_timestamp = r32(blob + p); p += 4;

    /* node_id_count (3 bytes) */
    if (p + 3 > blob_len) return 0;
    snap->node_id_count = r24(blob + p); p += 3;
    if (snap->node_id_count > node_cap) return 0;

    /* node_ids */
    if (p + snap->node_id_count * 33 > blob_len) return 0;
    for (uint32_t i = 0; i < snap->node_id_count; i++) {
        memcpy(node_buf[i].pubkey, blob + p, 33); p += 33;
    }
    snap->node_ids = node_buf;

    /* channel_count (4 bytes) */
    if (p + 4 > blob_len) return 0;
    snap->channel_count = r32(blob + p); p += 4;
    if (snap->channel_count > chan_cap) return 0;

    /* channels */
    for (uint32_t c = 0; c < snap->channel_count; c++) {
        rgs_channel_t *ch = &chan_buf[c];
        memset(ch, 0, sizeof(*ch));

        /* scid (8), features (2), n1_idx (3), n2_idx (3), funding (8) = 24 */
        if (p + 24 > blob_len) return 0;
        ch->short_channel_id  = r64(blob + p); p += 8;
        ch->features          = r16(blob + p); p += 2;
        ch->node_id_1_idx     = r24(blob + p); p += 3;
        ch->node_id_2_idx     = r24(blob + p); p += 3;
        ch->funding_satoshis  = r64(blob + p); p += 8;

        /* update_count (1 byte) */
        if (p + 1 > blob_len) return 0;
        ch->update_count = (int)(blob[p++]);
        if (ch->update_count > RGS_MAX_UPDATES_PER_CHAN) return 0;

        for (int u = 0; u < ch->update_count; u++) {
            rgs_channel_update_t *upd = &ch->updates[u];
            /* direction(1) + cltv(2) + min(8) + max(8) + base(4) + ppm(4) + flags(2) + ts(4) = 33 */
            if (p + 33 > blob_len) return 0;
            upd->direction                  = (int)(blob[p++]);
            upd->cltv_expiry_delta          = r16(blob + p); p += 2;
            upd->htlc_minimum_msat          = r64(blob + p); p += 8;
            upd->htlc_maximum_msat          = r64(blob + p); p += 8;
            upd->fee_base_msat              = r32(blob + p); p += 4;
            upd->fee_proportional_millionths= r32(blob + p); p += 4;
            upd->flags                      = r16(blob + p); p += 2;
            upd->timestamp                  = r32(blob + p); p += 4;
        }
    }
    snap->channels = chan_buf;
    return 1;
}

/* ---- Build ---- */

size_t rgs_build(const rgs_snapshot_t *snap,
                  const rgs_node_id_t *node_ids,
                  const rgs_channel_t *channels,
                  unsigned char *out, size_t out_cap)
{
    if (!snap || !out || out_cap < 16) return 0;

    size_t p = 0;

    /* Magic */
    if (p + RGS_MAGIC_LEN > out_cap) return 0;
    memcpy(out + p, RGS_MAGIC, RGS_MAGIC_LEN); p += RGS_MAGIC_LEN;

    /* last_sync_timestamp */
    if (p + 4 > out_cap) return 0;
    w32(out + p, snap->last_sync_timestamp); p += 4;

    /* node_id_count (3 bytes) */
    if (p + 3 > out_cap) return 0;
    w24(out + p, snap->node_id_count); p += 3;

    /* node_ids */
    if (p + snap->node_id_count * 33 > out_cap) return 0;
    for (uint32_t i = 0; i < snap->node_id_count; i++) {
        memcpy(out + p, node_ids[i].pubkey, 33); p += 33;
    }

    /* channel_count */
    if (p + 4 > out_cap) return 0;
    w32(out + p, snap->channel_count); p += 4;

    /* channels */
    for (uint32_t c = 0; c < snap->channel_count; c++) {
        const rgs_channel_t *ch = &channels[c];
        if (p + 24 + 1 > out_cap) return 0;
        w64(out + p, ch->short_channel_id); p += 8;
        w16(out + p, ch->features);         p += 2;
        w24(out + p, ch->node_id_1_idx);    p += 3;
        w24(out + p, ch->node_id_2_idx);    p += 3;
        w64(out + p, ch->funding_satoshis); p += 8;
        out[p++] = (unsigned char)ch->update_count;

        for (int u = 0; u < ch->update_count; u++) {
            const rgs_channel_update_t *upd = &ch->updates[u];
            if (p + 33 > out_cap) return 0;
            out[p++] = (unsigned char)upd->direction;
            w16(out + p, upd->cltv_expiry_delta);           p += 2;
            w64(out + p, upd->htlc_minimum_msat);           p += 8;
            w64(out + p, upd->htlc_maximum_msat);           p += 8;
            w32(out + p, upd->fee_base_msat);               p += 4;
            w32(out + p, upd->fee_proportional_millionths); p += 4;
            w16(out + p, upd->flags);                       p += 2;
            w32(out + p, upd->timestamp);                   p += 4;
        }
    }
    return p;
}

/* ---- Query helpers ---- */

const rgs_channel_t *rgs_find_channel(const rgs_snapshot_t *snap,
                                       const rgs_channel_t *channels,
                                       uint64_t scid)
{
    if (!snap || !channels) return NULL;
    for (uint32_t i = 0; i < snap->channel_count; i++) {
        if (channels[i].short_channel_id == scid)
            return &channels[i];
    }
    return NULL;
}

const rgs_channel_update_t *rgs_get_update(const rgs_channel_t *chan, int direction)
{
    if (!chan) return NULL;
    for (int u = 0; u < chan->update_count; u++) {
        if (chan->updates[u].direction == direction) {
            /* Check not disabled */
            if (chan->updates[u].flags & 1) return NULL;
            return &chan->updates[u];
        }
    }
    return NULL;
}

uint32_t rgs_count_active_channels(const rgs_snapshot_t *snap,
                                    const rgs_channel_t *channels)
{
    if (!snap || !channels) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < snap->channel_count; i++) {
        const rgs_channel_t *ch = &channels[i];
        for (int u = 0; u < ch->update_count; u++) {
            if (!(ch->updates[u].flags & 1)) { count++; break; }
        }
    }
    return count;
}
