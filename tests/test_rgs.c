/*
 * test_rgs.c — Tests for Rapid Gossip Sync compact gossip format.
 *
 * PR #39: RGS for fast routing table initialization (LDK/Zeus/Phoenix)
 */

#include "superscalar/rgs.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void make_pubkey(unsigned char pk[33], unsigned char seed)
{
    pk[0] = 0x02;
    memset(pk + 1, seed, 32);
}

/* Helper: build a simple RGS blob with known content */
static size_t build_test_blob(unsigned char *out, size_t cap,
                               uint32_t ts,
                               unsigned char pk1_seed, unsigned char pk2_seed,
                               uint64_t scid, uint64_t funding_sat,
                               int add_updates)
{
    rgs_node_id_t nodes[2];
    make_pubkey(nodes[0].pubkey, pk1_seed);
    make_pubkey(nodes[1].pubkey, pk2_seed);

    rgs_channel_t chan;
    memset(&chan, 0, sizeof(chan));
    chan.short_channel_id = scid;
    chan.features         = 0;
    chan.node_id_1_idx    = 0;
    chan.node_id_2_idx    = 1;
    chan.funding_satoshis = funding_sat;
    chan.update_count     = add_updates ? 2 : 0;

    if (add_updates) {
        chan.updates[0].direction                   = 0;
        chan.updates[0].cltv_expiry_delta            = 40;
        chan.updates[0].htlc_minimum_msat            = 1000;
        chan.updates[0].htlc_maximum_msat            = 100000000;
        chan.updates[0].fee_base_msat                = 1000;
        chan.updates[0].fee_proportional_millionths  = 100;
        chan.updates[0].flags                        = 0;  /* enabled */
        chan.updates[0].timestamp                    = ts;

        chan.updates[1].direction                   = 1;
        chan.updates[1].cltv_expiry_delta            = 40;
        chan.updates[1].htlc_minimum_msat            = 1000;
        chan.updates[1].htlc_maximum_msat            = 100000000;
        chan.updates[1].fee_base_msat                = 2000;
        chan.updates[1].fee_proportional_millionths  = 200;
        chan.updates[1].flags                        = 0;  /* enabled */
        chan.updates[1].timestamp                    = ts;
    }

    rgs_snapshot_t snap;
    snap.last_sync_timestamp = ts;
    snap.node_id_count       = 2;
    snap.channel_count       = 1;

    return rgs_build(&snap, nodes, &chan, out, cap);
}

/* RGS1: rgs_build + rgs_parse round-trip */
int test_rgs_roundtrip(void)
{
    unsigned char blob[4096];
    size_t len = build_test_blob(blob, sizeof(blob), 1700000000,
                                  0x11, 0x22, 0x0001020304050607ULL,
                                  1000000, 1);
    ASSERT(len > 0, "build ok");
    ASSERT(memcmp(blob, RGS_MAGIC, RGS_MAGIC_LEN) == 0, "magic ok");

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;

    ASSERT(rgs_parse(blob, len, &snap, nodes, 16, chans, 64), "parse ok");
    ASSERT(snap.last_sync_timestamp == 1700000000, "timestamp preserved");
    ASSERT(snap.node_id_count == 2, "2 nodes");
    ASSERT(snap.channel_count == 1, "1 channel");
    ASSERT(chans[0].short_channel_id == 0x0001020304050607ULL, "scid preserved");
    ASSERT(chans[0].funding_satoshis == 1000000, "funding preserved");
    ASSERT(chans[0].update_count == 2, "2 updates");

    /* Verify updates */
    ASSERT(chans[0].updates[0].direction == 0, "update0 direction=0");
    ASSERT(chans[0].updates[0].fee_base_msat == 1000, "fee_base ok");
    ASSERT(chans[0].updates[1].direction == 1, "update1 direction=1");
    ASSERT(chans[0].updates[1].fee_proportional_millionths == 200, "fee_ppm ok");
    return 1;
}

/* RGS2: node pubkeys preserved in round-trip */
int test_rgs_node_ids_preserved(void)
{
    unsigned char blob[4096];
    size_t len = build_test_blob(blob, sizeof(blob), 1234567890,
                                  0xAA, 0xBB, 12345678, 500000, 0);
    ASSERT(len > 0, "build ok");

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;
    ASSERT(rgs_parse(blob, len, &snap, nodes, 16, chans, 64), "parse ok");

    ASSERT(nodes[0].pubkey[0] == 0x02, "node0 compressed prefix");
    ASSERT(nodes[0].pubkey[1] == 0xAA, "node0 seed ok");
    ASSERT(nodes[1].pubkey[1] == 0xBB, "node1 seed ok");
    return 1;
}

/* RGS3: rgs_find_channel finds by SCID */
int test_rgs_find_channel(void)
{
    unsigned char blob[4096];
    size_t len = build_test_blob(blob, sizeof(blob), 1000, 0x11, 0x22, 999888777, 100000, 0);

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;
    ASSERT(rgs_parse(blob, len, &snap, nodes, 16, chans, 64), "parse ok");

    const rgs_channel_t *found = rgs_find_channel(&snap, chans, 999888777);
    ASSERT(found != NULL, "channel found");
    ASSERT(found->short_channel_id == 999888777, "correct scid");

    ASSERT(rgs_find_channel(&snap, chans, 999) == NULL, "unknown scid = NULL");
    ASSERT(rgs_find_channel(NULL, chans, 999888777) == NULL, "NULL snap = NULL");
    return 1;
}

/* RGS4: rgs_get_update returns correct direction */
int test_rgs_get_update(void)
{
    unsigned char blob[4096];
    size_t len = build_test_blob(blob, sizeof(blob), 2000, 0x33, 0x44, 42, 200000, 1);

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;
    ASSERT(rgs_parse(blob, len, &snap, nodes, 16, chans, 64), "parse ok");

    const rgs_channel_update_t *u0 = rgs_get_update(&chans[0], 0);
    ASSERT(u0 != NULL, "direction 0 update found");
    ASSERT(u0->fee_base_msat == 1000, "dir0 fee_base ok");

    const rgs_channel_update_t *u1 = rgs_get_update(&chans[0], 1);
    ASSERT(u1 != NULL, "direction 1 update found");
    ASSERT(u1->fee_base_msat == 2000, "dir1 fee_base ok");

    ASSERT(rgs_get_update(NULL, 0) == NULL, "NULL chan = NULL");
    return 1;
}

/* RGS5: disabled channel update returns NULL */
int test_rgs_disabled_channel(void)
{
    unsigned char blob[4096];
    size_t len = build_test_blob(blob, sizeof(blob), 3000, 0x55, 0x66, 77, 300000, 1);

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;
    ASSERT(rgs_parse(blob, len, &snap, nodes, 16, chans, 64), "parse ok");

    /* Manually set disabled flag on direction 0 */
    chans[0].updates[0].flags |= 1;

    ASSERT(rgs_get_update(&chans[0], 0) == NULL, "disabled update = NULL");
    ASSERT(rgs_get_update(&chans[0], 1) != NULL, "enabled update still ok");
    return 1;
}

/* RGS6: rgs_count_active_channels */
int test_rgs_count_active(void)
{
    unsigned char blob[4096];
    size_t len = build_test_blob(blob, sizeof(blob), 4000, 0x77, 0x88, 11, 400000, 1);

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;
    ASSERT(rgs_parse(blob, len, &snap, nodes, 16, chans, 64), "parse ok");

    uint32_t active = rgs_count_active_channels(&snap, chans);
    ASSERT(active == 1, "1 active channel");

    /* Disable both directions */
    chans[0].updates[0].flags |= 1;
    chans[0].updates[1].flags |= 1;
    active = rgs_count_active_channels(&snap, chans);
    ASSERT(active == 0, "0 active after disabling");

    ASSERT(rgs_count_active_channels(NULL, chans) == 0, "NULL snap = 0");
    return 1;
}

/* RGS7: parse rejects bad magic */
int test_rgs_bad_magic(void)
{
    unsigned char blob[64];
    memset(blob, 0, sizeof(blob));
    memcpy(blob, "BADHDR", 6);

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;
    ASSERT(!rgs_parse(blob, sizeof(blob), &snap, nodes, 16, chans, 64),
           "bad magic rejected");
    return 1;
}

/* RGS8: parse rejects truncated blob */
int test_rgs_truncated(void)
{
    unsigned char blob[4096];
    size_t full_len = build_test_blob(blob, sizeof(blob), 5000, 0x99, 0xAA, 123, 500000, 2);
    ASSERT(full_len > 0, "build ok");

    rgs_node_id_t nodes[16];
    rgs_channel_t chans[64];
    rgs_snapshot_t snap;

    /* Try parsing half the blob */
    ASSERT(!rgs_parse(blob, full_len / 2, &snap, nodes, 16, chans, 64),
           "truncated blob rejected");
    return 1;
}

/* RGS9: build rejects buffer too small */
int test_rgs_build_small_buf(void)
{
    rgs_node_id_t nodes[2];
    make_pubkey(nodes[0].pubkey, 0xBB);
    make_pubkey(nodes[1].pubkey, 0xCC);

    rgs_channel_t chan;
    memset(&chan, 0, sizeof(chan));
    chan.short_channel_id = 42;
    chan.funding_satoshis = 100000;

    rgs_snapshot_t snap;
    snap.last_sync_timestamp = 1000;
    snap.node_id_count       = 2;
    snap.channel_count       = 1;

    unsigned char tiny[10];
    ASSERT(rgs_build(&snap, nodes, &chan, tiny, sizeof(tiny)) == 0,
           "small buffer returns 0");
    return 1;
}

/* RGS10: NULL safety */
int test_rgs_null_safety(void)
{
    rgs_node_id_t nodes[4];
    rgs_channel_t chans[4];
    rgs_snapshot_t snap;
    unsigned char blob[256];

    ASSERT(!rgs_parse(NULL, 100, &snap, nodes, 4, chans, 4), "NULL blob rejected");
    ASSERT(!rgs_parse(blob, 100, NULL, nodes, 4, chans, 4), "NULL snap rejected");
    ASSERT(rgs_build(NULL, nodes, chans, blob, sizeof(blob)) == 0, "NULL snap rejected");
    return 1;
}
