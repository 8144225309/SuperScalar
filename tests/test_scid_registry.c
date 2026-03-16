/*
 * test_scid_registry.c — Unit tests for fake SCID encode/decode and route hints
 */

#include "superscalar/scid_registry.h"
#include "superscalar/persist.h"
#include <string.h>
#include <stdio.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Test S1: SCID encode/decode round-trip */
int test_scid_encode_decode(void)
{
    uint32_t fid = 42, lid = 7;
    uint64_t scid = scid_encode(fid, lid);

    /* Verify layout: fid in bits 63-40, lid in bits 39-16, output_index=0 */
    ASSERT((scid >> 40) == 42, "factory_id in upper 24 bits");
    ASSERT(((scid >> 16) & 0xFFFFFF) == 7, "leaf_idx in middle 24 bits");
    ASSERT((scid & 0xFFFF) == 0, "output_index is 0");

    uint32_t fid_out = 0, lid_out = 0;
    scid_decode(scid, &fid_out, &lid_out);
    ASSERT(fid_out == fid, "factory_id round-trips");
    ASSERT(lid_out == lid, "leaf_idx round-trips");

    /* Edge cases */
    uint64_t s_max = scid_encode(0xFFFFFF, 0xFFFFFF);
    uint32_t f2, l2;
    scid_decode(s_max, &f2, &l2);
    ASSERT(f2 == 0xFFFFFF, "max factory_id round-trips");
    ASSERT(l2 == 0xFFFFFF, "max leaf_idx round-trips");

    uint64_t s_zero = scid_encode(0, 0);
    ASSERT(s_zero == 0, "zero factory + zero leaf = 0");

    return 1;
}

/* Test S2: route_hint wire format */
int test_scid_route_hint_format(void)
{
    unsigned char node_id[33];
    memset(node_id, 0x02, 33);
    node_id[0] = 0x02;

    uint32_t fid = 100, lid = 3;
    uint64_t scid = scid_encode(fid, lid);

    unsigned char hint[51];
    ASSERT(scid_route_hint(hint, node_id, scid, 1000, 250, 40),
           "scid_route_hint returns 1");

    /* pubkey: bytes 0..32 */
    ASSERT(memcmp(hint, node_id, 33) == 0, "pubkey at offset 0");

    /* scid: bytes 33..40 big-endian */
    uint64_t scid_read = 0;
    for (int i = 0; i < 8; i++)
        scid_read = (scid_read << 8) | hint[33 + i];
    ASSERT(scid_read == scid, "scid big-endian at offset 33");

    /* fee_base_msat: bytes 41..44 */
    uint32_t fb = ((uint32_t)hint[41] << 24) | ((uint32_t)hint[42] << 16)
                | ((uint32_t)hint[43] <<  8) |  (uint32_t)hint[44];
    ASSERT(fb == 1000, "fee_base_msat correct");

    /* fee_proportional_millionths: bytes 45..48 */
    uint32_t fp = ((uint32_t)hint[45] << 24) | ((uint32_t)hint[46] << 16)
                | ((uint32_t)hint[47] <<  8) |  (uint32_t)hint[48];
    ASSERT(fp == 250, "fee_ppm correct");

    /* cltv_expiry_delta: bytes 49..50 */
    uint16_t cltv = ((uint16_t)hint[49] << 8) | hint[50];
    ASSERT(cltv == 40, "cltv_expiry_delta correct");

    return 1;
}

/* Test S3: persist SCID registry round-trip */
int test_scid_persist_roundtrip(void)
{
    persist_t p;
    ASSERT(persist_open(&p, ":memory:"), "open in-memory DB");
    ASSERT(persist_schema_version(&p) == PERSIST_SCHEMA_VERSION, "schema version current");
    ASSERT(PERSIST_SCHEMA_VERSION >= 6, "schema version >= 6");

    uint32_t fid = 7, lid = 3;
    uint64_t scid = scid_encode(fid, lid);

    ASSERT(persist_save_scid_entry(&p, fid, lid, scid), "save scid entry");

    uint32_t fid_out = 0, lid_out = 0;
    ASSERT(persist_load_scid_entry(&p, scid, &fid_out, &lid_out), "load scid entry");
    ASSERT(fid_out == fid, "factory_id persisted correctly");
    ASSERT(lid_out == lid, "leaf_idx persisted correctly");

    /* Unknown SCID returns 0 */
    ASSERT(!persist_load_scid_entry(&p, 0xDEAD000000000000ULL, &fid_out, &lid_out),
           "unknown scid returns 0");

    persist_close(&p);
    return 1;
}
