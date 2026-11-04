/* Rotation by a co-signed close into the new factory: key freshness, the
   balance carry, the close check a client runs before signing, the resume
   and resolve decisions, the records, and the wire messages. */
#include "superscalar/lsp_channels.h"
#include "superscalar/factory_keys.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wire.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

static secp256k1_context *cin_ctx(void) {
    static secp256k1_context *c = NULL;
    if (!c) c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return c;
}

static int mk_pk(secp256k1_pubkey *pk, unsigned char b) {
    unsigned char s[32];
    memset(s, b, 32);
    return secp256k1_ec_pubkey_create(cin_ctx(), pk, s);
}

/* The LSP and client records, and the DB snapshot. */
int test_cin_records(void) {
    char path[] = "/tmp/ss_cin_rec_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    const char *dying = "11111111111111111111111111111111111111111111111111111111111111aa";
    const char *newf = "22222222222222222222222222222222222222222222222222222222222222bb";
    TEST_ASSERT(persist_save_rotation_cin(&db, dying, "02abcd", 777, NULL), "save cin");
    char *ph = NULL, *sh = NULL;
    uint32_t h = 0;
    TEST_ASSERT(persist_load_rotation_cin(&db, dying, &ph, &h, &sh) == 1 && ph &&
                strcmp(ph, "02abcd") == 0 && h == 777 && sh == NULL, "load cin");
    free(ph);
    TEST_ASSERT(persist_save_rotation_cin(&db, dying, "02abcd", 777, "0200aa"), "signed close");
    TEST_ASSERT(persist_load_rotation_cin(&db, dying, NULL, NULL, &sh) == 1 && sh &&
                strcmp(sh, "0200aa") == 0, "signed close kept");
    free(sh);
    persist_rotation_progress_t r;
    memset(&r, 0, sizeof(r));
    r.phase = LSP_ROT_PROGRESS_CLOSING;
    snprintf(r.new_funding_txid, 65, "%s", newf);
    snprintf(r.close_txid, 65, "%s", newf);
    TEST_ASSERT(persist_save_rotation_progress(&db, dying, &r), "progress");
    char found[65];
    TEST_ASSERT(persist_find_rotation_by_new_funding(&db, newf, found) == 1 &&
                strcmp(found, dying) == 0, "found by the replacement funding");
    TEST_ASSERT(persist_find_rotation_by_new_funding(&db, dying, found) == 0, "none");

    persist_client_rotation_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.old_txid, 65, "%s", dying);
    c.old_vout = 1;
    c.key_index = 3;
    snprintf(c.state, sizeof(c.state), "key_sent");
    TEST_ASSERT(persist_client_rotation_save(&db, &c), "client row");
    persist_client_rotation_t b;
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(persist_client_rotation_load_open(&db, &b) == 1 && b.key_index == 3 &&
                strcmp(b.state, "key_sent") == 0 && b.close_hex == NULL, "open row");
    snprintf(c.state, sizeof(c.state), "close_signed");
    snprintf(c.close_txid, 65, "%s", newf);
    c.close_hex = "0200";
    TEST_ASSERT(persist_client_rotation_save(&db, &c), "update");
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(persist_client_rotation_load(&db, dying, &b) == 1 &&
                strcmp(b.close_txid, newf) == 0 && b.close_hex &&
                strcmp(b.close_hex, "0200") == 0, "reload");
    free(b.close_hex);
    snprintf(c.state, sizeof(c.state), "done");
    c.close_hex = NULL;
    TEST_ASSERT(persist_client_rotation_save(&db, &c), "done");
    TEST_ASSERT(persist_client_rotation_load_open(&db, &b) == 0, "no open row when done");

    char snap[64];
    snprintf(snap, sizeof(snap), "%s.snap", path);
    unlink(snap);
    TEST_ASSERT(persist_snapshot_to(&db, snap), "snapshot");
    persist_t s2;
    TEST_ASSERT(persist_open(&s2, snap), "open snapshot");
    TEST_ASSERT(persist_load_rotation_cin(&s2, dying, NULL, NULL, NULL) == 1, "snapshot holds rows");
    persist_close(&s2);
    persist_close(&db);
    unlink(snap);
    unlink(path);
    return 1;
}

/* A client binds the first tree it signs over a replacement funding. */
int test_cin_tree_bind_record(void) {
    char path[] = "/tmp/ss_cin_tb_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    const char *x = "1111111111111111111111111111111111111111111111111111111111111111";
    const char *y = "2222222222222222222222222222222222222222222222222222222222222222";
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, x, "aa") == 1, "the first tree binds");
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, x, "aa") == 1, "the same tree again");
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, x, "bb") == 0,
                "another tree over the same close is refused");
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, y, "bb") == 1,
                "another close binds its own tree");
    persist_close(&db);
    unlink(path);
    return 1;
}

/* Keys that differ only in case, and numbers out of range. */
int test_cin_json_strict(void) {
    cJSON *j = cJSON_Parse("{\"FUNDING_AMOUNT\":111,\"Funding_Vout\":1,"
                           "\"funding_amount\":222,\"funding_vout\":0}");
    TEST_ASSERT(j && !wire_json_unambiguous(j), "case variants refused");
    cJSON_Delete(j);
    j = cJSON_Parse("{\"a\":{\"x\":1,\"X\":2}}");
    TEST_ASSERT(j && !wire_json_unambiguous(j), "nested case variants refused");
    cJSON_Delete(j);
    j = cJSON_Parse("{\"a\":[{\"k\":1},{\"k\":2}],\"b\":{\"k\":3},\"n\":7,\"neg\":-1,"
                    "\"frac\":1.5,\"big\":1e300,\"s\":\"5\",\"w\":4294967296}");
    TEST_ASSERT(j && wire_json_unambiguous(j), "distinct keys pass");
    uint64_t v = 0;
    TEST_ASSERT(wire_json_get_uint(j, "n", 10, &v) && v == 7, "in range");
    TEST_ASSERT(!wire_json_get_uint(j, "n", 6, &v), "above the maximum");
    TEST_ASSERT(!wire_json_get_uint(j, "neg", 10, &v), "negative");
    TEST_ASSERT(!wire_json_get_uint(j, "frac", 10, &v), "fraction");
    TEST_ASSERT(!wire_json_get_uint(j, "big", UINT64_MAX, &v), "huge");
    TEST_ASSERT(!wire_json_get_uint(j, "s", 10, &v), "a string");
    TEST_ASSERT(!wire_json_get_uint(j, "w", UINT32_MAX, &v), "past 32 bits");
    TEST_ASSERT(!wire_json_get_uint(j, "N", 10, &v), "exact case only");
    cJSON_Delete(j);
    return 1;
}

int test_cin_wire_roundtrip(void) {
    secp256k1_context *ctx = cin_ctx();
    secp256k1_pubkey pk, back;
    TEST_ASSERT(mk_pk(&pk, 0x61), "pk");
    unsigned char d[32], d2[32];
    memset(d, 0x5a, 32);
    cJSON *k = wire_build_rotation_key(ctx, &pk, d);
    TEST_ASSERT(k && wire_parse_rotation_key(k, ctx, &back, d2) && memcmp(d, d2, 32) == 0,
                "rotation key");
    unsigned char a[33], b[33];
    size_t la = 33, lb = 33;
    secp256k1_ec_pubkey_serialize(ctx, a, &la, &pk, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, b, &lb, &back, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(a, b, 33) == 0, "same key");
    cJSON_Delete(k);
    const char *t = "33333333333333333333333333333333333333333333333333333333333333cc";
    cJSON *dn = wire_build_rotation_done(t, "0200ff", 1);
    char tt[65];
    char *hex = NULL;
    int conf = 0;
    TEST_ASSERT(dn && wire_parse_rotation_done(dn, tt, &hex, &conf) && strcmp(tt, t) == 0 &&
                hex && strcmp(hex, "0200ff") == 0 && conf == 1, "rotation done");
    free(hex);
    cJSON_Delete(dn);
    return 1;
}

/* A rotation reserves a NEW key; the active key stays the one in use. */
int test_cin_reserve_next_key(void) {
    secp256k1_context *ctx = cin_ctx();
    unsigned char root[32], lctx[33], zero[33], sk[32], nsk[32];
    memset(root, 0x42, 32);
    memset(lctx, 0x77, 33);
    lctx[0] = 0x02;
    memset(zero, 0, 33);
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    uint32_t idx = 9, nidx = 9;
    factory_key_source_t src;
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 0, "first");
    TEST_ASSERT(persist_factory_key_set_state(&db, 0, FACTORY_KEY_STATE_ACTIVE, 0), "active");
    TEST_ASSERT(!factory_key_reserve_next(&db, ctx, root, zero, nsk, &nidx), "zero ctx refused");
    TEST_ASSERT(factory_key_reserve_next(&db, ctx, root, lctx, nsk, &nidx) && nidx == 1 &&
                memcmp(sk, nsk, 32) != 0, "a new index");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 0 &&
                src == FACTORY_KEY_RELOADED, "the active key stays current");
    unsigned char again[32];
    TEST_ASSERT(factory_key_derive_stored(&db, ctx, root, 1, again) &&
                memcmp(again, nsk, 32) == 0, "the reserved key re-derives");
    TEST_ASSERT(persist_factory_key_set_state(&db, 1, FACTORY_KEY_STATE_ACTIVE, 0), "promoted");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 1,
                "after the switch the replacement key is current");
    persist_close(&db);
    return 1;
}
