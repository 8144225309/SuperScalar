/* Per-factory client keys (factory_keys.h): derivation, hardening,
   refusal of reused or identity keys, the seed scan and reload after a
   restart. */
#include "superscalar/factory_keys.h"
#include "superscalar/persist.h"
#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

static secp256k1_context *fk_ctx(void) {
    static secp256k1_context *c = NULL;
    if (!c) c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return c;
}

static void ser33(const secp256k1_context *ctx, const secp256k1_pubkey *pk,
                  unsigned char out[33]) {
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, pk, SECP256K1_EC_COMPRESSED);
}

static void root_and_ctx(unsigned char root[32], unsigned char lctx[33]) {
    memset(root, 0x42, 32);
    memset(lctx, 0, 33);
    lctx[0] = 0x02;
    memset(lctx + 1, 0x77, 32);
}

/* Same inputs, same key; any input change gives another key. */
int test_factory_key_derive_deterministic(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], a[32], b[32], c[32], d[32], e[32];
    root_and_ctx(root, lctx);
    TEST_ASSERT(factory_key_derive(ctx, a, root, lctx, 0), "derive 0");
    TEST_ASSERT(factory_key_derive(ctx, b, root, lctx, 0), "derive 0 again");
    TEST_ASSERT(memcmp(a, b, 32) == 0, "deterministic");
    TEST_ASSERT(factory_key_derive(ctx, c, root, lctx, 1), "derive 1");
    TEST_ASSERT(memcmp(a, c, 32) != 0, "index changes the key");
    unsigned char lctx2[33];
    memcpy(lctx2, lctx, 33);
    lctx2[5] ^= 1;
    TEST_ASSERT(factory_key_derive(ctx, d, root, lctx2, 0), "derive other lsp");
    TEST_ASSERT(memcmp(a, d, 32) != 0, "LSP context changes the key");
    unsigned char root2[32];
    memcpy(root2, root, 32);
    root2[31] ^= 1;
    TEST_ASSERT(factory_key_derive(ctx, e, root2, lctx, 0), "derive other root");
    TEST_ASSERT(memcmp(a, e, 32) != 0, "root changes the key");
    TEST_ASSERT(memcmp(a, root, 32) != 0, "never the root key");
    /* Pubkey helper agrees with the secret. */
    unsigned char pk33[33], pk33b[33];
    secp256k1_pubkey pk;
    TEST_ASSERT(factory_key_derive_pubkey(ctx, pk33, root, lctx, 0), "derive pubkey");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, a), "pk");
    ser33(ctx, &pk, pk33b);
    TEST_ASSERT(memcmp(pk33, pk33b, 33) == 0, "pubkey matches secret");
    /* A fixed vector, so the derivation cannot change by accident. */
    {
        unsigned char data[69], want[32];
        memcpy(data, root, 32);
        memcpy(data + 32, lctx, 33);
        data[65] = 0; data[66] = 0; data[67] = 0; data[68] = 7;
        extern void sha256_tagged(const char *, const unsigned char *, size_t,
                                  unsigned char *);
        sha256_tagged("SuperScalar/factory-key/v1", data, sizeof(data), want);
        unsigned char got[32];
        TEST_ASSERT(factory_key_derive(ctx, got, root, lctx, 7), "derive 7");
        TEST_ASSERT(memcmp(got, want, 32) == 0, "tagged-hash layout");
    }
    return 1;
}

/* Hardened: keys are hashes of the root secret, not root + tweak.  Knowing
   one factory key (and its index) gives no linear relation to the root or
   to another index. */
int test_factory_key_hardened(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], k0[32], k1[32], k0r[32];
    root_and_ctx(root, lctx);
    TEST_ASSERT(factory_key_derive(ctx, k0, root, lctx, 0), "k0");
    TEST_ASSERT(factory_key_derive(ctx, k1, root, lctx, 1), "k1");
    /* An additive scheme would give k0 - root == H(ctx, 0): with root + 1 the
       key would move by exactly 1.  Check it does not. */
    unsigned char root_p1[32];
    memcpy(root_p1, root, 32);
    TEST_ASSERT(secp256k1_ec_seckey_tweak_add(ctx, root_p1,
        (const unsigned char[32]){[31] = 1}), "root + 1");
    TEST_ASSERT(factory_key_derive(ctx, k0r, root_p1, lctx, 0), "k0(root+1)");
    unsigned char k0_p1[32];
    memcpy(k0_p1, k0, 32);
    TEST_ASSERT(secp256k1_ec_seckey_tweak_add(ctx, k0_p1,
        (const unsigned char[32]){[31] = 1}), "k0 + 1");
    TEST_ASSERT(memcmp(k0r, k0_p1, 32) != 0, "root + 1 does not shift the key by 1");
    /* k1 - k0 must not equal the root-independent difference an additive
       tweak would give: recompute both differences for a second root. */
    unsigned char r2[32], j0[32], j1[32];
    memset(r2, 0x55, 32);
    TEST_ASSERT(factory_key_derive(ctx, j0, r2, lctx, 0), "j0");
    TEST_ASSERT(factory_key_derive(ctx, j1, r2, lctx, 1), "j1");
    unsigned char d1[32], d2[32], neg[32];
    memcpy(neg, k0, 32);
    TEST_ASSERT(secp256k1_ec_seckey_negate(ctx, neg), "neg k0");
    memcpy(d1, k1, 32);
    TEST_ASSERT(secp256k1_ec_seckey_tweak_add(ctx, d1, neg), "k1 - k0");
    memcpy(neg, j0, 32);
    TEST_ASSERT(secp256k1_ec_seckey_negate(ctx, neg), "neg j0");
    memcpy(d2, j1, 32);
    TEST_ASSERT(secp256k1_ec_seckey_tweak_add(ctx, d2, neg), "j1 - j0");
    TEST_ASSERT(memcmp(d1, d2, 32) != 0, "index steps depend on the root secret");
    return 1;
}

/* Fresh reservation, reuse of an unused reservation across a restart,
   active marking, and a reload from a file DB. */
int test_factory_key_select_reserve_and_reload(void) {
    secp256k1_context *ctx = fk_ctx();
    char path[] = "/tmp/ss_fk_reload_XXXXXX";
    int tfd = mkstemp(path);
    TEST_ASSERT(tfd >= 0, "mkstemp");
    close(tfd);
    unlink(path);
    unsigned char root[32], lctx[33], sk[32], sk2[32];
    root_and_ctx(root, lctx);
    uint32_t idx = 99, idx2 = 99;
    factory_key_source_t src;

    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src), "select fresh");
    TEST_ASSERT(src == FACTORY_KEY_FRESH && idx == 0, "first index 0, fresh");
    TEST_ASSERT(memcmp(sk, root, 32) != 0, "factory key is not the identity key");
    /* Restart before any factory: the same reserved key comes back. */
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk2, &idx2, &src), "select again");
    TEST_ASSERT(src == FACTORY_KEY_RELOADED && idx2 == 0 &&
                memcmp(sk, sk2, 32) == 0, "reserved key reused before a factory");
    TEST_ASSERT(persist_factory_key_set_state(&db, 0, FACTORY_KEY_STATE_ACTIVE, 0),
                "mark active");
    persist_close(&db);

    TEST_ASSERT(persist_open(&db, path), "reopen");
    memset(sk2, 0, 32);
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk2, &idx2, &src), "reload");
    TEST_ASSERT(src == FACTORY_KEY_RELOADED && idx2 == 0 && memcmp(sk, sk2, 32) == 0,
                "restart reloads the same factory key");
    /* The wrong root key for this DB is refused, never silently replaced. */
    unsigned char wrong[32];
    memset(wrong, 0x43, 32);
    TEST_ASSERT(!factory_key_select(&db, ctx, wrong, lctx, sk2, &idx2, &src),
                "wrong root refused");
    persist_close(&db);
    unlink(path);
    return 1;
}

/* An index that was handed over is never reserved again, even if the
   counter row is lowered. */
int test_factory_key_never_reused(void) {
    secp256k1_context *ctx = fk_ctx();
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char root[32], lctx[33], sk[32];
    root_and_ctx(root, lctx);
    uint32_t idx;
    factory_key_source_t src;
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 0,
                "reserve 0");
    TEST_ASSERT(persist_factory_key_set_state(&db, 0, FACTORY_KEY_STATE_RELEASED, 0),
                "release 0");
    TEST_ASSERT(persist_save_counter(&db, FACTORY_KEY_COUNTER, 0), "counter lowered");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src), "select");
    TEST_ASSERT(src == FACTORY_KEY_FRESH && idx == 1, "next index past the released one");
    unsigned char pk0[33];
    TEST_ASSERT(factory_key_derive_pubkey(ctx, pk0, root, lctx, 0), "pk0");
    TEST_ASSERT(persist_factory_key_is_released(&db, pk0), "released key recorded");
    persist_close(&db);
    return 1;
}

/* Participant-list checks before signing a factory. */
int test_factory_key_refuses_identity_and_released(void) {
    secp256k1_context *ctx = fk_ctx();
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char root[32], lctx[33], fsk[32], other[32];
    root_and_ctx(root, lctx);
    TEST_ASSERT(factory_key_derive(ctx, fsk, root, lctx, 3), "fsk");
    secp256k1_pubkey id_pk, my_pk, lsp_pk, c2_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &id_pk, root), "id");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &my_pk, fsk), "mine");
    memset(other, 0x11, 32);
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &lsp_pk, other), "lsp");
    memset(other, 0x12, 32);
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &c2_pk, other), "c2");

    secp256k1_pubkey parts[3] = { lsp_pk, my_pk, c2_pk };
    const char *why = NULL;
    TEST_ASSERT(factory_key_check_participants(ctx, &db, &id_pk, &my_pk, 1, parts, 3, &why),
                "normal list accepted");

    parts[2] = id_pk;   /* the identity key smuggled into another slot */
    TEST_ASSERT(!factory_key_check_participants(ctx, &db, &id_pk, &my_pk, 1, parts, 3, &why),
                "identity key refused");
    TEST_ASSERT(why && strstr(why, "identity"), "reason: identity");

    parts[2] = my_pk;   /* my factory key twice */
    TEST_ASSERT(!factory_key_check_participants(ctx, &db, &id_pk, &my_pk, 1, parts, 3, &why),
                "duplicate of my key refused");

    parts[2] = c2_pk;
    parts[1] = c2_pk;   /* my slot holds someone else's key */
    TEST_ASSERT(!factory_key_check_participants(ctx, &db, &id_pk, &my_pk, 1, parts, 3, &why),
                "wrong key in my slot refused");

    /* A key this client released before is refused anywhere. */
    unsigned char my33[33];
    ser33(ctx, &my_pk, my33);
    TEST_ASSERT(persist_factory_key_save(&db, 3, lctx, my33, 0, FACTORY_KEY_STATE_RELEASED),
                "record released");
    parts[1] = my_pk;
    parts[2] = c2_pk;
    TEST_ASSERT(!factory_key_check_participants(ctx, &db, &id_pk, &my_pk, 1, parts, 3, &why),
                "released key refused");
    TEST_ASSERT(why && strstr(why, "released"), "reason: released");

    /* Legacy factory: the identity key is the factory key, in my slot only. */
    secp256k1_pubkey legacy[3] = { lsp_pk, id_pk, c2_pk };
    TEST_ASSERT(factory_key_check_participants(ctx, NULL, &id_pk, &id_pk, 1, legacy, 3, &why),
                "legacy list accepted");
    persist_close(&db);
    return 1;
}

/* 1 if the key table is readable and empty. */
static int no_key_rows(persist_t *db) {
    int64_t mx = 0;
    return persist_factory_key_max_index(db, &mx) && mx < 0;
}

static int save_factory_with_client_key(persist_t *db, secp256k1_context *ctx,
                                        const secp256k1_pubkey *client_pk) {
    unsigned char s[32];
    secp256k1_pubkey pks[3];
    memset(s, 0x31, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], s)) return 0;
    pks[1] = *client_pk;
    memset(s, 0x32, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], s)) return 0;
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 3, 10, 4);
    unsigned char txid[32], spk[34];
    memset(txid, 0x01, 32);
    spk[0] = 0x51; spk[1] = 0x20;
    memset(spk + 2, 0xAA, 32);
    factory_set_funding(f, txid, 0, 100000, spk, 34);
    int ok = persist_save_factory(db, f, ctx, 0);
    factory_free(f);
    free(f);
    return ok;
}

/* DB with a factory but no key row (key table lost): scan finds the key in
   the window, records it, and moves the counter past it by a random skip. */
int test_factory_key_seed_scan(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], sk37[32], sk[32];
    root_and_ctx(root, lctx);
    TEST_ASSERT(factory_key_derive(ctx, sk37, root, lctx, 37), "k37");
    secp256k1_pubkey pk37;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk37, sk37), "pk37");

    /* Pure scan over a target list. */
    unsigned char targets[2][33];
    memset(targets[0], 0x02, 33);
    ser33(ctx, &pk37, targets[1]);
    uint32_t found = 0;
    size_t which = 9;
    TEST_ASSERT(factory_key_scan(ctx, root, lctx, (const unsigned char (*)[33])targets,
                                 2, FACTORY_KEY_SCAN_WINDOW, &found, &which), "scan");
    TEST_ASSERT(found == 37 && which == 1, "found index 37");
    TEST_ASSERT(!factory_key_scan(ctx, root, lctx, (const unsigned char (*)[33])targets,
                                  2, 37, &found, &which), "outside a smaller window");

    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &pk37), "factory");
    uint32_t idx = 0;
    factory_key_source_t src;
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src), "select");
    TEST_ASSERT(src == FACTORY_KEY_RECOVERED && idx == 37 && memcmp(sk, sk37, 32) == 0,
                "recovered by scan");
    uint64_t next = persist_load_counter(&db, FACTORY_KEY_COUNTER, 0);
    TEST_ASSERT(next >= 38ULL + FACTORY_KEY_SKIP_MIN &&
                next < 38ULL + FACTORY_KEY_SKIP_MAX, "counter skipped ahead");
    /* The recovered key now reloads directly. */
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) &&
                src == FACTORY_KEY_RELOADED && idx == 37, "reload after recovery");
    persist_close(&db);

    /* A key beyond the window is not found: selection fails, nothing reserved. */
    unsigned char sk_far[32];
    secp256k1_pubkey pk_far;
    TEST_ASSERT(factory_key_derive(ctx, sk_far, root, lctx, FACTORY_KEY_SCAN_WINDOW + 5), "far");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk_far, sk_far), "pk far");
    TEST_ASSERT(persist_open(&db, ":memory:"), "open 2");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &pk_far), "factory far");
    TEST_ASSERT(!factory_key_select(&db, ctx, root, lctx, sk, &idx, &src),
                "not found outside the window");
    TEST_ASSERT(no_key_rows(&db), "nothing reserved");
    persist_close(&db);
    return 1;
}

/* A DB factory that signs with the identity key (created before per-factory
   keys) keeps using it. */
int test_factory_key_legacy_factory(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], sk[32];
    root_and_ctx(root, lctx);
    secp256k1_pubkey id_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &id_pk, root), "id");
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &id_pk), "legacy factory");
    uint32_t idx;
    factory_key_source_t src;
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src), "select");
    TEST_ASSERT(src == FACTORY_KEY_LEGACY && memcmp(sk, root, 32) == 0, "legacy");
    TEST_ASSERT(no_key_rows(&db), "no key row written");
    persist_close(&db);
    return 1;
}

/* A new key needs a pinned LSP context when a DB is used; without a DB the
   ephemeral key may use the zero context. */
int test_factory_key_requires_pinned_context(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], sk[32], zero[33];
    root_and_ctx(root, lctx);
    memset(zero, 0, sizeof(zero));
    uint32_t idx;
    factory_key_source_t src;
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(!factory_key_select(&db, ctx, root, NULL, sk, &idx, &src),
                "no pinned key: refused");
    TEST_ASSERT(!factory_key_select(&db, ctx, root, zero, sk, &idx, &src),
                "zero context: refused");
    TEST_ASSERT(no_key_rows(&db), "nothing reserved");
    uint64_t c = 0;
    TEST_ASSERT(persist_load_counter_checked(&db, FACTORY_KEY_COUNTER, &c) == 0,
                "counter untouched");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) &&
                src == FACTORY_KEY_FRESH, "pinned: reserved");
    persist_close(&db);
    TEST_ASSERT(factory_key_select(NULL, ctx, root, NULL, sk, &idx, &src),
                "no DB: ephemeral key allowed");
    return 1;
}

/* The scan tries the pinned context, then the zero context; a match on an
   index that was released before is refused and the row stays released. */
int test_factory_key_scan_contexts_and_released(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], zero[33], k[32], sk[32];
    root_and_ctx(root, lctx);
    memset(zero, 0, sizeof(zero));
    secp256k1_pubkey pk;
    uint32_t idx = 0;
    factory_key_source_t src;
    unsigned char got_ctx[33];

    /* A factory signed with a zero-context key (derived before pinning). */
    TEST_ASSERT(factory_key_derive(ctx, k, root, zero, 5), "k5 zero ctx");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, k), "pk");
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &pk), "factory");
    TEST_ASSERT(factory_key_lookup(&db, ctx, root, lctx, sk, &idx, &src, got_ctx) == 1 &&
                src == FACTORY_KEY_RECOVERED && idx == 5 && memcmp(sk, k, 32) == 0 &&
                factory_key_ctx_is_zero(got_ctx), "zero-context key found");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) &&
                src == FACTORY_KEY_RECOVERED && idx == 5, "recovered");
    uint32_t ridx;
    unsigned char rctx[33], rpk[33];
    TEST_ASSERT(persist_factory_key_load_current(&db, &ridx, rctx, rpk) == 1 &&
                ridx == 5 && factory_key_ctx_is_zero(rctx), "row keeps the zero context");
    persist_close(&db);

    /* The same factory, but index 5 is recorded as released: refused. */
    TEST_ASSERT(persist_open(&db, ":memory:"), "open 2");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &pk), "factory 2");
    unsigned char pk33[33];
    ser33(ctx, &pk, pk33);
    TEST_ASSERT(persist_factory_key_save(&db, 5, zero, pk33, 0, FACTORY_KEY_STATE_RELEASED),
                "released row");
    TEST_ASSERT(factory_key_lookup(&db, ctx, root, lctx, sk, &idx, &src, NULL) == -1,
                "lookup refuses a released index");
    TEST_ASSERT(!factory_key_select(&db, ctx, root, lctx, sk, &idx, &src),
                "select refuses a released index");
    char state[16];
    TEST_ASSERT(persist_factory_key_get_state(&db, 5, state) == 1 &&
                strcmp(state, FACTORY_KEY_STATE_RELEASED) == 0, "still released");
    persist_close(&db);
    return 1;
}

/* Rows are never overwritten; lookup never writes. */
int test_factory_key_no_overwrite_and_read_only_lookup(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], a[33], b[33], sk[32];
    root_and_ctx(root, lctx);
    memset(a, 0x02, 33);
    memset(b, 0x03, 33);
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(persist_factory_key_save(&db, 0, lctx, a, -1, FACTORY_KEY_STATE_RESERVED),
                "first insert");
    TEST_ASSERT(!persist_factory_key_save(&db, 0, lctx, b, -1, FACTORY_KEY_STATE_ACTIVE),
                "second insert on the same index fails");
    unsigned char got[33];
    uint32_t idx;
    TEST_ASSERT(persist_factory_key_load_current(&db, &idx, NULL, got) == 1 &&
                memcmp(got, a, 33) == 0, "original row kept");
    persist_close(&db);

    /* Lookup on an empty DB: nothing, and nothing written. */
    factory_key_source_t src;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open 2");
    TEST_ASSERT(factory_key_lookup(&db, ctx, root, lctx, sk, &idx, &src, NULL) == 0,
                "empty DB: none");
    TEST_ASSERT(no_key_rows(&db), "no row");
    /* Lookup on a restorable factory: found, still nothing written. */
    unsigned char k[32];
    secp256k1_pubkey pk;
    TEST_ASSERT(factory_key_derive(ctx, k, root, lctx, 9), "k9");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, k), "pk9");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &pk), "factory");
    TEST_ASSERT(factory_key_lookup(&db, ctx, root, lctx, sk, &idx, &src, NULL) == 1 &&
                src == FACTORY_KEY_RECOVERED && idx == 9, "found by scan");
    uint64_t c = 0;
    TEST_ASSERT(no_key_rows(&db) &&
                persist_load_counter_checked(&db, FACTORY_KEY_COUNTER, &c) == 0,
                "lookup wrote nothing");
    persist_close(&db);
    return 1;
}

/* A DB read error is an error, never "no row": nothing is reserved and the
   caller is told to stop. */
int test_factory_key_db_errors_refuse(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char root[32], lctx[33], sk[32];
    root_and_ctx(root, lctx);
    uint32_t idx;
    factory_key_source_t src;
    persist_t db;

    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(sqlite3_exec(db.db, "DROP TABLE id_counters;", NULL, NULL, NULL) == SQLITE_OK,
                "drop counters");
    uint64_t c = 0;
    TEST_ASSERT(persist_load_counter_checked(&db, FACTORY_KEY_COUNTER, &c) == -1,
                "counter read reports the error");
    TEST_ASSERT(!factory_key_select(&db, ctx, root, lctx, sk, &idx, &src),
                "select refuses on a counter read error");
    TEST_ASSERT(no_key_rows(&db), "nothing reserved");
    persist_close(&db);

    TEST_ASSERT(persist_open(&db, ":memory:"), "open 2");
    TEST_ASSERT(sqlite3_exec(db.db, "DROP TABLE factory_keys;", NULL, NULL, NULL) == SQLITE_OK,
                "drop keys");
    int64_t mx = 0;
    TEST_ASSERT(!persist_factory_key_max_index(&db, &mx), "max index reports the error");
    TEST_ASSERT(persist_factory_key_load_current(&db, &idx, NULL, NULL) == -1,
                "load reports the error");
    TEST_ASSERT(!factory_key_select(&db, ctx, root, lctx, sk, &idx, &src),
                "select refuses on a key table error");
    persist_close(&db);
    return 1;
}

/* WIF, BIP-380 checksum and the payout descriptors. */
int test_factory_key_payout_descriptors(void) {
    char sum[9], wif[64], d[128], body[96];
    TEST_ASSERT(descriptor_checksum("raw(deadbeef)", sum) && strcmp(sum, "89f8spxm") == 0,
                "BIP-380 vector");
    unsigned char one[32];
    memset(one, 0, 32);
    one[31] = 1;
    TEST_ASSERT(factory_key_wif(one, 1, wif, sizeof(wif)) &&
                strcmp(wif, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn") == 0,
                "mainnet WIF of key 1");
    TEST_ASSERT(factory_key_wif(one, 0, wif, sizeof(wif)) && wif[0] == 'c', "testnet WIF");
    TEST_ASSERT(factory_key_descriptor(one, 0, 1, d, sizeof(d)), "rawtr descriptor");
    snprintf(body, sizeof(body), "rawtr(%s)", wif);
    TEST_ASSERT(strncmp(d, body, strlen(body)) == 0 && d[strlen(body)] == '#', "rawtr body");
    TEST_ASSERT(descriptor_checksum(body, sum) && strcmp(d + strlen(body) + 1, sum) == 0,
                "rawtr checksum");
    TEST_ASSERT(factory_key_descriptor(one, 0, 0, d, sizeof(d)) && strncmp(d, "tr(c", 4) == 0,
                "tr descriptor");
    return 1;
}

/* HELLO carries both keys; the LSP's identity rows survive a factory
   rewrite and are dropped when a slot's factory key changes. */
int test_factory_key_hello_and_identity_rows(void) {
    secp256k1_context *ctx = fk_ctx();
    unsigned char s[32];
    secp256k1_pubkey id_pk, fac_pk, got;
    memset(s, 0x61, 32);
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &id_pk, s), "id");
    memset(s, 0x62, 32);
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &fac_pk, s), "fac");

    cJSON *hello = wire_build_hello(ctx, &id_pk);
    TEST_ASSERT(wire_parse_hello_factory_pubkey(hello, ctx, &got) == 0, "absent -> 0");
    wire_hello_set_factory_pubkey(hello, ctx, &fac_pk);
    TEST_ASSERT(wire_parse_hello_factory_pubkey(hello, ctx, &got) == 1, "present -> 1");
    unsigned char a[33], b[33];
    ser33(ctx, &got, a);
    ser33(ctx, &fac_pk, b);
    TEST_ASSERT(memcmp(a, b, 33) == 0, "factory pubkey roundtrip");
    cJSON_ReplaceItemInObject(hello, "factory_pubkey", cJSON_CreateString("zz"));
    TEST_ASSERT(wire_parse_hello_factory_pubkey(hello, ctx, &got) == -1, "malformed -> -1");
    cJSON_Delete(hello);

    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &fac_pk), "factory");
    secp256k1_pubkey ids[2], back[2];
    ids[0] = id_pk;
    memset(s, 0x63, 32);
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &ids[1], s), "id2");
    TEST_ASSERT(persist_save_participant_identities(&db, 0, ctx, ids, 2), "save ids");
    memset(back, 0, sizeof(back));
    TEST_ASSERT(persist_load_participant_identities(&db, 0, ctx, back, 2) == 2, "load ids");
    ser33(ctx, &back[0], a);
    ser33(ctx, &id_pk, b);
    TEST_ASSERT(memcmp(a, b, 33) == 0, "identity roundtrip");
    /* Rewriting the same factory keeps the identities. */
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &fac_pk), "rewrite");
    TEST_ASSERT(persist_load_participant_identities(&db, 0, ctx, back, 2) == 2,
                "identities kept across a rewrite");
    /* A new key in slot 1 drops that slot's stale identity. */
    TEST_ASSERT(save_factory_with_client_key(&db, ctx, &id_pk), "slot 1 key changed");
    TEST_ASSERT(persist_load_participant_identities(&db, 0, ctx, back, 2) == 1,
                "stale identity dropped");
    persist_close(&db);
    return 1;
}
