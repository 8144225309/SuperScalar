/* Unit tests for include/superscalar/persist_wt.h (Phase 1a) and
   include/superscalar/lsp_wt.h (Phase 1b.2). */

#include "superscalar/persist_wt.h"
#include "superscalar/lsp_wt.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static const char *WT_TMP_PATH = "/tmp/test_persist_wt.db";

static void cleanup_db(void) {
    unlink(WT_TMP_PATH);
    char buf[300];
    snprintf(buf, sizeof(buf), "%s-wal", WT_TMP_PATH); unlink(buf);
    snprintf(buf, sizeof(buf), "%s-shm", WT_TMP_PATH); unlink(buf);
}

int test_persist_wt_open_close(void) {
    cleanup_db();
    persist_wt_t pwt;
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "open on fresh path");
    ASSERT(pwt.db != NULL, "db handle non-NULL");
    persist_wt_close(&pwt);
    ASSERT(pwt.db == NULL, "db handle NULL after close");

    /* Re-open existing file — should not reapply schema, just verify version */
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "re-open existing");
    persist_wt_close(&pwt);
    cleanup_db();
    return 1;
}

int test_persist_wt_register_watch_round_trip(void) {
    cleanup_db();
    persist_wt_t pwt;
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "open");

    unsigned char parent_txid[32];   memset(parent_txid, 0xAA, 32);
    unsigned char response_txid[32]; memset(response_txid, 0xBB, 32);
    unsigned char spk[34];           memset(spk, 0xCC, 34);

    int64_t watch_id = persist_wt_register_watch(&pwt,
        /* kind            */ WT_KIND_FACTORY_NODE,
        /* factory_id      */ 42,
        /* parent_txid32   */ parent_txid,
        /* parent_vout     */ 1,
        /* parent_value_sat*/ 1000000,
        /* parent_spk      */ spk,
        /* parent_spk_len  */ sizeof(spk),
        /* csv_delay       */ 144,
        /* response_tx_hex */ "0200000001abc...",
        /* response_txid32 */ response_txid,
        /* fee_bump_budget */ 5000,
        /* fee_bump_dline  */ 800000);
    ASSERT(watch_id > 0, "register_watch returns positive id");

    int n = persist_wt_count_active_watches(&pwt);
    ASSERT(n == 1, "count_active = 1 after one register");

    /* Reject NULL inputs */
    ASSERT(persist_wt_register_watch(&pwt, WT_KIND_FACTORY_NODE, 1,
                                       NULL, 0, 0, spk, 34, 0,
                                       "hex", response_txid, 0, 0) == -1,
           "NULL parent_txid rejected");
    ASSERT(persist_wt_register_watch(&pwt, WT_KIND_FACTORY_NODE, 1,
                                       parent_txid, 0, 0, NULL, 0, 0,
                                       "hex", response_txid, 0, 0) == -1,
           "zero-len spk rejected");

    /* Supersede + re-count */
    ASSERT(persist_wt_supersede_watch(&pwt, watch_id, 700000) == 1,
           "supersede succeeds");
    ASSERT(persist_wt_supersede_watch(&pwt, watch_id, 700001) == 0,
           "double-supersede no-ops");
    n = persist_wt_count_active_watches(&pwt);
    ASSERT(n == 0, "count_active = 0 after supersede");

    persist_wt_close(&pwt);
    cleanup_db();
    return 1;
}

int test_lsp_wt_register_factory_node_watch(void) {
    /* Phase 1b.2: thin LSP-side adapter that hex-encodes a signed-tx
       blob and delegates to persist_wt_register_watch.  This test
       checks: (a) the row appears, (b) the response_tx_hex column
       holds the lowercase hex of the input bytes, (c) NULL inputs
       are rejected. */
    cleanup_db();
    persist_wt_t pwt;
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "open");

    /* Sample signed-tx blob: 4 bytes for variety; helper hex-encodes
       to "deadbeef".  The exact value doesn't matter — only that the
       round-trip lands correctly. */
    unsigned char signed_tx[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    unsigned char parent_txid[32];   memset(parent_txid, 0x11, 32);
    unsigned char response_txid[32]; memset(response_txid, 0x22, 32);
    unsigned char spk[34];           memset(spk, 0x33, 34);

    int64_t watch_id = lsp_wt_register_factory_node_watch(&pwt,
        /* factory_id      */ 7,
        /* parent_txid32   */ parent_txid,
        /* parent_vout     */ 2,
        /* parent_value_sat*/ 500000,
        /* parent_spk      */ spk,
        /* parent_spk_len  */ sizeof(spk),
        /* csv_delay       */ 100,
        /* signed_tx       */ signed_tx,
        /* signed_tx_len   */ sizeof(signed_tx),
        /* response_txid32 */ response_txid,
        /* fee_bump_budget */ 1234,
        /* fee_bump_dline  */ 999999);
    ASSERT(watch_id > 0, "watch_id positive");

    /* Verify the response_tx_hex column got the lowercase hex form
       of {0xDE, 0xAD, 0xBE, 0xEF} -> "deadbeef". */
    sqlite3_stmt *st;
    const char *sql =
        "SELECT r.response_tx_hex FROM wt_watches w "
        "JOIN wt_responses r ON r.response_id = w.response_id "
        "WHERE w.watch_id = ?;";
    ASSERT(sqlite3_prepare_v2(pwt.db, sql, -1, &st, NULL) == SQLITE_OK, "prep join");
    sqlite3_bind_int64(st, 1, watch_id);
    ASSERT(sqlite3_step(st) == SQLITE_ROW, "row present");
    const char *hex = (const char *)sqlite3_column_text(st, 0);
    ASSERT(hex != NULL, "response_tx_hex not NULL");
    ASSERT(strcmp(hex, "deadbeef") == 0, "hex round-trip matches");
    sqlite3_finalize(st);

    /* Reject NULL pwt + NULL inputs. */
    ASSERT(lsp_wt_register_factory_node_watch(NULL, 1, parent_txid, 0, 0,
                                                spk, 34, 0,
                                                signed_tx, 4,
                                                response_txid, 0, 0) == -1,
           "NULL pwt rejected");
    ASSERT(lsp_wt_register_factory_node_watch(&pwt, 1, NULL, 0, 0,
                                                spk, 34, 0,
                                                signed_tx, 4,
                                                response_txid, 0, 0) == -1,
           "NULL parent_txid rejected");
    ASSERT(lsp_wt_register_factory_node_watch(&pwt, 1, parent_txid, 0, 0,
                                                spk, 34, 0,
                                                NULL, 4,
                                                response_txid, 0, 0) == -1,
           "NULL signed_tx rejected");
    ASSERT(lsp_wt_register_factory_node_watch(&pwt, 1, parent_txid, 0, 0,
                                                spk, 34, 0,
                                                signed_tx, 0,
                                                response_txid, 0, 0) == -1,
           "zero-len signed_tx rejected");

    persist_wt_close(&pwt);
    cleanup_db();
    return 1;
}

/* SF-WT-TRUSTLESS Phase 2c — list_by_kind iterator state for the
   round-trip test below.  Records per-kind row counts seen by the
   callback so we can ASSERT the iterator only visits matching rows. */
typedef struct {
    int n_factory;
    int n_subfactory;
    int n_commitment;
    int n_force_close;
    /* Capture last row's response_tx_hex + factory_id for shape checks. */
    char last_hex[128];
    uint32_t last_factory_id;
} kind_count_ctx_t;

static int kind_count_cb(uint32_t factory_id,
                          const unsigned char parent_txid32[32],
                          uint32_t parent_vout,
                          uint64_t parent_value_sat,
                          const unsigned char *parent_spk,
                          size_t parent_spk_len,
                          uint32_t csv_delay,
                          const char *response_tx_hex,
                          const unsigned char response_txid32[32],
                          uint64_t fee_bump_budget_sat,
                          uint32_t fee_bump_deadline_height,
                          void *user) {
    (void)parent_txid32; (void)parent_vout; (void)parent_value_sat;
    (void)parent_spk;    (void)parent_spk_len; (void)csv_delay;
    (void)response_txid32;
    (void)fee_bump_budget_sat; (void)fee_bump_deadline_height;
    kind_count_ctx_t *ctx = (kind_count_ctx_t *)user;
    ctx->last_factory_id = factory_id;
    if (response_tx_hex) {
        strncpy(ctx->last_hex, response_tx_hex, sizeof(ctx->last_hex) - 1);
        ctx->last_hex[sizeof(ctx->last_hex) - 1] = '\0';
    }
    return 1;
}

int test_persist_wt_kinds_round_trip(void) {
    /* Phase 2c: register one row of each kind via the LSP-side adapters
       and verify persist_wt_list_watches_by_kind returns exactly the
       matching rows.  Also verifies watch_kind is the only schema
       difference from v1. */
    cleanup_db();
    persist_wt_t pwt;
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "open");

    unsigned char parent[32]; memset(parent, 0x11, 32);
    unsigned char txid[32];   memset(txid,   0x22, 32);
    unsigned char spk[34];    memset(spk,    0x33, 34);
    unsigned char sigtx[4] = {0xCA, 0xFE, 0xBA, 0xBE};
    /* Each kind gets a different signed-tx blob so we can identify rows
       by their response_tx_hex content. */
    unsigned char sigtx_f[4]  = {0x01, 0x02, 0x03, 0x04}; /* "01020304" */
    unsigned char sigtx_sf[4] = {0x05, 0x06, 0x07, 0x08}; /* "05060708" */
    unsigned char sigtx_co[4] = {0x09, 0x0A, 0x0B, 0x0C}; /* "090a0b0c" */
    unsigned char sigtx_fc[4] = {0x0D, 0x0E, 0x0F, 0x10}; /* "0d0e0f10" */
    (void)sigtx;

    int64_t f_id  = lsp_wt_register_factory_node_watch(&pwt,    101, parent, 0, 1000, spk, 34, 0,
                                                       sigtx_f,  4, txid, 0, 0);
    int64_t sf_id = lsp_wt_register_subfactory_node_watch(&pwt, 202, parent, 0, 2000, spk, 34, 0,
                                                       sigtx_sf, 4, txid, 0, 0);
    int64_t co_id = lsp_wt_register_commitment_watch(&pwt,      303, parent, 1, 3000, spk, 34, 144,
                                                       sigtx_co, 4, txid);
    int64_t fc_id = lsp_wt_register_force_close_watch(&pwt,     404, parent, 2, 4000, spk, 34, 144,
                                                       sigtx_fc, 4, txid);
    ASSERT(f_id  > 0, "factory_node watch id > 0");
    ASSERT(sf_id > 0, "subfactory_node watch id > 0");
    ASSERT(co_id > 0, "commitment watch id > 0");
    ASSERT(fc_id > 0, "force_close watch id > 0");
    ASSERT(persist_wt_count_active_watches(&pwt) == 4, "4 total active");

    /* Iterate per kind and verify exactly one match each, with the
       expected response_tx_hex content. */
    kind_count_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    int v = persist_wt_list_watches_by_kind(&pwt, WT_KIND_FACTORY_NODE,
                                              kind_count_cb, &ctx);
    ASSERT(v == 1, "1 factory_node row");
    ASSERT(ctx.last_factory_id == 101, "factory_id round-trips for kind=0");
    ASSERT(strcmp(ctx.last_hex, "01020304") == 0, "factory_node hex matches");

    memset(&ctx, 0, sizeof(ctx));
    v = persist_wt_list_watches_by_kind(&pwt, WT_KIND_SUBFACTORY_NODE,
                                          kind_count_cb, &ctx);
    ASSERT(v == 1, "1 subfactory_node row");
    ASSERT(ctx.last_factory_id == 202, "factory_id round-trips for kind=1");
    ASSERT(strcmp(ctx.last_hex, "05060708") == 0, "subfactory_node hex matches");

    memset(&ctx, 0, sizeof(ctx));
    v = persist_wt_list_watches_by_kind(&pwt, WT_KIND_CHANNEL_COMMITMENT,
                                          kind_count_cb, &ctx);
    ASSERT(v == 1, "1 commitment row");
    ASSERT(ctx.last_factory_id == 303, "channel_id round-trips for kind=2");
    ASSERT(strcmp(ctx.last_hex, "090a0b0c") == 0, "commitment hex matches");

    memset(&ctx, 0, sizeof(ctx));
    v = persist_wt_list_watches_by_kind(&pwt, WT_KIND_FORCE_CLOSE_HTLC,
                                          kind_count_cb, &ctx);
    ASSERT(v == 1, "1 force_close row");
    ASSERT(ctx.last_factory_id == 404, "channel_id round-trips for kind=3");
    ASSERT(strcmp(ctx.last_hex, "0d0e0f10") == 0, "force_close hex matches");

    persist_wt_close(&pwt);
    cleanup_db();
    return 1;
}

int test_persist_wt_v1_to_v2_migration(void) {
    /* Phase 2c: create a wt.db at schema v1 manually (sqlite directly),
       then open via persist_wt_open and verify it migrates in-place to
       v2: watch_kind column exists with default 0, existing rows get
       watch_kind = 0, schema_version is bumped to 2. */
    cleanup_db();

    sqlite3 *raw = NULL;
    ASSERT(sqlite3_open(WT_TMP_PATH, &raw) == SQLITE_OK, "raw open");
    /* Hand-craft a minimal v1 schema. */
    const char *v1_ddl =
        "CREATE TABLE wt_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT INTO wt_meta (key, value) VALUES ('schema_version', '1');"
        "CREATE TABLE wt_responses ("
        "  response_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  response_tx_hex TEXT NOT NULL,"
        "  response_txid BLOB NOT NULL,"
        "  fee_bump_anchor BLOB,"
        "  fee_bump_budget INTEGER NOT NULL DEFAULT 0,"
        "  fee_bump_deadline INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE wt_watches ("
        "  watch_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  factory_id INTEGER NOT NULL,"
        "  parent_txid BLOB NOT NULL,"
        "  parent_vout INTEGER NOT NULL,"
        "  parent_value_sat INTEGER NOT NULL,"
        "  parent_spk BLOB NOT NULL,"
        "  csv_delay INTEGER NOT NULL,"
        "  response_id INTEGER NOT NULL,"
        "  superseded_at INTEGER,"
        "  registered_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
        "  FOREIGN KEY (response_id) REFERENCES wt_responses(response_id)"
        ");"
        "INSERT INTO wt_responses (response_tx_hex, response_txid)"
        "  VALUES ('aabb', x'1111111111111111111111111111111111111111111111111111111111111111');"
        "INSERT INTO wt_watches (factory_id, parent_txid, parent_vout, parent_value_sat,"
        "                         parent_spk, csv_delay, response_id)"
        "  VALUES (77, x'2222222222222222222222222222222222222222222222222222222222222222',"
        "          0, 10000, x'33333333', 0, 1);";
    char *err = NULL;
    int rc = sqlite3_exec(raw, v1_ddl, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("  v1 DDL err: %s\n", err ? err : "?");
        if (err) sqlite3_free(err);
        sqlite3_close(raw);
        return 0;
    }
    sqlite3_close(raw);

    /* Open via persist_wt_open — should migrate in place. */
    persist_wt_t pwt;
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "migrated open");

    /* watch_kind column now present, default 0 on existing row. */
    sqlite3_stmt *st;
    ASSERT(sqlite3_prepare_v2(pwt.db,
        "SELECT watch_kind FROM wt_watches WHERE watch_id = 1;", -1, &st, NULL) == SQLITE_OK,
        "select watch_kind from migrated row");
    ASSERT(sqlite3_step(st) == SQLITE_ROW, "row present");
    int kind = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    ASSERT(kind == 0, "migrated row has watch_kind = 0 (FACTORY_NODE default)");

    /* schema_version bumped to 2. */
    ASSERT(sqlite3_prepare_v2(pwt.db,
        "SELECT value FROM wt_meta WHERE key = 'schema_version';", -1, &st, NULL) == SQLITE_OK,
        "select schema_version");
    ASSERT(sqlite3_step(st) == SQLITE_ROW, "schema_version row present");
    const char *ver = (const char *)sqlite3_column_text(st, 0);
    ASSERT(ver && strcmp(ver, "2") == 0, "schema_version is 2 after migration");
    sqlite3_finalize(st);

    /* New rows can be added with non-zero kind. */
    unsigned char parent[32]; memset(parent, 0x44, 32);
    unsigned char txid[32];   memset(txid, 0x55, 32);
    unsigned char spk[34];    memset(spk, 0x66, 34);
    unsigned char sigtx[2] = {0xFF, 0xEE};
    int64_t new_id = lsp_wt_register_subfactory_node_watch(&pwt,
        999, parent, 0, 999, spk, 34, 0, sigtx, 2, txid, 0, 0);
    ASSERT(new_id > 0, "subfactory insert after migration");

    persist_wt_close(&pwt);
    cleanup_db();
    return 1;
}

int test_persist_wt_no_secrets_in_schema(void) {
    /* Trustless invariant: no column name in any wt_* table contains a
       secret keyword. Cheap belt-and-braces check that catches a future
       schema bump that smuggles in a key. */
    cleanup_db();
    persist_wt_t pwt;
    ASSERT(persist_wt_open(&pwt, WT_TMP_PATH) == 1, "open");

    sqlite3_stmt *st;
    const char *sql =
        "SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'wt_%';";
    ASSERT(sqlite3_prepare_v2(pwt.db, sql, -1, &st, NULL) == SQLITE_OK, "prep");
    int saw_secret = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *ddl = (const char *)sqlite3_column_text(st, 0);
        if (!ddl) continue;
        if (strstr(ddl, "secret") || strstr(ddl, "seckey") ||
            strstr(ddl, "private") || strstr(ddl, "revocation_secret")) {
            saw_secret = 1;
            printf("    secret-like column in WT DDL: %s\n", ddl);
        }
    }
    sqlite3_finalize(st);
    ASSERT(saw_secret == 0, "WT schema must not contain secret-like columns");

    persist_wt_close(&pwt);
    cleanup_db();
    return 1;
}
