/* Unit tests for include/superscalar/persist_wt.h (Phase 1a). */

#include "superscalar/persist_wt.h"
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
    ASSERT(persist_wt_register_watch(&pwt, 1, NULL, 0, 0, spk, 34, 0,
                                       "hex", response_txid, 0, 0) == -1,
           "NULL parent_txid rejected");
    ASSERT(persist_wt_register_watch(&pwt, 1, parent_txid, 0, 0, NULL, 0, 0,
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
