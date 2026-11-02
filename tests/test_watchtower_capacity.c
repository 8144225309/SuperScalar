/* Watchtower capacity and registration-failure tests.

   1. More than 128 revoked commitments are all watched, all get a DB row,
      and all come back after a simulated restart (the table used to be a
      fixed 128 entries for the whole daemon, restart hydration stopped at
      128 rows, and registrations past the cap were dropped silently).
   2. A registration that fails because the table cannot grow leaves the
      previous entry untouched (it used to overwrite entries[n_entries-1]
      with the new penalty TX), and its DB row is still written.
   3. Rebuilding an old commitment whose HTLC snapshot is larger than the
      channel's current HTLC array grows the array instead of overflowing it.
*/

#include "superscalar/channel.h"
#include "superscalar/watchtower.h"
#include "superscalar/persist.h"
#include "superscalar/fee.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <secp256k1.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* LSP channel + client channel over the same funding output.  The client
   watches the LSP's revoked commitments, exactly like the client daemon. */
typedef struct {
    secp256k1_context *ctx;
    channel_t lsp_ch;
    channel_t client_ch;
    persist_t db;
    fee_estimator_static_t fee;
} wtc_fixture_t;

static int wtc_setup(wtc_fixture_t *f) {
    memset(f, 0, sizeof(*f));
    f->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char lsp_sec[32], client_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(client_sec, 0x22, 32);
    secp256k1_pubkey lsp_pk, client_pk;
    if (!secp256k1_ec_pubkey_create(f->ctx, &lsp_pk, lsp_sec)) return 0;
    if (!secp256k1_ec_pubkey_create(f->ctx, &client_pk, client_sec)) return 0;

    unsigned char funding_txid[32];
    memset(funding_txid, 0xAA, 32);
    unsigned char funding_spk[34] = {0x51, 0x20};
    memset(funding_spk + 2, 0xBB, 32);

    if (!channel_init(&f->lsp_ch, f->ctx, lsp_sec, &lsp_pk, &client_pk,
                      funding_txid, 0, 1000000, funding_spk, 34,
                      500000, 499846, 144)) return 0;
    if (!channel_init(&f->client_ch, f->ctx, client_sec, &client_pk, &lsp_pk,
                      funding_txid, 0, 1000000, funding_spk, 34,
                      499846, 500000, 144)) return 0;
    if (!channel_generate_random_basepoints(&f->lsp_ch)) return 0;
    if (!channel_generate_random_basepoints(&f->client_ch)) return 0;
    channel_set_remote_basepoints(&f->lsp_ch,
        &f->client_ch.local_payment_basepoint,
        &f->client_ch.local_delayed_payment_basepoint,
        &f->client_ch.local_revocation_basepoint);
    channel_set_remote_basepoints(&f->client_ch,
        &f->lsp_ch.local_payment_basepoint,
        &f->lsp_ch.local_delayed_payment_basepoint,
        &f->lsp_ch.local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(&f->lsp_ch, &f->client_ch.local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(&f->client_ch, &f->lsp_ch.local_htlc_basepoint);

    secp256k1_pubkey p;
    for (uint64_t cn = 0; cn < 2; cn++) {
        if (!channel_get_per_commitment_point(&f->lsp_ch, cn, &p)) return 0;
        channel_set_remote_pcp(&f->client_ch, cn, &p);
        if (!channel_get_per_commitment_point(&f->client_ch, cn, &p)) return 0;
        channel_set_remote_pcp(&f->lsp_ch, cn, &p);
    }

    if (!persist_open(&f->db, NULL)) return 0;
    fee_estimator_static_init(&f->fee, 1000);
    return 1;
}

static void wtc_teardown(wtc_fixture_t *f) {
    channel_cleanup(&f->lsp_ch);
    channel_cleanup(&f->client_ch);
    persist_close(&f->db);
    secp256k1_context_destroy(f->ctx);
}

/* The LSP revokes its commitment `cn`: the client stores the LSP's secret
   for cn (verified against the committed point) and the point for cn+1;
   both channels move to cn+1. */
static int wtc_revoke(wtc_fixture_t *f, uint64_t cn) {
    if (f->lsp_ch.n_local_pcs <= cn + 1 &&
        !channel_generate_local_pcs(&f->lsp_ch, cn + 1)) return 0;
    secp256k1_pubkey next;
    if (!channel_get_per_commitment_point(&f->lsp_ch, cn + 1, &next)) return 0;
    channel_set_remote_pcp(&f->client_ch, cn + 1, &next);
    f->lsp_ch.commitment_number = cn + 1;
    f->client_ch.commitment_number = cn + 1;
    unsigned char secret[32];
    if (!channel_get_revocation_secret(&f->lsp_ch, cn, secret)) return 0;
    int ok = channel_receive_revocation(&f->client_ch, cn, secret);
    secure_zero(secret, 32);
    return ok;
}

/* Register the LSP's revoked commitment `cn` with the client's watchtower,
   the way the client daemon does.  Returns the registration status. */
static int wtc_register(wtc_fixture_t *f, watchtower_t *wt, uint64_t cn,
                        const htlc_t *htlcs, size_t n_htlcs) {
    return watchtower_watch_revoked_commitment(wt, &f->client_ch, 0, cn,
        f->client_ch.local_amount, f->client_ch.remote_amount,
        htlcs, n_htlcs, NULL, 0);
}

static int wtc_count_rows(persist_t *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static const watchtower_entry_t *wtc_find(const watchtower_t *wt, uint64_t cn) {
    for (size_t i = 0; i < wt->n_entries; i++)
        if (wt->entries[i].type == WATCH_COMMITMENT && wt->entries[i].commit_num == cn)
            return &wt->entries[i];
    return NULL;
}

#define WTC_N 1000

/* 1000 revoked commitments (the old fixed table held 128 for the whole
   daemon) are all watched, all persisted, all re-armed on restart. */
int test_watchtower_watches_1000_revoked_commitments(void) {
    wtc_fixture_t f;
    TEST_ASSERT(wtc_setup(&f), "fixture");

    watchtower_t wt;
    TEST_ASSERT(watchtower_init(&wt, 1, NULL, (fee_estimator_t *)&f.fee, &f.db),
                "watchtower_init");

    int all_ok = 1;
    for (uint64_t cn = 0; cn < WTC_N; cn++) {
        TEST_ASSERT(wtc_revoke(&f, cn), "revoke");
        if (!wtc_register(&f, &wt, cn, NULL, 0)) all_ok = 0;
    }
    TEST_ASSERT(all_ok, "every registration reported success");
    TEST_ASSERT(wt.n_entries == WTC_N, "all 1000 revoked commitments in the table");

    /* Every one is armed: distinct txid and a pre-built penalty TX. */
    for (uint64_t cn = 0; cn < WTC_N; cn++) {
        const watchtower_entry_t *e = wtc_find(&wt, cn);
        TEST_ASSERT(e != NULL, "entry present for every commitment");
        TEST_ASSERT(e->signed_penalty_tx && e->signed_penalty_tx_len > 0,
                    "entry has its pre-built penalty TX");
        TEST_ASSERT(e->csv_delay == 144, "csv_delay stamped on the right entry");
    }
    TEST_ASSERT(memcmp(wt.entries[0].txid, wt.entries[WTC_N - 1].txid, 32) != 0,
                "entries watch distinct commitments");

    /* Every one has a DB row with its penalty bytes. */
    TEST_ASSERT(wtc_count_rows(&f.db, "SELECT COUNT(*) FROM old_commitments") == WTC_N,
                "1000 old_commitments rows");
    TEST_ASSERT(wtc_count_rows(&f.db, "SELECT COUNT(*) FROM old_commitments "
                               "WHERE signed_penalty_tx_hex != ''") == WTC_N,
                "1000 rows carry the penalty TX");

    /* Simulated restart: drop the in-memory table, hydrate from the DB. */
    watchtower_cleanup(&wt);
    watchtower_t wt2;
    TEST_ASSERT(watchtower_init(&wt2, 1, NULL, (fee_estimator_t *)&f.fee, &f.db),
                "watchtower_init after restart");
    TEST_ASSERT(wt2.n_entries == WTC_N, "restart hydration loads all 1000");
    for (uint64_t cn = 0; cn < WTC_N; cn++) {
        const watchtower_entry_t *e = wtc_find(&wt2, cn);
        TEST_ASSERT(e != NULL, "hydrated entry present for every commitment");
        TEST_ASSERT(e->signed_penalty_tx && e->signed_penalty_tx_len > 0,
                    "hydrated entry has its penalty TX");
    }
    watchtower_cleanup(&wt2);
    wtc_teardown(&f);
    return 1;
}

static void *wtc_failing_realloc(void *ptr, size_t size) {
    (void)ptr; (void)size;
    return NULL;
}

/* When the table cannot take another entry, the failed registration
   must leave entries[n_entries-1] (someone else's watch) untouched. */
int test_watchtower_failed_registration_keeps_last_entry(void) {
    wtc_fixture_t f;
    TEST_ASSERT(wtc_setup(&f), "fixture");

    watchtower_t wt;
    TEST_ASSERT(watchtower_init(&wt, 1, NULL, (fee_estimator_t *)&f.fee, &f.db),
                "watchtower_init");

    /* Fill the table to exactly its current capacity. */
    size_t cap = wt.entries_cap;
    TEST_ASSERT(cap > 0, "table has a capacity");
    for (uint64_t cn = 0; cn < cap; cn++) {
        TEST_ASSERT(wtc_revoke(&f, cn), "revoke");
        TEST_ASSERT(wtc_register(&f, &wt, cn, NULL, 0), "registration within capacity");
    }
    TEST_ASSERT(wt.n_entries == cap, "table full");

    /* Snapshot the last entry. */
    watchtower_entry_t *last = &wt.entries[cap - 1];
    TEST_ASSERT(last->signed_penalty_tx && last->signed_penalty_tx_len > 0,
                "last entry armed");
    size_t snap_len = last->signed_penalty_tx_len;
    unsigned char *snap = malloc(snap_len);
    TEST_ASSERT(snap != NULL, "snapshot alloc");
    memcpy(snap, last->signed_penalty_tx, snap_len);
    unsigned char snap_txid[32];
    memcpy(snap_txid, last->txid, 32);
    uint64_t snap_cn = last->commit_num;
    uint32_t snap_csv = last->csv_delay;

    /* The table cannot grow any more: the next registration fails. */
    wt.entries_realloc = wtc_failing_realloc;
    uint64_t next_cn = (uint64_t)cap;
    TEST_ASSERT(wtc_revoke(&f, next_cn), "revoke next");
    TEST_ASSERT(!wtc_register(&f, &wt, next_cn, NULL, 0),
                "registration that cannot be stored reports failure");

    last = &wt.entries[cap - 1];
    TEST_ASSERT(wt.n_entries == cap, "no entry added");
    TEST_ASSERT(last->commit_num == snap_cn, "last entry still watches its own commitment");
    TEST_ASSERT(memcmp(last->txid, snap_txid, 32) == 0, "last entry txid unchanged");
    TEST_ASSERT(last->csv_delay == snap_csv, "last entry csv_delay unchanged");
    TEST_ASSERT(last->signed_penalty_tx_len == snap_len &&
                memcmp(last->signed_penalty_tx, snap, snap_len) == 0,
                "last entry penalty TX not overwritten by the failed registration");
    free(snap);

    /* The failed registration's row was still written (independently of the
       in-memory table), with its penalty bytes, so a restart re-arms it. */
    {
        char sql[160];
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM old_commitments "
                 "WHERE commit_num = %llu AND signed_penalty_tx_hex != ''",
                 (unsigned long long)next_cn);
        TEST_ASSERT(wtc_count_rows(&f.db, sql) == 1,
                    "row for the failed in-memory registration is persisted");
    }
    wt.entries_realloc = NULL;
    watchtower_cleanup(&wt);

    watchtower_t wt2;
    TEST_ASSERT(watchtower_init(&wt2, 1, NULL, (fee_estimator_t *)&f.fee, &f.db),
                "watchtower_init after restart");
    TEST_ASSERT(wt2.n_entries == cap + 1, "restart re-arms every row, including the failed one");
    TEST_ASSERT(wtc_find(&wt2, next_cn) != NULL, "failed registration re-armed");
    watchtower_cleanup(&wt2);
    wtc_teardown(&f);
    return 1;
}

/* An old commitment whose HTLC snapshot is bigger than the channel's
   current HTLC array (the array is allocated for 64 and only grows when an
   HTLC is added) must be rebuilt with all its HTLC outputs. */
int test_watchtower_rebuild_grows_htlc_array(void) {
    wtc_fixture_t f;
    TEST_ASSERT(wtc_setup(&f), "fixture");
    TEST_ASSERT(wtc_revoke(&f, 0), "revoke");

    size_t cap_before = f.client_ch.htlcs_cap;
    size_t n_old = cap_before + 6;
    htlc_t *old = calloc(n_old, sizeof(htlc_t));
    TEST_ASSERT(old != NULL, "alloc snapshot");
    for (size_t i = 0; i < n_old; i++) {
        old[i].id = i;
        old[i].direction = (i % 2) ? HTLC_OFFERED : HTLC_RECEIVED;
        old[i].state = HTLC_STATE_ACTIVE;
        old[i].amount_sats = 1000 + i;
        memset(old[i].payment_hash, (int)(i + 1), 32);
        old[i].cltv_expiry = 500 + (uint32_t)i;
    }

    watchtower_t wt;
    TEST_ASSERT(watchtower_init(&wt, 1, NULL, (fee_estimator_t *)&f.fee, &f.db),
                "watchtower_init");
    size_t n_htlcs_before = f.client_ch.n_htlcs;
    TEST_ASSERT(wtc_register(&f, &wt, 0, old, n_old),
                "registration with a large HTLC snapshot succeeds");
    TEST_ASSERT(wt.n_entries == 1, "one entry");
    TEST_ASSERT(wt.entries[0].n_htlc_outputs == n_old, "every HTLC output recorded");
    TEST_ASSERT(f.client_ch.n_htlcs == n_htlcs_before, "channel HTLC state restored");
    {
        char sql[128];
        snprintf(sql, sizeof sql,
                 "SELECT COUNT(*) FROM old_commitment_htlcs WHERE commit_num = 0");
        TEST_ASSERT(wtc_count_rows(&f.db, sql) == (int)n_old, "HTLC output rows persisted");
    }
    free(old);
    watchtower_cleanup(&wt);
    wtc_teardown(&f);
    return 1;
}
