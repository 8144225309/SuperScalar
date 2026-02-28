/*
 * fuzz_persist_load.c — libFuzzer harness for persist_load_factory().
 *
 * Creates an in-memory SQLite database, inserts fuzz data as factory
 * rows, then calls persist_load_factory().  The loader must validate
 * gracefully and never crash on malformed data.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include <secp256k1.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return 0;

    persist_t p;
    memset(&p, 0, sizeof(p));

    /* Open in-memory database */
    if (!persist_open(&p, ":memory:"))
        return 0;

    /* Insert fuzz-derived factory row directly via SQL */
    {
        const char *sql =
            "INSERT OR REPLACE INTO factories "
            "(id, n_participants, funding_txid, funding_vout, funding_amount, "
            "step_blocks, states_per_layer, cltv_timeout, fee_per_tx, leaf_arity) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(p.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            /* Derive values from fuzz input */
            int n_part = (size >= 1) ? (data[0] % 20) : 2;
            uint32_t vout = (size >= 5) ? *(uint32_t *)(data + 1) : 0;
            int64_t amount = (size >= 13) ? *(int64_t *)(data + 5) : 0;
            int step = (size >= 15) ? *(uint16_t *)(data + 13) : 6;
            int states = (size >= 19) ? *(uint32_t *)(data + 15) : 4;
            int cltv = (size >= 23) ? *(uint32_t *)(data + 19) : 1000;
            int64_t fee = (size >= 31) ? *(int64_t *)(data + 23) : 300;
            int arity = (size >= 32) ? (data[31] % 3) : 2;

            /* Create a hex txid from remaining data */
            char txid_hex[65];
            memset(txid_hex, '0', 64);
            txid_hex[64] = '\0';
            size_t copy_len = (size - 32 > 64) ? 64 : size - 32;
            for (size_t i = 0; i < copy_len; i++) {
                const char hx[] = "0123456789abcdef";
                txid_hex[i] = hx[data[32 + i] & 0x0f];
            }

            sqlite3_bind_int(stmt, 1, n_part);
            sqlite3_bind_text(stmt, 2, txid_hex, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, (int)vout);
            sqlite3_bind_int64(stmt, 4, amount);
            sqlite3_bind_int(stmt, 5, step);
            sqlite3_bind_int(stmt, 6, states);
            sqlite3_bind_int(stmt, 7, cltv);
            sqlite3_bind_int64(stmt, 8, fee);
            sqlite3_bind_int(stmt, 9, arity);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    /* Attempt to load — should validate and not crash */
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        factory_t f;
        memset(&f, 0, sizeof(f));
        persist_load_factory(&p, 1, &f, ctx);
        secp256k1_context_destroy(ctx);
    }

    persist_close(&p);
    return 0;
}
