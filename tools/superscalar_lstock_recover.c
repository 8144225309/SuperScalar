/*
 * superscalar_lstock_recover: assemble the broadcastable hashlock L-stock
 * poison from a CLIENT's persisted reveal (l_stock_poison_reveals), for the
 * #53 trustless recourse path.
 *
 * After a leaf advance the LSP reveals its per-(leaf,state) secret to the
 * client (MSG_LSTOCK_REVEAL); the client verifies SHA256(secret)==H_old and
 * persists it alongside the co-signed Leaf-P poison template.  If the LSP later
 * broadcasts that SUPERSEDED leaf state to over-claim its L-stock, the client
 * (or a watchtower the client feeds revealed secrets to) loads the row here and
 * assembles the witness [agg_sig, secret(preimage), Leaf-P script, control
 * block] via factory_assemble_poison_from_template, then broadcasts it to
 * redirect the L-stock to the clients.
 *
 * Output: the complete poison tx hex on stdout (the caller broadcasts it, e.g.
 * `bitcoin-cli sendrawtransaction $(superscalar_lstock_recover ...)`).
 * Exit codes: 0 = hex printed; 4 = no poison row; 5 = secret not yet revealed
 * (the anti-vacuity guarantee: no reveal, no recourse); other = usage/IO error.
 *
 * This models the CLIENT's recourse — the secret-less standalone watchtower
 * cannot assemble a hashlock poison on its own (see #62).
 *
 * Usage:
 *   superscalar_lstock_recover --db <client.db>
 *       [--factory-id N] --node-idx N --state N
 */
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

static void usage(const char *a0) {
    fprintf(stderr,
        "Usage: %s --db PATH [--factory-id N] --node-idx N --state N\n"
        "  Assembles the hashlock L-stock poison from the persisted reveal and\n"
        "  prints the tx hex.  Exits non-zero if no secret was revealed.\n", a0);
}

int main(int argc, char **argv) {
    const char *db_path = NULL;
    long factory_id = 0;
    long node_idx = -1;
    long state = -1;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--db")         && i+1 < argc) db_path    = argv[++i];
        else if (!strcmp(argv[i], "--factory-id") && i+1 < argc) factory_id = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--node-idx")   && i+1 < argc) node_idx   = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--state")      && i+1 < argc) state      = strtol(argv[++i], NULL, 10);
        else { usage(argv[0]); return 2; }
    }
    if (!db_path || node_idx < 0 || state < 0) { usage(argv[0]); return 2; }

    persist_t db;
    if (!persist_open(&db, db_path)) {
        fprintf(stderr, "lstock-recover: cannot open db %s\n", db_path);
        return 3;
    }

    unsigned char hash32[32], agg_sig64[64], secret32[32];
    unsigned char leaf_script[128], control_block[65];
    size_t leaf_script_len = 0, control_block_len = 0;
    int has_secret = 0;
    tx_buf_t unsigned_tx; tx_buf_init(&unsigned_tx, 256);

    int loaded = persist_load_l_stock_poison(&db, (uint32_t)factory_id,
                    (uint32_t)node_idx, (uint32_t)state,
                    hash32, agg_sig64, &unsigned_tx,
                    leaf_script, &leaf_script_len,
                    control_block, &control_block_len,
                    secret32, &has_secret);
    if (!loaded) {
        fprintf(stderr, "lstock-recover: no poison row for factory=%ld node=%ld state=%ld\n",
                factory_id, node_idx, state);
        tx_buf_free(&unsigned_tx); persist_close(&db); return 4;
    }
    if (!has_secret) {
        fprintf(stderr, "lstock-recover: secret NOT yet revealed for node=%ld state=%ld"
                        " -- no recourse (anti-vacuity)\n", node_idx, state);
        tx_buf_free(&unsigned_tx); persist_close(&db); return 5;
    }

    tx_buf_t poison; tx_buf_init(&poison, 256);
    int ok = factory_assemble_poison_from_template(
                 unsigned_tx.data, unsigned_tx.len,
                 agg_sig64, secret32, hash32,
                 leaf_script, leaf_script_len,
                 control_block, control_block_len,
                 &poison);
    if (!ok || poison.len == 0) {
        fprintf(stderr, "lstock-recover: assembly failed (hash guard or bad template)\n");
        tx_buf_free(&poison); tx_buf_free(&unsigned_tx); persist_close(&db); return 6;
    }

    char *hex = (char *)malloc(poison.len * 2 + 1);
    if (!hex) { tx_buf_free(&poison); tx_buf_free(&unsigned_tx); persist_close(&db); return 7; }
    hex_encode(poison.data, poison.len, hex);
    printf("%s\n", hex);
    free(hex);

    tx_buf_free(&poison);
    tx_buf_free(&unsigned_tx);
    persist_close(&db);
    return 0;
}
