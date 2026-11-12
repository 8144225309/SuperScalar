/*
 * test_factory_recovery.c — force-close recovery over large persisted trees.
 *
 * The tree lives in an in-memory DB and the chain is a mock that enforces
 * what a node enforces: a transaction is accepted only while unconfirmed,
 * only when its parent is known, and only when the parent is buried as deep
 * as the child's relative timelock asks.
 */

#include "superscalar/factory_recovery.h"
#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include <sqlite3.h>
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* 389 tree transactions is what a 127-client factory with one client per
   leaf produces. */
#define FRT_NODES 389
#define FRT_FUNDING \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

typedef struct {
    int n;
    int confs[FRT_NODES];       /* -1 unknown, 0 mempool, >= 1 confirmed */
    int sends[FRT_NODES];       /* accepted broadcasts per node */
    int attempts[FRT_NODES];    /* broadcast attempts per node */
    int refuse;                 /* node the mock never accepts, or -1 */
    int funding_confs;
} frt_chain_t;

/* Node i hangs under (i-1)/3; every second node carries a 2-block lock. */
static int frt_parent(int i) { return i == 0 ? -1 : (i - 1) / 3; }
static uint32_t frt_nsequence(int i) { return (i % 2) ? 2u : 0xFFFFFFFEu; }
static int frt_lock(int i) { return (i % 2) ? 2 : 0; }

static void frt_txid(int i, char out[65])
{
    snprintf(out, 65, "%056d%08x", 0, (unsigned)i);
}

static void frt_hex(int i, char out[32])
{
    snprintf(out, 32, "02000000%08x00000000", (unsigned)i);
}

static int frt_index_of_txid(const char *txid)
{
    unsigned idx = 0;
    if (!txid || strlen(txid) != 64) return -1;
    if (strncmp(txid, FRT_FUNDING, 64) == 0) return -2;
    if (sscanf(txid + 56, "%8x", &idx) != 1) return -1;
    return (int)idx;
}

static int frt_get_confirmations(chain_backend_t *self, const char *txid)
{
    frt_chain_t *c = (frt_chain_t *)self->ctx;
    int idx = frt_index_of_txid(txid);
    if (idx == -2) return c->funding_confs;
    if (idx < 0 || idx >= c->n) return -1;
    return c->confs[idx];
}

static int frt_get_confirmations_batch(chain_backend_t *self,
                                       const char **txids, size_t n,
                                       int *confs_out)
{
    for (size_t i = 0; i < n; i++)
        confs_out[i] = frt_get_confirmations(self, txids[i]);
    return 1;
}

static int frt_send_raw_tx(chain_backend_t *self, const char *tx_hex,
                           char *txid_out)
{
    frt_chain_t *c = (frt_chain_t *)self->ctx;
    unsigned idx = 0;
    if (!tx_hex || strlen(tx_hex) != 24 || sscanf(tx_hex + 8, "%8x", &idx) != 1)
        return 0;
    if ((int)idx >= c->n) return 0;
    c->attempts[idx]++;
    if ((int)idx == c->refuse) return 0;
    if (c->confs[idx] >= 1) return 0;            /* already in a block */
    int par = frt_parent((int)idx);
    int par_confs = par < 0 ? c->funding_confs : c->confs[par];
    if (par_confs < 0) return 0;                 /* input missing */
    if (par_confs < frt_lock((int)idx)) return 0; /* non-BIP68-final */
    c->confs[idx] = 0;                           /* (re)enters the mempool */
    c->sends[idx]++;
    if (txid_out) frt_txid((int)idx, txid_out);
    return 1;
}

static void frt_mine(frt_chain_t *c)
{
    c->funding_confs++;
    for (int i = 0; i < c->n; i++)
        if (c->confs[i] >= 0) c->confs[i]++;
}

static void frt_chain_init(chain_backend_t *be, frt_chain_t *c, int batch)
{
    memset(c, 0, sizeof(*c));
    c->n = FRT_NODES;
    c->refuse = -1;
    c->funding_confs = 6;
    for (int i = 0; i < FRT_NODES; i++) c->confs[i] = -1;
    memset(be, 0, sizeof(*be));
    be->get_confirmations = frt_get_confirmations;
    be->get_confirmations_batch = batch ? frt_get_confirmations_batch : NULL;
    be->send_raw_tx = frt_send_raw_tx;
    be->is_regtest = 1;
    be->ctx = c;
}

static int frt_exec(persist_t *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("  SQL failed: %s: %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return 0;
    }
    return 1;
}

/* A factory row plus an n-node tree; leaf_node >= 0 adds this DB's channel. */
static int frt_build_db(persist_t *db, int n, int leaf_node)
{
    if (!persist_open(db, NULL)) return 0;
    if (!frt_exec(db,
            "INSERT INTO factories (id, n_participants, funding_txid, "
            "funding_vout, funding_amount, state) VALUES (0, 128, '"
            FRT_FUNDING "', 0, 12800000, 'active');"))
        return 0;
    if (!frt_exec(db, "BEGIN;")) return 0;
    for (int i = 0; i < n; i++) {
        char txid[65], hex[32], sql[512];
        frt_txid(i, txid);
        frt_hex(i, hex);
        snprintf(sql, sizeof(sql),
                 "INSERT INTO tree_nodes (factory_id, node_index, type, "
                 "parent_index, parent_vout, nsequence, txid, is_built, "
                 "is_signed, signed_tx_hex) VALUES (0, %d, '%s', %d, 0, %u, "
                 "'%s', 1, 1, '%s');",
                 i, (i % 2) ? "state" : "kickoff", frt_parent(i),
                 frt_nsequence(i), txid, hex);
        if (!frt_exec(db, sql)) return 0;
    }
    if (!frt_exec(db, "COMMIT;")) return 0;
    if (leaf_node >= 0) {
        char txid[65], sql[512];
        frt_txid(leaf_node, txid);
        snprintf(sql, sizeof(sql),
                 "INSERT INTO channels (id, factory_id, slot, local_amount, "
                 "remote_amount, funding_amount, funding_txid, funding_vout) "
                 "VALUES (0, 0, 0, 50000, 50000, 100000, '%s', 0);", txid);
        if (!frt_exec(db, sql)) return 0;
    }
    return 1;
}

static int frt_state_cb(void *out, int n, char **vals, char **cols)
{
    (void)cols;
    if (n > 0 && vals[0]) snprintf((char *)out, 16, "%s", vals[0]);
    return 0;
}

/* The factory row's state column. */
static int frt_factory_state_is(persist_t *db, const char *want)
{
    char state[16] = {0};
    sqlite3_exec(db->db, "SELECT state FROM factories WHERE id=0;",
                 frt_state_cb, state, NULL);
    return strcmp(state, want) == 0;
}

/* Run passes, one block apart, until the run reports itself published. */
static int frt_run_until_published(persist_t *db, chain_backend_t *be,
                                   frt_chain_t *c, const char *leaf,
                                   factory_recovery_result_t *res,
                                   char *status, size_t cap)
{
    for (int pass = 0; pass < 64; pass++) {
        if (!factory_recovery_run(db, be, 0, leaf, res, status, cap))
            return 0;
        if (res->published) return 1;
        frt_mine(c);
    }
    return 0;
}

/* A whole-tree force-close publishes every node of a 389-node tree. */
int test_factory_recovery_publishes_tree_beyond_128_nodes(void)
{
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, /* batch = */ 1);
    ASSERT(frt_build_db(&db, FRT_NODES, -1), "build 389-node tree");

    factory_recovery_result_t res;
    char status[512] = {0};
    ASSERT(factory_recovery_run(&db, &be, 0, NULL, &res, status,
                                sizeof(status)), "first pass runs");
    ASSERT(frt_factory_state_is(&db, "active"),
           "factory stays active while leaves are unconfirmed");
    frt_mine(c);
    int ok = frt_run_until_published(&db, &be, c, NULL, &res, status,
                                     sizeof(status));
    if (!ok) printf("  status: %s\n", status);
    ASSERT(ok, "whole tree published");
    ASSERT(res.n_tree_nodes == FRT_NODES, "all 389 nodes loaded");
    ASSERT(res.n_target == FRT_NODES, "all 389 nodes are targets");
    ASSERT(res.n_confirmed + res.n_in_mempool == FRT_NODES,
           "all 389 nodes accounted for");
    ASSERT(res.n_waiting == 0 && res.n_rejected == 0, "nothing left over");
    for (int i = 0; i < FRT_NODES; i++) {
        if (c->sends[i] != 1) printf("  node %d sent %d times\n", i, c->sends[i]);
        ASSERT(c->sends[i] == 1, "every node broadcast exactly once");
    }

    /* Once every leaf (a state node nobody spends) is confirmed, the scan
       marks the factory closed. */
    frt_mine(c);
    ASSERT(frt_factory_state_is(&db, "active"), "not closed before the scan");
    factory_recovery_scan(&db, &be);
    ASSERT(frt_factory_state_is(&db, "closed"),
           "factory closed once all leaves are confirmed");

    /* listfactories reports the same tree. */
    cJSON *list = factory_recovery_list(&db, &be);
    cJSON *f0 = cJSON_GetArrayItem(list, 0);
    cJSON *nn = f0 ? cJSON_GetObjectItem(f0, "n_tree_nodes") : NULL;
    cJSON *nl = f0 ? cJSON_GetObjectItem(f0, "n_leaf") : NULL;
    cJSON *nc = f0 ? cJSON_GetObjectItem(f0, "n_leaf_confirmed") : NULL;
    int listed = (nn && cJSON_IsNumber(nn)) ? nn->valueint : -1;
    int leaves = (nl && cJSON_IsNumber(nl)) ? nl->valueint : -1;
    int leaves_conf = (nc && cJSON_IsNumber(nc)) ? nc->valueint : -1;
    cJSON_Delete(list);
    ASSERT(listed == FRT_NODES, "listfactories counts all 389 nodes");
    ASSERT(leaves == 129, "129 childless state nodes are leaves");
    ASSERT(leaves_conf == leaves, "every leaf is reported confirmed");

    persist_close(&db);
    free(c);
    return 1;
}

/* A client whose leaf is node 388 gets its whole path, and only its path. */
int test_factory_recovery_client_path_above_128(void)
{
    const int leaf = FRT_NODES - 1;
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, /* batch = */ 0);
    ASSERT(frt_build_db(&db, FRT_NODES, leaf), "build tree + channel");

    char leaf_txid[65], want[65];
    frt_txid(leaf, want);
    ASSERT(factory_recovery_client_leaf(&db, 0, leaf_txid) == 1,
           "client leaf found in DB");
    ASSERT(strcmp(leaf_txid, want) == 0, "client leaf is node 388");

    int on_path[FRT_NODES] = {0};
    int path_len = 0, above_128 = 0;
    for (int at = leaf; at >= 0; at = frt_parent(at)) {
        on_path[at] = 1;
        path_len++;
        if (at >= 128) above_128++;
    }
    ASSERT(above_128 >= 2, "path crosses node index 128");

    /* The first pass can only publish the root: not finished yet. */
    factory_recovery_result_t res;
    char status[512] = {0};
    ASSERT(factory_recovery_run(&db, &be, 0, leaf_txid, &res, status,
                                sizeof(status)), "first pass runs");
    ASSERT(!res.published, "one pass does not finish a timelocked path");
    ASSERT(res.n_waiting > 0, "unpublished path nodes are reported waiting");
    ASSERT(res.first_unpublished >= 0, "next unpublished node is named");
    frt_mine(c);

    int ok = frt_run_until_published(&db, &be, c, leaf_txid, &res, status,
                                     sizeof(status));
    if (!ok) printf("  status: %s\n", status);
    ASSERT(ok, "exit path published");
    ASSERT(res.leaf_node == leaf, "leaf node resolved");
    ASSERT(res.n_tree_nodes == FRT_NODES, "whole tree loaded");
    ASSERT(res.n_target == path_len, "target is exactly the path");
    ASSERT(c->confs[leaf] >= 0, "leaf node 388 is on chain or in mempool");
    ASSERT(frt_factory_state_is(&db, "active"),
           "one client's exit does not close the factory");
    for (int i = 0; i < FRT_NODES; i++) {
        if (on_path[i]) {
            ASSERT(c->sends[i] == 1, "every path node broadcast once");
        } else {
            ASSERT(c->attempts[i] == 0, "nothing off the path is broadcast");
        }
    }

    persist_close(&db);
    free(c);
    return 1;
}

/* A persisted tree with part of it missing is an error, never a success. */
int test_factory_recovery_incomplete_tree_is_error(void)
{
    const int leaf = FRT_NODES - 1;
    char leaf_txid[65];
    frt_txid(leaf, leaf_txid);
    factory_recovery_result_t res;
    char status[512];
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");

    static const struct {
        const char *what;
        const char *sql;
        int use_leaf;
    } cases[] = {
        { "node missing in the middle",
          "DELETE FROM tree_nodes WHERE node_index = 200;", 0 },
        { "node missing in the middle, exit path",
          "DELETE FROM tree_nodes WHERE node_index = 200;", 1 },
        { "first node missing",
          "DELETE FROM tree_nodes WHERE node_index = 0;", 0 },
        { "tree cut off at 128 nodes, exit path",
          "DELETE FROM tree_nodes WHERE node_index >= 128;", 1 },
        { "parent outside the tree",
          "UPDATE tree_nodes SET parent_index = 5000 WHERE node_index = 300;", 0 },
        { "parent cycle",
          "UPDATE tree_nodes SET parent_index = 129 WHERE node_index = 42;", 1 },
        { "path node without a signed transaction",
          "UPDATE tree_nodes SET signed_tx_hex = NULL WHERE node_index = 129;", 1 },
        { "tree node without a signed transaction",
          "UPDATE tree_nodes SET signed_tx_hex = '' WHERE node_index = 301;", 0 },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        persist_t db;
        frt_chain_init(&be, c, /* batch = */ (int)(k & 1));
        ASSERT(frt_build_db(&db, FRT_NODES, leaf), "build tree");
        ASSERT(frt_exec(&db, cases[k].sql), "damage tree");

        int failed = 1;
        for (int pass = 0; pass < 40 && failed; pass++) {
            memset(status, 0, sizeof(status));
            if (factory_recovery_run(&db, &be, 0,
                                     cases[k].use_leaf ? leaf_txid : NULL,
                                     &res, status, sizeof(status)))
                failed = 0;
            if (res.published) failed = 0;
            frt_mine(c);
        }
        if (!failed) printf("  case: %s; status: %s\n", cases[k].what, status);
        ASSERT(failed, "damaged tree never reports success");
        ASSERT(strstr(status, "ERROR") != NULL, "status says ERROR");

        if (cases[k].use_leaf) {
            int sent = 0;
            for (int i = 0; i < FRT_NODES; i++) sent += c->attempts[i];
            if (sent) printf("  case: %s broadcast %d\n", cases[k].what, sent);
            ASSERT(sent == 0, "a broken exit path broadcasts nothing");
        }
        persist_close(&db);
    }

    /* The damaged DBs above are also visible to listfactories. */
    {
        persist_t db;
        frt_chain_init(&be, c, 1);
        ASSERT(frt_build_db(&db, FRT_NODES, -1), "build tree");
        ASSERT(frt_exec(&db, "DELETE FROM tree_nodes WHERE node_index = 200;"),
               "damage tree");
        cJSON *list = factory_recovery_list(&db, &be);
        cJSON *f0 = cJSON_GetArrayItem(list, 0);
        int has_err = f0 && cJSON_IsString(cJSON_GetObjectItem(f0, "tree_error"));
        cJSON_Delete(list);
        ASSERT(has_err, "listfactories reports the incomplete tree");
        persist_close(&db);
    }

    free(c);
    return 1;
}

/* A path node the network keeps refusing is never reported as published. */
int test_factory_recovery_refused_path_node_never_succeeds(void)
{
    const int leaf = FRT_NODES - 1;
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, 1);
    ASSERT(frt_build_db(&db, FRT_NODES, leaf), "build tree + channel");
    c->refuse = frt_parent(leaf);   /* node 129 */
    ASSERT(c->refuse >= 128, "refused node is above index 128");

    char leaf_txid[65];
    frt_txid(leaf, leaf_txid);
    factory_recovery_result_t res;
    char status[512] = {0};
    int ever_published = 0;
    for (int pass = 0; pass < 40; pass++) {
        ASSERT(factory_recovery_run(&db, &be, 0, leaf_txid, &res, status,
                                    sizeof(status)), "pass runs");
        if (res.published) ever_published = 1;
        frt_mine(c);
    }
    ASSERT(!ever_published, "never published while a path node is refused");
    ASSERT(res.n_rejected == 1, "the refused node is reported as rejected");
    ASSERT(res.first_unpublished == c->refuse, "the refused node is named");
    ASSERT(c->confs[leaf] < 0, "leaf was never published");

    persist_close(&db);
    free(c);
    return 1;
}
