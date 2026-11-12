/*
 * test_factory_recovery.c — force-close recovery over large persisted trees.
 *
 * The tree lives in an in-memory DB.  Every node is a real (unsigned,
 * minimal) serialized transaction spending output 0 of its parent, so
 * recovery reads outpoints, nSequence and nLockTime from the bytes as it
 * does on a real node.  The chain is a mock that enforces what a node
 * enforces: a transaction is accepted only while unconfirmed, only when its
 * parent is known and not spent by something else, only when the parent is
 * buried as deep as the child's relative timelock asks, and only once its
 * absolute height lock has passed.
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
/* Slots past the tree: other signed versions of the last node (a leaf kept
   from before an advance, and so on). */
#define FRT_SLOTS (FRT_NODES + 4)
#define FRT_LEAF  (FRT_NODES - 1)
#define FRT_FUNDING \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
#define FRT_HEIGHT0 200

/* Node i hangs under (i-1)/3; every second node carries a 2-block lock.
   The extra slots are versions of node FRT_LEAF. */
static int frt_parent(int i)
{
    if (i >= FRT_NODES) i = FRT_LEAF;
    return i == 0 ? -1 : (i - 1) / 3;
}
static uint32_t frt_nsequence(int i)
{
    if (i >= FRT_NODES) i = FRT_LEAF;
    return (i % 2) ? 2u : 0xFFFFFFFEu;
}
static int frt_lock(int i) { return (frt_nsequence(i) & 0x80000000u) ? 0 : (int)(frt_nsequence(i) & 0xFFFF); }

static char     g_txid[FRT_SLOTS][65];
static char     g_hex[FRT_SLOTS][128];
static uint32_t g_locktime[FRT_SLOTS];

static void frt_put_le(char *out, uint64_t v, int bytes)
{
    for (int b = 0; b < bytes; b++)
        sprintf(out + 2 * b, "%02x", (unsigned)((v >> (8 * b)) & 0xFF));
}

/* version 2 | 1 input (prev:0, empty script, nseq) | 1 output (amount, empty
   script) | locktime.  The amount carries the slot number. */
static void frt_tx_hex(const char *prev_display, uint32_t nseq, uint64_t amount,
                       uint32_t locktime, char out[128])
{
    char *o = out;
    o += sprintf(o, "0200000001");
    for (int i = 31; i >= 0; i--) {             /* outpoint, internal order */
        memcpy(o, prev_display + 2 * i, 2);
        o += 2;
    }
    o += sprintf(o, "0000000000");              /* vout 0, empty scriptSig */
    frt_put_le(o, nseq, 4); o += 8;
    o += sprintf(o, "01");
    frt_put_le(o, amount, 8); o += 16;
    o += sprintf(o, "00");
    frt_put_le(o, locktime, 4); o += 8;
    *o = '\0';
}

static int frt_hex_txid(const char *hex, char out[65])
{
    unsigned char b[64];
    size_t len = strlen(hex) / 2;
    if (len > sizeof(b)) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        b[i] = (unsigned char)v;
    }
    factory_recovery_tx_info_t ti;
    if (!factory_recovery_tx_info(b, len, &ti)) return 0;
    memcpy(out, ti.txid, 65);
    return 1;
}

/* Build every slot's transaction; parents come first, so their txids are
   known when a child is built. */
static int frt_build_txs(void)
{
    for (int i = 0; i < FRT_SLOTS; i++) {
        int par = frt_parent(i);
        frt_tx_hex(par < 0 ? FRT_FUNDING : g_txid[par], frt_nsequence(i),
                   (uint64_t)i, g_locktime[i], g_hex[i]);
        if (!frt_hex_txid(g_hex[i], g_txid[i])) return 0;
    }
    return 1;
}

static int frt_index_of_txid(const char *txid)
{
    if (!txid) return -1;
    if (strcmp(txid, FRT_FUNDING) == 0) return -2;
    for (int i = 0; i < FRT_SLOTS; i++)
        if (strcmp(txid, g_txid[i]) == 0) return i;
    return -1;
}

typedef struct {
    int confs[FRT_SLOTS];       /* -1 unknown, 0 mempool, >= 1 confirmed */
    int sends[FRT_SLOTS];       /* accepted broadcasts per slot */
    int attempts[FRT_SLOTS];    /* broadcast attempts per slot */
    int refuse;                 /* slot the mock never accepts, or -1 */
    int conflicted;             /* slot whose input another tx spent, or -1 */
    int funding_confs;
    int height;
} frt_chain_t;

static int frt_get_confirmations(chain_backend_t *self, const char *txid)
{
    frt_chain_t *c = (frt_chain_t *)self->ctx;
    int idx = frt_index_of_txid(txid);
    if (idx == -2) return c->funding_confs;
    if (idx < 0) return -1;
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

static int frt_get_block_height(chain_backend_t *self)
{
    return ((frt_chain_t *)self->ctx)->height;
}

/* Output 0 of txid: spent by another transaction if a child that conflicts
   is marked, unknown if txid is not known. */
static int frt_is_outpoint_unspent(chain_backend_t *self, const char *txid,
                                   uint32_t vout)
{
    frt_chain_t *c = (frt_chain_t *)self->ctx;
    (void)vout;
    int idx = frt_index_of_txid(txid);
    if (idx == -2) return 1;
    if (idx < 0 || c->confs[idx] < 0) return 0;
    if (c->conflicted >= 0 && frt_parent(c->conflicted) == idx) return 0;
    return 1;
}

static int frt_send_raw_tx(chain_backend_t *self, const char *tx_hex,
                           char *txid_out)
{
    frt_chain_t *c = (frt_chain_t *)self->ctx;
    int idx = -1;
    for (int i = 0; i < FRT_SLOTS && idx < 0; i++)
        if (strcmp(tx_hex, g_hex[i]) == 0) idx = i;
    if (idx < 0) return 0;
    c->attempts[idx]++;
    if (idx == c->refuse || idx == c->conflicted) return 0;
    if (c->confs[idx] >= 1) return 0;            /* already in a block */
    int par = frt_parent(idx);
    int par_confs = par < 0 ? c->funding_confs : c->confs[par];
    if (par_confs < 0) return 0;                 /* input missing */
    if (par_confs < frt_lock(idx)) return 0;     /* non-BIP68-final */
    if (g_locktime[idx] > (uint32_t)c->height) return 0;   /* non-final */
    c->confs[idx] = 0;                           /* (re)enters the mempool */
    c->sends[idx]++;
    if (txid_out) memcpy(txid_out, g_txid[idx], 65);
    return 1;
}

static void frt_mine(frt_chain_t *c)
{
    c->funding_confs++;
    c->height++;
    for (int i = 0; i < FRT_SLOTS; i++)
        if (c->confs[i] >= 0) c->confs[i]++;
}

static void frt_chain_init(chain_backend_t *be, frt_chain_t *c, int batch)
{
    memset(c, 0, sizeof(*c));
    c->refuse = -1;
    c->conflicted = -1;
    c->funding_confs = 6;
    c->height = FRT_HEIGHT0;
    for (int i = 0; i < FRT_SLOTS; i++) c->confs[i] = -1;
    memset(be, 0, sizeof(*be));
    be->get_confirmations = frt_get_confirmations;
    be->get_confirmations_batch = batch ? frt_get_confirmations_batch : NULL;
    be->get_block_height = frt_get_block_height;
    be->is_outpoint_unspent = frt_is_outpoint_unspent;
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

/* A factory row plus an n-node tree; channel_slot >= 0 adds this DB's
   channel funded by that slot, commit_slot >= 0 a signed commitment
   spending output 0 of that slot. */
static int frt_build_db(persist_t *db, int n, int channel_slot, int commit_slot)
{
    if (!frt_build_txs()) return 0;
    if (!persist_open(db, NULL)) return 0;
    if (!frt_exec(db,
            "INSERT INTO factories (id, n_participants, funding_txid, "
            "funding_vout, funding_amount, state) VALUES (0, 128, '"
            FRT_FUNDING "', 0, 12800000, 'active');"))
        return 0;
    if (!frt_exec(db, "BEGIN;")) return 0;
    for (int i = 0; i < n; i++) {
        char sql[640];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO tree_nodes (factory_id, node_index, type, "
                 "parent_index, parent_vout, nsequence, txid, is_built, "
                 "is_signed, signed_tx_hex) VALUES (0, %d, '%s', %d, 0, %u, "
                 "'%.64s', 1, 1, '%.127s');",
                 i, (i % 2) ? "state" : "kickoff", frt_parent(i),
                 frt_nsequence(i), g_txid[i], g_hex[i]);
        if (!frt_exec(db, sql)) return 0;
    }
    if (!frt_exec(db, "COMMIT;")) return 0;
    if (channel_slot >= 0) {
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO channels (id, factory_id, slot, local_amount, "
                 "remote_amount, funding_amount, funding_txid, funding_vout) "
                 "VALUES (0, 0, 0, 50000, 50000, 100000, '%.64s', 0);",
                 g_txid[channel_slot]);
        if (!frt_exec(db, sql)) return 0;
    }
    if (commit_slot >= 0) {
        char hex[128], sql[512];
        frt_tx_hex(g_txid[commit_slot], 0xFFFFFFFFu, 49000, 0, hex);
        snprintf(sql, sizeof(sql),
                 "INSERT INTO signed_commitments (channel_id, commitment_number, "
                 "sig64_hex, signed_tx_hex) VALUES (0, 3, '%0128d', '%s');",
                 0, hex);
        if (!frt_exec(db, sql)) return 0;
    }
    return 1;
}

/* Keep slot as an earlier version of node FRT_LEAF. */
static int frt_keep_leaf(persist_t *db, int slot, int node)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO client_funding_leaf (factory_id, node_index, txid, "
             "signed_tx_hex) VALUES (0, %d, '%.64s', '%.127s');",
             node, g_txid[slot], g_hex[slot]);
    return frt_exec(db, sql);
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

static int frt_attempts_total(const frt_chain_t *c)
{
    int n = 0;
    for (int i = 0; i < FRT_SLOTS; i++) n += c->attempts[i];
    return n;
}

/* A whole-tree force-close publishes every node of a 389-node tree. */
int test_factory_recovery_publishes_tree_beyond_128_nodes(void)
{
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, /* batch = */ 1);
    ASSERT(frt_build_db(&db, FRT_NODES, -1, -1), "build 389-node tree");

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
    const int leaf = FRT_LEAF;
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, /* batch = */ 0);
    ASSERT(frt_build_db(&db, FRT_NODES, leaf, leaf), "build tree + channel");

    char leaf_txid[65];
    ASSERT(factory_recovery_client_leaf(&db, 0, leaf_txid) == 1,
           "client leaf found in DB");
    ASSERT(strcmp(leaf_txid, g_txid[leaf]) == 0, "client leaf is node 388");

    int on_path[FRT_SLOTS] = {0};
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
    ASSERT(!res.retained_leaf, "the current leaf row is used");
    ASSERT(res.n_tree_nodes == FRT_NODES, "whole tree loaded");
    ASSERT(res.n_target == path_len, "target is exactly the path");
    ASSERT(c->confs[leaf] >= 0, "leaf node 388 is on chain or in mempool");
    ASSERT(frt_factory_state_is(&db, "active"),
           "one client's exit does not close the factory");
    for (int i = 0; i < FRT_SLOTS; i++) {
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
    const int leaf = FRT_LEAF;
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
        ASSERT(frt_build_db(&db, FRT_NODES, leaf, leaf), "build tree");
        ASSERT(frt_exec(&db, cases[k].sql), "damage tree");

        int failed = 1;
        for (int pass = 0; pass < 40 && failed; pass++) {
            memset(status, 0, sizeof(status));
            if (factory_recovery_run(&db, &be, 0,
                                     cases[k].use_leaf ? g_txid[leaf] : NULL,
                                     &res, status, sizeof(status)))
                failed = 0;
            if (res.published) failed = 0;
            frt_mine(c);
        }
        if (!failed) printf("  case: %s; status: %s\n", cases[k].what, status);
        ASSERT(failed, "damaged tree never reports success");
        ASSERT(strstr(status, "ERROR") != NULL, "status says ERROR");

        if (cases[k].use_leaf) {
            int sent = frt_attempts_total(c);
            if (sent) printf("  case: %s broadcast %d\n", cases[k].what, sent);
            ASSERT(sent == 0, "a broken exit path broadcasts nothing");
        }
        persist_close(&db);
    }

    /* A whole-tree run that fails part-way still reports its counts. */
    {
        persist_t db;
        frt_chain_init(&be, c, 1);
        ASSERT(frt_build_db(&db, FRT_NODES, -1, -1), "build tree");
        ASSERT(frt_exec(&db, "UPDATE tree_nodes SET signed_tx_hex = '' "
                             "WHERE node_index = 301;"), "damage tree");
        ASSERT(!factory_recovery_run(&db, &be, 0, NULL, &res, status,
                                     sizeof(status)), "run fails");
        ASSERT(strstr(status, "ERROR") && strstr(status, "; broadcast ") &&
               strstr(status, "of 389 confirmed"),
               "error status carries the counts");
        persist_close(&db);
    }

    /* The damaged DBs above are also visible to listfactories. */
    {
        persist_t db;
        frt_chain_init(&be, c, 1);
        ASSERT(frt_build_db(&db, FRT_NODES, -1, -1), "build tree");
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

/* A path node the network keeps refusing is never reported as published,
   and the refusal is told apart from a wait. */
int test_factory_recovery_refused_path_node_never_succeeds(void)
{
    const int leaf = FRT_LEAF;
    static const struct { int conflict; const char *why; } kinds[] = {
        { 0, "unspent" },          /* refused although its input is fine */
        { 1, "already spent" },    /* its input went to another transaction */
    };
    for (size_t k = 0; k < 2; k++) {
        persist_t db;
        chain_backend_t be;
        frt_chain_t *c = malloc(sizeof(*c));
        ASSERT(c, "alloc mock chain");
        frt_chain_init(&be, c, 1);
        ASSERT(frt_build_db(&db, FRT_NODES, leaf, leaf), "build tree + channel");
        int bad = frt_parent(leaf);   /* node 129 */
        ASSERT(bad >= 128, "refused node is above index 128");
        if (kinds[k].conflict) c->conflicted = bad; else c->refuse = bad;

        factory_recovery_result_t res;
        char status[512] = {0};
        int ever_published = 0;
        for (int pass = 0; pass < 40; pass++) {
            ASSERT(factory_recovery_run(&db, &be, 0, g_txid[leaf], &res, status,
                                        sizeof(status)), "pass runs");
            if (res.published) ever_published = 1;
            frt_mine(c);
        }
        ASSERT(!ever_published, "never published while a path node is refused");
        ASSERT(res.n_rejected == 1, "the refused node is reported as rejected");
        ASSERT(res.first_unpublished == bad, "the refused node is named");
        ASSERT(res.reject_node == bad, "the rejected node is named");
        if (!strstr(res.reject_why, kinds[k].why))
            printf("  reason: %s\n", res.reject_why);
        ASSERT(strstr(res.reject_why, kinds[k].why) != NULL,
               "the reason says why");
        ASSERT(c->confs[leaf] < 0, "leaf was never published");
        persist_close(&db);
        free(c);
    }
    return 1;
}

/* A node behind an absolute height lock waits for it; it is not rejected,
   and it is not even offered before the lock height. */
int test_factory_recovery_height_lock_waits(void)
{
    const int leaf = FRT_LEAF;
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, 1);
    g_locktime[leaf] = FRT_HEIGHT0 + 40;
    int built = frt_build_db(&db, FRT_NODES, leaf, leaf);
    if (!built) g_locktime[leaf] = 0;
    ASSERT(built, "build tree with a height-locked leaf");

    factory_recovery_result_t res;
    char status[512] = {0};
    int ok = 0;
    for (int pass = 0; pass < 64 && !ok; pass++) {
        ASSERT(factory_recovery_run(&db, &be, 0, g_txid[leaf], &res, status,
                                    sizeof(status)), "pass runs");
        ASSERT(res.n_rejected == 0, "a height lock is a wait, not a refusal");
        if (c->height < FRT_HEIGHT0 + 40)
            ASSERT(c->attempts[leaf] == 0, "not offered before the lock height");
        ok = res.published;
        frt_mine(c);
    }
    g_locktime[leaf] = 0;
    ASSERT(ok, "published once the lock height is reached");
    ASSERT(c->sends[leaf] == 1, "leaf broadcast once");
    persist_close(&db);
    free(c);
    return 1;
}

/* The exit leaf is the transaction the stored commitment spends, whatever
   the channel row says. */
int test_factory_recovery_exit_leaf_from_commitment(void)
{
    persist_t db;
    ASSERT(frt_build_db(&db, FRT_NODES, /* channel row */ 5, FRT_LEAF),
           "build tree, stale channel row, commitment on node 388");
    char leaf_txid[65];
    ASSERT(factory_recovery_client_leaf(&db, 0, leaf_txid) == 1, "leaf found");
    ASSERT(strcmp(leaf_txid, g_txid[FRT_LEAF]) == 0,
           "leaf is what the commitment spends");
    persist_close(&db);

    ASSERT(frt_build_db(&db, FRT_NODES, 7, -1), "no commitment");
    ASSERT(factory_recovery_client_leaf(&db, 0, leaf_txid) == 1, "leaf found");
    ASSERT(strcmp(leaf_txid, g_txid[7]) == 0,
           "without a commitment the channel row decides");
    persist_close(&db);
    return 1;
}

/* After an advance replaced the client's leaf in its tree, the exit
   publishes the kept copy its commitment spends, never the current row. */
int test_factory_recovery_kept_leaf_after_advance(void)
{
    const int kept = FRT_NODES;           /* an earlier version of node 388 */
    persist_t db;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    frt_chain_init(&be, c, 0);
    ASSERT(frt_build_db(&db, FRT_NODES, kept, kept), "build advanced tree");
    ASSERT(frt_keep_leaf(&db, kept, FRT_LEAF), "keep the funding leaf");

    char leaf_txid[65];
    ASSERT(factory_recovery_client_leaf(&db, 0, leaf_txid) == 1, "leaf found");
    ASSERT(strcmp(leaf_txid, g_txid[kept]) == 0, "leaf is the kept version");

    factory_recovery_result_t res;
    char status[512] = {0};
    int ok = frt_run_until_published(&db, &be, c, leaf_txid, &res, status,
                                     sizeof(status));
    if (!ok) printf("  status: %s\n", status);
    ASSERT(ok, "exit path through the kept leaf published");
    ASSERT(res.leaf_node == FRT_LEAF && res.retained_leaf,
           "reported as the kept version of node 388");
    ASSERT(c->confs[kept] >= 0, "kept leaf on chain or in mempool");
    ASSERT(c->attempts[FRT_LEAF] == 0, "the current row is never offered");
    for (int at = frt_parent(FRT_LEAF); at >= 0; at = frt_parent(at))
        ASSERT(c->sends[at] == 1, "every ancestor broadcast once");
    persist_close(&db);
    free(c);
    return 1;
}

/* An exit leaf that is neither in the tree nor kept is an error, and so is
   a kept copy that does not spend the node's parent; neither broadcasts. */
int test_factory_recovery_exit_leaf_missing_is_error(void)
{
    const int other = FRT_NODES + 1;
    const int wrong = FRT_NODES + 2;
    chain_backend_t be;
    frt_chain_t *c = malloc(sizeof(*c));
    ASSERT(c, "alloc mock chain");
    factory_recovery_result_t res;
    char status[512];

    persist_t db;
    frt_chain_init(&be, c, 1);
    ASSERT(frt_build_db(&db, FRT_NODES, other, other), "commitment on an unknown leaf");
    ASSERT(!factory_recovery_run(&db, &be, 0, g_txid[other], &res, status,
                                 sizeof(status)), "unknown leaf fails");
    ASSERT(strstr(status, "ERROR") && strstr(status, "moved past"),
           "status says the tree moved past the leaf");
    ASSERT(frt_attempts_total(c) == 0, "nothing broadcast");
    persist_close(&db);

    frt_chain_init(&be, c, 1);
    ASSERT(frt_build_db(&db, FRT_NODES, wrong, wrong), "build");
    /* Kept under the wrong node: it does not spend that node's parent. */
    ASSERT(frt_keep_leaf(&db, wrong, 50), "keep under node 50");
    ASSERT(!factory_recovery_run(&db, &be, 0, g_txid[wrong], &res, status,
                                 sizeof(status)), "mismatched copy fails");
    ASSERT(strstr(status, "ERROR") != NULL, "status says ERROR");
    ASSERT(frt_attempts_total(c) == 0, "nothing broadcast");
    persist_close(&db);

    free(c);
    return 1;
}
