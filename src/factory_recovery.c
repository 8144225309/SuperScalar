/*
 * factory_recovery.c — startup recovery scan and CLI recovery for DW factories
 *
 * Queries the factories + tree_nodes tables directly via sqlite3, then uses
 * chain_backend_t to check confirmations and broadcast signed TXs.
 *
 * Design: topological broadcast (BFS passes).  A tree node is broadcastable
 * when its parent is confirmed (or, for the root/kickoff node, the factory
 * funding TX is confirmed).  Passes repeat until no new broadcasts occur.
 */

#include "superscalar/factory_recovery.h"
#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include <sqlite3.h>
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal node representation                                         */
/* ------------------------------------------------------------------ */

#define FR_MAX_NODES 128

typedef struct {
    int32_t  node_index;
    int32_t  parent_index;   /* -1 = root (no parent in this factory tree) */
    char     txid[65];
    char     type[16];       /* "kickoff", "state", "leaf", etc. */
    char    *signed_tx_hex;  /* heap-allocated; NULL if unsigned */
    int      confs;          /* -2=unchecked, -1=not found, 0=mempool, >=1=confirmed */
} fr_node_t;

static void fr_nodes_free(fr_node_t *nodes, int n)
{
    for (int i = 0; i < n; i++)
        free(nodes[i].signed_tx_hex);
}

/* ------------------------------------------------------------------ */
/* DB helpers                                                           */
/* ------------------------------------------------------------------ */

/* Load all tree nodes for factory_id.  Returns count, -1 on error. */
static int load_nodes_for_factory(sqlite3 *db, uint32_t factory_id,
                                  fr_node_t *nodes, int max)
{
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT node_index, parent_index, txid, type, signed_tx_hex "
        "FROM tree_nodes WHERE factory_id=? ORDER BY node_index ASC";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(stmt, 1, (int)factory_id);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max) {
        fr_node_t *nd = &nodes[count];
        memset(nd, 0, sizeof(*nd));

        nd->node_index = sqlite3_column_int(stmt, 0);

        if (sqlite3_column_type(stmt, 1) == SQLITE_NULL)
            nd->parent_index = -1;
        else
            nd->parent_index = sqlite3_column_int(stmt, 1);

        const char *txid = (const char *)sqlite3_column_text(stmt, 2);
        if (txid) strncpy(nd->txid, txid, sizeof(nd->txid) - 1);

        const char *type = (const char *)sqlite3_column_text(stmt, 3);
        if (type) strncpy(nd->type, type, sizeof(nd->type) - 1);

        const char *hex = (const char *)sqlite3_column_text(stmt, 4);
        if (hex && hex[0])
            nd->signed_tx_hex = strdup(hex);

        nd->confs = -2;
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

/* ------------------------------------------------------------------ */
/* Chain helpers                                                         */
/* ------------------------------------------------------------------ */

static int get_confs(chain_backend_t *chain, const char *txid)
{
    if (!chain || !txid || !txid[0]) return -1;
    return chain->get_confirmations(chain, txid);
}

static void refresh_confs(chain_backend_t *chain, fr_node_t *nodes, int n)
{
    for (int i = 0; i < n; i++) {
        nodes[i].confs = nodes[i].txid[0]
                         ? get_confs(chain, nodes[i].txid)
                         : -1;
    }
}

static fr_node_t *find_node(fr_node_t *nodes, int n, int32_t idx)
{
    for (int i = 0; i < n; i++)
        if (nodes[i].node_index == idx) return &nodes[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Broadcast                                                             */
/* ------------------------------------------------------------------ */

static int broadcast_node(chain_backend_t *chain, persist_t *p,
                           fr_node_t *node, uint32_t factory_id)
{
    (void)factory_id;
    if (!node->signed_tx_hex || !node->signed_tx_hex[0]) return 0;

    char result_txid[65] = {0};
    char source[40];
    snprintf(source, sizeof(source), "recovery_node_%d", node->node_index);

    int ok = chain->send_raw_tx(chain, node->signed_tx_hex, result_txid);

    /* Log every attempt (success or failure) to the broadcast audit table */
    const char *log_txid = result_txid[0] ? result_txid : node->txid;
    persist_log_broadcast(p, log_txid, source, node->signed_tx_hex,
                          ok ? "ok" : "failed");

    if (ok) {
        printf("LSP recovery: broadcast node %d type=%s txid=%.16s...\n",
               node->node_index, node->type,
               result_txid[0] ? result_txid : node->txid);
        fflush(stdout);
    } else {
        printf("LSP recovery: broadcast node %d FAILED (already confirmed?)\n",
               node->node_index);
        fflush(stdout);
    }
    return ok;
}

/* Check if all leaf nodes are confirmed (returns 0 if none found). */
static int all_leaves_confirmed(fr_node_t *nodes, int n)
{
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(nodes[i].type, "leaf") == 0) {
            found = 1;
            if (nodes[i].confs < 1) return 0;
        }
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* Core per-factory recovery                                            */
/* ------------------------------------------------------------------ */

/* Returns number of TXs broadcast. */
static int do_factory_recovery(persist_t *p, chain_backend_t *chain,
                                uint32_t factory_id, const char *funding_txid)
{
    fr_node_t nodes[FR_MAX_NODES];
    int n = load_nodes_for_factory(p->db, factory_id, nodes, FR_MAX_NODES);
    if (n <= 0) return 0;

    int funding_confs = get_confs(chain, funding_txid);
    refresh_confs(chain, nodes, n);

    int total_broadcast = 0;
    int progress = 1;
    while (progress) {
        progress = 0;
        for (int i = 0; i < n; i++) {
            fr_node_t *nd = &nodes[i];
            if (nd->confs >= 1) continue;    /* already confirmed */
            if (!nd->signed_tx_hex) continue; /* not yet signed — skip */

            /* Determine whether parent is confirmed */
            int parent_ok = 0;
            if (nd->parent_index < 0) {
                /* Root node: depends on the factory funding TX */
                parent_ok = (funding_confs >= 1);
            } else {
                fr_node_t *par = find_node(nodes, n, nd->parent_index);
                parent_ok = par && (par->confs >= 1);
            }
            if (!parent_ok) continue;

            int ok = broadcast_node(chain, p, nd, factory_id);
            if (ok) {
                /* Treat as in-mempool so children can be queued in same pass */
                nd->confs = 0;
                total_broadcast++;
                progress = 1;
            }
        }
    }

    /* Re-check confirmations after broadcasts and auto-close if done */
    refresh_confs(chain, nodes, n);
    if (all_leaves_confirmed(nodes, n)) {
        persist_mark_factory_closed(p, factory_id);
        printf("LSP recovery: factory %u fully settled — marked closed\n",
               factory_id);
        fflush(stdout);
    }

    fr_nodes_free(nodes, n);
    return total_broadcast;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int factory_recovery_scan(persist_t *p, chain_backend_t *chain)
{
    if (!p || !p->db || !chain) return 0;

    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT id, funding_txid, state FROM factories WHERE state != 'closed'";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t    fid   = (uint32_t)sqlite3_column_int(stmt, 0);
        const char *ftxid = (const char *)sqlite3_column_text(stmt, 1);
        const char *state = (const char *)sqlite3_column_text(stmt, 2);

        printf("LSP recovery: factory %u state=%s funding=%.16s...\n",
               fid, state ? state : "?", ftxid ? ftxid : "none");
        fflush(stdout);

        if (ftxid && ftxid[0])
            do_factory_recovery(p, chain, fid, ftxid);

        count++;
    }
    sqlite3_finalize(stmt);

    if (count > 0) {
        printf("LSP recovery: scanned %d non-closed factor%s\n",
               count, count == 1 ? "y" : "ies");
        fflush(stdout);
    }
    return count;
}

cJSON *factory_recovery_list(persist_t *p, chain_backend_t *chain)
{
    cJSON *arr = cJSON_CreateArray();
    if (!p || !p->db) return arr;

    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT id, funding_txid, funding_vout, funding_amount, state, created_at "
        "FROM factories ORDER BY id ASC";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return arr;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t    fid      = (uint32_t)sqlite3_column_int(stmt, 0);
        const char *ftxid    = (const char *)sqlite3_column_text(stmt, 1);
        int         fvout    = sqlite3_column_int(stmt, 2);
        int64_t     famount  = sqlite3_column_int64(stmt, 3);
        const char *state    = (const char *)sqlite3_column_text(stmt, 4);
        int64_t     created  = sqlite3_column_int64(stmt, 5);

        cJSON *fobj = cJSON_CreateObject();
        cJSON_AddNumberToObject(fobj, "factory_id",          (double)fid);
        cJSON_AddStringToObject(fobj, "funding_txid",        ftxid ? ftxid : "");
        cJSON_AddNumberToObject(fobj, "funding_vout",        (double)fvout);
        cJSON_AddNumberToObject(fobj, "funding_amount_sats", (double)famount);
        cJSON_AddStringToObject(fobj, "state",               state ? state : "unknown");
        cJSON_AddNumberToObject(fobj, "created_at",          (double)created);

        /* Tree node stats */
        fr_node_t nodes[FR_MAX_NODES];
        int n_nodes = load_nodes_for_factory(p->db, fid, nodes, FR_MAX_NODES);
        int n_confirmed = 0, n_leaf = 0, n_leaf_confirmed = 0;
        if (n_nodes > 0) {
            if (chain) refresh_confs(chain, nodes, n_nodes);
            for (int i = 0; i < n_nodes; i++) {
                if (chain && nodes[i].confs >= 1) n_confirmed++;
                if (strcmp(nodes[i].type, "leaf") == 0) {
                    n_leaf++;
                    if (chain && nodes[i].confs >= 1) n_leaf_confirmed++;
                }
            }
            fr_nodes_free(nodes, n_nodes);
        }
        cJSON_AddNumberToObject(fobj, "n_tree_nodes",        (double)(n_nodes < 0 ? 0 : n_nodes));
        cJSON_AddNumberToObject(fobj, "n_confirmed",         (double)n_confirmed);
        cJSON_AddNumberToObject(fobj, "n_leaf",              (double)n_leaf);
        cJSON_AddNumberToObject(fobj, "n_leaf_confirmed",    (double)n_leaf_confirmed);

        int fconfs = (chain && ftxid && ftxid[0]) ? get_confs(chain, ftxid) : -1;
        cJSON_AddNumberToObject(fobj, "funding_confs", (double)fconfs);

        cJSON_AddItemToArray(arr, fobj);
    }
    sqlite3_finalize(stmt);
    return arr;
}

int factory_recovery_run(persist_t *p, chain_backend_t *chain,
                         uint32_t factory_id,
                         char *status_out, size_t cap)
{
    if (!p || !p->db) {
        if (status_out && cap) snprintf(status_out, cap, "persist not available");
        return 0;
    }
    if (!chain) {
        if (status_out && cap) snprintf(status_out, cap, "no chain backend available");
        return 0;
    }

    sqlite3_stmt *stmt;
    const char *sql = "SELECT funding_txid, state FROM factories WHERE id=?";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        if (status_out && cap) snprintf(status_out, cap, "DB error");
        return 0;
    }
    sqlite3_bind_int(stmt, 1, (int)factory_id);

    char funding_txid[65] = {0};
    char state[16] = {0};
    int found = (sqlite3_step(stmt) == SQLITE_ROW);
    if (found) {
        const char *t = (const char *)sqlite3_column_text(stmt, 0);
        const char *s = (const char *)sqlite3_column_text(stmt, 1);
        if (t) strncpy(funding_txid, t, sizeof(funding_txid) - 1);
        if (s) strncpy(state, s, sizeof(state) - 1);
    }
    sqlite3_finalize(stmt);

    if (!found) {
        if (status_out && cap)
            snprintf(status_out, cap, "factory %u not found", factory_id);
        return 0;
    }

    int n = do_factory_recovery(p, chain, factory_id, funding_txid);
    if (status_out && cap) {
        snprintf(status_out, cap, "factory %u (state=%s): broadcast %d TX%s",
                 factory_id, state[0] ? state : "?", n, n == 1 ? "" : "s");
    }
    return n > 0 ? 1 : 0;
}
