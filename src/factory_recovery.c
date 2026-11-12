/*
 * factory_recovery.c — startup recovery scan and CLI recovery for DW factories
 *
 * Queries the factories + tree_nodes tables directly via sqlite3, then uses
 * chain_backend_t to check confirmations and broadcast signed TXs.
 *
 * Design: topological broadcast (BFS passes).  A tree node is broadcastable
 * when its parent is confirmed (or, for the root/kickoff node, the factory
 * funding TX is confirmed).  Passes repeat until no new broadcasts occur.
 *
 * The node set is sized from the persisted tree itself.  A tree that cannot
 * be loaded completely is an error, never a shorter tree.
 */

#include "superscalar/factory_recovery.h"
#include "superscalar/cpfp.h"
#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include "superscalar/tx_builder.h"
#include "superscalar/tapscript.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/types.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <sqlite3.h>
#include <cJSON.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* Internal node representation                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    int32_t  node_index;
    int32_t  parent_index;   /* -1 = root (no parent in this factory tree) */
    uint32_t nsequence;      /* nSequence of the node's input */
    char     txid[65];
    char     type[16];       /* "kickoff" or "state" */
    char    *signed_tx_hex;  /* heap-allocated; NULL if unsigned */
    int      confs;          /* -2=unchecked, -1=not found, 0=mempool, >=1=confirmed */
    int      target;         /* this run has to publish the node */
    int      sent;           /* accepted by the node during this run */
    int      rejected;       /* refused for a reason waiting will not cure */
    const char *reject_why;  /* static text */
    int      is_leaf;        /* "state" node that no other node spends */
    int      retained;       /* an earlier signed version of node_index that
                                this client's channel is funded by */
    /* From the signed bytes, when they parse: */
    int      parsed;
    char     prev_txid[65];  /* first input's outpoint */
    uint32_t prev_vout;
    uint32_t locktime;
} fr_node_t;

/* A factory's whole persisted tree.  nodes[i].node_index == i. */
typedef struct {
    fr_node_t *nodes;
    int        n;
} fr_tree_t;

static void fr_tree_free(fr_tree_t *t)
{
    if (!t) return;
    for (int i = 0; i < t->n; i++)
        free(t->nodes[i].signed_tx_hex);
    free(t->nodes);
    t->nodes = NULL;
    t->n = 0;
}

static void fr_why(char *why, size_t cap, const char *fmt, ...)
{
    if (!why || !cap) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(why, cap, fmt, ap);
    va_end(ap);
}

/* Defined with the sweep code below. */
static unsigned char nibble(char c);
static int64_t read_varint(const unsigned char *buf, size_t len, size_t *pos);

static void fr_display_hex(const unsigned char *b32, char out[65])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hx[b32[31 - i] >> 4];
        out[2 * i + 1] = hx[b32[31 - i] & 0xF];
    }
    out[64] = '\0';
}

static uint32_t fr_le32(const unsigned char *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

int factory_recovery_tx_info(const unsigned char *tx, size_t len,
                             factory_recovery_tx_info_t *out)
{
    if (!tx || !out || len < 10) return 0;
    memset(out, 0, sizeof(*out));
    size_t pos = 4;
    int segwit = (tx[4] == 0x00 && tx[5] == 0x01);
    if (segwit) pos += 2;
    size_t body = pos;
    int64_t n_in = read_varint(tx, len, &pos);
    if (n_in < 1 || (uint64_t)n_in > (uint64_t)(len - pos) / 41) return 0;
    for (int64_t i = 0; i < n_in; i++) {
        if (len - pos < 36) return 0;
        if (i == 0) {
            fr_display_hex(tx + pos, out->prev_txid);
            out->prev_vout = fr_le32(tx + pos + 32);
        }
        pos += 36;
        int64_t sl = read_varint(tx, len, &pos);
        if (sl < 0 || (uint64_t)sl > (uint64_t)(len - pos) ||
            len - pos - (size_t)sl < 4)
            return 0;
        pos += (size_t)sl;
        if (i == 0) out->nsequence = fr_le32(tx + pos);
        pos += 4;
    }
    int64_t n_out = read_varint(tx, len, &pos);
    if (n_out < 0 || (uint64_t)n_out > (uint64_t)(len - pos) / 9) return 0;
    for (int64_t i = 0; i < n_out; i++) {
        if (len - pos < 8) return 0;
        pos += 8;
        int64_t sl = read_varint(tx, len, &pos);
        if (sl < 0 || (uint64_t)sl > (uint64_t)(len - pos)) return 0;
        pos += (size_t)sl;
    }
    out->n_outputs = (size_t)n_out;
    size_t body_end = pos;
    if (segwit) {
        for (int64_t i = 0; i < n_in; i++) {
            int64_t items = read_varint(tx, len, &pos);
            if (items < 0) return 0;
            for (int64_t k = 0; k < items; k++) {
                int64_t il = read_varint(tx, len, &pos);
                if (il < 0 || (uint64_t)il > (uint64_t)(len - pos)) return 0;
                pos += (size_t)il;
            }
        }
    }
    if (len - pos != 4) return 0;
    out->locktime = fr_le32(tx + pos);

    size_t strip_len = 4 + (body_end - body) + 4;
    unsigned char *strip = malloc(strip_len);
    if (!strip) return 0;
    memcpy(strip, tx, 4);
    memcpy(strip + 4, tx + body, body_end - body);
    memcpy(strip + 4 + (body_end - body), tx + pos, 4);
    unsigned char h[32];
    sha256_double(strip, strip_len, h);
    free(strip);
    fr_display_hex(h, out->txid);
    return 1;
}

/* factory_recovery_tx_info over hex. */
static int fr_tx_info_hex(const char *hex, factory_recovery_tx_info_t *out)
{
    if (!hex) return 0;
    size_t hl = strlen(hex);
    if (hl < 20 || (hl & 1)) return 0;
    size_t len = hl / 2;
    unsigned char *b = malloc(len);
    if (!b) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi == 0xFF || lo == 0xFF) { free(b); return 0; }
        b[i] = (unsigned char)(hi << 4 | lo);
    }
    int ok = factory_recovery_tx_info(b, len, out);
    free(b);
    return ok;
}

/* Fill the parsed fields from the node's signed bytes.  nSequence from the
   transaction itself wins over the stored column. */
static void fr_parse_node(fr_node_t *nd)
{
    factory_recovery_tx_info_t ti;
    nd->parsed = 0;
    if (!nd->signed_tx_hex || !fr_tx_info_hex(nd->signed_tx_hex, &ti)) return;
    nd->parsed = 1;
    memcpy(nd->prev_txid, ti.prev_txid, sizeof(nd->prev_txid));
    nd->prev_vout = ti.prev_vout;
    nd->nsequence = ti.nsequence;
    nd->locktime  = ti.locktime;
}

/* ------------------------------------------------------------------ */
/* DB helpers                                                           */
/* ------------------------------------------------------------------ */

/*
 * Load every tree node of factory_id.
 *
 * Returns 1 with the tree in *t, 0 if the factory has no tree nodes, -1 if
 * the tree is not complete and self-consistent (why says what is wrong):
 * the rows must be exactly node_index 0..COUNT-1, every parent must be
 * another row of the same tree, and every node must reach a root.
 */
static int fr_tree_load(sqlite3 *db, uint32_t factory_id, fr_tree_t *t,
                        char *why, size_t why_cap)
{
    t->nodes = NULL;
    t->n = 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*), MIN(node_index), MAX(node_index) "
            "FROM tree_nodes WHERE factory_id=?",
            -1, &stmt, NULL) != SQLITE_OK) {
        fr_why(why, why_cap, "cannot read tree_nodes: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_int64 count = -1, min_idx = 0, max_idx = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count   = sqlite3_column_int64(stmt, 0);
        min_idx = sqlite3_column_int64(stmt, 1);
        max_idx = sqlite3_column_int64(stmt, 2);
    }
    sqlite3_finalize(stmt);
    if (count < 0) {
        fr_why(why, why_cap, "cannot count tree_nodes: %s", sqlite3_errmsg(db));
        return -1;
    }
    if (count == 0) return 0;
    if (min_idx != 0 || max_idx != count - 1 || count > INT32_MAX) {
        fr_why(why, why_cap,
               "tree is incomplete: %lld node(s) stored with indices %lld..%lld",
               (long long)count, (long long)min_idx, (long long)max_idx);
        return -1;
    }

    fr_node_t *nodes = calloc((size_t)count, sizeof(*nodes));
    if (!nodes) {
        fr_why(why, why_cap, "out of memory for %lld tree nodes",
               (long long)count);
        return -1;
    }
    t->nodes = nodes;

    if (sqlite3_prepare_v2(db,
            "SELECT node_index, parent_index, txid, type, signed_tx_hex, "
            "nsequence FROM tree_nodes WHERE factory_id=? "
            "ORDER BY node_index ASC",
            -1, &stmt, NULL) != SQLITE_OK) {
        fr_why(why, why_cap, "cannot read tree_nodes: %s", sqlite3_errmsg(db));
        fr_tree_free(t);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, (int)factory_id);

    int rc;
    int bad = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (t->n >= count ||
            sqlite3_column_int64(stmt, 0) != (sqlite3_int64)t->n) {
            fr_why(why, why_cap, "tree is incomplete: node %d is missing", t->n);
            bad = 1;
            break;
        }
        fr_node_t *nd = &nodes[t->n];
        nd->node_index = (int32_t)t->n;

        if (sqlite3_column_type(stmt, 1) == SQLITE_NULL)
            nd->parent_index = -1;
        else
            nd->parent_index = sqlite3_column_int(stmt, 1);

        const char *txid = (const char *)sqlite3_column_text(stmt, 2);
        if (txid) snprintf(nd->txid, sizeof(nd->txid), "%s", txid);

        const char *type = (const char *)sqlite3_column_text(stmt, 3);
        if (type) snprintf(nd->type, sizeof(nd->type), "%s", type);

        const char *hex = (const char *)sqlite3_column_text(stmt, 4);
        if (hex && hex[0]) {
            nd->signed_tx_hex = strdup(hex);
            if (!nd->signed_tx_hex) {
                fr_why(why, why_cap, "out of memory loading node %d", t->n);
                t->n++;
                bad = 1;
                break;
            }
        }

        nd->nsequence = (uint32_t)sqlite3_column_int64(stmt, 5);
        nd->confs = -2;
        fr_parse_node(nd);
        t->n++;
    }
    sqlite3_finalize(stmt);

    if (!bad && rc != SQLITE_DONE) {
        fr_why(why, why_cap, "reading tree_nodes failed after %d of %lld: %s",
               t->n, (long long)count, sqlite3_errmsg(db));
        bad = 1;
    }
    if (!bad && t->n != count) {
        fr_why(why, why_cap, "tree is incomplete: loaded %d of %lld nodes",
               t->n, (long long)count);
        bad = 1;
    }

    /* Every parent is a row of this tree, and every node reaches a root. */
    for (int i = 0; !bad && i < t->n; i++) {
        int32_t par = nodes[i].parent_index;
        if (par < -1 || par >= t->n || par == i) {
            fr_why(why, why_cap,
                   "tree is incomplete: node %d names parent %d, which is not "
                   "in the tree", i, (int)par);
            bad = 1;
        }
    }
    for (int i = 0; !bad && i < t->n; i++) {
        int steps = 0;
        for (int32_t at = i; at >= 0; at = nodes[at].parent_index) {
            if (++steps > t->n) {
                fr_why(why, why_cap,
                       "tree is inconsistent: node %d never reaches the root",
                       i);
                bad = 1;
                break;
            }
        }
    }

    if (bad) {
        fr_tree_free(t);
        return -1;
    }

    /* Tree rows are typed "kickoff" or "state" only: a leaf is a state node
       that is nobody's parent. */
    for (int i = 0; i < t->n; i++)
        nodes[i].is_leaf = (strcmp(nodes[i].type, "state") == 0);
    for (int i = 0; i < t->n; i++)
        if (nodes[i].parent_index >= 0)
            nodes[nodes[i].parent_index].is_leaf = 0;
    return 1;
}

/*
 * A client keeps the signed leaf transaction its channel is funded by when
 * an advance replaces that leaf in its tree (client_funding_leaf).  Append
 * the retained copy with txid to the tree, as a node standing beside the
 * current row of the same index and hanging from the same parent.
 * Returns its array index, -1 if there is none, -2 if the stored copy does
 * not fit the tree (why says how).
 */
static int fr_add_retained(sqlite3 *db, uint32_t factory_id, fr_tree_t *t,
                           const char *txid, char *why, size_t why_cap)
{
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
            "SELECT node_index, signed_tx_hex FROM client_funding_leaf "
            "WHERE factory_id=? AND txid=?",
            -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_text(stmt, 2, txid, -1, SQLITE_TRANSIENT);
    int node = -1;
    char *hex = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        node = sqlite3_column_int(stmt, 0);
        const char *h = (const char *)sqlite3_column_text(stmt, 1);
        if (h && h[0]) hex = strdup(h);
    }
    sqlite3_finalize(stmt);
    if (node < 0 && !hex) return -1;
    if (node < 0 || node >= t->n || !hex) {
        fr_why(why, why_cap, "retained leaf %.16s... names node %d, which is "
               "not in the %d-node tree", txid, node, t->n);
        free(hex);
        return -2;
    }

    fr_node_t *grown = realloc(t->nodes, (size_t)(t->n + 1) * sizeof(*grown));
    if (!grown) {
        fr_why(why, why_cap, "out of memory");
        free(hex);
        return -2;
    }
    t->nodes = grown;
    fr_node_t *nd = &t->nodes[t->n];
    memset(nd, 0, sizeof(*nd));
    nd->node_index    = node;
    nd->parent_index  = t->nodes[node].parent_index;
    nd->nsequence     = t->nodes[node].nsequence;
    snprintf(nd->txid, sizeof(nd->txid), "%s", txid);
    memcpy(nd->type, t->nodes[node].type, sizeof(nd->type));
    nd->signed_tx_hex = hex;
    nd->confs         = -2;
    nd->retained      = 1;
    fr_parse_node(nd);
    t->n++;

    /* It must be the transaction it claims to be, spending the parent. */
    factory_recovery_tx_info_t ti;
    const char *parent_txid = nd->parent_index >= 0
                              ? t->nodes[nd->parent_index].txid : NULL;
    if (!fr_tx_info_hex(hex, &ti) || strcasecmp(ti.txid, txid) != 0 ||
        (parent_txid && parent_txid[0] &&
         strcasecmp(ti.prev_txid, parent_txid) != 0)) {
        fr_why(why, why_cap, "retained leaf %.16s... for node %d is not a "
               "signed transaction with that txid spending node %d",
               txid, node, (int)nd->parent_index);
        return -2;
    }
    return t->n - 1;
}

/* ------------------------------------------------------------------ */
/* Chain helpers                                                         */
/* ------------------------------------------------------------------ */

static int get_confs(chain_backend_t *chain, const char *txid)
{
    if (!chain || !txid || !txid[0]) return -1;
    return chain->get_confirmations(chain, txid);
}

/* Refresh confirmations; targets_only leaves the nodes a run does not have
   to publish unqueried. */
static void refresh_confs(chain_backend_t *chain, fr_tree_t *t,
                          int targets_only)
{
    if (!chain) return;
    fr_node_t *nodes = t->nodes;
    int n = t->n;
    int done = 0;

    /* Try batch method first (single RPC round-trip) */
    if (chain->get_confirmations_batch && n > 0) {
        const char **txids = calloc((size_t)n, sizeof(*txids));
        int *confs = calloc((size_t)n, sizeof(*confs));
        int *map = calloc((size_t)n, sizeof(*map));  /* batch index -> node */
        if (txids && confs && map) {
            int count = 0;
            for (int i = 0; i < n; i++) {
                if (targets_only && !nodes[i].target) continue;
                if (nodes[i].txid[0]) {
                    txids[count] = nodes[i].txid;
                    map[count] = i;
                    count++;
                }
            }
            if (count > 0 && chain->get_confirmations_batch(chain,
                    txids, (size_t)count, confs)) {
                for (int i = 0; i < n; i++)
                    if (!nodes[i].txid[0] &&
                        (!targets_only || nodes[i].target))
                        nodes[i].confs = -1;
                for (int j = 0; j < count; j++)
                    nodes[map[j]].confs = confs[j];
                done = 1;
            }
        }
        free(txids);
        free(confs);
        free(map);
    }

    /* Fallback: individual queries */
    if (!done) {
        for (int i = 0; i < n; i++) {
            if (targets_only && !nodes[i].target) continue;
            nodes[i].confs = nodes[i].txid[0]
                             ? get_confs(chain, nodes[i].txid)
                             : -1;
        }
    }

    /* A transaction that is in the chain or the mempool has all of its
       ancestors there too, at least as deep.  A backend that only looks a
       limited number of blocks back can stop seeing an old ancestor; take
       its depth from the descendant it does see. */
    for (int i = 0; i < n; i++) {
        if (nodes[i].confs < 0) continue;
        int depth = nodes[i].confs;
        for (int32_t at = nodes[i].parent_index; at >= 0;
             at = nodes[at].parent_index) {
            if (nodes[at].confs >= depth) break;
            nodes[at].confs = depth;
        }
    }
}

/* Blocks the node's parent must be buried before the node is final
   (BIP 68 height lock), 0 when it has no relative lock. */
static int relative_lock_blocks(uint32_t nsequence)
{
    if (nsequence & 0x80000000u) return 0;   /* lock disabled */
    if (nsequence & 0x00400000u) return 0;   /* time-based: not used here */
    return (int)(nsequence & 0xFFFFu);
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

    int ok = cpfp_send_default(chain, node->signed_tx_hex, result_txid);

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

/* Check if all leaf nodes are confirmed at the network-safe depth
   (returns 0 if none found).
   #265: was hardcoded `confs < 1` ("any confirmation at all"); now uses
   chain_funding_confs (1 on regtest, configurable on other networks,
   default 6 on mainnet) so factory recovery on mainnet waits for
   reorg-safe depth before declaring the factory fully settled. */
static int all_leaves_confirmed(chain_backend_t *chain, const fr_tree_t *t)
{
    int min_confs = chain ? chain_funding_confs(chain, chain->is_regtest) : 1;
    int found = 0;
    for (int i = 0; i < t->n; i++) {
        if (!t->nodes[i].is_leaf) continue;
        found = 1;
        if (t->nodes[i].confs < min_confs) return 0;
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* Core per-factory recovery                                            */
/* ------------------------------------------------------------------ */

/*
 * One pass over one factory.
 *
 * allow_broadcast: 0 = do NOT broadcast ANY tree node during this pass.
 * This is the safe mode for startup / reorg scans: an active factory's tree
 * should never be force-published just because the funding confirmed.
 * 1 = explicit operator-requested force-close; OK to broadcast from the
 * root down.
 *
 * leaf_txid: NULL publishes the whole tree.  Otherwise only the path from
 * the root to the node with that txid is published.
 *
 * Returns 1 if the pass ran without error (res says how far it got), 0 if
 * the factory has no tree, -1 on error (why says which).
 */
static int do_factory_recovery(persist_t *p, chain_backend_t *chain,
                                uint32_t factory_id, const char *funding_txid,
                                int allow_broadcast, const char *leaf_txid,
                                factory_recovery_result_t *res,
                                char *why, size_t why_cap)
{
    factory_recovery_result_t local;
    if (!res) res = &local;
    memset(res, 0, sizeof(*res));
    res->leaf_node = -1;
    res->first_unpublished = -1;
    res->reject_node = -1;

    fr_tree_t tree;
    int loaded = fr_tree_load(p->db, factory_id, &tree, why, why_cap);
    if (loaded <= 0) return loaded;

    fr_node_t *nodes = tree.nodes;
    int n = tree.n;
    res->n_tree_nodes = n;

    /* Which nodes this run has to publish. */
    if (leaf_txid) {
        int leaf = -1;
        for (int i = 0; i < n && leaf < 0; i++)
            if (nodes[i].txid[0] && strcasecmp(nodes[i].txid, leaf_txid) == 0)
                leaf = i;
        if (leaf < 0) {
            /* The tree has moved past the leaf (an advance replaced it):
               only the copy kept when it was replaced can be published.
               The current row of that index spends the same output, so it
               is never a substitute. */
            leaf = fr_add_retained(p->db, factory_id, &tree, leaf_txid,
                                   why, why_cap);
            nodes = tree.nodes;
            n = tree.n;
            if (leaf == -1)
                fr_why(why, why_cap,
                       "exit leaf %.16s... is neither one of the %d tree "
                       "nodes in this DB nor a kept copy of one; the tree "
                       "has moved past it and the current leaf would spend "
                       "the output the commitment needs",
                       leaf_txid, res->n_tree_nodes);
            if (leaf < 0) {
                fr_tree_free(&tree);
                return -1;
            }
        }
        res->leaf_node = nodes[leaf].node_index;
        res->retained_leaf = nodes[leaf].retained;
        nodes[leaf].target = 1;
        for (int32_t at = nodes[leaf].parent_index; at >= 0;
             at = nodes[at].parent_index)
            nodes[at].target = 1;
    } else {
        for (int i = 0; i < n; i++) nodes[i].target = 1;
    }

    int missing = -1;
    for (int i = 0; i < n; i++) {
        if (!nodes[i].target) continue;
        res->n_target++;
        if (!nodes[i].signed_tx_hex && missing < 0) missing = i;
    }
    if (missing >= 0 && allow_broadcast) {
        fr_why(why, why_cap, "node %d has no signed transaction stored",
               missing);
        /* An exit path with a hole cannot be completed: publish nothing.
           A whole-tree run still publishes the nodes it does have. */
        if (leaf_txid) {
            fr_tree_free(&tree);
            return -1;
        }
    }

    int funding_confs = get_confs(chain, funding_txid);
    int height = chain->get_block_height ? chain->get_block_height(chain) : -1;
    refresh_confs(chain, &tree, /* targets_only = */ 1);

    int progress = allow_broadcast;
    while (progress) {
        progress = 0;
        for (int i = 0; i < n; i++) {
            fr_node_t *nd = &nodes[i];
            /* Skip if already confirmed or already tried this call
             * (send_raw_tx can succeed again for a mempool TX, which would
             * spin this loop forever). */
            if (!nd->target || nd->confs >= 1 || nd->sent || nd->rejected)
                continue;
            if (!nd->signed_tx_hex) continue; /* not signed — skip */

            /* A child goes out only once its parent is CONFIRMED.  Tree txs
               are TRUC: an unconfirmed TRUC tx may have one unconfirmed
               ancestor and one descendant, so a child sent while the parent
               is in the mempool is either rejected or takes the parent's only
               descendant slot, which the CPFP child on the parent's anchor
               needs. */
            int parent_ok = 0;
            int parent_depth = 0;
            if (nd->parent_index < 0) {
                /* Root node (kickoff): depends on the factory funding TX. */
                parent_ok = (funding_confs >= chain_funding_confs(chain, chain->is_regtest));
                parent_depth = funding_confs;
            } else {
                fr_node_t *par = &nodes[nd->parent_index];
                parent_ok = par->confs >= 1;
                parent_depth = par->confs;
            }
            if (!parent_ok) continue;
            /* An absolute height lock not reached yet: wait. */
            if (nd->parsed && nd->locktime > 0 && nd->locktime < 500000000u &&
                nd->nsequence != 0xFFFFFFFFu && height >= 0 &&
                (uint32_t)height < nd->locktime)
                continue;

            int ok = broadcast_node(chain, p, nd, factory_id);
            if (ok) {
                nd->confs = 0;
                nd->sent = 1;
                res->n_broadcast++;
                progress = 1;
            } else if (parent_depth >= 1 &&
                       parent_depth >= relative_lock_blocks(nd->nsequence) &&
                       get_confs(chain, nd->txid) < 0) {
                /* Not a timelock wait: the parent is deep enough, any
                   height lock has passed, and the node is still nowhere to
                   be seen.  Waiting will not change that. */
                nd->rejected = 1;
                nd->reject_why = "refused by the node";
                if (nd->parsed && chain->is_outpoint_unspent) {
                    int u = chain->is_outpoint_unspent(chain, nd->prev_txid,
                                                       nd->prev_vout);
                    if (u == 0)
                        nd->reject_why = "its input is already spent by "
                                         "another transaction";
                    else if (u == 1)
                        nd->reject_why = "refused by the node although its "
                                         "input is unspent and mature (fee "
                                         "below the node's floor, or policy)";
                }
            }
        }
    }

    /* Re-check confirmations after broadcasts and auto-close if done */
    refresh_confs(chain, &tree, /* targets_only = */ 1);
    if (!leaf_txid && all_leaves_confirmed(chain, &tree)) {
        persist_mark_factory_closed(p, factory_id);
        printf("LSP recovery: factory %u fully settled — marked closed\n",
               factory_id);
        fflush(stdout);
    }

    res->first_unpublished = -1;
    res->reject_node = -1;
    for (int i = 0; i < n; i++) {
        fr_node_t *nd = &nodes[i];
        if (!nd->target) continue;
        if (nd->confs >= 1) {
            res->n_confirmed++;
        } else if (nd->confs == 0 || nd->sent) {
            res->n_in_mempool++;
        } else {
            if (nd->rejected) {
                res->n_rejected++;
                if (res->reject_node < 0) {
                    res->reject_node = nd->node_index;
                    snprintf(res->reject_why, sizeof(res->reject_why), "%s",
                             nd->reject_why ? nd->reject_why : "refused");
                }
            } else {
                res->n_waiting++;
            }
            if (res->first_unpublished < 0)
                res->first_unpublished = nd->node_index;
        }
    }
    res->published =
        (res->n_confirmed + res->n_in_mempool == res->n_target);

    fr_tree_free(&tree);
    return (missing >= 0 && allow_broadcast) ? -1 : 1;
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

        if (ftxid && ftxid[0]) {
            char why[256] = {0};
            if (do_factory_recovery(p, chain, fid, ftxid,
                                    /* allow_broadcast = */ 0, NULL, NULL,
                                    why, sizeof(why)) < 0) {
                fprintf(stderr, "LSP recovery: factory %u: %s\n", fid, why);
            }
        }

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
        fr_tree_t tree;
        char why[256] = {0};
        int loaded = fr_tree_load(p->db, fid, &tree, why, sizeof(why));
        int n_nodes = 0;
        int n_confirmed = 0, n_leaf = 0, n_leaf_confirmed = 0;
        if (loaded > 0) {
            n_nodes = tree.n;
            if (chain) refresh_confs(chain, &tree, /* targets_only = */ 0);
            for (int i = 0; i < tree.n; i++) {
                if (chain && tree.nodes[i].confs >= 1) n_confirmed++;
                if (tree.nodes[i].is_leaf) {
                    n_leaf++;
                    if (chain && tree.nodes[i].confs >= 1) n_leaf_confirmed++;
                }
            }
            fr_tree_free(&tree);
        } else if (loaded < 0) {
            cJSON_AddStringToObject(fobj, "tree_error", why);
        }
        cJSON_AddNumberToObject(fobj, "n_tree_nodes",        (double)n_nodes);
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

int factory_recovery_client_leaf(persist_t *p, uint32_t factory_id,
                                 char txid_out[65])
{
    if (txid_out) txid_out[0] = '\0';
    if (!p || !p->db || !txid_out) return -1;

    sqlite3_stmt *stmt;
    /* The commitment is what this client will publish: its input is the
       leaf output, whatever the channel row says. */
    if (sqlite3_prepare_v2(p->db,
            "SELECT signed_tx_hex FROM signed_commitments "
            "ORDER BY commitment_number DESC LIMIT 1",
            -1, &stmt, NULL) == SQLITE_OK) {
        factory_recovery_tx_info_t ti;
        int have = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW)
            have = fr_tx_info_hex((const char *)sqlite3_column_text(stmt, 0),
                                  &ti);
        sqlite3_finalize(stmt);
        if (have) {
            snprintf(txid_out, 65, "%s", ti.prev_txid);
            return 1;
        }
    }

    if (sqlite3_prepare_v2(p->db,
            "SELECT DISTINCT funding_txid FROM channels "
            "WHERE factory_id=? AND funding_txid IS NOT NULL "
            "  AND funding_txid != ''",
            -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(stmt, 1, (int)factory_id);

    int found = 0;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(stmt, 0);
        if (found == 0 && t) snprintf(txid_out, 65, "%s", t);
        found++;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE || found > 1) {
        txid_out[0] = '\0';
        return -1;
    }
    return found;
}

int factory_recovery_run(persist_t *p, chain_backend_t *chain,
                         uint32_t factory_id, const char *leaf_txid,
                         factory_recovery_result_t *res,
                         char *status_out, size_t cap)
{
    if (res) {
        memset(res, 0, sizeof(*res));
        res->leaf_node = -1;
        res->first_unpublished = -1;
        res->reject_node = -1;
    }
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

    factory_recovery_result_t local;
    if (!res) res = &local;
    char why[256] = {0};
    int rc = do_factory_recovery(p, chain, factory_id, funding_txid,
                                 /* allow_broadcast = */ 1, leaf_txid, res,
                                 why, sizeof(why));
    if (rc == 0)
        snprintf(why, sizeof(why), "no tree nodes stored");
    if (rc <= 0) {
        res->published = 0;
        if (status_out && cap && res->n_target > 0)
            snprintf(status_out, cap,
                     "factory %u (state=%s): ERROR: %s; broadcast %d TX%s, "
                     "%d of %d confirmed, %d in mempool, %d waiting, "
                     "%d rejected (%d tree nodes)",
                     factory_id, state[0] ? state : "?", why,
                     res->n_broadcast, res->n_broadcast == 1 ? "" : "s",
                     res->n_confirmed, res->n_target, res->n_in_mempool,
                     res->n_waiting, res->n_rejected, res->n_tree_nodes);
        else if (status_out && cap)
            snprintf(status_out, cap, "factory %u (state=%s): ERROR: %s",
                     factory_id, state[0] ? state : "?", why);
        return 0;
    }

    if (status_out && cap) {
        char scope[64];
        if (leaf_txid)
            snprintf(scope, sizeof(scope), "exit path to node %d%s",
                     res->leaf_node, res->retained_leaf ? " (kept leaf)" : "");
        else
            snprintf(scope, sizeof(scope), "whole tree");
        snprintf(status_out, cap,
                 "factory %u (state=%s): broadcast %d TX%s; %s: %d of %d "
                 "confirmed, %d in mempool, %d waiting, %d rejected "
                 "(%d tree nodes)",
                 factory_id, state[0] ? state : "?",
                 res->n_broadcast, res->n_broadcast == 1 ? "" : "s", scope,
                 res->n_confirmed, res->n_target, res->n_in_mempool,
                 res->n_waiting, res->n_rejected, res->n_tree_nodes);
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* factory_sweep_run                                                     */
/* ------------------------------------------------------------------ */

/* Decode one hex nibble. Returns 0xFF on invalid char. */
static unsigned char nibble(char c)
{
    if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned char)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (unsigned char)(c - 'A' + 10);
    return 0xFF;
}

/* Hex-encode n bytes into out (must have room for 2n+1 bytes). */
static void hex_encode(const unsigned char *in, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]   = hx[in[i] >> 4];
        out[2*i+1] = hx[in[i] & 0xF];
    }
    out[2*n] = '\0';
}

/* Read a Bitcoin varint from buf at *pos. Advances *pos. Returns value or -1. */
static int64_t read_varint(const unsigned char *buf, size_t len, size_t *pos)
{
    if (*pos >= len) return -1;
    unsigned char first = buf[(*pos)++];
    if (first < 0xFD) return (int64_t)first;
    if (first == 0xFD) {
        if (*pos + 2 > len) return -1;
        uint16_t v = (uint16_t)buf[*pos] | ((uint16_t)buf[*pos+1] << 8);
        *pos += 2;
        return (int64_t)v;
    }
    if (first == 0xFE) {
        if (*pos + 4 > len) return -1;
        uint32_t v = (uint32_t)buf[*pos]       | ((uint32_t)buf[*pos+1] << 8) |
                     ((uint32_t)buf[*pos+2] << 16) | ((uint32_t)buf[*pos+3] << 24);
        *pos += 4;
        return (int64_t)v;
    }
    /* 0xFF — 8-byte varint, uncommon in practice */
    if (*pos + 8 > len) return -1;
    uint64_t v = 0;
    for (int b = 0; b < 8; b++) v |= ((uint64_t)buf[*pos+b] << (8*b));
    *pos += 8;
    return (int64_t)v;
}

/*
 * Parse a raw segwit Bitcoin TX (as hex) and extract every output.
 * Allocates *amounts_out, *spks_out and *spk_lens_out, one entry per output
 * (caller frees all three).  spk_lens_out[i] is the scriptPubKey length,
 * capped at the 34 bytes kept.
 * Returns number of outputs parsed, -1 on error (nothing left allocated).
 */
static int tx_parse_outputs(const char *hex,
                             uint64_t **amounts_out,
                             unsigned char (**spks_out)[34],
                             size_t **spk_lens_out)
{
    *amounts_out = NULL;
    *spks_out = NULL;
    *spk_lens_out = NULL;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t len = hex_len / 2;
    unsigned char *tx = malloc(len);
    if (!tx) return -1;

    /* Hex-decode the full TX */
    for (size_t i = 0; i < len; i++) {
        unsigned char hi = nibble(hex[2*i]);
        unsigned char lo = nibble(hex[2*i+1]);
        if (hi == 0xFF || lo == 0xFF) { free(tx); return -1; }
        tx[i] = (unsigned char)(hi << 4 | lo);
    }

    size_t pos = 0;

    /* nVersion (4 bytes) */
    if (pos + 4 > len) { free(tx); return -1; }
    pos += 4;

    /* Segwit marker: 0x00 0x01 */
    int segwit = 0;
    if (pos + 2 <= len && tx[pos] == 0x00 && tx[pos+1] == 0x01) {
        segwit = 1;
        pos += 2;
    }

    /* Input count */
    int64_t n_inputs = read_varint(tx, len, &pos);
    if (n_inputs < 0) { free(tx); return -1; }

    /* Skip inputs: txid(32) + vout(4) + scriptLen + script + sequence(4) */
    for (int64_t i = 0; i < n_inputs; i++) {
        if (pos + 36 > len) { free(tx); return -1; }
        pos += 36;  /* txid + vout */
        int64_t script_len = read_varint(tx, len, &pos);
        if (script_len < 0) { free(tx); return -1; }
        pos += (size_t)script_len + 4;  /* script + sequence */
        if (pos > len) { free(tx); return -1; }
    }

    /* Output count */
    int64_t n_outputs = read_varint(tx, len, &pos);
    /* An output is at least 9 bytes, so the TX length bounds the count. */
    if (n_outputs < 0 || (uint64_t)n_outputs > (uint64_t)(len - pos) / 9) {
        free(tx);
        return -1;
    }

    size_t n_alloc = n_outputs > 0 ? (size_t)n_outputs : 1;
    uint64_t *amounts = calloc(n_alloc, sizeof(*amounts));
    unsigned char (*spks)[34] = calloc(n_alloc, sizeof(*spks));
    size_t *spk_lens = calloc(n_alloc, sizeof(*spk_lens));
    if (!amounts || !spks || !spk_lens) {
        free(amounts); free(spks); free(spk_lens); free(tx);
        return -1;
    }
#define TX_PARSE_FAIL() do { \
        free(amounts); free(spks); free(spk_lens); free(tx); return -1; \
    } while (0)

    int count = 0;
    for (int64_t i = 0; i < n_outputs; i++) {
        if (pos + 8 > len) TX_PARSE_FAIL();
        uint64_t amount = 0;
        for (int b = 0; b < 8; b++) amount |= ((uint64_t)tx[pos+b] << (8*b));
        pos += 8;

        int64_t spk_len = read_varint(tx, len, &pos);
        if (spk_len < 0) TX_PARSE_FAIL();
        if (pos + (size_t)spk_len > len) TX_PARSE_FAIL();

        amounts[count] = amount;
        size_t copy = (size_t)spk_len < 34 ? (size_t)spk_len : 34;
        memcpy(spks[count], tx + pos, copy);
        spk_lens[count] = copy;
        count++;
        pos += (size_t)spk_len;
    }
#undef TX_PARSE_FAIL

    (void)segwit;
    free(tx);
    *amounts_out = amounts;
    *spks_out = spks;
    *spk_lens_out = spk_lens;
    return count;
}

cJSON *factory_sweep_run(persist_t *p, chain_backend_t *chain,
                         secp256k1_context *ctx,
                         const unsigned char *lsp_seckey32,
                         uint32_t factory_id,
                         const unsigned char *dest_spk,
                         size_t dest_spk_len,
                         uint64_t fee_sats,
                         int dry_run)
{
    cJSON *results = cJSON_CreateArray();
    if (!p || !p->db || !ctx || !lsp_seckey32) return results;

    /* Derive LSP x-only pubkey for comparison against output keys */
    secp256k1_pubkey lsp_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &lsp_pub, lsp_seckey32))
        return results;

    secp256k1_xonly_pubkey lsp_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &lsp_pub);
    unsigned char lsp_xonly_bytes[32];
    secp256k1_xonly_pubkey_serialize(ctx, lsp_xonly_bytes, &lsp_xonly);

    /* Build the LSP keypair for signing */
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_seckey32))
        return results;

    /* Get factory CLTV timeout (needed for nLockTime on sweep TXs) */
    uint32_t cltv_timeout = 0;
    {
        sqlite3_stmt *st;
        if (sqlite3_prepare_v2(p->db,
                "SELECT cltv_timeout FROM factories WHERE id=?",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, (int)factory_id);
            if (sqlite3_step(st) == SQLITE_ROW)
                cltv_timeout = (uint32_t)sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
        }
    }

    /*
     * Find all confirmed leaf state nodes: type='state' nodes with no
     * children in tree_nodes (bottom of the DW tree).
     */
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT tn.node_index, tn.txid, tn.signed_tx_hex "
        "FROM tree_nodes tn "
        "WHERE tn.factory_id=? AND tn.type='state' "
        "  AND NOT EXISTS ("
        "    SELECT 1 FROM tree_nodes child "
        "    WHERE child.factory_id=tn.factory_id "
        "      AND child.parent_index=tn.node_index"
        "  ) "
        "ORDER BY tn.node_index ASC";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return results;
    sqlite3_bind_int(stmt, 1, (int)factory_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int    node_idx  = sqlite3_column_int(stmt, 0);
        const char *txid = (const char *)sqlite3_column_text(stmt, 1);
        const char *hex  = (const char *)sqlite3_column_text(stmt, 2);

        if (!txid || !hex || !hex[0]) continue;

        /* Skip expensive per-node confirmation check — just parse outputs
           and attempt to spend. Unspent outputs succeed; already-spent ones
           fail harmlessly at broadcast with "inputs-missingorspent". */

        /* Parse outputs from the raw TX */
        uint64_t *amounts = NULL;
        unsigned char (*spks)[34] = NULL;
        size_t *spk_lens = NULL;
        int n_outs = tx_parse_outputs(hex, &amounts, &spks, &spk_lens);
        if (n_outs <= 0) {
            free(amounts); free(spks); free(spk_lens);
            continue;
        }

        /* Convert txid to internal-order bytes (display txid is reversed) */
        unsigned char txid_internal[32];
        if (strlen(txid) == 64) {
            for (int b = 0; b < 32; b++) {
                unsigned char hi = nibble(txid[2*(31-b)]);
                unsigned char lo = nibble(txid[2*(31-b)+1]);
                txid_internal[b] = (unsigned char)(hi << 4 | lo);
            }
        }

        for (int vout = 0; vout < n_outs; vout++) {
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "txid", txid);
            cJSON_AddNumberToObject(entry, "vout", (double)vout);
            cJSON_AddNumberToObject(entry, "amount_sats", (double)amounts[vout]);
            cJSON_AddNumberToObject(entry, "node_index", (double)node_idx);

            /* Encode the output scriptPubKey as hex for reporting */
            char spk_hex[69] = {0};
            if (spk_lens[vout] > 0)
                hex_encode(spks[vout], spk_lens[vout], spk_hex);
            cJSON_AddStringToObject(entry, "spk_hex", spk_hex);

            /*
             * Determine if this is a key-path-only LSP output:
             *   P2TR = OP_1(0x51) PUSHBYTES_32(0x20) <32-byte-xonly-key>
             * Check both untweaked AND taptweak(LSP) for L-stock outputs.
             */
            int is_lsp_key_path = 0;
            if (spk_lens[vout] == 34 &&
                spks[vout][0] == 0x51 && spks[vout][1] == 0x20) {
                if (memcmp(spks[vout] + 2, lsp_xonly_bytes, 32) == 0) {
                    is_lsp_key_path = 1;
                } else {
                    /* Check taptweak(LSP_xonly, NULL) — L-stock key-path */
                    unsigned char tw_data[32];
                    sha256_tagged("TapTweak", lsp_xonly_bytes, 32, tw_data);
                    secp256k1_pubkey tw_full;
                    if (secp256k1_xonly_pubkey_tweak_add(ctx, &tw_full,
                            &lsp_xonly, tw_data)) {
                        secp256k1_xonly_pubkey tw_xo;
                        unsigned char tw_bytes[32];
                        secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xo, NULL, &tw_full);
                        secp256k1_xonly_pubkey_serialize(ctx, tw_bytes, &tw_xo);
                        if (memcmp(spks[vout] + 2, tw_bytes, 32) == 0)
                            is_lsp_key_path = 1;
                    }
                }
            }

            if (!is_lsp_key_path) {
                /* A shared output (channel, tree node) has no path the LSP
                   can spend alone: it is settled by a commitment, a tree
                   transaction, a cooperative spend, or its end-date payout
                   to the members. */
                cJSON_AddStringToObject(entry, "status", "requires_client_key");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            if (amounts[vout] <= fee_sats) {
                cJSON_AddStringToObject(entry, "status", "insufficient_funds");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            if (dry_run || !chain || !dest_spk || dest_spk_len == 0) {
                cJSON_AddStringToObject(entry, "status", "dry_run");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            /* Build sweep TX: single input, single output to dest_spk */
            tx_output_t sweep_out;
            sweep_out.amount_sats = amounts[vout] - fee_sats;
            memcpy(sweep_out.script_pubkey, dest_spk,
                   dest_spk_len < 34 ? dest_spk_len : 34);
            sweep_out.script_pubkey_len = dest_spk_len < 34 ? dest_spk_len : 34;

            tx_buf_t unsigned_tx;
            tx_buf_init(&unsigned_tx, 256);
            int built = build_unsigned_tx_with_locktime(
                &unsigned_tx, NULL,
                txid_internal, (uint32_t)vout,
                0xFFFFFFFE,        /* nSequence: enables nLockTime */
                cltv_timeout,      /* nLockTime: satisfies CLTV if any */
                &sweep_out, 1);

            if (!built || unsigned_tx.oom) {
                tx_buf_free(&unsigned_tx);
                cJSON_AddStringToObject(entry, "status", "build_failed");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            /* BIP-341 key-path sighash */
            unsigned char sighash[32];
            int ok = compute_taproot_sighash(
                sighash,
                unsigned_tx.data, unsigned_tx.len,
                0,                         /* input index */
                spks[vout], spk_lens[vout], /* prevout scriptPubKey */
                amounts[vout],              /* prevout amount */
                0xFFFFFFFE);               /* nSequence */

            if (!ok) {
                tx_buf_free(&unsigned_tx);
                cJSON_AddStringToObject(entry, "status", "sighash_failed");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            /* Schnorr sign — use tweaked keypair if output is tap-tweaked */
            unsigned char sig64[64];
            unsigned char aux[32] = {0};
            secp256k1_keypair sign_kp = lsp_kp;
            if (memcmp(spks[vout] + 2, lsp_xonly_bytes, 32) != 0) {
                /* Output key != plain LSP key — apply taptweak to keypair */
                unsigned char tw_data[32];
                sha256_tagged("TapTweak", lsp_xonly_bytes, 32, tw_data);
                secp256k1_keypair_xonly_tweak_add(ctx, &sign_kp, tw_data);
            }
            if (!secp256k1_schnorrsig_sign32(ctx, sig64, sighash, &sign_kp, aux)) {
                tx_buf_free(&unsigned_tx);
                cJSON_AddStringToObject(entry, "status", "sign_failed");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            /* Attach witness */
            tx_buf_t signed_tx;
            tx_buf_init(&signed_tx, unsigned_tx.len + 80);
            ok = finalize_signed_tx(&signed_tx, unsigned_tx.data, unsigned_tx.len, sig64);
            tx_buf_free(&unsigned_tx);

            if (!ok || signed_tx.oom) {
                tx_buf_free(&signed_tx);
                cJSON_AddStringToObject(entry, "status", "finalize_failed");
                cJSON_AddItemToArray(results, entry);
                continue;
            }

            /* Hex-encode the signed TX for broadcast + audit */
            size_t tx_hex_len = signed_tx.len * 2 + 1;
            char *tx_hex_str = malloc(tx_hex_len);
            if (tx_hex_str) hex_encode(signed_tx.data, signed_tx.len, tx_hex_str);

            char result_txid[65] = {0};
            int broadcast_ok = chain->send_raw_tx(chain, tx_hex_str, result_txid);

            char source[48];
            snprintf(source, sizeof(source), "sweep_factory%u_node%d_vout%d",
                     factory_id, node_idx, vout);
            persist_log_broadcast(p,
                result_txid[0] ? result_txid : txid,
                source,
                tx_hex_str ? tx_hex_str : "",
                broadcast_ok ? "ok" : "failed");

            free(tx_hex_str);
            tx_buf_free(&signed_tx);

            if (broadcast_ok) {
                cJSON_AddStringToObject(entry, "status", "swept");
                cJSON_AddStringToObject(entry, "sweep_txid", result_txid);
                printf("LSP sweep: factory %u node %d vout %d -> %s\n",
                       factory_id, node_idx, vout, result_txid);
                fflush(stdout);
            } else {
                /* Likely already spent or invalid sig (MuSig output we misidentified) */
                cJSON_AddStringToObject(entry, "status", "broadcast_failed");
            }

            cJSON_AddItemToArray(results, entry);
        }
        free(amounts);
        free(spks);
        free(spk_lens);
    }
    sqlite3_finalize(stmt);
    return results;
}
