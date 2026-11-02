/*
 * factory_recovery.c — startup recovery scan and CLI recovery for DW factories
 *
 * Queries the factories + tree_nodes tables directly via sqlite3, then uses
 * chain_backend_t to check confirmations and broadcast signed TXs.
 *
 * Design: topological broadcast (passes).  A TX is broadcastable when every
 * input's parent is confirmed deep enough for that input's BIP-68 lock (the
 * root spends the factory funding TX) and its nLockTime has passed.  Passes
 * repeat until no new broadcasts occur.  The node set is sized from the DB
 * and includes full Pseudo-Spilman chains (chain[0..N]), so the CURRENT
 * signed state is what gets published.
 */

#include "superscalar/factory_recovery.h"
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* Internal representation                                              */
/* ------------------------------------------------------------------ */

/*
 * Every array here is sized from the DB at load time; there is no fixed
 * node cap.  (A fixed 128-entry array used to drop every node at index
 * 128 or above, so a client of a 64-client factory could "exit" without
 * its leaf ever being published.)
 *
 * One fr_tx_t is one publishable transaction:
 *   - a plain tree node contributes its current signed TX (chain_pos -1);
 *   - a Pseudo-Spilman leaf / sub-factory that has advanced contributes
 *     its whole chain: chain[0] (ps_initial_signed_states, or the
 *     tree_nodes row when that is all there is) followed by chain[1..N]
 *     from ps_leaf_chains / ps_subfactory_chains.  chain[k] spends
 *     chain[k-1], so only the full sequence reaches the current state.
 *
 * Dependencies are read from each TX's own inputs (prevout txids), not
 * from parent_index, so chained entries and multi-input sub-factory TXs
 * are ordered correctly, and BIP-68 relative locks / nLockTime are known
 * per input.  That lets a pass tell "waiting for a timelock" apart from
 * "should have been accepted and was not" (a reported failure).
 */
typedef struct {
    int32_t   node_index;
    int32_t   parent_index;     /* -1 = root */
    int       chain_pos;        /* -1 plain tree TX; >= 0 PS chain position */
    char      type[16];         /* tree_nodes.type ("kickoff" / "state") */
    char      txid[65];         /* display hex (recomputed from the bytes) */
    char     *signed_tx_hex;    /* heap; NULL when the bytes are missing */
    const char *missing_why;    /* why the bytes are missing (static string) */
    int       confs;            /* -2 unchecked, -1 not found, 0 mempool, >=1 */
    int       parsed;
    uint32_t  version;
    size_t    n_inputs;
    char    (*prev_txid)[65];
    uint32_t *prev_vout;
    uint32_t *nseq;
    uint32_t  locktime;
    int       sent;             /* broadcast (or planned in dry-run) this pass */
    int       failed;           /* ready, but the node rejected it */
    const char *fail_why;
} fr_tx_t;

typedef struct {
    int32_t node_index;
    int32_t parent_index;
    char    type[16];
    int     is_leaf;            /* "state" node with no child in tree_nodes */
} fr_row_t;

typedef struct {
    fr_tx_t  *tx;
    size_t    n, cap;
    fr_row_t *rows;             /* tree_nodes rows, in node_index order */
    size_t    n_rows, rows_cap;
    long      expected_rows;    /* SELECT COUNT(*) — detects a short read */
    int       load_error;
    char      load_why[160];
} fr_set_t;

/* Defined further down (shared with the sweep code). */
static int64_t read_varint(const unsigned char *buf, size_t len, size_t *pos);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

static void fr_tx_clear(fr_tx_t *t)
{
    free(t->signed_tx_hex);
    free(t->prev_txid);
    free(t->prev_vout);
    free(t->nseq);
    memset(t, 0, sizeof(*t));
}

static void fr_set_free(fr_set_t *s)
{
    for (size_t i = 0; i < s->n; i++) fr_tx_clear(&s->tx[i]);
    free(s->tx);
    free(s->rows);
    memset(s, 0, sizeof(*s));
}

static fr_tx_t *fr_set_push(fr_set_t *s)
{
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 64;
        fr_tx_t *nt = realloc(s->tx, nc * sizeof(*nt));
        if (!nt) return NULL;
        s->tx = nt;
        s->cap = nc;
    }
    fr_tx_t *t = &s->tx[s->n++];
    memset(t, 0, sizeof(*t));
    t->confs = -2;
    t->chain_pos = -1;
    return t;
}

static void fr_load_fail(fr_set_t *s, const char *why)
{
    if (!s->load_error)
        snprintf(s->load_why, sizeof(s->load_why), "%s", why);
    s->load_error = 1;
}

static char *fr_strdup_or_null(const unsigned char *txt)
{
    if (!txt || !txt[0]) return NULL;
    return strdup((const char *)txt);
}

static void fr_bytes_to_display_hex(const unsigned char *b32, char *out65)
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        unsigned char c = b32[31 - i];
        out65[2 * i]     = hx[c >> 4];
        out65[2 * i + 1] = hx[c & 0xF];
    }
    out65[64] = '\0';
}

static uint32_t fr_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Parse t->signed_tx_hex: inputs (prevout + nSequence), nLockTime, and the
   txid (double-SHA256 of the non-witness serialization).  Returns 1 if the
   TX parsed; 0 leaves t->parsed = 0. */
static int fr_parse_tx(fr_tx_t *t)
{
    t->parsed = 0;
    if (!t->signed_tx_hex) return 0;
    size_t hl = strlen(t->signed_tx_hex);
    if (hl < 20 || (hl & 1)) return 0;
    size_t len = hl / 2;
    unsigned char *b = malloc(len);
    if (!b) return 0;
    if (hex_decode(t->signed_tx_hex, b, len) != (int)len) { free(b); return 0; }

    int ok = 0;
    size_t pos = 0;
    do {
        t->version = fr_le32(b);
        pos = 4;
        int segwit = (len > 6 && b[4] == 0x00 && b[5] == 0x01);
        if (segwit) pos += 2;
        size_t body_start = pos;
        int64_t nin = read_varint(b, len, &pos);
        if (nin <= 0 || nin > 100000) break;
        t->n_inputs  = (size_t)nin;
        t->prev_txid = calloc(t->n_inputs, sizeof(*t->prev_txid));
        t->prev_vout = calloc(t->n_inputs, sizeof(*t->prev_vout));
        t->nseq      = calloc(t->n_inputs, sizeof(*t->nseq));
        if (!t->prev_txid || !t->prev_vout || !t->nseq) break;
        int bad = 0;
        for (size_t i = 0; i < t->n_inputs && !bad; i++) {
            if (pos + 36 > len) { bad = 1; break; }
            fr_bytes_to_display_hex(b + pos, t->prev_txid[i]);
            t->prev_vout[i] = fr_le32(b + pos + 32);
            pos += 36;
            int64_t sl = read_varint(b, len, &pos);
            if (sl < 0 || pos + (size_t)sl + 4 > len) { bad = 1; break; }
            pos += (size_t)sl;
            t->nseq[i] = fr_le32(b + pos);
            pos += 4;
        }
        if (bad) break;
        int64_t nout = read_varint(b, len, &pos);
        if (nout < 0) break;
        for (int64_t o = 0; o < nout && !bad; o++) {
            if (pos + 8 > len) { bad = 1; break; }
            pos += 8;
            int64_t sl = read_varint(b, len, &pos);
            if (sl < 0 || pos + (size_t)sl > len) { bad = 1; break; }
            pos += (size_t)sl;
        }
        if (bad) break;
        size_t body_end = pos;
        if (segwit) {
            for (size_t i = 0; i < t->n_inputs && !bad; i++) {
                int64_t ni = read_varint(b, len, &pos);
                if (ni < 0) { bad = 1; break; }
                for (int64_t k = 0; k < ni; k++) {
                    int64_t il = read_varint(b, len, &pos);
                    if (il < 0 || pos + (size_t)il > len) { bad = 1; break; }
                    pos += (size_t)il;
                }
            }
            if (bad) break;
        }
        if (pos + 4 != len) break;
        t->locktime = fr_le32(b + pos);

        size_t sl = 4 + (body_end - body_start) + 4;
        unsigned char *strip = malloc(sl);
        if (!strip) break;
        memcpy(strip, b, 4);
        memcpy(strip + 4, b + body_start, body_end - body_start);
        memcpy(strip + 4 + (body_end - body_start), b + pos, 4);
        unsigned char h[32];
        sha256_double(strip, sl, h);
        free(strip);
        fr_bytes_to_display_hex(h, t->txid);
        ok = 1;
    } while (0);
    free(b);
    t->parsed = ok;
    return ok;
}

/* ------------------------------------------------------------------ */
/* DB loading                                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int   pos;
    int   epoch;
    char  txid[65];
    char *hex;
} fr_chain_row_t;

/* Read one node's chain rows from ps_leaf_chains or ps_subfactory_chains
   (prepared statement `st`).  Rows come back ordered by chain_pos.
   Returns the count (rows in *out, caller frees), or -1 on error. */
static int fr_read_chain_rows(sqlite3_stmt *st, uint32_t fid, int32_t node,
                              fr_chain_row_t **out)
{
    *out = NULL;
    if (!st) return 0;
    sqlite3_reset(st);
    sqlite3_bind_int(st, 1, (int)fid);
    sqlite3_bind_int(st, 2, (int)node);
    int n = 0, cap = 0;
    fr_chain_row_t *v = NULL;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            int nc = cap ? cap * 2 : 8;
            fr_chain_row_t *nv = realloc(v, (size_t)nc * sizeof(*nv));
            if (!nv) {
                for (int i = 0; i < n; i++) free(v[i].hex);
                free(v);
                return -1;
            }
            v = nv;
            cap = nc;
        }
        fr_chain_row_t *r = &v[n++];
        memset(r, 0, sizeof(*r));
        r->pos   = sqlite3_column_int(st, 0);
        const unsigned char *tx = sqlite3_column_text(st, 1);
        if (tx) snprintf(r->txid, sizeof(r->txid), "%s", (const char *)tx);
        r->hex   = fr_strdup_or_null(sqlite3_column_text(st, 2));
        r->epoch = sqlite3_column_int(st, 3);
    }
    *out = v;
    return n;
}

static fr_tx_t *fr_push_tx(fr_set_t *s, const fr_row_t *row, int chain_pos,
                           const char *txid, char *hex_owned,
                           const char *missing_why)
{
    fr_tx_t *t = fr_set_push(s);
    if (!t) { free(hex_owned); fr_load_fail(s, "out of memory"); return NULL; }
    t->node_index   = row->node_index;
    t->parent_index = row->parent_index;
    t->chain_pos    = chain_pos;
    memcpy(t->type, row->type, sizeof(t->type));
    if (txid) snprintf(t->txid, sizeof(t->txid), "%s", txid);
    t->signed_tx_hex = hex_owned;
    t->missing_why   = hex_owned ? NULL : (missing_why ? missing_why
                                                       : "no signed TX stored");
    if (hex_owned) fr_parse_tx(t);
    return t;
}

/* Expand one tree_nodes row into its publishable TX(s). */
static void fr_expand_node(fr_set_t *s, uint32_t fid, const fr_row_t *row,
                           const char *tree_txid, char *tree_hex,
                           sqlite3_stmt *st_init, sqlite3_stmt *st_leaf,
                           sqlite3_stmt *st_sub)
{
    /* chain[0] of a PS node (replaced on every root-driven Tier B) */
    int   have_init = 0, init_epoch = 0;
    char  init_txid[65] = {0};
    char *init_hex = NULL;
    if (st_init) {
        sqlite3_reset(st_init);
        sqlite3_bind_int(st_init, 1, (int)fid);
        sqlite3_bind_int(st_init, 2, (int)row->node_index);
        if (sqlite3_step(st_init) == SQLITE_ROW) {
            const unsigned char *tx = sqlite3_column_text(st_init, 0);
            if (tx) snprintf(init_txid, sizeof(init_txid), "%s", (const char *)tx);
            init_hex   = fr_strdup_or_null(sqlite3_column_text(st_init, 1));
            init_epoch = sqlite3_column_int(st_init, 2);
            have_init  = (init_hex != NULL);
        }
    }

    fr_chain_row_t *lrows = NULL, *srows = NULL;
    int nl = fr_read_chain_rows(st_leaf, fid, row->node_index, &lrows);
    int ns = fr_read_chain_rows(st_sub,  fid, row->node_index, &srows);
    if (nl < 0 || ns < 0) fr_load_fail(s, "out of memory reading PS chain rows");
    if (nl < 0) nl = 0;
    if (ns < 0) ns = 0;

    fr_chain_row_t *rows = nl > 0 ? lrows : srows;
    int nrows = nl > 0 ? nl : ns;

    if (nl > 0 && ns > 0) {
        /* A node is a PS leaf or a sub-factory, never both. */
        fr_push_tx(s, row, 0, NULL, NULL,
                   "PS chain rows in both leaf and sub-factory tables");
        free(tree_hex);
        goto out;
    }

    if (nrows == 0) {
        /* Never advanced.  For a PS node the initial-state row is the
           current chain[0] (it is replaced on root-driven Tier B, which an
           older tree_nodes row may predate); otherwise the tree row is the
           current signed state. */
        if (have_init) {
            free(tree_hex);
            fr_push_tx(s, row, -1, init_txid, init_hex, NULL);
            init_hex = NULL;
        } else {
            fr_push_tx(s, row, -1, tree_txid, tree_hex, NULL);
        }
        goto out;
    }

    /* Advanced PS node: publish chain[0..N]. */
    {
        char *c0_hex = NULL;
        const char *c0_txid = NULL;
        const char *c0_why = NULL;
        if (have_init) {
            c0_hex = init_hex;
            c0_txid = init_txid;
            init_hex = NULL;
            free(tree_hex);
        } else {
            /* Without an initial-state row the tree row is chain[0] only if
               it is not one of the chain rows (a client re-persists
               tree_nodes with chain[N]). */
            int is_row = 0;
            for (int k = 0; k < nrows; k++)
                if (tree_txid && strcasecmp(rows[k].txid, tree_txid) == 0)
                    is_row = 1;
            if (!is_row && tree_hex) {
                c0_hex = tree_hex;
                c0_txid = tree_txid;
            } else {
                free(tree_hex);
                c0_why = "PS chain[0] missing (no ps_initial_signed_states row)";
            }
        }
        fr_push_tx(s, row, 0, c0_txid, c0_hex, c0_why);

        /* chain[1..N]: rows of chain[0]'s epoch, contiguous from pos 0. */
        int expect = 0, gap = 0;
        for (int k = 0; k < nrows; k++) {
            if (have_init && rows[k].epoch != init_epoch) {
                if (rows[k].epoch > init_epoch) {
                    fr_push_tx(s, row, k + 1, NULL, NULL,
                               "PS chain row newer than its chain[0] epoch");
                    gap = 1;
                }
                continue;
            }
            if (gap || rows[k].pos != expect) {
                fr_push_tx(s, row, expect + 1, NULL, NULL,
                           "PS chain history has a gap");
                gap = 1;
                break;
            }
            fr_push_tx(s, row, expect + 1, rows[k].txid, rows[k].hex,
                       "PS chain row has no signed TX");
            rows[k].hex = NULL;
            expect++;
        }
    }

out:
    free(init_hex);
    for (int k = 0; k < nl; k++) free(lrows[k].hex);
    for (int k = 0; k < ns; k++) free(srows[k].hex);
    free(lrows);
    free(srows);
}

/* Load every tree node of factory_id plus its PS chain.  Returns 1 if the
   factory has tree nodes, 0 if it has none, -1 on DB error.  A short read
   (fewer rows than COUNT(*)) or an allocation failure sets s->load_error. */
static int fr_load(persist_t *p, uint32_t fid, fr_set_t *s)
{
    memset(s, 0, sizeof(*s));
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(p->db,
            "SELECT COUNT(*) FROM tree_nodes WHERE factory_id=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)fid);
    s->expected_rows = (sqlite3_step(st) == SQLITE_ROW)
                       ? (long)sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (s->expected_rows < 0) return -1;
    if (s->expected_rows == 0) return 0;

    /* Optional tables (absent on very old DBs): a failed prepare = no rows. */
    sqlite3_stmt *st_init = NULL, *st_leaf = NULL, *st_sub = NULL;
    if (sqlite3_prepare_v2(p->db,
            "SELECT txid, signed_tx_hex, epoch FROM ps_initial_signed_states "
            "WHERE factory_id=? AND node_idx=?", -1, &st_init, NULL) != SQLITE_OK)
        st_init = NULL;
    if (sqlite3_prepare_v2(p->db,
            "SELECT chain_pos, txid, signed_tx_hex, epoch FROM ps_leaf_chains "
            "WHERE factory_id=? AND leaf_node_idx=? ORDER BY chain_pos ASC",
            -1, &st_leaf, NULL) != SQLITE_OK)
        st_leaf = NULL;
    if (sqlite3_prepare_v2(p->db,
            "SELECT chain_pos, txid, signed_tx_hex, epoch FROM ps_subfactory_chains "
            "WHERE factory_id=? AND sub_node_idx=? ORDER BY chain_pos ASC",
            -1, &st_sub, NULL) != SQLITE_OK)
        st_sub = NULL;

    int rc = 1;
    if (sqlite3_prepare_v2(p->db,
            "SELECT node_index, parent_index, txid, type, signed_tx_hex "
            "FROM tree_nodes WHERE factory_id=? ORDER BY node_index ASC",
            -1, &st, NULL) != SQLITE_OK) {
        rc = -1;
        goto done;
    }
    sqlite3_bind_int(st, 1, (int)fid);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (s->n_rows == s->rows_cap) {
            size_t nc = s->rows_cap ? s->rows_cap * 2 : 64;
            fr_row_t *nr = realloc(s->rows, nc * sizeof(*nr));
            if (!nr) { fr_load_fail(s, "out of memory loading tree nodes"); break; }
            s->rows = nr;
            s->rows_cap = nc;
        }
        fr_row_t *row = &s->rows[s->n_rows++];
        memset(row, 0, sizeof(*row));
        row->node_index   = sqlite3_column_int(st, 0);
        row->parent_index = (sqlite3_column_type(st, 1) == SQLITE_NULL)
                            ? -1 : sqlite3_column_int(st, 1);
        const unsigned char *txid = sqlite3_column_text(st, 2);
        char tree_txid[65] = {0};
        if (txid) snprintf(tree_txid, sizeof(tree_txid), "%s", (const char *)txid);
        const unsigned char *type = sqlite3_column_text(st, 3);
        if (type) snprintf(row->type, sizeof(row->type), "%s", (const char *)type);
        char *hex = fr_strdup_or_null(sqlite3_column_text(st, 4));
        fr_expand_node(s, fid, row, tree_txid[0] ? tree_txid : NULL, hex,
                       st_init, st_leaf, st_sub);
    }
    sqlite3_finalize(st);

    if ((long)s->n_rows != s->expected_rows) {
        char why[160];
        snprintf(why, sizeof(why), "loaded %zu of %ld tree nodes",
                 s->n_rows, s->expected_rows);
        fr_load_fail(s, why);
    }

    /* Leaves: persist_save_tree_nodes writes only "kickoff" / "state", so a
       leaf is a "state" node that no other tree node names as its parent
       (PS sub-factories are leaves; a PS leaf that hosts them is not). */
    for (size_t i = 0; i < s->n_rows; i++) {
        int has_child = 0;
        for (size_t j = 0; j < s->n_rows && !has_child; j++)
            if (s->rows[j].parent_index == s->rows[i].node_index) has_child = 1;
        s->rows[i].is_leaf = !has_child && strcmp(s->rows[i].type, "state") == 0;
    }

done:
    if (st_init) sqlite3_finalize(st_init);
    if (st_leaf) sqlite3_finalize(st_leaf);
    if (st_sub)  sqlite3_finalize(st_sub);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Chain helpers                                                         */
/* ------------------------------------------------------------------ */

static int get_confs(chain_backend_t *chain, const char *txid)
{
    if (!chain || !txid || !txid[0]) return -1;
    return chain->get_confirmations(chain, txid);
}

static void refresh_confs(chain_backend_t *chain, fr_set_t *s)
{
    if (!chain) return;
    for (size_t i = 0; i < s->n; i++) s->tx[i].confs = -1;

    /* Batch (single round-trip per chunk) when available; every TX is
       covered, in chunks of FR_BATCH. */
    enum { FR_BATCH = 256 };
    size_t i = 0;
    while (i < s->n) {
        const char *txids[FR_BATCH];
        int confs[FR_BATCH];
        size_t map[FR_BATCH];
        size_t count = 0, next = i;
        for (; next < s->n && count < FR_BATCH; next++) {
            if (!s->tx[next].txid[0]) continue;
            txids[count] = s->tx[next].txid;
            map[count] = next;
            count++;
        }
        int done = 0;
        if (count > 0 && chain->get_confirmations_batch &&
            chain->get_confirmations_batch(chain, txids, count, confs)) {
            for (size_t j = 0; j < count; j++) s->tx[map[j]].confs = confs[j];
            done = 1;
        }
        if (!done)
            for (size_t j = 0; j < count; j++)
                s->tx[map[j]].confs = get_confs(chain, s->tx[map[j]].txid);
        i = next;
    }
}

static fr_tx_t *fr_find(fr_set_t *s, const char *txid)
{
    for (size_t i = 0; i < s->n; i++)
        if (s->tx[i].txid[0] && strcasecmp(s->tx[i].txid, txid) == 0)
            return &s->tx[i];
    return NULL;
}

/* BIP-68 relative lock in blocks for one input, 0 if none, -1 if time-based. */
static int fr_csv_blocks(uint32_t version, uint32_t nseq)
{
    if (version < 2 || (nseq & 0x80000000u)) return 0;
    if (nseq & 0x00400000u) return -1;
    return (int)(nseq & 0xFFFFu);
}

/* Is t publishable now?  Every input's parent must be confirmed deep enough
   for its BIP-68 lock (or, with no lock, at least in the mempool / sent this
   pass); the funding input needs the network funding depth; a height-based
   nLockTime must have passed.  Inputs outside the factory (none today) are
   left for the node to judge. */
static int fr_ready(fr_set_t *s, const fr_tx_t *t, const char *funding_txid,
                    int funding_confs, int funding_min, int tip)
{
    if (!t->parsed) return 0;
    int any_non_final = 0;
    for (size_t j = 0; j < t->n_inputs; j++) {
        if (t->nseq[j] != 0xFFFFFFFFu) any_non_final = 1;
        int csv = fr_csv_blocks(t->version, t->nseq[j]);
        int have;
        fr_tx_t *u = fr_find(s, t->prev_txid[j]);
        if (u) {
            if (u->confs >= 1)                  have = u->confs;
            else if (u->confs == 0 || u->sent)  have = 0;
            else                                return 0;
        } else if (funding_txid && funding_txid[0] &&
                   strcasecmp(t->prev_txid[j], funding_txid) == 0) {
            if (funding_confs < funding_min) return 0;
            have = funding_confs;
        } else {
            continue;
        }
        if (csv < 0) { if (have < 1) return 0; continue; }
        if (have < csv) return 0;
    }
    if (any_non_final && t->locktime != 0 && t->locktime < 500000000u) {
        /* Final in the next block once tip >= nLockTime. */
        if (tip < 0 || (uint32_t)tip < t->locktime) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Broadcast                                                             */
/* ------------------------------------------------------------------ */

static int broadcast_tx(chain_backend_t *chain, persist_t *p, fr_tx_t *t)
{
    char result_txid[65] = {0};
    char source[48];
    if (t->chain_pos < 0)
        snprintf(source, sizeof(source), "recovery_node_%d", t->node_index);
    else
        snprintf(source, sizeof(source), "recovery_node_%d_chain%d",
                 t->node_index, t->chain_pos);

    int ok = chain->send_raw_tx(chain, t->signed_tx_hex, result_txid);

    /* Log every attempt (success or failure) to the broadcast audit table */
    const char *log_txid = result_txid[0] ? result_txid : t->txid;
    persist_log_broadcast(p, log_txid, source, t->signed_tx_hex,
                          ok ? "ok" : "failed");

    if (ok) {
        printf("LSP recovery: broadcast node %d chain_pos %d type=%s txid=%.16s...\n",
               t->node_index, t->chain_pos, t->type,
               result_txid[0] ? result_txid : t->txid);
        fflush(stdout);
        return 1;
    }

    /* Rejected although every input and timelock was satisfied: say whether
       an input was spent by a different transaction (a conflicting state). */
    t->fail_why = "rejected by the node";
    if (chain->is_outpoint_unspent) {
        for (size_t j = 0; j < t->n_inputs; j++) {
            if (chain->is_outpoint_unspent(chain, t->prev_txid[j],
                                           t->prev_vout[j]) == 0) {
                t->fail_why = "input already spent by another transaction";
                break;
            }
        }
    }
    printf("LSP recovery: broadcast node %d chain_pos %d FAILED: %s\n",
           t->node_index, t->chain_pos, t->fail_why);
    fflush(stdout);
    t->failed = 1;
    return 0;
}

/* All leaves' current TX (chain tip for PS) confirmed at the network-safe
   depth (returns 0 if the tree has no leaf).
   #265: was hardcoded `confs < 1`; now uses chain_funding_confs (1 on
   regtest, configurable elsewhere, default 6 on mainnet). */
static int all_leaves_confirmed(chain_backend_t *chain, fr_set_t *s)
{
    int min_confs = chain ? chain_funding_confs(chain, chain->is_regtest) : 1;
    int found = 0;
    for (size_t i = 0; i < s->n_rows; i++) {
        if (!s->rows[i].is_leaf) continue;
        const fr_tx_t *tip = NULL;
        for (size_t k = 0; k < s->n; k++)
            if (s->tx[k].node_index == s->rows[i].node_index &&
                (!tip || s->tx[k].chain_pos > tip->chain_pos))
                tip = &s->tx[k];
        if (!tip || tip->confs < min_confs) return 0;
        found = 1;
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* Core per-factory recovery                                            */
/* ------------------------------------------------------------------ */

enum { FR_MODE_SCAN = 0, FR_MODE_DRY_RUN = 1, FR_MODE_BROADCAST = 2 };

static void fr_note_failure(factory_recovery_result_t *r, const fr_tx_t *t,
                            const char *why)
{
    r->n_failed++;
    if (r->first_fail_why[0]) return;
    r->first_fail_node = t ? t->node_index : -1;
    r->first_fail_chain_pos = t ? t->chain_pos : -1;
    size_t wl = why ? strlen(why) : 0;
    if (wl >= sizeof(r->first_fail_why)) wl = sizeof(r->first_fail_why) - 1;
    if (wl) memcpy(r->first_fail_why, why, wl);
    r->first_fail_why[wl] = '\0';
}

/* mode FR_MODE_SCAN: do NOT broadcast any tree node.  This is the startup /
   reorg scan: an active factory's tree must never be force-published just
   because the funding confirmed, so the scan only refreshes confirmations
   and marks a fully settled factory closed.  It is not a rebroadcast path
   (Core re-mempools reorged-out transactions itself, and
   persist_retry_pending_broadcasts retries queued ones).
   FR_MODE_DRY_RUN: compute what a broadcast pass would publish, send nothing.
   FR_MODE_BROADCAST: explicit operator / self-exit force-close; publish every
   TX whose inputs and timelocks allow it, root down.
   Returns 1 if the factory had tree nodes, 0 if none, -1 on DB error. */
static int do_factory_recovery(persist_t *p, chain_backend_t *chain,
                               uint32_t factory_id, const char *funding_txid,
                               int mode, factory_recovery_result_t *res)
{
    factory_recovery_result_t local;
    if (!res) res = &local;
    memset(res, 0, sizeof(*res));
    res->first_fail_node = -1;
    res->first_fail_chain_pos = -1;
    res->dry_run = (mode == FR_MODE_DRY_RUN);

    fr_set_t s;
    int lrc = fr_load(p, factory_id, &s);
    if (lrc <= 0) {
        if (lrc < 0) fr_note_failure(res, NULL, "DB error loading tree nodes");
        fr_set_free(&s);
        return lrc;
    }
    res->n_tree_nodes = (int)s.n_rows;
    res->n_txs = (int)s.n;

    int funding_confs = get_confs(chain, funding_txid);
    int funding_min = chain ? chain_funding_confs(chain, chain->is_regtest) : 1;
    int tip = chain && chain->get_block_height ? chain->get_block_height(chain) : -1;
    refresh_confs(chain, &s);

    if (mode != FR_MODE_SCAN) {
        if (s.load_error) fr_note_failure(res, NULL, s.load_why);

        /* Topological passes until nothing new becomes publishable.  A TX
           sent this pass counts as in-mempool for its children (only those
           without a relative lock can follow it in the same pass). */
        int progress = 1;
        while (progress) {
            progress = 0;
            for (size_t i = 0; i < s.n; i++) {
                fr_tx_t *t = &s.tx[i];
                if (t->confs >= 0 || t->sent || t->failed) continue;
                if (!t->signed_tx_hex || !t->parsed) continue;
                if (!fr_ready(&s, t, funding_txid, funding_confs,
                              funding_min, tip))
                    continue;
                if (mode == FR_MODE_DRY_RUN) {
                    t->sent = 1;
                    res->n_broadcast++;
                    progress = 1;
                    continue;
                }
                if (broadcast_tx(chain, p, t)) {
                    t->sent = 1;
                    res->n_broadcast++;
                    progress = 1;
                }
            }
        }

        for (size_t i = 0; i < s.n; i++) {
            fr_tx_t *t = &s.tx[i];
            if (t->confs >= 1)                 res->n_confirmed++;
            else if (t->sent)                  ;  /* counted in n_broadcast */
            else if (t->confs == 0)            res->n_in_mempool++;
            else if (!t->signed_tx_hex)        fr_note_failure(res, t, t->missing_why);
            else if (!t->parsed)               fr_note_failure(res, t,
                                                   "stored signed TX does not parse");
            else if (t->failed)                fr_note_failure(res, t, t->fail_why);
            else                               res->n_waiting++;
        }
    } else {
        for (size_t i = 0; i < s.n; i++)
            if (s.tx[i].confs >= 1) res->n_confirmed++;
    }

    /* Re-check after real broadcasts, then auto-close if settled. */
    if (mode == FR_MODE_BROADCAST && res->n_broadcast > 0)
        refresh_confs(chain, &s);
    res->settled = all_leaves_confirmed(chain, &s);
    if (res->settled && mode != FR_MODE_DRY_RUN) {
        persist_mark_factory_closed(p, factory_id);
        printf("LSP recovery: factory %u fully settled — marked closed\n",
               factory_id);
        fflush(stdout);
    }

    fr_set_free(&s);
    return 1;
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

    /* Collect first: do_factory_recovery may UPDATE factories (auto-close)
       while this SELECT is still stepping. */
    size_t n = 0, cap = 0;
    struct fr_scan_item { uint32_t id; char txid[65]; char state[16]; } *items = NULL;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 8;
            void *ni = realloc(items, nc * sizeof(*items));
            if (!ni) break;
            items = ni;
            cap = nc;
        }
        struct fr_scan_item *it = &items[n++];
        memset(it, 0, sizeof(*it));
        it->id = (uint32_t)sqlite3_column_int(stmt, 0);
        const char *ftxid = (const char *)sqlite3_column_text(stmt, 1);
        const char *state = (const char *)sqlite3_column_text(stmt, 2);
        if (ftxid) snprintf(it->txid, sizeof(it->txid), "%s", ftxid);
        if (state) snprintf(it->state, sizeof(it->state), "%s", state);
    }
    sqlite3_finalize(stmt);

    for (size_t i = 0; i < n; i++) {
        printf("LSP recovery: factory %u state=%s funding=%.16s...\n",
               items[i].id, items[i].state[0] ? items[i].state : "?",
               items[i].txid[0] ? items[i].txid : "none");
        fflush(stdout);
        if (items[i].txid[0])
            do_factory_recovery(p, chain, items[i].id, items[i].txid,
                                FR_MODE_SCAN, NULL);
    }
    free(items);

    if (n > 0) {
        printf("LSP recovery: scanned %zu non-closed factor%s\n",
               n, n == 1 ? "y" : "ies");
        fflush(stdout);
    }
    return (int)n;
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
        {   /* a pending root advance freezes leaf operations */
            persist_root_advance_status_t rs;
            if (persist_load_root_advance_status(p, fid, &rs) == 1) {
                cJSON *ra = cJSON_CreateObject();
                cJSON_AddNumberToObject(ra, "epoch", (double)rs.epoch);
                cJSON_AddStringToObject(ra, "withholders", rs.withholders);
                cJSON_AddNumberToObject(ra, "frozen_since_height", (double)rs.since_height);
                cJSON_AddNumberToObject(ra, "last_redrive_height",
                                        (double)rs.last_redrive_height);
                cJSON_AddBoolToObject(ra, "escalated", rs.escalated ? 1 : 0);
                cJSON_AddItemToObject(fobj, "root_advance_pending", ra);
            }
        }

        /* Tree node stats (whole tree; PS chains included in n_txs) */
        fr_set_t s;
        int n_confirmed = 0, n_leaf = 0, n_leaf_confirmed = 0;
        int lrc = fr_load(p, fid, &s);
        if (lrc > 0) {
            if (chain) refresh_confs(chain, &s);
            for (size_t i = 0; i < s.n; i++)
                if (chain && s.tx[i].confs >= 1) n_confirmed++;
            for (size_t i = 0; i < s.n_rows; i++) {
                if (!s.rows[i].is_leaf) continue;
                n_leaf++;
                const fr_tx_t *tip = NULL;
                for (size_t k = 0; k < s.n; k++)
                    if (s.tx[k].node_index == s.rows[i].node_index &&
                        (!tip || s.tx[k].chain_pos > tip->chain_pos))
                        tip = &s.tx[k];
                if (chain && tip && tip->confs >= 1) n_leaf_confirmed++;
            }
        }
        cJSON_AddNumberToObject(fobj, "n_tree_nodes",        (double)s.n_rows);
        cJSON_AddNumberToObject(fobj, "n_txs",               (double)s.n);
        cJSON_AddNumberToObject(fobj, "n_confirmed",         (double)n_confirmed);
        cJSON_AddNumberToObject(fobj, "n_leaf",              (double)n_leaf);
        cJSON_AddNumberToObject(fobj, "n_leaf_confirmed",    (double)n_leaf_confirmed);
        fr_set_free(&s);

        int fconfs = (chain && ftxid && ftxid[0]) ? get_confs(chain, ftxid) : -1;
        cJSON_AddNumberToObject(fobj, "funding_confs", (double)fconfs);

        cJSON_AddItemToArray(arr, fobj);
    }
    sqlite3_finalize(stmt);
    return arr;
}

int factory_recovery_run_ex(persist_t *p, chain_backend_t *chain,
                            uint32_t factory_id, int dry_run,
                            factory_recovery_result_t *res,
                            char *status_out, size_t cap)
{
    factory_recovery_result_t local;
    if (!res) res = &local;
    memset(res, 0, sizeof(*res));
    res->first_fail_node = -1;
    res->first_fail_chain_pos = -1;
    res->dry_run = dry_run ? 1 : 0;

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

    int rc = do_factory_recovery(p, chain, factory_id, funding_txid,
                                 dry_run ? FR_MODE_DRY_RUN : FR_MODE_BROADCAST,
                                 res);
    if (rc == 0 && res->n_failed == 0)
        fr_note_failure(res, NULL, "factory has no tree nodes in the DB");

    if (status_out && cap) {
        int n = snprintf(status_out, cap,
            "factory %u (state=%s): %s %d TX%s; confirmed %d/%d, in mempool %d, "
            "waiting %d, failed %d%s",
            factory_id, state[0] ? state : "?",
            dry_run ? "dry run, would broadcast" : "broadcast",
            res->n_broadcast, res->n_broadcast == 1 ? "" : "s",
            res->n_confirmed, res->n_txs, res->n_in_mempool,
            res->n_waiting, res->n_failed,
            res->settled ? "; settled" : "");
        if (res->n_failed > 0 && n > 0 && (size_t)n < cap) {
            if (res->first_fail_node >= 0)
                snprintf(status_out + n, cap - (size_t)n,
                         " (first: node %d chain_pos %d: %s)",
                         res->first_fail_node, res->first_fail_chain_pos,
                         res->first_fail_why);
            else
                snprintf(status_out + n, cap - (size_t)n, " (%s)",
                         res->first_fail_why);
        }
    }
    return res->n_failed == 0 ? 1 : 0;
}

int factory_recovery_run(persist_t *p, chain_backend_t *chain,
                         uint32_t factory_id,
                         char *status_out, size_t cap)
{
    return factory_recovery_run_ex(p, chain, factory_id, /*dry_run=*/0, NULL,
                                   status_out, cap);
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
 * Parse a raw segwit Bitcoin TX (as hex) and extract outputs.
 * Fills amounts_out[] and spks_out[][34] up to max entries.
 * spk_lens_out[i] is set to the actual scriptPubKey length.
 * Returns number of outputs parsed, -1 on error.
 */
static int tx_parse_outputs(const char *hex,
                             uint64_t *amounts_out,
                             unsigned char (*spks_out)[34],
                             size_t *spk_lens_out,
                             int max)
{
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
    if (n_outputs < 0) { free(tx); return -1; }

    int count = 0;
    for (int64_t i = 0; i < n_outputs; i++) {
        if (pos + 8 > len) { free(tx); return -1; }
        uint64_t amount = 0;
        for (int b = 0; b < 8; b++) amount |= ((uint64_t)tx[pos+b] << (8*b));
        pos += 8;

        int64_t spk_len = read_varint(tx, len, &pos);
        if (spk_len < 0) { free(tx); return -1; }
        if (pos + (size_t)spk_len > len) { free(tx); return -1; }

        if (count < max) {
            amounts_out[count] = amount;
            size_t copy = (size_t)spk_len < 34 ? (size_t)spk_len : 34;
            memcpy(spks_out[count], tx + pos, copy);
            spk_lens_out[count] = copy;
            count++;
        }
        pos += (size_t)spk_len;
    }

    (void)segwit;
    free(tx);
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
#define MAX_LEAF_OUTS 8
        uint64_t amounts[MAX_LEAF_OUTS];
        unsigned char spks[MAX_LEAF_OUTS][34];
        size_t spk_lens[MAX_LEAF_OUTS];
        int n_outs = tx_parse_outputs(hex, amounts, spks, spk_lens, MAX_LEAF_OUTS);
        if (n_outs <= 0) continue;

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
                /*
                 * Try CLTV script-path sweep: output key is
                 * taptweak(MuSig2_agg(client, LSP), CLTV_leaf_hash).
                 * The LSP can spend via the script leaf after cltv_timeout
                 * blocks using only its own private key.
                 */
                int handled = 0;
                secp256k1_pubkey client_pub;
                int have_client = 0;
                do {
                    if (cltv_timeout == 0) break;
                    if (spk_lens[vout] != 34 ||
                        spks[vout][0] != 0x51 || spks[vout][1] != 0x20)
                        break;

                    /* Find client pubkey: channels.slot → factory_participants.slot+1 */
                    {
                        sqlite3_stmt *cst;
                        if (sqlite3_prepare_v2(p->db,
                                "SELECT slot FROM channels "
                                "WHERE factory_id=? AND funding_txid=?"
                                "  AND funding_vout=?",
                                -1, &cst, NULL) == SQLITE_OK) {
                            sqlite3_bind_int (cst, 1, (int)factory_id);
                            sqlite3_bind_text(cst, 2, txid, -1, SQLITE_STATIC);
                            sqlite3_bind_int (cst, 3, vout);
                            if (sqlite3_step(cst) == SQLITE_ROW) {
                                int ch_slot = sqlite3_column_int(cst, 0);
                                sqlite3_stmt *pst;
                                if (sqlite3_prepare_v2(p->db,
                                        "SELECT pubkey FROM factory_participants "
                                        "WHERE factory_id=? AND slot=?",
                                        -1, &pst, NULL) == SQLITE_OK) {
                                    sqlite3_bind_int(pst, 1, (int)factory_id);
                                    sqlite3_bind_int(pst, 2, ch_slot + 1);
                                    if (sqlite3_step(pst) == SQLITE_ROW) {
                                        const char *pk_hex =
                                            (const char *)sqlite3_column_text(pst, 0);
                                        if (pk_hex && strlen(pk_hex) == 66) {
                                            unsigned char pb[33];
                                            int ok2 = 1;
                                            for (int b2 = 0; b2 < 33 && ok2; b2++) {
                                                unsigned char h2 = nibble(pk_hex[2*b2]);
                                                unsigned char l2 = nibble(pk_hex[2*b2+1]);
                                                if (h2 == 0xFF || l2 == 0xFF)
                                                    ok2 = 0;
                                                else
                                                    pb[b2] = (unsigned char)(h2 << 4 | l2);
                                            }
                                            if (ok2 && secp256k1_ec_pubkey_parse(
                                                    ctx, &client_pub, pb, 33))
                                                have_client = 1;
                                        }
                                    }
                                    sqlite3_finalize(pst);
                                }
                            }
                            sqlite3_finalize(cst);
                        }
                    }
                    if (!have_client) break;

                    /* Reconstruct output key: taptweak(MuSig2(client,LSP), CLTV_leaf) */
                    secp256k1_pubkey pks[2] = { client_pub, lsp_pub };
                    musig_keyagg_t ka;
                    if (!musig_aggregate_keys(ctx, &ka, pks, 2)) break;

                    tapscript_leaf_t cltv_leaf;
                    if (!tapscript_build_cltv_timeout(&cltv_leaf, cltv_timeout,
                                                       &lsp_xonly, ctx)) break;

                    unsigned char merkle_root[32];
                    tapscript_merkle_root(merkle_root, &cltv_leaf, 1);

                    secp256k1_xonly_pubkey tweaked;
                    int parity = 0;
                    if (!tapscript_tweak_pubkey(ctx, &tweaked, &parity,
                                                 &ka.agg_pubkey, merkle_root)) break;

                    unsigned char tweaked_bytes[32];
                    secp256k1_xonly_pubkey_serialize(ctx, tweaked_bytes, &tweaked);
                    if (memcmp(tweaked_bytes, spks[vout] + 2, 32) != 0) break;

                    /* Key matches: this is a CLTV output */
                    handled = 1;
                    int block_height = chain ? chain->get_block_height(chain) : 0;
                    if (block_height < (int)cltv_timeout) {
                        cJSON_AddStringToObject(entry, "status", "cltv_not_mature");
                        cJSON_AddNumberToObject(entry, "cltv_timeout",
                                                (double)cltv_timeout);
                        cJSON_AddNumberToObject(entry, "current_height",
                                                (double)block_height);
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }
                    if (amounts[vout] <= fee_sats) {
                        cJSON_AddStringToObject(entry, "status", "insufficient_funds");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }
                    if (dry_run || !chain || !dest_spk || dest_spk_len == 0) {
                        cJSON_AddStringToObject(entry, "status", "dry_run_cltv");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }

                    /* Build unsigned sweep TX */
                    tx_output_t sweep_out;
                    sweep_out.amount_sats = amounts[vout] - fee_sats;
                    size_t splen = dest_spk_len < 34 ? dest_spk_len : 34;
                    memcpy(sweep_out.script_pubkey, dest_spk, splen);
                    sweep_out.script_pubkey_len = splen;

                    tx_buf_t unsigned_tx2;
                    tx_buf_init(&unsigned_tx2, 512);
                    int built2 = build_unsigned_tx_with_locktime(
                        &unsigned_tx2, NULL,
                        txid_internal, (uint32_t)vout,
                        0xFFFFFFFE, cltv_timeout,
                        &sweep_out, 1);
                    if (!built2 || unsigned_tx2.oom) {
                        tx_buf_free(&unsigned_tx2);
                        cJSON_AddStringToObject(entry, "status", "build_failed");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }

                    /* BIP-342 script-path sighash */
                    unsigned char sighash2[32];
                    int sh2_ok = compute_tapscript_sighash(
                        sighash2,
                        unsigned_tx2.data, unsigned_tx2.len,
                        0,
                        spks[vout], spk_lens[vout],
                        amounts[vout], 0xFFFFFFFE,
                        &cltv_leaf);
                    if (!sh2_ok) {
                        tx_buf_free(&unsigned_tx2);
                        cJSON_AddStringToObject(entry, "status", "sighash_failed");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }

                    /* Sign with LSP key (the key inside the CLTV script) */
                    unsigned char sig2[64];
                    unsigned char aux2[32] = {0};
                    if (!secp256k1_schnorrsig_sign32(ctx, sig2, sighash2,
                                                      &lsp_kp, aux2)) {
                        tx_buf_free(&unsigned_tx2);
                        cJSON_AddStringToObject(entry, "status", "sign_failed");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }

                    /* Control block: (0xC0|parity) || internal_xonly[32] */
                    unsigned char ctrl[33];
                    size_t ctrl_len = 0;
                    if (!tapscript_build_control_block(ctrl, &ctrl_len, parity,
                                                        &ka.agg_pubkey, ctx)) {
                        tx_buf_free(&unsigned_tx2);
                        cJSON_AddStringToObject(entry, "status", "ctrl_failed");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }

                    /* Finalize script-path witness: [sig, script, control_block] */
                    tx_buf_t signed_tx2;
                    tx_buf_init(&signed_tx2, unsigned_tx2.len + 200);
                    int fin2 = finalize_script_path_tx(
                        &signed_tx2,
                        unsigned_tx2.data, unsigned_tx2.len,
                        sig2,
                        cltv_leaf.script, cltv_leaf.script_len,
                        ctrl, ctrl_len);
                    tx_buf_free(&unsigned_tx2);
                    if (!fin2 || signed_tx2.oom) {
                        tx_buf_free(&signed_tx2);
                        cJSON_AddStringToObject(entry, "status", "finalize_failed");
                        cJSON_AddItemToArray(results, entry);
                        break;
                    }

                    /* Hex-encode, broadcast, log */
                    size_t hlen2 = signed_tx2.len * 2 + 1;
                    char *tx_hex2 = malloc(hlen2);
                    if (tx_hex2)
                        hex_encode(signed_tx2.data, signed_tx2.len, tx_hex2);
                    char rtxid2[65] = {0};
                    int bcast2 = chain->send_raw_tx(chain, tx_hex2, rtxid2);
                    char src2[52];
                    snprintf(src2, sizeof(src2), "cltvsweep%u_n%d_v%d",
                             factory_id, node_idx, vout);
                    persist_log_broadcast(p,
                        rtxid2[0] ? rtxid2 : txid,
                        src2,
                        tx_hex2 ? tx_hex2 : "",
                        bcast2 ? "ok" : "failed");
                    free(tx_hex2);
                    tx_buf_free(&signed_tx2);

                    if (bcast2) {
                        cJSON_AddStringToObject(entry, "status", "swept_cltv");
                        cJSON_AddStringToObject(entry, "sweep_txid", rtxid2);
                        printf("CLTV sweep: factory %u node %d vout %d -> %s\n",
                               factory_id, node_idx, vout, rtxid2);
                        fflush(stdout);
                    } else {
                        cJSON_AddStringToObject(entry, "status", "broadcast_failed");
                    }
                    cJSON_AddItemToArray(results, entry);
                } while (0);

                if (!handled) {
                    cJSON_AddStringToObject(entry, "status", "requires_client_key");
                    cJSON_AddItemToArray(results, entry);
                }
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
    }
    sqlite3_finalize(stmt);
    return results;
}
