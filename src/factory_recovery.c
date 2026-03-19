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
#include "superscalar/tx_builder.h"
#include "superscalar/types.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
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

        /* Check this state TX is confirmed */
        int confs = chain ? chain->get_confirmations(chain, txid) : -1;
        if (confs < 1) continue;  /* not confirmed — skip */

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
             * If the 32-byte key matches the LSP x-only pubkey, we can sign.
             */
            int is_lsp_key_path = 0;
            if (spk_lens[vout] == 34 &&
                spks[vout][0] == 0x51 && spks[vout][1] == 0x20 &&
                memcmp(spks[vout] + 2, lsp_xonly_bytes, 32) == 0) {
                is_lsp_key_path = 1;
            }

            if (!is_lsp_key_path) {
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

            /* Schnorr sign */
            unsigned char sig64[64];
            unsigned char aux[32] = {0};
            if (!secp256k1_schnorrsig_sign32(ctx, sig64, sighash, &lsp_kp, aux)) {
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
