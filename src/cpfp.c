#include "superscalar/cpfp.h"
#include "superscalar/channel.h"   /* P2A_SPK, ANCHOR_OUTPUT_AMOUNT */
#include "superscalar/sha256.h"
#include "superscalar/fee.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* ---- parsing ---------------------------------------------------------- */

static int rd_varint(const unsigned char *tx, size_t len, size_t *pos, uint64_t *out) {
    if (*pos >= len) return 0;
    unsigned char b = tx[*pos];
    if (b < 0xfd) { *out = b; *pos += 1; return 1; }
    size_t n = b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (*pos + 1 + n > len) return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v |= (uint64_t)tx[*pos + 1 + i] << (8 * i);
    *out = v;
    *pos += 1 + n;
    return 1;
}

int cpfp_parse_tx(const unsigned char *tx, size_t len, cpfp_tx_info_t *out) {
    if (!tx || !out || len < 10) return 0;
    memset(out, 0, sizeof(*out));
    out->anchor_vout = -1;
    out->version = (uint32_t)tx[0] | ((uint32_t)tx[1] << 8) |
                   ((uint32_t)tx[2] << 16) | ((uint32_t)tx[3] << 24);
    int segwit = (tx[4] == 0x00 && tx[5] == 0x01);
    size_t start = segwit ? 6 : 4, pos = start;
    uint64_t n_in, n_out, v;
    if (!rd_varint(tx, len, &pos, &n_in) || n_in == 0 || n_in > CPFP_MAX_INPUTS)
        return 0;
    out->n_inputs = (size_t)n_in;
    for (size_t i = 0; i < out->n_inputs; i++) {
        if (pos + 36 > len) return 0;
        memcpy(out->in_txid[i], tx + pos, 32);
        out->in_vout[i] = (uint32_t)tx[pos + 32] | ((uint32_t)tx[pos + 33] << 8) |
                          ((uint32_t)tx[pos + 34] << 16) | ((uint32_t)tx[pos + 35] << 24);
        pos += 36;
        if (!rd_varint(tx, len, &pos, &v) || pos + v + 4 > len) return 0;
        pos += (size_t)v + 4;
    }
    if (!rd_varint(tx, len, &pos, &n_out)) return 0;
    out->n_outputs = (size_t)n_out;
    for (size_t i = 0; i < out->n_outputs; i++) {
        if (pos + 8 > len) return 0;
        uint64_t amt = 0;
        for (int k = 0; k < 8; k++) amt |= (uint64_t)tx[pos + k] << (8 * k);
        pos += 8;
        if (!rd_varint(tx, len, &pos, &v) || pos + v > len) return 0;
        if (v == P2A_SPK_LEN && memcmp(tx + pos, P2A_SPK, P2A_SPK_LEN) == 0 &&
            out->anchor_vout < 0) {
            out->anchor_vout = (int)i;
            out->anchor_amount = amt;
        }
        out->out_total += amt;
        pos += (size_t)v;
    }
    size_t outputs_end = pos;
    if (segwit) {
        for (size_t i = 0; i < out->n_inputs; i++) {
            uint64_t n_items;
            if (!rd_varint(tx, len, &pos, &n_items)) return 0;
            for (uint64_t k = 0; k < n_items; k++) {
                if (!rd_varint(tx, len, &pos, &v) || pos + v > len) return 0;
                pos += (size_t)v;
            }
        }
    }
    if (pos + 4 != len) return 0;

    /* txid over the witness-less serialization */
    size_t base_len = 4 + (outputs_end - start) + 4;
    unsigned char *base = malloc(base_len);
    if (!base) return 0;
    memcpy(base, tx, 4);
    memcpy(base + 4, tx + start, outputs_end - start);
    memcpy(base + 4 + (outputs_end - start), tx + len - 4, 4);
    sha256_double(base, base_len, out->txid);
    free(base);
    unsigned char disp[32];
    memcpy(disp, out->txid, 32);
    reverse_bytes(disp, 32);
    hex_encode(disp, 32, out->txid_hex);

    size_t weight = base_len * 3 + len;
    out->vsize = (weight + 3) / 4;
    return 1;
}

uint64_t cpfp_child_fee(uint64_t parent_fee, size_t parent_vsize,
                        size_t child_vsize, uint64_t pkg_rate) {
    uint64_t pkg = fee_at_rate(pkg_rate, parent_vsize + child_vsize);
    uint64_t own = fee_at_rate(pkg_rate, child_vsize);
    if (pkg == FEE_INVALID || own == FEE_INVALID) return FEE_INVALID;
    uint64_t need = pkg > parent_fee ? pkg - parent_fee : 0;
    return need > own ? need : own;
}

/* ---- child construction ----------------------------------------------- */

/* What a CPFP child on a parent's anchor must achieve. */
typedef struct {
    uint64_t base_fee;      /* fee of the parent and its unconfirmed ancestors */
    size_t   base_vsize;    /* their total vsize */
    uint64_t pkg_rate;      /* (base + child) must reach this, sat/kvB */
    int      replaces;      /* the child replaces mempool txs (RBF / TRUC
                               sibling eviction) */
    uint64_t repl_fee;      /* their fees, descendants included */
    uint64_t repl_rate;     /* the highest feerate among them, sat/kvB */
    uint64_t incr_rate;     /* the node's incremental relay feerate, sat/kvB */
    uint64_t max_fee;       /* the child pays at most this; 0 = no limit */
    /* A wallet coin to spend first: the input of our own child that this one
       replaces (spent in the mempool, so the wallet does not list it). */
    int      has_coin;
    char     coin_txid[65];
    uint32_t coin_vout;
    uint64_t coin_amount;
    unsigned char coin_spk[64];
    size_t   coin_spk_len;
} child_spec_t;

/* A wallet coin build_child reserved (get_utxo locks it): released once the
   child is broadcast or given up on, so no concurrent caller picks it. */
typedef struct {
    int      held;
    char     txid[65];
    uint32_t vout;
} coin_lock_t;

static void coin_release(wallet_source_t *wallet, coin_lock_t *lock) {
    if (lock && lock->held && wallet && wallet->release_utxo)
        wallet->release_utxo(wallet, lock->txid, lock->vout);
    if (lock) lock->held = 0;
}

/* Fee a child of vsize pays under spec: the package shortfall, at least what
   replacing the conflicting txs requires (BIP 125 rules 3, 4 and 6: their
   fees plus the incremental relay fee for the child's size, at a higher
   feerate), at most max_fee.  FEE_INVALID if no fee within max_fee meets the
   replacement rules.  *capped (optional): 1 when max_fee kept the child below
   the package target. */
static uint64_t spec_fee(const child_spec_t *s, size_t vsize, int *capped) {
    if (capped) *capped = 0;
    uint64_t fee = cpfp_child_fee(s->base_fee, s->base_vsize, vsize, s->pkg_rate);
    if (fee == FEE_INVALID) return FEE_INVALID;
    uint64_t min = 0;
    if (s->replaces) {
        uint64_t incr = fee_at_rate(s->incr_rate, vsize);
        if (incr == FEE_INVALID || s->repl_fee > FEE_MAX_SATS) return FEE_INVALID;
        min = s->repl_fee + incr;
        uint64_t by_rate = (uint64_t)(((unsigned __int128)s->repl_rate * vsize) / 1000) + 1;
        if (by_rate > min) min = by_rate;
    }
    if (fee < min) fee = min;
    if (s->max_fee > 0 && fee > s->max_fee) {
        if (capped) *capped = 1;
        fee = s->max_fee;
        if (fee < min) return FEE_INVALID;
    }
    return fee;
}

static void write_input(tx_buf_t *t, const unsigned char *txid32, uint32_t vout) {
    tx_buf_write_bytes(t, txid32, 32);
    tx_buf_write_u32_le(t, vout);
    tx_buf_write_varint(t, 0);            /* empty scriptSig */
    tx_buf_write_u32_le(t, 0xFFFFFFFDu);
}

static int build_anchor_only(const cpfp_tx_info_t *parent, uint32_t version,
                             tx_buf_t *child_out, uint64_t *fee_out) {
    /* P2A input, a 0-value OP_RETURN output padded so the tx meets the 65-byte
       minimum non-witness size; the whole anchor value is fee.  A 0-value
       anchor pays nothing: no such child. */
    if (parent->anchor_amount == 0) return 0;
    static const unsigned char op_return[5] = { 0x6a, 0x03, 0x53, 0x53, 0x41 };
    tx_buf_reset(child_out);
    tx_buf_write_u32_le(child_out, version);
    tx_buf_write_varint(child_out, 1);
    write_input(child_out, parent->txid, (uint32_t)parent->anchor_vout);
    tx_buf_write_varint(child_out, 1);
    tx_buf_write_u64_le(child_out, 0);
    tx_buf_write_varint(child_out, sizeof(op_return));
    tx_buf_write_bytes(child_out, op_return, sizeof(op_return));
    tx_buf_write_u32_le(child_out, 0);
    if (child_out->oom) return 0;
    if (fee_out) *fee_out = parent->anchor_amount;
    return 1;
}

static int build_wallet_child(wallet_source_t *w, const cpfp_tx_info_t *parent,
                              uint32_t version, const char *w_txid_hex,
                              uint32_t w_vout, uint64_t w_amount,
                              const unsigned char *w_spk, size_t w_spk_len,
                              const unsigned char *chg_spk, size_t chg_spk_len,
                              uint64_t fee, tx_buf_t *child_out) {
    unsigned char w_txid[32];
    if (hex_decode(w_txid_hex, w_txid, 32) != 32) return 0;
    reverse_bytes(w_txid, 32);
    uint64_t in_total = w_amount + parent->anchor_amount;
    if (fee > FEE_MAX_SATS || in_total <= fee + CHANNEL_DUST_LIMIT_SATS) return 0;

    tx_buf_t u;
    tx_buf_init(&u, 256);
    tx_buf_write_u32_le(&u, version);
    tx_buf_write_varint(&u, 2);
    write_input(&u, parent->txid, (uint32_t)parent->anchor_vout);  /* P2A: no witness */
    write_input(&u, w_txid, w_vout);
    tx_buf_write_varint(&u, 1);
    tx_buf_write_u64_le(&u, in_total - fee);
    tx_buf_write_varint(&u, chg_spk_len);
    tx_buf_write_bytes(&u, chg_spk, chg_spk_len);
    tx_buf_write_u32_le(&u, 0);
    if (u.oom) { tx_buf_free(&u); return 0; }

    size_t cap = u.len + 512;
    unsigned char *buf = malloc(cap);
    if (!buf) { tx_buf_free(&u); return 0; }
    memcpy(buf, u.data, u.len);
    size_t blen = u.len;
    tx_buf_free(&u);
    int ok = w->sign_input(w, buf, &blen, 1, w_spk, w_spk_len, w_amount);
    if (ok) {
        tx_buf_reset(child_out);
        tx_buf_write_bytes(child_out, buf, blen);
        ok = !child_out->oom;
    }
    free(buf);
    return ok;
}

/* ---- why an exit could not get its fee-paying child -------------------- */

static cpfp_need_t g_need_seen;
static int g_child_no_coin;   /* build_child fell back to the anchor alone */

cpfp_need_t cpfp_need_seen(void) { return g_need_seen; }
void cpfp_need_clear(void) { g_need_seen = CPFP_NEED_NONE; }

const char *cpfp_need_text(cpfp_need_t n) {
    switch (n) {
    case CPFP_NEED_COIN:
        return "no wallet coin available: a unilateral exit needs a small "
               "confirmed on-chain coin in the bitcoind wallet named by --wallet";
    case CPFP_NEED_PACKAGE_RELAY:
        return "no package relay backend: the fee-paying child can only be sent "
               "with it through bitcoind RPC (submitpackage, Bitcoin Core 29.1+)";
    default:
        return "none";
    }
}

static void need_record(cpfp_need_t n, const char *txid_hex) {
    if (g_need_seen == CPFP_NEED_NONE) g_need_seen = n;
    fprintf(stderr, "CPFP: ERROR: %s needs a fee-paying child: %s\n",
            txid_hex ? txid_hex : "the transaction", cpfp_need_text(n));
}

int cpfp_anchor_alone_short(uint64_t parent_fee, size_t parent_vsize,
                            uint64_t anchor_amount, uint64_t need_rate) {
    uint64_t want = fee_at_rate(need_rate, parent_vsize + CPFP_ANCHOR_ONLY_CHILD_VSIZE);
    return want == FEE_INVALID || parent_fee + anchor_amount < want;
}

/* Build a child for parent under spec.  With a wallet: spends spec's coin if
   it has one (falling back to a coin from get_utxo when the wallet cannot sign
   it), plus the anchor, into a change output.  Without one, or when the
   wallet has nothing usable: the anchor-only child, unless the child must
   replace something (an anchor-only child cannot outbid a mempool tx).
   Returns 1 with *fee_out, *used_wallet_out and *capped_out (all optional).
   A coin taken from get_utxo stays locked in *lock until the caller has
   broadcast the child (coin_release). */
static int build_child(wallet_source_t *wallet, const cpfp_tx_info_t *parent,
                       const child_spec_t *spec, tx_buf_t *child_out,
                       uint64_t *fee_out, int *used_wallet_out, int *capped_out,
                       coin_lock_t *lock) {
    if (lock) lock->held = 0;
    g_child_no_coin = 0;
    if (!parent || !child_out || parent->anchor_vout < 0) return 0;
    uint32_t version = parent->version == 3 ? 3u : 2u;
    if (used_wallet_out) *used_wallet_out = 0;
    if (capped_out) *capped_out = 0;

    if (wallet && wallet->get_utxo && wallet->sign_input && wallet->get_change_spk) {
        unsigned char chg_spk[64];
        size_t chg_len = 0;
        if (wallet->get_change_spk(wallet, chg_spk, &chg_len) && chg_len > 0 &&
            chg_len <= sizeof(chg_spk)) {
            /* Size estimate: 2 inputs, 1 output; the wallet witness is at most
               a P2WPKH one (108 bytes), the anchor witness is empty. */
            size_t base = 4 + 1 + 2 * 41 + 1 + (8 + 1 + chg_len) + 4;
            size_t est_vsize = (4 * base + 2 + 1 + 108 + 3) / 4;
            int capped = 0;
            uint64_t fee = spec_fee(spec, est_vsize, &capped);
            if (fee == FEE_INVALID) {
                fprintf(stderr, "CPFP: no child fee for %s within the budget "
                        "(%llu sat/kvB target)\n", parent->txid_hex,
                        (unsigned long long)spec->pkg_rate);
                return 0;
            }
            for (int attempt = spec->has_coin ? 0 : 1; attempt < 2; attempt++) {
                char w_txid[65];
                uint32_t w_vout = 0;
                uint64_t w_amount = 0;
                unsigned char w_spk[64];
                size_t w_spk_len = 0;
                int picked = 0;
                if (attempt == 0) {
                    memcpy(w_txid, spec->coin_txid, 65);
                    w_vout = spec->coin_vout;
                    w_amount = spec->coin_amount;
                    memcpy(w_spk, spec->coin_spk, spec->coin_spk_len);
                    w_spk_len = spec->coin_spk_len;
                } else if (wallet->get_utxo(wallet, fee + CHANNEL_DUST_LIMIT_SATS + 1000,
                                            w_txid, &w_vout, &w_amount, w_spk,
                                            &w_spk_len)) {
                    picked = 1;
                } else {
                    fprintf(stderr, "CPFP: no wallet UTXO for the child of %s\n",
                            parent->txid_hex);
                    break;
                }
                if (wallet->type == WALLET_SOURCE_RPC) {
                    /* The anchor may be an output of a tx that is not in the
                       mempool yet, or spent there by the child this one
                       replaces: the wallet cannot look it up itself. */
                    wallet_source_rpc_set_prevout_hint((wallet_source_rpc_t *)wallet,
                        parent->txid_hex, (uint32_t)parent->anchor_vout,
                        "51024e73", parent->anchor_amount);
                }
                uint64_t f = fee;
                int ok = build_wallet_child(wallet, parent, version, w_txid, w_vout,
                                            w_amount, w_spk, w_spk_len, chg_spk,
                                            chg_len, f, child_out);
                cpfp_tx_info_t ci;
                if (ok && cpfp_parse_tx(child_out->data, child_out->len, &ci)) {
                    uint64_t need = spec_fee(spec, ci.vsize, &capped);
                    if (need == FEE_INVALID) {
                        ok = 0;
                    } else if (need != f) {
                        f = need;
                        ok = build_wallet_child(wallet, parent, version, w_txid, w_vout,
                                                w_amount, w_spk, w_spk_len, chg_spk,
                                                chg_len, f, child_out);
                    }
                }
                if (wallet->type == WALLET_SOURCE_RPC)
                    wallet_source_rpc_set_prevout_hint((wallet_source_rpc_t *)wallet,
                                                       NULL, 0, NULL, 0);
                if (ok) {
                    if (picked && lock) {
                        lock->held = 1;
                        memcpy(lock->txid, w_txid, 65);
                        lock->vout = w_vout;
                    } else if (picked && wallet->release_utxo) {
                        wallet->release_utxo(wallet, w_txid, w_vout);
                    }
                    if (fee_out) *fee_out = f;
                    if (used_wallet_out) *used_wallet_out = 1;
                    if (capped_out) *capped_out = capped;
                    return 1;
                }
                if (picked && wallet->release_utxo)
                    wallet->release_utxo(wallet, w_txid, w_vout);
                fprintf(stderr, "CPFP: wallet child for %s failed%s\n", parent->txid_hex,
                        attempt == 0 ? " with the replaced child's coin" : "");
            }
        }
    }
    g_child_no_coin = 1;
    if (spec->replaces) {
        uint64_t need = spec_fee(spec, CPFP_ANCHOR_ONLY_CHILD_VSIZE, NULL);
        if (need == FEE_INVALID || need > parent->anchor_amount) {
            fprintf(stderr, "CPFP: an anchor-only child cannot replace the current "
                    "child of %s\n", parent->txid_hex);
            return 0;
        }
    }
    fprintf(stderr, "CPFP: using the anchor alone for the child of %s\n", parent->txid_hex);
    return build_anchor_only(parent, version, child_out, fee_out);
}

int cpfp_build_anchor_child(wallet_source_t *wallet,
                            const cpfp_tx_info_t *parent,
                            uint64_t parent_fee, uint64_t pkg_rate,
                            tx_buf_t *child_out, uint64_t *child_fee_out,
                            int *used_wallet_out) {
    if (!parent) return 0;
    child_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.base_fee = parent_fee;
    spec.base_vsize = parent->vsize;
    spec.pkg_rate = pkg_rate;
    /* nothing is broadcast here: the coin is released on return */
    coin_lock_t lock;
    int ok = build_child(wallet, parent, &spec, child_out, child_fee_out,
                         used_wallet_out, NULL, &lock);
    coin_release(wallet, &lock);
    return ok;
}

/* ---- broadcast -------------------------------------------------------- */

static uint64_t btc_to_sat(double btc) {
    return btc > 0 ? (uint64_t)(btc * 100000000.0 + 0.5) : 0;
}

static cJSON *rpc_json(regtest_t *rt, const char *method, const char *params,
                       int quiet) {
    char *r = quiet ? regtest_exec_quiet(rt, method, params)
                    : regtest_exec(rt, method, params);
    if (!r) return NULL;
    cJSON *j = cJSON_Parse(r);
    free(r);
    return j;
}

/* max(mempoolminfee, minrelaytxfee) in sat/kvB; 0 if unavailable. */
static uint64_t mempool_floor(regtest_t *rt) {
    cJSON *j = rpc_json(rt, "getmempoolinfo", "", 0);
    if (!j) return 0;
    uint64_t a = 0, b = 0;
    cJSON *m = cJSON_GetObjectItem(j, "mempoolminfee");
    cJSON *n = cJSON_GetObjectItem(j, "minrelaytxfee");
    if (m && cJSON_IsNumber(m)) a = btc_to_sat(m->valuedouble);
    if (n && cJSON_IsNumber(n)) b = btc_to_sat(n->valuedouble);
    cJSON_Delete(j);
    return a > b ? a : b;
}

/* The node's incremental relay feerate (sat/kvB); Core's default (100
   sat/kvB since 29.1) if it does not report one. */
static uint64_t incremental_rate(regtest_t *rt) {
    cJSON *j = rpc_json(rt, "getnetworkinfo", "", 0);
    cJSON *v = j ? cJSON_GetObjectItem(j, "incrementalfee") : NULL;
    uint64_t r = (v && cJSON_IsNumber(v)) ? btc_to_sat(v->valuedouble) : 0;
    cJSON_Delete(j);
    return r > 0 ? r : FEE_FLOOR_SAT_PER_KVB;
}

/* Sum of the values of the outputs tx spends, or UINT64_MAX when one of
   them is not in the UTXO set (or mempool). */
static uint64_t input_total(regtest_t *rt, const cpfp_tx_info_t *ti) {
    uint64_t total = 0;
    for (size_t i = 0; i < ti->n_inputs; i++) {
        unsigned char d[32];
        memcpy(d, ti->in_txid[i], 32);
        reverse_bytes(d, 32);
        char hex[65], params[96];
        hex_encode(d, 32, hex);
        snprintf(params, sizeof(params), "\"%s\" %u true", hex, ti->in_vout[i]);
        cJSON *j = rpc_json(rt, "gettxout", params, 0);
        cJSON *val = j ? cJSON_GetObjectItem(j, "value") : NULL;
        if (!val || !cJSON_IsNumber(val)) { cJSON_Delete(j); return UINT64_MAX; }
        total += btc_to_sat(val->valuedouble);
        cJSON_Delete(j);
    }
    return total;
}

/* getmempoolentry of txid (display hex); NULL when it is not in the mempool. */
static cJSON *mempool_entry(regtest_t *rt, const char *txid_hex) {
    char params[80];
    snprintf(params, sizeof(params), "\"%s\"", txid_hex);
    return rpc_json(rt, "getmempoolentry", params, 1);
}

/* 1 if txid (display hex) is in the node's mempool. */
static int in_mempool(regtest_t *rt, const char *txid_hex) {
    cJSON *e = mempool_entry(rt, txid_hex);
    cJSON_Delete(e);
    return e != NULL;
}

/* fees.<name> of a mempool entry, in sats. */
static uint64_t entry_fee(const cJSON *e, const char *name) {
    cJSON *fees = cJSON_GetObjectItem(e, "fees");
    cJSON *v = fees ? cJSON_GetObjectItem(fees, name) : NULL;
    return (v && cJSON_IsNumber(v)) ? btc_to_sat(v->valuedouble) : 0;
}

static size_t entry_size(const cJSON *e, const char *name) {
    cJSON *v = cJSON_GetObjectItem(e, name);
    return (v && cJSON_IsNumber(v) && v->valuedouble > 0) ? (size_t)v->valuedouble : 0;
}

static uint64_t rate_of(uint64_t fee, size_t vsize) {
    return vsize ? (uint64_t)(((unsigned __int128)fee * 1000) / vsize) : 0;
}

static int already_known(const char *err) {
    return err && (strstr(err, "already in block chain") ||
                   strstr(err, "txn-already-known") ||
                   strstr(err, "txn-already-in-mempool") ||
                   strstr(err, "outputs already in utxo set"));
}

/* sendrawtransaction; returns CPFP_SENT_ALONE / CPFP_KNOWN / CPFP_FAILED.
   no_max_rate: lift the node's per-tx maxfeerate (a CPFP child alone pays a
   high rate by design). */
static cpfp_result_t send_alone(regtest_t *rt, const char *tx_hex, int quiet,
                                int no_max_rate) {
    size_t n = strlen(tx_hex) + 8;
    char *params = malloc(n);
    if (!params) return CPFP_FAILED;
    snprintf(params, n, no_max_rate ? "\"%s\" 0" : "\"%s\"", tx_hex);
    char *r = regtest_exec(rt, "sendrawtransaction", params);
    free(params);
    if (!r) return CPFP_FAILED;
    cpfp_result_t res = CPFP_FAILED;
    const char *s = r;
    while (*s == '"' || *s == ' ' || *s == '\n') s++;
    size_t hexlen = 0;
    while ((s[hexlen] >= '0' && s[hexlen] <= '9') || (s[hexlen] >= 'a' && s[hexlen] <= 'f'))
        hexlen++;
    if (hexlen == 64 && !strstr(r, "error"))
        res = CPFP_SENT_ALONE;
    else if (already_known(r))
        res = CPFP_KNOWN;
    else if (!quiet)
        fprintf(stderr, "sendrawtransaction error: %s\n", r);
    free(r);
    return res;
}

/* Txid of the mempool tx spending txid:vout, written to out (empty if none). */
static void anchor_spender(regtest_t *rt, const char *txid_hex, uint32_t vout,
                           char out[65]) {
    out[0] = '\0';
    char params[128];
    snprintf(params, sizeof(params), "[{\"txid\":\"%s\",\"vout\":%u}]", txid_hex, vout);
    cJSON *j = rpc_json(rt, "gettxspendingprevout", params, 1);
    cJSON *e = (j && cJSON_IsArray(j)) ? cJSON_GetArrayItem(j, 0) : NULL;
    cJSON *s = e ? cJSON_GetObjectItem(e, "spendingtxid") : NULL;
    if (s && cJSON_IsString(s) && strlen(s->valuestring) == 64)
        memcpy(out, s->valuestring, 65);
    cJSON_Delete(j);
}

/* The coin a mempool child of the parent (child_txid, spending its anchor)
   spends besides the anchor, as spec's coin to reuse, when it is the
   wallet's own: a child we sent earlier is replaced spending the same coin.
   A coin that is not ours (a third party's or another party's child) is
   never reused: we cannot sign it, and the child is outbid with a coin of
   our own instead.  Returns 1 if spec now has a coin. */
static int replaced_child_coin(regtest_t *rt, wallet_source_t *wallet,
                               const char *child_txid,
                               const cpfp_tx_info_t *parent, child_spec_t *spec) {
    if (!wallet || !wallet->owns_coin) return 0;
    char params[96];
    snprintf(params, sizeof(params), "\"%s\" true", child_txid);
    cJSON *j = rpc_json(rt, "getrawtransaction", params, 1);
    cJSON *vin = j ? cJSON_GetObjectItem(j, "vin") : NULL;
    int found = 0;
    for (int i = 0; vin && !found && i < cJSON_GetArraySize(vin); i++) {
        cJSON *in = cJSON_GetArrayItem(vin, i);
        cJSON *t = cJSON_GetObjectItem(in, "txid");
        cJSON *v = cJSON_GetObjectItem(in, "vout");
        if (!t || !cJSON_IsString(t) || !v || !cJSON_IsNumber(v)) continue;
        if (strcmp(t->valuestring, parent->txid_hex) == 0 &&
            (int)v->valuedouble == parent->anchor_vout) continue;
        /* spent in the mempool, so look it up in the chain state only */
        char p2[96];
        snprintf(p2, sizeof(p2), "\"%s\" %u false", t->valuestring,
                 (unsigned)v->valuedouble);
        cJSON *o = rpc_json(rt, "gettxout", p2, 1);
        cJSON *val = o ? cJSON_GetObjectItem(o, "value") : NULL;
        cJSON *spk = o ? cJSON_GetObjectItem(o, "scriptPubKey") : NULL;
        cJSON *hex = spk ? cJSON_GetObjectItem(spk, "hex") : NULL;
        if (val && cJSON_IsNumber(val) && hex && cJSON_IsString(hex) &&
            strlen(t->valuestring) == 64 && strlen(hex->valuestring) / 2 <= sizeof(spec->coin_spk)) {
            int n = hex_decode(hex->valuestring, spec->coin_spk, sizeof(spec->coin_spk));
            if (n > 0 && wallet->owns_coin(wallet, t->valuestring,
                                           (uint32_t)v->valuedouble,
                                           spec->coin_spk, (size_t)n)) {
                memcpy(spec->coin_txid, t->valuestring, 65);
                spec->coin_vout = (uint32_t)v->valuedouble;
                spec->coin_amount = btc_to_sat(val->valuedouble);
                spec->coin_spk_len = (size_t)n;
                spec->has_coin = 1;
                found = 1;
            } else if (n > 0) {
                printf("CPFP: the current child %s of %s spends %s:%u, not a coin "
                       "of this wallet: outbidding it with one of ours\n", child_txid,
                       parent->txid_hex, t->valuestring, (unsigned)v->valuedouble);
            }
        }
        cJSON_Delete(o);
    }
    cJSON_Delete(j);
    return found;
}

/* The parent (ti) is in the mempool.  If the best package it is part of
   (its own ancestor feerate, or any child's) is below need, put a child on
   its anchor that brings it to need plus 10%: alongside, or replacing the
   anchor's current spender (RBF; for a TRUC parent, whatever child it has,
   by sibling eviction).  The replacement pays for everything it evicts: the
   conflicting child and all of its descendants.  A child we sent earlier is
   replaced spending the same wallet coin; anyone else's child (a third
   party's cheap anchor spend that would pin the package, or another party
   bumping the same tx from its own wallet) is outbid with a coin of ours.
   When the node refuses a child that reuses our coin, a fresh coin is tried.
   The child pays at most max_fee.  Returns CPFP_KNOWN when the package
   already reaches need, CPFP_BUMPED when a child now brings it there, and
   CPFP_BUMP_FAILED when no child could be built or the node refused it. */
static cpfp_result_t bump_in_mempool(regtest_t *rt, wallet_source_t *wallet,
                                     const cpfp_tx_info_t *ti, const cJSON *entry,
                                     uint64_t need, uint64_t max_fee) {
    child_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.base_fee = entry_fee(entry, "ancestor");
    spec.base_vsize = entry_size(entry, "ancestorsize");
    if (spec.base_vsize == 0) {
        spec.base_fee = entry_fee(entry, "base");
        spec.base_vsize = ti->vsize;
    }
    uint64_t best = rate_of(spec.base_fee, spec.base_vsize);

    char spender[65] = "";
    if (ti->anchor_vout >= 0)
        anchor_spender(rt, ti->txid_hex, (uint32_t)ti->anchor_vout, spender);
    cJSON *spentby = cJSON_GetObjectItem(entry, "spentby");
    for (int i = 0; spentby && i < cJSON_GetArraySize(spentby); i++) {
        cJSON *c = cJSON_GetArrayItem(spentby, i);
        if (!c || !cJSON_IsString(c)) continue;
        cJSON *ce = mempool_entry(rt, c->valuestring);
        if (!ce) continue;
        uint64_t r = rate_of(entry_fee(ce, "ancestor"), entry_size(ce, "ancestorsize"));
        if (r > best) best = r;
        if (ti->version == 3 || strcmp(c->valuestring, spender) == 0) {
            /* a direct conflict of the new child: replacing it evicts its
               descendants too, and BIP 125 rule 3 counts all their fees */
            spec.replaces = 1;
            spec.repl_fee += entry_fee(ce, "descendant");
            uint64_t cr = rate_of(entry_fee(ce, "modified"), entry_size(ce, "vsize"));
            if (cr > spec.repl_rate) spec.repl_rate = cr;
        }
        cJSON_Delete(ce);
    }
    if (best >= need) return CPFP_KNOWN;
    if (ti->anchor_vout < 0) {
        fprintf(stderr, "CPFP: %s is in the mempool at %llu sat/kvB, below %llu, "
                "and has no anchor to bump\n", ti->txid_hex,
                (unsigned long long)best, (unsigned long long)need);
        return CPFP_BUMP_FAILED;
    }

    spec.pkg_rate = need + need / 10;
    spec.incr_rate = incremental_rate(rt);
    spec.max_fee = max_fee;
    if (spender[0])
        replaced_child_coin(rt, wallet, spender, ti, &spec);

    for (int attempt = 0; attempt < 2; attempt++) {
        tx_buf_t child;
        tx_buf_init(&child, 256);
        uint64_t child_fee = 0;
        int used_wallet = 0, capped = 0;
        coin_lock_t lock;
        if (!build_child(wallet, ti, &spec, &child, &child_fee, &used_wallet, &capped,
                         &lock)) {
            tx_buf_free(&child);
            fprintf(stderr, "CPFP: %s is in the mempool at %llu sat/kvB, below %llu; "
                    "no child could bump it\n", ti->txid_hex,
                    (unsigned long long)best, (unsigned long long)need);
            if (g_child_no_coin) need_record(CPFP_NEED_COIN, ti->txid_hex);
            return CPFP_BUMP_FAILED;
        }
        /* the reused coin went into this child (a fresh one stays locked) */
        int reused = spec.has_coin && used_wallet && !lock.held;
        char *hex = malloc(child.len * 2 + 1);
        if (!hex) { tx_buf_free(&child); coin_release(wallet, &lock); return CPFP_BUMP_FAILED; }
        hex_encode(child.data, child.len, hex);
        cpfp_tx_info_t ci;
        int parsed = cpfp_parse_tx(child.data, child.len, &ci);
        tx_buf_free(&child);
        cpfp_result_t r = send_alone(rt, hex, 0, 1);
        free(hex);
        coin_release(wallet, &lock);
        if (r != CPFP_SENT_ALONE) {
            fprintf(stderr, "CPFP: bump of %s refused by the node\n", ti->txid_hex);
            if (reused && attempt == 0) {
                fprintf(stderr, "CPFP: retrying the bump of %s with a fresh wallet "
                        "coin\n", ti->txid_hex);
                spec.has_coin = 0;
                continue;
            }
            return CPFP_BUMP_FAILED;
        }
        size_t cvs = parsed ? ci.vsize : 0;
        printf("CPFP: %s was in the mempool at %llu sat/kvB (need %llu): %s%s child %s "
               "pays %llu, package now %llu sat/kvB%s\n", ti->txid_hex,
               (unsigned long long)best, (unsigned long long)need,
               spec.replaces ? "replacing its child, " : "",
               used_wallet ? "wallet-funded" : "anchor-only",
               parsed ? ci.txid_hex : "?", (unsigned long long)child_fee,
               (unsigned long long)rate_of(spec.base_fee + child_fee, spec.base_vsize + cvs),
               capped ? " (capped by the fee budget)" : "");
        return CPFP_BUMPED;
    }
    return CPFP_BUMP_FAILED;
}

cpfp_result_t cpfp_send_presigned(regtest_t *rt, wallet_source_t *wallet,
                                  uint64_t target_rate, uint64_t max_child_fee,
                                  const char *tx_hex, char *txid_out) {
    if (!rt || !tx_hex) return CPFP_FAILED;
    if (max_child_fee == 0) max_child_fee = CPFP_DEFAULT_MAX_CHILD_FEE;
    size_t len = strlen(tx_hex) / 2;
    unsigned char *tx = malloc(len ? len : 1);
    if (!tx) return CPFP_FAILED;
    cpfp_tx_info_t ti;
    if (hex_decode(tx_hex, tx, len) != (int)len || !cpfp_parse_tx(tx, len, &ti)) {
        free(tx);
        return send_alone(rt, tx_hex, 0, 0);
    }
    free(tx);
    if (txid_out) { memcpy(txid_out, ti.txid_hex, 64); txid_out[64] = '\0'; }

    uint64_t need = mempool_floor(rt);
    if (target_rate > need) need = target_rate;

    /* Already in the mempool: raise its package if it is short of need. */
    cJSON *entry = mempool_entry(rt, ti.txid_hex);
    if (entry) {
        cpfp_result_t r = bump_in_mempool(rt, wallet, &ti, entry, need, max_child_fee);
        cJSON_Delete(entry);
        return r;
    }

    uint64_t in = input_total(rt, &ti);
    if (in == UINT64_MAX || in < ti.out_total) {
        /* Inputs not available: not yet valid, already confirmed or
           conflicted.  Let the node say which. */
        return send_alone(rt, tx_hex, 0, 0);
    }
    uint64_t parent_fee = in - ti.out_total;
    int pays_enough = parent_fee >= fee_at_rate(need, ti.vsize);
    if (pays_enough || ti.anchor_vout < 0) {
        cpfp_result_t r = send_alone(rt, tx_hex, ti.anchor_vout >= 0, 0);
        if (r != CPFP_FAILED || ti.anchor_vout < 0) return r;
        /* Refused despite the fee check (policy we did not model):
           fall through to the package. */
    }

    /* Package: the child brings parent + child to the floor plus 10%. */
    child_spec_t spec;
    memset(&spec, 0, sizeof(spec));
    spec.base_fee = parent_fee;
    spec.base_vsize = ti.vsize;
    spec.pkg_rate = need + need / 10;
    spec.max_fee = max_child_fee;
    tx_buf_t child;
    tx_buf_init(&child, 256);
    uint64_t child_fee = 0;
    int used_wallet = 0, capped = 0;
    coin_lock_t lock;
    if (!build_child(wallet, &ti, &spec, &child, &child_fee, &used_wallet, &capped,
                     &lock)) {
        tx_buf_free(&child);
        fprintf(stderr, "CPFP: could not build a child for %s\n", ti.txid_hex);
        /* No coin, and the anchor alone (0-value at rate 0) cannot pay. */
        if (g_child_no_coin)
            need_record(CPFP_NEED_COIN, ti.txid_hex);
        return CPFP_FAILED;
    }
    char *child_hex = malloc(child.len * 2 + 1);
    size_t plen = strlen(tx_hex) + child.len * 2 + 16;
    char *params = malloc(plen);
    if (!child_hex || !params) {
        free(child_hex); free(params); tx_buf_free(&child);
        coin_release(wallet, &lock);
        return CPFP_FAILED;
    }
    hex_encode(child.data, child.len, child_hex);
    tx_buf_free(&child);
    snprintf(params, plen, "[\"%s\",\"%s\"]", tx_hex, child_hex);
    free(child_hex);
    char *r = regtest_exec(rt, "submitpackage", params);
    free(params);
    /* broadcast done: the coin is spent in the mempool or free again */
    coin_release(wallet, &lock);
    if (!r) return CPFP_FAILED;

    cpfp_result_t res = CPFP_FAILED;
    cJSON *j = cJSON_Parse(r);
    cJSON *msg = j ? cJSON_GetObjectItem(j, "package_msg") : NULL;
    if (msg && cJSON_IsString(msg) && strcmp(msg->valuestring, "success") == 0) {
        res = CPFP_SENT_PACKAGE;
        printf("CPFP: %s (fee %llu, %zu vB) sent as a package with a %s child "
               "paying %llu at %llu sat/kvB%s\n", ti.txid_hex,
               (unsigned long long)parent_fee, ti.vsize,
               used_wallet ? "wallet-funded" : "anchor-only",
               (unsigned long long)child_fee, (unsigned long long)spec.pkg_rate,
               capped ? " (capped by the fee budget)" : "");
    } else if (in_mempool(rt, ti.txid_hex)) {
        /* The node accepted the parent on its own and rejected the child. */
        res = CPFP_PARENT_ONLY;
        fprintf(stderr, "CPFP: %s accepted without its child (%s); it is in the "
                "mempool and the next broadcast bumps it\n", ti.txid_hex, r);
    } else {
        fprintf(stderr, "CPFP: submitpackage for %s failed: %s\n", ti.txid_hex, r);
        if (already_known(r)) res = CPFP_KNOWN;
        else if (!used_wallet && g_child_no_coin &&
                 (strstr(r, "fee not met") || strstr(r, "fee too low") ||
                  strstr(r, "insufficient fee")) &&
                 cpfp_anchor_alone_short(parent_fee, ti.vsize, ti.anchor_amount,
                                         mempool_floor(rt)))
            need_record(CPFP_NEED_COIN, ti.txid_hex);
    }
    cJSON_Delete(j);
    free(r);
    return res;
}

/* ---- node requirements ------------------------------------------------ */

int cpfp_check_node_version(regtest_t *rt) {
    if (!rt) return 1;
    cJSON *j = rpc_json(rt, "getnetworkinfo", "", 0);
    cJSON *v = j ? cJSON_GetObjectItem(j, "version") : NULL;
    if (!v || !cJSON_IsNumber(v)) {
        cJSON_Delete(j);
        fprintf(stderr, "WARNING: cannot read the Bitcoin Core version "
                "(getnetworkinfo); Bitcoin Core %d.%d or later is required\n",
                CPFP_MIN_NODE_VERSION / 10000, (CPFP_MIN_NODE_VERSION / 100) % 100);
        return 1;
    }
    long ver = (long)v->valuedouble;
    cJSON_Delete(j);
    if (ver >= CPFP_MIN_NODE_VERSION) return 1;
    fprintf(stderr, "ERROR: Bitcoin Core %ld.%ld.%ld is too old: factory exits use "
            "TRUC (nVersion 3) transactions, P2A anchors and package relay "
            "(submitpackage), which need Bitcoin Core %d.%d or later\n",
            ver / 10000, (ver / 100) % 100, ver % 100,
            CPFP_MIN_NODE_VERSION / 10000, (CPFP_MIN_NODE_VERSION / 100) % 100);
    return 0;
}

/* ---- process defaults ------------------------------------------------- */

static regtest_t *g_cpfp_rt;
static wallet_source_t *g_cpfp_wallet;
static fee_estimator_t *g_cpfp_urgent;
static uint64_t g_cpfp_max_child_fee;
static fee_target_t g_cpfp_target = FEE_TARGET_URGENT;

void cpfp_set_default_target(fee_target_t target) {
    g_cpfp_target = target;
}

void cpfp_set_default(regtest_t *rt, wallet_source_t *wallet, fee_estimator_t *urgent,
                      uint64_t max_child_fee) {
    g_cpfp_rt = rt;
    g_cpfp_wallet = wallet;
    g_cpfp_urgent = urgent;
    g_cpfp_max_child_fee = max_child_fee;
}

cpfp_result_t cpfp_send_default(chain_backend_t *cb, const char *tx_hex,
                                char *txid_out) {
    if (g_cpfp_rt) {
        uint64_t target = (g_cpfp_urgent && g_cpfp_urgent->get_rate)
            ? g_cpfp_urgent->get_rate(g_cpfp_urgent, g_cpfp_target) : 0;
        return cpfp_send_presigned(g_cpfp_rt, g_cpfp_wallet, target,
                                   g_cpfp_max_child_fee, tx_hex, txid_out);
    }
    if (cb && cb->send_raw_tx) {
        if (cb->send_raw_tx(cb, tx_hex, txid_out)) return CPFP_SENT_ALONE;
        /* Refused on its own.  A pre-signed tx with a P2A anchor is sized
           to be relayed with a child when it pays less than the node needs,
           and this backend cannot send one. */
        size_t len = strlen(tx_hex) / 2;
        unsigned char *tx = malloc(len ? len : 1);
        cpfp_tx_info_t ti;
        if (tx && hex_decode(tx_hex, tx, len) == (int)len &&
            cpfp_parse_tx(tx, len, &ti) && ti.anchor_vout >= 0) {
            fprintf(stderr, "CPFP: %s refused by the chain backend; if it pays "
                    "less than the node's minimum relay fee it cannot be sent "
                    "without a child\n", ti.txid_hex);
            need_record(CPFP_NEED_PACKAGE_RELAY, ti.txid_hex);
        }
        free(tx);
        return CPFP_FAILED;
    }
    return CPFP_FAILED;
}
