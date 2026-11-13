/* End-date payout: the spend rules of every shared output under the inverted
   timeout default, and the members' claim at the end date T0.

   Unit: over every tree shape the builder makes, no tree output and no
   channel output has a script path (so none the host alone can satisfy),
   every shared output that holds members' value at T0 has exactly one
   payout, and each payout has nLockTime T0, no host output, conserves value
   and pays every member at least its channel capacity.

   Regtest: the tree (or part of it) is on chain and the host is silent.  At
   T0 the host alone cannot spend a channel output or a tree output, by the
   old timeout leaf or by key path; every member's payout confirms.  With no
   tree published the distribution transaction confirms at T0 and the tree
   is dead. */
#include "superscalar/factory.h"
#include "superscalar/tapscript.h"
#include "superscalar/tx_builder.h"
#include "superscalar/channel.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/client.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/wire.h"
#include "superscalar/persist.h"
#include "superscalar/cli_arity.h"
#include "superscalar/lsp.h"
#include "cJSON.h"

/* BIP-341 key-only output key: internal + H_TapTweak(internal) * G. */
static int keyonly_tweak(const secp256k1_context *ctx, secp256k1_xonly_pubkey *out,
                         const secp256k1_xonly_pubkey *internal) {
    unsigned char ser[32], tw[32];
    secp256k1_pubkey full;
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, internal)) return 0;
    sha256_tagged("TapTweak", ser, 32, tw);
    return secp256k1_xonly_pubkey_tweak_add(ctx, &full, internal, tw) &&
           secp256k1_xonly_pubkey_from_pubkey(ctx, out, NULL, &full);
}
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define EP_MAX_CLIENTS 64

static secp256k1_keypair *ep_keys(secp256k1_context *ctx, size_t n) {
    secp256k1_keypair *kps = calloc(n, sizeof(*kps));
    if (!kps) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char buf[24], sk[32];
        memcpy(buf, "end-date-payout-key", 19);
        buf[19] = (unsigned char)(i >> 24); buf[20] = (unsigned char)(i >> 16);
        buf[21] = (unsigned char)(i >> 8);  buf[22] = (unsigned char)i;
        buf[23] = 0x5c;
        sha256(buf, sizeof(buf), sk);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) { free(kps); return NULL; }
    }
    return kps;
}

typedef struct {
    const char *name;
    uint8_t arity[4];
    size_t n_arity;
    uint32_t static_thr;
    uint32_t ps_k;           /* pseudo-Spilman sub-factory arity, 0 = default */
    size_t n_clients;
} ep_shape_t;

/* Init (not build) a factory of the shape, funding script computed. */
static int ep_init(factory_t *f, secp256k1_context *ctx, const secp256k1_keypair *kps,
                   const ep_shape_t *s, uint32_t cltv) {
    if (!factory_init(f, ctx, kps, s->n_clients + 1, 10, 4)) return 0;
    if (s->n_arity == 1)
        factory_set_arity(f, (factory_arity_t)s->arity[0]);
    else if (!factory_set_level_arity(f, s->arity, s->n_arity))
        return 0;
    if (s->static_thr) factory_set_static_near_root(f, s->static_thr);
    if (s->ps_k) factory_set_ps_subfactory_arity(f, s->ps_k);
    f->use_tree_anchor = 1;
    f->cltv_timeout = cltv;
    return 1;
}

/* Key-only P2TR of a single key (where the host would be paid). */
static void ep_keyonly_spk(secp256k1_context *ctx, const secp256k1_pubkey *pk,
                           unsigned char spk[34]) {
    secp256k1_xonly_pubkey x, t;
    unsigned char ser[32], tw[32];
    secp256k1_pubkey full;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &x, NULL, pk);
    secp256k1_xonly_pubkey_serialize(ctx, ser, &x);
    sha256_tagged("TapTweak", ser, 32, tw);
    secp256k1_xonly_pubkey_tweak_add(ctx, &full, &x, tw);
    secp256k1_xonly_pubkey_from_pubkey(ctx, &t, NULL, &full);
    build_p2tr_script_pubkey(spk, &t);
}

static int ep_keyagg_spk(secp256k1_context *ctx, const secp256k1_pubkey *pks, size_t n,
                         unsigned char spk[34]) {
    musig_keyagg_t ka;
    secp256k1_xonly_pubkey k;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) return 0;
    if (!keyonly_tweak(ctx, &k, &ka.agg_pubkey)) return 0;
    build_p2tr_script_pubkey(spk, &k);
    return 1;
}

/* Minimal parse of an unsigned single-input transaction. */
typedef struct {
    uint32_t version, nsequence, locktime;
    unsigned char prev_txid[32];
    uint32_t prev_vout;
    size_t n_out;
    uint64_t amount[EP_MAX_CLIENTS + 2];
    unsigned char spk[EP_MAX_CLIENTS + 2][34];
    size_t spk_len[EP_MAX_CLIENTS + 2];
} ep_tx_t;

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int ep_parse(const tx_buf_t *t, ep_tx_t *o) {
    const unsigned char *d = t->data;
    size_t n = t->len, pos = 0;
    if (n < 60) return 0;
    o->version = rd32(d); pos = 4;
    if (d[pos++] != 1) return 0;
    memcpy(o->prev_txid, d + pos, 32); pos += 32;
    o->prev_vout = rd32(d + pos); pos += 4;
    if (d[pos++] != 0) return 0;
    o->nsequence = rd32(d + pos); pos += 4;
    o->n_out = d[pos++];
    if (o->n_out > EP_MAX_CLIENTS + 2) return 0;
    for (size_t i = 0; i < o->n_out; i++) {
        if (pos + 9 > n) return 0;
        uint64_t a = 0;
        for (int b = 0; b < 8; b++) a |= (uint64_t)d[pos + b] << (8 * b);
        o->amount[i] = a; pos += 8;
        size_t l = d[pos++];
        if (l > 34 || pos + l > n) return 0;
        memcpy(o->spk[i], d + pos, l);
        o->spk_len[i] = l;
        pos += l;
    }
    if (pos + 4 != n) return 0;
    o->locktime = rd32(d + pos);
    return 1;
}

static int ep_is_anchor(const tx_output_t *o) {
    return o->script_pubkey_len == P2A_SPK_LEN &&
           memcmp(o->script_pubkey, P2A_SPK, P2A_SPK_LEN) == 0;
}

static uint64_t ep_capacity(const factory_t *f, uint32_t participant) {
    size_t node = 0;
    uint32_t vout = 0;
    if (!factory_client_to_leaf(f, participant - 1, &node, &vout)) return 0;
    return f->nodes[node].outputs[vout].amount_sats;
}

/* Every spend rule of one built tree.  Returns 1 or prints the first
   violation. */
static int ep_check_tree(secp256k1_context *ctx, factory_t *f, const char *name) {
    unsigned char host_spk[34];
    ep_keyonly_spk(ctx, &f->pubkeys[0], host_spk);
#define EP_FAIL(...) do { printf("  FAIL: shape %s: ", name); printf(__VA_ARGS__); printf("\n"); return 0; } while (0)
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *x = &f->nodes[i];
        /* 1. The output a node spends is key path only. */
        unsigned char spk[34];
        secp256k1_xonly_pubkey k;
        if (!keyonly_tweak(ctx, &k, &x->keyagg.agg_pubkey)) EP_FAIL("tweak");
        build_p2tr_script_pubkey(spk, &k);
        if (memcmp(spk, x->spending_spk, 34) != 0)
            EP_FAIL("node %zu input has a script path", i);

        for (uint32_t v = 0; v < x->n_outputs; v++) {
            const tx_output_t *o = &x->outputs[v];
            if (ep_is_anchor(o)) {
                if (factory_find_payout(f, (uint32_t)i, v) >= 0) EP_FAIL("anchor %zu:%u has a payout", i, v);
                continue;
            }
            int child = -1;
            for (size_t c = 0; c < f->n_nodes; c++)
                if (f->nodes[c].parent_index == (int)i && f->nodes[c].parent_vout == v) child = (int)c;
            int want_payout = 1;
            if (child >= 0) {
                /* 2a. A tree output is the child's key-only key. */
                if (memcmp(o->script_pubkey, f->nodes[child].spending_spk, 34) != 0)
                    EP_FAIL("output %zu:%u is not its child's key", i, v);
                if (x->type == NODE_KICKOFF && !x->is_static_only &&
                    f->nodes[child].type == NODE_STATE)
                    want_payout = 0;   /* kickoff into its own state */
                if (f->nodes[child].n_signers - 1 > FACTORY_MAX_DIST_CLIENTS)
                    want_payout = 0;   /* above the TRUC payout bound */
            } else {
                /* 2b. A leaf output is the stock or a member's 2-of-2, key path only. */
                unsigned char stock[34];
                int is_stock = build_l_stock_spk(f, x, stock) && memcmp(stock, o->script_pubkey, 34) == 0;
                int is_chan = 0;
                for (size_t s = 1; s < x->n_signers && !is_chan; s++) {
                    secp256k1_pubkey a[2] = { f->pubkeys[x->signer_indices[s]], f->pubkeys[0] };
                    secp256k1_pubkey b[2] = { f->pubkeys[0], f->pubkeys[x->signer_indices[s]] };
                    unsigned char sa[34], sb[34];
                    if (ep_keyagg_spk(ctx, a, 2, sa) && memcmp(sa, o->script_pubkey, 34) == 0) is_chan = 1;
                    if (ep_keyagg_spk(ctx, b, 2, sb) && memcmp(sb, o->script_pubkey, 34) == 0) is_chan = 1;
                }
                if (!is_stock && !is_chan)
                    EP_FAIL("leaf output %zu:%u is neither stock nor key-only channel", i, v);
                if (is_stock) {
                    uint32_t nm = (uint32_t)x->n_signers - 1;
                    if (o->amount_sats < factory_payout_fee(f, nm) + factory_tree_anchor_sats(f) +
                                         (uint64_t)nm * CHANNEL_DUST_LIMIT_SATS)
                        want_payout = 0;
                }
            }
            int pi = factory_find_payout(f, (uint32_t)i, v);
            if (want_payout && pi < 0) EP_FAIL("output %zu:%u has no end-date payout", i, v);
            if (!want_payout && pi >= 0) EP_FAIL("output %zu:%u has an unexpected payout", i, v);
            if (pi < 0) continue;

            /* 3. The payout itself. */
            const factory_payout_t *p = &f->payouts[pi];
            ep_tx_t t;
            if (!ep_parse(&p->unsigned_tx, &t)) EP_FAIL("payout %d unparsable", pi);
            if (t.version != FACTORY_TREE_TX_VERSION) EP_FAIL("payout %d version %u", pi, t.version);
            if (t.locktime != f->cltv_timeout) EP_FAIL("payout %d locktime %u != T0 %u", pi, t.locktime, f->cltv_timeout);
            if (t.nsequence != 0xFFFFFFFEu) EP_FAIL("payout %d nSequence", pi);
            if (memcmp(t.prev_txid, x->txid, 32) != 0 || t.prev_vout != v)
                EP_FAIL("payout %d spends the wrong outpoint", pi);
            if (t.n_out != p->n_members + 1 || t.spk_len[t.n_out - 1] != P2A_SPK_LEN ||
                memcmp(t.spk[t.n_out - 1], P2A_SPK, P2A_SPK_LEN) != 0)
                EP_FAIL("payout %d: not one output per member plus a last P2A anchor", pi);
            uint64_t sum = 0;
            for (size_t k2 = 0; k2 < t.n_out; k2++) {
                sum += t.amount[k2];
                if (t.spk_len[k2] == 34 && memcmp(t.spk[k2], host_spk, 34) == 0)
                    EP_FAIL("payout %d pays the host", pi);
            }
            if (sum + factory_payout_fee(f, p->n_members) > o->amount_sats)
                EP_FAIL("payout %d pays out more than its input less the fee", pi);
            if (o->amount_sats - sum - factory_payout_fee(f, p->n_members) >= p->n_members)
                EP_FAIL("payout %d leaves more than division dust unpaid", pi);
            for (uint32_t m = 0; m < p->n_members; m++) {
                unsigned char mspk[34];
                if (!factory_member_payout_spk(f, p->members[m], mspk)) EP_FAIL("member spk");
                if (t.spk_len[m] != 34 || memcmp(t.spk[m], mspk, 34) != 0)
                    EP_FAIL("payout %d output %u does not pay member %u", pi, m, p->members[m]);
                if (p->kind == PAYOUT_TREE && t.amount[m] < ep_capacity(f, p->members[m]))
                    EP_FAIL("payout %d pays member %u less than its capacity", pi, p->members[m]);
            }
            /* 4. Signed and valid under the output's key. */
            if (!p->is_signed) EP_FAIL("payout %d not signed", pi);
            if (!secp256k1_schnorrsig_verify(ctx, p->sig, p->sighash, 32, &p->output_key))
                EP_FAIL("payout %d signature invalid", pi);
        }
    }
#undef EP_FAIL
    return 1;
}

int test_end_date_spend_rules_all_shapes(void) {
    static const ep_shape_t shapes[] = {
        { "advanceless N=4 (1.0 default)",  {4, 3}, 2, 1, 0, 4 },
        { "advanceless N=16",                {4, 4, 3}, 3, 2, 0, 16 },
        { "advanceless N=64",                {8, 8, 3}, 3, 2, 0, 64 },
        { "PS leaves with DW layers",        {3}, 1, 0, 0, 4 },
        { "arity-1 leaves",                  {1}, 1, 0, 0, 4 },
        { "arity-2 leaves",                  {2}, 1, 0, 0, 4 },
        { "n-way leaves under DW",           {2, 4}, 2, 0, 0, 8 },
        { "PS sub-factories K=2",            {3}, 1, 0, 2, 4 },
    };
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    for (size_t si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
        const ep_shape_t *s = &shapes[si];
        secp256k1_keypair *kps = ep_keys(ctx, s->n_clients + 1);
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(kps && f, "alloc");
        TEST_ASSERT(ep_init(f, ctx, kps, s, 5000), s->name);
        unsigned char txid[32], spk[34];
        memset(txid, 0x6B, 32);
        TEST_ASSERT(factory_compute_funding_spk(f, spk), "funding spk");
        TEST_ASSERT(factory_set_funding(f, txid, 0, (uint64_t)s->n_clients * 200000 + 1000000, spk, 34),
                    "set funding");
        if (!factory_build_tree(f)) {
            printf("  FAIL: shape %s: tree (with its payouts) does not build\n", s->name);
            return 0;
        }
        TEST_ASSERT(factory_sign_all(f), "sign tree and payouts");
        if (!ep_check_tree(ctx, f, s->name)) return 0;
        factory_free(f);
        free(f);
        free(kps);
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---------------------------------------------------------------- regtest */

static char *ep_hex(const tx_buf_t *t) {
    char *h = malloc(t->len * 2 + 1);
    if (h) hex_encode(t->data, t->len, h);
    return h;
}

/* testmempoolaccept: 1 allowed, 0 refused (reason copied when asked). */
static int ep_accept(regtest_t *rt, const tx_buf_t *t, char *why, size_t why_len) {
    char *h = ep_hex(t);
    if (!h) return 0;
    size_t pl = strlen(h) + 8;
    char *params = malloc(pl);
    if (!params) { free(h); return 0; }
    snprintf(params, pl, "[\"%s\"]", h);
    free(h);
    char *res = regtest_exec(rt, "testmempoolaccept", params);
    free(params);
    int ok = 0;
    if (res) {
        cJSON *j = cJSON_Parse(res);
        cJSON *e = (j && cJSON_IsArray(j)) ? cJSON_GetArrayItem(j, 0) : NULL;
        cJSON *a = e ? cJSON_GetObjectItem(e, "allowed") : NULL;
        ok = a && cJSON_IsTrue(a);
        if (why && why_len) {
            cJSON *r = e ? cJSON_GetObjectItem(e, "reject-reason") : NULL;
            snprintf(why, why_len, "%s", (r && cJSON_IsString(r)) ? r->valuestring : "");
        }
        cJSON_Delete(j);
    }
    free(res);
    return ok;
}

static int ep_send(regtest_t *rt, const tx_buf_t *t, char txid[65]) {
    char *h = ep_hex(t);
    int ok = h && regtest_send_raw_tx(rt, h, txid);
    free(h);
    return ok;
}

/* Fund the factory's funding script and attach the outpoint. */
static int ep_fund(regtest_t *rt, factory_t *f, const char *mine_addr, double btc) {
    unsigned char spk[34];
    char addr[128], txid_hex[65];
    if (!factory_compute_funding_spk(f, spk)) return 0;
    if (!regtest_derive_p2tr_address(rt, spk + 2, addr, sizeof(addr))) return 0;
    if (!regtest_fund_address(rt, addr, btc, txid_hex)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    char params[160];
    snprintf(params, sizeof(params), "\"%s\" true true", txid_hex);
    char *res = regtest_exec(rt, "gettransaction", params);
    if (!res) return 0;
    char want[69];
    hex_encode(spk, 34, want);
    cJSON *j = cJSON_Parse(res);
    free(res);
    cJSON *vouts = j ? cJSON_GetObjectItem(cJSON_GetObjectItem(j, "decoded"), "vout") : NULL;
    int vout = -1;
    uint64_t amount = 0;
    for (int i = 0; vouts && i < cJSON_GetArraySize(vouts); i++) {
        cJSON *v = cJSON_GetArrayItem(vouts, i);
        cJSON *h = cJSON_GetObjectItem(cJSON_GetObjectItem(v, "scriptPubKey"), "hex");
        if (h && cJSON_IsString(h) && strcmp(h->valuestring, want) == 0) {
            vout = cJSON_GetObjectItem(v, "n")->valueint;
            amount = (uint64_t)(cJSON_GetObjectItem(v, "value")->valuedouble * 1e8 + 0.5);
        }
    }
    cJSON_Delete(j);
    if (vout < 0) return 0;
    unsigned char txid[32];
    hex_decode(txid_hex, txid, 32);
    reverse_bytes(txid, 32);
    return factory_set_funding(f, txid, (uint32_t)vout, amount, spk, 34);
}

/* The two ways the host could try to take an output alone at the end date:
   the timeout leaf earlier trees committed to (T0 CLTV DROP host CHECKSIG,
   under the output's own internal key), and a key-path signature by the
   host's key alone.  Both must be refused for every shared output. */
static int ep_host_alone_refused(regtest_t *rt, secp256k1_context *ctx, const factory_t *f,
                                 const secp256k1_keypair *host,
                                 const unsigned char *txid, uint32_t vout,
                                 const tx_output_t *o, const secp256k1_xonly_pubkey *internal,
                                 const char *what) {
    secp256k1_xonly_pubkey hx;
    secp256k1_keypair_xonly_pub(ctx, &hx, NULL, host);
    tx_output_t to;
    secp256k1_pubkey hpk;
    secp256k1_keypair_pub(ctx, &hpk, host);
    ep_keyonly_spk(ctx, &hpk, to.script_pubkey);
    to.script_pubkey_len = 34;
    to.amount_sats = o->amount_sats - 1000;
    unsigned char aux[32];
    memset(aux, 0x77, 32);
    char why[96];

    /* (a) a timeout leaf at T0, or at any of the earlier locks a tree
       staggered by depth used (5 blocks per half-level) */
    tx_buf_t u, s;
    tx_buf_init(&u, 256);
    tx_buf_init(&s, 512);
    unsigned char sig[64];
    for (uint32_t k = 0; k <= 8 && 5 * k < f->cltv_timeout; k++) {
        uint32_t lock = f->cltv_timeout - 5 * k;
        tapscript_leaf_t leaf;
        unsigned char merkle[32], sh[32], cb[65];
        secp256k1_xonly_pubkey tweaked;
        int parity = 0;
        size_t cbl = 0;
        tx_buf_free(&u);
        tx_buf_free(&s);
        tx_buf_init(&u, 256);
        tx_buf_init(&s, 512);
        int built = tapscript_build_cltv_timeout(&leaf, lock, &hx, ctx) &&
                    tapscript_merkle_root(merkle, &leaf, 1) &&
                    tapscript_tweak_pubkey(ctx, &tweaked, &parity, internal, merkle) &&
                    build_unsigned_tx_locktime(&u, NULL, txid, vout, 0xFFFFFFFEu, lock,
                                               &to, 1) &&
                    compute_tapscript_sighash(sh, u.data, u.len, 0, o->script_pubkey,
                                              o->script_pubkey_len, o->amount_sats,
                                              0xFFFFFFFEu, &leaf) &&
                    secp256k1_schnorrsig_sign32(ctx, sig, sh, host, aux) &&
                    tapscript_build_control_block(cb, &cbl, parity, internal, ctx) &&
                    finalize_script_path_tx(&s, u.data, u.len, sig, leaf.script,
                                            leaf.script_len, cb, cbl);
        if (!built) { printf("  FAIL: %s: could not build the timeout-leaf attempt\n", what); return 0; }
        if (ep_accept(rt, &s, why, sizeof(why))) {
            printf("  FAIL: %s: the host ALONE can spend it by a timeout leaf (lock %u) at "
                   "height %d\n", what, lock, regtest_get_block_height(rt));
            return 0;
        }
        if (k == 0)
            printf("  %s: host-alone timeout-leaf spend refused (%s)\n", what, why);
    }

    /* (b) key path, the host's signature only */
    unsigned char ksh[32];
    tx_buf_free(&s);
    tx_buf_init(&s, 512);
    if (!compute_taproot_sighash(ksh, u.data, u.len, 0, o->script_pubkey, o->script_pubkey_len,
                                 o->amount_sats, 0xFFFFFFFEu) ||
        !secp256k1_schnorrsig_sign32(ctx, sig, ksh, host, aux) ||
        !finalize_signed_tx(&s, u.data, u.len, sig)) {
        printf("  FAIL: %s: could not build the key-path attempt\n", what);
        return 0;
    }
    if (ep_accept(rt, &s, why, sizeof(why))) {
        printf("  FAIL: %s: the host ALONE can spend it by key path\n", what);
        return 0;
    }
    tx_buf_free(&u);
    tx_buf_free(&s);
    return 1;
}

/* The internal key of a shared output (tree output, channel, stock). */
static int ep_output_internal(const factory_t *f, uint32_t node, uint32_t vout,
                              secp256k1_xonly_pubkey *out) {
    for (size_t c = 0; c < f->n_nodes; c++)
        if (f->nodes[c].parent_index == (int)node && f->nodes[c].parent_vout == vout) {
            *out = f->nodes[c].keyagg.agg_pubkey;
            return 1;
        }
    int pi = factory_find_payout(f, node, vout);
    if (pi < 0) return 0;
    *out = f->payouts[pi].keyagg.agg_pubkey;
    return 1;
}

/* Publish the path from the root to member 1's leaf, waiting out each
   relative lock. */
static int ep_publish_path(regtest_t *rt, factory_t *f, const char *mine_addr,
                           int *on_chain) {
    size_t leaf = 0;
    uint32_t lv = 0;
    if (!factory_client_to_leaf(f, 0, &leaf, &lv)) return 0;
    int path[64];
    size_t n = factory_collect_path_to_root(f, (int)leaf, path, 64);
    if (n == 0) return 0;
    for (size_t k = 0; k < n; k++) {   /* root first */
        factory_node_t *x = &f->nodes[path[k]];
        uint32_t ns = x->nsequence;
        if (!(ns & 0x80000000u) && ns != 0xFFFFFFFEu && (ns & 0xFFFF) > 0)
            regtest_mine_blocks(rt, (int)(ns & 0xFFFF), mine_addr);
        char txid[65];
        if (!ep_send(rt, &x->signed_tx, txid)) {
            printf("  FAIL: broadcast of tree node %d refused\n", path[k]);
            return 0;
        }
        regtest_mine_blocks(rt, 1, mine_addr);
        on_chain[path[k]] = 1;
    }
    return 1;
}

static int ep_scenario_tree_published(regtest_t *rt, secp256k1_context *ctx,
                                      const char *mine_addr, const ep_shape_t *shape) {
    printf("  -- shape: %s\n", shape->name);
    secp256k1_keypair *kps = ep_keys(ctx, shape->n_clients + 1);
    factory_t *f = calloc(1, sizeof(factory_t));
    int *on_chain = calloc(256, sizeof(int));
    TEST_ASSERT(kps && f && on_chain, "alloc");
    int h = regtest_get_block_height(rt);
    /* Room for every relative lock on the path, then T0. */
    uint32_t t0 = (uint32_t)h + 120;
    TEST_ASSERT(ep_init(f, ctx, kps, shape, t0), "init factory");
    TEST_ASSERT(ep_fund(rt, f, mine_addr, 0.02), "fund factory");
    TEST_ASSERT(factory_build_tree(f), "build tree and payouts");
    TEST_ASSERT(factory_sign_all(f), "sign tree and payouts");
    TEST_ASSERT(f->n_payouts > 0, "payouts exist");

    TEST_ASSERT(ep_publish_path(rt, f, mine_addr, on_chain), "publish member 1 path");
    TEST_ASSERT(regtest_get_block_height(rt) < (int)t0 - 2, "path published before T0");

    /* The on-chain unspent shared outputs: every output of a published node
       whose spender is not published (anchors aside). */
    size_t n_live = 0;
    uint32_t live_node[64], live_vout[64];
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (!on_chain[i]) continue;
        for (uint32_t v = 0; v < f->nodes[i].n_outputs && n_live < 64; v++) {
            int spent = 0;
            for (size_t c = 0; c < f->n_nodes; c++)
                if (on_chain[c] && f->nodes[c].parent_index == (int)i &&
                    f->nodes[c].parent_vout == v) spent = 1;
            if (spent || ep_is_anchor(&f->nodes[i].outputs[v])) continue;
            live_node[n_live] = (uint32_t)i;
            live_vout[n_live++] = v;
        }
    }
    TEST_ASSERT(n_live >= 2, "a channel and at least one more shared output are on chain");

    /* Before T0: no payout is final. */
    char why[96];
    for (size_t k = 0; k < n_live; k++) {
        int pi = factory_find_payout(f, live_node[k], live_vout[k]);
        if (pi < 0) continue;
        TEST_ASSERT(!ep_accept(rt, &f->payouts[pi].signed_tx, why, sizeof(why)),
                    "a payout is not valid before T0");
        TEST_ASSERT(strstr(why, "non-final") != NULL, "refused as non-final");
    }

    /* Mine to T0: the next block is the first one any end-date spend can enter. */
    int now = regtest_get_block_height(rt);
    regtest_mine_blocks(rt, (int)t0 - now, mine_addr);
    TEST_ASSERT(regtest_get_block_height(rt) == (int)t0, "tip at T0");

    /* At T0 the host alone can take no channel output and no tree output:
       not by any timeout leaf under any internal key the output could have
       (its child's key, or MuSig2 of a leaf member and the host in either
       order), and not by key path.  The stock keeps its relative leaf. */
    for (size_t k = 0; k < n_live; k++) {
        const factory_node_t *x = &f->nodes[live_node[k]];
        const tx_output_t *o = &x->outputs[live_vout[k]];
        unsigned char stock[34];
        if (build_l_stock_spk(f, x, stock) && memcmp(stock, o->script_pubkey, 34) == 0)
            continue;
        secp256k1_xonly_pubkey cand[64];
        size_t nc = 0;
        if (ep_output_internal(f, live_node[k], live_vout[k], &cand[nc])) nc++;
        for (size_t s = 1; s < x->n_signers && nc + 2 <= 64; s++) {
            secp256k1_pubkey a[2] = { f->pubkeys[x->signer_indices[s]], f->pubkeys[0] };
            secp256k1_pubkey b[2] = { f->pubkeys[0], f->pubkeys[x->signer_indices[s]] };
            musig_keyagg_t ka;
            if (musig_aggregate_keys(ctx, &ka, a, 2)) cand[nc++] = ka.agg_pubkey;
            if (musig_aggregate_keys(ctx, &ka, b, 2)) cand[nc++] = ka.agg_pubkey;
        }
        for (size_t c = 0; c < f->n_nodes && nc < 64; c++)
            if (f->nodes[c].parent_index == (int)live_node[k] &&
                f->nodes[c].parent_vout == live_vout[k])
                cand[nc++] = f->nodes[c].keyagg.agg_pubkey;
        for (size_t ci = 0; ci < nc; ci++) {
            char what[64];
            snprintf(what, sizeof(what), "output %u:%u", live_node[k], live_vout[k]);
            if (!ep_host_alone_refused(rt, ctx, f, &kps[0], x->txid, live_vout[k], o,
                                       &cand[ci], what))
                return 0;
        }
    }

    int live_payout[64];
    for (size_t k = 0; k < n_live; k++) {
        live_payout[k] = factory_find_payout(f, live_node[k], live_vout[k]);
        TEST_ASSERT(live_payout[k] >= 0, "every unspent on-chain shared output has a payout");
    }

    /* Every member claims its share at T0. */
    char ids[256][65];
    for (size_t k = 0; k < n_live; k++) {
        const factory_payout_t *p = &f->payouts[live_payout[k]];
        if (!ep_send(rt, &p->signed_tx, ids[k])) {
            printf("  FAIL: payout of %u:%u refused at T0\n", p->node_idx, p->vout);
            return 0;
        }
        printf("  payout of %u:%u (%s, %u member%s) broadcast: %s\n", p->node_idx, p->vout,
               p->kind == PAYOUT_CHANNEL ? "channel" : p->kind == PAYOUT_STOCK ? "stock" : "tree",
               p->n_members, p->n_members == 1 ? "" : "s", ids[k]);
    }
    regtest_mine_blocks(rt, 1, mine_addr);
    for (size_t k = 0; k < n_live; k++)
        TEST_ASSERT(regtest_get_confirmations(rt, ids[k]) >= 1, "payout confirmed");

    factory_free(f);
    free(f);
    free(kps);
    free(on_chain);
    return 1;
}

static int ep_regtest_setup(regtest_t *rt, const char *wallet, char *mine_addr, size_t len) {
    if (!regtest_init(rt)) {
        printf("  FAIL: bitcoind not running\n");
        return 0;
    }
    regtest_create_wallet(rt, wallet);
    regtest_get_new_address(rt, mine_addr, len);
    if (!regtest_fund_from_faucet(rt, 1.0))
        regtest_mine_blocks(rt, 101, mine_addr);
    return 1;
}

/* Tree published, mined to T0: the host alone
   can no longer sweep any channel or tree output, and every member's share
   confirms through its payout. */
int test_regtest_end_date_payout(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ep_regtest_setup(&rt, "test_end_date", mine_addr, sizeof(mine_addr))) return 0;
    static const ep_shape_t shapes[] = {
        { "advanceless N=4 (1.0 default)", {4, 3}, 2, 1, 0, 4 },
        { "arity-2 leaves under DW layers", {2}, 1, 0, 0, 4 },
    };
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
        if (!ep_scenario_tree_published(&rt, ctx, mine_addr, &shapes[i])) return 0;
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Honest expiry, nothing published: the distribution transaction is not
   valid before T0, confirms at T0 paying every member at least its
   capacity, and the tree can no longer be published. */
int test_regtest_end_date_no_tree(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ep_regtest_setup(&rt, "test_end_date_nt", mine_addr, sizeof(mine_addr))) return 0;

    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(kps && f, "alloc");
    uint32_t t0 = (uint32_t)regtest_get_block_height(&rt) + 12;
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, t0), "init");
    TEST_ASSERT(ep_fund(&rt, f, mine_addr, 0.02), "fund");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_sign_all(f), "sign");

    tx_output_t outs[8];
    size_t nd = factory_compute_distribution_outputs_balanced(
        f, outs, 8, factory_distribution_fee(f, 4), NULL, 0);
    TEST_ASSERT(nd == 4, "distribution outputs");
    tx_buf_t dist;
    tx_buf_init(&dist, 512);
    TEST_ASSERT(factory_build_distribution_tx(f, &dist, NULL, outs, nd,
                                              factory_distribution_locktime(f)),
                "distribution TX");
    char why[96];
    TEST_ASSERT(!ep_accept(&rt, &dist, why, sizeof(why)), "distribution TX not valid before T0");
    TEST_ASSERT(strstr(why, "non-final") != NULL, "refused as non-final");

    /* The funding output has no script path: the host alone cannot take it. */
    {
        tx_output_t fo;
        memcpy(fo.script_pubkey, f->funding_spk, 34);
        fo.script_pubkey_len = 34;
        fo.amount_sats = f->funding_amount_sats;
        if (!ep_host_alone_refused(&rt, ctx, f, &kps[0], f->funding_txid, f->funding_vout,
                                   &fo, &f->nodes[0].keyagg.agg_pubkey, "funding output"))
            return 0;
    }

    int now = regtest_get_block_height(&rt);
    regtest_mine_blocks(&rt, (int)t0 - now, mine_addr);
    char txid[65];
    TEST_ASSERT(ep_send(&rt, &dist, txid), "distribution TX accepted at T0");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, txid) >= 1, "distribution TX confirmed");

    for (uint32_t m = 1; m <= 4; m++) {
        unsigned char mspk[34];
        TEST_ASSERT(factory_member_payout_spk(f, m, mspk), "member spk");
        uint64_t paid = 0;
        for (size_t k = 0; k < nd; k++)
            if (memcmp(outs[k].script_pubkey, mspk, 34) == 0) paid = outs[k].amount_sats;
        if (memcmp(outs[0].script_pubkey, mspk, 34) == 0)
            paid -= factory_tree_anchor_sats(f);   /* the anchor comes out of output 0 */
        TEST_ASSERT(paid >= ep_capacity(f, m), "member paid at least its capacity");
    }

    /* The tree is dead: the root kickoff spends a spent output. */
    TEST_ASSERT(!ep_accept(&rt, &f->nodes[0].signed_tx, why, sizeof(why)),
                "root kickoff refused after the distribution TX");
    printf("  root kickoff after the T0 payout: %s\n", why);

    tx_buf_free(&dist);
    factory_free(f);
    free(f);

    /* The host races the distribution TX: it publishes the root kickoff two
       blocks before T0 (pre-signed, valid at any height), which kills the
       distribution TX.  It still takes nothing: no root output can be spent
       by the host alone, before T0 or at it, and at T0 the payout of every
       root output pays the members under it. */
    f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc");
    t0 = (uint32_t)regtest_get_block_height(&rt) + 12;
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, t0), "init 2");
    TEST_ASSERT(ep_fund(&rt, f, mine_addr, 0.02), "fund 2");
    TEST_ASSERT(factory_build_tree(f), "build 2");
    TEST_ASSERT(factory_sign_all(f), "sign 2");
    now = regtest_get_block_height(&rt);
    regtest_mine_blocks(&rt, (int)t0 - 3 - now, mine_addr);
    TEST_ASSERT(ep_send(&rt, &f->nodes[0].signed_tx, txid), "host publishes the root kickoff");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_block_height(&rt) == (int)t0 - 2, "root kickoff two blocks before T0");
    for (int step = 0; step < 3; step++) {   /* tips T0-2, T0-1, T0 */
        for (uint32_t v = 0; v < f->nodes[0].n_outputs; v++) {
            if (ep_is_anchor(&f->nodes[0].outputs[v])) continue;
            secp256k1_xonly_pubkey internal;
            char what[48];
            snprintf(what, sizeof(what), "root output 0:%u", v);
            TEST_ASSERT(ep_output_internal(f, 0, v, &internal), "internal");
            if (!ep_host_alone_refused(&rt, ctx, f, &kps[0], f->nodes[0].txid, v,
                                       &f->nodes[0].outputs[v], &internal, what))
                return 0;
        }
        if (step < 2) regtest_mine_blocks(&rt, 1, mine_addr);
    }
    TEST_ASSERT(regtest_get_block_height(&rt) == (int)t0, "tip at T0");
    size_t n_paid = 0;
    char ids[16][65];
    for (uint32_t v = 0; v < f->nodes[0].n_outputs && n_paid < 16; v++) {
        int pi = factory_find_payout(f, 0, v);
        if (pi < 0) continue;
        TEST_ASSERT(ep_send(&rt, &f->payouts[pi].signed_tx, ids[n_paid]),
                    "root output payout accepted at T0");
        n_paid++;
    }
    TEST_ASSERT(n_paid == 4, "one payout per root output (4 leaves)");
    regtest_mine_blocks(&rt, 1, mine_addr);
    for (size_t k = 0; k < n_paid; k++)
        TEST_ASSERT(regtest_get_confirmations(&rt, ids[k]) >= 1, "root output payout confirmed");
    printf("  host published the root kickoff at T0-2: every member paid at T0 by the "
           "root outputs' payouts\n");

    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------- the host's forced exit */

/* LSP-side and member-side views of member 1's channel on the leaf output,
   wired the way the daemons wire them (basepoints, per-commitment points,
   nonce pools exchanged). */
static int ep_channel_pair(secp256k1_context *ctx, const factory_t *f,
                           const secp256k1_keypair *kps, channel_t *lsp_ch,
                           channel_t *cli_ch, uint64_t lsp_bal, uint64_t cli_bal) {
    size_t leaf = 0;
    uint32_t vout = 0;
    if (!factory_client_to_leaf(f, 0, &leaf, &vout)) return 0;
    const factory_node_t *x = &f->nodes[leaf];
    const tx_output_t *o = &x->outputs[vout];
    unsigned char lsec[32], csec[32];
    secp256k1_pubkey lpk = f->pubkeys[0], cpk = f->pubkeys[1];
    if (!secp256k1_keypair_sec(ctx, lsec, &kps[0]) || !secp256k1_keypair_sec(ctx, csec, &kps[1]))
        return 0;
    if (!channel_init(lsp_ch, ctx, lsec, &lpk, &cpk, x->txid, vout, o->amount_sats,
                      o->script_pubkey, 34, lsp_bal, cli_bal, 10) ||
        !channel_init(cli_ch, ctx, csec, &cpk, &lpk, x->txid, vout, o->amount_sats,
                      o->script_pubkey, 34, cli_bal, lsp_bal, 10)) {
        printf("  channel_init\n");
        return 0;
    }
    lsp_ch->funder_is_local = 1;
    lsp_ch->use_cpfp_anchor = 1;
    cli_ch->use_cpfp_anchor = 1;
    channel_set_commit_fee_rate(lsp_ch, f->tree_fee_rate);
    channel_set_commit_fee_rate(cli_ch, f->tree_fee_rate);
    musig_keyagg_t ka;
    uint32_t idx;
    if (!channel_discover_funding_keyagg(ctx, &lpk, &cpk, o->script_pubkey, 34, &ka, &idx)) {
        printf("  discover\n");
        return 0;
    }
    lsp_ch->funding_keyagg = ka;
    lsp_ch->local_funding_signer_idx = idx;
    if (!channel_discover_funding_keyagg(ctx, &cpk, &lpk, o->script_pubkey, 34, &ka, &idx))
        return 0;
    cli_ch->funding_keyagg = ka;
    cli_ch->local_funding_signer_idx = idx;
    if (!channel_generate_random_basepoints(lsp_ch) || !channel_generate_random_basepoints(cli_ch)) {
        printf("  basepoints\n");
        return 0;
    }
    channel_set_remote_basepoints(lsp_ch, &cli_ch->local_payment_basepoint,
                                  &cli_ch->local_delayed_payment_basepoint,
                                  &cli_ch->local_revocation_basepoint);
    channel_set_remote_basepoints(cli_ch, &lsp_ch->local_payment_basepoint,
                                  &lsp_ch->local_delayed_payment_basepoint,
                                  &lsp_ch->local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(lsp_ch, &cli_ch->local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(cli_ch, &lsp_ch->local_htlc_basepoint);
    for (uint64_t cn = 0; cn <= 1; cn++) {
        secp256k1_pubkey a, b;
        if (!channel_get_per_commitment_point(lsp_ch, cn, &a) ||
            !channel_get_per_commitment_point(cli_ch, cn, &b)) {
            printf("  pcp %llu\n", (unsigned long long)cn);
            return 0;
        }
        channel_set_remote_pcp(cli_ch, cn, &a);
        channel_set_remote_pcp(lsp_ch, cn, &b);
    }
    if (!channel_init_nonce_pool(lsp_ch, 16) || !channel_init_nonce_pool(cli_ch, 16)) {
        printf("  nonce pool\n");
        return 0;
    }
    unsigned char lpn[16][66], cpn[16][66];
    for (int i = 0; i < 16; i++) {
        musig_pubnonce_serialize(ctx, lpn[i], &lsp_ch->local_nonce_pool.nonces[i].pubnonce);
        musig_pubnonce_serialize(ctx, cpn[i], &cli_ch->local_nonce_pool.nonces[i].pubnonce);
    }
    return channel_set_remote_pubnonces(lsp_ch, (const unsigned char (*)[66])cpn, 16) &&
           channel_set_remote_pubnonces(cli_ch, (const unsigned char (*)[66])lpn, 16);
}

/* The host keeps its own commitment, co-signed by the member through the
   real protocol handlers (initial HOST_COMMITMENT_SIG, then a REVOKE_AND_ACK
   after an update that leaves the member with little), and before T0 pushes
   the member's path and that commitment on chain.  At T0 the member's
   channel payout spends nothing (the host closed the channel with the real
   balances), and the member's balance sits in the host's commitment. */
int test_regtest_end_date_host_forced_exit(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ep_regtest_setup(&rt, "test_end_date_fe", mine_addr, sizeof(mine_addr))) return 0;
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    channel_t *lsp_ch = calloc(1, sizeof(channel_t)), *cli_ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(kps && f && lsp_ch && cli_ch, "alloc");
    uint32_t t0 = (uint32_t)regtest_get_block_height(&rt) + 40;
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, t0), "init");
    TEST_ASSERT(ep_fund(&rt, f, mine_addr, 0.02), "fund");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_sign_all(f), "sign");

    size_t leaf = 0;
    uint32_t vout = 0;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &leaf, &vout), "leaf");
    uint64_t cap = f->nodes[leaf].outputs[vout].amount_sats;
    TEST_ASSERT(ep_channel_pair(ctx, f, kps, lsp_ch, cli_ch, cap / 2, cap / 2 - 2000),
                "channel pair");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Commitment 0: the host signs the member's, the member co-signs the host's. */
    {
        unsigned char ps[32];
        uint32_t ni;
        TEST_ASSERT(channel_create_commitment_partial_sig(lsp_ch, ps, &ni), "host psig 0");
        wire_msg_t m;
        memset(&m, 0, sizeof(m));
        m.msg_type = MSG_COMMITMENT_SIGNED;
        m.json = wire_build_commitment_signed(0, 0, ps, ni);
        TEST_ASSERT(client_handle_initial_commitment_signed(cli_ch, &m), "member takes 0");
        cJSON_Delete(m.json);
        cJSON *reply = cJSON_CreateObject();
        TEST_ASSERT(client_add_host_commit_sig(cli_ch, reply), "member co-signs host 0");
        TEST_ASSERT(lsp_take_host_commit_sig(lsp_ch, reply) &&
                    lsp_ch->has_latest_commitment_sig, "host holds its commitment 0");
        cJSON_Delete(reply);
    }

    /* The member spends almost everything: commitment 1 leaves it 1000 sats. */
    uint64_t total = lsp_ch->local_amount + lsp_ch->remote_amount;
    lsp_ch->commitment_number = cli_ch->commitment_number = 1;
    /* per-commitment secrets for the next number, as the daemons keep them */
    channel_generate_local_pcs(lsp_ch, 2);
    channel_generate_local_pcs(cli_ch, 2);
    lsp_ch->remote_amount = cli_ch->local_amount = 1000;
    lsp_ch->local_amount = cli_ch->remote_amount = total - 1000;
    {
        unsigned char ps[32];
        uint32_t ni;
        TEST_ASSERT(channel_create_commitment_partial_sig(lsp_ch, ps, &ni), "host psig 1");
        wire_msg_t m;
        memset(&m, 0, sizeof(m));
        m.msg_type = MSG_COMMITMENT_SIGNED;
        m.json = wire_build_commitment_signed(0, 1, ps, ni);
        TEST_ASSERT(client_handle_commitment_signed(sv[1], cli_ch, ctx, &m),
                    "member takes 1 and sends REVOKE_AND_ACK");
        cJSON_Delete(m.json);
        wire_msg_t ack;
        TEST_ASSERT(wire_recv(sv[0], &ack) && ack.msg_type == MSG_REVOKE_AND_ACK, "ack");
        uint32_t cid;
        unsigned char sec[32], np[33];
        TEST_ASSERT(lsp_parse_member_revoke(lsp_ch, ack.json, &cid, sec, np),
                    "host takes the revocation and its co-signed commitment 1");
        cJSON_Delete(ack.json);
        TEST_ASSERT(lsp_ch->has_latest_commitment_sig && lsp_ch->latest_commitment_sig_cn == 1,
                    "host holds its commitment 1");
    }

    /* Forced exit, before T0: the member's path, then the host's commitment. */
    int *on_chain = calloc(256, sizeof(int));
    TEST_ASSERT(on_chain && ep_publish_path(&rt, f, mine_addr, on_chain), "push the path");
    tx_buf_t commit;
    tx_buf_init(&commit, 512);
    char ctxid[65], sent[65];
    TEST_ASSERT(lsp_signed_host_commitment(lsp_ch, &commit, ctxid), "host commitment");
    TEST_ASSERT(ep_send(&rt, &commit, sent), "host commitment accepted before T0");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, ctxid) >= 1, "host commitment confirmed");
    TEST_ASSERT(regtest_get_block_height(&rt) < (int)t0, "all of it before T0");

    /* The member's real balance is an output of the host's commitment. */
    {
        int found = 0;
        for (uint32_t v = 0; v < 8 && !found; v++) {
            char params[100];
            snprintf(params, sizeof(params), "\"%s\" %u", ctxid, v);
            char *res = regtest_exec(&rt, "gettxout", params);
            cJSON *j = res ? cJSON_Parse(res) : NULL;
            cJSON *val = j ? cJSON_GetObjectItem(j, "value") : NULL;
            if (val && cJSON_IsNumber(val)) {
                uint64_t a = (uint64_t)(val->valuedouble * 1e8 + 0.5);
                printf("  host commitment output %u: %llu sats\n", v, (unsigned long long)a);
                if (a == 1000) found = 1;
            }
            cJSON_Delete(j);
            free(res);
        }
        TEST_ASSERT(found, "the member's 1000-sat balance is an output of the host commitment");
    }

    /* At T0 the member's channel payout is dead: the channel is closed. */
    int now = regtest_get_block_height(&rt);
    regtest_mine_blocks(&rt, (int)t0 - now, mine_addr);
    int pi = factory_find_payout(f, (uint32_t)leaf, vout);
    TEST_ASSERT(pi >= 0, "channel payout exists");
    char why[96];
    TEST_ASSERT(!ep_accept(&rt, &f->payouts[pi].signed_tx, why, sizeof(why)),
                "the channel payout is refused once the host closed the channel");
    printf("  channel payout after the forced exit: %s\n", why);

    close(sv[0]);
    close(sv[1]);
    tx_buf_free(&commit);
    channel_cleanup(lsp_ch);
    channel_cleanup(cli_ch);
    free(lsp_ch);
    free(cli_ch);
    free(on_chain);
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A member takes a factory only with a valid end-date payout for every
   output on its path: FACTORY_READY without the payout signatures, or with
   one of them wrong, is refused; the complete one is taken and every payout
   on the member's path is signed. */
int test_end_date_member_refuses_missing_payouts(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    TEST_ASSERT(kps, "keys");
    unsigned char txid[32], spk[34];
    memset(txid, 0x4D, 32);

    factory_t *lsp_f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(lsp_f && ep_init(lsp_f, ctx, kps, &shape, 5000), "init");
    TEST_ASSERT(factory_compute_funding_spk(lsp_f, spk) &&
                factory_set_funding(lsp_f, txid, 0, 2000000, spk, 34) &&
                factory_build_tree(lsp_f) && factory_sign_all(lsp_f), "signed factory");
    cJSON *ready = wire_build_factory_ready(lsp_f);
    TEST_ASSERT(ready && cJSON_GetObjectItem(ready, "payout_sigs"), "FACTORY_READY carries payouts");

    for (int variant = 0; variant < 3; variant++) {
        factory_t *m = calloc(1, sizeof(factory_t));
        TEST_ASSERT(m && ep_init(m, ctx, kps, &shape, 5000), "member init");
        TEST_ASSERT(factory_set_funding(m, txid, 0, 2000000, spk, 34) && factory_build_tree(m),
                    "member builds the same tree");
        cJSON *msg = cJSON_Duplicate(ready, 1);
        if (variant == 1) {
            cJSON_DeleteItemFromObject(msg, "payout_sigs");
        } else if (variant == 2) {
            /* flip a bit of the signature of a payout on member 1's path */
            int pi = -1;
            for (size_t k = 0; k < lsp_f->n_payouts && pi < 0; k++)
                if (factory_payout_on_path(lsp_f, k, 1)) pi = (int)k;
            TEST_ASSERT(pi >= 0, "payout on path");
            size_t len = lsp_f->n_payouts * 64;
            unsigned char *sigs = malloc(len);
            TEST_ASSERT(sigs && wire_json_get_hex(msg, "payout_sigs", sigs, len) == (int)len, "sigs");
            sigs[pi * 64 + 5] ^= 0x01;
            cJSON_DeleteItemFromObject(msg, "payout_sigs");
            wire_json_add_hex(msg, "payout_sigs", sigs, len);
            free(sigs);
        }
        int r = client_apply_factory_ready(m, msg, 1);
        cJSON_Delete(msg);
        if (variant == 0) {
            TEST_ASSERT(r >= 0, "the complete FACTORY_READY is taken");
            TEST_ASSERT(factory_payouts_all_signed(m, 1), "every payout on the path is signed");
        } else {
            TEST_ASSERT(r < 0, variant == 1 ? "missing payout signatures refused"
                                            : "a wrong payout signature is refused");
        }
        factory_free(m);
        free(m);
    }
    cJSON_Delete(ready);
    factory_free(lsp_f);
    free(lsp_f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Once a member co-signs the LSP's commitments, it releases no preimage
   while an older LSP commitment it co-signed is unrevoked: the LSP could
   publish that one after taking the preimage. */
int test_end_date_member_waits_for_host_revocation(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    channel_t *lsp_ch = calloc(1, sizeof(channel_t)), *cli_ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(kps && f && lsp_ch && cli_ch, "alloc");
    unsigned char txid[32], spk[34];
    memset(txid, 0x3C, 32);
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, 5000) && factory_compute_funding_spk(f, spk) &&
                factory_set_funding(f, txid, 0, 2000000, spk, 34) && factory_build_tree(f),
                "tree");
    size_t leaf = 0;
    uint32_t vout = 0;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &leaf, &vout), "leaf");
    uint64_t cap = f->nodes[leaf].outputs[vout].amount_sats;
    TEST_ASSERT(ep_channel_pair(ctx, f, kps, lsp_ch, cli_ch, cap / 2, cap / 2 - 2000), "pair");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* commitment 0, co-signed both ways */
    unsigned char ps[32];
    uint32_t ni;
    TEST_ASSERT(channel_create_commitment_partial_sig(lsp_ch, ps, &ni), "host psig 0");
    wire_msg_t m;
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_COMMITMENT_SIGNED;
    m.json = wire_build_commitment_signed(0, 0, ps, ni);
    TEST_ASSERT(client_handle_initial_commitment_signed(cli_ch, &m), "member 0");
    cJSON_Delete(m.json);
    cJSON *reply = cJSON_CreateObject();
    TEST_ASSERT(client_add_host_commit_sig(cli_ch, reply) && lsp_take_host_commit_sig(lsp_ch, reply),
                "host 0 co-signed");
    cJSON_Delete(reply);
    TEST_ASSERT(client_host_old_commitments_revoked(cli_ch), "nothing older than 0");

    /* commitment 1: the member co-signs the LSP's commitment 1 */
    lsp_ch->commitment_number = cli_ch->commitment_number = 1;
    /* per-commitment secrets for the next number, as the daemons keep them */
    channel_generate_local_pcs(lsp_ch, 2);
    channel_generate_local_pcs(cli_ch, 2);
    lsp_ch->remote_amount += 5000; lsp_ch->local_amount -= 5000;
    cli_ch->local_amount += 5000;  cli_ch->remote_amount -= 5000;
    TEST_ASSERT(channel_create_commitment_partial_sig(lsp_ch, ps, &ni), "host psig 1");
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_COMMITMENT_SIGNED;
    m.json = wire_build_commitment_signed(0, 1, ps, ni);
    TEST_ASSERT(client_handle_commitment_signed(sv[1], cli_ch, ctx, &m), "member 1");
    cJSON_Delete(m.json);
    wire_msg_t ack;
    TEST_ASSERT(wire_recv(sv[0], &ack), "ack");
    uint32_t cid;
    unsigned char sec[32], np[33];
    TEST_ASSERT(lsp_parse_member_revoke(lsp_ch, ack.json, &cid, sec, np), "host takes 1");
    cJSON_Delete(ack.json);

    /* The LSP has not revoked its commitment 0: no preimage. */
    TEST_ASSERT(!client_host_old_commitments_revoked(cli_ch),
                "an unrevoked older LSP commitment blocks the preimage");
    unsigned char preimage[32];
    memset(preimage, 0x11, 32);
    TEST_ASSERT(!client_fulfill_payment(sv[1], cli_ch, 0, preimage), "fulfil refused");

    /* The LSP's revocation of commitment 0 arrives: the preimage may go. */
    unsigned char lsp_sec[32];
    secp256k1_pubkey next;
    TEST_ASSERT(channel_generate_local_pcs(lsp_ch, 2) &&
                channel_get_revocation_secret(lsp_ch, 0, lsp_sec) &&
                channel_get_per_commitment_point(lsp_ch, 2, &next), "LSP secret");
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_LSP_REVOKE_AND_ACK;
    m.json = wire_build_revoke_and_ack(0, lsp_sec, ctx, &next);
    TEST_ASSERT(client_handle_lsp_revoke_and_ack(cli_ch, ctx, &m), "member takes the revocation");
    cJSON_Delete(m.json);
    TEST_ASSERT(client_host_old_commitments_revoked(cli_ch), "revoked: the preimage may go");

    close(sv[0]);
    close(sv[1]);
    channel_cleanup(lsp_ch);
    channel_cleanup(cli_ch);
    free(lsp_ch);
    free(cli_ch);
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}


/* Commitment 0 co-signed both ways, as at channel open. */
static int ep_open_cosigned(secp256k1_context *ctx, channel_t *lsp_ch, channel_t *cli_ch) {
    unsigned char ps[32];
    uint32_t ni;
    if (!channel_create_commitment_partial_sig(lsp_ch, ps, &ni)) return 0;
    wire_msg_t m;
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_COMMITMENT_SIGNED;
    m.json = wire_build_commitment_signed(0, 0, ps, ni);
    int ok = client_handle_initial_commitment_signed(cli_ch, &m);
    cJSON_Delete(m.json);
    cJSON *reply = cJSON_CreateObject();
    ok = ok && client_add_host_commit_sig(cli_ch, reply) && lsp_take_host_commit_sig(lsp_ch, reply);
    cJSON_Delete(reply);
    (void)ctx;
    return ok;
}

/* Move 5000 sat to the member and have the LSP sign the member's commitment 1. */
static int ep_update_to_1(channel_t *lsp_ch, channel_t *cli_ch, wire_msg_t *cs_out) {
    lsp_ch->commitment_number = cli_ch->commitment_number = 1;
    channel_generate_local_pcs(lsp_ch, 2);
    channel_generate_local_pcs(cli_ch, 2);
    lsp_ch->remote_amount += 5000; lsp_ch->local_amount -= 5000;
    cli_ch->local_amount += 5000;  cli_ch->remote_amount -= 5000;
    unsigned char ps[32];
    uint32_t ni;
    if (!channel_create_commitment_partial_sig(lsp_ch, ps, &ni)) return 0;
    memset(cs_out, 0, sizeof(*cs_out));
    cs_out->msg_type = MSG_COMMITMENT_SIGNED;
    cs_out->json = wire_build_commitment_signed(0, 1, ps, ni);
    return cs_out->json != NULL;
}

/* An update is taken only with the member's signature over the LSP's
   commitment at the new number.  The LSP refuses a REVOKE_AND_ACK without
   it (as one whose signature does not verify): it takes no revocation,
   keeps the LSP commitment it holds (the previous one, co-signed and not
   revoked) and the channel takes no further update.  A member that cannot
   co-sign sends no revocation: it fails the update with an error. */
int test_end_date_update_needs_host_cosig(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(kps && f, "alloc");
    unsigned char txid[32], spk[34];
    memset(txid, 0x5E, 32);
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, 5000) && factory_compute_funding_spk(f, spk) &&
                factory_set_funding(f, txid, 0, 2000000, spk, 34) && factory_build_tree(f),
                "tree");
    size_t leaf = 0;
    uint32_t vout = 0;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &leaf, &vout), "leaf");
    uint64_t cap = f->nodes[leaf].outputs[vout].amount_sats;

    for (int side = 0; side < 2; side++) {
        channel_t *lsp_ch = calloc(1, sizeof(channel_t)), *cli_ch = calloc(1, sizeof(channel_t));
        TEST_ASSERT(lsp_ch && cli_ch, "alloc");
        TEST_ASSERT(ep_channel_pair(ctx, f, kps, lsp_ch, cli_ch, cap / 2, cap / 2 - 2000), "pair");
        TEST_ASSERT(ep_open_cosigned(ctx, lsp_ch, cli_ch), "commitment 0 co-signed");
        unsigned char held0[32];
        memcpy(held0, lsp_ch->host_commit_txid, 32);
        TEST_ASSERT(lsp_ch->host_commit_tx_len > 0, "LSP holds its commitment 0");
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        wire_msg_t cs;
        if (side == 1) {
            /* the member has no nonce left to co-sign with */
            cli_ch->remote_nonce_next = cli_ch->remote_nonce_count;
        }
        TEST_ASSERT(ep_update_to_1(lsp_ch, cli_ch, &cs), "LSP signs the member's commitment 1");
        int handled = client_handle_commitment_signed(sv[1], cli_ch, ctx, &cs);
        cJSON_Delete(cs.json);
        wire_msg_t ack;
        memset(&ack, 0, sizeof(ack));
        TEST_ASSERT(wire_recv_timeout(sv[0], &ack, 5), "reply from the member");
        if (side == 0) {
            TEST_ASSERT(handled && ack.msg_type == MSG_REVOKE_AND_ACK, "member revokes");
            cJSON_DeleteItemFromObject(ack.json, "host_commit_psig");
            cJSON_DeleteItemFromObject(ack.json, "host_commit_nonce_index");
            uint32_t cid;
            unsigned char sec[32], np[33];
            TEST_ASSERT(!lsp_parse_member_revoke(lsp_ch, ack.json, &cid, sec, np),
                        "a revocation without the co-signature is refused");
            TEST_ASSERT(lsp_ch->host_commit_refused, "the channel takes no further update");
            TEST_ASSERT(!channel_get_received_revocation(lsp_ch, 0, sec),
                        "no revocation taken");
            TEST_ASSERT(lsp_ch->latest_commitment_sig_cn == 0 &&
                        memcmp(lsp_ch->host_commit_txid, held0, 32) == 0,
                        "the LSP still holds its co-signed commitment 0");
            unsigned char ps[32];
            uint32_t ni;
            TEST_ASSERT(!channel_create_commitment_partial_sig(lsp_ch, ps, &ni),
                        "no new commitment is signed on the channel");
        } else {
            TEST_ASSERT(!handled, "the member fails the update");
            TEST_ASSERT(ack.msg_type != MSG_REVOKE_AND_ACK,
                        "no revocation without the co-signature");
            TEST_ASSERT(ack.msg_type == MSG_ERROR, "the member reports the failed update");
        }
        if (ack.json) cJSON_Delete(ack.json);
        close(sv[0]);
        close(sv[1]);
        channel_cleanup(lsp_ch);
        channel_cleanup(cli_ch);
        free(lsp_ch);
        free(cli_ch);
    }
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The preimage rule holds after the member's channel is rebuilt from its
   database, as a restart or a reconnect does (client_run_reconnect): an
   unrevoked older LSP commitment still blocks the preimage; once the LSP's
   revocation is stored, the rebuilt channel releases it. */
int test_end_date_revocation_wait_survives_restart(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    channel_t *lsp_ch = calloc(1, sizeof(channel_t)), *cli_ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(kps && f && lsp_ch && cli_ch, "alloc");
    unsigned char txid[32], spk[34];
    memset(txid, 0x6F, 32);
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, 5000) && factory_compute_funding_spk(f, spk) &&
                factory_set_funding(f, txid, 0, 2000000, spk, 34) && factory_build_tree(f),
                "tree");
    size_t leaf = 0;
    uint32_t vout = 0;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &leaf, &vout), "leaf");
    uint64_t cap = f->nodes[leaf].outputs[vout].amount_sats;
    TEST_ASSERT(ep_channel_pair(ctx, f, kps, lsp_ch, cli_ch, cap / 2, cap / 2 - 2000), "pair");
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "member database");
    channel_set_persist(cli_ch, &db, 0);
    TEST_ASSERT(ep_open_cosigned(ctx, lsp_ch, cli_ch), "commitment 0 co-signed");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    wire_msg_t cs;
    TEST_ASSERT(ep_update_to_1(lsp_ch, cli_ch, &cs), "update");
    TEST_ASSERT(client_handle_commitment_signed(sv[1], cli_ch, ctx, &cs), "member 1");
    cJSON_Delete(cs.json);
    wire_msg_t ack;
    TEST_ASSERT(wire_recv(sv[0], &ack), "ack");
    uint32_t cid;
    unsigned char sec[32], np[33];
    TEST_ASSERT(lsp_parse_member_revoke(lsp_ch, ack.json, &cid, sec, np), "host takes 1");
    cJSON_Delete(ack.json);

    /* restart: the channel is rebuilt; the LSP's commitment 0 is unrevoked */
    for (int round = 0; round < 2; round++) {
        if (round == 1) {
            unsigned char lsp_sec[32];
            secp256k1_pubkey next;
            TEST_ASSERT(channel_get_revocation_secret(lsp_ch, 0, lsp_sec) &&
                        channel_get_per_commitment_point(lsp_ch, 2, &next), "LSP secret");
            wire_msg_t m;
            memset(&m, 0, sizeof(m));
            m.msg_type = MSG_LSP_REVOKE_AND_ACK;
            m.json = wire_build_revoke_and_ack(0, lsp_sec, ctx, &next);
            TEST_ASSERT(client_handle_lsp_revoke_and_ack(cli_ch, ctx, &m), "revocation stored");
            cJSON_Delete(m.json);
        }
        channel_t *l2 = calloc(1, sizeof(channel_t)), *re = calloc(1, sizeof(channel_t));
        TEST_ASSERT(l2 && re && ep_channel_pair(ctx, f, kps, l2, re, cap / 2, cap / 2 - 2000),
                    "rebuilt channel");
        re->commitment_number = 1;
        TEST_ASSERT(client_restore_host_revocations(re, &db, 0), "restore");
        if (round == 0) {
            TEST_ASSERT(!client_host_old_commitments_revoked(re),
                        "after a restart an unrevoked older LSP commitment still blocks the preimage");
            unsigned char preimage[32];
            memset(preimage, 0x11, 32);
            TEST_ASSERT(!client_fulfill_payment(sv[1], re, 0, preimage), "fulfil refused");
        } else {
            TEST_ASSERT(client_host_old_commitments_revoked(re),
                        "the stored revocation is restored: the preimage may go");
        }
        channel_cleanup(l2);
        channel_cleanup(re);
        free(l2);
        free(re);
    }
    persist_close(&db);
    close(sv[0]);
    close(sv[1]);
    channel_cleanup(lsp_ch);
    channel_cleanup(cli_ch);
    free(lsp_ch);
    free(cli_ch);
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* No factory without an end date in the future: the member refuses a
   proposal with CLTV timeout 0 (with or without a chain view), the builder
   makes no payouts for it, and the LSP does not start the ceremony. */
int test_end_date_refuses_missing_end_date(void) {
    char err[320];
    TEST_ASSERT(!cli_validate_proposed_cltv(0, 0, 10, err, sizeof(err)),
                "CLTV 0 refused without a chain view");
    TEST_ASSERT(!cli_validate_proposed_cltv(0, 500, 10, err, sizeof(err)),
                "CLTV 0 refused with a chain view");
    TEST_ASSERT(!cli_validate_proposed_cltv(400, 500, 10, err, sizeof(err)),
                "a CLTV in the past is refused");
    TEST_ASSERT(cli_validate_proposed_cltv(600, 500, 10, err, sizeof(err)),
                "a CLTV past the exit is taken");

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(kps && f, "alloc");
    unsigned char txid[32], spk[34];
    memset(txid, 0x70, 32);
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, 0) && factory_compute_funding_spk(f, spk) &&
                factory_set_funding(f, txid, 0, 2000000, spk, 34) && factory_build_tree(f),
                "tree without an end date");
    TEST_ASSERT(f->n_payouts == 0, "no payouts without an end date");
    factory_free(f);
    free(f);

    lsp_t *l = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(l, "alloc");
    TEST_ASSERT(lsp_run_factory_creation(l, txid, 0, 2000000, spk, 34, 10, 4, 0) == 0,
                "the LSP proposes no factory without an end date");
    free(l);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The commitment anchor comes from the funder's balance only: a state that
   leaves the funder too little for it is not built, so it is never signed. */
int test_end_date_anchor_from_funder_only(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    channel_t *lsp_ch = calloc(1, sizeof(channel_t)), *cli_ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(kps && f && lsp_ch && cli_ch, "alloc");
    unsigned char txid[32], spk[34];
    memset(txid, 0x71, 32);
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, 5000) && factory_compute_funding_spk(f, spk) &&
                factory_set_funding(f, txid, 0, 2000000, spk, 34) && factory_build_tree(f),
                "tree");
    size_t leaf = 0;
    uint32_t vout = 0;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &leaf, &vout), "leaf");
    uint64_t cap = f->nodes[leaf].outputs[vout].amount_sats;
    TEST_ASSERT(ep_channel_pair(ctx, f, kps, lsp_ch, cli_ch, cap / 2, cap / 2 - 2000), "pair");
    tx_buf_t t;
    tx_buf_init(&t, 512);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(lsp_ch, &t, ct) &&
                channel_build_commitment_tx(cli_ch, &t, ct), "both commitments built");
    /* the LSP (funder) keeps 300 sat: below the 240-sat anchor plus dust */
    uint64_t total = lsp_ch->local_amount + lsp_ch->remote_amount;
    lsp_ch->local_amount = 300;  lsp_ch->remote_amount = total - 300;
    cli_ch->remote_amount = 300; cli_ch->local_amount = total - 300;
    TEST_ASSERT(!channel_build_commitment_tx(lsp_ch, &t, ct),
                "the LSP's commitment is not built from the member's balance");
    TEST_ASSERT(!channel_build_commitment_tx(cli_ch, &t, ct),
                "the member's commitment is not built from the member's balance");
    unsigned char ps[32];
    uint32_t ni;
    TEST_ASSERT(!channel_create_commitment_partial_sig(lsp_ch, ps, &ni),
                "so no signature for that state");
    tx_buf_free(&t);
    channel_cleanup(lsp_ch);
    channel_cleanup(cli_ch);
    free(lsp_ch);
    free(cli_ch);
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Between updates the LSP refreshes a channel's signing nonces before they
   run out (lsp_channels_refresh_nonces, from the daemon loop); the member
   answers with a fresh pool (client_handle_nonce_refresh), and the next
   update, with its co-signature of the LSP's commitment, signs from the
   fresh pools. */
int test_end_date_nonce_refresh(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const ep_shape_t shape = { "advanceless N=4", {4, 3}, 2, 1, 0, 4 };
    secp256k1_keypair *kps = ep_keys(ctx, 5);
    factory_t *f = calloc(1, sizeof(factory_t));
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    channel_t *cli_ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(kps && f && mgr && lsp && cli_ch, "alloc");
    mgr->entries = calloc(1, sizeof(lsp_channel_entry_t));
    lsp->client_fds = calloc(1, sizeof(int));
    TEST_ASSERT(mgr->entries && lsp->client_fds, "alloc");
    unsigned char txid[32], spk[34];
    memset(txid, 0x72, 32);
    TEST_ASSERT(ep_init(f, ctx, kps, &shape, 5000) && factory_compute_funding_spk(f, spk) &&
                factory_set_funding(f, txid, 0, 2000000, spk, 34) && factory_build_tree(f),
                "tree");
    size_t leaf = 0;
    uint32_t vout = 0;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &leaf, &vout), "leaf");
    uint64_t cap = f->nodes[leaf].outputs[vout].amount_sats;
    channel_t *lsp_ch = &mgr->entries[0].channel;
    TEST_ASSERT(ep_channel_pair(ctx, f, kps, lsp_ch, cli_ch, cap / 2, cap / 2 - 2000), "pair");
    mgr->ctx = ctx;
    mgr->n_channels = 1;
    mgr->entries[0].ready = 1;
    TEST_ASSERT(ep_open_cosigned(ctx, lsp_ch, cli_ch), "commitment 0 co-signed");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    lsp->client_fds[0] = sv[0];

    /* nearly spent on both sides */
    lsp_ch->remote_nonce_next = lsp_ch->remote_nonce_count - 1;
    cli_ch->remote_nonce_next = cli_ch->remote_nonce_count - 1;
    pid_t pid = fork();
    TEST_ASSERT(pid >= 0, "fork");
    if (pid == 0) {
        close(sv[0]);
        wire_msg_t m;
        memset(&m, 0, sizeof(m));
        int ok = wire_recv_timeout(sv[1], &m, 10) && m.msg_type == MSG_CHANNEL_NONCES &&
                 cJSON_IsTrue(cJSON_GetObjectItem(m.json, "refresh")) &&
                 client_handle_nonce_refresh(sv[1], cli_ch, ctx, &m);
        if (m.json) cJSON_Delete(m.json);
        /* then the next update, signed from the fresh pools */
        memset(&m, 0, sizeof(m));
        ok = ok && wire_recv_timeout(sv[1], &m, 10) && m.msg_type == MSG_COMMITMENT_SIGNED;
        if (ok) {
            cli_ch->commitment_number = 1;
            channel_generate_local_pcs(cli_ch, 2);
            cli_ch->local_amount += 5000;  cli_ch->remote_amount -= 5000;
            ok = client_handle_commitment_signed(sv[1], cli_ch, ctx, &m);
        }
        if (m.json) cJSON_Delete(m.json);
        _exit(ok ? 0 : 1);
    }
    close(sv[1]);
    TEST_ASSERT(lsp_channels_refresh_nonces(mgr, lsp, 0, 0) == 1, "nonces refreshed");
    TEST_ASSERT(lsp_ch->remote_nonce_next == 0 &&
                lsp_ch->remote_nonce_count >= CHANNEL_NONCE_REFRESH_AT, "fresh member nonces");
    wire_msg_t cs;
    TEST_ASSERT(ep_update_to_1(lsp_ch, cli_ch, &cs), "LSP signs commitment 1 with fresh nonces");
    TEST_ASSERT(wire_send(sv[0], MSG_COMMITMENT_SIGNED, cs.json), "send");
    cJSON_Delete(cs.json);
    wire_msg_t ack;
    memset(&ack, 0, sizeof(ack));
    TEST_ASSERT(wire_recv_timeout(sv[0], &ack, 10) && ack.msg_type == MSG_REVOKE_AND_ACK, "ack");
    uint32_t cid;
    unsigned char sec[32], np[33];
    TEST_ASSERT(lsp_parse_member_revoke(lsp_ch, ack.json, &cid, sec, np),
                "the member's co-signature of the LSP's commitment 1 verifies");
    cJSON_Delete(ack.json);
    int st = 0;
    waitpid(pid, &st, 0);
    TEST_ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0, "member side");
    close(sv[0]);
    channel_cleanup(lsp_ch);
    channel_cleanup(cli_ch);
    free(cli_ch);
    free(mgr->entries);
    free(mgr);
    free(lsp->client_fds);
    free(lsp);
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}
