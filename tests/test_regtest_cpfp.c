/* Regtest: broadcasting pre-signed TRUC tree transactions.

   The tree's transactions are TRUC (nVersion 3) with a keyless P2A anchor.
   These tests run against a real bitcoind -regtest and check how the exit
   paths put them in the mempool. */

#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include "superscalar/factory.h"
#include "superscalar/factory_recovery.h"
#include "superscalar/persist.h"
#include "superscalar/cpfp.h"
#include "superscalar/watchtower.h"
#include "superscalar/fee.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "cJSON.h"
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define RT_N 5   /* LSP + 4 clients */

/* Fund a factory of RT_N participants on regtest, build and sign its tree
   (arity 2, tree anchors, every DW delay 0), all keys local. */
static int fund_tree(regtest_t *rt, secp256k1_context *ctx, const char *mine_addr,
                     factory_t *f, secp256k1_keypair *kps, uint64_t tree_rate,
                     char fund_txid_out[65]) {
    secp256k1_pubkey pks[RT_N];
    for (size_t i = 0; i < RT_N; i++) {
        unsigned char sk[32];
        memset(sk, 0, 32);
        sk[0] = 0x5c;
        sk[31] = (unsigned char)(i + 1);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk) ||
            !secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, RT_N)) return 0;
    unsigned char agg[32], tweak[32], spk[34], tw_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, agg, &ka.agg_pubkey);
    sha256_tagged("TapTweak", agg, 32, tweak);
    secp256k1_pubkey tw;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw, &ka.cache, tweak)) return 0;
    secp256k1_xonly_pubkey twx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &twx, NULL, &tw);
    build_p2tr_script_pubkey(spk, &twx);
    secp256k1_xonly_pubkey_serialize(ctx, tw_ser, &twx);

    char addr[128];
    if (!regtest_derive_p2tr_address(rt, tw_ser, addr, sizeof(addr))) return 0;
    if (!regtest_fund_address(rt, addr, 0.01, fund_txid_out)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    uint32_t vout = UINT32_MAX;
    uint64_t amount = 0;
    for (uint32_t v = 0; v < 4 && vout == UINT32_MAX; v++) {
        unsigned char s[64];
        size_t sl = 0;
        uint64_t a = 0;
        if (regtest_get_tx_output(rt, fund_txid_out, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, spk, 34) == 0) { vout = v; amount = a; }
    }
    if (vout == UINT32_MAX) return 0;
    unsigned char txid[32];
    hex_decode(fund_txid_out, txid, 32);
    reverse_bytes(txid, 32);
    if (!factory_init(f, ctx, kps, RT_N, 1, 4)) return 0;
    f->use_tree_anchor = 1;
    f->tree_fee_rate = tree_rate;
    factory_set_funding(f, txid, vout, amount, spk, 34);
    if (!factory_build_tree(f) || !factory_sign_all(f)) return 0;
    for (int i = 0; i < 15; i++)          /* newest state: every delay 0 */
        if (!factory_advance(f)) return 0;
    return 1;
}

static void node_txid(const factory_t *f, size_t i, char out[65]) {
    unsigned char d[32];
    memcpy(d, f->nodes[i].txid, 32);
    reverse_bytes(d, 32);
    hex_encode(d, 32, out);
}

/* getmempoolentry field (descendantcount, ...); -1 if not in the mempool. */
static long mempool_field(regtest_t *rt, const char *txid, const char *field) {
    char params[80];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *r = regtest_exec(rt, "getmempoolentry", params);
    if (!r) return -1;
    cJSON *j = cJSON_Parse(r);
    free(r);
    cJSON *v = j ? cJSON_GetObjectItem(j, field) : NULL;
    long out = (v && cJSON_IsNumber(v)) ? (long)v->valuedouble : -1;
    cJSON_Delete(j);
    return out;
}

/* Factory recovery sends a tree child only once its parent is confirmed:
   with the parent unconfirmed the child would take the TRUC parent's only
   descendant slot (or be rejected), and the parent could not be CPFP'd.
   Passes run back to back without mining must never put a child in. */
int test_regtest_recovery_waits_for_confirmed_parent(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    TEST_ASSERT(regtest_init(&rt), "bitcoind");
    regtest_create_wallet(&rt, "cpfp_recovery");
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)), "address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    factory_t *f = calloc(1, sizeof(factory_t));
    secp256k1_keypair kps[RT_N];
    char fund_txid[65];
    TEST_ASSERT(f && fund_tree(&rt, ctx, mine_addr, f, kps, 0, fund_txid), "factory");
    printf("  tree: %zu nodes, funding %s\n", f->n_nodes, fund_txid);

    char db_path[] = "/tmp/ss_rt_recovery_XXXXXX";
    int fd = mkstemp(db_path);
    TEST_ASSERT(fd >= 0, "db file");
    close(fd);
    persist_t p;
    TEST_ASSERT(persist_open(&p, db_path), "persist");
    TEST_ASSERT(persist_save_factory(&p, f, ctx, 0), "save factory");
    TEST_ASSERT(persist_save_tree_nodes(&p, f, 0), "save tree");

    chain_backend_t cb;
    chain_backend_regtest_init(&cb, &rt);
    cpfp_set_default(&rt, NULL, NULL, 0);

    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) node_txid(f, i, txids[i]);

    int all_confirmed = 0;
    for (int round = 0; round < 20 && !all_confirmed; round++) {
        /* three passes back to back, nothing mined in between */
        for (int pass = 0; pass < 3; pass++) {
            char status[256];
            factory_recovery_run(&p, &cb, 0, status, sizeof(status));
            for (size_t i = 0; i < f->n_nodes; i++) {
                if (mempool_field(&rt, txids[i], "vsize") < 0) continue;
                int par = f->nodes[i].parent_index;
                if (par >= 0 && regtest_get_confirmations(&rt, txids[par]) < 1) {
                    printf("  FAIL: node %zu in the mempool with parent %d unconfirmed\n",
                           i, par);
                    return 0;
                }
                long dc = mempool_field(&rt, txids[i], "descendantcount");
                if (dc != 1) {
                    printf("  FAIL: node %zu has %ld mempool descendants\n", i, dc - 1);
                    return 0;
                }
            }
        }
        /* the anchor slot is free: an anchor child is accepted on every
           unconfirmed node */
        for (size_t i = 0; i < f->n_nodes; i++) {
            if (mempool_field(&rt, txids[i], "vsize") < 0) continue;
            cpfp_tx_info_t ti;
            TEST_ASSERT(cpfp_parse_tx(f->nodes[i].signed_tx.data,
                                      f->nodes[i].signed_tx.len, &ti), "parse");
            if (ti.anchor_vout < 0) continue;
            tx_buf_t child;
            tx_buf_init(&child, 128);
            TEST_ASSERT(cpfp_build_anchor_child(NULL, &ti, 0, 1250, &child, NULL, NULL),
                        "anchor child");
            char *hex = malloc(child.len * 2 + 1);
            TEST_ASSERT(hex, "alloc");
            hex_encode(child.data, child.len, hex);
            char ctxid[65];
            int sent = regtest_send_raw_tx(&rt, hex, ctxid);
            free(hex);
            tx_buf_free(&child);
            TEST_ASSERT(sent, "CPFP child accepted on the unconfirmed node");
        }
        regtest_mine_blocks(&rt, 1, mine_addr);
        int nc = 0;
        for (size_t i = 0; i < f->n_nodes; i++)
            if (regtest_get_confirmations(&rt, txids[i]) >= 1) nc++;
        printf("  round %d: %d/%zu tree txs confirmed\n", round + 1, nc, f->n_nodes);
        all_confirmed = (nc == (int)f->n_nodes);
    }
    TEST_ASSERT(all_confirmed, "whole tree confirmed, one level per block");

    cpfp_set_default(NULL, NULL, NULL, 0);
    persist_close(&p);
    unlink(db_path);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- submitpackage: parent accepted, child rejected ------------------ */

/* An RPC wallet whose signature on the CPFP child no longer matches the
   child: after signing it takes one more sat of fee from the change. */
typedef struct {
    wallet_source_rpc_t rpc;     /* must be first */
    int (*inner_sign)(wallet_source_t *, unsigned char *, size_t *, size_t,
                      const unsigned char *, size_t, uint64_t);
} bad_sig_wallet_t;

static int bad_sig_sign(wallet_source_t *self, unsigned char *tx, size_t *len,
                        size_t idx, const unsigned char *spk, size_t spk_len,
                        uint64_t amount) {
    bad_sig_wallet_t *w = (bad_sig_wallet_t *)self;
    if (!w->inner_sign(self, tx, len, idx, spk, spk_len, amount)) return 0;
    /* version, segwit marker+flag, 1-byte input count, two empty-scriptSig
       inputs, 1-byte output count: the change amount starts at byte 90 */
    if (*len < 98 || tx[4] != 0 || tx[6] != 2 || tx[89] != 1) return 0;
    uint64_t v = 0;
    for (int k = 0; k < 8; k++) v |= (uint64_t)tx[90 + k] << (8 * k);
    v -= 1;
    for (int k = 0; k < 8; k++) tx[90 + k] = (unsigned char)(v >> (8 * k));
    return 1;
}

/* A parent that pays the relay floor but not the target goes as a package;
   when the node takes the parent and rejects the child, the parent is in the
   mempool and the result says so (it is not a failed broadcast). */
int test_regtest_cpfp_parent_accepted_child_rejected(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    TEST_ASSERT(regtest_init(&rt), "bitcoind");
    regtest_create_wallet(&rt, "cpfp_partial");
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)), "address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    regtest_mine_blocks(&rt, 1, mine_addr);

    factory_t *f = calloc(1, sizeof(factory_t));
    secp256k1_keypair kps[RT_N];
    char fund_txid[65];
    TEST_ASSERT(f && fund_tree(&rt, ctx, mine_addr, f, kps, 0, fund_txid), "factory");

    bad_sig_wallet_t w;
    memset(&w, 0, sizeof(w));
    wallet_source_rpc_init(&w.rpc, &rt);
    w.inner_sign = w.rpc.base.sign_input;
    w.rpc.base.sign_input = bad_sig_sign;

    const factory_node_t *root = &f->nodes[0];
    char *hex = malloc(root->signed_tx.len * 2 + 1);
    TEST_ASSERT(hex, "alloc");
    hex_encode(root->signed_tx.data, root->signed_tx.len, hex);
    char txid[65] = {0};
    /* 1250 sat/kvB pays min relay, not the 20000 target: package path */
    cpfp_result_t res = cpfp_send_presigned(&rt, &w.rpc.base, 20000, 0, hex, txid);
    printf("  result %d for %s\n", (int)res, txid);
    TEST_ASSERT(res == CPFP_PARENT_ONLY, "parent in, child out: CPFP_PARENT_ONLY");
    TEST_ASSERT(mempool_field(&rt, txid, "vsize") > 0, "parent is in the mempool");
    TEST_ASSERT(mempool_field(&rt, txid, "descendantcount") == 1, "without a child");

    /* the next broadcast, with a working wallet, bumps it in the mempool */
    wallet_source_rpc_t good;
    wallet_source_rpc_init(&good, &rt);
    res = cpfp_send_presigned(&rt, &good.base, 20000, 0, hex, txid);
    TEST_ASSERT(res == CPFP_BUMPED, "retry bumps the parent left without a child");
    TEST_ASSERT(mempool_field(&rt, txid, "descendantcount") == 2, "now with a child");

    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, txid) >= 1, "parent confirms");
    free(hex);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- re-bumping a pre-signed tx already in the mempool --------------- */

/* First txid in a mempool entry's spentby list (empty if none). */
static void first_child(regtest_t *rt, const char *txid, char out[65]) {
    out[0] = '\0';
    char params[80];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *r = regtest_exec(rt, "getmempoolentry", params);
    if (!r) return;
    cJSON *j = cJSON_Parse(r);
    free(r);
    cJSON *s = j ? cJSON_GetObjectItem(j, "spentby") : NULL;
    cJSON *c = (s && cJSON_GetArraySize(s) > 0) ? cJSON_GetArrayItem(s, 0) : NULL;
    if (c && cJSON_IsString(c) && strlen(c->valuestring) == 64)
        memcpy(out, c->valuestring, 65);
    cJSON_Delete(j);
}

/* Ancestor feerate (sat/kvB) of a mempool tx; 0 if not in the mempool. */
static uint64_t ancestor_rate(regtest_t *rt, const char *txid) {
    char params[80];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *r = regtest_exec(rt, "getmempoolentry", params);
    if (!r) return 0;
    cJSON *j = cJSON_Parse(r);
    free(r);
    cJSON *fees = j ? cJSON_GetObjectItem(j, "fees") : NULL;
    cJSON *af = fees ? cJSON_GetObjectItem(fees, "ancestor") : NULL;
    cJSON *as = j ? cJSON_GetObjectItem(j, "ancestorsize") : NULL;
    uint64_t rate = 0;
    if (af && as && as->valuedouble > 0)
        rate = (uint64_t)(af->valuedouble * 1e8 * 1000 / as->valuedouble);
    cJSON_Delete(j);
    return rate;
}

/* "txid:vout" of a mempool tx's input that is not parent's anchor. */
static void wallet_input_of(regtest_t *rt, const char *txid, char out[80]) {
    out[0] = '\0';
    char params[96];
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *r = regtest_exec(rt, "getrawtransaction", params);
    if (!r) return;
    cJSON *j = cJSON_Parse(r);
    free(r);
    cJSON *vin = j ? cJSON_GetObjectItem(j, "vin") : NULL;
    if (vin && cJSON_GetArraySize(vin) == 2) {
        cJSON *in = cJSON_GetArrayItem(vin, 1);
        cJSON *t = cJSON_GetObjectItem(in, "txid");
        cJSON *v = cJSON_GetObjectItem(in, "vout");
        if (t && v) snprintf(out, 80, "%s:%d", t->valuestring, (int)v->valuedouble);
    }
    cJSON_Delete(j);
}

/* A pre-signed tree tx sits in the mempool with a cheap anchor-only child a
   third party attached (P2A is anyone-can-spend), and then the fee estimate
   rises.  Every retry must raise the package to the current rate: the first
   outbids the third-party child, the next replaces our own child spending
   the same wallet coin, a retry at a rate already met changes nothing, the
   fee budget is respected, and the package confirms. */
int test_regtest_cpfp_rebump_in_mempool(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    TEST_ASSERT(regtest_init(&rt), "bitcoind");
    regtest_create_wallet(&rt, "cpfp_bump");
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)), "address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    regtest_mine_blocks(&rt, 1, mine_addr);

    factory_t *f = calloc(1, sizeof(factory_t));
    secp256k1_keypair kps[RT_N];
    char fund_txid[65];
    TEST_ASSERT(f && fund_tree(&rt, ctx, mine_addr, f, kps, 0, fund_txid), "factory");
    const factory_node_t *root = &f->nodes[0];
    char *hex = malloc(root->signed_tx.len * 2 + 1);
    TEST_ASSERT(hex, "alloc");
    hex_encode(root->signed_tx.data, root->signed_tx.len, hex);
    cpfp_tx_info_t ti;
    TEST_ASSERT(cpfp_parse_tx(root->signed_tx.data, root->signed_tx.len, &ti), "parse");

    /* The griefer: parent + a 240-sat anchor-only child, as a package. */
    tx_buf_t g;
    tx_buf_init(&g, 128);
    TEST_ASSERT(cpfp_build_anchor_child(NULL, &ti, 0, 1250, &g, NULL, NULL), "griefer child");
    char *ghex = malloc(g.len * 2 + 1);
    TEST_ASSERT(ghex, "alloc");
    hex_encode(g.data, g.len, ghex);
    cpfp_tx_info_t gi;
    TEST_ASSERT(cpfp_parse_tx(g.data, g.len, &gi), "parse griefer");
    tx_buf_free(&g);
    size_t plen = strlen(hex) + strlen(ghex) + 16;
    char *params = malloc(plen);
    TEST_ASSERT(params, "alloc");
    snprintf(params, plen, "[\"%s\",\"%s\"]", hex, ghex);
    char *r = regtest_exec(&rt, "submitpackage", params);
    free(params);
    free(ghex);
    TEST_ASSERT(r && strstr(r, "\"success\""), "griefer package accepted");
    free(r);
    TEST_ASSERT(mempool_field(&rt, gi.txid_hex, "vsize") > 0, "griefer child in");
    uint64_t r0 = ancestor_rate(&rt, gi.txid_hex);
    printf("  griefed package at %llu sat/kvB\n", (unsigned long long)r0);

    wallet_source_rpc_t w;
    wallet_source_rpc_init(&w, &rt);
    fee_estimator_static_t est;
    char txid[65], c1[65], c2[65], c3[65], in1[80], in2[80];

    /* 1. estimate rises to 20 sat/vB: our retry outbids the griefer */
    fee_estimator_static_init(&est, 20000);
    cpfp_set_default(&rt, &w.base, &est.base, 0);
    cpfp_result_t res = cpfp_send_default(NULL, hex, txid);
    TEST_ASSERT(res == CPFP_BUMPED, "retry bumps the in-mempool parent");
    TEST_ASSERT(mempool_field(&rt, gi.txid_hex, "vsize") < 0, "griefer child evicted");
    first_child(&rt, txid, c1);
    TEST_ASSERT(c1[0] && mempool_field(&rt, txid, "descendantcount") == 2, "one child");
    uint64_t r1 = ancestor_rate(&rt, c1);
    printf("  after retry 1: package %llu sat/kvB\n", (unsigned long long)r1);
    TEST_ASSERT(r1 >= 20000, "package at the new estimate");
    wallet_input_of(&rt, c1, in1);
    TEST_ASSERT(in1[0], "wallet-funded child");

    /* 2. estimate rises again: our own child is replaced, same coin */
    fee_estimator_static_init(&est, 60000);
    res = cpfp_send_default(NULL, hex, txid);
    TEST_ASSERT(res == CPFP_BUMPED, "second retry bumps again");
    first_child(&rt, txid, c2);
    TEST_ASSERT(c2[0] && strcmp(c1, c2) != 0, "a new child");
    TEST_ASSERT(mempool_field(&rt, c1, "vsize") < 0, "our previous child replaced");
    uint64_t r2 = ancestor_rate(&rt, c2);
    printf("  after retry 2: package %llu sat/kvB\n", (unsigned long long)r2);
    TEST_ASSERT(r2 >= 60000, "package at the higher estimate");
    wallet_input_of(&rt, c2, in2);
    TEST_ASSERT(strcmp(in1, in2) == 0, "the replacement spends the same wallet coin");

    /* 3. a retry at a rate already met leaves the package alone */
    res = cpfp_send_default(NULL, hex, txid);
    TEST_ASSERT(res == CPFP_KNOWN, "nothing to do");
    first_child(&rt, txid, c3);
    TEST_ASSERT(strcmp(c2, c3) == 0, "child unchanged");

    /* 4. the fee budget bounds the child: 1000 sat/vB is out of reach */
    fee_estimator_static_init(&est, 1000000);
    cpfp_set_default(&rt, &w.base, &est.base, 5000);
    res = cpfp_send_default(NULL, hex, txid);
    TEST_ASSERT(res == CPFP_BUMP_FAILED, "no bump beyond the budget, reported as such");
    first_child(&rt, txid, c3);
    TEST_ASSERT(strcmp(c2, c3) == 0, "child unchanged");

    /* 5. it confirms */
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, txid) >= 1, "parent confirmed");
    TEST_ASSERT(regtest_get_confirmations(&rt, c2) >= 1, "our child confirmed");

    cpfp_set_default(NULL, NULL, NULL, 0);
    free(hex);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- watchtower escalator on a response that went out as a package ---- */

/* A tree root is in the mempool at the rate it was signed at and the
   watchtower tracks it for fee bumping, with no value at stake recorded: its
   budget is the configured ceiling per bump (not half the 240-sat anchor).
   The escalator raises the package with a child on the anchor; the next
   escalation replaces that child, never adding a second one on the same
   anchor (which the node rejects as a failed RBF, every cycle); a bump the
   budget cannot pay is not recorded as a broadcast. */
int test_regtest_wt_escalator_replaces_own_child(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    TEST_ASSERT(regtest_init(&rt), "bitcoind");
    regtest_create_wallet(&rt, "cpfp_wt");
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)), "address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    regtest_mine_blocks(&rt, 1, mine_addr);

    factory_t *f = calloc(1, sizeof(factory_t));
    secp256k1_keypair kps[RT_N];
    char fund_txid[65];
    TEST_ASSERT(f && fund_tree(&rt, ctx, mine_addr, f, kps, 0, fund_txid), "factory");
    const factory_node_t *root = &f->nodes[0];
    char *hex = malloc(root->signed_tx.len * 2 + 1);
    TEST_ASSERT(hex, "alloc");
    hex_encode(root->signed_tx.data, root->signed_tx.len, hex);
    cpfp_tx_info_t ti;
    TEST_ASSERT(cpfp_parse_tx(root->signed_tx.data, root->signed_tx.len, &ti), "parse");

    static watchtower_t wt;
    fee_estimator_static_t est;
    fee_estimator_static_init(&est, 20000);
    TEST_ASSERT(watchtower_init(&wt, 1, &rt, &est.base, NULL), "watchtower");

    /* the root relays alone at its signed rate (1.25 sat/vB) */
    char txid[65], c0[65], c1[65];
    cpfp_result_t res = cpfp_send_presigned(&rt, wt.wallet, 0, 0, hex, txid);
    TEST_ASSERT(res == CPFP_SENT_ALONE, "root in the mempool on its own");
    TEST_ASSERT(watchtower_add_pending_tx(&wt, txid, (uint32_t)ti.anchor_vout,
                                          ti.anchor_amount, 0), "track it");

    /* 1. first escalation: 20 sat/vB, within the ceiling budget */
    watchtower_check(&wt);
    TEST_ASSERT(wt.n_pending == 1, "still pending");
    printf("  escalation budget: %llu sat\n",
           (unsigned long long)wt.pending[0].fee_bump.budget_sat);
    TEST_ASSERT(wt.pending[0].fee_bump.budget_sat == wt.max_bump_fee_sat,
                "budget = the configured ceiling");
    first_child(&rt, txid, c0);
    TEST_ASSERT(c0[0], "a child on the root's anchor");
    uint64_t r0 = ancestor_rate(&rt, c0);
    printf("  escalated package: %llu sat/kvB\n", (unsigned long long)r0);
    TEST_ASSERT(r0 >= 20000, "package at the scheduled rate");
    TEST_ASSERT(wt.pending[0].fee_bump.last_feerate == 20000, "escalation recorded");

    /* a re-run at the rate the package already pays changes nothing */
    wt.pending[0].fee_bump.last_feerate = 0;
    watchtower_check(&wt);
    first_child(&rt, txid, c1);
    TEST_ASSERT(strcmp(c0, c1) == 0, "child unchanged");
    TEST_ASSERT(wt.pending[0].fee_bump.last_feerate == 20000, "met rate recorded");

    /* 2. the schedule reaches 60 sat/vB: our child is replaced */
    wt.pending[0].fee_bump.start_feerate = 60000;
    wt.pending[0].fee_bump.last_feerate = 0;
    watchtower_check(&wt);
    first_child(&rt, txid, c1);
    TEST_ASSERT(c1[0] && strcmp(c0, c1) != 0, "a replacement child");
    TEST_ASSERT(mempool_field(&rt, c0, "vsize") < 0, "the first child is gone");
    TEST_ASSERT(mempool_field(&rt, txid, "descendantcount") == 2, "still one child");
    uint64_t r1 = ancestor_rate(&rt, c1);
    printf("  escalated package: %llu sat/kvB\n", (unsigned long long)r1);
    TEST_ASSERT(r1 >= 60000, "package at the escalated rate");
    TEST_ASSERT(wt.pending[0].fee_bump.last_feerate == 60000, "escalation recorded");

    /* a bump beyond the budget fails and is not recorded as a broadcast */
    uint64_t saved_budget = wt.pending[0].fee_bump.budget_sat;
    wt.pending[0].fee_bump.budget_sat = 2000;
    wt.pending[0].fee_bump.start_feerate = 200000;
    wt.pending[0].fee_bump.last_feerate = 0;
    watchtower_check(&wt);
    first_child(&rt, txid, c0);
    TEST_ASSERT(strcmp(c0, c1) == 0, "child unchanged");
    TEST_ASSERT(wt.pending[0].fee_bump.last_feerate == 0, "failed bump not recorded");
    wt.pending[0].fee_bump.budget_sat = saved_budget;

    /* 3. it confirms and leaves the pending list */
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, txid) >= 1, "confirmed");
    watchtower_check(&wt);
    TEST_ASSERT(wt.n_pending == 0, "no longer pending");

    watchtower_cleanup(&wt);
    free(hex);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- outbidding a child funded from someone else's wallet ------------ */

/* A second wallet on the same node, holding n confirmed coins of btc each
   sent from rt's wallet. */
static int second_wallet(regtest_t *rt, const char *mine_addr, regtest_t *out,
                         const char *name, int n, double btc) {
    if (!regtest_init(out) || !regtest_create_wallet(out, name)) return 0;
    for (int i = 0; i < n; i++) {
        char addr[128], txid[65];
        if (!regtest_get_new_address(out, addr, sizeof(addr)) ||
            !regtest_fund_address(rt, addr, btc, txid)) return 0;
    }
    regtest_mine_blocks(rt, 1, mine_addr);
    return 1;
}

/* Hex string an RPC returns, either bare or as the field of an object;
   out empty on error. */
static void rpc_hex(regtest_t *rt, const char *method, const char *params,
                    const char *field, char *out, size_t cap) {
    out[0] = '\0';
    char *r = regtest_exec(rt, method, params);
    if (!r) return;
    if (field) {
        cJSON *j = cJSON_Parse(r);
        cJSON *v = j ? cJSON_GetObjectItem(j, field) : NULL;
        if (v && cJSON_IsString(v) && strlen(v->valuestring) < cap)
            strcpy(out, v->valuestring);
        cJSON_Delete(j);
    } else {
        const char *s = r;
        while (*s == '"' || *s == ' ' || *s == '\n') s++;
        size_t n = 0;
        while (n + 1 < cap && ((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f')))
            n++;
        if (n + 1 < cap && !strstr(r, "error")) { memcpy(out, s, n); out[n] = '\0'; }
    }
    free(r);
}

/* The anchor of a pre-signed tx in the mempool is spent by a child funded
   from a wallet other than ours: another party bumping the same tx from its
   own wallet, or a third party pinning it.  That child's coin is not ours,
   so the bump must not reuse it (the wallet cannot sign it and the node
   refuses the result): it outbids the child with a coin of our own, paying
   for the child and every descendant it has, and the package confirms.
   1. TRUC tree root: A sends it as a package at 20 sat/vB; B, with its own
      wallet, raises it to 60 sat/vB; A at a rate that is met changes
      nothing; A at 100 sat/vB outbids B's child.
   2. non-TRUC parent with an anchor: a third party's wallet-funded child
      and a grandchild spending its change; our bump evicts both. */
int test_regtest_cpfp_outbid_foreign_wallet_child(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    TEST_ASSERT(regtest_init(&rt), "bitcoind");
    regtest_create_wallet(&rt, "cpfp_two_a");
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)), "address");
    if (!regtest_fund_from_faucet(&rt, 2.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    regtest_mine_blocks(&rt, 1, mine_addr);
    regtest_t rt_b, rt_g;
    TEST_ASSERT(second_wallet(&rt, mine_addr, &rt_b, "cpfp_two_b", 2, 0.1), "wallet B");
    TEST_ASSERT(second_wallet(&rt, mine_addr, &rt_g, "cpfp_two_g", 2, 0.1), "wallet G");
    wallet_source_rpc_t wa, wb, wg;
    wallet_source_rpc_init(&wa, &rt);
    wallet_source_rpc_init(&wb, &rt_b);
    wallet_source_rpc_init(&wg, &rt_g);

    /* 1. two honest parties, two wallets, one TRUC tree root */
    factory_t *f = calloc(1, sizeof(factory_t));
    secp256k1_keypair kps[RT_N];
    char fund_txid[65];
    TEST_ASSERT(f && fund_tree(&rt, ctx, mine_addr, f, kps, 0, fund_txid), "factory");
    const factory_node_t *root = &f->nodes[0];
    char *hex = malloc(root->signed_tx.len * 2 + 1);
    TEST_ASSERT(hex, "alloc");
    hex_encode(root->signed_tx.data, root->signed_tx.len, hex);
    char txid[65], ca[65], cb[65], ca2[65], ina[80], inb[80], ina2[80];

    cpfp_result_t res = cpfp_send_presigned(&rt, &wa.base, 20000, 0, hex, txid);
    TEST_ASSERT(res == CPFP_SENT_PACKAGE, "A: root sent as a package");
    first_child(&rt, txid, ca);
    wallet_input_of(&rt, ca, ina);
    TEST_ASSERT(ina[0], "A's child is wallet-funded");
    printf("  A's package: %llu sat/kvB\n", (unsigned long long)ancestor_rate(&rt, ca));

    res = cpfp_send_presigned(&rt, &wb.base, 60000, 0, hex, txid);
    printf("  B's bump: result %d\n", (int)res);
    TEST_ASSERT(res == CPFP_BUMPED, "B raises the package A sent");
    first_child(&rt, txid, cb);
    TEST_ASSERT(cb[0] && strcmp(ca, cb) != 0, "B's child replaced A's");
    TEST_ASSERT(mempool_field(&rt, ca, "vsize") < 0, "A's child evicted");
    wallet_input_of(&rt, cb, inb);
    TEST_ASSERT(inb[0] && strcmp(ina, inb) != 0, "B's child spends a coin of B's");
    uint64_t rb = ancestor_rate(&rt, cb);
    printf("  B's package: %llu sat/kvB\n", (unsigned long long)rb);
    TEST_ASSERT(rb >= 60000, "package at B's rate");

    res = cpfp_send_presigned(&rt, &wa.base, 20000, 0, hex, txid);
    TEST_ASSERT(res == CPFP_KNOWN, "A: rate already met");
    first_child(&rt, txid, ca2);
    TEST_ASSERT(strcmp(ca2, cb) == 0, "B's child unchanged");

    res = cpfp_send_presigned(&rt, &wa.base, 100000, 0, hex, txid);
    TEST_ASSERT(res == CPFP_BUMPED, "A outbids B's child");
    first_child(&rt, txid, ca2);
    TEST_ASSERT(ca2[0] && strcmp(ca2, cb) != 0, "A's new child replaced B's");
    wallet_input_of(&rt, ca2, ina2);
    TEST_ASSERT(ina2[0] && strcmp(ina2, inb) != 0, "not spending B's coin");
    uint64_t ra = ancestor_rate(&rt, ca2);
    printf("  A's new package: %llu sat/kvB\n", (unsigned long long)ra);
    TEST_ASSERT(ra >= 100000, "package at A's new rate");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, txid) >= 1, "root confirmed");
    TEST_ASSERT(regtest_get_confirmations(&rt, ca2) >= 1, "A's child confirmed");
    free(hex);
    factory_free(f);
    free(f);

    /* 2. a non-TRUC parent with an anchor, at 1 sat/vB, from wallet A */
    char addr_a[128], params[2400], raw[1024], funded[2048], signed_p[2048];
    for (int i = 0; i < 2; i++) {     /* confirmed coins for our child */
        char t[65];
        TEST_ASSERT(regtest_get_new_address(&rt, addr_a, sizeof(addr_a)) &&
                    regtest_fund_address(&rt, addr_a, 0.05, t), "coin");
    }
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_new_address(&rt, addr_a, sizeof(addr_a)), "address");
    snprintf(params, sizeof(params),
             "[] [{\"bcrt1pfeesnyr2tx\":0.00000240},{\"%s\":0.001}]", addr_a);
    rpc_hex(&rt, "createrawtransaction", params, NULL, raw, sizeof(raw));
    TEST_ASSERT(raw[0], "createrawtransaction");
    snprintf(params, sizeof(params), "\"%s\" {\"fee_rate\":1}", raw);
    rpc_hex(&rt, "fundrawtransaction", params, "hex", funded, sizeof(funded));
    TEST_ASSERT(funded[0], "fundrawtransaction");
    snprintf(params, sizeof(params), "\"%s\"", funded);
    rpc_hex(&rt, "signrawtransactionwithwallet", params, "hex", signed_p, sizeof(signed_p));
    TEST_ASSERT(signed_p[0], "sign parent");
    char ptxid[65];
    TEST_ASSERT(regtest_send_raw_tx(&rt, signed_p, ptxid), "parent in the mempool");

    /* the third party attaches a wallet-funded child (package 2 sat/vB) */
    res = cpfp_send_presigned(&rt, &wg.base, 2000, 0, signed_p, NULL);
    TEST_ASSERT(res == CPFP_BUMPED, "third-party child attached");
    char cg[65], gdesc[65];
    first_child(&rt, ptxid, cg);
    TEST_ASSERT(cg[0], "third-party child in the mempool");
    /* ... and spends its change in a grandchild */
    char gaddr[128], graw[1024], gsigned[1024];
    TEST_ASSERT(regtest_get_new_address(&rt_g, gaddr, sizeof(gaddr)), "address");
    uint64_t cval = 0;
    unsigned char cspk[64];
    size_t cspk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(&rt, cg, 0, &cval, cspk, &cspk_len) && cval > 2000,
                "child change");
    snprintf(params, sizeof(params),
             "[{\"txid\":\"%s\",\"vout\":0}] [{\"%s\":%.8f}]", cg, gaddr,
             (double)(cval - 300) / 1e8);
    rpc_hex(&rt_g, "createrawtransaction", params, NULL, graw, sizeof(graw));
    TEST_ASSERT(graw[0], "createrawtransaction");
    snprintf(params, sizeof(params), "\"%s\"", graw);
    rpc_hex(&rt_g, "signrawtransactionwithwallet", params, "hex", gsigned, sizeof(gsigned));
    TEST_ASSERT(gsigned[0] && regtest_send_raw_tx(&rt_g, gsigned, gdesc), "grandchild");
    TEST_ASSERT(mempool_field(&rt, cg, "descendantcount") == 2, "child has a descendant");

    res = cpfp_send_presigned(&rt, &wa.base, 30000, 0, signed_p, NULL);
    printf("  our bump: result %d\n", (int)res);
    TEST_ASSERT(res == CPFP_BUMPED, "our bump outbids the third-party child");
    char cn[65];
    first_child(&rt, ptxid, cn);
    TEST_ASSERT(cn[0] && strcmp(cn, cg) != 0, "our child on the anchor");
    TEST_ASSERT(mempool_field(&rt, cg, "vsize") < 0, "third-party child evicted");
    TEST_ASSERT(mempool_field(&rt, gdesc, "vsize") < 0, "its descendant evicted");
    uint64_t rn = ancestor_rate(&rt, cn);
    printf("  non-TRUC package after the bump: %llu sat/kvB\n", (unsigned long long)rn);
    TEST_ASSERT(rn >= 30000, "package at our rate");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, ptxid) >= 1, "parent confirmed");
    TEST_ASSERT(regtest_get_confirmations(&rt, cn) >= 1, "our child confirmed");

    secp256k1_context_destroy(ctx);
    return 1;
}
