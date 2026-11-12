/* Fees of every pre-signed factory transaction, and the CPFP child builder
   used to broadcast them.

   The pre-signed rate is a factory term (tree_fee_rate, default 100 sat/kvB,
   0 allowed): every tree node, chain advance and the distribution TX pays
   exactly that rate for its real vsize, measured from the transaction bytes
   independently of the sizing model, and carries one P2A anchor last (0
   sat at rate 0, else 240). */


#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/channel.h"
#include "superscalar/fee.h"
#include "superscalar/cpfp.h"
#include "superscalar/client.h"
#include "superscalar/lsp.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

/* Shape of a test factory. */
typedef struct {
    const char *name;
    int arity;              /* 1, 2 or 3 (PS); 0 = level arities below */
    uint8_t levels[3];
    size_t n_levels;
    uint32_t ps_k;          /* PS sub-factory arity (0/1 = none) */
    uint32_t static_depth;
} shape_t;

static int make_factory(secp256k1_context *ctx, factory_t *f, secp256k1_keypair *kps,
                        size_t n_clients, const shape_t *sh, uint64_t rate,
                        uint64_t funding) {
    size_t n = n_clients + 1;
    secp256k1_pubkey *pks = calloc(n, sizeof(*pks));
    if (!pks) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32];
        memset(sk, 0, 32);
        sk[30] = (unsigned char)(i >> 8);
        sk[31] = (unsigned char)(i + 1);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk) ||
            !secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) { free(pks); return 0; }
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) { free(pks); return 0; }
    free(pks);
    unsigned char ser[32], tweak[32], spk[34];
    secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey);
    sha256_tagged("TapTweak", ser, 32, tweak);
    secp256k1_pubkey tw;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw, &ka.cache, tweak)) return 0;
    secp256k1_xonly_pubkey twx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &twx, NULL, &tw);
    build_p2tr_script_pubkey(spk, &twx);

    unsigned char txid[32];
    memset(txid, 0x5A, 32);
    if (!factory_init(f, ctx, kps, n, 4, 4)) return 0;
    if (sh->n_levels > 0)
        factory_set_level_arity(f, sh->levels, sh->n_levels);
    else if (sh->arity == 1)
        factory_set_arity(f, FACTORY_ARITY_1);
    else if (sh->arity == 3)
        factory_set_arity(f, FACTORY_ARITY_PS);
    if (sh->static_depth > 0)
        factory_set_static_near_root(f, sh->static_depth);
    if (sh->ps_k > 1)
        factory_set_ps_subfactory_arity(f, sh->ps_k);
    f->use_tree_anchor = 1;
    f->cltv_timeout = 500;
    f->tree_fee_rate = rate;
    factory_set_funding(f, txid, 0, funding, spk, 34);
    return 1;
}


/* Count a node's P2TR and P2A outputs. */
static void count_outputs(const factory_node_t *node, size_t *p2tr, size_t *p2a) {
    *p2tr = *p2a = 0;
    for (size_t k = 0; k < node->n_outputs; k++) {
        if (node->outputs[k].script_pubkey_len == P2A_SPK_LEN) (*p2a)++;
        else (*p2tr)++;
    }
}

/* ceil(rate x vsize / 1000), computed here independently of src/fee.c. */
static uint64_t ref_fee(uint64_t rate, size_t vsize) {
    return (uint64_t)(((unsigned __int128)rate * vsize + 999) / 1000);
}

/* Every node: input == outputs + fee, fee == the agreed rate for the model
   vsize, the anchor (when present) last and worth 240 sat (0 at rate 0);
   for signed trees, the model vsize is the real one and the tx is TRUC. */
static int check_all_nodes(const factory_t *f, int signed_txs, const char *label,
                           int expect_anchor) {
    uint64_t want_anchor = f->tree_fee_rate == 0 ? 0 : ANCHOR_OUTPUT_AMOUNT;
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];
        size_t p2tr, p2a;
        count_outputs(node, &p2tr, &p2a);
        uint64_t out = 0;
        for (size_t k = 0; k < node->n_outputs; k++) out += node->outputs[k].amount_sats;
        uint64_t in = node->parent_index < 0 ? f->funding_amount_sats
            : f->nodes[node->parent_index].outputs[node->parent_vout].amount_sats;
        size_t model = fee_keypath_tx_vsize(1, p2tr, p2a);
        if (in != out + node->fee_sats || node->fee_sats != ref_fee(f->tree_fee_rate, model)) {
            printf("  FAIL: %s node %zu: in %llu, out %llu, fee %llu, want %llu (%zu vB)\n",
                   label, i, (unsigned long long)in, (unsigned long long)out,
                   (unsigned long long)node->fee_sats,
                   (unsigned long long)ref_fee(f->tree_fee_rate, model), model);
            return 0;
        }
        if (p2a > 1 || (expect_anchor && p2a != 1)) {
            printf("  FAIL: %s node %zu: %zu P2A outputs\n", label, i, p2a);
            return 0;
        }
        if (p2a == 1 && (node->outputs[node->n_outputs - 1].script_pubkey_len != P2A_SPK_LEN ||
                         node->outputs[node->n_outputs - 1].amount_sats != want_anchor)) {
            printf("  FAIL: %s node %zu: anchor not last or not %llu sat\n", label, i,
                   (unsigned long long)want_anchor);
            return 0;
        }
        if (signed_txs) {
            cpfp_tx_info_t ti;
            if (!node->is_signed ||
                !cpfp_parse_tx(node->signed_tx.data, node->signed_tx.len, &ti) ||
                ti.vsize != model || ti.version != FACTORY_TREE_TX_VERSION) {
                printf("  FAIL: %s node %zu: signed tx (vsize / version)\n", label, i);
                return 0;
            }
        }
    }
    return 1;
}

/* Every node pays exactly the agreed rate for its exact size, across shapes,
   client counts and rates (0 included: no fee, a 0-value anchor). */
int test_tree_fee_every_node_exact_rate(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const shape_t shapes[] = {
        { "arity1", 1, {0}, 0, 0, 0 },
        { "arity2", 2, {0}, 0, 0, 0 },
        { "ps",     3, {0}, 0, 0, 0 },
        { "arity2+static1", 2, {0}, 0, 0, 1 },
        { "mixed{2,4}", 0, {2, 4}, 2, 0, 0 },
    };
    static const size_t clients[] = { 2, 4, 5, 8, 16, 64 };
    static const uint64_t rates[] = { 0, 100, 1000, 50000 };
    int n_built = 0;
    for (size_t si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
        for (size_t ci = 0; ci < sizeof(clients) / sizeof(clients[0]); ci++) {
            for (size_t ri = 0; ri < sizeof(rates) / sizeof(rates[0]); ri++) {
                size_t nc = clients[ci];
                if (shapes[si].static_depth > 0 && nc < 8) continue;
                secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
                factory_t *f = calloc(1, sizeof(factory_t));
                TEST_ASSERT(kps && f, "alloc");
                TEST_ASSERT(make_factory(ctx, f, kps, nc, &shapes[si], rates[ri],
                                         100000000), "init");
                char label[96];
                snprintf(label, sizeof(label), "%s n=%zu rate=%llu", shapes[si].name,
                         nc, (unsigned long long)rates[ri]);
                if (!factory_build_tree(f)) {
                    printf("  FAIL: %s: build_tree\n", label);
                    return 0;
                }
                TEST_ASSERT_EQ(f->tree_fee_rate, rates[ri], "the agreed rate is kept");
                int do_sign = nc <= 8 && (ri == 0 || ri == 1);
                if (do_sign) TEST_ASSERT(factory_sign_all(f), "sign_all");
                /* n-way leaves and sub-factories carry no anchor */
                int anchorless = 0;
                for (size_t ni = 0; ni < f->n_nodes; ni++) {
                    size_t p2tr, p2a;
                    count_outputs(&f->nodes[ni], &p2tr, &p2a);
                    if (p2a == 0) anchorless = 1;
                }
                if (!check_all_nodes(f, do_sign, label, 0)) return 0;
                char why[200];
                int ok = factory_check_tree_fees(f, why, sizeof(why));
                if (anchorless && rates[ri] == 0) {
                    /* a node without an anchor cannot get a fee at rate 0 */
                    TEST_ASSERT(!ok, "anchorless n-way leaf refused at rate 0");
                } else if (!ok) {
                    printf("  FAIL: %s: %s\n", label, why);
                    return 0;
                }
                n_built++;
                factory_free(f);
                free(f);
                free(kps);
            }
        }
    }
    printf("  %d tree shapes checked\n", n_built);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The 4-client arity-2 leaf (3 P2TR + P2A, 210 vB): 21 sat at the default
   0.1 sat/vB, nothing at rate 0 with a 0-value anchor. */
int test_tree_fee_arity2_leaf_210vb(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    static const uint64_t rates[] = { FACTORY_DEFAULT_TREE_FEE_RATE, 0 };
    static const uint64_t fees[] = { 21, 0 };
    static const uint64_t anchors[] = { ANCHOR_OUTPUT_AMOUNT, 0 };
    for (int r = 0; r < 2; r++) {
        secp256k1_keypair kps[5];
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, rates[r], 200000), "init");
        TEST_ASSERT(factory_build_tree(f), "build");
        TEST_ASSERT(factory_sign_all(f), "sign");
        size_t leaf = f->leaf_node_indices[0];
        cpfp_tx_info_t ti;
        TEST_ASSERT(cpfp_parse_tx(f->nodes[leaf].signed_tx.data,
                                  f->nodes[leaf].signed_tx.len, &ti), "parse");
        TEST_ASSERT_EQ(ti.vsize, 210, "3 P2TR + P2A leaf = 210 vB");
        TEST_ASSERT_EQ(ti.anchor_vout, 3, "anchor last");
        TEST_ASSERT_EQ(ti.anchor_amount, anchors[r], "anchor value follows the rate");
        TEST_ASSERT_EQ(f->nodes[leaf].fee_sats, fees[r], "exact fee");
        factory_free(f);
        free(f);
    }
    TEST_ASSERT_EQ(FACTORY_DEFAULT_TREE_FEE_RATE, 100, "default 0.1 sat/vB");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* PS chain advances carry the anchor and pay the agreed rate for their size;
   a sub-factory multi-input advance pays for every input. */
int test_tree_fee_ps_chains(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const uint64_t rates[] = { 0, 100, 3000 };
    for (int r = 0; r < 3; r++) {
        shape_t sh = { "ps", 3, {0}, 0, 0, 0 };
        secp256k1_keypair kps[5];
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, rates[r], 1000000), "init");
        TEST_ASSERT(factory_build_tree(f), "build");
        TEST_ASSERT(factory_sign_all(f), "sign");
        size_t li = f->leaf_node_indices[0];
        factory_node_t *leaf = &f->nodes[li];
        for (int adv = 1; adv <= 3; adv++) {
            uint64_t before = leaf->outputs[0].amount_sats;
            TEST_ASSERT(factory_advance_leaf(f, 0), "advance");
            TEST_ASSERT_EQ(leaf->n_outputs, 2, "channel + anchor");
            TEST_ASSERT_EQ(leaf->outputs[1].script_pubkey_len, P2A_SPK_LEN, "anchor");
            TEST_ASSERT_EQ(before - leaf->outputs[0].amount_sats,
                           factory_ps_chain_reserve(f), "reserve = fee + anchor");
            cpfp_tx_info_t ti;
            TEST_ASSERT(cpfp_parse_tx(leaf->signed_tx.data, leaf->signed_tx.len, &ti),
                        "parse");
            TEST_ASSERT_EQ(ti.vsize, fee_keypath_tx_vsize(1, 1, 1), "chain tx vsize");
            TEST_ASSERT_EQ(leaf->fee_sats, ref_fee(rates[r], ti.vsize), "chain fee");
            TEST_ASSERT_EQ(ti.anchor_amount, rates[r] ? ANCHOR_OUTPUT_AMOUNT : 0,
                           "anchor value");
            TEST_ASSERT_EQ(ti.version, FACTORY_TREE_TX_VERSION, "TRUC");
        }
        char why[200];
        TEST_ASSERT(factory_check_tree_fees(f, why, sizeof(why)), why);
        factory_free(f);
        free(f);
    }

    /* k=2 sub-factories: the chain advance spends all k+1 outputs. */
    shape_t sh2 = { "ps-k2", 3, {0}, 0, 2, 0 };
    secp256k1_keypair kps2[9];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps2, 8, &sh2, 1000, 2000000), "init k2");
    TEST_ASSERT(factory_build_tree(f), "build k2");
    TEST_ASSERT(check_all_nodes(f, 0, "ps-k2", 0), "k2 nodes");
    TEST_ASSERT(factory_subfactory_chain_advance_unsigned(f, 0, 0, 0, 10000), "sub advance");
    factory_node_t *sub = &f->nodes[f->nodes[f->leaf_node_indices[0]].subfactory_node_indices[0]];
    size_t vs = fee_keypath_tx_vsize(sub->ps_n_prev_outputs, sub->n_outputs, 0);
    TEST_ASSERT_EQ(sub->ps_n_prev_outputs, 3, "3 inputs");
    TEST_ASSERT_EQ(sub->fee_sats, ref_fee(1000, vs), "multi-input advance pays every input");
    char why[200];
    TEST_ASSERT(factory_check_tree_fees(f, why, sizeof(why)), why);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- distribution TX ------------------------------------------------- */

/* A client's channel capacity: its channel output in its leaf. */
static uint64_t chan_capacity(const factory_t *f, size_t ci) {
    size_t node = 0;
    uint32_t vout = 0;
    if (!factory_client_to_leaf(f, ci, &node, &vout) ||
        vout >= f->nodes[node].n_outputs) return 0;
    return f->nodes[node].outputs[vout].amount_sats;
}

/* Client payouts of a built distribution TX (its outputs but the anchor). */
static int dist_payouts(const factory_t *f, uint64_t *pay, size_t n) {
    const unsigned char *d = f->dist_unsigned_tx.data;
    size_t pos = 4 + 1 + 41;
    size_t nout = d[pos];
    pos += (nout < 0xfd) ? 1 : 3;
    if (nout >= 0xfd) nout = (size_t)d[pos - 2] | ((size_t)d[pos - 1] << 8);
    if (nout != n + 1) return 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= (uint64_t)d[pos + b] << (8 * b);
        pay[i] = v;
        pos += 8;
        size_t sl = d[pos];
        pos += 1 + sl;
    }
    return 1;
}

/* Distribution TX: nVersion 3 at every client count up to
   FACTORY_MAX_DIST_CLIENTS, exactly the agreed rate for its size, the
   anchor by the rate, every client paid at least its full channel capacity;
   one more client is refused. */
int test_tree_fee_distribution_tx(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(factory_distribution_tx_vsize(FACTORY_MAX_DIST_CLIENTS) <= TRUC_MAX_VSIZE,
                "the largest allowed distribution TX fits TRUC");
    TEST_ASSERT(factory_distribution_tx_vsize(FACTORY_MAX_DIST_CLIENTS + 1) > TRUC_MAX_VSIZE,
                "one more client does not");
    static const size_t clients[] = { 2, 4, 64, FACTORY_MAX_DIST_CLIENTS };
    static const uint64_t rates[] = { 0, 100, 2000 };
    for (size_t ci = 0; ci < sizeof(clients) / sizeof(clients[0]); ci++) {
        for (size_t ri = 0; ri < 3; ri++) {
            size_t nc = clients[ci];
            if (nc == FACTORY_MAX_DIST_CLIENTS && ri == 2) continue;
            shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
            secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
            factory_t *f = calloc(1, sizeof(factory_t));
            TEST_ASSERT(kps && f, "alloc");
            TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, rates[ri], 100000000), "init");
            TEST_ASSERT(factory_build_tree(f), "build");
            tx_output_t *outs = calloc(nc + 1, sizeof(tx_output_t));
            uint64_t fee = factory_distribution_fee(f, nc);
            size_t n = factory_compute_distribution_outputs(f, outs, nc + 1, fee);
            TEST_ASSERT_EQ(n, nc, "one output per client");
            TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500), "build dist");
            size_t vs = (4 * f->dist_unsigned_tx.len + 2 + FEE_KEYPATH_WITNESS_BYTES + 3) / 4;
            TEST_ASSERT_EQ(vs, factory_distribution_tx_vsize(nc), "dist vsize model");
            TEST_ASSERT_EQ(fee, ref_fee(rates[ri], vs), "exact fee");
            TEST_ASSERT_EQ(f->dist_unsigned_tx.data[0], 3, "TRUC at every size");
            char why[200];
            TEST_ASSERT(factory_check_tree_fees(f, why, sizeof(why)), why);
            uint64_t *pay = calloc(nc, sizeof(uint64_t));
            TEST_ASSERT(pay && dist_payouts(f, pay, nc), "parse");
            for (size_t i = 0; i < nc; i++)
                TEST_ASSERT(pay[i] >= chan_capacity(f, i), "at least the channel capacity");
            free(pay);
            free(outs);
            factory_free(f);
            free(f);
            free(kps);
        }
    }
    /* 231 and 255 clients: refused */
    static const size_t too_many[] = { FACTORY_MAX_DIST_CLIENTS + 1, 250 };
    for (size_t k = 0; k < 2; k++) {
        size_t nc = too_many[k];
        shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
        secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(kps && f, "alloc");
        TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, 100, 100000000), "init");
        TEST_ASSERT(factory_build_tree(f), "build");
        tx_output_t *outs = calloc(nc + 1, sizeof(tx_output_t));
        TEST_ASSERT_EQ(factory_compute_distribution_outputs(f, outs, nc + 1,
                           factory_distribution_fee(f, nc)), 0, "outputs refused");
        for (size_t i = 0; i < nc; i++) {
            outs[i].amount_sats = 1000;
            outs[i].script_pubkey[0] = 0x51; outs[i].script_pubkey[1] = 0x20;
            outs[i].script_pubkey_len = 34;
        }
        TEST_ASSERT(!factory_build_distribution_tx_unsigned(f, outs, nc, 500),
                    "distribution TX refused");
        free(outs);
        factory_free(f);
        free(f);
        free(kps);
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The distribution TX pays every client at least its full channel capacity;
   its fee and anchor come out of what is left above the capacities (the
   LSP's share), never out of one client.  Amounts that leave no room for
   them are refused, never scaled down. */
int test_distribution_fee_from_lsp_share(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    const size_t nc = 8;
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(kps && f, "alloc");
    TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, 1000, 4000000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    uint64_t fee = factory_distribution_fee(f, nc);
    uint64_t anchor = factory_tree_anchor_sats(f);
    tx_output_t outs[16];
    uint64_t cap[16], caps = 0, pay[16];
    for (size_t i = 0; i < nc; i++) { cap[i] = chan_capacity(f, i); caps += cap[i]; }
    size_t n = factory_compute_distribution_outputs_balanced(f, outs, 16, fee, cap, nc);
    TEST_ASSERT_EQ(n, nc, "balanced outputs");
    TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500), "build balanced");
    TEST_ASSERT(dist_payouts(f, pay, nc), "parse balanced");
    uint64_t sum = 0;
    for (size_t i = 0; i < nc; i++) {
        TEST_ASSERT(pay[i] >= cap[i], "at least the amount asked");
        sum += pay[i];
    }
    TEST_ASSERT_EQ(sum + anchor + fee, f->funding_amount_sats, "funding = payouts + anchor + fee");
    uint64_t over[16];
    uint64_t room = f->funding_amount_sats - caps;
    for (size_t i = 0; i < nc; i++) over[i] = cap[i];
    over[0] += room - fee - anchor + 1;
    TEST_ASSERT_EQ(factory_compute_distribution_outputs_balanced(f, outs, 16, fee, over, nc),
                   0, "one sat short of fee + anchor: refused, not scaled down");
    over[0] -= 1;
    TEST_ASSERT_EQ(factory_compute_distribution_outputs_balanced(f, outs, 16, fee, over, nc),
                   nc, "exactly enough: built");
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A node paying anything but the agreed rate, or carrying the wrong anchor
   value, is refused by the check every member runs before signing. */
int test_tree_fee_checker_rejects_wrong_fee(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    char why[200];
    static const int64_t deltas[] = { +1, -1, +500 };
    for (int d = 0; d < 3; d++) {
        secp256k1_keypair kps[5];
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 100, 200000), "init");
        TEST_ASSERT(factory_build_tree(f), "build");
        TEST_ASSERT(factory_check_tree_fees(f, why, sizeof(why)), "ok as built");
        size_t li = f->leaf_node_indices[0];
        factory_node_t *leaf = &f->nodes[li];
        /* move sats between a channel output and the fee, then re-serialize */
        leaf->outputs[0].amount_sats = (uint64_t)((int64_t)leaf->outputs[0].amount_sats -
                                                  deltas[d]);
        TEST_ASSERT(factory_rebuild_path_unsigned(f, (int)li), "rebuild");
        TEST_ASSERT(!factory_check_tree_fees(f, why, sizeof(why)), "refused");
        TEST_ASSERT(strstr(why, "pays") != NULL, why);
        factory_free(f);
        free(f);
    }
    /* a 0-value anchor at a non-zero rate */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 100, 200000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    size_t li = f->leaf_node_indices[0];
    factory_node_t *leaf = &f->nodes[li];
    leaf->outputs[0].amount_sats += leaf->outputs[leaf->n_outputs - 1].amount_sats;
    leaf->outputs[leaf->n_outputs - 1].amount_sats = 0;
    TEST_ASSERT(factory_rebuild_path_unsigned(f, (int)li), "rebuild");
    TEST_ASSERT(!factory_check_tree_fees(f, why, sizeof(why)), "wrong anchor refused");
    TEST_ASSERT(strstr(why, "anchor") != NULL, why);
    /* a different rate than proposed */
    f->tree_fee_rate = 200;
    TEST_ASSERT(!factory_check_tree_fees(f, why, sizeof(why)), "other rate refused");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Member policy: its own ceiling, nothing to match with the LSP; 0 is a
   valid rate. */
int test_tree_fee_client_policy(void) {
    client_set_max_tree_fee_rate(CLIENT_DEFAULT_MAX_TREE_FEE_RATE);
    TEST_ASSERT(client_tree_fee_rate_acceptable(0), "rate 0 accepted");
    TEST_ASSERT(client_tree_fee_rate_acceptable(FACTORY_DEFAULT_TREE_FEE_RATE), "default");
    TEST_ASSERT(client_tree_fee_rate_acceptable(CLIENT_DEFAULT_MAX_TREE_FEE_RATE), "ceiling");
    TEST_ASSERT(!client_tree_fee_rate_acceptable(CLIENT_DEFAULT_MAX_TREE_FEE_RATE + 1),
                "above the ceiling refused");
    client_set_max_tree_fee_rate(500);
    TEST_ASSERT(!client_tree_fee_rate_acceptable(501), "own lower ceiling");
    client_set_max_tree_fee_rate(0);
    TEST_ASSERT(client_tree_fee_rate_acceptable(10000000), "no ceiling");
    client_set_max_tree_fee_rate(CLIENT_DEFAULT_MAX_TREE_FEE_RATE);
    return 1;
}

/* The commitment fee: one function, the agreed rate for the exact size
   (167 vB with no HTLC, +43 per HTLC/PTLC output). */
int test_commitment_fee_exact_vsize(void) {
    TEST_ASSERT_EQ(fee_commitment_tx_vsize(0), 167, "to_local + to_remote + anchor");
    TEST_ASSERT_EQ(fee_commitment_tx_vsize(1), 210, "one HTLC output");
    TEST_ASSERT_EQ(fee_commitment_tx_at(100, 0), 17, "0.1 sat/vB");
    TEST_ASSERT_EQ(fee_commitment_tx_at(0, 0), 0, "rate 0");
    TEST_ASSERT_EQ(fee_commitment_tx_at(1000, 2), 253, "1 sat/vB, 2 HTLCs");
    TEST_ASSERT(fee_commitment_tx_vsize(channel_max_commit_htlc_outputs()) <=
                CHANNEL_MAX_COMMIT_VSIZE, "the cap fits");
    TEST_ASSERT(fee_commitment_tx_vsize(channel_max_commit_htlc_outputs() + 1) >
                CHANNEL_MAX_COMMIT_VSIZE, "one more does not");
    TEST_ASSERT_EQ(channel_max_commit_htlc_outputs(), 228, "228 outputs");
    return 1;
}

/* ---- CPFP child builder --------------------------------------------- */

/* Mock wallet: one UTXO, a P2WPKH-sized fake witness. */
typedef struct {
    wallet_source_t base;
    uint64_t utxo_amount;
    int released;
    int signed_idx;
} mock_wallet_t;

static int mock_get_utxo(wallet_source_t *self, uint64_t min_sats, char txid_hex[65],
                         uint32_t *vout, uint64_t *amount, unsigned char *spk,
                         size_t *spk_len) {
    mock_wallet_t *m = (mock_wallet_t *)self;
    if (m->utxo_amount < min_sats) return 0;
    memset(txid_hex, 'b', 64);
    txid_hex[64] = '\0';
    *vout = 7;
    *amount = m->utxo_amount;
    spk[0] = 0x00; spk[1] = 0x14; memset(spk + 2, 0x44, 20);
    *spk_len = 22;
    return 1;
}
static int mock_change(wallet_source_t *self, unsigned char *spk, size_t *spk_len) {
    (void)self;
    spk[0] = 0x51; spk[1] = 0x20; memset(spk + 2, 0x66, 32);
    *spk_len = 34;
    return 1;
}
/* Re-serialize as segwit with an empty witness for input 0 and a 107-byte
   P2WPKH-shaped witness for input 1. */
static int mock_sign(wallet_source_t *self, unsigned char *tx, size_t *tx_len,
                     size_t input_idx, const unsigned char *spk, size_t spk_len,
                     uint64_t amount) {
    (void)spk; (void)spk_len; (void)amount;
    mock_wallet_t *m = (mock_wallet_t *)self;
    m->signed_idx = (int)input_idx;
    size_t len = *tx_len;
    unsigned char *o = malloc(len + 200);
    if (!o) return 0;
    size_t p = 0;
    memcpy(o, tx, 4); p = 4;
    o[p++] = 0x00; o[p++] = 0x01;
    memcpy(o + p, tx + 4, len - 8); p += len - 8;
    o[p++] = 0x00;                         /* input 0: no witness */
    o[p++] = 0x02; o[p++] = 71; memset(o + p, 0x30, 71); p += 71;
    o[p++] = 33; memset(o + p, 0x02, 33); p += 33;
    memcpy(o + p, tx + len - 4, 4); p += 4;
    memcpy(tx, o, p);
    *tx_len = p;
    free(o);
    return 1;
}
static void mock_release(wallet_source_t *self, const char *t, uint32_t v) {
    (void)t; (void)v;
    ((mock_wallet_t *)self)->released++;
}

static int make_parent(secp256k1_context *ctx, factory_t *f, secp256k1_keypair *kps,
                       uint64_t rate, cpfp_tx_info_t *pi, size_t *leaf_out) {
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    if (!make_factory(ctx, f, kps, 4, &sh, rate, 200000)) return 0;
    if (!factory_build_tree(f) || !factory_sign_all(f)) return 0;
    *leaf_out = f->leaf_node_indices[0];
    const factory_node_t *n = &f->nodes[*leaf_out];
    return cpfp_parse_tx(n->signed_tx.data, n->signed_tx.len, pi);
}

int test_cpfp_parse_and_fee_math(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    cpfp_tx_info_t pi;
    size_t li;
    TEST_ASSERT(make_parent(ctx, f, kps, 100, &pi, &li), "parent");
    TEST_ASSERT(memcmp(pi.txid, f->nodes[li].txid, 32) == 0, "txid matches the node");
    TEST_ASSERT_EQ(pi.version, 3, "TRUC parent");
    TEST_ASSERT_EQ(pi.anchor_vout, 3, "anchor vout");
    TEST_ASSERT_EQ(pi.anchor_amount, ANCHOR_OUTPUT_AMOUNT, "anchor amount");
    TEST_ASSERT_EQ(pi.n_inputs, 1, "one input");
    /* (21 + c) / (210 + 150) >= 5 sat/vB  ->  c = 1800 - 21 = 1779 */
    TEST_ASSERT_EQ(cpfp_child_fee(21, 210, 150, 5000), 1779, "package math");
    TEST_ASSERT_EQ(cpfp_child_fee(5000, 210, 150, 5000), 750, "child pays its own size");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Anchor-only child: the 240-sat anchor pays for it; a 0-value anchor (rate
   0) cannot, so none is built. */
int test_cpfp_anchor_only_child(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    cpfp_tx_info_t pi;
    size_t li;
    TEST_ASSERT(make_parent(ctx, f, kps, 100, &pi, &li), "parent");
    tx_buf_t child;
    tx_buf_init(&child, 128);
    uint64_t cfee = 0;
    int used = 1;
    TEST_ASSERT(cpfp_build_anchor_child(NULL, &pi, 21, 1000, &child, &cfee, &used),
                "anchor-only child");
    TEST_ASSERT_EQ(used, 0, "no wallet");
    TEST_ASSERT_EQ(cfee, ANCHOR_OUTPUT_AMOUNT, "pays the anchor value");
    cpfp_tx_info_t ci;
    TEST_ASSERT(cpfp_parse_tx(child.data, child.len, &ci), "parse child");
    TEST_ASSERT_EQ(ci.vsize, CPFP_ANCHOR_ONLY_CHILD_VSIZE, "65 vB");
    TEST_ASSERT_EQ(ci.version, 3, "TRUC child of a TRUC parent");
    TEST_ASSERT_EQ(ci.in_vout[0], 3, "the anchor vout");
    tx_buf_free(&child);
    factory_free(f);
    free(f);

    f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_parent(ctx, f, kps, 0, &pi, &li), "rate-0 parent");
    TEST_ASSERT_EQ(pi.anchor_amount, 0, "0-value anchor");
    tx_buf_init(&child, 128);
    TEST_ASSERT(!cpfp_build_anchor_child(NULL, &pi, 0, 1000, &child, NULL, NULL),
                "no anchor-only child on a 0-value anchor");
    tx_buf_free(&child);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_cpfp_wallet_child_reaches_package_rate(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const uint64_t parent_rates[] = { 100, 0 };
    for (int pr = 0; pr < 2; pr++) {
        secp256k1_keypair kps[5];
        factory_t *f = calloc(1, sizeof(factory_t));
        cpfp_tx_info_t pi;
        size_t li;
        TEST_ASSERT(make_parent(ctx, f, kps, parent_rates[pr], &pi, &li), "parent");
        uint64_t pfee = f->nodes[li].fee_sats;
        mock_wallet_t w;
        memset(&w, 0, sizeof(w));
        w.base.type = WALLET_SOURCE_NONE;
        w.base.get_utxo = mock_get_utxo;
        w.base.get_change_spk = mock_change;
        w.base.sign_input = mock_sign;
        w.base.release_utxo = mock_release;
        w.utxo_amount = 100000;
        w.signed_idx = -1;
        static const uint64_t rates[] = { 100, 2000, 100000 };
        for (size_t ri = 0; ri < 3; ri++) {
            tx_buf_t child;
            tx_buf_init(&child, 256);
            uint64_t cfee = 0;
            int used = 0;
            TEST_ASSERT(cpfp_build_anchor_child(&w.base, &pi, pfee, rates[ri], &child,
                                                &cfee, &used), "wallet child");
            TEST_ASSERT_EQ(used, 1, "wallet used");
            TEST_ASSERT_EQ(w.signed_idx, 1, "wallet signs input 1");
            cpfp_tx_info_t ci;
            TEST_ASSERT(cpfp_parse_tx(child.data, child.len, &ci), "parse");
            TEST_ASSERT_EQ(ci.n_inputs, 2, "anchor + wallet input");
            TEST_ASSERT(ci.vsize <= 1000, "within the TRUC child limit");
            TEST_ASSERT_EQ(ci.out_total, w.utxo_amount + pi.anchor_amount - cfee, "change");
            uint64_t pkg_fee = pfee + cfee;
            TEST_ASSERT(pkg_fee >= fee_at_rate(rates[ri], pi.vsize + ci.vsize),
                        "package reaches the target rate");
            tx_buf_free(&child);
        }
        factory_free(f);
        free(f);
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A pre-signed exit tx that needs a fee-paying child it cannot get is
   reported with the reason, never as a quiet failure. */
extern void hex_encode(const unsigned char *data, size_t len, char *out);
static int need_send_ok;
static int need_send(chain_backend_t *self, const char *hex, char *txid_out) {
    (void)self; (void)hex;
    if (txid_out) { memset(txid_out, '0', 64); txid_out[64] = '\0'; }
    return need_send_ok;
}
int test_cpfp_exit_needs_child_reported(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    cpfp_tx_info_t pi;
    size_t li;
    TEST_ASSERT(f && make_parent(ctx, f, kps, 100, &pi, &li), "parent");
    const factory_node_t *n = &f->nodes[li];
    char *hex = malloc(n->signed_tx.len * 2 + 1);
    TEST_ASSERT(hex, "alloc");
    hex_encode(n->signed_tx.data, n->signed_tx.len, hex);

    /* The anchor alone: 21 + 240 sat for 210 + 65 vB = 950 sat/kvB. */
    TEST_ASSERT(!cpfp_anchor_alone_short(21, 210, 240, 100), "enough at 0.1 sat/vB");
    TEST_ASSERT(!cpfp_anchor_alone_short(21, 210, 240, 949), "enough just below");
    TEST_ASSERT(cpfp_anchor_alone_short(21, 210, 240, 1000), "short at 1 sat/vB");
    TEST_ASSERT(cpfp_anchor_alone_short(0, 210, 0, 100), "a 0-value anchor never pays");

    chain_backend_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.send_raw_tx = need_send;
    cpfp_set_default(NULL, NULL, NULL, 0);
    cpfp_need_clear();
    need_send_ok = 1;
    char txid[65];
    TEST_ASSERT(cpfp_send_default(&cb, hex, txid) == CPFP_SENT_ALONE, "accepted alone");
    TEST_ASSERT_EQ(cpfp_need_seen(), CPFP_NEED_NONE, "nothing needed");
    need_send_ok = 0;
    TEST_ASSERT(cpfp_send_default(&cb, hex, txid) == CPFP_FAILED, "refused");
    TEST_ASSERT_EQ(cpfp_need_seen(), CPFP_NEED_PACKAGE_RELAY,
                   "refused with an anchor and no package relay: reported");
    TEST_ASSERT(strstr(cpfp_need_text(CPFP_NEED_COIN), "--wallet") != NULL,
                "coin text names --wallet");
    cpfp_need_clear();
    free(hex);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A fee no transaction can pay is a failure, never a capped or wrapped
   number. */
int test_tree_fee_overflow_fails(void) {
    TEST_ASSERT(fee_at_rate(UINT64_MAX / 2, 1000) == FEE_INVALID, "overflowing product");
    TEST_ASSERT(fee_at_rate(UINT64_MAX, 1) == FEE_INVALID, "huge rate");
    TEST_ASSERT(fee_at_rate(3000000000000ULL, 1000000) == FEE_INVALID,
                "fee above the money supply");
    TEST_ASSERT(fee_at_rate(1000000000000ULL, 1000000) == 1000000000000000ULL,
                "1e15 sat is still a number");
    TEST_ASSERT_EQ(fee_at_rate(0, 210), 0, "rate 0, no fee");
    /* past the old 1 BTC cap the fee is exact */
    size_t vs = factory_distribution_tx_vsize(64);
    TEST_ASSERT_EQ(fee_at_rate(36000, vs), ref_fee(36000, vs), "exact past the old cap");
    TEST_ASSERT(cpfp_child_fee(0, 210, 150, UINT64_MAX) == FEE_INVALID,
                "child fee propagates the failure");
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, UINT64_MAX / 4, 200000000), "init");
    TEST_ASSERT(!factory_build_tree(f), "no tree at an unpayable rate");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}
