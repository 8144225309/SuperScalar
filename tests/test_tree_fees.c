/* Fee sizing of every pre-signed factory transaction, and the CPFP child
   builder used to broadcast them.

   Each tree node must pay fee_presigned(tree_fee_rate, its real vsize), the
   P2A anchor included, and so never less than the minimum relay feerate.
   The real vsize is measured from the signed transaction bytes, independently
   of the sizing model. */

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

/* Every node: fee recorded == input - outputs, == fee_presigned(rate, model
   vsize), and >= min relay for the vsize measured from the signed tx. */
static int check_all_nodes(const factory_t *f, int signed_txs, const char *label,
                           int expect_anchor) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];
        size_t p2tr, p2a;
        count_outputs(node, &p2tr, &p2a);
        uint64_t out = 0;
        for (size_t k = 0; k < node->n_outputs; k++) out += node->outputs[k].amount_sats;
        uint64_t in = node->parent_index < 0 ? f->funding_amount_sats
            : f->nodes[node->parent_index].outputs[node->parent_vout].amount_sats;
        if (in != out + node->fee_sats) {
            printf("  FAIL: %s node %zu: in %llu != out %llu + fee %llu\n", label, i,
                   (unsigned long long)in, (unsigned long long)out,
                   (unsigned long long)node->fee_sats);
            return 0;
        }
        size_t model = fee_keypath_tx_vsize(1, p2tr, p2a);
        if (node->fee_sats != fee_presigned(f->tree_fee_rate, model)) {
            printf("  FAIL: %s node %zu: fee %llu != presigned(%llu, %zu)\n", label, i,
                   (unsigned long long)node->fee_sats,
                   (unsigned long long)f->tree_fee_rate, model);
            return 0;
        }
        if (p2a > 1 || (expect_anchor && p2a != 1)) {
            printf("  FAIL: %s node %zu has no P2A anchor\n", label, i);
            return 0;
        }
        if (signed_txs) {
            cpfp_tx_info_t ti;
            if (!node->is_signed ||
                !cpfp_parse_tx(node->signed_tx.data, node->signed_tx.len, &ti)) {
                printf("  FAIL: %s node %zu: signed tx unparsable\n", label, i);
                return 0;
            }
            if (ti.vsize != model) {
                printf("  FAIL: %s node %zu: real vsize %zu != model %zu\n",
                       label, i, ti.vsize, model);
                return 0;
            }
            if (node->fee_sats < fee_at_rate(FEE_MIN_RELAY_SAT_PER_KVB, ti.vsize)) {
                printf("  FAIL: %s node %zu: fee %llu below min relay for %zu vB\n",
                       label, i, (unsigned long long)node->fee_sats, ti.vsize);
                return 0;
            }
            if (ti.version != FACTORY_TREE_TX_VERSION) {
                printf("  FAIL: %s node %zu: version %u\n", label, i, ti.version);
                return 0;
            }
            if (p2a == 1 && ti.anchor_vout != (int)node->n_outputs - 1) {
                printf("  FAIL: %s node %zu: anchor not last\n", label, i);
                return 0;
            }
        }
    }
    if (!factory_check_tree_fees(f, FEE_PRESIGNED_FLOOR_SAT_PER_KVB, NULL)) {
        printf("  FAIL: %s: factory_check_tree_fees rejected the tree\n", label);
        return 0;
    }
    return 1;
}

/* Tree node fees across arities, client counts and rates. */
int test_tree_fee_every_node_pays_relay(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const shape_t shapes[] = {
        { "arity1", 1, {0}, 0, 0, 0 },
        { "arity2", 2, {0}, 0, 0, 0 },
        { "ps",     3, {0}, 0, 0, 0 },
        { "mixed{2,4}", 0, {2, 4}, 2, 0, 0 },
        { "mixed{2,4,8}+static1", 0, {2, 4, 8}, 3, 0, 1 },
    };
    static const size_t clients[] = { 2, 4, 5, 8, 16 };
    static const uint64_t rates[] = { 0, 1000, 5000, 50000 };
    int n_built = 0;
    for (size_t si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
        for (size_t ci = 0; ci < sizeof(clients) / sizeof(clients[0]); ci++) {
            for (size_t ri = 0; ri < sizeof(rates) / sizeof(rates[0]); ri++) {
                size_t nc = clients[ci];
                if (shapes[si].n_levels == 3 && nc < 8) continue;
                secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
                factory_t *f = calloc(1, sizeof(factory_t));
                TEST_ASSERT(kps && f, "alloc");
                TEST_ASSERT(make_factory(ctx, f, kps, nc, &shapes[si], rates[ri],
                                         20000000), "init");
                char label[96];
                snprintf(label, sizeof(label), "%s n=%zu rate=%llu", shapes[si].name,
                         nc, (unsigned long long)rates[ri]);
                if (!factory_build_tree(f)) {
                    printf("  FAIL: %s: build_tree\n", label);
                    return 0;
                }
                uint64_t want = rates[ri] < FEE_PRESIGNED_FLOOR_SAT_PER_KVB
                                ? FEE_PRESIGNED_FLOOR_SAT_PER_KVB : rates[ri];
                TEST_ASSERT_EQ(f->tree_fee_rate, want, "rate written back, floored");
                /* Sign the small trees to measure real vsizes. */
                int do_sign = nc <= 8 && (ri == 0 || ri == 3);
                if (do_sign) TEST_ASSERT(factory_sign_all(f), "sign_all");
                if (!check_all_nodes(f, do_sign, label, shapes[si].n_levels == 0)) return 0;
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

/* 64-client trees whose top levels are static kickoffs (no DW state): the
   static root of such a tree, with several P2TR outputs and the anchor, was
   pre-signed with the flat 200 sat whatever its size (213 vB seen).  Every
   node, the root included, pays its own vsize at the tree rate. */
int test_tree_fee_static_root_64_clients(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const shape_t shapes[] = {
        { "arity2+static1", 2, {0}, 0, 0, 1 },
        { "arity2+static2", 2, {0}, 0, 0, 2 },
        { "ps+static1",     3, {0}, 0, 0, 1 },
        { "ps+static2",     3, {0}, 0, 0, 2 },
        { "arity1+static1", 1, {0}, 0, 0, 1 },
        { "mixed{2,4,8}+static1", 0, {2, 4, 8}, 3, 0, 1 },
        { "mixed{4,4,4}+static1", 0, {4, 4, 4}, 3, 0, 1 },
    };
    static const uint64_t rates[] = { 0, 1000, 2000 };
    for (size_t si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
        for (size_t ri = 0; ri < sizeof(rates) / sizeof(rates[0]); ri++) {
            const size_t nc = 64;
            secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
            factory_t *f = calloc(1, sizeof(factory_t));
            TEST_ASSERT(kps && f, "alloc");
            TEST_ASSERT(make_factory(ctx, f, kps, nc, &shapes[si], rates[ri],
                                     100000000), "init");
            char label[96];
            snprintf(label, sizeof(label), "%s n=64 rate=%llu", shapes[si].name,
                     (unsigned long long)rates[ri]);
            if (!factory_build_tree(f)) {
                printf("  FAIL: %s: build_tree\n", label);
                return 0;
            }
            TEST_ASSERT(f->n_nodes > 0 && f->nodes[0].parent_index < 0, "root first");
            size_t p2tr, p2a;
            count_outputs(&f->nodes[0], &p2tr, &p2a);
            size_t vs = fee_keypath_tx_vsize(1, p2tr, p2a);
            TEST_ASSERT(f->nodes[0].fee_sats >= fee_at_rate(FEE_MIN_RELAY_SAT_PER_KVB, vs),
                        "root pays the minimum relay fee for its size");
            if (ri == 0)
                printf("  %s: root %zu P2TR + %zu P2A, %zu vB, fee %llu sat\n",
                       label, p2tr, p2a, vs, (unsigned long long)f->nodes[0].fee_sats);
            if (!check_all_nodes(f, 0, label, shapes[si].n_levels == 0)) return 0;
            factory_free(f);
            free(f);
            free(kps);
        }
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The 4-client arity-2 leaf that used to pay 200 sat for 210 vB. */
int test_tree_fee_arity2_leaf_210vb(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 0, 200000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_sign_all(f), "sign");
    size_t leaf = f->leaf_node_indices[0];
    cpfp_tx_info_t ti;
    TEST_ASSERT(cpfp_parse_tx(f->nodes[leaf].signed_tx.data,
                              f->nodes[leaf].signed_tx.len, &ti), "parse");
    TEST_ASSERT_EQ(ti.vsize, 210, "3 P2TR + P2A leaf = 210 vB");
    TEST_ASSERT_EQ(ti.n_outputs, 4, "4 outputs");
    TEST_ASSERT_EQ(ti.anchor_vout, 3, "anchor last");
    TEST_ASSERT_EQ(f->nodes[leaf].fee_sats, 263, "ceil(1.25 x 210)");
    TEST_ASSERT(f->nodes[leaf].fee_sats >= 210, "meets 1 sat/vB");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* PS chain advances carry an anchor and pay for their real size; sub-factory
   multi-input advances pay for every input. */
int test_tree_fee_ps_chains(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "ps", 3, {0}, 0, 0, 0 };
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 3000, 1000000), "init");
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
        TEST_ASSERT(cpfp_parse_tx(leaf->signed_tx.data, leaf->signed_tx.len, &ti), "parse");
        TEST_ASSERT_EQ(ti.vsize, fee_keypath_tx_vsize(1, 1, 1), "chain tx vsize");
        TEST_ASSERT_EQ(leaf->fee_sats, fee_presigned(3000, ti.vsize), "chain fee");
        TEST_ASSERT_EQ(ti.version, FACTORY_TREE_TX_VERSION, "TRUC");
    }
    TEST_ASSERT(factory_check_tree_fees(f, FEE_PRESIGNED_FLOOR_SAT_PER_KVB, NULL),
                "tree check after advances");
    factory_free(f);
    free(f);

    /* k=2 sub-factories: chain advance spends all k+1 outputs. */
    shape_t sh2 = { "ps-k2", 3, {0}, 0, 2, 0 };
    secp256k1_keypair kps2[9];
    f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps2, 8, &sh2, 0, 2000000), "init k2");
    TEST_ASSERT(factory_build_tree(f), "build k2");
    TEST_ASSERT(check_all_nodes(f, 0, "ps-k2", 0), "k2 nodes");
    TEST_ASSERT(factory_subfactory_chain_advance_unsigned(f, 0, 0, 0, 10000), "sub advance");
    factory_node_t *sub = &f->nodes[f->nodes[f->leaf_node_indices[0]].subfactory_node_indices[0]];
    size_t vs = fee_keypath_tx_vsize(sub->ps_n_prev_outputs, sub->n_outputs, 0);
    TEST_ASSERT_EQ(sub->ps_n_prev_outputs, 3, "3 inputs");
    TEST_ASSERT_EQ(sub->fee_sats, fee_presigned(FEE_PRESIGNED_FLOOR_SAT_PER_KVB, vs),
                   "multi-input advance pays for every input");
    TEST_ASSERT(sub->fee_sats >= 312, "k=2 advance pays >= 1 sat/vB of 312 vB");
    TEST_ASSERT(factory_check_tree_fees(f, FEE_PRESIGNED_FLOOR_SAT_PER_KVB, NULL),
                "tree check after sub advance");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Distribution TX: fee from the real size at every client count; TRUC while
   it fits the TRUC size limit. */
int test_tree_fee_distribution_tx(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const size_t clients[] = { 2, 4, 8, 16, 64 };
    for (size_t ci = 0; ci < sizeof(clients) / sizeof(clients[0]); ci++) {
        size_t nc = clients[ci];
        shape_t sh = { "arity1", 1, {0}, 0, 0, 0 };
        secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, 0, 10000000), "init");
        TEST_ASSERT(factory_build_tree(f), "build");
        tx_output_t *outs = calloc(nc + 1, sizeof(tx_output_t));
        uint64_t fee = factory_distribution_fee(f, nc);
        size_t n = factory_compute_distribution_outputs(f, outs, nc + 1, fee);
        TEST_ASSERT_EQ(n, nc, "one output per client");
        TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500), "build dist");
        /* unsigned bytes + one 64-byte key-path witness */
        size_t vs = (4 * f->dist_unsigned_tx.len + 2 + FEE_KEYPATH_WITNESS_BYTES + 3) / 4;
        TEST_ASSERT_EQ(vs, fee_keypath_tx_vsize(1, nc, 1), "dist vsize model");
        uint64_t out = 0;
        for (size_t i = 0; i < n; i++) out += outs[i].amount_sats;
        TEST_ASSERT_EQ(f->funding_amount_sats - out, fee, "fee = funding - outputs");
        TEST_ASSERT(fee >= fee_at_rate(FEE_MIN_RELAY_SAT_PER_KVB, vs), "dist meets relay");
        TEST_ASSERT_EQ(f->dist_unsigned_tx.data[0], 3, "TRUC dist");
        TEST_ASSERT_EQ(f->dist_unsigned_tx.data[f->dist_unsigned_tx.len - 4 - 13 + 8 + 1], 0x51,
                       "P2A anchor last");
        free(outs);
        factory_free(f);
        free(f);
        free(kps);
    }
    TEST_ASSERT_EQ(factory_distribution_tx_version(200), 3, "200 clients fit TRUC");
    TEST_ASSERT_EQ(factory_distribution_tx_version(255), 2, "255 clients exceed 10 kvB");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Poison tx fee is raised to the floor for wide leaves. */
int test_tree_fee_poison_floor(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "wide", 0, {15}, 1, 0, 0 };
    secp256k1_keypair kps[16];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 15, &sh, 3000, 10000000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    size_t li = f->leaf_node_indices[0];
    factory_node_t *leaf = &f->nodes[li];
    TEST_ASSERT_EQ(leaf->n_signers, 16, "15-client leaf");
    tx_buf_t ptx;
    tx_buf_init(&ptx, 512);
    unsigned char sh32[32], ptxid[32], ltxid[32];
    memset(ltxid, 0x33, 32);
    uint64_t l_amount = 100000;
    TEST_ASSERT(factory_build_l_stock_poison_tx_unsigned(f, leaf, ltxid, 15, l_amount,
                                                        1000, &ptx, sh32, ptxid),
                "build poison");
    cpfp_tx_info_t ti;
    TEST_ASSERT(cpfp_parse_tx(ptx.data, ptx.len, &ti), "parse");
    size_t vs = fee_keypath_tx_vsize(1, 15, 0);
    uint64_t fee = l_amount - ti.out_total;
    TEST_ASSERT_EQ((4 * ptx.len + 2 + FEE_KEYPATH_WITNESS_BYTES + 3) / 4, vs, "size model");
    TEST_ASSERT(fee_presigned(3000, vs) > 1000, "the flat 1000 would underpay at 3 sat/vB");
    TEST_ASSERT_EQ(fee, fee_presigned(3000, vs), "fee raised to the tree rate");
    TEST_ASSERT(fee >= vs, "meets 1 sat/vB");
    tx_buf_free(&ptx);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A flat 200-sat tree is caught by the checker. */
int test_tree_fee_checker_rejects_underpaying_node(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 0, 200000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_check_tree_fees(f, FEE_MIN_RELAY_SAT_PER_KVB, NULL), "ok as built");
    /* Shift fee into the first leaf output so it pays 200 for 210 vB. */
    size_t li = f->leaf_node_indices[0];
    factory_node_t *leaf = &f->nodes[li];
    leaf->outputs[0].amount_sats += leaf->fee_sats - 200;
    size_t bad = 9999;
    TEST_ASSERT(!factory_check_tree_fees(f, FEE_MIN_RELAY_SAT_PER_KVB, &bad), "rejected");
    TEST_ASSERT_EQ(bad, li, "the leaf is reported");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Client signing policy on the proposed tree fee rate. */
int test_tree_fee_client_policy(void) {
    client_set_max_tree_fee_rate(CLIENT_DEFAULT_MAX_TREE_FEE_RATE);
    TEST_ASSERT(!client_tree_fee_rate_acceptable(200), "below floor refused");
    TEST_ASSERT(!client_tree_fee_rate_acceptable(1000), "min relay without margin refused");
    TEST_ASSERT(client_tree_fee_rate_acceptable(FEE_PRESIGNED_FLOOR_SAT_PER_KVB), "floor ok");
    TEST_ASSERT(client_tree_fee_rate_acceptable(CLIENT_DEFAULT_MAX_TREE_FEE_RATE), "max ok");
    TEST_ASSERT(!client_tree_fee_rate_acceptable(CLIENT_DEFAULT_MAX_TREE_FEE_RATE + 1),
                "above ceiling refused");
    client_set_max_tree_fee_rate(0);
    TEST_ASSERT(client_tree_fee_rate_acceptable(10000000), "no ceiling");
    TEST_ASSERT(!client_tree_fee_rate_acceptable(0), "floor still applies");
    client_set_max_tree_fee_rate(CLIENT_DEFAULT_MAX_TREE_FEE_RATE);
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
                       cpfp_tx_info_t *pi, size_t *leaf_out) {
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    if (!make_factory(ctx, f, kps, 4, &sh, 0, 200000)) return 0;
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
    TEST_ASSERT(make_parent(ctx, f, kps, &pi, &li), "parent");
    TEST_ASSERT(memcmp(pi.txid, f->nodes[li].txid, 32) == 0, "txid matches the node");
    TEST_ASSERT_EQ(pi.version, 3, "TRUC parent");
    TEST_ASSERT_EQ(pi.anchor_vout, 3, "anchor vout");
    TEST_ASSERT_EQ(pi.anchor_amount, ANCHOR_OUTPUT_AMOUNT, "anchor amount");
    TEST_ASSERT_EQ(pi.n_inputs, 1, "one input");
    TEST_ASSERT(memcmp(pi.in_txid[0], f->nodes[f->nodes[li].parent_index].txid, 32) == 0,
                "spends its parent");

    /* (263 + c) / (210 + 150) >= 5 sat/vB  ->  c = 1800 - 263 = 1537 */
    TEST_ASSERT_EQ(cpfp_child_fee(263, 210, 150, 5000), 1537, "package math");
    TEST_ASSERT_EQ(cpfp_child_fee(5000, 210, 150, 5000), 750, "child pays its own size");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_cpfp_anchor_only_child(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    cpfp_tx_info_t pi;
    size_t li;
    TEST_ASSERT(make_parent(ctx, f, kps, &pi, &li), "parent");
    tx_buf_t child;
    tx_buf_init(&child, 128);
    uint64_t cfee = 0;
    int used = 1;
    TEST_ASSERT(cpfp_build_anchor_child(NULL, &pi, 263, 5000, &child, &cfee, &used),
                "anchor-only child");
    TEST_ASSERT_EQ(used, 0, "no wallet");
    TEST_ASSERT_EQ(cfee, ANCHOR_OUTPUT_AMOUNT, "pays the anchor value");
    cpfp_tx_info_t ci;
    TEST_ASSERT(cpfp_parse_tx(child.data, child.len, &ci), "parse child");
    TEST_ASSERT_EQ(ci.vsize, CPFP_ANCHOR_ONLY_CHILD_VSIZE, "65 vB, the minimum standard size");
    TEST_ASSERT_EQ(child.len, 65, "non-witness serialization");
    TEST_ASSERT_EQ(ci.version, 3, "TRUC child of a TRUC parent");
    TEST_ASSERT_EQ(ci.n_inputs, 1, "anchor only");
    TEST_ASSERT(memcmp(ci.in_txid[0], pi.txid, 32) == 0, "spends the parent");
    TEST_ASSERT_EQ(ci.in_vout[0], 3, "the anchor vout");
    TEST_ASSERT_EQ(ci.out_total, 0, "OP_RETURN, value 0");
    tx_buf_free(&child);

    /* No anchor: nothing to build. */
    cpfp_tx_info_t noanchor = pi;
    noanchor.anchor_vout = -1;
    tx_buf_init(&child, 128);
    TEST_ASSERT(!cpfp_build_anchor_child(NULL, &noanchor, 263, 5000, &child, NULL, NULL),
                "refuses a parent without an anchor");
    tx_buf_free(&child);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_cpfp_wallet_child_reaches_package_rate(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    cpfp_tx_info_t pi;
    size_t li;
    TEST_ASSERT(make_parent(ctx, f, kps, &pi, &li), "parent");
    mock_wallet_t w;
    memset(&w, 0, sizeof(w));
    w.base.type = WALLET_SOURCE_NONE;
    w.base.get_utxo = mock_get_utxo;
    w.base.get_change_spk = mock_change;
    w.base.sign_input = mock_sign;
    w.base.release_utxo = mock_release;
    w.utxo_amount = 100000;
    w.signed_idx = -1;

    static const uint64_t rates[] = { 2000, 10000, 100000 };
    for (size_t ri = 0; ri < 3; ri++) {
        tx_buf_t child;
        tx_buf_init(&child, 256);
        uint64_t cfee = 0;
        int used = 0;
        TEST_ASSERT(cpfp_build_anchor_child(&w.base, &pi, 263, rates[ri], &child,
                                            &cfee, &used), "wallet child");
        TEST_ASSERT_EQ(used, 1, "wallet used");
        TEST_ASSERT_EQ(w.signed_idx, 1, "wallet signs input 1");
        cpfp_tx_info_t ci;
        TEST_ASSERT(cpfp_parse_tx(child.data, child.len, &ci), "parse");
        TEST_ASSERT_EQ(ci.n_inputs, 2, "anchor + wallet input");
        TEST_ASSERT_EQ(ci.in_vout[0], 3, "input 0 is the anchor");
        TEST_ASSERT_EQ(ci.version, 3, "TRUC child");
        TEST_ASSERT(ci.vsize <= 1000, "within the TRUC child limit");
        TEST_ASSERT_EQ(ci.out_total, w.utxo_amount + ANCHOR_OUTPUT_AMOUNT - cfee, "change");
        uint64_t pkg_fee = 263 + cfee;
        TEST_ASSERT(pkg_fee >= fee_at_rate(rates[ri], pi.vsize + ci.vsize),
                    "package reaches the target rate");
        TEST_ASSERT(pkg_fee <= fee_at_rate(rates[ri], pi.vsize + ci.vsize) + 2,
                    "and does not overshoot");
        tx_buf_free(&child);
    }
    TEST_ASSERT_EQ(w.released, 3, "UTXO released every time");

    /* Wallet too poor: falls back to the anchor alone. */
    w.utxo_amount = 100;
    tx_buf_t child;
    tx_buf_init(&child, 128);
    int used = 1;
    TEST_ASSERT(cpfp_build_anchor_child(&w.base, &pi, 263, 10000, &child, NULL, &used),
                "fallback child");
    TEST_ASSERT_EQ(used, 0, "anchor-only fallback");
    TEST_ASSERT_EQ(child.len, 65, "anchor-only size");
    tx_buf_free(&child);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- fees at high rates and large client counts ---------------------- */

/* ceil(rate x vsize / 1000), computed here independently of src/fee.c. */
static uint64_t ref_fee(uint64_t rate, size_t vsize) {
    return (uint64_t)(((unsigned __int128)rate * vsize + 999) / 1000);
}

/* Fees are exact at every rate a factory can be built at: the old helper
   capped any fee whose rate x vsize passed 1e8 sat-kvB at 1 BTC, so a
   64-client distribution TX at 36 sat/vB paid 1 BTC to miners and with less
   than 1 BTC of funding no distribution TX was built at all. */
int test_tree_fee_high_rate_large_n(void) {
    /* rates at and above where the 1 BTC cap used to fire for each size */
    static const size_t clients[] = { 22, 64, 127, 230 };
    static const uint64_t rates[] = { 100000, 36000, 19000, 11000 };
    for (size_t i = 0; i < 4; i++) {
        size_t vs = fee_keypath_tx_vsize(1, clients[i], 1);
        TEST_ASSERT(rates[i] > 100000000ULL / (vs + 1), "rate is past the old cap");
        uint64_t want = ref_fee(rates[i], vs);
        TEST_ASSERT(want < 1000000, "the real fee is well under 0.01 BTC");
        TEST_ASSERT_EQ(fee_at_rate(rates[i], vs), want, "fee_at_rate exact");
        TEST_ASSERT_EQ(fee_presigned(rates[i], vs), want, "fee_presigned exact");
        /* CPFP child for that parent at twice the rate */
        uint64_t child = cpfp_child_fee(want, vs, 150, 2 * rates[i]);
        TEST_ASSERT_EQ(child, ref_fee(2 * rates[i], vs + 150) - want,
                       "child pays the package shortfall, not 1 BTC");
    }

    /* Real factories: 22 / 64 / 127 clients, arity 2, 2 BTC and 0.5 BTC. */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const uint64_t fundings[] = { 200000000, 50000000 };
    for (size_t i = 0; i < 3; i++) {
        for (size_t fi = 0; fi < 2; fi++) {
            size_t nc = clients[i];
            shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
            secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
            factory_t *f = calloc(1, sizeof(factory_t));
            TEST_ASSERT(kps && f, "alloc");
            TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, rates[i], fundings[fi]),
                        "init");
            TEST_ASSERT(factory_build_tree(f), "build");
            uint64_t tree_total = 0;
            for (size_t n = 0; n < f->n_nodes; n++) {
                size_t p2tr, p2a;
                count_outputs(&f->nodes[n], &p2tr, &p2a);
                TEST_ASSERT_EQ(f->nodes[n].fee_sats,
                               ref_fee(rates[i], fee_keypath_tx_vsize(1, p2tr, p2a)),
                               "tree node fee exact");
                tree_total += f->nodes[n].fee_sats;
            }
            uint64_t dfee = factory_distribution_fee(f, nc);
            TEST_ASSERT_EQ(dfee, ref_fee(rates[i], fee_keypath_tx_vsize(1, nc, 1)),
                           "distribution fee exact");
            tx_output_t *outs = calloc(nc + 1, sizeof(tx_output_t));
            size_t n = factory_compute_distribution_outputs(f, outs, nc + 1, dfee);
            TEST_ASSERT_EQ(n, nc, "distribution outputs built at any funding");
            TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500),
                        "distribution TX built");
            uint64_t out = 0;
            for (size_t k = 0; k < n; k++) out += outs[k].amount_sats;
            TEST_ASSERT_EQ(f->funding_amount_sats - out, dfee,
                           "miners get the sized fee, nothing more");
            char why[200];
            TEST_ASSERT(factory_check_presigned_fee_bounds(f, why, sizeof(why)), why);
            printf("  %zu clients @ %llu sat/kvB, %llu sat: tree fees %llu, "
                   "distribution fee %llu\n", nc, (unsigned long long)rates[i],
                   (unsigned long long)fundings[fi], (unsigned long long)tree_total,
                   (unsigned long long)dfee);
            free(outs);
            factory_free(f);
            free(f);
            free(kps);
        }
    }
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
    TEST_ASSERT(fee_presigned(UINT64_MAX, 210) == FEE_INVALID, "presigned too");
    TEST_ASSERT_EQ(fee_at_rate(0, 210), 0, "no rate, no fee");
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

/* The pre-signing sanity bounds: a node or distribution TX paying more than
   the agreed rate, or an exit path paying more than
   FACTORY_MAX_EXIT_FEE_PCT of the funding, is refused. */
int test_tree_fee_presigned_bounds(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    char why[200];

    /* 1. a node over-paying for its size */
    secp256k1_keypair kps[9];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 8, &sh, 25000, 480000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_check_presigned_fee_bounds(f, why, sizeof(why)), why);
    size_t li = f->leaf_node_indices[0];
    f->nodes[li].outputs[0].amount_sats -= 1000;   /* 1000 sat more to miners */
    TEST_ASSERT(!factory_check_presigned_fee_bounds(f, why, sizeof(why)), "over-paying node");
    TEST_ASSERT(strstr(why, "above the agreed") != NULL, why);
    factory_free(f);
    free(f);

    /* 2. the tree's total fee above the bound: small funding at a high rate */
    int saw_tree_refusal = 0;
    for (uint64_t fund = 150000; fund <= 2000000 && !saw_tree_refusal; fund += 50000) {
        f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, 8, &sh, 100000, fund), "init");
        if (factory_build_tree(f) &&
            !factory_check_presigned_fee_bounds(f, why, sizeof(why))) {
            TEST_ASSERT(strstr(why, "the tree's pre-signed fees total") != NULL, why);
            saw_tree_refusal = 1;
        }
        factory_free(f);
        free(f);
    }
    TEST_ASSERT(saw_tree_refusal, "a buildable tree above the bound is refused");

    /* 3. the bound follows the sums exactly (64 clients at 100 sat/vB) */
    {
        size_t nc = 64;
        secp256k1_keypair *k64 = calloc(nc + 1, sizeof(*k64));
        int n_ok = 0, n_refused = 0;
        for (uint64_t fund = 2000000; fund <= 30000000; fund += 2000000) {
            factory_t *g = calloc(1, sizeof(factory_t));
            TEST_ASSERT(make_factory(ctx, g, k64, nc, &sh, 100000, fund), "init");
            if (factory_build_tree(g)) {
                uint64_t total = 0;
                for (size_t n = 0; n < g->n_nodes; n++) total += g->nodes[n].fee_sats;
                uint64_t dfee = factory_distribution_fee(g, nc);
                uint64_t cap = fund * FACTORY_MAX_EXIT_FEE_PCT / 100;
                int ok = factory_check_presigned_fee_bounds(g, why, sizeof(why));
                TEST_ASSERT_EQ(ok, total <= cap && dfee <= cap, "bound matches the sums");
                if (ok) n_ok++; else n_refused++;
            }
            factory_free(g);
            free(g);
        }
        TEST_ASSERT(n_ok > 0 && n_refused > 0, "both sides of the bound exercised");
        free(k64);
    }

    /* 4. no distribution TX without cltv: the bound only covers the tree */
    f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 8, &sh, 1250, 480000), "init");
    f->cltv_timeout = 0;
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_check_presigned_fee_bounds(f, why, sizeof(why)), why);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The tree-exit drill configurations (N x 60000 sat, 25 sat/vB) stay inside
   the bounds. */
int test_tree_fee_bounds_drill_configs(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const shape_t shapes[] = {
        { "arity1", 1, {0}, 0, 0, 0 },
        { "arity2", 2, {0}, 0, 0, 0 },
        { "ps",     3, {0}, 0, 0, 0 },
    };
    static const size_t clients[] = { 4, 8 };
    for (size_t si = 0; si < 3; si++) {
        for (size_t ci = 0; ci < 2; ci++) {
            size_t nc = clients[ci];
            secp256k1_keypair kps[9];
            factory_t *f = calloc(1, sizeof(factory_t));
            TEST_ASSERT(make_factory(ctx, f, kps, nc, &shapes[si], 25000, nc * 60000),
                        "init");
            TEST_ASSERT(factory_build_tree(f), "build");
            uint64_t total = 0;
            for (size_t n = 0; n < f->n_nodes; n++) total += f->nodes[n].fee_sats;
            char why[200];
            int ok = factory_check_presigned_fee_bounds(f, why, sizeof(why));
            printf("  %s n=%zu: tree fees %llu of %llu (%llu%%)%s%s\n", shapes[si].name,
                   nc, (unsigned long long)total, (unsigned long long)(nc * 60000),
                   (unsigned long long)(total * 100 / (nc * 60000)), ok ? "" : " REFUSED: ",
                   ok ? "" : why);
            TEST_ASSERT(ok, why);
            factory_free(f);
            free(f);
        }
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* In a fee spike the LSP sizes the tree at the agreed maximum, so clients
   with default settings still sign it; an explicit rate is left alone. */
int test_tree_fee_lsp_clamps_to_agreed_max(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    TEST_ASSERT_EQ(factory_max_tree_fee_rate(), FACTORY_MAX_TREE_FEE_RATE, "default");
    TEST_ASSERT_EQ(CLIENT_DEFAULT_MAX_TREE_FEE_RATE, FACTORY_MAX_TREE_FEE_RATE,
                   "client and LSP share one maximum");
    static const struct { uint64_t est, max, want; } cases[] = {
        { 300000, FACTORY_MAX_TREE_FEE_RATE, FACTORY_MAX_TREE_FEE_RATE }, /* spike */
        { 100001, FACTORY_MAX_TREE_FEE_RATE, FACTORY_MAX_TREE_FEE_RATE },
        {  50000, FACTORY_MAX_TREE_FEE_RATE, 50000 },                      /* normal */
        { 300000, 200000, 200000 },                                        /* configured */
        { 300000, 0, 300000 },                                             /* no ceiling */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        factory_set_max_tree_fee_rate(cases[i].max);
        secp256k1_keypair kps[5];
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 0, 50000000), "init");
        fee_estimator_static_t fe;
        fee_estimator_static_init(&fe, cases[i].est);
        f->fee = &fe.base;
        TEST_ASSERT(factory_build_tree(f), "build");
        TEST_ASSERT_EQ(f->tree_fee_rate, cases[i].want, "tree rate");
        TEST_ASSERT(client_tree_fee_rate_acceptable(f->tree_fee_rate),
                    "a client with the same maximum signs it");
        factory_free(f);
        free(f);
    }
    factory_set_max_tree_fee_rate(FACTORY_MAX_TREE_FEE_RATE);

    /* An explicit rate is what the tree is sized at (the LSP refuses to start
       with one above the maximum); the client refuses it if it is above. */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(make_factory(ctx, f, kps, 4, &sh, 150000, 50000000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT_EQ(f->tree_fee_rate, 150000, "explicit rate kept");
    TEST_ASSERT(!client_tree_fee_rate_acceptable(f->tree_fee_rate), "client refuses it");
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- tree fee rate planned before funding ----------------------------- */

/* An LSP with n clients (keys only: lsp_plan_tree_fee_rate builds trial
   trees, it talks to nobody). */
static lsp_t *plan_lsp(secp256k1_context *ctx, size_t n) {
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return NULL;
    lsp->client_pubkeys = calloc(n, sizeof(secp256k1_pubkey));
    if (!lsp->client_pubkeys) { free(lsp); return NULL; }
    lsp->ctx = ctx;
    for (size_t i = 0; i <= n; i++) {
        unsigned char sk[32];
        memset(sk, 0, 32);
        sk[0] = 0x71;
        sk[31] = (unsigned char)(i + 1);
        secp256k1_keypair kp;
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_create(ctx, &kp, sk) ||
            !secp256k1_keypair_pub(ctx, &pk, &kp)) {
            free(lsp->client_pubkeys);
            free(lsp);
            return NULL;
        }
        if (i == 0) lsp->lsp_pubkey = pk;
        else lsp->client_pubkeys[i - 1] = pk;
    }
    lsp->n_clients = n;
    return lsp;
}

/* Whether a factory of shape sh, n clients, funding, at rate passes the
   bound every signer checks. */
static int bound_ok(secp256k1_context *ctx, const shape_t *sh, size_t n,
                    uint64_t funding, uint64_t rate) {
    secp256k1_keypair kps[10];
    factory_t *f = calloc(1, sizeof(factory_t));
    int ok = f && make_factory(ctx, f, kps, n, sh, rate, funding) &&
             factory_build_tree(f) &&
             factory_check_presigned_fee_bounds(f, NULL, 0);
    if (f) { factory_free(f); free(f); }
    return ok;
}

/* The pre-signed fee bound depends only on the tree shape, the client
   count, the rate and the funding, so the LSP settles the rate before it
   funds anything: the highest rate within the bound (lowering a spike
   estimate to it), the asked rate when it passes, and a refusal when even
   the floor fails.  A tree then built from the estimate with that maximum is
   sized at it and passes the clients' check. */
int test_tree_fee_plan_rate_before_funding(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const shape_t shapes[] = {
        { "arity1", 1, {0}, 0, 0, 0 },
        { "arity2", 2, {0}, 0, 0, 0 },
        { "ps",     3, {0}, 0, 0, 0 },
    };
    lsp_t *lsp = plan_lsp(ctx, 4);
    TEST_ASSERT(lsp, "lsp");
    fee_estimator_static_t spike;
    fee_estimator_static_init(&spike, 300000);        /* 300 sat/vB */
    for (size_t si = 0; si < 3; si++) {
        const shape_t *sh = &shapes[si];
        factory_t *cfg = calloc(1, sizeof(factory_t));
        TEST_ASSERT(cfg, "cfg");
        cfg->leaf_arity = sh->arity == 1 ? FACTORY_ARITY_1 :
                          sh->arity == 3 ? FACTORY_ARITY_PS : FACTORY_ARITY_2;
        cfg->fee = &spike.base;
        uint64_t funding = 4 * 60000, max = 0, asked = 0;
        char why[256];

        /* spike, small funding: lowered to the highest rate that passes */
        TEST_ASSERT(lsp_plan_tree_fee_rate(lsp, cfg, 4, funding, 4, 4, 500,
                                           &max, &asked, why, sizeof(why)), why);
        printf("  %s, 4 x 60000 sat, estimate 300 sat/vB: asked %llu, max %llu sat/kvB\n",
               sh->name, (unsigned long long)asked, (unsigned long long)max);
        TEST_ASSERT_EQ(asked, FACTORY_MAX_TREE_FEE_RATE, "estimate clamped to the maximum");
        TEST_ASSERT(max >= FEE_PRESIGNED_FLOOR_SAT_PER_KVB && max < asked, "lowered");
        TEST_ASSERT(bound_ok(ctx, sh, 4, funding, max), "passes at the planned maximum");
        TEST_ASSERT(!bound_ok(ctx, sh, 4, funding, max + 1), "the highest such rate");

        /* the ceremony's tree, from the estimate, is sized at that maximum */
        secp256k1_keypair kps[5];
        factory_t *f = calloc(1, sizeof(factory_t));
        TEST_ASSERT(make_factory(ctx, f, kps, 4, sh, 0, funding), "init");
        f->fee = &spike.base;
        f->tree_fee_rate_max = max;
        TEST_ASSERT(factory_build_tree(f), "build");
        TEST_ASSERT_EQ(f->tree_fee_rate, max, "tree sized at the planned maximum");
        TEST_ASSERT(factory_check_presigned_fee_bounds(f, why, sizeof(why)), why);
        TEST_ASSERT(client_tree_fee_rate_acceptable(f->tree_fee_rate), "clients accept it");
        factory_free(f);
        free(f);

        /* enough funding: the estimate (clamped) is the maximum */
        TEST_ASSERT(lsp_plan_tree_fee_rate(lsp, cfg, 4, 50000000, 4, 4, 500,
                                           &max, &asked, why, sizeof(why)), why);
        TEST_ASSERT_EQ(max, FACTORY_MAX_TREE_FEE_RATE, "nothing lowered");

        /* an explicit rate that passes is kept; the search stops there */
        cfg->tree_fee_rate = 25000;
        TEST_ASSERT(lsp_plan_tree_fee_rate(lsp, cfg, 4, 50000000, 4, 4, 500,
                                           &max, &asked, why, sizeof(why)), why);
        TEST_ASSERT_EQ(asked, 25000, "explicit rate asked");
        TEST_ASSERT_EQ(max, 25000, "explicit rate kept");
        cfg->tree_fee_rate = 0;

        /* too little funding even at the floor: refused, nothing to fund */
        TEST_ASSERT(!lsp_plan_tree_fee_rate(lsp, cfg, 4, 5000, 4, 4, 500,
                                            &max, &asked, why, sizeof(why)),
                    "refused at the floor");
        printf("  %s, 5000 sat: refused (%s)\n", sh->name, why);
        TEST_ASSERT(strstr(why, "floor") != NULL, "says the floor fails");
        TEST_ASSERT_EQ(max, 0, "no rate");
        free(cfg);
    }
    free(lsp->client_pubkeys);
    free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The LSP's own transactions sized from an estimate (rotation close, JIT
   and reallocated commitments, JIT close) use the estimate clamped to the
   same agreed maximum as the tree. */
int test_tree_fee_lsp_own_tx_rate_clamped(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 300000);           /* 300 sat/vB spike */
    TEST_ASSERT_EQ(factory_lsp_fee_rate(&fe.base), FACTORY_MAX_TREE_FEE_RATE,
                   "spike clamped to the agreed maximum");
    TEST_ASSERT_EQ(fee_commitment_tx_at(factory_lsp_fee_rate(&fe.base), 0),
                   (154 * FACTORY_MAX_TREE_FEE_RATE + 999) / 1000,
                   "commitment fee at the maximum");
    fee_estimator_static_init(&fe, 5000);
    TEST_ASSERT_EQ(factory_lsp_fee_rate(&fe.base), 5000, "below the maximum: kept");
    TEST_ASSERT_EQ(fee_commitment_tx_at(5000, 0), fee_for_commitment_tx(&fe.base, 0),
                   "same commitment fee as fee_for_commitment_tx");
    /* follows the configured maximum; 0 = none */
    fee_estimator_static_init(&fe, 300000);
    uint64_t saved_max = factory_max_tree_fee_rate();
    factory_set_max_tree_fee_rate(50000);
    uint64_t at_50 = factory_lsp_fee_rate(&fe.base);
    factory_set_max_tree_fee_rate(0);
    uint64_t at_none = factory_lsp_fee_rate(&fe.base);
    factory_set_max_tree_fee_rate(saved_max);
    TEST_ASSERT_EQ(at_50, 50000, "configured maximum");
    TEST_ASSERT_EQ(at_none, 300000, "no maximum");
    TEST_ASSERT_EQ(factory_lsp_fee_rate(NULL), 0, "no estimator");
    return 1;
}

/* A rotation plans the new factory for every client online before the key
   turnover; fewer of them may join.  That plan is an upper bound: with
   fewer clients the highest rate within the bound is never lower, and a
   plan that passes for n clients passes for fewer. */
int test_tree_fee_plan_fewer_clients_no_worse(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    static const shape_t shapes[] = {
        { "arity1", 1, {0}, 0, 0, 0 },
        { "arity2", 2, {0}, 0, 0, 0 },
        { "ps",     3, {0}, 0, 0, 0 },
    };
    lsp_t *lsp = plan_lsp(ctx, 8);
    TEST_ASSERT(lsp, "lsp");
    fee_estimator_static_t spike;
    fee_estimator_static_init(&spike, 300000);
    static const uint64_t fundings[] = { 8 * 30000, 8 * 60000, 2000000 };
    for (size_t si = 0; si < 3; si++) {
        for (size_t fi = 0; fi < 3; fi++) {
            factory_t *cfg = calloc(1, sizeof(factory_t));
            TEST_ASSERT(cfg, "cfg");
            cfg->leaf_arity = shapes[si].arity == 1 ? FACTORY_ARITY_1 :
                              shapes[si].arity == 3 ? FACTORY_ARITY_PS : FACTORY_ARITY_2;
            cfg->fee = &spike.base;
            uint64_t prev = 0;
            int prev_ok = 0;
            for (size_t n = 8; n >= 2; n--) {
                uint64_t max = 0, asked = 0;
                char why[256];
                int ok = lsp_plan_tree_fee_rate(lsp, cfg, n, fundings[fi], 4, 4, 500,
                                                &max, &asked, why, sizeof(why));
                if (prev_ok) {
                    TEST_ASSERT(ok, "passes for fewer clients");
                    TEST_ASSERT(max >= prev, "rate not lower for fewer clients");
                }
                prev = max;
                prev_ok = ok;
            }
            free(cfg);
        }
    }
    free(lsp->client_pubkeys);
    free(lsp);
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
    TEST_ASSERT(f && make_parent(ctx, f, kps, &pi, &li), "parent");
    const factory_node_t *n = &f->nodes[li];
    char *hex = malloc(n->signed_tx.len * 2 + 1);
    TEST_ASSERT(hex, "alloc");
    hex_encode(n->signed_tx.data, n->signed_tx.len, hex);

    /* The anchor alone: 263 + 240 sat for 210 + 65 vB = 1829 sat/kvB. */
    TEST_ASSERT(!cpfp_anchor_alone_short(263, 210, 240, 1000), "enough at 1 sat/vB");
    TEST_ASSERT(!cpfp_anchor_alone_short(263, 210, 240, 1829), "enough at its own rate");
    TEST_ASSERT(cpfp_anchor_alone_short(263, 210, 240, 1830), "short just above");
    TEST_ASSERT(cpfp_anchor_alone_short(263, 210, 240, 5000), "short at 5 sat/vB");
    /* the root seen at a 5 sat/vB floor: 395 < 945 */
    TEST_ASSERT(cpfp_anchor_alone_short(155, 124, 240, 5000), "root short at 5 sat/vB");

    /* No RPC: the chain backend refuses the tx, which carries an anchor. */
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
    TEST_ASSERT(strstr(cpfp_need_text(CPFP_NEED_PACKAGE_RELAY), "package relay") != NULL,
                "relay text");
    TEST_ASSERT(strstr(cpfp_need_text(CPFP_NEED_COIN), "--wallet") != NULL,
                "coin text names --wallet");
    cpfp_need_clear();
    TEST_ASSERT_EQ(cpfp_need_seen(), CPFP_NEED_NONE, "cleared");

    /* A refused tx without an anchor is not a package matter. */
    tx_output_t o;
    memset(&o, 0, sizeof(o));
    o.amount_sats = 1000;
    o.script_pubkey[0] = 0x51; o.script_pubkey[1] = 0x20;
    memset(o.script_pubkey + 2, 0x33, 32);
    o.script_pubkey_len = 34;
    tx_buf_t plain;
    tx_buf_init(&plain, 128);
    unsigned char in_txid[32];
    memset(in_txid, 0x44, 32);
    TEST_ASSERT(build_unsigned_tx(&plain, NULL, in_txid, 0, 0xfffffffd, &o, 1), "plain tx");
    char *phex = malloc(plain.len * 2 + 1);
    TEST_ASSERT(phex, "alloc");
    hex_encode(plain.data, plain.len, phex);
    TEST_ASSERT(cpfp_send_default(&cb, phex, txid) == CPFP_FAILED, "plain refused");
    TEST_ASSERT_EQ(cpfp_need_seen(), CPFP_NEED_NONE, "no anchor: not reported as a package need");

    free(phex);
    tx_buf_free(&plain);
    free(hex);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}


/* ---- distribution TX: fee and anchor from the LSP's share ------------- */

#ifndef FACTORY_DIST_NON_TRUC_FEE_RATE
#define FACTORY_DIST_NON_TRUC_FEE_RATE 20000
#endif

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
    cpfp_tx_info_t ti;
    unsigned char *buf = malloc(f->dist_unsigned_tx.len + 1);
    if (!buf) return 0;
    memcpy(buf, f->dist_unsigned_tx.data, f->dist_unsigned_tx.len);
    int ok = cpfp_parse_tx(buf, f->dist_unsigned_tx.len, &ti);
    free(buf);
    if (!ok) return 0;
    /* outputs follow: version(4) vin(1) input(41) vout-count varint */
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

/* The distribution TX pays every client at least its full channel capacity;
   its fee and P2A anchor come out of what is left above the capacities (the
   LSP's share), never out of one client.  A set of client amounts that does
   not leave room for them is refused, not scaled down. */
int test_distribution_fee_from_lsp_share(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    const size_t nc = 8;
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(kps && f, "alloc");
    TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, 0, 4000000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    uint64_t fee = factory_distribution_fee(f, nc);
    tx_output_t outs[16];

    /* equal split: every client the same (the anchor is not client 0's) */
    size_t n = factory_compute_distribution_outputs(f, outs, 16, fee);
    TEST_ASSERT_EQ(n, nc, "outputs");
    TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500), "build dist");
    uint64_t pay[16];
    TEST_ASSERT(dist_payouts(f, pay, nc), "parse dist");
    uint64_t lo = UINT64_MAX, hi = 0, sum = 0;
    for (size_t i = 0; i < nc; i++) {
        if (pay[i] < lo) lo = pay[i];
        if (pay[i] > hi) hi = pay[i];
        sum += pay[i];
        TEST_ASSERT(pay[i] >= chan_capacity(f, i), "at least the channel capacity");
    }
    printf("  equal split: payouts %llu..%llu, fee %llu, anchor %d\n",
           (unsigned long long)lo, (unsigned long long)hi, (unsigned long long)fee,
           ANCHOR_OUTPUT_AMOUNT);
    TEST_ASSERT(hi - lo < nc, "client 0 does not pay the anchor");
    TEST_ASSERT_EQ(sum + ANCHOR_OUTPUT_AMOUNT + fee, f->funding_amount_sats,
                   "funding = payouts + anchor + fee");

    /* per-client amounts (capacities): each gets its amount plus a share of
       the rest; the fee and anchor come from the rest */
    uint64_t cap[16];
    uint64_t caps = 0;
    for (size_t i = 0; i < nc; i++) { cap[i] = chan_capacity(f, i); caps += cap[i]; }
    n = factory_compute_distribution_outputs_balanced(f, outs, 16, fee, cap, nc);
    TEST_ASSERT_EQ(n, nc, "balanced outputs");
    TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500), "build balanced");
    TEST_ASSERT(dist_payouts(f, pay, nc), "parse balanced");
    for (size_t i = 0; i < nc; i++)
        TEST_ASSERT(pay[i] >= cap[i], "balanced: at least the amount asked");

    /* amounts that leave no room for the fee and the anchor: refused */
    uint64_t over[16];
    uint64_t room = f->funding_amount_sats - caps;   /* the LSP's share */
    for (size_t i = 0; i < nc; i++) over[i] = cap[i];
    over[0] += room - fee - ANCHOR_OUTPUT_AMOUNT + 1;
    TEST_ASSERT_EQ(factory_compute_distribution_outputs_balanced(f, outs, 16, fee, over, nc),
                   0, "one sat short of fee + anchor: refused, not scaled down");
    over[0] -= 1;
    TEST_ASSERT_EQ(factory_compute_distribution_outputs_balanced(f, outs, 16, fee, over, nc),
                   nc, "exactly enough: built");
    for (size_t i = 0; i < nc; i++) over[i] = cap[i] * 2;
    TEST_ASSERT_EQ(factory_compute_distribution_outputs_balanced(f, outs, 16, fee, over, nc),
                   0, "amounts above the funding: refused, not scaled down");

    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A distribution TX above the TRUC limit (about 231 clients and more) is
   nVersion 2: it cannot go in as a package below the minimum relay fee and
   its anchor can be pinned.  It is signed at a high rate instead, at least
   FACTORY_DIST_NON_TRUC_FEE_RATE, paid from the LSP's share; a factory whose
   funding cannot carry that fee within the pre-signed bound is refused before
   funding. */
int test_distribution_above_truc_paid_high(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    const size_t nc = 240;
    TEST_ASSERT_EQ(factory_distribution_tx_version(nc), 2, "240 clients: not TRUC");
    TEST_ASSERT_EQ(factory_distribution_tx_version(200), 3, "200 clients: TRUC");
    shape_t sh = { "arity2", 2, {0}, 0, 0, 0 };
    secp256k1_keypair *kps = calloc(nc + 1, sizeof(*kps));
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(kps && f, "alloc");
    TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, 0, 100000000), "init");
    TEST_ASSERT(factory_build_tree(f), "build");
    size_t vs = fee_keypath_tx_vsize(1, nc, 1);
    uint64_t fee = factory_distribution_fee(f, nc);
    printf("  %zu clients: distribution TX %zu vB, fee %llu sat (tree rate %llu)\n", nc, vs,
           (unsigned long long)fee, (unsigned long long)f->tree_fee_rate);
    TEST_ASSERT_EQ(fee, fee_presigned(FACTORY_DIST_NON_TRUC_FEE_RATE, vs),
                   "signed at the non-TRUC rate, not the tree rate");
    char why[200];
    TEST_ASSERT(factory_check_presigned_fee_bounds(f, why, sizeof(why)), why);
    tx_output_t *outs = calloc(nc + 1, sizeof(tx_output_t));
    TEST_ASSERT(outs, "alloc");
    size_t n = factory_compute_distribution_outputs(f, outs, nc + 1, fee);
    TEST_ASSERT_EQ(n, nc, "outputs");
    TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n, 500), "build dist");
    TEST_ASSERT_EQ(f->dist_unsigned_tx.data[0], 2, "nVersion 2");
    uint64_t *pay = calloc(nc, sizeof(uint64_t));
    TEST_ASSERT(pay && dist_payouts(f, pay, nc), "parse dist");
    for (size_t i = 0; i < nc; i++)
        TEST_ASSERT(pay[i] >= chan_capacity(f, i), "every client at least its capacity");
    /* a higher tree rate wins */
    factory_free(f);
    memset(f, 0, sizeof(*f));
    TEST_ASSERT(make_factory(ctx, f, kps, nc, &sh, 30000, 100000000), "init 30 sat/vB");
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT_EQ(factory_distribution_fee(f, nc), fee_presigned(30000, vs),
                   "a tree rate above it is used");
    factory_free(f);
    free(f);
    free(pay);
    free(outs);

    /* Before funding: 800000 sat for 240 clients carries the distribution TX
       at the tree floor (13 ksat) but not at 20 sat/vB (206 ksat, above 25%
       of the funding): the LSP refuses the factory. */
    lsp_t *lsp = plan_lsp(ctx, nc);
    TEST_ASSERT(lsp, "lsp");
    factory_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.leaf_arity = FACTORY_ARITY_2;
    cfg.tree_fee_rate = FEE_PRESIGNED_FLOOR_SAT_PER_KVB;
    uint64_t max_rate = 0, asked = 0;
    int planned = lsp_plan_tree_fee_rate(lsp, &cfg, nc, 800000, 4, 4, 500,
                                         &max_rate, &asked, why, sizeof(why));
    printf("  plan for %zu clients at 800000 sat: %d (%s)\n", nc, planned, why);
    TEST_ASSERT(!planned, "refused before funding");
    planned = lsp_plan_tree_fee_rate(lsp, &cfg, nc, 4000000, 4, 4, 500,
                                     &max_rate, &asked, why, sizeof(why));
    TEST_ASSERT(planned, "4000000 sat carries it");
    free(lsp->client_pubkeys);
    free(lsp);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

