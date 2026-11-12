#include "superscalar/tapscript.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
#include "superscalar/sha256.h"

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

#define TEST_ASSERT_NEQ(a, b, msg) do { \
    if ((a) == (b)) { \
        printf("  FAIL: %s (line %d): %s (both %ld)\n", \
               __func__, __LINE__, msg, (long)(a)); \
        return 0; \
    } \
} while(0)

/* Secret keys for 5 participants: LSP + 4 clients */
static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },  /* Client A */
    { [0 ... 31] = 0x32 },  /* Client B */
    { [0 ... 31] = 0x43 },  /* Client C */
    { [0 ... 31] = 0x54 },  /* Client D */
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static int make_keypairs(secp256k1_context *ctx, secp256k1_keypair *kps) {
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }
    return 1;
}

/* ---- Unit test 1: TapLeaf hash ---- */

int test_tapscript_leaf_hash(void) {
    secp256k1_context *ctx = test_ctx();

    /* Create a known keypair for LSP */
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckeys[0])) return 0;
    secp256k1_xonly_pubkey lsp_xonly;
    if (!secp256k1_keypair_xonly_pub(ctx, &lsp_xonly, NULL, &kp)) return 0;

    tapscript_leaf_t leaf;
    tapscript_build_cltv_timeout(&leaf, 500, &lsp_xonly, ctx);

    /* Verify script structure:
       <locktime_push> OP_CLTV(0xb1) OP_DROP(0x75) <32-byte-push(0x20)> <pubkey> OP_CHECKSIG(0xac) */
    TEST_ASSERT(leaf.script_len > 36, "script length > 36");

    /* Find OP_CLTV */
    int found_cltv = 0;
    for (size_t i = 0; i < leaf.script_len; i++) {
        if (leaf.script[i] == 0xb1) { found_cltv = 1; break; }
    }
    TEST_ASSERT(found_cltv, "script contains OP_CLTV");

    /* Last byte should be OP_CHECKSIG */
    TEST_ASSERT(leaf.script[leaf.script_len - 1] == 0xac, "ends with OP_CHECKSIG");

    /* Leaf hash should be 32 non-zero bytes */
    unsigned char zero[32];
    memset(zero, 0, 32);
    TEST_ASSERT(memcmp(leaf.leaf_hash, zero, 32) != 0, "leaf hash non-zero");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test 2: tweak with tree vs without ---- */

int test_tapscript_tweak_with_tree(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckeys[0])) return 0;
    secp256k1_xonly_pubkey internal_key;
    if (!secp256k1_keypair_xonly_pub(ctx, &internal_key, NULL, &kp)) return 0;

    /* Key-path only tweak */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &internal_key)) return 0;
    unsigned char kp_tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, kp_tweak);

    secp256k1_pubkey kp_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &kp_tweaked_full, &internal_key, kp_tweak)) return 0;
    secp256k1_xonly_pubkey kp_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &kp_tweaked, NULL, &kp_tweaked_full)) return 0;

    /* Tweak with a taptree */
    tapscript_leaf_t leaf;
    tapscript_build_cltv_timeout(&leaf, 500, &internal_key, ctx);

    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &leaf, 1);

    secp256k1_xonly_pubkey tree_tweaked;
    int parity = 0;
    TEST_ASSERT(tapscript_tweak_pubkey(ctx, &tree_tweaked, &parity, &internal_key,
                                        merkle_root),
                "tweak with tree");

    /* The two tweaked keys should differ */
    unsigned char kp_ser[32], tree_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, kp_ser, &kp_tweaked)) return 0;
    if (!secp256k1_xonly_pubkey_serialize(ctx, tree_ser, &tree_tweaked)) return 0;
    TEST_ASSERT(memcmp(kp_ser, tree_ser, 32) != 0, "tweaked keys differ");

    /* Both produce valid 34-byte P2TR scriptPubKeys */
    unsigned char spk1[34], spk2[34];
    build_p2tr_script_pubkey(spk1, &kp_tweaked);
    build_p2tr_script_pubkey(spk2, &tree_tweaked);
    TEST_ASSERT(spk1[0] == 0x51 && spk1[1] == 0x20, "spk1 is P2TR");
    TEST_ASSERT(spk2[0] == 0x51 && spk2[1] == 0x20, "spk2 is P2TR");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test 3: control block ---- */

int test_tapscript_control_block(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckeys[0])) return 0;
    secp256k1_xonly_pubkey internal_key;
    if (!secp256k1_keypair_xonly_pub(ctx, &internal_key, NULL, &kp)) return 0;

    /* Build taptree */
    tapscript_leaf_t leaf;
    tapscript_build_cltv_timeout(&leaf, 500, &internal_key, ctx);
    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &leaf, 1);

    secp256k1_xonly_pubkey tweaked;
    int parity = 0;
    tapscript_tweak_pubkey(ctx, &tweaked, &parity, &internal_key, merkle_root);

    /* Build control block */
    unsigned char cb[33 + 32];  /* max: 33 + 32*depth */
    size_t cb_len = 0;
    TEST_ASSERT(tapscript_build_control_block(cb, &cb_len, parity, &internal_key, ctx),
                "build control block");

    /* Verify length = 33 (single-leaf, no merkle path) */
    TEST_ASSERT_EQ(cb_len, 33, "control block length");

    /* First byte = leaf_version | parity */
    unsigned char expected_first = TAPSCRIPT_LEAF_VERSION | (parity & 1);
    TEST_ASSERT(cb[0] == expected_first, "control block first byte");

    /* Internal key in control block matches */
    unsigned char ik_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ik_ser, &internal_key)) return 0;
    TEST_ASSERT(memcmp(cb + 1, ik_ser, 32) == 0, "control block internal key");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test 4: script-path sighash differs from key-path ---- */

int test_tapscript_sighash(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckeys[0])) return 0;
    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &kp)) return 0;

    /* Build a dummy tx */
    unsigned char fake_txid[32];
    memset(fake_txid, 0xBB, 32);

    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &xonly);

    tx_output_t out;
    out.amount_sats = 50000;
    memcpy(out.script_pubkey, spk, 34);
    out.script_pubkey_len = 34;

    tx_buf_t tx;
    tx_buf_init(&tx, 256);
    build_unsigned_tx(&tx, NULL, fake_txid, 0, 0xFFFFFFFE, &out, 1);

    /* Build leaf for script-path */
    tapscript_leaf_t leaf;
    tapscript_build_cltv_timeout(&leaf, 100, &xonly, ctx);

    /* Key-path sighash */
    unsigned char kp_sighash[32];
    compute_taproot_sighash(kp_sighash, tx.data, tx.len, 0,
                             spk, 34, 60000, 0xFFFFFFFE);

    /* Script-path sighash */
    unsigned char sp_sighash[32];
    compute_tapscript_sighash(sp_sighash, tx.data, tx.len, 0,
                               spk, 34, 60000, 0xFFFFFFFE, &leaf);

    /* They should differ */
    TEST_ASSERT(memcmp(kp_sighash, sp_sighash, 32) != 0,
                "key-path and script-path sighash differ");

    tx_buf_free(&tx);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test 5: factory tree with timeout ---- */

int test_factory_tree_with_timeout(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Compute funding spk (same as Phase 1) */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &tmp.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Build factory WITH cltv_timeout */
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init(f, ctx, kps, 5, 2, 4);
    f->cltv_timeout = 1000;  /* some block height */
    factory_set_funding(f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree with timeout");
    TEST_ASSERT_EQ(f->n_nodes, 6, "6 nodes");

    /* Build factory WITHOUT cltv_timeout for comparison */
    factory_t *f2 = calloc(1, sizeof(factory_t));
    if (!f2) return 0;
    factory_init(f2, ctx, kps, 5, 2, 4);
    f2->cltv_timeout = 0;
    factory_set_funding(f2, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f2), "build tree without timeout");

    /* The end date changes no tree output: no node input has a script path
       (in particular none the host could spend alone after the CLTV), so
       every output script is the same with and without a CLTV. */
    for (size_t i = 0; i < f->n_nodes; i++) {
        TEST_ASSERT(memcmp(f->nodes[i].spending_spk, f2->nodes[i].spending_spk, 34) == 0,
                    "node input script independent of the CLTV");
        for (size_t v = 0; v < f->nodes[i].n_outputs; v++)
            TEST_ASSERT(memcmp(f->nodes[i].outputs[v].script_pubkey,
                               f2->nodes[i].outputs[v].script_pubkey, 34) == 0,
                        "node output script independent of the CLTV");
    }

    /* All 6 txs should sign and verify via key-path */
    TEST_ASSERT(factory_sign_all(f), "sign all with timeout");

    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        TEST_ASSERT(node->is_signed, "node signed");

        /* Recompute sighash and verify */
        const unsigned char *prev_spk;
        size_t prev_spk_len;
        uint64_t prev_amount;

        if (node->parent_index < 0) {
            prev_spk = f->funding_spk;
            prev_spk_len = f->funding_spk_len;
            prev_amount = f->funding_amount_sats;
        } else {
            factory_node_t *parent = &f->nodes[node->parent_index];
            prev_spk = parent->outputs[node->parent_vout].script_pubkey;
            prev_spk_len = parent->outputs[node->parent_vout].script_pubkey_len;
            prev_amount = parent->outputs[node->parent_vout].amount_sats;
        }

        unsigned char sighash[32];
        TEST_ASSERT(compute_taproot_sighash(sighash,
            node->unsigned_tx.data, node->unsigned_tx.len,
            0, prev_spk, prev_spk_len, prev_amount, node->nsequence),
            "compute sighash");

        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->unsigned_tx.len, 64);

        int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                                  &node->tweaked_pubkey);
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu sig valid", i);
        TEST_ASSERT(valid, msg);
    }

    factory_free(f);
    free(f);
    factory_free(f2);
    free(f2);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test 7: multi-level staggered timeout ---- */

int test_multi_level_timeout_unit(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Compute funding spk */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &tmp.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xCC, 32);

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init(f, ctx, kps, 5, 2, 4);
    f->cltv_timeout = 1000;
    factory_set_funding(f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");
    TEST_ASSERT_EQ(f->n_nodes, 6, "6 nodes");

    /* No CLTV anywhere in the tree: the end date lives only in the payouts.
       Every payout has nLockTime = the CLTV, a final-enabling nSequence, and
       no output for the host. */
    unsigned char host_spk[34];
    {
        secp256k1_xonly_pubkey hx, ht;
        unsigned char ser[32], tw[32];
        secp256k1_pubkey full;
        TEST_ASSERT(secp256k1_keypair_xonly_pub(ctx, &hx, NULL, &kps[0]), "host key");
        secp256k1_xonly_pubkey_serialize(ctx, ser, &hx);
        sha256_tagged("TapTweak", ser, 32, tw);
        TEST_ASSERT(secp256k1_xonly_pubkey_tweak_add(ctx, &full, &hx, tw), "tweak");
        secp256k1_xonly_pubkey_from_pubkey(ctx, &ht, NULL, &full);
        build_p2tr_script_pubkey(host_spk, &ht);
    }
    TEST_ASSERT(f->n_payouts > 0, "payouts built");
    for (size_t pi = 0; pi < f->n_payouts; pi++) {
        const factory_payout_t *p = &f->payouts[pi];
        const tx_buf_t *u = &p->unsigned_tx;
        TEST_ASSERT(u->len > 10, "payout tx");
        uint32_t lt = (uint32_t)u->data[u->len - 4] | ((uint32_t)u->data[u->len - 3] << 8) |
                      ((uint32_t)u->data[u->len - 2] << 16) | ((uint32_t)u->data[u->len - 1] << 24);
        TEST_ASSERT_EQ(lt, 1000, "payout nLockTime is the end date");
        for (size_t k = 0; k + 34 <= u->len; k++)
            TEST_ASSERT(memcmp(u->data + k, host_spk, 34) != 0, "no payout pays the host");
    }

    /* All 6 txs should sign and verify via key-path */
    TEST_ASSERT(factory_sign_all(f), "sign all");

    for (size_t i = 0; i < f->n_nodes; i++) {
        TEST_ASSERT(f->nodes[i].is_signed, "node signed");
    }

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Revocation checksig leaf test ---- */

int test_revocation_checksig_leaf(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    TEST_ASSERT(make_keypairs(ctx, kps), "make keypairs");

    /* Use first keypair as revocation key */
    secp256k1_pubkey rev_pub;
    secp256k1_keypair_pub(ctx, &rev_pub, &kps[0]);
    secp256k1_xonly_pubkey rev_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &rev_xonly, NULL, &rev_pub);

    tapscript_leaf_t leaf;
    TEST_ASSERT(tapscript_build_revocation_checksig(&leaf, &rev_xonly, ctx),
                "build revocation checksig leaf");

    /* Script: OP_PUSHBYTES_32(0x20) || key(32) || OP_CHECKSIG(0xac) = 34 bytes */
    TEST_ASSERT_EQ(leaf.script_len, 34, "script length");
    TEST_ASSERT_EQ(leaf.script[0], 0x20, "OP_PUSHBYTES_32");
    TEST_ASSERT_EQ(leaf.script[33], 0xac, "OP_CHECKSIG");

    /* Verify key bytes match serialized xonly key */
    unsigned char key_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, key_ser, &rev_xonly);
    TEST_ASSERT(memcmp(leaf.script + 1, key_ser, 32) == 0, "key matches");

    /* Leaf hash should be non-zero */
    unsigned char zero[32] = {0};
    TEST_ASSERT(memcmp(leaf.leaf_hash, zero, 32) != 0, "leaf hash non-zero");

    secp256k1_context_destroy(ctx);
    return 1;
}
