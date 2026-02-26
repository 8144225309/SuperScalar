#include "superscalar/tapscript.h"
#include "superscalar/factory.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);

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
    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.cltv_timeout = 1000;  /* some block height */
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree with timeout");
    TEST_ASSERT_EQ(f.n_nodes, 6, "6 nodes");

    /* All non-root nodes should have taptree (staggered CLTVs) */
    TEST_ASSERT(f.nodes[0].has_taptree == 0, "kickoff_root no taptree");
    TEST_ASSERT(f.nodes[1].has_taptree == 1, "state_root has taptree");
    TEST_ASSERT(f.nodes[2].has_taptree == 1, "kickoff_left has taptree");
    TEST_ASSERT(f.nodes[3].has_taptree == 1, "kickoff_right has taptree");
    TEST_ASSERT(f.nodes[4].has_taptree == 1, "state_left has taptree");
    TEST_ASSERT(f.nodes[5].has_taptree == 1, "state_right has taptree");

    /* Verify per-node staggered CLTV values */
    TEST_ASSERT_EQ(f.nodes[1].cltv_timeout, 1000, "state_root cltv = 1000 (root)");
    TEST_ASSERT_EQ(f.nodes[2].cltv_timeout, 995, "kickoff_left cltv = 995 (mid)");
    TEST_ASSERT_EQ(f.nodes[3].cltv_timeout, 995, "kickoff_right cltv = 995 (mid)");
    TEST_ASSERT_EQ(f.nodes[4].cltv_timeout, 990, "state_left cltv = 990 (leaf)");
    TEST_ASSERT_EQ(f.nodes[5].cltv_timeout, 990, "state_right cltv = 990 (leaf)");

    /* Build factory WITHOUT cltv_timeout for comparison */
    factory_t f2;
    factory_init(&f2, ctx, kps, 5, 2, 4);
    f2.cltv_timeout = 0;
    factory_set_funding(&f2, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f2), "build tree without timeout");

    /* spending_spk of taptree nodes should differ between f and f2 */
    TEST_ASSERT(memcmp(f.nodes[1].spending_spk, f2.nodes[1].spending_spk, 34) != 0,
                "state_root spk differs with taptree");
    TEST_ASSERT(memcmp(f.nodes[2].spending_spk, f2.nodes[2].spending_spk, 34) != 0,
                "kickoff_left spk differs with taptree");
    TEST_ASSERT(memcmp(f.nodes[4].spending_spk, f2.nodes[4].spending_spk, 34) != 0,
                "state_left spk differs with taptree");

    /* spending_spk of kickoff_root should be SAME (no taptree on either) */
    TEST_ASSERT(memcmp(f.nodes[0].spending_spk, f2.nodes[0].spending_spk, 34) == 0,
                "kickoff_root spk same without taptree");

    /* All 6 txs should sign and verify via key-path */
    TEST_ASSERT(factory_sign_all(&f), "sign all with timeout");

    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node signed");

        /* Recompute sighash and verify */
        const unsigned char *prev_spk;
        size_t prev_spk_len;
        uint64_t prev_amount;

        if (node->parent_index < 0) {
            prev_spk = f.funding_spk;
            prev_spk_len = f.funding_spk_len;
            prev_amount = f.funding_amount_sats;
        } else {
            factory_node_t *parent = &f.nodes[node->parent_index];
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

    factory_free(&f);
    factory_free(&f2);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Regtest helper: find vout matching expected_spk ---- */

static int find_funding_vout(
    regtest_t *rt,
    const char *txid_hex,
    const unsigned char *expected_spk,
    size_t expected_spk_len,
    int *vout_out,
    uint64_t *amount_out
) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\" true true", txid_hex);
    char *result = regtest_exec(rt, "gettransaction", params);
    if (!result) return 0;

    char expected_hex[69];
    hex_encode(expected_spk, expected_spk_len, expected_hex);

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return 0;

    cJSON *decoded = cJSON_GetObjectItem(json, "decoded");
    if (!decoded) { cJSON_Delete(json); return 0; }

    cJSON *vouts = cJSON_GetObjectItem(decoded, "vout");
    if (!vouts || !cJSON_IsArray(vouts)) { cJSON_Delete(json); return 0; }

    int found = 0;
    int arr_size = cJSON_GetArraySize(vouts);
    for (int i = 0; i < arr_size; i++) {
        cJSON *vout_obj = cJSON_GetArrayItem(vouts, i);
        if (!vout_obj) continue;

        cJSON *n_item = cJSON_GetObjectItem(vout_obj, "n");
        cJSON *value_item = cJSON_GetObjectItem(vout_obj, "value");
        cJSON *spk_obj = cJSON_GetObjectItem(vout_obj, "scriptPubKey");
        if (!n_item || !value_item || !spk_obj) continue;

        cJSON *hex_item = cJSON_GetObjectItem(spk_obj, "hex");
        if (!hex_item || !cJSON_IsString(hex_item)) continue;

        if (strcmp(hex_item->valuestring, expected_hex) == 0) {
            *vout_out = n_item->valueint;
            *amount_out = (uint64_t)(value_item->valuedouble * 100000000.0 + 0.5);
            found = 1;
            break;
        }
    }

    cJSON_Delete(json);
    return found;
}

/* ---- Regtest helper: get current block height ---- */

static int get_block_height(regtest_t *rt) {
    char *result = regtest_exec(rt, "getblockcount", "");
    if (!result) return -1;
    int h = atoi(result);
    free(result);
    return h;
}

/* ---- Regtest test 6: timeout spend ---- */

int test_regtest_timeout_spend(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_timeout");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Get LSP xonly pubkey */
    secp256k1_xonly_pubkey lsp_xonly;
    if (!secp256k1_keypair_xonly_pub(ctx, &lsp_xonly, NULL, &kps[0])) return 0;

    /* Compute funding spk (5-of-5, key-path-only for the funding output) */
    secp256k1_pubkey all_pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &all_pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t fund_ka;
    musig_aggregate_keys(ctx, &fund_ka, all_pks, 5);

    unsigned char ik_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ik_ser, &fund_ka.agg_pubkey)) return 0;
    unsigned char fund_tweak[32];
    sha256_tagged("TapTweak", ik_ser, 32, fund_tweak);

    musig_keyagg_t fund_tmp = fund_ka;
    secp256k1_pubkey fund_tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &fund_tweaked_pk,
                                             &fund_tmp.cache, fund_tweak)) return 0;
    secp256k1_xonly_pubkey fund_tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &fund_tweaked_xonly, NULL,
                                         &fund_tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &fund_tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tw_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tw_ser, &fund_tweaked_xonly)) return 0;
    char key_hex[65];
    hex_encode(tw_ser, 32, key_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    {
        char *dstart = strstr(desc_result, "\"descriptor\"");
        TEST_ASSERT(dstart != NULL, "find descriptor");
        dstart = strchr(dstart + 12, '"');
        TEST_ASSERT(dstart != NULL, "descriptor value start");
        dstart++;
        char *dend = strchr(dstart, '"');
        TEST_ASSERT(dend != NULL, "descriptor value end");
        size_t dlen = (size_t)(dend - dstart);
        memcpy(checksummed_desc, dstart, dlen);
        checksummed_desc[dlen] = '\0';
    }
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char factory_addr[128];
    {
        char *start = strchr(addr_result, '"');
        TEST_ASSERT(start != NULL, "addr quote");
        start++;
        char *end = strchr(start, '"');
        TEST_ASSERT(end != NULL, "addr end quote");
        size_t len = (size_t)(end - start);
        memcpy(factory_addr, start, len);
        factory_addr[len] = '\0';
    }
    free(addr_result);

    /* Fund factory */
    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    /* Find factory vout */
    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    TEST_ASSERT(find_funding_vout(&rt, funding_txid_hex, fund_spk, 34,
                                   &found_vout, &fund_amount),
                "find factory vout");
    printf("  Factory funded: %s vout=%d amount=%lu\n",
           funding_txid_hex, found_vout, (unsigned long)fund_amount);

    /* Set cltv_timeout = current_height + 10 */
    int current_height = get_block_height(&rt);
    TEST_ASSERT(current_height > 0, "get block height");
    uint32_t cltv_timeout = (uint32_t)current_height + 10;
    printf("  Current height=%d, cltv_timeout=%u\n", current_height, cltv_timeout);

    /* Init factory with timeout, advance to max state (all delays = 0) */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);
    f.cltv_timeout = cltv_timeout;

    for (int i = 0; i < 15; i++)
        dw_counter_advance(&f.counter);

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");
    printf("  Tree built: %zu nodes, kickoff_left has_taptree=%d\n",
           f.n_nodes, f.nodes[2].has_taptree);

    /* Broadcast kickoff_root (node 0), mine 1 block */
    {
        char *tx_hex = (char *)malloc(f.nodes[0].signed_tx.len * 2 + 1);
        hex_encode(f.nodes[0].signed_tx.data, f.nodes[0].signed_tx.len, tx_hex);
        char txid[65];
        int sent = regtest_send_raw_tx(&rt, tx_hex, txid);
        free(tx_hex);
        TEST_ASSERT(sent, "broadcast kickoff_root");
        printf("  Broadcast kickoff_root: %s\n", txid);
    }
    regtest_mine_blocks(&rt, 1, mine_addr);

    /* Broadcast state_root (node 1), mine 1 block (nSeq=0 since maxed) */
    {
        char *tx_hex = (char *)malloc(f.nodes[1].signed_tx.len * 2 + 1);
        hex_encode(f.nodes[1].signed_tx.data, f.nodes[1].signed_tx.len, tx_hex);
        char txid[65];
        int sent = regtest_send_raw_tx(&rt, tx_hex, txid);
        free(tx_hex);
        TEST_ASSERT(sent, "broadcast state_root");
        printf("  Broadcast state_root: %s\n", txid);
    }
    regtest_mine_blocks(&rt, 1, mine_addr);

    /* DON'T broadcast kickoff_left (simulate uncooperative clients).
       Instead, mine until height >= cltv_timeout, then spend via timeout path. */

    /* state_root output 0 is the one we want to spend via timeout.
       It pays to kickoff_left's spending_spk (which has the taptree). */
    factory_node_t *state_root = &f.nodes[1];
    factory_node_t *kickoff_left = &f.nodes[2];

    /* Get state_root txid in display order */
    unsigned char sr_txid_display[32];
    memcpy(sr_txid_display, state_root->txid, 32);
    reverse_bytes(sr_txid_display, 32);

    /* Mine until we pass cltv_timeout */
    int height_now = get_block_height(&rt);
    int blocks_needed = (int)cltv_timeout - height_now;
    if (blocks_needed > 0) {
        printf("  Mining %d blocks to reach cltv_timeout...\n", blocks_needed);
        regtest_mine_blocks(&rt, blocks_needed, mine_addr);
    }

    height_now = get_block_height(&rt);
    printf("  Height after mining: %d (need >= %u)\n", height_now, cltv_timeout);
    TEST_ASSERT(height_now >= (int)cltv_timeout, "height >= cltv_timeout");

    /* Construct timeout tx:
       - Input: state_root txid : vout 0
       - nSequence: 0xFFFFFFFE (enables nLockTime)
       - nLockTime: cltv_timeout
       - Output: LSP's own P2TR address (minus fee) */

    /* LSP output key (single key, key-path-only) */
    secp256k1_xonly_pubkey lsp_tweaked;
    unsigned char lsp_out_spk[34];
    {
        unsigned char lsp_ik[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, lsp_ik, &lsp_xonly)) return 0;
        unsigned char lsp_tw[32];
        sha256_tagged("TapTweak", lsp_ik, 32, lsp_tw);
        secp256k1_pubkey lsp_tw_full;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &lsp_tw_full, &lsp_xonly, lsp_tw)) return 0;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_tweaked, NULL, &lsp_tw_full)) return 0;
        build_p2tr_script_pubkey(lsp_out_spk, &lsp_tweaked);
    }

    uint64_t timeout_output_amount = state_root->outputs[0].amount_sats - 500;

    tx_output_t timeout_out;
    timeout_out.amount_sats = timeout_output_amount;
    memcpy(timeout_out.script_pubkey, lsp_out_spk, 34);
    timeout_out.script_pubkey_len = 34;

    /* Build unsigned timeout tx with nLockTime */
    tx_buf_t timeout_unsigned;
    tx_buf_init(&timeout_unsigned, 256);
    TEST_ASSERT(build_unsigned_tx_locktime(&timeout_unsigned, NULL,
                                            state_root->txid, 0,
                                            0xFFFFFFFE, cltv_timeout,
                                            &timeout_out, 1),
                "build timeout tx");

    /* Compute script-path sighash */
    unsigned char timeout_sighash[32];
    TEST_ASSERT(compute_tapscript_sighash(timeout_sighash,
                    timeout_unsigned.data, timeout_unsigned.len,
                    0,
                    kickoff_left->spending_spk, kickoff_left->spending_spk_len,
                    state_root->outputs[0].amount_sats,
                    0xFFFFFFFE,
                    &kickoff_left->timeout_leaf),
                "compute timeout sighash");

    /* Sign with LSP private key (single Schnorr sig, no MuSig) */
    unsigned char timeout_sig[64];
    {
        unsigned char lsp_seckey[32];
        if (!secp256k1_keypair_sec(ctx, lsp_seckey, &kps[0])) return 0;

        secp256k1_keypair lsp_signkp;
        if (!secp256k1_keypair_create(ctx, &lsp_signkp, lsp_seckey)) return 0;
        memset(lsp_seckey, 0, 32);

        /* Sign with BIP-340 schnorrsig */
        unsigned char aux_rand[32];
        memset(aux_rand, 0x42, 32);
        int sig_ok = secp256k1_schnorrsig_sign32(ctx, timeout_sig, timeout_sighash,
                                                   &lsp_signkp, aux_rand);
        TEST_ASSERT(sig_ok, "schnorr sign timeout");

        /* Verify against the LSP xonly pubkey (not the tweaked one!) */
        int verify_ok = secp256k1_schnorrsig_verify(ctx, timeout_sig, timeout_sighash,
                                                      32, &lsp_xonly);
        TEST_ASSERT(verify_ok, "verify timeout sig");
    }

    /* Build control block */
    unsigned char control_block[33];
    size_t cb_len = 0;
    TEST_ASSERT(tapscript_build_control_block(control_block, &cb_len,
                    kickoff_left->output_parity,
                    &kickoff_left->keyagg.agg_pubkey, ctx),
                "build control block");

    /* Finalize with script-path witness */
    tx_buf_t timeout_signed;
    tx_buf_init(&timeout_signed, 512);
    TEST_ASSERT(finalize_script_path_tx(&timeout_signed,
                    timeout_unsigned.data, timeout_unsigned.len,
                    timeout_sig,
                    kickoff_left->timeout_leaf.script,
                    kickoff_left->timeout_leaf.script_len,
                    control_block, cb_len),
                "finalize script path tx");

    /* Broadcast timeout tx */
    char *timeout_hex = (char *)malloc(timeout_signed.len * 2 + 1);
    hex_encode(timeout_signed.data, timeout_signed.len, timeout_hex);

    char timeout_txid[65];
    int sent = regtest_send_raw_tx(&rt, timeout_hex, timeout_txid);
    if (!sent) {
        printf("  FAIL: timeout tx broadcast failed\n");
        printf("  Tx hex: %s\n", timeout_hex);
    }
    free(timeout_hex);
    TEST_ASSERT(sent, "broadcast timeout tx");
    printf("  Broadcast timeout tx: %s\n", timeout_txid);

    /* Mine 1 block and verify confirmed */
    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, timeout_txid);
    printf("  Timeout tx confirmations: %d\n", conf);
    TEST_ASSERT(conf > 0, "timeout tx confirmed");

    printf("  Timeout script-path spend confirmed on regtest!\n");

    tx_buf_free(&timeout_unsigned);
    tx_buf_free(&timeout_signed);
    factory_free(&f);
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

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.cltv_timeout = 1000;
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT_EQ(f.n_nodes, 6, "6 nodes");

    /* Verify each taptree node has correct CLTV in its timeout_leaf script */
    for (size_t i = 1; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->has_taptree == 1, "node has taptree");
        TEST_ASSERT(node->timeout_leaf.script_len > 0, "script non-empty");

        /* Verify OP_CLTV (0xb1) present */
        int found = 0;
        for (size_t j = 0; j < node->timeout_leaf.script_len; j++) {
            if (node->timeout_leaf.script[j] == 0xb1) { found = 1; break; }
        }
        TEST_ASSERT(found, "OP_CLTV in script");
    }

    /* Verify CLTV ordering: leaf < mid < root */
    TEST_ASSERT(f.nodes[4].cltv_timeout < f.nodes[2].cltv_timeout,
                "leaf cltv < mid cltv");
    TEST_ASSERT(f.nodes[5].cltv_timeout < f.nodes[3].cltv_timeout,
                "leaf cltv < mid cltv (right)");
    TEST_ASSERT(f.nodes[2].cltv_timeout < f.nodes[1].cltv_timeout,
                "mid cltv < root cltv");

    /* Verify exact values: step=5 */
    TEST_ASSERT_EQ(f.nodes[1].cltv_timeout, 1000, "state_root = base");
    TEST_ASSERT_EQ(f.nodes[2].cltv_timeout, 995,  "kickoff_left = base-5");
    TEST_ASSERT_EQ(f.nodes[3].cltv_timeout, 995,  "kickoff_right = base-5");
    TEST_ASSERT_EQ(f.nodes[4].cltv_timeout, 990,  "state_left = base-10");
    TEST_ASSERT_EQ(f.nodes[5].cltv_timeout, 990,  "state_right = base-10");

    /* All 6 txs should sign and verify via key-path */
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    for (size_t i = 0; i < f.n_nodes; i++) {
        TEST_ASSERT(f.nodes[i].is_signed, "node signed");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}
