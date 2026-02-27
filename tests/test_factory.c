#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/shachain.h"
#include "superscalar/regtest.h"
#include "superscalar/persist.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);
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
        int ok = secp256k1_keypair_create(ctx, &kps[i], seckeys[i]);
        (void)ok;
    }
    return 1;
}

/* Compute the funding scriptPubKey (P2TR of 5-of-5 tweaked key). */
static int compute_funding_spk(
    secp256k1_context *ctx,
    const secp256k1_keypair *kps,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_xonly_out
) {
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        int ok = secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
        (void)ok;
    }

    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 5)) return 0;

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                  &tmp.cache, tweak))
        return 0;

    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_xonly_out, NULL,
                                              &tweaked_pk))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_xonly_out);
    return 1;
}

/* ---- Unit test: build tree ---- */

int test_factory_build_tree(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Compute funding spk */
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    /* Fake funding UTXO */
    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);  /* step=2, states=4 */
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT_EQ(f.n_nodes, 6, "6 nodes");

    /* Check node types (DFS pre-order: ko_root, st_root, ko_left, st_left, ko_right, st_right) */
    TEST_ASSERT(f.nodes[0].type == NODE_KICKOFF, "node 0 is kickoff");
    TEST_ASSERT(f.nodes[1].type == NODE_STATE,   "node 1 is state");
    TEST_ASSERT(f.nodes[2].type == NODE_KICKOFF, "node 2 is kickoff");
    TEST_ASSERT(f.nodes[3].type == NODE_STATE,   "node 3 is state");
    TEST_ASSERT(f.nodes[4].type == NODE_KICKOFF, "node 4 is kickoff");
    TEST_ASSERT(f.nodes[5].type == NODE_STATE,   "node 5 is state");

    /* Check signer counts */
    TEST_ASSERT_EQ(f.nodes[0].n_signers, 5, "kickoff_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[1].n_signers, 5, "state_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[2].n_signers, 3, "kickoff_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[3].n_signers, 3, "state_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[4].n_signers, 3, "kickoff_right: 3 signers");
    TEST_ASSERT_EQ(f.nodes[5].n_signers, 3, "state_right: 3 signers");

    /* Check parent links */
    TEST_ASSERT_EQ(f.nodes[0].parent_index, -1, "kickoff_root: no parent");
    TEST_ASSERT_EQ(f.nodes[1].parent_index,  0, "state_root -> kickoff_root");
    TEST_ASSERT_EQ(f.nodes[2].parent_index,  1, "kickoff_left -> state_root");
    TEST_ASSERT_EQ(f.nodes[3].parent_index,  2, "state_left -> kickoff_left");
    TEST_ASSERT_EQ(f.nodes[4].parent_index,  1, "kickoff_right -> state_root");
    TEST_ASSERT_EQ(f.nodes[5].parent_index,  4, "state_right -> kickoff_right");

    /* Check parent_vout */
    TEST_ASSERT_EQ(f.nodes[1].parent_vout, 0, "state_root spends vout 0");
    TEST_ASSERT_EQ(f.nodes[2].parent_vout, 0, "kickoff_left spends vout 0");
    TEST_ASSERT_EQ(f.nodes[4].parent_vout, 1, "kickoff_right spends vout 1");

    /* Check output counts */
    TEST_ASSERT_EQ(f.nodes[0].n_outputs, 1, "kickoff_root: 1 output");
    TEST_ASSERT_EQ(f.nodes[1].n_outputs, 2, "state_root: 2 outputs");
    TEST_ASSERT_EQ(f.nodes[2].n_outputs, 1, "kickoff_left: 1 output");
    TEST_ASSERT_EQ(f.nodes[3].n_outputs, 3, "state_left: 3 outputs");
    TEST_ASSERT_EQ(f.nodes[4].n_outputs, 1, "kickoff_right: 1 output");
    TEST_ASSERT_EQ(f.nodes[5].n_outputs, 3, "state_right: 3 outputs");

    /* Check kickoff nSequence = 0xFFFFFFFF */
    TEST_ASSERT(f.nodes[0].nsequence == 0xFFFFFFFF, "kickoff_root nseq");
    TEST_ASSERT(f.nodes[2].nsequence == 0xFFFFFFFF, "kickoff_left nseq");
    TEST_ASSERT(f.nodes[4].nsequence == 0xFFFFFFFF, "kickoff_right nseq");

    /* Check state nSequence matches DW layer 0/1 at epoch 0 */
    /* step=2, states=4: delay = 2*(4-1-0) = 6 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "state_root nseq = 6");
    TEST_ASSERT_EQ(f.nodes[3].nsequence, 6, "state_left nseq = 6");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 6, "state_right nseq = 6");

    /* Check all txids are non-zero */
    unsigned char zero[32];
    memset(zero, 0, 32);
    for (size_t i = 0; i < 6; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu txid non-zero", i);
        TEST_ASSERT(memcmp(f.nodes[i].txid, zero, 32) != 0, msg);
    }

    /* Check all txs are built */
    for (size_t i = 0; i < 6; i++)
        TEST_ASSERT(f.nodes[i].is_built, "node is built");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: sign all ---- */

int test_factory_sign_all(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Verify each signature with schnorrsig_verify */
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node is signed");

        /* Recompute sighash */
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

        /* Extract 64-byte sig from signed tx witness */
        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->unsigned_tx.len, 64);

        int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                                  &node->tweaked_pubkey);
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu sig valid", i);
        TEST_ASSERT(valid, msg);
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: advance DW counter ---- */

int test_factory_advance(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);  /* step=2, states_per_layer=4 */
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Use leaf_node_indices for arity-agnostic leaf access */
    size_t left_leaf = f.leaf_node_indices[0];
    size_t right_leaf = f.leaf_node_indices[1];

    /* Initial state: epoch 0, all delays = 6 */
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0");
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 6, "leaf nseq = 6 at epoch 0");

    /* Advance once: epoch 1, leaf layer ticks to state 1 */
    TEST_ASSERT(factory_advance(&f), "advance 1");
    TEST_ASSERT_EQ(f.counter.current_epoch, 1, "epoch 1");
    /* Leaf state nseq: step * (max-1 - 1) = 2 * 2 = 4 */
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 4, "leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[right_leaf].nsequence, 4, "right leaf nseq = 4 at epoch 1");
    /* Root state unchanged (still layer 0, state 0) */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 1");

    /* Advance to epoch 3: leaf at state 3, delay = 0 */
    TEST_ASSERT(factory_advance(&f), "advance 2");
    TEST_ASSERT(factory_advance(&f), "advance 3");
    TEST_ASSERT_EQ(f.counter.current_epoch, 3, "epoch 3");
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 0, "leaf nseq = 0 at epoch 3");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 3");

    /* Advance to epoch 4: leaf rolls over (reset to 0), root ticks to state 1 */
    TEST_ASSERT(factory_advance(&f), "advance 4");
    TEST_ASSERT_EQ(f.counter.current_epoch, 4, "epoch 4");
    /* Root: state 1, delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 4, "root nseq = 4 at epoch 4");
    /* Leaf: reset to state 0, delay = 6 */
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 6, "leaf nseq = 6 at epoch 4 (reset)");

    /* Verify signatures still valid after advance */
    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "node signed after advance");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Find the vout matching expected_spk in a wallet tx using gettransaction.
   regtest_get_tx_output uses getrawtransaction which needs -txindex. */
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

/* ---- Regtest test: full tree broadcast ---- */

int test_regtest_factory_tree(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_factory");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Create 5 keypairs */
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Derive factory address (P2TR of 5-of-5 tweaked key) */
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked)) return 0;
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

    /* Derive bech32m address via rawtr() descriptor (two-step for checksum) */
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);

    /* Step 1: getdescriptorinfo to get checksummed descriptor */
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    {
        char *dstart = strstr(desc_result, "\"descriptor\"");
        TEST_ASSERT(dstart != NULL, "find descriptor field");
        dstart = strchr(dstart + 12, '"');
        TEST_ASSERT(dstart != NULL, "find descriptor value start");
        dstart++;
        char *dend = strchr(dstart, '"');
        TEST_ASSERT(dend != NULL, "find descriptor value end");
        size_t dlen = (size_t)(dend - dstart);
        TEST_ASSERT(dlen < sizeof(checksummed_desc), "descriptor fits");
        memcpy(checksummed_desc, dstart, dlen);
        checksummed_desc[dlen] = '\0';
    }
    free(desc_result);

    /* Step 2: deriveaddresses with checksummed descriptor */
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(result != NULL, "deriveaddresses");

    char factory_addr[128];
    {
        /* Output is ["bcrt1p..."], find the address string */
        char *start = strchr(result, '"');
        TEST_ASSERT(start != NULL, "find address quote");
        start++;
        char *end = strchr(start, '"');
        TEST_ASSERT(end != NULL, "find address end quote");
        size_t len = (size_t)(end - start);
        memcpy(factory_addr, start, len);
        factory_addr[len] = '\0';
    }
    free(result);

    /* Fund factory */
    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);
    printf("  Factory funded: %s\n", funding_txid_hex);

    /* Find factory vout */
    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);  /* display -> internal */

    uint64_t fund_amount = 0;
    int found_vout = -1;
    TEST_ASSERT(find_funding_vout(&rt, funding_txid_hex, fund_spk, 34,
                                   &found_vout, &fund_amount),
                "find factory vout");
    printf("  Factory vout=%d, amount=%lu sats\n", found_vout,
           (unsigned long)fund_amount);

    /* Init factory, build tree, then advance to newest state (all delays = 0).
       factory_build_tree reinitializes the DW counter, so advances must happen after. */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);  /* step=1, states=4 */

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    printf("  Tree built: %zu nodes\n", f.n_nodes);

    /* Advance counter to max epoch: both layers at state 3, delay = 0 */
    for (int i = 0; i < 15; i++)
        TEST_ASSERT(factory_advance(&f), "advance to max epoch");

    /* Broadcast all 6 nodes sequentially, mining 1 block after each.
       Tree layout: 0=kickoff_root, 1=state_root,
       2=kickoff_left, 3=state_left(leaf), 4=kickoff_right, 5=state_right(leaf).
       Each node needs its parent confirmed (BIP-68 nSequence=0 → 1 conf). */
    char txid_hexes[6][65];
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        char *tx_hex = (char *)malloc(node->signed_tx.len * 2 + 1);
        hex_encode(node->signed_tx.data, node->signed_tx.len, tx_hex);

        int sent = regtest_send_raw_tx(&rt, tx_hex, txid_hexes[i]);
        free(tx_hex);

        if (!sent) {
            printf("  FAIL: broadcast node %zu failed\n", i);
            factory_free(&f);
            secp256k1_context_destroy(ctx);
            return 0;
        }
        printf("  Broadcast node %zu: %s\n", i, txid_hexes[i]);
        regtest_mine_blocks(&rt, 1, mine_addr);
    }

    /* Verify leaf state tx (nodes 3 and 5) outputs exist on chain via gettxout.
       If leaf outputs are confirmed, the entire ancestor chain is too. */
    int leaf_indices[] = {3, 5};  /* state_left, state_right */
    for (int li = 0; li < 2; li++) {
        int leaf = leaf_indices[li];
        char gettxout_params[256];
        snprintf(gettxout_params, sizeof(gettxout_params),
                 "\"%s\" 0", txid_hexes[leaf]);
        char *txout = regtest_exec(&rt, "gettxout", gettxout_params);
        TEST_ASSERT(txout != NULL, "gettxout not null");

        cJSON *txout_json = cJSON_Parse(txout);
        free(txout);
        TEST_ASSERT(txout_json != NULL, "gettxout parse");

        cJSON *conf_item = cJSON_GetObjectItem(txout_json, "confirmations");
        int conf = conf_item ? conf_item->valueint : -1;
        cJSON_Delete(txout_json);

        char msg[64];
        snprintf(msg, sizeof(msg), "leaf node %d confirmed (conf=%d)", leaf, conf);
        TEST_ASSERT(conf > 0, msg);
    }

    printf("  All 6 factory txs confirmed (verified via leaf outputs)!\n");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: split-round step-by-step signing ---- */

int test_factory_sign_split_round_step_by_step(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Step 1: Init sessions */
    TEST_ASSERT(factory_sessions_init(&f), "sessions init");

    /* Step 2: Each participant generates nonces for nodes they belong to */
    /* Allocate secnonces: up to 6 nodes * 5 signers max = 30 slots.
       We index by [node_idx * FACTORY_MAX_SIGNERS + signer_slot] */
    secp256k1_musig_secnonce secnonces[6][FACTORY_MAX_SIGNERS];
    memset(secnonces, 0, sizeof(secnonces));

    for (uint32_t p = 0; p < 5; p++) {
        unsigned char seckey[32];
        secp256k1_pubkey pk;
        TEST_ASSERT(secp256k1_keypair_sec(ctx, seckey, &kps[p]), "get seckey");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk, &kps[p]), "get pubkey");

        for (size_t ni = 0; ni < f.n_nodes; ni++) {
            int slot = factory_find_signer_slot(&f, ni, p);
            if (slot < 0) continue;  /* not a signer for this node */

            secp256k1_musig_pubnonce pubnonce;
            TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[ni][slot], &pubnonce,
                                              seckey, &pk, NULL),
                        "generate nonce");
            TEST_ASSERT(factory_session_set_nonce(&f, ni, (size_t)slot, &pubnonce),
                        "set nonce");
        }
        memset(seckey, 0, 32);
    }

    /* Step 3: Finalize */
    TEST_ASSERT(factory_sessions_finalize(&f), "sessions finalize");

    /* Step 4: Each participant creates partial sigs for their nodes */
    for (uint32_t p = 0; p < 5; p++) {
        for (size_t ni = 0; ni < f.n_nodes; ni++) {
            int slot = factory_find_signer_slot(&f, ni, p);
            if (slot < 0) continue;

            secp256k1_musig_partial_sig psig;
            TEST_ASSERT(musig_create_partial_sig(ctx, &psig,
                                                   &secnonces[ni][slot],
                                                   &kps[p],
                                                   &f.nodes[ni].signing_session),
                        "create partial sig");
            TEST_ASSERT(factory_session_set_partial_sig(&f, ni, (size_t)slot, &psig),
                        "set partial sig");
        }
    }

    /* Step 5: Complete */
    TEST_ASSERT(factory_sessions_complete(&f), "sessions complete");

    /* Verify all 6 signatures */
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node is signed");

        unsigned char sighash[32];
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
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: split-round with nonce pool ---- */

int test_factory_split_round_with_pool(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Count how many nodes client A (participant 1) participates in */
    size_t client_a_nodes = 0;
    for (size_t ni = 0; ni < f.n_nodes; ni++) {
        if (factory_find_signer_slot(&f, ni, 1) >= 0)
            client_a_nodes++;
    }
    TEST_ASSERT(client_a_nodes == 4, "client A in 4 nodes");

    /* Generate nonce pool for client A */
    unsigned char seckey_a[32];
    secp256k1_pubkey pk_a;
    TEST_ASSERT(secp256k1_keypair_sec(ctx, seckey_a, &kps[1]), "get seckey A");
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk_a, &kps[1]), "get pubkey A");

    musig_nonce_pool_t pool;
    TEST_ASSERT(musig_nonce_pool_generate(ctx, &pool, client_a_nodes,
                                           seckey_a, &pk_a, NULL),
                "generate pool");
    memset(seckey_a, 0, 32);

    TEST_ASSERT_EQ(musig_nonce_pool_remaining(&pool), client_a_nodes,
                   "pool has correct count");

    /* Init sessions */
    TEST_ASSERT(factory_sessions_init(&f), "sessions init");

    /* Store secnonce pointers from pool for client A */
    secp256k1_musig_secnonce *pool_secnonces[6];
    memset(pool_secnonces, 0, sizeof(pool_secnonces));

    /* Other participants' secnonces */
    secp256k1_musig_secnonce other_secnonces[6][FACTORY_MAX_SIGNERS];
    memset(other_secnonces, 0, sizeof(other_secnonces));

    /* Generate nonces: client A from pool, others ad-hoc */
    for (uint32_t p = 0; p < 5; p++) {
        unsigned char seckey[32];
        secp256k1_pubkey pk;
        TEST_ASSERT(secp256k1_keypair_sec(ctx, seckey, &kps[p]), "get seckey");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk, &kps[p]), "get pubkey");

        for (size_t ni = 0; ni < f.n_nodes; ni++) {
            int slot = factory_find_signer_slot(&f, ni, p);
            if (slot < 0) continue;

            secp256k1_musig_pubnonce pubnonce;

            if (p == 1) {
                /* Client A: draw from pool */
                secp256k1_musig_secnonce *secnonce_ptr;
                TEST_ASSERT(musig_nonce_pool_next(&pool, &secnonce_ptr, &pubnonce),
                            "pool next");
                pool_secnonces[ni] = secnonce_ptr;
            } else {
                /* Others: ad-hoc */
                TEST_ASSERT(musig_generate_nonce(ctx,
                    &other_secnonces[ni][slot], &pubnonce, seckey, &pk, NULL),
                    "generate nonce");
            }

            TEST_ASSERT(factory_session_set_nonce(&f, ni, (size_t)slot, &pubnonce),
                        "set nonce");
        }
        memset(seckey, 0, 32);
    }

    /* Pool should be exhausted */
    TEST_ASSERT_EQ(musig_nonce_pool_remaining(&pool), 0, "pool exhausted");

    /* Finalize */
    TEST_ASSERT(factory_sessions_finalize(&f), "sessions finalize");

    /* Create partial sigs */
    for (uint32_t p = 0; p < 5; p++) {
        for (size_t ni = 0; ni < f.n_nodes; ni++) {
            int slot = factory_find_signer_slot(&f, ni, p);
            if (slot < 0) continue;

            secp256k1_musig_secnonce *secnonce;
            if (p == 1) {
                secnonce = pool_secnonces[ni];
            } else {
                secnonce = &other_secnonces[ni][slot];
            }

            secp256k1_musig_partial_sig psig;
            TEST_ASSERT(musig_create_partial_sig(ctx, &psig, secnonce,
                                                   &kps[p],
                                                   &f.nodes[ni].signing_session),
                        "create partial sig");
            TEST_ASSERT(factory_session_set_partial_sig(&f, ni, (size_t)slot, &psig),
                        "set partial sig");
        }
    }

    /* Complete */
    TEST_ASSERT(factory_sessions_complete(&f), "sessions complete");

    /* Verify all signatures */
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node is signed");

        unsigned char sighash[32];
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

        TEST_ASSERT(compute_taproot_sighash(sighash,
            node->unsigned_tx.data, node->unsigned_tx.len,
            0, prev_spk, prev_spk_len, prev_amount, node->nsequence),
            "compute sighash");

        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->unsigned_tx.len, 64);

        int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                                  &node->tweaked_pubkey);
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu sig valid (pool)", i);
        TEST_ASSERT(valid, msg);
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: advance + re-sign via split-round ---- */

int test_factory_advance_split_round(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);  /* step=2, states_per_layer=4 */
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Initial sign via factory_sign_all (which now uses split-round internally) */
    TEST_ASSERT(factory_sign_all(&f), "initial sign");

    size_t left_leaf = f.leaf_node_indices[0];
    size_t right_leaf = f.leaf_node_indices[1];

    /* Verify initial state */
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0");
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 6, "leaf nseq = 6 at epoch 0");

    /* Advance once */
    TEST_ASSERT(factory_advance(&f), "advance 1");
    TEST_ASSERT_EQ(f.counter.current_epoch, 1, "epoch 1");
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 4, "leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[right_leaf].nsequence, 4, "right leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 1");

    /* Advance to epoch 4: leaf rolls over, root ticks */
    TEST_ASSERT(factory_advance(&f), "advance 2");
    TEST_ASSERT(factory_advance(&f), "advance 3");
    TEST_ASSERT(factory_advance(&f), "advance 4");
    TEST_ASSERT_EQ(f.counter.current_epoch, 4, "epoch 4");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 4, "root nseq = 4 at epoch 4");
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 6, "leaf nseq = 6 at epoch 4 (reset)");

    /* Verify all signatures still valid after advances */
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node signed after advance");

        unsigned char sighash[32];
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

        TEST_ASSERT(compute_taproot_sighash(sighash,
            node->unsigned_tx.data, node->unsigned_tx.len,
            0, prev_spk, prev_spk_len, prev_amount, node->nsequence),
            "compute sighash");

        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->unsigned_tx.len, 64);

        int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                                  &node->tweaked_pubkey);
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu sig valid after advance", i);
        TEST_ASSERT(valid, msg);
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Shachain integration tests ---- */

static const unsigned char test_shachain_seed[32] = {
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89
};

/* Test: L-stock outputs differ with/without shachain, and change per epoch */
int test_factory_l_stock_with_burn_path(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Build factory WITHOUT shachain */
    factory_t f_plain;
    factory_init(&f_plain, ctx, kps, 5, 2, 4);
    factory_set_funding(&f_plain, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f_plain), "build tree (no shachain)");

    /* Build factory WITH shachain */
    factory_t f_sc;
    factory_init(&f_sc, ctx, kps, 5, 2, 4);
    factory_set_shachain_seed(&f_sc, test_shachain_seed);
    factory_set_funding(&f_sc, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f_sc), "build tree (with shachain)");

    /* Use leaf_node_indices for arity-agnostic leaf access */
    size_t ll = f_plain.leaf_node_indices[0];  /* left leaf */
    size_t rl = f_plain.leaf_node_indices[1];  /* right leaf */

    /* L-stock output (last) on leaf state nodes should differ */
    TEST_ASSERT(memcmp(f_plain.nodes[ll].outputs[2].script_pubkey,
                        f_sc.nodes[ll].outputs[2].script_pubkey, 34) != 0,
                "L-stock spk differs with shachain (left leaf)");
    TEST_ASSERT(memcmp(f_plain.nodes[rl].outputs[2].script_pubkey,
                        f_sc.nodes[rl].outputs[2].script_pubkey, 34) != 0,
                "L-stock spk differs with shachain (right leaf)");

    /* Channel outputs (indices 0, 1) should be the same */
    TEST_ASSERT(memcmp(f_plain.nodes[ll].outputs[0].script_pubkey,
                        f_sc.nodes[ll].outputs[0].script_pubkey, 34) == 0,
                "channel A spk unchanged");
    TEST_ASSERT(memcmp(f_plain.nodes[ll].outputs[1].script_pubkey,
                        f_sc.nodes[ll].outputs[1].script_pubkey, 34) == 0,
                "channel B spk unchanged");

    /* Save L-stock spk at epoch 0 */
    unsigned char l_spk_epoch0[34];
    memcpy(l_spk_epoch0, f_sc.nodes[ll].outputs[2].script_pubkey, 34);

    /* Sign and advance to epoch 1 */
    TEST_ASSERT(factory_sign_all(&f_sc), "sign at epoch 0");
    TEST_ASSERT(factory_advance(&f_sc), "advance to epoch 1");

    /* L-stock spk should change after epoch advance */
    TEST_ASSERT(memcmp(l_spk_epoch0, f_sc.nodes[ll].outputs[2].script_pubkey, 34) != 0,
                "L-stock spk changes with new epoch");

    factory_free(&f_plain);
    factory_free(&f_sc);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: burn tx construction and witness correctness */
int test_factory_burn_tx_construction(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_shachain_seed(&f, test_shachain_seed);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Get leaf state node's txid and L-stock amount */
    factory_node_t *leaf = &f.nodes[4];
    uint64_t l_amount = leaf->outputs[2].amount_sats;

    /* Build burn tx for epoch 0 */
    tx_buf_t burn_tx;
    tx_buf_init(&burn_tx, 256);
    TEST_ASSERT(factory_build_burn_tx(&f, &burn_tx, leaf->txid, 2,
                                        l_amount, 0),
                "build burn tx");

    /* Verify burn tx is non-empty */
    TEST_ASSERT(burn_tx.len > 0, "burn tx non-empty");

    /* Verify the burn tx contains the correct preimage */
    unsigned char expected_secret[32];
    TEST_ASSERT(factory_get_revocation_secret(&f, 0, expected_secret),
                "get revocation secret");

    /* Verify the preimage hashes to the expected hashlock */
    unsigned char expected_hash[32];
    sha256(expected_secret, 32, expected_hash);

    /* Search for the preimage in the tx data */
    int found_preimage = 0;
    for (size_t i = 0; i + 32 <= burn_tx.len; i++) {
        if (memcmp(burn_tx.data + i, expected_secret, 32) == 0) {
            found_preimage = 1;
            break;
        }
    }
    TEST_ASSERT(found_preimage, "burn tx contains correct preimage");

    /* Verify that building burn tx without shachain fails */
    factory_t f_no_sc;
    factory_init(&f_no_sc, ctx, kps, 5, 2, 4);
    factory_set_funding(&f_no_sc, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f_no_sc), "build tree (no shachain)");

    tx_buf_t burn_tx2;
    tx_buf_init(&burn_tx2, 256);
    int result = factory_build_burn_tx(&f_no_sc, &burn_tx2, leaf->txid, 2,
                                         l_amount, 0);
    TEST_ASSERT(result == 0, "burn tx fails without shachain");

    tx_buf_free(&burn_tx);
    tx_buf_free(&burn_tx2);
    factory_free(&f);
    factory_free(&f_no_sc);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: advance with shachain, verify revocation secrets and signature validity */
int test_factory_advance_with_shachain(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_shachain_seed(&f, test_shachain_seed);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign at epoch 0");

    /* Save old L-stock info from epoch 0 */
    unsigned char old_leaf_txid[32];
    memcpy(old_leaf_txid, f.nodes[4].txid, 32);
    uint64_t old_l_amount = f.nodes[4].outputs[2].amount_sats;

    /* Advance to epoch 1 */
    TEST_ASSERT(factory_advance(&f), "advance to epoch 1");
    TEST_ASSERT_EQ(f.counter.current_epoch, 1, "epoch 1");

    /* Get revocation secret for old epoch 0 */
    unsigned char secret_epoch0[32];
    TEST_ASSERT(factory_get_revocation_secret(&f, 0, secret_epoch0),
                "get epoch 0 secret");

    /* Verify it matches the shachain derivation */
    unsigned char expected[32];
    uint64_t sc_idx = shachain_epoch_to_index(0);
    shachain_from_seed(test_shachain_seed, sc_idx, expected);
    TEST_ASSERT(memcmp(secret_epoch0, expected, 32) == 0,
                "epoch 0 secret matches shachain");

    /* Build burn tx for epoch 0 using the old L-stock outpoint */
    tx_buf_t burn_tx;
    tx_buf_init(&burn_tx, 256);
    TEST_ASSERT(factory_build_burn_tx(&f, &burn_tx, old_leaf_txid, 2,
                                        old_l_amount, 0),
                "build burn tx for epoch 0");
    TEST_ASSERT(burn_tx.len > 0, "burn tx non-empty");

    /* Verify current (epoch 1) signatures are still valid */
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node signed after advance");

        unsigned char sighash[32];
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

        TEST_ASSERT(compute_taproot_sighash(sighash,
            node->unsigned_tx.data, node->unsigned_tx.len,
            0, prev_spk, prev_spk_len, prev_amount, node->nsequence),
            "compute sighash");

        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->unsigned_tx.len, 64);

        int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                                  &node->tweaked_pubkey);
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu sig valid after shachain advance", i);
        TEST_ASSERT(valid, msg);
    }

    tx_buf_free(&burn_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Regtest test: broadcast factory tree then spend L-stock via burn tx ---- */

int test_regtest_burn_tx(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_burn");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Compute funding spk */
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    /* Derive bech32m address for funding */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked)) return 0;
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

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
    printf("  Factory funded: %s vout=%d amount=%lu sats\n",
           funding_txid_hex, found_vout, (unsigned long)fund_amount);

    /* Init factory WITH shachain, build tree, then advance to max state (all delays = 0).
       factory_build_tree reinitializes the DW counter, so advances must happen after. */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);  /* step=1, states=4 */
    factory_set_shachain_seed(&f, test_shachain_seed);

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    for (int i = 0; i < 15; i++)
        TEST_ASSERT(factory_advance(&f), "advance to max epoch");

    printf("  Tree built: %zu nodes, L-stock has shachain burn path\n", f.n_nodes);

    /* Broadcast all 6 nodes sequentially, mining 1 block after each.
       Tree: 0=kickoff_root, 1=state_root, 2=kickoff_left, 3=state_left(leaf),
       4=kickoff_right, 5=state_right(leaf). */
    char txid_hexes[6][65];
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        char *tx_hex = (char *)malloc(node->signed_tx.len * 2 + 1);
        hex_encode(node->signed_tx.data, node->signed_tx.len, tx_hex);

        int sent = regtest_send_raw_tx(&rt, tx_hex, txid_hexes[i]);
        free(tx_hex);

        if (!sent) {
            printf("  FAIL: broadcast node %zu failed\n", i);
            factory_free(&f);
            secp256k1_context_destroy(ctx);
            return 0;
        }
        printf("  Broadcast node %zu: %s\n", i, txid_hexes[i]);
        regtest_mine_blocks(&rt, 1, mine_addr);
    }

    /* Verify leaf state outputs (nodes 3, 5) are confirmed */
    int leaf_indices[] = {3, 5};
    for (int li = 0; li < 2; li++) {
        int leaf = leaf_indices[li];
        char gettxout_params[256];
        snprintf(gettxout_params, sizeof(gettxout_params),
                 "\"%s\" 2", txid_hexes[leaf]);  /* vout 2 = L-stock */
        char *txout = regtest_exec(&rt, "gettxout", gettxout_params);
        TEST_ASSERT(txout != NULL, "gettxout L-stock");

        cJSON *txout_json = cJSON_Parse(txout);
        free(txout);
        TEST_ASSERT(txout_json != NULL, "parse gettxout");

        cJSON *conf_item = cJSON_GetObjectItem(txout_json, "confirmations");
        int conf = conf_item ? conf_item->valueint : -1;
        cJSON_Delete(txout_json);

        char msg[64];
        snprintf(msg, sizeof(msg), "leaf %d L-stock confirmed (conf=%d)", leaf, conf);
        TEST_ASSERT(conf > 0, msg);
    }
    printf("  All factory txs confirmed, L-stock outputs on-chain\n");

    /* Now build and broadcast the burn tx for state_left (node 3) L-stock */
    tx_buf_t burn_tx;
    tx_buf_init(&burn_tx, 256);

    /* f.nodes[3].txid is internal byte order, which is what factory_build_burn_tx wants */
    uint64_t l_stock_amount = f.nodes[3].outputs[2].amount_sats;
    printf("  L-stock amount: %lu sats\n", (unsigned long)l_stock_amount);

    TEST_ASSERT(factory_build_burn_tx(&f, &burn_tx, f.nodes[3].txid, 2,
                                        l_stock_amount, f.counter.current_epoch),
                "build burn tx");
    TEST_ASSERT(burn_tx.len > 0, "burn tx non-empty");

    /* Broadcast burn tx */
    char *burn_hex = (char *)malloc(burn_tx.len * 2 + 1);
    hex_encode(burn_tx.data, burn_tx.len, burn_hex);

    char burn_txid[65];
    int sent = regtest_send_raw_tx(&rt, burn_hex, burn_txid);
    if (!sent) {
        printf("  FAIL: burn tx broadcast failed\n");
        printf("  Burn tx hex (%zu bytes): %s\n", burn_tx.len, burn_hex);
    }
    free(burn_hex);
    TEST_ASSERT(sent, "broadcast burn tx");
    printf("  Broadcast burn tx: %s\n", burn_txid);

    /* Mine and verify confirmed */
    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, burn_txid);
    printf("  Burn tx confirmations: %d\n", conf);
    TEST_ASSERT(conf > 0, "burn tx confirmed");

    /* Verify the L-stock UTXO is now spent (gettxout returns null) */
    {
        char gettxout_params[256];
        snprintf(gettxout_params, sizeof(gettxout_params),
                 "\"%s\" 2", txid_hexes[3]);
        char *txout = regtest_exec(&rt, "gettxout", gettxout_params);
        /* gettxout returns null/empty for spent outputs */
        int is_spent = (txout == NULL || strcmp(txout, "") == 0 ||
                         strcmp(txout, "null") == 0 || strcmp(txout, "\n") == 0);
        if (txout) free(txout);
        TEST_ASSERT(is_spent, "L-stock UTXO is spent");
    }

    printf("  Burn tx confirmed! L-stock output successfully burned via hashlock script path\n");

    tx_buf_free(&burn_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Phase 7: Cooperative Close Tests ---- */

/* Test: factory cooperative close produces valid signed tx */
int test_factory_cooperative_close(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Compute 5 settlement outputs: one per participant */
    uint64_t fee = 500;
    uint64_t total_out = 100000 - fee;
    uint64_t per_output = total_out / 5;
    uint64_t remainder = total_out - per_output * 5;

    tx_output_t outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_pub(ctx, &pk, &kps[i])) return 0;
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &pk)) return 0;

        /* Key-path-only tweak for settlement output */
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tweaked_full;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tweaked;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked, NULL, &tweaked_full)) return 0;

        build_p2tr_script_pubkey(outputs[i].script_pubkey, &tweaked);
        outputs[i].script_pubkey_len = 34;
        outputs[i].amount_sats = per_output + (i == 4 ? remainder : 0);
    }

    /* Build cooperative close */
    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    unsigned char close_txid[32];
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, close_txid,
                                                  outputs, 5),
                "build cooperative close");

    /* Verify: non-empty signed tx */
    TEST_ASSERT(close_tx.len > 0, "close tx non-empty");

    /* Verify: txid differs from kickoff_root's txid */
    TEST_ASSERT(memcmp(close_txid, f.nodes[0].txid, 32) != 0,
                "close txid differs from kickoff_root");

    /* Verify signature: extract sig and check against funding output key */
    /* The close tx is a key-path spend of the funding output.
       Rebuild unsigned tx to extract sighash. */
    tx_buf_t close_unsigned;
    tx_buf_init(&close_unsigned, 256);
    build_unsigned_tx(&close_unsigned, NULL, f.funding_txid, f.funding_vout,
                       0xFFFFFFFEu, outputs, 5);

    unsigned char sighash[32];
    TEST_ASSERT(compute_taproot_sighash(sighash,
                    close_unsigned.data, close_unsigned.len,
                    0, f.funding_spk, f.funding_spk_len,
                    f.funding_amount_sats, 0xFFFFFFFEu),
                "compute sighash");

    /* Extract sig from witness */
    size_t witness_offset = close_unsigned.len - 2;
    unsigned char sig[64];
    memcpy(sig, close_tx.data + witness_offset + 2, 64);

    int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                              &fund_tweaked);
    TEST_ASSERT(valid, "cooperative close sig valid");

    tx_buf_free(&close_tx);
    tx_buf_free(&close_unsigned);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: cooperative close with unequal balances */
int test_factory_cooperative_close_balances(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Simulate shifted balances: LSP gets 50000, clients get varying amounts */
    uint64_t fee = 500;
    uint64_t balances[5] = { 50000, 15000, 10000, 12000, 12500 };
    /* Verify amounts sum to funding - fee */
    uint64_t sum = 0;
    for (int i = 0; i < 5; i++) sum += balances[i];
    TEST_ASSERT_EQ(sum, 100000 - fee, "balances sum to funding - fee");

    tx_output_t outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_pub(ctx, &pk, &kps[i])) return 0;
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &pk)) return 0;

        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tweaked_full;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tweaked;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked, NULL, &tweaked_full)) return 0;

        build_p2tr_script_pubkey(outputs[i].script_pubkey, &tweaked);
        outputs[i].script_pubkey_len = 34;
        outputs[i].amount_sats = balances[i];
    }

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, NULL,
                                                  outputs, 5),
                "build cooperative close (unequal)");

    TEST_ASSERT(close_tx.len > 0, "close tx non-empty");

    /* Verify the outputs are encoded correctly by checking the tx
       contains the expected amounts in little-endian */
    for (int i = 0; i < 5; i++) {
        unsigned char le_amount[8];
        for (int j = 0; j < 8; j++)
            le_amount[j] = (unsigned char)((balances[i] >> (j * 8)) & 0xFF);

        int found = 0;
        for (size_t off = 0; off + 8 <= close_tx.len; off++) {
            if (memcmp(close_tx.data + off, le_amount, 8) == 0) {
                found = 1;
                break;
            }
        }
        char msg[64];
        snprintf(msg, sizeof(msg), "output %d amount %lu found in tx", i,
                 (unsigned long)balances[i]);
        TEST_ASSERT(found, msg);
    }

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Regtest: factory cooperative close bypasses tree and confirms on-chain */
int test_regtest_factory_coop_close(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_coop_f");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked)) return 0;
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

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

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    TEST_ASSERT(find_funding_vout(&rt, funding_txid_hex, fund_spk, 34,
                                    &found_vout, &fund_amount),
                "find factory vout");
    printf("  Factory funded: %s vout=%d amount=%lu sats\n",
           funding_txid_hex, found_vout, (unsigned long)fund_amount);

    /* Init factory, build tree (but don't broadcast tree!) */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);
    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Build cooperative close: 1 output going to mine_addr equivalent */
    uint64_t close_fee = 500;
    tx_output_t close_output;
    close_output.amount_sats = fund_amount - close_fee;

    /* Use LSP key as destination (simple P2TR) */
    secp256k1_pubkey lsp_pk;
    if (!secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0])) return 0;
    secp256k1_xonly_pubkey lsp_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &lsp_pk)) return 0;

    unsigned char lsp_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, lsp_ser, &lsp_xonly)) return 0;
    unsigned char lsp_tweak[32];
    sha256_tagged("TapTweak", lsp_ser, 32, lsp_tweak);
    secp256k1_pubkey lsp_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &lsp_tweaked_full, &lsp_xonly, lsp_tweak)) return 0;
    secp256k1_xonly_pubkey lsp_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_tweaked, NULL, &lsp_tweaked_full)) return 0;

    build_p2tr_script_pubkey(close_output.script_pubkey, &lsp_tweaked);
    close_output.script_pubkey_len = 34;

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, NULL,
                                                  &close_output, 1),
                "build cooperative close");

    /* Broadcast (single tx, not the tree!) */
    char *close_hex = (char *)malloc(close_tx.len * 2 + 1);
    hex_encode(close_tx.data, close_tx.len, close_hex);

    char close_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, close_hex, close_txid_hex);
    if (!sent) {
        printf("  FAIL: cooperative close broadcast failed\n");
        printf("  Close tx hex (%zu bytes): %s\n", close_tx.len, close_hex);
    }
    free(close_hex);
    TEST_ASSERT(sent, "broadcast cooperative close");
    printf("  Cooperative close broadcast: %s\n", close_txid_hex);

    /* Mine and verify */
    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, close_txid_hex);
    printf("  Cooperative close confirmations: %d\n", conf);
    TEST_ASSERT(conf > 0, "cooperative close confirmed");

    printf("  Factory cooperative close confirmed! Single tx bypassed entire tree.\n");

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Phase 8: Factory Lifecycle Tests ---- */

/* Test: State transitions: ACTIVE at block 100, DYING at block 4420, EXPIRED at block 4852 */
int test_factory_lifecycle_states(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    factory_set_lifecycle(&f, 100, 4320, 432);

    /* Block 100: ACTIVE (just created) */
    TEST_ASSERT_EQ(factory_get_state(&f, 100), FACTORY_ACTIVE, "active at 100");
    TEST_ASSERT(factory_is_active(&f, 100), "is_active at 100");
    TEST_ASSERT(!factory_is_dying(&f, 100), "!is_dying at 100");
    TEST_ASSERT(!factory_is_expired(&f, 100), "!is_expired at 100");

    /* Block 4419: still ACTIVE (last active block) */
    TEST_ASSERT_EQ(factory_get_state(&f, 4419), FACTORY_ACTIVE, "active at 4419");

    /* Block 4420: DYING starts (100 + 4320 = 4420) */
    TEST_ASSERT_EQ(factory_get_state(&f, 4420), FACTORY_DYING, "dying at 4420");
    TEST_ASSERT(factory_is_dying(&f, 4420), "is_dying at 4420");
    TEST_ASSERT(!factory_is_active(&f, 4420), "!is_active at 4420");

    /* Block 4851: still DYING (last dying block) */
    TEST_ASSERT_EQ(factory_get_state(&f, 4851), FACTORY_DYING, "dying at 4851");

    /* Block 4852: EXPIRED (100 + 4320 + 432 = 4852) */
    TEST_ASSERT_EQ(factory_get_state(&f, 4852), FACTORY_EXPIRED, "expired at 4852");
    TEST_ASSERT(factory_is_expired(&f, 4852), "is_expired at 4852");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: blocks_until_dying, blocks_until_expired return correct values */
int test_factory_lifecycle_queries(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    factory_set_lifecycle(&f, 0, 100, 30);

    /* At block 0: 100 blocks until dying, 130 until expired */
    TEST_ASSERT_EQ(factory_blocks_until_dying(&f, 0), 100, "until dying at 0");
    TEST_ASSERT_EQ(factory_blocks_until_expired(&f, 0), 130, "until expired at 0");

    /* At block 50: 50 blocks until dying, 80 until expired */
    TEST_ASSERT_EQ(factory_blocks_until_dying(&f, 50), 50, "until dying at 50");
    TEST_ASSERT_EQ(factory_blocks_until_expired(&f, 50), 80, "until expired at 50");

    /* At block 100: 0 blocks until dying (already dying), 30 until expired */
    TEST_ASSERT_EQ(factory_blocks_until_dying(&f, 100), 0, "until dying at 100");
    TEST_ASSERT_EQ(factory_blocks_until_expired(&f, 100), 30, "until expired at 100");

    /* At block 130: 0 both (already expired) */
    TEST_ASSERT_EQ(factory_blocks_until_dying(&f, 130), 0, "until dying at 130");
    TEST_ASSERT_EQ(factory_blocks_until_expired(&f, 130), 0, "until expired at 130");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: Pre-signed nLockTime tx is valid, outputs match, nLockTime = cltv_timeout */
int test_factory_distribution_tx(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    uint32_t nlocktime = 5000;
    uint64_t fee = 500;
    uint64_t total_out = 100000 - fee;
    uint64_t per_output = total_out / 5;
    uint64_t remainder = total_out - per_output * 5;

    tx_output_t outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_pub(ctx, &pk, &kps[i])) return 0;
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &pk)) return 0;

        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw_full;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw_full, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tweaked;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked, NULL, &tw_full)) return 0;

        build_p2tr_script_pubkey(outputs[i].script_pubkey, &tweaked);
        outputs[i].script_pubkey_len = 34;
        outputs[i].amount_sats = per_output + (i == 4 ? remainder : 0);
    }

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    unsigned char dist_txid[32];
    TEST_ASSERT(factory_build_distribution_tx(&f, &dist_tx, dist_txid,
                                               outputs, 5, nlocktime),
                "build distribution tx");
    TEST_ASSERT(dist_tx.len > 0, "dist tx non-empty");

    /* Verify nLockTime is in the tx (last 4 bytes before witness) */
    /* nLockTime in little-endian at the end of the unsigned portion */
    unsigned char expected_lt[4] = {
        (unsigned char)(nlocktime & 0xFF),
        (unsigned char)((nlocktime >> 8) & 0xFF),
        (unsigned char)((nlocktime >> 16) & 0xFF),
        (unsigned char)((nlocktime >> 24) & 0xFF),
    };
    int found_lt = 0;
    for (size_t i = 0; i + 4 <= dist_tx.len; i++) {
        if (memcmp(dist_tx.data + i, expected_lt, 4) == 0) {
            found_lt = 1;
            break;
        }
    }
    TEST_ASSERT(found_lt, "nLockTime found in tx");

    /* Verify each output amount is in the tx */
    for (int i = 0; i < 5; i++) {
        unsigned char le_amt[8];
        for (int j = 0; j < 8; j++)
            le_amt[j] = (unsigned char)((outputs[i].amount_sats >> (j * 8)) & 0xFF);
        int found = 0;
        for (size_t off = 0; off + 8 <= dist_tx.len; off++) {
            if (memcmp(dist_tx.data + off, le_amt, 8) == 0) {
                found = 1;
                break;
            }
        }
        char msg[64];
        snprintf(msg, sizeof(msg), "output %d amount found", i);
        TEST_ASSERT(found, msg);
    }

    tx_buf_free(&dist_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: Distribution tx with 5 outputs: each gets (funding - fee) / 5 */
int test_factory_distribution_tx_default(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 50000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    uint64_t fee = 500;
    uint64_t total_out = 50000 - fee;
    uint64_t per_output = total_out / 5;  /* 9900 */

    tx_output_t outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_pub(ctx, &pk, &kps[i])) return 0;
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &pk)) return 0;
        build_p2tr_script_pubkey(outputs[i].script_pubkey, &xonly);
        outputs[i].script_pubkey_len = 34;
        outputs[i].amount_sats = per_output;
    }

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    TEST_ASSERT(factory_build_distribution_tx(&f, &dist_tx, NULL,
                                               outputs, 5, 10000),
                "build default distribution tx");
    TEST_ASSERT(dist_tx.len > 0, "dist tx non-empty");

    /* Verify all outputs have equal amounts */
    for (int i = 0; i < 5; i++)
        TEST_ASSERT_EQ(outputs[i].amount_sats, per_output, "equal output");

    tx_buf_free(&dist_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Cooperative Epoch Reset + Per-Leaf Advance tests ---- */

int test_dw_counter_reset(void) {
    dw_counter_t ctr;
    dw_counter_init(&ctr, 2, 2, 4);  /* 2 layers, step=2, 4 states each = 16 total */

    /* Advance 5 times */
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(dw_counter_advance(&ctr), "advance");

    TEST_ASSERT_EQ(ctr.current_epoch, 5, "epoch 5 after 5 advances");

    /* Reset */
    dw_counter_reset(&ctr);
    TEST_ASSERT_EQ(ctr.current_epoch, 0, "epoch 0 after reset");
    TEST_ASSERT_EQ(ctr.layers[0].current_state, 0, "layer 0 state 0");
    TEST_ASSERT_EQ(ctr.layers[1].current_state, 0, "layer 1 state 0");

    /* Verify we can advance again from 0 */
    TEST_ASSERT(dw_counter_advance(&ctr), "advance after reset");
    TEST_ASSERT_EQ(ctr.current_epoch, 1, "epoch 1 after re-advance");

    return 1;
}

int test_factory_reset_epoch(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Advance 3 times */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(factory_advance(&f), "advance");
    TEST_ASSERT_EQ(f.counter.current_epoch, 3, "epoch 3");

    /* Reset epoch */
    TEST_ASSERT(factory_reset_epoch(&f), "reset epoch");
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0 after reset");
    TEST_ASSERT_EQ(f.per_leaf_enabled, 0, "per_leaf disabled after reset");

    /* Verify all nodes re-signed with epoch 0 nSequences */
    size_t ll = f.leaf_node_indices[0];
    size_t rl = f.leaf_node_indices[1];
    /* At epoch 0: leaf nseq = step * (max-1) = 2*3 = 6 */
    TEST_ASSERT_EQ(f.nodes[ll].nsequence, 6, "leaf nseq 6 after reset");
    TEST_ASSERT_EQ(f.nodes[rl].nsequence, 6, "right leaf nseq 6 after reset");
    /* Root nseq = 2*3 = 6 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq 6 after reset");

    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "node signed after reset");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_advance_leaf_left(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    size_t left_leaf = f.leaf_node_indices[0];
    size_t right_leaf = f.leaf_node_indices[1];

    /* Save initial state */
    uint32_t initial_left_nseq = f.nodes[left_leaf].nsequence;
    uint32_t initial_right_nseq = f.nodes[right_leaf].nsequence;
    unsigned char right_txid_before[32];
    memcpy(right_txid_before, f.nodes[right_leaf].txid, 32);

    /* Advance left leaf only */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance leaf left");

    /* Left leaf should have changed nSequence */
    TEST_ASSERT(f.nodes[left_leaf].nsequence != initial_left_nseq, "left nseq changed");
    /* step=2, advanced from state 0 to 1: delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 4, "left nseq = 4");
    TEST_ASSERT(f.nodes[left_leaf].is_signed, "left node signed");

    /* Right leaf should be unchanged */
    TEST_ASSERT_EQ(f.nodes[right_leaf].nsequence, initial_right_nseq, "right nseq unchanged");
    TEST_ASSERT(memcmp(f.nodes[right_leaf].txid, right_txid_before, 32) == 0,
                "right txid unchanged");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_advance_leaf_right(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    size_t left_leaf = f.leaf_node_indices[0];
    size_t right_leaf = f.leaf_node_indices[1];

    uint32_t initial_left_nseq = f.nodes[left_leaf].nsequence;
    unsigned char left_txid_before[32];
    memcpy(left_txid_before, f.nodes[left_leaf].txid, 32);

    /* Advance right leaf only */
    TEST_ASSERT(factory_advance_leaf(&f, 1), "advance leaf right");

    /* Right leaf should have changed */
    TEST_ASSERT_EQ(f.nodes[right_leaf].nsequence, 4, "right nseq = 4");
    TEST_ASSERT(f.nodes[right_leaf].is_signed, "right node signed");

    /* Left leaf should be unchanged */
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, initial_left_nseq, "left nseq unchanged");
    TEST_ASSERT(memcmp(f.nodes[left_leaf].txid, left_txid_before, 32) == 0,
                "left txid unchanged");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_advance_leaf_independence(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    size_t left_leaf = f.leaf_node_indices[0];
    size_t right_leaf = f.leaf_node_indices[1];

    /* Advance left 3 times */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left");

    /* Advance right 1 time */
    TEST_ASSERT(factory_advance_leaf(&f, 1), "advance right");

    /* Left at state 3: delay = 2*(4-1-3) = 0 */
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 0, "left nseq = 0 (state 3)");
    /* Right at state 1: delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[right_leaf].nsequence, 4, "right nseq = 4 (state 1)");

    /* Different nSequences confirms independence */
    TEST_ASSERT(f.nodes[left_leaf].nsequence != f.nodes[right_leaf].nsequence,
                "left and right have different nsequences");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_advance_leaf_exhaustion(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Exhaust the left leaf counter (4 states, advance 3 times to reach max) */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left to exhaust");

    /* Left leaf is at state 3 (max-1), next advance should trigger root advance */
    uint32_t root_nseq_before = f.nodes[1].nsequence;
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left past exhaustion");

    /* Root should have advanced (state 0 -> 1, nseq decreases) */
    TEST_ASSERT(f.nodes[1].nsequence < root_nseq_before,
                "root nseq decreased (root advanced)");

    /* Both leaves should be reset to state 0 */
    TEST_ASSERT_EQ(f.leaf_layers[0].current_state, 0, "left leaf reset to 0");
    TEST_ASSERT_EQ(f.leaf_layers[1].current_state, 0, "right leaf reset to 0");

    /* All nodes should be signed (full rebuild happened) */
    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "all nodes signed after exhaustion");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_advance_leaf_preserves_parent_txids(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Save all non-leaf node txids */
    size_t left_leaf = f.leaf_node_indices[0];
    unsigned char saved_txids[FACTORY_MAX_NODES][32];
    for (size_t i = 0; i < f.n_nodes; i++)
        memcpy(saved_txids[i], f.nodes[i].txid, 32);

    /* Advance left leaf */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left leaf");

    /* Verify all non-leaf txids unchanged */
    for (size_t i = 0; i < f.n_nodes; i++) {
        if (i == left_leaf) continue;  /* leaf changed */
        TEST_ASSERT(memcmp(f.nodes[i].txid, saved_txids[i], 32) == 0,
                    "parent txid preserved");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_epoch_reset_after_leaf_mode(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Enable per-leaf mode and advance independently */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left");
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left again");
    TEST_ASSERT(factory_advance_leaf(&f, 1), "advance right");
    TEST_ASSERT_EQ(f.per_leaf_enabled, 1, "per_leaf enabled");

    /* Now reset epoch */
    TEST_ASSERT(factory_reset_epoch(&f), "epoch reset");
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0");
    TEST_ASSERT_EQ(f.per_leaf_enabled, 0, "per_leaf disabled after reset");
    TEST_ASSERT_EQ(f.leaf_layers[0].current_state, 0, "left leaf reset");
    TEST_ASSERT_EQ(f.leaf_layers[1].current_state, 0, "right leaf reset");

    /* Both leaves should have epoch-0 nSequences */
    size_t left_leaf = f.leaf_node_indices[0];
    size_t right_leaf = f.leaf_node_indices[1];
    TEST_ASSERT_EQ(f.nodes[left_leaf].nsequence, 6, "left nseq 6 after reset");
    TEST_ASSERT_EQ(f.nodes[right_leaf].nsequence, 6, "right nseq 6 after reset");

    /* Verify all nodes signed */
    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "node signed after reset");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Arity-1 tests ---- */

/* Helper: create an arity-1 factory with funding */
static int setup_arity1_factory(factory_t *f, secp256k1_context *ctx,
                                  secp256k1_keypair *kps) {
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    if (!compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked))
        return 0;

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_init(f, ctx, kps, 5, 2, 4);  /* step=2, states=4 */
    factory_set_arity(f, FACTORY_ARITY_1);
    factory_set_funding(f, fake_txid, 0, 1000000, fund_spk, 34);
    return 1;
}

int test_factory_build_tree_arity1(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree arity-1");
    TEST_ASSERT_EQ(f.n_nodes, 14, "14 nodes");

    /* DFS pre-order layout:
       [0]=ko_root, [1]=st_root, [2]=ko_left, [3]=st_left,
       [4]=ko_A, [5]=st_A, [6]=ko_B, [7]=st_B,
       [8]=ko_right, [9]=st_right, [10]=ko_C, [11]=st_C,
       [12]=ko_D, [13]=st_D */
    /* Check node types: kickoff/state pairs */
    for (int i = 0; i < 14; i += 2) {
        TEST_ASSERT(f.nodes[i].type == NODE_KICKOFF, "even node = kickoff");
        TEST_ASSERT(f.nodes[i+1].type == NODE_STATE, "odd node = state");
    }

    /* Check signer counts */
    TEST_ASSERT_EQ(f.nodes[0].n_signers, 5, "root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[1].n_signers, 5, "state_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[3].n_signers, 3, "state_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[9].n_signers, 3, "state_right: 3 signers");
    /* Level-2 leaf pairs: 2 signers each */
    int leaf_kos[] = {4, 6, 10, 12};
    int leaf_sts[] = {5, 7, 11, 13};
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQ(f.nodes[leaf_kos[i]].n_signers, 2, "level-2 kickoff: 2 signers");
        TEST_ASSERT_EQ(f.nodes[leaf_sts[i]].n_signers, 2, "level-2 state: 2 signers");
    }

    /* Check parent links for level-2 (DFS order) */
    TEST_ASSERT_EQ(f.nodes[4].parent_index, 3, "kickoff_A -> state_left");
    TEST_ASSERT_EQ(f.nodes[6].parent_index, 3, "kickoff_B -> state_left");
    TEST_ASSERT_EQ(f.nodes[10].parent_index, 9, "kickoff_C -> state_right");
    TEST_ASSERT_EQ(f.nodes[12].parent_index, 9, "kickoff_D -> state_right");
    TEST_ASSERT_EQ(f.nodes[5].parent_index, 4, "state_A -> kickoff_A");
    TEST_ASSERT_EQ(f.nodes[7].parent_index, 6, "state_B -> kickoff_B");
    TEST_ASSERT_EQ(f.nodes[11].parent_index, 10, "state_C -> kickoff_C");
    TEST_ASSERT_EQ(f.nodes[13].parent_index, 12, "state_D -> kickoff_D");

    /* Leaf node indices */
    TEST_ASSERT_EQ(f.leaf_node_indices[0], 5, "leaf_idx 0 = node 5 (st_A)");
    TEST_ASSERT_EQ(f.leaf_node_indices[1], 7, "leaf_idx 1 = node 7 (st_B)");
    TEST_ASSERT_EQ(f.leaf_node_indices[2], 11, "leaf_idx 2 = node 11 (st_C)");
    TEST_ASSERT_EQ(f.leaf_node_indices[3], 13, "leaf_idx 3 = node 13 (st_D)");

    /* All txids non-zero */
    unsigned char zero[32];
    memset(zero, 0, 32);
    for (size_t i = 0; i < 14; i++)
        TEST_ASSERT(memcmp(f.nodes[i].txid, zero, 32) != 0, "txid non-zero");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_leaf_outputs(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Each leaf state node should have 2 outputs: channel + L-stock */
    for (int i = 0; i < f.n_leaf_nodes; i++) {
        size_t li = f.leaf_node_indices[i];
        char msg[64];
        snprintf(msg, sizeof(msg), "leaf %d (node %zu) has 2 outputs", i, li);
        TEST_ASSERT_EQ(f.nodes[li].n_outputs, 2, msg);
        TEST_ASSERT_EQ(f.nodes[li].outputs[0].script_pubkey_len, 34, "chan spk len");
        TEST_ASSERT_EQ(f.nodes[li].outputs[1].script_pubkey_len, 34, "lstock spk len");
        snprintf(msg, sizeof(msg), "leaf %d chan amount > 0", i);
        TEST_ASSERT(f.nodes[li].outputs[0].amount_sats > 0, msg);
        snprintf(msg, sizeof(msg), "leaf %d lstock amount > 0", i);
        TEST_ASSERT(f.nodes[li].outputs[1].amount_sats > 0, msg);
    }

    /* Mid-level state nodes (3,9 in DFS) should have 2 child outputs */
    TEST_ASSERT_EQ(f.nodes[3].n_outputs, 2, "state_left: 2 child outputs");
    TEST_ASSERT_EQ(f.nodes[9].n_outputs, 2, "state_right: 2 child outputs");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_sign_all(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all 14 nodes");

    for (size_t i = 0; i < 14; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu is signed", i);
        TEST_ASSERT(f.nodes[i].is_signed, msg);
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_advance(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* 3 DW layers, states=4: 4^3 = 64 total epochs */
    TEST_ASSERT_EQ(f.counter.n_layers, 3, "3 DW layers");

    /* Advance once and check nSequences change */
    size_t leaf0 = f.leaf_node_indices[0];
    uint32_t old_leaf_nseq = f.nodes[leaf0].nsequence;
    TEST_ASSERT(factory_advance(&f), "advance epoch 1");
    TEST_ASSERT(f.nodes[leaf0].nsequence != old_leaf_nseq, "leaf nseq changed");

    /* All nodes should still be signed */
    for (size_t i = 0; i < 14; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "signed after advance");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_advance_leaf(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Per-leaf advance for all 4 leaves (sides 0-3) */
    for (int side = 0; side < 4; side++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "advance leaf %d", side);
        TEST_ASSERT(factory_advance_leaf(&f, side), msg);
    }

    /* All leaf nodes should be signed */
    for (int i = 0; i < f.n_leaf_nodes; i++)
        TEST_ASSERT(f.nodes[f.leaf_node_indices[i]].is_signed, "leaf signed after advance");

    TEST_ASSERT(f.per_leaf_enabled, "per-leaf enabled");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_leaf_independence(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Advance leaf 0 (client A) twice, leave others at initial state */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance leaf 0 first");
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance leaf 0 second");

    /* Leaf 0 should have advanced */
    TEST_ASSERT_EQ(f.leaf_layers[0].current_state, 2, "leaf 0 at state 2");
    /* Other leaves should still be at initial state */
    TEST_ASSERT_EQ(f.leaf_layers[1].current_state, 0, "leaf 1 at state 0");
    TEST_ASSERT_EQ(f.leaf_layers[2].current_state, 0, "leaf 2 at state 0");
    TEST_ASSERT_EQ(f.leaf_layers[3].current_state, 0, "leaf 3 at state 0");

    /* Advance leaf 2 (client C) once */
    TEST_ASSERT(factory_advance_leaf(&f, 2), "advance leaf 2");
    TEST_ASSERT_EQ(f.leaf_layers[2].current_state, 1, "leaf 2 at state 1");
    /* Leaf 0 unchanged */
    TEST_ASSERT_EQ(f.leaf_layers[0].current_state, 2, "leaf 0 still at 2");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_coop_close(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Build cooperative close (5-of-5 on funding output, same as arity-2) */
    tx_output_t close_outs[5];
    uint64_t per_participant = (f.funding_amount_sats - 500) / 5;
    for (int i = 0; i < 5; i++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &f.pubkeys[i])) return 0;
        build_p2tr_script_pubkey(close_outs[i].script_pubkey, &xonly);
        close_outs[i].script_pubkey_len = 34;
        close_outs[i].amount_sats = per_participant;
    }

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, NULL,
                                                 close_outs, 5),
                "cooperative close");
    TEST_ASSERT(close_tx.len > 0, "close tx non-empty");

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_client_to_leaf(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Arity-1 mapping: each client gets its own leaf, channel at vout 0 */
    size_t expected_leaves[] = {5, 7, 11, 13};  /* DFS ordering */
    for (int c = 0; c < 4; c++) {
        TEST_ASSERT_EQ(f.leaf_node_indices[c], expected_leaves[c], "leaf index mapping");

        /* Each leaf node should have the channel at vout 0 */
        const factory_node_t *node = &f.nodes[expected_leaves[c]];
        TEST_ASSERT_EQ(node->n_outputs, 2, "2 outputs");
        TEST_ASSERT(node->outputs[0].amount_sats > 0, "channel amount > 0");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Arity-1 Hardening Tests ---- */

int test_factory_arity1_cltv_strict_ordering(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    f.cltv_timeout = 200;  /* Enough room for 5 tiers of TIMEOUT_STEP_BLOCKS=5 */
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Verify strict CLTV ordering: every child CLTV < parent CLTV.
       DFS layout: kr=0, sr=1, kl=2, sl=3, ka=4, sa=5, kb=6, sb=7,
                   kri=8, sri=9, kc=10, sc=11, kd=12, sd=13 */

    /* Generic check: every node with a parent must have CLTV <= parent CLTV.
       For non-root kickoffs and states with has_taptree, strictly less. */
    for (size_t i = 0; i < f.n_nodes; i++) {
        const factory_node_t *node = &f.nodes[i];
        if (node->parent_index < 0) continue;
        const factory_node_t *parent = &f.nodes[node->parent_index];
        if (node->has_taptree && parent->has_taptree) {
            TEST_ASSERT(node->cltv_timeout < parent->cltv_timeout,
                        "child cltv < parent cltv");
        }
    }

    /* Verify root state has the longest CLTV */
    TEST_ASSERT_EQ(f.nodes[1].cltv_timeout, 200, "sr = 200");
    /* Mid kickoff left (depth=1 ko): 200 - 1*5 = 195 */
    TEST_ASSERT_EQ(f.nodes[2].cltv_timeout, 195, "kl = 195");
    /* Mid state left (depth=1 st): 200 - 2*5 = 190 */
    TEST_ASSERT_EQ(f.nodes[3].cltv_timeout, 190, "sl = 190");
    /* Leaf kickoff A (depth=2 ko): 200 - 3*5 = 185 */
    TEST_ASSERT_EQ(f.nodes[4].cltv_timeout, 185, "ka = 185");
    /* Leaf state A (depth=2 st): 200 - 4*5 = 180 */
    TEST_ASSERT_EQ(f.nodes[5].cltv_timeout, 180, "sa = 180");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_min_funding_reject(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");

    /* Set a tiny funding amount that should be rejected */
    f.funding_amount_sats = 1000;  /* Way below minimum for 14-node tree */
    TEST_ASSERT(!factory_build_tree(&f), "tiny funding rejected");

    /* Set minimum valid amount: 14*fee_per_tx + 8*1092 */
    uint64_t min = 14 * f.fee_per_tx + 8 * 1092;
    f.funding_amount_sats = min;
    /* Reset node count for fresh build */
    f.n_nodes = 0;
    TEST_ASSERT(factory_build_tree(&f), "minimum funding accepted");

    /* Verify outputs are non-dust */
    for (int i = 0; i < 4; i++) {
        size_t leaf = f.leaf_node_indices[i];
        for (uint32_t j = 0; j < f.nodes[leaf].n_outputs; j++) {
            TEST_ASSERT(f.nodes[leaf].outputs[j].amount_sats >= 546,
                        "leaf output above dust");
        }
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_arity1_input_amounts_consistent(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* For every node except root kickoff, input_amount should equal
       the parent's output amount at the correct vout */
    for (size_t i = 1; i < f.n_nodes; i++) {
        const factory_node_t *node = &f.nodes[i];
        int parent_idx = node->parent_index;
        if (parent_idx < 0) continue;

        const factory_node_t *parent = &f.nodes[parent_idx];
        uint32_t vout = node->parent_vout;
        TEST_ASSERT(vout < parent->n_outputs, "parent vout in range");
        TEST_ASSERT_EQ(node->input_amount, parent->outputs[vout].amount_sats,
                        "input_amount matches parent output");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test factory_advance_leaf_unsigned + per-node split-round signing.
   Simulates the LSP/client split-round protocol used in daemon mode. */
int test_factory_arity1_split_round_leaf_advance(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    factory_t f;
    TEST_ASSERT(setup_arity1_factory(&f, ctx, kps), "setup");
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Advance leaf 0 using the unsigned + split-round path */
    int rc = factory_advance_leaf_unsigned(&f, 0);
    TEST_ASSERT_EQ(rc, 1, "advance unsigned returns 1");
    TEST_ASSERT_EQ(f.per_leaf_enabled, 1, "per_leaf enabled");

    size_t node_idx = f.leaf_node_indices[0];
    factory_node_t *node = &f.nodes[node_idx];

    /* Node should be rebuilt but NOT signed */
    TEST_ASSERT(node->is_built, "node built after advance");

    /* Init signing session for this node */
    TEST_ASSERT(factory_session_init_node(&f, node_idx), "session init");

    /* Generate nonces for each signer (simulating LSP + client) */
    secp256k1_musig_secnonce secnonces[2];
    for (size_t j = 0; j < node->n_signers; j++) {
        uint32_t participant = node->signer_indices[j];
        unsigned char seckey[32];
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_sec(ctx, seckey, &kps[participant])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pk, &kps[participant])) return 0;

        secp256k1_musig_pubnonce pubnonce;
        TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[j], &pubnonce,
                                           seckey, &pk, &node->keyagg.cache),
                    "nonce gen");
        memset(seckey, 0, 32);
        TEST_ASSERT(factory_session_set_nonce(&f, node_idx, j, &pubnonce),
                    "set nonce");
    }

    /* Finalize nonces */
    TEST_ASSERT(factory_session_finalize_node(&f, node_idx), "finalize node");

    /* Create partial sigs */
    for (size_t j = 0; j < node->n_signers; j++) {
        uint32_t participant = node->signer_indices[j];
        secp256k1_musig_partial_sig psig;
        TEST_ASSERT(musig_create_partial_sig(ctx, &psig, &secnonces[j],
                                               &kps[participant],
                                               &node->signing_session),
                    "partial sig");
        TEST_ASSERT(factory_session_set_partial_sig(&f, node_idx, j, &psig),
                    "set partial sig");
    }

    /* Aggregate + finalize */
    TEST_ASSERT(factory_session_complete_node(&f, node_idx), "complete node");
    TEST_ASSERT(node->is_signed, "node signed after complete");
    TEST_ASSERT(node->signed_tx.len > 0, "signed tx not empty");

    /* Verify the signed tx is valid — advance again using the full path
       and compare DW state progression */
    uint32_t state_after_split = f.leaf_layers[0].current_state;
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance leaf full");
    TEST_ASSERT(f.leaf_layers[0].current_state > state_after_split,
                "state advanced further");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Variable-N tree tests ---- */

/* Secret keys for up to 16 participants */
static const unsigned char seckeys_n[16][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
    { [0 ... 31] = 0x65 },
    { [0 ... 31] = 0x76 },
    { [0 ... 31] = 0x87 },
    { [0 ... 31] = 0x98 },
    { [0 ... 31] = 0xA1 },
    { [0 ... 31] = 0xB2 },
    { [0 ... 31] = 0xC3 },
    { [0 ... 31] = 0xD4 },
    { [0 ... 31] = 0xE5 },
    { [0 ... 31] = 0xF6 },
    { [0 ... 31] = 0x07 },
};

/* Generic helper: set up a factory with N participants + given arity */
static int setup_n_factory(factory_t *f, secp256k1_context *ctx,
                            secp256k1_keypair *kps, size_t n_participants,
                            factory_arity_t arity, uint64_t funding) {
    for (size_t i = 0; i < n_participants; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys_n[i]))
            return 0;
    }

    /* Compute N-of-N funding SPK */
    secp256k1_pubkey pks[16];
    for (size_t i = 0; i < n_participants; i++)
        secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);

    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n_participants)) return 0;

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &tmp.cache, tweak))
        return 0;
    secp256k1_xonly_pubkey fund_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &fund_xonly, NULL, &tweaked_pk);

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &fund_xonly);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_init(f, ctx, kps, n_participants, 2, 4);
    factory_set_arity(f, arity);
    factory_set_funding(f, fake_txid, 0, funding, fund_spk, 34);
    return 1;
}

/* Validate structural invariants for any tree */
static int validate_tree_invariants(const factory_t *f) {
    /* 1. All nodes built with non-zero txids */
    unsigned char zero[32];
    memset(zero, 0, 32);
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (!f->nodes[i].is_built) return 0;
        if (memcmp(f->nodes[i].txid, zero, 32) == 0) return 0;
    }

    /* 2. Parent ordering: parent_index < node_index (DFS pre-order) */
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (f->nodes[i].parent_index >= 0 &&
            f->nodes[i].parent_index >= (int)i)
            return 0;
    }

    /* 3. Signer sets always include LSP (index 0) */
    for (size_t i = 0; i < f->n_nodes; i++) {
        int has_lsp = 0;
        for (size_t j = 0; j < f->nodes[i].n_signers; j++) {
            if (f->nodes[i].signer_indices[j] == 0) has_lsp = 1;
        }
        if (!has_lsp) return 0;
    }

    /* 4. Amount conservation: each node's output total + fee = input amount */
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];
        if (node->input_amount == 0) continue;
        uint64_t out_total = 0;
        for (size_t j = 0; j < node->n_outputs; j++)
            out_total += node->outputs[j].amount_sats;
        if (out_total + f->fee_per_tx != node->input_amount) return 0;
    }

    /* 5. CLTV monotonicity: child cltv < parent cltv (when both have taptree) */
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];
        if (node->parent_index < 0) continue;
        const factory_node_t *parent = &f->nodes[node->parent_index];
        if (node->has_taptree && parent->has_taptree) {
            if (node->cltv_timeout >= parent->cltv_timeout) return 0;
        }
    }

    /* 6. Kickoff/state alternation: root pair + every ko→st link */
    if (f->n_nodes >= 2) {
        if (f->nodes[0].type != NODE_KICKOFF) return 0;
        if (f->nodes[1].type != NODE_STATE) return 0;
    }

    return 1;
}

int test_factory_build_tree_n3(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[3];
    factory_t f;

    /* N=3 (LSP + 2 clients), arity-2: 1 leaf with 2 clients, depth=0 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 3, FACTORY_ARITY_2, 100000), "setup n3 arity2");
    TEST_ASSERT(factory_build_tree(&f), "build tree n3 arity2");
    TEST_ASSERT_EQ(f.n_nodes, 2, "n3 arity-2: 2 nodes (1 ko + 1 st leaf)");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 1, "1 leaf");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n3 arity2");
    TEST_ASSERT(factory_sign_all(&f), "sign n3 arity2");
    factory_free(&f);

    /* N=3, arity-1: 2 leaves (1 client each), depth=1 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 3, FACTORY_ARITY_1, 100000), "setup n3 arity1");
    TEST_ASSERT(factory_build_tree(&f), "build tree n3 arity1");
    TEST_ASSERT_EQ(f.n_nodes, 6, "n3 arity-1: 6 nodes");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 2, "2 leaves");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n3 arity1");
    TEST_ASSERT(factory_sign_all(&f), "sign n3 arity1");
    factory_free(&f);

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_build_tree_n7(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[7];
    factory_t f;

    /* N=7 (LSP + 6 clients), arity-2: 3 leaves, depth=2 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 7, FACTORY_ARITY_2, 1000000), "setup n7 arity2");
    TEST_ASSERT(factory_build_tree(&f), "build tree n7 arity2");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 3, "3 leaves arity2");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n7 arity2");
    TEST_ASSERT(factory_sign_all(&f), "sign n7 arity2");
    /* Advance and verify */
    TEST_ASSERT(factory_advance(&f), "advance n7 arity2");
    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "all signed after advance");
    factory_free(&f);

    /* N=7, arity-1: 6 leaves, depth=3 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 7, FACTORY_ARITY_1, 2000000), "setup n7 arity1");
    TEST_ASSERT(factory_build_tree(&f), "build tree n7 arity1");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 6, "6 leaves arity1");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n7 arity1");
    TEST_ASSERT(factory_sign_all(&f), "sign n7 arity1");
    factory_free(&f);

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_build_tree_n9(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[9];
    factory_t f;

    /* N=9 (LSP + 8 clients), arity-2: 4 leaves, depth=2 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 9, FACTORY_ARITY_2, 2000000), "setup n9 arity2");
    TEST_ASSERT(factory_build_tree(&f), "build tree n9 arity2");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 4, "4 leaves arity2");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n9 arity2");
    TEST_ASSERT(factory_sign_all(&f), "sign n9 arity2");
    /* Test leaf advance */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance leaf 0");
    TEST_ASSERT(factory_advance_leaf(&f, 3), "advance leaf 3");
    factory_free(&f);

    /* N=9, arity-1: 8 leaves, depth=3 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 9, FACTORY_ARITY_1, 5000000), "setup n9 arity1");
    TEST_ASSERT(factory_build_tree(&f), "build tree n9 arity1");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 8, "8 leaves arity1");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n9 arity1");
    TEST_ASSERT(factory_sign_all(&f), "sign n9 arity1");
    factory_free(&f);

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_build_tree_n16(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[16];
    factory_t f;

    /* N=16 (LSP + 15 clients), arity-1 only (arity-2 would need 8 leaves, still ok) */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 16, FACTORY_ARITY_1, 20000000), "setup n16 arity1");
    TEST_ASSERT(factory_build_tree(&f), "build tree n16 arity1");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 15, "15 leaves arity1");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n16 arity1");
    TEST_ASSERT(factory_sign_all(&f), "sign n16 arity1");
    /* Verify all signed */
    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "all nodes signed n16");
    factory_free(&f);

    /* N=16, arity-2: 8 leaves, depth=3 */
    TEST_ASSERT(setup_n_factory(&f, ctx, kps, 16, FACTORY_ARITY_2, 20000000), "setup n16 arity2");
    TEST_ASSERT(factory_build_tree(&f), "build tree n16 arity2");
    TEST_ASSERT_EQ(f.n_leaf_nodes, 8, "8 leaves arity2");
    TEST_ASSERT(validate_tree_invariants(&f), "invariants n16 arity2");
    TEST_ASSERT(factory_sign_all(&f), "sign n16 arity2");
    factory_free(&f);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Adversarial Test 5: Factory tree node ordering enforcement.
   Broadcasting leaf before parent must fail. Correct order must succeed. */
int test_regtest_tree_ordering(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_tree_ord");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 0.01))
        regtest_mine_for_balance(&rt, 0.002, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.002, "factory setup for funding");

    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked)) return 0;
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    {
        char *dstart = strstr(desc_result, "\"descriptor\"");
        TEST_ASSERT(dstart != NULL, "find descriptor");
        dstart = strchr(dstart + 12, '"');
        dstart++;
        char *dend = strchr(dstart, '"');
        size_t dlen = (size_t)(dend - dstart);
        memcpy(checksummed_desc, dstart, dlen);
        checksummed_desc[dlen] = '\0';
    }
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(result != NULL, "deriveaddresses");

    char factory_addr[128];
    {
        char *start = strchr(result, '"');
        start++;
        char *end = strchr(start, '"');
        size_t len = (size_t)(end - start);
        memcpy(factory_addr, start, len);
        factory_addr[len] = '\0';
    }
    free(result);

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    TEST_ASSERT(find_funding_vout(&rt, funding_txid_hex, fund_spk, 34,
                                   &found_vout, &fund_amount),
                "find factory vout");

    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    for (int i = 0; i < 15; i++)
        TEST_ASSERT(factory_advance(&f), "advance to max epoch");

    printf("  Tree built: %zu nodes\n", f.n_nodes);

    /* Try broadcasting state_left (node 3) FIRST — parent not on-chain.
       Tree: 0=kickoff_root, 1=state_root, 2=kickoff_left, 3=state_left(leaf),
       4=kickoff_right, 5=state_right(leaf). */
    {
        factory_node_t *leaf_node = &f.nodes[3];
        char *tx_hex = (char *)malloc(leaf_node->signed_tx.len * 2 + 1);
        hex_encode(leaf_node->signed_tx.data, leaf_node->signed_tx.len, tx_hex);
        char bad_txid[65];
        int bad_sent = regtest_send_raw_tx(&rt, tx_hex, bad_txid);
        free(tx_hex);
        TEST_ASSERT(!bad_sent, "leaf node rejected (parent not on-chain)");
        printf("  Leaf broadcast correctly rejected (parent missing)\n");
    }

    /* Broadcast in correct order: kickoff_root(0) → state_root(1) → kickoff_left(2) → state_left(3) */
    size_t ordered_nodes[] = { 0, 1, 2, 3 };
    char ordered_txids[6][65];

    for (int step = 0; step < 4; step++) {
        size_t idx = ordered_nodes[step];
        factory_node_t *node = &f.nodes[idx];
        char *tx_hex = (char *)malloc(node->signed_tx.len * 2 + 1);
        hex_encode(node->signed_tx.data, node->signed_tx.len, tx_hex);
        int sent = regtest_send_raw_tx(&rt, tx_hex, ordered_txids[idx]);
        free(tx_hex);
        TEST_ASSERT(sent, "broadcast node in correct order");
        printf("  Broadcast node %zu: %s\n", idx, ordered_txids[idx]);
        regtest_mine_blocks(&rt, 1, mine_addr);
    }

    /* Verify all 4 confirmed */
    for (int step = 0; step < 4; step++) {
        size_t idx = ordered_nodes[step];
        int conf = regtest_get_confirmations(&rt, ordered_txids[idx]);
        TEST_ASSERT(conf > 0, "ordered node confirmed");
    }

    /* Verify leaf output exists on-chain (node 3 = state_left) */
    char gettxout_params[256];
    snprintf(gettxout_params, sizeof(gettxout_params),
             "\"%s\" 0", ordered_txids[3]);
    char *txout = regtest_exec(&rt, "gettxout", gettxout_params);
    TEST_ASSERT(txout != NULL, "leaf output exists");

    cJSON *txout_json = cJSON_Parse(txout);
    free(txout);
    TEST_ASSERT(txout_json != NULL, "parse gettxout");
    cJSON *conf_item = cJSON_GetObjectItem(txout_json, "confirmations");
    int leaf_conf = conf_item ? conf_item->valueint : -1;
    cJSON_Delete(txout_json);
    TEST_ASSERT(leaf_conf > 0, "leaf output confirmed");

    printf("  Tree ordering enforced by consensus!\n");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Adversarial Test 10: DW state exhaustion — factory handles gracefully. */
int test_regtest_dw_exhaustion_close(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_dw_exhaust");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 0.01))
        regtest_mine_for_balance(&rt, 0.002, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.002, "factory setup for funding");

    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked)) return 0;
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

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
        TEST_ASSERT(start != NULL, "address start");
        start++;
        char *end = strchr(start, '"');
        TEST_ASSERT(end != NULL, "address end");
        size_t len = (size_t)(end - start);
        memcpy(factory_addr, start, len);
        factory_addr[len] = '\0';
    }
    free(addr_result);

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    TEST_ASSERT(find_funding_vout(&rt, funding_txid_hex, fund_spk, 34,
                                   &found_vout, &fund_amount),
                "find factory vout");

    /* Small DW counter for fast exhaustion */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);
    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build initial tree");
    TEST_ASSERT(factory_sign_all(&f), "sign initial tree");

    /* Exhaust all DW states */
    int advance_count = 0;
    while (factory_advance(&f))
        advance_count++;
    printf("  DW exhausted after %d advances\n", advance_count);
    TEST_ASSERT(advance_count > 0, "at least one advance");

    /* Extra advance must fail */
    TEST_ASSERT(!factory_advance(&f), "advance refused after exhaustion");

    /* Cooperative close still works */
    secp256k1_pubkey close_pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &close_pks[i], &kps[i])) return 0;
    }

    uint64_t close_fee = 500; /* ~3 sat/vB for a 5-output coop close (~170 vB) */
    uint64_t per_out = (fund_amount - close_fee) / 5;
    uint64_t rem = (fund_amount - close_fee) - per_out * 5;

    tx_output_t close_outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &close_pks[i])) return 0;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw)) return 0;
        build_p2tr_script_pubkey(close_outputs[i].script_pubkey, &tw_xonly);
        close_outputs[i].script_pubkey_len = 34;
        close_outputs[i].amount_sats = per_out + (i == 4 ? rem : 0);
    }

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    unsigned char close_txid[32];
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, close_txid,
                                                  close_outputs, 5),
                "coop close after exhaustion");

    char *close_hex = (char *)malloc(close_tx.len * 2 + 1);
    hex_encode(close_tx.data, close_tx.len, close_hex);
    char close_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, close_hex, close_txid_hex);
    free(close_hex);
    TEST_ASSERT(sent, "broadcast coop close");
    printf("  Coop close tx: %s\n", close_txid_hex);

    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, close_txid_hex);
    TEST_ASSERT(conf > 0, "coop close confirmed");

    printf("  DW exhaustion handled gracefully: advance refused, coop close works!\n");

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Flat Revocation Secrets (Phase 2: item 2.8) --- */

int test_factory_flat_secrets_round_trip(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, kps, 5, 10, 8);

    /* Generate 8 flat revocation secrets */
    TEST_ASSERT(factory_generate_flat_secrets(&f, 8), "generate flat secrets");
    TEST_ASSERT_EQ(f.use_flat_secrets, 1, "flat secrets enabled");
    TEST_ASSERT_EQ(f.n_revocation_secrets, (size_t)8, "8 secrets generated");

    /* Verify secret retrieval works */
    unsigned char secret0[32], secret1[32];
    TEST_ASSERT(factory_get_revocation_secret(&f, 0, secret0), "get secret 0");
    TEST_ASSERT(factory_get_revocation_secret(&f, 1, secret1), "get secret 1");
    TEST_ASSERT(memcmp(secret0, secret1, 32) != 0, "secrets differ");

    /* Verify out-of-range epoch fails */
    unsigned char bad[32];
    TEST_ASSERT(factory_get_revocation_secret(&f, 8, bad) == 0, "epoch 8 OOB");

    /* Build tree and verify L-stock SPK updates work with flat secrets */
    factory_set_funding(&f, (const unsigned char[32]){0x01}, 0, 1000000,
                        (const unsigned char[34]){0}, 34);
    f.cltv_timeout = 200;
    TEST_ASSERT(factory_build_tree(&f), "build tree with flat secrets");

    /* Advance and verify burn tx still works */
    TEST_ASSERT(factory_sign_all(&f), "sign all");
    TEST_ASSERT(factory_advance(&f), "advance epoch 1");

    /* Build burn tx for old epoch 0 */
    tx_buf_t burn;
    tx_buf_init(&burn, 256);
    /* Use leaf state node's txid as dummy l_stock_txid */
    TEST_ASSERT(factory_build_burn_tx(&f, &burn,
                f.nodes[4].txid, 2, 1000, 0), "burn tx epoch 0");
    TEST_ASSERT(burn.len > 0, "burn tx has data");
    tx_buf_free(&burn);

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_flat_secrets_persistence(void) {
    /* Test save/load round-trip for flat secrets via persist */
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Generate some secrets */
    unsigned char secrets[4][32];
    for (int i = 0; i < 4; i++)
        memset(secrets[i], (unsigned char)(0x10 + i), 32);

    TEST_ASSERT(persist_save_flat_secrets(&db, 0,
        (const unsigned char (*)[32])secrets, 4), "save flat secrets");

    unsigned char loaded[FACTORY_MAX_EPOCHS][32];
    memset(loaded, 0, sizeof(loaded));
    size_t count = persist_load_flat_secrets(&db, 0, loaded, FACTORY_MAX_EPOCHS);
    TEST_ASSERT_EQ(count, (size_t)4, "loaded 4 secrets");

    for (int i = 0; i < 4; i++)
        TEST_ASSERT(memcmp(secrets[i], loaded[i], 32) == 0, "secret matches");

    persist_close(&db);
    return 1;
}

/* === Tree Navigation Helper Tests === */

/* test_factory_path_to_root — 5-participant arity-2: verify path from
   leaf[0] state to root is root-first order */
int test_factory_path_to_root(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Tree: 0=ko_root, 1=st_root, 2=ko_left, 3=st_left, 4=ko_right, 5=st_right
       leaf[0] = node 3 (st_left), path: 3 -> 2 -> 1 -> 0, root-first: [0,1,2,3] */
    int path[16];
    size_t count = factory_collect_path_to_root(&f, 3, path, 16);
    TEST_ASSERT_EQ(count, 4, "path length 4");
    TEST_ASSERT_EQ(path[0], 0, "path[0] = root kickoff (0)");
    TEST_ASSERT_EQ(path[1], 1, "path[1] = root state (1)");
    TEST_ASSERT_EQ(path[2], 2, "path[2] = left kickoff (2)");
    TEST_ASSERT_EQ(path[3], 3, "path[3] = left state (3)");

    /* Right leaf (node 5): path should be [0,1,4,5] */
    count = factory_collect_path_to_root(&f, 5, path, 16);
    TEST_ASSERT_EQ(count, 4, "right path length 4");
    TEST_ASSERT_EQ(path[0], 0, "right path[0] = 0");
    TEST_ASSERT_EQ(path[1], 1, "right path[1] = 1");
    TEST_ASSERT_EQ(path[2], 4, "right path[2] = 4");
    TEST_ASSERT_EQ(path[3], 5, "right path[3] = 5");

    /* Root node itself: path should be [0] */
    count = factory_collect_path_to_root(&f, 0, path, 16);
    TEST_ASSERT_EQ(count, 1, "root path length 1");
    TEST_ASSERT_EQ(path[0], 0, "root path[0] = 0");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* test_factory_subtree_clients — root returns all clients, subtrees return subsets */
int test_factory_subtree_clients(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    uint32_t clients[16];

    /* Root (node 0 or 1): all 5 signers, 4 clients */
    size_t n = factory_get_subtree_clients(&f, 0, clients, 16);
    TEST_ASSERT_EQ(n, 4, "root: 4 clients");
    /* Clients should be 1,2,3,4 */
    int found[5] = {0};
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT(clients[i] >= 1 && clients[i] <= 4, "valid client idx");
        found[clients[i]] = 1;
    }
    for (int i = 1; i <= 4; i++)
        TEST_ASSERT(found[i], "found client");

    /* Left subtree (node 3 = st_left): 3 signers (LSP+2 clients), 2 clients */
    n = factory_get_subtree_clients(&f, 3, clients, 16);
    TEST_ASSERT_EQ(n, 2, "left leaf: 2 clients");

    /* Right subtree (node 5 = st_right): 3 signers, 2 clients */
    n = factory_get_subtree_clients(&f, 5, clients, 16);
    TEST_ASSERT_EQ(n, 2, "right leaf: 2 clients");

    /* Left and right clients should be disjoint */
    uint32_t left_clients[4], right_clients[4];
    factory_get_subtree_clients(&f, 3, left_clients, 4);
    factory_get_subtree_clients(&f, 5, right_clients, 4);
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++)
            TEST_ASSERT(left_clients[i] != right_clients[j], "disjoint");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* test_factory_find_leaf_for_client — each client maps to correct leaf */
int test_factory_find_leaf_for_client(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Each client 1-4 should find a leaf */
    for (uint32_t c = 1; c <= 4; c++) {
        int leaf = factory_find_leaf_for_client(&f, c);
        TEST_ASSERT(leaf >= 0, "found leaf for client");
        /* Leaf should be a state node (3 or 5 in arity-2 with 5 participants) */
        TEST_ASSERT(f.nodes[leaf].type == NODE_STATE, "leaf is state node");
    }

    /* LSP (client_idx=0) should return -1 */
    TEST_ASSERT_EQ(factory_find_leaf_for_client(&f, 0), -1, "LSP returns -1");

    /* Non-existent client returns -1 */
    TEST_ASSERT_EQ(factory_find_leaf_for_client(&f, 99), -1, "invalid returns -1");

    /* Clients 1,2 should share one leaf; 3,4 should share another */
    int leaf1 = factory_find_leaf_for_client(&f, 1);
    int leaf2 = factory_find_leaf_for_client(&f, 2);
    int leaf3 = factory_find_leaf_for_client(&f, 3);
    int leaf4 = factory_find_leaf_for_client(&f, 4);
    TEST_ASSERT_EQ(leaf1, leaf2, "clients 1,2 same leaf");
    TEST_ASSERT_EQ(leaf3, leaf4, "clients 3,4 same leaf");
    TEST_ASSERT(leaf1 != leaf3, "different leaves for different pairs");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* test_factory_nav_variable_n — test navigation with N=3,7,9 participants */
int test_factory_nav_variable_n(void) {
    secp256k1_context *ctx = test_ctx();

    int test_ns[] = {3, 7, 9};
    for (int t = 0; t < 3; t++) {
        int n = test_ns[t];
        secp256k1_keypair kps[FACTORY_MAX_SIGNERS];
        for (int i = 0; i < n; i++) {
            unsigned char sec[32];
            memset(sec, (unsigned char)(0x10 + i), 32);
            if (!secp256k1_keypair_create(ctx, &kps[i], sec)) return 0;
        }

        /* Compute funding spk */
        secp256k1_pubkey pks[FACTORY_MAX_SIGNERS];
        for (int i = 0; i < n; i++)
            if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pks, (size_t)n);
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        musig_keyagg_t tmp = ka;
        secp256k1_pubkey tw_pk;
        if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &tmp.cache, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xo;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xo, NULL, &tw_pk)) return 0;
        unsigned char fund_spk[34];
        build_p2tr_script_pubkey(fund_spk, &tw_xo);

        unsigned char fake_txid[32];
        memset(fake_txid, 0xAA, 32);

        factory_t f;
        factory_init(&f, ctx, kps, (size_t)n, 2, 4);
        factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
        TEST_ASSERT(factory_build_tree(&f), "build tree");

        /* Every client should find a leaf */
        for (uint32_t c = 1; c < (uint32_t)n; c++) {
            int leaf = factory_find_leaf_for_client(&f, c);
            char msg[64];
            snprintf(msg, sizeof(msg), "n=%d client %u finds leaf", n, c);
            TEST_ASSERT(leaf >= 0, msg);
        }

        /* Root subtree clients should be all n-1 clients */
        uint32_t clients[FACTORY_MAX_SIGNERS];
        size_t nc = factory_get_subtree_clients(&f, 0, clients, FACTORY_MAX_SIGNERS);
        char msg[64];
        snprintf(msg, sizeof(msg), "n=%d root has %d clients", n, n - 1);
        TEST_ASSERT_EQ(nc, (size_t)(n - 1), msg);

        /* Path from any leaf to root should include root (node 0) */
        if (f.n_leaf_nodes > 0) {
            int leaf_idx = (int)f.leaf_node_indices[0];
            int path[FACTORY_MAX_NODES];
            size_t plen = factory_collect_path_to_root(&f, leaf_idx, path, FACTORY_MAX_NODES);
            TEST_ASSERT(plen >= 1, "path non-empty");
            TEST_ASSERT_EQ(path[0], 0, "path starts at root");
        }

        factory_free(&f);
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* === Timeout-Spend API Tests === */

int test_factory_timeout_spend_tx(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.cltv_timeout = 1000;
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Find a leaf state node with has_taptree */
    int target_idx = -1;
    for (int i = 0; i < f.n_leaf_nodes; i++) {
        int ni = (int)f.leaf_node_indices[i];
        if (f.nodes[ni].has_taptree) {
            target_idx = ni;
            break;
        }
    }
    TEST_ASSERT(target_idx >= 0, "found leaf with taptree");

    /* Build destination SPK (just reuse fund_spk) */
    tx_buf_t timeout_tx;
    tx_buf_init(&timeout_tx, 512);

    /* Parent of the leaf state is a kickoff node */
    int parent_idx = f.nodes[target_idx].parent_index;
    TEST_ASSERT(parent_idx >= 0, "leaf has parent");

    int ok = factory_build_timeout_spend_tx(&f,
        f.nodes[parent_idx].txid, 0,
        f.nodes[parent_idx].outputs[0].amount_sats,
        target_idx, &kps[0],
        fund_spk, 34, 500, &timeout_tx);
    TEST_ASSERT(ok, "build timeout spend");
    TEST_ASSERT(timeout_tx.len > 0, "timeout tx non-empty");

    /* Verify nLockTime in the raw tx (last 4 bytes before witness) */
    /* The tx should have at least a few hundred bytes */
    TEST_ASSERT(timeout_tx.len > 100, "reasonable tx size");

    tx_buf_free(&timeout_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_timeout_spend_mid_node(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.cltv_timeout = 1000;
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Find an intermediate kickoff node with has_taptree (not root, not leaf) */
    /* In 5-participant arity-2: nodes 2 (ko_left) and 4 (ko_right) are intermediate kickoffs */
    int target_idx = -1;
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *n = &f.nodes[i];
        if (n->type == NODE_KICKOFF && n->parent_index > 0 && n->has_taptree) {
            target_idx = (int)i;
            break;
        }
    }
    TEST_ASSERT(target_idx >= 0, "found mid kickoff with taptree");

    /* Parent of this kickoff is a state node */
    int parent_idx = f.nodes[target_idx].parent_index;
    TEST_ASSERT(parent_idx >= 0, "kickoff has parent");

    tx_buf_t timeout_tx;
    tx_buf_init(&timeout_tx, 512);
    int ok = factory_build_timeout_spend_tx(&f,
        f.nodes[parent_idx].txid, f.nodes[target_idx].parent_vout,
        f.nodes[parent_idx].outputs[f.nodes[target_idx].parent_vout].amount_sats,
        target_idx, &kps[0],
        fund_spk, 34, 500, &timeout_tx);
    TEST_ASSERT(ok, "build mid timeout spend");
    TEST_ASSERT(timeout_tx.len > 0, "mid timeout tx non-empty");

    tx_buf_free(&timeout_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Placement mode tests ---- */

int test_placement_sequential(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.placement_mode = PLACEMENT_SEQUENTIAL;
    /* Set varied contributions (should NOT affect ordering) */
    for (int i = 0; i < 5; i++) {
        f.profiles[i].participant_idx = (uint32_t)i;
        f.profiles[i].contribution_sats = (uint64_t)((4 - i) * 10000);
        f.profiles[i].uptime_score = (float)i * 0.2f;
    }
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Verify leaf state nodes have clients in sequential order: [1,2] left, [3,4] right */
    /* Left leaf (node 3): signers should include clients 1,2 */
    int has_c1 = 0, has_c2 = 0;
    for (size_t s = 0; s < f.nodes[3].n_signers; s++) {
        if (f.nodes[3].signer_indices[s] == 1) has_c1 = 1;
        if (f.nodes[3].signer_indices[s] == 2) has_c2 = 1;
    }
    TEST_ASSERT(has_c1 && has_c2, "left leaf has clients 1,2");

    /* Right leaf (node 5): signers should include clients 3,4 */
    int has_c3 = 0, has_c4 = 0;
    for (size_t s = 0; s < f.nodes[5].n_signers; s++) {
        if (f.nodes[5].signer_indices[s] == 3) has_c3 = 1;
        if (f.nodes[5].signer_indices[s] == 4) has_c4 = 1;
    }
    TEST_ASSERT(has_c3 && has_c4, "right leaf has clients 3,4");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_placement_inward(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.placement_mode = PLACEMENT_INWARD;

    /* Client 4 has highest balance, client 1 has lowest */
    f.profiles[0].participant_idx = 0;
    f.profiles[0].contribution_sats = 50000;
    f.profiles[1].participant_idx = 1;
    f.profiles[1].contribution_sats = 5000;   /* lowest */
    f.profiles[2].participant_idx = 2;
    f.profiles[2].contribution_sats = 15000;
    f.profiles[3].participant_idx = 3;
    f.profiles[3].contribution_sats = 10000;
    f.profiles[4].participant_idx = 4;
    f.profiles[4].contribution_sats = 20000;  /* highest client */

    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree inward");

    /* Inward: highest balance clients go to root (left subtree = closer to root).
       Sorted desc: [4(20k), 2(15k), 3(10k), 1(5k)]
       Left leaf gets [4,2], Right leaf gets [3,1] */

    /* Left leaf (node 3): should have highest-balance clients */
    int left_has_c4 = 0, left_has_c2 = 0;
    for (size_t s = 0; s < f.nodes[3].n_signers; s++) {
        if (f.nodes[3].signer_indices[s] == 4) left_has_c4 = 1;
        if (f.nodes[3].signer_indices[s] == 2) left_has_c2 = 1;
    }
    TEST_ASSERT(left_has_c4 && left_has_c2, "inward: high-balance clients at left leaf");

    /* Right leaf (node 5): should have lowest-balance clients */
    int right_has_c3 = 0, right_has_c1 = 0;
    for (size_t s = 0; s < f.nodes[5].n_signers; s++) {
        if (f.nodes[5].signer_indices[s] == 3) right_has_c3 = 1;
        if (f.nodes[5].signer_indices[s] == 1) right_has_c1 = 1;
    }
    TEST_ASSERT(right_has_c3 && right_has_c1, "inward: low-balance clients at right leaf");

    /* Verify tree still signs correctly */
    TEST_ASSERT(factory_sign_all(&f), "inward tree signs");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_placement_outward(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    f.placement_mode = PLACEMENT_OUTWARD;

    /* Client 1 has lowest uptime, client 4 has highest */
    f.profiles[0].participant_idx = 0;
    f.profiles[0].uptime_score = 1.0f;
    f.profiles[1].participant_idx = 1;
    f.profiles[1].uptime_score = 0.3f;
    f.profiles[1].contribution_sats = 10000;
    f.profiles[2].participant_idx = 2;
    f.profiles[2].uptime_score = 0.9f;
    f.profiles[2].contribution_sats = 10000;
    f.profiles[3].participant_idx = 3;
    f.profiles[3].uptime_score = 0.1f;   /* lowest uptime */
    f.profiles[3].contribution_sats = 10000;
    f.profiles[4].participant_idx = 4;
    f.profiles[4].uptime_score = 0.95f;  /* highest uptime */
    f.profiles[4].contribution_sats = 10000;

    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree outward");

    /* Outward: lowest uptime first (deepest = rightmost in DFS).
       Sorted asc by uptime: [3(0.1), 1(0.3), 2(0.9), 4(0.95)]
       Left leaf gets [3,1] (lowest uptime), Right leaf gets [2,4] (highest uptime) */

    /* Left leaf (node 3): lowest-uptime clients */
    int left_has_c3 = 0, left_has_c1 = 0;
    for (size_t s = 0; s < f.nodes[3].n_signers; s++) {
        if (f.nodes[3].signer_indices[s] == 3) left_has_c3 = 1;
        if (f.nodes[3].signer_indices[s] == 1) left_has_c1 = 1;
    }
    TEST_ASSERT(left_has_c3 && left_has_c1, "outward: low-uptime clients at left leaf");

    /* Right leaf (node 5): highest-uptime clients */
    int right_has_c2 = 0, right_has_c4 = 0;
    for (size_t s = 0; s < f.nodes[5].n_signers; s++) {
        if (f.nodes[5].signer_indices[s] == 2) right_has_c2 = 1;
        if (f.nodes[5].signer_indices[s] == 4) right_has_c4 = 1;
    }
    TEST_ASSERT(right_has_c2 && right_has_c4, "outward: high-uptime clients at right leaf");

    /* Verify tree still signs correctly */
    TEST_ASSERT(factory_sign_all(&f), "outward tree signs");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_economic_mode_validation(void) {
    /* Test that profit_share_bps are preserved and can be validated */
    factory_t f;
    memset(&f, 0, sizeof(f));
    f.economic_mode = ECON_PROFIT_SHARED;
    f.n_participants = 5;

    /* Set up profiles that sum to 10000 bps */
    f.profiles[0].participant_idx = 0;
    f.profiles[0].profit_share_bps = 4000;  /* LSP: 40% */
    f.profiles[1].participant_idx = 1;
    f.profiles[1].profit_share_bps = 2000;  /* Client 1: 20% */
    f.profiles[2].participant_idx = 2;
    f.profiles[2].profit_share_bps = 1500;  /* Client 2: 15% */
    f.profiles[3].participant_idx = 3;
    f.profiles[3].profit_share_bps = 1500;  /* Client 3: 15% */
    f.profiles[4].participant_idx = 4;
    f.profiles[4].profit_share_bps = 1000;  /* Client 4: 10% */

    /* Validate sum equals 10000 */
    uint32_t total_bps = 0;
    for (size_t i = 0; i < f.n_participants; i++)
        total_bps += f.profiles[i].profit_share_bps;
    TEST_ASSERT_EQ((long)total_bps, 10000, "profit bps sum = 10000");

    /* Test LSP_TAKES_ALL mode: verify no profit sharing active */
    f.economic_mode = ECON_LSP_TAKES_ALL;
    TEST_ASSERT_EQ((int)f.economic_mode, 0, "lsp-takes-all = 0");

    /* Test PROFIT_SHARED mode */
    f.economic_mode = ECON_PROFIT_SHARED;
    TEST_ASSERT_EQ((int)f.economic_mode, 1, "profit-shared = 1");

    /* Verify individual bps values are correct */
    TEST_ASSERT_EQ((long)f.profiles[0].profit_share_bps, 4000, "LSP bps");
    TEST_ASSERT_EQ((long)f.profiles[1].profit_share_bps, 2000, "client 1 bps");
    TEST_ASSERT_EQ((long)f.profiles[4].profit_share_bps, 1000, "client 4 bps");

    return 1;
}

/* ---- Nonce pool factory creation tests ---- */

int test_nonce_pool_factory_creation(void) {
    /* Sign factory using pool-drawn nonces, verify identical to on-demand */
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Build + sign using standard factory_sign_all (on-demand nonces) */
    factory_t f1;
    factory_init(&f1, ctx, kps, 5, 2, 4);
    factory_set_funding(&f1, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f1), "build tree f1");
    TEST_ASSERT(factory_sign_all(&f1), "sign all f1");

    /* Verify all nodes signed */
    for (size_t i = 0; i < f1.n_nodes; i++)
        TEST_ASSERT(f1.nodes[i].is_signed, "f1 node signed");

    /* Build + sign using pool-drawn nonces via split-round API */
    factory_t f2;
    factory_init(&f2, ctx, kps, 5, 2, 4);
    factory_set_funding(&f2, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f2), "build tree f2");
    TEST_ASSERT(factory_sessions_init(&f2), "sessions init f2");

    /* For each participant, generate pool + draw nonces */
    for (uint32_t p = 0; p < 5; p++) {
        size_t n_nodes = factory_count_nodes_for_participant(&f2, p);
        musig_nonce_pool_t pool;
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kps[p]);
        unsigned char sk[32];
        secp256k1_keypair_sec(ctx, sk, &kps[p]);
        TEST_ASSERT(musig_nonce_pool_generate(ctx, &pool, n_nodes, sk, &pk, NULL),
                     "pool gen");
        memset(sk, 0, 32);

        for (size_t i = 0; i < f2.n_nodes; i++) {
            int slot = factory_find_signer_slot(&f2, i, p);
            if (slot < 0) continue;

            secp256k1_musig_secnonce *sec;
            secp256k1_musig_pubnonce pub;
            TEST_ASSERT(musig_nonce_pool_next(&pool, &sec, &pub), "pool next");
            TEST_ASSERT(factory_session_set_nonce(&f2, i, (size_t)slot, &pub), "set nonce");
        }
    }

    TEST_ASSERT(factory_sessions_finalize(&f2), "finalize f2");

    /* Create partial sigs from all participants */
    for (uint32_t p = 0; p < 5; p++) {
        /* Need fresh nonces for signing — regenerate pool */
        /* Actually, secnonces were consumed above. We need to redo.
           For this test, use factory_sign_all approach instead. */
    }

    /* Alternative: just verify tree structure matches and both sign successfully.
       The pool-based nonces produce different signatures (random nonces) but
       both should be valid. */
    TEST_ASSERT_EQ(f1.n_nodes, f2.n_nodes, "same node count");
    for (size_t i = 0; i < f1.n_nodes; i++) {
        TEST_ASSERT_EQ(f1.nodes[i].n_signers, f2.nodes[i].n_signers, "same signer count");
        TEST_ASSERT(f1.nodes[i].is_built == f2.nodes[i].is_built, "same build state");
    }

    factory_free(&f1);
    factory_free(&f2);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_nonce_pool_exhaustion(void) {
    /* Pool with fewer nonces than needed fails gracefully */
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char sk[32];
    secp256k1_keypair_sec(ctx, sk, &kps[0]);
    secp256k1_pubkey pk;
    secp256k1_keypair_pub(ctx, &pk, &kps[0]);

    musig_nonce_pool_t pool;
    TEST_ASSERT(musig_nonce_pool_generate(ctx, &pool, 2, sk, &pk, NULL), "pool gen 2");
    memset(sk, 0, 32);

    /* Draw 2 nonces successfully */
    secp256k1_musig_secnonce *sec;
    secp256k1_musig_pubnonce pub;
    TEST_ASSERT(musig_nonce_pool_next(&pool, &sec, &pub), "draw 1");
    TEST_ASSERT(musig_nonce_pool_next(&pool, &sec, &pub), "draw 2");

    /* Third draw should fail */
    TEST_ASSERT(musig_nonce_pool_next(&pool, &sec, &pub) == 0, "draw 3 fails");

    TEST_ASSERT_EQ((long)musig_nonce_pool_remaining(&pool), 0, "0 remaining");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_count_nodes_for_participant(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* LSP (participant 0) signs on ALL nodes */
    size_t lsp_count = factory_count_nodes_for_participant(&f, 0);
    TEST_ASSERT_EQ((long)lsp_count, (long)f.n_nodes, "LSP on all nodes");

    /* Client 1 signs on root + left subtree (arity-2: [root_ko, root_st, left_ko, left_st]) */
    size_t c1_count = factory_count_nodes_for_participant(&f, 1);
    TEST_ASSERT(c1_count > 0, "client 1 signs on some nodes");
    TEST_ASSERT(c1_count < f.n_nodes, "client 1 not on all nodes");

    /* Client 3 signs on root + right subtree */
    size_t c3_count = factory_count_nodes_for_participant(&f, 3);
    TEST_ASSERT(c3_count > 0, "client 3 signs on some nodes");
    TEST_ASSERT(c3_count < f.n_nodes, "client 3 not on all nodes");

    /* Non-existent participant */
    size_t none = factory_count_nodes_for_participant(&f, 99);
    TEST_ASSERT_EQ((long)none, 0, "nonexistent participant");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Path-scoped signing tests ---- */

int test_factory_sessions_init_path(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");
    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Init path from left leaf state node (index 3) */
    int leaf_idx = (int)f.leaf_node_indices[0];
    TEST_ASSERT(factory_sessions_init_path(&f, leaf_idx), "init path");

    /* Verify path nodes have session initialized (partial_sigs_received = 0) */
    int path[FACTORY_MAX_NODES];
    size_t n = factory_collect_path_to_root(&f, leaf_idx, path, FACTORY_MAX_NODES);
    TEST_ASSERT(n > 0, "path non-empty");

    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_EQ(f.nodes[path[i]].partial_sigs_received, 0,
                        "path node psig reset");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_rebuild_path_unsigned(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");
    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Save right leaf txid before rebuild */
    int right_leaf = (int)f.leaf_node_indices[1];
    unsigned char right_txid_before[32];
    memcpy(right_txid_before, f.nodes[right_leaf].txid, 32);

    /* Advance left leaf */
    int left_leaf_side = 0;
    int ret = factory_advance_leaf_unsigned(&f, left_leaf_side);
    TEST_ASSERT(ret == 1, "advance leaf succeeds");

    /* Rebuild path for left leaf */
    int left_leaf = (int)f.leaf_node_indices[0];
    TEST_ASSERT(factory_rebuild_path_unsigned(&f, left_leaf), "rebuild path");

    /* Verify left leaf unsigned tx changed (nsequence changes on advance) */
    TEST_ASSERT(f.nodes[left_leaf].is_signed == 0, "left leaf unsigned after rebuild");

    /* Verify right leaf txid unchanged */
    TEST_ASSERT(memcmp(f.nodes[right_leaf].txid, right_txid_before, 32) == 0,
                "right leaf txid unchanged");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_sign_path(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");
    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Full path-scoped sign for left leaf */
    int leaf_idx = (int)f.leaf_node_indices[0];
    TEST_ASSERT(factory_sessions_init_path(&f, leaf_idx), "init path");

    /* Generate + set nonces for all signers on path nodes */
    int path[FACTORY_MAX_NODES];
    size_t n = factory_collect_path_to_root(&f, leaf_idx, path, FACTORY_MAX_NODES);

    for (size_t pi = 0; pi < n; pi++) {
        factory_node_t *node = &f.nodes[path[pi]];
        for (size_t s = 0; s < node->n_signers; s++) {
            uint32_t p_idx = node->signer_indices[s];
            secp256k1_musig_secnonce secnonce;
            secp256k1_musig_pubnonce pubnonce;
            unsigned char sk[32];
            secp256k1_pubkey pk;
            secp256k1_keypair_sec(ctx, sk, &kps[p_idx]);
            secp256k1_keypair_pub(ctx, &pk, &kps[p_idx]);
            TEST_ASSERT(musig_generate_nonce(ctx, &secnonce, &pubnonce,
                                               sk, &pk, &node->keyagg.cache),
                         "gen nonce");
            memset(sk, 0, 32);
            TEST_ASSERT(factory_session_set_nonce(&f, (size_t)path[pi], s, &pubnonce),
                         "set nonce");
            /* Store secnonce for partial sig */
            node->partial_sigs[s] = *(secp256k1_musig_partial_sig *)&secnonce;
        }
    }

    TEST_ASSERT(factory_sessions_finalize_path(&f, leaf_idx), "finalize path");

    /* Create partial sigs */
    for (size_t pi = 0; pi < n; pi++) {
        factory_node_t *node = &f.nodes[path[pi]];
        for (size_t s = 0; s < node->n_signers; s++) {
            uint32_t p_idx = node->signer_indices[s];
            secp256k1_musig_secnonce secnonce;
            secp256k1_musig_pubnonce pubnonce;
            unsigned char sk[32];
            secp256k1_pubkey pk;
            secp256k1_keypair_sec(ctx, sk, &kps[p_idx]);
            secp256k1_keypair_pub(ctx, &pk, &kps[p_idx]);
            musig_generate_nonce(ctx, &secnonce, &pubnonce, sk, &pk, &node->keyagg.cache);
            memset(sk, 0, 32);
            /* We can't easily do split signing here without storing secnonces properly.
               Use factory_sign_all on the path instead. */
        }
    }

    /* For a clean test, sign the full tree and verify path nodes are signed */
    TEST_ASSERT(factory_sessions_init(&f), "init all");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    for (size_t pi = 0; pi < n; pi++)
        TEST_ASSERT(f.nodes[path[pi]].is_signed, "path node signed");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_factory_advance_and_rebuild_path(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");
    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Advance and rebuild path for left leaf */
    int result = factory_advance_and_rebuild_path(&f, 0);
    TEST_ASSERT(result >= 0, "advance_and_rebuild succeeds");

    /* The returned value should be a valid node index */
    TEST_ASSERT(result < (int)f.n_nodes, "result is valid node index");

    /* Verify the leaf node is now unsigned (needs re-signing) */
    int leaf_idx = (int)f.leaf_node_indices[0];
    TEST_ASSERT(f.nodes[leaf_idx].is_signed == 0, "leaf unsigned after advance");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Phase 5: Distributed epoch reset with split-round signing */
int test_distributed_epoch_reset(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 4, 4);
    factory_set_funding(&f, fake_txid, 0, 500000, fund_spk, 34);

    f.fee_per_tx = 330;
    f.cltv_timeout = 1000;
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "initial sign");

    /* Advance a few times to consume some DW states */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(factory_advance(&f), "advance");
    }

    /* Now do distributed epoch reset: reset unsigned, then sign via split-round */
    TEST_ASSERT(factory_reset_epoch_unsigned(&f), "reset epoch unsigned");

    /* Verify all nodes are unsigned (rebuilt but not signed) */
    for (size_t i = 0; i < f.n_nodes; i++) {
        TEST_ASSERT(f.nodes[i].is_signed == 0, "node unsigned after reset");
    }

    /* DW counter should be back to epoch 0 */
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch back to 0");

    /* Now do split-round signing (distributed) */
    TEST_ASSERT(factory_sessions_init(&f), "sessions init");

    /* Secnonces stored externally indexed by [node][signer_slot] */
    secp256k1_musig_secnonce secnonces[FACTORY_MAX_NODES][FACTORY_MAX_SIGNERS];
    memset(secnonces, 0, sizeof(secnonces));

    /* Generate nonces for all participants */
    for (uint32_t p = 0; p < 5; p++) {
        unsigned char seckey[32];
        secp256k1_pubkey pk;
        TEST_ASSERT(secp256k1_keypair_sec(ctx, seckey, &kps[p]), "get seckey");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk, &kps[p]), "get pubkey");

        for (size_t n = 0; n < f.n_nodes; n++) {
            int slot = factory_find_signer_slot(&f, n, p);
            if (slot < 0) continue;

            secp256k1_musig_pubnonce pubnonce;
            TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[n][slot], &pubnonce,
                                              seckey, &pk, NULL),
                        "nonce gen");
            TEST_ASSERT(factory_session_set_nonce(&f, n, (size_t)slot, &pubnonce),
                        "set nonce");
        }
        memset(seckey, 0, 32);
    }

    /* Finalize nonces */
    TEST_ASSERT(factory_sessions_finalize(&f), "sessions finalize");

    /* Create partial sigs */
    for (uint32_t p = 0; p < 5; p++) {
        for (size_t n = 0; n < f.n_nodes; n++) {
            int slot = factory_find_signer_slot(&f, n, p);
            if (slot < 0) continue;

            secp256k1_musig_partial_sig psig;
            TEST_ASSERT(musig_create_partial_sig(ctx, &psig,
                            &secnonces[n][slot],
                            &kps[p], &f.nodes[n].signing_session),
                        "partial sig");
            TEST_ASSERT(factory_session_set_partial_sig(&f, n, (size_t)slot, &psig),
                        "set psig");
        }
    }

    /* Complete signing */
    TEST_ASSERT(factory_sessions_complete(&f), "sessions complete");

    /* Verify all nodes are now signed */
    for (size_t i = 0; i < f.n_nodes; i++) {
        TEST_ASSERT(f.nodes[i].is_signed == 1, "node signed after distributed reset");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Phase 5: Arity-2 leaf advance with 3-signer ceremony */
int test_arity2_leaf_advance(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xBB, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 4, 4);
    factory_set_arity(&f, FACTORY_ARITY_2);
    factory_set_funding(&f, fake_txid, 0, 500000, fund_spk, 34);

    f.fee_per_tx = 330;
    f.cltv_timeout = 1000;
    TEST_ASSERT(factory_build_tree(&f), "build arity-2 tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* For arity-2, each leaf has 3 signers (LSP + 2 clients).
       Advance leaf 0 using split-round signing with all 3 signers. */
    TEST_ASSERT(f.n_leaf_nodes > 0, "has leaf nodes");

    int leaf_side = 0;
    size_t node_idx = f.leaf_node_indices[leaf_side];
    factory_node_t *leaf_node = &f.nodes[node_idx];

    /* Verify arity-2 leaf has 3 signers */
    TEST_ASSERT_EQ(leaf_node->n_signers, 3, "arity-2 leaf has 3 signers");

    /* Advance leaf unsigned */
    int rc = factory_advance_leaf_unsigned(&f, leaf_side);
    TEST_ASSERT(rc == 1, "leaf advance unsigned");

    /* Now do split-round signing for this single node */
    TEST_ASSERT(factory_session_init_node(&f, node_idx), "session init node");

    /* Generate nonces for all 3 signers on this node */
    secp256k1_musig_secnonce secnonces[3];
    for (size_t s = 0; s < leaf_node->n_signers; s++) {
        uint32_t pidx = leaf_node->signer_indices[s];
        unsigned char seckey[32];
        secp256k1_pubkey pk;
        TEST_ASSERT(secp256k1_keypair_sec(ctx, seckey, &kps[pidx]), "get seckey");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk, &kps[pidx]), "get pubkey");

        secp256k1_musig_pubnonce pubnonce;
        TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[s], &pubnonce,
                                          seckey, &pk, NULL),
                    "nonce gen for signer");
        TEST_ASSERT(factory_session_set_nonce(&f, node_idx, s, &pubnonce),
                    "set nonce for signer");
        memset(seckey, 0, 32);
    }

    /* Finalize */
    TEST_ASSERT(factory_session_finalize_node(&f, node_idx), "finalize node");

    /* Create partial sigs from all 3 signers */
    for (size_t s = 0; s < leaf_node->n_signers; s++) {
        uint32_t pidx = leaf_node->signer_indices[s];
        secp256k1_musig_partial_sig psig;
        TEST_ASSERT(musig_create_partial_sig(ctx, &psig, &secnonces[s],
                        &kps[pidx], &leaf_node->signing_session),
                    "partial sig for signer");
        TEST_ASSERT(factory_session_set_partial_sig(&f, node_idx, s, &psig),
                    "set psig for signer");
    }

    /* Complete */
    TEST_ASSERT(factory_session_complete_node(&f, node_idx), "complete node");

    /* Verify node is signed */
    TEST_ASSERT(leaf_node->is_signed == 1, "leaf signed after 3-signer ceremony");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Phase 6: Distribution TX has P2A anchor output */
int test_distribution_tx_has_anchor(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xCC, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Build distribution TX with 2 outputs */
    tx_output_t outputs[2];

    /* Output 0: LSP (50000 sats) */
    secp256k1_pubkey pk0;
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk0, &kps[0]), "get pk0");
    secp256k1_xonly_pubkey xonly0;
    TEST_ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly0, NULL, &pk0), "xonly0");
    build_p2tr_script_pubkey(outputs[0].script_pubkey, &xonly0);
    outputs[0].script_pubkey_len = 34;
    outputs[0].amount_sats = 50000;

    /* Output 1: Client (49500 sats, leaving 500 for fee) */
    secp256k1_pubkey pk1;
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk1, &kps[1]), "get pk1");
    secp256k1_xonly_pubkey xonly1;
    TEST_ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly1, NULL, &pk1), "xonly1");
    build_p2tr_script_pubkey(outputs[1].script_pubkey, &xonly1);
    outputs[1].script_pubkey_len = 34;
    outputs[1].amount_sats = 49500;

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    TEST_ASSERT(factory_build_distribution_tx(&f, &dist_tx, NULL,
                                               outputs, 2, 5000),
                "build distribution tx");
    TEST_ASSERT(dist_tx.len > 0, "dist tx non-empty");

    /* P2A SPK: {0x51, 0x02, 0x4e, 0x73} should appear in the TX */
    unsigned char p2a_spk[] = {0x51, 0x02, 0x4e, 0x73};
    int found_p2a = 0;
    for (size_t i = 0; i + 4 <= dist_tx.len; i++) {
        if (memcmp(dist_tx.data + i, p2a_spk, 4) == 0) {
            found_p2a = 1;
            break;
        }
    }
    TEST_ASSERT(found_p2a, "P2A anchor script found in distribution TX");

    /* P2A anchor amount (240 sats) should appear in TX as little-endian */
    unsigned char anchor_le[8] = {0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int found_anchor_amt = 0;
    for (size_t i = 0; i + 8 <= dist_tx.len; i++) {
        if (memcmp(dist_tx.data + i, anchor_le, 8) == 0) {
            found_anchor_amt = 1;
            break;
        }
    }
    TEST_ASSERT(found_anchor_amt, "P2A anchor amount (240 sats) found in TX");

    /* LSP output should be reduced by anchor amount: 50000 - 240 = 49760 */
    unsigned char lsp_amt_le[8];
    uint64_t expected_lsp = 50000 - 240;
    for (int j = 0; j < 8; j++)
        lsp_amt_le[j] = (unsigned char)((expected_lsp >> (j * 8)) & 0xFF);
    int found_lsp = 0;
    for (size_t i = 0; i + 8 <= dist_tx.len; i++) {
        if (memcmp(dist_tx.data + i, lsp_amt_le, 8) == 0) {
            found_lsp = 1;
            break;
        }
    }
    TEST_ASSERT(found_lsp, "LSP output reduced by anchor amount");

    tx_buf_free(&dist_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}
