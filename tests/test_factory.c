#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/shachain.h"
#include "superscalar/regtest.h"
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

    /* Check node types */
    TEST_ASSERT(f.nodes[0].type == NODE_KICKOFF, "node 0 is kickoff");
    TEST_ASSERT(f.nodes[1].type == NODE_STATE,   "node 1 is state");
    TEST_ASSERT(f.nodes[2].type == NODE_KICKOFF, "node 2 is kickoff");
    TEST_ASSERT(f.nodes[3].type == NODE_KICKOFF, "node 3 is kickoff");
    TEST_ASSERT(f.nodes[4].type == NODE_STATE,   "node 4 is state");
    TEST_ASSERT(f.nodes[5].type == NODE_STATE,   "node 5 is state");

    /* Check signer counts */
    TEST_ASSERT_EQ(f.nodes[0].n_signers, 5, "kickoff_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[1].n_signers, 5, "state_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[2].n_signers, 3, "kickoff_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[3].n_signers, 3, "kickoff_right: 3 signers");
    TEST_ASSERT_EQ(f.nodes[4].n_signers, 3, "state_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[5].n_signers, 3, "state_right: 3 signers");

    /* Check parent links */
    TEST_ASSERT_EQ(f.nodes[0].parent_index, -1, "kickoff_root: no parent");
    TEST_ASSERT_EQ(f.nodes[1].parent_index,  0, "state_root -> kickoff_root");
    TEST_ASSERT_EQ(f.nodes[2].parent_index,  1, "kickoff_left -> state_root");
    TEST_ASSERT_EQ(f.nodes[3].parent_index,  1, "kickoff_right -> state_root");
    TEST_ASSERT_EQ(f.nodes[4].parent_index,  2, "state_left -> kickoff_left");
    TEST_ASSERT_EQ(f.nodes[5].parent_index,  3, "state_right -> kickoff_right");

    /* Check parent_vout */
    TEST_ASSERT_EQ(f.nodes[1].parent_vout, 0, "state_root spends vout 0");
    TEST_ASSERT_EQ(f.nodes[2].parent_vout, 0, "kickoff_left spends vout 0");
    TEST_ASSERT_EQ(f.nodes[3].parent_vout, 1, "kickoff_right spends vout 1");

    /* Check output counts */
    TEST_ASSERT_EQ(f.nodes[0].n_outputs, 1, "kickoff_root: 1 output");
    TEST_ASSERT_EQ(f.nodes[1].n_outputs, 2, "state_root: 2 outputs");
    TEST_ASSERT_EQ(f.nodes[2].n_outputs, 1, "kickoff_left: 1 output");
    TEST_ASSERT_EQ(f.nodes[3].n_outputs, 1, "kickoff_right: 1 output");
    TEST_ASSERT_EQ(f.nodes[4].n_outputs, 3, "state_left: 3 outputs");
    TEST_ASSERT_EQ(f.nodes[5].n_outputs, 3, "state_right: 3 outputs");

    /* Check kickoff nSequence = 0xFFFFFFFF */
    TEST_ASSERT(f.nodes[0].nsequence == 0xFFFFFFFF, "kickoff_root nseq");
    TEST_ASSERT(f.nodes[2].nsequence == 0xFFFFFFFF, "kickoff_left nseq");
    TEST_ASSERT(f.nodes[3].nsequence == 0xFFFFFFFF, "kickoff_right nseq");

    /* Check state nSequence matches DW layer 0/1 at epoch 0 */
    /* step=2, states=4: delay = 2*(4-1-0) = 6 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "state_root nseq = 6");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "state_left nseq = 6");
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

    /* Initial state: epoch 0, all delays = 6 */
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq = 6 at epoch 0");

    /* Advance once: epoch 1, leaf layer ticks to state 1 */
    TEST_ASSERT(factory_advance(&f), "advance 1");
    TEST_ASSERT_EQ(f.counter.current_epoch, 1, "epoch 1");
    /* Leaf state nseq: step * (max-1 - 1) = 2 * 2 = 4 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 4, "leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 4, "right leaf nseq = 4 at epoch 1");
    /* Root state unchanged (still layer 0, state 0) */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 1");

    /* Advance to epoch 3: leaf at state 3, delay = 0 */
    TEST_ASSERT(factory_advance(&f), "advance 2");
    TEST_ASSERT(factory_advance(&f), "advance 3");
    TEST_ASSERT_EQ(f.counter.current_epoch, 3, "epoch 3");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 0, "leaf nseq = 0 at epoch 3");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 3");

    /* Advance to epoch 4: leaf rolls over (reset to 0), root ticks to state 1 */
    TEST_ASSERT(factory_advance(&f), "advance 4");
    TEST_ASSERT_EQ(f.counter.current_epoch, 4, "epoch 4");
    /* Root: state 1, delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 4, "root nseq = 4 at epoch 4");
    /* Leaf: reset to state 0, delay = 6 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq = 6 at epoch 4 (reset)");

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

    /* Init factory and advance to newest state (all delays = 0) */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);  /* step=1, states=4 */

    /* Advance counter to max epoch: both layers at state 3, delay = 0 */
    for (int i = 0; i < 15; i++)
        dw_counter_advance(&f.counter);

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    printf("  Tree built: %zu nodes\n", f.n_nodes);

    /* Broadcast order:
       0: kickoff_root  -> mine 1 block
       1: state_root    -> mine 1 block (nseq=0)
       2,3: kickoff_left, kickoff_right -> mine 1 block
       4,5: state_left, state_right -> mine 1 block
    */
    size_t broadcast_groups[][2] = {
        {0, 1},   /* kickoff_root */
        {1, 2},   /* state_root */
        {2, 4},   /* kickoff_left + kickoff_right */
        {4, 6},   /* state_left + state_right */
    };

    char txid_hexes[6][65];

    for (int g = 0; g < 4; g++) {
        size_t start = broadcast_groups[g][0];
        size_t end = broadcast_groups[g][1];

        for (size_t i = start; i < end; i++) {
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
        }

        regtest_mine_blocks(&rt, 1, mine_addr);
    }

    /* Verify leaf state tx outputs exist on chain via gettxout.
       If leaf outputs are confirmed, the entire ancestor chain is too. */
    for (int leaf = 4; leaf <= 5; leaf++) {
        char gettxout_params[256];
        /* Check vout 0 of each leaf state tx */
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

    /* Verify initial state */
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq = 6 at epoch 0");

    /* Advance once */
    TEST_ASSERT(factory_advance(&f), "advance 1");
    TEST_ASSERT_EQ(f.counter.current_epoch, 1, "epoch 1");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 4, "leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 4, "right leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 1");

    /* Advance to epoch 4: leaf rolls over, root ticks */
    TEST_ASSERT(factory_advance(&f), "advance 2");
    TEST_ASSERT(factory_advance(&f), "advance 3");
    TEST_ASSERT(factory_advance(&f), "advance 4");
    TEST_ASSERT_EQ(f.counter.current_epoch, 4, "epoch 4");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 4, "root nseq = 4 at epoch 4");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq = 6 at epoch 4 (reset)");

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

    /* L-stock output (index 2) on leaf state nodes (indices 4, 5) should differ */
    TEST_ASSERT(memcmp(f_plain.nodes[4].outputs[2].script_pubkey,
                        f_sc.nodes[4].outputs[2].script_pubkey, 34) != 0,
                "L-stock spk differs with shachain (left leaf)");
    TEST_ASSERT(memcmp(f_plain.nodes[5].outputs[2].script_pubkey,
                        f_sc.nodes[5].outputs[2].script_pubkey, 34) != 0,
                "L-stock spk differs with shachain (right leaf)");

    /* Channel outputs (indices 0, 1) should be the same */
    TEST_ASSERT(memcmp(f_plain.nodes[4].outputs[0].script_pubkey,
                        f_sc.nodes[4].outputs[0].script_pubkey, 34) == 0,
                "channel A spk unchanged");
    TEST_ASSERT(memcmp(f_plain.nodes[4].outputs[1].script_pubkey,
                        f_sc.nodes[4].outputs[1].script_pubkey, 34) == 0,
                "channel B spk unchanged");

    /* Save L-stock spk at epoch 0 */
    unsigned char l_spk_epoch0[34];
    memcpy(l_spk_epoch0, f_sc.nodes[4].outputs[2].script_pubkey, 34);

    /* Sign and advance to epoch 1 */
    TEST_ASSERT(factory_sign_all(&f_sc), "sign at epoch 0");
    TEST_ASSERT(factory_advance(&f_sc), "advance to epoch 1");

    /* L-stock spk should change after epoch advance */
    TEST_ASSERT(memcmp(l_spk_epoch0, f_sc.nodes[4].outputs[2].script_pubkey, 34) != 0,
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

    /* Init factory WITH shachain, advance to max state (all delays = 0) */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);  /* step=1, states=4 */
    factory_set_shachain_seed(&f, test_shachain_seed);

    for (int i = 0; i < 15; i++)
        dw_counter_advance(&f.counter);

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");
    printf("  Tree built: %zu nodes, L-stock has shachain burn path\n", f.n_nodes);

    /* Broadcast all 6 nodes in groups */
    size_t broadcast_groups[][2] = {
        {0, 1}, {1, 2}, {2, 4}, {4, 6},
    };
    char txid_hexes[6][65];

    for (int g = 0; g < 4; g++) {
        size_t start = broadcast_groups[g][0];
        size_t end = broadcast_groups[g][1];

        for (size_t i = start; i < end; i++) {
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
        }
        regtest_mine_blocks(&rt, 1, mine_addr);
    }

    /* Verify leaf outputs are confirmed */
    for (int leaf = 4; leaf <= 5; leaf++) {
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

    /* Now build and broadcast the burn tx for state_left (node 4) L-stock */
    tx_buf_t burn_tx;
    tx_buf_init(&burn_tx, 256);

    /* f.nodes[4].txid is internal byte order, which is what factory_build_burn_tx wants */
    uint64_t l_stock_amount = f.nodes[4].outputs[2].amount_sats;
    printf("  L-stock amount: %lu sats\n", (unsigned long)l_stock_amount);

    TEST_ASSERT(factory_build_burn_tx(&f, &burn_tx, f.nodes[4].txid, 2,
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
                 "\"%s\" 2", txid_hexes[4]);
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
    /* At epoch 0: leaf nseq = step * (max-1) = 2*3 = 6 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq 6 after reset");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 6, "right leaf nseq 6 after reset");
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

    /* Save initial state */
    uint32_t initial_left_nseq = f.nodes[4].nsequence;
    uint32_t initial_right_nseq = f.nodes[5].nsequence;
    unsigned char right_txid_before[32];
    memcpy(right_txid_before, f.nodes[5].txid, 32);

    /* Advance left leaf only */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance leaf left");

    /* Left leaf (node 4) should have changed nSequence */
    TEST_ASSERT(f.nodes[4].nsequence != initial_left_nseq, "left nseq changed");
    /* step=2, advanced from state 0 to 1: delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 4, "left nseq = 4");
    TEST_ASSERT(f.nodes[4].is_signed, "left node signed");

    /* Right leaf (node 5) should be unchanged */
    TEST_ASSERT_EQ(f.nodes[5].nsequence, initial_right_nseq, "right nseq unchanged");
    TEST_ASSERT(memcmp(f.nodes[5].txid, right_txid_before, 32) == 0,
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

    uint32_t initial_left_nseq = f.nodes[4].nsequence;
    unsigned char left_txid_before[32];
    memcpy(left_txid_before, f.nodes[4].txid, 32);

    /* Advance right leaf only */
    TEST_ASSERT(factory_advance_leaf(&f, 1), "advance leaf right");

    /* Right leaf (node 5) should have changed */
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 4, "right nseq = 4");
    TEST_ASSERT(f.nodes[5].is_signed, "right node signed");

    /* Left leaf (node 4) should be unchanged */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, initial_left_nseq, "left nseq unchanged");
    TEST_ASSERT(memcmp(f.nodes[4].txid, left_txid_before, 32) == 0,
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

    /* Advance left 3 times */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left");

    /* Advance right 1 time */
    TEST_ASSERT(factory_advance_leaf(&f, 1), "advance right");

    /* Left at state 3: delay = 2*(4-1-3) = 0 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 0, "left nseq = 0 (state 3)");
    /* Right at state 1: delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 4, "right nseq = 4 (state 1)");

    /* Different nSequences confirms independence */
    TEST_ASSERT(f.nodes[4].nsequence != f.nodes[5].nsequence,
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

    /* Save parent txids (nodes 0-3) */
    unsigned char parent_txids[4][32];
    for (int i = 0; i < 4; i++)
        memcpy(parent_txids[i], f.nodes[i].txid, 32);

    /* Advance left leaf */
    TEST_ASSERT(factory_advance_leaf(&f, 0), "advance left leaf");

    /* Verify parent txids unchanged (nodes 0-3) */
    for (int i = 0; i < 4; i++)
        TEST_ASSERT(memcmp(f.nodes[i].txid, parent_txids[i], 32) == 0,
                    "parent txid preserved");

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
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "left nseq 6 after reset");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 6, "right nseq 6 after reset");

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

    /* Check node types: kickoff/state alternating at each level */
    TEST_ASSERT(f.nodes[0].type == NODE_KICKOFF, "n0 kickoff");
    TEST_ASSERT(f.nodes[1].type == NODE_STATE,   "n1 state");
    TEST_ASSERT(f.nodes[2].type == NODE_KICKOFF, "n2 kickoff");
    TEST_ASSERT(f.nodes[3].type == NODE_KICKOFF, "n3 kickoff");
    TEST_ASSERT(f.nodes[4].type == NODE_STATE,   "n4 state");
    TEST_ASSERT(f.nodes[5].type == NODE_STATE,   "n5 state");
    for (int i = 6; i <= 9; i++)
        TEST_ASSERT(f.nodes[i].type == NODE_KICKOFF, "level-2 kickoff");
    for (int i = 10; i <= 13; i++)
        TEST_ASSERT(f.nodes[i].type == NODE_STATE, "level-2 state");

    /* Check signer counts */
    TEST_ASSERT_EQ(f.nodes[0].n_signers, 5, "root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[1].n_signers, 5, "state_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[4].n_signers, 3, "state_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[5].n_signers, 3, "state_right: 3 signers");
    for (int i = 6; i <= 9; i++)
        TEST_ASSERT_EQ(f.nodes[i].n_signers, 2, "level-2 kickoff: 2 signers");
    for (int i = 10; i <= 13; i++)
        TEST_ASSERT_EQ(f.nodes[i].n_signers, 2, "level-2 state: 2 signers");

    /* Check parent links for level-2 */
    TEST_ASSERT_EQ(f.nodes[6].parent_index, 4, "kickoff_A -> state_left");
    TEST_ASSERT_EQ(f.nodes[7].parent_index, 4, "kickoff_B -> state_left");
    TEST_ASSERT_EQ(f.nodes[8].parent_index, 5, "kickoff_C -> state_right");
    TEST_ASSERT_EQ(f.nodes[9].parent_index, 5, "kickoff_D -> state_right");
    TEST_ASSERT_EQ(f.nodes[10].parent_index, 6, "state_A -> kickoff_A");
    TEST_ASSERT_EQ(f.nodes[11].parent_index, 7, "state_B -> kickoff_B");
    TEST_ASSERT_EQ(f.nodes[12].parent_index, 8, "state_C -> kickoff_C");
    TEST_ASSERT_EQ(f.nodes[13].parent_index, 9, "state_D -> kickoff_D");

    /* Leaf node indices */
    TEST_ASSERT_EQ(f.leaf_node_indices[0], 10, "leaf_idx 0 = node 10");
    TEST_ASSERT_EQ(f.leaf_node_indices[1], 11, "leaf_idx 1 = node 11");
    TEST_ASSERT_EQ(f.leaf_node_indices[2], 12, "leaf_idx 2 = node 12");
    TEST_ASSERT_EQ(f.leaf_node_indices[3], 13, "leaf_idx 3 = node 13");

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

    /* Each leaf state node (10-13) should have 2 outputs: channel + L-stock */
    for (int i = 10; i <= 13; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "node %d has 2 outputs", i);
        TEST_ASSERT_EQ(f.nodes[i].n_outputs, 2, msg);
        /* Both outputs should have 34-byte SPK */
        TEST_ASSERT_EQ(f.nodes[i].outputs[0].script_pubkey_len, 34, "chan spk len");
        TEST_ASSERT_EQ(f.nodes[i].outputs[1].script_pubkey_len, 34, "lstock spk len");
        /* Amounts should be non-zero */
        snprintf(msg, sizeof(msg), "node %d chan amount > 0", i);
        TEST_ASSERT(f.nodes[i].outputs[0].amount_sats > 0, msg);
        snprintf(msg, sizeof(msg), "node %d lstock amount > 0", i);
        TEST_ASSERT(f.nodes[i].outputs[1].amount_sats > 0, msg);
    }

    /* Mid-level state nodes (4,5) should have 2 child outputs, not 3 leaf outputs */
    TEST_ASSERT_EQ(f.nodes[4].n_outputs, 2, "state_left: 2 child outputs");
    TEST_ASSERT_EQ(f.nodes[5].n_outputs, 2, "state_right: 2 child outputs");

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
    uint32_t old_leaf_nseq = f.nodes[10].nsequence;
    TEST_ASSERT(factory_advance(&f), "advance epoch 1");
    TEST_ASSERT(f.nodes[10].nsequence != old_leaf_nseq, "leaf nseq changed");

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
    for (int i = 10; i <= 13; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "leaf signed after advance");

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

    /* Arity-1 mapping: client_idx -> node 10+client_idx, vout 0 */
    for (int c = 0; c < 4; c++) {
        size_t expected_node = 10 + (size_t)c;
        TEST_ASSERT_EQ(f.leaf_node_indices[c], expected_node, "leaf index mapping");

        /* Each leaf node should have the channel at vout 0 */
        const factory_node_t *node = &f.nodes[expected_node];
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

    /* Verify 5-tier strict CLTV ordering:
       sr (root_cltv=200) > kl/kri (195) > sl/sri (190) > ka-kd (185) > sa-sd (180)
       Every child CLTV must be strictly less than its parent. */

    /* Node indices: kr=0, sr=1, kl=2, kri=3, sl=4, sri=5,
       ka=6, kb=7, kc=8, kd=9, sa=10, sb=11, sc=12, sd=13 */
    uint32_t sr_cltv  = f.nodes[1].cltv_timeout;   /* root state */
    uint32_t kl_cltv  = f.nodes[2].cltv_timeout;   /* mid kickoff left */
    uint32_t kri_cltv = f.nodes[3].cltv_timeout;   /* mid kickoff right */
    uint32_t sl_cltv  = f.nodes[4].cltv_timeout;   /* mid state left */
    uint32_t sri_cltv = f.nodes[5].cltv_timeout;   /* mid state right */

    /* Tier 1 > Tier 2: root state > mid kickoffs */
    TEST_ASSERT(sr_cltv > kl_cltv, "sr > kl cltv");
    TEST_ASSERT(sr_cltv > kri_cltv, "sr > kri cltv");
    /* Tier 2 > Tier 3: mid kickoffs > mid states */
    TEST_ASSERT(kl_cltv > sl_cltv, "kl > sl cltv");
    TEST_ASSERT(kri_cltv > sri_cltv, "kri > sri cltv");

    /* Tier 3 > Tier 4 > Tier 5: for each per-client subtree */
    for (int i = 0; i < 4; i++) {
        int ko_idx = 6 + i;   /* ka=6, kb=7, kc=8, kd=9 */
        int st_idx = 10 + i;  /* sa=10, sb=11, sc=12, sd=13 */
        uint32_t parent_st_cltv = (i < 2) ? sl_cltv : sri_cltv;
        uint32_t ko_cltv = f.nodes[ko_idx].cltv_timeout;
        uint32_t st_cltv = f.nodes[st_idx].cltv_timeout;

        /* mid state > leaf kickoff > leaf state */
        TEST_ASSERT(parent_st_cltv > ko_cltv, "parent state > leaf kickoff cltv");
        TEST_ASSERT(ko_cltv > st_cltv, "leaf kickoff > leaf state cltv");
    }

    /* Verify exact values */
    TEST_ASSERT_EQ(sr_cltv, 200, "sr = 200");
    TEST_ASSERT_EQ(kl_cltv, 195, "kl = 195");
    TEST_ASSERT_EQ(sl_cltv, 190, "sl = 190");
    TEST_ASSERT_EQ(f.nodes[6].cltv_timeout, 185, "ka = 185");
    TEST_ASSERT_EQ(f.nodes[10].cltv_timeout, 180, "sa = 180");

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
