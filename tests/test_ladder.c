#include "superscalar/ladder.h"
#include "superscalar/adaptor.h"
#include "superscalar/regtest.h"
#include "superscalar/lsp_channels.h"
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

/* Secret keys */
static const unsigned char lsp_sec[32] = { [0 ... 31] = 0x10 };
static const unsigned char client_secs[4][32] = {
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static int make_client_keypairs(secp256k1_context *ctx,
                                  secp256k1_keypair *client_kps) {
    for (int i = 0; i < 4; i++) {
        if (!secp256k1_keypair_create(ctx, &client_kps[i], client_secs[i])) return 0;
    }
    return 1;
}

/* Compute funding spk for 5-of-5 (LSP + 4 clients) */
static int compute_funding_spk(
    secp256k1_context *ctx,
    const secp256k1_keypair *lsp_kp,
    const secp256k1_keypair *client_kps,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_xonly_out)
{
    secp256k1_pubkey pks[5];
    if (!secp256k1_keypair_pub(ctx, &pks[0], lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i + 1], &client_kps[i])) return 0;
    }

    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 5)) return 0;

    unsigned char ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tw_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &tmp.cache, tweak))
        return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_xonly_out, NULL, &tw_pk))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_xonly_out);
    return 1;
}

/* --- Unit tests --- */

/* Test 12: Create 3 overlapping factories, verify IDs and lifecycle params */
int test_ladder_create_factories(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);  /* 100 active, 30 dying */

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Create 3 factories at different blocks */
    for (int i = 0; i < 3; i++) {
        fake_txid[0] = (unsigned char)i;
        ladder_advance_block(&lad, (uint32_t)(i * 100));
        TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                           fake_txid, 0, fund_spk, 34),
                    "create factory");
    }

    TEST_ASSERT_EQ(lad.n_factories, 3, "3 factories");
    TEST_ASSERT_EQ(lad.factories[0].factory_id, 0, "factory 0 id");
    TEST_ASSERT_EQ(lad.factories[1].factory_id, 1, "factory 1 id");
    TEST_ASSERT_EQ(lad.factories[2].factory_id, 2, "factory 2 id");

    /* Verify lifecycle params */
    TEST_ASSERT_EQ(lad.factories[0].factory.active_blocks, 100, "f0 active");
    TEST_ASSERT_EQ(lad.factories[0].factory.dying_blocks, 30, "f0 dying");
    TEST_ASSERT_EQ(lad.factories[0].factory.created_block, 0, "f0 created");
    TEST_ASSERT_EQ(lad.factories[1].factory.created_block, 100, "f1 created");
    TEST_ASSERT_EQ(lad.factories[2].factory.created_block, 200, "f2 created");

    /* All should be initialized and funded */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(lad.factories[i].is_initialized, "initialized");
        TEST_ASSERT(lad.factories[i].is_funded, "funded");
    }

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 13: Advance blocks, verify ACTIVE→DYING→EXPIRED transitions */
int test_ladder_state_transitions(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Create factory at block 0 */
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    /* At block 0: ACTIVE */
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_ACTIVE, "active at 0");

    /* At block 50: still ACTIVE */
    ladder_advance_block(&lad, 50);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_ACTIVE, "active at 50");

    /* At block 99: last ACTIVE block */
    ladder_advance_block(&lad, 99);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_ACTIVE, "active at 99");

    /* At block 100: DYING starts */
    ladder_advance_block(&lad, 100);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "dying at 100");

    /* At block 129: last DYING block */
    ladder_advance_block(&lad, 129);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "dying at 129");

    /* At block 130: EXPIRED */
    ladder_advance_block(&lad, 130);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_EXPIRED, "expired at 130");

    /* Verify helpers */
    ladder_factory_t *active = ladder_get_active(&lad);
    TEST_ASSERT(active == NULL, "no active factory");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 14: Record 4 client departures, verify ladder_can_close returns true,
   build coop close with extracted keys */
int test_ladder_key_turnover_close(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    secp256k1_pubkey client_pks[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;
    for (int i = 0; i < 4; i++) {
        if (!secp256k1_keypair_pub(ctx, &client_pks[i], &client_kps[i])) return 0;
    }

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    /* Can't close yet */
    TEST_ASSERT(!ladder_can_close(&lad, 0), "can't close yet");

    /* Simulate PTLC key turnover for each client */
    secp256k1_pubkey all_pks[5];
    secp256k1_keypair all_kps[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        all_pks[i + 1] = client_pks[i];
    }

    for (int c = 0; c < 4; c++) {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, all_pks, 5);

        unsigned char presig[64];
        int nonce_parity;
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fake_txid, all_kps, 5, &ka, NULL, &all_pks[c + 1]),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_secs[c],
                                    nonce_parity),
                    "adapt");

        unsigned char extracted[32];
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig,
                                            nonce_parity),
                    "extract");

        TEST_ASSERT(ladder_record_key_turnover(&lad, 0, (uint32_t)(c + 1),
                                                extracted),
                    "record turnover");
    }

    /* Now can close */
    TEST_ASSERT(ladder_can_close(&lad, 0), "can close now");

    /* Build close tx */
    tx_output_t output;
    output.amount_sats = 100000 - 500;
    build_p2tr_script_pubkey(output.script_pubkey, &fund_tweaked);
    output.script_pubkey_len = 34;

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(ladder_build_close(&lad, 0, &close_tx, &output, 1),
                "build close");
    TEST_ASSERT(close_tx.len > 0, "close tx non-empty");

    tx_buf_free(&close_tx);
    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 15: Create factory at block 0, advance to dying, create factory 2,
   verify both exist with correct states */
int test_ladder_overlapping(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid1[32], fake_txid2[32];
    memset(fake_txid1, 0xAA, 32);
    memset(fake_txid2, 0xBB, 32);

    /* Create factory 0 at block 0 */
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid1, 0, fund_spk, 34),
                "create factory 0");

    /* Advance to block 100: factory 0 enters dying */
    ladder_advance_block(&lad, 100);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "f0 dying");

    /* Create factory 1 at block 100 */
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid2, 0, fund_spk, 34),
                "create factory 1");

    /* Update block to re-evaluate states */
    ladder_advance_block(&lad, 100);

    /* Verify both exist with correct states */
    TEST_ASSERT_EQ(lad.n_factories, 2, "2 factories");
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "f0 dying");
    TEST_ASSERT_EQ(lad.factories[1].cached_state, FACTORY_ACTIVE, "f1 active");

    /* Get active/dying by state */
    ladder_factory_t *active = ladder_get_active(&lad);
    ladder_factory_t *dying = ladder_get_dying(&lad);
    TEST_ASSERT(active != NULL, "found active");
    TEST_ASSERT(dying != NULL, "found dying");
    TEST_ASSERT_EQ(active->factory_id, 1, "active is f1");
    TEST_ASSERT_EQ(dying->factory_id, 0, "dying is f0");

    /* Advance past factory 0 expiry */
    ladder_advance_block(&lad, 130);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_EXPIRED, "f0 expired");
    TEST_ASSERT_EQ(lad.factories[1].cached_state, FACTORY_ACTIVE, "f1 still active");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Regtest tests --- */

/* Helper: derive bech32m address from tweaked xonly key */
static int derive_factory_address(regtest_t *rt, secp256k1_context *ctx,
                                    const secp256k1_xonly_pubkey *tweaked,
                                    char *addr_out, size_t addr_len) {
    unsigned char ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, tweaked)) return 0;
    char key_hex[65];
    hex_encode(ser, 32, key_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);
    char *desc_result = regtest_exec(rt, "getdescriptorinfo", params);
    if (!desc_result) return 0;

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    if (!dstart) { free(desc_result); return 0; }
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(rt, "deriveaddresses", params);
    if (!addr_result) return 0;

    char *start = strchr(addr_result, '"'); start++;
    char *end = strchr(start, '"');
    size_t len = (size_t)(end - start);
    if (len >= addr_len) { free(addr_result); return 0; }
    memcpy(addr_out, start, len);
    addr_out[len] = '\0';
    free(addr_result);
    return 1;
}

/* Test 16 (regtest): Fund factory, advance through ACTIVE→DYING→EXPIRED */
int test_regtest_ladder_lifecycle(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_ladder_life");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    char factory_addr[128];
    TEST_ASSERT(derive_factory_address(&rt, ctx, &fund_tweaked,
                                         factory_addr, sizeof(factory_addr)),
                "derive address");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Find vout */
    uint64_t fund_amount = 0;
    int found_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding_txid_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                found_vout = v;
                fund_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find vout");

    /* Use small block counts for regtest: active=10, dying=5 */
    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 10, 5);

    /* Get current block height */
    char *height_str = regtest_exec(&rt, "getblockcount", "");
    TEST_ASSERT(height_str != NULL, "getblockcount");
    uint32_t start_height = (uint32_t)atoi(height_str);
    free(height_str);
    lad.current_block = start_height;

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, fund_amount,
                                       fund_txid_bytes, (uint32_t)found_vout,
                                       fund_spk, 34),
                "create factory");
    printf("  Factory created at block %u\n", start_height);

    /* ACTIVE: mine 5 blocks, verify still active */
    regtest_mine_blocks(&rt, 5, mine_addr);
    ladder_advance_block(&lad, start_height + 5);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_ACTIVE, "active +5");
    printf("  Block %u: ACTIVE\n", start_height + 5);

    /* DYING: mine 5 more (total 10), should be dying */
    regtest_mine_blocks(&rt, 5, mine_addr);
    ladder_advance_block(&lad, start_height + 10);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "dying +10");
    printf("  Block %u: DYING\n", start_height + 10);

    /* EXPIRED: mine 5 more (total 15), should be expired */
    regtest_mine_blocks(&rt, 5, mine_addr);
    ladder_advance_block(&lad, start_height + 15);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_EXPIRED, "expired +15");
    printf("  Block %u: EXPIRED\n", start_height + 15);

    printf("  Lifecycle transitions verified on-chain!\n");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 17 (regtest): Full demo - fund factory 1, PTLC migrate, coop-close,
   fund factory 2 with reclaimed UTXO */
int test_regtest_ladder_ptlc_migration(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_ladder_ptlc");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    secp256k1_pubkey client_pks[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;
    for (int i = 0; i < 4; i++) {
        if (!secp256k1_keypair_pub(ctx, &client_pks[i], &client_kps[i])) return 0;
    }

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    char factory_addr[128];
    TEST_ASSERT(derive_factory_address(&rt, ctx, &fund_tweaked,
                                         factory_addr, sizeof(factory_addr)),
                "derive address");

    /* Fund factory 1 */
    char funding1_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding1_hex),
                "fund factory 1");
    regtest_mine_blocks(&rt, 1, mine_addr);
    printf("  Factory 1 funded: %s\n", funding1_hex);

    unsigned char fund1_txid[32];
    hex_decode(funding1_hex, fund1_txid, 32);
    reverse_bytes(fund1_txid, 32);

    uint64_t fund1_amount = 0;
    int fund1_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding1_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                fund1_vout = v;
                fund1_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(fund1_vout >= 0, "find factory 1 vout");

    /* Create ladder and factory 1 */
    char *height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t start_height = (uint32_t)atoi(height_str);
    free(height_str);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 10, 5);  /* active=10, dying=5 */
    lad.current_block = start_height;

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, fund1_amount,
                                       fund1_txid, (uint32_t)fund1_vout,
                                       fund_spk, 34),
                "create factory 1");

    /* Advance to dying period */
    regtest_mine_blocks(&rt, 10, mine_addr);
    ladder_advance_block(&lad, start_height + 10);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "f1 dying");
    printf("  Factory 1 now DYING at block %u\n", start_height + 10);

    /* PTLC key turnover for all 4 clients */
    secp256k1_pubkey all_pks[5];
    secp256k1_keypair all_kps[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        all_pks[i + 1] = client_pks[i];
    }

    for (int c = 0; c < 4; c++) {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, all_pks, 5);

        unsigned char presig[64];
        int nonce_parity;
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fund1_txid, all_kps, 5, &ka, NULL, &all_pks[c + 1]),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_secs[c],
                                    nonce_parity),
                    "adapt");

        unsigned char extracted[32];
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig,
                                            nonce_parity),
                    "extract");

        TEST_ASSERT(ladder_record_key_turnover(&lad, 0, (uint32_t)(c + 1),
                                                extracted),
                    "record turnover");
    }
    TEST_ASSERT(ladder_can_close(&lad, 0), "can close factory 1");

    /* Build and broadcast cooperative close of factory 1 */
    /* Output goes to a fresh P2TR address the LSP controls */
    tx_output_t close_output;
    close_output.amount_sats = fund1_amount - 500;
    {
        secp256k1_pubkey lsp_pk;
        if (!secp256k1_keypair_pub(ctx, &lsp_pk, &lsp_kp)) return 0;
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &lsp_pk)) return 0;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &lsp_xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &lsp_xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw)) return 0;
        build_p2tr_script_pubkey(close_output.script_pubkey, &tw_xonly);
        close_output.script_pubkey_len = 34;
    }

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(ladder_build_close(&lad, 0, &close_tx, &close_output, 1),
                "build close tx");

    char *close_hex = (char *)malloc(close_tx.len * 2 + 1);
    hex_encode(close_tx.data, close_tx.len, close_hex);

    char close_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, close_hex, close_txid_hex);
    free(close_hex);
    TEST_ASSERT(sent, "broadcast close");
    printf("  Factory 1 coop close: %s\n", close_txid_hex);

    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, close_txid_hex);
    TEST_ASSERT(conf > 0, "close confirmed");

    /* Now fund factory 2 using a new funding tx */
    char funding2_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding2_hex),
                "fund factory 2");
    regtest_mine_blocks(&rt, 1, mine_addr);
    printf("  Factory 2 funded: %s\n", funding2_hex);

    unsigned char fund2_txid[32];
    hex_decode(funding2_hex, fund2_txid, 32);
    reverse_bytes(fund2_txid, 32);

    uint64_t fund2_amount = 0;
    int fund2_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding2_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                fund2_vout = v;
                fund2_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(fund2_vout >= 0, "find factory 2 vout");

    /* Update current block */
    height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t cur_height = (uint32_t)atoi(height_str);
    free(height_str);
    ladder_advance_block(&lad, cur_height);

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, fund2_amount,
                                       fund2_txid, (uint32_t)fund2_vout,
                                       fund_spk, 34),
                "create factory 2");

    TEST_ASSERT_EQ(lad.n_factories, 2, "2 factories in ladder");
    TEST_ASSERT_EQ(lad.factories[1].cached_state, FACTORY_ACTIVE, "f2 active");
    printf("  Factory 2 created and ACTIVE. Full migration demo complete!\n");

    tx_buf_free(&close_tx);
    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 18 (regtest): Fund factory, advance past CLTV timeout, broadcast
   pre-signed distribution tx, verify clients receive funds */
int test_regtest_ladder_distribution_fallback(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_dist");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    char factory_addr[128];
    TEST_ASSERT(derive_factory_address(&rt, ctx, &fund_tweaked,
                                         factory_addr, sizeof(factory_addr)),
                "derive address");

    char funding_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_hex),
                "fund");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid[32];
    hex_decode(funding_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                found_vout = v;
                fund_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find vout");

    /* Get current height */
    char *height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t start_height = (uint32_t)atoi(height_str);
    free(height_str);

    /* nLockTime = current height + 20 (simulates CLTV timeout) */
    uint32_t nlocktime = start_height + 20;

    /* Build factory with 5 keypairs */
    secp256k1_keypair all_kps[5];
    secp256k1_pubkey all_pks[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        if (!secp256k1_keypair_pub(ctx, &all_pks[i + 1], &client_kps[i])) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 1, 4);
    factory_set_funding(&f, fund_txid, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Build distribution tx: 5 equal outputs (1 per participant) */
    uint64_t dist_fee = 500;
    uint64_t per_output = (fund_amount - dist_fee) / 5;
    uint64_t remainder = (fund_amount - dist_fee) - per_output * 5;

    tx_output_t dist_outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &all_pks[i])) return 0;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw)) return 0;
        build_p2tr_script_pubkey(dist_outputs[i].script_pubkey, &tw_xonly);
        dist_outputs[i].script_pubkey_len = 34;
        dist_outputs[i].amount_sats = per_output + (i == 4 ? remainder : 0);
    }

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    TEST_ASSERT(factory_build_distribution_tx(&f, &dist_tx, NULL,
                                               dist_outputs, 5, nlocktime),
                "build distribution tx");
    TEST_ASSERT(dist_tx.len > 0, "dist tx non-empty");
    printf("  Distribution tx built (nLockTime=%u)\n", nlocktime);

    /* Try broadcasting before nLockTime — should fail (BIP-113 median time) */
    char *dist_hex = (char *)malloc(dist_tx.len * 2 + 1);
    hex_encode(dist_tx.data, dist_tx.len, dist_hex);

    char dist_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, dist_hex, dist_txid_hex);
    /* This might succeed or fail depending on current height vs nLockTime */
    if (sent) {
        printf("  Distribution tx already accepted (height >= nLockTime)\n");
    } else {
        printf("  Distribution tx rejected (height < nLockTime), mining...\n");

        /* Mine until past nLockTime */
        height_str = regtest_exec(&rt, "getblockcount", "");
        uint32_t cur = (uint32_t)atoi(height_str);
        free(height_str);

        int blocks_needed = (int)(nlocktime - cur + 1);
        if (blocks_needed > 0)
            regtest_mine_blocks(&rt, blocks_needed, mine_addr);

        /* Try again */
        sent = regtest_send_raw_tx(&rt, dist_hex, dist_txid_hex);
        TEST_ASSERT(sent, "distribution tx accepted after nLockTime");
    }
    free(dist_hex);

    printf("  Distribution tx broadcast: %s\n", dist_txid_hex);
    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, dist_txid_hex);
    TEST_ASSERT(conf > 0, "distribution tx confirmed");
    printf("  Distribution tx confirmed! Clients receive fallback funds.\n");

    tx_buf_free(&dist_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Continuous Ladder Daemon (Gap #3) tests --- */

/* Test: ladder_evict_expired removes EXPIRED factories and compacts array */
int test_ladder_evict_expired(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Create 3 factories at blocks 0, 100, 200 */
    for (int i = 0; i < 3; i++) {
        fake_txid[0] = (unsigned char)i;
        ladder_advance_block(&lad, (uint32_t)(i * 100));
        TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                           fake_txid, 0, fund_spk, 34),
                    "create factory");
    }
    TEST_ASSERT_EQ(lad.n_factories, 3, "3 factories");

    /* Advance to block 310: factory 0 EXPIRED (0+100+30=130), factory 1 EXPIRED (100+100+30=230),
       factory 2 DYING (200+100=300..330) */
    ladder_advance_block(&lad, 310);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_EXPIRED, "f0 expired");
    TEST_ASSERT_EQ(lad.factories[1].cached_state, FACTORY_EXPIRED, "f1 expired");
    TEST_ASSERT_EQ(lad.factories[2].cached_state, FACTORY_DYING, "f2 dying");

    /* Evict expired */
    size_t freed = ladder_evict_expired(&lad);
    TEST_ASSERT_EQ(freed, 2, "freed 2 slots");
    TEST_ASSERT_EQ(lad.n_factories, 1, "1 factory remaining");
    TEST_ASSERT_EQ(lad.factories[0].factory_id, 2, "remaining is factory 2");
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "still dying");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: auto-rotation trigger fires only on ACTIVE→DYING transition,
   and rot_attempted_mask prevents double-trigger */
int test_rotation_trigger_condition(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    /* Save old state */
    factory_state_t old_state = lad.factories[0].cached_state;
    TEST_ASSERT_EQ(old_state, FACTORY_ACTIVE, "starts active");

    /* Advance to DYING */
    ladder_advance_block(&lad, 100);
    factory_state_t new_state = lad.factories[0].cached_state;
    TEST_ASSERT_EQ(new_state, FACTORY_DYING, "now dying");

    /* Simulate trigger condition check */
    uint32_t attempted_mask = 0;
    int should_trigger = (new_state == FACTORY_DYING &&
                          old_state == FACTORY_ACTIVE &&
                          !(attempted_mask & (1u << lad.factories[0].factory_id)));
    TEST_ASSERT(should_trigger, "trigger fires on ACTIVE->DYING");

    /* Mark as attempted */
    attempted_mask |= (1u << lad.factories[0].factory_id);

    /* Same transition again (e.g. re-checking same height) — should NOT trigger */
    old_state = new_state;
    ladder_advance_block(&lad, 101);
    new_state = lad.factories[0].cached_state;
    should_trigger = (new_state == FACTORY_DYING &&
                      old_state == FACTORY_ACTIVE &&
                      !(attempted_mask & (1u << lad.factories[0].factory_id)));
    TEST_ASSERT(!should_trigger, "no double trigger (state same)");

    /* Factory 0 already attempted, so even with forced condition it's masked */
    should_trigger = (1 && !(attempted_mask & (1u << lad.factories[0].factory_id)));
    TEST_ASSERT(!should_trigger, "masked by attempted_mask");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: rotation context fields survive the save/restore pattern
   used in lsp_channels_rotate_factory */
int test_rotation_context_save_restore(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Build a minimal factory for lsp_channels_init */
    unsigned char lsp_sec_local[32];
    memset(lsp_sec_local, 0x10, 32);
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec_local)) return 0;

    secp256k1_keypair all_kps[5];
    all_kps[0] = lsp_kp;
    for (int i = 0; i < 4; i++) {
        unsigned char s[32];
        memset(s, 0x21 + i * 0x11, 32);
        if (!secp256k1_keypair_create(ctx, &all_kps[i + 1], s)) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 1, 4);

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0xBB, 32);
    memset(fake_spk, 0xCC, 34);
    factory_set_funding(&f, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Init mgr with rot fields set */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, lsp_sec_local, 4), "init mgr");

    /* Set rot fields */
    memset(mgr.rot_lsp_seckey, 0xAA, 32);
    mgr.rot_fee_est = (void *)0xDEADBEEF;
    memset(mgr.rot_fund_spk, 0xBB, 34);
    mgr.rot_fund_spk_len = 34;
    strncpy(mgr.rot_fund_addr, "tb1qtest123", sizeof(mgr.rot_fund_addr));
    strncpy(mgr.rot_mine_addr, "tb1qmine456", sizeof(mgr.rot_mine_addr));
    mgr.rot_step_blocks = 10;
    mgr.rot_states_per_layer = 4;
    mgr.rot_is_regtest = 1;
    mgr.rot_funding_sats = 100000;
    mgr.rot_auto_rotate = 1;
    mgr.rot_attempted_mask = 0x05;
    mgr.bridge_fd = 42;
    mgr.persist = (void *)0xCAFEBABE;
    mgr.ladder = (void *)0x12345678;

    /* Save state (same pattern as lsp_channels_rotate_factory) */
    int saved_bridge_fd = mgr.bridge_fd;
    void *saved_persist = mgr.persist;
    void *saved_ladder = mgr.ladder;
    unsigned char saved_seckey[32];
    memcpy(saved_seckey, mgr.rot_lsp_seckey, 32);
    void *saved_fee_est = mgr.rot_fee_est;
    uint16_t saved_step_blocks = mgr.rot_step_blocks;
    uint32_t saved_spl = mgr.rot_states_per_layer;
    int saved_is_regtest = mgr.rot_is_regtest;
    uint64_t saved_funding_sats = mgr.rot_funding_sats;
    int saved_auto_rotate = mgr.rot_auto_rotate;
    uint32_t saved_attempted_mask = mgr.rot_attempted_mask;

    /* Re-init (memsets mgr to 0) */
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, lsp_sec_local, 4), "reinit mgr");

    /* Verify fields are zeroed */
    TEST_ASSERT_EQ(mgr.bridge_fd, -1, "bridge_fd reset to -1");
    TEST_ASSERT_EQ((long)(uintptr_t)mgr.persist, 0, "persist zeroed");
    TEST_ASSERT_EQ((long)(uintptr_t)mgr.ladder, 0, "ladder zeroed");
    TEST_ASSERT_EQ(mgr.rot_auto_rotate, 0, "rot_auto_rotate zeroed");

    /* Restore */
    mgr.bridge_fd = saved_bridge_fd;
    mgr.persist = saved_persist;
    mgr.ladder = saved_ladder;
    memcpy(mgr.rot_lsp_seckey, saved_seckey, 32);
    mgr.rot_fee_est = saved_fee_est;
    mgr.rot_step_blocks = saved_step_blocks;
    mgr.rot_states_per_layer = saved_spl;
    mgr.rot_is_regtest = saved_is_regtest;
    mgr.rot_funding_sats = saved_funding_sats;
    mgr.rot_auto_rotate = saved_auto_rotate;
    mgr.rot_attempted_mask = saved_attempted_mask;

    /* Verify restored values */
    TEST_ASSERT_EQ(mgr.bridge_fd, 42, "bridge_fd restored");
    TEST_ASSERT_EQ((long)(uintptr_t)mgr.persist, (long)(uintptr_t)0xCAFEBABE, "persist restored");
    TEST_ASSERT_EQ((long)(uintptr_t)mgr.ladder, (long)(uintptr_t)0x12345678, "ladder restored");
    unsigned char expected_seckey[32];
    memset(expected_seckey, 0xAA, 32);
    TEST_ASSERT(memcmp(mgr.rot_lsp_seckey, expected_seckey, 32) == 0, "seckey restored");
    TEST_ASSERT_EQ((long)(uintptr_t)mgr.rot_fee_est, (long)(uintptr_t)0xDEADBEEF, "fee_est restored");
    TEST_ASSERT_EQ(mgr.rot_step_blocks, 10, "step_blocks restored");
    TEST_ASSERT_EQ(mgr.rot_states_per_layer, 4, "spl restored");
    TEST_ASSERT_EQ(mgr.rot_is_regtest, 1, "is_regtest restored");
    TEST_ASSERT_EQ((long)mgr.rot_funding_sats, 100000, "funding_sats restored");
    TEST_ASSERT_EQ(mgr.rot_auto_rotate, 1, "auto_rotate restored");
    TEST_ASSERT_EQ(mgr.rot_attempted_mask, 0x05, "attempted_mask restored");

    memset(saved_seckey, 0, 32);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Adversarial Test 3: PTLC turnover completes but LSP refuses cooperative close.
   Distribution tx nLockTime fallback returns funds to all clients. */
int test_regtest_ptlc_no_coop_close(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_no_coop");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 0.01))
        regtest_mine_for_balance(&rt, 0.002, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.002, "factory setup for funding");

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    char factory_addr[128];
    TEST_ASSERT(derive_factory_address(&rt, ctx, &fund_tweaked,
                                         factory_addr, sizeof(factory_addr)),
                "derive address");

    char funding_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_hex),
                "fund");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid[32];
    hex_decode(funding_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                found_vout = v;
                fund_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find vout");

    char *height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t start_height = (uint32_t)atoi(height_str);
    free(height_str);

    /* nLockTime simulates CLTV timeout after factory expires */
    uint32_t nlocktime = start_height + 20;

    /* Build factory */
    secp256k1_keypair all_kps[5];
    secp256k1_pubkey all_pks[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        if (!secp256k1_keypair_pub(ctx, &all_pks[i + 1], &client_kps[i])) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 1, 4);
    factory_set_funding(&f, fund_txid, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* LSP has all client keys (PTLC turnover complete) but refuses coop close.
       Build distribution tx as fallback: 5 equal outputs (1 per participant). */
    uint64_t dist_fee = 500;
    uint64_t per_output = (fund_amount - dist_fee) / 5;
    uint64_t remainder = (fund_amount - dist_fee) - per_output * 5;

    tx_output_t dist_outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &all_pks[i])) return 0;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw)) return 0;
        build_p2tr_script_pubkey(dist_outputs[i].script_pubkey, &tw_xonly);
        dist_outputs[i].script_pubkey_len = 34;
        dist_outputs[i].amount_sats = per_output + (i == 4 ? remainder : 0);
    }

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    TEST_ASSERT(factory_build_distribution_tx(&f, &dist_tx, NULL,
                                               dist_outputs, 5, nlocktime),
                "build distribution tx");
    printf("  Distribution tx built (nLockTime=%u, LSP refused coop close)\n", nlocktime);

    /* Mine past nLockTime */
    height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t cur = (uint32_t)atoi(height_str);
    free(height_str);

    int blocks_needed = (int)(nlocktime - cur + 1);
    if (blocks_needed > 0)
        regtest_mine_blocks(&rt, blocks_needed, mine_addr);

    /* Broadcast distribution tx */
    char *dist_hex = (char *)malloc(dist_tx.len * 2 + 1);
    hex_encode(dist_tx.data, dist_tx.len, dist_hex);
    char dist_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, dist_hex, dist_txid_hex);
    free(dist_hex);
    TEST_ASSERT(sent, "distribution tx accepted after nLockTime");
    printf("  Distribution tx broadcast: %s\n", dist_txid_hex);

    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, dist_txid_hex);
    TEST_ASSERT(conf > 0, "distribution tx confirmed");

    /* Verify each client output amount matches expected */
    for (int i = 0; i < 5; i++) {
        uint64_t out_amt;
        unsigned char out_spk[64];
        size_t out_spk_len;
        int got = regtest_get_tx_output(&rt, dist_txid_hex, (uint32_t)i,
                                          &out_amt, out_spk, &out_spk_len);
        TEST_ASSERT(got, "get distribution output");
        uint64_t expected = per_output + (i == 4 ? remainder : 0);
        TEST_ASSERT(out_amt == expected, "output amount matches");
    }
    printf("  All 5 participants receive correct distribution amounts.\n");
    printf("  PTLC turnover + no coop close → distribution fallback works!\n");

    tx_buf_free(&dist_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Adversarial Test 4: All clients offline — distribution tx recovery.
   LSP can recover via distribution tx after nLockTime, and client funds are preserved. */
int test_regtest_all_offline_recovery(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_offline_rec");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 0.01))
        regtest_mine_for_balance(&rt, 0.002, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.002, "factory setup for funding");

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    char factory_addr[128];
    TEST_ASSERT(derive_factory_address(&rt, ctx, &fund_tweaked,
                                         factory_addr, sizeof(factory_addr)),
                "derive address");

    char funding_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_hex),
                "fund");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid[32];
    hex_decode(funding_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);

    uint64_t fund_amount = 0;
    int found_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                found_vout = v;
                fund_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find vout");

    char *height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t start_height = (uint32_t)atoi(height_str);
    free(height_str);

    uint32_t nlocktime = start_height + 20;

    secp256k1_keypair all_kps[5];
    secp256k1_pubkey all_pks[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        if (!secp256k1_keypair_pub(ctx, &all_pks[i + 1], &client_kps[i])) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 1, 4);
    factory_set_funding(&f, fund_txid, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* "All clients go offline" — no client operations performed.
       LSP builds distribution tx with N+1 outputs. */
    uint64_t dist_fee = 500;
    uint64_t per_output = (fund_amount - dist_fee) / 5;
    uint64_t remainder = (fund_amount - dist_fee) - per_output * 5;

    tx_output_t dist_outputs[5];
    for (int i = 0; i < 5; i++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &all_pks[i])) return 0;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw)) return 0;
        build_p2tr_script_pubkey(dist_outputs[i].script_pubkey, &tw_xonly);
        dist_outputs[i].script_pubkey_len = 34;
        dist_outputs[i].amount_sats = per_output + (i == 4 ? remainder : 0);
    }

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    TEST_ASSERT(factory_build_distribution_tx(&f, &dist_tx, NULL,
                                               dist_outputs, 5, nlocktime),
                "build distribution tx");

    /* Mine past nLockTime */
    height_str = regtest_exec(&rt, "getblockcount", "");
    uint32_t cur = (uint32_t)atoi(height_str);
    free(height_str);
    int blocks_needed = (int)(nlocktime - cur + 1);
    if (blocks_needed > 0)
        regtest_mine_blocks(&rt, blocks_needed, mine_addr);

    char *dist_hex = (char *)malloc(dist_tx.len * 2 + 1);
    hex_encode(dist_tx.data, dist_tx.len, dist_hex);
    char dist_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, dist_hex, dist_txid_hex);
    free(dist_hex);
    TEST_ASSERT(sent, "distribution tx accepted");
    printf("  Distribution tx (all offline): %s\n", dist_txid_hex);

    regtest_mine_blocks(&rt, 1, mine_addr);
    int dist_conf = regtest_get_confirmations(&rt, dist_txid_hex);
    TEST_ASSERT(dist_conf > 0, "distribution tx confirmed");

    /* Verify: distribution tx has 5 outputs (1 LSP + 4 clients) */
    int output_count = 0;
    for (int v = 0; v < 6; v++) {
        uint64_t amt;
        unsigned char spk[64];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, dist_txid_hex, (uint32_t)v,
                                    &amt, spk, &spk_len))
            output_count++;
    }
    TEST_ASSERT(output_count == 5, "distribution tx has 5 outputs");

    /* Verify: each output >= expected balance (P2TR to participant keys) */
    for (int i = 0; i < 5; i++) {
        uint64_t out_amt;
        unsigned char out_spk[64];
        size_t out_spk_len;
        TEST_ASSERT(regtest_get_tx_output(&rt, dist_txid_hex, (uint32_t)i,
                                            &out_amt, out_spk, &out_spk_len),
                    "get output");
        TEST_ASSERT(out_amt >= per_output, "output amount sufficient");
        /* Verify output is P2TR (0x5120 prefix) */
        TEST_ASSERT(out_spk_len == 34 && out_spk[0] == 0x51 && out_spk[1] == 0x20,
                    "output is P2TR");
    }

    printf("  All offline recovery complete: 5 P2TR outputs, client funds preserved.\n");

    tx_buf_free(&dist_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Security Model Tests --- */

/* Test: Partial departure blocks cooperative close.
   Record key turnover for only 2 of 4 clients; verify ladder_can_close returns 0.
   Then record remaining 2; verify it returns 1.
   Proves: offline clients prevent rotation from completing. */
int test_ladder_partial_departure_blocks_close(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    secp256k1_pubkey client_pks[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;
    for (int i = 0; i < 4; i++) {
        if (!secp256k1_keypair_pub(ctx, &client_pks[i], &client_kps[i])) return 0;
    }

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    /* Build keypair arrays for PTLC */
    secp256k1_pubkey all_pks[5];
    secp256k1_keypair all_kps[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        all_pks[i + 1] = client_pks[i];
    }

    /* Record turnover for clients 1 and 2 only (clients 3 and 4 are "offline") */
    for (int c = 0; c < 2; c++) {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, all_pks, 5);

        unsigned char presig[64];
        int nonce_parity;
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fake_txid, all_kps, 5, &ka, NULL, &all_pks[c + 1]),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_secs[c],
                                    nonce_parity),
                    "adapt");

        unsigned char extracted[32];
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig,
                                            nonce_parity),
                    "extract");

        TEST_ASSERT(ladder_record_key_turnover(&lad, 0, (uint32_t)(c + 1),
                                                extracted),
                    "record turnover");
    }

    /* 2 of 4 departed — cannot close */
    TEST_ASSERT(!ladder_can_close(&lad, 0), "2/4 departed: cannot close");

    /* ladder_build_close should also fail with missing clients */
    tx_output_t output;
    output.amount_sats = 99500;
    build_p2tr_script_pubkey(output.script_pubkey, &fund_tweaked);
    output.script_pubkey_len = 34;
    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(!ladder_build_close(&lad, 0, &close_tx, &output, 1),
                "build_close fails with partial departure");
    tx_buf_free(&close_tx);

    /* Record turnover for remaining clients 3 and 4 */
    for (int c = 2; c < 4; c++) {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, all_pks, 5);

        unsigned char presig[64];
        int nonce_parity;
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fake_txid, all_kps, 5, &ka, NULL, &all_pks[c + 1]),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_secs[c],
                                    nonce_parity),
                    "adapt");

        unsigned char extracted[32];
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig,
                                            nonce_parity),
                    "extract");

        TEST_ASSERT(ladder_record_key_turnover(&lad, 0, (uint32_t)(c + 1),
                                                extracted),
                    "record turnover");
    }

    /* All 4 departed — can close */
    TEST_ASSERT(ladder_can_close(&lad, 0), "4/4 departed: can close");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: Factory tree currently requires exactly 5 participants (LSP + 4 clients).
   Rotation MUST include all 4 clients — fewer participants fails gracefully.
   Proves: the current security model requires full participation for rotation,
   and the code handles the constraint without crashing. */
int test_ladder_restructure_fewer_clients(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    /* Create original factory with 4 clients (5 participants total) — works */
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create original factory");
    TEST_ASSERT_EQ(lad.factories[0].factory.n_participants, 5,
                   "original has 5 participants");

    /* Advance to DYING */
    ladder_advance_block(&lad, 100);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "factory dying");

    /* With generalized N, factories can be created with 2+ clients (arity-2).
       Only LSP+1 (2 participants) should fail for arity-2 (needs >=2 clients). */
    unsigned char fake_txid2[32];
    memset(fake_txid2, 0xBB, 32);

    /* Attempt with 1 client (2 participants) — fails (arity-2 needs >= 2 clients) */
    int result_1 = ladder_create_factory(&lad, client_kps, 1, 100000,
                                          fake_txid2, 0, fund_spk, 34);
    TEST_ASSERT(!result_1, "2 participants (LSP+1) fails gracefully");
    TEST_ASSERT_EQ(lad.n_factories, 1, "factory count unchanged after failure");

    /* Attempt with 2 clients (3 participants) — succeeds with generalized N */
    secp256k1_keypair online_kps[2];
    online_kps[0] = client_kps[0];
    online_kps[1] = client_kps[1];

    int result_2 = ladder_create_factory(&lad, online_kps, 2, 100000,
                                          fake_txid2, 0, fund_spk, 34);
    TEST_ASSERT(result_2, "3 participants (LSP+2) succeeds");
    TEST_ASSERT_EQ(lad.n_factories, 2, "2 factories after LSP+2");

    /* Create another with full 4 clients */
    unsigned char fake_txid3[32];
    memset(fake_txid3, 0xCC, 32);
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid3, 0, fund_spk, 34),
                "full 4 clients (5 participants) works");
    TEST_ASSERT_EQ(lad.n_factories, 3, "3 factories total");
    TEST_ASSERT_EQ(lad.factories[2].cached_state, FACTORY_ACTIVE,
                   "new factory is ACTIVE");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: DW cross-layer delay ordering.
   DW formula: delay = step * (max_states - 1 - state_index).
   State 0 = oldest (max delay), state max-1 = newest (delay 0).

   The security invariant: when the counter advances, the innermost layer
   ticks fastest (like an odometer). A newer global state always has a
   LOWER total delay sum across layers than an older state. This ensures
   the newest state's transactions confirm first, invalidating older states. */
int test_dw_cross_layer_delay_ordering(void) {
    /* Test with a 3-layer counter (step=1, states_per_layer=4) */
    dw_counter_t ctr;
    dw_counter_init(&ctr, 3, 1, 4);

    TEST_ASSERT_EQ(ctr.n_layers, 3, "3 layers");
    TEST_ASSERT_EQ(ctr.total_states, 64, "4^3 = 64 total states");

    /* At epoch 0 (oldest state), all layers are at state 0.
       delay = step * (max_states - 1 - 0) = 1 * 3 = 3 per layer.
       Total path delay = 3 * 3 = 9. This is the MAXIMUM total delay. */
    for (uint32_t i = 0; i < ctr.n_layers; i++) {
        uint16_t delay = dw_delay_for_state(&ctr.layers[i].config,
                                             ctr.layers[i].current_state);
        TEST_ASSERT_EQ(delay, 3, "initial delay = (4-1-0)*1 = 3");
    }
    uint16_t total_delay_epoch0 = 3 * 3;

    /* Advance to newest state (epoch 63 = total_states - 1).
       All layers at state 3 (max-1), delay = (4-1-3)*1 = 0 per layer.
       Total = 0. This is the MINIMUM total delay. */
    for (uint32_t i = 0; i < ctr.total_states - 1; i++)
        dw_counter_advance(&ctr);

    for (uint32_t i = 0; i < ctr.n_layers; i++) {
        uint16_t delay = dw_delay_for_state(&ctr.layers[i].config,
                                             ctr.layers[i].current_state);
        TEST_ASSERT_EQ(delay, 0, "newest delay = 0");
        TEST_ASSERT_EQ(ctr.layers[i].current_state, 3, "all layers at max state");
    }

    /* Core security invariant: WITHIN each layer, a higher state index
       always has a strictly lower delay. Newer states outpace older ones.
       This is what makes DW invalidation work — the newest state confirms
       at each layer before any older state can. */
    for (uint32_t states = 4, s = 0; s < states - 1; s++) {
        dw_layer_config_t cfg = { .step_blocks = 1, .max_states = states };
        uint16_t d_older = dw_delay_for_state(&cfg, s);
        uint16_t d_newer = dw_delay_for_state(&cfg, s + 1);
        TEST_ASSERT(d_newer < d_older,
                    "newer state has strictly lower delay within layer");
    }

    /* Also verify with larger step_blocks */
    for (uint32_t s = 0; s < 3; s++) {
        dw_layer_config_t cfg = { .step_blocks = 144, .max_states = 4 };
        uint16_t d_older = dw_delay_for_state(&cfg, s);
        uint16_t d_newer = dw_delay_for_state(&cfg, s + 1);
        TEST_ASSERT(d_newer < d_older,
                    "step=144: newer state still lower delay");
    }

    /* Verify odometer behavior: layer n_layers-1 is innermost (fastest).
       After 1 advance from reset, layer 2 goes to state 1, others stay at 0. */
    dw_counter_reset(&ctr);
    dw_counter_advance(&ctr);

    TEST_ASSERT_EQ(ctr.layers[0].current_state, 0, "layer 0 (outermost) at 0");
    TEST_ASSERT_EQ(ctr.layers[1].current_state, 0, "layer 1 still at 0");
    TEST_ASSERT_EQ(ctr.layers[2].current_state, 1, "layer 2 (innermost) advanced");

    uint16_t delay_inner = dw_delay_for_state(&ctr.layers[2].config,
                                               ctr.layers[2].current_state);
    uint16_t delay_outer = dw_delay_for_state(&ctr.layers[0].config,
                                               ctr.layers[0].current_state);

    /* Layer 2 at state 1: delay = (4-1-1)*1 = 2
       Layer 0 at state 0: delay = (4-1-0)*1 = 3
       The faster-ticking inner layer has LOWER delay (newer state) */
    TEST_ASSERT_EQ(delay_inner, 2, "inner layer delay after advance");
    TEST_ASSERT_EQ(delay_outer, 3, "outer layer delay (unchanged)");
    TEST_ASSERT(delay_inner < delay_outer,
                "inner layer delay < outer layer delay");

    /* Advance 3 more times (total 4): layer 2 rolls over to state 0,
       layer 1 advances to state 1 */
    for (int i = 0; i < 3; i++)
        dw_counter_advance(&ctr);

    TEST_ASSERT_EQ(ctr.layers[2].current_state, 0, "layer 2 rolled over");
    TEST_ASSERT_EQ(ctr.layers[1].current_state, 1, "layer 1 advanced on rollover");
    TEST_ASSERT_EQ(ctr.layers[0].current_state, 0, "layer 0 still at 0");

    /* After rollover, both layer 0 and 1 have been used,
       total delay is less than epoch 0 */
    uint16_t total_after_rollover = 0;
    for (uint32_t i = 0; i < ctr.n_layers; i++) {
        total_after_rollover += dw_delay_for_state(&ctr.layers[i].config,
                                                    ctr.layers[i].current_state);
    }
    TEST_ASSERT(total_after_rollover < total_delay_epoch0,
                "total delay after 4 advances < initial");

    return 1;
}

/* Test: Full rotation cycle as a pure unit test.
   Create factory → advance to dying → PTLC turnover all 4 clients →
   build cooperative close → create new factory in ladder →
   evict expired → verify clean state. */
int test_ladder_full_rotation_cycle(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    secp256k1_pubkey client_pks[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;
    for (int i = 0; i < 4; i++) {
        if (!secp256k1_keypair_pub(ctx, &client_pks[i], &client_kps[i])) return 0;
    }

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid1[32];
    memset(fake_txid1, 0xAA, 32);

    /* Phase 1: Create first factory at block 0 */
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid1, 0, fund_spk, 34),
                "create factory 1");
    TEST_ASSERT_EQ(lad.n_factories, 1, "1 factory");
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_ACTIVE, "f1 active");

    /* Phase 2: Advance to DYING */
    ladder_advance_block(&lad, 100);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "f1 dying");
    TEST_ASSERT(ladder_get_dying(&lad) != NULL, "dying factory found");
    TEST_ASSERT(ladder_get_active(&lad) == NULL, "no active factory");

    /* Phase 3: PTLC key turnover for all 4 clients */
    secp256k1_pubkey all_pks[5];
    secp256k1_keypair all_kps[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        all_pks[i + 1] = client_pks[i];
    }

    for (int c = 0; c < 4; c++) {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, all_pks, 5);

        unsigned char presig[64];
        int nonce_parity;
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fake_txid1, all_kps, 5, &ka, NULL, &all_pks[c + 1]),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_secs[c],
                                    nonce_parity),
                    "adapt");

        unsigned char extracted[32];
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig,
                                            nonce_parity),
                    "extract");

        TEST_ASSERT(ladder_record_key_turnover(&lad, 0, (uint32_t)(c + 1),
                                                extracted),
                    "record turnover");
    }
    TEST_ASSERT(ladder_can_close(&lad, 0), "can close factory 1");

    /* Phase 4: Build cooperative close */
    tx_output_t close_output;
    close_output.amount_sats = 99500;
    build_p2tr_script_pubkey(close_output.script_pubkey, &fund_tweaked);
    close_output.script_pubkey_len = 34;

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(ladder_build_close(&lad, 0, &close_tx, &close_output, 1),
                "build close tx");
    TEST_ASSERT(close_tx.len > 0, "close tx non-empty");

    /* Phase 5: Create new factory (simulates funding with reclaimed UTXO) */
    unsigned char fake_txid2[32];
    memset(fake_txid2, 0xBB, 32);

    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid2, 0, fund_spk, 34),
                "create factory 2");
    TEST_ASSERT_EQ(lad.n_factories, 2, "2 factories");

    /* Factory 1 is still DYING, factory 2 is ACTIVE */
    ladder_advance_block(&lad, 100);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_DYING, "f1 still dying");
    TEST_ASSERT_EQ(lad.factories[1].cached_state, FACTORY_ACTIVE, "f2 active");

    /* Phase 6: Advance past factory 1 expiry, evict */
    ladder_advance_block(&lad, 130);
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_EXPIRED, "f1 expired");

    size_t freed = ladder_evict_expired(&lad);
    TEST_ASSERT_EQ(freed, 1, "evicted 1 factory");
    TEST_ASSERT_EQ(lad.n_factories, 1, "1 factory remaining");
    TEST_ASSERT_EQ(lad.factories[0].factory_id, 1, "remaining is factory 2");
    TEST_ASSERT_EQ(lad.factories[0].cached_state, FACTORY_ACTIVE, "f2 still active");

    /* Verify the active factory is functional */
    TEST_ASSERT(ladder_get_active(&lad) != NULL, "active factory accessible");
    TEST_ASSERT(ladder_get_dying(&lad) == NULL, "no dying factory");

    tx_buf_free(&close_tx);
    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: Fill ladder to capacity, evict, and reuse slots.
   Proves: the ladder array compaction and slot reuse works
   correctly under the LADDER_MAX_FACTORIES limit. */
int test_ladder_evict_and_reuse_slot(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 10, 5);  /* short lifecycle for testing */

    /* Fill all LADDER_MAX_FACTORIES (8) slots */
    for (int i = 0; i < LADDER_MAX_FACTORIES; i++) {
        unsigned char fake_txid[32];
        memset(fake_txid, (unsigned char)(0xA0 + i), 32);
        ladder_advance_block(&lad, (uint32_t)(i * 10));
        TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                           fake_txid, 0, fund_spk, 34),
                    "create factory to fill slots");
    }
    TEST_ASSERT_EQ(lad.n_factories, LADDER_MAX_FACTORIES, "ladder full");

    /* One more should fail */
    unsigned char overflow_txid[32];
    memset(overflow_txid, 0xFF, 32);
    TEST_ASSERT(!ladder_create_factory(&lad, client_kps, 4, 100000,
                                        overflow_txid, 0, fund_spk, 34),
                "overflow rejected");

    /* Advance past the first 6 factories' expiry (each at block i*10 + 10 + 5) */
    ladder_advance_block(&lad, 65);

    /* Count expired */
    int expired_count = 0;
    for (size_t i = 0; i < lad.n_factories; i++) {
        if (lad.factories[i].cached_state == FACTORY_EXPIRED)
            expired_count++;
    }
    TEST_ASSERT(expired_count >= 4, "at least 4 expired");

    /* Evict expired */
    size_t freed = ladder_evict_expired(&lad);
    TEST_ASSERT(freed >= 4, "freed expired slots");
    TEST_ASSERT(lad.n_factories <= 4, "compacted");

    /* Now create a new factory in the freed slot */
    unsigned char new_txid[32];
    memset(new_txid, 0xEE, 32);
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       new_txid, 0, fund_spk, 34),
                "create factory in freed slot");

    /* Verify the new factory is ACTIVE and has correct ID */
    ladder_factory_t *newest = &lad.factories[lad.n_factories - 1];
    TEST_ASSERT(newest->is_initialized, "new factory initialized");
    TEST_ASSERT_EQ(newest->cached_state, FACTORY_ACTIVE, "new factory active");
    TEST_ASSERT(newest->factory_id >= LADDER_MAX_FACTORIES,
                "new factory has fresh ID (not reused)");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Gap 6 (regtest): Funding UTXO double-spend rejected by consensus.
   Proves: if someone spends the factory's funding UTXO away (cooperative close),
   the kickoff transaction (which also spends that UTXO) is rejected by Bitcoin Core.
   This is the last line of defense — even though no production code checks UTXO
   liveness, Bitcoin consensus itself prevents double-spends. */
int test_regtest_funding_double_spend_rejected(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_dbl_spend");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Create keypairs */
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, &lsp_kp, client_kps,
                                      fund_spk, &fund_tweaked),
                "compute funding spk");

    /* Derive bech32m address and fund */
    char factory_addr[128];
    TEST_ASSERT(derive_factory_address(&rt, ctx, &fund_tweaked,
                                         factory_addr, sizeof(factory_addr)),
                "derive address");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Find the funding vout */
    uint64_t fund_amount = 0;
    int found_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding_txid_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                found_vout = v;
                fund_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find vout");
    printf("  Funded: %s vout=%d amount=%lu sats\n",
           funding_txid_hex, found_vout, (unsigned long)fund_amount);

    /* Build the 5-of-5 keypair array */
    secp256k1_keypair all_kps[5];
    secp256k1_pubkey all_pks[5];
    all_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(ctx, &all_pks[0], &lsp_kp)) return 0;
    for (int i = 0; i < 4; i++) {
        all_kps[i + 1] = client_kps[i];
        if (!secp256k1_keypair_pub(ctx, &all_pks[i + 1], &client_kps[i])) return 0;
    }

    /* Init factory, build tree, sign all (creates kickoff tx) */
    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 1, 4);
    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");
    printf("  Factory tree built: %zu nodes\n", f.n_nodes);

    /* Save kickoff tx hex before spending the UTXO away */
    char *kickoff_hex = (char *)malloc(f.nodes[0].signed_tx.len * 2 + 1);
    hex_encode(f.nodes[0].signed_tx.data, f.nodes[0].signed_tx.len, kickoff_hex);

    /* Step 1: Spend the funding UTXO via cooperative close (double-spend) */
    uint64_t close_fee = 500;
    tx_output_t close_output;
    close_output.amount_sats = fund_amount - close_fee;

    secp256k1_xonly_pubkey lsp_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &all_pks[0])) {
        free(kickoff_hex); return 0;
    }
    unsigned char lsp_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, lsp_ser, &lsp_xonly)) {
        free(kickoff_hex); return 0;
    }
    unsigned char lsp_tweak[32];
    sha256_tagged("TapTweak", lsp_ser, 32, lsp_tweak);
    secp256k1_pubkey lsp_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &lsp_tweaked_full, &lsp_xonly, lsp_tweak)) {
        free(kickoff_hex); return 0;
    }
    secp256k1_xonly_pubkey lsp_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_tweaked, NULL, &lsp_tweaked_full)) {
        free(kickoff_hex); return 0;
    }
    build_p2tr_script_pubkey(close_output.script_pubkey, &lsp_tweaked);
    close_output.script_pubkey_len = 34;

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, NULL,
                                                  &close_output, 1),
                "build cooperative close");

    char *close_hex = (char *)malloc(close_tx.len * 2 + 1);
    hex_encode(close_tx.data, close_tx.len, close_hex);
    char close_txid_hex[65];
    int close_sent = regtest_send_raw_tx(&rt, close_hex, close_txid_hex);
    free(close_hex);
    TEST_ASSERT(close_sent, "broadcast cooperative close (spends funding UTXO)");
    printf("  Cooperative close broadcast: %s\n", close_txid_hex);

    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, close_txid_hex) > 0,
                "cooperative close confirmed");
    printf("  Funding UTXO now spent by cooperative close\n");

    /* Step 2: Try to broadcast kickoff (same UTXO) — must fail */
    char kickoff_txid_hex[65];
    int kickoff_sent = regtest_send_raw_tx(&rt, kickoff_hex, kickoff_txid_hex);
    free(kickoff_hex);
    TEST_ASSERT(!kickoff_sent,
                "kickoff rejected: funding UTXO already spent (double-spend blocked)");
    printf("  Kickoff correctly rejected — Bitcoin consensus prevents double-spend\n");

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* === Partial Rotation Tests === */

/* test_ladder_get_cooperative_clients — depart 2 of 4, verify list */
int test_ladder_get_cooperative_clients(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;
    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    /* Depart clients 1 and 3 (indices 1,3 in 1-based participant idx) */
    unsigned char fake_key[32];
    memset(fake_key, 0x11, 32);
    ladder_record_key_turnover(&lad, 0, 1, fake_key);
    memset(fake_key, 0x33, 32);
    ladder_record_key_turnover(&lad, 0, 3, fake_key);

    uint32_t coop[8];
    size_t n = ladder_get_cooperative_clients(&lad, 0, coop, 8);
    TEST_ASSERT_EQ(n, 2, "2 cooperative");
    /* Should be clients 1 and 3 */
    int found1 = 0, found3 = 0;
    for (size_t i = 0; i < n; i++) {
        if (coop[i] == 1) found1 = 1;
        if (coop[i] == 3) found3 = 1;
    }
    TEST_ASSERT(found1, "found client 1");
    TEST_ASSERT(found3, "found client 3");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* test_ladder_get_uncooperative_clients — same setup, verify complement */
int test_ladder_get_uncooperative_clients(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;
    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    /* Depart clients 1 and 3 */
    unsigned char fake_key[32];
    memset(fake_key, 0x11, 32);
    ladder_record_key_turnover(&lad, 0, 1, fake_key);
    memset(fake_key, 0x33, 32);
    ladder_record_key_turnover(&lad, 0, 3, fake_key);

    uint32_t uncoop[8];
    size_t n = ladder_get_uncooperative_clients(&lad, 0, uncoop, 8);
    TEST_ASSERT_EQ(n, 2, "2 uncooperative");
    /* Should be clients 2 and 4 */
    int found2 = 0, found4 = 0;
    for (size_t i = 0; i < n; i++) {
        if (uncoop[i] == 2) found2 = 1;
        if (uncoop[i] == 4) found4 = 1;
    }
    TEST_ASSERT(found2, "found client 2");
    TEST_ASSERT(found4, "found client 4");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* test_ladder_can_partial_close_thresholds — 0/4=no, 1/4=no, 2/4=yes, 4/4=yes */
int test_ladder_can_partial_close_thresholds(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;
    secp256k1_keypair client_kps[4];
    if (!make_client_keypairs(ctx, client_kps)) return 0;

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    compute_funding_spk(ctx, &lsp_kp, client_kps, fund_spk, &fund_tweaked);

    ladder_t lad;
    ladder_init(&lad, ctx, &lsp_kp, 100, 30);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);
    TEST_ASSERT(ladder_create_factory(&lad, client_kps, 4, 100000,
                                       fake_txid, 0, fund_spk, 34),
                "create factory");

    unsigned char fake_key[32];
    memset(fake_key, 0xFF, 32);

    /* 0 departed: no */
    TEST_ASSERT(!ladder_can_partial_close(&lad, 0), "0/4: no partial close");

    /* 1 departed: no */
    ladder_record_key_turnover(&lad, 0, 1, fake_key);
    TEST_ASSERT(!ladder_can_partial_close(&lad, 0), "1/4: no partial close");

    /* 2 departed: yes */
    ladder_record_key_turnover(&lad, 0, 2, fake_key);
    TEST_ASSERT(ladder_can_partial_close(&lad, 0), "2/4: partial close OK");

    /* 3 departed: yes */
    ladder_record_key_turnover(&lad, 0, 3, fake_key);
    TEST_ASSERT(ladder_can_partial_close(&lad, 0), "3/4: partial close OK");

    /* 4 departed (all): yes (but full close would also work) */
    ladder_record_key_turnover(&lad, 0, 4, fake_key);
    TEST_ASSERT(ladder_can_partial_close(&lad, 0), "4/4: partial close OK");
    TEST_ASSERT(ladder_can_close(&lad, 0), "4/4: full close also OK");

    ladder_free(&lad);
    secp256k1_context_destroy(ctx);
    return 1;
}
