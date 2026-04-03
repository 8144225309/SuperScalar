/*
 * test_reorg.c — Reorg resistance tests
 *
 * Exercises reorg detection and recovery across BIP 158 backend,
 * watchtower, HTLC timeout, and JIT channel components using
 * mock chain backends with controllable state.
 */

#include "superscalar/channel.h"
#include "superscalar/chain_backend.h"
#include "superscalar/bip158_backend.h"
#include "superscalar/watchtower.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); return 0; } \
} while(0)

/* ---- BIP 158 tx_cache invalidation ---- */

int test_reorg_bip158_tx_cache_invalidation(void) {
    bip158_backend_t b;
    memset(&b, 0, sizeof(b));
    b.tip_height = 110;
    b.headers_synced = 110;
    b.filter_headers_synced = 110;

    /* Populate tx_cache with entries at heights 100-110 */
    for (int h = 100; h <= 110; h++) {
        size_t slot = b.n_tx_cache++;
        memset(b.tx_cache[slot].txid, (unsigned char)h, 32);
        b.tx_cache[slot].height = h;
    }
    TEST_ASSERT(b.n_tx_cache == 11, "11 cache entries");

    /* Simulate reorg to height 105 */
    int rolled = bip158_handle_reorg(&b, 105);
    TEST_ASSERT(rolled == 5, "5 blocks rolled back");
    TEST_ASSERT(b.tip_height == 105, "tip rolled to 105");
    TEST_ASSERT(b.headers_synced == 105, "headers rolled to 105");
    TEST_ASSERT(b.filter_headers_synced == 105, "filter headers rolled to 105");

    /* Entries at 100-105 should be preserved, 106-110 invalidated */
    int valid = 0, invalid = 0;
    for (size_t i = 0; i < b.n_tx_cache; i++) {
        if (b.tx_cache[i].height >= 0 && b.tx_cache[i].height <= 105)
            valid++;
        else if (b.tx_cache[i].height == -1)
            invalid++;
    }
    TEST_ASSERT(valid == 6, "6 valid entries (100-105)");
    TEST_ASSERT(invalid == 5, "5 invalidated entries (106-110)");

    return 1;
}

/* ---- BIP 158 block_disconnected callback ---- */

static int g_disconnected_count = 0;
static uint32_t g_last_disconnected_height = 0;

static void test_disconnected_cb(uint32_t height, void *ctx) {
    (void)ctx;
    g_disconnected_count++;
    g_last_disconnected_height = height;
}

int test_reorg_bip158_callback_fires(void) {
    bip158_backend_t b;
    memset(&b, 0, sizeof(b));
    b.tip_height = 110;
    b.headers_synced = 110;
    b.filter_headers_synced = 110;
    b.block_disconnected_cb = test_disconnected_cb;
    b.block_disconnected_ctx = NULL;

    g_disconnected_count = 0;
    g_last_disconnected_height = 0;

    bip158_handle_reorg(&b, 105);

    TEST_ASSERT(g_disconnected_count == 5, "callback fired 5 times");
    /* Callback fires in descending order: 110, 109, 108, 107, 106 */
    TEST_ASSERT(g_last_disconnected_height == 106, "last disconnected height is 106");

    return 1;
}

/* ---- HTLC timeout monotonicity guard ---- */

int test_reorg_htlc_timeout_no_premature_fail(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a channel with an HTLC expiring at height 110 */
    unsigned char sec[32] = {[0 ... 31] = 0x42};
    secp256k1_keypair kp;
    secp256k1_keypair_create(ctx, &kp, sec);
    secp256k1_pubkey pk;
    secp256k1_keypair_pub(ctx, &pk, &kp);

    unsigned char fake_txid[32] = {0};
    unsigned char fake_spk[34] = {0x51, 0x20};

    channel_t ch;
    channel_init(&ch, ctx, sec, &pk, &pk,
                 fake_txid, 0, 100000, fake_spk, 34,
                 50000, 50000, 144);

    /* Add an HTLC expiring at height 110 */
    unsigned char phash[32] = {[0 ... 31] = 0xAA};
    uint64_t htlc_id;
    channel_add_htlc(&ch, HTLC_OFFERED, 1000, phash, 110, &htlc_id);

    /* Check at height 108 — HTLC should NOT be timed out */
    int failed = channel_check_htlc_timeouts(&ch, 108);
    TEST_ASSERT(failed == 0, "no timeout at 108");

    /* Check at height 110 — HTLC SHOULD be timed out */
    failed = channel_check_htlc_timeouts(&ch, 110);
    TEST_ASSERT(failed == 1, "timeout at 110");

    /* Add another HTLC expiring at 115 */
    unsigned char phash2[32] = {[0 ... 31] = 0xBB};
    channel_add_htlc(&ch, HTLC_OFFERED, 2000, phash2, 115, &htlc_id);

    /* Simulate reorg: height goes backward to 107 */
    failed = channel_check_htlc_timeouts(&ch, 107);
    TEST_ASSERT(failed == 0, "no timeout during reorg (height went backward)");

    /* Height recovers past 115 */
    failed = channel_check_htlc_timeouts(&ch, 116);
    TEST_ASSERT(failed == 1, "timeout at 116 after recovery");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- No-op reorg on BIP 158 (already at fork point) ---- */

int test_reorg_bip158_noop(void) {
    bip158_backend_t b;
    memset(&b, 0, sizeof(b));
    b.tip_height = 100;

    int rolled = bip158_handle_reorg(&b, 100);
    TEST_ASSERT(rolled == 0, "no rollback when at fork point");
    TEST_ASSERT(b.tip_height == 100, "tip unchanged");

    rolled = bip158_handle_reorg(&b, 200);
    TEST_ASSERT(rolled == 0, "no rollback when fork above tip");

    return 1;
}
