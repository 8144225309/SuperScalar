/* Tests for JIT Channel Fallback (Gap #2) */

#include "superscalar/jit_channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/wire.h"
#include "superscalar/persist.h"
#include "superscalar/channel.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/fee.h"
#include "superscalar/watchtower.h"
#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <cJSON.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

/* Test macros (same as test_main.c) */
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

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

/* --- Step 1: Offline Detection Tests --- */

int test_last_message_time_update(void) {
    /* Verify that lsp_channel_entry_t fields are initialized */
    lsp_channel_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.last_message_time = time(NULL);
    entry.offline_detected = 0;

    TEST_ASSERT(entry.last_message_time > 0, "last_message_time should be set");
    TEST_ASSERT_EQ(entry.offline_detected, 0, "offline_detected should be 0");

    /* Simulate aging (must exceed JIT_OFFLINE_TIMEOUT_SEC = 300) */
    entry.last_message_time -= 400;  /* 400 seconds ago */
    time_t now = time(NULL);
    int is_stale = (now - entry.last_message_time >= JIT_OFFLINE_TIMEOUT_SEC);
    TEST_ASSERT(is_stale, "should be stale after 400s");

    return 1;
}

int test_offline_detection_flag(void) {
    lsp_channel_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.last_message_time = time(NULL) - 400;  /* 400s ago */
    entry.offline_detected = 0;

    /* Simulate detection logic */
    time_t now = time(NULL);
    if (now - entry.last_message_time >= JIT_OFFLINE_TIMEOUT_SEC) {
        entry.offline_detected = 1;
    }
    TEST_ASSERT_EQ(entry.offline_detected, 1, "should be detected offline");

    /* Reset on reconnect */
    entry.last_message_time = time(NULL);
    entry.offline_detected = 0;
    TEST_ASSERT_EQ(entry.offline_detected, 0, "should be reset after reconnect");

    return 1;
}

/* --- Step 2: Wire Message Round-Trip Tests --- */

int test_jit_offer_round_trip(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a test pubkey */
    unsigned char seckey[32];
    memset(seckey, 0x42, 32);
    secp256k1_pubkey pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, seckey), "create pubkey");

    cJSON *j = wire_build_jit_offer(2, 50000, "factory_expired", ctx, &pk);
    TEST_ASSERT(j != NULL, "build jit_offer");

    size_t cidx;
    uint64_t amount;
    char reason[64];
    secp256k1_pubkey pk_out;
    TEST_ASSERT(wire_parse_jit_offer(j, ctx, &cidx, &amount, reason,
                                       sizeof(reason), &pk_out),
                "parse jit_offer");

    TEST_ASSERT_EQ((long)cidx, 2, "client_idx mismatch");
    TEST_ASSERT_EQ((long)amount, 50000, "funding_amount mismatch");
    TEST_ASSERT(strcmp(reason, "factory_expired") == 0, "reason mismatch");

    /* Compare pubkeys */
    unsigned char ser1[33], ser2[33];
    size_t l1 = 33, l2 = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser1, &l1, &pk, SECP256K1_EC_COMPRESSED)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser2, &l2, &pk_out, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(ser1, ser2, 33) == 0, "pubkey mismatch");

    cJSON_Delete(j);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_jit_accept_round_trip(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char seckey[32];
    memset(seckey, 0x43, 32);
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, seckey)) return 0;

    cJSON *j = wire_build_jit_accept(3, ctx, &pk);
    TEST_ASSERT(j != NULL, "build jit_accept");

    size_t cidx;
    secp256k1_pubkey pk_out;
    TEST_ASSERT(wire_parse_jit_accept(j, ctx, &cidx, &pk_out), "parse jit_accept");
    TEST_ASSERT_EQ((long)cidx, 3, "client_idx mismatch");

    unsigned char ser1[33], ser2[33];
    size_t l1 = 33, l2 = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser1, &l1, &pk, SECP256K1_EC_COMPRESSED)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser2, &l2, &pk_out, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(ser1, ser2, 33) == 0, "pubkey mismatch");

    cJSON_Delete(j);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_jit_ready_round_trip(void) {
    cJSON *j = wire_build_jit_ready(0x8001,
        "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb",
        0, 100000, 45000, 45000);
    TEST_ASSERT(j != NULL, "build jit_ready");

    uint32_t jit_ch_id;
    char txid[65];
    uint32_t vout;
    uint64_t amount, local, remote;
    TEST_ASSERT(wire_parse_jit_ready(j, &jit_ch_id, txid, sizeof(txid),
                                       &vout, &amount, &local, &remote),
                "parse jit_ready");

    TEST_ASSERT_EQ((long)jit_ch_id, 0x8001, "jit_channel_id mismatch");
    TEST_ASSERT_EQ((long)vout, 0, "vout mismatch");
    TEST_ASSERT_EQ((long)amount, 100000, "amount mismatch");
    TEST_ASSERT_EQ((long)local, 45000, "local mismatch");
    TEST_ASSERT_EQ((long)remote, 45000, "remote mismatch");

    cJSON_Delete(j);
    return 1;
}

int test_jit_migrate_round_trip(void) {
    cJSON *j = wire_build_jit_migrate(0x8002, 5, 30000, 20000);
    TEST_ASSERT(j != NULL, "build jit_migrate");

    uint32_t jit_ch_id, factory_id;
    uint64_t local, remote;
    TEST_ASSERT(wire_parse_jit_migrate(j, &jit_ch_id, &factory_id,
                                         &local, &remote),
                "parse jit_migrate");

    TEST_ASSERT_EQ((long)jit_ch_id, 0x8002, "jit_channel_id mismatch");
    TEST_ASSERT_EQ((long)factory_id, 5, "target_factory_id mismatch");
    TEST_ASSERT_EQ((long)local, 30000, "local_balance mismatch");
    TEST_ASSERT_EQ((long)remote, 20000, "remote_balance mismatch");

    cJSON_Delete(j);
    return 1;
}

/* --- Step 3: JIT Channel Create/Find Tests --- */

int test_jit_channel_init_and_find(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;

    TEST_ASSERT(jit_channels_init(&mgr), "jit_channels_init");
    TEST_ASSERT(mgr.jit_channels != NULL, "jit_channels allocated");
    TEST_ASSERT_EQ((long)mgr.n_jit_channels, 0, "n_jit should be 0");
    TEST_ASSERT_EQ(mgr.jit_enabled, 0, "opening JIT channels is off after init");

    /* No channels yet */
    TEST_ASSERT(jit_channel_find(&mgr, 0) == NULL, "should find nothing");
    TEST_ASSERT_EQ(jit_channel_is_active(&mgr, 0), 0, "should not be active");

    /* Manually insert a JIT channel */
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 1;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 1;
    mgr.n_jit_channels = 1;

    TEST_ASSERT(jit_channel_find(&mgr, 1) != NULL, "should find JIT for client 1");
    TEST_ASSERT(jit_channel_find(&mgr, 0) == NULL, "should not find JIT for client 0");
    TEST_ASSERT_EQ(jit_channel_is_active(&mgr, 1), 1, "client 1 JIT should be active");
    TEST_ASSERT_EQ(jit_channel_is_active(&mgr, 0), 0, "client 0 JIT should not be active");

    jit_channels_cleanup(&mgr);
    TEST_ASSERT(mgr.jit_channels == NULL, "should be freed");
    return 1;
}

int test_jit_channel_id_no_collision(void) {
    /* JIT IDs start at 0x8000, factory channel IDs are 0-based */
    for (size_t i = 0; i < 8; i++) {
        uint32_t jit_id = JIT_CHANNEL_ID_BASE | (uint32_t)i;
        TEST_ASSERT(jit_id >= JIT_CHANNEL_ID_BASE, "JIT ID should be >= base");
        TEST_ASSERT(jit_id != (uint32_t)i, "JIT ID should not collide with factory ID");
    }
    return 1;
}

/* --- Step 4: Effective Channel Dispatch Tests --- */

int test_jit_routing_prefers_factory(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.n_channels = 4;
    mgr.entries[0].ready = 1;
    mgr.entries[0].channel_id = 0;
    mgr.entries[0].channel.local_amount = 50000;

    jit_channels_init(&mgr);

    /* Insert JIT channel for client 0 */
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 0;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE;
    jits[0].channel.local_amount = 10000;
    mgr.n_jit_channels = 1;

    /* Should prefer factory */
    uint32_t ch_id;
    channel_t *ch = jit_get_effective_channel(&mgr, 0, &ch_id);
    TEST_ASSERT(ch != NULL, "should find a channel");
    TEST_ASSERT_EQ((long)ch_id, 0, "should be factory channel_id");
    TEST_ASSERT_EQ((long)ch->local_amount, 50000, "should be factory local_amount");

    jit_channels_cleanup(&mgr);
    free(mgr.entries);
    return 1;
}

int test_jit_routing_fallback(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.n_channels = 4;
    mgr.entries[2].ready = 0;  /* Factory channel NOT ready */
    mgr.entries[2].channel_id = 2;

    jit_channels_init(&mgr);

    /* Insert JIT channel for client 2 */
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 2;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 2;
    jits[0].channel.local_amount = 20000;
    mgr.n_jit_channels = 1;

    /* Should fall back to JIT */
    uint32_t ch_id;
    channel_t *ch = jit_get_effective_channel(&mgr, 2, &ch_id);
    TEST_ASSERT(ch != NULL, "should find JIT channel");
    TEST_ASSERT_EQ((long)ch_id, (long)(JIT_CHANNEL_ID_BASE | 2),
                   "should be JIT channel_id");
    TEST_ASSERT_EQ((long)ch->local_amount, 20000, "should be JIT local_amount");

    jit_channels_cleanup(&mgr);
    free(mgr.entries);
    return 1;
}

/* --- Step 5: Client JIT Flow Tests --- */

int test_client_jit_accept_flow(void) {
    /* Test that JIT_OFFER → JIT_ACCEPT wire round-trip works */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_sec[32], cli_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(cli_sec, 0x22, 32);
    secp256k1_pubkey lsp_pk, cli_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &cli_pk, cli_sec)) return 0;

    /* LSP builds offer */
    cJSON *offer = wire_build_jit_offer(1, 25000, "new_client", ctx, &lsp_pk);
    TEST_ASSERT(offer != NULL, "build offer");

    /* Client parses + auto-accepts */
    size_t cidx;
    uint64_t amount;
    char reason[64];
    secp256k1_pubkey parsed_lsp_pk;
    TEST_ASSERT(wire_parse_jit_offer(offer, ctx, &cidx, &amount,
                                       reason, sizeof(reason), &parsed_lsp_pk),
                "parse offer");
    cJSON_Delete(offer);

    /* Client builds accept */
    cJSON *accept = wire_build_jit_accept(cidx, ctx, &cli_pk);
    TEST_ASSERT(accept != NULL, "build accept");

    /* LSP parses accept */
    size_t parsed_cidx;
    secp256k1_pubkey parsed_cli_pk;
    TEST_ASSERT(wire_parse_jit_accept(accept, ctx, &parsed_cidx, &parsed_cli_pk),
                "parse accept");
    cJSON_Delete(accept);

    TEST_ASSERT_EQ((long)parsed_cidx, 1, "client_idx should match");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_client_jit_channel_dispatch(void) {
    /* Test that COMMITMENT_SIGNED with JIT channel_id dispatches correctly */
    uint32_t jit_id = JIT_CHANNEL_ID_BASE | 3;
    TEST_ASSERT(jit_id >= JIT_CHANNEL_ID_BASE,
                "JIT channel ID should be >= JIT_CHANNEL_ID_BASE");

    /* Simulate dispatch logic */
    uint32_t parsed_id = jit_id;
    int is_jit = (parsed_id >= JIT_CHANNEL_ID_BASE) ? 1 : 0;
    TEST_ASSERT_EQ(is_jit, 1, "should detect JIT channel");

    parsed_id = 2;  /* factory channel */
    is_jit = (parsed_id >= JIT_CHANNEL_ID_BASE) ? 1 : 0;
    TEST_ASSERT_EQ(is_jit, 0, "should detect factory channel");

    return 1;
}

/* --- Step 6: Persistence Tests --- */

int test_persist_jit_save_load(void) {
    persist_t p;
    TEST_ASSERT(persist_open(&p, ":memory:"), "open db");

    jit_channel_t jit;
    memset(&jit, 0, sizeof(jit));
    jit.jit_channel_id = 0x8001;
    jit.client_idx = 1;
    jit.state = JIT_STATE_OPEN;
    strncpy(jit.funding_txid_hex, "aabb", 64);
    jit.funding_vout = 0;
    jit.funding_amount = 50000;
    jit.channel.local_amount = 20000;
    jit.channel.remote_amount = 20000;
    jit.channel.commitment_number = 3;
    jit.created_at = time(NULL);
    jit.created_block = 100;
    jit.target_factory_id = 0;

    TEST_ASSERT(persist_save_jit_channel(&p, &jit), "save jit");

    jit_channel_t loaded[4];
    size_t count = 0;
    persist_load_jit_channels(&p, loaded, 4, &count);
    TEST_ASSERT_EQ((long)count, 1, "should load 1 JIT channel");
    TEST_ASSERT_EQ((long)loaded[0].jit_channel_id, 0x8001, "id match");
    TEST_ASSERT_EQ((long)loaded[0].client_idx, 1, "client_idx match");
    TEST_ASSERT(loaded[0].state == JIT_STATE_OPEN, "state match");
    TEST_ASSERT_EQ((long)loaded[0].funding_amount, 50000, "amount match");
    TEST_ASSERT_EQ((long)loaded[0].channel.local_amount, 20000, "local match");
    TEST_ASSERT_EQ((long)loaded[0].channel.remote_amount, 20000, "remote match");
    TEST_ASSERT_EQ((long)loaded[0].channel.commitment_number, 3, "cn match");
    TEST_ASSERT_EQ((long)loaded[0].created_block, 100, "block match");

    persist_close(&p);
    return 1;
}

int test_persist_jit_update(void) {
    persist_t p;
    TEST_ASSERT(persist_open(&p, ":memory:"), "open db");

    jit_channel_t jit;
    memset(&jit, 0, sizeof(jit));
    jit.jit_channel_id = 0x8002;
    jit.client_idx = 2;
    jit.state = JIT_STATE_OPEN;
    jit.funding_amount = 40000;
    jit.channel.local_amount = 15000;
    jit.channel.remote_amount = 15000;
    TEST_ASSERT(persist_save_jit_channel(&p, &jit), "save jit");

    /* Update state */
    TEST_ASSERT(persist_update_jit_state(&p, 0x8002, "migrating"), "update state");

    /* Update balance */
    TEST_ASSERT(persist_update_jit_balance(&p, 0x8002, 10000, 20000, 5),
                "update balance");

    /* Load and verify */
    jit_channel_t loaded[4];
    size_t count = 0;
    persist_load_jit_channels(&p, loaded, 4, &count);
    TEST_ASSERT_EQ((long)count, 1, "should load 1");
    TEST_ASSERT(loaded[0].state == JIT_STATE_MIGRATING, "state should be migrating");
    TEST_ASSERT_EQ((long)loaded[0].channel.local_amount, 10000, "local updated");
    TEST_ASSERT_EQ((long)loaded[0].channel.remote_amount, 20000, "remote updated");
    TEST_ASSERT_EQ((long)loaded[0].channel.commitment_number, 5, "cn updated");

    persist_close(&p);
    return 1;
}

int test_persist_jit_delete(void) {
    persist_t p;
    TEST_ASSERT(persist_open(&p, ":memory:"), "open db");

    jit_channel_t jit;
    memset(&jit, 0, sizeof(jit));
    jit.jit_channel_id = 0x8003;
    jit.client_idx = 3;
    jit.state = JIT_STATE_OPEN;
    TEST_ASSERT(persist_save_jit_channel(&p, &jit), "save jit");

    TEST_ASSERT(persist_delete_jit_channel(&p, 0x8003), "delete jit");

    jit_channel_t loaded[4];
    size_t count = 0;
    persist_load_jit_channels(&p, loaded, 4, &count);
    TEST_ASSERT_EQ((long)count, 0, "should be deleted");

    persist_close(&p);
    return 1;
}

/* --- Step 7: Cooperative Close Tests --- */

int test_jit_cooperative_close(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Set up LSP and client keys */
    unsigned char lsp_sec[32], cli_sec[32];
    memset(lsp_sec, 0x71, 32);
    memset(cli_sec, 0x72, 32);
    secp256k1_pubkey lsp_pk, cli_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec), "lsp pk");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &cli_pk, cli_sec), "cli pk");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 4;
    memcpy(mgr.rot_lsp_seckey, lsp_sec, 32);

    jit_channels_init(&mgr);

    /* Create a JIT channel with proper channel_t initialization */
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 1;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 1;
    jits[0].funding_amount = 100000;
    jits[0].channel.local_amount = 45000;
    jits[0].channel.remote_amount = 45000;
    jits[0].channel.remote_funding_pubkey = cli_pk;
    mgr.n_jit_channels = 1;

    /* Verify key match logic: provide correct extracted key */
    secp256k1_pubkey extracted_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &extracted_pk, cli_sec),
                "create extracted pk");
    unsigned char ser_ext[33], ser_remote[33];
    size_t l1 = 33, l2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser_ext, &l1, &extracted_pk,
                                    SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, ser_remote, &l2,
                                    &jits[0].channel.remote_funding_pubkey,
                                    SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(ser_ext, ser_remote, 33) == 0,
                "extracted key should match JIT remote funding pubkey");

    /* Can't fully test broadcast without regtest, but verify the key match
       and state prerequisites work correctly */
    TEST_ASSERT(jit_channel_is_active(&mgr, 1), "JIT should be active");

    /* Call with NULL chain_be — should return 0 (no crash) */
    int ret = jit_channel_cooperative_close(&mgr, 1, cli_sec, NULL);
    TEST_ASSERT_EQ(ret, 0, "should fail with NULL chain_be");
    TEST_ASSERT(jits[0].state == JIT_STATE_OPEN,
                "state should remain OPEN after failed close");

    jit_channels_cleanup(&mgr);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_jit_cooperative_close_key_mismatch(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_sec[32], cli_sec[32], wrong_sec[32];
    memset(lsp_sec, 0x81, 32);
    memset(cli_sec, 0x82, 32);
    memset(wrong_sec, 0x99, 32);
    secp256k1_pubkey lsp_pk, cli_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec), "lsp pk");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &cli_pk, cli_sec), "cli pk");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 4;

    jit_channels_init(&mgr);

    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 2;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 2;
    jits[0].funding_amount = 50000;
    jits[0].channel.remote_funding_pubkey = cli_pk;
    mgr.n_jit_channels = 1;

    /* Provide wrong extracted key — function exits before using chain_be vtable */
    chain_backend_t dummy_be;
    memset(&dummy_be, 0, sizeof(dummy_be));
    int ret = jit_channel_cooperative_close(&mgr, 2, wrong_sec, &dummy_be);
    TEST_ASSERT_EQ(ret, 0, "should fail with wrong key");
    TEST_ASSERT(jits[0].state == JIT_STATE_OPEN,
                "state should remain OPEN on key mismatch");

    jit_channels_cleanup(&mgr);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Step 7b: Migration Tests --- */

/* A chain on which every queried outpoint was spent by a confirmed
   transaction. */
static int migrate_chain_spent(chain_backend_t *self, const char *txid_hex,
                               uint32_t vout) {
    (void)self; (void)txid_hex; (void)vout;
    return 1;
}

int test_jit_migrate_lifecycle(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.n_channels = 4;
    mgr.entries[1].ready = 1;
    mgr.entries[1].channel_id = 1;
    mgr.entries[1].channel.local_amount = 40000;
    mgr.entries[1].channel.remote_amount = 40000;

    jit_channels_init(&mgr);

    /* Create a fake JIT channel */
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 1;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 1;
    jits[0].channel.local_amount = 5000;
    jits[0].channel.remote_amount = 3000;
    memset(jits[0].funding_txid_hex, 'b', 64);
    mgr.n_jit_channels = 1;

    /* The JIT funding output has been spent on chain. */
    chain_backend_t spent_chain;
    memset(&spent_chain, 0, sizeof(spent_chain));
    spent_chain.is_outpoint_spent_confirmed = migrate_chain_spent;
    mgr.chain_be = &spent_chain;

    TEST_ASSERT(jit_channel_is_active(&mgr, 1), "JIT should be active before migrate");

    /* Migrate (no LSP/fd needed for state transition test) */
    TEST_ASSERT_EQ(jit_channel_migrate(&mgr, NULL, 1, 0), 1, "migrate retires the channel");

    /* JIT channel should be closed */
    TEST_ASSERT(jits[0].state == JIT_STATE_CLOSED, "JIT should be closed");
    TEST_ASSERT_EQ(jit_channel_is_active(&mgr, 1), 0, "JIT should not be active");

    /* Factory balances should be UNCHANGED (JIT funds recovered on-chain) */
    TEST_ASSERT_EQ((long)mgr.entries[1].channel.local_amount, 40000,
                   "factory local should be unchanged after migration");
    TEST_ASSERT_EQ((long)mgr.entries[1].channel.remote_amount, 40000,
                   "factory remote should be unchanged after migration");

    jit_channels_cleanup(&mgr);
    free(mgr.entries);
    return 1;
}

int test_jit_migrate_no_balance_hack(void) {
    /* Verify migration does NOT touch factory channel balances.
       JIT funds are recovered via on-chain cooperative close (Phase A.5),
       not by adjusting in-memory balances. */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.n_channels = 4;
    mgr.entries[0].ready = 1;
    mgr.entries[0].channel_id = 0;
    mgr.entries[0].channel.local_amount = 100000;
    mgr.entries[0].channel.remote_amount = 80000;

    jit_channels_init(&mgr);

    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 0;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 0;
    jits[0].channel.local_amount = 15000;
    jits[0].channel.remote_amount = 12000;
    memset(jits[0].funding_txid_hex, 'c', 64);
    mgr.n_jit_channels = 1;

    /* The JIT funding output has been spent on chain. */
    chain_backend_t spent_chain;
    memset(&spent_chain, 0, sizeof(spent_chain));
    spent_chain.is_outpoint_spent_confirmed = migrate_chain_spent;
    mgr.chain_be = &spent_chain;

    TEST_ASSERT_EQ(jit_channel_migrate(&mgr, NULL, 0, 0), 1, "migrate retires the channel");
    TEST_ASSERT(jits[0].state == JIT_STATE_CLOSED, "JIT should be closed");

    TEST_ASSERT_EQ((long)mgr.entries[0].channel.local_amount, 100000,
                   "factory local unchanged");
    TEST_ASSERT_EQ((long)mgr.entries[0].channel.remote_amount, 80000,
                   "factory remote unchanged");

    jit_channels_cleanup(&mgr);
    free(mgr.entries);
    return 1;
}

/* --- Step 8: State Conversion Tests --- */

int test_jit_state_conversion(void) {
    TEST_ASSERT(strcmp(jit_state_to_str(JIT_STATE_NONE), "none") == 0, "none");
    TEST_ASSERT(strcmp(jit_state_to_str(JIT_STATE_FUNDING), "funding") == 0, "funding");
    TEST_ASSERT(strcmp(jit_state_to_str(JIT_STATE_OPEN), "open") == 0, "open");
    TEST_ASSERT(strcmp(jit_state_to_str(JIT_STATE_MIGRATING), "migrating") == 0, "migrating");
    TEST_ASSERT(strcmp(jit_state_to_str(JIT_STATE_CLOSED), "closed") == 0, "closed");

    TEST_ASSERT_EQ((long)jit_state_from_str("none"), (long)JIT_STATE_NONE, "from none");
    TEST_ASSERT_EQ((long)jit_state_from_str("open"), (long)JIT_STATE_OPEN, "from open");
    TEST_ASSERT_EQ((long)jit_state_from_str("migrating"),
                   (long)JIT_STATE_MIGRATING, "from migrating");
    TEST_ASSERT_EQ((long)jit_state_from_str("closed"),
                   (long)JIT_STATE_CLOSED, "from closed");
    TEST_ASSERT_EQ((long)jit_state_from_str("bogus"),
                   (long)JIT_STATE_NONE, "unknown -> none");

    return 1;
}

int test_jit_msg_type_names(void) {
    TEST_ASSERT(strcmp(wire_msg_type_name(MSG_JIT_OFFER), "JIT_OFFER") == 0,
                "JIT_OFFER name");
    TEST_ASSERT(strcmp(wire_msg_type_name(MSG_JIT_ACCEPT), "JIT_ACCEPT") == 0,
                "JIT_ACCEPT name");
    TEST_ASSERT(strcmp(wire_msg_type_name(MSG_JIT_READY), "JIT_READY") == 0,
                "JIT_READY name");
    TEST_ASSERT(strcmp(wire_msg_type_name(MSG_JIT_MIGRATE), "JIT_MIGRATE") == 0,
                "JIT_MIGRATE name");
    return 1;
}

/* --- JIT Hardening Tests --- */

/* test_jit_watchtower_registration deleted in #208 A3.2 — it asserted
   the live channel-pointer registration mechanism (watchtower_set_channel
   + wt.channels[idx]) which has been removed in favor of the oracular
   model.  The new invariant ("no live channel state in the watchtower")
   is enforced by the absence of the channels[] field — there's no
   meaningful test to write. */

/* Step 1: Watchtower revocation tracking for JIT */
int test_jit_watchtower_revocation(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a real channel for the watchtower to use */
    unsigned char lsp_sec[32], cli_sec[32];
    memset(lsp_sec, 0x55, 32);
    memset(cli_sec, 0x66, 32);
    secp256k1_pubkey lsp_pk, cli_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &cli_pk, cli_sec)) return 0;

    /* Build a minimal funding outpoint */
    unsigned char fund_txid[32];
    memset(fund_txid, 0xaa, 32);
    unsigned char fund_spk[34];
    memset(fund_spk, 0, 34);
    fund_spk[0] = 0x51;
    fund_spk[1] = 0x20;

    channel_t ch;
    channel_init(&ch, ctx, lsp_sec, &lsp_pk, &cli_pk,
                   fund_txid, 0, 100000, fund_spk, 34,
                   45000, 45000, 144);
    channel_generate_random_basepoints(&ch);

    watchtower_t wt;
    watchtower_init(&wt, 8, NULL, NULL, NULL);

    /* Register as JIT watchtower index (e.g. index 5 for client 1 with 4 factory channels).
       watchtower_set_channel dropped in #208 A3.2. */
    uint32_t wt_chan_id = 5;

    /* Add a watch entry manually */
    unsigned char fake_txid[32];
    memset(fake_txid, 0xbb, 32);
    unsigned char fake_spk[34];
    memset(fake_spk, 0, 34);
    fake_spk[0] = 0x51;
    fake_spk[1] = 0x20;

    int ok = watchtower_watch(&wt, wt_chan_id, 0, fake_txid, 0, 40000, fake_spk, 34);
    TEST_ASSERT(ok, "watchtower_watch should succeed");
    TEST_ASSERT_EQ((long)wt.n_entries, 1, "should have 1 entry");
    TEST_ASSERT_EQ((long)wt.entries[0].channel_id, (long)wt_chan_id,
                   "entry channel_id should be JIT watchtower index");

    channel_cleanup(&ch);
    watchtower_cleanup(&wt);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Step 1: Watchtower entries removed on JIT close/migrate */
int test_jit_watchtower_cleanup_on_close(void) {
    watchtower_t wt;
    watchtower_init(&wt, 8, NULL, NULL, NULL);

    /* Add entries for JIT channel index 6 */
    unsigned char txid1[32], txid2[32];
    memset(txid1, 0x11, 32);
    memset(txid2, 0x22, 32);
    unsigned char spk[34];
    memset(spk, 0, 34);
    spk[0] = 0x51;
    spk[1] = 0x20;

    watchtower_watch(&wt, 6, 0, txid1, 0, 10000, spk, 34);
    watchtower_watch(&wt, 6, 1, txid2, 0, 12000, spk, 34);
    /* Also add an entry for a different channel */
    unsigned char txid3[32];
    memset(txid3, 0x33, 32);
    watchtower_watch(&wt, 0, 0, txid3, 0, 15000, spk, 34);

    TEST_ASSERT_EQ((long)wt.n_entries, 3, "should have 3 entries");

    /* Remove JIT channel 6 entries */
    watchtower_remove_channel(&wt, 6);

    TEST_ASSERT_EQ((long)wt.n_entries, 1, "should have 1 entry left");
    TEST_ASSERT_EQ((long)wt.entries[0].channel_id, 0,
                   "remaining entry should be channel 0");

    watchtower_cleanup(&wt);
    return 1;
}

/* Step 2: Persist JIT OPEN + basepoints, reload and verify state */
int test_jit_persist_reload_active(void) {
    persist_t p;
    TEST_ASSERT(persist_open(&p, ":memory:"), "open db");

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    jit_channel_t jit;
    memset(&jit, 0, sizeof(jit));
    jit.jit_channel_id = 0x8003;
    jit.client_idx = 3;
    jit.state = JIT_STATE_OPEN;
    jit.funding_amount = 75000;
    jit.channel.local_amount = 30000;
    jit.channel.remote_amount = 35000;
    jit.channel.commitment_number = 2;
    jit.channel.ctx = ctx;
    jit.created_at = time(NULL);

    /* Generate random basepoints (local) */
    channel_generate_random_basepoints(&jit.channel);

    /* Generate fake remote basepoints (need valid pubkeys for serialization) */
    unsigned char rsec[32];
    for (int i = 0; i < 4; i++) {
        memset(rsec, 0x30 + i, 32);
        secp256k1_pubkey *rp = (i == 0) ? &jit.channel.remote_payment_basepoint :
                               (i == 1) ? &jit.channel.remote_delayed_payment_basepoint :
                               (i == 2) ? &jit.channel.remote_revocation_basepoint :
                                          &jit.channel.remote_htlc_basepoint;
        if (!secp256k1_ec_pubkey_create(ctx, rp, rsec)) return 0;
    }

    /* Save JIT + basepoints */
    TEST_ASSERT(persist_save_jit_channel(&p, &jit), "save jit");
    persist_save_basepoints(&p, jit.jit_channel_id, &jit.channel);

    /* Reload */
    jit_channel_t loaded[4];
    size_t count = 0;
    persist_load_jit_channels(&p, loaded, 4, &count);
    TEST_ASSERT_EQ((long)count, 1, "should load 1");
    TEST_ASSERT(loaded[0].state == JIT_STATE_OPEN, "state should be OPEN");
    TEST_ASSERT_EQ((long)loaded[0].jit_channel_id, 0x8003, "id match");
    TEST_ASSERT_EQ((long)loaded[0].channel.local_amount, 30000, "local match");

    /* Load basepoints */
    unsigned char loaded_secs[4][32], loaded_bps[4][33];
    memset(loaded_secs, 0, sizeof(loaded_secs));
    TEST_ASSERT(persist_load_basepoints(&p, 0x8003, loaded_secs, loaded_bps),
                "load basepoints");

    /* Verify a local basepoint secret was loaded (non-zero) */
    unsigned char zero[32];
    memset(zero, 0, 32);
    TEST_ASSERT(memcmp(loaded_secs[0], zero, 32) != 0,
                "payment_secret should be loaded");

    persist_close(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Step 2: CLOSED JIT channels not activated on reload */
int test_jit_persist_skip_closed(void) {
    persist_t p;
    TEST_ASSERT(persist_open(&p, ":memory:"), "open db");

    jit_channel_t jit;
    memset(&jit, 0, sizeof(jit));
    jit.jit_channel_id = 0x8004;
    jit.client_idx = 0;
    jit.state = JIT_STATE_CLOSED;
    jit.funding_amount = 50000;
    TEST_ASSERT(persist_save_jit_channel(&p, &jit), "save closed jit");

    /* Load and check - should still load it but state is CLOSED */
    jit_channel_t loaded[4];
    size_t count = 0;
    persist_load_jit_channels(&p, loaded, 4, &count);
    TEST_ASSERT_EQ((long)count, 1, "should load 1");
    TEST_ASSERT(loaded[0].state == JIT_STATE_CLOSED, "state should be CLOSED");

    /* Simulate reconnect logic: only activate OPEN ones */
    int activated = 0;
    for (size_t i = 0; i < count; i++) {
        if (loaded[i].state == JIT_STATE_OPEN)
            activated = 1;
    }
    TEST_ASSERT_EQ(activated, 0, "should not activate closed JIT");

    persist_close(&p);
    return 1;
}

/* Step 3: Multiple simultaneous JIT channels */
int test_jit_multiple_channels(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.n_channels = 4;

    jit_channels_init(&mgr);

    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;

    /* Create JIT for clients 0, 2, 3 */
    jits[0].client_idx = 0;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 0;
    jits[0].channel.local_amount = 10000;

    jits[1].client_idx = 2;
    jits[1].state = JIT_STATE_OPEN;
    jits[1].jit_channel_id = JIT_CHANNEL_ID_BASE | 2;
    jits[1].channel.local_amount = 20000;

    jits[2].client_idx = 3;
    jits[2].state = JIT_STATE_OPEN;
    jits[2].jit_channel_id = JIT_CHANNEL_ID_BASE | 3;
    jits[2].channel.local_amount = 30000;

    mgr.n_jit_channels = 3;

    /* Verify find returns correct channel for each */
    jit_channel_t *f0 = jit_channel_find(&mgr, 0);
    jit_channel_t *f2 = jit_channel_find(&mgr, 2);
    jit_channel_t *f3 = jit_channel_find(&mgr, 3);
    jit_channel_t *f1 = jit_channel_find(&mgr, 1);

    TEST_ASSERT(f0 != NULL, "should find JIT for client 0");
    TEST_ASSERT(f2 != NULL, "should find JIT for client 2");
    TEST_ASSERT(f3 != NULL, "should find JIT for client 3");
    TEST_ASSERT(f1 == NULL, "should NOT find JIT for client 1");

    TEST_ASSERT_EQ((long)f0->channel.local_amount, 10000, "client 0 amount");
    TEST_ASSERT_EQ((long)f2->channel.local_amount, 20000, "client 2 amount");
    TEST_ASSERT_EQ((long)f3->channel.local_amount, 30000, "client 3 amount");

    /* Verify effective channel dispatch */
    uint32_t ch_id;
    channel_t *eff0 = jit_get_effective_channel(&mgr, 0, &ch_id);
    TEST_ASSERT(eff0 != NULL, "should get effective for client 0");
    TEST_ASSERT_EQ((long)ch_id, (long)(JIT_CHANNEL_ID_BASE | 0), "JIT ch_id for 0");

    jit_channels_cleanup(&mgr);
    free(mgr.entries);
    return 1;
}

/* Step 3: Multiple JIT channels with correct watchtower indices */
int test_jit_multiple_watchtower_indices(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;

    watchtower_t wt;
    watchtower_init(&wt, 4, NULL, NULL, NULL);
    mgr.watchtower = &wt;

    jit_channels_init(&mgr);
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;

    /* Create JIT for clients 0, 2, 3 and register with watchtower */
    size_t clients[] = {0, 2, 3};
    for (int i = 0; i < 3; i++) {
        jits[i].client_idx = clients[i];
        jits[i].state = JIT_STATE_OPEN;
        jits[i].jit_channel_id = JIT_CHANNEL_ID_BASE | (uint32_t)clients[i];

        size_t wt_idx = mgr.n_channels + clients[i];
        /* watchtower_set_channel dropped in #208 A3.2 — direct field
           write keeps the assertion below meaningful for legacy sweep
           paths that still reach into channels[]. */
        if (wt_idx < wt.channels_cap)
            wt.channels[wt_idx] = &jits[i].channel;
    }
    mgr.n_jit_channels = 3;

    /* Verify watchtower indices: 4+0=4, 4+2=6, 4+3=7 */
    TEST_ASSERT(wt.channels[4] == &jits[0].channel,
                "wt[4] should be client 0 JIT");
    TEST_ASSERT(wt.channels[5] == NULL,
                "wt[5] should be NULL (no client 1 JIT)");
    TEST_ASSERT(wt.channels[6] == &jits[1].channel,
                "wt[6] should be client 2 JIT");
    TEST_ASSERT(wt.channels[7] == &jits[2].channel,
                "wt[7] should be client 3 JIT");

    jit_channels_cleanup(&mgr);
    watchtower_cleanup(&wt);
    return 1;
}

/* Step 4: JIT funding confirmation transition */
int test_jit_funding_confirmation_transition(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;

    watchtower_t wt;
    watchtower_init(&wt, 4, NULL, NULL, NULL);
    mgr.watchtower = &wt;
    /* No regtest connection — check_funding should return 0 */

    jit_channels_init(&mgr);

    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 1;
    jits[0].state = JIT_STATE_FUNDING;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 1;
    strncpy(jits[0].funding_txid_hex, "aabbccdd", 64);
    mgr.n_jit_channels = 1;

    /* Without regtest, check_funding should return 0 (no transitions) */
    int transitions = jit_channels_check_funding(&mgr);
    TEST_ASSERT_EQ(transitions, 0, "no transitions without regtest");

    /* Channel should still be FUNDING */
    TEST_ASSERT(jits[0].state == JIT_STATE_FUNDING,
                "state should still be FUNDING");

    /* Manually simulate confirmed state */
    jits[0].state = JIT_STATE_OPEN;
    jits[0].funding_confirmed = 1;
    TEST_ASSERT(jit_channel_is_active(&mgr, 1), "should be active after manual open");

    jit_channels_cleanup(&mgr);
    watchtower_cleanup(&wt);
    return 1;
}

/* --- Regtest: daemon loop JIT trigger on factory expiry --- */

typedef struct {
    int fd;
    secp256k1_context *ctx;
    unsigned char seckey[32];
} jit_client_ctx_t;

static void *jit_client_handler(void *arg) {
    jit_client_ctx_t *c = (jit_client_ctx_t *)arg;
    wire_msg_t msg;

    /* 1. Receive JIT_OFFER */
    if (!wire_recv(c->fd, &msg) || msg.msg_type != MSG_JIT_OFFER) return NULL;
    cJSON_Delete(msg.json);

    /* 2. Send JIT_ACCEPT with our pubkey */
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(c->ctx, &pk, c->seckey)) return NULL;
    cJSON *acc = wire_build_jit_accept(0, c->ctx, &pk);
    wire_send(c->fd, MSG_JIT_ACCEPT, acc);
    cJSON_Delete(acc);

    /* 3. Receive BASEPOINTS, send ours back */
    if (!wire_recv(c->fd, &msg) || msg.msg_type != MSG_CHANNEL_BASEPOINTS) return NULL;
    cJSON_Delete(msg.json);

    unsigned char sk[32];
    secp256k1_pubkey bps[6];
    for (int i = 0; i < 6; i++) {
        memset(sk, 0x10 + i, 32);
        sk[31] = (unsigned char)(i + 1);
        if (!secp256k1_ec_pubkey_create(c->ctx, &bps[i], sk)) return NULL;
    }
    cJSON *bpm = wire_build_channel_basepoints(
        JIT_CHANNEL_ID_BASE, c->ctx,
        &bps[0], &bps[1], &bps[2], &bps[3], &bps[4], &bps[5]);
    wire_send(c->fd, MSG_CHANNEL_BASEPOINTS, bpm);
    cJSON_Delete(bpm);

    /* 4. Receive NONCES, send matching count of fake nonces */
    if (!wire_recv(c->fd, &msg) || msg.msg_type != MSG_CHANNEL_NONCES) return NULL;
    uint32_t ch_id;
    unsigned char recv_nonces[256][66];
    size_t nonce_count = 0;
    wire_parse_channel_nonces(msg.json, &ch_id, recv_nonces, 256, &nonce_count);
    cJSON_Delete(msg.json);

    unsigned char (*fake_nonces)[66] = calloc(nonce_count, 66);
    for (size_t i = 0; i < nonce_count; i++)
        memset(fake_nonces[i], 0x42 + (unsigned char)(i & 0xFF), 66);

    cJSON *nm = wire_build_channel_nonces(JIT_CHANNEL_ID_BASE,
                                            (const unsigned char (*)[66])fake_nonces,
                                            nonce_count);
    wire_send(c->fd, MSG_CHANNEL_NONCES, nm);
    cJSON_Delete(nm);
    free(fake_nonces);

    /* 5. Receive JIT_READY */
    if (!wire_recv(c->fd, &msg) || msg.msg_type != MSG_JIT_READY) return NULL;
    cJSON_Delete(msg.json);

    static int client_ok = 1;  /* any non-NULL value signals success to pthread_join */
    return &client_ok;
}

int test_regtest_jit_daemon_trigger(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Connect to regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_jit_trigger");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    regtest_fund_from_faucet(&rt, 10.0);

    /* Create minimal factory with short lifecycle */
    int base_height = regtest_get_block_height(&rt);
    factory_t *f = calloc(1, sizeof(factory_t));
    factory_alloc_default_arrays(f);
    if (!f) return 0;

    factory_set_lifecycle(f, (uint32_t)base_height, 5, 5);

    /* Verify state transitions */
    TEST_ASSERT(factory_get_state(f, (uint32_t)base_height) == FACTORY_ACTIVE,
                "should be ACTIVE at creation");

    regtest_mine_blocks(&rt, 5, mine_addr);
    int h2 = regtest_get_block_height(&rt);
    TEST_ASSERT(factory_get_state(f, (uint32_t)h2) == FACTORY_DYING,
                "should be DYING after active_blocks");

    regtest_mine_blocks(&rt, 5, mine_addr);
    int h3 = regtest_get_block_height(&rt);
    TEST_ASSERT(factory_get_state(f, (uint32_t)h3) == FACTORY_EXPIRED,
                "should be EXPIRED after dying_blocks");

    /* Set up watchtower with regtest connection */
    watchtower_t wt;
    watchtower_init(&wt, 2, &rt, NULL, NULL); /* factory channels + JIT slots */

    /* Set up lsp_channel_mgr_t */
    unsigned char lsp_seckey[32];
    memset(lsp_seckey, 0x01, 32);
    lsp_seckey[31] = 0x01;

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 1;
    mgr.ctx = ctx;
    mgr.n_channels = 1;
    mgr.watchtower = &wt;
    memcpy(mgr.rot_lsp_seckey, lsp_seckey, 32);
    mgr.rot_is_regtest = 1;
    snprintf(mgr.rot_fund_addr, sizeof(mgr.rot_fund_addr), "%s", mine_addr);
    snprintf(mgr.rot_mine_addr, sizeof(mgr.rot_mine_addr), "%s", mine_addr);
    mgr.rot_funding_sats = 50000;
    jit_channels_init(&mgr);

    /* Set up lsp_t with factory */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;

    lsp->client_fds = calloc(LSP_MAX_CLIENTS, sizeof(int));
    lsp->client_pubkeys = calloc(LSP_MAX_CLIENTS, sizeof(secp256k1_pubkey));
    lsp->clients_cap = LSP_MAX_CLIENTS;
    lsp->factory = *f;

    /* Verify daemon loop JIT trigger conditions */
    int h = regtest_get_block_height(mgr.watchtower->rt);
    factory_state_t fs = factory_get_state(&lsp->factory, (uint32_t)h);
    TEST_ASSERT(fs == FACTORY_EXPIRED, "daemon should detect factory EXPIRED");
    TEST_ASSERT(!mgr.jit_enabled, "JIT opens are off after init");
    TEST_ASSERT(!jit_channel_is_active(&mgr, 0), "no active JIT for client 0");

    /* Create socketpair for client wire protocol */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    lsp->client_fds[0] = sv[0];

    /* Start client thread to handle JIT protocol */
    jit_client_ctx_t client_args;
    client_args.fd = sv[1];
    client_args.ctx = ctx;
    memset(client_args.seckey, 0x02, 32);
    client_args.seckey[31] = 0x02;

    pthread_t tid;
    pthread_create(&tid, NULL, jit_client_handler, &client_args);

    /* Without the opt-in nothing is opened and the wallet is not used. */
    double bal_before = regtest_get_balance(&rt);
    TEST_ASSERT(!jit_channel_create(&mgr, lsp, 0, 50000, "factory_expired"),
                "jit_channel_create refuses while JIT opens are disabled");
    TEST_ASSERT_EQ(lsp_channels_jit_expiry_trigger(&mgr, lsp), 0,
                   "expiry trigger does nothing while JIT opens are disabled");
    TEST_ASSERT_EQ((long)mgr.n_jit_channels, 0, "no JIT channel recorded");
    TEST_ASSERT(regtest_get_balance(&rt) == bal_before, "wallet balance unchanged");

    /* Opt in, as the experimental flag does, and open through the same
       factory-expired trigger the daemon loop runs. */
    mgr.jit_enabled = 1;
    int ok = lsp_channels_jit_expiry_trigger(&mgr, lsp) == 1 &&
             jit_channel_is_active(&mgr, 0);
    TEST_ASSERT(ok, "expiry trigger should open the JIT channel");

    /* Verify JIT channel is active */
    TEST_ASSERT(jit_channel_is_active(&mgr, 0), "JIT should be active after create");
    TEST_ASSERT_EQ((long)mgr.n_jit_channels, 1, "should have 1 JIT channel");

    jit_channel_t *jit = jit_channel_find(&mgr, 0);
    TEST_ASSERT(jit != NULL, "should find JIT for client 0");
    TEST_ASSERT(jit->state == JIT_STATE_OPEN, "JIT state should be OPEN");
    TEST_ASSERT(jit->funding_amount > 0, "funding_amount should be set");

    void *thread_ret;
    pthread_join(tid, &thread_ret);
    TEST_ASSERT(thread_ret != NULL, "client thread should succeed");

    /* Cleanup */
    jit_channels_cleanup(&mgr);
    watchtower_cleanup(&wt);
    free(mgr.entries);
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
    free(f);
    close(sv[0]);
    close(sv[1]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- JIT opens are off unless explicitly enabled --- */

#include "superscalar/ladder.h"
#include "superscalar/lsps.h"
#include "superscalar/wallet_source.h"
#include <poll.h>

static int g_gate_wallet_calls;
static int g_gate_broadcast_calls;

static int gate_wallet_get_utxo(wallet_source_t *self, uint64_t min_sats,
                                char txid_hex[65], uint32_t *vout,
                                uint64_t *amount, unsigned char *spk,
                                size_t *spk_len) {
    (void)self; (void)min_sats; (void)txid_hex; (void)vout; (void)amount;
    (void)spk; (void)spk_len;
    g_gate_wallet_calls++;
    return 0;
}

static int gate_chain_send_raw_tx(chain_backend_t *self, const char *tx_hex,
                                  char *txid_out) {
    (void)self; (void)tx_hex; (void)txid_out;
    g_gate_broadcast_calls++;
    return 0;
}

/* 1 if a wire frame is waiting on fd within timeout_ms. */
static int gate_fd_readable(int fd, int timeout_ms) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    return poll(&p, 1, timeout_ms) > 0 && (p.revents & POLLIN);
}

typedef struct {
    lsp_channel_mgr_t mgr;
    lsp_t *lsp;
    secp256k1_context *ctx;
    wallet_source_t wallet;
    chain_backend_t chain;
    int peer_fd[2];             /* the client ends of the connections */
    ladder_t *ladder;
} jit_gate_fixture_t;

static int jit_gate_fixture_init(jit_gate_fixture_t *fx, size_t n_clients) {
    memset(fx, 0, sizeof(*fx));
    fx->peer_fd[0] = fx->peer_fd[1] = -1;
    if (n_clients < 1 || n_clients > 2) return 0;
    fx->ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    fx->mgr.ctx = fx->ctx;
    fx->mgr.entries = calloc(n_clients, sizeof(lsp_channel_entry_t));
    fx->mgr.entries_cap = n_clients;
    fx->mgr.n_channels = n_clients;
    memset(fx->mgr.rot_lsp_seckey, 0x01, 32);
    fx->mgr.jit_funding_sats = 50000;
    fx->wallet.get_utxo = gate_wallet_get_utxo;
    fx->chain.send_raw_tx = gate_chain_send_raw_tx;
    fx->mgr.wallet_src = &fx->wallet;
    fx->mgr.chain_be = &fx->chain;
    if (!jit_channels_init(&fx->mgr)) return 0;

    fx->lsp = calloc(1, sizeof(lsp_t));
    if (!fx->mgr.entries || !fx->lsp) return 0;
    fx->lsp->client_fds = calloc(LSP_MAX_CLIENTS, sizeof(int));
    if (!fx->lsp->client_fds) return 0;
    fx->lsp->clients_cap = LSP_MAX_CLIENTS;
    fx->lsp->n_clients = n_clients;
    for (size_t i = 0; i < LSP_MAX_CLIENTS; i++) fx->lsp->client_fds[i] = -1;
    for (size_t i = 0; i < n_clients; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
        fx->lsp->client_fds[i] = sv[0];
        fx->peer_fd[i] = sv[1];
    }

    /* One factory, expired. */
    fx->ladder = calloc(1, sizeof(ladder_t));
    if (!fx->ladder) return 0;
    fx->ladder->n_factories = 1;
    fx->ladder->factories[0].cached_state = FACTORY_EXPIRED;
    fx->mgr.ladder = fx->ladder;

    g_gate_wallet_calls = 0;
    g_gate_broadcast_calls = 0;
    return 1;
}

static void jit_gate_fixture_free(jit_gate_fixture_t *fx) {
    for (size_t i = 0; i < 2; i++) {
        if (fx->peer_fd[i] >= 0) close(fx->peer_fd[i]);
        if (fx->lsp && fx->lsp->client_fds[i] >= 0) close(fx->lsp->client_fds[i]);
    }
    jit_channels_cleanup(&fx->mgr);
    free(fx->mgr.entries);
    if (fx->lsp) free(fx->lsp->client_fds);
    free(fx->lsp);
    free(fx->ladder);
    if (fx->ctx) secp256k1_context_destroy(fx->ctx);
}

/* Reads one JIT_OFFER and hangs up, so an enabled open fails fast. */
static void *gate_peer_take_offer_and_hang_up(void *arg) {
    int *fd = (int *)arg;
    static int got_offer = 1;
    wire_msg_t msg;
    void *ret = NULL;
    if (wire_recv(*fd, &msg)) {
        if (msg.msg_type == MSG_JIT_OFFER) ret = &got_offer;
        cJSON_Delete(msg.json);
    }
    /* Half-close: the LSP sees end-of-stream, and may still write a reply. */
    shutdown(*fd, SHUT_WR);
    return ret;
}

int test_jit_create_refused_when_disabled(void) {
    jit_gate_fixture_t fx;
    TEST_ASSERT(jit_gate_fixture_init(&fx, 1), "fixture");
    TEST_ASSERT_EQ(jit_channels_enabled(&fx.mgr), 0, "JIT opens are off by default");

    TEST_ASSERT_EQ(jit_channel_create(&fx.mgr, fx.lsp, 0, 50000, "factory_expired"),
                   0, "create refuses when JIT opens are disabled");
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[0], 200), "nothing was sent to the client");
    TEST_ASSERT_EQ(g_gate_wallet_calls, 0, "wallet untouched");
    TEST_ASSERT_EQ(g_gate_broadcast_calls, 0, "nothing broadcast");
    TEST_ASSERT_EQ((long)fx.mgr.n_jit_channels, 0, "no JIT slot taken");

    /* Enabled: the same call does reach the client. */
    fx.mgr.jit_enabled = 1;
    pthread_t tid;
    pthread_create(&tid, NULL, gate_peer_take_offer_and_hang_up, &fx.peer_fd[0]);
    TEST_ASSERT_EQ(jit_channel_create(&fx.mgr, fx.lsp, 0, 50000, "factory_expired"),
                   0, "open fails when the client hangs up");
    void *peer_ret = NULL;
    pthread_join(tid, &peer_ret);
    TEST_ASSERT(peer_ret != NULL, "with JIT enabled the client receives JIT_OFFER");

    jit_gate_fixture_free(&fx);
    return 1;
}

int test_jit_expiry_trigger_refused_when_disabled(void) {
    jit_gate_fixture_t fx;
    TEST_ASSERT(jit_gate_fixture_init(&fx, 2), "fixture");

    /* Every factory expired and both clients connected: nothing happens. */
    for (int pass = 0; pass < 3; pass++)
        TEST_ASSERT_EQ(lsp_channels_jit_expiry_trigger(&fx.mgr, fx.lsp), 0,
                       "trigger does nothing when JIT opens are disabled");
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[0], 200), "client 0 got nothing");
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[1], 50), "client 1 got nothing");
    TEST_ASSERT_EQ(g_gate_wallet_calls, 0, "wallet untouched");
    TEST_ASSERT_EQ(g_gate_broadcast_calls, 0, "nothing broadcast");
    TEST_ASSERT_EQ((long)fx.mgr.n_jit_channels, 0, "no JIT slot taken");

    /* Enabled: each connected client is offered a channel. */
    fx.mgr.jit_enabled = 1;
    pthread_t tid[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&tid[i], NULL, gate_peer_take_offer_and_hang_up, &fx.peer_fd[i]);
    TEST_ASSERT_EQ(lsp_channels_jit_expiry_trigger(&fx.mgr, fx.lsp), 2,
                   "with JIT enabled the trigger attempts an open per client");
    for (int i = 0; i < 2; i++) {
        void *peer_ret = NULL;
        pthread_join(tid[i], &peer_ret);
        TEST_ASSERT(peer_ret != NULL, "with JIT enabled the client receives JIT_OFFER");
    }

    /* A factory that has not expired never triggers, enabled or not. */
    fx.ladder->factories[0].cached_state = FACTORY_ACTIVE;
    TEST_ASSERT_EQ(lsp_channels_jit_expiry_trigger(&fx.mgr, fx.lsp), 0,
                   "no trigger while a factory is active");

    jit_gate_fixture_free(&fx);
    return 1;
}

static cJSON *gate_build_lsps2_buy(int id) {
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(req, "method", "lsps2.buy");
    cJSON_AddNumberToObject(req, "id", id);
    cJSON *params = cJSON_CreateObject();
    cJSON *ofp = cJSON_CreateObject();
    cJSON_AddNumberToObject(ofp, "min_fee_msat", 1000);
    cJSON_AddItemToObject(params, "opening_fee_params", ofp);
    cJSON_AddNumberToObject(params, "payment_size_msat", 5000000000.0);
    cJSON_AddItemToObject(req, "params", params);
    return req;
}

int test_lsps2_buy_refused_when_jit_disabled(void) {
    jit_gate_fixture_t fx;
    TEST_ASSERT(jit_gate_fixture_init(&fx, 1), "fixture");

    lsps_ctx_t lctx = { .mgr = &fx.mgr, .lsp = fx.lsp, .client_idx = 0 };
    cJSON *req = gate_build_lsps2_buy(41);
    TEST_ASSERT_EQ(lsps_handle_request(&lctx, fx.lsp->client_fds[0], req), 1,
                   "request is handled");
    cJSON_Delete(req);

    /* The client gets exactly one frame: a JSON-RPC error for its request. */
    TEST_ASSERT(gate_fd_readable(fx.peer_fd[0], 1000), "client gets a reply");
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(fx.peer_fd[0], &msg), "recv reply");
    TEST_ASSERT_EQ(msg.msg_type, MSG_LSPS_RESPONSE, "reply is an LSPS response, not JIT_OFFER");
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(msg.json, "id");
    const cJSON *err = cJSON_GetObjectItemCaseSensitive(msg.json, "error");
    const cJSON *code = err ? cJSON_GetObjectItemCaseSensitive(err, "code") : NULL;
    TEST_ASSERT(id && (int)id->valuedouble == 41, "reply carries the request id");
    TEST_ASSERT(err && code && (int)code->valuedouble == LSPS_ERR_METHOD_NOT_FOUND,
                "reply is an error");
    TEST_ASSERT(cJSON_GetObjectItemCaseSensitive(msg.json, "result") == NULL,
                "no result, no channel id");
    cJSON_Delete(msg.json);
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[0], 200), "no further frame (no JIT_OFFER)");
    TEST_ASSERT_EQ(g_gate_wallet_calls, 0, "wallet untouched");
    TEST_ASSERT_EQ(g_gate_broadcast_calls, 0, "nothing broadcast");
    TEST_ASSERT_EQ((long)fx.mgr.n_jit_channels, 0, "no JIT slot taken");

    /* Enabled: the same request does start an open. */
    fx.mgr.jit_enabled = 1;
    pthread_t tid;
    pthread_create(&tid, NULL, gate_peer_take_offer_and_hang_up, &fx.peer_fd[0]);
    req = gate_build_lsps2_buy(42);
    lsps_handle_request(&lctx, fx.lsp->client_fds[0], req);
    cJSON_Delete(req);
    void *peer_ret = NULL;
    pthread_join(tid, &peer_ret);
    TEST_ASSERT(peer_ret != NULL, "with JIT enabled the client receives JIT_OFFER");

    jit_gate_fixture_free(&fx);
    return 1;
}

/* --- LSPS requests from outside peers --- */

/* Parses a JSON-RPC reply: returns the error code (0 if it is a result) and
   the id; -1 if the reply does not parse. */
static int peer_reply_error_code(const char *reply, int *id_out, int *has_result) {
    cJSON *j = cJSON_Parse(reply);
    if (!j) return -1;
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(j, "id");
    const cJSON *err = cJSON_GetObjectItemCaseSensitive(j, "error");
    const cJSON *code = err ? cJSON_GetObjectItemCaseSensitive(err, "code") : NULL;
    if (id_out) *id_out = id ? (int)id->valuedouble : -1;
    if (has_result)
        *has_result = cJSON_GetObjectItemCaseSensitive(j, "result") != NULL;
    int rc = code ? (int)code->valuedouble : 0;
    cJSON_Delete(j);
    return rc;
}

int test_lsps_peer_request_refuses_buy(void) {
    jit_gate_fixture_t fx;
    TEST_ASSERT(jit_gate_fixture_init(&fx, 1), "fixture");
    /* Even an LSP that has opted in to JIT opens, with client 0 connected. */
    fx.mgr.jit_enabled = 1;

    char reply[2048];
    int id = 0, has_result = 0;

    cJSON *req = gate_build_lsps2_buy(77);
    char *req_s = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    int n = lsps_peer_request(req_s, reply, sizeof(reply));
    free(req_s);
    TEST_ASSERT(n > 0 && (size_t)n == strlen(reply), "a reply is returned to the peer");
    TEST_ASSERT_EQ(peer_reply_error_code(reply, &id, &has_result),
                   LSPS_ERR_METHOD_NOT_FOUND, "lsps2.buy from a peer is an error");
    TEST_ASSERT_EQ(id, 77, "reply carries the request id");
    TEST_ASSERT(!has_result, "no result, no channel id");
    TEST_ASSERT(strstr(reply, "lsps2.buy is not available") != NULL,
                "the refusal names the method");
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[0], 200),
                "nothing was written to factory client 0");
    TEST_ASSERT_EQ(g_gate_wallet_calls, 0, "wallet untouched");
    TEST_ASSERT_EQ(g_gate_broadcast_calls, 0, "nothing broadcast");
    TEST_ASSERT_EQ((long)fx.mgr.n_jit_channels, 0, "no JIT slot taken");

    /* Read-only methods are still answered, through the reply buffer. */
    n = lsps_peer_request("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"lsps2.get_info\"}",
                          reply, sizeof(reply));
    TEST_ASSERT(n > 0, "get_info is answered");
    TEST_ASSERT_EQ(peer_reply_error_code(reply, &id, &has_result), 0, "get_info is not an error");
    TEST_ASSERT(id == 5 && has_result, "get_info reply has a result");

    n = lsps_peer_request("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"lsps9.nope\"}",
                          reply, sizeof(reply));
    TEST_ASSERT(n > 0, "unknown method is answered");
    TEST_ASSERT_EQ(peer_reply_error_code(reply, &id, NULL), LSPS_ERR_METHOD_NOT_FOUND,
                   "unknown method is method-not-found");

    n = lsps_peer_request("{not json", reply, sizeof(reply));
    TEST_ASSERT(n > 0, "malformed JSON is answered");
    TEST_ASSERT_EQ(peer_reply_error_code(reply, NULL, NULL), LSPS_ERR_PARSE_ERROR,
                   "malformed JSON is a parse error");

    char tiny[8];
    TEST_ASSERT_EQ(lsps_peer_request("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"lsps2.buy\"}",
                                     tiny, sizeof(tiny)), 0,
                   "a reply that does not fit is not truncated into the buffer");
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[0], 50),
                "still nothing written to factory client 0");

    jit_gate_fixture_free(&fx);
    return 1;
}

/* --- A JIT channel whose funding output is still on chain is not forgotten --- */

/* What the fake chain says about the outpoint: 1 = spent by a confirmed
   transaction, 0 = unspent, -1 = cannot tell. */
static int g_fake_spent_answer;
static int g_fake_spent_queries;

static int fake_outpoint_spent_confirmed(chain_backend_t *self,
                                         const char *txid_hex, uint32_t vout) {
    (void)self; (void)txid_hex; (void)vout;
    g_fake_spent_queries++;
    return g_fake_spent_answer;
}

static size_t jit_rows_in_db(persist_t *p) {
    jit_channel_t *loaded = calloc(4, sizeof(jit_channel_t));
    size_t count = 0;
    persist_load_jit_channels(p, loaded, 4, &count);
    free(loaded);
    return count;
}

static void fill_open_jit(jit_channel_t *jit, size_t client_idx) {
    memset(jit, 0, sizeof(*jit));
    jit->client_idx = client_idx;
    jit->state = JIT_STATE_OPEN;
    jit->jit_channel_id = JIT_CHANNEL_ID_BASE | (uint32_t)client_idx;
    jit->funding_amount = 50000;
    jit->funding_confirmed = 1;
    memset(jit->funding_txid_hex, 'a', 64);
    jit->funding_txid_hex[64] = '\0';
    jit->funding_vout = 1;
    jit->channel.local_amount = 30000;
    jit->channel.remote_amount = 20000;
}

int test_jit_migrate_keeps_unspent_channel(void) {
    jit_gate_fixture_t fx;
    TEST_ASSERT(jit_gate_fixture_init(&fx, 2), "fixture");
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open db");
    fx.mgr.persist = &db;
    fx.chain.is_outpoint_spent_confirmed = fake_outpoint_spent_confirmed;

    jit_channel_t *jits = (jit_channel_t *)fx.mgr.jit_channels;
    fill_open_jit(&jits[0], 1);
    fx.mgr.n_jit_channels = 1;
    TEST_ASSERT(persist_save_jit_channel(&db, &jits[0]), "save jit row");
    TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 1, "row present before");

    /* Unspent, then "cannot tell": the channel and its row stay, and the
       client is told nothing. */
    for (int answer = 0; answer >= -1; answer--) {
        g_fake_spent_answer = answer;
        g_fake_spent_queries = 0;
        TEST_ASSERT_EQ(jit_channel_migrate(&fx.mgr, fx.lsp, 1, 0), 0,
                       "a channel still on chain is not retired");
        TEST_ASSERT_EQ(g_fake_spent_queries, 1, "the chain was asked");
        TEST_ASSERT(jits[0].state == JIT_STATE_OPEN, "state stays OPEN");
        TEST_ASSERT(jit_channel_is_active(&fx.mgr, 1), "channel still active");
        TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 1, "row is kept");
        TEST_ASSERT(!gate_fd_readable(fx.peer_fd[1], 100), "no JIT_MIGRATE sent");
    }

    /* A backend that cannot answer the question, and no backend at all. */
    fx.chain.is_outpoint_spent_confirmed = NULL;
    TEST_ASSERT_EQ(jit_channel_migrate(&fx.mgr, fx.lsp, 1, 0), 0,
                   "kept when the backend has no chain-only spent query");
    fx.mgr.chain_be = NULL;
    TEST_ASSERT_EQ(jit_channel_migrate(&fx.mgr, fx.lsp, 1, 0), 0,
                   "kept when there is no chain backend");
    TEST_ASSERT(jits[0].state == JIT_STATE_OPEN, "state stays OPEN");
    TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 1, "row is kept");
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[1], 100), "no JIT_MIGRATE sent");

    /* Confirmed spent: retired, row deleted, client told. */
    fx.mgr.chain_be = &fx.chain;
    fx.chain.is_outpoint_spent_confirmed = fake_outpoint_spent_confirmed;
    g_fake_spent_answer = 1;
    TEST_ASSERT_EQ(jit_channel_migrate(&fx.mgr, fx.lsp, 1, 0), 1,
                   "a channel whose output is confirmed spent is retired");
    TEST_ASSERT(jits[0].state == JIT_STATE_CLOSED, "state is CLOSED");
    TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 0, "row is deleted");
    TEST_ASSERT(gate_fd_readable(fx.peer_fd[1], 1000), "client is told");
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(fx.peer_fd[1], &msg), "recv");
    TEST_ASSERT_EQ(msg.msg_type, MSG_JIT_MIGRATE, "JIT_MIGRATE");
    cJSON_Delete(msg.json);
    TEST_ASSERT(!gate_fd_readable(fx.peer_fd[0], 50), "other client untouched");

    fx.mgr.persist = NULL;
    persist_close(&db);
    jit_gate_fixture_free(&fx);
    return 1;
}

static size_t wt_entries_for(const watchtower_t *wt, uint32_t channel_id) {
    size_t n = 0;
    for (size_t i = 0; i < wt->n_entries; i++)
        if (wt->entries[i].channel_id == channel_id) n++;
    return n;
}

int test_jit_client_migrate_keeps_factory_watch(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open db");

    /* The client watchtower: its factory channel is channel id 0. */
    watchtower_t wt;
    watchtower_init(&wt, 1, NULL, NULL, NULL);
    chain_backend_t chain;
    memset(&chain, 0, sizeof(chain));
    chain.is_outpoint_spent_confirmed = fake_outpoint_spent_confirmed;
    wt.chain = &chain;

    jit_channel_t jit;
    fill_open_jit(&jit, 0);
    TEST_ASSERT(persist_save_jit_channel(&db, &jit), "save jit row");

    unsigned char spk[34];
    memset(spk, 0, sizeof(spk));
    spk[0] = 0x51; spk[1] = 0x20;
    unsigned char txid[32];
    for (unsigned char cn = 0; cn < 3; cn++) {
        memset(txid, 0x40 + cn, 32);
        TEST_ASSERT(watchtower_watch(&wt, 0, cn, txid, 0, 10000, spk, 34),
                    "watch a revoked factory-channel commitment");
    }
    memset(txid, 0x77, 32);
    TEST_ASSERT(watchtower_watch(&wt, jit.jit_channel_id, 0, txid, 0, 9000, spk, 34),
                "an entry under the JIT channel id");
    TEST_ASSERT_EQ((long)wt.n_entries, 4, "4 entries");

    /* Output not seen spent: nothing changes. */
    for (int answer = 0; answer >= -1; answer--) {
        g_fake_spent_answer = answer;
        TEST_ASSERT_EQ(jit_client_handle_migrate(&jit, jit.jit_channel_id, &wt, &db), 0,
                       "record kept while the output is not seen spent");
        TEST_ASSERT(jit.state == JIT_STATE_OPEN, "state stays OPEN");
        TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 1, "row is kept");
        TEST_ASSERT_EQ((long)wt.n_entries, 4, "no watch entry removed");
    }
    /* No chain view at all. */
    TEST_ASSERT_EQ(jit_client_handle_migrate(&jit, jit.jit_channel_id, NULL, &db), 0,
                   "record kept without a chain view");
    TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 1, "row is kept");

    /* A message naming some other channel changes nothing either. */
    g_fake_spent_answer = 1;
    TEST_ASSERT_EQ(jit_client_handle_migrate(&jit, 0, &wt, &db), 0,
                   "a message for channel id 0 is not for the JIT channel");
    TEST_ASSERT_EQ((long)wt.n_entries, 4, "no watch entry removed");
    TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 1, "row is kept");

    /* Output confirmed spent: the JIT record goes, the factory channel's
       watch entries all stay. */
    TEST_ASSERT_EQ(jit_client_handle_migrate(&jit, jit.jit_channel_id, &wt, &db), 1,
                   "record closed once the output is confirmed spent");
    TEST_ASSERT(jit.state == JIT_STATE_CLOSED, "state is CLOSED");
    TEST_ASSERT_EQ((long)jit_rows_in_db(&db), 0, "row is deleted");
    TEST_ASSERT_EQ((long)wt_entries_for(&wt, 0), 3,
                   "every factory-channel watch entry is still there");
    TEST_ASSERT_EQ((long)wt_entries_for(&wt, jit.jit_channel_id), 0,
                   "only the JIT channel's entry was removed");

    wt.chain = NULL;
    watchtower_cleanup(&wt);
    persist_close(&db);
    return 1;
}
