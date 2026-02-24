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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <cJSON.h>

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

    /* Simulate aging */
    entry.last_message_time -= 200;  /* 200 seconds ago */
    time_t now = time(NULL);
    int is_stale = (now - entry.last_message_time >= JIT_OFFLINE_TIMEOUT_SEC);
    TEST_ASSERT(is_stale, "should be stale after 200s");

    return 1;
}

int test_offline_detection_flag(void) {
    lsp_channel_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.last_message_time = time(NULL) - 200;  /* 200s ago */
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
    secp256k1_ec_pubkey_serialize(ctx, ser1, &l1, &pk, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, ser2, &l2, &pk_out, SECP256K1_EC_COMPRESSED);
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
    secp256k1_ec_pubkey_create(ctx, &pk, seckey);

    cJSON *j = wire_build_jit_accept(3, ctx, &pk);
    TEST_ASSERT(j != NULL, "build jit_accept");

    size_t cidx;
    secp256k1_pubkey pk_out;
    TEST_ASSERT(wire_parse_jit_accept(j, ctx, &cidx, &pk_out), "parse jit_accept");
    TEST_ASSERT_EQ((long)cidx, 3, "client_idx mismatch");

    unsigned char ser1[33], ser2[33];
    size_t l1 = 33, l2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser1, &l1, &pk, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, ser2, &l2, &pk_out, SECP256K1_EC_COMPRESSED);
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
    TEST_ASSERT_EQ(mgr.jit_enabled, 1, "jit should be enabled");

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
    return 1;
}

int test_jit_routing_fallback(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
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
    secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec);
    secp256k1_ec_pubkey_create(ctx, &cli_pk, cli_sec);

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

/* --- Step 7: Migration Tests --- */

int test_jit_migrate_lifecycle(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
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
    mgr.n_jit_channels = 1;

    TEST_ASSERT(jit_channel_is_active(&mgr, 1), "JIT should be active before migrate");

    /* Migrate (no LSP/fd needed for balance accounting test) */
    jit_channel_migrate(&mgr, NULL, 1, 0);

    /* JIT channel should be closed */
    TEST_ASSERT(jits[0].state == JIT_STATE_CLOSED, "JIT should be closed");
    TEST_ASSERT_EQ(jit_channel_is_active(&mgr, 1), 0, "JIT should not be active");

    /* Factory channel should have absorbed JIT balance */
    TEST_ASSERT_EQ((long)mgr.entries[1].channel.local_amount, 45000,
                   "factory local should include JIT local");
    TEST_ASSERT_EQ((long)mgr.entries[1].channel.remote_amount, 43000,
                   "factory remote should include JIT remote");

    jit_channels_cleanup(&mgr);
    return 1;
}

int test_jit_migrate_balance(void) {
    /* Verify balance arithmetic in migration */
    uint64_t factory_local = 100000;
    uint64_t factory_remote = 80000;
    uint64_t jit_local = 15000;
    uint64_t jit_remote = 12000;

    factory_local += jit_local;
    factory_remote += jit_remote;

    TEST_ASSERT_EQ((long)factory_local, 115000, "local sum");
    TEST_ASSERT_EQ((long)factory_remote, 92000, "remote sum");

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

/* Step 1: Watchtower registration on JIT create */
int test_jit_watchtower_registration(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;
    mgr.ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Set up a watchtower */
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    wt.n_channels = 4;
    mgr.watchtower = &wt;

    jit_channels_init(&mgr);

    /* Manually create a JIT channel for client 2 */
    jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
    jits[0].client_idx = 2;
    jits[0].state = JIT_STATE_OPEN;
    jits[0].jit_channel_id = JIT_CHANNEL_ID_BASE | 2;
    mgr.n_jit_channels = 1;

    /* Simulate what jit_channel_create does: register with watchtower */
    size_t wt_idx = mgr.n_channels + jits[0].client_idx;  /* 4+2=6 */
    watchtower_set_channel(&wt, wt_idx, &jits[0].channel);

    TEST_ASSERT_EQ((long)wt_idx, 6, "watchtower index should be 6");
    TEST_ASSERT(wt.channels[6] == &jits[0].channel,
                "watchtower channel[6] should point to JIT channel");
    TEST_ASSERT(wt.n_channels >= 7,
                "watchtower n_channels should be >= 7");

    jit_channels_cleanup(&mgr);
    secp256k1_context_destroy(mgr.ctx);
    return 1;
}

/* Step 1: Watchtower revocation tracking for JIT */
int test_jit_watchtower_revocation(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a real channel for the watchtower to use */
    unsigned char lsp_sec[32], cli_sec[32];
    memset(lsp_sec, 0x55, 32);
    memset(cli_sec, 0x66, 32);
    secp256k1_pubkey lsp_pk, cli_pk;
    secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec);
    secp256k1_ec_pubkey_create(ctx, &cli_pk, cli_sec);

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
    memset(&wt, 0, sizeof(wt));
    wt.n_channels = 8;

    /* Register as JIT watchtower index (e.g. index 5 for client 1 with 4 factory channels) */
    uint32_t wt_chan_id = 5;
    watchtower_set_channel(&wt, wt_chan_id, &ch);

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

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Step 1: Watchtower entries removed on JIT close/migrate */
int test_jit_watchtower_cleanup_on_close(void) {
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    wt.n_channels = 8;

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
        secp256k1_ec_pubkey_create(ctx, rp, rsec);
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
    return 1;
}

/* Step 3: Multiple JIT channels with correct watchtower indices */
int test_jit_multiple_watchtower_indices(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;

    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    wt.n_channels = 4;
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
        watchtower_set_channel(&wt, wt_idx, &jits[i].channel);
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
    return 1;
}

/* Step 4: JIT funding confirmation transition */
int test_jit_funding_confirmation_transition(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;

    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    wt.n_channels = 4;
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
    return 1;
}
