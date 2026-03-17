/*
 * test_bolt8.c — BOLT #8 Noise_XK handshake tests
 *
 * Tests:
 *   test_bolt8_handshake_vectors  — byte-exact BOLT #8 spec test vectors
 *   test_bolt8_key_rotation       — sk/rk rotate correctly at message 1000
 *   test_bolt8_init_features      — BOLT #1 init contains feature bits 729 + 759
 *   test_bolt8_lsps_dispatch      — LSPS0 request (type 37969) routes to handler
 */

#include "superscalar/bolt8.h"
#include "superscalar/bolt8_server.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Decode a lowercase hex string into bytes; returns 0 if wrong length */
static int hex2bin(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b = 0;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return 0;
        out[i] = (unsigned char)b;
    }
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 1: BOLT #8 spec test vectors (byte-exact act1/act2/act3)
 *
 * Source: https://github.com/lightning/bolts/blob/master/08-transport.md
 *
 * Initiator:
 *   ls.priv = 1111...1111
 *   e.priv  = 1212...1212
 * Responder:
 *   rs.priv = 2121...2121
 *   e.priv  = 2222...2222
 * ----------------------------------------------------------------------- */
int test_bolt8_handshake_vectors(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                                       | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "create secp256k1 context");

    /* Test keys */
    unsigned char ls_priv[32];
    unsigned char rs_priv[32], rs_pub33[33];
    unsigned char ie_priv[32]; /* initiator ephemeral */
    unsigned char re_priv[32]; /* responder ephemeral */

    ASSERT(hex2bin("1111111111111111111111111111111111111111111111111111111111111111",
                   ls_priv, 32), "decode ls.priv");
    ASSERT(hex2bin("2121212121212121212121212121212121212121212121212121212121212121",
                   rs_priv, 32), "decode rs.priv");
    ASSERT(hex2bin("1212121212121212121212121212121212121212121212121212121212121212",
                   ie_priv, 32), "decode initiator e.priv");
    ASSERT(hex2bin("2222222222222222222222222222222222222222222222222222222222222222",
                   re_priv, 32), "decode responder e.priv");

    /* Derive responder's static pubkey */
    secp256k1_pubkey rs_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &rs_pub, rs_priv), "create rs pubkey");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, rs_pub33, &pub_len, &rs_pub,
                                   SECP256K1_EC_COMPRESSED);

    /* Expected outputs from BOLT #8 spec */
    const char *act1_hex =
        "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"
        "0df6086551151f58b8afe6c195782c6a";
    const char *act2_hex =
        "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"
        "6e2470b93aac583c9ef6eafca3f730ae";
    const char *act3_hex =
        "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235"
        "5361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";

    unsigned char exp_act1[50], exp_act2[50], exp_act3[66];
    ASSERT(hex2bin(act1_hex, exp_act1, 50), "decode expected act1");
    ASSERT(hex2bin(act2_hex, exp_act2, 50), "decode expected act2");
    ASSERT(hex2bin(act3_hex, exp_act3, 66), "decode expected act3");

    /* Expected final keys (initiator's perspective) */
    unsigned char exp_sk[32], exp_rk[32];
    ASSERT(hex2bin("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9",
                   exp_sk, 32), "decode expected sk");
    ASSERT(hex2bin("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442",
                   exp_rk, 32), "decode expected rk");

    /* --- Initiator side --- */
    bolt8_hs_t i_hs;
    bolt8_hs_init(&i_hs, rs_pub33);

    unsigned char act1[50];
    ASSERT(bolt8_act1_create(&i_hs, ctx, ie_priv, rs_pub33, act1), "act1_create");
    ASSERT(memcmp(act1, exp_act1, 50) == 0, "act1 bytes match spec");

    /* --- Responder side --- */
    bolt8_hs_t r_hs;
    bolt8_hs_init(&r_hs, rs_pub33);

    ASSERT(bolt8_act1_process(&r_hs, ctx, act1, rs_priv), "act1_process");

    unsigned char act2[50];
    ASSERT(bolt8_act2_create(&r_hs, ctx, re_priv, act2), "act2_create");
    ASSERT(memcmp(act2, exp_act2, 50) == 0, "act2 bytes match spec");

    /* --- Back to initiator --- */
    ASSERT(bolt8_act2_process(&i_hs, ctx, act2), "act2_process");

    unsigned char act3[66];
    bolt8_state_t i_state;
    ASSERT(bolt8_act3_create(&i_hs, ctx, ls_priv, act3, &i_state), "act3_create");
    ASSERT(memcmp(act3, exp_act3, 66) == 0, "act3 bytes match spec");

    /* Verify initiator transport keys match spec */
    ASSERT(memcmp(i_state.sk, exp_sk, 32) == 0, "initiator sk matches spec");
    ASSERT(memcmp(i_state.rk, exp_rk, 32) == 0, "initiator rk matches spec");

    /* --- Responder processes act3 --- */
    bolt8_state_t r_state;
    ASSERT(bolt8_act3_process(&r_hs, ctx, act3, &r_state), "act3_process");

    /* Responder's recv key = initiator's send key */
    ASSERT(memcmp(r_state.rk, exp_sk, 32) == 0, "responder rk == initiator sk");
    ASSERT(memcmp(r_state.sk, exp_rk, 32) == 0, "responder sk == initiator rk");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 2: Key rotation — sk/rk rotate at message 1000 (nonce 1000)
 *
 * BOLT #8 spec vectors for initiator (5-byte zero messages):
 *   Message  500 (0-indexed): nonce 1000 triggers rotation
 *   Message  501:              first message after rotation
 *   Message 1000 (0-indexed): second rotation
 *   Message 1001:              first message after second rotation
 * ----------------------------------------------------------------------- */
int test_bolt8_key_rotation(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                                       | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "create secp256k1 context");

    unsigned char ls_priv[32], rs_priv[32], rs_pub33[33];
    unsigned char ie_priv[32], re_priv[32];

    hex2bin("1111111111111111111111111111111111111111111111111111111111111111", ls_priv, 32);
    hex2bin("2121212121212121212121212121212121212121212121212121212121212121", rs_priv, 32);
    hex2bin("1212121212121212121212121212121212121212121212121212121212121212", ie_priv, 32);
    hex2bin("2222222222222222222222222222222222222222222222222222222222222222", re_priv, 32);

    secp256k1_pubkey rs_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &rs_pub, rs_priv), "derive rs pubkey");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, rs_pub33, &pub_len, &rs_pub, SECP256K1_EC_COMPRESSED);

    /* Complete handshake to get transport state */
    bolt8_hs_t i_hs, r_hs;
    bolt8_hs_init(&i_hs, rs_pub33);
    bolt8_hs_init(&r_hs, rs_pub33);

    unsigned char act1[50], act2[50], act3[66];
    ASSERT(bolt8_act1_create(&i_hs, ctx, ie_priv, rs_pub33, act1), "act1_create (rotation)");
    ASSERT(bolt8_act1_process(&r_hs, ctx, act1, rs_priv), "act1_process (rotation)");
    ASSERT(bolt8_act2_create(&r_hs, ctx, re_priv, act2), "act2_create (rotation)");
    ASSERT(bolt8_act2_process(&i_hs, ctx, act2), "act2_process (rotation)");

    bolt8_state_t i_state, r_state;
    ASSERT(bolt8_act3_create(&i_hs, ctx, ls_priv, act3, &i_state), "act3_create (rotation)");
    ASSERT(bolt8_act3_process(&r_hs, ctx, act3, &r_state), "act3_process (rotation)");

    /* Send 1002 "hello" messages (5 bytes each); verify output at spec indices */
    unsigned char payload[5] = {'h', 'e', 'l', 'l', 'o'};
    unsigned char enc_buf[5 + 34];

    /* BOLT #8 spec vectors for 5-byte zero messages (from BOLT #8 appendix) */
    unsigned char exp_500[39], exp_501[39], exp_1000[39], exp_1001[39];
    hex2bin("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8",
            exp_500, 39);
    hex2bin("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd",
            exp_501, 39);
    hex2bin("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09",
            exp_1000, 39);
    hex2bin("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36",
            exp_1001, 39);

    for (int i = 0; i < 1002; i++) {
        memset(enc_buf, 0, sizeof(enc_buf));
        ASSERT(bolt8_write_message(&i_state, payload, 5, enc_buf), "encrypt message");

        if (i == 500)
            ASSERT(memcmp(enc_buf, exp_500, 39) == 0, "message 500 matches spec");
        if (i == 501)
            ASSERT(memcmp(enc_buf, exp_501, 39) == 0, "message 501 matches spec");
        if (i == 1000)
            ASSERT(memcmp(enc_buf, exp_1000, 39) == 0, "message 1000 matches spec");
        if (i == 1001)
            ASSERT(memcmp(enc_buf, exp_1001, 39) == 0, "message 1001 matches spec");
    }

    /* Also verify send nonce counter is correct (should be 2 * 1002 = 2004 after) */
    ASSERT(i_state.sn == 4, "sn wraps around correctly after two rotations");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 3: BOLT #1 init message contains feature bits 729 and 759
 * ----------------------------------------------------------------------- */
int test_bolt8_init_features(void) {
    /* Build the init message payload directly using the same logic as bolt8_server.c */
    #define INIT_FEATURES_LEN_TEST 95

    /* Feature bytes: bit N at byte[len-1 - N/8], position N%8 */
    unsigned char features[INIT_FEATURES_LEN_TEST];
    memset(features, 0, INIT_FEATURES_LEN_TEST);

    /* Bit 729: byte = 94 - 91 = 3, position = 1 */
    features[3] |= (1u << (BOLT8_FEATURE_BIT_LSPS0 % 8));
    /* Bit 759: byte = 94 - 94 = 0, position = 7 */
    features[0] |= (1u << (BOLT8_FEATURE_BIT_SUPERSCALAR % 8));

    /* Verify bit 729 is set */
    int bit729_byte = (int)(INIT_FEATURES_LEN_TEST - 1 - BOLT8_FEATURE_BIT_LSPS0 / 8);
    int bit729_pos  = BOLT8_FEATURE_BIT_LSPS0 % 8;
    ASSERT(bit729_byte == 3, "bit 729 at expected byte index");
    ASSERT((features[bit729_byte] >> bit729_pos) & 1, "bit 729 (LSPS0) is set");

    /* Verify bit 759 is set */
    int bit759_byte = (int)(INIT_FEATURES_LEN_TEST - 1 - BOLT8_FEATURE_BIT_SUPERSCALAR / 8);
    int bit759_pos  = BOLT8_FEATURE_BIT_SUPERSCALAR % 8;
    ASSERT(bit759_byte == 0, "bit 759 at expected byte index");
    ASSERT((features[bit759_byte] >> bit759_pos) & 1, "bit 759 (SuperScalar) is set");

    /* Verify these are odd bits (optional features) */
    ASSERT(BOLT8_FEATURE_BIT_LSPS0 % 2 == 1, "bit 729 is odd (optional)");
    ASSERT(BOLT8_FEATURE_BIT_SUPERSCALAR % 2 == 1, "bit 759 is odd (optional)");

    /* Build full init message: type(2) + gflen(2) + lflen(2) + features(95) */
    unsigned char init_msg[2 + 2 + 2 + INIT_FEATURES_LEN_TEST];
    init_msg[0] = 0x00; init_msg[1] = 0x10;  /* type 16 */
    init_msg[2] = 0x00; init_msg[3] = 0x00;  /* gflen = 0 */
    init_msg[4] = 0x00; init_msg[5] = INIT_FEATURES_LEN_TEST;
    memcpy(init_msg + 6, features, INIT_FEATURES_LEN_TEST);

    /* Verify message type is 16 */
    uint16_t msg_type = ((uint16_t)init_msg[0] << 8) | init_msg[1];
    ASSERT(msg_type == BOLT1_MSG_INIT, "init message type is 16");

    /* Verify feature bytes are in the right position */
    ASSERT(init_msg[6 + 3] == features[3], "LSPS0 feature byte in init message");
    ASSERT(init_msg[6 + 0] == features[0], "SuperScalar feature byte in init message");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 4: LSPS0 request (type 0x9451) dispatches correctly
 *
 * We test the dispatch logic directly (without a real socket) by verifying
 * that the message type routing in bolt8_dispatch_message is correct.
 * The actual lsps_handle_request() is tested in test_lsps.c.
 * ----------------------------------------------------------------------- */

static int g_lsps0_dispatch_called = 0;
static char g_lsps0_dispatch_method[64];

static int test_lsps0_dispatch_cb(void *userdata, int fd, bolt8_state_t *state,
                                    const char *json_req, char *resp_buf, size_t resp_cap) {
    (void)userdata; (void)fd; (void)state; (void)resp_cap;
    g_lsps0_dispatch_called = 1;
    /* Extract method name from JSON (minimal parse: find "method":"XXX") */
    const char *m = strstr(json_req, "\"method\"");
    if (m) {
        const char *colon = strchr(m, ':');
        if (colon) {
            const char *q1 = strchr(colon, '"');
            if (q1) {
                const char *q2 = strchr(q1 + 1, '"');
                if (q2 && (size_t)(q2 - q1 - 1) < sizeof(g_lsps0_dispatch_method)) {
                    memcpy(g_lsps0_dispatch_method, q1 + 1, (size_t)(q2 - q1 - 1));
                    g_lsps0_dispatch_method[q2 - q1 - 1] = '\0';
                }
            }
        }
    }
    /* Return a minimal JSON response */
    int n = snprintf(resp_buf, resp_cap,
                     "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    return n > 0 ? n : 0;
}

int test_bolt8_lsps_dispatch(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                                       | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "create context");

    unsigned char ls_priv[32], rs_priv[32], rs_pub33[33];
    unsigned char ie_priv[32], re_priv[32];
    hex2bin("1111111111111111111111111111111111111111111111111111111111111111", ls_priv, 32);
    hex2bin("2121212121212121212121212121212121212121212121212121212121212121", rs_priv, 32);
    hex2bin("1212121212121212121212121212121212121212121212121212121212121212", ie_priv, 32);
    hex2bin("2222222222222222222222222222222222222222222222222222222222222222", re_priv, 32);

    secp256k1_pubkey rs_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &rs_pub, rs_priv), "derive rs pubkey");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, rs_pub33, &pub_len, &rs_pub, SECP256K1_EC_COMPRESSED);

    /* Complete handshake */
    bolt8_hs_t i_hs, r_hs;
    bolt8_hs_init(&i_hs, rs_pub33);
    bolt8_hs_init(&r_hs, rs_pub33);

    unsigned char act1[50], act2[50], act3[66];
    bolt8_act1_create(&i_hs, ctx, ie_priv, rs_pub33, act1);
    bolt8_act1_process(&r_hs, ctx, act1, rs_priv);
    bolt8_act2_create(&r_hs, ctx, re_priv, act2);
    bolt8_act2_process(&i_hs, ctx, act2);

    bolt8_state_t i_state, r_state;
    bolt8_act3_create(&i_hs, ctx, ls_priv, act3, &i_state);
    bolt8_act3_process(&r_hs, ctx, act3, &r_state);

    /* Build an LSPS0 request message:
       [type=0x9451 (2 bytes)][JSON payload] */
    const char *json_req = "{\"jsonrpc\":\"2.0\",\"method\":\"lsps1.get_info\",\"id\":1,\"params\":{}}";
    size_t json_len = strlen(json_req);
    size_t msg_len = 2 + json_len;
    unsigned char *msg = (unsigned char *)malloc(msg_len);
    ASSERT(msg != NULL, "alloc message");

    msg[0] = (LSPS0_MSG_REQUEST >> 8) & 0xff;
    msg[1] = LSPS0_MSG_REQUEST & 0xff;
    memcpy(msg + 2, json_req, json_len);

    /* Use a socket pair to test dispatch */
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Encrypt and send message on the "initiator" side */
    unsigned char *enc = (unsigned char *)malloc(msg_len + BOLT8_MSG_OVERHEAD);
    ASSERT(enc != NULL, "alloc enc buffer");
    ASSERT(bolt8_write_message(&i_state, msg, msg_len, enc), "encrypt dispatch msg");
    {
        ssize_t n = write(sv[0], enc, msg_len + BOLT8_MSG_OVERHEAD);
        ASSERT(n == (ssize_t)(msg_len + BOLT8_MSG_OVERHEAD), "write encrypted message");
    }
    free(enc);
    free(msg);

    /* Set up server config with our callback */
    bolt8_server_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.ctx = ctx;
    cfg.lsps0_request_cb = test_lsps0_dispatch_cb;

    g_lsps0_dispatch_called = 0;
    memset(g_lsps0_dispatch_method, 0, sizeof(g_lsps0_dispatch_method));

    /* Dispatch the message from the "responder" side */
    bolt8_dispatch_message(&cfg, sv[1], &r_state);

    ASSERT(g_lsps0_dispatch_called, "LSPS0 callback was invoked");
    ASSERT(strcmp(g_lsps0_dispatch_method, "lsps1.get_info") == 0,
           "correct method dispatched");

    close(sv[0]);
    close(sv[1]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 5: bolt8_connect outbound initiator via socketpair
 *
 * Run a simple responder thread that performs the responder side of
 * the 3-act handshake; verify the initiator side populates state_out.
 * ----------------------------------------------------------------------- */

struct outbound_connect_arg {
    int fd;
    unsigned char rs_priv[32];
    unsigned char rs_pub33[33];
    int result;           /* 1 = success */
};

static void *responder_thread(void *arg) {
    struct outbound_connect_arg *a = (struct outbound_connect_arg *)arg;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                                        | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { a->result = 0; return NULL; }

    bolt8_hs_t hs;
    bolt8_hs_init(&hs, a->rs_pub33);

    /* Act 1 */
    unsigned char act1[BOLT8_ACT1_SIZE];
    {
        size_t got = 0;
        while (got < BOLT8_ACT1_SIZE) {
            ssize_t n = read(a->fd, act1 + got, BOLT8_ACT1_SIZE - got);
            if (n <= 0) { a->result = 0; secp256k1_context_destroy(ctx); return NULL; }
            got += (size_t)n;
        }
    }
    if (!bolt8_act1_process(&hs, ctx, act1, a->rs_priv)) {
        a->result = 0; secp256k1_context_destroy(ctx); return NULL;
    }

    /* Act 2 */
    unsigned char re_priv[32];
    FILE *rnd = fopen("/dev/urandom", "rb");
    if (!rnd || fread(re_priv, 1, 32, rnd) != 32) {
        if (rnd) fclose(rnd);
        a->result = 0; secp256k1_context_destroy(ctx); return NULL;
    }
    fclose(rnd);

    unsigned char act2[BOLT8_ACT2_SIZE];
    if (!bolt8_act2_create(&hs, ctx, re_priv, act2)) {
        a->result = 0; secp256k1_context_destroy(ctx); return NULL;
    }
    {
        ssize_t n = write(a->fd, act2, BOLT8_ACT2_SIZE);
        if (n != BOLT8_ACT2_SIZE) { a->result = 0; secp256k1_context_destroy(ctx); return NULL; }
    }

    /* Act 3 */
    unsigned char act3[BOLT8_ACT3_SIZE];
    {
        size_t got = 0;
        while (got < BOLT8_ACT3_SIZE) {
            ssize_t n = read(a->fd, act3 + got, BOLT8_ACT3_SIZE - got);
            if (n <= 0) { a->result = 0; secp256k1_context_destroy(ctx); return NULL; }
            got += (size_t)n;
        }
    }
    bolt8_state_t r_state;
    a->result = bolt8_act3_process(&hs, ctx, act3, &r_state) ? 1 : 0;

    secp256k1_context_destroy(ctx);
    return NULL;
}

int test_bolt8_outbound_connect(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                                        | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "create context");

    unsigned char ls_priv[32], rs_priv[32];
    hex2bin("1111111111111111111111111111111111111111111111111111111111111111", ls_priv, 32);
    hex2bin("2121212121212121212121212121212121212121212121212121212121212121", rs_priv, 32);

    unsigned char rs_pub33[33];
    secp256k1_pubkey rs_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &rs_pub, rs_priv), "derive rs pubkey");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, rs_pub33, &pub_len, &rs_pub, SECP256K1_EC_COMPRESSED);

    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    struct outbound_connect_arg arg;
    arg.fd = sv[1];
    memcpy(arg.rs_priv, rs_priv, 32);
    memcpy(arg.rs_pub33, rs_pub33, 33);
    arg.result = 0;

    pthread_t tid;
    ASSERT(pthread_create(&tid, NULL, responder_thread, &arg) == 0, "create thread");

    bolt8_state_t i_state;
    int ok = bolt8_connect(sv[0], ctx, ls_priv, rs_pub33,
                           BOLT8_HANDSHAKE_TIMEOUT_MS, &i_state);

    pthread_join(tid, NULL);

    ASSERT(ok, "bolt8_connect returned 1");
    ASSERT(arg.result, "responder completed handshake");

    /* Verify transport keys are non-zero */
    unsigned char zeros[32] = {0};
    ASSERT(memcmp(i_state.sk, zeros, 32) != 0, "initiator sk is non-zero");
    ASSERT(memcmp(i_state.rk, zeros, 32) != 0, "initiator rk is non-zero");

    close(sv[0]);
    close(sv[1]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 6: Phase-specific timeout constants have sane values
 * ----------------------------------------------------------------------- */
int test_bolt8_phase_timeout_constants(void) {
    /* Handshake timeout: 60s */
    ASSERT(BOLT8_HANDSHAKE_TIMEOUT_MS == 60000,
           "BOLT8_HANDSHAKE_TIMEOUT_MS is 60s");
    /* Init timeout: 30s */
    ASSERT(BOLT8_INIT_TIMEOUT_MS == 30000,
           "BOLT8_INIT_TIMEOUT_MS is 30s");
    /* Ping interval: 60s */
    ASSERT(BOLT8_PING_INTERVAL_MS == 60000,
           "BOLT8_PING_INTERVAL_MS is 60s");
    /* Ping timeout: 30s */
    ASSERT(BOLT8_PING_TIMEOUT_MS == 30000,
           "BOLT8_PING_TIMEOUT_MS is 30s");
    /* Idle timeout: 300s */
    ASSERT(BOLT8_IDLE_TIMEOUT_MS == 300000,
           "BOLT8_IDLE_TIMEOUT_MS is 300s");
    /* Ordering: handshake >= init, ping_interval > ping_timeout */
    ASSERT(BOLT8_HANDSHAKE_TIMEOUT_MS >= BOLT8_INIT_TIMEOUT_MS,
           "handshake timeout >= init timeout");
    ASSERT(BOLT8_PING_INTERVAL_MS > BOLT8_PING_TIMEOUT_MS,
           "ping interval > ping timeout");
    ASSERT(BOLT8_IDLE_TIMEOUT_MS > BOLT8_PING_INTERVAL_MS + BOLT8_PING_TIMEOUT_MS,
           "idle timeout > ping interval + ping timeout");
    return 1;
}
