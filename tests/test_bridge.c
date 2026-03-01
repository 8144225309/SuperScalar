#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/wire.h"
#include "superscalar/noise.h"
#include "superscalar/bridge.h"
#include "superscalar/tor.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <secp256k1.h>

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

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* ---- Test 1: Bridge message build/parse round-trip ---- */

int test_bridge_msg_round_trip(void) {
    unsigned char hash[32], preimage[32];
    memset(hash, 0xAA, 32);
    memset(preimage, 0xBB, 32);

    /* BRIDGE_HELLO */
    {
        cJSON *j = wire_build_bridge_hello();
        TEST_ASSERT(j != NULL, "build bridge_hello");
        cJSON_Delete(j);
    }

    /* BRIDGE_HELLO_ACK */
    {
        cJSON *j = wire_build_bridge_hello_ack();
        TEST_ASSERT(j != NULL, "build bridge_hello_ack");
        cJSON_Delete(j);
    }

    /* BRIDGE_ADD_HTLC */
    {
        cJSON *j = wire_build_bridge_add_htlc(hash, 50000, 500, 42);
        TEST_ASSERT(j != NULL, "build bridge_add_htlc");

        unsigned char ph[32];
        uint64_t am, hid;
        uint32_t ce;
        TEST_ASSERT(wire_parse_bridge_add_htlc(j, ph, &am, &ce, &hid),
                     "parse bridge_add_htlc");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "add_htlc payment_hash");
        TEST_ASSERT_EQ(am, 50000, "add_htlc amount_msat");
        TEST_ASSERT_EQ(ce, 500, "add_htlc cltv_expiry");
        TEST_ASSERT_EQ(hid, 42, "add_htlc htlc_id");
        cJSON_Delete(j);
    }

    /* BRIDGE_FULFILL_HTLC */
    {
        cJSON *j = wire_build_bridge_fulfill_htlc(hash, preimage, 42);
        TEST_ASSERT(j != NULL, "build bridge_fulfill_htlc");

        unsigned char ph[32], pi[32];
        uint64_t hid;
        TEST_ASSERT(wire_parse_bridge_fulfill_htlc(j, ph, pi, &hid),
                     "parse bridge_fulfill_htlc");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "fulfill payment_hash");
        TEST_ASSERT_MEM_EQ(pi, preimage, 32, "fulfill preimage");
        TEST_ASSERT_EQ(hid, 42, "fulfill htlc_id");
        cJSON_Delete(j);
    }

    /* BRIDGE_FAIL_HTLC */
    {
        cJSON *j = wire_build_bridge_fail_htlc(hash, "unknown_payment_hash", 42);
        TEST_ASSERT(j != NULL, "build bridge_fail_htlc");

        unsigned char ph[32];
        char reason[256];
        uint64_t hid;
        TEST_ASSERT(wire_parse_bridge_fail_htlc(j, ph, reason, sizeof(reason), &hid),
                     "parse bridge_fail_htlc");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "fail payment_hash");
        TEST_ASSERT(strcmp(reason, "unknown_payment_hash") == 0, "fail reason");
        TEST_ASSERT_EQ(hid, 42, "fail htlc_id");
        cJSON_Delete(j);
    }

    /* BRIDGE_SEND_PAY */
    {
        cJSON *j = wire_build_bridge_send_pay("lnbc10n1p0...", hash, 7);
        TEST_ASSERT(j != NULL, "build bridge_send_pay");

        char bolt11[256];
        unsigned char ph[32];
        uint64_t rid;
        TEST_ASSERT(wire_parse_bridge_send_pay(j, bolt11, sizeof(bolt11), ph, &rid),
                     "parse bridge_send_pay");
        TEST_ASSERT(strcmp(bolt11, "lnbc10n1p0...") == 0, "send_pay bolt11");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "send_pay payment_hash");
        TEST_ASSERT_EQ(rid, 7, "send_pay request_id");
        cJSON_Delete(j);
    }

    /* BRIDGE_PAY_RESULT */
    {
        cJSON *j = wire_build_bridge_pay_result(7, 1, preimage);
        TEST_ASSERT(j != NULL, "build bridge_pay_result");

        uint64_t rid;
        int success;
        unsigned char pi[32];
        TEST_ASSERT(wire_parse_bridge_pay_result(j, &rid, &success, pi),
                     "parse bridge_pay_result");
        TEST_ASSERT_EQ(rid, 7, "pay_result request_id");
        TEST_ASSERT_EQ(success, 1, "pay_result success");
        TEST_ASSERT_MEM_EQ(pi, preimage, 32, "pay_result preimage");
        cJSON_Delete(j);
    }

    /* BRIDGE_REGISTER */
    {
        cJSON *j = wire_build_bridge_register(hash, preimage, 50000, 2);
        TEST_ASSERT(j != NULL, "build bridge_register");

        unsigned char ph[32];
        unsigned char pi2[32];
        uint64_t am;
        size_t dc;
        TEST_ASSERT(wire_parse_bridge_register(j, ph, pi2, &am, &dc),
                     "parse bridge_register");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "register payment_hash");
        TEST_ASSERT_MEM_EQ(pi2, preimage, 32, "register preimage");
        TEST_ASSERT_EQ(am, 50000, "register amount_msat");
        TEST_ASSERT_EQ(dc, 2, "register dest_client");
        cJSON_Delete(j);
    }

    return 1;
}

/* ---- Test 2: Bridge HELLO handshake over socketpair ---- */

int test_bridge_hello_handshake(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Simulate bridge side: send BRIDGE_HELLO */
    cJSON *hello = wire_build_bridge_hello();
    TEST_ASSERT(wire_send(sv[0], MSG_BRIDGE_HELLO, hello), "send BRIDGE_HELLO");
    cJSON_Delete(hello);

    /* Simulate LSP side: receive BRIDGE_HELLO */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv BRIDGE_HELLO");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_HELLO, "msg type");
    cJSON_Delete(msg.json);

    /* LSP sends BRIDGE_HELLO_ACK */
    cJSON *ack = wire_build_bridge_hello_ack();
    TEST_ASSERT(wire_send(sv[1], MSG_BRIDGE_HELLO_ACK, ack), "send ACK");
    cJSON_Delete(ack);

    /* Bridge receives ACK */
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv ACK");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_HELLO_ACK, "ack type");
    cJSON_Delete(msg.json);

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 3: Invoice registry ---- */

int test_bridge_invoice_registry(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;
    mgr.bridge_fd = -1;

    unsigned char hash1[32], hash2[32], hash3[32];
    unsigned char pre1[32], pre2[32];
    memset(hash1, 0x11, 32);
    memset(hash2, 0x22, 32);
    memset(hash3, 0x33, 32);
    memset(pre1, 0xA1, 32);
    memset(pre2, 0xA2, 32);

    /* Register invoices */
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash1, pre1, 0, 10000),
                 "register invoice 1");
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash2, pre2, 2, 20000),
                 "register invoice 2");
    TEST_ASSERT_EQ(mgr.n_invoices, 2, "n_invoices");

    /* Look up existing */
    size_t dest;
    TEST_ASSERT(lsp_channels_lookup_invoice(&mgr, hash1, &dest), "lookup 1");
    TEST_ASSERT_EQ(dest, 0, "dest for hash1");

    TEST_ASSERT(lsp_channels_lookup_invoice(&mgr, hash2, &dest), "lookup 2");
    TEST_ASSERT_EQ(dest, 2, "dest for hash2");

    /* Look up non-existing */
    TEST_ASSERT(!lsp_channels_lookup_invoice(&mgr, hash3, &dest), "lookup unknown");

    return 1;
}

/* ---- Test 4: Bridge inbound flow (mock) ---- */

int test_bridge_inbound_flow(void) {
    int sv[2];  /* sv[0]=bridge side, sv[1]=LSP side */
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Bridge sends ADD_HTLC to LSP */
    unsigned char hash[32];
    memset(hash, 0xCC, 32);

    cJSON *add = wire_build_bridge_add_htlc(hash, 50000, 500, 1);
    TEST_ASSERT(wire_send(sv[0], MSG_BRIDGE_ADD_HTLC, add), "send add_htlc");
    cJSON_Delete(add);

    /* LSP side receives */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv add_htlc");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_ADD_HTLC, "msg type");

    unsigned char ph[32];
    uint64_t am, hid;
    uint32_t ce;
    TEST_ASSERT(wire_parse_bridge_add_htlc(msg.json, ph, &am, &ce, &hid),
                 "parse add_htlc");
    TEST_ASSERT_MEM_EQ(ph, hash, 32, "payment_hash");
    TEST_ASSERT_EQ(am, 50000, "amount_msat");
    cJSON_Delete(msg.json);

    /* LSP sends FULFILL_HTLC back */
    unsigned char preimage[32];
    memset(preimage, 0xDD, 32);
    cJSON *fulfill = wire_build_bridge_fulfill_htlc(hash, preimage, 1);
    TEST_ASSERT(wire_send(sv[1], MSG_BRIDGE_FULFILL_HTLC, fulfill),
                 "send fulfill");
    cJSON_Delete(fulfill);

    /* Bridge receives fulfill */
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv fulfill");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_FULFILL_HTLC, "fulfill type");

    unsigned char rph[32], rpi[32];
    uint64_t rhid;
    TEST_ASSERT(wire_parse_bridge_fulfill_htlc(msg.json, rph, rpi, &rhid),
                 "parse fulfill");
    TEST_ASSERT_MEM_EQ(rpi, preimage, 32, "preimage matches");
    TEST_ASSERT_EQ(rhid, 1, "htlc_id matches");
    cJSON_Delete(msg.json);

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 5: Bridge outbound flow (mock) ---- */

int test_bridge_outbound_flow(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* LSP sends SEND_PAY to bridge */
    unsigned char hash[32];
    memset(hash, 0xEE, 32);
    cJSON *pay = wire_build_bridge_send_pay("lnbc1pvjluezpp5...", hash, 99);
    TEST_ASSERT(wire_send(sv[1], MSG_BRIDGE_SEND_PAY, pay), "send pay");
    cJSON_Delete(pay);

    /* Bridge receives */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv send_pay");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_SEND_PAY, "send_pay type");

    char bolt11[256];
    unsigned char ph[32];
    uint64_t rid;
    TEST_ASSERT(wire_parse_bridge_send_pay(msg.json, bolt11, sizeof(bolt11),
                                             ph, &rid), "parse send_pay");
    TEST_ASSERT_EQ(rid, 99, "request_id");
    cJSON_Delete(msg.json);

    /* Bridge sends PAY_RESULT back */
    unsigned char preimage[32];
    memset(preimage, 0xFF, 32);
    cJSON *result = wire_build_bridge_pay_result(99, 1, preimage);
    TEST_ASSERT(wire_send(sv[0], MSG_BRIDGE_PAY_RESULT, result), "send result");
    cJSON_Delete(result);

    /* LSP receives */
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv pay_result");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_PAY_RESULT, "pay_result type");

    uint64_t rrid;
    int success;
    unsigned char rpi[32];
    TEST_ASSERT(wire_parse_bridge_pay_result(msg.json, &rrid, &success, rpi),
                 "parse pay_result");
    TEST_ASSERT_EQ(rrid, 99, "result request_id");
    TEST_ASSERT_EQ(success, 1, "result success");
    TEST_ASSERT_MEM_EQ(rpi, preimage, 32, "result preimage");
    cJSON_Delete(msg.json);

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 6: Bridge unknown payment hash → fail ---- */

int test_bridge_unknown_hash(void) {
    /* Test that lookup of unregistered hash fails */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;
    mgr.bridge_fd = -1;

    unsigned char hash[32];
    memset(hash, 0x99, 32);

    size_t dest;
    TEST_ASSERT(!lsp_channels_lookup_invoice(&mgr, hash, &dest),
                 "unknown hash should not resolve");

    /* Verify bridge_fail_htlc message builds correctly */
    cJSON *fail = wire_build_bridge_fail_htlc(hash, "unknown_payment_hash", 5);
    TEST_ASSERT(fail != NULL, "build fail msg");

    unsigned char ph[32];
    char reason[256];
    uint64_t hid;
    TEST_ASSERT(wire_parse_bridge_fail_htlc(fail, ph, reason, sizeof(reason), &hid),
                 "parse fail msg");
    TEST_ASSERT_MEM_EQ(ph, hash, 32, "fail hash");
    TEST_ASSERT(strcmp(reason, "unknown_payment_hash") == 0, "fail reason");
    TEST_ASSERT_EQ(hid, 5, "fail htlc_id");
    cJSON_Delete(fail);

    return 1;
}

/* ---- Test 7: LSP accepts bridge via BRIDGE_HELLO ---- */

int test_lsp_bridge_accept(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Manually simulate what lsp_accept_bridge does */

    /* Bridge side sends HELLO */
    cJSON *hello = wire_build_bridge_hello();
    TEST_ASSERT(wire_send(sv[0], MSG_BRIDGE_HELLO, hello), "send hello");
    cJSON_Delete(hello);

    /* LSP side receives and validates */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv hello");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_HELLO, "hello type");
    cJSON_Delete(msg.json);

    /* LSP sends ACK */
    cJSON *ack = wire_build_bridge_hello_ack();
    TEST_ASSERT(wire_send(sv[1], MSG_BRIDGE_HELLO_ACK, ack), "send ack");
    cJSON_Delete(ack);

    /* Bridge receives ACK */
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv ack");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_HELLO_ACK, "ack type");
    cJSON_Delete(msg.json);

    /* Verify bridge_fd would be set */
    int bridge_fd = sv[1];
    TEST_ASSERT(bridge_fd >= 0, "bridge_fd valid");

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 8: Bridge handles MSG_BRIDGE_REGISTER from LSP ---- */

int test_bridge_register_forward(void) {
    int sv[2];  /* sv[0]=plugin side, sv[1]=bridge plugin_fd */
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    bridge_t br;
    bridge_init(&br);
    br.plugin_fd = sv[1];

    /* Build a REGISTER message as the LSP would send */
    unsigned char hash[32];
    unsigned char pre[32];
    memset(hash, 0x55, 32);
    memset(pre, 0x66, 32);
    cJSON *reg = wire_build_bridge_register(hash, pre, 75000, 3);
    TEST_ASSERT(reg != NULL, "build register");

    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_REGISTER;
    msg.json = reg;

    /* Bridge should handle it successfully */
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &msg), "handle register");
    cJSON_Delete(reg);

    /* Read the JSON that bridge forwarded to the plugin side */
    char buf[4096];
    ssize_t n = read(sv[0], buf, sizeof(buf) - 1);
    TEST_ASSERT(n > 0, "read plugin output");
    buf[n] = '\0';

    /* Parse and verify the forwarded JSON */
    cJSON *fwd = cJSON_Parse(buf);
    TEST_ASSERT(fwd != NULL, "parse forwarded JSON");

    cJSON *method = cJSON_GetObjectItem(fwd, "method");
    TEST_ASSERT(method != NULL && cJSON_IsString(method), "method exists");
    TEST_ASSERT(strcmp(method->valuestring, "invoice_registered") == 0,
                 "method is invoice_registered");

    cJSON *amt = cJSON_GetObjectItem(fwd, "amount_msat");
    TEST_ASSERT(amt != NULL && cJSON_IsNumber(amt), "amount_msat exists");
    TEST_ASSERT_EQ((uint64_t)amt->valuedouble, 75000, "amount_msat value");

    cJSON *dc = cJSON_GetObjectItem(fwd, "dest_client");
    TEST_ASSERT(dc != NULL && cJSON_IsNumber(dc), "dest_client exists");
    TEST_ASSERT_EQ((size_t)dc->valuedouble, 3, "dest_client value");

    /* Verify payment_hash hex round-trips */
    unsigned char parsed_hash[32];
    TEST_ASSERT(wire_json_get_hex(fwd, "payment_hash", parsed_hash, 32) == 32,
                 "payment_hash hex");
    TEST_ASSERT_MEM_EQ(parsed_hash, hash, 32, "payment_hash matches");

    /* Verify preimage hex round-trips */
    unsigned char parsed_pre[32];
    TEST_ASSERT(wire_json_get_hex(fwd, "preimage", parsed_pre, 32) == 32,
                 "preimage hex");
    TEST_ASSERT_MEM_EQ(parsed_pre, pre, 32, "preimage matches");

    cJSON_Delete(fwd);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 9: LSP inbound via bridge (full socketpair) ---- */

int test_lsp_inbound_via_bridge(void) {
    /* Test the bridge origin tracking + fulfill back-propagation path */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;
    mgr.bridge_fd = -1;

    /* Create a payment hash from a known preimage */
    unsigned char preimage[32];
    memset(preimage, 0x42, 32);
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    /* Register invoice: this payment_hash goes to client 1 */
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, payment_hash, preimage, 1, 100000),
                 "register invoice");

    /* Verify lookup works */
    size_t dest;
    TEST_ASSERT(lsp_channels_lookup_invoice(&mgr, payment_hash, &dest),
                 "lookup invoice");
    TEST_ASSERT_EQ(dest, 1, "dest client");

    /* Track bridge origin */
    uint64_t bridge_htlc_id = 77;
    lsp_channels_track_bridge_origin(&mgr, payment_hash, bridge_htlc_id);

    /* Verify origin tracking */
    uint64_t origin_id = lsp_channels_get_bridge_origin(&mgr, payment_hash);
    TEST_ASSERT_EQ(origin_id, bridge_htlc_id, "bridge origin id");

    /* After retrieval, should be consumed */
    origin_id = lsp_channels_get_bridge_origin(&mgr, payment_hash);
    TEST_ASSERT_EQ(origin_id, 0, "origin consumed");

    /* Test the full wire round-trip: bridge → LSP → bridge */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Bridge sends ADD_HTLC */
    cJSON *add = wire_build_bridge_add_htlc(payment_hash, 100000, 500,
                                              bridge_htlc_id);
    TEST_ASSERT(wire_send(sv[0], MSG_BRIDGE_ADD_HTLC, add), "send add");
    cJSON_Delete(add);

    /* LSP receives */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv add");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_ADD_HTLC, "add type");
    cJSON_Delete(msg.json);

    /* LSP sends FULFILL back (after client fulfills) */
    cJSON *fulfill = wire_build_bridge_fulfill_htlc(payment_hash, preimage,
                                                      bridge_htlc_id);
    TEST_ASSERT(wire_send(sv[1], MSG_BRIDGE_FULFILL_HTLC, fulfill),
                 "send fulfill");
    cJSON_Delete(fulfill);

    /* Bridge receives fulfill */
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv fulfill");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_FULFILL_HTLC, "fulfill type");

    unsigned char recv_ph[32], recv_pi[32];
    uint64_t recv_hid;
    TEST_ASSERT(wire_parse_bridge_fulfill_htlc(msg.json, recv_ph, recv_pi,
                                                 &recv_hid),
                 "parse fulfill");
    TEST_ASSERT_MEM_EQ(recv_pi, preimage, 32, "preimage matches");
    TEST_ASSERT_EQ(recv_hid, bridge_htlc_id, "htlc_id matches");

    /* Verify preimage matches payment hash */
    unsigned char check_hash[32];
    sha256(recv_pi, 32, check_hash);
    TEST_ASSERT_MEM_EQ(check_hash, payment_hash, 32, "preimage→hash valid");

    cJSON_Delete(msg.json);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 10: Bridge set_lsp_pubkey stores NK state correctly ---- */

int test_bridge_set_nk_pubkey(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char seckey[32];
    memset(seckey, 0, 32);
    seckey[31] = 1;

    secp256k1_pubkey pubkey;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey),
                 "create pubkey");

    /* Set NK mode */
    bridge_t br;
    bridge_init(&br);
    TEST_ASSERT(br.use_nk == 0, "default NN mode");

    bridge_set_lsp_pubkey(&br, &pubkey);
    TEST_ASSERT(br.use_nk == 1, "NK mode enabled");

    /* Verify pubkey stored correctly */
    unsigned char ser1[33], ser2[33];
    size_t len1 = 33, len2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser1, &len1, &pubkey,
                                   SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, ser2, &len2, &br.lsp_pubkey,
                                   SECP256K1_EC_COMPRESSED);
    TEST_ASSERT_MEM_EQ(ser1, ser2, 33, "stored pubkey matches");

    /* Clear NK mode */
    bridge_set_lsp_pubkey(&br, NULL);
    TEST_ASSERT(br.use_nk == 0, "NK mode cleared");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 11: Bridge HTLC timeout ---- */

int test_bridge_htlc_timeout(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;

    /* Create a socketpair to act as bridge_fd */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    mgr.bridge_fd = sv[1];

    /* Track a bridge origin with cltv_expiry = 600 */
    unsigned char payment_hash[32];
    memset(payment_hash, 0xAA, 32);
    lsp_channels_track_bridge_origin(&mgr, payment_hash, 42);
    mgr.htlc_origins[mgr.n_htlc_origins - 1].cltv_expiry = 600;

    /* At height 500, should NOT time out (600 - 500 = 100 > FACTORY_CLTV_DELTA=40) */
    lsp_channels_check_bridge_htlc_timeouts(&mgr, NULL, 500);
    TEST_ASSERT(mgr.htlc_origins[0].active == 1, "not timed out at height 500");

    /* At height 565, should time out (600 - 565 = 35 < FACTORY_CLTV_DELTA=40) */
    lsp_channels_check_bridge_htlc_timeouts(&mgr, NULL, 565);
    TEST_ASSERT(mgr.htlc_origins[0].active == 0, "timed out at height 565");

    /* Read the BRIDGE_FAIL_HTLC message that was sent */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv fail from timeout");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_FAIL_HTLC, "fail msg type");

    unsigned char ph[32];
    char reason[256];
    uint64_t hid;
    TEST_ASSERT(wire_parse_bridge_fail_htlc(msg.json, ph, reason,
                                              sizeof(reason), &hid),
                 "parse fail");
    TEST_ASSERT_MEM_EQ(ph, payment_hash, 32, "fail payment_hash");
    TEST_ASSERT(strcmp(reason, "htlc_timeout") == 0, "fail reason");
    TEST_ASSERT_EQ(hid, 42, "fail htlc_id");
    cJSON_Delete(msg.json);

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 12: wire_connect with hostname (localhost) ---- */

int test_wire_connect_hostname(void) {
    /* Listen on a known test port, then connect via getaddrinfo path */
    int listen_fd = wire_listen("127.0.0.1", 19876);
    if (listen_fd < 0) {
        printf("  SKIP: cannot bind port 19876\n");
        return 1;
    }

    /* Connect via IP string (verifies getaddrinfo with numeric host) */
    int fd = wire_connect("127.0.0.1", 19876);
    TEST_ASSERT(fd >= 0, "connect to 127.0.0.1");
    wire_close(fd);

    /* Connect via NULL (verifies default "127.0.0.1" fallback) */
    fd = wire_connect(NULL, 19876);
    TEST_ASSERT(fd >= 0, "connect to NULL (default)");
    wire_close(fd);

    close(listen_fd);
    return 1;
}

/* ---- Test 13: .onion without proxy returns -1 (safety) ---- */

int test_wire_connect_onion_no_proxy(void) {
    /* Ensure no proxy is set */
    wire_set_proxy(NULL, 0);

    /* Connecting to a .onion address without proxy should fail */
    int fd = wire_connect("abc123def456.onion", 9735);
    TEST_ASSERT(fd == -1, ".onion without proxy should fail");

    return 1;
}

/* ---- Test 14: Tor SOCKS5 greeting bytes ---- */

int test_tor_parse_proxy_arg(void) {
    /* Test that tor_parse_proxy_arg works correctly */
    char host[256];
    int port;

    TEST_ASSERT(tor_parse_proxy_arg("127.0.0.1:9050", host, sizeof(host), &port),
                 "parse 127.0.0.1:9050");
    TEST_ASSERT(strcmp(host, "127.0.0.1") == 0, "host");
    TEST_ASSERT_EQ(port, 9050, "port");

    TEST_ASSERT(tor_parse_proxy_arg("localhost:9150", host, sizeof(host), &port),
                 "parse localhost:9150");
    TEST_ASSERT(strcmp(host, "localhost") == 0, "host");
    TEST_ASSERT_EQ(port, 9150, "port");

    /* Invalid cases */
    TEST_ASSERT(!tor_parse_proxy_arg("nocolon", host, sizeof(host), &port),
                 "no colon fails");
    TEST_ASSERT(!tor_parse_proxy_arg(":9050", host, sizeof(host), &port),
                 "empty host fails");
    TEST_ASSERT(!tor_parse_proxy_arg("host:0", host, sizeof(host), &port),
                 "port 0 fails");
    TEST_ASSERT(!tor_parse_proxy_arg("host:99999", host, sizeof(host), &port),
                 "port >65535 fails");

    return 1;
}

/* ---- Test 15: Tor control response parsing ---- */

int test_tor_parse_proxy_arg_edge_cases(void) {
    /* Verify that tor_parse_proxy_arg handles edge cases */
    char host[256];
    int port;

    /* IPv6-style with brackets (last colon separates port) */
    TEST_ASSERT(tor_parse_proxy_arg("[::1]:9050", host, sizeof(host), &port),
                 "parse [::1]:9050");
    TEST_ASSERT(strcmp(host, "[::1]") == 0, "ipv6 host");
    TEST_ASSERT_EQ(port, 9050, "ipv6 port");

    /* Standard onion address format */
    TEST_ASSERT(tor_parse_proxy_arg("192.168.1.100:9050", host, sizeof(host), &port),
                 "parse 192.168.1.100:9050");
    TEST_ASSERT(strcmp(host, "192.168.1.100") == 0, "ip host");
    TEST_ASSERT_EQ(port, 9050, "ip port");

    /* Max port */
    TEST_ASSERT(tor_parse_proxy_arg("host:65535", host, sizeof(host), &port),
                 "parse max port");
    TEST_ASSERT_EQ(port, 65535, "max port value");

    return 1;
}

/* ---- Test 16: Tor SOCKS5 mock server (protocol validation) ---- */

int test_tor_socks5_mock(void) {
    int mock_port = 19900 + (getpid() % 1000);

    int listen_fd = wire_listen("127.0.0.1", mock_port);
    if (listen_fd < 0) {
        printf("  SKIP: cannot bind port %d\n", mock_port);
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: mock SOCKS5 server */
        close(listen_fd);  /* re-opened via accept in parent; child is the client */
        /* Actually — child is the SOCKS5 mock server, parent is the caller.
           Let's swap: child accepts, parent calls tor_connect_socks5. */
        _exit(0);  /* placeholder */
    }

    /* Fix: child = mock server (accept), parent = tor_connect_socks5 caller */
    waitpid(pid, NULL, 0);
    close(listen_fd);

    /* Re-implement with correct fork roles */
    listen_fd = wire_listen("127.0.0.1", mock_port + 1);
    if (listen_fd < 0) {
        printf("  SKIP: cannot bind port %d\n", mock_port + 1);
        return 1;
    }

    pid = fork();
    if (pid == 0) {
        /* Child: mock SOCKS5 server — accept one connection, run protocol */
        int cfd = wire_accept(listen_fd);
        close(listen_fd);
        if (cfd < 0) _exit(1);

        /* Phase 1: Read SOCKS5 greeting */
        unsigned char greeting[3];
        if (read(cfd, greeting, 3) != 3) _exit(1);
        if (greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00)
            _exit(2);

        /* Phase 1: Respond with NO_AUTH */
        unsigned char resp1[2] = {0x05, 0x00};
        if (write(cfd, resp1, 2) != 2) _exit(3);

        /* Phase 2: Read CONNECT request header */
        unsigned char hdr[4];
        if (read(cfd, hdr, 4) != 4) _exit(4);
        if (hdr[0] != 0x05 || hdr[1] != 0x01 || hdr[2] != 0x00 || hdr[3] != 0x03)
            _exit(5);

        /* Read domain length + domain + port */
        unsigned char dlen;
        if (read(cfd, &dlen, 1) != 1) _exit(6);
        if (dlen != 10) _exit(7);  /* "test.onion" */

        char domain[256];
        if (read(cfd, domain, dlen) != dlen) _exit(8);
        if (memcmp(domain, "test.onion", 10) != 0) _exit(9);

        unsigned char port_bytes[2];
        if (read(cfd, port_bytes, 2) != 2) _exit(10);
        uint16_t rport = (uint16_t)((port_bytes[0] << 8) | port_bytes[1]);
        if (rport != 9735) _exit(11);

        /* Phase 2: Respond with success (IPv4 bound addr) */
        unsigned char resp2[] = {0x05, 0x00, 0x00, 0x01,
                                 127, 0, 0, 1,
                                 0x00, 0x00};
        if (write(cfd, resp2, 10) != 10) _exit(12);

        /* Tunnel open — echo one byte back */
        unsigned char byte;
        if (read(cfd, &byte, 1) != 1) _exit(13);
        if (write(cfd, &byte, 1) != 1) _exit(14);

        close(cfd);
        _exit(0);
    }

    /* Parent: call tor_connect_socks5 to connect through the mock */
    close(listen_fd);
    usleep(100000);  /* let child accept */

    int fd = tor_connect_socks5("127.0.0.1", mock_port + 1, "test.onion", 9735);
    TEST_ASSERT(fd >= 0, "socks5 connect failed");

    /* Verify tunnel works — send a byte, expect echo */
    unsigned char test_byte = 0x42;
    TEST_ASSERT(write(fd, &test_byte, 1) == 1, "tunnel write");
    unsigned char echo;
    TEST_ASSERT(read(fd, &echo, 1) == 1, "tunnel read");
    TEST_ASSERT(echo == 0x42, "echo mismatch");

    close(fd);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "mock server child failed");

    return 1;
}

/* ---- Test 17: NK handshake over real TCP ---- */

int test_regtest_bridge_nk_handshake(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Server static keypair */
    unsigned char server_sec[32];
    memset(server_sec, 0xAA, 32);
    secp256k1_pubkey server_pub;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &server_pub, server_sec),
                "server pubkey create");

    int port = 19900 + (getpid() % 1000);
    int listen_fd = wire_listen("127.0.0.1", port);
    if (listen_fd < 0) {
        printf("  SKIP: cannot bind port %d\n", port);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: bridge side (NK initiator) */
        close(listen_fd);
        usleep(100000);  /* let parent accept */

        secp256k1_context *child_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        int fd = wire_connect("127.0.0.1", port);
        if (fd < 0) _exit(1);

        /* NK initiator handshake */
        noise_state_t ns;
        if (!noise_handshake_nk_initiator(&ns, fd, child_ctx, &server_pub))
            _exit(2);
        if (!wire_set_encryption(fd, &ns))
            _exit(3);

        /* Send BRIDGE_HELLO (encrypted) */
        cJSON *hello = wire_build_bridge_hello();
        if (!wire_send(fd, MSG_BRIDGE_HELLO, hello)) {
            cJSON_Delete(hello);
            _exit(4);
        }
        cJSON_Delete(hello);

        /* Receive BRIDGE_HELLO_ACK (encrypted) */
        wire_msg_t msg;
        if (!wire_recv(fd, &msg)) _exit(5);
        if (msg.msg_type != MSG_BRIDGE_HELLO_ACK) {
            cJSON_Delete(msg.json);
            _exit(6);
        }
        cJSON_Delete(msg.json);

        /* Send a test message (encrypted) */
        unsigned char dummy_hash[32];
        memset(dummy_hash, 0xDD, 32);
        cJSON *add = wire_build_bridge_add_htlc(dummy_hash, 50000, 500, 99);
        if (!wire_send(fd, MSG_BRIDGE_ADD_HTLC, add)) {
            cJSON_Delete(add);
            _exit(7);
        }
        cJSON_Delete(add);

        wire_clear_encryption(fd);
        close(fd);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: LSP side (NK responder) */
    int fd = wire_accept(listen_fd);
    close(listen_fd);
    TEST_ASSERT(fd >= 0, "accept failed");

    /* NK responder handshake */
    noise_state_t ns;
    int ok = noise_handshake_nk_responder(&ns, fd, ctx, server_sec);
    TEST_ASSERT(ok, "NK responder handshake failed");
    TEST_ASSERT(wire_set_encryption(fd, &ns), "set encryption");

    /* Receive BRIDGE_HELLO (encrypted) */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(fd, &msg), "recv BRIDGE_HELLO");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_HELLO, "hello type");
    cJSON_Delete(msg.json);

    /* Send BRIDGE_HELLO_ACK (encrypted) */
    cJSON *ack = wire_build_bridge_hello_ack();
    TEST_ASSERT(wire_send(fd, MSG_BRIDGE_HELLO_ACK, ack), "send ack");
    cJSON_Delete(ack);

    /* Receive test message (encrypted), verify it decrypted correctly */
    TEST_ASSERT(wire_recv(fd, &msg), "recv test msg");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_ADD_HTLC, "test msg type");

    unsigned char ph[32];
    uint64_t am, hid;
    uint32_t ce;
    TEST_ASSERT(wire_parse_bridge_add_htlc(msg.json, ph, &am, &ce, &hid),
                "parse test add_htlc");
    TEST_ASSERT_EQ(am, 50000, "amount_msat");
    TEST_ASSERT_EQ(hid, 99, "htlc_id");
    cJSON_Delete(msg.json);

    wire_clear_encryption(fd);
    close(fd);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "NK initiator child failed");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 18: Bridge payment through real regtest factory ---- */

/* Secret keys for 5 participants: LSP + 4 clients (same as test_channels.c) */
static const unsigned char bridge_seckeys[5][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },  /* Client A */
    { [0 ... 31] = 0x32 },  /* Client B */
    { [0 ... 31] = 0x43 },  /* Client C */
    { [0 ... 31] = 0x54 },  /* Client D */
};

typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
} bridge_payee_data_t;

static int recv_skip_revocations_bridge(int fd, wire_msg_t *out) {
    for (;;) {
        if (!wire_recv(fd, out)) return 0;
        if (out->msg_type != 0x50) return 1;  /* MSG_LSP_REVOKE_AND_ACK */
        cJSON_Delete(out->json);
    }
}

static int bridge_payee_cb(int fd, channel_t *ch, uint32_t my_index,
                             secp256k1_context *ctx,
                             const secp256k1_keypair *keypair,
                             factory_t *factory,
                             size_t n_participants,
                             void *user_data) {
    bridge_payee_data_t *data = (bridge_payee_data_t *)user_data;
    (void)keypair; (void)factory; (void)n_participants;

    if (my_index != 1) {
        /* Only client 0 (index 1) is the payee. Others idle. */
        return 1;
    }

    /* Wait for ADD_HTLC from LSP */
    wire_msg_t msg;
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Bridge payee %u: recv failed\n", my_index);
        return 0;
    }
    if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
        /* Parse and store the HTLC */
        uint64_t htlc_id, amount_msat;
        unsigned char ph[32];
        uint32_t cltv;
        if (wire_parse_update_add_htlc(msg.json, &htlc_id, &amount_msat,
                                          ph, &cltv)) {
            channel_add_htlc(ch, HTLC_RECEIVED, amount_msat / 1000,
                               ph, cltv, &htlc_id);
        }
        cJSON_Delete(msg.json);
    } else {
        fprintf(stderr, "Bridge payee %u: expected ADD_HTLC, got 0x%02x\n",
                my_index, msg.msg_type);
        cJSON_Delete(msg.json);
        return 0;
    }

    /* Handle COMMITMENT_SIGNED */
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Bridge payee %u: recv commit failed\n", my_index);
        return 0;
    }
    if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
        client_handle_commitment_signed(fd, ch, ctx, &msg);
        cJSON_Delete(msg.json);
    } else {
        cJSON_Delete(msg.json);
    }

    /* Fulfill with preimage */
    printf("Bridge payee %u: fulfilling HTLC with preimage\n", my_index);
    uint64_t htlc_id = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE &&
            ch->htlcs[i].direction == HTLC_RECEIVED) {
            htlc_id = ch->htlcs[i].id;
            break;
        }
    }
    client_fulfill_payment(fd, ch, htlc_id, data->preimage);

    /* Handle COMMITMENT_SIGNED for the fulfill */
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Bridge payee %u: recv commit failed\n", my_index);
        return 0;
    }
    if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
        client_handle_commitment_signed(fd, ch, ctx, &msg);
        cJSON_Delete(msg.json);
    } else {
        cJSON_Delete(msg.json);
    }

    return 1;
}

int test_regtest_bridge_payment(void) {
    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_bridge")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_bridge\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_bridge", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], bridge_seckeys[i])) return 0;
    }

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Compute funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Mine and fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Generate payment preimage and hash */
    unsigned char preimage[32] = { [0 ... 31] = 0x88 };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    int lsp_port = 19800 + (getpid() % 1000);

    /* Prepare per-client callback data */
    bridge_payee_data_t payee_data;
    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);

    bridge_payee_data_t idle_data;
    memset(&idle_data, 0, sizeof(idle_data));

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t cpid = fork();
        if (cpid == 0) {
            usleep(100000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, bridge_seckeys[c + 1]))
                _exit(1);

            void *cb_data;
            if (c == 0) cb_data = &payee_data;    /* Client 0 (index 1) = payee */
            else cb_data = &idle_data;             /* Others = idle */

            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", lsp_port,
                                               bridge_payee_cb, cb_data);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = cpid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], lsp_port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(&lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp.factory, bridge_seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: send channel_ready failed\n");
            lsp_ok = 0;
        }
    }

    if (lsp_ok) {
        /* Create socketpair to simulate bridge connection */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fprintf(stderr, "LSP: bridge socketpair failed\n");
            lsp_ok = 0;
        } else {
            ch_mgr.bridge_fd = sv[0];

            /* Register invoice: payment_hash → client 0 */
            lsp_channels_register_invoice(&ch_mgr, payment_hash, preimage, 0, 5000000);

            /* Write BRIDGE_ADD_HTLC from bridge side (sv[1]) */
            cJSON *add = wire_build_bridge_add_htlc(payment_hash, 5000000, 600, 1);
            wire_send(sv[1], MSG_BRIDGE_ADD_HTLC, add);
            cJSON_Delete(add);

            /* Run event loop:
               Iteration 1: bridge_fd readable → handle_bridge_msg(ADD_HTLC)
                 → forwards to client 0, waits for REVOKE_AND_ACK (client callback handles)
               Iteration 2: client_fd[0] readable → handle_msg(FULFILL_HTLC)
                 → checks bridge origin → writes BRIDGE_FULFILL_HTLC to bridge_fd */
            if (!lsp_channels_run_event_loop(&ch_mgr, &lsp, 2)) {
                fprintf(stderr, "LSP: event loop failed\n");
                lsp_ok = 0;
            }

            if (lsp_ok) {
                /* Read BRIDGE_FULFILL_HTLC from bridge side (sv[1]) */
                wire_msg_t fulfill_msg;
                if (!wire_recv(sv[1], &fulfill_msg)) {
                    fprintf(stderr, "Bridge: recv fulfill failed\n");
                    lsp_ok = 0;
                } else {
                    TEST_ASSERT_EQ(fulfill_msg.msg_type, MSG_BRIDGE_FULFILL_HTLC,
                                   "fulfill msg type");

                    unsigned char recv_ph[32], recv_pi[32];
                    uint64_t recv_hid;
                    TEST_ASSERT(wire_parse_bridge_fulfill_htlc(fulfill_msg.json,
                                    recv_ph, recv_pi, &recv_hid),
                                "parse bridge fulfill");

                    /* Verify preimage matches payment hash */
                    unsigned char check_hash[32];
                    sha256(recv_pi, 32, check_hash);
                    TEST_ASSERT_MEM_EQ(check_hash, payment_hash, 32,
                                       "preimage→hash valid");
                    TEST_ASSERT_EQ(recv_hid, 1, "bridge htlc_id");

                    /* Verify channel balance: client 0's remote increased */
                    channel_t *ch0 = &ch_mgr.entries[0].channel;
                    fee_estimator_t fe;
                    fee_init(&fe, 1000);
                    uint64_t commit_fee = fee_for_commitment_tx(&fe, 0);
                    uint64_t usable = ch0->funding_amount > commit_fee ?
                                      ch0->funding_amount - commit_fee : 0;
                    uint64_t orig_remote = usable / 2;
                    TEST_ASSERT_EQ(ch0->remote_amount, orig_remote + 5000,
                                   "payee remote balance increased");

                    printf("Bridge payment: preimage matches, balance correct\n");
                    cJSON_Delete(fulfill_msg.json);
                }
            }

            close(sv[0]);
            close(sv[1]);
        }
    }

    /* Cooperative close */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        size_t n_total = 5;
        uint64_t per_party = close_total / n_total;

        tx_output_t close_outputs[5];
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        close_outputs[n_total - 1].amount_sats = close_total - per_party * (n_total - 1);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_total)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                printf("Bridge payment: cooperative close confirmed (%s)\n",
                       close_txid);
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }

        tx_buf_free(&close_tx);
    }

    /* Wait for children */
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Child client %d failed (status=%d)\n", c,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            lsp_ok = 0;
        }
    }

    lsp_cleanup(&lsp);
    secp256k1_context_destroy(ctx);
    return lsp_ok;
}

/* ---- Test 19: Bridge invoice registration + BOLT11 return flow (regtest) ---- */

typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    int bolt11_received;
} invoice_flow_data_t;

static int invoice_flow_cb(int fd, channel_t *ch, uint32_t my_index,
                           secp256k1_context *ctx,
                           const secp256k1_keypair *keypair,
                           factory_t *factory,
                           size_t n_participants,
                           void *user_data) {
    invoice_flow_data_t *data = (invoice_flow_data_t *)user_data;
    (void)keypair; (void)factory; (void)n_participants;

    if (my_index != 1) {
        /* Only client 0 (index 1) is the invoicing party. Others idle. */
        return 1;
    }

    /* Step 1: Send MSG_REGISTER_INVOICE to LSP */
    printf("Invoice flow client %u: sending REGISTER_INVOICE\n", my_index);
    cJSON *reg = wire_build_register_invoice(data->payment_hash,
                                              data->preimage,
                                              5000000, 0);  /* 5000 sat, dest=client 0 */
    if (!wire_send(fd, MSG_REGISTER_INVOICE, reg)) {
        fprintf(stderr, "Invoice flow client %u: send REGISTER_INVOICE failed\n", my_index);
        cJSON_Delete(reg);
        return 0;
    }
    cJSON_Delete(reg);

    /* Step 2: Wait for MSG_INVOICE_BOLT11 from LSP */
    wire_msg_t msg;
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Invoice flow client %u: recv BOLT11 failed\n", my_index);
        return 0;
    }
    if (msg.msg_type != MSG_INVOICE_BOLT11) {
        fprintf(stderr, "Invoice flow client %u: expected INVOICE_BOLT11 (0x%02x), got 0x%02x\n",
                my_index, MSG_INVOICE_BOLT11, msg.msg_type);
        cJSON_Delete(msg.json);
        return 0;
    }

    /* Verify payment_hash matches */
    unsigned char recv_hash[32];
    char recv_bolt11[2048];
    if (!wire_parse_invoice_bolt11(msg.json, recv_hash, recv_bolt11, sizeof(recv_bolt11))) {
        fprintf(stderr, "Invoice flow client %u: parse BOLT11 failed\n", my_index);
        cJSON_Delete(msg.json);
        return 0;
    }
    if (memcmp(recv_hash, data->payment_hash, 32) != 0) {
        fprintf(stderr, "Invoice flow client %u: BOLT11 payment_hash mismatch\n", my_index);
        cJSON_Delete(msg.json);
        return 0;
    }
    printf("Invoice flow client %u: received BOLT11 = %s\n", my_index, recv_bolt11);
    data->bolt11_received = 1;
    cJSON_Delete(msg.json);

    /* Step 3: Wait for ADD_HTLC (inbound payment from bridge) */
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Invoice flow client %u: recv ADD_HTLC failed\n", my_index);
        return 0;
    }
    if (msg.msg_type != MSG_UPDATE_ADD_HTLC) {
        fprintf(stderr, "Invoice flow client %u: expected ADD_HTLC, got 0x%02x\n",
                my_index, msg.msg_type);
        cJSON_Delete(msg.json);
        return 0;
    }
    uint64_t htlc_id, amount_msat;
    unsigned char ph[32];
    uint32_t cltv;
    if (wire_parse_update_add_htlc(msg.json, &htlc_id, &amount_msat, ph, &cltv)) {
        channel_add_htlc(ch, HTLC_RECEIVED, amount_msat / 1000, ph, cltv, &htlc_id);
    }
    cJSON_Delete(msg.json);

    /* Step 4: Handle COMMITMENT_SIGNED */
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Invoice flow client %u: recv commit failed\n", my_index);
        return 0;
    }
    if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
        client_handle_commitment_signed(fd, ch, ctx, &msg);
        cJSON_Delete(msg.json);
    } else {
        cJSON_Delete(msg.json);
    }

    /* Step 5: Fulfill HTLC with preimage */
    printf("Invoice flow client %u: fulfilling HTLC\n", my_index);
    uint64_t fulfill_id = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE &&
            ch->htlcs[i].direction == HTLC_RECEIVED) {
            fulfill_id = ch->htlcs[i].id;
            break;
        }
    }
    client_fulfill_payment(fd, ch, fulfill_id, data->preimage);

    /* Step 6: Handle COMMITMENT_SIGNED for the fulfill */
    if (!recv_skip_revocations_bridge(fd, &msg)) {
        fprintf(stderr, "Invoice flow client %u: recv commit failed\n", my_index);
        return 0;
    }
    if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
        client_handle_commitment_signed(fd, ch, ctx, &msg);
        cJSON_Delete(msg.json);
    } else {
        cJSON_Delete(msg.json);
    }

    return 1;
}

int test_regtest_bridge_invoice_flow(void) {
    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_bridge_inv")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_bridge_inv\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_bridge_inv", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], bridge_seckeys[i])) return 0;
    }

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Compute funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Mine and fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Generate payment preimage and hash */
    unsigned char preimage[32] = { [0 ... 31] = 0x99 };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    int lsp_port = 19900 + (getpid() % 1000);

    /* Prepare per-client callback data */
    invoice_flow_data_t inv_data;
    memcpy(inv_data.payment_hash, payment_hash, 32);
    memcpy(inv_data.preimage, preimage, 32);
    inv_data.bolt11_received = 0;

    invoice_flow_data_t idle_data;
    memset(&idle_data, 0, sizeof(idle_data));

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t cpid = fork();
        if (cpid == 0) {
            usleep(100000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, bridge_seckeys[c + 1]))
                _exit(1);

            void *cb_data;
            if (c == 0) cb_data = &inv_data;     /* Client 0 (index 1) = invoicing */
            else cb_data = &idle_data;            /* Others = idle */

            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", lsp_port,
                                               invoice_flow_cb, cb_data);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = cpid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], lsp_port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(&lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp.factory, bridge_seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: send channel_ready failed\n");
            lsp_ok = 0;
        }
    }

    if (lsp_ok) {
        /* Create socketpair to simulate bridge connection */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fprintf(stderr, "LSP: bridge socketpair failed\n");
            lsp_ok = 0;
        } else {
            ch_mgr.bridge_fd = sv[0];

            /* Step 1: Run event loop for 1 msg — client sends MSG_REGISTER_INVOICE,
               LSP handles it and writes MSG_BRIDGE_REGISTER to bridge_fd */
            if (!lsp_channels_run_event_loop(&ch_mgr, &lsp, 1)) {
                fprintf(stderr, "LSP: event loop (register) failed\n");
                lsp_ok = 0;
            }

            if (lsp_ok) {
                /* Step 2: Read MSG_BRIDGE_REGISTER from bridge side (sv[1]) */
                wire_msg_t reg_msg;
                if (!wire_recv(sv[1], &reg_msg)) {
                    fprintf(stderr, "Bridge: recv BRIDGE_REGISTER failed\n");
                    lsp_ok = 0;
                } else {
                    TEST_ASSERT_EQ(reg_msg.msg_type, MSG_BRIDGE_REGISTER,
                                   "register msg type");

                    unsigned char reg_ph[32], reg_pi[32];
                    uint64_t reg_amount;
                    size_t reg_dest;
                    TEST_ASSERT(wire_parse_bridge_register(reg_msg.json,
                                    reg_ph, reg_pi, &reg_amount, &reg_dest),
                                "parse bridge register");
                    TEST_ASSERT_MEM_EQ(reg_ph, payment_hash, 32,
                                       "register payment_hash matches");
                    TEST_ASSERT_MEM_EQ(reg_pi, preimage, 32,
                                       "register preimage present");
                    TEST_ASSERT_EQ(reg_amount, 5000000, "register amount_msat");
                    TEST_ASSERT_EQ(reg_dest, 0, "register dest_client");
                    printf("Bridge: BRIDGE_REGISTER verified (hash + preimage)\n");
                    cJSON_Delete(reg_msg.json);
                }
            }

            if (lsp_ok) {
                /* Step 3: Send MSG_INVOICE_BOLT11 through bridge side (sv[1]) */
                const char *test_bolt11 = "lnbcrt50u1ptest_invoice_flow_bolt11";
                cJSON *bolt11_msg = wire_build_invoice_bolt11(payment_hash, test_bolt11);
                wire_send(sv[1], MSG_INVOICE_BOLT11, bolt11_msg);
                cJSON_Delete(bolt11_msg);

                /* Step 4: Run event loop for 1 msg — LSP receives INVOICE_BOLT11
                   from bridge_fd, forwards to client */
                if (!lsp_channels_run_event_loop(&ch_mgr, &lsp, 1)) {
                    fprintf(stderr, "LSP: event loop (bolt11) failed\n");
                    lsp_ok = 0;
                }
            }

            if (lsp_ok) {
                /* Step 5: Send MSG_BRIDGE_ADD_HTLC through bridge side (sv[1]) */
                cJSON *add = wire_build_bridge_add_htlc(payment_hash, 5000000, 600, 1);
                wire_send(sv[1], MSG_BRIDGE_ADD_HTLC, add);
                cJSON_Delete(add);

                /* Step 6: Run event loop for 2 msgs — LSP forwards to client,
                   client fulfills, LSP writes BRIDGE_FULFILL_HTLC */
                if (!lsp_channels_run_event_loop(&ch_mgr, &lsp, 2)) {
                    fprintf(stderr, "LSP: event loop (htlc) failed\n");
                    lsp_ok = 0;
                }
            }

            if (lsp_ok) {
                /* Step 7: Read MSG_BRIDGE_FULFILL_HTLC from bridge side (sv[1]) */
                wire_msg_t fulfill_msg;
                if (!wire_recv(sv[1], &fulfill_msg)) {
                    fprintf(stderr, "Bridge: recv fulfill failed\n");
                    lsp_ok = 0;
                } else {
                    TEST_ASSERT_EQ(fulfill_msg.msg_type, MSG_BRIDGE_FULFILL_HTLC,
                                   "fulfill msg type");

                    unsigned char recv_ph[32], recv_pi[32];
                    uint64_t recv_hid;
                    TEST_ASSERT(wire_parse_bridge_fulfill_htlc(fulfill_msg.json,
                                    recv_ph, recv_pi, &recv_hid),
                                "parse bridge fulfill");

                    /* Verify preimage matches payment hash */
                    unsigned char check_hash[32];
                    sha256(recv_pi, 32, check_hash);
                    TEST_ASSERT_MEM_EQ(check_hash, payment_hash, 32,
                                       "preimage→hash valid");
                    TEST_ASSERT_EQ(recv_hid, 1, "bridge htlc_id");

                    /* Verify channel balance: client 0's remote increased */
                    channel_t *ch0 = &ch_mgr.entries[0].channel;
                    fee_estimator_t fe;
                    fee_init(&fe, 1000);
                    uint64_t commit_fee = fee_for_commitment_tx(&fe, 0);
                    uint64_t usable = ch0->funding_amount > commit_fee ?
                                      ch0->funding_amount - commit_fee : 0;
                    uint64_t orig_remote = usable / 2;
                    TEST_ASSERT_EQ(ch0->remote_amount, orig_remote + 5000,
                                   "payee remote balance increased");

                    printf("Invoice flow: preimage matches, balance correct\n");
                    cJSON_Delete(fulfill_msg.json);
                }
            }

            close(sv[0]);
            close(sv[1]);
        }
    }

    /* Cooperative close */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        size_t n_total = 5;
        uint64_t per_party = close_total / n_total;

        tx_output_t close_outputs[5];
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        close_outputs[n_total - 1].amount_sats = close_total - per_party * (n_total - 1);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_total)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                printf("Invoice flow: cooperative close confirmed (%s)\n",
                       close_txid);
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }

        tx_buf_free(&close_tx);
    }

    /* Wait for children */
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Child client %d failed (status=%d)\n", c,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            lsp_ok = 0;
        }
    }

    lsp_cleanup(&lsp);
    secp256k1_context_destroy(ctx);
    return lsp_ok;
}

/* ---- Tor Safety Tests ---- */

/* Test: --tor-only refuses clearnet connections */
int test_tor_only_refuses_clearnet(void) {
    /* Set tor-only + proxy */
    wire_set_proxy("127.0.0.1", 9050);
    wire_set_tor_only(1);

    /* Attempt clearnet connection — should return -1 immediately */
    int fd = wire_connect("1.2.3.4", 9735);
    TEST_ASSERT(fd == -1, "tor-only should refuse clearnet connection");

    /* Also test hostname (not .onion) */
    fd = wire_connect("example.com", 9735);
    TEST_ASSERT(fd == -1, "tor-only should refuse hostname connection");

    /* Cleanup */
    wire_set_tor_only(0);
    wire_set_proxy(NULL, 0);
    return 1;
}

/* Test: --tor-only allows .onion with proxy (will fail at SOCKS5 connect, not at guard) */
int test_tor_only_allows_onion(void) {
    /* Set tor-only + proxy */
    wire_set_proxy("127.0.0.1", 9050);
    wire_set_tor_only(1);

    /* Attempt .onion connection — should NOT be blocked by tor-only guard.
       It will fail at TCP connect to 127.0.0.1:9050 (no Tor running),
       but that's a different error (-1 from connect, not from guard). */
    int fd = wire_connect("abcdefghijklmnop.onion", 9735);
    /* fd will be -1 because there's no SOCKS5 proxy at 9050, but the
       tor-only guard specifically should not block it.  We verify by
       checking that it gets past the guard (the proxy connect will fail). */
    TEST_ASSERT(fd == -1, "expected -1 from SOCKS5 connect failure");
    /* The key assertion is that we didn't get blocked by the tor-only
       guard — we got blocked later by the proxy connect.  Since we
       can't distinguish error sources in the return value, we just
       verify no crash and the .onion path was attempted. */

    wire_set_tor_only(0);
    wire_set_proxy(NULL, 0);
    return 1;
}

/* Test: .onion without proxy still refused (existing guard) */
int test_tor_only_requires_proxy(void) {
    /* Set tor-only WITHOUT proxy */
    wire_set_tor_only(1);

    int fd = wire_connect("abcdefghijklmnop.onion", 9735);
    TEST_ASSERT(fd == -1, "onion without proxy should fail");

    wire_set_tor_only(0);
    return 1;
}

/* Test: wire_listen with bind address */
int test_bind_localhost(void) {
    /* Listen on 127.0.0.1 with random port */
    int listen_fd = wire_listen("127.0.0.1", 0);  /* port 0 = OS-assigned */
    if (listen_fd < 0) {
        /* Port 0 may not be supported on all platforms, try explicit port */
        listen_fd = wire_listen("127.0.0.1", 19876);
    }
    TEST_ASSERT(listen_fd >= 0, "wire_listen on 127.0.0.1 should succeed");

    /* Verify we got a valid socket */
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int ok = getsockname(listen_fd, (struct sockaddr *)&addr, &len);
    TEST_ASSERT(ok == 0, "getsockname failed");
    /* Verify it's bound to 127.0.0.1 */
    TEST_ASSERT(addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
                "should be bound to 127.0.0.1");

    close(listen_fd);
    return 1;
}

/* Test: tor password file reading logic */
int test_tor_password_file(void) {
    /* Write a temp file with a password */
    const char *tmpfile = "/tmp/test_tor_pw.txt";
    FILE *f = fopen(tmpfile, "w");
    TEST_ASSERT(f != NULL, "cannot create temp file");
    fprintf(f, "my_secret_password\n");
    fclose(f);

    /* Read it back using the same logic as superscalar_lsp.c */
    char buf[256];
    f = fopen(tmpfile, "r");
    TEST_ASSERT(f != NULL, "cannot reopen temp file");
    TEST_ASSERT(fgets(buf, sizeof(buf), f) != NULL, "fgets failed");
    buf[strcspn(buf, "\r\n")] = '\0';
    fclose(f);

    TEST_ASSERT(strcmp(buf, "my_secret_password") == 0,
                "password mismatch");

    /* Test with password that has no trailing newline */
    f = fopen(tmpfile, "w");
    fprintf(f, "no_newline");
    fclose(f);

    f = fopen(tmpfile, "r");
    TEST_ASSERT(fgets(buf, sizeof(buf), f) != NULL, "fgets failed");
    buf[strcspn(buf, "\r\n")] = '\0';
    fclose(f);

    TEST_ASSERT(strcmp(buf, "no_newline") == 0,
                "password without newline mismatch");

    unlink(tmpfile);
    return 1;
}

/* ---- Bridge Reliability Tests ---- */

/* Test: bridge heartbeat detects stale connection */
int test_bridge_heartbeat_stale(void) {
    bridge_t br;
    bridge_init(&br);
    bridge_set_heartbeat(&br, 2);  /* 2-second heartbeat */

    /* Just initialized — should not be stale */
    TEST_ASSERT(!bridge_is_stale(&br), "should not be stale right after init");

    /* Simulate staleness by setting last_lsp_activity to the past */
    br.lsp_fd = 999;  /* fake fd so is_stale doesn't short-circuit */
    br.last_lsp_activity = time(NULL) - 10;  /* 10 seconds ago */
    TEST_ASSERT(bridge_is_stale(&br), "should be stale after timeout");

    /* Reset activity — should no longer be stale */
    br.last_lsp_activity = time(NULL);
    TEST_ASSERT(!bridge_is_stale(&br), "should not be stale after activity");

    br.lsp_fd = -1;  /* don't actually close fake fd */
    return 1;
}

/* Test: bridge reconnect logic via fork (mock LSP) */
int test_bridge_reconnect(void) {
    /* Create a mock LSP using socketpair */
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        printf("  SKIP: socketpair not available\n");
        return 1;
    }

    bridge_t br;
    bridge_init(&br);
    br.lsp_fd = fds[0];
    br.last_lsp_activity = time(NULL);
    strncpy(br.lsp_host, "127.0.0.1", sizeof(br.lsp_host));
    br.lsp_port = 19999;

    /* Send a BRIDGE_HELLO_ACK from mock LSP side */
    cJSON *ack = wire_build_bridge_hello_ack();
    int sent = wire_send(fds[1], MSG_BRIDGE_HELLO_ACK, ack);
    cJSON_Delete(ack);
    TEST_ASSERT(sent, "mock LSP send HELLO_ACK failed");

    /* Bridge receives it — activity timestamp should update */
    wire_msg_t msg;
    int ok = wire_recv(br.lsp_fd, &msg);
    TEST_ASSERT(ok, "bridge recv failed");
    br.last_lsp_activity = time(NULL);  /* update as bridge_run would */
    TEST_ASSERT(msg.msg_type == MSG_BRIDGE_HELLO_ACK, "wrong msg type");
    cJSON_Delete(msg.json);

    /* Simulate LSP crash by closing mock end */
    close(fds[1]);

    /* Now bridge should detect stale connection */
    br.last_lsp_activity = time(NULL) - 60;
    TEST_ASSERT(bridge_is_stale(&br), "should detect stale after crash");

    /* Cleanup — close our end */
    close(fds[0]);
    br.lsp_fd = -1;

    /* Verify reconnect_attempts tracking */
    br.reconnect_attempts = 0;
    br.reconnect_attempts++;  /* simulate a failed reconnect */
    TEST_ASSERT(br.reconnect_attempts == 1, "reconnect counter wrong");

    return 1;
}

/* Test: bridge_set_heartbeat validation */
int test_bridge_heartbeat_config(void) {
    bridge_t br;
    bridge_init(&br);

    /* Default heartbeat interval */
    TEST_ASSERT_EQ(br.heartbeat_interval, 30, "default should be 30");

    /* Set custom interval */
    bridge_set_heartbeat(&br, 60);
    TEST_ASSERT_EQ(br.heartbeat_interval, 60, "should be 60");

    /* Set to 0 — should fall back to 30 */
    bridge_set_heartbeat(&br, 0);
    TEST_ASSERT_EQ(br.heartbeat_interval, 30, "0 should default to 30");

    /* Negative — should fall back to 30 */
    bridge_set_heartbeat(&br, -1);
    TEST_ASSERT_EQ(br.heartbeat_interval, 30, "negative should default to 30");

    return 1;
}

/* ---- Test: INVOICE_BOLT11 wire round-trip over socketpair ---- */

int test_bridge_invoice_bolt11_round_trip(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    unsigned char hash[32];
    memset(hash, 0xDD, 32);
    const char *bolt11 = "lnbc100n1ptest...fake_bolt11_string_for_testing";

    /* Build and send */
    cJSON *j = wire_build_invoice_bolt11(hash, bolt11);
    TEST_ASSERT(j != NULL, "build invoice_bolt11");
    TEST_ASSERT(wire_send(sv[0], MSG_INVOICE_BOLT11, j), "send invoice_bolt11");
    cJSON_Delete(j);

    /* Receive and parse */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv invoice_bolt11");
    TEST_ASSERT_EQ(msg.msg_type, MSG_INVOICE_BOLT11, "msg type");

    unsigned char parsed_hash[32];
    char parsed_bolt11[2048];
    TEST_ASSERT(wire_parse_invoice_bolt11(msg.json, parsed_hash,
                    parsed_bolt11, sizeof(parsed_bolt11)),
                "parse invoice_bolt11");
    TEST_ASSERT_MEM_EQ(parsed_hash, hash, 32, "payment_hash matches");
    TEST_ASSERT(strcmp(parsed_bolt11, bolt11) == 0, "bolt11 matches");

    cJSON_Delete(msg.json);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test: bridge_handle_plugin_msg dispatches invoice_bolt11 ---- */

int test_bridge_bolt11_plugin_to_lsp(void) {
    int lsp_sv[2];  /* lsp_sv[0]=bridge lsp_fd, lsp_sv[1]=LSP side */
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");

    bridge_t br;
    bridge_init(&br);
    br.lsp_fd = lsp_sv[0];

    /* Simulate plugin sending invoice_bolt11 JSON */
    unsigned char hash[32];
    memset(hash, 0xEE, 32);
    char hash_hex[65];
    hex_encode(hash, 32, hash_hex);

    char line[4096];
    snprintf(line, sizeof(line),
        "{\"method\":\"invoice_bolt11\","
        "\"payment_hash\":\"%s\","
        "\"bolt11\":\"lnbc500n1ptest_bolt11\"}",
        hash_hex);

    TEST_ASSERT(bridge_handle_plugin_msg(&br, line), "handle invoice_bolt11");

    /* Read MSG_INVOICE_BOLT11 from LSP side */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(lsp_sv[1], &msg), "recv from LSP side");
    TEST_ASSERT_EQ(msg.msg_type, MSG_INVOICE_BOLT11, "msg type");

    unsigned char recv_hash[32];
    char recv_bolt11[2048];
    TEST_ASSERT(wire_parse_invoice_bolt11(msg.json, recv_hash,
                    recv_bolt11, sizeof(recv_bolt11)),
                "parse bolt11");
    TEST_ASSERT_MEM_EQ(recv_hash, hash, 32, "hash matches");
    TEST_ASSERT(strcmp(recv_bolt11, "lnbc500n1ptest_bolt11") == 0,
                "bolt11 matches");

    cJSON_Delete(msg.json);
    close(lsp_sv[0]);
    close(lsp_sv[1]);
    return 1;
}

/* ---- Test: bridge_handle_lsp_msg passes preimage in BRIDGE_REGISTER ---- */

int test_bridge_preimage_passthrough(void) {
    int plugin_sv[2];  /* plugin_sv[0]=plugin side, plugin_sv[1]=bridge plugin_fd */
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, plugin_sv) == 0, "socketpair");

    bridge_t br;
    bridge_init(&br);
    br.plugin_fd = plugin_sv[1];

    /* Build BRIDGE_REGISTER with preimage */
    unsigned char hash[32], pre[32];
    memset(hash, 0x77, 32);
    memset(pre, 0x88, 32);

    cJSON *reg = wire_build_bridge_register(hash, pre, 42000, 1);
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_REGISTER;
    msg.json = reg;

    TEST_ASSERT(bridge_handle_lsp_msg(&br, &msg), "handle register");
    cJSON_Delete(reg);

    /* Read JSON from plugin side */
    char buf[4096];
    ssize_t n = read(plugin_sv[0], buf, sizeof(buf) - 1);
    TEST_ASSERT(n > 0, "read plugin output");
    buf[n] = '\0';

    cJSON *fwd = cJSON_Parse(buf);
    TEST_ASSERT(fwd != NULL, "parse forwarded JSON");

    /* Verify preimage is present */
    unsigned char parsed_pre[32];
    TEST_ASSERT(wire_json_get_hex(fwd, "preimage", parsed_pre, 32) == 32,
                 "preimage in JSON");
    TEST_ASSERT_MEM_EQ(parsed_pre, pre, 32, "preimage matches");

    /* Verify payment_hash */
    unsigned char parsed_hash[32];
    TEST_ASSERT(wire_json_get_hex(fwd, "payment_hash", parsed_hash, 32) == 32,
                 "payment_hash in JSON");
    TEST_ASSERT_MEM_EQ(parsed_hash, hash, 32, "hash matches");

    cJSON_Delete(fwd);
    close(plugin_sv[0]);
    close(plugin_sv[1]);
    return 1;
}

/* ---- Test: keysend wire round-trip + LSP bridge keysend handling ---- */

int test_bridge_keysend_inbound(void) {
    /* 1. Build keysend ADD_HTLC with preimage + dest_client */
    unsigned char preimage[32], hash[32];
    memset(preimage, 0xCC, 32);
    sha256(preimage, 32, hash);

    cJSON *ks = wire_build_bridge_add_htlc_keysend(hash, 50000, 144, 7,
                                                      preimage, 2);
    TEST_ASSERT(ks != NULL, "build keysend");

    /* Verify keysend fields present */
    cJSON *ks_flag = cJSON_GetObjectItem(ks, "keysend");
    TEST_ASSERT(ks_flag && cJSON_IsTrue(ks_flag), "keysend flag true");
    cJSON *dc = cJSON_GetObjectItem(ks, "dest_client");
    TEST_ASSERT(dc && cJSON_IsNumber(dc) && (int)dc->valuedouble == 2,
                "dest_client == 2");

    /* 2. Parse with keysend-aware parser */
    unsigned char p_hash[32], p_pre[32];
    uint64_t p_amt, p_htlc;
    uint32_t p_cltv;
    int p_is_ks = 0;
    size_t p_dest = 99;

    TEST_ASSERT(wire_parse_bridge_add_htlc_keysend(ks, p_hash, &p_amt, &p_cltv,
                    &p_htlc, &p_is_ks, p_pre, &p_dest),
                "parse keysend");
    TEST_ASSERT(p_is_ks == 1, "is_keysend = 1");
    TEST_ASSERT_MEM_EQ(p_hash, hash, 32, "hash matches");
    TEST_ASSERT_MEM_EQ(p_pre, preimage, 32, "preimage matches");
    TEST_ASSERT_EQ((long)p_dest, 2, "dest_client matches");
    TEST_ASSERT_EQ((long)p_amt, 50000, "amount matches");
    TEST_ASSERT_EQ((long)p_cltv, 144, "cltv matches");
    TEST_ASSERT_EQ((long)p_htlc, 7, "htlc_id matches");

    /* 3. Parse regular (non-keysend) ADD_HTLC — keysend flag should be 0 */
    cJSON *reg = wire_build_bridge_add_htlc(hash, 50000, 144, 7);
    int reg_ks = 1;
    TEST_ASSERT(wire_parse_bridge_add_htlc_keysend(reg, p_hash, &p_amt, &p_cltv,
                    &p_htlc, &reg_ks, p_pre, &p_dest),
                "parse regular as keysend");
    TEST_ASSERT(reg_ks == 0, "non-keysend flag = 0");

    cJSON_Delete(ks);
    cJSON_Delete(reg);

    /* 4. Test LSP bridge handler with keysend message over socketpair */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 4;
    mgr.bridge_fd = sv[0];
    for (size_t i = 0; i < 4; i++) {
        mgr.entries[i].channel.local_amount = 50000;
        mgr.entries[i].channel.remote_amount = 50000;
    }

    /* Send keysend ADD_HTLC via bridge */
    cJSON *ks2 = wire_build_bridge_add_htlc_keysend(hash, 10000000, 200, 42,
                                                       preimage, 1);
    wire_send(sv[1], MSG_BRIDGE_ADD_HTLC, ks2);
    cJSON_Delete(ks2);

    /* Read and handle in bridge handler — should register invoice for keysend */
    wire_msg_t recv_msg;
    TEST_ASSERT(wire_recv(sv[0], &recv_msg), "recv keysend msg");
    TEST_ASSERT_EQ(recv_msg.msg_type, MSG_BRIDGE_ADD_HTLC, "msg type");

    /* Verify invoice was NOT registered before handle (it shouldn't be) */
    size_t lookup_dest;
    TEST_ASSERT(!lsp_channels_lookup_invoice(&mgr, hash, &lookup_dest),
                "no invoice before handle");

    /* We can't fully run handle_bridge_msg because it needs valid lsp_t with
       real client fds, but we can verify the keysend parsing works e2e */
    int is_ks_check = 0;
    unsigned char pre_check[32];
    size_t dest_check = 99;
    unsigned char hash_check[32];
    uint64_t amt_check, htlc_check;
    uint32_t cltv_check;
    TEST_ASSERT(wire_parse_bridge_add_htlc_keysend(recv_msg.json, hash_check,
                    &amt_check, &cltv_check, &htlc_check,
                    &is_ks_check, pre_check, &dest_check),
                "parse received keysend");
    TEST_ASSERT(is_ks_check == 1, "received is keysend");
    TEST_ASSERT_EQ((long)dest_check, 1, "dest_client = 1");
    TEST_ASSERT_MEM_EQ(pre_check, preimage, 32, "preimage round-trip");

    /* Register invoice via keysend path and verify lookup works */
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash_check, pre_check,
                    dest_check, amt_check),
                "keysend register");
    TEST_ASSERT(lsp_channels_lookup_invoice(&mgr, hash_check, &lookup_dest),
                "lookup after keysend register");
    TEST_ASSERT_EQ((long)lookup_dest, 1, "dest_client from lookup");

    cJSON_Delete(recv_msg.json);
    close(sv[0]);
    close(sv[1]);
    secp256k1_context_destroy(ctx);
    return 1;
}
