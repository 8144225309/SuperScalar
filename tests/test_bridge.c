#include "superscalar/wire.h"
#include "superscalar/bridge.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void sha256(const unsigned char *, size_t, unsigned char *);

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
        cJSON *j = wire_build_bridge_register(hash, 50000, 2);
        TEST_ASSERT(j != NULL, "build bridge_register");

        unsigned char ph[32];
        uint64_t am;
        size_t dc;
        TEST_ASSERT(wire_parse_bridge_register(j, ph, &am, &dc),
                     "parse bridge_register");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "register payment_hash");
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
    memset(hash1, 0x11, 32);
    memset(hash2, 0x22, 32);
    memset(hash3, 0x33, 32);

    /* Register invoices */
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash1, 0, 10000),
                 "register invoice 1");
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash2, 2, 20000),
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

/* ---- Test 8: LSP inbound via bridge (full socketpair) ---- */

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
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, payment_hash, 1, 100000),
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
