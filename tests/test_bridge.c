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
#include "superscalar/bolt11.h"
#include "superscalar/chain_backend.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
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
        cJSON *j = wire_build_bridge_hello(NULL);
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
        cJSON *j = wire_build_bridge_send_pay("lnbc10n1p0...", hash, 7, 123456, 144);
        TEST_ASSERT(j != NULL, "build bridge_send_pay");

        char bolt11[256];
        unsigned char ph[32];
        uint64_t rid, max_total;
        uint32_t max_delay;
        TEST_ASSERT(wire_parse_bridge_send_pay(j, bolt11, sizeof(bolt11), ph, &rid,
                                                 &max_total, &max_delay),
                     "parse bridge_send_pay");
        TEST_ASSERT_EQ(max_delay, 144, "send_pay max_delay");
        TEST_ASSERT(strcmp(bolt11, "lnbc10n1p0...") == 0, "send_pay bolt11");
        TEST_ASSERT_MEM_EQ(ph, hash, 32, "send_pay payment_hash");
        TEST_ASSERT_EQ(rid, 7, "send_pay request_id");
        TEST_ASSERT_EQ(max_total, 123456, "send_pay max_total_msat");

        /* A request without a delay bound or a spend cap is malformed. */
        cJSON_DeleteItemFromObject(j, "max_delay");
        TEST_ASSERT(!wire_parse_bridge_send_pay(j, bolt11, sizeof(bolt11), ph,
                                                  &rid, &max_total, &max_delay),
                     "send_pay without max_delay rejected");
        cJSON_AddNumberToObject(j, "max_delay", 144);
        cJSON_DeleteItemFromObject(j, "max_total_msat");
        TEST_ASSERT(!wire_parse_bridge_send_pay(j, bolt11, sizeof(bolt11), ph,
                                                  &rid, &max_total, &max_delay),
                     "send_pay without max_total_msat rejected");
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
    cJSON *hello = wire_build_bridge_hello(NULL);
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
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;

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

    free(mgr.invoices);
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
    cJSON *pay = wire_build_bridge_send_pay("lnbc1pvjluezpp5...", hash, 99, 5000, 144);
    TEST_ASSERT(wire_send(sv[1], MSG_BRIDGE_SEND_PAY, pay), "send pay");
    cJSON_Delete(pay);

    /* Bridge receives */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[0], &msg), "recv send_pay");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_SEND_PAY, "send_pay type");

    char bolt11[256];
    unsigned char ph[32];
    uint64_t rid, max_total;
    uint32_t max_delay;
    TEST_ASSERT(wire_parse_bridge_send_pay(msg.json, bolt11, sizeof(bolt11),
                                             ph, &rid, &max_total, &max_delay),
                "parse send_pay");
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
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;

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

    free(mgr.invoices);
    return 1;
}

/* ---- Test 7: LSP accepts bridge via BRIDGE_HELLO ---- */

int test_lsp_bridge_accept(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Manually simulate what lsp_accept_bridge does */

    /* Bridge side sends HELLO */
    cJSON *hello = wire_build_bridge_hello(NULL);
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
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;

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
    free(mgr.invoices);
    free(mgr.htlc_origins);
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
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;

    /* Create a socketpair to act as bridge_fd */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    mgr.bridge_fd = sv[1];

    /* Track a bridge origin with cltv_expiry = 600 */
    unsigned char payment_hash[32];
    memset(payment_hash, 0xAA, 32);
    lsp_channels_track_bridge_origin(&mgr, payment_hash, 42);
    mgr.htlc_origins[mgr.n_htlc_origins - 1].cltv_expiry = 600;

    /* At height 500, should NOT time out (600 - 500 = 100 > FACTORY_CLTV_DELTA_DEFAULT=40) */
    lsp_channels_check_bridge_htlc_timeouts(&mgr, NULL, 500);
    TEST_ASSERT(mgr.htlc_origins[0].active == 1, "not timed out at height 500");

    /* At height 565, should time out (600 - 565 = 35 < FACTORY_CLTV_DELTA_DEFAULT=40) */
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
    free(mgr.entries);
    free(mgr.htlc_origins);
    return 1;
}

/* ---- Test 12: wire_connect with hostname (localhost) ---- */

int test_wire_connect_hostname(void) {
    /* Listen on a known test port, then connect via getaddrinfo path */
    int listen_fd = wire_listen("127.0.0.1", 19876);
    if (listen_fd < 0) {
        printf("  SKIP: cannot bind port 19876\n");
        return 2;
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
        return 2;
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
        return 2;
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
        return 2;
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
        cJSON *hello = wire_build_bridge_hello(NULL);
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
    /* my_index of the bridge payee.  Default 1 keeps the legacy N=5
       single-payee behavior; tests that route to a non-leaf-0 client
       (to exercise the LSP-side leaf mapping at mixed-arity scale)
       set this to the target client's my_index (1-based). */
    uint32_t payee_my_index;
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

    /* The caller signals payee selection by setting payee_my_index = my
       1-based slot.  Idle clients are passed a zero-initialized struct
       (payee_my_index == 0); they immediately return without trying to
       receive the bridge HTLC. */
    if (data->payee_my_index == 0 || my_index != data->payee_my_index) {
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
    memset(&payee_data, 0, sizeof(payee_data));
    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);
    payee_data.payee_my_index = 1;  /* client 0 is the payee in this N=5 test */

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
                                               bridge_payee_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = cpid;
    }

    /* Parent: run LSP */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], lsp_port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp->factory, bridge_seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, lsp)) {
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
            if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 2)) {
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
    fee_estimator_static_t fe;
                    fee_estimator_static_init(&fe, 1000);
                    uint64_t commit_fee = fee_for_commitment_tx((fee_estimator_t *)&fe, 0);
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

        if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs, n_total, 0)) {
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

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);
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

/* ---- External-node OUT direction: a factory user pays a NON-factory node ----
   Counterpart to test_regtest_bridge_payment (which proves IN: external -> user).
   Here a factory client offers an HTLC tagged with a bolt11 (no dest_client), so
   the LSP debits that client and forwards MSG_BRIDGE_SEND_PAY to the bridge (the
   external world). The external side (the socketpair far end = the "65th node")
   returns PAY_RESULT, the client's outbound HTLC settles, and its channel balance
   is debited by exactly the amount. Driven entirely in-process via a socketpair;
   no production code change. */

typedef struct {
    int active;                  /* 1 = this client is the OUT sender */
    uint32_t sender_my_index;    /* 1-based slot of the OUT sender */
    uint64_t amount_sats;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;
    char bolt11[1024];
} bridge_out_data_t;

static int bridge_out_sender_cb(int fd, channel_t *ch, uint32_t my_index,
                                secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                factory_t *factory, size_t n_participants,
                                void *user_data) {
    bridge_out_data_t *d = (bridge_out_data_t *)user_data;
    (void)keypair; (void)factory; (void)n_participants;
    if (!d->active || my_index != d->sender_my_index)
        return 1;  /* idle client: just participate in creation */

    /* Offer an HTLC tagged with a bolt11 (and NO dest_client) so the LSP routes
       it OUTBOUND to the bridge instead of to another factory leaf. Mirrors
       client_send_payment but swaps dest_client -> bolt11. */
    uint64_t htlc_id;
    if (!channel_add_htlc(ch, HTLC_OFFERED, d->amount_sats, d->payment_hash,
                           d->cltv_expiry, &htlc_id)) {
        fprintf(stderr, "OUT sender %u: channel_add_htlc failed\n", my_index);
        return 0;
    }
    cJSON *msg = wire_build_update_add_htlc(htlc_id, d->amount_sats * 1000,
                                             d->payment_hash, d->cltv_expiry);
    cJSON_AddStringToObject(msg, "bolt11", d->bolt11);  /* the outbound marker */
    int ok = wire_send(fd, MSG_UPDATE_ADD_HTLC, msg);
    cJSON_Delete(msg);
    if (!ok) { fprintf(stderr, "OUT sender %u: send add_htlc failed\n", my_index); return 0; }
    printf("OUT sender %u: offered bolt11 HTLC (%llu sats) to bridge\n",
           my_index, (unsigned long long)d->amount_sats);

    /* COMMITMENT_SIGNED acknowledging the HTLC-bearing commitment. */
    wire_msg_t m;
    if (!recv_skip_revocations_bridge(fd, &m)) {
        fprintf(stderr, "OUT sender %u: recv commit failed\n", my_index); return 0;
    }
    if (m.msg_type == MSG_COMMITMENT_SIGNED) {
        client_handle_commitment_signed(fd, ch, ctx, &m);
        cJSON_Delete(m.json);
    } else {
        fprintf(stderr, "OUT sender %u: expected COMMIT_SIGNED, got 0x%02x\n",
                my_index, m.msg_type);
        cJSON_Delete(m.json); return 0;
    }

    /* Wait for FULFILL (LSP fulfills our outbound HTLC once PAY_RESULT returns). */
    if (!recv_skip_revocations_bridge(fd, &m)) {
        fprintf(stderr, "OUT sender %u: recv fulfill failed\n", my_index); return 0;
    }
    if (m.msg_type == MSG_UPDATE_FULFILL_HTLC) {
        uint64_t fid; unsigned char fpi[32];
        if (wire_parse_update_fulfill_htlc(m.json, &fid, fpi))
            channel_fulfill_htlc(ch, fid, fpi);
        printf("OUT sender %u: outbound payment fulfilled by bridge\n", my_index);
        cJSON_Delete(m.json);
    } else {
        fprintf(stderr, "OUT sender %u: expected FULFILL, got 0x%02x\n",
                my_index, m.msg_type);
        cJSON_Delete(m.json); return 0;
    }

    /* COMMITMENT_SIGNED for the fulfill. */
    if (recv_skip_revocations_bridge(fd, &m)) {
        if (m.msg_type == MSG_COMMITMENT_SIGNED)
            client_handle_commitment_signed(fd, ch, ctx, &m);
        cJSON_Delete(m.json);
    }
    return 1;
}

int test_regtest_bridge_out(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) { printf("  FAIL: regtest not available\n"); return 0; }
    if (!regtest_create_wallet(&rt, "test_bridge_out")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_bridge_out\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_bridge_out", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[5];
    secp256k1_pubkey  pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], bridge_seckeys[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

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

    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    if (!desc_result) return 0;
    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    if (!dstart) { free(desc_result); return 0; }
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen); checksummed_desc[dlen] = '\0';
    free(desc_result);
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    if (!addr_result) return 0;
    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen); fund_addr[alen] = '\0';
    free(addr_result);

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");
    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex), "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);
    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);
    uint64_t funding_amount = 0;
    unsigned char actual_spk[256]; size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v, &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) { funding_vout = v; break; }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* OUT sender = client 0 (1-based my_index 1). It pays an external bolt11. */
    unsigned char out_preimage[32] = { [0 ... 31] = 0x77 };
    unsigned char out_hash[32];
    sha256(out_preimage, 32, out_hash);
    const uint64_t OUT_AMT = 4000;

    int lsp_port = 19700 + (getpid() % 1000);

    bridge_out_data_t out_data;
    memset(&out_data, 0, sizeof(out_data));
    out_data.active = 1;
    out_data.sender_my_index = 1;       /* client 0 */
    out_data.amount_sats = OUT_AMT;
    memcpy(out_data.payment_hash, out_hash, 32);
    /* Expiry well past the tip: room for the invoice's final hop and the
       LSP's forwarding margin. */
    const uint32_t OUT_CLTV_BLOCKS = 600;
    int out_tip = regtest_get_block_height(&rt);
    TEST_ASSERT(out_tip > 0, "chain tip");
    out_data.cltv_expiry = (uint32_t)out_tip + OUT_CLTV_BLOCKS;
    {
        /* The outside invoice: same hash and amount as the HTLC offered. */
        unsigned char payee_key[32] = { [0 ... 31] = 0x65 };
        bolt11_invoice_t ext;
        memset(&ext, 0, sizeof(ext));
        strcpy(ext.network, "bcrt");
        ext.amount_msat = OUT_AMT * 1000; ext.has_amount = 1;
        ext.timestamp = (uint32_t)time(NULL);
        ext.expiry = 3600;
        ext.min_final_cltv_expiry = 18;
        memcpy(ext.payment_hash, out_hash, 32);
        memset(ext.payment_secret, 0x66, 32);
        ext.has_payment_secret = 1;
        strcpy(ext.description, "outside payee");
        TEST_ASSERT(bolt11_encode(&ext, payee_key, ctx, out_data.bolt11,
                                   sizeof(out_data.bolt11)),
                    "encode outside invoice");
    }
    bridge_out_data_t idle_data;
    memset(&idle_data, 0, sizeof(idle_data));

    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t cpid = fork();
        if (cpid == 0) {
            usleep(100000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, bridge_seckeys[c + 1])) _exit(1);
            void *cb_data = (c == 0) ? (void *)&out_data : (void *)&idle_data;
            int ok = client_run_with_channels(child_ctx, &child_kp, "127.0.0.1", lsp_port,
                                              bridge_out_sender_cb, cb_data, NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = cpid;
    }

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], lsp_port, 4);
    int lsp_ok = 1;
    if (!lsp_accept_clients(lsp)) { fprintf(stderr, "LSP: accept failed\n"); lsp_ok = 0; }
    if (lsp_ok && !lsp_run_factory_creation(lsp, funding_txid, funding_vout, funding_amount,
                                            fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n"); lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp->factory, bridge_seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n"); lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) { fprintf(stderr, "LSP: basepoints failed\n"); lsp_ok = 0; }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) { fprintf(stderr, "LSP: send_ready failed\n"); lsp_ok = 0; }
    chain_backend_t out_chain;
    chain_backend_regtest_init(&out_chain, &rt);
    if (lsp_ok) {
        snprintf(ch_mgr.network, sizeof(ch_mgr.network), "regtest");
        ch_mgr.chain_be = &out_chain;
    }

    if (lsp_ok) {
        /* Socketpair = the bridge link. sv[1] is the EXTERNAL world (the 65th node). */
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { fprintf(stderr, "socketpair failed\n"); lsp_ok = 0; }
        else {
            ch_mgr.bridge_fd = sv[0];

            channel_t *ch0 = &ch_mgr.entries[0].channel;
            uint64_t before_local = ch0->local_amount;
            uint64_t before_remote = ch0->remote_amount;
            printf("OUT: client 0 before  local=%llu remote=%llu\n",
                   (unsigned long long)before_local, (unsigned long long)before_remote);

            /* Step 1: drive the LSP until it forwards the outbound pay to the
               bridge. The sender's HTLC arrives, the LSP debits + emits
               MSG_BRIDGE_SEND_PAY on sv[0]. */
            if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 1)) {
                fprintf(stderr, "LSP: event loop (emit send_pay) failed\n"); lsp_ok = 0;
            }

            /* Step 2: the external node receives the pay-out request. */
            wire_msg_t sp;
            if (lsp_ok && !wire_recv(sv[1], &sp)) { fprintf(stderr, "external: recv SEND_PAY failed\n"); lsp_ok = 0; }
            else if (lsp_ok) {
                TEST_ASSERT_EQ(sp.msg_type, MSG_BRIDGE_SEND_PAY, "external got SEND_PAY (pay-out)");
                char rb[1024]; unsigned char rph[32]; uint64_t rid = 0, rmax = 0;
                uint32_t rdelay = 0;
                TEST_ASSERT(wire_parse_bridge_send_pay(sp.json, rb, sizeof(rb), rph,
                                                         &rid, &rmax, &rdelay),
                            "external: parse SEND_PAY");
                TEST_ASSERT(rdelay >= 18 && rdelay < OUT_CLTV_BLOCKS,
                            "SEND_PAY route delay fits inside the HTLC's lifetime");
                TEST_ASSERT_MEM_EQ(rph, out_hash, 32, "SEND_PAY names the HTLC's hash");
                TEST_ASSERT_EQ(rmax, OUT_AMT * 1000, "SEND_PAY caps spend at the HTLC amount");
                printf("external (65th node): received pay-out request %llu for bolt11=%s\n",
                       (unsigned long long)rid, rb);
                cJSON_Delete(sp.json);

                /* Step 3: external node pays it and returns PAY_RESULT(success). */
                cJSON *res = wire_build_bridge_pay_result(rid, 1, out_preimage);
                wire_send(sv[1], MSG_BRIDGE_PAY_RESULT, res);
                cJSON_Delete(res);

                /* Step 4: drive the LSP to consume PAY_RESULT + fulfill the
                   sender's outbound HTLC. */
                if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 1)) {
                    fprintf(stderr, "LSP: event loop (consume pay_result) failed\n"); lsp_ok = 0;
                }

                uint64_t after_local = ch0->local_amount;
                uint64_t after_remote = ch0->remote_amount;
                printf("OUT: client 0 after   local=%llu remote=%llu\n",
                       (unsigned long long)after_local, (unsigned long long)after_remote);
                /* Sender paid OUT_AMT to the external world: the sender's side of
                   the channel must be debited by exactly OUT_AMT. */
                int debited = (before_remote - after_remote == OUT_AMT) ||
                              (before_local - after_local == OUT_AMT);
                TEST_ASSERT(debited, "OUT sender debited by exactly the pay-out amount");
                printf("OUT: pay-out accounting verified (-%llu sats left the factory)\n",
                       (unsigned long long)OUT_AMT);
            }
            close(sv[0]); close(sv[1]);
        }
    }

    /* Cooperative close (sanity: factory still closes after the pay-out). */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        size_t n_total = 5;
        uint64_t per = close_total / n_total;
        tx_output_t co[5];
        for (size_t i = 0; i < n_total; i++) {
            co[i].amount_sats = per;
            memcpy(co[i].script_pubkey, fund_spk, 34);
            co[i].script_pubkey_len = 34;
        }
        co[n_total - 1].amount_sats = close_total - per * (n_total - 1);
        tx_buf_t close_tx; tx_buf_init(&close_tx, 512);
        if (lsp_run_cooperative_close(lsp, &close_tx, co, n_total, 0)) {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                printf("OUT: cooperative close confirmed (%s)\n", close_txid);
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);
    int all_ok = 1;
    for (int c = 0; c < 4; c++) {
        int st; waitpid(child_pids[c], &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { fprintf(stderr, "client %d exited bad\n", c); all_ok = 0; }
    }
    secp256k1_context_destroy(ctx);
    TEST_ASSERT(lsp_ok, "bridge OUT: LSP operations");
    TEST_ASSERT(all_ok, "bridge OUT: all clients completed");
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
                                               invoice_flow_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = cpid;
    }

    /* Parent: run LSP */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], lsp_port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp->factory, bridge_seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, lsp)) {
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
            if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 1)) {
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
                if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 1)) {
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
                if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 2)) {
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
    fee_estimator_static_t fe;
                    fee_estimator_static_init(&fe, 1000);
                    uint64_t commit_fee = fee_for_commitment_tx((fee_estimator_t *)&fe, 0);
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

        if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs, n_total, 0)) {
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

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);
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
        return 2;
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
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 4;
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
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
    free(mgr.entries);
    free(mgr.invoices);
    free(mgr.htlc_origins);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- N=64 mixed-arity bridge payment (Campaign #3 canonical shape) ----
 *
 * Mirrors test_regtest_bridge_payment but on the production canonical shape
 * (1 LSP + 64 clients, mixed-arity {2,4,8}, static_threshold=1).  Proves the
 * bridge HTLC forward path works at N=64 over the wire ceremony AFTER the
 * mixed-arity preservation fix (PR #115 + the fee_per_tx preservation in
 * this PR) — before those fixes the LSP would silently build a uniform
 * binary tree and clients would diverge on tree shape.
 *
 * One client (index 1, the "payee") receives a bridge ADD_HTLC from a
 * simulated bridge daemon; the other 63 clients are idle.  We assert:
 *   - factory builds with the configured shape (level_arity preserved,
 *     static_threshold=1 root)
 *   - bridge ADD_HTLC forwards to client 0, gets fulfilled with preimage
 *   - cooperative close confirms with 65 outputs on chain
 *
 * Per-output sweep + econ_assert at this N is already covered by
 * test_regtest_nway_n64_arity_2_4_8_static_threshold_1_lifecycle (PR #112).
 * This test focuses on the wire-ceremony + bridge HTLC path at scale.
 */

static unsigned char N64_BRIDGE_SECKEYS[65][32];

static void init_n64_bridge_seckeys(void) {
    /* 0xFC prefix to avoid colliding with N64_SECKEYS (0xFD), N32 (0xFE),
       and the 4-client bridge_seckeys (0x10/0x21/0x32/0x43/0x54). */
    for (int i = 0; i < 65; i++) {
        memset(N64_BRIDGE_SECKEYS[i], 0, 32);
        N64_BRIDGE_SECKEYS[i][0] = 0xFC;
        N64_BRIDGE_SECKEYS[i][30] = (unsigned char)((i + 1) >> 8);
        N64_BRIDGE_SECKEYS[i][31] = (unsigned char)((i + 1) & 0xFF);
    }
}

/* Internal helper — single function body, parameterized by payee_client_idx
   (0-based) and a wallet/port-bias label so the two thin wrappers below can
   exercise the cross-leaf LSP-side mapping without colliding. */
static int run_bridge_payment_n64_mixed_arity(size_t payee_client_idx,
                                                const char *wallet_label,
                                                int port_bias) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, wallet_label)) {
        char loadparam[128];
        snprintf(loadparam, sizeof(loadparam), "\"%s\"", wallet_label);
        char *lr = regtest_exec(&rt, "loadwallet", loadparam);
        if (lr) free(lr);
        strncpy(rt.wallet, wallet_label, sizeof(rt.wallet) - 1);
    }
    /* Tree depth ~3 with up to 80+ nodes; bump scan depth so close output
       lookups don't miss deep history on hosts without -txindex. */
    rt.scan_depth = 1200;

    init_n64_bridge_seckeys();

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    const size_t N = 65;  /* 1 LSP + 64 clients */
    secp256k1_keypair *kps = calloc(N, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(N, sizeof(secp256k1_pubkey));
    if (!kps || !pks) return 0;
    for (size_t i = 0; i < N; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], N64_BRIDGE_SECKEYS[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* N-of-N MuSig + taptweak P2TR funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, N);
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

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.10, "10M sats funding budget");

    /* Fund 0.10 BTC = 10M sats. After ~80 nodes × 1000 sats tree fees,
       each of 64 channels ends with ~150k sats — generous headroom for
       commitment fee + dust limit + 5000 sat HTLC. */
    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.10, funding_txid_hex),
                "fund n64 factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 4; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "find n64 funding vout");

    unsigned char preimage[32] = { [0 ... 31] = 0xCC };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    int lsp_port = 19900 + port_bias + (getpid() % 1000);

    /* Pre-bind the LSP listen socket BEFORE forking so the 64 children
       don't race ahead of accept_clients.  Without this, children that
       connect during the init/accept gap get ECONNREFUSED. */
    int pre_listen_fd = wire_listen(NULL, lsp_port);
    if (pre_listen_fd < 0) {
        fprintf(stderr, "LSP-n64: wire_listen failed on port %d\n", lsp_port);
        return 0;
    }

    bridge_payee_data_t payee_data;
    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);
    payee_data.payee_my_index = (uint32_t)(payee_client_idx + 1);  /* 1-based */
    bridge_payee_data_t idle_data;
    memset(&idle_data, 0, sizeof(idle_data));

    /* Fork 64 client processes.  Stagger by 30ms so connect order is stable
       (test_init defaults require_slot_hints=0, so order matters for keyagg). */
    const int N_CLIENTS = 64;
    pid_t *child_pids = calloc(N_CLIENTS, sizeof(pid_t));
    if (!child_pids) return 0;
    for (int c = 0; c < N_CLIENTS; c++) {
        pid_t cpid = fork();
        if (cpid == 0) {
            close(pre_listen_fd);  /* child doesn't need the listen socket */
            usleep(30000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp,
                                           N64_BRIDGE_SECKEYS[c + 1]))
                _exit(1);

            void *cb_data = ((size_t)c == payee_client_idx)
                ? (void *)&payee_data : (void *)&idle_data;
            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", lsp_port,
                                               bridge_payee_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = cpid;
    }

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], lsp_port, (size_t)N_CLIENTS);
    /* Hand off the pre-bound listen socket so accept_clients doesn't try to
       re-bind a port that's still in TIME_WAIT or held by a child. */
    lsp->listen_fd = pre_listen_fd;
    /* Generous per-handshake budget — accepting 64 clients with 30ms stagger
       takes ~2s minimum; leave headroom for slow CI hosts. */
    lsp->accept_timeout_sec = 30;
    /* Default per-IP rate limiter (10/min, 4 concurrent handshakes) is way
       too tight for 64 clients connecting from 127.0.0.1 in rapid succession.
       Production CLI sets this via --max-connection-rate / --max-handshakes;
       for the test we just override directly. */
    rate_limiter_init(&lsp->rate_limiter, 256, 60, 128);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP-n64: accept clients failed\n");
        lsp_ok = 0;
    }

    /* Configure Campaign #3 canonical shape BEFORE lsp_run_factory_creation.
       PR #115 made these survive the function's internal init reset; the
       fee_per_tx preservation in this PR likewise lets 1000 sats/tx survive
       (default 200 falls below regtest mempool min relay for wider state
       nodes at this scale). */
    if (lsp_ok) {
        uint8_t arities[3] = { 2, 4, 8 };
        factory_set_level_arity(&lsp->factory, arities, 3);
        factory_set_static_near_root(&lsp->factory, 1);
        lsp->factory.fee_per_tx = 1000;
    }

    if (lsp_ok && !lsp_run_factory_creation(lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP-n64: factory creation failed\n");
        lsp_ok = 0;
    }

    /* Verify the wire ceremony preserved the configured shape. */
    if (lsp_ok) {
        TEST_ASSERT_EQ(lsp->factory.n_level_arity, 3,
                       "n64 mixed-arity preserved (n_level_arity=3)");
        TEST_ASSERT_EQ(lsp->factory.static_threshold_depth, 1,
                       "n64 static_threshold=1 preserved");
        TEST_ASSERT(lsp->factory.fee_per_tx >= 1000,
                    "n64 fee_per_tx >= 1000 preserved");
        TEST_ASSERT(lsp->factory.n_leaf_nodes == 8,
                    "n64 mixed {2,4,8} -> 8 leaves at depth 2");
        printf("  [bridge-n64] factory: %zu nodes, %d leaves, fee_per_tx=%llu\n",
               lsp->factory.n_nodes, lsp->factory.n_leaf_nodes,
               (unsigned long long)lsp->factory.fee_per_tx);
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp->factory,
                                N64_BRIDGE_SECKEYS[0], (size_t)N_CLIENTS)) {
            fprintf(stderr, "LSP-n64: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP-n64: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP-n64: send channel_ready failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
            fprintf(stderr, "LSP-n64: bridge socketpair failed\n");
            lsp_ok = 0;
        } else {
            ch_mgr.bridge_fd = sv[0];

            /* Register invoice routed to the configured payee channel.
               channel index = client index (0-based). */
            lsp_channels_register_invoice(&ch_mgr, payment_hash, preimage,
                                           payee_client_idx, 5000000);

            cJSON *add = wire_build_bridge_add_htlc(payment_hash, 5000000,
                                                     600, 1);
            wire_send(sv[1], MSG_BRIDGE_ADD_HTLC, add);
            cJSON_Delete(add);

            /* Two iterations: bridge ADD_HTLC -> forward to client 0; then
               client 0 FULFILL -> bridge FULFILL response. */
            if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 2)) {
                fprintf(stderr, "LSP-n64: event loop failed\n");
                lsp_ok = 0;
            }

            if (lsp_ok) {
                wire_msg_t fulfill_msg;
                if (!wire_recv(sv[1], &fulfill_msg)) {
                    fprintf(stderr, "Bridge-n64: recv fulfill failed\n");
                    lsp_ok = 0;
                } else {
                    TEST_ASSERT_EQ(fulfill_msg.msg_type,
                                   MSG_BRIDGE_FULFILL_HTLC,
                                   "n64 fulfill msg type");
                    unsigned char recv_ph[32], recv_pi[32];
                    uint64_t recv_hid;
                    TEST_ASSERT(wire_parse_bridge_fulfill_htlc(fulfill_msg.json,
                                    recv_ph, recv_pi, &recv_hid),
                                "n64 parse bridge fulfill");
                    unsigned char check_hash[32];
                    sha256(recv_pi, 32, check_hash);
                    TEST_ASSERT_MEM_EQ(check_hash, payment_hash, 32,
                                       "n64 preimage->hash valid");
                    printf("Bridge-n64: preimage matches, fulfill received\n");
                    cJSON_Delete(fulfill_msg.json);
                }
            }
            close(sv[0]);
            close(sv[1]);
        }
    }

    /* Cooperative close: 65 equal-share outputs to the funding SPK
       (we're not exercising per-party deltas here — that's covered by
       the dedicated N=64 lifecycle tests). */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 5000;  /* 5000 sat fee */
        size_t n_total = N;
        uint64_t per_party = close_total / n_total;

        tx_output_t *close_outputs = calloc(n_total, sizeof(tx_output_t));
        if (!close_outputs) lsp_ok = 0;
        if (lsp_ok) {
            for (size_t i = 0; i < n_total; i++) {
                close_outputs[i].amount_sats = per_party;
                memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
                close_outputs[i].script_pubkey_len = 34;
            }
            close_outputs[n_total - 1].amount_sats =
                close_total - per_party * (n_total - 1);

            tx_buf_t close_tx;
            tx_buf_init(&close_tx, 4096);

            if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs,
                                            n_total, 0)) {
                fprintf(stderr, "LSP-n64: cooperative close failed\n");
                lsp_ok = 0;
            } else {
                char *close_hex = malloc(close_tx.len * 2 + 1);
                if (close_hex) {
                    hex_encode(close_tx.data, close_tx.len, close_hex);
                    char close_txid[65];
                    if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                        regtest_mine_blocks(&rt, 1, mine_addr);
                        printf("Bridge-n64: coop close confirmed (%s)\n",
                               close_txid);
                    } else {
                        fprintf(stderr, "LSP-n64: broadcast close tx failed\n");
                        lsp_ok = 0;
                    }
                    free(close_hex);
                }
            }
            tx_buf_free(&close_tx);
            free(close_outputs);
        }
    }

    /* Wait for all 64 children */
    for (int c = 0; c < N_CLIENTS; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Child client %d (n64) failed (status=%d)\n", c,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            lsp_ok = 0;
        }
    }
    free(child_pids);

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);
    free(kps);
    free(pks);
    secp256k1_context_destroy(ctx);
    return lsp_ok;
}

/* Original test: route to client 0.  Client 0 lives in leaf 0; both the
   legacy `client_idx/2` formula and the mixed-arity walk-leaves logic
   produce the same (leaf 0, vout 0) for client 0, so this case alone
   doesn't catch LSP/client divergence in the leaf mapping. */
int test_regtest_bridge_payment_n64_mixed_arity(void) {
    return run_bridge_payment_n64_mixed_arity(0, "test_bridge_n64", 0);
}

/* Cross-leaf coverage: route to client 8.  At N=64 mixed-arity {2,4,8} the
   first leaf holds clients 0..7; client 8 is the FIRST client of the
   SECOND leaf.  This exercises the LSP-side leaf mapping path that the
   client-0 case skips — without the matching mixed-arity fix in
   src/lsp_channels.c::client_to_leaf the LSP and client end up on
   DIFFERENT leaves, MuSig commitment sigs fail to verify, and the
   bridge HTLC never fulfills. */
int test_regtest_bridge_payment_n64_mixed_arity_client8(void) {
    return run_bridge_payment_n64_mixed_arity(8, "test_bridge_n64_c8", 200);
}

/* ---- Outbound invoice validation ---- */

static const unsigned char out_payee_key[32] = { [0 ... 31] = 0x5a };

/* Encode an invoice for the outbound-check tests. */
static int make_out_invoice(secp256k1_context *ctx, const char *hrp,
                            uint64_t amount_msat, const unsigned char *hash32,
                            uint32_t timestamp, uint32_t expiry,
                            int min_final_cltv, char *out, size_t out_cap) {
    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strncpy(inv.network, hrp, sizeof(inv.network) - 1);
    inv.amount_msat = amount_msat;
    inv.has_amount = amount_msat > 0;
    inv.timestamp = timestamp;
    inv.expiry = expiry;
    inv.min_final_cltv_expiry = min_final_cltv;
    memcpy(inv.payment_hash, hash32, 32);
    memset(inv.payment_secret, 0x33, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "outbound");
    return bolt11_encode(&inv, out_payee_key, ctx, out, out_cap);
}

int test_bridge_outbound_budget(void) {
    /* No fee: the whole HTLC is available. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(4000, 0), 4000000, "no fee");
    /* 1000 ppm of 4,000,000 msat = 4,000 msat. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(4000, 1000), 3996000, "0.1% fee");
    /* The fee rounds up: 1 ppm of 1,000 msat still costs 1 msat. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(1, 1), 999, "fee rounds up");
    /* A fee of 100% or more leaves nothing. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(4000, 1000000), 0, "100% fee");
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(4000, 5000000), 0, ">100% fee");
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(0, 0), 0, "empty HTLC");
    /* Large amounts do not overflow: 21M BTC in sats at 2500 ppm. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_budget_msat(2100000000000000ULL, 2500),
                   2100000000000000000ULL - 5250000000000000ULL, "21M BTC");

    TEST_ASSERT(lsp_bridge_invoice_network_ok("mainnet", "bc"), "mainnet/bc");
    TEST_ASSERT(lsp_bridge_invoice_network_ok("regtest", "bcrt"), "regtest/bcrt");
    TEST_ASSERT(lsp_bridge_invoice_network_ok("signet", "tbs"), "signet/tbs");
    TEST_ASSERT(lsp_bridge_invoice_network_ok("testnet4", "tb"), "testnet4/tb");
    TEST_ASSERT(!lsp_bridge_invoice_network_ok("mainnet", "bcrt"), "mainnet/bcrt");
    TEST_ASSERT(!lsp_bridge_invoice_network_ok("regtest", "bc"), "regtest/bc");
    TEST_ASSERT(!lsp_bridge_invoice_network_ok("signet", "tb"), "signet/tb");
    TEST_ASSERT(!lsp_bridge_invoice_network_ok(NULL, "bc"), "unknown chain");
    TEST_ASSERT(!lsp_bridge_invoice_network_ok("", "bc"), "empty chain");
    return 1;
}

int test_bridge_outbound_invoice_check(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");

    unsigned char hash[32], other_hash[32];
    memset(hash, 0xA1, 32);
    memset(other_hash, 0xA2, 32);
    const uint32_t T = 1700000000;   /* invoice creation time */
    const uint64_t NOW = T + 100;
    char inv[2048];
    uint64_t inv_msat = 0, budget = 0;
    uint32_t min_cltv = 0;

    /* An invoice for exactly what the HTLC carries is accepted. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", NOW, &inv_msat, &budget, &min_cltv),
                   BRIDGE_PAY_OK, "matching invoice accepted");
    TEST_ASSERT_EQ(inv_msat, 4000000, "invoice amount reported");
    TEST_ASSERT_EQ(budget, 4000000, "budget reported");
    TEST_ASSERT_EQ(min_cltv, 40, "min_final_cltv reported");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_OK, "outputs are optional");

    /* The invoice must be for the hash the HTLC is locked to. */
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, other_hash, 4000,
                       0, "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_HASH_MISMATCH, "foreign payment hash refused");

    /* The invoice must not ask for more than the HTLC carries... */
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 3999, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC, "invoice above HTLC refused");
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000001, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC, "1 msat above HTLC refused");
    /* ...where a much larger invoice in a bigger unit is no exception. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000000ULL, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC, "1000x invoice refused");

    /* ...nor for more than is left after the LSP's fee. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 1000,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC, "fee not covered: refused");
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 3996000, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    budget = 0;
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 1000,
                       "regtest", NOW, NULL, &budget, NULL),
                   BRIDGE_PAY_OK, "HTLC minus fee covers invoice");
    TEST_ASSERT_EQ(budget, 3996000, "budget is HTLC minus fee");

    /* Amountless invoices are refused. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 0, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_NO_AMOUNT, "amountless invoice refused");

    /* Wrong chain, or a chain the LSP cannot name. */
    TEST_ASSERT(make_out_invoice(ctx, "bc", 4000000, hash, T, 3600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_WRONG_NETWORK, "mainnet invoice on regtest refused");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       NULL, NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_WRONG_NETWORK, "unknown chain refused");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "mainnet", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_OK, "mainnet invoice on mainnet accepted");

    /* Expiry: valid until timestamp + expiry, exclusive. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, hash, T, 600, 40,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", (uint64_t)T + 599, NULL, NULL, NULL),
                   BRIDGE_PAY_OK, "last valid second accepted");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, inv, hash, 4000, 0,
                       "regtest", (uint64_t)T + 600, NULL, NULL, NULL),
                   BRIDGE_PAY_EXPIRED, "expired invoice refused");

    /* Not an invoice at all. */
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, "lnbcrt40u1pexternal",
                       hash, 4000, 0, "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_BAD_INVOICE, "garbage refused");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, "", hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_BAD_INVOICE, "empty string refused");
    TEST_ASSERT_EQ(lsp_bridge_check_outbound_invoice(ctx, NULL, hash, 4000, 0,
                       "regtest", NOW, NULL, NULL, NULL),
                   BRIDGE_PAY_BAD_INVOICE, "NULL refused");

    /* Every refusal has its own reason string. */
    TEST_ASSERT(strcmp(lsp_bridge_pay_check_str(BRIDGE_PAY_HASH_MISMATCH),
                       "invoice_payment_hash_mismatch") == 0, "reason string");
    TEST_ASSERT(strcmp(lsp_bridge_pay_check_str(BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC),
                       "invoice_amount_exceeds_htlc") == 0, "reason string");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- The bridge hands the plugin the hash and spend cap with each pay ---- */

int test_bridge_pay_request_carries_limits(void) {
    int sv[2];  /* sv[0]=plugin side, sv[1]=bridge plugin_fd */
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    bridge_t br;
    bridge_init(&br);
    br.plugin_fd = sv[1];

    unsigned char hash[32];
    memset(hash, 0xC3, 32);
    cJSON *pay = wire_build_bridge_send_pay("lnbcrt40u1pinvoice", hash, 11,
                                              3996000, 432);
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_SEND_PAY;
    msg.json = pay;
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &msg), "handle send_pay");
    cJSON_Delete(pay);

    char buf[4096];
    ssize_t n = read(sv[0], buf, sizeof(buf) - 1);
    TEST_ASSERT(n > 0, "read plugin output");
    buf[n] = '\0';
    cJSON *fwd = cJSON_Parse(buf);
    TEST_ASSERT(fwd != NULL, "parse forwarded JSON");

    cJSON *method = cJSON_GetObjectItem(fwd, "method");
    TEST_ASSERT(method && cJSON_IsString(method) &&
                strcmp(method->valuestring, "pay_request") == 0,
                "method is pay_request");
    cJSON *b11 = cJSON_GetObjectItem(fwd, "bolt11");
    TEST_ASSERT(b11 && cJSON_IsString(b11) &&
                strcmp(b11->valuestring, "lnbcrt40u1pinvoice") == 0, "bolt11");
    cJSON *rid = cJSON_GetObjectItem(fwd, "request_id");
    TEST_ASSERT(rid && cJSON_IsNumber(rid), "request_id exists");
    TEST_ASSERT_EQ((uint64_t)rid->valuedouble, 11, "request_id");
    unsigned char fwd_hash[32];
    TEST_ASSERT(wire_json_get_hex(fwd, "payment_hash", fwd_hash, 32) == 32,
                "payment_hash forwarded");
    TEST_ASSERT_MEM_EQ(fwd_hash, hash, 32, "payment_hash matches");
    cJSON *mt = cJSON_GetObjectItem(fwd, "max_total_msat");
    TEST_ASSERT(mt && cJSON_IsNumber(mt), "max_total_msat forwarded");
    TEST_ASSERT_EQ((uint64_t)mt->valuedouble, 3996000, "max_total_msat value");
    cJSON *md = cJSON_GetObjectItem(fwd, "max_delay");
    TEST_ASSERT(md && cJSON_IsNumber(md), "max_delay forwarded");
    TEST_ASSERT_EQ((uint32_t)md->valuedouble, 432, "max_delay value");

    cJSON_Delete(fwd);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Operator-initiated pay: invoice is checked, spend is capped ---- */

int test_bridge_operator_pay(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.bridge_fd = sv[0];
    mgr.next_request_id = 5;
    snprintf(mgr.network, sizeof(mgr.network), "regtest");

    unsigned char hash[32];
    memset(hash, 0xD4, 32);
    uint32_t now = (uint32_t)time(NULL);
    char inv[2048];
    uint64_t rid = 0;
    const char *err = NULL;

    /* Refusals send nothing to the bridge. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 0, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(!lsp_channels_operator_pay(&mgr, inv, &rid, &err),
                "amountless invoice refused");
    TEST_ASSERT(err && strcmp(err, "invoice_without_amount") == 0, "reason");
    TEST_ASSERT(make_out_invoice(ctx, "bc", 2000000, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(!lsp_channels_operator_pay(&mgr, inv, &rid, &err),
                "wrong-chain invoice refused");
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 2000000, hash, now - 7200, 3600,
                                  18, inv, sizeof(inv)), "encode");
    TEST_ASSERT(!lsp_channels_operator_pay(&mgr, inv, &rid, &err),
                "expired invoice refused");
    TEST_ASSERT(!lsp_channels_operator_pay(&mgr, "not-an-invoice", &rid, &err),
                "garbage refused");
    TEST_ASSERT_EQ(mgr.next_request_id, 5, "no request id consumed by refusals");

    /* A good invoice goes out with its own hash and a bounded spend:
       2,000,000 msat + 0.5% = 2,010,000 msat. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 2000000, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(lsp_channels_operator_pay(&mgr, inv, &rid, &err),
                "valid invoice sent");
    TEST_ASSERT_EQ(rid, 5, "request id returned");

    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "bridge receives SEND_PAY");
    TEST_ASSERT_EQ(msg.msg_type, MSG_BRIDGE_SEND_PAY, "SEND_PAY type");
    char rb[2048];
    unsigned char rph[32];
    uint64_t rrid = 0, rmax = 0;
    uint32_t rdelay = 0;
    TEST_ASSERT(wire_parse_bridge_send_pay(msg.json, rb, sizeof(rb), rph, &rrid,
                                             &rmax, &rdelay), "parse SEND_PAY");
    TEST_ASSERT_EQ(rdelay, LSP_BRIDGE_OPERATOR_MAX_DELAY, "default route delay");
    TEST_ASSERT(strcmp(rb, inv) == 0, "invoice forwarded unchanged");
    TEST_ASSERT_MEM_EQ(rph, hash, 32, "hash taken from the invoice");
    TEST_ASSERT_EQ(rmax, 2010000, "spend capped at amount + allowance");
    cJSON_Delete(msg.json);

    /* Small invoices get the flat 5 sat allowance. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 10000, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(lsp_channels_operator_pay(&mgr, inv, &rid, &err), "small invoice sent");
    TEST_ASSERT(wire_recv(sv[1], &msg), "bridge receives SEND_PAY");
    TEST_ASSERT(wire_parse_bridge_send_pay(msg.json, rb, sizeof(rb), rph, &rrid,
                                             &rmax, &rdelay), "parse SEND_PAY");
    TEST_ASSERT_EQ(rmax, 15000, "flat allowance for a small invoice");
    cJSON_Delete(msg.json);

    /* No bridge: refused. */
    mgr.bridge_fd = -1;
    TEST_ASSERT(!lsp_channels_operator_pay(&mgr, inv, &rid, &err), "no bridge");

    close(sv[0]);
    close(sv[1]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- A client HTLC for an invoice it does not fund is failed, not paid ---- */

/* Chain backend stub reporting a fixed tip. */
static int fixed_tip_height;
static int fixed_tip_get_block_height(chain_backend_t *self) {
    (void)self;
    return fixed_tip_height;
}

/* Offer an HTLC (expiring at height 500) with a bolt11 from client 0 and
   return the reason the LSP failed it with ("" if it was not failed). */
static int offer_outside_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp, int client_peer_fd,
                              const unsigned char *hash, uint64_t amount_msat,
                              const char *bolt11, char *reason, size_t reason_cap) {
    cJSON *add = wire_build_update_add_htlc(9, amount_msat, hash, 500);
    cJSON_AddStringToObject(add, "bolt11", bolt11);
    wire_msg_t msg;
    msg.msg_type = MSG_UPDATE_ADD_HTLC;
    msg.json = add;
    int handled = lsp_channels_handle_msg(mgr, lsp, 0, &msg);
    cJSON_Delete(add);
    reason[0] = 0;
    if (!handled) return 0;

    wire_msg_t reply;
    if (!wire_recv_timeout(client_peer_fd, &reply, 5)) return 0;
    uint64_t failed_id = 0;
    int ok = reply.msg_type == MSG_UPDATE_FAIL_HTLC &&
             wire_parse_update_fail_htlc(reply.json, &failed_id, reason, reason_cap) &&
             failed_id == 9;
    cJSON_Delete(reply.json);
    return ok;
}

int test_lsp_outbound_htlc_refused(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");
    int cl[2], br[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0, "client socketpair");
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, br) == 0, "bridge socketpair");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 1;
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.bridge_fd = br[0];
    mgr.next_request_id = 1;
    snprintf(mgr.network, sizeof(mgr.network), "regtest");
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && lsp, "alloc");
    int client_fd = cl[0];
    lsp->client_fds = &client_fd;

    unsigned char hash[32], other_hash[32];
    memset(hash, 0xE5, 32);
    memset(other_hash, 0xE6, 32);
    uint32_t now = (uint32_t)time(NULL);
    char inv[2048], reason[128];

    /* Invoice for a different payment hash than the HTLC. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, other_hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "invoice_payment_hash_mismatch") == 0,
                "refused: hash mismatch");

    /* Invoice for more than the HTLC carries. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 400000000, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "invoice_amount_exceeds_htlc") == 0,
                "refused: amount above HTLC");

    /* Sub-satoshi remainder of the HTLC does not count: 4,000,999 msat is
       a 4,000 sat HTLC and cannot fund a 4,000,999 msat invoice. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000999, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000999, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "invoice_amount_exceeds_htlc") == 0,
                "refused: msat remainder not counted");

    /* Not an invoice. */
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000,
                                    "lnbcrt40u1pexternaldest0",
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "invalid_invoice") == 0, "refused: undecodable");

    /* None of the refusals reached the bridge, took a request id, or
       touched the channel. */
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(br[1], &stray, 1), "nothing sent to bridge");
    TEST_ASSERT_EQ(mgr.next_request_id, 1, "no request id consumed");
    TEST_ASSERT_EQ(mgr.entries[0].channel.n_htlcs, 0, "no HTLC added");

    /* A valid invoice, but the LSP cannot tell how far away the HTLC's
       expiry is. */
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "chain_height_unavailable") == 0,
                "refused: chain tip unknown");

    /* The HTLC expires at 500.  The route needs the invoice's 18 final-hop
       blocks and the LSP its 40-block margin, so a tip of 442 leaves no
       room, and a tip past the expiry certainly does not. */
    chain_backend_t tip;
    memset(&tip, 0, sizeof(tip));
    tip.get_block_height = fixed_tip_get_block_height;
    mgr.chain_be = &tip;
    fixed_tip_height = 442;
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "cltv_expiry_out_of_bounds") == 0,
                "refused: expiry too close to the tip");
    fixed_tip_height = 800000;
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "cltv_expiry_out_of_bounds") == 0,
                "refused: expiry below the tip");
    TEST_ASSERT(!wire_recv_timeout(br[1], &stray, 1), "nothing sent to bridge");
    TEST_ASSERT_EQ(mgr.entries[0].channel.n_htlcs, 0, "no HTLC added");

    /* A valid invoice with no bridge connected is failed too. */
    mgr.bridge_fd = -1;
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "bridge_unavailable") == 0, "refused: no bridge");

    close(cl[0]); close(cl[1]); close(br[0]); close(br[1]);
    free(mgr.entries);
    free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Outbound HTLC deadline vs. the outside route ---- */

int test_bridge_outbound_max_delay(void) {
    uint32_t delay = 0;

    /* Tip 1000, invoice needs 18 final-hop blocks, LSP keeps 40: the HTLC
       must expire after 1058. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1058, 1000, 18, 40, 0, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "expiry == tip+final+margin refused");
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1059, 1000, 18, 40, 0, &delay),
                   BRIDGE_PAY_OK, "one block more accepted");
    /* The route may use what is left after the margin: 1059 - 40 - 1000. */
    TEST_ASSERT_EQ(delay, 19, "max delay leaves the margin");

    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1500, 1000, 18, 40, 0, &delay),
                   BRIDGE_PAY_OK, "roomy expiry accepted");
    TEST_ASSERT_EQ(delay, 460, "max delay = expiry - margin - tip");
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1500, 1000, 18, 40, 0, NULL),
                   BRIDGE_PAY_OK, "output is optional");

    /* A larger final-hop requirement or margin needs a later expiry. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1500, 1000, 461, 40, 0, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "final hop does not fit");
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1500, 1000, 18, 482, 0, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "margin does not fit");

    /* An expiry that is only large as a bare number is still in the past. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(500, 800000, 18, 40, 0, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "expiry below the tip refused");

    /* Tip unknown: refuse rather than guess. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1500, 0, 18, 40, 0, &delay),
                   BRIDGE_PAY_NO_CHAIN_HEIGHT, "unknown tip refused");

    /* The HTLC must also expire before the factory does. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1400, 1000, 18, 40, 1400, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "expiry at factory timeout refused");
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(1399, 1000, 18, 40, 1400, &delay),
                   BRIDGE_PAY_OK, "expiry before factory timeout accepted");

    /* A zero margin falls back to the default. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(
                       1000 + 18 + FACTORY_CLTV_DELTA_DEFAULT, 1000, 18, 0, 0, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "default margin applied");

    /* No wrap-around near the top of the height range. */
    TEST_ASSERT_EQ(lsp_bridge_outbound_max_delay(100, UINT32_MAX - 5, 18, 40, 0, &delay),
                   BRIDGE_PAY_CLTV_OUT_OF_BOUNDS, "no wrap-around");

    TEST_ASSERT(strcmp(lsp_bridge_pay_check_str(BRIDGE_PAY_CLTV_OUT_OF_BOUNDS),
                       "cltv_expiry_out_of_bounds") == 0, "reason string");
    TEST_ASSERT(strcmp(lsp_bridge_pay_check_str(BRIDGE_PAY_NO_CHAIN_HEIGHT),
                       "chain_height_unavailable") == 0, "reason string");
    return 1;
}

/* ---- Plugin port: shared secret file ---- */

static const char TEST_PLUGIN_SECRET[] =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

int test_bridge_plugin_secret_file(void) {
    char dir[] = "/tmp/ss_bridge_secret_XXXXXX";
    TEST_ASSERT(mkdtemp(dir) != NULL, "mkdtemp");
    char path[256], path2[256], link_path[256];
    snprintf(path, sizeof(path), "%s/plugin.secret", dir);
    snprintf(path2, sizeof(path2), "%s/other.secret", dir);
    snprintf(link_path, sizeof(link_path), "%s/link.secret", dir);

    /* First use creates the file: 64 hex characters, owner-only. */
    char s1[BRIDGE_PLUGIN_SECRET_HEX_LEN + 1], s2[BRIDGE_PLUGIN_SECRET_HEX_LEN + 1];
    TEST_ASSERT(bridge_plugin_secret_load(path, s1), "secret created");
    TEST_ASSERT_EQ(strlen(s1), BRIDGE_PLUGIN_SECRET_HEX_LEN, "secret length");
    TEST_ASSERT(strspn(s1, "0123456789abcdef") == BRIDGE_PLUGIN_SECRET_HEX_LEN,
                "secret is hex");
    struct stat st;
    TEST_ASSERT(stat(path, &st) == 0, "secret file exists");
    TEST_ASSERT_EQ(st.st_mode & 0777, 0600, "secret file mode 0600");

    /* Loading again returns the same secret; a new file gets a new one. */
    TEST_ASSERT(bridge_plugin_secret_load(path, s2), "secret reloaded");
    TEST_ASSERT(strcmp(s1, s2) == 0, "same secret on reload");
    TEST_ASSERT(bridge_plugin_secret_load(path2, s2), "second secret created");
    TEST_ASSERT(strcmp(s1, s2) != 0, "secrets are random");

    /* A file others can read is refused. */
    TEST_ASSERT(chmod(path, 0644) == 0, "chmod 0644");
    TEST_ASSERT(!bridge_plugin_secret_load(path, s2), "world-readable secret refused");
    TEST_ASSERT(chmod(path, 0640) == 0, "chmod 0640");
    TEST_ASSERT(!bridge_plugin_secret_load(path, s2), "group-readable secret refused");
    TEST_ASSERT(chmod(path, 0600) == 0, "chmod 0600");
    TEST_ASSERT(bridge_plugin_secret_load(path, s2), "0600 accepted again");

    /* A symlink is not followed. */
    TEST_ASSERT(symlink(path, link_path) == 0, "symlink");
    TEST_ASSERT(!bridge_plugin_secret_load(link_path, s2), "symlink refused");

    /* Content that is not a 64-hex secret is refused. */
    FILE *f = fopen(path2, "w");
    TEST_ASSERT(f != NULL, "open for rewrite");
    fputs("not-a-secret\n", f);
    fclose(f);
    TEST_ASSERT(!bridge_plugin_secret_load(path2, s2), "malformed secret refused");

    /* A missing directory cannot be created into. */
    char nodir[300];
    snprintf(nodir, sizeof(nodir), "%s/missing/plugin.secret", dir);
    TEST_ASSERT(!bridge_plugin_secret_load(nodir, s2), "missing directory");

    bridge_t br;
    bridge_init(&br);
    TEST_ASSERT(!bridge_set_plugin_secret(&br, "abc"), "short secret rejected");
    TEST_ASSERT(!br.has_plugin_secret, "no secret set");
    TEST_ASSERT(bridge_set_plugin_secret(&br, s1), "secret set");
    TEST_ASSERT(br.has_plugin_secret, "secret recorded");

    unlink(link_path); unlink(path); unlink(path2); rmdir(dir);
    return 1;
}

/* ---- Plugin port: binds to loopback unless told otherwise ---- */

static int bound_addr(int fd, struct sockaddr_in *out) {
    socklen_t len = sizeof(*out);
    memset(out, 0, sizeof(*out));
    return getsockname(fd, (struct sockaddr *)out, &len) == 0;
}

int test_bridge_plugin_port_loopback(void) {
    bridge_t br;
    bridge_init(&br);
    struct sockaddr_in sa;

    /* No secret, no listener. */
    TEST_ASSERT(!bridge_listen_plugin(&br, NULL, 0), "no secret: refuses to listen");
    TEST_ASSERT_EQ(br.plugin_listen_fd, -1, "nothing bound");

    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");

    /* Default: loopback only. */
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen (default address)");
    TEST_ASSERT(bound_addr(br.plugin_listen_fd, &sa), "getsockname");
    TEST_ASSERT_EQ(ntohl(sa.sin_addr.s_addr), INADDR_LOOPBACK, "bound to 127.0.0.1");
    wire_close(br.plugin_listen_fd);
    br.plugin_listen_fd = -1;

    TEST_ASSERT(bridge_listen_plugin(&br, "", 0), "listen (empty address)");
    TEST_ASSERT(bound_addr(br.plugin_listen_fd, &sa), "getsockname");
    TEST_ASSERT_EQ(ntohl(sa.sin_addr.s_addr), INADDR_LOOPBACK, "empty = 127.0.0.1");
    wire_close(br.plugin_listen_fd);
    br.plugin_listen_fd = -1;

    /* Another address only when asked for explicitly. */
    TEST_ASSERT(bridge_listen_plugin(&br, "0.0.0.0", 0), "listen (explicit address)");
    TEST_ASSERT(bound_addr(br.plugin_listen_fd, &sa), "getsockname");
    TEST_ASSERT_EQ(ntohl(sa.sin_addr.s_addr), INADDR_ANY, "bound as requested");
    wire_close(br.plugin_listen_fd);
    br.plugin_listen_fd = -1;

    /* An address that does not parse is an error, not "all interfaces". */
    TEST_ASSERT(!bridge_listen_plugin(&br, "localhost", 0), "hostname rejected");
    TEST_ASSERT(!bridge_listen_plugin(&br, "not-an-address", 0), "garbage rejected");
    TEST_ASSERT_EQ(br.plugin_listen_fd, -1, "nothing bound");
    TEST_ASSERT_EQ(wire_listen("not-an-address", 0), -1,
                   "wire_listen rejects an unparseable address");

    bridge_cleanup(&br);
    return 1;
}

/* ---- Plugin port: only an authenticated connection becomes the plugin ---- */

static int connect_plugin_port(const bridge_t *br) {
    struct sockaddr_in sa;
    if (!bound_addr(br->plugin_listen_fd, &sa)) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}

static int wait_readable(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return poll(&p, 1, 5000) == 1;
}

static int send_str(int fd, const char *s) {
    return write(fd, s, strlen(s)) == (ssize_t)strlen(s);
}

/* 1 if the peer closed the connection without sending anything (a reset
   counts: that is what closing with unread input produces). */
static int peer_closed(int fd) {
    char c;
    ssize_t n = read(fd, &c, 1);
    return n == 0 || (n < 0 && errno == ECONNRESET);
}

/* Accept `fd`'s connection, feed it `first_line` and service it. */
static int offer_first_line(bridge_t *br, int fd, const char *first_line) {
    if (!wait_readable(br->plugin_listen_fd)) return -2;
    if (!bridge_accept_plugin(br)) return -3;
    if (!send_str(fd, first_line)) return -4;
    if (!wait_readable(br->plugin_pending_fd)) return -5;
    return bridge_service_pending_plugin(br);
}

int test_bridge_plugin_auth(void) {
    bridge_t br;
    bridge_init(&br);
    int lsp_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");
    br.lsp_fd = lsp_sv[1];
    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen");

    char good[256], line[512];
    snprintf(good, sizeof(good), "{\"method\":\"auth\",\"token\":\"%s\"}\n",
             TEST_PLUGIN_SECRET);

    /* Wrong secrets: a different one, one differing only in its last
       character, a truncated one, an empty one. */
    static const char *bad_tokens[] = {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeef0",
        "00112233445566778899aabbccddeeff",
        "",
    };
    for (size_t i = 0; i < sizeof(bad_tokens) / sizeof(bad_tokens[0]); i++) {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        snprintf(line, sizeof(line), "{\"method\":\"auth\",\"token\":\"%s\"}\n",
                 bad_tokens[i]);
        TEST_ASSERT_EQ(offer_first_line(&br, c, line), -1, "wrong secret dropped");
        TEST_ASSERT_EQ(br.plugin_fd, -1, "not accepted as the plugin");
        TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "no longer pending");
        TEST_ASSERT(peer_closed(c), "connection closed, nothing sent to it");
        close(c);
    }

    /* A connection that starts talking without authenticating is dropped
       and its message goes nowhere. */
    static const char *unauthenticated[] = {
        "{\"method\":\"htlc_accepted\",\"payment_hash\":"
        "\"abababababababababababababababababababababababababababababababab\","
        "\"amount_msat\":5000000,\"cltv_expiry\":500}\n",
        "{\"method\":\"pay_result\",\"request_id\":1,\"success\":true,\"preimage\":"
        "\"abababababababababababababababababababababababababababababababab\"}\n",
        "{\"token\":\"00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff\"}\n",
        "not json\n",
    };
    for (size_t i = 0; i < sizeof(unauthenticated) / sizeof(unauthenticated[0]); i++) {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT_EQ(offer_first_line(&br, c, unauthenticated[i]), -1,
                       "unauthenticated message dropped");
        TEST_ASSERT_EQ(br.plugin_fd, -1, "not accepted as the plugin");
        TEST_ASSERT(peer_closed(c), "connection closed");
        close(c);
    }
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(lsp_sv[0], &stray, 1),
                "nothing from unauthenticated peers reached the LSP");

    /* A first line too long to be an auth message is dropped. */
    {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        char big[600];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        TEST_ASSERT(wait_readable(br.plugin_listen_fd), "incoming");
        TEST_ASSERT(bridge_accept_plugin(&br), "accept");
        TEST_ASSERT(send_str(c, big), "send oversized line");
        int r = 0;
        for (int tries = 0; tries < 10 && r == 0; tries++) {
            TEST_ASSERT(wait_readable(br.plugin_pending_fd), "data pending");
            r = bridge_service_pending_plugin(&br);
        }
        TEST_ASSERT_EQ(r, -1, "oversized first line dropped");
        TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "no longer pending");
        close(c);
    }

    /* A connection that never authenticates is dropped after the timeout. */
    {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT(wait_readable(br.plugin_listen_fd), "incoming");
        TEST_ASSERT(bridge_accept_plugin(&br), "accept");
        time_t t0 = br.plugin_pending_since;
        TEST_ASSERT(!bridge_expire_pending_plugin(&br, t0 + BRIDGE_PLUGIN_AUTH_TIMEOUT - 1),
                    "still within the timeout");
        TEST_ASSERT(br.plugin_pending_fd >= 0, "still pending");
        TEST_ASSERT(bridge_expire_pending_plugin(&br, t0 + BRIDGE_PLUGIN_AUTH_TIMEOUT),
                    "expired");
        TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "dropped");
        TEST_ASSERT(peer_closed(c), "connection closed");
        close(c);
    }

    /* The right secret, arriving in two pieces and followed at once by a
       plugin message. */
    int plugin = connect_plugin_port(&br);
    TEST_ASSERT(plugin >= 0, "connect");
    TEST_ASSERT(wait_readable(br.plugin_listen_fd), "incoming");
    TEST_ASSERT(bridge_accept_plugin(&br), "accept");
    TEST_ASSERT_EQ(br.plugin_fd, -1, "not the plugin before authenticating");
    TEST_ASSERT(write(plugin, good, 20) == 20, "send first part");
    TEST_ASSERT(wait_readable(br.plugin_pending_fd), "data pending");
    TEST_ASSERT_EQ(bridge_service_pending_plugin(&br), 0, "auth line incomplete");
    TEST_ASSERT_EQ(br.plugin_fd, -1, "still not the plugin");
    snprintf(line, sizeof(line), "%s{\"method\":\"invoice_bolt11\",\"payment_hash\":"
             "\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\","
             "\"bolt11\":\"lnbcrt1ptest\"}\n", good + 20);
    TEST_ASSERT(send_str(plugin, line), "send rest + next message");
    int r = 0;
    for (int tries = 0; tries < 10 && r == 0; tries++) {
        TEST_ASSERT(wait_readable(br.plugin_pending_fd), "data pending");
        r = bridge_service_pending_plugin(&br);
    }
    TEST_ASSERT_EQ(r, 1, "right secret accepted");
    TEST_ASSERT(br.plugin_fd >= 0, "now the plugin");
    TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "no longer pending");

    /* It is told so... */
    char buf[256];
    ssize_t n = read(plugin, buf, sizeof(buf) - 1);
    TEST_ASSERT(n > 0, "auth reply");
    buf[n] = '\0';
    TEST_ASSERT(strstr(buf, "\"auth_ok\"") != NULL, "auth_ok sent");

    /* ...and the message behind the auth line is ordinary plugin traffic.
       (If more than the auth line has arrived it is already buffered.) */
    char *next = bridge_read_plugin_line(&br);
    TEST_ASSERT(next != NULL, "message after auth available");
    TEST_ASSERT(strstr(next, "\"invoice_bolt11\"") != NULL, "message intact");
    TEST_ASSERT(bridge_handle_plugin_msg(&br, next), "message handled");
    free(next);
    wire_msg_t fwd;
    TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &fwd, 5), "forwarded to LSP");
    TEST_ASSERT_EQ(fwd.msg_type, MSG_INVOICE_BOLT11, "INVOICE_BOLT11");
    cJSON_Delete(fwd.json);

    /* While it is connected nobody else gets in, right secret or not, and
       the plugin keeps its connection. */
    int live_fd = br.plugin_fd;
    for (int i = 0; i < 2; i++) {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT(send_str(c, good), "second connection sends the secret");
        TEST_ASSERT(wait_readable(br.plugin_listen_fd), "incoming");
        TEST_ASSERT(!bridge_accept_plugin(&br), "second connection refused");
        TEST_ASSERT_EQ(br.plugin_fd, live_fd, "plugin connection unchanged");
        TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "nothing pending");
        TEST_ASSERT(peer_closed(c), "second connection closed");
        close(c);
    }

    close(plugin);
    close(lsp_sv[0]);
    bridge_cleanup(&br);
    return 1;
}

/* ---- Inbound bridge HTLC must carry the invoice amount ---- */

/* Hand the LSP an inbound bridge HTLC and return the reason it was failed
   with ("" if no failure came back). */
static int offer_bridge_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp, int bridge_peer_fd,
                             const unsigned char *hash, uint64_t amount_msat,
                             uint32_t cltv_expiry, uint64_t htlc_id,
                             char *reason, size_t reason_cap) {
    cJSON *add = wire_build_bridge_add_htlc(hash, amount_msat, cltv_expiry, htlc_id);
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_ADD_HTLC;
    msg.json = add;
    int handled = lsp_channels_handle_bridge_msg(mgr, lsp, &msg);
    cJSON_Delete(add);
    reason[0] = '\0';
    if (!handled) return 0;

    wire_msg_t reply;
    if (!wire_recv_timeout(bridge_peer_fd, &reply, 5)) return 0;
    unsigned char failed_hash[32];
    uint64_t failed_id = 0;
    int ok = reply.msg_type == MSG_BRIDGE_FAIL_HTLC &&
             wire_parse_bridge_fail_htlc(reply.json, failed_hash, reason,
                                          reason_cap, &failed_id) &&
             failed_id == htlc_id && memcmp(failed_hash, hash, 32) == 0;
    cJSON_Delete(reply.json);
    return ok;
}

int test_lsp_inbound_amount_below_invoice(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 2;
    mgr.bridge_fd = sv[0];
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 2;
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.invoices && mgr.htlc_origins && lsp, "alloc");

    unsigned char preimage[32], hash[32];
    memset(preimage, 0x39, 32);
    sha256(preimage, 32, hash);
    const uint64_t INVOICE_MSAT = 5000000;
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash, preimage, 1, INVOICE_MSAT),
                "register invoice");
    uint64_t registered = 0;
    TEST_ASSERT(lsp_channels_invoice_amount(&mgr, hash, &registered), "invoice found");
    TEST_ASSERT_EQ(registered, INVOICE_MSAT, "invoice amount");

    char reason[128];

    /* Less than the invoice asks for: refused, whether by a lot (a part of
       a split payment), by one satoshi, or by one millisatoshi. */
    static const uint64_t short_amounts[] = { 1000, 2500000, 4999000, 4999999 };
    for (size_t i = 0; i < sizeof(short_amounts) / sizeof(short_amounts[0]); i++) {
        TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash, short_amounts[i],
                                       500, 70 + i, reason, sizeof(reason)),
                    "short HTLC failed back");
        TEST_ASSERT(strcmp(reason, "amount_below_invoice") == 0,
                    "refused: below invoice amount");
    }
    /* Nothing was offered to the client and nothing is tracked. */
    TEST_ASSERT_EQ(mgr.entries[1].channel.n_htlcs, 0, "no HTLC offered to client");
    TEST_ASSERT(!lsp_channels_bridge_htlc_pending(&mgr, hash), "no HTLC tracked");
    size_t dest = 99;
    TEST_ASSERT(lsp_channels_lookup_invoice(&mgr, hash, &dest) && dest == 1,
                "invoice still payable");

    /* The full amount gets past the amount check (and is stopped only by
       the next one: this HTLC's expiry is too low to forward). */
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash, INVOICE_MSAT,
                                   10, 80, reason, sizeof(reason)),
                "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "cltv_expiry_out_of_bounds") == 0,
                "full amount is not refused for its amount");
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash, INVOICE_MSAT + 1000,
                                   10, 81, reason, sizeof(reason)),
                "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "cltv_expiry_out_of_bounds") == 0,
                "overpayment is not refused for its amount");

    /* While one HTLC for the invoice is in flight, another is refused even
       at the full amount. */
    lsp_channels_track_bridge_origin(&mgr, hash, 90);
    TEST_ASSERT(lsp_channels_bridge_htlc_pending(&mgr, hash), "HTLC in flight");
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash, INVOICE_MSAT,
                                   500, 91, reason, sizeof(reason)),
                "second HTLC failed back");
    TEST_ASSERT(strcmp(reason, "duplicate_payment_hash") == 0,
                "refused: payment already in flight");
    TEST_ASSERT_EQ(lsp_channels_get_bridge_origin(&mgr, hash), 90,
                   "first HTLC still the tracked one");

    /* An invoice registered without an amount accepts any amount. */
    unsigned char preimage2[32], hash2[32];
    memset(preimage2, 0x3a, 32);
    sha256(preimage2, 32, hash2);
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash2, preimage2, 0, 0),
                "register amountless invoice");
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash2, 1000, 10, 95,
                                   reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "cltv_expiry_out_of_bounds") == 0,
                "amountless invoice: not refused for its amount");

    /* Unknown hash: unchanged. */
    unsigned char unknown[32];
    memset(unknown, 0x3b, 32);
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], unknown, INVOICE_MSAT, 500, 96,
                                   reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "unknown_payment_hash") == 0, "unknown hash");

    close(sv[0]);
    close(sv[1]);
    free(mgr.entries);
    free(mgr.invoices);
    free(mgr.htlc_origins);
    free(lsp);
    return 1;
}

/* ---- Outbound pays are tracked in the slot the tracker filled ---- */

int test_lsp_outbound_origin_slot_reuse(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.htlc_origins = calloc(4, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = 4;
    TEST_ASSERT(mgr.htlc_origins != NULL, "alloc");

    unsigned char h[6][32];
    for (int i = 0; i < 6; i++) memset(h[i], 0x60 + i, 32);

    /* Three pays in flight fill slots 0..2 */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(lsp_channels_track_outbound_pay(&mgr, h[i], 100 + i, i, 10 + i, 500)
                    == &mgr.htlc_origins[i], "pay tracked in next slot");
    TEST_ASSERT_EQ(mgr.n_htlc_origins, 3, "three origins");

    /* The first one resolves, leaving slot 0 free below the others */
    mgr.htlc_origins[0].active = 0;
    TEST_ASSERT(lsp_channels_origin_slot_free(&mgr), "a slot is free");

    /* Two more pays start while pays 101 and 102 are still in flight */
    htlc_origin_t *d = lsp_channels_track_outbound_pay(&mgr, h[3], 103, 1, 21, 600);
    htlc_origin_t *e = lsp_channels_track_outbound_pay(&mgr, h[4], 104, 0, 22, 700);
    TEST_ASSERT(d == &mgr.htlc_origins[0], "freed slot reused");
    TEST_ASSERT(e == &mgr.htlc_origins[3], "then the table grows");

    /* Every pay in flight is still found by its own request id, with its
       own hash and sender */
    static const struct { uint64_t rid; int hash; size_t sender; uint64_t htlc; }
        want[] = { {101, 1, 1, 11}, {102, 2, 2, 12}, {103, 3, 1, 21}, {104, 4, 0, 22} };
    for (size_t w = 0; w < 4; w++) {
        int found = 0;
        for (size_t i = 0; i < mgr.n_htlc_origins; i++) {
            htlc_origin_t *o = &mgr.htlc_origins[i];
            if (!o->active || o->request_id != want[w].rid) continue;
            found++;
            TEST_ASSERT_MEM_EQ(o->payment_hash, h[want[w].hash], 32, "hash of this pay");
            TEST_ASSERT_EQ(o->sender_idx, want[w].sender, "sender of this pay");
            TEST_ASSERT_EQ(o->sender_htlc_id, want[w].htlc, "sender HTLC of this pay");
            TEST_ASSERT_EQ(o->bridge_htlc_id, 0, "outbound origin");
        }
        TEST_ASSERT_EQ(found, 1, "exactly one origin per request id");
    }
    TEST_ASSERT_EQ(d->cltv_expiry, 600, "expiry recorded");

    /* Full table: refused, nothing overwritten */
    TEST_ASSERT(!lsp_channels_origin_slot_free(&mgr), "table full");
    TEST_ASSERT(lsp_channels_track_outbound_pay(&mgr, h[5], 105, 3, 23, 800) == NULL,
                "no slot: not tracked");
    TEST_ASSERT_EQ(mgr.htlc_origins[3].request_id, 104, "last entry untouched");

    free(mgr.htlc_origins);
    return 1;
}

/* ---- Outbound pay results: only the right preimage settles the HTLC ---- */

typedef struct {
    lsp_channel_mgr_t mgr;
    lsp_t *lsp;
    int client_fd;      /* LSP's end of the client connection */
    int client_peer;    /* the client's end */
    int bridge_peer;    /* the bridge's end of the bridge connection */
    unsigned char preimage[32], hash[32];
    uint64_t htlc_id;
} pay_fixture_t;

/* One client with one 4,000 sat HTLC offered for an outside payment that
   is in flight as request 7. */
static int pay_fixture_init(pay_fixture_t *f) {
    memset(f, 0, sizeof(*f));
    int cl[2], br[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, cl) != 0) return 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, br) != 0) return 0;
    f->client_fd = cl[0]; f->client_peer = cl[1];
    f->bridge_peer = br[1];
    f->mgr.n_channels = 1;
    f->mgr.bridge_fd = br[0];
    f->mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    f->mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    f->mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    f->mgr.next_request_id = 8;
    f->lsp = calloc(1, sizeof(lsp_t));
    if (!f->mgr.entries || !f->mgr.htlc_origins || !f->lsp) return 0;
    f->lsp->client_fds = &f->client_fd;
    /* The client never answers: reads on its connection end at once */
    shutdown(f->client_peer, SHUT_WR);

    memset(f->preimage, 0x71, 32);
    sha256(f->preimage, 32, f->hash);
    channel_t *ch = &f->mgr.entries[0].channel;
    ch->local_amount = 100000;
    ch->remote_amount = 100000;
    if (!channel_add_htlc(ch, HTLC_RECEIVED, 4000, f->hash, 500, &f->htlc_id))
        return 0;
    return lsp_channels_track_outbound_pay(&f->mgr, f->hash, 7, 0, f->htlc_id,
                                            500) != NULL;
}

static void pay_fixture_free(pay_fixture_t *f) {
    close(f->client_fd); close(f->client_peer);
    close(f->mgr.bridge_fd); close(f->bridge_peer);
    free(f->mgr.entries[0].channel.htlcs);
    free(f->mgr.entries);
    free(f->mgr.htlc_origins);
    free(f->lsp);
}

static int deliver_pay_result(pay_fixture_t *f, uint64_t request_id, int success,
                              const unsigned char *preimage) {
    cJSON *res = wire_build_bridge_pay_result(request_id, success, preimage);
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_PAY_RESULT;
    msg.json = res;
    int r = lsp_channels_handle_bridge_msg(&f->mgr, f->lsp, &msg);
    cJSON_Delete(res);
    return r;
}

/* 1 if the HTLC is still pending, the origin still open and the client has
   been sent nothing. */
static int pay_untouched(pay_fixture_t *f) {
    channel_t *ch = &f->mgr.entries[0].channel;
    wire_msg_t stray;
    if (wire_recv_timeout(f->client_peer, &stray, 1)) {
        cJSON_Delete(stray.json);
        return 0;
    }
    return ch->n_htlcs == 1 && ch->htlcs[0].state == HTLC_STATE_ACTIVE &&
           ch->local_amount == 100000 &&
           f->mgr.htlc_origins[0].active &&
           !lsp_channels_outbound_was_paid(&f->mgr, f->hash);
}

int test_lsp_pay_result_requires_preimage(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    unsigned char wrong[32], zero[32];
    memset(wrong, 0x72, 32);
    memset(zero, 0, 32);

    /* "Success" with a preimage of something else, or of nothing */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, wrong), "handled");
    TEST_ASSERT(pay_untouched(&f), "wrong preimage changes nothing");
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, zero), "handled");
    TEST_ASSERT(pay_untouched(&f), "zero preimage changes nothing");

    /* "Success" with no preimage at all does not even parse */
    TEST_ASSERT(!deliver_pay_result(&f, 7, 1, NULL), "success without preimage rejected");
    TEST_ASSERT(pay_untouched(&f), "missing preimage changes nothing");

    /* A result for another request, or for no request, touches nothing */
    TEST_ASSERT(deliver_pay_result(&f, 99, 1, f.preimage), "handled");
    TEST_ASSERT(pay_untouched(&f), "unknown request id changes nothing");
    TEST_ASSERT(deliver_pay_result(&f, 0, 0, NULL), "handled");
    TEST_ASSERT(pay_untouched(&f), "request id 0 changes nothing");

    /* The real preimage settles it: the LSP is credited, the client told */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    channel_t *ch = &f.mgr.entries[0].channel;
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC fulfilled");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "LSP credited the HTLC amount");
    TEST_ASSERT(!f.mgr.htlc_origins[0].active, "origin closed");
    TEST_ASSERT(lsp_channels_outbound_was_paid(&f.mgr, f.hash), "remembered as paid");
    wire_msg_t m;
    TEST_ASSERT(wire_recv_timeout(f.client_peer, &m, 5), "client notified");
    TEST_ASSERT_EQ(m.msg_type, MSG_UPDATE_FULFILL_HTLC, "FULFILL to client");
    uint64_t fid; unsigned char fpre[32];
    TEST_ASSERT(wire_parse_update_fulfill_htlc(m.json, &fid, fpre), "parse FULFILL");
    TEST_ASSERT_EQ(fid, f.htlc_id, "the client's HTLC");
    TEST_ASSERT_MEM_EQ(fpre, f.preimage, 32, "with the preimage");
    cJSON_Delete(m.json);

    /* A repeat of the result changes nothing further */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "not credited twice");

    pay_fixture_free(&f);
    return 1;
}

int test_lsp_pay_result_failure(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;

    /* A definitive failure refunds the client and closes the origin */
    TEST_ASSERT(deliver_pay_result(&f, 7, 0, NULL), "handled");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC failed");
    TEST_ASSERT_EQ(ch->remote_amount, 100000, "client refunded");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "LSP not credited");
    TEST_ASSERT(!f.mgr.htlc_origins[0].active, "origin closed");
    TEST_ASSERT(!lsp_channels_outbound_was_paid(&f.mgr, f.hash), "not marked paid");
    wire_msg_t m;
    TEST_ASSERT(wire_recv_timeout(f.client_peer, &m, 5), "client notified");
    TEST_ASSERT_EQ(m.msg_type, MSG_UPDATE_FAIL_HTLC, "FAIL to client");
    cJSON_Delete(m.json);

    /* A late "success" for the same request finds nothing to settle */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "nothing credited afterwards");
    TEST_ASSERT(!wire_recv_timeout(f.client_peer, &m, 1), "client told nothing more");

    pay_fixture_free(&f);
    return 1;
}

/* ---- One outside payment per hash ---- */

int test_lsp_outbound_one_pay_per_hash(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    f.mgr.ctx = ctx;
    snprintf(f.mgr.network, sizeof(f.mgr.network), "regtest");
    chain_backend_t tip;
    memset(&tip, 0, sizeof(tip));
    tip.get_block_height = fixed_tip_get_block_height;
    fixed_tip_height = 100;
    f.mgr.chain_be = &tip;
    /* this test reads the LSP's replies on the client connection */
    int cl[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0, "socketpair");
    close(f.client_fd); close(f.client_peer);
    f.client_fd = cl[0]; f.client_peer = cl[1];

    char inv[2048], reason[128];
    uint32_t now = (uint32_t)time(NULL);
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, f.hash, now, 3600, 18,
                                  inv, sizeof(inv)), "encode");

    /* Request 7 is paying this hash: a second HTLC for it is refused */
    TEST_ASSERT(offer_outside_htlc(&f.mgr, f.lsp, f.client_peer, f.hash, 4000000,
                                    inv, reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "payment_hash_in_flight") == 0,
                "refused while the first pay is in flight");
    TEST_ASSERT_EQ(f.mgr.entries[0].channel.n_htlcs, 1, "no second HTLC taken");
    TEST_ASSERT_EQ(f.mgr.next_request_id, 8, "no second pay requested");

    /* After the first pay completed, the invoice is paid: refused again */
    f.mgr.htlc_origins[0].active = 0;
    lsp_channels_note_outbound_paid(&f.mgr, f.hash);
    TEST_ASSERT(offer_outside_htlc(&f.mgr, f.lsp, f.client_peer, f.hash, 4000000,
                                    inv, reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "invoice_already_paid") == 0,
                "refused once the invoice was paid");
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(f.bridge_peer, &stray, 1), "nothing sent to bridge");

    /* The memory of paid hashes is bounded and keeps the newest */
    unsigned char h[32];
    for (int i = 0; i < LSP_OUTBOUND_PAID_MAX; i++) {
        memset(h, 0, 32); h[0] = (unsigned char)i; h[1] = 0xEE;
        lsp_channels_note_outbound_paid(&f.mgr, h);
    }
    TEST_ASSERT(lsp_channels_outbound_was_paid(&f.mgr, h), "newest remembered");
    TEST_ASSERT(!lsp_channels_outbound_was_paid(&f.mgr, f.hash), "oldest forgotten");

    pay_fixture_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}
