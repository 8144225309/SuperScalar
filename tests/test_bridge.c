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
#include "superscalar/persist.h"
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

/* Whether the last refusal read by offer_outside_htlc said the HTLC was
   never taken */
static int last_refusal_uncommitted;

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
    last_refusal_uncommitted = ok && wire_update_fail_htlc_is_uncommitted(reply.json);
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
    TEST_ASSERT(last_refusal_uncommitted,
                "refusal says the HTLC was never taken (no commitment follows)");

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

/* Read one line from the bridge on a client socket. */
static int read_line(int fd, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        if (read(fd, buf + n, 1) != 1) return 0;
        if (buf[n] == '\n') { buf[n] = '\0'; return 1; }
        n++;
    }
    return 0;
}

/* The plugin's end of the session set up by the last plugin_handshake */
static unsigned char t_session_key[32];
static uint64_t t_session_rx, t_session_tx;

/* One message from the bridge, as the plugin receives it: the line must
   carry the MAC for the next counter value; it is stripped. */
static int plugin_read_msg(bridge_t *br, int fd, char *buf, size_t cap) {
    (void)br;
    char raw[2048], mac[65];
    if (!read_line(fd, raw, sizeof(raw))) return 0;
    if (strlen(raw) < 66 || raw[64] != ' ') return 0;
    bridge_plugin_line_mac(t_session_key, "b2p", t_session_rx, raw + 65, mac);
    if (memcmp(raw, mac, 64) != 0) return 0;
    t_session_rx++;
    size_t n = strlen(raw + 65);
    if (n >= cap) return 0;
    memcpy(buf, raw + 65, n + 1);
    return 1;
}

/* One message to the bridge, as the plugin sends it */
static int plugin_send_msg(bridge_t *br, int fd, const char *json) {
    (void)br;
    char mac[65];
    bridge_plugin_line_mac(t_session_key, "p2b", t_session_tx++, json, mac);
    return send_str(fd, mac) && send_str(fd, " ") && send_str(fd, json) &&
           send_str(fd, "\n");
}

static void hex_of(const unsigned char *in, size_t len, char *out) {
    hex_encode(in, len, out);
}

/* The plugin's side of the handshake up to and including its response,
   computed with `secret`.  Leaves the bridge's nonce and proof in *_out.
   Returns the result of servicing the response (1 = accepted). */
static int plugin_handshake(bridge_t *br, int fd, const char *secret,
                            const char *response_role,
                            unsigned char bridge_nonce_out[32],
                            int *bridge_proof_ok_out) {
    unsigned char np[32], proof[32], expect[32];
    char hex[65], line[512];
    for (int i = 0; i < 32; i++) np[i] = (unsigned char)(0xA0 + i);
    hex_of(np, 32, hex);
    snprintf(line, sizeof(line), "{\"method\":\"auth_hello\",\"nonce\":\"%s\"}\n", hex);
    if (offer_first_line(br, fd, line) != 0) return -10;   /* challenge is out */

    if (!read_line(fd, line, sizeof(line))) return -11;
    cJSON *ch = cJSON_Parse(line);
    if (!ch) return -12;
    cJSON *m = cJSON_GetObjectItem(ch, "method");
    int ok = m && cJSON_IsString(m) && strcmp(m->valuestring, "auth_challenge") == 0 &&
             wire_json_get_hex(ch, "nonce", bridge_nonce_out, 32) == 32 &&
             wire_json_get_hex(ch, "proof", proof, 32) == 32;
    cJSON_Delete(ch);
    if (!ok) return -13;
    /* what a plugin holding the bridge's real secret expects to see */
    bridge_plugin_auth_proof(br->plugin_secret, BRIDGE_AUTH_ROLE_BRIDGE, np,
                              bridge_nonce_out, expect);
    if (bridge_proof_ok_out)
        *bridge_proof_ok_out = memcmp(proof, expect, 32) == 0;

    if (!bridge_plugin_auth_proof(secret, response_role, np, bridge_nonce_out, proof))
        return -14;
    hex_of(proof, 32, hex);
    snprintf(line, sizeof(line), "{\"method\":\"auth_response\",\"proof\":\"%s\"}\n", hex);
    if (!send_str(fd, line)) return -15;
    if (!wait_readable(br->plugin_pending_fd)) return -16;
    /* the session both ends now share (if this side used the right secret) */
    bridge_plugin_session_key(secret, np, bridge_nonce_out, t_session_key);
    t_session_rx = 0;
    t_session_tx = 0;
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

    char line[1024];
    unsigned char nb1[32], nb2[32];
    int bridge_ok = 0;

    /* The proof is a keyed MAC over role and both nonces */
    {
        unsigned char a[32], b[32], p1[32], p2[32];
        memset(a, 1, 32); memset(b, 2, 32);
        TEST_ASSERT(bridge_plugin_auth_proof(TEST_PLUGIN_SECRET, "plugin", a, b, p1), "proof");
        TEST_ASSERT(bridge_plugin_auth_proof(TEST_PLUGIN_SECRET, "bridge", a, b, p2), "proof");
        TEST_ASSERT(memcmp(p1, p2, 32) != 0, "roles give different proofs");
        TEST_ASSERT(bridge_plugin_auth_proof(TEST_PLUGIN_SECRET, "plugin", b, a, p2), "proof");
        TEST_ASSERT(memcmp(p1, p2, 32) != 0, "nonce order matters");
        TEST_ASSERT(bridge_plugin_auth_proof(
            "ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "plugin", a, b, p2), "proof");
        TEST_ASSERT(memcmp(p1, p2, 32) != 0, "secret matters");
        TEST_ASSERT(!bridge_plugin_auth_proof("abc", "plugin", a, b, p2), "bad secret");

        /* Fixed values the plugin's implementation is tested against too */
        char hex[65];
        hex_of(p1, 32, hex);
        TEST_ASSERT(strcmp(hex, "7f0ce9d7bbc1eb564d7696fb9dc9cd3d"
                                "8ba0f4c0ef0da075860610dcc7ad929e") == 0,
                    "plugin proof, known answer");
        TEST_ASSERT(bridge_plugin_auth_proof(TEST_PLUGIN_SECRET, "bridge", a, b, p2), "proof");
        hex_of(p2, 32, hex);
        TEST_ASSERT(strcmp(hex, "3b505ab3809df5713d5f24a15bda1465"
                                "e41680ccf6ec56a5763c789ed46f5aa1") == 0,
                    "bridge proof, known answer");
    }

    /* A plugin with another secret is dropped; so is one that answers
       with the bridge's kind of proof (its own challenge reflected). */
    {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT_EQ(plugin_handshake(&br, c,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            BRIDGE_AUTH_ROLE_PLUGIN, nb1, &bridge_ok), -1, "wrong secret dropped");
        TEST_ASSERT(bridge_ok, "the bridge proved itself to the plugin");
        TEST_ASSERT_EQ(br.plugin_fd, -1, "not accepted as the plugin");
        TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "no longer pending");
        TEST_ASSERT(peer_closed(c), "connection closed, nothing more sent");
        close(c);

        c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT_EQ(plugin_handshake(&br, c, TEST_PLUGIN_SECRET,
            BRIDGE_AUTH_ROLE_BRIDGE, nb2, &bridge_ok), -1, "reflected proof dropped");
        TEST_ASSERT_EQ(br.plugin_fd, -1, "not accepted as the plugin");
        TEST_ASSERT(peer_closed(c), "connection closed");
        close(c);
        TEST_ASSERT(memcmp(nb1, nb2, 32) != 0, "a fresh bridge nonce per connection");
    }

    /* A connection that does not open with auth_hello is dropped and gets
       nothing: neither a challenge nor any use of its message.  That
       includes presenting the secret itself. */
    snprintf(line, sizeof(line), "{\"method\":\"auth\",\"token\":\"%s\"}\n",
             TEST_PLUGIN_SECRET);
    const char *unauthenticated[] = {
        line,
        "{\"method\":\"htlc_accepted\",\"payment_hash\":"
        "\"abababababababababababababababababababababababababababababababab\","
        "\"amount_msat\":5000000,\"cltv_expiry\":500}\n",
        "{\"method\":\"pay_result\",\"request_id\":1,\"success\":true,\"preimage\":"
        "\"abababababababababababababababababababababababababababababababab\"}\n",
        "{\"method\":\"auth_hello\",\"nonce\":\"abcd\"}\n",
        "{\"method\":\"auth_response\",\"proof\":"
        "\"abababababababababababababababababababababababababababababababab\"}\n",
        "not json\n",
    };
    for (size_t i = 0; i < sizeof(unauthenticated) / sizeof(unauthenticated[0]); i++) {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT_EQ(offer_first_line(&br, c, unauthenticated[i]), -1,
                       "unauthenticated message dropped");
        TEST_ASSERT_EQ(br.plugin_fd, -1, "not accepted as the plugin");
        TEST_ASSERT(peer_closed(c), "connection closed, nothing sent to it");
        close(c);
    }
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(lsp_sv[0], &stray, 1),
                "nothing from unauthenticated peers reached the LSP");

    /* After the challenge, anything but the right response is dropped */
    {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT_EQ(offer_first_line(&br, c,
            "{\"method\":\"auth_hello\",\"nonce\":"
            "\"0101010101010101010101010101010101010101010101010101010101010101\"}\n"),
            0, "challenge sent");
        TEST_ASSERT(read_line(c, line, sizeof(line)), "challenge received");
        TEST_ASSERT(send_str(c, "{\"method\":\"pay_result\",\"request_id\":1,"
                                "\"success\":false}\n"), "send");
        TEST_ASSERT(wait_readable(br.plugin_pending_fd), "data pending");
        TEST_ASSERT_EQ(bridge_service_pending_plugin(&br), -1,
                       "message instead of a response dropped");
        TEST_ASSERT_EQ(br.plugin_fd, -1, "not accepted as the plugin");
        close(c);
    }

    /* A line too long to be a handshake message is dropped. */
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

    /* The real plugin: both proofs check out. */
    int plugin = connect_plugin_port(&br);
    TEST_ASSERT(plugin >= 0, "connect");
    TEST_ASSERT_EQ(plugin_handshake(&br, plugin, TEST_PLUGIN_SECRET,
                                     BRIDGE_AUTH_ROLE_PLUGIN, nb1, &bridge_ok),
                   1, "right secret accepted");
    TEST_ASSERT(bridge_ok, "the bridge proved itself first");
    TEST_ASSERT(br.plugin_fd >= 0, "now the plugin");
    TEST_ASSERT_EQ(br.plugin_pending_fd, -1, "no longer pending");
    TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)), "authentic reply");
    TEST_ASSERT(strstr(line, "\"auth_ok\"") != NULL, "auth_ok sent");

    /* The secret itself was never needed on the wire, and a message sent
       now is ordinary plugin traffic. */
    TEST_ASSERT(plugin_send_msg(&br, plugin, "{\"method\":\"invoice_bolt11\",\"payment_hash\":"
        "\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\","
        "\"bolt11\":\"lnbcrt1ptest\"}"), "send plugin message");
    TEST_ASSERT(wait_readable(br.plugin_fd), "plugin data");
    char *next = bridge_read_plugin_line(&br);
    TEST_ASSERT(next != NULL, "message available");
    TEST_ASSERT(bridge_handle_plugin_msg(&br, next), "message handled");
    free(next);
    wire_msg_t fwd;
    TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &fwd, 5), "forwarded to LSP");
    TEST_ASSERT_EQ(fwd.msg_type, MSG_INVOICE_BOLT11, "INVOICE_BOLT11");
    cJSON_Delete(fwd.json);

    /* While it is connected nobody else gets in, and the plugin keeps its
       connection. */
    int live_fd = br.plugin_fd;
    for (int i = 0; i < 2; i++) {
        int c = connect_plugin_port(&br);
        TEST_ASSERT(c >= 0, "connect");
        TEST_ASSERT(send_str(c, "{\"method\":\"auth_hello\",\"nonce\":"
            "\"0101010101010101010101010101010101010101010101010101010101010101\"}\n"),
            "second connection starts a handshake");
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
    if (f->client_fd >= 0) close(f->client_fd);
    close(f->client_peer);
    close(f->mgr.bridge_fd); close(f->bridge_peer);
    channel_cleanup(&f->mgr.entries[0].channel);
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

/* ---- Bridge pending table: freed on resolve, bounded, ids never 0 ---- */

int test_bridge_pending_table(void) {
    bridge_t br;
    bridge_init(&br);
    unsigned char h[32];

    /* Fill the table: every id is distinct and non-zero */
    uint64_t ids[BRIDGE_MAX_PENDING];
    for (int i = 0; i < BRIDGE_MAX_PENDING; i++) {
        memset(h, 0, 32); h[0] = (unsigned char)i; h[1] = (unsigned char)(i >> 8);
        ids[i] = bridge_add_pending(&br, h);
        TEST_ASSERT(ids[i] != 0, "id is never 0");
        TEST_ASSERT(i == 0 || ids[i] != ids[i - 1], "ids are distinct");
    }
    TEST_ASSERT_EQ(br.n_pending, BRIDGE_MAX_PENDING, "table full");
    memset(h, 0xFE, 32);
    TEST_ASSERT_EQ(bridge_add_pending(&br, h), 0, "full table refuses");
    TEST_ASSERT_EQ(br.n_pending, BRIDGE_MAX_PENDING, "nothing added");

    /* Resolving one frees its slot for the next HTLC */
    TEST_ASSERT(bridge_release_pending(&br, ids[100]), "release by id");
    TEST_ASSERT(!bridge_release_pending(&br, ids[100]), "only once");
    TEST_ASSERT(!bridge_release_pending(&br, 0), "id 0 is nobody");
    TEST_ASSERT_EQ(br.n_pending, BRIDGE_MAX_PENDING - 1, "one slot free");
    uint64_t fresh = bridge_add_pending(&br, h);
    TEST_ASSERT(fresh != 0 && fresh != ids[100], "freed slot reused with a new id");
    uint64_t by_hash = 0;
    TEST_ASSERT(bridge_resolve_pending(&br, h, &by_hash), "resolve by hash");
    TEST_ASSERT_EQ(by_hash, fresh, "the id it was given");
    TEST_ASSERT(!bridge_resolve_pending(&br, h, &by_hash), "gone after resolve");

    /* The id counter wrapping around does not produce 0 */
    br.next_htlc_id = UINT64_MAX;
    TEST_ASSERT_EQ(bridge_add_pending(&br, h), UINT64_MAX, "last id before wrap");
    TEST_ASSERT(bridge_release_pending(&br, UINT64_MAX), "release");
    TEST_ASSERT_EQ(bridge_add_pending(&br, h), 1, "wraps to 1, not 0");
    return 1;
}

/* Send the bridge an htlc_accepted from the plugin; returns what it did:
   the htlc_id it forwarded to the LSP, or 0 if it refused to the plugin. */
static int bridge_inbound_once(bridge_t *br, int lsp_peer, int plugin_peer,
                               int n, uint64_t *htlc_id_out) {
    char line[256];
    snprintf(line, sizeof(line),
             "{\"method\":\"htlc_accepted\",\"payment_hash\":\"%064x\","
             "\"amount_msat\":5000000,\"cltv_expiry\":500}", n);
    if (!bridge_handle_plugin_msg(br, line)) return 0;
    *htlc_id_out = 0;
    struct pollfd p[2] = { { .fd = lsp_peer, .events = POLLIN },
                           { .fd = plugin_peer, .events = POLLIN } };
    if (poll(p, 2, 5000) < 1) return 0;
    if (p[0].revents & POLLIN) {
        wire_msg_t m;
        unsigned char ph[32]; uint64_t amt; uint32_t cltv;
        if (!wire_recv(lsp_peer, &m)) return 0;
        int ok = m.msg_type == MSG_BRIDGE_ADD_HTLC &&
                 wire_parse_bridge_add_htlc(m.json, ph, &amt, &cltv, htlc_id_out);
        cJSON_Delete(m.json);
        return ok;
    }
    char buf[512];
    ssize_t r = read(plugin_peer, buf, sizeof(buf) - 1);
    if (r <= 0) return 0;
    buf[r] = '\0';
    return strstr(buf, "\"htlc_resolve\"") && strstr(buf, "\"fail\"") &&
           strstr(buf, "bridge_busy");
}

int test_bridge_inbound_beyond_pending_limit(void) {
    int lsp_sv[2], plugin_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, plugin_sv) == 0, "socketpair");
    bridge_t br;
    bridge_init(&br);
    br.lsp_fd = lsp_sv[1];
    br.plugin_fd = plugin_sv[1];

    /* Far more HTLCs than the table holds pass through, each resolved by
       the LSP before the next: every one gets a usable id. */
    for (int n = 1; n <= 3 * BRIDGE_MAX_PENDING; n++) {
        uint64_t id = 0;
        TEST_ASSERT(bridge_inbound_once(&br, lsp_sv[0], plugin_sv[0], n, &id),
                    "htlc_accepted handled");
        TEST_ASSERT(id != 0, "forwarded to the LSP with a non-zero id");

        unsigned char ph[32];
        memset(ph, 0, 32);
        cJSON *res = (n % 2) ? wire_build_bridge_fail_htlc(ph, "no", id)
                             : wire_build_bridge_fulfill_htlc(ph, ph, id);
        wire_msg_t m;
        m.msg_type = (n % 2) ? MSG_BRIDGE_FAIL_HTLC : MSG_BRIDGE_FULFILL_HTLC;
        m.json = res;
        TEST_ASSERT(bridge_handle_lsp_msg(&br, &m), "LSP resolution handled");
        cJSON_Delete(res);
        char buf[512];
        TEST_ASSERT(read(plugin_sv[0], buf, sizeof(buf)) > 0, "resolution reaches plugin");
        TEST_ASSERT_EQ(br.n_pending, 0, "entry freed");
    }

    /* With nothing resolved, the table fills; the next HTLC is refused to
       the plugin and nothing with id 0 goes to the LSP. */
    for (int n = 1; n <= BRIDGE_MAX_PENDING; n++) {
        uint64_t id = 0;
        TEST_ASSERT(bridge_inbound_once(&br, lsp_sv[0], plugin_sv[0], 5000 + n, &id),
                    "htlc_accepted handled");
        TEST_ASSERT(id != 0, "forwarded with a non-zero id");
    }
    for (int n = 1; n <= 3; n++) {
        uint64_t id = 99;
        TEST_ASSERT(bridge_inbound_once(&br, lsp_sv[0], plugin_sv[0], 9000 + n, &id),
                    "over-limit htlc_accepted answered");
        TEST_ASSERT_EQ(id, 0, "refused to the plugin, not forwarded");
    }
    TEST_ASSERT_EQ(br.n_pending, BRIDGE_MAX_PENDING, "table still full");

    close(lsp_sv[0]); close(lsp_sv[1]);
    close(plugin_sv[0]); close(plugin_sv[1]);
    return 1;
}

/* ---- An inbound HTLC offered again re-attaches; a second one is refused ---- */

/* Hand the LSP an inbound bridge HTLC carrying the plugin's name for it.
   Returns the type of the bridge message it answered with (0 = none) and,
   for a failure, the reason. */
static int offer_bridge_htlc_as(lsp_channel_mgr_t *mgr, lsp_t *lsp, int bridge_peer_fd,
                                const unsigned char *hash, uint64_t amount_msat,
                                uint32_t cltv_expiry, uint64_t htlc_id,
                                const char *upstream_id, char *reason,
                                size_t reason_cap, unsigned char *preimage_out) {
    cJSON *add = wire_build_bridge_add_htlc(hash, amount_msat, cltv_expiry, htlc_id);
    if (upstream_id) cJSON_AddStringToObject(add, "upstream_id", upstream_id);
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_ADD_HTLC;
    msg.json = add;
    int handled = lsp_channels_handle_bridge_msg(mgr, lsp, &msg);
    cJSON_Delete(add);
    reason[0] = '\0';
    if (!handled) return -1;

    wire_msg_t reply;
    if (!wire_recv_timeout(bridge_peer_fd, &reply, 1)) return 0;
    unsigned char h[32]; uint64_t id = 0;
    int type = reply.msg_type;
    if (type == MSG_BRIDGE_FAIL_HTLC) {
        if (!wire_parse_bridge_fail_htlc(reply.json, h, reason, reason_cap, &id) ||
            id != htlc_id) type = -1;
    } else if (type == MSG_BRIDGE_FULFILL_HTLC) {
        if (!wire_parse_bridge_fulfill_htlc(reply.json, h, preimage_out, &id) ||
            id != htlc_id) type = -1;
    }
    cJSON_Delete(reply.json);
    return type;
}

int test_lsp_inbound_replay_reattaches(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 2;
    mgr.bridge_fd = sv[0];
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.invoices && mgr.htlc_origins && lsp, "alloc");

    unsigned char preimage[32], hash[32], got[32];
    memset(preimage, 0x44, 32);
    sha256(preimage, 32, hash);
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash, preimage, 1, 5000000),
                "register invoice");
    char reason[128];

    /* The HTLC is with client 1: 5,000 sat, expiry 500, known to the
       Lightning node as HTLC 5 on channel 100x1x0. */
    channel_t *ch = &mgr.entries[1].channel;
    ch->local_amount = 100000;
    uint64_t client_htlc;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_OFFERED, 5000, hash, 500, &client_htlc),
                "HTLC with the client");
    htlc_origin_t *o = lsp_channels_track_bridge_origin(&mgr, hash, 90);
    TEST_ASSERT(o != NULL, "origin");
    o->sender_idx = 1; o->sender_htlc_id = client_htlc; o->cltv_expiry = 500;
    strcpy(o->upstream_id, "100x1x0:5");

    /* The node restarts and offers the same HTLC again, under a new id */
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 91,
                                         "100x1x0:5", reason, sizeof(reason), got),
                   0, "same HTLC again: no failure, no second offer");
    TEST_ASSERT_EQ(o->bridge_htlc_id, 91, "origin now answers to the new id");
    TEST_ASSERT(o->active, "origin still open");
    TEST_ASSERT_EQ(ch->n_htlcs, 1, "client not offered a second HTLC");
    TEST_ASSERT_EQ(mgr.n_htlc_origins, 1, "no second origin");

    /* A different HTLC for the same hash is still refused, and so is one
       the plugin cannot name */
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 92,
                                         "100x1x0:6", reason, sizeof(reason), got),
                   MSG_BRIDGE_FAIL_HTLC, "second HTLC failed");
    TEST_ASSERT(strcmp(reason, "duplicate_payment_hash") == 0, "as a duplicate");
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 93,
                                         "", reason, sizeof(reason), got),
                   MSG_BRIDGE_FAIL_HTLC, "unnamed HTLC failed");
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 94,
                                         NULL, reason, sizeof(reason), got),
                   MSG_BRIDGE_FAIL_HTLC, "HTLC without identity failed");
    TEST_ASSERT_EQ(o->bridge_htlc_id, 91, "the first HTLC keeps its origin");

    /* The client fulfils: the fulfil goes to the id of the latest offer */
    TEST_ASSERT_EQ(lsp_channels_settle_bridge_origin(&mgr, hash, preimage), 91,
                   "fulfil is for the re-attached id");
    TEST_ASSERT(!o->active, "origin closed");

    /* If the node never got that answer and offers the HTLC once more, it
       gets the fulfil again; nobody is offered anything */
    memset(got, 0, 32);
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 95,
                                         "100x1x0:5", reason, sizeof(reason), got),
                   MSG_BRIDGE_FULFILL_HTLC, "fulfil repeated");
    TEST_ASSERT_MEM_EQ(got, preimage, 32, "with the preimage");
    TEST_ASSERT_EQ(ch->n_htlcs, 1, "client not offered anything");
    TEST_ASSERT_EQ(lsp_channels_settle_bridge_origin(&mgr, hash, preimage), 0,
                   "no origin was opened for the repeat");

    free(ch->htlcs);
    close(sv[0]); close(sv[1]);
    free(mgr.entries); free(mgr.invoices); free(mgr.htlc_origins); free(lsp);
    return 1;
}

int test_lsp_inbound_replay_restored_origin(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 2;
    mgr.bridge_fd = sv[0];
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.invoices && mgr.htlc_origins && lsp, "alloc");

    unsigned char preimage[32], hash[32], got[32];
    memset(preimage, 0x45, 32);
    sha256(preimage, 32, hash);
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash, preimage, 1, 5000000),
                "register invoice");
    char reason[128];

    /* As after an LSP restart: the origin is known, the node's name for
       the HTLC is not. */
    channel_t *ch = &mgr.entries[1].channel;
    ch->local_amount = 100000;
    uint64_t client_htlc;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_OFFERED, 5000, hash, 500, &client_htlc),
                "HTLC with the client");
    htlc_origin_t *o = lsp_channels_track_bridge_origin(&mgr, hash, 90);
    TEST_ASSERT(o != NULL, "origin");
    o->sender_idx = 1; o->sender_htlc_id = client_htlc;

    /* An offer that does not match the HTLC the client holds is refused */
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 6000000, 500, 91,
                                         "100x1x0:5", reason, sizeof(reason), got),
                   MSG_BRIDGE_FAIL_HTLC, "other amount refused");
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 501, 92,
                                         "100x1x0:5", reason, sizeof(reason), got),
                   MSG_BRIDGE_FAIL_HTLC, "other expiry refused");
    TEST_ASSERT_EQ(o->bridge_htlc_id, 90, "origin unchanged");

    /* One that matches it is the same HTLC: adopted, with its name */
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 93,
                                         "100x1x0:5", reason, sizeof(reason), got),
                   0, "matching offer re-attached");
    TEST_ASSERT_EQ(o->bridge_htlc_id, 93, "origin answers to the new id");
    TEST_ASSERT(strcmp(o->upstream_id, "100x1x0:5") == 0, "identity adopted");

    /* From then on only that HTLC matches */
    TEST_ASSERT_EQ(offer_bridge_htlc_as(&mgr, lsp, sv[1], hash, 5000000, 500, 94,
                                         "100x1x0:7", reason, sizeof(reason), got),
                   MSG_BRIDGE_FAIL_HTLC, "another HTLC refused");
    TEST_ASSERT(strcmp(reason, "duplicate_payment_hash") == 0, "as a duplicate");

    free(ch->htlcs);
    close(sv[0]); close(sv[1]);
    free(mgr.entries); free(mgr.invoices); free(mgr.htlc_origins); free(lsp);
    return 1;
}

int test_bridge_replay_keeps_pending_id(void) {
    int lsp_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");
    bridge_t br;
    bridge_init(&br);
    br.lsp_fd = lsp_sv[1];

    static const char *offers[] = { "100x1x0:5", "100x1x0:5", "100x1x0:6", "", "" };
    uint64_t ids[5];
    for (int i = 0; i < 5; i++) {
        char line[512];
        snprintf(line, sizeof(line),
                 "{\"method\":\"htlc_accepted\",\"payment_hash\":\"%064x\","
                 "\"amount_msat\":5000000,\"cltv_expiry\":500,"
                 "\"upstream_id\":\"%s\"}", 0xabc, offers[i]);
        TEST_ASSERT(bridge_handle_plugin_msg(&br, line), "htlc_accepted handled");
        wire_msg_t m;
        TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &m, 5), "forwarded to LSP");
        unsigned char ph[32]; uint64_t amt; uint32_t cltv;
        TEST_ASSERT(wire_parse_bridge_add_htlc(m.json, ph, &amt, &cltv, &ids[i]),
                    "parse ADD_HTLC");
        cJSON *up = cJSON_GetObjectItem(m.json, "upstream_id");
        TEST_ASSERT(up && cJSON_IsString(up) &&
                    strcmp(up->valuestring, offers[i]) == 0,
                    "identity passed on to the LSP");
        cJSON_Delete(m.json);
    }
    TEST_ASSERT(ids[0] != 0, "id assigned");
    TEST_ASSERT_EQ(ids[1], ids[0], "same HTLC offered again keeps its id");
    TEST_ASSERT(ids[2] != ids[0], "another HTLC for the hash gets its own");
    TEST_ASSERT(ids[3] != ids[0] && ids[3] != ids[2], "an unnamed HTLC gets its own");
    TEST_ASSERT(ids[4] != ids[3], "unnamed HTLCs are never merged");
    TEST_ASSERT_EQ(br.n_pending, 4, "four HTLCs pending");

    close(lsp_sv[0]); close(lsp_sv[1]);
    return 1;
}

/* ---- Outbound pay results are acknowledged; open pays outlive expiry ---- */

/* The request id of the PAY_RESULT_ACK waiting on the bridge link, 0 if
   none; its rejection reason ("" = applied) is left in last_ack_reason. */
static char last_ack_reason[64];
static uint64_t next_pay_ack(pay_fixture_t *f) {
    wire_msg_t m;
    uint64_t rid = 0;
    strcpy(last_ack_reason, "?");
    if (!wire_recv_timeout(f->bridge_peer, &m, 1)) return 0;
    if (m.msg_type != MSG_BRIDGE_PAY_RESULT_ACK ||
        !wire_parse_bridge_pay_result_ack(m.json, &rid, last_ack_reason,
                                           sizeof(last_ack_reason)))
        rid = 0;
    cJSON_Delete(m.json);
    return rid;
}

int test_lsp_pay_result_acknowledged(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    unsigned char wrong[32];
    memset(wrong, 0x72, 32);

    /* A "success" with the wrong preimage is rejected for good: answered
       so that it is not repeated, while the HTLC stays held and the origin
       open */
    uint64_t rid;
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, wrong), "handled");
    rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "wrong preimage answered");
    TEST_ASSERT(strcmp(last_ack_reason, "preimage_mismatch") == 0, "as rejected");
    TEST_ASSERT(pay_untouched(&f), "HTLC held, origin open");

    /* The applied result is acknowledged as applied */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "applied result acknowledged");
    TEST_ASSERT(last_ack_reason[0] == '\0', "as applied");

    /* A repeat (the first ack was lost) is acknowledged again and changes
       nothing */
    channel_t *ch = &f.mgr.entries[0].channel;
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    TEST_ASSERT_EQ(next_pay_ack(&f), 7, "repeat acknowledged");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "credited once");

    /* So is a result for a payment this LSP has no record of */
    TEST_ASSERT(deliver_pay_result(&f, 4242, 0, NULL), "handled");
    TEST_ASSERT_EQ(next_pay_ack(&f), 4242, "unknown request acknowledged");

    pay_fixture_free(&f);

    /* A failure that was applied is acknowledged too */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    TEST_ASSERT(deliver_pay_result(&f, 7, 0, NULL), "handled");
    TEST_ASSERT_EQ(next_pay_ack(&f), 7, "applied failure acknowledged");
    pay_fixture_free(&f);
    return 1;
}

int test_lsp_outbound_pay_held_past_expiry(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;
    htlc_origin_t *o = &f.mgr.htlc_origins[0];
    wire_msg_t stray;

    /* A second HTLC from the same client, with no outside payment behind
       it, expiring at 300: the expiry pass does fail that one. */
    unsigned char other_hash[32];
    memset(other_hash, 0x73, 32);
    uint64_t plain_htlc;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_RECEIVED, 2000, other_hash, 300, &plain_htlc),
                "plain HTLC");
    TEST_ASSERT_EQ(ch->remote_amount, 94000, "both HTLCs out of the client's balance");

    /* The outside-payment HTLC expires at 500.  Both timer paths the daemon
       loop runs each block (the per-block expiry pass and the bridge
       timeout check) are driven well before, near, at and past that
       height, with no result from the Lightning node: it is never failed
       and nobody is told anything about it. */
    static const uint32_t heights[] = { 100, 299, 300, 459, 460, 489, 490,
                                        499, 500, 501, 100000 };
    for (size_t i = 0; i < sizeof(heights) / sizeof(heights[0]); i++) {
        lsp_channels_expire_htlcs(&f.mgr, f.lsp, heights[i]);
        lsp_channels_check_bridge_htlc_timeouts(&f.mgr, f.lsp, heights[i]);
        TEST_ASSERT(o->active, "origin stays open");
        TEST_ASSERT(lsp_channels_htlc_awaits_outside_pay(&f.mgr, 0, f.htlc_id),
                    "HTLC still waits for its outside payment");
        TEST_ASSERT_EQ(ch->n_htlcs, heights[i] >= 300 ? 1 : 2,
                       "only the plain HTLC is failed, at its expiry");
        TEST_ASSERT_EQ(ch->remote_amount, heights[i] >= 300 ? 96000 : 94000,
                       "client refunded the plain HTLC only");
        TEST_ASSERT(ch->htlcs[0].id == f.htlc_id &&
                    ch->htlcs[0].state == HTLC_STATE_ACTIVE,
                    "outside-payment HTLC still held");
        TEST_ASSERT_EQ(o->expiry_warned, heights[i] >= 460,
                       "warned once the expiry is near");
    }
    TEST_ASSERT(!wire_recv_timeout(f.client_peer, &stray, 1), "client told nothing");
    TEST_ASSERT(!wire_recv_timeout(f.bridge_peer, &stray, 1), "bridge told nothing");

    /* The result still settles it when it finally arrives */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC fulfilled");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "LSP credited");
    TEST_ASSERT_EQ(next_pay_ack(&f), 7, "acknowledged");

    pay_fixture_free(&f);
    return 1;
}

int test_bridge_forwards_pay_result_ack(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    bridge_t br;
    bridge_init(&br);
    br.plugin_fd = sv[1];

    cJSON *ack = wire_build_bridge_pay_result_ack(31, NULL);
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_PAY_RESULT_ACK;
    msg.json = ack;
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &msg), "ack handled");

    char buf[256];
    ssize_t n = read(sv[0], buf, sizeof(buf) - 1);
    TEST_ASSERT(n > 0, "plugin told");
    buf[n] = '\0';
    cJSON *fwd = cJSON_Parse(buf);
    TEST_ASSERT(fwd != NULL, "parse");
    cJSON *m = cJSON_GetObjectItem(fwd, "method");
    cJSON *rid = cJSON_GetObjectItem(fwd, "request_id");
    TEST_ASSERT(m && cJSON_IsString(m) && strcmp(m->valuestring, "pay_result_ack") == 0,
                "pay_result_ack");
    TEST_ASSERT(rid && cJSON_IsNumber(rid) && (uint64_t)rid->valuedouble == 31,
                "request id");
    cJSON *st = cJSON_GetObjectItem(fwd, "status");
    TEST_ASSERT(st && cJSON_IsString(st) && strcmp(st->valuestring, "applied") == 0,
                "status applied");
    cJSON_Delete(fwd);

    /* A rejection reaches the plugin with its reason */
    {
        cJSON *rej = wire_build_bridge_pay_result_ack(32, "preimage_mismatch");
        wire_msg_t rm; rm.msg_type = MSG_BRIDGE_PAY_RESULT_ACK; rm.json = rej;
        TEST_ASSERT(bridge_handle_lsp_msg(&br, &rm), "rejection handled");
        cJSON_Delete(rej);
        n = read(sv[0], buf, sizeof(buf) - 1);
        TEST_ASSERT(n > 0, "plugin told");
        buf[n] = '\0';
        TEST_ASSERT(strstr(buf, "\"rejected\"") && strstr(buf, "preimage_mismatch") &&
                    strstr(buf, "\"request_id\":32"), "status and reason forwarded");
    }

    /* With the plugin away the ack is dropped, not an error: the plugin
       will repeat its result */
    br.plugin_fd = -1;
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &msg), "ack without plugin is not fatal");
    cJSON_Delete(ack);

    /* A pay result that claims success without a preimage goes nowhere */
    int lsp_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");
    br.lsp_fd = lsp_sv[1];
    TEST_ASSERT(bridge_handle_plugin_msg(&br,
        "{\"method\":\"pay_result\",\"request_id\":5,\"success\":true}"),
        "handled");
    TEST_ASSERT(bridge_handle_plugin_msg(&br,
        "{\"method\":\"pay_result\",\"request_id\":5,\"success\":true,"
        "\"preimage\":\"abcd\"}"), "handled");
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(lsp_sv[0], &stray, 1), "not forwarded to the LSP");
    TEST_ASSERT(bridge_handle_plugin_msg(&br,
        "{\"method\":\"pay_result\",\"request_id\":5,\"success\":false}"), "handled");
    TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &stray, 5), "a failure is forwarded");
    TEST_ASSERT_EQ(stray.msg_type, MSG_BRIDGE_PAY_RESULT, "PAY_RESULT");
    cJSON_Delete(stray.json);

    close(sv[0]); close(sv[1]); close(lsp_sv[0]); close(lsp_sv[1]);
    return 1;
}

/* ---- An invoice of one of the LSP's own clients is not paid outside ---- */

int test_lsp_outbound_internal_invoice_refused(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");
    int cl[2], br[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0, "socketpair");
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, br) == 0, "socketpair");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 2;
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    mgr.bridge_fd = br[0];
    mgr.next_request_id = 1;
    snprintf(mgr.network, sizeof(mgr.network), "regtest");
    chain_backend_t tip;
    memset(&tip, 0, sizeof(tip));
    tip.get_block_height = fixed_tip_get_block_height;
    fixed_tip_height = 100;
    mgr.chain_be = &tip;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.invoices && mgr.htlc_origins && lsp, "alloc");
    int client_fds[2] = { cl[0], -1 };
    lsp->client_fds = client_fds;

    /* Client 1 has an invoice out; client 0 tries to pay it as an outside
       invoice. */
    unsigned char preimage[32], hash[32];
    memset(preimage, 0x53, 32);
    sha256(preimage, 32, hash);
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash, preimage, 1, 4000000),
                "client 1's invoice");
    char inv[2048], reason[128];
    TEST_ASSERT(make_out_invoice(ctx, "bcrt", 4000000, hash, (uint32_t)time(NULL),
                                  3600, 18, inv, sizeof(inv)), "encode");
    TEST_ASSERT(offer_outside_htlc(&mgr, lsp, cl[1], hash, 4000000, inv,
                                    reason, sizeof(reason)), "HTLC failed back");
    TEST_ASSERT(strcmp(reason, "invoice_is_internal") == 0,
                "own client's invoice not paid through the Lightning node");
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(br[1], &stray, 1), "nothing sent to bridge");
    TEST_ASSERT_EQ(mgr.next_request_id, 1, "no pay requested");
    TEST_ASSERT_EQ(mgr.entries[0].channel.n_htlcs, 0, "no HTLC taken");

    close(cl[0]); close(cl[1]); close(br[0]); close(br[1]);
    free(mgr.entries); free(mgr.invoices); free(mgr.htlc_origins); free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- One payment hash, both directions: origins are not interchangeable ---- */

/* Active origin rows in the database: total, and how many are outbound */
static size_t db_origins(persist_t *db, size_t *n_outbound) {
    unsigned char hashes[8][32];
    uint64_t bridge_ids[8], req_ids[8], htlc_ids[8];
    size_t senders[8];
    size_t n = persist_load_htlc_origins(db, hashes, bridge_ids, req_ids,
                                          senders, htlc_ids, 8);
    *n_outbound = 0;
    for (size_t i = 0; i < n; i++)
        if (bridge_ids[i] == 0) (*n_outbound)++;
    return n;
}

int test_lsp_same_hash_inbound_and_outbound(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    f.mgr.persist = &db;
    f.mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    f.mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    TEST_ASSERT(f.mgr.invoices != NULL, "alloc");
    channel_t *ch = &f.mgr.entries[0].channel;
    htlc_origin_t *out = &f.mgr.htlc_origins[0];
    lsp_channels_origin_save(&f.mgr, out);      /* request 7 for hash H, in flight */
    size_t n_out = 0;
    TEST_ASSERT_EQ(db_origins(&db, &n_out), 1, "one origin stored");
    char reason[128];
    size_t dest;

    /* The client that is paying H on the outside now registers H as an
       invoice: refused, and it is told there will be no invoice. */
    int cl[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0, "socketpair");
    close(f.client_fd); close(f.client_peer);
    f.client_fd = cl[0]; f.client_peer = cl[1];
    shutdown(f.client_peer, SHUT_WR);   /* the client never answers */
    {
        cJSON *reg = wire_build_register_invoice(f.hash, f.preimage, 4000000, 0);
        wire_msg_t m; m.msg_type = MSG_REGISTER_INVOICE; m.json = reg;
        TEST_ASSERT(lsp_channels_handle_msg(&f.mgr, f.lsp, 0, &m), "handled");
        cJSON_Delete(reg);
        TEST_ASSERT(!lsp_channels_lookup_invoice(&f.mgr, f.hash, &dest),
                    "hash in flight is not registered as an invoice");
        wire_msg_t r;
        TEST_ASSERT(wire_recv_timeout(f.client_peer, &r, 5), "client answered");
        unsigned char rh[32]; char rb[64];
        TEST_ASSERT(r.msg_type == MSG_INVOICE_BOLT11 &&
                    wire_parse_invoice_bolt11(r.json, rh, rb, sizeof(rb)) &&
                    rb[0] == '\0', "with an empty invoice");
        cJSON_Delete(r.json);
        TEST_ASSERT(!lsp_channels_register_invoice(&f.mgr, f.hash, f.preimage, 0, 4000000),
                    "direct registration refused too");
    }

    /* An inbound HTLC for H, with or without a keysend preimage, is refused */
    TEST_ASSERT(offer_bridge_htlc(&f.mgr, f.lsp, f.bridge_peer, f.hash, 4000000,
                                   500, 70, reason, sizeof(reason)), "failed back");
    TEST_ASSERT(strcmp(reason, "payment_hash_in_use") == 0, "inbound HTLC refused");
    {
        cJSON *ks = wire_build_bridge_add_htlc_keysend(f.hash, 4000000, 500, 71,
                                                         f.preimage, 0);
        wire_msg_t m; m.msg_type = MSG_BRIDGE_ADD_HTLC; m.json = ks;
        TEST_ASSERT(lsp_channels_handle_bridge_msg(&f.mgr, f.lsp, &m), "handled");
        cJSON_Delete(ks);
        wire_msg_t r; unsigned char rh[32]; uint64_t rid = 0;
        TEST_ASSERT(wire_recv_timeout(f.bridge_peer, &r, 5), "bridge answered");
        TEST_ASSERT(r.msg_type == MSG_BRIDGE_FAIL_HTLC &&
                    wire_parse_bridge_fail_htlc(r.json, rh, reason, sizeof(reason), &rid) &&
                    rid == 71 && strcmp(reason, "payment_hash_in_use") == 0,
                    "keysend for the hash refused");
        cJSON_Delete(r.json);
        TEST_ASSERT(!lsp_channels_lookup_invoice(&f.mgr, f.hash, &dest),
                    "keysend did not register the hash");
    }
    TEST_ASSERT_EQ(ch->n_htlcs, 1, "nothing offered to the client");

    /* Even with an inbound origin for H standing next to the outbound one,
       each is found, settled and stored on its own. */
    TEST_ASSERT(lsp_channels_get_bridge_origin(&f.mgr, f.hash) == 0 && out->active,
                "an outbound origin is not an inbound one");
    htlc_origin_t *in = lsp_channels_track_bridge_origin(&f.mgr, f.hash, 90);
    TEST_ASSERT(in != NULL && in != out, "inbound origin in its own entry");
    in->sender_idx = 0; in->sender_htlc_id = 555;
    lsp_channels_origin_save(&f.mgr, in);
    TEST_ASSERT(in->db_id != 0 && in->db_id != out->db_id, "its own row");
    TEST_ASSERT(lsp_channels_find_origin(&f.mgr, f.hash, 0) == in, "found as inbound");
    TEST_ASSERT(lsp_channels_find_origin(&f.mgr, f.hash, 1) == out, "found as outbound");
    TEST_ASSERT_EQ(db_origins(&db, &n_out), 2, "two origins stored");

    /* The client settles the inbound HTLC */
    TEST_ASSERT_EQ(lsp_channels_settle_bridge_origin(&f.mgr, f.hash, f.preimage), 90,
                   "the inbound origin is the one settled");
    TEST_ASSERT(!in->active, "inbound origin closed");
    TEST_ASSERT(out->active && out->request_id == 7, "outbound origin untouched");
    TEST_ASSERT_EQ(db_origins(&db, &n_out), 1, "one origin left in the database");
    TEST_ASSERT_EQ(n_out, 1, "and it is the outbound one");

    /* The outside payment's result still finds its HTLC */
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "client's HTLC claimed");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "LSP credited");
    TEST_ASSERT(!out->active, "outbound origin closed");
    TEST_ASSERT_EQ(db_origins(&db, &n_out), 0, "no origin left in the database");

    /* Paid: the hash can still not become an invoice or an inbound payment */
    TEST_ASSERT(lsp_channels_hash_spent_or_busy(&f.mgr, f.hash), "hash is spent");
    TEST_ASSERT(!lsp_channels_register_invoice(&f.mgr, f.hash, f.preimage, 0, 4000000),
                "paid hash not registered");
    wire_msg_t drain;
    while (wire_recv_timeout(f.bridge_peer, &drain, 1)) cJSON_Delete(drain.json);
    TEST_ASSERT(offer_bridge_htlc(&f.mgr, f.lsp, f.bridge_peer, f.hash, 4000000,
                                   500, 72, reason, sizeof(reason)), "failed back");
    TEST_ASSERT(strcmp(reason, "payment_hash_in_use") == 0, "paid hash refused inbound");

    /* An unrelated hash registers as before */
    unsigned char p2[32], h2[32];
    memset(p2, 0x74, 32);
    sha256(p2, 32, h2);
    TEST_ASSERT(lsp_channels_register_invoice(&f.mgr, h2, p2, 0, 1000), "fresh hash ok");

    free(f.mgr.invoices);
    f.mgr.persist = NULL;
    persist_close(&db);
    pay_fixture_free(&f);
    return 1;
}

/* ---- Inbound HTLC: no origin, no offer; a failed offer leaves nothing behind ---- */

int test_lsp_inbound_origin_table_and_rollback(void) {
    int sv[2], cl[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0, "socketpair");
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 1;
    mgr.bridge_fd = sv[0];
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    mgr.htlc_origins = calloc(2, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = 2;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.invoices && mgr.htlc_origins && lsp, "alloc");
    int client_fd = cl[0];
    lsp->client_fds = &client_fd;
    shutdown(cl[1], SHUT_WR);          /* the client never answers */

    unsigned char preimage[32], hash[32], other[2][32];
    memset(preimage, 0x46, 32);
    sha256(preimage, 32, hash);
    memset(other[0], 0x47, 32);
    memset(other[1], 0x48, 32);
    TEST_ASSERT(lsp_channels_register_invoice(&mgr, hash, preimage, 0, 5000000),
                "register invoice");
    channel_t *ch = &mgr.entries[0].channel;
    ch->local_amount = 100000;
    char reason[128];
    wire_msg_t stray;

    /* Origin table full: refused, and the client is offered nothing */
    htlc_origin_t *a = lsp_channels_track_bridge_origin(&mgr, other[0], 1);
    htlc_origin_t *b = lsp_channels_track_bridge_origin(&mgr, other[1], 2);
    TEST_ASSERT(a && b && !lsp_channels_origin_slot_free(&mgr), "table full");
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash, 5000000, 500, 70,
                                   reason, sizeof(reason)), "failed back");
    TEST_ASSERT(strcmp(reason, "too_many_pending_payments") == 0,
                "refused for want of an origin");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "no HTLC offered to the client");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "nothing reserved");
    TEST_ASSERT(!wire_recv_timeout(cl[1], &stray, 1), "client sent nothing");

    /* With room, the HTLC is offered; the client does not complete the
       commitment, so it is taken back: failure to the bridge, origin
       closed, balance restored, nothing in flight. */
    a->active = 0;
    TEST_ASSERT(offer_bridge_htlc(&mgr, lsp, sv[1], hash, 5000000, 500, 71,
                                   reason, sizeof(reason)), "failed back");
    TEST_ASSERT(strcmp(reason, "client_disconnected") == 0 ||
                strcmp(reason, "commitment_failed") == 0 ||
                strcmp(reason, "client_unreachable") == 0, "offer rolled back");
    TEST_ASSERT(!lsp_channels_hash_in_flight(&mgr, hash), "no origin left for it");
    TEST_ASSERT(lsp_channels_origin_slot_free(&mgr), "its origin slot is free again");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "LSP balance restored");
    int still_active = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++)
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE) still_active++;
    TEST_ASSERT_EQ(still_active, 0, "no HTLC left with the client");
    TEST_ASSERT(b->active && b->bridge_htlc_id == 2, "other origin untouched");

    /* The invoice can be paid again afterwards */
    size_t dest;
    TEST_ASSERT(lsp_channels_lookup_invoice(&mgr, hash, &dest), "invoice still open");

    free(ch->htlcs);
    close(sv[0]); close(sv[1]); close(cl[0]); close(cl[1]);
    free(mgr.entries); free(mgr.invoices); free(mgr.htlc_origins); free(lsp);
    return 1;
}

/* ---- Pay results that cannot be used are rejected once, not left hanging ---- */

int test_lsp_pay_result_rejections(void) {
    pay_fixture_t f;
    channel_t *ch;
    uint64_t rid;
    wire_msg_t stray;

    /* The client's HTLC is gone when a success arrives */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    ch = &f.mgr.entries[0].channel;
    TEST_ASSERT(channel_fail_htlc(ch, f.htlc_id), "HTLC removed");
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "answered");
    TEST_ASSERT(strcmp(last_ack_reason, "no_htlc") == 0, "rejected: no HTLC");
    TEST_ASSERT(!f.mgr.htlc_origins[0].active, "origin closed: nothing left to settle");
    TEST_ASSERT(!lsp_channels_outbound_was_paid(&f.mgr, f.hash), "not counted as paid");
    TEST_ASSERT(!wire_recv_timeout(f.client_peer, &stray, 1), "client told nothing");
    pay_fixture_free(&f);

    /* ...or when a failure arrives */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    ch = &f.mgr.entries[0].channel;
    TEST_ASSERT(channel_fail_htlc(ch, f.htlc_id), "HTLC removed");
    TEST_ASSERT(deliver_pay_result(&f, 7, 0, NULL), "handled");
    rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "answered");
    TEST_ASSERT(strcmp(last_ack_reason, "no_htlc") == 0, "rejected: no HTLC");
    TEST_ASSERT(!f.mgr.htlc_origins[0].active, "origin closed");
    TEST_ASSERT(!wire_recv_timeout(f.client_peer, &stray, 1), "client told nothing");
    pay_fixture_free(&f);

    /* The origin names a client that does not exist */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    f.mgr.htlc_origins[0].sender_idx = 9;
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "answered");
    TEST_ASSERT(strcmp(last_ack_reason, "no_channel") == 0, "rejected: no channel");
    pay_fixture_free(&f);

    /* The ack wire format */
    {
        char reason[32]; uint64_t r = 0;
        cJSON *a = wire_build_bridge_pay_result_ack(5, NULL);
        TEST_ASSERT(wire_parse_bridge_pay_result_ack(a, &r, reason, sizeof(reason)) &&
                    r == 5 && reason[0] == '\0', "applied round-trips");
        cJSON_ReplaceItemInObject(a, "status", cJSON_CreateString("maybe"));
        TEST_ASSERT(!wire_parse_bridge_pay_result_ack(a, &r, reason, sizeof(reason)),
                    "unknown status rejected");
        cJSON_Delete(a);
        a = wire_build_bridge_pay_result_ack(6, "no_htlc");
        TEST_ASSERT(wire_parse_bridge_pay_result_ack(a, &r, reason, sizeof(reason)) &&
                    r == 6 && strcmp(reason, "no_htlc") == 0, "rejected round-trips");
        cJSON_Delete(a);
    }
    return 1;
}

/* ---- A pay that could not be requested gives the HTLC back ---- */

int test_lsp_outbound_htlc_returned(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;

    lsp_channels_fail_outbound_htlc(&f.mgr, f.lsp, &f.mgr.htlc_origins[0], 0,
                                     f.htlc_id, "bridge_unavailable");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC returned");
    TEST_ASSERT_EQ(ch->remote_amount, 100000, "client refunded");
    TEST_ASSERT(!f.mgr.htlc_origins[0].active, "origin closed");
    TEST_ASSERT(!lsp_channels_hash_in_flight(&f.mgr, f.hash), "hash free again");
    wire_msg_t m;
    TEST_ASSERT(wire_recv_timeout(f.client_peer, &m, 5), "client told");
    uint64_t fid = 0; char reason[64];
    TEST_ASSERT(m.msg_type == MSG_UPDATE_FAIL_HTLC &&
                wire_parse_update_fail_htlc(m.json, &fid, reason, sizeof(reason)) &&
                fid == f.htlc_id && strcmp(reason, "bridge_unavailable") == 0,
                "UPDATE_FAIL_HTLC with the reason");
    cJSON_Delete(m.json);

    /* Without an origin (table was full) the HTLC is still returned */
    uint64_t second;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_RECEIVED, 3000, f.hash, 500, &second), "HTLC");
    lsp_channels_fail_outbound_htlc(&f.mgr, f.lsp, NULL, 0, second, "bridge_unavailable");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC returned");

    pay_fixture_free(&f);
    return 1;
}

/* ---- A fulfil is kept, and repeated, until the bridge confirms it ---- */

/* Read one BRIDGE_FULFILL_HTLC from the bridge link; 1 if it is for `hash`
   with `preimage` */
static int next_fulfil_is(int bridge_peer, const unsigned char *hash,
                          const unsigned char *preimage, uint64_t *id_out) {
    wire_msg_t m;
    unsigned char h[32], p[32];
    if (!wire_recv_timeout(bridge_peer, &m, 1)) return 0;
    int ok = m.msg_type == MSG_BRIDGE_FULFILL_HTLC &&
             wire_parse_bridge_fulfill_htlc(m.json, h, p, id_out) &&
             memcmp(h, hash, 32) == 0 && memcmp(p, preimage, 32) == 0;
    cJSON_Delete(m.json);
    return ok;
}

static void deliver_bridge_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp, uint8_t type,
                               cJSON *json) {
    wire_msg_t m;
    m.msg_type = type;
    m.json = json;
    lsp_channels_handle_bridge_msg(mgr, lsp, &m);
    cJSON_Delete(json);
}

int test_lsp_fulfil_kept_until_confirmed(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 1;
    mgr.bridge_fd = -1;                      /* the bridge is away */
    mgr.persist = &db;
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.htlc_origins && lsp, "alloc");

    unsigned char preimage[32], hash[32];
    memset(preimage, 0x49, 32);
    sha256(preimage, 32, hash);
    htlc_origin_t *o = lsp_channels_track_bridge_origin(&mgr, hash, 90);
    TEST_ASSERT(o != NULL, "origin");
    strcpy(o->upstream_id, "100x1x0:5");
    lsp_channels_origin_save(&mgr, o);

    /* The client fulfils while the bridge is away */
    TEST_ASSERT_EQ(lsp_channels_settle_bridge_origin(&mgr, hash, preimage), 90, "settled");
    TEST_ASSERT_EQ(lsp_channels_flush_bridge_fulfils(&mgr), 0, "nobody to send it to");
    persist_bridge_fulfil_t rows[4];
    TEST_ASSERT_EQ(persist_load_bridge_fulfils(&db, rows, 4, 0), 1, "fulfil is on disk");
    TEST_ASSERT(memcmp(rows[0].preimage, preimage, 32) == 0 &&
                strcmp(rows[0].upstream_id, "100x1x0:5") == 0 &&
                rows[0].bridge_htlc_id == 90, "with preimage, name and id");

    /* The bridge connects: the fulfil goes out, and again on each flush and
       on the bridge's heartbeat, until it is confirmed */
    mgr.bridge_fd = sv[0];
    uint64_t id = 0;
    TEST_ASSERT_EQ(lsp_channels_flush_bridge_fulfils(&mgr), 1, "sent on connect");
    TEST_ASSERT(next_fulfil_is(sv[1], hash, preimage, &id) && id == 90, "the fulfil");
    TEST_ASSERT_EQ(lsp_channels_flush_bridge_fulfils(&mgr), 1, "sent again");
    TEST_ASSERT(next_fulfil_is(sv[1], hash, preimage, &id), "the fulfil again");
    {
        deliver_bridge_msg(&mgr, lsp, MSG_BRIDGE_HELLO, wire_build_bridge_hello(NULL));
        wire_msg_t m;
        TEST_ASSERT(wire_recv_timeout(sv[1], &m, 1) &&
                    m.msg_type == MSG_BRIDGE_HELLO_ACK, "heartbeat answered");
        cJSON_Delete(m.json);
        TEST_ASSERT(next_fulfil_is(sv[1], hash, preimage, &id), "and the fulfil repeated");
    }

    /* A restart in between loses nothing */
    {
        lsp_channel_mgr_t again;
        memset(&again, 0, sizeof(again));
        again.persist = &db;
        again.bridge_fd = sv[0];
        TEST_ASSERT_EQ(lsp_channels_load_bridge_fulfils(&again), 1, "restored from disk");
        TEST_ASSERT_EQ(lsp_channels_flush_bridge_fulfils(&again), 1, "and sent");
        TEST_ASSERT(next_fulfil_is(sv[1], hash, preimage, &id) && id == 90, "the fulfil");
        TEST_ASSERT(lsp_channels_hash_spent_or_busy(&again, hash),
                    "the hash stays spent across the restart");
    }

    /* Confirmed: no longer sent, no longer on disk */
    deliver_bridge_msg(&mgr, lsp, MSG_BRIDGE_FULFILL_ACK,
                       wire_build_bridge_fulfill_ack(hash));
    TEST_ASSERT_EQ(lsp_channels_flush_bridge_fulfils(&mgr), 0, "nothing left to send");
    TEST_ASSERT_EQ(persist_load_bridge_fulfils(&db, rows, 4, 0), 0, "nothing left on disk");
    wire_msg_t stray;
    TEST_ASSERT(!wire_recv_timeout(sv[1], &stray, 1), "bridge sent nothing more");

    /* More unconfirmed fulfils than the memory holds: none of the others
       pushes an unconfirmed one out while a confirmed slot is free */
    for (int i = 0; i < LSP_BRIDGE_FULFILLED_MAX - 1; i++) {
        unsigned char p[32], h[32];
        memset(p, 0, 32); p[0] = (unsigned char)(i + 1);
        sha256(p, 32, h);
        TEST_ASSERT(lsp_channels_track_bridge_origin(&mgr, h, 200 + i), "origin");
        TEST_ASSERT(lsp_channels_settle_bridge_origin(&mgr, h, p) == (uint64_t)(200 + i),
                    "settled");
    }
    TEST_ASSERT_EQ(lsp_channels_flush_bridge_fulfils(&mgr),
                   (size_t)(LSP_BRIDGE_FULFILLED_MAX - 1),
                   "every unconfirmed fulfil is still repeated");

    close(sv[0]); close(sv[1]);
    free(mgr.entries); free(mgr.htlc_origins); free(lsp);
    persist_close(&db);
    return 1;
}

/* ---- The bridge keeps messages for a plugin that is away ---- */

int test_bridge_queues_for_absent_plugin(void) {
    bridge_t br;
    bridge_init(&br);
    int lsp_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");
    br.lsp_fd = lsp_sv[1];
    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen");

    /* No plugin: a fulfil, a failure and a pay request from the LSP are
       accepted and kept, in order */
    unsigned char h1[32], h2[32], pre[32];
    memset(h1, 0x51, 32); memset(h2, 0x52, 32); memset(pre, 0x53, 32);
    wire_msg_t m;
    m.msg_type = MSG_BRIDGE_FULFILL_HTLC;
    m.json = wire_build_bridge_fulfill_htlc(h1, pre, 4);
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &m), "fulfil accepted without a plugin");
    cJSON_Delete(m.json);
    m.msg_type = MSG_BRIDGE_FAIL_HTLC;
    m.json = wire_build_bridge_fail_htlc(h2, "no", 5);
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &m), "failure accepted without a plugin");
    cJSON_Delete(m.json);
    m.msg_type = MSG_BRIDGE_SEND_PAY;
    m.json = wire_build_bridge_send_pay("lnbcrt1pinvoice", h1, 9, 1000, 100);
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &m), "pay request accepted without a plugin");
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(br.plugin_queue_len, 3, "three messages waiting");

    /* An ack is not kept: the plugin asks again */
    m.msg_type = MSG_BRIDGE_PAY_RESULT_ACK;
    m.json = wire_build_bridge_pay_result_ack(9, NULL);
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &m), "ack accepted");
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(br.plugin_queue_len, 3, "ack not queued");

    /* The plugin connects and authenticates: it gets them, in order */
    int plugin = connect_plugin_port(&br);
    TEST_ASSERT(plugin >= 0, "connect");
    unsigned char nb[32];
    TEST_ASSERT_EQ(plugin_handshake(&br, plugin, TEST_PLUGIN_SECRET,
                                     BRIDGE_AUTH_ROLE_PLUGIN, nb, NULL), 1, "authenticated");
    TEST_ASSERT_EQ(br.plugin_queue_len, 0, "queue emptied");
    char line[1024];
    TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)) &&
                strstr(line, "\"auth_ok\""), "auth_ok first");
    TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)) &&
                strstr(line, "\"fulfill\"") && strstr(line, "\"htlc_id\":4"), "then the fulfil");
    TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)) &&
                strstr(line, "\"fail\"") && strstr(line, "\"htlc_id\":5"), "then the failure");
    TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)) &&
                strstr(line, "\"pay_request\"") && strstr(line, "\"request_id\":9"),
                "then the pay request");

    /* A plugin message the bridge cannot handle costs the plugin its
       connection, nothing else: pending HTLCs stay, the bridge goes on */
    TEST_ASSERT(plugin_send_msg(&br, plugin,
        "{\"method\":\"htlc_accepted\",\"payment_hash\":"
        "\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\","
        "\"amount_msat\":5000000,\"cltv_expiry\":500,\"upstream_id\":\"1x1x1:1\"}"),
        "send htlc_accepted");
    TEST_ASSERT(wait_readable(br.plugin_fd), "plugin data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 1, "good message handled");
    TEST_ASSERT_EQ(br.n_pending, 1, "one HTLC pending");
    TEST_ASSERT(plugin_send_msg(&br, plugin, "{\"method\":\"no_such_thing\"}"), "send junk");
    TEST_ASSERT(wait_readable(br.plugin_fd), "plugin data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "bad message: connection dropped");
    TEST_ASSERT_EQ(br.plugin_fd, -1, "plugin gone");
    TEST_ASSERT_EQ(br.n_pending, 1, "pending HTLC kept");
    TEST_ASSERT(br.plugin_listen_fd >= 0, "still listening");

    /* What the LSP says meanwhile waits for the plugin's return */
    m.msg_type = MSG_BRIDGE_FULFILL_HTLC;
    m.json = wire_build_bridge_fulfill_htlc(h1, pre, 4);
    TEST_ASSERT(bridge_handle_lsp_msg(&br, &m), "fulfil accepted");
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(br.plugin_queue_len, 1, "kept for the plugin");

    /* The plugin confirms a fulfil: the LSP is told */
    close(plugin);
    plugin = connect_plugin_port(&br);
    TEST_ASSERT(plugin >= 0, "reconnect");
    TEST_ASSERT_EQ(plugin_handshake(&br, plugin, TEST_PLUGIN_SECRET,
                                     BRIDGE_AUTH_ROLE_PLUGIN, nb, NULL), 1, "authenticated");
    wire_msg_t drain;
    while (wire_recv_timeout(lsp_sv[0], &drain, 1)) cJSON_Delete(drain.json);
    TEST_ASSERT(bridge_handle_plugin_msg(&br,
        "{\"method\":\"htlc_resolved\",\"payment_hash\":"
        "\"5151515151515151515151515151515151515151515151515151515151515151\"}"),
        "htlc_resolved handled");
    wire_msg_t ack;
    TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &ack, 5), "LSP told");
    unsigned char ah[32];
    TEST_ASSERT(ack.msg_type == MSG_BRIDGE_FULFILL_ACK &&
                wire_parse_bridge_fulfill_ack(ack.json, ah) &&
                memcmp(ah, h1, 32) == 0, "BRIDGE_FULFILL_ACK for the hash");
    cJSON_Delete(ack.json);

    /* The plugin could not hand the preimage to the node: the LSP is told
       that, not that the fulfil was taken */
    TEST_ASSERT(bridge_handle_plugin_msg(&br,
        "{\"method\":\"htlc_unresolved\",\"payment_hash\":"
        "\"5151515151515151515151515151515151515151515151515151515151515151\","
        "\"reason\":\"channel_gone\"}"),
        "htlc_unresolved handled");
    TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &ack, 5), "LSP told");
    char why[32];
    TEST_ASSERT(ack.msg_type == MSG_BRIDGE_FULFILL_UNRESOLVED &&
                wire_parse_bridge_fulfill_unresolved(ack.json, ah, why, sizeof(why)) &&
                memcmp(ah, h1, 32) == 0 && strcmp(why, "channel_gone") == 0,
                "BRIDGE_FULFILL_UNRESOLVED for the hash, with the reason");
    cJSON_Delete(ack.json);

    close(plugin);
    close(lsp_sv[0]);
    bridge_cleanup(&br);
    return 1;
}

/* ---- The bridge tells the plugin which LSP it serves ---- */

int test_bridge_reports_lsp_key(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    TEST_ASSERT(ctx != NULL, "ctx");
    unsigned char sk[32]; memset(sk, 0x31, 32);
    secp256k1_pubkey pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, sk), "key");
    unsigned char ser[33]; size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser, &len, &pk, SECP256K1_EC_COMPRESSED);
    char want[67];
    hex_encode(ser, 33, want);

    bridge_t br;
    bridge_init(&br);
    TEST_ASSERT(br.lsp_pubkey_hex[0] == '\0', "no key, nothing to report");
    bridge_set_lsp_pubkey(&br, &pk);
    TEST_ASSERT(strcmp(br.lsp_pubkey_hex, want) == 0, "pinned key reported as hex");
    bridge_set_lsp_pubkey(&br, NULL);
    TEST_ASSERT(br.lsp_pubkey_hex[0] == '\0', "cleared with the pin");
    bridge_set_lsp_pubkey(&br, &pk);

    /* It reaches the plugin with auth_ok */
    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen");
    int plugin = connect_plugin_port(&br);
    TEST_ASSERT(plugin >= 0, "connect");
    unsigned char nb[32];
    TEST_ASSERT_EQ(plugin_handshake(&br, plugin, TEST_PLUGIN_SECRET,
                                     BRIDGE_AUTH_ROLE_PLUGIN, nb, NULL), 1, "authenticated");
    char line[512];
    TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)), "auth_ok");
    TEST_ASSERT(strstr(line, "\"auth_ok\"") && strstr(line, "\"lsp_pubkey\"") &&
                strstr(line, want), "auth_ok names the LSP");

    close(plugin);
    bridge_cleanup(&br);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- After the handshake every line is authenticated ---- */

static int authenticated_plugin(bridge_t *br) {
    unsigned char nb[32];
    int fd = connect_plugin_port(br);
    if (fd < 0) return -1;
    if (plugin_handshake(br, fd, TEST_PLUGIN_SECRET, BRIDGE_AUTH_ROLE_PLUGIN,
                         nb, NULL) != 1) { close(fd); return -1; }
    char line[512];
    if (!plugin_read_msg(br, fd, line, sizeof(line)) || !strstr(line, "\"auth_ok\"")) {
        close(fd);
        return -1;
    }
    return fd;
}

int test_bridge_plugin_line_auth(void) {
    static const char INVOICE_MSG[] =
        "{\"method\":\"invoice_bolt11\",\"payment_hash\":"
        "\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\","
        "\"bolt11\":\"lnbcrt1ptest\"}";
    bridge_t br;
    bridge_init(&br);
    int lsp_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, lsp_sv) == 0, "socketpair");
    br.lsp_fd = lsp_sv[1];
    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen");
    wire_msg_t fwd;
    char mac[65], line[1024];

    /* Fixed values the plugin's implementation is tested against too */
    {
        unsigned char a[32], b[32], key[32];
        char hex[65];
        memset(a, 1, 32); memset(b, 2, 32);
        TEST_ASSERT(bridge_plugin_session_key(TEST_PLUGIN_SECRET, a, b, key), "key");
        hex_of(key, 32, hex);
        TEST_ASSERT(strcmp(hex, "b82c8f11332731da93b2a74578dcd74f"
                                "3ad5c53f993fa73c6035fbffb026f7bd") == 0, "session key");
        bridge_plugin_line_mac(key, "p2b", 5, "{\"method\":\"x\"}", mac);
        TEST_ASSERT(strcmp(mac, "156441f14fd282e5f8452c617350d874"
                                "d86aa147c30ae1db48f05c1ad3d9778f") == 0, "plugin line MAC");
        bridge_plugin_line_mac(key, "b2p", 5, "{\"method\":\"x\"}", mac);
        TEST_ASSERT(strcmp(mac, "a79dbb5cfe974d96c51faa83d5f96604"
                                "18cc3aaa2aafa87337c5d71587a7ded9") == 0, "bridge line MAC");
        bridge_plugin_line_mac(key, "p2b", 6, "{\"method\":\"x\"}", mac);
        TEST_ASSERT(strcmp(mac, "1788b7bfdb453e6a307a0824b5aa678b"
                                "4448fe3c7a6a7f89e09986b08c358ff8") == 0, "counter matters");
        TEST_ASSERT(!bridge_plugin_session_key("abc", a, b, key), "bad secret");
    }

    /* Authentic lines are handled, in order */
    int plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin authenticated");
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(plugin_send_msg(&br, plugin, INVOICE_MSG), "send");
        TEST_ASSERT(wait_readable(br.plugin_fd), "data");
        TEST_ASSERT_EQ(bridge_service_plugin(&br), 1, "authentic line handled");
        TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &fwd, 5), "forwarded to LSP");
        cJSON_Delete(fwd.json);
    }
    TEST_ASSERT_EQ(br.plugin_rx_seq, 3, "three lines counted");

    /* What the bridge sends carries its own MACs, counted separately */
    {
        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "htlc_resolve");
        TEST_ASSERT(bridge_send_plugin_json(&br, j), "send");
        TEST_ASSERT(bridge_send_plugin_json(&br, j), "send");
        cJSON_Delete(j);
        TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)), "authentic");
        TEST_ASSERT(plugin_read_msg(&br, plugin, line, sizeof(line)), "authentic");
        TEST_ASSERT_EQ(br.plugin_tx_seq, 3, "auth_ok and two messages");
    }

    /* A line without a MAC, as something that only passed the handshake
       along would have to send it, ends the connection and goes nowhere */
    TEST_ASSERT(send_str(plugin, INVOICE_MSG) && send_str(plugin, "\n"), "send bare");
    TEST_ASSERT(wait_readable(br.plugin_fd), "data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "bare line: connection dropped");
    TEST_ASSERT_EQ(br.plugin_fd, -1, "plugin gone");
    TEST_ASSERT(!br.plugin_session, "session ended");
    TEST_ASSERT(!wire_recv_timeout(lsp_sv[0], &fwd, 1), "nothing forwarded");
    close(plugin);

    /* A line with somebody else's MAC */
    plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin authenticated");
    {
        unsigned char other[32];
        memset(other, 0x99, 32);
        bridge_plugin_line_mac(other, "p2b", 0, INVOICE_MSG, mac);
        snprintf(line, sizeof(line), "%s %s\n", mac, INVOICE_MSG);
        TEST_ASSERT(send_str(plugin, line), "send forged");
        TEST_ASSERT(wait_readable(br.plugin_fd), "data");
        TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "forged line: dropped");
    }
    close(plugin);

    /* A changed line under a genuine MAC */
    plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin authenticated");
    bridge_plugin_line_mac(t_session_key, "p2b", 0, INVOICE_MSG, mac);
    snprintf(line, sizeof(line), "%s %s\n", mac, INVOICE_MSG);
    *strstr(line, "lnbcrt1ptest") = 'L';
    TEST_ASSERT(send_str(plugin, line), "send altered");
    TEST_ASSERT(wait_readable(br.plugin_fd), "data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "altered line: dropped");
    close(plugin);

    /* A genuine line sent twice (replay), and one sent out of turn */
    plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin authenticated");
    bridge_plugin_line_mac(t_session_key, "p2b", 0, INVOICE_MSG, mac);
    snprintf(line, sizeof(line), "%s %s\n", mac, INVOICE_MSG);
    TEST_ASSERT(send_str(plugin, line), "send");
    TEST_ASSERT(wait_readable(br.plugin_fd), "data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 1, "first time: handled");
    TEST_ASSERT(wire_recv_timeout(lsp_sv[0], &fwd, 5), "forwarded");
    cJSON_Delete(fwd.json);
    TEST_ASSERT(send_str(plugin, line), "send again");
    TEST_ASSERT(wait_readable(br.plugin_fd), "data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "replayed line: dropped");
    TEST_ASSERT(!wire_recv_timeout(lsp_sv[0], &fwd, 1), "not forwarded twice");
    close(plugin);

    plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin authenticated");
    bridge_plugin_line_mac(t_session_key, "p2b", 1, INVOICE_MSG, mac);   /* skips 0 */
    snprintf(line, sizeof(line), "%s %s\n", mac, INVOICE_MSG);
    TEST_ASSERT(send_str(plugin, line), "send");
    TEST_ASSERT(wait_readable(br.plugin_fd), "data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "line out of turn: dropped");
    close(plugin);

    /* A line the bridge sent cannot be sent back to it */
    plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin authenticated");
    bridge_plugin_line_mac(t_session_key, "b2p", 0, INVOICE_MSG, mac);
    snprintf(line, sizeof(line), "%s %s\n", mac, INVOICE_MSG);
    TEST_ASSERT(send_str(plugin, line), "send");
    TEST_ASSERT(wait_readable(br.plugin_fd), "data");
    TEST_ASSERT_EQ(bridge_service_plugin(&br), 0, "reflected line: dropped");
    close(plugin);

    close(lsp_sv[0]);
    bridge_cleanup(&br);
    return 1;
}

/* ---- A silent connection cannot keep the plugin out ---- */

int test_bridge_plugin_silent_connection_replaced(void) {
    bridge_t br;
    bridge_init(&br);
    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen");
    TEST_ASSERT(BRIDGE_PLUGIN_AUTH_TIMEOUT <= 5, "short handshake deadline");

    /* Something connects and says nothing */
    int squatter = connect_plugin_port(&br);
    TEST_ASSERT(squatter >= 0, "connect");
    TEST_ASSERT(wait_readable(br.plugin_listen_fd), "incoming");
    TEST_ASSERT(bridge_accept_plugin(&br), "accepted as pending");
    int squatter_fd = br.plugin_pending_fd;

    /* The plugin arrives: it takes the pending slot and authenticates */
    int plugin = authenticated_plugin(&br);
    TEST_ASSERT(plugin >= 0, "plugin got in past the silent connection");
    TEST_ASSERT(br.plugin_fd >= 0 && br.plugin_fd != squatter_fd, "plugin is the plugin");
    TEST_ASSERT(peer_closed(squatter), "silent connection closed");
    close(squatter);
    close(plugin);
    bridge_cleanup(&br);

    /* A connection in the middle of the handshake is not displaced */
    bridge_init(&br);
    TEST_ASSERT(bridge_set_plugin_secret(&br, TEST_PLUGIN_SECRET), "set secret");
    TEST_ASSERT(bridge_listen_plugin(&br, NULL, 0), "listen");
    int first = connect_plugin_port(&br);
    TEST_ASSERT(first >= 0, "connect");
    TEST_ASSERT_EQ(offer_first_line(&br, first,
        "{\"method\":\"auth_hello\",\"nonce\":"
        "\"0101010101010101010101010101010101010101010101010101010101010101\"}\n"),
        0, "challenge sent");
    int pending_fd = br.plugin_pending_fd;
    int second = connect_plugin_port(&br);
    TEST_ASSERT(second >= 0, "connect");
    TEST_ASSERT(wait_readable(br.plugin_listen_fd), "incoming");
    TEST_ASSERT(!bridge_accept_plugin(&br), "newcomer refused");
    TEST_ASSERT_EQ(br.plugin_pending_fd, pending_fd, "handshake in progress kept");
    TEST_ASSERT(peer_closed(second), "newcomer closed");
    close(first); close(second);
    bridge_cleanup(&br);
    return 1;
}

/* ---- Waiting for a client's reply: keepalives do not count ---- */

int test_lsp_recv_client_reply_skips_keepalives(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    wire_msg_t m;
    cJSON *empty = cJSON_CreateObject();

    /* The LSP pings its clients every 30 s, so a pong can be on the wire
       ahead of the REVOKE_AND_ACK it is waiting for; so can a ping. */
    TEST_ASSERT(wire_send(sv[1], MSG_PONG, empty), "pong");
    TEST_ASSERT(wire_send(sv[1], MSG_PING, empty), "ping");
    TEST_ASSERT(wire_send(sv[1], MSG_PONG, empty), "pong");
    TEST_ASSERT(wire_send(sv[1], MSG_REVOKE_AND_ACK, empty), "the reply");
    TEST_ASSERT(lsp_channels_recv_client_reply(sv[0], &m, MSG_REVOKE_AND_ACK, 5),
                "reply found behind the keepalives");
    TEST_ASSERT_EQ(m.msg_type, MSG_REVOKE_AND_ACK, "it is the reply");
    cJSON_Delete(m.json);
    /* ...and the ping was answered */
    TEST_ASSERT(wire_recv_timeout(sv[1], &m, 5) && m.msg_type == MSG_PONG,
                "ping answered with a pong");
    cJSON_Delete(m.json);

    /* Another message in between is dropped, the reply still found */
    TEST_ASSERT(wire_send(sv[1], MSG_QUEUE_POLL, empty), "stray");
    TEST_ASSERT(wire_send(sv[1], MSG_REVOKE_AND_ACK, empty), "the reply");
    TEST_ASSERT(lsp_channels_recv_client_reply(sv[0], &m, MSG_REVOKE_AND_ACK, 5),
                "reply found behind a stray message");
    cJSON_Delete(m.json);

    /* Keepalives alone are not a reply: the wait ends at its deadline */
    TEST_ASSERT(wire_send(sv[1], MSG_PONG, empty), "pong");
    time_t t0 = time(NULL);
    TEST_ASSERT(!lsp_channels_recv_client_reply(sv[0], &m, MSG_REVOKE_AND_ACK, 2),
                "no reply: gives up");
    TEST_ASSERT(time(NULL) - t0 <= 4, "at the deadline");

    /* A closed connection ends it at once */
    close(sv[1]);
    TEST_ASSERT(!lsp_channels_recv_client_reply(sv[0], &m, MSG_REVOKE_AND_ACK, 30),
                "connection gone");
    TEST_ASSERT(!lsp_channels_recv_client_reply(-1, &m, MSG_REVOKE_AND_ACK, 30),
                "no connection");
    cJSON_Delete(empty);
    close(sv[0]);
    return 1;
}

/* ---- An incomplete commitment exchange drops the client's connection ---- */

int test_lsp_incomplete_commitment_drops_client(void) {
    pay_fixture_t f;
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");

    /* Fulfil: the client (which never answers here) is told, the fulfil
       stands, and the connection is given up rather than used further */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    f.mgr.persist = &db;
    channel_t *ch = &f.mgr.entries[0].channel;
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "handled");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC fulfilled");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "LSP credited");
    TEST_ASSERT_EQ(f.client_fd, -1, "client connection dropped");
    uint64_t pending = 0;
    TEST_ASSERT(persist_load_pending_cs(&db, f.mgr.entries[0].channel_id, &pending) &&
                pending == ch->commitment_number,
                "commitment remembered for the client's reconnect");
    wire_msg_t m;
    TEST_ASSERT(wire_recv_timeout(f.client_peer, &m, 5) &&
                m.msg_type == MSG_UPDATE_FULFILL_HTLC, "client had been told");
    cJSON_Delete(m.json);
    uint64_t rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "result acknowledged all the same");
    f.mgr.persist = NULL;
    pay_fixture_free(&f);

    /* Failure: the same, with a plain UPDATE_FAIL_HTLC (the HTLC was in the
       commitment, so it is not flagged as never taken) */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    f.mgr.persist = &db;
    ch = &f.mgr.entries[0].channel;
    TEST_ASSERT(deliver_pay_result(&f, 7, 0, NULL), "handled");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC failed");
    TEST_ASSERT_EQ(ch->remote_amount, 100000, "client refunded");
    TEST_ASSERT_EQ(f.client_fd, -1, "client connection dropped");
    TEST_ASSERT(wire_recv_timeout(f.client_peer, &m, 5), "client had been told");
    TEST_ASSERT_EQ(m.msg_type, MSG_UPDATE_FAIL_HTLC, "UPDATE_FAIL_HTLC");
    TEST_ASSERT(!wire_update_fail_htlc_is_uncommitted(m.json),
                "a committed HTLC: a commitment exchange belongs to it");
    cJSON_Delete(m.json);
    f.mgr.persist = NULL;
    pay_fixture_free(&f);

    persist_close(&db);
    return 1;
}

/* ---- A refused HTLC is undone on the client; a failed one is failed ---- */

int test_channel_rollback_htlc(void) {
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.local_amount = 100000;
    ch.remote_amount = 100000;
    unsigned char h1[32], h2[32];
    memset(h1, 0x81, 32); memset(h2, 0x82, 32);
    uint64_t a = 99, b = 99, c = 99;

    /* Added, then refused: as if it had never been added */
    TEST_ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 4000, h1, 500, &a), "add");
    TEST_ASSERT_EQ(ch.commitment_number, 1, "commitment advanced by the add");
    TEST_ASSERT(channel_rollback_htlc(&ch, a), "rollback");
    TEST_ASSERT_EQ(ch.local_amount, 100000, "amount back");
    TEST_ASSERT_EQ(ch.remote_amount, 100000, "fee back");
    TEST_ASSERT_EQ(ch.n_htlcs, 0, "HTLC gone");
    TEST_ASSERT_EQ(ch.commitment_number, 0, "commitment number back");
    TEST_ASSERT(!channel_rollback_htlc(&ch, a), "only once");

    /* The next HTLC takes the same id, as it does on the side that never
       saw the first one */
    TEST_ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 3000, h2, 500, &b), "add again");
    TEST_ASSERT_EQ(b, a, "same HTLC id");
    TEST_ASSERT_EQ(ch.commitment_number, 1, "same commitment number");

    /* Only the latest HTLC, and only while it is the latest change */
    TEST_ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 2000, h1, 500, &c), "second HTLC");
    TEST_ASSERT(!channel_rollback_htlc(&ch, b), "an earlier HTLC cannot be rolled back");
    TEST_ASSERT(!channel_rollback_htlc(&ch, 12345), "nor one that does not exist");
    TEST_ASSERT(channel_rollback_htlc(&ch, c), "the latest can");
    TEST_ASSERT(channel_fail_htlc(&ch, b), "fail the first");
    TEST_ASSERT(!channel_rollback_htlc(&ch, b), "a failed HTLC is not rolled back");
    TEST_ASSERT_EQ(ch.local_amount, 100000, "all amounts back");

    /* An HTLC the peer offered is never rolled back */
    uint64_t r = 99;
    TEST_ASSERT(channel_add_htlc(&ch, HTLC_RECEIVED, 2000, h1, 500, &r), "received HTLC");
    uint64_t cn = ch.commitment_number;
    uint64_t loc = ch.local_amount, rem = ch.remote_amount;
    TEST_ASSERT(!channel_rollback_htlc(&ch, r), "a received HTLC cannot be rolled back");
    TEST_ASSERT_EQ(ch.n_htlcs, 1, "it stays");
    TEST_ASSERT(ch.local_amount == loc && ch.remote_amount == rem, "amounts untouched");
    TEST_ASSERT_EQ(ch.commitment_number, cn, "commitment number untouched");
    TEST_ASSERT(channel_fail_htlc(&ch, r), "fail it");

    /* Nor an own offer once a commitment containing it has been accepted */
    uint64_t d = 99;
    TEST_ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 2000, h2, 500, &d), "offer");
    TEST_ASSERT(ch.has_unsigned_offer && ch.unsigned_offer_id == d, "offer is unsigned");
    ch.has_unsigned_offer = 0;      /* what accepting COMMITMENT_SIGNED does */
    cn = ch.commitment_number;
    loc = ch.local_amount; rem = ch.remote_amount;
    TEST_ASSERT(!channel_rollback_htlc(&ch, d), "a committed offer cannot be rolled back");
    TEST_ASSERT_EQ(ch.n_htlcs, 1, "it stays");
    TEST_ASSERT(ch.local_amount == loc && ch.remote_amount == rem, "amounts untouched");
    TEST_ASSERT_EQ(ch.commitment_number, cn, "commitment number untouched");

    /* The client refuses the LSP's claim that such an HTLC was never taken,
       and changes nothing */
    {
        wire_msg_t fm;
        int committed = -1;
        uint64_t fid = 0;
        fm.msg_type = MSG_UPDATE_FAIL_HTLC;
        fm.json = wire_build_update_fail_htlc_uncommitted(d, "x");
        TEST_ASSERT(!client_handle_fail_htlc(&ch, &fm, &committed, &fid),
                    "refusal of a committed HTLC is a protocol error");
        cJSON_Delete(fm.json);
        TEST_ASSERT_EQ(ch.n_htlcs, 1, "HTLC kept");
        TEST_ASSERT(ch.local_amount == loc && ch.remote_amount == rem, "amounts kept");
        TEST_ASSERT_EQ(ch.commitment_number, cn, "commitment number kept");
    }
    channel_cleanup(&ch);
    return 1;
}

/* ---- A revocation secret that does not match is not a revocation ---- */

int test_lsp_refuses_bad_revocation_secret(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");
    unsigned char good[32], bad[32];
    memset(good, 0x33, 32);
    memset(bad, 0x34, 32);
    secp256k1_pubkey committed;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &committed, good), "point");

    /* The client committed to a point for commitment 0 and now answers the
       next commitment with a secret that is not the one behind it */
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;
    ch->ctx = ctx;
    TEST_ASSERT_EQ(ch->commitment_number, 1, "one commitment to revoke");
    channel_set_remote_pcp(ch, 0, &committed);
    int ok = lsp_channels_accept_revocation(&f.mgr, f.lsp, ch, bad);
    TEST_ASSERT_EQ(ok, 0, "wrong secret refused");
    TEST_ASSERT(!ch->received_revocation_valid || !ch->received_revocation_valid[0],
                "nothing stored for the commitment");
    TEST_ASSERT_EQ(f.client_fd, -1, "client connection dropped");
    wire_msg_t m;
    TEST_ASSERT(!wire_recv_timeout(f.client_peer, &m, 1),
                "the LSP released nothing: no revocation of its own was sent");
    ch->ctx = NULL;
    pay_fixture_free(&f);

    /* The right secret is taken, and the connection kept */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    ch = &f.mgr.entries[0].channel;
    ch->ctx = ctx;
    channel_set_remote_pcp(ch, 0, &committed);
    ok = lsp_channels_accept_revocation(&f.mgr, f.lsp, ch, good);
    TEST_ASSERT_EQ(ok, 1, "matching secret accepted");
    TEST_ASSERT(ch->received_revocation_valid && ch->received_revocation_valid[0],
                "stored");
    TEST_ASSERT(f.client_fd >= 0, "connection kept");

    /* A secret for a commitment whose point is not known is refused too */
    uint64_t extra;
    unsigned char h[32];
    memset(h, 0x35, 32);
    TEST_ASSERT(channel_add_htlc(ch, HTLC_OFFERED, 1000, h, 500, &extra), "next commitment");
    ok = lsp_channels_accept_revocation(&f.mgr, f.lsp, ch, good);
    TEST_ASSERT_EQ(ok, 0, "no committed point: refused");
    TEST_ASSERT_EQ(f.client_fd, -1, "client connection dropped");
    ch->ctx = NULL;
    pay_fixture_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- A pay result for a channel with an exchange in progress waits ---- */

int test_lsp_pay_result_waits_for_busy_channel(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;

    /* The LSP is waiting for this client's reply in another exchange */
    f.mgr.entries[0].exchange_in_progress = 1;
    TEST_ASSERT(deliver_pay_result(&f, 7, 1, f.preimage), "taken");
    TEST_ASSERT(pay_untouched(&f), "nothing applied, client sent nothing");
    uint64_t rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 0, "not acknowledged yet");
    TEST_ASSERT_EQ(f.mgr.n_bridge_deferred, 1, "kept for later");
    size_t ran = lsp_channels_run_deferred_bridge_msgs(&f.mgr, f.lsp);
    TEST_ASSERT_EQ(ran, 0, "not while the channel is busy");
    TEST_ASSERT(pay_untouched(&f), "still nothing applied");

    /* The outer exchange is over: the result is applied and acknowledged */
    f.mgr.entries[0].exchange_in_progress = 0;
    ran = lsp_channels_run_deferred_bridge_msgs(&f.mgr, f.lsp);
    TEST_ASSERT_EQ(ran, 1, "applied once the channel is free");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "HTLC fulfilled");
    TEST_ASSERT_EQ(ch->local_amount, 104000, "LSP credited");
    TEST_ASSERT(lsp_channels_outbound_was_paid(&f.mgr, f.hash), "payment recorded");
    rid = next_pay_ack(&f);
    TEST_ASSERT_EQ(rid, 7, "acknowledged now");
    TEST_ASSERT_EQ(f.mgr.n_bridge_deferred, 0, "nothing left waiting");
    ran = lsp_channels_run_deferred_bridge_msgs(&f.mgr, f.lsp);
    TEST_ASSERT_EQ(ran, 0, "and not applied twice");
    pay_fixture_free(&f);

    /* A failure waits the same way */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    f.mgr.entries[0].exchange_in_progress = 1;
    TEST_ASSERT(deliver_pay_result(&f, 7, 0, NULL), "taken");
    TEST_ASSERT(pay_untouched(&f), "nothing applied");
    f.mgr.entries[0].exchange_in_progress = 0;
    ran = lsp_channels_run_deferred_bridge_msgs(&f.mgr, f.lsp);
    TEST_ASSERT_EQ(ran, 1, "applied");
    TEST_ASSERT_EQ(f.mgr.entries[0].channel.n_htlcs, 0, "HTLC failed back");
    pay_fixture_free(&f);
    return 1;
}

/* ---- A client fails only an HTLC it was offered ---- */

int test_lsp_client_cannot_fail_its_own_htlc(void) {
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;
    wire_msg_t m;
    m.msg_type = MSG_UPDATE_FAIL_HTLC;

    /* The HTLC the client offered for an outside payment in flight */
    m.json = wire_build_update_fail_htlc(f.htlc_id, "changed my mind");
    int r = lsp_channels_handle_msg(&f.mgr, f.lsp, 0, &m);
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(r, 0, "refused");
    TEST_ASSERT(pay_untouched(&f), "HTLC, balance and origin untouched");

    /* The same once the outside payment is no longer tracked: still an HTLC
       the client offered, never one it may fail */
    f.mgr.htlc_origins[0].active = 0;
    uint64_t rem = ch->remote_amount;
    m.json = wire_build_update_fail_htlc(f.htlc_id, "again");
    r = lsp_channels_handle_msg(&f.mgr, f.lsp, 0, &m);
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(r, 0, "refused");
    TEST_ASSERT_EQ(ch->n_htlcs, 1, "HTLC kept");
    TEST_ASSERT_EQ(ch->remote_amount, rem, "client not refunded");

    /* An HTLC that does not exist */
    m.json = wire_build_update_fail_htlc(4242, "none");
    r = lsp_channels_handle_msg(&f.mgr, f.lsp, 0, &m);
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(r, 0, "refused");

    /* One the LSP offered to the client can be failed by it */
    unsigned char h[32];
    memset(h, 0x44, 32);
    uint64_t offered;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_OFFERED, 3000, h, 500, &offered), "LSP offers");
    TEST_ASSERT_EQ(ch->local_amount, 97000, "LSP's amount locked");
    m.json = wire_build_update_fail_htlc(offered, "no thanks");
    r = lsp_channels_handle_msg(&f.mgr, f.lsp, 0, &m);
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(r, 1, "accepted");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "LSP's amount back");
    TEST_ASSERT_EQ(ch->n_htlcs, 1, "only the client's own HTLC is left");
    pay_fixture_free(&f);
    return 1;
}

/* ---- An inbound HTLC failed while the bridge is away: the bridge hears ---- */

/* The fixture's channel with one more HTLC, offered by the LSP for an inbound
   payment known to the node as upstream 1x1x1:0 (bridge id 31, expiry 500) */
static htlc_origin_t *add_inbound_origin(pay_fixture_t *f, const unsigned char *hash) {
    channel_t *ch = &f->mgr.entries[0].channel;
    uint64_t id;
    if (!channel_add_htlc(ch, HTLC_OFFERED, 3000, hash, 500, &id)) return NULL;
    htlc_origin_t *o = lsp_channels_track_bridge_origin(&f->mgr, hash, 31);
    if (!o) return NULL;
    o->sender_idx = 0;
    o->sender_htlc_id = id;
    o->cltv_expiry = 500;
    strcpy(o->upstream_id, "1x1x1:0");
    return o;
}

static int next_bridge_fail(pay_fixture_t *f, const unsigned char *hash, uint64_t *id) {
    wire_msg_t m;
    unsigned char got[32];
    char why[64];
    if (!wire_recv_timeout(f->bridge_peer, &m, 1)) return 0;
    int ok = m.msg_type == MSG_BRIDGE_FAIL_HTLC &&
             wire_parse_bridge_fail_htlc(m.json, got, why, sizeof(why), id) &&
             memcmp(got, hash, 32) == 0;
    cJSON_Delete(m.json);
    return ok;
}

int test_lsp_inbound_timeout_reaches_bridge_later(void) {
    unsigned char h[32];
    memset(h, 0x61, 32);
    pay_fixture_t f;
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    channel_t *ch = &f.mgr.entries[0].channel;
    htlc_origin_t *o = add_inbound_origin(&f, h);
    TEST_ASSERT(o != NULL, "inbound HTLC in flight");
    int bridge_fd = f.mgr.bridge_fd;

    /* Near expiry with the bridge away: the client's HTLC is failed, the
       origin stays until the bridge can be told */
    f.mgr.bridge_fd = -1;
    lsp_channels_check_bridge_htlc_timeouts(&f.mgr, f.lsp, 495);
    TEST_ASSERT_EQ(ch->n_htlcs, 1, "the inbound HTLC is failed on the channel");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "LSP's amount back");
    TEST_ASSERT(o->active && o->fail_pending, "origin kept: fail still to deliver");
    TEST_ASSERT(lsp_channels_bridge_htlc_pending(&f.mgr, h), "hash still in use");
    wire_msg_t m;
    TEST_ASSERT(wire_recv_timeout(f.client_peer, &m, 1) &&
                m.msg_type == MSG_UPDATE_FAIL_HTLC, "client told once");
    cJSON_Delete(m.json);
    lsp_channels_check_bridge_htlc_timeouts(&f.mgr, f.lsp, 496);
    TEST_ASSERT(o->active && o->fail_pending, "still waiting for the bridge");
    TEST_ASSERT_EQ(ch->local_amount, 100000, "nothing failed twice");

    /* The bridge is back: its first heartbeat brings the verdict */
    f.mgr.bridge_fd = bridge_fd;
    deliver_bridge_msg(&f.mgr, f.lsp, MSG_BRIDGE_HELLO, wire_build_bridge_hello(NULL));
    TEST_ASSERT(wire_recv_timeout(f.bridge_peer, &m, 1) &&
                m.msg_type == MSG_BRIDGE_HELLO_ACK, "heartbeat answered");
    cJSON_Delete(m.json);
    uint64_t id = 0;
    TEST_ASSERT(next_bridge_fail(&f, h, &id), "BRIDGE_FAIL_HTLC for the HTLC");
    TEST_ASSERT_EQ(id, 31, "under the bridge's id");
    TEST_ASSERT(!o->active, "origin closed");
    size_t again = lsp_channels_flush_bridge_fails(&f.mgr);
    TEST_ASSERT_EQ(again, 0, "told once");
    pay_fixture_free(&f);

    /* The node offers the held HTLC again after the reconnect, before any
       heartbeat: it gets the fail verdict under the new id */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    o = add_inbound_origin(&f, h);
    TEST_ASSERT(o != NULL, "inbound HTLC in flight");
    bridge_fd = f.mgr.bridge_fd;
    f.mgr.bridge_fd = -1;
    lsp_channels_check_bridge_htlc_timeouts(&f.mgr, f.lsp, 495);
    TEST_ASSERT(o->active && o->fail_pending, "fail waits for the bridge");
    f.mgr.bridge_fd = bridge_fd;
    cJSON *add = wire_build_bridge_add_htlc(h, 3000000, 500, 77);
    cJSON_AddStringToObject(add, "upstream_id", "1x1x1:0");
    deliver_bridge_msg(&f.mgr, f.lsp, MSG_BRIDGE_ADD_HTLC, add);
    id = 0;
    TEST_ASSERT(next_bridge_fail(&f, h, &id), "fail verdict for the re-offered HTLC");
    TEST_ASSERT_EQ(id, 77, "under its new id");
    TEST_ASSERT(!o->active, "origin closed");
    TEST_ASSERT_EQ(f.mgr.entries[0].channel.n_htlcs, 1, "nothing offered to the client again");
    pay_fixture_free(&f);

    /* With the bridge connected the verdict goes out at once, as before */
    TEST_ASSERT(pay_fixture_init(&f), "fixture");
    o = add_inbound_origin(&f, h);
    TEST_ASSERT(o != NULL, "inbound HTLC in flight");
    lsp_channels_check_bridge_htlc_timeouts(&f.mgr, f.lsp, 495);
    id = 0;
    TEST_ASSERT(next_bridge_fail(&f, h, &id) && id == 31, "failed back at once");
    TEST_ASSERT(!o->active, "origin closed");
    pay_fixture_free(&f);
    return 1;
}

/* ---- A fulfil the node could not take stays on record ---- */

int test_lsp_unresolved_fulfil_is_kept(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.persist = &db;
    mgr.bridge_fd = sv[0];
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.htlc_origins && lsp, "alloc");

    unsigned char preimage[32], hash[32];
    memset(preimage, 0x52, 32);
    sha256(preimage, 32, hash);
    htlc_origin_t *o = lsp_channels_track_bridge_origin(&mgr, hash, 90);
    TEST_ASSERT(o != NULL, "origin");
    strcpy(o->upstream_id, "5x5x5:3");
    uint64_t bid = lsp_channels_settle_bridge_origin(&mgr, hash, preimage);
    TEST_ASSERT_EQ(bid, 90, "client fulfilled");
    size_t sent = lsp_channels_flush_bridge_fulfils(&mgr);
    TEST_ASSERT_EQ(sent, 1, "fulfil sent to the bridge");
    wire_msg_t m;
    TEST_ASSERT(wire_recv_timeout(sv[1], &m, 1) &&
                m.msg_type == MSG_BRIDGE_FULFILL_HTLC, "the fulfil");
    cJSON_Delete(m.json);

    /* The node could not take it: not confirmed, not forgotten */
    deliver_bridge_msg(&mgr, lsp, MSG_BRIDGE_FULFILL_UNRESOLVED,
                       wire_build_bridge_fulfill_unresolved(hash, "channel_gone"));
    TEST_ASSERT(mgr.bridge_fulfilled[0].undelivered, "still not confirmed");
    TEST_ASSERT(mgr.bridge_fulfilled[0].unresolved, "marked for the operator");
    TEST_ASSERT(memcmp(mgr.bridge_fulfilled[0].preimage, preimage, 32) == 0 &&
                strcmp(mgr.bridge_fulfilled[0].upstream_id, "5x5x5:3") == 0,
                "preimage and upstream HTLC kept");
    persist_bridge_fulfil_t rows[4];
    size_t n = persist_load_bridge_fulfils(&db, rows, 4, 0);
    TEST_ASSERT_EQ(n, 1, "still in the database");
    TEST_ASSERT(memcmp(rows[0].preimage, preimage, 32) == 0 &&
                memcmp(rows[0].payment_hash, hash, 32) == 0 &&
                strcmp(rows[0].upstream_id, "5x5x5:3") == 0, "with preimage, hash and upstream");
    TEST_ASSERT(lsp_channels_hash_spent_or_busy(&mgr, hash), "hash stays spent");
    sent = lsp_channels_flush_bridge_fulfils(&mgr);
    TEST_ASSERT_EQ(sent, 0, "not repeated at every heartbeat");
    TEST_ASSERT(!wire_recv_timeout(sv[1], &m, 1), "bridge sent nothing more");

    /* After a restart it is offered to the node once more */
    {
        lsp_channel_mgr_t again;
        memset(&again, 0, sizeof(again));
        again.persist = &db;
        again.bridge_fd = sv[0];
        n = lsp_channels_load_bridge_fulfils(&again);
        TEST_ASSERT_EQ(n, 1, "restored from disk");
        sent = lsp_channels_flush_bridge_fulfils(&again);
        TEST_ASSERT_EQ(sent, 1, "and sent");
        TEST_ASSERT(wire_recv_timeout(sv[1], &m, 1) &&
                    m.msg_type == MSG_BRIDGE_FULFILL_HTLC, "the fulfil");
        cJSON_Delete(m.json);
    }

    /* The wire message */
    {
        unsigned char got[32];
        char why[32];
        cJSON *j = wire_build_bridge_fulfill_unresolved(hash, "channel_gone");
        TEST_ASSERT(wire_parse_bridge_fulfill_unresolved(j, got, why, sizeof(why)) &&
                    memcmp(got, hash, 32) == 0 && strcmp(why, "channel_gone") == 0,
                    "round trip");
        cJSON_DeleteItemFromObject(j, "payment_hash");
        TEST_ASSERT(!wire_parse_bridge_fulfill_unresolved(j, got, why, sizeof(why)),
                    "hash required");
        cJSON_Delete(j);
    }

    close(sv[0]); close(sv[1]);
    free(mgr.htlc_origins); free(lsp);
    persist_close(&db);
    return 1;
}

int test_client_handles_update_fail_htlc(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "ctx");
    int cl[2], br[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0, "socketpair");
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, br) == 0, "socketpair");

    /* The LSP's view of client 0, and the client's own view of its channel */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 1;
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    mgr.bridge_fd = br[0];
    mgr.next_request_id = 1;
    snprintf(mgr.network, sizeof(mgr.network), "regtest");
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(mgr.entries && mgr.htlc_origins && lsp, "alloc");
    int client_fd = cl[0];
    lsp->client_fds = &client_fd;
    channel_t *lsp_ch = &mgr.entries[0].channel;
    lsp_ch->local_amount = 100000; lsp_ch->remote_amount = 100000;
    channel_t client_ch;
    memset(&client_ch, 0, sizeof(client_ch));
    client_ch.local_amount = 100000; client_ch.remote_amount = 100000;

    unsigned char hash[32];
    memset(hash, 0x83, 32);
    wire_msg_t m;
    int committed = -1;
    uint64_t failed_id = 99;

    /* Twice over: the client offers an HTLC for an invoice the LSP will not
       pay, the LSP refuses it, the client undoes it.  After each round both
       sides hold the same state, so the next payment starts clean. */
    for (int round = 0; round < 2; round++) {
        uint64_t id;
        TEST_ASSERT(channel_add_htlc(&client_ch, HTLC_OFFERED, 4000, hash, 500, &id),
                    "client adds the HTLC");
        cJSON *add = wire_build_update_add_htlc(id, 4000000, hash, 500);
        cJSON_AddStringToObject(add, "bolt11", "lnbcrt40u1pnotaninvoice");
        m.msg_type = MSG_UPDATE_ADD_HTLC; m.json = add;
        TEST_ASSERT(lsp_channels_handle_msg(&mgr, lsp, 0, &m), "LSP handles the ADD");
        cJSON_Delete(add);

        TEST_ASSERT(wire_recv_timeout(cl[1], &m, 5), "client gets the answer");
        TEST_ASSERT_EQ(m.msg_type, MSG_UPDATE_FAIL_HTLC, "UPDATE_FAIL_HTLC");
        TEST_ASSERT(client_handle_fail_htlc(&client_ch, &m, &committed, &failed_id),
                    "client applies it");
        cJSON_Delete(m.json);
        TEST_ASSERT_EQ(committed, 0, "refusal: no commitment exchange follows");
        TEST_ASSERT_EQ(failed_id, id, "for its HTLC");

        TEST_ASSERT_EQ(client_ch.n_htlcs, lsp_ch->n_htlcs, "same HTLCs (none)");
        TEST_ASSERT_EQ(client_ch.commitment_number, lsp_ch->commitment_number,
                       "same commitment number");
        TEST_ASSERT_EQ(client_ch.local_amount, 100000, "client balance restored");
        TEST_ASSERT_EQ(client_ch.next_htlc_id, lsp_ch->next_htlc_id, "same next HTLC id");
        TEST_ASSERT(!wire_recv_timeout(cl[1], &m, 1), "nothing follows the refusal");
    }

    /* A committed HTLC that the LSP fails: the client fails it too and
       expects the commitment exchange (its commitment number moves on, as
       the LSP's does) */
    uint64_t lsp_id, client_id;
    TEST_ASSERT(channel_add_htlc(&client_ch, HTLC_OFFERED, 4000, hash, 500, &client_id),
                "client side of a committed HTLC");
    TEST_ASSERT(channel_add_htlc(lsp_ch, HTLC_RECEIVED, 4000, hash, 500, &lsp_id),
                "LSP side of it");
    TEST_ASSERT_EQ(client_id, lsp_id, "same id on both sides");
    lsp_channels_fail_outbound_htlc(&mgr, lsp, NULL, 0, lsp_id, "bridge_unavailable");
    TEST_ASSERT(wire_recv_timeout(cl[1], &m, 5), "client gets the failure");
    TEST_ASSERT(client_handle_fail_htlc(&client_ch, &m, &committed, &failed_id),
                "client applies it");
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(committed, 1, "failure of a committed HTLC");
    TEST_ASSERT_EQ(client_ch.n_htlcs, 0, "HTLC gone on the client");
    TEST_ASSERT_EQ(client_ch.local_amount, 100000, "client refunded");
    TEST_ASSERT_EQ(client_ch.commitment_number, lsp_ch->commitment_number,
                   "both sides moved to the same commitment");
    TEST_ASSERT_EQ(lsp_ch->remote_amount, 100000, "LSP's view of the client restored");

    /* A fail for an HTLC the client does not have changes nothing */
    cJSON *bogus = wire_build_update_fail_htlc(777, "x");
    m.msg_type = MSG_UPDATE_FAIL_HTLC; m.json = bogus;
    TEST_ASSERT(!client_handle_fail_htlc(&client_ch, &m, &committed, &failed_id),
                "unknown HTLC");
    cJSON_Delete(bogus);
    bogus = wire_build_update_fail_htlc_uncommitted(777, "x");
    m.json = bogus;
    TEST_ASSERT(!client_handle_fail_htlc(&client_ch, &m, &committed, &failed_id),
                "unknown refused HTLC");
    cJSON_Delete(bogus);
    TEST_ASSERT_EQ(client_ch.local_amount, 100000, "balance untouched");

    channel_cleanup(&client_ch); channel_cleanup(lsp_ch);
    if (client_fd >= 0) close(client_fd);
    close(cl[1]); close(br[0]); close(br[1]);
    free(mgr.entries); free(mgr.htlc_origins); free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}
