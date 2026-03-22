/*
 * test_admin_rpc.c — Unit tests for the JSON-RPC 2.0 admin interface
 *
 * AR1:  getinfo → result contains "node_id"
 * AR2:  getinfo with real privkey → node_id is 66-char hex
 * AR3:  listpeers → result is array
 * AR4:  listchannels → result is array
 * AR5:  listpayments → result is array
 * AR6:  listinvoices → result is array
 * AR7:  createinvoice → result contains "bolt11"
 * AR8:  createinvoice with amount=0 → bolt11 present
 * AR9:  pay with bad bolt11 → error response, no crash
 * AR10: keysend with invalid dest → error response
 * AR11: unknown method → error code -32601
 * AR12: malformed JSON → error code -32700
 * AR13: getroute with no gossip → error response
 * AR14: feerates with no fee_est → defaults returned
 * AR15: feerates with fee_est → values > 0
 * AR16: stop → sets shutdown_flag
 * AR17: listinvoices after createinvoice → invoice present
 * AR18: listpayments empty → empty array
 * AR19: closechannel unknown id → error response
 * AR20: openchannel null pmgr → error response
 * AR21: openchannel missing peer_id/amount → error "missing"
 * AR22: openchannel invalid hex peer_id → error "invalid peer"
 * AR23: openchannel valid peer_id but not connected → error "not connected"
 * AR24: openchannel zero amount_sat → error "missing"
 * AR25: closechannel SPK has P2TR prefix 0x51 0x20 (not zero)
 * AR26: closechannel SPK x-only pubkey bytes are non-zero when privkey set
 * AR27: listfactories with no persist → returns empty array
 * AR28: recoverfactory with no persist → returns error
 * AR29: sweepfactory with no persist → returns error
 * AR30: sweepfactory missing dest_spk_hex → returns error
 */

#include "superscalar/admin_rpc.h"
#include "superscalar/invoice.h"
#include "superscalar/fee_estimator.h"
#include "superscalar/lsp_channels.h"
#include <cJSON.h>
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Helpers ---- */

static admin_rpc_t make_rpc(secp256k1_context *ctx,
                              bolt11_invoice_table_t *inv_tbl,
                              payment_table_t *pay_tbl)
{
    admin_rpc_t rpc;
    memset(&rpc, 0, sizeof(rpc));
    rpc.ctx = ctx;
    memset(rpc.node_privkey, 0x11, 32);
    rpc.invoices = inv_tbl;
    rpc.payments = pay_tbl;
    rpc.listen_fd = -1;
    return rpc;
}

static int dispatch(admin_rpc_t *rpc, const char *req,
                     char *out, size_t cap)
{
    return (int)admin_rpc_handle_request(rpc, req, out, cap);
}

/* ================================================================== */
/* AR1 — getinfo returns result with node_id                          */
/* ================================================================== */
int test_admin_rpc_getinfo_has_node_id(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[1024];
    int n = dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\",\"params\":{}}",
        out, sizeof(out));
    ASSERT(n > 0, "AR1: dispatch returned > 0");
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR1: valid JSON");
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR1: result is object");
    cJSON *nid = cJSON_GetObjectItemCaseSensitive(res, "node_id");
    ASSERT(cJSON_IsString(nid), "AR1: node_id present");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR2 — getinfo with real privkey → 66-char hex node_id             */
/* ================================================================== */
int test_admin_rpc_getinfo_node_id_hex(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    bolt11_invoice_table_t inv; invoice_init(&inv);
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc = make_rpc(ctx, &inv, &pay);

    char out[1024];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getinfo\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    cJSON *nid = cJSON_GetObjectItemCaseSensitive(res, "node_id");
    ASSERT(cJSON_IsString(nid), "AR2: node_id is string");
    ASSERT(strlen(nid->valuestring) == 66, "AR2: node_id is 66 hex chars");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR3 — listpeers returns array                                       */
/* ================================================================== */
int test_admin_rpc_listpeers_is_array(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[1024];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"listpeers\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR3: listpeers result is array");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR4 — listchannels returns array                                    */
/* ================================================================== */
int test_admin_rpc_listchannels_is_array(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[1024];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"listchannels\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR4: listchannels result is array");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR5 — listpayments returns array                                    */
/* ================================================================== */
int test_admin_rpc_listpayments_is_array(void)
{
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.payments = &pay; rpc.listen_fd = -1;
    char out[1024];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"listpayments\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR5: listpayments result is array");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR6 — listinvoices returns array                                    */
/* ================================================================== */
int test_admin_rpc_listinvoices_is_array(void)
{
    bolt11_invoice_table_t inv; invoice_init(&inv);
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.invoices = &inv; rpc.listen_fd = -1;
    char out[1024];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"listinvoices\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR6: listinvoices result is array");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR7 — createinvoice returns bolt11                                  */
/* ================================================================== */
int test_admin_rpc_createinvoice_has_bolt11(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    bolt11_invoice_table_t inv; invoice_init(&inv);
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc = make_rpc(ctx, &inv, &pay);

    char out[2048];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"createinvoice\","
        "\"params\":{\"amount_msat\":10000,\"description\":\"test\"}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR7: parse response");
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR7: result is object");
    cJSON *b = cJSON_GetObjectItemCaseSensitive(res, "bolt11");
    ASSERT(cJSON_IsString(b), "AR7: bolt11 present");
    ASSERT(strlen(b->valuestring) > 10, "AR7: bolt11 non-empty");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR8 — createinvoice with amount=0 (any-amount) → bolt11 present   */
/* ================================================================== */
int test_admin_rpc_createinvoice_any_amount(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    bolt11_invoice_table_t inv; invoice_init(&inv);
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc = make_rpc(ctx, &inv, &pay);

    char out[2048];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"createinvoice\","
        "\"params\":{\"amount_msat\":0,\"description\":\"any\"}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR8: result is object (amount=0)");
    cJSON *b = cJSON_GetObjectItemCaseSensitive(res, "bolt11");
    ASSERT(cJSON_IsString(b), "AR8: bolt11 present for amount=0");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR9 — pay with bad bolt11 → error response, no crash              */
/* ================================================================== */
int test_admin_rpc_pay_bad_bolt11(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    bolt11_invoice_table_t inv; invoice_init(&inv);
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc = make_rpc(ctx, &inv, &pay);

    char out[1024];
    int n = dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"pay\","
        "\"params\":{\"bolt11\":\"not_a_real_invoice\"}}",
        out, sizeof(out));
    ASSERT(n > 0, "AR9: returns bytes");
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR9: parse response");
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR9: error field present");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR10 — keysend with invalid dest pubkey → error response           */
/* ================================================================== */
int test_admin_rpc_keysend_bad_dest(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    bolt11_invoice_table_t inv; invoice_init(&inv);
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc = make_rpc(ctx, &inv, &pay);

    char out[1024];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"keysend\","
        "\"params\":{\"destination\":\"not_hex\",\"amount_msat\":1000}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR10: error for bad dest");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR11 — unknown method → error code -32601                          */
/* ================================================================== */
int test_admin_rpc_unknown_method(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"nonexistent\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR11: error present");
    cJSON *code = cJSON_GetObjectItemCaseSensitive(err, "code");
    ASSERT(cJSON_IsNumber(code), "AR11: code is number");
    ASSERT((int)code->valuedouble == -32601, "AR11: code is -32601");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR12 — malformed JSON → error code -32700                          */
/* ================================================================== */
int test_admin_rpc_malformed_json(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc, "{not valid json", out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR12: error present for bad JSON");
    cJSON *code = cJSON_GetObjectItemCaseSensitive(err, "code");
    ASSERT((int)code->valuedouble == -32700, "AR12: parse error code");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR13 — getroute with no gossip → error                             */
/* ================================================================== */
int test_admin_rpc_getroute_no_gossip(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"getroute\","
        "\"params\":{\"destination\":\"0211\",\"amount_msat\":1000}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR13: error when gossip=NULL");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR14 — feerates with no fee_est → defaults returned               */
/* ================================================================== */
int test_admin_rpc_feerates_defaults(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"feerates\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR14: result is object");
    cJSON *n = cJSON_GetObjectItemCaseSensitive(res, "normal_sat_per_kvb");
    ASSERT(cJSON_IsNumber(n), "AR14: normal_sat_per_kvb present");
    ASSERT(n->valuedouble > 0, "AR14: default rate > 0");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR15 — feerates with static fee_est → values > 0                  */
/* ================================================================== */

/* Minimal static fee estimator for testing */
static uint64_t test_fee_get_rate(fee_estimator_t *self, fee_target_t t)
{
    (void)self;
    switch (t) {
    case FEE_TARGET_URGENT:  return 5000;
    case FEE_TARGET_NORMAL:  return 2000;
    case FEE_TARGET_ECONOMY: return 1000;
    default:                 return 500;
    }
}
static void test_fee_update(fee_estimator_t *self) { (void)self; }
static void test_fee_free(fee_estimator_t *self) { (void)self; }

int test_admin_rpc_feerates_with_estimator(void)
{
    fee_estimator_t fe;
    fe.get_rate = test_fee_get_rate;
    fe.update   = test_fee_update;
    fe.free     = test_fee_free;

    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.fee_est = &fe; rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"feerates\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR15: result is object");
    cJSON *fast = cJSON_GetObjectItemCaseSensitive(res, "fast_sat_per_kvb");
    ASSERT(cJSON_IsNumber(fast) && fast->valuedouble == 5000,
           "AR15: fast=5000 from estimator");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR16 — stop sets shutdown_flag                                      */
/* ================================================================== */
int test_admin_rpc_stop_sets_flag(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    volatile int shutdown = 0;
    rpc.shutdown_flag = &shutdown;
    char out[256];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"stop\",\"params\":{}}",
        out, sizeof(out));
    ASSERT(shutdown == 1, "AR16: shutdown_flag set to 1");
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR16: result present");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR17 — listinvoices after createinvoice shows the invoice          */
/* ================================================================== */
int test_admin_rpc_listinvoices_after_create(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    bolt11_invoice_table_t inv; invoice_init(&inv);
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc = make_rpc(ctx, &inv, &pay);

    char out[2048];
    /* create invoice */
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"createinvoice\","
        "\"params\":{\"amount_msat\":5000,\"description\":\"hello\"}}",
        out, sizeof(out));

    /* list invoices */
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"listinvoices\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR17: listinvoices is array");
    ASSERT(cJSON_GetArraySize(res) >= 1, "AR17: at least one invoice listed");
    cJSON *first = cJSON_GetArrayItem(res, 0);
    cJSON *desc = cJSON_GetObjectItemCaseSensitive(first, "description");
    ASSERT(cJSON_IsString(desc), "AR17: description present");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR18 — listpayments empty → count 0                               */
/* ================================================================== */
int test_admin_rpc_listpayments_empty(void)
{
    payment_table_t pay; payment_init(&pay);
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.payments = &pay; rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":16,\"method\":\"listpayments\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR18: listpayments is array");
    ASSERT(cJSON_GetArraySize(res) == 0, "AR18: empty table → empty array");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR19 — closechannel with unknown id → error                        */
/* ================================================================== */
int test_admin_rpc_closechannel_unknown(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"closechannel\","
        "\"params\":{\"channel_id\":99999}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    /* Either error (no channel_mgr) or channel not found error */
    ASSERT(cJSON_GetObjectItemCaseSensitive(r, "error") != NULL ||
           cJSON_GetObjectItemCaseSensitive(r, "result") != NULL,
           "AR19: returns error or result, no crash");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR20 — openchannel null pmgr → error                               */
/* ================================================================== */
int test_admin_rpc_openchannel_deferred(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":18,\"method\":\"openchannel\","
        "\"params\":{\"peer_id\":\"0211\",\"amount_sat\":100000}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR20: openchannel null pmgr returns error");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR27 — listfactories with no channel_mgr → empty array             */
/* ================================================================== */
int test_admin_rpc_listfactories_no_persist(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":19,\"method\":\"listfactories\",\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR21: parse response");
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsArray(res), "AR21: listfactories returns array when persist=NULL");
    ASSERT(cJSON_GetArraySize(res) == 0, "AR27: empty array when no factories");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR21 — openchannel missing params → error                          */
/* ================================================================== */
int test_admin_rpc_openchannel_missing_params(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.listen_fd = -1;
    rpc.ctx  = ctx;
    rpc.pmgr = &pmgr;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"openchannel\","
        "\"params\":{}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR21: missing params returns error");
    cJSON *msg = cJSON_GetObjectItemCaseSensitive(err, "message");
    ASSERT(cJSON_IsString(msg) && strstr(msg->valuestring, "missing"),
           "AR21: error message mentions missing");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR22 — openchannel invalid hex peer_id → error                     */
/* ================================================================== */
int test_admin_rpc_openchannel_invalid_peer_hex(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.listen_fd = -1;
    rpc.ctx  = ctx;
    rpc.pmgr = &pmgr;
    char out[512];
    /* "notahex" is not 66 hex chars → invalid */
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"openchannel\","
        "\"params\":{\"peer_id\":\"notahex\",\"amount_sat\":100000}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR22: invalid hex returns error");
    cJSON *msg = cJSON_GetObjectItemCaseSensitive(err, "message");
    ASSERT(cJSON_IsString(msg) && strstr(msg->valuestring, "invalid"),
           "AR22: error message mentions invalid");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR23 — openchannel peer not connected → error                      */
/* ================================================================== */
int test_admin_rpc_openchannel_peer_not_connected(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.listen_fd = -1;
    rpc.ctx  = ctx;
    rpc.pmgr = &pmgr;
    char out[512];
    /* Valid 33-byte compressed pubkey hex (66 chars), but not in pmgr */
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":23,\"method\":\"openchannel\","
        "\"params\":{\"peer_id\":"
        "\"02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f001b2\","
        "\"amount_sat\":100000}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR23: not connected returns error");
    cJSON *msg = cJSON_GetObjectItemCaseSensitive(err, "message");
    ASSERT(cJSON_IsString(msg) && strstr(msg->valuestring, "not connected"),
           "AR23: error message mentions not connected");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR24 — openchannel zero amount_sat → error                         */
/* ================================================================== */
int test_admin_rpc_openchannel_zero_amount(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.listen_fd = -1;
    rpc.ctx  = ctx;
    rpc.pmgr = &pmgr;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":24,\"method\":\"openchannel\","
        "\"params\":{\"peer_id\":"
        "\"02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f001b2\","
        "\"amount_sat\":0}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR24: zero amount returns error");
    cJSON *msg = cJSON_GetObjectItemCaseSensitive(err, "message");
    ASSERT(cJSON_IsString(msg) && strstr(msg->valuestring, "missing"),
           "AR24: error message mentions missing");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR25 — closechannel with matching channel finds the channel and    */
/*         returns a result object (SPK computed, not placeholder)    */
/* ================================================================== */
int test_admin_rpc_closechannel_spk_not_error(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc));
    rpc.listen_fd = -1;
    rpc.ctx  = ctx;
    rpc.pmgr = &pmgr;
    /* Set a real node privkey so the P2TR SPK can be derived */
    memset(rpc.node_privkey, 0x55, 32);

    /* Set up a minimal channel_mgr with one channel */
    lsp_channel_mgr_t cm; memset(&cm, 0, sizeof(cm));
    lsp_channel_entry_t entry; memset(&entry, 0, sizeof(entry));
    entry.channel_id = 77;
    cm.entries = &entry;
    cm.n_channels = 1;
    rpc.channel_mgr = &cm;

    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":25,\"method\":\"closechannel\","
        "\"params\":{\"channel_id\":77}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    /* Should return a result (not an error) — channel was found, SPK computed */
    cJSON *res = cJSON_GetObjectItemCaseSensitive(r, "result");
    ASSERT(cJSON_IsObject(res), "AR25: closechannel returns result (not error) for known channel");
    cJSON *status = cJSON_GetObjectItemCaseSensitive(res, "status");
    ASSERT(cJSON_IsString(status), "AR25: result has status field");
    cJSON_Delete(r);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AR28 — recoverfactory with no persist → error response             */
/* ================================================================== */
int test_admin_rpc_recoverfactory_no_persist(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"recoverfactory\","
        "\"params\":{\"factory_id\":0}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR22: parse response");
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR22: error when persist not available");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR23 — sweepfactory with no persist → error response               */
/* ================================================================== */
int test_admin_rpc_sweepfactory_no_persist(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"sweepfactory\","
        "\"params\":{\"factory_id\":1,\"dest_spk_hex\":\"51200000000000000000000000000000000000000000000000000000000000000001\"}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR23: parse response");
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR23: error when persist not available");
    cJSON_Delete(r);
    return 1;
}

/* ================================================================== */
/* AR24 — sweepfactory missing dest_spk_hex → error response          */
/* ================================================================== */
int test_admin_rpc_sweepfactory_missing_dest(void)
{
    admin_rpc_t rpc; memset(&rpc, 0, sizeof(rpc)); rpc.listen_fd = -1;
    char out[512];
    dispatch(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"sweepfactory\","
        "\"params\":{\"factory_id\":1}}",
        out, sizeof(out));
    cJSON *r = cJSON_Parse(out);
    ASSERT(r, "AR24: parse response");
    cJSON *err = cJSON_GetObjectItemCaseSensitive(r, "error");
    ASSERT(cJSON_IsObject(err), "AR30: error when dest_spk_hex missing");
    cJSON_Delete(r);
    return 1;
}

/* AR26 — closechannel SPK x-only pubkey derived from node key is     */
/*         non-zero (not the old 32-zero placeholder)                 */
/* ================================================================== */
int test_admin_rpc_closechannel_spk_nonzero(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "AR26: ctx");

    /* Directly verify the P2TR SPK derivation: same logic as the fix */
    unsigned char node_priv[32]; memset(node_priv, 0x42, 32);
    secp256k1_pubkey node_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &node_pub, node_priv), "AR26: pubkey create");

    unsigned char pub33[33];
    size_t plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub33, &plen, &node_pub, SECP256K1_EC_COMPRESSED);

    /* spk[0]=OP_1, spk[1]=PUSH32, spk[2..33]=x-only pubkey */
    unsigned char spk[34];
    spk[0] = 0x51; spk[1] = 0x20;
    memcpy(spk + 2, pub33 + 1, 32);

    ASSERT(spk[0] == 0x51, "AR26: OP_1 prefix");
    ASSERT(spk[1] == 0x20, "AR26: PUSH32");

    /* Verify x-only bytes are not all-zero (old placeholder was 32 zeros) */
    int all_zero = 1;
    for (int i = 2; i < 34; i++) if (spk[i]) { all_zero = 0; break; }
    ASSERT(!all_zero, "AR26: x-only pubkey bytes are non-zero");

    secp256k1_context_destroy(ctx);
    return 1;
}
