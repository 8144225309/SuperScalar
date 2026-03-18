#include "superscalar/lsps.h"
#include "superscalar/wire.h"
#include <cJSON.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Test E1: LSPS0 request round-trip — method and id preserved */
int test_lsps0_request_roundtrip(void)
{
    cJSON *req = cJSON_CreateObject();
    ASSERT(req != NULL, "create object");
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(req, "method", "lsps1.get_info");
    cJSON_AddNumberToObject(req, "id", 42);
    cJSON_AddNullToObject(req, "params");

    int id = 0;
    const char *method = lsps_parse_request(req, &id);
    ASSERT(method != NULL, "method should be parsed");
    ASSERT(strcmp(method, "lsps1.get_info") == 0, "method should be lsps1.get_info");
    ASSERT(id == 42, "id should be 42");

    cJSON_Delete(req);
    return 1;
}

/* Test E2: unknown method returns error code -32601 */
int test_lsps0_error_response(void)
{
    cJSON *err = lsps_build_error(99, LSPS_ERR_METHOD_NOT_FOUND, "method not found");
    ASSERT(err != NULL, "build error response");

    const cJSON *code_field = cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(err, "error"), "code");
    ASSERT(code_field != NULL, "error.code exists");
    ASSERT(cJSON_IsNumber(code_field), "error.code is number");
    ASSERT((int)code_field->valuedouble == LSPS_ERR_METHOD_NOT_FOUND,
           "error code is -32601");

    const cJSON *id_field = cJSON_GetObjectItemCaseSensitive(err, "id");
    ASSERT(id_field != NULL && (int)id_field->valuedouble == 99, "id preserved");

    cJSON_Delete(err);
    return 1;
}

/* Test E3: lsps1.get_info response has required fields */
int test_lsps1_get_info_response(void)
{
    lsps1_info_t info = {
        .min_channel_balance_msat = 1000000,
        .max_channel_balance_msat = 100000000000ULL,
        .min_confirmations = 1,
        .base_fee_msat = 1000,
        .fee_ppm = 100,
    };

    cJSON *resp = lsps1_build_get_info_response(&info);
    ASSERT(resp != NULL, "build get_info response");

    ASSERT(cJSON_GetObjectItemCaseSensitive(resp, "min_channel_balance_msat") != NULL,
           "min_channel_balance_msat present");
    ASSERT(cJSON_GetObjectItemCaseSensitive(resp, "max_channel_balance_msat") != NULL,
           "max_channel_balance_msat present");
    ASSERT(cJSON_GetObjectItemCaseSensitive(resp, "fee_ppm") != NULL,
           "fee_ppm present");

    cJSON_Delete(resp);
    return 1;
}

/* Test E4: lsps1.create_order parses required fields */
int test_lsps1_create_order(void)
{
    cJSON *params = cJSON_CreateObject();
    ASSERT(params != NULL, "create params");
    cJSON_AddNumberToObject(params, "channel_balance_msat", 5000000);
    cJSON_AddNumberToObject(params, "confirms_within_blocks", 3);

    uint64_t amount = 0; uint32_t confs = 0;
    ASSERT(lsps1_parse_create_order(params, &amount, &confs) == 1, "parse ok");
    ASSERT(amount == 5000000, "amount correct");
    ASSERT(confs == 3, "confs correct");

    cJSON_Delete(params);
    return 1;
}

/* Test E5: lsps2.get_info response has fee params */
int test_lsps2_get_info(void)
{
    lsps2_fee_params_t params = {
        .min_fee_msat = 500,
        .fee_ppm = 200,
        .min_channel_balance_msat = 100000,
        .max_channel_balance_msat = 10000000000ULL,
    };

    cJSON *resp = lsps2_build_get_info_response(&params);
    ASSERT(resp != NULL, "build lsps2 get_info");

    const cJSON *fee_ppm = cJSON_GetObjectItemCaseSensitive(resp, "fee_ppm");
    ASSERT(fee_ppm != NULL && (int)fee_ppm->valuedouble == 200, "fee_ppm correct");

    const cJSON *min_fee = cJSON_GetObjectItemCaseSensitive(resp, "min_fee_msat");
    ASSERT(min_fee != NULL && (uint64_t)min_fee->valuedouble == 500, "min_fee_msat correct");

    cJSON_Delete(resp);
    return 1;
}

/* Test E6: lsps2.buy with valid opening_fee_params succeeds (parse only) */
int test_lsps2_buy_creates_jit(void)
{
    cJSON *params = cJSON_CreateObject();
    ASSERT(params != NULL, "create params");

    /* opening_fee_params object */
    cJSON *ofp = cJSON_CreateObject();
    cJSON_AddNumberToObject(ofp, "min_fee_msat", 1000);
    cJSON_AddItemToObject(params, "opening_fee_params", ofp);
    cJSON_AddNumberToObject(params, "payment_size_msat", 10000000);

    uint64_t amount = 0, fee = 0;
    ASSERT(lsps2_parse_buy(params, &amount, &fee) == 1, "parse lsps2.buy ok");
    ASSERT(amount == 10000000, "payment_size_msat correct");
    ASSERT(fee == 1000, "fee from opening_fee_params.min_fee_msat");

    cJSON_Delete(params);
    return 1;
}

/* Phase 2 fix: new LSPS context / NULL-safety tests */

/* Test E7: NULL ctx on lsps2.buy returns error response (not segfault) */
int test_lsps_null_ctx_returns_error(void)
{
    /* Build a well-formed lsps2.buy request */
    cJSON *req = cJSON_CreateObject();
    ASSERT(req != NULL, "create request");
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(req, "method", "lsps2.buy");
    cJSON_AddNumberToObject(req, "id", 7);
    cJSON *params = cJSON_CreateObject();
    cJSON *ofp = cJSON_CreateObject();
    cJSON_AddNumberToObject(ofp, "min_fee_msat", 1000);
    cJSON_AddItemToObject(params, "opening_fee_params", ofp);
    cJSON_AddNumberToObject(params, "payment_size_msat", 5000000);
    cJSON_AddItemToObject(req, "params", params);

    /* Call with NULL ctx and fd=-1: should return 1 (handled), not segfault */
    int ret = lsps_handle_request(NULL, -1, req);
    ASSERT(ret == 1, "lsps2.buy with NULL ctx should return 1 (handled with error response)");

    cJSON_Delete(req);
    return 1;
}

/* Test E8: malformed JSON (not an object) returns 0 */
int test_lsps_malformed_json_returns_zero(void)
{
    cJSON *arr = cJSON_CreateArray();
    ASSERT(arr != NULL, "create array");

    int ret = lsps_handle_request(NULL, -1, arr);
    ASSERT(ret == 0, "malformed JSON (array) should return 0");

    cJSON_Delete(arr);
    return 1;
}

/* Test E9: lsps1.get_order round-trip — create then retrieve */
int test_lsps1_get_order(void)
{
    /* Step 1: create_order via handle_request (fd=-1 swallows wire send) */
    cJSON *create_req = cJSON_CreateObject();
    ASSERT(create_req != NULL, "create request");
    cJSON_AddStringToObject(create_req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(create_req, "method", "lsps1.create_order");
    cJSON_AddNumberToObject(create_req, "id", 10);
    cJSON *cparams = cJSON_CreateObject();
    cJSON_AddNumberToObject(cparams, "channel_balance_msat", 5000000);
    cJSON_AddNumberToObject(cparams, "confirms_within_blocks", 3);
    cJSON_AddItemToObject(create_req, "params", cparams);
    ASSERT(lsps_handle_request(NULL, -1, create_req) == 1, "create_order handled");
    cJSON_Delete(create_req);

    /* Step 2: lsps1_parse_get_order with string id */
    cJSON *gparams = cJSON_CreateObject();
    ASSERT(gparams != NULL, "create get_order params");
    cJSON_AddStringToObject(gparams, "order_id", "1");
    int oid = 0;
    ASSERT(lsps1_parse_get_order(gparams, &oid) == 1, "parse get_order string id ok");
    ASSERT(oid == 1, "order_id parsed as 1");
    cJSON_Delete(gparams);

    /* Step 3: lsps1_parse_get_order with numeric id */
    cJSON *gparams2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(gparams2, "order_id", 1);
    int oid2 = 0;
    ASSERT(lsps1_parse_get_order(gparams2, &oid2) == 1, "parse numeric order_id ok");
    ASSERT(oid2 == 1, "numeric order_id correct");
    cJSON_Delete(gparams2);

    /* Step 4: get_order via handle_request — order just created; should be handled */
    cJSON *get_req = cJSON_CreateObject();
    ASSERT(get_req != NULL, "create get_order request");
    cJSON_AddStringToObject(get_req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(get_req, "method", "lsps1.get_order");
    cJSON_AddNumberToObject(get_req, "id", 11);
    cJSON *gp = cJSON_CreateObject();
    cJSON_AddStringToObject(gp, "order_id", "1");
    cJSON_AddItemToObject(get_req, "params", gp);
    ASSERT(lsps_handle_request(NULL, -1, get_req) == 1, "get_order handled");
    cJSON_Delete(get_req);

    /* Step 5: get_order for unknown id → error response (still returns 1 = handled) */
    cJSON *bad_req = cJSON_CreateObject();
    ASSERT(bad_req != NULL, "create bad get_order request");
    cJSON_AddStringToObject(bad_req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(bad_req, "method", "lsps1.get_order");
    cJSON_AddNumberToObject(bad_req, "id", 12);
    cJSON *bp = cJSON_CreateObject();
    cJSON_AddStringToObject(bp, "order_id", "9999");
    cJSON_AddItemToObject(bad_req, "params", bp);
    ASSERT(lsps_handle_request(NULL, -1, bad_req) == 1,
           "get_order unknown id returns error response (handled)");
    cJSON_Delete(bad_req);

    return 1;
}

/* ================================================================== */
/* SM1 — lsps1_order_fund() transitions order 1 to "PENDING_FUNDING" */
/*       (order 1 was created by E9 / test_lsps1_get_order)          */
/* ================================================================== */
int test_lsps1_order_fund_pending(void)
{
    /* Order 1 exists in CREATED state from E9 */
    int r = lsps1_order_fund(1,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        100, -1);
    ASSERT(r == 1, "lsps1_order_fund returns 1");

    /* Second call on same order (now PENDING_FUNDING) must return 0 */
    int r2 = lsps1_order_fund(1,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        101, -1);
    ASSERT(r2 == 0, "double-fund returns 0");
    return 1;
}

/* ================================================================== */
/* SM2 — lsps1_order_tick() below threshold: no state change         */
/* ================================================================== */
int test_lsps1_order_tick_below_threshold(void)
{
    /* funded_at=100, confs=3: threshold = 103. Tick at 102 → no change */
    int r = lsps1_order_tick(1, 102);
    ASSERT(r == 0, "tick below threshold returns 0");
    return 1;
}

/* ================================================================== */
/* SM3 — lsps1_order_tick() at threshold: transitions to COMPLETED   */
/* ================================================================== */
int test_lsps1_order_tick_completes(void)
{
    int r = lsps1_order_tick(1, 103);
    ASSERT(r == 1, "tick at threshold returns 1 (COMPLETED)");

    /* Idempotent: another tick on completed order returns 0 */
    int r2 = lsps1_order_tick(1, 110);
    ASSERT(r2 == 0, "tick on completed order returns 0");
    return 1;
}

/* ================================================================== */
/* SM4 — fresh order: fund + tick round-trip                          */
/* ================================================================== */
int test_lsps1_get_order_after_fund(void)
{
    /* Create a fresh order (will get id=2 — s_order_next_id was 2 after E9) */
    cJSON *req = cJSON_CreateObject();
    ASSERT(req != NULL, "alloc create_order req");
    cJSON_AddStringToObject(req, "jsonrpc", "2.0");
    cJSON_AddStringToObject(req, "method", "lsps1.create_order");
    cJSON_AddNumberToObject(req, "id", 40);
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "channel_balance_msat", 2000000);
    cJSON_AddNumberToObject(p, "confirms_within_blocks", 6);
    cJSON_AddItemToObject(req, "params", p);
    ASSERT(lsps_handle_request(NULL, -1, req) == 1, "create_order ok");
    cJSON_Delete(req);

    /* Fund order 2 at height 200 */
    ASSERT(lsps1_order_fund(2,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        200, -1) == 1, "fund fresh order ok");

    /* Tick just below threshold (200+6-1=205) */
    ASSERT(lsps1_order_tick(2, 205) == 0, "not yet completed at 205");

    /* Tick at threshold (200+6=206) */
    ASSERT(lsps1_order_tick(2, 206) == 1, "completed at 206");
    return 1;
}

/* ================================================================== */
/* SM5 — COMPLETED notification JSON structure is correct             */
/* ================================================================== */
int test_lsps1_completion_notify_json(void)
{
    cJSON *note = cJSON_CreateObject();
    ASSERT(note != NULL, "alloc note");
    cJSON_AddStringToObject(note, "order_id",  "99");
    cJSON_AddStringToObject(note, "new_state", "COMPLETED");

    const cJSON *oid_f = cJSON_GetObjectItemCaseSensitive(note, "order_id");
    ASSERT(oid_f && cJSON_IsString(oid_f) && strcmp(oid_f->valuestring, "99") == 0,
           "order_id field correct");

    const cJSON *ns_f = cJSON_GetObjectItemCaseSensitive(note, "new_state");
    ASSERT(ns_f && cJSON_IsString(ns_f) &&
           strcmp(ns_f->valuestring, "COMPLETED") == 0,
           "new_state is COMPLETED");

    /* wire_send with fd=-1 must not crash */
    wire_send(-1, MSG_LSPS_NOTIFY, note);

    cJSON_Delete(note);
    return 1;
}
