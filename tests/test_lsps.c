#include "superscalar/lsps.h"
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
