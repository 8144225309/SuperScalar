#include "superscalar/lsps.h"
#include "superscalar/wire.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------
 * LSPS0 — JSON-RPC 2.0 dispatch
 * --------------------------------------------------------------------- */

const char *lsps_parse_request(const cJSON *json, int *id_out)
{
    if (!json || !cJSON_IsObject(json)) return NULL;

    const cJSON *method = cJSON_GetObjectItemCaseSensitive(json, "method");
    if (!method || !cJSON_IsString(method)) return NULL;

    if (id_out) {
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(json, "id");
        *id_out = (id && cJSON_IsNumber(id)) ? (int)id->valuedouble : 0;
    }

    return method->valuestring;
}

cJSON *lsps_build_response(int id, cJSON *result)
{
    cJSON *resp = cJSON_CreateObject();
    if (!resp) { cJSON_Delete(result); return NULL; }
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(resp, "id", id);
    if (result)
        cJSON_AddItemToObject(resp, "result", result);
    else
        cJSON_AddNullToObject(resp, "result");
    return resp;
}

cJSON *lsps_build_error(int id, int code, const char *message)
{
    cJSON *resp = cJSON_CreateObject();
    if (!resp) return NULL;
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(resp, "id", id);
    cJSON *err = cJSON_CreateObject();
    if (!err) { cJSON_Delete(resp); return NULL; }
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message ? message : "error");
    cJSON_AddItemToObject(resp, "error", err);
    return resp;
}

int lsps_handle_request(void *lsp_ctx, int fd, const cJSON *json)
{
    (void)lsp_ctx;

    int req_id = 0;
    const char *method = lsps_parse_request(json, &req_id);
    if (!method) return 0;

    cJSON *response = NULL;

    if (strcmp(method, "lsps1.get_info") == 0) {
        lsps1_info_t info = {
            .min_channel_balance_msat = 1000000,
            .max_channel_balance_msat = 100000000000ULL,
            .min_confirmations = 1,
            .base_fee_msat = 1000,
            .fee_ppm = 100,
        };
        response = lsps_build_response(req_id, lsps1_build_get_info_response(&info));
    } else if (strcmp(method, "lsps1.create_order") == 0) {
        const cJSON *params = cJSON_GetObjectItemCaseSensitive(json, "params");
        uint64_t amount_msat = 0; uint32_t confs = 1;
        if (!params || !lsps1_parse_create_order(params, &amount_msat, &confs)) {
            response = lsps_build_error(req_id, LSPS_ERR_INVALID_PARAMS, "invalid params");
        } else {
            cJSON *result = cJSON_CreateObject();
            cJSON_AddStringToObject(result, "order_state", "CREATED");
            cJSON_AddNumberToObject(result, "amount_msat", (double)amount_msat);
            response = lsps_build_response(req_id, result);
        }
    } else if (strcmp(method, "lsps2.get_info") == 0) {
        lsps2_fee_params_t params = {
            .min_fee_msat = 1000,
            .fee_ppm = 100,
            .min_channel_balance_msat = 1000000,
            .max_channel_balance_msat = 100000000000ULL,
        };
        response = lsps_build_response(req_id, lsps2_build_get_info_response(&params));
    } else if (strcmp(method, "lsps2.buy") == 0) {
        const cJSON *params = cJSON_GetObjectItemCaseSensitive(json, "params");
        uint64_t amount_msat = 0, fee_msat = 0;
        if (!params || !lsps2_parse_buy(params, &amount_msat, &fee_msat)) {
            response = lsps_build_error(req_id, LSPS_ERR_INVALID_PARAMS, "invalid params");
        } else {
            cJSON *result = cJSON_CreateObject();
            /* Return a fake SCID for the JIT channel */
            cJSON_AddStringToObject(result, "jit_channel_scid", "800000x1x0");
            response = lsps_build_response(req_id, result);
        }
    } else {
        response = lsps_build_error(req_id, LSPS_ERR_METHOD_NOT_FOUND, "method not found");
    }

    if (response) {
        wire_send(fd, MSG_LSPS_RESPONSE, response);
        cJSON_Delete(response);
    }
    return 1;
}

/* -----------------------------------------------------------------------
 * LSPS1 helpers
 * --------------------------------------------------------------------- */

cJSON *lsps1_build_get_info_response(const lsps1_info_t *info)
{
    if (!info) return NULL;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddNumberToObject(obj, "min_channel_balance_msat",
                             (double)info->min_channel_balance_msat);
    cJSON_AddNumberToObject(obj, "max_channel_balance_msat",
                             (double)info->max_channel_balance_msat);
    cJSON_AddNumberToObject(obj, "min_confirmations", info->min_confirmations);
    cJSON_AddNumberToObject(obj, "base_fee_msat", (double)info->base_fee_msat);
    cJSON_AddNumberToObject(obj, "fee_ppm", info->fee_ppm);
    return obj;
}

int lsps1_parse_create_order(const cJSON *params,
                               uint64_t *amount_msat, uint32_t *confs)
{
    if (!params || !cJSON_IsObject(params)) return 0;
    const cJSON *a = cJSON_GetObjectItemCaseSensitive(params, "channel_balance_msat");
    if (!a || !cJSON_IsNumber(a)) return 0;
    *amount_msat = (uint64_t)a->valuedouble;
    const cJSON *c = cJSON_GetObjectItemCaseSensitive(params, "confirms_within_blocks");
    *confs = (c && cJSON_IsNumber(c)) ? (uint32_t)c->valuedouble : 1;
    return 1;
}

/* -----------------------------------------------------------------------
 * LSPS2 helpers
 * --------------------------------------------------------------------- */

cJSON *lsps2_build_get_info_response(const lsps2_fee_params_t *params)
{
    if (!params) return NULL;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddNumberToObject(obj, "min_fee_msat", (double)params->min_fee_msat);
    cJSON_AddNumberToObject(obj, "fee_ppm", params->fee_ppm);
    cJSON_AddNumberToObject(obj, "min_channel_balance_msat",
                             (double)params->min_channel_balance_msat);
    cJSON_AddNumberToObject(obj, "max_channel_balance_msat",
                             (double)params->max_channel_balance_msat);
    return obj;
}

int lsps2_parse_buy(const cJSON *params,
                     uint64_t *amount_msat, uint64_t *fee_msat)
{
    if (!params || !cJSON_IsObject(params)) return 0;
    const cJSON *a = cJSON_GetObjectItemCaseSensitive(params, "opening_fee_params");
    /* opening_fee_params is an object; just check it exists */
    if (!a || !cJSON_IsObject(a)) return 0;
    const cJSON *amt = cJSON_GetObjectItemCaseSensitive(params, "payment_size_msat");
    *amount_msat = (amt && cJSON_IsNumber(amt)) ? (uint64_t)amt->valuedouble : 0;
    const cJSON *fee = cJSON_GetObjectItemCaseSensitive(a, "min_fee_msat");
    *fee_msat = (fee && cJSON_IsNumber(fee)) ? (uint64_t)fee->valuedouble : 0;
    return 1;
}
