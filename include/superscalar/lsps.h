#ifndef SUPERSCALAR_LSPS_H
#define SUPERSCALAR_LSPS_H

#include <stdint.h>
#include <stddef.h>
#include <cJSON.h>

/*
 * LSPS0/1/2 standard protocol implementation.
 *
 * LSPS0: JSON-RPC 2.0 transport over noise-encrypted peer connection.
 * LSPS1: Channel purchase API (wraps factory creation).
 * LSPS2: JIT channel API (wraps jit_channel_create/migrate).
 *
 * Wire message types (added to wire.h):
 *   0x65: MSG_LSPS_REQUEST   (client → LSP)
 *   0x66: MSG_LSPS_RESPONSE  (LSP → client)
 *   0x67: MSG_LSPS_NOTIFY    (LSP → client: async)
 */

/* JSON-RPC 2.0 error codes */
#define LSPS_ERR_PARSE_ERROR      (-32700)
#define LSPS_ERR_INVALID_REQUEST  (-32600)
#define LSPS_ERR_METHOD_NOT_FOUND (-32601)
#define LSPS_ERR_INVALID_PARAMS   (-32602)
#define LSPS_ERR_INTERNAL_ERROR   (-32603)

/* Context passed from the server message loop into the LSPS handler.
   Required so lsps2.buy can call jit_channel_create(). */
typedef struct {
    void  *mgr;          /* lsp_channel_mgr_t * */
    void  *lsp;          /* lsp_t * */
    size_t client_idx;   /* index of requesting client in lsp->client_fds */
} lsps_ctx_t;

/*
 * Parse an incoming LSPS JSON-RPC request.
 * Returns the method name string (points into json, do not free separately).
 * id_out receives the request id (may be 0 if absent/null).
 * Returns NULL on parse error.
 */
const char *lsps_parse_request(const cJSON *json, int *id_out);

/*
 * Build a JSON-RPC 2.0 success response.
 * result: cJSON object for the result field (ownership transferred).
 * Returns a new cJSON object (caller must cJSON_Delete).
 */
cJSON *lsps_build_response(int id, cJSON *result);

/*
 * Build a JSON-RPC 2.0 error response.
 * Returns a new cJSON object (caller must cJSON_Delete).
 */
cJSON *lsps_build_error(int id, int code, const char *message);

/*
 * Dispatch an LSPS request to the appropriate handler.
 * ctx: LSPS context with mgr, lsp, and client_idx (may be NULL for testing).
 * fd: client connection file descriptor for sending responses.
 * json: the parsed JSON-RPC request object.
 * Returns 1 if handled, 0 if unknown method.
 */
int lsps_handle_request(const lsps_ctx_t *ctx, int fd, const cJSON *json);

/* -----------------------------------------------------------------------
 * LSPS1 — Channel purchase API
 * --------------------------------------------------------------------- */

typedef struct {
    uint64_t min_channel_balance_msat;
    uint64_t max_channel_balance_msat;
    uint32_t min_confirmations;
    uint64_t base_fee_msat;
    uint32_t fee_ppm;
} lsps1_info_t;

cJSON *lsps1_build_get_info_response(const lsps1_info_t *info);
int    lsps1_parse_create_order(const cJSON *params,
                                  uint64_t *amount_msat, uint32_t *confs);

/* -----------------------------------------------------------------------
 * LSPS2 — JIT channel API
 * --------------------------------------------------------------------- */

typedef struct {
    uint64_t min_fee_msat;
    uint32_t fee_ppm;
    uint64_t min_channel_balance_msat;
    uint64_t max_channel_balance_msat;
} lsps2_fee_params_t;

cJSON *lsps2_build_get_info_response(const lsps2_fee_params_t *params);
int    lsps2_parse_buy(const cJSON *params,
                        uint64_t *amount_msat, uint64_t *fee_msat);

#endif /* SUPERSCALAR_LSPS_H */
