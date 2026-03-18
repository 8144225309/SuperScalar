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

/*
 * In-memory order record stored by lsps1.create_order and retrieved by
 * lsps1.get_order.  The order registry is module-internal; these fields
 * mirror what the wire responses expose.
 */
typedef struct {
    int      order_id;
    uint64_t amount_msat;
    uint32_t confs;
    char     state[16];   /* "CREATED", "COMPLETED", … */
} lsps1_order_t;

cJSON *lsps1_build_get_info_response(const lsps1_info_t *info);
int    lsps1_parse_create_order(const cJSON *params,
                                  uint64_t *amount_msat, uint32_t *confs);

/*
 * Parse a lsps1.get_order params object.
 * Accepts "order_id" as either a JSON number or a decimal string.
 * Returns 1 on success, 0 on failure.
 */
int    lsps1_parse_get_order(const cJSON *params, int *order_id_out);

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

=======
/* -----------------------------------------------------------------------
 * LSPS2 — Deferred funding broadcast (PR #19 Commit 5)
 *
 * Funding tx is withheld until intercepted HTLCs cover the channel-open cost.
 * Set client_trusts_lsp = 1 in lsps_ctx_t for immediate broadcast (testnet).
 * --------------------------------------------------------------------- */

#define LSPS1_CONFIRM_TIMEOUT_BLOCKS 144 /* ~24 h of blocks: FAILED if confs not seen */
#define LSPS2_HTLC_WAIT_SECS    5     /* LDK: LIQUIDITY_REQUEST_TIMEOUT */
#define LSPS2_CLTV_DELTA       72     /* LDK: channel cltv expiry delta */
#define LSPS2_PENDING_MAX      16     /* max concurrent JIT channels pending */

typedef struct {
    int      active;
    uint64_t scid;                    /* intercept SCID assigned at buy */
    uint64_t amount_msat;             /* client requested amount */
    uint64_t fee_msat;                /* agreed fee */
    uint64_t cost_msat;               /* channel-open cost (= fee_msat) */
    uint64_t collected_msat;          /* sum of intercepted HTLCs so far */
    char     funding_tx_hex[4096];    /* serialised funding tx (held until covered) */
    uint32_t created_at;              /* unix timestamp */
    size_t   client_idx;
} lsps2_pending_t;

typedef struct {
    lsps2_pending_t entries[LSPS2_PENDING_MAX];
    int count;
} lsps2_pending_table_t;

/*
 * Called when an HTLC arrives on an intercept SCID.
 * Accumulates collected_msat. If collected >= cost_msat, broadcast funding tx
 * and call jit_channel_create(). Returns 1 if broadcast triggered, 0 if waiting.
 * mgr and lsp may be NULL in unit tests (no actual channel created).
 */
int lsps2_handle_intercept_htlc(lsps2_pending_table_t *tbl,
                                  uint64_t scid, uint64_t amount_msat,
                                  void *mgr, void *lsp);

/* Phase J: LSPS1 order state machine helpers */
int  lsps1_order_fund(int order_id, const char *funding_txid_hex,
                      uint32_t funded_at_height, int client_fd);
int  lsps1_order_tick(int order_id, uint32_t current_height);
void lsps1_orders_tick_all(uint32_t current_height);

/* Phase K: LSPS2 JIT pending lookup */
lsps2_pending_t *lsps2_pending_lookup(lsps2_pending_table_t *tbl,
                                       uint64_t scid);

/* Gap 2: expire HTLCs that have waited > LSPS2_HTLC_WAIT_SECS */
void lsps2_pending_expire(lsps2_pending_table_t *tbl);

>>>>>>> origin/superscalar-ln-parity-
/* -----------------------------------------------------------------------
 * LSPS2 — Deferred funding broadcast (PR #19 Commit 5)
 *
 * Funding tx is withheld until intercepted HTLCs cover the channel-open cost.
 * Set client_trusts_lsp = 1 in lsps_ctx_t for immediate broadcast (testnet).
 * --------------------------------------------------------------------- */

#define LSPS1_CONFIRM_TIMEOUT_BLOCKS 144 /* ~24 h of blocks: FAILED if confs not seen */
#define LSPS2_HTLC_WAIT_SECS    5     /* LDK: LIQUIDITY_REQUEST_TIMEOUT */
#define LSPS2_CLTV_DELTA       72     /* LDK: channel cltv expiry delta */
#define LSPS2_PENDING_MAX      16     /* max concurrent JIT channels pending */

typedef struct {
    int      active;
    uint64_t scid;                    /* intercept SCID assigned at buy */
    uint64_t amount_msat;             /* client requested amount */
    uint64_t fee_msat;                /* agreed fee */
    uint64_t cost_msat;               /* channel-open cost (= fee_msat) */
    uint64_t collected_msat;          /* sum of intercepted HTLCs so far */
    char     funding_tx_hex[4096];    /* serialised funding tx (held until covered) */
    uint32_t created_at;              /* unix timestamp */
    size_t   client_idx;
} lsps2_pending_t;

typedef struct {
    lsps2_pending_t entries[LSPS2_PENDING_MAX];
    int count;
} lsps2_pending_table_t;

/*
 * Called when an HTLC arrives on an intercept SCID.
 * Accumulates collected_msat. If collected >= cost_msat, broadcast funding tx
 * and call jit_channel_create(). Returns 1 if broadcast triggered, 0 if waiting.
 * mgr and lsp may be NULL in unit tests (no actual channel created).
 */
int lsps2_handle_intercept_htlc(lsps2_pending_table_t *tbl,
                                  uint64_t scid, uint64_t amount_msat,
                                  void *mgr, void *lsp);

/* Phase J: LSPS1 order state machine helpers */
int  lsps1_order_fund(int order_id, const char *funding_txid_hex,
                      uint32_t funded_at_height, int client_fd);
int  lsps1_order_tick(int order_id, uint32_t current_height);
void lsps1_orders_tick_all(uint32_t current_height);

/* Phase K: LSPS2 JIT pending lookup */
lsps2_pending_t *lsps2_pending_lookup(lsps2_pending_table_t *tbl,
                                       uint64_t scid);

/* Gap 2: expire HTLCs that have waited > LSPS2_HTLC_WAIT_SECS */
void lsps2_pending_expire(lsps2_pending_table_t *tbl);
#endif /* SUPERSCALAR_LSPS_H */
