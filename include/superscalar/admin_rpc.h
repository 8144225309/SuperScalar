/*
 * admin_rpc.h — JSON-RPC 2.0 Unix-socket admin interface
 *
 * Provides a CLN-compatible operator interface over a Unix domain socket.
 * The core dispatch function admin_rpc_handle_request() is pure and
 * testable without a real socket.
 *
 * Reference: CLN lightningd/jsonrpc.c, LDK-node lightning_node_manager.rs,
 *            LND rpcserver.go.
 */

#ifndef SUPERSCALAR_ADMIN_RPC_H
#define SUPERSCALAR_ADMIN_RPC_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "peer_mgr.h"
#include "payment.h"
#include "invoice.h"
#include "htlc_forward.h"
#include "mpp.h"
#include "lsp_channels.h"
#include "gossip_store.h"
#include "fee_estimator.h"
#include "pathfind.h"
#include "wallet_source.h"

#define ADMIN_RPC_RESPONSE_MAX  65536

/*
 * Context passed to every RPC handler.
 * Pointers may be NULL — handlers that need them return an error.
 */
typedef struct {
    secp256k1_context      *ctx;
    unsigned char           node_privkey[32];   /* derive node pubkey from this */

    peer_mgr_t             *pmgr;
    lsp_channel_mgr_t      *channel_mgr;
    payment_table_t        *payments;
    bolt11_invoice_table_t *invoices;
    gossip_store_t         *gossip;
    htlc_forward_table_t   *fwd;
    mpp_table_t            *mpp;
    fee_estimator_t        *fee_est;
    uint32_t               *block_height;       /* current chain tip; may be NULL */
    wallet_source_t        *wallet;             /* on-chain wallet; NULL = no channel open */
    volatile int           *shutdown_flag;

    /* Unix socket state */
    int  listen_fd;
    char socket_path[256];
} admin_rpc_t;

/*
 * Initialise admin_rpc_t.
 * Returns 1 on success, 0 if socket could not be bound.
 * Pass socket_path="" to skip socket creation (useful for unit tests).
 */
int admin_rpc_init(admin_rpc_t *rpc, const char *socket_path);

/*
 * Pure dispatch: parse json_in as a JSON-RPC 2.0 request, execute the
 * method, write the response to json_out (NUL-terminated).
 * Returns bytes written to json_out (not including NUL), 0 on error.
 * Thread-safe as long as rpc->shutdown_flag write is atomic.
 */
size_t admin_rpc_handle_request(admin_rpc_t *rpc,
                                 const char  *json_in,
                                 char        *json_out,
                                 size_t       out_cap);

/*
 * Service one connection on rpc->listen_fd (blocking).
 * Reads a newline-terminated JSON-RPC request, calls handle_request,
 * writes the response back, closes the connection.
 * Returns 1 if a request was handled, 0 on socket error / no connection.
 */
int admin_rpc_service(admin_rpc_t *rpc);

/*
 * Close the listen socket and unlink the socket file.
 */
void admin_rpc_close(admin_rpc_t *rpc);

#endif /* SUPERSCALAR_ADMIN_RPC_H */
