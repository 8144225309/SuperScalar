#ifndef SUPERSCALAR_P2P_BITCOIN_H
#define SUPERSCALAR_P2P_BITCOIN_H

#include <stdint.h>
#include <stddef.h>

/*
 * Minimal Bitcoin P2P client for BIP 157/158 light client operation.
 *
 * Implements the subset of the Bitcoin P2P protocol needed to:
 *   - Perform the version/verack handshake with a full node
 *   - Download compact block filters (BIP 157 getcfilters/cfilter)
 *   - Broadcast raw transactions (inv/tx exchange)
 *
 * Design: synchronous blocking I/O.  The light client scan loop runs at
 * polling intervals, not real-time, so there is no need for a select/epoll
 * event loop.  Each function either succeeds, times out, or disconnects.
 *
 * Full block download via P2P (getdata/block wire parsing) is Phase 5.
 * For now, filter hits still fall back to the regtest RPC for the full-block
 * scan.  Everything except that one fallback is P2P-native.
 */

/* Maximum accepted payload size (4 MB — covers any valid mainnet block) */
#define P2P_MAX_PAYLOAD  (4 * 1024 * 1024)

/* BIP 157 basic filter type */
#define P2P_FILTER_BASIC 0x00

typedef struct {
    int      fd;              /* TCP socket (-1 = not connected)  */
    uint8_t  magic[4];        /* network-specific magic bytes     */
    uint32_t peer_version;    /* protocol version negotiated      */
} p2p_conn_t;

/* -----------------------------------------------------------------------
 * Connection
 * --------------------------------------------------------------------- */

/*
 * Open a TCP connection to host:port and complete the version/verack
 * handshake.  network must be one of "mainnet", "testnet", "signet",
 * "regtest" (or NULL which defaults to "mainnet").
 * Returns 1 on success, 0 on any failure.  conn->fd is set to -1 on
 * failure so p2p_close() is always safe to call.
 */
int p2p_connect(p2p_conn_t *conn, const char *host, int port,
                const char *network);

/* Close the socket and reset conn->fd to -1. Safe to call on an already
   closed connection. */
void p2p_close(p2p_conn_t *conn);

/* -----------------------------------------------------------------------
 * BIP 157 compact filter download
 * --------------------------------------------------------------------- */

/*
 * Send a getcfilters request.
 *   start_height : first block height to request a filter for
 *   stop_hash32  : 32-byte internal-order hash of the last block in the
 *                  range (for a single-block request this is just that
 *                  block's hash)
 * Returns 1 on success.
 *
 * The peer will respond with one cfilter message per block in
 * [start_height .. height(stop_hash)].  Call p2p_recv_cfilter() once
 * per expected response.
 */
int p2p_send_getcfilters(p2p_conn_t *conn, uint32_t start_height,
                         const uint8_t *stop_hash32);

/*
 * Receive one cfilter response (skips ping/pong and other housekeeping
 * messages transparently).
 *
 * Outputs (all required, non-NULL):
 *   block_hash32_out : 32-byte internal-order hash of the filtered block
 *   filter_out       : heap-allocated raw filter bytes; caller must free()
 *   filter_len_out   : byte length of *filter_out
 *   key_out          : 16-byte SipHash key = first 16 bytes of block hash
 *
 * Returns  1 on success
 *          0 on timeout or soft error (skip block, keep going)
 *         -1 on disconnect or protocol error (reconnect needed)
 */
int p2p_recv_cfilter(p2p_conn_t *conn,
                     uint8_t  block_hash32_out[32],
                     uint8_t **filter_out, size_t *filter_len_out,
                     uint8_t  key_out[16]);

/* -----------------------------------------------------------------------
 * Transaction broadcast
 * --------------------------------------------------------------------- */

/*
 * Broadcast a raw transaction to the connected peer.
 *   tx_bytes    : complete serialised transaction
 *   tx_len      : byte length
 *   txid32_out  : if non-NULL, receives the txid in internal byte order
 *                 (SHA256d of the raw tx bytes, little-endian)
 * Returns 1 on success (peer acknowledged with getdata and we sent tx).
 */
int p2p_broadcast_tx(p2p_conn_t *conn,
                     const uint8_t *tx_bytes, size_t tx_len,
                     uint8_t txid32_out[32]);

/* -----------------------------------------------------------------------
 * Low-level framing helpers (exposed for unit tests)
 * --------------------------------------------------------------------- */

/*
 * Build a framed P2P message (24-byte header + payload) and write it to
 * conn->fd.  payload may be NULL when payload_len == 0.
 * Returns 1 on success.
 */
int p2p_send_msg(p2p_conn_t *conn, const char *command,
                 const uint8_t *payload, uint32_t payload_len);

/*
 * Read one P2P message from conn->fd.
 *   command_out : caller-supplied buffer of at least 13 bytes; receives
 *                 the null-terminated command string
 *   payload_out : set to a heap-allocated buffer holding the payload;
 *                 caller must free() even when return value is 0
 * Returns the payload length (>= 0) on success, -1 on error/disconnect.
 */
int p2p_recv_msg(p2p_conn_t *conn, char command_out[13],
                 uint8_t **payload_out);

#endif /* SUPERSCALAR_P2P_BITCOIN_H */
