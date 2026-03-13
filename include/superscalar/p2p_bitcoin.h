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
    int      fd;                 /* TCP socket (-1 = not connected)      */
    uint8_t  magic[4];           /* network-specific magic bytes         */
    uint32_t peer_version;       /* protocol version negotiated          */
    int32_t  peer_start_height;  /* chain tip reported in version msg    */
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
 * Block header sync (BIP 157 Phase 1: replace RPC height/hash lookups)
 * --------------------------------------------------------------------- */

/*
 * Send a getheaders request to download block headers.
 *   locator_hashes : array of n_locator known block hashes (most-recent first).
 *                    Pass NULL / 0 for a cold start (no known headers).
 *   stop_hash32    : fetch headers up to this hash; NULL or all-zeros means
 *                    "as many as possible" (up to 2000 per BIP 31).
 * Returns 1 on success.
 */
int p2p_send_getheaders(p2p_conn_t *conn,
                        const uint8_t (*locator_hashes)[32], size_t n_locator,
                        const uint8_t *stop_hash32);

/*
 * Receive a headers response (skips ping/pong and other housekeeping
 * messages transparently).
 *
 *   hashes_out  : caller-allocated array of at least max_headers entries;
 *                 receives SHA256d(80-byte header) for each returned block
 *   max_headers : capacity of hashes_out (use 2000 — the P2P max per reply)
 *
 * Returns number of headers received (0 .. 2000), or -1 on disconnect.
 */
int p2p_recv_headers(p2p_conn_t *conn,
                     uint8_t (*hashes_out)[32], size_t max_headers);

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
 * BIP 157 filter header chain download
 * --------------------------------------------------------------------- */

/*
 * Send a getcfheaders request.  Same wire layout as getcfilters (37 bytes):
 *   filter_type(1) + start_height(4 LE) + stop_hash(32)
 * Returns 1 on success.
 *
 * The peer responds with one cfheaders message containing up to 2000
 * filter header hashes plus the prev_filter_header before start_height.
 */
int p2p_send_getcfheaders(p2p_conn_t *conn, uint32_t start_height,
                          const uint8_t *stop_hash32);

/*
 * Receive one cfheaders response (skips ping/pong transparently).
 *
 * Outputs (all required, non-NULL):
 *   stop_hash_out        : 32-byte hash of the last block in the range
 *   prev_filter_hdr_out  : 32-byte filter header immediately before start_height
 *                          (all zeros when start_height == 0)
 *   headers_out          : heap-allocated array of count × 32 bytes;
 *                          caller must free() (even on return 0)
 *   count_out            : number of filter headers in *headers_out
 *
 * Returns  1 on success
 *          0 on timeout or soft error
 *         -1 on disconnect or protocol error
 */
int p2p_recv_cfheaders(p2p_conn_t *conn,
                       uint8_t  stop_hash_out[32],
                       uint8_t  prev_filter_hdr_out[32],
                       uint8_t **headers_out,
                       size_t  *count_out);

/* -----------------------------------------------------------------------
 * P2P block download and transaction scanning
 * --------------------------------------------------------------------- */

/*
 * Callback invoked by p2p_scan_block_txs for each transaction in a block.
 * Matches the regtest_tx_callback_t signature for drop-in compatibility.
 *   txid_hex : 64-char display-order (reversed) hex string + NUL
 *   n_outputs: number of outputs
 *   spks     : array of n_outputs scriptPubKey byte spans (not heap-owned)
 *   spk_lens : array of n_outputs scriptPubKey byte lengths
 *   ctx      : opaque caller context
 */
typedef void (*p2p_block_scan_cb_t)(const char *txid_hex,
                                     size_t n_outputs,
                                     const unsigned char **spks,
                                     const size_t *spk_lens,
                                     void *ctx);

/*
 * Send a getdata(MSG_BLOCK, block_hash32) request.
 * Returns 1 on success.
 */
int p2p_send_getdata_block(p2p_conn_t *conn, const uint8_t *block_hash32);

/*
 * Receive one "block" message (skips ping/pong transparently).
 *   block_out     : set to a heap-allocated buffer holding the full block;
 *                   caller must free() even when return value is not 1
 *   block_len_out : byte length of *block_out
 * Returns  1 on success
 *          0 on timeout
 *         -1 on disconnect
 */
int p2p_recv_block(p2p_conn_t *conn,
                   uint8_t **block_out, size_t *block_len_out);

/*
 * Parse a raw Bitcoin block (as received via P2P) and invoke callback for
 * each transaction.  Handles both legacy and segwit serialization.
 * Returns the number of transactions processed (>= 0), or -1 on parse error.
 */
int p2p_scan_block_txs(const uint8_t *block, size_t block_len,
                       p2p_block_scan_cb_t callback, void *ctx);

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
 * Mempool awareness (BIP 35)
 * --------------------------------------------------------------------- */

/*
 * Send a `mempool` message (BIP 35) to ask the peer to announce all current
 * mempool transactions via `inv(MSG_TX, ...)` messages.
 * Only useful when connected to a peer that supports BIP 35 (version >= 60002).
 * Returns 1 on success.
 */
int p2p_send_mempool(p2p_conn_t *conn);

/*
 * Non-blocking poll for pending `inv(MSG_TX)` messages.  Sets a short socket
 * receive timeout (timeout_ms milliseconds), reads up to 32 P2P messages, and
 * collects the internal-byte-order txids of any MSG_TX inv entries into
 * txids_out[].  Silently handles ping/pong housekeeping.  Restores the normal
 * 30-second receive timeout before returning.
 *
 *   txids_out  : caller-allocated array of at least max_txids × 32-byte entries
 *   max_txids  : capacity of txids_out
 *   timeout_ms : milliseconds to wait for the first message (50–200 ms typical)
 *
 * Returns the number of unique MSG_TX txids collected (0 if none or on error).
 */
int p2p_poll_inv(p2p_conn_t *conn,
                 uint8_t txids_out[][32], int max_txids,
                 int timeout_ms);

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
