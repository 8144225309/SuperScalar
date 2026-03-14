#ifndef SUPERSCALAR_BIP158_BACKEND_H
#define SUPERSCALAR_BIP158_BACKEND_H

#include "chain_backend.h"
#include "p2p_bitcoin.h"
#include "fee_estimator.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * BIP 157/158 compact block filter light client backend.
 *
 * Replaces bitcoin-cli TXID polling with compact block filter queries:
 *   - Downloads one compact filter (~10 KB) per new block from a BIP 157 peer
 *   - Checks all registered scriptPubKeys against the GCS filter
 *   - Only downloads the full block (~1-2 MB) on a filter match
 *   - Skips the vast majority of blocks with no relevant scripts
 *
 * Usage:
 *   1. bip158_backend_init(&backend, "mainnet")
 *   2. watchtower_set_chain_backend(&wt, &backend.base)
 *   3. Call backend.base.register_script() for each watched scriptPubKey
 *      (watchtower_watch / watchtower_watch_factory_node do this automatically)
 *   4. watchtower_check() drives the scan loop
 *
 * SuperScalar script load profile:
 *   - Steady state (1 active factory epoch):   ~80 scriptPubKeys
 *   - During factory rotation (2 epochs):      ~160 scriptPubKeys
 *   - With watchtower history (open channels): 100-300 scriptPubKeys typical
 */

/* GCS parameters for BIP 158 basic filter (type 0) */
#define BIP158_P  19           /* Golomb-Rice parameter                */
#define BIP158_M  784931ULL    /* False-positive rate denominator (1/M) */

/* Capacity limits */
#define BIP158_MAX_SCRIPTS     512   /* watched scriptPubKeys             */
#define BIP158_TX_CACHE_SIZE   256   /* confirmed tx entries              */

/* Header ring buffer: one difficulty-adjustment window of block hashes.
   Indexed by (height % BIP158_HEADER_WINDOW) — wraps safely for long chains. */
#define BIP158_HEADER_WINDOW  2016   /* ~63 KB inline in the struct       */

typedef struct {
    unsigned char spk[34];
    size_t        spk_len;
} bip158_script_t;

typedef struct {
    unsigned char txid[32];  /* internal byte order */
    int32_t       height;
} bip158_tx_entry_t;

typedef struct {
    chain_backend_t  base;   /* Must be first — cast-compatible              */

    /* Script registry */
    bip158_script_t  scripts[BIP158_MAX_SCRIPTS];
    size_t           n_scripts;

    /* Confirmed tx cache: populated when a filter match triggers a full-block
       download and the committing tx is found inside */
    bip158_tx_entry_t tx_cache[BIP158_TX_CACHE_SIZE];
    size_t            n_tx_cache;
    size_t            tx_cache_cursor;  /* next eviction slot (wraps at BIP158_TX_CACHE_SIZE) */

    /* Chain tip (updated on each successful filter download) */
    int32_t          tip_height;

    /* Block header ring buffer — populated by bip158_sync_headers() via P2P.
       Stores SHA256d(80-byte header) for the most recent BIP158_HEADER_WINDOW
       heights.  Indexed by height % BIP158_HEADER_WINDOW.
       headers_synced == -1 until the first header sync completes. */
    uint8_t          header_hashes[BIP158_HEADER_WINDOW][32];
    int32_t          headers_synced;

    /* Filter header ring buffer — populated by bip158_sync_filter_headers().
       BIP 157 filter header chain: filter_header[N] =
         SHA256d(SHA256d(filter_bytes[N]) || filter_header[N-1])
       prev at height -1 is all zeros.  Indexed by height % BIP158_HEADER_WINDOW.
       filter_headers_synced == -1 until the first cfheaders sync completes. */
    uint8_t          filter_headers[BIP158_HEADER_WINDOW][32];
    int32_t          filter_headers_synced;

    /* Network ("mainnet", "signet", "testnet") */
    char             network[16];

    /* RPC context for Phase 3 scan loop (regtest_t *); NULL when using P2P */
    void            *rpc_ctx;

    /* SQLite persistence handle (persist_t *); NULL = no checkpointing.
       Set by bip158_backend_set_db(); not owned — caller manages lifetime. */
    void            *db;

    /* P2P peer connection.  p2p.fd == -1 when not connected.
       Set by bip158_backend_connect_p2p(); closed by bip158_backend_free(). */
    p2p_conn_t       p2p;

    /* Peer rotation (Phase 6): up to BIP158_MAX_PEERS peers tried in round-robin
       order when a connection drops.  Populated by bip158_backend_connect_p2p()
       (sets slot 0) and bip158_backend_add_peer() (appends further slots). */
#define BIP158_MAX_PEERS 8
    char             peer_hosts[BIP158_MAX_PEERS][256];
    int              peer_ports[BIP158_MAX_PEERS];
    int              n_peers;        /* number of configured peers (>= 1 when connected) */
    int              current_peer;   /* index of the last successfully connected peer */

    /* Mempool awareness (Phase 7, BIP 35).
       Set by bip158_backend_set_mempool_cb(); fired for each unconfirmed
       MSG_TX seen via P2P inv subscription. */
    void           (*mempool_cb)(const char *txid_hex, void *ctx);
    void            *mempool_ctx;
    int              mempool_subscribed; /* 1 after mempool message sent */

    /* Optional fee estimator — receives per-block fee samples after each
       full-block download.  Set by bip158_backend_set_fee_estimator().
       Not owned; caller manages lifetime. */
    fee_estimator_t *fee_estimator;

    /* Optional UTXO tracking callbacks — fired for every output and input
     * in each full-block P2P download.  Set via bip158_backend_set_utxo_cb().
     * Allows wallet_source_hd_t to detect incoming UTXOs and spends.
     * NULL = disabled. */
    p2p_output_cb_t utxo_found_cb;
    p2p_input_cb_t  utxo_spent_cb;
    void           *utxo_cb_ctx;
} bip158_backend_t;

/* Parse a "HOST:PORT" string.  host_out receives the NUL-terminated hostname,
 * *port_out the port number.  Returns 1 on success, 0 on error.
 * Shared utility used by superscalar_lsp and superscalar_client. */
int bip158_parse_host_port(const char *arg,
                            char *host_out, size_t host_cap,
                            int *port_out);

/*
 * Verify hard-coded BIP 158 filter header checkpoints for a received batch.
 * Called automatically by bip158_sync_filter_headers() after each cfheaders
 * batch.  Also exposed for unit testing.
 *
 * start_height: block height of hdrs[0]
 * n:            number of headers in the batch (already stored in ring buffer)
 *
 * Returns 1 if all in-range checkpoints match, 0 on mismatch.
 * On mismatch, closes the peer connection so the caller can reconnect.
 */
int bip158_verify_filter_checkpoints(bip158_backend_t *b,
                                      int start_height, int n);

/*
 * Return the number of hard-coded filter header checkpoints for the given
 * network name ("mainnet", "testnet3" / "testnet").  Returns 0 for unknown
 * networks (e.g. "regtest", "signet").  Useful for diagnostics.
 */
int bip158_backend_checkpoint_count(const char *network);

/* -------------------------------------------------------------------------
 * Phase 6 — GCS encoder and filter header construction
 * ------------------------------------------------------------------------- */

/*
 * Build a BIP 158 compact filter (type 0) from an array of scripts.
 * Output format: varint(N) || Golomb-Rice encoded sorted deltas.
 * This is exactly the payload consumed by bip158_gcs_match_any /
 * bip158_scan_filter after stripping the leading varint.
 *
 * key16:    first 16 bytes of the block hash (SipHash key)
 * out_buf:  output buffer; must be at least bip158_gcs_build_size(n) bytes
 * Returns bytes written, or 0 on error.
 */
size_t bip158_gcs_build_size(size_t n);
size_t bip158_gcs_build(const bip158_script_t *scripts, size_t n,
                         const unsigned char *key16,
                         unsigned char *out_buf, size_t out_cap);

/*
 * Compute a BIP 157 filter header:
 *   filter_header[N] = SHA256d( SHA256d(filter_bytes) || prev_filter_header[N-1] )
 *
 * filter_bytes / filter_len : complete serialised filter (varint(N) + GCS bits)
 * prev_filter_hdr           : filter header at height N-1; all-zeros at height 0
 * out                       : 32-byte output
 */
void bip158_compute_filter_header(const unsigned char *filter_bytes,
                                   size_t filter_len,
                                   const unsigned char prev_filter_hdr[32],
                                   unsigned char out[32]);

/* Initialise backend. Returns 1 on success, 0 on failure. */
int  bip158_backend_init(bip158_backend_t *backend, const char *network);
void bip158_backend_free(bip158_backend_t *backend);

/*
 * Attach a fee estimator to receive per-block fee samples.
 * After each full-block P2P download, bip158_backend_scan() calls
 * fee_estimator_blocks_add_sample() if fe is a fee_estimator_blocks_t,
 * and fee_estimator_blocks_set_floor() after connect/reconnect.
 * Pass NULL to detach.  The caller retains ownership.
 */
void bip158_backend_set_fee_estimator(bip158_backend_t *backend,
                                       fee_estimator_t *fe);

/*
 * Attach a regtest_t RPC handle for the Phase-3 scan loop.
 * Must be called before bip158_backend_scan() when not using a P2P peer.
 * rt is typed void* to avoid pulling regtest.h into this header.
 */
void bip158_backend_set_rpc(bip158_backend_t *backend, void *rt);

/*
 * Attach a persist_t database handle for scan checkpointing (Phase 4).
 * When set, bip158_backend_scan() saves tip_height + ring buffers after each
 * successful filter pass, and bip158_backend_restore_checkpoint() loads them
 * on startup so scanning resumes from the last committed block.
 * db is typed void* to avoid pulling persist.h into this header.
 * The caller retains ownership; the backend does not close the handle.
 */
void bip158_backend_set_db(bip158_backend_t *backend, void *db);

/*
 * Register a callback to be invoked for each unconfirmed transaction seen via
 * P2P mempool inv subscription (Phase 7).  txid_hex is a 64-char display-order
 * (reversed) hex string.  Pass NULL to disable.
 */
void bip158_backend_set_mempool_cb(bip158_backend_t *backend,
                                    void (*cb)(const char *txid_hex, void *ctx),
                                    void *ctx);

/*
 * Poll for pending mempool inv announcements from the connected peer.
 * Subscribes via BIP 35 `mempool` message on first call.  Reads pending
 * inv(MSG_TX) messages (up to 100 ms wait) and fires the registered
 * mempool_cb for each new txid seen.
 * Returns the number of txids dispatched, or 0 if none / no connection.
 * Safe to call frequently (e.g., every scan cycle).
 */
int bip158_backend_poll_mempool(bip158_backend_t *backend);

/*
 * Add a fallback peer for automatic rotation on disconnect (Phase 6).
 * Up to BIP158_MAX_PEERS peers total (including the primary set by
 * bip158_backend_connect_p2p()).  Silently ignored when the list is full.
 */
void bip158_backend_add_peer(bip158_backend_t *backend,
                              const char *host, int port);

/*
 * Attempt to reconnect to the next available peer in the rotation list.
 * Tries each peer once, starting from the one after current_peer.
 * Returns 1 if a connection was established, 0 if all peers failed.
 * Called automatically by bip158_backend_scan() on mid-scan disconnect;
 * also available for manual use by callers.
 */
int bip158_backend_reconnect(bip158_backend_t *backend);

/*
 * Restore tip_height, headers_synced, filter_headers_synced, and both ring
 * buffers from the checkpoint saved in the attached persist_t database.
 * No-op if no database is attached or no checkpoint row exists.
 * Call once after bip158_backend_set_db() and before the first scan().
 * Returns 1 if a checkpoint was loaded, 0 otherwise.
 */
int bip158_backend_restore_checkpoint(bip158_backend_t *backend);

/*
 * Open a Bitcoin P2P connection to host:port and perform the version/verack
 * handshake.  On success, bip158_backend_scan() will use this connection for
 * filter fetching instead of the regtest RPC.  cb_send_raw_tx() will also
 * broadcast via P2P once connected.
 * Returns 1 on success, 0 on failure (backend continues using rpc_ctx).
 */
int bip158_backend_connect_p2p(bip158_backend_t *backend,
                                const char *host, int port);

/*
 * Walk blocks from last synced height + 1 up to the current chain tip.
 * For each new block:
 *   1. Fetch compact filter — via P2P getcfilters/cfilter if connected,
 *      otherwise via regtest RPC getblockfilter.
 *   2. Run the GCS filter against all registered scriptPubKeys.
 *   3. On a match, fetch the full block via RPC (Phase 3/4) and cache
 *      every tx whose outputs include a watched script.
 * Updates backend->tip_height on success.
 * Returns the number of matched blocks (may include false positives),
 * or -1 on hard error (no rpc_ctx attached; rpc_ctx required even when P2P
 * is active for block-height and block-hash lookup until Phase 5).
 */
int bip158_backend_scan(bip158_backend_t *backend);

/*
 * Low-level GCS helpers — exposed for unit testing.
 *
 * bip158_gcs_match_any: check whether any of the n_scripts watched scripts
 * appear in a serialised GCS filter.
 *   filter_data / filter_len : raw bytes after the leading N varint
 *   n_items                  : N decoded from that varint
 *   key16                    : 16-byte SipHash key (first 16 bytes of block hash)
 * Returns 1 if at least one script matches (or false-positive), 0 if none.
 */
int bip158_gcs_match_any(const unsigned char *filter_data, size_t filter_len,
                          uint64_t n_items,
                          const unsigned char *key16,
                          const bip158_script_t *scripts, size_t n_scripts);

/*
 * Store a confirmed tx in the backend's cache so get_confirmations() can
 * return meaningful results after a filter match drives a full-block download.
 */
void bip158_cache_tx(bip158_backend_t *backend,
                     const unsigned char *txid32, int32_t height);

/*
 * Scan a full serialised BIP 158 filter (including leading N varint) against
 * the backend's script registry. Returns 1 on any match, 0 if none.
 * key16: first 16 bytes of the block hash (SipHash key).
 * Called internally by the scan loop once per new block.
 */
int bip158_scan_filter(bip158_backend_t *backend,
                        const unsigned char *filter_bytes, size_t filter_len,
                        const unsigned char *key16);

/*
 * Register callbacks fired for every tx output and input in each downloaded
 * full block.  Enables in-process wallet UTXO tracking without RPC.
 * found_cb: fired for each output (txid, vout_idx, amount, spk, spk_len)
 * spent_cb: fired for each input  (spending_txid, prev_txid32, prev_vout)
 * Pass NULL to disable.  Caller retains ownership.
 */
void bip158_backend_set_utxo_cb(bip158_backend_t *backend,
                                  p2p_output_cb_t found_cb,
                                  p2p_input_cb_t spent_cb,
                                  void *ctx);

#endif /* SUPERSCALAR_BIP158_BACKEND_H */
