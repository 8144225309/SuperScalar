#include "superscalar/bip158_backend.h"
#include "superscalar/p2p_bitcoin.h"
#include "superscalar/persist.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * SipHash-2-4
 * Used by BIP 158 to hash filter elements into [0, N*M).
 * ------------------------------------------------------------------------- */

#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define SIPHASH_ROUND(v0,v1,v2,v3) do { \
    v0 += v1; v1 = ROTL64(v1,13); v1 ^= v0; v0 = ROTL64(v0,32); \
    v2 += v3; v3 = ROTL64(v3,16); v3 ^= v2;                      \
    v0 += v3; v3 = ROTL64(v3,21); v3 ^= v0;                      \
    v2 += v1; v1 = ROTL64(v1,17); v1 ^= v2; v2 = ROTL64(v2,32); \
} while(0)

static uint64_t load_le64(const unsigned char *p)
{
    return (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16)| ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32)| ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48)| ((uint64_t)p[7] << 56);
}

static uint64_t siphash24(const unsigned char *key16,
                           const unsigned char *data, size_t len)
{
    uint64_t k0 = load_le64(key16);
    uint64_t k1 = load_le64(key16 + 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = load_le64(data + i * 8);
        v3 ^= m;
        SIPHASH_ROUND(v0,v1,v2,v3);
        SIPHASH_ROUND(v0,v1,v2,v3);
        v0 ^= m;
    }

    /* Last (partial) block — pad with message length in high byte */
    uint64_t last = (uint64_t)(len & 0xff) << 56;
    size_t rem = len & 7;
    const unsigned char *tail = data + blocks * 8;
    switch (rem) {
        case 7: last |= (uint64_t)tail[6] << 48; /* fall through */
        case 6: last |= (uint64_t)tail[5] << 40; /* fall through */
        case 5: last |= (uint64_t)tail[4] << 32; /* fall through */
        case 4: last |= (uint64_t)tail[3] << 24; /* fall through */
        case 3: last |= (uint64_t)tail[2] << 16; /* fall through */
        case 2: last |= (uint64_t)tail[1] <<  8; /* fall through */
        case 1: last |= (uint64_t)tail[0];        /* fall through */
        default: break;
    }
    v3 ^= last;
    SIPHASH_ROUND(v0,v1,v2,v3);
    SIPHASH_ROUND(v0,v1,v2,v3);
    v0 ^= last;

    /* Finalise */
    v2 ^= 0xff;
    SIPHASH_ROUND(v0,v1,v2,v3);
    SIPHASH_ROUND(v0,v1,v2,v3);
    SIPHASH_ROUND(v0,v1,v2,v3);
    SIPHASH_ROUND(v0,v1,v2,v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* -------------------------------------------------------------------------
 * BIP 158 hash: map a scriptPubKey to [0, F) where F = N * M
 * Uses 128-bit multiply-shift to avoid modulo bias.
 * ------------------------------------------------------------------------- */

static uint64_t bip158_hash(const unsigned char *key16,
                             const unsigned char *spk, size_t spk_len,
                             uint64_t F)
{
    uint64_t h = siphash24(key16, spk, spk_len);
#ifdef __SIZEOF_INT128__
    return (uint64_t)((__uint128_t)h * F >> 64);
#else
    /* Portable 64x64→high-64 multiply using 32-bit halves.
     * Split: h = hi_h*2^32 + lo_h, F = hi_F*2^32 + lo_F
     * (h*F) >> 64 = hh + (lh>>32) + (hl>>32) + (mid>>32)
     * where mid = (ll>>32) + (lh & mask32) + (hl & mask32) */
    uint64_t lo_h  = h & 0xffffffffULL;
    uint64_t hi_h  = h >> 32;
    uint64_t lo_F  = F & 0xffffffffULL;
    uint64_t hi_F  = F >> 32;
    uint64_t ll    = lo_h * lo_F;
    uint64_t lh    = lo_h * hi_F;
    uint64_t hl    = hi_h * lo_F;
    uint64_t hh    = hi_h * hi_F;
    uint64_t mid   = (ll >> 32) + (lh & 0xffffffffULL) + (hl & 0xffffffffULL);
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}

/* -------------------------------------------------------------------------
 * Bit reader (MSB-first) for Golomb-Rice decoding
 * ------------------------------------------------------------------------- */

typedef struct {
    const unsigned char *data;
    size_t               len_bits;
    size_t               pos;    /* current bit position */
} bit_reader_t;

static void bit_reader_init(bit_reader_t *r,
                             const unsigned char *data, size_t len_bytes)
{
    r->data     = data;
    r->len_bits = len_bytes * 8;
    r->pos      = 0;
}

/* Read one bit (MSB-first). Returns 0 or 1, or -1 on overrun. */
static int read_bit(bit_reader_t *r)
{
    if (r->pos >= r->len_bits) return -1;
    int bit = (r->data[r->pos / 8] >> (7 - (r->pos % 8))) & 1;
    r->pos++;
    return bit;
}

/* Read P bits as a uint64. Returns -1 on overrun. */
static int64_t read_bits(bit_reader_t *r, int p)
{
    uint64_t val = 0;
    for (int i = 0; i < p; i++) {
        int b = read_bit(r);
        if (b < 0) return -1;
        val = (val << 1) | (uint64_t)b;
    }
    return (int64_t)val;
}

/* Golomb-Rice decode one value. Returns delta or -1 on error. */
static int64_t golomb_rice_decode(bit_reader_t *r)
{
    /* Unary quotient: q one-bits followed by a zero-bit (BIP 158 Golomb-Rice).
       Bound to prevent runaway decode on malformed / fuzz input. */
    uint64_t q = 0;
    int b;
    while ((b = read_bit(r)) == 1) {
        if (++q > (1ULL << 30)) return -1;  /* unreasonably large quotient */
    }
    if (b < 0) return -1;  /* overrun */

    /* P-bit remainder */
    int64_t rem = read_bits(r, BIP158_P);
    if (rem < 0) return -1;

    return (int64_t)((q << BIP158_P) | (uint64_t)rem);
}

/* -------------------------------------------------------------------------
 * Bitcoin varint decoder (for reading N from the filter header)
 * ------------------------------------------------------------------------- */

/* Returns bytes consumed, writes value to *out. Returns 0 on error. */
static size_t read_varint(const unsigned char *data, size_t len, uint64_t *out)
{
    if (len < 1) return 0;
    uint8_t first = data[0];
    if (first < 0xfd) {
        *out = first;
        return 1;
    } else if (first == 0xfd) {
        if (len < 3) return 0;
        *out = (uint64_t)data[1] | ((uint64_t)data[2] << 8);
        return 3;
    } else if (first == 0xfe) {
        if (len < 5) return 0;
        *out = (uint64_t)data[1]        | ((uint64_t)data[2] << 8)  |
               ((uint64_t)data[3] << 16)| ((uint64_t)data[4] << 24);
        return 5;
    } else {
        if (len < 9) return 0;
        *out = (uint64_t)data[1]        | ((uint64_t)data[2] <<  8) |
               ((uint64_t)data[3] << 16)| ((uint64_t)data[4] << 24)|
               ((uint64_t)data[5] << 32)| ((uint64_t)data[6] << 40)|
               ((uint64_t)data[7] << 48)| ((uint64_t)data[8] << 56);
        return 9;
    }
}

/* -------------------------------------------------------------------------
 * Test-only export: wraps the static bip158_hash so unit tests can compute
 * expected hash values without duplicating the SipHash implementation.
 * ------------------------------------------------------------------------- */
uint64_t _bip158_test_hash(const unsigned char *key16,
                            const unsigned char *spk, size_t spk_len,
                            uint64_t F)
{
    return bip158_hash(key16, spk, spk_len, F);
}

/* -------------------------------------------------------------------------
 * GCS batch match (public, exposed for unit tests)
 *
 * Checks whether any of n_scripts watched scripts appear in the filter.
 * filter_data/filter_len: raw GCS bytes (after the leading N varint).
 * n_items: the N decoded from that varint.
 * key16: 16-byte SipHash key (first 16 bytes of the block hash).
 *
 * Algorithm:
 *   1. Hash each watched script to [0, F) where F = N * M
 *   2. Sort query hashes
 *   3. Decode the GCS (sorted delta-encoded values) and merge with queries
 * Returns 1 on any match (including false positives), 0 if no match.
 * ------------------------------------------------------------------------- */

static int cmp_uint64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int bip158_gcs_match_any(const unsigned char *filter_data, size_t filter_len,
                          uint64_t n_items,
                          const unsigned char *key16,
                          const bip158_script_t *scripts, size_t n_scripts)
{
    if (!n_items || !n_scripts || !filter_data || !scripts) return 0;

    /* Guard against overflow in F = n_items * M */
    if (n_items > UINT64_MAX / BIP158_M) return 0;
    uint64_t F = n_items * BIP158_M;

    /* Hash all watched scripts */
    uint64_t *qhash = malloc(n_scripts * sizeof(uint64_t));
    if (!qhash) return 0;
    for (size_t i = 0; i < n_scripts; i++)
        qhash[i] = bip158_hash(key16, scripts[i].spk, scripts[i].spk_len, F);

    qsort(qhash, n_scripts, sizeof(uint64_t), cmp_uint64);

    /* Merge-scan the GCS */
    bit_reader_t r;
    bit_reader_init(&r, filter_data, filter_len);

    uint64_t value = 0;
    size_t   qi    = 0;
    int      found = 0;

    for (uint64_t i = 0; i < n_items && qi < n_scripts; i++) {
        int64_t delta = golomb_rice_decode(&r);
        if (delta < 0) break;
        value += (uint64_t)delta;

        /* Advance query pointer past hashes smaller than current value */
        while (qi < n_scripts && qhash[qi] < value)
            qi++;

        if (qi < n_scripts && qhash[qi] == value) {
            found = 1;
            break;
        }
    }

    free(qhash);
    return found;
}

/* -------------------------------------------------------------------------
 * Confirmed tx cache
 * ------------------------------------------------------------------------- */

void bip158_cache_tx(bip158_backend_t *backend,
                     const unsigned char *txid32, int32_t height)
{
    /* Check for duplicate */
    for (size_t i = 0; i < backend->n_tx_cache; i++) {
        if (memcmp(backend->tx_cache[i].txid, txid32, 32) == 0) {
            backend->tx_cache[i].height = height;
            return;
        }
    }
    /* Evict oldest entry if full (true circular FIFO cursor) */
    size_t slot;
    if (backend->n_tx_cache < BIP158_TX_CACHE_SIZE) {
        slot = backend->n_tx_cache++;
    } else {
        slot = backend->tx_cache_cursor % BIP158_TX_CACHE_SIZE;
        backend->tx_cache_cursor++;
    }
    memcpy(backend->tx_cache[slot].txid, txid32, 32);
    backend->tx_cache[slot].height = height;
}

/* -------------------------------------------------------------------------
 * chain_backend_t vtable implementation
 * ------------------------------------------------------------------------- */

static int cb_get_block_height(chain_backend_t *self)
{
    bip158_backend_t *b = (bip158_backend_t *)self;
    return (int)b->tip_height;  /* updated by scan loop; -1 until first sync */
}

static int cb_get_confirmations(chain_backend_t *self, const char *txid_hex)
{
    bip158_backend_t *b = (bip158_backend_t *)self;
    if (b->tip_height < 0) return -1;

    /* Convert display-order hex txid to internal byte order */
    unsigned char txid[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        /* Hex pairs are in display order (reversed from internal) */
        if (sscanf(txid_hex + (31 - i) * 2, "%02x", &byte) != 1)
            return -1;
        txid[i] = (unsigned char)byte;
    }

    for (size_t i = 0; i < b->n_tx_cache; i++) {
        if (memcmp(b->tx_cache[i].txid, txid, 32) == 0)
            return (int)(b->tip_height - b->tx_cache[i].height + 1);
    }
    return -1;  /* not found */
}

static bool cb_is_in_mempool(chain_backend_t *self, const char *txid_hex)
{
    /* TODO: query peer mempool via BIP 157 connection */
    (void)self; (void)txid_hex;
    return false;
}

/* hex_decode: convert an even-length hex string to bytes.
   Returns number of bytes written, or -1 on invalid input. */
static int hex_decode(const char *hex, unsigned char *out, size_t max_out)
{
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0 || hlen / 2 > max_out) return -1;
    for (size_t i = 0; i < hlen / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return (int)(hlen / 2);
}

static int cb_send_raw_tx(chain_backend_t *self, const char *tx_hex,
                           char *txid_out)
{
    bip158_backend_t *b = (bip158_backend_t *)self;

    if (b->p2p.fd < 0) return 0;   /* no P2P connection */

    /* Decode hex to raw bytes */
    size_t        hlen     = strlen(tx_hex);
    unsigned char *tx_bytes = malloc(hlen / 2 + 1);
    if (!tx_bytes) return 0;
    int tx_len = hex_decode(tx_hex, tx_bytes, hlen / 2 + 1);
    if (tx_len < 0) { free(tx_bytes); return 0; }

    uint8_t txid32[32];
    int ok = p2p_broadcast_tx(&b->p2p,
                               tx_bytes, (size_t)tx_len,
                               txid32);
    free(tx_bytes);
    if (!ok) return 0;

    if (txid_out) {
        /* Write txid as display-order hex (reversed internal bytes) */
        static const char hx[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            txid_out[(31 - i) * 2]     = hx[(txid32[i] >> 4) & 0xf];
            txid_out[(31 - i) * 2 + 1] = hx[txid32[i] & 0xf];
        }
        txid_out[64] = '\0';
    }
    return 1;
}

static int cb_register_script(chain_backend_t *self,
                               const unsigned char *spk, size_t spk_len)
{
    bip158_backend_t *b = (bip158_backend_t *)self;
    if (!spk || spk_len == 0 || spk_len > 34) return 0;
    if (b->n_scripts >= BIP158_MAX_SCRIPTS)    return 0;

    /* Deduplicate */
    for (size_t i = 0; i < b->n_scripts; i++) {
        if (b->scripts[i].spk_len == spk_len &&
            memcmp(b->scripts[i].spk, spk, spk_len) == 0)
            return 1;
    }

    memcpy(b->scripts[b->n_scripts].spk, spk, spk_len);
    b->scripts[b->n_scripts].spk_len = spk_len;
    b->n_scripts++;
    return 1;
}

static int cb_unregister_script(chain_backend_t *self,
                                 const unsigned char *spk, size_t spk_len)
{
    bip158_backend_t *b = (bip158_backend_t *)self;
    for (size_t i = 0; i < b->n_scripts; i++) {
        if (b->scripts[i].spk_len == spk_len &&
            memcmp(b->scripts[i].spk, spk, spk_len) == 0) {
            /* Swap with last */
            b->scripts[i] = b->scripts[--b->n_scripts];
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

int bip158_backend_init(bip158_backend_t *backend, const char *network)
{
    if (!backend) return 0;
    memset(backend, 0, sizeof(*backend));

    backend->base.get_block_height  = cb_get_block_height;
    backend->base.get_confirmations = cb_get_confirmations;
    backend->base.is_in_mempool     = cb_is_in_mempool;
    backend->base.send_raw_tx       = cb_send_raw_tx;
    backend->base.register_script   = cb_register_script;
    backend->base.unregister_script = cb_unregister_script;
    backend->base.ctx               = backend;

    backend->tip_height             = -1;  /* unknown until first sync */
    backend->headers_synced         = -1;  /* no block headers yet     */
    backend->filter_headers_synced  = -1;  /* no filter headers yet    */
    backend->p2p.fd                 = -1;  /* no P2P connection yet    */

    if (network)
        snprintf(backend->network, sizeof(backend->network), "%s", network);

    return 1;
}

void bip158_backend_free(bip158_backend_t *backend)
{
    if (!backend) return;
    p2p_close(&backend->p2p);
}

/*
 * Scan a raw BIP 158 filter (full serialised bytes including leading N varint)
 * against the backend's script registry. Returns 1 on any match, 0 if none.
 * Exposed internally for the scan loop (called per new block).
 */
int bip158_scan_filter(bip158_backend_t *backend,
                        const unsigned char *filter_bytes, size_t filter_len,
                        const unsigned char *key16)
{
    if (!backend->n_scripts || !filter_bytes || filter_len < 1) return 0;

    uint64_t n_items = 0;
    size_t   hdr     = read_varint(filter_bytes, filter_len, &n_items);
    if (!hdr || !n_items) return 0;

    return bip158_gcs_match_any(filter_bytes + hdr, filter_len - hdr,
                                 n_items, key16,
                                 backend->scripts, backend->n_scripts);
}

/* -------------------------------------------------------------------------
 * Phase 3: RPC-backed scan loop
 * Uses regtest bitcoin-cli calls to fetch filters and full blocks.
 * ------------------------------------------------------------------------- */

void bip158_backend_set_rpc(bip158_backend_t *backend, void *rt)
{
    if (backend) backend->rpc_ctx = rt;
}

void bip158_backend_set_db(bip158_backend_t *backend, void *db)
{
    if (backend) backend->db = db;
}

void bip158_backend_set_mempool_cb(bip158_backend_t *backend,
                                    void (*cb)(const char *txid_hex, void *ctx),
                                    void *ctx)
{
    if (!backend) return;
    backend->mempool_cb  = cb;
    backend->mempool_ctx = ctx;
}

int bip158_backend_poll_mempool(bip158_backend_t *backend)
{
    if (!backend || backend->p2p.fd < 0 || !backend->mempool_cb) return 0;

    /* Subscribe to mempool (BIP 35) on first call */
    if (!backend->mempool_subscribed) {
        if (p2p_send_mempool(&backend->p2p))
            backend->mempool_subscribed = 1;
    }

    /* Collect pending MSG_TX inv announcements (100 ms poll window) */
    uint8_t txids[256][32];
    int n = p2p_poll_inv(&backend->p2p, txids, 256, 100);

    /* Convert each txid to display-order hex and fire the callback */
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        char hex[65];
        for (int b = 0; b < 32; b++) {
            hex[(31 - b) * 2]     = hx[(txids[i][b] >> 4) & 0xf];
            hex[(31 - b) * 2 + 1] = hx[txids[i][b] & 0xf];
        }
        hex[64] = '\0';
        backend->mempool_cb(hex, backend->mempool_ctx);
    }
    return n;
}

int bip158_backend_restore_checkpoint(bip158_backend_t *backend)
{
    if (!backend || !backend->db) return 0;

    int32_t tip = -1, hdr = -1, fhdr = -1;
    int found = persist_load_bip158_checkpoint(
        (persist_t *)backend->db,
        &tip, &hdr, &fhdr,
        (uint8_t *)backend->header_hashes,
        sizeof(backend->header_hashes),
        (uint8_t *)backend->filter_headers,
        sizeof(backend->filter_headers));

    if (found) {
        backend->tip_height            = tip;
        backend->headers_synced        = hdr;
        backend->filter_headers_synced = fhdr;
    }
    return found;
}

/* Callback context for scan_tx_callback */
typedef struct {
    bip158_backend_t *backend;
    int32_t           height;
    int               found;   /* set to 1 if at least one script matched */
} scan_cb_ctx_t;

/* Per-tx callback: if any output script is watched, cache the txid. */
static void scan_tx_callback(const char *txid_hex,
                              size_t n_outputs,
                              const unsigned char **spks,
                              const size_t *spk_lens,
                              void *ctx)
{
    scan_cb_ctx_t    *sc = (scan_cb_ctx_t *)ctx;
    bip158_backend_t *b  = sc->backend;

    for (size_t i = 0; i < n_outputs; i++) {
        for (size_t j = 0; j < b->n_scripts; j++) {
            if (b->scripts[j].spk_len == spk_lens[i] &&
                memcmp(b->scripts[j].spk, spks[i], spk_lens[i]) == 0) {
                /* Convert display-order hex txid to internal byte order:
                   decode 64-char hex then reverse the 32 bytes. */
                unsigned char txid[32];
                if (hex_decode(txid_hex, txid, 32) == 32) {
                    for (int lo = 0, hi = 31; lo < hi; lo++, hi--) {
                        unsigned char t = txid[lo];
                        txid[lo] = txid[hi];
                        txid[hi] = t;
                    }
                    bip158_cache_tx(b, txid, sc->height);
                }
                sc->found = 1;
                return;  /* one cache entry per tx is sufficient */
            }
        }
    }
}

/* Convert 32 internal-byte-order bytes to a 64-char display-order hex string. */
static void bytes_to_hash_hex(const uint8_t in32[32], char out65[65])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out65[(31 - i) * 2]     = hx[(in32[i] >> 4) & 0xf];
        out65[(31 - i) * 2 + 1] = hx[in32[i] & 0xf];
    }
    out65[64] = '\0';
}

/*
 * Sync block header hashes into the ring buffer via P2P getheaders/headers.
 * Issues up to-2000-header round trips until the peer stops sending more.
 * Returns the highest synced height on success, or -1 on P2P error.
 */
static int bip158_sync_headers(bip158_backend_t *b)
{
    uint8_t (*new_hashes)[32] = malloc(2000 * sizeof(*new_hashes));
    if (!new_hashes) return -1;

    int result = (b->headers_synced >= 0) ? b->headers_synced : -1;

    for (;;) {
        int start_height = (b->headers_synced >= 0) ? b->headers_synced + 1 : 0;

        /* Single-entry locator from our current best known block, or empty */
        uint8_t        locator_buf[1][32];
        const uint8_t (*locator)[32] = NULL;
        size_t         n_locator     = 0;
        if (b->headers_synced >= 0) {
            memcpy(locator_buf[0],
                   b->header_hashes[b->headers_synced % BIP158_HEADER_WINDOW], 32);
            locator   = locator_buf;
            n_locator = 1;
        }

        if (!p2p_send_getheaders(&b->p2p, locator, n_locator, NULL)) {
            result = -1;
            break;
        }

        int n = p2p_recv_headers(&b->p2p, new_hashes, 2000);
        if (n < 0) { result = -1; break; }
        if (n == 0) break;  /* peer has nothing more to send */

        for (int i = 0; i < n; i++) {
            int height = start_height + i;
            memcpy(b->header_hashes[height % BIP158_HEADER_WINDOW],
                   new_hashes[i], 32);
            b->headers_synced = height;
        }
        result = b->headers_synced;

        if (n < 2000) break;  /* fewer than max → reached peer's tip */
    }

    free(new_hashes);
    return result;
}

/*
 * Sync BIP 157 filter headers into the ring buffer via P2P getcfheaders/cfheaders.
 *
 * Per BIP 157 the filter header chain is:
 *   filter_header[N] = SHA256d( SHA256d(filter_bytes[N]) || filter_header[N-1] )
 * where filter_header[-1] = 0x00 * 32 (genesis prev is all zeros).
 *
 * The peer provides prev_filter_header in its cfheaders response; we verify
 * continuity against what we already know before storing.
 *
 * Returns the highest synced height, or -1 on P2P error.
 */
static int bip158_sync_filter_headers(bip158_backend_t *b, int tip_height)
{
    if (tip_height < 0) return -1;

    int result = b->filter_headers_synced;

    for (;;) {
        int start = (b->filter_headers_synced >= 0)
                  ? b->filter_headers_synced + 1
                  : 0;
        if (start > tip_height) break;

        int end = (start + 1999 < tip_height) ? start + 1999 : tip_height;
        const uint8_t *stop_hash =
            b->header_hashes[end % BIP158_HEADER_WINDOW];

        if (!p2p_send_getcfheaders(&b->p2p, (uint32_t)start, stop_hash)) {
            result = -1;
            break;
        }

        uint8_t  stop_out[32], prev_fh[32];
        uint8_t *hdrs   = NULL;
        size_t   count  = 0;
        int r = p2p_recv_cfheaders(&b->p2p, stop_out, prev_fh, &hdrs, &count);
        if (r != 1) {
            free(hdrs);
            if (r == -1) result = -1;
            break;
        }

        /* Verify chain continuity at the join point */
        if (start == 0) {
            /* Genesis prev must be all zeros per BIP 157 */
            uint8_t zeros[32] = {0};
            if (memcmp(prev_fh, zeros, 32) != 0) {
                free(hdrs); result = -1; break;
            }
        } else {
            /* prev_fh must match what we stored for (start - 1) */
            if (memcmp(prev_fh,
                       b->filter_headers[(start - 1) % BIP158_HEADER_WINDOW],
                       32) != 0) {
                free(hdrs); result = -1; break;
            }
        }

        for (size_t i = 0; i < count; i++) {
            int height = start + (int)i;
            memcpy(b->filter_headers[height % BIP158_HEADER_WINDOW],
                   hdrs + i * 32, 32);
            b->filter_headers_synced = height;
        }
        free(hdrs);
        result = b->filter_headers_synced;
        if ((int)count < 2000) break;
    }

    return result;
}

/*
 * Compute the BIP 157 filter header for one block, given:
 *   filter_bytes / filter_len : raw filter (including N varint) as from cfilter
 *   prev_filter_hdr           : filter header at height-1 (zeros at height 0)
 *
 * filter_header[N] = SHA256d( SHA256d(filter) || prev_filter_header[N-1] )
 */
static void compute_filter_header(const uint8_t *filter_bytes, size_t filter_len,
                                   const uint8_t prev_filter_hdr[32],
                                   uint8_t out[32])
{
    uint8_t filter_hash[32];
    sha256_double(filter_bytes, filter_len, filter_hash);

    uint8_t combined[64];
    memcpy(combined,      filter_hash,      32);
    memcpy(combined + 32, prev_filter_hdr,  32);
    sha256_double(combined, 64, out);
}

/*
 * BIP 158 scan loop — Phase 3 (RPC) + Phase 4/5 (P2P filter + header sync).
 *
 * P2P path (preferred when backend->p2p.fd >= 0):
 *   1. bip158_sync_headers() fetches block hashes into the ring buffer and
 *      provides the chain tip height — no RPC needed for header data.
 *   2. getcfilters requests are batched in chunks of 1000 blocks.
 *   3. Filter hits use regtest_scan_block_txs() when rpc_ctx is available;
 *      otherwise the hit is counted tentatively (Phase 5 replaces this).
 *
 * RPC path (fallback, or when P2P is not connected):
 *   Uses regtest_get_block_height, regtest_get_block_hash,
 *   regtest_get_block_filter, and regtest_scan_block_txs.
 *
 * Returns number of matched blocks, or -1 on hard error.
 */
int bip158_backend_scan(bip158_backend_t *backend)
{
    if (!backend) return -1;

    regtest_t *rt = (regtest_t *)backend->rpc_ctx;

    if (backend->p2p.fd < 0 && !rt) return -1;
    if (!backend->n_scripts) return 0;

    /* Determine chain tip — P2P path syncs headers + filter headers.
       Phase 6: attempt peer rotation on disconnect before falling back. */
    int tip = -1;
    if (backend->p2p.fd >= 0) {
        tip = bip158_sync_headers(backend);
        if (tip >= 0) {
            bip158_sync_filter_headers(backend, tip);
        } else {
            p2p_close(&backend->p2p);
            if (backend->n_peers > 1)
                bip158_backend_reconnect(backend);
        }
    } else if (backend->n_peers > 0) {
        /* Lost connection between scan calls; try to restore it */
        bip158_backend_reconnect(backend);
    }
    /* Re-check after possible reconnect */
    if (tip < 0 && backend->p2p.fd >= 0) {
        tip = bip158_sync_headers(backend);
        if (tip >= 0)
            bip158_sync_filter_headers(backend, tip);
        else
            p2p_close(&backend->p2p);
    }
    if (tip < 0) {
        if (!rt) return -1;
        tip = regtest_get_block_height(rt);
        if (tip < 0) return -1;
    }

    int start = (backend->tip_height >= 0) ? backend->tip_height + 1 : tip;
    if (start > tip) return 0;

#define FILTER_BUF_MAX (4 * 1024 * 1024)
    unsigned char *filter_buf = malloc(FILTER_BUF_MAX);
    if (!filter_buf) return -1;

    int matched = 0;

    if (backend->p2p.fd >= 0) {
        /* === P2P path: batched getcfilters, ring-buffer block hashes === */
        for (int h = start; h <= tip && backend->p2p.fd >= 0; ) {
            int batch_end = (h + 999 < tip) ? h + 999 : tip;
            const uint8_t *stop = backend->header_hashes[batch_end % BIP158_HEADER_WINDOW];

            if (!p2p_send_getcfilters(&backend->p2p, (uint32_t)h, stop)) {
                p2p_close(&backend->p2p);
                break;
            }

            int batch_ok = 1;
            for (int bh = h; bh <= batch_end; bh++) {
                uint8_t *pf = NULL;
                size_t   pf_len;
                uint8_t  recv_hash[32], recv_key[16];

                int r = p2p_recv_cfilter(&backend->p2p, recv_hash,
                                          &pf, &pf_len, recv_key);
                if (r != 1) {
                    free(pf);
                    if (r == -1) p2p_close(&backend->p2p);
                    batch_ok = 0;
                    break;
                }

                size_t use_len = (pf_len <= FILTER_BUF_MAX) ? pf_len : 0;
                if (use_len) memcpy(filter_buf, pf, use_len);
                free(pf);

                /* BIP 157 filter header validation — verify filter is authentic.
                   Skip if filter headers haven't been synced for this height. */
                if (backend->filter_headers_synced >= bh && use_len > 0) {
                    static const uint8_t genesis_prev[32] = {0};
                    const uint8_t *prev_fh =
                        (bh > 0)
                        ? backend->filter_headers[(bh - 1) % BIP158_HEADER_WINDOW]
                        : genesis_prev;
                    uint8_t computed_fh[32];
                    compute_filter_header(filter_buf, use_len, prev_fh,
                                          computed_fh);
                    if (memcmp(computed_fh,
                               backend->filter_headers[bh % BIP158_HEADER_WINDOW],
                               32) != 0) {
                        /* Peer sent a filter that doesn't match the committed
                           header — likely a misbehaving or stale peer. */
                        p2p_close(&backend->p2p);
                        batch_ok = 0;
                        break;
                    }
                }

                if (!bip158_scan_filter(backend, filter_buf, use_len, recv_key)) {
                    backend->tip_height = bh;
                    continue;
                }

                /* Filter hit: download full block via P2P and scan txs.
                   Falls back to RPC if P2P block download fails. */
                scan_cb_ctx_t sc = { backend, (int32_t)bh, 0 };
                int block_scanned = 0;
                if (p2p_send_getdata_block(&backend->p2p, recv_hash)) {
                    uint8_t *blk  = NULL;
                    size_t   blen = 0;
                    int br = p2p_recv_block(&backend->p2p, &blk, &blen);
                    if (br == 1) {
                        p2p_scan_block_txs(blk, blen,
                                           (p2p_block_scan_cb_t)scan_tx_callback,
                                           &sc);
                        block_scanned = 1;
                    } else if (br < 0) {
                        p2p_close(&backend->p2p);
                    }
                    free(blk);
                } else {
                    p2p_close(&backend->p2p);
                }
                /* RPC fallback if P2P block download didn't complete */
                if (!block_scanned && rt) {
                    char hash_hex[65];
                    bytes_to_hash_hex(recv_hash, hash_hex);
                    regtest_scan_block_txs(rt, hash_hex, scan_tx_callback, &sc);
                    block_scanned = 1;
                }
                if (sc.found) matched++;
                else if (!block_scanned) matched++;  /* false positive — tentative */
                backend->tip_height = bh;
            }

            if (!batch_ok) break;
            h = batch_end + 1;
        }
    } else {
        /* === RPC path === */
        for (int h = start; h <= tip; h++) {
            char          hash_hex[65];
            size_t        filter_len = 0;
            unsigned char key[16];

            if (!regtest_get_block_hash(rt, h, hash_hex, sizeof(hash_hex))) {
                backend->tip_height = h;
                continue;
            }
            if (!regtest_get_block_filter(rt, hash_hex,
                                           filter_buf, &filter_len,
                                           FILTER_BUF_MAX, key)) {
                backend->tip_height = h;
                continue;
            }
            if (!bip158_scan_filter(backend, filter_buf, filter_len, key)) {
                backend->tip_height = h;
                continue;
            }

            scan_cb_ctx_t sc = { backend, (int32_t)h, 0 };
            regtest_scan_block_txs(rt, hash_hex, scan_tx_callback, &sc);
            if (sc.found) matched++;
            backend->tip_height = h;
        }
    }

    free(filter_buf);
#undef FILTER_BUF_MAX

    /* Phase 4: persist scan checkpoint so the next startup resumes here */
    if (backend->db) {
        persist_save_bip158_checkpoint(
            (persist_t *)backend->db,
            backend->tip_height,
            backend->headers_synced,
            backend->filter_headers_synced,
            (const uint8_t *)backend->header_hashes,
            sizeof(backend->header_hashes),
            (const uint8_t *)backend->filter_headers,
            sizeof(backend->filter_headers));
    }

    return matched;
}

/* -------------------------------------------------------------------------
 * Phase 4: P2P connection management
 * ------------------------------------------------------------------------- */

int bip158_backend_connect_p2p(bip158_backend_t *backend,
                                const char *host, int port)
{
    if (!backend) return 0;
    /* Close any existing connection first */
    p2p_close(&backend->p2p);
    int ok = p2p_connect(&backend->p2p, host, port, backend->network);
    if (ok) {
        /* Record as primary peer (slot 0) if not already present */
        if (backend->n_peers == 0) {
            snprintf(backend->peer_hosts[0], sizeof(backend->peer_hosts[0]),
                     "%s", host);
            backend->peer_ports[0] = port;
            backend->n_peers = 1;
            backend->current_peer = 0;
        }
    }
    return ok;
}

void bip158_backend_add_peer(bip158_backend_t *backend,
                              const char *host, int port)
{
    if (!backend || !host || port <= 0) return;
    if (backend->n_peers >= BIP158_MAX_PEERS) return;
    snprintf(backend->peer_hosts[backend->n_peers],
             sizeof(backend->peer_hosts[0]), "%s", host);
    backend->peer_ports[backend->n_peers] = port;
    backend->n_peers++;
}

int bip158_backend_reconnect(bip158_backend_t *backend)
{
    if (!backend || backend->n_peers == 0) return 0;

    p2p_close(&backend->p2p);

    /* Try each peer once, starting after the last successful one */
    for (int i = 1; i <= backend->n_peers; i++) {
        int idx = (backend->current_peer + i) % backend->n_peers;
        const char *h = backend->peer_hosts[idx];
        int         p = backend->peer_ports[idx];
        if (!h[0] || p <= 0) continue;

        fprintf(stderr, "BIP158: reconnecting to %s:%d (peer %d/%d)...\n",
                h, p, idx + 1, backend->n_peers);
        if (p2p_connect(&backend->p2p, h, p, backend->network)) {
            backend->current_peer = idx;
            fprintf(stderr, "BIP158: reconnected to %s:%d\n", h, p);
            return 1;
        }
    }
    return 0;
}
