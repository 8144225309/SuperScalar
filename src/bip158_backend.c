#include "superscalar/bip158_backend.h"
#include "superscalar/p2p_bitcoin.h"
#include "superscalar/regtest.h"
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
    /* Unary quotient: count leading zeros then one 1-bit */
    uint64_t q = 0;
    int b;
    while ((b = read_bit(r)) == 0)
        q++;
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
    /* Evict oldest entry if full (circular overwrite) */
    size_t slot = backend->n_tx_cache < BIP158_TX_CACHE_SIZE
                  ? backend->n_tx_cache++
                  : (size_t)(height % BIP158_TX_CACHE_SIZE);
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

    backend->tip_height = -1;   /* unknown until first sync */
    backend->p2p.fd     = -1;   /* no P2P connection yet     */

    if (network)
        strncpy(backend->network, network, sizeof(backend->network) - 1);

    return 1;
}

void bip158_backend_free(bip158_backend_t *backend)
{
    if (!backend) return;

    /* Free cached filter data */
    for (size_t i = 0; i < BIP158_FILTER_CACHE; i++) {
        free(backend->filters[i].data);
        backend->filters[i].data = NULL;
    }

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
                /* Convert display-order hex txid to internal byte order */
                unsigned char txid[32];
                for (int k = 0; k < 32; k++) {
                    unsigned int byte;
                    sscanf(txid_hex + (31 - k) * 2, "%02x", &byte);
                    txid[k] = (unsigned char)byte;
                }
                bip158_cache_tx(b, txid, sc->height);
                sc->found = 1;
                return;  /* one cache entry per tx is sufficient */
            }
        }
    }
}

/* Convert a 64-char display-order hex block hash to 32 internal bytes. */
static int hash_hex_to_bytes(const char *hex64, uint8_t out32[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex64 + (31 - i) * 2, "%02x", &byte) != 1) return 0;
        out32[i] = (uint8_t)byte;
    }
    return 1;
}

/*
 * BIP 158 scan loop — Phase 3 (RPC) + Phase 4 (P2P filter fetch).
 *
 * Priority:
 *   - If backend->p2p.fd >= 0: fetch compact filters via P2P getcfilters/cfilter
 *   - Else if backend->rpc_ctx: fetch compact filters via getblockfilter RPC
 *   - Else: return -1
 *
 * Full-block scan on filter hit still uses RPC (regtest_scan_block_txs) when
 * rpc_ctx is available.  P2P block parsing is Phase 5.
 *
 * Returns number of matched blocks, or -1 on hard error.
 */
int bip158_backend_scan(bip158_backend_t *backend)
{
    if (!backend) return -1;

    regtest_t *rt = (regtest_t *)backend->rpc_ctx;

    /* Need at least one fetch path */
    if (backend->p2p.fd < 0 && !rt) return -1;
    /* Need RPC for block height + hash lookup (both paths use this for now) */
    if (!rt) return -1;

    if (!backend->n_scripts) return 0;

    int tip = regtest_get_block_height(rt);
    if (tip < 0) return -1;

    int start = (backend->tip_height >= 0) ? backend->tip_height + 1 : tip;

#define FILTER_BUF_MAX (4 * 1024 * 1024)
    unsigned char *filter_buf = malloc(FILTER_BUF_MAX);
    if (!filter_buf) return -1;

    int matched = 0;

    for (int h = start; h <= tip; h++) {
        char    hash_hex[65];
        uint8_t hash_bytes[32];

        if (!regtest_get_block_hash(rt, h, hash_hex, sizeof(hash_hex)))
            continue;

        size_t        filter_len = 0;
        unsigned char key[16];

        if (backend->p2p.fd >= 0) {
            /* Phase 4: fetch filter via P2P */
            if (!hash_hex_to_bytes(hash_hex, hash_bytes)) {
                backend->tip_height = h;
                continue;
            }
            if (!p2p_send_getcfilters(&backend->p2p, (uint32_t)h, hash_bytes)) {
                /* P2P send failed — connection likely dead */
                p2p_close(&backend->p2p);
                /* Fall through to RPC below on next iteration */
                backend->tip_height = h;
                continue;
            }
            uint8_t *p2p_filter = NULL;
            uint8_t  p2p_hash[32], p2p_key[16];
            int r = p2p_recv_cfilter(&backend->p2p, p2p_hash,
                                      &p2p_filter, &filter_len, p2p_key);
            if (r != 1) {
                free(p2p_filter);
                if (r == -1) p2p_close(&backend->p2p);
                backend->tip_height = h;
                continue;
            }
            if (filter_len <= FILTER_BUF_MAX) {
                memcpy(filter_buf, p2p_filter, filter_len);
                memcpy(key, p2p_key, 16);
            } else {
                filter_len = 0;  /* oversized — treat as no match */
            }
            free(p2p_filter);
        } else {
            /* Phase 3: fetch filter via RPC */
            if (!regtest_get_block_filter(rt, hash_hex,
                                           filter_buf, &filter_len,
                                           FILTER_BUF_MAX, key)) {
                backend->tip_height = h;
                continue;
            }
        }

        if (!bip158_scan_filter(backend, filter_buf, filter_len, key)) {
            backend->tip_height = h;
            continue;
        }

        /* Filter hit — fetch full block via RPC and cache matching txids.
           Phase 5 will replace this with P2P getdata/block parsing. */
        if (rt) {
            scan_cb_ctx_t sc = { backend, (int32_t)h, 0 };
            regtest_scan_block_txs(rt, hash_hex, scan_tx_callback, &sc);
            if (sc.found) matched++;
        } else {
            matched++;  /* filter hit but can't confirm; count tentatively */
        }
        backend->tip_height = h;
    }

    free(filter_buf);
#undef FILTER_BUF_MAX
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
    return p2p_connect(&backend->p2p, host, port, backend->network);
}
