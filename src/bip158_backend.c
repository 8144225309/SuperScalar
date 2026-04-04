#include "superscalar/bip158_backend.h"
#include "superscalar/p2p_bitcoin.h"
#include "superscalar/persist.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

/* Forward declaration — defined later in the SipHash section */
static uint64_t load_le64(const unsigned char *p);

/* -------------------------------------------------------------------------
 * Block fee sample extraction
 * Parse the coinbase transaction to estimate average block fee rate.
 * Returns sat/kvB, or 0 if parsing fails.
 * ------------------------------------------------------------------------- */
static uint64_t bip158_extract_block_fee_sample(const uint8_t *block,
                                                  size_t block_len,
                                                  uint32_t height)
{
    if (!block || block_len < 90) return 0;

    /* Skip 80-byte block header */
    const uint8_t *p = block + 80;
    size_t rem = block_len - 80;

    /* tx_count varint */
    if (rem < 1) return 0;
    uint64_t tx_count = 0;
    size_t vi = 1;
    if (p[0] < 0xfd)      { tx_count = p[0]; vi = 1; }
    else if (p[0] == 0xfd && rem >= 3) { tx_count = (uint64_t)p[1] | ((uint64_t)p[2] << 8); vi = 3; }
    else return 0;
    (void)tx_count;
    p += vi; rem -= vi;

    /* Coinbase tx starts here (segwit or legacy).
       nVersion(4) + optional segwit marker(2) + vin_count(varint) */
    if (rem < 5) return 0;
    p += 4; rem -= 4;  /* skip nVersion */

    /* Segwit marker + flag */
    int is_segwit = 0;
    if (rem >= 2 && p[0] == 0x00 && p[1] != 0x00) {
        is_segwit = 1;
        p += 2; rem -= 2;
    }

    /* vin_count varint — should be 1 for coinbase */
    if (rem < 1) return 0;
    /* Skip varint (assume 1 input for coinbase) */
    size_t vin_vi = (p[0] < 0xfd) ? 1 : (p[0] == 0xfd ? 3 : 9);
    if (rem < vin_vi) return 0;
    p += vin_vi; rem -= vin_vi;

    /* Skip coinbase input: prevhash(32) + vout(4) + script_len varint + script + sequence(4) */
    if (rem < 37) return 0;
    p += 36; rem -= 36;  /* prevhash + vout */
    uint64_t script_len = 0;
    size_t sl_vi = 1;
    if (p[0] < 0xfd)      { script_len = p[0]; sl_vi = 1; }
    else if (p[0] == 0xfd && rem >= 3) { script_len = (uint64_t)p[1] | ((uint64_t)p[2] << 8); sl_vi = 3; }
    else return 0;
    if (rem < sl_vi + script_len + 4) return 0;
    p += sl_vi + script_len + 4; rem -= sl_vi + script_len + 4;

    /* vout_count varint */
    if (rem < 1) return 0;
    uint64_t vout_count = 0;
    size_t vc_vi = 1;
    if (p[0] < 0xfd)      { vout_count = p[0]; vc_vi = 1; }
    else if (p[0] == 0xfd && rem >= 3) { vout_count = (uint64_t)p[1] | ((uint64_t)p[2] << 8); vc_vi = 3; }
    else return 0;
    p += vc_vi; rem -= vc_vi;

    /* Sum all coinbase output amounts */
    uint64_t total_out = 0;
    for (uint64_t v = 0; v < vout_count; v++) {
        if (rem < 9) return 0;
        uint64_t amt = load_le64(p);
        total_out += amt;
        p += 8; rem -= 8;
        uint64_t spk_len = 0;
        size_t spk_vi = 1;
        if (p[0] < 0xfd)      { spk_len = p[0]; spk_vi = 1; }
        else if (p[0] == 0xfd && rem >= 3) { spk_len = (uint64_t)p[1] | ((uint64_t)p[2] << 8); spk_vi = 3; }
        else return 0;
        if (rem < spk_vi + spk_len) return 0;
        p += spk_vi + spk_len; rem -= spk_vi + spk_len;
    }

    /* Segwit witness for coinbase — skip it */
    (void)is_segwit;

    /* Block subsidy = 50 BTC >> (height / 210000) */
    uint64_t subsidy = 5000000000ULL >> (height / 210000);

    /* Fees = coinbase output - subsidy.  If output <= subsidy, skip (likely no fee txs). */
    if (total_out <= subsidy) return 0;
    uint64_t total_fees = total_out - subsidy;

    /* Conservative weight = block_len * 4 (no witness data distinction) */
    uint64_t block_weight = (uint64_t)block_len * 4;
    if (block_weight == 0) return 0;

    /* avg_sat_per_kvb = total_fees * 4000 / block_weight */
    if (total_fees > UINT64_MAX / 4000) return 0;  /* overflow guard */
    uint64_t avg = total_fees * 4000 / block_weight;
    if (avg < 1000) avg = 1000;  /* floor at 1 sat/vB */
    return avg;
}

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
 * Bit writer (MSB-first) for Golomb-Rice encoding
 * ------------------------------------------------------------------------- */

typedef struct {
    unsigned char *data;
    size_t         cap;   /* capacity in bytes */
    size_t         pos;   /* current bit position */
} bit_writer_t;

static void bit_writer_init(bit_writer_t *w, unsigned char *data, size_t cap)
{
    w->data = data;
    w->cap  = cap;
    w->pos  = 0;
    memset(data, 0, cap);
}

/* Write one bit (MSB-first). Returns 0 on success, -1 on overflow. */
static int write_bit(bit_writer_t *w, int bit)
{
    size_t byte_pos = w->pos / 8;
    if (byte_pos >= w->cap) return -1;
    if (bit) w->data[byte_pos] |= (uint8_t)(1 << (7 - (w->pos % 8)));
    w->pos++;
    return 0;
}

/* Write p bits of val (MSB-first). Returns 0 on success, -1 on overflow. */
static int write_bits(bit_writer_t *w, uint64_t val, int p)
{
    for (int i = p - 1; i >= 0; i--) {
        if (write_bit(w, (int)((val >> i) & 1)) < 0) return -1;
    }
    return 0;
}

/* Golomb-Rice encode one delta value. Returns 0 on success, -1 on overflow. */
static int golomb_rice_encode(bit_writer_t *w, uint64_t delta)
{
    uint64_t q = delta >> BIP158_P;
    uint64_t r = delta & ((1ULL << BIP158_P) - 1);
    /* Unary quotient: q one-bits followed by a zero-bit */
    for (uint64_t i = 0; i < q; i++) {
        if (write_bit(w, 1) < 0) return -1;
    }
    if (write_bit(w, 0) < 0) return -1;
    /* P-bit remainder */
    return write_bits(w, r, BIP158_P);
}

/* Write a Bitcoin varint into buf (capacity cap). Returns bytes written or 0. */
static size_t write_varint(unsigned char *buf, size_t cap, uint64_t val)
{
    if (val < 0xfd) {
        if (cap < 1) return 0;
        buf[0] = (uint8_t)val;
        return 1;
    } else if (val <= 0xffff) {
        if (cap < 3) return 0;
        buf[0] = 0xfd; buf[1] = (uint8_t)val; buf[2] = (uint8_t)(val >> 8);
        return 3;
    } else if (val <= 0xffffffff) {
        if (cap < 5) return 0;
        buf[0] = 0xfe;
        for (int i = 0; i < 4; i++) buf[1+i] = (uint8_t)(val >> (i*8));
        return 5;
    } else {
        if (cap < 9) return 0;
        buf[0] = 0xff;
        for (int i = 0; i < 8; i++) buf[1+i] = (uint8_t)(val >> (i*8));
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
 * GCS encoder (Phase 6) — builds a BIP 158 compact filter from scripts.
 *
 * Takes an array of bip158_script_t elements, sorts and Golomb-Rice encodes
 * the SipHash values into out_buf.  Output format:
 *   varint(N) || packed Golomb-Rice bitstream
 * which is exactly the payload expected by bip158_gcs_match_any after the
 * leading varint(N) has been stripped.
 *
 * key16:    first 16 bytes of the block hash (SipHash key, internal byte order)
 * out_cap:  must be at least bip158_gcs_build_size(n) bytes
 *
 * Returns bytes written, or 0 on error (buffer too small, allocation failure).
 * ------------------------------------------------------------------------- */

size_t bip158_gcs_build_size(size_t n)
{
    /* Conservative upper bound: varint(N) + n * (max_quotient_bits + P + 1).
     * For N < 0xfd the varint is 1 byte.  Each element's GCS word is at most
     * (F/n) >> P ≈ M bits of unary quotient plus P+1 bits, where M=784931≈20
     * bits.  Round up generously: varint(N) + n*(P+22) bits → bytes. */
    size_t vi  = (n < 0xfd) ? 1 : (n <= 0xffff) ? 3 : 5;
    size_t bits = (n == 0) ? 0 : n * (size_t)(BIP158_P + 22);
    return vi + (bits + 7) / 8 + 8;  /* +8 for alignment slack */
}

size_t bip158_gcs_build(const bip158_script_t *scripts, size_t n,
                         const unsigned char *key16,
                         unsigned char *out_buf, size_t out_cap)
{
    if (!out_buf || out_cap == 0) return 0;

    /* Guard against overflow: F = n * M */
    if (n > UINT64_MAX / BIP158_M) return 0;
    uint64_t F = (n > 0) ? (uint64_t)n * BIP158_M : 0;

    /* Hash all scripts into [0, F) */
    uint64_t *vals = NULL;
    if (n > 0) {
        vals = malloc(n * sizeof(uint64_t));
        if (!vals) return 0;
        for (size_t i = 0; i < n; i++)
            vals[i] = bip158_hash(key16, scripts[i].spk, scripts[i].spk_len, F);
        qsort(vals, n, sizeof(uint64_t), cmp_uint64);
    }

    /* Write varint(N) */
    size_t vi_len = write_varint(out_buf, out_cap, (uint64_t)n);
    if (vi_len == 0) { free(vals); return 0; }

    /* Golomb-Rice encode sorted deltas */
    bit_writer_t w;
    bit_writer_init(&w, out_buf + vi_len, out_cap - vi_len);

    uint64_t prev = 0;
    for (size_t i = 0; i < n; i++) {
        if (golomb_rice_encode(&w, vals[i] - prev) < 0) {
            free(vals);
            return 0;
        }
        prev = vals[i];
    }

    free(vals);

    size_t bytes_written = (w.pos + 7) / 8;
    return vi_len + bytes_written;
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
    bip158_backend_t *b = (bip158_backend_t *)self;
    if (!txid_hex || strlen(txid_hex) != 64) return false;

    /* Parse display-order hex → internal bytes (reversed) */
    unsigned char txid[32];
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(txid_hex + (31 - i) * 2, "%02x", &byte) != 1) return false;
        txid[i] = (unsigned char)byte;
    }

    int count = b->mempool_cache_count < BIP158_MEMPOOL_CACHE_SIZE
                ? b->mempool_cache_count : BIP158_MEMPOOL_CACHE_SIZE;
    for (int i = 0; i < count; i++) {
        if (memcmp(b->mempool_cache[i], txid, 32) == 0) return true;
    }
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

    if (b->peers[b->current_peer].fd < 0) return 0;   /* no P2P connection */

    /* Decode hex to raw bytes */
    size_t        hlen     = strlen(tx_hex);
    unsigned char *tx_bytes = malloc(hlen / 2 + 1);
    if (!tx_bytes) return 0;
    int tx_len = hex_decode(tx_hex, tx_bytes, hlen / 2 + 1);
    if (tx_len < 0) { free(tx_bytes); return 0; }

    uint8_t txid32[32];
    int ok = p2p_broadcast_tx(&b->peers[b->current_peer],
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
 * BIP 158 filter header checkpoints
 *
 * Hard-coded known-good filter header values at fixed block heights.
 * Source: lightninglabs/neutrino chainsync/filtercontrol.go
 * Byte order: little-endian (wire / internal Bitcoin hash order).
 *
 * These let us detect a malicious peer that tries to serve a fabricated
 * filter header chain from genesis.  Any mismatch causes peer disconnect.
 * ------------------------------------------------------------------------- */

typedef struct {
    int32_t height;
    uint8_t filter_header[32];
} bip158_cp_t;

static const bip158_cp_t mainnet_checkpoints[] = {
    { 100000, {0xa5,0x7f,0xaa,0x53,0x41,0xbe,0x06,0x6a,0xa2,0x04,0xe4,0x1f,0x47,0x31,0x3a,0xb7,
               0xab,0x63,0x97,0xf5,0x8b,0xfe,0xb5,0xb7,0x01,0xeb,0x69,0xb3,0x1a,0xbc,0x8c,0xf2} },
    { 200000, {0xb3,0x32,0x0f,0x4c,0x8e,0x6b,0x04,0x95,0x6b,0xe0,0xe8,0x6a,0xc5,0xd5,0x00,0x33,
               0x41,0xc1,0xac,0x03,0x6a,0x5f,0xa2,0xe7,0xbf,0x4f,0x2f,0x73,0x71,0x14,0x03,0xe5} },
    { 300000, {0x5b,0xaa,0xf8,0xbf,0x19,0xe7,0x51,0xbb,0x8d,0xa9,0x2b,0x45,0x8c,0xb3,0xed,0xbf,
               0xa9,0xd9,0x2d,0x1d,0xc9,0x43,0x31,0xca,0x29,0xe9,0xdd,0xfc,0x20,0x02,0xd5,0x1b} },
    { 400000, {0x3a,0x2e,0x19,0xef,0x78,0x5f,0xc6,0x62,0xb2,0xb3,0xed,0x56,0x16,0x0f,0x26,0x7a,
               0x31,0x2e,0xfb,0xa8,0xc1,0xc1,0xee,0x0d,0xc7,0x69,0xc5,0xf1,0xb1,0x3a,0x97,0x5d} },
    { 500000, {0x3c,0x1a,0x63,0xaa,0xca,0x07,0xa8,0x00,0x42,0xa4,0x59,0x5a,0x09,0x8b,0xe3,0x1b,
               0x66,0xfb,0x99,0x3f,0xb6,0x79,0xc2,0x9b,0x0a,0xdc,0x9b,0x3c,0x29,0xca,0x16,0x5d} },
    { 600000, {0xf8,0x98,0x75,0x37,0x4e,0x20,0x0e,0xf7,0x5e,0x51,0xab,0xb2,0xb4,0xf5,0x17,0x68,
               0x0c,0x0e,0x14,0x47,0x25,0x46,0x60,0xa8,0x86,0x43,0x2f,0x0b,0x4d,0x85,0xe0,0xbd} },
    { 660000, {0x32,0x30,0xd3,0x4a,0xfa,0x78,0x74,0x4f,0xf9,0x83,0x74,0xbb,0x34,0x9a,0xc1,0x50,
               0xb3,0xfe,0x43,0x84,0xe8,0x8e,0xfa,0x17,0x2b,0x08,0xbc,0xfa,0x75,0x23,0x31,0x08} },
};

static const bip158_cp_t testnet3_checkpoints[] = {
    { 100000,  {0x1c,0x5a,0xb6,0x58,0x2c,0xd0,0x06,0x2b,0x27,0xfd,0xf3,0xb5,0x76,0xe7,0x37,0x59,
                0x52,0xcc,0xd8,0x0a,0x25,0x33,0xd1,0xfc,0x27,0x56,0x62,0x14,0x3f,0x63,0xc0,0x97} },
    { 200000,  {0x87,0xcc,0x38,0xcc,0x8e,0x10,0x81,0x90,0x6e,0x28,0xa7,0x73,0x37,0xbc,0x84,0xaf,
                0x6c,0x73,0xa5,0xb1,0x16,0x36,0x10,0xcf,0xcd,0x3a,0xbe,0x5a,0x7e,0x81,0xaa,0x51} },
    { 400000,  {0x48,0x7c,0x83,0xfa,0x9d,0x02,0xc3,0x36,0x42,0xcf,0x5d,0x39,0xe8,0xc1,0xfd,0x2b,
                0x40,0xc4,0x36,0x8b,0xa0,0x48,0xcd,0xcf,0x85,0xcd,0x12,0x43,0x3d,0x9b,0xab,0x4a} },
    { 600000,  {0x5d,0xb5,0x53,0x97,0x91,0xa6,0x1a,0x13,0x51,0x2d,0x5a,0xb9,0x97,0x62,0xc3,0x51,
                0xb9,0x5c,0x87,0xb6,0xaa,0x85,0x9e,0x73,0xa0,0xdb,0xe2,0x98,0x91,0x9c,0x3d,0x71} },
    { 800000,  {0x99,0x5b,0x32,0xf8,0x64,0x9d,0x0b,0x14,0xc6,0xcf,0x98,0x80,0x68,0xe8,0xa5,0x72,
                0x9a,0x5e,0x1f,0x4b,0xb1,0x20,0xc1,0x93,0x02,0xa7,0x69,0x72,0xf2,0xdf,0xaf,0x0d} },
    { 1000000, {0x5f,0x9c,0xda,0x78,0xf3,0x55,0x11,0xe3,0x02,0xc3,0x62,0x6b,0xd8,0x2e,0x30,0x36,
                0x7f,0x18,0x43,0xf7,0x84,0x55,0x2c,0x8d,0x8f,0x5f,0xeb,0xf6,0xa2,0x3f,0x04,0xc2} },
    { 1400000, {0xb3,0xd9,0x42,0x05,0x93,0x07,0x59,0x57,0x3e,0x8d,0xcb,0xde,0x46,0xaf,0x86,0x28,
                0x93,0xed,0x1d,0x6b,0x61,0x12,0x25,0xe8,0x8c,0x4c,0x3d,0x48,0x50,0x17,0xae,0xf9} },
    { 1500000, {0x90,0x50,0xbc,0x94,0x93,0x78,0x4b,0xca,0xb2,0x16,0x50,0x29,0x0b,0x86,0x55,0x42,
                0xdb,0xeb,0x75,0x2f,0x53,0xe7,0xdb,0xb8,0xf9,0x9d,0xf0,0xda,0x13,0xfa,0x0c,0xdc} },
};

static const bip158_cp_t *get_checkpoints(const char *network, size_t *count)
{
    if (strcmp(network, "mainnet") == 0) {
        *count = sizeof(mainnet_checkpoints) / sizeof(mainnet_checkpoints[0]);
        return mainnet_checkpoints;
    }
    if (strcmp(network, "testnet3") == 0 || strcmp(network, "testnet") == 0) {
        *count = sizeof(testnet3_checkpoints) / sizeof(testnet3_checkpoints[0]);
        return testnet3_checkpoints;
    }
    *count = 0;
    return NULL;
}

/*
 * After a batch of filter headers has been stored into the ring buffer,
 * verify any hard-coded checkpoints whose heights fall within
 * [start_height, start_height + n).
 *
 * Returns 1 if all in-range checkpoints match, 0 on mismatch.
 * On mismatch, the peer connection is closed so the caller can reconnect.
 */
int bip158_verify_filter_checkpoints(bip158_backend_t *b,
                                      int start_height, int n)
{
    size_t cp_count;
    const bip158_cp_t *cps = get_checkpoints(b->network, &cp_count);
    if (!cps) return 1;  /* no checkpoints for this network */

    for (size_t i = 0; i < cp_count; i++) {
        int32_t ch = cps[i].height;
        if (ch < start_height || ch >= start_height + n) continue;
        const uint8_t *stored = b->filter_headers[ch % BIP158_HEADER_WINDOW];
        if (memcmp(stored, cps[i].filter_header, 32) != 0) {
            fprintf(stderr,
                    "BIP158: checkpoint mismatch at height %d — "
                    "disconnecting peer\n", (int)ch);
            p2p_close(&b->peers[b->current_peer]);
            return 0;
        }
    }
    return 1;
}

int bip158_backend_checkpoint_count(const char *network)
{
    size_t count = 0;
    get_checkpoints(network ? network : "", &count);
    return (int)count;
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
    conf_targets_default(&backend->base.conf);

    backend->tip_height             = -1;  /* unknown until first sync */
    backend->headers_synced         = -1;  /* no block headers yet     */
    backend->filter_headers_synced  = -1;  /* no filter headers yet    */
    for (int i = 0; i < BIP158_MAX_PEERS; i++) {
        backend->peers[i].fd = -1;         /* no P2P connection yet    */
    }
    backend->n_connected = 0;
    memset(backend->peer_connected, 0, sizeof(backend->peer_connected));

    if (network)
        snprintf(backend->network, sizeof(backend->network), "%s", network);

    return 1;
}

void bip158_backend_free(bip158_backend_t *backend)
{
    if (!backend) return;
    for (int i = 0; i < BIP158_MAX_PEERS; i++) {
        p2p_close(&backend->peers[i]);
    }
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
    if (!backend || backend->peers[backend->current_peer].fd < 0) return 0;

    /* Subscribe to mempool (BIP 35) on first call */
    if (!backend->mempool_subscribed) {
        if (p2p_send_mempool(&backend->peers[backend->current_peer]))
            backend->mempool_subscribed = 1;
    }

    /* Collect pending MSG_TX inv announcements (100 ms poll window) */
    uint8_t txids[256][32];
    int n = p2p_poll_inv(&backend->peers[backend->current_peer], txids, 256, 100);

    /* Convert each txid to display-order hex, fire callback, cache raw bytes */
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        /* Store raw bytes in the ring buffer */
        int slot = backend->mempool_cache_head % BIP158_MEMPOOL_CACHE_SIZE;
        memcpy(backend->mempool_cache[slot], txids[i], 32);
        backend->mempool_cache_head++;
        if (backend->mempool_cache_count < BIP158_MEMPOOL_CACHE_SIZE)
            backend->mempool_cache_count++;

        /* Fire callback with display-order hex */
        if (backend->mempool_cb) {
            char hex[65];
            for (int b = 0; b < 32; b++) {
                hex[(31 - b) * 2]     = hx[(txids[i][b] >> 4) & 0xf];
                hex[(31 - b) * 2 + 1] = hx[txids[i][b] & 0xf];
            }
            hex[64] = '\0';
            backend->mempool_cb(hex, backend->mempool_ctx);
        }
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

        if (!p2p_send_getheaders(&b->peers[b->current_peer], locator, n_locator, NULL)) {
            result = -1;
            break;
        }

        uint32_t nbits_batch[2000];
        uint32_t ts_batch[2000];
        uint8_t  prev_hashes[2000][32];
        int n = p2p_recv_headers_pow(&b->peers[b->current_peer], new_hashes, 2000,
                                      nbits_batch, ts_batch, prev_hashes);
        if (n < 0) { result = -1; break; }
        if (n == 0) break;  /* peer has nothing more to send */

        for (int i = 0; i < n; i++) {
            int height = start_height + i;

            /* Reorg detection: validate chain continuity via prev_hash */
            if (height > 0 && b->headers_synced >= height - 1) {
                int prev_idx = (height - 1) % BIP158_HEADER_WINDOW;
                if (memcmp(prev_hashes[i], b->header_hashes[prev_idx], 32) != 0) {
                    /* prev_hash mismatch — peer is on a different chain.
                       Walk backward to find the fork point. */
                    int fork_height = height - 1;
                    /* The fork is at least at height-1; the peer's chain diverged here.
                       For simplicity, reorg to the block before the mismatch. */
                    fprintf(stderr, "BIP158: prev_hash mismatch at height %d "
                            "(chain fork detected)\n", height);
                    bip158_handle_reorg(b, fork_height);
                    /* Restart header sync from new tip */
                    result = b->tip_height;
                    goto headers_done;
                }
            }

            memcpy(b->header_hashes[height % BIP158_HEADER_WINDOW],
                   new_hashes[i], 32);
            b->nBits_ring[height % BIP158_HEADER_WINDOW] = nbits_batch[i];
            b->timestamp_ring[height % BIP158_HEADER_WINDOW] = ts_batch[i];
            /* Difficulty transition check at every 2016-block boundary */
            if (height > 0 && (height % 2016) == 0) {
                uint32_t old_bits = b->nBits_ring[(height - 1) % BIP158_HEADER_WINDOW];
                uint32_t new_bits = nbits_batch[i];
                /* Compute real timespan: time of last block in window minus first block.
                 * height >= 2016 here (height > 0 and height % 2016 == 0), so
                 * height - 2016 >= 0 is guaranteed. */
                // cppcheck-suppress negativeIndex
                uint32_t t_first = b->timestamp_ring[(height - 2016) % BIP158_HEADER_WINDOW];
                uint32_t t_last  = b->timestamp_ring[(height - 1) % BIP158_HEADER_WINDOW];
                uint32_t actual_timespan = (t_last > t_first) ? (t_last - t_first) : 1209600;
                if (!p2p_validate_difficulty_transition(old_bits, new_bits, actual_timespan)) {
                    fprintf(stderr, "BIP158: difficulty transition violation at height %d\n",
                            height);
                    p2p_close(&b->peers[b->current_peer]);
                    result = -1;
                    goto headers_done;
                }
            }
            b->headers_synced = height;
        }
        result = b->headers_synced;

        if (n < 2000) break;  /* fewer than max → reached peer's tip */
    }

headers_done:
    free(new_hashes);
    return result;
}

/* -------------------------------------------------------------------------
 * Phase 6: conflict resolution — verify a peer's filter header by downloading
 * the block, collecting output scripts, and recomputing the filter locally.
 *
 * Called when a peer returns a filter header that differs from the value
 * already stored in the ring buffer (i.e., from a previous peer connection).
 *
 * Returns 1 if the current peer's header is correct (stored value updated).
 * Returns 0 if the current peer's header is wrong or cannot be verified
 *           (peer is disconnected so the caller can rotate to the next one).
 *
 * Limitation: only output scripts are available here; input prevout scripts
 * require a UTXO set which a light client does not have.  A mismatch of even
 * the outputs is conclusive evidence of a bad peer; when the computed header
 * matches neither stored nor peer, we disconnect conservatively.
 * ------------------------------------------------------------------------- */

typedef struct {
    bip158_script_t *scripts;
    size_t           n;
    size_t           cap;
} collect_scripts_ctx_t;

static void collect_scripts_cb(const char *txid_hex,
                                size_t n_outputs,
                                const unsigned char **spks,
                                const size_t *spk_lens,
                                void *ctx)
{
    collect_scripts_ctx_t *c = ctx;
    (void)txid_hex;
    for (size_t i = 0; i < n_outputs; i++) {
        /* BIP 158: skip OP_RETURN outputs (0x6a prefix) */
        if (spk_lens[i] > 0 && spks[i][0] == 0x6a) continue;
        if (spk_lens[i] > sizeof(c->scripts[0].spk)) continue;
        if (c->n >= c->cap) continue;
        memcpy(c->scripts[c->n].spk, spks[i], spk_lens[i]);
        c->scripts[c->n].spk_len = spk_lens[i];
        c->n++;
    }
}

static int bip158_resolve_conflict(bip158_backend_t *b, int height,
                                    const uint8_t peer_hdr[32])
{
    const uint8_t *stored     = b->filter_headers[height % BIP158_HEADER_WINDOW];
    const uint8_t *block_hash = b->header_hashes[height % BIP158_HEADER_WINDOW];

    /* Download the block from the current peer */
    if (!p2p_send_getdata_block(&b->peers[b->current_peer], block_hash)) goto disconnect;

    uint8_t *block_data = NULL;
    size_t   block_len  = 0;
    if (p2p_recv_block(&b->peers[b->current_peer], &block_data, &block_len) != 1) goto disconnect;

    /* Collect output scripts (OP_RETURN excluded) */
    collect_scripts_ctx_t cctx;
    cctx.cap     = 4096;
    cctx.scripts = malloc(cctx.cap * sizeof(bip158_script_t));
    cctx.n       = 0;
    if (!cctx.scripts) { free(block_data); goto disconnect; }

    p2p_scan_block_txs(block_data, block_len, collect_scripts_cb, &cctx);
    free(block_data);

    /* Build the compact filter from collected scripts */
    size_t filter_cap = bip158_gcs_build_size(cctx.n);
    uint8_t *filter = malloc(filter_cap);
    if (!filter) { free(cctx.scripts); goto disconnect; }

    size_t filter_len = bip158_gcs_build(cctx.scripts, cctx.n,
                                          block_hash, filter, filter_cap);
    free(cctx.scripts);

    if (filter_len == 0) { free(filter); goto disconnect; }

    /* Compute the filter header locally */
    uint8_t prev_fh[32] = {0};
    if (height > 0)
        memcpy(prev_fh, b->filter_headers[(height - 1) % BIP158_HEADER_WINDOW], 32);

    uint8_t local_hdr[32];
    bip158_compute_filter_header(filter, filter_len, prev_fh, local_hdr);
    free(filter);

    /* local == stored → peer's header is wrong; disconnect peer */
    if (memcmp(local_hdr, stored, 32) == 0) {
        fprintf(stderr, "BIP158: conflict at height %d — peer header wrong, "
                "disconnecting\n", height);
        p2p_close(&b->peers[b->current_peer]);
        return 0;
    }

    /* local == peer → stored value was wrong; update and trust peer */
    if (memcmp(local_hdr, peer_hdr, 32) == 0) {
        fprintf(stderr, "BIP158: conflict at height %d — updating stored "
                "header from peer\n", height);
        memcpy(b->filter_headers[height % BIP158_HEADER_WINDOW], peer_hdr, 32);
        return 1;
    }

    /* Neither matches — likely because we lack prevout scripts; disconnect
     * the current peer conservatively */
    fprintf(stderr, "BIP158: conflict at height %d — cannot verify "
            "(no prevouts available), disconnecting\n", height);

disconnect:
    p2p_close(&b->peers[b->current_peer]);
    return 0;
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

        if (!p2p_send_getcfheaders(&b->peers[b->current_peer], (uint32_t)start, stop_hash)) {
            result = -1;
            break;
        }

        uint8_t  stop_out[32], prev_fh[32];
        uint8_t *hdrs   = NULL;
        size_t   count  = 0;
        int r = p2p_recv_cfheaders(&b->peers[b->current_peer], stop_out, prev_fh, &hdrs, &count);
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

        /* Detect conflicts: compare new headers against previously-stored
         * values at heights we have already processed from an earlier peer.
         * On mismatch, download the block to arbitrate (Phase 6). */
        for (size_t i = 0; i < count; i++) {
            int height = start + (int)i;
            if (height <= b->filter_headers_synced) {
                /* We already have this height from a previous peer connection */
                const uint8_t *new_hdr = hdrs + i * 32;
                if (memcmp(b->filter_headers[height % BIP158_HEADER_WINDOW],
                           new_hdr, 32) != 0) {
                    int ok = bip158_resolve_conflict(b, height, new_hdr);
                    if (!ok) {
                        free(hdrs);
                        result = -1;
                        goto done;
                    }
                }
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

        /* Verify hard-coded checkpoints for this batch */
        if (!bip158_verify_filter_checkpoints(b, start, (int)count)) {
            result = -1;
            break;
        }

        if ((int)count < 2000) break;
    }

done:
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

/* Public wrapper — exposed for unit testing and bip158_resolve_conflict(). */
void bip158_compute_filter_header(const unsigned char *filter_bytes,
                                   size_t filter_len,
                                   const unsigned char prev_filter_hdr[32],
                                   unsigned char out[32])
{
    compute_filter_header(filter_bytes, filter_len, prev_filter_hdr, out);
}

int bip158_backend_connect_all(bip158_backend_t *backend)
{
    if (!backend || backend->n_peers == 0) return 0;

    int limit = backend->n_peers < 3 ? backend->n_peers : 3;
    int connected = 0;

    for (int i = 0; i < limit; i++) {
        if (backend->peer_connected[i]) {
            connected++;
            continue;
        }
        if (p2p_connect(&backend->peers[i],
                         backend->peer_hosts[i],
                         backend->peer_ports[i],
                         backend->network)) {
            backend->peer_connected[i] = 1;
            connected++;
            fprintf(stderr, "BIP158: connected to peer %d (%s:%d)\n",
                    i, backend->peer_hosts[i], backend->peer_ports[i]);
        }
    }

    backend->n_connected = connected;
    /* If no current peer is connected, pick first connected */
    if (backend->peers[backend->current_peer].fd < 0) {
        for (int i = 0; i < limit; i++) {
            if (backend->peer_connected[i]) {
                backend->current_peer = i;
                break;
            }
        }
    }
    return connected;
}

/*
 * BIP 158 scan loop — Phase 5 complete (P2P primary, RPC fallback).
 *
 * P2P path (preferred when backend->peers[backend->current_peer].fd >= 0):
 *   1. bip158_sync_headers() fetches block hashes into the ring buffer and
 *      provides the chain tip height — no RPC needed for header data.
 *   2. getcfilters requests are batched in chunks of 1000 blocks.
 *   3. Filter hits download full block via P2P; on failure, fall back to
 *      regtest_scan_block_txs() if rpc_ctx is available.
 *
 * Fallback path (P2P down, ring buffer + RPC last resort):
 *   Uses ring-buffer block hashes when available, then regtest_get_block_hash,
 *   regtest_get_block_filter, and regtest_scan_block_txs as last resort.
 *
 * Returns number of matched blocks, or -1 on hard error.
 */
int bip158_backend_scan(bip158_backend_t *backend)
{
    if (!backend) return -1;

    regtest_t *rt = (regtest_t *)backend->rpc_ctx;

    if (backend->peers[backend->current_peer].fd < 0 && !rt && backend->n_peers == 0) return -1;
    if (!backend->n_scripts) return 0;

    /* Determine chain tip — P2P path syncs headers + filter headers.
       Phase 6: attempt peer rotation on disconnect before falling back. */
    int tip = -1;
    if (backend->peers[backend->current_peer].fd >= 0) {
        tip = bip158_sync_headers(backend);
        if (tip >= 0) {
            bip158_sync_filter_headers(backend, tip);
        } else {
            p2p_close(&backend->peers[backend->current_peer]);
            if (backend->n_peers > 1)
                bip158_backend_reconnect(backend);
        }
    } else if (backend->n_peers > 0) {
        /* Lost connection between scan calls; try to restore it */
        bip158_backend_reconnect(backend);
    }
    /* Re-check after possible reconnect */
    if (tip < 0 && backend->peers[backend->current_peer].fd >= 0) {
        tip = bip158_sync_headers(backend);
        if (tip >= 0)
            bip158_sync_filter_headers(backend, tip);
        else
            p2p_close(&backend->peers[backend->current_peer]);
    }
    if (tip < 0) {
        /* Phase 5: use headers_synced from ring buffer before RPC */
        if (backend->headers_synced >= 0)
            tip = backend->headers_synced;
        else if (rt)
            tip = regtest_get_block_height(rt);
        if (tip < 0) return 0;  /* no tip yet; caller retries on next poll */
    }

    int start = (backend->tip_height >= 0) ? backend->tip_height + 1 : tip;
    if (start > tip) return 0;

#define FILTER_BUF_MAX (4 * 1024 * 1024)
    unsigned char *filter_buf = malloc(FILTER_BUF_MAX);
    if (!filter_buf) return -1;

    int matched = 0;

    if (backend->peers[backend->current_peer].fd >= 0) {
        /* === P2P path: batched getcfilters, ring-buffer block hashes === */
        for (int h = start; h <= tip && backend->peers[backend->current_peer].fd >= 0; ) {
            int batch_end = (h + 999 < tip) ? h + 999 : tip;
            const uint8_t *stop = backend->header_hashes[batch_end % BIP158_HEADER_WINDOW];

            if (!p2p_send_getcfilters(&backend->peers[backend->current_peer], (uint32_t)h, stop)) {
                p2p_close(&backend->peers[backend->current_peer]);
                break;
            }

            int batch_ok = 1;
            for (int bh = h; bh <= batch_end; bh++) {
                uint8_t *pf = NULL;
                size_t   pf_len;
                uint8_t  recv_hash[32], recv_key[16];

                int r = p2p_recv_cfilter(&backend->peers[backend->current_peer], recv_hash,
                                          &pf, &pf_len, recv_key);
                if (r != 1) {
                    free(pf);
                    if (r == -1) p2p_close(&backend->peers[backend->current_peer]);
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
                        p2p_close(&backend->peers[backend->current_peer]);
                        batch_ok = 0;
                        break;
                    }
                }

                if (!bip158_scan_filter(backend, filter_buf, use_len, recv_key)) {
                    backend->tip_height = bh;
                    if (backend->block_connected_cb)
                        backend->block_connected_cb((uint32_t)bh,
                                                     backend->block_connected_ctx);
                    continue;
                }

                /* Filter hit: download full block via P2P and scan txs.
                   Falls back to RPC if P2P block download fails. */
                scan_cb_ctx_t sc = { backend, (int32_t)bh, 0 };
                int block_scanned = 0;
                if (p2p_send_getdata_block(&backend->peers[backend->current_peer], recv_hash)) {
                    uint8_t *blk  = NULL;
                    size_t   blen = 0;
                    int br = p2p_recv_block(&backend->peers[backend->current_peer], &blk, &blen);
                    if (br == 1) {
                        p2p_scan_block_txs(blk, blen,
                                           (p2p_block_scan_cb_t)scan_tx_callback,
                                           &sc);
                        block_scanned = 1;

                        /* Fire UTXO tracking callbacks if registered */
                        if (backend->utxo_found_cb || backend->utxo_spent_cb) {
                            p2p_scan_block_full(blk, blen,
                                                backend->utxo_found_cb,
                                                backend->utxo_spent_cb,
                                                backend->utxo_cb_ctx);
                        }

                        /* Extract fee sample from coinbase for fee estimator */
                        if (backend->fee_estimator && blen > 80 + 4 + 1) {
                            uint64_t sample = bip158_extract_block_fee_sample(
                                blk, blen, (uint32_t)bh);
                            if (sample > 0)
                                fee_estimator_blocks_add_sample(
                                    (fee_estimator_blocks_t *)backend->fee_estimator,
                                    sample);
                        }
                    } else if (br < 0) {
                        p2p_close(&backend->peers[backend->current_peer]);
                    }
                    free(blk);
                } else {
                    p2p_close(&backend->peers[backend->current_peer]);
                }
                /* Phase 5: fall back to RPC scan if P2P block download failed */
                if (!block_scanned && rt) {
                    char hx[65];
                    for (int b = 0; b < 32; b++)
                        sprintf(hx + b*2, "%02x", recv_hash[31 - b]);
                    hx[64] = 0;
                    regtest_scan_block_txs(rt, hx, scan_tx_callback, &sc);
                    block_scanned = 1;
                } else if (!block_scanned) {
                    fprintf(stderr, "BIP158: block %d P2P download failed, no RPC fallback\n", bh);
                }
                if (sc.found) matched++;
                backend->tip_height = bh;
                if (backend->block_connected_cb)
                    backend->block_connected_cb((uint32_t)bh,
                                                 backend->block_connected_ctx);
            }

            if (!batch_ok) break;
            h = batch_end + 1;
        }
    } else if (backend->peers[backend->current_peer].fd < 0) {
        /* === Fallback path: ring-buffer hashes + P2P reconnect + RPC last resort === */
        /* Phase 5: when P2P is down but we have header data in the ring buffer,
           attempt to reconnect and use P2P for filters + blocks.
           Only fall back to RPC if both P2P and ring buffer are unavailable. */
        if (backend->n_peers > 0)
            bip158_backend_reconnect(backend);

        /* If reconnect succeeded, re-enter P2P path on next scan call */
        if (backend->peers[backend->current_peer].fd >= 0)
            return 0;  /* will use P2P path on next poll */

        /* True fallback: RPC path for environments without P2P peers */
        if (!rt) return 0;  /* no RPC either; caller retries later */
        for (int h = start; h <= tip; h++) {
            char          hash_hex[65];
            size_t        filter_len = 0;
            unsigned char key[16];

            /* Use ring buffer hash if available, else RPC */
            int have_hash = 0;
            if (backend->headers_synced >= h && h >= 0) {
                const uint8_t *bh = backend->header_hashes[h % BIP158_HEADER_WINDOW];
                for (int b = 0; b < 32; b++)
                    sprintf(hash_hex + b*2, "%02x", bh[31 - b]);
                hash_hex[64] = 0;
                have_hash = 1;
            } else {
                have_hash = regtest_get_block_hash(rt, h, hash_hex, sizeof(hash_hex));
            }
            if (!have_hash) {
                backend->tip_height = h;
                if (backend->block_connected_cb)
                    backend->block_connected_cb((uint32_t)h,
                                                 backend->block_connected_ctx);
                continue;
            }
            if (!regtest_get_block_filter(rt, hash_hex,
                                           filter_buf, &filter_len,
                                           FILTER_BUF_MAX, key)) {
                backend->tip_height = h;
                if (backend->block_connected_cb)
                    backend->block_connected_cb((uint32_t)h,
                                                 backend->block_connected_ctx);
                continue;
            }
            if (!bip158_scan_filter(backend, filter_buf, filter_len, key)) {
                backend->tip_height = h;
                if (backend->block_connected_cb)
                    backend->block_connected_cb((uint32_t)h,
                                                 backend->block_connected_ctx);
                continue;
            }

            scan_cb_ctx_t sc = { backend, (int32_t)h, 0 };
            regtest_scan_block_txs(rt, hash_hex, scan_tx_callback, &sc);
            if (sc.found) matched++;
            backend->tip_height = h;
            if (backend->block_connected_cb)
                backend->block_connected_cb((uint32_t)h,
                                             backend->block_connected_ctx);
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
    p2p_close(&backend->peers[backend->current_peer]);
    int ok = p2p_connect(&backend->peers[backend->current_peer], host, port, backend->network);
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

/* -------------------------------------------------------------------------
 * Host:port string parser (shared utility for LSP and client binaries)
 * ------------------------------------------------------------------------- */

int bip158_parse_host_port(const char *arg,
                            char *host_out, size_t host_cap,
                            int *port_out)
{
    if (!arg || !host_out || !port_out) return 0;
    const char *colon = strrchr(arg, ':');
    if (!colon || colon == arg) return 0;
    size_t hlen = (size_t)(colon - arg);
    if (hlen >= host_cap) return 0;
    memcpy(host_out, arg, hlen);
    host_out[hlen] = '\0';
    *port_out = atoi(colon + 1);
    return (*port_out > 0 && *port_out <= 65535);
}

int bip158_backend_reconnect(bip158_backend_t *backend)
{
    if (!backend || backend->n_peers == 0) return 0;

    p2p_close(&backend->peers[backend->current_peer]);

    /* Try each peer once, starting after the last successful one */
    for (int i = 1; i <= backend->n_peers; i++) {
        int idx = (backend->current_peer + i) % backend->n_peers;
        const char *h = backend->peer_hosts[idx];
        int         p = backend->peer_ports[idx];
        if (!h[0] || p <= 0) continue;

        fprintf(stderr, "BIP158: reconnecting to %s:%d (peer %d/%d)...\n",
                h, p, idx + 1, backend->n_peers);
        if (p2p_connect(&backend->peers[idx], h, p, backend->network)) {
            backend->current_peer = idx;
            fprintf(stderr, "BIP158: reconnected to %s:%d (services=0x%llx, feefilter=%llu sat/kvB)\n",
                    h, p, (unsigned long long)backend->peers[backend->current_peer].peer_services,
                    (unsigned long long)backend->peers[backend->current_peer].peer_feefilter_sat_per_kvb);
            /* Update fee estimator floor with peer's feefilter */
            if (backend->fee_estimator &&
                backend->peers[backend->current_peer].peer_feefilter_sat_per_kvb > 0) {
                fee_estimator_blocks_set_floor(
                    (fee_estimator_blocks_t *)backend->fee_estimator,
                    backend->peers[backend->current_peer].peer_feefilter_sat_per_kvb);
            }
            return 1;
        }
    }
    return 0;
}

void bip158_backend_set_fee_estimator(bip158_backend_t *backend,
                                       fee_estimator_t *fe)
{
    if (!backend) return;
    backend->fee_estimator = fe;
}

void bip158_backend_set_utxo_cb(bip158_backend_t *backend,
                                  p2p_output_cb_t found_cb,
                                  p2p_input_cb_t  spent_cb,
                                  void *ctx)
{
    if (!backend) return;
    backend->utxo_found_cb = found_cb;
    backend->utxo_spent_cb = spent_cb;
    backend->utxo_cb_ctx   = ctx;
}

void bip158_backend_set_block_connected_cb(bip158_backend_t *backend,
                                            void (*cb)(uint32_t height,
                                                       void *cb_ctx),
                                            void *cb_ctx)
{
    if (!backend) return;
    backend->block_connected_cb  = cb;
    backend->block_connected_ctx = cb_ctx;
}

void bip158_backend_set_block_disconnected_cb(bip158_backend_t *backend,
                                               void (*cb)(uint32_t height,
                                                          void *cb_ctx),
                                               void *cb_ctx)
{
    if (!backend) return;
    backend->block_disconnected_cb  = cb;
    backend->block_disconnected_ctx = cb_ctx;
}

int bip158_handle_reorg(bip158_backend_t *b, int fork_height)
{
    if (!b || fork_height < 0) return 0;
    if (b->tip_height <= fork_height) return 0;  /* no rollback needed */

    int rolled_back = (int)b->tip_height - fork_height;
    fprintf(stderr, "BIP158: reorg detected — rolling back from %d to %d (%d blocks)\n",
            (int)b->tip_height, fork_height, rolled_back);

    /* Fire block_disconnected_cb for each rolled-back height (descending) */
    if (b->block_disconnected_cb) {
        for (int h = (int)b->tip_height; h > fork_height; h--)
            b->block_disconnected_cb((uint32_t)h, b->block_disconnected_ctx);
    }

    /* Invalidate tx_cache entries above fork height */
    for (size_t i = 0; i < b->n_tx_cache; i++) {
        if (b->tx_cache[i].height > fork_height) {
            memset(b->tx_cache[i].txid, 0, 32);
            b->tx_cache[i].height = -1;
        }
    }

    /* Roll back state */
    b->tip_height = fork_height;
    if (b->headers_synced > fork_height)
        b->headers_synced = fork_height;
    if (b->filter_headers_synced > fork_height)
        b->filter_headers_synced = fork_height;

    /* Clear mempool cache (may contain txs from reorged blocks) */
    b->mempool_cache_count = 0;
    b->mempool_cache_head  = 0;

    /* Fire the chain_backend reorg callback if set */
    if (b->base.reorg_cb)
        b->base.reorg_cb(fork_height, fork_height + rolled_back, b->base.reorg_cb_ctx);

    /* Persist corrected checkpoint */
    if (b->db) {
        persist_save_bip158_checkpoint(
            (persist_t *)b->db,
            b->tip_height, b->headers_synced, b->filter_headers_synced,
            (const uint8_t *)b->header_hashes, sizeof(b->header_hashes),
            (const uint8_t *)b->filter_headers, sizeof(b->filter_headers));
    }

    return rolled_back;
}
