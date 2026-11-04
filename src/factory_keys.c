/* Per-factory client keys: derivation, recovery scan, startup selection and
   payout descriptors.  See include/superscalar/factory_keys.h. */
#include "superscalar/factory_keys.h"
#include "superscalar/persist.h"
#include "superscalar/sha256.h"
#include "superscalar/factory.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <string.h>

extern int channel_read_random_bytes(unsigned char *buf, size_t len);

static const unsigned char fk_zero_ctx[33];

int factory_key_derive(const secp256k1_context *ctx, unsigned char out_seckey32[32],
                       const unsigned char root_seckey32[32],
                       const unsigned char lsp_ctx33[33], uint32_t index) {
    if (!ctx || !out_seckey32 || !root_seckey32 || !lsp_ctx33) return 0;
    unsigned char buf[32 + 33 + 4];
    memcpy(buf, root_seckey32, 32);
    memcpy(buf + 32, lsp_ctx33, 33);
    buf[65] = (unsigned char)(index >> 24);
    buf[66] = (unsigned char)(index >> 16);
    buf[67] = (unsigned char)(index >> 8);
    buf[68] = (unsigned char)index;
    sha256_tagged(FACTORY_KEY_TAG, buf, sizeof(buf), out_seckey32);
    secure_zero(buf, sizeof(buf));
    if (!secp256k1_ec_seckey_verify(ctx, out_seckey32)) {
        secure_zero(out_seckey32, 32);
        return 0;
    }
    return 1;
}

int factory_key_derive_pubkey(const secp256k1_context *ctx, unsigned char out33[33],
                              const unsigned char root_seckey32[32],
                              const unsigned char lsp_ctx33[33], uint32_t index) {
    unsigned char sk[32];
    if (!factory_key_derive(ctx, sk, root_seckey32, lsp_ctx33, index)) return 0;
    secp256k1_pubkey pk;
    size_t len = 33;
    int ok = secp256k1_ec_pubkey_create(ctx, &pk, sk) &&
             secp256k1_ec_pubkey_serialize(ctx, out33, &len, &pk,
                                           SECP256K1_EC_COMPRESSED);
    secure_zero(sk, sizeof(sk));
    return ok;
}

void factory_key_lsp_ctx(const secp256k1_context *ctx, const secp256k1_pubkey *lsp_pk,
                         unsigned char out33[33]) {
    memset(out33, 0, 33);
    if (!ctx || !lsp_pk) return;
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, out33, &len, lsp_pk,
                                       SECP256K1_EC_COMPRESSED))
        memset(out33, 0, 33);
}

int factory_key_ctx_is_zero(const unsigned char ctx33[33]) {
    return !ctx33 || memcmp(ctx33, fk_zero_ctx, 33) == 0;
}

int factory_key_scan(const secp256k1_context *ctx, const unsigned char root_seckey32[32],
                     const unsigned char lsp_ctx33[33],
                     const unsigned char (*targets33)[33], size_t n_targets,
                     uint32_t window, uint32_t *found_index, size_t *found_target) {
    if (!ctx || !root_seckey32 || !lsp_ctx33 || !targets33 || n_targets == 0)
        return 0;
    for (uint32_t i = 0; i < window; i++) {
        unsigned char pk[33];
        if (!factory_key_derive_pubkey(ctx, pk, root_seckey32, lsp_ctx33, i))
            continue;
        for (size_t t = 0; t < n_targets; t++) {
            if (memcmp(pk, targets33[t], 33) == 0) {
                if (found_index) *found_index = i;
                if (found_target) *found_target = t;
                return 1;
            }
        }
    }
    return 0;
}

uint32_t factory_key_recovery_skip(void) {
    unsigned char r[4];
    if (!channel_read_random_bytes(r, sizeof(r))) return 0;
    uint32_t v = ((uint32_t)r[0] << 24) | ((uint32_t)r[1] << 16) |
                 ((uint32_t)r[2] << 8) | (uint32_t)r[3];
    return FACTORY_KEY_SKIP_MIN + v % (FACTORY_KEY_SKIP_MAX - FACTORY_KEY_SKIP_MIN);
}

int factory_key_lookup(persist_t *db, const secp256k1_context *ctx,
                       const unsigned char root_seckey32[32],
                       const unsigned char *pinned_ctx33,
                       unsigned char out_seckey32[32], uint32_t *out_index,
                       factory_key_source_t *out_source, unsigned char out_ctx33[33]) {
    if (!db || !ctx || !root_seckey32 || !out_seckey32) return -1;

    /* 1. A key row chosen for the current factory (or reserved). */
    uint32_t row_idx = 0;
    unsigned char row_ctx[33], row_pk[33], pk[33];
    int rc = persist_factory_key_load_current(db, &row_idx, row_ctx, row_pk);
    if (rc < 0) {
        fprintf(stderr, "factory key: cannot read the key table\n");
        return -1;
    }
    if (rc == 1) {
        if (!factory_key_derive_pubkey(ctx, pk, root_seckey32, row_ctx, row_idx) ||
            memcmp(pk, row_pk, 33) != 0) {
            fprintf(stderr, "factory key: stored key %u does not match this root "
                    "key (wrong --seckey/keyfile for this DB?)\n", row_idx);
            return -1;
        }
        if (!factory_key_derive(ctx, out_seckey32, root_seckey32, row_ctx, row_idx))
            return -1;
        if (out_index) *out_index = row_idx;
        if (out_source) *out_source = FACTORY_KEY_RELOADED;
        if (out_ctx33) memcpy(out_ctx33, row_ctx, 33);
        return 1;
    }

    /* 2. A factory in the DB without a key row: legacy or restored. */
    int fx = persist_factory_exists_checked(db, 0);
    if (fx < 0) {
        fprintf(stderr, "factory key: cannot read the stored factory\n");
        return -1;
    }
    if (fx == 0) return 0;

    unsigned char parts[FACTORY_MAX_SIGNERS][33];
    int n = persist_load_participant_pubkeys33(db, 0, parts, FACTORY_MAX_SIGNERS);
    if (n < 0) {
        fprintf(stderr, "factory key: cannot read the stored factory's participants\n");
        return -1;
    }
    unsigned char id33[33];
    secp256k1_pubkey id_pk;
    size_t len = 33;
    if (!secp256k1_ec_pubkey_create(ctx, &id_pk, root_seckey32) ||
        !secp256k1_ec_pubkey_serialize(ctx, id33, &len, &id_pk, SECP256K1_EC_COMPRESSED))
        return -1;
    for (int i = 0; i < n; i++) {
        if (memcmp(parts[i], id33, 33) == 0) {
            memcpy(out_seckey32, root_seckey32, 32);
            if (out_index) *out_index = 0;
            if (out_source) *out_source = FACTORY_KEY_LEGACY;
            if (out_ctx33) memset(out_ctx33, 0, 33);
            return 1;
        }
    }

    /* Recovery scan: the pinned context, then the zero context (keys derived
       before a pinned LSP key was required). */
    const unsigned char *ctxs[2];
    size_t n_ctx = 0;
    if (pinned_ctx33 && !factory_key_ctx_is_zero(pinned_ctx33)) ctxs[n_ctx++] = pinned_ctx33;
    ctxs[n_ctx++] = fk_zero_ctx;
    for (size_t c = 0; c < n_ctx && n > 0; c++) {
        uint32_t found = 0;
        if (!factory_key_scan(ctx, root_seckey32, ctxs[c],
                              (const unsigned char (*)[33])parts, (size_t)n,
                              FACTORY_KEY_SCAN_WINDOW, &found, NULL))
            continue;
        char state[16];
        int st = persist_factory_key_get_state(db, found, state);
        if (st < 0) {
            fprintf(stderr, "factory key: cannot read the key table\n");
            return -1;
        }
        if (st == 1) {
            fprintf(stderr, "factory key: the stored factory uses key %u, which this "
                    "DB records as %s; refusing to use it again\n", found, state);
            return -1;
        }
        if (!factory_key_derive(ctx, out_seckey32, root_seckey32, ctxs[c], found))
            return -1;
        if (out_index) *out_index = found;
        if (out_source) *out_source = FACTORY_KEY_RECOVERED;
        if (out_ctx33) memcpy(out_ctx33, ctxs[c], 33);
        return 1;
    }
    fprintf(stderr, "factory key: the stored factory has no key of this client in "
            "indexes [0, %u)\n", FACTORY_KEY_SCAN_WINDOW);
    return -1;
}

/* The first index a new reservation may take: past every row and the
   counter.  0 on a DB error. */
static int fk_next_index(persist_t *db, uint64_t *next) {
    uint64_t counter = 0;
    int64_t mx = -1;
    if (persist_load_counter_checked(db, FACTORY_KEY_COUNTER, &counter) < 0 ||
        !persist_factory_key_max_index(db, &mx))
        return 0;
    *next = counter;
    if (mx >= 0 && (uint64_t)mx + 1 > *next) *next = (uint64_t)mx + 1;
    return 1;
}

int factory_key_select(persist_t *db, const secp256k1_context *ctx,
                       const unsigned char root_seckey32[32],
                       const unsigned char *pinned_ctx33,
                       unsigned char out_seckey32[32], uint32_t *out_index,
                       factory_key_source_t *out_source) {
    if (!ctx || !root_seckey32 || !out_seckey32) return 0;

    if (!db) {
        if (!factory_key_derive(ctx, out_seckey32, root_seckey32,
                                pinned_ctx33 ? pinned_ctx33 : fk_zero_ctx, 0))
            return 0;
        if (out_index) *out_index = 0;
        if (out_source) *out_source = FACTORY_KEY_FRESH;
        return 1;
    }

    int own = !persist_in_transaction(db);
    if (own && !persist_begin(db)) {
        fprintf(stderr, "factory key: cannot open a DB transaction\n");
        return 0;
    }
    uint32_t idx = 0;
    factory_key_source_t src = FACTORY_KEY_FRESH;
    unsigned char used_ctx[33];
    int rc = factory_key_lookup(db, ctx, root_seckey32, pinned_ctx33, out_seckey32,
                                &idx, &src, used_ctx);
    if (rc < 0) goto fail;

    if (rc == 1 && src == FACTORY_KEY_RECOVERED) {
        uint32_t skip = factory_key_recovery_skip();
        uint64_t cur = 0;
        unsigned char pk[33];
        if (skip == 0 || !fk_next_index(db, &cur) ||
            !factory_key_derive_pubkey(ctx, pk, root_seckey32, used_ctx, idx))
            goto fail;
        uint64_t next = (uint64_t)idx + 1 + skip;
        if (cur > next) next = cur;
        if (!persist_factory_key_save(db, idx, used_ctx, pk, 0, FACTORY_KEY_STATE_ACTIVE) ||
            !persist_save_counter(db, FACTORY_KEY_COUNTER, next))
            goto fail;
    } else if (rc == 0) {
        /* Nothing stored: reserve the next index, bound to the pinned LSP key. */
        if (!pinned_ctx33 || factory_key_ctx_is_zero(pinned_ctx33)) {
            fprintf(stderr, "factory key: a new factory key needs the LSP's key "
                    "pinned (--lsp-pubkey) when a client DB is used\n");
            goto fail;
        }
        uint64_t next = 0;
        if (!fk_next_index(db, &next) || next > UINT32_MAX) goto fail;
        idx = (uint32_t)next;
        unsigned char pk[33];
        /* An index whose hash is not a valid key is skipped (never in practice). */
        while (!factory_key_derive_pubkey(ctx, pk, root_seckey32, pinned_ctx33, idx)) {
            if (idx == UINT32_MAX) goto fail;
            idx++;
        }
        if (!persist_factory_key_save(db, idx, pinned_ctx33, pk, -1,
                                      FACTORY_KEY_STATE_RESERVED) ||
            !persist_save_counter(db, FACTORY_KEY_COUNTER, (uint64_t)idx + 1) ||
            !factory_key_derive(ctx, out_seckey32, root_seckey32, pinned_ctx33, idx))
            goto fail;
        src = FACTORY_KEY_FRESH;
    }
    if (own && !persist_commit(db)) {
        fprintf(stderr, "factory key: commit failed\n");
        secure_zero(out_seckey32, 32);
        return 0;
    }
    if (out_index) *out_index = idx;
    if (out_source) *out_source = src;
    return 1;

fail:
    if (own) persist_rollback(db);
    secure_zero(out_seckey32, 32);
    fprintf(stderr, "factory key: no factory key chosen\n");
    return 0;
}

int factory_key_check_participants(const secp256k1_context *ctx, persist_t *db,
                                   const secp256k1_pubkey *identity_pk,
                                   const secp256k1_pubkey *my_factory_pk,
                                   size_t my_slot,
                                   const secp256k1_pubkey *participants, size_t n,
                                   const char **why) {
    const char *dummy;
    if (!why) why = &dummy;
    *why = NULL;
    if (!ctx || !my_factory_pk || !participants || my_slot >= n) {
        *why = "bad arguments";
        return 0;
    }
    unsigned char mine[33], id33[33], cur[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, mine, &len, my_factory_pk,
                                       SECP256K1_EC_COMPRESSED)) {
        *why = "bad factory key";
        return 0;
    }
    int have_id = 0;
    if (identity_pk) {
        len = 33;
        have_id = secp256k1_ec_pubkey_serialize(ctx, id33, &len, identity_pk,
                                                SECP256K1_EC_COMPRESSED);
    }
    /* A legacy factory signs with the identity key itself: then it may sit in
       this client's own slot, and only there. */
    int legacy = have_id && memcmp(mine, id33, 33) == 0;
    for (size_t i = 0; i < n; i++) {
        len = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, cur, &len, &participants[i],
                                           SECP256K1_EC_COMPRESSED)) {
            *why = "bad participant key";
            return 0;
        }
        if (i == my_slot) {
            if (memcmp(cur, mine, 33) != 0) {
                *why = "my slot does not hold my factory key";
                return 0;
            }
        } else if (memcmp(cur, mine, 33) == 0) {
            *why = "my factory key appears in another slot";
            return 0;
        }
        if (have_id && !legacy && memcmp(cur, id33, 33) == 0) {
            *why = "a participant key is my identity key";
            return 0;
        }
        if (db) {
            int rel = persist_factory_key_is_released(db, cur);
            if (rel < 0) {
                *why = "cannot read the key table";
                return 0;
            }
            if (rel) {
                *why = "a participant key was released to the LSP before";
                return 0;
            }
        }
    }
    return 1;
}

/* --- Payout descriptors --- */

static int fk_base58check(const unsigned char *data, size_t len, char *out, size_t outlen) {
    static const char b58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    unsigned char buf[64 + 4], h[32];
    if (len > 64) return 0;
    memcpy(buf, data, len);
    sha256_double(data, len, h);
    memcpy(buf + len, h, 4);
    size_t n = len + 4;
    unsigned char digits[100];
    size_t nd = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned int carry = buf[i];
        for (size_t j = 0; j < nd; j++) {
            carry += (unsigned int)digits[j] << 8;
            digits[j] = (unsigned char)(carry % 58);
            carry /= 58;
        }
        while (carry) {
            if (nd >= sizeof(digits)) return 0;
            digits[nd++] = (unsigned char)(carry % 58);
            carry /= 58;
        }
    }
    size_t zeros = 0;
    while (zeros < n && buf[zeros] == 0) zeros++;
    if (zeros + nd + 1 > outlen) return 0;
    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    for (size_t i = 0; i < nd; i++) out[o++] = b58[digits[nd - 1 - i]];
    out[o] = '\0';
    secure_zero(buf, sizeof(buf));
    secure_zero(digits, sizeof(digits));
    return 1;
}

int factory_key_wif(const unsigned char seckey32[32], int mainnet, char *out, size_t outlen) {
    if (!seckey32 || !out) return 0;
    unsigned char raw[34];
    raw[0] = mainnet ? 0x80 : 0xef;
    memcpy(raw + 1, seckey32, 32);
    raw[33] = 0x01;                          /* compressed */
    int ok = fk_base58check(raw, sizeof(raw), out, outlen);
    secure_zero(raw, sizeof(raw));
    return ok;
}

static uint64_t fk_polymod(uint64_t c, int val) {
    uint8_t c0 = (uint8_t)(c >> 35);
    c = ((c & 0x7ffffffffULL) << 5) ^ (uint64_t)val;
    if (c0 & 1) c ^= 0xf5dee51989ULL;
    if (c0 & 2) c ^= 0xa9fdca3312ULL;
    if (c0 & 4) c ^= 0x1bab10e32dULL;
    if (c0 & 8) c ^= 0x3706b1677aULL;
    if (c0 & 16) c ^= 0x644d626ffdULL;
    return c;
}

int descriptor_checksum(const char *desc, char out9[9]) {
    static const char input_charset[] =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    static const char checksum_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    if (!desc || !out9) return 0;
    uint64_t c = 1;
    int cls = 0, clscount = 0;
    for (const char *p = desc; *p; p++) {
        const char *f = strchr(input_charset, *p);
        if (!f || *p == '\0') return 0;
        int pos = (int)(f - input_charset);
        c = fk_polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        if (++clscount == 3) {
            c = fk_polymod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) c = fk_polymod(c, cls);
    for (int j = 0; j < 8; j++) c = fk_polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; j++) out9[j] = checksum_charset[(c >> (5 * (7 - j))) & 31];
    out9[8] = '\0';
    return 1;
}

int factory_key_descriptor(const unsigned char seckey32[32], int mainnet, int raw,
                           char *out, size_t outlen) {
    char wif[64], body[96], sum[9];
    if (!out || !factory_key_wif(seckey32, mainnet, wif, sizeof(wif))) return 0;
    int n = snprintf(body, sizeof(body), "%s(%s)", raw ? "rawtr" : "tr", wif);
    secure_zero(wif, sizeof(wif));
    int ok = n > 0 && (size_t)n < sizeof(body) && descriptor_checksum(body, sum) &&
             (size_t)snprintf(out, outlen, "%s#%s", body, sum) < outlen;
    secure_zero(body, sizeof(body));
    return ok;
}

int factory_key_reserve_next(persist_t *db, const secp256k1_context *ctx,
                             const unsigned char root_seckey32[32],
                             const unsigned char *pinned_ctx33,
                             unsigned char out_seckey32[32], uint32_t *out_index) {
    if (!db || !ctx || !root_seckey32 || !out_seckey32) return 0;
    if (!pinned_ctx33 || factory_key_ctx_is_zero(pinned_ctx33)) {
        fprintf(stderr, "factory key: a new factory key needs the LSP's key pinned "
                "(--lsp-pubkey)\n");
        return 0;
    }
    int own = !persist_in_transaction(db);
    if (own && !persist_begin(db)) return 0;
    uint64_t next = 0;
    unsigned char pk[33];
    if (!fk_next_index(db, &next) || next > UINT32_MAX) goto fail;
    uint32_t idx = (uint32_t)next;
    while (!factory_key_derive_pubkey(ctx, pk, root_seckey32, pinned_ctx33, idx)) {
        if (idx == UINT32_MAX) goto fail;
        idx++;
    }
    if (!persist_factory_key_save(db, idx, pinned_ctx33, pk, -1, FACTORY_KEY_STATE_RESERVED) ||
        !persist_save_counter(db, FACTORY_KEY_COUNTER, (uint64_t)idx + 1) ||
        !factory_key_derive(ctx, out_seckey32, root_seckey32, pinned_ctx33, idx))
        goto fail;
    if (own && !persist_commit(db)) {
        secure_zero(out_seckey32, 32);
        return 0;
    }
    if (out_index) *out_index = idx;
    return 1;
fail:
    if (own) persist_rollback(db);
    secure_zero(out_seckey32, 32);
    return 0;
}

int factory_key_derive_stored(persist_t *db, const secp256k1_context *ctx,
                              const unsigned char root_seckey32[32], uint32_t index,
                              unsigned char out_seckey32[32]) {
    if (!db || !ctx || !root_seckey32 || !out_seckey32) return 0;
    unsigned char rctx[33], rpk[33], pk[33];
    char state[16];
    if (persist_factory_key_get_row(db, index, rctx, rpk, state) != 1) return 0;
    if (!factory_key_derive_pubkey(ctx, pk, root_seckey32, rctx, index) ||
        memcmp(pk, rpk, 33) != 0)
        return 0;
    return factory_key_derive(ctx, out_seckey32, root_seckey32, rctx, index);
}
