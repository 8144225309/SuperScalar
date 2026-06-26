/* persist_crypto.c — at-rest field encryption for lsp.db (#327, "LND/Core model").
 *
 * Rationale (matches Bitcoin Core / CLN / LND practice): protect the secrets,
 * derive a Data Encryption Key (DEK) from the operator root key, and seal the
 * sensitive columns in place with the existing ChaCha20-Poly1305 AEAD. No new
 * dependency (OpenSSL + aead and hkdf helpers are already linked). Metadata stays in the
 * clear and is protected by 0600 perms (#327) + operator full-disk encryption,
 * exactly as CLN/LND do (they do NOT encrypt the whole DB).
 *
 * Sealed TEXT  columns store  "ssenc1:" + hex(nonce[12] | tag[16] | ct).
 * Sealed BLOB  columns store  "SSE1"(4) | nonce[12] | tag[16] | ct.
 * The distinct prefixes let reads transparently pass through legacy plaintext,
 * which is what makes the v36->v37 migration (and mixed states) safe.
 *
 * Engagement is key-gated: encryption only activates when the operator passes
 * --encrypt-db (auto-required on mainnet). Keyless regtest/tests stay plaintext,
 * so the existing unit + regtest suites are unaffected.
 */
#include "superscalar/persist.h"
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- primitives already in the library (see crypto_aead.c / hkdf) ---------- */
extern void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                         const unsigned char *ikm, size_t ikm_len);
extern void hkdf_expand(unsigned char *okm, size_t okm_len, const unsigned char prk[32],
                        const unsigned char *info, size_t info_len);
extern int aead_encrypt(unsigned char *ciphertext, unsigned char tag[16],
                        const unsigned char *plaintext, size_t pt_len,
                        const unsigned char *aad, size_t aad_len,
                        const unsigned char key[32], const unsigned char nonce[12]);
extern int aead_decrypt(unsigned char *plaintext,
                        const unsigned char *ciphertext, size_t ct_len,
                        const unsigned char tag[16],
                        const unsigned char *aad, size_t aad_len,
                        const unsigned char key[32], const unsigned char nonce[12]);

#define TXT_PREFIX     "ssenc1:"
#define TXT_PREFIX_LEN 7
#define BLOB_MAGIC     "SSE1"
#define BLOB_MAGIC_LEN 4
#define HDR_LEN        28          /* nonce(12) + tag(16) */

/* ---- small local helpers --------------------------------------------------- */
static void zero(void *p, size_t n) { volatile unsigned char *v = p; while (n--) *v++ = 0; }

static int rng12(unsigned char *n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t r = fread(n, 1, 12, f);
    fclose(f);
    return r == 12;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static char *bytes_to_hex(const unsigned char *b, size_t n) {
    static const char hx[] = "0123456789abcdef";
    char *s = malloc(n * 2 + 1);
    if (!s) return NULL;
    for (size_t i = 0; i < n; i++) { s[i*2] = hx[b[i] >> 4]; s[i*2+1] = hx[b[i] & 0xf]; }
    s[n * 2] = '\0';
    return s;
}
static int hex_to_bytes(const char *s, size_t slen, unsigned char *out, size_t cap, size_t *n) {
    if (slen % 2) return 0;
    size_t b = slen / 2;
    if (b > cap) return 0;
    for (size_t i = 0; i < b; i++) {
        int hi = hexval((unsigned char)s[i*2]), lo = hexval((unsigned char)s[i*2+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *n = b;
    return 1;
}

/* ---- DEK derivation -------------------------------------------------------- */
/* DEK = HKDF-SHA256(root_key) with a domain-separated salt+info, so the DB key
 * is independent of (and reveals nothing about) the LSP signing key itself. */
int persist_set_encryption_key(persist_t *p, const unsigned char root_key[32]) {
    if (!p || !root_key) return 0;
    unsigned char prk[32];
    hkdf_extract(prk, (const unsigned char *)"superscalar-db-dek-v1", 21, root_key, 32);
    hkdf_expand(p->dek, 32, prk, (const unsigned char *)"field-encryption-v1", 19);
    zero(prk, sizeof prk);
    p->enc_enabled = 1;
    return 1;
}

/* ---- TEXT seal / open ------------------------------------------------------ */
/* Returns a malloc'd string the caller must free. When encryption is off, this
 * is just strdup(plain) so callers are uniform. NULL in -> NULL out. */
char *persist_seal_text(persist_t *p, const char *plain) {
    if (!plain) return NULL;
    if (!p || !p->enc_enabled) return strdup(plain);
    size_t pl = strlen(plain);
    unsigned char nonce[12], tag[16];
    if (!rng12(nonce)) return NULL;
    unsigned char *ct = malloc(pl ? pl : 1);
    if (!ct) return NULL;
    if (!aead_encrypt(ct, tag, (const unsigned char *)plain, pl, NULL, 0, p->dek, nonce)) {
        free(ct); return NULL;
    }
    size_t blen = HDR_LEN + pl;
    unsigned char *blob = malloc(blen);
    if (!blob) { zero(ct, pl); free(ct); return NULL; }
    memcpy(blob, nonce, 12);
    memcpy(blob + 12, tag, 16);
    memcpy(blob + HDR_LEN, ct, pl);
    zero(ct, pl); free(ct);
    char *hex = bytes_to_hex(blob, blen);
    zero(blob, blen); free(blob);
    if (!hex) return NULL;
    char *out = malloc(TXT_PREFIX_LEN + strlen(hex) + 1);
    if (!out) { free(hex); return NULL; }
    memcpy(out, TXT_PREFIX, TXT_PREFIX_LEN);
    strcpy(out + TXT_PREFIX_LEN, hex);
    free(hex);
    return out;
}

/* Reverses persist_seal_text. Legacy plaintext (no prefix) is passed through.
 * *out is malloc'd (caller frees). Returns 0 on a real failure (ciphertext but
 * no/wrong key, or tag mismatch) so callers can refuse rather than corrupt. */
int persist_open_text(persist_t *p, const char *stored, char **out) {
    if (!stored) { *out = NULL; return 1; }
    if (strncmp(stored, TXT_PREFIX, TXT_PREFIX_LEN) != 0) {
        *out = strdup(stored);
        return *out ? 1 : 0;
    }
    if (!p || !p->enc_enabled) return 0;          /* sealed data but no key */
    const char *hex = stored + TXT_PREFIX_LEN;
    size_t hlen = strlen(hex);
    if (hlen % 2) return 0;
    size_t blen = hlen / 2;
    if (blen < HDR_LEN) return 0;
    unsigned char *blob = malloc(blen);
    if (!blob) return 0;
    size_t got = 0;
    if (!hex_to_bytes(hex, hlen, blob, blen, &got)) { free(blob); return 0; }
    size_t ctlen = blen - HDR_LEN;
    unsigned char *pt = malloc(ctlen + 1);
    if (!pt) { free(blob); return 0; }
    int ok = aead_decrypt(pt, blob + HDR_LEN, ctlen, blob + 12, NULL, 0, p->dek, blob);
    zero(blob, blen); free(blob);
    if (!ok) { free(pt); return 0; }
    pt[ctlen] = '\0';
    *out = (char *)pt;
    return 1;
}

/* ---- BLOB seal / open ------------------------------------------------------ */
/* *out malloc'd (caller frees), *out_len set. Encryption off -> verbatim copy. */
int persist_seal_blob(persist_t *p, const unsigned char *plain, size_t plain_len,
                      unsigned char **out, size_t *out_len) {
    if (!plain) { *out = NULL; *out_len = 0; return 1; }
    if (!p || !p->enc_enabled) {
        unsigned char *c = malloc(plain_len ? plain_len : 1);
        if (!c) return 0;
        memcpy(c, plain, plain_len);
        *out = c; *out_len = plain_len;
        return 1;
    }
    unsigned char nonce[12], tag[16];
    if (!rng12(nonce)) return 0;
    unsigned char *ct = malloc(plain_len ? plain_len : 1);
    if (!ct) return 0;
    if (!aead_encrypt(ct, tag, plain, plain_len, NULL, 0, p->dek, nonce)) { free(ct); return 0; }
    size_t blen = BLOB_MAGIC_LEN + HDR_LEN + plain_len;
    unsigned char *blob = malloc(blen);
    if (!blob) { zero(ct, plain_len); free(ct); return 0; }
    memcpy(blob, BLOB_MAGIC, BLOB_MAGIC_LEN);
    memcpy(blob + BLOB_MAGIC_LEN, nonce, 12);
    memcpy(blob + BLOB_MAGIC_LEN + 12, tag, 16);
    memcpy(blob + BLOB_MAGIC_LEN + HDR_LEN, ct, plain_len);
    zero(ct, plain_len); free(ct);
    *out = blob; *out_len = blen;
    return 1;
}

int persist_open_blob(persist_t *p, const unsigned char *stored, size_t stored_len,
                      unsigned char **out, size_t *out_len) {
    if (!stored) { *out = NULL; *out_len = 0; return 1; }
    if (stored_len < BLOB_MAGIC_LEN || memcmp(stored, BLOB_MAGIC, BLOB_MAGIC_LEN) != 0) {
        unsigned char *c = malloc(stored_len ? stored_len : 1);   /* legacy plaintext */
        if (!c) return 0;
        memcpy(c, stored, stored_len);
        *out = c; *out_len = stored_len;
        return 1;
    }
    if (!p || !p->enc_enabled) return 0;
    if (stored_len < BLOB_MAGIC_LEN + HDR_LEN) return 0;
    const unsigned char *nonce = stored + BLOB_MAGIC_LEN;
    const unsigned char *tag   = stored + BLOB_MAGIC_LEN + 12;
    const unsigned char *ct    = stored + BLOB_MAGIC_LEN + HDR_LEN;
    size_t ctlen = stored_len - BLOB_MAGIC_LEN - HDR_LEN;
    unsigned char *pt = malloc(ctlen ? ctlen : 1);
    if (!pt) return 0;
    int ok = aead_decrypt(pt, ct, ctlen, tag, NULL, 0, p->dek, nonce);
    if (!ok) { free(pt); return 0; }
    *out = pt; *out_len = ctlen;
    return 1;
}

/* ---- secret-column registry ----------------------------------------------- */
/* Single source of truth for which columns are sealed. The migration pass and
 * the completeness self-check both iterate this, so adding a column here is the
 * ONLY bookkeeping needed (plus wrapping that column's runtime accessor). */
typedef struct { const char *table, *idcol, *col; int is_blob; } secret_col_t;
static const secret_col_t SECRET_COLS[] = {
    /* The crown jewel: the HD wallet seed. A plaintext read of this row alone
       lets an attacker derive every wallet key and drain all funds — so it is
       sealed first and on its own (fully wrapped at runtime + tested).

       FAST-FOLLOW (same pattern, each needs its runtime accessor wrapped +
       an enc_version bump so existing rows re-migrate):
         revocation_secrets.secret, factory_revocation_secrets.secret,
         channels.local_{payment,delayed,revocation,htlc}_secret,
         revocation_releases.revocation_secret (BLOB).
       v0.3 (payment-privacy tier): preimage / payment_secret / stateless_nonce
       across htlcs/ptlcs/ln_invoices/local_pcs. */
    { "hd_wallet_state",            "id",         "seed_hex",                0 },
};
static const size_t N_SECRET_COLS = sizeof(SECRET_COLS) / sizeof(SECRET_COLS[0]);

/* Encrypt one column's existing plaintext rows in place (per-row, C-side). */
static int migrate_text_col(persist_t *p, const secret_col_t *sc) {
    char q[256];
    snprintf(q, sizeof q, "SELECT %s, %s FROM %s WHERE %s IS NOT NULL AND %s NOT LIKE '%s%%';",
             sc->idcol, sc->col, sc->table, sc->col, sc->col, TXT_PREFIX);
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(p->db, q, -1, &sel, NULL) != SQLITE_OK) return 0;
    /* buffer rows first (can't UPDATE while SELECT cursor is open on same table) */
    typedef struct { sqlite3_int64 id; char *val; } row_t;
    row_t *rows = NULL; size_t n = 0, cap = 0;
    int ok = 1;
    while (sqlite3_step(sel) == SQLITE_ROW) {
        const char *v = (const char *)sqlite3_column_text(sel, 1);
        if (!v) continue;
        if (n == cap) { cap = cap ? cap * 2 : 16; row_t *tmp = realloc(rows, cap * sizeof(row_t)); if (!tmp) { ok = 0; break; } rows = tmp; }
        rows[n].id = sqlite3_column_int64(sel, 0);
        rows[n].val = strdup(v);
        n++;
    }
    sqlite3_finalize(sel);
    for (size_t i = 0; ok && i < n; i++) {
        char *sealed = persist_seal_text(p, rows[i].val);
        if (!sealed) { ok = 0; break; }
        char u[256];
        snprintf(u, sizeof u, "UPDATE %s SET %s=? WHERE %s=?;", sc->table, sc->col, sc->idcol);
        sqlite3_stmt *up = NULL;
        if (sqlite3_prepare_v2(p->db, u, -1, &up, NULL) != SQLITE_OK) { free(sealed); ok = 0; break; }
        sqlite3_bind_text(up, 1, sealed, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(up, 2, rows[i].id);
        if (sqlite3_step(up) != SQLITE_DONE) ok = 0;
        sqlite3_finalize(up);
        free(sealed);
    }
    for (size_t i = 0; i < n; i++) { if (rows[i].val) { zero(rows[i].val, strlen(rows[i].val)); free(rows[i].val); } }
    free(rows);
    return ok;
}

static int migrate_blob_col(persist_t *p, const secret_col_t *sc) {
    char q[256];
    snprintf(q, sizeof q, "SELECT %s, %s FROM %s WHERE %s IS NOT NULL;",
             sc->idcol, sc->col, sc->table, sc->col);
    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(p->db, q, -1, &sel, NULL) != SQLITE_OK) return 0;
    typedef struct { sqlite3_int64 id; unsigned char *val; size_t len; } row_t;
    row_t *rows = NULL; size_t n = 0, cap = 0;
    int ok = 1;
    while (sqlite3_step(sel) == SQLITE_ROW) {
        const void *v = sqlite3_column_blob(sel, 1);
        int vl = sqlite3_column_bytes(sel, 1);
        if (!v || vl <= 0) continue;
        /* skip already-sealed */
        if (vl >= BLOB_MAGIC_LEN && memcmp(v, BLOB_MAGIC, BLOB_MAGIC_LEN) == 0) continue;
        if (n == cap) { cap = cap ? cap * 2 : 16; row_t *tmp = realloc(rows, cap * sizeof(row_t)); if (!tmp) { ok = 0; break; } rows = tmp; }
        rows[n].id = sqlite3_column_int64(sel, 0);
        rows[n].val = malloc((size_t)vl);
        if (!rows[n].val) { ok = 0; break; }
        memcpy(rows[n].val, v, (size_t)vl);
        rows[n].len = (size_t)vl;
        n++;
    }
    sqlite3_finalize(sel);
    for (size_t i = 0; ok && i < n; i++) {
        unsigned char *sealed = NULL; size_t slen = 0;
        if (!persist_seal_blob(p, rows[i].val, rows[i].len, &sealed, &slen)) { ok = 0; break; }
        char u[256];
        snprintf(u, sizeof u, "UPDATE %s SET %s=? WHERE %s=?;", sc->table, sc->col, sc->idcol);
        sqlite3_stmt *up = NULL;
        if (sqlite3_prepare_v2(p->db, u, -1, &up, NULL) != SQLITE_OK) { free(sealed); ok = 0; break; }
        sqlite3_bind_blob(up, 1, sealed, (int)slen, SQLITE_TRANSIENT);
        sqlite3_bind_int64(up, 2, rows[i].id);
        if (sqlite3_step(up) != SQLITE_DONE) ok = 0;
        sqlite3_finalize(up);
        free(sealed);
    }
    for (size_t i = 0; i < n; i++) { if (rows[i].val) { zero(rows[i].val, rows[i].len); free(rows[i].val); } }
    free(rows);
    return ok;
}

/* ---- apply: migrate + key-verification ------------------------------------ */
/* Called after persist_open + persist_set_encryption_key, before any secret is
 * read. On a fresh/plaintext DB it seals existing rows and writes a verification
 * token; on an already-encrypted DB it verifies the DEK (wrong passphrase ->
 * fail closed, never corrupt). Returns 1 on success. */
int persist_apply_encryption(persist_t *p) {
    if (!p || !p->db) return 0;
    if (!p->enc_enabled) return 1;   /* nothing to do without a key */

    /* read the marker */
    sqlite3_stmt *st = NULL;
    int have_token = 0;
    unsigned char token[64]; size_t token_len = 0;
    if (sqlite3_prepare_v2(p->db, "SELECT verify FROM db_encryption WHERE id=1;", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const void *v = sqlite3_column_blob(st, 0);
            int vl = sqlite3_column_bytes(st, 0);
            if (v && vl > 0 && (size_t)vl <= sizeof token) { memcpy(token, v, (size_t)vl); token_len = (size_t)vl; have_token = 1; }
        }
        sqlite3_finalize(st);
    }

    static const char VERIFY_PLAINTEXT[] = "superscalar-db-verify-v1";

    if (have_token) {
        /* verify the DEK against the stored token */
        unsigned char *pt = NULL; size_t ptlen = 0;
        if (!persist_open_blob(p, token, token_len, &pt, &ptlen)) {
            fprintf(stderr, "persist: DB is encrypted but the key did not verify "
                            "(wrong passphrase/keyfile?) — refusing to open.\n");
            return 0;
        }
        int match = (ptlen == sizeof(VERIFY_PLAINTEXT) - 1) &&
                    memcmp(pt, VERIFY_PLAINTEXT, ptlen) == 0;
        if (pt) { zero(pt, ptlen); free(pt); }
        if (!match) {
            fprintf(stderr, "persist: DB encryption verification token mismatch — refusing to open.\n");
            return 0;
        }
        return 1;
    }

    /* No token yet: migrate existing plaintext rows + write the token, atomically. */
    int own_txn = !persist_in_transaction(p);
    if (own_txn && !persist_begin(p)) return 0;
    int ok = 1;
    for (size_t i = 0; ok && i < N_SECRET_COLS; i++) {
        ok = SECRET_COLS[i].is_blob ? migrate_blob_col(p, &SECRET_COLS[i])
                                    : migrate_text_col(p, &SECRET_COLS[i]);
        if (!ok) fprintf(stderr, "persist: encryption migration failed at %s.%s\n",
                         SECRET_COLS[i].table, SECRET_COLS[i].col);
    }
    if (ok) {
        unsigned char *tok = NULL; size_t toklen = 0;
        ok = persist_seal_blob(p, (const unsigned char *)VERIFY_PLAINTEXT,
                               sizeof(VERIFY_PLAINTEXT) - 1, &tok, &toklen);
        if (ok) {
            sqlite3_stmt *ins = NULL;
            if (sqlite3_prepare_v2(p->db,
                    "INSERT INTO db_encryption (id, enabled, kdf, verify) VALUES (1,1,'hkdf-sha256/chacha20-poly1305',?) "
                    "ON CONFLICT(id) DO UPDATE SET enabled=1, kdf=excluded.kdf, verify=excluded.verify;",
                    -1, &ins, NULL) == SQLITE_OK) {
                sqlite3_bind_blob(ins, 1, tok, (int)toklen, SQLITE_TRANSIENT);
                ok = (sqlite3_step(ins) == SQLITE_DONE);
                sqlite3_finalize(ins);
            } else ok = 0;
        }
        free(tok);
    }
    if (own_txn) { if (ok) ok = persist_commit(p); else persist_rollback(p); }
    if (ok) fprintf(stderr, "persist: at-rest field encryption active (%zu secret columns sealed).\n", N_SECRET_COLS);
    return ok;
}

/* True if the on-disk DB carries the encryption marker (used to refuse a keyless
 * open of an encrypted DB). */
int persist_db_is_encrypted(persist_t *p) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *st = NULL;
    int enc = 0;
    if (sqlite3_prepare_v2(p->db, "SELECT enabled FROM db_encryption WHERE id=1;", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) enc = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return enc;
}
