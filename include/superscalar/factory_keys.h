#ifndef SUPERSCALAR_FACTORY_KEYS_H
#define SUPERSCALAR_FACTORY_KEYS_H

/* Per-factory client keys.
 *
 * A client signs each factory with its own key, derived from its root
 * (identity) secret:
 *
 *   k_i = tagged_hash("SuperScalar/factory-key/v1",
 *                     root_seckey || lsp_ctx33 || u32_be(i))
 *
 * lsp_ctx33 is the LSP's pinned static pubkey.  A new key is only reserved
 * with a pinned LSP key; keys derived before that rule used 33 zero bytes,
 * and recovery still tries that context.  The derivation is hardened: k_i
 * reveals nothing about the root secret or about any other k_j, so handing
 * one factory key to the LSP never exposes the identity key or another
 * factory.  The root key stays the client's identity (HELLO / RECONNECT) and
 * is never a factory key.
 *
 * i comes from a counter in the client DB that only moves forward.  A
 * reserved index (sent to the LSP but not yet in a signed factory) is reused
 * across restarts so the funding address stays the same; an index is never
 * handed out again once it has been used or released. */

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include "superscalar/persist.h"

#define FACTORY_KEY_TAG             "SuperScalar/factory-key/v1"
#define FACTORY_KEY_SCAN_WINDOW     1000u
/* After a recovery by scan, the next index skips ahead by a random amount in
   [FACTORY_KEY_SKIP_MIN, FACTORY_KEY_SKIP_MAX) so an index whose use was
   lost with the DB is not handed out again by accident. */
#define FACTORY_KEY_SKIP_MIN        (1u << 20)
#define FACTORY_KEY_SKIP_MAX        (1u << 31)

/* id_counters row holding the next unused index. */
#define FACTORY_KEY_COUNTER         "factory_key_next"

/* factory_keys.state values */
#define FACTORY_KEY_STATE_RESERVED  "reserved"   /* sent to the LSP, no factory yet */
#define FACTORY_KEY_STATE_ACTIVE    "active"     /* used by a persisted factory */
#define FACTORY_KEY_STATE_RELEASED  "released"   /* handed over to the LSP: never reuse */
#define FACTORY_KEY_STATE_RETIRED   "retired"    /* a factory we moved out of, not released */

typedef enum {
    FACTORY_KEY_FRESH = 0,      /* new index reserved */
    FACTORY_KEY_RELOADED = 1,   /* reserved/active index found in the DB */
    FACTORY_KEY_RECOVERED = 2,  /* DB has a factory but no key row: found by scan */
    FACTORY_KEY_LEGACY = 3,     /* DB factory was created with the identity key */
} factory_key_source_t;

/* k_i into out_seckey32.  Returns 0 if the hash is not a valid secret key
   (probability ~2^-128) or on bad arguments. */
int factory_key_derive(const secp256k1_context *ctx, unsigned char out_seckey32[32],
                       const unsigned char root_seckey32[32],
                       const unsigned char lsp_ctx33[33], uint32_t index);

/* Compressed pubkey of k_i. */
int factory_key_derive_pubkey(const secp256k1_context *ctx, unsigned char out33[33],
                              const unsigned char root_seckey32[32],
                              const unsigned char lsp_ctx33[33], uint32_t index);

/* lsp_ctx33 from an optional pinned LSP pubkey (NULL -> 33 zero bytes). */
void factory_key_lsp_ctx(const secp256k1_context *ctx, const secp256k1_pubkey *lsp_pk,
                         unsigned char out33[33]);

/* 1 if CTX33 is the zero context (no LSP key bound). */
int factory_key_ctx_is_zero(const unsigned char ctx33[33]);

/* Seed-only recovery: the first index in [0, window) whose pubkey is one of
   targets33[0..n).  Returns 1 and sets *found_index / *found_target. */
int factory_key_scan(const secp256k1_context *ctx, const unsigned char root_seckey32[32],
                     const unsigned char lsp_ctx33[33],
                     const unsigned char (*targets33)[33], size_t n_targets,
                     uint32_t window, uint32_t *found_index, size_t *found_target);

/* Random skip in [FACTORY_KEY_SKIP_MIN, FACTORY_KEY_SKIP_MAX).  0 on RNG failure. */
uint32_t factory_key_recovery_skip(void);

/* Read-only: find this client's factory key in DB.  Never writes.
     - a reserved/active key row: re-derive it (with the row's context) and
       check its pubkey (RELOADED);
     - else a stored factory: LEGACY if one of its participants is the
       identity key; otherwise scan [0, FACTORY_KEY_SCAN_WINDOW) with the
       pinned context (PINNED_CTX33, may be NULL) and then the zero context
       (RECOVERED).  A match on an index that already has a key row (used or
       released before) is refused.
   Returns 1 with the secret, index, source and the context used (out_ctx33
   may be NULL); 0 if the DB holds neither a key row nor a factory; -1 on a
   DB error or anything refused (logged). */
int factory_key_lookup(persist_t *db, const secp256k1_context *ctx,
                       const unsigned char root_seckey32[32],
                       const unsigned char *pinned_ctx33,
                       unsigned char out_seckey32[32], uint32_t *out_index,
                       factory_key_source_t *out_source, unsigned char out_ctx33[33]);

/* Choose this client's factory key at startup: factory_key_lookup, then
   record a RECOVERED key (row + counter moved past it by a random skip), or,
   when nothing is stored, reserve the next index.  A new reservation needs a
   pinned, non-zero LSP context.  Reads and writes run in one transaction.
   db may be NULL (index 0, nothing persisted; zero context if unpinned).
   Returns 1 with the secret in out_seckey32 (the root key for LEGACY), 0 on
   any error (logged; the caller must not continue). */
int factory_key_select(persist_t *db, const secp256k1_context *ctx,
                       const unsigned char root_seckey32[32],
                       const unsigned char *pinned_ctx33,
                       unsigned char out_seckey32[32], uint32_t *out_index,
                       factory_key_source_t *out_source);

/* Refuse a participant list that would make this client sign with a key the
   LSP may know: my_slot must hold my_factory_pk; no other slot may hold
   my_factory_pk or the identity key; no slot may hold a key this client has
   released (db may be NULL; a DB read error refuses).  Returns 1 if
   acceptable; otherwise 0 with a short reason in why (may be NULL). */
int factory_key_check_participants(const secp256k1_context *ctx, persist_t *db,
                                   const secp256k1_pubkey *identity_pk,
                                   const secp256k1_pubkey *my_factory_pk,
                                   size_t my_slot,
                                   const secp256k1_pubkey *participants, size_t n,
                                   const char **why);

/* --- Spending payouts ---
   A client's cooperative-close output pays P2TR(k_i) untweaked
   (descriptor rawtr(KEY)); its distribution-TX output pays the BIP-86
   tweaked key (descriptor tr(KEY)). */

/* WIF of SECKEY32 (compressed); MAINNET selects the 0x80 prefix, else 0xef. */
int factory_key_wif(const unsigned char seckey32[32], int mainnet, char *out, size_t outlen);

/* BIP-380 descriptor checksum (8 characters + NUL). */
int descriptor_checksum(const char *desc, char out9[9]);

/* "rawtr(WIF)#checksum" (RAW = 1) or "tr(WIF)#checksum" (RAW = 0). */
int factory_key_descriptor(const unsigned char seckey32[32], int mainnet, int raw,
                           char *out, size_t outlen);

/* Reserve a NEW index (never the current one) for a replacement factory,
   bound to the pinned LSP context; committed before returning.  Returns 1
   with the secret and index. */
int factory_key_reserve_next(persist_t *db, const secp256k1_context *ctx,
                             const unsigned char root_seckey32[32],
                             const unsigned char *pinned_ctx33,
                             unsigned char out_seckey32[32], uint32_t *out_index);

/* The secret of the stored key row INDEX (re-derived with the row's context
   and checked against its pubkey).  Read-only. */
int factory_key_derive_stored(persist_t *db, const secp256k1_context *ctx,
                              const unsigned char root_seckey32[32], uint32_t index,
                              unsigned char out_seckey32[32]);

#endif /* SUPERSCALAR_FACTORY_KEYS_H */
