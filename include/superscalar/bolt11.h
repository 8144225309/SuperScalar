/*
 * bolt11.h — BOLT #11 invoice decode/encode
 *
 * Supports lnbc/lnbs/lntb/lnbcrt prefixes (mainnet/signet/testnet/regtest).
 * Mandatory since BOLT #11 v1.1: payment_secret in tagged field.
 *
 * Spec: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
 * Reference: CLN common/bolt11.c, LDK lightning-invoice crate.
 */

#ifndef SUPERSCALAR_BOLT11_H
#define SUPERSCALAR_BOLT11_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

#define BOLT11_MAX_DESCRIPTION  640
#define BOLT11_MAX_ROUTE_HINTS  8
#define BOLT11_MAX_HOPS_PER_HINT 8

/* Per-hop route hint (tagged field r) */
typedef struct {
    unsigned char pubkey[33];
    uint64_t      short_channel_id;
    uint32_t      fee_base_msat;
    uint32_t      fee_ppm;
    uint16_t      cltv_expiry_delta;
} bolt11_hop_hint_t;

typedef struct {
    bolt11_hop_hint_t hops[BOLT11_MAX_HOPS_PER_HINT];
    int               n_hops;
} bolt11_route_hint_t;

/* Feature bits (BOLT #9) relevant to BOLT #11 invoices */
#define BOLT11_FEATURE_VAR_ONION       8    /* TLV onion format (mandatory ~2019) */
#define BOLT11_FEATURE_PAYMENT_SECRET  14   /* payment_secret (mandatory 2021) */
#define BOLT11_FEATURE_BASIC_MPP       16   /* basic MPP (optional) */
#define BOLT11_FEATURE_AMP             30   /* AMP (optional) */

typedef struct {
    char     network[8];            /* "bc", "bs", "tb", "bcrt" */
    uint64_t amount_msat;           /* 0 = any amount */
    uint32_t timestamp;             /* Unix timestamp */
    uint32_t expiry;                /* default 3600 seconds */
    unsigned char payment_hash[32];
    unsigned char payment_secret[32]; /* mandatory since BOLT #11 v1.1 */
    char     description[BOLT11_MAX_DESCRIPTION]; /* or description_hash */
    unsigned char description_hash[32];
    unsigned char payee_pubkey[33]; /* recovered from signature if absent */
    bolt11_route_hint_t hints[BOLT11_MAX_ROUTE_HINTS];
    int      n_hints;
    uint16_t features;
    int      has_payment_secret;
    int      has_amount;
    int      has_description_hash;  /* 1 if description_hash used, 0 if description text */
    int      min_final_cltv_expiry; /* tagged field c; default 18 */
    /* Tagged field 27: payment_metadata (used for Level-2 stateless nonce) */
    unsigned char metadata[64];
    size_t        metadata_len;
    int           has_metadata;
} bolt11_invoice_t;

/*
 * Decode a bech32-encoded BOLT #11 invoice string.
 * invoice_str: null-terminated "lnbc..." / "lnbs..." string.
 * out: filled on success.
 * ctx: secp256k1 context with VERIFY capability (for sig recovery).
 * Returns 1 on success, 0 on parse/validation error.
 */
int bolt11_decode(secp256k1_context *ctx,
                  const char *invoice_str,
                  bolt11_invoice_t *out);

/*
 * Encode a bolt11_invoice_t to a bech32 string.
 * node_privkey: 32-byte private key used to sign the invoice.
 * ctx: secp256k1 context with SIGN capability.
 * out: buffer for the encoded string.
 * out_cap: size of out buffer (at least 1024 bytes recommended).
 * Returns 1 on success, 0 on error.
 */
int bolt11_encode(const bolt11_invoice_t *inv,
                  const unsigned char node_privkey[32],
                  secp256k1_context *ctx,
                  char *out, size_t out_cap);

#endif /* SUPERSCALAR_BOLT11_H */
