/*
 * bolt4_failure.c — BOLT #4 onion failure message parser
 */

#include "superscalar/bolt4_failure.h"
#include <string.h>
#include <stddef.h>

static uint16_t read_u16_be(const unsigned char *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_u32_be(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static uint64_t read_u64_be(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* -----------------------------------------------------------------------
 * Parse a channel_update from failure_data.
 * Format: len(2BE) + channel_update_bytes(len)
 * Returns bytes consumed (2 + len), 0 on error.
 * --------------------------------------------------------------------- */
static size_t parse_channel_update(const unsigned char *data, size_t avail,
                                    bolt4_failure_t *out)
{
    if (avail < 2) return 0;
    uint16_t cu_len = read_u16_be(data);
    if ((size_t)cu_len + 2 > avail) return 0;
    if (cu_len > BOLT4_CHANNEL_UPDATE_MAX) cu_len = BOLT4_CHANNEL_UPDATE_MAX;
    if (cu_len > 0) {
        memcpy(out->channel_update_buf, data + 2, cu_len);
        out->channel_update_len = cu_len;
    }
    return 2 + cu_len;
}

/* -----------------------------------------------------------------------
 * Parse
 * --------------------------------------------------------------------- */

int bolt4_failure_parse(const unsigned char *plaintext, size_t plaintext_len,
                         bolt4_failure_t *out)
{
    if (!plaintext || plaintext_len < 2 || !out) return 0;

    memset(out, 0, sizeof(*out));

    out->failure_code = read_u16_be(plaintext);

    /* Extract flag bits */
    out->is_bad_onion    = (out->failure_code & BOLT4_FAIL_BADONION) ? 1 : 0;
    out->is_permanent    = (out->failure_code & BOLT4_FAIL_PERM)     ? 1 : 0;
    out->is_node_failure = (out->failure_code & BOLT4_FAIL_NODE)     ? 1 : 0;
    out->has_channel_update = (out->failure_code & BOLT4_FAIL_UPDATE)? 1 : 0;

    const unsigned char *data    = plaintext + 2;
    size_t               data_len = (plaintext_len >= 2) ? plaintext_len - 2 : 0;
    size_t               pos      = 0;

    /* Parse failure_data based on code */
    switch (out->failure_code) {

    /* Bad-onion: sha256_of_onion (32 bytes) */
    case BOLT4_INVALID_ONION_VERSION:
    case BOLT4_INVALID_ONION_HMAC:
    case BOLT4_INVALID_ONION_KEY:
    case BOLT4_INVALID_ONION_BLINDING:
        if (data_len - pos >= 32) {
            memcpy(out->bad_onion_sha256, data + pos, 32);
            out->has_bad_onion_sha = 1;
            pos += 32;
        }
        break;

    /* UPDATE only: channel_update */
    case BOLT4_TEMPORARY_CHANNEL_FAILURE:
    case BOLT4_EXPIRY_TOO_SOON: {
        size_t n = parse_channel_update(data + pos, data_len - pos, out);
        pos += n;
        break;
    }

    /* disabled_flags(2) + channel_update */
    case BOLT4_CHANNEL_DISABLED:
        if (data_len - pos >= 2) {
            out->disabled_flags     = read_u16_be(data + pos);
            out->has_disabled_flags = 1;
            pos += 2;
        }
        {
            size_t n = parse_channel_update(data + pos, data_len - pos, out);
            pos += n;
        }
        break;

    /* htlc_msat(8) + channel_update */
    case BOLT4_AMOUNT_BELOW_MINIMUM:
    case BOLT4_FEE_INSUFFICIENT:
        if (data_len - pos >= 8) {
            out->htlc_msat     = read_u64_be(data + pos);
            out->has_htlc_msat = 1;
            pos += 8;
        }
        {
            size_t n = parse_channel_update(data + pos, data_len - pos, out);
            pos += n;
        }
        break;

    /* cltv_expiry(4) + channel_update */
    case BOLT4_INCORRECT_CLTV_EXPIRY:
        if (data_len - pos >= 4) {
            out->cltv_expiry     = read_u32_be(data + pos);
            out->has_cltv_expiry = 1;
            pos += 4;
        }
        {
            size_t n = parse_channel_update(data + pos, data_len - pos, out);
            pos += n;
        }
        break;

    /* INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS: htlc_msat(8) + height(4) */
    case BOLT4_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
        if (data_len - pos >= 8) {
            out->htlc_msat     = read_u64_be(data + pos);
            out->has_htlc_msat = 1;
            pos += 8;
        }
        if (data_len - pos >= 4) {
            out->block_height     = read_u32_be(data + pos);
            out->has_block_height = 1;
            pos += 4;
        }
        break;

    /* FINAL_INCORRECT_HTLC_AMOUNT: htlc_msat(8) */
    case BOLT4_FINAL_INCORRECT_HTLC_AMOUNT:
        if (data_len - pos >= 8) {
            out->htlc_msat     = read_u64_be(data + pos);
            out->has_htlc_msat = 1;
            pos += 8;
        }
        break;

    /* FINAL_INCORRECT_CLTV_EXPIRY: cltv_expiry(4) */
    case BOLT4_FINAL_INCORRECT_CLTV_EXPIRY:
        if (data_len - pos >= 4) {
            out->cltv_expiry     = read_u32_be(data + pos);
            out->has_cltv_expiry = 1;
            pos += 4;
        }
        break;

    /* No additional data for these */
    case BOLT4_PERMANENT_CHANNEL_FAILURE:
    case BOLT4_REQUIRED_CHANNEL_FEATURE_MISSING:
    case BOLT4_UNKNOWN_NEXT_PEER:
    case BOLT4_PERMANENT_NODE_FAILURE:
    case BOLT4_TEMPORARY_NODE_FAILURE:
    case BOLT4_REQUIRED_NODE_FEATURE_MISSING:
    case BOLT4_UNKNOWN_PAYMENT_HASH:
    case BOLT4_FINAL_EXPIRY_TOO_SOON:
    default:
        break;
    }

    (void)pos; /* suppress unused warning */
    return 1;
}

/* -----------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

int bolt4_failure_is_permanent(const bolt4_failure_t *f)
{
    if (!f) return 0;
    return f->is_permanent;
}

int bolt4_failure_is_node_failure(const bolt4_failure_t *f)
{
    if (!f) return 0;
    return f->is_node_failure;
}

int bolt4_failure_is_bad_onion(const bolt4_failure_t *f)
{
    if (!f) return 0;
    return f->is_bad_onion;
}

int bolt4_failure_has_update(const bolt4_failure_t *f)
{
    if (!f) return 0;
    return f->has_channel_update && f->channel_update_len > 0;
}

/* -----------------------------------------------------------------------
 * Human-readable failure strings
 * --------------------------------------------------------------------- */

const char *bolt4_failure_str(uint16_t code)
{
    switch (code) {
    case BOLT4_INVALID_ONION_VERSION:          return "invalid_onion_version";
    case BOLT4_INVALID_ONION_HMAC:             return "invalid_onion_hmac";
    case BOLT4_INVALID_ONION_KEY:              return "invalid_onion_key";
    case BOLT4_INVALID_ONION_BLINDING:         return "invalid_onion_blinding";
    case BOLT4_TEMPORARY_CHANNEL_FAILURE:      return "temporary_channel_failure";
    case BOLT4_PERMANENT_CHANNEL_FAILURE:      return "permanent_channel_failure";
    case BOLT4_REQUIRED_CHANNEL_FEATURE_MISSING: return "required_channel_feature_missing";
    case BOLT4_UNKNOWN_NEXT_PEER:              return "unknown_next_peer";
    case BOLT4_AMOUNT_BELOW_MINIMUM:           return "amount_below_minimum";
    case BOLT4_FEE_INSUFFICIENT:               return "fee_insufficient";
    case BOLT4_INCORRECT_CLTV_EXPIRY:          return "incorrect_cltv_expiry";
    case BOLT4_EXPIRY_TOO_SOON:                return "expiry_too_soon";
    case BOLT4_CHANNEL_DISABLED:               return "channel_disabled";
    case BOLT4_PERMANENT_NODE_FAILURE:         return "permanent_node_failure";
    case BOLT4_TEMPORARY_NODE_FAILURE:         return "temporary_node_failure";
    case BOLT4_REQUIRED_NODE_FEATURE_MISSING:  return "required_node_feature_missing";
    case BOLT4_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS: return "incorrect_or_unknown_payment_details";
    case BOLT4_UNKNOWN_PAYMENT_HASH:           return "unknown_payment_hash";
    case BOLT4_FINAL_EXPIRY_TOO_SOON:          return "final_expiry_too_soon";
    case BOLT4_FINAL_INCORRECT_CLTV_EXPIRY:    return "final_incorrect_cltv_expiry";
    case BOLT4_FINAL_INCORRECT_HTLC_AMOUNT:    return "final_incorrect_htlc_amount";
    default:                                   return "unknown_failure_code";
    }
}
