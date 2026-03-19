/*
 * payment_uri.c — BIP 21 Payment URI + Nostr Wallet Connect (NIP-47).
 *
 * Reference:
 *   BIP 21: github.com/bitcoin/bips bip-0021.mediawiki
 *   NIP-47: github.com/nostr-protocol/nips/blob/master/47.md
 *   Alby: getalby.com; Mutiny: github.com/MutinyWallet/mutiny-node
 */

#include "superscalar/payment_uri.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>

/* ---- URL decoding ---- */

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode URL-encoded string in-place, returns decoded length */
static size_t url_decode(const char *in, size_t in_len, char *out, size_t out_cap)
{
    size_t i = 0, j = 0;
    while (i < in_len && j + 1 < out_cap) {
        if (in[i] == '%' && i + 2 < in_len) {
            int hi = hex_digit(in[i+1]);
            int lo = hex_digit(in[i+2]);
            if (hi >= 0 && lo >= 0) {
                out[j++] = (char)((hi << 4) | lo);
                i += 3; continue;
            }
        }
        if (in[i] == '+') { out[j++] = ' '; i++; continue; }
        out[j++] = in[i++];
    }
    out[j] = '\0';
    return j;
}

/* Parse a single query parameter name=value from the query string.
 * Advances *pos past the parameter. Returns 1 if found, 0 at end. */
static int parse_next_param(const char *query, size_t *pos,
                              char *name_out, size_t name_cap,
                              char *val_out, size_t val_cap)
{
    size_t len = strlen(query);
    if (*pos >= len) return 0;
    /* Skip & separators */
    while (*pos < len && query[*pos] == '&') (*pos)++;
    if (*pos >= len) return 0;

    /* Find '=' */
    size_t eq = *pos;
    while (eq < len && query[eq] != '=' && query[eq] != '&') eq++;
    if (eq >= len || query[eq] == '&') {
        /* parameter without value */
        url_decode(query + *pos, eq - *pos, name_out, name_cap);
        val_out[0] = '\0';
        *pos = eq;
        return 1;
    }

    url_decode(query + *pos, eq - *pos, name_out, name_cap);
    eq++; /* skip '=' */

    /* Find end of value */
    size_t vend = eq;
    while (vend < len && query[vend] != '&') vend++;
    url_decode(query + eq, vend - eq, val_out, val_cap);
    *pos = vend;
    return 1;
}

/* ---- BIP 21 ---- */

/* Parse "amount" field: BTC decimal string → satoshis */
static uint64_t parse_btc_amount(const char *s)
{
    /* e.g. "0.001" = 100000 sat */
    uint64_t btc_int = 0, btc_frac = 0;
    int frac_digits = 0;
    const char *p = s;
    while (*p >= '0' && *p <= '9') btc_int = btc_int * 10 + (*p++ - '0');
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9' && frac_digits < 8) {
            btc_frac = btc_frac * 10 + (*p++ - '0');
            frac_digits++;
        }
        /* Pad to 8 decimal places */
        while (frac_digits < 8) { btc_frac *= 10; frac_digits++; }
    }
    return btc_int * 100000000ULL + btc_frac;
}

int payment_uri_parse(const char *uri, payment_uri_t *out)
{
    if (!uri || !out) return 0;
    memset(out, 0, sizeof(*out));

    /* Find scheme */
    const char *p = uri;
    if (strncasecmp(p, "bitcoin:", 8) != 0) return 0;
    p += 8;

    /* Extract address (before '?') */
    const char *qmark = strchr(p, '?');
    if (qmark) {
        size_t alen = (size_t)(qmark - p);
        if (alen >= sizeof(out->address)) alen = sizeof(out->address) - 1;
        memcpy(out->address, p, alen);
        out->address[alen] = '\0';
    } else {
        strncpy(out->address, p, sizeof(out->address) - 1);
        return 1; /* address-only URI */
    }

    /* Parse query parameters */
    const char *query = qmark + 1;
    size_t pos = 0;
    char name[64], val[PAYMENT_URI_INVOICE_MAX];
    while (parse_next_param(query, &pos, name, sizeof(name), val, sizeof(val))) {
        if (strcmp(name, "amount") == 0) {
            out->amount_sat = parse_btc_amount(val);
            out->has_amount = 1;
        } else if (strcmp(name, "label") == 0) {
            strncpy(out->label, val, sizeof(out->label) - 1);
        } else if (strcmp(name, "message") == 0) {
            strncpy(out->message, val, sizeof(out->message) - 1);
        } else if (strcmp(name, "lightning") == 0) {
            strncpy(out->lightning, val, sizeof(out->lightning) - 1);
            out->has_lightning = 1;
        } else if (strcmp(name, "lno") == 0) {
            strncpy(out->offer, val, sizeof(out->offer) - 1);
            out->has_offer = 1;
        }
    }
    return 1;
}

int payment_uri_build(char *out, size_t out_cap,
                       const char *address,
                       const char *invoice,
                       uint64_t amount_sat,
                       const char *label)
{
    if (!out || out_cap == 0) return 0;

    char tmp[4096];
    int p = 0;

    /* Scheme + address */
    if (address && *address)
        p += snprintf(tmp + p, sizeof(tmp) - (size_t)p, "bitcoin:%s", address);
    else
        p += snprintf(tmp + p, sizeof(tmp) - (size_t)p, "bitcoin:");

    char sep = '?';
    if (amount_sat > 0) {
        /* Convert satoshis to BTC decimal (8 decimal places) */
        uint64_t btc_int = amount_sat / 100000000ULL;
        uint64_t btc_frac = amount_sat % 100000000ULL;
        p += snprintf(tmp + p, sizeof(tmp) - (size_t)p,
                      "%camount=%llu.%08llu", sep,
                      (unsigned long long)btc_int,
                      (unsigned long long)btc_frac);
        sep = '&';
    }
    if (label && *label) {
        p += snprintf(tmp + p, sizeof(tmp) - (size_t)p, "%clabel=%s", sep, label);
        sep = '&';
    }
    if (invoice && *invoice) {
        p += snprintf(tmp + p, sizeof(tmp) - (size_t)p, "%clightning=%s", sep, invoice);
        sep = '&';
    }

    if (p < 0 || (size_t)p >= out_cap) return 0;
    memcpy(out, tmp, (size_t)p + 1);
    return p + 1;
}

/* ---- Nostr Wallet Connect (NIP-47) ---- */

int nwc_parse_connection(const char *uri, nwc_connection_t *out)
{
    if (!uri || !out) return 0;
    memset(out, 0, sizeof(*out));

    /* Accept: nostrwalletconnect://pk@relay?... or nostr+walletconnect://pk?... */
    const char *p = uri;
    if (strncmp(p, "nostrwalletconnect://", 21) == 0) p += 21;
    else if (strncmp(p, "nostr+walletconnect://", 22) == 0) p += 22;
    else return 0;

    /* Extract pubkey (64 hex chars) */
    const char *pk_start = p;
    size_t pk_len = 0;
    while (*p && *p != '@' && *p != '?') { p++; pk_len++; }
    if (pk_len != NWC_PUBKEY_HEX_LEN) return 0;
    memcpy(out->wallet_pubkey, pk_start, NWC_PUBKEY_HEX_LEN);
    out->wallet_pubkey[NWC_PUBKEY_HEX_LEN] = '\0';

    /* Skip optional @relay part */
    if (*p == '@') {
        p++;
        const char *relay_start = p;
        while (*p && *p != '?') p++;
        size_t rlen = (size_t)(p - relay_start);
        if (rlen > 0 && rlen < NWC_RELAY_MAX) {
            memcpy(out->relay, relay_start, rlen);
            out->relay[rlen] = '\0';
        }
    }

    /* Parse query params */
    if (*p == '?') {
        p++;
        size_t pos = 0;
        char name[64], val[NWC_RELAY_MAX];
        while (parse_next_param(p, &pos, name, sizeof(name), val, sizeof(val))) {
            if (strcmp(name, "relay") == 0) {
                strncpy(out->relay, val, sizeof(out->relay) - 1);
            } else if (strcmp(name, "secret") == 0) {
                if (strlen(val) == NWC_SECRET_HEX_LEN) {
                    memcpy(out->secret, val, NWC_SECRET_HEX_LEN);
                    out->secret[NWC_SECRET_HEX_LEN] = '\0';
                }
            }
        }
    }

    /* Must have pubkey, relay, and secret */
    return (out->wallet_pubkey[0] && out->relay[0] && out->secret[0]) ? 1 : 0;
}

int nwc_build_pay_invoice(char *out, size_t out_cap,
                           const char *id, const char *invoice)
{
    if (!out || !id || !invoice || out_cap == 0) return 0;
    int n = snprintf(out, out_cap,
        "{\"id\":\"%s\",\"method\":\"%s\",\"params\":{\"invoice\":\"%s\"}}",
        id, NWC_CMD_PAY_INVOICE, invoice);
    return (n > 0 && (size_t)n < out_cap) ? n : 0;
}

int nwc_build_get_balance(char *out, size_t out_cap, const char *id)
{
    if (!out || !id || out_cap == 0) return 0;
    int n = snprintf(out, out_cap,
        "{\"id\":\"%s\",\"method\":\"%s\",\"params\":{}}",
        id, NWC_CMD_GET_BALANCE);
    return (n > 0 && (size_t)n < out_cap) ? n : 0;
}

int nwc_build_make_invoice(char *out, size_t out_cap,
                            const char *id, uint64_t amount_msat,
                            const char *description, uint32_t expiry_secs)
{
    if (!out || !id || out_cap == 0) return 0;
    if (!description) description = "";
    if (!expiry_secs) expiry_secs = 3600;

    int n = snprintf(out, out_cap,
        "{\"id\":\"%s\",\"method\":\"%s\",\"params\":"
        "{\"amount\":%llu,\"description\":\"%s\",\"expiry\":%u}}",
        id, NWC_CMD_MAKE_INVOICE,
        (unsigned long long)amount_msat, description, expiry_secs);
    return (n > 0 && (size_t)n < out_cap) ? n : 0;
}

/* Simple JSON field extractor (reuse pattern from lnurl.c) */
static int json_str(const char *json, const char *key, char *out, size_t cap)
{
    if (!json || !key || !out) return 0;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *kp = strstr(json, search);
    if (!kp) return 0;
    kp += strlen(search);
    while (*kp == ' ' || *kp == ':' || *kp == '\t') kp++;
    if (*kp != '"') return 0;
    kp++;
    size_t i = 0;
    while (*kp && *kp != '"' && i + 1 < cap) {
        if (*kp == '\\' && *(kp+1)) kp++;
        out[i++] = *kp++;
    }
    out[i] = '\0';
    return (*kp == '"') ? 1 : 0;
}

int nwc_parse_response(const char *json,
                        char *result_type_out, size_t rt_cap,
                        char *result_out, size_t res_cap,
                        int *error_code)
{
    if (!json || !result_type_out || !result_out) return 0;
    if (error_code) *error_code = 0;

    /* Check for error */
    if (strstr(json, "\"error\"")) {
        if (error_code) {
            /* Try to extract error code */
            const char *ep = strstr(json, "\"code\"");
            if (ep) {
                ep += 6;
                while (*ep == ' ' || *ep == ':') ep++;
                *error_code = (int)strtol(ep, NULL, 10);
            }
            if (*error_code == 0) *error_code = -1;
        }
        return 0;
    }

    /* Extract result_type */
    if (!json_str(json, "result_type", result_type_out, rt_cap)) return 0;

    /* Extract result as raw JSON substring */
    const char *rp = strstr(json, "\"result\"");
    if (!rp) return 0;
    rp += 8;
    while (*rp == ' ' || *rp == ':') rp++;
    size_t i = 0;
    int depth = 0;
    int in_str = 0, escaped = 0;
    while (*rp && i + 1 < res_cap) {
        result_out[i++] = *rp;
        if (escaped) { escaped = 0; rp++; continue; }
        if (*rp == '\\') { escaped = 1; rp++; continue; }
        if (*rp == '"') { in_str = !in_str; }
        if (!in_str) {
            if (*rp == '{' || *rp == '[') depth++;
            else if (*rp == '}' || *rp == ']') {
                depth--;
                if (depth <= 0) { rp++; break; }
            } else if (depth == 0 && (*rp == ',' || *rp == ' ')) break;
        }
        rp++;
    }
    result_out[i] = '\0';
    return 1;
}
