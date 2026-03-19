#ifndef SUPERSCALAR_LNURL_H
#define SUPERSCALAR_LNURL_H

/*
 * lnurl.h — LNURL-pay, Lightning Address (LUD-16), and BIP 353 DNS payments.
 *
 * Implements:
 *   - LNURL bech32 encode/decode (LUD-01)
 *   - Lightning Address URL construction (LUD-16): user@domain → HTTPS endpoint
 *   - LNURL-pay JSON response parsing (LUD-06)
 *   - BIP 353 DNS TXT record parsing: ⚡user@domain → DNS query name + TXT parse
 *
 * Reference:
 *   LUD-01: https://github.com/lnurl/luds/blob/legacy/lud01.md
 *   LUD-06: https://github.com/lnurl/luds/blob/legacy/lud06.md
 *   LUD-16: https://github.com/lnurl/luds/blob/legacy/lud16.md
 *   BIP 353: https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki
 *   CLN: contrib/pyln-client/pyln/client/lightning.py, plugins/lnurl
 *   LDK-node: lightning-node-connect lnurl_payment.rs
 */

#include <stddef.h>
#include <stdint.h>

/* ---- LNURL bech32 encode/decode (LUD-01) ---- */

/*
 * Encode a URL as an LNURL bech32 string (hrp="lnurl").
 * Returns 1 on success, 0 if output buffer too small or URL too long.
 * out receives a NUL-terminated uppercase bech32 string.
 */
int lnurl_encode(const char *url, char *out, size_t out_cap);

/*
 * Decode an LNURL bech32 string to the underlying URL.
 * Accepts both upper and lower case input.
 * Returns 1 on success (hrp is "lnurl"), 0 on error.
 */
int lnurl_decode(const char *lnurl, char *url_out, size_t url_cap);

/*
 * Check if a string looks like an LNURL (starts with lnurl/LNURL, bech32).
 * Returns 1 if yes.
 */
int lnurl_is_lnurl(const char *s);

/* ---- Lightning Address (LUD-16) ---- */

/*
 * Convert a Lightning Address (user@domain) to a LNURL-pay HTTP endpoint.
 * Result is: https://<domain>/.well-known/lnurlp/<user>
 * or for .onion: http://<domain>/.well-known/lnurlp/<user>
 * Returns 1 on success, 0 on error (bad format, output too small).
 */
int lnaddr_to_url(const char *address, char *url_out, size_t url_cap);

/*
 * Split a Lightning Address into user and domain parts.
 * Both out buffers must be at least 256 bytes.
 * Returns 1 on success, 0 on error.
 */
int lnaddr_split(const char *address, char *user_out, char *domain_out);

/* ---- LNURL-pay parameters (LUD-06) ---- */

#define LNURL_CALLBACK_MAX  512
#define LNURL_METADATA_MAX  1024
#define LNURL_DOMAIN_MAX    256

typedef struct {
    uint64_t min_sendable;          /* minimum payment in msat */
    uint64_t max_sendable;          /* maximum payment in msat */
    char     callback[LNURL_CALLBACK_MAX]; /* URL to call with ?amount= */
    char     metadata[LNURL_METADATA_MAX]; /* LUD-06 metadata JSON */
    int      allows_nostr;          /* LUD-18: nostr zaps supported */
    int      comment_allowed;       /* LUD-12: max comment length */
} lnurl_pay_params_t;

/*
 * Parse a LNURL-pay first-step JSON response into lnurl_pay_params_t.
 * JSON must contain: minSendable, maxSendable, callback, metadata.
 * Returns 1 on success, 0 on error.
 */
int lnurl_parse_pay_params(const char *json, lnurl_pay_params_t *out);

/*
 * Build a LNURL-pay second-step request URL.
 * Appends ?amount=<msat> to params->callback.
 * Returns 1 on success, 0 if buffer too small.
 */
int lnurl_build_pay_request(const lnurl_pay_params_t *params,
                             uint64_t amount_msat,
                             char *url_out, size_t url_cap);

/*
 * Parse a LNURL-pay second-step JSON response to extract the BOLT #11 invoice.
 * JSON contains {"pr": "lnbc...", "routes": [...], ...}
 * Returns 1 on success, 0 on error.
 * invoice_out receives a NUL-terminated BOLT #11 invoice string.
 */
int lnurl_parse_pay_invoice(const char *json,
                             char *invoice_out, size_t inv_cap);

/* ---- BIP 353 DNS payments ---- */

/*
 * Convert a BIP 353 address (user@domain) to DNS TXT query name.
 * Result is: <user>._bitcoin-payment.<domain>
 * e.g. "alice@example.com" → "alice._bitcoin-payment.example.com"
 * Returns 1 on success, 0 on error.
 */
int bip353_to_dns_name(const char *address,
                        char *dns_name_out, size_t dns_cap);

/*
 * Parse a BIP 353 DNS TXT record value.
 * Format: "bitcoin:?lightning=lnbc..." or "bitcoin:?lno=lno..."
 * Extracts the payment instruction (invoice or offer) into out.
 * Returns LNURL_BIP353_BOLT11 (1), LNURL_BIP353_OFFER (2), or 0 on error.
 */
#define LNURL_BIP353_BOLT11  1
#define LNURL_BIP353_OFFER   2

int bip353_parse_txt_record(const char *txt,
                              char *payment_out, size_t pay_cap);

/*
 * Validate a BIP 353 address format (user@domain with valid DNS chars).
 * Returns 1 if valid, 0 if not.
 */
int bip353_validate_address(const char *address);

#endif /* SUPERSCALAR_LNURL_H */
