/*
 * test_lnurl.c — Tests for LNURL-pay, Lightning Address, and BIP 353.
 *
 * PR #35: LNURL + Lightning Address + BIP 353 DNS payments
 */

#include "superscalar/lnurl.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* LU1: lnaddr_split extracts user and domain */
int test_lnurl_lnaddr_split(void)
{
    char user[256], domain[256];
    ASSERT(lnaddr_split("alice@example.com", user, domain), "split ok");
    ASSERT(strcmp(user, "alice") == 0, "user=alice");
    ASSERT(strcmp(domain, "example.com") == 0, "domain=example.com");

    ASSERT(!lnaddr_split("noatsign", user, domain), "no @ rejected");
    ASSERT(!lnaddr_split("@nodomain", user, domain), "empty user rejected");
    ASSERT(!lnaddr_split(NULL, user, domain), "NULL rejected");
    return 1;
}

/* LU2: lnaddr_to_url builds correct HTTPS endpoint */
int test_lnurl_lnaddr_to_url(void)
{
    char url[512];
    ASSERT(lnaddr_to_url("alice@example.com", url, sizeof(url)), "url built");
    ASSERT(strcmp(url, "https://example.com/.well-known/lnurlp/alice") == 0,
           "URL matches LUD-16");
    return 1;
}

/* LU3: lnaddr_to_url uses HTTP for .onion domains */
int test_lnurl_lnaddr_onion(void)
{
    char url[512];
    ASSERT(lnaddr_to_url("bob@abc123def456.onion", url, sizeof(url)), "onion url built");
    ASSERT(strncmp(url, "http://", 7) == 0, "onion uses http://");
    ASSERT(strstr(url, "abc123def456.onion") != NULL, "onion domain present");
    return 1;
}

/* LU4: lnurl_encode + lnurl_decode round-trip */
int test_lnurl_encode_decode_roundtrip(void)
{
    const char *url = "https://example.com/.well-known/lnurlp/alice";
    char encoded[1024];
    ASSERT(lnurl_encode(url, encoded, sizeof(encoded)), "encode ok");
    /* encoded string should start with LNURL1 */
    ASSERT(strncmp(encoded, "LNURL1", 6) == 0, "starts with LNURL1");

    char decoded[512];
    ASSERT(lnurl_decode(encoded, decoded, sizeof(decoded)), "decode ok");
    ASSERT(strcmp(decoded, url) == 0, "round-trip matches");
    return 1;
}

/* LU5: lnurl_is_lnurl detects LNURL strings */
int test_lnurl_is_lnurl(void)
{
    ASSERT(lnurl_is_lnurl("LNURL1DP68GURN..."), "uppercase LNURL detected");
    ASSERT(lnurl_is_lnurl("lnurl1dp68gurn..."), "lowercase lnurl detected");
    ASSERT(!lnurl_is_lnurl("lnbc100n1pj..."), "BOLT #11 invoice not LNURL");
    ASSERT(!lnurl_is_lnurl("bitcoin:?lightning=lnbc..."), "BIP-21 URI not LNURL");
    ASSERT(!lnurl_is_lnurl(NULL), "NULL not LNURL");
    return 1;
}

/* LU6: lnurl_parse_pay_params parses JSON response */
int test_lnurl_parse_pay_params(void)
{
    const char *json = "{"
        "\"minSendable\": 1000,"
        "\"maxSendable\": 100000000,"
        "\"callback\": \"https://example.com/pay\","
        "\"metadata\": \"[[\\\"text/plain\\\",\\\"Pay Alice\\\"]]\","
        "\"tag\": \"payRequest\""
        "}";

    lnurl_pay_params_t params;
    ASSERT(lnurl_parse_pay_params(json, &params), "parse ok");
    ASSERT(params.min_sendable == 1000, "minSendable=1000");
    ASSERT(params.max_sendable == 100000000, "maxSendable=100000000");
    ASSERT(strcmp(params.callback, "https://example.com/pay") == 0, "callback ok");
    return 1;
}

/* LU7: lnurl_parse_pay_params rejects missing fields */
int test_lnurl_parse_pay_params_missing(void)
{
    /* Missing callback */
    const char *json = "{\"minSendable\": 1000, \"maxSendable\": 100000}";
    lnurl_pay_params_t params;
    ASSERT(!lnurl_parse_pay_params(json, &params), "missing callback rejected");
    ASSERT(!lnurl_parse_pay_params(NULL, &params), "NULL json rejected");
    ASSERT(!lnurl_parse_pay_params(json, NULL), "NULL out rejected");
    return 1;
}

/* LU8: lnurl_build_pay_request appends amount */
int test_lnurl_build_pay_request(void)
{
    lnurl_pay_params_t params;
    memset(&params, 0, sizeof(params));
    strncpy(params.callback, "https://example.com/pay", sizeof(params.callback) - 1);

    char url[512];
    ASSERT(lnurl_build_pay_request(&params, 50000, url, sizeof(url)), "build ok");
    ASSERT(strstr(url, "amount=50000") != NULL, "amount param present");
    ASSERT(strstr(url, "?amount=50000") != NULL, "? separator used");

    /* Callback already has query params */
    strncpy(params.callback, "https://example.com/pay?node=abc", sizeof(params.callback) - 1);
    ASSERT(lnurl_build_pay_request(&params, 100, url, sizeof(url)), "build with existing params");
    ASSERT(strstr(url, "&amount=100") != NULL, "& separator used");
    return 1;
}

/* LU9: lnurl_parse_pay_invoice extracts pr field */
int test_lnurl_parse_pay_invoice(void)
{
    const char *json = "{\"pr\": \"lnbc500n1pjtest...\", \"routes\": []}";
    char invoice[256];
    ASSERT(lnurl_parse_pay_invoice(json, invoice, sizeof(invoice)), "parse ok");
    ASSERT(strcmp(invoice, "lnbc500n1pjtest...") == 0, "invoice extracted");

    ASSERT(!lnurl_parse_pay_invoice("{\"error\": \"amount too small\"}", invoice, sizeof(invoice)),
           "error response rejected");
    return 1;
}

/* LU10: bip353_to_dns_name constructs correct query */
int test_lnurl_bip353_dns_name(void)
{
    char dns[512];
    ASSERT(bip353_to_dns_name("alice@example.com", dns, sizeof(dns)), "dns name built");
    ASSERT(strcmp(dns, "alice._bitcoin-payment.example.com") == 0, "DNS name correct");

    ASSERT(!bip353_to_dns_name("noatsign", dns, sizeof(dns)), "no @ rejected");
    return 1;
}

/* LU11: bip353_parse_txt_record extracts BOLT #11 invoice */
int test_lnurl_bip353_parse_bolt11(void)
{
    const char *txt = "bitcoin:?lightning=lnbc100n1pjtest1234";
    char payment[512];
    int type = bip353_parse_txt_record(txt, payment, sizeof(payment));
    ASSERT(type == LNURL_BIP353_BOLT11, "returns BOLT11 type");
    ASSERT(strcmp(payment, "lnbc100n1pjtest1234") == 0, "invoice extracted");
    return 1;
}

/* LU12: bip353_parse_txt_record extracts BOLT #12 offer */
int test_lnurl_bip353_parse_offer(void)
{
    const char *txt = "bitcoin:?lno=lno1qgsxxxxxxxxxx";
    char payment[512];
    int type = bip353_parse_txt_record(txt, payment, sizeof(payment));
    ASSERT(type == LNURL_BIP353_OFFER, "returns OFFER type");
    ASSERT(strcmp(payment, "lno1qgsxxxxxxxxxx") == 0, "offer extracted");

    /* Also works with lightning= starting with lno */
    const char *txt2 = "bitcoin:?lightning=lno1qgsyyyyyy";
    type = bip353_parse_txt_record(txt2, payment, sizeof(payment));
    ASSERT(type == LNURL_BIP353_OFFER, "lno via lightning= is offer");
    return 1;
}

/* LU13: bip353_validate_address accepts valid addresses */
int test_lnurl_bip353_validate(void)
{
    ASSERT(bip353_validate_address("alice@example.com"), "alice@example.com valid");
    ASSERT(bip353_validate_address("user.name@sub.domain.tld"), "dots in user valid");
    ASSERT(bip353_validate_address("user+tag@domain.com"), "plus in user valid");
    ASSERT(!bip353_validate_address("noatsign"), "no @ invalid");
    ASSERT(!bip353_validate_address("@domain.com"), "empty user invalid");
    ASSERT(!bip353_validate_address("user@"), "empty domain invalid");
    ASSERT(!bip353_validate_address(NULL), "NULL invalid");
    ASSERT(!bip353_validate_address("user@nodot"), "domain without dot invalid (non-onion)");
    return 1;
}

/* LU14: lnurl_encode rejects empty/NULL URL */
int test_lnurl_encode_edge_cases(void)
{
    char out[1024];
    ASSERT(!lnurl_encode(NULL, out, sizeof(out)), "NULL url rejected");
    ASSERT(!lnurl_encode("", out, sizeof(out)), "empty url rejected");
    ASSERT(!lnurl_encode("https://example.com", out, 5), "small buffer rejected");
    return 1;
}

/* LU15: lnurl_decode rejects bad input */
int test_lnurl_decode_edge_cases(void)
{
    char out[512];
    ASSERT(!lnurl_decode(NULL, out, sizeof(out)), "NULL rejected");
    ASSERT(!lnurl_decode("bitcoin1q...", out, sizeof(out)), "wrong hrp rejected");
    ASSERT(!lnurl_decode("lnurl1", out, sizeof(out)), "too short rejected");
    return 1;
}
