/*
 * test_payment_uri.c — Tests for BIP 21 Payment URIs and Nostr Wallet Connect.
 *
 * PR #38: BIP 21 + NWC (NIP-47)
 */

#include "superscalar/payment_uri.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* PU1: parse address-only BIP 21 URI */
int test_bip21_parse_address_only(void)
{
    payment_uri_t out;
    ASSERT(payment_uri_parse("bitcoin:bc1qtest123", &out), "parse ok");
    ASSERT(strcmp(out.address, "bc1qtest123") == 0, "address extracted");
    ASSERT(!out.has_amount, "no amount");
    ASSERT(!out.has_lightning, "no lightning");
    return 1;
}

/* PU2: parse BIP 21 URI with amount */
int test_bip21_parse_amount(void)
{
    payment_uri_t out;
    ASSERT(payment_uri_parse("bitcoin:bc1qtest?amount=0.001", &out), "parse ok");
    ASSERT(out.has_amount, "has amount");
    ASSERT(out.amount_sat == 100000, "0.001 BTC = 100000 sat");
    return 1;
}

/* PU3: parse unified QR (address + lightning) */
int test_bip21_parse_unified_qr(void)
{
    const char *uri = "bitcoin:bc1qtest123?amount=0.00050000&lightning=lnbc500n1pjtest";
    payment_uri_t out;
    ASSERT(payment_uri_parse(uri, &out), "parse ok");
    ASSERT(strcmp(out.address, "bc1qtest123") == 0, "address ok");
    ASSERT(out.amount_sat == 50000, "0.0005 BTC = 50000 sat");
    ASSERT(out.has_lightning, "has lightning");
    ASSERT(strcmp(out.lightning, "lnbc500n1pjtest") == 0, "lightning ok");
    return 1;
}

/* PU4: parse BIP 21 with label and message */
int test_bip21_parse_label_message(void)
{
    const char *uri = "bitcoin:bc1q?label=Alice&message=Coffee";
    payment_uri_t out;
    ASSERT(payment_uri_parse(uri, &out), "parse ok");
    ASSERT(strcmp(out.label, "Alice") == 0, "label ok");
    ASSERT(strcmp(out.message, "Coffee") == 0, "message ok");
    return 1;
}

/* PU5: parse invoice-only BIP 21 (no address) */
int test_bip21_parse_invoice_only(void)
{
    const char *uri = "bitcoin:?lightning=lnbc100n1pjtest&lno=lno1qgstest";
    payment_uri_t out;
    ASSERT(payment_uri_parse(uri, &out), "parse ok");
    ASSERT(strlen(out.address) == 0, "no address");
    ASSERT(out.has_lightning, "has lightning");
    ASSERT(out.has_offer, "has offer");
    ASSERT(strcmp(out.lightning, "lnbc100n1pjtest") == 0, "lightning ok");
    ASSERT(strcmp(out.offer, "lno1qgstest") == 0, "offer ok");
    return 1;
}

/* PU6: build BIP 21 URI */
int test_bip21_build(void)
{
    char buf[1024];
    int n = payment_uri_build(buf, sizeof(buf),
                               "bc1qtest123",
                               "lnbc500n1pjtest",
                               50000,   /* 50000 sat */
                               NULL);
    ASSERT(n > 0, "build ok");
    ASSERT(strncmp(buf, "bitcoin:bc1qtest123?", 20) == 0, "scheme+address ok");
    ASSERT(strstr(buf, "amount=") != NULL, "amount present");
    ASSERT(strstr(buf, "lightning=lnbc500n1pjtest") != NULL, "lightning present");
    return 1;
}

/* PU7: build BIP 21 URI without address (invoice-only) */
int test_bip21_build_invoice_only(void)
{
    char buf[1024];
    int n = payment_uri_build(buf, sizeof(buf), NULL, "lnbc123n1pjtest", 0, NULL);
    ASSERT(n > 0, "build ok");
    ASSERT(strncmp(buf, "bitcoin:?", 9) == 0 || strncmp(buf, "bitcoin:", 8) == 0,
           "scheme ok");
    ASSERT(strstr(buf, "lightning=lnbc123n1pjtest") != NULL, "lightning present");
    return 1;
}

/* PU8: BIP 21 rejects non-bitcoin scheme */
int test_bip21_parse_bad_scheme(void)
{
    payment_uri_t out;
    ASSERT(!payment_uri_parse("lightning:lnbc...", &out), "lightning: scheme rejected");
    ASSERT(!payment_uri_parse(NULL, &out), "NULL rejected");
    ASSERT(!payment_uri_parse("bitcoin:test", NULL), "NULL out rejected");
    return 1;
}

/* NWC1: parse NWC connection URI */
int test_nwc_parse_connection(void)
{
    const char *uri =
        "nostrwalletconnect://"
        "b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4"
        "@relay.getalby.com/v1"
        "?relay=wss://relay.getalby.com/v1"
        "&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c";

    nwc_connection_t conn;
    ASSERT(nwc_parse_connection(uri, &conn), "parse ok");
    ASSERT(strlen(conn.wallet_pubkey) == 64, "pubkey is 64 hex chars");
    ASSERT(strstr(conn.relay, "relay.getalby.com") != NULL, "relay ok");
    ASSERT(strlen(conn.secret) == 64, "secret is 64 hex chars");
    return 1;
}

/* NWC2: build pay_invoice command */
int test_nwc_build_pay_invoice(void)
{
    char buf[512];
    int n = nwc_build_pay_invoice(buf, sizeof(buf), "req1", "lnbc500n1pjtest");
    ASSERT(n > 0, "build ok");
    ASSERT(strstr(buf, "\"pay_invoice\"") != NULL, "method ok");
    ASSERT(strstr(buf, "lnbc500n1pjtest") != NULL, "invoice in params");
    ASSERT(strstr(buf, "\"req1\"") != NULL, "id ok");
    return 1;
}

/* NWC3: build get_balance command */
int test_nwc_build_get_balance(void)
{
    char buf[256];
    int n = nwc_build_get_balance(buf, sizeof(buf), "req2");
    ASSERT(n > 0, "build ok");
    ASSERT(strstr(buf, "\"get_balance\"") != NULL, "method ok");
    ASSERT(strstr(buf, "\"req2\"") != NULL, "id ok");
    return 1;
}

/* NWC4: build make_invoice command */
int test_nwc_build_make_invoice(void)
{
    char buf[512];
    int n = nwc_build_make_invoice(buf, sizeof(buf), "req3", 50000, "Coffee", 3600);
    ASSERT(n > 0, "build ok");
    ASSERT(strstr(buf, "\"make_invoice\"") != NULL, "method ok");
    ASSERT(strstr(buf, "\"Coffee\"") != NULL, "description ok");
    ASSERT(strstr(buf, "50000") != NULL, "amount ok");
    return 1;
}

/* NWC5: parse success response */
int test_nwc_parse_response_ok(void)
{
    const char *json = "{"
        "\"result_type\":\"pay_invoice\","
        "\"result\":{\"preimage\":\"abc123\"}"
        "}";
    char rtype[64], result[256];
    int errcode = 0;
    ASSERT(nwc_parse_response(json, rtype, sizeof(rtype), result, sizeof(result), &errcode),
           "parse ok");
    ASSERT(strcmp(rtype, "pay_invoice") == 0, "result_type ok");
    ASSERT(errcode == 0, "no error");
    return 1;
}

/* NWC6: parse error response */
int test_nwc_parse_response_error(void)
{
    const char *json = "{"
        "\"result_type\":\"pay_invoice\","
        "\"error\":{\"code\":600,\"message\":\"insufficient balance\"}"
        "}";
    char rtype[64], result[256];
    int errcode = 0;
    ASSERT(!nwc_parse_response(json, rtype, sizeof(rtype), result, sizeof(result), &errcode),
           "error response returns 0");
    ASSERT(errcode != 0, "error code set");
    return 1;
}

/* NWC7: NWC rejects bad URI */
int test_nwc_parse_bad_uri(void)
{
    nwc_connection_t conn;
    ASSERT(!nwc_parse_connection("https://example.com", &conn), "https rejected");
    ASSERT(!nwc_parse_connection(NULL, &conn), "NULL rejected");
    /* Short pubkey */
    ASSERT(!nwc_parse_connection("nostrwalletconnect://tooshort?relay=wss://r&secret=abc",
                                  &conn), "short pubkey rejected");
    return 1;
}
