#ifndef SUPERSCALAR_PAYMENT_URI_H
#define SUPERSCALAR_PAYMENT_URI_H

/*
 * payment_uri.h — BIP 21 Payment URI parsing/building and Nostr Wallet Connect.
 *
 * BIP 21: bitcoin:address[?amount=X][&label=Y][&message=Z][&lightning=lnbc...][&lno=lno1...]
 *   - Used by every Bitcoin/LN wallet for QR code payments
 *   - Unified QR: includes both on-chain address and Lightning invoice
 *
 * NWC (Nostr Wallet Connect, NIP-47):
 *   - Connection string: nostrwalletconnect://pubkey@relay?relay=...&secret=...
 *   - Commands: pay_invoice, get_balance, make_invoice, lookup_invoice
 *   - Used by Alby, ZBD, Strike, Mutiny, and most LN wallets for OAuth-like API
 *
 * Reference:
 *   BIP 21: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
 *   NIP-47: https://github.com/nostr-protocol/nips/blob/master/47.md
 *   Alby: getalby.com, github.com/getAlby/alby-hub
 *   Mutiny: github.com/MutinyWallet/mutiny-node
 */

#include <stddef.h>
#include <stdint.h>

/* ---- BIP 21 ---- */

#define PAYMENT_URI_ADDR_MAX     128  /* Bitcoin address max length */
#define PAYMENT_URI_INVOICE_MAX 2048  /* BOLT #11 invoice max length */
#define PAYMENT_URI_OFFER_MAX   1024  /* BOLT #12 offer max length */
#define PAYMENT_URI_LABEL_MAX    256
#define PAYMENT_URI_MSG_MAX      512

typedef struct {
    char     address[PAYMENT_URI_ADDR_MAX];   /* Bitcoin address (may be empty) */
    uint64_t amount_sat;                       /* satoshis (0 = not specified) */
    char     label[PAYMENT_URI_LABEL_MAX];     /* human-readable label */
    char     message[PAYMENT_URI_MSG_MAX];     /* payment description */
    char     lightning[PAYMENT_URI_INVOICE_MAX]; /* BOLT #11 invoice */
    char     offer[PAYMENT_URI_OFFER_MAX];       /* BOLT #12 offer */
    int      has_amount;   /* 1 if amount= was present */
    int      has_lightning;/* 1 if lightning= was present */
    int      has_offer;    /* 1 if lno= was present */
} payment_uri_t;

/*
 * Parse a BIP 21 payment URI into payment_uri_t.
 * Handles:
 *   bitcoin:ADDRESS
 *   bitcoin:ADDRESS?amount=0.001&label=Foo&lightning=lnbc...
 *   bitcoin:?lightning=lnbc... (invoice-only, no address)
 *   BITCOIN:... (case-insensitive scheme)
 *
 * Amounts are in BTC (decimal), stored as satoshis.
 * Returns 1 on success, 0 on parse error.
 */
int payment_uri_parse(const char *uri, payment_uri_t *out);

/*
 * Build a BIP 21 unified payment URI.
 * address: Bitcoin address (may be NULL for invoice-only URIs)
 * invoice: BOLT #11 invoice string (may be NULL)
 * amount_sat: satoshis (0 = omit amount field)
 * label: label string (may be NULL)
 * Returns bytes written (including NUL), 0 on error.
 */
int payment_uri_build(char *out, size_t out_cap,
                       const char *address,
                       const char *invoice,
                       uint64_t amount_sat,
                       const char *label);

/* ---- Nostr Wallet Connect (NIP-47) ---- */

#define NWC_PUBKEY_HEX_LEN  64    /* 32 bytes hex = 64 chars */
#define NWC_SECRET_HEX_LEN  64
#define NWC_RELAY_MAX       512

typedef struct {
    char wallet_pubkey[NWC_PUBKEY_HEX_LEN + 1];  /* NWC wallet pubkey (hex) */
    char relay[NWC_RELAY_MAX];                     /* WebSocket relay URL */
    char secret[NWC_SECRET_HEX_LEN + 1];           /* client secret (hex) */
    int  lud16_supported;  /* wallet supports LUD-16 (Lightning Address) */
} nwc_connection_t;

/*
 * Parse a Nostr Wallet Connect URI into nwc_connection_t.
 * Format: nostrwalletconnect://pubkey@relay?relay=wss://...&secret=hexsecret
 *   OR:   nostr+walletconnect://pubkey?relay=wss://...&secret=hexsecret
 *
 * Returns 1 on success, 0 on error.
 */
int nwc_parse_connection(const char *uri, nwc_connection_t *out);

/*
 * NWC command types (NIP-47 request method strings).
 */
#define NWC_CMD_PAY_INVOICE    "pay_invoice"
#define NWC_CMD_GET_BALANCE    "get_balance"
#define NWC_CMD_MAKE_INVOICE   "make_invoice"
#define NWC_CMD_LOOKUP_INVOICE "lookup_invoice"
#define NWC_CMD_LIST_TXNS      "list_transactions"

/*
 * Build a NWC pay_invoice JSON request.
 * id: unique request ID (caller provides)
 * invoice: BOLT #11 invoice to pay
 * Returns bytes written, 0 on error.
 */
int nwc_build_pay_invoice(char *out, size_t out_cap,
                           const char *id,
                           const char *invoice);

/*
 * Build a NWC get_balance JSON request.
 */
int nwc_build_get_balance(char *out, size_t out_cap, const char *id);

/*
 * Build a NWC make_invoice JSON request.
 * amount_msat: 0 = any amount
 * description: invoice description
 * expiry_secs: 0 = default 3600
 */
int nwc_build_make_invoice(char *out, size_t out_cap,
                            const char *id,
                            uint64_t amount_msat,
                            const char *description,
                            uint32_t expiry_secs);

/*
 * Parse a NWC response JSON.
 * Returns 1 if response has result_type and result, 0 if error.
 * error_code: set to error code if response is an error (or 0).
 */
int nwc_parse_response(const char *json,
                        char *result_type_out, size_t rt_cap,
                        char *result_out, size_t res_cap,
                        int *error_code);

#endif /* SUPERSCALAR_PAYMENT_URI_H */
