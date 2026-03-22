#ifndef SUPERSCALAR_TRAMPOLINE_H
#define SUPERSCALAR_TRAMPOLINE_H

/*
 * trampoline.h — BOLT #4 trampoline routing (Phoenix/LDK-node pattern).
 *
 * Trampoline routing allows a sender with limited routing information to
 * delegate path-finding to a trusted intermediate node (the "trampoline").
 * The sender builds a trampoline onion, wraps it in a regular Sphinx onion
 * addressed to the trampoline node, which then routes to the next trampoline
 * or final destination.
 *
 * Wire format (BOLT #4 trampoline TLV, type 0x0c in hop payload):
 *   amt_to_forward (bigsize)
 *   outgoing_cltv_value (bigsize)
 *   short_channel_id (8 bytes) — optional, 0 if not present
 *   trampoline_onion (variable) — nested trampoline packet
 *
 * Reference:
 *   Phoenix wallet (ACINQ) — uses trampoline by default
 *   BOLT #4 PR #716: trampoline routing proposal
 *   LDK: lightning/src/ln/channel_state.rs (trampoline hints)
 *   CLN: plugins/renepay (approximate trampoline support)
 */

#include <stdint.h>
#include <stddef.h>

/* TLV type for trampoline routing in BOLT #4 hop payload */
#define TRAMPOLINE_TLV_TYPE         0x0c
/* TLV type for trampoline onion packet (inner nested onion) */
#define TRAMPOLINE_ONION_TLV_TYPE   0x0e
/* Max number of trampoline hops in a path */
#define TRAMPOLINE_MAX_HOPS         3
/* Trampoline onion packet size (smaller than regular 1366-byte onion) */
#define TRAMPOLINE_ONION_SIZE       400

typedef struct {
    unsigned char pubkey[33];    /* trampoline node pubkey */
    uint64_t      amt_msat;      /* amount to forward to this trampoline hop */
    uint32_t      cltv_expiry;   /* outgoing CLTV expiry */
    uint64_t      fee_msat;      /* fee charged by this trampoline (for display) */
} trampoline_hop_t;

typedef struct {
    trampoline_hop_t hops[TRAMPOLINE_MAX_HOPS];
    int              n_hops;
    unsigned char    dest_pubkey[33];  /* final destination node pubkey */
    uint64_t         dest_amt_msat;    /* amount at final destination */
    uint32_t         dest_cltv;        /* CLTV at final destination */
} trampoline_path_t;

/* ---- Trampoline hop payload TLV encoding ---- */

/*
 * Build a trampoline hop payload TLV entry (type 0x0c).
 * This goes into the outer Sphinx onion's TLV payload for the trampoline node.
 *
 * Fields encoded:
 *   amt_to_forward  (type 2, bigsize)
 *   outgoing_cltv   (type 4, bigsize)
 *   trampoline_pk   (type 14, 33 bytes) — next trampoline node pubkey
 *
 * Returns bytes written, 0 on error.
 */
size_t trampoline_build_hop_payload(const trampoline_hop_t *hop,
                                     unsigned char *buf, size_t buf_cap);

/*
 * Parse a trampoline hop payload TLV.
 * Returns 1 on success, 0 on error.
 */
int trampoline_parse_hop_payload(const unsigned char *buf, size_t buf_len,
                                  trampoline_hop_t *hop_out);

/* ---- Trampoline fee/CLTV estimation ---- */

/*
 * Estimate fees and CLTV delta for a trampoline path.
 * Since the sender doesn't know the full route from trampoline to dest,
 * Phoenix uses conservative fee/CLTV estimates.
 *
 * Phoenix defaults (ACINQ LSP):
 *   fee = max(100, amount_msat * 1000 / 1_000_000)  [0.1% min 100 msat]
 *   cltv_delta = 288 (blocks) for safety margin
 *
 * Fills in hop->fee_msat and adjusts hop->amt_msat.
 * Returns 1 on success.
 */
int trampoline_estimate_fees(trampoline_hop_t *hop,
                              uint64_t dest_amount_msat);

/*
 * Calculate total trampoline fees for a multi-hop trampoline path.
 * Returns total extra msat added to the source payment.
 */
uint64_t trampoline_path_total_fees(const trampoline_path_t *path);

/* ---- Route hint encoding for BOLT #11 invoices ---- */

/*
 * Build a BOLT #11 route hint for trampoline:
 * Encodes the trampoline node as a route hint with special fee/CLTV params
 * that signal to the payer that this is a trampoline path.
 *
 * Writes to buf as a TLV block (type 3 in BOLT #11 = route_hint).
 * Returns bytes written, 0 on error.
 */
size_t trampoline_build_invoice_hint(const trampoline_hop_t *trampoline,
                                      unsigned char *buf, size_t buf_cap);

/*
 * Parse a route hint from a BOLT #11 invoice into a trampoline hop.
 * Returns 1 if the hint looks like a trampoline node, 0 otherwise.
 */
int trampoline_parse_invoice_hint(const unsigned char *buf, size_t buf_len,
                                   trampoline_hop_t *hop_out);

/* ---- Trampoline path building ---- */

/*
 * Build a simple single-trampoline path (Phoenix model):
 *   source → trampoline → destination
 *
 * trampoline: the LSP node acting as trampoline (pubkey, from route hint)
 * dest_pubkey: final payment destination
 * amount_msat: amount at destination
 * cltv_final: CLTV at final destination (from invoice)
 *
 * Returns 1 on success, 0 on error.
 */
int trampoline_build_single_hop_path(trampoline_path_t *path,
                                      const unsigned char trampoline_pubkey[33],
                                      const unsigned char dest_pubkey[33],
                                      uint64_t amount_msat,
                                      uint32_t cltv_final);

#endif /* SUPERSCALAR_TRAMPOLINE_H */
