#ifndef SUPERSCALAR_FEE_H
#define SUPERSCALAR_FEE_H

#include <stdint.h>
#include <stddef.h>
#include "superscalar/fee_estimator.h"

struct regtest_t;  /* forward declaration */

/* -----------------------------------------------------------------------
 * Backwards-compatibility shims (deprecated — use fee_estimator_*.h APIs)
 *
 * fee_init: callers MUST pass a pointer to a fee_estimator_static_t that
 * is cast to fee_estimator_t *.  e.g.:
 *   fee_estimator_static_t fe;
 *   fee_init((fee_estimator_t *)&fe, 1000);
 * --------------------------------------------------------------------- */
void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb);

/* Deprecated: calls fe->update() if set; ignored for static estimators. */
int fee_update_from_node(fee_estimator_t *fe, void *rt, int target_blocks);

/* -----------------------------------------------------------------------
 * Fee helpers — call through the vtable
 *
 * Every helper below returns ceil(rate x vsize / 1000) in sats, 0 when the
 * rate is 0 (no estimate), and FEE_INVALID when the fee would exceed
 * FEE_MAX_SATS (the 21M BTC money supply): no transaction can pay it, so a
 * caller that gets FEE_INVALID must fail rather than build the transaction.
 * --------------------------------------------------------------------- */

/* Largest fee any transaction can pay: the money supply, in sats. */
#define FEE_MAX_SATS 2100000000000000ULL
/* Returned by the fee helpers when the fee exceeds FEE_MAX_SATS. */
#define FEE_INVALID  UINT64_MAX

/* General-purpose: fee for a transaction of given virtual size (NORMAL rate). */
uint64_t fee_estimate(fee_estimator_t *fe, size_t vsize_bytes);

/* Penalty tx is ~165 vB — uses URGENT rate (next 1-2 blocks). */
uint64_t fee_for_penalty_tx(fee_estimator_t *fe);

/* HTLC resolution tx is ~180 vB — uses URGENT rate. */
uint64_t fee_for_htlc_tx(fee_estimator_t *fe);

/* CPFP child tx is ~264 vB (2-in keypath, 1-out P2TR) — uses URGENT rate. */
uint64_t fee_for_cpfp_child(fee_estimator_t *fe);

/* Commitment tx is 154 vB base + 43 vB per active HTLC — uses NORMAL rate. */
uint64_t fee_for_commitment_tx(fee_estimator_t *fe, size_t n_htlcs);

/* The same commitment fee at a given rate (sat/kvB). */
uint64_t fee_commitment_tx_at(uint64_t sat_per_kvb, size_t n_htlcs);

/* -----------------------------------------------------------------------
 * Exact sizing for pre-signed transactions
 *
 * A pre-signed transaction cannot be re-signed when it is broadcast, so its
 * fee must be sized from its real virtual size and must never fall below what
 * nodes relay.  Bitcoin Core rejects any transaction whose fee is below
 * -minrelaytxfee x vsize (default 1000 sat/kvB), even inside a package unless
 * the transaction is TRUC (nVersion 3).
 * --------------------------------------------------------------------- */

/* Bitcoin Core default -minrelaytxfee (sat/kvB). */
#define FEE_MIN_RELAY_SAT_PER_KVB        1000
/* Floor for every pre-signed transaction: min relay plus a 25% margin. */
#define FEE_PRESIGNED_FLOOR_SAT_PER_KVB  1250

/* Serialized sizes used by the vsize helpers. */
#define FEE_P2TR_OUTPUT_BYTES     43   /* 8 amount + 1 len + 34 spk */
#define FEE_P2A_OUTPUT_BYTES      13   /* 8 amount + 1 len + 4 spk  */
#define FEE_KEYPATH_WITNESS_BYTES 66   /* 1 item count + 1 len + 64-byte sig */

/* Virtual size of a transaction whose inputs all have empty scriptSigs.
   outputs_bytes: serialized size of all outputs (each 8 + varint + spk).
   witness_bytes: serialized witness of all inputs (0 = legacy serialization,
   no marker/flag). */
size_t fee_tx_vsize(size_t n_inputs, size_t n_outputs, size_t outputs_bytes,
                    size_t witness_bytes);

/* Virtual size of a transaction with n_inputs taproot key-path inputs,
   n_p2tr P2TR outputs and n_p2a P2A anchor outputs. */
size_t fee_keypath_tx_vsize(size_t n_inputs, size_t n_p2tr, size_t n_p2a);

/* ceil(sat_per_kvb * vsize / 1000); FEE_INVALID above FEE_MAX_SATS. */
uint64_t fee_at_rate(uint64_t sat_per_kvb, size_t vsize);

/* Fee for a pre-signed transaction of the given vsize at sat_per_kvb, never
   below FEE_PRESIGNED_FLOOR_SAT_PER_KVB; FEE_INVALID above FEE_MAX_SATS. */
uint64_t fee_presigned(uint64_t sat_per_kvb, size_t vsize);

#endif /* SUPERSCALAR_FEE_H */
