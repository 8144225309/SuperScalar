#ifndef SUPERSCALAR_LN_DISPATCH_H
#define SUPERSCALAR_LN_DISPATCH_H

/*
 * ln_dispatch.h — LN peer message dispatch loop
 *
 * After the BOLT #8 handshake + BOLT #1 init, ongoing peer messages
 * (update_add_htlc, update_fulfill_htlc, commitment_signed, etc.) are
 * dispatched here from a dedicated pthread.
 *
 * Reference: LDK ChannelManager::process_pending_events(),
 *            CLN lightningd/peer_htlcs.c, LND htlcswitch/switch.go
 */

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>
#include "peer_mgr.h"
#include "htlc_forward.h"
#include "mpp.h"
#include "payment.h"

/*
 * Aggregate context for the LN dispatch loop.
 * All fields are caller-owned and must outlive ln_dispatch_run().
 */
typedef struct {
    peer_mgr_t            *pmgr;          /* connected peer registry */
    htlc_forward_table_t  *fwd;           /* in-flight HTLC forwards */
    mpp_table_t           *mpp;           /* MPP part aggregation */
    payment_table_t       *payments;      /* outbound payment tracking */
    secp256k1_context     *ctx;           /* secp256k1 context */
    unsigned char          our_privkey[32]; /* node private key */
    volatile int          *shutdown_flag; /* set non-zero to stop loop */
} ln_dispatch_t;

/*
 * Process a single plaintext BOLT #2 message already stripped of BOLT #8
 * framing (msg includes the 2-byte type prefix).
 *
 * Dispatches:
 *   BOLT2_UPDATE_ADD_HTLC     → htlc_forward_process()
 *   BOLT2_UPDATE_FULFILL_HTLC → htlc_forward_settle()
 *   BOLT2_UPDATE_FAIL_HTLC    → htlc_forward_fail()
 *   BOLT2_COMMITMENT_SIGNED   → (forward to htlc_commit layer)
 *   BOLT2_REVOKE_AND_ACK      → (forward to htlc_commit layer)
 *   Unknown types             → silently ignored
 *
 * Returns the wire type processed (e.g. 128 = update_add_htlc),
 *         -1 on parse error, 0 for unknown/ignored type.
 */
int ln_dispatch_process_msg(ln_dispatch_t *d, int peer_idx,
                             const unsigned char *msg, size_t msg_len);

/*
 * Run the LN peer message dispatch loop (blocking).
 * Call from a dedicated pthread after peer_mgr is populated.
 * Reads from all connected peer fds via select(2) with a 100 ms timeout,
 * dispatches via ln_dispatch_process_msg(), and repeats until
 * *d->shutdown_flag becomes non-zero.
 */
void ln_dispatch_run(ln_dispatch_t *d);

#endif /* SUPERSCALAR_LN_DISPATCH_H */
