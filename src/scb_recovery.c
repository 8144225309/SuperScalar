/*
 * scb_recovery.c — SCB channel recovery orchestrator
 */

#include "superscalar/scb_recovery.h"
#include "superscalar/chan_open.h"
#include <stdio.h>

int scb_recovery_channel(peer_mgr_t        *pmgr,
                          secp256k1_context *ctx,
                          channel_t         *ch,
                          watchtower_t      *wt,
                          int                peer_idx)
{
    if (!pmgr || !ch) return -1;

    /* Run channel reestablish (peer must already be connected at peer_idx) */
    int r = chan_reestablish(pmgr, peer_idx, ctx, ch);
    if (r == 0) {
        /* DLP: peer is ahead — register for watchtower sweep */
        fprintf(stderr, "scb_recovery: DLP detected on peer %d — registering sweep\n",
                peer_idx);
        if (wt)
            watchtower_set_channel(wt, (size_t)peer_idx, ch);
        return 1;
    }
    return 0;
}
