/*
 * scb_recovery.h — SCB channel recovery orchestrator
 *
 * High-level helper that connects to a peer, runs channel_reestablish,
 * and if DLP is detected (peer ahead of us) triggers force-close and
 * registers the channel with the watchtower for HTLC sweep.
 *
 * Reference: BOLT #2 §channel-reestablish, LND SCB recovery flow.
 */

#ifndef SUPERSCALAR_SCB_RECOVERY_H
#define SUPERSCALAR_SCB_RECOVERY_H

#include <secp256k1.h>
#include "peer_mgr.h"
#include "channel.h"
#include "watchtower.h"

/*
 * Reconnect to peer and run channel_reestablish.
 * If DLP is detected (chan_reestablish returns 0), registers the channel
 * with the watchtower for sweep.
 *
 * Returns:
 *   1  = DLP triggered: force-close registered with watchtower
 *   0  = normal re-sync (no DLP)
 *  -1  = ch is NULL or pmgr is NULL (invalid args)
 */
int scb_recovery_channel(peer_mgr_t        *pmgr,
                          secp256k1_context *ctx,
                          channel_t         *ch,
                          watchtower_t      *wt,
                          int                peer_idx);

#endif /* SUPERSCALAR_SCB_RECOVERY_H */
