#ifndef SUPERSCALAR_PTLC_COMMIT_H
#define SUPERSCALAR_PTLC_COMMIT_H

#include "channel.h"
#include "peer_mgr.h"
#include <secp256k1.h>

/* Add a PTLC to a channel's PTLC list. Returns 1 on success. */
int channel_add_ptlc(channel_t *ch, ptlc_direction_t dir,
                      uint64_t amount_sats,
                      const secp256k1_pubkey *point,
                      uint32_t cltv_expiry, uint64_t *id_out);

/* Settle a PTLC with the adapted signature. Returns 1 on success. */
int channel_settle_ptlc(channel_t *ch, uint64_t ptlc_id,
                         const unsigned char adapted_sig64[64]);

/* Fail a PTLC. Returns 1 on success. */
int channel_fail_ptlc(channel_t *ch, uint64_t ptlc_id);

/* Dispatch a PTLC message (type 0x4C/0x4D/0x4E). Returns msg_type or -1. */
int ptlc_commit_dispatch(peer_mgr_t *mgr, int peer_idx,
                          channel_t *ch,
                          secp256k1_context *ctx,
                          const unsigned char *msg, size_t msg_len);

#endif /* SUPERSCALAR_PTLC_COMMIT_H */
