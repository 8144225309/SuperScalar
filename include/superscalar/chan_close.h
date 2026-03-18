/*
 * chan_close.h — BOLT #2 cooperative channel close wire protocol
 *
 * Implements the two-message cooperative close flow (BOLT #2 §2.3):
 *
 *   1. Either side sends shutdown (type 38).
 *      - No new HTLCs are accepted after shutdown is sent.
 *      - Both sides send shutdown before negotiating fees.
 *
 *   2. Once all pending HTLCs are resolved, fee negotiation begins via
 *      closing_signed (type 39).  Each side proposes a fee; the other
 *      side responds with the midpoint between their previous proposal
 *      and the received fee ("meet in the middle").  Negotiation ends
 *      when both sides propose the same fee.
 *
 * Wire formats:
 *   shutdown:       type(2) + channel_id(32) + len(2) + scriptpubkey(len)
 *   closing_signed: type(2) + channel_id(32) + fee_satoshis(8) + sig(64)
 *
 * Reference: BOLT #2 §2.3, CLN closingd/closingd.c, LDK channel.rs close_channel.
 */

#ifndef SUPERSCALAR_CHAN_CLOSE_H
#define SUPERSCALAR_CHAN_CLOSE_H

#include <stdint.h>
#include <stddef.h>
#include "channel.h"
#include "peer_mgr.h"

/* Maximum scriptpubkey length accepted in shutdown (standard outputs ≤ 34 bytes) */
#define CHAN_CLOSE_MAX_SPK_LEN  34

/*
 * Build a shutdown message into buf.
 * Wire: type(2) + channel_id(32) + len(2) + scriptpubkey(len)
 * Returns message length on success, 0 if buf_cap too small.
 */
size_t chan_close_build_shutdown(const unsigned char channel_id[32],
                                  const unsigned char *scriptpubkey,
                                  uint16_t spk_len,
                                  unsigned char *buf, size_t buf_cap);

/*
 * Build a closing_signed message into buf.
 * Wire: type(2) + channel_id(32) + fee_satoshis(8) + sig(64)
 * Total: 76 bytes. Returns 76 on success, 0 if buf_cap < 76.
 */
size_t chan_close_build_closing_signed(const unsigned char channel_id[32],
                                        uint64_t fee_satoshis,
                                        const unsigned char sig64[64],
                                        unsigned char *buf, size_t buf_cap);

/*
 * Parse an inbound shutdown message (msg includes the 2-byte type prefix).
 * spk_out must point to a buffer of at least spk_buf_cap bytes.
 * Returns 1 on success, 0 if malformed or spk too long for spk_buf_cap.
 */
int chan_close_recv_shutdown(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id_out[32],
                              unsigned char *spk_out, uint16_t *spk_len_out,
                              size_t spk_buf_cap);

/*
 * Parse an inbound closing_signed message (msg includes the 2-byte type prefix).
 * Returns 1 on success, 0 if malformed (too short).
 */
int chan_close_recv_closing_signed(const unsigned char *msg, size_t msg_len,
                                    unsigned char channel_id_out[32],
                                    uint64_t *fee_out,
                                    unsigned char sig64_out[64]);

/*
 * "Meet in the middle" fee negotiation step (BOLT #2 §2.3.1).
 *
 * Given our preferred fee and the peer's proposed fee, returns the
 * counter-proposal: the midpoint, rounded toward our_fee.
 * When our_fee == their_fee (or they converge), both sides accept.
 *
 * Convergence: each call moves halfway toward their_fee, so in at most
 * ~log2(|our_fee - their_fee|) steps the fees are equal.
 */
uint64_t chan_close_negotiate_fee(uint64_t our_fee, uint64_t their_fee);

/*
 * Send shutdown to peer via peer_mgr_send.
 * Returns 1 on success, 0 on send failure.
 */
int chan_close_send_shutdown(peer_mgr_t *mgr, int peer_idx,
                              const unsigned char channel_id[32],
                              const unsigned char *scriptpubkey,
                              uint16_t spk_len);

/*
 * Send closing_signed to peer via peer_mgr_send.
 * Returns 1 on success, 0 on send failure.
 */
int chan_close_send_closing_signed(peer_mgr_t *mgr, int peer_idx,
                                    const unsigned char channel_id[32],
                                    uint64_t fee_satoshis,
                                    const unsigned char sig64[64]);

#endif /* SUPERSCALAR_CHAN_CLOSE_H */
