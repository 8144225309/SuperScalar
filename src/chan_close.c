/*
 * chan_close.c — BOLT #2 cooperative channel close wire protocol
 *
 * See chan_close.h for the full API description.
 *
 * Spec: BOLT #2 §2.3.
 * Reference: CLN closingd/closingd.c, LDK channel.rs, LND lnwallet/channel.go.
 */

#include "superscalar/chan_close.h"
#include "superscalar/peer_mgr.h"
#include "superscalar/htlc_commit.h"   /* BOLT2_SHUTDOWN, BOLT2_CLOSING_SIGNED */
#include <string.h>
#include <stdint.h>

/* ---- Serialisation helpers (same convention as chan_open.c) ---- */

static void put_u16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}
static void put_u64(unsigned char *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) b[7-i] = (unsigned char)(v >> (i*8));
}
static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint64_t get_u64(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* ---- Message builders ---- */

size_t chan_close_build_shutdown(const unsigned char channel_id[32],
                                  const unsigned char *scriptpubkey,
                                  uint16_t spk_len,
                                  unsigned char *buf, size_t buf_cap)
{
    size_t msg_len = 2 + 32 + 2 + spk_len;
    if (buf_cap < msg_len) return 0;

    size_t pos = 0;
    put_u16(buf + pos, BOLT2_SHUTDOWN);    pos += 2;
    memcpy(buf + pos, channel_id, 32);     pos += 32;
    put_u16(buf + pos, spk_len);           pos += 2;
    memcpy(buf + pos, scriptpubkey, spk_len); pos += spk_len;

    return pos;
}

size_t chan_close_build_closing_signed(const unsigned char channel_id[32],
                                        uint64_t fee_satoshis,
                                        const unsigned char sig64[64],
                                        unsigned char *buf, size_t buf_cap)
{
    /* Fixed size: type(2) + channel_id(32) + fee(8) + sig(64) = 106 bytes */
    if (buf_cap < 106) return 0;

    size_t pos = 0;
    put_u16(buf + pos, BOLT2_CLOSING_SIGNED); pos += 2;
    memcpy(buf + pos, channel_id, 32);         pos += 32;
    put_u64(buf + pos, fee_satoshis);          pos += 8;
    memcpy(buf + pos, sig64, 64);              pos += 64;

    return pos;   /* 106 */
}

/* ---- Message parsers ---- */

int chan_close_recv_shutdown(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id_out[32],
                              unsigned char *spk_out, uint16_t *spk_len_out,
                              size_t spk_buf_cap)
{
    /* Minimum: type(2) + channel_id(32) + len(2) = 36 bytes */
    if (msg_len < 36) return 0;
    if (get_u16(msg) != BOLT2_SHUTDOWN) return 0;

    memcpy(channel_id_out, msg + 2, 32);
    uint16_t spk_len = get_u16(msg + 34);

    if (msg_len < (size_t)(36 + spk_len)) return 0;
    if (spk_len > spk_buf_cap) return 0;

    memcpy(spk_out, msg + 36, spk_len);
    *spk_len_out = spk_len;
    return 1;
}

int chan_close_recv_closing_signed(const unsigned char *msg, size_t msg_len,
                                    unsigned char channel_id_out[32],
                                    uint64_t *fee_out,
                                    unsigned char sig64_out[64])
{
    /* Fixed: type(2) + channel_id(32) + fee(8) + sig(64) = 106 bytes */
    if (msg_len < 106) return 0;
    if (get_u16(msg) != BOLT2_CLOSING_SIGNED) return 0;

    memcpy(channel_id_out, msg + 2, 32);
    *fee_out = get_u64(msg + 34);
    memcpy(sig64_out, msg + 42, 64);
    return 1;
}

/* ---- Fee negotiation ---- */

uint64_t chan_close_negotiate_fee(uint64_t our_fee, uint64_t their_fee)
{
    if (our_fee == their_fee) return our_fee;
    /* Midpoint, rounded toward our_fee (i.e. floor toward their_fee) */
    return (our_fee + their_fee) / 2;
}

/* ---- High-level senders ---- */

int chan_close_send_shutdown(peer_mgr_t *mgr, int peer_idx,
                              const unsigned char channel_id[32],
                              const unsigned char *scriptpubkey,
                              uint16_t spk_len)
{
    unsigned char buf[2 + 32 + 2 + CHAN_CLOSE_MAX_SPK_LEN];
    size_t len = chan_close_build_shutdown(channel_id, scriptpubkey, spk_len,
                                           buf, sizeof(buf));
    if (!len) return 0;
    return peer_mgr_send(mgr, peer_idx, buf, len);
}

int chan_close_send_closing_signed(peer_mgr_t *mgr, int peer_idx,
                                    const unsigned char channel_id[32],
                                    uint64_t fee_satoshis,
                                    const unsigned char sig64[64])
{
    unsigned char buf[106];
    size_t len = chan_close_build_closing_signed(channel_id, fee_satoshis, sig64,
                                                  buf, sizeof(buf));
    if (!len) return 0;
    return peer_mgr_send(mgr, peer_idx, buf, len);
}
