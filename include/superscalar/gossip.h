/*
 * gossip.h — BOLT #7 gossip message construction and verification
 *
 * Minimum-viable gossip for LSP node visibility:
 *   1. node_announcement (type 257)  — appear in the routing graph
 *   2. channel_announcement (type 256) — required before node_announcement accepted
 *   3. channel_update (type 258)    — routing policy advertisement
 *   4. gossip_timestamp_filter (type 265) — request gossip since last sync
 *
 * All signatures are 64-byte Schnorr (secp256k1_schnorrsig_sign32) over
 * SHA256(SHA256(type || data_after_signature)).
 */

#ifndef SUPERSCALAR_GOSSIP_H
#define SUPERSCALAR_GOSSIP_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

/* BOLT #7 message types */
#define GOSSIP_MSG_CHANNEL_ANNOUNCEMENT   256
#define GOSSIP_MSG_NODE_ANNOUNCEMENT      257
#define GOSSIP_MSG_CHANNEL_UPDATE         258
#define GOSSIP_MSG_TIMESTAMP_FILTER       265

/* chain_hash for mainnet (genesis block SHA256d, byte-reversed for display) */
extern const unsigned char GOSSIP_CHAIN_HASH_MAINNET[32];
extern const unsigned char GOSSIP_CHAIN_HASH_TESTNET[32];
extern const unsigned char GOSSIP_CHAIN_HASH_SIGNET[32];

/* Return the chain hash for a network name ("mainnet", "signet", "testnet").
   Returns GOSSIP_CHAIN_HASH_MAINNET for NULL or unrecognized names. */
const unsigned char *gossip_chain_hash_for_network(const char *network);

/* channel_update message_flags */
#define GOSSIP_UPDATE_MSGFLAG_HTLC_MAX  0x01  /* htlc_maximum_msat present */

/* channel_update channel_flags */
#define GOSSIP_UPDATE_CHANFLAG_DIRECTION 0x01  /* 0=node1→node2, 1=node2→node1 */
#define GOSSIP_UPDATE_CHANFLAG_DISABLED  0x02  /* channel is disabled */

/*
 * Build and sign a node_announcement message (type 257).
 *
 * Layout after type(2):
 *   signature(64) flen(2) features(flen) timestamp(4) node_id(33)
 *   rgb_color(3) alias(32) addrlen(2) [addr...]
 *
 * Signature covers: SHA256(SHA256(type(2) || flen..addrs))
 * ipv4_addr: dotted-decimal string, or NULL for no address.
 *
 * Returns total message bytes written, or 0 on error.
 */
size_t gossip_build_node_announcement(
    unsigned char *out, size_t out_cap,
    secp256k1_context *ctx,
    const unsigned char node_priv32[32],
    uint32_t         timestamp,
    const unsigned char rgb[3],
    const char      *alias_utf8,    /* up to 32 bytes; padded with NUL */
    const char      *ipv4_addr,     /* "1.2.3.4" or NULL */
    uint16_t         port           /* TCP port; ignored if ipv4_addr==NULL */
);

/*
 * Verify a signed node_announcement.
 * msg: full message starting at type bytes (2 bytes type + 64 bytes sig + data).
 * Returns 1 if signature is valid, 0 otherwise.
 */
int gossip_verify_node_announcement(
    secp256k1_context *ctx,
    const unsigned char *msg, size_t msg_len);

/*
 * Build the unsigned interior of a channel_announcement (type 256).
 * The four 64-byte signatures are left as zero and must be filled by callers.
 *
 * Layout after type(2):
 *   node_sig_1(64) node_sig_2(64) bitcoin_sig_1(64) bitcoin_sig_2(64)
 *   flen(2) features(flen) chain_hash(32) short_channel_id(8)
 *   node_id_1(33) node_id_2(33) bitcoin_key_1(33) bitcoin_key_2(33)
 *
 * Returns total message bytes, or 0 on error.
 */
size_t gossip_build_channel_announcement_unsigned(
    unsigned char *out, size_t out_cap,
    const unsigned char chain_hash32[32],
    uint64_t         short_channel_id,
    const unsigned char node_id_1_33[33],
    const unsigned char node_id_2_33[33],
    const unsigned char bitcoin_key_1_33[33],
    const unsigned char bitcoin_key_2_33[33]
);

/*
 * Build and sign a channel_update message (type 258).
 *
 * Layout after type(2):
 *   signature(64) chain_hash(32) short_channel_id(8) timestamp(4)
 *   message_flags(1) channel_flags(1) cltv_expiry_delta(2)
 *   htlc_minimum_msat(8) fee_base_msat(4) fee_proportional_millionths(4)
 *   [htlc_maximum_msat(8)]   -- present if GOSSIP_UPDATE_MSGFLAG_HTLC_MAX set
 *
 * Returns total message bytes, or 0 on error.
 */
size_t gossip_build_channel_update(
    unsigned char *out, size_t out_cap,
    secp256k1_context *ctx,
    const unsigned char node_priv32[32],
    const unsigned char chain_hash32[32],
    uint64_t         short_channel_id,
    uint32_t         timestamp,
    uint8_t          message_flags,
    uint8_t          channel_flags,
    uint16_t         cltv_expiry_delta,
    uint64_t         htlc_minimum_msat,
    uint32_t         fee_base_msat,
    uint32_t         fee_proportional_millionths,
    uint64_t         htlc_maximum_msat   /* used if HTLC_MAX flag set */
);

/*
 * Build a gossip_timestamp_filter message (type 265).
 * Requests gossip messages with timestamp >= first_timestamp
 * and < first_timestamp + timestamp_range.
 *
 * Returns total message bytes, or 0 on error.
 */
size_t gossip_build_timestamp_filter(
    unsigned char *out, size_t out_cap,
    const unsigned char chain_hash32[32],
    uint32_t         first_timestamp,
    uint32_t         timestamp_range
);

/*
 * Validate a received channel_announcement (type 256).
 * Checks all 4 Schnorr signatures:
 *   node_sig_1  (offset 2)  signed by node_id_1
 *   node_sig_2  (offset 66) signed by node_id_2
 *   bitcoin_sig_1 (offset 130) signed by bitcoin_key_1
 *   bitcoin_sig_2 (offset 194) signed by bitcoin_key_2
 *
 * Signed data: SHA256(SHA256(type(2) || data_after_all_sigs))
 *   = SHA256(SHA256(msg[0..1] || msg[258..end]))
 *   (assuming features_len is at msg[258..259])
 *
 * msg: raw wire bytes including the 2-byte type prefix.
 * Returns 1 if all 4 sigs valid, 0 otherwise.
 */
int gossip_validate_channel_announcement(secp256k1_context *ctx,
                                          const unsigned char *msg, size_t msg_len);

/* BOLT #7 gossip query message types */
#define GOSSIP_MSG_QUERY_SCIDS         261
#define GOSSIP_MSG_REPLY_SCIDS_END     262
#define GOSSIP_MSG_QUERY_RANGE         263
#define GOSSIP_MSG_REPLY_RANGE         264

/* Parse a query_short_channel_ids message (type 261).
   scids_out: array to fill, scids_cap: max entries.
   Returns number of SCIDs parsed, or -1 on error. */
int gossip_parse_query_scids(const unsigned char *msg, size_t msg_len,
                              const unsigned char chain_hash[32],
                              uint64_t *scids_out, int scids_cap);

/* Build a reply_short_channel_ids_end (type 262).
   complete: 1 if all SCIDs were sent, 0 otherwise. */
size_t gossip_build_reply_scids_end(unsigned char *out, size_t out_cap,
                                     const unsigned char chain_hash[32],
                                     int complete);

/* Parse a query_channel_range message (type 263). */
int gossip_parse_query_range(const unsigned char *msg, size_t msg_len,
                              unsigned char chain_hash_out[32],
                              uint32_t *first_blocknum, uint32_t *num_blocks);

/* Build a reply_channel_range message (type 264). */
size_t gossip_build_reply_range(unsigned char *out, size_t out_cap,
                                 const unsigned char chain_hash[32],
                                 uint32_t first_blocknum, uint32_t num_blocks,
                                 const uint64_t *scids, int n_scids,
                                 int complete);

#endif /* SUPERSCALAR_GOSSIP_H */
