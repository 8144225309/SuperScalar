/*
 * peer_storage.h — BOLT #9 peer storage messages (types 7 and 9)
 *
 * Peer storage allows a node to ask its channel peer to hold an encrypted
 * backup blob (e.g. a Static Channel Backup).  If the node loses data, it
 * can reconnect and ask for the blob back.
 *
 * Message types (BOLT #9 / peer-storage feature):
 *   7  peer_storage          — "please store this blob for me"
 *   9  your_peer_storage     — "here is your stored blob"
 *
 * Wire format (both messages identical except for type byte):
 *   type(2) + blob_len(2) + blob(blob_len)
 *
 * Reference: BOLT #9 §peer-storage, CLN peer_storage plugin, ACINQ impl.
 */

#ifndef SUPERSCALAR_PEER_STORAGE_H
#define SUPERSCALAR_PEER_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include "peer_mgr.h"

/* BOLT #9 type numbers for peer storage */
#define BOLT9_PEER_STORAGE       7   /* node → peer: store this */
#define BOLT9_YOUR_PEER_STORAGE  9   /* peer → node: here is yours */

/* Maximum blob size (64 KiB is the BOLT #9 limit) */
#define PEER_STORAGE_MAX_BLOB  65535

/*
 * Build a peer_storage or your_peer_storage message into buf.
 * type must be BOLT9_PEER_STORAGE (7) or BOLT9_YOUR_PEER_STORAGE (9).
 * Wire: type(2) + blob_len(2) + blob(blob_len)
 * Returns message length on success, 0 if buf_cap is too small.
 */
size_t peer_storage_build(uint16_t type,
                           const unsigned char *blob, uint16_t blob_len,
                           unsigned char *buf, size_t buf_cap);

/*
 * Parse a peer_storage or your_peer_storage message.
 * type_out receives 7 or 9.
 * blob_out must point to a buffer of at least blob_buf_cap bytes.
 * Returns 1 on success, 0 if malformed or blob_len > blob_buf_cap.
 */
int peer_storage_parse(const unsigned char *msg, size_t msg_len,
                        uint16_t *type_out,
                        unsigned char *blob_out, uint16_t *blob_len_out,
                        size_t blob_buf_cap);

/*
 * Send peer_storage (type 7) to peer via peer_mgr_send.
 * Returns 1 on success, 0 on failure.
 */
int peer_storage_send(peer_mgr_t *mgr, int peer_idx,
                       const unsigned char *blob, uint16_t blob_len);

/*
 * Send your_peer_storage (type 9) to peer via peer_mgr_send.
 * Returns 1 on success, 0 on failure.
 */
int peer_storage_send_reply(peer_mgr_t *mgr, int peer_idx,
                              const unsigned char *blob, uint16_t blob_len);

#endif /* SUPERSCALAR_PEER_STORAGE_H */
