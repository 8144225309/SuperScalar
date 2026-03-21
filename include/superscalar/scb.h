/*
 * scb.h — Static Channel Backup (SCB)
 *
 * Compact per-channel backup for disaster recovery.
 * With just the SCB file + node private key, the peer can help
 * force-close all channels via data_loss_protect / channel_reestablish.
 *
 * Format:
 *   magic[8] "SSSCB001"
 *   n_entries[4 LE]
 *   entries: [peer_pubkey(33) + funding_txid(32) + funding_vout(4 LE)
 *             + local_msat(8 LE) + remote_msat(8 LE) + flags(4 LE)] * n
 *   Total per entry: 89 bytes
 *
 * Reference: LND chanbackup/single.go, CLN plugins/staticbackup.c
 */

#ifndef SUPERSCALAR_SCB_H
#define SUPERSCALAR_SCB_H

#include <stdint.h>
#include <stddef.h>
#include "channel.h"

#define SCB_MAGIC      "SSSCB001"
#define SCB_MAGIC_LEN   8
#define SCB_ENTRY_LEN   (33 + 32 + 4 + 8 + 8 + 4)  /* 89 bytes */
#define SCB_MAX_ENTRIES 256

typedef struct {
    unsigned char peer_pubkey[33];   /* remote node ID (compressed 33 bytes) */
    unsigned char funding_txid[32];  /* funding txid (internal byte order)   */
    uint32_t      funding_vout;      /* funding output index                  */
    uint64_t      local_msat;        /* our balance at backup time            */
    uint64_t      remote_msat;       /* peer balance at backup time           */
    uint32_t      flags;             /* channel flags (close_state etc.)      */
} scb_entry_t;

/*
 * Populate an scb_entry_t from a channel_t and the peer's pubkey.
 * peer_pubkey33: 33-byte compressed pubkey (from peer_mgr entry).
 */
void scb_entry_from_channel(scb_entry_t *e, const channel_t *ch,
                             const unsigned char peer_pubkey33[33]);

/*
 * Write SCB file. Overwrites any existing file.
 * Returns 1 on success, 0 on error.
 */
int scb_save(const char *path, const scb_entry_t *entries, size_t n);

/*
 * Load SCB file. Returns number of entries on success (≥ 0), -1 on error.
 * Fills at most max_entries entries into entries_out.
 * If the file has more than max_entries entries, only the first max_entries
 * are returned but the full count is still returned.
 */
int scb_load(const char *path, scb_entry_t *entries_out, size_t max_entries);

#endif /* SUPERSCALAR_SCB_H */
