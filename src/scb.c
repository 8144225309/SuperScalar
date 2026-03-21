/*
 * scb.c — Static Channel Backup (SCB)
 *
 * See scb.h for format description.
 * Reference: LND chanbackup/single.go, CLN plugins/staticbackup.c
 */

#include "superscalar/scb.h"
#include <string.h>
#include <stdio.h>

/* --- Little-endian helpers (no alignment required) --- */

static void put_le32(unsigned char *b, uint32_t v)
{
    b[0] = (unsigned char)(v);
    b[1] = (unsigned char)(v >> 8);
    b[2] = (unsigned char)(v >> 16);
    b[3] = (unsigned char)(v >> 24);
}

static void put_le64(unsigned char *b, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        b[i] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
}

static uint32_t get_le32(const unsigned char *b)
{
    return (uint32_t)b[0]
         | ((uint32_t)b[1] << 8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
}

static uint64_t get_le64(const unsigned char *b)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | b[i];
    return v;
}

/* --- Public API --- */

void scb_entry_from_channel(scb_entry_t *e, const channel_t *ch,
                             const unsigned char peer_pubkey33[33])
{
    memset(e, 0, sizeof(*e));
    if (peer_pubkey33)
        memcpy(e->peer_pubkey, peer_pubkey33, 33);
    memcpy(e->funding_txid, ch->funding_txid, 32);
    e->funding_vout = ch->funding_vout;
    e->local_msat   = ch->local_amount;
    e->remote_msat  = ch->remote_amount;
    e->flags        = (uint32_t)ch->close_state;
}

int scb_save(const char *path, const scb_entry_t *entries, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;

    /* Header: magic + entry count */
    if (fwrite(SCB_MAGIC, 1, SCB_MAGIC_LEN, f) != SCB_MAGIC_LEN) {
        fclose(f); return 0;
    }
    unsigned char hdr[4];
    put_le32(hdr, (uint32_t)n);
    if (fwrite(hdr, 1, 4, f) != 4) {
        fclose(f); return 0;
    }

    /* Entries */
    for (size_t i = 0; i < n; i++) {
        unsigned char buf[SCB_ENTRY_LEN];
        memcpy(buf,      entries[i].peer_pubkey,  33);
        memcpy(buf + 33, entries[i].funding_txid, 32);
        put_le32(buf + 65, entries[i].funding_vout);
        put_le64(buf + 69, entries[i].local_msat);
        put_le64(buf + 77, entries[i].remote_msat);
        put_le32(buf + 85, entries[i].flags);
        if (fwrite(buf, 1, SCB_ENTRY_LEN, f) != (size_t)SCB_ENTRY_LEN) {
            fclose(f); return 0;
        }
    }

    fclose(f);
    return 1;
}

int scb_load(const char *path, scb_entry_t *entries_out, size_t max_entries)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Verify magic */
    char magic[SCB_MAGIC_LEN];
    if (fread(magic, 1, SCB_MAGIC_LEN, f) != (size_t)SCB_MAGIC_LEN
            || memcmp(magic, SCB_MAGIC, SCB_MAGIC_LEN) != 0) {
        fclose(f); return -1;
    }

    /* Read entry count */
    unsigned char hdr[4];
    if (fread(hdr, 1, 4, f) != 4) {
        fclose(f); return -1;
    }
    uint32_t n = get_le32(hdr);
    if (n > SCB_MAX_ENTRIES) {
        fclose(f); return -1;
    }

    /* Read entries (up to max_entries) */
    size_t to_fill = (n < (uint32_t)max_entries) ? n : (uint32_t)max_entries;
    for (size_t i = 0; i < to_fill; i++) {
        unsigned char buf[SCB_ENTRY_LEN];
        if (fread(buf, 1, SCB_ENTRY_LEN, f) != (size_t)SCB_ENTRY_LEN) {
            fclose(f); return -1;
        }
        memcpy(entries_out[i].peer_pubkey,  buf,      33);
        memcpy(entries_out[i].funding_txid, buf + 33, 32);
        entries_out[i].funding_vout = get_le32(buf + 65);
        entries_out[i].local_msat   = get_le64(buf + 69);
        entries_out[i].remote_msat  = get_le64(buf + 77);
        entries_out[i].flags        = get_le32(buf + 85);
    }

    fclose(f);
    return (int)n;
}
