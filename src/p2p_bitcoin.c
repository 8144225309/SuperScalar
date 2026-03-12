#include "superscalar/p2p_bitcoin.h"
#include "superscalar/sha256.h"
#include "superscalar/wire.h"    /* wire_connect_direct_internal */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Network magic bytes (4-byte little-endian prefix on every message)
 * ------------------------------------------------------------------------- */

static void set_magic(uint8_t magic[4], const char *network)
{
    if (network && strcmp(network, "mainnet") == 0) {
        magic[0]=0xF9; magic[1]=0xBE; magic[2]=0xB4; magic[3]=0xD9;
    } else if (network && (strcmp(network, "testnet") == 0 ||
                            strcmp(network, "testnet3") == 0)) {
        magic[0]=0x0B; magic[1]=0x11; magic[2]=0x09; magic[3]=0x07;
    } else if (network && strcmp(network, "signet") == 0) {
        magic[0]=0x0A; magic[1]=0x03; magic[2]=0xCF; magic[3]=0x40;
    } else {
        /* regtest (default) */
        magic[0]=0xFA; magic[1]=0xBF; magic[2]=0xB5; magic[3]=0xDA;
    }
}

/* -------------------------------------------------------------------------
 * Wire helpers
 * ------------------------------------------------------------------------- */

static void write_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void write_le64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]         |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* First 4 bytes of SHA256d(payload) — used as the P2P message checksum */
static void p2p_checksum(const uint8_t *data, size_t len, uint8_t out[4])
{
    unsigned char h[32];
    sha256_double(data, len, h);
    memcpy(out, h, 4);
}

/* Known checksum for an empty payload (SHA256d("") first 4 bytes) */
static const uint8_t CKSUM_EMPTY[4] = {0x5d, 0xf6, 0xe0, 0xe2};

/* Block until exactly n bytes have been read from fd.
   Returns 1 on success, 0 on short read or error. */
static int read_exact(int fd, uint8_t *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, buf + done, n - done);
        if (r <= 0) return 0;
        done += (size_t)r;
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * Low-level message send / receive
 * ------------------------------------------------------------------------- */

int p2p_send_msg(p2p_conn_t *conn, const char *command,
                 const uint8_t *payload, uint32_t payload_len)
{
    uint8_t header[24];

    memcpy(header, conn->magic, 4);
    memset(header + 4, 0, 12);
    strncpy((char *)(header + 4), command, 12);
    write_le32(header + 16, payload_len);

    if (payload_len == 0) {
        memcpy(header + 20, CKSUM_EMPTY, 4);
    } else {
        p2p_checksum(payload, payload_len, header + 20);
    }

    if (write(conn->fd, header, 24) != 24) return 0;
    if (payload_len > 0) {
        if (write(conn->fd, payload, payload_len) != (ssize_t)payload_len)
            return 0;
    }
    return 1;
}

int p2p_recv_msg(p2p_conn_t *conn, char command_out[13], uint8_t **payload_out)
{
    *payload_out = NULL;

    uint8_t header[24];
    if (!read_exact(conn->fd, header, 24)) return -1;

    if (memcmp(header, conn->magic, 4) != 0) return -1;

    memcpy(command_out, header + 4, 12);
    command_out[12] = '\0';

    uint32_t len = read_le32(header + 16);
    if (len > P2P_MAX_PAYLOAD) return -1;

    if (len == 0) {
        /* Verify empty-payload checksum */
        if (memcmp(header + 20, CKSUM_EMPTY, 4) != 0) return -1;
        return 0;
    }

    uint8_t *payload = malloc(len);
    if (!payload) return -1;

    if (!read_exact(conn->fd, payload, len)) {
        free(payload);
        return -1;
    }

    uint8_t cksum[4];
    p2p_checksum(payload, len, cksum);
    if (memcmp(cksum, header + 20, 4) != 0) {
        free(payload);
        return -1;
    }

    *payload_out = payload;
    return (int)len;
}

/* -------------------------------------------------------------------------
 * Version / verack handshake
 * ------------------------------------------------------------------------- */

/* Build and send a minimal version message with BIP 157 support (v70016).
   We advertise NODE_NONE services (light client — we don't serve data).
   relay=0 tells the peer not to push unsolicited transactions at us. */
static int send_version(p2p_conn_t *conn)
{
    uint8_t buf[102];
    size_t  n = 0;

    write_le32(buf + n, 70016);             n += 4;  /* version       */
    write_le64(buf + n, 0);                 n += 8;  /* services: none */
    write_le64(buf + n, (uint64_t)time(NULL)); n += 8; /* timestamp   */

    /* addr_recv (26 bytes): services + 16-byte IPv6 addr + port */
    write_le64(buf + n, 0);  n += 8;
    memset(buf + n, 0, 16);  n += 16;       /* addr */
    write_le16(buf + n, 8333); n += 2;      /* port (ignored for recv) */

    /* addr_from (26 bytes): same structure, all zeros */
    write_le64(buf + n, 0);  n += 8;
    memset(buf + n, 0, 16);  n += 16;
    write_le16(buf + n, 0);  n += 2;

    write_le64(buf + n, 0);  n += 8;        /* nonce             */
    buf[n++] = 0;                            /* user_agent: ""    */
    write_le32(buf + n, 0);  n += 4;        /* start_height: 0   */
    buf[n++] = 0;                            /* relay: false      */

    return p2p_send_msg(conn, "version", buf, (uint32_t)n);
}

int p2p_connect(p2p_conn_t *conn, const char *host, int port,
                const char *network)
{
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    set_magic(conn->magic, network);

    conn->fd = wire_connect_direct_internal(host, port);
    if (conn->fd < 0) return 0;

    if (!send_version(conn)) { p2p_close(conn); return 0; }

    /* Read messages until we have seen both version and verack from peer.
       A well-behaved node sends version first, then verack after we ack.
       We send our verack immediately upon receiving the peer's version. */
    int got_version = 0, got_verack = 0;
    for (int i = 0; i < 20 && (!got_version || !got_verack); i++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) { p2p_close(conn); return 0; }

        if (strcmp(cmd, "version") == 0) {
            if (plen >= 4) conn->peer_version = read_le32(payload);
            got_version = 1;
            /* Reply immediately with our verack */
            p2p_send_msg(conn, "verack", NULL, 0);
        } else if (strncmp(cmd, "verack", 6) == 0) {
            got_verack = 1;
        }
        /* Ignore other messages (e.g. sendheaders, sendcmpct) during handshake */
        free(payload);
    }

    if (!got_version || !got_verack) { p2p_close(conn); return 0; }
    return 1;
}

void p2p_close(p2p_conn_t *conn)
{
    if (conn && conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

/* -------------------------------------------------------------------------
 * BIP 157 compact filter download
 * ------------------------------------------------------------------------- */

int p2p_send_getcfilters(p2p_conn_t *conn, uint32_t start_height,
                         const uint8_t *stop_hash32)
{
    uint8_t buf[37];
    buf[0] = P2P_FILTER_BASIC;
    write_le32(buf + 1, start_height);
    memcpy(buf + 5, stop_hash32, 32);
    return p2p_send_msg(conn, "getcfilters", buf, 37);
}

int p2p_recv_cfilter(p2p_conn_t *conn,
                     uint8_t  block_hash32_out[32],
                     uint8_t **filter_out, size_t *filter_len_out,
                     uint8_t  key_out[16])
{
    /* Read messages, transparently handling keepalives, until cfilter arrives.
       Limit iterations to avoid spinning forever on a chatty peer. */
    for (int i = 0; i < 64; i++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) return -1;

        if (strcmp(cmd, "ping") == 0) {
            /* Reflect payload back as pong (keepalive) */
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "cfilter") == 0) {
            /* Payload: filter_type(1) + block_hash(32) + filter_bytes */
            if (plen < 33) { free(payload); return 0; }

            memcpy(block_hash32_out, payload + 1, 32);
            /* SipHash key for this filter = first 16 bytes of block hash */
            memcpy(key_out, payload + 1, 16);

            size_t   flen  = (size_t)(plen - 33);
            uint8_t *fdata = malloc(flen > 0 ? flen : 1);
            if (!fdata) { free(payload); return 0; }
            if (flen > 0) memcpy(fdata, payload + 33, flen);
            *filter_out     = fdata;
            *filter_len_out = flen;
            free(payload);
            return 1;
        }

        /* Ignore all other message types */
        free(payload);
    }

    return 0;  /* timed out waiting for cfilter */
}

/* -------------------------------------------------------------------------
 * Transaction broadcast
 * ------------------------------------------------------------------------- */

int p2p_broadcast_tx(p2p_conn_t *conn,
                     const uint8_t *tx_bytes, size_t tx_len,
                     uint8_t txid32_out[32])
{
    /* Compute txid = SHA256d(raw_tx) */
    uint8_t txid[32];
    sha256_double(tx_bytes, tx_len, txid);
    if (txid32_out) memcpy(txid32_out, txid, 32);

    /* Send inv(MSG_TX, txid) to announce the transaction */
    uint8_t inv_buf[37];
    inv_buf[0] = 0x01;               /* varint count = 1 */
    write_le32(inv_buf + 1, 1);      /* MSG_TX = 1       */
    memcpy(inv_buf + 5, txid, 32);
    if (!p2p_send_msg(conn, "inv", inv_buf, 37)) return 0;

    /* Wait for peer to request it via getdata, then send the tx payload.
       Limit to 8 iterations to skip unrelated messages. */
    for (int i = 0; i < 8; i++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) return 0;

        if (strcmp(cmd, "ping") == 0) {
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "getdata") == 0) {
            free(payload);
            return p2p_send_msg(conn, "tx",
                                tx_bytes, (uint32_t)tx_len);
        }

        free(payload);
    }

    return 0;  /* peer never requested the tx */
}
