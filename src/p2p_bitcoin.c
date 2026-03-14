#include "superscalar/p2p_bitcoin.h"
#include "superscalar/sha256.h"
#include "superscalar/wire.h"    /* wire_connect_direct_internal */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

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

/* Ports in Bitcoin P2P addr structures are big-endian (network byte order) */
static void write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
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

static uint64_t read_le64(const uint8_t *p)
{
    return (uint64_t)p[0]          | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16)  | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32)  | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48)  | ((uint64_t)p[7] << 56);
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
    memcpy(header + 4, command, strnlen(command, 12));
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

    /* addr_recv (26 bytes): services + 16-byte IPv6 addr + port (BE per spec) */
    write_le64(buf + n, 0);  n += 8;
    memset(buf + n, 0, 16);  n += 16;       /* addr */
    write_be16(buf + n, 8333); n += 2;      /* port big-endian (ignored for recv) */

    /* addr_from (26 bytes): same structure, all zeros */
    write_le64(buf + n, 0);  n += 8;
    memset(buf + n, 0, 16);  n += 16;
    write_be16(buf + n, 0);  n += 2;

    write_le64(buf + n, 0);  n += 8;        /* nonce             */
    buf[n++] = 0;                            /* user_agent: ""    */
    write_le32(buf + n, 0);  n += 4;        /* start_height: 0   */
    buf[n++] = 0;                            /* relay: false      */

    return p2p_send_msg(conn, "version", buf, (uint32_t)n);
}

int p2p_do_version_handshake(p2p_conn_t *conn)
{
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
            if (plen >= 4)  conn->peer_version  = read_le32(payload);
            if (plen >= 12) conn->peer_services = read_le64(payload + 4);
            /* Parse start_height: version(4)+services(8)+time(8)+addr_recv(26)+
               addr_from(26)+nonce(8) = 80 bytes, then user_agent varint+string,
               then start_height(4 LE). */
            if (plen > 80) {
                const uint8_t *p   = payload + 80;
                size_t         rem = (size_t)(plen - 80);
                size_t ua_skip = 1;
                if (p[0] == 0xfd && rem >= 3) ua_skip = 3 + ((size_t)p[1] | ((size_t)p[2] << 8));
                else                           ua_skip = 1 + p[0];
                if (ua_skip < rem && rem - ua_skip >= 4)
                    conn->peer_start_height = (int32_t)read_le32(p + ua_skip);
            }
            got_version = 1;
            /* Reply immediately with our verack */
            p2p_send_msg(conn, "verack", NULL, 0);
        } else if (strncmp(cmd, "verack", 6) == 0) {
            got_verack = 1;
        } else if (strncmp(cmd, "feefilter", 9) == 0 && plen >= 8) {
            /* BIP 133: peer's mempool minimum fee rate (sat/kvB as 8-byte LE) */
            conn->peer_feefilter_sat_per_kvb = read_le64(payload);
        }
        /* Ignore other messages (e.g. sendheaders, sendcmpct) during handshake */
        free(payload);
    }

    if (!got_version || !got_verack) { p2p_close(conn); return 0; }
    /* Require BIP 157 support (protocol version 70016+) */
    if (conn->peer_version < 70016) { p2p_close(conn); return 0; }
    /* Require NODE_COMPACT_FILTERS service bit — don't connect to nodes that
       can't serve BIP 157 compact filters (would fail at getcfilters anyway). */
    if (!(conn->peer_services & NODE_COMPACT_FILTERS)) { p2p_close(conn); return 0; }
    return 1;
}

int p2p_connect(p2p_conn_t *conn, const char *host, int port,
                const char *network)
{
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    set_magic(conn->magic, network);

    conn->fd = wire_connect_direct_internal(host, port);
    if (conn->fd < 0) return 0;

    /* 30-second receive timeout — prevents blocking forever on a stalled peer */
    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return p2p_do_version_handshake(conn);
}

void p2p_close(p2p_conn_t *conn)
{
    if (conn && conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

/* -------------------------------------------------------------------------
 * Block header download (getheaders / headers)
 * ------------------------------------------------------------------------- */

int p2p_send_getheaders(p2p_conn_t *conn,
                        const uint8_t (*locator_hashes)[32], size_t n_locator,
                        const uint8_t *stop_hash32)
{
    /* version(4) + varint(1-3) + n_locator*32 + stop_hash(32) */
    size_t   buf_size = 4 + 9 + n_locator * 32 + 32;
    uint8_t *buf      = malloc(buf_size);
    if (!buf) return 0;

    size_t n = 0;
    write_le32(buf + n, 70016); n += 4;

    /* CompactSize varint for locator hash count */
    if (n_locator < 0xfd) {
        buf[n++] = (uint8_t)n_locator;
    } else {
        buf[n++] = 0xfd;
        buf[n++] = (uint8_t)(n_locator & 0xff);
        buf[n++] = (uint8_t)((n_locator >> 8) & 0xff);
    }

    for (size_t i = 0; i < n_locator; i++) {
        memcpy(buf + n, locator_hashes[i], 32);
        n += 32;
    }

    /* stop_hash: all zeros = "as many as possible" */
    if (stop_hash32) memcpy(buf + n, stop_hash32, 32);
    else             memset(buf + n, 0, 32);
    n += 32;

    int ok = p2p_send_msg(conn, "getheaders", buf, (uint32_t)n);
    free(buf);
    return ok;
}

int p2p_recv_headers(p2p_conn_t *conn,
                     uint8_t (*hashes_out)[32], size_t max_headers)
{
    for (int attempt = 0; attempt < 64; attempt++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) return -1;

        if (strcmp(cmd, "ping") == 0) {
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "headers") == 0) {
            if (plen < 1) { free(payload); return 0; }

            const uint8_t *p   = payload;
            size_t         rem = (size_t)plen;

            /* Parse CompactSize count */
            uint64_t count;
            size_t   varint_len;
            if (p[0] < 0xfd) {
                count      = p[0];
                varint_len = 1;
            } else if (p[0] == 0xfd && rem >= 3) {
                count      = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
                varint_len = 3;
            } else {
                free(payload);
                return 0;
            }
            p   += varint_len;
            rem -= varint_len;

            /* Each entry: 80-byte header + 1-byte tx_count varint (always 0x00) */
            size_t n_stored = 0;
            for (uint64_t i = 0; i < count; i++) {
                if (rem < 81) break;
                if (n_stored < max_headers && hashes_out)
                    sha256_double(p, 80, hashes_out[n_stored++]);
                p   += 81;
                rem -= 81;
            }

            free(payload);
            return (int)n_stored;
        }

        /* Ignore other message types */
        free(payload);
    }

    return 0;
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
            /* Payload: filter_type(1) + block_hash(32) +
             *          num_filter_bytes(CompactSize) + filter_bytes */
            if (plen < 34) { free(payload); return 0; }

            memcpy(block_hash32_out, payload + 1, 32);
            /* SipHash key for this filter = first 16 bytes of block hash
             * (already in internal byte order in the P2P message) */
            memcpy(key_out, payload + 1, 16);

            /* Skip the CompactSize length prefix */
            const uint8_t *p   = payload + 33;
            size_t         rem = (size_t)(plen - 33);
            uint64_t       filter_byte_count = 0;
            size_t         varint_len;
            if (p[0] < 0xfd) {
                filter_byte_count = p[0];
                varint_len = 1;
            } else if (p[0] == 0xfd && rem >= 3) {
                filter_byte_count = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
                varint_len = 3;
            } else if (p[0] == 0xfe && rem >= 5) {
                filter_byte_count = (uint64_t)p[1] | ((uint64_t)p[2] << 8) |
                                    ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24);
                varint_len = 5;
            } else {
                free(payload); return 0;
            }
            if (rem < varint_len + filter_byte_count) { free(payload); return 0; }

            size_t   flen  = (size_t)filter_byte_count;
            uint8_t *fdata = malloc(flen > 0 ? flen : 1);
            if (!fdata) { free(payload); return 0; }
            if (flen > 0) memcpy(fdata, p + varint_len, flen);
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
 * BIP 157 filter header chain download
 * ------------------------------------------------------------------------- */

int p2p_send_getcfheaders(p2p_conn_t *conn, uint32_t start_height,
                          const uint8_t *stop_hash32)
{
    uint8_t buf[37];
    buf[0] = P2P_FILTER_BASIC;
    write_le32(buf + 1, start_height);
    memcpy(buf + 5, stop_hash32, 32);
    return p2p_send_msg(conn, "getcfheaders", buf, 37);
}

int p2p_recv_cfheaders(p2p_conn_t *conn,
                       uint8_t  stop_hash_out[32],
                       uint8_t  prev_filter_hdr_out[32],
                       uint8_t **headers_out,
                       size_t  *count_out)
{
    *headers_out = NULL;
    *count_out   = 0;

    for (int attempt = 0; attempt < 64; attempt++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) return -1;

        if (strcmp(cmd, "ping") == 0) {
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "cfheaders") == 0) {
            /* Payload layout:
             *   filter_type      (1 byte)
             *   stop_hash        (32 bytes)
             *   prev_filter_hdr  (32 bytes)
             *   header_count     (CompactSize varint)
             *   filter_headers[] (count × 32 bytes) */
            if (plen < 66) { free(payload); return 0; }

            memcpy(stop_hash_out,       payload + 1,  32);
            memcpy(prev_filter_hdr_out, payload + 33, 32);

            const uint8_t *p   = payload + 65;
            size_t         rem = (size_t)(plen - 65);

            uint64_t count;
            size_t   varint_len;
            if (p[0] < 0xfd) {
                count      = p[0];
                varint_len = 1;
            } else if (p[0] == 0xfd && rem >= 3) {
                count      = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
                varint_len = 3;
            } else if (p[0] == 0xfe && rem >= 5) {
                count      = (uint64_t)p[1] | ((uint64_t)p[2] <<  8) |
                             ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24);
                varint_len = 5;
            } else {
                free(payload); return 0;
            }

            if (rem < varint_len + count * 32) { free(payload); return 0; }

            size_t   hlen = (size_t)count * 32;
            uint8_t *hdrs = malloc(hlen > 0 ? hlen : 1);
            if (!hdrs) { free(payload); return 0; }
            if (hlen > 0) memcpy(hdrs, p + varint_len, hlen);

            *headers_out = hdrs;
            *count_out   = (size_t)count;
            free(payload);
            return 1;
        }

        free(payload);
    }

    return 0;  /* timed out waiting for cfheaders */
}

/* -------------------------------------------------------------------------
 * Block download and transaction scanning
 * ------------------------------------------------------------------------- */

/* Decode one CompactSize varint.  Returns 1 on success, 0 on insufficient
   data.  Sets *val and *consumed on success. */
static int parse_varint_block(const uint8_t *p, size_t rem,
                               uint64_t *val, size_t *consumed)
{
    if (rem < 1) return 0;
    if (p[0] < 0xfd) {
        *val = p[0]; *consumed = 1; return 1;
    } else if (p[0] == 0xfd && rem >= 3) {
        *val = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
        *consumed = 3; return 1;
    } else if (p[0] == 0xfe && rem >= 5) {
        *val = (uint64_t)p[1] | ((uint64_t)p[2] <<  8) |
               ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24);
        *consumed = 5; return 1;
    } else if (p[0] == 0xff && rem >= 9) {
        *val = (uint64_t)p[1]       | ((uint64_t)p[2] <<  8) |
               ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24) |
               ((uint64_t)p[5] << 32) | ((uint64_t)p[6] << 40) |
               ((uint64_t)p[7] << 48) | ((uint64_t)p[8] << 56);
        *consumed = 9; return 1;
    }
    return 0;
}

int p2p_send_getdata_block(p2p_conn_t *conn, const uint8_t *block_hash32)
{
    /* inv: count=1 (varint) + type(4 LE MSG_BLOCK=2) + hash(32) */
    uint8_t buf[37];
    buf[0] = 0x01;
    write_le32(buf + 1, 2);  /* MSG_BLOCK */
    memcpy(buf + 5, block_hash32, 32);
    return p2p_send_msg(conn, "getdata", buf, 37);
}

int p2p_recv_block(p2p_conn_t *conn,
                   uint8_t **block_out, size_t *block_len_out)
{
    *block_out     = NULL;
    *block_len_out = 0;

    for (int attempt = 0; attempt < 64; attempt++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) return -1;

        if (strcmp(cmd, "ping") == 0) {
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "block") == 0) {
            *block_out     = payload;
            *block_len_out = (size_t)plen;
            return 1;
        }

        free(payload);
    }

    return 0;  /* timed out waiting for block */
}

int p2p_scan_block_txs(const uint8_t *block, size_t block_len,
                       p2p_block_scan_cb_t callback, void *ctx)
{
    if (!block || block_len < 81) return -1;  /* header(80) + tx_count(1) */

    const uint8_t *p   = block + 80;
    size_t         rem = block_len - 80;

    uint64_t tx_count; size_t vl;
    if (!parse_varint_block(p, rem, &tx_count, &vl)) return -1;
    p += vl; rem -= vl;

    static const char hx[] = "0123456789abcdef";
    int processed = 0;

    for (uint64_t tx_i = 0; tx_i < tx_count; tx_i++) {
        if (rem < 4) return -1;
        const uint8_t *tx_start = p;

        p += 4; rem -= 4;  /* version */

        /* Detect segwit marker (0x00) + flag (0x01) */
        int segwit = (rem >= 2 && p[0] == 0x00 && p[1] == 0x01);
        if (segwit) { p += 2; rem -= 2; }

        const uint8_t *inputs_start = p;  /* for segwit txid */

        /* Skip inputs */
        uint64_t vin_count;
        if (!parse_varint_block(p, rem, &vin_count, &vl)) return -1;
        p += vl; rem -= vl;

        for (uint64_t i = 0; i < vin_count; i++) {
            if (rem < 36) return -1;  /* txid(32) + vout(4) */
            p += 36; rem -= 36;
            uint64_t ss_len;
            if (!parse_varint_block(p, rem, &ss_len, &vl)) return -1;
            if (rem < vl + ss_len) return -1;
            p += vl + ss_len; rem -= vl + ss_len;
            if (rem < 4) return -1;  /* sequence */
            p += 4; rem -= 4;
        }
        const uint8_t *inputs_end = p;

        /* Parse outputs — collect scriptPubKey pointers into the block buffer */
        uint64_t vout_count;
        if (!parse_varint_block(p, rem, &vout_count, &vl)) return -1;
        p += vl; rem -= vl;

        if (vout_count > 4096) return -1;  /* sanity cap */

        const unsigned char **spks    = malloc(vout_count * sizeof(*spks));
        size_t              *spk_lens = malloc(vout_count * sizeof(*spk_lens));
        if (!spks || !spk_lens) { free(spks); free(spk_lens); return -1; }

        for (uint64_t i = 0; i < vout_count; i++) {
            if (rem < 8) { free(spks); free(spk_lens); return -1; }
            p += 8; rem -= 8;  /* value */
            uint64_t spk_len;
            if (!parse_varint_block(p, rem, &spk_len, &vl)) {
                free(spks); free(spk_lens); return -1;
            }
            if (rem < vl + spk_len || spk_len > 10000) {
                free(spks); free(spk_lens); return -1;
            }
            p += vl; rem -= vl;
            spks[i]    = p;
            spk_lens[i] = (size_t)spk_len;
            p += spk_len; rem -= spk_len;
        }
        const uint8_t *outputs_end = p;

        /* Skip witness data */
        if (segwit) {
            for (uint64_t i = 0; i < vin_count; i++) {
                uint64_t n_items;
                if (!parse_varint_block(p, rem, &n_items, &vl)) {
                    free(spks); free(spk_lens); return -1;
                }
                p += vl; rem -= vl;
                for (uint64_t j = 0; j < n_items; j++) {
                    uint64_t item_len;
                    if (!parse_varint_block(p, rem, &item_len, &vl)) {
                        free(spks); free(spk_lens); return -1;
                    }
                    if (rem < vl + item_len) { free(spks); free(spk_lens); return -1; }
                    p += vl + item_len; rem -= vl + item_len;
                }
            }
        }

        if (rem < 4) { free(spks); free(spk_lens); return -1; }  /* locktime */
        p += 4; rem -= 4;

        /* Compute txid */
        uint8_t txid[32];
        if (!segwit) {
            sha256_double(tx_start, (size_t)(p - tx_start), txid);
        } else {
            /* Segwit legacy txid = SHA256d(version || inputs+outputs || locktime)
               Excludes marker/flag/witness; inputs_start is after marker/flag. */
            size_t   io_len     = (size_t)(outputs_end - inputs_start);
            size_t   legacy_len = 4 + io_len + 4;
            uint8_t *legacy     = malloc(legacy_len);
            if (!legacy) { free(spks); free(spk_lens); return -1; }
            memcpy(legacy,             tx_start,    4);       /* version */
            memcpy(legacy + 4,         inputs_start, io_len); /* inputs+outputs */
            memcpy(legacy + 4 + io_len, p - 4,       4);      /* locktime */
            sha256_double(legacy, legacy_len, txid);
            free(legacy);
        }

        /* Display-order hex txid (reversed bytes) */
        char txid_hex[65];
        for (int k = 0; k < 32; k++) {
            txid_hex[(31 - k) * 2]     = hx[(txid[k] >> 4) & 0xf];
            txid_hex[(31 - k) * 2 + 1] = hx[txid[k] & 0xf];
        }
        txid_hex[64] = '\0';

        callback(txid_hex, (size_t)vout_count, spks, spk_lens, ctx);
        free(spks);
        free(spk_lens);
        processed++;

        (void)inputs_end;  /* only used for segwit path; suppress warning */
    }

    return processed;
}

int p2p_scan_block_full(const uint8_t *block, size_t block_len,
                         p2p_output_cb_t output_cb,
                         p2p_input_cb_t input_cb,
                         void *ctx)
{
    if (!block || block_len < 81) return -1;
    if (!output_cb && !input_cb) return 0;

    const uint8_t *p   = block + 80;
    size_t         rem = block_len - 80;

    uint64_t tx_count; size_t vl;
    if (!parse_varint_block(p, rem, &tx_count, &vl)) return -1;
    p += vl; rem -= vl;

    static const char hx[] = "0123456789abcdef";
    int processed = 0;

    for (uint64_t tx_i = 0; tx_i < tx_count; tx_i++) {
        if (rem < 4) return -1;
        const uint8_t *tx_start = p;
        p += 4; rem -= 4;  /* version */

        int segwit = (rem >= 2 && p[0] == 0x00 && p[1] == 0x01);
        if (segwit) { p += 2; rem -= 2; }

        const uint8_t *inputs_start = p;

        /* --- Inputs --- */
        uint64_t vin_count;
        if (!parse_varint_block(p, rem, &vin_count, &vl)) return -1;
        p += vl; rem -= vl;

        /* Collect input prevouts for spending detection */
        uint8_t  (*inp_txids)[32] = NULL;
        uint32_t  *inp_vouts      = NULL;
        if (input_cb && vin_count > 0 && vin_count <= 4096) {
            inp_txids = (uint8_t (*)[32])malloc(vin_count * 32);
            inp_vouts = (uint32_t *)malloc(vin_count * sizeof(uint32_t));
        }

        for (uint64_t i = 0; i < vin_count; i++) {
            if (rem < 36) { free(inp_txids); free(inp_vouts); return -1; }
            if (inp_txids) {
                memcpy(inp_txids[i], p, 32);
                inp_vouts[i] = (uint32_t)p[32] | ((uint32_t)p[33] << 8) |
                               ((uint32_t)p[34] << 16) | ((uint32_t)p[35] << 24);
            }
            p += 36; rem -= 36;
            uint64_t ss_len;
            if (!parse_varint_block(p, rem, &ss_len, &vl)) {
                free(inp_txids); free(inp_vouts); return -1;
            }
            if (rem < vl + ss_len) { free(inp_txids); free(inp_vouts); return -1; }
            p += vl + ss_len; rem -= vl + ss_len;
            if (rem < 4) { free(inp_txids); free(inp_vouts); return -1; }
            p += 4; rem -= 4;
        }
        const uint8_t *inputs_end = p;

        /* --- Outputs --- */
        uint64_t vout_count;
        if (!parse_varint_block(p, rem, &vout_count, &vl)) {
            free(inp_txids); free(inp_vouts); return -1;
        }
        p += vl; rem -= vl;
        if (vout_count > 4096) { free(inp_txids); free(inp_vouts); return -1; }

        /* Collect output info for amount callback */
        uint64_t  *out_amounts = NULL;
        uint8_t  **out_spks    = NULL;
        size_t    *out_spklens = NULL;
        if (output_cb && vout_count > 0) {
            out_amounts = (uint64_t *)malloc(vout_count * sizeof(uint64_t));
            out_spks    = (uint8_t **)malloc(vout_count * sizeof(uint8_t *));
            out_spklens = (size_t *)  malloc(vout_count * sizeof(size_t));
            if (!out_amounts || !out_spks || !out_spklens) {
                free(out_amounts); free(out_spks); free(out_spklens);
                free(inp_txids);   free(inp_vouts);
                return -1;
            }
        }

        for (uint64_t i = 0; i < vout_count; i++) {
            if (rem < 8) { free(out_amounts); free(out_spks); free(out_spklens);
                           free(inp_txids); free(inp_vouts); return -1; }
            uint64_t amt = (uint64_t)p[0] | ((uint64_t)p[1]<<8) | ((uint64_t)p[2]<<16) |
                           ((uint64_t)p[3]<<24) | ((uint64_t)p[4]<<32) | ((uint64_t)p[5]<<40) |
                           ((uint64_t)p[6]<<48) | ((uint64_t)p[7]<<56);
            p += 8; rem -= 8;
            uint64_t spk_len;
            if (!parse_varint_block(p, rem, &spk_len, &vl)) {
                free(out_amounts); free(out_spks); free(out_spklens);
                free(inp_txids);   free(inp_vouts); return -1;
            }
            if (rem < vl + spk_len || spk_len > 10000) {
                free(out_amounts); free(out_spks); free(out_spklens);
                free(inp_txids);   free(inp_vouts); return -1;
            }
            p += vl; rem -= vl;
            if (out_amounts) {
                out_amounts[i] = amt;
                out_spks[i]    = (uint8_t *)p;
                out_spklens[i] = (size_t)spk_len;
            }
            p += spk_len; rem -= spk_len;
        }
        const uint8_t *outputs_end = p;

        /* Skip witness */
        if (segwit) {
            for (uint64_t i = 0; i < vin_count; i++) {
                uint64_t n_items;
                if (!parse_varint_block(p, rem, &n_items, &vl)) {
                    free(out_amounts); free(out_spks); free(out_spklens);
                    free(inp_txids);   free(inp_vouts); return -1;
                }
                p += vl; rem -= vl;
                for (uint64_t j = 0; j < n_items; j++) {
                    uint64_t item_len;
                    if (!parse_varint_block(p, rem, &item_len, &vl)) {
                        free(out_amounts); free(out_spks); free(out_spklens);
                        free(inp_txids);   free(inp_vouts); return -1;
                    }
                    if (rem < vl + item_len) {
                        free(out_amounts); free(out_spks); free(out_spklens);
                        free(inp_txids);   free(inp_vouts); return -1;
                    }
                    p += vl + item_len; rem -= vl + item_len;
                }
            }
        }
        if (rem < 4) { free(out_amounts); free(out_spks); free(out_spklens);
                       free(inp_txids);   free(inp_vouts); return -1; }
        p += 4; rem -= 4;  /* locktime */

        /* Compute txid */
        uint8_t txid[32];
        if (!segwit) {
            sha256_double(tx_start, (size_t)(p - tx_start), txid);
        } else {
            size_t io_len     = (size_t)(outputs_end - inputs_start);
            size_t legacy_len = 4 + io_len + 4;
            uint8_t *legacy   = (uint8_t *)malloc(legacy_len);
            if (!legacy) {
                free(out_amounts); free(out_spks); free(out_spklens);
                free(inp_txids);   free(inp_vouts); return -1;
            }
            memcpy(legacy,              tx_start,     4);
            memcpy(legacy + 4,          inputs_start, io_len);
            memcpy(legacy + 4 + io_len, p - 4,        4);
            sha256_double(legacy, legacy_len, txid);
            free(legacy);
        }

        /* Display-order txid hex */
        char txid_hex[65];
        for (int k = 0; k < 32; k++) {
            txid_hex[(31 - k) * 2]     = hx[(txid[k] >> 4) & 0xf];
            txid_hex[(31 - k) * 2 + 1] = hx[ txid[k]       & 0xf];
        }
        txid_hex[64] = '\0';

        /* Fire output callbacks */
        if (output_cb && out_amounts) {
            for (uint64_t i = 0; i < vout_count; i++)
                output_cb(txid_hex, (uint32_t)i, out_amounts[i],
                          out_spks[i], out_spklens[i], ctx);
        }

        /* Fire input callbacks */
        if (input_cb && inp_txids) {
            for (uint64_t i = 0; i < vin_count; i++)
                input_cb(txid_hex, inp_txids[i], inp_vouts[i], ctx);
        }

        free(out_amounts); free(out_spks); free(out_spklens);
        free(inp_txids);   free(inp_vouts);

        (void)inputs_end;
        processed++;
    }
    return processed;
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

/* -------------------------------------------------------------------------
 * Phase 7: Mempool awareness (BIP 35)
 * ------------------------------------------------------------------------- */

int p2p_send_mempool(p2p_conn_t *conn)
{
    /* The `mempool` message has an empty payload (BIP 35) */
    return p2p_send_msg(conn, "mempool", NULL, 0);
}

int p2p_poll_inv(p2p_conn_t *conn,
                 uint8_t txids_out[][32], int max_txids,
                 int timeout_ms)
{
    if (!conn || conn->fd < 0 || !txids_out || max_txids <= 0) return 0;

    /* Temporarily shorten the receive timeout to avoid blocking */
    struct timeval short_tv;
    short_tv.tv_sec  = timeout_ms / 1000;
    short_tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO,
               &short_tv, sizeof(short_tv));

    int n_txids = 0;

    /* Read up to a small number of messages; stop on timeout or error */
    for (int iter = 0; iter < 32 && n_txids < max_txids; iter++) {
        char     cmd[13];
        uint8_t *payload = NULL;
        int      plen    = p2p_recv_msg(conn, cmd, &payload);

        if (plen < 0) {
            /* EAGAIN / EWOULDBLOCK from short timeout = no more data */
            free(payload);
            break;
        }

        if (strcmp(cmd, "ping") == 0) {
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "inv") == 0 && plen > 0) {
            /* inv payload: varint(count) + [type(4 LE) + hash(32)] * count */
            const uint8_t *p   = payload;
            size_t         rem = (size_t)plen;

            /* Decode varint count */
            if (rem < 1) { free(payload); continue; }
            uint64_t count;
            size_t   vi_len;
            if (p[0] < 0xfd) {
                count  = p[0];
                vi_len = 1;
            } else if (p[0] == 0xfd && rem >= 3) {
                count  = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
                vi_len = 3;
            } else {
                free(payload); continue;
            }
            p   += vi_len;
            rem -= vi_len;

            for (uint64_t i = 0; i < count && rem >= 36 && n_txids < max_txids; i++) {
                uint32_t type;
                memcpy(&type, p, 4);
                type = (uint32_t)(p[0] | ((uint32_t)p[1] << 8) |
                                  ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
                if (type == 1 /* MSG_TX */)
                    memcpy(txids_out[n_txids++], p + 4, 32);
                p   += 36;
                rem -= 36;
            }
        }

        free(payload);
    }

    /* Restore normal 30-second receive timeout */
    struct timeval norm_tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &norm_tv, sizeof(norm_tv));

    return n_txids;
}

/* -------------------------------------------------------------------------
 * Phase B: PoW / nBits header chain validation
 * ------------------------------------------------------------------------- */

/* Decode compact nBits to 32-byte target (big-endian).
   nBits format: top byte = exponent, lower 3 bytes = mantissa.
   Negative/overflow nBits → invalid (return 0). */
static int decode_target(uint32_t nBits, uint8_t target[32])
{
    memset(target, 0, 32);
    uint32_t exponent = (nBits >> 24) & 0xff;
    uint32_t mantissa = nBits & 0x00ffffff;
    /* Reject negative (bit 23 of mantissa set) */
    if (mantissa & 0x00800000) return 0;
    /* Reject overflow: exponent > 32 → too large for 256-bit */
    if (exponent > 32) return 0;
    if (exponent == 0 || mantissa == 0) return 0;
    /* Place mantissa at byte offset (32 - exponent) */
    /* target is big-endian; byte 0 is most significant */
    int offset = (int)exponent - 3;
    if (offset < 0) {
        /* Shift mantissa right by -offset bytes */
        mantissa >>= ((-offset) * 8);
        offset = 0;
    }
    if (offset + 3 > 32) return 0;  /* overflow */
    target[32 - 1 - offset]     = (uint8_t)(mantissa & 0xff);
    target[32 - 1 - (offset+1)] = (uint8_t)((mantissa >> 8) & 0xff);
    target[32 - 1 - (offset+2)] = (uint8_t)((mantissa >> 16) & 0xff);
    return 1;
}

int p2p_validate_header_pow(const uint8_t header80[80])
{
    if (!header80) return 0;

    /* nBits at bytes 72-75, little-endian */
    uint32_t nBits = (uint32_t)header80[72]        |
                     ((uint32_t)header80[73] <<  8) |
                     ((uint32_t)header80[74] << 16) |
                     ((uint32_t)header80[75] << 24);

    /* Decode nBits to 32-byte target */
    uint8_t target[32];
    if (!decode_target(nBits, target)) return 0;  /* invalid nBits */

    /* Compute SHA256d of header */
    uint8_t hash_internal[32];
    sha256_double(header80, 80, hash_internal);

    /* Reverse hash to big-endian for comparison */
    uint8_t hash_be[32];
    for (int i = 0; i < 32; i++)
        hash_be[i] = hash_internal[31 - i];

    /* hash_be < target: compare byte by byte from most significant */
    for (int i = 0; i < 32; i++) {
        if (hash_be[i] < target[i]) return 1;   /* hash < target: valid */
        if (hash_be[i] > target[i]) return 0;   /* hash > target: invalid */
    }
    return 0;  /* hash == target: technically invalid (must be strictly less) */
}

/* 256-bit compare: returns -1 if a<b, 0 if equal, +1 if a>b */
static int cmp256(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* Shift 256-bit big-endian value left by n bits (n <= 8).
   Returns 0 if overflow, 1 if ok. */
static int shl256(const uint8_t in[32], int n, uint8_t out[32]) {
    unsigned carry = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned v = ((unsigned)in[i] << n) | carry;
        out[i] = (uint8_t)(v & 0xff);
        carry = v >> 8;
    }
    return carry == 0;
}

/* Shift 256-bit big-endian value right by n bits (n <= 8). */
static void shr256(const uint8_t in[32], int n, uint8_t out[32]) {
    unsigned carry = 0;
    for (int i = 0; i < 32; i++) {
        unsigned v = ((carry << 8) | in[i]);
        out[i] = (uint8_t)(v >> n);
        carry = v & ((1u << n) - 1u);
    }
}

int p2p_validate_difficulty_transition(uint32_t old_bits, uint32_t new_bits,
                                        uint32_t actual_timespan_secs)
{
    (void)actual_timespan_secs;  /* timespan clamping not needed for range check */

    /* Decode both targets — invalid nBits → reject */
    uint8_t old_target[32], new_target[32];
    if (!decode_target(old_bits, old_target)) return 0;
    if (!decode_target(new_bits, new_target)) return 0;
    if ((new_bits & 0x00800000)) return 0;  /* negative target */

    /* new_target must be in [old/4, old*4] */
    uint8_t max_target[32];
    if (!shl256(old_target, 2, max_target)) {
        /* old_target * 4 overflows → anything is valid on the upper end */
        memset(max_target, 0xff, 32);
    }
    if (cmp256(new_target, max_target) > 0) return 0;  /* too easy: >4x */

    uint8_t min_target[32];
    shr256(old_target, 2, min_target);
    if (cmp256(new_target, min_target) < 0) return 0;  /* too hard: <1/4x */

    return 1;
}

int p2p_recv_headers_pow(p2p_conn_t *conn,
                          uint8_t (*hashes_out)[32], size_t max_headers,
                          uint32_t *nbits_out)
{
    for (int attempt = 0; attempt < 64; attempt++) {
        char     cmd[13];
        uint8_t *payload;
        int      plen = p2p_recv_msg(conn, cmd, &payload);
        if (plen < 0) return -1;

        if (strcmp(cmd, "ping") == 0) {
            p2p_send_msg(conn, "pong", payload, (uint32_t)plen);
            free(payload);
            continue;
        }

        if (strcmp(cmd, "headers") == 0) {
            if (plen < 1) { free(payload); return 0; }

            const uint8_t *p   = payload;
            size_t         rem = (size_t)plen;

            uint64_t count;
            size_t   varint_len;
            if (p[0] < 0xfd) {
                count      = p[0];
                varint_len = 1;
            } else if (p[0] == 0xfd && rem >= 3) {
                count      = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
                varint_len = 3;
            } else {
                free(payload);
                return 0;
            }
            p   += varint_len;
            rem -= varint_len;

            size_t n_stored = 0;
            for (uint64_t i = 0; i < count; i++) {
                if (rem < 81) break;
                /* PoW validation */
                if (!p2p_validate_header_pow(p)) {
                    fprintf(stderr, "P2P: header PoW invalid at index %llu, closing peer\n",
                            (unsigned long long)i);
                    free(payload);
                    p2p_close(conn);
                    return -1;
                }
                if (n_stored < max_headers && hashes_out) {
                    sha256_double(p, 80, hashes_out[n_stored]);
                    if (nbits_out) {
                        nbits_out[n_stored] = (uint32_t)p[72]        |
                                              ((uint32_t)p[73] <<  8) |
                                              ((uint32_t)p[74] << 16) |
                                              ((uint32_t)p[75] << 24);
                    }
                    n_stored++;
                }
                p   += 81;
                rem -= 81;
            }

            free(payload);
            return (int)n_stored;
        }

        free(payload);
    }
    return 0;
}

int p2p_connect_nonblocking(p2p_conn_t *conn, const char *host, int port,
                              const char *network, int timeout_ms)
{
    /* For simplicity, delegate to the blocking connect with a short socket timeout.
       A full non-blocking implementation would use O_NONBLOCK + select().
       This version sets SO_RCVTIMEO / SO_SNDTIMEO to timeout_ms. */
    if (!p2p_connect(conn, host, port, network)) return 0;

    /* Apply timeout to the connected socket */
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 1;
}
