/*
 * lsp_wellknown.h — LSP discovery via /.well-known/lsps.json
 *
 * SuperScalar LSPs advertise their connection parameters over plain HTTP at
 * GET /.well-known/lsps.json.  TLS termination is handled by the operator's
 * reverse proxy (nginx/caddy).
 *
 * Usage (LSP side):
 *   lsp_wellknown_cfg_t cfg = { .pubkey_hex = ..., ... };
 *   lsp_wellknown_handle_connection(fd, &cfg);   // per-connection
 *
 * Usage (client side):
 *   char host[256]; uint16_t port; char pubkey[67];
 *   lsp_wellknown_fetch_http("lsp.example.com", host, sizeof(host),
 *                            &port, pubkey, sizeof(pubkey));
 */

#ifndef SUPERSCALAR_LSP_WELLKNOWN_H
#define SUPERSCALAR_LSP_WELLKNOWN_H

#include <stddef.h>
#include <stdint.h>

/* Parameters served in the .well-known/lsps.json body */
typedef struct {
    const char *pubkey_hex;       /* node pubkey, 66-char hex */
    const char *host;             /* publicly reachable hostname or IP */
    uint16_t    bolt8_port;       /* BOLT #8 port (default 9735) */
    uint16_t    native_port;      /* native Noise port */
    const char *network;          /* "bitcoin","testnet","signet","regtest" */
    uint32_t    fee_ppm;          /* routing fee in parts-per-million */
    uint64_t    min_channel_sats;
    uint64_t    max_channel_sats;
    const char *version;          /* software version string */
} lsp_wellknown_cfg_t;

/*
 * Build the .well-known/lsps.json body into buf.
 * Returns bytes written (excluding NUL), or 0 on error.
 */
size_t lsp_wellknown_build_json(const lsp_wellknown_cfg_t *cfg,
                                 char *buf, size_t buf_cap);

/*
 * Parse a .well-known/lsps.json body.
 * Fills host_out, port_out (bolt8_port), pubkey_hex_out.
 * Returns 1 on success, 0 on parse error or missing fields.
 */
int lsp_wellknown_parse_json(const char *json,
                              char *host_out,       size_t host_cap,
                              uint16_t *port_out,
                              char *pubkey_hex_out, size_t pubkey_cap);

/*
 * Handle one HTTP connection: read the GET request on fd, write the JSON
 * response (or 404 for unknown paths).  Closes fd when done.
 * Callable with a socketpair fd for unit testing.
 */
void lsp_wellknown_handle_connection(int fd,
                                      const lsp_wellknown_cfg_t *cfg);

/*
 * Fetch .well-known/lsps.json over plain HTTP from host:80.
 * On success fills host_out, port_out, pubkey_hex_out and returns 1.
 * On error returns 0.
 */
int lsp_wellknown_fetch_http(const char *domain,
                              char *host_out,       size_t host_cap,
                              uint16_t *port_out,
                              char *pubkey_hex_out, size_t pubkey_cap);

/*
 * Same as lsp_wellknown_fetch_http but connects to an explicit tcp_port
 * instead of port 80.  Useful for testing with non-privileged ports.
 */
int lsp_wellknown_fetch_http_port(const char *domain, uint16_t tcp_port,
                                   char *host_out,       size_t host_cap,
                                   uint16_t *port_out,
                                   char *pubkey_hex_out, size_t pubkey_cap);

/*
 * Fork a background process that accepts HTTP connections on tcp_port and
 * serves the .well-known/lsps.json endpoint.  Returns 1 in the parent on
 * success, 0 on error.  The child runs indefinitely; the parent continues.
 * Requires fork() (Linux/macOS).
 */
int lsp_wellknown_serve_fork(const lsp_wellknown_cfg_t *cfg,
                              uint16_t tcp_port);

#endif /* SUPERSCALAR_LSP_WELLKNOWN_H */
