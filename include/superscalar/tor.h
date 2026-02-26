#ifndef SUPERSCALAR_TOR_H
#define SUPERSCALAR_TOR_H

#include <stddef.h>

/* Connect to host:port via Tor SOCKS5 proxy at proxy_host:proxy_port.
   For .onion addresses, Tor resolves the name (no DNS leak).
   Returns connected fd on success, -1 on failure. */
int tor_connect_socks5(const char *proxy_host, int proxy_port,
                       const char *host, int port);

/* Create an ephemeral Tor hidden service mapping virtual_port to
   127.0.0.1:local_port via Tor control port at control_host:control_port.
   Writes the .onion hostname (without .onion suffix) to onion_out.
   Returns control fd (keep open to maintain service) or -1 on failure. */
int tor_create_hidden_service(const char *control_host, int control_port,
                              const char *control_password,
                              int virtual_port, int local_port,
                              char *onion_out, size_t onion_out_len);

/* Parse a "HOST:PORT" string (e.g. "127.0.0.1:9050") into components.
   Returns 1 on success, 0 on parse failure. */
int tor_parse_proxy_arg(const char *arg, char *host_out, size_t host_len,
                        int *port_out);

#endif /* SUPERSCALAR_TOR_H */
