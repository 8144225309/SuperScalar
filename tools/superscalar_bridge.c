#include "superscalar/bridge.h"
#include "superscalar/tor.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n"
            "  --lsp-host HOST       LSP host (default: 127.0.0.1)\n"
            "  --lsp-port PORT       LSP port (default: 9735)\n"
            "  --plugin-port PORT    Plugin listen port (default: 9736)\n"
            "  --lsp-pubkey HEX      LSP static pubkey (33-byte hex) for NK authentication\n"
            "  --tor-proxy HOST:PORT SOCKS5 proxy for Tor (default: 127.0.0.1:9050)\n"
            "  --help                Show this help\n", prog);
}

int main(int argc, char *argv[]) {
    const char *lsp_host = "127.0.0.1";
    int lsp_port = 9735;
    int plugin_port = 9736;
    const char *lsp_pubkey_hex = NULL;
    const char *tor_proxy_arg = NULL;

    static struct option long_options[] = {
        {"lsp-host",    required_argument, 0, 'h'},
        {"lsp-port",    required_argument, 0, 'l'},
        {"plugin-port", required_argument, 0, 'p'},
        {"lsp-pubkey",  required_argument, 0, 'k'},
        {"tor-proxy",   required_argument, 0, 't'},
        {"help",        no_argument,       0, '?'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h': lsp_host = optarg; break;
        case 'l': lsp_port = atoi(optarg); break;
        case 'p': plugin_port = atoi(optarg); break;
        case 'k': lsp_pubkey_hex = optarg; break;
        case 't': tor_proxy_arg = optarg; break;
        default: usage(argv[0]); return 1;
        }
    }

    /* Parse --tor-proxy HOST:PORT */
    if (tor_proxy_arg) {
        char proxy_host[256];
        int proxy_port;
        if (!tor_parse_proxy_arg(tor_proxy_arg, proxy_host, sizeof(proxy_host),
                                  &proxy_port)) {
            fprintf(stderr, "Error: invalid --tor-proxy format (use HOST:PORT)\n");
            return 1;
        }
        wire_set_proxy(proxy_host, proxy_port);
        printf("Bridge: Tor SOCKS5 proxy set to %s:%d\n", proxy_host, proxy_port);
    }

    printf("SuperScalar Bridge Daemon\n");
    printf("  LSP: %s:%d\n", lsp_host, lsp_port);
    printf("  Plugin port: %d\n", plugin_port);

    bridge_t br;
    bridge_init(&br);

    /* NK authentication: pin LSP static pubkey if provided */
    if (lsp_pubkey_hex) {
        secp256k1_context *ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_VERIFY);
        unsigned char pk_buf[33];
        if (hex_decode(lsp_pubkey_hex, pk_buf, 33) != 33) {
            fprintf(stderr, "Error: --lsp-pubkey must be 33-byte compressed pubkey hex\n");
            secp256k1_context_destroy(ctx);
            return 1;
        }
        secp256k1_pubkey lsp_pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &lsp_pk, pk_buf, 33)) {
            fprintf(stderr, "Error: invalid --lsp-pubkey\n");
            secp256k1_context_destroy(ctx);
            return 1;
        }
        bridge_set_lsp_pubkey(&br, &lsp_pk);
        printf("Bridge: NK authentication enabled (pinned LSP pubkey)\n");
        secp256k1_context_destroy(ctx);
    }

    if (!bridge_connect_lsp(&br, lsp_host, lsp_port)) {
        fprintf(stderr, "Failed to connect to LSP\n");
        return 1;
    }

    if (!bridge_listen_plugin(&br, plugin_port)) {
        fprintf(stderr, "Failed to listen for plugin\n");
        bridge_cleanup(&br);
        return 1;
    }

    printf("Bridge running, waiting for plugin connection...\n");

    int rc = bridge_run(&br);
    bridge_cleanup(&br);
    return rc ? 0 : 1;
}
