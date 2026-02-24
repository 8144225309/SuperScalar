#include "superscalar/bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n"
            "  --lsp-host HOST    LSP host (default: 127.0.0.1)\n"
            "  --lsp-port PORT    LSP port (default: 9735)\n"
            "  --plugin-port PORT Plugin listen port (default: 9736)\n"
            "  --help             Show this help\n", prog);
}

int main(int argc, char *argv[]) {
    const char *lsp_host = "127.0.0.1";
    int lsp_port = 9735;
    int plugin_port = 9736;

    static struct option long_options[] = {
        {"lsp-host",    required_argument, 0, 'h'},
        {"lsp-port",    required_argument, 0, 'l'},
        {"plugin-port", required_argument, 0, 'p'},
        {"help",        no_argument,       0, '?'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h': lsp_host = optarg; break;
        case 'l': lsp_port = atoi(optarg); break;
        case 'p': plugin_port = atoi(optarg); break;
        default: usage(argv[0]); return 1;
        }
    }

    printf("SuperScalar Bridge Daemon\n");
    printf("  LSP: %s:%d\n", lsp_host, lsp_port);
    printf("  Plugin port: %d\n", plugin_port);

    bridge_t br;
    bridge_init(&br);

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
