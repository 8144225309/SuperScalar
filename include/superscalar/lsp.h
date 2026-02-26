#ifndef SUPERSCALAR_LSP_H
#define SUPERSCALAR_LSP_H

#include "factory.h"
#include "wire.h"
#include <secp256k1.h>

#define LSP_MAX_CLIENTS 8

typedef struct {
    secp256k1_context *ctx;
    secp256k1_keypair  lsp_keypair;
    secp256k1_pubkey   lsp_pubkey;

    /* Connected clients */
    int client_fds[LSP_MAX_CLIENTS];
    secp256k1_pubkey client_pubkeys[LSP_MAX_CLIENTS];
    size_t n_clients;
    size_t expected_clients;

    /* Factory (built after all clients connect) */
    factory_t factory;

    /* Bridge daemon connection (Phase 14) */
    int bridge_fd;

    /* Listen socket */
    int listen_fd;
    int port;

    /* Accept timeout: max seconds to wait for each client connection.
       0 = no timeout (block indefinitely, default). */
    int accept_timeout_sec;

    /* NK (server-authenticated) handshake. If use_nk=1, lsp_accept_clients
       uses Noise NK with nk_seckey instead of NN. Default: 0 (NN). */
    int use_nk;
    unsigned char nk_seckey[32];
} lsp_t;

/* Initialize LSP state. Returns 1 on success, 0 on failure. */
int lsp_init(lsp_t *lsp, secp256k1_context *ctx,
              const secp256k1_keypair *keypair, int port,
              size_t expected_clients);

/* Accept expected_clients connections, do HELLO handshake with each.
   Returns 1 when all clients connected. */
int lsp_accept_clients(lsp_t *lsp);

/* Run full factory creation ceremony over the wire.
   funding_txid: internal byte order, already funded.
   Returns 1 on success (factory fully signed). */
int lsp_run_factory_creation(lsp_t *lsp,
                              const unsigned char *funding_txid, uint32_t funding_vout,
                              uint64_t funding_amount,
                              const unsigned char *funding_spk, size_t funding_spk_len,
                              uint16_t step_blocks, uint32_t states_per_layer,
                              uint32_t cltv_timeout);

/* Run cooperative close ceremony over the wire.
   Returns 1 on success, fills close_tx_out with signed tx. */
int lsp_run_cooperative_close(lsp_t *lsp,
                               tx_buf_t *close_tx_out,
                               const tx_output_t *outputs, size_t n_outputs);

/* Accept a bridge daemon connection (Phase 14).
   Expects MSG_BRIDGE_HELLO, sends MSG_BRIDGE_HELLO_ACK.
   Returns 1 on success. */
int lsp_accept_bridge(lsp_t *lsp);

/* Send MSG_ERROR to all connected clients, then close their fds. */
void lsp_abort_ceremony(lsp_t *lsp, const char *reason);

/* Cleanup */
void lsp_cleanup(lsp_t *lsp);

#endif /* SUPERSCALAR_LSP_H */
