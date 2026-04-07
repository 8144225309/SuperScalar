#ifndef SUPERSCALAR_CHAIN_BACKEND_RPC_H
#define SUPERSCALAR_CHAIN_BACKEND_RPC_H

#include "chain_backend.h"

/* Context for HTTP JSON-RPC chain backend (direct bitcoind connection). */
typedef struct {
    char host[256];
    int port;
    char rpcuser[128];
    char rpcpassword[128];
    char wallet[128];
} chain_backend_rpc_ctx_t;

/* Initialize a chain_backend_t backed by HTTP JSON-RPC to bitcoind.
   Works with any network (mainnet, signet, testnet, regtest).
   wallet may be NULL or "" if no wallet path is needed. */
int chain_backend_rpc_init(chain_backend_t *backend,
                            const char *host, int port,
                            const char *rpcuser, const char *rpcpassword,
                            const char *wallet,
                            const char *network);

#endif /* SUPERSCALAR_CHAIN_BACKEND_RPC_H */
