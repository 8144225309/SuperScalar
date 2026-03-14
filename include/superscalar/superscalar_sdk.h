#ifndef SUPERSCALAR_SDK_H
#define SUPERSCALAR_SDK_H

#include "chain_backend.h"
#include "fee_estimator.h"
#include "wallet_source.h"
#include "watchtower.h"
#include "persist.h"
#include <stdint.h>
#include <stddef.h>

/*
 * superscalar_sdk.h — top-level configuration and node types.
 *
 * Provides a single entry point (ss_node_init / ss_node_run_cycle /
 * ss_node_free) that wires together a chain backend, fee estimator, wallet
 * source, watchtower, and optional SQLite persistence from a declarative
 * ss_config_t.
 *
 * Typical usage:
 *   ss_config_t cfg;
 *   ss_config_default(&cfg, "mainnet");
 *   cfg.chain_mode = SS_CHAIN_BIP158;
 *   cfg.bip158_peer = "127.0.0.1:8333";
 *   cfg.fee_mode = SS_FEE_BLOCKS;
 *
 *   ss_node_t node;
 *   ss_node_init(&node, &cfg);
 *   while (running) ss_node_run_cycle(&node);
 *   ss_node_free(&node);
 */

/* -------------------------------------------------------------------------
 * Mode enums
 * ------------------------------------------------------------------------- */

typedef enum {
    SS_CHAIN_RPC,      /* bitcoin-cli / JSON-RPC (requires cli_path) */
    SS_CHAIN_BIP158,   /* BIP 157/158 P2P compact block filters       */
} ss_chain_mode_t;

typedef enum {
    SS_FEE_STATIC,     /* Fixed sat/kvB supplied by caller             */
    SS_FEE_RPC,        /* estimatesmartfee (requires cli_path)          */
    SS_FEE_BLOCKS,     /* Block-derived + BIP 133 feefilter floor       */
    SS_FEE_API,        /* HTTP mempool.space endpoint (or custom URL)   */
} ss_fee_mode_t;

typedef enum {
    SS_WALLET_NONE,    /* No wallet — CPFP disabled                    */
    SS_WALLET_RPC,     /* bitcoin-cli wallet (requires cli_path)        */
} ss_wallet_mode_t;

/* -------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

typedef struct {
    /* Network: "regtest", "signet", "testnet3", "testnet4", "mainnet" */
    const char       *network;

    /* Chain backend */
    ss_chain_mode_t   chain_mode;
    const char       *bip158_peer;           /* "host:port" for primary BIP 158 peer  */
    const char       *bip158_fallbacks[7];   /* fallback peers (NULL-terminated list)  */

    /* Fee estimator */
    ss_fee_mode_t     fee_mode;
    uint64_t          fee_static_sat_per_kvb;   /* SS_FEE_STATIC: rate in sat/kvB       */
    const char       *fee_api_url;              /* SS_FEE_API: NULL → mempool.space      */
    ss_http_get_fn    fee_http_get;             /* SS_FEE_API: NULL → built-in POSIX     */
    void             *fee_http_ctx;             /* SS_FEE_API: context for http_get      */

    /* Wallet source */
    ss_wallet_mode_t  wallet_mode;

    /* Bitcoin RPC / CLI (shared by chain, fee, and wallet when mode requires it) */
    const char       *cli_path;     /* path to bitcoin-cli (default: "bitcoin-cli") */
    const char       *rpcuser;
    const char       *rpcpassword;
    int               rpcport;      /* 0 = network default                          */

    /* Optional SQLite persistence */
    const char       *db_path;      /* NULL = no persistence                        */
} ss_config_t;

/* Fill cfg with safe defaults for the given network. */
void ss_config_default(ss_config_t *cfg, const char *network);

/* -------------------------------------------------------------------------
 * Node
 * ------------------------------------------------------------------------- */

/* Forward declarations for concrete types stored inside the node */
struct bip158_backend_t;

typedef struct {
    chain_backend_t  *chain;    /* active chain backend (points into _chain_impl) */
    fee_estimator_t  *fee;      /* active fee estimator (points into _fee_impl)   */
    wallet_source_t  *wallet;   /* active wallet source (points into _wallet_impl) */
    watchtower_t      wt;
    persist_t         db;

    /* Private backing storage — do not access directly */
    void             *_chain_impl;   /* heap-alloc'd bip158_backend_t or NULL */
    void             *_fee_impl;     /* heap-alloc'd concrete fee type or NULL */
    void             *_wallet_impl;  /* heap-alloc'd wallet_source_rpc_t or NULL */
} ss_node_t;

/*
 * Initialise the node from cfg.
 * Returns 1 on success, 0 on failure.
 * On failure all internally allocated resources are freed; the caller does
 * not need to call ss_node_free().
 */
int  ss_node_init(ss_node_t *node, const ss_config_t *cfg);

/*
 * Run one chain-scan cycle:
 *   - Drives the chain backend scan (compact filter pass or RPC poll)
 *   - Calls fee_estimator update() if set
 *   - Calls watchtower_check()
 * Returns number of matched/acted blocks, or -1 on fatal error.
 */
int  ss_node_run_cycle(ss_node_t *node);

/* Free all resources owned by the node. */
void ss_node_free(ss_node_t *node);

#endif /* SUPERSCALAR_SDK_H */
