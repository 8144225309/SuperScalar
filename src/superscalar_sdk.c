#include "superscalar/superscalar_sdk.h"
#include "superscalar/bip158_backend.h"
#include "superscalar/chain_backend.h"
#include "superscalar/fee_estimator.h"
#include "superscalar/wallet_source.h"
#include "superscalar/regtest.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Chain backend for RPC mode — forward declared in chain_backend.c */
extern void chain_backend_regtest_init(chain_backend_t *backend, regtest_t *rt);

/* -------------------------------------------------------------------------
 * ss_config_default
 * ------------------------------------------------------------------------- */
void ss_config_default(ss_config_t *cfg, const char *network)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->network               = network ? network : "regtest";
    cfg->chain_mode            = SS_CHAIN_RPC;
    cfg->fee_mode              = SS_FEE_RPC;
    cfg->fee_static_sat_per_kvb = 1000;
    cfg->wallet_mode           = SS_WALLET_RPC;
    cfg->cli_path              = "bitcoin-cli";
    cfg->rpcuser               = "rpcuser";
    cfg->rpcpassword           = "rpcpass";
    cfg->rpcport               = 0;
    cfg->db_path               = NULL;
}

/* -------------------------------------------------------------------------
 * ss_node_init
 * ------------------------------------------------------------------------- */
int ss_node_init(ss_node_t *node, const ss_config_t *cfg)
{
    if (!node || !cfg) return 0;
    memset(node, 0, sizeof(*node));

    /* ---- Persistence ---- */
    if (cfg->db_path) {
        if (!persist_open(&node->db, cfg->db_path)) {
            fprintf(stderr, "ss_node: failed to open database: %s\n", cfg->db_path);
            return 0;
        }
    }

    /* ---- RPC handle (shared by chain/fee/wallet when needed) ---- */
    regtest_t *rt = NULL;
    if (cfg->chain_mode == SS_CHAIN_RPC ||
        cfg->fee_mode   == SS_FEE_RPC   ||
        cfg->wallet_mode == SS_WALLET_RPC) {
        rt = calloc(1, sizeof(regtest_t));
        if (!rt) { persist_close(&node->db); return 0; }
        int ok = regtest_init_full(rt, cfg->network,
                                   cfg->cli_path     ? cfg->cli_path     : "bitcoin-cli",
                                   cfg->rpcuser      ? cfg->rpcuser      : "rpcuser",
                                   cfg->rpcpassword  ? cfg->rpcpassword  : "rpcpass",
                                   NULL /* datadir */,
                                   cfg->rpcport);
        if (!ok) {
            fprintf(stderr, "ss_node: RPC init failed (is bitcoind running?)\n");
            free(rt);
            persist_close(&node->db);
            return 0;
        }
        node->_wallet_impl = rt;   /* rt lifetime: owned by node, freed in ss_node_free */
    }

    /* ---- Chain backend ---- */
    if (cfg->chain_mode == SS_CHAIN_BIP158) {
        bip158_backend_t *b = calloc(1, sizeof(bip158_backend_t));
        if (!b) goto fail;
        if (!bip158_backend_init(b, cfg->network)) {
            free(b);
            goto fail;
        }
        if (cfg->db_path) {
            bip158_backend_set_db(b, &node->db);
            bip158_backend_restore_checkpoint(b);
        }
        /* Primary peer */
        if (cfg->bip158_peer) {
            char host[256]; int port;
            if (bip158_parse_host_port(cfg->bip158_peer, host, sizeof(host), &port))
                bip158_backend_connect_p2p(b, host, port);
        }
        /* Fallback peers */
        for (int i = 0; i < 7 && cfg->bip158_fallbacks[i]; i++) {
            char host[256]; int port;
            if (bip158_parse_host_port(cfg->bip158_fallbacks[i], host, sizeof(host), &port))
                bip158_backend_add_peer(b, host, port);
        }
        node->_chain_impl = b;
        node->chain = &b->base;
    } else {
        /* SS_CHAIN_RPC: wrap regtest_t as a chain_backend_t */
        chain_backend_t *cb = calloc(1, sizeof(chain_backend_t));
        if (!cb) goto fail;
        chain_backend_regtest_init(cb, (regtest_t *)node->_wallet_impl);
        node->_chain_impl = cb;
        node->chain = cb;
    }

    /* ---- Fee estimator ---- */
    switch (cfg->fee_mode) {
        case SS_FEE_STATIC: {
            fee_estimator_static_t *fe = calloc(1, sizeof(fee_estimator_static_t));
            if (!fe) goto fail;
            fee_estimator_static_init(fe, cfg->fee_static_sat_per_kvb);
            node->_fee_impl = fe;
            node->fee = &fe->base;
            break;
        }
        case SS_FEE_RPC: {
            fee_estimator_rpc_t *fe = calloc(1, sizeof(fee_estimator_rpc_t));
            if (!fe) goto fail;
            fee_estimator_rpc_init(fe, (regtest_t *)node->_wallet_impl);
            node->_fee_impl = fe;
            node->fee = &fe->base;
            break;
        }
        case SS_FEE_BLOCKS: {
            fee_estimator_blocks_t *fe = calloc(1, sizeof(fee_estimator_blocks_t));
            if (!fe) goto fail;
            fee_estimator_blocks_init(fe);
            /* Wire into BIP 158 backend so it gets per-block samples */
            if (cfg->chain_mode == SS_CHAIN_BIP158)
                bip158_backend_set_fee_estimator(
                    (bip158_backend_t *)node->_chain_impl, &fe->base);
            node->_fee_impl = fe;
            node->fee = &fe->base;
            break;
        }
        case SS_FEE_API: {
            fee_estimator_api_t *fe = calloc(1, sizeof(fee_estimator_api_t));
            if (!fe) goto fail;
            fee_estimator_api_init(fe, cfg->fee_api_url,
                                   cfg->fee_http_get, cfg->fee_http_ctx);
            node->_fee_impl = fe;
            node->fee = &fe->base;
            break;
        }
    }

    /* ---- Wallet source ---- */
    wallet_source_t *wallet = NULL;
    if (cfg->wallet_mode == SS_WALLET_RPC && rt) {
        /* Reuse the regtest_t already in _wallet_impl */
        wallet_source_rpc_t *ws = calloc(1, sizeof(wallet_source_rpc_t));
        if (!ws) goto fail;
        wallet_source_rpc_init(ws, rt);
        /* Store as a separate alloc — _wallet_impl is already rt */
        /* Attach to the watchtower after init; keep pointer in ws */
        wallet = &ws->base;
        /* We need to free ws in ss_node_free; piggyback on fee_impl slot
           if it's not used... but it is. Use a second field. */
        /* Simplest: free ws via the wallet pointer stored in wt.wallet.
           We track it by storing the pointer in an otherwise-unused
           _wallet_impl — but _wallet_impl is already rt.  Use a local
           variable and rely on watchtower owning the pointer indirectly. */
        /* Actually: wt._wallet_rpc_default is embedded; but that only
           works when rt is passed to watchtower_init.  Here we use a
           heap ws.  Store it in a scratch slot: repurpose _wallet_impl. */
        /* Let rt live in a plain local (no heap needed for regtest_t
           since we already have it heap-allocated in _wallet_impl). */
        /* Store ws in _wallet_impl; rt is stored via the ws->rt pointer
           which references the same heap block.  Free order: ws first,
           then rt. */
        node->_wallet_impl = ws;   /* overwrite the rt pointer! */
        /* But we still need rt alive — save it in ws->rt already done above.
           The original rt malloc is now only referenced by ws->rt. */
    }

    /* ---- Watchtower ---- */
    if (!watchtower_init(&node->wt, 0,
                          (cfg->wallet_mode == SS_WALLET_RPC && rt) ? rt : NULL,
                          node->fee,
                          cfg->db_path ? &node->db : NULL)) {
        fprintf(stderr, "ss_node: watchtower_init failed\n");
        goto fail;
    }
    if (node->chain)
        watchtower_set_chain_backend(&node->wt, node->chain);
    if (wallet)
        watchtower_set_wallet(&node->wt, wallet);

    return 1;

fail:
    ss_node_free(node);
    return 0;
}

/* -------------------------------------------------------------------------
 * ss_node_run_cycle
 * ------------------------------------------------------------------------- */
int ss_node_run_cycle(ss_node_t *node)
{
    if (!node) return -1;

    /* Update fee estimator (no-op if update slot is NULL) */
    if (node->fee && node->fee->update)
        node->fee->update(node->fee);

    /* Scan chain */
    int matched = 0;
    if (node->chain && node->chain->get_confirmations) {
        /* Generic poll — for BIP 158 the scan is driven by bip158_backend_scan */
        if (node->_chain_impl) {
            /* Try to cast to bip158_backend_t by checking if chain pointer == &base */
            bip158_backend_t *b = (bip158_backend_t *)node->_chain_impl;
            if (node->chain == &b->base)
                matched = bip158_backend_scan(b);
        }
    }

    /* Watchtower check */
    watchtower_check(&node->wt);

    return matched;
}

/* -------------------------------------------------------------------------
 * ss_node_free
 * ------------------------------------------------------------------------- */
void ss_node_free(ss_node_t *node)
{
    if (!node) return;

    watchtower_cleanup(&node->wt);

    /* Fee estimator */
    if (node->_fee_impl) {
        fee_estimator_t *fe = (fee_estimator_t *)node->_fee_impl;
        if (fe->free) fe->free(fe);
        free(node->_fee_impl);
        node->_fee_impl = NULL;
    }

    /* Chain backend */
    if (node->_chain_impl) {
        if (node->chain == &((bip158_backend_t *)node->_chain_impl)->base)
            bip158_backend_free((bip158_backend_t *)node->_chain_impl);
        free(node->_chain_impl);
        node->_chain_impl = NULL;
    }

    /* Wallet source / regtest_t
       _wallet_impl may be a wallet_source_rpc_t* (heap) which itself holds
       a pointer to the heap-allocated regtest_t.  Free the rpc wrapper,
       then the regtest_t. */
    if (node->_wallet_impl) {
        /* If wallet mode was RPC, _wallet_impl is wallet_source_rpc_t* */
        wallet_source_rpc_t *ws = (wallet_source_rpc_t *)node->_wallet_impl;
        if (ws->base.free) ws->base.free(&ws->base);
        regtest_t *rt = (regtest_t *)ws->rt;
        free(ws);
        if (rt) free(rt);
        node->_wallet_impl = NULL;
    }

    /* Persistence */
    persist_close(&node->db);

    memset(node, 0, sizeof(*node));
}
