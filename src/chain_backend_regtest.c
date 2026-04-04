#include "superscalar/chain_backend.h"
#include "superscalar/regtest.h"

/*
 * chain_backend_t implementation backed by the existing regtest_t / bitcoin-cli
 * harness.  TXID polling does not require script pre-registration, so
 * register_script / unregister_script are no-ops that always succeed.
 */

static int cb_get_block_height(chain_backend_t *self)
{
    return regtest_get_block_height((regtest_t *)self->ctx);
}

static int cb_get_confirmations(chain_backend_t *self, const char *txid_hex)
{
    return regtest_get_confirmations((regtest_t *)self->ctx, txid_hex);
}

static bool cb_is_in_mempool(chain_backend_t *self, const char *txid_hex)
{
    return regtest_is_in_mempool((regtest_t *)self->ctx, txid_hex);
}

static int cb_send_raw_tx(chain_backend_t *self, const char *tx_hex,
                          char *txid_out)
{
    return regtest_send_raw_tx((regtest_t *)self->ctx, tx_hex, txid_out);
}

static int cb_get_confirmations_batch(chain_backend_t *self,
                                      const char **txids_hex, size_t n_txids,
                                      int *confs_out)
{
    return regtest_get_confirmations_batch((regtest_t *)self->ctx,
                                           txids_hex, n_txids, confs_out);
}

static int cb_register_script(chain_backend_t *self,
                               const unsigned char *spk, size_t spk_len)
{
    (void)self; (void)spk; (void)spk_len;
    return 1;
}

static int cb_unregister_script(chain_backend_t *self,
                                 const unsigned char *spk, size_t spk_len)
{
    (void)self; (void)spk; (void)spk_len;
    return 1;
}

void chain_backend_regtest_init(chain_backend_t *backend, regtest_t *rt)
{
    backend->get_block_height        = cb_get_block_height;
    backend->get_confirmations       = cb_get_confirmations;
    backend->get_confirmations_batch = cb_get_confirmations_batch;
    backend->is_in_mempool           = cb_is_in_mempool;
    backend->send_raw_tx       = cb_send_raw_tx;
    backend->register_script   = cb_register_script;
    backend->unregister_script = cb_unregister_script;
    backend->ctx               = rt;
    backend->safe_confirmations = MAINNET_SAFE_CONFIRMATIONS;
}
