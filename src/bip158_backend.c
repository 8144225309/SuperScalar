#include "superscalar/bip158_backend.h"
#include <string.h>

/*
 * BIP 157/158 compact block filter backend — stub implementation.
 *
 * Peer connection, GCS filter decoding, script registry, and confirmed-tx
 * cache are not yet implemented.
 * See issue #11: https://github.com/8144225309/SuperScalar/issues/11
 */

int bip158_backend_init(bip158_backend_t *backend, const char *network)
{
    (void)network;
    memset(backend, 0, sizeof(*backend));
    /* TODO: initialise peer connection, filter cache, script registry */
    return 0;
}

void bip158_backend_free(bip158_backend_t *backend)
{
    /* TODO: tear down peer connection, free filter cache and script registry */
    (void)backend;
}
