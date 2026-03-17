/*
 * test_peer_mgr.c — Unit tests for the peer connection manager
 */

#include "superscalar/peer_mgr.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Test PM1: init populates our_pubkey ---- */
int test_peer_mgr_init(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char priv[32];
    memset(priv, 0x42, 32);

    peer_mgr_t mgr;
    ASSERT(peer_mgr_init(&mgr, ctx, priv), "init succeeds");
    ASSERT(mgr.count == 0, "no peers initially");
    ASSERT(mgr.our_pubkey[0] == 0x02 || mgr.our_pubkey[0] == 0x03,
           "our_pubkey is valid compressed pubkey");
    ASSERT(memcmp(mgr.our_privkey, priv, 32) == 0, "privkey stored");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test PM2: find returns -1 for unknown peer ---- */
int test_peer_mgr_find_unknown(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char priv[32];
    memset(priv, 0x11, 32);

    peer_mgr_t mgr;
    peer_mgr_init(&mgr, ctx, priv);

    unsigned char unknown_pk[33];
    memset(unknown_pk, 0x02, 33);
    ASSERT(peer_mgr_find(&mgr, unknown_pk) == -1, "unknown peer returns -1");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test PM3: connect fails to non-existent host ---- */
int test_peer_mgr_connect_fail(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char priv[32];
    memset(priv, 0x33, 32);

    peer_mgr_t mgr;
    peer_mgr_init(&mgr, ctx, priv);

    unsigned char their_pk[33];
    memset(their_pk, 0x02, 33);
    their_pk[1] = 0xAB;

    /* Connecting to 127.0.0.1:1 should fail immediately */
    int idx = peer_mgr_connect(&mgr, "127.0.0.1", 1, their_pk);
    ASSERT(idx < 0, "connection to closed port fails");
    ASSERT(mgr.count == 0, "peer count unchanged on failure");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test PM4: disconnect removes entry ---- */
int test_peer_mgr_disconnect(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char priv[32];
    memset(priv, 0x22, 32);

    peer_mgr_t mgr;
    peer_mgr_init(&mgr, ctx, priv);

    /* Manually insert a fake peer */
    peer_entry_t *p = &mgr.peers[0];
    memset(p, 0, sizeof(*p));
    memset(p->pubkey, 0x02, 33);
    p->fd = -1; /* already closed */
    mgr.count = 1;

    ASSERT(peer_mgr_find(&mgr, p->pubkey) == 0, "peer found at index 0");
    peer_mgr_disconnect(&mgr, 0);
    ASSERT(mgr.count == 0, "count decremented after disconnect");

    secp256k1_context_destroy(ctx);
    return 1;
}
