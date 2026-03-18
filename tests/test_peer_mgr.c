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

/* ================================================================== */
/* PM5 — peer_mgr_mark_disconnected preserves metadata, retains slot  */
/* ================================================================== */
int test_peer_mgr_mark_disconnected_preserves(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    memset(mgr.peers[0].pubkey, 0x33, 33);
    strncpy(mgr.peers[0].host, "127.0.0.1", sizeof(mgr.peers[0].host));
    mgr.peers[0].port = 9735;
    mgr.peers[0].fd   = 10;
    mgr.count = 1;

    peer_mgr_mark_disconnected(&mgr, 0, 30);

    ASSERT(mgr.peers[0].fd == -1, "PM5: fd closed");
    ASSERT(mgr.peers[0].disconnected_at > 0, "PM5: disconnected_at set");
    ASSERT(mgr.peers[0].next_reconnect_at ==
           mgr.peers[0].disconnected_at + 30, "PM5: next_reconnect_at = at+30");
    ASSERT(mgr.peers[0].reconnect_attempts == 1, "PM5: attempts incremented");
    ASSERT(mgr.count == 1, "PM5: slot retained");
    ASSERT(memcmp(mgr.peers[0].saved_pubkey, mgr.peers[0].pubkey, 33) == 0,
           "PM5: saved_pubkey preserved");
    return 1;
}

/* ================================================================== */
/* PM6 — peer_mgr_mark_disconnected caps backoff at 300 s             */
/* ================================================================== */
int test_peer_mgr_mark_disconnected_caps_backoff(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.peers[0].fd = 3;
    mgr.count = 1;

    peer_mgr_mark_disconnected(&mgr, 0, 9999);

    uint32_t delta = mgr.peers[0].next_reconnect_at -
                     mgr.peers[0].disconnected_at;
    ASSERT(delta <= 300, "PM6: backoff capped at 300 s");
    return 1;
}

/* ================================================================== */
/* PM7 — peer_mgr_mark_disconnected increments on repeated calls      */
/* ================================================================== */
int test_peer_mgr_mark_disconnected_increments(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.peers[0].fd = -1;
    mgr.count = 1;

    peer_mgr_mark_disconnected(&mgr, 0, 5);
    peer_mgr_mark_disconnected(&mgr, 0, 5);
    peer_mgr_mark_disconnected(&mgr, 0, 5);

    ASSERT(mgr.peers[0].reconnect_attempts == 3,
           "PM7: 3 calls → 3 attempts");
    return 1;
}

/* ================================================================== */
/* PM8 — peer_mgr_reconnect_all skips if timer not yet elapsed        */
/* ================================================================== */
int test_peer_mgr_reconnect_all_skips_early(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.peers[0].fd              = -1;
    mgr.peers[0].disconnected_at = 1000;
    mgr.peers[0].next_reconnect_at = 2000;
    mgr.count = 1;

    int r = peer_mgr_reconnect_all(&mgr, NULL, 1500 /* too early */);
    ASSERT(r == 0, "PM8: reconnect skipped when timer not elapsed");
    return 1;
}

/* ================================================================== */
/* PM9 — peer_mgr_reconnect_all fails gracefully on bad host          */
/* ================================================================== */
int test_peer_mgr_reconnect_all_fails_gracefully(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.peers[0].fd              = -1;
    mgr.peers[0].disconnected_at = 1000;
    mgr.peers[0].next_reconnect_at = 900; /* overdue */
    strncpy(mgr.peers[0].saved_host, "127.0.0.1",
            sizeof(mgr.peers[0].saved_host));
    mgr.peers[0].saved_port = 1; /* port 1: connection will fail */
    mgr.count = 1;

    int r = peer_mgr_reconnect_all(&mgr, NULL, 2000);
    ASSERT(r == 0, "PM9: failed TCP → reconnect returns 0, no crash");
    ASSERT(mgr.peers[0].next_reconnect_at > 2000,
           "PM9: backoff rescheduled after failure");
    return 1;
}

/* ================================================================== */
/* PM10 — peer_mgr_reconnect_all skips connected peers                */
/* ================================================================== */
int test_peer_mgr_reconnect_all_skips_connected(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.peers[0].fd              = 5;  /* still connected */
    mgr.peers[0].disconnected_at = 0;
    mgr.count = 1;

    int r = peer_mgr_reconnect_all(&mgr, NULL, 9999);
    ASSERT(r == 0, "PM10: connected peer not touched");
    ASSERT(mgr.peers[0].fd == 5, "PM10: fd unchanged");
    return 1;
}

/* ================================================================== */
/* PM11 — channel_scid field exists in peer_entry_t                   */
/* ================================================================== */
int test_peer_mgr_channel_scid_field(void)
{
    peer_entry_t e;
    memset(&e, 0, sizeof(e));
    e.channel_scid = 0xCAFEBABE00000001ULL;
    ASSERT(e.channel_scid == 0xCAFEBABE00000001ULL,
           "PM11: channel_scid field accessible");
    return 1;
}
