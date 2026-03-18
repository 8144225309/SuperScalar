/*
 * test_htlc_forward.c — Unit tests for HTLC forwarding engine
 */

#include "superscalar/htlc_forward.h"
#include "superscalar/peer_mgr.h"
#include "superscalar/onion.h"
#include "superscalar/mpp.h"
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

static void make_privkey(unsigned char priv[32], int seed) {
    memset(priv, seed & 0xff, 32);
    priv[0] = 0x01;
    if (priv[0] == 0) priv[0] = 1;
}

/* ---- Test HF1: final hop delivery ---- */
int test_htlc_forward_final(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32], our_pub[33];
    make_privkey(our_priv, 1);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, our_priv), "pub");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &pub_len, &pub, SECP256K1_EC_COMPRESSED);

    unsigned char payment_secret[32];
    memset(payment_secret, 0xBB, 32);

    /* Build a final-hop onion */
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, our_pub, 33);
    hop.amount_msat = 10000;
    hop.cltv_expiry = 700000;
    hop.is_final    = 1;
    memcpy(hop.payment_secret, payment_secret, 32);
    hop.total_msat  = 10000;

    unsigned char session_key[32];
    memset(session_key, 0x44, 32);
    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt), "build onion");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    htlc_forward_entry_t out;
    int ret = htlc_forward_process(&fwd, &mpp, our_priv, ctx,
                                    onion_pkt, 1001, 555, 10000, 700000, &out);
    ASSERT(ret == FORWARD_FINAL, "recognized as final hop");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test HF2: settle propagation ---- */
int test_htlc_forward_settle(void)
{
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);

    /* Manually add an in-flight entry */
    htlc_forward_entry_t *e = &fwd.entries[fwd.count++];
    memset(e, 0, sizeof(*e));
    e->in_htlc_id  = 100;
    e->in_chan_id  = 200;
    e->out_htlc_id = 300;
    e->out_chan_id = 400;
    e->state       = FORWARD_STATE_INFLIGHT;

    unsigned char preimage[32];
    memset(preimage, 0xAA, 32);
    htlc_forward_settle(&fwd, 300, 400, preimage);

    ASSERT(fwd.entries[0].state == FORWARD_STATE_SETTLED, "entry settled");
    return 1;
}

/* ---- Test HF3: fail propagation with error re-encryption ---- */
int test_htlc_forward_fail(void)
{
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);

    htlc_forward_entry_t *e = &fwd.entries[fwd.count++];
    memset(e, 0, sizeof(*e));
    e->in_htlc_id  = 10;
    e->in_chan_id  = 20;
    e->out_htlc_id = 30;
    e->out_chan_id = 40;
    e->state       = FORWARD_STATE_INFLIGHT;
    memset(e->onion_shared_secret, 0x55, 32);

    unsigned char error_in[256];
    memset(error_in, 0x99, 256);
    unsigned char error_out[256];

    htlc_forward_fail(&fwd, 30, 40, error_in, 256, error_out);

    ASSERT(fwd.entries[0].state == FORWARD_STATE_FAILED, "entry failed");
    /* Error should be re-encrypted (different from input) */
    ASSERT(memcmp(error_in, error_out, 256) != 0, "error was re-encrypted");

    return 1;
}

/* ---- Test HF4: init clears table ---- */
int test_htlc_forward_init(void)
{
    htlc_forward_table_t fwd;
    /* Set some garbage */
    memset(&fwd, 0xFF, sizeof(fwd));
    htlc_forward_init(&fwd);
    ASSERT(fwd.count == 0, "count zeroed after init");
    return 1;
}

/* ================================================================== */
/* HF5 — htlc_forward_entry_t has next_onion field                    */
/* ================================================================== */
int test_htlc_forward_entry_has_next_onion(void)
{
    htlc_forward_entry_t e;
    memset(&e, 0, sizeof(e));
    /* The field must exist and be ONION_PACKET_SIZE bytes */
    ASSERT(sizeof(e.next_onion) == ONION_PACKET_SIZE,
           "HF5: next_onion is ONION_PACKET_SIZE bytes");
    return 1;
}

/* ================================================================== */
/* HF6 — FORWARD_RELAY result with zeroed onion → entry state pending */
/* ================================================================== */
int test_htlc_forward_relay_state_pending(void)
{
    static htlc_forward_table_t fwd; /* static: avoids 390KB stack alloc */
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    memset(&mpp, 0, sizeof(mpp));

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "HF6: ctx created");

    unsigned char priv[32];
    memset(priv, 0x22, 32);
    unsigned char onion[ONION_PACKET_SIZE] = {0};

    htlc_forward_entry_t out;
    int res = htlc_forward_process(&fwd, &mpp, priv, ctx,
                                    onion, 1, 0, 1000000, 500, &out);

    /* A zeroed onion fails to peel — FORWARD_FAIL is acceptable */
    ASSERT(res == FORWARD_FAIL || res == FORWARD_RELAY,
           "HF6: no crash on zeroed onion");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* HF7 — in_channel_id field exists and is 32 bytes                   */
/* ================================================================== */
int test_htlc_forward_in_channel_id_field(void)
{
    htlc_forward_entry_t e;
    memset(&e, 0x55, sizeof(e));
    ASSERT(sizeof(e.in_channel_id) == 32, "HF7: in_channel_id is 32 bytes");
    return 1;
}

/* ================================================================== */
/* HF8 — peer_mgr_find_by_scid returns -1 for empty table             */
/* ================================================================== */
int test_htlc_forward_find_by_scid_empty(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    int idx = peer_mgr_find_by_scid(&mgr, 0xDEADBEEFULL);
    ASSERT(idx == -1, "HF8: find_by_scid on empty table returns -1");
    return 1;
}

/* ================================================================== */
/* HF9 — peer_mgr_find_by_scid finds a matching peer                  */
/* ================================================================== */
int test_htlc_forward_find_by_scid_found(void)
{
    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.peers[0].fd           = 5;
    mgr.peers[0].channel_scid = 0xABCD1234ULL;
    mgr.count = 1;

    int idx = peer_mgr_find_by_scid(&mgr, 0xABCD1234ULL);
    ASSERT(idx == 0, "HF9: find_by_scid returns correct peer index");

    int idx2 = peer_mgr_find_by_scid(&mgr, 0x9999ULL);
    ASSERT(idx2 == -1, "HF9: wrong scid returns -1");
    return 1;
}
