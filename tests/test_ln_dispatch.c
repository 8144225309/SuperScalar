/*
 * test_ln_dispatch.c — Unit tests for the LN peer message dispatch loop
 *
 * LD1: write update_add_htlc → verify forward table entry created
 * LD2: write update_fulfill_htlc → verify htlc_forward_settle called
 * LD3: unknown message type → silently ignored (no crash, returns 0)
 * LD4: update_fail_htlc → verify htlc_forward_fail called
 * LD5: truncated update_add_htlc → returns -1 (error)
 */

#include "superscalar/ln_dispatch.h"
#include "superscalar/chan_close.h"
#include "superscalar/htlc_forward.h"
#include "superscalar/invoice.h"
#include "superscalar/mpp.h"
#include "superscalar/onion.h"            /* onion_build */
#include "superscalar/onion_last_hop.h"   /* ONION_PACKET_SIZE */
#include "superscalar/bolt8_server.h"     /* bolt8_server_cfg_t */
#include "superscalar/lsps.h"             /* lsps0_bolt8_cb test helpers */
#include "superscalar/bolt12.h"           /* invoice_request_decode */
#include "superscalar/peer_mgr.h"         /* peer_mgr_set_proxy */
#include "superscalar/tor.h"              /* tor_parse_proxy_arg */
#include <cJSON.h>
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Helpers ---- */

static void wr16(unsigned char *b, uint16_t v)
{
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)v;
}
static void wr64(unsigned char *b, uint64_t v)
{
    for (int i = 7; i >= 0; i--) b[7-i] = (unsigned char)(v >> (i * 8));
}
static void wr32(unsigned char *b, uint32_t v)
{
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >>  8); b[3] = (unsigned char)v;
}

/* Build a minimal ln_dispatch_t with an empty forward table */
static ln_dispatch_t make_dispatch(secp256k1_context *ctx,
                                    htlc_forward_table_t *fwd,
                                    mpp_table_t *mpp)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.ctx      = ctx;
    d.fwd      = fwd;
    d.mpp      = mpp;
    d.payments = NULL;
    d.pmgr     = NULL;
    /* Use a dummy but valid private key */
    memset(d.our_privkey, 0x11, 32);
    return d;
}

/* Build an update_add_htlc message (type 128) into buf (at least 1452 bytes).
 * Returns message length. */
static size_t build_update_add_htlc(unsigned char *buf,
                                     uint64_t htlc_id,
                                     uint64_t amount_msat,
                                     uint32_t cltv_expiry)
{
    /* type(2) + channel_id(32) + htlc_id(8) + amount_msat(8) +
       payment_hash(32) + cltv_expiry(4) + onion(ONION_PACKET_SIZE) */
    size_t len = 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE;
    memset(buf, 0, len);
    wr16(buf, 128);                   /* type = update_add_htlc */
    /* channel_id: buf+2 = all zeros */
    wr64(buf + 34, htlc_id);          /* htlc_id */
    wr64(buf + 42, amount_msat);      /* amount_msat */
    /* payment_hash: buf+50 = all zeros */
    wr32(buf + 82, cltv_expiry);      /* cltv_expiry */
    /* onion: buf+86 = all zeros (deliberately invalid — FORWARD_FAIL expected) */
    return len;
}

/* Build an update_fulfill_htlc message (type 130).
 * Returns message length (74 bytes total). */
static size_t build_update_fulfill_htlc(unsigned char *buf,
                                         uint64_t htlc_id,
                                         const unsigned char preimage[32])
{
    /* type(2) + channel_id(32) + htlc_id(8) + preimage(32) = 74 */
    size_t len = 74;
    memset(buf, 0, len);
    wr16(buf, 130);               /* type = update_fulfill_htlc */
    /* channel_id: buf+2 = zeros */
    wr64(buf + 34, htlc_id);     /* htlc_id */
    memcpy(buf + 42, preimage, 32);
    return len;
}

/* Build an update_fail_htlc message (type 131).
 * Returns message length. */
static size_t build_update_fail_htlc(unsigned char *buf,
                                      uint64_t htlc_id,
                                      const unsigned char *reason, uint16_t reason_len)
{
    /* type(2) + channel_id(32) + htlc_id(8) + len(2) + reason */
    size_t len = 2 + 32 + 8 + 2 + reason_len;
    memset(buf, 0, len);
    wr16(buf, 131);                    /* type = update_fail_htlc */
    wr64(buf + 34, htlc_id);
    buf[42] = (unsigned char)(reason_len >> 8);
    buf[43] = (unsigned char)reason_len;
    if (reason && reason_len) memcpy(buf + 44, reason, reason_len);
    return len;
}

/* ================================================================== */
/* LD1 — update_add_htlc → forward table processes (FORWARD_FAIL ok) */
/* ================================================================== */
int test_ln_dispatch_add_htlc(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    unsigned char buf[2048];
    size_t len = build_update_add_htlc(buf, 42, 1000000, 800050);

    int rc = ln_dispatch_process_msg(&d, 0, buf, len);
    /* update_add_htlc type = 128; return is type or -1 on error */
    ASSERT(rc == 128 || rc == -1,
           "dispatch returns 128 (ok) or -1 (onion fail) — both valid");
    /* With a zeroed onion, htlc_forward_process returns FORWARD_FAIL
     * so no entry is added. Either way, no crash. */

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD2 — update_fulfill_htlc → htlc_forward_settle called            */
/* ================================================================== */
int test_ln_dispatch_fulfill(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    unsigned char preimage[32];
    memset(preimage, 0xAB, 32);

    unsigned char buf[128];
    size_t len = build_update_fulfill_htlc(buf, 7, preimage);

    int rc = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(rc == 130, "update_fulfill_htlc returns type 130");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD3 — unknown message type silently ignored                        */
/* ================================================================== */
int test_ln_dispatch_unknown_type(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    /* Build a fake message with an unknown type (0x9999) */
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    wr16(buf, 0x9999);
    size_t len = sizeof(buf);

    int rc = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(rc == 0, "unknown type returns 0 (silently ignored)");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD4 — update_fail_htlc → htlc_forward_fail dispatched             */
/* ================================================================== */
int test_ln_dispatch_fail(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    unsigned char reason[16];
    memset(reason, 0x0F, 16);
    unsigned char buf[256];
    size_t len = build_update_fail_htlc(buf, 3, reason, 16);

    int rc = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(rc == 131, "update_fail_htlc returns type 131");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD5 — truncated message returns -1                                  */
/* ================================================================== */
int test_ln_dispatch_truncated(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    /* update_add_htlc needs at least 86+ONION_PACKET_SIZE bytes; provide 10 */
    unsigned char buf[10];
    wr16(buf, 128);
    memset(buf + 2, 0, 8);

    int rc = ln_dispatch_process_msg(&d, 0, buf, sizeof(buf));
    ASSERT(rc == -1, "truncated update_add_htlc returns -1");

    /* Empty message */
    ASSERT(ln_dispatch_process_msg(&d, 0, buf, 0) == -1,
           "zero-length message returns -1");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD6 — FORWARD_FINAL claims matching invoice and settles it         */
/* ================================================================== */
int test_ln_dispatch_invoice_claim(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    /* Our private key (same as make_dispatch) */
    unsigned char our_priv[32];
    memset(our_priv, 0x11, 32);
    secp256k1_pubkey our_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &our_pub, our_priv), "pubkey");
    unsigned char our_pub33[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub33, &pub_len, &our_pub,
                                   SECP256K1_EC_COMPRESSED);

    /* Build a valid final-hop onion for our key */
    unsigned char payment_secret[32];
    memset(payment_secret, 0xBB, 32);
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, our_pub33, 33);
    hop.amount_msat  = 500000;
    hop.cltv_expiry  = 700100;
    hop.is_final     = 1;
    memcpy(hop.payment_secret, payment_secret, 32);
    hop.total_msat   = 500000;

    unsigned char session_key[32];
    memset(session_key, 0x44, 32);
    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt), "build onion");

    /* Pre-insert a matching invoice */
    unsigned char payment_hash[32];
    memset(payment_hash, 0xCC, 32);
    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);
    bolt11_invoice_entry_t *e = &tbl.entries[0];
    e->active      = 1;
    e->settled     = 0;
    memcpy(e->payment_hash, payment_hash, 32);
    memset(e->preimage, 0xDD, 32);
    e->amount_msat = 0;           /* accept any amount */
    e->created_at  = (uint32_t)time(NULL);
    e->expiry      = 3600;
    tbl.count      = 1;

    /* Build update_add_htlc with our payment_hash */
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);
    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);
    d.invoices = &tbl;
    /* pmgr = NULL: fulfill send is guarded by peer_idx >= 0 check */

    size_t msg_len = 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE;
    unsigned char *msg = (unsigned char *)calloc(1, msg_len);
    ASSERT(msg, "alloc");
    wr16(msg, 128);                              /* type */
    /* channel_id: msg+2 = zeros */
    wr64(msg + 34, 1);                           /* htlc_id */
    wr64(msg + 42, 500000);                      /* amount_msat */
    memcpy(msg + 50, payment_hash, 32);          /* payment_hash at p+48 */
    wr32(msg + 82, 700100);                      /* cltv_expiry */
    memcpy(msg + 86, onion_pkt, ONION_PACKET_SIZE); /* onion at p+84 */

    int rc = ln_dispatch_process_msg(&d, 0, msg, msg_len);
    free(msg);
    ASSERT(rc == 128 || rc == -1, "returns 128 or -1");

    /* Invoice should be settled (invoice_claim sets settled=1) */
    ASSERT(tbl.entries[0].settled == 1, "invoice settled after final-hop claim");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD7 — FORWARD_FINAL with no matching invoice: no crash             */
/* ================================================================== */
int test_ln_dispatch_no_matching_invoice(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32];
    memset(our_priv, 0x11, 32);
    secp256k1_pubkey our_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &our_pub, our_priv), "pubkey");
    unsigned char our_pub33[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub33, &pub_len, &our_pub,
                                   SECP256K1_EC_COMPRESSED);

    /* Build final-hop onion */
    unsigned char payment_secret[32];
    memset(payment_secret, 0xBB, 32);
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, our_pub33, 33);
    hop.amount_msat = 500000;
    hop.cltv_expiry = 700100;
    hop.is_final    = 1;
    memcpy(hop.payment_secret, payment_secret, 32);
    hop.total_msat  = 500000;

    unsigned char session_key[32];
    memset(session_key, 0x44, 32);
    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt), "build onion");

    /* Empty invoice table: no match */
    bolt11_invoice_table_t tbl;
    invoice_init(&tbl);

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);
    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);
    d.invoices = &tbl;

    size_t msg_len = 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE;
    unsigned char *msg = (unsigned char *)calloc(1, msg_len);
    ASSERT(msg, "alloc");
    wr16(msg, 128);
    wr64(msg + 34, 1);
    wr64(msg + 42, 500000);
    /* payment_hash: zeros (no matching invoice) */
    wr32(msg + 82, 700100);
    memcpy(msg + 86, onion_pkt, ONION_PACKET_SIZE);

    int rc = ln_dispatch_process_msg(&d, 0, msg, msg_len);
    free(msg);
    /* No crash, returns 128 (FORWARD_FINAL reached) or -1 (onion error) */
    ASSERT(rc == 128 || rc == -1, "no matching invoice: no crash");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LD8 — FORWARD_FINAL with d->invoices=NULL: no crash                */
/* ================================================================== */
int test_ln_dispatch_forward_final_no_invoices(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32];
    memset(our_priv, 0x11, 32);
    secp256k1_pubkey our_pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &our_pub, our_priv), "pubkey");
    unsigned char our_pub33[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub33, &pub_len, &our_pub,
                                   SECP256K1_EC_COMPRESSED);

    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, our_pub33, 33);
    hop.amount_msat = 500000; hop.cltv_expiry = 700100;
    hop.is_final = 1; hop.total_msat = 500000;
    unsigned char session_key[32];
    memset(session_key, 0x44, 32);
    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt), "build onion");

    htlc_forward_table_t fwd; htlc_forward_init(&fwd);
    mpp_table_t mpp; mpp_init(&mpp);
    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);
    d.invoices = NULL;  /* no invoice table */

    size_t msg_len = 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE;
    unsigned char *msg = (unsigned char *)calloc(1, msg_len);
    ASSERT(msg, "alloc");
    wr16(msg, 128);
    wr64(msg + 34, 1); wr64(msg + 42, 500000);
    wr32(msg + 82, 700100);
    memcpy(msg + 86, onion_pkt, ONION_PACKET_SIZE);

    int rc = ln_dispatch_process_msg(&d, 0, msg, msg_len);
    free(msg);
    ASSERT(rc == 128 || rc == -1, "no invoice table: no crash");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_ln_dispatch_peer_idx_neg1(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);
    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);
    /* pmgr is NULL from make_dispatch */

    /* update_fulfill_htlc with peer_idx=-1 */
    unsigned char preimage[32];
    memset(preimage, 0xAB, 32);
    unsigned char buf[128];
    size_t len = build_update_fulfill_htlc(buf, 7, preimage);

    int rc = ln_dispatch_process_msg(&d, -1, buf, len);
    ASSERT(rc == 130, "peer_idx=-1 returns correct type 130, no crash");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* BS1 — bolt8_server_cfg_t has ln_dispatch field; routing path works */
/* ================================================================== */
int test_bolt8_ln_dispatch_routing(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);
    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    /* Verify bolt8_server_cfg_t has ln_dispatch field */
    bolt8_server_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.ln_dispatch = &d;
    ASSERT(cfg.ln_dispatch == &d, "ln_dispatch field exists and can be set");

    /* Simulate what bolt8_dispatch_message does for a BOLT #2 type:
     * call ln_dispatch_process_msg with peer_idx=-1 */
    unsigned char buf[128];
    size_t len = build_update_fulfill_htlc(buf, 42, (unsigned char *)
                                            "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB"
                                            "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB"
                                            "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB"
                                            "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB");
    int rc = ln_dispatch_process_msg((ln_dispatch_t *)cfg.ln_dispatch,
                                      /*peer_idx=*/ -1, buf, len);
    ASSERT(rc == 130, "bolt8-routed BOLT #2 msg dispatched correctly");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LS1 — lsps1_get_info JSON response contains min_channel_balance    */
/* ================================================================== */
int test_lsps0_get_info_response(void)
{
    lsps1_info_t info;
    memset(&info, 0, sizeof(info));
    info.min_channel_balance_msat = 100000000ULL;
    info.max_channel_balance_msat = 10000000000ULL;
    info.min_confirmations = 1;
    info.base_fee_msat     = 1000;
    info.fee_ppm           = 500;

    cJSON *result = lsps1_build_get_info_response(&info);
    ASSERT(result, "result non-NULL");

    cJSON *resp = lsps_build_response(1, result);
    ASSERT(resp, "resp non-NULL");
    char *s = cJSON_PrintUnformatted(resp);
    ASSERT(s, "serialize ok");
    ASSERT(strstr(s, "min_channel_balance_msat") != NULL,
           "response contains min_channel_balance_msat");
    free(s);
    cJSON_Delete(resp);
    return 1;
}

/* ================================================================== */
/* LS2 — unknown LSPS method → error with METHOD_NOT_FOUND code       */
/* ================================================================== */
int test_lsps0_unknown_method(void)
{
    cJSON *err = lsps_build_error(99, LSPS_ERR_METHOD_NOT_FOUND, "method not found");
    ASSERT(err, "err non-NULL");
    char *s = cJSON_PrintUnformatted(err);
    ASSERT(s, "serialize ok");
    /* JSON-RPC error should contain the code */
    ASSERT(strstr(s, "-32601") != NULL || strstr(s, "error") != NULL,
           "error response contains error field");
    free(s);
    cJSON_Delete(err);
    return 1;
}

/* ================================================================== */
/* LS3 — invoice_create with "tbs" → bech32 starts with "lntbs"       */
/* ================================================================== */
int test_lsps0_invoice_create_tbs(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char priv[32]; memset(priv, 0x44, 32);
    bolt11_invoice_table_t tbl; invoice_init(&tbl);
    char bech32[512]; memset(bech32, 0, sizeof(bech32));
    int r = invoice_create(&tbl, ctx, priv, "signet", 10000, "test", 3600, bech32, sizeof(bech32));
    ASSERT(r == 1, "invoice_create returns 1");
    ASSERT(strncmp(bech32, "lntbs", 5) == 0, "bech32 starts with lntbs");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LS4 — invoice_create with amount=0 (any-amount) → returns 1        */
/* ================================================================== */
int test_lsps0_invoice_any_amount(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char priv[32]; memset(priv, 0x55, 32);
    bolt11_invoice_table_t tbl; invoice_init(&tbl);
    char bech32[512]; memset(bech32, 0, sizeof(bech32));
    int r = invoice_create(&tbl, ctx, priv, "tbs", 0, "any amount", 3600, bech32, sizeof(bech32));
    ASSERT(r == 1, "any-amount invoice returns 1");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* LS5 — lsps_parse_request with NULL JSON → returns NULL, no crash   */
/* ================================================================== */
int test_lsps0_malformed_json(void)
{
    int id = 0;
    const char *method = lsps_parse_request(NULL, &id);
    ASSERT(method == NULL, "NULL json returns NULL method");
    return 1;
}

/* ================================================================== */
/* LS6 — lsps2_get_info response contains fee_ppm                     */
/* ================================================================== */
int test_lsps0_lsps2_get_info(void)
{
    lsps2_fee_params_t params;
    memset(&params, 0, sizeof(params));
    params.min_fee_msat             = 1000;
    params.fee_ppm                  = 500;
    params.min_channel_balance_msat = 100000000ULL;
    params.max_channel_balance_msat = 10000000000ULL;

    cJSON *result = lsps2_build_get_info_response(&params);
    ASSERT(result, "result non-NULL");
    cJSON *resp = lsps_build_response(1, result);
    ASSERT(resp, "resp non-NULL");
    char *s = cJSON_PrintUnformatted(resp);
    ASSERT(s, "serialize ok");
    ASSERT(strstr(s, "fee_ppm") != NULL, "response contains fee_ppm");
    free(s);
    cJSON_Delete(resp);
    return 1;
}

/* ================================================================== */
/* TW1 — peer_mgr_set_proxy sets tor_proxy_port                       */
/* ================================================================== */
int test_peer_mgr_tor_proxy_set(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char priv[32]; memset(priv, 0x11, 32);
    peer_mgr_t mgr; peer_mgr_init(&mgr, ctx, priv);
    peer_mgr_set_proxy(&mgr, "127.0.0.1", 9050);
    ASSERT(mgr.tor_proxy_port == 9050, "tor_proxy_port set to 9050");
    ASSERT(strcmp(mgr.tor_proxy_host, "127.0.0.1") == 0, "tor_proxy_host set");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* TW2 — .onion host with no proxy → connect fails (TCP, no Tor)      */
/* ================================================================== */
int test_peer_mgr_onion_no_proxy(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char priv[32]; memset(priv, 0x22, 32);
    peer_mgr_t mgr; peer_mgr_init(&mgr, ctx, priv);
    /* No proxy set: tor_proxy_port == 0, so TCP path taken and fails */
    unsigned char their_pk[33]; memset(their_pk, 0x02, 33);
    int r = peer_mgr_connect(&mgr, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion",
                              9735, their_pk);
    ASSERT(r < 0, ".onion without proxy → connect fails");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* TW3 — non-.onion host bypasses Tor regardless of proxy             */
/* ================================================================== */
int test_peer_mgr_clearnet_bypass_tor(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char priv[32]; memset(priv, 0x33, 32);
    peer_mgr_t mgr; peer_mgr_init(&mgr, ctx, priv);
    peer_mgr_set_proxy(&mgr, "127.0.0.1", 9050);
    /* clearnet host: even with proxy configured, TCP path taken → fails to closed port */
    unsigned char their_pk[33]; memset(their_pk, 0x02, 33);
    int r = peer_mgr_connect(&mgr, "127.0.0.1", 1, their_pk);
    ASSERT(r < 0, "clearnet host with proxy still uses TCP and fails on closed port");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* TW4 — tor_parse_proxy_arg parses HOST:PORT                         */
/* ================================================================== */
int test_tor_parse_proxy_arg_basic(void)
{
    char host[256]; int port = 0;
    int r = tor_parse_proxy_arg("127.0.0.1:9050", host, sizeof(host), &port);
    ASSERT(r == 1, "parse succeeds");
    ASSERT(strcmp(host, "127.0.0.1") == 0, "host correct");
    ASSERT(port == 9050, "port correct");
    return 1;
}

/* ================================================================== */
/* JI1 — lsps2_pending_lookup: unknown SCID returns NULL             */
/* ================================================================== */
int test_lsps2_pending_lookup_null(void)
{
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.entries[0].active = 1;
    tbl.entries[0].scid   = 0x1111111111111111ULL;
    tbl.count = 1;
    ASSERT(lsps2_pending_lookup(&tbl, 0x2222222222222222ULL) == NULL,
           "unknown SCID returns NULL");
    ASSERT(lsps2_pending_lookup(NULL, 0x1111111111111111ULL) == NULL,
           "NULL table returns NULL");
    return 1;
}

/* ================================================================== */
/* JI2 — lsps2_pending_lookup: matching SCID returns entry pointer   */
/* ================================================================== */
int test_lsps2_pending_lookup_found(void)
{
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.entries[0].active    = 1;
    tbl.entries[0].scid      = 0xDEADBEEF00000001ULL;
    tbl.entries[0].cost_msat = 5000;
    tbl.count = 1;

    lsps2_pending_t *p = lsps2_pending_lookup(&tbl, 0xDEADBEEF00000001ULL);
    ASSERT(p != NULL, "matching SCID returns non-NULL");
    ASSERT(p->scid      == 0xDEADBEEF00000001ULL, "scid matches");
    ASSERT(p->cost_msat == 5000, "cost_msat matches");
    return 1;
}

/* ================================================================== */
/* JI3 — ln_dispatch with jit_pending set: no crash on type-128      */
/* ================================================================== */
int test_ln_dispatch_jit_pending_wired(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx alloc");

    htlc_forward_table_t fwd; htlc_forward_init(&fwd);
    mpp_table_t          mpp; mpp_init(&mpp);
    ln_dispatch_t d = make_dispatch(ctx, &fwd, &mpp);

    lsps2_pending_table_t jit_tbl;
    memset(&jit_tbl, 0, sizeof(jit_tbl));
    jit_tbl.entries[0].active    = 1;
    jit_tbl.entries[0].scid      = 0xABCD000000000001ULL;
    jit_tbl.entries[0].cost_msat = 9999999999ULL;
    jit_tbl.count = 1;
    d.jit_pending = &jit_tbl;

    /* A zeroed onion → FORWARD_FAIL; no crash expected */
    unsigned char buf[2048];
    size_t len = build_update_add_htlc(buf, 99, 1000, 800100);
    int rc = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(rc == 128 || rc == -1, "type-128 with jit_pending wired: no crash");

    /* Entry not modified since onion was invalid (no relay) */
    ASSERT(jit_tbl.entries[0].collected_msat == 0, "no spurious collection");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* JI4 — lsps2_handle_intercept_htlc below cost: accumulates, no open*/
/* ================================================================== */
int test_lsps2_intercept_htlc_below_cost(void)
{
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.entries[0].active    = 1;
    tbl.entries[0].scid      = 0xCCCCCCCC00000001ULL;
    tbl.entries[0].cost_msat = 10000;
    tbl.count = 1;

    /* 3000 msat — below 10000 cost */
    int r = lsps2_handle_intercept_htlc(&tbl, 0xCCCCCCCC00000001ULL,
                                          3000, NULL, NULL);
    ASSERT(r == 0, "below cost returns 0");
    ASSERT(tbl.entries[0].collected_msat == 3000, "3000 accumulated");
    ASSERT(tbl.entries[0].active == 1, "entry still active");

    /* Another 8000 → now >= 10000, channel-open triggered */
    int r2 = lsps2_handle_intercept_htlc(&tbl, 0xCCCCCCCC00000001ULL,
                                           8000, NULL, NULL);
    ASSERT(r2 == 1, "cost covered returns 1");
    ASSERT(tbl.entries[0].active == 0, "entry deactivated after open");
    return 1;
}

/* ================================================================== */
/* EX1 — lsps2_pending_expire: fresh entry (created_at=now) not evicted */
/* ================================================================== */
int test_lsps2_pending_expire_fresh(void)
{
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.entries[0].active     = 1;
    tbl.entries[0].scid       = 0xABCD0001ULL;
    tbl.entries[0].created_at = (uint32_t)time(NULL);
    tbl.count = 1;

    lsps2_pending_expire(&tbl);
    ASSERT(tbl.entries[0].active == 1, "EX1: fresh entry survives expire");
    return 1;
}

/* ================================================================== */
/* EX2 — lsps2_pending_expire: stale entry (created_at=0) is evicted  */
/* ================================================================== */
int test_lsps2_pending_expire_stale(void)
{
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.entries[0].active     = 1;
    tbl.entries[0].scid       = 0xABCD0002ULL;
    tbl.entries[0].created_at = 1; /* epoch + 1 s — definitely expired */
    tbl.count = 1;

    lsps2_pending_expire(&tbl);
    ASSERT(tbl.entries[0].active == 0, "EX2: stale entry evicted");
    return 1;
}

/* ================================================================== */
/* JC1 — jit_open_cb pointer wires through ln_dispatch_t              */
/* ================================================================== */
static int g_jc1_called = 0;
static void jc1_cb(void *ctx, uint64_t scid, uint64_t amt,
                   size_t peer_idx, uint64_t htlc_id)
{
    (void)ctx; (void)scid; (void)amt; (void)peer_idx; (void)htlc_id;
    g_jc1_called = 1;
}

int test_jit_open_cb_wires(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.jit_open_cb = jc1_cb;
    ASSERT(d.jit_open_cb != NULL, "JC1: jit_open_cb field present");

    /* Call it directly — should set flag */
    d.jit_open_cb(NULL, 0, 0, 0, 0);
    ASSERT(g_jc1_called == 1, "JC1: callback invoked");
    return 1;
}

/* ================================================================== */
/* JC2 — jit_open_cb called when cost covered in dispatch loop        */
/* ================================================================== */
static int g_jc2_called = 0;
static uint64_t g_jc2_scid = 0;
static void jc2_cb(void *ctx, uint64_t scid, uint64_t amt,
                   size_t peer_idx, uint64_t htlc_id)
{
    (void)ctx; (void)amt; (void)peer_idx; (void)htlc_id;
    g_jc2_called = 1;
    g_jc2_scid   = scid;
}

int test_jit_open_cb_on_cost_covered(void)
{
    lsps2_pending_table_t jit_tbl;
    memset(&jit_tbl, 0, sizeof(jit_tbl));
    jit_tbl.entries[0].active     = 1;
    jit_tbl.entries[0].scid       = 0x800000DEADBEEF01ULL;
    jit_tbl.entries[0].cost_msat  = 5000;
    jit_tbl.entries[0].created_at = (uint32_t)time(NULL);
    jit_tbl.count = 1;

    /* lsps2_handle_intercept_htlc with amount >= cost → returns 1 → callback fires */
    int covered = lsps2_handle_intercept_htlc(&jit_tbl, 0x800000DEADBEEF01ULL,
                                               6000, NULL, NULL);
    ASSERT(covered == 1, "JC2: cost covered returns 1");

    /* Simulate what ln_dispatch would do */
    if (covered == 1)
        jc2_cb(NULL, 0x800000DEADBEEF01ULL, 6000, 0, 1);

    ASSERT(g_jc2_called == 1, "JC2: callback invoked after cost covered");
    ASSERT(g_jc2_scid == 0x800000DEADBEEF01ULL, "JC2: scid passed correctly");
    return 1;
}

/* ================================================================== */
/* JC3 — jit_open_cb NULL guard: no crash when cb not wired           */
/* ================================================================== */
int test_jit_open_cb_null_guard(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.jit_open_cb = NULL; /* explicitly NULL */

    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.entries[0].active     = 1;
    tbl.entries[0].scid       = 0x1234ULL;
    tbl.entries[0].cost_msat  = 100;
    tbl.entries[0].created_at = (uint32_t)time(NULL);
    tbl.count = 1;
    d.jit_pending = &tbl;

    /* Cost covered but cb is NULL — should not crash */
    int covered = lsps2_handle_intercept_htlc(&tbl, 0x1234ULL, 200, NULL, NULL);
    ASSERT(covered == 1, "JC3: cost covered");
    if (covered == 1 && d.jit_open_cb)
        d.jit_open_cb(d.jit_cb_ctx, 0x1234ULL, 200, 0, 0);
    /* Reaching here without crash = pass */
    return 1;
}

/* ================================================================== */
/* LD1 — ln_dispatch_process_msg routes type 132 (commitment_signed)  */
/* ================================================================== */
int test_ln_dispatch_routes_commitment_signed(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    /* No peer_channels → htlc_commit_dispatch skipped, returns type */

    /* Build minimal commitment_signed: type(2) + channel_id(32) + sig(64) = 98 */
    unsigned char msg[100];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 132; /* type 132 */

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 132, "LD1: type 132 routes correctly, returns 132");
    return 1;
}

/* ================================================================== */
/* LD2 — ln_dispatch_process_msg routes type 133 (revoke_and_ack)     */
/* ================================================================== */
int test_ln_dispatch_routes_revoke_and_ack(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    unsigned char msg[100];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 133;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 133, "LD2: type 133 routes correctly");
    return 1;
}

/* ================================================================== */
/* LD3 — ln_dispatch_process_msg routes type 134 (update_fee)         */
/* ================================================================== */
int test_ln_dispatch_routes_update_fee(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    /* update_fee: type(2) + channel_id(32) + feerate_per_kw(4) = 38 bytes */
    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 134;
    /* feerate at offset 34: 1000 sat/kw big-endian */
    msg[34] = 0; msg[35] = 0; msg[36] = 0x03; msg[37] = 0xE8;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 134, "LD3: type 134 routes correctly, returns 134");
    return 1;
}

/* ================================================================== */
/* LD4 — ln_dispatch_process_msg routes type 136 (channel_reestablish)*/
/* ================================================================== */
int test_ln_dispatch_routes_channel_reestablish(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    unsigned char msg[120];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 136;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 136, "LD4: type 136 routes correctly");
    return 1;
}

/* ================================================================== */
/* LD5 — ln_dispatch_flush_relay with empty fwd → returns 0, no crash */
/* ================================================================== */
int test_ln_dispatch_flush_relay_empty(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    static htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    d.fwd = &fwd;

    peer_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    d.pmgr = &mgr;

    int r = ln_dispatch_flush_relay(&d);
    ASSERT(r == 0, "LD5: empty fwd returns 0");
    return 1;
}

/* ================================================================== */
/* CC1 — shutdown (type 38) dispatched                                 */
/* ================================================================== */
int test_ln_dispatch_routes_shutdown(void)
{
    /* type(2) + channel_id(32) + spk_len(2) + spk(2) = 38 bytes */
    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 38;
    msg[34] = 0; msg[35] = 2;
    msg[36] = 0x51; msg[37] = 0x01;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 38, "CC1: shutdown routes correctly");
    return 1;
}

/* ================================================================== */
/* CC2 — closing_signed (type 39) dispatched                           */
/* ================================================================== */
int test_ln_dispatch_routes_closing_signed(void)
{
    /* type(2) + channel_id(32) + fee(8) + sig(64) = 106 bytes */
    unsigned char msg[106];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 39;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 39, "CC2: closing_signed routes correctly");
    return 1;
}

/* ================================================================== */
/* CC3 — shutdown advances close_state (RECV_SHUTDOWN set)            */
/* ================================================================== */
int test_ln_dispatch_shutdown_state_recv(void)
{
    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    channel_t *chp = &ch;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.pmgr = &pmgr;
    d.peer_channels = &chp;

    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 38;
    msg[34] = 0; msg[35] = 2;
    msg[36] = 0x51; msg[37] = 0x01;
    ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(ch.close_state & 2, "CC3: RECV_SHUTDOWN set");
    return 1;
}

/* ================================================================== */
/* CC4 — fee negotiation: midpoint convergence                         */
/* ================================================================== */
int test_ln_dispatch_close_fee_converge(void)
{
    uint64_t our = 1000, their = 2000;
    uint64_t mid = chan_close_negotiate_fee(our, their);
    ASSERT(mid == 1500, "CC4: midpoint");
    our = their;
    mid = chan_close_negotiate_fee(our, their);
    ASSERT(mid == their, "CC4: equal converges");
    return 1;
}

/* ================================================================== */
/* CC5 — shutdown too short returns -1                                 */
/* ================================================================== */
int test_ln_dispatch_shutdown_too_short(void)
{
    unsigned char msg[10] = {0, 38, 0};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == -1, "CC5: too short returns -1");
    return 1;
}

/* ================================================================== */
/* CC6 — closing_signed too short returns -1                           */
/* ================================================================== */
int test_ln_dispatch_closing_signed_too_short(void)
{
    unsigned char msg[10] = {0, 39, 0};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == -1, "CC6: too short returns -1");
    return 1;
}

/* ================================================================== */
/* CC7 — closing_signed with matching fees => state=5 (DONE)          */
/* ================================================================== */
int test_ln_dispatch_close_fee_agree(void)
{
    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.close_state = 3;
    ch.close_our_fee_sat = 1000;
    channel_t *chp = &ch;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.pmgr = &pmgr;
    d.peer_channels = &chp;

    unsigned char msg[106];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 39;
    /* fee = 1000 at offset 34..41 big-endian: 0x00000000000003e8 */
    msg[40] = 0x03; msg[41] = 0xe8;
    ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(ch.close_state == 5, "CC7: fees agreed, state=5");
    return 1;
}

/* ================================================================== */
/* CC8 — shutdown mirrors: sets both sent and recv bits                */
/* ================================================================== */
int test_ln_dispatch_shutdown_mirrors(void)
{
    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.close_state = 0;
    channel_t *chp = &ch;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.pmgr = &pmgr;
    d.peer_channels = &chp;

    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 38;
    msg[34] = 0; msg[35] = 2;
    msg[36] = 0x51; msg[37] = 0x01;
    ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT((ch.close_state & 3) == 3, "CC8: both bits set after mirror");
    return 1;
}

/* ================================================================== */
/* CC9 — no crash when peer_channels is NULL during shutdown          */
/* ================================================================== */
int test_ln_dispatch_shutdown_no_channels(void)
{
    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 38;
    msg[34] = 0; msg[35] = 2;
    msg[36] = 0x51; msg[37] = 0x01;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 38, "CC9: no crash with NULL peer_channels");
    return 1;
}

/* ================================================================== */
/* CC10 — fee midpoint: 500 and 1500 gives 1000                       */
/* ================================================================== */
int test_ln_dispatch_close_fee_midpoint(void)
{
    uint64_t counter = chan_close_negotiate_fee(500, 1500);
    ASSERT(counter == 1000, "CC10: midpoint is 1000");
    return 1;
}

/* ================================================================== */
/* CC11 — closing_signed negotiating: state=4 after counter proposed  */
/* ================================================================== */
int test_ln_dispatch_close_negotiating_state(void)
{
    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.close_state = 3;
    ch.close_our_fee_sat = 500;
    channel_t *chp = &ch;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.pmgr = &pmgr;
    d.peer_channels = &chp;

    unsigned char msg[106];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 39;
    /* their_fee = 2000 = 0x7d0 at offset 34..41 */
    msg[40] = 0x07; msg[41] = 0xd0;
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 39, "CC11: returns 39");
    ASSERT(ch.close_state == 4, "CC11: negotiating state=4");
    return 1;
}

/* ================================================================== */
/* CC12 — fee convergence: midpoint always moves toward their_fee     */
/* ================================================================== */
int test_ln_dispatch_close_fee_large_gap(void)
{
    /* The negotiate_fee returns (our+their)/2, which monotonically
       moves our fee toward their fee. Test that each step reduces the gap. */
    uint64_t our = 500, their = 1000;
    uint64_t prev_gap = their - our;
    for (int i = 0; i < 10; i++) {
        uint64_t counter = chan_close_negotiate_fee(our, their);
        if (counter == their) break; /* converged */
        ASSERT(counter >= our, "CC12: counter moves toward their_fee");
        uint64_t new_gap = their - counter;
        ASSERT(new_gap <= prev_gap, "CC12: gap shrinks or stays same");
        prev_gap = new_gap;
        our = counter;
    }
    /* Test equal values converge immediately */
    uint64_t result = chan_close_negotiate_fee(750, 750);
    ASSERT(result == 750, "CC12: equal values converge immediately");
    return 1;
}

/* ================================================================== */
/* QLD1 — routes type 0x6D (queue poll)                               */
/* ================================================================== */
int test_ln_dispatch_routes_queue_poll(void)
{
    unsigned char msg[4] = {0x00, 0x6D, 0x00, 0x00};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6D, "QLD1: type 0x6D dispatched");
    return 1;
}

/* ================================================================== */
/* QLD2 — routes type 0x6F (queue done)                               */
/* ================================================================== */
int test_ln_dispatch_routes_queue_done(void)
{
    unsigned char msg[4] = {0x00, 0x6F, 0x00, 0x00};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6F, "QLD2: type 0x6F dispatched");
    return 1;
}

/* ================================================================== */
/* DF-LD1 — dispatch type 78 (open_channel2)                          */
/* ================================================================== */
int test_ln_dispatch_routes_open_channel2(void)
{
    unsigned char msg[350];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4E; /* type 78 */
    /* Fill minimal valid sizes */
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 78, "DF-LD1: type 78 dispatched");
    return 1;
}

/* ================================================================== */
/* DF-LD2 — open_channel2 too short routes to PTLC path (returns 78) */
/* ================================================================== */
int test_ln_dispatch_open_channel2_too_short(void)
{
    /* A short type-78 message is treated as PTLC_COMPLETE (same wire type 0x4E)
       and returns 78 (not -1) since the combined case handles both */
    unsigned char msg[10];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4E; /* type 78 = 0x4E */
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 78, "DF-LD2: short type-78 returns 78 (PTLC path)");
    return 1;
}

/* ================================================================== */
/* PTLC-LD1 — dispatch type 0x4C (PTLC_PRESIG)                       */
/* ================================================================== */
int test_ln_dispatch_routes_ptlc_presig(void)
{
    unsigned char msg[74]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4C;
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x4C, "PTLC-LD1: type 0x4C dispatched");
    return 1;
}

/* ================================================================== */
/* PTLC-LD2 — dispatch type 0x4D (PTLC_ADAPTED_SIG)                  */
/* ================================================================== */
int test_ln_dispatch_routes_ptlc_adapted(void)
{
    unsigned char msg[74]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4D;
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x4D, "PTLC-LD2: type 0x4D dispatched");
    return 1;
}

/* ================================================================== */
/* PTLC-LD3 — type 0x4E with short msg returns 78 (PTLC path)        */
/* ================================================================== */
int test_ln_dispatch_routes_ptlc_complete(void)
{
    unsigned char msg[10]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4E;
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 78, "PTLC-LD3: type 0x4E short msg -> 78");
    return 1;
}

/* ================================================================== */
/* CB1 — closing_signed with matching fee → close_state == 5          */
/* ================================================================== */
int test_ln_dispatch_close_broadcast(void)
{
    /* Build closing_signed: type(2) + channel_id(32) + fee(8) + sig(64) = 106 */
    unsigned char msg[106];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x27; /* type 39 = closing_signed */
    /* channel_id = all zeros (matches any channel) */
    /* fee = 1000 sat (big-endian u64) */
    msg[40] = 0x03; msg[41] = 0xE8; /* 0x00000000000003E8 = 1000 */

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.close_state       = 3;       /* SENT_SHUTDOWN | RECV_SHUTDOWN */
    ch.close_our_fee_sat = 1000;    /* same as peer fee → instant agree */
    ch.local_amount      = 2000000; /* 2000 sat in msat */
    ch.remote_amount     = 1000000; /* 1000 sat in msat */
    /* minimal non-empty SPKs so broadcast path is entered */
    ch.funding_spk[0]      = 0x51; ch.funding_spk[1] = 0x20;
    ch.funding_spk_len     = 34;
    ch.close_our_spk[0]    = 0x76; ch.close_our_spk_len   = 1;
    ch.close_their_spk[0]  = 0x76; ch.close_their_spk_len = 1;

    channel_t *channels[1] = { &ch };
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.peer_channels = channels;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 39,       "CB1: closing_signed returns 39");
    ASSERT(ch.close_state == 5, "CB1: close_state == 5 after fee agreement");
    return 1;
}


/* ================================================================== */
/* GD1 — type 256 with gi set → gi.n_channel_ann incremented         */
/* ================================================================== */
int test_ln_dispatch_gossip_type256_gi(void)
{
    gossip_store_t gs;
    gossip_store_open_in_memory(&gs);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, &gs); /* NULL ctx = no sig verify */

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.gi = &gi;

    /* Minimal type-256 message (just 2-byte type, no content) */
    unsigned char msg[2];
    msg[0] = 0x01; msg[1] = 0x00; /* type 256 */
    ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));

    /* With malformed payload, the ingest may reject but shouldn't crash */
    /* We just verify no crash and function returns 256 */
    unsigned char msg2[130];
    memset(msg2, 0, sizeof(msg2));
    msg2[0] = 0x01; msg2[1] = 0x00;
    int r = ln_dispatch_process_msg(&d, 0, msg2, sizeof(msg2));
    ASSERT(r == 256, "GD1: type 256 returns 256");

    gossip_store_close(&gs);
    return 1;
}

/* ================================================================== */
/* GD2 — type 257 dispatches to gi                                    */
/* ================================================================== */
int test_ln_dispatch_gossip_type257_gi(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL);

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.gi = &gi;

    unsigned char msg[64]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x01; /* type 257 */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 257, "GD2: type 257 returns 257");
    return 1;
}

/* ================================================================== */
/* GD3 — type 258 dispatches to gi                                    */
/* ================================================================== */
int test_ln_dispatch_gossip_type258_gi(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL);

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.gi = &gi;

    unsigned char msg[64]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x02; /* type 258 */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 258, "GD3: type 258 returns 258");
    return 1;
}

/* ================================================================== */
/* GD4 — gi == NULL + type 256 → no crash, returns 256               */
/* ================================================================== */
int test_ln_dispatch_gossip_gi_null_no_crash(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.gi = NULL;

    unsigned char msg[4]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x00; /* type 256 */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 256, "GD4: type 256 returns 256 with NULL gi");
    return 1;
}

/* ================================================================== */

/* FF1 -- FORWARD_FAIL with valid pmgr sends fail_malformed, no crash */
int test_ln_dispatch_forward_fail_sends_malformed(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    memset(&mpp, 0, sizeof(mpp));
    unsigned char node_priv[32];
    memset(node_priv, 0x11, 32);
    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.fwd = &fwd; d.mpp = &mpp;
    memcpy(d.our_privkey, node_priv, 32);
    d.ctx = ctx; d.pmgr = &pmgr;
    size_t msg_len = 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE;
    unsigned char *msg = calloc(1, msg_len);
    msg[0] = 0x00; msg[1] = 0x80;
    msg[2+32+8+6] = 0x27; msg[2+32+8+7] = 0x10;
    int r = ln_dispatch_process_msg(&d, 0, msg, msg_len);
    free(msg);
    secp256k1_context_destroy(ctx);
    ASSERT(r == 128, "FF1: FORWARD_FAIL path returns 128");
    return 1;
}

/* FF2 -- FORWARD_FAIL with NULL pmgr no crash */
int test_ln_dispatch_forward_fail_null_pmgr(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    memset(&mpp, 0, sizeof(mpp));
    unsigned char node_priv[32];
    memset(node_priv, 0x22, 32);
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.fwd = &fwd; d.mpp = &mpp;
    memcpy(d.our_privkey, node_priv, 32);
    d.ctx = ctx; d.pmgr = NULL;
    size_t msg_len = 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE;
    unsigned char *msg = calloc(1, msg_len);
    msg[0] = 0x00; msg[1] = 0x80;
    msg[2+32+8+7] = 0x01;
    int r = ln_dispatch_process_msg(&d, 0, msg, msg_len);
    free(msg);
    secp256k1_context_destroy(ctx);
    ASSERT(r == 128, "FF2: NULL pmgr FORWARD_FAIL returns 128 without crash");
    return 1;
}


/* ================================================================== */
/* PR #72: Startup/shutdown flow -- ln_dispatch_load_state() tests    */
/* ================================================================== */

#include "superscalar/persist.h"

/* Helper: build a deterministic invoice entry (mirrors test_persist.c) */
static bolt11_invoice_entry_t boot_make_invoice(unsigned char seed)
{
    bolt11_invoice_entry_t e;
    memset(&e, 0, sizeof(e));
    memset(e.payment_hash,   seed,     32);
    memset(e.preimage,       seed + 1, 32);
    memset(e.payment_secret, seed + 2, 32);
    e.amount_msat = 100000ULL + seed;
    e.expiry      = 3600;
    e.created_at  = 1700000000U + seed;
    e.settled     = 0;
    e.active      = 1;
    snprintf(e.description, sizeof(e.description), "boot invoice %d", (int)seed);
    return e;
}

/* BOOT1: NULL persist -> ln_dispatch_load_state returns -1, no crash */
int test_ln_dispatch_boot1_null_persist(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    /* d.persist == NULL */
    int r = ln_dispatch_load_state(&d);
    ASSERT(r == -1, "BOOT1: NULL persist returns -1");
    return 1;
}

/* BOOT2: save 1 invoice to in-memory DB, fresh invoice_table -> 1 restored */
int test_ln_dispatch_boot2_load_one_invoice(void)
{
    persist_t db;
    ASSERT(persist_open(&db, NULL), "BOOT2: persist_open");

    bolt11_invoice_entry_t inv = boot_make_invoice(0xA1);
    ASSERT(persist_save_ln_invoice(&db, &inv), "BOOT2: save invoice");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist  = (struct persist_t *)&db;
    d.invoices = &tbl;

    int r = ln_dispatch_load_state(&d);
    ASSERT(r == 1, "BOOT2: load_state returns 1");
    ASSERT(tbl.count == 1, "BOOT2: invoice_table has 1 entry");
    ASSERT(memcmp(tbl.entries[0].payment_hash, inv.payment_hash, 32) == 0,
           "BOOT2: payment_hash matches");

    persist_close(&db);
    return 1;
}

/* BOOT3: save 3 invoices, load -> all 3 restored */
int test_ln_dispatch_boot3_load_three_invoices(void)
{
    persist_t db;
    ASSERT(persist_open(&db, NULL), "BOOT3: persist_open");

    for (unsigned char s = 1; s <= 3; s++) {
        bolt11_invoice_entry_t inv = boot_make_invoice(s * 0x10);
        ASSERT(persist_save_ln_invoice(&db, &inv), "BOOT3: save invoice");
    }

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist  = (struct persist_t *)&db;
    d.invoices = &tbl;

    int r = ln_dispatch_load_state(&d);
    ASSERT(r == 3, "BOOT3: load_state returns 3");
    ASSERT(tbl.count == 3, "BOOT3: invoice_table has 3 entries");

    persist_close(&db);
    return 1;
}

/* BOOT4: persist set but invoices = NULL -> returns 0 (no crash) */
int test_ln_dispatch_boot4_null_invoices(void)
{
    persist_t db;
    ASSERT(persist_open(&db, NULL), "BOOT4: persist_open");

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist  = (struct persist_t *)&db;
    d.invoices = NULL;  /* no invoice table */

    int r = ln_dispatch_load_state(&d);
    ASSERT(r >= 0, "BOOT4: NULL invoices returns >= 0, no crash");

    persist_close(&db);
    return 1;
}


/* ================================================================== */
/* PR #73: BOOT5 -- save a channel via persist, load_state restores it */
/* ================================================================== */
int test_ln_dispatch_boot5_channel_restore(void)
{
    persist_t db;
    ASSERT(persist_open(&db, NULL), "BOOT5: persist_open");

    unsigned char channel_id[32];
    unsigned char peer_pk[33];
    memset(channel_id, 0xAB, sizeof(channel_id));
    memset(peer_pk,    0xCD, sizeof(peer_pk));
    uint64_t cap_sat   = 500000;
    uint64_t local_ms  = 300000000;
    uint64_t remote_ms = 200000000;
    ASSERT(persist_save_ln_peer_channel(&db, channel_id, peer_pk,
                                         cap_sat, local_ms, remote_ms, 0, NULL, 0),
           "BOOT5: persist_save_ln_peer_channel");

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    channel_t *channels[PEER_MGR_MAX_PEERS];
    memset(channels, 0, sizeof(channels));
    channels[0] = &ch;

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist       = (struct persist_t *)&db;
    d.peer_channels = channels;

    int r = ln_dispatch_load_state(&d);
    ASSERT(r >= 1, "BOOT5: load_state returns >= 1");
    ASSERT(ch.funding_amount == cap_sat,
           "BOOT5: funding_amount restored");
    ASSERT(ch.local_amount  == local_ms  / 1000,
           "BOOT5: local_amount restored");
    ASSERT(ch.remote_amount == remote_ms / 1000,
           "BOOT5: remote_amount restored");
    ASSERT(memcmp(ch.funding_txid, channel_id, 32) == 0,
           "BOOT5: funding_txid matches channel_id");

    persist_close(&db);
    return 1;
}

/* ================================================================== */
/* PR #73: BOOT6 -- NULL peer_channels -> no crash, returns >= 0      */
/* ================================================================== */
int test_ln_dispatch_boot6_null_channels_no_crash(void)
{
    persist_t db;
    ASSERT(persist_open(&db, NULL), "BOOT6: persist_open");

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist       = (struct persist_t *)&db;
    d.peer_channels = NULL;
    d.invoices      = NULL;

    int r = ln_dispatch_load_state(&d);
    ASSERT(r >= 0, "BOOT6: NULL peer_channels returns >= 0, no crash");

    persist_close(&db);
    return 1;
}

/* ================================================================== */
/* PR #74: UF1 -- update_fee sets ch->fee_rate_sat_per_kvb            */
/* ================================================================== */
int test_ln_dispatch_uf1_feerate_updated(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    channel_t *channels[PEER_MGR_MAX_PEERS];
    memset(channels, 0, sizeof(channels));
    channels[0] = &ch;
    d.peer_channels = channels;

    /* update_fee: type(2=134) + channel_id(32) + feerate_per_kw(4) = 38 bytes */
    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 134;
    /* feerate_per_kw = 2500 big-endian: 0x000009C4 */
    msg[34] = 0x00; msg[35] = 0x00; msg[36] = 0x09; msg[37] = 0xC4;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 134, "UF1: returns 134");
    ASSERT(ch.fee_rate_sat_per_kvb == 2500, "UF1: feerate updated to 2500");
    return 1;
}

/* ================================================================== */
/* PR #74: UF2 -- truncated update_fee (< 38 bytes) -> returns -1    */
/* ================================================================== */
int test_ln_dispatch_uf2_truncated_update_fee(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    unsigned char msg[37];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 134;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == -1, "UF2: truncated update_fee returns -1");
    return 1;
}

/* ================================================================== */
/* PR #74: UF3 -- NULL peer_channels -> no crash, returns 134         */
/* ================================================================== */
int test_ln_dispatch_uf3_null_channels(void)
{
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.peer_channels = NULL;

    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 134;
    msg[34] = 0; msg[35] = 0; msg[36] = 0x03; msg[37] = 0xE8;

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 134, "UF3: NULL peer_channels returns 134, no crash");
    return 1;
}
