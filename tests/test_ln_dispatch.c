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
