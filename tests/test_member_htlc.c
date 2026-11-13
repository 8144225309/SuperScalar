/* A member decides on the HTLCs in its own channel from its own state:
   the direction of an HTLC, whether an incoming one pays its invoice, and
   the preimage it makes for an invoice. */
#include "superscalar/client.h"
#include "superscalar/channel.h"
#include "superscalar/wire.h"
#include "superscalar/sha256.h"
#include "superscalar/invoice.h"
#include "superscalar/bolt11.h"
#include "test_onion_util.h"
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %lld, expected %lld)\n", \
               __func__, __LINE__, msg, (long long)(a), (long long)(b)); \
        return 0; \
    } \
} while(0)

static void member_channel(channel_t *ch) {
    memset(ch, 0, sizeof(*ch));
    ch->local_amount = 100000;
    ch->remote_amount = 100000;
}

static wire_msg_t host_add(uint64_t id, uint64_t amount_msat,
                           const unsigned char *hash, uint32_t cltv,
                           int dest_client) {
    wire_msg_t m;
    m.msg_type = MSG_UPDATE_ADD_HTLC;
    m.json = wire_build_update_add_htlc(id, amount_msat, hash, cltv);
    if (dest_client >= 0)
        cJSON_AddNumberToObject(m.json, "dest_client", dest_client);
    return m;
}

/* An add from the host is an HTLC the host offers to the member.  One that
   claims to be the member's own payment (dest_client) is refused and
   changes nothing; only the member's own add books an HTLC it offers. */
int test_member_host_add_is_never_own_payment(void) {
    channel_t ch;
    member_channel(&ch);
    unsigned char hash[32];
    memset(hash, 0x5a, 32);

    for (int dest = 0; dest < 3; dest++) {
        wire_msg_t m = host_add(7, 20000000, hash, 500, dest);
        TEST_ASSERT(!client_handle_add_htlc(&ch, &m),
                    "a host add claiming to be ours is refused");
        cJSON_Delete(m.json);
        TEST_ASSERT_EQ(ch.local_amount, 100000, "member balance unchanged");
        TEST_ASSERT_EQ(ch.remote_amount, 100000, "host balance unchanged");
        TEST_ASSERT_EQ(ch.n_htlcs, 0, "nothing booked");
        TEST_ASSERT_EQ(ch.commitment_number, 0, "no new state");
    }

    /* The same add without the claim is an incoming HTLC. */
    wire_msg_t m = host_add(7, 20000000, hash, 500, -1);
    TEST_ASSERT(client_handle_add_htlc(&ch, &m), "incoming HTLC booked");
    cJSON_Delete(m.json);
    TEST_ASSERT_EQ(ch.n_htlcs, 1, "one HTLC");
    TEST_ASSERT(ch.htlcs[0].direction == HTLC_RECEIVED, "offered to us");
    TEST_ASSERT_EQ(ch.htlcs[0].id, 7, "under the host's id");
    TEST_ASSERT_EQ(ch.local_amount, 100000, "member balance unchanged");

    /* A payment the member makes itself is booked when it sends the add. */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    unsigned char h2[32];
    memset(h2, 0x6b, 32);
    TEST_ASSERT(client_send_payment(sv[0], &ch, 3000, h2, 500, 1), "send");
    TEST_ASSERT_EQ(ch.n_htlcs, 2, "two HTLCs");
    TEST_ASSERT(ch.htlcs[1].direction == HTLC_OFFERED, "ours");
    TEST_ASSERT(ch.local_amount < 100000, "member pays for its own payment");
    wire_msg_t sent;
    TEST_ASSERT(wire_recv_timeout(sv[1], &sent, 5), "add sent");
    TEST_ASSERT_EQ(sent.msg_type, MSG_UPDATE_ADD_HTLC, "UPDATE_ADD_HTLC");
    cJSON_Delete(sent.json);
    close(sv[0]);
    close(sv[1]);
    channel_cleanup(&ch);
    return 1;
}

/* What the member sends after settling: 1 fulfil, 0 fail, -1 other. */
static int sent_kind(int fd, const unsigned char *preimage) {
    wire_msg_t m;
    if (!wire_recv_timeout(fd, &m, 5)) return -1;
    int kind = -1;
    char *s = m.json ? cJSON_PrintUnformatted(m.json) : NULL;
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", preimage[i]);
    int leaks = s && strstr(s, hex) != NULL;
    if (m.msg_type == MSG_UPDATE_FULFILL_HTLC) kind = 1;
    else if (m.msg_type == MSG_UPDATE_FAIL_HTLC && !leaks) kind = 0;
    free(s);
    if (m.json) cJSON_Delete(m.json);
    return kind;
}

/* The member releases its preimage only for an HTLC that pays its
   invoice: at least the invoiced amount, expiring far enough past the
   chain tip.  Anything else is failed back and the preimage kept. */
int test_member_underpaid_htlc_gets_no_preimage(void) {
    unsigned char pre[32], hash[32];
    memset(pre, 0x11, 32);
    sha256(pre, 32, hash);
    const uint64_t invoice_msat = 20000000;   /* 20000 sat */
    const uint32_t tip = 400;
    struct { uint64_t sats; uint32_t cltv; uint32_t tip; int want; const char *what; }
    cases[] = {
        {  5000, 500, tip,  0, "a quarter of the invoice" },
        { 19999, 500, tip,  0, "one sat short" },
        { 20000, 500, tip,  1, "the invoiced amount" },
        { 25000, 500, tip,  1, "more than the invoice" },
        { 20000, tip + CLIENT_MIN_FINAL_CLTV_DELTA - 1, tip, 0, "expiring too soon" },
        { 20000, tip + CLIENT_MIN_FINAL_CLTV_DELTA, tip, 1, "expiring just late enough" },
        { 20000, 500, 0,    0, "no chain tip to judge the expiry by" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        channel_t ch;
        member_channel(&ch);
        wire_msg_t m = host_add(3, cases[i].sats * 1000, hash, cases[i].cltv, -1);
        TEST_ASSERT(client_handle_add_htlc(&ch, &m), "HTLC booked");
        cJSON_Delete(m.json);
        uint64_t local0 = ch.local_amount;
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        int r = client_settle_invoice_htlc(sv[0], &ch, 3, pre, invoice_msat,
                                           NULL, NULL, cases[i].tip);
        int kind = sent_kind(sv[1], pre);
        close(sv[0]);
        close(sv[1]);
        if (r != cases[i].want || kind != cases[i].want) {
            printf("  case: %s (r=%d, sent=%d)\n", cases[i].what, r, kind);
            TEST_ASSERT(0, "settled as the invoice says");
        }
        if (cases[i].want) {
            TEST_ASSERT_EQ(ch.local_amount, local0 + cases[i].sats, "paid");
        } else {
            TEST_ASSERT_EQ(ch.local_amount, local0, "not paid");
            TEST_ASSERT(ch.htlcs[0].state == HTLC_STATE_FAILED, "failed back");
        }
        channel_cleanup(&ch);
    }
    return 1;
}

static int rng_fails(unsigned char *buf, size_t len) {
    (void)buf; (void)len;
    return 0;
}

/* Without fresh randomness there is no invoice preimage at all. */
int test_member_invoice_preimage_needs_randomness(void) {
    unsigned char pre[32], hash[32];
    memset(pre, 0xee, 32);
    memset(hash, 0xee, 32);
    client_set_rand_source(rng_fails);
    int r = client_new_invoice_preimage(pre, hash);
    client_set_rand_source(NULL);
    TEST_ASSERT(!r, "no randomness, no invoice");
    unsigned char zero[32];
    memset(zero, 0, 32);
    TEST_ASSERT(memcmp(pre, zero, 32) == 0 && memcmp(hash, zero, 32) == 0,
                "nothing usable is left behind");

    unsigned char pre2[32], hash2[32], check[32];
    TEST_ASSERT(client_new_invoice_preimage(pre, hash), "fresh preimage");
    TEST_ASSERT(client_new_invoice_preimage(pre2, hash2), "another one");
    sha256(pre, 32, check);
    TEST_ASSERT(memcmp(check, hash, 32) == 0, "hash of the preimage");
    TEST_ASSERT(memcmp(pre, pre2, 32) != 0, "a new preimage every time");
    return 1;
}


/* --- The member's own invoice, paid from outside the factory --- */

/* The onion a payer's node builds for us, the last hop: it decodes only
   with our key, only for its payment hash, and only untouched. */
int test_member_final_hop_onion(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char sk[32], other[32], sess[32], secret[32], hash[32], hash2[32];
    memset(sk, 0x31, 32); memset(other, 0x32, 32); memset(sess, 0x41, 32);
    memset(secret, 0x51, 32); memset(hash, 0x61, 32); memset(hash2, 0x62, 32);
    secp256k1_pubkey pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, sk), "key");

    unsigned char tlv[80], onion[1366];
    size_t n = test_final_hop_tlv(20000000, 520, secret, 20000000, tlv);
    TEST_ASSERT(test_build_final_onion(ctx, sess, &pk, tlv, n, hash, 32, onion),
                "build");
    client_final_hop_t hop;
    TEST_ASSERT(client_decode_final_hop(ctx, sk, onion, hash, &hop), "decodes");
    TEST_ASSERT(hop.present && hop.has_payment_data, "payment data");
    TEST_ASSERT_EQ(hop.amt_to_forward, 20000000, "amount");
    TEST_ASSERT_EQ(hop.outgoing_cltv, 520, "expiry");
    TEST_ASSERT_EQ(hop.total_msat, 20000000, "total");
    TEST_ASSERT(memcmp(hop.payment_secret, secret, 32) == 0, "secret");

    TEST_ASSERT(!client_decode_final_hop(ctx, other, onion, hash, &hop) &&
                hop.present && !hop.has_payment_data, "not for another key");
    TEST_ASSERT(!client_decode_final_hop(ctx, sk, onion, hash2, &hop),
                "not for another payment hash");
    onion[600] ^= 1;
    TEST_ASSERT(!client_decode_final_hop(ctx, sk, onion, hash, &hop),
                "a changed onion is refused");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* BOLT 4 final-hop rules for a payment to our own BOLT 11 invoice: the
   onion names our payment secret, a single part, at least the invoice
   amount, and no more than the HTLC carries; without an onion (or with
   one that is not ours) the preimage stays with us. */
int test_member_external_payment_rules(void) {
    unsigned char secret[32], wrong[32];
    memset(secret, 0x51, 32);
    memset(wrong, 0x52, 32);
    const uint64_t inv = 20000000;
    const uint32_t tip = 400;
    htlc_t h;
    memset(&h, 0, sizeof(h));
    h.direction = HTLC_RECEIVED;
    h.state = HTLC_STATE_ACTIVE;
    h.amount_sats = 20000;
    h.cltv_expiry = 520;

    client_final_hop_t ok;
    memset(&ok, 0, sizeof(ok));
    ok.present = 1; ok.has_payment_data = 1;
    memcpy(ok.payment_secret, secret, 32);
    ok.amt_to_forward = 20000000; ok.total_msat = 20000000; ok.outgoing_cltv = 520;
    TEST_ASSERT(client_htlc_pays_invoice(&h, inv, secret, &ok, tip),
                "a valid outside payment pays");

    client_final_hop_t c = ok;
    memcpy(c.payment_secret, wrong, 32);
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, &c, tip), "wrong secret");
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, NULL, tip), "no onion");
    c = ok; c.has_payment_data = 0;
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, &c, tip),
                "an onion that is not ours");
    c = ok; c.total_msat = 40000000;
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, &c, tip),
                "a part of a multi-part payment");
    c = ok; c.amt_to_forward = c.total_msat = 19000000;
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, &c, tip),
                "less than the invoice");
    c = ok; c.amt_to_forward = c.total_msat = 21000000;
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, &c, tip),
                "the onion asks for more than the HTLC carries");
    c = ok; c.outgoing_cltv = 521;
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, secret, &c, tip),
                "the HTLC expires sooner than the onion says");

    /* an invoice for a payment inside the factory takes no onion */
    TEST_ASSERT(client_htlc_pays_invoice(&h, inv, NULL, NULL, tip), "internal");
    TEST_ASSERT(!client_htlc_pays_invoice(&h, inv, NULL, &ok, tip),
                "internal invoice with an outside onion");
    return 1;
}

/* The member signs its invoice itself, through the LSP's node: the invoice
   names the member as payee, carries the route hint, and what the member
   sends the LSP holds the hash but not the preimage or the secret. */
int test_member_signs_its_own_invoice(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char sk[32];
    memset(sk, 0x31, 32);
    secp256k1_pubkey pk;
    unsigned char pk33[33];
    size_t len = 33;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, sk) &&
                secp256k1_ec_pubkey_serialize(ctx, pk33, &len, &pk,
                                              SECP256K1_EC_COMPRESSED), "key");
    unsigned char lsp_node[33];
    lsp_node[0] = 0x03;
    memset(lsp_node + 1, 0x44, 32);
    uint64_t scid = (700ULL << 40) | (1ULL << 16) | 2;

    bolt11_invoice_table_t *tbl = calloc(1, sizeof(*tbl));
    TEST_ASSERT(tbl != NULL, "alloc");
    invoice_init(tbl);
    char b11[2048];
    TEST_ASSERT(invoice_create_with_hint(tbl, ctx, sk, "regtest", 20000000,
                    "member", 0, lsp_node, scid, 0, 0, 40, b11, sizeof(b11)),
                "member signs");
    const bolt11_invoice_entry_t *e = NULL;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++)
        if (tbl->entries[i].active) e = &tbl->entries[i];
    TEST_ASSERT(e != NULL, "entry");

    bolt11_invoice_t d;
    TEST_ASSERT(bolt11_decode(ctx, b11, &d), "decodes");
    TEST_ASSERT(memcmp(d.payee_pubkey, pk33, 33) == 0, "the member is the payee");
    TEST_ASSERT(memcmp(d.payment_hash, e->payment_hash, 32) == 0, "hash");
    TEST_ASSERT(d.has_payment_secret &&
                memcmp(d.payment_secret, e->payment_secret, 32) == 0, "secret");
    TEST_ASSERT(d.n_hints == 1 && d.hints[0].n_hops == 1 &&
                memcmp(d.hints[0].hops[0].pubkey, lsp_node, 33) == 0 &&
                d.hints[0].hops[0].short_channel_id == scid,
                "routed through the LSP's node");

    /* What the LSP is sent */
    char pre_hex[65], sec_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(pre_hex + 2 * i, "%02x", e->preimage[i]);
        sprintf(sec_hex + 2 * i, "%02x", e->payment_secret[i]);
    }
    cJSON *created = wire_build_invoice_created(e->payment_hash, 20000000);
    wire_invoice_created_set_bolt11(created, b11);
    cJSON *reg = wire_build_register_invoice(e->payment_hash, 20000000, 0);
    char *a = cJSON_PrintUnformatted(created), *b = cJSON_PrintUnformatted(reg);
    TEST_ASSERT(a && b && !strstr(a, pre_hex) && !strstr(b, pre_hex) &&
                !strstr(b, sec_hex), "no preimage (or secret) goes to the LSP");
    free(a); free(b);
    cJSON_Delete(created);
    cJSON_Delete(reg);
    free(tbl);
    secp256k1_context_destroy(ctx);
    return 1;
}
