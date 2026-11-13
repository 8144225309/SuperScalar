/*
 * fuzz_client_msg.c -- libFuzzer harness: sequences of channel messages
 * against an in-memory channel, on the member's side and on the LSP's.
 *
 * Each input sets up a funded channel pair (LSP and member channel_t over
 * one 2-of-2 funding output, basepoints, per-commitment points and nonce
 * pools exchanged: the state right after channel open), then plays a
 * sequence of operations, one per input chunk:
 *
 *   byte 0, bit 0 = 0: the member's handlers (src/client.c) take the
 *                      messages, as the member daemon dispatches them:
 *                      UPDATE_ADD_HTLC, COMMITMENT_SIGNED, UPDATE_FULFILL_HTLC,
 *                      UPDATE_FAIL_HTLC, LSP_REVOKE_AND_ACK and the async
 *                      notices; the member also offers and fulfils HTLCs.
 *   byte 0, bit 0 = 1: the LSP's per-client handler (lsp_channels_handle_msg)
 *                      takes the messages of one of two members.
 *
 * A message is either built with the wire builders from fuzzed fields
 * (ids, amounts, hashes, secrets, nonce indices), signed honestly by the
 * other side's channel where the operation says so, or parsed from fuzzed
 * JSON text.  The other end of every connection is drained after each
 * operation and never answers (reads see end of file).
 *
 * After every operation each channel must still conserve its funding:
 * local + remote + every active HTLC (with its fee) == funding - base
 * commitment fee (client_channel_balanced), and neither balance may exceed
 * the funding.  A violation aborts.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <secp256k1.h>
#include "superscalar/channel.h"
#include "superscalar/client.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wire.h"
#include "cJSON.h"

static secp256k1_context *g_ctx;

/* ---- input reader ---- */
typedef struct { const uint8_t *p; size_t n; } in_t;

static int take(in_t *in, void *out, size_t len) {
    if (in->n < len) { memset(out, 0, len); in->n = 0; return 0; }
    memcpy(out, in->p, len);
    in->p += len; in->n -= len;
    return 1;
}
static uint8_t u8(in_t *in) { uint8_t v; take(in, &v, 1); return v; }
static uint16_t u16(in_t *in) { uint8_t b[2]; take(in, b, 2); return (uint16_t)(b[0] | (b[1] << 8)); }
static uint32_t u32(in_t *in) { uint8_t b[4]; take(in, b, 4); return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }

/* ---- channel pair ---- */
static void fill_secret(unsigned char *s, unsigned char tag) {
    memset(s, tag, 32);
    s[0] = 0x01;
}

/* lsp_ch: the LSP's channel (LSP local), cl_ch: the member's.  Balances
   lsp_amt / cl_amt add up to funding less the base commitment fee. */
static int channel_pair(channel_t *lsp_ch, channel_t *cl_ch, unsigned char key_tag,
                        uint64_t funding, uint64_t lsp_amt, uint64_t cl_amt) {
    unsigned char lsp_sec[32], cl_sec[32], txid[32], spk[34], s[4][32];
    fill_secret(lsp_sec, (unsigned char)(0x31 + key_tag));
    fill_secret(cl_sec, (unsigned char)(0x51 + key_tag));
    memset(txid, 0xC4 ^ key_tag, 32);
    secp256k1_pubkey lsp_pk, cl_pk;
    if (!secp256k1_ec_pubkey_create(g_ctx, &lsp_pk, lsp_sec) ||
        !secp256k1_ec_pubkey_create(g_ctx, &cl_pk, cl_sec)) return 0;
    secp256k1_pubkey order[2] = { cl_pk, lsp_pk };
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(g_ctx, &ka, order, 2)) return 0;
    unsigned char ser[32], twk[32];
    secp256k1_pubkey tweaked;
    secp256k1_xonly_pubkey out_key;
    if (!secp256k1_xonly_pubkey_serialize(g_ctx, ser, &ka.agg_pubkey)) return 0;
    sha256_tagged("TapTweak", ser, 32, twk);
    if (!secp256k1_xonly_pubkey_tweak_add(g_ctx, &tweaked, &ka.agg_pubkey, twk) ||
        !secp256k1_xonly_pubkey_from_pubkey(g_ctx, &out_key, NULL, &tweaked)) return 0;
    build_p2tr_script_pubkey(spk, &out_key);

    if (!channel_init(lsp_ch, g_ctx, lsp_sec, &lsp_pk, &cl_pk, txid, 0, funding,
                      spk, 34, lsp_amt, cl_amt, 144)) return 0;
    if (!channel_init(cl_ch, g_ctx, cl_sec, &cl_pk, &lsp_pk, txid, 0, funding,
                      spk, 34, cl_amt, lsp_amt, 144)) {
        channel_cleanup(lsp_ch);
        return 0;
    }
    channel_set_commit_fee_rate(lsp_ch, 100);
    channel_set_commit_fee_rate(cl_ch, 100);
    lsp_ch->funder_is_local = 1;
    cl_ch->funder_is_local = 0;
    for (int i = 0; i < 4; i++) fill_secret(s[i], (unsigned char)(0x70 + 16 * key_tag + i));
    channel_set_local_basepoints(lsp_ch, s[0], s[1], s[2]);
    channel_set_local_htlc_basepoint(lsp_ch, s[3]);
    for (int i = 0; i < 4; i++) fill_secret(s[i], (unsigned char)(0x90 + 16 * key_tag + i));
    channel_set_local_basepoints(cl_ch, s[0], s[1], s[2]);
    channel_set_local_htlc_basepoint(cl_ch, s[3]);
    channel_set_remote_basepoints(lsp_ch, &cl_ch->local_payment_basepoint,
        &cl_ch->local_delayed_payment_basepoint, &cl_ch->local_revocation_basepoint);
    channel_set_remote_basepoints(cl_ch, &lsp_ch->local_payment_basepoint,
        &lsp_ch->local_delayed_payment_basepoint, &lsp_ch->local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(lsp_ch, &cl_ch->local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(cl_ch, &lsp_ch->local_htlc_basepoint);
    for (uint64_t cn = 0; cn < 2; cn++) {
        secp256k1_pubkey p;
        if (!channel_get_per_commitment_point(cl_ch, cn, &p)) return 0;
        channel_set_remote_pcp(lsp_ch, cn, &p);
        if (!channel_get_per_commitment_point(lsp_ch, cn, &p)) return 0;
        channel_set_remote_pcp(cl_ch, cn, &p);
    }
    if (!channel_init_nonce_pool(lsp_ch, 8) || !channel_init_nonce_pool(cl_ch, 8)) return 0;
    unsigned char nonces[8][66];
    for (size_t i = 0; i < 8; i++)
        musig_pubnonce_serialize(g_ctx, nonces[i], &lsp_ch->local_nonce_pool.nonces[i].pubnonce);
    channel_set_remote_pubnonces(cl_ch, (const unsigned char (*)[66])nonces, 8);
    for (size_t i = 0; i < 8; i++)
        musig_pubnonce_serialize(g_ctx, nonces[i], &cl_ch->local_nonce_pool.nonces[i].pubnonce);
    channel_set_remote_pubnonces(lsp_ch, (const unsigned char (*)[66])nonces, 8);
    return 1;
}

static void check_conserved(const channel_t *ch, const char *who) {
    if (ch->local_amount > ch->funding_amount || ch->remote_amount > ch->funding_amount ||
        !client_channel_balanced(ch)) {
        fprintf(stderr, "fuzz_client_msg: %s channel no longer conserves its funding: "
                "local=%llu remote=%llu htlcs=%zu funding=%llu\n", who,
                (unsigned long long)ch->local_amount, (unsigned long long)ch->remote_amount,
                ch->n_htlcs, (unsigned long long)ch->funding_amount);
        abort();
    }
}

static void drain(int fd) {
    unsigned char buf[4096];
    while (read(fd, buf, sizeof(buf)) > 0) {}
}

/* Message types the member's dispatcher handles, and the LSP's. */
static const uint8_t client_types[] = {
    MSG_UPDATE_ADD_HTLC, MSG_COMMITMENT_SIGNED, MSG_UPDATE_FULFILL_HTLC,
    MSG_UPDATE_FAIL_HTLC, MSG_LSP_REVOKE_AND_ACK, MSG_FUNDING_REORG, MSG_CEREMONY_ABORT,
};
static const uint8_t lsp_types[] = {
    MSG_UPDATE_ADD_HTLC, MSG_UPDATE_FULFILL_HTLC, MSG_UPDATE_FAIL_HTLC,
    MSG_COMMITMENT_SIGNED, MSG_REVOKE_AND_ACK, MSG_REGISTER_INVOICE,
};

/* A message from the input: fuzzed JSON text, or one built with the wire
   builders from fuzzed fields (signed by `signer` when asked). */
static int build_msg(in_t *in, const uint8_t *types, size_t n_types,
                     channel_t *signer, wire_msg_t *m) {
    uint8_t sel = u8(in);
    m->msg_type = types[(sel & 0x3f) % n_types];
    m->json = NULL;
    if (sel & 0x80) {                         /* raw JSON text */
        size_t len = u8(in);
        if (len > in->n) len = in->n;
        char *txt = malloc(len + 1);
        if (!txt) return 0;
        take(in, txt, len);
        txt[len] = 0;
        m->json = cJSON_Parse(txt);
        free(txt);
        return m->json != NULL;
    }
    unsigned char h32[32], p33[33];
    uint64_t id = u8(in) % 8;
    switch (m->msg_type) {
    case MSG_UPDATE_ADD_HTLC: {
        uint64_t amt = (uint64_t)u16(in) * (1 + (u8(in) % 4));
        uint32_t cltv = 100 + u16(in);
        memset(h32, u8(in), 32);
        uint8_t mode = u8(in);
        uint64_t msat = amt * 1000 + (mode & 1);
        if ((sel & 0x40) && signer) {
            /* offered honestly: the sender's own channel takes it too */
            uint64_t lid;
            if (channel_add_htlc(signer, HTLC_OFFERED, amt, h32, cltv, &lid)) id = lid;
        }
        m->json = wire_build_update_add_htlc(id, msat, h32, cltv);
        if (m->json && (mode & 2)) cJSON_AddNumberToObject(m->json, "dest_client", (mode >> 2) & 3);
        break;
    }
    case MSG_COMMITMENT_SIGNED: {
        unsigned char psig[32];
        uint32_t nidx = u8(in) % 10;
        uint64_t cn = u8(in) % 6;
        if ((sel & 0x40) && signer &&
            channel_create_commitment_partial_sig(signer, psig, &nidx)) {
            cn = signer->commitment_number;
        } else {
            take(in, psig, 32);
        }
        m->json = wire_build_commitment_signed(0, cn, psig, nidx);
        break;
    }
    case MSG_UPDATE_FULFILL_HTLC: {
        unsigned char pre[32];
        memset(pre, u8(in), 32);
        m->json = wire_build_update_fulfill_htlc(id, pre);
        break;
    }
    case MSG_UPDATE_FAIL_HTLC:
        m->json = (sel & 0x40) ? wire_build_update_fail_htlc_uncommitted(id, "fuzz")
                               : wire_build_update_fail_htlc(id, "fuzz");
        break;
    case MSG_LSP_REVOKE_AND_ACK:
    case MSG_REVOKE_AND_ACK: {
        unsigned char secret[32];
        secp256k1_pubkey next;
        int honest = (sel & 0x40) && signer && signer->commitment_number > 0 &&
                     channel_get_per_commitment_secret(signer, signer->commitment_number - 1, secret) &&
                     channel_get_per_commitment_point(signer, signer->commitment_number + 1, &next);
        if (!honest) {
            take(in, secret, 32);
            unsigned char nsec[32];
            fill_secret(nsec, u8(in));
            if (!secp256k1_ec_pubkey_create(g_ctx, &next, nsec)) return 0;
        }
        m->json = wire_build_revoke_and_ack(0, secret, g_ctx, &next);
        break;
    }
    case MSG_FUNDING_REORG:
        m->json = cJSON_CreateObject();
        if (m->json) {
            cJSON_AddNumberToObject(m->json, "frozen", u8(in) & 1);
            cJSON_AddStringToObject(m->json, "funding_txid", "00");
        }
        break;
    case MSG_REGISTER_INVOICE: {
        unsigned char pre[32];
        memset(pre, u8(in), 32);
        sha256(pre, 32, h32);
        if (sel & 0x40) h32[0] ^= 1;
        m->json = wire_build_register_invoice(h32, (uint64_t)u16(in) * 1000, u8(in) % 3);
        break;
    }
    default:
        memset(p33, 0, sizeof(p33));
        m->json = cJSON_CreateObject();
        break;
    }
    return m->json != NULL;
}

/* ---- member side ---- */
static void run_client(in_t *in) {
    channel_t lsp_ch, cl_ch;
    memset(&lsp_ch, 0, sizeof(lsp_ch));
    memset(&cl_ch, 0, sizeof(cl_ch));
    if (!channel_pair(&lsp_ch, &cl_ch, 0, 100000, 60000, 39983)) return;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) goto out_ch;
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    shutdown(sv[1], SHUT_WR);
    check_conserved(&cl_ch, "member");

    for (int steps = 0; in->n > 0 && steps < 64; steps++) {
        uint8_t op = u8(in);
        if (op % 8 == 6) {                       /* the member offers an HTLC */
            unsigned char h[32];
            memset(h, u8(in), 32);
            client_send_payment(sv[0], &cl_ch, u16(in), h, 100 + u16(in), u8(in) % 4);
        } else if (op % 8 == 7) {                /* the member fulfils one */
            unsigned char pre[32];
            memset(pre, u8(in), 32);
            client_fulfill_payment(sv[0], &cl_ch, u8(in) % 8, pre);
        } else {
            wire_msg_t m;
            if (!build_msg(in, client_types, sizeof(client_types), &lsp_ch, &m)) {
                if (m.json) cJSON_Delete(m.json);
                continue;
            }
            switch (m.msg_type) {
            case MSG_UPDATE_ADD_HTLC:
                client_handle_add_htlc(&cl_ch, &m);
                break;
            case MSG_COMMITMENT_SIGNED:
                client_handle_commitment_signed(sv[0], &cl_ch, g_ctx, &m);
                break;
            case MSG_UPDATE_FULFILL_HTLC: {   /* as the member daemon does */
                uint64_t hid;
                unsigned char pre[32];
                if (wire_parse_update_fulfill_htlc(m.json, &hid, pre))
                    channel_fulfill_htlc(&cl_ch, hid, pre);
                break;
            }
            case MSG_UPDATE_FAIL_HTLC:
                client_handle_fail_htlc(&cl_ch, &m, NULL, NULL);
                break;
            case MSG_LSP_REVOKE_AND_ACK:
                client_handle_lsp_revoke_and_ack(&cl_ch, g_ctx, &m);
                break;
            default:
                client_handle_async_msg(&m);
                break;
            }
            cJSON_Delete(m.json);
        }
        drain(sv[1]);
        check_conserved(&cl_ch, "member");
    }
    close(sv[0]);
    close(sv[1]);
out_ch:
    channel_cleanup(&lsp_ch);
    channel_cleanup(&cl_ch);
}

/* ---- LSP side: two members, the LSP's per-client handler ---- */
#define FUZZ_MEMBERS 2
static void run_lsp(in_t *in) {
    lsp_channel_mgr_t mgr;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    channel_t cl_ch[FUZZ_MEMBERS];
    int fds[FUZZ_MEMBERS], peers[FUZZ_MEMBERS];
    size_t made = 0;
    memset(&mgr, 0, sizeof(mgr));
    memset(cl_ch, 0, sizeof(cl_ch));
    mgr.entries = calloc(FUZZ_MEMBERS, sizeof(lsp_channel_entry_t));
    mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    if (!lsp || !mgr.entries || !mgr.htlc_origins) goto out;
    mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    mgr.ctx = g_ctx;
    mgr.bridge_fd = -1;
    mgr.entries_cap = FUZZ_MEMBERS;
    lsp->client_fds = fds;
    for (; made < FUZZ_MEMBERS; made++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        fds[made] = sv[0];
        peers[made] = sv[1];
        fcntl(sv[1], F_SETFL, O_NONBLOCK);
        shutdown(sv[1], SHUT_WR);
        if (!channel_pair(&mgr.entries[made].channel, &cl_ch[made], (unsigned char)(made + 1),
                          100000, 60000, 39983)) {
            close(sv[0]);
            close(sv[1]);
            break;
        }
        mgr.entries[made].channel_id = (uint32_t)made;
        mgr.entries[made].ready = 1;
    }
    if (made < FUZZ_MEMBERS) goto out;
    mgr.n_channels = FUZZ_MEMBERS;
    lsp->n_clients = FUZZ_MEMBERS;

    for (int steps = 0; in->n > 0 && steps < 64; steps++) {
        size_t c = u8(in) % FUZZ_MEMBERS;
        wire_msg_t m;
        if (!build_msg(in, lsp_types, sizeof(lsp_types), &cl_ch[c], &m)) {
            if (m.json) cJSON_Delete(m.json);
            continue;
        }
        lsp_channels_handle_msg(&mgr, lsp, c, &m);
        cJSON_Delete(m.json);
        for (size_t i = 0; i < FUZZ_MEMBERS; i++) {
            drain(peers[i]);
            check_conserved(&mgr.entries[i].channel, "LSP");
        }
    }
out:
    for (size_t i = 0; i < made && i < FUZZ_MEMBERS; i++) {
        close(fds[i]);
        close(peers[i]);
        channel_cleanup(&mgr.entries[i].channel);
        channel_cleanup(&cl_ch[i]);
    }
    free(mgr.entries);
    free(mgr.htlc_origins);
    free(lsp);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);   /* as the daemons do */
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 4096) return 0;
    in_t in = { data + 1, size - 1 };
    if (data[0] & 1)
        run_lsp(&in);
    else
        run_client(&in);
    return 0;
}
