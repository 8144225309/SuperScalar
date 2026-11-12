/*
 * client_dist.c -- the client publishes its factory's distribution
 * transaction once it is due and the factory is still open.
 */

#include "superscalar/client_dist.h"
#include "superscalar/client.h"
#include "superscalar/factory.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

#define DIST_MAX_OUTPUTS 4096
#define DIST_MAX_SPK     10000

static void set_err(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

static int rd_varint(const unsigned char *b, size_t len, size_t *pos, uint64_t *v) {
    if (*pos >= len) return 0;
    unsigned char c = b[(*pos)++];
    size_t n = c < 0xfd ? 0 : c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
    if (n == 0) { *v = c; return 1; }
    if (len - *pos < n) return 0;
    uint64_t r = 0;
    for (size_t i = 0; i < n; i++) r |= (uint64_t)b[*pos + i] << (8 * i);
    *pos += n;
    *v = r;
    return 1;
}

static uint32_t rd_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void display_hex(const unsigned char *internal32, char *out65) {
    unsigned char d[32];
    for (int i = 0; i < 32; i++) d[i] = internal32[31 - i];
    hex_encode(d, 32, out65);
    out65[64] = '\0';
}

int client_dist_verify(const secp256k1_context *ctx,
                       const unsigned char *tx, size_t tx_len,
                       const unsigned char *funding_txid32, uint32_t funding_vout,
                       uint64_t funding_amount,
                       const unsigned char *funding_spk, size_t funding_spk_len,
                       uint32_t expected_locktime,
                       const secp256k1_pubkey *member_pubkey,
                       uint64_t member_min_sats,
                       client_dist_tx_t *out, char *err, size_t errlen) {
    if (out) memset(out, 0, sizeof(*out));
    if (!ctx || !tx || !funding_txid32 || !funding_spk || !out) {
        set_err(err, errlen, "missing input");
        return 0;
    }
    /* version(4) marker flag | 1 input | outputs | witness | locktime(4) */
    if (tx_len < 4 + 2 + 1 + 41 + 1 + 4 || tx[4] != 0x00 || tx[5] != 0x01) {
        set_err(err, errlen, "not a signed segwit transaction");
        return 0;
    }
    size_t pos = 6;
    uint64_t n_in = 0, script_len = 0, n_out = 0;
    if (!rd_varint(tx, tx_len, &pos, &n_in) || n_in != 1) {
        set_err(err, errlen, "must have exactly one input");
        return 0;
    }
    if (tx_len - pos < 36) { set_err(err, errlen, "truncated input"); return 0; }
    const unsigned char *prevout = tx + pos;
    pos += 36;
    if (!rd_varint(tx, tx_len, &pos, &script_len) || script_len != 0 ||
        tx_len - pos < 4) {
        set_err(err, errlen, "input has a scriptSig or is truncated");
        return 0;
    }
    uint32_t sequence = rd_u32(tx + pos);
    pos += 4;
    if (!rd_varint(tx, tx_len, &pos, &n_out) || n_out == 0 ||
        n_out > DIST_MAX_OUTPUTS) {
        set_err(err, errlen, "bad output count");
        return 0;
    }
    for (uint64_t i = 0; i < n_out; i++) {
        uint64_t spk_len = 0;
        if (tx_len - pos < 8) { set_err(err, errlen, "truncated output"); return 0; }
        pos += 8;
        if (!rd_varint(tx, tx_len, &pos, &spk_len) || spk_len > DIST_MAX_SPK ||
            tx_len - pos < spk_len) {
            set_err(err, errlen, "truncated output script");
            return 0;
        }
        pos += (size_t)spk_len;
    }
    size_t outputs_end = pos;
    uint64_t n_items = 0, item_len = 0;
    if (!rd_varint(tx, tx_len, &pos, &n_items) || n_items != 1 ||
        !rd_varint(tx, tx_len, &pos, &item_len) || item_len != 64 ||
        tx_len - pos < 64) {
        set_err(err, errlen, "witness is not one 64-byte key-path signature");
        return 0;
    }
    const unsigned char *sig = tx + pos;
    pos += 64;
    if (tx_len - pos != 4) {
        set_err(err, errlen, "trailing or missing bytes after the witness");
        return 0;
    }
    uint32_t locktime = rd_u32(tx + pos);

    if (memcmp(prevout, funding_txid32, 32) != 0 ||
        rd_u32(prevout + 32) != funding_vout) {
        set_err(err, errlen, "does not spend the factory funding output");
        return 0;
    }
    if (locktime == 0 || locktime >= 500000000u) {
        set_err(err, errlen, "nLockTime is not a block height");
        return 0;
    }
    if (expected_locktime != 0 && locktime != expected_locktime) {
        char m[96];
        snprintf(m, sizeof(m), "nLockTime %u is not the factory CLTV timeout %u",
                 (unsigned)locktime, (unsigned)expected_locktime);
        set_err(err, errlen, m);
        return 0;
    }
    if (member_pubkey &&
        !client_distribution_pays_member(ctx, tx, tx_len, member_pubkey,
                                         member_min_sats)) {
        char m[128];
        snprintf(m, sizeof(m), "pays this member less than its channel "
                 "capacity of %llu sat", (unsigned long long)member_min_sats);
        set_err(err, errlen, m);
        return 0;
    }
    if (sequence == 0xFFFFFFFFu) {
        set_err(err, errlen, "input nSequence disables its nLockTime");
        return 0;
    }
    if (funding_spk_len != 34 || funding_spk[0] != 0x51 || funding_spk[1] != 0x20) {
        set_err(err, errlen, "funding script is not P2TR");
        return 0;
    }

    /* Non-witness serialization: what the txid and the sighash commit to. */
    size_t body = outputs_end - 6;
    size_t ulen = 4 + body + 4;
    unsigned char *utx = malloc(ulen);
    if (!utx) { set_err(err, errlen, "out of memory"); return 0; }
    memcpy(utx, tx, 4);
    memcpy(utx + 4, tx + 6, body);
    memcpy(utx + 4 + body, tx + tx_len - 4, 4);

    unsigned char sighash[32];
    secp256k1_xonly_pubkey key;
    int ok = compute_taproot_sighash(sighash, utx, ulen, 0, funding_spk,
                                     funding_spk_len, funding_amount, sequence) &&
             secp256k1_xonly_pubkey_parse(ctx, &key, funding_spk + 2) &&
             secp256k1_schnorrsig_verify(ctx, sig, sighash, 32, &key);
    if (!ok) {
        free(utx);
        set_err(err, errlen, "signature does not verify against the funding key");
        return 0;
    }
    unsigned char txid[32];
    sha256_double(utx, ulen, txid);
    free(utx);

    out->tx = malloc(tx_len);
    if (!out->tx) { set_err(err, errlen, "out of memory"); return 0; }
    memcpy(out->tx, tx, tx_len);
    out->tx_len = tx_len;
    display_hex(txid, out->txid_hex);
    display_hex(funding_txid32, out->funding_txid_hex);
    out->funding_vout = funding_vout;
    out->locktime = locktime;
    out->n_outputs = (size_t)n_out;
    return 1;
}

void client_dist_free(client_dist_tx_t *d) {
    if (!d) return;
    free(d->tx);
    memset(d, 0, sizeof(*d));
}

/* The stored TX bytes, heap-allocated.  1 = found, 0 = none, -1 = error. */
static int load_stored(persist_t *db, uint32_t factory_id,
                       unsigned char **tx_out, size_t *len_out) {
    size_t len = 0;
    *tx_out = NULL;
    *len_out = 0;
    if (!persist_load_distribution_tx(db, factory_id, NULL, &len, 0)) return 0;
    if (len == 0) return -1;
    unsigned char *tx = malloc(len);
    size_t got = 0;
    if (!tx || !persist_load_distribution_tx(db, factory_id, tx, &got, len) ||
        got != len) {
        free(tx);
        return -1;
    }
    *tx_out = tx;
    *len_out = len;
    return 1;
}

int client_dist_load(persist_t *db, secp256k1_context *ctx, uint32_t factory_id,
                     client_dist_tx_t *out, char *err, size_t errlen) {
    memset(out, 0, sizeof(*out));
    if (err && errlen) err[0] = '\0';
    unsigned char *tx = NULL;
    size_t len = 0;
    int r = load_stored(db, factory_id, &tx, &len);
    if (r == 0) return 0;
    if (r < 0) { set_err(err, errlen, "stored distribution TX unreadable"); return -1; }

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f || !persist_load_factory(db, factory_id, f, ctx)) {
        free(f);
        free(tx);
        set_err(err, errlen, "factory record unreadable");
        return -1;
    }
    /* This member: the client whose channel row the DB holds; it must be
       paid at least its channel capacity. */
    const secp256k1_pubkey *member = NULL;
    uint64_t member_min = 0;
    for (size_t slot = 0; slot + 1 < f->n_participants; slot++) {
        uint64_t la = 0, ra = 0, cn = 0;
        if (persist_load_channel_state(db, (uint32_t)slot, &la, &ra, &cn)) {
            member = &f->pubkeys[slot + 1];
            member_min = client_member_channel_capacity(f, (uint32_t)slot + 1);
            break;
        }
    }
    int ok = 0;
    if (!member)
        set_err(err, errlen, "no channel record for this member");
    else if (member_min == 0)
        set_err(err, errlen, "this member has no channel output in the factory");
    else
        ok = client_dist_verify(ctx, tx, len, f->funding_txid, f->funding_vout,
                                f->funding_amount_sats, f->funding_spk,
                                f->funding_spk_len, f->cltv_timeout, member,
                                member_min, out, err, errlen);
    factory_free(f);
    free(f);
    free(tx);
    return ok ? 1 : -1;
}

int client_dist_settles(client_dist_status_t s) {
    return s == CLIENT_DIST_BROADCAST || s == CLIENT_DIST_IN_MEMPOOL ||
           s == CLIENT_DIST_CONFIRMED || s == CLIENT_DIST_REFUSED;
}

int client_dist_may_exit(int confs, int close_confs, int has_jit,
                         size_t n_watched) {
    return close_confs > 0 && confs >= close_confs && !has_jit && n_watched == 0;
}

client_dist_status_t client_dist_step(chain_backend_t *chain,
                                      const client_dist_tx_t *d,
                                      client_dist_send_fn send, int *tip_out,
                                      int *confs_out) {
    if (tip_out) *tip_out = -1;
    if (confs_out) *confs_out = -1;
    if (!d || !d->tx) return CLIENT_DIST_NONE;
    if (!chain || !chain->get_block_height) return CLIENT_DIST_NO_CHAIN;
    int tip = chain->get_block_height(chain);
    if (tip_out) *tip_out = tip;
    if (tip < 0) return CLIENT_DIST_NO_CHAIN;

    int confs = chain->get_confirmations
                ? chain->get_confirmations(chain, d->txid_hex) : -1;
    if (confs_out) *confs_out = confs >= 0 ? confs : -1;
    if (confs >= 1) return CLIENT_DIST_CONFIRMED;
    if (confs == 0) return CLIENT_DIST_IN_MEMPOOL;

    /* Not valid before its nLockTime: a block at height h takes it once
       nLockTime < h, so the mempool takes it from tip == nLockTime on. */
    if ((uint32_t)tip < d->locktime) return CLIENT_DIST_NOT_YET;

    int unspent = chain->is_outpoint_unspent
                  ? chain->is_outpoint_unspent(chain, d->funding_txid_hex,
                                               d->funding_vout)
                  : -1;
    if (unspent == 0) {
        /* Without a transaction index a confirmed distribution TX is only
           visible through its outputs. */
        for (size_t i = 0; chain->is_outpoint_unspent && i < d->n_outputs; i++)
            if (chain->is_outpoint_unspent(chain, d->txid_hex, (uint32_t)i) == 1)
                return CLIENT_DIST_CONFIRMED;
        return CLIENT_DIST_FUNDING_SPENT;
    }

    /* unspent == 1: due and the funding output is there.  unspent == -1:
       the backend cannot say; the TX is still sent, but nothing is settled
       by it (the funding output may already be spent by the tree). */
    char *hex = malloc(d->tx_len * 2 + 1);
    if (!hex) return unspent == 1 ? CLIENT_DIST_REFUSED : CLIENT_DIST_FUNDING_UNKNOWN;
    hex_encode(d->tx, d->tx_len, hex);
    hex[d->tx_len * 2] = '\0';
    char txid[65] = {0};
    int sent = send ? send(chain, hex, txid)
                    : (chain->send_raw_tx && chain->send_raw_tx(chain, hex, txid));
    free(hex);
    if (unspent != 1) return CLIENT_DIST_FUNDING_UNKNOWN;
    return sent ? CLIENT_DIST_BROADCAST : CLIENT_DIST_REFUSED;
}

const char *client_dist_status_str(client_dist_status_t s) {
    switch (s) {
    case CLIENT_DIST_NONE:          return "none";
    case CLIENT_DIST_INVALID:       return "invalid";
    case CLIENT_DIST_NO_CHAIN:      return "no-chain";
    case CLIENT_DIST_NOT_YET:       return "not-yet-valid";
    case CLIENT_DIST_BROADCAST:     return "broadcast";
    case CLIENT_DIST_IN_MEMPOOL:    return "in-mempool";
    case CLIENT_DIST_REFUSED:       return "refused";
    case CLIENT_DIST_CONFIRMED:     return "confirmed";
    case CLIENT_DIST_FUNDING_SPENT: return "funding-spent";
    case CLIENT_DIST_FUNDING_UNKNOWN: return "funding-unknown";
    }
    return "unknown";
}

/* What the status means, for a log line; tip is the height it was taken at. */
static void report(FILE *out, const char *prefix, client_dist_status_t s,
                   const client_dist_tx_t *d, int tip) {
    switch (s) {
    case CLIENT_DIST_NOT_YET:
        fprintf(out, "%sdistribution TX %s is valid from block %u (tip %d, %d "
                "blocks to go)\n", prefix, d->txid_hex, d->locktime, tip,
                (int)d->locktime - tip);
        break;
    case CLIENT_DIST_BROADCAST:
        fprintf(out, "%sblock %d has reached the distribution TX nLockTime %u and "
                "the factory funding output %s:%u is unspent: broadcast "
                "distribution TX %s\n", prefix, tip, d->locktime,
                d->funding_txid_hex, d->funding_vout, d->txid_hex);
        break;
    case CLIENT_DIST_IN_MEMPOOL:
        fprintf(out, "%sdistribution TX %s is in the mempool, waiting for it to "
                "confirm\n", prefix, d->txid_hex);
        break;
    case CLIENT_DIST_REFUSED:
        fprintf(out, "%sdistribution TX %s is due (block %d, nLockTime %u) but the "
                "node did not accept it (reason above); it is sent again until it "
                "confirms\n", prefix, d->txid_hex, tip, d->locktime);
        break;
    case CLIENT_DIST_CONFIRMED:
        fprintf(out, "%sdistribution TX %s is confirmed: the factory is settled on "
                "chain and this client's share is paid to its key\n", prefix,
                d->txid_hex);
        break;
    case CLIENT_DIST_FUNDING_SPENT:
        fprintf(out, "%sthe factory funding output %s:%u is spent by another "
                "transaction; distribution TX %s can no longer confirm\n", prefix,
                d->funding_txid_hex, d->funding_vout, d->txid_hex);
        break;
    case CLIENT_DIST_FUNDING_UNKNOWN:
        fprintf(out, "%sdistribution TX %s is due (block %d, nLockTime %u) and was "
                "sent, but this chain backend cannot tell whether the funding "
                "output %s:%u is still unspent; it does not count as the exit\n",
                prefix, d->txid_hex, tip, d->locktime, d->funding_txid_hex,
                d->funding_vout);
        break;
    case CLIENT_DIST_NO_CHAIN:
        fprintf(out, "%schain tip unknown; distribution TX %s not checked\n",
                prefix, d->txid_hex);
        break;
    default:
        break;
    }
    fflush(out);
}

client_dist_status_t client_dist_watch(client_dist_watch_t *w, persist_t *db,
                                       secp256k1_context *ctx,
                                       chain_backend_t *chain,
                                       client_dist_send_fn send,
                                       unsigned interval_s, FILE *out) {
    if (!w || !db) return CLIENT_DIST_NONE;
    time_t now = time(NULL);
    if (w->last_check != 0 && now - w->last_check < (time_t)interval_s)
        return w->last;
    w->last_check = now;

    /* Re-verify only when the stored TX changed (a rotation replaces it). */
    unsigned char *tx = NULL;
    size_t len = 0;
    int r = load_stored(db, 0, &tx, &len);
    int same = w->checked && r == w->raw_state && len == w->raw_len &&
               (len == 0 || memcmp(tx, w->raw, len) == 0);
    if (same) {
        free(tx);
    } else {
        char err[160] = "stored distribution TX unreadable";
        free(w->raw);
        w->raw = tx;
        w->raw_len = len;
        w->raw_state = r;
        w->checked = 1;
        client_dist_free(&w->d);
        w->loaded = r <= 0 ? r : client_dist_load(db, ctx, 0, &w->d, err, sizeof(err));
        w->reported = 0;
        if (w->loaded == 1)
            fprintf(out, "Client: distribution TX %s stored and verified (spends "
                    "%s:%u, nLockTime %u); it is broadcast from block %u on if "
                    "the factory is still open then\n", w->d.txid_hex,
                    w->d.funding_txid_hex, w->d.funding_vout, w->d.locktime,
                    w->d.locktime);
        else if (w->loaded < 0)
            fprintf(out, "Client: WARNING: stored distribution TX not usable (%s); "
                    "it will not be broadcast\n", err);
        fflush(out);
    }
    if (w->loaded != 1) {
        w->last = w->loaded == 0 ? CLIENT_DIST_NONE : CLIENT_DIST_INVALID;
        return w->last;
    }

    int tip = -1;
    client_dist_status_t s = client_dist_step(chain, &w->d, send, &tip, &w->confs);
    if (!w->reported || s != w->last || s == CLIENT_DIST_BROADCAST) {
        if (s != CLIENT_DIST_NOT_YET || w->reported)
            report(out, "Client: ", s, &w->d, tip);
        w->reported = 1;
    }
    w->last = s;
    return s;
}

void client_dist_watch_free(client_dist_watch_t *w) {
    if (!w) return;
    client_dist_free(&w->d);
    free(w->raw);
    memset(w, 0, sizeof(*w));
}

int client_dist_force_close(persist_t *db, chain_backend_t *chain,
                            client_dist_send_fn send, FILE *out,
                            client_dist_status_t *status_out) {
    if (status_out) *status_out = CLIENT_DIST_NONE;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return 0;
    client_dist_tx_t d;
    char err[160];
    int r = client_dist_load(db, ctx, 0, &d, err, sizeof(err));
    secp256k1_context_destroy(ctx);
    if (r == 0) {
        fprintf(out, "Force-close: no distribution TX in DB\n");
        return 0;
    }
    if (r < 0) {
        fprintf(out, "Force-close: stored distribution TX not usable (%s); "
                "not broadcasting it\n", err);
        return 0;
    }
    int tip = -1;
    client_dist_status_t s = client_dist_step(chain, &d, send, &tip, NULL);
    report(out, "Force-close: ", s, &d, tip);
    if (status_out) *status_out = s;
    int settles = client_dist_settles(s);
    if (settles)
        fprintf(out, "Force-close: the distribution TX is this factory's exit; "
                "NOT publishing the factory tree (it spends the funding output "
                "and the distribution TX could then never confirm)\n");
    else if (s == CLIENT_DIST_NOT_YET || s == CLIENT_DIST_FUNDING_UNKNOWN)
        fprintf(out, "Force-close: publishing the factory tree now; once it "
                "spends the funding output the distribution TX can never "
                "confirm\n");
    client_dist_free(&d);
    return settles;
}
