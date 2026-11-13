/* One channel's engine on one connection: see
   include/superscalar/chan_update_session.h. */

#include "superscalar/chan_update_session.h"
#include "superscalar/chan_update_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

int cu_session_is_msg(uint8_t type) {
    return (type >= MSG_CU_OFFER && type <= MSG_CU_ERROR) || type == MSG_CU_OPEN;
}

static int keep_other(cu_session_t *s, wire_msg_t *m) {
    if (s->n_other >= CU_SESSION_OTHER_CAP) {
        cJSON_Delete(m->json);
        return 0;
    }
    s->other[s->n_other++] = *m;
    return 1;
}

int cu_session_take_other(cu_session_t *s, wire_msg_t *out) {
    if (!s || !out || s->n_other == 0) return 0;
    *out = s->other[0];
    memmove(&s->other[0], &s->other[1], (s->n_other - 1) * sizeof(wire_msg_t));
    s->n_other--;
    return 1;
}

static int send_json(cu_session_t *s, uint8_t type, cJSON *j) {
    if (!j) return 0;
    int ok = wire_send(s->fd, type, j);
    cJSON_Delete(j);
    return ok;
}

/* Everything the engine produced, and a nonce top-up when one is due
   (sent first: the peer needs it before the signatures that use it). */
static int flush(cu_session_t *s) {
    uint32_t first;
    unsigned char pub[CU_NONCE_BATCH][66];
    size_t np = 0;
    int ok = 1;
    if (!cu_chops_topup(&s->ops, &first, pub, &np)) ok = 0;
    if (ok && np) ok = send_json(s, MSG_CU_NONCES, cu_wire_nonces(s->cfg.channel_id, first, pub, np));
    size_t k = 0;
    while (ok && s->c && k < s->c->n_out) {
        uint8_t type;
        cJSON *j = NULL;
        size_t used = cu_wire_encode(s->cfg.side, &s->c->out[k], s->c->n_out - k, &type, &j);
        if (!used) { ok = 0; break; }
        ok = send_json(s, type, j);
        k += used;
    }
    if (s->c) s->c->n_out = 0;
    return ok;
}

int cu_session_handle(cu_session_t *s, uint8_t type, const cJSON *json) {
    if (!s || !json) return CU_ERR_ARG;
    int rc = CU_OK;
    if (type == MSG_CU_NONCES) {
        uint32_t ch, first;
        unsigned char pub[CU_NONCE_BATCH][66];
        size_t np;
        if (!cu_wire_parse_nonces(json, &ch, &first, pub, CU_NONCE_BATCH, &np)
            || ch != s->cfg.channel_id
            || !cu_chops_peer_nonces(&s->ops, first, (const unsigned char (*)[66])pub, np))
            rc = CU_ERR_PROTOCOL;
    } else {
        cu_msg_t m[CU_MAX_UPDATES + 1];
        size_t nm = 0;
        if (!s->c || !cu_wire_decode(type, json, m, CU_MAX_UPDATES + 1, &nm)) rc = CU_ERR_PROTOCOL;
        for (size_t i = 0; rc == CU_OK && i < nm; i++) rc = cu_on_message(s->c, &m[i]);
    }
    if (!flush(s) && rc == CU_OK) rc = CU_ERR_PROTOCOL;
    if (rc != CU_OK) s->last_rc = rc;
    return rc;
}

/* The next engine message; others are kept for the caller. */
static int recv_engine(cu_session_t *s, wire_msg_t *m, int timeout_sec) {
    for (;;) {
        if (!wire_recv_timeout(s->fd, m, timeout_sec)) return 0;
        if (cu_session_is_msg(m->msg_type)) return 1;
        if (!keep_other(s, m)) return 0;
    }
}

/* ---- commitment 0 ---- */

static cJSON *open_points(uint32_t ch, const secp256k1_context *ctx,
                          const secp256k1_pubkey *p0, const secp256k1_pubkey *p1) {
    unsigned char b[33];
    size_t l = 33;
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", ch);
    cJSON_AddStringToObject(j, "stage", "points");
    secp256k1_ec_pubkey_serialize(ctx, b, &l, p0, SECP256K1_EC_COMPRESSED);
    wire_json_add_hex(j, "p0", b, 33);
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, b, &l, p1, SECP256K1_EC_COMPRESSED);
    wire_json_add_hex(j, "p1", b, 33);
    return j;
}

static cJSON *open_sig(uint32_t ch, const unsigned char psig[32], uint32_t idx) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", ch);
    cJSON_AddStringToObject(j, "stage", "sig");
    wire_json_add_hex(j, "psig", psig, 32);
    cJSON_AddNumberToObject(j, "nonce_index", idx);
    return j;
}

static int stage_is(const cJSON *j, const char *stage) {
    const cJSON *it = cJSON_GetObjectItem(j, "stage");
    return it && cJSON_IsString(it) && strcmp(it->valuestring, stage) == 0;
}

static int get_point(const secp256k1_context *ctx, const cJSON *j, const char *k, secp256k1_pubkey *p) {
    const cJSON *it = cJSON_GetObjectItem(j, k);
    unsigned char b[33];
    if (!it || !cJSON_IsString(it) || strlen(it->valuestring) != 66) return 0;
    if (hex_decode(it->valuestring, b, 33) != 33) return 0;
    return secp256k1_ec_pubkey_parse(ctx, p, b, 33);
}

static int get_sig(const cJSON *j, unsigned char psig[32], uint32_t *idx) {
    const cJSON *p = cJSON_GetObjectItem(j, "psig"), *i = cJSON_GetObjectItem(j, "nonce_index");
    if (!p || !cJSON_IsString(p) || strlen(p->valuestring) != 64) return 0;
    if (!i || !cJSON_IsNumber(i) || i->valuedouble < 0 || i->valuedouble > 4294967295.0) return 0;
    if (hex_decode(p->valuestring, psig, 32) != 32) return 0;
    *idx = (uint32_t)i->valuedouble;
    return 1;
}

static void session_init(cu_session_t *s, int fd, persist_t *db, const cu_config_t *cfg,
                         channel_t *ch, secp256k1_context *ctx) {
    memset(s, 0, sizeof(*s));
    s->fd = fd;
    s->db = db;
    s->cfg = *cfg;
    s->ch = ch;
    s->ctx = ctx;
    cu_chops_init(&s->ops, ch, cfg->side, cfg->channel_id, NULL);
}

static int load_engine(cu_session_t *s, uint32_t tip) {
    if (!s->c) s->c = calloc(1, sizeof(cu_chan_t));
    if (!s->c) return 0;
    if (cu_load(s->c, s->db, &s->cfg, &CU_CHANNEL_OPS, &s->ops, s->ctx) != CU_OK) return 0;
    cu_on_block(s->c, tip);
    cu_clear_outputs(s->c);
    return 1;
}

int cu_session_open(cu_session_t *s, int fd, persist_t *db, const cu_config_t *cfg,
                    channel_t *ch, secp256k1_context *ctx, const cu_state_t *initial,
                    uint32_t tip, int timeout_sec) {
    if (!s || !db || !cfg || !ch || !ctx || !initial) return 0;
    session_init(s, fd, db, cfg, ch, ctx);
    unsigned char sec[2][32], pub[CU_NONCE_BATCH][66], psig[32], peer_psig[32], signed_txid[32], sig[64];
    secp256k1_pubkey pt[2], peer[2];
    size_t np;
    uint32_t idx, peer_idx;
    int have_nonces = 0, have_points = 0, ok = 1;
    for (int k = 0; ok && k < 2; k++)
        ok = channel_read_random_bytes(sec[k], 32) && secp256k1_ec_pubkey_create(ctx, &pt[k], sec[k]);
    ok = ok && cu_chops_connect(&s->ops, pub, &np)
            && send_json(s, MSG_CU_NONCES, cu_wire_nonces(cfg->channel_id, 0, pub, np))
            && send_json(s, MSG_CU_OPEN, open_points(cfg->channel_id, ctx, &pt[0], &pt[1]));
    /* The peer's nonces and points, in either order. */
    while (ok && (!have_nonces || !have_points)) {
        wire_msg_t m;
        if (!recv_engine(s, &m, timeout_sec)) { ok = 0; break; }
        if (m.msg_type == MSG_CU_NONCES) {
            ok = cu_session_handle(s, m.msg_type, m.json) == CU_OK;
            have_nonces = 1;
        } else if (m.msg_type == MSG_CU_OPEN && stage_is(m.json, "points")) {
            ok = get_point(ctx, m.json, "p0", &peer[0]) && get_point(ctx, m.json, "p1", &peer[1]);
            have_points = 1;
        } else {
            ok = 0;
        }
        cJSON_Delete(m.json);
    }
    unsigned char *tx = malloc(CU_TX_MAX);
    size_t len = CU_TX_MAX;
    ok = ok && tx;
    if (ok && cfg->side == CU_HOST)
        ok = cu_open_sign(&s->ops, initial, &peer[0], psig, &idx, signed_txid)
          && send_json(s, MSG_CU_OPEN, open_sig(cfg->channel_id, psig, idx));
    if (ok) {
        wire_msg_t m;
        ok = recv_engine(s, &m, timeout_sec);
        if (ok) {
            ok = m.msg_type == MSG_CU_OPEN && stage_is(m.json, "sig") && get_sig(m.json, peer_psig, &peer_idx);
            cJSON_Delete(m.json);
        }
    }
    /* The member verifies its own commitment 0 before it signs the host's. */
    ok = ok && cu_open_verify(&s->ops, initial, sec[0], peer_psig, peer_idx, tx, &len, sig);
    if (ok && cfg->side == CU_MEMBER)
        ok = cu_open_sign(&s->ops, initial, &peer[0], psig, &idx, signed_txid)
          && send_json(s, MSG_CU_OPEN, open_sig(cfg->channel_id, psig, idx));
    ok = ok && cu_create(db, cfg, initial, sec[0], sec[1], &peer[0], &peer[1],
                         tx, len, sig, signed_txid) == CU_OK;
    free(tx);
    memset(sec, 0, sizeof(sec));
    return ok && load_engine(s, tip);
}

int cu_session_resume(cu_session_t *s, int fd, persist_t *db, const cu_config_t *cfg,
                      channel_t *ch, secp256k1_context *ctx, uint32_t tip) {
    if (!s || !db || !cfg || !ch || !ctx) return 0;
    cu_chan_t *keep = s->c;
    wire_msg_t other[CU_SESSION_OTHER_CAP];
    size_t n_other = s->n_other;
    memcpy(other, s->other, n_other * sizeof(wire_msg_t));
    session_init(s, fd, db, cfg, ch, ctx);
    s->c = keep;
    memcpy(s->other, other, n_other * sizeof(wire_msg_t));
    s->n_other = n_other;
    if (!load_engine(s, tip)) return 0;
    unsigned char pub[CU_NONCE_BATCH][66];
    size_t np;
    if (!cu_chops_connect(&s->ops, pub, &np)
        || !send_json(s, MSG_CU_NONCES, cu_wire_nonces(cfg->channel_id, 0, pub, np))
        || cu_reestablish_msg(s->c, &s->c->out[0]) != CU_OK)
        return 0;
    s->c->n_out = 1;
    return flush(s);
}

int cu_session_offer(cu_session_t *s, const cu_update_t *u, size_t n) {
    if (!s || !s->c) return CU_ERR_ARG;
    int rc = cu_offer(s->c, u, n);
    if (!flush(s) && rc == CU_OK) rc = CU_ERR_PROTOCOL;
    return rc;
}

int cu_session_round(cu_session_t *s, const cu_update_t *own, size_t n) {
    if (!s || !s->c) return CU_ERR_ARG;
    cu_update_t all[CU_MAX_UPDATES];
    size_t nr = 0;
    const cu_update_t *r = cu_requests(s->c, &nr);
    if (nr + n == 0 || nr + n > CU_MAX_UPDATES) return CU_ERR_ARG;
    memcpy(all, r, nr * sizeof(cu_update_t));
    for (size_t i = 0; i < n; i++) {
        all[nr + i] = own[i];
        all[nr + i].sender = CU_HOST;
    }
    int rc = cu_propose(s->c, all, nr + n);
    if (!flush(s) && rc == CU_OK) rc = CU_ERR_PROTOCOL;
    return rc;
}

static int holds(const cu_session_t *s, int cond, uint64_t min_held) {
    const cu_chan_t *c = s->c;
    if (c->rec.held < min_held) return 0;
    if (cond & CU_WAIT_REST) {
        if (c->rec.phase != CU_PHASE_IDLE) return 0;
        if (c->cfg.side == CU_MEMBER && c->n_offered) return 0;
    }
    if (cond & CU_WAIT_REQUEST) {
        size_t nr = 0;
        cu_requests(c, &nr);
        if (nr == 0) return 0;
    }
    return 1;
}

int cu_session_wait(cu_session_t *s, int cond, uint64_t min_held, int timeout_sec) {
    if (!s || !s->c) return CU_ERR_ARG;
    while (!holds(s, cond, min_held)) {
        if (s->c->rec.halted) return CU_ERR_HALTED;
        wire_msg_t m;
        if (!recv_engine(s, &m, timeout_sec)) return CU_ERR_PROTOCOL;
        int rc = cu_session_handle(s, m.msg_type, m.json);
        cJSON_Delete(m.json);
        if (rc != CU_OK) return rc;
    }
    return CU_OK;
}

void cu_session_disconnect(cu_session_t *s) {
    if (!s || !s->c) return;
    cu_on_disconnect(s->c);
    s->fd = -1;
}

void cu_session_free(cu_session_t *s) {
    if (!s) return;
    for (size_t i = 0; i < s->n_other; i++) cJSON_Delete(s->other[i].json);
    s->n_other = 0;
    free(s->c);
    s->c = NULL;
}
