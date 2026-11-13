/* Wire form of the channel-update engine's messages: see
   include/superscalar/chan_update_wire.h. */

#include "superscalar/chan_update_wire.h"
#include "superscalar/wire.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

/* ---- fields ---- */

static void add_u64(cJSON *o, const char *k, uint64_t v) {
    char b[24];
    snprintf(b, sizeof(b), "%llu", (unsigned long long)v);
    cJSON_AddStringToObject(o, k, b);
}

static int get_u64(const cJSON *o, const char *k, uint64_t *v) {
    const cJSON *it = cJSON_GetObjectItem(o, k);
    if (!it || !cJSON_IsString(it) || !it->valuestring) return 0;
    const char *s = it->valuestring;
    size_t len = strlen(s);
    if (len == 0 || len > 20) return 0;
    for (size_t i = 0; i < len; i++) if (s[i] < '0' || s[i] > '9') return 0;
    if (len > 1 && s[0] == '0') return 0;
    errno = 0;
    unsigned long long x = strtoull(s, NULL, 10);
    if (errno) return 0;
    *v = (uint64_t)x;
    return 1;
}

static void add_u32(cJSON *o, const char *k, uint32_t v) {
    cJSON_AddNumberToObject(o, k, (double)v);
}

static int get_u32(const cJSON *o, const char *k, uint32_t *v) {
    const cJSON *it = cJSON_GetObjectItem(o, k);
    if (!it || !cJSON_IsNumber(it)) return 0;
    double d = it->valuedouble;
    if (d < 0 || d > 4294967295.0 || d != (double)(uint32_t)d) return 0;
    *v = (uint32_t)d;
    return 1;
}

static int get_i32(const cJSON *o, const char *k, int32_t *v) {
    const cJSON *it = cJSON_GetObjectItem(o, k);
    if (!it || !cJSON_IsNumber(it)) return 0;
    double d = it->valuedouble;
    if (d < -2147483648.0 || d > 2147483647.0 || d != (double)(int32_t)d) return 0;
    *v = (int32_t)d;
    return 1;
}

static int get_hex(const cJSON *o, const char *k, unsigned char *out, size_t len) {
    const cJSON *it = cJSON_GetObjectItem(o, k);
    if (!it || !cJSON_IsString(it) || !it->valuestring) return 0;
    if (strlen(it->valuestring) != 2 * len) return 0;
    return wire_json_get_hex(o, k, out, len) == (int)len;
}

static cJSON *update_json(const cu_update_t *u) {
    cJSON *j = cJSON_CreateObject();
    add_u32(j, "kind", u->kind);
    add_u32(j, "sender", u->sender);
    add_u64(j, "id", u->id);
    add_u64(j, "amount_msat", u->amount_msat);
    wire_json_add_hex(j, "payment_hash", u->payment_hash, 32);
    wire_json_add_hex(j, "preimage", u->preimage, 32);
    add_u32(j, "cltv_expiry", u->cltv_expiry);
    add_u32(j, "reason", u->reason);
    add_u64(j, "feerate_per_kvb", u->feerate_per_kvb);
    return j;
}

static int update_parse(const cJSON *j, cu_update_t *u) {
    uint32_t kind, sender;
    memset(u, 0, sizeof(*u));
    if (!cJSON_IsObject(j)) return 0;
    if (!get_u32(j, "kind", &kind) || kind < CU_UPD_ADD || kind > CU_UPD_FEE) return 0;
    if (!get_u32(j, "sender", &sender) || sender > CU_MEMBER) return 0;
    u->kind = (uint8_t)kind;
    u->sender = (uint8_t)sender;
    return get_u64(j, "id", &u->id)
        && get_u64(j, "amount_msat", &u->amount_msat)
        && get_hex(j, "payment_hash", u->payment_hash, 32)
        && get_hex(j, "preimage", u->preimage, 32)
        && get_u32(j, "cltv_expiry", &u->cltv_expiry)
        && get_u32(j, "reason", &u->reason)
        && get_u64(j, "feerate_per_kvb", &u->feerate_per_kvb);
}

static int is_update(uint8_t t) {
    return t == CU_MSG_ADD || t == CU_MSG_FULFILL || t == CU_MSG_FAIL || t == CU_MSG_FEE;
}

static uint8_t msg_of_kind(uint8_t kind) {
    return kind == CU_UPD_ADD ? CU_MSG_ADD : kind == CU_UPD_FULFILL ? CU_MSG_FULFILL
         : kind == CU_UPD_FAIL ? CU_MSG_FAIL : CU_MSG_FEE;
}

static void add_cs(cJSON *j, const cu_msg_t *m) {
    add_u64(j, "n", m->n);
    wire_json_add_hex(j, "psig", m->psig, 32);
    add_u32(j, "nonce_index", m->nonce_index);
    wire_json_add_hex(j, "digest", m->digest, 32);
}

static int parse_cs(const cJSON *j, cu_msg_t *m) {
    m->type = CU_MSG_COMMIT_SIG;
    return get_u64(j, "n", &m->n)
        && get_hex(j, "psig", m->psig, 32)
        && get_u32(j, "nonce_index", &m->nonce_index)
        && get_hex(j, "digest", m->digest, 32);
}

/* ---- encode ---- */

size_t cu_wire_encode(cu_side_t from, const cu_msg_t *m, size_t n, uint8_t *type, cJSON **json) {
    if (!m || n == 0 || !type || !json) return 0;
    cJSON *j = cJSON_CreateObject();
    if (!j) return 0;
    cJSON_AddNumberToObject(j, "channel_id", m[0].channel_id);
    size_t used = 1;
    if (is_update(m[0].type)) {
        size_t k = 0;
        while (k < n && k < CU_MAX_UPDATES && is_update(m[k].type)) k++;
        cJSON *arr = cJSON_AddArrayToObject(j, "updates");
        for (size_t i = 0; i < k; i++) cJSON_AddItemToArray(arr, update_json(&m[i].upd));
        if (from == CU_HOST) {
            /* The host's updates always open a round with its signature. */
            if (k >= n || m[k].type != CU_MSG_COMMIT_SIG) { cJSON_Delete(j); return 0; }
            add_cs(j, &m[k]);
            *type = MSG_CU_ROUND;
            used = k + 1;
        } else {
            *type = MSG_CU_OFFER;
            used = k;
        }
    } else {
        switch (m[0].type) {
        case CU_MSG_COMMIT_SIG:
            /* The host's resent signature without updates does not occur:
               a round always carries its updates. */
            if (from == CU_HOST) { cJSON_Delete(j); return 0; }
            add_cs(j, &m[0]);
            *type = MSG_CU_COMMIT_SIG;
            break;
        case CU_MSG_REVOKE:
            add_u64(j, "n_revoked", m[0].n);
            wire_json_add_hex(j, "secret", m[0].secret, 32);
            wire_json_add_hex(j, "next_point", m[0].next_point, 33);
            *type = MSG_CU_REVOKE;
            break;
        case CU_MSG_REESTABLISH:
            add_u64(j, "next_commitment_number", m[0].re.next_commitment_number);
            add_u64(j, "next_revocation_number", m[0].re.next_revocation_number);
            wire_json_add_hex(j, "last_remote_secret", m[0].re.last_remote_secret, 32);
            wire_json_add_hex(j, "my_current_point", m[0].re.my_current_point, 33);
            wire_json_add_hex(j, "sent_digest", m[0].re.sent_digest, 32);
            *type = MSG_CU_REESTABLISH;
            break;
        case CU_MSG_REFUSE:
            cJSON_AddItemToObject(j, "update", update_json(&m[0].upd));
            cJSON_AddNumberToObject(j, "code", m[0].code);
            *type = MSG_CU_REFUSE;
            break;
        case CU_MSG_ERROR:
            cJSON_AddNumberToObject(j, "code", m[0].code);
            *type = MSG_CU_ERROR;
            break;
        default:
            cJSON_Delete(j);
            return 0;
        }
    }
    *json = j;
    return used;
}

/* ---- decode ---- */

int cu_wire_decode(uint8_t type, const cJSON *json, cu_msg_t *out, size_t cap, size_t *n) {
    uint32_t ch;
    if (!json || !out || !n || cap == 0) return 0;
    *n = 0;
    if (!get_u32(json, "channel_id", &ch)) return 0;
    memset(out, 0, sizeof(*out));
    out[0].channel_id = ch;
    switch (type) {
    case MSG_CU_OFFER:
    case MSG_CU_ROUND: {
        const cJSON *arr = cJSON_GetObjectItem(json, "updates");
        if (!cJSON_IsArray(arr)) return 0;
        int k = cJSON_GetArraySize(arr);
        size_t need = (size_t)k + (type == MSG_CU_ROUND ? 1 : 0);
        if (k < 1 || k > CU_MAX_UPDATES || need > cap) return 0;
        for (int i = 0; i < k; i++) {
            memset(&out[i], 0, sizeof(out[i]));
            out[i].channel_id = ch;
            if (!update_parse(cJSON_GetArrayItem(arr, i), &out[i].upd)) return 0;
            out[i].type = msg_of_kind(out[i].upd.kind);
        }
        if (type == MSG_CU_ROUND) {
            memset(&out[k], 0, sizeof(out[k]));
            out[k].channel_id = ch;
            if (!parse_cs(json, &out[k])) return 0;
        }
        *n = need;
        return 1;
    }
    case MSG_CU_COMMIT_SIG:
        if (!parse_cs(json, &out[0])) return 0;
        break;
    case MSG_CU_REVOKE:
        out[0].type = CU_MSG_REVOKE;
        if (!get_u64(json, "n_revoked", &out[0].n) || !get_hex(json, "secret", out[0].secret, 32)
            || !get_hex(json, "next_point", out[0].next_point, 33))
            return 0;
        break;
    case MSG_CU_REESTABLISH:
        out[0].type = CU_MSG_REESTABLISH;
        if (!get_u64(json, "next_commitment_number", &out[0].re.next_commitment_number)
            || !get_u64(json, "next_revocation_number", &out[0].re.next_revocation_number)
            || !get_hex(json, "last_remote_secret", out[0].re.last_remote_secret, 32)
            || !get_hex(json, "my_current_point", out[0].re.my_current_point, 33)
            || !get_hex(json, "sent_digest", out[0].re.sent_digest, 32))
            return 0;
        break;
    case MSG_CU_REFUSE:
        out[0].type = CU_MSG_REFUSE;
        if (!update_parse(cJSON_GetObjectItem(json, "update"), &out[0].upd)
            || !get_i32(json, "code", &out[0].code))
            return 0;
        break;
    case MSG_CU_ERROR:
        out[0].type = CU_MSG_ERROR;
        if (!get_i32(json, "code", &out[0].code)) return 0;
        break;
    default:
        return 0;
    }
    *n = 1;
    return 1;
}

cJSON *cu_wire_nonces(uint32_t channel_id, uint32_t first, const unsigned char pub[][66], size_t n) {
    cJSON *j = cJSON_CreateObject();
    if (!j) return NULL;
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    add_u32(j, "first_index", first);
    cJSON *arr = cJSON_AddArrayToObject(j, "nonces");
    for (size_t i = 0; i < n; i++) {
        char hex[133];
        static const char d[] = "0123456789abcdef";
        for (size_t b = 0; b < 66; b++) { hex[2 * b] = d[pub[i][b] >> 4]; hex[2 * b + 1] = d[pub[i][b] & 15]; }
        hex[132] = 0;
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    return j;
}

int cu_wire_parse_nonces(const cJSON *json, uint32_t *channel_id, uint32_t *first,
                         unsigned char pub[][66], size_t cap, size_t *n) {
    if (!json || !get_u32(json, "channel_id", channel_id) || !get_u32(json, "first_index", first))
        return 0;
    const cJSON *arr = cJSON_GetObjectItem(json, "nonces");
    if (!cJSON_IsArray(arr)) return 0;
    int k = cJSON_GetArraySize(arr);
    if (k < 1 || (size_t)k > cap) return 0;
    for (int i = 0; i < k; i++) {
        const cJSON *it = cJSON_GetArrayItem(arr, i);
        if (!cJSON_IsString(it) || strlen(it->valuestring) != 132) return 0;
        if (hex_decode(it->valuestring, pub[i], 66) != 66) return 0;
    }
    *n = (size_t)k;
    return 1;
}
