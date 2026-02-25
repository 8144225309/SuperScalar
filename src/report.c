#include "superscalar/report.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>     /* _chsize, _fileno */
#else
#include <unistd.h> /* ftruncate, fileno */
#endif

extern void hex_encode(const unsigned char *data, size_t len, char *out);

int report_init(report_t *r, const char *path) {
    memset(r, 0, sizeof(*r));

    if (!path) {
        r->enabled = 0;
        return 1;
    }

    r->fp = fopen(path, "w");
    if (!r->fp)
        return 0;

    strncpy(r->path, path, sizeof(r->path) - 1);
    r->root = cJSON_CreateObject();
    r->current = r->root;
    r->stack_depth = 0;
    r->enabled = 1;
    return 1;
}

void report_add_hex(report_t *r, const char *key,
                    const unsigned char *data, size_t len) {
    if (!r->enabled || !r->current || !data || len == 0) return;

    char *hex = (char *)malloc(len * 2 + 1);
    if (!hex) return;
    hex_encode(data, len, hex);

    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, cJSON_CreateString(hex));
    } else {
        cJSON_AddStringToObject(r->current, key, hex);
    }
    free(hex);
}

void report_add_uint(report_t *r, const char *key, uint64_t val) {
    if (!r->enabled || !r->current) return;

    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, cJSON_CreateNumber((double)val));
    } else {
        cJSON_AddNumberToObject(r->current, key, (double)val);
    }
}

void report_add_int(report_t *r, const char *key, int64_t val) {
    if (!r->enabled || !r->current) return;

    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, cJSON_CreateNumber((double)val));
    } else {
        cJSON_AddNumberToObject(r->current, key, (double)val);
    }
}

void report_add_string(report_t *r, const char *key, const char *val) {
    if (!r->enabled || !r->current || !val) return;

    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, cJSON_CreateString(val));
    } else {
        cJSON_AddStringToObject(r->current, key, val);
    }
}

void report_add_pubkey(report_t *r, const char *key,
                       secp256k1_context *ctx, const secp256k1_pubkey *pk) {
    if (!r->enabled || !r->current || !ctx || !pk) return;

    unsigned char buf[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk,
                                        SECP256K1_EC_COMPRESSED))
        return;

    report_add_hex(r, key, buf, 33);
}

void report_add_bool(report_t *r, const char *key, int val) {
    if (!r->enabled || !r->current) return;

    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, cJSON_CreateBool(val));
    } else {
        cJSON_AddBoolToObject(r->current, key, val);
    }
}

void report_begin_section(report_t *r, const char *name) {
    if (!r->enabled || !r->current) return;
    if (r->stack_depth >= 15) return;  /* guard overflow */

    r->stack[r->stack_depth++] = r->current;

    cJSON *section = cJSON_CreateObject();
    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, section);
    } else {
        cJSON_AddItemToObject(r->current, name, section);
    }
    r->current = section;
}

void report_end_section(report_t *r) {
    if (!r->enabled || r->stack_depth <= 0) return;
    r->current = r->stack[--r->stack_depth];
}

void report_begin_array(report_t *r, const char *name) {
    if (!r->enabled || !r->current) return;
    if (r->stack_depth >= 15) return;

    r->stack[r->stack_depth++] = r->current;

    cJSON *arr = cJSON_CreateArray();
    if (cJSON_IsArray(r->current)) {
        cJSON_AddItemToArray(r->current, arr);
    } else {
        cJSON_AddItemToObject(r->current, name, arr);
    }
    r->current = arr;
}

void report_end_array(report_t *r) {
    if (!r->enabled || r->stack_depth <= 0) return;
    r->current = r->stack[--r->stack_depth];
}

void report_flush(report_t *r) {
    if (!r->enabled || !r->fp || !r->root) return;

    char *json_str = cJSON_Print(r->root);
    if (!json_str) return;

    /* Rewind and overwrite */
    rewind(r->fp);
    fputs(json_str, r->fp);
    fflush(r->fp);
    /* Truncate any leftover from a previous longer write */
#ifdef _WIN32
    _chsize(_fileno(r->fp), (long)strlen(json_str));
#else
    if (ftruncate(fileno(r->fp), (off_t)strlen(json_str)) != 0) {
        /* best-effort truncation; ignore failure */
    }
#endif
    free(json_str);
}

void report_close(report_t *r) {
    if (!r->enabled) return;

    report_flush(r);

    if (r->fp) {
        fclose(r->fp);
        r->fp = NULL;
    }
    if (r->root) {
        cJSON_Delete(r->root);
        r->root = NULL;
    }
    r->current = NULL;
    r->enabled = 0;
}
