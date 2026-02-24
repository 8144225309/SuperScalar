#ifndef SUPERSCALAR_REPORT_H
#define SUPERSCALAR_REPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <secp256k1.h>

/* Forward declaration — avoid pulling in cJSON.h in the public header */
struct cJSON;

/*
 * Diagnostic report: builds a JSON document incrementally.
 * Used by LSP and client binaries with --report PATH.
 * All crypto data (sighashes, sigs, txids, pubkeys) is logged at each phase.
 */

typedef struct {
    struct cJSON *root;       /* top-level JSON object */
    struct cJSON *current;    /* current section (object or array) being populated */
    struct cJSON *stack[16];  /* section stack for push/pop */
    int stack_depth;
    FILE *fp;                 /* output file */
    char path[256];
    int enabled;              /* 0 if no --report flag */
} report_t;

/* Initialize a report. path=NULL disables reporting (no-op on all calls).
   Returns 1 on success (or if disabled), 0 on file open failure. */
int  report_init(report_t *r, const char *path);

/* Add a hex-encoded byte array field. */
void report_add_hex(report_t *r, const char *key,
                    const unsigned char *data, size_t len);

/* Add an unsigned integer field. */
void report_add_uint(report_t *r, const char *key, uint64_t val);

/* Add a signed integer field. */
void report_add_int(report_t *r, const char *key, int64_t val);

/* Add a string field. */
void report_add_string(report_t *r, const char *key, const char *val);

/* Add a compressed pubkey field (33-byte hex). */
void report_add_pubkey(report_t *r, const char *key,
                       secp256k1_context *ctx, const secp256k1_pubkey *pk);

/* Add a boolean field. */
void report_add_bool(report_t *r, const char *key, int val);

/* Begin a nested JSON object section. */
void report_begin_section(report_t *r, const char *name);

/* End the current nested object section. */
void report_end_section(report_t *r);

/* Begin a JSON array. */
void report_begin_array(report_t *r, const char *name);

/* End the current array. */
void report_end_array(report_t *r);

/* Flush current JSON state to disk (overwrites file with pretty-printed JSON). */
void report_flush(report_t *r);

/* Final flush + fclose. */
void report_close(report_t *r);

#endif /* SUPERSCALAR_REPORT_H */
