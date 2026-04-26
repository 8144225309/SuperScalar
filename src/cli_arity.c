#include "superscalar/cli_arity.h"
#include "superscalar/factory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

/* Helper: clear write into err_buf with NUL termination. */
static void cli_set_err(char *buf, size_t len, const char *fmt, ...) {
    if (!buf || len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, len, fmt, ap);
    va_end(ap);
    (void)n;
    buf[len - 1] = '\0';
}

int cli_parse_arity_spec(const char *spec,
                          uint8_t *arities_out, size_t arities_cap,
                          size_t *n_arities_out,
                          int *leaf_arity_out,
                          char *err_buf, size_t err_buf_len) {
    if (!spec || !arities_out || !n_arities_out || !leaf_arity_out ||
        arities_cap == 0) {
        cli_set_err(err_buf, err_buf_len, "Error: cli_parse_arity_spec: NULL arg");
        return 0;
    }
    /* Reject empty / whitespace-only string. */
    const char *p = spec;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) {
        cli_set_err(err_buf, err_buf_len,
                    "Error: --arity requires a value (e.g. 3 or 2,4,8)");
        return 0;
    }

    /* Make a local mutable copy for strtok. */
    char buf[256];
    size_t spec_len = strlen(spec);
    if (spec_len >= sizeof(buf)) {
        cli_set_err(err_buf, err_buf_len,
                    "Error: --arity value too long (max %zu chars)", sizeof(buf) - 1);
        return 0;
    }
    memcpy(buf, spec, spec_len + 1);

    size_t n = 0;
    char *tok = strtok(buf, ",");
    while (tok) {
        /* Skip leading spaces in the token */
        while (*tok && isspace((unsigned char)*tok)) tok++;
        if (!*tok) {
            cli_set_err(err_buf, err_buf_len,
                        "Error: --arity has empty entry (check commas)");
            return 0;
        }
        /* Reject non-digit characters (atoi would silently coerce). */
        for (const char *q = tok; *q && !isspace((unsigned char)*q); q++) {
            if (!isdigit((unsigned char)*q)) {
                cli_set_err(err_buf, err_buf_len,
                            "Error: --arity entry '%s' is not a positive integer", tok);
                return 0;
            }
        }
        if (n >= arities_cap) {
            cli_set_err(err_buf, err_buf_len,
                        "Error: --arity has too many levels (max %zu)", arities_cap);
            return 0;
        }
        long v = strtol(tok, NULL, 10);
        if (v < 1 || v > 15) {
            cli_set_err(err_buf, err_buf_len,
                        "Error: --arity entry %ld out of range; arity must be 1-15 "
                        "(arity-A leaves need A+1 outputs and FACTORY_MAX_OUTPUTS=16)",
                        v);
            return 0;
        }
        arities_out[n++] = (uint8_t)v;
        tok = strtok(NULL, ",");
    }
    if (n == 0) {
        cli_set_err(err_buf, err_buf_len,
                    "Error: --arity parsed zero entries");
        return 0;
    }
    *n_arities_out = n;
    *leaf_arity_out = (int)arities_out[n - 1];
    return 1;
}

int cli_parse_static_near_root(const char *spec,
                                uint32_t *value_out,
                                char *err_buf, size_t err_buf_len) {
    if (!spec || !value_out) {
        cli_set_err(err_buf, err_buf_len,
                    "Error: cli_parse_static_near_root: NULL arg");
        return 0;
    }
    const char *p = spec;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) {
        cli_set_err(err_buf, err_buf_len,
                    "Error: --static-near-root requires a value (0 disables)");
        return 0;
    }
    /* Reject non-digit characters. */
    for (const char *q = p; *q && !isspace((unsigned char)*q); q++) {
        if (!isdigit((unsigned char)*q)) {
            cli_set_err(err_buf, err_buf_len,
                        "Error: --static-near-root '%s' is not a non-negative integer", p);
            return 0;
        }
    }
    long v = strtol(p, NULL, 10);
    if (v < 0 || v >= (long)FACTORY_MAX_LEVELS) {
        cli_set_err(err_buf, err_buf_len,
                    "Error: --static-near-root must be in [0, %d) (got %ld)",
                    FACTORY_MAX_LEVELS, v);
        return 0;
    }
    *value_out = (uint32_t)v;
    return 1;
}

int cli_validate_shape_for_bolt2016(
    const uint8_t *level_arities, size_t n_level_arity,
    factory_arity_t leaf_arity,
    size_t n_clients,
    uint32_t static_threshold,
    uint16_t step_blocks,
    uint32_t states_per_layer,
    uint32_t *ewt_out,
    char *err_buf, size_t err_buf_len)
{
    uint32_t ewt = factory_compute_ewt_for_shape(
        level_arities, n_level_arity, leaf_arity,
        n_clients, static_threshold, step_blocks, states_per_layer);
    if (ewt_out) *ewt_out = ewt;
    if (ewt <= CLI_ARITY_BOLT2016_CEILING) return 1;

    /* Build a printable shape descriptor for the error. */
    char shape[128];
    if (n_level_arity > 0) {
        size_t off = 0;
        for (size_t i = 0; i < n_level_arity && off < sizeof(shape) - 4; i++) {
            int n = snprintf(shape + off, sizeof(shape) - off,
                             "%s%u", (i == 0 ? "" : ","),
                             (unsigned)level_arities[i]);
            if (n < 0) break;
            off += (size_t)n;
        }
    } else {
        snprintf(shape, sizeof(shape), "%d", (int)leaf_arity);
    }
    cli_set_err(err_buf, err_buf_len,
        "Error: --arity %s --clients %zu%s%u produces ewt %u blocks "
        "(~%u days at 144 blk/day), exceeds BOLT 2016-block ceiling. "
        "See docs/factory-arity.md for canonical shapes. "
        "Try mixed arity with wider mid-tree branching (e.g. --arity 2,4,8) "
        "or add --static-near-root 1 or 2 to remove DW state from near-root layers.",
        shape, n_clients,
        (static_threshold > 0 ? " --static-near-root " : ""),
        (unsigned)static_threshold,
        ewt, ewt / 144);
    return 0;
}
