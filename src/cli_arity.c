#include "superscalar/cli_arity.h"
#include "superscalar/network.h"
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
    uint32_t ps_subfactory_arity,
    size_t n_clients,
    uint32_t static_threshold,
    uint16_t step_blocks,
    uint32_t states_per_layer,
    uint32_t *ewt_out,
    char *err_buf, size_t err_buf_len)
{
    uint32_t ewt = factory_compute_ewt_for_shape(
        level_arities, n_level_arity, leaf_arity, ps_subfactory_arity,
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
    char static_clause[64];
    if (static_threshold > 0)
        snprintf(static_clause, sizeof(static_clause),
                 " --static-near-root %u", (unsigned)static_threshold);
    else
        static_clause[0] = '\0';
    cli_set_err(err_buf, err_buf_len,
        "Error: --arity %s --clients %zu%s produces ewt %u blocks "
        "(~%u days at 144 blk/day), exceeds BOLT 2016-block ceiling. "
        "See docs/factory-arity.md for canonical shapes. "
        "Try mixed arity with wider mid-tree branching (e.g. --arity 2,4,8) "
        "or add --static-near-root 1 or 2 to remove DW state from near-root layers.",
        shape, n_clients, static_clause,
        ewt, ewt / 144);
    return 0;
}

int cli_validate_mainnet_step_floor(const char *network, uint16_t step_blocks,
                                    char *err_buf, size_t err_buf_len)
{
    if (!network_is_mainnet(network)) return 1;                     /* non-mainnet: always OK */
    if (step_blocks >= CLI_ARITY_MAINNET_MIN_STEP_BLOCKS) return 1;
    cli_set_err(err_buf, err_buf_len,
        "Error: --step-blocks %u is below the mainnet safety floor of %u "
        "(~1 day). The DW timeout-tree step sets the CLTV/CSV ladder spacing; "
        "a small step shrinks the reorg / fee-race margin. Re-run with "
        "--step-blocks %u (or higher) on mainnet.",
        (unsigned)step_blocks,
        (unsigned)CLI_ARITY_MAINNET_MIN_STEP_BLOCKS,
        (unsigned)CLI_ARITY_MAINNET_MIN_STEP_BLOCKS);
    return 0;
}

uint32_t cli_factory_exit_blocks(const uint8_t *level_arities, size_t n_level_arity,
                                 factory_arity_t leaf_arity,
                                 uint32_t ps_subfactory_arity, size_t n_clients,
                                 uint32_t static_threshold, uint16_t step_blocks,
                                 uint32_t states_per_layer)
{
    uint64_t ewt = factory_compute_ewt_for_shape(level_arities, n_level_arity,
                                                 leaf_arity, ps_subfactory_arity,
                                                 n_clients,
                                                 static_threshold, step_blocks,
                                                 states_per_layer);
    uint32_t depth = 1;
    while (depth < 32 && ((size_t)1 << (depth - 1)) < n_clients) depth++;
    uint64_t total = ewt + (2u * depth + 3u);
    return total > UINT32_MAX / 2 ? UINT32_MAX / 2 : (uint32_t)total;
}

int cli_validate_factory_cltv(uint32_t cltv_timeout, uint32_t created,
                              uint32_t active_blocks, uint32_t dying_blocks,
                              uint32_t exit_blocks,
                              char *err_buf, size_t err_buf_len)
{
    uint64_t expired = (uint64_t)created + active_blocks + dying_blocks;
    uint64_t need = expired + exit_blocks + CLI_FACTORY_CLTV_MARGIN;
    if ((uint64_t)cltv_timeout >= need) return 1;
    cli_set_err(err_buf, err_buf_len,
        "Error: factory CLTV timeout %u is too early: a factory created at "
        "block %u with %u active and %u dying blocks expires at block %llu, "
        "and the LSP's forced exit of a member can take %u blocks (+%u margin) "
        "after that, before the end-date payouts are valid. "
        "Use --cltv-timeout %llu or later (or leave it unset).",
        (unsigned)cltv_timeout, (unsigned)created, (unsigned)active_blocks,
        (unsigned)dying_blocks, (unsigned long long)expired,
        (unsigned)exit_blocks, (unsigned)CLI_FACTORY_CLTV_MARGIN,
        (unsigned long long)need);
    return 0;
}

int cli_validate_proposed_cltv(uint32_t cltv_timeout, uint32_t tip,
                               uint32_t exit_blocks,
                               char *err_buf, size_t err_buf_len)
{
    if (tip == 0) return 1;
    uint64_t need = (uint64_t)tip + exit_blocks + CLI_FACTORY_CLTV_MARGIN;
    if ((uint64_t)cltv_timeout > need) return 1;
    cli_set_err(err_buf, err_buf_len,
        "factory CLTV timeout %u is not safely in the future: chain tip %u, "
        "and a member's exit from this tree can take %u blocks (+%u margin); "
        "the end-date payouts would be valid before the exit could confirm",
        (unsigned)cltv_timeout, (unsigned)tip, (unsigned)exit_blocks,
        (unsigned)CLI_FACTORY_CLTV_MARGIN);
    return 0;
}

uint32_t cli_factory_auto_cltv_offset(uint32_t base_offset, uint32_t exit_blocks)
{
    uint64_t off = (uint64_t)base_offset + exit_blocks + CLI_FACTORY_CLTV_MARGIN +
                   CLI_FACTORY_TIP_SKEW;
    return off > UINT32_MAX / 2 ? UINT32_MAX / 2 : (uint32_t)off;
}

uint32_t cli_factory_force_exit_height(uint32_t cltv_timeout, uint32_t exit_blocks)
{
    uint64_t back = (uint64_t)exit_blocks + CLI_FACTORY_CLTV_MARGIN;
    return (uint64_t)cltv_timeout > back ? (uint32_t)(cltv_timeout - back) : 0;
}
