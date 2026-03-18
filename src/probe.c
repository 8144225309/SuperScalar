/*
 * probe.c — Fake-HTLC channel liquidity probing
 *
 * See probe.h for the full API description.
 */

#include "superscalar/probe.h"
#include <stdio.h>
#include <stdint.h>

int probe_build_payment_hash(unsigned char buf[32]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    int ok = (fread(buf, 1, 32, f) == 32);
    fclose(f);
    return ok;
}

probe_result_t probe_classify_failure(uint16_t code) {
    switch (code) {
    case PROBE_ERR_UNKNOWN_PAYMENT_HASH:
        return PROBE_RESULT_LIQUID;
    case PROBE_ERR_TEMPORARY_CHANNEL_FAILURE:
        return PROBE_RESULT_LIQUIDITY_FAIL;
    case PROBE_ERR_CHANNEL_DISABLED:
    case PROBE_ERR_UNKNOWN_NEXT_PEER:
        return PROBE_RESULT_CHANNEL_FAIL;
    case PROBE_ERR_AMOUNT_BELOW_MINIMUM:
    case PROBE_ERR_FEE_INSUFFICIENT:
    case PROBE_ERR_INCORRECT_CLTV_EXPIRY:
    case PROBE_ERR_EXPIRY_TOO_SOON:
    case PROBE_ERR_FINAL_EXPIRY_TOO_SOON:
        return PROBE_RESULT_POLICY_FAIL;
    default:
        return PROBE_RESULT_UNKNOWN;
    }
}

int probe_is_success_failure(uint16_t code) {
    return code == PROBE_ERR_UNKNOWN_PAYMENT_HASH;
}

int probe_is_liquidity_failure(uint16_t code) {
    return code == PROBE_ERR_TEMPORARY_CHANNEL_FAILURE;
}
