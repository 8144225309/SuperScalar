/* SuperScalar CLN plugin — skeleton implementation.
 *
 * STUB ONLY. Every entry point returns success and logs a STUB: line so
 * the loader can verify dispatch wiring without performing any real
 * factory work. Real implementation lands incrementally under #172. */

#include "superscalar_cln.h"
#include "blip56_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Opaque handle — kept minimal until real state is added. */
struct cln_plugin_handle {
    uint32_t magic;           /* sanity-check token for FFI callers */
    uint64_t msgs_received;   /* useful even in skeleton for smoke tests */
};

#define SCLN_HANDLE_MAGIC 0x5C1AB116u   /* "SCLA" + "B16" — bLIP-56 marker */

cln_plugin_handle_t *superscalar_cln_init(void)
{
    fprintf(stderr, "STUB: superscalar_cln_init() — would set up factory state\n");
    cln_plugin_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->magic = SCLN_HANDLE_MAGIC;
    h->msgs_received = 0;
    return h;
}

void superscalar_cln_shutdown(cln_plugin_handle_t *h)
{
    if (!h) return;
    fprintf(stderr, "STUB: superscalar_cln_shutdown() — would tear down %llu msg state\n",
            (unsigned long long)h->msgs_received);
    h->magic = 0;
    free(h);
}

scln_status_t superscalar_cln_handle_blip56_msg(
    cln_plugin_handle_t *h,
    const uint8_t       *msg,
    size_t               msg_len)
{
    if (!h || h->magic != SCLN_HANDLE_MAGIC) return SCLN_ERR_INTERNAL;
    if (!msg || msg_len == 0)                return SCLN_ERR_BAD_MSG;

    blip56_frame_t frame;
    if (blip56_decode(msg, msg_len, &frame) != 0) {
        fprintf(stderr, "STUB: blip56_decode failed (len=%zu)\n", msg_len);
        return SCLN_ERR_BAD_MSG;
    }

    h->msgs_received++;

    switch (frame.type) {
    case BLIP56_MSG_FACTORY_PROPOSE:
        fprintf(stderr, "STUB: would call factory_propose(...) payload_len=%zu\n",
                frame.payload_len);
        break;
    case BLIP56_MSG_NONCE_BUNDLE:
    case BLIP56_MSG_ALL_NONCES:
    case BLIP56_MSG_PSIG_BUNDLE:
        fprintf(stderr, "STUB: factory signing msg type=0x%02x\n", (unsigned)frame.type);
        break;
    case BLIP56_MSG_UPDATE_ADD_HTLC:
    case BLIP56_MSG_COMMITMENT_SIGNED:
    case BLIP56_MSG_REVOKE_AND_ACK:
        fprintf(stderr, "STUB: channel op msg type=0x%02x\n", (unsigned)frame.type);
        break;
    case BLIP56_MSG_PING:
        fprintf(stderr, "STUB: would emit PONG\n");
        break;
    default:
        fprintf(stderr, "STUB: unhandled msg type=0x%02x\n", (unsigned)frame.type);
        break;
    }
    return SCLN_OK;
}

int superscalar_cln_main(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr, "STUB: superscalar_cln_main() — CLN plugin manifest not yet implemented\n");
    return 0;
}
