/*
 * fuzz_noise_handshake.c — libFuzzer harness for noise_handshake_responder().
 *
 * Feeds arbitrary bytes through a socketpair as if they were an initiator's
 * handshake message.  The responder must never crash regardless of input.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <secp256k1.h>
#include "superscalar/noise.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 50) return 0;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return 0;

    /* Set short read timeout so we don't hang */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Write fuzz data to one end, close to signal EOF */
    write(fds[1], data, size);
    close(fds[1]);

    /* Create secp256k1 context */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        close(fds[0]);
        return 0;
    }

    /* Attempt handshake as responder — must never crash */
    noise_state_t ns;
    memset(&ns, 0, sizeof(ns));
    noise_handshake_responder(&ns, fds[0], ctx);

    close(fds[0]);
    secp256k1_context_destroy(ctx);
    return 0;
}
