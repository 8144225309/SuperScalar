/*
 * fuzz_wire_recv.c — libFuzzer harness for wire_recv().
 *
 * Feeds arbitrary bytes through a socketpair to wire_recv(), testing
 * the frame-level parser: length decode, WIRE_MAX_FRAME_SIZE check,
 * JSON payload parse.  Must never crash.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "superscalar/wire.h"
#include <cJSON.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return 0;

    /* Set short timeout so we don't hang */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Write fuzz data to one end, close it to signal EOF */
    write(fds[1], data, size);
    close(fds[1]);

    /* Try to receive a wire message — should never crash */
    wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    int ok = wire_recv(fds[0], &msg);
    if (ok && msg.json) {
        cJSON_Delete(msg.json);
    }

    close(fds[0]);
    return 0;
}
