/*
 * http_util.c - implementation of http_util_internal.h shared helpers.
 *
 * One-byte-at-a-time read_line is fine for tiny HTTP request lines
 * (request line + a handful of headers).  Both callers parse only the
 * request-line and discard the rest, so a fancier buffered reader is
 * not justified.
 */

#include "superscalar/http_util_internal.h"

#include <unistd.h>
#include <sys/types.h>

int http_util_read_line(int fd, char *buf, size_t cap) {
    if (cap == 0) return 0;
    size_t i = 0;
    while (i < cap - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return 0;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = '\0';
    return 1;
}

int http_util_write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}
