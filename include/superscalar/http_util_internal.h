/*
 * http_util_internal.h - minimal HTTP I/O helpers shared between
 * src/lsp_wellknown.c and src/prometheus_exporter.c.
 *
 * Internal header (not part of the public include/superscalar/ API):
 * just enough to remove the byte-identical copies of read_line/write_all
 * that those two HTTP servers had carried.  If a third HTTP endpoint
 * appears, it should use these helpers too.
 */

#ifndef SUPERSCALAR_HTTP_UTIL_INTERNAL_H
#define SUPERSCALAR_HTTP_UTIL_INTERNAL_H

#include <stddef.h>

/* Read one CRLF- or LF-terminated line from fd into buf (NUL-terminated,
   line terminator stripped).  Returns 0 on EOF or read() error. */
int http_util_read_line(int fd, char *buf, size_t cap);

/* Write all len bytes of buf to fd.  Returns 0 on partial-write or
   write() error, 1 on success. */
int http_util_write_all(int fd, const char *buf, size_t len);

#endif /* SUPERSCALAR_HTTP_UTIL_INTERNAL_H */
