#ifndef SUPERSCALAR_TYPES_H
#define SUPERSCALAR_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct { unsigned char data[32]; } hash256_t;
typedef struct { unsigned char data[33]; } pubkey33_t;
typedef struct { unsigned char data[32]; } seckey_t;

typedef struct {
    hash256_t txid;
    uint32_t  vout;
} outpoint_t;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
    int oom;  /* sticky flag: set on allocation failure */
} tx_buf_t;

void tx_buf_init(tx_buf_t *buf, size_t initial_cap);
void tx_buf_free(tx_buf_t *buf);
void tx_buf_reset(tx_buf_t *buf);
void tx_buf_ensure(tx_buf_t *buf, size_t additional);

/* Zero sensitive memory in a way the compiler cannot optimize away. */
void secure_zero(void *ptr, size_t len);

/* SS_MUST_CHECK marks a function whose result the caller must act on.

   The project builds with -Wno-unused-result (libsecp256k1's own annotations
   would otherwise fire everywhere), which leaves warn_unused_result inert on
   its own.  Functions that need a hard guarantee therefore also get a
   same-named wrapper macro in their header:

       SS_MUST_CHECK int (f)(args);
       #define f(...) ((f)(__VA_ARGS__) != 0)

   A call whose result is discarded is then an unused comparison, which
   -Wunused-value (part of -Wall, an error under -Werror) rejects.  Use the
   result, or cast it to (void) where ignoring it is deliberate.  Define the
   function as `int (f)(...)` so the macro does not expand there. */
#if defined(__GNUC__) || defined(__clang__)
#define SS_MUST_CHECK __attribute__((warn_unused_result))
#else
#define SS_MUST_CHECK
#endif

#endif /* SUPERSCALAR_TYPES_H */
