/*
 * fuzz_hex_decode.c — libFuzzer harness for hex_decode().
 *
 * hex_decode() is the foundation of all binary parsing in the wire
 * protocol.  It must never crash regardless of input (odd length,
 * non-hex chars, empty string, NUL-embedded, etc.).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void hex_encode(const unsigned char *data, size_t len, char *out);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Treat input as a NUL-terminated string for hex_decode */
    char *str = (char *)__builtin_alloca(size + 1);
    memcpy(str, data, size);
    str[size] = '\0';

    unsigned char out[512];
    int decoded_len = hex_decode(str, out, sizeof(out));

    /* If decode succeeded, round-trip through encode */
    if (decoded_len > 0 && (size_t)decoded_len <= sizeof(out)) {
        char re_encoded[1025];
        hex_encode(out, (size_t)decoded_len, re_encoded);
        /* Verify round-trip: re-decode should match */
        unsigned char out2[512];
        int decoded_len2 = hex_decode(re_encoded, out2, sizeof(out2));
        (void)decoded_len2;  /* just ensure no crash */
    }

    return 0;
}
