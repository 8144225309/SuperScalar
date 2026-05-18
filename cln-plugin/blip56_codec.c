/* bLIP-56 wire codec — skeleton implementation.
 *
 * STUB ONLY: decode trivially splits type byte and payload; encode
 * concatenates. Real codec will route through src/wire.c TLV machinery
 * once the plugin's send path is wired up (#172). */

#include "blip56_codec.h"

#include <stdio.h>
#include <string.h>

int blip56_decode(const uint8_t *buf, size_t buf_len, blip56_frame_t *out)
{
    if (!buf || !out || buf_len < 1) return -1;
    out->type        = (blip56_msg_type_t)buf[0];
    out->payload     = buf_len > 1 ? &buf[1] : NULL;
    out->payload_len = buf_len - 1;
    fprintf(stderr, "STUB: blip56_decode type=0x%02x payload_len=%zu\n",
            (unsigned)out->type, out->payload_len);
    return 0;
}

int blip56_encode(blip56_msg_type_t type,
                  const uint8_t    *payload,
                  size_t            payload_len,
                  uint8_t          *out,
                  size_t            out_cap)
{
    if (!out)                          return -1;
    if (out_cap < 1 + payload_len)     return -1;
    out[0] = (uint8_t)type;
    if (payload && payload_len)
        memcpy(&out[1], payload, payload_len);
    fprintf(stderr, "STUB: blip56_encode type=0x%02x payload_len=%zu\n",
            (unsigned)type, payload_len);
    return (int)(1 + payload_len);
}
