#ifndef SUPERSCALAR_CHAN_UPDATE_WIRE_H
#define SUPERSCALAR_CHAN_UPDATE_WIRE_H

/* Wire form of the channel-update engine's messages (ids MSG_CU_* in
   wire.h).  The host opens a round with one MSG_CU_ROUND that carries the
   round's updates and its commitment_signed; the member asks with
   MSG_CU_OFFER and is answered by a round or MSG_CU_REFUSE.  All integers
   wider than 32 bits travel as decimal strings; every field is checked
   against its bounds before use (INV-58). */

#include "chan_update.h"
#include <cJSON.h>

/* Encode the next wire message from a run of the engine's outbox, as sent
   by `from`.  Returns the number of engine messages it covers (0 on an
   outbox the wire cannot carry); *json is the caller's to free. */
size_t cu_wire_encode(cu_side_t from, const cu_msg_t *m, size_t n,
                      uint8_t *type, cJSON **json);

/* Decode one wire message into engine messages, in order (a round gives
   its updates, then the commitment_signed).  Returns 1, or 0 on any
   malformed or out-of-bounds field. */
int cu_wire_decode(uint8_t type, const cJSON *json, cu_msg_t *out, size_t cap, size_t *n);

/* MSG_CU_NONCES: public nonces for signature indices first ... */
cJSON *cu_wire_nonces(uint32_t channel_id, uint32_t first, const unsigned char pub[][66], size_t n);
int cu_wire_parse_nonces(const cJSON *json, uint32_t *channel_id, uint32_t *first,
                         unsigned char pub[][66], size_t cap, size_t *n);

#endif /* SUPERSCALAR_CHAN_UPDATE_WIRE_H */
