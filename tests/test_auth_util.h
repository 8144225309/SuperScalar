#ifndef SUPERSCALAR_TEST_AUTH_UTIL_H
#define SUPERSCALAR_TEST_AUTH_UTIL_H

#include <stdint.h>
#include <sys/types.h>

/* Give the two ends a, b of a socketpair matching encrypted sessions, as a
   Noise handshake between them would (a plays the LSP, b the client).
   Every call gives the pair a session binding of its own, copied to
   hash_out32 when it is not NULL.  Returns 1 on success.  Close such fds
   with wire_close, which forgets their sessions. */
int test_auth_secure_pair(int a, int b, unsigned char *hash_out32);

/* Client side: answer the LSP key challenge on fd with the key whose
   secret is sec32, for purpose (MSG_HELLO or MSG_RECONNECT).  Returns 1
   once the proof is sent. */
int test_auth_answer(int fd, const unsigned char *sec32, uint8_t purpose);

/* Fork a child that answers the key challenge on fd (test_auth_answer)
   and exits 0 if it could.  Returns the child pid, -1 on failure. */
pid_t test_auth_answer_fork(int fd, const unsigned char *sec32,
                            uint8_t purpose);

#endif
