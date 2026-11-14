/* Test helpers for client authentication (see test_auth_util.h). */
#include "test_auth_util.h"
#include "superscalar/wire.h"
#include "superscalar/noise.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <unistd.h>

int test_auth_secure_pair(int a, int b, unsigned char *hash_out32)
{
    static unsigned int counter = 0;
    unsigned char seed[8], k1[32], k2[32], h[32];
    counter++;
    memcpy(seed, &counter, sizeof(counter));
    memcpy(seed + 4, "pair", 4);
    sha256_tagged("test/k1", seed, 8, k1);
    sha256_tagged("test/k2", seed, 8, k2);
    sha256_tagged("test/hash", seed, 8, h);
    noise_state_t na, nb;
    memset(&na, 0, sizeof(na));
    memset(&nb, 0, sizeof(nb));
    memcpy(na.send_key, k1, 32);
    memcpy(na.recv_key, k2, 32);
    memcpy(nb.send_key, k2, 32);
    memcpy(nb.recv_key, k1, 32);
    memcpy(na.handshake_hash, h, 32);
    memcpy(nb.handshake_hash, h, 32);
    if (!wire_mark_encryption_required(a) || !wire_mark_encryption_required(b) ||
        !wire_set_encryption(a, &na) || !wire_set_encryption(b, &nb))
        return 0;
    if (hash_out32) memcpy(hash_out32, h, 32);
    return 1;
}

int test_auth_answer(int fd, const unsigned char *sec32, uint8_t purpose)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kp;
    int ok = ctx && secp256k1_keypair_create(ctx, &kp, sec32) &&
             wire_client_auth_respond(ctx, fd, &kp, purpose, 10);
    if (ctx) secp256k1_context_destroy(ctx);
    return ok;
}

pid_t test_auth_answer_fork(int fd, const unsigned char *sec32,
                            uint8_t purpose)
{
    pid_t pid = fork();
    if (pid == 0)
        _exit(test_auth_answer(fd, sec32, purpose) ? 0 : 1);
    return pid;
}
