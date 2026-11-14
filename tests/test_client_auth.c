/* Client authentication: a peer that names a client key in HELLO proves it
   holds that key, on its connection, before the LSP gives it a slot. */
#include "superscalar/wire.h"
#include "superscalar/noise.h"
#include "superscalar/lsp.h"
#include "test_auth_util.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* A proof verifies only for the challenge, purpose, key and connection it
   was made for. */
int test_client_auth_proof_binding(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char sk[32], sk2[32], c1[32], c2[32], h1[32], h2[32], sig[64];
    memset(sk, 0x31, 32);
    memset(sk2, 0x32, 32);
    memset(c1, 0xc1, 32);
    memset(c2, 0xc2, 32);
    memset(h1, 0xa1, 32);
    memset(h2, 0xb2, 32);
    secp256k1_keypair kp, kp2;
    secp256k1_pubkey pk, pk2;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp, sk) &&
                secp256k1_keypair_create(ctx, &kp2, sk2) &&
                secp256k1_keypair_pub(ctx, &pk, &kp) &&
                secp256k1_keypair_pub(ctx, &pk2, &kp2), "keys");

    TEST_ASSERT(wire_client_auth_sign(ctx, &kp, c1, MSG_RECONNECT, h1, sig),
                "sign");
    TEST_ASSERT(wire_client_auth_verify(ctx, sig, c1, MSG_RECONNECT, &pk, h1),
                "verifies for what it was made for");
    TEST_ASSERT(!wire_client_auth_verify(ctx, sig, c2, MSG_RECONNECT, &pk, h1),
                "not for another challenge on the same connection");
    TEST_ASSERT(!wire_client_auth_verify(ctx, sig, c1, MSG_RECONNECT, &pk, h2),
                "not on another connection");
    TEST_ASSERT(!wire_client_auth_verify(ctx, sig, c1, MSG_HELLO, &pk, h1),
                "not as a HELLO");
    TEST_ASSERT(!wire_client_auth_verify(ctx, sig, c1, MSG_RECONNECT, &pk2, h1),
                "not for another key");
    TEST_ASSERT(wire_client_auth_sign(ctx, &kp2, c1, MSG_RECONNECT, h1, sig),
                "sign with another key");
    TEST_ASSERT(!wire_client_auth_verify(ctx, sig, c1, MSG_RECONNECT, &pk, h1),
                "a signature by another key does not prove pk");
    TEST_ASSERT(!wire_client_auth_sign(ctx, &kp, c1, MSG_PING, h1, sig),
                "only HELLO and RECONNECT are proven");

    /* No encrypted session, no challenge and no answer. */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(!wire_client_auth_challenge(ctx, sv[0], MSG_HELLO, &pk),
                "no challenge without a session");
    TEST_ASSERT(!wire_client_auth_respond(ctx, sv[1], &kp, MSG_HELLO, 1),
                "no answer without a session");
    close(sv[0]);
    close(sv[1]);

    /* Over a session: the right key passes, another key does not, and a
       peer that answers with something else does not either. */
    for (int round = 0; round < 3; round++) {
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        TEST_ASSERT(test_auth_secure_pair(sv[0], sv[1], NULL), "session");
        pid_t pid;
        if (round == 2) {
            pid = fork();
            if (pid == 0) {
                wire_msg_t m;
                if (!wire_recv(sv[1], &m)) _exit(1);
                if (m.json) cJSON_Delete(m.json);
                cJSON *j = cJSON_CreateObject();
                cJSON_AddStringToObject(j, "sig", "00");
                wire_send(sv[1], MSG_CLIENT_AUTH_PROOF, j);
                cJSON_Delete(j);
                _exit(0);
            }
        } else {
            pid = test_auth_answer_fork(sv[1], round == 0 ? sk : sk2,
                                        MSG_HELLO);
        }
        TEST_ASSERT(pid > 0, "fork");
        int ok = wire_client_auth_challenge(ctx, sv[0], MSG_HELLO, &pk);
        int st = 0;
        waitpid(pid, &st, 0);
        wire_close(sv[0]);
        wire_close(sv[1]);
        TEST_ASSERT(ok == (round == 0), round == 0 ? "the key holder passes"
                                                   : "no one else does");
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- The first HELLO of a factory --- */

#define FIRST_HELLO_PORT 29871

/* A client process: connects, sends a HELLO naming the key of name_sk and
   answers the key challenge with the key of sign_sk.  Exits 0 if it gets
   HELLO_ACK and want_ack, or no HELLO_ACK and !want_ack. */
static void hello_client(const unsigned char *name_sk,
                         const unsigned char *sign_sk,
                         int want_ack, unsigned int delay_ms)
{
    usleep(delay_ms * 1000);
    secp256k1_context *c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey name_pk;
    if (!secp256k1_ec_pubkey_create(c, &name_pk, name_sk)) _exit(10);
    int fd = -1;
    for (int i = 0; i < 50 && fd < 0; i++) {
        fd = wire_connect("127.0.0.1", FIRST_HELLO_PORT);
        if (fd < 0) usleep(100000);
    }
    if (fd < 0 || !wire_noise_handshake_initiator(fd, c)) _exit(11);
    cJSON *m = wire_build_hello(c, &name_pk);
    if (!wire_send(fd, MSG_HELLO, m)) _exit(12);
    cJSON_Delete(m);
    if (!test_auth_answer(fd, sign_sk, MSG_HELLO)) _exit(13);
    wire_msg_t r;
    memset(&r, 0, sizeof(r));
    int got = wire_recv_timeout(fd, &r, 15) && r.msg_type == MSG_HELLO_ACK;
    _exit(got == want_ack ? 0 : 1);
}

/* The first HELLO of a factory takes a client slot only if the peer proves
   the key it names: an impostor that connects first, naming the victim
   key, is dropped, and the victim gets its slot. */
int test_client_auth_first_hello_proven(void)
{
    unsigned char lsp_sk[32], victim_sk[32], imp_sk[32];
    memset(lsp_sk, 0x10, 32);
    memset(victim_sk, 0x21, 32);
    memset(imp_sk, 0x66, 32);
    pid_t imp = fork();
    if (imp == 0) hello_client(victim_sk, imp_sk, 0, 300);
    pid_t vic = fork();
    if (vic == 0) hello_client(victim_sk, victim_sk, 1, 1500);
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair lkp;
    secp256k1_pubkey vpk;
    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    int ok = secp256k1_keypair_create(ctx, &lkp, lsp_sk) &&
             secp256k1_ec_pubkey_create(ctx, &vpk, victim_sk) &&
             lsp_init(&lsp, ctx, &lkp, FIRST_HELLO_PORT, 1);
    if (ok) {
        lsp.accept_timeout_sec = 20;
        ok = lsp_accept_clients(&lsp) && lsp.n_clients == 1 &&
             secp256k1_ec_pubkey_cmp(ctx, &lsp.client_pubkeys[0], &vpk) == 0;
    }
    /* closing the listener also ends a client still waiting on it */
    lsp_cleanup(&lsp);
    int si = 0, sv = 0;
    waitpid(imp, &si, 0);
    waitpid(vic, &sv, 0);
    secp256k1_context_destroy(ctx);
    TEST_ASSERT(ok, "the victim holds the slot");
    TEST_ASSERT(WIFEXITED(si) && WEXITSTATUS(si) == 0,
                "the impostor got no HELLO_ACK");
    TEST_ASSERT(WIFEXITED(sv) && WEXITSTATUS(sv) == 0,
                "the victim got its HELLO_ACK");
    return 1;
}
