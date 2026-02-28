/* Phase 15: Daemon mode tests */
#include "superscalar/wire.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <pthread.h>

#include "superscalar/sha256.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Test 1: MSG_REGISTER_INVOICE wire message round-trip */
int test_register_invoice_wire(void) {
    unsigned char payment_hash[32];
    memset(payment_hash, 0xAB, 32);
    uint64_t amount_msat = 50000000;
    size_t dest_client = 2;

    /* Build */
    cJSON *msg = wire_build_register_invoice(payment_hash, amount_msat, dest_client);
    TEST_ASSERT(msg != NULL, "build returned NULL");

    /* Parse */
    unsigned char parsed_hash[32];
    uint64_t parsed_amount;
    size_t parsed_dest;
    int ok = wire_parse_register_invoice(msg, parsed_hash, &parsed_amount, &parsed_dest);
    TEST_ASSERT(ok, "parse failed");
    TEST_ASSERT_MEM_EQ(parsed_hash, payment_hash, 32, "payment_hash mismatch");
    TEST_ASSERT_EQ(parsed_amount, amount_msat, "amount_msat mismatch");
    TEST_ASSERT_EQ(parsed_dest, dest_client, "dest_client mismatch");

    cJSON_Delete(msg);
    return 1;
}

/* Test 2: LSP daemon loop exits cleanly on shutdown flag */

static volatile sig_atomic_t test_shutdown_flag = 0;

static void *shutdown_thread(void *arg) {
    (void)arg;
    usleep(500000);  /* 500ms */
    test_shutdown_flag = 1;
    return NULL;
}

int test_daemon_event_loop(void) {
    /* Create a socketpair to act as client fds */
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    TEST_ASSERT(r == 0, "socketpair failed");

    /* Set up minimal lsp_t with one client fd */
    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    lsp.client_fds[0] = sv[0];
    lsp.client_fds[1] = sv[0];
    lsp.client_fds[2] = sv[0];
    lsp.client_fds[3] = sv[0];
    lsp.n_clients = 4;

    /* Set up minimal channel manager */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 4;
    mgr.bridge_fd = -1;
    mgr.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Set shutdown flag from another thread after a delay */
    test_shutdown_flag = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, shutdown_thread, NULL);

    int ok = lsp_channels_run_daemon_loop(&mgr, &lsp, &test_shutdown_flag);
    TEST_ASSERT(ok, "daemon loop returned failure");

    pthread_join(tid, NULL);
    secp256k1_context_destroy(mgr.ctx);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* Test 3: Client daemon receives ADD_HTLC and sends FULFILL via socketpair.
   Tests the wire message flow for the daemon auto-fulfill path.
   Skips commitment signing (covered by regtest tests with full ceremony). */
int test_client_daemon_autofulfill(void) {
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    TEST_ASSERT(r == 0, "socketpair failed");

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Client keypair */
    unsigned char client_seckey[32];
    memset(client_seckey, 0x22, 32);
    secp256k1_pubkey client_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &client_pubkey, client_seckey)) return 0;

    /* LSP keypair */
    unsigned char lsp_seckey[32];
    memset(lsp_seckey, 0x11, 32);
    secp256k1_pubkey lsp_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &lsp_pubkey, lsp_seckey)) return 0;

    /* Initialize a minimal client channel (just needs HTLC tracking) */
    channel_t ch;
    unsigned char fake_txid[32];
    memset(fake_txid, 0x01, 32);
    unsigned char fake_spk[34] = {0x51, 0x20};
    memset(fake_spk + 2, 0xAA, 32);

    TEST_ASSERT(channel_init(&ch, ctx, client_seckey, &client_pubkey, &lsp_pubkey,
                              fake_txid, 0, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init failed");

    /* Preimage and payment hash */
    unsigned char preimage[32];
    memset(preimage, 0x42, 32);
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    /* Send ADD_HTLC over sv[1] (as if from LSP) */
    cJSON *add_msg = wire_build_update_add_htlc(0, 1000000, payment_hash, 500);
    TEST_ASSERT(wire_send(sv[1], MSG_UPDATE_ADD_HTLC, add_msg), "send ADD_HTLC failed");
    cJSON_Delete(add_msg);

    /* Fork: child handles the ADD_HTLC on sv[0] and sends FULFILL back */
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[1]);

        /* Recv ADD_HTLC and add to channel */
        wire_msg_t m;
        if (!wire_recv(sv[0], &m)) _exit(1);
        if (m.msg_type != MSG_UPDATE_ADD_HTLC) {
            cJSON_Delete(m.json);
            _exit(2);
        }
        if (!client_handle_add_htlc(&ch, &m)) {
            cJSON_Delete(m.json);
            _exit(3);
        }
        cJSON_Delete(m.json);

        /* Find active received HTLC and fulfill it */
        int found = 0;
        for (size_t h = 0; h < ch.n_htlcs; h++) {
            if (ch.htlcs[h].state == HTLC_STATE_ACTIVE &&
                ch.htlcs[h].direction == HTLC_RECEIVED) {
                client_fulfill_payment(sv[0], &ch, ch.htlcs[h].id, preimage);
                found = 1;
                break;
            }
        }
        if (!found) _exit(4);

        close(sv[0]);
        secp256k1_context_destroy(ctx);
        _exit(0);
    }

    /* Parent: read FULFILL_HTLC response */
    close(sv[0]);

    wire_msg_t resp;
    TEST_ASSERT(wire_recv(sv[1], &resp), "recv FULFILL_HTLC failed");
    TEST_ASSERT_EQ(resp.msg_type, MSG_UPDATE_FULFILL_HTLC, "expected FULFILL_HTLC");

    unsigned char recv_preimage[32];
    uint64_t recv_htlc_id;
    TEST_ASSERT(wire_parse_update_fulfill_htlc(resp.json, &recv_htlc_id, recv_preimage),
                "parse fulfill failed");
    TEST_ASSERT_MEM_EQ(recv_preimage, preimage, 32, "preimage mismatch");
    cJSON_Delete(resp.json);

    close(sv[1]);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed");

    secp256k1_context_destroy(ctx);
    return 1;
}
