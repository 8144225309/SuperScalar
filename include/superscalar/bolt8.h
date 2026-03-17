#ifndef SUPERSCALAR_BOLT8_H
#define SUPERSCALAR_BOLT8_H

/*
 * BOLT #8 — Noise_XK_secp256k1_ChaChaPoly_SHA256
 *
 * Three-act handshake (166 bytes total):
 *   Act 1 (initiator → responder): 50 bytes
 *   Act 2 (responder → initiator): 50 bytes
 *   Act 3 (initiator → responder): 66 bytes
 *
 * Three DH operations: ee, es, se
 * Prologue: empty string
 * Nonce encoding: big-endian (4 zero bytes + 8-byte BE counter)
 * Key rotation: every 1000 messages (per direction)
 *
 * Post-handshake message framing:
 *   18 bytes header (2-byte BE length + 16-byte tag)
 *   N+16 bytes body  (N-byte payload + 16-byte tag)
 */

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

/* Handshake state — evolves through acts 1/2/3 */
typedef struct {
    unsigned char h[32];       /* running handshake hash */
    unsigned char ck[32];      /* chaining key */
    unsigned char temp_k[32];  /* current temp key (updated each act) */
    unsigned char re_pub[33];  /* remote ephemeral pubkey (set after processing act1 or act2) */
    unsigned char e_priv[32];  /* our ephemeral private key (set during act1_create or act2_create) */
} bolt8_hs_t;

/* Post-handshake transport state */
typedef struct {
    unsigned char sk[32];   /* send key */
    unsigned char rk[32];   /* recv key */
    unsigned char ck[32];   /* chaining key (used for key rotation every 1000 messages) */
    uint64_t sn;            /* send nonce counter */
    uint64_t rn;            /* recv nonce counter */
} bolt8_state_t;

#define BOLT8_ACT1_SIZE  50
#define BOLT8_ACT2_SIZE  50
#define BOLT8_ACT3_SIZE  66

/* Phase-specific timeout constants (milliseconds) */
#define BOLT8_HANDSHAKE_TIMEOUT_MS   60000   /* CLN: 60s for full 3-act handshake */
#define BOLT8_INIT_TIMEOUT_MS        30000   /* Eclair: 30s for BOLT #1 init exchange */
#define BOLT8_PING_INTERVAL_MS       60000   /* LND: ping every 60s */
#define BOLT8_PING_TIMEOUT_MS        30000   /* LND: expect pong within 30s */
#define BOLT8_IDLE_TIMEOUT_MS       300000   /* LND: disconnect after 5min silence */

/* --- Handshake functions --- */

/* Initialize handshake state.
   rs_pub33: responder's static pubkey (33 bytes compressed secp256k1).
   Call once before act1. Both initiator and responder call this with the
   responder's static pubkey. */
void bolt8_hs_init(bolt8_hs_t *hs, const unsigned char rs_pub33[33]);

/* Act 1 — initiator builds 50-byte message.
   e_priv32: initiator's ephemeral private key (32 bytes; random in production).
   rs_pub33: responder's static pubkey (same as bolt8_hs_init).
   act1_out: 50-byte output buffer.
   Stores e_priv32 in hs for use during act2_process.
   Returns 1 on success, 0 on crypto failure. */
int bolt8_act1_create(bolt8_hs_t *hs, secp256k1_context *ctx,
                      const unsigned char e_priv32[32],
                      const unsigned char rs_pub33[33],
                      unsigned char act1_out[BOLT8_ACT1_SIZE]);

/* Act 1 — responder processes 50-byte message.
   act1_in: 50-byte act1 from initiator.
   rs_priv32: responder's static private key.
   Stores initiator's ephemeral pubkey in hs->re_pub for act2_create.
   Returns 1 on success, 0 on auth failure (wrong key or bad MAC). */
int bolt8_act1_process(bolt8_hs_t *hs, secp256k1_context *ctx,
                       const unsigned char act1_in[BOLT8_ACT1_SIZE],
                       const unsigned char rs_priv32[32]);

/* Act 2 — responder builds 50-byte message.
   e_priv32: responder's ephemeral private key (random in production).
   act2_out: 50-byte output buffer.
   Stores e_priv32 in hs for use during act3_process.
   Returns 1 on success, 0 on crypto failure. */
int bolt8_act2_create(bolt8_hs_t *hs, secp256k1_context *ctx,
                      const unsigned char e_priv32[32],
                      unsigned char act2_out[BOLT8_ACT2_SIZE]);

/* Act 2 — initiator processes 50-byte message.
   act2_in: 50-byte act2 from responder.
   Uses hs->e_priv (set in act1_create) for ee DH.
   Stores responder's ephemeral pubkey in hs->re_pub for act3_create.
   Returns 1 on success, 0 on auth failure. */
int bolt8_act2_process(bolt8_hs_t *hs, secp256k1_context *ctx,
                       const unsigned char act2_in[BOLT8_ACT2_SIZE]);

/* Act 3 — initiator builds 66-byte message and derives transport keys.
   s_priv32: initiator's static private key.
   act3_out: 66-byte output buffer.
   state_out: populated with sk, rk, ck, sn=0, rn=0 on success.
   Returns 1 on success, 0 on crypto failure. */
int bolt8_act3_create(bolt8_hs_t *hs, secp256k1_context *ctx,
                      const unsigned char s_priv32[32],
                      unsigned char act3_out[BOLT8_ACT3_SIZE],
                      bolt8_state_t *state_out);

/* Act 3 — responder processes 66-byte message and derives transport keys.
   act3_in: 66-byte act3 from initiator.
   Uses hs->e_priv (set in act2_create) for se DH.
   state_out: populated with sk, rk, ck, sn=0, rn=0 on success.
   Returns 1 on success, 0 on auth failure. */
int bolt8_act3_process(bolt8_hs_t *hs, secp256k1_context *ctx,
                       const unsigned char act3_in[BOLT8_ACT3_SIZE],
                       bolt8_state_t *state_out);

/* --- Post-handshake message framing --- */

/* Encrypt message for sending.
   Produces (18 + msg_len + 16) bytes in out_buf.
   out_buf must be at least msg_len + 34 bytes.
   Performs key rotation at sn == 1000 (automatically).
   Returns 1 on success. */
int bolt8_write_message(bolt8_state_t *state,
                        const unsigned char *msg, size_t msg_len,
                        unsigned char *out_buf);

/* Decrypt a framed message from in_buf (must be msg_len + 34 bytes).
   out_msg must be at least msg_len bytes.
   Returns 1 on success, 0 on auth failure. */
int bolt8_read_message(bolt8_state_t *state,
                       const unsigned char *in_buf, size_t total_len,
                       unsigned char *out_msg, size_t *out_msg_len);

/* Framing overhead added to each message */
#define BOLT8_MSG_OVERHEAD 34  /* 18 header + 16 body tag */

/* Send a framed message over fd. Returns 1 on success. */
int bolt8_send(bolt8_state_t *state, int fd,
               const unsigned char *msg, size_t msg_len);

/* Receive a framed message from fd. out_msg must be >= max_len bytes.
   Returns 1 on success, 0 on I/O error or auth failure. */
int bolt8_recv(bolt8_state_t *state, int fd,
               unsigned char *out_msg, size_t *out_msg_len, size_t max_len);

/*
 * bolt8_connect — outbound BOLT #8 initiator.
 * Performs acts 1/2/3 on an already-connected fd.
 * timeout_ms: per-phase deadline applied as SO_RCVTIMEO/SO_SNDTIMEO.
 * their_pub33: remote static pubkey (33 bytes). Must be a valid secp256k1 point.
 * Returns 1 on success with state_out populated, 0 on failure.
 */
int bolt8_connect(int fd,
                  secp256k1_context *ctx,
                  const unsigned char our_priv32[32],
                  const unsigned char their_pub33[33],
                  int timeout_ms,
                  bolt8_state_t *state_out);

#endif /* SUPERSCALAR_BOLT8_H */
