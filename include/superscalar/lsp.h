#ifndef SUPERSCALAR_LSP_H
#define SUPERSCALAR_LSP_H

#include "factory.h"
#include "wire.h"
#include "rate_limit.h"
#include "persist.h"
#include "persist_wt.h"
#include <secp256k1.h>

/* Default inbound-connection capacity; --max-connections overrides it and
   client_fds/client_pubkeys are heap-allocated, so this is a default, not a cap. */
#define LSP_MAX_CLIENTS 256


typedef struct {
    secp256k1_context *ctx;
    secp256k1_keypair  lsp_keypair;
    secp256k1_pubkey   lsp_pubkey;

    /* Connected clients (dynamically allocated, capacity clients_cap) */
    int *client_fds;
    secp256k1_pubkey *client_pubkeys;
    size_t n_clients;
    size_t clients_cap;
    size_t expected_clients;

    /* Factory (built after all clients connect) */
    factory_t factory;

    /* #53 Phase 3: hashlock-gated L-stock poison.  When set, the binary
       (tools/superscalar_lsp.c) has installed a real random shachain seed
       on .factory and lsp_run_factory_creation_stateless calls
       factory_enable_hashlock_poison(f) AFTER factory_init_from_pubkeys
       re-init (which wipes use_hashlock_poison).  Default 0 (off / legacy
       L-stock key-path).  The client needs no equivalent flag — it mirrors
       each node's per-(leaf,state) hash off the wire. */
    int enable_hashlock_poison;

    /* Bridge daemon connection (Phase 14) */
    int bridge_fd;

    /* Finding A: expected bridge static pubkey for defense-in-depth pinning.
       Set via lsp_set_expected_bridge_pubkey (CLI --bridge-pubkey). If set,
       BRIDGE_HELLO whose bridge_pubkey is absent or mismatched is rejected. */
    secp256k1_pubkey expected_bridge_pubkey;
    int has_expected_bridge_pubkey;

    /* Listen socket */
    int listen_fd;
    int port;

    /* Accept timeout: max seconds to wait for each client connection.
       0 = no timeout (block indefinitely, default). */
    int accept_timeout_sec;

    /* Maximum connections the LSP will accept.
       Defaults to LSP_MAX_CLIENTS; --max-connections overrides. */
    int max_connections;

    /* NK (server-authenticated) handshake. If use_nk=1, lsp_accept_clients
       uses Noise NK with nk_seckey instead of NN. Default: 0 (NN). */
    int use_nk;
    unsigned char nk_seckey[32];

    /* Per-IP connection rate limiter + concurrent handshake cap. */
    rate_limiter_t rate_limiter;

    /* Optional per-client amounts for balance-aware distribution TX.
       Set before lsp_run_factory_creation() during rotation so the
       distribution TX reflects actual channel balances, not equal split.
       NULL = use equal split (initial creation). */
    const uint64_t *dist_client_amounts;
    size_t dist_n_client_amounts;

    /* When set, lsp_accept_clients refuses to proceed unless every client's
       HELLO included a valid slot_hint forming a permutation of 1..n_clients.
       Without slot_hints the funding-address derivation depends on TCP accept
       order — non-deterministic across restarts, which is a fund-loss risk
       (Campaign #3 stranded 6.5M signet sats this way). Enable on all
       non-regtest deployments. Default: 0 (off, regtest-friendly). */
    int require_slot_hints;

    /* Optional ceremony persistence handle (task #205).  When non-NULL,
       lsp_run_factory_creation calls the SF-CEREMONY-HELPERS API to
       record each phase transition: PROPOSE sent, NONCEs received,
       SIGs received, FINALIZED.  NULL = no persistence (legacy / tests
       without --db).  The caller (tools/superscalar_lsp.c) sets this
       from g_db after persist_open succeeds.  Persist is observability,
       not gating — helper failures are logged but never abort the
       ceremony. */
    persist_t *db;
    /* SF-BACKUP-PRE-ROTATION (#213): if non-NULL, dir to write
     * pre-rotation SQLite snapshots into.  NULL = disabled. */
    char *backup_dir;

    /* SF-WT-TRUSTLESS Phase 1b (#248): optional handle to the
     * watchtower-side persistence file.  When non-NULL, the LSP mirrors
     * each ceremony-completion watch+response pair into this file (which
     * the watchtower process will be the only reader of in Phase 2).
     * Owned by the binary (tools/superscalar_lsp.c) — the lsp_t struct
     * holds a borrowed pointer, never frees it.
     *
     * NULL is the legacy / not-configured state.  Phase 1b lands the
     * struct field + CLI plumbing only; the LSP-side register callsites
     * follow in Phase 1b.2.  See docs/watchtower-trustless-schema.md
     * for the trust model. */
    persist_wt_t *wt_db;

    /* Ceremony scratch, sized to expected_clients+1 by lsp_ensure_scratch() and
       released in lsp_cleanup().
       These were fixed [FACTORY_MAX_SIGNERS] STACK arrays, which is what capped
       the daemon at 255 clients: at n_participants = 257 they overflow, and
       lifting the --clients guard without converting them produced
       `*** stack smashing detected ***`, not a clean refusal (ASan named
       src/lsp.c:238 'seen' as the first to go).
       They live on the struct rather than as heap locals because the functions
       using them have several early returns; a local would need a free() on
       every one, which is where leaks and double-frees get introduced. One
       allocation, one free, no per-return bookkeeping.
       Capacity is +1 because 'seen' is indexed by SLOT (1..n_clients), not by
       client index, and pubkeys carries the LSP at [0]. */
    int              *scratch_slot_hints;  /* [scratch_cap] by client index */
    int              *scratch_seen;        /* [scratch_cap] by slot number */
    secp256k1_pubkey *scratch_pubkeys;     /* [scratch_cap]: LSP then clients */
    /* Save/restore buffer for factory.profiles across the stateless-creation
       re-init.  Was participant_profile_t[FACTORY_MAX_SIGNERS] on the stack and
       copied with sizeof(the array) -- as a pointer that would silently become
       sizeof(void*), so the two memcpys now carry explicit element counts. */
    participant_profile_t *scratch_profiles; /* [scratch_cap] */
    size_t            scratch_cap;
} lsp_t;

/* Ensure the ceremony scratch holds `want` entries. 1 on success, 0 on OOM.
   Idempotent and safe on a zeroed lsp_t; grows, never shrinks. */
int lsp_ensure_scratch(lsp_t *lsp, size_t want);

/* Initialize LSP state. Returns 1 on success, 0 on failure. */
int lsp_init(lsp_t *lsp, secp256k1_context *ctx,
              const secp256k1_keypair *keypair, int port,
              size_t expected_clients);

/* Accept expected_clients connections, do HELLO handshake with each.
   Returns 1 when all clients connected. */
int lsp_accept_clients(lsp_t *lsp);

/* Run full factory creation ceremony over the wire.
   funding_txid: internal byte order, already funded.
   Returns 1 on success (factory fully signed). */
int lsp_run_factory_creation(lsp_t *lsp,
                              const unsigned char *funding_txid, uint32_t funding_vout,
                              uint64_t funding_amount,
                              const unsigned char *funding_spk, size_t funding_spk_len,
                              uint16_t step_blocks, uint32_t states_per_layer,
                              uint32_t cltv_timeout);

/* Run cooperative close ceremony over the wire.
   Returns 1 on success, fills close_tx_out with signed tx. */
int lsp_run_cooperative_close(lsp_t *lsp,
                               tx_buf_t *close_tx_out,
                               const tx_output_t *outputs, size_t n_outputs,
                               uint32_t current_height);

/* Accept a bridge daemon connection (Phase 14).
   Expects MSG_BRIDGE_HELLO, sends MSG_BRIDGE_HELLO_ACK.
   Returns 1 on success. */
int lsp_accept_bridge(lsp_t *lsp);

/* Set the expected bridge static pubkey for Finding A defense-in-depth pin. */
void lsp_set_expected_bridge_pubkey(lsp_t *lsp, const secp256k1_pubkey *pk);

/* Return 1 if hello_json's bridge_pubkey matches the configured pin (or if
   no pin is configured); 0 to reject + log. Used at all BRIDGE_HELLO accept
   sites. */
int lsp_validate_bridge_pin(lsp_t *lsp, cJSON *hello_json);

/* Send MSG_ERROR to all connected clients, then close their fds. */
void lsp_abort_ceremony(lsp_t *lsp, const char *reason);

/* Derive an 8-byte ceremony_id from (factory_instance_id, type, epoch).
   Shared with src/lsp_rotation.c (ROTATE ceremony) and any other ceremony
   driver that needs to compute or recompute a deterministic ceremony_id
   (e.g., when linking parent_ceremony_id back to the dying factory's
   INITIAL ceremony). */
void lsp_ceremony_derive_id(const unsigned char *fid32,
                              uint8_t ceremony_type,
                              uint64_t epoch,
                              unsigned char out_cid8[8]);

/* Serialize a client's pubkey as 33 compressed bytes. Shared helper used
   by ceremony drivers that persist participant phases. */
void lsp_ceremony_get_client_pubkey33(const lsp_t *lsp, size_t client_idx,
                                       unsigned char out33[33]);

/* Cleanup */
void lsp_cleanup(lsp_t *lsp);

#endif /* SUPERSCALAR_LSP_H */
