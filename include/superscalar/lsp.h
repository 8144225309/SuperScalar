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

    /* Set by lsp_run_cooperative_close once the fully signed close exists and
       is about to go to the clients (after it is persisted as 'closing').
       From then on any client can publish that close, so this factory is not
       served again: the daemon loop stops and no HTLC is accepted. */
    int closing;
} lsp_t;

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

/* Start-up handling of a factory whose cooperative close was signed and handed
   to the clients ('closing', persisted before CLOSE_DONE).  Any client can
   publish that close, so the factory must never be served again.

   Re-broadcasts the queued close.  If it confirmed, marks the factory closed.
   Otherwise the factory stays 'closing'; with force_close set, the signed
   factory tree is also published from the DB (factory_recovery_run, one
   pass): the operator's way out when the close cannot confirm, e.g. its fee
   is too low.  The close and the tree both spend the funding output, so
   whichever confirms first wins; once the tree's root confirms the close can
   no longer confirm and later runs keep publishing the tree until it is
   settled (factory_recovery_run then marks the factory closed).

   status (optional) receives a one-line explanation for the operator. */
enum {
    LSP_CLOSING_NOT     = -1,  /* not 'closing': serve normally */
    LSP_CLOSING_DONE    =  0,  /* the close confirmed; factory marked closed */
    LSP_CLOSING_PENDING =  1,  /* still 'closing': do not serve; run again */
    LSP_CLOSING_FAILED  =  2   /* force_close: part of the tree cannot be
                                  published (see status) */
};
struct chain_backend;
int lsp_resume_closing_factory(persist_t *db, struct chain_backend *chain,
                               uint32_t factory_id, int force_close,
                               char *status, size_t status_cap);

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
