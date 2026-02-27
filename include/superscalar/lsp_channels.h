#ifndef SUPERSCALAR_LSP_CHANNELS_H
#define SUPERSCALAR_LSP_CHANNELS_H

#include "channel.h"
#include "lsp.h"
#include "wire.h"
#include "watchtower.h"
#include <signal.h>
#include <time.h>

/* Safety margin for HTLC forwarding: outgoing cltv_expiry is reduced by this
   delta so the LSP has time to claim on-chain if the factory needs a unilateral
   close before the upstream HTLC expires. 40 blocks ~ 6.7 hours. */
#define FACTORY_CLTV_DELTA 40

/* Validate and adjust cltv_expiry for HTLC forwarding through a factory channel.
   Returns 1 if cltv_expiry has enough room for the delta, 0 if too low.
   On success, *fwd_cltv_out = cltv_expiry - FACTORY_CLTV_DELTA. */
int lsp_validate_cltv_for_forward(uint32_t cltv_expiry, uint32_t *fwd_cltv_out);

/* Per-client channel entry managed by the LSP */
typedef struct {
    channel_t channel;          /* Poon-Dryja channel (LSP=local, client=remote) */
    uint32_t channel_id;        /* channel_id sent over wire (= client index) */
    int ready;                  /* 1 after CHANNEL_READY sent */
    time_t last_message_time;   /* epoch timestamp of last wire message */
    int offline_detected;        /* 1 if declared offline */
} lsp_channel_entry_t;

/* Invoice registry entry for bridge inbound payments (Phase 14) */
#define MAX_INVOICE_REGISTRY 64

typedef struct {
    unsigned char payment_hash[32];
    size_t dest_client;
    uint64_t amount_msat;
    uint64_t bridge_htlc_id;     /* correlation ID for bridge response */
    int active;
} invoice_entry_t;

/* HTLC origin tracking for bridge back-propagation (Phase 14) */
#define MAX_HTLC_ORIGINS 64

typedef struct {
    unsigned char payment_hash[32];
    uint64_t bridge_htlc_id;     /* 0 = intra-factory, >0 = from bridge */
    uint64_t request_id;         /* outbound pay correlation (Phase 17) */
    size_t sender_idx;           /* originating client index (Phase 17) */
    uint64_t sender_htlc_id;    /* HTLC id on sender's channel (Phase 17) */
    uint32_t cltv_expiry;       /* timelock for bridge HTLC timeout */
    int active;
} htlc_origin_t;

typedef struct {
    lsp_channel_entry_t entries[LSP_MAX_CLIENTS];
    size_t n_channels;
    secp256k1_context *ctx;

    /* Bridge support (Phase 14) */
    int bridge_fd;               /* -1 if no bridge connected */
    invoice_entry_t invoices[MAX_INVOICE_REGISTRY];
    size_t n_invoices;
    htlc_origin_t htlc_origins[MAX_HTLC_ORIGINS];
    size_t n_htlc_origins;
    uint64_t next_request_id;    /* for outbound pay correlation */

    /* Watchtower (Phase 18) */
    watchtower_t *watchtower;

    /* Fee estimator (Phase 2) */
    void *fee;      /* fee_estimator_t* or NULL — avoids header dependency */

    /* Persistence (Phase 23) */
    void *persist;  /* persist_t* or NULL — avoids header dependency */

    /* Ladder manager (Tier 2) */
    void *ladder;   /* ladder_t* or NULL — avoids header dependency */

    /* Continuous ladder rotation (set once at daemon startup) */
    unsigned char rot_lsp_seckey[32];
    void *rot_fee_est;              /* fee_estimator_t* — avoids header dependency */
    unsigned char rot_fund_spk[34];
    size_t rot_fund_spk_len;
    char rot_fund_addr[128];
    char rot_mine_addr[128];
    uint16_t rot_step_blocks;
    uint32_t rot_states_per_layer;
    int rot_is_regtest;
    uint64_t rot_funding_sats;
    int rot_leaf_arity;            /* FACTORY_ARITY_1 or FACTORY_ARITY_2 */
    int rot_auto_rotate;           /* 1 = auto-rotate enabled */
    uint32_t rot_attempted_mask;   /* bitmask: bit i = factory i already attempted */

    /* Rotation retry with backoff (reset on first attempt to avoid aliasing) */
    uint8_t  rot_retry_count[8];        /* per-factory failure count (indexed by factory_id % 8) */
    uint32_t rot_last_attempt_block[8]; /* block height of last failed attempt */
    uint32_t rot_max_retries;           /* 0 = default (3); after N failures, broadcast dist TX */
    uint32_t rot_retry_base_delay;      /* 0 = default (10 blocks); doubles per retry */

    /* JIT Channel Fallback (Gap #2) */
    void *jit_channels;            /* jit_channel_t* array or NULL — avoids header dependency */
    size_t n_jit_channels;
    int jit_enabled;               /* 1 = JIT enabled (default), 0 = --no-jit */
    uint64_t jit_funding_sats;     /* per-client JIT funding amount */

    /* Factory arity (Upgrade 2) */
    int leaf_arity;                /* FACTORY_ARITY_1 or FACTORY_ARITY_2 */

    /* Interactive CLI in daemon loop */
    int cli_enabled;               /* 1 = stdin commands (pay/status/rotate/close) */

    /* Configurable confirmation timeout */
    int confirm_timeout_secs;      /* 0 = use default (3600 regtest, 7200 non-regtest) */

    /* Fee policy: configurable per-LSP operator strategy.
       Zero-fee (default): routing_fee_ppm=0, lsp_balance_pct=50
       Revenue (profitable): routing_fee_ppm=1000, lsp_balance_pct=60 (example) */
    uint64_t routing_fee_ppm;      /* routing fee in parts-per-million (0 = free) */
    uint16_t lsp_balance_pct;      /* LSP's share of channel capacity (0-100, default 50) */

    /* Placement + Economics */
    placement_mode_t placement_mode;   /* CLI: --placement-mode */
    economic_mode_t  economic_mode;    /* CLI: --economic-mode */
    uint16_t default_profit_bps;       /* CLI: --default-profit-bps */

    /* Funding reserve tracking (Phase 6) */
    uint64_t available_balance_sats;     /* wallet balance */
    uint64_t locked_in_factories_sats;   /* capital in active factories */
    uint64_t reserved_for_fees_sats;     /* fee reserve */

    /* Profit settlement (Phase 7) */
    uint64_t accumulated_fees_sats;       /* total routing fees since last settlement */
    uint32_t last_settlement_block;       /* block height of last settlement */
    uint32_t settlement_interval_blocks;  /* blocks between settlements (default: 144) */
} lsp_channel_mgr_t;

/* Initialize channels from factory leaf outputs.
   Must be called after factory creation succeeds.
   lsp_seckey32: LSP's secret key (used to derive channel basepoints).
   Returns 1 on success. */
int lsp_channels_init(lsp_channel_mgr_t *mgr,
                       secp256k1_context *ctx,
                       const factory_t *factory,
                       const unsigned char *lsp_seckey32,
                       size_t n_clients);

/* Initialize channels from DB (recovery after restart).
   Same as lsp_channels_init EXCEPT: loads basepoints and channel state
   from DB instead of generating fresh ones. Sets entry->ready = 1.
   db: persist_t* passed as void* to avoid header dependency.
   Returns 1 on success. */
int lsp_channels_init_from_db(lsp_channel_mgr_t *mgr,
                               secp256k1_context *ctx,
                               const factory_t *factory,
                               const unsigned char *lsp_seckey32,
                               size_t n_clients,
                               void *db);

/* Exchange MSG_CHANNEL_BASEPOINTS with all clients.
   Must be called after lsp_channels_init() and before lsp_channels_send_ready().
   Sends LSP's basepoint pubkeys and receives client's basepoint pubkeys.
   Returns 1 on success. */
int lsp_channels_exchange_basepoints(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Send CHANNEL_READY to all clients. Returns 1 on success. */
int lsp_channels_send_ready(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Handle an incoming channel message from a client.
   Dispatches based on msg_type. Returns 1 on success, 0 on error. */
int lsp_channels_handle_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                              size_t client_idx, const wire_msg_t *msg);

/* Get a channel entry by client index. */
lsp_channel_entry_t *lsp_channels_get(lsp_channel_mgr_t *mgr, size_t client_idx);

/* Build close outputs reflecting current channel balances.
   outputs: caller-allocated array of at least (n_channels + 1) entries.
   Returns number of outputs written. Output 0 = LSP (sum of local_amounts - close_fee),
   Outputs 1..N = clients (each remote_amount). */
size_t lsp_channels_build_close_outputs(const lsp_channel_mgr_t *mgr,
                                         const factory_t *factory,
                                         tx_output_t *outputs,
                                         uint64_t close_fee);

/* Run a select()-based event loop handling channel messages.
   Processes messages until expected_msgs messages have been handled.
   Returns 1 on success, 0 on error. */
int lsp_channels_run_event_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t expected_msgs);

/* Run a daemon event loop handling channel messages until shutdown.
   Loops on select() with 5-second timeout checking *shutdown_flag.
   Returns 1 on clean shutdown. */
int lsp_channels_run_daemon_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   volatile sig_atomic_t *shutdown_flag);

/* Handle a single CLI command line (extracted for testability).
   Returns 1 if command was recognized, 0 otherwise. */
int lsp_channels_handle_cli_line(lsp_channel_mgr_t *mgr, void *lsp_ptr,
                                  const char *line,
                                  volatile sig_atomic_t *shutdown_flag);

/* Settle accumulated routing fee profits to clients per their profit_share_bps.
   Shifts balance from LSP-local to client-remote via channel_update().
   Returns number of channels settled (0 if nothing to settle). */
int lsp_channels_settle_profits(lsp_channel_mgr_t *mgr, const factory_t *factory);

/* Calculate unsettled profit share for a client (for cooperative close). */
uint64_t lsp_channels_unsettled_share(const lsp_channel_mgr_t *mgr,
                                       const factory_t *factory,
                                       size_t client_idx);

/* --- Continuous Ladder Rotation (Gap #3) --- */

/* Perform a full factory rotation: PTLC turnover → cooperative close →
   fund new factory → create new factory → reinitialize channels.
   All parameters come from mgr->rot_* fields.
   Returns 1 on success, 0 on failure. */
int lsp_channels_rotate_factory(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* --- Reconnection (Phase 16) --- */

/* Handle a reconnecting client on a new fd.
   Reads MSG_RECONNECT, matches pubkey to client slot, re-exchanges nonces,
   sends MSG_RECONNECT_ACK. Returns 1 on success. */
int lsp_channels_handle_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, int new_fd);

/* --- Bridge support (Phase 14) --- */

/* Set bridge fd in channel manager. */
void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd);

/* Register an invoice (payment_hash → dest_client) for bridge inbound routing. */
int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    size_t dest_client, uint64_t amount_msat);

/* Look up invoice by payment_hash. Returns dest_client index, or -1. */
int lsp_channels_lookup_invoice(lsp_channel_mgr_t *mgr,
                                  const unsigned char *payment_hash32,
                                  size_t *dest_client_out);

/* Handle a MSG_BRIDGE_* message from the bridge daemon.
   Dispatches based on msg_type. Returns 1 on success. */
int lsp_channels_handle_bridge_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                     const wire_msg_t *msg);

/* Track that an HTLC came from the bridge (for back-propagation). */
void lsp_channels_track_bridge_origin(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t bridge_htlc_id);

/* Check bridge HTLC timeouts: fail back any HTLC whose cltv_expiry is
   approaching (within FACTORY_CLTV_DELTA blocks of current height).
   Fails the HTLC on both the bridge and the destination channel.
   Called from the daemon loop timeout path. */
void lsp_channels_check_bridge_htlc_timeouts(lsp_channel_mgr_t *mgr,
                                               lsp_t *lsp,
                                               uint32_t current_height);

/* Check if an HTLC originated from the bridge. Returns bridge_htlc_id, 0 if not. */
uint64_t lsp_channels_get_bridge_origin(lsp_channel_mgr_t *mgr,
                                          const unsigned char *payment_hash32);

/* --- Demo mode (Phase 17) --- */

/* Print a formatted balance table for all channels. */
void lsp_channels_print_balances(const lsp_channel_mgr_t *mgr);

/* Initiate a payment from one client to another via the LSP.
   Sends MSG_CREATE_INVOICE to receiver, waits for invoice, adds HTLC on
   sender's channel, forwards to receiver, waits for fulfill, back-propagates.
   Returns 1 on success. */
int lsp_channels_initiate_payment(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                    size_t from_client, size_t to_client,
                                    uint64_t amount_sats);

/* Run a scripted demo sequence of payments after channels are ready.
   Returns 1 on success. */
int lsp_channels_run_demo_sequence(lsp_channel_mgr_t *mgr, lsp_t *lsp);

#endif /* SUPERSCALAR_LSP_CHANNELS_H */
