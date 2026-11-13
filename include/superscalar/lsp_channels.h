#ifndef SUPERSCALAR_LSP_CHANNELS_H
#define SUPERSCALAR_LSP_CHANNELS_H

#include "channel.h"
#include "htlc_inbound.h"
#include "lsp.h"
#include "wire.h"
#include "watchtower.h"
#include <signal.h>
#include <time.h>

/* Safety margin for HTLC forwarding: outgoing cltv_expiry is reduced by this
   delta so the LSP has time to claim on-chain if the factory needs a unilateral
   close before the upstream HTLC expires.
   Default 40 is ONLY used as a fallback when the factory counter isn't available.
   The correct value is computed from the DW tree depth by
   lsp_compute_factory_cltv_delta(). */
#define FACTORY_CLTV_DELTA_DEFAULT 40

/* Compute the minimum CLTV delta needed for safe HTLC forwarding through
   a factory.  This is the worst-case DW tree unwind time: each layer must
   be broadcast and wait for step_blocks confirmations.
   Formula: sum(layers: step_blocks * (max_states - 1))
            + n_layers * 6 (confirmation buffer per layer)
            + 36 (flat safety margin ~6 hours) */
uint32_t lsp_compute_factory_cltv_delta(const void *factory_ptr);

/* Validate and adjust cltv_expiry for HTLC forwarding through a factory channel.
   cltv_expiry is an absolute block height, so it is measured against the
   chain tip: returns 1 only if cltv_expiry > current_height + cltv_delta.
   Pass current_height = 0 when the tip is not known; the HTLC must then at
   least exceed cltv_delta itself.
   Rejects HTLCs whose cltv_expiry >= factory_cltv_timeout (funds would be
   trapped past factory expiry). Pass 0 for factory_cltv_timeout to skip check.
   cltv_delta is the minimum safety margin computed by lsp_compute_factory_cltv_delta.
   On success, *fwd_cltv_out = cltv_expiry - cltv_delta. */
int lsp_validate_cltv_for_forward(uint32_t cltv_expiry, uint32_t *fwd_cltv_out,
                                   uint32_t factory_cltv_timeout,
                                   uint32_t cltv_delta,
                                   uint32_t current_height);

/* --- Outbound payments through the bridge --- */

/* Outcome of checking an invoice against the HTLC a client offered for it. */
typedef enum {
    BRIDGE_PAY_OK = 0,
    BRIDGE_PAY_BAD_INVOICE,          /* does not decode */
    BRIDGE_PAY_WRONG_NETWORK,        /* invoice is for another chain */
    BRIDGE_PAY_HASH_MISMATCH,        /* invoice hash != HTLC hash */
    BRIDGE_PAY_NO_AMOUNT,            /* amountless invoices are refused */
    BRIDGE_PAY_AMOUNT_EXCEEDS_HTLC,  /* invoice asks for more than the HTLC funds */
    BRIDGE_PAY_EXPIRED,
    BRIDGE_PAY_NO_CHAIN_HEIGHT,      /* tip unknown: deadline cannot be judged */
    BRIDGE_PAY_CLTV_OUT_OF_BOUNDS     /* HTLC expires too soon for the route, or past the factory */
} bridge_pay_check_t;

/* Short reason string for a check result (used as the HTLC failure reason). */
const char *lsp_bridge_pay_check_str(bridge_pay_check_t r);

/* 1 if a BOLT #11 network prefix ("bc", "tb", "tbs", "bcrt") belongs to the
   named chain ("mainnet", "testnet", "testnet4", "signet", "regtest"). */
int lsp_bridge_invoice_network_ok(const char *network, const char *invoice_hrp);

/* What is left of an offered HTLC for the outside payment once the LSP's
   routing fee (routing_fee_ppm, rounded up) is taken: the most that may be
   spent on the invoice and its routing fees together.  Returns 0 when the
   fee consumes the whole HTLC. */
uint64_t lsp_bridge_outbound_budget_msat(uint64_t htlc_amount_sats,
                                           uint64_t routing_fee_ppm);

/* Check an invoice a client asked the LSP to pay against the HTLC it offered.
   The invoice must decode, be for `network`, carry exactly the HTLC's payment
   hash, state an amount no greater than the HTLC amount minus the LSP's fee,
   and not be expired at `now` (unix seconds).
   On BRIDGE_PAY_OK the outputs (each optional) are filled:
     invoice_msat_out    the invoice amount
     budget_msat_out     lsp_bridge_outbound_budget_msat() for this HTLC
     min_final_cltv_out  the invoice's min_final_cltv_expiry */
bridge_pay_check_t lsp_bridge_check_outbound_invoice(
    secp256k1_context *ctx, const char *bolt11,
    const unsigned char *htlc_payment_hash32, uint64_t htlc_amount_sats,
    uint64_t routing_fee_ppm, const char *network, uint64_t now,
    uint64_t *invoice_msat_out, uint64_t *budget_msat_out,
    uint32_t *min_final_cltv_out);

/* How long the outside payment may stay locked up, given the HTLC the client
   offered for it.  The HTLC must expire later than
       current_height + min_final_cltv + forward_margin
   (the invoice's final-hop requirement plus the blocks the LSP keeps for
   itself to claim the client's HTLC after the outside payment settles) and
   before factory_cltv_timeout (0 = no limit).
   On success returns BRIDGE_PAY_OK and sets *max_delay_out to the largest
   total route delay, in blocks from the current tip, that still leaves
   forward_margin before the client's HTLC expires. */
bridge_pay_check_t lsp_bridge_outbound_max_delay(uint32_t htlc_cltv_expiry,
                                                  uint32_t current_height,
                                                  uint32_t min_final_cltv,
                                                  uint32_t forward_margin,
                                                  uint32_t factory_cltv_timeout,
                                                  uint32_t *max_delay_out);

/* Route delay allowed for operator-initiated pays, which have no client
   HTLC to bound them (Core Lightning's own default). */
#define LSP_BRIDGE_OPERATOR_MAX_DELAY 2016

/* Per-client channel entry managed by the LSP */
typedef struct {
    channel_t channel;          /* Poon-Dryja channel (LSP=local, client=remote) */
    uint32_t channel_id;        /* channel_id sent over wire (= client index) */
    int ready;                  /* 1 after CHANNEL_READY sent */
    /* Nonce refresh (lsp_channels_refresh_nonces): an unanswered one is
       retried, whatever the count, from nonce_refresh_retry_at on. */
    int nonce_refresh_pending;
    unsigned nonce_refresh_fails;
    time_t nonce_refresh_retry_at;
    time_t last_message_time;   /* epoch timestamp of last wire message */
    int offline_detected;        /* 1 if declared offline */
    unsigned char close_spk[34]; /* P2TR scriptPubKey for client's close output */
    size_t close_spk_len;       /* 34 when populated, 0 if unset */
    uint64_t accumulated_fees_sats; /* routing fees earned on THIS channel */
    int exchange_in_progress;   /* the LSP is waiting for this client's reply:
                                   no other exchange may start on the channel */
} lsp_channel_entry_t;

/* Invoice registry entry for bridge inbound payments (Phase 14) */
#define MAX_INVOICE_REGISTRY 256

typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    size_t dest_client;
    uint64_t amount_msat;
    uint64_t bridge_htlc_id;     /* correlation ID for bridge response */
    int active;
} invoice_entry_t;

/* HTLC origin tracking for bridge back-propagation (Phase 14) */
#define MAX_HTLC_ORIGINS 256

typedef struct {
    unsigned char payment_hash[32];
    uint64_t bridge_htlc_id;     /* 0 = intra-factory, >0 = from bridge */
    uint64_t request_id;         /* outbound pay correlation (Phase 17) */
    size_t sender_idx;           /* originating client index (Phase 17) */
    uint64_t sender_htlc_id;    /* HTLC id on sender's channel (Phase 17) */
    uint32_t cltv_expiry;       /* timelock for bridge HTLC timeout */
    /* Which HTLC on the Lightning node this is ("<channel>:<id>" as the
       plugin reports it; "" if unknown).  The node offers an unresolved
       HTLC again after it restarts; this tells that apart from a second
       HTLC for the same hash. */
    #define BRIDGE_UPSTREAM_ID_MAX 64
    char upstream_id[BRIDGE_UPSTREAM_ID_MAX];
    int expiry_warned;          /* outbound: unresolved-near-expiry logged */
    int fail_pending;           /* inbound: failed towards the client, the
                                   bridge has still to be told (saved with
                                   the origin) */
    int64_t db_id;              /* its row in the database, 0 if not saved */
    int active;
} htlc_origin_t;

/* Reorg detection (R1).  See lsp_reorg_poll() below. */
typedef enum {
    LSP_REORG_INCONCLUSIVE      = -1, /* a read the check needed failed: the
                                         stored tip is kept, retried next poll */
    LSP_REORG_NONE              = 0,
    LSP_REORG_HEIGHT_REGRESSION = 1,  /* tip went backward */
    LSP_REORG_SAME_HEIGHT       = 2,  /* same height, different tip hash */
    LSP_REORG_FORWARD           = 3,  /* tip advanced, the block at the stored
                                         height is no longer the stored one */
    LSP_REORG_UNSEEN_BLOCK      = 4,  /* stored tip still canonical, but a block
                                         built on it after it was stored has
                                         been disconnected */
} lsp_reorg_kind_t;

#define LSP_REORG_SEEN_MAX 32

/* A detector's stored tip.  height/hash always come from one snapshot
   (regtest_get_tip).  seen[] holds disconnected chain tips that already sat
   above the stored tip when it was stored, so they are not reported again
   as UNSEEN_BLOCK on a later poll (ring buffer).  Zero-initialise. */
typedef struct {
    int32_t height;                    /* 0 = nothing stored yet */
    char    hash[65];
    char    seen[LSP_REORG_SEEN_MAX][65];
    size_t  n_seen;
    size_t  seen_next;
    /* Set by lsp_reorg_poll(): for a reported reorg, the highest height the
       old and new chains still share (blocks above it were disconnected);
       -1 when the poll reported none. */
    int32_t fork_height;
} lsp_reorg_state_t;

/* Chain data read after the current tip, for lsp_reorg_classify().
   NULL means "not read, or the read failed". */
typedef struct {
    const char *hash_at_last;          /* active chain's hash at st->height */
    const char *hash_at_next;          /* ... at st->height + 1 */
    const regtest_chain_tip_t *tips;   /* getchaintips */
    size_t n_tips;
} lsp_reorg_view_t;
/* An inbound bridge HTLC the client has fulfilled: kept so the fulfil can
   be given again if the Lightning node offers the same HTLC once more
   (it never received, or lost, the first answer). */
typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    char upstream_id[BRIDGE_UPSTREAM_ID_MAX];
    uint64_t bridge_htlc_id;
    int undelivered;    /* the bridge has not confirmed this fulfil yet */
    int unresolved;     /* the Lightning node could not take it: kept, not
                           repeated until the next start */
} bridge_fulfilled_t;

typedef struct {
    lsp_channel_entry_t *entries;
    size_t n_channels;
    size_t entries_cap;
    secp256k1_context *ctx;

    /* Bridge support (Phase 14) */
    int bridge_fd;               /* -1 if no bridge connected */
    invoice_entry_t *invoices;
    size_t n_invoices;
    size_t invoices_cap;
    htlc_origin_t *htlc_origins;
    size_t n_htlc_origins;
    size_t htlc_origins_cap;
    uint64_t next_request_id;    /* for outbound pay correlation */
    char network[16];            /* chain name; invoices for any other chain
                                    are refused.  Set after init. */
    /* Payment hashes of the most recent outside payments that completed
       (ring buffer): a client is not charged a second time for one. */
    #define LSP_BRIDGE_FULFILLED_MAX 32
    bridge_fulfilled_t bridge_fulfilled[LSP_BRIDGE_FULFILLED_MAX];
    size_t n_bridge_fulfilled;
    size_t bridge_fulfilled_next;
    /* Bridge messages that arrived for a channel with an exchange in
       progress; handled once the channel is free. */
    #define LSP_BRIDGE_DEFERRED_MAX 16
    struct { uint8_t msg_type; void *json; } bridge_deferred[LSP_BRIDGE_DEFERRED_MAX];
    size_t n_bridge_deferred;
    #define LSP_OUTBOUND_PAID_MAX 64
    unsigned char outbound_paid[LSP_OUTBOUND_PAID_MAX][32];
    size_t n_outbound_paid;
    size_t outbound_paid_next;

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
    uint64_t rot_tree_fee_rate;     /* --tree-fee-rate: the agreed rate of rotated factories */
    unsigned char rot_fund_spk[34];
    size_t rot_fund_spk_len;
    char rot_fund_addr[128];
    char rot_mine_addr[128];
    uint16_t rot_step_blocks;
    uint32_t rot_states_per_layer;
    int rot_is_regtest;
    uint64_t rot_funding_sats;
    int rot_leaf_arity;            /* FACTORY_ARITY_1 or FACTORY_ARITY_2 */
    int rot_enabled;               /* 1 = rotation may run (--enable-rotation-experimental);
                                      default 0: every rotation path is refused */
    uint32_t force_exit_height;    /* the LSP pushes every member's channel on
                                      chain from this height (0 = never): the
                                      end date minus a forced exit and margin */
    int rot_auto_rotate;           /* 1 = rotate automatically when a factory turns
                                      DYING; only ever set together with rot_enabled */
    uint32_t rot_attempted_mask;   /* bitmask: bit i = factory i already attempted */

    /* Rotation retry with backoff (reset on first attempt to avoid aliasing) */
    uint8_t  rot_retry_count[8];        /* per-factory failure count (indexed by factory_id % 8) */
    uint32_t rot_last_attempt_block[8]; /* block height of last failed attempt */
    uint32_t rot_max_retries;           /* 0 = default (3); after N failures, broadcast dist TX */
    uint32_t rot_retry_base_delay;      /* 0 = default (10 blocks); doubles per retry */
    uint8_t  rot_postponed[8];          /* 1 = last attempt postponed on fees (no retry
                                           used): tried again on the next block;
                                           2 = still postponed when the factory expired */

    /* JIT Channel Fallback (Gap #2) */
    void *jit_channels;            /* jit_channel_t* array or NULL — avoids header dependency */
    size_t n_jit_channels;
    size_t jit_channels_cap;
    int jit_enabled;               /* 1 = JIT opens allowed (experimental opt-in); default 0 */

    /* Client messages read while a blocking exchange was waiting for a
       different message.  Handled, in arrival order, by
       lsp_channels_drain_deferred(). */
    struct lsp_deferred_msg *deferred_msgs;
    size_t n_deferred_msgs;
    size_t deferred_msgs_cap;
    uint64_t jit_funding_sats;     /* per-client JIT funding amount */

    /* Factory arity (Upgrade 2) */
    int leaf_arity;                /* FACTORY_ARITY_1 or FACTORY_ARITY_2 */

    /* Interactive CLI in daemon loop */
    int cli_enabled;               /* 1 = stdin commands (pay/status/rotate/close) */
    int test_bad_settlement;       /* 1 = halve settlement amounts (cheat test) */

    /* Configurable confirmation timeout */
    int confirm_timeout_secs;      /* 0 = use default (3600 regtest, 7200 non-regtest) */

    /* Fee policy: configurable per-LSP operator strategy.
       Default: routing_fee_ppm=0, lsp_balance_pct=100 (LSP retains all capacity)
       Revenue (profitable): routing_fee_ppm=1000 (example) */
    uint64_t routing_fee_ppm;      /* routing fee in parts-per-million (0 = free) */
    uint16_t lsp_balance_pct;      /* LSP's share of channel capacity (0-100, default 100) */

    /* Placement + Economics */
    placement_mode_t placement_mode;   /* CLI: --placement-mode */
    economic_mode_t  economic_mode;    /* CLI: --economic-mode */
    uint16_t default_profit_bps;       /* CLI: --default-profit-bps */

    /* Auto-rebalance (Signet/Testnet4 deployment) */
    int auto_rebalance;             /* 1 = enabled, check on periodic timeout */
    uint32_t last_rebalance_block;  /* block height of last auto-rebalance */
    uint16_t rebalance_threshold_pct; /* imbalance threshold 0-100 (default 80) */

    /* Daemon heartbeat */
    int heartbeat_interval;             /* seconds between status lines (0 = disabled) */
    time_t last_heartbeat;              /* timestamp of last heartbeat output */
    time_t daemon_start_time;           /* timestamp when daemon loop started */

    /* Reorg detection (R1): the heartbeat's own stored tip. */
    lsp_reorg_state_t hb_reorg;

    /* R5: set by lsp_channels_revalidate_funding() when the funding TX it
       checked was not confirmed (pending in the mempool, stale, or gone).
       While set, the daemon loop re-runs revalidation on every new block. */
    int funding_anchor_unconfirmed;

    /* The block that confirmed the factory funding TX
       (funding_anchor_txid, display hex).  Recorded from gettxout while the
       funding output is unspent, persisted in funding_anchors (v43), and
       used when the output has been spent (factory closed, or its tree on
       chain): the funding TX is still confirmed as long as this block is in
       the active chain.  Lets revalidation work without -txindex and at any
       depth. */
    char    funding_anchor_txid[65];
    int32_t funding_anchor_height;
    char    funding_anchor_block[65];

    /* Funding reserve tracking (Phase 6) */
    uint64_t available_balance_sats;     /* wallet balance */
    uint64_t locked_in_factories_sats;   /* capital in active factories */
    uint64_t reserved_for_fees_sats;     /* fee reserve */

    /* Profit settlement (Phase 7) */
    uint64_t accumulated_fees_sats;       /* total routing fees since last settlement */
    uint32_t last_settlement_block;       /* block height of last settlement */
    uint32_t settlement_interval_blocks;  /* blocks between settlements (default: 144) */

    /* Async rotation coordination (--async-rotation flag) */
    void *readiness;  /* readiness_tracker_t* or NULL */
    void *notify;     /* notify_t* or NULL */

    /* Chain backend and wallet source for mode-agnostic funding/broadcast */
    void *chain_be;   /* chain_backend_t* — regtest or bip158 */
    void *wallet_src; /* wallet_source_t* — rpc or hd */

    /* Admin RPC (JSON-RPC 2.0 Unix socket — serviced in daemon loop) */
    void *admin_rpc;  /* admin_rpc_t* or NULL */

    /* Sweeper: auto-sweep timelocked outputs after force-close */
    void *sweeper;    /* sweeper_t* or NULL — avoids header dependency */

    /* Native inbound HTLC tracking (fake-SCID / BOLT #4 path) */
    htlc_inbound_table_t htlc_inbound;

    /* Deferred reconnection queue: connections accepted during ceremonies
       are queued here and processed when the daemon loop resumes.
       Prevents reentrancy while keeping the listen socket responsive. */
    #define PENDING_RECONNECT_MAX 8
    struct {
        int fd;
        uint8_t msg_type;     /* MSG_RECONNECT, MSG_BRIDGE_HELLO, MSG_HELLO */
        void *json;           /* cJSON* — owned by queue entry, freed on drain */
        int valid;
    } pending_reconnects[8];
    size_t n_pending_reconnects;

    /* P2TR scriptPubKey for the LSP's cooperative-close output.
       Symmetric with per-entry close_spk (each client's own P2TR). Derived
       from factory->pubkeys[0] at init so that the LSP alone can spend its
       recovered share (L-stock + sum(local_amounts) + accumulated_fees)
       with its own seckey, instead of the N-of-N factory funding SPK. */
    unsigned char lsp_close_spk[34];
    size_t lsp_close_spk_len;       /* 34 when populated, 0 if unset */
} lsp_channel_mgr_t;

/* Initialize channels from factory leaf outputs.
   Must be called after factory creation succeeds.
   lsp_seckey32: LSP's secret key (used to derive channel basepoints).
   Returns 1 on success. */
void lsp_channels_cleanup(lsp_channel_mgr_t *mgr);

/* --- Messages held back during a blocking exchange --- */

typedef struct lsp_deferred_msg {
    size_t client_idx;
    wire_msg_t msg;
} lsp_deferred_msg_t;

/* Most messages that may be held at once. */
#define LSP_DEFERRED_MSGS_MAX 256

/* Hold a message from client_idx for later handling.  On success (1) the
   queue owns msg->json and msg->json is set to NULL.  Returns 0, leaving msg
   untouched, if the queue is full or memory is exhausted. */
int lsp_channels_defer_msg(lsp_channel_mgr_t *mgr, size_t client_idx,
                            wire_msg_t *msg);

/* Number of messages currently held. */
size_t lsp_channels_deferred_count(const lsp_channel_mgr_t *mgr);

/* Pass every held message to lsp_channels_handle_msg(), oldest first, and
   empty the queue.  A message whose client has disconnected is dropped.
   Returns the number of messages handled. */
int lsp_channels_drain_deferred(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Free the queue and everything in it without handling. */
void lsp_channels_free_deferred(lsp_channel_mgr_t *mgr);

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

/* Re-register every PS leaf chain entry and PS sub-factory chain entry
   with the watchtower after recovery (PR-B / v22).

   persist_load_factory restores in-memory factory state plus, for the
   LATEST chain entry of each PS leaf and sub-factory, the wire-signed
   poison TX bytes (now living in node->poison_signed_tx /
   sub->poison_signed_tx with poison_is_signed=1).  This helper walks
   every restored leaf + sub-factory, looks up the prior chain entry's
   txid (the "stale" state to watch for), and calls
   watchtower_watch_factory_node_with_channels /
   watchtower_watch_subfactory_node so a post-restart breach still
   triggers the response_tx + poison_tx broadcast.

   Without this rehydrate step, the wire-ceremony work from PRs
   #136-#138 is silently undone by the first LSP crash — watchtower
   has no entries beyond DW commitments.

   Pre-condition: mgr->watchtower set, mgr->persist set,
   factory_recovery already loaded chains into the in-memory factory.
   Returns 1 on success (even if 0 entries to register), 0 on bad args. */
int lsp_channels_rehydrate_watchtower_from_chains(lsp_channel_mgr_t *mgr);

/* Exchange MSG_CHANNEL_BASEPOINTS with all clients.
   Must be called after lsp_channels_init() and before lsp_channels_send_ready().
   Sends LSP's basepoint pubkeys and receives client's basepoint pubkeys.
   Returns 1 on success. */
int lsp_channels_exchange_basepoints(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Send CHANNEL_READY to all clients. Returns 1 on success. */
int lsp_channels_send_ready(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Rotation: carry a client's balance from its old channel into the freshly
   initialised channel ch of the new factory.  The channel keeps the funding
   amount of its leaf output and its fee rate, exactly as at channel open, so
   both sides build the same commitment; the client gets client_balance and
   the LSP the rest of the usable amount.  Returns 0 and leaves the default
   split if client_balance does not fit in the new channel. */
int lsp_channel_carry_client_balance(channel_t *ch, uint64_t client_balance);

/* Handle an incoming channel message from a client.
   Dispatches based on msg_type. Returns 1 on success, 0 on error. */
int lsp_channels_handle_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                              size_t client_idx, const wire_msg_t *msg);

/* Get a channel entry by client index. */
lsp_channel_entry_t *lsp_channels_get(lsp_channel_mgr_t *mgr, size_t client_idx);

/* Build close outputs reflecting current channel balances.
   outputs: caller-allocated array of at least (n_channels + 1) entries.
   Returns number of outputs written. Output 0 = LSP (sum of local_amounts - close_fee),
   Outputs 1..N = clients (each remote_amount).
   close_spk/close_spk_len: if non-NULL, override SPK for ALL outputs
   (wallet-controlled address for UTXO recycling / rotation). If NULL/0,
   LSP output uses factory funding SPK and client outputs use per-client
   close addresses (entry->close_spk, derived from factory pubkey). */
size_t lsp_channels_build_close_outputs(const lsp_channel_mgr_t *mgr,
                                         const factory_t *factory,
                                         tx_output_t *outputs,
                                         uint64_t close_fee,
                                         const unsigned char *close_spk,
                                         size_t close_spk_len);

/* Run a select()-based event loop handling channel messages.
   Processes messages until expected_msgs messages have been handled.
   Returns 1 on success, 0 on error. */
int lsp_channels_run_event_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t expected_msgs);

/* Once every factory has expired, offer a JIT channel to each connected
   client that has none.  Does nothing unless opening JIT channels is enabled
   (mgr->jit_enabled).  Returns the number of opens attempted. */
int lsp_channels_jit_expiry_trigger(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Run a daemon event loop handling channel messages until shutdown.
   Loops on select() with 5-second timeout checking *shutdown_flag.
   Returns 1 on clean shutdown. */
/* Run one daemon loop iteration: accept connections, drain reconnect queue,
 * poll clients for 1 second. Returns immediately. */
int lsp_channels_run_daemon_loop_once(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      volatile int *shutdown_flag);

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

/* Settle accumulated per-channel fees via HTLC payment to each client.
   Unlike settle_profits (which modifies balances directly and desynchronizes
   state), this uses the standard HTLC add→commit→revoke→fulfill flow so
   the settlement is reflected in a signed commitment TX.  If the client
   force-closes after settlement, their commitment includes the settled fees. */
int lsp_channels_settle_via_payment(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      const factory_t *factory);

/* Calculate unsettled profit share for a client (for cooperative close). */
uint64_t lsp_channels_unsettled_share(const lsp_channel_mgr_t *mgr,
                                       const factory_t *factory,
                                       size_t client_idx);

/* --- Leaf-Level Fund Reallocation (Upgrade 3) --- */

/* Why the LSP offers no operation that reallocates a leaf: a reallocation
   replaces the leaf transaction, the clients' channels cannot yet be moved
   to the new leaf output, and so clients refuse to co-sign one. */
#define LSP_LEAF_REALLOC_UNAVAILABLE \
    "not available until channels can follow a reallocated leaf"

/* Run the leaf reallocation ceremony: propose new output amounts for a leaf
   to its clients and collect a MuSig2 signature for the new leaf state.
   amounts[] must sum to the current leaf output total; each amount >= 546
   sats.  Clients currently refuse every proposal (see
   LSP_LEAF_REALLOC_UNAVAILABLE), so this fails; nothing that serves users
   calls it.  When the ceremony fails for any reason the LSP's leaf is put
   back exactly as it was before the call.
   Returns 1 on success, 0 on failure. */
int lsp_realloc_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                      int leaf_side, const uint64_t *amounts, size_t n_amounts);

/* --- Tier B state-advance ceremony (Gap B + F) ---

   Driven when factory_advance_leaf_unsigned() returns -1 (per-leaf DW
   counter exhausted, root layer advanced, every non-PS-leaf node's
   unsigned TX rebuilt and waiting to be re-signed).  Runs an N-of-N
   MuSig ceremony bundled across all affected nodes — see
   docs/rotation-ceremony.md.

   Preconditions:
     - factory_advance_leaf_unsigned(f, trigger_leaf_side) returned -1
       (caller must NOT call advance again before invoking us)
     - All clients are connected on lsp->client_fds[]
   Postconditions:
     - On success: every affected node has signed_tx populated, the
       watchtower has a fresh poison TX for each leaf's NEW state
       (overlap window — old entries remain), persist has the new DW
       counter.  All clients receive PATH_SIGN_DONE.
     - On failure: returns 0, on-chain factory is unchanged, ceremony
       can be retried.

   Returns 1 on success, 0 on any failure. */
int lsp_run_state_advance(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                            int trigger_leaf_side);

/* F1: Persist chain[0] for every PS leaf and PS sub-factory node in the
   factory.  Idempotent (uses INSERT OR REPLACE under the hood).  Called
   from two sites:
     - Factory creation (tools/superscalar_lsp.c) — initial chain[0] save.
     - After a root-driven Tier B ceremony (lsp_run_state_advance with
       trigger_leaf_side == -1) — saves the new epoch's chain[0].
   `persist` is persist_t* (typed as void* to avoid header dependency).
   Returns number of rows persisted (>=0); 0 may indicate no PS nodes,
   not an error. */
int lsp_persist_ps_chain0_all(void *persist, factory_t *f);

/* R5 (mainnet pre-flight): revalidate each factory channel's funding
   against the active chain.  What is checked is the factory's funding TX
   (lsp->factory.funding_txid), not ch->funding_txid: for a factory channel
   that is the off-chain leaf state TX, which is normally never broadcast.
   The funding is checked through its output (gettxout) and its recorded
   confirming block, so neither -txindex nor a scan depth limits it.
   Sets ch->funding_pending_reorg=1 when the funding TX is neither confirmed
   nor in the mempool, or has sat in the mempool past the network threshold;
   clears it back to 0 when it has >= 1 confirmation again.  Sets
   mgr->funding_anchor_unconfirmed when the funding TX was not confirmed.
   With lsp == NULL (or no factory funding set) ch->funding_txid itself is
   checked.
   LN-aligned: channel is FROZEN (HTLCs + commitment builds refused), not
   abandoned — re-confirmation re-enables it.
   When `lsp` is non-NULL, sends MSG_FUNDING_REORG to lsp->client_fds[slot]
   on every flip so the client mirrors the freeze state.
   Returns the number of channels whose flag state changed. */
int lsp_channels_revalidate_funding(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* 1 when the daemon loop should call lsp_channels_revalidate_funding() on
   the next new block: some channel is frozen, or the last revalidation saw
   the funding TX unconfirmed. */
int lsp_channels_funding_recheck_due(const lsp_channel_mgr_t *mgr);

/* Record the factory funding TX's confirming block (see
   mgr->funding_anchor_*) if not known yet: from memory, then the DB, then
   gettxout.  The daemon loop calls it on each new block until it is known.
   Returns 1 when the anchor is known after the call. */
int lsp_channels_note_funding_anchor(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Test hook: when set, the anchor recording calls it after the gettxout
   read and before it looks up the block at the computed height, so a test
   can change the chain inside that window.  NULL outside tests. */
extern void (*lsp_channels_test_anchor_hook)(void *arg);
extern void *lsp_channels_test_anchor_hook_arg;

/* Reorg detection (R1) classification.  Pure: no I/O.
   st is the stored tip (from the previous poll), (cur_height, cur_hash) the
   tip now, from one regtest_get_tip() snapshot.  view carries what was read
   after cur (see lsp_reorg_needs_hash_at_last / lsp_reorg_needs_tips).
   - First observation (st->height == 0): NONE.
   - cur_height < st->height: HEIGHT_REGRESSION.
   - same height, different hash: SAME_HEIGHT.
   - cur_height > st->height: the block at st->height must still be st->hash;
     if it is not, and st->hash is not the active block at st->height + 1
     either, FORWARD_REORG.  (If it is the block at +1, the stored pair was
     read across a block arrival; nothing was replaced and the check falls
     through.  A block hash commits to its ancestry, so one hash cannot sit
     at two heights.)
   - Tip changed but none of the above: a getchaintips entry with status
     "valid-fork" or "invalid", forking at or above st->height and reaching
     above it, that is not in st->seen, is a block built on the stored tip
     after it was stored and since disconnected: UNSEEN_BLOCK.  This catches
     reorgs entirely between two polls, which the hash comparison cannot see.
     "invalid" also covers blocks that failed validation and were never
     connected; reporting one costs a single extra run of the reorg handler.
   - Any needed read missing from view: INCONCLUSIVE (also for a failed tip
     read, cur_height <= 0). */
lsp_reorg_kind_t lsp_reorg_classify(const lsp_reorg_state_t *st,
                                    int32_t cur_height, const char *cur_hash,
                                    const lsp_reorg_view_t *view);

/* Which reads lsp_reorg_classify() needs for this transition. */
int lsp_reorg_needs_hash_at_last(const lsp_reorg_state_t *st, int32_t cur_height);
int lsp_reorg_needs_tips(const lsp_reorg_state_t *st, int32_t cur_height,
                         const char *cur_hash);

/* Store (cur_height, cur_hash) as the new tip, and remember the disconnected
   tips in `tips` that already sit above it (so a later poll does not report
   them as UNSEEN_BLOCK).  Call only after a conclusive classification. */
void lsp_reorg_state_advance(lsp_reorg_state_t *st, int32_t cur_height,
                             const char *cur_hash,
                             const regtest_chain_tip_t *tips, size_t n_tips);

/* Fork height of a reorg just classified as `kind` against `prev` (the
   stored tip before the poll).  Exact when getchaintips lists the branch
   holding prev->hash (fork = its height - branchlen) or, for UNSEEN_BLOCK,
   the reported branch; otherwise one below the lower of the two tips.
   That fallback assumes the reorg went at most one block below the lower
   tip: for a deeper reorg whose old branch getchaintips no longer lists
   (e.g. bitcoind restarted since), the result is above the real fork.
   -1 for NONE / INCONCLUSIVE.  Pure. */
int32_t lsp_reorg_fork_height(const lsp_reorg_state_t *prev,
                              lsp_reorg_kind_t kind, int32_t cur_height,
                              const lsp_reorg_view_t *view);

/* Reorg handler step for PS sub-factory chains: roll back only entries
   observed confirmed above fork_height.  Nothing records that height
   (ps_chain_confirmed_height) today, so this resets nothing; it is the hook
   for when force-close tracking stamps the height at which a chain entry
   confirmed.  Chains never seen on chain (the normal, off-chain case) are
   left as they are.  Returns the count. */
int lsp_reorg_rollback_subfactory_chains(factory_t *f, int32_t fork_height);

/* A detector's stored tip in the DB (v43 reorg_tips), so the first poll
   after a restart compares against the tip seen before the restart and
   reports a reorg that happened while the LSP was down.  `persist` is a
   persist_t*.  Load fills height and hash (seen[] starts empty) and
   returns 1 when a row exists; save returns 1 on success. */
int lsp_reorg_state_load(void *persist, const char *detector,
                         lsp_reorg_state_t *st);
int lsp_reorg_state_save(void *persist, const char *detector,
                         const lsp_reorg_state_t *st);

/* One detector poll: tip snapshot, the reads above, classify, and advance
   *st unless the result is INCONCLUSIVE.  Writes the tip read to
   *cur_height / cur_hash (-1 / "" when the tip read failed).  Used by the
   daemon loop and the heartbeat, each with its own state. */
lsp_reorg_kind_t lsp_reorg_poll(regtest_t *rt, lsp_reorg_state_t *st,
                                int32_t *cur_height, char cur_hash[65]);

/* "HEIGHT_REGRESSION" / "SAME_HEIGHT" / "FORWARD_REORG" /
   "UNSEEN_BLOCK_REORG" / "INCONCLUSIVE" / "" (NONE). */
const char *lsp_reorg_kind_str(lsp_reorg_kind_t kind);

/* PS k² sub-factory chain extension ceremony driver (Gap E followup
   Phase 2b, t/1242).  Drives the multi-party MuSig signing of a new
   sub-factory state when the LSP "sells liquidity from sales-stock":
   the client at `channel_idx_in_sub` within sub-factory
   `sub_idx_in_leaf` of `leaf_side` gains `delta_sats` of inbound
   capacity by moving that amount out of the sub-factory's sales-stock.
   N-of-N MuSig over the sub-factory's signers (LSP + k clients in this
   sub-factory only).  See docs/ps-subfactories.md and the canonical
   t/1242 spec passage on "buying liquidity via the pseudo-Spilman
   factory".

   Returns 1 on success (chain extended, all participants confirmed
   via DONE), 0 on any failure. */
int lsp_subfactory_chain_advance(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   int leaf_side, int sub_idx_in_leaf,
                                   int channel_idx_in_sub,
                                   uint64_t delta_sats);

/* Buy inbound liquidity from L-stock for a client.  This needs a leaf
   reallocation, so it is refused: the call reports
   LSP_LEAF_REALLOC_UNAVAILABLE, contacts no client, leaves the leaf and the
   channel untouched and returns 0. */
int lsp_channels_buy_liquidity(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                size_t client_idx, uint64_t amount_sats);

/* --- Continuous Ladder Rotation (Gap #3) --- */

/* Rotation is experimental and off unless the operator opts in: sets
   mgr->rot_enabled to `enabled`, and mgr->rot_auto_rotate (rotate when a
   factory turns DYING) to `enabled && automatic`. */
void lsp_channels_set_rotation(lsp_channel_mgr_t *mgr, int enabled, int automatic);

/* Perform a full factory rotation: PTLC turnover → cooperative close →
   fund new factory → create new factory → reinitialize channels.
   All parameters come from mgr->rot_* fields.
   Refused (LSP_ROTATE_FAILED, nothing done) unless mgr->rot_enabled.
   Otherwise returns LSP_ROTATE_OK, LSP_ROTATE_FAILED, or LSP_ROTATE_POSTPONED: the
   old factory's cooperative close would cost more than half its funding at
   the current fee estimate; nothing was sent or changed, and the
   postponement is already recorded (lsp_rotation_record_postponed): not a
   failed attempt.  A replacement factory that cannot be built, or whose
   channels cannot hold the carried balances, is LSP_ROTATE_FAILED, also
   with nothing sent or changed: its shape, client count, funding and agreed
   tree rate do not change with the fee market. */
#define LSP_ROTATE_FAILED    0
#define LSP_ROTATE_OK        1
#define LSP_ROTATE_POSTPONED 2
int lsp_channels_rotate_factory(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Fire ceremony if all clients are ready (async-rotation mode).
   Resets the readiness tracker once the ceremony ran, unless it was
   postponed (then the clients stay ready and it fires again on a later
   block).  Returns 1 if the rotation completed, else 0. */
int lsp_check_rotation_readiness(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* --- Reconnection (Phase 16) --- */

/* Handle a reconnecting client on a new fd.
   Reads MSG_RECONNECT, matches pubkey to client slot, re-exchanges nonces,
   sends MSG_RECONNECT_ACK. Returns 1 on success. */
int lsp_channels_handle_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, int new_fd);

/* Detect commitment TXs on-chain and register to_local outputs with the
   sweeper for CSV-delayed sweep. Called from daemon loop. */
int lsp_channels_detect_commitment_sweeps(lsp_channel_mgr_t *mgr);

/* Balance conservation invariant check.
   Verifies sum(local + remote + active_htlcs + active_ptlcs) == funding_amount
   for every channel. Returns 1 if all channels pass, 0 if any violated.
   Logs CONSERVATION VIOLATION to stderr on failure. */
int lsp_channels_check_conservation(const lsp_channel_mgr_t *mgr);

/* --- Bridge support (Phase 14) --- */

/* Set bridge fd in channel manager. */
void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd);

/* How outside payments end (BRIDGE_PAY_RESULT):
     - success with the preimage of the HTLC's hash: the client's HTLC is
       fulfilled;
     - failure: the client's HTLC is failed back.  The plugin reports
       failure only when the node can no longer complete the payment;
     - no result: the HTLC stays held.  It is never failed on a timer (see
       lsp_channels_expire_htlcs), because a payment that completed must
       not be refunded;
     - a result that cannot be used is rejected, once and for good:
         preimage_mismatch  a "success" whose preimage is not the HTLC's.
                            The HTLC stays held and the origin open: the
                            node claims a payment it cannot prove, and
                            whether to refund is an operator's decision;
         no_htlc            the client's HTLC is no longer there to settle
                            (the origin is closed, nothing is left to do);
         no_channel         the origin names a client that does not exist.
   Every result is answered with BRIDGE_PAY_RESULT_ACK, "applied" or
   "rejected" with the reason; the plugin repeats a result until it is
   answered and never after. */

/* Wait up to timeout_sec for a message of type `expected` from a client.
   Keepalives that arrive first are dealt with (a ping is answered, a pong
   dropped); any other message that is not the expected one is logged and
   dropped.  Returns 1 with the message, 0 on timeout or a lost connection. */
int lsp_channels_recv_client_reply(int fd, wire_msg_t *msg, uint8_t expected,
                                    int timeout_sec);

/* After an HTLC on a client's channel was fulfilled or failed (and the
   client told): sign the new commitment, send COMMITMENT_SIGNED, take the
   client's REVOKE_AND_ACK and send the LSP's own revocation.  old_* is the
   channel as it was before the change, for the watchtower.
   Returns 1 when the exchange completed.  If it did not, the client's
   connection is dropped, so nothing further happens on a channel whose
   commitment is in doubt until the client reconnects and the pending
   commitment is sent again. */
int lsp_channels_commit_htlc_update(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                     size_t client_idx,
                                     uint64_t old_local, uint64_t old_remote,
                                     const htlc_t *old_htlcs, size_t old_n_htlcs);

/* Give a client back the HTLC it offered for an outside payment that was
   never requested from the Lightning node, and close its origin.  The HTLC
   is in the commitment, so the commitment exchange follows. */
void lsp_channels_fail_outbound_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      htlc_origin_t *origin, size_t client_idx,
                                      uint64_t htlc_id, const char *reason);

/* Amount of the registered invoice for payment_hash32, in msat (0 = the
   invoice names no amount).  Returns 1 if the invoice is registered. */
int lsp_channels_invoice_amount(lsp_channel_mgr_t *mgr,
                                 const unsigned char *payment_hash32,
                                 uint64_t *amount_msat_out);

/* 1 if an HTLC that came in through the bridge for payment_hash32 is still
   unresolved. */
int lsp_channels_bridge_htlc_pending(const lsp_channel_mgr_t *mgr,
                                      const unsigned char *payment_hash32);

/* Chain the LSP runs on, for invoice checks: mgr->network if set, else the
   watchtower's chain connection, else NULL. */
const char *lsp_channels_network(const lsp_channel_mgr_t *mgr);

/* Current chain tip height from the chain backend (or the watchtower's chain
   connection); 0 if neither is available. */
uint32_t lsp_channels_chain_height(const lsp_channel_mgr_t *mgr);

/* Ask the bridge to pay an invoice out of the LSP's own Lightning node on the
   operator's instruction (no client HTLC backs it).  The invoice must decode,
   be for this chain, state an amount and be unexpired; the node is allowed
   the invoice amount plus a small routing-fee allowance.  Returns 1 and sets
   *request_id_out on success; on failure returns 0 and points *err_out at a
   static reason string. */
int lsp_channels_operator_pay(lsp_channel_mgr_t *mgr, const char *bolt11,
                               uint64_t *request_id_out, const char **err_out);

/* Register an invoice (payment_hash → dest_client) for bridge inbound routing. */
int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    const unsigned char *preimage32,
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
/* Record that an HTLC for payment_hash32 came in through the bridge
   (bridge_htlc_id > 0) or went out through it (bridge_htlc_id == 0).
   Returns the origin entry that was filled (an earlier free slot is reused
   before the table grows), or NULL if the table is full.  The caller
   completes the entry and writes it with lsp_channels_origin_save. */
htlc_origin_t *lsp_channels_track_bridge_origin(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t bridge_htlc_id);

/* The client fulfilled an HTLC that came in through the bridge: close its
   origin, remember the preimage for a replay, and return the bridge's
   htlc_id for the fulfil (0 if the hash did not come from the bridge). */
uint64_t lsp_channels_settle_bridge_origin(lsp_channel_mgr_t *mgr,
                                             const unsigned char *payment_hash32,
                                             const unsigned char *preimage32);

/* Fulfils the bridge has not confirmed (BRIDGE_FULFILL_ACK) are kept in the
   database as well and sent again: when the bridge connects, on its
   heartbeat, and when the node offers the HTLC again.
   lsp_channels_flush_bridge_fulfils sends them; it returns how many.
   lsp_channels_load_bridge_fulfils restores them after a restart. */
size_t lsp_channels_flush_bridge_fulfils(lsp_channel_mgr_t *mgr);

/* Tell the bridge about inbound HTLCs that were failed while it was away.
   Returns how many. */
size_t lsp_channels_flush_bridge_fails(lsp_channel_mgr_t *mgr);

/* Handle the bridge messages that were put aside because their channel had
   an exchange in progress.  Does nothing while any channel still has one.
   Returns how many were handled. */
size_t lsp_channels_run_deferred_bridge_msgs(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Take the revocation secret a client sent for the commitment before the
   channel's current one.  Returns 1 if it matches the point the client
   committed to and was stored.  Otherwise nothing is stored, the error is
   logged and the client's connection is dropped: the caller must not go on
   with the exchange (no watchtower entry, no revocation of its own). */
/* The LSP's own latest commitment of ch that the member co-signed, fully
   signed (lsp_take_host_commit_sig); 0 when it holds none. */
int lsp_signed_host_commitment(const channel_t *ch, tx_buf_t *out,
                               char txid_hex_out[65]);

/* The LSP's forced exit of member c's channel before the end date, one step
   per call (call once a block): publish the next pre-signed transaction of
   the member's path whose parent is confirmed and whose relative lock has
   passed; once the path is confirmed, the LSP's own latest commitment.
   Returns 1 when that commitment is confirmed, 0 while in progress, -1 when
   the LSP holds no signed commitment for the channel. */
int lsp_force_exit_step(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t c,
                        chain_backend_t *chain);

/* Below this many signing nonces left on a channel (either side) the LSP
   runs a fresh nonce exchange between updates (MSG_CHANNEL_NONCES with
   "refresh"); every update uses two of each side's nonces. */
#define CHANNEL_NONCE_REFRESH_AT 32
/* Seconds the LSP waits for the member's fresh nonces. */
#define CHANNEL_NONCE_REFRESH_WAIT 5
/* Refresh channel c's nonces when below CHANNEL_NONCE_REFRESH_AT (or always,
   with force), waiting at most CHANNEL_NONCE_REFRESH_WAIT seconds.  The
   channel's pools change only when the member answers; without an answer
   the next attempt waits for a back-off.  Returns 1 if the channel has
   enough afterwards. */
int lsp_channels_refresh_nonces(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t c, int force);

/* Take the member's signature over the LSP's own commitment from json
   (REVOKE_AND_ACK or HOST_COMMITMENT_SIG): 0 when it is missing or does not
   verify, which refuses the update and marks the channel refused. */
int lsp_take_host_commit_sig(channel_t *ch, const cJSON *json);
/* wire_parse_revoke_and_ack plus lsp_take_host_commit_sig for ch. */
int lsp_parse_member_revoke(channel_t *ch, const cJSON *json, uint32_t *channel_id,
                            unsigned char *rev_secret, unsigned char *next_point);

int lsp_channels_accept_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                    channel_t *ch,
                                    const unsigned char *secret32);

/* 1 if the client's revocation of the commitment before the channel's
   current one has been accepted and stored. */
int lsp_channels_peer_revoked(const channel_t *ch);

/* The client did not revoke its previous commitment after being offered or
   offering HTLC `htlc_id`: the HTLC is failed in the LSP's state and the
   client's connection is dropped.  The caller must stop there: nothing is
   recorded as paid and nothing is forwarded on the strength of that HTLC. */
void lsp_channels_abort_unrevoked_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                        size_t client_idx, channel_t *ch,
                                        uint64_t htlc_id);

/* Handle a bridge message that arrived while the LSP waits for the reply of
   the client on `waiting_client_fd`.  That client's channel counts as busy
   for the duration, so the message starts no second exchange on it. */
void lsp_channels_handle_bridge_msg_during_wait(lsp_channel_mgr_t *mgr,
                                                 lsp_t *lsp,
                                                 int waiting_client_fd,
                                                 const wire_msg_t *msg);

/* Restore the HTLC origins in flight from the database, with their expiry,
   their name on the Lightning node and whether a failure still has to be
   reported to the bridge.  Returns how many. */
size_t lsp_channels_restore_origins(lsp_channel_mgr_t *mgr);
size_t lsp_channels_load_bridge_fulfils(lsp_channel_mgr_t *mgr);

/* 1 if an HTLC for payment_hash32 is in flight through the bridge in either
   direction. */
int lsp_channels_hash_in_flight(const lsp_channel_mgr_t *mgr,
                                 const unsigned char *payment_hash32);

/* Remember / look up an outside payment that completed. */
void lsp_channels_note_outbound_paid(lsp_channel_mgr_t *mgr,
                                      const unsigned char *payment_hash32);
int lsp_channels_outbound_was_paid(const lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32);

/* 1 if HTLC htlc_id on client client_idx's channel pays for an outside
   payment whose result has not arrived yet. */
int lsp_channels_htlc_awaits_outside_pay(const lsp_channel_mgr_t *mgr,
                                          size_t client_idx, uint64_t htlc_id);

/* The per-block expiry pass of the daemon loop.
   - Channel HTLCs that have reached their expiry are failed, except those
     that pay for an outside payment still in flight: only the Lightning
     node's result may settle those (a timer could refund a payment that
     went through).
   - Inbound bridge HTLCs within 10 blocks of their expiry are failed back
     to the bridge.  Outbound origins are left alone. */
void lsp_channels_expire_htlcs(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                uint32_t height);

/* The open origin for payment_hash32 in one direction: outbound != 0 for
   an outside payment requested by a client, 0 for an HTLC that came in
   through the bridge.  One hash can have one of each; they are never
   interchangeable.  NULL if there is none. */
htlc_origin_t *lsp_channels_find_origin(lsp_channel_mgr_t *mgr,
                                         const unsigned char *payment_hash32,
                                         int outbound);

/* Write an origin to the database (insert the first time, update after). */
void lsp_channels_origin_save(lsp_channel_mgr_t *mgr, htlc_origin_t *origin);

/* Close an origin, in memory and its own row in the database. */
void lsp_channels_origin_close(lsp_channel_mgr_t *mgr, htlc_origin_t *origin);

/* 1 if payment_hash32 must not be used for a new invoice or a new inbound
   payment: an HTLC for it is in flight in either direction, an outside
   payment for it completed, or an inbound one was fulfilled (its preimage
   is known outside). */
int lsp_channels_hash_spent_or_busy(const lsp_channel_mgr_t *mgr,
                                     const unsigned char *payment_hash32);

/* 1 if another origin can be recorded. */
int lsp_channels_origin_slot_free(const lsp_channel_mgr_t *mgr);

/* Record an outside payment requested for a client's HTLC, so that the
   bridge's result for request_id finds its way back to that HTLC.
   Returns the origin entry, or NULL if the table is full. */
htlc_origin_t *lsp_channels_track_outbound_pay(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t request_id,
                                        size_t sender_idx,
                                        uint64_t sender_htlc_id,
                                        uint32_t cltv_expiry);

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

/* lsppay: LSP -> client inbound payment over the factory channel (the final
   hop of a real inbound LN payment; the external payer is simulated by the
   LSP).  For the pct-100 onboarding model where clients start with zero
   balance.  Invoice + OFFERED-HTLC leg + fulfill; no sender client, no
   back-propagation.  Returns 1 on success. */
int lsp_channels_lsppay(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                          size_t to_client, uint64_t amount_sats);

/* Create an external invoice so a client can receive from the LN via bridge.
   Sends MSG_CREATE_INVOICE, waits for MSG_INVOICE_CREATED, drains
   MSG_REGISTER_INVOICE, and forwards MSG_BRIDGE_REGISTER to bridge.
   Returns 1 on success. */
int lsp_channels_create_external_invoice(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                          size_t client_idx, uint64_t amount_msat);

/* Run a scripted demo sequence of payments after channels are ready.
   Returns 1 on success. */
int lsp_channels_run_demo_sequence(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Add a pending HTLC on a channel without fulfilling it.
   Used by --test-htlc-force-close to leave an HTLC in-flight for
   on-chain resolution testing.  Returns 1 on success. */
int lsp_channels_add_pending_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                    size_t from_client, uint64_t amount_sats,
                                    const unsigned char *payment_hash,
                                    uint32_t cltv_expiry);

/* Check all channels for imbalance (>threshold% on one side) and rebalance.
   Returns number of rebalance operations performed. */
int lsp_channels_auto_rebalance(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Rebalance entry: from → to, amount_sats */
typedef struct {
    size_t from;
    size_t to;
    uint64_t amount_sats;
} rebalance_entry_t;

/* Execute a batch of rebalance transfers.
   Returns number of successful transfers. */
int lsp_channels_batch_rebalance(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   const rebalance_entry_t *entries, size_t n_entries);

/* Advance one leaf (arity-1 DW or PS) via the wire ceremony.
   leaf_side: 0..n_leaf_nodes-1. Returns 1 on success, 0 on failure/skip/refusal.

   The advance replaces the transaction that funds the leaf's channel and does
   not re-anchor the channel, so it is refused (no state change, nothing sent)
   while an open channel is funded by the leaf, whatever its balances -- or by
   any leaf of the factory when the advance would exhaust this leaf and roll
   over into a whole-tree state advance.  allow_live_channel != 0 skips that
   check; it is for harnesses that exercise the ceremony itself.
   Payments never advance a leaf. */
int lsp_channels_advance_ps_leaf(lsp_channel_mgr_t *mgr, lsp_t *lsp, int leaf_side,
                                  int allow_live_channel);

/* Tick the factory's root counter forward (PS Tier B trigger).
   For PS factories, root rollover is block-driven (leaves chain-extend).
   On rollover, drives Tier B ceremony to re-sign every non-PS-leaf node
   for the new epoch.  A rollover replaces every leaf without re-anchoring
   any channel, so the tick is refused (counter untouched) while any channel
   of the factory is open, unless allow_live_channel != 0 (harnesses only).
   Returns 1 = ceremony complete, 0 = no rollover,
   -1 = refused or ceremony failed. */
int lsp_factory_tick_root(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                           int allow_live_channel);
#endif /* SUPERSCALAR_LSP_CHANNELS_H */
