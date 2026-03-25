#ifndef SUPERSCALAR_NOTIFY_H
#define SUPERSCALAR_NOTIFY_H

#include <stdint.h>
#include <stddef.h>

/* --- Notification event types --- */
#define NOTIFY_ROTATION_NEEDED    1  /* factory rotation starting */
#define NOTIFY_FACTORY_EXPIRING   3  /* factory approaching CLTV timeout */
#define NOTIFY_PAYMENT_RECEIVED   4  /* inbound payment pending */
#define NOTIFY_QUEUE_ITEM         5  /* generic: pending work queued */

/* --- Notification backend types --- */
#define NOTIFY_BACKEND_LOG        0  /* log to stdout (default) */
#define NOTIFY_BACKEND_WEBHOOK    1  /* POST to URL */
#define NOTIFY_BACKEND_EXEC       2  /* run external script */

/* --- Callback signature --- */
/* backend_data: opaque pointer to backend-specific state
   client_idx:   which client to notify
   event_type:   NOTIFY_* constant
   urgency:      QUEUE_URGENCY_* level
   detail_json:  JSON string with event details (may be NULL) */
typedef void (*notify_callback_t)(void *backend_data,
                                  uint32_t client_idx,
                                  int event_type,
                                  int urgency,
                                  const char *detail_json);

/* --- Notification system --- */
typedef struct {
    int backend_type;
    notify_callback_t callback;
    void *backend_data;
} notify_t;

/* Initialize with the log backend (default — prints to stdout). */
void notify_init_log(notify_t *n);

/* Initialize with a webhook backend.
   url: the webhook endpoint to POST to.
   Allocates internal state; call notify_cleanup() when done. */
void notify_init_webhook(notify_t *n, const char *url);

/* Initialize with an exec backend.
   script_path: path to script invoked as: script <client_idx> <event> <urgency> <json>
   Allocates internal state; call notify_cleanup() when done. */
void notify_init_exec(notify_t *n, const char *script_path);

/* Send a notification. Safe to call with n=NULL (no-op). */
void notify_send(notify_t *n, uint32_t client_idx,
                 int event_type, int urgency,
                 const char *detail_json);

/* Clean up backend resources. */
void notify_cleanup(notify_t *n);

/* Human-readable name for an event type. */
const char *notify_event_name(int event_type);

#endif /* SUPERSCALAR_NOTIFY_H */
